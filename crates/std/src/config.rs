//! kcptun's client and server configuration: the flag tables, the JSON overlay, the mode
//! presets and the post-parse validation.
//!
//! Go sources:
//! - `kcptun/std/config.go`: `BaseConfig`, `ModeParams`, `PredefinedModes`, `ApplyMode`,
//!   `ParseJSONConfig`
//! - `kcptun/client/config.go`, `kcptun/server/config.go`: the two `Config` structs
//! - `kcptun/client/main.go`, `kcptun/server/main.go`: the flag tables, the assignment of the
//!   parsed flags to the configuration, and the checks that follow
//!
//! The order of operations Go uses, which the types here preserve, is:
//!
//! 1. parse the command line ([`crate::cli`]) and copy every flag into the configuration
//!    ([`ClientConfig::from_context`] / [`ServerConfig::from_context`]);
//! 2. overlay the `-c` JSON file, which therefore **wins over the command line**
//!    ([`parse_json_config`]);
//! 3. validate ([`ClientConfig::check_conn`], [`BaseConfig::normalize_rate_limit`]);
//! 4. open the log file;
//! 5. apply the mode preset, which wins over both the command line and the JSON file
//!    ([`BaseConfig::apply_mode`]).

use std::io::Read as _;
use std::path::Path;

use kcptun_kcp::goerrno;

use crate::cli::{App, Context, FlagSpec, RunOutcome};
use crate::gojson::{self, Field, JsonStruct};

/// Largest smux version either side will negotiate.
// Go: kcptun/client/main.go:maxSmuxVer, kcptun/server/main.go:maxSmuxVer
pub const MAX_SMUX_VER: i64 = 2;

/// Largest total number of Reed-Solomon shards (see [`BaseConfig::check_fec`]).
// Go: klauspost/reedsolomon@v1.13.0 reedsolomon.go:ErrMaxShardNum
const MAX_FEC_SHARDS: i64 = 256;

// ---------------------------------------------------------------------------------------
// Configuration structs
// ---------------------------------------------------------------------------------------

/// The settings the client and the server share.
///
/// Every field is `i64` where Go uses `int` (64-bit on every target of this port), and the
/// documentation comments name the flag and the JSON key.
// Go: kcptun/std/config.go:BaseConfig
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BaseConfig {
    /// `-key`, `"key"`: pre-shared secret.
    pub key: String,
    /// `-crypt`, `"crypt"`: cipher name; unknown names fall back to AES.
    pub crypt: String,
    /// `-mode`, `"mode"`: `fast3`, `fast2`, `fast`, `normal` or anything else for manual.
    pub mode: String,
    /// `-mtu`, `"mtu"`.
    pub mtu: i64,
    /// `-ratelimit`, `"ratelimit"`: bytes per second, 0 to disable.
    pub rate_limit: i64,
    /// `-sndwnd`, `"sndwnd"`.
    pub snd_wnd: i64,
    /// `-rcvwnd`, `"rcvwnd"`.
    pub rcv_wnd: i64,
    /// `-datashard`, `"datashard"`.
    pub data_shard: i64,
    /// `-parityshard`, `"parityshard"`.
    pub parity_shard: i64,
    /// `-dscp`, `"dscp"`.
    pub dscp: i64,
    /// `-nocomp`, `"nocomp"`: disables snappy compression.
    pub no_comp: bool,
    /// `-strictsource`, `"strictsource"`: restores Go's rule that every datagram must come from
    /// the address we send to. Off by default: Deviation V23; Go has no such flag.
    pub strict_source: bool,
    /// `-acknodelay`, `"acknodelay"` (hidden flag).
    pub ack_nodelay: bool,
    /// `-nodelay`, `"nodelay"` (hidden flag; overwritten by a known `-mode`).
    pub no_delay: i64,
    /// `-interval`, `"interval"` (hidden flag; overwritten by a known `-mode`).
    pub interval: i64,
    /// `-resend`, `"resend"` (hidden flag; overwritten by a known `-mode`).
    pub resend: i64,
    /// `-nc`, `"nc"` (hidden flag; overwritten by a known `-mode`).
    pub no_congestion: i64,
    /// `-sockbuf`, `"sockbuf"`.
    pub sock_buf: i64,
    /// `-smuxver`, `"smuxver"`.
    pub smux_ver: i64,
    /// `-smuxbuf`, `"smuxbuf"`.
    pub smux_buf: i64,
    /// `-framesize`, `"framesize"`.
    pub frame_size: i64,
    /// `-streambuf`, `"streambuf"`.
    pub stream_buf: i64,
    /// `-keepalive`, `"keepalive"`: seconds between heartbeats.
    pub keep_alive: i64,
    /// `-log`, `"log"`: log file, empty for stderr.
    pub log: String,
    /// `-snmplog`, `"snmplog"`: SNMP CSV file, with a Go time layout in its name.
    pub snmp_log: String,
    /// `-snmpperiod`, `"snmpperiod"`: seconds between SNMP rows.
    pub snmp_period: i64,
    /// `-quiet`, `"quiet"`.
    pub quiet: bool,
    /// `-tcp`, `"tcp"`: fake-TCP transport (Linux only).
    pub tcp: bool,
    /// `-pprof`, `"pprof"`.
    pub pprof: bool,
    /// `-QPP`, `"qpp"`.
    pub qpp: bool,
    /// `-QPPCount`, `"qpp-count"`.
    pub qpp_count: i64,
    /// `-closewait`, `"closewait"`: seconds to wait before tearing a connection down.
    pub close_wait: i64,
}

/// The client configuration.
// Go: kcptun/client/config.go:Config
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientConfig {
    /// The embedded `std.BaseConfig`.
    pub base: BaseConfig,
    /// `-localaddr`, `"localaddr"`: TCP listen address, or a unix socket path.
    pub local_addr: String,
    /// `-remoteaddr`, `"remoteaddr"`: the kcptun server, possibly a port range.
    pub remote_addr: String,
    /// `-conn`, `"conn"`: number of UDP tunnels.
    pub conn: i64,
    /// `-autoexpire`, `"autoexpire"`: seconds after which a tunnel is replaced, 0 to disable.
    pub auto_expire: i64,
    /// `-scavengettl`, `"scavengettl"`: how long an expired tunnel may live on.
    pub scavenge_ttl: i64,
}

/// The server configuration.
// Go: kcptun/server/config.go:Config
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServerConfig {
    /// The embedded `std.BaseConfig`.
    pub base: BaseConfig,
    /// `-listen`, `"listen"`: KCP listen address, possibly a port range.
    pub listen: String,
    /// `-target`, `"target"`: where accepted streams are forwarded.
    pub target: String,
}

// ---------------------------------------------------------------------------------------
// Mode presets
// ---------------------------------------------------------------------------------------

/// The four KCP knobs a `-mode` preset sets.
// Go: kcptun/std/config.go:ModeParams
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeParams {
    pub no_delay: i64,
    pub interval: i64,
    pub resend: i64,
    pub no_congestion: i64,
}

/// The predefined `-mode` profiles.
// Go: kcptun/std/config.go:PredefinedModes
pub const PREDEFINED_MODES: &[(&str, ModeParams)] = &[
    (
        "normal",
        ModeParams {
            no_delay: 0,
            interval: 40,
            resend: 2,
            no_congestion: 1,
        },
    ),
    (
        "fast",
        ModeParams {
            no_delay: 0,
            interval: 30,
            resend: 2,
            no_congestion: 1,
        },
    ),
    (
        "fast2",
        ModeParams {
            no_delay: 1,
            interval: 20,
            resend: 2,
            no_congestion: 1,
        },
    ),
    (
        "fast3",
        ModeParams {
            no_delay: 1,
            interval: 10,
            resend: 2,
            no_congestion: 1,
        },
    ),
];

/// The parameters of a predefined mode, if `name` is one.
// Go: kcptun/std/config.go:PredefinedModes
pub fn predefined_mode(name: &str) -> Option<ModeParams> {
    PREDEFINED_MODES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, p)| *p)
}

impl BaseConfig {
    /// Applies the `-mode` preset, returning whether `mode` named one.
    ///
    /// Go runs this **after** the JSON file has been merged, so a preset overrides both the
    /// command line and the file; any other mode name (`manual`, a typo, …) keeps the explicit
    /// `-nodelay/-interval/-resend/-nc` values.
    // Go: kcptun/std/config.go:(*BaseConfig).ApplyMode
    pub fn apply_mode(&mut self) -> bool {
        match predefined_mode(&self.mode) {
            Some(p) => {
                self.no_delay = p.no_delay;
                self.interval = p.interval;
                self.resend = p.resend;
                self.no_congestion = p.no_congestion;
                true
            }
            None => false,
        }
    }

    // -----------------------------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------------------------

    /// Clamps a negative `-ratelimit` to 0 and returns the line Go logs when it does.
    ///
    /// Go: `log.Printf("ratelimit %d is negative, falling back to 0", config.RateLimit)`.
    // Go: kcptun/client/main.go, kcptun/server/main.go (Action, right after the JSON overlay)
    pub fn normalize_rate_limit(&mut self) -> Option<String> {
        if self.rate_limit < 0 {
            let msg = format!(
                "ratelimit {} is negative, falling back to 0",
                self.rate_limit
            );
            self.rate_limit = 0;
            return Some(msg);
        }
        None
    }

    /// Rejects a smux version neither side implements.
    ///
    /// The text is Go's `log.Fatal("unsupported smux version:", config.SmuxVer)`, whose
    /// `fmt.Sprint` semantics put **no** space between the string and the number.
    // Go: kcptun/client/main.go, kcptun/server/main.go (Action, after the startup log)
    pub fn check_smux_ver(&self) -> Result<(), String> {
        if self.smux_ver > MAX_SMUX_VER {
            return Err(format!("unsupported smux version:{}", self.smux_ver));
        }
        Ok(())
    }

    /// Rejects FEC settings that would produce parity no kcptun peer can decode.
    ///
    /// Deviation V07: with `datashard + parityshard > 256` klauspost's `reedsolomon.New`
    /// silently switches to the Leopard GF(2^16) codec, so a Go sender emits parity shards that
    /// every receiver drops (`kcp-go`'s `newFECDecoder` refuses more than 256 shards outright).
    /// The port refuses the configuration instead of tunnelling data that cannot be recovered.
    pub fn check_fec(&self) -> Result<(), String> {
        if self.data_shard.saturating_add(self.parity_shard) > MAX_FEC_SHARDS {
            return Err(format!(
                "datashard {} + parityshard {} exceeds {MAX_FEC_SHARDS}: \
                 cannot create Encoder with more than {MAX_FEC_SHARDS} data+parity shards",
                self.data_shard, self.parity_shard
            ));
        }
        Ok(())
    }
}

impl ClientConfig {
    /// Rejects `-conn 0` and below.
    ///
    /// Go: `log.Fatal("conn must be greater than 0")`, checked before anything else, because
    /// `numconn := uint16(config.Conn)` would otherwise divide by zero.
    // Go: kcptun/client/main.go (Action, right after the JSON overlay)
    pub fn check_conn(&self) -> Result<(), String> {
        if self.conn <= 0 {
            return Err("conn must be greater than 0".to_string());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// JSON overlay
// ---------------------------------------------------------------------------------------

impl BaseConfig {
    /// The shared fields, in the declaration order of Go's `BaseConfig`.
    fn base_json_fields(&mut self) -> Vec<(&'static str, Field<'_>)> {
        vec![
            ("key", Field::Str(&mut self.key)),
            ("crypt", Field::Str(&mut self.crypt)),
            ("mode", Field::Str(&mut self.mode)),
            ("mtu", Field::Int(&mut self.mtu)),
            ("ratelimit", Field::Int(&mut self.rate_limit)),
            ("sndwnd", Field::Int(&mut self.snd_wnd)),
            ("rcvwnd", Field::Int(&mut self.rcv_wnd)),
            ("datashard", Field::Int(&mut self.data_shard)),
            ("parityshard", Field::Int(&mut self.parity_shard)),
            ("dscp", Field::Int(&mut self.dscp)),
            ("nocomp", Field::Bool(&mut self.no_comp)),
            ("strictsource", Field::Bool(&mut self.strict_source)),
            ("acknodelay", Field::Bool(&mut self.ack_nodelay)),
            ("nodelay", Field::Int(&mut self.no_delay)),
            ("interval", Field::Int(&mut self.interval)),
            ("resend", Field::Int(&mut self.resend)),
            ("nc", Field::Int(&mut self.no_congestion)),
            ("sockbuf", Field::Int(&mut self.sock_buf)),
            ("smuxver", Field::Int(&mut self.smux_ver)),
            ("smuxbuf", Field::Int(&mut self.smux_buf)),
            ("framesize", Field::Int(&mut self.frame_size)),
            ("streambuf", Field::Int(&mut self.stream_buf)),
            ("keepalive", Field::Int(&mut self.keep_alive)),
            ("log", Field::Str(&mut self.log)),
            ("snmplog", Field::Str(&mut self.snmp_log)),
            ("snmpperiod", Field::Int(&mut self.snmp_period)),
            ("quiet", Field::Bool(&mut self.quiet)),
            ("tcp", Field::Bool(&mut self.tcp)),
            ("pprof", Field::Bool(&mut self.pprof)),
            ("qpp", Field::Bool(&mut self.qpp)),
            ("qpp-count", Field::Int(&mut self.qpp_count)),
            ("closewait", Field::Int(&mut self.close_wait)),
        ]
    }
}

impl JsonStruct for ClientConfig {
    const GO_STRUCT_NAME: &'static str = "Config";
    const GO_TYPE_NAME: &'static str = "main.Config";

    fn json_fields(&mut self) -> Vec<(&'static str, Field<'_>)> {
        let mut fields = self.base.base_json_fields();
        fields.extend([
            ("localaddr", Field::Str(&mut self.local_addr)),
            ("remoteaddr", Field::Str(&mut self.remote_addr)),
            ("conn", Field::Int(&mut self.conn)),
            ("autoexpire", Field::Int(&mut self.auto_expire)),
            ("scavengettl", Field::Int(&mut self.scavenge_ttl)),
        ]);
        fields
    }
}

impl JsonStruct for ServerConfig {
    const GO_STRUCT_NAME: &'static str = "Config";
    const GO_TYPE_NAME: &'static str = "main.Config";

    fn json_fields(&mut self) -> Vec<(&'static str, Field<'_>)> {
        let mut fields = self.base.base_json_fields();
        fields.extend([
            ("listen", Field::Str(&mut self.listen)),
            ("target", Field::Str(&mut self.target)),
        ]);
        fields
    }
}

/// Why a `-c` configuration file could not be applied.
///
/// Go passes every one of these to `checkError`, which prints `%+v` and exits with
/// `os.Exit(-1)`: status **255** on unix.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigFileError {
    /// `os.Open` failed: `open /etc/kcptun.json: no such file or directory`.
    #[error("open {path}: {err}")]
    Open { path: String, err: String },
    /// Reading failed after a successful open: `read /etc: is a directory`.
    #[error("read {path}: {err}")]
    Read { path: String, err: String },
    /// The file is not valid JSON.
    #[error(transparent)]
    Syntax(#[from] gojson::SyntaxError),
    /// A value does not fit its field.
    #[error(transparent)]
    Unmarshal(#[from] gojson::UnmarshalError),
}

/// Overlays the JSON file at `path` onto `config`.
///
/// Only the keys the file contains change anything, so the command line supplies the rest
/// (DECISIONS D11). Keys are matched exactly first and case-insensitively afterwards, unknown
/// keys are ignored and `null` leaves a field alone; see [`crate::gojson`].
// Go: kcptun/std/config.go:ParseJSONConfig
pub fn parse_json_config<C: JsonStruct>(
    config: &mut C,
    path: impl AsRef<Path>,
) -> Result<(), ConfigFileError> {
    let path = path.as_ref();
    let display = path.to_string_lossy().into_owned();
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) => {
            return Err(ConfigFileError::Open {
                path: display,
                err: go_error_text(&e),
            });
        }
    };
    // Go: encoding/json Decoder.refill, the decoder reads in chunks (512 bytes to start with,
    // doubling afterwards) and tries to decode after each one, so it stops at the end of the
    // first complete value instead of draining the file. Reading everything up front would hang
    // on an endless source: `-c /dev/zero` must report `invalid character '\x00' …` the way Go
    // does, not grow the heap without bound.
    let mut data: Vec<u8> = Vec::new();
    let mut chunk = 512usize;
    loop {
        let filled = data.len();
        data.resize(filled + chunk, 0);
        let n = match file.read(&mut data[filled..]) {
            Ok(n) => n,
            Err(e) => {
                return Err(ConfigFileError::Read {
                    path: display,
                    err: go_error_text(&e),
                });
            }
        };
        data.truncate(filled + n);
        match gojson::parse(&data) {
            Ok(value) => return Ok(gojson::decode_struct(config, &value)?),
            // More input may still complete the value, unless the source is exhausted, in
            // which case Go reports the same truncation error (`unexpected end of JSON input`,
            // or `EOF` for an empty file).
            Err(e) => {
                if n == 0
                    || !matches!(
                        e,
                        gojson::SyntaxError::Eof | gojson::SyntaxError::UnexpectedEof
                    )
                {
                    return Err(e.into());
                }
            }
        }
        chunk = chunk.saturating_mul(2).min(1 << 20);
    }
}

/// The in-memory half of [`parse_json_config`]: parse `data` and overlay it.
// Go: encoding/json Decoder.Decode
pub fn parse_json_bytes<C: JsonStruct>(config: &mut C, data: &[u8]) -> Result<(), ConfigFileError> {
    // Go's Decoder scans the whole value before decoding any of it, so a syntax error leaves
    // the configuration untouched while a type error does not (decoding continues).
    let value = gojson::parse(data)?;
    gojson::decode_struct(config, &value)?;
    Ok(())
}

/// Renders an OS error the way Go's `syscall.Errno` does, so `checkError` prints
/// `open x.json: no such file or directory` exactly like Go.
///
/// **DECISIONS D30:** the text comes from Go's own errno table
/// ([`kcptun_kcp::goerrno`]), not from the C library: a static musl build spells
/// `EADDRINUSE` differently from glibc, and Go, and this contract is not allowed to depend on
/// the target's libc. An error that carries no errno keeps the platform's own text with a
/// lower-case first letter and without Rust's ` (os error N)` suffix, as before.
///
/// Public because the binaries build Go's `*net.OpError` texts from it
/// (`dial tcp 127.0.0.1:12948: connect: connection refused`).
// Go: go1.27.1 syscall/syscall_unix.go:(Errno).Error()
pub fn go_error_text(err: &std::io::Error) -> String {
    goerrno::go_error_text(err)
}

/// Renders a [`kcptun_smux::Error`] the way Go's `log.Println(err)` renders the error smux hands
/// back from `AcceptStream`/`OpenStream`.
///
/// Go returns the underlying connection's error unchanged from those calls
/// (`session.go:socketReadError`), so a session that died on a socket failure logs a bare
/// `syscall.Errno`, which **DECISIONS D30** spells from Go's own table, not the C library's.
/// Every other variant already carries smux's own Go text (`invalid protocol`,
/// `io: read/write on closed pipe`, …) and is returned verbatim: lower-casing or rewriting those
/// would move them away from Go, not towards it.
// Go: smux@v1.5.55 session.go:AcceptStream()/OpenStream(), go1.27.1
//     syscall/syscall_unix.go:(Errno).Error()
pub fn smux_error_text(err: &kcptun_smux::Error) -> String {
    match err {
        kcptun_smux::Error::Io(inner) => goerrno::go_error_text(inner),
        other => other.to_string(),
    }
}

// ---------------------------------------------------------------------------------------
// Flag tables
// ---------------------------------------------------------------------------------------

/// Usage text of `-crypt`, identical on both sides.
const CRYPT_USAGE: &str = "aes, aes-128, aes-128-gcm, aes-192, salsa20, blowfish, twofish, cast5, 3des, tea, xtea, xor, sm4, none, null";
/// Usage text of `-mode`.
const MODE_USAGE: &str = "profiles: fast3, fast2, fast, normal, manual";
/// Usage text of `-QPPCount`.
const QPP_COUNT_USAGE: &str = "the prime number of pads to use for QPP: The more pads you use, the more secure the encryption. Each pad requires 256 bytes.";
/// Usage text of `-snmplog`.
const SNMPLOG_USAGE: &str =
    "collect snmp to file, aware of timeformat in golang, like: ./snmp-20060102.log";
/// Usage text of `-log`.
const LOG_USAGE: &str = "specify a log file to output, default goes to stderr";
/// Usage text of `-c`.
const CONFIG_USAGE: &str = "config from json file, which will override the command from shell";

/// The client's flag table, in urfave's declaration (and therefore help) order.
// Go: kcptun/client/main.go:myApp.Flags
pub fn client_flags() -> Vec<FlagSpec<'static>> {
    vec![
        FlagSpec::str_flag("localaddr,l", ":12948", "local listen address"),
        FlagSpec::str_flag(
            "remoteaddr, r",
            "vps:29900",
            r#"kcp server address, eg: "IP:29900" a for single port, "IP:minport-maxport" for port range"#,
        ),
        FlagSpec::str_flag(
            "key",
            "it's a secrect",
            "pre-shared secret between client and server",
        )
        .env("KCPTUN_KEY"),
        FlagSpec::str_flag("crypt", "aes", CRYPT_USAGE),
        FlagSpec::str_flag("mode", "fast", MODE_USAGE),
        FlagSpec::bool_flag("QPP", "enable Quantum Permutation Pads(QPP)"),
        FlagSpec::int_flag("QPPCount", 61, QPP_COUNT_USAGE),
        FlagSpec::int_flag("conn", 1, "set num of UDP connections to server"),
        FlagSpec::int_flag(
            "autoexpire",
            0,
            "set auto expiration time(in seconds) for a single UDP connection, 0 to disable",
        ),
        FlagSpec::int_flag(
            "scavengettl",
            600,
            "set how long an expired connection can live (in seconds)",
        ),
        FlagSpec::int_flag("mtu", 1350, "set maximum transmission unit for UDP packets"),
        FlagSpec::int_flag(
            "ratelimit",
            0,
            "set maximum outgoing speed (in bytes per second) for a single KCP connection, 0 to disable. Also known as packet pacing",
        ),
        FlagSpec::int_flag("sndwnd", 128, "set send window size(num of packets)"),
        FlagSpec::int_flag("rcvwnd", 512, "set receive window size(num of packets)"),
        FlagSpec::int_flag(
            "datashard,ds",
            10,
            "set reed-solomon erasure coding - datashard",
        ),
        FlagSpec::int_flag(
            "parityshard,ps",
            3,
            "set reed-solomon erasure coding - parityshard",
        ),
        FlagSpec::int_flag("dscp", 0, "set DSCP(6bit)"),
        FlagSpec::bool_flag("nocomp", "disable compression"),
        FlagSpec::bool_flag(
            "strictsource",
            "only accept packets from the address packets are sent to",
        )
        // Hidden, so `--help` stays Go's byte for byte: this flag has no Go counterpart, and it
        // only ever restores Go's own behaviour (Deviation V23). README documents it.
        .hidden(),
        FlagSpec::bool_flag(
            "acknodelay",
            "flush ack immediately when a packet is received",
        )
        .hidden(),
        FlagSpec::int_flag("nodelay", 0, "").hidden(),
        FlagSpec::int_flag("interval", 50, "").hidden(),
        FlagSpec::int_flag("resend", 0, "").hidden(),
        FlagSpec::int_flag("nc", 0, "").hidden(),
        FlagSpec::int_flag("sockbuf", 4194304, "per-socket buffer in bytes"),
        FlagSpec::int_flag("smuxver", 2, "specify smux version, available 1,2"),
        FlagSpec::int_flag("smuxbuf", 4194304, "the overall de-mux buffer in bytes"),
        FlagSpec::int_flag("framesize", 8192, "smux max frame size"),
        FlagSpec::int_flag(
            "streambuf",
            2097152,
            "per stream receive buffer in bytes, smux v2+",
        ),
        FlagSpec::int_flag("keepalive", 10, "seconds between heartbeats"),
        FlagSpec::int_flag(
            "closewait",
            0,
            "the seconds to wait before tearing down a connection",
        ),
        FlagSpec::str_flag("snmplog", "", SNMPLOG_USAGE),
        FlagSpec::int_flag("snmpperiod", 60, "snmp collect period, in seconds"),
        FlagSpec::str_flag("log", "", LOG_USAGE),
        FlagSpec::bool_flag("quiet", "to suppress the 'stream open/close' messages"),
        FlagSpec::bool_flag("tcp", "to emulate a TCP connection(linux)"),
        FlagSpec::str_flag("c", "", CONFIG_USAGE),
        FlagSpec::bool_flag("pprof", "start profiling server on :6060"),
    ]
}

/// The server's flag table, in urfave's declaration (and therefore help) order.
// Go: kcptun/server/main.go:myApp.Flags
pub fn server_flags() -> Vec<FlagSpec<'static>> {
    vec![
        FlagSpec::str_flag(
            "listen,l",
            ":29900",
            r#"kcp server listen address, eg: "IP:29900" for a single port, "IP:minport-maxport" for port range"#,
        ),
        FlagSpec::str_flag(
            "target, t",
            "127.0.0.1:12948",
            "target server address, or path/to/unix_socket",
        ),
        FlagSpec::str_flag(
            "key",
            "it's a secrect",
            "pre-shared secret between client and server",
        )
        .env("KCPTUN_KEY"),
        FlagSpec::str_flag("crypt", "aes", CRYPT_USAGE),
        FlagSpec::bool_flag("QPP", "enable Quantum Permutation Pads(QPP)"),
        FlagSpec::int_flag("QPPCount", 61, QPP_COUNT_USAGE),
        FlagSpec::str_flag("mode", "fast", MODE_USAGE),
        FlagSpec::int_flag("mtu", 1350, "set maximum transmission unit for UDP packets"),
        FlagSpec::int_flag(
            "ratelimit",
            0,
            "set maximum outgoing speed (in bytes per second) for a single KCP connection, 0 to disable. Also known as packet pacing.",
        ),
        FlagSpec::int_flag("sndwnd", 1024, "set send window size(num of packets)"),
        FlagSpec::int_flag("rcvwnd", 1024, "set receive window size(num of packets)"),
        FlagSpec::int_flag(
            "datashard,ds",
            10,
            "set reed-solomon erasure coding - datashard",
        ),
        FlagSpec::int_flag(
            "parityshard,ps",
            3,
            "set reed-solomon erasure coding - parityshard",
        ),
        FlagSpec::int_flag("dscp", 0, "set DSCP(6bit)"),
        FlagSpec::bool_flag("nocomp", "disable compression"),
        FlagSpec::bool_flag(
            "strictsource",
            "only accept packets from the address packets are sent to",
        )
        // Hidden, so `--help` stays Go's byte for byte: this flag has no Go counterpart, and it
        // only ever restores Go's own behaviour (Deviation V23). README documents it.
        .hidden(),
        FlagSpec::bool_flag(
            "acknodelay",
            "flush ack immediately when a packet is received",
        )
        .hidden(),
        FlagSpec::int_flag("nodelay", 0, "").hidden(),
        FlagSpec::int_flag("interval", 50, "").hidden(),
        FlagSpec::int_flag("resend", 0, "").hidden(),
        FlagSpec::int_flag("nc", 0, "").hidden(),
        FlagSpec::int_flag("sockbuf", 4194304, "per-socket buffer in bytes"),
        FlagSpec::int_flag("smuxver", 2, "specify smux version, available 1,2"),
        FlagSpec::int_flag("smuxbuf", 4194304, "the overall de-mux buffer in bytes"),
        FlagSpec::int_flag("framesize", 8192, "smux max frame size"),
        FlagSpec::int_flag(
            "streambuf",
            2097152,
            "per stream receive buffer in bytes, smux v2+",
        ),
        FlagSpec::int_flag("keepalive", 10, "seconds between heartbeats"),
        FlagSpec::int_flag(
            "closewait",
            30,
            "the seconds to wait before tearing down a connection",
        ),
        FlagSpec::str_flag("snmplog", "", SNMPLOG_USAGE),
        FlagSpec::int_flag("snmpperiod", 60, "snmp collect period, in seconds"),
        FlagSpec::bool_flag("pprof", "start profiling server on :6060"),
        FlagSpec::str_flag("log", "", LOG_USAGE),
        FlagSpec::bool_flag("quiet", "to suppress the 'stream open/close' messages"),
        FlagSpec::bool_flag("tcp", "to emulate a TCP connection(linux)"),
        FlagSpec::str_flag("c", "", CONFIG_USAGE),
    ]
}

/// The client application: `cli.NewApp()` with kcptun's name, usage, version and flags.
///
/// `help_name` is what urfave prints in the USAGE line; the binary passes
/// `filepath_base(argv[0])`.
// Go: kcptun/client/main.go (myApp.Name / Usage / Version)
pub fn client_app(help_name: impl Into<String>) -> App<'static> {
    App::new(
        "kcptun",
        help_name,
        "client(with SMUX)",
        crate::VERSION,
        client_flags(),
    )
}

/// The server application.
// Go: kcptun/server/main.go (myApp.Name / Usage / Version)
pub fn server_app(help_name: impl Into<String>) -> App<'static> {
    App::new(
        "kcptun",
        help_name,
        "server(with SMUX)",
        crate::VERSION,
        server_flags(),
    )
}

impl ClientConfig {
    /// Copies every flag into the configuration, in Go's assignment order.
    // Go: kcptun/client/main.go:myApp.Action
    // The field-by-field assignment mirrors Go's Action line for line, which is the point.
    #[allow(clippy::field_reassign_with_default)]
    pub fn from_context(c: &Context) -> Self {
        let mut config = ClientConfig::default();
        config.local_addr = c.string("localaddr");
        config.remote_addr = c.string("remoteaddr");
        config.base.key = c.string("key");
        config.base.crypt = c.string("crypt");
        config.base.mode = c.string("mode");
        config.conn = c.int("conn");
        config.auto_expire = c.int("autoexpire");
        config.scavenge_ttl = c.int("scavengettl");
        config.base.mtu = c.int("mtu");
        config.base.rate_limit = c.int("ratelimit");
        config.base.snd_wnd = c.int("sndwnd");
        config.base.rcv_wnd = c.int("rcvwnd");
        config.base.data_shard = c.int("datashard");
        config.base.parity_shard = c.int("parityshard");
        config.base.dscp = c.int("dscp");
        config.base.no_comp = c.bool("nocomp");
        config.base.strict_source = c.bool("strictsource");
        config.base.ack_nodelay = c.bool("acknodelay");
        config.base.no_delay = c.int("nodelay");
        config.base.interval = c.int("interval");
        config.base.resend = c.int("resend");
        config.base.no_congestion = c.int("nc");
        config.base.sock_buf = c.int("sockbuf");
        config.base.smux_buf = c.int("smuxbuf");
        config.base.frame_size = c.int("framesize");
        config.base.stream_buf = c.int("streambuf");
        config.base.smux_ver = c.int("smuxver");
        config.base.keep_alive = c.int("keepalive");
        config.base.log = c.string("log");
        config.base.snmp_log = c.string("snmplog");
        config.base.snmp_period = c.int("snmpperiod");
        config.base.quiet = c.bool("quiet");
        config.base.tcp = c.bool("tcp");
        config.base.pprof = c.bool("pprof");
        config.base.qpp = c.bool("QPP");
        config.base.qpp_count = c.int("QPPCount");
        config.base.close_wait = c.int("closewait");
        config
    }

    /// The configuration an empty client command line produces (every flag at its default).
    pub fn defaults() -> Self {
        Self::from_context(&default_context(&client_app("kcptun-client")))
    }
}

impl ServerConfig {
    /// Copies every flag into the configuration, in Go's assignment order.
    // Go: kcptun/server/main.go:myApp.Action
    // The field-by-field assignment mirrors Go's Action line for line, which is the point.
    #[allow(clippy::field_reassign_with_default)]
    pub fn from_context(c: &Context) -> Self {
        let mut config = ServerConfig::default();
        config.listen = c.string("listen");
        config.target = c.string("target");
        config.base.key = c.string("key");
        config.base.crypt = c.string("crypt");
        config.base.mode = c.string("mode");
        config.base.mtu = c.int("mtu");
        config.base.rate_limit = c.int("ratelimit");
        config.base.snd_wnd = c.int("sndwnd");
        config.base.rcv_wnd = c.int("rcvwnd");
        config.base.data_shard = c.int("datashard");
        config.base.parity_shard = c.int("parityshard");
        config.base.dscp = c.int("dscp");
        config.base.no_comp = c.bool("nocomp");
        config.base.strict_source = c.bool("strictsource");
        config.base.ack_nodelay = c.bool("acknodelay");
        config.base.no_delay = c.int("nodelay");
        config.base.interval = c.int("interval");
        config.base.resend = c.int("resend");
        config.base.no_congestion = c.int("nc");
        config.base.sock_buf = c.int("sockbuf");
        config.base.smux_buf = c.int("smuxbuf");
        config.base.frame_size = c.int("framesize");
        config.base.stream_buf = c.int("streambuf");
        config.base.smux_ver = c.int("smuxver");
        config.base.keep_alive = c.int("keepalive");
        config.base.log = c.string("log");
        config.base.snmp_log = c.string("snmplog");
        config.base.snmp_period = c.int("snmpperiod");
        config.base.pprof = c.bool("pprof");
        config.base.quiet = c.bool("quiet");
        config.base.tcp = c.bool("tcp");
        config.base.qpp = c.bool("QPP");
        config.base.qpp_count = c.int("QPPCount");
        config.base.close_wait = c.int("closewait");
        config
    }

    /// The configuration an empty server command line produces (every flag at its default).
    pub fn defaults() -> Self {
        Self::from_context(&default_context(&server_app("kcptun-server")))
    }
}

/// Runs `app` with no arguments and no environment, which yields the defaults.
fn default_context(app: &App<'_>) -> Context {
    match app.run(&["kcptun".to_string()], &()).outcome {
        RunOutcome::Action(ctx) => ctx,
        // Unreachable: an empty command line has no flags to reject and no help to print.
        RunOutcome::Exit(code) => unreachable!("empty command line exited with {code}"),
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
