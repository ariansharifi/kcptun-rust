//! Tests for [`crate::config`] and [`crate::gojson`].
//!
//! `vectors_config_*` replay `testdata/vectors/config.json`, which `tools/govectors` produced
//! by running kcptun's own `std.ParseJSONConfig` + `ApplyMode` (Go 1.27.1's `encoding/json`)
//! over the same documents: every case carries the configuration the command line produced,
//! the file's bytes, Go's error text and the configuration Go ended up with.
//!
//! The unit tests below cover what the vectors cannot reach: the file-level errors (a missing
//! `-c` file), the flag tables (checked against the Go binaries' help text) and the validation
//! helpers.

use serde::Deserialize;

use super::*;
use crate::gojson::{SyntaxError, UnmarshalError};

// ---------------------------------------------------------------------------------------
// Golden vectors
// ---------------------------------------------------------------------------------------

/// A configuration as Go's `json.Marshal` renders it: the shared fields plus both sides'
/// extras, of which only one side's are present.
#[derive(Debug, Clone, Deserialize)]
struct VecConfig {
    key: String,
    crypt: String,
    mode: String,
    mtu: i64,
    ratelimit: i64,
    sndwnd: i64,
    rcvwnd: i64,
    datashard: i64,
    parityshard: i64,
    dscp: i64,
    nocomp: bool,
    acknodelay: bool,
    nodelay: i64,
    interval: i64,
    resend: i64,
    nc: i64,
    sockbuf: i64,
    smuxver: i64,
    smuxbuf: i64,
    framesize: i64,
    streambuf: i64,
    keepalive: i64,
    log: String,
    snmplog: String,
    snmpperiod: i64,
    quiet: bool,
    tcp: bool,
    pprof: bool,
    qpp: bool,
    #[serde(rename = "qpp-count")]
    qpp_count: i64,
    closewait: i64,
    #[serde(default)]
    localaddr: String,
    #[serde(default)]
    remoteaddr: String,
    #[serde(default)]
    conn: i64,
    #[serde(default)]
    autoexpire: i64,
    #[serde(default)]
    scavengettl: i64,
    #[serde(default)]
    listen: String,
    #[serde(default)]
    target: String,
}

impl VecConfig {
    fn base(&self) -> BaseConfig {
        BaseConfig {
            key: self.key.clone(),
            crypt: self.crypt.clone(),
            mode: self.mode.clone(),
            mtu: self.mtu,
            rate_limit: self.ratelimit,
            snd_wnd: self.sndwnd,
            rcv_wnd: self.rcvwnd,
            data_shard: self.datashard,
            parity_shard: self.parityshard,
            dscp: self.dscp,
            no_comp: self.nocomp,
            ack_nodelay: self.acknodelay,
            no_delay: self.nodelay,
            interval: self.interval,
            resend: self.resend,
            no_congestion: self.nc,
            sock_buf: self.sockbuf,
            smux_ver: self.smuxver,
            smux_buf: self.smuxbuf,
            frame_size: self.framesize,
            stream_buf: self.streambuf,
            keep_alive: self.keepalive,
            log: self.log.clone(),
            snmp_log: self.snmplog.clone(),
            snmp_period: self.snmpperiod,
            quiet: self.quiet,
            tcp: self.tcp,
            pprof: self.pprof,
            qpp: self.qpp,
            qpp_count: self.qpp_count,
            close_wait: self.closewait,
        }
    }

    fn client(&self) -> ClientConfig {
        ClientConfig {
            base: self.base(),
            local_addr: self.localaddr.clone(),
            remote_addr: self.remoteaddr.clone(),
            conn: self.conn,
            auto_expire: self.autoexpire,
            scavenge_ttl: self.scavengettl,
        }
    }

    fn server(&self) -> ServerConfig {
        ServerConfig {
            base: self.base(),
            listen: self.listen.clone(),
            target: self.target.clone(),
        }
    }
}

/// One recorded `ParseJSONConfig` + `ApplyMode`.
#[derive(Debug, Deserialize)]
struct VecCase {
    name: String,
    side: String,
    before: VecConfig,
    /// The `-c` file, when its bytes are valid UTF-8.
    #[serde(default)]
    json: String,
    /// The `-c` file in hex, for the cases whose bytes are not valid UTF-8.
    #[serde(default)]
    json_hex: String,
    #[serde(default)]
    err: String,
    mode_applied: bool,
    config: VecConfig,
}

impl VecCase {
    /// The exact bytes of the `-c` file.
    fn body(&self) -> Vec<u8> {
        if self.json_hex.is_empty() {
            self.json.clone().into_bytes()
        } else {
            hex::decode(&self.json_hex).expect("json_hex is hex")
        }
    }
}

fn load_cases() -> Vec<VecCase> {
    let file = kcptun_testkit::vectors!("config");
    assert!(!file.is_empty(), "the config area has no cases");
    file.cases.iter().map(|c| c.to::<VecCase>()).collect()
}

#[test]
fn vectors_config_overlay() {
    for case in load_cases() {
        let body = case.body();
        let (got_err, got_applied, got_client, got_server);
        match case.side.as_str() {
            "client" => {
                let mut config = case.before.client();
                got_err = parse_json_bytes(&mut config, &body).err();
                got_applied = config.base.apply_mode();
                got_client = Some(config);
                got_server = None;
            }
            "server" => {
                let mut config = case.before.server();
                got_err = parse_json_bytes(&mut config, &body).err();
                got_applied = config.base.apply_mode();
                got_client = None;
                got_server = Some(config);
            }
            other => panic!("case {}: unknown side {other:?}", case.name),
        }

        let err_text = got_err.map(|e| e.to_string()).unwrap_or_default();
        assert_eq!(err_text, case.err, "case {}: error text", case.name);
        assert_eq!(
            got_applied, case.mode_applied,
            "case {}: ApplyMode",
            case.name
        );
        if let Some(got) = got_client {
            assert_eq!(got, case.config.client(), "case {}", case.name);
        }
        if let Some(got) = got_server {
            assert_eq!(got, case.config.server(), "case {}", case.name);
        }
    }
}

/// The flag tables' defaults must be the ones the generator recorded for an empty command
/// line (WIRE-FORMAT §0).
#[test]
fn vectors_config_defaults_match_flag_tables() {
    let cases = load_cases();
    let client = cases
        .iter()
        .find(|c| c.name == "client/defaults")
        .expect("client/defaults case");
    assert_eq!(ClientConfig::defaults(), client.before.client());

    let server = cases
        .iter()
        .find(|c| c.name == "server/defaults")
        .expect("server/defaults case");
    assert_eq!(ServerConfig::defaults(), server.before.server());
}

// ---------------------------------------------------------------------------------------
// Flag tables
// ---------------------------------------------------------------------------------------

/// The rendered help must match the Go binaries' `-h` output byte for byte (captured by
/// `tools/gen-cli-golden.sh`, program name normalised to the Rust binary's).
#[test]
fn client_help_matches_go() {
    if crate::VERSION != "SELFBUILD" {
        return; // the golden text was captured from a SELFBUILD binary
    }
    assert_eq!(
        client_app("kcptun-client").render_help(),
        include_str!("../../../testdata/golden/cli/client_help.txt")
    );
}

#[test]
fn server_help_matches_go() {
    if crate::VERSION != "SELFBUILD" {
        return;
    }
    assert_eq!(
        server_app("kcptun-server").render_help(),
        include_str!("../../../testdata/golden/cli/server_help.txt")
    );
}

#[test]
fn hidden_flags_are_the_kcp_knobs() {
    for flags in [client_flags(), server_flags()] {
        let hidden: Vec<&str> = flags.iter().filter(|f| f.hidden).map(|f| f.name).collect();
        assert_eq!(
            hidden,
            ["acknodelay", "nodelay", "interval", "resend", "nc"]
        );
    }
}

#[test]
fn key_flag_reads_the_env() {
    let env: std::collections::HashMap<String, String> =
        [("KCPTUN_KEY".to_string(), "from-env".to_string())]
            .into_iter()
            .collect();
    let app = client_app("kcptun-client");

    let run = app.run(&["kcptun".to_string()], &env);
    let crate::cli::RunOutcome::Action(ctx) = run.outcome else {
        panic!("empty command line should run the action")
    };
    assert_eq!(ClientConfig::from_context(&ctx).base.key, "from-env");

    // The flag still wins over the environment.
    let argv = ["kcptun", "-key", "from-flag"].map(String::from);
    let run = app.run(&argv, &env);
    let crate::cli::RunOutcome::Action(ctx) = run.outcome else {
        panic!("-key should run the action")
    };
    assert_eq!(ClientConfig::from_context(&ctx).base.key, "from-flag");
}

#[test]
fn from_context_reads_every_flag() {
    let argv = [
        "kcptun",
        "-localaddr",
        ":9000",
        "-r",
        "example:4000-4010",
        "-crypt",
        "salsa20",
        "-mode",
        "manual",
        "-QPP",
        "-QPPCount",
        "127",
        "-conn",
        "4",
        "-autoexpire",
        "3600",
        "-scavengettl",
        "120",
        "-mtu",
        "1200",
        "-ratelimit",
        "1048576",
        "-sndwnd",
        "256",
        "-rcvwnd",
        "2048",
        "-ds",
        "20",
        "-ps",
        "5",
        "-dscp",
        "46",
        "-nocomp",
        "-acknodelay",
        "-nodelay",
        "1",
        "-interval",
        "20",
        "-resend",
        "2",
        "-nc",
        "1",
        "-sockbuf",
        "8388608",
        "-smuxver",
        "1",
        "-smuxbuf",
        "8388608",
        "-framesize",
        "4096",
        "-streambuf",
        "1048576",
        "-keepalive",
        "15",
        "-closewait",
        "5",
        "-snmplog",
        "./snmp-20060102.log",
        "-snmpperiod",
        "30",
        "-log",
        "/var/log/kcptun.log",
        "-quiet",
        "-tcp",
        "-pprof",
    ]
    .map(String::from);

    let run = client_app("kcptun-client").run(&argv, &());
    let crate::cli::RunOutcome::Action(ctx) = run.outcome else {
        panic!("the command line should parse: {}", run.stdout)
    };
    let config = ClientConfig::from_context(&ctx);
    assert_eq!(
        config,
        ClientConfig {
            base: BaseConfig {
                key: "it's a secrect".to_string(),
                crypt: "salsa20".to_string(),
                mode: "manual".to_string(),
                mtu: 1200,
                rate_limit: 1048576,
                snd_wnd: 256,
                rcv_wnd: 2048,
                data_shard: 20,
                parity_shard: 5,
                dscp: 46,
                no_comp: true,
                ack_nodelay: true,
                no_delay: 1,
                interval: 20,
                resend: 2,
                no_congestion: 1,
                sock_buf: 8388608,
                smux_ver: 1,
                smux_buf: 8388608,
                frame_size: 4096,
                stream_buf: 1048576,
                keep_alive: 15,
                log: "/var/log/kcptun.log".to_string(),
                snmp_log: "./snmp-20060102.log".to_string(),
                snmp_period: 30,
                quiet: true,
                tcp: true,
                pprof: true,
                qpp: true,
                qpp_count: 127,
                close_wait: 5,
            },
            local_addr: ":9000".to_string(),
            remote_addr: "example:4000-4010".to_string(),
            conn: 4,
            auto_expire: 3600,
            scavenge_ttl: 120,
        }
    );
}

#[test]
fn server_from_context_reads_its_own_flags() {
    let argv = [
        "kcptun",
        "-l",
        ":4100",
        "-t",
        "127.0.0.1:8080",
        "-closewait",
        "7",
    ]
    .map(String::from);
    let run = server_app("kcptun-server").run(&argv, &());
    let crate::cli::RunOutcome::Action(ctx) = run.outcome else {
        panic!("the command line should parse: {}", run.stdout)
    };
    let config = ServerConfig::from_context(&ctx);
    assert_eq!(config.listen, ":4100");
    assert_eq!(config.target, "127.0.0.1:8080");
    assert_eq!(config.base.close_wait, 7);
    // Untouched flags keep the server's own defaults.
    assert_eq!(config.base.snd_wnd, 1024);
    assert_eq!(config.base.rcv_wnd, 1024);
}

// ---------------------------------------------------------------------------------------
// Mode presets
// ---------------------------------------------------------------------------------------

#[test]
fn apply_mode_presets() {
    let cases = [
        ("normal", Some((0, 40, 2, 1))),
        ("fast", Some((0, 30, 2, 1))),
        ("fast2", Some((1, 20, 2, 1))),
        ("fast3", Some((1, 10, 2, 1))),
        ("manual", None),
        ("", None),
        ("Fast3", None),
        (" fast3", None),
    ];
    for (mode, want) in cases {
        let mut config = BaseConfig {
            mode: mode.to_string(),
            no_delay: 9,
            interval: 99,
            resend: 9,
            no_congestion: 9,
            ..BaseConfig::default()
        };
        let applied = config.apply_mode();
        match want {
            Some((nd, iv, rs, nc)) => {
                assert!(applied, "mode {mode:?}");
                assert_eq!(
                    (
                        config.no_delay,
                        config.interval,
                        config.resend,
                        config.no_congestion
                    ),
                    (nd, iv, rs, nc),
                    "mode {mode:?}"
                );
            }
            None => {
                assert!(!applied, "mode {mode:?}");
                assert_eq!(
                    (
                        config.no_delay,
                        config.interval,
                        config.resend,
                        config.no_congestion
                    ),
                    (9, 99, 9, 9),
                    "mode {mode:?} must keep the manual values"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// JSON overlay
// ---------------------------------------------------------------------------------------

#[test]
fn json_file_overrides_the_command_line() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("kcptun.json");
    std::fs::write(&path, br#"{"MTU":1200,"Mode":"fast2","SndWnd":77}"#).expect("write");

    let argv = ["kcptun", "-mtu", "1400", "-mode", "fast3"].map(String::from);
    let run = client_app("kcptun-client").run(&argv, &());
    let crate::cli::RunOutcome::Action(ctx) = run.outcome else {
        panic!("the command line should parse")
    };
    let mut config = ClientConfig::from_context(&ctx);
    parse_json_config(&mut config, &path).expect("the file decodes");
    config.base.apply_mode();

    assert_eq!(config.base.mtu, 1200, "the file wins over -mtu");
    assert_eq!(config.base.snd_wnd, 77);
    assert_eq!(config.base.mode, "fast2");
    // fast2 = {1, 20, 2, 1}: the preset runs after the file.
    assert_eq!(
        (
            config.base.no_delay,
            config.base.interval,
            config.base.resend,
            config.base.no_congestion
        ),
        (1, 20, 2, 1)
    );
}

#[test]
fn missing_file_reports_gos_message() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("nope.json");
    let mut config = ClientConfig::defaults();
    let err = parse_json_config(&mut config, &path).expect_err("the file does not exist");
    assert_eq!(
        err.to_string(),
        format!("open {}: no such file or directory", path.display())
    );
    assert_eq!(config, ClientConfig::defaults(), "nothing was changed");
}

#[test]
fn directory_reports_a_read_error() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut config = ClientConfig::defaults();
    // Unix opens a directory happily and fails on the first read, exactly as Go does.
    let err = parse_json_config(&mut config, dir.path()).expect_err("a directory is not a file");
    let text = err.to_string();
    assert!(
        text == format!("read {}: is a directory", dir.path().display())
            || text == format!("open {}: is a directory", dir.path().display()),
        "unexpected message: {text}"
    );
}

/// Go's `json.NewDecoder(file).Decode` stops at the end of the first value, so the rest of the
/// file is never read. The port decodes in the same refill loop.
#[test]
fn decoding_stops_after_the_first_value() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("kcptun.json");
    let mut bytes = br#"{"mtu":1200}"#.to_vec();
    // 4 MiB of junk that would be a syntax error if the decoder kept reading.
    bytes.extend(std::iter::repeat_n(b'}', 4 << 20));
    std::fs::write(&path, &bytes).expect("write");

    let mut config = ClientConfig::defaults();
    parse_json_config(&mut config, &path).expect("the first value decodes");
    assert_eq!(config.base.mtu, 1200);
}

/// An endless source must not be drained: Go reports the first invalid byte and exits 255.
#[cfg(unix)]
#[test]
fn endless_source_reports_the_first_invalid_byte() {
    let mut config = ClientConfig::defaults();
    let err = parse_json_config(&mut config, "/dev/zero").expect_err("NUL is not JSON");
    assert_eq!(
        err.to_string(),
        r"invalid character '\x00' looking for beginning of value"
    );
    assert_eq!(config, ClientConfig::defaults(), "nothing was changed");
}

#[test]
fn type_errors_keep_going() {
    let mut config = ClientConfig::defaults();
    let err = parse_json_bytes(&mut config, br#"{"mtu":"x","sndwnd":99,"conn":3}"#)
        .expect_err("mtu is a string");
    assert_eq!(
        err,
        ConfigFileError::Unmarshal(UnmarshalError::Field {
            value: "string".to_string(),
            struct_name: "Config",
            field: "mtu".to_string(),
            go_type: "int",
        })
    );
    assert_eq!(config.base.mtu, 1350, "the bad field is left alone");
    assert_eq!(config.base.snd_wnd, 99, "later fields are still applied");
    assert_eq!(config.conn, 3);
}

/// Go pushes the document's key onto `errorContext.FieldStack`, so a key matched by the
/// case-insensitive fallback is reported as the file spells it, not as the `json:"…"` tag.
// Go: encoding/json decode.go:(*decodeState).object
#[test]
fn type_error_names_the_document_key() {
    for (body, want) in [
        (&br#"{"MTU":"x"}"#[..], "Config.MTU"),
        (&br#"{"QPP-Count":"x"}"#[..], "Config.QPP-Count"),
        ("{\"\u{17f}ndwnd\":true}".as_bytes(), "Config.\u{17f}ndwnd"),
        // The key is unescaped before it reaches the field stack.
        (&br#"{"\u004DTU":"x"}"#[..], "Config.MTU"),
        (&br#"{"MTU":1.5}"#[..], "Config.MTU"),
    ] {
        let mut config = ClientConfig::defaults();
        let err = parse_json_bytes(&mut config, body).expect_err("wrong type for mtu");
        let text = err.to_string();
        assert!(
            text.contains(want),
            "{}: {text} should name {want}",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn syntax_errors_change_nothing() {
    let mut config = ClientConfig::defaults();
    let err = parse_json_bytes(&mut config, br#"{"mtu":1200,}"#).expect_err("trailing comma");
    assert_eq!(
        err,
        ConfigFileError::Syntax(SyntaxError::Invalid(
            "invalid character '}' looking for beginning of object key string".to_string()
        ))
    );
    assert_eq!(config, ClientConfig::defaults());
}

#[test]
fn empty_file_is_eof() {
    let mut config = ServerConfig::defaults();
    assert_eq!(
        parse_json_bytes(&mut config, b"").expect_err("empty"),
        ConfigFileError::Syntax(SyntaxError::Eof)
    );
    assert_eq!(
        parse_json_bytes(&mut config, b"  \n").expect_err("blank"),
        ConfigFileError::Syntax(SyntaxError::Eof)
    );
}

/// Go caps nesting at `maxNestingDepth = 10000` and returns `exceeded max depth`; a native
/// stack cannot grow, so the parser must reach that cap without overflowing (porting guide §5).
#[test]
fn deep_nesting_hits_gos_max_depth() {
    use crate::gojson::MAX_NESTING_DEPTH;

    let mut config = ClientConfig::defaults();

    // Exactly at the cap Go still accepts the containers and only runs out of input.
    let at_cap = "[".repeat(MAX_NESTING_DEPTH).into_bytes();
    assert_eq!(
        parse_json_bytes(&mut config, &at_cap).expect_err("truncated"),
        ConfigFileError::Syntax(SyntaxError::UnexpectedEof)
    );

    // One more container, and a wildly deeper document, are refused rather than fatal.
    for depth in [MAX_NESTING_DEPTH, 100_000] {
        let deep = format!(r#"{{"unknown":{}"#, "[".repeat(depth)).into_bytes();
        assert_eq!(
            parse_json_bytes(&mut config, &deep).expect_err("too deep"),
            ConfigFileError::Syntax(SyntaxError::MaxDepth),
            "object plus {depth} arrays"
        );
    }

    // A well-formed document at the cap decodes (and is dropped) without overflowing either.
    let closed = format!(
        "{}{}",
        "[".repeat(MAX_NESTING_DEPTH),
        "]".repeat(MAX_NESTING_DEPTH)
    );
    assert_eq!(
        parse_json_bytes(&mut config, closed.as_bytes()).expect_err("an array is not an object"),
        ConfigFileError::Unmarshal(UnmarshalError::TopLevel {
            value: "array".to_string(),
            go_type: "main.Config",
        })
    );
}

/// Go replaces one U+FFFD per invalid *byte*, not per maximal invalid subsequence, so a key
/// written in a non-UTF-8 encoding derives the same PBKDF2 session key on both ports.
// Go: encoding/json/internal/jsonwire/decode.go:consumeStringResumable ("n += rn")
#[test]
fn invalid_utf8_yields_one_replacement_per_byte() {
    for (body, want) in [
        (
            b"{\"key\":\"\xe3\xba\xc3\"}".as_slice(),
            "\u{fffd}".repeat(3),
        ),
        (b"{\"key\":\"\xc4\xe3\xba\xc3\"}", "\u{fffd}".repeat(4)),
        (b"{\"key\":\"\xff\"}", "\u{fffd}".to_string()),
        (b"{\"key\":\"\xe3\xba\"}", "\u{fffd}".repeat(2)),
    ] {
        let mut config = ClientConfig::defaults();
        parse_json_bytes(&mut config, body).expect("invalid UTF-8 is replaced, not rejected");
        assert_eq!(config.base.key, want, "{body:?}");
    }
}

/// The fallback key match is `strings.EqualFold`, which folds U+017F onto `s`.
// Go: encoding/json/v2/fields.go:matchFoldedName
#[test]
fn folded_keys_follow_equalfold() {
    let mut config = ClientConfig::defaults();
    parse_json_bytes(&mut config, "{\"\u{17f}ndwnd\":77}".as_bytes()).expect("folds onto sndwnd");
    assert_eq!(config.base.snd_wnd, 77);

    parse_json_bytes(&mut config, br#"{"Key":"a"}"#).expect("folds onto key");
    assert_eq!(config.base.key, "a");

    // U+212A KELVIN SIGN folds onto `k`.
    parse_json_bytes(&mut config, "{\"\u{212a}ey\":\"b\"}".as_bytes()).expect("folds onto key");
    assert_eq!(config.base.key, "b");

    // A rune whose fold set holds no ASCII letter matches nothing.
    parse_json_bytes(&mut config, "{\"\u{444}ey\":\"c\"}".as_bytes()).expect("unknown key");
    assert_eq!(config.base.key, "b");
}

/// The parser must never panic, whatever a user puts in the file (porting guide §5).
#[test]
fn parser_survives_arbitrary_input() {
    let seeds: &[&[u8]] = &[
        b"",
        b"{",
        b"[[[[[[[[[[",
        b"{\"a\":{\"b\":{\"c\":{}}}}",
        b"\"\\ud800\\ud800\\udc00\"",
        b"{\"mtu\":-}",
        b"\xff\xfe\xfd",
        b"{\"key\":\"\\u",
        b"1e999999999999999999",
        b"{\"mtu\":00000000000000000000000000}",
    ];
    let mut rng: u64 = 0x9e3779b97f4a7c15;
    for seed in seeds {
        let mut config = ClientConfig::defaults();
        let _ = parse_json_bytes(&mut config, seed);
        // Truncations and single-byte mutations of the same input.
        for cut in 0..seed.len() {
            let _ = parse_json_bytes(&mut config, &seed[..cut]);
        }
        for _ in 0..64 {
            rng = rng
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let mut data = seed.to_vec();
            if data.is_empty() {
                continue;
            }
            let i = (rng >> 33) as usize % data.len();
            data[i] = (rng >> 11) as u8;
            let _ = parse_json_bytes(&mut config, &data);
        }
    }
}

// ---------------------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------------------

#[test]
fn conn_must_be_positive() {
    let mut config = ClientConfig::defaults();
    assert_eq!(config.check_conn(), Ok(()));
    for conn in [0, -1] {
        config.conn = conn;
        assert_eq!(
            config.check_conn(),
            Err("conn must be greater than 0".to_string())
        );
    }
}

#[test]
fn negative_ratelimit_falls_back_to_zero() {
    let mut config = BaseConfig::default();
    assert_eq!(config.normalize_rate_limit(), None);

    config.rate_limit = -1500;
    assert_eq!(
        config.normalize_rate_limit(),
        Some("ratelimit -1500 is negative, falling back to 0".to_string())
    );
    assert_eq!(config.rate_limit, 0);
    assert_eq!(config.normalize_rate_limit(), None);
}

#[test]
fn smuxver_above_two_is_fatal() {
    let mut config = BaseConfig::default();
    for ver in [-1, 0, 1, 2] {
        config.smux_ver = ver;
        assert_eq!(config.check_smux_ver(), Ok(()), "smuxver {ver}");
    }
    config.smux_ver = 3;
    // fmt.Sprint puts no space between a string and a number.
    assert_eq!(
        config.check_smux_ver(),
        Err("unsupported smux version:3".to_string())
    );
}

/// Deviation V07: more than 256 shards makes Go switch to a codec no kcptun peer can decode.
#[test]
fn fec_shards_above_256_are_rejected() {
    let mut config = BaseConfig::default();
    for (ds, ps) in [(10, 3), (128, 128), (256, 0), (0, 0)] {
        config.data_shard = ds;
        config.parity_shard = ps;
        assert_eq!(config.check_fec(), Ok(()), "({ds}, {ps})");
    }
    config.data_shard = 200;
    config.parity_shard = 57;
    assert_eq!(
        config.check_fec(),
        Err(
            "datashard 200 + parityshard 57 exceeds 256: cannot create Encoder with more \
             than 256 data+parity shards"
                .to_string()
        )
    );
    // No overflow panic on absurd values.
    config.data_shard = i64::MAX;
    config.parity_shard = i64::MAX;
    assert!(config.check_fec().is_err());
}

// ---------------------------------------------------------------------------------------
// The shipped example configurations (dist/*.json.example)
// ---------------------------------------------------------------------------------------
//
// `dist/local.json.example` and `dist/server.json.example` are byte-for-byte copies of Go's,
// which only works because the `json:"…"` tags of `std/config.go` are reproduced exactly. An
// unknown key is *ignored* (D11, Go's `encoding/json`), so a key this parser did not know
// would silently do nothing in production; these tests are what notices.

/// `dist/local.json.example`, as shipped.
const DIST_LOCAL_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../dist/local.json.example"
));

/// `dist/server.json.example`, as shipped.
const DIST_SERVER_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../dist/server.json.example"
));

/// The keys of a JSON object.
fn json_keys(text: &str) -> Vec<String> {
    let doc: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(text).expect("the example file is a JSON object");
    doc.keys().cloned().collect()
}

/// The key names [`parse_json_config`] accepts for `C`.
fn known_keys<C: JsonStruct + Default>() -> Vec<&'static str> {
    let mut config = C::default();
    config.json_fields().into_iter().map(|(n, _)| n).collect()
}

#[test]
fn dist_local_example_uses_known_keys_only() {
    let known = known_keys::<ClientConfig>();
    for key in json_keys(DIST_LOCAL_JSON) {
        assert!(
            known.contains(&key.as_str()),
            "dist/local.json.example sets \"{key}\", which the client's JSON fields do not \
             cover - the parser would ignore it",
        );
    }
}

#[test]
fn dist_server_example_uses_known_keys_only() {
    let known = known_keys::<ServerConfig>();
    for key in json_keys(DIST_SERVER_JSON) {
        assert!(
            known.contains(&key.as_str()),
            "dist/server.json.example sets \"{key}\", which the server's JSON fields do not \
             cover - the parser would ignore it",
        );
    }
}

/// Every value in the file must reach its field. Overlaying onto `Default` rather than onto the
/// flag defaults makes the assertion show exactly which fields the file sets: everything else
/// is still zero.
#[test]
fn dist_local_example_overlays_every_value() {
    let mut config = ClientConfig::default();
    parse_json_bytes(&mut config, DIST_LOCAL_JSON.as_bytes()).expect("valid example");
    assert_eq!(
        config,
        ClientConfig {
            base: BaseConfig {
                key: "PASSWORD".to_string(),
                crypt: "aes-128".to_string(),
                mode: "fast3".to_string(),
                mtu: 1400,
                rate_limit: 1048576,
                snd_wnd: 128,
                rcv_wnd: 1024,
                data_shard: 10,
                parity_shard: 3,
                dscp: 46,
                no_comp: true,
                ack_nodelay: false,
                no_delay: 1,
                interval: 40,
                resend: 2,
                no_congestion: 1,
                sock_buf: 16777217,
                smux_ver: 2,
                smux_buf: 16777217,
                stream_buf: 2097152,
                keep_alive: 10,
                quiet: false,
                tcp: false,
                qpp: true,
                qpp_count: 61,
                // Not set by the file: framesize, log, snmplog, snmpperiod, pprof, closewait.
                ..BaseConfig::default()
            },
            local_addr: ":3000".to_string(),
            remote_addr: "127.0.0.1:29900-29999".to_string(),
            auto_expire: 300,
            // Not set by the file: conn, scavengettl.
            ..ClientConfig::default()
        }
    );
}

#[test]
fn dist_server_example_overlays_every_value() {
    let mut config = ServerConfig::default();
    parse_json_bytes(&mut config, DIST_SERVER_JSON.as_bytes()).expect("valid example");
    assert_eq!(
        config,
        ServerConfig {
            base: BaseConfig {
                key: "PASSWORD".to_string(),
                crypt: "aes-128".to_string(),
                mode: "fast3".to_string(),
                mtu: 1400,
                rate_limit: 104857600,
                snd_wnd: 2048,
                rcv_wnd: 2048,
                data_shard: 10,
                parity_shard: 3,
                dscp: 46,
                no_comp: true,
                ack_nodelay: false,
                no_delay: 1,
                interval: 40,
                resend: 2,
                no_congestion: 1,
                sock_buf: 16777217,
                smux_ver: 2,
                smux_buf: 16777217,
                stream_buf: 2097152,
                keep_alive: 10,
                pprof: false,
                quiet: false,
                tcp: false,
                qpp: true,
                qpp_count: 61,
                // Not set by the file: framesize, log, snmplog, snmpperiod, closewait.
                ..BaseConfig::default()
            },
            listen: ":29900-29999".to_string(),
            target: "127.0.0.1:2000".to_string(),
        }
    );
}

/// What a user actually gets from `-c dist/<file>`: the flag defaults, overlaid with the file,
/// then the checks `main` runs, then the `-mode` preset. `fast3` overrides the file's own
/// nodelay/interval/resend/nc, which is why its `"interval": 40` does not survive.
#[test]
fn dist_examples_are_valid_configurations() {
    let defaults = ClientConfig::defaults();
    let mut client = ClientConfig::defaults();
    parse_json_bytes(&mut client, DIST_LOCAL_JSON.as_bytes()).expect("valid example");
    assert_eq!(client.check_conn(), Ok(()), "conn keeps its flag default");
    assert_eq!(client.conn, defaults.conn);
    assert_eq!(client.scavenge_ttl, defaults.scavenge_ttl);
    assert_eq!(client.base.frame_size, defaults.base.frame_size);
    assert_eq!(client.base.normalize_rate_limit(), None);
    assert_eq!(client.base.check_smux_ver(), Ok(()));
    assert_eq!(client.base.check_fec(), Ok(()));
    assert!(client.base.apply_mode(), "\"fast3\" is a predefined mode");
    assert_eq!(
        ModeParams {
            no_delay: client.base.no_delay,
            interval: client.base.interval,
            resend: client.base.resend,
            no_congestion: client.base.no_congestion,
        },
        predefined_mode("fast3").expect("fast3")
    );

    let server_defaults = ServerConfig::defaults();
    let mut server = ServerConfig::defaults();
    parse_json_bytes(&mut server, DIST_SERVER_JSON.as_bytes()).expect("valid example");
    assert_eq!(server.base.frame_size, server_defaults.base.frame_size);
    assert_eq!(server.base.normalize_rate_limit(), None);
    assert_eq!(server.base.check_smux_ver(), Ok(()));
    assert_eq!(server.base.check_fec(), Ok(()));
    assert!(server.base.apply_mode(), "\"fast3\" is a predefined mode");
}

// ---------------------------------------------------------------------------------------
// D30: the smux error renderer
// ---------------------------------------------------------------------------------------

/// `EADDRINUSE`, spelled out so `crates/std` keeps no `libc` dependency for one constant
/// (`mainutil`'s tests do the same).
#[cfg(target_os = "linux")]
const EADDRINUSE: i32 = 98;
#[cfg(all(unix, not(target_os = "linux")))]
const EADDRINUSE: i32 = 48;
#[cfg(not(unix))]
const EADDRINUSE: i32 = 10048;

/// Both arms of [`smux_error_text`]: an `Error::Io` is spelled from Go's errno table (D30),
/// every other variant is smux's own Go text and must come back **verbatim** — routing those
/// through `go_error_text` too would lower-case them away from Go rather than towards it.
#[test]
fn smux_errors_take_gos_errno_text_and_keep_smuxs_own() {
    let in_use = kcptun_smux::Error::from(std::io::Error::from_raw_os_error(EADDRINUSE));
    assert_eq!(smux_error_text(&in_use), "address already in use");

    // smux's own errors are Go's strings already; they pass through untouched.
    assert_eq!(
        smux_error_text(&kcptun_smux::Error::InvalidProtocol),
        "invalid protocol"
    );
    assert_eq!(
        smux_error_text(&kcptun_smux::Error::Consumed),
        "peer consumed more than sent"
    );
}
