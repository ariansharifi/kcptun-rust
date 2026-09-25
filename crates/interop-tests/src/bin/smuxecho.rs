//! `kcptun-smuxecho` — the Rust counterpart of the Go interop peer
//! `tools/gointerop/cmd/smuxecho`, so a Rust↔Rust run can be measured with exactly the same
//! shape as a Go↔Go run (two processes, smux over TCP loopback, kcptun's `std.Pipe` half-close
//! order on the server).
//!
//! ```text
//! kcptun-smuxecho server -listen 127.0.0.1:0 [smux flags]
//! kcptun-smuxecho client -remote ADDR [smux flags] [-streams K -bytes N -seed S -chunk C -timeout T -early-closewrite]
//! kcptun-smuxecho idle   -remote ADDR [smux flags] [-streams K -hold SECS -probe]
//! ```
//!
//! The smux flags (`-ver`, `-smuxbuf`, `-streambuf`, `-framesize`, `-keepalive`), their
//! defaults, the `listening on: <addr>` line, the client's one-line JSON report and the exit
//! codes (0 success, 1 failure, 2 bad usage) are `smuxecho`'s, so both binaries are
//! interchangeable in a benchmark or interop run. `server` and `client` are thin wrappers
//! around [`kcptun_interop_tests::smuxecho`], which is what the interop tests already drive.
//!
//! `idle` is the extra mode the Go peer does not need: it opens `-streams` streams, optionally
//! proves each one is live end to end (one byte echoed), prints its JSON line and then holds
//! the streams open for `-hold` seconds so the *peer's* RSS can be sampled from outside while
//! nothing is in flight. The peer may be either implementation, so per-stream memory is
//! compared with the same client on both sides.
//!
//! Sub-step 06.6 smoke measurement (numbers in the `[06.6]` commit message):
//!
//! ```sh
//! cargo build --release -p kcptun-interop-tests --bin kcptun-smuxecho
//! # throughput, 1 and 64 streams (duration_ms from the client report)
//! target/release/kcptun-smuxecho server -listen 127.0.0.1:24101 &
//! target/release/kcptun-smuxecho client -remote 127.0.0.1:24101 -streams 1 -bytes 67108864
//! target/release/kcptun-smuxecho client -remote 127.0.0.1:24101 -streams 64 -bytes 4194304
//! # 10k idle streams: sample `ps -o rss= -p <server pid>` before and while the client holds
//! target/release/kcptun-smuxecho idle -remote 127.0.0.1:24101 -streams 10000 -hold 5
//! ```
//!
//! `duration_ms` is **not** a smux measurement: it is the client's wall time, and the
//! verifying client spends most of it generating `PrngStream` and hashing, not in smux. Any
//! run of it must therefore be cross-matrixed — Rust client → Go server and Go client → Rust
//! server as well as the two like-for-like pairs. On TCP loopback at these sizes only the
//! *client* implementation moves the number; swapping the server changes nothing, which is
//! the proof that smux is not the bottleneck. A smux-bound throughput comparison needs a
//! payload mode that skips the per-byte PRNG and SHA on both peers; the Go peer has no such
//! mode, so the real comparison is Step 12's.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kcptun_interop_tests::smuxecho::{
    ClientRun, CloseWriteOrder, RustEchoServer, SmuxSettings, run_rust_client,
};
use kcptun_smux::conn::SplitConn;
use kcptun_smux::stream::Stream;
use serde::Serialize;
use tokio::net::TcpStream;

/// Program name in usage and log lines, matching the Go peer's `prog`.
const PROG: &str = "smuxecho";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(mode) = args.first().map(String::as_str) else {
        return usage();
    };
    let rest = &args[1..];
    let code = match mode {
        "server" => run(server(rest)),
        "client" => run(client(rest)),
        "idle" => run(idle(rest)),
        _ => return usage(),
    };
    ExitCode::from(code)
}

// Go: tools/gointerop/cmd/smuxecho/main.go:usage()
fn usage() -> ExitCode {
    eprintln!("usage: {PROG} server|client|idle [flags]   ({PROG} server -h for the flags)");
    ExitCode::from(2)
}

/// Runs one mode on a multi-threaded runtime and turns its error into Go's exit codes.
fn run(f: impl Future<Output = Result<u8, Failure>>) -> u8 {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("{PROG}: runtime: {e}");
            return 1;
        }
    };
    match rt.block_on(f) {
        Ok(code) => code,
        Err(Failure { code, message }) => {
            if !message.is_empty() {
                eprintln!("{PROG}: {message}");
            }
            code
        }
    }
}

/// An error with the exit code it produces (2 for bad usage, 1 for everything else, 0 for
/// `-h`). An empty `message` is printed by whoever produced it, as Go's `flag` package prints
/// the usage block itself before `parse` exits 0.
#[derive(Debug)]
struct Failure {
    code: u8,
    message: String,
}

impl Failure {
    fn usage(message: impl Into<String>) -> Self {
        Failure {
            code: 2,
            message: message.into(),
        }
    }

    fn failed(message: impl Into<String>) -> Self {
        Failure {
            code: 1,
            message: message.into(),
        }
    }

    /// `-h`/`-help`: the flag list has been printed, exit 0 like Go's `flag.ErrHelp` path.
    fn help() -> Self {
        Failure {
            code: 0,
            message: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------------------

/// What a flag expects on the command line.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// `-name value` or `-name=value`.
    Value,
    /// A bool flag: `-name` or `-name=value`. Go's `flag` package accepts exactly these two
    /// forms for a bool; `-name value` is *not* one of them (parsing stops at the first
    /// non-flag word, which `smuxecho`'s `parse` then rejects), so it is not accepted here
    /// either.
    Bool,
}

impl Kind {
    /// What `-h` prints after the flag name, where Go's `flag.PrintDefaults` prints the Go
    /// type (`int`, `string`, ...); the declarations here do not carry that type.
    fn label(self) -> &'static str {
        match self {
            Kind::Value => "value",
            Kind::Bool => "",
        }
    }
}

/// One declared flag: name, kind, default value and the Go peer's usage text.
struct Flag(&'static str, Kind, &'static str, &'static str);

/// The smux flags every mode takes, with `smuxecho`'s (kcptun's) defaults.
// Go: tools/gointerop/cmd/smuxecho/main.go:smuxFlags.register()
const SMUX_FLAGS: &[Flag] = &[
    Flag("ver", Kind::Value, "2", "smux protocol version, 1 or 2"),
    Flag(
        "smuxbuf",
        Kind::Value,
        "4194304",
        "smux session receive buffer in bytes",
    ),
    Flag(
        "streambuf",
        Kind::Value,
        "2097152",
        "per-stream receive buffer in bytes (v2)",
    ),
    Flag("framesize", Kind::Value, "8192", "smux maximum frame size"),
    Flag(
        "keepalive",
        Kind::Value,
        "10",
        "keepalive interval in seconds",
    ),
];

/// Prints the flag list on stderr, in the shape of Go's `flag.FlagSet.PrintDefaults` for a
/// set created as `flag.NewFlagSet(prog+" server", ...)`. Two deliberate differences remain
/// from Go's output, both because the declarations here do not carry a Go type: Go prints the
/// Go type after the name (`-ver int`, `-listen string`) where this prints `value`, and Go
/// quotes string defaults (`(default "127.0.0.1:0")`) where this prints them bare. The flag
/// order does match: Go sorts by name, and so does this.
// Go: flag.FlagSet.PrintDefaults()
fn print_help(set: &str, declared: &[&[Flag]]) {
    eprintln!("Usage of {set}:");
    let mut flags: Vec<&Flag> = declared.iter().copied().flatten().collect();
    flags.sort_by_key(|flag| flag.0);
    for Flag(name, kind, default, usage) in flags {
        let label = kind.label();
        if label.is_empty() {
            eprintln!("  -{name}");
        } else {
            eprintln!("  -{name} {label}");
        }
        eprintln!("    \t{usage} (default {default})");
    }
}

/// Parsed command line: every declared flag, filled with its default when absent.
struct Flags(BTreeMap<&'static str, String>);

impl Flags {
    /// Parses Go-style `-flag value` arguments against `declared` (which must list every
    /// accepted flag). Unknown flags, missing values and positional arguments are usage
    /// errors, as they are in Go's `flag.FlagSet` with `ContinueOnError`; `-h`/`-help` prints
    /// the flag list on stderr and exits 0, as `flag.ErrHelp` does in the Go peer's `parse`.
    /// `set` names the flag set, e.g. `smuxecho server`.
    // Go: tools/gointerop/cmd/smuxecho/main.go:parse()
    fn parse(set: &str, args: &[String], declared: &[&[Flag]]) -> Result<Flags, Failure> {
        let mut values = BTreeMap::new();
        for flag in declared.iter().copied().flatten() {
            values.insert(flag.0, flag.2.to_string());
        }
        let find = |name: &str| -> Option<&Flag> {
            declared
                .iter()
                .copied()
                .flatten()
                .find(|flag| flag.0 == name)
        };

        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];
            i += 1;
            let Some(body) = arg.strip_prefix("--").or_else(|| arg.strip_prefix('-')) else {
                // Go's `flag.Parse` stops at the first non-flag word, so `fs.Args()` holds
                // that word and everything after it; `%v` of that slice prints `[a b c]`.
                let rest = args[i - 1..].join(" ");
                return Err(Failure::usage(format!("unexpected arguments: [{rest}]")));
            };
            let (name, inline) = match body.split_once('=') {
                Some((name, value)) => (name, Some(value.to_string())),
                None => (body, None),
            };
            let Some(flag) = find(name) else {
                if matches!(name, "h" | "help") {
                    print_help(set, declared);
                    return Err(Failure::help());
                }
                return Err(Failure::usage(format!(
                    "flag provided but not defined: -{name}"
                )));
            };
            let value = match (inline, flag.1) {
                (Some(value), _) => value,
                // A bare bool flag is `true`; Go's `flag` package never consumes the next
                // argument for a bool.
                (None, Kind::Bool) => "true".to_string(),
                (None, Kind::Value) => {
                    let Some(value) = args.get(i) else {
                        return Err(Failure::usage(format!("flag needs an argument: -{name}")));
                    };
                    i += 1;
                    value.clone()
                }
            };
            values.insert(flag.0, value);
        }
        Ok(Flags(values))
    }

    fn raw(&self, name: &str) -> &str {
        self.0
            .get(name)
            .map(String::as_str)
            .expect("flag is declared")
    }

    fn int<T: std::str::FromStr>(&self, name: &str) -> Result<T, Failure> {
        self.raw(name)
            .parse()
            .map_err(|_| Failure::usage(format!("invalid value for -{name}: {}", self.raw(name))))
    }

    fn bool(&self, name: &str) -> Result<bool, Failure> {
        match self.raw(name) {
            "true" => Ok(true),
            "false" => Ok(false),
            other => Err(Failure::usage(format!(
                "invalid value for -{name}: {other}"
            ))),
        }
    }

    fn addr(&self, name: &str) -> Result<SocketAddr, Failure> {
        self.raw(name)
            .parse()
            .map_err(|e| Failure::usage(format!("invalid value for -{name}: {e}")))
    }

    /// The smux settings these flags describe, verified like Go's `BuildSmuxConfig` does.
    fn settings(&self) -> Result<SmuxSettings, Failure> {
        let settings = SmuxSettings {
            version: self.int("ver")?,
            smuxbuf: self.int("smuxbuf")?,
            streambuf: self.int("streambuf")?,
            framesize: self.int("framesize")?,
            keepalive_secs: self.int("keepalive")?,
        };
        kcptun_smux::mux::verify_config(&settings.config())
            .map_err(|e| Failure::usage(e.to_string()))?;
        Ok(settings)
    }
}

// ---------------------------------------------------------------------------------------
// server
// ---------------------------------------------------------------------------------------

const SERVER_FLAGS: &[Flag] = &[Flag(
    "listen",
    Kind::Value,
    "127.0.0.1:0",
    "TCP address to listen on",
)];

/// Serves smux echo sessions until the accept loop fails, which is the only way Go's
/// `runServer` returns: it logs `accept: <err>` and returns 1.
// Go: tools/gointerop/cmd/smuxecho/main.go:runServer()
async fn server(args: &[String]) -> Result<u8, Failure> {
    let flags = Flags::parse(&format!("{PROG} server"), args, &[SMUX_FLAGS, SERVER_FLAGS])?;
    let settings = flags.settings()?;
    let server = RustEchoServer::start(flags.addr("listen")?, &settings)
        .await
        .map_err(Failure::failed)?;
    println!("listening on: {}", server.addr());
    Err(Failure::failed(server.stopped().await))
}

// ---------------------------------------------------------------------------------------
// client
// ---------------------------------------------------------------------------------------

const CLIENT_FLAGS: &[Flag] = &[
    Flag(
        "remote",
        Kind::Value,
        "127.0.0.1:29900",
        "TCP address of the echo server",
    ),
    Flag("streams", Kind::Value, "4", "number of concurrent streams"),
    Flag(
        "bytes",
        Kind::Value,
        "1048576",
        "bytes to send on each stream",
    ),
    Flag(
        "seed",
        Kind::Value,
        "1",
        "seed of stream 0; stream i uses seed+i",
    ),
    Flag("chunk", Kind::Value, "32768", "bytes per Write call"),
    Flag(
        "timeout",
        Kind::Value,
        "60",
        "overall deadline in seconds, 0 none",
    ),
    Flag(
        "early-closewrite",
        Kind::Bool,
        "false",
        "CloseWrite right after sending (kcptun Pipe order) instead of after the whole echo \
         arrived; exposes the pinned smux bug described in the README",
    ),
];

/// One stream's result, with `smuxecho`'s JSON field names.
// Go: tools/gointerop/cmd/smuxecho/main.go:streamResult
#[derive(Serialize)]
struct StreamReport {
    index: usize,
    id: u32,
    seed: u64,
    received: u64,
    sha256: String,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// The client's JSON report, parsed by `kcptun_interop_tests::smuxecho::SmuxEchoReport`.
// Go: tools/gointerop/cmd/smuxecho/main.go:clientReport
#[derive(Serialize)]
struct ClientReport {
    ok: bool,
    ver: isize,
    streams: usize,
    bytes_per_stream: u64,
    total_bytes: u64,
    duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    results: Vec<StreamReport>,
}

/// Sends the deterministic stream on `-streams` streams and verifies each echo.
// Go: tools/gointerop/cmd/smuxecho/main.go:runClient()
async fn client(args: &[String]) -> Result<u8, Failure> {
    let flags = Flags::parse(&format!("{PROG} client"), args, &[SMUX_FLAGS, CLIENT_FLAGS])?;
    let settings = flags.settings()?;
    let streams: usize = flags.int("streams")?;
    // Go declares -bytes as int64 and rejects a negative value in the check below, so parse it
    // as i64 here rather than u64: a negative value must reach that check, not the generic
    // "invalid value" parse error.
    let bytes: i64 = flags.int("bytes")?;
    let chunk: usize = flags.int("chunk")?;
    if streams == 0 || chunk == 0 || bytes < 0 {
        return Err(Failure::usage(
            "-streams and -chunk must be > 0, -bytes >= 0",
        ));
    }
    let bytes = bytes as u64;
    let order = if flags.bool("early-closewrite")? {
        CloseWriteOrder::Early
    } else {
        CloseWriteOrder::AfterEcho
    };
    let run = ClientRun {
        remote: flags.addr("remote")?,
        streams,
        bytes,
        seed: flags.int("seed")?,
        chunk,
        timeout_secs: flags.int("timeout")?,
    };

    let start = Instant::now();
    let outcome = run_rust_client(&run, &settings, order).await;
    let duration_ms = start.elapsed().as_millis() as u64;
    let mut report = ClientReport {
        ok: false,
        ver: settings.version,
        streams,
        bytes_per_stream: bytes,
        // Go computes `int64(*nstreams) * *nbytes`, which wraps silently; a debug build must
        // not panic on a huge -bytes (docs/porting-guide.md: no panics on input).
        total_bytes: bytes.wrapping_mul(streams as u64),
        duration_ms,
        error: None,
        results: Vec::new(),
    };
    match outcome {
        Ok(results) => {
            report.ok = results.iter().all(|r| r.ok);
            report.results = results
                .into_iter()
                .map(|r| StreamReport {
                    index: r.index,
                    id: r.id,
                    seed: r.seed,
                    received: r.received,
                    sha256: r.sha256,
                    ok: r.ok,
                    error: r.error,
                })
                .collect();
        }
        Err(e) => report.error = Some(e),
    }
    let ok = report.ok;
    print_json(&report);
    Ok(u8::from(!ok))
}

// ---------------------------------------------------------------------------------------
// idle
// ---------------------------------------------------------------------------------------

const IDLE_FLAGS: &[Flag] = &[
    Flag(
        "remote",
        Kind::Value,
        "127.0.0.1:29900",
        "TCP address of the echo server",
    ),
    Flag(
        "streams",
        Kind::Value,
        "10000",
        "number of idle streams to open",
    ),
    Flag(
        "hold",
        Kind::Value,
        "5",
        "seconds to hold the streams open after the report",
    ),
    Flag(
        "probe",
        Kind::Bool,
        "true",
        "echo one byte on every stream before reporting",
    ),
];

/// The `idle` mode's JSON line.
#[derive(Serialize)]
struct IdleReport {
    ok: bool,
    ver: isize,
    streams: usize,
    /// Wall time spent opening the streams.
    open_ms: u64,
    /// Wall time spent echoing one byte on every stream (0 with `-probe=false`).
    probe_ms: u64,
    /// This process's RSS in KiB before the first stream was opened.
    client_rss_kb_before: Option<u64>,
    /// This process's RSS in KiB with every stream open and idle.
    client_rss_kb_after: Option<u64>,
    /// Seconds the streams are held open after this line is printed.
    hold_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Opens `-streams` idle streams, reports, then holds them for `-hold` seconds so the peer's
/// RSS can be sampled from outside while the session is quiet.
async fn idle(args: &[String]) -> Result<u8, Failure> {
    let flags = Flags::parse(&format!("{PROG} idle"), args, &[SMUX_FLAGS, IDLE_FLAGS])?;
    let settings = flags.settings()?;
    let streams: usize = flags.int("streams")?;
    let hold_secs: u64 = flags.int("hold")?;
    let probe = flags.bool("probe")?;
    if streams == 0 {
        return Err(Failure::usage("-streams must be > 0"));
    }
    let remote = flags.addr("remote")?;

    let rss_before = rss_kb(std::process::id());
    let conn = TcpStream::connect(remote)
        .await
        .map_err(|e| Failure::failed(format!("connect {remote}: {e}")))?;
    let session = kcptun_smux::mux::client(SplitConn::tcp(conn), Some(settings.config()))
        .map_err(|e| Failure::failed(e.to_string()))?;

    let start = Instant::now();
    let mut open = Vec::with_capacity(streams);
    for i in 0..streams {
        let stream = session
            .open_stream()
            .await
            .map_err(|e| Failure::failed(format!("OpenStream {i}: {e}")))?;
        open.push(Arc::new(stream));
    }
    let open_ms = start.elapsed().as_millis() as u64;

    // One byte echoed per stream proves the peer really allocated the stream (and, for Go,
    // started its goroutine), so the RSS sample is not taken on SYNs it has not processed.
    let probe_start = Instant::now();
    let mut error = None;
    if probe {
        let tasks: Vec<_> = open
            .iter()
            .map(|stream| {
                let stream = Arc::clone(stream);
                tokio::spawn(async move { probe_stream(&stream).await })
            })
            .collect();
        for (i, task) in tasks.into_iter().enumerate() {
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    error.get_or_insert(format!("stream {i}: {e}"));
                }
                Err(e) => {
                    error.get_or_insert(format!("stream {i} task: {e}"));
                }
            }
        }
    }
    let probe_ms = probe_start.elapsed().as_millis() as u64;

    let report = IdleReport {
        ok: error.is_none() && session.num_streams() == streams,
        ver: settings.version,
        streams: session.num_streams(),
        open_ms,
        probe_ms,
        client_rss_kb_before: rss_before,
        client_rss_kb_after: rss_kb(std::process::id()),
        hold_secs,
        error,
    };
    let ok = report.ok;
    print_json(&report);

    tokio::time::sleep(Duration::from_secs(hold_secs)).await;
    // Keep the streams (and so the peer's) alive until here, then close the session.
    drop(open);
    let _ = session.close().await;
    Ok(u8::from(!ok))
}

/// Writes one byte and reads it back, the smallest round trip that forces the peer to have a
/// live stream.
async fn probe_stream(stream: &Stream) -> Result<(), String> {
    stream
        .write(b"\x00")
        .await
        .map_err(|e| format!("write: {e}"))?;
    let mut buf = [0u8; 1];
    match stream.read(&mut buf).await {
        Ok(1) => Ok(()),
        Ok(n) => Err(format!("read returned {n} bytes")),
        Err(e) => Err(format!("read: {e}")),
    }
}

// ---------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------

/// Prints one JSON line on stdout, like the Go peer's `peer.PrintJSON`.
fn print_json<T: Serialize>(value: &T) {
    match serde_json::to_string(value) {
        Ok(line) => println!("{line}"),
        Err(e) => eprintln!("{PROG}: encode report: {e}"),
    }
}

/// Resident set size of `pid` in KiB, via `ps` (the same number on macOS and Linux, and the
/// one an outside sampler would read). `None` if `ps` is missing or prints something else.
fn rss_kb(pid: u32) -> Option<u64> {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    parse_ps_rss(&String::from_utf8_lossy(&out.stdout))
}

/// Parses the single number `ps -o rss=` prints (leading spaces, trailing newline).
fn parse_ps_rss(out: &str) -> Option<u64> {
    out.split_whitespace().next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn flags_default_to_the_go_peers_values() {
        let flags =
            Flags::parse("client", &[], &[SMUX_FLAGS, CLIENT_FLAGS]).expect("defaults parse");
        assert_eq!(flags.settings().expect("verify"), SmuxSettings::default());
        assert_eq!(flags.raw("remote"), "127.0.0.1:29900");
        assert_eq!(flags.int::<usize>("streams").expect("streams"), 4);
        assert_eq!(flags.int::<u64>("bytes").expect("bytes"), 1048576);
        assert_eq!(flags.int::<usize>("chunk").expect("chunk"), 32768);
        assert_eq!(flags.int::<u64>("timeout").expect("timeout"), 60);
        assert!(!flags.bool("early-closewrite").expect("bool"));
    }

    #[test]
    fn flags_parse_go_and_gnu_spellings() {
        let flags = Flags::parse(
            "client",
            &args(&[
                "-ver",
                "1",
                "--framesize=1024",
                "-remote",
                "127.0.0.1:24000",
                "-early-closewrite",
            ]),
            &[SMUX_FLAGS, CLIENT_FLAGS],
        )
        .expect("parse");
        let settings = flags.settings().expect("verify");
        assert_eq!(settings.version, 1);
        assert_eq!(settings.framesize, 1024);
        assert_eq!(
            flags.addr("remote").expect("addr"),
            "127.0.0.1:24000".parse::<SocketAddr>().expect("addr")
        );
        assert!(flags.bool("early-closewrite").expect("bool"));

        // Go's flag package takes the `=` form for a bool, and only that form.
        let flags = Flags::parse("idle", &args(&["-probe=false"]), &[SMUX_FLAGS, IDLE_FLAGS])
            .expect("parse");
        assert!(!flags.bool("probe").expect("bool"));
    }

    #[test]
    fn flags_reject_bad_usage() {
        for bad in [
            args(&["-nope", "1"]),
            args(&["-ver"]),
            args(&["positional"]),
        ] {
            let err = Flags::parse("client", &bad, &[SMUX_FLAGS, CLIENT_FLAGS])
                .err()
                .expect("usage error");
            assert_eq!(err.code, 2, "{bad:?}");
        }
        // A value that smux's VerifyConfig rejects is a usage error too, with Go's text.
        let flags = Flags::parse("client", &args(&["-ver", "3"]), &[SMUX_FLAGS, CLIENT_FLAGS])
            .expect("parse");
        let err = flags.settings().expect_err("verify fails");
        assert_eq!(err.code, 2);
        assert_eq!(err.message, "unsupported protocol version");

        // Go's flag package never consumes the next word for a bool, so `-probe false` leaves
        // `false` as a positional argument, which `parse` rejects.
        let err = Flags::parse(
            "idle",
            &args(&["-probe", "false"]),
            &[SMUX_FLAGS, IDLE_FLAGS],
        )
        .err()
        .expect("usage error");
        assert_eq!(err.code, 2);
        assert_eq!(err.message, "unexpected arguments: [false]");
    }

    #[test]
    fn help_flags_exit_zero_without_an_error_line() {
        for spelling in ["-h", "-help", "--help", "-h=true"] {
            let err = Flags::parse(
                "smuxecho client",
                &args(&[spelling]),
                &[SMUX_FLAGS, CLIENT_FLAGS],
            )
            .err()
            .unwrap_or_else(|| panic!("{spelling} stops parsing"));
            assert_eq!(err.code, 0, "{spelling}");
            // Empty: `print_help` has already written the flag list, so `run` prints nothing.
            assert_eq!(err.message, "", "{spelling}");
        }
    }

    #[test]
    fn reports_use_the_go_field_names() {
        let report = ClientReport {
            ok: true,
            ver: 1,
            streams: 1,
            bytes_per_stream: 10,
            total_bytes: 10,
            duration_ms: 3,
            error: None,
            results: vec![StreamReport {
                index: 0,
                id: 3,
                seed: 5,
                received: 10,
                sha256: "ab".into(),
                ok: true,
                error: None,
            }],
        };
        let line = serde_json::to_string(&report).expect("encode");
        let parsed = kcptun_interop_tests::smuxecho::SmuxEchoReport::from_output(&line)
            .expect("the Go report parser reads it");
        assert!(parsed.ok);
        assert_eq!(parsed.ver, 1);
        assert_eq!(parsed.results.len(), 1);
        assert_eq!(parsed.results[0].id, 3);
        assert_eq!(parsed.results[0].error, None);
    }

    #[test]
    fn parses_ps_rss_output() {
        assert_eq!(parse_ps_rss(" 123456\n"), Some(123456));
        assert_eq!(parse_ps_rss("7\n"), Some(7));
        assert_eq!(parse_ps_rss("\n"), None);
        assert_eq!(parse_ps_rss("RSS\n"), None);
        // The real thing, for this process — skipped where `ps` is absent or restricted, so
        // the parser test stays environment-independent.
        if let Some(rss) = rss_kb(std::process::id()) {
            assert!(rss > 0);
        }
    }
}
