//! Driving the `smuxecho` Go peer (`tools/gointerop/cmd/smuxecho`, see its README) and its Rust
//! counterparts, so both directions of a smux session can be tested against real Go code:
//!
//! | Case | Go side | Rust side |
//! |---|---|---|
//! | Rust client ↔ Go server | [`start_go_server`] (`smuxecho server`) | [`run_rust_client`] |
//! | Go client ↔ Rust server | [`run_go_client`] (`smuxecho client`) | [`RustEchoServer`] |
//!
//! Both peers speak the same deterministic byte stream (`kcptun_testkit::servers::PrngStream`,
//! which is `internal/peer.Stream` in Go), so each side can verify the echo with a SHA-256 it
//! computes from the seed alone.
//!
//! The Rust echo server mirrors `smuxecho`'s `echoStream`, which is kcptun's `std.Pipe`
//! half-close order: copy the stream into itself until the peer's FIN, then `CloseWrite`, then
//! `Close`.

use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use kcptun_smux::conn::SplitConn;
use kcptun_smux::mux::{Config, default_config};
use kcptun_smux::session::Session;
use kcptun_smux::stream::Stream;
use kcptun_testkit::proc::{Proc, ProcBuilder};
use kcptun_testkit::servers::PrngStream;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// How long a server may take to print `listening on:`.
pub const SERVER_START_TIMEOUT: Duration = Duration::from_secs(20);

/// The smux settings both peers are given; the names are `smuxecho`'s flags, which are
/// kcptun's.
// Go: tools/gointerop/cmd/smuxecho/main.go:smuxFlags, kcptun std/smuxcfg.go:BuildSmuxConfig
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmuxSettings {
    /// `-ver`: protocol version, 1 or 2.
    pub version: isize,
    /// `-smuxbuf`: session receive buffer (`MaxReceiveBuffer`).
    pub smuxbuf: isize,
    /// `-streambuf`: per-stream receive buffer (`MaxStreamBuffer`, version 2).
    pub streambuf: isize,
    /// `-framesize`: largest frame payload (`MaxFrameSize`).
    pub framesize: isize,
    /// `-keepalive`: keepalive interval in seconds (`KeepAliveInterval`). kcptun's
    /// `BuildSmuxConfig` sets only the interval; the timeout stays at smux `DefaultConfig`'s
    /// 30 s.
    pub keepalive_secs: u64,
}

impl Default for SmuxSettings {
    /// kcptun's defaults, which are also `smuxecho`'s.
    fn default() -> Self {
        SmuxSettings {
            version: 2,
            smuxbuf: 4194304,
            streambuf: 2097152,
            framesize: 8192,
            keepalive_secs: 10,
        }
    }
}

impl SmuxSettings {
    /// Sets `-ver`.
    pub fn version(mut self, version: isize) -> Self {
        self.version = version;
        self
    }

    /// Sets `-framesize`.
    pub fn framesize(mut self, framesize: isize) -> Self {
        self.framesize = framesize;
        self
    }

    /// Sets `-streambuf`.
    pub fn streambuf(mut self, streambuf: isize) -> Self {
        self.streambuf = streambuf;
        self
    }

    /// Sets `-smuxbuf`.
    pub fn smuxbuf(mut self, smuxbuf: isize) -> Self {
        self.smuxbuf = smuxbuf;
        self
    }

    /// The flags `smuxecho` takes for these settings (both modes).
    pub fn args(&self) -> Vec<String> {
        vec![
            "-ver".into(),
            self.version.to_string(),
            "-smuxbuf".into(),
            self.smuxbuf.to_string(),
            "-streambuf".into(),
            self.streambuf.to_string(),
            "-framesize".into(),
            self.framesize.to_string(),
            "-keepalive".into(),
            self.keepalive_secs.to_string(),
        ]
    }

    /// The same settings as a [`Config`], built the way kcptun's `BuildSmuxConfig` does: it
    /// starts from smux's `DefaultConfig()` and overrides only the version, the three buffer
    /// sizes and `KeepAliveInterval`. `KeepAliveTimeout` is *not* touched and stays at the
    /// default 30 s, so both peers must be left at that value to agree.
    // Go: kcptun std/smuxcfg.go:BuildSmuxConfig (verbatim copy in
    // tools/gointerop/internal/std/smuxcfg.go, which is what smuxecho calls)
    pub fn config(&self) -> Config {
        Config {
            version: self.version,
            keep_alive_interval: Duration::from_secs(self.keepalive_secs),
            max_frame_size: self.framesize,
            max_receive_buffer: self.smuxbuf,
            max_stream_buffer: self.streambuf,
            ..default_config()
        }
    }
}

/// One stream's result in the Go client's report (`streamResult` in `smuxecho`'s `main.go`).
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct StreamResult {
    /// Index of the stream in the run.
    pub index: i64,
    /// smux stream id.
    pub id: u32,
    /// Seed of the deterministic stream.
    pub seed: u64,
    /// Bytes of echo received.
    pub received: i64,
    /// SHA-256 of the received echo.
    pub sha256: String,
    /// Whether this stream verified.
    pub ok: bool,
    /// Go's error text, if any.
    #[serde(default)]
    pub error: Option<String>,
}

/// The Go client's JSON report (`clientReport` in `smuxecho`'s `main.go`).
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct SmuxEchoReport {
    /// True if every stream verified.
    pub ok: bool,
    /// Protocol version used.
    pub ver: i64,
    /// Number of streams.
    pub streams: i64,
    /// Bytes sent on each stream.
    pub bytes_per_stream: i64,
    /// `streams × bytes_per_stream`.
    pub total_bytes: i64,
    /// Wall time of the run.
    pub duration_ms: i64,
    /// Go's error text, if the run failed as a whole.
    #[serde(default)]
    pub error: Option<String>,
    /// Per-stream results.
    #[serde(default)]
    pub results: Vec<StreamResult>,
}

impl SmuxEchoReport {
    /// Finds the last line of `output` that parses as a report.
    pub fn from_output(output: &str) -> Option<SmuxEchoReport> {
        output
            .lines()
            .rev()
            .filter(|l| l.trim_start().starts_with('{'))
            .find_map(|l| serde_json::from_str(l.trim()).ok())
    }
}

/// Starts `smuxecho server` on `listen` and waits for its `listening on:` line.
pub fn start_go_server(
    bin: &Path,
    listen: SocketAddr,
    settings: &SmuxSettings,
) -> Result<(Proc, String), String> {
    let mut p = ProcBuilder::new(bin)
        .name("smuxecho-server")
        .arg("server")
        .arg("-listen")
        .arg(listen.to_string())
        .args(settings.args())
        .spawn()
        .map_err(|e| e.to_string())?;
    let line = p
        .wait_for_log_line("listening on:", SERVER_START_TIMEOUT)
        .map_err(|e| e.to_string())?;
    let addr = line
        .split_once("listening on:")
        .map(|(_, a)| a.trim().to_string())
        .unwrap_or_default();
    Ok((p, addr))
}

/// Parameters of one echo run, for either implementation's client.
#[derive(Clone, Copy, Debug)]
pub struct ClientRun {
    /// Server address.
    pub remote: SocketAddr,
    /// Number of concurrent streams.
    pub streams: usize,
    /// Bytes sent on each stream.
    pub bytes: u64,
    /// Seed of stream 0; stream *i* uses `seed + i`.
    pub seed: u64,
    /// Bytes per write call.
    pub chunk: usize,
    /// The client's own deadline in seconds (0 for none).
    pub timeout_secs: u64,
}

impl ClientRun {
    /// A run of `streams` streams of `bytes` bytes each, with `smuxecho`'s defaults otherwise.
    pub fn new(remote: SocketAddr, streams: usize, bytes: u64) -> Self {
        ClientRun {
            remote,
            streams,
            bytes,
            seed: 1,
            chunk: 32 * 1024,
            timeout_secs: 120,
        }
    }

    /// Sets the stream seed.
    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// The flags `smuxecho client` takes for this run (the smux settings come separately).
    pub fn args(&self) -> Vec<String> {
        vec![
            "-remote".into(),
            self.remote.to_string(),
            "-streams".into(),
            self.streams.to_string(),
            "-bytes".into(),
            self.bytes.to_string(),
            "-seed".into(),
            self.seed.to_string(),
            "-chunk".into(),
            self.chunk.to_string(),
            "-timeout".into(),
            self.timeout_secs.to_string(),
        ]
    }
}

/// Outcome of a Go client run.
#[derive(Debug)]
pub struct GoClientOutcome {
    /// Exit code (`None` if killed by a signal).
    pub exit_code: Option<i32>,
    /// The parsed report, if the client printed one.
    pub report: Option<SmuxEchoReport>,
    /// The whole client log (stdout and stderr).
    pub log: String,
}

/// Runs `smuxecho client` to completion. `extra` adds flags such as `-early-closewrite`.
pub fn run_go_client<I, S>(
    bin: &Path,
    run: &ClientRun,
    settings: &SmuxSettings,
    extra: I,
) -> Result<GoClientOutcome, String>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut p = ProcBuilder::new(bin)
        .name("smuxecho-client")
        .arg("client")
        .args(run.args())
        .args(settings.args())
        .args(extra.into_iter().map(Into::into))
        .spawn()
        .map_err(|e| e.to_string())?;
    let limit = Duration::from_secs(run.timeout_secs.saturating_add(30));
    let status = p.wait_timeout(limit).map_err(|e| e.to_string())?;
    let log = p.log();
    let Some(status) = status else {
        return Err(format!(
            "smuxecho client still running after {limit:?}; log:\n{}",
            p.log_tail()
        ));
    };
    Ok(GoClientOutcome {
        exit_code: status.code(),
        report: SmuxEchoReport::from_output(&log),
        log,
    })
}

/// When the Rust client half-closes its write side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseWriteOrder {
    /// Right after the last byte has been sent: kcptun's `std.Pipe` order, and what
    /// `smuxecho client -early-closewrite` does. This is the order that loses data in Go
    /// (deviation V11).
    Early,
    /// Only once the whole echo has arrived, which is how `smuxecho client` avoids the Go bug.
    AfterEcho,
}

/// One stream's outcome in a Rust client run; the fields mirror [`StreamResult`].
#[derive(Clone, Debug, PartialEq)]
pub struct RustStreamResult {
    /// Index of the stream in the run.
    pub index: usize,
    /// smux stream id.
    pub id: u32,
    /// Seed of the deterministic stream.
    pub seed: u64,
    /// Bytes of echo received.
    pub received: u64,
    /// SHA-256 of the received echo.
    pub sha256: String,
    /// The SHA-256 the sent stream has.
    pub expected_sha256: String,
    /// Whether the echo matched.
    pub ok: bool,
    /// The error, if the stream failed.
    pub error: Option<String>,
    /// Bytes that were buffered but unread when the peer's FIN arrived. With
    /// [`CloseWriteOrder::Early`] this is what smux v1.5.55 would have thrown away (V11).
    pub buffered_at_fin: usize,
}

/// Runs a Rust smux client against `run.remote`: opens `run.streams` streams, sends the
/// deterministic stream on each, half-closes in `order` and verifies the echo.
pub async fn run_rust_client(
    run: &ClientRun,
    settings: &SmuxSettings,
    order: CloseWriteOrder,
) -> Result<Vec<RustStreamResult>, String> {
    let conn = TcpStream::connect(run.remote)
        .await
        .map_err(|e| format!("connect {}: {e}", run.remote))?;
    let session = kcptun_smux::mux::client(SplitConn::tcp(conn), Some(settings.config()))
        .map_err(|e| e.to_string())?;

    // Go's `runClient`: one deadline for the whole run, set on every stream right after
    // `OpenStream`, so a stuck peer fails the run instead of hanging it.
    let deadline = (run.timeout_secs > 0)
        .then(|| tokio::time::Instant::now() + Duration::from_secs(run.timeout_secs));

    let mut tasks = Vec::with_capacity(run.streams);
    for i in 0..run.streams {
        let stream = session
            .open_stream()
            .await
            .map_err(|e| format!("OpenStream {i}: {e}"))?;
        if deadline.is_some() {
            stream.set_deadline(deadline);
        }
        let seed = run.seed + i as u64;
        let bytes = run.bytes;
        let chunk = run.chunk;
        tasks.push(tokio::spawn(async move {
            run_rust_stream(i, stream, seed, bytes, chunk, order).await
        }));
    }

    let mut results = Vec::with_capacity(run.streams);
    for t in tasks {
        results.push(t.await.map_err(|e| format!("stream task: {e}"))?);
    }
    let _ = session.close().await;
    Ok(results)
}

/// One stream of [`run_rust_client`]: send, half-close, verify the echo up to the end of the
/// stream. Mirrors `smuxecho`'s `runStream`.
// Go: tools/gointerop/cmd/smuxecho/main.go:runStream
async fn run_rust_stream(
    index: usize,
    stream: Stream,
    seed: u64,
    bytes: u64,
    chunk: usize,
    order: CloseWriteOrder,
) -> RustStreamResult {
    let id = stream.id();
    let stream = Arc::new(stream);
    let expected_sha256 = PrngStream::sha256_hex(seed, bytes);
    let mut result = RustStreamResult {
        index,
        id,
        seed,
        received: 0,
        sha256: String::new(),
        expected_sha256: expected_sha256.clone(),
        ok: false,
        error: None,
        buffered_at_fin: 0,
    };

    // The reader signals "everything arrived" so the AfterEcho order can half-close then.
    let echoed = Arc::new(tokio::sync::Notify::new());
    let writer = {
        let stream = Arc::clone(&stream);
        let echoed = Arc::clone(&echoed);
        tokio::spawn(async move {
            let mut src = PrngStream::new(seed, bytes);
            let mut buf = vec![0u8; chunk];
            loop {
                let n = src.fill(&mut buf);
                if n == 0 {
                    break;
                }
                stream.write(&buf[..n]).await.map_err(|e| e.to_string())?;
            }
            if order == CloseWriteOrder::AfterEcho {
                echoed.notified().await;
            }
            stream.close_write().await.map_err(|e| e.to_string())
        })
    };

    let mut hasher = Sha256::new();
    let mut expected = PrngStream::new(seed, bytes);
    let mut expbuf = vec![0u8; 64 * 1024];
    let mut buf = vec![0u8; 64 * 1024];
    let mut received = 0u64;
    let mut fin_seen = false;
    loop {
        if !fin_seen && stream.got_fin() {
            // What Go's `tryHalfCloseCleanup` would have discarded at this moment.
            result.buffered_at_fin = stream.buffered_len();
            fin_seen = true;
        }
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                let want = expected.fill(&mut expbuf[..n]);
                if want != n || expbuf[..n] != buf[..n] {
                    result.error = Some(format!("echo mismatch around byte {received}"));
                    break;
                }
                hasher.update(&buf[..n]);
                received += n as u64;
                if received >= bytes {
                    echoed.notify_waiters();
                    echoed.notify_one();
                }
            }
            Err(e) => {
                result.error = Some(format!("read: {e}"));
                break;
            }
        }
    }
    // Let a writer that is still waiting for the echo finish, whatever went wrong.
    echoed.notify_waiters();
    echoed.notify_one();

    result.received = received;
    result.sha256 = hex::encode(hasher.finalize());
    match writer.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            result.error.get_or_insert(e);
        }
        Err(e) => {
            result.error.get_or_insert(format!("writer task: {e}"));
        }
    }
    if result.error.is_none() && received != bytes {
        result.error = Some(format!("echo ended after {received} of {bytes} bytes"));
    }
    result.ok = result.error.is_none() && result.sha256 == expected_sha256;
    let _ = stream.close().await;
    result
}

/// A Rust smux echo server: one smux session per accepted TCP connection, every stream echoed
/// with kcptun's `std.Pipe` half-close order. It stops when dropped.
// Go: tools/gointerop/cmd/smuxecho/main.go:runServer / serveConn / echoStream
pub struct RustEchoServer {
    addr: SocketAddr,
    connections: Arc<AtomicU64>,
    /// Carries the `accept` error that ended the accept loop, like Go's `runServer` returning
    /// 1 after `log.Println("accept:", err)`.
    stopped: watch::Receiver<Option<String>>,
    task: JoinHandle<()>,
}

impl RustEchoServer {
    /// Binds `listen` and serves until the server is dropped.
    pub async fn start(listen: SocketAddr, settings: &SmuxSettings) -> Result<Self, String> {
        let listener = {
            // Serialised against process spawning; see `kcptun_testkit::socket_creation_guard`.
            let guard = kcptun_testkit::socket_creation_guard();
            let std_listener =
                std::net::TcpListener::bind(listen).map_err(|e| format!("bind {listen}: {e}"))?;
            std_listener
                .set_nonblocking(true)
                .map_err(|e| e.to_string())?;
            drop(guard);
            TcpListener::from_std(std_listener).map_err(|e| e.to_string())?
        };
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        let connections = Arc::new(AtomicU64::new(0));
        let config = settings.config();
        let (stopped_tx, stopped) = watch::channel(None);
        let task = {
            let connections = Arc::clone(&connections);
            tokio::spawn(async move {
                loop {
                    let (conn, _peer) = match listener.accept().await {
                        Ok(accepted) => accepted,
                        Err(e) => {
                            let _ = stopped_tx.send(Some(format!("accept: {e}")));
                            return;
                        }
                    };
                    connections.fetch_add(1, Ordering::Relaxed);
                    let Ok(session) = kcptun_smux::mux::server(SplitConn::tcp(conn), Some(config))
                    else {
                        continue;
                    };
                    tokio::spawn(serve_session(session));
                }
            })
        };
        Ok(RustEchoServer {
            addr,
            connections,
            stopped,
            task,
        })
    }

    /// The address the server listens on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// How many connections have been accepted.
    pub fn connections(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }

    /// Resolves when the accept loop ends, with the `accept` error that ended it. Go's
    /// `runServer` logs that error and returns 1; a long-running Rust peer awaits this so it
    /// fails the same way instead of idling with no listener.
    // Go: tools/gointerop/cmd/smuxecho/main.go:runServer() accept error path
    pub async fn stopped(&self) -> String {
        let mut rx = self.stopped.clone();
        loop {
            let current = rx.borrow_and_update().clone();
            if let Some(message) = current {
                return message;
            }
            if rx.changed().await.is_err() {
                return "accept: loop ended".to_string();
            }
        }
    }
}

impl Drop for RustEchoServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Accepts and echoes every stream of one session (Go's `serveConn`).
async fn serve_session(session: Session<SplitConn<TcpStream>>) {
    loop {
        match session.accept_stream().await {
            Ok(stream) => {
                tokio::spawn(echo_stream(stream));
            }
            Err(_) => return,
        }
    }
}

/// kcptun's `std.Pipe` order: copy until the peer's FIN, then `CloseWrite`, then `Close`.
///
/// Go's `io.Copy(s, s)` takes the `io.WriterTo` fast path: `*smux.Stream` embeds `*stream`,
/// which implements `WriteTo`, so `io.Copy` allocates no 32 KiB copy buffer and hands each
/// received frame buffer straight to `Write`. [`Stream::read_chunk`] + [`Stream::write_bytes`]
/// is that same path here, so an idle echo stream costs no per-stream buffer.
// Go: tools/gointerop/cmd/smuxecho/main.go:echoStream -> io.Copy takes smux Stream's WriteTo
// fast path (smux@v1.5.55 stream.go:stream.WriteTo())
async fn echo_stream(stream: Stream) {
    while let Ok(Some(chunk)) = stream.read_chunk().await {
        if stream.write_bytes(&chunk).await.is_err() {
            break;
        }
    }
    let _ = stream.close_write().await;
    let _ = stream.close().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_report_from_mixed_output() {
        let out = "smuxecho: remote address: 127.0.0.1:1\n\
            {\"ok\":true,\"ver\":1,\"streams\":1,\"bytes_per_stream\":10,\"total_bytes\":10,\
            \"duration_ms\":3,\"results\":[{\"index\":0,\"id\":3,\"seed\":5,\"received\":10,\
            \"sha256\":\"ab\",\"ok\":true}]}\n";
        let r = SmuxEchoReport::from_output(out).expect("report");
        assert!(r.ok);
        assert_eq!(r.ver, 1);
        assert_eq!(r.results.len(), 1);
        assert_eq!(r.results[0].id, 3);
        assert_eq!(r.error, None);

        let bad = "{\"ok\":false,\"ver\":2,\"streams\":1,\"bytes_per_stream\":10,\
            \"total_bytes\":10,\"duration_ms\":1,\"error\":\"read: timeout\",\"results\":[]}";
        let r = SmuxEchoReport::from_output(bad).expect("report");
        assert!(!r.ok);
        assert_eq!(r.error.as_deref(), Some("read: timeout"));
        assert_eq!(SmuxEchoReport::from_output("no json\n{broken"), None);
    }

    #[test]
    fn settings_match_kcptun_flags_and_config() {
        let s = SmuxSettings::default().version(1).framesize(1024);
        assert_eq!(
            s.args(),
            [
                "-ver",
                "1",
                "-smuxbuf",
                "4194304",
                "-streambuf",
                "2097152",
                "-framesize",
                "1024",
                "-keepalive",
                "10"
            ]
        );
        let cfg = s.config();
        assert_eq!(cfg.version, 1);
        assert_eq!(cfg.max_frame_size, 1024);
        assert_eq!(cfg.max_receive_buffer, 4194304);
        assert_eq!(cfg.max_stream_buffer, 2097152);
        assert_eq!(cfg.keep_alive_interval, Duration::from_secs(10));
        // kcptun's BuildSmuxConfig never sets KeepAliveTimeout, so it keeps smux
        // DefaultConfig()'s 30 s whatever -keepalive is.
        assert_eq!(cfg.keep_alive_timeout, Duration::from_secs(30));
        assert_eq!(
            SmuxSettings {
                keepalive_secs: 5,
                ..s
            }
            .config()
            .keep_alive_timeout,
            Duration::from_secs(30),
            "the timeout does not follow the interval"
        );
        kcptun_smux::mux::verify_config(&cfg).expect("kcptun's settings verify");
    }

    #[test]
    fn client_run_args() {
        let run = ClientRun::new("127.0.0.1:22001".parse().expect("addr"), 4, 1024).seed(7);
        assert_eq!(
            run.args(),
            [
                "-remote",
                "127.0.0.1:22001",
                "-streams",
                "4",
                "-bytes",
                "1024",
                "-seed",
                "7",
                "-chunk",
                "32768",
                "-timeout",
                "120"
            ]
        );
    }
}
