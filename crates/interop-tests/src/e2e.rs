//! End-to-end harness (plan step 09.3): the real `kcptun-client` and `kcptun-server` binaries on
//! loopback, with the test itself acting as the local application.
//!
//! Step 09.3 uses it Rust↔Rust; step 09.4's [`interop_matrix`](crate::interop_matrix) reuses it
//! with either implementation at either end, through
//! [`client_impl`](TunnelBuilder::client_impl) / [`server_impl`](TunnelBuilder::server_impl).
//!
//! ```text
//! test app ──TCP/unix──▶ kcptun-client ══KCP/UDP══▶ kcptun-server ──TCP/unix──▶ target server
//! ```
//!
//! | Item | Purpose |
//! |---|---|
//! | [`Tunnel`] / [`TunnelBuilder`] | spawn both binaries, wait until they listen, connect to the client |
//! | [`LocalStream`] | the application side of the tunnel, TCP or unix |
//! | [`ResponderServer`] | a target that answers only *after* the peer's EOF (half-close and `closewait`) |
//! | [`UnixEchoServer`] | an echo target on a unix socket (testkit's servers are TCP only) |
//! | [`serial_guard`] | runs the end-to-end tests one at a time |
//!
//! Every process is a [`Proc`], which kills and reaps on drop, so a panicking or timing-out test
//! leaves nothing running — there is no explicit kill on any path. Fixed UDP ports come from
//! [`kcptun_testkit::ports`] (`[22000, 29000)`, never below 4000, as `tools/lab/README.md` requires); the
//! client's local listener binds port 0 and the harness reads the port back out of its
//! `listening on:` line.
//!
//! **Serialisation.** [`serial_guard`] gives the whole file one tunnel at a time. That keeps the
//! timing assertions (`closewait`, `autoexpire`) honest on a loaded laptop, keeps the heavy cases
//! from sharing a machine, and closes the macOS file-descriptor race the
//! [`proc`](kcptun_testkit::proc) module documents: a child spawned by one test thread can
//! inherit a socket another thread is creating at that instant. Application connections are made
//! under [`socket_creation_guard`](kcptun_testkit::socket_creation_guard) for the same reason.
//!
//! The binaries are located by [`bins::bin`](crate::bins::bin); the Rust side prefers
//! `target/release`:
//!
//! ```sh
//! cargo build --release -p kcptun-client -p kcptun-server
//! cargo test -p kcptun-interop-tests --test e2e -- --ignored --nocapture
//! ```

use std::fmt;
use std::io;
use std::net::SocketAddr;
#[cfg(unix)]
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use kcptun_testkit::ports::{self, PortBlock};
use kcptun_testkit::proc::{Proc, ProcBuilder, ProcError};
use kcptun_testkit::servers::{PrngStream, write_prng_stream};
use kcptun_testkit::socket_creation_guard;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, MutexGuard, watch};
use tokio::task::JoinHandle;

use crate::bins::{BinNotFound, Impl, bin};
use crate::matrix::{Case, Side};

/// The address family every listener in this module binds.
pub const HOST: &str = "127.0.0.1";

/// How long a binary may take to print the line that says it is listening.
pub const START_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait after the server's `Listening on:` line before using the port.
///
/// Go logs that line *before* `kcp.ListenWithOptions` (`server/main.go:392-394`) and so does the
/// port, so the line means "about to bind", not "bound". Probing the port instead would be worse:
/// the probe's own bind could win the race and take the server down.
const BIND_SETTLE: Duration = Duration::from_millis(100);

/// Read size of the copies in this module.
const BUF_SIZE: usize = 64 * 1024;

/// First pause after a failed `accept` (e.g. `EMFILE`); doubles up to [`ACCEPT_BACKOFF_MAX`], as
/// in [`kcptun_testkit::servers`]. Without it a persistent accept error spins a core.
const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(5);
/// Longest pause between failed `accept`s.
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// How long [`connect_local`] keeps retrying an `EADDRNOTAVAIL`; see there. It covers a full
/// macOS `TIME_WAIT` (2 × `net.inet.tcp.msl`, 30 s by default) with room to spare, because that
/// is how long an exhausted ephemeral-port range takes to refill.
const CONNECT_RETRY_WINDOW: Duration = Duration::from_secs(45);
/// How long [`connect_local`] waits between those attempts.
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// One end-to-end case at a time; see the [module docs](self).
static SERIAL: Mutex<()> = Mutex::const_new(());

/// Takes the lock that serialises the end-to-end tests. Every test holds it for its whole body.
pub async fn serial_guard() -> MutexGuard<'static, ()> {
    SERIAL.lock().await
}

// ---------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------

/// Why a tunnel could not be started.
#[derive(Debug)]
pub enum StartError {
    /// A binary was not found (build it, or set `KCPTUN_RS_BIN_DIR`).
    Bin(BinNotFound),
    /// A process could not be spawned.
    Spawn(io::Error),
    /// A process died, or never printed the line that says it is listening.
    Log(ProcError),
    /// The `listening on:` line did not hold the address it was expected to hold.
    Parse(String),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartError::Bin(e) => write!(f, "{e}"),
            StartError::Spawn(e) => write!(f, "spawn: {e}"),
            StartError::Log(e) => write!(f, "{e}"),
            StartError::Parse(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for StartError {}

impl From<BinNotFound> for StartError {
    fn from(e: BinNotFound) -> Self {
        StartError::Bin(e)
    }
}

impl From<io::Error> for StartError {
    fn from(e: io::Error) -> Self {
        StartError::Spawn(e)
    }
}

impl From<ProcError> for StartError {
    fn from(e: ProcError) -> Self {
        StartError::Log(e)
    }
}

// ---------------------------------------------------------------------------------------
// The tunnel
// ---------------------------------------------------------------------------------------

/// What the client's `-localaddr` should be.
#[derive(Clone, Debug)]
enum LocalSpec {
    /// `127.0.0.1:0`; the bound port is read back from the `listening on:` line.
    Tcp,
    /// A unix socket path.
    #[cfg(unix)]
    Unix(PathBuf),
}

/// Where an application connects to reach the tunnel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalEndpoint {
    /// The address the client's TCP listener bound.
    Tcp(SocketAddr),
    /// The client's unix socket path.
    #[cfg(unix)]
    Unix(PathBuf),
}

/// Builder for a [`Tunnel`]. Start with [`Tunnel::builder`].
#[derive(Clone, Debug)]
pub struct TunnelBuilder {
    client_case: Case,
    server_case: Case,
    client_impl: Impl,
    server_impl: Impl,
    key: String,
    target: String,
    ports: u16,
    local: LocalSpec,
    client_args: Vec<String>,
    server_args: Vec<String>,
}

impl TunnelBuilder {
    /// Sets the wire configuration both sides are given (`-crypt`, `-mode`, FEC, `-smuxver`,
    /// `-mtu`, `-nocomp`, `-QPP`, `-conn`).
    pub fn case(self, case: Case) -> Self {
        self.client_case(case.clone()).server_case(case)
    }

    /// Sets the client's configuration alone (step 09.4 runs a deliberate FEC mismatch).
    pub fn client_case(mut self, case: Case) -> Self {
        self.client_case = case;
        self
    }

    /// Sets the server's configuration alone.
    pub fn server_case(mut self, case: Case) -> Self {
        self.server_case = case;
        self
    }

    /// Which implementation provides `kcptun-client` (default [`Impl::Rust`]).
    pub fn client_impl(mut self, which: Impl) -> Self {
        self.client_impl = which;
        self
    }

    /// Which implementation provides `kcptun-server` (default [`Impl::Rust`]).
    pub fn server_impl(mut self, which: Impl) -> Self {
        self.server_impl = which;
        self
    }

    /// The `-key` both sides are given (QPP wants at least 211 bytes; see step 09.4).
    pub fn key(mut self, key: impl Into<String>) -> Self {
        self.key = key.into();
        self
    }

    /// Uses a range of `n` consecutive UDP ports (kcptun's `host:min-max` syntax) instead of one.
    pub fn udp_ports(mut self, n: u16) -> Self {
        self.ports = n;
        self
    }

    /// Makes the client listen on a unix socket instead of TCP. The caller owns the directory.
    #[cfg(unix)]
    pub fn local_unix(mut self, path: impl Into<PathBuf>) -> Self {
        self.local = LocalSpec::Unix(path.into());
        self
    }

    /// Appends flags to the client's command line.
    pub fn client_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.client_args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Appends flags to the server's command line.
    pub fn server_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.server_args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Appends flags to both command lines.
    pub fn both_args<I, S>(self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let args: Vec<String> = args.into_iter().map(Into::into).collect();
        self.client_args(args.clone()).server_args(args)
    }

    /// Spawns both binaries and waits until each one is listening.
    pub async fn start(self) -> Result<Tunnel, StartError> {
        let server_bin = bin(self.server_impl, "server")?;
        let client_bin = bin(self.client_impl, "client")?;
        let block = ports::allocate(self.ports);
        let listen = format!("{HOST}:{}", block.range_spec());

        let mut server_args = vec![
            "-l".to_string(),
            listen.clone(),
            "-t".to_string(),
            self.target.clone(),
            "-key".to_string(),
            self.key.clone(),
        ];
        server_args.extend(self.server_case.args(Side::Server));
        server_args.extend(self.server_args.iter().cloned());
        let server_builder = ProcBuilder::new(&server_bin)
            .name(format!("kcptun-server ({})", self.server_impl))
            .args(&server_args)
            // The key is a flag here; an inherited KCPTUN_KEY would only confuse a failure.
            .env_remove("KCPTUN_KEY");
        // The last port is logged last, so its line means every listener of the range is up.
        let server_ready = format!("Listening on: {HOST}:{}/udp", block.last());
        let server = spawn_listening(&server_builder, &server_ready).await?;

        let local_arg = match &self.local {
            LocalSpec::Tcp => format!("{HOST}:0"),
            #[cfg(unix)]
            LocalSpec::Unix(path) => path.display().to_string(),
        };
        let mut client_args = vec![
            "-l".to_string(),
            local_arg,
            "-r".to_string(),
            listen.clone(),
            "-key".to_string(),
            self.key.clone(),
        ];
        client_args.extend(self.client_case.args(Side::Client));
        client_args.extend(self.client_args.iter().cloned());
        let mut client = ProcBuilder::new(&client_bin)
            .name(format!("kcptun-client ({})", self.client_impl))
            .args(&client_args)
            .env_remove("KCPTUN_KEY")
            .spawn()?;
        let line = client
            .wait_for_log_line_async("listening on:", START_TIMEOUT)
            .await?;
        let local = parse_local(&line, &self.local)?;

        Ok(Tunnel {
            server,
            client,
            local,
            listen,
            block,
            server_builder,
            server_ready,
            client_impl: self.client_impl,
            server_impl: self.server_impl,
        })
    }
}

/// Spawns `builder` and waits for the line that says it is listening.
async fn spawn_listening(builder: &ProcBuilder, ready: &str) -> Result<Proc, StartError> {
    let mut proc = builder.clone().spawn()?;
    proc.wait_for_log_line_async(ready, START_TIMEOUT).await?;
    // The line precedes the bind (see BIND_SETTLE).
    tokio::time::sleep(BIND_SETTLE).await;
    Ok(proc)
}

/// Reads the address the client bound out of its `listening on:` line.
fn parse_local(line: &str, spec: &LocalSpec) -> Result<LocalEndpoint, StartError> {
    let addr = line
        .split_once("listening on: ")
        .map(|(_, rest)| rest.trim())
        .ok_or_else(|| StartError::Parse(format!("no address in {line:?}")))?;
    match spec {
        LocalSpec::Tcp => addr
            .parse::<SocketAddr>()
            .map(LocalEndpoint::Tcp)
            .map_err(|e| StartError::Parse(format!("listening on: {addr:?}: {e}"))),
        #[cfg(unix)]
        LocalSpec::Unix(path) => {
            if Path::new(addr) == path {
                Ok(LocalEndpoint::Unix(path.clone()))
            } else {
                Err(StartError::Parse(format!(
                    "client listens on {addr:?}, expected {}",
                    path.display()
                )))
            }
        }
    }
}

/// A running `kcptun-client` and `kcptun-server` pair. Both processes are killed and reaped when
/// this value is dropped, including when a test panics or times out.
#[derive(Debug)]
pub struct Tunnel {
    server: Proc,
    client: Proc,
    local: LocalEndpoint,
    listen: String,
    block: PortBlock,
    server_builder: ProcBuilder,
    server_ready: String,
    client_impl: Impl,
    server_impl: Impl,
}

impl Tunnel {
    /// A tunnel to `target` (a `host:port` or, on unix, a socket path) with kcptun's defaults,
    /// Rust on both ends.
    pub fn builder(target: impl Into<String>) -> TunnelBuilder {
        TunnelBuilder {
            client_case: Case::new(),
            server_case: Case::new(),
            client_impl: Impl::Rust,
            server_impl: Impl::Rust,
            key: "kcptun-rust e2e".to_string(),
            target: target.into(),
            ports: 1,
            local: LocalSpec::Tcp,
            client_args: Vec::new(),
            server_args: Vec::new(),
        }
    }

    /// Which implementation runs the client.
    pub fn client_impl(&self) -> Impl {
        self.client_impl
    }

    /// Which implementation runs the server.
    pub fn server_impl(&self) -> Impl {
        self.server_impl
    }

    /// Where an application connects to reach the tunnel.
    pub fn local(&self) -> &LocalEndpoint {
        &self.local
    }

    /// The server's `-l` / client's `-r` value, e.g. `127.0.0.1:22000-22004`.
    pub fn listen_spec(&self) -> &str {
        &self.listen
    }

    /// The UDP ports the server listens on.
    pub fn udp_ports(&self) -> PortBlock {
        self.block
    }

    /// Connects to the client as an application would.
    pub async fn connect(&self) -> io::Result<LocalStream> {
        connect_local(&self.local).await
    }

    /// The server process.
    pub fn server(&mut self) -> &mut Proc {
        &mut self.server
    }

    /// The client process.
    pub fn client(&mut self) -> &mut Proc {
        &mut self.client
    }

    /// Everything the server has logged so far.
    pub fn server_log(&self) -> String {
        self.server.log()
    }

    /// Everything the client has logged so far.
    pub fn client_log(&self) -> String {
        self.client.log()
    }

    /// Kills the server, as an operator restarting it would.
    pub fn stop_server(&mut self) -> io::Result<()> {
        self.server.kill().map(drop)
    }

    /// Starts a new server with the same command line (and so the same ports).
    pub async fn start_server(&mut self) -> Result<(), StartError> {
        self.server = spawn_listening(&self.server_builder, &self.server_ready).await?;
        Ok(())
    }

    /// Fails if either process has exited or logged a Rust panic.
    pub fn check_alive(&mut self) -> Result<(), String> {
        for (what, proc) in [("server", &mut self.server), ("client", &mut self.client)] {
            if let Ok(Some(status)) = proc.try_wait() {
                return Err(format!("{what} exited ({status}):\n{}", proc.log_tail()));
            }
            let log = proc.log();
            let panics = panic_lines(&log);
            if !panics.is_empty() {
                return Err(format!("{what} panicked:\n{}", panics.join("\n")));
            }
        }
        Ok(())
    }
}

/// The lines of `log` that look like a Rust panic.
pub fn panic_lines(log: &str) -> Vec<&str> {
    log.lines()
        .filter(|l| l.contains("panicked at") || l.contains("fatal runtime error"))
        .collect()
}

/// The text following `prefix` on every log line that contains it, in order.
///
/// `log_values(&tunnel.server_log(), "remote address: ")` is the list of KCP peers the server
/// accepted.
pub fn log_values<'a>(log: &'a str, prefix: &str) -> Vec<&'a str> {
    log.lines()
        .filter_map(|l| l.split_once(prefix).map(|(_, rest)| rest.trim()))
        .collect()
}

/// The `(local, remote)` pairs of the `smux version: N on connection: L -> R` lines, i.e. one
/// entry per KCP session the client brought up.
pub fn session_endpoints(log: &str) -> Vec<(String, String)> {
    log_values(log, "on connection: ")
        .into_iter()
        .filter_map(|rest| rest.split_once(" -> "))
        .map(|(l, r)| (l.trim().to_string(), r.trim().to_string()))
        .collect()
}

// ---------------------------------------------------------------------------------------
// The application side
// ---------------------------------------------------------------------------------------

/// The application end of the tunnel: the connection to `kcptun-client`.
#[derive(Debug)]
pub enum LocalStream {
    /// A TCP connection to the client's `-localaddr`.
    Tcp(TcpStream),
    /// A unix connection to the client's `-localaddr`.
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
}

impl AsyncRead for LocalStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            LocalStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(unix)]
            LocalStream::Unix(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for LocalStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            LocalStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(unix)]
            LocalStream::Unix(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            LocalStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            #[cfg(unix)]
            LocalStream::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    /// `shutdown(2)` on the write side — the half-close the application performs.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            LocalStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(unix)]
            LocalStream::Unix(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Connects to `endpoint` with the socket created under
/// [`socket_creation_guard`](kcptun_testkit::socket_creation_guard), so a `kcptun-*` process
/// spawned at that instant cannot inherit the connection and hold it open (macOS; see the
/// [module docs](self)).
///
/// `EADDRNOTAVAIL` is retried for [`CONNECT_RETRY_WINDOW`], [`CONNECT_RETRY_DELAY`] apart: a case
/// that opens thousands of connections can exhaust the platform's ephemeral port range (macOS
/// offers 16384 of them and holds each for a 30 s `TIME_WAIT`), and that is pressure from the test
/// itself, not a tunnel failure — the range refills on its own, so waiting is the right answer.
/// A range still full at the end of the window fails with the same error as before, and the test's
/// own timeout bounds the wait either way.
pub async fn connect_local(endpoint: &LocalEndpoint) -> io::Result<LocalStream> {
    let deadline = Instant::now() + CONNECT_RETRY_WINDOW;
    loop {
        match connect_local_once(endpoint).await {
            Err(e) if e.kind() == io::ErrorKind::AddrNotAvailable && Instant::now() < deadline => {
                tokio::time::sleep(CONNECT_RETRY_DELAY).await;
            }
            result => return result,
        }
    }
}

/// One [`connect_local`] attempt.
async fn connect_local_once(endpoint: &LocalEndpoint) -> io::Result<LocalStream> {
    match endpoint {
        LocalEndpoint::Tcp(addr) => {
            let addr = *addr;
            let sock = tokio::task::spawn_blocking(move || {
                let _fd = socket_creation_guard();
                let sock = std::net::TcpStream::connect(addr)?;
                sock.set_nodelay(true)?;
                sock.set_nonblocking(true)?;
                io::Result::Ok(sock)
            })
            .await
            .map_err(io::Error::other)??;
            Ok(LocalStream::Tcp(TcpStream::from_std(sock)?))
        }
        #[cfg(unix)]
        LocalEndpoint::Unix(path) => {
            let path = path.clone();
            let sock = tokio::task::spawn_blocking(move || {
                let _fd = socket_creation_guard();
                let sock = std::os::unix::net::UnixStream::connect(&path)?;
                sock.set_nonblocking(true)?;
                io::Result::Ok(sock)
            })
            .await
            .map_err(io::Error::other)??;
            Ok(LocalStream::Unix(tokio::net::UnixStream::from_std(sock)?))
        }
    }
}

/// Reads exactly `len` bytes and returns their lower-case hex SHA-256.
///
/// Unlike [`hash_reader`](kcptun_testkit::servers::hash_reader) this does not wait for EOF, so a
/// response can be checked while the tunnel is still tearing the stream down (`closewait`).
pub async fn hash_exact<R: AsyncRead + Unpin>(r: &mut R, len: u64) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut left = len;
    let mut buf = vec![0u8; BUF_SIZE];
    while left > 0 {
        let want = usize::try_from(left).unwrap_or(BUF_SIZE).min(BUF_SIZE);
        let n = r.read(&mut buf[..want]).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("truncated after {} of {len} bytes", len - left),
            ));
        }
        hasher.update(&buf[..n]);
        left -= n as u64;
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Fails unless the next read ends the stream.
pub async fn expect_eof<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<()> {
    let mut buf = [0u8; 64];
    match r.read(&mut buf).await? {
        0 => Ok(()),
        n => Err(io::Error::other(format!(
            "{n} unexpected bytes after the end of the response: {:?}",
            &buf[..n.min(16)]
        ))),
    }
}

/// Sends the `(seed, len)` [`PrngStream`], half-closes, and returns the SHA-256 of what came
/// back — the round trip an echo target completes.
pub async fn echo_round_trip<S>(stream: &mut S, seed: u64, len: u64) -> io::Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (mut r, mut w) = tokio::io::split(stream);
    let send = async {
        write_prng_stream(&mut w, seed, len).await?;
        w.shutdown().await
    };
    // Both halves run in this task; `tokio::spawn` would need a `'static` stream.
    let (written, sha) = tokio::join!(send, hash_exact(&mut r, len));
    // The read result leads — a truncated echo says more than the write error it causes — but the
    // write error is carried along rather than dropped: "the echo stopped at 0 bytes" and "the
    // request never went out" are very different failures, and only the second names a cause.
    match (sha, written) {
        (Ok(sha), Ok(())) => Ok(sha),
        (Ok(_), Err(w)) => Err(io::Error::new(w.kind(), format!("request: {w}"))),
        (Err(r), Ok(())) => Err(r),
        (Err(r), Err(w)) => Err(io::Error::new(r.kind(), format!("{r} (request: {w})"))),
    }
}

/// The SHA-256 an [`echo_round_trip`] of `(seed, len)` must return.
pub fn expected_sha256(seed: u64, len: u64) -> String {
    PrngStream::sha256_hex(seed, len)
}

// ---------------------------------------------------------------------------------------
// Target servers
// ---------------------------------------------------------------------------------------

/// Accept loop plumbing: the accept task and every connection task stop when this is dropped, and
/// each connection is `shutdown(2)`-ed rather than merely dropped (see [`split_closer_tcp`]).
#[derive(Debug)]
pub(crate) struct Acceptor {
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl Acceptor {
    /// Signals stop and waits for the accept task to end. The connection tasks are told to stop
    /// too, and shut their socket down as they go, but are not waited for.
    pub(crate) async fn shutdown(&mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for Acceptor {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

/// One connection of a [`ResponderServer`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponderRecord {
    /// Bytes of request received before the peer's EOF.
    pub request_bytes: u64,
    /// How long after the connection was accepted the peer's EOF arrived.
    pub eof_after: Duration,
}

/// A TCP target that reads the request **to EOF**, then sends the `(seed, len)`
/// [`PrngStream`] and closes.
///
/// This is the shape the plan's half-close case needs: the application shuts its write side while
/// the answer is still to come, so every response byte crosses a smux stream whose peer has
/// already sent FIN. It also measures `closewait`, which delays exactly that EOF.
#[derive(Debug)]
pub struct ResponderServer {
    addr: SocketAddr,
    seed: u64,
    len: u64,
    records: watch::Receiver<Vec<ResponderRecord>>,
    _acceptor: Acceptor,
}

impl ResponderServer {
    /// Starts the server on `127.0.0.1` with an ephemeral port.
    pub async fn start(seed: u64, len: u64) -> io::Result<Self> {
        let (rec_tx, records) = watch::channel(Vec::new());
        let rec_tx = Arc::new(rec_tx);
        let (listener, addr) = bind_tcp().await?;
        let acceptor = serve(listener, move |mut conn| {
            let rec_tx = Arc::clone(&rec_tx);
            async move {
                let started = Instant::now();
                let mut request_bytes = 0u64;
                let mut buf = vec![0u8; BUF_SIZE];
                loop {
                    match conn.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => request_bytes += n as u64,
                        // A reset before the request ended leaves no record.
                        Err(_) => return,
                    }
                }
                rec_tx.send_modify(|v| {
                    v.push(ResponderRecord {
                        request_bytes,
                        eof_after: started.elapsed(),
                    });
                });
                if write_prng_stream(&mut conn, seed, len).await.is_ok() {
                    let _ = conn.shutdown().await;
                }
                // Drain until the peer closes, so the response is never turned into a reset.
                let mut sink = [0u8; 1024];
                while matches!(conn.read(&mut sink).await, Ok(n) if n > 0) {}
            }
        });
        Ok(ResponderServer {
            addr,
            seed,
            len,
            records,
            _acceptor: acceptor,
        })
    }

    /// Listening address, as a `-t` value.
    pub fn target(&self) -> String {
        self.addr.to_string()
    }

    /// The SHA-256 a complete response hashes to.
    pub fn expected_sha256(&self) -> String {
        PrngStream::sha256_hex(self.seed, self.len)
    }

    /// Waits until `n` connections have reached the end of their request.
    pub async fn wait_for_records(
        &self,
        n: usize,
        timeout: Duration,
    ) -> io::Result<Vec<ResponderRecord>> {
        let mut rx = self.records.clone();
        match tokio::time::timeout(timeout, rx.wait_for(|v| v.len() >= n)).await {
            Ok(Ok(v)) => Ok(v.clone()),
            Ok(Err(_)) => Err(io::Error::other("responder stopped")),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "timed out after {timeout:?} waiting for {n} requests (have {})",
                    self.records.borrow().len()
                ),
            )),
        }
    }
}

/// An echo target on a unix socket; testkit's servers are TCP only.
///
/// A unix target also costs no ephemeral ports, which matters for the cases that open thousands
/// of streams — see `e2e_slow_one_thousand_short_streams`.
#[derive(Debug)]
#[cfg(unix)]
pub struct UnixEchoServer {
    path: PathBuf,
    connections: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
    acceptor: Acceptor,
}

#[cfg(unix)]
impl UnixEchoServer {
    /// Starts the server on `path`, which must not exist yet.
    pub async fn start(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let listener = {
            let _fd = socket_creation_guard();
            tokio::net::UnixListener::bind(&path)?
        };
        let connections = Arc::new(AtomicU64::new(0));
        let bytes = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&connections);
        let byte_counter = Arc::clone(&bytes);
        let (stop, mut stop_rx) = watch::channel(false);
        let conn_stop = stop.subscribe();
        let task = tokio::spawn(async move {
            let mut backoff = Duration::ZERO;
            loop {
                let accepted = tokio::select! {
                    _ = stop_rx.wait_for(|s| *s) => return,
                    r = listener.accept() => r,
                };
                let conn = match accepted {
                    Ok((conn, _)) => {
                        backoff = Duration::ZERO;
                        conn
                    }
                    Err(_) => {
                        // Back off instead of spinning (e.g. EMFILE), still honouring stop.
                        backoff = (backoff * 2).clamp(ACCEPT_BACKOFF_MIN, ACCEPT_BACKOFF_MAX);
                        tokio::select! {
                            _ = stop_rx.wait_for(|s| *s) => return,
                            () = tokio::time::sleep(backoff) => continue,
                        }
                    }
                };
                // A second handle to the socket, so stop really closes it even if a `kcptun-*`
                // process inherited a copy of the fd (macOS; see the module docs).
                let Ok((conn, closer)) = split_closer_unix(conn) else {
                    continue;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let echoed = Arc::clone(&byte_counter);
                let mut rx = conn_stop.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        _ = rx.wait_for(|s| *s) => {
                            let _ = closer.shutdown(std::net::Shutdown::Both);
                        }
                        () = echo(conn, echoed) => {}
                    }
                });
            }
        });
        Ok(UnixEchoServer {
            path,
            connections,
            bytes,
            acceptor: Acceptor {
                stop,
                task: Some(task),
            },
        })
    }

    /// Stops accepting and shuts every open connection down. Unlike
    /// [`EchoServer::shutdown`](kcptun_testkit::servers::EchoServer::shutdown) it does not wait
    /// for the connection tasks to finish, only for the accept task (see [`Acceptor::shutdown`]).
    pub async fn shutdown(mut self) {
        self.acceptor.shutdown().await;
    }

    /// The socket path, as a `-t` value.
    pub fn target(&self) -> String {
        self.path.display().to_string()
    }

    /// Connections accepted so far.
    pub fn connections(&self) -> u64 {
        self.connections.load(Ordering::SeqCst)
    }

    /// Bytes echoed so far.
    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::SeqCst)
    }
}

/// Echoes every byte back, counting them in `echoed`, then half-closes on the peer's EOF.
#[cfg(unix)]
async fn echo<S: AsyncRead + AsyncWrite + Unpin>(mut conn: S, echoed: Arc<AtomicU64>) {
    let mut buf = vec![0u8; BUF_SIZE];
    loop {
        match conn.read(&mut buf).await {
            Ok(0) => {
                let _ = conn.shutdown().await;
                return;
            }
            Ok(n) => {
                if conn.write_all(&buf[..n]).await.is_err() {
                    return;
                }
                echoed.fetch_add(n as u64, Ordering::SeqCst);
            }
            Err(_) => return,
        }
    }
}

/// Returns `conn` together with a duplicated std handle to the same socket, as
/// [`kcptun_testkit::servers`] does: dropping a tokio handle does not close an fd a child process
/// copied, but `shutdown(2)` on any handle takes the connection down.
fn split_closer_tcp(conn: TcpStream) -> io::Result<(TcpStream, std::net::TcpStream)> {
    let std_conn = conn.into_std()?;
    let closer = std_conn.try_clone()?;
    std_conn.set_nonblocking(true)?;
    Ok((TcpStream::from_std(std_conn)?, closer))
}

/// [`split_closer_tcp`] for a unix connection.
#[cfg(unix)]
fn split_closer_unix(
    conn: tokio::net::UnixStream,
) -> io::Result<(tokio::net::UnixStream, std::os::unix::net::UnixStream)> {
    let std_conn = conn.into_std()?;
    let closer = std_conn.try_clone()?;
    std_conn.set_nonblocking(true)?;
    Ok((tokio::net::UnixStream::from_std(std_conn)?, closer))
}

/// Binds a TCP listener on `127.0.0.1:0`, under the file-descriptor guard.
pub(crate) async fn bind_tcp() -> io::Result<(tokio::net::TcpListener, SocketAddr)> {
    let listener = {
        let _fd = socket_creation_guard();
        std::net::TcpListener::bind((HOST, 0))?
    };
    listener.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(listener)?;
    let addr = listener.local_addr()?;
    Ok((listener, addr))
}

/// Runs `handler` for every accepted connection until the [`Acceptor`] is dropped.
pub(crate) fn serve<F, Fut>(listener: tokio::net::TcpListener, handler: F) -> Acceptor
where
    F: Fn(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (stop, mut stop_rx) = watch::channel(false);
    let conn_stop = stop.subscribe();
    let task = tokio::spawn(async move {
        let mut backoff = Duration::ZERO;
        loop {
            let accepted = tokio::select! {
                _ = stop_rx.wait_for(|s| *s) => return,
                r = listener.accept() => r,
            };
            let conn = match accepted {
                Ok((conn, _)) => {
                    backoff = Duration::ZERO;
                    conn
                }
                Err(_) => {
                    // Back off instead of spinning (e.g. EMFILE), still honouring stop.
                    backoff = (backoff * 2).clamp(ACCEPT_BACKOFF_MIN, ACCEPT_BACKOFF_MAX);
                    tokio::select! {
                        _ = stop_rx.wait_for(|s| *s) => return,
                        () = tokio::time::sleep(backoff) => continue,
                    }
                }
            };
            let _ = conn.set_nodelay(true);
            // A second handle to the socket, so stop really closes it even if a `kcptun-*`
            // process inherited a copy of the fd (macOS; see the module docs).
            let Ok((conn, closer)) = split_closer_tcp(conn) else {
                continue;
            };
            let fut = handler(conn);
            let mut rx = conn_stop.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = rx.wait_for(|s| *s) => {
                        let _ = closer.shutdown(std::net::Shutdown::Both);
                    }
                    () = fut => {}
                }
            });
        }
    });
    Acceptor {
        stop,
        task: Some(task),
    }
}
