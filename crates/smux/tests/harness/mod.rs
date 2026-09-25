//! Shared fixtures for the ported Go smux tests (plan step 06.5).
//!
//! Go's `session_test.go` and `stream_test.go` run every test over a real TCP connection to a
//! server goroutine on `localhost:0` (`setupServer`, `getTCPConnectionPair`). The port runs the
//! same tests twice: once over [`tokio::io::duplex`], which is cheap and exercises the session
//! without a kernel in the way, and once over TCP loopback, which is what Go does. The
//! [`both_transports!`] and [`both_echo_servers!`] macros pair a generic test body with the two
//! transports.
//!
//! Go reference: `reference/latest/smux/session_test.go` (`setupServer`, `handleConnection`,
//! `setupServerV2`, `handleConnectionV2`, `getTCPConnectionPair`, `getSmuxStreamPair`).

#![allow(dead_code)] // each test binary uses a subset

use std::time::Duration;

use kcptun_smux::conn::{SmuxConn, SplitConn};
use kcptun_smux::mux::{Config, client, default_config, server};
use kcptun_smux::session::Session;
use kcptun_smux::stream::Stream;
use tokio::io::DuplexStream;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// Room for a whole `MaxReceiveBuffer` of frames, so an in-memory pipe never becomes the thing
/// under test.
pub const PIPE_CAPACITY: usize = 1 << 22;

/// How long a test waits for something that should happen straight away.
pub const PATIENCE: Duration = Duration::from_secs(20);

/// [`default_config`] with a protocol version; Go's `DefaultConfig()` plus `config.Version = v`.
pub fn config(version: isize) -> Config {
    Config {
        version,
        ..default_config()
    }
}

/// [`config`] with the keepalive turned off, for tests that must see only the frames they cause.
pub fn quiet_config(version: isize) -> Config {
    Config {
        keep_alive_disabled: true,
        ..config(version)
    }
}

/// Two sessions of the same configuration over one in-memory pipe (client first).
// Go: reference/latest/smux/session_test.go:getSmuxStreamPair (over net.Pipe / TCP)
pub fn duplex_pair(
    cfg: Config,
) -> (
    Session<SplitConn<DuplexStream>>,
    Session<SplitConn<DuplexStream>>,
) {
    let (ours, theirs) = tokio::io::duplex(PIPE_CAPACITY);
    let cli = client(SplitConn::new(ours), Some(cfg)).expect("client");
    let srv = server(SplitConn::new(theirs), Some(cfg)).expect("server");
    (cli, srv)
}

/// Two sessions of the same configuration over a TCP loopback connection (client first).
// Go: reference/latest/smux/session_test.go:getTCPConnectionPair
pub async fn tcp_pair(
    cfg: Config,
) -> (Session<SplitConn<TcpStream>>, Session<SplitConn<TcpStream>>) {
    let (a, b) = tcp_conn_pair().await;
    let cli = client(SplitConn::tcp(a), Some(cfg)).expect("client");
    let srv = server(SplitConn::tcp(b), Some(cfg)).expect("server");
    (cli, srv)
}

/// A connected pair of TCP loopback sockets.
// Go: reference/latest/smux/session_test.go:getTCPConnectionPair
pub async fn tcp_conn_pair() -> (TcpStream, TcpStream) {
    let listener = listen().await;
    let addr = listener.local_addr().expect("local addr");
    let accepted = tokio::spawn(async move { listener.accept().await });
    let dialed = TcpStream::connect(addr).await.expect("connect");
    let (accepted, _) = accepted.await.expect("join").expect("accept");
    (dialed, accepted)
}

/// A TCP listener on an ephemeral loopback port.
pub async fn listen() -> TcpListener {
    // Binding is serialised against process spawning; see `kcptun_testkit::socket_creation_guard`
    // (this crate spawns none, but the lock is process-wide and cheap).
    let guard = kcptun_testkit::socket_creation_guard();
    let std_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    std_listener.set_nonblocking(true).expect("nonblocking");
    drop(guard);
    TcpListener::from_std(std_listener).expect("from_std")
}

/// Echoes every stream of `session` until it fails, mirroring Go's `handleConnection`: read into
/// a 64 KiB buffer, write back what came in, stop on the first error.
// Go: reference/latest/smux/session_test.go:handleConnection / handleConnectionV2
pub fn spawn_echo_server<C: SmuxConn>(session: Session<C>) {
    tokio::spawn(async move {
        loop {
            match session.accept_stream().await {
                Ok(stream) => {
                    tokio::spawn(echo_stream(stream));
                }
                Err(_) => return,
            }
        }
    });
}

/// One echoed stream (Go's inner goroutine of `handleConnection`).
async fn echo_stream(stream: Stream) {
    let mut buf = vec![0u8; 65536];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if stream.write(&buf[..n]).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// A client session whose peer echoes every stream, over an in-memory pipe.
// Go: reference/latest/smux/session_test.go:setupServer
pub fn duplex_echo_client(cfg: Config) -> Session<SplitConn<DuplexStream>> {
    let (cli, srv) = duplex_pair(cfg);
    spawn_echo_server(srv);
    cli
}

/// A client session whose peer echoes every stream, over TCP loopback.
// Go: reference/latest/smux/session_test.go:setupServer
pub async fn tcp_echo_client(cfg: Config) -> Session<SplitConn<TcpStream>> {
    let (cli, srv) = tcp_pair(cfg).await;
    spawn_echo_server(srv);
    cli
}

/// A connected pair of streams (client side first), like Go's `getSmuxStreamPair`.
// Go: reference/latest/smux/session_test.go:getSmuxStreamPair
pub async fn stream_pair<C: SmuxConn>(cli: &Session<C>, srv: &Session<C>) -> (Stream, Stream) {
    let (opened, accepted) = tokio::join!(cli.open_stream(), srv.accept_stream());
    (opened.expect("open"), accepted.expect("accept"))
}

/// Reads exactly `want` bytes, failing on an early end of stream (Go's `io.ReadFull`).
pub async fn read_full(stream: &Stream, want: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(want);
    let mut buf = vec![0u8; 65536];
    while out.len() < want {
        let n = stream.read(&mut buf).await.expect("read");
        assert_ne!(n, 0, "unexpected EOF after {} of {want} bytes", out.len());
        out.extend_from_slice(&buf[..n]);
    }
    out
}

/// Reads until the end of the stream.
pub async fn read_to_end(stream: &Stream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 65536];
    loop {
        let n = stream.read(&mut buf).await.expect("read");
        if n == 0 {
            return out;
        }
        out.extend_from_slice(&buf[..n]);
    }
}

/// Polls `check` until it holds, so a test never sleeps longer than it must.
pub async fn wait_until(what: &str, mut check: impl FnMut() -> bool) {
    timeout(PATIENCE, async {
        while !check() {
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

/// Awaits `f`, failing the test if it takes longer than [`PATIENCE`].
pub async fn in_time<T>(what: &str, f: impl Future<Output = T>) -> T {
    timeout(PATIENCE, f)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

/// `n` deterministic pseudo-random bytes (the same stream the Go interop peers send).
pub fn payload(seed: u64, n: usize) -> Vec<u8> {
    kcptun_testkit::servers::PrngStream::to_vec(seed, n)
}

/// Runs a generic test body against a duplex pair and a TCP pair.
#[macro_export]
macro_rules! both_transports {
    ($cfg:expr, $body:ident) => {{
        let cfg = $cfg;
        let (cli, srv) = $crate::harness::duplex_pair(cfg);
        $body(cli, srv).await;
        let (cli, srv) = $crate::harness::tcp_pair(cfg).await;
        $body(cli, srv).await;
    }};
}

/// Runs a generic test body against a client session whose peer echoes, over both transports.
#[macro_export]
macro_rules! both_echo_servers {
    ($cfg:expr, $body:ident) => {{
        let cfg = $cfg;
        $body($crate::harness::duplex_echo_client(cfg)).await;
        $body($crate::harness::tcp_echo_client(cfg).await).await;
    }};
}
