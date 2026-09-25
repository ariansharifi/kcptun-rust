//! Tests for the server binary (plan step 09.1).
//!
//! The startup block is compared against the output of the pinned Go binary
//! (`reference/bin/server_darwin_arm64 -l :29900`), captured with the timestamp and `file:line`
//! header turned off; step 09.5 turns that comparison into a live differential test over ~30
//! command lines.
//!
//! The end-to-end cases drive the real accept path: KCP listener → `UDPSession` →
//! `CompStream` → smux → target dial → `pipe`, from an in-process KCP client, so a regression
//! anywhere between the listener and the target socket fails here rather than in step 09.3.

use std::io::Write as _;
use std::sync::{Mutex, MutexGuard};

use kcptun_kcp::UdpSession;
use kcptun_smux::{Session, SmuxConn};
use kcptun_std::config::ServerConfig;
use kcptun_testkit::servers::{EchoServer, PrngStream};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;

// ---------------------------------------------------------------------------------------
// Capturing the process-wide logger
// ---------------------------------------------------------------------------------------

/// Serialises the tests that redirect the process-wide logger **and** every test that can make
/// the server log.
///
/// `log::set_output` swaps the sink for the whole process, so a `serve_listener` running in
/// another test's runtime would otherwise drop its `remote address:` and
/// `smux version: … on connection:` lines into whatever capture happens to be open. Both kinds of
/// test take this lock, which is why the end-to-end cases below are plain `#[test]`s driving
/// their own runtime rather than `#[tokio::test]`s: the guard is held across `block_on` from
/// synchronous code, never across an `await`.
static LOG_LOCK: Mutex<()> = Mutex::new(());

/// Runs `fut` on a two-worker runtime while holding [`LOG_LOCK`].
fn run_locked(fut: impl Future<Output = ()>) {
    let _guard: MutexGuard<'_, ()> = LOG_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let rt = runtime::build_with(2).expect("runtime");
    rt.block_on(fut);
}

/// A `log.SetOutput` sink that keeps what was written.
#[derive(Clone)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("sink").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Sink {
    /// What has been written so far, split into lines.
    fn lines(&self) -> Vec<String> {
        let bytes = self.0.lock().expect("sink").clone();
        String::from_utf8(bytes)
            .expect("log output is utf-8")
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Whether a line beginning with `prefix` has been written yet.
    fn has_line_starting_with(&self, prefix: &str) -> bool {
        self.lines().iter().any(|line| line.starts_with(prefix))
    }
}

/// Runs `f` with the logger redirected and its header turned off, and returns the lines it
/// wrote.
fn capture_log(f: impl FnOnce()) -> Vec<String> {
    capture_log_with(|_| f())
}

/// [`capture_log`], handing `f` the sink so it can wait for a line instead of sleeping.
fn capture_log_with(f: impl FnOnce(Sink)) -> Vec<String> {
    let _guard: MutexGuard<'_, ()> = LOG_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let sink = Sink(Arc::new(Mutex::new(Vec::new())));
    let flags = log::flags();
    log::set_flags(0);
    log::set_output(Box::new(sink.clone()));
    f(sink.clone());
    let _ = std::io::stderr().flush();
    log::set_output_stderr();
    log::set_flags(flags);
    sink.lines()
}

// ---------------------------------------------------------------------------------------
// Startup block
// ---------------------------------------------------------------------------------------

/// `reference/bin/server_darwin_arm64 -l :29900 -t 127.0.0.1:12948`, with the log header
/// stripped. `snmplog:` really does end in a space: `log.Println("snmplog:", "")`.
const GO_STARTUP_DEFAULTS: &[&str] = &[
    "version: SELFBUILD",
    "smux version: 2",
    "listening on: :29900",
    "target: 127.0.0.1:12948",
    "encryption: aes",
    "QPP: false",
    "QPP Count: 61",
    "nodelay parameters: 0 30 2 1",
    "sndwnd: 1024 rcvwnd: 1024",
    "compression: true",
    "mtu: 1350",
    "ratelimit: 0",
    "datashard: 10 parityshard: 3",
    "acknodelay: false",
    "dscp: 0",
    "sockbuf: 4194304",
    "smuxbuf: 4194304",
    "framesize: 8192",
    "streambuf: 2097152",
    "keepalive: 10",
    "snmplog: ",
    "snmpperiod: 60",
    "pprof: false",
    "quiet: false",
    "tcp: false",
];

#[test]
fn startup_log_matches_the_go_binary_with_the_defaults() {
    let mut config = ServerConfig::defaults();
    // Go applies the mode preset before the block: -mode fast is 0 30 2 1, not -interval 50.
    config.base.apply_mode();
    let lines = capture_log(|| log_startup(&config));
    assert_eq!(lines, GO_STARTUP_DEFAULTS);
}

#[test]
fn startup_log_reports_the_configured_values() {
    let mut config = ServerConfig::defaults();
    config.listen = ":29900-29905".to_string();
    config.target = "/tmp/kcptun.sock".to_string();
    config.base.mode = "manual".to_string();
    config.base.no_delay = 1;
    config.base.interval = 10;
    config.base.resend = 2;
    config.base.no_congestion = 1;
    config.base.no_comp = true;
    config.base.qpp = true;
    config.base.qpp_count = 7;
    config.base.tcp = true;
    config.base.quiet = true;
    config.base.snmp_log = "./snmp-20060102.log".to_string();
    config.base.apply_mode();

    let lines = capture_log(|| log_startup(&config));
    assert_eq!(lines[2], "listening on: :29900-29905");
    assert_eq!(lines[3], "target: /tmp/kcptun.sock");
    assert_eq!(lines[5], "QPP: true");
    assert_eq!(lines[6], "QPP Count: 7");
    // manual keeps the explicit nodelay parameters.
    assert_eq!(lines[7], "nodelay parameters: 1 10 2 1");
    assert_eq!(lines[9], "compression: false");
    assert_eq!(lines[20], "snmplog: ./snmp-20060102.log");
    assert_eq!(lines[23], "quiet: true");
    assert_eq!(lines[24], "tcp: true");
    assert_eq!(lines.len(), GO_STARTUP_DEFAULTS.len());
}

// ---------------------------------------------------------------------------------------
// Target classification and dial errors
// ---------------------------------------------------------------------------------------

#[test]
fn the_target_is_tcp_when_it_splits_into_host_and_port() {
    let target_type = |target: &str| {
        if goaddr::is_host_port(target) {
            TargetType::Tcp
        } else {
            TargetType::Unix
        }
    };
    assert_eq!(target_type("127.0.0.1:12948"), TargetType::Tcp);
    assert_eq!(target_type("[::1]:12948"), TargetType::Tcp);
    assert_eq!(target_type("example.com:80"), TargetType::Tcp);
    assert_eq!(target_type("/var/run/kcptun.sock"), TargetType::Unix);
    assert_eq!(target_type("kcptun.sock"), TargetType::Unix);
}

#[test]
fn dial_errors_read_like_gos_net_operror() {
    let refused = io::Error::from(io::ErrorKind::ConnectionRefused);
    assert_eq!(
        dial_error("tcp", "127.0.0.1:12948", Some(&refused)),
        "dial tcp 127.0.0.1:12948: connect: connection refused"
    );
    assert_eq!(
        dial_error("unix", "/tmp/x.sock", None),
        "dial unix /tmp/x.sock: i/o timeout"
    );
}

/// `reference/bin/server_darwin_arm64 -l 127.0.0.1:24999` against a held port prints
/// `listen udp 127.0.0.1:24999: bind: address already in use`. (Go's `checkError` uses `%+v`, so
/// the `errors.WithStack` around it also prints a 14-line Go stack trace afterwards; this port
/// logs the message line only: a deviation still awaiting its own entry in docs/DECISIONS.md.)
#[test]
fn listen_failures_read_like_gos_net_operror() {
    let in_use = io::Error::from_raw_os_error(libc::EADDRINUSE);
    assert_eq!(
        listen_error("127.0.0.1:24999", &in_use),
        "listen udp 127.0.0.1:24999: bind: address already in use"
    );
    // Go's OpError carries the resolved *net.UDPAddr, not the flag text.
    assert_eq!(
        listen_error("localhost:24999", &in_use),
        "listen udp 127.0.0.1:24999: bind: address already in use"
    );
    // A wildcard host resolves to a nil IP, which Go prints as an empty host.
    assert_eq!(
        listen_error(":24999", &in_use),
        "listen udp :24999: bind: address already in use"
    );
    // ResolveUDPAddr's own failures reach checkError unwrapped.
    let no_port = kcptun_kcp::addr::resolve_udp_addr("udp", "127.0.0.1")
        .expect_err("a port is required")
        .to_string();
    assert_eq!(no_port, "address 127.0.0.1: missing port in address");
    assert_eq!(
        listen_error("127.0.0.1", &io::Error::other(no_port.clone())),
        no_port
    );
}

/// `reference/bin/server_darwin_arm64 -l :24909 -sockbuf 999999999999` prints
/// `SetReadBuffer: set udp [::]:24909: setsockopt: invalid argument`.
#[test]
fn socket_option_failures_read_like_gos_net_operror() {
    let rt = runtime::build_with(1).expect("runtime");
    let _enter = rt.enter();
    let lis = Listener::listen_with_options("127.0.0.1:0", None, 0, 0).expect("kcp listener");
    let port = lis.addr().expect("listen addr").port();
    assert_eq!(
        setsockopt_error(
            "udp",
            lis.addr().ok(),
            &io::Error::from_raw_os_error(libc::EINVAL)
        ),
        format!("set udp 127.0.0.1:{port}: setsockopt: invalid argument")
    );
    // Go's `errInvalidOperation` is not a syscall error and is logged bare.
    assert_eq!(
        setsockopt_error(
            "udp",
            lis.addr().ok(),
            &io::Error::other("invalid operation")
        ),
        "invalid operation"
    );
    let _ = lis.close();
}

/// Go's `*net.OpError` names the address `net.DialTimeout` actually tried, not the `-t` text:
/// `server_darwin_arm64 -t localhost:12948` logs `dial tcp [::1]:12948: connect: connection
/// refused`.
#[test]
fn a_hostname_target_reports_the_address_it_dialled() {
    let rt = runtime::build_with(1).expect("runtime");
    // Nothing listens on port 1, and `localhost` resolves from the hosts file, not the network.
    let err = rt
        .block_on(dial_tcp("localhost:1"))
        .expect_err("port 1 is not open");
    assert!(
        err.starts_with("dial tcp 127.0.0.1:1: connect:")
            || err.starts_with("dial tcp [::1]:1: connect:"),
        "the resolved address should be named, got {err:?}"
    );
}

#[test]
fn a_dial_failure_is_logged_and_does_not_take_the_process_down() {
    let lines = capture_log(|| {
        logln!(dial_error(
            "tcp",
            "127.0.0.1:1",
            Some(&io::Error::from(io::ErrorKind::ConnectionRefused))
        ));
    });
    assert_eq!(lines, ["dial tcp 127.0.0.1:1: connect: connection refused"]);
}

// ---------------------------------------------------------------------------------------
// The tcpraw listener (--tcp)
// ---------------------------------------------------------------------------------------

/// Off Linux there is no fake TCP at all: Go's stub answers `os not supported`, the server logs
/// that one line (`log.Println(err)`) and carries on with UDP only.
#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn the_tcpraw_listener_reports_gos_os_not_supported() {
    let Err(err) = tcpraw_listen(":29900").await else {
        panic!("tcpraw cannot listen on this platform");
    };
    assert_eq!(err.to_string(), "os not supported");
}

/// On Linux the listener is real, so this case only checks that a failure is reported rather
/// than being fatal, with an address that cannot be bound, so that nothing is listened on and
/// no iptables rule is touched whatever privileges the test runner happens to have.
///
/// 192.0.2.1 is TEST-NET-1 (RFC 5737) and is not one of this host's addresses: without
/// `CAP_NET_RAW` the raw socket fails with `EPERM`, and with it the bind fails with
/// `EADDRNOTAVAIL`. Either way `listen` gives up before it opens the TCP listener or shells out
/// to `iptables`. The privileged path is step 10.5's, in the netns lab.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_tcpraw_listener_reports_a_failure_instead_of_exiting() {
    let Err(err) = tcpraw_listen("192.0.2.1:29900").await else {
        panic!("192.0.2.1 is not an address of this host");
    };
    assert!(!err.to_string().is_empty(), "{err:?}");
}

// ---------------------------------------------------------------------------------------
// End to end: an in-process KCP client through the real accept path
// ---------------------------------------------------------------------------------------

/// The server configuration the end-to-end cases share.
fn e2e_config(target: String, no_comp: bool, smux_ver: i64, qpp: bool) -> ServerConfig {
    let mut config = ServerConfig::defaults();
    config.base.apply_mode();
    config.target = target;
    config.base.key = "it's a secrect".to_string();
    config.base.no_comp = no_comp;
    config.base.smux_ver = smux_ver;
    config.base.qpp = qpp;
    // No FEC and no crypto: this exercises the proxy, not the packet layer (step 05 covers it).
    config.base.data_shard = 0;
    config.base.parity_shard = 0;
    config.base.close_wait = 0;
    config.base.quiet = true;
    config
}

/// Opens one stream over `mux`, echoes `payload` through it and checks what comes back.
async fn echo_through<C: SmuxConn>(
    mux: &Session<C>,
    qpp: Option<Arc<QppPad>>,
    key: &[u8],
    payload: &[u8],
) {
    let stream = mux.open_stream().await.expect("open stream");
    let s = SmuxStream::new(stream);
    match qpp {
        #[cfg(feature = "qpp")]
        Some(pad) => {
            let mut s = kcptun_std::qpp::QppStream::new(s, pad, key);
            echo_roundtrip(&mut s, payload).await;
        }
        #[cfg(not(feature = "qpp"))]
        Some(pad) => match *pad {},
        None => {
            let _ = key;
            let mut s = s;
            echo_roundtrip(&mut s, payload).await;
        }
    }
}

/// Writes `payload`, reads exactly as many bytes back, and half-closes the stream.
///
/// The half-close is what makes the server side finish: Go's client ends every proxied stream
/// with `p1.Close()` (`client/main.go:handleClient`'s defer), whose `cmdFIN` is the EOF the
/// server's `pipe` is waiting for. Dropping the handle instead sends nothing, and a KCP session
/// that simply stops talking is not noticed until it times out, so without this the server's
/// `stream closed` line arrives seconds later, when the listener is torn down.
async fn echo_roundtrip<S>(s: &mut S, payload: &[u8])
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    s.write_all(payload).await.expect("write");
    s.flush().await.expect("flush");
    let mut got = vec![0u8; payload.len()];
    s.read_exact(&mut got).await.expect("read");
    assert_eq!(got, payload, "the target's echo came back changed");
    s.shutdown().await.expect("close write");
}

/// Runs one end-to-end case: a real listener served by [`serve_listener`], an echo target, and
/// an in-process KCP + smux client.
async fn tunnel_case(no_comp: bool, smux_ver: i64, qpp: bool, payload_len: usize) {
    let echo = EchoServer::start().await.expect("echo server");
    let config = e2e_config(echo.addr().to_string(), no_comp, smux_ver, qpp);
    let pad = qpp_pad(&config.base, qpp.then_some(61));
    assert_eq!(
        pad.is_some(),
        qpp,
        "the pad is built exactly when -QPP is on"
    );
    let key = config.base.key.clone();

    let listener = Listener::listen_with_options("127.0.0.1:0", None, 0, 0).expect("kcp listener");
    let listen_addr = listener.addr().expect("listen addr");
    let server = tokio::spawn(serve_listener(
        Arc::clone(&listener),
        pad.clone(),
        Arc::new(config),
    ));

    // The client side of kcptun, as step 09.2 will build it.
    let session =
        UdpSession::dial_with_options(&listen_addr.to_string(), None, 0, 0).expect("dial");
    session.set_stream_mode(true);
    session.set_write_delay(false);
    session.set_mtu(1350);
    session.set_window_size(1024, 1024);
    let smux_config: kcptun_smux::Config =
        smuxcfg::build_smux_config(smux_ver, 4194304, 2097152, 8192, 10)
            .expect("smux config")
            .into();
    let conn = KcpConn::new(session);
    let payload = PrngStream::to_vec(7, payload_len);

    if no_comp {
        let mux = kcptun_smux::client(conn, Some(smux_config)).expect("smux client");
        echo_through(&mux, pad.clone(), key.as_bytes(), &payload).await;
        // A second stream over the same session, as a real client multiplexes.
        echo_through(&mux, pad, key.as_bytes(), b"second").await;
        mux.close().await.expect("close mux");
    } else {
        let mux =
            kcptun_smux::client(CompStream::new(conn), Some(smux_config)).expect("smux client");
        echo_through(&mux, pad.clone(), key.as_bytes(), &payload).await;
        echo_through(&mux, pad, key.as_bytes(), b"second").await;
        mux.close().await.expect("close mux");
    }

    server.abort();
    let _ = listener.close();
    echo.shutdown().await;
}

#[test]
fn a_stream_reaches_the_target_with_compression() {
    run_locked(tunnel_case(false, 2, false, 128 * 1024));
}

#[test]
fn a_stream_reaches_the_target_without_compression() {
    run_locked(tunnel_case(true, 2, false, 128 * 1024));
}

#[test]
fn a_stream_reaches_the_target_over_smux_v1() {
    run_locked(tunnel_case(true, 1, false, 64 * 1024));
}

#[cfg(feature = "qpp")]
#[test]
fn a_stream_reaches_the_target_through_qpp() {
    run_locked(tunnel_case(false, 2, true, 128 * 1024));
}

#[cfg(feature = "qpp")]
#[test]
fn a_stream_reaches_the_target_through_qpp_without_compression() {
    run_locked(tunnel_case(true, 2, true, 64 * 1024));
}

/// The stream-level log lines, which log scrapers and step 09.5 depend on.
///
/// The logger is process-wide, so the whole exchange runs on a runtime of its own inside the
/// capture rather than on a `#[tokio::test]` runtime.
#[test]
fn the_stream_log_lines_are_gos() {
    let target = Arc::new(Mutex::new(String::new()));
    let target_out = Arc::clone(&target);

    let lines = capture_log_with(move |sink| {
        let rt = runtime::build_with(2).expect("runtime");
        rt.block_on(async move {
            let echo = EchoServer::start().await.expect("echo server");
            *target_out.lock().expect("target") = echo.addr().to_string();
            let config = Arc::new({
                let mut config = e2e_config(echo.addr().to_string(), true, 2, false);
                config.base.quiet = false;
                config
            });

            let listener =
                Listener::listen_with_options("127.0.0.1:0", None, 0, 0).expect("kcp listener");
            let listen_addr = listener.addr().expect("listen addr");
            let server = tokio::spawn(serve_listener(Arc::clone(&listener), None, config));

            let session =
                UdpSession::dial_with_options(&listen_addr.to_string(), None, 0, 0).expect("dial");
            session.set_stream_mode(true);
            let smux_config: kcptun_smux::Config =
                smuxcfg::build_smux_config(2, 4194304, 2097152, 8192, 10)
                    .expect("smux config")
                    .into();
            let mux =
                kcptun_smux::client(KcpConn::new(session), Some(smux_config)).expect("smux client");
            echo_through(&mux, None, b"", b"hello").await;
            mux.close().await.expect("close mux");
            // Wait for the server to log `stream closed` before the capture ends. The stream was
            // half-closed above, so this normally takes a few milliseconds; polling the sink
            // rather than sleeping a fixed amount keeps the assertion below deterministic on a
            // loaded machine.
            for _ in 0..500 {
                if sink.has_line_starting_with("stream closed in: ") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }

            server.abort();
            let _ = listener.close();
            echo.shutdown().await;
        });
    });

    let target = target.lock().expect("target").clone();
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("remote address: 127.0.0.1:")),
        "missing `remote address:` line in {lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("smux version: 2 on connection: 127.0.0.1:")),
        "missing `smux version: … on connection:` line in {lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("stream opened in: 127.0.0.1:")
                && l.ends_with(&format!("(3) out: {target}"))),
        "missing `stream opened` line in {lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("stream closed in: 127.0.0.1:")
                && l.ends_with(&format!("(3) out: {target}"))),
        "missing `stream closed` line in {lines:?}"
    );
}
