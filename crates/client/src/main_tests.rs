//! Tests for the client binary (plan step 09.2).
//!
//! The startup block is compared against the output of the pinned Go binary
//! (`reference/bin/client_darwin_arm64 -l 127.0.0.1:24948 -r 127.0.0.1:29900`), captured with
//! the timestamp and `file:line` header turned off; step 09.5 turns that comparison into a live
//! differential test over ~30 command lines.
//!
//! The end-to-end cases drive the real client path: local TCP/unix accept → `create_conn` →
//! `UDPSession` → `CompStream` → smux → `pipe`, against a minimal in-process kcptun *server*
//! (the mirror image of what `crates/server`'s tests do with an in-process client), so a
//! regression anywhere between the local socket and the KCP session fails here rather than in
//! step 09.3.

use std::io::Write as _;
use std::net::SocketAddr;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use kcptun_kcp::Listener;
use kcptun_smux::SplitConn;
use kcptun_std::config::ClientConfig;
use kcptun_std::multiport;
use kcptun_testkit::servers::{EchoServer, PrngStream};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use super::*;

// ---------------------------------------------------------------------------------------
// Capturing the process-wide logger
// ---------------------------------------------------------------------------------------

/// Serialises the tests that redirect the process-wide logger **and** every test that can make
/// the client log (`log::set_output` swaps the sink for the whole process). The guard is held
/// across `block_on` from synchronous code, never across an `await`.
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

/// `reference/bin/client_darwin_arm64 -l 127.0.0.1:24948 -r 127.0.0.1:29900`, with the log
/// header stripped. `snmplog:` really does end in a space: `log.Println("snmplog:", "")`.
const GO_STARTUP_DEFAULTS: &[&str] = &[
    "version: SELFBUILD",
    "smux version: 2",
    "listening on: 127.0.0.1:24948",
    "encryption: aes",
    "QPP: false",
    "QPP Count: 61",
    "nodelay parameters: 0 30 2 1",
    "remote address: 127.0.0.1:29900",
    "sndwnd: 128 rcvwnd: 512",
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
    "conn: 1",
    "autoexpire: 0",
    "scavengettl: 600",
    "snmplog: ",
    "snmpperiod: 60",
    "quiet: false",
    "tcp: false",
    "pprof: false",
];

#[test]
fn startup_log_matches_the_go_binary_with_the_defaults() {
    let mut config = ClientConfig::defaults();
    config.local_addr = "127.0.0.1:24948".to_string();
    config.remote_addr = "127.0.0.1:29900".to_string();
    // Go applies the mode preset before the block: -mode fast is 0 30 2 1, not -interval 50.
    config.base.apply_mode();
    let lines = capture_log(|| {
        // Go prints `version:` before it creates the listener, and the rest after.
        log_version();
        log_startup(&config, "127.0.0.1:24948");
    });
    assert_eq!(lines, GO_STARTUP_DEFAULTS);
}

#[test]
fn startup_log_reports_the_configured_values() {
    let mut config = ClientConfig::defaults();
    config.local_addr = "/tmp/kcptun.sock".to_string();
    config.remote_addr = "10.0.0.1:29900-29905".to_string();
    config.conn = 4;
    config.auto_expire = 30;
    config.scavenge_ttl = 10;
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

    let lines = capture_log(|| log_startup(&config, "/tmp/kcptun.sock"));
    assert_eq!(lines[1], "listening on: /tmp/kcptun.sock");
    assert_eq!(lines[3], "QPP: true");
    assert_eq!(lines[4], "QPP Count: 7");
    // manual keeps the explicit nodelay parameters.
    assert_eq!(lines[5], "nodelay parameters: 1 10 2 1");
    assert_eq!(lines[6], "remote address: 10.0.0.1:29900-29905");
    assert_eq!(lines[8], "compression: false");
    assert_eq!(lines[19], "conn: 4");
    assert_eq!(lines[20], "autoexpire: 30");
    assert_eq!(lines[21], "scavengettl: 10");
    assert_eq!(lines[22], "snmplog: ./snmp-20060102.log");
    assert_eq!(lines[24], "quiet: true");
    assert_eq!(lines[25], "tcp: true");
    // One line shorter than the block above, which also carries `version:`.
    assert_eq!(lines.len(), GO_STARTUP_DEFAULTS.len() - 1);
}

/// `client_darwin_arm64 -autoexpire 30 -scavengettl 600` prints the two red lines; the defaults
/// (`-autoexpire 0`) print neither, however large `-scavengettl` is.
#[test]
fn the_scavengettl_warning_follows_gos_condition() {
    let warn = |auto_expire, scavenge_ttl| {
        let mut config = ClientConfig::defaults();
        config.auto_expire = auto_expire;
        config.scavenge_ttl = scavenge_ttl;
        scavenge_warnings(&config)
    };
    assert_eq!(
        warn(30, 600),
        [
            "WARNING: scavengettl is bigger than autoexpire, connections may race hard to use bandwidth.",
            "Try limiting scavengettl to a smaller value.",
        ]
    );
    // autoexpire off: no warning at all, which is Go's `config.AutoExpire != 0` guard.
    assert!(warn(0, 600).is_empty());
    assert!(warn(600, 600).is_empty());
    assert!(warn(600, 599).is_empty());
    assert_eq!(warn(600, 601).len(), 2);
    // Go compares `!= 0`, so a negative autoexpire warns too (and then never expires anything).
    assert_eq!(warn(-1, 600).len(), 2);
}

// ---------------------------------------------------------------------------------------
// The uint16 -conn cast
// ---------------------------------------------------------------------------------------

#[test]
fn a_conn_count_that_truncates_to_zero_is_rejected_at_startup() {
    // Everything kcptun can actually use passes through unchanged, including the values Go
    // narrows silently.
    assert_eq!(conn_u16(1), Ok(1));
    assert_eq!(conn_u16(4), Ok(4));
    assert_eq!(conn_u16(65535), Ok(65535));
    assert_eq!(conn_u16(65537), Ok(1));

    // Go's `rr % numconn` would divide by zero at the first accepted connection.
    assert_eq!(
        conn_u16(65536),
        Err("conn 65536 does not fit in uint16: kcptun would truncate it to 0".to_string())
    );
    assert_eq!(
        conn_u16(131_072),
        Err("conn 131072 does not fit in uint16: kcptun would truncate it to 0".to_string())
    );

    // `check_conn` keeps Go's semantics (it checks an int), so it is this check, and only this
    // check, that stops the value.
    let mut config = ClientConfig::defaults();
    config.conn = 65536;
    assert_eq!(config.check_conn(), Ok(()));

    // Ordering: Go's `numconn := uint16(config.Conn)` (client/main.go:410) runs *before*
    // `qpp.NewQPP(..., uint16(config.QPPCount))` (417-420), so `action` must call `conn_u16`
    // before `qpp_pad`. With `-conn 65536 -QPPCount 65536` it is this message that Go's cast
    // order reaches first, and both are `log.Fatal`, so only the first one is ever printed.
    assert!(conn_u16(65536).is_err());
    #[cfg(feature = "qpp")]
    assert!(kcptun_std::mainutil::qpp_count_u16(65536).is_err());
}

// ---------------------------------------------------------------------------------------
// dial(): the multiport address and the per-dial random port
// ---------------------------------------------------------------------------------------

#[test]
fn the_remote_port_is_drawn_per_dial() {
    let single = multiport::parse("127.0.0.1:29900").expect("single port");
    assert_eq!(
        random_remote_addr(&single),
        Ok("127.0.0.1:29900".to_string())
    );

    // A range: every draw is inside it, and 200 draws over six ports cannot plausibly all be
    // the same one (that would mean the port was picked once per process, not per dial).
    let range = multiport::parse("127.0.0.1:29900-29905").expect("port range");
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..200 {
        let addr = random_remote_addr(&range).expect("random port");
        let port: u64 = addr
            .strip_prefix("127.0.0.1:")
            .expect("host")
            .parse()
            .expect("port");
        assert!((29900..=29905).contains(&port), "{addr} is out of range");
        seen.insert(port);
    }
    assert!(
        seen.len() > 1,
        "the port must be drawn per dial, saw {seen:?}"
    );

    // Go's `fmt.Sprintf("%v:%v", multiPort.Host, ...)` keeps the host verbatim, brackets and all.
    let v6 = multiport::parse("[::1]:29900").expect("ipv6");
    assert_eq!(random_remote_addr(&v6), Ok("[::1]:29900".to_string()));
}

/// `client_darwin_arm64 -r badaddr` logs `re-connecting: dial(): malformed address:badaddr`
/// once a second, forever.
#[test]
fn a_malformed_remote_address_is_reported_by_every_dial() {
    // `dial` memoises the parse in a process-wide `OnceLock`, exactly as Go's `sync.Once` does,
    // so the error text is checked through `multiport::parse` here and the wrapping through
    // `create_conn`'s caller below.
    let err = multiport::parse("badaddr").expect_err("no port");
    assert_eq!(err.to_string(), "malformed address:badaddr");
    assert_eq!(
        format!("dial(): {err}"),
        "dial(): malformed address:badaddr"
    );
}

// ---------------------------------------------------------------------------------------
// The local listener
// ---------------------------------------------------------------------------------------

#[test]
fn the_listener_is_unix_exactly_when_the_address_is_not_a_host_port() {
    assert!(goaddr::is_host_port("127.0.0.1:12948"));
    assert!(goaddr::is_host_port(":12948"));
    assert!(goaddr::is_host_port("[::1]:12948"));
    assert!(!goaddr::is_host_port("/var/run/kcptun.sock"));
    assert!(!goaddr::is_host_port("kcptun.sock"));
}

#[test]
fn a_wildcard_listener_is_dual_stack_and_prints_gos_address() {
    // `TcpListener::from_std` registers with the reactor, so these run inside a runtime, as
    // `action` does.
    let rt = runtime::build_with(1).expect("runtime");
    let _enter = rt.enter();
    let listener = listen_local(":0").expect("wildcard listener");
    let addr = listener.addr_string();
    // Go binds AF_INET6 with IPV6_V6ONLY off for a wildcard address and prints `[::]:port`.
    assert!(
        addr.starts_with("[::]:") || addr.starts_with("0.0.0.0:"),
        "unexpected wildcard address {addr}"
    );
    let port: u16 = addr
        .rsplit(':')
        .next()
        .expect("port")
        .parse()
        .expect("port");
    assert_ne!(port, 0, "the kernel-assigned port must be reported");
}

#[test]
fn a_literal_listener_prints_the_address_it_bound() {
    let rt = runtime::build_with(1).expect("runtime");
    let _enter = rt.enter();
    let listener = listen_local("127.0.0.1:0").expect("loopback listener");
    assert!(
        listener.addr_string().starts_with("127.0.0.1:"),
        "{}",
        listener.addr_string()
    );
}

/// `client_darwin_arm64 -l 127.0.0.1:<busy>` prints
/// `listen tcp 127.0.0.1:<busy>: bind: address already in use`, and `-l :<busy>` names the
/// *resolved* address, `:<busy>`, not the `[::]:<busy>` the socket would have bound.
#[test]
fn a_failing_bind_reads_like_gos_net_operror() {
    let rt = runtime::build_with(1).expect("runtime");
    let _enter = rt.enter();
    let held = listen_local("127.0.0.1:0").expect("first listener");
    let addr = held.addr_string();
    let err = listen_local(&addr).expect_err("the port is taken");
    assert_eq!(
        err,
        format!("listen tcp {addr}: bind: address already in use")
    );
}

#[test]
fn a_bad_listen_address_reports_the_resolver_error() {
    // `net.SplitHostPort` accepts these, so Go takes the TCP branch and ResolveTCPAddr fails.
    assert_eq!(
        listen_local("127.0.0.1:99999").expect_err("port out of range"),
        "address 99999: invalid port"
    );
    // The Step 05 numeric-only-port limitation of `crates/kcp/src/addr.rs` (step 05.1), not
    // fidelity: Go consults /etc/services, so `-l 127.0.0.1:http` resolves to port 80 and fails
    // with `listen tcp 127.0.0.1:80: bind: permission denied`, and for a name that really is
    // unknown its cgo resolver says `lookup tcp/nosuchservice: unknown port` (both checked
    // against `reference/bin/client_darwin_arm64`). What is pinned here is the `udp/` → `tcp/`
    // rewrite of `listen.rs:resolve_tcp_addr`, which keeps the network name out of the `udp`
    // resolver this port shares between both protocols.
    assert_eq!(
        listen_local("127.0.0.1:nosuchservice").expect_err("named port"),
        "address tcp/nosuchservice: unknown port"
    );
}

#[cfg(unix)]
#[test]
fn a_unix_listener_reports_the_path_and_gos_bind_error() {
    let dir = std::env::temp_dir().join(format!("kcptun-client-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path: PathBuf = dir.join("kcptun.sock");
    let path_str = path.to_string_lossy().into_owned();

    let rt = runtime::build_with(1).expect("runtime");
    let _enter = rt.enter();
    let listener = listen_local(&path_str).expect("unix listener");
    assert_eq!(listener.addr_string(), path_str);

    // Binding the same path again is Go's `bind: address already in use`.
    let err = listen_local(&path_str).expect_err("the path is taken");
    assert_eq!(
        err,
        format!("listen unix {path_str}: bind: address already in use")
    );

    // A path that does not fit in `sun_path` is Go's `bind: invalid argument` (EINVAL), not
    // Rust's errno-less `path must be shorter than SUN_LEN`. Verified against
    // `reference/bin/client_darwin_arm64 -l <105-byte path>`.
    let too_long = dir.join("z".repeat(120));
    let too_long = too_long.to_string_lossy().into_owned();
    assert_eq!(
        listen_local(&too_long).expect_err("the path does not fit in sun_path"),
        format!("listen unix {too_long}: bind: invalid argument")
    );

    // A path whose directory does not exist is Go's `bind: no such file or directory`.
    let missing = dir.join("nope").join("kcptun.sock");
    let missing = missing.to_string_lossy().into_owned();
    assert_eq!(
        listen_local(&missing).expect_err("no such directory"),
        format!("listen unix {missing}: bind: no such file or directory")
    );

    drop(listener);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------------------
// The scavenger
// ---------------------------------------------------------------------------------------

/// Two smux client sessions over in-memory pipes, so the scavenger can be driven without a
/// network. Only `is_closed`, `close` and `local_addr` are used by it.
fn test_session() -> Arc<Session<SplitConn<tokio::io::DuplexStream>>> {
    let (a, b) = tokio::io::duplex(4096);
    // The peer end is kept alive by the returned guard's closure over `b`; a dropped peer would
    // fail the session's receive loop and close it, which is exactly what the test must control.
    let peer = SplitConn::new(b);
    let session = kcptun_smux::client(SplitConn::new(a), None).expect("smux client");
    // Keep the peer connection alive for as long as the session is.
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        while peer.read(&mut buf).await.map(|n| n > 0).unwrap_or(false) {}
    });
    Arc::new(session)
}

#[test]
fn the_scavenger_closes_expired_sessions_and_reaps_closed_ones() {
    let lines = capture_log_with(|sink| {
        let rt = runtime::build_with(2).expect("runtime");
        rt.block_on(async move {
            let (tx, rx) = mpsc::channel::<TimedSession<SplitConn<tokio::io::DuplexStream>>>(128);
            // A 20 ms period instead of Go's 5 s, and no TTL on top of the expiry date.
            let task = tokio::spawn(scavenger(rx, 0, Duration::from_millis(20)));

            // One session that is already past its deadline: the scavenger closes it.
            let expired = test_session();
            tx.send(TimedSession {
                session: Arc::clone(&expired),
                expiry_date: Instant::now(),
            })
            .await
            .expect("send");

            // One that closed by itself: the scavenger only reports it.
            let closed = test_session();
            closed.close().await.expect("close");
            tx.send(TimedSession {
                session: Arc::clone(&closed),
                expiry_date: Instant::now() + Duration::from_secs(3600),
            })
            .await
            .expect("send");

            // One that is neither: it must survive every tick.
            let live = test_session();
            tx.send(TimedSession {
                session: Arc::clone(&live),
                expiry_date: Instant::now() + Duration::from_secs(3600),
            })
            .await
            .expect("send");

            for _ in 0..200 {
                if sink.has_line_starting_with("scavenger: session closed due to ttl:")
                    && sink.has_line_starting_with("scavenger: session normally closed:")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            // Give the scavenger a few more ticks to prove it leaves the live session alone.
            tokio::time::sleep(Duration::from_millis(80)).await;
            assert!(expired.is_closed(), "the expired session must be closed");
            assert!(!live.is_closed(), "the live session must be left alone");
            task.abort();
        });
    });

    assert_eq!(
        lines
            .iter()
            .filter(|l| l.starts_with("scavenger: session closed due to ttl:"))
            .count(),
        1,
        "{lines:?}"
    );
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.starts_with("scavenger: session normally closed:"))
            .count(),
        1,
        "{lines:?}"
    );
}

#[test]
fn a_deadline_follows_gos_signed_seconds() {
    let now = Instant::now();
    assert_eq!(go_deadline(now, 0), now);
    assert_eq!(go_deadline(now, 30), now + Duration::from_secs(30));
    // Go's `time.Duration(-1) * time.Second` moves the deadline backwards; only `autoexpire > 0`
    // ever reads it, but it must not panic.
    assert!(go_deadline(now, -1) < now);
    assert!(go_deadline(now, i64::MIN) <= now);
}

// ---------------------------------------------------------------------------------------
// End to end: the real client path against a minimal in-process kcptun server
// ---------------------------------------------------------------------------------------

/// The client configuration the end-to-end cases share.
fn e2e_config(
    remote_addr: String,
    local_addr: String,
    no_comp: bool,
    smux_ver: i64,
    qpp: bool,
) -> ClientConfig {
    let mut config = ClientConfig::defaults();
    config.base.apply_mode();
    config.local_addr = local_addr;
    config.remote_addr = remote_addr;
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

/// The other half of kcptun: a KCP listener whose smux streams are proxied to `target`.
///
/// This is `crates/server`'s `serve_listener` in miniature: the client tests cannot depend on
/// the server binary, and only the parts the client talks to are needed.
async fn tiny_server(
    listener: Arc<Listener>,
    target: SocketAddr,
    no_comp: bool,
    smux_ver: i64,
    qpp: Option<Arc<QppPad>>,
    key: String,
) {
    while let Ok(conn) = listener.accept().await {
        conn.set_stream_mode(true);
        conn.set_write_delay(false);
        let smux_config: kcptun_smux::Config =
            smuxcfg::build_smux_config(smux_ver, 4194304, 2097152, 8192, 10)
                .expect("smux config")
                .into();
        let qpp = qpp.clone();
        let key = key.clone();
        let conn = KcpConn::new(conn);
        if no_comp {
            tokio::spawn(tiny_server_mux(conn, smux_config, target, qpp, key));
        } else {
            tokio::spawn(tiny_server_mux(
                CompStream::new(conn),
                smux_config,
                target,
                qpp,
                key,
            ));
        }
    }
}

async fn tiny_server_mux<C: SmuxConn>(
    conn: C,
    smux_config: kcptun_smux::Config,
    target: SocketAddr,
    qpp: Option<Arc<QppPad>>,
    key: String,
) {
    // The key only feeds the QPP arm below, which is uninhabited without the feature (D19 keeps
    // the qpp-off build supported, tests included).
    #[cfg(not(feature = "qpp"))]
    let _ = key;
    let mux = kcptun_smux::server(conn, Some(smux_config)).expect("smux server");
    while let Ok(stream) = mux.accept_stream().await {
        let qpp = qpp.clone();
        // Only the `qpp` arm below consumes it; without the feature that arm is uninhabited.
        #[cfg(feature = "qpp")]
        let key = key.clone();
        tokio::spawn(async move {
            let p2 = TcpStream::connect(target).await.expect("dial target");
            let _ = p2.set_nodelay(true);
            let s1 = SmuxStream::new(stream);
            match qpp {
                #[cfg(feature = "qpp")]
                Some(pad) => {
                    let s1 = kcptun_std::qpp::QppStream::new(s1, pad, key.as_bytes());
                    let _ = pipe(s1, p2, 0).await;
                }
                #[cfg(not(feature = "qpp"))]
                Some(pad) => match *pad {},
                None => {
                    let _ = pipe(s1, p2, 0).await;
                }
            }
        });
    }
}

/// Runs one end-to-end case: the real client accept loop, a minimal server and an echo target.
async fn tunnel_case(no_comp: bool, smux_ver: i64, qpp: bool, conn: i64, payload_len: usize) {
    let echo = EchoServer::start().await.expect("echo server");
    let kcp_listener =
        Listener::listen_with_options("127.0.0.1:0", None, 0, 0).expect("kcp listener");
    let kcp_addr = kcp_listener.addr().expect("listen addr");

    let mut config = e2e_config(
        kcp_addr.to_string(),
        "127.0.0.1:0".to_string(),
        no_comp,
        smux_ver,
        qpp,
    );
    config.conn = conn;
    let pad = qpp_pad(&config.base, qpp.then_some(61));
    assert_eq!(
        pad.is_some(),
        qpp,
        "the pad is built exactly when -QPP is on"
    );

    let server = tokio::spawn(tiny_server(
        Arc::clone(&kcp_listener),
        echo.addr(),
        no_comp,
        smux_ver,
        pad.clone(),
        config.base.key.clone(),
    ));

    let listener = listen_local(&config.local_addr).expect("local listener");
    let local_addr = listener.addr_string();
    let numconn = conn_u16(config.conn).expect("conn count");
    let dialer = Arc::new(Dialer::new(Arc::new(config), None));
    let client = if no_comp {
        tokio::spawn(serve(listener, dialer, pad.clone(), numconn, |c| c))
    } else {
        tokio::spawn(serve(
            listener,
            dialer,
            pad.clone(),
            numconn,
            CompStream::new,
        ))
    };

    // Two clients, so `-conn 4` really rotates and a second stream shares the first session.
    let payload = PrngStream::to_vec(7, payload_len);
    for payload in [payload.as_slice(), b"second".as_slice()] {
        let mut app = TcpStream::connect(&local_addr).await.expect("connect");
        app.set_nodelay(true).expect("nodelay");
        app.write_all(payload).await.expect("write");
        app.flush().await.expect("flush");
        let mut got = vec![0u8; payload.len()];
        app.read_exact(&mut got).await.expect("read");
        assert_eq!(got, payload, "the echo came back changed");
        app.shutdown().await.expect("close write");
    }

    client.abort();
    server.abort();
    let _ = kcp_listener.close();
    echo.shutdown().await;
}

#[test]
fn a_local_client_reaches_the_target_with_compression() {
    run_locked(tunnel_case(false, 2, false, 1, 128 * 1024));
}

#[test]
fn a_local_client_reaches_the_target_without_compression() {
    run_locked(tunnel_case(true, 2, false, 1, 128 * 1024));
}

#[test]
fn a_local_client_reaches_the_target_over_smux_v1() {
    run_locked(tunnel_case(true, 1, false, 1, 64 * 1024));
}

#[test]
fn four_tunnels_carry_the_traffic_round_robin() {
    run_locked(tunnel_case(false, 2, false, 4, 32 * 1024));
}

#[cfg(feature = "qpp")]
#[test]
fn a_local_client_reaches_the_target_through_qpp() {
    run_locked(tunnel_case(false, 2, true, 1, 128 * 1024));
}

#[cfg(feature = "qpp")]
#[test]
fn a_local_client_reaches_the_target_through_qpp_without_compression() {
    run_locked(tunnel_case(true, 2, true, 1, 64 * 1024));
}

/// The stream-level log lines, which log scrapers and step 09.5 depend on, plus the
/// `re-connecting:` retry loop and the `smux version: … on connection:` line of `create_conn`.
#[test]
fn the_stream_log_lines_are_gos() {
    let lines = capture_log_with(|sink| {
        let rt = runtime::build_with(2).expect("runtime");
        rt.block_on(async move {
            let echo = EchoServer::start().await.expect("echo server");
            let kcp_listener =
                Listener::listen_with_options("127.0.0.1:0", None, 0, 0).expect("kcp listener");
            let kcp_addr = kcp_listener.addr().expect("listen addr");
            // A wildcard `-l`, the documented configuration: the listener is dual-stack, so an
            // IPv4 client is accepted as `::ffff:127.0.0.1` and the log lines only match Go's
            // once the address is unmapped.
            let mut config = e2e_config(kcp_addr.to_string(), ":0".to_string(), true, 2, false);
            config.base.quiet = false;

            let server = tokio::spawn(tiny_server(
                Arc::clone(&kcp_listener),
                echo.addr(),
                true,
                2,
                None,
                config.base.key.clone(),
            ));

            let listener = listen_local(&config.local_addr).expect("local listener");
            let local_addr = listener.addr_string();
            let dialer = Arc::new(Dialer::new(Arc::new(config), None));
            let client = tokio::spawn(serve(listener, dialer, None, 1, |c| c));

            // `[::]:<port>` (or `0.0.0.0:<port>` where the kernel has no IPv6): reach it over
            // IPv4 so the accepted peer is the mapped address.
            let port = local_addr.rsplit(':').next().expect("port").to_string();
            let mut app = TcpStream::connect(format!("127.0.0.1:{port}"))
                .await
                .expect("connect");
            app.write_all(b"hello").await.expect("write");
            let mut got = [0u8; 5];
            app.read_exact(&mut got).await.expect("read");
            app.shutdown().await.expect("close write");

            for _ in 0..500 {
                if sink.has_line_starting_with("stream closed in: ") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }

            client.abort();
            server.abort();
            let _ = kcp_listener.close();
            echo.shutdown().await;
        });
    });

    // Go's `kcpconn.LocalAddr()` is the wildcard socket `kcp.DialWithOptions` binds
    // (`net.ListenUDP("udp4", nil)` for an IPv4 remote), so it really does print `0.0.0.0:<port>`.
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("smux version: 2 on connection: 0.0.0.0:")
                && l.contains(" -> 127.0.0.1:")),
        "missing `smux version: … on connection:` line in {lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("stream opened in: 127.0.0.1:")
                && l.contains(" out: 127.0.0.1:")
                && l.ends_with("(3)")),
        "missing `stream opened` line in {lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("stream closed in: 127.0.0.1:") && l.ends_with("(3)")),
        "missing `stream closed` line in {lines:?}"
    );
    // Go's `net.IP.String()` unmaps `::ffff:a.b.c.d`; nothing may leak the mapped form.
    assert!(
        !lines.iter().any(|l| l.contains("::ffff:")),
        "an IPv4-mapped address reached a log line in {lines:?}"
    );
}

/// A server that is not there yet: `wait_conn` retries once a second, and the client recovers
/// as soon as the session can be built. The dial itself cannot fail for UDP, so the failure is
/// forced through `--tcp`: off Linux that is Go's own `os not supported`, and on Linux it is a
/// fake-TCP dial that cannot come up.
///
/// The remote is port 1, which nothing listens on: on Linux the raw socket fails with `EPERM`
/// without `CAP_NET_RAW` and the real TCP connect is refused with it, so the dial fails before
/// `tcpraw` registers a connection or touches `iptables` whatever privileges the test runner
/// has. The successful path is step 10.5's, in the netns lab.
#[test]
fn a_failing_dial_is_retried_with_gos_message() {
    let lines = capture_log_with(|sink| {
        let rt = runtime::build_with(2).expect("runtime");
        rt.block_on(async move {
            let mut config = ClientConfig::defaults();
            config.base.apply_mode();
            config.base.tcp = true;
            config.remote_addr = "127.0.0.1:1".to_string();
            let dialer = Arc::new(Dialer::new(Arc::new(config), None));

            let dialer = tokio::spawn(async move {
                let _session: Arc<Session<KcpConn>> = dialer.wait_conn(|c| c).await;
            });
            for _ in 0..200 {
                if sink.has_line_starting_with("re-connecting: ") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            dialer.abort();
        });
    });

    // Go: `log.Println("re-connecting:", err)` with `errors.Wrap(err, "tcpraw.Dial()")` inside
    // `dial()`, which `createConn` wraps in turn.
    assert!(
        lines
            .first()
            .is_some_and(|l| l.starts_with("re-connecting: dial(): tcpraw.Dial(): ")),
        "{lines:?}"
    );
    // Go's text exactly, on every platform its tcpraw does not build for.
    #[cfg(not(target_os = "linux"))]
    assert_eq!(
        lines.first().map(String::as_str),
        Some("re-connecting: dial(): tcpraw.Dial(): os not supported")
    );
}
