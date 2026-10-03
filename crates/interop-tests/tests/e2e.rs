//! Rust↔Rust end-to-end tests (plan step 09.3): the real `kcptun-client` and `kcptun-server`
//! binaries on loopback, driven through their own sockets and read back out of their own logs.
//!
//! | Test | What it pins |
//! |---|---|
//! | `e2e_round_trip_with_the_defaults` | the whole path with kcptun's defaults (aes, FEC 10/3, snappy, smux v2, server `-closewait 30`) |
//! | `e2e_half_close_ends_the_connection` | V24: the application's `shutdown(SHUT_WR)` ends its connection at once, with no answer, while its request still arrives whole |
//! | `e2e_half_close_ends_the_connection_with_qpp` | the same with `-QPP` |
//! | `e2e_closewait_delays_each_sides_teardown` | `-closewait` is each side's grace before it tears down: the client's delays the application's end, the server's the target's EOF |
//! | `e2e_autoexpire_replaces_the_session_and_the_scavenger_closes_it` | `-autoexpire 3 -scavengettl 2` |
//! | `e2e_conn_4_spreads_sessions_over_four_udp_source_ports` | `-conn 4` round-robin |
//! | `e2e_unix_listener_and_unix_target` | unix socket on both ends |
//! | `e2e_port_range_listens_on_every_port_and_dials_inside_it` | `-l host:a-b` / `-r host:a-b` |
//! | `e2e_fifty_long_streams_with_interleaved_traffic` | 50 concurrent streams, 10 request/response rounds each |
//!
//! The heavy cases (200 MB bulk, 1000 streams, the ~30 s keepalive) live in `e2e_slow.rs`.
//!
//! Every case holds [`serial_guard`] for its whole body, so exactly one tunnel runs at a time,
//! and is wrapped in a timeout, so a hang fails instead of hanging. Both binaries are
//! `kcptun_testkit::proc::Proc` values: they are killed and reaped when the [`Tunnel`] is
//! dropped, on the panic and timeout paths too.
//!
//! Needs the Rust binaries, hence `#[ignore]`:
//!
//! ```sh
//! cargo build --release -p kcptun-client -p kcptun-server
//! cargo test -p kcptun-interop-tests --test e2e -- --ignored --nocapture
//! ```

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use kcptun_interop_tests::Case;
use kcptun_interop_tests::e2e::{
    self, LocalEndpoint, LocalStream, ResponderServer, StreamEnd, Tunnel, connect_local,
    echo_round_trip, expect_eof, expected_sha256, log_values, read_until_closed, serial_guard,
    session_endpoints,
};
use kcptun_testkit::servers::EchoServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// How long a teardown that a `-closewait` of 0 makes immediate may take on a loaded machine. On
/// loopback it takes milliseconds.
const PROMPTLY: Duration = Duration::from_secs(1);

/// Runs one end-to-end case: serialised against every other case, and bounded so a hang fails
/// the test (and drops the [`Tunnel`], which kills both processes) instead of blocking forever.
async fn e2e_case(timeout: Duration, body: impl Future<Output = ()>) {
    let _serial = serial_guard().await;
    if tokio::time::timeout(timeout, body).await.is_err() {
        panic!("end-to-end case timed out after {timeout:?}");
    }
}

/// Reads what is left of `app` after a half-close and returns how many bytes it held, how the
/// connection ended, and how long after `since` it did. A connection still open after `limit`
/// fails the test with `what` in the message.
async fn read_the_end(
    app: &mut LocalStream,
    since: Instant,
    limit: Duration,
    what: &str,
) -> (u64, StreamEnd, Duration) {
    let (bytes, end) = tokio::time::timeout(limit, read_until_closed(app))
        .await
        .unwrap_or_else(|_| {
            panic!("{what}: the connection was still open {limit:?} after the half-close")
        })
        .unwrap_or_else(|e| panic!("{what}: reading after the half-close: {e}"));
    (bytes, end, since.elapsed())
}

/// The port of a `host:port` log value.
#[track_caller]
fn port_of(addr: &str) -> u16 {
    addr.rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("no port in {addr:?}"))
}

/// The distinct values of `prefix` in a log, as a set.
fn distinct(log: &str, prefix: &str) -> BTreeSet<String> {
    log_values(log, prefix)
        .into_iter()
        .map(str::to_string)
        .collect()
}

// ---------------------------------------------------------------------------------------
// The default path
// ---------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_round_trip_with_the_defaults() {
    e2e_case(Duration::from_secs(120), async {
        const SEED: u64 = 1;
        const LEN: u64 = 1 << 20;

        let echo = EchoServer::start().await.expect("echo server");
        // kcptun's defaults throughout (aes, FEC 10/3, snappy, smux v2, mtu 1350), the server's
        // `-closewait 30` included. Up to v0.2.1 that default delayed each direction's
        // half-close by 30 s, so the end of this stream took about a minute and the case ran
        // with `-closewait 0`. Since V24 the application's end of stream comes from the client,
        // which tears the connection down at the application's half-close (its default is 0),
        // and the server's 30 s only keep the target connection open: the application must not
        // wait for them. `e2e_closewait_delays_each_sides_teardown` measures both graces.
        let mut tunnel = Tunnel::builder(echo.addr().to_string())
            .start()
            .await
            .unwrap_or_else(|e| panic!("{e}"));

        let mut app = tunnel.connect().await.expect("connect");
        let sha = echo_round_trip(&mut app, SEED, LEN).await.expect("echo");
        let half_closed = Instant::now();
        assert_eq!(sha, expected_sha256(SEED, LEN), "echoed bytes");
        let (stray, end, ended) =
            read_the_end(&mut app, half_closed, Duration::from_secs(30), "defaults").await;
        assert_eq!(stray, 0, "bytes after the end of the echo");
        assert_eq!(
            end,
            StreamEnd::Eof,
            "nothing owed to the application was thrown away"
        );
        assert!(
            ended < PROMPTLY,
            "the end of stream came {ended:?} after the half-close: the server's -closewait 30 \
             is holding the application up"
        );

        assert_eq!(echo.connections(), 1, "one target connection");
        assert_eq!(echo.bytes(), LEN, "bytes echoed");
        // One local connection, so exactly one KCP session and one stream.
        assert_eq!(session_endpoints(&tunnel.client_log()).len(), 1);
        assert_eq!(distinct(&tunnel.server_log(), "remote address: ").len(), 1);
        tunnel.check_alive().unwrap_or_else(|e| panic!("{e}"));
        echo.shutdown().await;
    })
    .await;
}

// ---------------------------------------------------------------------------------------
// Half-close (deviation V24)
// ---------------------------------------------------------------------------------------

/// An application that half-closes and then waits for its answer: deviation V24 end to end.
///
/// The tunnel no longer carries a half-close across. The client tears the whole connection
/// down `-closewait` seconds after the application's EOF, and its default is 0, so the
/// application reads the end of its connection at once, without one byte of an answer. The
/// [`ResponderServer`] cannot answer any sooner: it answers only after *its* EOF, which it gets
/// when the server tears its side down, and by then nothing is left to carry the answer back.
/// What the teardown must not lose is the request: everything the application sent before its
/// EOF still reaches the target.
///
/// The end must be a clean EOF rather than a reset: when the client tears down, nothing owed to
/// the application is thrown away (no answer has arrived), and V24 resets a socket only when
/// something is (rule 4 of `crates/std/src/pipe.rs`).
///
/// Up to v0.2.1 this case asserted the opposite, a complete answer through the half-closed
/// stream (deviations V11 and V04). That half-close pipe is the one that leaked sockets in
/// production: a direction waiting for smux window credit after the peer had dropped the stream
/// waited forever, with the other direction's socket already half-closed.
async fn half_close_case(qpp: bool) {
    const SEED: u64 = 7;
    const LEN: u64 = 1 << 20;
    const REQUEST: &[u8] = b"REQUEST";

    let responder = ResponderServer::start(SEED, LEN).await.expect("responder");
    let mut tunnel = Tunnel::builder(responder.target())
        .case(Case::new().qpp(qpp))
        // The server's default of 30 s would only postpone the target's EOF, which
        // `e2e_closewait_delays_each_sides_teardown` measures. The client keeps its default, 0.
        .server_args(["-closewait", "0"])
        .start()
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    let mut app = tunnel.connect().await.expect("connect");
    app.write_all(REQUEST).await.expect("request");
    let half_closed = Instant::now();
    app.shutdown().await.expect("half-close");

    let what = format!("qpp={qpp}");
    let (answer, end, ended) =
        read_the_end(&mut app, half_closed, Duration::from_secs(30), &what).await;
    assert_eq!(
        answer, 0,
        "{what}: {answer} bytes of an answer arrived after the half-close"
    );
    assert_eq!(
        end,
        StreamEnd::Eof,
        "{what}: nothing owed to the application was thrown away"
    );
    assert!(
        ended < PROMPTLY,
        "{what}: the connection ended {ended:?} after the half-close; the client's -closewait \
         is 0, so it must tear down at once"
    );

    // The target got the whole request, then its EOF, from the server's teardown at once.
    let records = responder
        .wait_for_records(1, Duration::from_secs(30))
        .await
        .expect("request record");
    assert_eq!(records.len(), 1, "{what}: one target connection");
    assert_eq!(
        records[0].request_bytes,
        REQUEST.len() as u64,
        "{what}: the request reached the target whole"
    );
    let target_eof = records[0].eof_at.saturating_duration_since(half_closed);
    assert!(
        target_eof < PROMPTLY,
        "{what}: the target's EOF came {target_eof:?} after the half-close, with the server's \
         -closewait 0"
    );

    // Both sides close the stream, and neither reports an error for it: tearing a half-closed
    // connection down is the normal end of a connection, not a failure.
    for side in ["client", "server"] {
        let proc = match side {
            "client" => tunnel.client(),
            _ => tunnel.server(),
        };
        proc.wait_for_log_async(
            &format!("the {side} closing the stream"),
            Duration::from_secs(30),
            |l| l.contains("stream closed in:"),
        )
        .await
        .unwrap_or_else(|e| panic!("{what}: {e}"));
    }
    for (side, log) in [
        ("client", tunnel.client_log()),
        ("server", tunnel.server_log()),
    ] {
        let errors: Vec<&str> = log.lines().filter(|l| l.contains("pipe:")).collect();
        assert!(
            errors.is_empty(),
            "{what}: the {side} logged an error for the torn-down connection:\n{}",
            errors.join("\n")
        );
    }
    tunnel.check_alive().unwrap_or_else(|e| panic!("{e}"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_half_close_ends_the_connection() {
    e2e_case(Duration::from_secs(120), half_close_case(false)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_half_close_ends_the_connection_with_qpp() {
    e2e_case(Duration::from_secs(120), half_close_case(true)).await;
}

// ---------------------------------------------------------------------------------------
// closewait
// ---------------------------------------------------------------------------------------

/// When each end saw a half-closed connection end, measured from the application's half-close.
#[derive(Debug)]
struct Ends {
    /// The application read the end of its connection: the client's teardown.
    app: Duration,
    /// The target read its EOF: the server's teardown.
    target: Duration,
}

/// Runs one half-close through a tunnel whose client has `-closewait client` (its default of 0
/// for `None`) and whose server has `-closewait server`, and returns when each end saw the
/// connection end.
async fn teardown_delays(client: Option<u32>, server: u32) -> Ends {
    const SEED: u64 = 11;
    const LEN: u64 = 4096;

    let responder = ResponderServer::start(SEED, LEN).await.expect("responder");
    let mut builder =
        Tunnel::builder(responder.target()).server_args(["-closewait", &server.to_string()]);
    if let Some(client) = client {
        builder = builder.client_args(["-closewait", &client.to_string()]);
    }
    let mut tunnel = builder.start().await.unwrap_or_else(|e| panic!("{e}"));

    let mut app = tunnel.connect().await.expect("connect");
    app.write_all(b"q").await.expect("request");
    let half_closed = Instant::now();
    app.shutdown().await.expect("half-close");

    let what = format!(
        "client -closewait {}, server -closewait {server}",
        client.map_or_else(|| "0 (default)".to_string(), |c| c.to_string())
    );
    let (answer, end, app_end) =
        read_the_end(&mut app, half_closed, Duration::from_secs(60), &what).await;
    // However late the end comes, it brings no answer: the target answers only after its EOF.
    assert_eq!(answer, 0, "{what}: an answer arrived");
    assert_eq!(
        end,
        StreamEnd::Eof,
        "{what}: the application's end of stream"
    );

    let records = responder
        .wait_for_records(1, Duration::from_secs(60))
        .await
        .expect("request record");
    assert_eq!(records[0].request_bytes, 1, "{what}: the request");
    tunnel.check_alive().unwrap_or_else(|e| panic!("{e}"));
    let ends = Ends {
        app: app_end,
        target: records[0].eof_at.saturating_duration_since(half_closed),
    };
    eprintln!("{what}: {ends:?}");
    ends
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_closewait_delays_each_sides_teardown() {
    e2e_case(Duration::from_secs(180), async {
        // What "about 2 s" may measure on a loaded machine.
        let about_two_seconds = Duration::from_millis(1500)..Duration::from_secs(8);

        // Control: `-closewait 0` on both sides, so both ends see the end at once.
        let prompt = teardown_delays(None, 0).await;
        assert!(
            prompt.app < PROMPTLY && prompt.target < PROMPTLY,
            "-closewait 0 on both sides: {prompt:?}"
        );

        // The server's grace holds the target alone: the client tears the application's
        // connection down at once, and the server closes the target 2 s later. This is the
        // server's default of 30 s, shortened.
        let server = teardown_delays(None, 2).await;
        assert!(
            server.app < PROMPTLY,
            "server -closewait 2 held the application for {:?}",
            server.app
        );
        assert!(
            about_two_seconds.contains(&server.target),
            "server -closewait 2 gave the target its EOF after {:?}",
            server.target
        );

        // The client's grace holds the whole connection: no half-close crosses the tunnel, so
        // the server hears nothing until the client tears down, and both ends see the end about
        // 2 s after the half-close.
        let client = teardown_delays(Some(2), 0).await;
        assert!(
            about_two_seconds.contains(&client.app),
            "client -closewait 2 ended the application's connection after {:?}",
            client.app
        );
        assert!(
            about_two_seconds.contains(&client.target),
            "client -closewait 2 gave the target its EOF after {:?}",
            client.target
        );
    })
    .await;
}

// ---------------------------------------------------------------------------------------
// autoexpire and the scavenger
// ---------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_autoexpire_replaces_the_session_and_the_scavenger_closes_it() {
    e2e_case(Duration::from_secs(180), async {
        const SEED: u64 = 21;
        const LEN: u64 = 4096;

        let echo = EchoServer::start().await.expect("echo server");
        let mut tunnel = Tunnel::builder(echo.addr().to_string())
            .client_args(["-autoexpire", "3", "-scavengettl", "2"])
            .server_args(["-closewait", "0"])
            .start()
            .await
            .unwrap_or_else(|e| panic!("{e}"));

        // First connection: brings up session 1.
        let mut app = tunnel.connect().await.expect("connect");
        let sha = echo_round_trip(&mut app, SEED, LEN).await.expect("echo");
        assert_eq!(sha, expected_sha256(SEED, LEN));
        drop(app);
        let first = session_endpoints(&tunnel.client_log());
        assert_eq!(first.len(), 1, "one session so far");

        // Past the auto-expiry, so the next connection must not reuse it.
        tokio::time::sleep(Duration::from_secs(4)).await;
        let mut app = tunnel.connect().await.expect("connect");
        let sha = echo_round_trip(&mut app, SEED + 1, LEN)
            .await
            .expect("echo");
        assert_eq!(sha, expected_sha256(SEED + 1, LEN));
        drop(app);

        let sessions = session_endpoints(&tunnel.client_log());
        assert_eq!(sessions.len(), 2, "the expired session was replaced");
        assert_ne!(sessions[0].0, sessions[1].0, "new UDP source port");

        // `scavengettl` seconds after the expiry, the scavenger closes the old session. Its
        // ticker runs every 5 s (Go's scavengePeriod), so this is the slow part of the case.
        let line = tunnel
            .client()
            .wait_for_log_async(
                "the scavenger closing the expired session",
                Duration::from_secs(60),
                |l| l.contains("scavenger: session closed due to ttl:"),
            )
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            line.ends_with(&sessions[0].0),
            "the scavenger closed {line:?}, expected the first session {}",
            sessions[0].0
        );

        tunnel.check_alive().unwrap_or_else(|e| panic!("{e}"));
        echo.shutdown().await;
    })
    .await;
}

// ---------------------------------------------------------------------------------------
// conn and port ranges
// ---------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_conn_4_spreads_sessions_over_four_udp_source_ports() {
    e2e_case(Duration::from_secs(180), async {
        const SEED: u64 = 31;
        const LEN: u64 = 4096;
        const CONNECTIONS: u64 = 8;

        let echo = EchoServer::start().await.expect("echo server");
        let mut tunnel = Tunnel::builder(echo.addr().to_string())
            .case(Case::new().conn(4))
            .server_args(["-closewait", "0"])
            .start()
            .await
            .unwrap_or_else(|e| panic!("{e}"));

        // `idx = rr % conn`, so the first four connections each bring up a session and the next
        // four reuse them.
        for i in 0..CONNECTIONS {
            let mut app = tunnel.connect().await.expect("connect");
            let sha = echo_round_trip(&mut app, SEED + i, LEN)
                .await
                .expect("echo");
            assert_eq!(sha, expected_sha256(SEED + i, LEN), "connection {i}");
        }

        let sessions = session_endpoints(&tunnel.client_log());
        assert_eq!(sessions.len(), 4, "one session per -conn slot, then reuse");
        let locals: BTreeSet<&str> = sessions.iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(
            locals.len(),
            4,
            "four distinct UDP source ports: {locals:?}"
        );

        // The server sees exactly those four peers. Only the ports can be compared: the client
        // dials with an unbound socket, so Go's (and this port's) `LocalAddr()` is
        // `0.0.0.0:<port>`, while the server's `RemoteAddr()` is `127.0.0.1:<port>`.
        let peers = distinct(&tunnel.server_log(), "remote address: ");
        assert_eq!(peers.len(), 4, "server saw {peers:?}");
        assert_eq!(
            peers.iter().map(|p| port_of(p)).collect::<BTreeSet<u16>>(),
            locals.iter().map(|l| port_of(l)).collect::<BTreeSet<u16>>(),
            "the server's peers are the client's sockets"
        );
        assert_eq!(echo.connections(), CONNECTIONS, "target connections");

        tunnel.check_alive().unwrap_or_else(|e| panic!("{e}"));
        echo.shutdown().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_port_range_listens_on_every_port_and_dials_inside_it() {
    e2e_case(Duration::from_secs(180), async {
        const SEED: u64 = 41;
        const LEN: u64 = 4096;
        const PORTS: u16 = 5;

        let echo = EchoServer::start().await.expect("echo server");
        let mut tunnel = Tunnel::builder(echo.addr().to_string())
            .udp_ports(PORTS)
            .case(Case::new().conn(4))
            .server_args(["-closewait", "0"])
            .start()
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let block = tunnel.udp_ports();
        assert!(tunnel.listen_spec().ends_with(&block.range_spec()));

        // One UDP listener per port of the range.
        let server_log = tunnel.server_log();
        let listening = log_values(&server_log, "Listening on: ");
        let want: Vec<String> = block
            .ports()
            .map(|p| format!("127.0.0.1:{p}/udp"))
            .collect();
        assert_eq!(listening, want, "one listener per port");

        for i in 0..4u64 {
            let mut app = tunnel.connect().await.expect("connect");
            let sha = echo_round_trip(&mut app, SEED + i, LEN)
                .await
                .expect("echo");
            assert_eq!(sha, expected_sha256(SEED + i, LEN), "connection {i}");
        }

        // Every session picked its destination port inside the range (a fresh draw per dial, so
        // the same port may come up twice).
        let sessions = session_endpoints(&tunnel.client_log());
        assert_eq!(sessions.len(), 4);
        for (_, remote) in &sessions {
            let port = port_of(remote);
            assert!(
                block.ports().any(|p| p == port),
                "session dialled {remote}, outside {}",
                block.range_spec()
            );
        }

        tunnel.check_alive().unwrap_or_else(|e| panic!("{e}"));
        echo.shutdown().await;
    })
    .await;
}

// ---------------------------------------------------------------------------------------
// unix sockets
// ---------------------------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_unix_listener_and_unix_target() {
    e2e_case(Duration::from_secs(120), async {
        const SEED: u64 = 51;
        const LEN: u64 = 256 << 10;

        let dir = tempfile::tempdir().expect("tempdir");
        let target = e2e::UnixEchoServer::start(dir.path().join("target.sock"))
            .await
            .expect("unix echo server");
        let local = dir.path().join("client.sock");
        let mut tunnel = Tunnel::builder(target.target())
            .local_unix(&local)
            .server_args(["-closewait", "0"])
            .start()
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(tunnel.local(), &LocalEndpoint::Unix(local.clone()));
        assert!(local.exists(), "the client's socket is on disk");

        let mut app = tunnel.connect().await.expect("connect");
        let sha = echo_round_trip(&mut app, SEED, LEN).await.expect("echo");
        assert_eq!(sha, expected_sha256(SEED, LEN));
        expect_eof(&mut app).await.expect("clean end of stream");
        assert_eq!(target.connections(), 1, "one unix target connection");

        // Go's `RemoteAddr()` of an accepted unix connection is the peer's (empty) name, so the
        // client's log line really does read `stream opened in:  out: …`.
        assert!(
            tunnel.client_log().contains("stream opened in:  out:"),
            "client log:\n{}",
            tunnel.client_log()
        );
        tunnel.check_alive().unwrap_or_else(|e| panic!("{e}"));
    })
    .await;
}

// ---------------------------------------------------------------------------------------
// Many streams
// ---------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_fifty_long_streams_with_interleaved_traffic() {
    e2e_case(Duration::from_secs(300), async {
        const STREAMS: u64 = 50;
        const ROUNDS: u64 = 10;
        const LEN: u64 = 8192;

        let echo = EchoServer::start().await.expect("echo server");
        let mut tunnel = Tunnel::builder(echo.addr().to_string())
            .server_args(["-closewait", "0"])
            .start()
            .await
            .unwrap_or_else(|e| panic!("{e}"));

        // Connect first, then let every stream run its rounds at the same time, so the
        // request/response turns of all 50 interleave on one smux session.
        let mut apps = Vec::new();
        for _ in 0..STREAMS {
            apps.push(tunnel.connect().await.expect("connect"));
        }
        let started = Instant::now();
        let mut set = tokio::task::JoinSet::new();
        for (i, mut app) in apps.into_iter().enumerate() {
            set.spawn(async move {
                for round in 0..ROUNDS {
                    let seed = 1_000 + (i as u64) * ROUNDS + round;
                    let payload = kcptun_testkit::servers::PrngStream::to_vec(seed, LEN as usize);
                    app.write_all(&payload)
                        .await
                        .unwrap_or_else(|e| panic!("stream {i} round {round} write: {e}"));
                    let mut back = vec![0u8; LEN as usize];
                    app.read_exact(&mut back)
                        .await
                        .unwrap_or_else(|e| panic!("stream {i} round {round} read: {e}"));
                    assert_eq!(back, payload, "stream {i} round {round}");
                }
                app.shutdown().await.expect("half-close");
                expect_eof(&mut app).await.expect("clean end of stream");
            });
        }
        while let Some(res) = set.join_next().await {
            res.expect("stream task");
        }
        eprintln!(
            "{STREAMS} streams x {ROUNDS} rounds x {LEN} B in {:?}",
            started.elapsed()
        );

        assert_eq!(
            echo.connections(),
            STREAMS,
            "one target connection per stream"
        );
        assert_eq!(echo.bytes(), STREAMS * ROUNDS * LEN, "bytes echoed");
        assert_eq!(
            session_endpoints(&tunnel.client_log()).len(),
            1,
            "one session carries all 50 streams"
        );
        tunnel.check_alive().unwrap_or_else(|e| panic!("{e}"));
        echo.shutdown().await;
    })
    .await;
}

// ---------------------------------------------------------------------------------------
// The harness itself
// ---------------------------------------------------------------------------------------

/// The helpers that parse logs and stream endpoints are pure, so they are checked without
/// spawning anything: this one runs in the normal gate.
#[test]
fn log_helpers_read_the_binaries_lines() {
    let log = "\
2026/09/23 10:00:00 main.rs:233: listening on: 127.0.0.1:22000-22004
2026/09/23 10:00:00 main.rs:204: Listening on: 127.0.0.1:22000/udp
2026/09/23 10:00:00 main.rs:204: Listening on: 127.0.0.1:22001/udp
2026/09/23 10:00:01 main.rs:355: remote address: 127.0.0.1:51001
2026/09/23 10:00:01 main.rs:389: smux version: 2 on connection: 127.0.0.1:51001 -> 127.0.0.1:22000
2026/09/23 10:00:02 main.rs:389: smux version: 2 on connection: 127.0.0.1:51002 -> 127.0.0.1:22001
";
    assert_eq!(
        log_values(log, "Listening on: "),
        ["127.0.0.1:22000/udp", "127.0.0.1:22001/udp"]
    );
    assert_eq!(log_values(log, "remote address: "), ["127.0.0.1:51001"]);
    assert_eq!(
        session_endpoints(log),
        [
            ("127.0.0.1:51001".to_string(), "127.0.0.1:22000".to_string()),
            ("127.0.0.1:51002".to_string(), "127.0.0.1:22001".to_string()),
        ]
    );
    assert_eq!(distinct(log, "remote address: ").len(), 1);
    assert!(e2e::panic_lines(log).is_empty());
    assert_eq!(
        e2e::panic_lines("thread 'main' panicked at src/main.rs:1:1:").len(),
        1
    );
}

/// Both spellings of the application endpoint reach [`connect_local`], and a connection to a
/// closed port fails rather than hanging.
#[tokio::test]
async fn connecting_to_a_dead_endpoint_fails() {
    let port = kcptun_testkit::ports::free_port();
    let endpoint = LocalEndpoint::Tcp(([127, 0, 0, 1], port).into());
    // Longer than `connect_local`'s 45 s `AddrNotAvailable` retry window, so that a drained
    // ephemeral range is reported as an error rather than as a spurious timeout here.
    let err = tokio::time::timeout(Duration::from_secs(60), connect_local(&endpoint))
        .await
        .expect("connect did not block")
        .expect_err("nothing listens there");
    assert!(
        matches!(
            err.kind(),
            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::AddrNotAvailable
        ),
        "{err:?}"
    );
}
