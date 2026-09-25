//! The heavy Rust↔Rust end-to-end cases (plan step 09.3). The quick ones are in `e2e.rs`; these
//! are split off because they move hundreds of megabytes, open a thousand sockets, or spend a
//! minute waiting for a timeout, not what a normal run wants.
//!
//! | Test | What it pins |
//! |---|---|
//! | `e2e_slow_bulk_200mb_each_way` | 200 MB up **and** down through one stream, SHA-256 verified |
//! | `e2e_slow_one_thousand_short_streams` | 1000 streams over one session, bounded concurrency |
//! | `e2e_slow_keepalive_closes_a_dead_session_and_the_client_recovers` | the smux keepalive timeout (~65 s), then recovery on a restarted server |
//!
//! Needs the Rust binaries, hence `#[ignore]`:
//!
//! ```sh
//! cargo build --release -p kcptun-client -p kcptun-server
//! cargo test -p kcptun-interop-tests --test e2e_slow -- --ignored --nocapture
//! ```
//!
//! As in `e2e.rs`, every case holds [`serial_guard`] and is bounded by a timeout, and both
//! binaries are killed and reaped when the [`Tunnel`] is dropped, including when a case panics
//! or times out.

use std::time::{Duration, Instant};

use kcptun_interop_tests::Case;
use kcptun_interop_tests::e2e::{
    Tunnel, TunnelBuilder, echo_round_trip, expected_sha256, serial_guard, session_endpoints,
};
use kcptun_testkit::servers::EchoServer;

// `e2e_slow_one_thousand_short_streams` is unix-only (its target is a unix-socket echo server),
// and these are the imports it alone uses.
#[cfg(unix)]
use std::sync::Arc;

#[cfg(unix)]
use kcptun_interop_tests::e2e::{UnixEchoServer, connect_local, log_values};
#[cfg(unix)]
use tokio::sync::Semaphore;

/// Runs one end-to-end case: serialised against every other case, and bounded so a hang fails the
/// test (and drops the [`Tunnel`], which kills both processes) instead of blocking forever.
async fn e2e_case(timeout: Duration, body: impl Future<Output = ()>) {
    let _serial = serial_guard().await;
    if tokio::time::timeout(timeout, body).await.is_err() {
        panic!("end-to-end case timed out after {timeout:?}");
    }
}

/// Calls `probe` every 20 ms until it returns a value, or `timeout` passes (then `None`).
///
/// Used where the thing being waited for is a *count* of log lines rather than one line, which
/// [`kcptun_testkit::proc::Proc::wait_for_log_async`] cannot express.
#[cfg(unix)]
async fn poll_for<T>(timeout: Duration, mut probe: impl FnMut() -> Option<T>) -> Option<T> {
    const INTERVAL: Duration = Duration::from_millis(20);
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(v) = probe() {
            return Some(v);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(INTERVAL).await;
    }
}

/// A tunnel tuned for throughput rather than for kcptun's defaults: no FEC, no compression (the
/// payload is random, so snappy would only cost CPU), a window and buffers that keep the link
/// full, and `-closewait 0` so the stream ends when the data does.
///
/// It is deliberately close to the "production profile" of 09.4, minus its `-crypt xor`: these
/// cases exercise the *default* cipher under load.
fn bulk_tunnel(target: String) -> TunnelBuilder {
    Tunnel::builder(target)
        .case(Case::new().nocomp(true).fec(0, 0).mtu(1400))
        .both_args([
            "-sndwnd",
            "2048",
            "-rcvwnd",
            "2048",
            "-smuxbuf",
            "16777216",
            "-streambuf",
            "16777216",
            "-sockbuf",
            "8388608",
        ])
        .server_args(["-closewait", "0"])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "heavy (moves 400 MB); needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_slow_bulk_200mb_each_way() {
    e2e_case(Duration::from_secs(900), async {
        const SEED: u64 = 202;
        const LEN: u64 = 200 * 1024 * 1024;

        let echo = EchoServer::start().await.expect("echo server");
        let mut tunnel = bulk_tunnel(echo.addr().to_string())
            .both_args(["-quiet"])
            .start()
            .await
            .unwrap_or_else(|e| panic!("{e}"));

        let mut app = tunnel.connect().await.expect("connect");
        let started = Instant::now();
        // 200 MB up and 200 MB back, at the same time, over one stream.
        let sha = echo_round_trip(&mut app, SEED, LEN).await.expect("echo");
        let elapsed = started.elapsed();
        assert_eq!(sha, expected_sha256(SEED, LEN), "echoed bytes");
        assert_eq!(echo.bytes(), LEN, "bytes the target echoed");

        let mib = (LEN as f64) / (1024.0 * 1024.0);
        eprintln!(
            "200 MB each way in {elapsed:?} ({:.1} MiB/s each way)",
            mib / elapsed.as_secs_f64()
        );
        tunnel.check_alive().unwrap_or_else(|e| panic!("{e}"));
        echo.shutdown().await;
    })
    .await;
}

/// The plan's 1000 short streams over one session.
///
/// **Ephemeral ports.** Every stream costs one: the application's TCP connection to
/// `kcptun-client`. The target is a *unix* socket rather than testkit's TCP [`EchoServer`]
/// precisely so the server's 1000 dials cost none: a TCP target would double the bill to ~2000,
/// and a `kcptun-server` that cannot dial its target has no way to retry. Even at 1000 the run is
/// a large share of macOS's 16384-port range (`net.inet.ip.portrange.first`), each held for a 30 s
/// `TIME_WAIT` (`net.inet.tcp.msl`), so back-to-back runs inside that window can still run the
/// range dry. [`connect_local`] then waits for it to refill instead of failing, which is why a
/// repeat run can take tens of seconds rather than the fraction of a second a first run takes.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "heavy (1000 streams at once); needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_slow_one_thousand_short_streams() {
    e2e_case(Duration::from_secs(600), async {
        /// The plan's 1000 short streams.
        const STREAMS: usize = 1000;
        /// How many run at once. The plan asks for 1000 concurrent streams; the cap keeps the
        /// case inside a 1024 file-descriptor limit (the Linux default, and this runs on
        /// lab-arm64 too) on all four processes involved, and keeps a laptop out of scheduler
        /// noise. The stream *count* is what the case is about, and it is also what the
        /// ephemeral-port cost in the doc comment scales with, which the cap does not change.
        const IN_FLIGHT: usize = 250;
        const LEN: u64 = 4096;

        let dir = tempfile::tempdir().expect("tempdir");
        let echo = UnixEchoServer::start(dir.path().join("target.sock"))
            .await
            .expect("unix echo server");
        let mut tunnel = bulk_tunnel(echo.target())
            .start()
            .await
            .unwrap_or_else(|e| panic!("{e}"));

        let endpoint = tunnel.local().clone();
        let limit = Arc::new(Semaphore::new(IN_FLIGHT));
        let started = Instant::now();
        let mut set = tokio::task::JoinSet::new();
        for i in 0..STREAMS {
            let endpoint = endpoint.clone();
            let limit = Arc::clone(&limit);
            set.spawn(async move {
                let _permit = limit.acquire().await.expect("semaphore");
                let seed = 5_000 + i as u64;
                let mut app = connect_local(&endpoint)
                    .await
                    .unwrap_or_else(|e| panic!("stream {i} connect: {e}"));
                let sha = echo_round_trip(&mut app, seed, LEN)
                    .await
                    .unwrap_or_else(|e| panic!("stream {i} echo: {e}"));
                assert_eq!(sha, expected_sha256(seed, LEN), "stream {i}");
            });
        }
        while let Some(res) = set.join_next().await {
            res.expect("stream task");
        }
        eprintln!("{STREAMS} streams of {LEN} B in {:?}", started.elapsed());

        assert_eq!(echo.connections(), STREAMS as u64, "target connections");
        assert_eq!(echo.bytes(), STREAMS as u64 * LEN, "bytes echoed");

        // `echo_round_trip` returns on the last echoed byte, but the client only logs
        // `stream closed` once its pipe has joined, which additionally needs the smux FIN and the
        // half-close of the application socket. Poll until both counts are in rather than sampling
        // a log the client is still writing.
        let client_log = poll_for(Duration::from_secs(30), || {
            let log = tunnel.client_log();
            let opened = log_values(&log, "stream opened in: ").len();
            let closed = log_values(&log, "stream closed in: ").len();
            (opened >= STREAMS && closed >= STREAMS).then_some(log)
        })
        .await
        .unwrap_or_else(|| {
            let log = tunnel.client_log();
            panic!(
                "the client logged {} opened / {} closed streams, expected {STREAMS} of each",
                log_values(&log, "stream opened in: ").len(),
                log_values(&log, "stream closed in: ").len()
            )
        });
        assert_eq!(
            log_values(&client_log, "stream opened in: ").len(),
            STREAMS,
            "one `stream opened` line per stream"
        );
        assert_eq!(
            log_values(&client_log, "stream closed in: ").len(),
            STREAMS,
            "one `stream closed` line per stream"
        );
        assert_eq!(
            session_endpoints(&client_log).len(),
            1,
            "one session carries all {STREAMS} streams"
        );
        tunnel.check_alive().unwrap_or_else(|e| panic!("{e}"));
        echo.shutdown().await;
    })
    .await;
}

/// The plan's "server restart → the client recovers" and "keepalive timeout closes a dead
/// session" case, which are one event chain.
///
/// Note that the client's `re-connecting:` loop is *not* what recovers here, and cannot be: it
/// only runs when `createConn()` fails, and dialling UDP does not fail. What happens instead is
/// that the smux session dies of its keepalive timeout, the scavenger reports it, and the next
/// accepted connection finds `mux.IsClosed()` and dials a fresh session. The `re-connecting:`
/// loop itself is covered by `crates/client`'s `a_failing_dial_is_retried_with_gos_message`.
///
/// That takes about a minute, not 30 seconds: `KeepAliveTimeout` is smux's default of 30 s
/// (`-keepalive` sets only the *interval*, `std/smuxcfg.go`) and the keepalive goroutine closes
/// the session on the first 30 s tick that finds `dataReady` still clear, so a session that was
/// carrying traffic when the peer died survives one tick and dies on the next. Measured: 65 s,
/// including the scavenger's 5 s reporting tick.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow (~65 s of waiting); needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_slow_keepalive_closes_a_dead_session_and_the_client_recovers() {
    e2e_case(Duration::from_secs(300), async {
        const SEED: u64 = 301;
        const LEN: u64 = 4096;

        let echo = EchoServer::start().await.expect("echo server");
        let mut tunnel = Tunnel::builder(echo.addr().to_string())
            // The scavenger only runs with `-autoexpire`; a TTL far in the future means it never
            // expires a session itself, so a session it closes was closed by its keepalive.
            .client_args(["-autoexpire", "3600", "-scavengettl", "3600"])
            .server_args(["-closewait", "0"])
            .start()
            .await
            .unwrap_or_else(|e| panic!("{e}"));

        let mut app = tunnel.connect().await.expect("connect");
        let sha = echo_round_trip(&mut app, SEED, LEN).await.expect("echo");
        assert_eq!(sha, expected_sha256(SEED, LEN));
        drop(app);

        // Restart the server on the same ports. The client keeps talking to a session the new
        // process knows nothing about.
        tunnel.stop_server().expect("stop the server");
        tunnel
            .start_server()
            .await
            .unwrap_or_else(|e| panic!("{e}"));

        let started = Instant::now();
        tunnel
            .client()
            .wait_for_log_async(
                "the scavenger reporting the dead session",
                Duration::from_secs(120),
                |l| l.contains("scavenger: session normally closed:"),
            )
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        eprintln!("the dead session was closed after {:?}", started.elapsed());

        // The next connection must bring up a new session against the restarted server.
        let mut app = tunnel.connect().await.expect("connect");
        let sha = echo_round_trip(&mut app, SEED + 1, LEN)
            .await
            .expect("echo after the restart");
        assert_eq!(sha, expected_sha256(SEED + 1, LEN));
        drop(app);

        let sessions = session_endpoints(&tunnel.client_log());
        assert_eq!(sessions.len(), 2, "the dead session was replaced");
        assert_ne!(sessions[0].0, sessions[1].0, "new UDP source port");
        assert_eq!(
            echo.connections(),
            2,
            "one target connection per round trip"
        );
        tunnel.check_alive().unwrap_or_else(|e| panic!("{e}"));
        echo.shutdown().await;
    })
    .await;
}
