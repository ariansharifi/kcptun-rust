//! Signals, SNMP output and exit behaviour (plan step 09.6), against the Go binaries.
//!
//! | Test | What it pins |
//! |---|---|
//! | `e2e_sigusr1_snmp_line_matches_go` | `SIGUSR1` prints `KCP SNMP:&{…}`, all 30 counters in Go's struct order — byte for byte Go's line |
//! | `e2e_sigterm_exits_like_go` | `SIGTERM` ends the process **by `SIGTERM`**, with Go's wait status, inside Go's `EXIT_WAIT` |
//! | `e2e_sigint_exits_like_go` | `SIGINT` does the same, and also leaves a `signal 15` status (Go re-raises `SIGTERM`) |
//! | `e2e_snmplog_csv_matches_go` | `-snmplog snmp-20060102.log -snmpperiod 1` writes Go's file name, header and rows |
//! | `e2e_snmplog_appends_without_a_second_header` | a restart on the same day appends to the file instead of re-writing the header |
//! | `e2e_sigusr1_reports_the_traffic_of_a_live_tunnel` | the counters are the real ones: non-zero after traffic, and never going backwards |
//! | `e2e_sigterm_ends_a_live_tunnel` | a client and a server with an open stream still die of `SIGTERM` in time |
//!
//! The first five run **both** implementations and compare; the last two are Rust↔Rust, because
//! counter values under traffic are not expected to match packet for packet (FEC and
//! retransmission counters depend on timing).
//!
//! Every process is a `kcptun_testkit::proc::Proc`, killed and reaped on drop, so a failing or
//! timing-out test leaves nothing running. Needs both implementations' binaries, hence
//! `#[ignore]`:
//!
//! ```sh
//! cargo build --release -p kcptun-client -p kcptun-server
//! cargo test -p kcptun-interop-tests --test signals -- --ignored --nocapture
//! ```
//!
//! Signals are Unix-only (Go's `std/signal.go` is `//go:build linux || darwin || freebsd`), so
//! the whole file is `#![cfg(unix)]`.
#![cfg(unix)]

use std::path::Path;
use std::time::Duration;

use kcptun_interop_tests::Impl;
use kcptun_interop_tests::clidiff::Exit;
use kcptun_interop_tests::e2e::{
    self, Tunnel, echo_round_trip, expected_sha256, hash_exact, serial_guard,
};
use kcptun_interop_tests::matrix::Side;
use kcptun_interop_tests::signals::{
    self, EXIT_WAIT, Instance, SIGNAL_TIMEOUT, SNMP_LOG_LAYOUT, Snapshot, SnmpCsv, Termination,
    now_unix,
};
use kcptun_testkit::proc::Proc;
use kcptun_testkit::servers::{EchoServer, write_prng_stream};

/// `SIGTERM`'s number: the status of a kcptun process that was asked to stop, whichever of
/// `SIGINT` and `SIGTERM` it was asked with.
// Go: kcptun/std/signal.go:sigHandler() — syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
const SIGTERM: i32 = 15;

/// How long the `-snmplog` runs are left alone; `-snmpperiod 1` gives one row per second, and
/// [`MIN_ROWS`] is what a slow machine must still manage in that time.
const SNMP_RUN: Duration = Duration::from_millis(3200);
/// Rows a [`SNMP_RUN`] must produce.
const MIN_ROWS: usize = 2;

/// The `-snmplog` flags every CSV case runs with.
const SNMP_ARGS: [&str; 4] = ["-snmplog", SNMP_LOG_LAYOUT, "-snmpperiod", "1"];

/// Cumulative counters, which can only ever grow. The rest (`CurrEstab`, the `RingBuffer*`
/// gauges, `FECShardMin`) are levels and may fall.
// Go: kcp-go/v5@v5.6.66 snmp.go — every one of these is only ever `atomic.AddUint64`ed.
const CUMULATIVE: [&str; 10] = [
    "BytesSent",
    "BytesReceived",
    "ActiveOpens",
    "PassiveOpens",
    "InPkts",
    "OutPkts",
    "InSegs",
    "OutSegs",
    "InBytes",
    "OutBytes",
];

// ---------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------

/// Starts an instance in `<root>/<case><side><impl>`.
#[track_caller]
fn start(implementation: Impl, side: Side, root: &Path, case: &str, extra: &[&str]) -> Instance {
    let dir = root.join(format!(
        "{case}-{}-{}",
        side.bin_name(),
        implementation.tag()
    ));
    Instance::start(implementation, side, &dir, extra).unwrap_or_else(|e| panic!("{case}: {e}"))
}

/// Fails if the process logged a Rust panic (a Go binary never can).
#[track_caller]
fn check_no_panic(what: &str, log: &str) {
    let panics = e2e::panic_lines(log);
    assert!(panics.is_empty(), "{what} panicked:\n{}", panics.join("\n"));
}

/// Signals the process and waits for the `KCP SNMP:` line it must produce.
#[track_caller]
fn sigusr1(instance: &mut Instance, n: usize) -> Vec<Snapshot> {
    instance.signal("USR1").unwrap_or_else(|e| panic!("{e}"));
    let found = instance
        .wait_for_snapshots(n)
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        instance.proc().is_running(),
        "SIGUSR1 must not end the process"
    );
    for snapshot in &found {
        snapshot.check_go_shape().unwrap_or_else(|e| {
            panic!("{:?} {:?}: {e}", instance.implementation(), instance.side())
        });
    }
    found
}

/// The same, for a process of a running [`Tunnel`].
async fn sigusr1_proc(proc: &mut Proc, n: usize) -> Vec<Snapshot> {
    proc.signal("USR1").unwrap_or_else(|e| panic!("{e}"));
    let found = signals::wait_for_snapshots_async(proc, n, SIGNAL_TIMEOUT)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    for snapshot in &found {
        snapshot
            .check_go_shape()
            .unwrap_or_else(|e| panic!("{}: {e}", proc.name()));
    }
    found
}

/// Asserts that a termination is Go's: death *by* `SIGTERM`, well inside `EXIT_WAIT`.
#[track_caller]
fn assert_died_of_sigterm(what: &str, end: Termination) {
    assert_eq!(
        end.exit,
        Exit::Signal(SIGTERM),
        "{what}: expected death by SIGTERM (Go re-raises it), took {:?}",
        end.elapsed
    );
    // Go's EXIT_WAIT is the fallback `os.Exit(0)` for a re-raise that did not work; reaching it
    // would mean the handler is broken even though the process did go away.
    assert!(
        end.elapsed < EXIT_WAIT,
        "{what}: took {:?}, past Go's EXIT_WAIT of {EXIT_WAIT:?}",
        end.elapsed
    );
}

/// Runs one instance with the `-snmplog` flags for [`SNMP_RUN`], stops it and returns its file.
#[track_caller]
fn snmp_run(implementation: Impl, side: Side, root: &Path, case: &str) -> (SnmpCsv, Vec<String>) {
    let mut instance = start(implementation, side, root, case, &SNMP_ARGS);
    std::thread::sleep(SNMP_RUN);
    let end = instance.terminate("TERM").unwrap_or_else(|e| panic!("{e}"));
    assert_died_of_sigterm(&format!("{case} {implementation} {side:?}"), end);
    check_no_panic(&format!("{implementation} {side:?}"), &instance.log());
    let files = instance.files().unwrap_or_else(|e| panic!("{e}"));
    let csv = instance.snmp_csv().unwrap_or_else(|e| panic!("{e}"));
    (csv, files)
}

// ---------------------------------------------------------------------------------------
// SIGUSR1
// ---------------------------------------------------------------------------------------

/// `SIGUSR1` prints the whole SNMP snapshot, and prints it exactly as Go does.
///
/// Both processes are idle — the client has dialled nothing, the server has received nothing —
/// so every counter is zero on both sides and the two lines have to be identical, not merely
/// alike. That is what makes this a differential rather than a shape check: a renamed, reordered,
/// missing or extra counter fails here.
// Go: kcptun/std/signal.go:sigHandler(), case syscall.SIGUSR1
#[test]
#[ignore = "needs reference/bin and the Rust binaries (cargo build --release -p kcptun-client -p kcptun-server)"]
fn e2e_sigusr1_snmp_line_matches_go() {
    let root = tempfile::tempdir().expect("tempdir");
    for side in [Side::Client, Side::Server] {
        let mut go = start(Impl::Go, side, root.path(), "usr1", &[]);
        let go_snapshot = sigusr1(&mut go, 1).remove(0);
        let mut rust = start(Impl::Rust, side, root.path(), "usr1", &[]);
        let rust_snapshot = sigusr1(&mut rust, 1).remove(0);

        assert_eq!(
            go_snapshot.nonzero(),
            Vec::new(),
            "an idle Go {side:?} has no traffic to report"
        );
        assert_eq!(
            rust_snapshot.raw, go_snapshot.raw,
            "{side:?}: SIGUSR1 line differs from Go's"
        );
        check_no_panic(&format!("rust {side:?}"), &rust.log());

        // A second SIGUSR1 prints a second line; the handler is a loop, not a one-shot.
        assert_eq!(sigusr1(&mut rust, 2).len(), 2);
        assert_eq!(sigusr1(&mut go, 2).len(), 2);
    }
}

/// The counters are the real ones: after a round trip through a live tunnel both ends report
/// traffic, and a second snapshot never goes backwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_sigusr1_reports_the_traffic_of_a_live_tunnel() {
    const SEED: u64 = 9;
    const LEN: u64 = 256 * 1024;

    let _serial = serial_guard().await;
    let echo = EchoServer::start().await.expect("echo server");
    let mut tunnel = Tunnel::builder(echo.addr().to_string())
        .server_args(["-closewait", "0"])
        .start()
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    let mut app = tunnel.connect().await.expect("connect");
    let sha = echo_round_trip(&mut app, SEED, LEN).await.expect("echo");
    assert_eq!(sha, expected_sha256(SEED, LEN), "echoed bytes");

    for (what, opens) in [("client", "ActiveOpens"), ("server", "PassiveOpens")] {
        let proc = match what {
            "client" => tunnel.client(),
            _ => tunnel.server(),
        };
        let first = sigusr1_proc(proc, 1).await.remove(0);
        for counter in ["BytesSent", "BytesReceived", "InPkts", "OutPkts"] {
            assert!(
                first.get(counter).unwrap_or(0) > 0,
                "{what}: {counter} is zero after {LEN} bytes each way: {}",
                first.raw
            );
        }
        // The client is the side that dials the KCP session, the server the side that accepts.
        assert!(
            first.get(opens).unwrap_or(0) > 0,
            "{what}: {opens} is zero: {}",
            first.raw
        );

        let second = sigusr1_proc(proc, 2).await.remove(1);
        for counter in CUMULATIVE {
            let (before, after) = (
                first.get(counter).unwrap_or(0),
                second.get(counter).unwrap_or(0),
            );
            assert!(
                after >= before,
                "{what}: {counter} went {before} -> {after}"
            );
        }
    }

    tunnel.check_alive().unwrap_or_else(|e| panic!("{e}"));
    drop(app);
    echo.shutdown().await;
}

// ---------------------------------------------------------------------------------------
// SIGTERM / SIGINT
// ---------------------------------------------------------------------------------------

/// `SIGTERM` ends both binaries the way it ends Go's: the handler runs, the signal is re-raised
/// at its default disposition, and the wait status says *killed by `SIGTERM`* rather than
/// *exited*. A supervisor cannot tell the two implementations apart.
// Go: kcptun/std/signal.go:sigHandler(), case syscall.SIGTERM
#[test]
#[ignore = "needs reference/bin and the Rust binaries (cargo build --release -p kcptun-client -p kcptun-server)"]
fn e2e_sigterm_exits_like_go() {
    exits_like_go("TERM");
}

/// `SIGINT` takes the same path, which is why a Ctrl-C'd kcptun also reports `signal 15`.
// Go: kcptun/std/signal.go:sigHandler(), case syscall.SIGINT
#[test]
#[ignore = "needs reference/bin and the Rust binaries (cargo build --release -p kcptun-client -p kcptun-server)"]
fn e2e_sigint_exits_like_go() {
    exits_like_go("INT");
}

#[track_caller]
fn exits_like_go(signal: &str) {
    let root = tempfile::tempdir().expect("tempdir");
    let case = format!("sig{}", signal.to_lowercase());
    for side in [Side::Client, Side::Server] {
        let mut go = start(Impl::Go, side, root.path(), &case, &[]);
        let go_end = go.terminate(signal).unwrap_or_else(|e| panic!("{e}"));
        let mut rust = start(Impl::Rust, side, root.path(), &case, &[]);
        let rust_end = rust.terminate(signal).unwrap_or_else(|e| panic!("{e}"));

        assert_died_of_sigterm(&format!("go {side:?} on SIG{signal}"), go_end);
        assert_eq!(
            rust_end.exit, go_end.exit,
            "{side:?} on SIG{signal}: Go ended with {}, we ended with {}",
            go_end.exit, rust_end.exit
        );
        assert_died_of_sigterm(&format!("rust {side:?} on SIG{signal}"), rust_end);
        check_no_panic(&format!("rust {side:?}"), &rust.log());

        // Nothing is logged on the way out: Go's handler prints nothing, and neither do we.
        let tail = rust.log();
        assert!(
            !tail.contains("panicked") && !tail.contains("SIG"),
            "unexpected shutdown output:\n{tail}"
        );
    }
}

/// A client and a server with a live KCP session, an open smux stream and a target connection
/// still die of `SIGTERM`, in time. (Go's handler cannot be blocked by a busy tunnel; neither
/// may ours — a shutdown that waits for a task to finish would show up here.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the Rust binaries: cargo build --release -p kcptun-client -p kcptun-server"]
async fn e2e_sigterm_ends_a_live_tunnel() {
    const SEED: u64 = 11;
    const LEN: u64 = 64 * 1024;

    let _serial = serial_guard().await;
    let echo = EchoServer::start().await.expect("echo server");
    let mut tunnel = Tunnel::builder(echo.addr().to_string())
        .server_args(["-closewait", "0"])
        .start()
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    // An open application connection, with bytes still in flight: the stream, the smux session
    // and the target connection are all alive when the signal arrives. The connection is *not*
    // half-closed (no `echo_round_trip` here), so nothing is winding down.
    let mut app = tunnel.connect().await.expect("connect");
    write_prng_stream(&mut app, SEED, LEN).await.expect("write");
    let sha = hash_exact(&mut app, LEN).await.expect("echo");
    assert_eq!(sha, expected_sha256(SEED, LEN));
    // A second round of bytes that nobody will read back.
    write_prng_stream(&mut app, SEED + 1, LEN)
        .await
        .expect("write");

    let server_end = signals::terminate_async(tunnel.server(), "TERM", SIGNAL_TIMEOUT)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_died_of_sigterm("server under load", server_end);

    let client_end = signals::terminate_async(tunnel.client(), "TERM", SIGNAL_TIMEOUT)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_died_of_sigterm("client under load", client_end);

    check_no_panic("server", &tunnel.server_log());
    check_no_panic("client", &tunnel.client_log());
    drop(app);
    echo.shutdown().await;
}

// ---------------------------------------------------------------------------------------
// -snmplog
// ---------------------------------------------------------------------------------------

/// `-snmplog snmp-20060102.log -snmpperiod 1` writes the same file, with the same name, the same
/// header and the same rows as Go.
///
/// Idle processes again, so every counter column is `0` on both sides and the rows can be
/// compared as text; only the `Unix` column (and how many rows a second of wall clock produced)
/// is allowed to differ.
// Go: kcptun/std/snmp.go:SnmpLogger(), writeSnmpRecord()
#[test]
#[ignore = "needs reference/bin and the Rust binaries (cargo build --release -p kcptun-client -p kcptun-server)"]
fn e2e_snmplog_csv_matches_go() {
    let root = tempfile::tempdir().expect("tempdir");
    for side in [Side::Client, Side::Server] {
        let (go, go_files) = snmp_run(Impl::Go, side, root.path(), "snmp");
        let (rust, rust_files) = snmp_run(Impl::Rust, side, root.path(), "snmp");
        let now = now_unix();

        for (what, csv) in [("go", &go), ("rust", &rust)] {
            let problems = csv.problems(now, MIN_ROWS);
            assert!(
                problems.is_empty(),
                "{what} {side:?} wrote {}:\n  {}",
                csv.name,
                problems.join("\n  ")
            );
        }
        // The formatted file name (`snmp-<today>.log`) and the header have to be Go's exactly.
        assert_eq!(rust.name, go.name, "{side:?}: -snmplog file name");
        assert_eq!(rust.header, go.header, "{side:?}: CSV header");
        // And so is the cadence: `-snmpperiod 1` is one row per second for both, so over the
        // same `SNMP_RUN` the counts can differ by at most the one row a tick boundary moves.
        assert!(
            rust.rows.len().abs_diff(go.rows.len()) <= 1,
            "{side:?}: {} rows vs Go's {}",
            rust.rows.len(),
            go.rows.len()
        );
        // A one-second ticker with `MissedTickBehavior::Skip` can never put two rows in the
        // same Unix second, so a too-fast ticker shows up here directly.
        for (what, csv) in [("go", &go), ("rust", &rust)] {
            let unix = csv.timestamps().unwrap_or_else(|e| panic!("{e}"));
            assert!(
                unix.windows(2).all(|w| w[1] > w[0]),
                "{what} {side:?}: Unix column does not strictly increase: {unix:?}"
            );
        }
        // Nothing else is written to the working directory.
        assert_eq!(
            go_files.as_slice(),
            std::slice::from_ref(&go.name),
            "{side:?}: Go's directory"
        );
        assert_eq!(
            rust_files.as_slice(),
            std::slice::from_ref(&rust.name),
            "{side:?}: our directory"
        );
        // Every counter column of every row is `0` on both sides: same rows, bar the clock.
        for (what, csv) in [("go", &go), ("rust", &rust)] {
            for (i, counters) in csv.counters().iter().enumerate() {
                assert!(
                    counters.iter().all(|v| v == "0"),
                    "{what} {side:?} row {}: an idle process reported {counters:?}",
                    i + 1
                );
            }
        }
    }
}

/// A second run on the same day appends: Go writes the header only into an empty file, so the
/// file keeps one header and simply grows. (A re-written header would be a row of names, which
/// `problems` rejects as non-numeric.)
// Go: kcptun/std/snmp.go:writeSnmpRecord() — `if stat.Size() == 0 { w.Write(header) }`
#[test]
#[ignore = "needs reference/bin and the Rust binaries (cargo build --release -p kcptun-client -p kcptun-server)"]
fn e2e_snmplog_appends_without_a_second_header() {
    let root = tempfile::tempdir().expect("tempdir");
    for implementation in [Impl::Go, Impl::Rust] {
        // Both runs share a directory, so the second one finds the first one's file.
        let dir = root.path().join(format!("append-{}", implementation.tag()));
        let mut first = Instance::start(implementation, Side::Client, &dir, &SNMP_ARGS)
            .unwrap_or_else(|e| panic!("{e}"));
        std::thread::sleep(SNMP_RUN);
        assert_died_of_sigterm(
            &format!("{implementation} first run"),
            first.terminate("TERM").unwrap_or_else(|e| panic!("{e}")),
        );
        let after_first = first
            .snmp_csv()
            .unwrap_or_else(|e| panic!("{e}"))
            .rows
            .len();

        let mut second = Instance::start(implementation, Side::Client, &dir, &SNMP_ARGS)
            .unwrap_or_else(|e| panic!("{e}"));
        std::thread::sleep(SNMP_RUN);
        assert_died_of_sigterm(
            &format!("{implementation} second run"),
            second.terminate("TERM").unwrap_or_else(|e| panic!("{e}")),
        );

        let csv = second.snmp_csv().unwrap_or_else(|e| panic!("{e}"));
        let problems = csv.problems(now_unix(), after_first + MIN_ROWS);
        assert!(
            problems.is_empty(),
            "{implementation} restarted into {}:\n  {}",
            csv.name,
            problems.join("\n  ")
        );
        assert!(
            csv.rows.len() > after_first,
            "{implementation}: {} row(s) after a restart, {after_first} before",
            csv.rows.len()
        );
    }
}
