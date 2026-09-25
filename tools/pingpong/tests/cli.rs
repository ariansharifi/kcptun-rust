//! CLI tests of the two dev-only lab binaries (`tool_*`, docs/porting-guide.md §8).
//!
//! The unit tests cover the pieces; these run the real executables the way `tools/lab/lab.py`
//! runs them on the lab host (same flags, same `RESULT` line, same CSV) over loopback instead
//! of through a tunnel. They are what would have caught a mode that parses its flags and then
//! never writes its CSV, which in a six-hour soak is only discovered six hours late.
//!
//! They are deliberately **not** the `e2e_*` category: those spawn the ported client and server
//! from `target/release` and are `#[ignore]`d. `CARGO_BIN_EXE_*` points at the binaries Cargo
//! has just built, so nothing here depends on a deployment or on a release build, the whole file
//! takes about four seconds, and the gate runs it. The flip side of `CARGO_BIN_EXE_*` is that it
//! bakes in laptop paths, so this file cannot travel to lab-arm64 via `tools/lab/remote-test.sh`,
//! acceptable for a tool that only ever drives the lab.

use std::path::Path;
use std::time::Duration;

use kcptun_testkit::{ports, proc::Proc};

/// Generous, because a loaded CI machine is slower than a laptop; nothing here waits this long
/// in practice.
const TIMEOUT: Duration = Duration::from_secs(30);

const PINGPONG: &str = env!("CARGO_BIN_EXE_pingpong");
const LABSAMPLE: &str = env!("CARGO_BIN_EXE_labsample");

/// Starts `pingpong serve` on a free loopback port and waits until it is listening.
fn serve(duration: &str) -> (Proc, u16) {
    let port = ports::free_port();
    let mut server = Proc::builder(PINGPONG)
        .name("pp-serve")
        .args(["serve", "--listen", &format!("127.0.0.1:{port}")])
        .args(["--duration", duration, "--report-interval", "1"])
        .spawn()
        .expect("spawn pingpong serve");
    server
        .wait_for_log_line("serve: listening on", TIMEOUT)
        .expect("server did not come up");
    (server, port)
}

/// The single `RESULT {...}` line a finished run prints.
fn result_line(text: &str) -> String {
    text.lines()
        .find(|l| l.starts_with("RESULT "))
        .unwrap_or_else(|| panic!("no RESULT line in:\n{text}"))
        .to_string()
}

/// Reads a `"name":<number>` field out of a `RESULT` line without a JSON parser.
fn field(line: &str, name: &str) -> f64 {
    let key = format!("\"{name}\":");
    let at = line
        .find(&key)
        .unwrap_or_else(|| panic!("no field {name} in {line}"));
    let rest = &line[at + key.len()..];
    let end = rest
        .find([',', '}'])
        .unwrap_or_else(|| panic!("unterminated field {name} in {line}"));
    rest[..end]
        .trim_matches('"')
        .parse()
        .unwrap_or_else(|e| panic!("field {name} is not a number in {line}: {e}"))
}

fn run_workload(name: &str, args: &[&str]) -> String {
    let mut proc = Proc::builder(PINGPONG)
        .name(name)
        .args(args)
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {name}: {e}"));
    let status = proc
        .wait_timeout(TIMEOUT)
        .expect("wait")
        .unwrap_or_else(|| panic!("{name} did not finish:\n{}", proc.log_tail()));
    assert!(status.success(), "{name} failed:\n{}", proc.log());
    proc.log()
}

fn csv_rows(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
fn tool_ping_reports_percentiles_and_writes_its_csv() {
    let dir = tempfile::tempdir().expect("tempdir");
    let csv = dir.path().join("ping.csv");
    let (mut server, port) = serve("20");

    let log = run_workload(
        "pp-ping",
        &[
            "ping",
            "--connect",
            &format!("127.0.0.1:{port}"),
            "--size",
            "64",
            "--duration",
            "3",
            "--warmup",
            "0",
            "--report-interval",
            "1",
            "--verify",
            "--tag",
            "e2e",
            "--out",
            &csv.to_string_lossy(),
        ],
    );

    let result = result_line(&log);
    assert!(result.contains("\"kind\":\"ping\""), "{result}");
    assert!(result.contains("\"tag\":\"e2e\""), "{result}");
    assert!(field(&result, "requests") > 0.0, "{result}");
    assert_eq!(field(&result, "errors"), 0.0, "{result}");
    assert!(field(&result, "rtt_p50_us") > 0.0, "{result}");
    assert!(
        field(&result, "rtt_p99_us") <= field(&result, "rtt_max_us"),
        "p99 above max: {result}"
    );

    let rows = csv_rows(&csv);
    assert_eq!(
        rows[0],
        "unix,iso,elapsed_s,tag,requests,errors,reconnects,count,min_us,mean_us,p50_us,p90_us,p99_us,max_us"
    );
    assert!(rows.len() >= 3, "expected interval rows, got {rows:?}");
    assert!(rows[1].contains(",e2e,"), "{:?}", rows[1]);

    let _ = server.kill();
}

#[test]
fn tool_bulk_moves_bytes_in_both_directions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let csv = dir.path().join("bulk.csv");
    let (mut server, port) = serve("20");

    let log = run_workload(
        "pp-bulk",
        &[
            "bulk",
            "--connect",
            &format!("127.0.0.1:{port}"),
            "--bytes",
            "256k",
            "--streams",
            "2",
            "--direction",
            "both",
            "--duration",
            "3",
            "--report-interval",
            "1",
            "--tag",
            "e2e",
            "--out",
            &csv.to_string_lossy(),
        ],
    );

    let result = result_line(&log);
    assert!(result.contains("\"kind\":\"bulk\""), "{result}");
    assert!(field(&result, "transfers") > 0.0, "{result}");
    assert_eq!(field(&result, "errors"), 0.0, "{result}");
    assert!(field(&result, "bytes_up") > 0.0, "{result}");
    assert!(field(&result, "bytes_down") > 0.0, "{result}");
    assert!(field(&result, "mbit_s") > 0.0, "{result}");
    assert!(csv_rows(&csv).len() >= 2);

    let _ = server.kill();
}

#[test]
fn tool_churn_opens_and_closes_streams_and_keeps_long_lived_ones() {
    let dir = tempfile::tempdir().expect("tempdir");
    let csv = dir.path().join("churn.csv");
    let (mut server, port) = serve("30");

    let log = run_workload(
        "pp-churn",
        &[
            "churn",
            "--connect",
            &format!("127.0.0.1:{port}"),
            "--rate",
            "20",
            "--min-bytes",
            "10k",
            "--max-bytes",
            "64k",
            "--duration",
            "4",
            "--long-lived",
            "2",
            "--long-lived-interval",
            "1",
            "--burst-every",
            "2",
            "--burst-streams",
            "2",
            "--burst-bytes",
            "128k",
            "--report-interval",
            "1",
            "--seed",
            "1234",
            "--tag",
            "e2e",
            "--out",
            &csv.to_string_lossy(),
        ],
    );

    let result = result_line(&log);
    assert!(result.contains("\"kind\":\"churn\""), "{result}");
    // ~20/s for 4 s, minus the ramp; anything near zero means the pacing is broken.
    assert!(field(&result, "opened") >= 40.0, "{result}");
    assert!(field(&result, "completed") >= 40.0, "{result}");
    assert_eq!(field(&result, "errors"), 0.0, "{result}");
    assert_eq!(field(&result, "timeouts"), 0.0, "{result}");
    assert_eq!(field(&result, "inflight_at_end"), 0.0, "{result}");
    assert!(field(&result, "long_lived_ok") > 0.0, "{result}");
    assert_eq!(field(&result, "long_lived_errors"), 0.0, "{result}");
    assert!(field(&result, "bursts") > 0.0, "{result}");
    assert!(field(&result, "bytes_up") > 0.0, "{result}");
    assert!(field(&result, "bytes_down") > 0.0, "{result}");

    let rows = csv_rows(&csv);
    assert!(
        rows.len() >= 3,
        "expected interval rows, got {}",
        rows.len()
    );
    assert_eq!(rows[0].split(',').count(), 21, "column count: {}", rows[0]);

    // The server saw the same streams: every churn stream is one accepted connection.
    let served = server.log();
    let _ = server.kill();
    assert!(
        served.contains("serve: t="),
        "the server printed no progress line:\n{served}"
    );
}

#[test]
fn tool_a_workload_whose_target_is_absent_fails_loudly_rather_than_hanging() {
    let port = ports::free_port();
    let mut proc = Proc::builder(PINGPONG)
        .name("pp-ping-dead")
        .args([
            "ping",
            "--connect",
            &format!("127.0.0.1:{port}"),
            "--duration",
            "2",
            "--warmup",
            "0",
        ])
        .spawn()
        .expect("spawn");
    let status = proc.wait_timeout(TIMEOUT).expect("wait").expect("exited");
    assert!(
        status.success(),
        "a refused connection is data, not a crash"
    );
    let result = result_line(&proc.log());
    assert_eq!(field(&result, "requests"), 0.0, "{result}");
    assert!(field(&result, "errors") > 0.0, "{result}");
}

#[test]
fn tool_bad_flags_are_refused_with_a_message() {
    for args in [
        vec!["ping"],                                            // no --connect
        vec!["ping", "--connect", "127.0.0.1:1", "--nope", "1"], // unknown flag
        vec!["churn", "--connect", "127.0.0.1:1", "--rate", "0"],
        vec!["serve", "--listen", "127.0.0.1:1", "--report-interval", "0"],
        // ECHO is lock-step, so a request larger than the tunnel's in-flight window would
        // deadlock both ends; `ping` refuses the size instead of hanging until --duration.
        vec!["ping", "--connect", "127.0.0.1:1", "--size", "4m"],
        vec!["nonsense"],
    ] {
        let mut proc = Proc::builder(PINGPONG)
            .name("pp-bad")
            .args(&args)
            .spawn()
            .expect("spawn");
        let status = proc.wait_timeout(TIMEOUT).expect("wait").expect("exited");
        assert!(
            !status.success(),
            "{args:?} should have failed:\n{}",
            proc.log()
        );
        assert!(
            proc.log().contains("pingpong: "),
            "{args:?} printed no diagnosis:\n{}",
            proc.log()
        );
    }
}

#[test]
fn tool_labsample_writes_one_row_per_process_per_interval() {
    let dir = tempfile::tempdir().expect("tempdir");
    let csv = dir.path().join("proc.csv");
    // Watch a process that is certainly alive and one that certainly is not.
    let (mut server, _port) = serve("20");
    let watched = server.pid();

    let mut sampler = Proc::builder(LABSAMPLE)
        .name("labsample")
        .args([
            "--out",
            &csv.to_string_lossy(),
            "--pid",
            &format!("srv={watched}"),
            "--interval",
            "1",
            "--duration",
            "3",
            "--tag",
            "e2e",
        ])
        .spawn()
        .expect("spawn labsample");
    let status = sampler
        .wait_timeout(TIMEOUT)
        .expect("wait")
        .unwrap_or_else(|| panic!("labsample did not finish:\n{}", sampler.log_tail()));
    assert!(status.success(), "labsample failed:\n{}", sampler.log());
    let _ = server.kill();

    let rows = csv_rows(&csv);
    assert_eq!(rows[0].split(',').count(), 25, "column count: {}", rows[0]);

    let header: Vec<&str> = rows[0].split(',').collect();
    let column = |row: &str, name: &str| -> String {
        let index = header
            .iter()
            .position(|h| *h == name)
            .unwrap_or_else(|| panic!("no column {name}"));
        row.split(',').nth(index).unwrap_or_default().to_string()
    };
    for row in &rows[1..] {
        assert_eq!(column(row, "label"), "srv");
        assert_eq!(column(row, "pid"), watched.to_string());
        assert_eq!(column(row, "tag"), "e2e");
    }

    if cfg!(target_os = "linux") {
        assert!(rows.len() >= 3, "expected several samples, got {rows:?}");
        for row in &rows[1..] {
            assert_ne!(column(row, "rss_kb"), "0", "no RSS in {row}");
            assert_ne!(column(row, "fds"), "", "no fd count in {row}");
            assert_eq!(column(row, "state"), "S", "unexpected state in {row}");
        }
        // The second row onwards can compute a rate; the first has nothing to diff against.
        assert_eq!(column(&rows[1], "cpu_pct"), "", "first sample has no rate");
        assert_ne!(column(&rows[2], "cpu_pct"), "", "later samples do");
    } else {
        // There is no /proc here, so every process reads as gone and the sampler stops after
        // two empty rounds instead of running to its deadline. That is the documented
        // behaviour, and asserting it keeps the macOS run meaningful.
        assert_eq!(rows.len(), 3, "header plus two empty rounds: {rows:?}");
        assert_eq!(column(&rows[1], "state"), "X");
        assert_eq!(column(&rows[2], "state"), "X");
    }
}

/// The `--log-cap-bytes` guard is what keeps a six-hour soak from filling the lab host's disk
/// (S2-S4 log three lines per stream at 20 streams/s). It is driven entirely by `lab.py`, so a
/// mis-quoted `--log cli=$HOME/...` made the sampler watch a path that does not exist and the
/// cap silently never fired, no error, just a blank `log_bytes` column six hours later. This
/// test is the one that fails loudly instead.
#[test]
fn tool_labsample_caps_a_watched_log_and_records_the_truncation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let csv = dir.path().join("proc.csv");
    let log = dir.path().join("cli.log");
    std::fs::write(&log, vec![b'x'; 4096]).expect("write log");

    let (mut server, _port) = serve("20");
    let watched = server.pid();
    let mut sampler = Proc::builder(LABSAMPLE)
        .name("labsample-cap")
        .args(["--out", &csv.to_string_lossy()])
        .args(["--pid", &format!("cli={watched}")])
        .args(["--log", &format!("cli={}", log.display())])
        .args(["--log-cap-bytes", "1024"])
        .args(["--interval", "1", "--duration", "3", "--tag", "cap"])
        .spawn()
        .expect("spawn labsample");
    let status = sampler
        .wait_timeout(TIMEOUT)
        .expect("wait")
        .unwrap_or_else(|| panic!("labsample did not finish:\n{}", sampler.log_tail()));
    assert!(status.success(), "labsample failed:\n{}", sampler.log());
    let _ = server.kill();

    let rows = csv_rows(&csv);
    let header: Vec<&str> = rows[0].split(',').collect();
    let column = |row: &str, name: &str| -> String {
        let index = header
            .iter()
            .position(|h| *h == name)
            .unwrap_or_else(|| panic!("no column {name}"));
        row.split(',').nth(index).unwrap_or_default().to_string()
    };
    // The very first sample sees 4096 bytes against a 1024 cap, truncates in place and says so.
    // Every column here moves on every platform: watching a log does not go through `/proc`.
    assert_eq!(
        column(&rows[1], "log_bytes"),
        "0",
        "not truncated: {}",
        rows[1]
    );
    assert_eq!(column(&rows[1], "log_truncations"), "1", "{}", rows[1]);
    for row in &rows[1..] {
        assert_ne!(column(row, "log_bytes"), "", "blank log size in {row}");
    }
    assert_eq!(
        std::fs::metadata(&log).expect("log still there").len(),
        0,
        "the file itself was not truncated"
    );
}

#[test]
fn tool_labsample_refuses_a_run_it_cannot_make_sense_of() {
    let mut proc = Proc::builder(LABSAMPLE)
        .name("labsample-bad")
        .args(["--out", "/dev/null"])
        .spawn()
        .expect("spawn");
    let status = proc.wait_timeout(TIMEOUT).expect("wait").expect("exited");
    assert!(!status.success());
    assert!(proc.log().contains("--pid"), "{}", proc.log());
}
