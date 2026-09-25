//! Tests for [`crate::pprof`]'s flag handling (D23), in both build configurations.
//!
//! `cargo test -p kcptun-std` covers the default build (feature off, the [`NOT_AVAILABLE`] line);
//! `cargo test -p kcptun-std --features pprof` covers the other side (on Unix; a Windows build
//! takes the [`NOT_AVAILABLE`] path either way), where `start(true)` must
//! log nothing and instead put a server on the port. The endpoint itself is tested in
//! `pprof_server_tests.rs`, which does not need the fixed `:6060`.

use std::sync::{Arc, Mutex};

use super::*;
use crate::log;

/// A log sink a test can read back (as in `log_tests.rs`).
#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn new() -> Capture {
        Capture(Arc::new(Mutex::new(Vec::new())))
    }

    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Runs `body` with the process-wide logger redirected into a [`Capture`], serialised against
/// every other test that does the same. `body` is handed the sink, so a test that has to wait for
/// a background task can watch what it logs.
fn with_captured_log_sink(body: impl FnOnce(&Capture)) -> String {
    let _guard = log::TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let sink = Capture::new();
    log::set_output(Box::new(sink.clone()));
    body(&sink);
    log::set_output_stderr();
    sink.text()
}

/// [`with_captured_log_sink`] for the tests that only read the log afterwards.
fn with_captured_log(body: impl FnOnce()) -> String {
    with_captured_log_sink(|_| body())
}

/// Without `--pprof` nothing is logged and nothing is started, whatever the build. This is the
/// common case: the flag defaults to false.
#[test]
fn test_start_disabled_is_silent() {
    let logged = with_captured_log(|| start(false));
    assert_eq!(logged, "");
}

/// The default build: `--pprof` is accepted, and says once that the profiler is not in it (D23).
#[cfg(not(all(feature = "pprof", unix)))]
#[test]
fn test_start_without_feature_logs_not_available() {
    let logged = with_captured_log(|| start(true));

    // One line, ending in the D23 text (the prefix is the log header: date, time and file:line).
    assert_eq!(logged.matches('\n').count(), 1, "{logged:?}");
    assert!(
        logged.ends_with("pprof: not available in this build\n"),
        "{logged:?}"
    );
    assert_eq!(NOT_AVAILABLE, "pprof: not available in this build");
}

/// The profiling build: `start(true)` spawns the server instead of logging the D23 line, and
/// `--pprof` behaves like Go's. The port is the fixed `:6060`, which another process (or another
/// test run) may hold, so the failure path is the only thing that may be logged.
#[cfg(all(feature = "pprof", unix))]
#[test]
fn test_start_with_feature_serves_or_reports_the_port() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    // Which of the two outcomes happened is only known once the spawned task has bound the port
    // or failed to, so wait for one of them rather than for a fixed delay.
    let mut listening = false;
    let logged = with_captured_log_sink(|sink| {
        runtime.block_on(async {
            start(true);
            // Up to ~3 s, in 20 ms steps.
            for _ in 0..150 {
                tokio::task::yield_now().await;
                if std::net::TcpStream::connect(("127.0.0.1", PORT))
                    .or_else(|_| std::net::TcpStream::connect(("::1", PORT)))
                    .is_ok()
                {
                    listening = true;
                    return;
                }
                if !sink.text().is_empty() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        });
    });

    assert!(!logged.contains(NOT_AVAILABLE), "{logged:?}");
    if !listening {
        // The listener never came up, so the only line this may produce is Go's, when :6060 is
        // already taken by another process or another run.
        assert!(
            logged.contains("pprof server: listen tcp :6060: bind: "),
            "{logged:?}"
        );
    }
}

/// The constants the binaries and the docs quote.
#[test]
fn test_constants() {
    assert_eq!(ADDR, ":6060");
    assert_eq!(PORT, 6060);
    assert_eq!(PROFILE_PATH, "/debug/pprof/profile");
}
