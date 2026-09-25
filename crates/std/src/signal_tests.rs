//! Tests for [`crate::signal`].
//!
//! The termination path is exercised through the [`ExitActions`] seam, so a test can watch the
//! process re-raise `SIGTERM` without being terminated by it.
//!
//! The two tests that want the *real* handlers and a real signal — `test_sigterm_…` and
//! `test_sigusr1_…` — re-exec this binary and signal the child. Neither may call [`install`] in
//! the test process: tokio never unregisters the libc handler it installs (tokio-1.53.1
//! `src/signal/unix.rs`: "the libc signal handler is never unregistered"), so once the test's
//! runtime is dropped, `SIGUSR1`, `SIGTERM` and `SIGINT` would be caught with nothing draining
//! tokio's signal pipe — the test binary would ignore Ctrl-C and any harness `SIGTERM` from then
//! on, and would need `SIGKILL`.

use std::sync::{Arc, Mutex};

use super::*;
// Only the re-exec tests below, which are unix-only, capture the log.
#[cfg(unix)]
use crate::log;

/// Serialises the tests: the hook registry and the logger are both process-wide.
static HOOK_LOCK: Mutex<()> = Mutex::new(());

/// What [`on_terminate`] did, in order.
#[derive(Debug, Default)]
struct Recorder {
    events: Mutex<Vec<&'static str>>,
}

impl Recorder {
    fn events(&self) -> Vec<&'static str> {
        self.events
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn push(&self, event: &'static str) {
        self.events
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(event);
    }
}

impl ExitActions for Recorder {
    fn schedule_fallback_exit(&self) {
        self.push("fallback exit");
    }

    fn reraise_sigterm(&self) {
        self.push("re-raise SIGTERM");
    }
}

/// Go's `postProcess()` body: the tcpraw reset goes into the registry like any other hook, and
/// running it with no fake-TCP connection open does nothing at all — the state of every kcptun
/// process started without `--tcp`, and of every process on a platform without raw sockets.
#[test]
fn test_register_iptables_reset() {
    let _guard = HOOK_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    post_process(); // drain whatever another test left behind

    register_iptables_reset();
    let marker = Arc::new(Mutex::new(false));
    let flag = Arc::clone(&marker);
    register_exit_hook(move || *flag.lock().unwrap() = true);

    post_process();
    assert!(
        *marker.lock().unwrap(),
        "the reset ran and the next hook after it too"
    );

    // Nothing is left registered, so a second call runs nothing.
    post_process();
}

#[test]
fn test_post_process_runs_hooks_in_order_once() {
    let _guard = HOOK_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    post_process(); // drain whatever another test left behind

    let ran = Arc::new(Mutex::new(Vec::new()));
    for name in ["first", "second", "third"] {
        let ran = Arc::clone(&ran);
        register_exit_hook(move || ran.lock().unwrap().push(name));
    }
    assert!(
        ran.lock().unwrap().is_empty(),
        "hooks run on the signal only"
    );

    post_process();
    assert_eq!(*ran.lock().unwrap(), ["first", "second", "third"]);

    // Go's postProcess is idempotent because iptables_reset is; the registry is, because a hook
    // is consumed when it runs.
    post_process();
    assert_eq!(*ran.lock().unwrap(), ["first", "second", "third"]);
}

/// A hook may register another one (and log) while it runs: the registry must not be locked.
#[test]
fn test_exit_hook_may_register_another() {
    let _guard = HOOK_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    post_process();

    let ran = Arc::new(Mutex::new(Vec::new()));
    let ran_outer = Arc::clone(&ran);
    register_exit_hook(move || {
        ran_outer.lock().unwrap().push("outer");
        let ran_inner = Arc::clone(&ran_outer);
        register_exit_hook(move || ran_inner.lock().unwrap().push("inner"));
    });

    post_process();
    assert_eq!(*ran.lock().unwrap(), ["outer"]);
    post_process();
    assert_eq!(*ran.lock().unwrap(), ["outer", "inner"]);
}

/// Go: postProcess(), signal.Stop(ch), Kill(getpid(), SIGTERM), then the EXIT_WAIT fallback.
#[test]
fn test_on_terminate_runs_hooks_then_terminates() {
    let _guard = HOOK_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    post_process();

    let recorder = Recorder::default();
    let hook_ran = Arc::new(Mutex::new(false));
    let flag = Arc::clone(&hook_ran);
    register_exit_hook(move || *flag.lock().unwrap() = true);

    on_terminate(&recorder);

    assert!(*hook_ran.lock().unwrap(), "the exit hooks run first");
    assert_eq!(recorder.events(), ["fallback exit", "re-raise SIGTERM"]);
}

#[test]
fn test_exit_wait_matches_go() {
    assert_eq!(EXIT_WAIT, 5);
}

/// The environment variable that marks the re-exec'd child of the two panic-path tests, and the
/// test the child is launched with.
#[cfg(unix)]
const PANIC_CHILD_ENV: &str = "KCPTUN_STD_PANIC_HOOK_CHILD";
#[cfg(unix)]
const PANIC_CHILD_TEST: &str = "signal::tests::test_a_panic_runs_the_exit_hooks";

/// The child both panic-path tests observe: a panic hook installed **before**
/// [`run_exit_hooks_on_panic`], then an exit hook, then a panic. Each step announces itself on
/// stdout, so the parent can check both that the exit hooks ran and that they ran *after* the
/// hook that was already there.
///
/// Everything here is process-global — the panic hook, the exit-hook registry — which is why it
/// lives in a child and not in the shared test process: `HOOK_LOCK` serialises the exit-hook
/// tests, but nothing stops the other ~500 tests in this binary from panicking while a
/// replacement panic hook is installed, and such a panic would lose its
/// `thread '…' panicked at …` line (libtest reports what the panic hook prints).
#[cfg(unix)]
fn panic_child() -> ! {
    fn say(line: &str) {
        use std::io::Write as _;
        // stdout is a pipe here, so it is block-buffered: flush, or the line dies with the
        // process.
        println!("{line}");
        let _ = std::io::stdout().flush();
    }

    // The hook `run_exit_hooks_on_panic` will chain to. It forwards to the one *it* replaced, so
    // the panic message and its backtrace still reach stderr exactly as they did.
    let inherited = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        say("previous hook");
        inherited(info);
    }));

    register_exit_hook(|| say("hook ran"));
    run_exit_hooks_on_panic();
    panic!("a panic on the way out");
}

/// Runs [`panic_child`] in a re-exec'd copy of this test binary and returns its stdout together
/// with whether it exited successfully.
#[cfg(unix)]
fn panic_child_output() -> (String, bool) {
    let output = {
        let _fds = kcptun_testkit::socket_creation_guard();
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", PANIC_CHILD_TEST, "--nocapture"])
            .env(PANIC_CHILD_ENV, "1")
            .stderr(std::process::Stdio::null())
            .output()
            .unwrap()
    };
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        output.status.success(),
    )
}

/// A panic runs the exit hooks, which is what stops a `--tcp` process leaving tcpraw's
/// `filter/OUTPUT` rules behind when it dies of one. Go's `postProcess` is reached from the
/// signal handler alone and does *not* run here.
///
/// The exit-hook registry and the panic hook are both process-wide, and a panicking test can
/// assert nothing afterwards, so this runs in a re-exec'd child and the parent reads its output.
/// The test binary is built with `panic = "unwind"`; the release binaries abort instead (D24),
/// and the panic runtime calls the hook before the abort either way.
#[cfg(unix)]
#[test]
fn test_a_panic_runs_the_exit_hooks() {
    if std::env::var_os(PANIC_CHILD_ENV).is_some() {
        panic_child();
    }

    let (text, success) = panic_child_output();
    assert!(
        text.lines().any(|line| line == "hook ran"),
        "the exit hooks did not run on the panic path:\n{text}"
    );
    assert!(!success, "the child should have panicked");
}

/// The hook that was installed before still runs, and first: the panic message and its backtrace
/// look exactly as they did, and the exit hooks run after them.
///
/// Asserted on the same child as [`test_a_panic_runs_the_exit_hooks`]: installing a replacement
/// panic hook in the shared test process would swallow the panic report of any other test that
/// happened to fail in that window.
#[cfg(unix)]
#[test]
fn test_the_panic_hook_chains_the_previous_one() {
    // The child is always launched with `--exact PANIC_CHILD_TEST`, so this arm is unreachable;
    // returning keeps a stray filter from spawning a grandchild.
    if std::env::var_os(PANIC_CHILD_ENV).is_some() {
        return;
    }

    let (text, _) = panic_child_output();
    let order: Vec<&str> = text
        .lines()
        .filter(|line| matches!(*line, "previous hook" | "hook ran"))
        .collect();
    assert_eq!(
        order,
        ["previous hook", "hook ran"],
        "the inherited panic hook must run, and run first:\n{text}"
    );
}

/// The whole shutdown path in a real process: `SIGTERM` runs the exit hooks and then **kills**
/// the process with `SIGTERM`, so a supervisor sees the same wait status Go's binaries produce
/// (signalled, not exited). The test re-runs itself as a child, marked by an environment
/// variable, because nothing else can observe a process dying of a signal.
#[cfg(unix)]
#[test]
fn test_sigterm_terminates_with_the_signal() {
    use std::io::{BufRead as _, BufReader, Write as _};

    const CHILD_ENV: &str = "KCPTUN_STD_SIGTERM_CHILD";
    const TEST_NAME: &str = "signal::tests::test_sigterm_terminates_with_the_signal";

    if std::env::var_os(CHILD_ENV).is_some() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            register_exit_hook(|| {
                // stdout is a pipe here, so it is block-buffered: flush, or the line dies with
                // the process.
                println!("hook ran");
                let _ = std::io::stdout().flush();
            });
            install().unwrap();
            println!("ready");
            let _ = std::io::stdout().flush();
            // The parent kills this process long before the sleep ends; if the re-raise ever
            // failed, the EXIT_WAIT fallback would exit(0) after 5 s and fail the assertion
            // below rather than hang.
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        });
        return;
    }

    let mut child = {
        let _fds = kcptun_testkit::socket_creation_guard();
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(CHILD_ENV, "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap()
    };
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let ready = lines
        .by_ref()
        .map_while(Result::ok)
        // `ends_with`, not `==`: libtest prints `test <name> ... ` WITHOUT a trailing newline
        // before the test body runs, so on Linux the child's own "ready" lands on that same line
        // and an equality test never matches. macOS happens to flush in the other order, which is
        // why the laptop gate could not see this and three signal tests were silently failing on
        // Linux (found in 10.6, on both libcs).
        .any(|line| line.trim_end().ends_with("ready"));
    assert!(ready, "the child never installed its handlers");

    let killed = {
        let _fds = kcptun_testkit::socket_creation_guard();
        std::process::Command::new("kill")
            .arg("-TERM")
            .arg(child.id().to_string())
            .status()
            .unwrap()
    };
    assert!(killed.success());

    let rest: Vec<String> = lines.map_while(Result::ok).collect();
    let status = child.wait().unwrap();
    assert!(
        rest.iter().any(|line| line == "hook ran"),
        "the exit hooks run before the process dies: {rest:?}"
    );
    // Go: signal.Stop(ch) + Kill(getpid(), SIGTERM) — the status says "killed by SIGTERM", not
    // "exited with 0".
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&status),
        Some(signal_hook::consts::signal::SIGTERM),
        "expected death by SIGTERM, got {status:?}"
    );
}

/// The real handler, with a real signal: `SIGUSR1` logs the SNMP snapshot in Go's `%+v` shape.
///
/// Like the `SIGTERM` test above, this runs in a re-exec'd child. `install()` is not reversible:
/// tokio registers its libc handler through a `OnceCell` and "the libc signal handler is never
/// unregistered" (tokio-1.53.1 `src/signal/unix.rs`). Calling it in the test process would leave
/// `SIGUSR1`, `SIGTERM` and `SIGINT` caught with no runtime draining tokio's signal pipe after the
/// runtime is dropped, so the test binary would silently ignore Ctrl-C and any harness `SIGTERM`
/// for the rest of the run.
#[cfg(unix)]
#[test]
fn test_sigusr1_logs_snmp_snapshot() {
    use std::io::Write as _;

    const CHILD_ENV: &str = "KCPTUN_STD_SIGUSR1_CHILD";
    const TEST_NAME: &str = "signal::tests::test_sigusr1_logs_snmp_snapshot";

    if std::env::var_os(CHILD_ENV).is_some() {
        let _guard = log::TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let sink = Capture::new();
        log::set_output(Box::new(sink.clone()));

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            // install() registers the handlers before it returns, so the signal below cannot
            // arrive while SIGUSR1 still has its default (terminating) disposition.
            install().unwrap();

            // `kill(2)` needs no crate of its own: the shell command sends the signal, and the
            // guard keeps the grandchild from inheriting a socket another test thread is
            // creating (see `kcptun_testkit::socket_creation_guard`).
            let killed = {
                let _fds = kcptun_testkit::socket_creation_guard();
                std::process::Command::new("kill")
                    .arg("-USR1")
                    .arg(std::process::id().to_string())
                    .status()
                    .unwrap()
            };
            assert!(killed.success());

            // The handler runs on another task; give it up to a second of real time.
            for _ in 0..100 {
                if !sink.text().is_empty() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        });
        log::set_output_stderr();

        let text = sink.text();
        let snapshot = kcptun_kcp::snmp::DEFAULT_SNMP.copy();
        assert!(
            text.contains(&format!("KCP SNMP:{snapshot}")),
            "logged {text:?}"
        );
        // stdout is a pipe here, so it is block-buffered: flush, or the parent sees nothing.
        print!("{text}");
        let _ = std::io::stdout().flush();
        return;
    }

    let output = {
        let _fds = kcptun_testkit::socket_creation_guard();
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(CHILD_ENV, "1")
            .stderr(std::process::Stdio::null())
            .output()
            .unwrap()
    };
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "the child failed: {}",
        output.status
    );
    assert!(text.contains("KCP SNMP:&{BytesSent:"), "logged {text:?}");
}

/// A log sink the test can read back. Only the unix-only re-exec tests above use it.
#[cfg(unix)]
#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);

#[cfg(unix)]
impl Capture {
    fn new() -> Capture {
        Capture(Arc::new(Mutex::new(Vec::new())))
    }

    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

#[cfg(unix)]
impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
