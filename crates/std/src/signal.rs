//! Signal handling and the exit hooks it runs.
//!
//! Go sources:
//! - `kcptun/std/signal.go` (`//go:build linux || darwin || freebsd`) — `init()` starts
//!   `sigHandler()`, which serves `SIGUSR1`, `SIGTERM` and `SIGINT` and ignores `SIGPIPE`;
//! - `kcptun/std/atexit.go` (`!linux`) and `atexit_linux.go` — `postProcess()`, empty except on
//!   Linux, where it calls `tcpraw.IPTablesReset()`.
//!
//! What the handler does:
//!
//! | Signal | Go | Here |
//! |---|---|---|
//! | `SIGUSR1` | `log.Printf("KCP SNMP:%+v", kcp.DefaultSnmp.Copy())` | the same line, from [`kcptun_kcp::snmp::DEFAULT_SNMP`] |
//! | `SIGINT`, `SIGTERM` | `postProcess()`, then the default disposition and a re-raised `SIGTERM`, with a 5 s `os.Exit(0)` fallback | [`post_process`], then the same |
//! | `SIGPIPE` | `signal.Ignore` | Rust's runtime already sets `SIG_IGN` at start-up |
//!
//! Re-raising is what makes `kcptun_client` die *of* `SIGTERM` rather than exiting with a status
//! of its own, so a supervisor sees the same wait status as with the Go binary.
//! `signal_hook::low_level::emulate_default_handler` performs the reset-and-raise; it is a safe
//! wrapper, so this crate keeps `#![forbid(unsafe_code)]`.
//!
//! **Exit hooks.** Go hard-codes `postProcess`, whose one job (Linux) is undoing tcpraw's iptables
//! rule. The rule is set up in Step 10, so this module keeps a registry instead:
//! [`register_exit_hook`] adds a closure, and the handler runs every registered hook once, in
//! registration order. [`register_iptables_reset`] puts Go's own `postProcess` body into it, and
//! the binaries call that at start-up (Step 10.4). Nothing else about the shutdown path changes.
//!
//! The hooks also run on the exit paths Go leaves uncovered — [`crate::log::fatal`],
//! [`crate::log::check_error`], a returning `main`, and (through
//! [`run_exit_hooks_on_panic`]) a panic — because a leftover `iptables` rule outlives the
//! process that installed it. `SIGKILL` remains the one case nothing can clean up after, in this
//! port exactly as in Go.
//!
//! **Windows.** Go does not build `signal.go` there at all, and neither does this port:
//! [`install`] is a no-op that returns `Ok(())`, while [`register_exit_hook`] and [`post_process`]
//! keep working, so a caller can still run its hooks on its own shutdown path.

use std::sync::Mutex;

/// Maximum number of seconds to wait for the re-raised `SIGTERM` to end the process.
// Go: kcptun/std/signal.go:EXIT_WAIT
pub const EXIT_WAIT: u64 = 5;

/// A hook registered with [`register_exit_hook`]; it runs at most once.
type ExitHook = Box<dyn FnOnce() + Send>;

/// Hooks to run when a termination signal arrives, in registration order.
// Go: kcptun/std/atexit_linux.go:postProcess() — a fixed body, a registry here.
static EXIT_HOOKS: Mutex<Vec<ExitHook>> = Mutex::new(Vec::new());

/// Registers a hook to run on `SIGINT`/`SIGTERM`, before the process is terminated.
///
/// Step 10 registers tcpraw's `iptables_reset()` here, which is all Go's `postProcess()` does.
/// Hooks run on the signal-handling task, in the order they were registered, and each runs at
/// most once.
// Go: kcptun/std/atexit_linux.go:postProcess()
pub fn register_exit_hook(hook: impl FnOnce() + Send + 'static) {
    hooks().push(Box::new(hook));
}

/// Registers tcpraw's `iptables_reset()` as an exit hook, which is the whole of Go's
/// `postProcess()`: on `SIGINT`/`SIGTERM` every live fake-TCP connection is closed, and closing
/// one removes the `filter/OUTPUT` rules it added.
///
/// The client and server call this once at start-up (Step 10.4), whether or not `--tcp` is on —
/// as in Go, where the call is compiled in unconditionally and finds nothing to do when no
/// tcpraw connection was ever made. On a platform without raw sockets it is a no-op, like Go's
/// `atexit.go`.
///
/// **It blocks** while `iptables`/`ip6tables` run, which is what makes the rules gone by the time
/// the process re-raises `SIGTERM`; Go's `postProcess` blocks its signal goroutine in exactly the
/// same way. The hook therefore occupies the signal-handling task for that time — acceptable
/// precisely because the process is on its way out.
// Go: kcptun/std/atexit_linux.go:postProcess()
pub fn register_iptables_reset() {
    register_exit_hook(kcptun_tcpraw::iptables_reset);
}

/// Makes a panic run the exit hooks too, so a `--tcp` process that dies of one does not leave
/// tcpraw's `filter/OUTPUT` rules behind.
///
/// Go has no equivalent: `postProcess` is reached from the signal handler alone, so a Go kcptun
/// that panics keeps its rules. This port runs the hooks on every exit path it controls
/// (step 10.4), and a panic is one of them.
///
/// The hook that was installed before — the default one, which prints the message and the
/// backtrace — runs first, so the panic still looks exactly as it did. `panic = "abort"` (D24)
/// does not skip it: the panic runtime calls the hook and only then aborts.
///
/// It is **not** a substitute for the signal path, and it does not see a bare `abort(2)`. The one
/// place this port aborts without panicking — tcpraw's accept loop, when the TTL of an accepted
/// connection cannot be pinned — therefore runs `iptables_reset` itself. Nothing at all can clean
/// up after `SIGKILL`, here or in Go.
pub fn run_exit_hooks_on_panic() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        previous(info);
        post_process();
    }));
}

/// Runs and forgets every registered exit hook.
// Go: kcptun/std/atexit.go:postProcess(), kcptun/std/atexit_linux.go:postProcess()
pub fn post_process() {
    // Taken out under the lock, run outside it: a hook must be free to register another one (and
    // to log, which takes its own lock).
    let hooks: Vec<_> = std::mem::take(&mut *hooks());
    for hook in hooks {
        hook();
    }
}

fn hooks() -> std::sync::MutexGuard<'static, Vec<ExitHook>> {
    // A panicking hook must not disable the rest of the shutdown path.
    EXIT_HOOKS.lock().unwrap_or_else(|p| p.into_inner())
}

/// Logs the SNMP snapshot, the way `SIGUSR1` asks for it.
// Go: kcptun/std/signal.go:sigHandler(), case syscall.SIGUSR1
// Only the unix `install` calls it; it is left compiled rather than `#[cfg(unix)]`-gated so the
// body keeps being type-checked on every target.
#[cfg_attr(not(unix), allow(dead_code))]
fn on_sigusr1() {
    // Go: log.Printf("KCP SNMP:%+v", kcp.DefaultSnmp.Copy()) — `%+v` of a *Snmp is
    // `&{BytesSent:0 …}`, which is what SnmpSnapshot's Display writes.
    crate::logf!("KCP SNMP:{}", kcptun_kcp::snmp::DEFAULT_SNMP.copy());
}

/// The two things that end the process, injectable so the shutdown path can be tested without
/// taking the test binary down with it.
///
/// Only the unix `install` has a real implementation (`unix::ProcessExit`); the trait itself
/// stays compiled everywhere, for the tests' sake.
#[cfg_attr(not(unix), allow(dead_code))]
trait ExitActions {
    /// Go: the `exitOnce` goroutine — `os.Exit(0)` after [`EXIT_WAIT`] seconds.
    fn schedule_fallback_exit(&self);
    /// Go: `signal.Stop(ch)` followed by `syscall.Kill(syscall.Getpid(), syscall.SIGTERM)`.
    fn reraise_sigterm(&self);
}

/// Runs the shutdown path of `SIGINT`/`SIGTERM`.
// Go: kcptun/std/signal.go:sigHandler(), case syscall.SIGTERM, syscall.SIGINT
#[cfg_attr(not(unix), allow(dead_code))]
fn on_terminate(actions: &dyn ExitActions) {
    post_process();
    // Go arms the fallback after the re-raise; it is armed first here because it exists precisely
    // for the case where the re-raise does *not* end the process, and that ordering is the only
    // one in which the fallback is certain to be armed. When the re-raise works — every normal
    // shutdown — neither order is observable, since the process is gone before the timer starts.
    actions.schedule_fallback_exit();
    actions.reraise_sigterm();
}

#[cfg(unix)]
pub use self::unix::install;

#[cfg(unix)]
mod unix {
    use std::io;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use tokio::signal::unix::{SignalKind, signal};

    use super::{EXIT_WAIT, ExitActions, on_sigusr1, on_terminate};

    /// Starts the signal-handling task: `SIGUSR1` dumps SNMP, `SIGINT`/`SIGTERM` shut the process
    /// down through the registered exit hooks.
    ///
    /// Go runs this from `init()`, so it is impossible to get wrong and impossible to fail. Here
    /// it needs a tokio runtime, so the caller starts it (`std::signal::install()` early in
    /// `main`), and installing the handlers can report an OS error, which Go's `signal.Notify`
    /// hides.
    ///
    /// `SIGPIPE` needs no attention: Rust's runtime sets it to `SIG_IGN` before `main`, which is
    /// what Go's `signal.Ignore(syscall.SIGPIPE)` arranges.
    // Go: kcptun/std/signal.go:init(), sigHandler()
    pub fn install() -> io::Result<()> {
        // The handlers are installed here, not inside the task, so that a signal arriving right
        // after `install()` returns is already caught (and so that the error is reported to the
        // caller).
        let mut sigusr1 = signal(SignalKind::user_defined1())?;
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;

        // Go: go sigHandler()
        tokio::spawn(async move {
            loop {
                // Go serves one signal at a time from a single channel; `recv()` is cancel-safe,
                // so the branches that lose the race keep their pending signal.
                tokio::select! {
                    _ = sigusr1.recv() => on_sigusr1(),
                    _ = sigterm.recv() => on_terminate(&ProcessExit),
                    _ = sigint.recv() => on_terminate(&ProcessExit),
                }
            }
        });
        Ok(())
    }

    /// The real shutdown: re-raise `SIGTERM` at its default disposition, and exit anyway after
    /// [`EXIT_WAIT`] seconds if that somehow left the process running.
    struct ProcessExit;

    /// Go: `var exitOnce sync.Once` — the fallback timer is armed once, however many signals
    /// arrive.
    static EXIT_ONCE: AtomicBool = AtomicBool::new(false);

    impl ExitActions for ProcessExit {
        fn schedule_fallback_exit(&self) {
            if EXIT_ONCE.swap(true, Ordering::SeqCst) {
                return;
            }
            // Go: go func() { time.Sleep(EXIT_WAIT * time.Second); os.Exit(0) }()
            tokio::spawn(async {
                tokio::time::sleep(Duration::from_secs(EXIT_WAIT)).await;
                std::process::exit(0);
            });
        }

        fn reraise_sigterm(&self) {
            // Go: signal.Stop(ch) restores SIGTERM's default disposition (no handler is left),
            // and syscall.Kill(getpid(), SIGTERM) then terminates the process *by the signal*, so
            // the wait status says "killed by SIGTERM". `emulate_default_handler` is the same
            // two steps: reset to SIG_DFL, unblock, raise. It returns only if that failed, and
            // the fallback timer then exits with 0.
            let _ = signal_hook::low_level::emulate_default_handler(
                signal_hook::consts::signal::SIGTERM,
            );
        }
    }
}

/// Windows has none of the signals `std/signal.go` serves, and Go excludes the file from the
/// build there; nothing is installed. [`register_exit_hook`] and [`post_process`] still work.
// Go: kcptun/std/signal.go — //go:build linux || darwin || freebsd
#[cfg(not(unix))]
pub fn install() -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
#[path = "signal_tests.rs"]
mod tests;
