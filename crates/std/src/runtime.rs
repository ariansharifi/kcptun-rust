//! The tokio runtime the binaries run on, and the environment variable that sizes it.
//!
//! kcptun never calls `runtime.GOMAXPROCS` itself: its goroutines are spread over however many
//! threads the Go runtime decided to use, which is the CPU count unless `GOMAXPROCS` says
//! otherwise. Go source: `runtime/proc.go:schedinit` (Go 1.27.1),
//!
//! ```go
//! var procs int32
//! if n, err := strconv.ParseInt(gogetenv("GOMAXPROCS"), 10, 32); err == nil && n > 0 {
//!     procs = int32(n)
//!     sched.customGOMAXPROCS = true
//! } else {
//!     procs = defaultGOMAXPROCS(numCPUStartup)
//! }
//! ```
//!
//! **D01**: this port runs on tokio's multi-threaded runtime with one worker thread per CPU, and
//! reads `GOMAXPROCS` the same way, so a deployment that pins it today keeps working. Note the
//! base: `ParseInt(s, 10, 32)` is decimal only — unlike the flag values, which Go parses with
//! base 0 (`crate::cli`) — it rejects underscores, `0x` prefixes and surrounding spaces, and it
//! overflows above `i32::MAX`. Anything that does not parse, or is not positive, falls back to
//! the CPU count, again like Go.

use std::io;
use std::num::NonZeroUsize;

/// The environment variable Go's runtime reads at start-up.
// Go: runtime/proc.go:schedinit — gogetenv("GOMAXPROCS")
pub const GOMAXPROCS: &str = "GOMAXPROCS";

/// The name tokio gives the worker threads, so `top -H` / `perf` show where the time goes.
const WORKER_NAME: &str = "kcptun-worker";

/// `GOMAXPROCS` as Go's runtime reads it: `Some(n)` only for a decimal integer that fits in an
/// `int32` and is greater than zero.
///
/// ```
/// # use kcptun_std::runtime::parse_gomaxprocs;
/// assert_eq!(parse_gomaxprocs("4"), Some(4));
/// assert_eq!(parse_gomaxprocs("+4"), Some(4));
/// assert_eq!(parse_gomaxprocs("0"), None);      // not > 0
/// assert_eq!(parse_gomaxprocs("0x4"), None);    // base 10, unlike the flag parser
/// assert_eq!(parse_gomaxprocs(" 4"), None);
/// ```
// Go: runtime/proc.go:schedinit, strconv/atoi.go:ParseInt(s, 10, 32)
pub fn parse_gomaxprocs(s: &str) -> Option<usize> {
    // Go: ParseInt accepts one leading sign, then base-10 digits only (underscores need base 0).
    let (neg, digits) = match s.as_bytes().first() {
        Some(b'+') => (false, &s[1..]),
        Some(b'-') => (true, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty() {
        // Go: ErrSyntax.
        return None;
    }
    let mut n: u64 = 0;
    for b in digits.bytes() {
        if !b.is_ascii_digit() {
            // Go: ErrSyntax.
            return None;
        }
        // Go: ErrRange for anything an int32 cannot hold; the accumulator only has to stay big
        // enough to notice, so it saturates just past the bit size Go checks.
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(b - b'0')))?;
        if n > i32::MAX as u64 {
            return None;
        }
    }
    // Go: `err == nil && n > 0` — a negative or zero value is parsed, then ignored.
    if neg || n == 0 {
        return None;
    }
    Some(n as usize)
}

/// The number of worker threads for a given `GOMAXPROCS` value (`None` when it is unset).
// Go: runtime/proc.go:schedinit
pub fn worker_threads_for(gomaxprocs: Option<&str>) -> usize {
    match gomaxprocs.and_then(parse_gomaxprocs) {
        Some(n) => n,
        None => default_worker_threads(),
    }
}

/// The number of worker threads to use, reading `GOMAXPROCS` from the environment.
// Go: runtime/proc.go:schedinit
pub fn worker_threads() -> usize {
    worker_threads_for(std::env::var(GOMAXPROCS).ok().as_deref())
}

/// One worker per CPU, the runtime's default when `GOMAXPROCS` says nothing.
///
/// Both counts start from the CPUs the process may run on (`sched_getaffinity` on Linux) and fall
/// back to 1 when that is unavailable, but they round a cgroup CPU limit differently, so a
/// container with a *fractional* limit gets fewer workers here than Go gets Ps:
///
/// * Go (1.25+) takes `min(ncpu, max(ceil(quota/period), 2))` —
///   `runtime/cgroup_linux.go:defaultGOMAXPROCS` → `adjustCgroupGOMAXPROCS` (Go 1.27.1);
/// * Rust's `available_parallelism` divides quota by period rounding *down*, with a floor of 1.
///
/// At a 1.5 CPU limit Go runs 2 Ps and this runs 1 worker; at 2.5, 3 against 2. It is a
/// performance difference only — nothing reaches the wire — and D01 specifies
/// `available_parallelism`; a container deployment that cares should set `GOMAXPROCS` explicitly,
/// which both runtimes then obey (see the README).
// Go: runtime/proc.go:schedinit → defaultGOMAXPROCS(numCPUStartup)
pub fn default_worker_threads() -> usize {
    std::thread::available_parallelism().map_or(1, NonZeroUsize::get)
}

/// Builds the multi-threaded runtime the binaries run on (D01), sized by [`worker_threads`].
///
/// All drivers are enabled: kcptun needs the I/O driver for its UDP and TCP sockets, the time
/// driver for KCP's 10 ms ticks, smux keep-alives and the scavenger, and the signal handler of
/// [`crate::signal`] rides on both.
pub fn build() -> io::Result<tokio::runtime::Runtime> {
    build_with(worker_threads())
}

/// [`build`] with an explicit worker count; `0` is raised to `1`, which tokio requires.
pub fn build_with(worker_threads: usize) -> io::Result<tokio::runtime::Runtime> {
    // No `on_thread_park` hook: plan 12.3's process-wide trim is `kcptun_kcp::memory::trim`, and
    // the one allocator that can be asked to give pages back (glibc's `malloc_trim`) walks every
    // arena from whichever thread calls it. A per-worker hook was needed only by the
    // thread-caching `mimalloc` build, which D07 rejected and 12.3d deleted.
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads.max(1))
        .thread_name(WORKER_NAME)
        .enable_all()
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The two lists below were run through Go 1.27.1 itself, case for case: a child process
    // started with `GOMAXPROCS=<case>` printing `runtime.GOMAXPROCS(0)` (10 = this machine's
    // NumCPU, i.e. the fallback). Only "1", "8", "+8", "0008" and "2147483647" changed it;
    // everything in the second list fell back. (Go accepts 2147483647 and then dies trying to
    // create that many Ps — the value is honoured, which is what is asserted here.)

    /// Values Go's `strconv.ParseInt(s, 10, 32)` accepts and `schedinit` then uses.
    #[test]
    fn test_parse_gomaxprocs_valid() {
        assert_eq!(parse_gomaxprocs("1"), Some(1));
        assert_eq!(parse_gomaxprocs("8"), Some(8));
        assert_eq!(parse_gomaxprocs("+8"), Some(8));
        assert_eq!(parse_gomaxprocs("0008"), Some(8));
        assert_eq!(parse_gomaxprocs("2147483647"), Some(2_147_483_647));
    }

    /// Everything Go rejects (syntax or range) or parses but does not use (`n > 0` fails).
    #[test]
    fn test_parse_gomaxprocs_invalid() {
        for s in [
            "",            // ErrSyntax
            "+",           // ErrSyntax
            "-",           // ErrSyntax
            "abc",         // ErrSyntax
            "4x",          // ErrSyntax
            "0x4",         // base 10: the `x` is a syntax error
            "0o4",         // idem
            "1_0",         // underscores need base 0
            " 4",          // no space is trimmed
            "4 ",          // idem
            "4\n",         // idem
            "4.0",         // ErrSyntax
            "2147483648",  // ErrRange for bitSize 32
            "99999999999", // idem
            "0",           // parses, but `n > 0` is false
            "-1",          // idem
            "-2147483648", // idem
        ] {
            assert_eq!(parse_gomaxprocs(s), None, "GOMAXPROCS={s:?}");
        }
    }

    /// A valid value wins; an invalid one and an unset variable both fall back to the CPU count.
    #[test]
    fn test_worker_threads_for() {
        assert_eq!(worker_threads_for(Some("3")), 3);
        assert_eq!(worker_threads_for(Some("1")), 1);

        let cpus = default_worker_threads();
        assert!(cpus >= 1);
        assert_eq!(worker_threads_for(None), cpus);
        assert_eq!(worker_threads_for(Some("")), cpus);
        assert_eq!(worker_threads_for(Some("bogus")), cpus);
        assert_eq!(worker_threads_for(Some("0")), cpus);
        assert_eq!(worker_threads_for(Some("-2")), cpus);
    }

    /// The process's own `GOMAXPROCS`, whatever it is, is read the same way. (The variable is
    /// not set here: `std::env::set_var` is `unsafe` in edition 2024 and this crate forbids
    /// `unsafe`, so the injectable [`worker_threads_for`] carries the cases above.)
    #[test]
    fn test_worker_threads_reads_the_environment() {
        match std::env::var(GOMAXPROCS) {
            // Set and usable: that value, not the CPU count.
            Ok(v) if parse_gomaxprocs(&v).is_some() => {
                assert_eq!(worker_threads(), parse_gomaxprocs(&v).unwrap());
            }
            // Unset, or set to something Go ignores: the CPU count.
            _ => assert_eq!(worker_threads(), default_worker_threads()),
        }
    }

    /// The runtime really is multi-threaded and really has the requested number of workers.
    #[test]
    fn test_build_with_worker_count() {
        let rt = build_with(2).unwrap();
        assert_eq!(rt.metrics().num_workers(), 2);
        // The drivers are enabled: this needs both the timer and a spawned task.
        rt.block_on(async {
            tokio::spawn(tokio::time::sleep(std::time::Duration::from_millis(1)))
                .await
                .unwrap();
        });

        // tokio rejects 0 workers; Go never gets there either (`n > 0`).
        let rt = build_with(0).unwrap();
        assert_eq!(rt.metrics().num_workers(), 1);
    }
}
