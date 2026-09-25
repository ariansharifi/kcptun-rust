//! CPU time of this process and of its finished children, for the benchmark harnesses
//! (plan step 05.9, Step 12).
//!
//! Wall-clock throughput alone cannot say which implementation is cheaper: a benchmark that is
//! slower because it was descheduled looks the same as one that burns more cycles. Both numbers
//! come from `getrusage(2)`, which POSIX defines and macOS and Linux both implement with
//! microsecond resolution:
//!
//! | Function | `who` | Counts |
//! |---|---|---|
//! | [`self_cpu`] | `RUSAGE_SELF` | every thread of this process |
//! | [`children_cpu`] | `RUSAGE_CHILDREN` | every child that has been **waited for** |
//!
//! `RUSAGE_CHILDREN` is a running total over reaped children only, so a harness that spawns a
//! peer must reap it (`Proc::kill`, or a `wait` that saw it exit: [`proc`](crate::proc) does
//! both) before reading the counter, and must not let unrelated children be reaped in between.
//! Take a reading before and after the measured work and subtract:
//!
//! ```no_run
//! let before = kcptun_testkit::cpu::children_cpu().expect("getrusage");
//! // ... spawn a peer, run the transfer, kill and reap the peer ...
//! let cpu = kcptun_testkit::cpu::children_cpu().expect("getrusage").saturating_sub(before);
//! println!("{cpu}");
//! ```
//!
//! This is the one place in the workspace outside `kcptun-kcp`'s batched I/O, its SIMD kernels
//! and `kcptun-tcpraw` where `unsafe` is allowed (docs/porting-guide.md §5): the two
//! `getrusage` calls below. Everything else here is safe code, and the crate root denies
//! `unsafe_code` so no other module can add any.

use std::fmt;
use std::io;
use std::time::Duration;

/// User and system CPU time, as reported by `getrusage(2)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct CpuTime {
    /// Time spent executing user instructions (`ru_utime`).
    pub user: Duration,
    /// Time spent in the kernel on this process's behalf (`ru_stime`).
    pub system: Duration,
}

impl CpuTime {
    /// User plus system time.
    pub fn total(&self) -> Duration {
        self.user.saturating_add(self.system)
    }

    /// `self - earlier`, per component, saturating at zero. Both readings must come from the
    /// same `who` (both [`self_cpu`] or both [`children_cpu`]); the counters only ever grow, so
    /// a saturating difference is the CPU spent in between.
    pub fn saturating_sub(&self, earlier: CpuTime) -> CpuTime {
        CpuTime {
            user: self.user.saturating_sub(earlier.user),
            system: self.system.saturating_sub(earlier.system),
        }
    }
}

impl fmt::Display for CpuTime {
    /// `1.234 s cpu (0.900 user + 0.334 sys)`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:.3} s cpu ({:.3} user + {:.3} sys)",
            self.total().as_secs_f64(),
            self.user.as_secs_f64(),
            self.system.as_secs_f64(),
        )
    }
}

/// CPU time used by this process (all threads), `getrusage(RUSAGE_SELF)`.
pub fn self_cpu() -> io::Result<CpuTime> {
    #[cfg(unix)]
    {
        rusage(libc::RUSAGE_SELF)
    }
    #[cfg(not(unix))]
    {
        Err(unsupported())
    }
}

/// CPU time used by the children of this process that have already been reaped,
/// `getrusage(RUSAGE_CHILDREN)`. See the [module docs](self) for how to use it.
pub fn children_cpu() -> io::Result<CpuTime> {
    #[cfg(unix)]
    {
        rusage(libc::RUSAGE_CHILDREN)
    }
    #[cfg(not(unix))]
    {
        Err(unsupported())
    }
}

#[cfg(not(unix))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "cpu: getrusage is only available on unix",
    )
}

/// The whole `unsafe` of this crate: `who` is `RUSAGE_SELF` or `RUSAGE_CHILDREN`.
#[cfg(unix)]
#[allow(
    unsafe_code,
    reason = "getrusage has no safe wrapper in std; docs/porting-guide.md §5 allows it here"
)]
fn rusage(who: libc::c_int) -> io::Result<CpuTime> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: `getrusage` fills the whole `struct rusage` it is handed; the pointer comes from
    // a live, correctly aligned, uninitialised `MaybeUninit<libc::rusage>` on this stack frame,
    // and `who` is one of the two constants the libc crate defines for this platform.
    let rc = unsafe { libc::getrusage(who, usage.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `getrusage` returned 0, so it initialised every field of the struct.
    let usage = unsafe { usage.assume_init() };
    Ok(CpuTime {
        user: duration_of(usage.ru_utime),
        system: duration_of(usage.ru_stime),
    })
}

/// A `struct timeval` as a [`Duration`]. Negative values cannot occur in an `rusage` and are
/// clamped to zero rather than wrapping (`tv_usec` is signed, and its width differs between
/// macOS and Linux).
#[cfg(unix)]
fn duration_of(tv: libc::timeval) -> Duration {
    let secs = u64::try_from(tv.tv_sec).unwrap_or(0);
    let micros = u64::try_from(tv.tv_usec).unwrap_or(0).min(999_999);
    Duration::new(secs, (micros * 1_000) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Burns a fixed amount of CPU (not a fixed amount of wall time, so the assertions below
    /// hold on a busy machine too).
    fn burn() {
        let mut x = 0u64;
        for i in 0..5_000_000u64 {
            x = x.wrapping_add(i).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        }
        std::hint::black_box(x);
    }

    #[test]
    fn total_and_saturating_sub_work_per_component() {
        let a = CpuTime {
            user: Duration::from_millis(1500),
            system: Duration::from_millis(500),
        };
        assert_eq!(a.total(), Duration::from_secs(2));
        let b = CpuTime {
            user: Duration::from_millis(2000),
            system: Duration::from_millis(400),
        };
        assert_eq!(
            b.saturating_sub(a),
            CpuTime {
                user: Duration::from_millis(500),
                // Cannot happen with two readings of the same counter; must not wrap.
                system: Duration::ZERO,
            }
        );
        assert_eq!(CpuTime::default().total(), Duration::ZERO);
        assert_eq!(
            a.to_string(),
            "2.000 s cpu (1.500 user + 0.500 sys)",
            "the display is what the benchmark tables print"
        );
    }

    #[test]
    fn self_cpu_counts_work_done_in_this_process() {
        let before = self_cpu().expect("getrusage(RUSAGE_SELF)");
        burn();
        let after = self_cpu().expect("getrusage(RUSAGE_SELF)");
        let delta = after.saturating_sub(before);
        assert!(
            delta.total() > Duration::ZERO,
            "burning CPU must show up: {delta}"
        );
        assert!(
            delta.total() < Duration::from_secs(60),
            "and must be a plausible amount: {delta}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn children_cpu_counts_a_reaped_child() {
        let before = children_cpu().expect("getrusage(RUSAGE_CHILDREN)");
        let mut p = crate::proc::ProcBuilder::new("/bin/sh")
            .name("cpu-burner")
            .arg("-c")
            // A shell loop of a few tens of milliseconds of CPU; no I/O, no network.
            .arg("i=0; while [ $i -lt 50000 ]; do i=$((i+1)); done")
            .spawn()
            .expect("spawn /bin/sh");
        let status = p
            .wait_timeout(Duration::from_secs(60))
            .expect("wait")
            .expect("the shell loop must finish");
        assert!(status.success(), "{status}");
        drop(p); // reaped by wait_timeout above; the counter already includes it
        let delta = children_cpu()
            .expect("getrusage(RUSAGE_CHILDREN)")
            .saturating_sub(before);
        assert!(
            delta.total() > Duration::ZERO,
            "a reaped child's CPU must show up: {delta}"
        );
    }
}
