//! Giving memory back after a burst: the Rust counterpart of Go's scavenger (plan 12.3).
//!
//! A Go kcptun process that has moved a large transfer returns most of the memory within a few
//! minutes: the collector frees the segment payloads and the runtime's *scavenger* then hands the
//! pages back to the kernel. A Rust process frees the same bytes at the same moment: `Drop` runs
//! as each segment is acknowledged, but nothing afterwards asks the allocator to unmap what it
//! is now sitting on, so RSS stays at the high-water mark. `docs/benchmarks/memory.md` §4
//! measured exactly that: ~100 MB held flat for 600 s after 512 MB each way, with musl **and**
//! with glibc, while Go fell to 73/57 MB.
//!
//! A heap profile (plan 12.3b, `crates/interop-tests/src/bin/memprobe.rs`) split that into two
//! causes and sized them: after 4 sessions had echoed 512 MB each way and every stream was
//! closed, the **live heap had fallen from 78 MB to 11.7 MB while RSS had not moved by one
//! page**. So roughly 85 % of the peak is memory the program has already given up and the
//! allocator is still holding, and the remaining ~1.1 MB per live session is capacity the program
//! itself keeps: the grown KCP rings, the `rcv_buf` heap, and the process-wide packet pool.
//!
//! This module is the missing half, and it addresses both causes:
//!
//! - [`trim`]: one pass: give the parked packet buffers back down to [`IDLE_POOL_PARKED`] and
//!   ask the allocator to return its free arenas to the operating system.
//! - [`trim_when_idle`]: a task the binaries spawn once, which runs [`trim`] when the process has
//!   been **quiet** for a whole interval and something has happened since the last trim. Idle is
//!   the only time this costs anything, and it is the only time there is anything to give back;
//!   under load it does nothing at all, which is why it can be unconditional rather than a flag.
//!   "Quiet" is a *small* delta rather than no delta at all, see [`QUIET_BYTES`], and the
//!   keepalive that makes the difference between a trim that fires and one that never does.
//! - [`UdpSession::shrink_idle`](crate::session::UdpSession::shrink_idle), which every session's
//!   own update task calls every [`SESSION_SHRINK_INTERVAL`]. The pool and the allocator are
//!   process-wide, but a session's rings can only be released under that session's lock.
//!
//! (It is deliberately *not* called a scavenger, although Go's runtime one is exactly what it
//! imitates: kcptun already has a `scavenger`, the client loop that expires idle KCP sessions
//! after `-scavengettl`, and the two have nothing to do with each other.)
//!
//! # What "ask the allocator" means per build
//!
//! | build | call | measured release after a 512 MB burst |
//! |---|---|---|
//! | Linux glibc: the `linux-gnu` artifacts and the `--target glibc` image (D07) | `malloc_trim(0)` | **95.6 %**, within one 30 s tick |
//! | **Linux musl**: the default release artifacts and the default image (D07) | - | 4.9 %: nothing to call, mallocng has no trim entry point |
//! | macOS / Windows / other | - | nothing to call |
//!
//! musl is the row that made D07 a question: there the *system* allocator has no way to be asked
//! at all: mallocng has no `malloc_trim` entry point, so there is nothing this module could
//! call, and 4.9 % is all the program-level half recovers. glibc's `malloc_trim(0)` returns the
//! burst outright, for +1.6 MB of idle RSS per process.
//!
//! That trade is **not** what the default was settled on, because a 512 MB burst is not the
//! workload this port is deployed into. 13.2c measured two real containers moving 4 GB across 8
//! streams and the musl build was lower at every sample (idle 2576/1944 kB against 4416/3688,
//! peak 6828/3888 against 19400/12536, settled 4480/3368 against 11480/10984, server/client),
//! and 12.3a measured the live mesh at 18.5 MB per client, 1.77 MB above the idle floor. So
//! **static musl is the default** (`tools/release.sh` group `linux-musl`, and the default
//! container image), and glibc is a supported option for burst-heavy deployments
//! (`tools/release.sh` group `linux-gnu`, `docker build --target glibc`): the one case where
//! this row is worth its higher floor. A static build keeps its high-water mark until it
//! restarts; `docs/benchmarks/memory.md` §8 puts both rounds side by side.
//!
//! A `mimalloc` global allocator was built and measured as the third option, because an
//! allocator that *can* be asked would have fixed the musl row: it released 49–55 % of the peak,
//! half of what glibc returns, while multiplying idle RSS by 4.4. **D07 rejected it and 12.3d
//! deleted the feature**, so `docs/benchmarks/memory.md` §6.2's mimalloc rows can no longer be
//! reproduced from this tree; that section says so.
//!
//! **These numbers are `docs/benchmarks/memory.md` §6.2**, not §6, whose four `mimalloc` rows are
//! void (the probe had no `#[global_allocator]` of its own, so it went on allocating through
//! mallocng or glibc). They read "3 %" and should be ignored.
//!
//! Go reference: there is none, `runtime/mgcscavenge.go` has no analogue in a program without a
//! garbage collector. The *behaviour* being matched is Go's, not any Go source file.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::bufpool;
use crate::snmp::DEFAULT_SNMP;

/// Packet buffers the pool keeps parked when the process goes quiet.
///
/// The pool parks up to [`bufpool::DEFAULT_CAPACITY`] (2048) 1500-byte buffers, 3 MB, which is
/// what a session needs to fill its whole tx channel. An idle process needs none of them, but
/// dropping to zero would make the first packet after a quiet minute allocate, so a small working
/// set stays: 64 buffers is 96 kB and is exactly one `sendmmsg` batch
/// ([`MAX_BATCH_SIZE`](crate::tx::MAX_BATCH_SIZE) = 64), so the first burst after a quiet period
/// refills the pool from the allocator one batch behind rather than 2048.
pub const IDLE_POOL_PARKED: usize = 64;

/// How often a session's update task calls
/// [`UdpSession::shrink_idle`](crate::session::UdpSession::shrink_idle).
///
/// Per-session capacity is the *other* half of the problem: the packet pool and the allocator are
/// process-wide, but the grown KCP rings and the `rcv_buf` heap belong to one session, and only
/// that session's lock can release them. The interval matches [`TRIM_INTERVAL`] so that a
/// process which has gone quiet has released both halves within about a minute, the same order as
/// Go's scavenger (memory.md §4 measured Go's first drop between +60 s and +120 s).
pub const SESSION_SHRINK_INTERVAL: Duration = Duration::from_secs(30);

/// How often [`trim_when_idle`] looks at the process.
///
/// Go's scavenger starts returning pages about 60 s after the allocation peak (memory.md §4
/// measured the first drop between +60 s and +120 s), so a 30 s tick with the
/// "quiet for a whole tick" rule below gives the same 30–60 s delay without a timer per session.
pub const TRIM_INTERVAL: Duration = Duration::from_secs(30);

/// Bytes that may move during one [`TRIM_INTERVAL`] and still count as **quiet**.
///
/// The obvious rule (the counters have not moved at all) is wrong, and wrong in exactly the
/// case this module exists for. smux sends an unconditional 8-byte `cmdNOP` keepalive per session
/// every `-keepalive` seconds (default 10; `kcptun_smux::session::keepalive`, Go
/// `smux@v1.5.55 session.go:keepalive()`), and every one of those writes goes through
/// [`UdpSession::write`](crate::session::UdpSession::write), which bumps
/// [`DEFAULT_SNMP`]`.bytes_sent`; the peer's NOPs bump `bytes_received` the same way. So a client
/// that has finished a burst and still holds its `-conn` KCP sessions, which is the normal case,
/// since kcptun only reaps a session after `-scavengettl` (600 s) and never if it is reused,
/// moves a few bytes every single tick, forever. A byte-for-byte stillness test would therefore
/// **never** fire on a shipped binary, and the process-wide half of the trim would be dead code.
///
/// 64 kB per 30 s tick is three orders of magnitude above that keepalive floor (8 B per session
/// per 10 s in each direction, so ~24 B per session per tick: 64 kB covers over a thousand
/// sessions) and three orders of magnitude below anything that could be called traffic: one
/// 1390-byte packet every 7 seconds. Anything moving real data crosses it immediately and is left
/// alone.
pub const QUIET_BYTES: u64 = 64 * 1024;

/// Bytes that must have moved since the last trim before another one is due.
///
/// [`QUIET_BYTES`] says when the process is idle *now*; this says whether being idle is news.
/// Without it a process whose keepalives slowly accumulate would trim once per
/// `REARM_BYTES / keepalive rate`, with it, an idle 4-session client re-arms after about a day,
/// i.e. effectively never, while anything that has actually carried a transfer (the only thing
/// with memory to give back) re-arms within the first megabyte of it.
pub const REARM_BYTES: u64 = 1024 * 1024;

/// What one [`trim`] gave back.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TrimReport {
    /// Packet buffers freed from the pool (1500 bytes each).
    pub buffers_freed: usize,
    /// Whether this build could ask the allocator to return memory at all (see the module docs).
    pub allocator_asked: bool,
}

impl std::fmt::Display for TrimReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} buffers freed, allocator {}",
            self.buffers_freed,
            if self.allocator_asked {
                "asked"
            } else {
                "has no trim entry point in this build"
            }
        )
    }
}

/// Frees the parked packet buffers down to [`IDLE_POOL_PARKED`] and asks the allocator to return
/// its free memory to the operating system.
///
/// Safe to call at any time and from any thread; under load it finds an empty pool and the
/// allocator finds nothing to unmap, so it is cheap rather than harmful. [`trim_when_idle`] still
/// keeps it off the hot path.
pub fn trim() -> TrimReport {
    TrimReport {
        buffers_freed: bufpool::default_pool().trim(IDLE_POOL_PARKED),
        allocator_asked: release_to_os(),
    }
}

/// Runs [`trim`] whenever the process has been quiet for a whole `interval` and there is
/// something to give back. Never returns; the binaries spawn it once and let the runtime drop it
/// at exit.
///
/// "Quiet" is the KCP byte counters ([`DEFAULT_SNMP`]'s `bytes_sent` and `bytes_received`, which
/// every session updates) moving no more than [`QUIET_BYTES`] across the whole interval, not
/// standing still, which smux's per-session keepalive would make impossible (see [`QUIET_BYTES`]).
/// One trim per quiet period: after a trim the process must move [`REARM_BYTES`] again before
/// another one is due, so an idle process does no work beyond two subtractions per tick.
///
/// # Known limit: this test is process-wide, and Go's scavenger has no such condition
///
/// Those counters are global, so "quiet" is **all-or-nothing for the whole process** rather than
/// one decision per session. Go's scavenger returns pages from a Go server that is busy on 26 of
/// its 27 tunnels; this does not. A server aggregating several clients stays above
/// [`QUIET_BYTES`] as long as *any one* of them is moving data, so the process-wide half never
/// fires and the high-water mark stands, even though the sessions that produced it have long gone
/// idle. [`UdpSession::shrink_idle`](crate::session::UdpSession::shrink_idle) is unaffected: it
/// is per session and runs regardless, but the `malloc_trim`, which is 85 % of the retained RSS,
/// does not run. The case is **unmeasured**: everything in `docs/benchmarks/memory.md` §6 and
/// §6.1 is a single-workload process that goes fully quiet. See caveat 14 and follow-up 6 there.
pub async fn trim_when_idle(interval: Duration) -> ! {
    let mut state = IdleTrimmer::new(Traffic::now());
    loop {
        tokio::time::sleep(interval).await;
        if state.tick(Traffic::now()) {
            trim();
        }
    }
}

/// The decision [`trim_when_idle`] makes on every tick, without the clock or the counters, so
/// that it can be tested on its own.
#[derive(Clone, Copy, Debug)]
struct IdleTrimmer {
    /// Counters at the previous tick.
    last: Traffic,
    /// Counters when the last trim ran. Starting here means an untouched process never trims.
    trimmed_at: Traffic,
}

impl IdleTrimmer {
    fn new(start: Traffic) -> IdleTrimmer {
        IdleTrimmer {
            last: start,
            trimmed_at: start,
        }
    }

    /// True when the process was quiet for the whole tick ([`QUIET_BYTES`]) and has moved
    /// [`REARM_BYTES`] since the last trim.
    fn tick(&mut self, traffic: Traffic) -> bool {
        // `wrapping_sub` on counters that only ever grow: the wrap is unreachable in practice and
        // the porting guide's rule is that arithmetic on wire/counter values never panics.
        let moved_this_tick = traffic.total().wrapping_sub(self.last.total());
        self.last = traffic;
        let quiet = moved_this_tick <= QUIET_BYTES;
        if quiet && traffic.total().wrapping_sub(self.trimmed_at.total()) >= REARM_BYTES {
            self.trimmed_at = traffic;
            return true;
        }
        false
    }
}

/// Like [`trim_when_idle`] with [`TRIM_INTERVAL`]; what the binaries spawn.
pub async fn trim_when_idle_default() -> ! {
    trim_when_idle(TRIM_INTERVAL).await
}

/// The traffic counters that decide whether the process is quiet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Traffic {
    sent: u64,
    received: u64,
}

impl Traffic {
    fn now() -> Traffic {
        Traffic {
            sent: load(&DEFAULT_SNMP.bytes_sent),
            received: load(&DEFAULT_SNMP.bytes_received),
        }
    }

    /// Bytes moved in either direction. Both counters only ever grow, so the sum is monotone and
    /// the difference between two of them is the traffic in between.
    fn total(self) -> u64 {
        self.sent.wrapping_add(self.received)
    }
}

fn load(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------------------------
// The allocator half, one body per build (see the table in the module docs)
// ---------------------------------------------------------------------------------------------

/// Asks the global allocator to return free memory to the operating system. Returns false when
/// this build has no way to ask, which is every build that is not glibc: mallocng (static musl)
/// and macOS's `libmalloc` expose no trim entry point at all.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn release_to_os() -> bool {
    // SAFETY: `malloc_trim` takes an integer pad, no pointers, and is thread-safe in glibc. The
    // return value only says whether any memory was released, which `TrimReport` does not claim.
    unsafe { libc::malloc_trim(0) };
    true
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn release_to_os() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn traffic(sent: u64, received: u64) -> Traffic {
        Traffic { sent, received }
    }

    /// `trim` runs against the process-wide pool without failing and leaves it usable. Both
    /// assertions are one-sided on purpose: `default_pool()` is shared with every other test in
    /// this binary (`session.rs`, `listener.rs`), which may be parking or taking buffers at the
    /// same moment, so nothing here may assert *how much* was freed. That is
    /// `bufpool::trim_frees_parked_buffers_down_to_keep`'s job, on a private pool.
    #[test]
    fn trim_leaves_the_shared_pool_usable() {
        let report = trim();
        assert_eq!(
            report.allocator_asked,
            cfg!(all(target_os = "linux", target_env = "gnu")),
            "{report}"
        );

        let buf = bufpool::default_pool().get(8);
        assert_eq!(buf.len(), 8);
    }

    /// The idle trimmer waits for a whole quiet tick, then trims exactly once per quiet period.
    #[test]
    fn idle_trimmer_trims_once_per_quiet_period() {
        const MB: u64 = 1024 * 1024;
        let mut s = IdleTrimmer::new(traffic(0, 0));

        // An untouched process has nothing to give back, however long it stays quiet.
        assert!(!s.tick(traffic(0, 0)));
        assert!(!s.tick(traffic(0, 0)));

        // A burst: the tick that sees it is not quiet, so it does not trim.
        assert!(!s.tick(traffic(100 * MB, 200 * MB)));
        // The next tick finds the counters at rest: trim.
        assert!(s.tick(traffic(100 * MB, 200 * MB)));
        // And not again until another `REARM_BYTES` has moved.
        assert!(!s.tick(traffic(100 * MB, 200 * MB)));
        assert!(!s.tick(traffic(100 * MB, 200 * MB)));

        // A megabyte in either direction re-arms it.
        assert!(!s.tick(traffic(100 * MB, 201 * MB)));
        assert!(s.tick(traffic(100 * MB, 201 * MB)));
        assert!(!s.tick(traffic(101 * MB, 201 * MB)));
        assert!(s.tick(traffic(101 * MB, 201 * MB)));
    }

    /// The regression this rule exists for: smux keeps every live session ticking with an 8-byte
    /// `cmdNOP` every `-keepalive` seconds, so the counters are *never* byte-for-byte still on a
    /// real client. A trim must still happen.
    #[test]
    fn idle_trimmer_trims_through_smux_keepalive() {
        const MB: u64 = 1024 * 1024;
        // 4 sessions × 3 keepalives per 30 s tick × 8 bytes, in each direction.
        const KEEPALIVE_PER_TICK: u64 = 4 * 3 * 8;

        let mut s = IdleTrimmer::new(traffic(0, 0));
        let (mut sent, mut received) = (100 * MB, 200 * MB);
        assert!(!s.tick(traffic(sent, received)), "the burst itself");

        // From here on nothing but keepalive moves, forever. The first such tick must trim.
        sent += KEEPALIVE_PER_TICK;
        received += KEEPALIVE_PER_TICK;
        assert!(
            s.tick(traffic(sent, received)),
            "keepalive defeated the trim"
        );

        // And then it must go quiet again rather than trimming on every tick: a day of keepalive
        // is nowhere near `REARM_BYTES`.
        for _ in 0..2_000 {
            sent += KEEPALIVE_PER_TICK;
            received += KEEPALIVE_PER_TICK;
            assert!(!s.tick(traffic(sent, received)), "re-armed on keepalive");
        }
    }

    /// A session that is actually carrying data is never called quiet, so `trim` stays off the
    /// hot path however long the transfer lasts.
    #[test]
    fn idle_trimmer_never_trims_under_load() {
        const MB: u64 = 1024 * 1024;
        let mut s = IdleTrimmer::new(traffic(0, 0));
        let mut sent = 0;
        for _ in 0..100 {
            sent += 10 * MB;
            assert!(!s.tick(traffic(sent, 0)));
        }
        // Even a trickle well above the keepalive floor counts as traffic.
        for _ in 0..100 {
            sent += QUIET_BYTES + 1;
            assert!(!s.tick(traffic(sent, 0)));
        }
    }

    /// Traffic in either direction alone counts towards the totals the trimmer compares.
    #[test]
    fn traffic_counts_both_directions() {
        assert_eq!(traffic(1, 2).total(), 3);
        assert_eq!(traffic(1, 3).total(), 4);
        assert_eq!(traffic(2, 2).total(), 4);
    }
}
