//! Millisecond clock used by the KCP state machine and the FEC encoder (DECISIONS D16).
//!
//! kcp-go reads the time through `currentMs()`: monotonic milliseconds since the package was
//! initialised, truncated to `uint32` (so it wraps after about 49.7 days, and all timestamp
//! arithmetic is wrapping). Protocol code here never reads the system time directly; it calls
//! [`Clock::now_ms`] exactly where Go calls `currentMs()`, so simulations can run on a virtual
//! clock.
//!
//! Any `Fn() -> u32 + Send + Sync + 'static` closure is a [`Clock`], which is how
//! `kcptun_testkit::VirtualClock` (which must not depend on this crate) plugs in:
//!
//! ```
//! use kcptun_kcp::clock::Clock;
//! let vc = kcptun_testkit::VirtualClock::new();
//! let clock = { let vc = vc.clone(); move || vc.now_ms() };
//! vc.advance(42);
//! assert_eq!(clock.now_ms(), 42);
//! ```
#![forbid(unsafe_code)]

use std::sync::LazyLock;
use std::time::Instant;

/// A source of wrapping millisecond timestamps.
pub trait Clock: Send + Sync + 'static {
    /// Current time in milliseconds, wrapping at `u32::MAX` like Go's `currentMs()`.
    fn now_ms(&self) -> u32;
}

impl<F> Clock for F
where
    F: Fn() -> u32 + Send + Sync + 'static,
{
    fn now_ms(&self) -> u32 {
        self()
    }
}

/// Monotonic reference time point: the first use of the system clock in this process.
///
/// Go initialises `refTime` when the package is loaded. Here it is initialised lazily on the
/// first [`current_ms`] call (or by [`init_ref_time`]); timestamps are only ever compared with
/// each other or echoed back by the peer, so the choice of origin is not observable.
// Go: kcp-go/v5@v5.6.66 kcp.go:refTime
static REF_TIME: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Fixes the reference time point now (optional; binaries may call it at startup to match
/// Go's "milliseconds since program start" origin).
pub fn init_ref_time() {
    LazyLock::force(&REF_TIME);
}

/// Elapsed monotonic milliseconds since the reference time point, truncated to `u32`.
// Go: kcp-go/v5@v5.6.66 kcp.go:currentMs()
pub fn current_ms() -> u32 {
    // uint32(time.Since(refTime) / time.Millisecond): whole milliseconds, then truncation.
    REF_TIME.elapsed().as_millis() as u32
}

/// The production clock: [`current_ms`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u32 {
        current_ms()
    }
}

/// A [`Clock`] extended to a monotonic, non-wrapping `i64` millisecond counter.
///
/// The FEC encoder measures the gap between consecutive packets against `maxFECEncodeLatency`
/// (500 ms) and needs a time that does **not** wrap: Go reads `time.Now().UnixMilli()` there,
/// while every other kcp-go timestamp is the wrapping `uint32` of [`Clock`]. Feeding
/// `now_ms() as i64` straight into `FecEncoder::encode` would make one group per `u32` wrap
/// (every 49.7 days) look continuous, so the session's tx task runs its clock through this
/// extender instead, accumulating `wrapping_sub` deltas (see `docs/porting-guide.md` §3).
///
/// The counter starts at 0 and only ever moves forward: a delta is always read as the forward
/// distance from the previous reading, so a clock that appears to go backwards (which the
/// monotonic [`SystemClock`] never does) is treated as having wrapped.
///
/// Not a Go type: kcp-go has no equivalent.
#[derive(Debug)]
pub struct MonotonicMs<C> {
    clock: C,
    /// The previous raw reading.
    last: u32,
    /// Milliseconds elapsed since the first reading.
    elapsed: i64,
}

impl<C: Clock> MonotonicMs<C> {
    /// Starts the counter at 0, reading `clock`.
    pub fn new(clock: C) -> Self {
        let last = clock.now_ms();
        MonotonicMs {
            clock,
            last,
            elapsed: 0,
        }
    }

    /// Reads the clock and returns the milliseconds elapsed since [`new`](Self::new).
    pub fn now_ms(&mut self) -> i64 {
        let now = self.clock.now_ms();
        // Wrapping distance: always the forward one, so a u32 wrap adds the right delta.
        self.elapsed = self
            .elapsed
            .saturating_add(i64::from(now.wrapping_sub(self.last)));
        self.last = now;
        self.elapsed
    }

    /// The last value [`now_ms`](Self::now_ms) returned, without reading the clock.
    pub fn last_ms(&self) -> i64 {
        self.elapsed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kcptun_testkit::VirtualClock;

    fn read<C: Clock>(c: &C) -> u32 {
        c.now_ms()
    }

    #[test]
    fn system_clock_is_monotonic() {
        init_ref_time();
        let a = SystemClock.now_ms();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let b = read(&SystemClock);
        assert!(b.wrapping_sub(a) as i32 >= 5, "a={a} b={b}");
        assert!(b.wrapping_sub(a) < 10_000, "a={a} b={b}");
    }

    #[test]
    fn closure_clock_follows_virtual_clock() {
        let vc = VirtualClock::starting_at(u64::from(u32::MAX));
        let clock = {
            let vc = vc.clone();
            move || vc.now_ms()
        };
        assert_eq!(read(&clock), u32::MAX);
        vc.advance(2);
        assert_eq!(read(&clock), 1);
    }

    /// The extended clock counts from 0 and survives the `u32` wrap that makes the raw clock
    /// jump backwards.
    #[test]
    fn monotonic_ms_extends_across_the_u32_wrap() {
        let vc = VirtualClock::starting_at(u64::from(u32::MAX) - 100);
        let clock = {
            let vc = vc.clone();
            move || vc.now_ms()
        };
        let mut ms = MonotonicMs::new(clock);
        assert_eq!(ms.now_ms(), 0);
        assert_eq!(ms.last_ms(), 0);

        vc.advance(50);
        assert_eq!(ms.now_ms(), 50);
        // Crosses the wrap: the raw clock goes 4294967245 -> 101.
        vc.advance(152);
        assert_eq!(ms.now_ms(), 202);
        assert_eq!(ms.last_ms(), 202);

        // Two more wraps, in steps small enough for the extender to see them (the counter is
        // only correct while it is read at least once per u32 period, i.e. every 49.7 days).
        let mut expected = 202i64;
        for _ in 0..4 {
            vc.advance(1 << 31);
            expected += 1 << 31;
            assert_eq!(ms.now_ms(), expected);
        }
        assert_eq!(ms.last_ms(), 202 + (1i64 << 33));
    }

    #[test]
    fn monotonic_ms_on_the_system_clock_moves_forward() {
        let mut ms = MonotonicMs::new(SystemClock);
        assert_eq!(ms.now_ms(), 0);
        std::thread::sleep(std::time::Duration::from_millis(5));
        let t = ms.now_ms();
        assert!((5..10_000).contains(&t), "t={t}");
        assert!(ms.now_ms() >= t);
    }

    #[test]
    fn clock_is_object_safe_and_shareable() {
        let boxed: Box<dyn Clock> = Box::new(|| 7u32);
        assert_eq!(boxed.now_ms(), 7);
        let shared: std::sync::Arc<dyn Clock> = std::sync::Arc::new(SystemClock);
        let _ = shared.now_ms();
    }
}
