//! A shared, manually advanced millisecond clock for deterministic simulations.
//!
//! # Relation to `kcptun_kcp::Clock` (DECISIONS D16, step 01.2)
//!
//! The single definition of the `Clock` trait (`fn now_ms(&self) -> u32`) lives in `kcptun-kcp`
//! (Step 03.1), which also gives closures a blanket implementation. This crate must not depend
//! on `kcptun-kcp` or any other kcptun crate: they dev-depend on `kcptun-testkit`, and a
//! dependency back would build a second copy of their types. So [`VirtualClock`] is a standalone
//! type with the same `now_ms() -> u32` signature, and tests adapt it with a closure:
//!
//! ```ignore
//! let clock = VirtualClock::new();
//! let kcp = Kcp::with_clock(conv, output, { let c = clock.clone(); move || c.now_ms() });
//! ```
//!
//! (`kcptun_kcp::kcp::Kcp::with_clock`, Step 03.2; its doc example compiles this pattern.)

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// A cloneable virtual clock counting milliseconds. All clones share the same time.
///
/// Time only moves when a test calls [`advance`](Self::advance) or [`set`](Self::set).
#[derive(Clone, Debug, Default)]
pub struct VirtualClock {
    ms: Arc<AtomicU64>,
}

impl VirtualClock {
    /// Creates a clock at time 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a clock at `ms` milliseconds, for example just below `u32::MAX` to exercise
    /// timestamp wrap-around.
    pub fn starting_at(ms: u64) -> Self {
        VirtualClock {
            ms: Arc::new(AtomicU64::new(ms)),
        }
    }

    /// Current time in milliseconds as a wrapping `u32`, like Go kcp-go `currentMs()`
    /// (`uint32(time.Since(refTime) / time.Millisecond)`).
    pub fn now_ms(&self) -> u32 {
        self.ms.load(Ordering::SeqCst) as u32
    }

    /// Current time in milliseconds, not wrapped, as an `i64` (saturating at `i64::MAX`).
    pub fn now_ms_i64(&self) -> i64 {
        i64::try_from(self.ms.load(Ordering::SeqCst)).unwrap_or(i64::MAX)
    }

    /// Current time in milliseconds, not wrapped.
    pub fn now_ms_u64(&self) -> u64 {
        self.ms.load(Ordering::SeqCst)
    }

    /// Moves the clock forward by `ms` milliseconds and returns the new (unwrapped) time.
    pub fn advance(&self, ms: u64) -> u64 {
        self.ms.fetch_add(ms, Ordering::SeqCst).wrapping_add(ms)
    }

    /// Sets the clock to `ms` milliseconds. Setting it backwards is allowed (tests of clock
    /// anomalies); normal simulations only move forward.
    pub fn set(&self, ms: u64) {
        self.ms.store(ms, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_time() {
        let a = VirtualClock::new();
        let b = a.clone();
        assert_eq!(a.now_ms(), 0);
        assert_eq!(a.advance(15), 15);
        assert_eq!(b.now_ms(), 15);
        b.set(1000);
        assert_eq!(a.now_ms_i64(), 1000);
        assert_eq!(a.now_ms_u64(), 1000);
    }

    #[test]
    fn now_ms_wraps_like_go_current_ms() {
        let c = VirtualClock::starting_at(u64::from(u32::MAX) - 1);
        assert_eq!(c.now_ms(), u32::MAX - 1);
        c.advance(3);
        assert_eq!(c.now_ms(), 1);
        assert_eq!(c.now_ms_i64(), i64::from(u32::MAX) + 2);
        // _itimediff-style arithmetic across the wrap stays correct.
        assert_eq!(1u32.wrapping_sub(u32::MAX - 1) as i32, 3);
    }

    #[test]
    fn closure_adapter_sees_updates() {
        let c = VirtualClock::new();
        let f = {
            let c = c.clone();
            move || c.now_ms()
        };
        c.advance(42);
        assert_eq!(f(), 42);
    }
}
