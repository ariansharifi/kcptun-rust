//! Byte-rate pacing of a session's tx task (port of the `golang.org/x/time/rate` subset kcp-go
//! uses, plus Deviation V02).
//!
//! kcp-go paces with a token bucket:
//!
//! ```go
//! // sess.go:SetRateLimit
//! limiter = rate.NewLimiter(rate.Inf, maxBatchSize*mtuLimit)            // bytesPerSecond == 0
//! limiter = rate.NewLimiter(rate.Limit(bytesPerSecond), maxBatchSize*mtuLimit)
//! // sess.go:postProcess
//! err := limiter.WaitN(ctx, bytesToSend)
//! ```
//!
//! so the rate is in **bytes per second**, the burst is [`BURST`] = 64 × 1500 = 96000 bytes, and
//! the only operation is `WaitN` with a background context (never cancelled, no deadline). That
//! is what this module implements: [`Limiter::reserve_n`] is `x/time/rate`'s `reserveN` with
//! `maxFutureReserve = InfDuration` followed by `Reservation.DelayFrom`, and [`Limiter::wait_n`]
//! is `WaitN` on top of it.
//!
//! **Deviation V02.** `x/time/rate` refuses `WaitN(n)` for `n > burst` (a limiter can never hand
//! out more than a burst at once), and kcp-go v5.6.66 turns that error into `panic(err)`; later
//! versions log it and send the batch unpaced. A batch can exceed the burst whenever FEC parity
//! and `dup` copies push one round past 96000 bytes, so neither behaviour is acceptable. Here
//! `reserve_n` always succeeds: the tokens go negative, the caller waits for the whole debt, and
//! the long-run rate stays correct.
//!
//! A zero rate means *unlimited* (Go's `rate.Inf`), and so does the state before kcptun ever
//! calls `SetRateLimit` (Go's empty `atomic.Value`, whose type assertion fails and skips the
//! wait entirely).
#![forbid(unsafe_code)]

use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::crypt::MTU_LIMIT;
use crate::tx::MAX_BATCH_SIZE;

/// Burst of a session's limiter: one full batch of maximum-sized packets.
// Go: kcp-go/v5@v5.6.66 sess.go:SetRateLimit() (`maxBatchSize*mtuLimit`)
pub const BURST: usize = MAX_BATCH_SIZE * MTU_LIMIT;

/// `x/time/rate`'s `InfDuration`: `time.Duration(math.MaxInt64)`, about 292 years.
// Go: golang.org/x/time/rate@v0.14.0 rate.go:InfDuration
pub const INF_DURATION: Duration = Duration::from_nanos(i64::MAX as u64);

/// A token bucket of `burst` bytes refilled at `limit` bytes per second.
///
/// Safe for concurrent use, like Go's `*rate.Limiter`.
// Go: golang.org/x/time/rate@v0.14.0 rate.go:Limiter
pub struct Limiter {
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    /// Bytes per second, or `f64::INFINITY` for Go's `rate.Inf`.
    limit: f64,
    /// Maximum number of tokens the bucket holds.
    burst: f64,
    /// Tokens available at [`last`](Self::last); may be negative (Deviation V02).
    tokens: f64,
    /// When [`tokens`](Self::tokens) was last updated. `None` until the first reservation, which
    /// is Go's zero `time.Time` (always before `t`, so the bucket starts full).
    last: Option<Instant>,
}

impl Limiter {
    /// The limiter kcptun's `-ratelimit` builds: `bytes_per_second` bytes per second with a
    /// [`BURST`]-byte bucket, or unlimited for `0`.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetRateLimit()
    pub fn new(bytes_per_second: u32) -> Limiter {
        Limiter {
            state: Mutex::new(State::new(bytes_per_second)),
        }
    }

    /// A limiter that never waits (Go's `rate.NewLimiter(rate.Inf, …)`).
    pub fn unlimited() -> Limiter {
        Limiter::new(0)
    }

    /// A limiter with an explicit rate and burst, for tests.
    ///
    /// `limit` is in tokens per second; `f64::INFINITY` is Go's `rate.Inf`.
    // Go: golang.org/x/time/rate@v0.14.0 rate.go:NewLimiter()
    pub fn with_burst(limit: f64, burst: usize) -> Limiter {
        Limiter {
            state: Mutex::new(State {
                limit,
                burst: burst as f64,
                tokens: burst as f64,
                last: None,
            }),
        }
    }

    /// Sets the rate in bytes per second; `0` disables pacing.
    ///
    /// Go stores a **new** `*rate.Limiter` in `s.rateLimiter`, which resets the bucket to full
    /// and forgets any debt. Resetting the state here has exactly that effect without the
    /// indirection of swapping the limiter out from under the tx task.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetRateLimit()
    pub fn set_rate(&self, bytes_per_second: u32) {
        *self.lock() = State::new(bytes_per_second);
    }

    /// The current rate in tokens per second (`f64::INFINITY` when unlimited).
    // Go: golang.org/x/time/rate@v0.14.0 rate.go:Limiter.Limit()
    pub fn limit(&self) -> f64 {
        self.lock().limit
    }

    /// The bucket size in tokens.
    // Go: golang.org/x/time/rate@v0.14.0 rate.go:Limiter.Burst()
    pub fn burst(&self) -> usize {
        self.lock().burst as usize
    }

    /// Whether the limiter paces at all.
    pub fn is_unlimited(&self) -> bool {
        self.lock().limit.is_infinite()
    }

    /// Tokens available at `now`, without consuming any (may be negative under Deviation V02).
    // Go: golang.org/x/time/rate@v0.14.0 rate.go:Limiter.TokensAt()
    pub fn tokens_at(&self, now: Instant) -> f64 {
        self.lock().advance(now)
    }

    /// Consumes `n` tokens at `now` and returns how long the caller has to wait before using
    /// them.
    ///
    /// This is `reserveN(t, n, InfDuration)` followed by `DelayFrom(t)`, minus the `ok` flag:
    /// under Deviation V02 a reservation of more than a burst is granted and repaid over several
    /// bucket-fills instead of being refused.
    // Go: golang.org/x/time/rate@v0.14.0 rate.go:Limiter.reserveN(), Reservation.DelayFrom()
    pub fn reserve_n(&self, now: Instant, n: usize) -> Duration {
        let mut state = self.lock();
        if state.limit.is_infinite() {
            // Go returns a reservation with timeToAct == t and leaves the bucket untouched.
            return Duration::ZERO;
        }

        // Calculate the remaining number of tokens resulting from the request.
        let tokens = state.advance(now) - n as f64;

        // Calculate the wait duration.
        let wait = if tokens < 0.0 {
            duration_from_tokens(state.limit, -tokens)
        } else {
            Duration::ZERO
        };

        // Update state. Deviation V02: Go only does this when `n <= burst`, and reports an error
        // otherwise; the reservation is always granted here.
        state.last = Some(now);
        state.tokens = tokens;
        wait
    }

    /// Waits until the limiter permits `n` more bytes.
    ///
    /// Go's `WaitN(context.Background(), n)`: no cancellation and no deadline, so the wait is
    /// never interrupted and never fails.
    // Go: golang.org/x/time/rate@v0.14.0 rate.go:Limiter.WaitN(), called from
    //     kcp-go/v5@v5.6.66 sess.go:postProcess()
    pub async fn wait_n(&self, n: usize) {
        let delay = self.reserve_n(Instant::now(), n);
        if delay > Duration::ZERO {
            tokio::time::sleep(delay).await;
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // The critical section is a handful of float operations and cannot panic, so the mutex
        // can only be poisoned by a panic elsewhere in this process; the state stays valid.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Default for Limiter {
    fn default() -> Self {
        Limiter::unlimited()
    }
}

impl fmt::Debug for Limiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.lock();
        f.debug_struct("Limiter")
            .field("limit", &state.limit)
            .field("burst", &state.burst)
            .field("tokens", &state.tokens)
            .finish()
    }
}

impl State {
    fn new(bytes_per_second: u32) -> State {
        // Go: `rate.Inf` for 0, `rate.Limit(bytesPerSecond)` otherwise; the burst is always
        // maxBatchSize*mtuLimit and the bucket starts full.
        let limit = if bytes_per_second == 0 {
            f64::INFINITY
        } else {
            f64::from(bytes_per_second)
        };
        State {
            limit,
            burst: BURST as f64,
            tokens: BURST as f64,
            last: None,
        }
    }

    /// Tokens available at `t`, capped at the burst. Does not mutate the state.
    // Go: golang.org/x/time/rate@v0.14.0 rate.go:Limiter.advance()
    fn advance(&self, t: Instant) -> f64 {
        // Go: `if t.Before(last) { last = t }`, i.e. time never runs backwards here. An
        // `Instant` can only go backwards if a caller passes an older one; saturating the
        // subtraction gives Go's zero elapsed time instead of panicking.
        let elapsed = match self.last {
            // No reservation yet: Go's zero time.Time is before any t, so the bucket is full
            // (`tokens + delta`, capped at burst) whatever the elapsed time would be.
            None => return cap_at_burst(self.tokens, self.burst),
            Some(last) => t.saturating_duration_since(last),
        };
        let delta = tokens_from_duration(self.limit, elapsed);
        cap_at_burst(self.tokens + delta, self.burst)
    }
}

/// Go's `if burst := float64(lim.burst); tokens > burst { tokens = burst }`.
///
/// Deliberately a comparison rather than `f64::min`, for two reasons. It is exactly what Go
/// does, NaN included: `NaN > burst` is false, so Go keeps the NaN where `f64::min` would
/// return `burst` (the only way to produce one here is `limit == INFINITY` with a zero elapsed
/// time, and `reserve_n` returns before `advance` in that case). And `f64::min` lowers to the
/// C23 `fminimum_num`, which **musl's libm does not provide for soft-float ARM**: it made
/// `arm-unknown-linux-musleabi` (ARMv6, DECISIONS D22) fail to link with `undefined symbol:
/// fminimum_num`, found while cross-building the release artifacts in 13.1.
// Go: golang.org/x/time/rate@v0.14.0 rate.go:397-399
fn cap_at_burst(tokens: f64, burst: f64) -> f64 {
    if tokens > burst { burst } else { tokens }
}

/// Time it takes to accumulate `tokens` tokens at `limit` tokens per second.
// Go: golang.org/x/time/rate@v0.14.0 rate.go:Limit.durationFromTokens()
fn duration_from_tokens(limit: f64, tokens: f64) -> Duration {
    if limit <= 0.0 {
        return INF_DURATION;
    }
    // Go: time.Duration((tokens / float64(limit)) * float64(time.Second)), i.e. nanoseconds
    // truncated towards zero, capped at MaxInt64.
    let nanos = (tokens / limit) * 1e9;
    // `>=` rather than `!(< )` so that a NaN (which compares false both ways) falls through to
    // the saturating cast below, which turns it into 0. Go's conversion of a NaN is
    // implementation-defined, so zero is as good an answer as any.
    if nanos >= i64::MAX as f64 {
        return INF_DURATION;
    }
    // Go returns `time.Duration(duration)`, a *signed* count that keeps the sign: `-1e6` there
    // is -1ms, not 0. Rust's `Duration` is unsigned, so a negative nanosecond count can only
    // saturate to `Duration::ZERO` - a representation deviation rather than Go's behaviour, and
    // unreachable from the one caller: `reserve_n` passes `-tokens` with `tokens < 0.0`, and
    // `limit > 0.0` is guaranteed by the check above. The clamping is left to the saturating
    // `as` cast rather than an `f64::max`, which would call the C23 `fmaximum_num` that
    // soft-float ARM musl does not provide (see `cap_at_burst`).
    Duration::from_nanos(nanos as u64)
}

/// Tokens accumulated over `d` at `limit` tokens per second.
// Go: golang.org/x/time/rate@v0.14.0 rate.go:Limit.tokensFromDuration()
fn tokens_from_duration(limit: f64, d: Duration) -> f64 {
    if limit <= 0.0 {
        return 0.0;
    }
    d.as_secs_f64() * limit
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn go_defaults_match_set_rate_limit() {
        let limiter = Limiter::new(1_000_000);
        assert_eq!(limiter.burst(), 96_000);
        assert_eq!(BURST, 96_000);
        assert!((limiter.limit() - 1_000_000.0).abs() < f64::EPSILON);
        assert!(!limiter.is_unlimited());
    }

    /// `bytesPerSecond == 0` is Go's `rate.Inf`: every reservation is granted immediately, the
    /// burst is ignored, and the bucket never drains.
    #[test]
    fn zero_rate_is_unlimited() {
        let limiter = Limiter::new(0);
        assert!(limiter.is_unlimited());
        assert!(limiter.limit().is_infinite());
        let t0 = Instant::now();
        for i in 0..1000 {
            assert_eq!(limiter.reserve_n(t0, 10 * BURST), Duration::ZERO, "i={i}");
        }
        assert_eq!(Limiter::default().reserve_n(t0, usize::MAX), Duration::ZERO);
    }

    /// The bucket starts full: a first reservation of the whole burst is free, and the next byte
    /// then waits exactly one byte's worth of time.
    #[test]
    fn burst_is_available_immediately_then_paced() {
        let rate = 100_000u32; // bytes per second => 1 byte per 10 µs
        let limiter = Limiter::new(rate);
        let t0 = Instant::now();

        assert_eq!(limiter.reserve_n(t0, BURST), Duration::ZERO);
        // Bucket empty: 1000 bytes take 10 ms to refill.
        assert_eq!(limiter.reserve_n(t0, 1000), ms(10));
        // 10 ms later the debt of the previous reservation is exactly repaid.
        assert_eq!(limiter.reserve_n(t0 + ms(10), 0), Duration::ZERO);
        assert_eq!(limiter.reserve_n(t0 + ms(10), 500), ms(5));
    }

    /// The burst cap is Go's comparison, not `f64::min`.
    ///
    /// Two things are pinned here. The ordinary cases have to agree with `f64::min` — anything
    /// else would change the pacing. The NaN case has to agree with **Go**, which keeps the NaN
    /// (`NaN > burst` is false) where `f64::min` would hand back `burst`. Keeping the comparison
    /// is also what lets `arm-unknown-linux-musleabi` link at all: `f64::min` lowers to the C23
    /// `fminimum_num`, which soft-float ARM musl does not provide (found in 13.1).
    #[test]
    fn cap_at_burst_follows_go_not_f64_min() {
        assert_eq!(cap_at_burst(10.0, 96_000.0), 10.0);
        assert_eq!(cap_at_burst(96_001.0, 96_000.0), 96_000.0);
        assert_eq!(cap_at_burst(96_000.0, 96_000.0), 96_000.0);
        assert_eq!(cap_at_burst(-5.0, 96_000.0), -5.0); // debt survives (deviation V02)
        assert_eq!(cap_at_burst(f64::INFINITY, 96_000.0), 96_000.0);
        assert!(cap_at_burst(f64::NAN, 96_000.0).is_nan());
        assert_eq!(
            f64::NAN.min(96_000.0),
            96_000.0,
            "the behaviour Go does *not* have"
        );
    }

    /// Idle time refills the bucket, but never past the burst.
    #[test]
    fn tokens_are_capped_at_the_burst() {
        let limiter = Limiter::new(100_000);
        let t0 = Instant::now();
        limiter.reserve_n(t0, BURST);
        assert!(limiter.tokens_at(t0).abs() < 1e-6);

        // 96000 bytes at 100000 B/s take 960 ms to refill; after an hour the bucket is still
        // exactly one burst.
        assert!((limiter.tokens_at(t0 + ms(960)) - BURST as f64).abs() < 1.0);
        let hour = t0 + Duration::from_secs(3600);
        assert!((limiter.tokens_at(hour) - BURST as f64).abs() < 1e-6);
        assert_eq!(limiter.reserve_n(hour, BURST), Duration::ZERO);
        assert!(limiter.reserve_n(hour, 1) > Duration::ZERO);
    }

    /// Deviation V02: `n > burst` is granted (Go: error, and `panic` in kcp-go v5.6.66) and the
    /// debt is repaid before the next packet goes out.
    #[test]
    fn reservation_larger_than_burst_goes_into_debt() {
        let rate = 100_000u32;
        let limiter = Limiter::new(rate);
        let t0 = Instant::now();

        // Three bursts at once: one is in the bucket, two have to be earned => 1.92 s.
        let wait = limiter.reserve_n(t0, 3 * BURST);
        assert_eq!(wait, Duration::from_millis(1920));
        assert!(limiter.tokens_at(t0) < 0.0, "the bucket is in debt");

        // Nothing is granted for free until the debt is repaid.
        assert_eq!(limiter.reserve_n(t0 + ms(1920), 0), Duration::ZERO);
        // …and the debt of the second reservation stacks on top of the first.
        let limiter = Limiter::new(rate);
        limiter.reserve_n(t0, 3 * BURST);
        assert_eq!(limiter.reserve_n(t0, BURST), Duration::from_millis(2880));
    }

    /// The long-run rate is the configured one: 2 MB paced at 1 MB/s takes ~2 s minus the free
    /// initial burst, whatever the packet size.
    #[test]
    fn long_run_rate_matches_the_limit() {
        for packet in [64usize, 1400, 96_000, 150_000] {
            let rate = 1_000_000u32;
            let limiter = Limiter::new(rate);
            let t0 = Instant::now();
            let mut now = t0;
            let mut sent = 0usize;
            let total = 2_000_000usize;
            while sent < total {
                let n = packet.min(total - sent);
                now += limiter.reserve_n(now, n);
                sent += n;
            }
            // The first `burst` bytes are free, everything after that is paced exactly.
            let expected = Duration::from_secs_f64((total - BURST) as f64 / f64::from(rate));
            let elapsed = now.duration_since(t0);
            let skew = elapsed.as_secs_f64() - expected.as_secs_f64();
            assert!(
                skew.abs() < 0.001,
                "packet={packet}: paced {elapsed:?}, expected {expected:?}"
            );
        }
    }

    /// `set_rate` behaves like Go storing a fresh limiter: new rate, bucket full again.
    #[test]
    fn set_rate_resets_the_bucket() {
        let limiter = Limiter::new(100_000);
        let t0 = Instant::now();
        assert!(limiter.reserve_n(t0, 2 * BURST) > Duration::ZERO);

        limiter.set_rate(50_000);
        assert!((limiter.limit() - 50_000.0).abs() < f64::EPSILON);
        assert_eq!(
            limiter.reserve_n(t0, BURST),
            Duration::ZERO,
            "bucket refilled"
        );

        limiter.set_rate(0);
        assert!(limiter.is_unlimited());
        assert_eq!(limiter.reserve_n(t0, 10 * BURST), Duration::ZERO);
    }

    /// A reservation timestamped before the previous one must not panic on the `Instant`
    /// subtraction; Go clamps `last` to `t` and grants no refill.
    #[test]
    fn time_going_backwards_is_clamped() {
        let limiter = Limiter::new(100_000);
        let t0 = Instant::now() + Duration::from_secs(10);
        limiter.reserve_n(t0, BURST);
        let wait = limiter.reserve_n(t0 - Duration::from_secs(5), 1000);
        assert_eq!(wait, ms(10), "no tokens may be earned by going backwards");
    }

    /// A rate so low that the wait overflows `time.Duration` saturates instead of wrapping.
    #[test]
    fn absurd_debt_saturates_at_inf_duration() {
        let limiter = Limiter::with_burst(1e-300, 0);
        let wait = limiter.reserve_n(Instant::now(), usize::MAX);
        assert_eq!(wait, INF_DURATION);
        // A zero or negative limit is Go's "never" as well.
        assert_eq!(duration_from_tokens(0.0, 1.0), INF_DURATION);
        assert_eq!(tokens_from_duration(0.0, Duration::from_secs(1)), 0.0);
        // A negative or NaN nanosecond count becomes zero in the saturating cast. For the
        // negative case that is a deviation, not Go: Go's `time.Duration(duration)` keeps the
        // sign, and Rust's unsigned `Duration` cannot. Unreachable from `reserve_n`, which only
        // ever passes a strictly positive token debt with `limit > 0`; pinned here so the cast
        // cannot start wrapping. NaN is implementation-defined in Go, so zero is fine.
        // (There is deliberately no `f64::max` here: see `cap_at_burst`.)
        assert_eq!(duration_from_tokens(1000.0, -1.0), Duration::ZERO);
        assert_eq!(duration_from_tokens(1000.0, f64::NAN), Duration::ZERO);
    }

    /// `wait_n` actually sleeps for the reservation, and returns at once when there is nothing
    /// to pay for.
    #[tokio::test(flavor = "current_thread")]
    async fn wait_n_paces_in_real_time() {
        let limiter = Limiter::new(100_000);
        let t0 = Instant::now();
        limiter.wait_n(BURST).await; // free: the initial burst
        assert!(t0.elapsed() < ms(50), "the burst must not wait");

        // The bucket is empty, so 2000 bytes at 100 kB/s take about 20 ms.
        let t1 = Instant::now();
        limiter.wait_n(2000).await;
        let elapsed = t1.elapsed();
        assert!(elapsed >= ms(15), "waited only {elapsed:?}");

        let t2 = Instant::now();
        Limiter::unlimited().wait_n(10 * BURST).await;
        assert!(t2.elapsed() < ms(50));
    }

    #[test]
    fn limiter_is_shared_between_threads() {
        let limiter = std::sync::Arc::new(Limiter::new(1_000_000));
        let t0 = Instant::now();
        std::thread::scope(|s| {
            for _ in 0..4 {
                let limiter = std::sync::Arc::clone(&limiter);
                s.spawn(move || {
                    for _ in 0..1000 {
                        limiter.reserve_n(t0, 100);
                    }
                });
            }
        });
        // 400 000 bytes reserved, 96 000 of them free: the bucket owes exactly the rest.
        let tokens = limiter.tokens_at(t0);
        assert!(
            (tokens + (400_000 - BURST) as f64).abs() < 1e-6,
            "tokens={tokens}"
        );
    }
}
