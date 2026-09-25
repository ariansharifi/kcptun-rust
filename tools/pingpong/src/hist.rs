//! A bounded-memory latency histogram.
//!
//! A 30-second pingpong run holds tens of thousands of samples; the 11.4 soak runs for six
//! hours and would hold hundreds of millions. Keeping every sample is therefore not an option —
//! the harness itself must not grow without bound — so latencies go into a log-linear histogram
//! in the shape HdrHistogram uses: 128 linear buckets per power of two, which bounds the
//! relative error of any reported percentile at 1/128 (0.8 %) while the whole histogram is a
//! fixed 58 KiB. `min` and `max` are tracked exactly, because the maximum is the number an
//! outlier hunt starts from.

/// Bits of precision inside one power of two: 2^7 = 128 sub-buckets.
const SUB_BITS: u32 = 7;
/// Sub-buckets per power of two.
const SUB: u64 = 1 << SUB_BITS;
/// Enough buckets for every `u64`: the linear region plus one block per shift.
const BUCKETS: usize = (SUB as usize) * (64 - SUB_BITS as usize + 1);

/// A histogram of non-negative values (the tools record nanoseconds).
#[derive(Debug, Clone)]
pub struct Histogram {
    buckets: Vec<u64>,
    count: u64,
    sum: u128,
    min: u64,
    max: u64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

impl Histogram {
    /// An empty histogram.
    pub fn new() -> Self {
        Self {
            buckets: vec![0; BUCKETS],
            count: 0,
            sum: 0,
            min: u64::MAX,
            max: 0,
        }
    }

    /// Bucket of `value`; contiguous and strictly monotonic in `value`.
    fn index(value: u64) -> usize {
        if value < SUB {
            return value as usize;
        }
        // `value >= SUB` so the leading bit is at or above SUB_BITS and `shift` cannot underflow.
        let msb = 63 - value.leading_zeros();
        let shift = msb - SUB_BITS;
        let sub = (value >> shift) - SUB;
        (SUB * u64::from(shift + 1) + sub) as usize
    }

    /// Smallest and largest value that land in `index`.
    fn bounds(index: usize) -> (u64, u64) {
        let index = index as u64;
        if index < SUB {
            return (index, index);
        }
        let shift = u32::try_from(index / SUB)
            .unwrap_or(u32::MAX)
            .saturating_sub(1);
        let sub = index % SUB;
        let low = (SUB + sub) << shift;
        (low, low + (1 << shift) - 1)
    }

    /// Records one value.
    pub fn record(&mut self, value: u64) {
        let i = Self::index(value);
        self.buckets[i] = self.buckets[i].saturating_add(1);
        self.count = self.count.saturating_add(1);
        self.sum = self.sum.saturating_add(u128::from(value));
        self.min = self.min.min(value);
        self.max = self.max.max(value);
    }

    /// Number of recorded values.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Smallest recorded value, or 0 when empty.
    pub fn min(&self) -> u64 {
        if self.count == 0 { 0 } else { self.min }
    }

    /// Largest recorded value, or 0 when empty.
    pub fn max(&self) -> u64 {
        self.max
    }

    /// Arithmetic mean, or 0 when empty.
    pub fn mean(&self) -> f64 {
        if self.count == 0 {
            return 0.0;
        }
        self.sum as f64 / self.count as f64
    }

    /// The value at `q` (0.0 to 1.0), interpolated to the middle of the winning bucket.
    ///
    /// The exact `max` is returned for `q >= 1.0`, and for any quantile whose bucket is the one
    /// holding the maximum, so `p99` never reads higher than `max`.
    pub fn quantile(&self, q: f64) -> u64 {
        if self.count == 0 {
            return 0;
        }
        if q >= 1.0 {
            return self.max;
        }
        let q = q.max(0.0);
        // `ceil` puts the median of an even count on the upper of the two middle samples, which
        // is what "at least q of the samples are <= this" means.
        let target = ((q * self.count as f64).ceil() as u64).clamp(1, self.count);
        let mut seen = 0u64;
        for (i, &n) in self.buckets.iter().enumerate() {
            if n == 0 {
                continue;
            }
            seen += n;
            if seen >= target {
                let (low, high) = Self::bounds(i);
                let mid = low + (high - low) / 2;
                return mid.clamp(self.min, self.max);
            }
        }
        self.max
    }

    /// Empties the histogram, for per-interval reporting.
    pub fn reset(&mut self) {
        self.buckets.fill(0);
        self.count = 0;
        self.sum = 0;
        self.min = u64::MAX;
        self.max = 0;
    }

    /// Adds every value of `other` to this histogram.
    pub fn merge(&mut self, other: &Histogram) {
        if other.count == 0 {
            return;
        }
        for (mine, theirs) in self.buckets.iter_mut().zip(other.buckets.iter()) {
            *mine = mine.saturating_add(*theirs);
        }
        self.count = self.count.saturating_add(other.count);
        self.sum = self.sum.saturating_add(other.sum);
        self.min = self.min.min(other.min);
        self.max = self.max.max(other.max);
    }

    /// The percentiles every lab report quotes, in microseconds.
    pub fn summary_us(&self) -> Summary {
        let us = |ns: u64| ns as f64 / 1000.0;
        Summary {
            count: self.count,
            min: us(self.min()),
            mean: us(self.mean() as u64),
            p50: us(self.quantile(0.50)),
            p90: us(self.quantile(0.90)),
            p99: us(self.quantile(0.99)),
            max: us(self.max()),
        }
    }
}

/// Percentiles of one histogram, in microseconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Summary {
    /// Number of samples.
    pub count: u64,
    /// Smallest sample.
    pub min: f64,
    /// Arithmetic mean.
    pub mean: f64,
    /// Median.
    pub p50: f64,
    /// 90th percentile.
    pub p90: f64,
    /// 99th percentile.
    pub p99: f64,
    /// Largest sample.
    pub max: f64,
}

impl Summary {
    /// The summary as JSON object fields (no braces), for the `RESULT` line.
    pub fn json_fields(&self, prefix: &str) -> String {
        format!(
            "\"{p}count\":{},\"{p}min_us\":{:.3},\"{p}mean_us\":{:.3},\"{p}p50_us\":{:.3},\
             \"{p}p90_us\":{:.3},\"{p}p99_us\":{:.3},\"{p}max_us\":{:.3}",
            self.count,
            self.min,
            self.mean,
            self.p50,
            self.p90,
            self.p99,
            self.max,
            p = prefix
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_values_are_exact() {
        let mut h = Histogram::new();
        for v in 0..SUB {
            h.record(v);
        }
        assert_eq!(h.count(), SUB);
        assert_eq!(h.min(), 0);
        assert_eq!(h.max(), SUB - 1);
        assert_eq!(h.quantile(0.5), 63);
        assert_eq!(h.quantile(1.0), SUB - 1);
    }

    #[test]
    fn indices_are_contiguous_and_monotonic() {
        let mut previous = 0usize;
        let mut value = 0u64;
        while value < 1 << 40 {
            let i = Histogram::index(value);
            assert!(i >= previous, "index fell back at {value}");
            assert!(i < BUCKETS, "index {i} out of range at {value}");
            let (low, high) = Histogram::bounds(i);
            assert!(
                low <= value && value <= high,
                "{value} not in [{low},{high}]"
            );
            previous = i;
            value = value.saturating_add(1 + value / 97);
        }
    }

    #[test]
    fn percentiles_stay_within_the_promised_error() {
        let mut h = Histogram::new();
        for v in 1..=100_000u64 {
            h.record(v * 1_000);
        }
        // 0.8 % is the bucket width at this magnitude; allow one bucket of slack.
        for (q, want) in [
            (0.5, 50_000_000.0),
            (0.9, 90_000_000.0),
            (0.99, 99_000_000.0),
        ] {
            let got = h.quantile(q) as f64;
            let err = (got - want).abs() / want;
            assert!(err < 0.01, "q{q}: got {got}, want {want} ({err})");
        }
        assert_eq!(h.max(), 100_000_000);
        assert_eq!(h.min(), 1_000);
    }

    #[test]
    fn quantiles_never_exceed_the_exact_max() {
        let mut h = Histogram::new();
        h.record(1);
        h.record(1_000_000_003);
        assert_eq!(h.max(), 1_000_000_003);
        assert!(h.quantile(0.99) <= h.max());
        assert!(h.quantile(0.5) >= h.min());
    }

    #[test]
    fn reset_and_merge_behave() {
        let mut a = Histogram::new();
        let mut b = Histogram::new();
        a.record(10);
        b.record(20);
        b.record(30);
        a.merge(&b);
        assert_eq!(a.count(), 3);
        assert_eq!(a.min(), 10);
        assert_eq!(a.max(), 30);
        assert_eq!(a.mean(), 20.0);
        a.reset();
        assert_eq!(a.count(), 0);
        assert_eq!(a.max(), 0);
        assert_eq!(a.min(), 0);
        assert_eq!(a.quantile(0.5), 0);
    }

    #[test]
    fn empty_summary_is_all_zero() {
        let s = Histogram::new().summary_us();
        assert_eq!(s.count, 0);
        assert_eq!(s.p99, 0.0);
        assert!(s.json_fields("rtt_").contains("\"rtt_p99_us\":0.000"));
    }
}
