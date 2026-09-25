//! A seeded pseudo-random source for workload shapes and payloads.
//!
//! Reproducibility is the point: a soak that behaved oddly must be repeatable, so every choice
//! (stream size, direction, payload bytes) comes from a seed the run records. SplitMix64 is used
//! rather than a dependency because the quality needed here is "not obviously patterned".

/// SplitMix64, the mixing function from Steele et al., "Fast splittable pseudorandom number
/// generators" (2014), as used by `rand`'s `SmallRng` seeding.
#[derive(Debug, Clone)]
pub struct SplitMix64(u64);

impl SplitMix64 {
    /// Seeds the generator.
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// Seeds from the wall clock, for a run that did not ask for a fixed seed.
    pub fn from_clock() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        Self::new(nanos ^ (std::process::id() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15))
    }

    /// The next 64 bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A float in `[0, 1)`.
    pub fn next_f64(&mut self) -> f64 {
        // 53 bits of mantissa, the largest exactly representable integer range.
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// A value in `[low, high]`, uniform. `high < low` yields `low`.
    pub fn uniform(&mut self, low: u64, high: u64) -> u64 {
        if high <= low {
            return low;
        }
        let span = high - low + 1;
        low + self.next_u64() % span
    }

    /// A value in `[low, high]`, uniform in the **logarithm**.
    ///
    /// The churn workload's sizes run from 10 kB to 1 MB. Drawn uniformly, the mean would sit at
    /// 505 kB and the run would be a bulk test wearing a churn costume; drawn log-uniformly the
    /// mean is about 215 kB and every decade of size is equally represented, which is what makes
    /// the workload exercise short streams as well as long ones.
    pub fn log_uniform(&mut self, low: u64, high: u64) -> u64 {
        if high <= low || low == 0 {
            return self.uniform(low, high);
        }
        let (lo, hi) = ((low as f64).ln(), (high as f64).ln());
        let v = (lo + self.next_f64() * (hi - lo)).exp();
        (v as u64).clamp(low, high)
    }

    /// True with probability `p`.
    pub fn chance(&mut self, p: f64) -> bool {
        self.next_f64() < p
    }

    /// Fills `buf` with pseudo-random bytes.
    ///
    /// Payloads must **not** be all zeroes: the S2 configuration runs with snappy compression on,
    /// and a compressible payload would measure the compressor rather than the tunnel.
    pub fn fill(&mut self, buf: &mut [u8]) {
        let (whole, tail) = buf.as_chunks_mut::<8>();
        for chunk in whole {
            *chunk = self.next_u64().to_le_bytes();
        }
        if !tail.is_empty() {
            let bytes = self.next_u64().to_le_bytes();
            tail.copy_from_slice(&bytes[..tail.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_seed_gives_the_same_stream() {
        let mut a = SplitMix64::new(42);
        let mut b = SplitMix64::new(42);
        let mut c = SplitMix64::new(43);
        let first: Vec<u64> = (0..8).map(|_| a.next_u64()).collect();
        let second: Vec<u64> = (0..8).map(|_| b.next_u64()).collect();
        let other: Vec<u64> = (0..8).map(|_| c.next_u64()).collect();
        assert_eq!(first, second);
        assert_ne!(first, other);
    }

    #[test]
    fn uniform_stays_inside_its_bounds() {
        let mut r = SplitMix64::new(7);
        for _ in 0..10_000 {
            let v = r.uniform(10, 20);
            assert!((10..=20).contains(&v), "{v}");
        }
        assert_eq!(r.uniform(5, 5), 5);
        assert_eq!(r.uniform(9, 1), 9);
    }

    #[test]
    fn log_uniform_stays_in_range_and_favours_small_values() {
        let mut r = SplitMix64::new(11);
        let low = 10 * 1024;
        let high = 1024 * 1024;
        let mut sum = 0u128;
        let n = 20_000;
        for _ in 0..n {
            let v = r.log_uniform(low, high);
            assert!((low..=high).contains(&v), "{v}");
            sum += u128::from(v);
        }
        let mean = (sum / u128::from(n as u64)) as u64;
        let uniform_mean = (low + high) / 2;
        assert!(
            mean < uniform_mean,
            "mean {mean} should be below {uniform_mean}"
        );
        assert!(mean > low, "mean {mean} should be above {low}");
    }

    #[test]
    fn fill_covers_every_byte_and_is_not_all_zero() {
        let mut r = SplitMix64::new(3);
        for len in [0usize, 1, 7, 8, 9, 4096] {
            let mut buf = vec![0u8; len];
            r.fill(&mut buf);
            assert!(
                len == 0 || buf.iter().any(|&b| b != 0),
                "len {len} stayed zero"
            );
        }
    }

    #[test]
    fn chance_is_roughly_fair() {
        let mut r = SplitMix64::new(5);
        let hits = (0..10_000).filter(|_| r.chance(0.5)).count();
        assert!((4_500..5_500).contains(&hits), "{hits}");
    }
}
