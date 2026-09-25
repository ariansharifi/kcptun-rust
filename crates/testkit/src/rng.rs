//! Deterministic pseudo-random generators owned by this crate.
//!
//! Test traces (netsim delivery orders, generated payloads, expected hashes) must never change
//! because a third-party crate changed its algorithm, so the generators are implemented here:
//!
//! - [`Pcg`] is bit-for-bit Go's `math/rand/v2` `PCG` (128-bit LCG with DXSM output). With
//!   [`govectors_rng`] and [`rand_bytes`] it reproduces `tools/govectors` byte streams exactly
//!   (`newRNG` / `randBytes` in `tools/govectors/vecio.go`), and Go interop peers can generate the
//!   same streams as Rust tests.
//! - [`SplitMix64`] is a tiny generator for deriving seeds.

/// Go's `math/rand/v2` PCG generator.
///
/// `Pcg::new(s1, s2).next_u64()` returns the same sequence as Go's
/// `rand.NewPCG(s1, s2).Uint64()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pcg {
    hi: u64,
    lo: u64,
}

// Go: go1.27.1 src/math/rand/v2/pcg.go:next() constants.
const MUL_HI: u64 = 2549297995355413924;
const MUL_LO: u64 = 4865540595714422341;
const INC_HI: u64 = 6364136223846793005;
const INC_LO: u64 = 1442695040888963407;
const CHEAP_MUL: u64 = 0xda942042e4dd58b5;

impl Pcg {
    // Go: go1.27.1 src/math/rand/v2/pcg.go:NewPCG()
    /// Creates a generator seeded like Go's `rand.NewPCG(seed1, seed2)`.
    pub const fn new(seed1: u64, seed2: u64) -> Self {
        Pcg {
            hi: seed1,
            lo: seed2,
        }
    }

    // Go: go1.27.1 src/math/rand/v2/pcg.go:next()
    fn next(&mut self) -> (u64, u64) {
        // state = state * mul + inc (128-bit, wrapping)
        let state = (u128::from(self.hi) << 64) | u128::from(self.lo);
        let mul = (u128::from(MUL_HI) << 64) | u128::from(MUL_LO);
        let inc = (u128::from(INC_HI) << 64) | u128::from(INC_LO);
        let state = state.wrapping_mul(mul).wrapping_add(inc);
        self.hi = (state >> 64) as u64;
        self.lo = state as u64;
        (self.hi, self.lo)
    }

    // Go: go1.27.1 src/math/rand/v2/pcg.go:Uint64()
    /// Returns the next 64 random bits (Go `Uint64`).
    pub fn next_u64(&mut self) -> u64 {
        let (mut hi, lo) = self.next();
        hi ^= hi >> 32;
        hi = hi.wrapping_mul(CHEAP_MUL);
        hi ^= hi >> 48;
        hi.wrapping_mul(lo | 1)
    }

    /// Returns the upper 32 bits of [`next_u64`](Self::next_u64) (Go `rand.Rand.Uint32`).
    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Returns a float uniformly distributed in `[0, 1)` (Go `rand.Rand.Float64`).
    pub fn next_f64(&mut self) -> f64 {
        // Go: go1.27.1 src/math/rand/v2/rand.go:Float64(): float64(r.Uint64()<<11>>11) / (1 << 53)
        ((self.next_u64() << 11) >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Returns `true` with probability `p` (`p <= 0` never, `p >= 1` always).
    ///
    /// Always consumes exactly one draw, so traces do not depend on the value of `p`.
    pub fn chance(&mut self, p: f64) -> bool {
        self.next_f64() < p
    }

    /// Returns a value uniformly distributed in `[0, n)`; `n == 0` returns 0.
    ///
    /// Uses Lemire's multiply-shift reduction (bias below 2^-64 per draw, irrelevant for tests).
    pub fn below(&mut self, n: u64) -> u64 {
        ((u128::from(self.next_u64()) * u128::from(n)) >> 64) as u64
    }

    /// Fills `buf` like govectors' `randBytes`: eight bytes per `Uint64`, little-endian.
    ///
    /// Filling in several calls is only equivalent to one call when every call but the last
    /// has a length that is a multiple of 8 (a partial word's remaining bytes are discarded,
    /// as in Go).
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

/// FNV-1a 64-bit hash (Go `hash/fnv.New64a`).
pub fn fnv1a64(data: &[u8]) -> u64 {
    const OFFSET: u64 = 14695981039346656037;
    const PRIME: u64 = 1099511628211;
    data.iter()
        .fold(OFFSET, |h, &b| (h ^ u64::from(b)).wrapping_mul(PRIME))
}

// Go: tools/govectors/vecio.go:newRNG()
/// The govectors generator for `(area, stream)`: a PCG seeded with FNV-1a-64 of
/// `"govectors/<area>"` and `stream`.
pub fn govectors_rng(area: &str, stream: u64) -> Pcg {
    Pcg::new(fnv1a64(format!("govectors/{area}").as_bytes()), stream)
}

// Go: tools/govectors/vecio.go:randBytes()
/// Returns `n` bytes drawn from `rng`, eight bytes per `Uint64` (little-endian).
pub fn rand_bytes(rng: &mut Pcg, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    rng.fill_bytes(&mut b);
    b
}

/// SplitMix64 (Steele, Lea and Flood), used to derive independent seeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Creates a generator with the given seed.
    pub const fn new(seed: u64) -> Self {
        SplitMix64 { state: seed }
    }

    /// Returns the next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    // Pins the same values as tools/govectors main_test.go:TestNewRNGIsPinned, proving that
    // `Pcg` + `rand_bytes` reproduce Go's math/rand/v2 PCG byte for byte.
    #[test]
    fn govectors_rng_matches_go_pinned_values() {
        assert_eq!(
            hex::encode(rand_bytes(&mut govectors_rng("test", 7), 20)),
            "e4a7fe36f62fc726956de0924782b941f7b3a9d5"
        );
        let bytes = rand_bytes(&mut govectors_rng("crypt", 0), 1000);
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "684ffc976a2ad92c9abb534650cd7fffa6fa51cfe74c276f1318b0793ac203a8"
        );
    }

    // Mirrors TestRandBytesPrefixStable and TestNewRNGStreamsDiffer.
    #[test]
    fn rand_bytes_prefix_stable_and_streams_differ() {
        let long = rand_bytes(&mut govectors_rng("x", 0), 21);
        let short = rand_bytes(&mut govectors_rng("x", 0), 13);
        assert_eq!(long[..13], short[..]);
        let a = rand_bytes(&mut govectors_rng("kcp", 0), 32);
        assert_ne!(a, rand_bytes(&mut govectors_rng("kcp", 1), 32));
        assert_ne!(a, rand_bytes(&mut govectors_rng("fec", 0), 32));
        assert_eq!(a, rand_bytes(&mut govectors_rng("kcp", 0), 32));
    }

    #[test]
    fn fnv1a64_known_values() {
        assert_eq!(fnv1a64(b""), 0xcbf29ce484222325);
        assert_eq!(fnv1a64(b"a"), 0xaf63dc4c8601ec8c);
    }

    #[test]
    fn splitmix64_reference_sequence() {
        // Reference values of SplitMix64 seeded with 0.
        let mut s = SplitMix64::new(0);
        assert_eq!(s.next_u64(), 0xe220a8397b1dcdaf);
        assert_eq!(s.next_u64(), 0x6e789e6aa1b965f4);
        assert_eq!(s.next_u64(), 0x06c45d188009454f);
    }

    #[test]
    fn helpers_stay_in_range() {
        let mut r = Pcg::new(1, 2);
        for _ in 0..10_000 {
            let f = r.next_f64();
            assert!((0.0..1.0).contains(&f));
            assert!(r.below(7) < 7);
        }
        assert_eq!(r.below(0), 0);
        assert!(!r.chance(0.0));
        assert!(r.chance(1.0));
    }
}
