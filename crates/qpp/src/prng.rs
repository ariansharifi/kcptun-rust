//! Port of `qpp@v1.1.25 prng.go` plus the two generator constructors from `qpp.go`.
//!
//! The pad selector and the one-time-pad bytes both come from `xoshiro256**`. Only that
//! generator is used by QPP; the `xorshift16/32/64star` helpers that sit beside it in `prng.go`
//! are dead code there and are not ported.

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::qpp::{PBKDF2_LOOPS, PM_SELECTOR_IDENTIFIER, PRNG_SALT};

/// A stateful random number generator: the `xoshiro256**` state, its latest output and how many
/// bytes of that output have already been consumed.
///
/// One instance is the whole cipher state of a QPP stream, so a sender and a receiver that both
/// start from `create_prng(seed)` stay in step however their reads and writes are chopped up.
// Go: qpp@v1.1.25 qpp.go:Rand
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rand {
    /// `xoshiro256**` state.
    pub(crate) xoshiro: [u64; 4],
    /// The latest random number: the bytes still being consumed.
    pub(crate) seed64: u64,
    /// Number of bytes of `seed64` already consumed, modulo `PAD_SWITCH`.
    pub(crate) count: u8,
}

impl Rand {
    /// The `xoshiro256**` state.
    pub fn xoshiro(&self) -> [u64; 4] {
        self.xoshiro
    }

    /// The latest random number.
    pub fn seed64(&self) -> u64 {
        self.seed64
    }

    /// Number of bytes of [`seed64`](Self::seed64) already consumed (0..8).
    pub fn count(&self) -> u8 {
        self.count
    }

    /// Advances the `xoshiro256**` state and returns its output, exactly as the encryption loop
    /// does when it crosses an eight-byte boundary. Does not touch `seed64` or `count`.
    // Go: qpp@v1.1.25 prng.go:xoshiro256ss(&rd.xoshiro)
    pub fn next_u64(&mut self) -> u64 {
        xoshiro256ss(&mut self.xoshiro)
    }
}

// Go: qpp@v1.1.25 prng.go:rol64()
/// Rotates `x` left by `k` bits.
fn rol64(x: u64, k: u32) -> u64 {
    x.rotate_left(k)
}

// Go: qpp@v1.1.25 prng.go:xoshiro256ss()
/// One `xoshiro256**` step: returns the output and advances `s`.
pub fn xoshiro256ss(s: &mut [u64; 4]) -> u64 {
    let result = rol64(s[1].wrapping_mul(5), 7).wrapping_mul(9);
    let t = s[1] << 17;

    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];

    s[2] ^= t;
    s[3] = rol64(s[3], 45);

    result
}

// Go: qpp@v1.1.25 qpp.go:CreatePRNG()
/// Creates the deterministic generator of a QPP stream:
/// `HMAC-SHA256(seed, "PERMUTATION_MATRIX_SELECTOR")`, stretched with
/// `PBKDF2-HMAC-SHA1(·, PRNG_SALT, 128, 32)` into the four little-endian state words, with
/// `seed64` the first output.
pub fn create_prng(seed: &[u8]) -> Rand {
    let mut mac = <Hmac<Sha256>>::new_from_slice(seed).expect("HMAC accepts a key of any length");
    mac.update(PM_SELECTOR_IDENTIFIER.as_bytes());
    let sum = mac.finalize().into_bytes();

    // Derive a key for xoroshiro256**
    let xoshiro = pbkdf2::pbkdf2_hmac_array::<Sha1, 32>(&sum, PRNG_SALT.as_bytes(), PBKDF2_LOOPS);
    new_rand(&xoshiro)
}

// Go: qpp@v1.1.25 qpp.go:FastPRNG()
/// Like [`create_prng`] but seeds the state straight from `SHA-256(seed)`. Suitable when the
/// seed already has sufficient randomness; kcptun does not use it.
pub fn fast_prng(seed: &[u8]) -> Rand {
    let sum = Sha256::digest(seed);
    new_rand(&sum)
}

/// Builds a [`Rand`] from 32 bytes of state material: four little-endian words, then one step.
fn new_rand(state: &[u8]) -> Rand {
    let word = |i: usize| {
        let mut b = [0u8; 8];
        b.copy_from_slice(&state[i..i + 8]);
        u64::from_le_bytes(b)
    };
    let mut rd = Rand {
        xoshiro: [word(0), word(8), word(16), word(24)],
        seed64: 0,
        count: 0,
    };
    rd.seed64 = xoshiro256ss(&mut rd.xoshiro);
    rd
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference `xoshiro256**` sequence for the all-ones-ish state used by the original
    /// paper's test vectors: state {1, 2, 3, 4}.
    #[test]
    fn xoshiro256ss_reference_sequence() {
        let mut s = [1u64, 2, 3, 4];
        let got: Vec<u64> = (0..5).map(|_| xoshiro256ss(&mut s)).collect();
        assert_eq!(
            got,
            vec![
                11520,
                0,
                1509978240,
                1215971899390074240,
                1216172134540287360
            ]
        );
    }

    /// `rol64` must be a rotation, not a shift, at the two widths QPP uses.
    #[test]
    fn rol64_rotates() {
        assert_eq!(rol64(1 << 63, 7), 1 << 6);
        assert_eq!(rol64(1 << 63, 45), 1 << 44);
        assert_eq!(rol64(0x0123_4567_89ab_cdef, 0), 0x0123_4567_89ab_cdef);
    }

    /// Both constructors are deterministic, start with `count == 0` and leave the state one
    /// step ahead of `seed64` (Go returns the generator after one `xoshiro256ss` call).
    #[test]
    fn prng_constructors_are_deterministic() {
        for rd in [create_prng(b"seed"), fast_prng(b"seed")] {
            assert_eq!(rd.count(), 0);
            let mut state = rd.xoshiro();
            let mut copy = rd.clone();
            assert_eq!(copy.next_u64(), xoshiro256ss(&mut state));
            assert_eq!(copy.xoshiro(), state);
            assert_eq!(copy.seed64(), rd.seed64());
        }
        assert_eq!(create_prng(b"seed"), create_prng(b"seed"));
        assert_ne!(create_prng(b"seed"), create_prng(b"seee"));
        assert_ne!(create_prng(b"seed"), fast_prng(b"seed"));
    }
}
