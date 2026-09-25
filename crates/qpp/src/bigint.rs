//! The bare minimum of arbitrary-precision arithmetic needed by
//! [`qpp_minimum_seed_length`](crate::qpp_minimum_seed_length): a non-negative integer that can
//! be multiplied by a small factor and asked for its bit length.
//!
//! Go uses `math/big` there. A whole bignum crate would be a heavy dependency for one factorial,
//! and the permutation shuffle's 256-bit modulo is done byte-wise in `qpp.rs` instead, so this
//! is all that is left.

/// A non-negative integer as little-endian 64-bit limbs, with no leading zero limb (zero is the
/// empty limb vector).
// Go: math/big.Int, as used by qpp@v1.1.25 qpp.go:QPPMinimumSeedLength()
pub(crate) struct BigUint {
    limbs: Vec<u64>,
}

impl BigUint {
    /// The value `v`.
    pub(crate) fn from_u64(v: u64) -> Self {
        BigUint {
            limbs: if v == 0 { Vec::new() } else { vec![v] },
        }
    }

    /// Multiplies in place by `m`.
    pub(crate) fn mul_u64(&mut self, m: u64) {
        if m == 0 {
            self.limbs.clear();
            return;
        }
        let mut carry: u64 = 0;
        for limb in &mut self.limbs {
            let wide = u128::from(*limb) * u128::from(m) + u128::from(carry);
            *limb = wide as u64;
            carry = (wide >> 64) as u64;
        }
        if carry != 0 {
            self.limbs.push(carry);
        }
    }

    /// Number of bits needed to represent the value; zero has bit length 0.
    // Go: math/big.Int.BitLen()
    pub(crate) fn bit_len(&self) -> usize {
        match self.limbs.last() {
            None => 0,
            Some(&top) => self.limbs.len() * 64 - top.leading_zeros() as usize,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BigUint;

    #[test]
    fn bit_len_of_small_values() {
        for v in [0u64, 1, 2, 3, 255, 256, u64::MAX] {
            let want = 64 - v.leading_zeros() as usize;
            assert_eq!(BigUint::from_u64(v).bit_len(), want, "value {v}");
        }
    }

    #[test]
    fn multiplication_carries_across_limbs() {
        // 2^64 = u64::MAX + 1 has 65 bits and two limbs.
        let mut n = BigUint::from_u64(u64::MAX);
        n.mul_u64(2);
        assert_eq!(n.limbs, vec![u64::MAX - 1, 1]);
        assert_eq!(n.bit_len(), 65);

        // 2^128 has 129 bits: three limbs, the top one equal to 1.
        let mut n = BigUint::from_u64(1);
        for _ in 0..4 {
            n.mul_u64(1 << 32);
        }
        assert_eq!(n.limbs, vec![0, 0, 1]);
        assert_eq!(n.bit_len(), 129);
    }

    #[test]
    fn multiplying_by_zero_gives_zero() {
        let mut n = BigUint::from_u64(u64::MAX);
        n.mul_u64(3);
        n.mul_u64(0);
        assert_eq!(n.bit_len(), 0);
        n.mul_u64(7);
        assert_eq!(n.bit_len(), 0);
    }

    /// 20! = 2432902008176640000 still fits in a `u64`, so the limb arithmetic can be checked
    /// against the plain one.
    #[test]
    fn factorial_matches_u64_arithmetic() {
        let mut n = BigUint::from_u64(1);
        let mut plain: u64 = 1;
        for i in 2..=20u64 {
            n.mul_u64(i);
            plain *= i;
        }
        assert_eq!(n.limbs, vec![plain]);
        assert_eq!(n.bit_len(), 64 - plain.leading_zeros() as usize);
    }
}
