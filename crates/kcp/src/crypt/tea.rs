//! TEA block cipher (port of `golang.org/x/crypto/tea`).
//!
//! kcp-go uses it with 16 rounds (`tea.NewCipherWithRounds(key, 16)`), not the standard 64. Words
//! are big-endian, as in x/crypto.

use super::CryptError;
use super::cfb::CfbBlock;

/// The size of a TEA block, in bytes.
// Go: golang.org/x/crypto/tea@v0.47.0 cipher.go:BlockSize
pub const BLOCK_SIZE: usize = 8;

/// The size of a TEA key, in bytes.
// Go: golang.org/x/crypto/tea@v0.47.0 cipher.go:KeySize
pub const KEY_SIZE: usize = 16;

/// The TEA key schedule constant.
// Go: golang.org/x/crypto/tea@v0.47.0 cipher.go:delta
const DELTA: u32 = 0x9e37_79b9;

/// The standard number of rounds in TEA.
// Go: golang.org/x/crypto/tea@v0.47.0 cipher.go:numRounds
const NUM_ROUNDS: usize = 64;

/// A TEA cipher instance with a fixed number of rounds.
///
/// Go keeps the raw 16-byte key and decodes the four big-endian key words on every block; here
/// they are decoded once at construction (same values, no observable difference).
// Go: golang.org/x/crypto/tea@v0.47.0 cipher.go:tea
#[derive(Clone)]
pub struct Tea {
    /// `k0..k3`: the key as four big-endian words.
    key: [u32; 4],
    /// Number of rounds (even); each loop iteration performs two.
    rounds: usize,
}

impl Tea {
    /// Creates a TEA cipher with the standard 64 rounds. The key must be 16 bytes.
    // Go: golang.org/x/crypto/tea@v0.47.0 cipher.go:NewCipher()
    pub fn new_cipher(key: &[u8]) -> Result<Tea, CryptError> {
        Tea::new_cipher_with_rounds(key, NUM_ROUNDS)
    }

    /// Creates a TEA cipher with the given (even) number of rounds. The key must be 16 bytes.
    ///
    /// Errors are Go's: `tea: incorrect key size` and `tea: odd number of rounds specified`.
    // Go: golang.org/x/crypto/tea@v0.47.0 cipher.go:NewCipherWithRounds()
    pub fn new_cipher_with_rounds(key: &[u8], rounds: usize) -> Result<Tea, CryptError> {
        let Ok(key) = <&[u8; KEY_SIZE]>::try_from(key) else {
            return Err(CryptError::TeaKeySize);
        };

        if rounds & 1 != 0 {
            return Err(CryptError::TeaOddRounds);
        }

        let (words, _) = key.as_chunks::<4>();
        let mut k = [0u32; 4];
        for (k, w) in k.iter_mut().zip(words) {
            *k = u32::from_be_bytes(*w);
        }
        Ok(Tea { key: k, rounds })
    }

    /// The block size in bytes (8).
    // Go: golang.org/x/crypto/tea@v0.47.0 cipher.go:tea.BlockSize()
    pub fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    /// Encrypts one 8-byte block in place.
    // Go: golang.org/x/crypto/tea@v0.47.0 cipher.go:tea.Encrypt()
    pub fn encrypt(&self, block: &mut [u8; BLOCK_SIZE]) {
        let (mut v0, mut v1) = load(block);
        let [k0, k1, k2, k3] = self.key;

        let mut sum = 0u32;

        for _ in 0..self.rounds / 2 {
            sum = sum.wrapping_add(DELTA);
            v0 = v0.wrapping_add(
                ((v1 << 4).wrapping_add(k0)) ^ v1.wrapping_add(sum) ^ ((v1 >> 5).wrapping_add(k1)),
            );
            v1 = v1.wrapping_add(
                ((v0 << 4).wrapping_add(k2)) ^ v0.wrapping_add(sum) ^ ((v0 >> 5).wrapping_add(k3)),
            );
        }

        store(block, v0, v1);
    }

    /// Decrypts one 8-byte block in place.
    // Go: golang.org/x/crypto/tea@v0.47.0 cipher.go:tea.Decrypt()
    pub fn decrypt(&self, block: &mut [u8; BLOCK_SIZE]) {
        let (mut v0, mut v1) = load(block);
        let [k0, k1, k2, k3] = self.key;

        // In general, sum = delta * n. Go: uint32(t.rounds/2), truncating.
        let mut sum = DELTA.wrapping_mul((self.rounds / 2) as u32);

        for _ in 0..self.rounds / 2 {
            v1 = v1.wrapping_sub(
                ((v0 << 4).wrapping_add(k2)) ^ v0.wrapping_add(sum) ^ ((v0 >> 5).wrapping_add(k3)),
            );
            v0 = v0.wrapping_sub(
                ((v1 << 4).wrapping_add(k0)) ^ v1.wrapping_add(sum) ^ ((v1 >> 5).wrapping_add(k1)),
            );
            sum = sum.wrapping_sub(DELTA);
        }

        store(block, v0, v1);
    }
}

impl std::fmt::Debug for Tea {
    // The key is secret: print only the round count.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tea")
            .field("rounds", &self.rounds)
            .finish_non_exhaustive()
    }
}

impl CfbBlock<BLOCK_SIZE> for Tea {
    #[inline(always)]
    fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        self.encrypt(block);
    }
}

/// `binary.BigEndian.Uint32(src), binary.BigEndian.Uint32(src[4:])`.
#[inline(always)]
fn load(block: &[u8; BLOCK_SIZE]) -> (u32, u32) {
    let v0 = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
    let v1 = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
    (v0, v1)
}

/// `binary.BigEndian.PutUint32(dst, v0); binary.BigEndian.PutUint32(dst[4:], v1)`.
#[inline(always)]
fn store(block: &mut [u8; BLOCK_SIZE], v0: u32, v1: u32) {
    block[..4].copy_from_slice(&v0.to_be_bytes());
    block[4..].copy_from_slice(&v1.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn hex8(s: &str) -> [u8; 8] {
        let v = hex::decode(s).expect("hex");
        v.try_into().expect("8 bytes")
    }

    /// Single-block known answers from `golang.org/x/crypto/tea` (pinned, vendored in kcptun):
    /// key `00 01 .. 0f`, plaintext `0123456789abcdef`; and the all-zero key and block.
    #[test]
    fn known_answers_match_x_crypto() {
        let seq: Vec<u8> = (0..16).collect();
        let zero = [0u8; 16];
        let cases = [
            (16, "4bba3193aceaa306", "ed285da1455b33c1"),
            (64, "14f0c75d2bebd98d", "41ea3a0a94baa940"),
            (2, "b6300894b87c6d44", "9e3779b9dbe8d32f"),
            (0, "0123456789abcdef", "0000000000000000"),
        ];
        for (rounds, want_seq, want_zero) in cases {
            let t = Tea::new_cipher_with_rounds(&seq, rounds).expect("valid");
            let mut b = hex8("0123456789abcdef");
            t.encrypt(&mut b);
            assert_eq!(hex::encode(b), want_seq, "rounds {rounds}");
            t.decrypt(&mut b);
            assert_eq!(hex::encode(b), "0123456789abcdef", "rounds {rounds}");

            let t = Tea::new_cipher_with_rounds(&zero, rounds).expect("valid");
            let mut b = [0u8; 8];
            t.encrypt(&mut b);
            assert_eq!(hex::encode(b), want_zero, "rounds {rounds}");
            t.decrypt(&mut b);
            assert_eq!(b, [0u8; 8]);
        }
        // NewCipher uses the standard 64 rounds.
        let t = Tea::new_cipher(&seq).expect("valid");
        let mut b = hex8("0123456789abcdef");
        t.encrypt(&mut b);
        assert_eq!(hex::encode(b), "14f0c75d2bebd98d");
    }

    #[test]
    fn errors_match_x_crypto() {
        let key = [0u8; 32];
        for len in 0..=key.len() {
            let r = Tea::new_cipher_with_rounds(&key[..len], 16);
            if len == KEY_SIZE {
                assert!(r.is_ok());
            } else {
                let e = r.expect_err("bad key size");
                assert_eq!(e.to_string(), "tea: incorrect key size");
            }
        }
        let e = Tea::new_cipher_with_rounds(&key[..16], 3).expect_err("odd rounds");
        assert_eq!(e.to_string(), "tea: odd number of rounds specified");
        // The key size is checked first.
        let e = Tea::new_cipher_with_rounds(&key[..15], 3).expect_err("bad key size");
        assert_eq!(e, CryptError::TeaKeySize);
    }

    #[test]
    fn debug_does_not_leak_key() {
        let t = Tea::new_cipher_with_rounds(&[0xab; 16], 16).expect("valid");
        assert_eq!(format!("{t:?}"), "Tea { rounds: 16, .. }");
    }

    proptest! {
        #[test]
        fn prop_tea_block_roundtrip(
            key in proptest::array::uniform16(any::<u8>()),
            block in proptest::array::uniform8(any::<u8>()),
            half_rounds in 0usize..=40,
        ) {
            let t = Tea::new_cipher_with_rounds(&key, half_rounds * 2).expect("valid");
            let mut b = block;
            t.encrypt(&mut b);
            t.decrypt(&mut b);
            prop_assert_eq!(b, block);
        }
    }
}
