//! XTEA block cipher (port of `golang.org/x/crypto/xtea`: `cipher.go` and `block.go`).
//!
//! The key-dependent part of every round (`sum + k[...]`) is precomputed into a 64-entry table,
//! exactly as in x/crypto. Words are big-endian.

use super::CryptError;
use super::cfb::CfbBlock;

/// The XTEA block size in bytes.
// Go: golang.org/x/crypto/xtea@v0.47.0 cipher.go:BlockSize
pub const BLOCK_SIZE: usize = 8;

/// XTEA is based on 64 rounds.
// Go: golang.org/x/crypto/xtea@v0.47.0 block.go:numRounds
const NUM_ROUNDS: usize = 64;

/// An XTEA cipher instance using a particular key.
// Go: golang.org/x/crypto/xtea@v0.47.0 cipher.go:Cipher
#[derive(Clone)]
pub struct Xtea {
    /// A series of precalculated values that are used each round.
    table: [u32; NUM_ROUNDS],
}

impl Xtea {
    /// Creates an XTEA cipher. The key must be 16 bytes, otherwise Go's
    /// `crypto/xtea: invalid key size N`.
    // Go: golang.org/x/crypto/xtea@v0.47.0 cipher.go:NewCipher()
    pub fn new_cipher(key: &[u8]) -> Result<Xtea, CryptError> {
        let Ok(key) = <&[u8; 16]>::try_from(key) else {
            return Err(CryptError::KeySize {
                pkg: "xtea",
                size: key.len(),
            });
        };

        let mut c = Xtea {
            table: [0; NUM_ROUNDS],
        };
        init_cipher(&mut c, key);

        Ok(c)
    }

    /// The block size in bytes (8).
    // Go: golang.org/x/crypto/xtea@v0.47.0 cipher.go:Cipher.BlockSize()
    pub fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    /// Encrypts one 8-byte block in place.
    // Go: golang.org/x/crypto/xtea@v0.47.0 cipher.go:Cipher.Encrypt() -> block.go:encryptBlock()
    pub fn encrypt(&self, block: &mut [u8; BLOCK_SIZE]) {
        let (mut v0, mut v1) = block_to_uint32(block);

        // Two rounds of XTEA applied per loop.
        let (pairs, _) = self.table.as_chunks::<2>();
        for &[t0, t1] in pairs {
            v0 = v0.wrapping_add(((v1 << 4 ^ v1 >> 5).wrapping_add(v1)) ^ t0);
            v1 = v1.wrapping_add(((v0 << 4 ^ v0 >> 5).wrapping_add(v0)) ^ t1);
        }

        uint32_to_block(v0, v1, block);
    }

    /// Decrypts one 8-byte block in place.
    // Go: golang.org/x/crypto/xtea@v0.47.0 cipher.go:Cipher.Decrypt() -> block.go:decryptBlock()
    pub fn decrypt(&self, block: &mut [u8; BLOCK_SIZE]) {
        let (mut v0, mut v1) = block_to_uint32(block);

        // Two rounds of XTEA applied per loop.
        let (pairs, _) = self.table.as_chunks::<2>();
        for &[t0, t1] in pairs.iter().rev() {
            v1 = v1.wrapping_sub(((v0 << 4 ^ v0 >> 5).wrapping_add(v0)) ^ t1);
            v0 = v0.wrapping_sub(((v1 << 4 ^ v1 >> 5).wrapping_add(v1)) ^ t0);
        }

        uint32_to_block(v0, v1, block);
    }
}

impl std::fmt::Debug for Xtea {
    // The round table is derived from the key: do not print it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Xtea").finish_non_exhaustive()
    }
}

impl CfbBlock<BLOCK_SIZE> for Xtea {
    #[inline(always)]
    fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        self.encrypt(block);
    }
}

/// Precalculates the round table from the key.
// Go: golang.org/x/crypto/xtea@v0.47.0 cipher.go:initCipher()
fn init_cipher(c: &mut Xtea, key: &[u8; 16]) {
    // Load the key into four uint32s.
    let (words, _) = key.as_chunks::<4>();
    let mut k = [0u32; 4];
    for (k, w) in k.iter_mut().zip(words) {
        *k = u32::from_be_bytes(*w);
    }

    // Precalculate the table.
    const DELTA: u32 = 0x9E37_79B9;
    let mut sum = 0u32;

    // Two rounds of XTEA applied per loop.
    let (pairs, _) = c.table.as_chunks_mut::<2>();
    for pair in pairs {
        pair[0] = sum.wrapping_add(k[(sum & 3) as usize]);
        sum = sum.wrapping_add(DELTA);
        pair[1] = sum.wrapping_add(k[((sum >> 11) & 3) as usize]);
    }
}

/// Reads an 8-byte block as two big-endian `u32`s.
// Go: golang.org/x/crypto/xtea@v0.47.0 block.go:blockToUint32()
#[inline(always)]
fn block_to_uint32(src: &[u8; BLOCK_SIZE]) -> (u32, u32) {
    let r0 = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
    let r1 = u32::from_be_bytes([src[4], src[5], src[6], src[7]]);
    (r0, r1)
}

/// Writes two `u32`s big-endian into an 8-byte block.
// Go: golang.org/x/crypto/xtea@v0.47.0 block.go:uint32ToBlock()
#[inline(always)]
fn uint32_to_block(v0: u32, v1: u32, dst: &mut [u8; BLOCK_SIZE]) {
    dst[..4].copy_from_slice(&v0.to_be_bytes());
    dst[4..].copy_from_slice(&v1.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Single-block known answers from `golang.org/x/crypto/xtea` (pinned, vendored in kcptun):
    /// key `00 01 .. 0f` with plaintext `0123456789abcdef`, and the all-zero key and block.
    #[test]
    fn known_answers_match_x_crypto() {
        let seq: Vec<u8> = (0..16).collect();
        let x = Xtea::new_cipher(&seq).expect("valid");
        let mut b: [u8; 8] = hex::decode("0123456789abcdef")
            .expect("hex")
            .try_into()
            .expect("8 bytes");
        x.encrypt(&mut b);
        assert_eq!(hex::encode(b), "14669763a456e1d8");
        x.decrypt(&mut b);
        assert_eq!(hex::encode(b), "0123456789abcdef");

        let x = Xtea::new_cipher(&[0u8; 16]).expect("valid");
        let mut b = [0u8; 8];
        x.encrypt(&mut b);
        assert_eq!(hex::encode(b), "dee9d4d8f7131ed9");
        x.decrypt(&mut b);
        assert_eq!(b, [0u8; 8]);
    }

    /// The table layout of x/crypto: even entries `sum + k[sum & 3]` before adding delta, odd
    /// entries `sum + k[(sum >> 11) & 3]` after.
    #[test]
    fn table_first_entries() {
        let key: Vec<u8> = (0..16).collect();
        let x = Xtea::new_cipher(&key).expect("valid");
        let k = [0x0001_0203u32, 0x0405_0607, 0x0809_0a0b, 0x0c0d_0e0f];
        assert_eq!(x.table[0], k[0]);
        let s1 = 0x9E37_79B9u32;
        assert_eq!(x.table[1], s1.wrapping_add(k[((s1 >> 11) & 3) as usize]));
        assert_eq!(x.table[2], s1.wrapping_add(k[(s1 & 3) as usize]));
    }

    #[test]
    fn errors_match_x_crypto() {
        let key = [0u8; 32];
        for len in 0..=key.len() {
            let r = Xtea::new_cipher(&key[..len]);
            if len == 16 {
                assert!(r.is_ok());
            } else {
                let e = r.expect_err("bad key size");
                assert_eq!(
                    e.to_string(),
                    format!("crypto/xtea: invalid key size {len}")
                );
            }
        }
    }

    #[test]
    fn debug_does_not_leak_key() {
        let x = Xtea::new_cipher(&[0xab; 16]).expect("valid");
        assert_eq!(format!("{x:?}"), "Xtea { .. }");
    }

    proptest! {
        #[test]
        fn prop_xtea_block_roundtrip(
            key in proptest::array::uniform16(any::<u8>()),
            block in proptest::array::uniform8(any::<u8>()),
        ) {
            let x = Xtea::new_cipher(&key).expect("valid");
            let mut b = block;
            x.encrypt(&mut b);
            x.decrypt(&mut b);
            prop_assert_eq!(b, block);
        }
    }
}
