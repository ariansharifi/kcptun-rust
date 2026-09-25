//! SM4 block cipher (port of `github.com/tjfoc/gmsm/sm4`, the implementation kcp-go links).
//!
//! Origin and licence: modified port of gmsm v1.4.1 `sm4/sm4.go`, Copyright Suzhou Tongji Fintech
//! Research Institute 2017, Apache License 2.0 (see `NOTICE.md` for the list of changes).
//!
//! kcp-go uses it for `-crypt sm4` with a 16-byte key. Like gmsm, a round combines the S-box
//! and the linear transform L into four 256-entry word tables (`sbox0..sbox3`, generated at
//! compile time here from `SBOX` and L; gmsm has them as literals), so a round is 4 table
//! lookups. RustCrypto's `sm4` 0.6 applies the S-box byte by byte and L separately, which is
//! about 20% slower than Go (plan 02.6, `docs/benchmarks/crypto.md`).
//!
//! As in Go, the table lookups are indexed by secret data (not constant time).

use super::CryptError;
use super::cfb::CfbBlock;

/// The SM4 block size in bytes.
// Go: github.com/tjfoc/gmsm@v1.4.1 sm4/sm4.go:BlockSize
pub const BLOCK_SIZE: usize = 16;

/// An instance of SM4 encryption: the 32 round keys.
///
/// gmsm also keeps two scratch buffers in the cipher (so it is not safe for concurrent use);
/// here the state is on the stack.
// Go: github.com/tjfoc/gmsm@v1.4.1 sm4/sm4.go:Sm4Cipher
#[derive(Clone)]
pub struct Sm4Cipher {
    subkeys: [u32; 32],
}

impl Sm4Cipher {
    /// Creates an SM4 cipher. The key must be 16 bytes, otherwise gmsm's
    /// `SM4: invalid key size N`.
    // Go: github.com/tjfoc/gmsm@v1.4.1 sm4/sm4.go:NewCipher()
    pub fn new_cipher(key: &[u8]) -> Result<Sm4Cipher, CryptError> {
        let key = <&[u8; BLOCK_SIZE]>::try_from(key)
            .map_err(|_| CryptError::Sm4KeySize { size: key.len() })?;
        Ok(Sm4Cipher {
            subkeys: generate_sub_keys(key),
        })
    }

    /// The SM4 block size, 16 bytes.
    // Go: github.com/tjfoc/gmsm@v1.4.1 sm4/sm4.go:Sm4Cipher.BlockSize()
    pub fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    /// Encrypts one block in place.
    // Go: github.com/tjfoc/gmsm@v1.4.1 sm4/sm4.go:Sm4Cipher.Encrypt()
    #[inline]
    pub fn encrypt(&self, block: &mut [u8; BLOCK_SIZE]) {
        crypt_block(&self.subkeys, block, false);
    }

    /// Decrypts one block in place.
    // Go: github.com/tjfoc/gmsm@v1.4.1 sm4/sm4.go:Sm4Cipher.Decrypt()
    pub fn decrypt(&self, block: &mut [u8; BLOCK_SIZE]) {
        crypt_block(&self.subkeys, block, true);
    }
}

impl std::fmt::Debug for Sm4Cipher {
    // The key schedule is secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sm4Cipher { .. }")
    }
}

impl CfbBlock<BLOCK_SIZE> for Sm4Cipher {
    #[inline(always)]
    fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        self.encrypt(block);
    }
}

/// System parameter FK of the key schedule.
// Go: github.com/tjfoc/gmsm@v1.4.1 sm4/sm4.go:fk
const FK: [u32; 4] = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];

/// Fixed parameters CK of the key schedule.
// Go: github.com/tjfoc/gmsm@v1.4.1 sm4/sm4.go:ck
const CK: [u32; 32] = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
];

/// The SM4 S-box.
// Go: github.com/tjfoc/gmsm@v1.4.1 sm4/sm4.go:sbox
#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];

/// The round transform `L(tau(x))` for a byte in the low position: `SBOX0[i] = L(SBOX[i])`.
/// `SBOX1..3` are the same for the byte at bits 8, 16 and 24, i.e. `SBOX0` rotated left by 8,
/// 16 and 24 bits (L commutes with rotation).
// Go: github.com/tjfoc/gmsm@v1.4.1 sm4/sm4.go:sbox0, sbox1, sbox2, sbox3 (literal tables)
static SBOX_T: [[u32; 256]; 4] = init_sbox_tables();

/// The encryption linear transform L: `b ^ (b <<< 2) ^ (b <<< 10) ^ (b <<< 18) ^ (b <<< 24)`.
const fn l(b: u32) -> u32 {
    b ^ b.rotate_left(2) ^ b.rotate_left(10) ^ b.rotate_left(18) ^ b.rotate_left(24)
}

const fn init_sbox_tables() -> [[u32; 256]; 4] {
    let mut t = [[0u32; 256]; 4];
    let mut i = 0;
    while i < 256 {
        let v = l(SBOX[i] as u32);
        t[0][i] = v;
        t[1][i] = v.rotate_left(8);
        t[2][i] = v.rotate_left(16);
        t[3][i] = v.rotate_left(24);
        i += 1;
    }
    t
}

/// `rl(x, i)`: rotate left.
// Go: github.com/tjfoc/gmsm@v1.4.1 sm4/sm4.go:rl()
#[inline(always)]
fn rl(x: u32, i: u8) -> u32 {
    x.rotate_left(u32::from(i % 32))
}

/// The key schedule's linear transform L'.
// Go: github.com/tjfoc/gmsm@v1.4.1 sm4/sm4.go:l0()
fn l0(b: u32) -> u32 {
    b ^ rl(b, 13) ^ rl(b, 23)
}

/// One key schedule round.
// Go: github.com/tjfoc/gmsm@v1.4.1 sm4/sm4.go:feistel0()
fn feistel0(x0: u32, x1: u32, x2: u32, x3: u32, rk: u32) -> u32 {
    x0 ^ l0(p(x1 ^ x2 ^ x3 ^ rk))
}

/// The non-linear transform tau: the S-box applied to each byte.
// Go: github.com/tjfoc/gmsm@v1.4.1 sm4/sm4.go:p()
fn p(a: u32) -> u32 {
    let [b0, b1, b2, b3] = a.to_be_bytes();
    u32::from_be_bytes([
        SBOX[usize::from(b0)],
        SBOX[usize::from(b1)],
        SBOX[usize::from(b2)],
        SBOX[usize::from(b3)],
    ])
}

/// Reads the block as four big-endian words.
// Go: github.com/tjfoc/gmsm@v1.4.1 sm4/sm4.go:permuteInitialBlock()
#[inline(always)]
fn permute_initial_block(block: &[u8; BLOCK_SIZE]) -> [u32; 4] {
    let (w, _) = block.as_chunks::<4>();
    [
        u32::from_be_bytes(w[0]),
        u32::from_be_bytes(w[1]),
        u32::from_be_bytes(w[2]),
        u32::from_be_bytes(w[3]),
    ]
}

/// Writes four words into the block, big-endian.
// Go: github.com/tjfoc/gmsm@v1.4.1 sm4/sm4.go:permuteFinalBlock()
#[inline(always)]
fn permute_final_block(block: &mut [u8; BLOCK_SIZE], b: [u32; 4]) {
    let (chunks, _) = block.as_chunks_mut::<4>();
    for (c, w) in chunks.iter_mut().zip(b) {
        *c = w.to_be_bytes();
    }
}

/// `sbox0[x&0xff] ^ sbox1[(x>>8)&0xff] ^ sbox2[(x>>16)&0xff] ^ sbox3[(x>>24)&0xff]`.
#[inline(always)]
fn t(x: u32) -> u32 {
    let [b0, b1, b2, b3] = x.to_le_bytes();
    SBOX_T[0][usize::from(b0)]
        ^ SBOX_T[1][usize::from(b1)]
        ^ SBOX_T[2][usize::from(b2)]
        ^ SBOX_T[3][usize::from(b3)]
}

/// The SM4 block transform, in place.
// Go: github.com/tjfoc/gmsm@v1.4.1 sm4/sm4.go:cryptBlock()
#[inline(always)]
fn crypt_block(subkeys: &[u32; 32], block: &mut [u8; BLOCK_SIZE], decrypt: bool) {
    let mut b = permute_initial_block(block);

    if decrypt {
        for i in 0..8 {
            let s = &subkeys[31 - 4 * i - 3..31 - 4 * i - 3 + 4];
            b[0] ^= t(b[1] ^ b[2] ^ b[3] ^ s[3]);
            b[1] ^= t(b[0] ^ b[2] ^ b[3] ^ s[2]);
            b[2] ^= t(b[0] ^ b[1] ^ b[3] ^ s[1]);
            b[3] ^= t(b[1] ^ b[2] ^ b[0] ^ s[0]);
        }
    } else {
        for i in 0..8 {
            let s = &subkeys[4 * i..4 * i + 4];
            b[0] ^= t(b[1] ^ b[2] ^ b[3] ^ s[0]);
            b[1] ^= t(b[0] ^ b[2] ^ b[3] ^ s[1]);
            b[2] ^= t(b[0] ^ b[1] ^ b[3] ^ s[2]);
            b[3] ^= t(b[1] ^ b[2] ^ b[0] ^ s[3]);
        }
    }
    b.reverse();
    permute_final_block(block, b);
}

/// The key schedule: 32 round keys from the 16-byte key.
// Go: github.com/tjfoc/gmsm@v1.4.1 sm4/sm4.go:generateSubKeys()
fn generate_sub_keys(key: &[u8; BLOCK_SIZE]) -> [u32; 32] {
    let mut subkeys = [0u32; 32];
    let mut b = permute_initial_block(key);
    b[0] ^= FK[0];
    b[1] ^= FK[1];
    b[2] ^= FK[2];
    b[3] ^= FK[3];
    for i in 0..32 {
        subkeys[i] = feistel0(b[0], b[1], b[2], b[3], CK[i]);
        b = [b[1], b[2], b[3], subkeys[i]];
    }
    subkeys
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipher::{BlockCipherEncrypt, KeyInit};
    use proptest::prelude::*;

    fn hex16(s: &str) -> [u8; 16] {
        hex::decode(s).expect("hex").try_into().expect("16 bytes")
    }

    /// The generated tables equal gmsm's literal `sbox0..sbox3` (first row of each).
    // Go: github.com/tjfoc/gmsm@v1.4.1 sm4/sm4.go:sbox0, sbox1, sbox2, sbox3
    #[test]
    fn sbox_tables_match_gmsm_literals() {
        let want: [[u32; 16]; 4] = [
            [
                0xd55b5b8e, 0x924242d0, 0xeaa7a74d, 0xfdfbfb06, 0xcf3333fc, 0xe2878765, 0x3df4f4c9,
                0xb5dede6b, 0x1658584e, 0xb4dada6e, 0x14505044, 0xc10b0bca, 0x28a0a088, 0xf8efef17,
                0x2cb0b09c, 0x05141411,
            ],
            [
                0x5b5b8ed5, 0x4242d092, 0xa7a74dea, 0xfbfb06fd, 0x3333fccf, 0x878765e2, 0xf4f4c93d,
                0xdede6bb5, 0x58584e16, 0xdada6eb4, 0x50504414, 0x0b0bcac1, 0xa0a08828, 0xefef17f8,
                0xb0b09c2c, 0x14141105,
            ],
            [
                0x5b8ed55b, 0x42d09242, 0xa74deaa7, 0xfb06fdfb, 0x33fccf33, 0x8765e287, 0xf4c93df4,
                0xde6bb5de, 0x584e1658, 0xda6eb4da, 0x50441450, 0x0bcac10b, 0xa08828a0, 0xef17f8ef,
                0xb09c2cb0, 0x14110514,
            ],
            [
                0x8ed55b5b, 0xd0924242, 0x4deaa7a7, 0x06fdfbfb, 0xfccf3333, 0x65e28787, 0xc93df4f4,
                0x6bb5dede, 0x4e165858, 0x6eb4dada, 0x44145050, 0xcac10b0b, 0x8828a0a0, 0x17f8efef,
                0x9c2cb0b0, 0x11051414,
            ],
        ];
        for (t, row) in want.iter().enumerate() {
            assert_eq!(&SBOX_T[t][..16], row, "sbox{t}");
        }
    }

    /// GB/T 32907-2016 example 1 (also gmsm sm4_test.go:TestSM4's key and data), and example 2:
    /// the same block encrypted 1,000,000 times.
    #[test]
    fn standard_examples() {
        let key = hex16("0123456789abcdeffedcba9876543210");
        let c = Sm4Cipher::new_cipher(&key).expect("valid");
        let mut b = key;
        c.encrypt(&mut b);
        assert_eq!(hex::encode(b), "681edf34d206965e86b3e94f536e4246");
        c.decrypt(&mut b);
        assert_eq!(b, key);

        for _ in 0..1_000_000 {
            c.encrypt(&mut b);
        }
        assert_eq!(hex::encode(b), "595298c7c6fd271f0402f804c33d3f66");
    }

    // Go: github.com/tjfoc/gmsm@v1.4.1 sm4/sm4_test.go:TestErrKeyLen
    #[test]
    fn errors_match_gmsm() {
        let key = [0u8; 32];
        for len in 0..=key.len() {
            let r = Sm4Cipher::new_cipher(&key[..len]);
            if len == 16 {
                assert!(r.is_ok());
            } else {
                let e = r.expect_err("bad key size");
                assert_eq!(e.to_string(), format!("SM4: invalid key size {len}"));
            }
        }
    }

    #[test]
    fn debug_does_not_leak_key() {
        let c = Sm4Cipher::new_cipher(&[3; 16]).expect("valid");
        assert_eq!(format!("{c:?}"), "Sm4Cipher { .. }");
        assert_eq!(c.block_size(), 16);
    }

    proptest! {
        /// Differential test against RustCrypto `sm4` (an independent implementation).
        #[test]
        fn prop_sm4_matches_rustcrypto(
            key in proptest::array::uniform16(any::<u8>()),
            block in proptest::array::uniform16(any::<u8>()),
        ) {
            let c = Sm4Cipher::new_cipher(&key).expect("valid");
            let r = sm4::Sm4::new_from_slice(&key).expect("valid");
            let mut got = block;
            c.encrypt(&mut got);
            let mut want = block;
            r.encrypt_block((&mut want).into());
            prop_assert_eq!(got, want);
            c.decrypt(&mut got);
            prop_assert_eq!(got, block);
        }
    }
}
