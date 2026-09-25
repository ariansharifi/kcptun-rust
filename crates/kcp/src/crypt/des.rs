//! DES and Triple DES (port of Go's `crypto/des`).
//!
//! Origin and licence: modified port of Go 1.27.1 `crypto/des` (`block.go`, `cipher.go`,
//! `const.go`), Copyright 2010-2011 The Go Authors, BSD-3-Clause (see `NOTICE.md`).
//!
//! kcp-go uses Triple DES (EDE, three keys) for `-crypt 3des`. Like Go, the S-boxes and the P
//! permutation are merged into precomputed `feistelBox` tables (built at compile time here) and
//! the initial/final permutations are done with bit exchanges, so a round is 8 table lookups.
//! RustCrypto's `des` 0.9 computes the permutations bit by bit and is about 5 times slower
//! (plan 02.6, `docs/benchmarks/crypto.md`).
//!
//! As in Go, the table lookups are indexed by secret data (not constant time). Weak keys are
//! accepted, as in Go.

use super::CryptError;
use super::cfb::CfbBlock;

/// The DES block size in bytes.
// Go: crypto/des (go1.27.1) cipher.go:BlockSize
pub const BLOCK_SIZE: usize = 8;

/// An instance of DES encryption: the 16 round subkeys.
// Go: crypto/des (go1.27.1) cipher.go:desCipher
#[derive(Clone)]
pub struct DesCipher {
    subkeys: [u64; 16],
}

impl DesCipher {
    /// Creates a DES cipher. The key must be 8 bytes, otherwise Go's
    /// `crypto/des: invalid key size N`.
    // Go: crypto/des (go1.27.1) cipher.go:NewCipher() (without the FIPS 140-only check)
    pub fn new_cipher(key: &[u8]) -> Result<DesCipher, CryptError> {
        let key = <&[u8; 8]>::try_from(key).map_err(|_| CryptError::KeySize {
            pkg: "des",
            size: key.len(),
        })?;
        Ok(DesCipher::generate_subkeys(key))
    }

    /// Creates the 16 56-bit subkeys from the original key.
    // Go: crypto/des (go1.27.1) block.go:desCipher.generateSubkeys()
    fn generate_subkeys(key_bytes: &[u8; 8]) -> DesCipher {
        // apply PC1 permutation to key
        let key = u64::from_be_bytes(*key_bytes);
        let permuted_key = permute_block(key, &PERMUTED_CHOICE1);

        // rotate halves of permuted key according to the rotation schedule
        let left_rotations = ks_rotate((permuted_key >> 28) as u32);
        let right_rotations = ks_rotate(((permuted_key << 4) as u32) >> 4);

        // generate subkeys
        let mut subkeys = [0u64; 16];
        for (i, subkey) in subkeys.iter_mut().enumerate() {
            // combine halves to form 56-bit input to PC2
            let pc2_input = u64::from(left_rotations[i]) << 28 | u64::from(right_rotations[i]);
            // apply PC2 permutation to 7 byte input
            *subkey = unpack(permute_block(pc2_input, &PERMUTED_CHOICE2));
        }
        DesCipher { subkeys }
    }

    /// The DES block size, 8 bytes.
    // Go: crypto/des (go1.27.1) cipher.go:desCipher.BlockSize()
    pub fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    /// Encrypts one block in place.
    // Go: crypto/des (go1.27.1) cipher.go:desCipher.Encrypt()
    pub fn encrypt(&self, block: &mut [u8; BLOCK_SIZE]) {
        crypt_block(&self.subkeys, block, false);
    }

    /// Decrypts one block in place.
    // Go: crypto/des (go1.27.1) cipher.go:desCipher.Decrypt()
    pub fn decrypt(&self, block: &mut [u8; BLOCK_SIZE]) {
        crypt_block(&self.subkeys, block, true);
    }
}

/// An instance of Triple DES (EDE) encryption.
// Go: crypto/des (go1.27.1) cipher.go:tripleDESCipher
#[derive(Clone)]
pub struct TripleDesCipher {
    cipher1: DesCipher,
    cipher2: DesCipher,
    cipher3: DesCipher,
}

impl TripleDesCipher {
    /// Creates a Triple DES cipher from `k1 | k2 | k3`. The key must be 24 bytes, otherwise Go's
    /// `crypto/des: invalid key size N`.
    // Go: crypto/des (go1.27.1) cipher.go:NewTripleDESCipher() (without the FIPS 140-only check)
    pub fn new_triple_des_cipher(key: &[u8]) -> Result<TripleDesCipher, CryptError> {
        let key = <&[u8; 24]>::try_from(key).map_err(|_| CryptError::KeySize {
            pkg: "des",
            size: key.len(),
        })?;
        let (keys, _) = key.as_chunks::<8>();
        Ok(TripleDesCipher {
            cipher1: DesCipher::generate_subkeys(&keys[0]),
            cipher2: DesCipher::generate_subkeys(&keys[1]),
            cipher3: DesCipher::generate_subkeys(&keys[2]),
        })
    }

    /// The DES block size, 8 bytes.
    // Go: crypto/des (go1.27.1) cipher.go:tripleDESCipher.BlockSize()
    pub fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    /// Encrypts one block in place: encrypt with k1, decrypt with k2, encrypt with k3, with the
    /// initial and final permutations applied once.
    // Go: crypto/des (go1.27.1) cipher.go:tripleDESCipher.Encrypt()
    #[inline]
    pub fn encrypt(&self, block: &mut [u8; BLOCK_SIZE]) {
        let b = permute_initial_block(u64::from_be_bytes(*block));
        let (mut left, mut right) = ((b >> 32) as u32, b as u32);

        left = left.rotate_left(1);
        right = right.rotate_left(1);

        let (k1, k2, k3) = (
            &self.cipher1.subkeys,
            &self.cipher2.subkeys,
            &self.cipher3.subkeys,
        );
        for i in 0..8 {
            (left, right) = feistel(left, right, k1[2 * i], k1[2 * i + 1]);
        }
        for i in 0..8 {
            (right, left) = feistel(right, left, k2[15 - 2 * i], k2[15 - (2 * i + 1)]);
        }
        for i in 0..8 {
            (left, right) = feistel(left, right, k3[2 * i], k3[2 * i + 1]);
        }

        left = left.rotate_right(1);
        right = right.rotate_right(1);

        let pre_output = u64::from(right) << 32 | u64::from(left);
        *block = permute_final_block(pre_output).to_be_bytes();
    }

    /// Decrypts one block in place.
    // Go: crypto/des (go1.27.1) cipher.go:tripleDESCipher.Decrypt()
    pub fn decrypt(&self, block: &mut [u8; BLOCK_SIZE]) {
        let b = permute_initial_block(u64::from_be_bytes(*block));
        let (mut left, mut right) = ((b >> 32) as u32, b as u32);

        left = left.rotate_left(1);
        right = right.rotate_left(1);

        let (k1, k2, k3) = (
            &self.cipher1.subkeys,
            &self.cipher2.subkeys,
            &self.cipher3.subkeys,
        );
        for i in 0..8 {
            (left, right) = feistel(left, right, k3[15 - 2 * i], k3[15 - (2 * i + 1)]);
        }
        for i in 0..8 {
            (right, left) = feistel(right, left, k2[2 * i], k2[2 * i + 1]);
        }
        for i in 0..8 {
            (left, right) = feistel(left, right, k1[15 - 2 * i], k1[15 - (2 * i + 1)]);
        }

        left = left.rotate_right(1);
        right = right.rotate_right(1);

        let pre_output = u64::from(right) << 32 | u64::from(left);
        *block = permute_final_block(pre_output).to_be_bytes();
    }
}

impl std::fmt::Debug for DesCipher {
    // The key schedule is secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DesCipher { .. }")
    }
}

impl std::fmt::Debug for TripleDesCipher {
    // The key schedule is secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TripleDesCipher { .. }")
    }
}

impl CfbBlock<BLOCK_SIZE> for TripleDesCipher {
    #[inline(always)]
    fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        self.encrypt(block);
    }
}

/// Single DES on one block, in place.
// Go: crypto/des (go1.27.1) block.go:cryptBlock()
fn crypt_block(subkeys: &[u64; 16], block: &mut [u8; BLOCK_SIZE], decrypt: bool) {
    let b = permute_initial_block(u64::from_be_bytes(*block));
    let (mut left, mut right) = ((b >> 32) as u32, b as u32);

    left = left.rotate_left(1);
    right = right.rotate_left(1);

    if decrypt {
        for i in 0..8 {
            (left, right) = feistel(left, right, subkeys[15 - 2 * i], subkeys[15 - (2 * i + 1)]);
        }
    } else {
        for i in 0..8 {
            (left, right) = feistel(left, right, subkeys[2 * i], subkeys[2 * i + 1]);
        }
    }

    left = left.rotate_right(1);
    right = right.rotate_right(1);

    // switch left & right and perform final permutation
    let pre_output = u64::from(right) << 32 | u64::from(left);
    *block = permute_final_block(pre_output).to_be_bytes();
}

/// Two DES rounds (the Feistel function applied to each half in turn).
// Go: crypto/des (go1.27.1) block.go:feistel()
#[inline(always)]
fn feistel(mut l: u32, mut r: u32, k0: u64, k1: u64) -> (u32, u32) {
    let fb = &FEISTEL_BOX;
    let sb = |s: usize, t: u32| fb[s][(t & 0x3f) as usize];

    let t = r ^ (k0 >> 32) as u32;
    l ^= sb(7, t) ^ sb(5, t >> 8) ^ sb(3, t >> 16) ^ sb(1, t >> 24);

    let t = r.rotate_left(28) ^ k0 as u32;
    l ^= sb(6, t) ^ sb(4, t >> 8) ^ sb(2, t >> 16) ^ sb(0, t >> 24);

    let t = l ^ (k1 >> 32) as u32;
    r ^= sb(7, t) ^ sb(5, t >> 8) ^ sb(3, t >> 16) ^ sb(1, t >> 24);

    let t = l.rotate_left(28) ^ k1 as u32;
    r ^= sb(6, t) ^ sb(4, t >> 8) ^ sb(2, t >> 16) ^ sb(0, t >> 24);

    (l, r)
}

/// `FEISTEL_BOX[s][16*i+j]` contains the output of `PERMUTATION_FUNCTION` for
/// `S_BOXES[s][i][j] << 4*(7-s)`. Go fills it once at run time (`feistelBoxOnce`); here it is
/// computed at compile time with the same code.
// Go: crypto/des (go1.27.1) block.go:feistelBox
static FEISTEL_BOX: [[u32; 64]; 8] = init_feistel_box();

/// General purpose function to perform DES block permutations.
// Go: crypto/des (go1.27.1) block.go:permuteBlock()
const fn permute_block(src: u64, permutation: &[u8]) -> u64 {
    let mut block = 0u64;
    let mut position = 0;
    while position < permutation.len() {
        let bit = (src >> permutation[position]) & 1;
        block |= bit << ((permutation.len() - 1) - position);
        position += 1;
    }
    block
}

// Go: crypto/des (go1.27.1) block.go:initFeistelBox()
const fn init_feistel_box() -> [[u32; 64]; 8] {
    let mut feistel_box = [[0u32; 64]; 8];
    let mut s = 0;
    while s < S_BOXES.len() {
        let mut i = 0;
        while i < 4 {
            let mut j = 0;
            while j < 16 {
                let mut f = (S_BOXES[s][i][j] as u64) << (4 * (7 - s));
                f = permute_block(f, &PERMUTATION_FUNCTION);

                // Row is determined by the 1st and 6th bit.
                // Column is the middle four bits.
                let row = (((i & 2) << 4) | (i & 1)) as u8;
                let col = (j << 1) as u8;
                let t = row | col;

                // The rotation was performed in the feistel rounds, being factored out and now
                // mixed into the feistelBox.
                f = (f << 1) | (f >> 31);

                feistel_box[s][t as usize] = f as u32;
                j += 1;
            }
            i += 1;
        }
        s += 1;
    }
    feistel_box
}

/// Equivalent to the permutation defined by `INITIAL_PERMUTATION`.
// Go: crypto/des (go1.27.1) block.go:permuteInitialBlock()
#[inline(always)]
fn permute_initial_block(mut block: u64) -> u64 {
    // block = b7 b6 b5 b4 b3 b2 b1 b0 (8 bytes)
    let mut b1 = block >> 48;
    let mut b2 = block << 48;
    block ^= b1 ^ b2 ^ b1 << 48 ^ b2 >> 48;

    // block = b1 b0 b5 b4 b3 b2 b7 b6
    b1 = block >> 32 & 0xff00ff;
    b2 = block & 0xff00ff00;
    block ^= b1 << 32 ^ b2 ^ b1 << 8 ^ b2 << 24; // exchange b0 b4 with b3 b7

    // exchange 4,5,6,7 with 32,33,34,35 etc.
    b1 = block & 0x0f0f00000f0f0000;
    b2 = block & 0x0000f0f00000f0f0;
    block ^= b1 ^ b2 ^ b1 >> 12 ^ b2 << 12;

    // exchange 0,1,4,5 with 18,19,22,23
    b1 = block & 0x3300330033003300;
    b2 = block & 0x00cc00cc00cc00cc;
    block ^= b1 ^ b2 ^ b1 >> 6 ^ b2 << 6;

    // exchange 0,2,4,6 with 9,11,13,15:
    b1 = block & 0xaaaaaaaa55555555;
    block ^= b1 ^ b1 >> 33 ^ b1 << 33;

    block
}

/// Equivalent to the permutation defined by `FINAL_PERMUTATION`.
// Go: crypto/des (go1.27.1) block.go:permuteFinalBlock()
#[inline(always)]
fn permute_final_block(mut block: u64) -> u64 {
    // Perform the same bit exchanges as permuteInitialBlock
    // but in reverse order.
    let mut b1 = block & 0xaaaaaaaa55555555;
    block ^= b1 ^ b1 >> 33 ^ b1 << 33;

    b1 = block & 0x3300330033003300;
    let mut b2 = block & 0x00cc00cc00cc00cc;
    block ^= b1 ^ b2 ^ b1 >> 6 ^ b2 << 6;

    b1 = block & 0x0f0f00000f0f0000;
    b2 = block & 0x0000f0f00000f0f0;
    block ^= b1 ^ b2 ^ b1 >> 12 ^ b2 << 12;

    b1 = block >> 32 & 0xff00ff;
    b2 = block & 0xff00ff00;
    block ^= b1 << 32 ^ b2 ^ b1 << 8 ^ b2 << 24;

    b1 = block >> 48;
    b2 = block << 48;
    block ^= b1 ^ b2 ^ b1 << 48 ^ b2 >> 48;
    block
}

/// Creates 16 28-bit blocks rotated according to the rotation schedule.
// Go: crypto/des (go1.27.1) block.go:ksRotate()
fn ks_rotate(input: u32) -> [u32; 16] {
    let mut out = [0u32; 16];
    let mut last = input;
    for (o, &rot) in out.iter_mut().zip(&KS_ROTATIONS) {
        // 28-bit circular left shift
        let left = (last << (4 + u32::from(rot))) >> 4;
        let right = (last << 4) >> (32 - u32::from(rot));
        *o = left | right;
        last = *o;
    }
    out
}

/// Expands the 48-bit input to 64 bits, with each 6-bit block padded by two extra bits at the
/// top, so the input blocks (four bits each) and the key blocks (six bits each) are aligned
/// without extra shifts.
// Go: crypto/des (go1.27.1) block.go:unpack()
fn unpack(x: u64) -> u64 {
    ((x >> 6) & 0xff)
        | ((x >> (6 * 3)) & 0xff) << 8
        | ((x >> (6 * 5)) & 0xff) << (8 * 2)
        | ((x >> (6 * 7)) & 0xff) << (8 * 3)
        | (x & 0xff) << (8 * 4)
        | ((x >> (6 * 2)) & 0xff) << (8 * 5)
        | ((x >> (6 * 4)) & 0xff) << (8 * 6)
        | ((x >> (6 * 6)) & 0xff) << (8 * 7)
}
/// Used to perform an initial permutation of a 64-bit input block.
// Go: crypto/des (go1.27.1) const.go:initialPermutation
#[cfg_attr(not(test), allow(dead_code, reason = "used by the permutation tests"))]
#[rustfmt::skip]
const INITIAL_PERMUTATION: [u8; 64] = [
    6, 14, 22, 30, 38, 46, 54, 62,
    4, 12, 20, 28, 36, 44, 52, 60,
    2, 10, 18, 26, 34, 42, 50, 58,
    0, 8, 16, 24, 32, 40, 48, 56,
    7, 15, 23, 31, 39, 47, 55, 63,
    5, 13, 21, 29, 37, 45, 53, 61,
    3, 11, 19, 27, 35, 43, 51, 59,
    1, 9, 17, 25, 33, 41, 49, 57,
];

/// Used to perform a final permutation of a 64-bit preoutput block. This is the inverse
/// of `INITIAL_PERMUTATION`.
// Go: crypto/des (go1.27.1) const.go:finalPermutation
#[cfg_attr(not(test), allow(dead_code, reason = "used by the permutation tests"))]
#[rustfmt::skip]
const FINAL_PERMUTATION: [u8; 64] = [
    24, 56, 16, 48, 8, 40, 0, 32,
    25, 57, 17, 49, 9, 41, 1, 33,
    26, 58, 18, 50, 10, 42, 2, 34,
    27, 59, 19, 51, 11, 43, 3, 35,
    28, 60, 20, 52, 12, 44, 4, 36,
    29, 61, 21, 53, 13, 45, 5, 37,
    30, 62, 22, 54, 14, 46, 6, 38,
    31, 63, 23, 55, 15, 47, 7, 39,
];

/// Yields a 32-bit output from a 32-bit input.
// Go: crypto/des (go1.27.1) const.go:permutationFunction
#[rustfmt::skip]
const PERMUTATION_FUNCTION: [u8; 32] = [
    16, 25, 12, 11, 3, 20, 4, 15,
    31, 17, 9, 6, 27, 14, 1, 22,
    30, 24, 8, 18, 0, 5, 29, 23,
    13, 19, 2, 26, 10, 21, 28, 7,
];

/// Used in the key schedule to select 56 bits from a 64-bit input.
// Go: crypto/des (go1.27.1) const.go:permutedChoice1
#[rustfmt::skip]
const PERMUTED_CHOICE1: [u8; 56] = [
    7, 15, 23, 31, 39, 47, 55, 63,
    6, 14, 22, 30, 38, 46, 54, 62,
    5, 13, 21, 29, 37, 45, 53, 61,
    4, 12, 20, 28, 1, 9, 17, 25,
    33, 41, 49, 57, 2, 10, 18, 26,
    34, 42, 50, 58, 3, 11, 19, 27,
    35, 43, 51, 59, 36, 44, 52, 60,
];

/// Used in the key schedule to produce each subkey by selecting 48 bits from the 56-bit
/// input.
// Go: crypto/des (go1.27.1) const.go:permutedChoice2
#[rustfmt::skip]
const PERMUTED_CHOICE2: [u8; 48] = [
    42, 39, 45, 32, 55, 51, 53, 28,
    41, 50, 35, 46, 33, 37, 44, 52,
    30, 48, 40, 49, 29, 36, 43, 54,
    15, 4, 25, 19, 9, 1, 26, 16,
    5, 11, 23, 8, 12, 7, 17, 0,
    22, 3, 10, 14, 6, 20, 27, 24,
];

/// 8 S-boxes composed of 4 rows and 16 columns, used in the DES cipher function.
// Go: crypto/des (go1.27.1) const.go:sBoxes
#[rustfmt::skip]
const S_BOXES: [[[u8; 16]; 4]; 8] = [
    // S-box 1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    // S-box 2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    // S-box 3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    // S-box 4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    // S-box 5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    // S-box 6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    // S-box 7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    // S-box 8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
];

/// Size of left rotation per round in each half of the key schedule.
// Go: crypto/des (go1.27.1) const.go:ksRotations
const KS_ROTATIONS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

#[cfg(test)]
mod tests {
    use super::*;
    use cipher::{BlockCipherEncrypt, KeyInit};
    use proptest::prelude::*;

    fn hex8(s: &str) -> [u8; 8] {
        hex::decode(s).expect("hex").try_into().expect("8 bytes")
    }

    /// Go: crypto/des (go1.27.1) des_test.go:encryptDESTests
    const ENCRYPT_DES_TESTS: [(&str, &str, &str); 27] = [
        ("0000000000000000", "0000000000000000", "8ca64de9c1b123a7"),
        ("0000000000000000", "ffffffffffffffff", "355550b2150e2451"),
        ("0000000000000000", "0123456789abcdef", "617b3a0ce8f07100"),
        ("0000000000000000", "fedcba9876543210", "9231f236ff9aa95c"),
        ("ffffffffffffffff", "0000000000000000", "caaaaf4deaf1dbae"),
        ("ffffffffffffffff", "ffffffffffffffff", "7359b2163e4edc58"),
        ("ffffffffffffffff", "0123456789abcdef", "6dce0dc9006556a3"),
        ("ffffffffffffffff", "fedcba9876543210", "9e84c5f3170f8eff"),
        ("0123456789abcdef", "0000000000000000", "d5d44ff720683d0d"),
        ("0123456789abcdef", "ffffffffffffffff", "59732356f36fde06"),
        ("0123456789abcdef", "0123456789abcdef", "56cc09e7cfdc4cef"),
        ("0123456789abcdef", "fedcba9876543210", "12c626af058b433b"),
        ("fedcba9876543210", "0000000000000000", "a68cdca90c9021f9"),
        ("fedcba9876543210", "ffffffffffffffff", "2a2bb008df97c2f2"),
        ("fedcba9876543210", "0123456789abcdef", "ed39d950fa74bcc4"),
        ("fedcba9876543210", "fedcba9876543210", "a933f6183023b310"),
        ("0123456789abcdef", "1111111111111111", "17668dfc7292532d"),
        ("0123456789abcdef", "0101010101010101", "b4fd231647a5bec0"),
        ("0e329232ea6d0d73", "8787878787878787", "0000000000000000"),
        ("736563523374243b", "6120746573743132", "370dee2c1fb4f7a5"),
        ("6162636465666768", "6162636465666768", "2a8d69de9d5fdff9"),
        ("6162636465666768", "3132333435363738", "21c60da534248bce"),
        ("3132333435363738", "6162636465666768", "94d4436bc3b5b693"),
        ("1f79905f8801c888", "c7461873af485fb3", "b0935088f992446a"),
        ("e6f4f2db31425301", "ff3d255012e34ac5", "8608d3d16c2fd255"),
        ("69c19dc115c5fb2b", "1a225caf1f1da3f9", "64ba316756911ea7"),
        ("6e5ee247c4bff651", "11c957ff66890ef0", "94c535b2c58b3972"),
    ];
    /// Go: crypto/des (go1.27.1) des_test.go:encryptTripleDESTests
    const ENCRYPT_TRIPLE_DES_TESTS: [(&str, &str, &str); 9] = [
        (
            "0000000000000000ffffffffffffffff0000000000000000",
            "0000000000000000",
            "9295b59bb384736e",
        ),
        (
            "0000000000000000ffffffffffffffff0000000000000000",
            "ffffffffffffffff",
            "c197f558748a20e7",
        ),
        (
            "ffffffffffffffff0000000000000000ffffffffffffffff",
            "0000000000000000",
            "3e680aa78b75df18",
        ),
        (
            "ffffffffffffffff0000000000000000ffffffffffffffff",
            "ffffffffffffffff",
            "6d6a4a644c7b8c91",
        ),
        (
            "616263646566676831323334353637384142434445464748",
            "3030303030303030",
            "e461b759688bff66",
        ),
        (
            "616263646566676831323334353637384142434445464748",
            "3132333435363738",
            "dbd092def834ff58",
        ),
        (
            "616263646566676831323334353637384142434445464748",
            "f0c58222d3e612d2",
            "bae441b13c374df4",
        ),
        (
            "d37d45ee22e9cf52f465a24f70d1818a3dbe2f39c771d2e9",
            "4953c3e978df9faf",
            "53405124d83cf988",
        ),
        (
            "cb107dda7e96570ae8ebe8078e87d357b26112b82a90b72f",
            "a3c260b10bb7286e",
            "56737dfbb5a1c3de",
        ),
    ];

    // Go: crypto/des (go1.27.1) des_test.go:TestDESEncryptBlock, TestDESDecryptBlock
    #[test]
    fn test_des_encrypt_decrypt_block() {
        for (i, (key, input, output)) in ENCRYPT_DES_TESTS.iter().enumerate() {
            let c = DesCipher::new_cipher(&hex::decode(key).expect("hex")).expect("valid");
            let mut b = hex8(input);
            c.encrypt(&mut b);
            assert_eq!(hex::encode(b), *output, "#{i}");
            c.decrypt(&mut b);
            assert_eq!(hex::encode(b), *input, "#{i}");
        }
    }

    // Go: crypto/des (go1.27.1) des_test.go:TestEncryptTripleDES, TestDecryptTripleDES
    #[test]
    fn test_encrypt_decrypt_triple_des() {
        for (i, (key, input, output)) in ENCRYPT_TRIPLE_DES_TESTS.iter().enumerate() {
            let key = hex::decode(key).expect("hex");
            let c = TripleDesCipher::new_triple_des_cipher(&key).expect("valid");
            let mut b = hex8(input);
            c.encrypt(&mut b);
            assert_eq!(hex::encode(b), *output, "#{i}");
            c.decrypt(&mut b);
            assert_eq!(hex::encode(b), *input, "#{i}");
        }
    }

    // Go: crypto/des (go1.27.1) internal_test.go:TestInitialPermute, TestFinalPermute
    #[test]
    fn test_initial_and_final_permute() {
        for i in 0..64 {
            let bit = 1u64 << i;
            assert_eq!(
                permute_initial_block(bit),
                1u64 << FINAL_PERMUTATION[63 - i],
                "initial {i}"
            );
            assert_eq!(
                permute_final_block(bit),
                1u64 << INITIAL_PERMUTATION[63 - i],
                "final {i}"
            );
        }
    }

    #[test]
    fn errors_match_go() {
        let key = [0u8; 32];
        for len in 0..=key.len() {
            let r = TripleDesCipher::new_triple_des_cipher(&key[..len]);
            if len == 24 {
                assert!(r.is_ok());
            } else {
                let e = r.expect_err("bad key size");
                assert_eq!(e.to_string(), format!("crypto/des: invalid key size {len}"));
            }
            let r = DesCipher::new_cipher(&key[..len]);
            assert_eq!(r.is_ok(), len == 8, "len {len}");
        }
    }

    #[test]
    fn debug_does_not_leak_key() {
        let c = TripleDesCipher::new_triple_des_cipher(&[7; 24]).expect("valid");
        assert_eq!(format!("{c:?}"), "TripleDesCipher { .. }");
        assert_eq!(c.block_size(), 8);
        let d = DesCipher::new_cipher(&[7; 8]).expect("valid");
        assert_eq!(format!("{d:?}"), "DesCipher { .. }");
        assert_eq!(d.block_size(), 8);
    }

    proptest! {
        /// Differential test against RustCrypto `des` (an independent implementation).
        #[test]
        fn prop_triple_des_matches_rustcrypto(
            key in proptest::collection::vec(any::<u8>(), 24),
            block in proptest::array::uniform8(any::<u8>()),
        ) {
            let c = TripleDesCipher::new_triple_des_cipher(&key).expect("valid");
            let r = des::TdesEde3::new_from_slice(&key).expect("valid");
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
