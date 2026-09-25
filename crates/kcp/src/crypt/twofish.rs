//! Twofish block cipher (port of `golang.org/x/crypto/twofish`).
//!
//! Origin and licence: modified port of `golang.org/x/crypto` v0.47.0 `twofish/twofish.go`,
//! Copyright 2011 The Go Authors, BSD-3-Clause (see `NOTICE.md`).
//!
//! kcp-go uses it for `-crypt twofish` with a 32-byte key. Like x/crypto (a port of the
//! LibTomCrypt code), the key-dependent S-boxes are fully precomputed with the MDS matrix folded
//! in (`s[4][256]`), so a round is 8 table lookups. RustCrypto's `twofish` 0.8 evaluates the
//! S-boxes per block and is about 40 times slower (plan 02.6, `docs/benchmarks/crypto.md`).
//!
//! As in Go, the table lookups are indexed by secret data (not constant time).

use super::CryptError;
use super::cfb::CfbBlock;

/// The block size of Twofish, in bytes.
// Go: golang.org/x/crypto/twofish@v0.47.0 twofish.go:BlockSize
pub const BLOCK_SIZE: usize = 16;

/// `x^8 + x^6 + x^5 + x^3 + 1`, see [TWOFISH] 4.2.
// Go: golang.org/x/crypto/twofish@v0.47.0 twofish.go:mdsPolynomial
const MDS_POLYNOMIAL: u32 = 0x169;
/// `x^8 + x^6 + x^3 + x^2 + 1`, see [TWOFISH] 4.3.
// Go: golang.org/x/crypto/twofish@v0.47.0 twofish.go:rsPolynomial
const RS_POLYNOMIAL: u32 = 0x14d;

/// An instance of Twofish encryption using a particular key.
// Go: golang.org/x/crypto/twofish@v0.47.0 twofish.go:Cipher
#[derive(Clone)]
pub struct Cipher {
    /// Key-dependent S-boxes combined with the MDS matrix.
    s: [[u32; 256]; 4],
    /// The 40 round subkeys (whitening and round keys).
    k: [u32; 40],
}

impl Cipher {
    /// Creates a Twofish cipher. The key must be 16, 24 or 32 bytes, otherwise Go's
    /// `crypto/twofish: invalid key size N`. Boxed: the cipher is about 4 KiB.
    // Go: golang.org/x/crypto/twofish@v0.47.0 twofish.go:NewCipher()
    pub fn new_cipher(key: &[u8]) -> Result<Box<Cipher>, CryptError> {
        let keylen = key.len();

        if keylen != 16 && keylen != 24 && keylen != 32 {
            return Err(CryptError::KeySize {
                pkg: "twofish",
                size: keylen,
            });
        }

        // k is the number of 64 bit words in key
        let k = keylen / 8;

        // Create the S[..] words
        let mut s_words = [0u8; 4 * 4];
        for i in 0..k {
            // Computes [y0 y1 y2 y3] = rs . [x0 x1 x2 x3 x4 x5 x6 x7]
            for (j, rs_row) in RS.iter().enumerate() {
                for (k, &rs_val) in rs_row.iter().enumerate() {
                    s_words[4 * i + j] ^= gf_mult(key[8 * i + k], rs_val, RS_POLYNOMIAL);
                }
            }
        }
        let s = &s_words;

        // Calculate subkeys
        let mut c = Box::new(Cipher {
            s: [[0; 256]; 4],
            k: [0; 40],
        });
        for i in 0..20u8 {
            // A = h(p * 2x, Me)
            let a = h(&[2 * i; 4], key, 0);

            // B = rolc(h(p * (2x + 1), Mo), 8)
            let b = h(&[2 * i + 1; 4], key, 1).rotate_left(8);

            let i = usize::from(i);
            c.k[2 * i] = a.wrapping_add(b);

            // K[2i+1] = (A + 2B) <<< 9
            c.k[2 * i + 1] = b.wrapping_mul(2).wrapping_add(a).rotate_left(9);
        }

        // Calculate sboxes
        let q = |t: usize, x: u8| SBOX[t][usize::from(x)];
        match k {
            2 => {
                for i in 0..256 {
                    let x = i as u8;
                    c.s[0][i] = mds_column_mult(q(1, q(0, q(0, x) ^ s[0]) ^ s[4]), 0);
                    c.s[1][i] = mds_column_mult(q(0, q(0, q(1, x) ^ s[1]) ^ s[5]), 1);
                    c.s[2][i] = mds_column_mult(q(1, q(1, q(0, x) ^ s[2]) ^ s[6]), 2);
                    c.s[3][i] = mds_column_mult(q(0, q(1, q(1, x) ^ s[3]) ^ s[7]), 3);
                }
            }
            3 => {
                for i in 0..256 {
                    let x = i as u8;
                    c.s[0][i] = mds_column_mult(q(1, q(0, q(0, q(1, x) ^ s[0]) ^ s[4]) ^ s[8]), 0);
                    c.s[1][i] = mds_column_mult(q(0, q(0, q(1, q(1, x) ^ s[1]) ^ s[5]) ^ s[9]), 1);
                    c.s[2][i] = mds_column_mult(q(1, q(1, q(0, q(0, x) ^ s[2]) ^ s[6]) ^ s[10]), 2);
                    c.s[3][i] = mds_column_mult(q(0, q(1, q(1, q(0, x) ^ s[3]) ^ s[7]) ^ s[11]), 3);
                }
            }
            _ => {
                for i in 0..256 {
                    let x = i as u8;
                    c.s[0][i] = mds_column_mult(
                        q(1, q(0, q(0, q(1, q(1, x) ^ s[0]) ^ s[4]) ^ s[8]) ^ s[12]),
                        0,
                    );
                    c.s[1][i] = mds_column_mult(
                        q(0, q(0, q(1, q(1, q(0, x) ^ s[1]) ^ s[5]) ^ s[9]) ^ s[13]),
                        1,
                    );
                    c.s[2][i] = mds_column_mult(
                        q(1, q(1, q(0, q(0, q(0, x) ^ s[2]) ^ s[6]) ^ s[10]) ^ s[14]),
                        2,
                    );
                    c.s[3][i] = mds_column_mult(
                        q(0, q(1, q(1, q(0, q(1, x) ^ s[3]) ^ s[7]) ^ s[11]) ^ s[15]),
                        3,
                    );
                }
            }
        }

        Ok(c)
    }

    /// The Twofish block size, 16 bytes.
    // Go: golang.org/x/crypto/twofish@v0.47.0 twofish.go:Cipher.BlockSize()
    pub fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    /// `S2[b0] ^ S3[b1] ^ S4[b2] ^ S1[b3]` of Go's round (the `t2` lookups).
    #[inline(always)]
    fn g1(&self, x: u32) -> u32 {
        let [b0, b1, b2, b3] = x.to_le_bytes();
        self.s[1][usize::from(b0)]
            ^ self.s[2][usize::from(b1)]
            ^ self.s[3][usize::from(b2)]
            ^ self.s[0][usize::from(b3)]
    }

    /// `S1[b0] ^ S2[b1] ^ S3[b2] ^ S4[b3]` of Go's round (the `t1` lookups).
    #[inline(always)]
    fn g0(&self, x: u32) -> u32 {
        let [b0, b1, b2, b3] = x.to_le_bytes();
        self.s[0][usize::from(b0)]
            ^ self.s[1][usize::from(b1)]
            ^ self.s[2][usize::from(b2)]
            ^ self.s[3][usize::from(b3)]
    }

    /// Encrypts one 16-byte block in place.
    // Go: golang.org/x/crypto/twofish@v0.47.0 twofish.go:Cipher.Encrypt()
    #[inline]
    pub fn encrypt(&self, block: &mut [u8; BLOCK_SIZE]) {
        // Load input
        let [mut ia, mut ib, mut ic, mut id] = load32l(block);

        // Pre-whitening
        ia ^= self.k[0];
        ib ^= self.k[1];
        ic ^= self.k[2];
        id ^= self.k[3];

        for i in 0..8 {
            let k = &self.k[8 + i * 4..12 + i * 4];
            // Go: `S1[..] ^ S2[..] ^ S3[..] ^ S4[..] + t2` evaluates left to right (`^` and `+`
            // have the same precedence in Go), i.e. `(S1 ^ S2 ^ S3 ^ S4) + t2`.
            let t2 = self.g1(ib);
            let t1 = self.g0(ia).wrapping_add(t2);
            ic = (ic ^ t1.wrapping_add(k[0])).rotate_right(1);
            id = id.rotate_left(1) ^ t2.wrapping_add(t1).wrapping_add(k[1]);

            let t2 = self.g1(id);
            let t1 = self.g0(ic).wrapping_add(t2);
            ia = (ia ^ t1.wrapping_add(k[2])).rotate_right(1);
            ib = ib.rotate_left(1) ^ t2.wrapping_add(t1).wrapping_add(k[3]);
        }

        // Output with "undo last swap"
        let ta = ic ^ self.k[4];
        let tb = id ^ self.k[5];
        let tc = ia ^ self.k[6];
        let td = ib ^ self.k[7];

        store32l(block, [ta, tb, tc, td]);
    }

    /// Decrypts one 16-byte block in place.
    // Go: golang.org/x/crypto/twofish@v0.47.0 twofish.go:Cipher.Decrypt()
    pub fn decrypt(&self, block: &mut [u8; BLOCK_SIZE]) {
        // Load input
        let [ta, tb, tc, td] = load32l(block);

        // Undo undo final swap
        let mut ia = tc ^ self.k[6];
        let mut ib = td ^ self.k[7];
        let mut ic = ta ^ self.k[4];
        let mut id = tb ^ self.k[5];

        for i in (1..=8).rev() {
            let k = &self.k[4 + i * 4..8 + i * 4];
            let t2 = self.g1(id);
            let t1 = self.g0(ic).wrapping_add(t2);
            ia = ia.rotate_left(1) ^ t1.wrapping_add(k[2]);
            ib = (ib ^ t2.wrapping_add(t1).wrapping_add(k[3])).rotate_right(1);

            let t2 = self.g1(ib);
            let t1 = self.g0(ia).wrapping_add(t2);
            ic = ic.rotate_left(1) ^ t1.wrapping_add(k[0]);
            id = (id ^ t2.wrapping_add(t1).wrapping_add(k[1])).rotate_right(1);
        }

        // Undo pre-whitening
        ia ^= self.k[0];
        ib ^= self.k[1];
        ic ^= self.k[2];
        id ^= self.k[3];

        store32l(block, [ia, ib, ic, id]);
    }
}

impl std::fmt::Debug for Cipher {
    // The key schedule is secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Twofish { .. }")
    }
}

impl CfbBlock<BLOCK_SIZE> for Cipher {
    #[inline(always)]
    fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
        self.encrypt(block);
    }
}

/// Reads the block as four little-endian words.
// Go: golang.org/x/crypto/twofish@v0.47.0 twofish.go:load32l()
#[inline(always)]
fn load32l(block: &[u8; BLOCK_SIZE]) -> [u32; 4] {
    let (words, _) = block.as_chunks::<4>();
    [
        u32::from_le_bytes(words[0]),
        u32::from_le_bytes(words[1]),
        u32::from_le_bytes(words[2]),
        u32::from_le_bytes(words[3]),
    ]
}

/// Stores four words into the block in little-endian form.
// Go: golang.org/x/crypto/twofish@v0.47.0 twofish.go:store32l()
#[inline(always)]
fn store32l(block: &mut [u8; BLOCK_SIZE], words: [u32; 4]) {
    let (chunks, _) = block.as_chunks_mut::<4>();
    for (c, w) in chunks.iter_mut().zip(words) {
        *c = w.to_le_bytes();
    }
}

/// The RS matrix. See [TWOFISH] 4.3.
// Go: golang.org/x/crypto/twofish@v0.47.0 twofish.go:rs
const RS: [[u8; 8]; 4] = [
    [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
    [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
    [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
    [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03],
];

/// The fixed permutations q0 and q1.
// Go: golang.org/x/crypto/twofish@v0.47.0 twofish.go:sbox
#[rustfmt::skip]
const SBOX: [[u8; 256]; 2] = [
    [
        0xa9, 0x67, 0xb3, 0xe8, 0x04, 0xfd, 0xa3, 0x76, 0x9a, 0x92, 0x80, 0x78, 0xe4, 0xdd, 0xd1, 0x38,
        0x0d, 0xc6, 0x35, 0x98, 0x18, 0xf7, 0xec, 0x6c, 0x43, 0x75, 0x37, 0x26, 0xfa, 0x13, 0x94, 0x48,
        0xf2, 0xd0, 0x8b, 0x30, 0x84, 0x54, 0xdf, 0x23, 0x19, 0x5b, 0x3d, 0x59, 0xf3, 0xae, 0xa2, 0x82,
        0x63, 0x01, 0x83, 0x2e, 0xd9, 0x51, 0x9b, 0x7c, 0xa6, 0xeb, 0xa5, 0xbe, 0x16, 0x0c, 0xe3, 0x61,
        0xc0, 0x8c, 0x3a, 0xf5, 0x73, 0x2c, 0x25, 0x0b, 0xbb, 0x4e, 0x89, 0x6b, 0x53, 0x6a, 0xb4, 0xf1,
        0xe1, 0xe6, 0xbd, 0x45, 0xe2, 0xf4, 0xb6, 0x66, 0xcc, 0x95, 0x03, 0x56, 0xd4, 0x1c, 0x1e, 0xd7,
        0xfb, 0xc3, 0x8e, 0xb5, 0xe9, 0xcf, 0xbf, 0xba, 0xea, 0x77, 0x39, 0xaf, 0x33, 0xc9, 0x62, 0x71,
        0x81, 0x79, 0x09, 0xad, 0x24, 0xcd, 0xf9, 0xd8, 0xe5, 0xc5, 0xb9, 0x4d, 0x44, 0x08, 0x86, 0xe7,
        0xa1, 0x1d, 0xaa, 0xed, 0x06, 0x70, 0xb2, 0xd2, 0x41, 0x7b, 0xa0, 0x11, 0x31, 0xc2, 0x27, 0x90,
        0x20, 0xf6, 0x60, 0xff, 0x96, 0x5c, 0xb1, 0xab, 0x9e, 0x9c, 0x52, 0x1b, 0x5f, 0x93, 0x0a, 0xef,
        0x91, 0x85, 0x49, 0xee, 0x2d, 0x4f, 0x8f, 0x3b, 0x47, 0x87, 0x6d, 0x46, 0xd6, 0x3e, 0x69, 0x64,
        0x2a, 0xce, 0xcb, 0x2f, 0xfc, 0x97, 0x05, 0x7a, 0xac, 0x7f, 0xd5, 0x1a, 0x4b, 0x0e, 0xa7, 0x5a,
        0x28, 0x14, 0x3f, 0x29, 0x88, 0x3c, 0x4c, 0x02, 0xb8, 0xda, 0xb0, 0x17, 0x55, 0x1f, 0x8a, 0x7d,
        0x57, 0xc7, 0x8d, 0x74, 0xb7, 0xc4, 0x9f, 0x72, 0x7e, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
        0x6e, 0x50, 0xde, 0x68, 0x65, 0xbc, 0xdb, 0xf8, 0xc8, 0xa8, 0x2b, 0x40, 0xdc, 0xfe, 0x32, 0xa4,
        0xca, 0x10, 0x21, 0xf0, 0xd3, 0x5d, 0x0f, 0x00, 0x6f, 0x9d, 0x36, 0x42, 0x4a, 0x5e, 0xc1, 0xe0,
    ],
    [
        0x75, 0xf3, 0xc6, 0xf4, 0xdb, 0x7b, 0xfb, 0xc8, 0x4a, 0xd3, 0xe6, 0x6b, 0x45, 0x7d, 0xe8, 0x4b,
        0xd6, 0x32, 0xd8, 0xfd, 0x37, 0x71, 0xf1, 0xe1, 0x30, 0x0f, 0xf8, 0x1b, 0x87, 0xfa, 0x06, 0x3f,
        0x5e, 0xba, 0xae, 0x5b, 0x8a, 0x00, 0xbc, 0x9d, 0x6d, 0xc1, 0xb1, 0x0e, 0x80, 0x5d, 0xd2, 0xd5,
        0xa0, 0x84, 0x07, 0x14, 0xb5, 0x90, 0x2c, 0xa3, 0xb2, 0x73, 0x4c, 0x54, 0x92, 0x74, 0x36, 0x51,
        0x38, 0xb0, 0xbd, 0x5a, 0xfc, 0x60, 0x62, 0x96, 0x6c, 0x42, 0xf7, 0x10, 0x7c, 0x28, 0x27, 0x8c,
        0x13, 0x95, 0x9c, 0xc7, 0x24, 0x46, 0x3b, 0x70, 0xca, 0xe3, 0x85, 0xcb, 0x11, 0xd0, 0x93, 0xb8,
        0xa6, 0x83, 0x20, 0xff, 0x9f, 0x77, 0xc3, 0xcc, 0x03, 0x6f, 0x08, 0xbf, 0x40, 0xe7, 0x2b, 0xe2,
        0x79, 0x0c, 0xaa, 0x82, 0x41, 0x3a, 0xea, 0xb9, 0xe4, 0x9a, 0xa4, 0x97, 0x7e, 0xda, 0x7a, 0x17,
        0x66, 0x94, 0xa1, 0x1d, 0x3d, 0xf0, 0xde, 0xb3, 0x0b, 0x72, 0xa7, 0x1c, 0xef, 0xd1, 0x53, 0x3e,
        0x8f, 0x33, 0x26, 0x5f, 0xec, 0x76, 0x2a, 0x49, 0x81, 0x88, 0xee, 0x21, 0xc4, 0x1a, 0xeb, 0xd9,
        0xc5, 0x39, 0x99, 0xcd, 0xad, 0x31, 0x8b, 0x01, 0x18, 0x23, 0xdd, 0x1f, 0x4e, 0x2d, 0xf9, 0x48,
        0x4f, 0xf2, 0x65, 0x8e, 0x78, 0x5c, 0x58, 0x19, 0x8d, 0xe5, 0x98, 0x57, 0x67, 0x7f, 0x05, 0x64,
        0xaf, 0x63, 0xb6, 0xfe, 0xf5, 0xb7, 0x3c, 0xa5, 0xce, 0xe9, 0x68, 0x44, 0xe0, 0x4d, 0x43, 0x69,
        0x29, 0x2e, 0xac, 0x15, 0x59, 0xa8, 0x0a, 0x9e, 0x6e, 0x47, 0xdf, 0x34, 0x35, 0x6a, 0xcf, 0xdc,
        0x22, 0xc9, 0xc0, 0x9b, 0x89, 0xd4, 0xed, 0xab, 0x12, 0xa2, 0x0d, 0x52, 0xbb, 0x02, 0x2f, 0xa9,
        0xd7, 0x61, 0x1e, 0xb4, 0x50, 0x04, 0xf6, 0xc2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xbe, 0x91,
    ],
];

/// Returns `a·b` in GF(2^8)/p.
// Go: golang.org/x/crypto/twofish@v0.47.0 twofish.go:gfMult()
fn gf_mult(mut a: u8, b: u8, p: u32) -> u8 {
    let mut bb = [0u32, u32::from(b)];
    let pp = [0u32, p];
    let mut result = 0u32;

    // branchless GF multiplier
    for _ in 0..7 {
        result ^= bb[usize::from(a & 1)];
        a >>= 1;
        bb[1] = pp[(bb[1] >> 7) as usize] ^ (bb[1] << 1);
    }
    result ^= bb[usize::from(a & 1)];
    result as u8
}

/// Calculates `y{col}` where `[y0 y1 y2 y3] = MDS · [x0]`; `col` is 0 to 3.
// Go: golang.org/x/crypto/twofish@v0.47.0 twofish.go:mdsColumnMult()
fn mds_column_mult(input: u8, col: usize) -> u32 {
    let mul01 = u32::from(input);
    let mul5b = u32::from(gf_mult(input, 0x5B, MDS_POLYNOMIAL));
    let mulef = u32::from(gf_mult(input, 0xEF, MDS_POLYNOMIAL));

    // Go panics on any other column; every caller passes a constant 0..=3.
    match col {
        0 => mul01 | mul5b << 8 | mulef << 16 | mulef << 24,
        1 => mulef | mulef << 8 | mul5b << 16 | mul01 << 24,
        2 => mul5b | mulef << 8 | mul01 << 16 | mulef << 24,
        _ => mul5b | mul01 << 8 | mulef << 16 | mul5b << 24,
    }
}

/// The S-box generation function. See [TWOFISH] 4.3.5.
// Go: golang.org/x/crypto/twofish@v0.47.0 twofish.go:h()
fn h(input: &[u8; 4], key: &[u8], offset: usize) -> u32 {
    let q = |t: usize, x: u8| SBOX[t][usize::from(x)];
    let mut y = *input;
    let n = key.len() / 8;
    // Go: `switch len(key) / 8 { case 4: ...; fallthrough; case 3: ...; fallthrough; case 2: }`
    if n == 4 {
        y[0] = q(1, y[0]) ^ key[4 * (6 + offset)];
        y[1] = q(0, y[1]) ^ key[4 * (6 + offset) + 1];
        y[2] = q(0, y[2]) ^ key[4 * (6 + offset) + 2];
        y[3] = q(1, y[3]) ^ key[4 * (6 + offset) + 3];
    }
    if n >= 3 {
        y[0] = q(1, y[0]) ^ key[4 * (4 + offset)];
        y[1] = q(1, y[1]) ^ key[4 * (4 + offset) + 1];
        y[2] = q(0, y[2]) ^ key[4 * (4 + offset) + 2];
        y[3] = q(0, y[3]) ^ key[4 * (4 + offset) + 3];
    }
    y[0] = q(
        1,
        q(0, q(0, y[0]) ^ key[4 * (2 + offset)]) ^ key[4 * offset],
    );
    y[1] = q(
        0,
        q(0, q(1, y[1]) ^ key[4 * (2 + offset) + 1]) ^ key[4 * offset + 1],
    );
    y[2] = q(
        1,
        q(1, q(0, y[2]) ^ key[4 * (2 + offset) + 2]) ^ key[4 * offset + 2],
    );
    y[3] = q(
        0,
        q(1, q(1, y[3]) ^ key[4 * (2 + offset) + 3]) ^ key[4 * offset + 3],
    );

    // [y0 y1 y2 y3] = MDS . [x0 x1 x2 x3]
    let mut mds_mult = 0u32;
    for (i, &yi) in y.iter().enumerate() {
        mds_mult ^= mds_column_mult(yi, i);
    }
    mds_mult
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipher::{BlockCipherEncrypt, KeyInit};
    use proptest::prelude::*;

    fn hex16(s: &str) -> [u8; 16] {
        hex::decode(s).expect("hex").try_into().expect("16 bytes")
    }

    /// x/crypto twofish_test.go:TestCipher vectors (LibTom and Schneier's ecb_ival.txt), with
    /// its 1000-fold encrypt/decrypt round trip of a zero block.
    // Go: golang.org/x/crypto/twofish@v0.47.0 twofish_test.go:testVectors, TestCipher
    #[test]
    fn test_cipher() {
        let cases = [
            (
                "9f589f5cf6122c32b6bfec2f2ae8c35a",
                "d491db16e7b1c39e86cb086b789f5419",
                "019f9809de1711858faac3a3ba20fbc3",
            ),
            (
                "88b2b2706b105e36b446bb6d731a1e88efa71f788965bd44",
                "39da69d6ba4997d585b6dc073ca341b2",
                "182b02d81497ea45f9daacdc29193a65",
            ),
            (
                "d43bb7556ea32e46f2a282b7d45b4e0d57ff739d4dc92c1bd7fc01700cc8216f",
                "90afe91bb288544f2c32dc239b2635e6",
                "6cb4561c40bf0a9705931cb6d408e7fa",
            ),
            (
                "00000000000000000000000000000000",
                "00000000000000000000000000000000",
                "9f589f5cf6122c32b6bfec2f2ae8c35a",
            ),
            (
                "0123456789abcdeffedcba98765432100011223344556677",
                "00000000000000000000000000000000",
                "cfd1d2e5a9be9cdf501f13b892bd2248",
            ),
            (
                "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
                "00000000000000000000000000000000",
                "37527be0052334b89f0cfccae87cfa20",
            ),
        ];
        for (key, dec, enc) in cases {
            let key = hex::decode(key).expect("hex");
            let c = Cipher::new_cipher(&key).expect("valid key");
            let mut b = hex16(dec);
            c.encrypt(&mut b);
            assert_eq!(hex::encode(b), enc, "key {}", hex::encode(&key));
            c.decrypt(&mut b);
            assert_eq!(hex::encode(b), dec);

            let mut b = [0u8; 16];
            for _ in 0..1000 {
                c.encrypt(&mut b);
            }
            for _ in 0..1000 {
                c.decrypt(&mut b);
            }
            assert_eq!(b, [0u8; 16]);
        }
    }

    /// x/crypto twofish_test.go:TestSbox: the q0/q1 tables match their generating nibble boxes.
    // Go: golang.org/x/crypto/twofish@v0.47.0 twofish_test.go:qbox, genSbox, TestSbox
    #[test]
    fn test_sbox() {
        const QBOX: [[[u8; 16]; 4]; 2] = [
            [
                [
                    0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4,
                ],
                [
                    0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD,
                ],
                [
                    0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1,
                ],
                [
                    0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA,
                ],
            ],
            [
                [
                    0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5,
                ],
                [
                    0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8,
                ],
                [
                    0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF,
                ],
                [
                    0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA,
                ],
            ],
        ];
        let gen_sbox = |qi: usize, x: u8| -> u8 {
            let (mut a0, mut b0) = (x / 16, x % 16);
            for i in 0..2 {
                let a1 = a0 ^ b0;
                let b1 = (a0 ^ ((b0 << 3) | (b0 >> 1)) ^ (a0 << 3)) & 15;
                a0 = QBOX[qi][2 * i][usize::from(a1)];
                b0 = QBOX[qi][2 * i + 1][usize::from(b1)];
            }
            (b0 << 4).wrapping_add(a0)
        };
        for (n, table) in SBOX.iter().enumerate() {
            for (m, &v) in table.iter().enumerate() {
                assert_eq!(v, gen_sbox(n, m as u8), "sbox[{n}][{m}]");
            }
        }
    }

    #[test]
    fn gf_mult_reduces_by_the_polynomial() {
        assert_eq!(gf_mult(0x01, 0xA4, RS_POLYNOMIAL), 0xA4);
        assert_eq!(gf_mult(0x00, 0xA4, RS_POLYNOMIAL), 0x00);
        // x * x^7 = x^8 = the polynomial without its x^8 term.
        assert_eq!(gf_mult(0x02, 0x80, RS_POLYNOMIAL), 0x4d);
        assert_eq!(gf_mult(0x02, 0x80, MDS_POLYNOMIAL), 0x69);
    }

    #[test]
    fn errors_match_x_crypto() {
        let key = [0u8; 40];
        for len in 0..=key.len() {
            let r = Cipher::new_cipher(&key[..len]);
            if matches!(len, 16 | 24 | 32) {
                assert!(r.is_ok(), "len {len}");
            } else {
                let e = r.expect_err("bad key size");
                assert_eq!(
                    e.to_string(),
                    format!("crypto/twofish: invalid key size {len}")
                );
            }
        }
    }

    #[test]
    fn debug_does_not_leak_key() {
        let c = Cipher::new_cipher(&[0xab; 32]).expect("valid");
        assert_eq!(format!("{c:?}"), "Twofish { .. }");
        assert_eq!(c.block_size(), 16);
    }

    proptest! {
        /// Differential test against RustCrypto `twofish` (an independent implementation).
        #[test]
        fn prop_twofish_matches_rustcrypto(
            key in proptest::collection::vec(any::<u8>(), 32),
            key_len in prop_oneof![Just(16usize), Just(24), Just(32)],
            block in proptest::array::uniform16(any::<u8>()),
        ) {
            let key = &key[..key_len];
            let c = Cipher::new_cipher(key).expect("valid");
            let r = twofish::Twofish::new_from_slice(key).expect("valid");
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
