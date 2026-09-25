//! GF(2^8) arithmetic with the generating polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D), exactly
//! as klauspost/reedsolomon v1.13.0 `galois.go`.
//!
//! klauspost ships the tables as literals (generated once from this polynomial). Here they are
//! computed at compile time by `const fn`s following the same generation, and the unit tests
//! compare them with klauspost's tables as recorded by `tools/govectors` (`rs.json`, case
//! `galois`, itself checked against the literals of the pinned `galois.go`).
#![forbid(unsafe_code)]

// Go: klauspost/reedsolomon@v1.13.0 galois.go:fieldSize
/// The number of elements in the field.
pub const FIELD_SIZE: usize = 256;

// Go: klauspost/reedsolomon@v1.13.0 galois.go:generatingPolynomial
/// The polynomial used to generate the logarithm table, without its x^8 term (0x11D & 0xFF).
///
/// There are a number of polynomials that work to generate a Galois field of 256 elements. The
/// choice is arbitrary, and klauspost (after Backblaze) uses the first one.
pub const GENERATING_POLYNOMIAL: u8 = 29;

/// Builds `(exp, log)`: `exp[i] = 2^i` for `i` in `0..256` (so `exp[255] = 1`, like klauspost's
/// 256-entry `expTable`), and `log[x]` the discrete logarithm base 2 of `x`, with `log[0] = 0`
/// (unused, like klauspost's `logTable[0]`).
const fn gen_exp_log() -> ([u8; FIELD_SIZE], [u8; FIELD_SIZE]) {
    let mut exp = [0u8; FIELD_SIZE];
    let mut log = [0u8; FIELD_SIZE];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < FIELD_SIZE {
        exp[i] = x as u8;
        if i < FIELD_SIZE - 1 {
            log[x as usize] = i as u8;
        }
        x <<= 1;
        if x >= FIELD_SIZE as u16 {
            x ^= 0x100 | GENERATING_POLYNOMIAL as u16;
        }
        i += 1;
    }
    (exp, log)
}

const EXP_LOG: ([u8; FIELD_SIZE], [u8; FIELD_SIZE]) = gen_exp_log();

// Go: klauspost/reedsolomon@v1.13.0 galois.go:expTable
/// `EXP_TABLE[i] = 2^i`, `i` in `0..256`.
pub static EXP_TABLE: [u8; FIELD_SIZE] = EXP_LOG.0;

// Go: klauspost/reedsolomon@v1.13.0 galois.go:logTable
/// `LOG_TABLE[x] = log2(x)` for `x != 0`; `LOG_TABLE[0] = 0`.
pub static LOG_TABLE: [u8; FIELD_SIZE] = EXP_LOG.1;

/// The product `a * b` from the log/exp tables: klauspost's original `galMultiply`, which
/// generated `mulTable`.
const fn mul_log_exp(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let log_a = EXP_LOG.1[a as usize] as usize;
    let log_b = EXP_LOG.1[b as usize] as usize;
    EXP_LOG.0[(log_a + log_b) % 255]
}

const fn gen_mul_table() -> [[u8; FIELD_SIZE]; FIELD_SIZE] {
    let mut t = [[0u8; FIELD_SIZE]; FIELD_SIZE];
    let mut a = 0;
    while a < FIELD_SIZE {
        let mut b = 0;
        while b < FIELD_SIZE {
            t[a][b] = mul_log_exp(a as u8, b as u8);
            b += 1;
        }
        a += 1;
    }
    t
}

const fn gen_inv_table() -> [u8; FIELD_SIZE] {
    let mut t = [0u8; FIELD_SIZE];
    let mut a = 1;
    while a < FIELD_SIZE {
        let log_a = EXP_LOG.1[a] as usize;
        t[a] = EXP_LOG.0[(255 - log_a) % 255];
        a += 1;
    }
    t
}

// Go: klauspost/reedsolomon@v1.13.0 galois.go:mulTable
/// The full multiplication table, `MUL_TABLE[a][b] = a * b` (64 KiB). The scalar kernels use
/// row `MUL_TABLE[c]`.
pub static MUL_TABLE: [[u8; FIELD_SIZE]; FIELD_SIZE] = gen_mul_table();

const fn gen_mul_table_nibbles(high: bool) -> [[u8; 16]; FIELD_SIZE] {
    let full = gen_mul_table();
    let mut t = [[0u8; 16]; FIELD_SIZE];
    let mut c = 0;
    while c < FIELD_SIZE {
        let mut x = 0;
        while x < 16 {
            t[c][x] = if high { full[c][x << 4] } else { full[c][x] };
            x += 1;
        }
        c += 1;
    }
    t
}

// Go: klauspost/reedsolomon@v1.13.0 galois.go:mulTableLow
/// Split-nibble table for the SIMD kernels: `MUL_TABLE_LOW[c][x] = c * x` for `x < 16`.
pub static MUL_TABLE_LOW: [[u8; 16]; FIELD_SIZE] = gen_mul_table_nibbles(false);

// Go: klauspost/reedsolomon@v1.13.0 galois.go:mulTableHigh
/// Split-nibble table for the SIMD kernels: `MUL_TABLE_HIGH[c][x] = c * (x << 4)` for `x < 16`,
/// so that `c * b = MUL_TABLE_LOW[c][b & 0xf] ^ MUL_TABLE_HIGH[c][b >> 4]`.
pub static MUL_TABLE_HIGH: [[u8; 16]; FIELD_SIZE] = gen_mul_table_nibbles(true);

// Go: klauspost/reedsolomon@v1.13.0 galois.go:invTable
/// Multiplicative inverses, `INV_TABLE[0] = 0`.
pub static INV_TABLE: [u8; FIELD_SIZE] = gen_inv_table();

// Go: klauspost/reedsolomon@v1.13.0 galois.go:galAdd()
/// Adds two elements of the field (xor).
#[inline]
pub fn gal_add(a: u8, b: u8) -> u8 {
    a ^ b
}

// Go: klauspost/reedsolomon@v1.13.0 galois.go:galMultiply()
/// Multiplies two elements of the field.
#[inline]
pub fn gal_multiply(a: u8, b: u8) -> u8 {
    MUL_TABLE[a as usize][b as usize]
}

// Go: klauspost/reedsolomon@v1.13.0 galois.go:galDivide()
/// `a / b`, the inverse of [`gal_multiply`].
///
/// Panics with Go's message if `b == 0` (an internal invariant: never reached from shard data).
pub fn gal_divide(a: u8, b: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    assert!(b != 0, "Argument 'divisor' is 0");
    let log_a = i32::from(LOG_TABLE[a as usize]);
    let log_b = i32::from(LOG_TABLE[b as usize]);
    let mut log_result = log_a - log_b;
    if log_result < 0 {
        log_result += 255;
    }
    EXP_TABLE[log_result as u8 as usize]
}

// Go: klauspost/reedsolomon@v1.13.0 galois.go:galOneOver()
/// `1 / a`, the same as `gal_divide(1, a)`.
///
/// Panics with Go's message if `a == 0`. The only caller, Gauss-Jordan elimination, checks the
/// pivot is non-zero first.
pub fn gal_one_over(a: u8) -> u8 {
    assert!(a != 0, "Argument 'divisor' is 0");
    let log_result = LOG_TABLE[a as usize] ^ 255;
    EXP_TABLE[log_result as usize]
}

// Go: klauspost/reedsolomon@v1.13.0 galois.go:galExp()
/// Computes `a^n`, the same as multiplying `a` by itself `n` times (`a^0 = 1`, also for
/// `a = 0`).
pub fn gal_exp(a: u8, n: usize) -> u8 {
    if n == 0 {
        return 1;
    }
    if a == 0 {
        return 0;
    }
    let log_a = LOG_TABLE[a as usize];
    // Go: `logResult := int(logA) * n; for logResult >= 255 { logResult -= 255 }`, i.e. mod 255
    // (n is at most 255 here, so the product cannot overflow; % keeps it exact for any n).
    let log_result = (usize::from(log_a) * (n % 255)) % 255;
    EXP_TABLE[log_result]
}

// Go: klauspost/reedsolomon@v1.13.0 galois_noasm.go:galMulSlice()
/// `out[i] = c * input[i]` for `i < input.len()`.
///
/// Scalar kernel over the 64 KiB [`MUL_TABLE`] (klauspost's generic path without the 2-byte
/// table). Panics if `out` is shorter than `input` (Go: `out = out[:len(in)]`); callers pass
/// equal-length shards.
pub fn gal_mul_slice(c: u8, input: &[u8], out: &mut [u8]) {
    let out = &mut out[..input.len()];
    if c == 1 {
        out.copy_from_slice(input);
        return;
    }
    let mt = &MUL_TABLE[c as usize];
    for (o, &i) in out.iter_mut().zip(input) {
        *o = mt[i as usize];
    }
}

// Go: klauspost/reedsolomon@v1.13.0 galois_noasm.go:galMulSliceXor()
/// `out[i] ^= c * input[i]` for `i < input.len()`.
///
/// Panics if `out` is shorter than `input`, like [`gal_mul_slice`].
pub fn gal_mul_slice_xor(c: u8, input: &[u8], out: &mut [u8]) {
    let out = &mut out[..input.len()];
    if c == 1 {
        slice_xor(input, out);
        return;
    }
    let mt = &MUL_TABLE[c as usize];
    for (o, &i) in out.iter_mut().zip(input) {
        *o ^= mt[i as usize];
    }
}

// Go: klauspost/reedsolomon@v1.13.0 galois.go:sliceXorGo()
/// `out[i] ^= input[i]` for `i < input.len()`.
pub fn slice_xor(input: &[u8], out: &mut [u8]) {
    let out = &mut out[..input.len()];
    for (o, &i) in out.iter_mut().zip(input) {
        *o ^= i;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kcptun_testkit::vectors;
    use kcptun_testkit::vectors::Blob;

    #[test]
    fn vectors_rs_galois_tables() {
        let file = vectors!("rs");
        let case = file.case("galois");
        kcptun_testkit::assert_hex_eq!(EXP_TABLE, case.bytes("exp"), "expTable");
        kcptun_testkit::assert_hex_eq!(LOG_TABLE, case.bytes("log"), "logTable");
        kcptun_testkit::assert_hex_eq!(INV_TABLE, case.bytes("inv"), "invTable");
        kcptun_testkit::assert_hex_eq!(MUL_TABLE[2], case.bytes("mul_row_2"), "mulTable[2]");
        let flat: Vec<u8> = MUL_TABLE.iter().flatten().copied().collect();
        assert_eq!(Blob::of(&flat), case.blob("mul_table"), "mulTable");
    }

    #[test]
    fn exp_table_start_matches_klauspost_literal() {
        // First 32 entries of klauspost galois.go expTable (polynomial 0x11D).
        let want = [
            0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x1d, 0x3a, 0x74, 0xe8, 0xcd, 0x87, 0x13,
            0x26, 0x4c, 0x98, 0x2d, 0x5a, 0xb4, 0x75, 0xea, 0xc9, 0x8f, 0x3, 0x6, 0xc, 0x18, 0x30,
            0x60, 0xc0,
        ];
        assert_eq!(EXP_TABLE[..32], want);
        assert_eq!(EXP_TABLE[255], 1);
        // logTable starts 0, 0, 1, 25, 2, 50, 26, 198.
        assert_eq!(LOG_TABLE[..8], [0, 0, 1, 25, 2, 50, 26, 198]);
    }

    #[test]
    fn nibble_tables_match_klauspost() {
        // First rows of klauspost galois.go mulTableLow / mulTableHigh.
        assert_eq!(MUL_TABLE_LOW[0], [0; 16]);
        assert_eq!(MUL_TABLE_LOW[1], core::array::from_fn(|i| i as u8));
        assert_eq!(
            MUL_TABLE_LOW[3],
            [
                0x0, 0x3, 0x6, 0x5, 0xc, 0xf, 0xa, 0x9, 0x18, 0x1b, 0x1e, 0x1d, 0x14, 0x17, 0x12,
                0x11
            ]
        );
        assert_eq!(
            MUL_TABLE_HIGH[2],
            [
                0x0, 0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0xe0, 0x1d, 0x3d, 0x5d, 0x7d, 0x9d, 0xbd,
                0xdd, 0xfd
            ]
        );
        assert_eq!(
            MUL_TABLE_HIGH[3],
            [
                0x0, 0x30, 0x60, 0x50, 0xc0, 0xf0, 0xa0, 0x90, 0x9d, 0xad, 0xfd, 0xcd, 0x5d, 0x6d,
                0x3d, 0xd
            ]
        );
        // The split identity for every product.
        for c in 0..FIELD_SIZE {
            for b in 0..FIELD_SIZE {
                assert_eq!(
                    MUL_TABLE_LOW[c][b & 0xf] ^ MUL_TABLE_HIGH[c][b >> 4],
                    MUL_TABLE[c][b],
                    "c={c} b={b}"
                );
            }
        }
    }

    #[test]
    fn field_identities() {
        for a in 0..=255u8 {
            assert_eq!(gal_multiply(a, 1), a);
            assert_eq!(gal_multiply(a, 0), 0);
            assert_eq!(gal_add(a, a), 0);
            assert_eq!(gal_exp(a, 0), 1);
            assert_eq!(gal_exp(a, 1), a);
            if a != 0 {
                assert_eq!(gal_multiply(a, gal_one_over(a)), 1, "a={a}");
                assert_eq!(gal_one_over(a), INV_TABLE[a as usize]);
                assert_eq!(gal_divide(a, a), 1);
            }
            for b in 1..=255u8 {
                assert_eq!(gal_divide(gal_multiply(a, b), b), a, "a={a} b={b}");
            }
            // a^n by repeated multiplication, for n past the group order.
            let mut p = 1u8;
            for n in 0..600 {
                assert_eq!(gal_exp(a, n), p, "a={a} n={n}");
                p = gal_multiply(p, a);
            }
        }
        assert_eq!(gal_divide(0, 7), 0);
    }

    #[test]
    #[should_panic(expected = "Argument 'divisor' is 0")]
    fn gal_one_over_zero_panics_like_go() {
        gal_one_over(0);
    }

    #[test]
    #[should_panic(expected = "Argument 'divisor' is 0")]
    fn gal_divide_by_zero_panics_like_go() {
        gal_divide(3, 0);
    }

    #[test]
    fn mul_slice_kernels() {
        let input: Vec<u8> = (0..=255u8).chain(0..=99u8).collect();
        for c in 0..=255u8 {
            let mut out = vec![0xa5u8; input.len() + 3];
            gal_mul_slice(c, &input, &mut out);
            for (i, &x) in input.iter().enumerate() {
                assert_eq!(out[i], gal_multiply(c, x));
            }
            assert_eq!(out[input.len()..], [0xa5; 3], "wrote past input.len()");

            let mut out = vec![0x3cu8; input.len()];
            gal_mul_slice_xor(c, &input, &mut out);
            for (i, &x) in input.iter().enumerate() {
                assert_eq!(out[i], gal_multiply(c, x) ^ 0x3c);
            }
        }
        let mut out = [1u8, 2, 3];
        slice_xor(&[1, 1], &mut out);
        assert_eq!(out, [0, 3, 3]);
    }
}
