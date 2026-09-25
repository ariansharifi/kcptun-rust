//! x86_64 kernels: AVX2 (`vpshufb` on 32 bytes) and SSSE3 (`pshufb` on 16 bytes) split-nibble
//! lookups, selected at run time by [`Kernel`](super::Kernel).
//!
//! Go reference (approach, not a line-by-line port): klauspost/reedsolomon@v1.13.0
//! `galois_amd64.s` (`galMulSSSE3`, `galMulAVX2`, `galMulAVX2_64` and their `Xor` forms) and
//! `galois_gen_amd64.s` (`mulAvxTwo_10xN`: all inputs into several outputs per pass).
//!
//! Every function here is `#[target_feature]` and `unsafe`: the caller must have checked that
//! the CPU supports the feature (a `Kernel` value is proof of that) and the slice lengths.

use core::arch::x86_64::{
    __m128i, __m256i, _mm_and_si128, _mm_loadu_si128, _mm_set1_epi8, _mm_setzero_si128,
    _mm_shuffle_epi8, _mm_srli_epi64, _mm_storeu_si128, _mm_xor_si128, _mm256_and_si256,
    _mm256_broadcastsi128_si256, _mm256_loadu_si256, _mm256_set1_epi8, _mm256_setzero_si256,
    _mm256_shuffle_epi8, _mm256_srli_epi64, _mm256_storeu_si256, _mm256_xor_si256,
};

use super::super::galois::{MUL_TABLE_HIGH, MUL_TABLE_LOW};

/// Checks the group shape and converts to arrays. Panics on a violated internal invariant.
#[allow(clippy::type_complexity)]
fn group<'r, 'a, 'o, 'b, const N: usize>(
    rows: &'r [&'a [u8]],
    inputs: &[&[u8]],
    outputs: &'o mut [&'b mut [u8]],
) -> (&'r [&'a [u8]; N], &'o mut [&'b mut [u8]; N]) {
    let rows: &[&[u8]; N] = rows.try_into().expect("code_group: one row per output");
    let outputs: &mut [&mut [u8]; N] = outputs.try_into().expect("code_group: N outputs per group");
    assert!(
        rows.iter().all(|r| r.len() >= inputs.len()),
        "code_group: one coefficient per input"
    );
    (rows, outputs)
}

// ---------------------------------------------------------------------------------------------
// SSSE3
// ---------------------------------------------------------------------------------------------

/// The low and high nibble tables of coefficient `c` (16 bytes each).
#[inline]
#[target_feature(enable = "ssse3")]
fn tables128(c: u8) -> (__m128i, __m128i) {
    // SAFETY: each table row is a `[u8; 16]`; `_mm_loadu_si128` has no alignment requirement.
    unsafe {
        (
            _mm_loadu_si128(MUL_TABLE_LOW[c as usize].as_ptr().cast()),
            _mm_loadu_si128(MUL_TABLE_HIGH[c as usize].as_ptr().cast()),
        )
    }
}

/// Computes `V` 16-byte vectors at `pos` of `N` outputs from all inputs.
///
/// # Safety
/// SSSE3 must be available; every input and output must be at least `pos + 16 * V` bytes.
#[inline]
#[target_feature(enable = "ssse3")]
unsafe fn step128<const N: usize, const V: usize, const XOR: bool>(
    rows: &[&[u8]; N],
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]; N],
    pos: usize,
) {
    let mask = _mm_set1_epi8(0x0f);
    let mut acc = [[_mm_setzero_si128(); V]; N];
    for (i, input) in inputs.iter().enumerate() {
        let mut lo = [_mm_setzero_si128(); V];
        let mut hi = [_mm_setzero_si128(); V];
        for v in 0..V {
            // SAFETY: `input.len() >= pos + 16 * V` (caller); unaligned load in bounds.
            let x = unsafe { _mm_loadu_si128(input.as_ptr().add(pos + 16 * v).cast()) };
            lo[v] = _mm_and_si128(x, mask);
            hi[v] = _mm_and_si128(_mm_srli_epi64::<4>(x), mask);
        }
        for (o, row) in rows.iter().enumerate() {
            let (tl, th) = tables128(row[i]);
            for v in 0..V {
                let y = _mm_xor_si128(_mm_shuffle_epi8(tl, lo[v]), _mm_shuffle_epi8(th, hi[v]));
                acc[o][v] = _mm_xor_si128(acc[o][v], y);
            }
        }
    }
    for (out, acc_o) in outputs.iter_mut().zip(&acc) {
        let p = out.as_mut_ptr();
        for (v, &a) in acc_o.iter().enumerate() {
            // SAFETY: `out.len() >= pos + 16 * V` (caller); unaligned access in bounds, `out`
            // exclusively borrowed.
            unsafe {
                let dst = p.add(pos + 16 * v).cast::<__m128i>();
                let y = if XOR {
                    _mm_xor_si128(a, _mm_loadu_si128(dst))
                } else {
                    a
                };
                _mm_storeu_si128(dst, y);
            }
        }
    }
}

/// The last `rem < 16` bytes at `pos`, through zero-padded 16-byte copies (bounds-checked).
#[target_feature(enable = "ssse3")]
fn partial128<const N: usize, const XOR: bool>(
    rows: &[&[u8]; N],
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]; N],
    pos: usize,
    rem: usize,
) {
    let mask = _mm_set1_epi8(0x0f);
    let mut acc = [_mm_setzero_si128(); N];
    for (i, input) in inputs.iter().enumerate() {
        let mut buf = [0u8; 16];
        buf[..rem].copy_from_slice(&input[pos..pos + rem]);
        // SAFETY: `buf` is 16 bytes.
        let x = unsafe { _mm_loadu_si128(buf.as_ptr().cast()) };
        let (lo, hi) = (
            _mm_and_si128(x, mask),
            _mm_and_si128(_mm_srli_epi64::<4>(x), mask),
        );
        for (o, row) in rows.iter().enumerate() {
            let (tl, th) = tables128(row[i]);
            let y = _mm_xor_si128(_mm_shuffle_epi8(tl, lo), _mm_shuffle_epi8(th, hi));
            acc[o] = _mm_xor_si128(acc[o], y);
        }
    }
    for (o, out) in outputs.iter_mut().enumerate() {
        let mut buf = [0u8; 16];
        // SAFETY: `buf` is 16 bytes.
        unsafe { _mm_storeu_si128(buf.as_mut_ptr().cast(), acc[o]) };
        let dst = &mut out[pos..pos + rem];
        if XOR {
            for (d, b) in dst.iter_mut().zip(&buf) {
                *d ^= b;
            }
        } else {
            dst.copy_from_slice(&buf[..rem]);
        }
    }
}

/// SSSE3 form of `neon::code_group`: `outputs[o][start..end] (^)= sum over i of
/// rows[o][i] * inputs[i][start..end]` for the `N` outputs. Up to 3 outputs 32 bytes per step,
/// more 16 bytes per step (16 xmm registers), then a padded partial vector.
///
/// Panics if `rows` or `outputs` do not have `N` entries, or a row is shorter than `inputs`.
///
/// # Safety
/// The CPU must support SSSE3; `start <= end`; every input and output must be at least `end`
/// bytes long.
#[target_feature(enable = "ssse3")]
pub(super) unsafe fn code_group_ssse3<const N: usize, const XOR: bool>(
    rows: &[&[u8]],
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]],
    start: usize,
    end: usize,
) {
    let (rows, outputs) = group::<N>(rows, inputs, outputs);
    let mut pos = start;
    if N <= 3 {
        while end - pos >= 32 {
            // SAFETY: SSSE3 is enabled here; every input and output is at least
            // `end >= pos + 32` bytes (caller).
            unsafe { step128::<N, 2, XOR>(rows, inputs, outputs, pos) };
            pos += 32;
        }
    }
    while end - pos >= 16 {
        // SAFETY: as above, with `end >= pos + 16`.
        unsafe { step128::<N, 1, XOR>(rows, inputs, outputs, pos) };
        pos += 16;
    }
    if pos < end {
        partial128::<N, XOR>(rows, inputs, outputs, pos, end - pos);
    }
}

// ---------------------------------------------------------------------------------------------
// AVX2
// ---------------------------------------------------------------------------------------------

/// The low and high nibble tables of coefficient `c`, broadcast to both 128-bit lanes.
#[inline]
#[target_feature(enable = "avx2")]
fn tables256(c: u8) -> (__m256i, __m256i) {
    let (tl, th) = tables128(c);
    (
        _mm256_broadcastsi128_si256(tl),
        _mm256_broadcastsi128_si256(th),
    )
}

/// Computes `V` 32-byte vectors at `pos` of `N` outputs from all inputs.
///
/// # Safety
/// AVX2 must be available; every input and output must be at least `pos + 32 * V` bytes.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn step256<const N: usize, const V: usize, const XOR: bool>(
    rows: &[&[u8]; N],
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]; N],
    pos: usize,
) {
    let mask = _mm256_set1_epi8(0x0f);
    let mut acc = [[_mm256_setzero_si256(); V]; N];
    for (i, input) in inputs.iter().enumerate() {
        let mut lo = [_mm256_setzero_si256(); V];
        let mut hi = [_mm256_setzero_si256(); V];
        for v in 0..V {
            // SAFETY: `input.len() >= pos + 32 * V` (caller); unaligned load in bounds.
            let x = unsafe { _mm256_loadu_si256(input.as_ptr().add(pos + 32 * v).cast()) };
            lo[v] = _mm256_and_si256(x, mask);
            hi[v] = _mm256_and_si256(_mm256_srli_epi64::<4>(x), mask);
        }
        for (o, row) in rows.iter().enumerate() {
            let (tl, th) = tables256(row[i]);
            for v in 0..V {
                let y = _mm256_xor_si256(
                    _mm256_shuffle_epi8(tl, lo[v]),
                    _mm256_shuffle_epi8(th, hi[v]),
                );
                acc[o][v] = _mm256_xor_si256(acc[o][v], y);
            }
        }
    }
    for (out, acc_o) in outputs.iter_mut().zip(&acc) {
        let p = out.as_mut_ptr();
        for (v, &a) in acc_o.iter().enumerate() {
            // SAFETY: `out.len() >= pos + 32 * V` (caller); unaligned access in bounds, `out`
            // exclusively borrowed.
            unsafe {
                let dst = p.add(pos + 32 * v).cast::<__m256i>();
                let y = if XOR {
                    _mm256_xor_si256(a, _mm256_loadu_si256(dst))
                } else {
                    a
                };
                _mm256_storeu_si256(dst, y);
            }
        }
    }
}

/// AVX2 form of `neon::code_group`: up to 3 outputs 64 bytes per step, more 32 bytes per step,
/// then one SSSE3 16-byte step and a padded partial vector.
///
/// Panics if `rows` or `outputs` do not have `N` entries, or a row is shorter than `inputs`.
///
/// # Safety
/// The CPU must support AVX2; `start <= end`; every input and output must be at least `end`
/// bytes long.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn code_group_avx2<const N: usize, const XOR: bool>(
    rows: &[&[u8]],
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]],
    start: usize,
    end: usize,
) {
    let (rows, outputs) = group::<N>(rows, inputs, outputs);
    let mut pos = start;
    if N <= 3 {
        while end - pos >= 64 {
            // SAFETY: AVX2 is enabled here; every input and output is at least
            // `end >= pos + 64` bytes (caller).
            unsafe { step256::<N, 2, XOR>(rows, inputs, outputs, pos) };
            pos += 64;
        }
    }
    while end - pos >= 32 {
        // SAFETY: as above, with `end >= pos + 32`.
        unsafe { step256::<N, 1, XOR>(rows, inputs, outputs, pos) };
        pos += 32;
    }
    if end - pos >= 16 {
        // SAFETY: AVX2 implies SSSE3; `end >= pos + 16`.
        unsafe { step128::<N, 1, XOR>(rows, inputs, outputs, pos) };
        pos += 16;
    }
    if pos < end {
        partial128::<N, XOR>(rows, inputs, outputs, pos, end - pos);
    }
}
