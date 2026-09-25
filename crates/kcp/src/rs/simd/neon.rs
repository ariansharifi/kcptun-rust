//! aarch64 NEON kernels: `vqtbl1q_u8` split-nibble lookups, 16 bytes per vector.
//!
//! Go reference (approach, not a line-by-line port): klauspost/reedsolomon@v1.13.0
//! `galois_arm64.s` (`galMulNEON`, `galMulXorNEON`) and `galois_gen_arm64.s`
//! (`mulNeon_10xN_64`: all inputs into up to 3 outputs, 64 bytes per step, or more outputs
//! 32 bytes per step).
//!
//! NEON is part of the baseline of every aarch64 target this module is compiled for
//! (`cfg(target_feature = "neon")`); the functions still carry `#[target_feature(enable =
//! "neon")]`, which the intrinsics require of their callers.

use core::arch::aarch64::{
    uint8x16_t, vandq_u8, vdupq_n_u8, veorq_u8, vld1q_u8, vqtbl1q_u8, vshrq_n_u8, vst1q_u8,
};

use super::super::galois::{MUL_TABLE_HIGH, MUL_TABLE_LOW};

/// The low and high nibble tables of coefficient `c`.
#[inline]
#[target_feature(enable = "neon")]
fn tables(c: u8) -> (uint8x16_t, uint8x16_t) {
    // SAFETY: each table row is a `[u8; 16]`, exactly one 16-byte vector.
    unsafe {
        (
            vld1q_u8(MUL_TABLE_LOW[c as usize].as_ptr()),
            vld1q_u8(MUL_TABLE_HIGH[c as usize].as_ptr()),
        )
    }
}

/// `c * x` bytewise, from the split nibbles `lo = x & 0xf`, `hi = x >> 4`.
#[inline]
#[target_feature(enable = "neon")]
fn mul(tl: uint8x16_t, th: uint8x16_t, lo: uint8x16_t, hi: uint8x16_t) -> uint8x16_t {
    veorq_u8(vqtbl1q_u8(tl, lo), vqtbl1q_u8(th, hi))
}

/// Computes `V` vectors (16 * `V` bytes) at `pos` of `N` outputs from all inputs.
///
/// # Safety
/// Every input and output must be at least `pos + 16 * V` bytes long.
#[inline]
#[target_feature(enable = "neon")]
unsafe fn step<const N: usize, const V: usize, const XOR: bool>(
    rows: &[&[u8]; N],
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]; N],
    pos: usize,
) {
    let mask = vdupq_n_u8(0x0f);
    let mut acc = [[vdupq_n_u8(0); V]; N];
    for (i, input) in inputs.iter().enumerate() {
        let mut lo = [vdupq_n_u8(0); V];
        let mut hi = [vdupq_n_u8(0); V];
        for v in 0..V {
            // SAFETY: the caller guarantees `input.len() >= pos + 16 * V`, so the 16 bytes at
            // `pos + 16 * v` (v < V) are in bounds; `vld1q_u8` has no alignment requirement.
            let x = unsafe { vld1q_u8(input.as_ptr().add(pos + 16 * v)) };
            lo[v] = vandq_u8(x, mask);
            hi[v] = vshrq_n_u8::<4>(x);
        }
        for (o, row) in rows.iter().enumerate() {
            let (tl, th) = tables(row[i]);
            for v in 0..V {
                acc[o][v] = veorq_u8(acc[o][v], mul(tl, th, lo[v], hi[v]));
            }
        }
    }
    for (out, acc_o) in outputs.iter_mut().zip(&acc) {
        let p = out.as_mut_ptr();
        for (v, &a) in acc_o.iter().enumerate() {
            // SAFETY: the caller guarantees `out.len() >= pos + 16 * V`; unaligned 16-byte
            // accesses at `pos + 16 * v` (v < V) are in bounds and `out` is exclusively borrowed.
            unsafe {
                let dst = p.add(pos + 16 * v);
                let y = if XOR { veorq_u8(a, vld1q_u8(dst)) } else { a };
                vst1q_u8(dst, y);
            }
        }
    }
}

/// The last `rem < 16` bytes at `pos`, through zero-padded 16-byte copies (bounds-checked).
#[target_feature(enable = "neon")]
fn partial<const N: usize, const XOR: bool>(
    rows: &[&[u8]; N],
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]; N],
    pos: usize,
    rem: usize,
) {
    let mask = vdupq_n_u8(0x0f);
    let mut acc = [vdupq_n_u8(0); N];
    for (i, input) in inputs.iter().enumerate() {
        let mut buf = [0u8; 16];
        buf[..rem].copy_from_slice(&input[pos..pos + rem]);
        // SAFETY: `buf` is 16 bytes.
        let x = unsafe { vld1q_u8(buf.as_ptr()) };
        let (lo, hi) = (vandq_u8(x, mask), vshrq_n_u8::<4>(x));
        for (o, row) in rows.iter().enumerate() {
            let (tl, th) = tables(row[i]);
            acc[o] = veorq_u8(acc[o], mul(tl, th, lo, hi));
        }
    }
    for (o, out) in outputs.iter_mut().enumerate() {
        let mut buf = [0u8; 16];
        // SAFETY: `buf` is 16 bytes.
        unsafe { vst1q_u8(buf.as_mut_ptr(), acc[o]) };
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

/// `outputs[o][start..end] (^)= sum over i of rows[o][i] * inputs[i][start..end]` for the
/// `N` outputs (`=` when `XOR` is false, `^=` when true).
///
/// Up to 3 outputs are computed 64 bytes per step, more 32 bytes per step (register budget,
/// like klauspost's generated kernels), then 16-byte steps and a padded partial vector.
///
/// Panics if `rows` or `outputs` do not have `N` entries, or a row has fewer than
/// `inputs.len()` coefficients.
///
/// # Safety
/// NEON must be available (always, on the targets this module is built for); `start <= end`;
/// every input and output must be at least `end` bytes long.
#[target_feature(enable = "neon")]
pub(super) unsafe fn code_group<const N: usize, const XOR: bool>(
    rows: &[&[u8]],
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]],
    start: usize,
    end: usize,
) {
    let rows: &[&[u8]; N] = rows.try_into().expect("code_group: one row per output");
    let outputs: &mut [&mut [u8]; N] = outputs.try_into().expect("code_group: N outputs per group");
    assert!(
        rows.iter().all(|r| r.len() >= inputs.len()),
        "code_group: one coefficient per input"
    );
    let mut pos = start;
    if N <= 3 {
        while end - pos >= 64 {
            // SAFETY: every input and output is at least `end >= pos + 64` bytes (caller).
            unsafe { step::<N, 4, XOR>(rows, inputs, outputs, pos) };
            pos += 64;
        }
    } else {
        while end - pos >= 32 {
            // SAFETY: as above, with `end >= pos + 32`.
            unsafe { step::<N, 2, XOR>(rows, inputs, outputs, pos) };
            pos += 32;
        }
    }
    while end - pos >= 16 {
        // SAFETY: as above, with `end >= pos + 16`.
        unsafe { step::<N, 1, XOR>(rows, inputs, outputs, pos) };
        pos += 16;
    }
    if pos < end {
        partial::<N, XOR>(rows, inputs, outputs, pos, end - pos);
    }
}
