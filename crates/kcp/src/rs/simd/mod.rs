//! SIMD GF(2^8) multiply kernels with runtime dispatch.
//!
//! All kernels use klauspost's split-nibble technique (`galois_amd64.s` / `galois_arm64.s`):
//! per coefficient `c` two 16-byte tables, [`MUL_TABLE_LOW`](super::galois::MUL_TABLE_LOW)`[c]`
//! and [`MUL_TABLE_HIGH`](super::galois::MUL_TABLE_HIGH)`[c]`, and
//! `c * b = low[b & 0xf] ^ high[b >> 4]`, sixteen (or thirty-two) bytes at a time with a byte
//! shuffle (`vqtbl1q_u8` on NEON, `pshufb` / `vpshufb` on SSSE3 / AVX2).
//!
//! Besides the one-slice kernels ([`gal_mul_slice`], [`gal_mul_slice_xor`], klauspost's
//! `galMulSlice`/`galMulSliceXor`), [`code_block`] computes several outputs from all inputs in one
//! pass, keeping the output accumulators in registers, like klauspost's generated
//! `mulNeon_10x3_64` / `mulAvxTwo_10x3_64` kernels (`galois_gen_*.s`). Every kernel computes the
//! same bytes as the scalar one (tested exhaustively and with proptests); only the speed differs.
//!
//! Kernels:
//! - aarch64: NEON (part of the baseline of every aarch64 target kcptun builds for);
//! - x86_64: AVX2, else SSSE3, detected at run time once (`is_x86_feature_detected!`);
//! - everywhere: the scalar kernels of [`galois`](super::galois) (64 KiB `MUL_TABLE`).
//!
//! `unsafe` code of the crate's Reed-Solomon codec lives only in this module: SIMD loads and
//! stores through raw pointers in the `neon` / `x86` children, and the calls of their
//! `#[target_feature]` functions in the dispatch arms of `mul_slice` / `code_group` here. A
//! [`Kernel`] value can only be obtained for a kernel the CPU supports, which is
//! what makes the dispatch functions safe.

use std::fmt;
use std::sync::OnceLock;

use super::galois;

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
mod neon;
#[cfg(target_arch = "x86_64")]
mod x86;

#[cfg(test)]
mod tests;

/// Outputs computed together by one pass of [`code_block`] (their accumulators stay in
/// registers). Larger output sets are processed in groups of this size.
pub const OUTPUT_GROUP: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Imp {
    Scalar,
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    Neon,
    #[cfg(target_arch = "x86_64")]
    Ssse3,
    #[cfg(target_arch = "x86_64")]
    Avx2,
}

/// A GF(2^8) multiply kernel that the running CPU supports.
///
/// Obtained from [`Kernel::detect`] (the fastest one), [`Kernel::available`] or
/// [`Kernel::SCALAR`]; a value always names a kernel that is safe to run here.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Kernel(Imp);

impl Kernel {
    /// The portable scalar kernel (table lookups, no SIMD).
    pub const SCALAR: Kernel = Kernel(Imp::Scalar);

    /// The fastest kernel for this CPU, detected on first use and cached.
    pub fn detect() -> Kernel {
        static DETECTED: OnceLock<Kernel> = OnceLock::new();
        *DETECTED.get_or_init(|| {
            *Kernel::available()
                .last()
                .expect("available() always contains the scalar kernel")
        })
    }

    /// Every kernel this CPU can run, slowest first (the scalar kernel first).
    pub fn available() -> Vec<Kernel> {
        #[allow(unused_mut)] // Only the scalar kernel on other architectures.
        let mut v = vec![Kernel::SCALAR];
        #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
        v.push(Kernel(Imp::Neon));
        #[cfg(target_arch = "x86_64")]
        {
            if std::arch::is_x86_feature_detected!("ssse3") {
                v.push(Kernel(Imp::Ssse3));
            }
            if std::arch::is_x86_feature_detected!("avx2") {
                v.push(Kernel(Imp::Avx2));
            }
        }
        v
    }

    /// The kernel's name: `scalar`, `neon`, `ssse3` or `avx2`.
    pub fn name(self) -> &'static str {
        match self.0 {
            Imp::Scalar => "scalar",
            #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
            Imp::Neon => "neon",
            #[cfg(target_arch = "x86_64")]
            Imp::Ssse3 => "ssse3",
            #[cfg(target_arch = "x86_64")]
            Imp::Avx2 => "avx2",
        }
    }
}

impl fmt::Debug for Kernel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Kernel({})", self.name())
    }
}

impl fmt::Display for Kernel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// Go: klauspost/reedsolomon@v1.13.0 galois_arm64.go:galMulSlice() / galois_amd64.go:galMulSlice()
/// `out[i] = c * input[i]` for `i < input.len()`, with `kernel`.
///
/// Panics if `out` is shorter than `input` (Go: `out = out[:len(in)]`); bytes of `out` past
/// `input.len()` are not touched.
pub fn gal_mul_slice(kernel: Kernel, c: u8, input: &[u8], out: &mut [u8]) {
    let out = &mut out[..input.len()];
    if c == 1 {
        out.copy_from_slice(input);
        return;
    }
    mul_slice::<false>(kernel, c, input, out);
}

// Go: klauspost/reedsolomon@v1.13.0 galois_arm64.go:galMulSliceXor() /
// galois_amd64.go:galMulSliceXor()
/// `out[i] ^= c * input[i]` for `i < input.len()`, with `kernel`.
///
/// Panics if `out` is shorter than `input`, like [`gal_mul_slice`].
pub fn gal_mul_slice_xor(kernel: Kernel, c: u8, input: &[u8], out: &mut [u8]) {
    let out = &mut out[..input.len()];
    if c == 1 {
        galois::slice_xor(input, out);
        return;
    }
    mul_slice::<true>(kernel, c, input, out);
}

/// One-slice kernel body (`c != 1`); `out.len() == input.len()`.
fn mul_slice<const XOR: bool>(kernel: Kernel, c: u8, input: &[u8], out: &mut [u8]) {
    // The `code_group` arguments are built only where a SIMD arm exists to consume them. On a
    // target with no SIMD kernel (armv7, armv6, i686) the match is `Scalar` alone, and building
    // them unconditionally made every cross-build of those targets emit four `unused` warnings —
    // invisible to CI, which only ever runs clippy for the host architecture.
    #[cfg(any(
        all(target_arch = "aarch64", target_feature = "neon"),
        target_arch = "x86_64"
    ))]
    let (rows, inputs, end): ([&[u8]; 1], [&[u8]; 1], usize) = ([&[c]], [input], input.len());
    match kernel.0 {
        // `out` is used directly here and moved into a one-element `outputs` inside each SIMD
        // arm instead; the arms are exclusive, so only one of them takes it.
        Imp::Scalar => {
            if XOR {
                galois::gal_mul_slice_xor(c, input, out);
            } else {
                galois::gal_mul_slice(c, input, out);
            }
        }
        #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
        // SAFETY: NEON is in the target baseline (the module only exists with
        // `target_feature = "neon"`); the single input and output are exactly `end` bytes long
        // and the row holds one coefficient per input, as `code_group` requires.
        Imp::Neon => {
            let mut outputs: [&mut [u8]; 1] = [out];
            // SAFETY: as above.
            unsafe { neon::code_group::<1, XOR>(&rows, &inputs, &mut outputs, 0, end) }
        }
        #[cfg(target_arch = "x86_64")]
        // SAFETY: a `Kernel(Imp::Avx2)` exists only if the CPU has AVX2 (`Kernel::available`);
        // the single input and output are exactly `end` bytes long and the row holds one
        // coefficient per input, as `code_group_avx2` requires.
        Imp::Avx2 => {
            let mut outputs: [&mut [u8]; 1] = [out];
            // SAFETY: as above.
            unsafe { x86::code_group_avx2::<1, XOR>(&rows, &inputs, &mut outputs, 0, end) }
        }
        #[cfg(target_arch = "x86_64")]
        // SAFETY: a `Kernel(Imp::Ssse3)` exists only if the CPU has SSSE3; lengths as above.
        Imp::Ssse3 => {
            let mut outputs: [&mut [u8]; 1] = [out];
            // SAFETY: as above.
            unsafe { x86::code_group_ssse3::<1, XOR>(&rows, &inputs, &mut outputs, 0, end) }
        }
    }
}

// Go: klauspost/reedsolomon@v1.13.0 reedsolomon.go:reedSolomon.codeSomeShards() (the body of
// one round, clear = true; the fused path corresponds to galois_gen_switch_*.go:galMulSlices*)
/// `outputs[r][start..end] = sum over c of matrix_rows[r][c] * inputs[c][start..end]`, with
/// `kernel`.
///
/// Every input and output must be at least `end` bytes long, `start <= end`, and
/// `matrix_rows` must hold one row of at least `inputs.len()` coefficients per output; these
/// are internal invariants of the codec, and the function panics if they do not hold. With no
/// inputs the outputs are left unchanged (like Go, which returns before touching them).
///
/// The scalar kernel runs klauspost's loop (each input times each coefficient, accumulated
/// into the outputs); the SIMD kernels compute up to [`OUTPUT_GROUP`] outputs at once from all
/// inputs with the accumulators in registers. The results are identical.
pub fn code_block(
    kernel: Kernel,
    matrix_rows: &[&[u8]],
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]],
    start: usize,
    end: usize,
) {
    if inputs.is_empty() || outputs.is_empty() {
        return;
    }
    assert!(
        start <= end
            && matrix_rows.len() == outputs.len()
            && matrix_rows.iter().all(|r| r.len() >= inputs.len())
            && inputs.iter().all(|s| s.len() >= end)
            && outputs.iter().all(|s| s.len() >= end),
        "rs::simd::code_block: shard or matrix size invariant violated"
    );
    if kernel.0 == Imp::Scalar {
        code_block_scalar(matrix_rows, inputs, outputs, start, end);
        return;
    }
    for (rows, outs) in matrix_rows
        .chunks(OUTPUT_GROUP)
        .zip(outputs.chunks_mut(OUTPUT_GROUP))
    {
        match rows.len() {
            1 => code_group::<1>(kernel, rows, inputs, outs, start, end),
            2 => code_group::<2>(kernel, rows, inputs, outs, start, end),
            3 => code_group::<3>(kernel, rows, inputs, outs, start, end),
            _ => code_group::<OUTPUT_GROUP>(kernel, rows, inputs, outs, start, end),
        }
    }
}

/// One group of `N` outputs of [`code_block`] with a SIMD kernel (sizes already checked).
fn code_group<const N: usize>(
    kernel: Kernel,
    rows: &[&[u8]],
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]],
    start: usize,
    end: usize,
) {
    match kernel.0 {
        Imp::Scalar => code_block_scalar(rows, inputs, outputs, start, end),
        #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
        // SAFETY: NEON is in the target baseline; `code_block` checked that every input and
        // output is at least `end` bytes long, `start <= end`, and `rows` has `N` rows (one per
        // output) of at least `inputs.len()` coefficients.
        Imp::Neon => unsafe { neon::code_group::<N, false>(rows, inputs, outputs, start, end) },
        #[cfg(target_arch = "x86_64")]
        // SAFETY: a `Kernel(Imp::Avx2)` exists only if the CPU has AVX2 (`Kernel::available`);
        // sizes checked by `code_block` as above.
        Imp::Avx2 => unsafe { x86::code_group_avx2::<N, false>(rows, inputs, outputs, start, end) },
        #[cfg(target_arch = "x86_64")]
        // SAFETY: a `Kernel(Imp::Ssse3)` exists only if the CPU has SSSE3; sizes as above.
        Imp::Ssse3 => unsafe {
            x86::code_group_ssse3::<N, false>(rows, inputs, outputs, start, end)
        },
    }
}

// Go: klauspost/reedsolomon@v1.13.0 reedsolomon.go:reedSolomon.codeSomeShards() (the
// galMulSlice/galMulSliceXor loop of one round, clear = true)
/// The scalar body of [`code_block`].
fn code_block_scalar(
    matrix_rows: &[&[u8]],
    inputs: &[&[u8]],
    outputs: &mut [&mut [u8]],
    start: usize,
    end: usize,
) {
    for (c, input) in inputs.iter().enumerate() {
        let input = &input[start..end];
        for (i_row, output) in outputs.iter_mut().enumerate() {
            let coef = matrix_rows[i_row][c];
            let out = &mut output[start..end];
            if c == 0 {
                galois::gal_mul_slice(coef, input, out);
            } else {
                galois::gal_mul_slice_xor(coef, input, out);
            }
        }
    }
}
