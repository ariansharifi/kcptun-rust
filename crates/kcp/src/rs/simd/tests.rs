//! Every SIMD kernel against the scalar one: exhaustively for short lengths, and proptests for
//! all 256 coefficients over random lengths (0..=4096), unaligned starts and tails, and xor into
//! existing contents.
#![forbid(unsafe_code)]

use super::*;
use kcptun_testkit::rng::{govectors_rng, rand_bytes};
use proptest::prelude::*;

/// The SIMD kernels of this CPU (everything but the scalar one).
fn simd_kernels() -> Vec<Kernel> {
    Kernel::available()
        .into_iter()
        .filter(|&k| k != Kernel::SCALAR)
        .collect()
}

/// Checks both one-slice kernels of `kernel` for coefficient `c` on `input` (placed at byte
/// offset `in_off` of a buffer) against the scalar kernels, with `out` placed at `out_off` and
/// guard bytes after it.
fn check_slices(kernel: Kernel, c: u8, input: &[u8], in_off: usize, out_off: usize, fill: u8) {
    let n = input.len();
    let mut in_buf = vec![0x5a; in_off + n];
    in_buf[in_off..].copy_from_slice(input);
    let input = &in_buf[in_off..];

    let initial: Vec<u8> = (0..n).map(|i| fill ^ (i as u8).wrapping_mul(73)).collect();
    for xor in [false, true] {
        let mut want = initial.clone();
        let mut buf = vec![0xa5; out_off + n + 7];
        buf[out_off..out_off + n].copy_from_slice(&initial);
        let got = &mut buf[out_off..];
        if xor {
            galois::gal_mul_slice_xor(c, input, &mut want);
            gal_mul_slice_xor(kernel, c, input, got);
        } else {
            galois::gal_mul_slice(c, input, &mut want);
            gal_mul_slice(kernel, c, input, got);
        }
        assert_eq!(
            &buf[out_off..out_off + n],
            &want[..],
            "{kernel} c={c} len={n} in_off={in_off} out_off={out_off} xor={xor}"
        );
        assert!(
            buf[..out_off].iter().all(|&b| b == 0xa5),
            "wrote before out"
        );
        assert!(
            buf[out_off + n..].iter().all(|&b| b == 0xa5),
            "{kernel} wrote past input.len() (len={n}, xor={xor})"
        );
    }
}

#[test]
fn kernel_detection() {
    let all = Kernel::available();
    assert_eq!(all[0], Kernel::SCALAR);
    assert_eq!(Kernel::detect(), *all.last().unwrap());
    assert_eq!(Kernel::detect(), Kernel::detect());
    #[cfg(target_arch = "aarch64")]
    assert_eq!(Kernel::detect().name(), "neon");
    let names: Vec<&str> = all.iter().map(|k| k.name()).collect();
    assert!(
        names
            .iter()
            .all(|n| ["scalar", "neon", "ssse3", "avx2"].contains(n))
    );
    assert_eq!(format!("{:?}", Kernel::SCALAR), "Kernel(scalar)");
    assert_eq!(Kernel::SCALAR.to_string(), "scalar");
    // Recorded in the test output, so CI logs show which kernels ran.
    println!("rs kernels: {names:?}, detected {}", Kernel::detect());
}

#[test]
fn slices_all_coefficients_short_lengths() {
    // Every coefficient and every length up to 4 * 64 + 17, which covers each step width
    // (64/32/16 bytes), the partial vector and their combinations.
    let data = rand_bytes(&mut govectors_rng("rs-simd", 1), 512);
    for kernel in simd_kernels() {
        for c in 0..=255u8 {
            for n in 0..=4 * 64 + 17 {
                check_slices(kernel, c, &data[..n], n % 7, (n * 3) % 5, c);
            }
        }
    }
}

#[test]
fn slices_every_byte_value() {
    // All 256 input bytes against all 256 coefficients (the whole multiplication table).
    let input: Vec<u8> = (0..=255u8).collect();
    for kernel in Kernel::available() {
        for c in 0..=255u8 {
            let mut out = vec![0u8; 256];
            gal_mul_slice(kernel, c, &input, &mut out);
            assert_eq!(out[..], galois::MUL_TABLE[c as usize][..], "{kernel} c={c}");
        }
    }
}

#[test]
#[should_panic(expected = "range end index 4 out of range for slice of length 3")]
fn slice_out_shorter_than_input_panics() {
    gal_mul_slice(Kernel::detect(), 7, &[1, 2, 3, 4], &mut [0; 3]);
}

/// `(inputs, outputs, len, start, end)`-shaped code_block case, checked against the scalar
/// kernel for every SIMD kernel; bytes outside `start..end` must stay untouched.
fn check_code_block(n_in: usize, n_out: usize, len: usize, start: usize, end: usize, seed: u64) {
    let mut rng = govectors_rng("rs-simd-block", seed);
    let rows: Vec<Vec<u8>> = (0..n_out).map(|_| rand_bytes(&mut rng, n_in)).collect();
    let inputs: Vec<Vec<u8>> = (0..n_in).map(|_| rand_bytes(&mut rng, len)).collect();
    let garbage: Vec<Vec<u8>> = (0..n_out).map(|_| rand_bytes(&mut rng, len)).collect();
    let row_refs: Vec<&[u8]> = rows.iter().map(Vec::as_slice).collect();
    let in_refs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();

    let run = |kernel: Kernel| {
        let mut outs = garbage.clone();
        let mut out_refs: Vec<&mut [u8]> = outs.iter_mut().map(Vec::as_mut_slice).collect();
        code_block(kernel, &row_refs, &in_refs, &mut out_refs, start, end);
        outs
    };
    let want = run(Kernel::SCALAR);
    // The scalar kernel itself against the definition, at a few positions.
    for (o, out) in want.iter().enumerate() {
        for x in [start, (start + end) / 2, end.saturating_sub(1)] {
            if (start..end).contains(&x) {
                let v = (0..n_in).fold(0u8, |a, i| {
                    a ^ galois::gal_multiply(rows[o][i], inputs[i][x])
                });
                assert_eq!(out[x], v, "scalar out {o} byte {x}");
            }
        }
        assert_eq!(out[..start], garbage[o][..start]);
        assert_eq!(out[end..], garbage[o][end..]);
    }
    for kernel in simd_kernels() {
        assert_eq!(
            run(kernel),
            want,
            "{kernel}: in={n_in} out={n_out} len={len} range={start}..{end}"
        );
    }
}

#[test]
fn code_block_shapes() {
    // Every group size (1..=4 and more than one group) against short and odd lengths.
    let mut seed = 0;
    for n_out in 1..=9 {
        for n_in in [1, 2, 3, 10, 17] {
            for len in [
                0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 200, 1370, 1500,
            ] {
                seed += 1;
                check_code_block(n_in, n_out, len, 0, len, seed);
                if len > 3 {
                    check_code_block(n_in, n_out, len, 3, len - 1, seed);
                }
            }
        }
    }
}

#[test]
fn code_block_without_inputs_or_outputs() {
    let mut out = vec![9u8; 4];
    let mut outs: Vec<&mut [u8]> = vec![&mut out];
    code_block(Kernel::detect(), &[&[]], &[], &mut outs, 0, 4);
    assert_eq!(out, [9; 4]);
    code_block(Kernel::detect(), &[], &[&[1, 2]], &mut [], 0, 2);
}

#[test]
#[should_panic(expected = "shard or matrix size invariant violated")]
fn code_block_checks_sizes() {
    let mut out = vec![0u8; 4];
    let mut outs: Vec<&mut [u8]> = vec![&mut out];
    code_block(Kernel::detect(), &[&[1]], &[&[1, 2, 3]], &mut outs, 0, 4);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// SIMD == scalar for all 256 coefficients, a random length in 0..=4096, unaligned input
    /// and output offsets, and xor into non-zero contents.
    #[test]
    fn prop_simd_mul_slice_matches_scalar(
        len in 0usize..=4096,
        in_off in 0usize..64,
        out_off in 0usize..64,
        seed in any::<u64>(),
        fill in any::<u8>(),
    ) {
        let data = rand_bytes(&mut govectors_rng("rs-simd-prop", seed), len);
        for kernel in simd_kernels() {
            for c in 0..=255u8 {
                check_slices(kernel, c, &data, in_off, out_off, fill);
            }
        }
    }

    /// The multi-output kernel equals the scalar loop for random shapes and sub-ranges.
    #[test]
    fn prop_simd_code_block_matches_scalar(
        n_in in 1usize..=24,
        n_out in 1usize..=10,
        len in 0usize..=4096,
        cut in (any::<prop::sample::Index>(), any::<prop::sample::Index>()),
        seed in any::<u64>(),
    ) {
        let (a, b) = (cut.0.index(len + 1), cut.1.index(len + 1));
        check_code_block(n_in, n_out, len, a.min(b), a.max(b), seed);
    }
}
