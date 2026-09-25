//! QPP benchmarks (plan step 07.2), the Rust side of Go's `qpp_test.go:BenchmarkQPP`.
//!
//! `encrypt/512` is Go's benchmark exactly: 64 pads, a 512-byte message encrypted in place, one
//! iteration per call, throughput in message bytes. The other sizes show where the per-call
//! overhead stops mattering, and `decrypt/512` checks that the reverse pads cost the same.
//! `new/<pads>` and `create_prng` cover setup, which kcptun pays once per session and once per
//! stream respectively.
//!
//! Run: `cargo bench -p kcptun-qpp --bench qpp`.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use kcptun_qpp::{QuantumPermutationPad, create_prng, fast_prng};

/// kcptun's default `-key`. The QPP seed is the raw key string, not the PBKDF2 pass.
const KEY: &[u8] = b"it's a secrect";

/// Go's `BenchmarkQPP` uses 64 pads; 61 is kcptun's default `-qpp-count`.
const BENCH_PADS: u16 = 64;

/// Message sizes: 512 is Go's, 1350 kcptun's default MTU, 8192 one smux frame.
const SIZES: [usize; 4] = [512, 1350, 8192, 65536];

/// A deterministic message of `n` bytes.
fn message(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 + 13) as u8).collect()
}

fn bench_transform(c: &mut Criterion) {
    let qpp = QuantumPermutationPad::new(KEY, BENCH_PADS);

    let mut group = c.benchmark_group("qpp");
    for size in SIZES {
        let mut msg = message(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("encrypt", size), &size, |b, _| {
            let mut rand = create_prng(KEY);
            b.iter(|| qpp.encrypt_with_prng(black_box(&mut msg), &mut rand));
        });
        group.bench_with_input(BenchmarkId::new("decrypt", size), &size, |b, _| {
            let mut rand = create_prng(KEY);
            b.iter(|| qpp.decrypt_with_prng(black_box(&mut msg), &mut rand));
        });
    }
    // Unaligned chunking: 7-byte pieces never line up with the 8-byte pad switch, so every
    // call goes through the head and tail loops.
    let mut msg = message(8192);
    group.throughput(Throughput::Bytes(7));
    group.bench_function("encrypt/chunked=7", |b| {
        let mut rand = create_prng(KEY);
        let mut off = 0;
        b.iter(|| {
            qpp.encrypt_with_prng(black_box(&mut msg[off..off + 7]), &mut rand);
            off = (off + 7) % (8192 - 7);
        });
    });
    group.finish();
}

fn bench_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("qpp_setup");
    for pads in [1u16, 7, 61, 1024] {
        group.bench_with_input(BenchmarkId::new("new", pads), &pads, |b, &pads| {
            b.iter(|| QuantumPermutationPad::new(black_box(KEY), pads));
        });
    }
    group.bench_function("create_prng", |b| {
        b.iter(|| create_prng(black_box(KEY)));
    });
    group.bench_function("fast_prng", |b| {
        b.iter(|| fast_prng(black_box(KEY)));
    });
    group.finish();
}

criterion_group!(benches, bench_transform, bench_setup);
criterion_main!(benches);
