//! AES-128-GCM backend comparison (plan 12.2b).
//!
//! Identical in shape to `crates/kcp/benches/crypt.rs` and to Go's
//! `BenchmarkCrypt/<dir>/aes-128-gcm/<len>` in `tools/govectors/bench_test.go`: one iteration
//! seals or opens one whole packet of `len` bytes in place; "decrypt" first copies a sealed
//! packet into the buffer, because opening overwrites the ciphertext (the Go bench pays for the
//! same copy).
//!
//! Run (laptop):
//!   cargo bench -- --noplot --warm-up-time 0.5 --measurement-time 2 1350
//! Run (lab-arm64), cross-built and copied per tools/lab/README.md:
//!   cargo zigbuild --release --benches --target aarch64-unknown-linux-musl
//! then copy `target/aarch64-unknown-linux-musl/release/deps/gcm-*` (not the `.d` file) to the
//! box as `kr-bench-gcm` — README.md has the exact scp line — and run it there:
//!   ./kr-bench-gcm --bench --noplot --warm-up-time 0.5 --measurement-time 2 1350
//!
//! Interleave the rounds with the Go binary and take medians; see docs/benchmarks/crypto.md.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use kcptun_aes_gcm_eval::{AwsLcGcm, FusedGcm, Halves, PacketAead, RingGcm, RustCryptoGcm, TAG};

/// The AES-128 key the comparison uses (arbitrary; GCM's speed does not depend on it).
const KEY: [u8; 16] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];

/// Whole-packet lengths: kcptun's default MTU and kcp-go's `mtuLimit`.
const PACKET_LENS: [usize; 2] = [1350, 1500];

/// The same non-trivial pattern the Rust and Go crypt benches use.
fn pattern(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| (i.wrapping_mul(131).wrapping_add(7)) as u8)
        .collect()
}

fn bench_backend<A: PacketAead>(c: &mut Criterion, name: &str) {
    let aead = A::new(&KEY);
    for n in PACKET_LENS {
        let plain_len = n - TAG;
        {
            let mut group = c.benchmark_group("gcm/encrypt");
            group.throughput(Throughput::Bytes(n as u64));
            let mut buf = pattern(n);
            group.bench_function(BenchmarkId::new(name, n), |b| {
                b.iter(|| black_box(aead.seal(black_box(&mut buf[..]), plain_len)))
            });
            group.finish();
        }
        {
            let mut group = c.benchmark_group("gcm/decrypt");
            group.throughput(Throughput::Bytes(n as u64));
            let mut sealed = pattern(n);
            aead.seal(&mut sealed, plain_len);
            let mut buf = pattern(n);
            group.bench_function(BenchmarkId::new(name, n), |b| {
                b.iter(|| {
                    buf.copy_from_slice(&sealed);
                    let plain = aead.open(black_box(&mut buf[..]));
                    black_box(plain).map(|p| p.len()).expect("authentic")
                })
            });
            group.finish();
        }
    }
}

/// The two halves of the fused backend on their own. `ctr + ghash` against the fused loop shows
/// how much AES and PMULL overlap; against Go it shows how much they could overlap.
fn bench_halves(c: &mut Criterion) {
    let halves = Halves::new(&KEY);
    let mut group = c.benchmark_group("gcm/halves");
    for n in PACKET_LENS {
        let plain_len = n - TAG;
        group.throughput(Throughput::Bytes(n as u64));
        let mut buf = pattern(n);
        group.bench_function(BenchmarkId::new("ctr-only", n), |b| {
            b.iter(|| halves.ctr_only(black_box(&mut buf[..]), plain_len))
        });
        let data = pattern(n);
        group.bench_function(BenchmarkId::new("ghash-whole", n), |b| {
            b.iter(|| black_box(halves.ghash_whole(black_box(&data), plain_len)))
        });
        group.bench_function(BenchmarkId::new("ghash-grouped", n), |b| {
            b.iter(|| black_box(halves.ghash_grouped(black_box(&data), plain_len)))
        });
    }
    group.finish();
}

fn gcm(c: &mut Criterion) {
    bench_backend::<RustCryptoGcm>(c, "rustcrypto");
    bench_backend::<RingGcm>(c, "ring");
    bench_backend::<AwsLcGcm>(c, "aws-lc-rs");
    bench_backend::<FusedGcm>(c, "fused");
    bench_halves(c);
}

criterion_group!(benches, gcm);
criterion_main!(benches);
