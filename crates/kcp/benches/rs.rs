//! Reed-Solomon codec benchmarks (plan step 04.2), the Rust side of `BenchmarkRS` in
//! `tools/govectors/bench_test.go`.
//!
//! kcp-go's shape: a (10, 3) code over 1370-byte shards (kcptun's defaults `-datashard 10
//! -parityshard 3`; 1370 is a full KCP segment at the default MTU). One iteration is one
//! `Encode` of all 3 parity shards, or one `ReconstructData` with 1 or 3 data shards missing
//! (the missing shards are emptied again before each iteration; their buffers keep their
//! capacity, like Go's `shards[i] = shards[i][:0]`). Throughput is the data bytes (10 x 1370).
//! Every kernel this CPU can run is measured (`scalar` and the SIMD ones).
//!
//! The missing shards are handed to the codec in two shapes, because that choice costs more
//! than the coding itself on some targets (see [`PoolShard`]):
//! - `reused`: an already initialised buffer whose length is moved back to the shard size, the
//!   equivalent of the pool buffer kcp-go passes (`defaultBufferPool.Get()[:0]`, which
//!   klauspost reslices to `[0:shardSize]` over its stale bytes). This is the like-for-like
//!   comparison with Go.
//! - `zeroed`: a plain `Vec<u8>` of length 0, the library's other [`ShardBuf`] impl and what
//!   the FEC decoder passes today; growing it zero-fills the shard before the codec overwrites
//!   it. The difference between the two is that memset.
//!
//! Run: `cargo bench -p kcptun-kcp --bench rs` (results: `docs/benchmarks/fec.md`, step 04.7).

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use kcptun_kcp::rs::{Codec, Kernel, ShardBuf};

const DATA_SHARDS: usize = 10;
const PARITY_SHARDS: usize = 3;
const SHARD_LEN: usize = 1370;

/// Missing data shards of the reconstruct benchmarks (1 and `PARITY_SHARDS`).
const MISSING: [&[usize]; 2] = [&[0], &[0, 4, 9]];

/// The same fixed, non-trivial pattern as the Go bench (`byte(i*131 + 7)` over all data).
fn shards() -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = (0..DATA_SHARDS)
        .map(|s| {
            (0..SHARD_LEN)
                .map(|i| ((s * SHARD_LEN + i) * 131 + 7) as u8)
                .collect()
        })
        .collect();
    v.resize(DATA_SHARDS + PARITY_SHARDS, vec![0; SHARD_LEN]);
    v
}

/// A shard buffer that reuses initialised storage, like the pool buffer kcp-go passes to
/// `ReconstructData`: the whole buffer stays initialised and only the logical length changes,
/// so making a missing shard `SHARD_LEN` bytes long again costs nothing. (The codec overwrites
/// every byte of an output shard, which is why klauspost never clears them either.)
struct PoolShard {
    buf: Vec<u8>,
    len: usize,
}

impl PoolShard {
    fn new(data: &[u8]) -> PoolShard {
        PoolShard {
            buf: data.to_vec(),
            len: data.len(),
        }
    }

    /// Marks the shard missing (Go: `shards[i] = shards[i][:0]`).
    fn clear(&mut self) {
        self.len = 0;
    }
}

impl ShardBuf for PoolShard {
    fn shard(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    fn shard_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.len]
    }

    fn set_shard_len(&mut self, n: usize) {
        assert!(
            n <= self.buf.len(),
            "PoolShard: shard longer than the buffer"
        );
        self.len = n;
    }
}

fn new_codec(kernel: Kernel) -> Codec {
    let mut c = Codec::new(DATA_SHARDS, PARITY_SHARDS).expect("valid (10, 3) code");
    c.set_kernel(kernel);
    c
}

fn bench_rs(c: &mut Criterion) {
    let shape = format!("{DATA_SHARDS}x{PARITY_SHARDS}/{SHARD_LEN}");

    let mut g = c.benchmark_group("rs/encode");
    g.throughput(Throughput::Bytes((DATA_SHARDS * SHARD_LEN) as u64));
    for kernel in Kernel::available() {
        let codec = new_codec(kernel);
        let mut shards = shards();
        g.bench_function(BenchmarkId::new(kernel.name(), &shape), |b| {
            b.iter(|| codec.encode(black_box(&mut shards)).expect("encode"))
        });
    }
    g.finish();

    let mut g = c.benchmark_group("rs/reconstruct_data");
    g.throughput(Throughput::Bytes((DATA_SHARDS * SHARD_LEN) as u64));
    for missing in MISSING {
        for kernel in Kernel::available() {
            let mut coded = shards();
            new_codec(kernel).encode(&mut coded).expect("encode");
            let want = coded.clone();

            // Go-equivalent: the missing shards come back as initialised buffers.
            let mut codec = new_codec(kernel);
            let mut pool: Vec<PoolShard> = coded.iter().map(|s| PoolShard::new(s)).collect();
            let id = BenchmarkId::new(
                kernel.name(),
                format!("{shape}/missing{}/reused", missing.len()),
            );
            g.bench_function(id, |b| {
                b.iter(|| {
                    for &m in missing {
                        pool[m].clear();
                    }
                    codec
                        .reconstruct_data(black_box(&mut pool))
                        .expect("reconstruct");
                })
            });
            for (k, (s, w)) in pool.iter().zip(&want).enumerate() {
                assert_eq!(s.shard(), &w[..], "{kernel}: reused shard {k}");
            }

            // Plain `Vec<u8>` shards: the codec zero-fills every missing shard first.
            let mut codec = new_codec(kernel);
            let mut shards = coded.clone();
            let id = BenchmarkId::new(
                kernel.name(),
                format!("{shape}/missing{}/zeroed", missing.len()),
            );
            g.bench_function(id, |b| {
                b.iter(|| {
                    for &m in missing {
                        shards[m].clear();
                    }
                    codec
                        .reconstruct_data(black_box(&mut shards))
                        .expect("reconstruct");
                })
            });
            assert_eq!(shards, want, "{kernel}: zeroed reconstruct_data result");
        }
    }
    g.finish();
}

criterion_group!(benches, bench_rs);
criterion_main!(benches);
