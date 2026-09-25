//! FEC encoder/decoder benchmarks (plan step 04.7), the Rust side of `BenchmarkFEC` in
//! `tools/govectors/internal/kcpcopy/fec_bench_test.go` (the pinned kcp-go v5.6.66 `fec.go`).
//! The Reed-Solomon codec alone is `benches/rs.rs`. Methodology and results:
//! `docs/benchmarks/fec.md`.
//!
//! kcptun's default shape: groups of 10 data + 3 parity shards, header offset 0 (like kcp-go's
//! `BenchmarkFECEncode`), 1370-byte packets. One iteration is one packet; throughput is the
//! packet length.
//!
//! - `fec/encode`: [`FecEncoder::encode`] of one packet with a fixed clock, so every group is
//!   continuous and every tenth call RS-encodes the group's 3 parity shards (steady state).
//! - `fec/decode/.../loss0`, `loss1`: [`FecDecoder::decode`] of one received packet. One
//!   prepared group (10 data + 3 parity packets from the encoder) is fed over and over with its
//!   seqids rewritten to advance group by group. `loss0` delivers every packet (the 10th data
//!   packet completes a full shard set, no RS); `loss1` drops one data packet per group (the
//!   index rotates through 0..9), so the first parity packet triggers `reconstruct_data` of one
//!   shard. The recovered buffers are dropped, as the session drops them after feeding KCP.
//!
//! Run: `cargo bench -p kcptun-kcp --bench fec`.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use kcptun_kcp::fec::{FEC_HEADER_SIZE, FEC_HEADER_SIZE_PLUS2, FecDecoder, FecEncoder};

const DATA_SHARDS: usize = 10;
const PARITY_SHARDS: usize = 3;
const SHARD_SIZE: usize = DATA_SHARDS + PARITY_SHARDS;
const PACKET_LEN: usize = 1370;
/// The fixed encoder clock (any value works: only differences matter).
const NOW_MS: i64 = 1_758_000_000_000;
/// The `rto` the session passes to `FecEncoder::encode` (Go: `sess.go:maxFECEncodeLatency`).
const RTO: u32 = kcptun_kcp::fec::MAX_FEC_ENCODE_LATENCY;

/// A packet whose bytes after the FEC header and size field are `(seq * PACKET_LEN + i) * 131
/// + 7`, the pattern of the Go bench (`benchFECPacket`).
fn packet(seq: usize) -> Vec<u8> {
    (0..PACKET_LEN)
        .map(|i| {
            if i < FEC_HEADER_SIZE_PLUS2 {
                0
            } else {
                ((seq * PACKET_LEN + i) * 131 + 7) as u8
            }
        })
        .collect()
}

fn encoder() -> FecEncoder {
    FecEncoder::new(DATA_SHARDS as isize, PARITY_SHARDS as isize, 0)
        .expect("valid (10, 3) code")
        .expect("FEC enabled")
}

fn decoder() -> FecDecoder {
    FecDecoder::new(DATA_SHARDS as isize, PARITY_SHARDS as isize).expect("valid (10, 3) code")
}

/// One encoded group: 10 data and 3 parity packets, seqids 0..=12.
fn group() -> Vec<Vec<u8>> {
    let mut enc = encoder();
    let mut group = Vec::with_capacity(SHARD_SIZE);
    for s in 0..DATA_SHARDS {
        let mut pkt = packet(s);
        let ps: Vec<Vec<u8>> = enc
            .encode(&mut pkt, RTO, NOW_MS)
            .expect("encode")
            .iter()
            .map(<[u8]>::to_vec)
            .collect();
        group.push(pkt);
        group.extend(ps);
    }
    assert_eq!(group.len(), SHARD_SIZE, "group size");
    group
}

/// Feeds the decoder the group's packets in a loop, rewriting seqids so that groups advance;
/// with `loss`, data packet `g % DATA_SHARDS` of group `g` is never delivered.
struct Feeder {
    group: Vec<Vec<u8>>,
    loss: bool,
    /// Seqid of the current group's first packet.
    base: u32,
    pos: usize,
    g: usize,
    paws: u32,
}

impl Feeder {
    fn new(loss: bool) -> Feeder {
        Feeder {
            group: group(),
            loss,
            base: 0,
            pos: 0,
            g: 0,
            paws: u32::MAX / SHARD_SIZE as u32 * SHARD_SIZE as u32,
        }
    }

    /// Delivers the next packet; returns the recovered shards.
    #[inline(always)]
    fn step(&mut self, dec: &mut FecDecoder) -> Vec<Vec<u8>> {
        if self.loss && self.pos == self.g % DATA_SHARDS {
            self.pos += 1; // this group's lost data packet
        }
        let pkt = &mut self.group[self.pos];
        pkt[..4].copy_from_slice(&self.base.wrapping_add(self.pos as u32).to_le_bytes());
        let rec = dec.decode(black_box(pkt));
        self.pos += 1;
        if self.pos == SHARD_SIZE {
            self.pos = 0;
            self.g += 1;
            self.base = self.base.wrapping_add(SHARD_SIZE as u32) % self.paws;
        }
        rec
    }
}

/// Checks the decode benchmark's input: with one loss per group, every group recovers exactly
/// the lost data shard (and nothing without loss).
fn check_feeder() {
    let group = group();
    for loss in [false, true] {
        let mut dec = decoder();
        let mut f = Feeder::new(loss);
        for g in 0..25 {
            let mut got = Vec::new();
            for _ in 0..SHARD_SIZE - usize::from(loss) {
                got.extend(f.step(&mut dec));
            }
            if loss {
                let lost = g % DATA_SHARDS;
                assert_eq!(got.len(), 1, "group {g}: recovered shards");
                assert_eq!(got[0], group[lost][FEC_HEADER_SIZE..], "group {g}: shard");
            } else {
                assert!(got.is_empty(), "group {g}: recovered without loss");
            }
        }
    }
}

fn bench_fec(c: &mut Criterion) {
    check_feeder();
    let shape = format!("{DATA_SHARDS}x{PARITY_SHARDS}/{PACKET_LEN}");

    let mut g = c.benchmark_group("fec");
    g.throughput(Throughput::Bytes(PACKET_LEN as u64));

    let mut enc = encoder();
    let mut pkt = packet(0);
    let (mut calls, mut parity) = (0usize, 0usize);
    g.bench_function(BenchmarkId::new("encode", &shape), |b| {
        b.iter(|| {
            let ps = enc
                .encode(black_box(&mut pkt), RTO, black_box(NOW_MS))
                .expect("encode");
            calls += 1;
            parity += black_box(ps).len();
        })
    });
    // Every group of DATA_SHARDS calls emits its parity (criterion's --test mode runs one call).
    assert!(calls < DATA_SHARDS || parity > 0, "no parity generated");

    for loss in [false, true] {
        let mut dec = decoder();
        let mut f = Feeder::new(loss);
        let id = BenchmarkId::new("decode", format!("{shape}/loss{}", u8::from(loss)));
        g.bench_function(id, |b| b.iter(|| f.step(&mut dec)));
    }
    g.finish();
}

criterion_group!(benches, bench_fec);
criterion_main!(benches);
