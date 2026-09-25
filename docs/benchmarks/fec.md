# FEC and Reed-Solomon: Rust vs Go (plan 04.7)

Per-packet cost of the FEC encoder and decoder, and of the Reed-Solomon codec underneath them, for
kcptun's default shape (`-datashard 10 -parityshard 3`). Go is the pinned kcp-go v5.6.66 `fec.go`
with klauspost/reedsolomon v1.13.0; Rust is `kcptun-kcp::fec` and `kcptun-kcp::rs` at the `[04.7]`
commit on `step/04-fec`. Both sides run the same algorithm on the same data; the FEC packets are
byte-identical (golden vectors, step 04.6).

## Benchmarks

One iteration is **one packet** (FEC) or **one group operation** (RS). Packets and shards are 1370
bytes, a full KCP segment at the default MTU; the FEC header offset is 0, as in kcp-go's own
`BenchmarkFECEncode`.

| Name | What one iteration does |
|---|---|
| `fec/encode` | `fecEncoder.encode(pkt, rto=500)` of one 1370-byte packet with a **fixed clock**, so every group counts as continuous (the fixed clock also removes Go's per-packet `time.Now().UnixMilli()`, which the Rust port never pays because `encode` takes `now_ms` from the caller: the Go encode figure is therefore a lower bound on real kcp-go and the ratio is conservative): the packet is sealed and copied into the shard cache, and every tenth call also RS-encodes the group's 3 parity shards and seals them (steady state, parity amortised over 10 packets). |
| `fec/decode/…/loss0` | `fecDecoder.decode(pkt)` of one received packet of a complete group (10 data + 3 parity). The 10th data packet completes a full shard set (no RS work, `FECFullShardSet++`); the 3 parity packets that follow are stored and later discarded. |
| `fec/decode/…/loss1` | Same, with one data packet lost per group (the lost index rotates through 0..9), so the first parity packet of each group triggers `ReconstructData` of 1 shard: 12 received packets per group, one recovery. |
| `rs/encode` | `Encode`: all 3 parity shards from the 10 data shards. |
| `rs/reconstruct_data/…/missing1`, `missing3` | `ReconstructData` with 1 or 3 data shards missing (`{0}` and `{0, 4, 9}`). |

The decoder benchmarks replay one prepared group with its seqids rewritten so the groups advance,
which keeps the decoder in the steady state (shard sets created, decoded and discarded) without
allocating input packets inside the timed loop. The Go side returns the recovered buffers to
`defaultBufferPool` inside the loop, as `sess.go` does; the Rust side drops them.

**Two shapes of missing shard in `reconstruct_data`.** kcp-go hands klauspost a **pool buffer**
resliced to length 0 (`defaultBufferPool.Get()[:0]`), and klauspost grows it back to the shard size
over its stale bytes without clearing (the codec overwrites every output byte anyway). The two rows
per case are:

- `reused`: a shard buffer that keeps its initialised storage and only moves a logical length
  (`PoolShard` in `benches/rs.rs`). **This is the like-for-like comparison with Go.**
- `zeroed`: a plain `Vec<u8>` of length 0, the library's other `ShardBuf` impl and what
  `fec::FecDecoder` passes today: growing it zero-fills the shard first. The difference between the
  two rows is exactly that memset, which is cheap on macOS and expensive against musl (see
  *Observations*).

## Methodology

- **Go:** `tools/govectors/internal/kcpcopy/fec_bench_test.go` (`BenchmarkFEC`, on the verbatim
  copy of the pinned `fec.go` with its injectable clock) and `tools/govectors/bench_test.go`
  (`BenchmarkRS`, the pinned klauspost codec directly). `b.SetBytes` is the packet length (FEC) or
  the data bytes, 10 × 1370 (RS); `-benchtime 1s`, `-count 3` on the laptop, 3 runs on lab-arm64.
  - Laptop: `cd tools/govectors && go test ./internal/kcpcopy -run '^$' -bench FEC -benchtime 1s
    -count 3` and `go test -run '^$' -bench RS …`, with `GOMODCACHE=$PWD/../../reference/gomod
    GOFLAGS=-modcacherw GOTOOLCHAIN=local`.
  - lab-arm64: `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c` → `kg-bench-fec`, `kg-bench-rs`,
    run with `-test.run '^$' -test.bench FEC|RS -test.benchtime 1s`.
- **Rust:** `crates/kcp/benches/fec.rs` and `crates/kcp/benches/rs.rs` (criterion 0.8, release
  profile: fat LTO, 1 CGU). Values are criterion **medians**.
  - Laptop: `cargo bench -p kcptun-kcp --bench fec -- --noplot --warm-up-time 1 --measurement-time
    3` (`--bench rs` with `--measurement-time 2`).
  - lab-arm64: `cargo-zigbuild test -p kcptun-kcp --bench {fec,rs} --release --no-run --target
    aarch64-unknown-linux-musl`, copied to `~/kcptun-lab/tests/bench/` as `kr-bench-fec` /
    `kr-bench-rs`, run with `--bench --noplot --warm-up-time 0.3 --measurement-time 1`. The musl
    build uses musl's **system allocator and libc** (mimalloc was not wired in for this round; D07 has since rejected it).
- **Machines.**
  - Laptop: Apple **M5** (10 cores), macOS 27.0, Go 1.27.1 darwin/arm64, Rust 1.98.1. Rust kernel:
    `neon`.
  - lab-arm64: **Neoverse-N1**, 2 vCPU, Ubuntu 24.04, shared with live services; load average 0.1–0.7
    during the runs, Go and Rust interleaved (A/B/A/B), each run well under 60 s (LAB.md §2). Treat
    these numbers as ±5%. Rust kernel: `neon`.
- The `scalar` rows are the portable fallback (no SIMD), measured only to show what the NEON kernels
  buy; no kcptun build uses them on these machines.
- Absolute numbers drift by up to ~8% between passes on both machines (thermal state, background
  load), in Go and in Rust alike. Each table therefore comes from **one interleaved Go/Rust pass**;
  the ratios repeated to within ±5% across all passes.

## Acceptance (plan 04.7: Rust ≤ Go ns/op on both NEON machines)

**Met everywhere.** The FEC encoder and decoder and the RS codec are faster than Go on both the M5
and the N1, in the like-for-like (`reused`) shape and also in the `zeroed` shape the FEC decoder
uses today.

## Results: laptop (Apple M5)

Time per iteration, ns (lower is better); "×Go" = Go time / Rust time.

| Benchmark | Go | Rust | ×Go |
|---|---:|---:|---:|
| fec/encode (per packet) | 131.6 | 85.9 | **1.53** |
| fec/decode loss0 (per packet) | 127.6 | 83.3 | **1.53** |
| fec/decode loss1 (per packet) | 190.0 | 120.0 | **1.58** |
| rs/encode | 1,186 | 641 | **1.85** |
| rs/reconstruct missing1 `reused` | 650 | 366 | **1.77** |
| rs/reconstruct missing1 `zeroed` | 650 | 383 | 1.70 |
| rs/reconstruct missing3 `reused` | 1,325 | 688 | **1.93** |
| rs/reconstruct missing3 `zeroed` | 1,325 | 747 | 1.78 |

Rust scalar fallback (same machine, for reference): encode 10,040 ns, reconstruct missing1 3,493 ns,
missing3 9,798 ns: 9.5–16× slower than the NEON kernels.

## Results: lab-arm64 (Neoverse-N1)

| Benchmark | Go | Rust | ×Go |
|---|---:|---:|---:|
| fec/encode (per packet) | 411.1 | 335.3 | **1.23** |
| fec/decode loss0 (per packet) | 459.5 | 215.9 | **2.13** |
| fec/decode loss1 (per packet) | 710.1 | 402.9 | **1.76** |
| rs/encode | 3,614 | 2,586 | **1.40** |
| rs/reconstruct missing1 `reused` | 2,220 | 1,437 | **1.54** |
| rs/reconstruct missing1 `zeroed` | 2,220 | 1,885 | 1.18 |
| rs/reconstruct missing3 `reused` | 4,335 | 2,763 | **1.57** |
| rs/reconstruct missing3 `zeroed` | 4,335 | 4,178 | 1.04 |

Rust scalar fallback: encode 28,382 ns, reconstruct missing1 9,747 ns, missing3 27,764 ns, 6.8–11×
slower than NEON.

Per group at the production shape this means, on the N1: a sender spends ~3.4 µs of FEC per 10
packets sent (Go ~4.1 µs), and a receiver ~4.8 µs per group with one loss recovered (Go ~8.5 µs).

## Observations

- **A `ReconstructData` call carries ~0.2 µs of fixed overhead.** On the N1, recovering one shard
  costs 1.44 µs, of which about 0.18 µs is per-call overhead: ~150 ns for the four small `Vec`s
  (valid indices, inputs, outputs, matrix rows) and ~30 ns for the SipHash of the 32-byte
  inversion-cache key, both measured directly, and the rest is the NEON coding of one output from
  10 × 1370 input bytes. Go pays the same kind of overhead (`984 B/op, 5 allocs/op`) with a faster
  allocator, which is part of why the ratio drops from 1.9× (M5) to 1.5× (N1).
- **musl's `memset` is the largest single overhead on Linux.** Zero-filling the 3 recovered shards
  (4,110 bytes) takes **1.42 µs** on the N1 musl build: more than half of the ~2.6 µs the NEON
  coding of those 3 shards needs, and the whole `reused` → `zeroed` difference (2.76 → 4.18 µs).
  musl's generic `memset` moves about 2.9 GB/s there. The same `reused` → `zeroed` delta on the
  M5 is only ~59 ns for those 4,110 bytes (~70 GB/s, macOS libc; a bare `memset` microbenchmark
  there measured ~27 ns, the table delta also carrying `Vec::resize`'s capacity check). It is why the `zeroed` shape only just meets the bar on the N1 (1.04×).
  - Go never pays it: its pool buffers are already initialised and klauspost reslices over the stale
    bytes.
  - Rust cannot skip it safely for a `Vec<u8>` that was handed over empty: the spare capacity is
    uninitialised. The fix is to hand the codec buffers that are already initialised: a buffer pool
    whose entries keep their full length, exactly the `PoolShard` shape measured here. That is the
    Step 05 / Step 12 buffer-pool work (D06), and it is worth ~0.45 µs per recovered shard on
    musl/aarch64.
- **The FEC decoder's fast path is where Rust gains most** (2.1× on the N1, `loss0`): Go allocates
  and pool-copies every received packet and hashes into `map[uint32]*shardHeap`, while the Rust port
  does the same work with one `Vec` copy and a `HashMap` entry. Both still allocate per packet
  (Rust: one `Vec` per stored packet, `163 B/op, 2 allocs/op` on the Go side); pooling is a Step 12
  item for both the decoder's stored packets and the recovered shards.
- **The encoder is copy-bound**, not coding-bound: 10 of 13 packets only seal a header and copy
  1370 bytes into the shard cache. Rust is 1.23–1.53× Go there, which is the memcpy plus the
  amortised RS encode.
- Apart from the memset-dominated `zeroed` reconstruct rows (4.9× and 5.6×), the N1 numbers are
  2.6–4.0× the M5 numbers, in line with the crypto and KCP benchmarks
  (`docs/benchmarks/crypto.md`, `docs/benchmarks/kcp.md`).

## Follow-ups (Step 12)

1. **Buffer pool for shard buffers** (D06, with Step 05): keep recovered-shard and stored-packet buffers
   at full length so `set_shard_len` is a truncation, removing the per-shard memset (~0.45 µs per
   recovered 1370-byte shard on musl/aarch64) and the per-packet allocation.
2. **Per-call scratch in `rs::Codec`**: the `valid_indices` / `inputs` / `outputs` / `matrix_rows`
   vectors are rebuilt on every `reconstruct_data` (~150 ns on the N1, ~10% of a 1-shard recovery),
   and `Codec::encode` rebuilds `inputs` / `outputs` / `rows` on every call (measured inside
   `rs/encode`; Go's klauspost `Encode` reports 24 B/op, 1 alloc/op against 3 Rust `Vec`s), as does
   `FecEncoder::encode` with its per-group `Vec<&mut [u8]>` of shard slices (the 04.4 deferral).
   A reusable scratch area inside the codec and the encoder would remove them all.
3. **Inversion-cache key**: the 32-byte bitmask key with the default SipHash hasher costs ~30 ns per
   recovery on the N1. A cheaper hash (or a small direct-mapped cache, since kcp-go sees only a
   handful of erasure patterns) would remove most of it.
4. `rs::Codec::new` is expensive for large shard counts (~12.7 ms for (249, 7) in release, 04.6
   note). It runs once per session and once per auto-tune retune, so it never shows here, but a
   malicious peer can force retunes: Step 12 should bound or cache codec construction.
