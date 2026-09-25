# KCP ARQ core: Rust vs Go (plan 03.6)

Baseline for Step 12. Both sides run the **same algorithm**: the Rust side is the naive, line-by-line
port of kcp-go's `kcp.go` (the permanent test oracle, DECISIONS D25), and the Go side is a verbatim
copy of the pinned kcp-go v5.6.66 core (`tools/govectors/internal/kcpcopy`, identical except for an
injectable clock). No algorithmic optimisation has been applied yet. The differences come only from the
language, runtime and allocator.

> The `flush` and `input_ack` rows below are the **baseline**, not what the port does today: plan
> 12.2c made `flush` skip the part of `snd_buf` it has already scanned (Decision D29) and 12.2d made
> the ACK path address a segment by its sequence number (Decision D31). Both naive scans stay in the
> code as the D25 oracle and keep benchmark ids of their own, so the baseline stays measurable and
> comparable with Go for ever. [§ 12.2c](#122c--skipping-the-scanned-part-of-snd_buf) and
> [§ 12.2d](#122d--addressing-the-acknowledged-segment-instead-of-searching-for-it) have the after
> numbers, and [§ 12.2e](#122e--the-same-two-decisions-on-a-neoverse-n1) has them for aarch64.
> The Neoverse-N1 `flush` row below is 7 % slower than the "before" 12.2c measured against, and
> [§ 12.1](#121--attributing-the-8--gap-between-the-036-and-122c-baselines) attributes that step
> to `[12.2a]`: **do not quote the two tables as one series** without reading it.

## Benchmarks

| Name | What one iteration does |
|---|---|
| `flush/snd_buf=<n>` | kcp-go's `BenchmarkFlush`: `flush(IKCP_FLUSH_FULL)` over a ring of `n` slots holding `n − 1` segments already sent once, none due. It scans the whole window. `n` = 1024 (Go's bench) and 8192 (the production window). |
| `input_ack/in_order/<w>` | Input the ACK packets acknowledging a full window of `w` in-flight segments (58 ACKs per 1400-byte packet, as a kcp-go receiver packs them), each carrying the cumulative `una`. Setup is excluded from timing on both sides. |
| `input_ack/sack/<w>` | Same, but the first segment was lost: `una` stays 0, every ACK is selective, and each packet triggers a fast-retransmit flush. |
| `input_ack/sack_oracle/<w>` | The same selective-ACK scenario with the D29 and D31 fast paths off: the naive line-by-line port, the D25 oracle and the "before" of 12.2d. Added in 12.2d. |
| `input_ack/in_order_oracle/<w>` | The same in-order scenario with the D29 and D31 fast paths off. Added in 12.2e, which found that the in-order path is not D29-neutral after all: `Kcp::input` flushes whenever the send window slides, so every one of these packets pays a `flush`. |
| `send_flush/64KiB` | Stream-mode sender/receiver pair with windows of 1024: send 64 KiB, flush, input every packet into the receiver, read everything, flush the receiver's ACKs and input them into the sender. |

- **Go:** `tools/govectors/internal/kcpcopy/bench_test.go`.
  - Laptop: `cd tools/govectors && go test ./internal/kcpcopy -run '^$' -bench . -benchtime 2s -benchmem`,
    with `GOMODCACHE=$PWD/../../reference/gomod GOFLAGS=-modcacherw GOTOOLCHAIN=local`.
  - lab-arm64: `GOOS=linux GOARCH=arm64 go test -c`, then `-test.benchtime 1s`.
- **Rust:** `crates/kcp/benches/kcp.rs` (criterion 0.8, release profile: fat LTO, 1 CGU), median.
  - Laptop: `cargo bench -p kcptun-kcp --bench kcp -- --noplot`.
  - lab-arm64: built with `cargo-zigbuild test -p kcptun-kcp --bench kcp --release --no-run --target
    aarch64-unknown-linux-musl`, run with `--bench --noplot --warm-up-time 0.5 --measurement-time 2`.
  - The musl build uses musl's **system allocator** (mimalloc was not wired in for this round; D07 has since rejected it).
- **Machines.**
  - Laptop: Apple M5, macOS 27.0, Go 1.27.1, Rust 1.98.1.
  - lab-arm64: Neoverse-N1, 2 vCPU, Ubuntu 24.04, shared with live services (load average 0.1–1.0 during
    the run), so treat those numbers as ±10%.
- Code at the `[03.6b]` commit on `step/03-kcp-arq`.

## Results

Time per iteration (lower is better); "Rust speed-up" = Go time / Rust time.

| Benchmark | M5 Go | M5 Rust | M5 speed-up | N1 Go | N1 Rust | N1 speed-up |
|---|---:|---:|---:|---:|---:|---:|
| flush/snd_buf=1024 | 2.25 µs | 1.32 µs | **1.70×** | 7.37 µs | 3.86 µs | **1.91×** |
| flush/snd_buf=8192 | 17.97 µs | 8.16 µs | **2.20×** | 63.3 µs | 30.8 µs | **2.06×** |
| input_ack/in_order/1024 | 50.8 µs | 18.5 µs | **2.74×** | 191 µs | 65.5 µs | **2.92×** |
| input_ack/in_order/8192 | 1.475 ms | 0.529 ms | **2.79×** | 5.64 ms | 2.22 ms | **2.54×** |
| input_ack/sack/1024 | 1.794 ms | 0.602 ms | **2.98×** | 5.27 ms | 2.30 ms | **2.29×** |
| input_ack/sack/8192 | 118.8 ms | 42.9 ms | **2.77×** | 347.7 ms | 143.6 ms | **2.42×** |
| send_flush/64KiB | 12.41 µs | 8.29 µs | **1.50×** | 43.6 µs | 41.9 µs | **1.04×** |

These figures are the `[03.6b]` commit's and nothing else's. Two of the Rust columns moved later
through unrelated code changes: `flush` by −7 % at `[12.2a]` and `in_order` by +8 % somewhere
before it, so a Rust number from this table may not be differenced against one from a later
section. [§ 12.1](#121--attributing-the-8--gap-between-the-036-and-122c-baselines) measures both
steps and says which figure belongs to which commit.

Go allocates about one object per acknowledged segment in `input_ack` (pool traffic from
`recycleSegment`) and 192 objects per `send_flush` iteration. On lab-arm64 the Rust `send_flush` result is
dominated by musl's allocator (one `Vec` per segment). Pooled segment buffers and mimalloc were Step 12
candidates; Step 12 pooled the buffers, and D07 rejected mimalloc.

## 12.2c: skipping the scanned part of `snd_buf`

`flush` no longer rescans the segments it has already looked at (Decision D29). The naive scan stays
in the code and keeps a benchmark id of its own, `snd_buf_oracle`, so the baseline above stays
measurable, stays comparable with Go's `BenchmarkFlush`, and can be differential-tested against the
optimised path on the same build (`crates/kcp/src/kcp/scan_tests.rs`, DECISIONS D25).

### What dominates the scan

Measured **before** choosing a structure, on the M5 at `snd_buf` = 8192, in one run, by changing what
the loop body has to do and nothing else:

| the loop body does | per flush | per segment |
|---|---:|---:|
| the full predicate and branch chain (the `flush/snd_buf` bench above) | 9.91 µs | 1.21 ns |
| nothing but `if acked == 1 { continue }`: one load and a branch | 3.87 µs | 0.47 ns |
| nothing at all: `snd_buf` empty, so there is no loop | 0.023 µs | - |

So 39 % of the cost is the bare walk over 8192 × 64 B of `Segment` and 61 % is the predicate.
**Neither dominates, and the floor for any structure that still visits every segment is 3.87 µs**: a
min-heap or a time wheel on `resendts` would pay that floor and then add its own bookkeeping on top.
Only not touching the segments wins, which is what D29 does: the flush proves the head of the window
is a no-op from a three-field summary and starts the loop past it.

### Result

M5, medians of **five** runs of each build, interleaved one after another so that thermal drift
cancels (this bench has a ±20 % run-to-run spread on a laptop, so single runs say nothing).
"Before" is the bench binary built at the parent commit; "after" is this one, whose `snd_buf` id is
the optimised path and whose `snd_buf_oracle` id is the same naive scan as "before" plus the
bookkeeping D29 needs:

```
cargo bench -p kcptun-kcp --bench kcp -- --noplot 'kcp/flush' --warm-up-time 1 --measurement-time 5
```

| Benchmark | before (naive) | after (`snd_buf`) | speed-up | after, oracle path | Go `BenchmarkFlush` |
|---|---:|---:|---:|---:|---:|
| flush/1024 | 1.127 µs | **25.5 ns** | **44×** | 1.410 µs | 2.25 µs → 88× |
| flush/8192 | 8.790 µs | **25.3 ns** | **347×** | 11.45 µs | 17.97 µs → 710× |

The same four columns on the Neoverse-N1 (lab-arm64, method and caveats in
[§ 12.2e](#122e--the-same-two-decisions-on-a-neoverse-n1)):

| Benchmark | before (naive) | after (`snd_buf`) | speed-up | after, oracle path | Go `BenchmarkFlush` |
|---|---:|---:|---:|---:|---:|
| flush/1024 | 3.569 µs | **70.2 ns** | **50.8×** | 3.928 µs | 7.327 µs → 104× |
| flush/8192 | 28.576 µs | **70.1 ns** | **408×** | 31.221 µs | 63.218 µs → 902× |

The two window sizes now measure the same, because neither touches a segment: at the production
window the flush is O(1) instead of O(8192), and what is left is the ack list, the probe checks and
the SNMP stores.

### What it costs, and when

The skip does **not** fire when a segment is within one `interval` of its retransmission timeout,
when a duplicate ACK is outstanding, or on the flush right after either. Those flushes take the
oracle path, and the summary is rebuilt exactly from it. In a healthy `-mode normal` transfer
(`interval` 40 ms, RTO ≥ 100 ms) a segment is acknowledged long before it comes within 40 ms of
falling due, so a full scan happens roughly once per RTO instead of on every flush.

That path is **26–30 % slower than it was on the M5** (the last column of the first table above
against its first: 1.25× at 1024, 1.30× at 8192, consistent across all five pairs), but only
**9–10 % slower on the N1** (1.100× at 1024, 1.093× at 8192). See
[§ 12.2e](#122e--the-same-two-decisions-on-a-neoverse-n1): the summary costs the same ~0.32 ns per
segment on both machines, and the N1's loop was three times slower to begin with, so the same
absolute cost is a third of the relative one. The summary costs three register operations per
segment: a count, a branchless fastack test and a running minimum of the `resendts - current` the
loop computes anyway, and the loop body was only about 30 operations to begin with. It is a
deliberate trade, not an oversight: at a plausible one full scan in ten, the average flush at 8192
goes from 8.79 µs to `0.9 × 0.025 + 0.1 × 11.45 ≈ 1.17 µs`, still **7.5× better than before and 15×
better than Go**. It does mean a transfer in a real loss storm, where nearly every flush has
something due: pays 30 % more per flush at the KCP level than it used to.

**The lab-arm64 (Neoverse-N1) numbers were taken in 12.2e**, and the two predictions this section
made came out one right and one wrong. *Right:* the ratio is larger on the N1: **408× at 8192**
against the M5's 347×, and 50.8× against 44× at 1024. *Wrong:* the 26–30 % on the oracle path is
**not** what an N1 pays; it pays **9–10 %**. The pathological case: a sustained loss storm where
nearly every flush has something due: is therefore three times cheaper on the deployment
architecture than the laptop measurement implied. 12.2e also found an effect this section missed
entirely: because `Kcp::input` flushes every time the send window slides, D29 makes the *ordinary*
in-order ACK path **6.6× faster** at the production window, which is a bigger practical win than the
loss-storm cost is a loss.

## 12.2d: addressing the acknowledged segment instead of searching for it

`parse_ack` no longer walks `snd_buf` looking for the sequence number an ACK names, and
`parse_fastack` no longer tests every segment to find out where to stop (Decision D31). The ring
holds `snd_una ..< snd_nxt` in ascending order with no gaps, so the segment is at offset
`sn - snd_una`; `Kcp::snd_buf_offset` states the four places that keep that true, checks the segment
it lands on and falls back to kcp-go's scan if it is not the right one.

### Result

M5, medians of **five** interleaved rounds per pair, two binaries built from the parent commit and
from this one and run one after the other (this bench has a wide run-to-run spread on a laptop,
the machine was shared with other work during the runs, so single runs say nothing):

```
cargo bench -p kcptun-kcp --bench kcp -- --noplot 'kcp/(flush|input_ack/sack)' \
    --warm-up-time 0.5 --measurement-time 2
```

| Benchmark | before (naive) | after | speed-up | same-build oracle id | Go `BenchmarkInputAck` |
|---|---:|---:|---:|---:|---:|
| input_ack/sack/1024 | 639 µs | **386 µs** | **1.65×** | 616 µs | 1.794 ms → 4.6× |
| input_ack/sack/8192 | 43.48 ms | **24.97 ms** | **1.74×** | 42.84 ms | 118.8 ms → 4.8× |
| input_ack/in_order/1024 | 12.25 µs | 12.70 µs | 0.96× (noise) | - | 50.8 µs |
| input_ack/in_order/8192 | 104 µs | 118 µs | 0.89× (noise) | - | 1.475 ms |

The `sack` rows are the median of **ten** interleaved rounds (a five-round set over
`kcp/(flush|input_ack)` and a five-round set over `kcp/(flush|input_ack/sack)`); the `in_order` rows
are the five rounds of the first set. The `sack_oracle` column comes from a third five-round set
after the id was added: it is the same scenario in the *after* binary with the fast paths switched
off, and it lands within 3 % of the separately built "before" at 8192 (8 % at 1024, where the
numbers are smaller and the spread wider). That agreement is what makes the cross-binary comparison
trustworthy, and it keeps the "before" reproducible from one build for ever.

These absolute times come from binaries that predate the `in_order_oracle` id added in 12.2e; adding
it shifts the whole `input_ack` group by about 7 % through code layout alone, so compare ratios
within one binary, not absolute times across builds
([§ 12.2e](#122e--the-same-two-decisions-on-a-neoverse-n1), "One caveat").

The same two selective-ACK rows on the Neoverse-N1 (lab-arm64, method and caveats in
[§ 12.2e](#122e--the-same-two-decisions-on-a-neoverse-n1)):

| Benchmark | before (naive) | after | speed-up | same-build oracle id | Go `BenchmarkInputAck` |
|---|---:|---:|---:|---:|---:|
| input_ack/sack/1024 | 2.309 ms | **1.454 ms** | **1.59×** | 2.306 ms | 5.330 ms → 3.7× |
| input_ack/sack/8192 | 143.03 ms | **85.61 ms** | **1.67×** | 143.59 ms | 351.84 ms → 4.1× |

The N1's `sack_oracle` agrees with its separately built "before" to **0.4 % at 8192 and 0.1 % at
1024** (far tighter than the M5's 3 % and 8 %, because the box was quiet) so the cross-binary
comparison is on firmer ground here than it was on the laptop. The N1 `in_order` rows are **not**
repeated in this table, because its "before" binary is the parent of **12.2c**, not of 12.2d, so it
carries D29 as well; D31 cannot touch `in_order` on either machine, for the reason immediately
below, but D29 turns out to touch it a great deal, and § 12.2e measures that on its own terms.

**`in_order` is unchanged by D31, and cannot change.** A kcp-go receiver puts its cumulative `una` into
every ACK of the packet, and `Input` applies it (`parse_una`, then `shrink_buf`) before it looks at
the command, so the acknowledged segments have already left `snd_buf` and the guard at the top of
`parse_ack`/`parse_fastack` rejects every one of them. Nothing reaches the offset at all; that is why
`in_order` was two orders of magnitude cheaper than `sack` to begin with. The two `in_order` rows
above are pure noise: on the M5 that scenario swung between 93 µs and 733 µs across eleven rounds
*of both binaries*.

What this paragraph got wrong, and § 12.2e corrects, is the wider claim that `in_order` is
unaffected by 12.2 altogether. It is unaffected by **D31**; it is not unaffected by **D29**, because
`Kcp::input` calls `flush(IKCP_FLUSH_FULL)` every time the send window slides
(`crates/kcp/src/kcp.rs`, "Determine if we need to flush data segments or acks"; Go:
kcp-go/v5 `kcp.go:Input`), and in this scenario every packet slides it. On a quiet N1 that is
**6.6×** at the production window. It did not show on the M5 only because the M5 pair was built
either side of 12.2d, with D29 already present in both halves.

### What is left, and why it is not an index

Half the selective-ACK cost is gone: the half that was `parse_ack` searching. The other half is
`parse_fastack`, and it is **inherently** proportional to how far into the window the ACK reaches:
every segment before `sn` that was sent no later than it has its `fastack` raised by one, so the
work is one read-modify-write per segment, not a search. At 8192 that is ~4096 segments × 64 B of
`Segment` per ACK, and the measured 24.97 ms over 8191 ACKs is 0.74 ns per segment: level with what
`flush`'s bare walk costs (0.47 ns/segment, § 12.2c), i.e. the loop is already at the memory
bandwidth of the ring and not at its arithmetic.

Going below that means not *touching* the `Segment`: keeping `(ts, fastack)` in a packed 8-byte
side array, an 8× cut in bytes streamed. That is a second structure that has to agree with `snd_buf`
segment for segment, which is exactly the class of bug D29 and D31 avoid by deriving everything from
the ring itself, so it is **not** done here. It is an option for a later sub-step if the N1 numbers
say the remaining cost matters; anything that keeps `fastack` where it is cannot beat what is above.
The N1 numbers are now in: `parse_fastack` costs **2.55 ns per segment touched** there (85.61 ms
over 8191 ACKs averaging ~4096 segments each) against the M5's 0.74 ns, and it is still level with
what the N1's full scan loop costs in `flush`: 28.576 µs over 8192 segments is 3.49 ns/segment. So the
conclusion holds on aarch64 too: that loop is at the ring's memory bandwidth, and the packed side
array is the only thing left that could move it.

A lazy `fastack` (a global bump counter and a per-segment epoch) was considered and rejected on
correctness rather than taste: a bump applies to the segments *before* a given `sn` that were sent
*no later than* a given `ts`, which is a two-dimensional dominance count, not a counter difference.

**The prediction this section made was wrong.** It read: "the naive path measured 143.6 ms there at
8192 against the M5's 42.9 ms, so the N1 has more to gain." 12.2e measured it, and as a *speed-up*
the N1 gains slightly **less**: **1.67× at 8192** against the M5's 1.74×, and **1.59× at 1024**
against 1.65×. The sentence is true only of wall-clock time: the N1 saves 57.4 ms per window where
the M5 saves 18.5 ms, and that is not what "more to gain" was taken to mean. The honest summary is
that D31's speed-up is a property of the *algorithm*, near-identical on both microarchitectures,
which in hindsight is what halving a linear scan should look like.

## 12.2e: the same two decisions on a Neoverse-N1

D29 and D31 were both accepted on laptop measurements alone, and both said so. This section is the
aarch64 half: same benchmarks, on lab-arm64 (Neoverse-N1, 2 vCPU, Ubuntu 24.04), which is the
architecture the port is actually deployed on.

### Method

Two binaries, cross-built on the laptop and run on the N1:

```sh
# "before": the parent of 12.2c (8ba1092): neither D29 nor D31.
# "after":  the 12.2d commit (e91ded1), i.e. the branch head BEFORE in_order_oracle was added.
# (both commits build to the same deps/ filename, so rename on the way out)
cargo-zigbuild test -p kcptun-kcp --bench kcp --release --no-run \
    --target aarch64-unknown-linux-musl
scp "$(ls -t target/aarch64-unknown-linux-musl/release/deps/kcp-* \
    | grep -v '\.d$' | head -1)" lab-arm64:~/kcptun-lab/tests/bench/kr-bench-kcp
# per round, one after the other, cwd separated so criterion's state cannot cross:
./kr-bench-kcp-before --bench --noplot --warm-up-time 0.5 --measurement-time 2 'kcp/(flush|input_ack)'
./kr-bench-kcp        --bench --noplot --warm-up-time 0.5 --measurement-time 2 'kcp/(flush|input_ack)'
./kg-bench-kcp -test.run '^$' -test.bench 'BenchmarkFlushWindow|BenchmarkInputAck' -test.benchtime 1s
```

- **Release, never debug.** Every `debug_assertions` build cross-checks D31's computed offset
  against the full linear scan on every ACK (`Kcp::parse_ack`), which makes the ACK path *slower*
  than before D31. Benchmarking it from a debug build would have measured the safety net.
- Medians of **five interleaved rounds**; both Rust binaries and the Go one run back to back inside
  each round, so drift cancels. Run-to-run spread was 0.4–4.7 % on every arm: much tighter than the
  ±20 % the laptop shows, because the box was quiet.
- `uptime` recorded per round: load average **0.11–0.13 before the first round** and 1.1–1.4 during
  them, of which ~1.0 is the benchmark itself on one of the two cores. The box's own 30 live kcptun
  processes and its `tc` setup were left running throughout (they are the baseline
  `docs/benchmarks/memory.md` compares against) and contribute the residual ~0.2.
- The Go side re-measured within 1–2 % of its 03.6 figures on the same box (63.2 µs against 63.3 µs
  at flush/8192, 351.8 ms against 347.7 ms at sack/8192), which is the independent check that the
  machine is in the same state as when the baseline table was taken.
- Three five-round sets were taken, all with the same three binaries: `flush` + `sack` (which is
  where the `flush` and `sack` rows come from), `in_order` on the two Rust binaries (the `in_order`
  Rust rows), and a third over every arm after `in_order_oracle` was added. The Go `in_order`
  figures come from that third set; the Go binary is the same one throughout and its other arms
  reproduced across the sets to within 1–2 %, which is what licenses the mix.

### Result

| Benchmark | N1 before | N1 after | speed-up | M5 speed-up | N1 same-build oracle | N1 Go | Go / after |
|---|---:|---:|---:|---:|---:|---:|---:|
| flush/1024 | 3.569 µs | **70.2 ns** | **50.8×** | 44× | 3.928 µs | 7.327 µs | 104× |
| flush/8192 | 28.576 µs | **70.1 ns** | **408×** | 347× | 31.221 µs | 63.218 µs | 902× |
| input_ack/in_order/1024 | 70.17 µs | **38.75 µs** | **1.81×** | - |, *(see below)* | 192.1 µs | 5.0× |
| input_ack/in_order/8192 | 2.381 ms | **358.1 µs** | **6.65×** | - |, *(see below)* | 5.671 ms | 15.8× |
| input_ack/sack/1024 | 2.309 ms | **1.454 ms** | **1.59×** | 1.65× | 2.306 ms | 5.330 ms | 3.7× |
| input_ack/sack/8192 | 143.03 ms | **85.61 ms** | **1.67×** | 1.74× | 143.59 ms | 351.84 ms | 4.1× |

### What the numbers say about the two predictions

1. **D29's ratio is larger on the N1: prediction held.** 408× at 8192 against the M5's 347×, 50.8×
   against 44× at 1024. The mechanism is the obvious one: `flush` becomes O(1) in the window on both
   machines (70 ns at 1024 and at 8192, indistinguishable), so the ratio is just however slow the
   scan it replaced was, and the N1's scan was 3.3× slower than the M5's.
2. **D29's accepted cost is *not* 26–30 % on an N1: prediction did not hold, in the port's
   favour.** The scan that cannot be skipped costs **+10.1 % at 1024 and +9.3 % at 8192** there,
   against the M5's +25 % and +30 %. The arithmetic is worth stating because it is the same on both
   machines: the summary adds `(31.221 − 28.576) / 8192 = 0.32 ns` per segment on the N1 and
   `(11.45 − 8.790) / 8192 = 0.325 ns` on the M5 (the *same* absolute cost) but the N1's loop was
   3.49 ns/segment to the M5's 1.07 ns/segment, so it is a third of the relative burden. The
   sustained-loss-storm case that D29 knowingly traded away is therefore materially cheaper on the
   deployment architecture than the decision assumed.
3. **D31 does not gain more on the N1: prediction did not hold.** 1.67× at 8192 against the M5's
   1.74×, 1.59× against 1.65× at 1024. See the paragraph at the end of § 12.2d.
4. **D29 also speeds up the ordinary in-order ACK path, which neither decision claimed, and this
   one is not architecture-specific.** 12.2d established that `in_order` is untouchable by D31, and
   generalised that to "unchanged". It is not:
   `Kcp::input` flushes whenever the send window slides, so in a transfer whose ACKs arrive in order,
   the normal case: *every* ACK packet pays a `flush`, and D29 makes each of them O(1). At the
   production window that is **6.65×** (2.381 ms → 358.1 µs), and **15.8× Go**. The arithmetic
   closes exactly: 8192 segments arrive in 142 packets, so the before figure is 16.8 µs per packet
   against a full-window scan of 28.6 µs (the window shrinks as `una` advances, so roughly half of
   it on average), and the after figure is 2.5 µs per packet, which is `parse_una` plus the freeing
   of 58 segment payloads at ~44 ns each, with the flush itself no longer visible.

That fourth point is the one that changes how D29 should be read. It was accepted as a large win in
a case that is rare (a full flush at the production window) against a small loss in a case that is
rarer still (a loss storm). It is in fact a **6.6× win on the commonest path there is**, bought for
9 % on the loss storm rather than 30 %.

### Reproducing it

`input_ack/in_order_oracle/<w>` was added in 12.2e so that point 4 is reproducible from a single
build for ever, the way `snd_buf_oracle` and `sack_oracle` already were. In the build that carries
it, `in_order_oracle/8192` measures 2.630 ms against `in_order/8192`'s 369.6 µs: **7.1×** within
one binary, confirming the 6.65× taken across the two. A within-build ratio is an **upper bound**,
not a second reading of the same quantity: the same-build oracle still carries D29's per-segment
bookkeeping (§ 12.2c; DECISIONS D29), which this very section measures at +9–10 % on the N1 and
+26–30 % on the M5 for the scan it runs. The arithmetic shows it: 2.381 ms × 1.093 = 2.602 ms,
which is the 2.630 ms oracle, while the optimised arm moved only 369.6/358.1 = +3.2 %. So the
cross-binary **6.65×** is the honest figure, and corrected for the bookkeeping the M5's 8.0× below
is ≈6.5×, which is what makes "not an aarch64 effect" a like-for-like claim.

**It is not an aarch64 effect.** The same single-binary pair on the M5 (medians of five rounds,
`--warm-up-time 0.5 --measurement-time 2`) gives 753.2 µs against 94.2 µs at 8192 (**8.0×**) and
21.73 µs against 12.04 µs at 1024: **1.81×**, level with the N1's 1.81× (70.17 µs → 38.75 µs in
the result table above). The laptop simply never
measured it: 12.2c benchmarked `flush` directly and never ran `input_ack`, and 12.2d's `in_order`
pair had D29 on both sides.

One caveat, and it is the 12.2b trap again (`docs/benchmarks/crypto.md`): **adding that benchmark id
moved the whole `input_ack` group by about 7 %** through code layout alone (sack/8192 85.61 ms →
92.81 ms, sack_oracle 143.59 ms → 153.36 ms, both in the same direction, while the `flush` group did
not move at all). The table above therefore comes from the binary *without* the new id: the one
that is byte-identical to a build of the 12.2d commit, and the within-build 7.1× above comes from
the binary with it. Ratios within one binary are sound in both; absolute times must not be mixed
across them.

## 12.1: attributing the 8 % gap between the 03.6 and 12.2c baselines

12.2e found, and refused to explain away, that two "before" baselines for the *same* naive scan
disagree on the same machine: the 03.6 row above says `flush/8192` = **30.8 µs** and `flush/1024`
= 3.86 µs on the N1, while a build of 12.2c's parent measures **28.576 µs** and 3.569 µs there.
Go reproduced its own 03.6 figures to within 1–2 % across the same interval, so the machine was
not the variable, but nothing said what was, and a series that is quoted as
30.8 µs → 70.1 ns without knowing that is a series with an unexplained step in it.

12.1 settled it by bisecting with binaries instead of reasoning about diffs.

### Method

Four bench binaries, one per commit, each built out of tree from `git archive` (nothing in the
worktree or the shared `.git` touched) and cross-compiled the same way 12.2e built its pair:

```sh
cargo-zigbuild test -p kcptun-kcp --bench kcp --release --no-run \
    --target aarch64-unknown-linux-musl
```

| label | commit | what it is |
|---|---|---|
| **A** | `29a4e16` | `[03.6b]`: the commit the 03.6 table was taken at |
| **B** | `6771f05` | the **parent** of `[12.2a]` |
| **C** | `ddaa595` | `[12.2a]`: V18 tx-channel backpressure |
| **D** | `8ba1092` | the **parent** of `[12.2c]`: 12.2e's "N1 before" |

`crates/kcp/benches/kcp.rs` is **unchanged** across all four commits, so the 12.2b/12.2e
code-layout trap (adding a benchmark id moves its whole group) cannot be the explanation. A build
of `[12.3b]` (`defdaf8`) turned out to be **byte-identical** to D, which rules 12.3b out without
running it: nothing between 12.3b and 12.2c's parent reaches this binary.

Five interleaved rounds on lab-arm64 (Neoverse-N1, 2 vCPU), all four Rust binaries and the Go
control back to back inside each round, each in its own working directory so criterion state
cannot cross; `--warm-up-time 0.5 --measurement-time 2`, Go at `-test.benchtime 1s`. Load average
0.14 before the first round and 0.9–1.0 during them, of which ~1.0 is the benchmark on one of the
two cores. The box's 30 live kcptun processes and its `tc` setup were left running throughout.

### Result

Medians of five rounds:

| build | flush/1024 | flush/8192 | step | input_ack/in_order/1024 | in_order/8192 | step |
|---|---:|---:|---|---:|---:|---|
| **A** `[03.6b]` | 3.868 µs | 30.758 µs | - | 65.41 µs | 2.2084 ms | - |
| **B** 12.2a parent | 3.861 µs | 31.187 µs | +1.4 % | 71.57 µs | 2.3829 ms | **+7.9 %** |
| **C** `[12.2a]` | 3.588 µs | 28.846 µs | **−7.5 %** | 70.23 µs | 2.4086 ms | +1.1 % |
| **D** 12.2c parent | 3.583 µs | 28.664 µs | −0.6 % | 70.20 µs | 2.4108 ms | +0.1 % |
| Go control | 7.291 µs | 62.876 µs | | | | |

The two endpoints reproduce the two published tables exactly: **A** gives 3.87 / 30.76 µs against
03.6's 3.86 / 30.8 and 65.4 µs / 2.21 ms against its 65.5 µs / 2.22 ms; **D** gives 3.58 / 28.66 µs
against 12.2e's 3.569 / 28.576 and 70.2 µs / 2.41 ms against its 70.17 µs / 2.381 ms. The Go
control is 62.876 µs against 03.6's 63.3 and 12.2e's 63.218: 0.7 %. Nothing about the machine
changed; both baselines were right about their own commits.

### What it means

1. **The `flush` gap is attributed: it is `[12.2a]`** (`ddaa595`, Deviation V18, tx-channel
   backpressure). It appears at exactly that commit, in one step, at both window sizes
   (−7.1 % at 1024, −7.5 % at 8192), and is flat on either side of it.
2. **It is not an algorithmic improvement and must not be read as one.** 12.2a's `flush` still
   visits every segment of `snd_buf`; what it adds is a `would_send` predicate evaluated *before*
   the retransmit branch chain (so that backpressure can stop without mutating a segment), which
   means the loop body now computes the same four conditions twice and still runs faster. That is
   a code-generation effect of the restructured loop, in the same class as the layout traps
   documented in [§ 12.2e](#reproducing-it) and `crypto.md`. 12.1 did not look at the assembly;
   the claim here is the attribution, not the mechanism.
3. **The `in_order` gap is a different step, and it goes the other way.** `in_order` gets ~8 %
   *slower* between `[03.6b]` and 12.2a's parent and is then flat. Nothing in that interval touches
   `crates/kcp/src/kcp.rs` at all: the commits in it are 05.x, 06.x, 08.x, 09.x and 10.x work plus
   `Cargo.lock` updates, so this too is codegen, not KCP. It is bounded to that interval rather
   than attributed to a commit; 12.1 stopped there because no number is quoted from inside it.
4. **How to quote the series.** `flush/8192` on the N1 is
   30.76 µs at `[03.6b]` → 28.66 µs from `[12.2a]` → **70.1 ns** from `[12.2c]` (D29). The middle
   step is a build artefact of an unrelated change and the last one is the optimisation. Quoting
   "30.8 µs → 70.1 ns" overstates D29 by 7 %; the figure D29 earned is 28.66 → 0.0701, **409×**.
   [§ 12.2c](#result) reports **408×** because it divides its own parent's 28.576 µs rather than
   this section's re-measured 28.664 µs: the same measurement to within 0.3 %, and 408× is the
   figure to quote, since it is the one with a table under it.

Both tables above are therefore left exactly as they are. Each is correct for its own commit, and
this section is the bridge between them.

## Observations for Step 12

- The O(window) scans are the dominant cost at the production window (8192):
  - `flush` scans every segment of `snd_buf` on every call (every write, every update tick, every ACK
    that advances `una`).
  - `parse_ack`/`parse_fastack` scan linearly for each ACK. The selective-ACK case is ~70× slower per
    ACK than the in-order one. (12.2d removed the `parse_ack` search; `parse_fastack` still raises
    one `fastack` per segment before the ACK, which is the algorithm, not the lookup.)
- These are algorithmic and identical in Go. Optimising them (D25: differential-tested against this
  naive oracle) is the biggest KCP-level win available for the production profile.
- Segment data is a plain `Vec<u8>` (`SegmentData` alias) and the heap's dedup set uses the default
  SipHash `HashSet`. Both are behind type aliases so they can be swapped after measurement.
