# The micro-benchmarks in one place (plan 12.1)

Steps 02, 03, 04, 05 and 06 each measured their own layer against the pinned Go reference and wrote
its own page. This is the index plan 12.1 asks for: one headline per layer, what each page's
acceptance criterion was, and (more usefully) **what each one is not evidence for**.

**For the whole picture: end to end, under impairment, over a real path and over six hours,
with what was never measured listed explicitly: read [`REPORT.md`](REPORT.md).** This page is
the micro-benchmark index underneath it.

Nothing here is a new measurement. Every number is the linked page's, taken at the linked page's
commit, and the pages are where the method, the spread and the caveats live. Read the page before
quoting a row.

## The layers

| Layer | Page | Headline, Rust vs Go | Machines |
|---|---|---|---|
| Packet crypto (02.6) | [`crypto.md`](crypto.md) | CFB decrypt **3.7–6.1×**, CFB encrypt 1.1–1.6×, salsa20 1.5–2.4×, xor 1.2–1.5×; **aes-128-gcm 0.68–0.88×**, the one failing cell | M5, Neoverse-N1 |
| KCP ARQ core (03.6) | [`kcp.md`](kcp.md) | naive port 1.0–2.9× Go; after D29/D31 `flush` is **O(1)** in the window (408× its own baseline, 902× Go) and selective-ACK input 1.6–1.7× | M5, Neoverse-N1 |
| FEC + Reed-Solomon (04.7) | [`fec.md`](fec.md) | FEC encode/decode **1.2–2.1×**, RS encode 1.4–1.9×, reconstruct 1.0–1.9× | M5, Neoverse-N1 |
| KCP session, loopback echo (05.9) | [`session.md`](session.md) | **0.37–0.58× the CPU per GB**, 1.2–3.1× the throughput | M5 (aarch64 half at medians of 3, in the `[12.2a]` commit) |
| smux (06.6) | [`smux.md`](smux.md) | per idle stream **2.93 vs 6.99 kB**; throughput indistinguishable, and the harness is not smux-bound | M5 |
| Memory, end to end (12.3a) | [`memory.md`](memory.md) | client idle RSS **1.71 vs 16.73 MB**; per idle stream 4.6 vs 22.5 kB; **retention after a burst is where Go wins** | Neoverse-N1 |
| Go vs Rust end to end (12.1) | [`2026-09-24-lab-arm64-netns-clean.md`](2026-09-24-lab-arm64-netns-clean.md) | goodput **1.74–2.34×**, CPU per GB **0.44–0.55×**, RSS 0.17–0.50×, p99 0.50–0.73× | aarch64, 2 vCPU |
| The same grid, no headroom: **S1 (12.1b)** | [`2026-09-24-lab-x86-1-netns-clean-s1-sockbuf.md`](2026-09-24-lab-x86-1-netns-clean-s1-sockbuf.md) | goodput **1.52–1.66×** on the bulk cells (1.97× on the competing-flow one), CPU per GB **0.48–0.61× both ends** (0.47–0.67× per end), RSS 0.15–0.29×, idle p99 0.48×; **S1 retransmits 0.0 % of `OutSegs` for Rust in every cell against 1.5–9.0 % for Go**; the one loss is p50 latency through a saturated tunnel, 15.04 ms against 0.52 | x86_64, 1 vCPU |
| The same grid, no headroom: **S2 (12.1)** | [`2026-09-24-lab-x86-1-netns-clean.md`](2026-09-24-lab-x86-1-netns-clean.md) | goodput 1.79–2.16×, CPU per GB 0.44–0.54×, zero retransmission on both sides. Its **`s1` half is withdrawn**, taken at a stock `net.core.rmem_max`, which docs/DECISIONS.md D32 rules invalid; the 1.22× goodput and 29–48 % retransmission figures this row used to carry were the host | x86_64, 1 vCPU |
| The S2 socket-buffer control (12.1b) | [`2026-09-24-lab-x86-1-netns-clean-s2-control.md`](2026-09-24-lab-x86-1-netns-clean-s2-control.md) | S2 `bulk-up` re-run at the raised ceiling: 1.66× against the earlier session's 1.79×, spreads overlapping, zero retransmission both times, the ceiling does not reach S2 | x86_64, 1 vCPU |

QPP has a benchmark (`crates/qpp/benches/qpp.rs`) and **no write-up**; plan 12.1 did not ask for
one, and none exists.

## What each page is not evidence for

This is the part worth having in one place, because every one of these has already been misread at
least once in this project.

* **`crypto.md` measures one whole-packet operation, not a session.** A 5.5× CFB decrypt does not
  become a 5.5× tunnel: at the production profile the cipher is `xor`, which is ~1 % of the packet
  path. The one number that matters operationally is the **aes-128-gcm shortfall**, because it is
  the default for `-crypt aes-128-gcm` users and 12.2b tried three backends and kept RustCrypto.
* **`kcp.md`'s 03.6 table is the `[03.6b]` commit's and no other.** Two of its Rust columns moved
  later through unrelated code changes: `flush` −7 % at `[12.2a]`, `in_order` +8 % somewhere before
  it, so its figures must not be differenced against a later section's. The page's
  [§ 12.1](kcp.md#121--attributing-the-8--gap-between-the-036-and-122c-baselines) attributes both
  steps. It also records two **code-layout traps**: adding a benchmark id moved a whole group by
  ~7 % in 12.2e and again in 12.2b, so absolute times may only be compared within one binary.
* **`fec.md`'s `zeroed` rows are the shape the decoder actually uses**, and on musl they only just
  meet the bar (1.04×) because musl's `memset` moves ~2.9 GB/s. D07 has since made glibc the default
  for the released Linux artifacts, which changes that row's premise; it has not been re-measured.
* **`session.md` is KCP only** (no smux, no snappy, no TCP proxy, no network) and its
  "production" profile is S1's crypto, FEC, MTU and windows on kcp-go's `-mode fast` timing, not
  S1's `-mode normal`. Its aarch64 column is much narrower than its M5 column: a 10-core laptop
  echoing over loopback is the friendliest case there is.
* **`smux.md` is not a smux measurement.** The verifying peers spend most of the timed region in a
  PRNG and SHA-256, so all four client/server combinations land within 8 %. That *is* the finding,
  smux is not the bottleneck, but it is not a throughput comparison of the two multiplexers, and
  there cannot be one until the Go peer gains a payload mode that skips the per-byte work.
* **`memory.md` is the only page that contradicts the headline**, and it is the important one: the
  port wins idle RSS by 6–10× and loses retention after a burst.
* **The dated end-to-end pages are per session.** Medians from two different sessions are not
  comparable, on a shared box or on a real path, including the pages above, whose absolute goodput
  differs by 2–3× mostly because one box has two cores and the other one.
* **One of those pages is half withdrawn, and the reason is worth the paragraph.** The 12.1 x86_64
  grid was taken on a host at the stock `net.core.rmem_max` of 212,992 B while S1 asks for
  `-sockbuf 8388608`; `setsockopt` clamps silently, so its S1 rows measured the ceiling.
  docs/DECISIONS.md D32 says discard rather than interpret, and 12.1b re-took them at a raised
  ceiling with the same binaries on the same host. What that page used to be quoted for is now the
  clearest illustration of why a method table must carry the ceiling: S1's retransmission share was
  read as "34 % on one core against 0 % on two cores, for the same Rust binary" and taken as
  evidence that a saturated receiver retransmits. At a ceiling that can hold the window it is
  **0.0 % on both hosts for Rust**, and 1.5–9.0 % and 13.2 % for Go. The saturated receiver was the
  socket buffer, not the missing core.

## Reproducing them

Each page has its own "method" section with the exact command. In summary:

```sh
# Rust: criterion benches, release profile (fat LTO, 1 CGU)
cargo bench -p kcptun-kcp --bench crypt -- --noplot
cargo bench -p kcptun-kcp --bench kcp   -- --noplot
cargo bench -p kcptun-kcp --bench fec   -- --noplot
cargo bench -p kcptun-kcp --bench rs    -- --noplot
cargo bench -p kcptun-qpp --bench qpp   -- --noplot

# Go: the pinned reference, through the vendored copies in tools/govectors
cd tools/govectors && env GOMODCACHE=$PWD/../../reference/gomod GOFLAGS=-modcacherw \
    GOTOOLCHAIN=local go test -run '^$' -bench . -benchtime 1s ./...

# the two end-to-end harnesses
KCPTUN_BENCH_REPEAT=5 cargo test -p kcptun-interop-tests --release \
    --test kcp_echo_bench -- --ignored --nocapture        # session.md
cargo build --release -p kcptun-interop-tests --bin kcptun-smuxecho   # smux.md

# aarch64: cross-build the bench executable and run it on the lab host
cargo-zigbuild test -p kcptun-kcp --bench kcp --release --no-run \
    --target aarch64-unknown-linux-musl
```

The lab-driven grid is separate: `tools/bench/bench.py`, see
[`../../tools/bench/README.md`](../../tools/bench/README.md).

## Rules these pages are written to

From step 12, "Rules for every optimisation":

1. Medians of **≥ 5 runs**, Go and Rust **interleaved**, on both machines. Where a page falls short
   of that it says so in its own text: `session.md`'s aarch64 column and `memory.md`'s lab-arm64
   staircase are both at three.
2. **One optimisation, one commit**, whose message carries the before/after table and the exact
   command.
3. A before/after pair must come from **two builds measured in the same session**, not from two
   pages written weeks apart. The 03.6-versus-12.2c gap is what happens otherwise.
