# KCP session layer: Rust vs Go loopback echo (plan 05.9, re-measured in 12.1)

The deferred write-up plan 12.1 owes for sub-step 05.9. The 05.9 smoke numbers went into a commit
message and were taken as medians of **three** runs on a machine that was also compiling; this page
is the same benchmark taken as medians of **five**, Rust and Go alternating run by run, with the
method and the caveats written down.

What it measures: one **echo of the whole payload over a loopback KCP session** — the client writes a
deterministic stream in `chunk`-sized `Write`s, the server writes back everything it reads, and the
client verifies every byte. Both sides are the peers the interop suite already drives, so a number
here describes the port rather than a benchmark written for the occasion.

| Side | Server | Client | CPU counted with |
|---|---|---|---|
| `rs` | `RustEchoServer`, in-process | `run_rust_client`, in-process | `getrusage(RUSAGE_SELF)` |
| `go` | `kcpecho server` (child process) | `kcpecho client` (child process) | `getrusage(RUSAGE_CHILDREN)` |

Source: `crates/interop-tests/src/echo_bench.rs` and `crates/interop-tests/tests/kcp_echo_bench.rs`.

## Method

```sh
KCPTUN_BENCH_REPEAT=5 cargo test -p kcptun-interop-tests --release \
    --test kcp_echo_bench -- --ignored --nocapture
```

| | |
|---|---|
| Machine | Apple M5 (Mac17,2), macOS 27.0, 10 cores, arm64 |
| Rust | 1.98.1, release profile (fat LTO, 1 CGU) |
| Go | 1.27.1; `kcpecho` from `reference/bin/kcpecho_darwin_arm64`, kcp-go v5.6.66 |
| Tree | `75fd8d8` (the merge of `main` into `step/12-bench`); no tracked file modified |
| Runs | 5 per (implementation, profile, payload, message size), Rust and Go alternating |
| Payloads | 8 MiB and 32 MiB, echoed — the link carries each twice |
| Message sizes | 4 KiB, 64 KiB, 512 KiB (kcp-go's `BenchmarkEchoSpeed4K/64K/512K` family) |
| Host load | load average **1.14 / 1.68 / 1.62** at the end of the run, on 10 cores: the laptop was also driving the 12.1 lab campaign over ssh (an idle ssh client) and the benchmark itself is one busy core. Not a quiet machine, but a *consistently* un-quiet one, and the arms alternate |

Read the **min–max** columns before the medians. Wall time on a laptop is far noisier than CPU
time; CPU per GB is the stable metric and is the one the acceptance criterion in step 12 is written
in.

### Two profiles, and what "production" means here

```
default    -crypt aes  -datashard 10 -parityshard 3 -mtu 1350 -sndwnd 128  -rcvwnd 512
production -crypt xor  -datashard 0  -parityshard 0  -mtu 1390 -sndwnd 8192 -rcvwnd 8192
```

> **This "production" profile is not S1.** It is S1's *crypto, FEC, MTU and window* settings on top
> of kcp-go's own `-mode fast` timing (`nodelay 0, interval 30, resend 2, nc 1` as `KcpCase`
> defaults them), whereas S1 is `-mode normal`. It is also KCP only: no smux, no snappy,
> no TCP proxying. The end-to-end S1 comparison is
> [`2026-09-24-lab-arm64-netns-clean.md`](2026-09-24-lab-arm64-netns-clean.md) (aarch64) and
> [`2026-09-24-lab-x86-1-netns-clean-s1-sockbuf.md`](2026-09-24-lab-x86-1-netns-clean-s1-sockbuf.md) (x86_64, S1 re-taken in 12.1b; the `s1` half of the older x86_64 page is withdrawn); this page
> is the session layer on its own.

Four things count *against* Rust here and are left that way rather than corrected for:

* the Rust timing window starts before key derivation (PBKDF2, 4096 rounds), the socket bind and the
  option setters; Go's starts after them;
* the CPU figure is both endpoints together, and the harness work — generating the stream, verifying
  and hashing the echo — is inside it on both sides;
* Rust's two endpoints share one runtime and one address space, Go's are two processes with a
  runtime each, so Go pays two runtime start-ups while Rust may win a little on locality;
* loopback has no loss and no RTT, so this says what the implementations *cost*, not what a link
  would deliver.

## Results

Throughput is payload MiB/s counted once (the wire carries it twice). `rs/go` above 1.00× means
Rust is faster; for CPU per GB, below 1.00× means Rust is cheaper.

| profile | payload | message | rs MiB/s | go MiB/s | rs/go | rs CPU s/GB | go CPU s/GB | rs/go |
|---|---|---|---:|---:|---:|---:|---:|---:|
| default | 8 MiB | 4 KiB | 71.4 | 57.6 | **1.24×** | 51.72 | 93.49 | **0.55×** |
| default | 8 MiB | 64 KiB | 86.0 | 70.8 | **1.22×** | 43.05 | 75.34 | **0.57×** |
| default | 8 MiB | 512 KiB | 87.9 | 74.1 | **1.19×** | 41.31 | 70.79 | **0.58×** |
| default | 32 MiB | 4 KiB | 90.4 | 65.2 | **1.39×** | 41.36 | 82.04 | **0.50×** |
| default | 32 MiB | 64 KiB | 113.1 | 84.0 | **1.35×** | 33.58 | 63.41 | **0.53×** |
| default | 32 MiB | 512 KiB | 114.7 | 85.6 | **1.34×** | 32.68 | 60.62 | **0.54×** |
| production | 8 MiB | 4 KiB | 101.3 | 47.3 | **2.14×** | 35.46 | 82.99 | **0.43×** |
| production | 8 MiB | 64 KiB | 101.3 | 62.0 | **1.63×** | 34.68 | 67.86 | **0.51×** |
| production | 8 MiB | 512 KiB | 102.6 | 63.0 | **1.63×** | 34.64 | 68.98 | **0.50×** |
| production | 32 MiB | 4 KiB | 135.6 | 43.9 | **3.09×** | 31.51 | 82.00 | **0.38×** |
| production | 32 MiB | 64 KiB | 148.8 | 52.6 | **2.83×** | 27.53 | 74.33 | **0.37×** |
| production | 32 MiB | 512 KiB | 147.5 | 57.2 | **2.58×** | 27.45 | 60.54 | **0.45×** |

### The spread behind those medians

| profile | payload | message | impl | MiB/s median | MiB/s min–max | CPU s/GB median | CPU s/GB min–max |
|---|---|---|---|---:|---|---:|---|
| default | 8 MiB | 4 KiB | rs | 71.4 | 69.6–80.0 | 51.72 | 46.87–52.83 |
| default | 8 MiB | 4 KiB | go | 57.6 | 57.1–63.0 | 93.49 | 84.79–94.42 |
| default | 8 MiB | 64 KiB | rs | 86.0 | 82.5–87.0 | 43.05 | 42.53–43.87 |
| default | 8 MiB | 64 KiB | go | 70.8 | 69.6–72.7 | 75.34 | 73.85–76.58 |
| default | 8 MiB | 512 KiB | rs | 87.9 | 85.1–100.0 | 41.31 | 35.93–42.66 |
| default | 8 MiB | 512 KiB | go | 74.1 | 70.8–76.9 | 70.79 | 66.17–73.67 |
| default | 32 MiB | 4 KiB | rs | 90.4 | 87.7–91.4 | 41.36 | 41.00–42.44 |
| default | 32 MiB | 4 KiB | go | 65.2 | 64.3–67.8 | 82.04 | 79.02–82.48 |
| default | 32 MiB | 64 KiB | rs | 113.1 | 111.9–113.1 | 33.58 | 33.21–33.72 |
| default | 32 MiB | 64 KiB | go | 84.0 | 82.9–87.0 | 63.41 | 59.93–63.72 |
| default | 32 MiB | 512 KiB | rs | 114.7 | 113.9–116.4 | 32.68 | 31.94–32.78 |
| default | 32 MiB | 512 KiB | go | 85.6 | 84.2–88.2 | 60.62 | 59.04–61.70 |
| production | 8 MiB | 4 KiB | rs | 101.3 | 100.0–102.6 | 35.46 | 35.10–36.02 |
| production | 8 MiB | 4 KiB | go | 47.3 | 46.0–58.8 | 82.99 | 81.18–96.80 |
| production | 8 MiB | 64 KiB | rs | 101.3 | 100.0–102.6 | 34.68 | 34.55–35.55 |
| production | 8 MiB | 64 KiB | go | 62.0 | 60.6–80.0 | 67.86 | 63.83–69.00 |
| production | 8 MiB | 512 KiB | rs | 102.6 | 101.3–105.3 | 34.64 | 32.46–35.98 |
| production | 8 MiB | 512 KiB | go | 63.0 | 61.1–67.2 | 68.98 | 57.99–69.40 |
| production | 32 MiB | 4 KiB | rs | 135.6 | 134.5–137.9 | 31.51 | 30.95–32.09 |
| production | 32 MiB | 4 KiB | go | 43.9 | 42.6–47.5 | 82.00 | 76.77–85.24 |
| production | 32 MiB | 64 KiB | rs | 148.8 | 146.1–150.9 | 27.53 | 27.10–28.15 |
| production | 32 MiB | 64 KiB | go | 52.6 | 40.7–59.0 | 74.33 | 66.03–78.04 |
| production | 32 MiB | 512 KiB | rs | 147.5 | 131.7–149.5 | 27.45 | 27.21–27.82 |
| production | 32 MiB | 512 KiB | go | 57.2 | 55.5–61.7 | 60.54 | 60.02–62.14 |

Spread below means `(max − min) / min` of the five runs. The Rust spreads are tight on the metric
this page is judged on: **nine of the twelve cells are within 4 % on CPU per GB, five of them
within 3 %**. The three loose ones — `default 8 MiB / 4 KiB` (12.7 %), `default 8 MiB / 512 KiB`
(18.7 %) and `production 8 MiB / 512 KiB` (10.8 %) — are all 8 MiB payloads, where the fixed
set-up cost is divided across the least data. Wall-clock MiB/s is looser than CPU per GB
throughout, exactly as the caveat above says it would be.

The **widest** spread on the page is Go's, on the
production profile (`32 MiB / 64 KiB`, 40.7–59.0 MiB/s, a 45 % swing), which is the shape kcp-go's
drop-on-full output channel produces: a burst that overruns the 2048-deep channel costs a
retransmission timeout per dropped packet, so a run either hits the cliff or does not. That is the
behaviour Deviation **V18** replaced with backpressure on the Rust side, and it is why the Rust
column for the same cell varies by 3 %.

## What this says, and what it does not

* **CPU per GB is the headline and it is unambiguous.** Rust costs 0.37–0.58× of Go's CPU per GB in
  every one of the twelve cells, and the advantage is largest exactly where the production deployment
  is: the production profile at a large payload, 0.37–0.45×.
* **Throughput is 1.19–3.09× Go**, but loopback throughput on a laptop is a *ceiling* measurement.
  It says the port does not have a throughput problem at the session layer; it does not predict a
  link.
* **This is not an end-to-end kcptun number.** No smux, no snappy, no TCP proxy, no network. For
  those, read [`2026-09-24-lab-arm64-netns-clean.md`](2026-09-24-lab-arm64-netns-clean.md) and
  [`2026-09-24-lab-x86-1-netns-clean-s1-sockbuf.md`](2026-09-24-lab-x86-1-netns-clean-s1-sockbuf.md).
* **It is one machine and one architecture.** The 12.2a commit measured the same sweep on
  lab-arm64's Neoverse-N1 (2 vCPU) at medians of three and got a much narrower Rust lead — 32 MiB
  production at 1.02–1.38× Go and 0.68–0.86× CPU per GB. A 10-core laptop echoing over loopback is
  the friendliest case there is; the 2-vCPU Linux box is the honest one. The aarch64 half of *this*
  table is not re-measured here and remains at medians of three.

## History, and why both payloads are in the sweep

The production profile used to be **payload dependent**: one `flush()` emits a whole send window and
the surplus over the session's packet channel was dropped after KCP had already counted it as
transmitted, so the transfer stepped through retransmission timeouts. Two steps removed it. The
table is `rs/go` throughput for 4 KiB / 64 KiB / 512 KiB messages:

| payload | host | 05.9 (drop, 2048) | 05.10 (drop, 8192) | 12.2a (backpressure, 2048) | 12.1 (this page) |
|---|---|---|---|---|---|
| 8 MiB | M5 | 0.25× / 0.19× / — | 1.88× / 1.56× / 1.53× | 1.82× / 1.69× / 1.70× | **2.14× / 1.63× / 1.63×** |
| 32 MiB | M5 | 1.53× / 1.20× / — | 2.33× / 2.36× / 2.42× | 2.74× / 2.83× / 2.63× | **3.09× / 2.83× / 2.58×** |
| 8 MiB | lab-arm64 aarch64 | 0.34× / 0.26× / — | 1.17× / 1.17× / 0.96× | 1.32× / 1.10× / 1.03× | not re-measured |
| 32 MiB | lab-arm64 aarch64 | 0.70× / 0.63× / — | 0.77× / 0.77× / 0.70× | 1.12× / 1.38× / 1.02× | not re-measured |

The earlier M5 rows are medians of three on a busier laptop (load average 1.5–2.9) and this row is
medians of five, so the 12.2a → 12.1 movement is **not** evidence of a change: nothing in the tree
touched this path between them. Both payloads stay in the sweep as the regression test for the band.

## Reproducing it

```sh
# the Go peer has to exist first
tools/fetch-reference.sh                       # only if reference/bin/kcpecho_* is missing
KCPTUN_BENCH_REPEAT=5 cargo test -p kcptun-interop-tests --release \
    --test kcp_echo_bench -- --ignored --nocapture
# other payloads:
KCPTUN_BENCH_BYTES=8388608,33554432 KCPTUN_BENCH_REPEAT=5 cargo test …
```

Related pages: [`crypto.md`](crypto.md) (the per-packet cipher cost inside these runs),
[`kcp.md`](kcp.md) (the ARQ core), [`smux.md`](smux.md) (the layer above),
[`micro.md`](micro.md) (all of the micro-benchmarks in one place).
