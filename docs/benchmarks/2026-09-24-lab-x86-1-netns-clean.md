# Go vs Rust end to end — lab-x86-1-netns-clean, 2026-09-24

> **⚠ The `s1` half of this page is WITHDRAWN — superseded by [2026-09-24-lab-x86-1-netns-clean-s1-sockbuf.md](2026-09-24-lab-x86-1-netns-clean-s1-sockbuf.md) (Sub-step 12.1b).** These runs were taken while `lab-x86-1` carried the stock `net.core.rmem_max` of 212,992 B, while S1 asks for `-sockbuf 8388608` on the client and 67,108,868 on the server. `setsockopt(SO_RCVBUF)` is silently clamped to that ceiling, and docs/DECISIONS.md **D32** — written from 11.2's evidence on the same class of host, where the clamp cost Go 95,133 datagrams and Rust 223,293 in one 65 s run and inverted three cells — rules that **any S1 measurement taken under a stock ceiling is invalid and must be discarded, not interpreted**. So every `s1` table and spread table below is withdrawn, together with every sentence of the observations that rests on an `s1` row — observations 1, 3, 4 and 5 all do, in part. Do not quote them, not even as a lower bound. The ceiling was raised on the host to 8,388,608 / 67,108,864 at 2026-09-24T21:57:15Z and the S1 grid re-taken there with the same binaries.
>
> **The `s2` half stands**, and was checked rather than assumed — see [2026-09-24-lab-x86-1-netns-clean-s2-control.md](2026-09-24-lab-x86-1-netns-clean-s2-control.md). S2 was clamped here too (it passes no `-sockbuf`, but kcptun's flag defaults to 4,194,304 B), and its window is not obviously small enough to be safe from that: `-sndwnd 128` at `-mtu 1350` is about 173 kB of data per flush, ~224 kB on the wire once FEC's 10/3 parity is counted — the same order as the 208 KiB ceiling rather than comfortably inside it, which is exactly why a control was run instead of the arithmetic trusted. S2's measured retransmitted share of `OutSegs` below is 0.0 % for both implementations, which an overflowing receive buffer cannot produce, and the control reproduces the `s2` cells at the raised ceiling.
>
> This banner was added **by hand**, not regenerated: the `lab-runs/` directory these tables were built from is no longer on the machine that ran the campaign, so the page can no longer be rebuilt with `bench.py report` and the byte-identical-regeneration property recorded for it when it was generated can no longer be checked. Two further blocks were hand-added and say so where they stand — the socket-buffer row in the method table and the warning above observation 1; everything else below this banner is exactly as generated. `tools/bench/campaigns/baseline-netns.json` is deliberately **not** carrying any of this: it is the recipe for a future run, and a fresh run of it on the now-raised ceiling would be a valid page that must not open by declaring itself withdrawn.

The Step 12.1 baseline: Go versus Rust end to end. Both tunnel ends run in the `kr-cli`/`kr-srv` namespaces of one host with no impairment, so what this measures is protocol and implementation efficiency on a single core, not a network. It is the reference the optimisations from 12.2f onwards are measured against, **not** a measurement of the unoptimised port — see the note below on what the binaries already carry.

## Method

| | |
|---|---|
| campaign | `baseline-netns.json` |
| client host | `lab-x86-1` — Linux 5.15.0-177-generic x86_64, 1 vCPU, Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz, ldd (Ubuntu GLIBC 2.35-0ubuntu3.15) 2.35, 1.9 GiB |
| arrangement | both tunnel ends in the `kr-cli`/`kr-srv` namespaces of one host, netem profile `clean` |
| configurations | `s1`, `s2` (s1 = the user's production profile, s2 = kcptun's own defaults) |
| metric families | `bulk-up`, `bulk-down`, `latency`, `latency-loaded` |
| repetitions | 5 per pair per cell, A/B interleaved (GG, RR, GR, RG, then again) |
| workload duration | 20 s |
| socket-buffer ceilings | `lab-x86-1` `net.core.rmem_max` **212,992**, `wmem_max` **212,992** — the stock kernel defaults, and the reason the `s1` half of this page is withdrawn (docs/DECISIONS.md D32). Requested `-sockbuf` → what the kernel granted: `s1` client 8,388,608 → **212,992**; `s1` server 67,108,868 → **212,992**; `s2` client and server 4,194,304* → **212,992**. An asterisk is kcptun's own default, which a configuration that passes no `-sockbuf` still asks for. **Added by hand in 12.1b, not recorded by these runs:** this page predates `bench.py` printing the ceiling, and the value is established from the host, where `/etc/sysctl.d/99-kcptun-lab.conf` (2026-09-24T21:57:15Z) is the only file under `/etc/sysctl.conf` or `/etc/sysctl.d/` that sets either limit and this campaign ran 09:50:34Z–11:14:01Z. |
| iperf3 | iperf 3.9 (cJSON 1.7.13) at `/usr/bin/iperf3`, sha256 `2c54c89b4d9016b9…` — the host's own package, which carries no build stamp of ours |
| started | 2026-09-24T09:50:34Z |
| finished | 2026-09-24T11:14:01Z |
| runs harvested | 120 |

Artefacts: go `75fd8d8d61c0` (none, linux/amd64) on `lab-x86-1`; lab tools `75fd8d8d61c0` (glibc 2.17, x86_64-unknown-linux-gnu) on `lab-x86-1`; rust `75fd8d8d61c0` (glibc 2.17, x86_64-unknown-linux-gnu) on `lab-x86-1`.

**Built from a modified tree:** `75fd8d8-dirty` (go, lab, rust). The commit above names the base, not the tree the binary was built from; check what differed before treating these numbers as that commit's.

Read before quoting anything here:

* Every cell is a **median over the repetitions of one session**, and the pairs inside a session were interleaved, so the columns share whatever the box was doing. Medians from two different sessions are not comparable — on a shared box, and on a real path, absolutely not.
* `RR/GG` is annotated ✓ when Rust is on the better side of Go for **that** row's direction (high is better for goodput and stream counts, low for CPU, memory, latency and retransmissions).
* A `·` cell is one that is deliberately not measured: step 12.1 gives the cross pairs (GR, RG) throughput only, because a CPU or RSS row for a mixed pair describes two different implementations at once.
* A `—` cell is **not measured**, never measured-as-zero. An `n/a` ratio is one the two cells beside it cannot support: either Go's median is zero, so the ratio is undefined rather than infinite, or both medians are segment counts below 100 over the whole run, where a ratio would be a verdict on noise. A number in parentheses after a cell is the number of runs behind it when that is fewer than the 5 the plan requires.
* CPU per GB divides the process's own `utime + stime` by the bytes the *workload* moved, not by the bytes that went over the wire: charging an implementation only for the goodput it delivered is what makes FEC and retransmission show up as cost rather than as credit.
* `RetransSegs` **decomposes**: one `flush` adds `LostSegs + FastRetransSegs + EarlyRetransSegs` into it, so all three components are printed beneath it and a `RetransSegs` row with an unexplained remainder means a counter is missing from this page rather than that some retransmission is unattributable. The three are medians of their own five runs, so they sum to the `RetransSegs` median only to within the run-to-run spread, not exactly; the per-run rows in the CSV do sum exactly.
* The host has **one** vCPU and carries both tunnel ends, the workload and the echo target. Absolute goodput here is a property of that core, not of a network; only the Go-versus-Rust columns of one cell are comparable.
* iperf3 is the host's own distribution package and its version is recorded nowhere (a step 12.0 note), so absolute iperf3 throughput is version-unattributed. Both arms of a cell used the same iperf3, so the ratios are safe.
* The build stamps read `75fd8d8-dirty`, and the page flags that above. What differed from `75fd8d8` was **only untracked files** — `tools/bench/bench.py`, its tests, its campaigns and `tools/pingpong/tests/bench_py.rs`, i.e. this harness itself, which the campaign was written with. No tracked file under `crates/` was modified, so the `kr-client`, `kr-server`, `kr-pingpong` and `kr-labsample` binaries are what `75fd8d8` builds. Stated here rather than left to the flag, because the flag cannot know that.
* **What these binaries already contain, and what this page is therefore a baseline *for*.** They are built from `75fd8d8`, which is not the naive port. It already carries `[12.2a]` (Deviation V18, tx-channel backpressure), `[12.2b]` (the AES-GCM backend comparison — no code change, RustCrypto stayed), `[12.2c]` (D29, `flush` skips the already-scanned part of `snd_buf`), `[12.2d]` (D31, ACK addressed by sequence number), `[12.2e]` (the aarch64 numbers for those two) and `[12.3a]`–`[12.3f]` (glibc as the Linux release default per D07, `crates/kcp/src/memory.rs` giving memory back after a burst, the contiguous receive batch). So this is the reference for **12.2f onwards** and for 12.5, and it is **not** a measurement of the unoptimised port. Differencing it against the naive-port figures in [`kcp.md`](kcp.md) § 03.6 would credit work already done here to work not yet done, which is the error `kcp.md` § 12.1 was written to stop.
* **What this grid does not cover.** `tools/bench/bench.py metrics` defines seven metric families and `lab.py` four configurations; this campaign runs four families (`bulk-up`, `bulk-down`, `latency`, `latency-loaded`) at two configurations (`s1`, `s2`). Not taken here: `bulk-par-up`/`bulk-par-down` (iperf3 `-P 8`, the second half of step 12's Goodput row), `churn` (its Scale row), and configurations `s3` and `s4`. step 12's Idle-cost and Startup rows and its S5 (QPP) have no harness family or `lab.py` configuration at all yet. The harness would run the first three unchanged — they are omitted for machine time, not because they do not work — so an absent family on this page means it was **not run**, and 12.5 must not present this page as the full grid.

## Configuration `s1` — the user's production profile

> **⚠ WITHDRAWN — every table in this section is invalid under docs/DECISIONS.md D32 and is superseded by [2026-09-24-lab-x86-1-netns-clean-s1-sockbuf.md](2026-09-24-lab-x86-1-netns-clean-s1-sockbuf.md).** The client's `-sockbuf 8388608` was clamped to 212,992 B by the host, so what these rows measure is the ceiling. See the banner at the top of the page.

```
both   -mode normal -crypt xor -mtu 1390 -sndwnd 8192 -rcvwnd 8192 -smuxver 2 -smuxbuf 16777216 -streambuf 16777216 -datashard 0 -parityshard 0 -nocomp -quiet
client -conn 4 -sockbuf 8388608
server -sockbuf 67108868
```

### `bulk-up` — one TCP stream through the tunnel, client to server (iperf3, forward)

| measurement | unit | GG | RR | GR | RG | RR/GG |
|---|---:|---:|---:|---:|---:|---:|
| goodput | Mbit/s | 147.9 | 182.1 | 204.2 | 157.1 | 1.23x ✓ |
| TCP retransmits | segments | 58 | 50 | 76 | 50 | n/a |
| CPU per GB, client | s/GB | 30.63 | 28.27 | · | · | 0.92x ✓ |
| CPU per GB, server | s/GB | 22.81 | 15.56 | · | · | 0.68x ✓ |
| CPU per GB, both ends | s/GB | 54.37 | 43.83 | · | · | 0.81x ✓ |
| RSS, client | kB | 52,516 | 17,540 | · | · | 0.33x ✓ |
| RSS, server | kB | 53,072 | 18,864 | · | · | 0.36x ✓ |
| peak VmHWM, client | kB | 52,516 | 20,324 | · | · | 0.39x ✓ |
| peak VmHWM, server | kB | 57,120 | 18,864 | · | · | 0.33x ✓ |
| OutSegs, client | segments | 565,601 | 649,113 | · | · | 1.15x |
| OutSegs, server | segments | 241,543 | 372,644 | · | · | 1.54x |
| retransmitted share, client | % of OutSegs | 36.5 | 34.2 | · | · | 0.94x ✓ |
| retransmitted share, server | % of OutSegs | 0.0 | 0.0 | · | · | n/a |
| RetransSegs, client | segments | 205,009 | 227,756 | · | · | 1.11x ✗ |
| RetransSegs, server | segments | 1 | 1 | · | · | n/a |
| FastRetransSegs, client | segments | 133,486 | 146,062 | · | · | 1.09x ✗ |
| FastRetransSegs, server | segments | 0 | 0 | · | · | n/a |
| EarlyRetransSegs, client | segments | 3,731 | 1,945 | · | · | 0.52x ✓ |
| EarlyRetransSegs, server | segments | 0 | 0 | · | · | n/a |
| LostSegs, client | segments | 67,454 | 79,999 | · | · | 1.19x ✗ |
| LostSegs, server | segments | 1 | 1 | · | · | n/a |
| RepeatSegs received by the client | segments | 1 | 2 | · | · | n/a |
| RepeatSegs received by the server | segments | 5,039 | 17,314 | · | · | 3.44x ✗ |

The spread behind those medians — every run of *goodput* (Mbit/s), in the order it ran:

| pair | runs | min | median | max | every run |
|---|---:|---:|---:|---:|---|
| GG | 5 | 136.4 | 147.9 | 158.0 | 157.3, 147.9, 136.4, 158.0, 146.6 |
| RR | 5 | 165.5 | 182.1 | 195.9 | 182.1, 165.5, 183.7, 195.9, 180.4 |
| GR | 5 | 199.4 | 204.2 | 229.2 | 229.2, 216.3, 204.2, 201.7, 199.4 |
| RG | 5 | 148.4 | 157.1 | 157.6 | 150.6, 157.6, 148.4, 157.1, 157.4 |

Produced by:

```sh
tools/lab/lab.py --host lab-x86-1 --runs-dir lab-runs/20260924T095034Z-bench-baseline run lab-runs/20260924T095034Z-bench-baseline/scenarios/baseline-s1-bulk-up.json --no-report --wait-load 600
```

### `bulk-down` — one TCP stream through the tunnel, server to client (iperf3 -R)

| measurement | unit | GG | RR | GR | RG | RR/GG |
|---|---:|---:|---:|---:|---:|---:|
| goodput | Mbit/s | 159.3 | 194.8 | 159.0 | 238.2 | 1.22x ✓ |
| TCP retransmits | segments | 55 | 54 | 48 | 68 | n/a |
| CPU per GB, client | s/GB | 22.53 | 15.07 | · | · | 0.67x ✓ |
| CPU per GB, server | s/GB | 29.37 | 26.51 | · | · | 0.90x ✓ |
| CPU per GB, both ends | s/GB | 51.70 | 41.59 | · | · | 0.80x ✓ |
| RSS, client | kB | 54,308 | 16,356 | · | · | 0.30x ✓ |
| RSS, server | kB | 48,164 | 15,948 | · | · | 0.33x ✓ |
| peak VmHWM, client | kB | 58,404 | 16,544 | · | · | 0.28x ✓ |
| peak VmHWM, server | kB | 49,744 | 19,972 | · | · | 0.40x ✓ |
| OutSegs, client | segments | 250,616 | 407,318 | · | · | 1.63x |
| OutSegs, server | segments | 521,532 | 623,280 | · | · | 1.20x |
| retransmitted share, client | % of OutSegs | 0.0 | 0.0 | · | · | n/a |
| retransmitted share, server | % of OutSegs | 33.7 | 29.3 | · | · | 0.87x ✓ |
| RetransSegs, client | segments | 1 | 3 | · | · | n/a |
| RetransSegs, server | segments | 178,053 | 177,437 | · | · | 1.00x ✓ |
| FastRetransSegs, client | segments | 0 | 0 | · | · | n/a |
| FastRetransSegs, server | segments | 116,909 | 114,183 | · | · | 0.98x ✓ |
| EarlyRetransSegs, client | segments | 0 | 0 | · | · | n/a |
| EarlyRetransSegs, server | segments | 4,111 | 1,298 | · | · | 0.32x ✓ |
| LostSegs, client | segments | 1 | 3 | · | · | n/a |
| LostSegs, server | segments | 53,446 | 67,250 | · | · | 1.26x ✗ |
| RepeatSegs received by the client | segments | 6,504 | 18,416 | · | · | 2.83x ✗ |
| RepeatSegs received by the server | segments | 1 | 3 | · | · | n/a |

The spread behind those medians — every run of *goodput* (Mbit/s), in the order it ran:

| pair | runs | min | median | max | every run |
|---|---:|---:|---:|---:|---|
| GG | 5 | 149.5 | 159.3 | 165.6 | 159.3, 160.1, 149.5, 152.9, 165.6 |
| RR | 5 | 181.6 | 194.8 | 200.7 | 181.6, 200.7, 194.8, 199.6, 183.3 |
| GR | 5 | 150.9 | 159.0 | 167.0 | 160.0, 167.0, 150.9, 159.0, 159.0 |
| RG | 5 | 212.8 | 238.2 | 242.7 | 212.8, 242.7, 238.5, 238.2, 232.4 |

Produced by:

```sh
tools/lab/lab.py --host lab-x86-1 --runs-dir lab-runs/20260924T095034Z-bench-baseline run lab-runs/20260924T095034Z-bench-baseline/scenarios/baseline-s1-bulk-down.json --no-report --wait-load 600
```

### `latency` — 64-byte ping/pong through an otherwise idle tunnel

| measurement | unit | GG | RR | RR/GG |
|---|---:|---:|---:|---:|
| latency p50 | ms | 0.44 | 0.23 | 0.53x ✓ |
| latency p90 | ms | 0.68 | 0.33 | 0.49x ✓ |
| latency p99 | ms | 1.50 | 0.69 | 0.46x ✓ |
| latency max | ms | 10.08 | 7.48 | 0.74x ✓ |
| latency errors | count | 0 | 0 | n/a |
| CPU over the run, client | s | 7.66 | 6.74 | 0.88x ✓ |
| CPU over the run, server | s | 7.45 | 6.75 | 0.91x ✓ |
| RSS, client | kB | 25,712 | 4,772 | 0.19x ✓ |
| RSS, server | kB | 25,760 | 4,524 | 0.18x ✓ |
| peak VmHWM, client | kB | 25,712 | 4,776 | 0.19x ✓ |
| peak VmHWM, server | kB | 25,760 | 4,720 | 0.18x ✓ |

The spread behind those medians — every run of *latency p50* (ms), in the order it ran:

| pair | runs | min | median | max | every run |
|---|---:|---:|---:|---:|---|
| GG | 5 | 0.40 | 0.44 | 0.48 | 0.44, 0.40, 0.47, 0.42, 0.48 |
| RR | 5 | 0.22 | 0.23 | 0.25 | 0.23, 0.22, 0.25, 0.22, 0.24 |

Produced by:

```sh
tools/lab/lab.py --host lab-x86-1 --runs-dir lab-runs/20260924T095034Z-bench-baseline run lab-runs/20260924T095034Z-bench-baseline/scenarios/baseline-s1-latency.json --no-report --wait-load 600
```

### `latency-loaded` — the same ping/pong while a bulk flow saturates the same tunnel

| measurement | unit | GG | RR | RR/GG |
|---|---:|---:|---:|---:|
| latency p50 | ms | 0.46 | 0.25 | 0.54x ✓ |
| latency p90 | ms | 1.20 | 0.42 | 0.35x ✓ |
| latency p99 | ms | 77.33 | 16.09 | 0.21x ✓ |
| latency max | ms | 420.78 | 309.63 | 0.74x ✓ |
| latency errors | count | 0 | 0 | n/a |
| goodput | Mbit/s | 90.6 | 134.2 | 1.48x ✓ |
| CPU per GB, client | s/GB | 41.28 | 23.81 | 0.58x ✓ |
| CPU per GB, server | s/GB | 27.11 | 19.31 | 0.71x ✓ |
| CPU per GB, both ends | s/GB | 68.39 | 43.06 | 0.63x ✓ |
| RSS, client | kB | 50,184 | 16,624 | 0.33x ✓ |
| RSS, server | kB | 54,104 | 12,600 | 0.23x ✓ |
| peak VmHWM, client | kB | 50,184 | 17,680 | 0.35x ✓ |
| peak VmHWM, server | kB | 54,992 | 13,308 | 0.24x ✓ |
| OutSegs, client | segments | 408,143 | 499,137 | 1.22x |
| OutSegs, server | segments | 169,754 | 262,774 | 1.55x |
| retransmitted share, client | % of OutSegs | 47.9 | 33.3 | 0.70x ✓ |
| retransmitted share, server | % of OutSegs | 0.0 | 0.0 | n/a |
| RetransSegs, client | segments | 206,432 | 166,124 | 0.80x ✓ |
| RetransSegs, server | segments | 11 | 5 | n/a |
| FastRetransSegs, client | segments | 90,075 | 109,002 | 1.21x ✗ |
| FastRetransSegs, server | segments | 0 | 0 | n/a |
| EarlyRetransSegs, client | segments | 5,976 | 1,154 | 0.19x ✓ |
| EarlyRetransSegs, server | segments | 0 | 0 | n/a |
| LostSegs, client | segments | 97,712 | 57,152 | 0.58x ✓ |
| LostSegs, server | segments | 11 | 5 | n/a |
| RepeatSegs received by the client | segments | 11 | 5 | n/a |
| RepeatSegs received by the server | segments | 8,390 | 7,414 | 0.88x ✓ |

The spread behind those medians — every run of *latency p50* (ms), in the order it ran:

| pair | runs | min | median | max | every run |
|---|---:|---:|---:|---:|---|
| GG | 5 | 0.44 | 0.46 | 0.48 | 0.48, 0.46, 0.47, 0.44, 0.45 |
| RR | 5 | 0.23 | 0.25 | 0.26 | 0.26, 0.25, 0.25, 0.23, 0.25 |

Produced by:

```sh
tools/lab/lab.py --host lab-x86-1 --runs-dir lab-runs/20260924T095034Z-bench-baseline run lab-runs/20260924T095034Z-bench-baseline/scenarios/baseline-s1-latency-loaded.json --no-report --wait-load 600
```

## Configuration `s2` — kcptun's own defaults

```
both   -mode fast -crypt aes -mtu 1350 -sndwnd 128 -rcvwnd 512 -smuxver 2 -smuxbuf 4194304 -streambuf 2097152 -datashard 10 -parityshard 3
client -conn 1
```

### `bulk-up` — one TCP stream through the tunnel, client to server (iperf3, forward)

| measurement | unit | GG | RR | GR | RG | RR/GG |
|---|---:|---:|---:|---:|---:|---:|
| goodput | Mbit/s | 140.0 | 250.6 | 159.8 | 223.9 | 1.79x ✓ |
| TCP retransmits | segments | 11 | 3 | 1 | 13 | n/a |
| CPU per GB, client | s/GB | 30.69 | 15.54 | · | · | 0.51x ✓ |
| CPU per GB, server | s/GB | 25.29 | 15.51 | · | · | 0.61x ✓ |
| CPU per GB, both ends | s/GB | 57.06 | 31.05 | · | · | 0.54x ✓ |
| RSS, client | kB | 29,320 | 5,700 | · | · | 0.19x ✓ |
| RSS, server | kB | 28,384 | 7,008 | · | · | 0.25x ✓ |
| peak VmHWM, client | kB | 29,320 | 5,708 | · | · | 0.19x ✓ |
| peak VmHWM, server | kB | 28,384 | 7,008 | · | · | 0.25x ✓ |
| OutSegs, client | segments | 371,416 | 582,174 | · | · | 1.57x |
| OutSegs, server | segments | 8,055 | 11,837 | · | · | 1.47x |
| retransmitted share, client | % of OutSegs | 0.0 | 0.0 | · | · | n/a |
| retransmitted share, server | % of OutSegs | 0.0 | 0.0 | · | · | n/a |
| RetransSegs, client | segments | 0 | 0 | · | · | n/a |
| RetransSegs, server | segments | 0 | 0 | · | · | n/a |
| FastRetransSegs, client | segments | 0 | 0 | · | · | n/a |
| FastRetransSegs, server | segments | 0 | 0 | · | · | n/a |
| EarlyRetransSegs, client | segments | 0 | 0 | · | · | n/a |
| EarlyRetransSegs, server | segments | 0 | 0 | · | · | n/a |
| LostSegs, client | segments | 0 | 0 | · | · | n/a |
| LostSegs, server | segments | 0 | 0 | · | · | n/a |
| RepeatSegs received by the client | segments | 0 | 0 | · | · | n/a |
| RepeatSegs received by the server | segments | 0 | 0 | · | · | n/a |

The spread behind those medians — every run of *goodput* (Mbit/s), in the order it ran:

| pair | runs | min | median | max | every run |
|---|---:|---:|---:|---:|---|
| GG | 5 | 129.5 | 140.0 | 155.2 | 155.2, 140.0, 146.5, 137.2, 129.5 |
| RR | 5 | 229.7 | 250.6 | 256.0 | 252.8, 256.0, 233.3, 250.6, 229.7 |
| GR | 5 | 151.8 | 159.8 | 182.1 | 151.8, 163.0, 158.2, 182.1, 159.8 |
| RG | 5 | 207.2 | 223.9 | 260.9 | 223.9, 212.8, 236.4, 260.9, 207.2 |

Produced by:

```sh
tools/lab/lab.py --host lab-x86-1 --runs-dir lab-runs/20260924T095034Z-bench-baseline run lab-runs/20260924T095034Z-bench-baseline/scenarios/baseline-s2-bulk-up.json --no-report --wait-load 600
```

### `bulk-down` — one TCP stream through the tunnel, server to client (iperf3 -R)

| measurement | unit | GG | RR | GR | RG | RR/GG |
|---|---:|---:|---:|---:|---:|---:|
| goodput | Mbit/s | 114.3 | 247.1 | 229.3 | 166.4 | 2.16x ✓ |
| TCP retransmits | segments | 9 | 3 | 9 | 2 | n/a |
| CPU per GB, client | s/GB | 34.44 | 15.76 | · | · | 0.46x ✓ |
| CPU per GB, server | s/GB | 36.23 | 15.76 | · | · | 0.44x ✓ |
| CPU per GB, both ends | s/GB | 71.50 | 31.53 | · | · | 0.44x ✓ |
| RSS, client | kB | 28,404 | 6,052 | · | · | 0.21x ✓ |
| RSS, server | kB | 27,912 | 5,336 | · | · | 0.19x ✓ |
| peak VmHWM, client | kB | 28,468 | 6,124 | · | · | 0.22x ✓ |
| peak VmHWM, server | kB | 27,912 | 5,336 | · | · | 0.19x ✓ |
| OutSegs, client | segments | 7,155 | 12,252 | · | · | 1.71x |
| OutSegs, server | segments | 304,712 | 560,258 | · | · | 1.84x |
| retransmitted share, client | % of OutSegs | 0.0 | 0.0 | · | · | n/a |
| retransmitted share, server | % of OutSegs | 0.0 | 0.0 | · | · | n/a |
| RetransSegs, client | segments | 0 | 0 | · | · | n/a |
| RetransSegs, server | segments | 0 | 0 | · | · | n/a |
| FastRetransSegs, client | segments | 0 | 0 | · | · | n/a |
| FastRetransSegs, server | segments | 0 | 0 | · | · | n/a |
| EarlyRetransSegs, client | segments | 0 | 0 | · | · | n/a |
| EarlyRetransSegs, server | segments | 0 | 0 | · | · | n/a |
| LostSegs, client | segments | 0 | 0 | · | · | n/a |
| LostSegs, server | segments | 0 | 0 | · | · | n/a |
| RepeatSegs received by the client | segments | 0 | 0 | · | · | n/a |
| RepeatSegs received by the server | segments | 0 | 0 | · | · | n/a |

The spread behind those medians — every run of *goodput* (Mbit/s), in the order it ran:

| pair | runs | min | median | max | every run |
|---|---:|---:|---:|---:|---|
| GG | 5 | 111.4 | 114.3 | 135.9 | 112.5, 117.1, 114.3, 111.4, 135.9 |
| RR | 5 | 239.3 | 247.1 | 259.8 | 239.3, 247.1, 245.7, 256.1, 259.8 |
| GR | 5 | 223.1 | 229.3 | 244.9 | 237.6, 229.3, 223.1, 227.3, 244.9 |
| RG | 5 | 150.4 | 166.4 | 171.3 | 150.4, 166.4, 170.0, 163.0, 171.3 |

Produced by:

```sh
tools/lab/lab.py --host lab-x86-1 --runs-dir lab-runs/20260924T095034Z-bench-baseline run lab-runs/20260924T095034Z-bench-baseline/scenarios/baseline-s2-bulk-down.json --no-report --wait-load 600
```

### `latency` — 64-byte ping/pong through an otherwise idle tunnel

| measurement | unit | GG | RR | RR/GG |
|---|---:|---:|---:|---:|
| latency p50 | ms | 0.67 | 0.25 | 0.37x ✓ |
| latency p90 | ms | 1.13 | 0.36 | 0.32x ✓ |
| latency p99 | ms | 2.89 | 0.71 | 0.25x ✓ |
| latency max | ms | 15.99 | 7.53 | 0.47x ✓ |
| latency errors | count | 0 | 0 | n/a |
| CPU over the run, client | s | 8.17 | 6.98 | 0.85x ✓ |
| CPU over the run, server | s | 8.01 | 6.98 | 0.87x ✓ |
| RSS, client | kB | 26,236 | 5,036 | 0.19x ✓ |
| RSS, server | kB | 26,456 | 5,184 | 0.20x ✓ |
| peak VmHWM, client | kB | 26,236 | 5,044 | 0.19x ✓ |
| peak VmHWM, server | kB | 26,456 | 5,184 | 0.20x ✓ |

The spread behind those medians — every run of *latency p50* (ms), in the order it ran:

| pair | runs | min | median | max | every run |
|---|---:|---:|---:|---:|---|
| GG | 5 | 0.64 | 0.67 | 0.72 | 0.72, 0.64, 0.70, 0.67, 0.67 |
| RR | 5 | 0.24 | 0.25 | 0.28 | 0.25, 0.28, 0.25, 0.26, 0.24 |

Produced by:

```sh
tools/lab/lab.py --host lab-x86-1 --runs-dir lab-runs/20260924T095034Z-bench-baseline run lab-runs/20260924T095034Z-bench-baseline/scenarios/baseline-s2-latency.json --no-report --wait-load 600
```

### `latency-loaded` — the same ping/pong while a bulk flow saturates the same tunnel

| measurement | unit | GG | RR | RR/GG |
|---|---:|---:|---:|---:|
| latency p50 | ms | 13.40 | 5.91 | 0.44x ✓ |
| latency p90 | ms | 21.56 | 9.08 | 0.42x ✓ |
| latency p99 | ms | 33.10 | 15.70 | 0.47x ✓ |
| latency max | ms | 52.68 | 31.56 | 0.60x ✓ |
| latency errors | count | 0 | 0 | n/a |
| goodput | Mbit/s | 117.4 | 228.1 | 1.94x ✓ |
| CPU per GB, client | s/GB | 29.77 | 14.27 | 0.48x ✓ |
| CPU per GB, server | s/GB | 27.08 | 14.29 | 0.53x ✓ |
| CPU per GB, both ends | s/GB | 56.78 | 28.56 | 0.50x ✓ |
| RSS, client | kB | 28,512 | 5,764 | 0.20x ✓ |
| RSS, server | kB | 29,740 | 5,656 | 0.19x ✓ |
| peak VmHWM, client | kB | 28,512 | 5,772 | 0.20x ✓ |
| peak VmHWM, server | kB | 29,740 | 5,656 | 0.19x ✓ |
| OutSegs, client | segments | 299,827 | 500,325 | 1.67x |
| OutSegs, server | segments | 10,866 | 15,704 | 1.45x |
| retransmitted share, client | % of OutSegs | 0.0 | 0.0 | n/a |
| retransmitted share, server | % of OutSegs | 0.0 | 0.0 | n/a |
| RetransSegs, client | segments | 0 | 0 | n/a |
| RetransSegs, server | segments | 0 | 0 | n/a |
| FastRetransSegs, client | segments | 0 | 0 | n/a |
| FastRetransSegs, server | segments | 0 | 0 | n/a |
| EarlyRetransSegs, client | segments | 0 | 0 | n/a |
| EarlyRetransSegs, server | segments | 0 | 0 | n/a |
| LostSegs, client | segments | 0 | 0 | n/a |
| LostSegs, server | segments | 0 | 0 | n/a |
| RepeatSegs received by the client | segments | 0 | 0 | n/a |
| RepeatSegs received by the server | segments | 0 | 0 | n/a |

The spread behind those medians — every run of *latency p50* (ms), in the order it ran:

| pair | runs | min | median | max | every run |
|---|---:|---:|---:|---:|---|
| GG | 5 | 11.50 | 13.40 | 13.99 | 11.50, 13.40, 13.34, 13.40, 13.99 |
| RR | 5 | 5.82 | 5.91 | 6.31 | 5.91, 5.88, 5.82, 6.31, 6.24 |

Produced by:

```sh
tools/lab/lab.py --host lab-x86-1 --runs-dir lab-runs/20260924T095034Z-bench-baseline run lab-runs/20260924T095034Z-bench-baseline/scenarios/baseline-s2-latency-loaded.json --no-report --wait-load 600
```

## Observations

> **⚠ Observations 1, 3, 4 and 5 below rest in whole or in part on the withdrawn `s1` tables, and three of their conclusions are now known to be wrong.** The S1 retransmission rates, the `RepeatSegs` lead and the cross-pair reading were all produced by this host's stock socket-buffer ceiling; see the banner at the top of the page and the [12.1b re-take](2026-09-24-lab-x86-1-netns-clean-s1-sockbuf.md), whose own observations say what each of them became. What still stands here is everything about `s2`.

**Every acceptance criterion in step 12's Definition of Done is met on this box, in both profiles.** Rust's goodput is 1.22-2.16x Go's, its CPU per GB for both ends together 0.44-0.81x (0.44-0.92x per end), its steady RSS 0.18-0.36x, its idle p50 latency 0.37-0.53x and its p99 under a competing bulk flow 0.21-0.47x. **No acceptance-criterion row — goodput, CPU per GB, RSS, p50 or p99 — has Rust on the wrong side of Go anywhere in the grid.** Seven other rows do carry a cross, and every one of them is an S1 retransmission or duplicate counter. Five are absolute `RetransSegs`/`FastRetransSegs`/`LostSegs` totals at 1.09-1.26x, on cells where Rust also moved more data (`OutSegs` 1.15-1.22x, goodput 1.22-1.48x) and where the `retransmitted share of OutSegs` row printed directly beside each of them goes the *other* way (0.94x, 0.87x, 0.70x — observation 4). The remaining two are `RepeatSegs`, at 2.83x and 3.44x, and those are the one real lead on this page; observation 5 takes them. That is the baseline Step 12.2f onwards has to beat, and it is also the first end-to-end number in this repository that is not a micro-benchmark or a memory measurement.

**The box is one vCPU and both tunnel ends run on it, so goodput here is a CPU measurement wearing a network's clothes.** Read the goodput and the CPU-per-GB rows together: they move as each other's reciprocal in every cell (S1 `bulk-up`, for example, is 148 -> 182 Mbit/s against 54.4 -> 43.8 CPU s/GB). Absolute Mbit/s says nothing about what a real link would deliver; the ratio between the columns is the result.

**The cross pairs say where S1's cost is, and it is the sending side — and S2 says the opposite.** On S1 `bulk-up` (the client sends) the fastest pair is **GR** at 204 Mbit/s — a *Go* client feeding a Rust server — ahead of RR's 182, while RG (Rust client, Go server) is slowest at 157. On S1 `bulk-down` (the server sends) the mirror holds: **RG** is fastest at 238 Mbit/s and GR slowest at 159. In both directions the pair with a **Go sender and a Rust receiver** wins, so at S1 the Rust receive path is clearly cheaper than Go's and the Rust *send* path is more expensive, and RR's overall win is the receive side carrying the send side. **At S2 it is exactly reversed**: uploading, RG (Rust client sending) reaches 224 Mbit/s against GR's 160; downloading, GR (Rust server sending) reaches 229 against RG's 166 — the Rust *sender* is the fast side, and RR is the fastest pair in both directions (251 and 247). So this is not a property of the port's send path in general; it is specific to S1's `-mode normal` with 8192-packet windows, `xor` and no FEC, which is also the only configuration in the grid that retransmits at all. **This is the single most useful lead in the grid for 12.2**, and it is a lead, not a finding: the cross pairs' CPU columns are deliberately not tabulated (step 12.1), both ends share one core, and attributing it needs a profile rather than a ratio.

**11.4's open question has its control, and the answer is "not the implementation".** The 11.4 soak found 28.4% of the Rust client's outgoing segments were retransmissions on a netem path with 0.1% configured loss, and recorded that it must not be tuned before a Go control landed. Here is that control, on a *clean* path with no configured loss at all: at S1 the retransmitted share of `OutSegs` is **36.5% for Go and 34.2% for Rust** uploading, **33.7% and 29.3%** downloading, and **47.9% and 33.3%** with a latency probe sharing the tunnel. At S2 both are at **0.0%**. Go does the same thing, slightly more of it. And the aarch64 page taken the same day ([2026-09-24-lab-arm64-netns-clean.md](2026-09-24-lab-arm64-netns-clean.md)) settles what *causes* it: on a box with a second core the same S1 profile gives **13.2% for Go and 0.0% for Rust**. Same binaries, same profile, same clean namespace path. So this is neither the port nor KCP: it is what a saturated receiver does, and the cheaper implementation stops doing it first. **Nothing about the RTO or the fast-retransmit threshold should be tuned on the strength of a retransmission count taken on a box that had no headroom.**

**One counter does go the other way here, and the second host says why it is not a port defect.** `RepeatSegs` — duplicate segments the *peer* received, i.e. retransmissions that were not needed — is 3-10x higher on this box when the sender is Rust: uploading, the server received 17,314 duplicates from a Rust client against 5,039 from a Go one (18,270 against 1,895 in the cross pairs); downloading, the client received 18,416 from a Rust server against 6,504 from a Go one (21,453 against 2,142). Both directions and both cross pairs agree across five runs each, at about 2.7-3.0% of `OutSegs` for Rust against 0.9-1.2% for Go in the like-for-like pairs, and 3.1-3.8% against 0.3% in the cross pairs. On the 2-vCPU aarch64 host the same cells are **0 for Rust and 12,640 / 14,936 for Go** — the sign reverses. Read together with the retransmission rows, the honest reading is that on this box Rust drives the saturated link harder and therefore wastes more of what it retransmits, not that its RTO estimate is worse than Go's. It stays a lead for 12.2, to be re-taken at a bounded rate rather than at saturation.

**Latency is the least ambiguous row here.** Through an idle S1 tunnel on loopback the port's p50 is 0.23 ms against Go's 0.44 and its p99 0.69 ms against 1.50, with no overlap at all between the two sets of five runs (Rust 0.216-0.248 ms p50, Go 0.396-0.482). Under a competing bulk flow the p99 gap widens to 16.1 ms against 77.3 ms. On a loopback path almost all of that is scheduling and copying rather than propagation, which is exactly what a port is allowed to be judged on.

**Memory is a rout here too, and it is not the same measurement as `memory.md`'s.** These are RSS figures for processes that have just moved several hundred megabytes, not idle ones: 17.5 MB against 52.5 MB for the S1 client, 5.7 MB against 29.3 MB at S2. `docs/benchmarks/memory.md` owns the idle floor (1.71 MB against 16.73) and, more importantly, owns the one place the port loses — what is given back after a burst. Nothing on this page measures release.

## Raw data

Every number above is a median of the rows in [`2026-09-24-lab-x86-1-netns-clean.csv`](2026-09-24-lab-x86-1-netns-clean.csv) — one row per configuration, metric, pair, repetition and measurement. The run directories the CSV names are under `lab-runs/` (gitignored) on the machine that ran the campaign, one `state.json`, `proc.csv`, `snmp-*.csv` and workload log per run.

The CSV is the **complete** record and is wider than the tables: it carries the cross pairs' CPU and memory rows, which the tables deliberately do not show (see the `·` note above). They are data, not a comparison — a GR row's CPU is a Go client's and a Rust server's added together — so anything read out of them is a lead to be confirmed, never a result.

Regenerate the page and the CSV from those directories without re-running anything:

```sh
tools/bench/bench.py report lab-runs/20260924T095034Z-bench-baseline
```

