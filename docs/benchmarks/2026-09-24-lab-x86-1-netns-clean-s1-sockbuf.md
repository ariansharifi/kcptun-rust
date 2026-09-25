# Go vs Rust end to end: lab-x86-1-netns-clean, S1 at a raised socket-buffer ceiling, 2026-09-24

> **Note: `-sockbuf` is clamped here, at a raised ceiling.** `s1` server asks for 67,108,868 B, `lab-x86-1` `net.core.rmem_max` is 8,388,608 B, so the receive buffer is 8x smaller than asked for; `s1` server asks for 67,108,868 B, `lab-x86-1` `net.core.wmem_max` is 67,108,864 B, so the send buffer is 4 B short. That is the same clamp lab-arm64 runs under, where D32 measured zero `UdpRcvbufErrors` over a 65 s S1 run, so it is a stated condition of these numbers rather than a reason to discard them.

**Sub-step 12.1b: the S1 half of the 12.1 baseline, re-taken on a host that can honour `-sockbuf`.** It supersedes the `s1` sections of [2026-09-24-lab-x86-1-netns-clean.md](2026-09-24-lab-x86-1-netns-clean.md), which were taken on the same host, with the same binaries, while `net.core.rmem_max` was the stock 212,992 B. docs/DECISIONS.md D32 says an S1 measurement taken under that ceiling is invalid and must be discarded rather than interpreted, so those rows are withdrawn and these replace them. Only the ceiling changed: same host, same byte-identical binaries, same campaign, same five repetitions, same interleaving.

## Method

| | |
|---|---|
| campaign | `baseline-netns-s1-sockbuf.json` |
| client host | `lab-x86-1`: Linux 5.15.0-177-generic x86_64, 1 vCPU, Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz, ldd (Ubuntu GLIBC 2.35-0ubuntu3.15) 2.35, 1.9 GiB |
| arrangement | both tunnel ends in the `kr-cli`/`kr-srv` namespaces of one host, netem profile `clean` |
| configurations | `s1` (s1 = the user's production profile) |
| metric families | `bulk-up`, `bulk-down`, `latency`, `latency-loaded` |
| repetitions | 5 per pair per cell, A/B interleaved (GG, RR, GR, RG, then again) |
| workload duration | 20 s |
| socket-buffer ceilings | `lab-x86-1` `rmem_max` 8,388,608, `wmem_max` 67,108,864: `setsockopt(SO_RCVBUF)`/`SO_SNDBUF` is silently clamped to these (docs/DECISIONS.md D32). Requested `-sockbuf` → what the kernel grants: `s1` client 8,388,608 → honoured; `s1` server 67,108,868 → **8,388,608**. |
| iperf3 | iperf 3.9 (cJSON 1.7.13) at `/usr/bin/iperf3`, sha256 `2c54c89b4d9016b9…`: the host's own package, which carries no build stamp of ours |
| started | 2026-09-24T22:08:12Z |
| finished | 2026-09-24T22:49:38Z |
| runs harvested | 60 |

Artefacts: go `75fd8d8d61c0` (none, linux/amd64) on `lab-x86-1`; lab tools `75fd8d8d61c0` (glibc 2.17, x86_64-unknown-linux-gnu) on `lab-x86-1`; rust `75fd8d8d61c0` (glibc 2.17, x86_64-unknown-linux-gnu) on `lab-x86-1`.

**Built from a modified tree:** `75fd8d8-dirty` (go, lab, rust). The commit above names the base, not the tree the binary was built from; check what differed before treating these numbers as that commit's.

Read before quoting anything here:

* Every cell is a **median over the repetitions of one session**, and the pairs inside a session were interleaved, so the columns share whatever the box was doing. Medians from two different sessions are not comparable, on a shared box, and on a real path, absolutely not.
* `RR/GG` is annotated ✓ when Rust is on the better side of Go for **that** row's direction (high is better for goodput and stream counts, low for CPU, memory, latency and retransmissions).
* A `·` cell is one that is deliberately not measured: step 12.1 gives the cross pairs (GR, RG) throughput only, because a CPU or RSS row for a mixed pair describes two different implementations at once.
* A `-` cell is **not measured**, never measured-as-zero. An `n/a` ratio is one the two cells beside it cannot support: either Go's median is zero, so the ratio is undefined rather than infinite, or both medians are segment counts below 100 over the whole run, where a ratio would be a verdict on noise. A number in parentheses after a cell is the number of runs behind it when that is fewer than the 5 the plan requires.
* CPU per GB divides the process's own `utime + stime` by the bytes the *workload* moved, not by the bytes that went over the wire: charging an implementation only for the goodput it delivered is what makes FEC and retransmission show up as cost rather than as credit.
* `RetransSegs` **decomposes**: one `flush` adds `LostSegs + FastRetransSegs + EarlyRetransSegs` into it, so all three components are printed beneath it and a `RetransSegs` row with an unexplained remainder means a counter is missing from this page rather than that some retransmission is unattributable. The three are medians of their own five runs, so they sum to the `RetransSegs` median only to within the run-to-run spread, not exactly; the per-run rows in the CSV do sum exactly.
* **What was wrong with the run this replaces, and how it is known.** `setsockopt(SO_RCVBUF)` and `SO_SNDBUF` are silently clamped to `net.core.rmem_max`/`wmem_max`, so an S1 client asking for `-sockbuf 8388608` on a stock Ubuntu box gets 212,992 B and is told nothing. 11.2 measured what that costs on the same class of host: over one 65 s S1 run Go lost 95,133 datagrams to `UdpRcvbufErrors` (24.4% of arrivals) and Rust lost 223,293 (48.3%); at a raised ceiling both lost zero and three cells that had failed the >= 0.95x criterion inverted to 1.09-1.45x (docs/DECISIONS.md D32). `lab-x86-1` carried the stock ceiling when the superseded campaign ran: its `/etc/sysctl.d/99-kcptun-lab.conf` is dated 2026-09-24T21:57:15Z and is the only file under `/etc/sysctl.conf` or `/etc/sysctl.d/` that sets either limit, while that campaign ran 09:50:34Z to 11:14:01Z. Neither 12.1 page records a ceiling at all, which is what let the rows out; `bench.py` now prints one in every method table and refuses to start a campaign that a stock ceiling would invalidate.
* **The same binaries, deliberately not rebuilt.** `~/kcptun-lab/bin` on `lab-x86-1` still holds the 12.1 deployment (`BUILD.txt`: `revision=75fd8d8-dirty`, `deployed=2026-09-24T09:44:50Z`) and nothing was redeployed for this run, so the only variable between the superseded page and this one is the host's socket-buffer ceiling. As on that page, what differed from `75fd8d8` was only untracked files (the harness itself) and no tracked file under `crates/` was modified.
* **The server's `-sockbuf` is still clamped, and that is the intended condition.** S1 asks the server for 67,108,868 B against a raised `rmem_max` of 8,388,608, so the kernel grants 8 MiB. That is exactly the ceiling lab-arm64 runs under, and the ceiling at which D32 measured zero `UdpRcvbufErrors`; the method table states it rather than leaving it implicit. What changed is the client, whose 8,388,608 B request is now honoured to the byte instead of being cut to 208 KiB.
* **Why S2 is not re-taken here, and why the obvious reason is wrong.** S2 passes no `-sockbuf`, which reads as "asks for nothing", but kcptun's flag defaults to 4,194,304 B (`reference/kcptun/client/main.go:185-188`, `server/main.go:176-179`) and the binary always calls `SetReadBuffer`/`SetWriteBuffer` with it, so S2 was clamped on the stock host too, by 20x. What exempts it is not its request but its window: `-sndwnd 128` at `-mtu 1350` is about 173 kB of data per flush, ~224 kB on the wire once FEC's 10/3 parity is counted, the same order as the 208 KiB ceiling rather than comfortably inside it, which is why this was checked rather than argued, and the superseded page measures the consequence directly, the retransmitted share of `OutSegs` at S2 is **0.0% for both implementations**, which a buffer that was overflowing could not produce. A separate one-cell control was run to check that rather than argue it; see [2026-09-24-lab-x86-1-netns-clean-s2-control.md](2026-09-24-lab-x86-1-netns-clean-s2-control.md).
* The host has **one** vCPU and carries both tunnel ends, the workload and the echo target. Absolute goodput here is a property of that core, not of a network; only the Go-versus-Rust columns of one cell are comparable.
* This page carries S1 only. The superseded page's S2 sections, its observations about the cross pairs at S2 and its coverage caveat still stand for S2; what is withdrawn is its S1 rows. Neither page is the full grid: `bulk-par-up`/`bulk-par-down`, `churn` and configurations `s3`/`s4` were not run, and step 12's Idle-cost and Startup rows and S5 (QPP) have no harness family at all.

## Configuration `s1`: the user's production profile

```
both   -mode normal -crypt xor -mtu 1390 -sndwnd 8192 -rcvwnd 8192 -smuxver 2 -smuxbuf 16777216 -streambuf 16777216 -datashard 0 -parityshard 0 -nocomp -quiet
client -conn 4 -sockbuf 8388608
server -sockbuf 67108868
```

### `bulk-up`: one TCP stream through the tunnel, client to server (iperf3, forward)

| measurement | unit | GG | RR | GR | RG | RR/GG |
|---|---:|---:|---:|---:|---:|---:|
| goodput | Mbit/s | 316.5 | 526.6 | 362.7 | 433.5 | 1.66x ✓ |
| TCP retransmits | segments | 57 | 156 | 32 | 211 | 2.74x ✗ |
| CPU per GB, client | s/GB | 11.04 | 6.93 | · | · | 0.63x ✓ |
| CPU per GB, server | s/GB | 13.53 | 6.84 | · | · | 0.51x ✓ |
| CPU per GB, both ends | s/GB | 24.49 | 13.78 | · | · | 0.56x ✓ |
| RSS, client | kB | 37,192 | 7,452 | · | · | 0.20x ✓ |
| RSS, server | kB | 44,564 | 13,000 | · | · | 0.29x ✓ |
| peak VmHWM, client | kB | 51,736 | 7,452 | · | · | 0.14x ✓ |
| peak VmHWM, server | kB | 50,692 | 13,000 | · | · | 0.26x ✓ |
| OutSegs, client | segments | 748,567 | 1,223,239 | · | · | 1.63x |
| OutSegs, server | segments | 17,511 | 21,230 | · | · | 1.21x |
| retransmitted share, client | % of OutSegs | 1.5 | 0.0 | · | · | 0.00x ✓ |
| retransmitted share, server | % of OutSegs | 0.0 | 0.0 | · | · | n/a |
| RetransSegs, client | segments | 10,611 | 0 | · | · | 0.00x ✓ |
| RetransSegs, server | segments | 1 | 0 | · | · | n/a |
| FastRetransSegs, client | segments | 3,450 | 0 | · | · | 0.00x ✓ |
| FastRetransSegs, server | segments | 0 | 0 | · | · | n/a |
| EarlyRetransSegs, client | segments | 0 | 0 | · | · | n/a |
| EarlyRetransSegs, server | segments | 0 | 0 | · | · | n/a |
| LostSegs, client | segments | 8,385 | 0 | · | · | 0.00x ✓ |
| LostSegs, server | segments | 1 | 0 | · | · | n/a |
| RepeatSegs received by the client | segments | 1 | 0 | · | · | n/a |
| RepeatSegs received by the server | segments | 3,779 | 0 | · | · | 0.00x ✓ |

The spread behind those medians: every run of *goodput* (Mbit/s), in the order it ran:

| pair | runs | min | median | max | every run |
|---|---:|---:|---:|---:|---|
| GG | 5 | 289.7 | 316.5 | 332.6 | 332.6, 324.7, 316.5, 313.7, 289.7 |
| RR | 5 | 498.3 | 526.6 | 579.6 | 498.3, 554.7, 526.6, 522.9, 579.6 |
| GR | 5 | 328.1 | 362.7 | 399.2 | 362.7, 399.2, 328.1, 368.8, 330.7 |
| RG | 5 | 283.8 | 433.5 | 491.1 | 424.2, 283.8, 491.1, 433.5, 470.5 |

Produced by:

```sh
tools/lab/lab.py --host lab-x86-1 --runs-dir lab-runs/20260924T220812Z-bench-s1-sockbuf run lab-runs/20260924T220812Z-bench-s1-sockbuf/scenarios/s1-sockbuf-s1-bulk-up.json --no-report --wait-load 600
```

### `bulk-down`: one TCP stream through the tunnel, server to client (iperf3 -R)

| measurement | unit | GG | RR | GR | RG | RR/GG |
|---|---:|---:|---:|---:|---:|---:|
| goodput | Mbit/s | 325.8 | 496.5 | 426.7 | 373.2 | 1.52x ✓ |
| TCP retransmits | segments | 70 | 101 | 169 | 24 | 1.44x ✗ |
| CPU per GB, client | s/GB | 13.14 | 7.32 | · | · | 0.56x ✓ |
| CPU per GB, server | s/GB | 11.12 | 7.40 | · | · | 0.67x ✓ |
| CPU per GB, both ends | s/GB | 24.26 | 14.73 | · | · | 0.61x ✓ |
| RSS, client | kB | 47,000 | 7,556 | · | · | 0.16x ✓ |
| RSS, server | kB | 34,168 | 7,168 | · | · | 0.21x ✓ |
| peak VmHWM, client | kB | 51,896 | 8,596 | · | · | 0.17x ✓ |
| peak VmHWM, server | kB | 45,176 | 7,168 | · | · | 0.16x ✓ |
| OutSegs, client | segments | 21,399 | 20,971 | · | · | 0.98x |
| OutSegs, server | segments | 705,406 | 1,109,505 | · | · | 1.57x |
| retransmitted share, client | % of OutSegs | 0.0 | 0.0 | · | · | n/a |
| retransmitted share, server | % of OutSegs | 1.7 | 0.0 | · | · | 0.00x ✓ |
| RetransSegs, client | segments | 1 | 0 | · | · | n/a |
| RetransSegs, server | segments | 11,736 | 0 | · | · | 0.00x ✓ |
| FastRetransSegs, client | segments | 0 | 0 | · | · | n/a |
| FastRetransSegs, server | segments | 4,401 | 0 | · | · | 0.00x ✓ |
| EarlyRetransSegs, client | segments | 0 | 0 | · | · | n/a |
| EarlyRetransSegs, server | segments | 0 | 0 | · | · | n/a |
| LostSegs, client | segments | 1 | 0 | · | · | n/a |
| LostSegs, server | segments | 7,313 | 0 | · | · | 0.00x ✓ |
| RepeatSegs received by the client | segments | 2,495 | 0 | · | · | 0.00x ✓ |
| RepeatSegs received by the server | segments | 1 | 0 | · | · | n/a |

The spread behind those medians: every run of *goodput* (Mbit/s), in the order it ran:

| pair | runs | min | median | max | every run |
|---|---:|---:|---:|---:|---|
| GG | 5 | 214.2 | 325.8 | 348.7 | 348.7, 347.0, 325.8, 293.4, 214.2 |
| RR | 5 | 412.9 | 496.5 | 530.9 | 516.4, 484.7, 530.9, 496.5, 412.9 |
| GR | 5 | 392.8 | 426.7 | 475.8 | 426.7, 475.8, 417.9, 470.1, 392.8 |
| RG | 5 | 329.9 | 373.2 | 395.6 | 342.0, 373.2, 395.6, 329.9, 374.6 |

Produced by:

```sh
tools/lab/lab.py --host lab-x86-1 --runs-dir lab-runs/20260924T220812Z-bench-s1-sockbuf run lab-runs/20260924T220812Z-bench-s1-sockbuf/scenarios/s1-sockbuf-s1-bulk-down.json --no-report --wait-load 600
```

### `latency`: 64-byte ping/pong through an otherwise idle tunnel

| measurement | unit | GG | RR | RR/GG |
|---|---:|---:|---:|---:|
| latency p50 | ms | 0.43 | 0.24 | 0.55x ✓ |
| latency p90 | ms | 0.66 | 0.35 | 0.53x ✓ |
| latency p99 | ms | 1.55 | 0.75 | 0.48x ✓ |
| latency max | ms | 9.82 | 9.00 | 0.92x ✓ |
| latency errors | count | 0 | 0 | n/a |
| CPU over the run, client | s | 7.69 | 6.78 | 0.88x ✓ |
| CPU over the run, server | s | 7.50 | 6.77 | 0.90x ✓ |
| RSS, client | kB | 26,684 | 4,924 | 0.18x ✓ |
| RSS, server | kB | 25,124 | 4,428 | 0.18x ✓ |
| peak VmHWM, client | kB | 26,684 | 4,928 | 0.18x ✓ |
| peak VmHWM, server | kB | 25,124 | 4,592 | 0.18x ✓ |

The spread behind those medians: every run of *latency p50* (ms), in the order it ran:

| pair | runs | min | median | max | every run |
|---|---:|---:|---:|---:|---|
| GG | 5 | 0.41 | 0.43 | 0.44 | 0.44, 0.44, 0.43, 0.43, 0.41 |
| RR | 5 | 0.22 | 0.24 | 0.26 | 0.24, 0.24, 0.22, 0.26, 0.22 |

Produced by:

```sh
tools/lab/lab.py --host lab-x86-1 --runs-dir lab-runs/20260924T220812Z-bench-s1-sockbuf run lab-runs/20260924T220812Z-bench-s1-sockbuf/scenarios/s1-sockbuf-s1-latency.json --no-report --wait-load 600
```

### `latency-loaded`: the same ping/pong while a bulk flow saturates the same tunnel

| measurement | unit | GG | RR | RR/GG |
|---|---:|---:|---:|---:|
| latency p50 | ms | 0.52 | 15.04 | 29.20x ✗ |
| latency p90 | ms | 27.46 | 22.74 | 0.83x ✓ |
| latency p99 | ms | 60.95 | 36.31 | 0.60x ✓ |
| latency max | ms | 121.07 | 49.32 | 0.41x ✓ |
| latency errors | count | 0 | 0 | n/a |
| goodput | Mbit/s | 238.2 | 469.7 | 1.97x ✓ |
| CPU per GB, client | s/GB | 12.83 | 6.45 | 0.50x ✓ |
| CPU per GB, server | s/GB | 13.66 | 6.41 | 0.47x ✓ |
| CPU per GB, both ends | s/GB | 26.76 | 12.86 | 0.48x ✓ |
| RSS, client | kB | 50,136 | 8,028 | 0.16x ✓ |
| RSS, server | kB | 44,776 | 6,940 | 0.15x ✓ |
| peak VmHWM, client | kB | 50,136 | 8,032 | 0.16x ✓ |
| peak VmHWM, server | kB | 47,204 | 6,940 | 0.15x ✓ |
| OutSegs, client | segments | 603,024 | 1,013,128 | 1.68x |
| OutSegs, server | segments | 46,082 | 20,509 | 0.45x |
| retransmitted share, client | % of OutSegs | 9.0 | 0.0 | 0.00x ✓ |
| retransmitted share, server | % of OutSegs | 0.0 | 0.0 | n/a |
| RetransSegs, client | segments | 51,877 | 0 | 0.00x ✓ |
| RetransSegs, server | segments | 3 | 0 | n/a |
| FastRetransSegs, client | segments | 15,870 | 0 | 0.00x ✓ |
| FastRetransSegs, server | segments | 0 | 0 | n/a |
| EarlyRetransSegs, client | segments | 1,204 | 0 | 0.00x ✓ |
| EarlyRetransSegs, server | segments | 0 | 0 | n/a |
| LostSegs, client | segments | 34,539 | 0 | 0.00x ✓ |
| LostSegs, server | segments | 3 | 0 | n/a |
| RepeatSegs received by the client | segments | 3 | 0 | n/a |
| RepeatSegs received by the server | segments | 13,882 | 0 | 0.00x ✓ |

The spread behind those medians: every run of *latency p50* (ms), in the order it ran:

| pair | runs | min | median | max | every run |
|---|---:|---:|---:|---:|---|
| GG | 5 | 0.43 | 0.52 | 0.91 | 0.52, 0.50, 0.43, 0.91, 0.74 |
| RR | 5 | 13.01 | 15.04 | 15.96 | 15.96, 13.47, 15.04, 13.01, 15.43 |

Produced by:

```sh
tools/lab/lab.py --host lab-x86-1 --runs-dir lab-runs/20260924T220812Z-bench-s1-sockbuf run lab-runs/20260924T220812Z-bench-s1-sockbuf/scenarios/s1-sockbuf-s1-latency-loaded.json --no-report --wait-load 600
```

## Observations

**The ceiling was worth more than any optimisation in Step 12, and it was hiding the port, not flattering it.** Same host, same binaries, same campaign, thirteen hours apart; the only change is `net.core.rmem_max` 212,992 -> 8,388,608. `bulk-up` goodput goes 147.9 -> 316.5 Mbit/s for GG and 182.1 -> 526.6 for RR, so the **RR/GG ratio goes 1.23x -> 1.66x**; `bulk-down` 1.22x -> 1.52x. CPU per GB for both ends together goes 0.81x -> 0.56x up and 0.80x -> 0.61x down, client RSS 0.33x -> 0.20x. Both implementations roughly doubled in absolute throughput, and Rust gained more of the doubling than Go did - which is the direction D32 predicted from 11.2's `UdpRcvbufErrors` counts (Go lost 24.4% of arriving datagrams at the stock ceiling, Rust 48.3%) but is not something that could be assumed. The withdrawn page understated this port at its own production profile by about a third on goodput and by a quarter on CPU.

**12.1's biggest S1 finding was the host, and it has evaporated.** The withdrawn page reported that S1 retransmits enormously on this box - 36.5% of `OutSegs` for Go and 34.2% for Rust uploading, 33.7% and 29.3% downloading, 47.9% and 33.3% with a latency probe sharing the tunnel - and concluded that this is 'what a saturated receiver does' rather than anything about either implementation. Half of that reading survives and half does not. At a ceiling that can hold S1's window, **Rust's retransmitted share of `OutSegs` is 0.0% in every S1 cell on this page** (`RetransSegs` 0, `FastRetransSegs` 0, `LostSegs` 0, on 1.0-1.2 million segments sent), while Go's is 1.5% uploading, 1.7% downloading and 9.0% with a probe sharing the tunnel. So the saturated receiver was the *buffer*, the two implementations were not doing the same thing after all, and **the implementation that stops retransmitting when given a buffer is this one**. Nothing about the RTO or the fast-retransmit threshold should be tuned on either page's numbers; the correct conclusion from both is that a retransmission count taken against a clamped receive buffer measures the clamp.

**The `RepeatSegs` lead 12.1 left open for 12.2 is closed, and it was an artefact.** The withdrawn page called it 'the one real lead on this page': duplicates the peer received were 3.44x and 2.83x higher when the sender was Rust (17,314 against 5,039 uploading), consistent over five runs and both cross pairs, while the 2-vCPU aarch64 box gave the opposite sign. At a raised ceiling the sign here reverses too: **`RepeatSegs` is 0 for Rust and 3,779 for Go** on `bulk-up`, 0 against 2,495 on `bulk-down`, 0 against 13,882 under a competing flow. Both hosts now agree. 12.2 does not need the bounded-rate re-run that lead was going to require - it needs nothing, because there is no longer a difference to explain.

**One cell is genuinely worse than Go, it is new, and it is the most interesting thing on this page.** With a bulk flow saturating the same tunnel, the 64-byte probe's **p50 is 15.04 ms for Rust against 0.52 ms for Go - 29.2x, with no overlap between the two sets of five runs** (Rust 13.01-15.96, Go 0.43-0.91). Three things have to be read beside it and none of them makes it go away. First, the rest of that distribution goes the other way: p90 22.74 ms against 27.46, p99 **36.31 against 60.95**, max 49.32 against 121.07. Second, in the same runs Rust carried **469.7 Mbit/s of competing bulk against Go's 238.2**, so the probe is queueing behind twice the traffic. Third, the shapes differ, not just the levels: Go's probe is mostly fast with a long tail (p50 0.52, p90 27.5, p99 61.0) while Rust's is a narrow band an order of magnitude up (p50 15.0, p90 22.7, p99 36.3), which is the signature of a **standing queue**, not of occasional stalls. At 469.7 Mbit/s, 15 ms of queue is about 880 kB in flight - well inside S1's 8192-segment window, and inside the receive buffer this page exists to have raised. The honest reading is that the port drives the tunnel to a fuller steady state than Go does and every packet in it pays a constant delay for that, and it is exactly the trade `-sndwnd 8192` asks for. It is **not** a smux scheduling defect as far as this page can tell: the shaper is a verbatim port (`crates/smux/src/shaper.rs`, D15) and the idle-tunnel cell below shows no added delay at all. **This is a lead for 12.2 and it needs a bounded-rate run** - the same probe against a rate-limited bulk flow, where both implementations carry the same load - before anything is concluded, let alone tuned. Note also that the withdrawn page had this cell at p50 **0.54x** (0.46 -> 0.25 ms), i.e. Rust comfortably ahead: the clamp was holding the port's send rate down and hiding this. step 12's Definition of Done names p99, not p50, and p99 here is 0.60x - but 12.5's report claims no acceptance row anywhere in the grid is on the wrong side of Go, and for this box that claim is now false.

**The cell that should not have moved did not move, which is what makes the rest of the page believable.** Through an *idle* S1 tunnel the receive buffer is never under pressure, so raising the ceiling should change nothing. It changed nothing: p50 0.43 ms Go / 0.24 ms Rust here against 0.44 / 0.23 on the withdrawn page, p99 1.55 / 0.75 against 1.50 / 0.69, CPU over the run 7.69 / 6.78 s against 7.66 / 6.74. Every one of those is inside the other session's spread. A page that claims a 2x change in the loaded cells has to be able to show a cell where nothing changed, and this is it.

**12.1's 'single most useful lead in the grid for 12.2' was also the clamp, and it points the other way now.** The withdrawn page found that at S1 the fastest pair in *both* directions was the one with a **Go sender and a Rust receiver** (GR 204 Mbit/s uploading, RG 238 downloading, both ahead of RR), concluded that the Rust send path is the expensive one at S1, and noted that S2 reversed it exactly. At a raised ceiling S1 agrees with S2 instead: uploading, **RG (a Rust client sending) is 433.5 against GR's 362.7**; downloading, **GR (a Rust server sending) is 426.7 against RG's 373.2**. The Rust *sender* is the fast side in both directions, and RR is the fastest pair in both (526.6 and 496.5). There is no S1-specific send-path cost to profile. The cross-pair columns are throughput only, as step 12.1 requires, and this is still a lead rather than a finding - but it is now a lead that says the two configurations behave the same way, which is one fewer thing for 12.2 to explain.

**Two rows carry a cross besides the p50 above, and both are the same small artefact.** `TCP retransmits` - iperf3's own count on the proxied TCP connection, not KCP's - is 156 against 57 uploading (2.74x) and 101 against 70 downloading (1.44x). These are segments on a loopback TCP connection inside the namespace, over a run in which Rust moved 1.66x and 1.52x more data, and the absolute numbers are three orders of magnitude below the KCP counters printed beneath them. They are recorded because every cross on this page is, not because 156 loopback retransmissions mean anything.

**What this page is and is not.** It is the S1 half of the 12.1 baseline and nothing else: `s2` is still the superseded page's (checked separately by the S2 control), and `bulk-par-up`/`bulk-par-down`, `churn`, `s3`, `s4`, step 12's Idle-cost and Startup rows and S5 (QPP) were not run here either. It is also still a *baseline for 12.2f onwards* rather than a measurement of the unoptimised port: the binaries carry `[12.2a]`-`[12.2e]` and `[12.3a]`-`[12.3f]` already, exactly as the superseded page said of the same files. And the box still has one vCPU carrying both tunnel ends, the workload and the target, so absolute Mbit/s here is a property of that core.

## Raw data

Every number above is a median of the rows in [`2026-09-24-lab-x86-1-netns-clean-s1-sockbuf.csv`](2026-09-24-lab-x86-1-netns-clean-s1-sockbuf.csv): one row per configuration, metric, pair, repetition and measurement. The run directories the CSV names are under `lab-runs/` (gitignored) on the machine that ran the campaign, one `state.json`, `proc.csv`, `snmp-*.csv` and workload log per run.

The CSV is the **complete** record and is wider than the tables: it carries the cross pairs' CPU and memory rows, which the tables deliberately do not show (see the `·` note above). They are data, not a comparison (a GR row's CPU is a Go client's and a Rust server's added together) so anything read out of them is a lead to be confirmed, never a result.

Regenerate the page and the CSV from those directories without re-running anything:

```sh
tools/bench/bench.py report lab-runs/20260924T220812Z-bench-s1-sockbuf
```

