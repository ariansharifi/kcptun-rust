# Go vs Rust end to end: lab-arm64-netns-clean, 2026-09-24

The Step 12.1 baseline on the deployment architecture: Go versus Rust end to end on the lab's only aarch64 host (Neoverse-N1, 2 vCPU), both tunnel ends in the `kr-cli`/`kr-srv` namespaces of that host with no impairment. The same grid as the x86_64 baseline, so the two can be read side by side (within each page, never across them. It is the reference the optimisations from 12.2f onwards are measured against, **not** a measurement of the unoptimised port) see the note below on what the binaries already carry.

## Method

| | |
|---|---|
| campaign | `baseline-netns-arm64.json` |
| client host | `lab-arm64`: Linux 6.17.0-1020-oracle aarch64, 2 vCPU, ldd (Ubuntu GLIBC 2.39-0ubuntu8.9) 2.39, 11.6 GiB |
| arrangement | both tunnel ends in the `kr-cli`/`kr-srv` namespaces of one host, netem profile `clean` |
| configurations | `s1`, `s2` (s1 = the user's production profile, s2 = kcptun's own defaults) |
| metric families | `bulk-up`, `bulk-down`, `latency`, `latency-loaded` |
| repetitions | 5 per pair per cell, A/B interleaved (GG, RR, GR, RG, then again) |
| workload duration | 20 s |
| socket-buffer ceilings | `lab-arm64` `net.core.rmem_max` 8,388,608, `wmem_max` 67,108,864: `setsockopt(SO_RCVBUF)`/`SO_SNDBUF` is silently clamped to these (docs/DECISIONS.md D32). Requested `-sockbuf` → what the kernel grants: `s1` client 8,388,608 → honoured; `s1` server 67,108,868 → **8,388,608**; `s2` client and server 4,194,304* → honoured. An asterisk is kcptun's own default, which a configuration that passes no `-sockbuf` still asks for. **Added by hand in 12.1b, and an inference rather than a record:** this page predates `bench.py` printing the ceiling and the `lab-runs/` directory behind it is no longer on the machine that ran the campaign, so the value is taken from tools/lab/README.md, which records this host as tuned to exactly these limits, and is corroborated by the S1 retransmission rows below (13.2 % for Go, **0.0 % for Rust**), which a clamped receive buffer could not produce. |
| iperf3 | iperf 3.16 (cJSON 1.7.15) at `/usr/bin/iperf3`, sha256 `626565d9571f0ebb…`: the host's own package, which carries no build stamp of ours |
| started | 2026-09-24T10:22:36Z |
| finished | 2026-09-24T12:05:33Z |
| runs harvested | 120 |

Artefacts: go `75fd8d8d61c0` (none, linux/arm64) on `lab-arm64`; lab tools `75fd8d8d61c0` (glibc 2.17, aarch64-unknown-linux-gnu) on `lab-arm64`; rust `75fd8d8d61c0` (glibc 2.17, aarch64-unknown-linux-gnu) on `lab-arm64`.

**Built from a modified tree:** `75fd8d8-dirty` (go, lab, rust). The commit above names the base, not the tree the binary was built from; check what differed before treating these numbers as that commit's.

Read before quoting anything here:

* Every cell is a **median over the repetitions of one session**, and the pairs inside a session were interleaved, so the columns share whatever the box was doing. Medians from two different sessions are not comparable, on a shared box, and on a real path, absolutely not.
* `RR/GG` is annotated ✓ when Rust is on the better side of Go for **that** row's direction (high is better for goodput and stream counts, low for CPU, memory, latency and retransmissions).
* A `·` cell is one that is deliberately not measured: step 12.1 gives the cross pairs (GR, RG) throughput only, because a CPU or RSS row for a mixed pair describes two different implementations at once.
* A `-` cell is **not measured**, never measured-as-zero. An `n/a` ratio is one the two cells beside it cannot support: either Go's median is zero, so the ratio is undefined rather than infinite, or both medians are segment counts below 100 over the whole run, where a ratio would be a verdict on noise. A number in parentheses after a cell is the number of runs behind it when that is fewer than the 5 the plan requires.
* CPU per GB divides the process's own `utime + stime` by the bytes the *workload* moved, not by the bytes that went over the wire: charging an implementation only for the goodput it delivered is what makes FEC and retransmission show up as cost rather than as credit.
* `RetransSegs` **decomposes**: one `flush` adds `LostSegs + FastRetransSegs + EarlyRetransSegs` into it, so all three components are printed beneath it and a `RetransSegs` row with an unexplained remainder means a counter is missing from this page rather than that some retransmission is unattributable. The three are medians of their own five runs, so they sum to the `RetransSegs` median only to within the run-to-run spread, not exactly; the per-run rows in the CSV do sum exactly.
* **Socket-buffer ceiling (added in Sub-step 12.1b).** `lab-arm64` is recorded in tools/lab/README.md as tuned to `net.core.rmem_max=8388608` / `wmem_max=67108864`, which is the ceiling docs/DECISIONS.md D32 measured zero `UdpRcvbufErrors` at, so the S1 rows on this page are **not** withdrawn the way the x86_64 page's are. The limits were not printed by the harness when this page was generated (they are now) and the runs it was built from are no longer on disk, so the ceiling here is an inference from the host record and from this page's own S1 retransmission rows (13.2 % for Go, 0.0 % for Rust, which a receive buffer that was overflowing could not produce), not something these runs recorded. `s1`'s server asks for 67,108,868 B and is granted 8,388,608 even at this ceiling; that clamp is a stated condition of the numbers, not a defect.
* The host has **two** vCPUs and carries both tunnel ends, the workload and the echo target, plus the host's own live kcptun deployment (27 clients, 3 servers), which was left running throughout. They are idle in the sense that matters here (the load average was 0.05 before the campaign) but they are not absent, and every run shares the box with them. The namespace lab is loopback-bound inside `kr-cli`/`kr-srv`, so nothing here touches the host's NIC.
* iperf3 is the host's own distribution package and its version is recorded nowhere but this page (a step 12.0 note), so absolute iperf3 throughput is version-unattributed and is **not** comparable with the x86_64 page, which used a different iperf3. Both arms of a cell used the same one, so the ratios are safe.
* The build stamps read `75fd8d8-dirty`, and the page flags that above. What differed from `75fd8d8` was **only untracked files**: `tools/bench/bench.py`, its tests, its campaigns and `tools/pingpong/tests/bench_py.rs`, i.e. this harness itself, which the campaign was written with. No tracked file under `crates/` was modified, so the `kr-client`, `kr-server`, `kr-pingpong` and `kr-labsample` binaries are what `75fd8d8` builds. Stated here rather than left to the flag, because the flag cannot know that.
* **What these binaries already contain, and what this page is therefore a baseline *for*.** They are built from `75fd8d8`, which is not the naive port. It already carries `[12.2a]` (Deviation V18, tx-channel backpressure), `[12.2b]` (the AES-GCM backend comparison, no code change, RustCrypto stayed), `[12.2c]` (D29, `flush` skips the already-scanned part of `snd_buf`), `[12.2d]` (D31, ACK addressed by sequence number), `[12.2e]` (the aarch64 numbers for those two) and `[12.3a]`–`[12.3f]` (glibc as the Linux release default per D07, `crates/kcp/src/memory.rs` giving memory back after a burst, the contiguous receive batch). So this is the reference for **12.2f onwards** and for 12.5, and it is **not** a measurement of the unoptimised port. Differencing it against the naive-port figures in [`kcp.md`](kcp.md) § 03.6 would credit work already done here to work not yet done, which is the error `kcp.md` § 12.1 was written to stop.
* **What this grid does not cover.** `tools/bench/bench.py metrics` defines seven metric families and `lab.py` four configurations; this campaign runs four families (`bulk-up`, `bulk-down`, `latency`, `latency-loaded`) at two configurations (`s1`, `s2`). Not taken here: `bulk-par-up`/`bulk-par-down` (iperf3 `-P 8`, the second half of step 12's Goodput row), `churn` (its Scale row), and configurations `s3` and `s4`. step 12's Idle-cost and Startup rows and its S5 (QPP) have no harness family or `lab.py` configuration at all yet. The harness would run the first three unchanged (they are omitted for machine time, not because they do not work) so an absent family on this page means it was **not run**, and 12.5 must not present this page as the full grid.

## Configuration `s1`: the user's production profile

```
both   -mode normal -crypt xor -mtu 1390 -sndwnd 8192 -rcvwnd 8192 -smuxver 2 -smuxbuf 16777216 -streambuf 16777216 -datashard 0 -parityshard 0 -nocomp -quiet
client -conn 4 -sockbuf 8388608
server -sockbuf 67108868
```

### `bulk-up`: one TCP stream through the tunnel, client to server (iperf3, forward)

| measurement | unit | GG | RR | GR | RG | RR/GG |
|---|---:|---:|---:|---:|---:|---:|
| goodput | Mbit/s | 587.1 | 1,022.5 | 765.0 | 732.9 | 1.74x ✓ |
| TCP retransmits | segments | 84 | 52 | 97 | 79 | n/a |
| CPU per GB, client | s/GB | 15.32 | 8.40 | · | · | 0.55x ✓ |
| CPU per GB, server | s/GB | 8.40 | 4.50 | · | · | 0.54x ✓ |
| CPU per GB, both ends | s/GB | 23.72 | 12.90 | · | · | 0.54x ✓ |
| RSS, client | kB | 57,756 | 28,696 | · | · | 0.50x ✓ |
| RSS, server | kB | 57,840 | 16,652 | · | · | 0.29x ✓ |
| peak VmHWM, client | kB | 57,756 | 30,816 | · | · | 0.53x ✓ |
| peak VmHWM, server | kB | 60,384 | 16,652 | · | · | 0.28x ✓ |
| OutSegs, client | segments | 1,470,402 | 2,194,518 | · | · | 1.49x |
| OutSegs, server | segments | 226,095 | 36,024 | · | · | 0.16x |
| retransmitted share, client | % of OutSegs | 13.2 | 0.0 | · | · | 0.00x ✓ |
| retransmitted share, server | % of OutSegs | 0.0 | 0.0 | · | · | n/a |
| RetransSegs, client | segments | 177,803 | 0 | · | · | 0.00x ✓ |
| RetransSegs, server | segments | 1 | 0 | · | · | n/a |
| FastRetransSegs, client | segments | 126,838 | 0 | · | · | 0.00x ✓ |
| FastRetransSegs, server | segments | 0 | 0 | · | · | n/a |
| EarlyRetransSegs, client | segments | 4,345 | 0 | · | · | 0.00x ✓ |
| EarlyRetransSegs, server | segments | 0 | 0 | · | · | n/a |
| LostSegs, client | segments | 34,030 | 0 | · | · | 0.00x ✓ |
| LostSegs, server | segments | 1 | 0 | · | · | n/a |
| RepeatSegs received by the client | segments | 1 | 0 | · | · | n/a |
| RepeatSegs received by the server | segments | 12,640 | 0 | · | · | 0.00x ✓ |

The spread behind those medians: every run of *goodput* (Mbit/s), in the order it ran:

| pair | runs | min | median | max | every run |
|---|---:|---:|---:|---:|---|
| GG | 5 | 472.6 | 587.1 | 638.3 | 638.3, 603.2, 587.1, 542.2, 472.6 |
| RR | 5 | 999.0 | 1,022.5 | 1,060.3 | 1,048.0, 999.0, 1,060.3, 1,011.0, 1,022.5 |
| GR | 5 | 661.2 | 765.0 | 806.6 | 661.2, 767.4, 765.0, 744.2, 806.6 |
| RG | 5 | 718.2 | 732.9 | 754.5 | 731.7, 733.6, 754.5, 732.9, 718.2 |

Produced by:

```sh
tools/lab/lab.py --host lab-arm64 --runs-dir lab-runs/20260924T102236Z-bench-baseline-arm64 run lab-runs/20260924T102236Z-bench-baseline-arm64/scenarios/baseline-arm64-s1-bulk-up.json --no-report --wait-load 600
```

### `bulk-down`: one TCP stream through the tunnel, server to client (iperf3 -R)

| measurement | unit | GG | RR | GR | RG | RR/GG |
|---|---:|---:|---:|---:|---:|---:|
| goodput | Mbit/s | 569.3 | 1,019.4 | 731.9 | 762.4 | 1.79x ✓ |
| TCP retransmits | segments | 123 | 54 | 82 | 119 | 0.44x ✓ |
| CPU per GB, client | s/GB | 8.29 | 4.48 | · | · | 0.54x ✓ |
| CPU per GB, server | s/GB | 15.53 | 8.45 | · | · | 0.54x ✓ |
| CPU per GB, both ends | s/GB | 23.82 | 12.93 | · | · | 0.54x ✓ |
| RSS, client | kB | 58,036 | 11,700 | · | · | 0.20x ✓ |
| RSS, server | kB | 57,352 | 25,832 | · | · | 0.45x ✓ |
| peak VmHWM, client | kB | 60,972 | 12,444 | · | · | 0.20x ✓ |
| peak VmHWM, server | kB | 57,352 | 30,552 | · | · | 0.53x ✓ |
| OutSegs, client | segments | 260,492 | 38,987 | · | · | 0.15x |
| OutSegs, server | segments | 1,346,220 | 1,966,784 | · | · | 1.46x |
| retransmitted share, client | % of OutSegs | 0.0 | 0.0 | · | · | n/a |
| retransmitted share, server | % of OutSegs | 11.8 | 0.0 | · | · | 0.00x ✓ |
| RetransSegs, client | segments | 3 | 0 | · | · | n/a |
| RetransSegs, server | segments | 161,120 | 0 | · | · | 0.00x ✓ |
| FastRetransSegs, client | segments | 0 | 0 | · | · | n/a |
| FastRetransSegs, server | segments | 119,667 | 0 | · | · | 0.00x ✓ |
| EarlyRetransSegs, client | segments | 0 | 0 | · | · | n/a |
| EarlyRetransSegs, server | segments | 5,145 | 0 | · | · | 0.00x ✓ |
| LostSegs, client | segments | 3 | 0 | · | · | n/a |
| LostSegs, server | segments | 38,269 | 0 | · | · | 0.00x ✓ |
| RepeatSegs received by the client | segments | 14,936 | 0 | · | · | 0.00x ✓ |
| RepeatSegs received by the server | segments | 3 | 0 | · | · | n/a |

The spread behind those medians: every run of *goodput* (Mbit/s), in the order it ran:

| pair | runs | min | median | max | every run |
|---|---:|---:|---:|---:|---|
| GG | 5 | 527.6 | 569.3 | 625.8 | 625.8, 599.1, 543.9, 569.3, 527.6 |
| RR | 5 | 986.2 | 1,019.4 | 1,028.3 | 1,028.3, 986.2, 1,022.9, 1,019.4, 1,008.3 |
| GR | 5 | 711.9 | 731.9 | 759.0 | 727.6, 752.9, 731.9, 759.0, 711.9 |
| RG | 5 | 668.1 | 762.4 | 800.4 | 707.4, 789.7, 762.4, 668.1, 800.4 |

Produced by:

```sh
tools/lab/lab.py --host lab-arm64 --runs-dir lab-runs/20260924T102236Z-bench-baseline-arm64 run lab-runs/20260924T102236Z-bench-baseline-arm64/scenarios/baseline-arm64-s1-bulk-down.json --no-report --wait-load 600
```

### `latency`: 64-byte ping/pong through an otherwise idle tunnel

| measurement | unit | GG | RR | RR/GG |
|---|---:|---:|---:|---:|
| latency p50 | ms | 0.34 | 0.23 | 0.68x ✓ |
| latency p90 | ms | 0.47 | 0.31 | 0.67x ✓ |
| latency p99 | ms | 0.71 | 0.52 | 0.73x ✓ |
| latency max | ms | 7.50 | 3.91 | 0.52x ✓ |
| latency errors | count | 0 | 0 | n/a |
| CPU over the run, client | s | 10.46 | 9.73 | 0.93x ✓ |
| CPU over the run, server | s | 10.69 | 8.65 | 0.81x ✓ |
| RSS, client | kB | 27,104 | 4,664 | 0.17x ✓ |
| RSS, server | kB | 27,204 | 4,584 | 0.17x ✓ |
| peak VmHWM, client | kB | 27,104 | 4,664 | 0.17x ✓ |
| peak VmHWM, server | kB | 27,204 | 4,584 | 0.17x ✓ |

The spread behind those medians: every run of *latency p50* (ms), in the order it ran:

| pair | runs | min | median | max | every run |
|---|---:|---:|---:|---:|---|
| GG | 5 | 0.33 | 0.34 | 0.35 | 0.34, 0.34, 0.34, 0.35, 0.33 |
| RR | 5 | 0.23 | 0.23 | 0.23 | 0.23, 0.23, 0.23, 0.23, 0.23 |

Produced by:

```sh
tools/lab/lab.py --host lab-arm64 --runs-dir lab-runs/20260924T102236Z-bench-baseline-arm64 run lab-runs/20260924T102236Z-bench-baseline-arm64/scenarios/baseline-arm64-s1-latency.json --no-report --wait-load 600
```

### `latency-loaded`: the same ping/pong while a bulk flow saturates the same tunnel

| measurement | unit | GG | RR | RR/GG |
|---|---:|---:|---:|---:|
| latency p50 | ms | 0.54 | 0.63 | 1.17x ✗ |
| latency p90 | ms | 2.68 | 2.81 | 1.05x ✗ |
| latency p99 | ms | 14.84 | 7.45 | 0.50x ✓ |
| latency max | ms | 64.96 | 31.71 | 0.49x ✓ |
| latency errors | count | 0 | 0 | n/a |
| goodput | Mbit/s | 620.7 | 1,083.7 | 1.75x ✓ |
| CPU per GB, client | s/GB | 11.03 | 6.14 | 0.56x ✓ |
| CPU per GB, server | s/GB | 7.99 | 4.33 | 0.54x ✓ |
| CPU per GB, both ends | s/GB | 19.02 | 10.47 | 0.55x ✓ |
| RSS, client | kB | 53,408 | 23,364 | 0.44x ✓ |
| RSS, server | kB | 46,716 | 12,664 | 0.27x ✓ |
| peak VmHWM, client | kB | 53,716 | 25,816 | 0.48x ✓ |
| peak VmHWM, server | kB | 55,836 | 13,196 | 0.24x ✓ |
| OutSegs, client | segments | 1,427,031 | 2,350,968 | 1.65x |
| OutSegs, server | segments | 137,155 | 65,979 | 0.48x |
| retransmitted share, client | % of OutSegs | 4.8 | 0.0 | 0.00x ✓ |
| retransmitted share, server | % of OutSegs | 0.0 | 0.0 | n/a |
| RetransSegs, client | segments | 71,978 | 0 | 0.00x ✓ |
| RetransSegs, server | segments | 0 | 0 | n/a |
| FastRetransSegs, client | segments | 61,974 | 0 | 0.00x ✓ |
| FastRetransSegs, server | segments | 0 | 0 | n/a |
| EarlyRetransSegs, client | segments | 1,935 | 0 | 0.00x ✓ |
| EarlyRetransSegs, server | segments | 0 | 0 | n/a |
| LostSegs, client | segments | 12,769 | 0 | 0.00x ✓ |
| LostSegs, server | segments | 0 | 0 | n/a |
| RepeatSegs received by the client | segments | 0 | 0 | n/a |
| RepeatSegs received by the server | segments | 2,234 | 0 | 0.00x ✓ |

The spread behind those medians: every run of *latency p50* (ms), in the order it ran:

| pair | runs | min | median | max | every run |
|---|---:|---:|---:|---:|---|
| GG | 5 | 0.49 | 0.54 | 0.67 | 0.54, 0.53, 0.49, 0.67, 0.55 |
| RR | 5 | 0.56 | 0.63 | 0.65 | 0.63, 0.60, 0.65, 0.56, 0.64 |

Produced by:

```sh
tools/lab/lab.py --host lab-arm64 --runs-dir lab-runs/20260924T102236Z-bench-baseline-arm64 run lab-runs/20260924T102236Z-bench-baseline-arm64/scenarios/baseline-arm64-s1-latency-loaded.json --no-report --wait-load 600
```

## Configuration `s2`: kcptun's own defaults

```
both   -mode fast -crypt aes -mtu 1350 -sndwnd 128 -rcvwnd 512 -smuxver 2 -smuxbuf 4194304 -streambuf 2097152 -datashard 10 -parityshard 3
client -conn 1
```

### `bulk-up`: one TCP stream through the tunnel, client to server (iperf3, forward)

| measurement | unit | GG | RR | GR | RG | RR/GG |
|---|---:|---:|---:|---:|---:|---:|
| goodput | Mbit/s | 315.3 | 694.4 | 451.7 | 559.4 | 2.20x ✓ |
| TCP retransmits | segments | 76 | 4 | 8 | 31 | n/a |
| CPU per GB, client | s/GB | 18.80 | 10.42 | · | · | 0.55x ✓ |
| CPU per GB, server | s/GB | 19.52 | 7.23 | · | · | 0.37x ✓ |
| CPU per GB, both ends | s/GB | 38.31 | 17.68 | · | · | 0.46x ✓ |
| RSS, client | kB | 29,668 | 5,864 | · | · | 0.20x ✓ |
| RSS, server | kB | 30,392 | 6,708 | · | · | 0.22x ✓ |
| peak VmHWM, client | kB | 29,668 | 5,864 | · | · | 0.20x ✓ |
| peak VmHWM, server | kB | 30,836 | 6,708 | · | · | 0.22x ✓ |
| OutSegs, client | segments | 775,887 | 1,502,341 | · | · | 1.94x |
| OutSegs, server | segments | 15,500 | 28,220 | · | · | 1.82x |
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

The spread behind those medians: every run of *goodput* (Mbit/s), in the order it ran:

| pair | runs | min | median | max | every run |
|---|---:|---:|---:|---:|---|
| GG | 5 | 306.1 | 315.3 | 321.7 | 306.1, 315.3, 321.7, 308.8, 316.5 |
| RR | 5 | 656.6 | 694.4 | 706.2 | 656.6, 703.8, 694.4, 689.4, 706.2 |
| GR | 5 | 436.7 | 451.7 | 461.3 | 454.2, 445.6, 451.7, 461.3, 436.7 |
| RG | 5 | 544.9 | 559.4 | 562.4 | 552.1, 559.4, 561.3, 562.4, 544.9 |

Produced by:

```sh
tools/lab/lab.py --host lab-arm64 --runs-dir lab-runs/20260924T102236Z-bench-baseline-arm64 run lab-runs/20260924T102236Z-bench-baseline-arm64/scenarios/baseline-arm64-s2-bulk-up.json --no-report --wait-load 600
```

### `bulk-down`: one TCP stream through the tunnel, server to client (iperf3 -R)

| measurement | unit | GG | RR | GR | RG | RR/GG |
|---|---:|---:|---:|---:|---:|---:|
| goodput | Mbit/s | 300.1 | 701.5 | 565.6 | 448.8 | 2.34x ✓ |
| TCP retransmits | segments | 92 | 5 | 39 | 13 | n/a |
| CPU per GB, client | s/GB | 19.78 | 7.08 | · | · | 0.36x ✓ |
| CPU per GB, server | s/GB | 19.63 | 10.42 | · | · | 0.53x ✓ |
| CPU per GB, both ends | s/GB | 39.41 | 17.51 | · | · | 0.44x ✓ |
| RSS, client | kB | 30,116 | 6,512 | · | · | 0.22x ✓ |
| RSS, server | kB | 29,624 | 5,612 | · | · | 0.19x ✓ |
| peak VmHWM, client | kB | 30,800 | 6,568 | · | · | 0.21x ✓ |
| peak VmHWM, server | kB | 29,624 | 5,612 | · | · | 0.19x ✓ |
| OutSegs, client | segments | 16,360 | 31,056 | · | · | 1.90x |
| OutSegs, server | segments | 671,173 | 1,381,905 | · | · | 2.06x |
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

The spread behind those medians: every run of *goodput* (Mbit/s), in the order it ran:

| pair | runs | min | median | max | every run |
|---|---:|---:|---:|---:|---|
| GG | 5 | 295.2 | 300.1 | 302.0 | 300.1, 302.0, 295.2, 301.8, 296.1 |
| RR | 5 | 696.3 | 701.5 | 707.6 | 705.1, 696.3, 698.4, 707.6, 701.5 |
| GR | 5 | 550.0 | 565.6 | 569.9 | 550.0, 566.0, 569.9, 562.4, 565.6 |
| RG | 5 | 444.3 | 448.8 | 454.6 | 450.6, 444.3, 448.8, 454.6, 445.9 |

Produced by:

```sh
tools/lab/lab.py --host lab-arm64 --runs-dir lab-runs/20260924T102236Z-bench-baseline-arm64 run lab-runs/20260924T102236Z-bench-baseline-arm64/scenarios/baseline-arm64-s2-bulk-down.json --no-report --wait-load 600
```

### `latency`: 64-byte ping/pong through an otherwise idle tunnel

| measurement | unit | GG | RR | RR/GG |
|---|---:|---:|---:|---:|
| latency p50 | ms | 0.46 | 0.25 | 0.54x ✓ |
| latency p90 | ms | 0.67 | 0.34 | 0.51x ✓ |
| latency p99 | ms | 1.01 | 0.57 | 0.56x ✓ |
| latency max | ms | 7.46 | 4.87 | 0.65x ✓ |
| latency errors | count | 0 | 0 | n/a |
| CPU over the run, client | s | 11.19 | 9.70 | 0.87x ✓ |
| CPU over the run, server | s | 11.23 | 8.80 | 0.78x ✓ |
| RSS, client | kB | 28,476 | 5,000 | 0.18x ✓ |
| RSS, server | kB | 28,476 | 4,728 | 0.17x ✓ |
| peak VmHWM, client | kB | 28,476 | 5,000 | 0.18x ✓ |
| peak VmHWM, server | kB | 28,476 | 4,728 | 0.17x ✓ |

The spread behind those medians: every run of *latency p50* (ms), in the order it ran:

| pair | runs | min | median | max | every run |
|---|---:|---:|---:|---:|---|
| GG | 5 | 0.45 | 0.46 | 0.47 | 0.46, 0.47, 0.46, 0.45, 0.46 |
| RR | 5 | 0.25 | 0.25 | 0.25 | 0.25, 0.25, 0.25, 0.25, 0.25 |

Produced by:

```sh
tools/lab/lab.py --host lab-arm64 --runs-dir lab-runs/20260924T102236Z-bench-baseline-arm64 run lab-runs/20260924T102236Z-bench-baseline-arm64/scenarios/baseline-arm64-s2-latency.json --no-report --wait-load 600
```

### `latency-loaded`: the same ping/pong while a bulk flow saturates the same tunnel

| measurement | unit | GG | RR | RR/GG |
|---|---:|---:|---:|---:|
| latency p50 | ms | 3.33 | 2.11 | 0.63x ✓ |
| latency p90 | ms | 8.68 | 3.68 | 0.42x ✓ |
| latency p99 | ms | 13.53 | 6.96 | 0.51x ✓ |
| latency max | ms | 28.92 | 17.73 | 0.61x ✓ |
| latency errors | count | 0 | 0 | n/a |
| goodput | Mbit/s | 291.9 | 667.7 | 2.29x ✓ |
| CPU per GB, client | s/GB | 18.10 | 9.67 | 0.53x ✓ |
| CPU per GB, server | s/GB | 18.90 | 6.90 | 0.37x ✓ |
| CPU per GB, both ends | s/GB | 37.13 | 16.57 | 0.45x ✓ |
| RSS, client | kB | 29,756 | 5,908 | 0.20x ✓ |
| RSS, server | kB | 30,236 | 6,412 | 0.21x ✓ |
| peak VmHWM, client | kB | 29,756 | 5,908 | 0.20x ✓ |
| peak VmHWM, server | kB | 30,952 | 6,412 | 0.21x ✓ |
| OutSegs, client | segments | 738,875 | 1,443,779 | 1.95x |
| OutSegs, server | segments | 29,218 | 41,317 | 1.41x |
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

The spread behind those medians: every run of *latency p50* (ms), in the order it ran:

| pair | runs | min | median | max | every run |
|---|---:|---:|---:|---:|---|
| GG | 5 | 3.25 | 3.33 | 3.35 | 3.33, 3.25, 3.33, 3.35, 3.32 |
| RR | 5 | 2.04 | 2.11 | 2.12 | 2.11, 2.08, 2.11, 2.12, 2.04 |

Produced by:

```sh
tools/lab/lab.py --host lab-arm64 --runs-dir lab-runs/20260924T102236Z-bench-baseline-arm64 run lab-runs/20260924T102236Z-bench-baseline-arm64/scenarios/baseline-arm64-s2-latency-loaded.json --no-report --wait-load 600
```

## Observations

**This is the deployment architecture, and it is the port's best page so far.** Rust's goodput is 1.74-2.34x Go's, its CPU per GB for both ends together 0.44-0.55x (0.36-0.56x per end), its steady RSS 0.17-0.50x and its idle p50 latency 0.54-0.68x, in both profiles and both directions. step 12's Definition of Done asks for CPU/GB <= Go with a 25% target at S1, goodput >= 0.98x Go and p99 <= Go: S1 comes in at **0.54x CPU per GB** (a 46% reduction, not 25%), **1.74-1.79x goodput** and **0.50-0.73x p99**.

**Two vCPUs change the retransmission picture, but the 1-vCPU comparison this observation was written against has since been withdrawn.** Here the S1 retransmitted share of `OutSegs` is **13.2% for Go and 0.0% for Rust** uploading, **11.8% and 0.0%** downloading. The x86_64 figures originally quoted beside them (36.5% Go, 34.2% Rust) came from a campaign run at that host's *stock* `net.core.rmem_max`, which docs/DECISIONS.md D32 rules invalid; re-taken at a raised ceiling ([the current x86_64 S1 grid](2026-09-24-lab-x86-1-netns-clean-s1-sockbuf.md), 12.1b) the same cells read **1.5% for Go and 0.0% for Rust** uploading, 1.7% and 0.0% downloading. So the second core is not what stops the retransmission (a receive buffer that can hold the window is) and the part of this observation that survives is the part about which implementation stops first: **Rust retransmits nothing at S1 on either host**, while Go retransmits on both. It is what happens when the receiving end cannot drain its socket fast enough, and the cheaper implementation stops doing it first. The 11.4 soak's 28.4% (Rust, this host, but the `wan50` netem profile) should be re-read in that light, and **nothing about the RTO or the fast-retransmit threshold should be tuned on the strength of a retransmission count taken on a saturated box.**

**The cross pairs agree with that reading and are worth reading as a CPU budget.** At S1 both mixed pairs land between the two like-for-like ones (GR 765 and RG 733 Mbit/s against GG 587 and RR 1022) and their CPU per GB does too (16.8 and 17.7 against 23.7 and 12.9). On this box, unlike the 1-vCPU one, there is no pair that beats RR in either direction: replacing either end with the Go binary costs roughly half the improvement, which is what you would expect if the win is spread evenly across the send and receive paths rather than concentrated in one of them.

**The one row where Rust is behind, stated plainly.** At S1 under a competing bulk flow the port's p50 latency is 0.63 ms against Go's 0.54 (and p90 2.81 against 2.68): the only two cells in the whole grid with a cross against them. In the same runs Rust is moving **1,084 Mbit/s against Go's 621**, so the tunnel it is measuring the latency through is carrying 1.75x the traffic; a queue that is 75% busier is not the same queue. It is still a real row and it is still Rust's loss: p99 in the same cell is 7.45 ms against 14.84, so the tail is better while the median is worse, which is the signature of a fuller pipe rather than a slower one. Worth a bounded-rate re-run in 12.2 before anything is concluded from it.

**Memory: the same rout, with one caveat about what these numbers are.** Steady RSS under load is 5.6-28.7 MB for Rust against 29.6-58.0 MB for Go, and in the idle-ish `latency` cells 4.6-5.0 MB against 27.1-28.5. These are processes that have just moved gigabytes, not idle ones; `docs/benchmarks/memory.md` owns the idle floor and owns the one measurement the port loses, which is how much of a burst is given back afterwards. Nothing on this page measures release.

**What this page may not be compared with.** Its absolute Mbit/s are ~3-5x the x86_64 page's, and almost none of that is the architecture: this box has two cores to that one's one, a different iperf3 (3.16 against 3.9) and a different kernel. Only the Go-versus-Rust columns *inside* one cell of one page mean anything. What the two pages may legitimately be read together for is the *shape* of a difference, the retransmission observation above is exactly that, and it needed both.

## Raw data

Every number above is a median of the rows in [`2026-09-24-lab-arm64-netns-clean.csv`](2026-09-24-lab-arm64-netns-clean.csv): one row per configuration, metric, pair, repetition and measurement. The run directories the CSV names are under `lab-runs/` (gitignored) on the machine that ran the campaign, one `state.json`, `proc.csv`, `snmp-*.csv` and workload log per run.

The CSV is the **complete** record and is wider than the tables: it carries the cross pairs' CPU and memory rows, which the tables deliberately do not show (see the `·` note above). They are data, not a comparison (a GR row's CPU is a Go client's and a Rust server's added together) so anything read out of them is a lead to be confirmed, never a result.

Regenerate the page and the CSV from those directories without re-running anything:

```sh
tools/bench/bench.py report lab-runs/20260924T102236Z-bench-baseline-arm64
```

