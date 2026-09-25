# Go vs Rust end to end: lab-x86-1-netns-clean, the S2 socket-buffer control, 2026-09-24

**Sub-step 12.1b's control for S2.** One cell (`s2` × `bulk-up`, five repetitions per pair, A/B interleaved) re-run on `lab-x86-1` after its `net.core.rmem_max` was raised from the stock 212,992 B to 8,388,608 B, with the same binaries as the 12.1 baseline. Its only job is to decide whether the S2 half of [2026-09-24-lab-x86-1-netns-clean.md](2026-09-24-lab-x86-1-netns-clean.md) survives the defect that withdrew its S1 half. It is a control, not a baseline: one metric family, and a comparison against a different session's medians, which the page's own rules say is weaker than a comparison inside one session.

## Method

| | |
|---|---|
| campaign | `baseline-netns-s2-control.json` |
| client host | `lab-x86-1`: Linux 5.15.0-177-generic x86_64, 1 vCPU, Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz, ldd (Ubuntu GLIBC 2.35-0ubuntu3.15) 2.35, 1.9 GiB |
| arrangement | both tunnel ends in the `kr-cli`/`kr-srv` namespaces of one host, netem profile `clean` |
| configurations | `s2` (s2 = kcptun's own defaults) |
| metric families | `bulk-up` |
| repetitions | 5 per pair per cell, A/B interleaved (GG, RR, GR, RG, then again) |
| workload duration | 20 s |
| socket-buffer ceilings | `lab-x86-1` `rmem_max` 8,388,608, `wmem_max` 67,108,864: `setsockopt(SO_RCVBUF)`/`SO_SNDBUF` is silently clamped to these (docs/DECISIONS.md D32). Requested `-sockbuf` → what the kernel grants: `s2` client 4,194,304* → honoured; `s2` server 4,194,304* → honoured. An asterisk is kcptun's own default of 4,194,304 B, which a configuration that passes no `-sockbuf` still asks for. |
| iperf3 | iperf 3.9 (cJSON 1.7.13) at `/usr/bin/iperf3`, sha256 `2c54c89b4d9016b9…`: the host's own package, which carries no build stamp of ours |
| started | 2026-09-24T22:49:38Z |
| finished | 2026-09-24T23:02:51Z |
| runs harvested | 20 |

Artefacts: go `75fd8d8d61c0` (none, linux/amd64) on `lab-x86-1`; lab tools `75fd8d8d61c0` (glibc 2.17, x86_64-unknown-linux-gnu) on `lab-x86-1`; rust `75fd8d8d61c0` (glibc 2.17, x86_64-unknown-linux-gnu) on `lab-x86-1`.

**Built from a modified tree:** `75fd8d8-dirty` (go, lab, rust). The commit above names the base, not the tree the binary was built from; check what differed before treating these numbers as that commit's.

Read before quoting anything here:

* Every cell is a **median over the repetitions of one session**, and the pairs inside a session were interleaved, so the columns share whatever the box was doing. Medians from two different sessions are not comparable, on a shared box, and on a real path, absolutely not.
* `RR/GG` is annotated ✓ when Rust is on the better side of Go for **that** row's direction (high is better for goodput and stream counts, low for CPU, memory, latency and retransmissions).
* A `·` cell is one that is deliberately not measured: step 12.1 gives the cross pairs (GR, RG) throughput only, because a CPU or RSS row for a mixed pair describes two different implementations at once.
* A `-` cell is **not measured**, never measured-as-zero. An `n/a` ratio is one the two cells beside it cannot support: either Go's median is zero, so the ratio is undefined rather than infinite, or both medians are segment counts below 100 over the whole run, where a ratio would be a verdict on noise. A number in parentheses after a cell is the number of runs behind it when that is fewer than the 5 the plan requires.
* CPU per GB divides the process's own `utime + stime` by the bytes the *workload* moved, not by the bytes that went over the wire: charging an implementation only for the goodput it delivered is what makes FEC and retransmission show up as cost rather than as credit.
* `RetransSegs` **decomposes**: one `flush` adds `LostSegs + FastRetransSegs + EarlyRetransSegs` into it, so all three components are printed beneath it and a `RetransSegs` row with an unexplained remainder means a counter is missing from this page rather than that some retransmission is unattributable. The three are medians of their own five runs, so they sum to the `RetransSegs` median only to within the run-to-run spread, not exactly; the per-run rows in the CSV do sum exactly.
* **Why this exists.** S2 was set aside as exempt from docs/DECISIONS.md D32 on the grounds that it passes no `-sockbuf` and therefore asks for little. That is false: kcptun's `-sockbuf` defaults to 4,194,304 B (`reference/kcptun/client/main.go:185-188`, `server/main.go:176-179`) and the binary always applies it, so S2 was clamped 20x on the stock host as well. The reason S2 is nevertheless expected to be unaffected is its window (`-sndwnd 128` at `-mtu 1350` is about 173 kB of data per flush, ~224 kB on the wire once FEC's 10/3 parity is counted, i.e. the same order as the 208 KiB ceiling rather than comfortably inside it) and the superseded page's own S2 rows show a retransmitted share of 0.0% for both implementations, which an overflowing buffer could not produce. An argument from the flags is what produced the defect this sub-step exists to repair, so the argument is checked with a measurement.
* **Cross-session comparison, stated as such.** Every other page in this directory compares columns *within* one session, because the pairs there were interleaved under the same conditions. This page compares its `RR/GG` ratio to the ratio on a page taken thirteen hours earlier on the same box. That is legitimate for the question asked (did raising the ceiling move S2?) and is not a basis for quoting either page's absolute Mbit/s against the other's.
* Same host, same deployment (`BUILD.txt`: `revision=75fd8d8-dirty`, `deployed=2026-09-24T09:44:50Z`), nothing rebuilt or redeployed. One vCPU carrying both tunnel ends, the workload and the target.

## Configuration `s2`: kcptun's own defaults

```
both   -mode fast -crypt aes -mtu 1350 -sndwnd 128 -rcvwnd 512 -smuxver 2 -smuxbuf 4194304 -streambuf 2097152 -datashard 10 -parityshard 3
client -conn 1
```

### `bulk-up`: one TCP stream through the tunnel, client to server (iperf3, forward)

| measurement | unit | GG | RR | GR | RG | RR/GG |
|---|---:|---:|---:|---:|---:|---:|
| goodput | Mbit/s | 143.5 | 238.4 | 166.7 | 229.4 | 1.66x ✓ |
| TCP retransmits | segments | 14 | 3 | 4 | 14 | n/a |
| CPU per GB, client | s/GB | 30.55 | 16.36 | · | · | 0.54x ✓ |
| CPU per GB, server | s/GB | 25.51 | 16.31 | · | · | 0.64x ✓ |
| CPU per GB, both ends | s/GB | 56.05 | 32.67 | · | · | 0.58x ✓ |
| RSS, client | kB | 28,836 | 5,684 | · | · | 0.20x ✓ |
| RSS, server | kB | 28,964 | 7,284 | · | · | 0.25x ✓ |
| peak VmHWM, client | kB | 28,836 | 5,692 | · | · | 0.20x ✓ |
| peak VmHWM, server | kB | 28,964 | 7,284 | · | · | 0.25x ✓ |
| OutSegs, client | segments | 372,451 | 550,780 | · | · | 1.48x |
| OutSegs, server | segments | 8,281 | 11,217 | · | · | 1.35x |
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
| GG | 5 | 133.3 | 143.5 | 164.0 | 143.5, 133.3, 164.0, 161.2, 134.7 |
| RR | 5 | 227.8 | 238.4 | 250.2 | 227.8, 250.2, 232.0, 238.4, 239.0 |
| GR | 5 | 160.1 | 166.7 | 172.2 | 171.6, 160.1, 166.7, 163.0, 172.2 |
| RG | 5 | 208.2 | 229.4 | 258.6 | 245.2, 258.6, 208.2, 221.8, 229.4 |

Produced by:

```sh
tools/lab/lab.py --host lab-x86-1 --runs-dir lab-runs/20260924T224938Z-bench-s2-control run lab-runs/20260924T224938Z-bench-s2-control/scenarios/s2-control-s2-bulk-up.json --no-report --wait-load 600
```

## Observations

**S2 did not move, and the `s2` half of the superseded page therefore stands.** Raising `net.core.rmem_max` from 212,992 B to 8,388,608 B changed the S1 cells of the same host beyond recognition - `bulk-up` goodput 147.9 -> 316.5 Mbit/s for GG and 182.1 -> 526.6 for RR, retransmitted share 36.5%/34.2% -> 1.5%/0.0%. Here, on the same day, the same host and the same binaries: GG **140.0 -> 143.5** Mbit/s, RR **250.6 -> 238.4**, CPU per GB for both ends together 0.54x -> 0.58x, client RSS 0.19x -> 0.20x, and **zero retransmitted segments in both sessions and in every pair**, before and after. Both goodput medians land inside the other session's own five-run spread (old GG 129.5-155.2 against new 133.3-164.0; old RR 229.7-256.0 against new 227.8-250.2), so the change is session noise on a 1-vCPU box, not an effect of the ceiling.

**The `RR/GG` ratio reads 1.79x on the old session and 1.66x on this one, and that difference is not a result.** It is two medians of five from two sessions thirteen hours apart, and the spreads behind them overlap almost completely - the ratio would move this far between two consecutive sessions with nothing changed at all. Anything quoting S2 `bulk-up` on this host should say **1.66-1.79x across two sessions** rather than pick one, which is what `docs/benchmarks/REPORT.md` now does. What the control establishes is the *absence* of an S1-sized effect, not a new S2 number.

**Why S2 was at risk at all, which is the part that was nearly got wrong.** S2 passes no `-sockbuf`, and it would be easy to record it as exempt on those grounds. It is not: kcptun's `-sockbuf` defaults to 4,194,304 B and both binaries always apply it to the UDP socket, so on the stock host S2's request was cut by a factor of twenty, exactly as S1's was by a factor of forty. What actually protects S2 is its **window**, and by less of a margin than a quick sum suggests: `-sndwnd 128` at `-mtu 1350` puts at most about 173 kB of data in flight per flush, ~224 kB on the wire once FEC's 10/3 parity is counted (the same order as the 208 KiB ceiling rather than comfortably inside it) where S1's `-sndwnd 8192` at `-mtu 1390` offers 11.4 MB into that same 208 KiB. Roughly one times the ceiling against fifty-five times it is a difference in kind, but at roughly one times it the arithmetic alone decides nothing, which is why this cell exists. The zero-retransmission rows on both sessions are that argument's confirmation, and this cell is the check that the argument is not merely plausible.

**One cell, one metric family, and a cross-session comparison.** This is a control and is labelled as one. It does not re-measure `bulk-down`, `latency` or `latency-loaded` at S2, and it compares its medians to a different session's, which every other page in this directory declines to do. If S2 ever becomes load-bearing for a claim the way S1 is, it should be re-taken as a full grid in one session rather than leaned on here.

## Raw data

Every number above is a median of the rows in [`2026-09-24-lab-x86-1-netns-clean-s2-control.csv`](2026-09-24-lab-x86-1-netns-clean-s2-control.csv): one row per configuration, metric, pair, repetition and measurement. The run directories the CSV names are under `lab-runs/` (gitignored) on the machine that ran the campaign, one `state.json`, `proc.csv`, `snmp-*.csv` and workload log per run.

The CSV is the **complete** record and is wider than the tables: it carries the cross pairs' CPU and memory rows, which the tables deliberately do not show (see the `·` note above). They are data, not a comparison (a GR row's CPU is a Go client's and a Rust server's added together) so anything read out of them is a lead to be confirmed, never a result.

Regenerate the page and the CSV from those directories without re-running anything:

```sh
tools/bench/bench.py report lab-runs/20260924T224938Z-bench-s2-control
```

