# Lab results

Reports written by `tools/lab/lab.py` from runs on a Linux lab host (tools/lab/README.md). Each file is
one session: a summary table, then a section per run with its command lines, workload results,
`/proc` metrics and SNMP counter totals. The host is part of the result: `--host` picks it, and
lab-arm64 (aarch64, production mesh) and lab-x86-1/lab-x86-2/lab-x86-3 (x86_64, expendable) are
different machines with different architectures, libc versions and neighbours.

| file | step | what it shows |
|---|---|---|
| [`11.2-netem-matrix.md`](11.2-netem-matrix.md) | 11.2 | the netem impairment matrix: what each cell showed, why two of them failed the acceptance criterion and what the host's socket-buffer ceiling had to do with it |
| [`11.2-netem-matrix-tables.md`](11.2-netem-matrix-tables.md) | 11.2 | the generated matrix: goodput, tunnel CPU per delivered bit, latency percentiles and the retransmission counters, per cell and per pair |
| [`11.2-netem-matrix-sockbuf.md`](11.2-netem-matrix-sockbuf.md) | 11.2 | the same S1 cells with `net.core.rmem_max` raised to lab-arm64's value: the controlled re-run |
| [`11.3b-wan-matrix.md`](11.3b-wan-matrix.md) | 11.3b | **the provenanced WAN session** (95.3 ms, lab-x86-2 → lab-arm64): the re-take of 11.3's headline, with every artefact on both ends stamped and hashed. Where the two WAN documents disagree, this one is authoritative |
| [`11.3-wan-matrix.md`](11.3-wan-matrix.md) | 11.3 | the earlier WAN matrix over the real RTT ladder (131.1 ms): what that rung showed, which rungs it could not measure, and why its `server_build` being empty in all 27 runs makes it a record rather than a measurement |
| `11.3-wan-<rung>-<scenario>.md` · `11.3b-wan-<rung>-<scenario>.md` | 11.3 / 11.3b | the generated detail behind one rung: every run's command lines (the tunnel's and the workload's), workload results, `/proc` metrics, SNMP totals and, from 12.0 onwards, the identity of every binary involved |
| [`11.4-soak.md`](11.4-soak.md) | 11.4 | the six-hour soak and the D07 allocator comparison: what passed, and which libc the Linux artifacts use |
| [`11.4-soak-rust-x86-2.md`](11.4-soak-rust-x86-2.md) · [`11.4-soak-go-x86-1.md`](11.4-soak-go-x86-1.md) | 11.4 | the generated detail behind the side-by-side six-hour pair |
| [`11.4-d07-musl-arm64.md`](11.4-d07-musl-arm64.md) · [`11.4-d07-glibc-arm64.md`](11.4-d07-glibc-arm64.md) | 11.4 | the two lab-arm64 runs that differ only in libc: D07's controlled measurement |
| [`11.5-failure-modes.md`](11.5-failure-modes.md) | 11.5 | the failure modes, Go beside Rust: restart, SIGKILL, a 45 s blackhole, `autoexpire` rotation, a port-range hop, a refused target and an unreachable one, what recovers, how long it takes, and by which mechanism |

11.1 built the runner; 11.2 onwards produce the results.

What these sessions add up to, together with `docs/benchmarks/`, is in
[`../benchmarks/REPORT.md`](../benchmarks/REPORT.md).

**A netns result depends on the host's `net.core.rmem_max`.** `setsockopt(SO_RCVBUF)` is clamped
to it silently, so a scenario asking for `-sockbuf 8388608` gets 208 KiB on a stock Ubuntu box and
8 MiB on lab-arm64. 11.2 found that this, and not either implementation, decided two of its cells.
Runs from 2026-09-24 onwards record both ceilings in `state.json` and the generated tables quote
them; anything older has to be read with tools/lab/README.md in hand.

**A WAN result is not a benchmark anyone can re-run.** The rungs of the ladder are real Internet
paths between the lab VPSs, and their capacity, their queueing and their cross traffic belong
to somebody else. Every `11.3-*` and `11.3b-*` file therefore compares Go and Rust *within one
session*, with the pairs interleaved, and says so at the top; a number in one of them must not be
compared with a number from another session, even between the same two hosts, including 11.3
against 11.3b, which are different rungs on different nights.

## Sessions on the record

**11.4 (2026-09-23/24).** Four runs of the soak scenario, summarised in
[`11.4-soak.md`](11.4-soak.md):

| run id | host | build | length | what it is for |
|---|---|---|---|---|
| `soak-rr-r1-20260923T202317Z` | lab-x86-2 | Rust, `x86_64-unknown-linux-gnu` (glibc 2.17) | 6 h | 11.4 acceptance, Rust arm |
| `soak-gg-r1-20260923T202339Z` | lab-x86-1 | Go, `reference/bin/*_linux_amd64` | 6 h | 11.4 acceptance, Go arm, same wall clock |
| `soak-rr-r1-20260923T162853Z` | lab-arm64 | Rust, `aarch64-unknown-linux-musl` | 6 h | D07, musl arm |
| `soak2h-rr-r1-20260924T020833Z` | lab-arm64 | Rust, `aarch64-unknown-linux-gnu` (glibc 2.17) | 2 h | D07, glibc arm: same box, same everything else |

All four are collected and all four hosts are back to their baselines. The first three started
before `deploy.sh` recorded `bin/BUILD.txt`, so their `state.json` has no `build` key and the
attribution above is written into each report by hand (11.1b).

Two 40-second `smoke` runs from 11.1b: `smoke-rr-r1-20260923T202009Z` (lab-x86-2) and
`smoke-gg-r1-20260923T202135Z` (lab-x86-1): were left with their data fetched but no report.
Both now have one, in `lab-runs/`, not here: a 40 s run is shorter than the ten-minute warm-up
window, so it carries no slope and proves only that the path works.

**11.3b (2026-09-24, 22:09–23:48Z).** Three sessions on the 95.3 ms rung, `lab-x86-2` (client) →
`lab-arm64` (server), summarised in [`11.3b-wan-matrix.md`](11.3b-wan-matrix.md):

| session | scenario | runs | artefacts |
|---|---|---:|---|
| `20260924T220941Z-wan-s1-bulk` | S1 bulk, 60 s each way | 12 | commit `2a966ab`, glibc 2.17 release on both ends, each hashed on its host |
| `20260924T224800Z-wan-s2-bulk` | S2 bulk, 60 s each way | 12 | as above |
| `20260924T232645Z-wan-s1-lat` | S1, 600 s ping under load | 2 | as above |

All 26 collected, no error markers, both hosts back to `host matches baseline`. This is the
session that re-took 11.3's unprovenanced headline; it is the one to quote for the real path.

## How to read one

- **Workload rows.** `ping` quotes p50/p90/p99/max of the request/response round trip through the
  tunnel; `churn` quotes completed/opened streams, throughput and errors; `bulk` and `iperf3`
  quote goodput. A `ping` percentile is accurate to about 0.8 % (a log-linear histogram, not a
  sample list, see `tools/pingpong/src/hist.rs`); `max` is exact.
- **Process metrics.** `RSS slope` and `fd slope` are what a soak lives or dies by: the
  least-squares gradient, per hour, over every sample **after warm-up** (the later of ten
  minutes and a tenth of the run). Flat means bounded; a positive gradient that holds for hours
  means a leak. They are there because `first→last` cannot tell a one-off step from a leak: a
  process that jumps 4 MB at minute three and is then flat for five hours has the same
  `first→last` as one that climbs all night. A run too short to leave warm-up prints `-`, not
  `0`. `VmHWM` never falls, so it shows the peak even when the sampling missed it. CPU seconds
  come from `utime + stime` between the first and last sample.
- **SNMP.** Deltas over the run, except `CurrEstab`, which is the live session count at the end
  (and `CurrEstabMax`, its high-water mark). `FECRecovered` and `FECErrs` are what tell you
  whether FEC did anything on a lossy profile.
- **Notes.** Lines from the collected logs that matched an error marker. "No error markers" is
  the expected outcome; an `invalid argument` from `SetReadBuffer` is filtered out because it is
  a faithful copy of Go's own message for a too-large `-sockbuf`.

Raw output (every CSV, every log, the `state.json` describing the run) stays in `lab-runs/`,
which is gitignored. Only the reports and any CSV a step explicitly commits belong here.
