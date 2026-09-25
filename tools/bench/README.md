# Benchmark harness (Step 12.1)

`bench.py` runs the **scenario × metric grid** of step 12 on a lab host and reduces
it to one page plus the raw CSV behind it. It runs on the laptop, drives everything through
[`tools/lab/lab.py`](../lab/lab.py), and uses only the Python standard library.

```sh
tools/bench/bench.py metrics                                     # what can be measured
tools/bench/bench.py scenarios campaigns/baseline-netns.json     # expand the grid, run nothing
tools/bench/bench.py --host lab-x86-1 run campaigns/baseline-netns.json
tools/bench/bench.py report lab-runs/20260924T095034Z-bench-baseline   # rebuild the page
```

Everything that touches a host goes through `lab.py`, which goes through the guarded server-side
helpers: only `kr-*`/`kg-*`/`iperf3` may be started, no port below 4000 is accepted, processes are
stopped only by PID file after `/proc/<pid>/exe` is verified, and netem only ever touches our own
veths (tools/lab/README.md). `bench.py` adds nothing that bypasses them, and it inherits `lab.py`'s
build-stamp provenance check (12.0): a cell whose binaries cannot be named refuses to start.

## What a campaign is

A campaign is a grid. One **cell** is one scenario configuration × one metric family, and one cell
is one `lab.py run` with every implementation pair in it — which is what gets the A/B interleaving
for free, because `lab.plan_runs` alternates the pairs inside each repetition.

```jsonc
{
  "name": "baseline",                 // [A-Za-z0-9._-]: becomes directories and PID file names
  "env": "lab-x86-1-netns-clean",     // names docs/benchmarks/<date>-<env>.md and .csv
  "description": "…",                 // the page's first paragraph
  "configs": ["s1", "s2"],            // lab.py's CONFIGS: s1 production, s2 defaults, s3, s4
  "metrics": ["bulk-up", "latency"],  // the families below
  "repetitions": 5,                   // per pair per cell; fewer than 5 is refused
  "duration": 20,                     // seconds of workload per run
  "mode": "netns",                    // netns (one host, netem) or wan (two hosts, real path)
  "netem": "clean",
  "server_host": "", "server_addr": "",   // wan only
  "sample_interval": 5, "snmp_period": 10, "settle": 5,
  "cooldown": 60,                     // quiet seconds between cells
  "client_flags": {}, "server_flags": {},
  "notes": ["a caveat that belongs on the page"],
  "observations": ["what the results mean, written after they exist"]
}
```

`observations` is written **after** the campaign has run and the page is then regenerated with
`report --campaign tools/bench/campaigns/<file>.json`. That keeps the reading of a result in the
committed campaign file beside the grid that produced it, and keeps the page itself regenerable
from the raw runs instead of hand-edited afterwards.

Every cell is validated by `lab.parse_scenario` at parse time, so the port rules, the netem rules
and the "an iperf3 workload cannot share a scenario with ping/bulk/churn" rule are checked once,
in one place, before anything runs.

## Metric families

`bench.py metrics` prints the live list. At the time of writing:

| family | workload | pairs | what comes out |
|---|---|---|---|
| `bulk-up` | iperf3, 1 stream, forward | GG RR GR RG | goodput, TCP retransmits, CPU/GB, RSS, VmHWM, KCP counters |
| `bulk-down` | iperf3 `-R` | GG RR GR RG | the same |
| `bulk-par-up` / `bulk-par-down` | iperf3 `-P 8`, both directions | GG RR GR RG | the same |
| `latency` | `kr-pingpong ping`, 64 B, idle tunnel | GG RR | p50/p90/p99/max, errors, **absolute** CPU seconds, RSS |
| `latency-loaded` | the same ping with a competing `bulk` flow | GG RR | the above plus the bulk flow's goodput |
| `churn` | `kr-pingpong churn` | GG RR | streams completed, errors, goodput, CPU/GB, RSS |

Two design decisions worth knowing:

* **CPU and memory are not separate cells.** They come out of `proc.csv` of the *same* runs that
  measure goodput, which is the only way the CPU figure describes the traffic the goodput figure
  describes.
* **The cross pairs (GR, RG) are throughput only**, as step 12.1 says. A CPU or RSS row for a
  mixed pair would put a Go client's number and a Rust server's number in one cell and invite
  exactly the comparison it cannot support. Those cells print `·`, not `—`.

CPU per GB divides the process's own `utime + stime` by the bytes the **workload** moved, never by
the bytes that went over the wire: charging an implementation only for the goodput it delivered is
what makes FEC and retransmission show up as a cost rather than as credit. A family that moves
almost no data (`latency`) reports absolute CPU seconds instead, because a per-GB figure computed
from 64-byte probes is a number in the thousands that means nothing.

## What it writes

| file | what |
|---|---|
| `docs/benchmarks/<date>-<env>.md` | one section per configuration, one table per metric family, medians across the repetitions, a column per pair, the `RR/GG` ratio, the spread behind the headline, and the **exact `lab.py` command** that produced each table |
| `docs/benchmarks/<date>-<env>.csv` | the raw long-format rows: one per configuration, metric, pair, repetition and measurement |
| `<runs-dir>/<stamp>-bench-<name>/scenarios/*.json` | the generated `lab.py` scenarios, kept as evidence |
| `<runs-dir>/<stamp>-bench-<name>/campaign.json` | the campaign, the host, the start and finish times, and any cell that failed |

`report` rebuilds both outputs from a finished campaign directory without re-running anything, so
the page can be regenerated after a change to its wording or its arithmetic.

## The rules it enforces in code

1. **Medians of ≥ 5 interleaved runs** (step 12 rule 1). `run` refuses a campaign with fewer
   repetitions; `--allow-few-repetitions` is for a shakedown, and the page it writes carries an
   **UNDER-REPLICATED** banner in its first paragraph.
2. **A `—` cell is not measured, never measured-as-zero**, and a cell with fewer than five runs
   behind it prints that count in parentheses.
3. **Each cell waits for the host to go quiet** (`lab.py --wait-load`), rather than `--force`ing
   past the preflight — on a 1-vCPU box, starting while the previous cell's load is still decaying
   measures the decay. A `cooldown` between cells does the same for the processes being reaped.
4. **Provenance is carried, not just checked.** A page built from runs whose binaries could not be
   named leads with `UNPROVENANCED`; one built from runs that could names the artefacts.
5. **`iperf3` is named and hashed** in the method table. It is the host's own distribution package
   and carries no build stamp of ours — a gap recorded against 12.0 — so a campaign at least says
   which file it was.
6. **The socket-buffer ceiling is on every page, and a stock one refuses to run** (12.1b,
   docs/DECISIONS.md D32). `setsockopt(SO_RCVBUF)`/`SO_SNDBUF` are silently clamped to
   `net.core.rmem_max`/`wmem_max`, so an S1 client asking for `-sockbuf 8388608` on a stock
   Ubuntu box gets 212,992 B and hears nothing about it; 11.2 measured 223,293 dropped datagrams
   in one 65 s run under that clamp and zero at a raised ceiling, with three cells inverting.
   The method table therefore always carries the ceilings and what each configuration's
   `-sockbuf` is actually granted — printing **not recorded** rather than nothing when no run
   says — the page leads with an `INVALID UNDER … D32` banner when the ceiling is the stock one,
   with a plain note when it is a raised ceiling that still clamps (which is what lab-arm64 runs
   under), and with a warning when one campaign's runs were not all taken under the same ceiling.
   `run` refuses to start on a stock ceiling at all; `--allow-clamped-sockbuf` measures the clamp
   on purpose and the page still says so. **A configuration that passes no `-sockbuf` is not
   exempt:** kcptun's flag defaults to 4,194,304 B and the binary always applies it, so `s2`,
   `s3` and `s4` are clamped 20× on a stock host as well.

## Tests

```sh
python3 tools/bench/bench_test.py
```

No lab host is needed: the planning half is pure and the reporting half reads run directories the
tests write by hand. They also run inside the cargo gate, through
[`tools/pingpong/tests/bench_py.rs`](../pingpong/tests/bench_py.rs), for the same reason
`lab_test.py` does — a python file that only a two-hour campaign exercises is not exercised.
