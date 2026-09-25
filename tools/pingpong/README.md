# `tools/pingpong` — lab workload driver and `/proc` sampler

**Development only.** Nothing here is part of the kcptun port and nothing reaches a release: the
crate is `publish = false`, the Dockerfile and the release workflow build `-p kcptun-client -p
kcptun-server` by name, and no other crate depends on it. It is a workspace member so that
`cargo fmt`, `cargo clippy` and `cargo test` cover it — the 11.4 soak runs these binaries
unattended for six hours, which is not the moment to find out that a flag is ignored.

Two binaries:

| binary | deployed as | job |
|---|---|---|
| `pingpong` | `~/kcptun-lab/bin/lab/kr-pingpong` | drives traffic **through** the tunnel |
| `labsample` | `~/kcptun-lab/bin/lab/kr-labsample` | samples `/proc` of the processes under test |

The `kr-` prefix is required: `lab-start.sh` starts only `kr-*`/`kg-*`/`iperf3` binaries, and
`lab-stop.sh` stops a process only after `/proc/<pid>/exe` matches the path it recorded.

## `pingpong`

```
pingpong serve  --listen ADDR [--duration S] [--idle-timeout S] [--report-interval S]
pingpong ping   --connect ADDR [--size N] [--duration S] [--conns N] [--interval-ms N]
                [--warmup S] [--verify] [--out CSV] [--report-interval S] [--tag NAME]
pingpong bulk   --connect ADDR [--bytes N] [--streams N] [--direction up|down|both] …
pingpong churn  --connect ADDR [--rate R] [--min-bytes N] [--max-bytes N] [--size-dist log|uniform]
                [--max-inflight N] [--stream-timeout S] [--long-lived N] [--long-lived-bytes N]
                [--long-lived-interval S] [--burst-every S] [--burst-streams N] [--burst-bytes N] …
```

`serve` is the target the kcptun server's `-t` points at. The protocol is three framed verbs —
`ECHO n`, `UP n`, `DN n` — with the byte count always in the header and **no half-close
anywhere**: kcptun's half-close behaviour differs between the implementations (DECISIONS V04 and
V11, and Go's QPP port has no `CloseWrite`), so a workload that ended a transfer with
`shutdown(SHUT_WR)` would measure that difference instead of the tunnel.

Every mode is bounded by `--duration`, appends an interval CSV as it goes, and prints one
machine-readable line when it finishes:

```
RESULT {"kind":"churn","tag":"churn","opened":431982,"completed":431980,"errors":0,…}
```

`tools/lab/lab.py` picks that line out of the process log.

`ping --size` is capped at **1 MiB**. `ECHO` is a lock-step exchange — the client writes all N
bytes before reading any back, and the target echoes as it reads — so a request larger than the
socket buffers plus the tunnel's in-flight window (S2's `streambuf` is 2 MiB) deadlocks both
ends, and `ping` has no per-request timeout to break it. Large transfers are what `bulk` is for.

### `churn`, the soak's workload

Plan 11.4 asks for *"open/close 20 streams/s, each 10 KB–1 MB, plus 10 long-lived streams and
periodic bulk bursts"*, and this mode is exactly that: a paced generator of short streams, a set
of connections that stay open and exchange a little every few seconds, and a burst every
`--burst-every` seconds.

Sizes are drawn **log-uniformly** by default. Drawn uniformly, 10 kB–1 MB averages 505 kB and
the "churn" is really a bulk test; log-uniform averages about 215 kB and gives every decade of
size equal weight.

Two bounds keep the driver honest across six hours: `--max-inflight` caps concurrent streams (a
refusal is counted, never queued, so the harness cannot run out of file descriptors) and
`--stream-timeout` abandons a stream stuck on a blackholed path instead of holding it for ever.

## `labsample`

```
labsample --out proc.csv --pid LABEL=PID [--pid …] [--log LABEL=PATH …]
          [--interval S] [--duration S] [--log-cap-bytes N] [--clock-ticks N] [--tag NAME]
```

One CSV row per watched process per interval: `VmRSS`, `VmHWM`, `RssAnon`, `RssFile`, `VmSize`,
threads, the count of `/proc/<pid>/fd`, `utime`/`stime` and the CPU percentage derived from
them, page faults, context switches and the host's load average. It never signals or kills
anything; it only reads `/proc`.

The session count and the SNMP deltas 11.4 also asks for come from the tunnel binaries
themselves: `-snmplog` writes a CSV whose `CurrEstab` column is the live session count, and both
implementations write the same columns.

`--log-cap-bytes` truncates a watched log that grows past the cap and records that it happened,
which is what keeps a run whose tunnel logs three lines per stream from filling the host's disk.

Linux only at runtime (it reads `/proc`); every parser it uses is unit-tested on any platform.

## Tests

`cargo test -p kcptun-pingpong` — unit tests for the parsers, the histogram, the CSV writer and
the framing, plus `tests/cli.rs`, which runs the real binaries over loopback and checks the
`RESULT` lines and the CSVs they produce. Those are named `tool_*` (docs/porting-guide.md §8) and
are **not** `#[ignore]`d, unlike the `e2e_*` suites in `crates/interop-tests`: they need no
deployment and no `target/release` build (`CARGO_BIN_EXE_*` points at what Cargo has just built)
and the whole file takes about four seconds, so the gate covers them. The cost of
`CARGO_BIN_EXE_*` is that it bakes in laptop paths, so this file cannot be shipped to the lab
host with `tools/lab/remote-test.sh`.
