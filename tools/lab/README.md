# Network lab tooling

Everything here runs **from the laptop** and drives a Linux lab host over ssh: `lab-arm64` by
default, any of `lab-x86-1`, `lab-x86-2`, `lab-x86-3` with `--host` (or `$KCPTUN_LAB_HOST`).
The safety rules are in [Hosts and safety rules](#hosts-and-safety-rules) below and they are
**binding**. **`lab-arm64` carries an unrelated production workload** and every rule applies there
without exception; the other three are expendable, but they are still somebody's real machines, so
the lab still cleans up after itself and still kills only its own PIDs.

Hosts differ in **architecture** (lab-arm64 is aarch64, the other three are x86_64), in **libc
version** (Ubuntu 22.04 is glibc 2.35, 24.04 is 2.39) and in **NIC name** (`enp0s6` on lab-arm64,
`ens3` elsewhere). `deploy.sh` and the baseline handle all three; nothing here is pinned to
one machine.

| file | what it is |
|---|---|
| `lab.py` | **scenario runner** (Step 11.1): `deploy`, `netns-up`, `netns-down`, `run`, `status`, `collect`, `report`, `compare`, `matrix`, `baseline`, `cleanup` |
| `lab_test.py` | tests for `lab.py`, with ssh replaced by a fake — `python3 tools/lab/lab_test.py` |
| `failure.py` | **failure-mode driver** (Step 11.5): `cases`, `run`, `report`. Breaks a running tunnel on a schedule and measures what happens next — see [Failure modes](#failure-modes) |
| `failure_test.py` | tests for `failure.py`, against the same fake host — `python3 tools/lab/failure_test.py` |
| `scenarios/*.json` | scenario definitions (`smoke`, `soak-s1-wan50`, `bulk-iperf3` / `bulk-capped` / `latency` — 11.2's workloads — and the `wan-*` set 11.3 runs across the real RTT ladder) |
| `matrix.sh` | drives 11.2's campaign: one `lab.py run` session per (config, netem profile) cell, serial, `--no-report` |
| `deploy.sh` | cross-builds and copies the scripts, the Go reference, the Rust binaries and the lab tools, for **either architecture** — see [Which architecture, which libc](#which-architecture-which-libc). `lab.py deploy` passes `--host` on as `$KCPTUN_LAB_HOST`; run directly, it takes the host from that variable |
| `lab.sh` | one-shot access to a single server-side helper |
| `remote-test.sh` | cross-builds test executables and runs them on the host |
| `udp-probe.py` | reachability check from the laptop. Run it before a WAN campaign: only 29900, 4000 and 12948 have ever been verified open on lab-arm64, and the rest of the sanctioned block is somebody else's firewall's business |
| `server/lab-*.sh` | the guarded helpers, deployed to `~/kcptun-lab/scripts/` |

The workload driver and the `/proc` sampler are Rust binaries in
[`tools/pingpong`](../pingpong/README.md); `deploy.sh --tools` installs them as
`~/kcptun-lab/bin/lab/kr-pingpong` and `kr-labsample`.

## Hosts and safety rules

Four Linux hosts, named here by **role** rather than by their ssh aliases. Put your own aliases in
`~/.ssh/config` under these names (or pass `--host`); nothing in this directory hard-codes an
address.

| Role name | CPU / RAM | OS / libc | NIC | What it is for |
|---|---|---|---|---|
| `lab-arm64` | **aarch64 Neoverse-N1, 2 vCPU**, 11 GiB | Ubuntu 24.04, glibc 2.39, Linux 6.17 | `enp0s6` | the only aarch64 box and the most capable one: the deployment architecture, the memory work, anything needing headroom. **Carries an unrelated production workload**, so it is never a quiet box |
| `lab-x86-1` | x86_64, **1 vCPU**, 1963 MB | Ubuntu 22.04, **glibc 2.35**, Linux 5.15 | `ens3` | the x86 SIMD kernels (RS codec SSSE3/AVX2, AES-NI) and syscall paths on real hardware, and the client end of a WAN run. A `--gnu` build for it must target glibc 2.17, not 2.39 |
| `lab-x86-2` | x86_64, **1 vCPU**, 1967 MB | Ubuntu 24.04, glibc 2.39 | `ens3` | **the only idle host** — no tunnel process, no containers, sshd the only non-loopback listener — which makes it the best measurement endpoint in the lab |
| `lab-x86-3` | x86_64, **1 vCPU**, **961 MB** (~680 MB available) | Ubuntu 24.04, glibc 2.39 | `ens3` | the smallest box by a wide margin. **Memory, not CPU, is the binding constraint**: a 512 MB-each-way probe simply kills the run |

Every host is 1–2 vCPU, so all four are good WAN *endpoints* and poor throughput ceilings. None of
them has a C toolchain, so every Rust and Go binary — **including test executables** — is
cross-built on the laptop with `cargo-zigbuild` and copied over by `deploy.sh` / `remote-test.sh`.
`net.core.rmem_max` / `wmem_max` are 8388608 / 67108864 on all four: a host left at the stock
212,992 silently clamps `-sockbuf` and invalidates any S1 measurement taken on it
([D32](../../docs/DECISIONS.md)). Only UDP/TCP **29900**, **4000** and **12948** have ever been
verified open inbound on `lab-arm64`; the rest of the sanctioned block is somebody else's
firewall's business, so check with `udp-probe.py` before a WAN campaign.

### Real WAN paths between the hosts

Measured 2026-09-23, 0 % loss throughout — a real RTT ladder from 5 ms to 131 ms, a 26x spread, and
far better evidence than netem emulation:

| Path | RTT | mdev | Note |
|---|---:|---:|---|
| `lab-x86-2` ↔ `lab-x86-1` | **5.1 ms** | 0.89 | the low end of the ladder |
| `lab-x86-2` ↔ `lab-x86-3` | **46.3 ms** | 6.55 | the jitteriest path in the lab — useful *because* of that |
| `lab-x86-3` ↔ `lab-x86-1` | **56.7 ms** | 0.14 | both x86_64 |
| `lab-x86-1` ↔ `lab-arm64` | **81.9 ms** | 0.09 | **x86_64 ↔ aarch64** |
| `lab-x86-2` ↔ `lab-arm64` | **95.3 ms** | 0.10 | from the idle box |
| `lab-x86-3` ↔ `lab-arm64` | **131.1 ms** | 0.13 | the long path |

### The rules (binding)

These are not dedicated test rigs. `lab-arm64` carries an unrelated production workload, and all
four are somebody's real machines. The guarded helpers in `server/` enforce these in code.

1. **Never kill processes by name.** No `pkill`/`killall` of `client`, `server` or `kcptun`. The
   lab's own processes are uniquely named (`kr-client`/`kr-server` for Rust, `kg-client`/`kg-server`
   for the Go reference) and are stopped **only by PID file**, after `/proc/<pid>/exe` is verified.
2. **Never run `tc` on a host's primary NIC**, or on any pre-existing interface. Impairment (netem)
   goes only on the veths inside the lab's own network namespaces (`kr-*`).
3. **Never flush, replace or restore iptables/nft rulesets.** Only add rules that can be deleted
   exactly (tcpraw adds and removes its own). Diff `sudo iptables -S` and `sudo ip6tables -S`
   before and after every session.
4. **Never listen on a port below 4000** — the lab hosts reserve those for their own traffic. Use
   UDP/TCP **29900–29920** for tunnels, 127.0.0.1:**12948–12960** for client listeners and TCP
   **5201** for iperf3 (inside a netns, or bound to 127.0.0.1). Automated tests (testkit `ports`)
   additionally take short-lived **127.0.0.1-only** ports in **22000–28999**, bind-probed first.
   Check before starting:
   `sudo ss -tulpn | grep -E ':(299[0-2][0-9]|1294[89]|1295[0-9]|5201)\b'`.
5. **sysctl changes are temporary.** Record the old value in `~/kcptun-lab/baseline/`, restore it at
   the end of the session, and never persist anything to `/etc/sysctl.d`.
6. **Be gentle with shared resources.** Check `uptime` first, keep saturation runs short
   (≤ 60 s each), prefer the loopback-bound netns lab over saturating a NIC, and interleave the Go
   and Rust arms (A/B/A/B) so background noise cancels.
7. **Everything lives under `~/kcptun-lab/`.** `~/kcptun-lab/scripts/cleanup.sh` stops the lab's
   PIDs, deletes its netns and veths, removes only its own iptables rules and restores sysctls. Run
   it at the end of every session and after any aborted run.
8. **Install only user-local tooling** (rustup into `~/.cargo`). Ask before `apt install`.
9. **Never touch a live service.** Nothing here replaces, modifies or profiles a process it did not
   start; the lab only ever runs its own Go and Rust instances side by side.
10. **No secrets in the repository.** Production *flags* may be referenced; keys may not.


## Failure modes

`failure.py` is 11.5. Where `lab.py` measures a healthy tunnel, this one breaks it on purpose:

```sh
tools/lab/failure.py --host lab-x86-3 cases                       # what there is, and what it costs
tools/lab/failure.py --host lab-x86-3 run                         # every case, GG then RR
tools/lab/failure.py --host lab-x86-3 run --case blackhole --pairs rr
tools/lab/failure.py report 20260924T212244Z 20260924T220251Z \
    --out docs/lab-results/11.5-failure-modes-tables.md   # several sessions, one document
```

Every case is a fixed timeline. A `kr-pingpong ping` runs through the tunnel for the whole case
at a **one-second** reporting interval, and at known offsets the driver stops a process, starts
it again, or switches the netem profile to `blackhole` (100 % loss). The CSV the ping writes is
therefore a second-by-second record of when traffic stopped and when it came back, and each
event's wall-clock time is recorded in `state.json`, so "recovery" is an arithmetic answer rather
than a stopwatch: the first second after the repair that carried a completed request.

Each case runs against **both implementations** (`--pairs gg,rr`, mixed pairs available), because
the question 11.5 asks is not "does it recover" but "does it recover the way Go does". A mode
where the two agree is the result; one where they differ is a finding for docs/DECISIONS.md.

Two details that are easy to get wrong and are therefore fixed in code:

- **Restarting an end starts a new process name** (`…-srv2`), never the old one again.
  `lab-start.sh` truncates `logs/<name>.log`, so reusing the name would erase the log of
  everything before the fault — which is the half that says how the tunnel behaved while it was
  healthy. Each generation also writes its own `-snmplog`, and the counters are read from the
  newest one.
- **A refused target and an unreachable one are different cases.** A closed port answers with an
  RST in microseconds; a blackholed address has to wait out kcptun's 10 s `dialTimeout`
  (reference/kcptun/server/main.go:488). `lab-netns.sh sink up` provides the second one with a
  route inside the server namespace whose next hop does not forward, so the SYN is dropped rather
  than refused.

## Which architecture, which libc

```sh
tools/lab/deploy.sh                      # auto: ask the host `uname -m`, build static musl
tools/lab/deploy.sh --gnu                # glibc 2.17 — what the release artifacts are (D07)
tools/lab/deploy.sh --arch x86_64 --gnu  # override the detection (refused if the host differs)
tools/lab/deploy.sh --gnu --glibc 2.39   # only for a host that actually has 2.39
```

| flag | default | notes |
|---|---|---|
| `--arch auto\|aarch64\|x86_64` | `auto` | `auto` asks the host, in the same ssh round trip that creates `~/kcptun-lab`. `$KCPTUN_LAB_ARCH` sets the default; `--arch` overrides it. Selecting an architecture the host cannot execute is **refused**, because the symptom otherwise is `Exec format error` in a log file hours later |
| `--gnu` | off (static musl) | glibc instead of musl. **DECISIONS D07**: glibc is what the released Linux artifacts are, and it is the build that gives memory back after a burst (musl's mallocng has no `malloc_trim`), so anything measuring memory should use it |
| `--glibc VERSION` | `2.17` | the minimum glibc `cargo-zigbuild` targets, matching `tools/release.sh`. 2.17 runs on every host in the lab; **2.39 will not start on Ubuntu 22.04** (lab-x86-1). `$KCPTUN_LAB_GLIBC` sets the default; `--glibc` overrides it |

The Go reference binaries follow the same choice: `reference/bin/*_linux_arm64` for aarch64,
`*_linux_amd64` for x86_64, copied as `kg-<name>`. Both sets are already in the repository, so
`tools/fetch-reference.sh` is not needed to add a host of the other architecture.

## Build stamps, and why a run refuses to start without one

Every deployment that copies binaries writes a `BUILD.txt` **beside them** — one per family:
`bin/rust/BUILD.txt`, `bin/go/BUILD.txt`, `bin/lab/BUILD.txt`. Each is `key=value` lines: host
machine type, target triple, libc flavour, cargo profile, the full `commit` and the short
`revision` (with `-dirty` when the tree was not clean), the deployment time, and the **sha256 of
every file it copied**. The `go` stamp carries two fields more, `reference_version` and
`go_toolchain`, read from `reference/VERSIONS.txt`: `commit` cannot name a Go reference binary,
because `reference/` is a gitignored symlink to a checkout shared between worktrees and
`tools/fetch-reference.sh` can replace every binary in it without this tree changing at all.
`bin/BUILD.txt` still exists as a manifest of the last deployment (`kind=deployment`), but
nothing reads it as an artefact identity — `lab.py` reads it only to explain a refusal ("only
the pre-12.0 aggregate exists") — because it describes whatever was copied last, not the binary
a run executes.

Before it starts anything, `lab.py run` resolves the stamp for the artefact **each end will
actually execute** — `kr-client` on the client host, `kr-server` on the server host, plus the
instruments: `kr-labsample` on both hosts, and `kr-pingpong` on *both* the host that echoes and
the host that measures — checks that each stamp carries a commit, a libc, a target and a deploy
time, and hashes the binary on the host to confirm it is the file the stamp describes. Anything
missing or mismatched and the run is
**refused**, before the baseline, before the namespace and before a single process is started.
Every stamp it resolves is then **recorded**, not merely demanded: the commit, libc and sha256
of each artefact go into `state.json` — `client_build_detail`, `server_build_detail`,
`tools_build_detail`, `target_build_detail`, and `server_tools_build_detail` /
`server_target_build_detail` on a WAN run — and every one of them into the report, which names
the file each number came out of, `kr-pingpong` included. A `compare` table names them on an
`Artefacts:` line under its `Medians over …` heading, one entry per distinct build. Requiring a
stamp and recording it are deliberately one step: an artefact that is checked but not recorded
is one whose refusal can never reach a report, which is 11.3's failure shape (a loud check whose
result never reaches the page the number is quoted from) reproduced inside 11.3's own fix.

A refusal prints the deployment that would fix it, as `tools/lab/lab.py --host <h> deploy
--rust` (or `--go`, `--tools`), carrying back everything the host still says about itself:
`--gnu --glibc VERSION` when a glibc is named — by the stamp, or, when there is no stamp at all,
by the pre-12.0 aggregate line, which is evidence even though it is not provenance — and
`--profile profiling` when the stamp records that profile. When nothing anywhere names a libc
the gap is stated on its own line instead of guessed, because `deploy.sh` defaults to static
musl and following the refusal's own instruction would then silently change what is being
measured (D07). That caveat is never appended to the command: the command line is meant to be
pasted. `lab.py` is named rather than `deploy.sh` deliberately — the script has no `--host`, and
dropping the flag to make it run would deploy to `$KCPTUN_LAB_HOST`, whose default is
`lab-arm64`. A host that is simply unreachable is told so plainly instead — "cannot read … over
ssh" — since a redeploy would fail the same way.

This exists because of 11.3: the stamp used to live one directory above the binaries, lab-arm64's
`kr-server` had none beside it, and all 27 runs of a WAN campaign recorded `server_build: ""`.
Nothing failed, nobody noticed until review, and that campaign's headline number is not provably
a measurement of any particular tree. `--allow-unprovenanced` runs anyway — it warns per end and
stamps every report of that session **UNPROVENANCED** in its first paragraph. So does every
`lab.py compare` table generated from such a session, or from a pre-12.0 state directory: the
comparison is what a rung is quoted from, so it is not allowed to look clean either.

Attribution matters beyond the revision: a flat (or climbing) RSS plateau cannot be attributed to
the shipping glibc build rather than a static musl one, and D07 measured those two returning
95.6% and 4.9% of the same burst.

## The server-side helpers

`lab.py` never manipulates the host directly. Everything that changes state goes through one of
these, which enforce the rules in code; the only direct ssh use is read-only (`cat /proc/...`,
`tar`).

| helper | purpose | added |
|---|---|---|
| `lab-baseline.sh` | snapshot iptables, sysctls, the primary NIC's qdiscs and the lab ports | 00.5 |
| `lab-netns.sh` | create/remove the `kr-cli` ↔ `kr-srv` namespaces, apply a netem profile; `sink up\|down` adds 11.5's dropped-SYN route inside `kr-srv` | 00.5, 11.5 |
| `lab-start.sh` | start one process with a PID file (only `kr-*`, `kg-*`, `iperf3`, `python3`; no port < 4000) | 00.5 |
| `lab-stop.sh` | stop by PID file, after verifying `/proc/<pid>/exe` | 00.5 |
| `lab-cleanup.sh` | stop everything, remove the namespaces, verify against the baseline — **`lab-stop.sh --all` plus `lab-netns.sh down`, so it destroys any detached or uncollected run on that host, including another session's.** `lab.py --host <h> status` first | 00.5 |
| `lab-signal.sh` | send `USR1`/`USR2`/`HUP` **without** stopping (kcptun's SNMP dump) | 11.1 |
| `lab-wait.sh` | block on the host until named processes exit (one ssh connection, not 21 600) | 11.1 |
| `lab-status.sh` | one machine-readable line per PID file | 11.1 |
| `lab-collect.sh` | gather a run's artefacts into `logs/<runid>/`, clipping oversized logs (byte-wise) and CSVs (record-wise); JSON is left whole | 11.1 |

`lab-stop.sh` refuses to kill a PID whose `/proc/<pid>/exe` differs from the one recorded when
it was started. **Do not weaken that check.** It is why nothing here can ever touch a production
process, and it is why the sampler is a compiled binary rather than a python script: an
interpreter records as `/usr/bin/python3` and runs as `/usr/bin/python3.12`, and the check —
correctly — then refuses to stop it (found the hard way in 12.3a).

## A session

```sh
tools/lab/lab.py --host lab-x86-2 deploy --gnu             # scripts + kg-* + kr-* + lab tools
tools/lab/lab.py --host lab-x86-2 baseline                 # snapshot (once per session per host)
tools/lab/lab.py --host lab-x86-2 run tools/lab/scenarios/smoke.json   # ~1 min, proves the path
tools/lab/lab.py --host lab-x86-2 status                   # what is still running there
tools/lab/lab.py --host lab-x86-2 cleanup                  # must end every session
```

`--host` is a per-invocation choice, and the baseline, the namespaces, the PID files and the
logs all live on the host, so two hosts can run different scenarios at the same time without
knowing about each other. That is how 11.1b soaks Go and Rust side by side: the same scenario,
`--pair go:go` on one box and `--pair rust:rust` on the other, started within a minute of each
other on near-identical hardware.

A long run is detached, so a laptop that sleeps cannot spoil it:

```sh
tools/lab/lab.py --host <h> run tools/lab/scenarios/soak-s1-wan50.json --detach
tools/lab/lab.py --host <h> status soak             # any time
tools/lab/lab.py --host <h> collect soak            # after ~6 h: SIGUSR1, stop, download, report
tools/lab/lab.py --host <h> cleanup                 # only once nothing is left uncollected
```

**`status` and `collect` need the same `--host` the run was started with.** `--host` defaults to
`lab-arm64`, and only the *server* host of a WAN run is recovered from `state.json` — the client
host comes from `--host`. A detached run started elsewhere and collected without it used to
address the default host instead: nothing to stop, a missing log directory, and the real
`<runid>-cli` left running for ever on the host that actually has it. Both commands now compare
`--host` against the `host` recorded in `state.json` and refuse, naming the right one;
`run --detach` prints the whole `collect` line, `--host` included.

**`cleanup` is not per run.** It runs `lab-stop.sh --all` and `lab-netns.sh down`, so it stops
every lab process on the host and removes the namespace lab. Run `status` first and collect
first: on a host that is also carrying somebody else's detached run — a six-hour soak, the
other end of a WAN rung — `cleanup` destroys that run's data.

Raw output lands in `lab-runs/<stamp>-<scenario>/<runid>/` (gitignored); the Markdown report is
also written to `docs/lab-results/`. `collect` needs the `state.json` that `run --detach` wrote
on the laptop, so collect a detached run from the same checkout that started it.

## Two hosts and a real path (`mode: "wan"`, Step 11.3)

A `netns` scenario puts both tunnel ends in the namespaces of one host and shapes the veths
between them. A **`wan`** scenario puts the client on `--host` and the server on
`--server-host`, two real machines, and measures the Internet path that is actually between
them:

```sh
tools/lab/lab.py --host lab-x86-3 run tools/lab/scenarios/wan-s1-bulk.json \
    --server-host lab-arm64 --server-addr <lab-arm64-ip>
```

| | netns | wan |
|---|---|---|
| tunnel ends | `kr-cli` / `kr-srv` on one host | the two hosts themselves, no namespace |
| impairment | a netem profile on our veths | whatever the path does; netem is **refused** |
| `/proc` sampling | one sampler | one per machine (`-smp` and `-smps`) — `/proc` is per machine |
| SNMP | both CSVs on one host | `snmp-cli.csv` on the client host, `snmp-srv.csv` on the server's |
| artefacts | `<run>/` | `<run>/` plus the server host's half in `<run>/server/` |
| `uptime` | preflight load check | recorded on **both** ends before and after every run |
| reproducible | yes | **no** — see below |

`--server-host`/`--server-addr` override the scenario, so one file serves every rung of the RTT
ladder [below](#real-wan-paths-between-the-hosts) (5.1 ms to 131.1 ms). Both hosts are preflighted, each for the ports it
will actually bind, and each host stops and collects only its own processes. `cleanup` is still
per host, so a WAN session ends with one `status` and one `cleanup` per end — and never on
a host whose other run has not been collected yet.

**`--bitrate` belongs to the rung, for the same reason.** `iperf3 -b` is a guard rail against
saturating a host's NIC (safety rule 6), never part of the measurement — and **a cap that
binds makes every implementation report the cap**, which is how 11.3's first attempt produced four
pairs all reporting exactly 60.0 Mbit/s. The committed `wan-*` scenarios carry `400M`, which never
binds at 131 ms and binds hard at 95 ms, where a Go client alone drives 631 Mbit/s. So the cap is
given on the command line like the path is, it applies to every iperf3 workload of the session
(every pair, both directions, so it can never favour one arm), and it is **not** added to the
scenario's name — it is a guard rail, not an axis like `--config`/`--netem`. Probe the rung first
with one short Go↔Go run, then set the cap above what it reached:

```sh
tools/lab/lab.py --host lab-x86-2 run tools/lab/scenarios/wan-s1-bulk.json \
    --server-host lab-arm64 --server-addr <lab-arm64-ip> --bitrate 900M
```

Every workload's full command line is printed in the generated report, next to its result, so a
cap that has quietly become the measurement is visible on the page the number is quoted from
rather than only inside `state.json`.

**A real path is not reproducible between sessions.** Its capacity, its queueing and its cross
traffic belong to somebody else, so a number from one evening cannot be compared with a number
from another. Only the Go-versus-Rust comparison *inside* one session means anything, which is
why the pairs are interleaved (GG, RR, GR, RG) and why the generated report says so at the top.

`lab.py compare <session>` turns a whole session into the table a path is actually read from —
one row per workload metric, one column per pair, medians across the repetitions, and the
`RR/GG` ratio that 11.2's acceptance criterion is written in terms of. The SNMP counters that
explain a goodput difference (`RetransSegs`, `FastRetransSegs`, `LostSegs`, `FECRecovered`,
`FECErrs`) are in the same table, per side:

```sh
tools/lab/lab.py compare 20260923T223000Z-wan-s1-bulk --report /tmp/rung.md
```

A pair that did not run is `—`, never `0`: on a rung where one implementation's binary could not
be deployed, the difference matters.

## The impairment matrix (`mode: "netns"`, Step 11.2)

11.2 is the same two workloads run over **28 cells**: seven netem profiles (`lab.py`'s `NETEM_PROFILES`)
crossed with four flag configurations (S1 the user's production profile, S2 kcptun's defaults,
S3 fast3 + AEAD + FEC, S4 salsa20 without FEC). Both axes are `run` overrides rather than 28
scenario files, because 28 near-identical files is how one of them ends up differing in
something nobody meant to vary:

```sh
tools/lab/lab.py --host lab-x86-2 run tools/lab/scenarios/bulk-iperf3.json \
    --config s1 --netem lossy10 --no-report
tools/lab/matrix.sh --host lab-x86-2 --configs "s1 s2" --profiles "clean wan50 lossy10"
```

Both overrides go into the scenario's name, and therefore into the session directory, the run
ids and the pid files: `bulk-s1-lossy10-gg-r1-<stamp>`. `--netem` is refused on a `wan`
scenario for the same reason the field is (a real path cannot be shaped).

The two workload files are `bulk-iperf3.json` (30 s of iperf3 each way) and `latency.json`
(30 s of 64-byte pingpong idle, then 30 s of it against a competing `pingpong bulk` flow — iperf3
cannot be the competitor, because a kcptun server forwards to exactly one target).
`bulk-capped.json` is the **control** for the unimpaired cells: identical to `bulk-iperf3` except
that it offers 250 Mbit/s instead of as much as iperf3 can push. On a one-vCPU lab host `clean`
and `lan` otherwise measure the core — both tunnel ends and both ends of iperf3 compete for it —
so the goodput column reads as a protocol result when it is an efficiency result. With every pair
delivering the same bits, the informative column becomes CPU per delivered bit.

`matrix.sh` is the campaign driver: one `lab.py run` per cell, **serial** (both tunnel ends, the
workload and the target share one host — two cells at once would measure each other), continuing
past a cell that fails, and with `--no-report`, because 28 per-session reports would bury the one
table the step is read from. `--host` is **mandatory** — lab.py's own default is lab-arm64, which
carries an unrelated production workload, and a two-hour saturating campaign must not be
what you get by typing nothing. `--max-load` above lab.py's 1.0 is accepted **only on an
expendable host**, because a saturating cell leaves the one-minute load average above 1.0 for
minutes after it ends and the *next* cell would otherwise stall on the previous one's exhaust;
every run still records `uptime` before and after.

`lab.py matrix <session prefix…>` builds that table across the sessions — unlike `compare`, an
ambiguous prefix is the normal case here, since every cell is its own session:

```sh
tools/lab/lab.py matrix 20260924T075157Z 20260924T080815Z \
    --report docs/lab-results/11.2-netem-matrix-tables.md
```

Name the sessions, not just the day: a date prefix cannot separate a campaign from a same-day
controlled re-run of three of its cells, and those are two experiments. (It would no longer
*merge* them — the kernel socket-buffer ceiling is part of a cell's key, so runs taken under
different ceilings land in different rows and every table grows a `ceiling` column saying which
is which — but a report of two campaigns is still not a report of one.)

It prints four tables and an error scan: goodput per cell with the `RR/GG` ratio and 11.2's
`≥ 0.95×` verdict; **tunnel CPU per delivered bit** (`cli` + `srv` only — `iperf3 -s` is the
workload, not the implementation), which is how D29's flush-scan cost is read on a host whose
throughput is itself CPU-bound; **request/response latency** through the tunnel, idle and against
a competing bulk flow, where a ratio below 1 is Rust ahead; and **retransmission attribution** per
side, where `Repeat/Lost` — duplicates *received* by the peer against segments the sender believed
lost — says whether a retransmission storm was spurious, and having Go in the next column says
whether it is KCP's or ours. The error scan is where 11.2's "the mixed pairs complete without
errors" is read, since `--no-report` leaves no per-session report to find it in.

Nothing here is deployed without provenance: `run` now **refuses** to start on a host whose
`bin/BUILD.txt` cannot be read. 11.3's 131 ms rung was measured with `server_build` empty in all
27 runs, which left a committed result that cannot be attributed to this tree's binary at all.

Before the first WAN campaign against a host, check the ports really are open from outside:
`tools/lab/udp-probe.py --ssh <host> --host <ip> --ports 29910,29911`. **Pass both.** `--ssh` is
where the echo listener runs and `--host` is the address the probes are sent to, so they have to
name the same machine; put the rungs' addresses in your `~/.ssh/config`. A port-range scenario
(`wan-s1-portrange`, `tunnel_port_count` 4) needs `--ports 29910,29911,29912,29913` — 29912 and
29913 are verified on lab-arm64 only. The `wan-*` scenarios deliberately use 29910+ and 22700
rather than the 29900/22600 defaults, so that a WAN run cannot collide with a netns lab (a
detached soak owns the defaults inside `kr-srv`, and the port check sees into the namespaces).

## What a scenario says

```jsonc
{
  "name": "soak",              // [A-Za-z0-9._-]: it becomes a directory and PID file names
  "config": "s1",              // s1 production, s2 defaults, s3 fast3+GCM+FEC, s4 salsa20
  "mode": "netns",             // netns (one host, netem) or wan (two hosts, the real path)
  "netem": "wan50",            // clean lan wan50 lossy2 lossy10 burst ratelimited
  "server_host": "",           // wan only: the ssh host the server runs on (or --server-host)
  "server_addr": "",           // wan only: the address the client dials (or --server-addr)
  "pairs": [["rust", "rust"]], // client impl x server impl; interleaved across repetitions
  "repetitions": 1,
  "tunnel_port": 29900,        // UDP 29900-29920
  "tunnel_port_count": 1,      // >1 spreads the tunnel over a kcptun multiport range
  "client_flags": {"conn": 4}, // overrides on top of the config, rendered Go style
  "server_flags": {},
  "sample_interval": 60,       // /proc sampling and workload CSV interval
  "snmp_period": 60,           // -snmplog period on both tunnel ends
  "workloads": [               // run concurrently; `start_after` staggers them
    {"type": "churn", "tag": "churn", "duration": 21600, "rate": 20, "max_bytes": "1m"},
    {"type": "ping",  "tag": "lat64", "duration": 21600, "size": 64}
  ]
}
```

Workload types: `iperf3` (bulk goodput, `-R`/`-P`/`-O`/`-b`), `ping` (latency percentiles),
`bulk` (a competing bulk flow), `churn` (open/close streams — the soak's workload). Every option
other than `type`, `tag`, `duration` and `start_after` is passed straight to the tool, so
`"min_bytes": "10k"` becomes `--min-bytes 10k`.

**A kcptun server forwards to exactly one target**, so an `iperf3` workload cannot share a
scenario with `ping`/`bulk`/`churn` (which need `kr-pingpong serve`). `lab.py` refuses that
combination rather than producing a run where half the workloads fail. Use `bulk` when a
competing flow has to share the tunnel with a latency probe.

## What a run records

| file in the run directory | written by | holds |
|---|---|---|
| `proc.csv` | `kr-labsample` | per-process RSS, VmHWM, CPU ticks, fd count, threads, context switches, load average, every `sample_interval`. A WAN run has one per machine — the client's here, the server's in `server/` — and the report merges them by label |
| `snmp-cli.csv`, `snmp-srv.csv` | the tunnel binaries (`-snmplog`) | all 30 kcp-go counters, including `CurrEstab` (the live session count). On a WAN run the server's is under `server/` |
| `ping-*.csv`, `churn-*.csv`, `bulk-*.csv` | `kr-pingpong` | per-interval latency percentiles, stream counts and throughput |
| `iperf3-*.json` | iperf3 `-J` | goodput and retransmits |
| `<name>.log` | every process | stdout and stderr, including the final `SIGUSR1` SNMP dump and the workload's `RESULT {…}` line |
| `MANIFEST` | `lab-collect.sh` | file sizes and the host's uptime at collection, plus `clipped=yes`/`oversize=yes` for anything that is not complete |

The `-snmplog` file names contain **no digits**: kcptun runs the file part of that path through
Go's reference-time formatter, so `snmp-2026.csv` would be rewritten into a date. Only the
directory may carry a timestamp.

## Rules this tooling keeps

- No port below 4000, ever — the scenario's ports are checked against the ranges in
  safety rule 4 when it is parsed, and checked to be *free* (on the host and inside both
  lab namespaces, via `lab-baseline.sh --ports-only`) before every run, so a second run started
  while a detached one still holds the tunnel port fails immediately and says which port.
- The workloads, the `pingpong serve` target and the sampler are duration-bounded and expire on
  their own, so an abandoned run stops generating traffic instead of running for ever. The kcptun
  client, the kcptun server and `iperf3 -s` are **not** bounded: they and the namespace lab stay
  up until `lab.py collect` or `lab.py cleanup` stops them. That is why `lab.py cleanup` has to
  end every session.
- Output is append-only CSV, flushed per row, written on the host: a dropped ssh connection
  costs nothing.
- Logs are capped (`log_cap_bytes`, enforced by the sampler) and clipped when collected, so no
  run can fill the host's disk.
- `lab.py` starts only processes it names, stops only those, and never passes `--all`.
