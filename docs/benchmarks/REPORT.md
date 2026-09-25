# Performance report: kcptun-rust against Go kcptun

This is the document to read if you are deciding whether to put this port where your Go kcptun is
today. It collects every measurement the project has taken, says what each one does and does not
show, and is deliberately explicit about the parts of the plan that were **never measured at all**.

Nothing here is new. Every figure is quoted from the page that took it, and each section links to
that page, which owns the method, the spread and the caveats. Where two pages disagree, the one
that is current is named.

**Contents:** [The short answer](#the-short-answer) · [How to read any number here](#how-to-read-any-number-here) ·
[What was measured, and on what](#what-was-measured-and-on-what) ·
[End to end, unimpaired](#end-to-end-unimpaired) · [Under impairment](#under-impairment) ·
[Over a real Internet path](#over-a-real-internet-path) · [Six hours of churn](#six-hours-of-churn) ·
[Memory](#memory) · [Component benchmarks](#component-benchmarks) ·
[Correctness alongside the speed](#correctness-alongside-the-speed) ·
[What was not measured](#what-was-not-measured) · [Open questions](#open-questions-and-leads-that-are-not-results) ·
[Choosing a build](#choosing-a-build) · [Reproducing all of it](#reproducing-all-of-it)

---

## The short answer

| | Verdict | Where it comes from |
|---|---|---|
| **CPU** | **Clearly cheaper.** End to end at the production profile, 0.56–0.61× Go's CPU per GB on a 1-vCPU x86_64 box and 0.54× on a 2-vCPU aarch64 box, both ends counted together. Under netem impairment, 0.38–0.49× Go's tunnel CPU per delivered bit on the five degraded S1 profiles (`lan`, at 1 ms delay, is 0.69×; the impaired S2/S3/S4 cells are 0.50–0.63×). Over six hours of churn at an identical delivered rate, 1,476 CPU-seconds against Go's 6,822. | [12.1 baselines](#end-to-end-unimpaired), [11.2](#under-impairment), [11.4](#six-hours-of-churn) |
| **Memory** | **Much cheaper, and the old caveat is fixed, on glibc.** Idle client 3.48 MB against Go's 16.73; after six hours of churn, 42 MiB against Go's 223 (client) and 48 against 236 (server). The port used to hold its high-water mark for ever; it now gives it back. **On a static musl build it still does not**, and that build ramps 32–45 MiB/h with no ceiling. | [Memory](#memory), [D07](../DECISIONS.md) |
| **Goodput** | **Ahead in every provenanced cell measured at a socket buffer the profile asks for.** 1.52–1.66× (1 vCPU, re-taken at a ceiling the profile can use: 12.1b) and 1.74–1.79× (2 vCPU) at the production profile unimpaired; across netem profiles, 1.13–1.65× on the cells the campaign took at its own socket-buffer ceiling, and 1.09–1.45× on the three cells re-run with the host's `net.core.rmem_max` raised, two different sessions, not one range (see footnote 1 on the goodput table). **That qualifier covers three provenanced cells that are genuinely below 1.0**: at the stock 208 KiB ceiling the S1 `clean`, `lossy10` and `burst` cells read 0.86×/0.80×, 0.86×/0.80× and 0.90×/0.97×, and they inverted to 1.09–1.45× once the host's ceiling was raised to what `-sockbuf` asks for, nothing else changed. **Over a real 95 ms Internet path, fully provenanced: no deficit on the S1 upload** (1.17× on the pair medians, 1.03× pooled by sender, inside a ±20 % within-pair spread) **and 1.68× on the download** (±2–3 % spread on the Go-sending arm, ±8 % on the Rust-sending one, the separation is far outside both). The one cell that ever went the other way on its own merits, 0.75× on a single upload stream over a real 131 ms path, comes from an **unprovenanced** session and **did not reproduce**; it is retracted as a property of this tree and kept as a record. | [12.1](#end-to-end-unimpaired), [11.2](#under-impairment), [11.3b](#over-a-real-internet-path) |
| **Latency** | **Ahead when the tunnel is idle; behind at the median when it is full.** Idle p50 0.55–0.68× Go and p99 0.48–0.73×. Under a competing bulk flow the tail is still better: p99 0.50–0.60×, max 0.41×, but **the median is worse on both boxes, and on the 1-vCPU box it is worse by 29×** (15.04 ms against Go's 0.52) while that flow carries 1.97× the traffic. That cell is a standing queue and a real open question, not a rounding error; [lead 1](#open-questions-and-leads-that-are-not-results) has it in full. Over a real 131 ms path, better at p50, p90, p99 *and* max while carrying 22 % more bulk (unprovenanced session, see the warning above that section). | [12.1](#end-to-end-unimpaired), [11.2](#under-impairment), [11.3](#over-a-real-internet-path) |
| **Correctness under load** | **No failure found.** 432,284 churned streams over six hours with zero errors and zero timeouts, flat descriptor count; 128/128 interop runs green on two platforms; no error marker in any collected log of any lab session. | [11.4](#six-hours-of-churn), [interop matrix](../interop-matrix.md) |
| **`-crypt aes-128-gcm`** | **Slower than Go**, 0.68–0.88×, on both machines. The one cipher the port loses. Three alternative backends were built and measured; all were rejected. | [crypto.md](crypto.md), [D27](../DECISIONS.md) |
| **Coverage** | **Partial, and the gaps are large.** Three of seven metric families, two of four configurations and 16 of 28 impairment cells were never run; three rows of the performance plan (idle cost, startup time, the QPP scenario) have **no harness at all**. See [What was not measured](#what-was-not-measured). | [D32](../DECISIONS.md), this report |

**If your deployment is a fleet of mostly-idle tunnels on small boxes**, which is the case this
port was written for: the case is strong: the saving is dominated by the per-process floor, and
that floor is a fifth of Go's before any tunnel state exists. **If you depend on `aes-128-gcm` or
on `-tcp`**, the evidence here does not yet support a swap. The single long-fat-pipe upload stream
used to be on that list, on the strength of one unprovenanced cell; a provenanced re-take of the
same question found no deficit, so it is off it, with the caveat that the upload direction is the
noisiest cell in the whole grid.

---

## How to read any number here

Four rules. They are not decoration; every one of them has already caught a wrong reading in this
project.

1. **A ratio is only valid inside the session that produced it.** Every lab campaign interleaved Go
   and Rust runs (GG, RR, GR, RG, then again) precisely so that whatever the machine or the path was
   doing happened to both. Medians from two different sessions, even the same scenario on the same
   host an hour later: are not comparable, and absolute Mbit/s from one page must never be compared
   with absolute Mbit/s from another.
2. **A netns or single-box number is not network performance.** Most of the end-to-end work puts
   both tunnel ends, the workload and its target on *one* host, joined by a veth pair. That measures
   what the two implementations *cost*; it does not predict what a link will deliver. The
   [real-path section](#over-a-real-internet-path) is the only one taken over a real path, and it
   carries its own, larger warning.
3. **A missing row means not measured, never measured as zero.** The source pages print an em dash
   for an unmeasured cell and `n/a` for a ratio their two cells cannot support. This report keeps
   that distinction and lists every absent family in
   [What was not measured](#what-was-not-measured).
4. **Do not difference these numbers against the port's early micro-benchmarks.** The 12.1 baseline
   binaries already carry the tx-channel backpressure (V18), the `flush` scan bound (D29), the ACK
   addressing (D31) and the whole 12.3 memory programme. Subtracting them from the naive-port
   figures in [`kcp.md`](kcp.md) § 03.6 would credit finished work to work not yet done;
   [`kcp.md` § 12.1](kcp.md#121--attributing-the-8--gap-between-the-036-and-122c-baselines) exists
   to stop exactly that.

---

## What was measured, and on what

| Machine | Spec | Role | Note |
|---|---|---|---|
| laptop "M5" | Apple M5 (Mac17,2), 10 cores, macOS 27.0, arm64 | every micro-benchmark | Not a quiet machine during the 12.1 round: load average 1.1–1.7 on 10 cores, recorded on each page |
| `lab-arm64` | Neoverse-N1, **2 vCPU**, 11.6 GiB, Ubuntu 24.04 (kernel 6.17, glibc 2.39), aarch64 | end-to-end grid, memory, aarch64 micro-benchmarks | **Carries a live production mesh**: 27 Go clients and 3 Go servers, left running throughout, contributing ~0.1–0.5 background load |
| `lab-x86-1` | Xeon E5-2680 v4, **1 vCPU**, 1.9 GiB, Ubuntu 22.04 (glibc 2.35), x86_64 | end-to-end grid, Go soak arm | Carried the **stock** `net.core.rmem_max` of 212,992 B during the 12.1 grid, which invalidated its S1 half ([D32](../DECISIONS.md)); raised to 8,388,608 / 67,108,864 at 2026-09-24T21:57:15Z and S1 re-taken |
| `lab-x86-2` | **1 vCPU**, 1.9 GiB, Ubuntu 24.04 (glibc 2.39), x86_64 | netem matrix, Rust soak arm | The only lab host that has never carried a tunnel |
| `lab-x86-3` | **1 vCPU**, 961 MB, Ubuntu 24.04, x86_64 | WAN client | |

**The configurations**, from step 12:

```
S1  "production": the profile the reference mesh runs, and the one this port was written for
    both:   -mode normal -crypt xor -mtu 1390 -sndwnd 8192 -rcvwnd 8192 -smuxver 2
            -smuxbuf 16777216 -streambuf 16777216 -datashard 0 -parityshard 0 -nocomp -quiet
    client: -conn 4 -sockbuf 8388608        server: -sockbuf 67108868

S2  kcptun's own defaults: aes, FEC 10/3, -mode fast, windows 128/512, compression on
S3  -mode fast3 -crypt aes-128-gcm, FEC 10/3, windows 1024
S4  -crypt salsa20, no FEC, windows 1024
S5  S2 + -QPP -QPPCount 61                  <- no harness exists; never run
```

**The builds.** The 12.1 end-to-end grid and the `session.md` / `smux.md` micro-benchmarks are
commit `75fd8d8`; the netem matrix is `7373bae`. The other component pages **predate it and are
each at their own commit**: [`micro.md`](micro.md) says which, and every number in the
[Component benchmarks](#component-benchmarks) table is that page's at that page's commit. The two
lab campaigns are glibc builds on Linux, which is what the release artifacts are
([D07](../DECISIONS.md)). The Go side is the pinned reference (`reference/bin/*`), copied
byte for byte. The 12.1 pages stamp `75fd8d8-dirty` and explain it rather than rounding it to a
clean hash: what differed was **untracked files only** (the benchmark harness itself) with no
tracked file under `crates/` modified, so the tunnel binaries are what `75fd8d8` builds.

**Two campaigns are attributed out of band, and both are said so here rather than in a footnote.**
The 11.3 WAN session records its client build in every run but no server build at all, and says
so; it has since been superseded by [11.3b](../lab-results/11.3b-wan-matrix.md), whose 26 runs
each record and hash **every** artefact on both hosts. The [11.4 soak](#six-hours-of-churn) pair: both the Rust and the
Go arm, and the musl arm of the D07 allocator comparison recorded **no `build` key at all**,
because the `BUILD.txt` stamping landed after those runs had started (11.1b); their source pages
carry the attribution copied in by hand. Only the two-hour glibc arm of that comparison carries a
stamp (`03afc40-dirty`). 12.0 makes both classes impossible to repeat; it does not retrospectively
validate the runs that predate it.

---

## End to end, unimpaired

Two grids, one per host, taken the same day, plus a 60-run re-take of the x86_64 S1 half that
evening. **They may not be read across each other**: their absolute throughput differs by 2–3×,
almost none of which is the architecture (one box has two cores to the other's one, and they ran
different iperf3 versions and kernels). Only the Go-versus-Rust columns *inside* one cell of one
page mean anything.

Both grids are `bulk-up`, `bulk-down`, `latency` and `latency-loaded`, at S1 and S2, five
repetitions per pair per cell, A/B/A/B interleaved, 20 s of workload each: 120 runs per host, and
60 more for the x86_64 S1 re-take plus 20 for its S2 control.

> **The x86_64 S1 numbers below are the 12.1b re-take, not 12.1's.** 12.1's x86_64 campaign ran
> while that host carried the stock `net.core.rmem_max` of 212,992 B against S1's
> `-sockbuf 8388608`, which [D32](../DECISIONS.md) rules invalid rather than merely noisy.
> The ceiling was raised and **the S1 grid re-taken with the same binaries on the same host**
> ([the current page](2026-09-24-lab-x86-1-netns-clean-s1-sockbuf.md)); the `s1` half of
> [the 12.1 page](2026-09-24-lab-x86-1-netns-clean.md) is withdrawn and carries a banner saying so.
> Its **S2 half stands** and was checked rather than assumed, with a one-cell control at the raised
> ceiling ([S2 control](2026-09-24-lab-x86-1-netns-clean-s2-control.md)). Nothing about the aarch64
> grid changes: that host was already tuned to the raised ceiling.

### S1, the production profile

| | [1 vCPU, x86_64](2026-09-24-lab-x86-1-netns-clean-s1-sockbuf.md) | [2 vCPU, aarch64](2026-09-24-lab-arm64-netns-clean.md) |
|---|---|---|
| goodput, up / down | **1.66× / 1.52×** | **1.74× / 1.79×** |
| CPU per GB, both ends | **0.56× / 0.61×** | **0.54× / 0.54×** |
| CPU per GB, per end | 0.51–0.67× | 0.54–0.55× |
| RSS under load, client / server | 0.20× / 0.29× | 0.50× / 0.29× |
| latency p50 / p99, idle tunnel | **0.55× / 0.48×** | 0.68× / 0.73× |
| latency p50 / p99, under a competing bulk flow | **29.20×** (worse) / 0.60× | **1.17×** (worse) / 0.50× |
| goodput of that competing flow | 1.97× | 1.75× |
| retransmitted share of `OutSegs`, up | 1.5 % Go, **0.0 % Rust** | 13.2 % Go, **0.0 % Rust** |

**What the ceiling was worth, since it is larger than anything Step 12 optimised.** Same host, same
binaries, same campaign, thirteen hours apart, one sysctl changed: `bulk-up` goodput went
147.9 → 316.5 Mbit/s for Go and 182.1 → 526.6 for Rust, so the ratio went 1.23× → 1.66×; CPU per GB
0.81× → 0.56×; client RSS 0.33× → 0.20×. **Two of 12.1's three x86_64 S1 findings were the
clamp**, and both are withdrawn with it: the 34–48 % retransmission rates (now 0.0 % for Rust in
every S1 cell, 1.5–9.0 % for Go), and the `RepeatSegs` lead that 12.1 left open for 12.2 (now 0 for
Rust against 3,779–13,882 for Go: the sign has reversed and the two hosts agree). A third, the
cross-pair reading that a *Go* sender with a Rust receiver is the fastest pair at S1, has also
reversed: the Rust sender is now the fast side in both directions, as it already was at S2.

### S2, kcptun's defaults

| | 1 vCPU, x86_64 | 2 vCPU, aarch64 |
|---|---|---|
| goodput, up / down | 1.66–1.79× ¹ / 2.16× | 2.20× / 2.34× |
| CPU per GB, both ends | 0.54× / 0.44× | 0.46× / 0.44× |
| latency p50 / p99, idle tunnel | 0.37× / 0.25× | 0.54× / 0.56× |
| latency p50 / p99, under load | 0.44× / 0.47× | 0.63× / 0.51× |

¹ Two sessions on the same host thirteen hours apart, both medians of five interleaved runs, with
overlapping spreads: 1.79× on the 12.1 session and 1.66× on the 12.1b control taken after the
socket-buffer ceiling was raised. The difference is session noise on a 1-vCPU box: S2 is the
configuration the ceiling does *not* reach, so the range is printed rather than one of the two
picked. The [S2 control](2026-09-24-lab-x86-1-netns-clean-s2-control.md) is what establishes that.

### The cells where the port is behind, in full

**Median latency through a saturated tunnel, on both boxes, and on the 1-vCPU box by a lot.** On the
2-vCPU box at S1 under a competing bulk flow the port's p50 is 0.63 ms against Go's 0.54 and its p90
2.81 against 2.68: small, and offset by Rust moving 1,084 Mbit/s against Go's 621 in the same runs,
with p99 7.45 ms against 14.84. On the 1-vCPU box the same cell, re-taken at a raised socket-buffer
ceiling, is far worse: **p50 15.04 ms against Go's 0.52, a factor of 29, with no overlap between the
two sets of five runs** (Rust 13.01–15.96, Go 0.43–0.91). What has to be read beside it, and does
not make it go away: p90 22.74 ms against 27.46, p99 **36.31 against 60.95**, max 49.32 against
121.07, and a competing flow carrying **469.7 Mbit/s against 238.2**. The two distributions have
different *shapes*: Go's probe is mostly fast with a long tail, Rust's is a narrow band an order of
magnitude higher, which is a standing queue rather than occasional stalls, and at 469.7 Mbit/s a
15 ms queue is about 880 kB in flight, well inside S1's 8192-segment window. It is the trade
`-sndwnd 8192` asks for, and it is not settled: it needs a bounded-rate run where both
implementations carry the same load. [Lead 1](#open-questions-and-leads-that-are-not-results) has it.

Note what this replaces. The 12.1 x86_64 page had this same cell at p50 **0.54×** and p99 0.21×,
i.e. Rust comfortably ahead: the clamped receive buffer was holding the port's send rate down and
hiding the queue. Those rows are withdrawn.

### What two hosts together showed, and what the re-take did to it

**S1's enormous retransmission counts were the lab host's receive buffer.** 12.1 found the S1
retransmitted share of `OutSegs` to be 36.5 % for Go and 34.2 % for Rust on the 1-vCPU box against
13.2 % and 0.0 % on the 2-vCPU box, and concluded (reasonably, on those two pages) that this is
what a saturated *receiver* does rather than anything about either implementation. The re-take at a
raised ceiling keeps the conclusion and moves the cause: on the same 1-vCPU box the share is now
**1.5 % for Go and 0.0 % for Rust** uploading, 1.7 % and 0.0 % downloading, 9.0 % and 0.0 % with a
probe sharing the tunnel. The saturated receiver was the 208 KiB buffer, not the missing core; and
**Rust retransmits nothing at S1 on either host once the buffer can hold the window**, while Go
still retransmits 1.5–9.0 % on one and 13.2 % on the other. It remains true that nothing about the
RTO or the fast-retransmit threshold should be tuned on a retransmission count taken against a
clamped buffer.

**The `RepeatSegs` lead 12.1 left open is closed, and it was the clamp.** 12.1 reported that a Rust
sender's peer received 3–10× more duplicate segments than a Go sender's on the 1-vCPU box
(17,314 against 5,039 uploading) while the 2-vCPU box gave the opposite sign, and left it as the one
real lead on the page. At a raised ceiling the 1-vCPU box reverses too: **0 for Rust against 3,779
for Go** uploading, 0 against 2,495 downloading, 0 against 13,882 under a competing flow. The two
hosts agree and there is no longer a difference to explain.

**The cross pairs (GR, RG) interoperate and behave as a cost budget.** Throughput is measured for
them; CPU and RSS deliberately are not, because a mixed pair's process metrics describe two
different implementations at once. On the 2-vCPU box both mixed pairs land between GG and RR in both
directions, so the saving is spread across the send and receive paths rather than concentrated in
one. 12.1 found the 1-vCPU box's S1 to be the exception: a *Go* sender with a Rust receiver
fastest in both directions, reversing S2 exactly, and called it the most useful lead in the grid.
**That reversed with the ceiling too.** At S1 re-taken, RG (a Rust client sending) is 433.5 Mbit/s
against GR's 362.7 uploading, and GR (a Rust server sending) is 426.7 against RG's 373.2
downloading: the Rust *sender* is the fast side in both directions, as it already was at S2, and RR
is the fastest pair in both. There is no S1-specific send-path cost left to profile.

---

## Under impairment

[11.2](../lab-results/11.2-netem-matrix.md) ran the two implementations across netem profiles on
one x86_64 box (`wan50` is about 100 ms RTT and 0.2 % round-trip loss; `lossy2` about 160 ms and
4 %; `lossy10` about 160 ms and 19 %; `burst` is Gilbert-Elliott at about 120 ms; `ratelimited` is
a 100 Mbit/s cap). Three repetitions per pair per cell, all four pairs interleaved.

**The first thing this campaign found was about the lab host, not about either implementation.**
`setsockopt(SO_RCVBUF)` is silently clamped to `net.core.rmem_max`, and the test host carried the
stock 208 KiB while S1 asks for 8 MB. Measured from `/proc/net/snmp` over one 65 s run: at the stock
ceiling Go lost 24.4 % of arriving datagrams to `UdpRcvbufErrors` and Rust 48.3 %; **at a properly
tuned ceiling both lost zero**, and every cell that had failed the acceptance criterion inverted
with nothing else changed (`clean` 0.86×/0.80× -> **1.45×/1.43×**, `lossy10` -> 1.09×/1.11×,
`burst` -> 1.25×/1.27×). Rust overflowed the small buffer more than Go because it puts the burst on
the wire faster. **This is the single most important operational note in this report: if your
kernel's `net.core.rmem_max` is below your `-sockbuf`, you are measuring your host.** The tooling
now records both ceilings per run and warns at preflight; the decision is
[D32](../DECISIONS.md).

### Goodput, RR against GG

| config | clean | lan | wan50 | lossy2 | lossy10 | burst | ratelimited |
|---|---|---|---|---|---|---|---|
| **S1** up / down | 1.45× / 1.43× ¹ | 1.16× / 1.13× | **1.65× / 1.47×** | **1.47× / 1.43×** | 1.09× / 1.11× ¹ | 1.25× / 1.27× ¹ | 1.00× / 1.00× ² |
| **S2** | 1.57× / 1.57× | not run | 1.13× / 1.13× | not run | 1.09× / 1.15× | not run | not run |
| **S3** | not run | not run | not run | not run | 1.11× / 1.13× | not run | not run |
| **S4** | not run | not run | not run | not run | 1.12× / 1.12× | not run | not run |

¹ from the controlled re-run with the socket-buffer ceiling raised to what the profile asks for; at
the stock ceiling these three cells read 0.86×/0.80×, 0.86×/0.80× and 0.90×/0.97×, and that is the
host. ² both implementations deliver the 100 Mbit/s cap exactly, so the interesting column is cost.
Every "not run" above is a cell that **was not measured**, see [D32](../DECISIONS.md) and
[What was not measured](#what-was-not-measured).

### Cost per delivered bit: the row that answers the deployment question

Tunnel CPU (client + server, excluding the workload) per megabit actually delivered. Lower is
better.

| S1 profile | Go ms/Mbit | Rust ms/Mbit | ratio |
|---|---:|---:|---:|
| clean, capped at 250 Mbit/s (equal load) | 1.42 | **0.95** | 0.67× |
| lan | 3.11 | **2.14** | 0.69× |
| wan50 | 8.85 | **4.22** | **0.48×** |
| lossy2 | 10.7 | **4.10** | **0.38×** |
| lossy10 | 7.05 | **3.07** | **0.44×** |
| burst | 6.53 | **2.88** | **0.44×** |
| ratelimited (equal goodput) | 6.74 | **3.32** | **0.49×** |

Go's cost per delivered bit rises steeply as the path degrades (1.42 -> 10.7) while Rust's roughly
quadruples from a much lower base (0.95 -> 4.10), so **the port is relatively cheapest exactly where
the path is worst**. The same holds at S2, S3 and S4 (0.63× on S3 `lossy10`). The raised-ceiling
re-run, which covers two of these cells, is lower still: 0.35× on `lossy10` and 0.34× on `burst`.

### Latency

Idle, at 100 ms and 160 ms RTT, **the two implementations are indistinguishable**: every percentile
within 2 %. That is the correct answer: the path dominates and neither adds to it. Only on `clean`,
where the numbers are a few hundred microseconds, does the per-packet cost difference show (p50 and
p99 both 0.58×).

Under a competing bulk flow the port is ahead on both axes at once, which needs stating carefully:
its p99 is 0.31–0.86× Go's **while its competing flow carried 1.6–2.1× as much data**. The
comparison is not rate-matched and the probe is queueing behind *more* traffic, so this is the
conservative reading, not the flattering one. One `clean` p90 cell goes the other way for the same
reason.

### The retransmission question, settled with a Go control

The soak had recorded 28.4 % of segments retransmitted on a path with 0.1 % configured loss, and
189× more duplicates received than segments lost, with no Go control. Two cells of this campaign
provide it. On the soak's own profile (S1 `wan50`): retransmitted share **35.6 % for Go, 36.4 % for
Rust**, with near-identical duplicate ratios (2.34 and 2.32). In the small-window regime (S2
`wan50`) both produce an enormous duplicate ratio and **Go's is the larger** (128× against 86.8×).
The soak's 189× sits between the two columns. So this is faithful KCP behaviour: `-mode normal`
with `nc = 1` has congestion control off and kcp-go is exactly as aggressive.

Where the two do differ is **mechanism**: Rust reaches the same amount of retransmission with more
fast retransmit and less RTO (62 % against 45 % on S1 `wan50`, 84 % against 61 % on `lossy2`), and
its `LostSegs` are correspondingly lower (40 k against 107 k on `lossy2`). Detecting loss from
duplicate ACKs instead of waiting out a timeout is why it delivers 1.47× the goodput there.

**Two cells run the other way and the generalisation does not survive them.** On S1 `lan` the
retransmitted share is 11.1 % for Go against **22.2 %** for Rust, RTO-driven rather than
duplicate-ACK-driven. `clean` is the same shape at smaller scale and is explained by the socket
buffer (it inverts under the raised ceiling); **`lan` was not re-run under the raised ceiling and is
unattributed.** It is listed here rather than left out.

---

## Over a real Internet path

Two sessions exist, on two rungs of the RTT ladder, and they are **not comparable with each
other**: a real Internet path is not reproducible between sessions, so only the Go-versus-Rust
comparisons *inside* one session mean anything. What they have in common is the shape: a 1-vCPU
x86_64 client sending over a long, clean transatlantic path into the 2-vCPU aarch64 box, the same
S1 and S2 profiles, the same scenarios, the same GG/RR/GR/RG interleaving.

| | **11.3b: 95.3 ms, provenanced** (2026-09-24) | 11.3, 131.1 ms, **unprovenanced** (2026-09-23/24) |
|---|---|---|
| client → server | `lab-x86-2` → `lab-arm64` | `lab-x86-3` → `lab-arm64` |
| runs | 26, no error markers | 27, no error markers |
| artefacts | **every binary on both ends stamped, hashed on the host, recorded in every run** | **`server_build` empty in all 27** |
| S1 up, RR/GG | **1.17×** (1.03× pooled by sender) | **0.75×** |
| S1 down, RR/GG | **1.68×** | 1.40× |
| S2, RR/GG | 1.14× up, 1.12× down (1.04× / 1.24× pooled by sender) | 1.04× both ways |
| status | **this is the one to quote** | kept as a record; its headline is not confirmed |

[Full write-up of 11.3b](../lab-results/11.3b-wan-matrix.md) ·
[of 11.3](../lab-results/11.3-wan-matrix.md).

**The 0.75× S1 upload is retracted as a property of this tree.** It came from the session in
which the Rust *server* artefact was never identified: out-of-band inspection says an older
static-musl aarch64 file, so no number from it may be presented as a measurement of this tree,
and that session cannot be re-run: 12.0 makes a run refuse to start on a host whose build stamp
cannot be read, and the binary is gone. Re-taking the *question* on the 95.3 ms rung with
everything stamped gives **1.17×** on the pair medians, and **1.03×** pooling all six Go-client
runs against all six Rust-client runs. The upload direction's own spread there is ±20 % within a
pair (Go's three GG runs: 464, 515, 683 Mbit/s), so the honest claim is **"no deficit, and no
reliable advantage either"** on the upload, and every acceptance cell of that session clears
11.2's 0.95× bar. A different rung cannot prove a number taken on another rung *wrong*; what it
can do is decline to reproduce it, which is what happened.

**What did reproduce, as a tendency rather than a separation, is the retransmission behaviour.**
On a single upload stream Rust's client-side retransmit share is the larger one at the pair
medians (**1.58 % against Go's 0.23 %** at 95 ms, where 11.3 measured 9.3 % against 3.2 %) with
the same ~99.7 % RTO-driven composition, and it is almost entirely **spurious** on both
implementations: the receiver's duplicate rate tracks the sender's retransmit rate to the second
decimal, so the segment that was retransmitted had already arrived. **Pooled by sender, the way
the goodput figure above is pooled, the gap is 1.61 % against 0.58 %, 2.8× and not 6.9×, and the
two per-run ranges overlap completely**: Go 0.005–5.79 %, Rust 1.32–2.37 %, with one Go run
higher than every Rust run of the session. Three repetitions on a path this noisy support the
ordering at the medians, not a run-by-run separation. At 95 ms it costs no goodput at all, and the
pair that retransmits more is the pair that moves more data. In the other direction the ordering
reverses and by more: sending from the aarch64 box, **Go retransmits 38.0 % of its segments
against Rust's 10.8 %**, and Rust delivers 1.65× the goodput at 0.60× the CPU per gigabyte.

**The mixed workload, which is what a tunnel actually carries, is where the port is furthest
ahead.** A 10-minute 64-byte probe with a competing bidirectional bulk flow inside the same
tunnel, one run per pair, on the provenanced rung:

| | Go | Rust | ratio |
|---|---:|---:|---|
| ping p50 / p90 / p99 / max | 114 / 184 / 282 / 498 ms | **98.8 / 108.8 / 231.2 / 284.7 ms** | 0.87× / 0.59× / 0.82× / 0.57× |
| competing bulk carried | 357 Mbit/s | **510 Mbit/s** | 1.43× |
| client retransmitted, share of segments sent | 21.6 % | **0.53 %** | 0.02× |
| client duplicates *received*, share of segments received | **14.1 %** | 21.2 % | 1.50× |
| server retransmitted, share of segments sent | 31.9 % | **24.2 %** | 0.76× |
| client peak RSS | 96 MB | **28 MB** | 0.29× |
| client CPU per GB moved | 11.1 s | **5.0 s** | 0.45× |
| errors | 0 | 0 | |

Better at every percentile including the tail, carrying 43 % more bulk, on 45 % of the CPU per
gigabyte, and here it is **Go** that retransmits 40× more. The two rows that go the other way are
in the table rather than omitted: Rust's client *receives* more duplicates (21.2 % against 14.1 %)
because the Rust server, while retransmitting less both absolutely and as a share, retransmits far
more **spuriously**: 84 % of its retransmissions arrive as duplicates against Go's 35 %, and
94 % against Go's 58 % in the client-sending direction. Rust sends fewer retransmissions here and
a larger fraction of them were not needed. 11.3's unprovenanced session found the
same shape (better everywhere, +22 % bulk, 0.37× the retransmissions). A report that quoted only
the single-stream upload, or only this, would be misleading, so both are here. A four-port range
(`-conn 4` over UDP 29910–29913) reproduced the single-port result unchanged, mixed pairs
included: that is from the unprovenanced session and has not been re-taken.

**Four of the six rungs of the RTT ladder have still never been run** (5.1, 46.3, 56.7 and
81.9 ms), and the 131.1 ms rung has never been run *provenanced*, which is the one that would
settle its own headline directly rather than by analogy. The runbooks are in the source documents.

---

## Six hours of churn

[11.4](../lab-results/11.4-soak.md) ran the same scenario: S1 flags, `wan50` netem, 20 streams/s of
10 kB–1 MB churn, 10 long-lived streams, an 8 MB × 4 burst every five minutes, a latency probe
alongside, on two near-identical 1-vCPU boxes for the same six hours: Rust on one, Go on the other.
Acceptance is the **slopes after warm-up**, not the endpoints, because first-to-last cannot tell a
one-off step from a leak.

**Provenance, stated up front:** neither arm's `state.json` carries a `build` key: the stamping
landed after these runs started (11.1b), so the binaries are attributed **by hand** in the two
source pages, the same class of out-of-band attribution as 11.3's server. 12.0 stops it recurring
without retrospectively validating these runs.

| | Rust client | Rust server | Go client | Go server |
|---|---:|---:|---:|---:|
| **RSS slope after warm-up** | **+537 kB/h** | **+201 kB/h** | +973 kB/h | +567 kB/h |
| **fd slope** | **-0.0 /h** | **+0.0 /h** | +0.4 /h | +0.5 /h |
| RSS first -> last | 4.3 -> **42.1 MiB** | 5.1 -> **47.6 MiB** | 15.6 -> 222.8 MiB | 15.2 -> 235.8 MiB |
| RSS max / `VmHWM` | 43.5 / 45.5 MiB | 49.6 / 49.6 MiB | 222.8 MiB | 261.7 / 261.9 MiB |
| CPU over 6 h | **1,476 s** | **1,487 s** | 6,822 s | 6,843 s |
| churn completed | **432,284 / 432,284 streams, 0 errors, 0 timeouts** | | 430,606 / 430,606, 0 errors | |
| delivered | 36.8 Mbit/s | | 36.7 Mbit/s | |

**Both sides pass, and both slopes are plateau drift rather than growth**: the Rust client sits in a
39–43 MiB band for six hours, Go's GC oscillates around about 185 MiB. The descriptor count holds at
1230 ± 5 for six hours under the production 30 s `closewait` linger at 20 streams/s, so the linger
reaches a steady state and does not accumulate.

**Stated plainly: the two boxes are near-identical but not identical** (different Ubuntu releases),
**and the Go box was CPU-saturated while the Rust box was not**: load 2.16 against 0.25 on a single
core. Both delivered the same offered load, because the churn is rate-driven, so treat the **RSS,
fd and CPU rows as the comparable ones and the latency percentiles as indicative only**. (For the
record they were 102.50 / 115.61 / 192.41 ms p50/p90/p99 for Rust against 111.94 / 191.37 / 374.34
for Go, but that gap is largely what the saturation costs.)

One design note worth knowing if you read the code: the process-wide idle trim added in 12.3b
**never fired once** during either six-hour run: the churn keeps the process busy every tick by
construction. The flat plateau above was held entirely by ordinary `free` on glibc. The trim only
acted in the 100 seconds after traffic stopped, taking the process from 45.3 to 13.6 MiB.

---

## Memory

This is the part of the report that changed most during the project, and the part where the port
used to lose. [`memory.md`](memory.md) owns it in full, including the two measurement harnesses
whose numbers **must not be subtracted from one another**.

### Idle, which is what a fleet is mostly doing

Real `kcptun-client` / `kcptun-server` processes on aarch64 with S1 flags and no connection ever
made, sampled at 60 s:

| | Rust, glibc (**what ships**) | Rust, static musl | Go |
|---|---:|---:|---:|
| client idle RSS | **3.48 MB** | 1.75 MB | 16.73 MB |
| server idle RSS | **4.37 MB** | 2.84 MB | 17.23 MB |
| per idle stream | **4.6 kB** | 4.6 kB | 22.5 kB (client) / 31.0 kB (server) |
| per idle KCP session, client | **55 kB** first generation, about 375 kB once sessions churn | 455 kB | 243 kB |
| per idle KCP session, server | **102 kB** | | 166 kB |

The idle floor is where the saving is. An idle stream costs a fifth of Go's because a proxied
connection that has never been read from owns no copy buffer at all (D17). A client session costs
55 kB while the process's sessions are its first, because the receive batch is one contiguous
allocation that the allocator serves from a fresh mapping and never touches; once sessions have been
replaced a few times glibc raises its dynamic `mmap` threshold and the steady state is about 375 kB.
**Both numbers are quoted, and which applies depends on whether your client replaces sessions**
(`-autoexpire`, errors, the 600 s scavenger). A client that holds its `-conn` sessions for the life
of the process (the common case) stays in the first column.

### What that arithmetic does to a real fleet

The reference deployment is a mesh of 27 Go clients averaging 18.5 MB and 3 Go servers averaging
17.2 MB, about **552 MB** in total.

| | Go | Rust, glibc, sessions never replaced | Rust, glibc, sessions churning |
|---|---:|---:|---:|
| per client (4 sessions + about 36 idle streams) | 18.5 MB | **3.72 MB** | 5.00 MB |
| 27 clients + 3 servers | **552 MB** | **about 113 MB** | **about 148 MB** |

That is roughly **550 MB -> 110–150 MB**, a saving of about 400–445 MB. It is an arithmetic
projection from measured per-object slopes, not an observation of a running mesh, and the "4
sessions + 36 streams" decomposition is a *fit* to the Go average: other combinations give the same
total. What is directly measured is the floor, and the floor alone accounts for 503 MB of the 552.

The old break-even that used to worry this section: Go pulling ahead above about 33 sessions per
client: **is gone on a glibc build whose sessions are its first**, where more sessions widen the
lead. It returns at about 101 sessions per client once they churn, and on static musl it survives at
about 71.

### The caveat that used to be fatal, and what is left of it

Until 12.3b, a Rust process **gave nothing back** after a burst: flat to the byte for 600 s with all
streams closed, while a Go process falls back over a few minutes and ends up *below*. A fleet of
bursty tunnels could therefore have sat above Go's total until something restarted them. A heap
profile showed the program had already freed 85 % of the peak and the allocator had simply never
been asked for it.

**On glibc that is fixed and verified at soak scale**: 50.3 MiB peak falling to 13.6 MiB within two
minutes of the traffic stopping, 73 % returned and it stayed returned for the 20 minutes measured;
a negative RSS slope over the identical window. **On static musl it is not fixed and cannot be**,
because mallocng has no `malloc_trim` entry point for the idle trim to call. See
[Choosing a build](#choosing-a-build).

---

## Component benchmarks

These are per-operation micro-benchmarks. They are useful for understanding *where* the end-to-end
difference comes from and are not predictions of tunnel throughput.
[`micro.md`](micro.md) is the index, and it also lists what each page is **not** evidence for.

| Layer | Headline, Rust against Go | Page |
|---|---|---|
| Packet crypto | CFB decrypt **3.7–6.1×**, CFB encrypt 1.1–1.6×, salsa20 1.5–2.4×, xor 1.2–1.5×; **aes-128-gcm 0.68–0.88×** | [crypto.md](crypto.md) |
| FEC + Reed-Solomon | encode/decode **1.2–2.1×**, RS encode 1.4–1.9×, reconstruct 1.0–1.9× | [fec.md](fec.md) |
| KCP ARQ core | naive port 1.0–2.9×; D29 makes `flush` **O(1) in the window** (408× its own baseline, 902× Go at `-sndwnd 8192`) and D31 makes the **ACK path** O(1) in it (selective-ACK input 1.6–1.7× its own baseline, 3.7–4.8× Go) | [kcp.md](kcp.md) |
| KCP session, loopback echo | **0.37–0.58× the CPU per GB**, 1.2–3.1× the throughput (laptop) | [session.md](session.md) |
| smux | per idle stream **2.93 kB against 6.99** | [smux.md](smux.md) |

Four things that belong next to that table rather than under it:

* **`aes-128-gcm` is the one cipher where this port loses**, 0.77×/0.76× on the laptop and
  0.69×/0.68× on the N1, at 1350 bytes. Go uses fused AES+GHASH assembly; the RustCrypto crate makes
  two passes. Three replacements were built and measured against Go on both machines: `ring`,
  `aws-lc-rs` and a hand-fused safe-Rust AES-CTR+GHASH, and **none met the bar of at least 1.0× for
  both seal and open on both machines**; the closest would have added tens of megabytes of vendored
  C and a mandatory C toolchain to an otherwise pure-Rust project. RustCrypto stays and the gap
  stays ([D27](../DECISIONS.md)). It matters for S3 and for anyone running
  `-crypt aes-128-gcm`; it does not touch S1, which uses `xor`.
* **`smux.md` is not a measurement of smux.** The verifying peers spend most of the timed region in
  a PRNG and SHA-256, so all four client/server combinations land within 8 %. That *is* a finding,
  smux is not the bottleneck, but there is no throughput comparison of the two multiplexers here
  and there cannot be until the Go peer gains a payload mode that skips the per-byte work. The
  per-idle-stream memory row *is* a real measurement, taken as a slope over N with a fresh server
  per point.
* **`session.md` is KCP only** (no smux, no snappy, no TCP proxy, no network) and its aarch64 half
  is at medians of three and was not re-measured. A 10-core laptop echoing over loopback is the
  friendliest case there is; on the 2-vCPU Linux box the same sweep gave a much narrower lead
  (1.02–1.38× throughput, 0.68–0.86× CPU per GB).
* **`fec.md`'s `zeroed` rows only just meet the bar on aarch64** (1.04×), because musl's `memset`
  moves about 2.9 GB/s there and the decoder zero-fills recovered shards. D07 has since made glibc
  the default, which changes that row's premise; **it has not been re-measured.**

### One series that must not be quoted as a series

`kcp.md`'s § 03.6 table is the `[03.6b]` commit's and no other. Two of its Rust columns moved later
through unrelated code changes: `flush` by -7 % at `[12.2a]` and `in_order` by **+8 % somewhere
before it**. The `flush` step was bisected to a specific commit and is a code-generation effect of a
restructured loop, not an algorithmic win, which is why the ratio D29 earned is 28.66 µs -> 70.1 ns,
**408×**, and not the larger figure that differencing the published tables would give. The
`in_order` step is **bounded to an interval and deliberately not attributed to a commit**: nothing
in that interval touches the KCP source at all, so it too is codegen. No number is quoted from
inside it, and those figures must not be read as a progression.

---

## Correctness alongside the speed

Performance work that broke the wire format would be worthless, so this is part of the same answer.

* **[Interop matrix](../interop-matrix.md): 128/128 runs green** on macOS/arm64 and Linux/aarch64.
  Every one of 32 cases: all 15 ciphers, 16 pairwise feature combinations and the production
  profile: runs in all four pairings with both `go->go` and `rs->rs` controls. Per run: 20 MB each
  way on one bulk stream, 100 concurrent 16 KiB streams each way, and a half-close probe, all
  SHA-256 verified with both processes' logs scanned afterwards. The only tolerated difference is a
  Go-side half-close truncation that reproduces in the `go->go` control (V11, V04); a Rust client is
  held to a complete response against either server.
* **No error marker in any collected log of any lab run**, across the 192-run impairment matrix, the
  27-run and 26-run WAN sessions, the 240 end-to-end baseline runs and four soak runs (the two 12.1 pages do
  not print a log scan; for those 240 runs that is `lab.py`'s check at run time, not a committed
  artefact). No stuck sessions: in
  every impairment cell, on both sides and for all four pairs, the live session count equalled the
  configured `-conn` at the peak and at the end.
* **The optimisations are differentially tested.** D25 keeps a `flush`/`input` oracle for ever, and
  the optimised paths are proven against it to emit identical packets and reach identical state on
  randomised lossy and reordering traces, plus Go golden traces and a fuzz run. As amended by D29,
  that oracle is **the same code path with the D29/D31 fast paths switched off**
  (`flush_scan.enabled = false`), not a separate naive copy: better, in that the two cannot drift,
  but it still carries the bookkeeping and is no longer byte-for-byte the pre-12.2c function. What
  still validates the loop body against kcp-go itself is the **Go golden traces**.

---

## What was not measured

This section is the point of the document. An absent row is **not measured**, never measured as
zero, and the gaps below are large enough that no one should read the tables above as a complete
evaluation.

**The end-to-end grid is partial.** `tools/bench/bench.py` defines seven metric families and four
configurations. The 12.1 campaign ran **four families at two configurations** on each host. Not run:

* `bulk-par-up` / `bulk-par-down`: iperf3 `-P 8`, the **second half of the plan's Goodput row**. All
  numbers above are single-stream.
* `churn`: the plan's **Scale row**. The 1k and 5k concurrent-stream figures, and the
  short-stream churn rate, do not exist. (The soak churned 432,284 streams, but at a fixed 20/s.)
* configurations **S3** and **S4** end to end. They appear only in the impairment matrix, at one
  profile each.

These three are implemented, tested and would run unchanged; they were omitted for machine time
(eight cells at five repetitions already took 1 h 24 m and 1 h 43 m on the two hosts).

**Three rows of the plan have no harness at all**, so there is nothing to run:

* **Idle cost**: CPU % and wakeups per second for N idle sessions over ten minutes. Never measured.
  The memory cost of idle sessions *is* measured; the CPU and wakeup cost is not.
* **Startup time**: time to "listening on", which is where PBKDF2 and QPP pad generation land.
  Never measured.
* **S5 (QPP)**: the `-QPP -QPPCount 61` scenario has no harness family and no lab configuration.
  QPP has a criterion benchmark and **no write-up of any kind**. Interop covers it for correctness;
  nothing covers it for performance.

**The impairment matrix is 12 of the 28 bulk cells** (16 cells in all, counting a capped control and
three latency cells; [D32](../DECISIONS.md)): S1 over all seven profiles, S2 over three, S3
and S4 over one each. **Sixteen bulk cells were never run**: S2, S3 and S4 over `lan`, `lossy2`,
`burst` and `ratelimited`, plus S3 and S4 over `clean` and `wan50`. The latency half is
`clean`/`wan50`/`lossy2` only. The unrun cells are interpolations between measured
ones (S2/S3/S4 differ from S1 only in cipher, FEC and window) but they are interpolations, not
measurements, and the source document lists every one of them with the command that would take it.

**Four of the six WAN rungs have never been run** (5.1, 46.3, 56.7 and 81.9 ms). Of the two that
have, only the 95.3 ms one is provenanced; the 131.1 ms one has never been re-taken with stamped
binaries, and neither has the four-port-range scenario.

**Step 12.4 (the optional advanced I/O work) was not attempted.** UDP GSO/GRO, a connected client
socket and `SO_REUSEPORT` sharded listeners are all unimplemented and unmeasured. Nothing in this
report depends on them; equally, none of the gains they might offer are in these numbers.

**D29's accepted cost has never been isolated.** The `flush` scan bound is 347–408× faster on the
scan it can skip and **26–30 % slower on the M5 (9–10 % on the N1) on the scan it cannot**, and both
of those are *Rust-against-Rust* figures. The impairment matrix shows the cost does not surface
against Go in deployment (the port is relatively *cheapest* on the lossiest profiles, 0.38–0.44×),
which settles the deployment question, but it does not measure the 26–30 %. The shipped binaries
have **no switch** for it (the toggle lives behind a development-only Cargo feature) and the
existing `flush` benchmark fills the send buffer with far-future timers, i.e. precisely the case the
optimisation *can* skip, so it measures the speed-up and not the penalty. **A benchmark whose
segments are all due is still owed.** Note also that at 9–10 % on the deployment architecture, the
penalty may simply be below what any netem or WAN run can resolve: "not detected" here is not the
same as "not present".

**Other measurements the pages themselves flag as incomplete:** scale beyond 16 sessions and 100
streams; how long a Go process takes to finish releasing (the port's endpoint is known, Go's is
not); a server that is never fully quiet, which is the case that decides whether the memory headline
holds for a server multiplexing many clients; **the real two-process pair at idle after 12.3c**, so
the shipped build's idle floor comes from `memory.md` § 6.2's real-binary idle table while the per-session
slope comes from § 7's single-process staircase; and the `fec.md` `zeroed` rows under glibc.

**Finally, `-tcp` (fake TCP) is functionally unverified**, which is not a performance statement but
belongs in any swap decision: nothing in this report exercises it.

---

## Open questions and leads that are not results

Listed as leads, because each one has a plausible reading in both directions and none has been
confirmed.

1. **The `RepeatSegs` lead reverses sign between hosts.** On the 1-vCPU box a Rust sender's peer
   receives 3–10× more duplicate segments than a Go sender's (2.7–3.0 % of `OutSegs` against
   0.9–1.2 %), consistently across both directions and both cross pairs over five runs each. On the
   2-vCPU box the same cells are **0 for Rust and 12,640 / 14,936 for Go**: the sign flips. The
   honest reading is that on a saturated single core the port drives the link harder and wastes more
   of what it retransmits, not that its RTO estimate is worse than Go's. **It must be re-taken at a
   bounded rate rather than at saturation before it means anything.**
2. **The S1 latency-under-load loss on the 2-vCPU box** (p50 1.17×, p90 1.05×) needs the same
   bounded-rate re-run, for the same reason: the two arms were not carrying the same amount of
   traffic.
3. **The upload direction over a real path** still confounds "direction" with "host" on both rungs
   measured: the sending client is always the small x86_64 box and the sending server always the
   2-vCPU aarch64 one. A rung between two identical 1-vCPU boxes (5.1 or 56.7 ms) is what separates
   them. 11.3's 0.75× is retracted (it did not reproduce, provenanced, at 95 ms), but the rung it
   was taken on has still never been run with stamped binaries.
1. **Median latency through a saturated S1 tunnel, on both boxes: the one open item that is
   large.** On the 1-vCPU box, re-taken at a raised socket-buffer ceiling, the probe's p50 is
   **15.04 ms against Go's 0.52** while the tail is better (p99 0.60×, max 0.41×) and the competing
   flow carries 1.97× the traffic; on the 2-vCPU box the same cell is a mild p50 1.17×, p90 1.05×
   with p99 0.50× and 1.75× the traffic. Same sign, two hosts, two orders of magnitude apart in
   size. The shape (a narrow band an order of magnitude up, rather than a long tail) says
   standing queue rather than stalls, and `-sndwnd 8192` is what asks for one. **It needs a
   bounded-rate run in which both implementations carry the same load**, which no cell in the grid
   does, before it is either a defect or a trade. Until then it is the reason the latency row of
   [the short answer](#the-short-answer) is split between idle and loaded.
2. **What 12.1 had as lead 1 (the `RepeatSegs` sign reversal between hosts) is closed, not open.**
   It was the x86_64 host's clamped receive buffer. At a raised ceiling that box gives 0 duplicates
   for Rust against 3,779–13,882 for Go, which is the aarch64 box's sign; both hosts now agree and
   the bounded-rate re-run that lead required is not needed. Recorded here rather than deleted
   because the lead was quoted.
3. **The 11.3 upload deficit** needs a rung between two identical 1-vCPU boxes to separate
   "direction" from "host", and a re-run against provenanced binaries to be a measurement of this
   tree at all.
4. **S1 `lan`'s inverted retransmission counters** were not re-run under the corrected socket-buffer
   ceiling and are unattributed. The 12.1b re-take shows how much that ceiling can be worth: it
   took the unimpaired x86_64 S1 retransmitted share from 34.2 % to 0.0 % for Rust, so these
   counters should be treated as unmeasured rather than as a small effect.
5. **The `in_order` +8 % codegen step** is bounded to an interval and not attributed to a commit.
6. **`aes-128-gcm`** remains open: RustCrypto is the best available pure-Rust option today and is
   still behind Go.

---

## Choosing a build

> ### Take the static musl artifact only if you have to
>
> Under sustained traffic a static musl build **does not give memory back at all**, and it does not
> merely keep its high-water mark: it **ramps 32–45 MiB/h and had not flattened after six hours
> (79 -> 253 MiB)**. On a 1 GB box that is an out-of-memory kill within a day.
>
> This is measured, not inferred, and the confound was removed by holding one box constant: same
> machine, same kernel, same netem profile, same flags, same churn seed, same workload driver, only
> the allocator changed. musl peaked at **253 MiB and released 0 %**, still climbing at
> **+44,860 kB/h**; glibc peaked at **50 MiB**, fell to **13.6 MiB** within two minutes and had a
> *negative* slope. Both arms carried the same 36.7 Mbit/s at the same latency and the same CPU.
> mallocng has **no `malloc_trim` entry point at all**, so the idle trim has nothing to call and no
> amount of idling helps.
>
> Limits of that comparison, stated: **n = 1 per arm** with no interleaving, and the two arms ran
> for different durations (6 h musl, 2 h glibc) at different times of day. Restricting musl to the
> same two hours still leaves it at 135 MiB (2.7×) and still climbing. The effect is 5× in peak
> and 75× in slope, far outside any plausible run-to-run spread, but it is one run each.
>
> Take musl when a single static file that runs on any Linux matters more than the process ever
> giving memory back.

**mimalloc was measured and rejected.** It solves about half the retention problem on musl (49–55 %
released against mallocng's 5 %) but raises the idle floor 4.5×: 56 MB -> 251 MB across the
reference mesh *before any traffic*, and costs a C build dependency. That is the number this port
is actually selling.

Both flavours are still built and published, so the option cannot rot and the documentation
offering it cannot start lying. The full decision and its evidence are
[D07](../DECISIONS.md); the operational consequences are in the
[README](../../README.md#binaries).

**Host tuning matters more than the choice of implementation on an untuned box.** If
`net.core.rmem_max` is below your `-sockbuf`, the kernel silently clamps it, and at S1's window that
alone decided three cells of the impairment matrix, and, when the unimpaired x86_64 S1 grid was
re-taken with it raised, doubled both implementations' throughput and took the port's retransmitted
share from 34.2 % to 0.0 %. Note that a configuration which passes **no** `-sockbuf` is not exempt:
kcptun's flag defaults to 4 MiB and is always applied, which is 20× the stock 212,992 B ceiling.
`dist/` ships the sysctl drop-in.

---

## Reproducing all of it

Every page has its own method section with the exact command. In summary:

```sh
# micro-benchmarks: Rust (criterion, release profile: fat LTO, 1 CGU)
cargo bench -p kcptun-kcp --bench crypt -- --noplot
cargo bench -p kcptun-kcp --bench kcp   -- --noplot
cargo bench -p kcptun-kcp --bench fec   -- --noplot
cargo bench -p kcptun-kcp --bench rs    -- --noplot

# micro-benchmarks: Go, against the pinned reference
cd tools/govectors && env GOMODCACHE=$PWD/../../reference/gomod GOFLAGS=-modcacherw \
    GOTOOLCHAIN=local go test -run '^$' -bench . -benchtime 1s ./...

# the two loopback end-to-end harnesses
KCPTUN_BENCH_REPEAT=5 cargo test -p kcptun-interop-tests --release \
    --test kcp_echo_bench -- --ignored --nocapture      # session.md
cargo build --release -p kcptun-interop-tests --bin kcptun-smuxecho   # smux.md

# the lab grid (needs a Linux host; tools/lab/README.md has the safety rules)
tools/bench/bench.py run    <campaign.json>
tools/bench/bench.py report <run-directory>          # regenerates a dated page and its CSV
tools/lab/matrix.sh --host <host> --configs s1 --profiles "clean lan wan50 lossy2 lossy10 burst"

# the interop matrix
KCPTUN_INTEROP_MATRIX_OUT=docs/interop-matrix.md \
  cargo test -p kcptun-interop-tests --test interop_matrix -- --ignored --nocapture interop_matrix_full
```

The dated end-to-end pages and their CSVs are rebuilt from the collected run directories **without
re-running anything**, so the tables can be regenerated from the raw samples. The raw run
directories themselves are not in the repository, and the two 12.1 pages' directories no longer
exist on the machine that ran them, so those two can no longer be regenerated at all; the banner
and the socket-buffer row added to them in 12.1b were written by hand and say so.

Every page's method table now carries the host's `net.core.rmem_max`/`wmem_max`, and
`tools/bench/bench.py run` refuses to start a campaign whose `-sockbuf` a stock ceiling would
shrink. Their absence is what let the withdrawn S1 rows out.

---

## Sources

| Document | What it holds |
|---|---|
| [`2026-09-24-lab-x86-1-netns-clean-s1-sockbuf.md`](2026-09-24-lab-x86-1-netns-clean-s1-sockbuf.md) | **the current S1 grid on 1 vCPU x86_64**, 60 runs, re-taken in 12.1b at a raised socket-buffer ceiling, with its full spread tables |
| [`2026-09-24-lab-x86-1-netns-clean.md`](2026-09-24-lab-x86-1-netns-clean.md) | the 12.1 grid on 1 vCPU x86_64, 120 runs. Its **`s1` half is withdrawn** under [D32](../DECISIONS.md) and carries a banner; its `s2` half is the S2 source above |
| [`2026-09-24-lab-x86-1-netns-clean-s2-control.md`](2026-09-24-lab-x86-1-netns-clean-s2-control.md) | the one-cell control that established the `s2` half survives the raised ceiling, 20 runs |
| [`2026-09-24-lab-arm64-netns-clean.md`](2026-09-24-lab-arm64-netns-clean.md) | the same grid on 2 vCPU aarch64, 120 runs |
| [`memory.md`](memory.md) | every memory measurement, both harnesses, the mesh arithmetic and the allocator comparison |
| [`micro.md`](micro.md) | the micro-benchmark index, and what each page is not evidence for |
| [`crypto.md`](crypto.md) · [`fec.md`](fec.md) · [`kcp.md`](kcp.md) · [`session.md`](session.md) · [`smux.md`](smux.md) | per-layer benchmarks |
| [`../lab-results/11.2-netem-matrix.md`](../lab-results/11.2-netem-matrix.md) | the impairment matrix: what each cell showed and what the host had to do with it |
| [`../lab-results/11.3b-wan-matrix.md`](../lab-results/11.3b-wan-matrix.md) | the provenanced real-path session (95 ms): the one to quote |
| [`../lab-results/11.3-wan-matrix.md`](../lab-results/11.3-wan-matrix.md) | the earlier real-path session (131 ms), superseded as evidence by its provenance caveat |
| [`../lab-results/11.4-soak.md`](../lab-results/11.4-soak.md) | the six-hour soak and the controlled allocator comparison |
| [`../interop-matrix.md`](../interop-matrix.md) | Go and Rust interop, per platform, with the exact binaries |
| [`../DECISIONS.md`](../DECISIONS.md) | every architecture decision (D-xx) and behaviour deviation (V-xx), with its evidence |
