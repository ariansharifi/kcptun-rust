# Memory: Rust vs Go (plan 12.3)

The user's question: *"you reckon this implementation with rust use less ram?"* Their mesh on
lab-arm64 runs **27 Go clients averaging 18.5 MB RSS and 3 Go servers averaging 17.2 MB, about
552 MB in total**.

**Short answer: yes for the part that makes up that 552 MB, and by a lot — but not everywhere.**

| | Rust | Go | |
|---|---:|---:|---|
| Idle client RSS | **1.71 MB** | 16.73 MB | Rust 9.8× smaller |
| Idle server RSS | **2.78 MB** | 17.23 MB | Rust 6.2× smaller |
| Per idle stream | **4.6 kB** | 22.5 kB (client) / 31.0 kB (server) | Rust 5–7× smaller |
| Per idle KCP session (client) | 698 kB (§3) · 435 → **55 kB** glibc / 595 → 455 kB musl (§7) | 243 kB | **two harnesses — do not subtract across them** (§7); on glibc 4.4× smaller than Go while the sessions are a process's first |
| Per idle KCP session (server) | **102 kB** | 166 kB | Rust 1.6× smaller |
| Peak (`VmHWM`) after 512 MB each way | **~100 MB** | ~135 MB | Rust 26% lower |
| RSS 4 min after that load stops | 100 MB (**unchanged**) | 57–73 MB (**still falling**) | **Go wins** |

The last row is what §1–§5 measured, and it is the one the port had to fix: Rust's floor was far
lower and its peak was lower, but a Rust process **did not give the peak back** — with musl or
with glibc — and a Go process does.

**§6 (sub-step 12.3b) closes it.** A heap profile shows the program had already freed 85 % of the
peak and the allocator had simply never been asked for it. With the fix, and built against glibc,
the same burst goes **132.6 MB → 6.7 MB within two minutes**, faster and further than Go's
scavenger. Built against **static musl it still does not**, because musl's mallocng has no trim
entry point at all — and mimalloc, measured, does not rescue it. That turns the last row into a
**build choice**, which is what D07 now has to decide; §6 has the table.

Read §6 together with **§6.1**: review found that the first version of the "is the process quiet?"
test could never have fired in the real binaries, because smux keepalives keep the byte counters
moving forever, and the probe that produced §6's table had no smux layer to show it. The rule was
corrected and the correction measured; §6.1 has the A/B and says exactly which of §6's numbers
cover which layer.

**§7 (sub-step 12.3c) closes the other one**, the 698 kB per idle client session that §3 left with
~300 kB unexplained. A heap profile says the batch was never the *allocation* problem it looked
like — kcp-go allocates the same 256 × 1500 B — it was that Rust made every byte of it **resident**
on a session that had never received a datagram, where Go's allocator leaves fresh pages untouched.
One contiguous allocation restores Go's behaviour at Go's batch size: **435 kB → 55 kB per session
on glibc**, against Go's 243 kB, at no throughput cost. On static musl it only goes 595 → 455 kB,
because mallocng memsets every `calloc` at every size — a third reason to read D07 as recommending
glibc. Those before/after pairs are **§7's single-process staircase, not §3's two-process fit**:
the same quantity reads 595 kB on musl where §3 read 698 kB, so the two harnesses' numbers must
not be subtracted from one another (§7 says why, and the caveats repeat it).

And the glibc win has a limit that §7 measures: it is the *first* generation of sessions that is
cheap. Once a client has replaced a session — an error, `-autoexpire`, the 600 s scavenger — glibc
stops handing the replacement batch a fresh mapping, and the steady state is ~375 kB per session
again. macOS keeps the win through churn; musl never had it.

## Methodology

- **What is measured.** `VmRSS`, `VmHWM`, `RssAnon` and `RssFile` from `/proc/<pid>/status`, plus
  `Threads`. `RssAnon` is the heap and stacks; `RssFile` is mostly the binary's own text and data
  pages, which is why it is reported separately — the Go binaries are 16.6 MB and the Rust ones
  2.4 MB, and that difference is real RSS but it is shared between processes of the same binary.
  Nothing here samples the kernel's socket buffers (`-sockbuf`), which are not part of RSS.
- **Both sides are ours.** The user's live containers were never touched, measured or compared
  against. Every number below comes from a Go process and a Rust process that this session started,
  with byte-identical flags, on the same host, interleaved A/B within every round.
- **Profile: S1 "production"**, taken from step 12 (scenario S1) and identical to
  `production_case()` in `crates/interop-tests/src/interop_matrix.rs`:

  ```
  common: -mode normal -crypt xor -mtu 1390 -sndwnd 8192 -rcvwnd 8192 -smuxver 2
          -smuxbuf 16777216 -streambuf 16777216 -datashard 0 -parityshard 0 -nocomp -quiet
  client: -conn 4 -sockbuf 8388608
  server: -sockbuf 67108868
  ```
- **Topology.** Everything on lab-arm64, loopback only (LAB.md §2.4 ports):

  ```
  loader/holder --TCP--> client 127.0.0.1:12948 (Rust) / :12949 (Go)
                         --UDP--> server 127.0.0.1:29901 (Rust) / :29902 (Go)
                         --TCP--> sink 127.0.0.1:22500
  ```

  Separate port pairs per implementation so an interleaved round can never collide. The sink is a
  small `python3` TCP server started once per session; a connection that sends nothing is simply
  held open (that is how an *idle* stream is made), a connection that sends `UP <n>` is drained and
  acked after exactly *n* bytes, and one that sends `DN <n>` is served *n* bytes. The ack protocol
  carries the byte count up front so that **no half-close is involved anywhere**, and the Go and the
  Rust client are therefore exercised identically (V11 never comes into play).
- **Starting and stopping.** Only the sanctioned lab helpers (`tools/lab/deploy.sh`,
  `tools/lab/lab.sh` → `~/kcptun-lab/scripts/lab-*.sh`). Every process has a PID file and is stopped
  by PID after `/proc/<pid>/exe` is verified. The `python3` helpers run through a copy of the
  interpreter at `~/kcptun-lab/bin/kr-python`, because `lab-stop.sh` compares `/proc/<pid>/exe`
  against the recorded path and `/usr/bin/python3` resolves to `/usr/bin/python3.12`. The only
  direct `ssh` use is read-only: `grep -E '^(VmRSS|VmHWM|RssAnon|RssFile|VmSize|Threads):'
  /proc/$p/status` and `/proc/loadavg`.

  A round is driven from the laptop like this (one implementation shown):

  ```sh
  tools/lab/lab.sh start sink  -- '$HOME/kcptun-lab/bin/kr-python' \
      '$HOME/kcptun-lab/tmp/labmem.py' sink --port 22500
  tools/lab/lab.sh start m-srv -- '$HOME/kcptun-lab/bin/rust/kr-server' \
      -l 127.0.0.1:29901 -t 127.0.0.1:22500 -key labkey \
      -mode normal -crypt xor -mtu 1390 -sndwnd 8192 -rcvwnd 8192 -smuxver 2 \
      -smuxbuf 16777216 -streambuf 16777216 -datashard 0 -parityshard 0 -nocomp -quiet \
      -sockbuf 67108868
  tools/lab/lab.sh start m-cli -- '$HOME/kcptun-lab/bin/rust/kr-client' \
      -l 127.0.0.1:12948 -r 127.0.0.1:29901 -key labkey \
      -mode normal -crypt xor -mtu 1390 -sndwnd 8192 -rcvwnd 8192 -smuxver 2 \
      -smuxbuf 16777216 -streambuf 16777216 -datashard 0 -parityshard 0 -nocomp -quiet \
      -conn 4 -sockbuf 8388608
  # ... sample /proc, then add idle streams:
  tools/lab/lab.sh start m-h0  -- '$HOME/kcptun-lab/bin/kr-python' \
      '$HOME/kcptun-lab/tmp/labmem.py' hold --port 12948 --n 4
  # ... or drive a load:
  tools/lab/lab.sh start m-ld  -- '$HOME/kcptun-lab/bin/kr-python' \
      '$HOME/kcptun-lab/tmp/labmem.py' load --port 12948 --streams 4 \
      --bytes 134217728 --dir up
  tools/lab/lab.sh stop m-h0 m-ld m-cli m-srv
  ```

  The Go rows are the same commands with `bin/go/kg-{client,server}` and ports 12949/29902.
- **Rounds.**
  - *Profile rounds* (**5 rounds**, R/G interleaved): start the pair, sample the idle RSS at
    t = 5, 30, 60 and 120 s, then hold 4 idle TCP connections (→ 4 KCP sessions + 4 smux streams,
    15 s), then 32 more (36 streams, 15 s), then 64 more (100 streams, 20 s).
  - *conn=16 rounds* (**3 rounds**): the same with `-conn 16` and 16 held connections, to get a
    second point on the session axis.
  - *Load rounds* (**2 rounds**): idle for 60 s, then 4 streams × 128 MB **up** (client → server),
    then 4 streams × 128 MB **down**, then idle samples at +10, +30, +60, +120 and +240 s.
  - *Allocator rounds* (**1 round each**, musl and glibc): one load round with the decay sampled to
    +600 s.
  - Every table below is a **median**; the sample count is in the `n` column or stated in the text.
- **Machines.**
  - lab-arm64: **Neoverse-N1, 2 vCPU**, 11.9 GB RAM, Ubuntu 24.04.4 (kernel 6.17.0-1020-oracle),
    4 KiB pages, THP `madvise`. Shared with the host's production services.
  - `uptime` was checked before every round and recorded with every sample. **Load average over the
    whole session: 0.01 to 1.67**, and below 1.0 for every idle and slope measurement; the only
    values above 1.0 are during Go's own load transfers (Go's runs pushed the box harder because
    they took longer, see *Under load*). The box was never saturated by anything but our own runs.
  - Laptop (build host only): Apple M5, macOS 27.0.
- **Binaries.**
  - **Rust:** `cargo zigbuild --release -p kcptun-client -p kcptun-server --target
    aarch64-unknown-linux-musl` (rustc 1.98.1; release profile = `opt-level 3`, fat LTO, 1 CGU,
    `panic = abort`, stripped), deployed as `kr-client` / `kr-server`, 2,504,888 and 2,499,000
    bytes. Tree at `e34fb56` with no local modifications.
  - **Go:** the pinned reference `kcptun v0.0.0-20260208051026-39935d5307f0` (kcp-go v5.6.66, smux
    v1.5.55), built by `tools/fetch-reference.sh` with
    `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -mod=vendor -trimpath` on Go 1.27.1, deployed
    from `reference/bin/{client,server}_linux_arm64` as `kg-client` / `kg-server`, 17,458,508 and
    17,383,900 bytes.
  - No `GOGC`, `GOMEMLIMIT` or `GOMAXPROCS` was set for Go; no allocator tuning for Rust. Both saw
    the same 2 CPUs.
- **⚠ Allocator.** **mimalloc is not wired in.** `mimalloc` appears only in the workspace dependency
  table of the root `Cargo.toml`; no crate depends on it and there is no `#[global_allocator]`
  anywhere in `crates/`. Every Rust number here is therefore the **musl system allocator**
  (mallocng) for the musl rows and **glibc 2.39 malloc** for the two glibc rows. D07 is still
  *Proposed*, and Step 12.3 may move all of these numbers.

## Results

### 1. Idle RSS — the number that maps onto the mesh

`-conn 4`, no connection ever made, so **zero KCP sessions and zero streams**. Median of 20 samples
(5 rounds × 4 sample times); the spread across all 20 was under 0.1 MB for every cell.

| | Rust RSS | Go RSS | ratio | Rust anon | Go anon | Rust file | Go file | Rust thr | Go thr |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| client | **1.71 MB** | 16.73 MB | **9.8×** | 0.16 MB | 8.14 MB | 1.55 MB | 8.59 MB | 3 | 7 |
| server | **2.78 MB** | 17.23 MB | **6.2×** | 0.80 MB | 8.21 MB | 1.97 MB | 9.02 MB | 3 | 7 |

Two things worth separating:

- **Heap and stacks (`RssAnon`): 0.16 MB vs 8.14 MB on the client, 51×.** A freshly started Go
  kcptun process has already committed ~8 MB of heap — the runtime's arenas, the scheduler, the
  GC's own structures, and goroutine stacks.
- **File-backed (`RssFile`): 1.55 MB vs 8.59 MB.** This is the resident part of the binary itself.
  It is genuine RSS, but the page cache shares it between processes running the *same* binary, so
  in the 27-client mesh it is paid roughly **once**, not 27 times. The honest per-process saving to
  carry forward is therefore closer to the anonymous difference (~8 MB/process) plus a one-off
  ~7 MB, rather than the full 15 MB × 27.

This Go idle floor is a good sanity check on the whole exercise: **16.73 MB and 17.23 MB against
the production mesh's averages of 18.5 MB and 17.2 MB.** The same binary, the same flags, the same CPU.

### 2. How long "settled" takes

Both implementations reach their idle RSS immediately and then do not move:

| impl | role | t=5 s | t=30 s | t=60 s | t=120 s |
|---|---|---:|---:|---:|---:|
| Rust | client | 1.71 | 1.71 | 1.71 | 1.71 |
| Rust | server | 2.78 | 2.78 | 2.78 | 2.78 |
| Go | client | 16.73 | 16.73 | 16.73 | 16.73 |
| Go | server | 17.23 | 17.23 | 17.23 | 17.23 |

(MB, medians of 5 rounds.) There is nothing to wait for at startup: PBKDF2 key derivation is done
before the listener opens, and an idle process allocates nothing afterwards. **60 s is the settle
time used for every other measurement**, which is 60 s more than these numbers need — it was chosen
so that a Go GC cycle (the runtime forces one every 2 minutes when otherwise idle) could not land
inside a sample window unnoticed. It never changed a reading.

### 3. Per-session and per-stream cost

Each held TCP connection creates one smux stream; the first `-conn` of them each create a new KCP
session as well (kcptun's round-robin fills the `muxes` slots before reusing them), so `hold4` with
`-conn 4` is *4 sessions + 4 streams* and `hold100` is *4 sessions + 100 streams*.

Median RSS in MB, 5 rounds (profile) / 3 rounds (conn=16):

| phase | Rust client | Go client | Rust server | Go server |
|---|---:|---:|---:|---:|
| idle (0 sessions) | 1.71 | 16.73 | 2.78 | 17.23 |
| 4 sessions + 4 streams | 5.14 | 18.84 | 3.47 | 18.11 |
| 4 sessions + 36 streams | 5.29 | 19.62 | 3.61 | 19.70 |
| 4 sessions + 100 streams | 5.57 | 20.95 | 3.91 | 21.01 |
| 16 sessions + 16 streams | 13.37 | 21.95 | 4.73 | 20.38 |

From those, fitting `ΔRSS = F + n·(session) + m·(stream)` over the two session counts (4 and 16) and
the 4→100 stream sweep:

| slope | Rust client | Go client | Rust server | Go server |
|---|---:|---:|---:|---:|
| per idle **stream** | **4.6 kB** | 22.5 kB | **4.7 kB** | 31.0 kB |
| per idle **session** | 698 kB | **243 kB** | **102 kB** | 166 kB |
| fixed cost of the first sessions | 699 kB | 1101 kB | 281 kB | 117 kB |

- **Streams: Rust wins by 5–7×**, and this is D17 working as designed — a proxied connection that
  is idle holds no copy buffer, where Go holds two goroutines and a 32 KiB `io.Copy` buffer for the
  life of the connection. At 100 streams the Go server has spent 3.1 MB on stream state and the
  Rust server 0.47 MB.
- **Client sessions: Rust loses by 2.9×, and this is the one place the port is clearly worse.**
  698 kB per session is a lot. The largest identified single contributor is the per-session receive
  batch: `ReadLoop::run` (`crates/kcp/src/session.rs:1469`) allocates `RecvSlot::batch(BATCH_SIZE)`
  = 256 slots × `MTU_LIMIT` 1500 B = **384 kB**, plus the `recvmmsg` `msghdr`/`iovec`/`sockaddr`
  arrays (~52 kB), all touched at allocation. kcp-go allocates the *same* 256 × 1500 batch per
  session in `readloop_linux.go:57`, so this is not a porting difference in itself — yet Go's
  measured slope is only 243 kB, i.e. **less than the batch it allocates**, presumably because the
  GC is returning other memory over the same interval. **The remaining ~300 kB of the Rust slope
  was not bisected** — that would need a heap profile (`dhat`/heaptrack), which this session did
  not run. Do not read the 384 kB attribution as a complete explanation.
  **→ §7 ran that profile.** The guess in the last sentence was wrong in an instructive way: Go's
  slope is smaller than its own batch because Go never *touches* the batch, and the ~300 kB was
  not a mystery allocation but the rest of the batch plus 36 kB of real session state. Fixed in
  12.3c — but read the number there, not a subtraction from this one: §7 measures the same
  quantity with a single-process staircase, on which this row's musl build reads 595 kB rather
  than 698 kB, and 55 kB after the fix on glibc (§7 and caveat 0).
- **Server sessions: Rust wins** (102 vs 166 kB), because the server side shares one listener
  socket and one receive batch across all sessions instead of one per session.
- The two session points (4 and 16) are a two-point fit, not a curve. Whether the slope stays
  linear at hundreds of sessions was **not measured**.

### 4. Under load, and whether it comes back

4 streams × 128 MB up (client → server), then 4 streams × 128 MB down; 512 MB in each direction.
Median of 2 rounds, RSS in MB:

| phase | Rust client | Go client | Rust server | Go server |
|---|---:|---:|---:|---:|
| idle | 1.71 | 16.74 | 2.78 | 17.25 |
| after the **up** transfer | 94.86 | 101.26 | 17.63 | 75.53 |
| after the **down** transfer | 99.88 | 134.37 | 101.55 | 135.80 |
| +10 s | 99.88 | 134.37 | 101.55 | 135.88 |
| +30 s | 99.88 | 134.38 | 101.55 | 135.96 |
| +60 s | 99.88 | 134.38 | 101.55 | 136.08 |
| +120 s | 99.88 | **100.61** | 101.55 | **111.20** |
| +240 s | 99.88 | **73.44** | 101.55 | **57.11** |
| **peak `VmHWM`** | **99.88** | 134.15 | **101.61** | 136.60 |

- **Rust's peak is 26% lower** than Go's in both roles, and the Rust server never even reaches
  20 MB while receiving 512 MB (the Go server reaches 76 MB on the same transfer).
- **Rust does not release. At all.** Not one page, over four minutes, in either role, in either
  round — the client sits at exactly 99.88 MB and the server at exactly 101.55 MB from the moment
  the transfer ends. Note the streams are *closed* by then; only the four KCP sessions remain.
- **Go does release**, on the Go runtime's schedule: nothing for the first 60 s, then the scavenger
  starts returning pages, and by +240 s the Go processes are at **73 MB and 57 MB — below Rust**,
  and still falling. Where Go would have settled was **not measured**; the 240 s window is too
  short, and the Go curve had clearly not finished.
- So on this axis **Go wins outright after about three minutes of idling**, and it is a real
  operational difference: a Rust process that has once handled a burst keeps that RSS until it is
  restarted, while a Go process gives most of it back.

That ~100 MB is not a leak, it is the configured budget: S1 sets `-smuxbuf 16777216` and
`-streambuf 16777216` (16 MB each) and an 8192-packet window, so 4 sessions × 4 streams can legally
buffer this much in flight. The question is only whether it is handed back afterwards.

#### Is it the allocator, or is it us?

One extra round each, same load, decay sampled out to **+600 s**, with the Rust binaries rebuilt
against glibc (`tools/lab/deploy.sh --rust --gnu`, target `aarch64-unknown-linux-gnu`, glibc 2.39)
and compared with the musl build under the same driver:

| | musl (mallocng) | glibc 2.39 |
|---|---:|---:|
| idle client / server | 1.71 / 2.79 MB | 3.33 / 4.27 MB |
| after up (client / server) | 95.68 / 13.39 MB | 69.95 / 9.43 MB |
| after down (client / server) | 101.33 / 98.02 MB | **70.02 / 60.30 MB** |
| +30 s | 101.33 / 98.02 | 70.02 / 60.30 |
| +120 s | 101.33 / 98.02 | 70.02 / 60.30 |
| +300 s | 101.33 / 98.02 | 70.02 / 60.30 |
| +600 s | 101.33 / 98.02 | 70.02 / 60.30 |
| loader throughput up / down | 766 / 782 Mbit/s | 946 / 880 Mbit/s |

Two findings:

- **The peak is very allocator-dependent.** The glibc build peaks **30–39% lower** than the musl
  build on exactly the same work (70.0 vs 101.3 MB client, 60.3 vs 98.0 MB server) and moves the
  data ~20% faster, at the cost of a ~1.6 MB higher idle floor. musl's mallocng is the weakest part
  of the shipped musl binary's memory profile. This is a direct input to D07 — and it says the
  allocator question is worth more than the ~300 kB of unattributed per-session cost.
- **Neither allocator gives the memory back.** Both are flat to the byte for ten minutes. So the
  retention is **not** a musl quirk; it is either program-level retained capacity (pools, grown
  ring buffers, smux stream buffers) or the behaviour both allocators share of keeping freed arenas
  mapped. This measurement **cannot separate those two**, and separating them is the first thing
  the 12.3 fix needs (a heap profile, or an explicit `malloc_trim`/`mi_collect` probe, would
  answer it immediately).

### 5. Side note: throughput

Not a throughput benchmark — one loopback path, a Python loader, 2 shared vCPUs — but the loader's
own numbers are worth one line because they set the context for the load rows above:

| | up | down |
|---|---:|---:|
| Rust | 770, 817 Mbit/s | 786, 761 Mbit/s |
| Go | 503, 518 Mbit/s | 242, 240 Mbit/s |

Both rounds shown. Go took 17.8 s to move the 512 MB down where Rust took 5.5 s, which is also why
the Go load rows were taken at a higher system load average (1.5–1.7 vs 0.5–0.6).

## 6. 12.3b — which of the two causes it was, and what now gives the memory back

§4 could not say whether the retained ~100 MB was **(a)** capacity the program still holds or
**(b)** free memory the allocator keeps mapped. A heap profile answers it in one reading.

### Method

`crates/interop-tests/src/bin/memprobe.rs`, built twice from the same source:

- **plain** — overrides no allocator, so its RSS is the honest production number;
- **`--features dhat`** — installs `dhat::Alloc`, whose `curr_bytes` *is* the live heap, and writes
  `dhat-heap.json` with per-call-site attribution. `--dump-at-close` ends the run while the
  sessions are still alive, so dhat's "at t-end" snapshot is exactly the retained state.

The workload is §4's, at the KCP layer and inside one process: `-crypt xor -mtu 1390 -sndwnd 8192
-rcvwnd 8192 -mode normal`, an echo listener and `--sessions 4` dialled sessions, each echoing
`--bytes`, so every byte crosses the link twice as §4's "up then down" does. One process holding
both endpoints is **not** comparable to §4's two-process RSS figures — it is a little over twice
one of them — but the *shape* (peak, what comes back, when) is the same and is what is at issue.
`--sessions 4 --bytes 134217728` is 512 MB in each direction, as in §4.

### The answer: it is the allocator, by 85 %

Laptop (M5, macOS), `--bytes 16777216 --dump-at-close`, dhat build:

| | live heap | RSS |
|---|---:|---:|
| idle, listener up, no session | 0.53 MB | 7.12 MB |
| peak of the burst (dhat's `t-gmax`) | **78.28 MB** | 103.54 MB |
| every stream closed, sessions still up | **11.72 MB** | **103.54 MB** |

**The program had already given up 85 % of the peak, and RSS had not moved by a single page.**
That is cause (b), and it is most of the problem. It also explains §4's glibc round: changing the
allocator changed the peak by 30–39 % and the *release* not at all, because both allocators were
being asked for nothing.

The 11.72 MB that is genuinely still live is cause (a), and dhat names it (8 sessions: 4 dialled,
4 accepted):

| still live | blocks | site |
|---:|---:|---|
| 3.66 MB | 8 | `RingBuffer::grow` — `snd_buf`, `snd_queue`, `rcv_queue` grown to the 8192 window |
| 2.43 MB | 8 | `SegmentHeap::push` — `rcv_buf`, the out-of-order receive heap |
| 2.99 MB | ~2000 | `BufferPool::get` — the process-wide 2048 × 1500 B packet pool |
| 2.10 MB | 4 | the probe's own echo buffers — harness, not the port |

So cause (a) is **≈1.1 MB per live session plus ≈3 MB once for the pool**, which is the same order
as §3's unexplained ~300 kB per client session — but it is not the answer to it, because this is a
*live* session's growth under traffic and §3's slope was measured on held, idle sessions; §7
answers §3's question. `RingBuffer` never shrinks, and neither does `rcv_buf`.

### What changed in the port

Three things, all in `kcptun_kcp::memory` and its callers, none of them a flag:

1. **`UdpSession::shrink_idle`**, called by each session's own update task every 30 s, gives back
   an *empty* KCP ring, an empty `rcv_buf`, an empty `acklist` and a fully consumed `recvbuf`.
   Only structures that are empty **at this instant** are released, so nothing received but not
   read is ever disturbed. That is weaker than "only idle sessions are touched", and the
   difference is worth knowing: `rcv_queue` is drained completely by every `recv`, and `recvbuf`
   is fully consumed at most instants between reads, so a session running at full rate whose 30 s
   tick lands on one of those moments gives its 8192-slot array back and regrows it — a few
   reallocations and roughly half a megabyte of `Segment` moves, per session, at most once per
   30 s. That is negligible against the transfer causing it (well under 2 MB/s of memcpy even at
   108 sessions) but it is capacity oscillation under load, not an idle-only change.
   `snd_queue`/`snd_buf` are empty only once everything sent has been acknowledged, so those
   really are released only between bursts.
2. **`BufferPool::trim`**, which drops the parked packet buffers to 64 (96 kB). This is what a Go
   GC cycle does to a `sync.Pool` for free.
3. **`memory::trim_when_idle`**, one task per process, which runs (2) and then **asks the
   allocator to hand its free pages back** — `malloc_trim(0)` on glibc, `mi_collect` with the
   `mimalloc` feature (plus `memory::on_thread_park`, because `mi_collect` only ever collects the
   calling thread's heap), and *nothing at all* on musl, whose mallocng has no such entry point.
   It fires when the KCP byte counters have moved **no more than 64 kB** across a whole 30 s tick
   and at least 1 MB has moved since the last trim, so an idle process does two subtractions per
   tick and a busy one does nothing at all. The 64 kB rather than zero is not slack: see §6.1.
   **This half is process-wide and all-or-nothing**: it reads the global `DEFAULT_SNMP` counters,
   so it fires only when the *whole* process is quiet for a tick. Go's scavenger has no such
   condition — it returns pages from a Go server that is busy on 26 of its 27 tunnels. A Rust
   **server** in the production mesh aggregates 9 clients, so as long as any one of them moves more
   than 64 kB in a 30 s tick the server never trims and keeps its high-water mark, even though the
   sessions that produced the peak have long gone idle. Per-session shrinking (1) still runs. This
   case is **unmeasured** — everything in §6/§6.1 is a single-workload process that goes fully
   quiet — see caveat 14.

### Does it work? (lab-arm64, S1, 512 MB each way)

One run per build:

```sh
# on lab-arm64, from ~/kcptun-lab/tests/bench/, one line per build
./memprobe --sessions 4 --bytes 134217728 --auto-trim --decay 180 --interval 30
```

`--auto-trim` is what spawns `memory::trim_when_idle`, the task the shipped binaries run; without
it the only trim in the run is the explicit one the probe calls after the decay, and the "+2 min"
column would be meaningless. So every row below carried it **except** the second one, "whole idle
trim disabled", which is the same command with `--auto-trim` left off and is there to show what
the process does without the task — whatever the earlier draft of this section said.

**Reproducibility gap, stated rather than papered over.** That earlier draft quoted the flags as
`--decay 120..180`, which is not something `--decay` parses (it takes one integer), and it omitted
`--auto-trim`; the per-build `--decay` value was recorded only as "somewhere between 120 and 180"
and cannot now be recovered per row. The decay length does not change the conclusion — every build
here is flat from its second decay sample onwards, so a 120 s and a 180 s run end in the same place
— but it does mean the burst times and peaks below are not exactly re-runnable. The next round
must record the literal command per row; step 12's rule #2 asks for it.

Load average was under 0.6 at the start of every round except the `gnu-mi` one (1.49). Every build
below carries the fix; they differ only in the allocator.

RSS in MB, sampled every 30 s. **"idle", "peak", "at close" and "+2 min" come from the run's own
`--auto-trim` ticks** — no explicit trim has happened by then — and **"end of run" is the last
sample, after the probe has called `memory::trim()` once by hand** (`after-trim+5s`). So the gap
between the last two columns is what an explicit trim adds on top of what the process does by
itself.

⚠ These rows are **raw-KCP** numbers: `memprobe` had no smux mode when they were taken, so the
`-smuxbuf`/`-streambuf` buffers, the token bucket and the keepalive are all absent. That does not
move the allocator conclusion — the retained bytes are the allocator's either way — but it is
exactly what hid the bug in §6.1, and it means these are not the shipped binaries' numbers. See
§6.1 and caveat 13.

| build | idle | peak `VmHWM` | at close | +2 min | end of run | burst |
|---|---:|---:|---:|---:|---:|---:|
| musl + system (what ships today) | 1.59 | 169.6 | 164.9 | 164.0 | 160.4 | 10.9 s |
| musl + system, **whole idle trim disabled** | 1.59 | 183.2 | 178.2 | 173.4 | 173.4 | 11.0 s |
| **glibc 2.39 + system (`malloc_trim`)** | 2.88 | 132.6 | 124.0 | **6.70** | **4.36** | 10.5 s |
| ~~musl + mimalloc v3~~ **void** | 1.66 | 169.1 | 164.1 | 162.8 | 159.7 | 10.4 s |
| ~~musl + mimalloc v3, `MIMALLOC_PURGE_DELAY=0`~~ **void** | 1.60 | 177.9 | 173.1 | 172.1 | 168.7 | 10.6 s |
| ~~musl + mimalloc **v2**~~ **void** | 1.62 | 173.6 | 168.9 | 168.3 | 164.5 | 10.5 s |
| ~~glibc + mimalloc v3~~ **void** | 3.12 | 135.5 | 129.6 | 113.2 | 113.3 | 10.4 s |

⚠ **The four `mimalloc` rows are void: they are system-allocator runs.** Review found that
`memprobe` had no `#[global_allocator]` of its own, so `--features mimalloc` linked the crate,
turned on `kcptun-kcp/mimalloc` (and therefore the `mi_collect` call and `on_thread_park`) — and
left the process allocating through mallocng or glibc exactly as the plain build does. Only a
`#[global_allocator]` static replaces `malloc`, and `kcptun-client`/`kcptun-server` have one while
the probe did not. The numbers are self-consistent with that reading: `musl + mimalloc` 169.1
against `musl + system` 169.6 is noise, and `MIMALLOC_PURGE_DELAY=0` moved nothing because that
variable is inert without mimalloc. The rows are kept struck through rather than deleted, so that
anything quoting them can be traced. `memprobe` now carries the allocator and §6.2 is the re-run;
**it reverses the "mimalloc does not release" conclusion.** The `musl + system`, `trim disabled`
and `glibc + system` rows are unaffected — none of them ever set the feature.

- **glibc gives everything back, and faster than Go.** 132.6 MB peak to **6.7 MB at +120 s and
  4.36 MB after an explicit trim** — below the process's own idle floor plus its sessions, and far
  below Go's 57–73 MB at +240 s (§4). The whole drop happens on the first tick the trimmer calls
  quiet, which in *this* harness is the first tick after the burst. §6.1 is about what "quiet"
  has to mean for that also to be true of a real client.
- **musl still cannot release**, because there is nothing to call. The per-session shrink and the
  pool trim run there too and give back a few MB over a few minutes, which is real and is not the
  answer. Note what the second row does and does not isolate: `--auto-trim` only switches the
  *process-wide* task on and off, while the per-session shrink is unconditional in the product, so
  the 183.2 vs 169.6 MB peaks are run-to-run variance (the first trim tick falls well after the
  burst has ended and cannot move a peak), and the honest reading of that row is only its flat
  tail.
- ~~**mimalloc does not release either.**~~ **Wrong, and withdrawn** — see the warning above and
  §6.2. What those rows measured was the system allocator with `mi_collect` being called on an
  empty mimalloc heap. With mimalloc actually installed it releases about half the peak on musl.
- ⚠ **The `glibc + mimalloc v3` row is stale for a second, independent reason.** When it was taken,
  `release_to_os`
  had the glibc `malloc_trim` arm gated on `not(feature = "mimalloc")`, so turning the feature on
  *removed* the only call that works — which is why that row releases 16 % where the row above it
  releases 95 %. Review flagged the gate as a footgun in its own right (Cargo unifies features
  across a workspace, so one crate or `--all-features` CI could have taken `malloc_trim` away from
  a binary that was not even using mimalloc), and the arms are now independent: a glibc build calls
  `malloc_trim` whether or not mimalloc is linked. So that row is doubly void: the wrong allocator
  *and* the trim suppressed. §6.2 replaces it.

## 6.1. The keepalive that made all of the above dead code

Review caught this after the table above was written, and it is the most important thing in §6.

`memory::trim_when_idle` decides the process is quiet by looking at the SNMP byte counters. The
first version asked whether they were **exactly equal** across a 30 s tick. In `memprobe` as it
then was, they were: the probe drives raw `kcptun-kcp` sessions with nothing above them, so once
the burst ends not one byte moves and the very next tick trims.

**In the shipped binaries they are never equal.** smux sends an unconditional 8-byte `cmdNOP`
keepalive per session every `-keepalive` seconds (default 10) for as long as the session lives
(`crates/smux/src/session.rs:keepalive`, Go `smux@v1.5.55 session.go:keepalive()`); each one goes
through `UdpSession::write` and bumps `DEFAULT_SNMP.bytes_sent`, and the peer's NOPs bump
`bytes_received`. The review that found this measured it straight off the release
`kcptun-client`/`kcptun-server` pair over loopback with S1 flags, `-conn 4`, one held idle TCP
connection and `-snmplog … -snmpperiod 5`: BytesSent 17, 17, 25, 25, 33, 33, 41, 41 and
BytesReceived 16, 16, 24, 24, 32, 32, 40, 40 — **+8 B every 10 s per live session, forever.** The
A/B below reproduces the same thing from the other end, inside a probe that now has a smux layer.

So on a real client the byte-for-byte test could never be satisfied, and the process-wide half of
12.3b — the `malloc_trim(0)` that is 85 % of the retained RSS and the whole 132.6 → 6.70 MB
headline — would simply never have run. And it would never have run in exactly the case the
sub-step exists for: a client that has finished a burst and is still holding its `-conn` sessions,
which kcptun only scavenges after `-scavengettl` (600 s) and never if the session is reused.

### The fix

Quiet is now a **small delta** rather than no delta: `memory::QUIET_BYTES` = 64 kB per tick, with
`memory::REARM_BYTES` = 1 MB of traffic required since the last trim before another is due.

The gap either side of 64 kB is wide enough that the exact value does not matter. A 4-session
client's keepalive is 3 NOPs per session per 30 s tick in each direction — 192 B of counter
movement per tick, **341× below** the threshold, and it would take over 1300 sessions to reach it.
In the other direction 64 kB per 30 s is 17 kbit/s, about one MTU-sized packet every 0.6 s;
nothing that is moving data sits under that.

### The A/B

`memprobe` gained a `--smux` mode for this: the same burst wrapped in a `kcptun_smux` session with
S1's `-smuxbuf 16777216 -streambuf 16777216 -framesize 8192` and the default `-keepalive 10`,
streams closed at the end of the burst and the **sessions held open through the whole decay** —
the state a kcptun client is in between bursts. Two runs of the identical command, differing only
in the `IdleTrimmer::tick` rule compiled in:

```sh
./memprobe --smux --sessions 4 --bytes 8388608 --auto-trim --decay 95 --interval 30
```

Laptop (M5, macOS — no allocator trim exists there, so `pool_parked` is what shows whether the
trimmer fired at all; 2048 is a full pool, 64 is `IDLE_POOL_PARKED`):

| rule | +31 s | +61 s | +91 s | +121 s | explicit `trim()` at the end |
|---|---:|---:|---:|---:|---|
| counters exactly equal (before) | 2048 | 2048 | 2048 | 2048 | freed 1984 buffers — **the task never ran** |
| delta ≤ `QUIET_BYTES` (after) | 2048 | **64** | 64 | 64 | freed 0 — already done |

Four smux sessions were alive and keepalive-ing for every one of those samples (the run logs
`4 sessions held open`). The old rule trims on **no** tick; the new one trims on the first tick
after the burst and then leaves it alone, which is the intended behaviour.

### And on Linux, where the trim has something to call

macOS only shows whether the *task* fired. The number that matters is RSS on glibc, so §6's own
workload was re-run on lab-arm64 with the smux layer in it, against the corrected rule
(`aarch64-unknown-linux-gnu.2.39`, `cargo zigbuild`, same tree as this document; load average 0.30
before and 0.36 after; the binary was removed from the box afterwards):

```sh
./memprobe --smux --sessions 4 --bytes 134217728 --auto-trim --decay 180 --interval 30
```

| phase | RSS | pool parked |
|---|---:|---:|
| start / idle (listener up, no session) | 2.30 / 3.07 MB | 0 |
| burst end (512 MB each way, 8.6 s) | 117.25 MB, `VmHWM` **118.72 MB** | 2048 |
| streams closed, 4 sessions held | 117.26 MB | 2048 |
| +39 s — the tick before it had the burst in it | 114.11 MB | 2048 |
| **+69 s — first quiet tick** | **7.58 MB** | 64 |
| +99 s … +189 s | 7.58 MB, flat | 64 |
| explicit `trim()` at the end | 7.56 MB | 64 |

**93.6 % of the peak, returned 69 s after the burst, with four live smux sessions writing
keepalives the whole time.** That is the result §6's table claims and could not have demonstrated:
same shape, same one-tick drop, now through the layer the product actually runs. The remaining
7.58 MB is the four live sessions plus the 64-buffer pool, not a floor the trim failed to reach.

A **raw-KCP round was run back-to-back on the same box and tree** as a control, so §6's table and
this one can be compared without a day or a build between them:

| glibc round, same binary | peak `VmHWM` | first quiet tick | released |
|---|---:|---:|---:|
| raw KCP (§6's workload) | 132.18 MB | 5.47 MB at +72 s | 95.9 % |
| `--smux`, 4 sessions held | 118.72 MB | 7.58 MB at +69 s | 93.6 % |

The raw number lands on §6's `glibc 2.39 + system` row (132.6 MB peak) to within 0.3 %, which is
the check that this tree still behaves as that table says. The smux round peaks 10 % *lower* and
holds ~2 MB more afterwards; the extra 2 MB is the four sessions it still has open, and why the
peak is lower was **not** investigated — smux's receive-window accounting bounding what one
session will buffer, where raw KCP lets the 8192-packet window run, is a guess, not a measurement.

Two honest notes on both rows. They are one run each. And `memprobe --smux` is still one process
holding both ends with no TCP proxy, so it is not the two-process client/server split of §1–§5 —
caveat 13 says what is left.

### x86_64 cross-check (lab-x86-1)

`malloc_trim` is glibc code, not architecture-specific, but the whole recommendation rests on it,
so it was confirmed on the lab's only x86_64 machine. lab-x86-1 has **1 vCPU, 2 GB and a live Go
kcptun client on it** (LAB.md §1), so the burst there is deliberately small — 2 sessions × 16 MB,
64 MB in total, peaking at 44 MB — and the box's load average was 0.00 before and after:

| build (x86_64) | idle | peak | at close | +64 s | end of run |
|---|---:|---:|---:|---:|---:|
| **glibc 2.35 + system** | 1.79 MB | 44.05 MB | 42.02 | **3.44 MB** | 5.03 MB |
| musl + system | 1.27 MB | 60.08 MB | 57.56 | 56.33 | 56.33 |

Same shape as aarch64 in both directions: glibc is flat for the first tick and then hands the
whole burst back at once (92 %), musl gives back 6 % and stops; musl also peaks 36 % higher for
the same work, as it does on aarch64. So neither the release nor mallocng's overhead is an
architecture effect.

## 6.2. The allocator table, re-run with mimalloc actually installed

§6's four `mimalloc` rows were system-allocator runs (the warning under that table says why).
`memprobe` now installs the allocator itself —

```rust
#[cfg(all(feature = "mimalloc", not(feature = "dhat")))]
#[global_allocator]
static MIMALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;
```

— and the whole table was re-taken in **one round, back to back, on the same tree and box**, so
these five rows can be compared with each other cell for cell. They may **not** be compared cell
for cell with §6's, which is a different round: `musl + system` re-measures 18 % higher here
(200.2 MB against 169.6 MB) for the same command, which is the honest size of the peak's
run-to-run and day-to-day spread and is larger than §6's ±10 % caveat claimed.

Verified before running that the allocator is in the binary: `strings memprobe-musl-mi | grep
mimalloc` matches and `memprobe-musl-sys` does not; the probe's own idle RSS also jumps from
1.65 MB to 7.21 MB with the feature, which is the same 4.4× step the **real** `kr-client` showed
(1.75 → 7.91 MB, next section) and is the cross-check that the feature is now doing something.

Literal commands, one per row (lab-arm64, aarch64, Ubuntu 24.04, load average 0.13 → 0.58 across
the whole round, binaries removed from the box afterwards). **⚠ Host-sharing note:** the box was
idle when the round started (16:25 UTC, load 0.13) but the 11.4 soak
(`soak-rr-r1-20260923T162853Z`) started on it at **16:28:53 UTC**, i.e. during the `musl-mi` row,
so the last three rows (`musl-mi-purge0`, `gnu-sys`, `gnu-mi`) ran alongside a Rust
client/server pair plus its churn and ping drivers. Load stayed under 0.6 on 2 vCPU throughout
and the burst times (10.6–13.0 s) are within the spread §6 already had, but the two glibc rows and
the purge-delay row are **not** on an idle box and the soak's own first 15 minutes are not on one
either. That weakens the peaks a little further; it does not touch the release percentages, which
are 5 % against 95 %. Cross-built with
`cargo zigbuild -p kcptun-interop-tests --bin memprobe --release [--features mimalloc] --target
aarch64-unknown-linux-{musl,gnu.2.39}`:

```sh
./memprobe-musl-sys --sessions 4 --bytes 134217728 --auto-trim --decay 180 --interval 30
./memprobe-musl-mi  --sessions 4 --bytes 134217728 --auto-trim --decay 180 --interval 30
MIMALLOC_PURGE_DELAY=0 \
./memprobe-musl-mi  --sessions 4 --bytes 134217728 --auto-trim --decay 180 --interval 30
./memprobe-gnu-sys  --sessions 4 --bytes 134217728 --auto-trim --decay 180 --interval 30
./memprobe-gnu-mi   --sessions 4 --bytes 134217728 --auto-trim --decay 180 --interval 30
```

RSS in MB. Columns as in §6: "+2 min" is the `--auto-trim` sample about 120 s after the burst
ended, "end of run" is `after-trim+5s`, i.e. after one explicit `memory::trim()`. Raw KCP, so
caveat 13 applies to all of them.

| build | idle | peak `VmHWM` | at close | +2 min | end of run | released | burst |
|---|---:|---:|---:|---:|---:|---:|---:|
| musl + system (what ships today) | 1.65 | 200.2 | 195.7 | 190.3 | 190.3 | **4.9 %** | 10.8 s |
| musl + **mimalloc v3** | 7.21 | 162.6 | 137.6 | 83.4 | 80.0 | **48.7 %** | 10.6 s |
| musl + mimalloc v3, `MIMALLOC_PURGE_DELAY=0` | 7.21 | 160.6 | 88.8 | 71.5 | 71.2 | **55.5 %** | 13.0 s |
| **glibc 2.39 + system (`malloc_trim`)** | 3.00 | **121.2** | 117.3 | **5.30** | **4.47** | **95.6 %** | 11.6 s |
| glibc 2.39 + mimalloc v3 | 8.76 | 155.5 | 143.2 | 71.2 | 68.0 | 54.2 % | 12.1 s |

Four things change, and one does not.

- **mimalloc does release — about half.** On musl it takes the peak from 162.6 MB to 83.4 MB two
  minutes after the burst, against the system allocator's 200.2 → 190.3. So the sub-step's
  headline finding that "musl cannot give memory back" is **not** a property of static linking; it
  is a property of *mallocng*, and swapping the allocator fixes half of it. `MIMALLOC_PURGE_DELAY=0`
  helps a little more (55.5 %) and mostly makes the release earlier — 88.8 MB already at close,
  where the default delay is still at 137.6 MB.
- **mimalloc also lowers the peak on musl**, by 19 % (200.2 → 162.6 MB), which the void rows could
  not have shown either.
- **glibc + system still wins every column that matters**: the lowest peak of any build (121.2 MB,
  25 % below mimalloc's), 95.6 % released within two minutes, and it gets there with an idle floor
  of 3.00 MB rather than 7.21.
- **mimalloc on glibc is strictly worse than glibc alone** — higher idle (8.76 vs 3.00), higher
  peak (155.5 vs 121.2) and it releases 54 % where glibc alone releases 96 %. That is not the old
  gating bug: `release_to_os` now calls `malloc_trim` unconditionally on glibc, and it has nothing
  to trim, because mimalloc has taken `malloc` over. Putting mimalloc under glibc replaces the one
  allocator in this table that fully releases with one that half-releases.
- **The idle cost is confirmed and unchanged.** 7.21 / 8.76 MB against 1.65 / 3.00 — the same 4.4×
  the real binaries show. mimalloc buys half a release for four times the idle floor; glibc buys
  the whole release for 1.35 MB.

So the correction strengthens rather than weakens **D07's recommendation**: mimalloc is no longer
"it does not even work", it is "it works half as well as the alternative, and costs 4.4× the
number this port is selling plus a vendored C toolchain". The choice between musl and glibc is
unchanged, and one option the void rows had ruled out is now genuinely open — **musl + mimalloc
for a build that must stay static and still give some memory back** (55 % with
`MIMALLOC_PURGE_DELAY=0`), at 7.21 MB idle per process, i.e. about 230 MB across the 27+3 mesh
before any traffic. That is a worse idle floor than glibc's 107 MB for a worse release, so it only
makes sense if static linking is non-negotiable.

Not re-run: **mimalloc v2**. That row needs a `libmimalloc-sys` downgrade in the workspace
manifest, which is not worth a dependency change to measure a version this project would not
ship; it should be read as unmeasured, not as evidence either way. Every row here is **one run**,
and the `musl + system` disagreement with §6 shows the peaks deserve ±20 %, not ±10 %; the
*release* percentages are orders apart and are not at risk from that.

### The wins this must not cost: idle RSS of the real binaries

`memprobe` is one process holding both endpoints, so it says nothing about §1's headline. That was
checked separately, with the **real `kr-client` and `kr-server`** on lab-arm64, S1 flags, no
connection ever made, sampled at t = 60 s — the same measurement as §1:

| build | client `VmRSS` | server `VmRSS` | 27 + 3 mesh, idle | vs §1 (musl, before 12.3b) |
|---|---:|---:|---:|---|
| musl + system (this tree) | **1.75 MB** | **2.84 MB** | **55.8 MB** | 1.71 / 2.78 — unchanged |
| glibc 2.39 + system | 3.48 MB | 4.37 MB | 107.1 MB | 3.33 / 4.27 — unchanged |
| musl + mimalloc v3 | 7.91 MB | 12.58 MB | 251.3 MB | **4.5× / 4.4× worse** |

Three things follow.

- **The fix costs the idle floor nothing measurable** (+40 and +60 kB on one sample each, against
  a 0.1 MB spread across §1's twenty). The 9.8×/6.2× headline of §1 survives intact.
- **This is where mimalloc's argument fails.** It *does* solve half the retention problem (§6.2:
  49–55 % released on musl against mallocng's 5 %), but it multiplies the number this port is
  actually selling by four and a half to do it. `RssAnon` shows where it goes — 164 kB → 6.24 MB
  on the client — and across the mesh it is 56 MB → 251 MB *before any traffic*, against glibc's
  107 MB for a full release.
- **glibc costs about 1.6 MB per process** and still leaves the idle floor 4.7× below Go's
  503 MB, while being the only build that gives a burst back. That is the trade to weigh.

### D07 — the recommendation

**Reject mimalloc, and make the released Linux binaries glibc rather than static musl.**

> **Status, 2026-09-24.** This recommendation is now the settled decision. It was contradicted in
> between by 13.2c's container round and reversed by 12.3e; **§8** re-measured it at soak scale
> with the real binaries, on one box with only the allocator changed, and it holds by a wider
> margin than anything here. 12.3f carries it out in the build: glibc is the default artifact and
> the default image, static musl is a documented fallback with the loud warning §8 spells out.

The `memprobe` rows are §6.2's round (all five taken back to back with the allocator actually
installed); the idle-RSS row is the real `kr-client`/`kr-server` pair. The two should not be mixed
with §6's earlier table.

| | musl + system | musl + mimalloc | **glibc + system** | glibc + mimalloc |
|---|---|---|---|---|
| idle RSS, real client / server | **1.75 / 2.84 MB** | 7.91 / 12.58 MB | 3.48 / 4.37 MB | not measured¹ |
| idle RSS, `memprobe` (§6.2) | **1.65 MB** | 7.21 MB | 3.00 MB | 8.76 MB |
| peak after 512 MB each way (§6.2) | 200.2 MB | 162.6 MB | **121.2 MB** | 155.5 MB |
| released 2 min after the burst (§6.2) | 4.9 % | 48.7 % (55.5 % with `PURGE_DELAY=0`) | **95.6 %** | 54.2 % |
| …with the smux layer and live sessions (§6.1) | not re-run | not re-run | **93.6 %** | not measured |
| time for the same burst (§6.2) | 10.8 s | 10.6 s | 11.6 s | 12.1 s |
| pure-Rust build, no C toolchain | **yes** | no | **yes** | no |
| runs on any Linux, statically | **yes** | yes | no (glibc ≥ build target) | no |

¹ The real-binary idle pair was measured for the three builds that were candidates; `memprobe`'s
row above covers the fourth and shows it is the worst of the four.

mimalloc loses on the axes that matter here. It **does** help with retention — §6.2 corrects the
earlier "3 %" to 49–55 % released on musl, and it lowers the musl peak by 19 % — but it
half-solves a problem glibc solves outright (95.6 %), it is *actively worse than glibc alone* when
layered on glibc (it takes `malloc` over, so the `malloc_trim` that works has nothing left to
trim), it **multiplies the real binaries' idle RSS by 4.5** — the single number this port is
selling — and it costs a vendored C build dependency, the same objection that decided D27 against
`aws-lc-rs`. The one case it could still be argued for is a build that must stay static *and* must
give memory back; that is a worse trade than glibc on both ends (230 MB mesh idle for 55 %, against
107 MB for 96 %), so it is a fallback, not a recommendation.

glibc wins the memory question outright and costs portability. That cost is smaller than it looks:
`cargo zigbuild --target aarch64-unknown-linux-gnu.2.17` builds and links (verified, 2026-09-23),
so a glibc artifact can be built against a glibc old enough for anything still running. The
honest trade for the user to decide is:

- **ship glibc** — 40 % lower peak than musl, everything returned within a minute, +1.6 MB idle
  per real process (§6.2's `memprobe` pair differs by 1.35 MB; the mesh figure below uses the
  real-binary row) (the mesh's idle floor 56 MB → 107 MB, against ~100 MB *per bursty client* given
  back, and still 4.7× below Go's 503 MB);
- **ship both**, glibc as the default Linux artifact and static musl as the portable fallback, with
  the musl one documented as keeping its high-water mark;
- **ship musl only** and accept that a process which has once seen a burst keeps that RSS. The
  program-level half of the fix still applies, which is the 183 → 170 MB peak above;
- **ship musl + mimalloc** only if static linking is non-negotiable *and* the high-water mark is
  unacceptable: §6.2 measures 49–55 % returned, at 7.21 MB idle per process (≈230 MB across the
  mesh) and a vendored C build. Worse than glibc on both ends; listed because §6's void rows had
  wrongly ruled it out.

These numbers are one run per build. The D07 entry is the orchestrator's to write.

## 7. 12.3c — where the 698 kB per client session went, and what is left of it

§3 measured **698 kB of RSS per idle client session against Go's 243 kB** — the one place the
client is clearly worse than Go — and could attribute only the 384 kB receive batch to it,
leaving ~300 kB unexplained and the 384 kB itself unexplained as a *difference*, since kcp-go
allocates the same 256 × 1500 B batch per session and still measures 243 kB.

**Both halves have the same answer, and it is not "Rust allocates more". It is that Rust *touches*
what Go leaves alone.**

### Method: an idle staircase, live heap beside RSS

`memprobe --idle --sessions N` (new in this sub-step) dials N client sessions in stages — 0, 1, 2,
4, 8, 16 — against a UDP sink that reads and discards, transfers **not one byte**, and samples RSS
(and, under `--features dhat`, the live heap) after each stage. One process, one allocator, no
peer, no smux: the slope of that staircase *is* the per-idle-session cost, measured directly
instead of fitted across two whole processes as in §3.

**It is the same quantity as §3's, but not the same harness, and it does not read the same.** On
the same box, the same static-musl build and the same allocator, the staircase measures **595 kB
per session where §3's two-process fit measured 698 kB** — 17 % lower, because §3 fitted a slope
across two processes at two session counts and absorbed whatever else moved between them. Every
before/after pair below is staircase-against-staircase; **no number in this section may be
subtracted from §3's 698 kB**, and where the mesh arithmetic further down needs a "before" it uses
the staircase's own, not §3's.

The dhat run (macOS, 16 sessions, `--dump-at-close`) attributes the live heap by call site. Per
session, largest first:

| bytes / session | site |
|---:|---|
| **384 000** | `RecvSlot::new` → `vec![0u8; MTU_LIMIT]`, 256 of them (`packet_conn.rs`) |
| 14 336 | the `Vec<RecvSlot>` itself, 256 × 56 B |
| 6 352 | `Arc<UdpSession>` — the session struct |
| 4 182 | `Kcp::set_mtu` → `buffer`, `(mtu + IKCP_OVERHEAD) * 3` |
| 4 096 × 3 | `RingBuffer::new` for `snd_queue`, `rcv_queue`, `snd_buf` (64 × `Segment`) |
| 3 456 | the `TxPipeline::run` tokio task |
| 1 536 | `txqueue`, `Vec<PacketBuf>` with `MAX_BATCH_SIZE` capacity |
| 1 500 | the `XorCrypt` pad, cloned per session |
| 1 500 | `recvbuf`, Go's `make([]byte, mtuLimit)` |
| 1 056 | the first `tokio::sync::mpsc` block of the tx channel |
| ~1 900 | everything else |
| **≈ 434 000** | total live heap per idle session |

So the *allocation* was never a mystery: 398 kB of the 434 kB is the receive batch, and the other
36 kB is the session itself. What §3 could not see is that the RSS slope on the same run was
**476 kB/session** — i.e. every one of those 384 000 allocated bytes was **resident**, on a session
that had never received a datagram.

### Why Go pays 243 kB for the same 384 kB batch

Go's `make([]byte, mtuLimit)` in `readloop_linux.go` comes out of a span the runtime knows is
freshly mapped and therefore already zero, so `mallocgc` skips the clear (`needzero`) and **no page
is faulted until a datagram lands in one**. RSS counts resident, not allocated, so Go's 256 × 1500
batch costs Go almost nothing while it is idle. `vec![0u8; 1500]` is `calloc` of a *small* block:
it is served from the allocator's bins and memset, and 256 of those fault every page of all of
them, immediately.

That is the same mistake 06.6 found in the per-stream copy buffer, one layer down, and
`docs/porting-guide.md` §7 now carries both cases.

Measured with `tools/bench/callocprobe/` — a small C probe that `calloc`s blocks and never reads
them, then reports how much of them `/proc/self/statm` calls resident. It is committed, with its
build and its invocations, in `tools/bench/callocprobe/README.md`; all three shapes below allocate
the same 6 144 000 bytes, so only the block size differs:

```sh
./callocprobe-glibc 16 384000     # one contiguous batch per session, as RecvBatch allocates now
./callocprobe-glibc 4096 1500     # one vec![0u8; MTU_LIMIT] per slot, as it did before 12.3c
./callocprobe-glibc 1 6144000     # a single large block, for the threshold
```

| allocator | 16 × 384 000 B | 4096 × 1500 B | 1 × 6 144 000 B |
|---|---:|---:|---:|
| glibc 2.39, lab-arm64 (aarch64) | **1 % resident** | 101 % | **0 %** |
| glibc 2.35, lab-x86-1 (x86_64) | **0 %** | 109 % | **0 %** |
| musl 1.2 (mallocng), lab-arm64 | 100 % | 137 % | 100 % |

(The first table this section carried was taken with an uncommitted version of the same probe and
read 103 % and 101/138 % in those cells; the committed probe reproduces it to within its rounding.)

glibc's `calloc` skips the memset exactly when the block is big enough to have come from its own
fresh `mmap`. **musl's never does, at any size** — a finding in its own right, and a third
independent strike against mallocng after §4's peak and §6's missing trim.

### The fix

One contiguous allocation for the whole batch instead of 256 small ones
(`crates/kcp/src/packet_conn.rs`): `RecvBatch` owns `slots * MTU_LIMIT` bytes plus one small
`SlotMeta` per slot, and hands out `RecvSlot<'_>` views into it. The batch size is **unchanged at
Go's 256**, nothing about the syscalls changes, and at 384 kB the region is above the default
`mmap` threshold of **glibc** (128 kB) and above **macOS**'s large-allocation threshold — which is
what the glibc and macOS rows of the table below measure: a fresh anonymous mapping, untouched
until datagrams arrive in it, which is precisely Go's behaviour.

That is a measured property of those two allocators, not one the size guarantees. **musl/mallocng
and mimalloc are measured counterexamples** in the same table (−24 % and +25 %), and glibc's own
threshold is *dynamic* — it is raised to the size of the first large mapped chunk the process
frees — so even there the property is not permanent; see *What session churn does to it* below.

### Per idle client session, before → after

`memprobe --idle --sessions 16`, slope over 16 sessions; medians of 5 interleaved rounds on macOS
and 3 on lab-arm64 (load average 0.21–0.35 throughout, checked before and after).

**Deviation from step 12 rule 1**, on the record rather than left to be inferred
from the per-table round counts: rule 1 asks for the median of ≥ 5 interleaved runs. Only the
macOS staircase above meets it. lab-arm64's staircase and 256 MiB burst are 3 rounds and the 05.9
laptop sweep is 3 runs per cell, because the box was carrying the 11.4 soak and laptop time was
shared; the churn table is a **single** run per box (caveat 15). The effect sizes here (8× on the
headline) are far outside that noise, so no conclusion in §7 turns on the shortfall — but it is a
shortfall.

| build | before | after | change | vs Go's 243 kB |
|---|---:|---:|---:|---|
| **lab-arm64, glibc 2.39** | 435 kB | **55 kB** | **−87 %** | **4.4× better than Go** |
| lab-arm64, musl (mallocng) | 595 kB | 455 kB | −24 % | still 1.9× worse |
| lab-arm64, musl + mimalloc | 517 kB | 645 kB | **+25 %** | 2.7× worse |
| macOS (M5, laptop) | 476 kB | **63 kB** | **−87 %** | — |

- On **glibc and macOS the gap is gone and reversed**: 55 kB where Go pays 243 kB. The remainder is
  the ~36 kB of genuine session state plus allocator rounding. (The 52 kB of `recvmmsg`
  `mmsghdr`/`iovec`/`sockaddr` scratch that §3 counted is *not* in an idle session's cost at all:
  `RecvScratch::reserve` runs inside the `recvmmsg` call, and an idle socket never becomes
  readable, so it is allocated on the first datagram and never before.)
- On **static musl the fix is partial**, because mallocng memsets the contiguous region too. What
  it does save there (140 kB) is mallocng's per-small-allocation overhead, not page faults.
- **mimalloc makes it worse**: it commits the segment a large object lands in, so the one big
  allocation is faulted eagerly *and* rounded up. §6.2 already recommended against mimalloc; this
  is another reason.

The same allocation is made once per **listener**, so a server process is 384 kB lighter at startup
on glibc (listener bring-up 772 kB → 388 kB) and 144 kB lighter on musl (712 → 568 kB).

It also settles a question left open since step 05.6: *off* Linux, Go's `defaultReadLoop` reads
into a single 1500-byte buffer, so a macOS or Windows client with `-conn N` was holding 384 kB × N
where Go holds 1.5 kB × N. The Rust batch is still 256 slots there (one `recvfrom` per slot, which
is what lets it drain a queued burst in one wake-up), but only the slots a datagram actually lands
in are resident — the macOS staircase above, 63 kB per session, is that note closed.

### What session churn does to it, and where it undoes it

Every number above comes from a staircase that only ever *allocates*. A real client also **frees**
batches: a session dies on an error, on `-autoexpire`, or when the 600 s scavenger collects one
with no streams, and the session that replaces it `calloc`s another 384 kB. Whether the
replacement still gets a fresh untouched mapping is allocator policy, not a property of this
change — and glibc's policy is explicitly not to: freeing a large mapped chunk **raises its dynamic
`mmap` threshold** to that chunk's size, after which an identically sized `calloc` comes out of the
arena and is memset.

`memprobe --idle --churn G` (new here) runs the staircase `G` times over, closing and dropping
every session in between. Slope per session within each generation, 16 sessions:

| generation | lab-arm64, glibc 2.39 (aarch64) | lab-x86-1, glibc 2.35 (x86_64) | macOS (M5) |
|---|---:|---:|---:|
| 1 (a fresh process) | **50 kB** | **35 kB** | **53 kB** |
| 2 | 19 kB | 0 kB | 3 kB |
| 3 | 279 kB | 370 kB | 5 kB |
| 4 | 374 kB | 387 kB | — |
| 5 | — | 387 kB | — |

```sh
memprobe --idle --sessions 16 --settle 3 --churn 4 --decay 0 --no-trim   # lab-arm64, glibc build
memprobe --idle --sessions 16 --settle 4 --churn 5 --decay 0 --no-trim   # lab-x86-1, glibc build
```

Generation 2 being free and generation 3 not is consistent across both glibc boxes, and the
likely reason is that glibc's `calloc` skips the memset for a *second* case as well: memory it has
just taken from a freshly extended arena, which it also knows to be zero. Generation 1's batches
are `mmap`ed; freeing them raises the threshold, so generation 2 comes from an arena that has to
grow to hold it and is still untouched; generation 3 is the first one served from recycled chunks,
and from there on it is memset every time. That is an inference from **memprobe's** shape
specifically, not something this measures directly — what is measured is the steady state — and
the callocprobe numbers below do not reproduce that two-generation cheap window, so the inference
should not be read as covering both probes.

**On glibc the win is a first-generation effect.** From the third generation on a live session
climbs back towards the whole batch — 279 kB then 374 kB on lab-arm64, 370 then 387 kB on lab-x86-1 —
settling at ~375–390 kB, essentially the whole batch resident again, i.e. roughly where the
per-slot `vec![0u8; MTU_LIMIT]` version was (435 kB on this harness).

`callocprobe 16 384000 3` corroborates the **mechanism** one layer down, on both glibc versions —
generation 1 gets a fresh mapping (1 % resident on lab-arm64, 0 % on lab-x86-1) and later generations
do not (36 % then 34 %; 35 % then 31 % on lab-x86-1) — and shows musl at **100 % in every
generation**, which is why musl was not re-run here: mallocng memsets every `calloc` at every size,
so churn can neither improve its 455 kB nor is there a mechanism by which it would make it worse.
It is *not* a second measurement of the same levels, and it differs from memprobe in two ways that
should be stated rather than smoothed over: its cheap window is **one generation shorter** (memprobe
has generation 2 essentially free as well — 19 kB on lab-arm64, 0 kB on lab-x86-1 against a 384 kB
batch — where callocprobe's generation 2 is already 35–36 % resident), and its steady state settles
at ~34–36 % where memprobe settles near 97 % of the batch. The shape agrees; the levels do not, and
the raw `calloc` loop has none of the session state and allocation traffic that surrounds the batch
in memprobe.

Two things soften it, and neither rescues it:

- **It is not a leak.** RSS falls all the way back when the generation is dropped (lab-arm64 8044 →
  3668 kB, lab-x86-1 9992 → 4188 kB), so a churning client oscillates rather than climbing. What it
  costs is the *live* session, which is what the mesh arithmetic multiplies.
- **macOS keeps the win through churn** — 3 and 5 kB per session in generations 2 and 3 — so this
  is glibc's dynamic threshold specifically, not something general about freeing and re-allocating.

What it does *not* do is change the recommendation, because the steady state is still a wash with
Go rather than a loss (≈375 kB against Go's 243 kB is the same order, where §6.1's trim is worth
tens of MB), and because a session that has never churned is the common case for the production mesh,
whose clients hold `-conn` sessions open for as long as the process lives. But the 55 kB figure
must be quoted as *a fresh process's* number, and the honest range for a long-lived glibc client is
**55 kB to ~375 kB per session depending on churn**. The fix for the churned case is one line —
`mallopt(M_MMAP_THRESHOLD, n)` pins the threshold and turns the dynamic adjustment off
(`no_dyn_threshold`) for the whole process — with the requirement that **`n` ≤ the batch size**,
`BATCH_SIZE * MTU_LIMIT` = 384 000 B, because glibc maps a request only when
`nb >= mp_.mmap_threshold`: a pin *above* the batch size would send every batch to the arena and
have it memset in generation 1 too, which is the bad case, not the fix. glibc's own default of
128 kB is what makes generation 1 cheap, so that is the value to pin. But that is a process-wide
allocator policy change with its own costs, so it is an
*Open after 12.3c* item below and a DECISIONS entry, not something to slip in here.

### It costs no throughput

The 05.9 echo sweep, both profiles × 8/32 MiB payloads × 4/64/512 KiB messages, 3 runs each, Rust
and Go alternating, on the laptop. CPU/GB is the stable metric (the harness's own note); Rust
medians before → after:

| profile | payload | msg | CPU s/GB before | after |
|---|---|---|---:|---:|
| default | 8 MiB | 4 KiB | 52.59 | 46.71 |
| default | 8 MiB | 64 KiB | 42.47 | 41.12 |
| default | 8 MiB | 512 KiB | 36.34 | 39.45 |
| default | 32 MiB | 4 KiB | 42.27 | 42.16 |
| default | 32 MiB | 64 KiB | 35.42 | 36.01 |
| default | 32 MiB | 512 KiB | 33.19 | 33.61 |
| production | 8 MiB | 4 KiB | 38.34 | 36.32 |
| production | 8 MiB | 64 KiB | 35.42 | 33.22 |
| production | 8 MiB | 512 KiB | 38.85 | 32.34 |
| production | 32 MiB | 4 KiB | 36.64 | 37.54 |
| production | 32 MiB | 64 KiB | 30.89 | 33.55 |
| production | 32 MiB | 512 KiB | 34.38 | 31.83 |

Six cells better, six worse, none outside the run-to-run spread, and **no degradation band**.

What that table does and does not support: it is Rust-only, CPU s/GB only. The Go arm was run
interleaved to cancel drift, but **no Go column and no throughput figure was retained from this
sweep**, so nothing here establishes a Rust-vs-Go throughput ratio on the laptop — the absolute
CPU/GB numbers (0.41–0.51× Go's, from V18's recorded laptop cells) are the only cross-language
figures, and docs/DECISIONS.md V18's own macOS arm64 production throughput range is
**1.42–2.89× Go** (1.42–2.24× at 8 MiB, 2.83–2.89× at 32 MiB), not a single narrow band. The
before → after *throughput* evidence this sub-step owes is the lab-arm64 table immediately below,
which has it directly.

On lab-arm64, a real burst through the Linux `recvmmsg` path — 4 sessions × 32 MiB echoed, so
256 MiB over the link, 3 interleaved rounds — is unchanged in time and **lower in peak RSS**:

| build | before | after |
|---|---|---|
| musl | 757 Mbit/s, peak 145.1 MB | 772 Mbit/s, peak 136.9 MB |
| glibc | 798 Mbit/s, peak 104.3 MB | 796 Mbit/s, peak 96.3 MB |

**Box conditions, and a warning for the 11.4 soak.** Unlike the staircase above, the load average
was **not recorded** around these rounds — that is a gap in the measurement, and the numbers should
be read with it. What *is* known is the window: every lab-arm64 measurement in §7 was taken between
roughly 18:00 and 19:20 local on 2026-09-23 (12.3b was committed at 17:59), and the 11.4 soak
started on the same box at 17:28 local, so **these rounds ran inside the soak's window**, as
caveat 15's churn run did (load average 0.51 before, 0.28 after, the nearest recorded samples).
The churn probe transfers no bytes, but this one does not: it pushes 3 × 256 MiB over the link on
a 2-vCPU box. It is therefore the one measurement in this sub-step that could have perturbed the
soak's own throughput, CPU and RSS figures, and whoever reads the soak should **discount the
18:00–19:20 window**. See caveat 16.

### What this does to the mesh arithmetic

*What this means for the 27+3 mesh*, below, fits 4 sessions and 36 streams per client. Every
session term in this table is **this section's staircase**, before and after alike, so the rows are
like-for-like with each other; §3's 698 kB is a different harness and appears nowhere in it. The
floors are §1's (musl) and §6.2's (glibc) and the stream term is §3's, neither of which 12.3c
touches.

| per client, 4 sessions + 36 streams | Go | Rust |
|---|---:|---:|
| musl, before 12.3c | 18.5 MB | 1.71 + 4 × 0.595 + 36 × 0.0046 = 4.26 MB |
| musl, after 12.3c | 18.5 MB | 1.71 + 4 × 0.455 + 36 × 0.0046 = 3.70 MB |
| glibc, before 12.3c | 18.5 MB | 3.33 + 4 × 0.435 + 36 × 0.0046 = 5.24 MB |
| glibc, after 12.3c, sessions never replaced | 18.5 MB | 3.33 + 4 × 0.055 + 36 × 0.0046 = **3.72 MB** |
| glibc, after 12.3c, churned steady state | 18.5 MB | 3.33 + 4 × 0.375 + 36 × 0.0046 = 5.00 MB |

(the glibc rows carry §6.2's 1.6 MB higher idle floor, which is the trade D07 weighs.) The
break-even that §3's closing paragraph worried about — "Go wins above ~33 sessions per client" —
**disappears on glibc for a process whose sessions are its first**: at 55 kB against Go's 243 kB,
more sessions make Rust look *better*, not worse. It comes back once sessions churn, at about 101
per client ((16.73 − 3.33) / (0.375 − 0.243)), which is still three times further out than §3's
33. On static musl it moves from 33 to about 71 ((16.73 − 1.71) / (0.455 − 0.243)) but never
disappears.

### Open after 12.3c

1. **Static musl.** 455 kB per session, against Go's 243 kB, is the one remaining loss, and it is
   an allocator property (mallocng memsets every `calloc`), not a porting difference. It goes away
   if D07 lands on glibc. If the release must stay static musl, the fix that works on *every*
   allocator is to stop allocating 256 slots up front — grow the batch from a few slots as
   receives actually fill it, and let 12.3b's `shrink_idle` give them back. That is a deviation
   from Go's fixed `batchSize` and needs its own DECISIONS entry, so it was not done here.
2. **Session churn on glibc**, measured above: by the third or fourth generation of sessions a
   live session is back to ~375 kB, because glibc raises its dynamic `mmap` threshold when it frees
   the first batch. The batch is still one allocation and still not memset by the *program*, so
   this is allocator policy, and the direct answer is `mallopt(M_MMAP_THRESHOLD, 128 * 1024)` (or
   `MALLOC_MMAP_THRESHOLD_` in the environment, or the `glibc.malloc.mmap_threshold` tunable) at
   start-up, which pins the threshold and disables the dynamic adjustment process-wide. The
   requirement, not just the number: the pin must be **≤ `BATCH_SIZE * MTU_LIMIT` (384 000 B)** for
   the batch to keep getting a fresh mapping, since glibc maps a request only when
   `nb >= mp_.mmap_threshold`. Pinning it *higher* than the batch (512 kB, say) does the opposite
   of the fix — it guarantees the batch is served from the arena and memset in every generation,
   including the first. 128 kB is glibc's own default and is what makes generation 1 cheap. That trades away glibc's own tuning for every other
   allocation in the process, so it belongs in D07 with the rest of the allocator decision rather
   than in this sub-step. Until it is decided, quote 55 kB as a fresh process's number and
   ~375 kB as a long-lived churning one.
3. **The real two-process pair** was not re-measured at idle with this change; the staircase and
   the listener rows above are `memprobe`. §1's floor cannot move (the client's batches are
   per session, and there are none at idle), and the server's floor should *drop* by the 384 kB
   the listener row shows.
4. **Scale beyond 16 sessions** is still unmeasured, as it was in §3.
5. **The listener's batch under churn** was not measured. It is allocated once per listener and a
   server does not churn listeners, so the first-generation number is the one that applies; a
   server that rebinds (`-autoexpire` has no server equivalent) is out of scope here.

## 8. 11.4 — the same question at soak scale, with the real binaries

§6 and §6.2 decided D07 with `memprobe` on a synthetic 512 MB burst. The 11.4 soak asked it again
with the **real `kr-client`/`kr-server` pair**, under six and two hours of production-shaped churn
(S1 flags, `wan50` netem, 20 streams/s of 10 kB–1 MB, 10 long-lived streams, an 8 MB × 4 burst every
five minutes). Full write-up and every confound in
[`docs/lab-results/11.4-soak.md`](../lab-results/11.4-soak.md).

**The controlled pair.** Both runs on **lab-arm64**, same aarch64 box, same 2 vCPU, same netem, same
flags, same churn seed, same workload-driver binary; only `kr-client`/`kr-server` were swapped from
`aarch64-unknown-linux-musl` to `aarch64-unknown-linux-gnu` (glibc 2.17). Both delivered 36.7–36.8
Mbit/s at p50 103.02 ms and 8.5 % of one core, under a background mesh at mean load 0.50 / 0.51.

| lab-arm64, client | static musl (mallocng) | glibc 2.17 |
|---|---:|---:|
| peak RSS / `VmHWM` | **253.0 MiB** | **50.3 MiB** |
| RSS 2 min after the traffic stops | 253.0 MiB | **13.6 MiB** |
| returned to the kernel | **0 %** | **73 %**, and it stayed returned for the 20 min measured |
| RSS slope, 2160–7200 s | **+44,860 kB/h** | **−600 kB/h** |
| RSS slope over its whole run | +32,053 kB/h (6 h) | +686 kB/h (2 h, including the release) |

**What is new, beyond confirming §6.** `memprobe` measured musl failing to give a *burst* back. Under
sustained churn musl gives nothing back at all, so what §6 called "keeps its high-water mark" is in
fact a **monotone ramp of 32–45 MiB/h that had not flattened after six hours** (79 → 253 MiB). On a
961 MB box that is an OOM within a day, and it is a much stronger warning than the one D07 currently
carries for the musl fallback. glibc, on the same box and the same workload, sets its `VmHWM` at
minute 40 and never moves it.

**Caveat 13 is closed.** This *is* the real two-process pair under load, with the proxy layer, the
TCP side and `-scavengettl` all in play: 132.6 → 6.7 MB in `memprobe` becomes 50.3 → 13.6 MiB in the
shipping binaries, on the first quiet 30 s tick after the churn stops.

**Caveat 14 is confirmed, and shown to be harmless on glibc.** `trim_when_idle` **never fired once**
during either six-hour run — the churn moves ~37 Mbit/s every tick by construction, so the process is
never quiet. The glibc plateau (39–43 MiB on lab-x86-2, 44–50 MiB on lab-arm64) was therefore held
entirely by ordinary `free`, with the trim dormant; the trim only showed up in the 100 seconds after
the traffic stopped, where it took the process from 45.3 to 13.6 MiB. So on glibc the all-or-nothing
rule costs a busy process nothing. On musl it is the difference between a ramp and nothing, because
`trim()` has no allocator call to make. The specific mesh case — one client active, the rest idle on
a server that aggregates nine — is still unmeasured; this soak had one client.

**Limits.** One run per build, no interleaving (step 12 rule 1 is not met), and the two arms ran for
different durations (6 h musl, 2 h glibc) at different times of day. Restricting the musl arm to the
glibc arm's two hours still leaves it at 135 MiB — 2.7× — and still climbing. The gnu binary is a PIE
against the system libc where the musl one is static. The effect is 5× in peak and 75× in slope, far
outside any plausible spread, but it is n=1 per arm.

### What ships as a result (D07 SETTLED, carried out in 12.3f)

D07 had moved twice before §8: 12.3d/13.2c made glibc the default on §6.2's 512 MB burst, and 12.3e
moved it back to musl on 13.2c's container round. §8 is what settles it, and **12.3f makes glibc the
default again** — for the release archives (`tools/release.sh`'s `default` group is `linux-gnu macos
freebsd`; the unmarked `kcptun-rust-linux-<arch>-<version>.tar.gz` is glibc 2.17) and for the
container image (`docker build .` is `debian:bookworm-slim`; `docker build --target musl` is the
Alpine one). Both flavours are still built and published — `release.yml` asks for `linux-gnu
linux-musl freebsd` on purpose — because an option nobody builds rots and the documentation offering
it then lies.

**Why the 12.3e call was wrong, since this file carried both rounds side by side.** 13.2c measured a
**single burst at small scale** — two containers on Docker Desktop's Linux VM, peaks of 7–19 MB. At
that scale glibc's higher floor and its per-thread arenas outweigh what its trim returns, and musl
has nothing to ratchet, so musl reads lower at every sample point and looks like the cheaper default.
That reading was correct about its own regime and wrong about the deployment: the mesh this port is
for runs for weeks with sessions churning continuously, which is §8's regime, and there the ordering
reverses by an order of magnitude. The lesson is not about allocators — it is that the measurement
regime has to match the deployment, and a cheaper-looking small-scale round must not overturn a
sustained one.

> ### ⚠ The warning the musl fallback needs is stronger than "keeps its high-water mark"
>
> That phrasing — §6's, and 12.3e's — is too mild, and it is what made the musl default look
> survivable. Under sustained churn a static musl build returns **nothing**, and its RSS is not a
> plateau but a **monotone ramp of 32–45 MiB/h that had not flattened after six hours (79 → 253
> MiB)**. On a 961 MB box that is an out-of-memory kill within a day. `mallocng` has **no
> `malloc_trim` entry point at all**, so `memory::trim` has nothing to call: no idle period, no
> flag and no tuning changes this. Take a musl artifact only when a single static file that runs
> on any Linux matters more than the process ever giving memory back, and then size the deployment
> for something that only grows.

## Caveats

0. **§1–§5's per-client-session row is superseded by §7, but not by subtraction.** §3's 698 kB is
   a *two-process fit* on the tree before 12.3c. §7 measures the same quantity with a
   single-process staircase, and that harness reads **595 → 455 kB on static musl and
   435 → 55 kB on glibc** — note that its own musl "before" is 595 kB, 17 % below §3's 698 kB for
   the same thing on the same box with the same allocator. So §7's numbers say what 12.3c changed
   and §3's number says what §3 measured; **the two are not on the same scale and must not be
   differenced**. Wherever a "before" is needed downstream (the mesh arithmetic in §7 and below),
   the staircase's own before is used. Every other row of §1–§5 stands.
1. **§1–§5 are system-allocator numbers taken before 12.3b**, on tree `e34fb56`. They are strongly
   allocator-dependent (§4: musl → glibc moved the peak by 30–39 %), and §6 measured mimalloc as
   well. §6's own numbers are a *different harness* — one process holding both endpoints — so its
   RSS figures are not comparable cell-for-cell with §1–§5's two-process ones.
2. **All Rust numbers outside §4's allocator table are the musl build.** The glibc build's idle
   floor is higher — 3.33 MB client and 4.27 MB server against musl's 1.71 and 2.78 — so if a glibc
   build is what gets deployed, the idle win shrinks to ~5.0× (client) and ~4.0× (server)
   instead of 9.8× and 6.2×.
3. ~~**The remaining ~300 kB per client session in Rust is unexplained.**~~ Answered in §7: it was
   not a separate allocation at all — 398 kB of the 434 kB live heap is the receive batch and the
   rest is genuine session state; the gap against Go was **residency, not allocation**. (§6's
   ≈1.1 MB of grown `RingBuffer`/`rcv_buf` is a *live* session's growth under traffic and cannot
   appear in §3's slope, which was measured on held, idle sessions that transferred nothing.)
4. **Where Go's post-load RSS settles was not measured** — the decay window ended while it was
   still falling. The comparison "Go ends below Rust" is therefore established, but the final Go
   value is not.
5. ~~**Why Rust holds its peak was not established.**~~ Answered in §6 with a dhat profile: 85 %
   allocator retention, 15 % program-level capacity. Both are addressed, but only a **glibc** build
   can act on the 85 %.
6. **Two session counts only** (4 and 16). Linearity beyond that is assumed, not shown. Nothing was
   measured at the 1k/5k stream scale the plan asks for in 12.1.
7. **Loopback only.** No netem, no real RTT. A 100 ms path keeps far more data in flight and would
   raise both sides' buffer occupancy; this measurement says nothing about that.
8. **The mesh extrapolation below assumes** the same profile, the same session and stream counts,
   and processes that are idle in the same sense as ours. The user's containers were never
   inspected (see the note under *Methodology*), so the session and stream counts in the model are
   *inferred from the Go RSS*, not observed.
9. **`RssFile` is shared.** 27 copies of one binary do not pay 27 × `RssFile`.
10. **Not repeated across days.** One session, on a box shared with live traffic. The idle numbers
    were stable to <0.1 MB across 20 samples, so they are solid; the load numbers come from 2 rounds
    each and should be treated as ±10%, and the two allocator rounds are single runs.
11. **§1–§5's harness is not committed.** The driver and the `sink`/`hold`/`load` helper were
    scratch scripts (the commands in *Methodology* reproduce them). Folding them into `tools/bench/`
    is 12.1's job. §6's harness **is** committed, as `memprobe`.
12. **§6 and §6.2 are one run per build.** The release percentages are far enough apart (95.6 %
    against 4.9 %) that repeats would not change the conclusion, but the **peaks are single
    samples and deserve ±20 %, not ±10 %**: §6.2 re-measured `musl + system` at 200.2 MB where §6
    had 169.6 MB for the same command on the same box. Rows may be compared within a round, not
    across rounds. One `musl + mimalloc` round in §6 took 28.5 s instead of 10.4 s and was
    discarded as host noise after a repeat came back at 10.4 s.
13. **§6 never measured the real `kcptun-client`/`kcptun-server` binaries under load**, and that is
    what hid the keepalive bug of §6.1. Its table is `memprobe` in **raw-KCP** mode: the same
    session, ring, pool and allocator code, with no smux above it. §6.1 closes most of the gap —
    `memprobe --smux` carries S1's smux buffers, the token bucket and the keepalive, and its
    glibc round reproduces the release — but the **proxy layer** (`std::Pipe`'s copy buffers, the
    TCP side, `-scavengettl`) is still unmeasured under load, and the two-process RSS split
    between a client and a server is still §4's, taken before 12.3b. A round with the real pair
    under §1–§5's driver remains worth doing; it needs that harness, which is not committed
    (caveat 11). **Closed by §8**: the 11.4 soak is the real pair, with the proxy layer and
    `-scavengettl` in play, and it reproduces the release (50.3 → 13.6 MiB on glibc, nothing on
    musl).
14. **The process-wide trim needs the *whole process* to be quiet, and a multiplexing server may
    never be.** `memory::trim_when_idle` compares the global `DEFAULT_SNMP` byte counters, so the
    `malloc_trim` that is 85 % of the retained RSS fires only when nothing anywhere in the process
    has moved more than 64 kB for a tick. Go's scavenger is traffic-independent and has no such
    condition. In the production mesh each of the 3 servers aggregates 9 clients: one client moving
    data is enough to keep the server above `QUIET_BYTES` forever, in which case it keeps its
    high-water mark where Go would have returned it. Everything measured in §6 and §6.1 is a
    single-workload process that goes fully quiet, so this case is **untested**. (The per-session
    shrink is unaffected — it is per session and runs regardless.) **§8 half-answers it.** The
    11.4 soak confirms the mechanism — the trim fired **zero** times in six hours of churn — and
    shows it costs a glibc process nothing, because ordinary `free` held a 39–50 MiB plateau
    without it. The specific mesh case (one client busy, eight idle, on one server) still needs
    its own run; the soak had a single client.
15. **§7's churn table is one run per box.** Three boxes agree on its shape — generation 1 cheap,
    generation 3–4 onwards back to the whole batch on glibc, flat on macOS — and `callocprobe` shows
    the same thing at the C level on both glibc versions, so the conclusion is solid; the
    individual per-generation slopes are single samples on a 16-session staircase and deserve
    ±20 %. lab-arm64 was carrying the 11.4 soak at the time (load average 0.51 before, 0.28 after);
    the probe transfers no bytes and sleeps between stages, so the two do not compete, but the
    numbers were taken on a box that was not idle. The x86_64 row is lab-x86-1, glibc 2.35 on a
    single vCPU — a different glibc and a different page-fault cost from lab-arm64's.
16. **§7's lab-arm64 throughput/peak-RSS rounds overlapped the 11.4 soak, and their load average
    was not recorded.** The 3 × 256 MiB rounds behind the musl/glibc table in *It costs no
    throughput* ran between roughly 18:00 and 19:20 local on 2026-09-23, inside the 11.4 soak's
    window on the same 2-vCPU box. Unlike §7's other lab-arm64 runs no `uptime` was captured with
    them, so their own contention is unquantified; and unlike the idle and churn probes they move
    real bytes, so the soak's throughput/CPU/RSS in that window should be discounted rather than
    read as steady state.

## What this means for the 27+3 mesh

The user's 552 MB, against what this measurement says:

| | Go (measured here) | Rust (measured here) |
|---|---:|---:|
| 27 idle clients | 27 × 16.73 = 451.7 MB | 27 × 1.71 = **46.2 MB** |
| 3 idle servers | 3 × 17.23 = 51.7 MB | 3 × 2.78 = **8.3 MB** |
| **idle floor** | **503.4 MB** | **54.5 MB** |

**The idle floor alone accounts for 503 MB of the mesh's 552 MB.** That is the whole point: their
mesh is mostly paying for 30 Go runtimes, not for tunnel state. Replacing the floor is where the
saving is.

Adding plausible tunnel state: their clients average 18.5 MB, i.e. **1.77 MB above the Go idle
floor**. With the Go slopes measured here that is consistent with roughly *4 sessions + ~36 idle
streams* per client (4 × 243 kB + 36 × 22.5 kB = 1.78 MB) — a fit, not an observation; other
combinations give the same total. Under that assumption:

Per-session terms are **§7's staircase** in every Rust column (§3's 698 kB is a different harness
— caveat 0 — and is not used here); floors are §1's for musl and §6.2's for glibc, stream terms are
§3's.

| | Go | Rust (musl, after 12.3c) | Rust (glibc, after 12.3c) | Rust (glibc, sessions churning) |
|---|---:|---:|---:|---:|
| per client | 18.5 MB | 1.71 + 4×0.455 + 36×0.0046 = **3.70 MB** | 3.33 + 4×0.055 + 36×0.0046 = **3.72 MB** | 3.33 + 4×0.375 + 36×0.0046 = **5.00 MB** |
| 27 clients | 499.5 MB | **99.9 MB** | **100.4 MB** | **135.0 MB** |
| 3 servers | 51.7 MB | **8.3 MB** (their servers measure at the idle floor) | **12.8 MB** | **12.8 MB** |
| **total** | **552 MB** (their number) | **≈ 108 MB** | **≈ 113 MB** | **≈ 148 MB** |

So: **roughly 550 MB → 110–150 MB, a saving of about 400–445 MB (≈ 73–80%)** — under the stated
assumptions, with everything idle. The glibc columns carry §6.2's higher idle floor (3.33/4.27 MB
per process against musl's 1.71/2.78) and still come out far lower. The spread between the last two
columns is session churn, which §7 measures and *Open after 12.3c* item 2 has the one-line answer
to; production clients hold their `-conn` sessions for the life of the process, so the third column
is the one their mesh should land on, and the fourth is the pessimistic bound.

The break-even that used to worry this section — sessions were the one thing Rust was worse at on
the client, with **Go ahead above ~33 sessions per client** ((16.73 − 1.71) / (0.698 − 0.243), on
§3's numbers) — **is gone on a glibc build whose sessions are its first**, where a session costs
55 kB against Go's 243 kB and more sessions widen the lead. It returns at ~101 sessions per client
once they churn, and on static musl it survives at about 71.

**The caveat that mattered operationally, and what is left of it.** As measured in §4, each of
those clients kept its high-water mark: a Rust client that once pushed a large transfer stayed at
that RSS — up to ~100 MB with S1's 16 MB smux and stream buffers — where the Go client falls back
over a few minutes, so a mesh of 27 bursty Rust clients could have sat *above* today's 552 MB until
something restarted them.

12.3b removes that **on a glibc build**: §6.1 measured 118.7 MB → 7.6 MB, 69 s after the burst,
with the smux sessions still up. On a **static musl build it stands**, because mallocng has no trim
to call, and the program-level half only recovers the 183 → 170 MB of peak. So the 75 % figure is
safe to quote for a glibc artifact and must still be qualified for a musl one — which is the
substance of what D07 decides.

## Follow-ups for 12.3

1. ~~**Give memory back after a burst.**~~ Done in 12.3b, §6 and §6.1: `UdpSession::shrink_idle`,
   `BufferPool::trim` and `memory::trim_when_idle`. Complete on glibc (raw KCP 132.6 → 6.7 MB;
   with the smux layer and four live keepalive-ing sessions, 118.7 → 7.6 MB), peak-only on static
   musl, which has no allocator trim to call. ~~Still open underneath it: a round with the **real
   two-process pair** under load (caveat 13).~~ Done in **§8**: the 11.4 soak ran the real pair for
   six and two hours and reproduced both halves — glibc 50.3 → 13.6 MiB on the first quiet tick,
   static musl 253.0 → 253.0 MiB.
2. ~~**The 698 kB client session.**~~ Explained and fixed in 12.3c, §7: it was not the batch's
   *size* but its residency. `BATCH_SIZE` stays at Go's 256 and the batch is now one contiguous
   allocation, which `calloc` serves from a fresh mapping and does not touch. On §7's staircase —
   which reads 595 kB on musl where §3's two-process fit read 698 kB, so the pairs below are that
   harness's own before and after — the slope goes **435 → 55 kB per session on glibc** (below
   Go's 243 kB) and 476 → 63 kB on macOS, with the 05.9 sweep and a lab-arm64 burst showing no
   throughput cost. The acceptance gate passes on both terms for a glibc build **whose sessions
   have not churned**. Two things are open underneath it: **static musl**, where mallocng memsets
   every `calloc` and the slope only falls 595 → 455 kB; and **glibc under session churn**, where
   by the third or fourth generation of sessions a live session is back to ~375 kB because glibc
   raises its dynamic `mmap` threshold on the first `free`. Fixing musl without an allocator change means growing the batch
   on demand instead of allocating 256 slots up front — a deviation from Go's fixed `batchSize`
   that needs its own DECISIONS entry; fixing the churn case means pinning
   `M_MMAP_THRESHOLD`, which belongs in D07.
3. ~~**Decide D07 on these numbers.**~~ Measured in §6 and re-measured in **§6.2** (§6's mimalloc
   rows were void — the probe had no `#[global_allocator]`), with a recommendation: **reject
   mimalloc** — it releases half of what glibc does, it raises the idle floor 4.4× and it costs a
   C build dependency — and make the released Linux binaries **glibc**, or ship both with musl
   documented as keeping its high-water mark. The entry itself is the orchestrator's to write.
   **§8 re-measured it at soak scale with the real binaries and it holds**, with one amendment:
   the musl fallback does not merely keep its high-water mark, it ramps 32–45 MiB/h without
   flattening. **Settled, and carried out in 12.3f**: glibc is the default release artifact and
   the default container image, static musl is the documented fallback, and both are still built
   so neither can rot. See §8's "What ships as a result".
4. **Extend the decay window** to where Go settles, so the comparison has both endpoints. Rust's
   end point is now known (§6: the idle floor, within a minute, on glibc); Go's is not.
5. **Scale**: sessions beyond 16, streams beyond 100, and the 1k/5k figures the plan asks for.
6. **A server that is never fully quiet** (caveat 14). The process-wide trim is all-or-nothing per
   process; a mesh server multiplexing 9 clients may never see a quiet tick and would then keep
   its high-water mark, which is the case that decides whether the 552 MB headline holds for the
   3 servers. Measure it — the 11.4 soak can sample server RSS with one client active and the rest
   idle — and if it is real, the fix is to make the decision per session (or to drive the trim
   from "no session has been busy for a tick" rather than from the global counters).
