# smux: Rust vs Go over TCP loopback (plan 06.6, re-measured in 12.1)

The deferred write-up plan 12.1 owes for sub-step 06.6. The 06.6 smoke numbers were taken on a
machine at **load average 49–87** with ~0 % idle, and the sub-step said in as many words that they
were a lower bound to be re-measured on a quiet machine in Step 12. This is that re-measurement:
same peers, same flags, medians of five interleaved rounds for throughput, and per-idle-stream
memory taken as a **slope over N** with a fresh server for every point instead of a single
difference from a baseline.

One of 06.6's two conclusions survives and one does not. Both are stated below.

## The peers

| | |
|---|---|
| Go | `reference/bin/smuxecho_darwin_arm64` — `tools/gointerop/cmd/smuxecho`, smux **v1.5.55**, built with kcptun's own `std.BuildSmuxConfig` |
| Rust | `target/release/kcptun-smuxecho` — `crates/interop-tests/src/bin/smuxecho.rs`, flag-for-flag interchangeable with the Go peer |
| Settings | kcptun's defaults on both sides: `-ver 2 -smuxbuf 4194304 -streambuf 2097152 -framesize 8192 -keepalive 10` |
| Transport | smux directly over **TCP loopback**. No KCP, no crypto, no FEC — this page is the multiplexer alone |

Both peers speak the same deterministic byte stream (`PrngStream` in Rust, `internal/peer.Stream`
in Go), so each side verifies the echo from a SHA-256 it computes from the seed.

## Method

```sh
cargo build --release -p kcptun-interop-tests --bin kcptun-smuxecho

# throughput: one Rust server and one Go server up at once, four client/server combinations
# per round, five rounds, interleaved
target/release/kcptun-smuxecho     server -listen 127.0.0.1:24101 &
reference/bin/smuxecho_darwin_arm64 server -listen 127.0.0.1:24102 &
<client> client -remote 127.0.0.1:<port> -streams 1  -bytes 67108864
<client> client -remote 127.0.0.1:<port> -streams 64 -bytes 4194304

# per-idle-stream memory: a FRESH server per point, N = 0, 2000, 10000, three rounds,
# `ps -o rss=` on the server while the client holds the streams open
target/release/kcptun-smuxecho idle -remote 127.0.0.1:<port> -streams <N> -hold 18
```

| | |
|---|---|
| Machine | Apple M5 (Mac17,2), macOS 27.0, 10 cores, arm64 |
| Host load | **1.35 / 1.59 / 1.59** before, **1.74 / 1.71 / 1.63** after, on 10 cores — the laptop was also driving the 12.1 lab campaign over ssh. Compare 06.6's 49–87 |
| Tree | `75fd8d8`; no tracked file modified |
| Rounds | throughput: 5, all four pairs inside each round; memory: 3, fresh server per point |

`GR` means **G**o client → **R**ust server, `RG` the other way, as everywhere else in this
repository.

## Throughput: 06.6's second conclusion survives, its first does not

Client wall time (`duration_ms` from the client's JSON line), medians of five rounds:

| workload | RR | GG | GR (Go cli) | RG (Go srv) | best/worst |
|---|---:|---:|---:|---:|---:|
| 1 stream × 64 MiB | **122 ms** | 126 ms | 126 ms | 128 ms | 1.05× |
| 64 streams × 4 MiB | 285 ms | **270 ms** | 265 ms | 279 ms | 1.08× |

Every run behind those medians:

| workload | pair | runs (ms, in order) |
|---|---|---|
| 1 × 64 MiB | RR | 141, 123, 122, 121, 121 |
| 1 × 64 MiB | RG | 127, 127, 128, 129, 128 |
| 1 × 64 MiB | GR | 126, 126, 131, 133, 124 |
| 1 × 64 MiB | GG | 126, 130, 121, 126, 125 |
| 64 × 4 MiB | RR | 289, 283, 285, 286, 285 |
| 64 × 4 MiB | RG | 279, 280, 278, 303, 276 |
| 64 × 4 MiB | GR | 274, 265, 257, 248, 268 |
| 64 × 4 MiB | GG | 274, 259, 270, 256, 271 |

**This is not a smux measurement, and the spread proves it.** All four combinations land inside 5 %
at one stream and 8 % at 64, in both directions of the comparison — the Rust client is marginally
ahead at one stream and marginally behind at 64. The verifying client spends most of the timed
region generating `PrngStream` bytes and hashing them, not in smux, so what this measures is
mostly two PRNGs and two SHA-256s. For scale: 64 MiB in 122 ms is 524 MiB/s and 256 MiB in 285 ms
is 898 MiB/s, on loopback.

| 06.6 said | 12.1 finds |
|---|---|
| "Swapping the **server** implementation does not move the number ⇒ smux is not the bottleneck." | **Confirmed, and now for the client too.** On a quiet machine no substitution on either side moves the number by more than 8 %. |
| Cross-matrix medians 150 / 140 / 169 / **188** ms (RR / RG / GR / GG) at 1 × 64 MiB — a Go client looking 25 % slower than a Rust one. | **Not reproduced.** At load average 1.5 the same four numbers are 122 / 128 / 126 / 126. The 188 ms was the loaded box, not the Go client. |

That second row is the useful part: 06.6's own caveat ("the absolute figures are a lower bound and
must be re-measured on a quiet machine") turns out to have applied to the *ratios* as well, because
the arms were not equally sensitive to contention.

**Still carried over from 06.6, and not closed here.** A smux-*bound* throughput comparison needs a
payload mode on **both** peers that skips the per-byte PRNG and SHA. The Go peer has none, and
adding one to `tools/gointerop/cmd/smuxecho` is a change to the Go reference side that 12.1 did not
make. Until then there is no number on this page that isolates the multiplexer, and this page does
not claim one.

## Memory per idle stream: 2.4× better, measured as a slope

A fresh server per point, `ps -o rss=` on the server while the client holds N streams open. Three
rounds; the widest spread across rounds is 2.0 % (the empty Go server, 9 616–9 808 kB) and every
other cell is at or under 1.1 %, so only the medians are tabulated. All three rounds are below.

| server | RSS at 0 streams | at 2 000 | at 10 000 | slope 2 000 → 10 000 |
|---|---:|---:|---:|---:|
| Rust | 6 016 kB | 14 112 kB | 37 520 kB | **2.93 kB/stream** |
| Go | 9 664 kB | 27 872 kB | 83 776 kB | **6.99 kB/stream** |
| ratio | 0.62× | 0.51× | 0.45× | **0.42×** |

Raw, all three rounds (kB):

| round | rs 0 | rs 2 000 | rs 10 000 | go 0 | go 2 000 | go 10 000 |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 6 016 | 14 000 | 37 392 | 9 616 | 27 808 | 84 016 |
| 2 | 6 016 | 14 144 | 37 520 | 9 664 | 27 872 | 83 648 |
| 3 | 6 000 | 14 112 | 37 568 | 9 808 | 27 888 | 83 776 |

The slope is taken between 2 000 and 10 000 rather than from the empty server, so that the fixed
cost of the first session — the buffers, the tasks, the allocator's first arenas — is not divided
across the streams. Taking it from zero instead gives 3.15 kB/stream for Rust and 7.41 for Go, i.e.
the same ratio; the lower figures are the honest marginal cost.

**The same Rust `idle` client drives both servers**, because the Go peer has no idle mode. That is
carried over from 06.6 and it means the Go *client's* per-idle-stream cost is still unmeasured. It
does not affect the table, which samples the **server**.

06.6 measured 3.14 kB/stream for Rust and 7.31 for Go by difference from a fresh baseline, and an
independent reviewer run got 3.05 and 8.05. The slope confirms both to within the spread of a
loaded machine, and D17 (buffer-on-readiness) is what the Rust column is: a stream that has never
been read from owns no copy buffer.

### One thing that did move, and is not explained here

The Rust server's **empty** RSS is 6.0 MB on this run against the 2.5 MiB 06.6 recorded — the Go
server's is 9.7 MB against 10.2 MiB, essentially unchanged. Two candidate causes, not separated:
the tree has moved a long way since 06.6 (12.3b added `crates/kcp/src/memory.rs` and the shrink
machinery, and this binary links the whole workspace), or 06.6's figure was taken on a box at load
average 49–87 under memory pressure, where resident pages get evicted and `ps -o rss=` reads low.
The Go side moving by 5 % while the Rust side moves by 2.4× argues for the first, but nothing here
measures it. It is a question for 12.3, not a finding of this page.

### And one observation that is *not* a measurement

Sampled during the throughput matrix above — after five rounds of 64 MiB transfers through each
server, so these are warm processes, not idle ones:

| | Rust server | Go server |
|---|---:|---:|
| RSS after the 5 throughput rounds | 11 600 kB | 24 032 kB |
| RSS while holding 10 000 idle streams | 42 400 kB | 83 872 kB |
| RSS 3 s after those streams closed | 42 416 kB | 92 320 kB |

Both processes retain what a burst grew. **Three seconds says nothing about release** — 12.3a's
measurement of that question ran for 600 s and `docs/benchmarks/memory.md` owns it. The rows are
here only to record what was sampled.

## Reproducing it

```sh
cargo build --release -p kcptun-interop-tests --bin kcptun-smuxecho
tools/fetch-reference.sh                    # only if reference/bin/smuxecho_* is missing

target/release/kcptun-smuxecho     server -listen 127.0.0.1:24101 &
reference/bin/smuxecho_darwin_arm64 server -listen 127.0.0.1:24102 &
for r in 1 2 3 4 5; do
  for cli in target/release/kcptun-smuxecho reference/bin/smuxecho_darwin_arm64; do
    for port in 24101 24102; do
      "$cli" client -remote 127.0.0.1:$port -streams 1  -bytes 67108864
      "$cli" client -remote 127.0.0.1:$port -streams 64 -bytes 4194304
    done
  done
done
```

For the memory slope, start a **fresh** server per point and sample `ps -o rss=` on it while
`kcptun-smuxecho idle -remote … -streams N -hold 18` holds the streams open.

Related pages: [`session.md`](session.md) (the KCP session under this layer),
[`memory.md`](memory.md) (end-to-end memory, including per idle stream through the whole stack),
[`micro.md`](micro.md) (all of the micro-benchmarks in one place).
