# Tuning guide

How to get a kcptun-rust link to behave, and what each knob really does. This is a port of the
tuning sections of the Go kcptun README (commit `39935d5`), updated where this implementation
differs: the flags, the defaults and the advice are otherwise the same, because the protocol and
the parameters are the same.

**Two rules before anything else.**

1. `-key`, `-crypt`, `-nocomp`, `-smuxver`, `-QPP` and `-QPPCount` must be **identical on both
   ends**. A mismatch does not negotiate; it fails.
2. Change one thing at a time and measure. Every parameter here trades throughput, latency,
   bandwidth or memory against one of the others.

**Contents:** [Before you tune](#before-you-tune) · [Throughput](#throughput) ·
[Latency](#latency) · [Head-of-line blocking](#head-of-line-blocking) ·
[Forward error correction](#forward-error-correction) · [Rate limiting and pacing](#rate-limiting-and-pacing) ·
[Multiport](#multiport) · [DSCP](#dscp) · [Encryption](#encryption) ·
[Quantum resistance](#quantum-resistance) · [Compression](#compression) · [Memory](#memory) ·
[Worker threads](#worker-threads) · [Slow devices](#slow-devices) · [SNMP](#snmp) ·
[Profiling](#profiling)

## Before you tune

Raise the kernel limits first. They are the same ones Go kcptun needs, for the same reason: this is
a UDP application moving a lot of small datagrams.

```sh
ulimit -n 65535          # or in ~/.bashrc, or LimitNOFILE= in the systemd unit
```

```
# /etc/sysctl.d/90-kcptun.conf: dist/linux/sysctl_linux
net.core.rmem_max=26214400       # bandwidth-delay product
net.core.rmem_default=26214400
net.core.wmem_max=26214400
net.core.wmem_default=26214400
net.core.netdev_max_backlog=2048 # proportional to -rcvwnd
```

FreeBSD equivalents are in [`dist/freebsd/sysctl_freebsd`](../dist/freebsd/sysctl_freebsd).

Then the per-socket buffer, which is what the process asks the kernel for and is capped by
`net.core.[rw]mem_max` above:

```
-sockbuf 16777217        # default 4194304
```

On a **slow processor this is critical**: if the application cannot drain the socket fast enough, a
small buffer means the kernel drops packets that arrived perfectly well. The advice is unchanged
from Go.

## Throughput

> **I have a fast link. How do I use it?**

Raise `-rcvwnd` on the receiving side and `-sndwnd` on the sending side **together and gradually**.
The smaller of the two bounds the link:

```
max rate ≈ window × MTU / RTT
```

So 1024 packets × 1350 B / 100 ms ≈ 13.8 MB/s. Increase the windows until measured throughput stops
improving; past that point you are only buying buffer bloat and memory. `-mtu` raises the same
product, but only up to the path MTU: a fragmented UDP datagram is worse than a smaller one.

Note that client and server have different defaults: the client sends with `-sndwnd 128` and
receives with `-rcvwnd 512`, the server uses 1024 for both. For a download-shaped workload the pair
that matters is the server's `-sndwnd` and the client's `-rcvwnd`.

**The window is also the largest burst the tunnel can produce.** One KCP flush can emit a whole
window of packets at once. In Go, anything that does not fit the internal send queue is dropped and
costs a retransmission timeout, which is why large windows there can be *slower* than small ones;
this port applies backpressure instead and leaves the surplus for the next flush
([V18](differences.md#full-list)). Large windows are therefore safe here, but they still cost memory,
see [Memory](#memory).

## Latency

> **I am using this for gaming / interactive traffic and want the lowest latency.**

Latency spikes are usually packet loss waiting for a retransmission. Make retransmission more
aggressive with `-mode`:

```
fast3 > fast2 > fast > normal > default
```

Left is more aggressive (retransmits sooner, uses more bandwidth), right is more conservative.
`-mode fast3` is the usual choice for interactive traffic on a lossy path.

`-mode manual` exposes the raw KCP parameters, `-nodelay -interval -resend -nc`:

```
-mode manual -nodelay 1 -interval 20 -resend 2 -nc 1
```

Understand each one before changing it; the
[KCP protocol documentation](https://github.com/skywind3000/kcp/blob/master/README.en.md#protocol-configuration)
describes them. A JSON config with a known `-mode` overrides these four keys, exactly as in Go.

[FEC](#forward-error-correction) is the other latency tool: recovering a lost packet from parity
costs no round trip at all, which matters most when the RTT is large.

## Head-of-line blocking

Every stream shares one KCP connection, so a stalled stream can hold up the others.

* `-smuxbuf` (default 4 MiB) is the whole de-mux buffer for a session. Raising it to 8 MiB or more
  reduces the chance of blocking, at the cost of memory.
* `-smuxver 2` plus `-streambuf` (default 2 MiB) caps each *stream* instead, and applies
  backpressure to the sender when a receiver is slow, which stops one stream from eating the whole
  session buffer. `-smuxver` must be identical on both sides.

```sh
kcptun-client -r "server_ip:29900" -l ":9000" -smuxver 2 -smuxbuf 8388608 -streambuf 2097152
```

Order of attack: raise `-smuxbuf` first; if you then need finer control of memory, use smux v2 and
`-streambuf`.

The other lever is `-conn`, which gives the client several independent KCP connections and spreads
new TCP connections over them round-robin. Streams on different connections cannot block each
other at all. `-autoexpire` recycles a connection after that many seconds (helpful against
middleboxes and for rebalancing), and `-scavengettl` decides how long an expired connection may
linger while its streams drain.

## Forward error correction

kcptun sends `-parityshard` redundant packets for every `-datashard` data packets, so the receiver
can reconstruct up to `parityshard` losses within a group without a retransmission.

* Defaults: `-datashard 10 -parityshard 3`, 30 % bandwidth overhead (`parityshard / datashard`).
* More parity: better on lossy paths, more bandwidth and more CPU.
* `-parityshard 0` (or both shards 0) turns FEC off: less CPU, less bandwidth, worse on a lossy
  link.
* The receiver **auto-tunes to the sender's parameters**, so the two sides need not match, and you
  can change one side without restarting the other.
* Most valuable on long-haul links: at a 200 ms RTT, recovering a packet from parity instead of
  waiting out an RTO is the difference between a hiccup and a stall.

**Limit:** `datashard + parityshard` must be at most 256. Go silently switches to a different
erasure code above that and produces parity no kcptun receiver can use; this port refuses the
configuration at startup instead ([V07](differences.md#full-list)).

FEC costs roughly 0.3–0.4 µs of CPU per packet on an ARM server core and less on a modern x86 or
Apple core, with vectorised (NEON / AVX2 / SSSE3) Reed-Solomon kernels chosen at run time. On a CPU
with neither (a 32-bit ARM router, an i686 box) the scalar fallback is 7–16× slower, and turning
FEC off is usually the right call. Measurements:
[docs/benchmarks/fec.md](benchmarks/fec.md).

## Rate limiting and pacing

`-ratelimit <bytes per second>` (default 0, unlimited) paces a single KCP connection's outgoing
packets instead of letting a flush emit them as a burst.

Why it helps:

1. **Fewer local drops.** Micro-bursts overflow NIC and kernel buffers, so packets are lost before
   they reach the wire (`ENOBUFS`).
2. **Smoother traffic**, which intermediate routers and shapers treat better; less jitter.
3. **Bandwidth control** on asymmetric links, where saturating the uplink destroys the downlink's
   ACK path.

`-ratelimit 1048576` is 1 MB/s. The limit applies per KCP connection, so with `-conn N` the total
is `N ×` the value.

## Multiport

Both sides can use a port *range* instead of a single port: `IP:min-max`, for example
`1.2.3.4:3000-4000`. The server listens on every port in the range, and the client picks one at
random for each new session (sessions do not hop ports mid-connection).

```sh
kcptun-server -l ":3000-4000" ...        # open UDP 3000-4000 in the firewall
kcptun-client -r "SERVER_IP:3000-4000" ...
```

Ranges are `1–65535` with `min <= max`. A single port (`IP:29900`) still works.

## DSCP

`-dscp <0-63>` marks the outgoing packets for DiffServ QoS; set it on both sides. `46` (EF) is the
usual choice for interactive traffic, if the network between the two hosts honours it at all.

This port writes the mark into the IPv6 traffic class shifted the same way as into the IPv4 TOS
byte. Go writes the raw value on IPv6, which shifts the class and sets stray ECN bits
([V03](differences.md#full-list)).

## Encryption

Every packet is encrypted in full (FEC header, KCP header, checksum and payload) under a key
derived from `-key` with PBKDF2. Each packet carries a fresh nonce, so identical plaintexts never
produce identical ciphertext.

* `-crypt` and `-key` must be identical on both sides. Change the default key; `it's a secrect` is
  upstream's and is public. `KCPTUN_KEY` keeps it out of the process list.
* `aes-128` is a good minimum: modern CPUs have AES instructions, and it is faster here than
  `salsa20`.
* `aes-128-gcm` is the only AEAD mode, and the only mode this port is **slower** at than Go
  (0.68–0.77× depending on machine and direction). Everything else is at or above parity, most of
  it well above, see [docs/benchmarks/crypto.md](benchmarks/crypto.md).
* `-crypt xor` is **insecure** (trivially broken by known-plaintext analysis). Do not use it unless
  you understand exactly what you are giving up; it exists for links where the payload is already
  encrypted and CPU is the binding constraint.
* `-crypt none` keeps the packet header format but sends it in plaintext, so the headers can be
  tampered with: window sizes, RTT, FEC properties, checksums. `-crypt null` sends raw data with
  no cryptographic framing at all: fastest, least secure, easiest to fingerprint.

kcptun has no asymmetric handshake, so replay of captured packets is theoretically possible; if
that matters, authenticate at a layer above.

## Quantum resistance

`-QPP` enables the Quantum Permutation Pad, as in Go:

```
-QPP                 enable it
-QPPCount 61         number of pads; each pad costs 256 bytes
```

Both flags must be identical on both sides (`"qpp": true`, `"qpp-count": 61` in JSON). For it to be
worth anything:

1. use a `-key` of at least **211 bytes**, and
2. keep `-QPPCount` **coprime with 8**: simplest is a prime, and at least 7.

Two notes specific to this port:

* `-QPPCount` above 65535 is refused at startup. Go truncates it to 16 bits, where `65536` becomes
  zero and crashes on the first byte of traffic and `65537` silently becomes a single pad, skipping
  Go's own safety warnings ([V15](differences.md#full-list)).
* QPP support comes from the GPL-3.0 `crates/qpp`, which the default build includes. See the
  [licence note](../README.md#licence) if you plan to distribute binaries.

## Compression

Snappy compression of the stream is **on by default**; `-nocomp` disables it, and the setting must
match on both sides.

It is worth keeping for plaintext, compressible traffic: cross-datacenter replication, redo logs,
message queues. It is worth turning off when the payload is already encrypted or already
compressed (TLS, media, most tunnelled traffic): every chunk is then compressed, found to be no
smaller, and sent as it was, for nothing.

## Memory

There is no garbage collector, so **`GOGC` has no effect here**. Go kcptun's memory advice
translates into the same flags with no runtime knob to go with them:

| What | Bounded by |
|---|---|
| Packet buffers in flight (rx, tx, FEC queues) | `-sndwnd`, `-rcvwnd`, `-datashard`, `-parityshard`, `-mtu` |
| De-mux buffer per session | `-smuxbuf` |
| Receive buffer per stream (smux v2) | `-streambuf` |
| Kernel socket buffers | `-sockbuf` (twice, send and receive, per UDP socket) |
| Number of KCP connections | `-conn` on the client |

Packet buffers come from a pool of fixed 1500-byte buffers with no zeroing on reuse, as in kcp-go.
A proxied TCP connection that is idle holds no copy buffer at all: buffers are taken only when
there is data to move, which is the main structural difference from Go, where the TCP → stream
direction holds `io.Copy`'s 32 KiB buffer for the connection's whole life (the stream → TCP
direction uses smux's own `WriteTo` and takes none; the pooled 4 KiB `bufSize` in Go's
`std/copy.go` is only the fallback path, when neither fast path applies).

A single flush can emit a whole send window, so `-sndwnd` also sets the worst-case burst held in
the send queue. With backpressure ([V18](differences.md#full-list)) that peak is about a quarter of
what the same configuration held before, roughly 3 MB per session at `-sndwnd 8192`.

On a memory-constrained device, lower `-smuxbuf` (it trades concurrency for memory), lower the
windows, and turn FEC off. On a big server with many clients, raise `-smuxbuf`, but its relation
to concurrency is not linear, so measure.

**No Go-vs-Rust RSS comparison has been published in this repository yet**; when one exists it will
be in `docs/benchmarks/`.

## Worker threads

The runtime uses one worker thread per available CPU. `GOMAXPROCS` overrides that, parsed with Go's
own rules (a decimal `int32` greater than zero; anything else is ignored), so existing deployment
scripts and unit files that set it keep working.

One case needs attention: in a container with a **fractional** CPU limit (`--cpus=1.5`, or a
Kubernetes limit of `1500m`), this port's automatic count is lower than Go's, because Go rounds the
cgroup limit up and never goes below 2. Set `GOMAXPROCS` explicitly there.

## Slow devices

Reed-Solomon coding and block ciphers are the expensive parts. On a low-end router or SoC:

* **Turn FEC off:** `-datashard 0 -parityshard 0` on both sides. On CPUs without NEON, AVX2 or
  SSSE3 (32-bit ARM, i686) the codec falls back to scalar kernels that are 7–16× slower than the
  vectorised ones.
* **Pick a cheap cipher.** Go's advice is `salsa20`; that holds here, and on a CPU with AES
  instructions `aes-128` is cheaper still. On the two machines measured this port encrypts at
  1.15–2.4× Go's speed for those two ciphers, and its CFB *decryption* is several times Go's, which
  is the direction a download-heavy client cares about.
* **Raise `-sockbuf`** (see [Before you tune](#before-you-tune)): a slow device that cannot drain
  the socket in time drops packets in the kernel.
* Keep the windows modest: a large `-sndwnd` on a device with little RAM buys nothing but memory
  pressure.

A statically linked musl build has no runtime dependencies, which makes these devices easy
targets: `tools/release.sh v0.1.0 linux-musl` builds them. **Read the warning below before you
reach for one on a device with little RAM**, which is exactly the device this section is about.

> ### ⚠ The static musl build never gives memory back
>
> The default Linux artifacts are **glibc** (`kcptun-rust-linux-<arch>-<version>.tar.gz`, glibc
> 2.17), and the musl ones carry a `-musl-` in the name. Under sustained traffic a static musl
> build does not merely keep its high-water mark: it **ramps 32–45 MiB/h and had not flattened
> after six hours (79 → 253 MiB)**. On a 1 GB box that is an out-of-memory kill within a day, and
> on the 64–256 MB routers this section is about it is very much sooner.
>
> Measured with only the allocator changed: same box, same kernel, same netem, same flags, same
> churn seed, and the same 36.7 Mbit/s at the same latency and CPU in both arms: musl peaked at
> **253 MiB and released 0 %**, still climbing at **+44,860 kB/h**; glibc peaked at **50 MiB**,
> fell to **13.6 MiB** within two minutes and had a *negative* slope. musl's `mallocng` has no
> `malloc_trim` entry point at all, so the tunnel's idle-trim has nothing to call: this is not
> something a flag can tune away. [`benchmarks/memory.md`](benchmarks/memory.md) §8 has the run.
>
> So on a small device, prefer the glibc artifact if the device has a usable glibc at all. If it
> does not, take musl and size the deployment for a process that only ever grows: keep `-sndwnd`
> and `-rcvwnd` small, keep `-scavengettl` short, and restart the tunnel on a timer.

## SNMP

Both binaries keep the same counters as Go: bytes and packets in and out, KCP segments,
retransmissions (normal, fast, early), losses, duplicates, FEC recoveries and errors, checksum
errors, connection counts.

* **`kill -USR1 <pid>`** dumps them to the log, as in Go.
* **`-snmplog ./snmp-20060102.log -snmpperiod 60`** appends them to a CSV file; the file name is a
  Go time layout, so the example rotates daily. (A layout containing the `MST` token renders
  differently here: a numeric offset rather than a zone abbreviation, see
  [V14](differences.md#full-list). Every other token is exact.)

Retransmission and FEC counters are the ones to watch while tuning: rising `RetransSegs` with flat
`FECRecovered` means more parity would help; rising `InErrs` means the kernel is dropping, so raise
`-sockbuf`.

## Profiling

`--pprof` is accepted by both binaries. In a build with the optional `pprof` cargo feature
(`cargo build --release --features pprof`, Unix only) it serves a CPU profile at
`http://<host>:6060/debug/pprof/profile?seconds=30` in the protobuf format `go tool pprof` reads.
Without the feature the flag logs one line and does nothing else
([V21](differences.md#full-list)).

```sh
go tool pprof -http=: 'http://127.0.0.1:6060/debug/pprof/profile?seconds=30'
```

Do not expose port 6060 to a network you do not control.
