# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Compatibility policy.** The *wire protocol* is kcptun's and does not change: any release of this
project interoperates with Go kcptun `39935d5` (kcp-go v5.6.66, smux v1.5.55). A change that could
break interoperability with those peers would be a major version and would be listed here first.

## [0.2.3] - 2026-10-03

Review fixes to 0.2.2's new teardown rules. They end fewer connections than 0.2.2, never more, and
lose less data. Nothing changes on the wire.

### Fixed

* **A payload is no longer held back by its window update** ([D35]). smux's frame read, the
  proxy's drain path, waited to send the window update a read made due before handing the payload
  over. With the session's send path congested (a full KCP window toward a dead or starved peer)
  the payload sat where nothing could see it: a teardown lost it without a reset, and a stream
  holding up its whole session stopped draining. The payload now goes first and the updates follow
  from a per-stream task, the order Go's `WriteTo` uses.
* **The stall rule no longer ends live transfers** ([V24](docs/differences.md)):
  * its clock starts when the far end stops, or when the session starvation starts, so a reader
    that was merely paused gets the whole 30 s after that, instead of being cut a second after a
    FIN or after another stream's burst briefly filled the session;
  * it no longer applies when the reader is beyond the tunnel: 0.2.2 ended such a transfer after
    120 s without credit (512 s at `-streambuf 16777216`), and since smux has no reset, the far
    application saw a clean but short stream;
  * a stream counts as holding up its session only while it holds a quarter of the session's
    buffer.
* **A stream cut off by its session's receive side failing** (a socket or protocol error that does
  not close the session) now resets the application's socket instead of ending it cleanly.

## [0.2.2] - 2026-10-03

A fix for a leak of finished connections in both binaries, found in production on 0.2.1. It
changes how a connection ends: read **Changed** before upgrading if an application behind the
tunnel half-closes its connections. Nothing changes on the wire.

### Fixed

* **Finished connections no longer leak their TCP side** ([V24](docs/differences.md), [D35]).
  Up to 0.2.1 the proxy pipe was a port of Go kcptun's 2026 `Pipe`, which half-closes each
  direction on its own and ends only once both have ended, and smux v1.5.55 does not wake a write
  that is waiting for window credit when the peer's FIN arrives. Once the far end dropped a stream, the direction writing into it
  waited forever, and the TCP socket the other direction had already half-closed was never read
  or closed again. In production that showed as client sockets in FIN-WAIT-2 holding 10-18 MB of
  unread data, haproxy's ends in CLOSE-WAIT, thousands of closed sockets whose descriptors stayed
  open, the same on the servers' target side, and one server holding 827 MB of its host's 829 MB
  of TCP memory. Go kcptun 2026-02 has the same hole; the Go releases before it do not, and
  neither does this one. The client also lets go of a dead session (its socket and queues) at
  once, not when the last connection through it ends or round-robin next lands on its slot, and a
  closed session no longer holds on to its streams' buffers.
  [How to check a host](docs/troubleshooting.md#connections-are-left-behind-fin-wait-2-close-wait-or-descriptors-with-no-connection).
* **TCP keepalive on proxied connections, as Go does** ([D36]). Go turns keepalive on (15 s
  idle, 15 s interval, 9 probes) for every TCP connection it accepts or dials; this port set only
  `TCP_NODELAY`. An application or a target that vanishes without a FIN or an RST is now noticed
  about 150 s after it went quiet, and its connection ends.

### Changed

* **A half-close is no longer passed through the tunnel** ([V24](docs/differences.md)). When
  either direction of a connection finishes, both ends are closed `-closewait` seconds later
  (client default 0, server 30), as in Go kcptun before 2026, and the far end sees the end of the
  stream only then. An application that calls `shutdown(SHUT_WR)` and then waits for the answer
  has its connection closed at once behind a client with the default `-closewait 0`; a longer
  client `-closewait` gives the answer that long. `-closewait` now runs once per connection, not
  once per direction, so a round trip against the server's default closes within 30 s, not 60.
* **A connection stuck after its far end has finished is ended** ([V24](docs/differences.md)).
  While one direction waits for its destination, both ends are checked once a second. A socket
  that was reset, or that keepalive gave up on, ends the connection
  (`pipe: connection reset by peer`). Once the far end has finished, or a stream is holding up its
  whole session, a connection on which nothing has moved for `-closewait`, but at least 30 s (at
  least 120 s when the reader that stopped is beyond the tunnel), is ended with
  `pipe: i/o timeout`. A reader that stops for that long after the far end has finished loses the
  tail it never read.
* **A connection cut short is reset, not closed** ([V24](docs/differences.md)). When teardown
  throws away data that kcptun holds for an application (or, on the server, for the target), that
  socket is reset (`SO_LINGER 0`), so the application reads `ECONNRESET` instead of a clean end of
  a short stream.

[D35]: docs/DECISIONS.md
[D36]: docs/DECISIONS.md

## [0.2.1] - 2026-09-25

The first published versions, 0.1.0 to 0.2.1 (2026-09-24 and 2026-09-25), recorded together. See
the [README](README.md#status) for what is not finished.

### Added

* **`kcptun-client` and `kcptun-server`**, drop-in replacements for the Go binaries: the same
  flags and aliases, the same defaults, Go's flag-parsing semantics (`-flag value`,
  `--flag=value`, base-0 integers, `--` terminator), the same JSON configuration keys with Go's
  override rules, the `KCPTUN_KEY` environment variable, and byte-identical `-h`, `-v` and startup
  log output apart from the program name.
* **KCP over UDP**, a faithful port of kcp-go v5.6.66: the ARQ state machine, stream mode,
  sessions, listener, batch I/O (`recvmmsg`/`sendmmsg` on Linux), rate limiting and pacing, DSCP,
  socket buffers, port ranges, and the full SNMP counter set.
* **Forward error correction**: a Reed-Solomon codec byte-compatible with klauspost/reedsolomon
  v1.13.0, with NEON, AVX2 and SSSE3 kernels chosen at run time and a scalar fallback, plus the
  FEC encoder, decoder and autotune.
* **All 15 `-crypt` modes**: aes, aes-128, aes-192, aes-128-gcm, salsa20, blowfish, twofish,
  cast5, 3des, tea, xtea, xor, sm4, none, null, with Go's PBKDF2 key derivation, each one
  verified against golden vectors generated by the Go code.
* **smux v1 and v2**: sessions, streams, the frame shaper, flow control and keepalive.
* **Snappy stream compression** with Go's framing and chunking rules, and **QPP** (Quantum
  Permutation Pad) as an on-by-default cargo feature.
* **Operational parity**: `SIGUSR1` SNMP dumps, `-snmplog` CSV files with Go time layouts,
  `-log`, `-quiet`, Unix-socket endpoints, Go's log format and timestamps.
* **Packaging**: `tools/release.sh` cross-builds Linux (x86_64, aarch64, armv7, armv6, i686),
  macOS and FreeBSD archives with SHA-256 sums and the licence texts, under both the cargo and
  the Go binary names; a `Dockerfile` that keeps the upstream image's contract (`/bin/client`,
  `/bin/server`, `EXPOSE 29900/udp 12948`); systemd units, FreeBSD rc files, sysctl drop-ins and
  the upstream example configurations in `dist/`.
  * The **default Linux artifacts and the default container image are glibc** (glibc 2.17 for
    the archives, `debian:bookworm-slim` for the image). Static musl is published beside them,
    `kcptun-rust-linux-<arch>-musl-<version>.tar.gz`, `docker build --target musl`, as a
    fallback for a host with no usable glibc.
  * ⚠ **The static musl build never returns memory.** Under sustained traffic it does not merely
    keep its high-water mark: it ramps **32–45 MiB/h and had not flattened after six hours
    (79 → 253 MiB)**, which on a 1 GB box is an OOM within a day. Measured on one box with only
    the allocator changed: musl 253 MiB peak, 0 % released, +44,860 kB/h; glibc 50 MiB peak,
    13.6 MiB after two minutes, negative slope, at identical throughput, latency and CPU
    (`docs/benchmarks/memory.md` §8). musl's `mallocng` has no `malloc_trim` entry point for the
    tunnel's idle-trim to call.
* **Documentation**: [README](README.md), [tuning guide](docs/tuning.md),
  [troubleshooting](docs/troubleshooting.md), [interop matrix](docs/interop-matrix.md),
  [benchmark reports](docs/benchmarks/) and the [porting guide](docs/porting-guide.md).

### Fixed

* **The binaries raise their own open-file limit, as the Go ones do** ([D34]). The Go *runtime*
  raises `RLIMIT_NOFILE` from the soft limit to the hard limit before `main` runs: kcptun's own
  source has no rlimit code at all, so Go kcptun gets it for free and this port got nothing.
  Under Docker's common `nofile` default of soft 1024 / hard 1048576 that left this port with
  1024 descriptors beside a Go kcptun with 1048576; on a busy server, where `-closewait` holds
  each finished connection for 30 s (Go's server default too), the ceiling arrives in minutes and
  `accept` starts failing with `too many open files`. Found in production, on a fleet that had
  moved two servers across. Both binaries now do what the Go runtime does, unconditionally and
  silently, and the `dist` CI job starts a server under `--ulimit nofile=1024:1048576` and fails
  if the process did not raise itself.

[D34]: docs/DECISIONS.md

### Verified against Go

* 128/128 interop runs green on macOS/arm64 and 128/128 on Linux/aarch64, across 32 configurations
  in all four pairings, including both Go↔Go and Rust↔Rust controls
  ([details](docs/interop-matrix.md)).
* Golden vectors generated from the Go code for every byte-level component.
* A live differential against the Go binaries across 50 command lines: help, version, startup logs,
  usage errors, exit codes and files left behind, with a closed allow-list of the documented
  differences.

### Differences from Go kcptun

Twenty-two intentional deviations (V01–V23, of which V13 was superseded by V18), all
wire-compatible, are listed in [`docs/differences.md`](docs/differences.md) and registered with
their evidence in [`docs/DECISIONS.md`](docs/DECISIONS.md). The ones a user notices:

* half-closed connections returned complete responses, where Go can truncate them (V11, V04).
  **No longer true since 0.2.2:** the binaries do not pass a half-close on at all, and a
  connection is closed `-closewait` seconds after either side finishes (V24);
* a usage error exits 2 instead of 0 (V06);
* configurations that Go accepts and then crashes on are refused at startup: FEC above 256 shards
  (V07), `-QPPCount` and `-conn` values that overflow Go's `uint16` cast (V15, V19);
* fatal errors print one line instead of a Go stack trace (V20);
* `--pprof` in a default build logs that the profiler is not compiled in (V21);
* the KCP send path applies backpressure instead of dropping packets when its queue is full (V18);
* a peer may answer from an address other than the one it is sent to (V23), which Go drops,
  multi-homed and anycast servers, direct-return load balancers and multi-WAN clients all need
  this. What is accepted widens; where packets are sent never moves. `-strictsource` restores
  Go's rule.

### Known limitations

* **`-tcp` (fake TCP) is unverified.** The transport and both binaries' `-tcp` paths are
  complete, but the privileged Linux tests (raw sockets, `iptables`, Go interop in `-tcp` mode)
  have not been run yet.
* Windows is not supported: not built, not released, not in CI. This is a Linux project (macOS is
  the development host).
* `aes-128-gcm` is slower than Go (0.68–0.77× on the two machines measured); every other cipher is
  at or above parity.
* A `-snmplog` file name containing the `MST` time-layout token renders a numeric offset rather
  than a zone abbreviation (V14).
* No Go-vs-Rust memory (RSS) comparison has been published yet.
