# kcptun-rust

A Rust port of [kcptun](https://github.com/xtaci/kcptun): a tunnel that carries TCP connections
over reliable UDP, with multiplexing, forward error correction, encryption and compression.

**It is a drop-in replacement for the Go binaries.** Same wire protocol, same flags, same JSON
config keys, same log lines, so a Rust client talks to a Go server, a Go client talks to a Rust
server, and you can swap one side, both, or neither.

```
 your app ──TCP──▶ kcptun-client ══KCP over UDP══▶ kcptun-server ──TCP──▶ target service
```

It is also **faster and much lighter**: roughly 1.5–1.8× the goodput at about half the CPU, and a
client that idles at 3.5 MB where Go's uses 16.7. [Full report, caveats included →](docs/benchmarks/REPORT.md)

## Run it

### Docker

The image is **[`ariyansharifi/kcptun-rust`](https://hub.docker.com/r/ariyansharifi/kcptun-rust)**
(`latest`, plus a tag per release; `linux/amd64` and `linux/arm64`).

```sh
# server: publishes the service at 127.0.0.1:9000 to the tunnel
docker run -d -p 29900:29900/udp ariyansharifi/kcptun-rust \
    /bin/server -t "127.0.0.1:9000" -l ":29900" -mode fast3 -key "YOUR_KEY"

# client: applications now connect to 127.0.0.1:9000 and come out at the target
docker run -d -p 9000:9000 ariyansharifi/kcptun-rust \
    /bin/client -r "SERVER_IP:29900" -l ":9000" -mode fast3 -key "YOUR_KEY"
```

### Binaries

Download from [Releases](https://github.com/ariansharifi/kcptun-rust/releases), or build:

```sh
cargo build --release -p kcptun-client -p kcptun-server
```

**Set `-key` on both ends**: the default secret is upstream's and is public. `-key`, `-crypt`,
`-nocomp`, `-smuxver`, `-QPP` and `-QPPCount` must be identical on both sides.

**Raise `net.core.rmem_max` before anything serious.** `setsockopt(SO_RCVBUF)` is silently clamped
to it, and the stock value costs both this port and Go roughly half their throughput.
[`dist/linux/sysctl_linux`](dist/linux/sysctl_linux) is the drop-in. (Open-file limits need nothing,
the binaries raise their own, as the Go ones do.)

→ [Docker in detail](docs/docker.md) · [all flags](docs/flags.md) · [tuning](docs/tuning.md) ·
[troubleshooting](docs/troubleshooting.md) · [service files and examples](dist/README.md)

## Compatible with Go kcptun

Built against kcptun `39935d5` (kcp-go v5.6.66, smux v1.5.55): the last full-code version, since
upstream is archived. Compatibility is tested, not asserted: **128/128 interop runs green** in all
four Go/Rust pairings on two platforms, plus golden vectors generated from the Go code for every
byte-level layer.

Behaviour is reproduced quirks included, so the differences are few and each one is deliberate.

→ [What "compatible" rests on](docs/compatibility.md) ·
[every difference from Go](docs/differences.md) · [interop matrix](docs/interop-matrix.md)

## Status

Released and in use, but young. **`-tcp` (fake TCP) is unverified** and **Windows is not
supported**. → [What is finished, and what is not](docs/status.md)

## Documentation

| | |
|---|---|
| [Docker](docs/docker.md) | The published image, building it yourself, open-file limits |
| [Flags](docs/flags.md) | Every flag of both binaries, with defaults |
| [Tuning](docs/tuning.md) | Throughput, latency, FEC, ciphers, memory, kernel limits |
| [Troubleshooting](docs/troubleshooting.md) | What the common failures look like and what they mean |
| [Compatibility](docs/compatibility.md) | The pinned Go reference and how it is verified |
| [Differences from Go](docs/differences.md) | All 23, with what Go does and why this differs |
| [Status](docs/status.md) | What is finished and what is not |
| [Performance report](docs/benchmarks/REPORT.md) | Go vs Rust, end to end, with every gap stated |
| [Interop matrix](docs/interop-matrix.md) | Go ↔ Rust results per platform |
| [Packaging](dist/README.md) | systemd units, sysctl drop-ins, example configurations |
| [Changelog](CHANGELOG.md) | What has changed |
| [Decisions](docs/DECISIONS.md) · [wire format](docs/WIRE-FORMAT.md) · [porting guide](docs/porting-guide.md) | For anyone reading or changing the code |

## Licence

**MIT, except [`crates/qpp`](crates/qpp/LICENSE), which is GPL-3.0**: it is a port of
[xtaci/qpp](https://github.com/xtaci/qpp) and inherits its licence.

The `qpp` feature is **on by default**, for parity with the Go binaries, so a default build is a
combined work and may only be distributed under the **GPL-3.0**, exactly the position Go kcptun is
in, since it links the same library. `cargo build --no-default-features` gives an **MIT-only**
binary; everything works except `-QPP`.

Full attribution, piece by piece: [NOTICE.md](NOTICE.md) · [LICENSE](LICENSE)

## Credits

The design, and most of the behaviour reproduced here, is [xtaci](https://github.com/xtaci)'s:
kcptun, kcp-go, smux, qpp and tcpraw, on top of [skywind3000](https://github.com/skywind3000)'s KCP
protocol and [klauspost](https://github.com/klauspost)'s Reed-Solomon work. This is a port, not a
new protocol.
