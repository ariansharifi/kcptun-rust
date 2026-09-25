# Running in Docker

## The published image

```
ariyansharifi/kcptun-rust
```

[hub.docker.com/r/ariyansharifi/kcptun-rust](https://hub.docker.com/r/ariyansharifi/kcptun-rust),
`latest`, plus a tag per release (`v0.2.0`, …). Built for `linux/amd64` and `linux/arm64` by the
release workflow, so `docker pull` picks the right one for the host.

```sh
docker pull ariyansharifi/kcptun-rust

# server: publish a TCP service on 9000 to the tunnel
docker run -d --name kcptun-server -p 29900:29900/udp \
    ariyansharifi/kcptun-rust /bin/server \
    -t "127.0.0.1:9000" -l ":29900" -mode fast3 -key "YOUR_KEY"

# client: applications connect to 127.0.0.1:9000 and come out at the target
docker run -d --name kcptun-client -p 9000:9000 \
    ariyansharifi/kcptun-rust /bin/client \
    -r "SERVER_IP:29900" -l ":9000" -mode fast3 -key "YOUR_KEY"
```

The image keeps the upstream Go image's contract: binaries at `/bin/client` and `/bin/server`,
no `ENTRYPOINT`, `EXPOSE 29900/udp 12948`, so `docker run` command lines written for the Go image
work unchanged. That is a tested claim, not a Dockerfile review: `tools/image-interop.sh` pushes
20 MB of SHA-256-verified data through a real tunnel in all four Go/Rust pairings, for both smux
versions, on every CI run.

## Open-file limits

**Nothing to configure: the binaries raise their own limit, as the Go ones do.**

This is worth knowing because it was an outage before it was a fix. The Go *runtime* raises
`RLIMIT_NOFILE` from the soft limit to the hard limit before `main` runs, so Go kcptun gets it for
free; kcptun's own source has no rlimit code at all. A Rust binary gets nothing, so under Docker's
common default (**soft 1024, hard 1048576**) this port ran with 1024 descriptors beside a Go
kcptun running with 1048576. On a busy server that arrives fast: `-closewait` holds each finished
connection for 30 s on the server (Go's default too), so tens of connections a second is a steady
state of hundreds of descriptors, and past the ceiling `accept` fails and the tunnel flaps with
`too many open files`.

Since **v0.2.1** both binaries do what the Go runtime does, unconditionally and silently
([D34](DECISIONS.md)). In a container started with `--ulimit nofile=1024:1048576`,
`/proc/1/limits` reads:

| | soft | hard |
|---|---|---|
| the container's shell | 1024 | 1048576 |
| Go kcptun (`aguegu/kcptun`) | **1048576** | 1048576 |
| this port, client and server | **1048576** | 1048576 |

That covers the usual case, where only the *soft* limit is low. **If your host caps the hard limit
too**, no process can raise itself past it and it has to be set on the container:

```sh
docker run --ulimit nofile=1048576:1048576 ...
```

```yaml
services:
  kcptun:
    ulimits:
      nofile: { soft: 1048576, hard: 1048576 }
```

Containers have to be **recreated** for this, not restarted. Check what one really has:

```sh
docker exec <name> cat /proc/1/limits | grep 'open files'
```

## Building the image yourself

Two flavours from one `Dockerfile`; the default is glibc:

```sh
docker build -t kcptun-rust .                      # DEFAULT: debian:bookworm-slim, glibc
docker build --target musl -t kcptun-rust:musl .   # fallback: alpine:3.21, static musl
```

**Take the musl image only if you have to.** Under sustained traffic a static musl build does not
give memory back at all, and does not merely hold its high-water mark: it ramps 32–45 MiB/h and had
not flattened after six hours (79 → 253 MiB). On a 1 GB host that is an OOM within a day. The same
box, kernel, profile, flags and churn seed with only the allocator changed gave glibc a 50 MiB peak
falling to 13.6 MiB, against musl's 253 MiB peak releasing 0 %. musl's `mallocng` has no
`malloc_trim` entry point, so the tunnel's idle-trim has nothing to call.
[`docs/benchmarks/memory.md`](benchmarks/memory.md) §8 has the run; the decision is
[D07](DECISIONS.md).

Stamp a version the way Go's `-ldflags "-X main.VERSION=…"` does, without it the binaries report
`SELFBUILD`:

```sh
docker build --build-arg KCPTUN_VERSION=v0.2.1 -t kcptun-rust .
```

## See also

* [`dist/README.md`](../dist/README.md): systemd units, sysctl drop-ins, example configurations
* [`docs/tuning.md`](tuning.md): socket buffers, FEC, ciphers, and the kernel limits that matter
  outside a container too
