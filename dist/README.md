# dist: files for \*nix distributions

Port of [`kcptun/dist/`](https://github.com/xtaci/kcptun) (Go, commit `39935d5307f0`): the service
files, kernel tuning and example configurations that ship alongside the binaries. Nothing here is
built or installed by `cargo`; `tools/check-dist.sh` checks it against the tree, and the two example
configurations are additionally parsed by the real configuration parser in
`crates/std/src/config_tests.rs` (`dist_*`).

| File | Provenance | Changes |
|---|---|---|
| `local.json.example` | `dist/local.json.example` | none, byte-for-byte |
| `server.json.example` | `dist/server.json.example` | none, byte-for-byte |
| `linux/kcptun-client.service` | `dist/linux/kcptun-client.service` | `GOGC` / `GOEXPERIMENT` dropped (see below) |
| `linux/kcptun-server.service` | `dist/linux/kcptun-server.service` | same |
| `linux/sysctl_linux` | `dist/linux/sysctl_linux` | none, byte-for-byte |
| `freebsd/kcptun-client.rc.conf` | `dist/freebsd/kcptun-client.rc.conf` | binary and configuration paths |
| `freebsd/kcptun-server.rc.conf` | `dist/freebsd/kcptun-server.rc.conf` | binary and configuration paths |
| `freebsd/sysctl_freebsd` | `dist/freebsd/sysctl_freebsd` | none, byte-for-byte |

The container image is `Dockerfile` in the repository root, also a port of upstream's. It keeps the
Go image's paths (`/bin/client`, `/bin/server`, `EXPOSE 29900/udp 12948`), so existing `docker run`
command lines work unchanged. One file builds two images, and `tools/check-dist.sh` holds both to
that same contract and pins each one's libc:

```sh
docker build -t kcptun-rust .                      # DEFAULT: debian:bookworm-slim, glibc
docker build --target musl -t kcptun-rust:musl .   # the fallback: alpine:3.21, static musl
```

⚠ **The musl image never returns memory.** Under sustained traffic it does not merely keep its
high-water mark: it ramps **32–45 MiB/h and had not flattened after six hours (79 → 253 MiB)**,
which on a 1 GB host is an OOM within a day. That is why the glibc image is the default even
though it is five times the size on disk (155 MB against 30.5 MB, 31.7 MB against 7.4 MB to
pull). Take `--target musl` only for a host with no usable glibc, or a tunnel short-lived enough
that a monotone ramp never reaches the ceiling, see `docs/benchmarks/memory.md` §8.

The same split applies to the release archives: `kcptun-rust-linux-<arch>-<version>.tar.gz` is
glibc 2.17 and is the default, `kcptun-rust-linux-<arch>-musl-<version>.tar.gz` is the static
fallback.

## Example configurations

Both files are upstream's, unchanged. They can be, because the JSON keys are part of the drop-in
contract: `std/config.go`'s `json:"…"` tags are reproduced exactly in `crates/std/src/config.rs`, so
every key in these files reaches the same field it reaches in Go, including the two that are not
spelled like their flags, `"qpp-count"` (flag `-QPPCount`) and `"nc"` (flag `-nc`). A key the parser
does not know is **ignored**, exactly as Go's `encoding/json` ignores it, so a typo is silent; the
`dist_*` tests exist to catch one in these two files.

Two things to know before copying them into production:

* a JSON file given with `-c` **overrides the command line** (DECISIONS D11), and a known `-mode`
  then overrides `nodelay`/`interval`/`resend`/`nc` from both;
* `"key": "PASSWORD"` is a placeholder. Change it, and prefer the `KCPTUN_KEY` environment variable
  when the file would otherwise be world-readable.

The client example sets neither `conn`, `autoexpire` nor `scavengettl`, and the server example sets
no client-only keys; that is upstream's choice, and the defaults from the command line apply.

## Linux

```sh
install -m 0755 kcptun-server /usr/bin/kcptun-server
install -m 0644 dist/linux/kcptun-server.service /etc/systemd/system/kcptun-server.service
install -m 0600 dist/server.json.example /etc/kcptun-server.json   # then edit "key"
systemctl daemon-reload && systemctl enable --now kcptun-server

install -m 0644 dist/linux/sysctl_linux /etc/sysctl.d/90-kcptun.conf && sysctl --system
```

The client side is the same with `client` in place of `server`.

`sysctl_linux` raises the socket buffer limits and the device backlog. It is unchanged from Go and
still applies: the ceiling it lifts is what `-sockbuf` asks the kernel for (`SO_SNDBUF`/`SO_RCVBUF`
are capped by `net.core.[rw]mem_max`), which has nothing to do with the language the tunnel is
written in.

Dropped from the two units: `Environment="GOGC=20"` and `Environment="GOEXPERIMENT=greenteagc"`.
Both tune the Go garbage collector, which this build does not have; carrying them over would leave
two settings that do nothing. `GOMAXPROCS` is *not* dropped: the port reads it exactly as Go's
runtime does, to size the tokio worker pool (see the repository `README.md`), and both units have a
commented-out line for it.

## FreeBSD

Upstream's two `rc.conf` scripts run the binary under `/usr/sbin/daemon`; they are kept as they are,
with the paths pointed at `kcptun-client` / `kcptun-server` in `/usr/local/bin` and the
configuration at `/usr/local/etc/kcptun/{client,server}.json`. Release archives also ship the
Go-style names (`client_freebsd_amd64`, DECISIONS D18), so a script written against upstream's line
keeps working. FreeBSD is a best-effort target (DECISIONS D22): nothing here has been run on a
FreeBSD host.

## Not ported

| Upstream file | Why not |
|---|---|
| `linux/debian/*` | `debian/rules` drives `go build`; a Rust package needs a `dh-cargo`-based rules file, a `debian/control` with the Rust build-dependencies and a vendored-crate policy decision. Out of scope for this sub-step, and nothing here can test a `.deb`. |
| `linux/kcptun.spec.rpm` | Same: `%build` is `go build` with `-linkmode=external`, and the spec generates its own unit files inline. |
| `freebsd/kcptun-patch-v20251212.diff`, `freebsd/kcptun-v20251219.patch` | Patches against the Go sources for the FreeBSD ports tree; they have no meaning here. |

Packaging for `.deb`/`.rpm` remains open work; the units, sysctl files and examples above are what
such a package would install.
