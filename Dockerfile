# kcptun-rust container image.
#
# Port of kcptun/Dockerfile (Go, commit 39935d5307f0). The contract the Go image established is
# kept exactly, so existing `docker run` command lines work unchanged:
#
#   * the client is at /bin/client and the server at /bin/server;
#   * no ENTRYPOINT and no CMD, so the binary is named on the command line;
#   * EXPOSE 29900/udp (the server's default -listen) and 12948 (the client's default -localaddr);
#   * the runtime carries iptables, which `-tcp` (fake-TCP) needs.
#
#   docker build -t kcptun-rust .
#   docker run -d -p 29900:29900/udp kcptun-rust /bin/server -t "10.0.0.1:8080" -l ":29900" \
#       -mode fast3 -key PASSWORD
#   docker run -d -p 12948:12948 kcptun-rust /bin/client -r "SERVER:29900" -l ":12948" \
#       -mode fast3 -key PASSWORD
#
# Differences from the Go image, all deliberate:
#
#   * it builds the *build context* instead of `git clone`ing the upstream repository, so the
#     image is reproducible from the tree it was built from (upstream's clone always builds
#     master, whatever the checkout says);
#   * the real binaries carry the names of DECISIONS D18, kcptun-client and kcptun-server, and
#     /bin/client and /bin/server are symlinks to them, so both names work. The usage line comes
#     from argv[0] in Go too (`App.HelpName` = `filepath.Base(os.Args[0])`, ported as
#     `std::cli::filepath_base`), so `/bin/client -h` prints `USAGE: client …`, exactly like the
#     Go image;
#   * it ships the licence texts the GPL-3.0 `crates/qpp` obliges (D19); upstream's image ships
#     none;
#   * the default runtime is debian:bookworm-slim rather than the Go image's alpine:3.18. The
#     Alpine image is still here, one `--target` away; the libc is the reason, and it is below.
#
# ---------------------------------------------------------------------------------------------
# TWO IMAGES FROM ONE FILE (DECISIONS D07, SETTLED 2026-09-24 by 11.4b)
# ---------------------------------------------------------------------------------------------
#
#   docker build -t kcptun-rust .                       # DEFAULT: debian:bookworm-slim, glibc
#   docker build --target musl -t kcptun-rust:musl .    # the fallback: alpine:3.21, static musl
#
# BuildKit - the default builder since Docker 23 - builds only the stages its target depends on,
# so the default build never enters the musl stages, and `--target musl` never enters the glibc
# ones.
#
# **The default is the glibc image.** The default has moved twice before (13.2c to glibc, 12.3e
# back to musl), so here is the run that settles it, in full. 11.4b held *everything* constant on
# ONE box - lab-arm64, aarch64, 2 vCPU, one kernel, one netem profile, one set of S1 flags, one
# churn seed, and the workload driver deliberately not redeployed - and changed only the
# allocator. Both arms delivered 36.7-36.8 Mbit/s at p50 103.02 ms and 8.5 % of one core, so the
# throughput confound does not exist:
#
#   | lab-arm64 client, production-shaped churn | static musl (mallocng) |    glibc 2.17 |
#   |------------------------------------------|-----------------------:|--------------:|
#   | peak RSS (VmHWM)                         |              253.0 MiB |      50.3 MiB |
#   | RSS two minutes after the traffic stops  |              253.0 MiB |      13.6 MiB |
#   | returned to the kernel                   |                    0 % |          73 % |
#   | RSS slope, 2160-7200 s                   |           +44,860 kB/h |     -600 kB/h |
#
# 5x in peak, 75x in slope. 13.2c's container round - the measurement that put the default on
# musl - was a **single burst at small scale** inside Docker Desktop's VM, with peaks under
# 20 MB: a regime where musl has nothing to ratchet, so it looked cheaper. A tunnel container in
# the deployment this port was written for is the other regime, long-running and continuously
# churning, and there musl loses by an order of magnitude.
#
# ** WARNING before reaching for `--target musl`.** Under sustained churn a static musl build
# does not merely keep a high-water mark: it **ramps 32-45 MiB/h and had not flattened after six
# hours (79 -> 253 MiB)**. On a 1 GB host that is an OOM within a day. mallocng has no
# `malloc_trim` entry point at all, so `kcptun_kcp::memory::trim` has nothing to call and no
# amount of idling helps. The musl image is for a host with no usable glibc, or a tunnel
# short-lived enough that a monotone ramp never matters - not a smaller-is-better default. It is
# a supported image and not a leftover: `tools/check-dist.sh` holds its two stages to the same
# drop-in contract, and to the same libc pairing, as the default ones.
#
# Size of this tree's images, measured on linux/arm64 2026-09-24 (`docker images` for the disk
# figure, `docker save | wc -c` for the transfer one):
#
#   | image                       | on disk | to pull |
#   |-----------------------------|--------:|--------:|
#   | this image (debian + glibc) |  155 MB | 31.7 MB |
#   | this image, --target musl   | 30.5 MB |  7.4 MB |
#   | upstream Go (aguegu/kcptun) | 62.9 MB | 19.3 MB |
#
# This image is built and exercised, not merely linted: `tools/image-interop.sh` pushes 20 MB of
# SHA-256-verified data through a real tunnel in all four pairings against the upstream Go image,
# for both smux versions, and the `dist` job of .github/workflows/ci.yml runs it alongside
# `tools/check-dist.sh`, hadolint and a smoke test of both names of both binaries.

# ---------------------------------------------------------------------------------------------
# The static-musl fallback, `docker build --target musl` - kept buildable rather than only
# described, because D07 keeps it supported for a host with no usable glibc (see the header).
# This stage and the one after it are the alternative image; the default one resumes at the next
# divider.
#
# The tag must match rust-toolchain.toml's channel; tools/check-dist.sh enforces that for every
# builder stage, and also holds each builder and its runtime to the same libc, so a dynamically
# linked binary can never meet a libc older than the one it was built against.
# ---------------------------------------------------------------------------------------------
FROM rust:1.98.1-alpine AS musl-builder

# build-base gives gcc, musl-dev and make: the musl target needs musl-dev to link. That is the
# linker's requirement, not a dependency's - nothing in the default feature set compiles C
# (D07 rejected the mimalloc allocator, D27 rejected aws-lc-rs).
# rustfmt and clippy come from rust-toolchain.toml's component list; the official image ships
# the "minimal" profile, so add them here instead of letting the first cargo command stop to
# download them.
# hadolint ignore=DL3018
RUN apk add --no-cache build-base && rustup component add rustfmt clippy

WORKDIR /src
COPY . .

ARG KCPTUN_VERSION=""
RUN set -eu; \
    : "${KCPTUN_VERSION:=$(date -u +%Y%m%d)}"; \
    export KCPTUN_VERSION; \
    cargo build --release --locked -p kcptun-client -p kcptun-server

FROM alpine:3.21 AS musl

LABEL org.opencontainers.image.source=https://github.com/ariansharifi/kcptun-rust
LABEL org.opencontainers.image.description="A Rust port of kcptun: a TCP-over-KCP tunnel (static musl)"
LABEL org.opencontainers.image.licenses="MIT AND GPL-3.0-or-later"

# `-tcp` opens a raw socket and installs an iptables rule that drops the kernel's RSTs for the
# fake-TCP flow (crates/tcpraw); without iptables in the image that mode cannot work. As
# upstream, the version is not pinned: an alpine base image is only as old as its rebuild.
# hadolint ignore=DL3018
RUN apk add --no-cache iptables

COPY --from=musl-builder /src/target/release/kcptun-client /bin/kcptun-client
COPY --from=musl-builder /src/target/release/kcptun-server /bin/kcptun-server

# D19, as in the default image.
COPY --from=musl-builder /src/LICENSE /usr/share/licenses/kcptun-rust/LICENSE
COPY --from=musl-builder /src/NOTICE.md /usr/share/licenses/kcptun-rust/NOTICE.md
COPY --from=musl-builder /src/crates/qpp/LICENSE /usr/share/licenses/kcptun-rust/LICENSE.qpp.GPL-3.0
# The Go image's paths. Relative targets, so they resolve whether /bin is a directory or a
# symlink into /usr/bin.
RUN ln -s kcptun-client /bin/client && ln -s kcptun-server /bin/server

EXPOSE 29900/udp
EXPOSE 12948

# ---------------------------------------------------------------------------------------------
# Default builder: glibc.
#
# `rust:<channel>-slim-bookworm` and `debian:bookworm-slim` are the same Debian 12 release and so
# carry the same glibc (2.36). That pairing is not cosmetic - a dynamically linked binary needs a
# runtime glibc at least as new as the one it was built against - and tools/check-dist.sh
# enforces it. (The musl pair above needs no such pairing: its binaries are static, so the
# runtime's libc never runs.)
# ---------------------------------------------------------------------------------------------
FROM rust:1.98.1-slim-bookworm AS builder

# Unlike the Alpine builder, this stage installs no packages: the Debian rust images already
# carry gcc and libc6-dev, which is all the gnu target needs in order to link, and nothing in
# the default feature set compiles C.
RUN rustup component add rustfmt clippy

WORKDIR /src
COPY . .

# Stamps the version `-v` prints, like Go's `-ldflags "-X main.VERSION=…"`. Empty means "the UTC
# build date", which is what the Go image does (`-X main.VERSION=$(date -u +%Y%m%d)`); pass
# `--build-arg KCPTUN_VERSION=v0.1.0` for a real release. Leaving it unset entirely would make
# the binaries report SELFBUILD and log file:line, which is not what a release image wants.
ARG KCPTUN_VERSION=""
RUN set -eu; \
    : "${KCPTUN_VERSION:=$(date -u +%Y%m%d)}"; \
    export KCPTUN_VERSION; \
    cargo build --release --locked -p kcptun-client -p kcptun-server

# ---------------------------------------------------------------------------------------------
# Default runtime: debian:bookworm-slim + the glibc binaries. Last stage in the file, so a plain
# `docker build .` produces this one.
# ---------------------------------------------------------------------------------------------
FROM debian:bookworm-slim

LABEL org.opencontainers.image.source=https://github.com/ariansharifi/kcptun-rust
LABEL org.opencontainers.image.description="A Rust port of kcptun: a TCP-over-KCP tunnel"
LABEL org.opencontainers.image.licenses="MIT AND GPL-3.0-or-later"

# The same job as the musl runtime's `apk add iptables`, in Debian's spelling.
# `--no-install-recommends` holds it to the netfilter libraries it actually needs, and the apt
# lists go again so they are not carried in a layer. Both bases drive the same backend (Alpine
# 3.21 ships xtables-nft-multi, Debian 12 points the `iptables` alternative at iptables-nft), so
# `-tcp` behaves the same in either image. As upstream, the version is not pinned: a base image
# is only as old as its rebuild.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/kcptun-client /bin/kcptun-client
COPY --from=builder /src/target/release/kcptun-server /bin/kcptun-server

# The binaries are a combined work with the GPL-3.0 crates/qpp (DECISIONS D19, feature `qpp` is
# on by default), so the image has to carry the licence texts. Upstream's image ships none.
COPY --from=builder /src/LICENSE /usr/share/licenses/kcptun-rust/LICENSE
COPY --from=builder /src/NOTICE.md /usr/share/licenses/kcptun-rust/NOTICE.md
COPY --from=builder /src/crates/qpp/LICENSE /usr/share/licenses/kcptun-rust/LICENSE.qpp.GPL-3.0
# The Go image's paths. Relative targets, so they resolve whether /bin is a directory or - as
# here - a symlink into /usr/bin (Debian's merged-/usr layout). One inherited difference is
# recorded rather than papered over: this base's own default command is bash where Alpine's is
# /bin/sh. Nothing documented depends on it, because neither image declares a CMD.
RUN ln -s kcptun-client /bin/client && ln -s kcptun-server /bin/server

EXPOSE 29900/udp
EXPOSE 12948
