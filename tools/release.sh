#!/usr/bin/env bash
# Cross-build kcptun-rust and package the release archives.
#
# Usage: tools/release.sh [OPTIONS] VERSION [TARGET|GROUP ...]
#        tools/release.sh --list
#
#   VERSION         what `-v` prints, e.g. v0.1.0. It is passed to the build as
#                   KCPTUN_VERSION, the Rust equivalent of Go's
#                   `-ldflags "-X main.VERSION=..."` (DECISIONS D18). A stamped build also
#                   drops the `file:line` prefix from every log line, exactly as a stamped Go
#                   build does (`crates/std/src/version.rs`, `is_selfbuild`).
#   TARGET          a Rust target triple from the table below.
#   GROUP           linux-gnu, linux-musl, linux, macos, freebsd, default, all.
#                   Windows is DROPPED (D22, user 2026-09-23: "primarily for linux, forget about
#                   windows completely"). The two rows are kept in the table below so a curious
#                   builder can still ask for them by triple, but no group includes them and
#                   nothing verifies them.
#                   The default is the group `default`: the **glibc** Linux targets, both macOS
#                   targets and FreeBSD x86_64. `linux-musl` builds the static musl artifacts,
#                   which are a documented fallback rather than the default, and `linux` builds
#                   both flavours.
#
#                   Why glibc is the default (DECISIONS D07, SETTLED 2026-09-24 by 11.4b).
#                   This has moved twice before, so here is the run that settles it: one box
#                   (lab-arm64, aarch64, 2 vCPU), one kernel, one netem profile, one set of S1
#                   flags, one churn seed, the workload driver deliberately not redeployed, and
#                   only the allocator changed. Both arms delivered 36.7-36.8 Mbit/s at the same
#                   p50 (103.02 ms) and the same CPU (8.5 % of a core), so throughput is not a
#                   confound:
#                     * static musl peaked at **253 MiB**, released **0 %** after the traffic
#                       stopped and was still ramping at **+44,860 kB/h**;
#                     * glibc peaked at **50 MiB**, fell to **13.6 MiB** within two minutes
#                       (73 % released) and had a *negative* slope of -600 kB/h.
#                   5x in peak, 75x in slope. The earlier musl call came from 13.2c's
#                   single-burst container round at peaks under 20 MB, a regime where musl has
#                   nothing to ratchet; the deployment this port is for is sustained churn,
#                   which is the other regime.
#
#                   ** WARNING about `linux-musl`.** Under sustained churn a static musl build
#                   does not merely keep a high-water mark: it **ramps 32-45 MiB/h and had not
#                   flattened after six hours (79 -> 253 MiB)**. On a 1 GB box that is an OOM
#                   within a day. mallocng has no `malloc_trim` entry point at all, so
#                   `kcptun_kcp::memory::trim` has nothing to call and no amount of idling helps.
#                   Take `linux-musl` only when a single static file that runs on any Linux
#                   matters more than the process ever giving memory back - a short-lived or
#                   low-churn tunnel, or a host with no usable glibc.
#
# Options:
#   -o, --out DIR      output directory (default: build/, *not* dist/, which is tracked
#                      packaging that must never be attached to a release). SHA256SUMS is
#                      written for *every* archive found there afterwards, not only the ones
#                      this run built, so a re-used directory cannot ship an unlisted archive;
#                      use --clean to start from an empty one instead.
#       --clean        remove DIR before building (a stale archive from an earlier version or
#                      target set would otherwise still be attached by release.yml, which
#                      publishes everything under build/)
#       --no-install   do not `rustup target add` a missing target; skip it instead
#       --keep-staging keep build/.staging (debugging only: the publish step of
#                      .github/workflows/release.yml attaches every file under build/)
#       --strict       a skipped or best-effort target is a failure too
#   -l, --list         print the target table and exit
#       --list-groups  print the group names, one per line, and exit
#
# Provenance: a port of `kcptun/build-release.sh` (Go, commit 39935d5307f0) with five
# deliberate differences:
#
#   1. the version is an argument, not `date -u +%Y%m%d`, because a release here is tagged
#      (release.yml demands `v1.2.3`); the Dockerfile keeps Go's date default for image builds;
#   2. checksums are **SHA-256**, not Go's SHA-1;
#   3. the archives carry the licence texts. The binaries are a combined work with the GPL-3.0
#      `crates/qpp` (DECISIONS D19, feature `qpp` is on by default and this script always
#      builds the default features), so LICENSE, NOTICE.md and the full GPL-3.0 text have to
#      travel with them. Upstream ships none;
#   4. no UPX. It would break the static musl binaries' `-v` smoke test for no benefit that a
#      release of a network daemon needs, and it makes the SHA-256 depend on the compressor;
#   5. the archive is named `kcptun-rust-<os>-<arch>[-<variant>]-<version>`, not Go's
#      `kcptun-<os>-<suffix>-<version>` (build-release.sh `package_name`), so a Rust artifact is
#      never mistaken for an upstream one. The file names *inside* are Go's, exactly.
#
# Archive hashes are **not** reproducible: `gzip -n` keeps the name and timestamp out of the
# gzip stream and the member headers carry no ownership, but tar still records every member's
# mtime, so two runs over the same tree produce different SHA-256 sums even when the binaries
# are byte-identical. Compare the per-binary sums in BUILD-INFO.txt to tell a changed build
# from a changed archive.
#
# Archive layout (flat, like Go's):
#
#   kcptun-client / kcptun-server            the real binaries (DECISIONS D18)
#   client_<os>_<arch> / server_<os>_<arch>  Go's names for the same files, so scripts and
#                                            playbooks written for upstream keep working.
#                                            Symlinks in the tarballs; real copies in the
#                                            Windows zips, where symlinks do not survive.
#   LICENSE, NOTICE.md, LICENSE.qpp.GPL-3.0  D19
#   BUILD-INFO.txt                           version, target, toolchain, commit, binary sums
#
# Every packaged binary is inspected (`tools/release-inspect.py`: right architecture, static
# and stripped where that is promised) and, when the host can run it, smoke-tested: `-v` must
# print the stamped version, and a log line must not carry `file:line`.
#
# macOS targets need a macOS host (or a real macOS SDK in SDKROOT). cargo-zigbuild alone is not
# enough: Rust's apple targets link `-framework CoreFoundation` and `-liconv`, and zig only
# bundles `libSystem.tbd`, so the link fails with `unable to find framework 'CoreFoundation'`
# (measured on 2026-09-23 with zig 0.16.0 / cargo-zigbuild 0.23.4, Xcode hidden). That is why
# .github/workflows/release.yml builds the macOS half on a macos runner.
#
# Works with macOS's bash 3.2 (no mapfile, no associative arrays).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build"
INSPECT="$ROOT/tools/release-inspect.py"

# ---------------------------------------------------------------------------------------------
# The target table (DECISIONS D22). Fields:
#
#   rust-triple : goos : goarch : variant : group : zig-target-suffix : tier
#
# `goos`/`goarch` are Go's spelling, because they are what the Go-style binary names in the
# archive are made of (`client_linux_arm64`). `variant` is empty for the flavour a user should
# pick (glibc on Linux, D07) and appears in the archive name otherwise, so the default is
# `kcptun-rust-linux-amd64-<version>.tar.gz` and the static fallback is
# `kcptun-rust-linux-amd64-musl-<version>.tar.gz`. The zig suffix pins the minimum glibc for the
# gnu flavours: without it zig picks its own default, and an artifact that only runs on the
# newest distro is not a release artifact. `tier` is `must` for the targets a release has to
# have, and `best-effort` for the ones D22 marks as such - their failure is reported but does
# not fail the run unless --strict is given.
# ---------------------------------------------------------------------------------------------
TARGETS="
x86_64-unknown-linux-gnu:linux:amd64::linux-gnu:.2.17:must
aarch64-unknown-linux-gnu:linux:arm64::linux-gnu:.2.17:must
armv7-unknown-linux-gnueabihf:linux:arm7::linux-gnu:.2.17:must
arm-unknown-linux-gnueabi:linux:arm6::linux-gnu:.2.17:must
i686-unknown-linux-gnu:linux:386::linux-gnu:.2.17:must
x86_64-unknown-linux-musl:linux:amd64:musl:linux-musl::must
aarch64-unknown-linux-musl:linux:arm64:musl:linux-musl::must
armv7-unknown-linux-musleabihf:linux:arm7:musl:linux-musl::must
arm-unknown-linux-musleabi:linux:arm6:musl:linux-musl::must
i686-unknown-linux-musl:linux:386:musl:linux-musl::must
x86_64-apple-darwin:darwin:amd64::macos::must
aarch64-apple-darwin:darwin:arm64::macos::must
x86_64-pc-windows-gnu:windows:amd64::windows::best-effort
aarch64-pc-windows-gnullvm:windows:arm64::windows::best-effort
x86_64-unknown-freebsd:freebsd:amd64::freebsd::best-effort
"

# D07 (SETTLED 2026-09-24): the default Linux artifacts are glibc; the static musl ones stay
# available as a documented fallback and are built by `all`, by the group `linux`, or by asking
# for `linux-musl`. release.yml asks for both, so neither flavour can rot unnoticed.
GROUP_DEFAULT="linux-gnu macos freebsd"
GROUP_ALL="linux-gnu linux-musl macos freebsd"

# ---------------------------------------------------------------------------------------------
# Small helpers.
# ---------------------------------------------------------------------------------------------
log() { printf '==> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
err() { printf 'release: %s\n' "$1" >&2; }
die() {
  err "$1"
  exit 1
}

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; $d'
}

rows() { printf '%s\n' "$TARGETS" | grep -v '^[[:space:]]*$'; }

field() { printf '%s\n' "$1" | cut -d: -f"$2"; }

row_for() {
  rows | grep "^$1:" || true
}

list_targets() {
  printf '%-32s %-8s %-6s %-9s %-12s %s\n' TRIPLE OS ARCH VARIANT GROUP TIER
  while IFS= read -r row; do
    printf '%-32s %-8s %-6s %-9s %-12s %s\n' \
      "$(field "$row" 1)" "$(field "$row" 2)" "$(field "$row" 3)" \
      "$(field "$row" 4)" "$(field "$row" 5)" "$(field "$row" 7)"
  done <<EOF
$(rows)
EOF
  printf '\ndefault: %s | all: %s\n' "$GROUP_DEFAULT" "$GROUP_ALL"
}

# Every name `group_targets` understands, one per line. `tools/check-workflows.sh` reads this to
# check that .github/workflows/release.yml asks for groups that still exist - that workflow
# cannot be run anywhere yet, so nothing else would notice a rename.
list_groups() {
  rows | cut -d: -f5 | sort -u
  printf '%s\n' linux default all
}

# Expands a group name to its triples; prints nothing for an unknown name.
group_targets() {
  expand=""
  case "$1" in
    linux) expand="linux-gnu linux-musl" ;;
    default) expand="$GROUP_DEFAULT" ;;
    all) expand="$GROUP_ALL" ;;
    *) expand="$1" ;;
  esac
  # shellcheck disable=SC2086  # the group lists are space-separated and must word-split.
  for g in $expand; do
    # A group name expands to its members; anything else has to be a triple from the table.
    if [ -n "$(row_for "$g")" ]; then
      printf '%s\n' "$g"
    else
      rows | awk -F: -v g="$g" '$5 == g { print $1 }'
    fi
  done
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# ---------------------------------------------------------------------------------------------
# Arguments.
# ---------------------------------------------------------------------------------------------
VERSION=""
requested=""
no_install=0
keep_staging=0
strict=0
clean=0

while [ $# -gt 0 ]; do
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    -l | --list)
      list_targets
      exit 0
      ;;
    --list-groups)
      list_groups
      exit 0
      ;;
    -o | --out)
      [ $# -ge 2 ] || die "--out needs a directory"
      OUT="$2"
      shift
      ;;
    --out=*) OUT="${1#--out=}" ;;
    --clean) clean=1 ;;
    --no-install) no_install=1 ;;
    --keep-staging) keep_staging=1 ;;
    --strict) strict=1 ;;
    -*) die "unknown option: $1 (try --help)" ;;
    *)
      if [ -z "$VERSION" ]; then
        VERSION="$1"
      else
        requested="$requested $1"
      fi
      ;;
  esac
  shift
done

[ -n "$VERSION" ] || {
  usage >&2
  exit 2
}
case "$VERSION" in
  *[[:space:]]* | */* | "") die "VERSION must not contain whitespace or '/': '$VERSION'" ;;
  SELFBUILD) die "VERSION must not be SELFBUILD: that is the unstamped build (see D18)" ;;
esac
# Not enforced, only pointed out: release.yml refuses anything but v1.2.3, and a tag is what a
# release is made from. A local build for testing may legitimately use any other string.
case "$VERSION" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) note "note: '$VERSION' is not a vX.Y.Z tag; release.yml would refuse it." ;;
esac

[ -n "$requested" ] || requested="default"

# The archive steps run in a subshell that cds into the staging directory.
case "$OUT" in
  /*) ;;
  *) OUT="$PWD/$OUT" ;;
esac

# Expand groups, keep the table's order, drop duplicates.
selected=""
for want in $requested; do
  expanded="$(group_targets "$want")"
  if [ -z "$expanded" ]; then
    die "unknown target or group: $want (try --list)"
  fi
  for t in $expanded; do
    case " $selected " in
      *" $t "*) ;;
      *) selected="$selected $t" ;;
    esac
  done
done

# ---------------------------------------------------------------------------------------------
# Toolchain.
# ---------------------------------------------------------------------------------------------
command -v cargo >/dev/null 2>&1 || die "cargo is not on PATH"
command -v python3 >/dev/null 2>&1 || die "python3 is not on PATH (tools/release-inspect.py)"
[ -x "$INSPECT" ] || die "missing or not executable: $INSPECT"

HOST_TRIPLE="$(rustc -vV | awk '/^host: / {print $2}')"
HOST_OS="$(uname -s)"
RUSTC_VERSION="$(rustc --version)"
ZIG_VERSION="$(zig version 2>/dev/null || echo 'not installed')"
GIT_COMMIT="$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
if [ -n "$(git -C "$ROOT" status --porcelain 2>/dev/null)" ]; then
  GIT_COMMIT="$GIT_COMMIT-dirty"
fi

have_zigbuild=0
if cargo zigbuild --help >/dev/null 2>&1 && command -v zig >/dev/null 2>&1; then
  have_zigbuild=1
fi

# Space-delimited, with a leading *and* a trailing space, so that the `*" $triple "*` test below
# matches the first and the last entry too. `rustup target list --installed` prints one target
# per line; `tr` supplies the trailing space.
installed_targets=" $(rustup target list --installed 2>/dev/null | tr '\n' ' ' || true)"

# Whether this host can run a binary built for $1 (the triple), so that `-v` and the log-format
# smoke test can be done. Same architecture and same OS only: no emulator is assumed, and a
# musl-static Linux binary runs on any Linux of its architecture.
can_run() {
  host_arch="${HOST_TRIPLE%%-*}"
  target_arch="${1%%-*}"
  [ "$host_arch" = "$target_arch" ] || return 1
  case "$HOST_OS:$1" in
    Darwin:*-apple-darwin) return 0 ;;
    Linux:*-linux-*) return 0 ;;
    FreeBSD:*-freebsd) return 0 ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------------------------
# Build, stage, archive, verify - one target at a time.
# ---------------------------------------------------------------------------------------------
if [ "$clean" -eq 1 ]; then
  rm -rf "$OUT"
fi
mkdir -p "$OUT"
STAGING="$OUT/.staging"
rm -rf "$STAGING"

# bsdtar (the `tar` of a macOS host) stores the extended attributes macOS puts on every file it
# copies - `com.apple.provenance` and friends - as a `PaxHeader` member per file. That is local
# host metadata, and it has no business in a published artifact, so it is turned off wherever
# the flags exist. GNU tar knows `--no-xattrs` but not `--no-mac-metadata`, hence the probe.
# The probe archives a real file, not an empty list: GNU tar refuses to create an empty archive
# and would make every flag look unsupported.
TAR_META_FLAGS=""
for flag in --no-mac-metadata --no-xattrs; do
  if tar "$flag" -cf /dev/null -C "$ROOT" LICENSE >/dev/null 2>&1; then
    TAR_META_FLAGS="$TAR_META_FLAGS $flag"
  fi
done

# Same argument for ownership: tar otherwise records the build host's uid/gid and account name in
# every member header (`-rwxr-xr-x 0 ariyan wheel ... kcptun-client`), which is host metadata a
# published artifact has no use for. bsdtar wants the value as a separate word (`--owner=0`
# misparses there), GNU tar takes either spelling plus `--numeric-owner`; probe the same one file
# both flag sets, and keep them in an array so the empty `--uname`/`--gname` values survive.
TAR_OWNER_FLAGS=()
if tar --uid 0 --gid 0 --uname "" --gname "" -cf /dev/null -C "$ROOT" LICENSE >/dev/null 2>&1; then
  TAR_OWNER_FLAGS=(--uid 0 --gid 0 --uname "" --gname "")
elif tar --owner=0 --group=0 --numeric-owner -cf /dev/null -C "$ROOT" LICENSE >/dev/null 2>&1; then
  TAR_OWNER_FLAGS=(--owner=0 --group=0 --numeric-owner)
fi

built=""
skipped=""
failed=""
failed_best_effort=""
archives=""

build_one() {
  triple="$1"
  row="$(row_for "$triple")"
  [ -n "$row" ] || die "no such target: $triple (try --list)"
  goos="$(field "$row" 2)"
  goarch="$(field "$row" 3)"
  variant="$(field "$row" 4)"
  zigsuffix="$(field "$row" 6)"

  ext=""
  if [ "$goos" = "windows" ]; then ext=".exe"; fi
  name="kcptun-rust-$goos-$goarch"
  if [ -n "$variant" ]; then name="$name-$variant"; fi
  name="$name-$VERSION"

  log "$triple ($goos/$goarch${variant:+, $variant})"

  # -- prerequisites ---------------------------------------------------------------------------
  case "$installed_targets" in
    *" $triple "*) ;;
    *)
      if [ "$no_install" -eq 1 ]; then
        note "rust target $triple is not installed (--no-install): skipping"
        return 2
      fi
      note "rustup target add $triple"
      rustup target add "$triple" >/dev/null 2>&1 || {
        note "rustup cannot install $triple: skipping"
        return 2
      }
      installed_targets="$installed_targets$triple "
      ;;
  esac

  # Which linker driver: the host's own toolchain for a native-OS target, zig for a cross.
  use_zig=1
  if [ "$goos" = "darwin" ]; then
    if [ "$HOST_OS" = "Darwin" ]; then
      use_zig=0 # the system linker already has the SDK, frameworks included
    elif [ -n "${SDKROOT:-}" ]; then
      note "non-macOS host: linking with zig against SDKROOT=$SDKROOT"
    else
      note "macOS targets need a macOS host or a real macOS SDK in SDKROOT: skipping"
      note "(zig bundles libSystem.tbd but no frameworks; Rust's apple std needs CoreFoundation)"
      return 2
    fi
  elif [ "$goos" = "linux" ] && [ "$HOST_OS" = "Linux" ] && [ "$triple" = "$HOST_TRIPLE" ]; then
    use_zig=0
  fi
  if [ "$use_zig" -eq 1 ] && [ "$have_zigbuild" -eq 0 ]; then
    note "cargo-zigbuild and zig are needed to cross-build $triple: skipping"
    note "(cargo install cargo-zigbuild; and install zig 0.13+)"
    return 2
  fi

  # -- build -----------------------------------------------------------------------------------
  # KCPTUN_VERSION is read by `option_env!` in crates/std/src/version.rs; cargo tracks it and
  # rebuilds when it changes, so no clean is needed between two versions.
  if [ "$use_zig" -eq 1 ]; then
    note "cargo zigbuild --release --target $triple$zigsuffix"
    KCPTUN_VERSION="$VERSION" cargo zigbuild --release --locked \
      --target "$triple$zigsuffix" -p kcptun-client -p kcptun-server || return 1
  else
    note "cargo build --release --target $triple"
    KCPTUN_VERSION="$VERSION" cargo build --release --locked \
      --target "$triple" -p kcptun-client -p kcptun-server || return 1
  fi

  bindir="$ROOT/target/$triple/release"
  for b in kcptun-client kcptun-server; do
    [ -f "$bindir/$b$ext" ] || {
      err "$triple: cargo produced no $bindir/$b$ext"
      return 1
    }
  done

  # -- stage -----------------------------------------------------------------------------------
  stage="$STAGING/$triple"
  rm -rf "$stage"
  mkdir -p "$stage"
  members=""
  for b in client server; do
    cp "$bindir/kcptun-$b$ext" "$stage/kcptun-$b$ext"
    chmod 0755 "$stage/kcptun-$b$ext"
    goname="${b}_${goos}_${goarch}$ext"
    if [ "$goos" = "windows" ]; then
      # zip does not carry symlinks to Windows; ship a second copy under the Go name.
      cp "$stage/kcptun-$b$ext" "$stage/$goname"
    else
      ln -s "kcptun-$b$ext" "$stage/$goname"
    fi
    members="$members kcptun-$b$ext $goname"
  done
  cp "$ROOT/LICENSE" "$ROOT/NOTICE.md" "$stage/"
  cp "$ROOT/crates/qpp/LICENSE" "$stage/LICENSE.qpp.GPL-3.0"
  members="$members LICENSE NOTICE.md LICENSE.qpp.GPL-3.0 BUILD-INFO.txt"

  linkage="dynamic"
  case "$triple" in
    *-musl*) linkage="musl, static" ;;
    *-gnu*) linkage="glibc ${zigsuffix#.}+" ;;
    *-apple-darwin) linkage="libSystem" ;;
    *-freebsd) linkage="libc" ;;
  esac
  {
    printf 'kcptun-rust %s\n\n' "$VERSION"
    printf 'target:    %s (%s/%s, %s)\n' "$triple" "$goos" "$goarch" "$linkage"
    printf 'commit:    %s\n' "$GIT_COMMIT"
    printf 'toolchain: %s\n' "$RUSTC_VERSION"
    if [ "$use_zig" -eq 1 ]; then
      printf '           zig %s (linker)\n' "$ZIG_VERSION"
    fi
    printf 'features:  default (qpp)\n\n'
    printf 'kcptun-client and kcptun-server are the binaries; client_%s_%s and server_%s_%s\n' \
      "$goos" "$goarch" "$goos" "$goarch"
    printf 'are the same files under the names Go kcptun uses.\n\n'
    printf 'This build includes the Quantum Permutation Pad (crates/qpp), a port of the\n'
    printf 'GPL-3.0 xtaci/qpp, so the binaries are a combined work licensed GPL-3.0; see\n'
    printf 'LICENSE.qpp.GPL-3.0. Everything else is MIT (LICENSE, NOTICE.md).\n\n'
    printf 'SHA-256:\n'
    for b in client server; do
      printf '  %s  %s\n' "$(sha256_of "$stage/kcptun-$b$ext")" "kcptun-$b$ext"
    done
  } >"$stage/BUILD-INFO.txt"

  # -- verify ----------------------------------------------------------------------------------
  verify_binaries "$triple" "$stage" "$ext" || return 1

  # -- archive ---------------------------------------------------------------------------------
  if [ "$goos" = "windows" ]; then
    command -v zip >/dev/null 2>&1 || {
      err "$triple: zip is not on PATH"
      return 1
    }
    archive="$OUT/$name.zip"
    rm -f "$archive"
    # shellcheck disable=SC2086  # members is a file list and must word-split.
    (cd "$stage" && zip -q -X "$archive" $members) || return 1
  else
    archive="$OUT/$name.tar.gz"
    rm -f "$archive"
    # `gzip -n` keeps the name and timestamp of the *stream* out of the file; the members' mtimes
    # are still there, so the archive hash is not reproducible (see the header).
    # COPYFILE_DISABLE and TAR_META_FLAGS keep macOS's per-file xattrs out of it, and
    # TAR_OWNER_FLAGS keeps the build account's uid/gid and name out of the member headers.
    # shellcheck disable=SC2086  # members and TAR_META_FLAGS are lists and must word-split.
    (cd "$stage" && COPYFILE_DISABLE=1 tar $TAR_META_FLAGS ${TAR_OWNER_FLAGS[@]+"${TAR_OWNER_FLAGS[@]}"} -cf - $members |
      gzip -n -9 >"$archive") || return 1
  fi
  archives="$archives $archive"
  note "$(basename "$archive") ($(sha256_of "$archive" | cut -c1-16)…, $(wc -c <"$archive" | tr -d ' ') bytes)"
  return 0
}

# Checks the two staged binaries: format, architecture, linkage, and - when this host can run
# them - that the version really was stamped in and that the log lines lost their `file:line`.
verify_binaries() {
  triple="$1"
  stage="$2"
  ext="$3"

  arch="${triple%%-*}"
  inspect_args="--format elf --arch $arch --stripped"
  case "$triple" in
    *-apple-darwin) inspect_args="--format macho --arch $arch" ;;
    *-windows-*) inspect_args="--format pe --arch $arch" ;;
    # A musl archive holding a dynamically linked binary would need a loader the target host
    # may not have, which is the one thing the static fallback promises never to need.
    *-musl*) inspect_args="$inspect_args --static" ;;
    # And the gnu artifacts are the default ones (D07) precisely because they use the host's
    # glibc, whose `malloc_trim` hands a burst back. A gnu archive holding a static binary is a
    # mis-packaged release, not a bonus: it would silently be a musl-grade artifact.
    *-linux-gnu*) inspect_args="$inspect_args --dynamic" ;;
  esac

  for b in client server; do
    bin="$stage/kcptun-$b$ext"
    # shellcheck disable=SC2086  # inspect_args is a flag list and must word-split.
    if ! described="$(python3 "$INSPECT" "$bin" $inspect_args)"; then
      err "$triple: kcptun-$b$ext failed inspection"
      return 1
    fi
    note "${described#"$stage/"}"
  done

  can_run "$triple" || {
    note "smoke test skipped: this host cannot run $triple binaries"
    return 0
  }

  # Neither invocation is supposed to reach a socket - `-v` prints and exits, and a missing
  # config file is fatal in `check_error` - but a release script must not be the thing that
  # leaves a daemon running if that ever changes, so bound them when the host has a `timeout`.
  TO=""
  command -v timeout >/dev/null 2>&1 && TO="timeout 30"
  command -v gtimeout >/dev/null 2>&1 && TO="gtimeout 30"

  for b in client server; do
    bin="$stage/kcptun-$b$ext"
    # 1. The version has to be the one asked for. An unstamped binary prints SELFBUILD.
    # shellcheck disable=SC2086  # $TO is a command prefix or empty and must word-split.
    got="$($TO "$bin" -v 2>&1 || true)"
    [ "$got" = "kcptun version $VERSION" ] || {
      err "$triple: kcptun-$b -v printed '$got', expected 'kcptun version $VERSION'"
      return 1
    }
    # 2. A stamped build must not log `file:line` (Go adds log.Lshortfile only for SELFBUILD).
    #    `-c` on a file that is not there fails in `check_error`, which is the log path every
    #    startup error takes, and exits without opening a socket.
    # shellcheck disable=SC2086  # $TO is a command prefix or empty and must word-split.
    line="$($TO "$bin" -c "$stage/definitely-not-a-config.json" 2>&1 | head -1 || true)"
    case "$line" in
      [0-9][0-9][0-9][0-9]/[0-9][0-9]/[0-9][0-9]\ [0-9][0-9]:[0-9][0-9]:[0-9][0-9]\ *) ;;
      *)
        err "$triple: kcptun-$b logged '$line', which has no Go log header"
        return 1
        ;;
    esac
    case "$line" in
      *.rs:[0-9]*:*)
        err "$triple: kcptun-$b still logs file:line ('$line'): the build is not stamped"
        return 1
        ;;
    esac
    note "smoke: kcptun-$b$ext -v and log format OK"
  done
  return 0
}

# ---------------------------------------------------------------------------------------------
# Run.
# ---------------------------------------------------------------------------------------------
log "kcptun-rust $VERSION -> $OUT"
note "host: $HOST_TRIPLE ($HOST_OS), $RUSTC_VERSION, zig $ZIG_VERSION, commit $GIT_COMMIT"
case "$GIT_COMMIT" in
  *-dirty)
    note "WARNING: the working tree is dirty; this is not a reproducible release build"
    # Name the offending paths. Without this the warning is unactionable, which is how a
    # published release came to be stamped -dirty with nobody able to say why.
    git -C "$ROOT" status --porcelain | head -20 | while IFS= read -r line; do
      note "  dirty: $line"
    done
    ;;
esac

for triple in $selected; do
  rc=0
  build_one "$triple" || rc=$?
  case "$rc" in
    0) built="$built $triple" ;;
    2) skipped="$skipped $triple" ;;
    *)
      if [ "$(field "$(row_for "$triple")" 7)" = "best-effort" ]; then
        failed_best_effort="$failed_best_effort $triple"
        note "FAILED (best effort, D22): $triple"
      else
        failed="$failed $triple"
        note "FAILED: $triple"
      fi
      ;;
  esac
done

# ---------------------------------------------------------------------------------------------
# Checksums and summary.
# ---------------------------------------------------------------------------------------------
# Over *every* archive in $OUT, not only the ones this run produced: release.yml attaches all of
# build/, so an archive left behind by an earlier run (another version, another target set) must
# either be listed here or not be there at all. --clean is the way to not have it there.
if [ -n "$archives" ]; then
  sums="$OUT/SHA256SUMS"
  : >"$sums"
  for a in "$OUT"/*.tar.gz "$OUT"/*.zip; do
    [ -f "$a" ] || continue # an unmatched glob is the literal pattern
    case " $archives " in
      *" $a "*) ;;
      *) note "WARNING: $(basename "$a") is left over from an earlier run (see --clean)" ;;
    esac
    printf '%s  %s\n' "$(sha256_of "$a")" "$(basename "$a")" >>"$sums"
  done
  log "SHA256SUMS"
  cat "$sums"
fi

if [ "$keep_staging" -eq 0 ]; then
  rm -rf "$STAGING"
else
  note "staging kept in $STAGING - remove it before publishing (release.yml attaches all of $OUT)"
fi

log "summary"
note "built:      ${built:- none}"
if [ -n "$skipped" ]; then note "skipped:   $skipped"; fi
if [ -n "$failed_best_effort" ]; then note "failed (best effort): $failed_best_effort"; fi
if [ -n "$failed" ]; then note "FAILED:     $failed"; fi

status=0
if [ -n "$failed" ] || [ -z "$built" ]; then status=1; fi
if [ "$strict" -eq 1 ] && { [ -n "$skipped" ] || [ -n "$failed_best_effort" ]; }; then
  status=1
fi
exit "$status"
