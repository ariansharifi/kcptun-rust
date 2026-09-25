#!/usr/bin/env bash
# Check the container image and the dist/ files against the repository they describe.
#
# Usage: tools/check-dist.sh
#
# The image itself is built and exercised elsewhere - `docker build` plus `tools/image-interop.sh`
# locally, and the `dist` job of .github/workflows/ci.yml on every push. The dist/ files cannot be
# exercised at all without a systemd or FreeBSD host. What this script checks, without a Docker
# daemon, is that both still agree with the tree and with the Go image's contract, which is what
# makes this port a drop-in:
#
#   1. the Dockerfile keeps the Go image's interface (/bin/client, /bin/server, EXPOSE
#      29900/udp and 12948, iptables in the runtime stage, the D19 licence texts, no ENTRYPOINT
#      and no CMD) in **both** of the images it builds - the default glibc one and the static
#      musl one D07 keeps as a documented fallback (`docker build --target musl`) - that each is
#      built on the libc its base image promises, and that everything it builds or copies exists
#      in this tree;
#   2. .dockerignore keeps the build context small without dropping a file the Dockerfile needs;
#   3. the systemd units point at binaries this workspace produces, and carry none of the Go
#      runtime environment the port cannot honour;
#   4. the files that are byte-for-byte copies of upstream's still are (only when reference/ is
#      present - it is fetched by tools/fetch-reference.sh and is not part of the repository);
#   5. `hadolint` passes, if it is installed (https://github.com/hadolint/hadolint).
#
# The example configurations are checked by `cargo test -p kcptun-std` (config::tests::dist_*),
# which parses them with the real parser.
#
# Works with macOS's bash 3.2 (no mapfile, no associative arrays).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOCKERFILE="$ROOT/Dockerfile"
DOCKERIGNORE="$ROOT/.dockerignore"

fail=0
err() {
  printf 'check-dist: %s\n' "$1" >&2
  fail=1
}
log() { printf '==> %s\n' "$*"; }

for f in Dockerfile .dockerignore dist/README.md \
  dist/local.json.example dist/server.json.example \
  dist/linux/kcptun-client.service dist/linux/kcptun-server.service dist/linux/sysctl_linux \
  dist/freebsd/kcptun-client.rc.conf dist/freebsd/kcptun-server.rc.conf \
  dist/freebsd/sysctl_freebsd; do
  [[ -f "$ROOT/$f" ]] || err "missing file: $f"
done
[[ $fail -eq 0 ]] || exit 1

# ---------------------------------------------------------------------------------------------
# 1. Both images keep the Go image's interface.
#
# The file builds two: the default one (`docker build .`, debian:bookworm-slim + glibc) and the
# one D07 keeps as a fallback for a host with no usable glibc (`docker build --target musl`). The
# contract is checked per runtime stage rather than per file, because a file-wide grep would be
# satisfied by whichever stage still had the line.
# ---------------------------------------------------------------------------------------------
log "both runtime stages keep the Go image's interface"

# Upstream declares neither an ENTRYPOINT nor a CMD, so the binary is named on the command line.
# Adding one would change what `docker run <image> /bin/server …` means.
if grep -qE '^[[:space:]]*(ENTRYPOINT|CMD)[[:space:]]' "$DOCKERFILE"; then
  err "Dockerfile declares an ENTRYPOINT or CMD; the Go image has neither"
fi

# Multi-stage: a builder and a slim runtime, twice over.
stages="$(grep -cE '^FROM ' "$DOCKERFILE" || true)"
[[ "$stages" -ge 2 ]] || err "Dockerfile is not multi-stage (found $stages FROM lines)"
grep -qE '^FROM .* AS builder$' "$DOCKERFILE" || err "Dockerfile has no 'AS builder' stage"

# The lines of one stage: its FROM line and everything up to the next one. `LAST` selects the
# final stage, which is what a plain `docker build .` produces.
stage_body() {
  if [[ "$1" == LAST ]]; then
    awk '/^FROM /{buf = ""} {buf = buf $0 "\n"} END{printf "%s", buf}' "$DOCKERFILE"
  else
    awk -v re="$1" '/^FROM /{f = ($0 ~ re)} f' "$DOCKERFILE"
  fi
}

check_runtime_contract() {
  local what="$1" body="$2" path licences
  # The two paths existing `docker run` command lines name.
  for path in /bin/client /bin/server; do
    printf '%s\n' "$body" | grep -qF -- "$path" ||
      err "$what no longer provides $path; upstream's docker run command lines would break"
  done
  printf '%s\n' "$body" | grep -qE '^EXPOSE 29900/udp' || err "$what has lost 'EXPOSE 29900/udp'"
  printf '%s\n' "$body" | grep -qE '^EXPOSE 12948' || err "$what has lost 'EXPOSE 12948'"
  # `-tcp` (fake-TCP) shells out to iptables, so a runtime stage has to carry it - whichever
  # package manager its base image happens to use.
  printf '%s\n' "$body" | grep -qE '(apk add|apt-get install)[^&|]*iptables' ||
    err "$what no longer installs iptables, which -tcp needs"
  # The binaries are a combined work with the GPL-3.0 crates/qpp, so every image has to carry the
  # three licence texts (D19).
  licences="$(printf '%s\n' "$body" | grep -c '/usr/share/licenses/kcptun-rust/' || true)"
  [[ "$licences" -ge 3 ]] ||
    err "$what copies $licences of the 3 licence texts D19 requires to /usr/share/licenses"
}

check_runtime_contract "the default runtime stage" "$(stage_body LAST)"

musl_runtime_body="$(stage_body '^FROM .* AS musl$')"
if [[ -z "$musl_runtime_body" ]]; then
  err "the Dockerfile has no 'AS musl' stage; D07 keeps the static musl image supported and buildable (docker build --target musl)"
else
  check_runtime_contract "the musl runtime stage (--target musl)" "$musl_runtime_body"
fi

# Every builder image must be the toolchain rust-toolchain.toml pins.
channel="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml")"
[[ -n "$channel" ]] || err "rust-toolchain.toml has no channel"
while IFS= read -r from_line; do
  case "$from_line" in
    "FROM rust:${channel}-"* | "FROM rust:${channel}@"* | "FROM rust:${channel} "*) ;;
    *) err "builder stage '$from_line' is not rust:$channel, the toolchain rust-toolchain.toml pins" ;;
  esac
done <<EOF
$(grep -E '^FROM rust:' "$DOCKERFILE")
EOF
grep -qE "^FROM rust:${channel}(-|@| )" "$DOCKERFILE" ||
  err "no builder stage is rust:$channel, the toolchain rust-toolchain.toml pins"

# ---------------------------------------------------------------------------------------------
# 1b. The libc each image ships (DECISIONS D07: the image went to glibc in 13.2c, back to musl in
#     12.3e and to glibc again in 12.3f once 11.4b settled it, which is why this is pinned rather
#     than left to whoever next edits a FROM line).
# ---------------------------------------------------------------------------------------------
log "the default image is the glibc build, and each stage pair agrees on its libc"

builder_from="$(sed -n 's/^FROM \(.*\) AS builder$/\1/p' "$DOCKERFILE" | tail -1)"
runtime_from="$(grep -E '^FROM ' "$DOCKERFILE" | tail -1 | sed 's/^FROM //')"
musl_builder_from="$(sed -n 's/^FROM \(.*\) AS musl-builder$/\1/p' "$DOCKERFILE" | tail -1)"
musl_runtime_from="$(sed -n 's/^FROM \(.*\) AS musl$/\1/p' "$DOCKERFILE" | tail -1)"

is_musl_base() {
  case "$1" in
    *alpine* | *musl*) return 0 ;;
  esac
  return 1
}

# D07 as settled (2026-09-24, 11.4b): the default image is the **glibc** one. One box, one
# kernel, one netem profile, one set of flags, one churn seed, only the allocator changed - and
# static musl peaked at 253 MiB, released 0 % after the traffic stopped and was still ramping at
# +44,860 kB/h, where glibc peaked at 50 MiB, fell to 13.6 MiB and had a slope of -600 kB/h. The
# 13.2c container round that put this on musl measured a single burst at under 20 MB of peak,
# where mallocng has nothing to ratchet; sustained churn is the regime that matters here.
if is_musl_base "$runtime_from"; then
  err "the default runtime stage is '$runtime_from', a musl base; D07 makes the glibc image the default (the static musl one is 'docker build --target musl')"
fi
if is_musl_base "$builder_from"; then
  err "the default builder stage is '$builder_from', a musl base; its default target is what lands in the default image (D07)"
fi

# The default pair has to stay glibc, and its two stages have to come from the same distribution
# release - a dynamically linked binary needs a runtime glibc at least as new as the one it was
# built against, which both image names spell out (rust:1.98.1-slim-bookworm, debian:bookworm-slim).
# Add a release here when one of the bases moves; silently failing to recognise it would turn this
# check off. (The musl pair needs no such pairing: its binaries are static, so the runtime's libc
# never runs - which is the whole of what the fallback is for.)
known_suites="bookworm trixie forky bullseye noble jammy plucky"
suite_of() {
  local name="$1" suite
  for suite in $known_suites; do
    case "$name" in *"$suite"*)
      printf '%s' "$suite"
      return 0
      ;;
    esac
  done
  return 1
}
if ! builder_suite="$(suite_of "$builder_from")"; then
  err "cannot tell which distribution '$builder_from' is; add its release to known_suites"
elif ! runtime_suite="$(suite_of "$runtime_from")"; then
  err "cannot tell which distribution '$runtime_from' is; add its release to known_suites"
elif [[ "$builder_suite" != "$runtime_suite" ]]; then
  err "the default builder is $builder_suite but its runtime is $runtime_suite; a binary built against a newer glibc than the runtime's fails to start with 'version GLIBC_2.x not found'"
fi

# And the musl fallback has to stay musl and stay present: an option nobody can build is a lie in
# the documentation, and one that quietly became dynamic would need a loader the host may lack.
if [[ -z "$musl_builder_from" || -z "$musl_runtime_from" ]]; then
  err "the musl fallback needs both an 'AS musl-builder' and an 'AS musl' stage (D07)"
elif ! is_musl_base "$musl_builder_from" || ! is_musl_base "$musl_runtime_from"; then
  err "the musl stages are '$musl_builder_from' / '$musl_runtime_from', not musl bases; --target musl would not be the static image D07 documents"
fi

# A release build, from the lockfile, of packages that exist - in every builder stage.
build_lines="$(grep -E '^[[:space:]]*cargo build ' "$DOCKERFILE" || true)"
[[ -n "$build_lines" ]] || err "Dockerfile runs no 'cargo build'"
while IFS= read -r build_line; do
  [[ -n "$build_line" ]] || continue
  case "$build_line" in
    *--release*) ;;
    *) err "a stage is not built with --release: $build_line" ;;
  esac
  case "$build_line" in
    *--locked*) ;;
    *) err "a stage is not built with --locked; it would ignore Cargo.lock: $build_line" ;;
  esac
  # Each stage's flavour is its base image's default target (see 1b). An explicit --target would
  # change the libc a stage produces without touching the FROM line this script reads, which is
  # exactly the accident the pinning is here to prevent.
  case "$build_line" in
    *--target*)
      err "a cargo build line passes --target; each stage's libc must be its base image's (D07): $build_line"
      ;;
  esac
  for pkg in $(printf '%s\n' "$build_line" | tr ' ' '\n' | grep -A1 -x -- '-p' | grep -v -x -- '-p'); do
    grep -qx "name = \"$pkg\"" "$ROOT"/crates/*/Cargo.toml ||
      err "the image builds -p $pkg, which is not a package in crates/"
  done
done <<EOF
$build_lines
EOF

# Everything copied out of a builder's source tree has to be in the tree. (target/… is the
# build output and only exists inside the image.)
copied="$(sed -n 's|^COPY --from=[a-z0-9-]*builder /src/\([^ ]*\) .*|\1|p' "$DOCKERFILE")"
for f in $copied; do
  case "$f" in
    target/*) continue ;;
  esac
  [[ -e "$ROOT/$f" ]] || err "Dockerfile copies $f out of the builder, but it is not in the tree"
done

# ---------------------------------------------------------------------------------------------
# 2. .dockerignore: small context, nothing missing.
# ---------------------------------------------------------------------------------------------
log ".dockerignore keeps the context small without dropping a needed file"

# Docker's rules, near enough for the simple patterns used here: every pattern is matched against
# the whole path, a match on a parent directory excludes what is below it, `!` re-includes, and
# the last matching pattern wins. Bash's `==` glob lets `*` cross a `/`, which only makes this
# check stricter than docker.
ignored() {
  local path="$1" line pat verdict=1
  while IFS= read -r line; do
    case "$line" in '' | '#'*) continue ;; esac
    if [[ "$line" == '!'* ]]; then
      pat="${line#!}"
      # shellcheck disable=SC2053  # glob match is the point
      if [[ "$path" == $pat || "$path" == ${pat%/}/* ]]; then verdict=1; fi
    else
      pat="$line"
      # shellcheck disable=SC2053
      if [[ "$path" == $pat || "$path" == ${pat%/}/* ]]; then verdict=0; fi
    fi
  done <"$DOCKERIGNORE"
  return $verdict
}

# What `cargo build --locked -p kcptun-client -p kcptun-server` and the licence copies need.
needed="Cargo.toml Cargo.lock rust-toolchain.toml clippy.toml crates/std/src/lib.rs
crates/client/src/main.rs crates/server/src/main.rs crates/qpp/src/lib.rs LICENSE NOTICE.md
crates/qpp/LICENSE"
for f in $needed; do
  [[ -e "$ROOT/$f" ]] || continue # a file a later step adds; nothing to protect yet
  if ignored "$f"; then
    err ".dockerignore excludes $f, which the image build needs"
  fi
done

# What must never reach the daemon: build output, fuzz corpora (hundreds of megabytes) and the
# reference checkout, which is a symlink out of the tree.
for f in target/release/kcptun-server crates/tcpraw/fuzz/corpus reference/kcptun .git/config; do
  ignored "$f" || err ".dockerignore does not exclude $f; the build context would carry it"
done

# ---------------------------------------------------------------------------------------------
# 3. The systemd units match the binaries this workspace builds.
# ---------------------------------------------------------------------------------------------
log "systemd units match the workspace's binaries"

for side in client server; do
  unit="$ROOT/dist/linux/kcptun-$side.service"
  exec_start="$(sed -n 's/^ExecStart=//p' "$unit")"
  [[ -n "$exec_start" ]] || err "kcptun-$side.service has no ExecStart"
  bin="$(printf '%s\n' "$exec_start" | awk '{print $1}')"
  case "$bin" in
    "/usr/bin/kcptun-$side") ;;
    *) err "kcptun-$side.service starts $bin; DECISIONS D18 names the binary kcptun-$side" ;;
  esac
  grep -qx "name = \"kcptun-$side\"" "$ROOT/crates/$side/Cargo.toml" ||
    err "no [[bin]] named kcptun-$side in crates/$side/Cargo.toml"
  case "$exec_start" in
    *"-c /etc/kcptun-$side.json"*) ;;
    *) err "kcptun-$side.service no longer reads /etc/kcptun-$side.json (upstream's path)" ;;
  esac
  for section in '[Unit]' '[Service]' '[Install]'; do
    grep -qxF "$section" "$unit" || err "kcptun-$side.service has no $section section"
  done
  # Upstream's operational settings, kept verbatim.
  for setting in 'Type=simple' 'Restart=on-failure' 'RestartSec=10' 'KillMode=process' \
    'LimitNOFILE=65536' 'WantedBy=multi-user.target'; do
    grep -qxF "$setting" "$unit" || err "kcptun-$side.service has lost '$setting'"
  done
  # Go runtime knobs do nothing here; they may be mentioned in a comment, not set.
  if grep -qE '^[[:space:]]*Environment=.*(GOGC|GOEXPERIMENT)' "$unit"; then
    err "kcptun-$side.service sets a Go runtime variable (GOGC/GOEXPERIMENT) that does nothing"
  fi
done

# The FreeBSD scripts must name the same binaries.
for side in client server; do
  rc="$ROOT/dist/freebsd/kcptun-$side.rc.conf"
  grep -q "kcptun-$side" "$rc" || err "kcptun-$side.rc.conf does not run kcptun-$side"
done

# dist/ is tracked packaging, not build output: a release workflow that collected dist/ would
# attach the systemd units and the example configurations to the release. tools/release.sh (13.1)
# writes to build/, as Go's build-release.sh does.
rel="$ROOT/.github/workflows/release.yml"
if [[ -f "$rel" ]] && grep -qE '(path: dist/?$|find dist )' "$rel"; then
  err "release.yml uses dist/ as the build output directory; dist/ is tracked packaging (use build/)"
fi

# ---------------------------------------------------------------------------------------------
# 4. The verbatim copies are still verbatim (needs reference/, which is optional).
# ---------------------------------------------------------------------------------------------
if [[ -d "$ROOT/reference/kcptun/dist" ]]; then
  log "files copied unchanged from the Go tree still match reference/"
  for f in local.json.example server.json.example linux/sysctl_linux freebsd/sysctl_freebsd; do
    if ! diff -q "$ROOT/reference/kcptun/dist/$f" "$ROOT/dist/$f" >/dev/null; then
      err "dist/$f differs from reference/kcptun/dist/$f, which it is a verbatim copy of"
    fi
  done
else
  log "reference/ not fetched - skipping the verbatim-copy check (tools/fetch-reference.sh)"
fi

# ---------------------------------------------------------------------------------------------
# 5. hadolint, when available.
# ---------------------------------------------------------------------------------------------
if command -v hadolint >/dev/null 2>&1; then
  log "hadolint $(hadolint --version | head -1)"
  hadolint "$DOCKERFILE" || fail=1
else
  log "hadolint not installed - skipping (see https://github.com/hadolint/hadolint)"
fi

if [[ $fail -ne 0 ]]; then
  echo "check-dist: FAILED" >&2
  exit 1
fi
log "dist OK"
