#!/usr/bin/env bash
# Deploy lab scripts and binaries to a lab host (~/kcptun-lab). Runs on the laptop.
#   Go reference binaries   -> bin/go/kg-client, kg-server (+ kg-<peer> for tools/gointerop peers)
#   Rust binaries           -> bin/rust/kr-client, kr-server (cross-built with cargo-zigbuild)
#   Lab tools (Step 11)     -> bin/lab/kr-pingpong, kr-labsample (tools/pingpong, dev-only)
# No lab host has a C toolchain, so all Rust code is built on the laptop (tools/lab/README.md).
#
# Each of those directories also receives a BUILD.txt describing what landed in it (see
# "build stamps" below): lab.py refuses to start a run whose ends it cannot identify.
#
# Usage: tools/lab/deploy.sh [--scripts] [--go] [--rust] [--tools]
#                           [--arch auto|aarch64|x86_64] [--glibc VERSION] [--gnu]
#                           [--profile release|profiling]
#   no selection flags = everything.
#   --arch   which architecture to build and copy. The default, `auto`, asks the host
#            (`uname -m`); $KCPTUN_LAB_ARCH overrides that default and --arch overrides both.
#            lab-arm64 is aarch64 and lab-x86-1/lab-x86-2/lab-x86-3 are x86_64, so `auto` keeps
#            every existing invocation doing exactly what it did before it could choose.
#   --gnu    build against glibc instead of static musl (DECISIONS D07: glibc is what the
#            released Linux artifacts are, so a soak that is meant to represent production
#            wants this). --glibc picks the minimum glibc to target; the default 2.17 is the
#            one tools/release.sh ships, and it runs on every host in the lab. A newer value
#            (e.g. --glibc 2.39) produces a binary that will NOT start on Ubuntu 22.04.
#            $KCPTUN_LAB_GLIBC sets that default and --glibc overrides it, exactly as
#            $KCPTUN_LAB_ARCH does for --arch.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HOST="${KCPTUN_LAB_HOST:-lab-arm64}"
ARCH="${KCPTUN_LAB_ARCH:-auto}"
GLIBC="${KCPTUN_LAB_GLIBC:-2.17}"
DO_SCRIPTS=0 DO_GO=0 DO_RUST=0 DO_TOOLS=0 GNU=0 PROFILE=release
# One cleanup trap for all three staging directories. Each holds full copies of the
# binaries being deployed, and the `write_build_stamp` that now follows every scp ends in
# an ssh that can fail (the host going away between the copy and the stamp); under
# `set -e` an explicit `rm -rf` after it would never run and the copies would survive in
# /var/folders. Registered once, because a later `trap ... EXIT` replaces an earlier one.
tmp="" tmp2="" tmp3=""
trap 'rm -rf "${tmp:-}" "${tmp2:-}" "${tmp3:-}"' EXIT
while [[ $# -gt 0 ]]; do
  case "$1" in
    --scripts) DO_SCRIPTS=1 ;;
    --go) DO_GO=1 ;;
    --rust) DO_RUST=1 ;;
    --tools) DO_TOOLS=1 ;;
    --gnu) GNU=1 ;;
    # The value-taking flags. Under `set -u` a missing value would abort with
    # `$2: unbound variable`, which does not say which flag was mistyped.
    --arch|--glibc|--profile)
      [[ $# -ge 2 ]] || { echo "deploy: $1 needs a value" >&2; exit 2; }
      case "$1" in
        --arch) ARCH="$2" ;;
        --glibc) GLIBC="$2" ;;
        --profile) PROFILE="$2" ;;
      esac
      shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done
if [[ $DO_SCRIPTS -eq 0 && $DO_GO -eq 0 && $DO_RUST -eq 0 && $DO_TOOLS -eq 0 ]]; then
  DO_SCRIPTS=1 DO_GO=1 DO_RUST=1 DO_TOOLS=1
fi

# One round trip: make the layout and learn the machine type at the same time, so `--arch auto`
# costs nothing. The mkdir has to come first anyway.
host_uname="$(ssh "$HOST" 'mkdir -p ~/kcptun-lab/{bin/go,bin/rust,bin/lab,run,logs,baseline,scripts,tests}; uname -m')"
host_uname="${host_uname%%[[:space:]]*}"

[[ "$ARCH" == auto ]] && ARCH="$host_uname"
case "$ARCH" in
  aarch64|arm64) RUST_ARCH=aarch64; GO_ARCH=arm64 ;;
  x86_64|amd64)  RUST_ARCH=x86_64;  GO_ARCH=amd64 ;;
  *) echo "deploy: unsupported architecture '$ARCH' (host reports '$host_uname')" >&2; exit 2 ;;
esac
# Copying binaries a host cannot execute is the one deploy mistake that shows up hours later as
# 'Exec format error' in a run log, so it is refused rather than warned about.
case "$host_uname:$RUST_ARCH" in
  aarch64:aarch64|arm64:aarch64|x86_64:x86_64|amd64:x86_64) ;;
  *) echo "deploy: $HOST is $host_uname but --arch selected $RUST_ARCH; refusing" >&2; exit 2 ;;
esac

# The Rust target triple and the triple cargo-zigbuild is given (which carries the glibc version).
if [[ $GNU -eq 1 ]]; then
  RUST_TARGET="$RUST_ARCH-unknown-linux-gnu"
  ZIG_TARGET="$RUST_TARGET.$GLIBC"
  LIBC_NOTE="glibc $GLIBC"
else
  RUST_TARGET="$RUST_ARCH-unknown-linux-musl"
  ZIG_TARGET="$RUST_TARGET"
  LIBC_NOTE="static musl"
fi
if [[ $DO_RUST -eq 1 || $DO_TOOLS -eq 1 ]]; then
  echo "deploy: host $HOST ($host_uname), target $RUST_TARGET ($LIBC_NOTE), profile $PROFILE"
else
  echo "deploy: host $HOST ($host_uname)"
fi

# --- build stamps ---------------------------------------------------------------------------
# Every directory that receives a binary also receives a BUILD.txt describing THAT binary, and
# the stamp carries the sha256 of each file it copied. lab.py refuses to start a run whose end
# it cannot identify from these, because 11.3 recorded 27 runs with an empty `server_build`:
# the aggregate bin/BUILD.txt this used to write said nothing about the kr-server one directory
# down, which was a leftover from an earlier session, and every number of that campaign is
# consequently unattributable.
#
# The `-dirty` marker matters more than the hash of the tree: lab binaries are routinely
# cross-built from a working tree that is ahead of HEAD, and a bare commit id invites a later
# reader of docs/lab-results/*.md to check that commit out and expect the same binary.
# `status --porcelain` rather than `describe --dirty`, because a brand new, still untracked
# source file is just as unreproducible as a modified one.
COMMIT="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
REVISION="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
TREE=clean
if [[ "$REVISION" != unknown && -n "$(git -C "$ROOT" status --porcelain 2>/dev/null)" ]]; then
  REVISION="$REVISION-dirty"
  TREE=dirty
fi
DEPLOYED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# macOS (where deploy.sh runs) has shasum; Linux has sha256sum. Either is fine, the digest is
# the same, and a host without one simply leaves lab.py unable to verify, never silently happy.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# The Go reference binaries are NOT built from this repository, so `commit` does not identify
# them: reference/ is a symlink to a checkout that is gitignored and shared between worktrees,
# and tools/fetch-reference.sh can replace every binary in it without this tree changing by one
# byte. What does identify them is reference/VERSIONS.txt: the pinned kcptun module version and
# the Go toolchain they were built with, so the go stamp carries both. Missing (a reference
# checkout that was never fetched) is recorded as `unknown` rather than omitted: a field that is
# simply absent reads as "nobody thought about this", which is how 11.3 happened.
go_reference_fields() {
  local versions="$ROOT/reference/VERSIONS.txt" version="" toolchain=""
  if [[ -r "$versions" ]]; then
    version="$(awk '$1 == "kcptun" { print $2; exit }' "$versions")"
    toolchain="$(awk '/^built with go version / { print $5; exit }' "$versions")"
  fi
  echo "reference_version=${version:-unknown}"
  echo "go_toolchain=${toolchain:-unknown}"
}

# write_build_stamp <remote-dir-under-~/kcptun-lab> <kind> <target> <libc> <profile>
#                   <dir-of-copies> [extra key=value lines]
# The stamp is sent on stdin rather than interpolated into the remote command line, so nothing
# in it (a path, a revision, the parentheses around the libc note) is ever re-parsed by the host.
write_build_stamp() {
  local remote_dir="$1" kind="$2" target="$3" libc="$4" profile="$5" staged="$6" extra="${7:-}"
  local names="" f stamp summary
  for f in "$staged"/*; do
    names="$names${names:+ }$(basename "$f")"
  done
  summary="host $host_uname, $kind $target ($libc), profile $profile, rev $REVISION,"
  summary="$summary deployed $DEPLOYED_AT"
  stamp="kind=$kind
host=$host_uname
target=$target
libc=$libc
profile=$profile
commit=$COMMIT
revision=$REVISION
tree=$TREE
deployed=$DEPLOYED_AT
binaries=$names"
  if [[ -n "$extra" ]]; then
    stamp="$stamp
$extra"
  fi
  for f in "$staged"/*; do
    stamp="$stamp
sha256.$(basename "$f")=$(sha256_of "$f")"
  done
  stamp="$stamp
summary=$summary"
  ssh "$HOST" "cat > \"\$HOME/kcptun-lab/$remote_dir/BUILD.txt\"" <<<"$stamp"
  echo "deploy: recorded $HOST:kcptun-lab/$remote_dir/BUILD.txt ($summary)"
}

if [[ $DO_SCRIPTS -eq 1 ]]; then
  scp -q "$ROOT"/tools/lab/server/*.sh "$HOST:kcptun-lab/scripts/"
  ssh "$HOST" 'chmod +x ~/kcptun-lab/scripts/*.sh'
  echo "deploy: scripts -> $HOST:kcptun-lab/scripts/"
fi

if [[ $DO_GO -eq 1 ]]; then
  bin="$ROOT/reference/bin"
  [[ -x "$bin/client_linux_$GO_ARCH" ]] || {
    echo "missing $bin/client_linux_$GO_ARCH; run tools/fetch-reference.sh" >&2; exit 1; }
  tmp="$(mktemp -d)"
  for f in "$bin"/*_linux_"$GO_ARCH"; do
    name="$(basename "$f" "_linux_$GO_ARCH")"
    cp "$f" "$tmp/kg-$name"
  done
  scp -q "$tmp"/kg-* "$HOST:kcptun-lab/bin/go/"
  echo "deploy: Go reference (linux/$GO_ARCH) -> $HOST:kcptun-lab/bin/go/ ($(ls "$tmp" | tr '\n' ' '))"
  # `commit` here is only *this* tree's revision: it says when the deployment was made, not
  # what was deployed, because reference/ is a gitignored symlink to a shared checkout that no
  # worktree's HEAD describes. `reference_version` and `go_toolchain` come out of
  # reference/VERSIONS.txt and are what actually name these binaries, alongside the sha256 of
  # each copied file. The libc is `none`: the reference binaries are pure Go and link no C
  # library at all, which is exactly why they run on every host here.
  write_build_stamp bin/go go "linux/$GO_ARCH" none reference "$tmp" "$(go_reference_fields)"
fi

if [[ $DO_RUST -eq 1 ]]; then
  (cd "$ROOT" && cargo zigbuild -q --profile "$PROFILE" --target "$ZIG_TARGET" -p kcptun-client -p kcptun-server)
  out="$ROOT/target/$RUST_TARGET/$PROFILE"
  tmp2="$(mktemp -d)"
  cp "$out/kcptun-client" "$tmp2/kr-client"
  cp "$out/kcptun-server" "$tmp2/kr-server"
  scp -q "$tmp2"/kr-* "$HOST:kcptun-lab/bin/rust/"
  echo "deploy: Rust ($RUST_TARGET, $LIBC_NOTE, $PROFILE) -> $HOST:kcptun-lab/bin/rust/"
  # Both binaries, always: a host that is only ever a server still gets kr-client stamped, and
  # more to the point a host that is only ever a server gets its kr-server stamped at all.
  write_build_stamp bin/rust rust "$RUST_TARGET" "$LIBC_NOTE" "$PROFILE" "$tmp2"
fi

if [[ $DO_TOOLS -eq 1 ]]; then
  # The Step 11 workload driver and /proc sampler. They are deployed under the kr- prefix
  # because lab-start.sh only starts kr-*/kg-* binaries and lab-stop.sh compares
  # /proc/<pid>/exe against the recorded path (tools/lab/README.md, safety rule 1).
  (cd "$ROOT" && cargo zigbuild -q --profile "$PROFILE" --target "$ZIG_TARGET" -p kcptun-pingpong)
  out="$ROOT/target/$RUST_TARGET/$PROFILE"
  tmp3="$(mktemp -d)"
  cp "$out/pingpong" "$tmp3/kr-pingpong"
  cp "$out/labsample" "$tmp3/kr-labsample"
  scp -q "$tmp3"/kr-* "$HOST:kcptun-lab/bin/lab/"
  echo "deploy: lab tools ($RUST_TARGET, $LIBC_NOTE, $PROFILE) -> $HOST:kcptun-lab/bin/lab/"
  write_build_stamp bin/lab lab "$RUST_TARGET" "$LIBC_NOTE" "$PROFILE" "$tmp3"
fi

# The aggregate manifest at bin/BUILD.txt, where deployments before 12.0 put the only stamp
# there was. It is kept because a person who knows that path should still find something there,
# but it is explicitly NOT what lab.py reads: it describes whatever this invocation copied,
# which need not be the binary a later run executes. The authoritative stamps are the per
# directory ones written above, each carrying the sha256 of the files beside it.
if [[ $DO_RUST -eq 1 || $DO_TOOLS -eq 1 || $DO_GO -eq 1 ]]; then
  build_line="host $host_uname"
  stamped=""
  if [[ $DO_RUST -eq 1 || $DO_TOOLS -eq 1 ]]; then
    build_line="$build_line, rust $RUST_TARGET ($LIBC_NOTE), profile $PROFILE"
    [[ $DO_RUST -eq 1 ]] && stamped="$stamped${stamped:+ }bin/rust"
    [[ $DO_TOOLS -eq 1 ]] && stamped="$stamped${stamped:+ }bin/lab"
  fi
  if [[ $DO_GO -eq 1 ]]; then
    build_line="$build_line, go linux/$GO_ARCH"
    stamped="$stamped${stamped:+ }bin/go"
  fi
  build_line="$build_line, rev $REVISION, deployed $DEPLOYED_AT"
  manifest="kind=deployment
host=$host_uname
commit=$COMMIT
revision=$REVISION
tree=$TREE
deployed=$DEPLOYED_AT
stamps=$stamped
summary=$build_line"
  # Sent on stdin rather than interpolated into the remote command line, so nothing in it
  # (a path, a revision, the parentheses around the libc note) is ever re-parsed by the host.
  ssh "$HOST" 'cat > ~/kcptun-lab/bin/BUILD.txt' <<<"$manifest"
  echo "deploy: recorded $HOST:kcptun-lab/bin/BUILD.txt ($build_line)"
fi
