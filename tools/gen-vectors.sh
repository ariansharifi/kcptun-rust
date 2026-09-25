#!/usr/bin/env bash
# Build tools/govectors (Go, pinned kcp-go/smux/qpp/... versions) and regenerate the
# golden vectors in testdata/vectors/, then show what changed.
#
# Usage: tools/gen-vectors.sh [--check] [all | AREA...]
#   (default)  regenerate the files in testdata/vectors and print `git diff --stat`.
#   --check    regenerate into a temporary directory and fail (exit 1) if any file would
#              change, is missing, or (for `all`) if testdata/vectors holds extra files.
#              The working tree is left untouched. Meant for CI.
# AREA: crypt fec autotune rs kcp smux snappy qpp cli config multiport timefmt errno
#       (default: all).
#
# The Go module cache is reference/gomod (populated by tools/fetch-reference.sh), so the
# user's global cache stays untouched. Set GO=/path/to/go to pick a toolchain.
# Works with macOS's bash 3.2 (no mapfile, no empty-array expansion under set -u).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/tools/govectors"
BIN="$SRC/govectors" # gitignored
OUT="$ROOT/testdata/vectors"

CHECK=0
areas=()
for arg in "$@"; do
  case "$arg" in
    --check) CHECK=1 ;;
    -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "gen-vectors: unknown option: $arg" >&2; exit 2 ;;
    *) areas+=("$arg") ;;
  esac
done
[[ ${#areas[@]} -gt 0 ]] || areas=(all)

GO="${GO:-$(command -v go || true)}"
[[ -n "$GO" ]] || GO=/opt/homebrew/bin/go
[[ -x "$GO" ]] || { echo "gen-vectors: go toolchain not found (set GO=/path/to/go)" >&2; exit 1; }

export GOMODCACHE="$ROOT/reference/gomod" GOFLAGS=-modcacherw GOTOOLCHAIN=local
# The `errno` area (D30) reads Go's own zerrors_<goos>_<goarch>.go tables out of the
# distribution, and `go build -trimpath` strips the compiled-in GOROOT from the binary.
export GOROOT="${GOROOT:-$("$GO" env GOROOT)}"
log() { printf '==> %s\n' "$*"; }

log "building govectors with $("$GO" version | cut -d' ' -f3-)"
(cd "$SRC" && "$GO" vet ./... && "$GO" test -count=1 ./... && "$GO" build -trimpath -o "$BIN" .)

if [[ $CHECK -eq 0 ]]; then
  log "writing $OUT"
  (cd "$ROOT" && "$BIN" -out testdata/vectors "${areas[@]}")
  log "changes (git diff --stat testdata/vectors)"
  git -C "$ROOT" --no-pager diff --stat -- testdata/vectors
  untracked="$(git -C "$ROOT" ls-files --others --exclude-standard -- testdata/vectors)"
  if [[ -n "$untracked" ]]; then
    echo "new (untracked) files:"
    printf '  %s\n' $untracked
  fi
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
log "regenerating into a temporary directory"
"$BIN" -out "$tmp" "${areas[@]}" >/dev/null

status=0
if [[ " ${areas[*]} " == *" all "* ]]; then
  # Whole directory: also catches stale files that no area produces any more.
  if [[ ! -d "$OUT" ]]; then
    echo "gen-vectors: $OUT does not exist" >&2
    status=1
  elif ! diff -ru "$OUT" "$tmp"; then
    status=1
  fi
else
  for f in "$tmp"/*.json; do
    name="$(basename "$f")"
    if [[ ! -f "$OUT/$name" ]]; then
      echo "missing: testdata/vectors/$name"
      status=1
    elif ! diff -u "$OUT/$name" "$f"; then
      status=1
    fi
  done
fi

if [[ $status -ne 0 ]]; then
  echo "gen-vectors: testdata/vectors is out of date; run tools/gen-vectors.sh and commit the result." >&2
  echo "(The \"go\" field records the toolchain, so the check expects the same Go version.)" >&2
  exit 1
fi
log "testdata/vectors is up to date"
