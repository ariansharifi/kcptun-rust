#!/usr/bin/env bash
# Capture the help text of the Go kcptun binaries into testdata/golden/cli/, with the program
# name normalised, so the Rust help renderer can be compared against it byte for byte.
#
# Usage: tools/gen-cli-golden.sh [--check]
#   (default)  rewrite testdata/golden/cli/{client,server}_help.txt and print `git diff --stat`.
#   --check    write into a temporary directory and fail (exit 1) if anything would change.
#
# The binaries come from reference/bin (tools/fetch-reference.sh), which is gitignored, so the
# captured text is checked in instead. urfave/cli prints filepath.Base(os.Args[0]) in the USAGE
# line; it is replaced with the name of the matching Rust binary, which is what
# crates/std passes as App::help_name.
#
# Works with macOS's bash 3.2.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/reference/bin"
OUT="$ROOT/testdata/golden/cli"

CHECK=0
case "${1:-}" in
  --check) CHECK=1 ;;
  -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  "") ;;
  *) echo "gen-cli-golden: unknown option: $1" >&2; exit 2 ;;
esac

case "$(uname -s)/$(uname -m)" in
  Darwin/arm64) SUFFIX=darwin_arm64 ;;
  Linux/aarch64) SUFFIX=linux_arm64 ;;
  Linux/x86_64) SUFFIX=linux_amd64 ;;
  *) echo "gen-cli-golden: no reference binaries for $(uname -s)/$(uname -m)" >&2; exit 1 ;;
esac

dest="$OUT"
if [[ $CHECK -eq 1 ]]; then
  dest="$(mktemp -d)"
  trap 'rm -rf "$dest"' EXIT
fi
mkdir -p "$dest"

status=0
for side in client server; do
  exe="$BIN/${side}_${SUFFIX}"
  [[ -x "$exe" ]] || { echo "gen-cli-golden: missing $exe (run tools/fetch-reference.sh)" >&2; exit 1; }
  # The help text is identical for every -h spelling; ${side}_${SUFFIX} is what urfave prints.
  "$exe" -h | sed "s|^   ${side}_${SUFFIX} |   kcptun-${side} |" > "$dest/${side}_help.txt"
  if [[ $CHECK -eq 1 ]]; then
    if ! diff -u "$OUT/${side}_help.txt" "$dest/${side}_help.txt"; then
      echo "gen-cli-golden: $OUT/${side}_help.txt is out of date" >&2
      status=1
    fi
  fi
done

if [[ $CHECK -eq 1 ]]; then
  exit $status
fi
echo "==> wrote $OUT"
git -C "$ROOT" diff --stat -- testdata/golden/cli || true
