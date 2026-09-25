#!/usr/bin/env bash
# Cross-build test executables for Linux aarch64 on the laptop and run them on lab-arm64.
# lab-arm64 has no C toolchain, so `cargo test` cannot run there natively (tools/lab/README.md).
# Tests must therefore embed their data (include_str!/include_bytes!) rather than read files
# relative to CARGO_MANIFEST_DIR at runtime.
#
# Works with macOS's bash 3.2 (no mapfile, no empty-array expansion under set -u).
# Usage: tools/lab/remote-test.sh [cargo test selection args...] [-- test harness args...]
#   e.g. tools/lab/remote-test.sh -p kcptun-kcp -- --test-threads 2
#        tools/lab/remote-test.sh -p kcptun-interop-tests -- --ignored
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HOST="${KCPTUN_LAB_HOST:-lab-arm64}"
TARGET="${KCPTUN_LAB_TARGET:-aarch64-unknown-linux-musl}"

cargo_args=() test_args=()
seen_sep=0
for a in "$@"; do
  if [[ $seen_sep -eq 0 && "$a" == "--" ]]; then seen_sep=1; continue; fi
  if [[ $seen_sep -eq 0 ]]; then cargo_args+=("$a"); else test_args+=("$a"); fi
done
[[ ${#cargo_args[@]} -gt 0 ]] || cargo_args=(--workspace)

cd "$ROOT"
json="$(mktemp)"
trap 'rm -f "$json"' EXIT
cargo-zigbuild test --no-run --target "$TARGET" --message-format=json "${cargo_args[@]}" > "$json"
exes=()
while IFS= read -r line; do exes+=("$line"); done < <(python3 - "$json" <<'EOF'
import json, sys
seen = set()
for line in open(sys.argv[1]):
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("profile", {}).get("test") and m.get("executable"):
        if m["executable"] not in seen:
            seen.add(m["executable"])
            print(m["executable"])
EOF
)
[[ ${#exes[@]} -gt 0 ]] || { echo "remote-test: no test executables built" >&2; exit 1; }

ssh "$HOST" 'rm -rf ~/kcptun-lab/tests && mkdir -p ~/kcptun-lab/tests'
scp -q "${exes[@]}" "$HOST:kcptun-lab/tests/"

fail=0
for exe in "${exes[@]}"; do
  name="$(basename "$exe")"
  echo "=== $name ${test_args[*]:-}"
  # shellcheck disable=SC2029
  quoted=""
  if [[ ${#test_args[@]} -gt 0 ]]; then quoted="$(printf '%q ' "${test_args[@]}")"; fi
  if ! ssh "$HOST" "cd ~/kcptun-lab/tests && KCPTUN_GO_BIN_DIR=\$HOME/kcptun-lab/bin/go KCPTUN_RS_BIN_DIR=\$HOME/kcptun-lab/bin/rust ./$name $quoted"; then
    fail=1
  fi
done
exit $fail
