#!/usr/bin/env bash
# Stop processes started by lab-start.sh, by PID file only, after verifying the PID still runs
# the recorded executable (guards against PID reuse). Never kills by name.
# Usage: lab-stop.sh <name>... | --all   [--signal SIG]
set -euo pipefail
. "$(dirname "$0")/lab-common.sh"

SIG=TERM
names=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --all) for f in "$RUN"/*.pid; do [[ -e "$f" ]] && names+=("$(basename "$f" .pid)"); done; shift ;;
    --signal) SIG="$2"; shift 2 ;;
    *) names+=("$1"); shift ;;
  esac
done

for name in "${names[@]}"; do
  f="$RUN/$name.pid"
  [[ -f "$f" ]] || { say "$name: no pid file"; continue; }
  read -r pid exe < "$f"
  if ! sudo kill -0 "$pid" 2>/dev/null; then
    say "$name: not running"; rm -f "$f"; continue
  fi
  actual="$(sudo readlink "/proc/$pid/exe" 2>/dev/null || true)"
  if [[ "$actual" != "$exe" ]]; then
    say "$name: pid $pid now runs '$actual', not '$exe'; NOT killing"; rm -f "$f"; continue
  fi
  sudo kill "-$SIG" "$pid"
  for _ in $(seq 50); do sudo kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
  if sudo kill -0 "$pid" 2>/dev/null; then sudo kill -KILL "$pid"; say "$name: killed (SIGKILL)"; else say "$name: stopped"; fi
  rm -f "$f"
done
