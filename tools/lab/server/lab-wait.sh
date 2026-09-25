#!/usr/bin/env bash
# Block until every named process started by lab-start.sh has exited.
#
# Usage: lab-wait.sh [--timeout S] [--quiet] <name>...
#   exit 0  every named process has exited
#   exit 2  the timeout expired with something still running (the caller decides what to do)
#
# Waiting happens HERE rather than in a poll loop on the laptop: a 30-second workload would
# otherwise cost 30 ssh round trips, and a six-hour one 21 600. One ssh connection, one sleep
# loop. A PID whose /proc/<pid>/exe no longer matches the recorded path counts as exited (the
# PID was reused), so this can never wait on somebody else's process.
set -euo pipefail
. "$(dirname "$0")/lab-common.sh"

TIMEOUT=600
QUIET=0
names=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --quiet) QUIET=1; shift ;;
    *) names+=("$1"); shift ;;
  esac
done
[[ ${#names[@]} -gt 0 ]] || die "usage: lab-wait.sh [--timeout S] <name>..."
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] && (( TIMEOUT > 0 && TIMEOUT <= 86400 )) || die "bad --timeout '$TIMEOUT'"

alive() {
  local f="$RUN/$1.pid" pid exe actual
  [[ -f "$f" ]] || return 1
  read -r pid exe < "$f"
  sudo kill -0 "$pid" 2>/dev/null || return 1
  actual="$(sudo readlink "/proc/$pid/exe" 2>/dev/null || true)"
  [[ "$actual" == "$exe" ]]
}

deadline=$(( $(date +%s) + TIMEOUT ))
while :; do
  running=()
  for name in "${names[@]}"; do alive "$name" && running+=("$name"); done
  if [[ ${#running[@]} -eq 0 ]]; then
    [[ $QUIET -eq 1 ]] || say "all finished: ${names[*]}"
    exit 0
  fi
  if (( $(date +%s) >= deadline )); then
    say "timeout after ${TIMEOUT}s, still running: ${running[*]}"
    exit 2
  fi
  sleep 1
done
