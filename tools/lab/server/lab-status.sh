#!/usr/bin/env bash
# Report what the lab is running, in one machine-readable line per PID file.
#
# Usage: lab-status.sh [<name>...]        (no names = every PID file)
#
# Output (one line each, fields are key=value and never contain spaces):
#   proc name=<n> pid=<p> state=<running|exited|pid-reused> log_bytes=<n> exe=<path>
#   netns profile=<p>                     (only when the namespace lab is up)
#
# This is how `lab.py status` checks on a detached run without touching anything: every field
# comes from a read of /proc or a stat of a log file.
set -euo pipefail
. "$(dirname "$0")/lab-common.sh"

names=("$@")
if [[ ${#names[@]} -eq 0 ]]; then
  for f in "$RUN"/*.pid; do [[ -e "$f" ]] && names+=("$(basename "$f" .pid)"); done
fi

for name in "${names[@]:-}"; do
  [[ -n "$name" ]] || continue
  f="$RUN/$name.pid"
  if [[ ! -f "$f" ]]; then
    echo "proc name=$name pid=- state=no-pidfile log_bytes=- exe=-"
    continue
  fi
  read -r pid exe < "$f"
  state=exited
  if sudo kill -0 "$pid" 2>/dev/null; then
    actual="$(sudo readlink "/proc/$pid/exe" 2>/dev/null || true)"
    if [[ "$actual" == "$exe" ]]; then state=running; else state=pid-reused; fi
  fi
  log="$LOGS/$name.log"
  bytes=-
  [[ -f "$log" ]] && bytes="$(stat -c %s "$log")"
  echo "proc name=$name pid=$pid state=$state log_bytes=$bytes exe=$exe"
done

if ns_exists "$NS_CLI" || ns_exists "$NS_SRV"; then
  echo "netns profile=$(cat "$RUN/netns-profile" 2>/dev/null || echo unknown)"
fi
