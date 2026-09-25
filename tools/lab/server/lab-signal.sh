#!/usr/bin/env bash
# Send a NON-FATAL signal to processes started by lab-start.sh, by PID file only, after
# verifying the PID still runs the recorded executable. Never kills, never signals by name.
#
# Usage: lab-signal.sh <USR1|USR2|HUP> <name>...
#
# This exists because lab-stop.sh --signal USR1 would *also* wait for the process to exit and
# then SIGKILL it: it is a stopper. kcptun's SNMP dump is a SIGUSR1 to a process that must keep
# running (step 11: "both sides' SNMP (SIGUSR1 dump at the end)"), so it needs its own path.
# Fatal signals are deliberately not accepted here — stopping is lab-stop.sh's job.
set -euo pipefail
. "$(dirname "$0")/lab-common.sh"

SIG="${1:-}"; shift || true
[[ -n "$SIG" && $# -gt 0 ]] || die "usage: lab-signal.sh <USR1|USR2|HUP> <name>..."
case "$SIG" in
  USR1|USR2|HUP) ;;
  *) die "refusing signal '$SIG': only USR1, USR2 and HUP (use lab-stop.sh to stop things)" ;;
esac

failed=0
for name in "$@"; do
  f="$RUN/$name.pid"
  if [[ ! -f "$f" ]]; then say "$name: no pid file"; failed=1; continue; fi
  read -r pid exe < "$f"
  if ! sudo kill -0 "$pid" 2>/dev/null; then say "$name: not running"; failed=1; continue; fi
  actual="$(sudo readlink "/proc/$pid/exe" 2>/dev/null || true)"
  if [[ "$actual" != "$exe" ]]; then
    say "$name: pid $pid now runs '$actual', not '$exe'; NOT signalling"; failed=1; continue
  fi
  sudo kill "-$SIG" "$pid"
  say "$name: sent SIG$SIG to pid $pid"
done
exit $failed
