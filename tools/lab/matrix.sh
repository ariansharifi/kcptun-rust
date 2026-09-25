#!/usr/bin/env bash
# Drive step 11.2's impairment matrix: one lab.py session per (config, netem profile) cell.
#
#   tools/lab/matrix.sh --host lab-x86-2 --configs "s1" --profiles "clean lan wan50"
#
# Each cell is a full interleaved session (GG, RR, GR, RG x --reps) of one scenario, run with
# `--no-report`: 28 per-session reports in docs/lab-results/ would bury the one table the step is
# actually read from, which `lab.py matrix` builds across the sessions afterwards.
#
# The cells are serial on purpose. Both tunnel ends, the workload and the target share one lab
# host (and on the NL boxes, one vCPU), so two cells at once would measure each other.
#
# Safety: everything goes through tools/lab/lab.py, which goes through the guarded server-side
# helpers (tools/lab/README.md). This script starts nothing itself and kills nothing by name; if it is
# interrupted, the lab.py it is waiting on stops that cell's own processes and nothing else.
#
# `--host` is **mandatory**: a campaign is a couple of hours of NIC-saturating traffic, and
# lab.py's own default host is lab-arm64, which carries a live production mesh
# (tools/lab/README.md). A default here would mean running the whole matrix against production by
# typing nothing at all, so there is none.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HOST="${KCPTUN_LAB_HOST:-}"
SCENARIO="$ROOT/tools/lab/scenarios/bulk-iperf3.json"
CONFIGS="s1"
PROFILES="clean lan wan50 lossy2 lossy10 burst ratelimited"
REPS=""
# tools/lab/README.md's expendable hosts: the ones the user said may be saturated. Only these may
# have the preflight load guard raised (see MAX_LOAD below).
EXPENDABLE="lab-x86-1 lab-x86-2 lab-x86-3"
# lab.py's own preflight threshold, which step 11.1 states as a requirement ("uptime load
# < 1.0"). A one-vCPU box leaves the 1-minute average above 1.0 for minutes after a saturating
# run, so a serial campaign on an expendable host stalls on the *previous* cell's exhaust; that
# is what --max-load is for, and it is refused on a host that is not expendable. Every run still
# records `uptime` before and after, which is what the report is read with.
MAX_LOAD=1.0
EXTRA=()

usage() {
  sed -n '2,20p' "$0"
  exit "${1:-0}"
}

# lab.py turns Ctrl-C into a clean SystemExit(130) after stopping that cell's processes, so the
# child exits normally and a bash `for` loop would happily start the next cell. Under nohup or
# CI the shell may not see the SIGINT at all, so the trap is what stops the campaign.
trap 'echo "matrix: interrupted" >&2; exit 130' INT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host|--scenario|--configs|--profiles|--reps|--max-load)
      [[ $# -ge 2 ]] || { echo "matrix: $1 needs a value" >&2; exit 2; }
      case "$1" in
        --host) HOST="$2" ;;
        --scenario) SCENARIO="$2" ;;
        --configs) CONFIGS="$2" ;;
        --profiles) PROFILES="$2" ;;
        --reps) REPS="$2" ;;
        --max-load) MAX_LOAD="$2" ;;
      esac
      shift ;;
    -h|--help) usage 0 ;;
    --) shift; EXTRA=("$@"); break ;;
    *) echo "matrix: unknown argument $1" >&2; usage 2 ;;
  esac
  shift
done

[[ -n "$HOST" ]] || {
  echo "matrix: --host is required (or \$KCPTUN_LAB_HOST); there is no default, because" >&2
  echo "matrix: lab.py's is lab-arm64 and that box carries production (tools/lab/README.md)" >&2
  usage 2
}
[[ -f "$SCENARIO" ]] || { echo "matrix: no scenario $SCENARIO" >&2; exit 2; }

# A load guard *looser* than lab.py's own is only sanctioned on a box the user called
# expendable. On any other host — production, or one this file has never heard of — the campaign
# runs at 1.0 or it does not run. A tighter value is somebody being careful and is always fine,
# hence the numeric comparison (bash 3.2 has no float test, so awk does it).
if awk -v load="$MAX_LOAD" 'BEGIN { exit !(load + 0 > 1.0) }' \
   && [[ " $EXPENDABLE " != *" $HOST "* ]]; then
  echo "matrix: --max-load $MAX_LOAD is looser than lab.py's 1.0, which step 11.1 asks" >&2
  echo "matrix: for; that is allowed only on an expendable host ($EXPENDABLE," >&2
  echo "matrix: tools/lab/README.md). $HOST is not one." >&2
  exit 2
fi

# macOS ships bash 3.2, where `"${empty[@]}"` under `set -u` is an "unbound variable" error, so
# every possibly-empty array is expanded through the `${a[@]+…}` guard.
rep_args=()
[[ -n "$REPS" ]] && rep_args=(--repetitions "$REPS")

failed=0
total=0
for config in $CONFIGS; do
  for profile in $PROFILES; do
    total=$((total + 1))
    echo "=== matrix: $HOST $(basename "$SCENARIO" .json)" \
         "config=$config netem=$profile ($(date -u +%H:%M:%SZ))"
    status=0
    "$ROOT/tools/lab/lab.py" --host "$HOST" run "$SCENARIO" \
        --config "$config" --netem "$profile" \
        --max-load "$MAX_LOAD" --no-report \
        ${rep_args[@]+"${rep_args[@]}"} ${EXTRA[@]+"${EXTRA[@]}"} || status=$?
    if [[ $status -eq 130 ]]; then
      # lab.py's own Ctrl-C path: it stopped that cell's processes and exited cleanly. The
      # operator meant the campaign, not the cell.
      echo "!!! matrix: cell config=$config netem=$profile interrupted; stopping" >&2
      exit 130
    fi
    if [[ $status -ne 0 ]]; then
      # A cell that fails is reported and the campaign continues: one impairment profile the
      # kernel will not apply must not cost the other six, and `lab.py matrix` prints an
      # em dash for a cell with no runs rather than inventing a zero.
      echo "!!! matrix: cell config=$config netem=$profile FAILED" >&2
      failed=$((failed + 1))
      # ...unless the failure left a tunnel up. Then every later cell fails its port check in
      # two seconds, and the campaign burns through the rest of the matrix producing nothing
      # while the orphaned processes keep running. Stop instead, and say what to do: the
      # leftovers have to be collected or stopped by name before anything else can use the
      # ports. (`lab.py cleanup` is per host, not per run, so it is the operator's decision.)
      # `state=running` only: lab-status.sh prints a `proc …` line for every PID file it finds,
      # including `state=exited` and `state=no-pidfile`, so matching the line type would abort
      # the campaign over a stale PID file left by a hard-killed lab.py.
      if "$ROOT/tools/lab/lab.py" --host "$HOST" status 2>/dev/null | grep -q 'state=running'; then
        echo "!!! matrix: $HOST still has lab processes running; stopping the campaign" >&2
        "$ROOT/tools/lab/lab.py" --host "$HOST" status >&2 || true
        break 2
      fi
    fi
  done
done

echo "=== matrix: $((total - failed))/$total cells completed ($(date -u +%H:%M:%SZ))"
exit $(( failed > 0 ? 1 : 0 ))
