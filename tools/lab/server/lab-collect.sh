#!/usr/bin/env bash
# Gather one run's artefacts into ~/kcptun-lab/logs/<runid>/ so they can be fetched in one go.
#
# Usage: lab-collect.sh <runid> [--max-bytes N] [<name>...]
#   <runid>       directory under logs/; [A-Za-z0-9._-]+ only (never a path)
#   --max-bytes   clip any file larger than this to its first and last half (default 8388608)
#   <name>...     processes whose logs/<name>.log is moved in (CSV files the run wrote
#                 directly into logs/<runid>/ are left alone)
#
# Clipping rather than refusing: a tunnel run without `-quiet` logs three lines per stream, so
# 20 streams/s for six hours is hundreds of megabytes of "stream opened". What matters is the
# beginning (start-up) and the end (whatever went wrong), and a marker line records how much was
# dropped so nobody mistakes a clipped log for a complete one.
set -euo pipefail
. "$(dirname "$0")/lab-common.sh"

RUNID="${1:?usage: lab-collect.sh <runid> [--max-bytes N] [<name>...]}"; shift
[[ "$RUNID" =~ ^[A-Za-z0-9._-]+$ ]] || die "bad run id '$RUNID'"
MAX=8388608
names=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --max-bytes) MAX="$2"; shift 2 ;;
    *) names+=("$1"); shift ;;
  esac
done
[[ "$MAX" =~ ^[0-9]+$ ]] && (( MAX >= 4096 )) || die "bad --max-bytes '$MAX'"

DEST="$LOGS/$RUNID"
mkdir -p "$DEST"

# Files this script altered or refused to alter, so the MANIFEST can say so and nobody mistakes
# a clipped artefact for a complete one. Space-delimited basenames; also makes clipping
# idempotent, since a file named on the command line is also matched by the sweep below.
ALTERED=" "
OVERSIZE=" "
noted() { case "$ALTERED$OVERSIZE" in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

# Logs: a byte splice with an in-band marker. A log is read by a human, so the marker belongs
# where the gap is.
clip_log() {
  local file="$1" base size half
  base="$(basename "$file")"
  noted "$base" && return 0
  size="$(stat -c %s "$file")"
  (( size > MAX )) || return 0
  half=$(( MAX / 2 ))
  {
    head -c "$half" "$file"
    printf '\n... lab-collect: %s bytes removed from the middle of a %s-byte log ...\n' \
      "$(( size - MAX ))" "$size"
    tail -c "$half" "$file"
  } > "$file.clipped"
  mv "$file.clipped" "$file"
  ALTERED="$ALTERED$base "
  say "clipped $base from $size to $(stat -c %s "$file") bytes"
}

# CSV: whole lines only, and NO marker inside the record stream. lab.py parses these with
# csv.reader, where a marker line would become a one-field row: a phantom process in the metrics
# table, or a bogus last record for the SNMP totals. The header and the last records survive
# (which is what `snmp_totals` reads), and the MANIFEST records that the file is not complete.
clip_csv() {
  local file="$1" base size half
  base="$(basename "$file")"
  noted "$base" && return 0
  size="$(stat -c %s "$file")"
  (( size > MAX )) || return 0
  half=$(( MAX / 2 ))
  {
    head -c "$half" "$file" | sed '$ d'   # drop the record cut in half at the front
    tail -c "$half" "$file" | sed '1 d'   # and the one cut in half at the back
  } > "$file.clipped"
  mv "$file.clipped" "$file"
  ALTERED="$ALTERED$base "
  say "clipped $base from $size to $(stat -c %s "$file") bytes (whole records)"
}

# Everything else (iperf3 -J output): not line-oriented, so any clip makes it unparseable.
# Leave it whole and flag it instead — an oversized one of these means a scenario went wrong.
flag_oversize() {
  local file="$1" base size
  base="$(basename "$file")"
  noted "$base" && return 0
  size="$(stat -c %s "$file")"
  (( size > MAX )) || return 0
  OVERSIZE="$OVERSIZE$base "
  say "WARNING: $base is $size bytes (> $MAX) and was left whole: clipping it would corrupt it"
}

for name in "${names[@]:-}"; do
  [[ -n "$name" ]] || continue
  src="$LOGS/$name.log"
  if [[ -f "$src" ]]; then
    mv "$src" "$DEST/$name.log"
    clip_log "$DEST/$name.log"
  else
    say "$name: no log"
  fi
done

# Anything the run wrote straight into the run directory (sampler CSV, -snmplog, workload CSVs),
# plus any log the caller did not name. Each kind is treated according to how it is parsed.
for f in "$DEST"/*; do
  [[ -f "$f" ]] || continue
  case "$(basename "$f")" in
    MANIFEST) ;;
    *.log) clip_log "$f" ;;
    *.csv) clip_csv "$f" ;;
    *) flag_oversize "$f" ;;
  esac
done

{
  echo "runid=$RUNID"
  echo "host=$(hostname)"
  echo "collected_at=$(date -u +%FT%TZ)"
  echo "uptime=$(uptime | sed 's/,/ /g' | tr -s ' ')"
  for f in "$DEST"/*; do
    [[ -f "$f" ]] || continue
    base="$(basename "$f")"
    [[ "$base" == "MANIFEST" ]] && continue
    note=""
    case "$ALTERED" in *" $base "*) note=" clipped=yes" ;; esac
    case "$OVERSIZE" in *" $base "*) note=" oversize=yes" ;; esac
    echo "file $base bytes=$(stat -c %s "$f")$note"
  done
} > "$DEST/MANIFEST"

say "collected into $DEST"
cat "$DEST/MANIFEST"
