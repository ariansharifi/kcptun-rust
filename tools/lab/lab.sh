#!/usr/bin/env bash
# Run a lab script on lab-arm64: tools/lab/lab.sh <start|stop|netns|baseline|cleanup|tcpraw> [args...]
# e.g. tools/lab/lab.sh start kg-srv -- '$HOME/kcptun-lab/bin/go/kg-server' -l :29900 -t 127.0.0.1:5201
# Arguments are passed through with shell quoting; use '$HOME/...' (single-quoted) for remote paths.
set -euo pipefail
HOST="${KCPTUN_LAB_HOST:-lab-arm64}"
cmd="${1:?usage: lab.sh <start|stop|netns|baseline|cleanup|tcpraw> [args...]}"; shift
args=""
for a in "$@"; do
  if [[ "$a" == '$HOME/'* ]]; then args+="\"\$HOME/${a#\$HOME/}\" "; else args+="$(printf '%q' "$a") "; fi
done
# shellcheck disable=SC2029
exec ssh "$HOST" "\$HOME/kcptun-lab/scripts/lab-$cmd.sh $args"
