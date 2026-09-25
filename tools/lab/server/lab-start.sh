#!/usr/bin/env bash
# Start one of OUR processes in the background with a PID file (the only way we stop things).
# Usage: lab-start.sh [--netns kr-cli|kr-srv] [--root] <name> -- <command> [args...]
#   <name>   unique label; PID file run/<name>.pid, log logs/<name>.log
#   --root   keep root inside the netns (only for tcpraw tests); default drops to the login user
set -euo pipefail
. "$(dirname "$0")/lab-common.sh"

NETNS="" ROOT=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --netns) NETNS="$2"; shift 2 ;;
    --root) ROOT=1; shift ;;
    --) shift; break ;;
    *) NAME="$1"; shift ;;
  esac
done
[[ -n "${NAME:-}" && $# -gt 0 ]] || die "usage: lab-start.sh [--netns NS] [--root] <name> -- <cmd...>"
[[ "$NAME" =~ ^[A-Za-z0-9._-]+$ ]] || die "bad name '$NAME'"
[[ -z "$NETNS" || "$NETNS" == "$NS_CLI" || "$NETNS" == "$NS_SRV" ]] || die "netns must be $NS_CLI or $NS_SRV"

cmd=("$@")
if [[ "${cmd[0]}" != /* ]]; then
  resolved="$(command -v "${cmd[0]}" || true)"
  [[ -n "$resolved" ]] || die "command not found: ${cmd[0]}"
  cmd[0]="$resolved"
fi
guard_binary "${cmd[0]}"
guard_ports "${cmd[@]:1}"

PIDFILE="$RUN/$NAME.pid"
LOG="$LOGS/$NAME.log"
if [[ -f "$PIDFILE" ]] && kill -0 "$(cut -d' ' -f1 "$PIDFILE")" 2>/dev/null; then
  die "$NAME already running (pid $(cut -d' ' -f1 "$PIDFILE"))"
fi

# The log is created empty here, by the login user, and every branch below then opens it with
# `>>` (O_APPEND) rather than `>`. That matters for the six-hour soak: kr-labsample truncates a
# watched log in place once it passes --log-cap-bytes, and a writer WITHOUT O_APPEND keeps its
# old file offset, so its next write re-extends the file to offset+n with a hole of NUL bytes in
# front: the file never actually shrinks, the cap fires again every interval, and the collected
# log starts with megabytes of NULs. With O_APPEND each write goes to the current end of file, so
# an external truncate really does restart the log. Creating it as the login user (rather than
# letting the `sudo` shell create it as root) is what lets the sampler open it for writing at all.
rm -f "$LOG"
: > "$LOG"
q=$(printf '%q ' "${cmd[@]}")
# Raise OUR OWN soft descriptor limit before exec.
#
# The host's soft limit is 1024 and its hard limit is 1048576, so this needs
# no privilege and changes nothing outside the process we are about to start - not the host, not the
# user's production mesh. It exists so the 11.4 soak can run on the PRODUCTION `closewait` default
# (server 30 s) instead of `closewait 0`: at 20 streams/s a 30 s linger is a legitimate steady state
# of roughly 600 descriptors per side, which 1024 cannot hold. The soak's acceptance is a FLAT
# PLATEAU, not a low number, so the limit has to leave room to see a plateau rather than a ceiling.
# See DECISIONS D28.
ulimit_prefix='ulimit -n 65536 2>/dev/null || true; '
if [[ -n "$NETNS" ]]; then
  ns_exists "$NETNS" || die "netns $NETNS does not exist (lab-netns.sh up)"
  if [[ $ROOT -eq 1 ]]; then
    pid=$(sudo bash -c "$ulimit_prefix ip netns exec $NETNS $q >> $(printf %q "$LOG") 2>&1 & echo \$!")
  else
    u="$(id -u)" g="$(id -g)"
    pid=$(sudo bash -c "$ulimit_prefix ip netns exec $NETNS setpriv --reuid=$u --regid=$g --init-groups -- $q >> $(printf %q "$LOG") 2>&1 & echo \$!")
  fi
else
  [[ $ROOT -eq 0 ]] || die "--root is only allowed inside a lab netns"
  pid=$(bash -c "$ulimit_prefix nohup $q >> $(printf %q "$LOG") 2>&1 & echo \$!")
fi
# PID file records the pid and the executable, so lab-stop.sh can verify before killing. The
# path is resolved first: /proc/<pid>/exe names the real file, so a recorded symlink (python3 ->
# python3.12) would never match and lab-stop.sh would refuse to stop its own process.
echo "$pid $(readlink -f "${cmd[0]}")" > "$PIDFILE"
sleep 0.3
if ! sudo kill -0 "$pid" 2>/dev/null; then
  echo "--- $LOG ---"; tail -20 "$LOG" || true
  rm -f "$PIDFILE"
  die "$NAME exited immediately"
fi
say "started $NAME (pid $pid${NETNS:+, netns $NETNS}) log=$LOG"
