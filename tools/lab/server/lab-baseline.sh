#!/usr/bin/env bash
# Snapshot host state before a lab session so lab-cleanup.sh can prove we left nothing behind.
# Usage: lab-baseline.sh                       (overwrites ~/kcptun-lab/baseline/)
#        lab-baseline.sh --ports-only <p>...   (read-only: are these ports free?)
#
# The baseline is taken once per session; `--ports-only` is what every *run* calls, because the
# port check has to happen again each time — a detached run still holding the tunnel port must be
# caught here rather than half-way through lab-start.sh.
set -euo pipefail
. "$(dirname "$0")/lab-common.sh"

# Every port anything is listening on: the host's own table plus each lab namespace, since the
# tunnel ends listen INSIDE kr-cli/kr-srv and are invisible to the host's `ss`.
listening_ports() {
  {
    sudo ss -Htulpn 2>/dev/null || true
    for ns in "$NS_CLI" "$NS_SRV"; do
      if ns_exists "$ns"; then
        sudo ip netns exec "$ns" ss -Htulpn 2>/dev/null || true
      fi
    done
  } | awk '{ n = split($5, a, ":"); if (a[n] ~ /^[0-9]+$/) print a[n] }' | sort -un
}

check_ports() {
  local all busy=() p
  all="$(listening_ports)"
  for p in "$@"; do
    [[ "$p" =~ ^[0-9]{1,5}$ ]] || die "bad port '$p'"
    if grep -qx -- "$p" <<<"$all"; then
      busy+=("$p")
    fi
  done
  if [[ ${#busy[@]} -gt 0 ]]; then
    die "lab port(s) already in use: ${busy[*]} (another run, detached or not, is still up)"
  fi
  say "lab ports $* are free"
}

if [[ "${1:-}" == "--ports-only" ]]; then
  shift
  [[ $# -gt 0 ]] || die "usage: lab-baseline.sh --ports-only <port>..."
  check_ports "$@"
  exit 0
fi

sudo -n true 2>/dev/null || die "passwordless sudo required"
sudo iptables -S > "$BASE/iptables.txt"
sudo ip6tables -S > "$BASE/ip6tables.txt"
: > "$BASE/sysctl.txt"
for k in "${SYSCTLS[@]}"; do echo "$k=$(sysctl -n "$k")" >> "$BASE/sysctl.txt"; done
NIC="$(primary_nic)"
echo "$NIC" > "$BASE/nic.txt"
tc qdisc show dev "$NIC" > "$BASE/tc-nic.txt"
ip -br link > "$BASE/links.txt"
sudo ss -tulpn > "$BASE/ss.txt"
date -u +%FT%TZ > "$BASE/taken-at.txt"
say "baseline saved to $BASE (NIC $NIC, $(wc -l < "$BASE/iptables.txt") iptables rules, $(wc -l < "$BASE/ss.txt") sockets)"

# Our whole sanctioned range must be free when a session starts.
if sudo ss -tulpn | grep -E ':(299[0-2][0-9]|1294[89]|1295[0-9]|5201)\b' ; then
  die "lab ports already in use (see above)"
fi
say "lab ports 29900-29929, 12948-12959, 5201 are free"
