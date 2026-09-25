#!/usr/bin/env bash
# Return the lab host to its baseline: stop our processes, remove our netns/veths, remove only
# iptables rules that are provably ours (tcpraw TTL=1 DROP rules on lab ports), restore sysctls,
# then verify. Exits non-zero (loudly) if anything is left that we did not expect.
set -uo pipefail
. "$(dirname "$0")/lab-common.sh"

[[ -f "$BASE/iptables.txt" ]] || die "no baseline; run lab-baseline.sh first"
problems=0

"$(dirname "$0")/lab-stop.sh" --all
"$(dirname "$0")/lab-netns.sh" down >/dev/null

# Leftover veths (should be gone with the netns).
for dev in $(ip -br link | awk '{print $1}' | grep -E '^kr-' | cut -d@ -f1); do
  sudo ip link del "$dev" && say "removed leftover link $dev"
done

# iptables: remove rules that are ours (tcpraw: TTL/hop-limit 1 DROP on ports 29900-29929).
ours='(ttl-eq 1|hl-eq 1).*(sport|dport) 299[0-2][0-9]'
for fam in iptables ip6tables; do
  while read -r rule; do
    [[ -z "$rule" ]] && continue
    if grep -qxF -- "$rule" "$BASE/$fam.txt"; then continue; fi
    if [[ "$rule" =~ ^-A\ OUTPUT && "$rule" =~ $ours ]]; then
      # shellcheck disable=SC2086
      sudo $fam ${rule/-A /-D } && say "$fam: removed our rule: $rule"
    else
      say "$fam: UNEXPECTED new rule (not removed): $rule"; problems=1
    fi
  done < <(sudo $fam -S)
  if ! diff -q <(sudo $fam -S) "$BASE/$fam.txt" >/dev/null; then
    say "$fam differs from baseline:"; diff <(sudo $fam -S) "$BASE/$fam.txt"; problems=1
  fi
done

# sysctls back to baseline values.
while IFS='=' read -r k v; do
  cur="$(sysctl -n "$k")"
  if [[ "$cur" != "$v" ]]; then sudo sysctl -q -w "$k=$v" && say "restored $k=$v (was $cur)"; fi
done < "$BASE/sysctl.txt"

# The NIC's qdiscs must be exactly as before (we never touch them). The interface name and the
# snapshot both come from the baseline, so a host whose NIC is not lab-arm64's enp0s6 is checked
# just as strictly; the enp0s6 fallback reads a baseline taken before 11.1b made this generic.
if [[ -f "$BASE/nic.txt" ]]; then
  nic="$(cat "$BASE/nic.txt")"; nic_snapshot="$BASE/tc-nic.txt"
else
  nic=enp0s6; nic_snapshot="$BASE/tc-enp0s6.txt"
fi
if [[ ! -f "$nic_snapshot" ]]; then
  say "no NIC qdisc snapshot in the baseline ($nic_snapshot); re-run lab-baseline.sh"; problems=1
elif ! diff -q <(tc qdisc show dev "$nic") "$nic_snapshot" >/dev/null; then
  say "$nic qdiscs differ from baseline (NOT caused by lab scripts?)"
  diff <(tc qdisc show dev "$nic") "$nic_snapshot"; problems=1
fi

if sudo ss -tulpn | grep -E ':(299[0-2][0-9]|1294[89]|1295[0-9]|5201)\b'; then
  say "lab ports still in use (see above)"; problems=1
fi

if [[ $problems -ne 0 ]]; then die "cleanup finished WITH PROBLEMS (see above)"; fi
say "cleanup OK: host matches baseline"
