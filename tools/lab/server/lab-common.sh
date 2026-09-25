# Shared helpers for the lab scripts (they run ON the lab host, under ~/kcptun-lab/scripts;
# sourced, not executed). Safety rules: tools/lab/README.md. The host is whichever one lab.py --host
# (or deploy.sh) selected — lab-arm64, lab-x86-1, lab-x86-2 or lab-x86-3 — so nothing here may
# assume lab-arm64's interface names.

LAB="${KCPTUN_LAB:-$HOME/kcptun-lab}"
RUN="$LAB/run"
LOGS="$LAB/logs"
BASE="$LAB/baseline"
NS_CLI=kr-cli
NS_SRV=kr-srv
VETH_CLI=kr-veth-c
VETH_SRV=kr-veth-s
# The host's own NIC — the one interface these scripts must never touch. Detected from the
# default route so that the lab also runs on the hosts that are not lab-arm64 (lab-x86-3's is
# `ens3`, not `enp0s6`); override with KCPTUN_LAB_NIC if a host has no default route.
# The field *after* the `dev` keyword, not a fixed column: a link-scope default route
# (`default dev ens3 scope link`) carries no `via`, and column 5 would then read `scope`.
NIC="${KCPTUN_LAB_NIC:-$(ip route show default 2>/dev/null |
  awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')}"
NIC="${NIC:-enp0s6}"
# sysctls we may change temporarily; the baseline records their original values.
SYSCTLS=(net.core.rmem_max net.core.wmem_max net.core.rmem_default net.core.wmem_default net.core.netdev_max_backlog)

mkdir -p "$RUN" "$LOGS" "$BASE"

die() { echo "lab: $*" >&2; exit 1; }
say() { echo "lab: $*"; }

# Refuse anything that would listen on (or even mention) a port below 4000 (user rule, LAB.md §2.4),
# or use a source port the host has reserved for its own traffic.
guard_ports() {
  local prev="" a p
  for a in "$@"; do
    for p in $(grep -oE ':[0-9]{1,5}(-[0-9]{1,5})?' <<<"$a" | tr -d ':' | tr '-' ' '); do
      if (( p > 0 && p < 4000 )); then die "refusing port $p (< 4000) in argument '$a'"; fi
    done
    if [[ "$prev" == "-p" || "$prev" == "--port" || "$prev" == "--cport" ]]; then
      if [[ "$a" =~ ^[0-9]+$ ]] && (( a > 0 && a < 4000 )); then die "refusing port $a (< 4000)"; fi
    fi
    prev="$a"
  done
}

# Only our own binaries may be started (never touch the production kcptun client/server).
guard_binary() {
  local b; b="$(basename "$1")"
  [[ "$b" =~ ^(kr-|kg-) || "$b" == iperf3 || "$b" == python3 ]] \
    || die "refusing to run '$b': only kr-*, kg-*, iperf3 and python3 are allowed"
}

ns_exists() { ip netns list 2>/dev/null | grep -qw "$1"; }

# The host's primary NIC: the interface its default route leaves by.
#
# It used to be hard-coded to lab-arm64's `enp0s6`, which made `lab-baseline.sh` fail outright
# ("Cannot find device enp0s6") on every other lab host — lab-x86-1, lab-x86-2 and lab-x86-3 all
# name theirs differently. The lab never touches this interface; it only records its qdiscs so
# cleanup can prove that (tools/lab/README.md, safety rule 2).
primary_nic() {
  local dev
  dev="$(ip -o route show default 2>/dev/null |
         awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit } }' | head -1)"
  if [[ -z "$dev" ]]; then
    # `ip -br link` prints a veth as `name@ifN`, which `tc` cannot use: a baseline taken on a host
    # with no default route (or after lab-netns.sh brought kr-veth-c/kr-veth-s up) would otherwise
    # record e.g. `kr-veth-c@if12` in nic.txt, and lab-cleanup.sh's `tc qdisc show dev` on it fails
    # inside a `diff -q <(...)` — reported as "qdiscs differ from baseline", a false safety alarm
    # at the end of a long session. Strip the peer suffix, and never pick one of our own links.
    dev="$(ip -o -br link show up 2>/dev/null |
           awk '$1 != "lo" && $1 !~ /^kr-/ { print $1; exit }' | cut -d@ -f1)"
  fi
  [[ -n "$dev" ]] || die "cannot work out the primary NIC (no default route, no link that is up)"
  echo "$dev"
}
