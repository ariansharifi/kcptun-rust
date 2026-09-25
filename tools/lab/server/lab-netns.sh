#!/usr/bin/env bash
# Two network namespaces joined by a veth pair, with optional netem impairment on OUR veths only.
#   ns kr-cli (10.200.0.1/30, kr-veth-c)  <==>  ns kr-srv (10.200.0.2/30, kr-veth-s)
# Never touches the host's primary NIC (see primary_nic) or any pre-existing interface
# (tools/lab/README.md, safety rule 2).
#
# Usage: lab-netns.sh up <profile> | down | set <profile> | status | sink <up|down>
# Profiles: clean lan wan50 lossy2 lossy10 burst ratelimited blackhole
set -euo pipefail
. "$(dirname "$0")/lab-common.sh"

# The "unreachable target" of Step 11.5: a route in the SERVER namespace for an address nothing
# answers at, whose next hop is the CLIENT namespace, which does not forward, so the SYN is
# dropped rather than refused. That distinction is the whole of the case: a closed port returns
# an RST in microseconds, while a blackholed one has to wait out kcptun's 10 s dialTimeout
# (reference/kcptun/server/main.go:488). TEST-NET-2 (RFC 5737) is reserved for documentation, so
# it can never be a real destination, and the route lives inside our own namespace and goes away
# with it.
SINK_NET=198.51.100.0/24

netem_params() {
  # A large queue limit avoids artificial drops at high bandwidth-delay products.
  case "$1" in
    clean) echo "" ;;
    # 11.5's blackhole: the path is up, the packets are gone. `loss 100%` rather than taking the
    # link down, because a down link fails a send immediately with ENETUNREACH and kcptun would
    # then see an error where a real blackhole gives it silence.
    blackhole) echo "limit 100000 loss 100%" ;;
    lan) echo "limit 100000 delay 1ms" ;;
    wan50) echo "limit 100000 delay 50ms 5ms distribution normal loss 0.1%" ;;
    lossy2) echo "limit 100000 delay 80ms 8ms loss 2% reorder 1% 50%" ;;
    lossy10) echo "limit 100000 delay 80ms loss 10%" ;;
    burst) echo "limit 100000 delay 60ms loss gemodel 1% 10% 70% 0.1%" ;;
    ratelimited) echo "limit 100000 delay 40ms rate 100mbit" ;;
    *) die "unknown profile '$1'" ;;
  esac
}

apply_profile() {
  local params; params="$(netem_params "$1")"
  sudo ip netns exec "$NS_CLI" tc qdisc del dev "$VETH_CLI" root 2>/dev/null || true
  sudo ip netns exec "$NS_SRV" tc qdisc del dev "$VETH_SRV" root 2>/dev/null || true
  if [[ -n "$params" ]]; then
    # shellcheck disable=SC2086
    sudo ip netns exec "$NS_CLI" tc qdisc add dev "$VETH_CLI" root netem $params
    # shellcheck disable=SC2086
    sudo ip netns exec "$NS_SRV" tc qdisc add dev "$VETH_SRV" root netem $params
  fi
  echo "$1" > "$RUN/netns-profile"
  say "netns profile: $1 ${params:+($params)}"
}

case "${1:-}" in
  up)
    profile="${2:-clean}"
    netem_params "$profile" >/dev/null
    ns_exists "$NS_CLI" && die "$NS_CLI already exists (run: lab-netns.sh down)"
    sudo ip netns add "$NS_CLI"
    sudo ip netns add "$NS_SRV"
    sudo ip link add "$VETH_CLI" type veth peer name "$VETH_SRV"
    sudo ip link set "$VETH_CLI" netns "$NS_CLI"
    sudo ip link set "$VETH_SRV" netns "$NS_SRV"
    sudo ip -n "$NS_CLI" addr add 10.200.0.1/30 dev "$VETH_CLI"
    sudo ip -n "$NS_SRV" addr add 10.200.0.2/30 dev "$VETH_SRV"
    for ns in "$NS_CLI" "$NS_SRV"; do sudo ip -n "$ns" link set lo up; done
    sudo ip -n "$NS_CLI" link set "$VETH_CLI" up
    sudo ip -n "$NS_SRV" link set "$VETH_SRV" up
    apply_profile "$profile"
    sudo ip netns exec "$NS_CLI" ping -c1 -W2 10.200.0.2 >/dev/null && say "netns up, 10.200.0.1 <-> 10.200.0.2 reachable"
    ;;
  set) apply_profile "${2:?profile}" ;;
  sink)
    ns_exists "$NS_SRV" || die "$NS_SRV does not exist (lab-netns.sh up)"
    case "${2:?usage: lab-netns.sh sink <up|down>}" in
      up) sudo ip -n "$NS_SRV" route replace "$SINK_NET" via 10.200.0.1
          say "sink route up: $SINK_NET via 10.200.0.1 (dropped, not refused)" ;;
      down) sudo ip -n "$NS_SRV" route del "$SINK_NET" 2>/dev/null || true
            say "sink route down" ;;
      *) die "usage: lab-netns.sh sink <up|down>" ;;
    esac
    ;;
  down)
    for ns in "$NS_CLI" "$NS_SRV"; do
      if ns_exists "$ns"; then
        for pid in $(sudo ip netns pids "$ns"); do sudo kill "$pid" 2>/dev/null || true; done
        sleep 0.5
        for pid in $(sudo ip netns pids "$ns"); do sudo kill -9 "$pid" 2>/dev/null || true; done
        sudo ip netns del "$ns"
      fi
    done
    rm -f "$RUN/netns-profile"
    say "netns down"
    ;;
  status)
    ip netns list | grep -E "^($NS_CLI|$NS_SRV)\b" || say "no lab netns"
    for pair in "$NS_CLI:$VETH_CLI" "$NS_SRV:$VETH_SRV"; do
      ns="${pair%%:*}" dev="${pair##*:}"
      ns_exists "$ns" && sudo ip netns exec "$ns" tc qdisc show dev "$dev"
    done
    ;;
  *) die "usage: lab-netns.sh up <profile> | down | set <profile> | status | sink <up|down>" ;;
esac
