#!/usr/bin/env bash
# Step 10.5: the `--tcp` (fake TCP) evidence, run inside the two lab network namespaces.
#
# Everything here needs root (raw sockets, iptables) and a `filter/OUTPUT` chain nobody else
# edits — which is what the namespaces are for: `kr-cli` and `kr-srv` have their own chains, so a
# rule left behind is provably ours and the host's own chain is never touched.
#
#   lab-tcpraw.sh matrix   — the interop matrix: {rust,go} client x {rust,go} server, crypt
#                            aes/xor, FEC 10/3 and 0/0, each checked by a 1 MiB echo whose
#                            SHA-256 must come back unchanged.
#   lab-tcpraw.sh v22      — the Go `--tcp` client receiving nothing (DECISIONS V22), with the
#                            rising `InErrs` from its own SIGUSR1 SNMP dump as the evidence.
#   lab-tcpraw.sh cleanup  — the `filter/OUTPUT` chain after a failed dial, SIGINT, SIGTERM and
#                            SIGKILL, compared with the baseline taken before each case.
#   lab-tcpraw.sh pcap     — one Go and one Rust session captured on the veth, then compared with
#                            `tshark`: the flags, window, header length and option layout of every
#                            crafted segment each implementation emits, and the TCP checksum of
#                            each one. Needs tshark on the lab host (`apt install tshark`).
#   lab-tcpraw.sh tests [binary...]
#                          — the 7 `#[ignore]`d privileged unit tests, inside `kr-cli` and with
#                            `net.ipv4.tcp_timestamps=0` set there first. That sysctl is the
#                            documented precondition of `test_dial_tcp_stream` (DECISIONS V10):
#                            the crafted segments carry no timestamp option, so a peer whose own
#                            random boot offset is already past zero discards them by PAWS about
#                            half the time. It is per-namespace, so the host is untouched, and it
#                            is restored when the run ends — the throughput and WAN profiles share
#                            these namespaces with a *kernel* TCP peer and must keep the default.
#                            Defaults to every executable in $LAB/tests (where remote-test.sh
#                            copies the cross-built binaries). The `write_*_fuzz_seeds` corpus
#                            writers are skipped — see the comment in tests().
#
# Prerequisites: lab-netns.sh up, and — for everything but `tests` — bin/rust/kr-{client,server} +
# bin/go/kg-{client,server} built for this host's architecture.
#
# Run from the laptop with `tools/lab/lab.sh tcpraw <cmd>`. That runs the script as the **login**
# user — `ubuntu` on lab-arm64, root only on the hosts that log in as root — so, exactly as in
# lab-netns.sh and lab-stop.sh, every privileged command here carries its own `sudo` rather than
# relying on the script being root. Running the whole file under `sudo` would not do: sudoers'
# `env_reset` makes `$HOME` /root, and lab-common.sh's `LAB="${KCPTUN_LAB:-$HOME/kcptun-lab}"`
# would then point at a directory that does not exist.
set -uo pipefail
. "$(dirname "$0")/lab-common.sh"

sudo -n true 2>/dev/null || die "passwordless sudo required"

CLI_IP=10.200.0.1
SRV_IP=10.200.0.2
TUN_PORT=29900   # the kcptun server: UDP always, plus the tcpraw listener with --tcp
LOCAL_PORT=29910 # the client's own TCP listener, in kr-cli
ECHO_PORT=29920  # the plain TCP echo service the tunnel carries, on kr-srv's loopback
KEY='step10.5 tcpraw'
BLOB=1048576
KR="$LAB/bin/rust"
KG="$LAB/bin/go"
# The wall-clock bound on one `--ignored` test binary. The whole privileged set runs in a few
# seconds; anything near this is a hang, not a slow machine.
TEST_TIMEOUT="${KCPTUN_LAB_TEST_TIMEOUT:-600}"
START="$(dirname "$0")/lab-start.sh"
STOP="$(dirname "$0")/lab-stop.sh"

problems=0
fail() { echo "FAIL: $*" >&2; problems=1; }

# Privileged background helpers. `sudo cmd &` would record sudo's own pid, which a non-root user
# cannot signal and which may or may not still exist once sudo has exec'd, so the pid of the
# command itself is taken the way lab-start.sh takes it.
BG_PIDS=()
BG_PID="" # set by bg_ns to the pid it just started
# The pid is handed back in BG_PID rather than on stdout: a `$(bg_ns …)` would run the whole
# function in a subshell, and the BG_PIDS entry the exit trap relies on would die with it.
bg_ns() { # <netns> <command...> — starts it in the background; sets BG_PID
  local ns="$1"; shift
  local q pid; q="$(printf '%q ' "$@")"
  BG_PID=""
  pid="$(sudo bash -c "ip netns exec $ns $q >/dev/null 2>&1 & echo \$!")" || return 1
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  BG_PIDS+=("$pid")
  BG_PID="$pid"
}
# Kills one recorded background process and forgets it, so the exit trap cannot signal a pid the
# kernel has since handed to somebody else. It escalates to SIGKILL after the same wait lab-stop.sh
# uses, and only drops the pid once it is really gone: a pid forgotten while still alive is one the
# exit trap can no longer reach — a root-owned tcpdump or holder left running on a shared lab host,
# which is the one outcome this file must never produce. If even SIGKILL leaves it, the pid stays
# in the list *and* the run is a failure, because a leak must be reported, not silently tolerated.
drop_bg() { # <pid> [signal]
  local pid="$1" sig="${2:-TERM}" keep=() p
  sudo kill "-$sig" "$pid" 2>/dev/null
  for _ in $(seq 50); do sudo kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
  if sudo kill -0 "$pid" 2>/dev/null; then
    sudo kill -KILL "$pid" 2>/dev/null
    for _ in $(seq 20); do sudo kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
  fi
  if sudo kill -0 "$pid" 2>/dev/null; then
    fail "background pid $pid survived SIG$sig and SIGKILL (kept in the exit trap's list)"
    return
  fi
  for p in ${BG_PIDS+"${BG_PIDS[@]}"}; do [[ "$p" == "$pid" ]] || keep+=("$p"); done
  BG_PIDS=(${keep+"${keep[@]}"})
}

# net.ipv4.tcp_timestamps is changed inside $NS_CLI by `tests`; this holds the value to put back
# while it is not at it, so the exit trap restores it even when a `die` cuts the run short.
TS_RESTORE=""

# Everything that must happen however this script ends — including a `die` in the middle of a
# subcommand, which used to leave the echo service, a tcpdump and the changed sysctl behind.
on_exit() {
  local rc=$? p unrestored=0
  # The fallback restore: `tests` does it itself on the normal path (where a failure can still
  # reach `problems`), so reaching here with TS_RESTORE set means a `die`, a signal or a bug cut
  # the run short.
  if [[ -n "$TS_RESTORE" ]]; then
    if sudo ip netns exec "$NS_CLI" sysctl -qw "net.ipv4.tcp_timestamps=$TS_RESTORE"; then
      say "net.ipv4.tcp_timestamps in $NS_CLI restored to $TS_RESTORE"
    else
      echo "FAIL: could not restore net.ipv4.tcp_timestamps in $NS_CLI" >&2
      unrestored=1
    fi
    TS_RESTORE=""
  fi
  for p in ${BG_PIDS+"${BG_PIDS[@]}"}; do sudo kill "$p" 2>/dev/null; done
  BG_PIDS=()
  # Guarded: a `die` from one of the preflight checks below fires before these are defined.
  declare -F stop_all >/dev/null && stop_all
  declare -F stop_echo >/dev/null && stop_echo
  # A `return` from an EXIT trap cannot change the shell's exit status, so the one condition that
  # must not be reported as success — the namespace left with tcp_timestamps=0, which the
  # throughput and WAN profiles share with a kernel TCP peer — has to `exit` instead.
  [[ $unrestored -eq 0 ]] || exit 1
  return $rc
}
trap on_exit EXIT

# The tunnel binaries, needed by every subcommand that starts a tunnel — but not by `tests`,
# which runs a self-contained test executable.
need_tunnels() {
  local f
  for f in "$KR/kr-client" "$KR/kr-server" "$KG/kg-client" "$KG/kg-server"; do
    [[ -x "$f" ]] || die "missing $f"
  done
}
ns_exists "$NS_CLI" || die "no lab netns (run: lab-netns.sh up clean)"

# ---------------------------------------------------------------------------- helpers on disk

write_helpers() {
  cat > "$RUN/tcp-echo.py" <<'PY'
# A plain TCP echo service: what the tunnel carries. One thread per connection, echoing until EOF.
import socket, sys, threading
host, port = sys.argv[1], int(sys.argv[2])
def serve(c):
    with c:
        while True:
            b = c.recv(65536)
            if not b:
                return
            c.sendall(b)
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
s.listen(16)
print("echo listening on %s:%d" % (host, port), flush=True)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
  cat > "$RUN/tcp-probe.py" <<'PY'
# Sends `size` pseudo-random bytes through the tunnel and checks that exactly those bytes,
# in that order, come back. Prints the SHA-256 of both directions; exits non-zero on any
# mismatch, short read or timeout.
import hashlib, os, socket, sys, threading
host, port, size, timeout = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
payload = os.urandom(size)
s = socket.create_connection((host, port), timeout=timeout)
s.settimeout(timeout)
def send():
    try:
        s.sendall(payload)
    except OSError as e:
        print("send failed: %s" % e, flush=True)
threading.Thread(target=send, daemon=True).start()
got = bytearray()
try:
    while len(got) < size:
        b = s.recv(65536)
        if not b:
            break
        got += b
except OSError as e:
    print("recv failed after %d/%d bytes: %s" % (len(got), size, e), flush=True)
s.close()
sent_digest = hashlib.sha256(payload).hexdigest()
got_digest = hashlib.sha256(bytes(got)).hexdigest()
print("sent %d sha256=%s" % (size, sent_digest[:16]), flush=True)
print("got  %d sha256=%s" % (len(got), got_digest[:16]), flush=True)
sys.exit(0 if got_digest == sent_digest else 1)
PY
}

# The rules of one namespace's filter/OUTPUT chain, for before/after comparison.
chain() { sudo ip netns exec "$1" iptables -S OUTPUT; }
chain6() { sudo ip netns exec "$1" ip6tables -S OUTPUT; }

wait_for_log() { # <logfile> <pattern> <seconds>
  local f="$LOGS/$1" pat="$2" n="${3:-15}"
  for _ in $(seq $((n * 10))); do
    grep -qE "$pat" "$f" 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}

start_server() { # <impl> <crypt> <ds> <ps>
  local impl="$1" crypt="$2" ds="$3" ps="$4" bin
  bin="$KG/kg-server"
  [[ "$impl" == rust ]] && bin="$KR/kr-server"
  "$START" --netns "$NS_SRV" --root srv -- "$bin" \
    -l ":$TUN_PORT" -t "127.0.0.1:$ECHO_PORT" --tcp \
    --key "$KEY" --crypt "$crypt" --datashard "$ds" --parityshard "$ps" --mode fast >/dev/null
}

start_client() { # <impl> <crypt> <ds> <ps>
  local impl="$1" crypt="$2" ds="$3" ps="$4" bin
  bin="$KG/kg-client"
  [[ "$impl" == rust ]] && bin="$KR/kr-client"
  "$START" --netns "$NS_CLI" --root cli -- "$bin" \
    -l "$CLI_IP:$LOCAL_PORT" -r "$SRV_IP:$TUN_PORT" --tcp \
    --key "$KEY" --crypt "$crypt" --datashard "$ds" --parityshard "$ps" --mode fast --conn 1 >/dev/null
}

probe() { # <seconds>
  sudo ip netns exec "$NS_CLI" timeout "$1" python3 "$RUN/tcp-probe.py" "$CLI_IP" "$LOCAL_PORT" "$BLOB" "$1"
}

# Stops the two tunnel processes but leaves the echo service alone: it is shared by every cell.
stop_all() { "$STOP" cli srv >/dev/null 2>&1; }
stop_echo() { "$STOP" echo >/dev/null 2>&1; }

# Starts the plain TCP echo service the tunnel carries, unless it is already up.
start_echo() {
  [[ -f "$RUN/echo.pid" ]] && return 0
  "$START" --netns "$NS_SRV" --root echo -- python3 "$RUN/tcp-echo.py" 127.0.0.1 "$ECHO_PORT" >/dev/null
}

# ---------------------------------------------------------------------------- the interop matrix

matrix() {
  local cli srv crypt fec ds ps base_c base_s base6_c base6_s out rc
  # Both families: a `listen` installs one rule per protocol, so a leaked ip6tables rule would
  # otherwise pass every cell unnoticed.
  base_c="$(chain "$NS_CLI")"; base_s="$(chain "$NS_SRV")"
  base6_c="$(chain6 "$NS_CLI")"; base6_s="$(chain6 "$NS_SRV")"
  start_echo || die "the echo service did not start"

  for cli in rust go; do
    for srv in rust go; do
      for crypt in aes xor; do
        for fec in "10 3" "0 0"; do
          read -r ds ps <<<"$fec"
          say "=== client=$cli server=$srv crypt=$crypt fec=$ds/$ps"
          start_server "$srv" "$crypt" "$ds" "$ps" || { fail "server did not start"; continue; }
          wait_for_log srv.log 'Listening on' 15 || say "  (no 'Listening on' line yet)"
          start_client "$cli" "$crypt" "$ds" "$ps" || { fail "client did not start"; "$STOP" srv >/dev/null; continue; }
          wait_for_log cli.log 'listening on' 15 || say "  (no 'listening on' line yet)"

          out="$(probe 25 2>&1)"; rc=$?
          echo "$out" | sed 's/^/  /'

          # The DROP rules must be in place while the tunnel is up — that is what stops the
          # kernel from answering the crafted segments with its own RSTs. The client's rule
          # appears only once it has dialled, and it dials on the first accepted connection, so
          # this is read *after* the probe rather than before it.
          local rules_c rules_s
          rules_c="$(chain "$NS_CLI" | grep -c 'ttl-eq 1')"
          rules_s="$(chain "$NS_SRV" | grep -c 'ttl-eq 1')"
          say "  rules while up: client=$rules_c server=$rules_s"
          [[ "$rules_c" -ge 1 ]] || fail "$cli client installed no TTL=1 rule"
          [[ "$rules_s" -ge 1 ]] || fail "$srv server installed no TTL=1 rule"
          if [[ $rc -eq 0 ]]; then
            say "  RESULT: ok"
            [[ "$cli" == go ]] && fail "the Go --tcp client carried data; DECISIONS V22 says it cannot"
          else
            say "  RESULT: no data (rc=$rc)"
            [[ "$cli" == go ]] || fail "client=$cli server=$srv crypt=$crypt fec=$ds/$ps carried no data"
          fi
          stop_all
          sleep 0.5
          [[ "$(chain "$NS_CLI")" == "$base_c" ]] || { fail "client rules survived"; chain "$NS_CLI"; }
          [[ "$(chain "$NS_SRV")" == "$base_s" ]] || { fail "server rules survived"; chain "$NS_SRV"; }
          [[ "$(chain6 "$NS_CLI")" == "$base6_c" ]] || { fail "client ip6 rules survived"; chain6 "$NS_CLI"; }
          [[ "$(chain6 "$NS_SRV")" == "$base6_s" ]] || { fail "server ip6 rules survived"; chain6 "$NS_SRV"; }
        done
      done
    done
  done
  stop_all
}

# ----------------------------------------------------------- V22: the Go client receives nothing

v22() {
  say "=== DECISIONS V22: Go --tcp client, Rust --tcp server"
  start_echo
  start_server rust aes 10 3 || die "server did not start"
  wait_for_log srv.log 'Listening on' 15
  start_client go aes 10 3 || die "client did not start"
  wait_for_log cli.log 'listening on' 15

  read -r pid _ < "$RUN/cli.pid"
  sudo kill -USR1 "$pid"; sleep 0.5
  local before after
  before="$(grep -o 'InErrs:[0-9]*' "$LOGS/cli.log" | tail -1)"
  say "  SNMP before the probe: $before"

  probe 15 >/dev/null 2>&1 && fail "the Go --tcp client carried data; V22 says it cannot"
  say "  probe: no data came back (expected)"

  sudo kill -USR1 "$pid"; sleep 0.5
  after="$(grep -o 'InErrs:[0-9]*' "$LOGS/cli.log" | tail -1)"
  say "  SNMP after  the probe: $after"
  grep -o 'KCP SNMP:.*' "$LOGS/cli.log" | tail -1 | sed 's/^/  /'
  [[ "$before" != "$after" ]] || fail "InErrs did not rise; V22's mechanism is not what happened"

  # The same Go client against a *Go* server, to show the receive path — not the wire — is what
  # fails: if this also carries nothing, no Rust code is involved in the failure at all.
  stop_all; sleep 0.5
  say "=== control: Go --tcp client, Go --tcp server"
  start_echo
  start_server go aes 10 3 || die "server did not start"
  wait_for_log srv.log 'Listening on' 15
  start_client go aes 10 3 || die "client did not start"
  wait_for_log cli.log 'listening on' 15
  read -r pid _ < "$RUN/cli.pid"
  probe 15 >/dev/null 2>&1 && fail "Go client + Go server carried data, so V22 is not the whole story"
  sudo kill -USR1 "$pid"; sleep 0.5
  grep -o 'KCP SNMP:.*' "$LOGS/cli.log" | tail -1 | sed 's/^/  /'
  say "  Go client + Go server: no data either (kcp-go's own bug, not an interop mismatch)"
  stop_all
}

# ------------------------------------------------------------------- cleanup on every exit path

cleanup_case() { # <label> <signal|none> <expect-clean 0|1>
  local label="$1" sig="$2" expect="$3" base base6 now now6
  base="$(chain "$NS_CLI")"; base6="$(chain6 "$NS_CLI")"
  start_client rust aes 10 3 || { fail "$label: client did not start"; return; }
  wait_for_log cli.log 'listening on' 15

  # The client dials — and so appends its rule — only when a connection arrives at its own
  # listener, so one is opened and held for the life of the case.
  bg_ns "$NS_CLI" python3 -c \
    "import socket,time; s=socket.create_connection(('$CLI_IP',$LOCAL_PORT),10); s.sendall(b'ping'); s.recv(16); time.sleep(60)" \
    || { fail "$label: could not open the holding connection"; return; }
  local holder="$BG_PID"
  for _ in $(seq 100); do [[ "$(chain "$NS_CLI")" != "$base" ]] && break; sleep 0.1; done
  [[ "$(chain "$NS_CLI")" != "$base" ]] || fail "$label: no rule was installed, so nothing is being tested"

  read -r pid _ < "$RUN/cli.pid"
  if [[ "$sig" == KILL ]]; then
    sudo kill -KILL "$pid"; rm -f "$RUN/cli.pid"
  else
    "$STOP" cli --signal "$sig" >/dev/null
  fi
  for _ in $(seq 100); do sudo kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
  drop_bg "$holder"
  sleep 0.5
  now="$(chain "$NS_CLI")"; now6="$(chain6 "$NS_CLI")"
  if [[ "$now" == "$base" && "$now6" == "$base6" ]]; then
    if [[ "$expect" -eq 1 ]]; then say "$label: chain is back to baseline (as expected)";
    else fail "$label: the chain is clean, but this path cannot clean up — check the test"; fi
  else
    if [[ "$expect" -eq 0 ]]; then
      say "$label: rules survived (as expected, documented):"
      diff <(echo "$base") <(echo "$now") | sed 's/^/    /'
      # The documented manual fallback for this case.
      while read -r rule; do
        [[ "$rule" == -A* ]] || continue
        grep -qxF -- "$rule" <<<"$base" && continue
        # shellcheck disable=SC2086
        sudo ip netns exec "$NS_CLI" iptables ${rule/-A /-D } && say "    removed by hand: $rule"
      done <<<"$now"
    else
      fail "$label: rules survived an exit path that must clean up:"
      diff <(echo "$base") <(echo "$now") | sed 's/^/    /'
    fi
  fi
}

cleanup() {
  start_echo
  start_server rust aes 10 3 || die "server did not start"
  wait_for_log srv.log 'Listening on' 15

  cleanup_case SIGINT INT 1
  cleanup_case SIGTERM TERM 1
  cleanup_case SIGKILL KILL 0

  # Dials that fail. There is no exit here to test — Go's `waitConn` retries for ever, and so
  # does this port — but a leak would grow `filter/OUTPUT` once a second for the life of the
  # process. A refused connect fails *before* the rules are appended (Go's `Dial` order: raw
  # socket, real TCP connect, then iptables), so what this shows is that nothing accumulates; the
  # harder case, a dial abandoned *after* the rules went in, is covered by the unit test
  # `a_cancelled_dial_leaves_nothing_behind`.
  say "=== repeated failed dials"
  local base; base="$(chain "$NS_CLI")"
  "$STOP" srv >/dev/null 2>&1
  start_client rust aes 10 3 || { fail "client did not start"; return; }
  wait_for_log cli.log 'listening on' 15
  local i
  for i in $(seq 6); do
    sudo ip netns exec "$NS_CLI" timeout 2 python3 -c \
      "import socket,sys; s=socket.create_connection(('$CLI_IP',$LOCAL_PORT),2); s.sendall(b'x'); s.close()" \
      >/dev/null 2>&1
    sleep 1
  done
  say "  re-connecting lines: $(grep -c 're-connecting' "$LOGS/cli.log")"
  local during; during="$(chain "$NS_CLI")"
  if [[ "$(grep -c 'ttl-eq 1' <<<"$during")" -gt 1 ]]; then
    fail "failed dials accumulated rules:"; echo "$during" | sed 's/^/    /'
  else
    say "  rules during the retries: $(grep -c 'ttl-eq 1' <<<"$during") (no accumulation)"
  fi
  "$STOP" cli >/dev/null
  sleep 0.5
  if [[ "$(chain "$NS_CLI")" == "$base" ]]; then say "  chain is back to baseline"
  else fail "failed dials left rules behind"; chain "$NS_CLI"; fi
  stop_all
}

# ------------------------------------------------------------------------------ pcap comparison

# tshark over one namespace's capture. The `-o tcp.check_checksum:TRUE` matters: Wireshark leaves
# TCP checksum validation off by default and every segment then reads back as "unverified".
tsh() { # <pcap> <display filter> <field...>
  local f="$1" filter="$2"; shift 2
  local args=() e
  for e in "$@"; do args+=(-e "$e"); done
  sudo ip netns exec "$NS_CLI" tshark -r "$f" -o tcp.check_checksum:TRUE -Y "$filter" \
    -T fields -E occurrence=a -E aggregator=, "${args[@]}" 2>/dev/null
}

# The shape of every *crafted* segment one side emitted: flags, window, header length and the
# option kinds, one unique line each and no counts, so two runs of different lengths still
# compare. `tcp.len > 0` is what separates tcpraw's segments from the kernel's own handshake on
# the same 5-tuple — the real TCP connection tcpraw holds open never carries a byte — and it is
# also why the checksum check below cannot trip over the kernel's TX-offloaded (and therefore
# blank on the wire) handshake checksums.
segment_shapes() { # <pcap> <source ip>
  tsh "$1" "tcp.port==$TUN_PORT && tcp.len>0 && ip.src==$2" \
    tcp.flags tcp.window_size_value tcp.hdr_len tcp.option_kind tcp.option_len \
    | sort -u
}

analyse_pcap() { # <pcap> <label> <emitter ip>
  local f="$1" label="$2" ip="$3" total bad
  total="$(tsh "$f" "tcp.port==$TUN_PORT && tcp.len>0 && ip.src==$ip" frame.number | wc -l | tr -d ' ')"
  say "  $label: $total crafted segment(s) from $ip"
  [[ "$total" -gt 0 ]] || { fail "$label: $ip emitted no tcpraw segment at all"; return; }
  say "  $label: flags / window / hdr_len / option kinds / option lengths (unique):"
  local shapes; shapes="$(segment_shapes "$f" "$ip")"
  if [[ -n "$shapes" ]]; then
    sed 's/^/    /' <<<"$shapes"
  else
    # tshark prints nothing at all when one of the -e names is not a field it knows, so an empty
    # table here is a broken query rather than a capture with no segments in it.
    fail "$label: tshark returned no fields for $total segments — check the -e names in segment_shapes"
  fi
  bad="$(tsh "$f" "tcp.port==$TUN_PORT && tcp.len>0 && tcp.checksum.status==0" frame.number \
    | wc -l | tr -d ' ')"
  if [[ "$bad" -eq 0 ]]; then
    say "  $label: every crafted segment's TCP checksum verifies"
  else
    fail "$label: $bad crafted segment(s) with a bad TCP checksum"
  fi
}

pcap() { # one Go session and one Rust session, captured on the client's veth, then compared
  local impl out tcpdump_pid
  command -v tshark >/dev/null \
    || die "tshark is not installed on this host; the pcap comparison needs it (apt install tshark)"
  start_echo
  for impl in go rust; do
    out="$LOGS/tcpraw-$impl.pcap"
    sudo rm -f "$out"
    start_server "$impl" aes 10 3 || die "server did not start"
    wait_for_log srv.log 'Listening on' 15
    bg_ns "$NS_CLI" tcpdump -i "$VETH_CLI" -s 0 -w "$out" "tcp port $TUN_PORT" \
      || die "tcpdump did not start"
    tcpdump_pid="$BG_PID"
    sleep 1
    # Always a *Rust* client: the Go client cannot receive (V22), and what is being compared here
    # is the segments each implementation's tcpraw *emits* — the server's, for the Go side.
    start_client rust aes 10 3 || die "client did not start"
    wait_for_log cli.log 'listening on' 15
    sudo ip netns exec "$NS_CLI" timeout 20 python3 "$RUN/tcp-probe.py" "$CLI_IP" "$LOCAL_PORT" 65536 20 \
      | sed 's/^/  /'
    sleep 1
    # SIGTERM, so tcpdump flushes the capture file before it goes.
    drop_bg "$tcpdump_pid"
    stop_all; sleep 0.5
    say "captured $out ($(sudo stat -c %s "$out") bytes)"
    analyse_pcap "$out" "$impl server" "$SRV_IP"
    segment_shapes "$out" "$SRV_IP" > "$LOGS/tcpraw-$impl-shapes.txt"
  done
  stop_all

  # The comparison the plan asks for: what the Go server's tcpraw put on the wire against what
  # this port's did, over the identical session. The documented difference is V10, and measuring
  # it is what "verify with pcap in Step 10" meant: v1.2.32 writes a *malformed* timestamp option
  # of length 12 and pads the header out to 36 bytes, where this port writes the standard length
  # 10 and a 32-byte header. Measured on lab-x86-3, 2026-09-24:
  #   go    0x0018  65535  36  1,1,8,0,0  12   (NOP, NOP, TS(len 12), then two padding zeros)
  #   rust  0x0018  65535  32  1,1,8      10   (NOP, NOP, TS(len 10))
  # Same flags, same window, same option kinds; only the TS length and the header length differ,
  # which is V10 exactly. Anything else showing up here is a finding.
  say "=== segments emitted by the server, Go vs Rust (flags / window / hdr_len / option kinds / lengths)"
  if diff -u "$LOGS/tcpraw-go-shapes.txt" "$LOGS/tcpraw-rust-shapes.txt" > "$LOGS/tcpraw-shapes.diff"; then
    say "  identical on every field"
  else
    sed 's/^/  /' "$LOGS/tcpraw-shapes.diff"
  fi
  # Flags and window are not part of V10 and must match exactly.
  local go_fw rust_fw
  go_fw="$(cut -f1,2 "$LOGS/tcpraw-go-shapes.txt" | sort -u)"
  rust_fw="$(cut -f1,2 "$LOGS/tcpraw-rust-shapes.txt" | sort -u)"
  if [[ "$go_fw" == "$rust_fw" ]]; then
    say "  flags and window are identical: $(tr '\n' ' ' <<<"$go_fw")"
  else
    fail "flags/window differ, which V10 does not explain:"
    diff <(echo "$go_fw") <(echo "$rust_fw") | sed 's/^/    /'
  fi
  # The options layout is where V10 lives, so it is asserted against the documented shape above
  # rather than only printed: a Rust-side regression that emitted, say, a window-scale option or a
  # 40-byte header would otherwise print a diff and the run would still end in "OK".
  local go_hl rust_hl go_kinds rust_kinds opts=1
  go_hl="$(cut -f3,5 "$LOGS/tcpraw-go-shapes.txt" | sort -u)"
  rust_hl="$(cut -f3,5 "$LOGS/tcpraw-rust-shapes.txt" | sort -u)"
  [[ "$go_hl" == $'36\t12' ]] \
    || { fail "the Go server's hdr_len/option_len is '$go_hl', not V10's 36 / 12"; opts=0; }
  [[ "$rust_hl" == $'32\t10' ]] \
    || { fail "this port's hdr_len/option_len is '$rust_hl', not the 32 / 10 V10 describes"; opts=0; }
  # Both must be NOP, NOP, Timestamps; Go's trailing `,0,0` is gopacket padding the options out to
  # the 4-byte boundary, so only the prefix is common ground.
  go_kinds="$(cut -f4 "$LOGS/tcpraw-go-shapes.txt" | sort -u)"
  rust_kinds="$(cut -f4 "$LOGS/tcpraw-rust-shapes.txt" | sort -u)"
  [[ "$go_kinds" == 1,1,8* ]] \
    || { fail "the Go server's option kinds are '$go_kinds', not NOP,NOP,TS as V10 describes"; opts=0; }
  [[ "$rust_kinds" == 1,1,8* ]] \
    || { fail "this port's option kinds are '$rust_kinds', not NOP,NOP,TS as V10 describes"; opts=0; }
  [[ $opts -eq 0 ]] \
    || say "  options are V10 exactly: hdr_len/TS-len go $(tr '\t' '/' <<<"$go_hl"), rust $(tr '\t' '/' <<<"$rust_hl"); kinds $go_kinds vs $rust_kinds"
}

# ------------------------------------------------------------- the privileged unit tests, in netns

tests() { # [binary...] — cross-built test executables, default: everything in $LAB/tests
  local bins=() b base base6 ts_before rc
  if [[ $# -gt 0 ]]; then
    bins=("$@")
  else
    for b in "$LAB"/tests/*; do [[ -f "$b" && -x "$b" ]] && bins+=("$b"); done
  fi
  [[ ${#bins[@]} -gt 0 ]] || die "no test binaries (run tools/lab/remote-test.sh first, or pass a path)"
  for b in "${bins[@]}"; do [[ -x "$b" ]] || die "not executable: $b"; done

  base="$(chain "$NS_CLI")"; base6="$(chain6 "$NS_CLI")"
  # See the header: per-namespace, and put back below on the normal path — with the exit trap as
  # the fallback that makes the restore survive a `die`, a timeout or a Ctrl-C mid-run.
  ts_before="$(sudo ip netns exec "$NS_CLI" sysctl -n net.ipv4.tcp_timestamps 2>/dev/null)"
  [[ "$ts_before" =~ ^[0-9]+$ ]] || ts_before=1 # the kernel default, if it could not be read
  sudo ip netns exec "$NS_CLI" sysctl -qw net.ipv4.tcp_timestamps=0 \
    || die "could not clear net.ipv4.tcp_timestamps in $NS_CLI"
  TS_RESTORE="$ts_before"
  say "net.ipv4.tcp_timestamps in $NS_CLI: $ts_before -> 0 (V10's PAWS precondition)"

  for b in "${bins[@]}"; do
    say "=== $(basename "$b") --ignored"
    # Bounded, because this is exactly the failure 10.5 found: the first ever execution of
    # `a_cancelled_dial_leaves_nothing_behind` blocked for ever on an accept, and since it holds
    # the PRIVILEGED guard it took the rest of the `--ignored` run with it. Unbounded over ssh
    # that leaves a root-owned process holding raw sockets on a shared host and skips everything
    # below, sysctl restore included.
    # `--skip fuzz_seeds` drops the `write_*_fuzz_seeds` corpus writers, which are `#[ignore]`d
    # for an unrelated reason: each rewrites `env!("CARGO_MANIFEST_DIR")/fuzz/seeds/…`, and in a
    # cross-built executable that is the *laptop's* absolute path, baked in at compile time. Run
    # as root here, it creates a root-owned `/Users/…` tree outside ~/kcptun-lab, against
    # tools/lab/README.md rule 7 on a shared host. They are no part of 10.5 either: the privileged tcpraw
    # set is 7 tests. (The `*_fuzz_seed_files_up_to_date` readers are not `#[ignore]`d and their
    # names hold `fuzz_seed`, not `fuzz_seeds`, so this filter leaves them alone.)
    sudo ip netns exec "$NS_CLI" timeout -k 10 "$TEST_TIMEOUT" "$b" --ignored --skip fuzz_seeds
    rc=$?
    if [[ $rc -eq 124 ]]; then
      fail "$(basename "$b") --ignored timed out after ${TEST_TIMEOUT}s (a hung privileged test)"
    elif [[ $rc -ne 0 ]]; then
      fail "$(basename "$b") --ignored exited $rc"
    fi
  done

  # The normal-path restore, here and not only in the exit trap: a failure has to reach `problems`
  # and so the final `die`, which an EXIT trap cannot do once the exit status is fixed. Clearing
  # TS_RESTORE afterwards leaves the trap as a pure fallback.
  if sudo ip netns exec "$NS_CLI" sysctl -qw "net.ipv4.tcp_timestamps=$ts_before"; then
    TS_RESTORE=""
    say "net.ipv4.tcp_timestamps in $NS_CLI restored to $ts_before"
  else
    fail "could not restore net.ipv4.tcp_timestamps in $NS_CLI"
  fi

  # The privileged tests install and remove `filter/OUTPUT` rules of their own, so the chains are
  # part of the result: both families, as everywhere else here.
  [[ "$(chain "$NS_CLI")" == "$base" ]] || { fail "rules survived the test run"; chain "$NS_CLI"; }
  [[ "$(chain6 "$NS_CLI")" == "$base6" ]] || { fail "ip6 rules survived the test run"; chain6 "$NS_CLI"; }
}

cmd="${1:-}"
shift || true
case "$cmd" in
  matrix) write_helpers; need_tunnels; matrix ;;
  v22) write_helpers; need_tunnels; v22 ;;
  cleanup) write_helpers; need_tunnels; cleanup ;;
  pcap) write_helpers; need_tunnels; pcap ;;
  tests) tests "$@" ;;
  *) die "usage: lab-tcpraw.sh <matrix|v22|cleanup|pcap|tests [binary...]>" ;;
esac
# stop_all/stop_echo are the exit trap's job now, so they also run when a `die` above cuts in.
[[ $problems -eq 0 ]] || die "finished WITH PROBLEMS (see FAIL lines above)"
say "OK"
