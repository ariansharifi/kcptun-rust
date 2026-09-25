#!/usr/bin/env python3
"""Check that UDP (and optionally TCP) ports on a lab host are reachable from the laptop.

Starts a short-lived echo listener on the remote host over ssh (ports must be >= 4000, see
tools/lab/README.md, safety rule 4), then probes each port from here. The listener bounds itself to 20 seconds, so
an interrupted probe leaves nothing running.

Usage: tools/lab/udp-probe.py --ssh <host> --host <ip> [--ports 29900,29901] [--tcp]

Which of the sanctioned ports a cloud host actually lets in is a property of somebody else's
firewall, not of the lab: only 29900, 4000 and 12948 have ever been verified open on lab-arm64,
and nothing is known about the rest of the 29900-29920 block. Checking is a minute; finding out from a
WAN matrix that timed out for ninety minutes is not.
"""
import argparse
import os
import shlex
import socket
import subprocess
import sys
import time

REMOTE = r'''
import select, socket, sys, time
ports = [int(p) for p in sys.argv[1].split(",")]
tcp = sys.argv[2] == "1"
socks = []
for p in ports:
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("0.0.0.0", p)); socks.append(u)
    if tcp:
        t = socket.socket(); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        t.bind(("0.0.0.0", p)); t.listen(4); socks.append(t)
print("ready", flush=True)
end = time.time() + 20
while time.time() < end:
    r, _, _ = select.select(socks, [], [], 0.5)
    for s in r:
        if s.type == socket.SOCK_DGRAM:
            d, a = s.recvfrom(64); s.sendto(b"pong:" + d, a)
        else:
            c, _ = s.accept(); c.sendall(b"pong"); c.close()
'''


def ssh_hostname(alias: str) -> str | None:
    """The address `ssh <alias>` would dial, per ``ssh -G``; None if it cannot be resolved."""
    try:
        out = subprocess.run(["ssh", "-G", alias], capture_output=True, text=True,
                             timeout=10, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        key, _, value = line.partition(" ")
        if key == "hostname" and value.strip():
            return value.strip()
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ssh", default=os.environ.get("KCPTUN_LAB_HOST", "lab-arm64"),
                    help="ssh host (config alias) that runs the echo listener "
                         "[$KCPTUN_LAB_HOST]")
    ap.add_argument("--host", help="address the probes are sent to; defaults to the address "
                                   "`ssh -G <--ssh>` resolves")
    ap.add_argument("--ports", default="29900,29901")
    ap.add_argument("--tcp", action="store_true")
    a = ap.parse_args()
    # No default address. `--host` used to default to lab-arm64's IP while `--ssh` defaults to
    # lab-arm64, so `--ssh lab-x86-1 --ports ...` started the listener on one host and probed
    # another, printing "NO REPLY" for ports that are open: a false negative that looks exactly
    # like a closed firewall. `ssh -G` resolves the alias the same way ssh itself will.
    if not a.host:
        a.host = ssh_hostname(a.ssh)
        if not a.host:
            sys.exit(f"--host is required: cannot resolve an address for ssh host {a.ssh!r} "
                     "(pass the address explicitly, or add the alias to ~/.ssh/config)")
        print(f"--host not given; probing {a.host} (from `ssh -G {a.ssh}`)")
    ports = [int(p) for p in a.ports.split(",")]
    if any(p < 4000 for p in ports):
        sys.exit("refusing: ports below 4000 must not be used on a lab host "
                 "(tools/lab/README.md, safety rule 4)")
    # ssh joins its command words with spaces and hands the result to a *remote shell*, which
    # splits them again, so the listener has to be quoted as one shell word. Without this the
    # remote sh saw `python3 -c import` followed by the rest of the script as shell code, and
    # every probe failed with "remote listener failed to start" whatever the firewall said.
    remote = " ".join(shlex.quote(word) for word in
                      ("python3", "-c", REMOTE, a.ports, "1" if a.tcp else "0"))
    proc = subprocess.Popen(["ssh", a.ssh, remote], stdout=subprocess.PIPE, text=True)
    if proc.stdout.readline().strip() != "ready":
        sys.exit("remote listener failed to start")
    ok = True
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.5)
        got = False
        for _ in range(4):
            s.sendto(b"ping", (a.host, p))
            try:
                d, _ = s.recvfrom(64)
                got = d == b"pong:ping"
                break
            except socket.timeout:
                pass
        print(f"udp {p}: {'open' if got else 'NO REPLY'}")
        ok &= got
        if a.tcp:
            try:
                with socket.create_connection((a.host, p), timeout=3) as c:
                    got_t = c.recv(4) == b"pong"
            except OSError:
                got_t = False
            print(f"tcp {p}: {'open' if got_t else 'NO REPLY'}")
            ok &= got_t
    proc.terminate()
    time.sleep(0.2)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
