#!/usr/bin/env python3
"""Scenario runner for the Step 11 network lab (step 11, 11.1).

Runs **on the laptop** and drives the lab host over ssh. python3 standard library only.

    tools/lab/lab.py deploy                      # scripts, Go and Rust binaries, lab tools
    tools/lab/lab.py netns-up wan50              # namespace lab with netem on our veths
    tools/lab/lab.py run tools/lab/scenarios/smoke.json
    tools/lab/lab.py run tools/lab/scenarios/soak-s1-wan50.json --detach
    tools/lab/lab.py status <runid>
    tools/lab/lab.py collect <runid>             # finish a detached run and write the report
                                                 # (--host must name the host it was started on;
                                                 #  both refuse otherwise, naming the right one)
    tools/lab/lab.py netns-down
    tools/lab/lab.py cleanup                     # stop everything, verify against the baseline

A scenario runs in one of two **modes** (11.1 built the first, 11.3 added the second):

``netns``
    Both tunnel ends live in the ``kr-cli``/``kr-srv`` namespaces of a single host, with netem
    on our own veths. Reproducible, and the only way to *choose* an impairment.
``wan``
    The client runs on ``--host`` and the server on ``--server-host``, two real machines, with
    the real Internet path between them and **no netem anywhere**. Nothing is namespaced, the
    kcptun server listens on the host's own address, and both ends are sampled and collected
    separately::

        tools/lab/lab.py --host lab-x86-3 run tools/lab/scenarios/wan-s1-bulk.json \\
            --server-host lab-arm64 --server-addr <lab-arm64-ip>

    A real path is *not* reproducible between sessions: its capacity, queueing and cross
    traffic are somebody else's, so only Go-versus-Rust comparisons taken inside one session,
    interleaved (GG, RR, GR, RG), mean anything. `plan_runs` interleaves; the report says so.

Everything that changes state on the host goes through the guarded helpers in
``tools/lab/server/`` (``lab-baseline.sh``, ``lab-netns.sh``, ``lab-start.sh``, ``lab-stop.sh``,
``lab-signal.sh``, ``lab-wait.sh``, ``lab-status.sh``, ``lab-collect.sh``, ``lab-cleanup.sh``),
which enforce the safety rules of tools/lab/README.md in code: only ``kr-*``/``kg-*``/``iperf3``
binaries may be started, no port below 4000 may appear in an argument, processes are stopped
only by PID file after ``/proc/<pid>/exe`` is verified, and netem only ever touches our own
veths. This script adds nothing that bypasses them; its only direct ssh use is read-only
(``uptime``, ``cat``, ``tar``).

**The host runs a live production mesh.** Nothing here kills by name, touches a
process it did not start, or listens below port 4000.

A six-hour soak is the reason several things look paranoid:

* the workloads, ``pingpong serve`` and ``labsample`` are all given a ``--duration`` and stop by
  themselves, so a laptop that goes to sleep cannot leave traffic running for ever. The two
  tunnel ends and ``iperf3 -s`` have no such bound: they keep running (as does the namespace lab)
  until ``lab.py collect`` or ``lab.py cleanup`` stops them, which is why cleanup has to end
  every session;
* workload and sampler output is append-only CSV, flushed per row, written on the host: a
  dropped ssh connection loses nothing;
* ``run --detach`` returns as soon as the run is started, and ``collect`` finishes it later.

A run also refuses to start unless it can **name the binary each end will execute** (12.0): the
stamp ``deploy.sh`` leaves beside the binaries must carry a commit, a libc and a target, and the
binary on the host must hash to what that stamp records. ``--allow-unprovenanced`` downgrades
the refusal to a warning and marks every report of the session ``UNPROVENANCED``.
"""

from __future__ import annotations

import argparse
import collections
import csv
import dataclasses
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

# --------------------------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------------------------

REPO = Path(__file__).resolve().parents[2]
DEFAULT_HOST = os.environ.get("KCPTUN_LAB_HOST", "lab-arm64")
LAB = "$HOME/kcptun-lab"

# The ``label`` half of a ``label=value`` flag argument (``--pid cli=123``, ``--log cli=path``).
# Nothing outside this set is left unquoted for the remote shell.
LABEL_RE = re.compile(r"^[A-Za-z0-9_.-]+$")

SSH_OPTS = [
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=15",
    # A six-hour run is waited on with one ssh connection; keep it alive across a quiet hour.
    "-o", "ServerAliveInterval=30",
    "-o", "ServerAliveCountMax=6",
]

#: ssh failures that happened **before the remote command could run**, and are therefore safe to
#: retry. Every lab host is a VPS with sshd on the public Internet, so all of them are under
#: continuous credential-stuffing traffic; when a bot fills sshd's `MaxStartups` queue, an
#: honest connection is dropped during the key exchange. One 12-run cell of the 11.2 matrix is
#: about 250 ssh round trips, and losing that race once killed a cell mid-run, leaving a tunnel
#: up on the host, which then failed the port check of every cell after it. These signatures all
#: come from ssh's own pre-authentication path (`ssh` exits 255 and the command never started),
#: so retrying cannot run anything twice. A mid-session drop reads differently
#: ("client_loop: send disconnect", "Connection to ... closed by remote host") and is **not**
#: retried, because there the command may well have run.
SSH_RETRY_MARKERS = (
    "kex_exchange_identification",
    "connection reset by",
    "connection refused",
    "connection timed out",
    "no route to host",
    "banner exchange",
    "temporary failure in name resolution",
)

#: How long to wait before each retry. Four attempts over ~17 s: long enough to outlast a burst
#: of bot connections, short enough that a genuinely unreachable host still fails the run.
SSH_RETRY_BACKOFF = (2.0, 5.0, 10.0)

#: netem profiles, as implemented by ``lab-netns.sh`` (tools/lab/README.md).
#:
#: ``blackhole`` (100 % loss) is last deliberately: it is 11.5's fault injection rather than an
#: impairment to measure *through*, and ``matrix_family`` ranks profiles by their position in
#: this tuple, so appending it leaves every table already published in the order it was in.
PROFILES = ("clean", "lan", "wan50", "lossy2", "lossy10", "burst", "ratelimited", "blackhole")

#: How a scenario places its two tunnel ends. See the module docstring.
MODE_NETNS = "netns"
MODE_WAN = "wan"
MODES = (MODE_NETNS, MODE_WAN)

#: Ports, all used inside our network namespaces (tools/lab/README.md rule 4).
DEFAULT_TUNNEL_PORT = 29900       # UDP, 29900-29920
DEFAULT_LISTEN_PORT = 12948       # client listener, 12948-12960
DEFAULT_IPERF_PORT = 5201         # iperf3
DEFAULT_PINGPONG_PORT = 22600     # loopback-only test range 22000-28999

#: ``USER_HZ``: the unit of ``utime``/``stime`` in ``/proc/<pid>/stat``. 100 on every Linux the
#: lab runs on (lab-arm64 included), but it is a kernel build option, so the value lives here and
#: is passed to ``kr-labsample --clock-ticks`` as well as used to turn the CSV's tick counters
#: into seconds, one number, so the report's "CPU s" column can never contradict its own CSV.
CLOCK_TICKS = 100

#: The netns addresses ``lab-netns.sh`` configures.
NS_CLIENT = "kr-cli"
NS_SERVER = "kr-srv"
SERVER_IP = "10.200.0.2"

#: Where a WAN run's *server host* artefacts are kept inside the local run directory. Both
#: machines write a ``proc.csv`` and the client one is the run's own, so the server's needs a
#: place of its own rather than a rename that would make the two tables look unrelated.
SERVER_SUBDIR = "server"

#: How long ``finish_run`` lets the SIGUSR1 SNMP dump reach the process log before it stops the
#: tunnel. A module constant rather than a literal so the test suite can zero it: most of
#: ``lab_test.py`` drives a non-dry ``FakeRunner`` through ``finish_run``, and a real second each
#: made the python suite the slowest target in the gate.
SNMP_SETTLE_SECONDS = 1.0

#: kcptun's own ``-sockbuf`` default, in bytes.
#:
#: From `reference/kcptun/client/main.go:185-188` and `reference/kcptun/server/main.go:176-179`,
#: both ``Value: 4194304 // default socket buffer size in bytes``. It is applied to the UDP
#: socket with ``SetReadBuffer(config.SockBuf)`` *and* ``SetWriteBuffer(config.SockBuf)``
#: (`client/main.go:467-471`, `server/main.go:412-416`), unconditionally, so a configuration
#: that passes no ``-sockbuf`` at all is **not** asking for a small buffer: it is asking for
#: 4 MiB, 20x the stock `net.core.rmem_max` of 212992. S1 is the loud case because it names
#: 8 MiB explicitly, but S2/S3/S4 are clamped on a stock host too, which is why this is a
#: constant read out of the Go source rather than an absent flag treated as "no request".
#:
#: `tools/bench/bench.py` imports this rather than keeping its own copy: two tools warning about
#: two different numbers is how a clamp stays invisible for a campaign.
DEFAULT_SOCKBUF = 4194304

#: Flag sets from step 11.2. Values are rendered Go style (``-flag value``); ``True``
#: renders as a bare flag and ``False`` omits it.
CONFIGS: dict[str, dict[str, dict[str, Any]]] = {
    # S1: the user's production profile (docs/benchmarks/memory.md uses exactly these).
    "s1": {
        "common": {
            "mode": "normal", "crypt": "xor", "mtu": 1390,
            "sndwnd": 8192, "rcvwnd": 8192,
            "smuxver": 2, "smuxbuf": 16777216, "streambuf": 16777216,
            "datashard": 0, "parityshard": 0, "nocomp": True, "quiet": True,
        },
        "client": {"conn": 4, "sockbuf": 8388608},
        "server": {"sockbuf": 67108868},
    },
    # S2: kcptun's own defaults, written out so the scenario is self-documenting.
    "s2": {
        "common": {
            "mode": "fast", "crypt": "aes", "mtu": 1350,
            "sndwnd": 128, "rcvwnd": 512,
            "smuxver": 2, "smuxbuf": 4194304, "streambuf": 2097152,
            "datashard": 10, "parityshard": 3,
        },
        "client": {"conn": 1},
        "server": {},
    },
    # S3: fast3 with AEAD and FEC.
    "s3": {
        "common": {
            "mode": "fast3", "crypt": "aes-128-gcm", "mtu": 1350,
            "sndwnd": 1024, "rcvwnd": 1024,
            "smuxver": 2, "datashard": 10, "parityshard": 3,
        },
        "client": {"conn": 1},
        "server": {},
    },
    # S4: a stream cipher without FEC.
    "s4": {
        "common": {
            "mode": "fast", "crypt": "salsa20", "mtu": 1350,
            "sndwnd": 1024, "rcvwnd": 1024,
            "smuxver": 2, "datashard": 0, "parityshard": 0,
        },
        "client": {"conn": 1},
        "server": {},
    },
}

IMPLS = {"go": "g", "rust": "r"}

#: SNMP counters quoted in every report (the full set stays in the CSV).
#:
#: Every one is reported as the LAST record's absolute value, which for a run is its total, not
#: as a delta. `DefaultSnmp` is a process-global that starts at zero and is never reset (kcptun
#: has no `Reset()` call anywhere) and a run always starts fresh processes, so the last record IS
#: the whole-run total. Subtracting the first record would throw away a whole `-snmpperiod` of
#: traffic, because neither logger writes at t=0: Go's `time.NewTicker` + `for range ticker.C`
#: (reference/kcptun/std/snmp.go) and the Rust logger's discarded first `tick()`
#: (crates/std/src/snmp.rs) both put the first record at t=snmpperiod, already holding everything
#: that happened up to then. On the 11.2 lossy profiles that first period is full-rate bulk
#: traffic, and the FEC counters its acceptance check reads would be off by a double-digit
#: percentage. The session counters (MaxConn, ActiveOpens, PassiveOpens, CurrEstab) were already
#: absolute for the same reason.
SNMP_COLUMNS = (
    "BytesSent", "BytesReceived", "InPkts", "OutPkts", "InSegs", "OutSegs",
    "RetransSegs", "FastRetransSegs", "EarlyRetransSegs", "LostSegs", "RepeatSegs",
    "FECRecovered", "FECErrs", "FECParityShards", "InCsumErrors", "KCPInErrors", "InErrs",
    "MaxConn", "ActiveOpens", "PassiveOpens", "CurrEstab",
)

#: Log lines that mean something went wrong. Matched case-insensitively against every collected
#: log; anything matched is quoted in the report's "notes" section.
ERROR_MARKERS = (
    "panic",
    "fatal",
    "invalid",
    "corrupt",
    "too many open files",
    "cannot allocate",
    "csv write failed",
    "assertion",
)

#: Lines that look alarming but are the expected consequence of a tunnel being restarted,
#: blackholed or simply closed. They never make it into the report's notes.
BENIGN_MARKERS = (
    "invalid argument",          # SetReadBuffer on a small sockbuf, matches Go exactly
)


# --------------------------------------------------------------------------------------------
# ssh plumbing
# --------------------------------------------------------------------------------------------


class LabError(RuntimeError):
    """Anything that should stop the run with a readable message."""


@dataclass
class Result:
    """The outcome of one remote command."""

    argv: list[str]
    code: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.code == 0


def remote_quote(arg: str) -> str:
    """Quote one argument for the remote shell, leaving a leading ``$HOME/`` expandable.

    Remote paths are written ``$HOME/kcptun-lab/...`` (tools/lab/README.md) because the lab lives in
    the login user's home directory and the helpers are invoked through it.

    Some flags take the path *inside* a ``label=path`` value: ``kr-labsample --log
    cli=$HOME/kcptun-lab/logs/...``. Those must expand too: ``shlex.quote`` would single-quote
    the whole word because of the ``$``, the literal ``$HOME`` would then survive lab-start.sh's
    ``printf '%q '``, and the sampler would open a file that does not exist: silently, since
    a log it cannot stat is simply not reported. ``cli="$HOME/..."`` is one shell word and
    expands correctly, so the prefix is kept bare and only the path is quoted.
    """
    if arg.startswith("$HOME/"):
        return '"$HOME/' + arg[len("$HOME/"):].replace('"', '\\"') + '"'
    label, sep, rest = arg.partition("=")
    if sep and rest.startswith("$HOME/") and LABEL_RE.match(label):
        return label + "=" + remote_quote(rest)
    return shlex.quote(arg)


def ssh_should_retry(result: "Result") -> bool:
    """Whether an ssh failure is one the remote command cannot have survived (see the markers).

    ssh reserves 255 for its own errors; anything else is the remote command's exit status and
    is never retried, however it looks. The marker has to be in ssh's *stderr* and the command
    must have produced no output, so a remote command that merely printed "connection refused"
    is not mistaken for ssh failing to connect.
    """
    if result.code != 255 or result.out:
        return False
    lowered = result.err.lower()
    return any(marker in lowered for marker in SSH_RETRY_MARKERS)


class Runner:
    """Runs commands on the lab host over ssh."""

    def __init__(self, host: str, *, dry_run: bool = False, verbose: bool = False) -> None:
        self.host = host
        self.dry_run = dry_run
        self.verbose = verbose

    # -- low level ---------------------------------------------------------------------------

    def ssh(self, command: str, *, check: bool = True,
            timeout: float | None = 120.0) -> Result:
        """Runs one shell command on the host, retrying a connection ssh never established."""
        argv = ["ssh", *SSH_OPTS, self.host, command]
        if self.verbose or self.dry_run:
            print(f"+ ssh {self.host} {command}", file=sys.stderr)
        if self.dry_run:
            return Result(argv, 0, "", "")
        result = self._ssh_once(argv, command, timeout)
        for delay in SSH_RETRY_BACKOFF:
            if not ssh_should_retry(result):
                break
            print(f"lab: ssh to {self.host} did not connect "
                  f"({result.err.strip().splitlines()[-1] if result.err.strip() else '?'}); "
                  f"retrying in {delay:.0f}s", file=sys.stderr)
            time.sleep(delay)
            result = self._ssh_once(argv, command, timeout)
        err = result.err
        if check and not result.ok:
            raise LabError(f"remote command failed ({result.code}): {command}\n{err.strip()}")
        return result

    def _ssh_once(self, argv: Sequence[str], command: str,
                  timeout: float | None) -> Result:
        try:
            proc = subprocess.run(
                list(argv),
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise LabError(f"ssh timed out after {timeout}s: {command}") from exc
        return Result(
            list(argv),
            proc.returncode,
            proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"),
        )

    def lab(self, script: str, *args: str, check: bool = True,
            timeout: float | None = 120.0) -> Result:
        """Runs one of the guarded ``lab-*.sh`` helpers."""
        quoted = " ".join(remote_quote(a) for a in args)
        return self.ssh(f'"$HOME/kcptun-lab/scripts/lab-{script}.sh" {quoted}',
                        check=check, timeout=timeout)

    def local(self, argv: Sequence[str], *, check: bool = True,
              timeout: float | None = 900.0,
              env: dict[str, str] | None = None) -> Result:
        """Runs a command on the laptop (``deploy.sh``, ``tar``).

        ``env`` replaces the child's environment wholesale, so callers build it from
        ``os.environ``; it is how ``deploy.sh`` is told which host ``--host`` selected.
        """
        if self.verbose or self.dry_run:
            print("+ " + " ".join(shlex.quote(a) for a in argv), file=sys.stderr)
        if self.dry_run:
            return Result(list(argv), 0, "", "")
        proc = subprocess.run(argv, capture_output=True, timeout=timeout, check=False, env=env)
        result = Result(list(argv), proc.returncode,
                        proc.stdout.decode("utf-8", "replace"),
                        proc.stderr.decode("utf-8", "replace"))
        if check and not result.ok:
            raise LabError(f"command failed ({proc.returncode}): {' '.join(argv)}\n{result.err}")
        return result

    # -- convenience -------------------------------------------------------------------------

    def start(self, name: str, argv: Sequence[str], *, netns: str | None = None) -> None:
        """Starts one process through ``lab-start.sh``."""
        args: list[str] = []
        if netns:
            args += ["--netns", netns]
        args += [name, "--", *argv]
        self.lab("start", *args)

    def stop(self, names: Iterable[str]) -> None:
        names = [n for n in names]
        if names:
            self.lab("stop", *names, check=False)

    def socket_buffer_limits(self) -> dict[str, int]:
        """``net.core.rmem_max`` and ``wmem_max`` on the host, read straight from ``/proc``.

        `setsockopt(SO_RCVBUF)` is **silently clamped** to these, so a scenario that asks for
        `-sockbuf 8388608` on a host whose `rmem_max` is the 212992 default gets a 208 KiB
        buffer and never hears about it. On the 11.2 matrix that difference was the whole of
        the S1 `lossy10` result: one 65 s run overflowed the receive buffer 223,000 times, and
        the same run with `rmem_max` raised to lab-arm64's 8 MiB overflowed it **zero** times.
        Which is to say it is not a detail (it can invert the conclusion) so it is read
        before every run and kept in `state.json`.
        """
        out = self.ssh("cat /proc/sys/net/core/rmem_max /proc/sys/net/core/wmem_max",
                       check=False).out.split()
        limits: dict[str, int] = {}
        for name, value in zip(("rmem_max", "wmem_max"), out):
            try:
                limits[name] = int(value)
            except ValueError:
                pass
        return limits

    def pids(self, names: Sequence[str]) -> dict[str, int]:
        """Reads the PID files of `names`; a missing or unreadable file is simply absent."""
        if not names:
            return {}
        reads = " ; ".join(
            f"printf '%s ' {shlex.quote(n)} ; "
            f'cat "$HOME/kcptun-lab/run/{n}.pid" 2>/dev/null || echo'
            for n in names
        )
        out = self.ssh(reads, check=False).out
        found: dict[str, int] = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                found[parts[0]] = int(parts[1])
        return found

    def load_average(self) -> float | None:
        out = self.ssh("cat /proc/loadavg", check=False).out.split()
        try:
            return float(out[0])
        except (IndexError, ValueError):
            return None

    def uptime(self) -> str:
        """The host's ``uptime`` line, read-only.

        step 11.3 asks for it **before and after every run** on both ends, because a WAN
        number from a 1-vCPU box that was already loaded says nothing about the protocol. It is
        recorded in `state.json` and printed in the report rather than left in a terminal.
        """
        return " ".join(self.ssh("uptime", check=False).out.split())

    def peer(self, host: str) -> "Runner":
        """A runner for another lab host, carrying this one's dry-run and verbose settings.

        A WAN run drives two machines at once (11.3). Going through this rather than
        constructing a `Runner` directly is what lets the tests substitute a fake for *both*
        ends: `lab.py` never names the class.
        """
        if host == self.host:
            return self
        return Runner(host, dry_run=self.dry_run, verbose=self.verbose)

    def fetch_dir(self, remote_dir: str, local_dir: Path) -> None:
        """Copies a directory from the host by streaming a tar over ssh (read-only)."""
        if not self.dry_run:
            local_dir.mkdir(parents=True, exist_ok=True)
        parent, name = remote_dir.rsplit("/", 1)
        command = f'tar czf - -C {remote_quote(parent)} {shlex.quote(name)}'
        if self.verbose or self.dry_run:
            print(f"+ ssh {self.host} {command} | tar xzf - -C {local_dir}", file=sys.stderr)
        if self.dry_run:
            return
        with subprocess.Popen(
            ["ssh", *SSH_OPTS, self.host, command], stdout=subprocess.PIPE
        ) as source:
            extract = subprocess.run(
                ["tar", "xzf", "-", "-C", str(local_dir), "--strip-components", "1"],
                stdin=source.stdout,
                capture_output=True,
                check=False,
            )
            source.wait()
        if extract.returncode != 0:
            raise LabError(
                "could not fetch "
                f"{remote_dir}: {extract.stderr.decode('utf-8', 'replace').strip()}"
            )


# --------------------------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------------------------


@dataclass
class Workload:
    """One thing that drives traffic through the tunnel during a run."""

    type: str
    tag: str
    duration: int = 30
    start_after: int = 0
    options: dict[str, Any] = field(default_factory=dict)

    @property
    def needs_pingpong(self) -> bool:
        return self.type in ("ping", "bulk", "churn")


@dataclass
class Scenario:
    """A complete description of what to run."""

    name: str
    description: str = ""
    config: str = "s1"
    mode: str = MODE_NETNS
    #: WAN mode only: the ssh alias of the host the kcptun **server** runs on, and the address
    #: the client dials it at. The client host is always ``--host``.
    server_host: str = ""
    server_addr: str = ""
    netem: str = "clean"
    pairs: list[tuple[str, str]] = field(default_factory=lambda: [("rust", "rust")])
    repetitions: int = 1
    key: str = "labkey"
    settle: int = 5
    sample_interval: int = 60
    snmp_period: int = 60
    log_cap_bytes: int = 256 * 1024 * 1024
    client_flags: dict[str, Any] = field(default_factory=dict)
    server_flags: dict[str, Any] = field(default_factory=dict)
    workloads: list[Workload] = field(default_factory=list)
    tunnel_port: int = DEFAULT_TUNNEL_PORT
    #: How many consecutive tunnel ports the tunnel spans, kcptun's multiport range
    #: (``-l :29900-29903``, ``-r host:29900-29903``). 1 is a single port, as before.
    tunnel_port_count: int = 1
    listen_port: int = DEFAULT_LISTEN_PORT
    iperf_port: int = DEFAULT_IPERF_PORT
    pingpong_port: int = DEFAULT_PINGPONG_PORT
    source: str = ""

    @property
    def tunnel_ports(self) -> list[int]:
        """Every UDP port the tunnel occupies."""
        return [self.tunnel_port + offset for offset in range(self.tunnel_port_count)]

    @property
    def tunnel_spec(self) -> str:
        """kcptun's address suffix for the tunnel: ``29900`` or ``29900-29903``."""
        if self.tunnel_port_count == 1:
            return str(self.tunnel_port)
        return f"{self.tunnel_port}-{self.tunnel_ports[-1]}"

    @property
    def is_wan(self) -> bool:
        return self.mode == MODE_WAN

    @property
    def target(self) -> str:
        """``iperf3`` or ``pingpong``: a kcptun server forwards to exactly one address."""
        return "pingpong" if any(w.needs_pingpong for w in self.workloads) else "iperf3"

    @property
    def total_duration(self) -> int:
        """How long the traffic lasts, in seconds."""
        return max((w.start_after + w.duration for w in self.workloads), default=0)


def _as_int(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise LabError(f"{what}: want a number, got {value!r}")
    return int(value)


def _check_port(port: int, low: int, high: int, what: str) -> int:
    if not low <= port <= high:
        raise LabError(f"{what}: {port} is outside the sanctioned range {low}-{high} "
                       "(tools/lab/README.md rule 4)")
    if port < 4000:
        raise LabError(f"{what}: refusing a port below 4000")
    return port


def parse_scenario(raw: dict[str, Any], source: str = "") -> Scenario:
    """Validates a scenario dictionary. Every error names the field."""
    unknown = set(raw) - {f.name for f in dataclasses.fields(Scenario)}
    if unknown:
        raise LabError(f"unknown scenario field(s): {', '.join(sorted(unknown))}")

    name = str(raw.get("name") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
        raise LabError("name: must be [A-Za-z0-9._-] (it becomes a directory and a PID file)")

    config = str(raw.get("config", "s1")).lower()
    if config not in CONFIGS:
        raise LabError(f"config: {config!r} is not one of {', '.join(sorted(CONFIGS))}")

    mode = str(raw.get("mode", MODE_NETNS)).lower()
    if mode not in MODES:
        raise LabError(f"mode: {mode!r} is not one of {', '.join(MODES)}")

    netem = str(raw.get("netem", "clean"))
    if netem not in PROFILES:
        raise LabError(f"netem: {netem!r} is not one of {', '.join(PROFILES)}")
    if mode == MODE_WAN and netem != "clean":
        # A real path cannot be shaped: netem lives on the veths of the namespace lab, and the
        # only interface between two lab hosts is the primary NIC, which the lab never touches
        # (tools/lab/README.md rule 2). Silently ignoring the field would produce a report that
        # claims an impairment profile the run never had.
        raise LabError(f"netem: mode wan measures the real path, so it cannot apply {netem!r} "
                       "(netem needs the namespace lab; use mode netns)")

    pairs: list[tuple[str, str]] = []
    for pair in raw.get("pairs", [["rust", "rust"]]):
        if len(pair) != 2 or any(p not in IMPLS for p in pair):
            raise LabError(f"pairs: {pair!r} must be two of {', '.join(sorted(IMPLS))}")
        pairs.append((str(pair[0]), str(pair[1])))
    if not pairs:
        raise LabError("pairs: at least one client/server pair is required")

    workloads: list[Workload] = []
    seen_tags: set[str] = set()
    for index, item in enumerate(raw.get("workloads", [])):
        if not isinstance(item, dict):
            raise LabError(f"workloads[{index}]: want an object")
        options = dict(item)
        wtype = str(options.pop("type", "")).lower()
        if wtype not in ("iperf3", "ping", "bulk", "churn"):
            raise LabError(f"workloads[{index}].type: {wtype!r} is not iperf3, ping, bulk or churn")
        tag = str(options.pop("tag", f"{wtype}{index}"))
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", tag):
            raise LabError(f"workloads[{index}].tag: must be [A-Za-z0-9._-]")
        if tag in seen_tags:
            raise LabError(f"workloads[{index}].tag: {tag!r} is used twice")
        seen_tags.add(tag)
        duration = _as_int(options.pop("duration", 30), f"workloads[{index}].duration")
        start_after = _as_int(options.pop("start_after", 0), f"workloads[{index}].start_after")
        if duration <= 0 or start_after < 0:
            raise LabError(f"workloads[{index}]: duration must be > 0 and start_after >= 0")
        workloads.append(Workload(wtype, tag, duration, start_after, options))
    if not workloads:
        raise LabError("workloads: at least one is required")

    kinds = {w.type for w in workloads}
    if "iperf3" in kinds and kinds - {"iperf3"}:
        raise LabError(
            "workloads: a kcptun server forwards to exactly one target, so iperf3 workloads "
            "cannot share a scenario with ping/bulk/churn ones (use two scenarios, or replace "
            "the iperf3 flow with a `bulk` workload)"
        )

    port_count = _as_int(raw.get("tunnel_port_count", 1), "tunnel_port_count")
    if not 1 <= port_count <= 21:
        raise LabError("tunnel_port_count: must be between 1 and 21 "
                       "(the sanctioned range is 29900-29920)")

    scenario = Scenario(
        name=name,
        description=str(raw.get("description", "")),
        config=config,
        mode=mode,
        server_host=str(raw.get("server_host", "")),
        server_addr=str(raw.get("server_addr", "")),
        netem=netem,
        pairs=pairs,
        repetitions=_as_int(raw.get("repetitions", 1), "repetitions"),
        key=str(raw.get("key", "labkey")),
        settle=_as_int(raw.get("settle", 5), "settle"),
        sample_interval=_as_int(raw.get("sample_interval", 60), "sample_interval"),
        snmp_period=_as_int(raw.get("snmp_period", 60), "snmp_period"),
        log_cap_bytes=_as_int(raw.get("log_cap_bytes", 256 * 1024 * 1024), "log_cap_bytes"),
        client_flags=dict(raw.get("client_flags", {})),
        server_flags=dict(raw.get("server_flags", {})),
        workloads=workloads,
        tunnel_port=_check_port(_as_int(raw.get("tunnel_port", DEFAULT_TUNNEL_PORT),
                                        "tunnel_port"), 29900, 29920, "tunnel_port"),
        tunnel_port_count=port_count,
        listen_port=_check_port(_as_int(raw.get("listen_port", DEFAULT_LISTEN_PORT),
                                        "listen_port"), 12948, 12960, "listen_port"),
        iperf_port=_check_port(_as_int(raw.get("iperf_port", DEFAULT_IPERF_PORT),
                                       "iperf_port"), 5201, 5201, "iperf_port"),
        pingpong_port=_check_port(_as_int(raw.get("pingpong_port", DEFAULT_PINGPONG_PORT),
                                          "pingpong_port"), 22000, 28999, "pingpong_port"),
        source=source,
    )
    if scenario.repetitions < 1:
        raise LabError("repetitions: must be at least 1")
    if scenario.sample_interval < 1 or scenario.snmp_period < 1:
        raise LabError("sample_interval and snmp_period must be at least 1")
    # The whole range has to be inside the sanctioned block, not just its first port.
    _check_port(scenario.tunnel_ports[-1], 29900, 29920, "tunnel_port + tunnel_port_count")
    if "key" in scenario.client_flags or "key" in scenario.server_flags:
        raise LabError("client_flags/server_flags: set the shared key with `key`, not a flag")
    return scenario


def check_runnable(scenario: Scenario, client_host: str) -> None:
    """Whatever can only be checked once the command line's overrides are in.

    `server_host`/`server_addr` may come from the scenario file *or* from ``run``'s flags: one
    WAN scenario is meant to be pointed at every rung of the RTT ladder in turn (step 11.3),
    so neither can be required while the file is being parsed.
    """
    if not scenario.is_wan:
        return
    if scenario.netem != "clean":
        # Re-checked here and not only in `parse_scenario`, because `run --server-host` /
        # `--server-addr` promote a netns scenario to WAN *after* it has been parsed, which is
        # how every WAN run in the runbook is actually started. Checked at parse time only, a
        # `netem: wan50` file pointed at a real path ran with no impairment at all and a report
        # that said so in passing.
        raise LabError("netem: mode wan measures the real path, so it cannot apply "
                       f"{scenario.netem!r} (netem needs the namespace lab; use mode netns)")
    if not scenario.server_host:
        raise LabError("mode wan needs the server's ssh host (`run --server-host`, or the "
                       "scenario's `server_host`)")
    if not scenario.server_addr:
        # There is no default worth guessing: netns mode dials 10.200.0.2, and reusing that
        # here would send a two-host run into a namespace that does not exist.
        raise LabError("mode wan needs the address the client dials (`run --server-addr`, or "
                       "the scenario's `server_addr`)")
    if scenario.server_host == client_host:
        raise LabError(f"mode wan: client and server are both {client_host!r}; a WAN run needs "
                       "two hosts (use mode netns for a single-host run)")


def load_scenario(path: Path) -> Scenario:
    """Loads a ``.json`` or ``.toml`` scenario."""
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".toml":
        try:
            import tomllib
        except ModuleNotFoundError as exc:  # pragma: no cover - python < 3.11
            raise LabError("TOML scenarios need python 3.11+; use JSON instead") from exc
        raw = tomllib.loads(text)
    else:
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise LabError(f"{path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise LabError(f"{path}: want an object at the top level")
    try:
        return parse_scenario(raw, source=str(path))
    except LabError as exc:
        raise LabError(f"{path}: {exc}") from exc


# --------------------------------------------------------------------------------------------
# Command lines
# --------------------------------------------------------------------------------------------


def render_flags(flags: dict[str, Any]) -> list[str]:
    """Renders kcptun flags Go style: ``-flag value``, a bare ``-flag`` for ``True``."""
    argv: list[str] = []
    for name, value in flags.items():
        if value is False or value is None:
            continue
        argv.append(f"-{name}")
        if value is not True:
            argv.append(str(value))
    return argv


def merged_flags(scenario: Scenario, side: str) -> dict[str, Any]:
    """The configuration's flags for one side, with the scenario's overrides applied."""
    base = CONFIGS[scenario.config]
    flags: dict[str, Any] = dict(base["common"])
    flags.update(base[side])
    flags.update(scenario.client_flags if side == "client" else scenario.server_flags)
    return flags


def binary(impl: str, side: str) -> str:
    """The deployed path of one implementation's client or server."""
    if impl == "go":
        return f"{LAB}/bin/go/kg-{side}"
    return f"{LAB}/bin/rust/kr-{side}"


@dataclass
class RunPlan:
    """One concrete run: a pair, a repetition and the process names it owns."""

    runid: str
    scenario: Scenario
    client_impl: str
    server_impl: str
    repetition: int

    @property
    def names(self) -> list[str]:
        """Every process name, in start order."""
        names = [self.target_name, self.server_name, self.client_name, self.sampler_name,
                 *self.workload_names]
        if self.scenario.is_wan:
            # A second sampler, because /proc is per machine: the client host cannot see the
            # server's RSS and the server host cannot see the client's.
            names.insert(3, self.server_sampler_name)
        return names

    @property
    def target_name(self) -> str:
        return f"{self.runid}-tgt"

    @property
    def server_name(self) -> str:
        return f"{self.runid}-srv"

    @property
    def client_name(self) -> str:
        return f"{self.runid}-cli"

    @property
    def sampler_name(self) -> str:
        return f"{self.runid}-smp"

    @property
    def server_sampler_name(self) -> str:
        """The sampler on the *server* host: WAN mode only; /proc is per machine."""
        return f"{self.runid}-smps"

    @property
    def client_host_names(self) -> list[str]:
        """The processes that live on ``--host``: the client, its sampler and the workloads."""
        if not self.scenario.is_wan:
            return self.names
        return [self.client_name, self.sampler_name, *self.workload_names]

    @property
    def server_host_names(self) -> list[str]:
        """The processes that live on the server host (empty unless the run is a WAN one)."""
        if not self.scenario.is_wan:
            return []
        return [self.target_name, self.server_name, self.server_sampler_name]

    @property
    def workload_names(self) -> list[str]:
        return [f"{self.runid}-w{i}" for i in range(len(self.scenario.workloads))]

    @property
    def remote_dir(self) -> str:
        return f"{LAB}/logs/{self.runid}"

    # -- the command lines -------------------------------------------------------------------

    def target_argv(self) -> list[str]:
        s = self.scenario
        if s.target == "iperf3":
            return ["iperf3", "-s", "-B", "127.0.0.1", "-p", str(s.iperf_port)]
        # Outlive the traffic by a minute so a late workload never finds the target gone.
        return [
            f"{LAB}/bin/lab/kr-pingpong", "serve",
            "--listen", f"127.0.0.1:{s.pingpong_port}",
            "--duration", str(s.total_duration + s.settle + 60),
            "--report-interval", str(s.sample_interval),
        ]

    def server_argv(self) -> list[str]:
        s = self.scenario
        target = (f"127.0.0.1:{s.iperf_port}" if s.target == "iperf3"
                  else f"127.0.0.1:{s.pingpong_port}")
        return [
            binary(self.server_impl, "server"),
            "-l", f":{s.tunnel_spec}",
            "-t", target,
            "-key", s.key,
            *render_flags(merged_flags(s, "server")),
            "-snmplog", f"{self.remote_dir}/snmp-srv.csv",
            "-snmpperiod", str(s.snmp_period),
        ]

    @property
    def server_dial_addr(self) -> str:
        """Where the client dials the server: the netns address, or the real host's."""
        s = self.scenario
        return s.server_addr if s.is_wan else SERVER_IP

    def client_argv(self) -> list[str]:
        s = self.scenario
        return [
            binary(self.client_impl, "client"),
            "-l", f"127.0.0.1:{s.listen_port}",
            "-r", f"{self.server_dial_addr}:{s.tunnel_spec}",
            "-key", s.key,
            *render_flags(merged_flags(s, "client")),
            "-snmplog", f"{self.remote_dir}/snmp-cli.csv",
            "-snmpperiod", str(s.snmp_period),
        ]

    def sampler_argv(self, pids: dict[str, int]) -> list[str]:
        """The ``/proc`` sampler's command line for one machine.

        `pids` is what decides which processes it watches, which is also what splits a WAN run
        in two: ``/proc`` is per machine, so the client host is given the client's pid and the
        server host its server's and target's. The label sets are then disjoint and the two
        ``proc.csv`` files merge into one table without a collision, and a label missing from a
        WAN report means the process was not on that machine, not that it was not sampled.
        """
        s = self.scenario
        argv = [
            f"{LAB}/bin/lab/kr-labsample",
            "--out", f"{self.remote_dir}/proc.csv",
            "--interval", str(s.sample_interval),
            # Outlive the traffic, then stop by itself: an abandoned run leaves nothing behind.
            "--duration", str(s.total_duration + s.settle + 120),
            "--log-cap-bytes", str(s.log_cap_bytes),
            # Same USER_HZ the report uses for its own tick arithmetic (see CLOCK_TICKS).
            "--clock-ticks", str(CLOCK_TICKS),
            "--tag", self.runid,
        ]
        for label, name in (("cli", self.client_name), ("srv", self.server_name),
                            ("tgt", self.target_name)):
            if name in pids:
                argv += ["--pid", f"{label}={pids[name]}"]
        # Only the tunnel logs can grow with the workload; the target's cannot.
        for label, name in (("cli", self.client_name), ("srv", self.server_name)):
            if name in pids:
                argv += ["--log", f"{label}={LAB}/logs/{name}.log"]
        return argv

    def workload_argv(self, workload: Workload) -> list[str]:
        s = self.scenario
        options = dict(workload.options)
        if workload.type == "iperf3":
            argv = [
                "iperf3", "-c", "127.0.0.1", "-p", str(s.listen_port),
                "-t", str(workload.duration), "-J",
                "--logfile", f"{self.remote_dir}/iperf3-{workload.tag}.json",
            ]
            if options.pop("reverse", False):
                argv.append("-R")
            parallel = options.pop("parallel", None)
            if parallel:
                argv += ["-P", str(_as_int(parallel, "workload.parallel"))]
            omit = options.pop("omit", None)
            if omit:
                argv += ["-O", str(_as_int(omit, "workload.omit"))]
            bitrate = options.pop("bitrate", None)
            if bitrate:
                argv += ["-b", str(bitrate)]
            if options:
                raise LabError(f"workload {workload.tag}: unknown iperf3 option(s) "
                               f"{', '.join(sorted(options))}")
            return argv

        argv = [
            f"{LAB}/bin/lab/kr-pingpong", workload.type,
            "--connect", f"127.0.0.1:{s.listen_port}",
            "--duration", str(workload.duration),
            "--report-interval", str(s.sample_interval),
            "--tag", workload.tag,
            "--out", f"{self.remote_dir}/{workload.type}-{workload.tag}.csv",
        ]
        for key, value in options.items():
            flag = f"--{key.replace('_', '-')}"
            if value is True:
                argv.append(flag)
            elif value is False or value is None:
                continue
            else:
                argv += [flag, str(value)]
        return argv


def plan_runs(scenario: Scenario, stamp: str) -> list[RunPlan]:
    """Every run of a scenario, interleaved so the pairs share the host's conditions.

    Pairs alternate inside each repetition (GG, RR, GR, RG, then again), which is what makes a
    Go/Rust comparison on a box that also carries live traffic worth anything: background noise
    that drifts over ten minutes hits both implementations equally.
    """
    runs: list[RunPlan] = []
    for repetition in range(1, scenario.repetitions + 1):
        for client_impl, server_impl in scenario.pairs:
            code = IMPLS[client_impl] + IMPLS[server_impl]
            runid = f"{scenario.name}-{code}-r{repetition}-{stamp}"
            runs.append(RunPlan(runid, scenario, client_impl, server_impl, repetition))
    return runs


# --------------------------------------------------------------------------------------------
# Running
# --------------------------------------------------------------------------------------------


def preflight(runner: Runner, *, max_load: float, wait_seconds: int, force: bool,
              ports: Sequence[int] = ()) -> str:
    """Load check, port check and baseline snapshot (step 11.1 "Safety preflight")."""
    notes: list[str] = []
    deadline = time.monotonic() + max(0, wait_seconds)
    while True:
        load = runner.load_average()
        if load is None or load < max_load:
            notes.append(f"load average {load}")
            break
        if time.monotonic() >= deadline:
            message = (f"load average {load} is at or above {max_load}; the host carries live "
                       "traffic (tools/lab/README.md rule 6)")
            if not force:
                raise LabError(message + ": wait, or pass --force")
            notes.append("WARNING: " + message)
            break
        print(f"lab: load average {load} >= {max_load}, waiting…", file=sys.stderr)
        time.sleep(10)

    taken = runner.ssh('cat "$HOME/kcptun-lab/baseline/taken-at.txt" 2>/dev/null || true',
                       check=False).out.strip()
    if taken:
        notes.append(f"baseline from {taken}")
    else:
        runner.lab("baseline")
        notes.append("baseline taken now")

    # The baseline is taken once per session but the ports have to be checked on every run: the
    # usual way to collide is to start a second run while a detached one still holds the tunnel
    # port. `--ports-only` is read-only and looks inside the lab namespaces as well as the host.
    if ports:
        wanted = sorted({int(p) for p in ports})
        runner.lab("baseline", "--ports-only", *(str(p) for p in wanted))
        notes.append("ports " + ",".join(str(p) for p in wanted) + " free")
    return "; ".join(notes)


# --------------------------------------------------------------------------------------------
# Build provenance
# --------------------------------------------------------------------------------------------
#
# 11.3 ran a 27-run WAN campaign whose `server_build` is the empty string in **every** run,
# because `deployed_build` read one aggregate `bin/BUILD.txt` and the `kr-server` on the far
# host had none beside it. Nothing failed, nothing shouted, and the campaign's headline number
# (Rust 0.75x Go on the S1 upload at 131 ms) is consequently not a provable measurement of any
# particular tree. A silent empty field is exactly how that got 27 runs deep, so a run whose
# artefact cannot be identified now refuses to start.
#
# 11.3b re-took the question on the 95.3 ms rung with this check in force: 26 runs, every
# artefact on both hosts stamped, hashed and recorded, and the deficit did not reproduce
# (1.17x up, 1.68x down). That is what the refusal is for: the point is not that the old number
# was wrong, it is that nobody could tell.


#: Where `deploy.sh` leaves a stamp: *beside* the binaries it describes, one per family, never
#: one level up where a stale binary can sit next to no stamp at all.
BUILD_STAMPS = {
    "go": f"{LAB}/bin/go/BUILD.txt",
    "rust": f"{LAB}/bin/rust/BUILD.txt",
    "lab": f"{LAB}/bin/lab/BUILD.txt",
}

#: The pre-12.0 aggregate stamp. Read only to say *why* a host is unprovenanced: it describes
#: whatever the last deployment happened to copy, which need not be the binary about to run.
LEGACY_BUILD_STAMP = f"{LAB}/bin/BUILD.txt"

#: What a stamp must carry before a run may quote its numbers as this tree's.
REQUIRED_BUILD_FIELDS = ("kind", "commit", "libc", "target", "deployed")

#: The `deploy.sh` flag that rewrites each stamp.
BUILD_STAMP_FLAG = {"go": "--go", "rust": "--rust", "lab": "--tools"}

#: Every artefact identity a run records, in the order a single-host report prints them (a WAN
#: report groups them per host instead: client, tools, target, then server, server_tools,
#: server_target). The order here is the order `unprovenanced_notes` lists them. The `lab` family
#: is here because the numbers are only as attributable as the instrument that took them: a
#: latency percentile comes out of `kr-pingpong` and every RSS sample out of `kr-labsample`.
#:
#: This tuple is the *only* thing `unprovenanced_notes` iterates, so an artefact that `start_run`
#: requires but does not record is one whose refusal can never reach a report:
#: `--allow-unprovenanced` would promise an UNPROVENANCED banner and then produce a document
#: without one. That is 11.3's failure shape exactly, a loud check whose result never reaches
#: the page the number is quoted from, so requiring a stamp and recording it are one step here,
#: never two. The `target` keys are present only when the scenario's target is `kr-pingpong`; an
#: `iperf3` target is the host's own package and carries no stamp of ours.
BUILD_DETAIL_KEYS = ("client_build_detail", "server_build_detail",
                     "tools_build_detail", "target_build_detail",
                     "server_tools_build_detail", "server_target_build_detail")

#: How a report names each of them.
ARTEFACT_LABELS = {
    "client": "client",
    "server": "server",
    "tools": "lab tools",
    "server_tools": "lab tools (server host)",
    # Not "pingpong target": on a WAN run `kr-pingpong serve` sits on the *server* host while
    # `kr-pingpong ping|bulk|churn`: the end that emits every percentile, runs on the client
    # host, so calling the client-host copy the "target" misnames the measuring instrument.
    # Each line already carries the binary path and the host; the label need only say which file.
    "target": "pingpong",
    "server_target": "pingpong (server host)",
}

#: A stamp line is ``key=value``; anything else is prose (the human summary line).
BUILD_FIELD_RE = re.compile(r"^[A-Za-z0-9_.-]+$")

#: A commit as `git rev-parse` prints it. `unknown`, what `deploy.sh` records outside a
#: checkout, deliberately does not match.
COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")

#: The libc note `deploy.sh` writes, both as a stamp's `libc=` value and inside the pre-12.0
#: aggregate line (`rust x86_64-unknown-linux-gnu (glibc 2.17), profile release, …`). It is the
#: only thing a host deployed before 12.0 still says about which of D07's two allocators it is
#: running, which is what `BuildStamp.remedy` needs to avoid swapping one for the other.
LIBC_NOTE_RE = re.compile(r"glibc[ ]+[0-9][0-9.]*|static musl")


@dataclass(frozen=True)
class BuildStamp:
    """What is actually deployed on one host, for one implementation.

    `problem` is `None` when the stamp resolved *and* the binary this run will execute hashes to
    what the stamp says it does; otherwise it is the one-line reason, which is either refused
    (the default) or carried into the report as an "unprovenanced" marker.

    `legacy_summary` is the pre-12.0 aggregate line, when there was one and the per-family stamp
    is missing. It is never trusted as provenance (that is the whole point of the refusal) but
    it is the only evidence left of how the host was deployed, and `remedy()` uses it so that
    the suggested redeployment does not change the libc out from under the operator.
    Which target triple, which libc and which revision was measured is the difference between two
    opposite conclusions about the same numbers: D07 measured glibc returning 95.6 % of a burst
    where musl returns 4.9 %, so it belongs in `state.json` and in the report, not in prose
    somebody has to remember to write.

    Empty is **refused by the caller**, not tolerated: 11.3's whole 131 ms rung was measured with
    ``server_build`` blank in all 27 runs, which left a committed 0.75x upload result that cannot
    be attributed to this tree's binary at all. A number nobody can attribute to an artefact is
    worse than a run that did not happen, so `start_run` fails loudly instead.
    """

    kind: str
    host: str
    path: str
    binary: str
    fields: dict[str, str]
    summary: str
    problem: str | None = None
    legacy_summary: str = ""

    @property
    def ok(self) -> bool:
        return self.problem is None

    @property
    def commit(self) -> str:
        return self.fields.get("commit", "")

    @property
    def libc(self) -> str:
        return self.fields.get("libc", "")

    @property
    def sha256(self) -> str:
        return self.fields.get(f"sha256.{self.binary.rsplit('/', 1)[-1]}", "")

    @property
    def libc_evidence(self) -> str:
        """What is known about this host's libc: the stamp's note, the pre-12.0 line's, or ``""``.

        A stamp that resolved is authoritative. The case that matters more is the one this gate
        exists for (no per-family stamp at all, which is every host deployed before 12.0) and
        there `self.libc` is empty while the aggregate line `read_stamp_fields` already had to
        read usually still names a target and a libc note. That line is not provenance and is
        never recorded as such, but it is evidence, and evidence beats `deploy.sh`'s default.
        """
        if self.libc:
            return self.libc
        # Go binaries link no C library at all (`libc=none`), so nothing about them can be
        # flipped by `--gnu`; only the two Rust families can.
        if self.kind not in ("rust", "lab"):
            return ""
        match = LIBC_NOTE_RE.search(self.legacy_summary)
        return match.group(0) if match else ""

    def remedy(self) -> str:
        """The command line that would actually fix this, on the host that was refused.

        It names `lab.py deploy`, not `deploy.sh`: the script has no `--host` and takes its
        host from `$KCPTUN_LAB_HOST`, whose default is `lab-arm64`: the box carrying the live
        production mesh. A remedy of the form `deploy.sh --host <h> --rust` therefore exits 2
        with `unknown argument --host`, and the obvious hand-correction (dropping the flag)
        redeploys production instead of the host this run was refused on. `cmd_deploy` passes
        `--host` on as `$KCPTUN_LAB_HOST`, so the wrapper is the form that is safe to paste.

        The flags matter as much as the host. `deploy.sh` defaults to `GNU=0` and
        `PROFILE=release`, so a bare `deploy --rust` rebuilds a glibc host as static musl,
        the exact substitution DECISIONS D07 measured as 95.6% versus 4.9% of a burst returned
        to the OS, i.e. opposite RSS conclusions, and RSS is Step 12's headline. A refusal
        whose one actionable line quietly changes what is being measured is worse than no line
        at all, so everything the host still says about itself is carried back into it.
        """
        parts = ["tools/lab/lab.py", "--host", self.host, "deploy"]
        flag = BUILD_STAMP_FLAG.get(self.kind, "")
        if flag:
            parts.append(flag)
        glibc = re.match(r"glibc[ ]+([0-9][0-9.]*)", self.libc_evidence)
        if glibc:
            # The version as well as the flag: `--gnu` alone targets deploy.sh's default 2.17,
            # which is a different binary from the one a `--glibc 2.39` host is running.
            parts += ["--gnu", "--glibc", glibc.group(1)]
        # A resolved stamp records the cargo profile too, and `--profile profiling` is a
        # different binary again (different codegen, and `perf` symbols the release one lacks).
        profile = self.fields.get("profile", "")
        if self.kind in ("rust", "lab") and profile and profile != "release":
            parts += ["--profile", profile]
        return " ".join(parts)

    def remedy_caveat(self) -> str:
        """What the remedy cannot know, when the host says nothing about its own libc.

        Only for the unresolved-stamp case: guessing here is how a glibc host would get
        silently rebuilt as musl by following the refusal's own instruction, so the gap is
        stated instead of filled in.
        """
        if self.kind not in ("rust", "lab") or self.libc_evidence:
            return ""
        return ("This host records no libc anywhere, and deploy.sh defaults to static musl: "
                "add --gnu (and --glibc VERSION) if it was deployed against glibc, because "
                "the two are not the same measurement (DECISIONS D07).")

    def as_state(self) -> dict[str, str]:
        """The part of a stamp that belongs in `state.json`, beside the numbers it explains."""
        recorded = {
            "kind": self.kind,
            "host": self.host,
            "binary": self.binary,
            "stamp": self.path,
            "commit": self.commit,
            "revision": self.fields.get("revision", ""),
            "libc": self.libc,
            "target": self.fields.get("target", ""),
            "profile": self.fields.get("profile", ""),
            "deployed": self.fields.get("deployed", ""),
            "sha256": self.sha256,
            "summary": self.summary,
        }
        if self.problem:
            recorded["problem"] = self.problem
        return recorded


def parse_build_stamp(text: str) -> tuple[dict[str, str], str]:
    """Splits a stamp into its ``key=value`` fields and its human summary line."""
    fields: dict[str, str] = {}
    prose: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        key, sep, value = line.partition("=")
        key = key.strip()
        if sep and BUILD_FIELD_RE.match(key):
            fields[key] = value.strip()
        else:
            # A pre-12.0 stamp is one prose line with no `=` in it at all.
            prose.append(" ".join(line.split()))
    summary = fields.get("summary") or "; ".join(prose)
    return fields, summary


def stamp_problem(fields: dict[str, str], summary: str, kind: str) -> str | None:
    """Why this stamp does not identify a build, or `None` if it does."""
    if not fields:
        return (f"{BUILD_STAMPS[kind]} is not a build stamp (no key=value fields); it looks "
                "like a pre-12.0 deployment")
    missing = [name for name in REQUIRED_BUILD_FIELDS if not fields.get(name)]
    if missing:
        return f"{BUILD_STAMPS[kind]} records no {', '.join(missing)}"
    if fields["kind"] != kind:
        return (f"{BUILD_STAMPS[kind]} describes a {fields['kind']!r} deployment, not a "
                f"{kind!r} one")
    if not COMMIT_RE.match(fields["commit"]):
        return (f"{BUILD_STAMPS[kind]} records commit {fields['commit']!r}, which is not a "
                "revision (deploy.sh writes `unknown` outside a checkout)")
    if not summary:
        return f"{BUILD_STAMPS[kind]} has no summary line"
    return None


def artefact_path(impl: str, side: str) -> str:
    """The deployed file one end of a run executes, for any stamped family.

    ``lab`` is the measurement side: ``sampler`` is `kr-labsample`, which every run starts on
    every host, and ``target`` is `kr-pingpong`, which a latency scenario measures against.
    """
    if impl == "lab":
        return f"{LAB}/bin/lab/kr-pingpong" if side == "target" else f"{LAB}/bin/lab/kr-labsample"
    return binary(impl, side)


def read_stamp_fields(runner: Runner, kind: str) -> tuple[dict[str, str], str, str | None, str]:
    """Reads one family's stamp from the host.

    Returns its fields, its summary, what is wrong with it, and, only when there is no stamp
    at all: the pre-12.0 aggregate line that was read to explain why. That last one is not
    provenance and is never recorded as such; it is kept because it is the only surviving
    statement of how the host was deployed, and throwing it away is what made the refusal's
    remedy default a glibc host to musl.
    """
    path = BUILD_STAMPS[kind]
    result = runner.ssh(f'cat {remote_quote(path)} 2>/dev/null || true', check=False)
    if not result.ok:
        # The remote command ends in `|| true`, so a non-zero code is ssh itself failing: the
        # host is down, the key was rejected, the name does not resolve. Before 12.0 the first
        # thing to touch the host was `preflight`, which said so plainly; the provenance gate
        # now runs first and must not answer an unreachable host with "redeploy it": a remedy
        # that would fail in exactly the same way.
        raise LabError(f"{runner.host}: cannot read {path} over ssh: {result.err.strip()}")
    text = result.out
    if not text.strip():
        legacy_text = runner.ssh(f'cat {remote_quote(LEGACY_BUILD_STAMP)} 2>/dev/null || true',
                                 check=False).out
        # Flattened to one line: an aggregate written by 12.0's deploy.sh is `key=value` lines,
        # a pre-12.0 one is a single prose line, and both end up quoted inside a refusal that
        # has to stay readable (and whose `Redeploy it:` line is parsed back by a test).
        legacy = " ".join(legacy_text.split())
        problem = f"no build stamp at {path}"
        if legacy:
            problem += (f"; only the pre-12.0 aggregate {LEGACY_BUILD_STAMP} exists, and it "
                        f"describes whatever was copied last, not this binary: {legacy}")
        return {}, "", problem, legacy
    fields, summary = parse_build_stamp(text)
    return fields, summary, stamp_problem(fields, summary, kind), ""


def verify_binary_hash(runner: Runner, fields: dict[str, str], binary_path: str) -> str | None:
    """Checks the deployed binary against the sha256 its stamp recorded."""
    name = binary_path.rsplit("/", 1)[-1]
    recorded = fields.get(f"sha256.{name}", "")
    if not recorded:
        return f"the stamp records no sha256 for {name}"
    # `sha256sum` was verified present at /usr/bin/sha256sum on lab-x86-1 (2026-09-24, read
    # only); it is not in the set of tools any lab host is assumed to have, so it is not assumed anywhere
    # else: a host without it comes back with no digest and is unprovenanced, not good.
    result = runner.ssh(f'sha256sum {remote_quote(binary_path)} 2>/dev/null || true',
                        check=False)
    if not result.ok:
        # Same reasoning as `read_stamp_fields`: the remote command ends in `|| true`, so a
        # non-zero code is ssh itself failing: the host went away between the stamp read and
        # this one. Answering "could not be hashed" would have `require()` print a redeploy
        # line that would fail in exactly the same way.
        raise LabError(f"{runner.host}: cannot hash {binary_path} over ssh: "
                       f"{result.err.strip()}")
    got = result.out.split()[0] if result.out.split() else ""
    if not got:
        return f"{binary_path} could not be hashed on {runner.host} (missing, or no sha256sum)"
    if got != recorded:
        return (f"{binary_path} is sha256 {got[:12]}… but the stamp beside it records "
                f"{recorded[:12]}…: the binary was replaced without redeploying")
    return None


class BuildProvenance:
    """Resolves (and caches) the artefact each end of a run will actually execute.

    One instance covers a whole session, so the stamp is read once per (host, implementation,
    side) however many runs are interleaved across it.
    """

    def __init__(self, *, allow_unprovenanced: bool = False) -> None:
        self.allow_unprovenanced = allow_unprovenanced
        self._cache: dict[tuple[str, str, str], BuildStamp] = {}
        #: The stamp *file* per (host, family), so the two lab tools cost one read, not two.
        self._files: dict[tuple[str, str],
                          tuple[dict[str, str], str, str | None, str]] = {}
        #: Warned-about artefacts, so a 12-run session does not print the same line 24 times.
        self._warned: set[tuple[str, str, str]] = set()

    def stamp(self, runner: Runner, impl: str, side: str) -> BuildStamp:
        """The artefact `side` will execute on `runner`: its stamp, and what is wrong with it.

        The stamp alone is not enough: 11.3's far host held a `kr-server` from an earlier
        session that a later deployment never replaced, so a stamp one directory up described a
        file that was not the one being executed. The recorded sha256 closes that gap: the
        artefact that runs is the artefact that was stamped, or the run does not start.
        """
        key = (runner.host, impl, side)
        if key in self._cache:
            return self._cache[key]
        binary_path = artefact_path(impl, side)
        if runner.dry_run:
            # A dry run previews command lines without a host; there is nothing to read and
            # nothing to record, and refusing here would make `--dry-run` need a deployment.
            self._cache[key] = BuildStamp(impl, runner.host, BUILD_STAMPS[impl], binary_path,
                                          {}, "(dry run)")
            return self._cache[key]
        file_key = (runner.host, impl)
        if file_key not in self._files:
            self._files[file_key] = read_stamp_fields(runner, impl)
        fields, summary, problem, legacy = self._files[file_key]
        # The hash is per binary even when the stamp is shared: `kr-pingpong` and
        # `kr-labsample` are described by one file and are two different files on disk.
        if problem is None:
            problem = verify_binary_hash(runner, fields, binary_path)
        self._cache[key] = BuildStamp(impl, runner.host, BUILD_STAMPS[impl], binary_path,
                                      fields, summary, problem, legacy_summary=legacy)
        return self._cache[key]

    def require(self, runner: Runner, impl: str, side: str) -> BuildStamp:
        """The stamp, or a refusal. `--allow-unprovenanced` downgrades it to a loud warning."""
        stamp = self.stamp(runner, impl, side)
        if stamp.ok:
            return stamp
        message = (f"{runner.host}: the {impl} {side} artefact is unprovenanced, "
                   f"{stamp.problem}")
        if not self.allow_unprovenanced:
            # The caveat is its own line and never appended to the remedy: that line is meant
            # to be pasted (a test parses it back through `build_parser`) so prose after the
            # command would arrive as arguments.
            caveat = stamp.remedy_caveat()
            raise LabError(
                f"{message}.\n"
                f"  Redeploy it: {stamp.remedy()}\n"
                + (f"  {caveat}\n" if caveat else "")
                + "  A run that cannot name its binary cannot be quoted (11.3 recorded 27 "
                "such runs); pass --allow-unprovenanced to run anyway and have every report "
                "say so."
            )
        if (runner.host, impl, side) not in self._warned:
            self._warned.add((runner.host, impl, side))
            print(f"lab: WARNING, {message}; this session's report will be marked "
                  "UNPROVENANCED", file=sys.stderr)
        return stamp


def unprovenanced_notes(states: Sequence[dict[str, Any]]) -> list[str]:
    """One line per run that could not name an artefact, for the top of a report."""
    notes: list[str] = []
    for state in states:
        runid = state.get("runid", "?")
        details = {key: state.get(key) for key in BUILD_DETAIL_KEYS}
        if not any(details.values()):
            # A state from before 12.0: the 11.3 campaign's 27 runs are exactly this. A report
            # regenerated from one must not look like a clean measurement either.
            notes.append(f"`{runid}`: no artefact identity was recorded at all (the run "
                         "predates the 12.0 build stamp)")
            continue
        for key, detail in details.items():
            problem = (detail or {}).get("problem")
            if problem:
                side = key[: -len("_build_detail")]
                label = ARTEFACT_LABELS.get(side, side)
                notes.append(f"`{runid}` {label} on `{(detail or {}).get('host', '?')}`: "
                             f"{problem}")
    return notes


def unprovenanced_banner(states: Sequence[dict[str, Any]]) -> list[str]:
    """The warning block a report leads with, or `[]` when every artefact was identified.

    Every document a number can be quoted out of carries this: the session report, and the
    per-pair comparison table that `lab.py compare` writes, which is what a WAN rung is
    actually read from, and what carried 11.3's unattributable 0.75x.
    """
    notes = unprovenanced_notes(states)
    if not notes:
        return []
    lines = ["> ⚠ **UNPROVENANCED: do not quote these numbers as a measurement of a "
             "particular revision.** At least one end of the runs below could not be "
             "identified from what the host recorded:", ">"]
    lines += [f"> - {note}" for note in notes]
    lines.append("")
    return lines


def require_build(runner: Runner) -> str:
    """`deployed_build`, refusing to start a run on a host that cannot say what it holds."""
    build = deployed_build(runner)
    if not build:
        if runner.dry_run:
            # A dry run issues no ssh at all, so every read comes back empty; refusing here
            # would make `--dry-run` unusable for previewing a campaign.
            return "(dry run)"
        raise LabError(
            f"{runner.host}: no readable $HOME/kcptun-lab/bin/BUILD.txt, so the binaries this "
            f"run would measure cannot be attributed to a revision or a libc: deploy first: "
            f"tools/lab/lab.py --host {runner.host} deploy --gnu"
        )
    return build


def ensure_netns(runner: Runner, profile: str) -> None:
    """Brings the namespace lab up, or switches its netem profile if it is already up."""
    status = runner.lab("netns", "status", check=False).out
    if NS_CLIENT in status and NS_SERVER in status:
        runner.lab("netns", "set", profile)
    else:
        runner.lab("netns", "up", profile)


def start_run(runner: Runner, plan: RunPlan, server: Runner | None = None,
              provenance: BuildProvenance | None = None) -> dict[str, Any]:
    """Starts a run's processes and returns the state a later ``collect`` needs.

    `server` is the second host of a WAN run; it defaults to `runner`, which is the single-host
    netns arrangement 11.1 built. The two differ in exactly three ways: where the server end is
    started, whether anything is namespaced, and that a WAN run samples ``/proc`` on both
    machines because neither can see the other's.
    """
    scenario = plan.scenario
    server = server or runner
    wan = scenario.is_wan
    ns_client = None if wan else NS_CLIENT
    ns_server = None if wan else NS_SERVER
    # Resolved before anything starts, so the recorded artefact is the one this run is about to
    # use, and so that an unprovenanced end refuses the run instead of producing numbers
    # nobody can attribute afterwards (11.3).
    provenance = provenance or BuildProvenance()
    client_stamp = provenance.require(runner, plan.client_impl, "client")
    server_stamp = provenance.require(server, plan.server_impl, "server")
    # The instruments too: `kr-labsample` takes every RSS and CPU sample on both machines, and
    # a percentile from an unidentified `kr-pingpong` is no more quotable than one from an
    # unidentified tunnel.
    tools_stamp = provenance.require(runner, "lab", "sampler")
    server_tools_stamp = provenance.require(server, "lab", "sampler") if wan else tools_stamp
    target_stamp: BuildStamp | None = None
    server_target_stamp: BuildStamp | None = None
    if scenario.target == "pingpong":
        # Both ends of the latency measurement: the echo target on the server host, and the
        # `kr-pingpong` the client host runs as the workload: the one that actually emits
        # every percentile. In a netns run they are the same host; in a WAN run the client's
        # copy is a separate file that nothing else hashes, which is precisely the
        # stale-binary-beside-a-fresh-stamp case the sha256 exists to catch. An `iperf3` target
        # is the host's own package and carries no stamp of ours.
        #
        # Both stamps are *kept*, not just demanded. `--allow-unprovenanced` turns a refusal
        # into a marker carried by the state, and a marker thrown away here is a report that
        # promises an UNPROVENANCED banner and then prints a clean one, which is 11.3 again,
        # inside 11.3's own fix, for the instrument that emits every latency percentile.
        target_stamp = provenance.require(runner, "lab", "target")
        server_target_stamp = provenance.require(server, "lab", "target") if wan else target_stamp
    # What the kernel will actually give `-sockbuf` (see `socket_buffer_limits`).
    socket_limits = {runner.host: runner.socket_buffer_limits()}
    if wan:
        socket_limits[server.host] = server.socket_buffer_limits()
    # `uptime` on both ends, before and after: step 11.3 asks for it by name, because every
    # lab host has 1-2 vCPUs and some of them carry live production tunnels.
    uptime_before = {runner.host: runner.uptime()}
    if wan:
        uptime_before[server.host] = server.uptime()
    # Creates logs/<runid>/ (the -snmplog files and every CSV are written straight into it).
    runner.lab("collect", plan.runid)
    if wan:
        server.lab("collect", plan.runid)

    server.start(plan.target_name, plan.target_argv(), netns=ns_server)
    server.start(plan.server_name, plan.server_argv(), netns=ns_server)
    runner.start(plan.client_name, plan.client_argv(), netns=ns_client)

    if wan:
        client_pids = runner.pids([plan.client_name])
        server_pids = server.pids([plan.server_name, plan.target_name])
        pids = {**client_pids, **server_pids}
        runner.start(plan.sampler_name, plan.sampler_argv(client_pids))
        server.start(plan.server_sampler_name, plan.sampler_argv(server_pids))
    else:
        pids = runner.pids([plan.client_name, plan.server_name, plan.target_name])
        runner.start(plan.sampler_name, plan.sampler_argv(pids))

    if scenario.settle > 0 and not runner.dry_run:
        time.sleep(scenario.settle)

    started_at = time.time()
    for name, workload in zip(plan.workload_names, scenario.workloads):
        if workload.start_after > 0 and not runner.dry_run:
            delay = started_at + workload.start_after - time.time()
            if delay > 0:
                time.sleep(delay)
        runner.start(name, plan.workload_argv(workload), netns=ns_client)

    return {
        "runid": plan.runid,
        "scenario": scenario.name,
        "source": scenario.source,
        "config": scenario.config,
        "mode": scenario.mode,
        "netem": scenario.netem if not wan else "none (real path)",
        "client_impl": plan.client_impl,
        "server_impl": plan.server_impl,
        "repetition": plan.repetition,
        "target": scenario.target,
        "host": runner.host,
        "server_host": server.host,
        "server_addr": plan.server_dial_addr,
        # `build`/`server_build` stay the one-line summaries every existing report and
        # `docs/lab-results/` page quotes; the `_detail` dictionaries beside them carry the
        # commit, the libc and the sha256 of the exact file that ran on each side.
        "build": client_stamp.summary,
        "server_build": server_stamp.summary,
        "client_build_detail": client_stamp.as_state(),
        "server_build_detail": server_stamp.as_state(),
        "tools_build_detail": tools_stamp.as_state(),
        # Only for a `pingpong` target, and only a second entry when the two ends are two
        # machines: a netns run's echo target and workload are the same file on the same host,
        # and recording it twice would have the banner name it twice for one problem.
        **({"target_build_detail": target_stamp.as_state()} if target_stamp else {}),
        **({"server_tools_build_detail": server_tools_stamp.as_state()} if wan else {}),
        **({"server_target_build_detail": server_target_stamp.as_state()}
           if wan and server_target_stamp else {}),
        "socket_buffer_limits": socket_limits,
        "uptime_before": uptime_before,
        "started_unix": int(started_at),
        "started_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started_at)),
        "total_duration": scenario.total_duration,
        "names": plan.names,
        "client_host_names": plan.client_host_names,
        "server_host_names": plan.server_host_names,
        "pids": pids,
        "workloads": [
            {"name": name, "tag": w.tag, "type": w.type, "duration": w.duration,
             "start_after": w.start_after, "argv": plan.workload_argv(w)}
            for name, w in zip(plan.workload_names, scenario.workloads)
        ],
        "client_argv": plan.client_argv(),
        "server_argv": plan.server_argv(),
        "target_argv": plan.target_argv(),
        "remote_dir": plan.remote_dir,
    }


def wait_for_workloads(runner: Runner, state: dict[str, Any], *, slack: int = 120) -> bool:
    """Blocks on the host until every workload has finished. False on a timeout."""
    names = [w["name"] for w in state["workloads"]]
    if not names:
        return True
    timeout = state["total_duration"] + slack
    result = runner.lab("wait", "--timeout", str(timeout), *names,
                        check=False, timeout=timeout + 120)
    if result.code == 0:
        return True
    print(f"lab: {result.out.strip() or result.err.strip()}", file=sys.stderr)
    return False


def state_is_wan(state: dict[str, Any]) -> bool:
    """Whether a recorded run was a two-host one. Older states have no ``mode`` at all."""
    return state.get("mode") == MODE_WAN


def server_runner(runner: Runner, state: dict[str, Any]) -> Runner:
    """The runner for a recorded run's server host (the same one, unless it was a WAN run)."""
    if not state_is_wan(state):
        return runner
    return runner.peer(str(state.get("server_host") or runner.host))


def check_client_host(runner: Runner, state: dict[str, Any]) -> None:
    """Refuse to act on a recorded run from the wrong client host.

    ``--host`` defaults to ``lab-arm64``, and only the *server* host is recovered from the state
    (``server_runner``), so ``collect``/``status`` on a detached WAN run started elsewhere would
    silently address the default host: ``stop`` finds no pid files, ``collect`` fails on a
    missing log directory, and the real ``<runid>-cli``: nohup'd by ``lab-start.sh`` with no
    timeout: is left running for ever. ``start_run`` records ``host``, so the mismatch is free
    to detect; a state written before it did has no ``host`` key and is let through.
    """
    recorded = state.get("host")
    if recorded and recorded != runner.host:
        raise LabError(
            f"run {state.get('runid', '?')} was started on {recorded!r}, not {runner.host!r}; "
            f"pass --host {recorded}"
        )


def host_names(state: dict[str, Any], side: str) -> list[str]:
    """The processes a recorded run put on one host.

    A state written before 11.3 has only ``names``, and everything was on one host; falling back
    to it is what keeps ``collect`` working on a run an older checkout started.
    """
    if side == "server" and not state_is_wan(state):
        return []
    key = "client_host_names" if side == "client" else "server_host_names"
    recorded = state.get(key)
    if recorded is None:
        return list(state["names"]) if side == "client" else []
    return list(recorded)


def finish_run(runner: Runner, state: dict[str, Any], local_dir: Path,
               *, max_log_bytes: int) -> None:
    """SIGUSR1 both tunnel ends, stop everything, collect and download.

    On a WAN run each half happens on its own machine, and the server's artefacts land in
    ``<run>/server/`` so that two ``proc.csv`` files (one per machine) can coexist.
    """
    server = server_runner(runner, state)
    wan = state_is_wan(state)
    client_side = host_names(state, "client")
    server_side = host_names(state, "server")

    # step 11.1: "both sides' SNMP (SIGUSR1 dump at the end)". The dump lands in the
    # process log; the periodic -snmplog CSV is the time series next to it.
    if wan:
        runner.lab("signal", "USR1", state["runid"] + "-cli", check=False)
        server.lab("signal", "USR1", state["runid"] + "-srv", check=False)
    else:
        runner.lab("signal", "USR1", state["runid"] + "-cli", state["runid"] + "-srv",
                   check=False)
    if SNMP_SETTLE_SECONDS and not runner.dry_run:
        time.sleep(SNMP_SETTLE_SECONDS)

    # `uptime` after the run, on every host that took part (step 11.3). Read before the
    # processes are stopped, so the load average still reflects what the run did.
    after = {runner.host: runner.uptime()}
    if wan:
        after[server.host] = server.uptime()
    state["uptime_after"] = after

    # Stop **both** ends before anything is collected or downloaded. `collect` raises on a
    # failure and `fetch_dir` raises on any tar/ssh error, and the tar download is a long
    # unguarded window for Ctrl-C; with the server stopped last, either of those left
    # `<runid>-srv` and `<runid>-tgt` up on the other machine. `lab-start.sh` uses a bare
    # `nohup` with no timeout, so a kcptun server left that way runs for ever, only the sampler
    # and `kr-pingpong` self-terminate on `--duration`. `cmd_run` has a `finally` that stops
    # everything, but `cmd_collect` (the path a detached WAN run *must* use) has none, which
    # is exactly the case step 11.1 ("cleanup on exit or Ctrl-C") is about.
    runner.stop(client_side)
    if server_side:
        server.stop(server_side)
    runner.lab("collect", state["runid"], "--max-bytes", str(max_log_bytes), *client_side)
    runner.fetch_dir(state["remote_dir"], local_dir)
    if server_side:
        server.lab("collect", state["runid"], "--max-bytes", str(max_log_bytes), *server_side)
        server.fetch_dir(state["remote_dir"], local_dir / SERVER_SUBDIR)
    if not runner.dry_run and (local_dir / "state.json").exists():
        # Re-write it: `uptime_after` is only known now, and `collect` must leave a state file
        # that describes the finished run rather than the one that was started.
        (local_dir / "state.json").write_text(json.dumps(state, indent=2) + "\n")


# --------------------------------------------------------------------------------------------
# Reading results
# --------------------------------------------------------------------------------------------


def run_files(directory: Path, name: str) -> list[Path]:
    """Every copy of `name` a run produced: the client host's, then the server host's.

    A netns run has one of each file. A WAN run has the client half in `directory` and the
    server half in ``directory/server``, and both machines name their sampler output
    ``proc.csv``, so the reader has to look in both places rather than assume one.
    """
    return [path for path in (directory / name, directory / SERVER_SUBDIR / name)
            if path.exists()]


def run_file(directory: Path, name: str) -> Path:
    """The one copy of `name` to read, preferring the client host's."""
    found = run_files(directory, name)
    return found[0] if found else directory / name


def read_csv(path: Path) -> tuple[list[str], list[list[str]]]:
    """Reads one of the run's CSV files (all of them share the same dialect)."""
    if not path.exists():
        return [], []
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        rows = list(csv.reader(handle))
    if not rows:
        return [], []
    return rows[0], rows[1:]


def result_lines(path: Path) -> list[dict[str, Any]]:
    """Every ``RESULT {json}`` line a workload log holds."""
    if not path.exists():
        return []
    found: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("RESULT "):
            try:
                found.append(json.loads(line[len("RESULT "):]))
            except json.JSONDecodeError:
                continue
    return found


def iperf3_summary(path: Path) -> dict[str, Any] | None:
    """The numbers a report quotes out of an iperf3 ``-J`` file."""
    if not path.exists():
        return None
    try:
        report = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    end = report.get("end", {})
    sent = end.get("sum_sent", {})
    received = end.get("sum_received", {})
    if not sent and not received:
        return None
    return {
        "seconds": sent.get("seconds") or received.get("seconds"),
        "sent_mbit_s": (sent.get("bits_per_second") or 0) / 1e6,
        "received_mbit_s": (received.get("bits_per_second") or 0) / 1e6,
        "retransmits": sent.get("retransmits"),
        "bytes": received.get("bytes") or sent.get("bytes"),
        "reverse": bool(report.get("start", {}).get("test_start", {}).get("reverse")),
        "error": report.get("error"),
    }


#: Where warm-up ends, for the leak slopes below. A tunnel that has just started is still filling
#: its smux windows, its KCP buffers and its allocator's arenas, and it climbs steeply and
#: legitimately while it does; step 11.4's acceptance is a flat slope **after warm-up**, so
#: including that climb would report a leak on every healthy run. The cutoff is the later of ten
#: minutes and a tenth of the run, a tenth for a six-hour soak (36 min), the ten-minute floor
#: for a short one.
WARMUP_SECONDS = 600.0
WARMUP_FRACTION = 0.1
#: Below this many post-warm-up samples a slope is noise dressed as a number, so it is not
#: reported at all rather than reported badly.
MIN_SLOPE_SAMPLES = 6


def least_squares_slope(points: Sequence[tuple[float, float]]) -> float | None:
    """The gradient of the least-squares line through `points`, or None if there is not one.

    Endpoints alone cannot tell a leak from a single step: a process that jumps 4 MB at minute
    three and is flat for the next five hours has the same first→last difference as one that
    climbs steadily. The gradient over every sample is what distinguishes them.
    """
    count = len(points)
    if count < 2:
        return None
    mean_x = sum(x for x, _ in points) / count
    mean_y = sum(y for _, y in points) / count
    sxx = sum((x - mean_x) ** 2 for x, _ in points)
    if sxx == 0:
        return None
    sxy = sum((x - mean_x) * (y - mean_y) for x, y in points)
    return sxy / sxx


def warmup_cutoff(observed_span_s: float, total_duration: float | None) -> float:
    """Where warm-up ends, for a run of `total_duration` seconds seen for `observed_span_s`.

    The window is a property of the run that was **asked for**, not of the samples that happen to
    have arrived. Deriving it from the samples alone is how a six-hour soak collected after twenty
    minutes gets a ten-minute cutoff, six post-warm-up samples, and a gradient fitted entirely to
    its own warm-up: printed under a line calling it the acceptance criterion. `total_duration`
    is the intended length; only when it is unknown (0 or None) does the observed span stand in.
    """
    return max(WARMUP_SECONDS, WARMUP_FRACTION * (total_duration or observed_span_s))


def leak_slopes(series: Sequence[tuple[float, float, float | None]],
                total_duration: float | None = None) -> dict[str, Any]:
    """RSS and fd gradients per hour, over the samples that follow warm-up.

    `series` is ``(elapsed_s, rss_kb, fds_or_None)`` in sample order. `total_duration` is the
    run's intended length in seconds; see `warmup_cutoff` for why it is not inferred.
    """
    empty: dict[str, Any] = {
        "rss_slope_kb_h": None, "fd_slope_h": None,
        "slope_samples": 0, "slope_from_s": None, "slope_span_s": None,
    }
    if not series:
        return empty
    last = max(point[0] for point in series)
    empty["slope_span_s"] = last
    cutoff = warmup_cutoff(last, total_duration)
    # A run collected before its warm-up ended has no samples at all past the cutoff, so this one
    # test covers both it and the short run whose plateau is simply too thinly sampled.
    after = [point for point in series if point[0] >= cutoff]
    if len(after) < MIN_SLOPE_SAMPLES:
        # A short run (the smoke scenario, or a soak collected early) never leaves the warm-up
        # window. Saying so is more useful than a gradient fitted to three points.
        return empty
    rss = least_squares_slope([(point[0], point[1]) for point in after])
    fds = [(point[0], point[2]) for point in after if point[2] is not None]
    fd_slope = least_squares_slope(fds) if len(fds) >= MIN_SLOPE_SAMPLES else None
    return {
        "rss_slope_kb_h": None if rss is None else rss * 3600.0,
        "fd_slope_h": None if fd_slope is None else fd_slope * 3600.0,
        "slope_samples": len(after),
        "slope_from_s": cutoff,
        "slope_span_s": last,
    }


def format_slope(value: float | None) -> str:
    """A slope for the report table. `None` is "-", not 0: they mean different things."""
    if value is None:
        return "-"
    return f"{value:+.1f}"


def process_metrics(path: Path,
                    total_duration: float | None = None) -> dict[str, dict[str, Any]]:
    """Per-process CPU and memory, from the first and last sample of ``proc.csv``.

    Also the **leak slopes**: the gradient of RSS and of the descriptor count over every sample
    after warm-up, which is what step 11.4 actually accepts a soak on. `total_duration` is
    the run's intended length, which is what sizes the warm-up window (`warmup_cutoff`).
    """
    header, rows = read_csv(path)
    if not rows:
        return {}
    index = {name: i for i, name in enumerate(header)}

    def cell(row: list[str], name: str) -> str:
        position = index.get(name, -1)
        return row[position] if 0 <= position < len(row) else ""

    def number(row: list[str], name: str) -> float:
        try:
            return float(cell(row, name))
        except ValueError:
            return 0.0

    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        label = cell(row, "label")
        entry = out.setdefault(label, {
            "samples": 0, "rss_kb_first": None, "rss_kb_last": 0.0, "rss_kb_max": 0.0,
            "hwm_kb": 0.0, "fds_first": None, "fds_last": 0.0, "fds_max": 0.0,
            "cpu_ticks_first": None, "cpu_ticks_last": 0.0, "threads_last": 0.0,
            "cpu_pct_max": 0.0, "log_truncations": 0.0, "states": set(),
            "series": [],
        })
        entry["samples"] += 1
        state = cell(row, "state")
        entry["states"].add(state)
        # `X` is labsample's post-mortem row: the process is gone, so rss/fds/cpu are zeros
        # written only to timestamp the exit (labsample.rs `read_process` returning None). Folding
        # those into the first/last values would report "RSS 5480→0" and a negative cpu_seconds
        # for every run whose sampler ticks inside the shutdown window. The state is kept so the
        # report still shows that the process went away.
        if state == "X":
            continue
        rss = number(row, "rss_kb")
        cpu = number(row, "cpu_ticks")
        if entry["rss_kb_first"] is None:
            entry["rss_kb_first"] = rss
            entry["cpu_ticks_first"] = cpu
        entry["rss_kb_last"] = rss
        entry["rss_kb_max"] = max(entry["rss_kb_max"], rss)
        entry["hwm_kb"] = max(entry["hwm_kb"], number(row, "hwm_kb"))
        # An empty `fds` cell is labsample's "I could not count" (`count_fds` returning None: the
        # process exited between the two /proc reads, or the sampler itself hit EMFILE). Reading
        # it as 0 would print "fds 14→0 (−14)" on a row whose state is still `S`, and fd growth
        # is half of the 11.4 acceptance criterion. Skip the fd fields; rss/cpu on the same row
        # are still valid.
        raw_fds = cell(row, "fds")
        fds_or_none: float | None = None
        if raw_fds:
            fds = number(row, "fds")
            fds_or_none = fds
            if entry["fds_first"] is None:
                entry["fds_first"] = fds
            entry["fds_last"] = fds
            entry["fds_max"] = max(entry["fds_max"], fds)
        entry["series"].append((number(row, "elapsed_s"), rss, fds_or_none))
        entry["cpu_ticks_last"] = cpu
        entry["threads_last"] = number(row, "threads")
        entry["cpu_pct_max"] = max(entry["cpu_pct_max"], number(row, "cpu_pct"))
        entry["log_truncations"] = max(entry["log_truncations"], number(row, "log_truncations"))
    for entry in out.values():
        if entry["rss_kb_first"] is None:
            # Every row for this label was a post-mortem one: the process was already gone when
            # sampling started. There is nothing to report, but the report must still render,
            # the `states` column ("X") is what tells the reader what happened.
            entry["rss_kb_first"] = 0.0
            entry["cpu_ticks_first"] = 0.0
        if entry["fds_first"] is None:
            # No row ever carried an fd count (macOS, or /proc/<pid>/fd unreadable throughout).
            # `fds_last` is still its 0.0 default, so the growth below comes out as 0 rather than
            # as a drop invented out of a blank column.
            entry["fds_first"] = 0.0
        entry["cpu_seconds"] = (
            (entry["cpu_ticks_last"] - (entry["cpu_ticks_first"] or 0)) / float(CLOCK_TICKS))
        entry["rss_growth_kb"] = entry["rss_kb_last"] - (entry["rss_kb_first"] or 0)
        entry["fd_growth"] = entry["fds_last"] - (entry["fds_first"] or 0)
        entry.update(leak_slopes(entry.pop("series"), total_duration))
        entry["states"] = "".join(sorted(entry["states"]))
    return out


def collected_process_metrics(directory: Path,
                              total_duration: float | None = None) -> dict[str, dict[str, Any]]:
    """`process_metrics` over every ``proc.csv`` the run collected, merged into one table.

    A WAN run has two, one per machine, with disjoint labels (``cli`` on the client host,
    ``srv``/``tgt`` on the server's). A collision would mean the same process was sampled twice,
    which is worth showing rather than hiding, so the second copy is kept under ``<label>+``.
    """
    merged: dict[str, dict[str, Any]] = {}
    for path in run_files(directory, "proc.csv"):
        for label, entry in process_metrics(path, total_duration).items():
            while label in merged:
                label += "+"
            merged[label] = entry
    return merged


def snmp_totals(path: Path) -> dict[str, int]:
    """The last ``-snmplog`` record's counters (the run's totals) plus the peak CurrEstab.

    See ``SNMP_COLUMNS`` above for why this is an absolute value and not a delta.
    """
    header, rows = read_csv(path)
    if not rows:
        return {}
    index = {name: i for i, name in enumerate(header)}

    def value(row: list[str], name: str) -> int:
        position = index.get(name, -1)
        if not 0 <= position < len(row):
            return 0
        try:
            return int(row[position])
        except ValueError:
            return 0

    last = rows[-1]
    out = {name: value(last, name) for name in SNMP_COLUMNS if name in index}
    if "CurrEstab" in index:
        out["CurrEstabMax"] = max(value(row, "CurrEstab") for row in rows)
    out["_records"] = len(rows)
    return out


def scan_logs(directory: Path) -> list[str]:
    """Lines in the collected logs that look like something went wrong.

    Both halves of a WAN run are scanned: the server's log is on the server host, and a stack
    trace there matters at least as much as one on the client.
    """
    notes: list[str] = []
    for path in sorted(directory.glob("*.log")) + sorted(
            (directory / SERVER_SUBDIR).glob("*.log")):
        for number, line in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
        ):
            lowered = line.lower()
            if any(marker in lowered for marker in BENIGN_MARKERS):
                continue
            if any(marker in lowered for marker in ERROR_MARKERS):
                notes.append(f"{path.name}:{number}: {line.strip()[:200]}")
                if len(notes) >= 40:
                    notes.append("… (more suppressed)")
                    return notes
    return notes


# --------------------------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------------------------


def socket_buffer_ceilings_line(states: Sequence[dict[str, Any]]) -> str:
    """The session's kernel socket-buffer ceilings as one sentence, ``""`` when none recorded.

    D32 makes these a validity precondition, not a decoration: `setsockopt(SO_RCVBUF)` is
    clamped to `net.core.rmem_max` without a word from the kernel, so an S1 run (`-sockbuf
    8388608`) on a host with a stock 212992 ceiling measures the ceiling and must be discarded.
    Every report that prints a number therefore prints the ceilings beside it, so the
    precondition is checkable from the page rather than only from a `state.json` under the
    gitignored `lab-runs/`.
    """
    limits = sorted({
        f"{host} rmem_max {(values or {}).get('rmem_max', '?')}, "
        f"wmem_max {(values or {}).get('wmem_max', '?')}"
        for state in states
        for host, values in (state.get("socket_buffer_limits") or {}).items()
    })
    if not limits:
        return ""
    # States written before D32 have no ceilings at all; a mixed session says how many it has
    # rather than implying the recorded ones cover every run.
    recorded = sum(1 for state in states if state.get("socket_buffer_limits"))
    return ("Kernel socket-buffer ceilings (`-sockbuf` is silently clamped to them): "
            + "; ".join(f"`{line}`" for line in limits)
            + (f", recorded for {recorded} of {len(states)} runs."
               if recorded < len(states) else "."))


def markdown_report(states: list[dict[str, Any]], directories: list[Path]) -> str:
    """One Markdown document for a session: a summary table plus a section per run."""
    lines: list[str] = []
    first = states[0]
    lines.append(f"# Lab results: {first['scenario']}")
    lines.append("")
    if state_is_wan(first):
        lines.append(f"**Real path**: client host `{first['host']}` → server host "
                     f"`{first['server_host']}` (`{first['server_addr']}`), no netem anywhere, "
                     f"config `{first['config'].upper()}`. Generated by `tools/lab/lab.py`.")
        lines.append("")
        # The single most important caveat on any WAN number, and the one most easily lost
        # between a terminal and a commit message.
        lines.append("A real Internet path is not reproducible between sessions: its capacity, "
                     "queueing and cross traffic belong to somebody else, so **only the "
                     "Go-versus-Rust comparisons inside this session mean anything**. The runs "
                     "are interleaved (GG, RR, GR, RG) precisely so that whatever the path did "
                     "during the session happened to both implementations.")
    else:
        lines.append(f"Host `{first['host']}`, netem `{first['netem']}`, config "
                     f"`{first['config'].upper()}`, generated by `tools/lab/lab.py`.")
    ceilings = socket_buffer_ceilings_line(states)
    if ceilings:
        lines.append("")
        lines.append(ceilings)
    lines.append("")

    # A run only reaches a report unprovenanced when somebody passed --allow-unprovenanced, or
    # when the state predates 12.0. Either way the document says so at the top, in the place a
    # reader looks before quoting a number, rather than leaving an empty field further down.
    lines.extend(unprovenanced_banner(states))
    lines.append("| run | client | server | rep | workload | result |")
    lines.append("|---|---|---|---|---|---|")
    for state, directory in zip(states, directories):
        for row in summary_rows(state, directory):
            lines.append("| " + " | ".join(row) + " |")
    lines.append("")

    if len(states) > 1:
        # The comparison is the point of a multi-run session: a dozen run sections are the
        # evidence for it, not a substitute. It goes above them so the file can be read.
        lines.append("## Comparison")
        lines.append("")
        lines.append(compare_report(states, directories))

    for state, directory in zip(states, directories):
        lines.extend(run_section(state, directory))
    return "\n".join(lines) + "\n"


def summary_rows(state: dict[str, Any], directory: Path) -> list[list[str]]:
    rows: list[list[str]] = []
    for workload in state["workloads"]:
        result = describe_workload(state, workload, directory)
        rows.append([
            state["runid"], state["client_impl"], state["server_impl"],
            str(state["repetition"]), f"{workload['type']}/{workload['tag']}", result,
        ])
    return rows


def describe_workload(state: dict[str, Any], workload: dict[str, Any], directory: Path) -> str:
    """A one-line result for a workload, whichever kind it is."""
    if workload["type"] == "iperf3":
        summary = iperf3_summary(directory / f"iperf3-{workload['tag']}.json")
        if not summary:
            return "no iperf3 report"
        if summary.get("error"):
            return f"error: {summary['error']}"
        direction = "down" if summary["reverse"] else "up"
        return (f"{summary['received_mbit_s']:.1f} Mbit/s {direction}"
                + (f", {summary['retransmits']} retransmits"
                   if summary.get("retransmits") is not None else ""))
    results = result_lines(directory / f"{workload['name']}.log")
    if not results:
        return "no RESULT line"
    result = results[-1]
    if workload["type"] == "ping":
        return (f"p50 {result.get('rtt_p50_us', 0) / 1000:.2f} ms, "
                f"p90 {result.get('rtt_p90_us', 0) / 1000:.2f} ms, "
                f"p99 {result.get('rtt_p99_us', 0) / 1000:.2f} ms, "
                f"max {result.get('rtt_max_us', 0) / 1000:.2f} ms "
                f"({result.get('requests', 0)} requests, {result.get('errors', 0)} errors)")
    if workload["type"] == "bulk":
        return (f"{result.get('mbit_s', 0):.1f} Mbit/s, {result.get('transfers', 0)} transfers, "
                f"{result.get('errors', 0)} errors")
    return (f"{result.get('completed', 0)}/{result.get('opened', 0)} streams, "
            f"{result.get('mbit_s', 0):.1f} Mbit/s, {result.get('errors', 0)} errors, "
            f"{result.get('timeouts', 0)} timeouts, "
            f"{result.get('long_lived_ok', 0)} long-lived exchanges")


def workload_metrics(workload: dict[str, Any],
                     directory: Path) -> dict[str, float]:
    """The numbers of one workload, as ``metric -> value``, for the comparison table."""
    if workload["type"] == "iperf3":
        summary = iperf3_summary(directory / f"iperf3-{workload['tag']}.json")
        if not summary or summary.get("error"):
            return {}
        out = {"Mbit/s": summary["received_mbit_s"]}
        if summary.get("retransmits") is not None:
            out["TCP retrans"] = float(summary["retransmits"])
        return out
    results = result_lines(directory / f"{workload['name']}.log")
    if not results:
        return {}
    result = results[-1]
    if workload["type"] == "ping":
        return {
            "p50 ms": result.get("rtt_p50_us", 0) / 1000.0,
            "p90 ms": result.get("rtt_p90_us", 0) / 1000.0,
            "p99 ms": result.get("rtt_p99_us", 0) / 1000.0,
            "max ms": result.get("rtt_max_us", 0) / 1000.0,
            "errors": float(result.get("errors", 0)),
        }
    if workload["type"] == "bulk":
        return {"Mbit/s": result.get("mbit_s", 0.0), "errors": float(result.get("errors", 0))}
    return {
        "streams": float(result.get("completed", 0)),
        "Mbit/s": result.get("mbit_s", 0.0),
        "errors": float(result.get("errors", 0)),
    }


#: The SNMP counters a comparison quotes. On a WAN path these are the whole point: goodput alone
#: cannot say whether a rung was slow because the path lost packets or because the implementation
#: retransmitted needlessly, and on the jittery rung (tools/lab/README.md, mdev 6.6 ms) the retransmit
#: and FEC counters are what RTO estimation and the FEC/ARQ interaction actually show up in.
#: All three components of `RetransSegs` are here, kcp-go adds `LostSegs + FastRetransSegs +
#: EarlyRetransSegs` into it (reference/kcptun/vendor/github.com/xtaci/kcp-go/v5/kcp.go, the
#: "counter updates" block of `flush`), so the total decomposes exactly. Quoting two of the
#: three leaves a remainder that reads as unattributable retransmission, which is the one thing
#: these rows exist to attribute.
COMPARE_SNMP = ("RetransSegs", "FastRetransSegs", "EarlyRetransSegs", "LostSegs",
                "RepeatSegs", "FECRecovered", "FECErrs", "InErrs", "KCPInErrors")


def pair_code(state: dict[str, Any]) -> str:
    """``GG``, ``RR``, ``GR`` or ``RG``: client implementation first, as the run id spells it."""
    return (IMPLS[state["client_impl"]] + IMPLS[state["server_impl"]]).upper()


def median(values: Sequence[float]) -> float | None:
    """The median, or None for an empty sequence (the caller prints `-`, never 0)."""
    ordered = sorted(values)
    count = len(ordered)
    if count == 0:
        return None
    middle = count // 2
    if count % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def format_number(value: float | None) -> str:
    """A table cell. `None` is "-" (not measured), never `0` (measured as nothing)."""
    if value is None:
        return "-"
    # SNMP counters and stream counts are whole numbers and read as noise with a decimal point
    # on them; a rate or a percentile is not. Deciding by the value rather than by the column
    # keeps a median of an odd number of integers (which is one of them) looking like a count.
    if float(value).is_integer() and abs(value) < 1e15:
        return f"{int(value):,}"
    if abs(value) >= 100:
        return f"{value:,.0f}"
    if abs(value) >= 10:
        return f"{value:.1f}"
    return f"{value:.2f}"


def compare_artefacts(states: Sequence[dict[str, Any]]) -> list[str]:
    """One line naming every distinct artefact a comparison's numbers came from.

    The unprovenanced banner is only half of 12.0: `compare` is the table a rung is actually
    quoted from, so the case where everything *did* resolve has to say what produced the
    numbers, not stay silent and leave the reader to assume. Identities collapse to one entry
    per (family, commit, libc, target): a session's client, server and instruments are
    normally one build, and then this is one short line.
    """
    hosts: dict[tuple[str, str, str, str], set[str]] = {}
    order: list[tuple[str, str, str, str]] = []
    for state in states:
        for key in BUILD_DETAIL_KEYS:
            detail = state.get(key) or {}
            # A detail with a `problem` is named by the banner instead, with its reason.
            if detail.get("problem") or not detail.get("commit"):
                continue
            ident = (detail.get("kind", "?"), detail["commit"],
                     detail.get("libc", ""), detail.get("target", ""))
            if ident not in hosts:
                hosts[ident] = set()
                order.append(ident)
            hosts[ident].add(detail.get("host", "?"))
    if not order:
        return []
    described = []
    for ident in order:
        kind, commit, libc, target = ident
        where = ", ".join(f"`{host}`" for host in sorted(hosts[ident]))
        about = ", ".join(part for part in (libc, target) if part)
        label = ARTEFACT_LABELS.get("tools") if kind == "lab" else kind
        described.append(f"{label} `{commit[:12]}`"
                         + (f" ({about})" if about else "") + f" on {where}")
    return [f"Artefacts: {'; '.join(described)}.", ""]


def compare_report(states: Sequence[dict[str, Any]], directories: Sequence[Path]) -> str:
    """One table per workload, medians across repetitions, a column per pair.

    This is what a WAN rung is read from (step 11.3): the pairs ran interleaved inside one
    session, so the columns share whatever the path was doing, and the medians are over the
    repetitions of that one session only. Comparing a column here with one from another session,
    another evening, the same hosts: is exactly what a real path does not support.
    """
    if not states:
        return "No runs.\n"
    first = states[0]
    order = ["GG", "RR", "GR", "RG"]
    present = [code for code in order if any(pair_code(s) == code for s in states)]
    present += sorted({pair_code(s) for s in states} - set(present))

    lines: list[str] = []
    where = (f"`{first['host']}` → `{first.get('server_host', first['host'])}`"
             if state_is_wan(first) else f"`{first['host']}`, netem `{first['netem']}`")
    lines.append(f"### {first['scenario']}: {where}, config {first['config'].upper()}")
    lines.append("")
    repetitions = collections.Counter(pair_code(s) for s in states)
    plural = "run" if len(states) == 1 else "runs"
    lines.append("Medians over " + ", ".join(f"{repetitions[code]}×{code}" for code in present)
                 + f" ({len(states)} {plural}, interleaved).")
    lines.append("")
    # Which binaries these numbers came out of. Without it the table is quotable but not
    # checkable weeks later, which is the whole of 11.3's problem with the polarity flipped.
    lines.extend(compare_artefacts(states))

    # One row per (workload, metric). The workload list comes from the first run, because every
    # run of a session is the same scenario.
    rows: list[tuple[str, str, dict[str, list[float]]]] = []
    for workload in first["workloads"]:
        collected: dict[str, dict[str, list[float]]] = {}
        for state, directory in zip(states, directories):
            match = next((w for w in state["workloads"] if w["tag"] == workload["tag"]), None)
            if match is None:
                continue
            for metric, value in workload_metrics(match, directory).items():
                collected.setdefault(metric, {}).setdefault(pair_code(state), []).append(value)
        for metric, by_pair in collected.items():
            rows.append((f"{workload['type']}/{workload['tag']}", metric, by_pair))

    if rows:
        lines.append("| workload | metric | " + " | ".join(present) + " | RR/GG |")
        lines.append("|---|---|" + "---|" * (len(present) + 1))
        for label, metric, by_pair in rows:
            cells = [format_number(median(by_pair.get(code, []))) for code in present]
            gg, rr = median(by_pair.get("GG", [])), median(by_pair.get("RR", []))
            ratio = "-" if not gg or rr is None else f"{rr / gg:.2f}×"
            lines.append(f"| {label} | {metric} | " + " | ".join(cells) + f" | {ratio} |")
        lines.append("")

    # SNMP, per side, so a retransmit can be attributed to the end that sent it.
    snmp_rows: list[tuple[str, str, dict[str, list[float]]]] = []
    for side, side_label in (("cli", "client"), ("srv", "server")):
        gathered: dict[str, dict[str, list[float]]] = {}
        for state, directory in zip(states, directories):
            totals = snmp_totals(run_file(directory, f"snmp-{side}.csv"))
            for name in COMPARE_SNMP:
                if name in totals:
                    gathered.setdefault(name, {}).setdefault(
                        pair_code(state), []).append(float(totals[name]))
        for name, by_pair in gathered.items():
            snmp_rows.append((side_label, name, by_pair))
    if snmp_rows:
        lines.append("| SNMP | counter | " + " | ".join(present) + " | RR/GG |")
        lines.append("|---|---|" + "---|" * (len(present) + 1))
        for side_label, name, by_pair in snmp_rows:
            cells = [format_number(median(by_pair.get(code, []))) for code in present]
            gg, rr = median(by_pair.get("GG", [])), median(by_pair.get("RR", []))
            ratio = "-" if not gg or rr is None else f"{rr / gg:.2f}×"
            lines.append(f"| {side_label} | {name} | " + " | ".join(cells) + f" | {ratio} |")
        lines.append("")
    return "\n".join(lines) + "\n"


def artefact_lines(state: dict[str, Any], side: str) -> list[str]:
    """The exact file one end of a run executed: commit, libc and sha256, or why not.

    A run section that only carries `deploy.sh`'s prose summary cannot be checked against
    anything later; the commit and the hash can be. A state written before 12.0 has neither, and
    says so rather than implying the artefact was identified.
    """
    label = ARTEFACT_LABELS.get(side, side)
    detail = state.get(f"{side}_build_detail")
    if not detail:
        if side not in ("client", "server"):
            # The lab tools are a 12.0 addition; an older state simply has no line for them,
            # and its client/server lines already say the run predates the stamp.
            return []
        return [f"- {label} artefact: **not recorded** (run predates the 12.0 build stamp)"]
    if detail.get("problem"):
        return [f"- ⚠ **{label} artefact unprovenanced**: {detail['problem']}"]
    parts = [f"commit `{detail.get('commit') or '?'}`"]
    if detail.get("revision"):
        parts.append(f"rev `{detail['revision']}`")
    if detail.get("libc"):
        parts.append(f"libc `{detail['libc']}`")
    if detail.get("target"):
        parts.append(f"target `{detail['target']}`")
    if detail.get("sha256"):
        parts.append(f"sha256 `{detail['sha256'][:16]}…` (verified on the host)")
    return [f"- {label} artefact `{detail.get('binary', '?')}`: " + ", ".join(parts)]
#: step 11.2's acceptance criterion: "for each (profile, config), RR goodput ≥ 0.95× GG".
MATRIX_ACCEPTANCE = 0.95


def matrix_family(state: dict[str, Any]) -> str:
    """Which scenario *file* a run came from: ``bulk-iperf3``, ``bulk-capped``, ``latency``.

    `--config`/`--netem` put the cell's two axes into the scenario's *name*, so the name alone
    cannot tell the capped control (`bulkcap-s1-clean`) from the cell it is a control for
    (`bulk-s1-clean`) once both are grouped by `(config, netem)`: they would merge, and a
    250 Mbit/s cap would be averaged into an uncapped measurement. The file behind the run does
    distinguish them, and `parse_scenario` records it.
    """
    source = str(state.get("source") or "")
    if source:
        return Path(source).stem
    return str(state.get("scenario", "?"))


def sockbuf_key(state: dict[str, Any]) -> str:
    """A run's kernel socket-buffer ceilings as one short string, ``""`` when not recorded.

    This is a cell's fourth axis, not a decoration. `-sockbuf` is silently clamped to
    `net.core.rmem_max`/`wmem_max` (see `socket_buffer_limits`), and on the 11.2 campaign the
    same host, scenario, config and profile gave 0.86× RR/GG at the stock 212992 and 1.45× at
    lab-arm64's 8388608. Two such runs are two different experiments, so a median must never be
    taken across them: a campaign and a same-day controlled re-run of three of its cells share
    every other key component *and* the session-name prefix `lab.py matrix` selects on, and
    merging them yields a ratio that corresponds to no experiment at all.

    The host name is included only when a run records more than one (a WAN run records both
    ends), so the common netns form is just ``rmem/wmem``.
    """
    limits = state.get("socket_buffer_limits") or {}
    parts = []
    for host, values in sorted(limits.items()):
        text = f"{(values or {}).get('rmem_max', '?')}/{(values or {}).get('wmem_max', '?')}"
        parts.append(f"{host} {text}" if len(limits) > 1 else text)
    return "; ".join(parts)


def matrix_cells(states: Sequence[dict[str, Any]],
                 directories: Sequence[Path]) -> dict[tuple[str, str, str, str], list[int]]:
    """Group run indices into 11.2's cells: workload file, config, netem profile, ceiling.

    A cell holds every pair and every repetition that were interleaved inside it. `lab.py run
    --config/--netem` puts the two axes in the scenario name, so the sessions are separate
    directories; here they come back together as the axes of one table, profiles in
    tools/lab/README.md's order. The socket-buffer ceiling is the fourth component for the reason
    `sockbuf_key` gives.
    """
    cells: dict[tuple[str, str, str, str], list[int]] = {}
    for index, state in enumerate(states):
        key = (matrix_family(state), str(state.get("config", "?")).lower(),
               str(state.get("netem", "?")), sockbuf_key(state))
        cells.setdefault(key, []).append(index)

    def order(key: tuple[str, str, str, str]) -> tuple[str, int, str, str, str]:
        family, config, netem, sockbuf = key
        rank = PROFILES.index(netem) if netem in PROFILES else len(PROFILES)
        return (config, rank, netem, family, sockbuf)

    return {key: cells[key] for key in sorted(cells, key=order)}


def cell_goodput(runs: Sequence[tuple[dict[str, Any], Path]],
                 tag: str) -> dict[str, list[float]]:
    """``pair -> [Mbit/s, …]`` for one workload of one cell."""
    return cell_workload_metric(runs, tag, "Mbit/s")


def cell_workload_metric(runs: Sequence[tuple[dict[str, Any], Path]],
                         tag: str, metric: str) -> dict[str, list[float]]:
    """``pair -> [value, …]`` for one metric of one workload of one cell."""
    out: dict[str, list[float]] = {}
    for state, directory in runs:
        match = next((w for w in state["workloads"] if w["tag"] == tag), None)
        if match is None:
            continue
        value = workload_metrics(match, directory).get(metric)
        if value is not None:
            out.setdefault(pair_code(state), []).append(float(value))
    return out


def run_tunnel_cpu(state: dict[str, Any], directory: Path) -> tuple[float, float] | None:
    """One run's tunnel CPU seconds and the megabits it delivered, or None if either is missing.

    The tunnel is the ``cli`` and ``srv`` samples only: ``tgt`` is ``iperf3 -s``, which is the
    workload rather than the thing under test, and on a one-vCPU host it is a third of the CPU
    in the box. The megabits are the workloads' own reported goodput multiplied by their
    durations, so CPU per delivered bit is a ratio of two numbers from the same run, which is
    the only form in which D29's flush-scan cost can be read off a host whose throughput is
    itself CPU-bound.
    """
    metrics = collected_process_metrics(directory, state.get("total_duration"))
    cpu = sum(float(metrics[label]["cpu_seconds"]) for label in ("cli", "srv")
              if label in metrics)
    if not cpu:
        return None
    megabits = 0.0
    for workload in state["workloads"]:
        rate = workload_metrics(workload, directory).get("Mbit/s")
        if rate is not None:
            megabits += float(rate) * float(workload.get("duration", 0))
    if megabits <= 0:
        return None
    return cpu, megabits


def snmp_ratio_rows(runs: Sequence[tuple[dict[str, Any], Path]],
                    side: str) -> dict[str, dict[str, float | None]]:
    """Per-pair medians of the retransmission-attribution figures for one side of a cell.

    These are the counters step 11.2 asks to be *attributed* rather than tuned: the 11.4
    soak saw 28.4 % of segments retransmitted on a 0.1 %-loss path with 189× more duplicates
    received than segments lost, and the question this table answers is whether kcp-go does the
    same thing on the same path. `RetransSegs` decomposes exactly into `LostSegs +
    FastRetransSegs + EarlyRetransSegs` (kcp-go's `flush`), so quoting the share of it that is
    fast retransmit says which mechanism fired.

    Note which end each counter belongs to. `RepeatSegs` is incremented by the **receiver** when
    `parse_data` finds a segment it already has (kcp-go `kcp.go`, the `IKCP_PACKET_REGULAR`
    branch of `Input`); `LostSegs` is incremented by the **sender** when `flush` finds a segment
    past its `resendts`. So a duplicate counted here was caused by the *other* process, and the
    spurious-retransmission ratio is a cross-side one: `cell_spurious_rows` computes it.
    """
    gathered: dict[str, dict[str, list[float | None]]] = {}
    for state, directory in runs:
        totals = snmp_totals(run_file(directory, f"snmp-{side}.csv"))
        if not totals:
            continue
        out_segs = float(totals.get("OutSegs", 0))
        retrans = float(totals.get("RetransSegs", 0))
        lost = float(totals.get("LostSegs", 0))
        repeat = float(totals.get("RepeatSegs", 0))
        fast = float(totals.get("FastRetransSegs", 0))
        # A share with nothing in its denominator is *undefined*, not zero, and `format_number`
        # prints `None` as an em dash for exactly that: a run with no retransmissions at all
        # would otherwise report "0 % of them were fast" next to genuine 100 % values and read
        # as the opposite of what happened. `cell_spurious_rows` drops such a pair the same way.
        row: dict[str, float | None] = {
            "OutSegs": out_segs,
            "RetransSegs": retrans,
            "retrans %": 100.0 * retrans / out_segs if out_segs else None,
            "fast % of retrans": 100.0 * fast / retrans if retrans else None,
            "LostSegs": lost,
            "RepeatSegs": repeat,
            "FECRecovered": float(totals.get("FECRecovered", 0)),
            "FECErrs": float(totals.get("FECErrs", 0)),
            # "No stuck sessions" is one of step 11.2's four acceptance criteria, and the
            # campaign is driven with `--no-report`, so this table is the only place it can be
            # evidenced: `CurrEstab (peak)` is the highest sample of the run and
            # `CurrEstab (end)` the last one, so a session that never closed shows as the two
            # disagreeing. `MaxConn` is kcp-go's own high-water mark of concurrent sessions.
            "MaxConn": float(totals.get("MaxConn", 0)),
            "CurrEstab (peak)": float(totals.get("CurrEstabMax", 0)),
            "CurrEstab (end)": float(totals.get("CurrEstab", 0)),
        }
        for name, value in row.items():
            gathered.setdefault(name, {}).setdefault(pair_code(state), []).append(value)
    # The median is over the repetitions that *defined* the figure; a pair that defined it in
    # none of them keeps its column and gets the em dash, rather than dropping the whole row
    # and leaving the other pairs' numbers with nothing to be compared against.
    return {name: {code: median([v for v in values if v is not None])
                   for code, values in by_pair.items()}
            for name, by_pair in gathered.items()}


def cell_spurious_rows(
        runs: Sequence[tuple[dict[str, Any], Path]]) -> dict[str, dict[str, float | None]]:
    """``figure -> pair -> median`` of the cross-side duplicate ratios of one cell.

    The duplicates one end *receives* were caused by the retransmissions the other end *sent*,
    so the figure that says whether a retransmission storm was spurious pairs one side's
    `RepeatSegs` with the other side's `LostSegs`, never with its own. A ratio well above 1
    means the sender was retransmitting segments that had in fact arrived. It is a lower bound
    on the waste, because it counts only the duplicates that reached the peer.
    """
    gathered: dict[str, dict[str, list[float]]] = {}
    for state, directory in runs:
        client = snmp_totals(run_file(directory, "snmp-cli.csv"))
        server = snmp_totals(run_file(directory, "snmp-srv.csv"))
        if not client or not server:
            continue
        code = pair_code(state)
        for figure, dups, lost in (
            ("client dups / server lost", client.get("RepeatSegs", 0),
             server.get("LostSegs", 0)),
            ("server dups / client lost", server.get("RepeatSegs", 0),
             client.get("LostSegs", 0)),
        ):
            if lost:
                gathered.setdefault(figure, {}).setdefault(code, []).append(
                    float(dups) / float(lost))
    return {figure: {code: median(values) for code, values in by_pair.items()}
            for figure, by_pair in gathered.items()}


def matrix_report(states: Sequence[dict[str, Any]], directories: Sequence[Path]) -> str:
    """step 11.2's matrix: one row per (config, profile), Go and Rust side by side.

    `compare` is one session (one cell) in full. This is the campaign: every cell's goodput
    with the RR/GG ratio the acceptance criterion is written in, the tunnel CPU per delivered
    bit, and the retransmission counters that attribute a difference to a mechanism.
    """
    if not states:
        return "No runs.\n"
    cells = matrix_cells(states, directories)
    pairs_present = [code for code in ("GG", "RR", "GR", "RG")
                     if any(pair_code(s) == code for s in states)]
    hosts = sorted({str(s.get("host", "?")) for s in states})
    builds = sorted({str(s.get("build") or "(not recorded)") for s in states})

    lines: list[str] = []
    lines.append("### Impairment matrix: goodput")
    lines.append("")
    lines.append(f"{len(cells)} cells, {len(states)} runs, host(s) `{'`, `'.join(hosts)}`.")
    lines.append("Build(s): " + "; ".join(f"`{b}`" for b in builds) + ".")
    lines.append("")
    lines.append("Both tunnel ends, the workload and its target share **one host**, so these "
                 "numbers measure protocol behaviour and the two implementations' relative "
                 "standing, not absolute throughput (tools/lab/README.md).")
    # `-sockbuf` is clamped to these without a word from the kernel, and the clamp can invert a
    # cell's conclusion, so no table of these numbers goes out without them.
    ceilings_line = socket_buffer_ceilings_line(states)
    if ceilings_line:
        lines.append("")
        lines.append(ceilings_line)
    # Runs taken under different ceilings are different experiments and `matrix_cells` keeps
    # them in separate cells; when a report holds more than one, every table gains a `ceiling`
    # column saying which row is which. With a single ceiling the preamble has already named
    # it and a column repeating it would be noise.
    ceilings = sorted({key[3] for key in cells})
    split = len(ceilings) > 1
    ceiling_head = "ceiling rmem/wmem | " if split else ""
    ceiling_rule = "---|" if split else ""

    def ceiling_cell(sockbuf: str) -> str:
        return f"{sockbuf or '-'} | " if split else ""

    if split:
        lines.append("")
        if len([c for c in ceilings if c]) > 1:
            lines.append("**More than one ceiling is represented here**, and a median across "
                         "two of them is a number no experiment produced, so those runs are "
                         "kept in separate cells and the `ceiling` column says which row is "
                         "which.")
        else:
            lines.append("Some of these runs **do not record a ceiling** (`-`), so they are "
                         "kept in their own cells rather than merged with the runs that do: "
                         "what a run does not say about itself is not something this table "
                         "can assume. The `ceiling` column says which row is which.")
    lines.append("")
    header = f"| config | profile | {ceiling_head}scenario | workload | " + " | ".join(
        f"{code} Mbit/s" for code in pairs_present) + " | RR/GG | |"
    lines.append(header)
    lines.append(f"|---|---|{ceiling_rule}---|---|" + "---:|" * len(pairs_present) + "---:|---|")
    for (family, config, netem, sockbuf), indices in cells.items():
        runs = [(states[i], directories[i]) for i in indices]
        tags = [w["tag"] for w in runs[0][0]["workloads"]]
        for tag in tags:
            by_pair = cell_goodput(runs, tag)
            if not by_pair:
                continue
            cells_text = [format_number(median(by_pair.get(code, [])))
                          for code in pairs_present]
            gg, rr = median(by_pair.get("GG", [])), median(by_pair.get("RR", []))
            if not gg or rr is None:
                ratio, verdict = "-", "-"
            else:
                ratio = f"{rr / gg:.2f}×"
                verdict = "ok" if rr / gg >= MATRIX_ACCEPTANCE else "**investigate**"
            lines.append(f"| {config.upper()} | {netem} | {ceiling_cell(sockbuf)}"
                         f"{family} | {tag} | "
                         + " | ".join(cells_text) + f" | {ratio} | {verdict} |")
    lines.append("")
    lines.append(f"`ok` is step 11.2's criterion, RR ≥ {MATRIX_ACCEPTANCE:.2f}× GG.")
    lines.append("")

    lines.append("### Tunnel CPU per delivered bit")
    lines.append("")
    lines.append("`cli` + `srv` CPU seconds over the megabits the same run delivered: "
                 "`iperf3 -s` (`tgt`) is excluded because it is the workload, not the "
                 "implementation. Lower is better; a ratio above 1 means Rust spent more CPU "
                 "for the same delivered data.")
    lines.append("")
    lines.append(f"| config | profile | {ceiling_head}scenario | "
                 + " | ".join(f"{code} ms/Mbit" for code in pairs_present) + " | RR/GG |")
    lines.append(f"|---|---|{ceiling_rule}---|" + "---:|" * len(pairs_present) + "---:|")
    for (family, config, netem, sockbuf), indices in cells.items():
        by_pair: dict[str, list[float]] = {}
        for index in indices:
            measured = run_tunnel_cpu(states[index], directories[index])
            if measured is None:
                continue
            cpu, megabits = measured
            by_pair.setdefault(pair_code(states[index]), []).append(1000.0 * cpu / megabits)
        if not by_pair:
            continue
        cells_text = [format_number(median(by_pair.get(code, []))) for code in pairs_present]
        gg, rr = median(by_pair.get("GG", [])), median(by_pair.get("RR", []))
        ratio = "-" if not gg or rr is None else f"{rr / gg:.2f}×"
        lines.append(f"| {config.upper()} | {netem} | {ceiling_cell(sockbuf)}{family} | "
                     + " | ".join(cells_text) + f" | {ratio} |")
    lines.append("")

    # 11.2 asks for "30 s pingpong (64 B) with and without a competing bulk flow" beside the
    # bulk numbers, and a percentile is not a goodput, so it needs its own table. The idle and
    # the loaded probe are separate workloads (`latency.json` says why), so the cost of the
    # competing flow is the difference between two rows rather than something averaged away.
    latency_rows: list[tuple[str, str, str, str, str, dict[str, list[float]]]] = []
    for (_family, config, netem, sockbuf), indices in cells.items():
        runs = [(states[i], directories[i]) for i in indices]
        for workload in runs[0][0]["workloads"]:
            if workload["type"] != "ping":
                continue
            for metric in ("p50 ms", "p90 ms", "p99 ms", "max ms", "errors"):
                by_pair = cell_workload_metric(runs, workload["tag"], metric)
                if by_pair:
                    latency_rows.append(
                        (config, netem, sockbuf, workload["tag"], metric, by_pair))
    if latency_rows:
        lines.append("### Request/response latency through the tunnel")
        lines.append("")
        lines.append("64-byte `pingpong ping`, median across repetitions of each run's whole-run "
                     "percentile. A `…load` tag is the same probe with a competing bulk flow "
                     "over the same tunnel. Lower is better, so **RR/GG below 1 is Rust ahead** "
                     "- the opposite of the goodput table.")
        lines.append("")
        lines.append(f"| config | profile | {ceiling_head}probe | metric | "
                     + " | ".join(pairs_present) + " | RR/GG |")
        lines.append(f"|---|---|{ceiling_rule}---|---|" + "---:|" * (len(pairs_present) + 1))
        for config, netem, sockbuf, tag, metric, by_pair in latency_rows:
            cells_text = [format_number(median(by_pair.get(code, [])))
                          for code in pairs_present]
            gg, rr = median(by_pair.get("GG", [])), median(by_pair.get("RR", []))
            ratio = "-" if not gg or rr is None else f"{rr / gg:.2f}×"
            lines.append(f"| {config.upper()} | {netem} | {ceiling_cell(sockbuf)}{tag} | "
                         f"{metric} | " + " | ".join(cells_text) + f" | {ratio} |")
        lines.append("")

    lines.append("### Retransmission attribution")
    lines.append("")
    lines.append("Whole-run SNMP totals, medians across repetitions. `RepeatSegs` is counted by "
                 "the **receiver** and `LostSegs` by the **sender**, so the ratio that says "
                 "whether a retransmission storm was spurious pairs one end's duplicates with "
                 "the *other* end's timeouts: the two `dups / lost` rows. Well above 1 means "
                 "segments were retransmitted that had in fact arrived. Go and Rust meet the "
                 "same impairment in the same cell, so a ratio they share is KCP's behaviour "
                 "and one they do not is ours. `CurrEstab (peak)` beside `CurrEstab (end)` is "
                 "where 11.2's \"no stuck sessions\" criterion is read: a run that left a "
                 "session behind ends above its floor.")
    lines.append("")
    figures = ("retrans %", "fast % of retrans", "RepeatSegs", "LostSegs",
               "FECRecovered", "FECErrs",
               "MaxConn", "CurrEstab (peak)", "CurrEstab (end)")
    lines.append(f"| config | profile | {ceiling_head}scenario | side | figure | "
                 + " | ".join(pairs_present) + " |")
    lines.append(f"|---|---|{ceiling_rule}---|---|---|" + "---:|" * len(pairs_present))
    for (family, config, netem, sockbuf), indices in cells.items():
        runs = [(states[i], directories[i]) for i in indices]
        prefix = f"| {config.upper()} | {netem} | {ceiling_cell(sockbuf)}{family} |"
        for side, side_label in (("cli", "client"), ("srv", "server")):
            rows = snmp_ratio_rows(runs, side)
            if not rows:
                continue
            for figure in figures:
                if figure not in rows:
                    continue
                values = rows[figure]
                cells_text = [format_number(values.get(code)) for code in pairs_present]
                lines.append(f"{prefix} {side_label} | {figure} | "
                             + " | ".join(cells_text) + " |")
        for figure, values in cell_spurious_rows(runs).items():
            cells_text = [format_number(values.get(code)) for code in pairs_present]
            lines.append(f"{prefix} both | {figure} | " + " | ".join(cells_text) + " |")
    lines.append("")

    # "The mixed pairs complete without errors" is half of 11.2's acceptance criterion, and a
    # campaign run with `--no-report` has no per-session report in which anyone would see it.
    lines.append("### Errors in the collected logs")
    lines.append("")
    flagged = [(state, scan_logs(directory))
               for state, directory in zip(states, directories)]
    flagged = [(state, notes) for state, notes in flagged if notes]
    if not flagged:
        lines.append(f"None, in any of the {len(states)} runs.")
    else:
        lines.append(f"{len(flagged)} of {len(states)} runs matched an error marker.")
        lines.append("")
        for state, notes in flagged:
            lines.append(f"- `{state['runid']}`")
            for note in notes[:10]:
                lines.append(f"  - {note}")
    lines.append("")
    return "\n".join(lines) + "\n"


def run_section(state: dict[str, Any], directory: Path) -> list[str]:
    lines = ["", f"## {state['runid']}", ""]
    lines.append(f"- client **{state['client_impl']}**, server **{state['server_impl']}**, "
                 f"repetition {state['repetition']}, target `{state['target']}`")
    lines.append(f"- started {state['started_iso']}, traffic {state['total_duration']} s")
    # Which host and which artefact. Without these a section is unattributable, and two runs
    # reported side by side (11.1b's whole shape) cannot be told apart at all. `build` is the
    # *client implementation's* per-family stamp summary: target triple, libc, profile,
    # revision: resolved before preflight; `server_build` is the server's. In the netns
    # arrangement both ends share one machine, so the summary is labelled as the client's
    # rather than as a property of the host, which also runs the other implementation.
    if state_is_wan(state):
        lines.append(f"- client host `{state.get('host', '(not recorded)')}`, "
                     f"build `{state.get('build') or '(not recorded)'}`")
        lines.extend(artefact_lines(state, "client"))
        lines.extend(artefact_lines(state, "tools"))
        # The measuring end of a latency run: the `kr-pingpong` that emits every percentile in
        # the table below, on the host that runs it. `artefact_lines` returns nothing when the
        # key is absent, so an iperf3 run and a pre-12.0 state are unchanged.
        lines.extend(artefact_lines(state, "target"))
        lines.append(f"- server host `{state.get('server_host', '(not recorded)')}` "
                     f"(`{state.get('server_addr', '?')}`), "
                     f"build `{state.get('server_build') or '(not recorded)'}`")
        lines.extend(artefact_lines(state, "server"))
        lines.extend(artefact_lines(state, "server_tools"))
        lines.extend(artefact_lines(state, "server_target"))
    else:
        lines.append(f"- host `{state.get('host', '(not recorded)')}`, "
                     f"client build `{state.get('build') or '(not recorded)'}`")
        lines.extend(artefact_lines(state, "client"))
        lines.extend(artefact_lines(state, "server"))
        lines.extend(artefact_lines(state, "tools"))
        # One host, so one `kr-pingpong`: it is both the echo target and the workload.
        lines.extend(artefact_lines(state, "target"))
    lines.append(f"- client: `{' '.join(state['client_argv'])}`")
    lines.append(f"- server: `{' '.join(state['server_argv'])}`")
    for when in ("before", "after"):
        loads = state.get(f"uptime_{when}") or {}
        for host, line in sorted(loads.items()):
            # A 1-vCPU box that was already busy explains a WAN number that nothing in the
            # protocol would (step 11.3 asks for this on both ends of every run).
            lines.append(f"- uptime {when}, `{host}`: {line}")
    lines.append("")

    lines.append("### Workloads")
    lines.append("")
    lines.append("| workload | result | command |")
    lines.append("|---|---|---|")
    for workload in state["workloads"]:
        # The command line, not only the result: an iperf3 `-b` cap that binds turns every pair
        # of a session into a measurement of the cap, and 11.3's own caveat about that could
        # only be checked by opening `state.json`, because the report printed the tunnel's
        # argv and never the workload's. A number and the command that produced it belong on
        # the same page.
        argv = workload.get("argv") or []
        command = f"`{' '.join(argv)}`" if argv else "(not recorded)"
        lines.append(f"| {workload['type']}/{workload['tag']} | "
                     f"{describe_workload(state, workload, directory)} | {command} |")
    lines.append("")

    metrics = collected_process_metrics(directory, state.get("total_duration"))
    if metrics:
        lines.append("### Process metrics (`/proc`, sampled)")
        lines.append("")
        lines.append("| process | samples | CPU s | RSS first→last kB | RSS max | VmHWM kB "
                     "| RSS slope kB/h | fds first→last | fd slope /h | threads |")
        lines.append("|---|---|---|---|---|---|---|---|---|---|")
        cutoffs = {m["slope_from_s"] for m in metrics.values() if m["slope_from_s"] is not None}
        for label in sorted(metrics):
            m = metrics[label]
            lines.append(
                f"| {label} | {m['samples']} | {m['cpu_seconds']:.1f} | "
                f"{m['rss_kb_first']:.0f}→{m['rss_kb_last']:.0f} ({m['rss_growth_kb']:+.0f}) | "
                f"{m['rss_kb_max']:.0f} | {m['hwm_kb']:.0f} | "
                f"{format_slope(m['rss_slope_kb_h'])} | "
                f"{m['fds_first']:.0f}→{m['fds_last']:.0f} ({m['fd_growth']:+.0f}) | "
                f"{format_slope(m['fd_slope_h'])} | "
                f"{m['threads_last']:.0f} |"
            )
        lines.append("")
        if cutoffs:
            counted = min(m["slope_samples"] for m in metrics.values() if m["slope_samples"])
            lines.append(
                f"Slopes are least-squares gradients over the {counted}+ samples taken after "
                f"warm-up (from {min(cutoffs):.0f} s). A flat slope is the soak's acceptance "
                "criterion (step 11.4); first→last alone cannot tell a one-off step from "
                "a leak.")
        else:
            spans = [m["slope_span_s"] for m in metrics.values()
                     if m["slope_span_s"] is not None]
            observed = max(spans) if spans else 0.0
            intended = state.get("total_duration")
            cutoff = warmup_cutoff(observed, intended)
            note = ("Too few samples after warm-up for a slope (step 11.4 needs "
                    f"{MIN_SLOPE_SAMPLES} beyond {cutoff:.0f} s); "
                    "first→last is all this run supports.")
            if intended and intended >= cutoff > observed:
                # The dangerous case: a run that was long enough to clear warm-up, collected
                # before it did. Without this sentence the table's empty slope columns look like
                # a property of the process rather than of when the samples were taken. A run
                # that is simply shorter than the warm-up window (the smoke scenario) is not
                # this, and does not get the sentence.
                note += (f" This run was collected before warm-up ended: {observed:.0f} s of "
                         f"samples against an intended {intended:.0f} s.")
            lines.append(note)
        lines.append("")

    snmp = {side: snmp_totals(run_file(directory, f"snmp-{side}.csv"))
            for side in ("cli", "srv")}
    if any(snmp.values()):
        lines.append("### SNMP (totals for the run; the counters start at zero with the process)")
        lines.append("")
        names = [n for n in SNMP_COLUMNS
                 if any(n in snmp[side] for side in ("cli", "srv"))]
        lines.append("| counter | client | server |")
        lines.append("|---|---|---|")
        for name in names:
            lines.append(f"| {name} | {snmp['cli'].get(name, '-')} | "
                         f"{snmp['srv'].get(name, '-')} |")
        if "CurrEstabMax" in snmp["cli"] or "CurrEstabMax" in snmp["srv"]:
            lines.append(f"| CurrEstab (max) | {snmp['cli'].get('CurrEstabMax', '-')} | "
                         f"{snmp['srv'].get('CurrEstabMax', '-')} |")
        lines.append(f"| _records_ | {snmp['cli'].get('_records', 0)} | "
                     f"{snmp['srv'].get('_records', 0)} |")
        lines.append("")

    notes = scan_logs(directory)
    lines.append("### Notes")
    lines.append("")
    if notes:
        lines.append("Lines that matched an error marker:")
        lines.append("")
        for note in notes:
            lines.append(f"- `{note}`")
    else:
        lines.append("No error markers in any collected log.")
    lines.append("")
    return lines


# --------------------------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------------------------


def runs_dir(args: argparse.Namespace) -> Path:
    return Path(args.runs_dir).expanduser().resolve()


def find_run(args: argparse.Namespace, runid: str) -> Path:
    """The local directory of a run, by run id or by path.

    Layout: ``<runs-dir>/<stamp>-<scenario>/<runid>/state.json``. A prefix is accepted as long
    as it identifies exactly one run, so a run can be named without its timestamp.
    """
    candidate = Path(runid)
    if (candidate / "state.json").exists():
        return candidate.resolve()
    root = runs_dir(args)
    if not root.exists():
        raise LabError(f"no runs under {root}")
    found = [
        state.parent
        for pattern in ("*/state.json", "*/*/state.json")
        for state in sorted(root.glob(pattern))
        if state.parent.name.startswith(runid)
    ]
    exact = [path for path in found if path.name == runid]
    if exact:
        found = exact
    if len(found) == 1:
        return found[0]
    if len(found) > 1:
        raise LabError(f"{runid!r} matches {len(found)} runs; name one exactly")
    raise LabError(f"no run {runid!r} under {root}")


def find_session(args: argparse.Namespace, name: str) -> list[Path]:
    """Every collected run of one session, oldest first.

    `name` is a session directory, a path, or enough of one to identify it: sessions are
    ``<runs-dir>/<stamp>-<scenario>/``. The runs of a session are the rows of a comparison
    table, and they were interleaved, so their order matters.
    """
    candidate = Path(name)
    if not candidate.is_dir():
        root = runs_dir(args)
        matches = sorted(path for path in root.glob(f"{name}*") if path.is_dir())
        if not matches:
            matches = sorted(path for path in root.glob(f"*{name}*") if path.is_dir())
        if not matches:
            raise LabError(f"no session {name!r} under {root}")
        if len(matches) > 1:
            listed = ", ".join(path.name for path in matches)
            raise LabError(f"{name!r} matches {len(matches)} sessions: {listed}")
        candidate = matches[0]
    runs = sorted(path.parent for path in candidate.glob("*/state.json"))
    if not runs:
        raise LabError(f"{candidate} holds no collected runs")
    return runs


def cmd_compare(_runner: Runner, args: argparse.Namespace) -> int:
    """The per-pair comparison table for a whole session (step 11.3's per-path table)."""
    directories = find_session(args, args.session)
    states = [json.loads((path / "state.json").read_text()) for path in directories]
    order = sorted(range(len(states)), key=lambda index: states[index].get("started_unix", 0))
    states = [states[index] for index in order]
    directories = [directories[index] for index in order]
    # The comparison table is the artefact a rung is quoted from: `--report` writes it straight
    # into docs/lab-results/, so it leads with the same refusal to look clean that
    # `markdown_report` does. 11.3's 0.75x reached a document through exactly this path.
    banner = unprovenanced_banner(states)
    text = ("\n".join(banner) + "\n" if banner else "") + compare_report(states, directories)
    print(text, end="")
    if args.report:
        destination = Path(args.report)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
        print(f"lab: comparison written to {destination}", file=sys.stderr)
    return 0


def find_matrix_sessions(args: argparse.Namespace, name: str) -> list[Path]:
    """Every session directory matching `name`: a campaign, not a single session.

    `find_session` refuses an ambiguous prefix, which is right for `compare` (one session is one
    table) and wrong here: a campaign's cells are *separate* sessions by construction, so
    ``STAMP-bulk`` naming all seven impairment profiles is the normal case, not a mistake.
    """
    candidate = Path(name)
    if (candidate / "state.json").exists() or list(candidate.glob("*/state.json")):
        return [candidate.resolve()]
    root = runs_dir(args)
    matches = sorted(path for path in root.glob(f"{name}*")
                     if path.is_dir() and list(path.glob("*/state.json")))
    if not matches:
        matches = sorted(path for path in root.glob(f"*{name}*")
                         if path.is_dir() and list(path.glob("*/state.json")))
    if not matches:
        raise LabError(f"no session {name!r} with collected runs under {root}")
    return matches


def cmd_matrix(_runner: Runner, args: argparse.Namespace) -> int:
    """step 11.2's table across many sessions: one per (config, netem) cell."""
    directories: list[Path] = []
    for name in args.sessions:
        for session in find_matrix_sessions(args, name):
            directories.extend(sorted(path.parent
                                      for path in session.glob("*/state.json")))
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in directories:
        if path not in seen:
            seen.add(path)
            unique.append(path)
    states = [json.loads((path / "state.json").read_text()) for path in unique]
    order = sorted(range(len(states)), key=lambda index: states[index].get("started_unix", 0))
    states = [states[index] for index in order]
    directories = [unique[index] for index in order]
    text = matrix_report(states, directories)
    print(text, end="")
    if args.report:
        destination = Path(args.report)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
        print(f"lab: matrix written to {destination}", file=sys.stderr)
    return 0


def cmd_deploy(runner: Runner, args: argparse.Namespace) -> int:
    argv = [str(REPO / "tools" / "lab" / "deploy.sh")]
    for flag in ("scripts", "go", "rust", "tools", "gnu"):
        if getattr(args, flag):
            argv.append(f"--{flag}")
    # `auto` is deploy.sh's own default (it asks the host for `uname -m`), so passing it would be
    # harmless, but leaving it off keeps the echoed command line honest about what was chosen.
    if args.arch != "auto":
        argv += ["--arch", args.arch]
    if args.glibc:
        argv += ["--glibc", args.glibc]
    if args.profile != "release":
        argv += ["--profile", args.profile]
    # deploy.sh takes its host from $KCPTUN_LAB_HOST and knows nothing about our --host, so it
    # has to be told: without this, `lab.py --host lab-x86-1 deploy` would write into lab-arm64's
    # ~/kcptun-lab: the box that carries the live production mesh.
    result = runner.local(argv, check=False,
                          env={**os.environ, "KCPTUN_LAB_HOST": runner.host})
    print(result.out, end="")
    if not result.ok:
        print(result.err, end="", file=sys.stderr)
    return result.code


def cmd_netns_up(runner: Runner, args: argparse.Namespace) -> int:
    ensure_netns(runner, args.profile)
    print(runner.lab("netns", "status").out, end="")
    return 0


def cmd_netns_down(runner: Runner, _args: argparse.Namespace) -> int:
    print(runner.lab("netns", "down").out, end="")
    return 0


def cmd_baseline(runner: Runner, _args: argparse.Namespace) -> int:
    print(runner.lab("baseline").out, end="")
    return 0


def cmd_cleanup(runner: Runner, _args: argparse.Namespace) -> int:
    result = runner.lab("cleanup", check=False, timeout=300)
    print(result.out, end="")
    if not result.ok:
        print(result.err, end="", file=sys.stderr)
    return result.code


def cmd_status(runner: Runner, args: argparse.Namespace) -> int:
    state: dict[str, Any] | None = None
    if args.runid:
        state = json.loads((find_run(args, args.runid) / "state.json").read_text())
        check_client_host(runner, state)

    def show(on: Runner, names: Sequence[str], label: str = "") -> None:
        status = on.lab("status", *names, check=False).out
        if label:
            print(f"--- {label} {on.host}")
        print(status if status.strip() else "lab: nothing running, no namespace lab\n", end="")
        if state is None:
            return
        tail = on.ssh(
            f'tail -n 3 "$HOME/kcptun-lab/logs/{state["runid"]}/proc.csv" 2>/dev/null || true',
            check=False,
        ).out
        if tail.strip():
            print("\nlast samples:")
            print(tail, end="")

    if state is not None and state_is_wan(state):
        # Both halves, each from its own machine: a WAN run whose server end has died looks
        # perfectly healthy from the client host.
        show(runner, host_names(state, "client"), "client")
        show(server_runner(runner, state), host_names(state, "server"), "server")
    else:
        show(runner, state["names"] if state else [])
    return 0


def warn_clamped_sockbuf(runner: Runner, scenario: Scenario,
                         sides: Sequence[str] = ("client", "server")) -> None:
    """Say so, loudly, when the host will silently shrink the scenario's ``-sockbuf``.

    Not an error: measuring a tunnel against a small receive buffer is a legitimate thing to
    do, and it is what an untuned VPS gives a real deployment. Measuring it *without knowing*
    is not: tools/lab/README.md records lab-arm64 at `rmem_max` 8 MiB while a stock Ubuntu box is at
    212992, so the same scenario on two lab hosts is two different experiments.

    `sides` is which end's flags this host actually runs: both in the namespace lab, one each
    on a WAN run, where the two hosts have their own ceilings and their own halves of the
    tunnel.

    A side that names no ``-sockbuf`` is **not** skipped. It still asks the kernel for
    `DEFAULT_SOCKBUF`, so S2/S3/S4 are clamped 20x on a stock host exactly as S1 is clamped
    40x, and treating an absent flag as "no request" is what kept that silent.
    """
    limits = runner.socket_buffer_limits()
    if not limits:
        return
    # kcptun's `-sockbuf` sets SO_SNDBUF *and* SO_RCVBUF (`SetReadBuffer`/`SetWriteBuffer` in
    # reference/kcptun/client/main.go:467-471 and server/main.go:412-416), so each side is
    # against both ceilings: `wmem_max` decides how large a burst it can hand the kernel and
    # `rmem_max` how large a burst it can absorb.
    for side in sides:
        wanted = merged_flags(scenario, side).get("sockbuf")
        defaulted = not isinstance(wanted, int) or isinstance(wanted, bool)
        if defaulted:
            wanted = DEFAULT_SOCKBUF
        asked = f"-sockbuf {wanted}" if not defaulted else (
            f"default -sockbuf of {wanted} (kcptun's own, applied even though the "
            "configuration names no flag)")
        for sysctl, what in (("rmem_max", "receive"), ("wmem_max", "send")):
            limit = limits.get(sysctl)
            if limit and wanted > limit:
                print(f"lab: ⚠ {runner.host} net.core.{sysctl} is {limit}, so the {side}'s "
                      f"{asked} gives a {limit}-byte {what} buffer "
                      f"({wanted / limit:.0f}x smaller than asked for)", file=sys.stderr)


def cmd_run(runner: Runner, args: argparse.Namespace) -> int:
    scenario = load_scenario(Path(args.scenario))
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    if args.repetitions:
        scenario.repetitions = args.repetitions
    if args.pair:
        client_impl, _, server_impl = args.pair.partition(":")
        if client_impl not in IMPLS or server_impl not in IMPLS:
            raise LabError(f"--pair {args.pair!r}: want client:server, each go or rust")
        scenario.pairs = [(client_impl, server_impl)]
    # The iperf3 `-b` cap is a guard rail against saturating a host's NIC, not part of the
    # measurement, and what it has to clear is a property of the *path*, not of the scenario
    # file. 400M never binds on the 131 ms rung 11.3 ran and binds hard on the 95 ms one, where
    # a Go client alone drives 631 Mbit/s; a cap that binds makes every implementation report
    # the cap, which is how 11.3's first attempt produced four pairs all reporting exactly
    # 60.0 Mbit/s. So the cap is set per session, like the path, and the whole session shares
    # it (every pair, both directions) so that it can never favour one implementation.
    if getattr(args, "bitrate", None):
        capped = [w for w in scenario.workloads if w.type == "iperf3"]
        if not capped:
            raise LabError(f"--bitrate {args.bitrate}: {scenario.name} has no iperf3 workload "
                           "(-b is an iperf3 flag; the pingpong workloads have no bitrate)")
        for workload in capped:
            workload.options["bitrate"] = args.bitrate
        print(f"lab: iperf3 guard rail overridden to -b {args.bitrate} on "
              f"{', '.join(w.tag for w in capped)}", file=sys.stderr)
    # One WAN scenario, pointed at each rung of the RTT ladder in turn (step 11.3): the path
    # is a property of the session, not of the file.
    if getattr(args, "server_host", None):
        scenario.mode = MODE_WAN
        scenario.server_host = args.server_host
    if getattr(args, "server_addr", None):
        scenario.mode = MODE_WAN
        scenario.server_addr = args.server_addr
    # 11.2's matrix is 7 netem profiles x 4 flag configurations of the *same* workload, and
    # writing 28 near-identical scenario files is how one of them ends up differing in something
    # nobody meant to vary. The impairment and the flag set are properties of the cell, so they
    # are given on the command line, exactly as 11.3's path is. Both go into the scenario's name
    # (and therefore into the session directory, the run ids and the pid files), because
    # otherwise two cells of one campaign are indistinguishable once they are on disk.
    if getattr(args, "config", None):
        scenario.config = args.config
        scenario.name = f"{scenario.name}-{args.config}"
    if getattr(args, "netem", None):
        if scenario.is_wan:
            # parse_scenario refuses the same combination in a file; the override must not be a
            # way around it. A real path cannot be shaped (tools/lab/README.md rule 2), so this would
            # otherwise produce a report claiming an impairment the run never had.
            raise LabError(f"--netem {args.netem}: mode wan measures the real path and cannot "
                           "apply netem (netem needs the namespace lab; use mode netns)")
        scenario.netem = args.netem
        scenario.name = f"{scenario.name}-{args.netem}"
    check_runnable(scenario, runner.host)
    runs = plan_runs(scenario, stamp)
    if args.detach and len(runs) != 1:
        raise LabError("--detach runs exactly one pair and one repetition "
                       f"(this scenario plans {len(runs)})")

    session = runs_dir(args) / f"{stamp}-{scenario.name}"
    server = runner.peer(scenario.server_host) if scenario.is_wan else runner
    target_port = (scenario.iperf_port if scenario.target == "iperf3"
                   else scenario.pingpong_port)

    # Provenance first: it is read-only, it costs about one ssh per stamp file (one per family
    # per host, cached across the whole session) plus one per binary hashed, and it is the check
    # whose failure invalidates every number the session would otherwise spend hours producing.
    # Refusing here means nothing has been started, no baseline taken, no namespace touched and,
    # because this runs before the mkdir below, not even an empty session directory left for
    # `find_session` to match ambiguously later.
    provenance = BuildProvenance(
        allow_unprovenanced=getattr(args, "allow_unprovenanced", False))
    for plan in runs:
        provenance.require(runner, plan.client_impl, "client")
        provenance.require(server, plan.server_impl, "server")
    provenance.require(runner, "lab", "sampler")
    if scenario.is_wan:
        provenance.require(server, "lab", "sampler")
    if scenario.target == "pingpong":
        # The measuring end and the echo end; see `start_run`, which keeps both stamps. On a
        # netns run these are one host and the cache makes the second call free.
        provenance.require(runner, "lab", "target")
        provenance.require(server, "lab", "target")

    # A dry run previews commands; it must not leave a run directory, a state.json or: worse,
    # a fabricated, empty report inside the git-tracked docs/lab-results/.
    if not runner.dry_run:
        session.mkdir(parents=True, exist_ok=True)
    print(f"lab: {len(runs)} run(s) of {scenario.name} "
          f"({scenario.total_duration}s of traffic each) -> {session}")
    if scenario.is_wan:
        print(f"lab: real path {runner.host} -> {server.host} ({scenario.server_addr}), "
              "no netem")
        # Each host is checked for the ports it will actually bind: the tunnel and the target
        # belong to the server host, the client's listener to the client host. Checking all four
        # on both would refuse a run because the *other* machine's port is busy.
        checks = preflight(runner, max_load=args.max_load, wait_seconds=args.wait_load,
                           force=args.force, ports=(scenario.listen_port,))
        print(f"lab: preflight {runner.host}, {checks}")
        checks = preflight(server, max_load=args.max_load, wait_seconds=args.wait_load,
                           force=args.force,
                           ports=(*scenario.tunnel_ports, target_port))
        print(f"lab: preflight {server.host}, {checks}")
        # Both ends, because a WAN run uses the same S1 `-sockbuf 8388608` and each host clamps
        # its own half of it. 11.3's committed results were measured on hosts whose `rmem_max`
        # was never read, which is exactly the condition 11.2 found capable of inverting a
        # cell's conclusion: a WAN path cannot be re-run under a raised ceiling afterwards.
        warn_clamped_sockbuf(runner, scenario, ("client",))
        warn_clamped_sockbuf(server, scenario, ("server",))
    else:
        checks = preflight(runner, max_load=args.max_load, wait_seconds=args.wait_load,
                           force=args.force,
                           ports=(*scenario.tunnel_ports, scenario.listen_port,
                                  scenario.iperf_port, scenario.pingpong_port))
        print(f"lab: preflight, {checks}")
        warn_clamped_sockbuf(runner, scenario)
        ensure_netns(runner, scenario.netem)

    states: list[dict[str, Any]] = []
    directories: list[Path] = []
    #: The run being started or running, from *before* the first process of it exists. It is a
    #: `RunPlan` and not the state dictionary `start_run` returns, because the dangerous window
    #: is exactly the one where that dictionary does not exist yet: an interrupt between the
    #: first `lab-start.sh` and `start_run` returning used to leave a tunnel up on **two** hosts
    #: with nothing left on the laptop that knew their names. A plan knows every name it will
    #: use before any of them is used, and `lab-stop.sh` simply says "no pid file" for the ones
    #: that were never started.
    current: RunPlan | None = None

    def stop_everything(plan: RunPlan) -> None:
        """Stop this run on every host it touches: Ctrl-C must not leave a tunnel up."""
        runner.stop(plan.client_host_names)
        if plan.server_host_names:
            server.stop(plan.server_host_names)

    def emergency_stop(*_ignored: Any) -> None:
        if current is not None and not args.detach:
            print("\nlab: interrupted, stopping this run's processes", file=sys.stderr)
            stop_everything(current)
        raise SystemExit(130)

    previous = signal.signal(signal.SIGINT, emergency_stop)
    try:
        for plan in runs:
            print(f"lab: starting {plan.runid} "
                  f"({plan.client_impl} client -> {plan.server_impl} server)")
            current = plan
            started = start_run(runner, plan, server, provenance)
            local_dir = session / plan.runid
            if not runner.dry_run:
                local_dir.mkdir(parents=True, exist_ok=True)
                (local_dir / "state.json").write_text(json.dumps(started, indent=2) + "\n")
            if args.detach:
                # `--host` is part of the hint, not optional: it defaults to DEFAULT_HOST, and
                # `collect` takes the client host from it (only the server host comes from the
                # state), so the printed line has to name the host this run was started on.
                print(f"lab: detached; finish with\n"
                      f"    tools/lab/lab.py --host {runner.host} collect {plan.runid}")
                current = None
                return 0
            if not wait_for_workloads(runner, started, slack=args.slack):
                print("lab: workloads did not finish in time; collecting anyway",
                      file=sys.stderr)
            finish_run(runner, started, local_dir, max_log_bytes=args.max_log_bytes)
            states.append(started)
            directories.append(local_dir)
            current = None
    finally:
        signal.signal(signal.SIGINT, previous)
        if current is not None and not args.detach:
            stop_everything(current)

    if states and not args.no_report:
        write_report(states, directories, args, session, dry_run=runner.dry_run)
    return 0


def cmd_collect(runner: Runner, args: argparse.Namespace) -> int:
    local_dir = find_run(args, args.runid)
    state = json.loads((local_dir / "state.json").read_text())
    check_client_host(runner, state)
    if args.wait:
        wait_for_workloads(runner, state, slack=args.slack)
    finish_run(runner, state, local_dir, max_log_bytes=args.max_log_bytes)
    if not args.no_report:
        write_report([state], [local_dir], args, local_dir.parent, dry_run=runner.dry_run)
    return 0


def cmd_report(runner: Runner, args: argparse.Namespace) -> int:
    """Rebuild a report from collected runs: one run, or a whole session.

    A session is accepted because a scenario that aborts part-way (one flaky workload out of
    twelve) never reaches `write_report`, and the runs it *did* collect are on the laptop with
    no way to turn them into anything.
    """
    try:
        directories = [find_run(args, args.runid)]
    except LabError:
        directories = find_session(args, args.runid)
    states = [json.loads((path / "state.json").read_text()) for path in directories]
    order = sorted(range(len(states)), key=lambda index: states[index].get("started_unix", 0))
    states = [states[index] for index in order]
    directories = [directories[index] for index in order]
    write_report(states, directories, args, directories[0].parent, dry_run=runner.dry_run)
    return 0


def write_report(states: list[dict[str, Any]], directories: list[Path],
                 args: argparse.Namespace, session: Path, *, dry_run: bool = False) -> None:
    destination = Path(args.report) if args.report else (
        REPO / "docs" / "lab-results" / f"{states[0]['scenario']}-{session.name}.md"
    )
    if dry_run:
        # Nothing was collected, so there is nothing to summarise; writing anyway would drop an
        # empty report into the git-tracked docs/lab-results/.
        print(f"lab: dry run, no report written (would be {destination})")
        return
    text = markdown_report(states, directories)
    (session / "report.md").write_text(text, encoding="utf-8")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text, encoding="utf-8")
    print(f"lab: report written to {destination}")


# --------------------------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lab.py",
        description="Scenario runner for the kcptun network lab (Step 11).",
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help="ssh host (default %(default)s)")
    parser.add_argument("--runs-dir", default=str(REPO / "lab-runs"),
                        help="where raw run output is kept (default %(default)s)")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the commands instead of running them")
    parser.add_argument("-v", "--verbose", action="store_true", help="echo every command")
    sub = parser.add_subparsers(dest="command", required=True)

    deploy = sub.add_parser("deploy", help="copy scripts, binaries and lab tools to the host")
    for flag in ("scripts", "go", "rust", "tools"):
        deploy.add_argument(f"--{flag}", action="store_true")
    deploy.add_argument("--arch", choices=("auto", "aarch64", "x86_64"), default="auto",
                        help="architecture to build and copy; auto asks the host (default)")
    deploy.add_argument("--gnu", action="store_true",
                        help="build against glibc instead of static musl (DECISIONS D07: glibc "
                             "is what the released Linux artifacts are)")
    deploy.add_argument("--glibc", default=None, metavar="VERSION",
                        help="minimum glibc for --gnu (deploy.sh defaults to 2.17, which runs "
                             "on every lab host; 2.39 would not start on Ubuntu 22.04)")
    deploy.add_argument("--profile", default="release", help="cargo profile (default release)")
    deploy.set_defaults(func=cmd_deploy)

    netns_up = sub.add_parser("netns-up", help="create the namespace lab with a netem profile")
    netns_up.add_argument("profile", choices=PROFILES)
    netns_up.set_defaults(func=cmd_netns_up)

    sub.add_parser("netns-down", help="remove the namespace lab").set_defaults(func=cmd_netns_down)
    sub.add_parser("baseline", help="snapshot the host state").set_defaults(func=cmd_baseline)
    sub.add_parser("cleanup", help="stop everything and verify against the baseline"
                   ).set_defaults(func=cmd_cleanup)

    status = sub.add_parser("status", help="what the lab is running")
    status.add_argument("runid", nargs="?")
    status.set_defaults(func=cmd_status)

    run = sub.add_parser("run", help="run a scenario")
    run.add_argument("scenario")
    run.add_argument("--detach", action="store_true",
                     help="start and return; finish later with `collect`")
    run.add_argument("--repetitions", type=int, help="override the scenario's repetitions")
    run.add_argument("--config", choices=tuple(sorted(CONFIGS)),
                     help="override the scenario's flag configuration (11.2's matrix axis); "
                          "the name is appended to the scenario's")
    run.add_argument("--netem", choices=PROFILES,
                     help="override the scenario's impairment profile (11.2's other matrix "
                          "axis); the name is appended to the scenario's")
    run.add_argument("--pair", metavar="CLIENT:SERVER",
                     help="run only this pair, e.g. go:go (the soak's Go comparison run)")
    run.add_argument("--bitrate", metavar="RATE",
                     help="override every iperf3 workload's -b guard rail (e.g. 900M). The cap "
                          "belongs to the path, not to the scenario: 400M never binds on the "
                          "131 ms rung and binds hard on the 95 ms one, where a Go client alone "
                          "drives 631 Mbit/s, and a cap that binds makes every implementation "
                          "report the cap")
    run.add_argument("--server-host", metavar="HOST",
                     help="run the kcptun server on this second ssh host, over the real path "
                          "between it and --host (WAN mode, step 11.3). No netem is "
                          "applied, and nothing is namespaced")
    run.add_argument("--server-addr", metavar="ADDR",
                     help="the address the client dials the --server-host at (its public IP)")
    run.add_argument("--max-load", type=float, default=1.0,
                     help="refuse to start above this load average (default %(default)s)")
    run.add_argument("--wait-load", type=int, default=0,
                     help="seconds to wait for the load to fall before giving up")
    run.add_argument("--force", action="store_true", help="start even on a busy host")
    run.add_argument("--allow-unprovenanced", action="store_true",
                     help="start even when an end's deployed artefact cannot be identified "
                          "from its BUILD.txt; every report of the session is then marked "
                          "UNPROVENANCED (11.3 produced 27 runs nobody can attribute)")
    run.set_defaults(func=cmd_run)

    collect = sub.add_parser("collect", help="finish a detached run and write its report")
    collect.add_argument("runid")
    collect.add_argument("--wait", action="store_true",
                         help="wait for the workloads to finish first")
    collect.set_defaults(func=cmd_collect)

    report = sub.add_parser("report", help="regenerate a report from a collected run")
    report.add_argument("runid")
    report.set_defaults(func=cmd_report)

    compare = sub.add_parser(
        "compare", help="one table per workload for a whole session: medians per pair, "
                        "Go against Rust over the conditions they shared")
    compare.add_argument("session", help="a session directory under --runs-dir, or a prefix")
    compare.set_defaults(func=cmd_compare)

    matrix = sub.add_parser(
        "matrix", help="step 11.2's impairment matrix across many sessions: one row per "
                       "(config, netem) cell, with the RR/GG ratio, the tunnel CPU per "
                       "delivered bit and the retransmission counters")
    matrix.add_argument("sessions", nargs="+",
                        help="session directories under --runs-dir, or prefixes of them")
    matrix.set_defaults(func=cmd_matrix)

    for command in (run, collect, report, compare, matrix):
        command.add_argument("--report", help="write the Markdown report here")
    for command in (run, collect):
        command.add_argument("--no-report", action="store_true")
        command.add_argument("--slack", type=int, default=120,
                             help="extra seconds to wait for a workload (default %(default)s)")
        command.add_argument("--max-log-bytes", type=int, default=8 * 1024 * 1024,
                             help="clip collected logs to this size (default %(default)s)")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    runner = Runner(args.host, dry_run=args.dry_run, verbose=args.verbose)
    try:
        return int(args.func(runner, args))
    except LabError as exc:
        print(f"lab: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
