#!/usr/bin/env python3
"""Failure-mode driver for the Step 11 network lab (step 11, 11.5).

Runs **on the laptop** and drives one Linux lab host over ssh, exactly like `lab.py`, whose
`Runner`, flag sets, build provenance and guarded helpers this reuses rather than duplicates.

    tools/lab/failure.py --host lab-x86-3 cases
    tools/lab/failure.py --host lab-x86-3 run
    tools/lab/failure.py --host lab-x86-3 run --case server-restart --pairs rr
    tools/lab/failure.py report <session>

Where `lab.py` measures a *healthy* tunnel, this one breaks it on purpose and measures what
happens next. Each case is a fixed timeline: a `kr-pingpong ping` runs through the tunnel for
the whole case at a one-second reporting interval, and at known offsets the driver kills a
process, restarts it, or blackholes the path. The CSV the ping writes is therefore a
second-by-second record of when traffic stopped and when it came back, aligned to the fault by
unix time, and every case runs against **both implementations** so each answer is attributable:

* a failure mode where Rust matches Go is the point of the exercise;
* one where it does not is a finding for docs/DECISIONS.md.

Why a second file rather than another `lab.py` scenario type: a scenario there is a workload
schedule and nothing more — nothing in it can stop the server halfway and start it again, and
adding a fault timeline to `Scenario` would put "kill this" in the same object the soak and the
WAN matrix are described with. The two share everything that touches the host (the guarded
`lab-*.sh` helpers, the build stamps, the preflight, the netns lab) and differ only in what they
do with it.

**Safety.** Nothing here bypasses the rules of tools/lab/README.md: processes are started and stopped
only through `lab-start.sh` / `lab-stop.sh` by PID file, netem only ever touches our own veths
inside the `kr-cli`/`kr-srv` namespaces, no port below 4000 is used, and every case stops what it
started before the next one begins. SIGKILL is sent through `lab-stop.sh --signal KILL`, which
verifies `/proc/<pid>/exe` against the recorded path first, so "kill the server" can never mean
somebody else's server.
"""

from __future__ import annotations

import argparse
import json
import re
import signal
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

import lab  # noqa: E402  (the import needs the path above)
from lab import LAB, LabError, Runner  # noqa: E402

# --------------------------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------------------------

#: Ports. All inside the namespace lab, all in the sanctioned ranges (tools/lab/README.md rule 4),
#: and deliberately *not* `lab.py`'s defaults: a failure campaign and a matrix cell must be able
#: to run on one host without colliding, and the whole point of this file is that it is run
#: while something else is going on.
TUNNEL_PORT = 29904
TUNNEL_PORT_COUNT = 4          # the port-range case spans 29904-29907
LISTEN_PORT = 12952            # the client's TCP listener, inside kr-cli
PINGPONG_PORT = 22640          # the echo target, inside kr-srv on 127.0.0.1
REFUSED_PORT = 22641           # nothing ever listens here: connect() gets an RST
#: An address the server namespace has a route to but nothing answers at: the next hop is the
#: *client* namespace, which does not forward, so a SYN is dropped rather than refused. That is
#: the difference between the two target cases — a refused target fails in microseconds, an
#: unreachable one has to wait out Go's 10 s `dialTimeout` (reference/kcptun/server/main.go:488).
SINK_ADDR = "198.51.100.7"
SINK_PORT = 22642

KEY = "labkey"

# `kr-pingpong ping` has **no per-request timeout**, deliberately, and that is what makes it the
# right instrument here: a request on a session whose peer has died simply hangs until smux's
# keepalive closes the session, so the gap in the CSV *is* the recovery time rather than a
# timeout the workload chose. The reconnect after an error is a fixed 250 ms pause
# (tools/pingpong/src/ping.rs), which is the resolution of the two "target unreachable" cases.
# Everything below measures that hang at one-second resolution.

#: One CSV row per second from `kr-pingpong ping`. The resolution of every recovery number here:
#: a row says how many requests completed in the second ending at its timestamp, so a recovery
#: is reported to the end of the first second that carried a success and is over-estimated by
#: less than one second, never under-estimated.
REPORT_INTERVAL = 1

#: How long the tunnel is given to come up before the workload starts.
SETTLE = 4

#: Whether the timeline is walked in real time. Always true in a real run — the offsets *are*
#: the case, and a fault injected early enough measures something else. `failure_test.py` sets
#: it false so that driving a 160-second timeline against a fake host costs no wall clock; the
#: shipped value is asserted there, so zeroing it for the suite cannot quietly become zeroing it
#: for the lab.
WAIT_FOR_EVENTS = True

#: `-snmpperiod`. 5 s so that a 45-second outage is still several records wide; the counters are
#: what say whether a *new session was dialled* (`ActiveOpens`) rather than the old one reused.
SNMP_PERIOD = 5

#: Client implementation and server implementation, as the pair code every run id carries.
PAIR_CODES = {("go", "go"): "gg", ("rust", "rust"): "rr",
              ("go", "rust"): "gr", ("rust", "go"): "rg"}


# --------------------------------------------------------------------------------------------
# Cases
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Event:
    """One scheduled intervention, `at` seconds after the workload starts."""

    at: int
    action: str
    arg: str = ""
    note: str = ""

    @property
    def label(self) -> str:
        return f"{self.action}{' ' + self.arg if self.arg else ''}"


@dataclass(frozen=True)
class Check:
    """One acceptance condition on a metric the case's CSV produced.

    `low`/`high` are inclusive bounds; either may be `None` for an open end. A metric that could
    not be computed fails the check, because "no data" is not evidence of recovery.
    """

    metric: str
    low: float | None = None
    high: float | None = None
    why: str = ""

    def evaluate(self, metrics: dict[str, Any]) -> dict[str, Any]:
        value = metrics.get(self.metric)
        ok = isinstance(value, (int, float))
        if ok and self.low is not None and value < self.low:
            ok = False
        if ok and self.high is not None and value > self.high:
            ok = False
        return {"metric": self.metric, "value": value, "low": self.low, "high": self.high,
                "why": self.why, "ok": bool(ok)}

    @property
    def bounds(self) -> str:
        if self.low is not None and self.high is not None:
            return f"{fmt(self.low)}–{fmt(self.high)}"
        if self.low is not None:
            return f"≥ {fmt(self.low)}"
        if self.high is not None:
            return f"≤ {fmt(self.high)}"
        return "any"


@dataclass(frozen=True)
class LogCheck:
    """A line both implementations must log — kcptun's messages are part of its behaviour.

    `side` is `cli` or `srv`; `count` is the minimum number of matching lines. Matched
    case-sensitively against the collected process log, because these strings are ported
    verbatim from the Go reference (docs/porting-guide.md §3) and a differing one is a finding,
    not a formatting detail.
    """

    side: str
    text: str
    count: int = 1
    #: Invert it: the line must NOT appear. `count` is then ignored. A failure mode is defined
    #: as much by the mechanism that does *not* fire as by the one that does — 11.5's own plan
    #: bullet named the wrong one, and only an absence check can say so.
    absent: bool = False
    why: str = ""


@dataclass(frozen=True)
class Case:
    """One failure mode: a timeline, the flags it needs, and what must be true afterwards."""

    name: str
    title: str
    covers: str
    duration: int
    events: tuple[Event, ...] = ()
    client_flags: dict[str, Any] = field(default_factory=dict)
    server_flags: dict[str, Any] = field(default_factory=dict)
    #: `serve` is the echo target inside kr-srv; `refused` points the tunnel at a closed port
    #: and `sink` at the blackholed address, neither of which starts a target at all.
    target: str = "serve"
    netem: str = "clean"
    ports: int = 1
    ping_size: int = 64
    ping_interval_ms: int = 200
    #: `--tcp` (fake TCP, Step 10). Both ends need raw sockets and their own `filter/OUTPUT`
    #: chain, so they are started with `lab-start.sh --root` — inside the lab namespaces, whose
    #: rulesets are their own and disappear with them.
    tcp: bool = False
    #: Pairs this case can say anything about, as pair codes. Empty means all of them.
    only_pairs: tuple[str, ...] = ()
    skip_reason: str = ""
    expect: tuple[Check, ...] = ()
    expect_log: tuple[LogCheck, ...] = ()
    #: Metrics this case publishes as extra table columns, beyond `SUMMARY_COLUMNS`, as
    #: `(metric, heading)`. A number a case is *about* belongs in its table even when it is
    #: meaningless in every other one — the ports a port-range client dialled, say.
    extra_columns: tuple[tuple[str, str], ...] = ()

    def runs_pair(self, code: str) -> bool:
        return not self.only_pairs or code in self.only_pairs

    @property
    def tunnel_spec(self) -> str:
        if self.ports == 1:
            return str(TUNNEL_PORT)
        return f"{TUNNEL_PORT}-{TUNNEL_PORT + self.ports - 1}"

    @property
    def tunnel_ports(self) -> list[int]:
        return [TUNNEL_PORT + offset for offset in range(self.ports)]

    @property
    def target_addr(self) -> str:
        if self.target == "refused":
            return f"127.0.0.1:{REFUSED_PORT}"
        if self.target == "sink":
            return f"{SINK_ADDR}:{SINK_PORT}"
        return f"127.0.0.1:{PINGPONG_PORT}"


#: The timing the recovery cases are built around, and why they are as long as they are.
#:
#: A server that dies while its session is carrying traffic is not noticed for **30 to 60
#: seconds**, never the 30 the plan first assumed. smux's `KeepAliveTimeout` is its own 30 s
#: (`-keepalive` sets only the interval), and its keepalive goroutine closes the session on the
#: first 30 s tick that finds `dataReady` clear. A tick that lands while traffic is still
#: arriving clears the flag and lets the session live, so where the death falls inside that
#: 30 s window decides the answer: immediately after a tick gives ~60 s, immediately before it
#: gives ~30 s. 09.3 measured 64.89 s (the top of the band) and corrected the plan, which had
#: said 30 s and had named the client's `re-connecting:` loop as the mechanism — it is not:
#: that loop runs only when `createConn()` fails, and dialling UDP does not fail. Recovery then
#: costs one more accepted connection, which finds `IsClosed()` and dials anew.
#:
#: Both implementations are given the same fault offset, so both see the same phase of that
#: window and the comparison is not a comparison of luck. These cases are 160 s so that a
#: recovery at the top of the band still leaves a minute of proof that traffic really resumed.
RECOVERY_DURATION = 160

CASES: tuple[Case, ...] = (
    Case(
        name="server-restart",
        title="Server restarted (SIGTERM) during traffic",
        covers="Server restart during traffic: new streams work, old streams fail cleanly.",
        duration=RECOVERY_DURATION,
        events=(
            Event(20, "stop-server", "TERM", "the server exits cleanly"),
            Event(24, "start-server", note="a new server on the same port"),
        ),
        expect=(
            Check("recovery_from_heal_s", 20, 110,
                  why="smux keepalive (30 s interval, 30 s timeout) needs one dead tick and "
                      "then one more; 09.3 measured 64.89 s"),
            Check("post_heal_requests", 100, None,
                  why="traffic really resumed, not one lucky exchange"),
            Check("post_heal_errors", 0, 3,
                  why="once a session is re-dialled the path is healthy again"),
        ),
        expect_log=(
            LogCheck("cli", "smux version: 2 on connection:", 2,
                     why="the recovery mechanism, in the client's own words: a SECOND session "
                         "is dialled (client/main.go:473)"),
            LogCheck("cli", "re-connecting:", absent=True,
                     why="the plan's bullet named this and 09.3 corrected it: that loop runs "
                         "only when `createConn()` fails, and dialling UDP does not fail — so "
                         "the line a restart is supposed to produce must not be there"),
        ),
    ),
    Case(
        name="server-sigkill",
        title="Server SIGKILLed during traffic",
        covers="SIGKILL of either end (the server half).",
        duration=RECOVERY_DURATION,
        events=(
            Event(20, "stop-server", "KILL", "no FIN, no close, nothing on the wire"),
            Event(24, "start-server"),
        ),
        expect=(
            Check("recovery_from_heal_s", 20, 110,
                  why="a killed server is indistinguishable from a blackholed one, so the "
                      "same keepalive path recovers it"),
            Check("post_heal_requests", 100, None),
        ),
        expect_log=(
            LogCheck("cli", "smux version: 2 on connection:", 2,
                     why="a killed server is recovered from by the same re-dial"),
        ),
    ),
    Case(
        name="client-sigkill",
        title="Client SIGKILLed and restarted",
        covers="SIGKILL of either end (the client half); the server replaces the session.",
        duration=90,
        events=(
            Event(20, "stop-client", "KILL"),
            Event(24, "start-client"),
        ),
        expect=(
            Check("recovery_from_heal_s", 0, 20,
                  why="the workload reconnects to the new listener at once; nothing has to "
                      "time out, because the client dials a fresh conv"),
            Check("post_heal_requests", 100, None),
        ),
    ),
    Case(
        name="blackhole",
        title="Path blackholed for 45 s (netem loss 100%)",
        covers="Blackhole the path: smux keepalive closes the session; the client re-dials "
               "when traffic resumes.",
        duration=RECOVERY_DURATION,
        events=(
            Event(20, "netem", "blackhole", "100% loss both directions"),
            Event(65, "netem", "clean", "the path comes back"),
        ),
        expect=(
            Check("outage_s", 40, None,
                  why="the 45 s blackhole must actually stop traffic"),
            Check("recovery_from_heal_s", 0, 60,
                  why="once packets flow again the session is either alive or re-dialled"),
            Check("post_heal_requests", 100, None),
        ),
    ),
    Case(
        name="autoexpire",
        title="Session rotation under load (-autoexpire 30 -scavengettl 15)",
        covers="autoexpire/scavengettl under load: rotation without dropped new streams, old "
               "sessions closed after the TTL.",
        duration=150,
        client_flags={"autoexpire": 30, "scavengettl": 15},
        expect=(
            Check("reconnects", 1, None,
                  why="the scavenger closes the expired session, which ends the stream on it — "
                      "kcptun rotates by closing, there is no stream migration"),
            Check("max_gap_s", 0, 15,
                  why="a rotation costs one reconnect, not an outage"),
            Check("requests", 300, None),
            Check("client_active_opens", 2, None,
                  why="a floor on dials, not evidence of rotation: under `conn 4` the second "
                      "accepted connection dials a second session on its own "
                      "(reference/kcptun/client/main.go:429-437 dials whenever "
                      "`muxes[idx].session == nil`). The discriminator is the TTL log check "
                      "below"),
        ),
        expect_log=(
            LogCheck("cli", "scavenger: session closed due to ttl:", 1,
                     why="reference/kcptun/client/main.go:587 — the TTL path, not the "
                         "normally-closed one. THIS is what says a rotation happened"),
        ),
    ),
    Case(
        name="portrange",
        title="Port-range server, client hopping across sessions",
        covers="A port range server with the client hopping across sessions.",
        duration=150,
        ports=TUNNEL_PORT_COUNT,
        client_flags={"autoexpire": 30, "scavengettl": 15},
        extra_columns=(("distinct_remote_ports", "ports dialled"),
                       ("remote_ports_out_of_range", "out of range")),
        expect=(
            Check("reconnects", 1, None),
            Check("max_gap_s", 0, 15,
                  why="hopping to another port of the range is not an outage"),
            Check("requests", 300, None),
            Check("client_active_opens", 2, None,
                  why="a floor on dials, not evidence of rotation: under `conn 4` the second "
                      "accepted connection dials a second session on its own "
                      "(reference/kcptun/client/main.go:429-437). The discriminator is the "
                      "TTL log check below"),
            # What makes this case a *port-range* case rather than a second `autoexpire`:
            # `createConn()` picks the port afresh out of `[MinPort, MaxPort]` on every dial
            # (reference/kcptun/client/dial.go:56-63), so a client that parsed the range but
            # always dialled `MinPort` would otherwise pass unchanged. "More than one distinct
            # port" would be flaky at four dials (1 in 64 for a four-port range); "every dial
            # inside the range" is deterministic, and `distinct_remote_ports` is reported
            # beside it so the hopping is visible in the table without being asserted.
            Check("remote_ports_out_of_range", 0, 0,
                  why=f"every dial must land inside {TUNNEL_PORT}-"
                      f"{TUNNEL_PORT + TUNNEL_PORT_COUNT - 1} "
                      "(reference/kcptun/client/dial.go:56)"),
        ),
        expect_log=(
            LogCheck("cli", "scavenger: session closed due to ttl:", 1,
                     why="reference/kcptun/client/main.go:587 — the rotation this case hops "
                         "across the range with"),
        ),
    ),
    Case(
        name="tcp-server-restart",
        title="Server restarted, `--tcp` (fake TCP) transport",
        covers="--tcp variants of restart and blackhole (the restart half).",
        duration=RECOVERY_DURATION,
        tcp=True,
        # DECISIONS V22: the **Go** `--tcp` client never carries data at all (10.5 reproduced
        # it), so a GG or GR arm of this case would measure that bug rather than a restart.
        # 10.5 owns the `--tcp` interop matrix; what 11.5 adds is what a restart does to the
        # transport and to its `filter/OUTPUT` accounting.
        only_pairs=("rr", "rg"),
        skip_reason="the Go `--tcp` client carries no data (DECISIONS V22), so a Go-client arm "
                    "would measure that and not the restart",
        events=(
            Event(20, "stop-server", "TERM"),
            Event(24, "start-server"),
        ),
        expect=(
            Check("recovery_from_heal_s", 0, 120,
                  why="fake TCP is still KCP above it, so the same keepalive path recovers it"),
            Check("post_heal_requests", 50, None),
        ),
    ),
    Case(
        name="tcp-blackhole",
        title="Path blackholed for 45 s, `--tcp` transport",
        covers="--tcp variants of restart and blackhole (the blackhole half).",
        duration=RECOVERY_DURATION,
        tcp=True,
        only_pairs=("rr", "rg"),
        skip_reason="the Go `--tcp` client carries no data (DECISIONS V22)",
        events=(
            Event(20, "netem", "blackhole"),
            Event(65, "netem", "clean"),
        ),
        expect=(
            Check("outage_s", 40, None),
            Check("recovery_from_heal_s", 0, 90),
            Check("post_heal_requests", 50, None),
        ),
        expect_log=(
            # The one place in the campaign where `re-connecting:` is the *right* answer. Over
            # UDP `createConn()` cannot fail (09.3's correction, and the absence check on
            # `server-restart` asserts it), but `--tcp` makes `dial()` do a real
            # `tcpraw.Dial()`/TCP connect (reference/kcptun/client/dial.go:67), which returns
            # ENETUNREACH while netem is dropping everything. `waitConn`
            # (reference/kcptun/client/main.go:505) then logs and retries once a second, so on
            # this transport that loop genuinely is the recovery mechanism.
            LogCheck("cli", "re-connecting: dial(): tcpraw.Dial():", 1,
                     why="fake TCP is the one transport whose `createConn()` can fail, and the "
                         "wrap chain is Go's own (client/dial.go:67, client/main.go:505)"),
        ),
    ),
    Case(
        name="target-refused",
        title="Target refuses the connection",
        covers="Target unreachable: the stream closes and the client sees EOF.",
        duration=45,
        target="refused",
        expect=(
            Check("requests", 0, 0, why="nothing can be echoed: there is no target"),
            Check("errors", 20, None,
                  why="every attempt fails, and fails fast — an RST is not a timeout"),
            Check("median_error_interval_s", 0, 2,
                  why="a refused dial returns immediately; the 250 ms reconnect pause is the "
                      "only delay"),
        ),
    ),
    Case(
        name="target-blackholed",
        title="Target address blackholed (Go's 10 s dialTimeout)",
        covers="Target unreachable: dial fails after 10 s and the stream closes.",
        duration=75,
        target="sink",
        expect=(
            Check("requests", 0, 0),
            Check("errors", 2, None),
            Check("median_error_interval_s", 8, 14,
                  why="reference/kcptun/server/main.go:488 `const dialTimeout = 10 * "
                      "time.Second`, plus the workload's 250 ms pause"),
        ),
    ),
)

CASES_BY_NAME = {case.name: case for case in CASES}


# --------------------------------------------------------------------------------------------
# One case, one implementation pair
# --------------------------------------------------------------------------------------------


class CaseRun:
    """Starts, drives and stops one (case, pair) run, and returns the state it produced."""

    def __init__(self, runner: Runner, case: Case, client_impl: str, server_impl: str,
                 *, config: str, stamp: str) -> None:
        self.runner = runner
        self.case = case
        self.client_impl = client_impl
        self.server_impl = server_impl
        self.config = config
        self.pair = PAIR_CODES[(client_impl, server_impl)]
        self.runid = f"f-{case.name}-{self.pair}-{stamp}"
        #: Every process this run has started, newest last. Restarting an end starts a *new*
        #: name rather than reusing the old one: `lab-start.sh` truncates `logs/<name>.log`, so
        #: reusing it would throw away the log of everything before the fault — which is the
        #: half that says how the tunnel behaved while it was healthy.
        self.names: list[str] = []
        self.generation = {"srv": 0, "cli": 0}
        self.events: list[dict[str, Any]] = []
        self.netem = case.netem

    # -- names and command lines -------------------------------------------------------------

    @property
    def remote_dir(self) -> str:
        return f"{LAB}/logs/{self.runid}"

    def name(self, role: str, generation: int | None = None) -> str:
        if generation is None:
            generation = self.generation[role]
        return f"{self.runid}-{role}{generation}"

    @staticmethod
    def snmp_suffix(generation: int) -> str:
        """A generation as a **letter**, because `-snmplog` is a Go time layout.

        kcptun formats the file part of `-snmplog` through `time.Now().Format` so that
        `-snmplog snmp-20060102.csv` rotates daily (reference/kcptun/std/snmp.go:56, and
        crates/std/src/snmp.rs faithfully). A digit in that name is therefore not a digit: on
        2026-09-25 a run asking for `snmp-srv1.csv` got `snmp-srv9.csv` (layout `1` = month) and
        one asking for `snmp-srv2.csv` got `snmp-srv25.csv` (layout `2` = day) — two files whose
        alphabetical order is the reverse of their generation order. Letters carry no layout
        meaning, so `a`, `b`, `c` survive the formatting unchanged.
        """
        return chr(ord("a") + generation - 1)

    @property
    def target_name(self) -> str:
        return f"{self.runid}-tgt"

    @property
    def workload_name(self) -> str:
        return f"{self.runid}-w"

    def flags(self, side: str) -> list[str]:
        base = lab.CONFIGS[self.config]
        merged: dict[str, Any] = dict(base["common"])
        merged.update(base[side])
        merged.update(self.case.client_flags if side == "client" else self.case.server_flags)
        return lab.render_flags(merged)

    def target_argv(self) -> list[str]:
        return [
            f"{LAB}/bin/lab/kr-pingpong", "serve",
            "--listen", f"127.0.0.1:{PINGPONG_PORT}",
            # Outlive the workload: a target that stopped first would look like a failure the
            # case did not inject.
            "--duration", str(self.case.duration + SETTLE + 90),
            "--report-interval", "30",
        ]

    def server_argv(self, generation: int) -> list[str]:
        return [
            lab.binary(self.server_impl, "server"),
            "-l", f":{self.case.tunnel_spec}",
            "-t", self.case.target_addr,
            "-key", KEY,
            *(["-tcp"] if self.case.tcp else []),
            *self.flags("server"),
            "-snmplog", f"{self.remote_dir}/snmp-srv-{self.snmp_suffix(generation)}.csv",
            "-snmpperiod", str(SNMP_PERIOD),
        ]

    def client_argv(self, generation: int) -> list[str]:
        return [
            lab.binary(self.client_impl, "client"),
            "-l", f"127.0.0.1:{LISTEN_PORT}",
            "-r", f"{lab.SERVER_IP}:{self.case.tunnel_spec}",
            "-key", KEY,
            *(["-tcp"] if self.case.tcp else []),
            *self.flags("client"),
            "-snmplog", f"{self.remote_dir}/snmp-cli-{self.snmp_suffix(generation)}.csv",
            "-snmpperiod", str(SNMP_PERIOD),
        ]

    def workload_argv(self) -> list[str]:
        return [
            f"{LAB}/bin/lab/kr-pingpong", "ping",
            "--connect", f"127.0.0.1:{LISTEN_PORT}",
            "--size", str(self.case.ping_size),
            "--interval-ms", str(self.case.ping_interval_ms),
            "--duration", str(self.case.duration),
            # No warm-up: the percentiles are not the point here, and a warm-up would drop the
            # very first seconds, which are the control every recovery is measured against.
            "--warmup", "0",
            "--report-interval", str(REPORT_INTERVAL),
            "--tag", "lat",
            "--out", f"{self.remote_dir}/ping-lat.csv",
        ]

    # -- the timeline --------------------------------------------------------------------------

    def start_end(self, role: str) -> None:
        """Starts the next generation of one tunnel end."""
        self.generation[role] += 1
        generation = self.generation[role]
        name = self.name(role, generation)
        argv = (self.server_argv(generation) if role == "srv"
                else self.client_argv(generation))
        netns = lab.NS_SERVER if role == "srv" else lab.NS_CLIENT
        if self.case.tcp:
            # `--root` rather than `Runner.start`: tcpraw needs raw sockets and manages its own
            # `filter/OUTPUT` rules, which an unprivileged process cannot do. `lab-start.sh`
            # allows it only inside a lab namespace.
            self.runner.lab("start", "--netns", netns, "--root", name, "--", *argv)
        else:
            self.runner.start(name, argv, netns=netns)
        self.names.append(name)

    def stop_end(self, role: str, sig: str) -> None:
        """Stops the current generation of one end, by PID file, with `sig`."""
        name = self.name(role)
        self.runner.lab("stop", "--signal", sig, name, check=False)

    def apply(self, event: Event) -> None:
        if event.action == "stop-server":
            self.stop_end("srv", event.arg or "TERM")
        elif event.action == "start-server":
            self.start_end("srv")
        elif event.action == "stop-client":
            self.stop_end("cli", event.arg or "TERM")
        elif event.action == "start-client":
            self.start_end("cli")
        elif event.action == "netem":
            self.runner.lab("netns", "set", event.arg)
            self.netem = event.arg
        else:
            raise LabError(f"case {self.case.name}: unknown action {event.action!r}")

    def stop_everything(self) -> None:
        """Stops every process this run started, in any state — the Ctrl-C path too."""
        self.runner.stop([*reversed(self.names), self.target_name])
        self.restore_environment()

    def restore_environment(self) -> None:
        """Puts the namespaces back the way the next run — or the operator — expects them.

        Stopping the processes is not enough: a `blackhole` case interrupted inside its fault
        window would otherwise leave both namespaces at `loss 100%`, which is self-healing on
        the next driver run but is not a state anyone would expect to come back to.
        """
        if self.netem != self.case.netem:
            self.runner.lab("netns", "set", self.case.netem, check=False)
            self.netem = self.case.netem
        if self.case.target == "sink":
            self.runner.lab("netns", "sink", "down", check=False)

    # -- running -------------------------------------------------------------------------------

    def run(self, provenance: lab.BuildProvenance) -> dict[str, Any]:
        case = self.case
        runner = self.runner
        # Provenance before anything is started, on the same terms `lab.py` uses: a failure
        # mode that "matches Go" is a statement about two binaries, so both have to be nameable.
        client_stamp = provenance.require(runner, self.client_impl, "client")
        server_stamp = provenance.require(runner, self.server_impl, "server")
        # `kr-labsample` is deliberately NOT required: no failure case starts a sampler, and
        # `lab.artefact_path` hashes it separately from `kr-pingpong` even though the two share
        # one BUILD.txt — so requiring it would refuse a run over a binary the run never
        # executes. `kr-pingpong` (the `target` stamp) is required, because it is both the echo
        # target and the workload, and every number here is arithmetic over its CSV.
        target_stamp = provenance.require(runner, "lab", "target")

        runner.lab("collect", self.runid)
        lab.ensure_netns(runner, case.netem)
        if case.target == "sink":
            runner.lab("netns", "sink", "up")
        if case.target == "serve":
            runner.start(self.target_name, self.target_argv(), netns=lab.NS_SERVER)
        self.start_end("srv")
        self.start_end("cli")
        if not runner.dry_run:
            time.sleep(SETTLE)

        started_at = time.time()
        runner.start(self.workload_name, self.workload_argv(), netns=lab.NS_CLIENT)
        self.names.append(self.workload_name)
        for event in case.events:
            if WAIT_FOR_EVENTS and not runner.dry_run:
                delay = started_at + event.at - time.time()
                if delay > 0:
                    time.sleep(delay)
            self.apply(event)
            self.events.append({
                "at": event.at,
                "unix": time.time(),
                "action": event.action,
                "arg": event.arg,
                "note": event.note,
                "label": event.label,
            })
            print(f"    t+{event.at:>3}s  {event.label}"
                  f"{'  — ' + event.note if event.note else ''}")

        # The ssh that waits must outlast the wait itself: `Runner.lab` defaults to a
        # two-minute ssh timeout, which is shorter than every recovery case here, and a timeout
        # there raises rather than returning — it aborted a 16-run campaign at the first case.
        wait_seconds = case.duration + 90
        finished = runner.lab("wait", "--timeout", str(wait_seconds), self.workload_name,
                              check=False, timeout=wait_seconds + 120)
        if not finished.ok:
            print(f"lab: {self.runid}: the workload did not finish cleanly; collecting anyway",
                  file=sys.stderr)

        # SIGUSR1 both live ends for the SNMP dump, exactly as `lab.py finish_run` does.
        runner.lab("signal", "USR1", self.name("cli"), self.name("srv"), check=False)
        if lab.SNMP_SETTLE_SECONDS and not runner.dry_run:
            time.sleep(lab.SNMP_SETTLE_SECONDS)
        uptime_after = runner.uptime()
        # `stop_everything` also calls `restore_environment`: the namespaces go back to the
        # profile the next case expects to find, and the sink route goes down.
        self.stop_everything()
        runner.lab("collect", self.runid, *self.names, self.target_name)

        return {
            "runid": self.runid,
            "case": case.name,
            "title": case.title,
            "covers": case.covers,
            "config": self.config,
            "netem": case.netem,
            "target": case.target,
            "target_addr": case.target_addr,
            "tunnel": case.tunnel_spec,
            "client_impl": self.client_impl,
            "server_impl": self.server_impl,
            "pair": self.pair,
            "host": self.runner.host,
            "build": client_stamp.summary,
            "server_build": server_stamp.summary,
            "client_build_detail": client_stamp.as_state(),
            "server_build_detail": server_stamp.as_state(),
            "target_build_detail": target_stamp.as_state(),
            "socket_buffer_limits": {self.runner.host: runner.socket_buffer_limits()},
            "duration": case.duration,
            "started_unix": started_at,
            "started_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started_at)),
            "uptime_after": uptime_after,
            "events": self.events,
            "names": self.names,
            "client_argv": self.client_argv(self.generation["cli"]),
            "server_argv": self.server_argv(self.generation["srv"]),
            "workload_argv": self.workload_argv(),
            "remote_dir": self.remote_dir,
        }


# --------------------------------------------------------------------------------------------
# Reading a run back
# --------------------------------------------------------------------------------------------


@dataclass
class Sample:
    """One second of the workload's CSV, with the deltas that second contributed."""

    unix: float
    elapsed: float
    requests: int
    errors: int
    reconnects: int
    d_requests: int = 0
    d_errors: int = 0
    d_reconnects: int = 0


def samples(directory: Path) -> list[Sample]:
    """The workload CSV as a series of per-interval deltas.

    The CSV's `requests`, `errors` and `reconnects` are cumulative (they are the worker's
    running totals, not the interval's), so every question this file asks — when did traffic
    stop, when did it come back, how long was the longest gap — is a question about the
    differences between consecutive rows.
    """
    header, rows = lab.read_csv(directory / "ping-lat.csv")
    if not header:
        return []
    index = {name: position for position, name in enumerate(header)}
    needed = ("unix", "elapsed_s", "requests", "errors", "reconnects")
    if any(name not in index for name in needed):
        return []
    out: list[Sample] = []
    for row in rows:
        try:
            sample = Sample(
                unix=float(row[index["unix"]]),
                elapsed=float(row[index["elapsed_s"]]),
                requests=int(row[index["requests"]]),
                errors=int(row[index["errors"]]),
                reconnects=int(row[index["reconnects"]]),
            )
        except (IndexError, ValueError):
            continue
        if out:
            previous = out[-1]
            sample.d_requests = sample.requests - previous.requests
            sample.d_errors = sample.errors - previous.errors
            sample.d_reconnects = sample.reconnects - previous.reconnects
        else:
            sample.d_requests = sample.requests
            sample.d_errors = sample.errors
            sample.d_reconnects = sample.reconnects
        out.append(sample)
    return out


def snmp_last(directory: Path, prefix: str) -> dict[str, int]:
    """The last SNMP record of the newest generation of one end.

    A restarted end writes its own `snmp-srv-b.csv`; the counters restart with the process, so
    the answer to "did a new session get dialled after the restart" is in the *new* file, and
    reading the old one would answer a question about the run before the fault.
    """
    # Newest **by modification time**, not by name: the generation suffix is a letter now
    # (`CaseRun.snmp_suffix`), but a session collected before that fix has Go-layout-mangled
    # names whose alphabetical order is meaningless, and the file the running process is still
    # appending to is the newest one either way.
    files = sorted(directory.glob(f"snmp-{prefix}*.csv"),
                   key=lambda path: (path.stat().st_mtime, path.name))
    for path in reversed(files):
        header, rows = lab.read_csv(path)
        if not header or not rows:
            continue
        values: dict[str, int] = {}
        for name, cell in zip(header, rows[-1]):
            try:
                values[name] = int(cell)
            except ValueError:
                continue
        if values:
            return values
    return {}


def result_line(directory: Path, name: str) -> dict[str, Any]:
    """The workload's machine-readable `RESULT {...}` line, or `{}`."""
    path = directory / f"{name}.log"
    if not path.exists():
        return {}
    for line in reversed(path.read_text(encoding="utf-8", errors="replace").splitlines()):
        if line.startswith("RESULT "):
            try:
                return json.loads(line[len("RESULT "):])
            except json.JSONDecodeError:
                return {}
    return {}


def log_hits(directory: Path, state: dict[str, Any], side: str, text: str) -> int:
    """How many times `text` appears in one end's logs, across every generation of it."""
    total = 0
    for name in state.get("names", []):
        if not name.endswith(tuple(f"-{side}{n}" for n in range(1, 10))):
            continue
        path = directory / f"{name}.log"
        if not path.exists():
            continue
        total += path.read_text(encoding="utf-8", errors="replace").count(text)
    return total


def log_lines(directory: Path, state: dict[str, Any], side: str) -> list[str]:
    """Every line one end logged, oldest generation first."""
    lines: list[str] = []
    for name in state.get("names", []):
        if not name.endswith(tuple(f"-{side}{n}" for n in range(1, 10))):
            continue
        path = directory / f"{name}.log"
        if path.exists():
            lines += path.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines


#: `smux version: 2 on connection: <local> -> <remote>` — the client naming the peer of the
#: session it has just dialled (reference/kcptun/client/main.go:473). It is the only record a
#: run keeps of *which* port of a `-r` range a session went to, and `createConn()` picks that
#: port afresh per dial (reference/kcptun/client/dial.go:56-63).
CONNECTION_RE = re.compile(r"on connection:\s+\S+\s+->\s+(\S+)")


def dialled_ports(directory: Path, state: dict[str, Any]) -> list[int]:
    """The remote port of every session the client dialled, in the order it logged them."""
    ports: list[int] = []
    for line in log_lines(directory, state, "cli"):
        match = CONNECTION_RE.search(line)
        if not match:
            continue
        try:
            ports.append(int(match.group(1).rsplit(":", 1)[-1]))
        except ValueError:
            continue
    return ports


def tunnel_ports(state: dict[str, Any]) -> list[int]:
    """The `-r` range the run was given, as the ports it spans (`"29904-29907"`)."""
    low, _, high = str(state.get("tunnel", "")).partition("-")
    try:
        first = int(low)
        last = int(high) if high else first
    except ValueError:
        return []
    return list(range(first, last + 1)) if last >= first else []


def row_interval(series: Sequence[Sample]) -> float:
    """How much time one row of the workload CSV covers, measured from the rows themselves.

    `REPORT_INTERVAL` is what was asked for; this is what arrived, which on a loaded 1-vCPU box
    is not always the same thing (the reporter uses `MissedTickBehavior::Delay`).
    """
    if len(series) < 3:
        return float(REPORT_INTERVAL)
    steps = [second.unix - first.unix for first, second in zip(series, series[1:])]
    return statistics.median(steps) or float(REPORT_INTERVAL)


def metrics(state: dict[str, Any], directory: Path) -> dict[str, Any]:
    """Everything a check can be written against, derived from one run's collected files."""
    series = samples(directory)
    events = state.get("events", [])
    first_fault = events[0]["unix"] if events else None
    last_event = events[-1]["unix"] if events else None
    result = result_line(directory, state.get("runid", "") + "-w")

    ok_times = [s.unix for s in series if s.d_requests > 0]
    # One row covers the interval *ending* at its timestamp, so a row whose interval straddles
    # the fault reports requests that completed before it. Counting that row as "after" made a
    # SIGKILL look like a one-second outage while the same run's longest gap was forty. A
    # second is therefore only "after" an event when the whole second is after it, which can
    # over-state a recovery by one interval and can never under-state an outage.
    step = row_interval(series)
    out: dict[str, Any] = {
        "intervals": len(series),
        "requests": result.get("requests", series[-1].requests if series else None),
        "errors": result.get("errors", series[-1].errors if series else None),
        "reconnects": result.get("reconnects", series[-1].reconnects if series else None),
        # `kr-pingpong` reports its percentiles in microseconds, named `rtt_<pct>_us`
        # (tools/pingpong/src/hist.rs `json_fields`).
        "rtt_p50_ms": (round(result["rtt_p50_us"] / 1000.0, 2)
                       if result.get("rtt_p50_us") else None),
        "rtt_max_ms": (round(result["rtt_max_us"] / 1000.0, 2)
                       if result.get("rtt_max_us") else None),
    }

    # The longest run of consecutive seconds with no completed request, after the first one that
    # completed. Before the first success there is only start-up, which is not a gap.
    if len(ok_times) >= 2:
        gaps = [second - first for first, second in zip(ok_times, ok_times[1:])]
        out["max_gap_s"] = round(max(gaps), 1)
    elif ok_times:
        out["max_gap_s"] = 0.0

    if first_fault is not None:
        before = [t for t in ok_times if t <= first_fault]
        after = [t for t in ok_times if t >= first_fault + step]
        if before and after:
            out["outage_s"] = round(after[0] - before[-1], 1)
        out["recovery_from_fault_s"] = round(after[0] - first_fault, 1) if after else None
    if last_event is not None:
        after_heal = [t for t in ok_times if t >= last_event + step]
        out["recovery_from_heal_s"] = (round(after_heal[0] - last_event, 1)
                                       if after_heal else None)
        healed = [s for s in series if s.unix >= last_event + step]
        out["post_heal_requests"] = sum(s.d_requests for s in healed)
        # Errors *after* the first post-heal success: the ones during the recovery itself are
        # the failure mode, not a defect.
        if after_heal:
            out["post_heal_errors"] = sum(s.d_errors for s in series if s.unix > after_heal[0])

    # How long one failed attempt takes, which is what separates a refused dial (immediate RST)
    # from an unreachable one (Go's 10 s `dialTimeout`). Measured between the seconds in which
    # the error counter moved, weighted by how many errors each carried.
    # The **median** spacing, not the mean: an RST storm puts many errors in one second and a
    # few gaps between bursts, and a mean of that is pulled towards the gaps until it is no
    # longer distinguishable from a 10 s dialTimeout. The median is the typical attempt.
    error_times = [s.unix for s in series for _ in range(max(0, s.d_errors))]
    if len(error_times) >= 3:
        spacing = [second - first for first, second in zip(error_times, error_times[1:])]
        out["median_error_interval_s"] = round(statistics.median(spacing), 2)

    # Where the client's sessions went, which is the whole of the port-range case: a client
    # that parsed `-r host:29904-29907` but always dialled 29904 is indistinguishable from a
    # correct one on every other metric here.
    ports = dialled_ports(directory, state)
    allowed = set(tunnel_ports(state))
    out["distinct_remote_ports"] = len(set(ports))
    #: `None`, not `0`, when the run did not record its `-r` range: "no data" must fail the
    #: check rather than pass it (the same rule `Check.evaluate` applies to every metric).
    out["remote_ports_out_of_range"] = (
        sum(1 for port in ports if port not in allowed) if allowed else None)

    # `re-connecting:` is reported on every run, not only checked where it is expected. Over
    # UDP `createConn()` cannot fail, so the count is 0 and `server-restart` asserts that as an
    # absence; under `--tcp` the dial is a real TCP connect and the count is the number of
    # times `waitConn` retried. Publishing it as a column is what makes the two transports'
    # different mechanisms visible side by side rather than something a reader must grep for.
    out["client_re_connecting"] = log_hits(directory, state, "cli", "re-connecting:")

    client_snmp = snmp_last(directory, "cli")
    server_snmp = snmp_last(directory, "srv")
    out["client_active_opens"] = client_snmp.get("ActiveOpens")
    out["client_curr_estab"] = client_snmp.get("CurrEstab")
    out["server_passive_opens"] = server_snmp.get("PassiveOpens")
    out["server_curr_estab"] = server_snmp.get("CurrEstab")
    return out


def verdict(case: Case, state: dict[str, Any], values: dict[str, Any],
            directory: Path) -> dict[str, Any]:
    """Every check of one case against one run: the pass/fail rows and the overall answer."""
    rows = [check.evaluate(values) for check in case.expect]
    for check in case.expect_log:
        hits = log_hits(directory, state, check.side, check.text)
        rows.append({
            "metric": f"log[{check.side}] {check.text!r}",
            "value": hits,
            "low": None if check.absent else check.count,
            "high": 0 if check.absent else None,
            "why": check.why,
            "ok": hits == 0 if check.absent else hits >= check.count,
        })
    return {"checks": rows, "ok": all(row["ok"] for row in rows),
            "errors": lab.scan_logs(directory)}


# --------------------------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------------------------


def fmt(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.1f}" if abs(value) >= 0.1 or value == 0 else f"{value:.2f}"
    return str(value)


#: The columns of the summary table, in order: what the metric is called in `metrics` and how
#: the report heads it.
SUMMARY_COLUMNS = (
    ("recovery_from_heal_s", "recovery s"),
    ("outage_s", "outage s"),
    ("max_gap_s", "max gap s"),
    ("requests", "requests"),
    ("rtt_p50_ms", "p50 ms"),
    ("errors", "errors"),
    ("reconnects", "reconn"),
    ("client_re_connecting", "re-connecting"),
    ("client_active_opens", "cli ActiveOpens"),
    ("server_passive_opens", "srv PassiveOpens"),
)


def report(states: Sequence[dict[str, Any]], directories: Sequence[Path]) -> str:
    """One Markdown document for a whole campaign: a table per case, Go beside Rust."""
    lines: list[str] = ["# Step 11.5 — failure-mode behaviour, Go vs Rust", ""]
    if states:
        first = states[0]
        # Every distinct artefact the session used, not the first run's two: a campaign that
        # interleaves GG and RR executes four different binaries, and naming only one pair's is
        # how 11.3 came to publish numbers nobody could attribute (12.0).
        artefacts: dict[str, str] = {}
        for state in states:
            artefacts.setdefault(f"{state['client_impl']} client", state.get("build", "?"))
            artefacts.setdefault(f"{state['server_impl']} server",
                                 state.get("server_build", "?"))
        lines += [
            f"Host `{first['host']}`, netns lab, config **{first['config'].upper()}**, "
            f"{len(states)} runs.",
            "",
            *(f"- {role}: {summary}" for role, summary in sorted(artefacts.items())),
            "",
        ]
    lines += lab.unprovenanced_banner(list(states))

    by_case: dict[str, list[tuple[dict[str, Any], Path]]] = {}
    for state, directory in zip(states, directories):
        by_case.setdefault(state["case"], []).append((state, directory))

    overall: list[str] = []
    # In the order the cases are declared, not the order the run directories sort in: the table
    # of a campaign should read like the plan's bullet list, and an alphabetical `client-…`
    # before `server-…` is the order of nothing.
    for case in CASES:
        runs = by_case.get(case.name)
        if not runs:
            continue
        name = case.name
        lines += [f"## {case.title}", "", f"*{case.covers}*", ""]
        if case.events:
            lines.append("Timeline: " + ", ".join(
                f"t+{event.at}s {event.label}" for event in case.events) + ".")
            lines.append("")
        if case.only_pairs:
            lines += [f"Runs only as {', '.join(code.upper() for code in case.only_pairs)}: "
                      f"{case.skip_reason}", ""]
        columns = (*SUMMARY_COLUMNS, *case.extra_columns)
        head = "| pair | " + " | ".join(label for _, label in columns) + " | verdict |"
        lines += [head, "|" + "---|" * (len(columns) + 2)]
        details: list[str] = []
        for state, directory in runs:
            values = metrics(state, directory)
            answer = verdict(case, state, values, directory)
            row = [state["pair"].upper()]
            row += [fmt(values.get(metric)) for metric, _ in columns]
            row.append("PASS" if answer["ok"] else "**FAIL**")
            lines.append("| " + " | ".join(row) + " |")
            overall.append(f"{name}/{state['pair']}: "
                           f"{'PASS' if answer['ok'] else 'FAIL'}")
            for check in answer["checks"]:
                mark = "ok" if check["ok"] else "**FAIL**"
                want = Check(check["metric"], check["low"], check["high"]).bounds
                details.append(f"- `{state['pair'].upper()}` {check['metric']} = "
                               f"{fmt(check['value'])} (want {want}) {mark}"
                               + (f" — {check['why']}" if check["why"] else ""))
            for note in answer["errors"]:
                details.append(f"- `{state['pair'].upper()}` log marker: {note}")
        lines += ["", *details, ""]

    failures = [line for line in overall if "FAIL" in line]
    lines += ["## Verdict", "",
              f"{len(overall) - len(failures)} of {len(overall)} runs met every check.", ""]
    if failures:
        lines += ["Failed:", "", *(f"- {line}" for line in failures), ""]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------------------------


def selected_cases(names: Sequence[str]) -> list[Case]:
    if not names:
        return list(CASES)
    chosen: list[Case] = []
    for name in names:
        if name not in CASES_BY_NAME:
            raise LabError(f"unknown case {name!r}; known: "
                           + ", ".join(sorted(CASES_BY_NAME)))
        chosen.append(CASES_BY_NAME[name])
    return chosen


def selected_pairs(spec: str) -> list[tuple[str, str]]:
    """`gg,rr` → the implementation pairs, in the order given (the order they will interleave)."""
    codes = {code: pair for pair, code in PAIR_CODES.items()}
    pairs: list[tuple[str, str]] = []
    for item in spec.split(","):
        item = item.strip().lower()
        if item not in codes:
            raise LabError(f"unknown pair {item!r}; want one or more of "
                           + ", ".join(sorted(codes)))
        pairs.append(codes[item])
    return pairs


def cmd_cases(_runner: Runner, args: argparse.Namespace) -> int:
    del args
    for case in CASES:
        only = (f"  [{', '.join(code.upper() for code in case.only_pairs)} only]"
                if case.only_pairs else "")
        print(f"{case.name:18} {case.duration:>4}s  {case.title}{only}")
        print(f"{'':18} {'':>5} {case.covers}")
    total = sum(case.duration + SETTLE + 20 for case in CASES)
    print(f"\n{len(CASES)} cases, about {total // 60} min per implementation pair.")
    return 0


def cmd_run(runner: Runner, args: argparse.Namespace) -> int:
    cases = selected_cases(args.case)
    pairs = selected_pairs(args.pairs)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    session = Path(args.runs_dir).expanduser().resolve() / f"{stamp}-failure"

    provenance = lab.BuildProvenance(allow_unprovenanced=args.allow_unprovenanced)
    for client_impl, server_impl in pairs:
        provenance.require(runner, client_impl, "client")
        provenance.require(runner, server_impl, "server")
    # `kr-pingpong` only: no failure case starts `kr-labsample` (see `CaseRun.run`).
    provenance.require(runner, "lab", "target")

    ports = sorted({*range(TUNNEL_PORT, TUNNEL_PORT + TUNNEL_PORT_COUNT),
                    LISTEN_PORT, PINGPONG_PORT})
    checks = lab.preflight(runner, max_load=args.max_load, wait_seconds=args.wait_load,
                           force=args.force, ports=ports)
    print(f"lab: preflight — {checks}")
    if not runner.dry_run:
        session.mkdir(parents=True, exist_ok=True)

    plan = []
    for case in cases:
        for pair in pairs:
            code = PAIR_CODES[pair]
            if case.runs_pair(code):
                plan.append((case, pair))
            else:
                print(f"lab: skipping {case.name}/{code} — {case.skip_reason}")
    print(f"lab: {len(plan)} run(s) over {len(cases)} case(s) -> {session}")

    states: list[dict[str, Any]] = []
    directories: list[Path] = []
    current: CaseRun | None = None

    def emergency_stop(*_ignored: Any) -> None:
        if current is not None:
            print("\nlab: interrupted — stopping this run's processes", file=sys.stderr)
            current.stop_everything()
        raise SystemExit(130)

    previous = signal.signal(signal.SIGINT, emergency_stop)
    try:
        for case, (client_impl, server_impl) in plan:
            run = CaseRun(runner, case, client_impl, server_impl,
                          config=args.config, stamp=stamp)
            current = run
            print(f"lab: {run.runid} ({client_impl} client -> {server_impl} server, "
                  f"{case.duration}s)")
            state = run.run(provenance)
            local_dir = session / run.runid
            if not runner.dry_run:
                local_dir.mkdir(parents=True, exist_ok=True)
                runner.fetch_dir(run.remote_dir, local_dir)
                (local_dir / "state.json").write_text(json.dumps(state, indent=2) + "\n")
                values = metrics(state, local_dir)
                answer = verdict(case, state, values, local_dir)
                print(f"    {'PASS' if answer['ok'] else 'FAIL'}: "
                      + ", ".join(f"{metric}={fmt(values.get(metric))}"
                                  for metric, _ in (*SUMMARY_COLUMNS, *case.extra_columns)
                                  if values.get(metric) is not None))
                for check in answer["checks"]:
                    if not check["ok"]:
                        want = Check(check["metric"], check["low"], check["high"]).bounds
                        print(f"      FAIL {check['metric']} = {fmt(check['value'])} "
                              f"(want {want})")
            states.append(state)
            directories.append(local_dir)
            current = None
    finally:
        signal.signal(signal.SIGINT, previous)
        if current is not None:
            current.stop_everything()

    if states and not args.no_report and not runner.dry_run:
        text = report(states, directories)
        (session / "report.md").write_text(text)
        print(f"lab: report -> {session / 'report.md'}")
    return 0


def resolve_session(root: Path, spec: str) -> Path:
    """One session directory, given either its path or a unique substring of its name."""
    candidate = Path(spec)
    if candidate.is_dir():
        return candidate
    matches = sorted(path for path in root.glob(f"*{spec}*") if path.is_dir())
    if len(matches) != 1:
        raise LabError(f"{spec!r} matches {len(matches)} sessions under {root}")
    return matches[0]


def cmd_report(_runner: Runner, args: argparse.Namespace) -> int:
    root = Path(args.runs_dir).expanduser().resolve()
    # **Several** sessions, concatenated: a campaign is not always one `run` invocation. 11.5's
    # eight two-arm cases and its two `--tcp` RR-only cases were run separately (the `--tcp`
    # ones need `--pairs rr`), so the published document covers two session directories, and a
    # report command that took one could only be followed by moving directories around by hand.
    # `report` groups by case name regardless of which session a run came from.
    directories: list[Path] = []
    for spec in args.session:
        session = resolve_session(root, spec)
        found = sorted(path.parent for path in session.glob("*/state.json"))
        if not found:
            raise LabError(f"{session} holds no collected runs")
        directories += found
    states = [json.loads((path / "state.json").read_text()) for path in directories]
    text = report(states, directories)
    if args.out:
        Path(args.out).write_text(text)
        print(f"lab: report -> {args.out}")
    else:
        print(text)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Step 11.5 failure-mode runs against both implementations")
    parser.add_argument("--host", default=lab.DEFAULT_HOST,
                        help="ssh alias of the lab host (default %(default)s)")
    parser.add_argument("--runs-dir", default=str(lab.REPO / "lab-runs"),
                        help="where raw run output is kept (default %(default)s)")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the commands instead of running them")
    parser.add_argument("-v", "--verbose", action="store_true", help="echo every command")
    sub = parser.add_subparsers(dest="command", required=True)

    cases = sub.add_parser("cases", help="list the failure modes and what they cost")
    cases.set_defaults(func=cmd_cases)

    run = sub.add_parser("run", help="run the cases against both implementations")
    run.add_argument("--case", action="append", default=[],
                     help="run only this case (repeatable)")
    run.add_argument("--pairs", default="gg,rr",
                     help="implementation pairs, client:server coded as in lab.py "
                          "(default %(default)s)")
    run.add_argument("--config", default="s1", choices=sorted(lab.CONFIGS),
                     help="flag set from step 11.2 (default %(default)s)")
    run.add_argument("--max-load", type=float, default=1.0,
                     help="refuse to start above this load average (default %(default)s)")
    run.add_argument("--wait-load", type=int, default=0,
                     help="seconds to wait for the load to fall before refusing")
    run.add_argument("--force", action="store_true", help="run even above --max-load")
    run.add_argument("--allow-unprovenanced", action="store_true",
                     help="run with an unidentifiable binary, marking every report")
    run.add_argument("--no-report", action="store_true", help="collect without writing a report")
    run.set_defaults(func=cmd_run)

    rep = sub.add_parser("report", help="rebuild the report of one or more collected sessions")
    rep.add_argument("session", nargs="+",
                     help="session directories under --runs-dir, or unique substrings of "
                          "their names; several are concatenated into one document")
    rep.add_argument("--out", help="write here instead of standard output")
    rep.set_defaults(func=cmd_report)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    runner = Runner(args.host, dry_run=args.dry_run, verbose=args.verbose)
    try:
        return int(args.func(runner, args))
    except LabError as error:
        print(f"lab: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
