#!/usr/bin/env python3
"""Tests for tools/lab/failure.py. Run with `python3 tools/lab/failure_test.py`.

`failure.py` is the only thing in the lab that deliberately kills a running tunnel, and the
answers it produces — "recovery took 57 s", "the stream never came back" — are read off a CSV by
arithmetic nobody eyeballs. Both halves need a test that does not need a lab host:

* the **timeline**, because an event that fires against the wrong process name, or a restart
  that reuses a log file, destroys the evidence of a run that took three minutes to produce;
* the **arithmetic**, because a recovery number computed from cumulative counters as if they
  were per-interval ones is wrong in a way that still looks plausible.

The host is `lab_test.FakeRunner` — the same fake ssh `lab_test.py` uses, so a change to the
guarded helpers' interface breaks both suites at once rather than only the one that is run.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import failure  # noqa: E402  (the import needs the path above)
import lab  # noqa: E402
import lab_test  # noqa: E402  (FakeRunner, and the stamps that make a host provenanced)

REPO = Path(__file__).resolve().parents[2]

#: `CaseRun.run` sleeps `SETTLE` seconds and then once per event. A test that drives a real
#: timeline would pay all of it, so the module's two waits are zeroed for the suite and the
#: shipped values are asserted below — zeroing them here must never become zeroing them in a
#: real run.
_REAL_SETTLE = failure.SETTLE
_REAL_SNMP_SETTLE = lab.SNMP_SETTLE_SECONDS
_REAL_WAIT_FOR_EVENTS = failure.WAIT_FOR_EVENTS


def setUpModule() -> None:
    failure.SETTLE = 0
    failure.WAIT_FOR_EVENTS = False
    lab.SNMP_SETTLE_SECONDS = 0


def tearDownModule() -> None:
    failure.SETTLE = _REAL_SETTLE
    failure.WAIT_FOR_EVENTS = _REAL_WAIT_FOR_EVENTS
    lab.SNMP_SETTLE_SECONDS = _REAL_SNMP_SETTLE


def ping_csv(rows: list[tuple[float, int, int, int]]) -> str:
    """A `kr-pingpong ping` interval CSV from `(unix, requests, errors, reconnects)` tuples.

    The counters are **cumulative**, exactly as `ping` writes them (tools/pingpong/src/ping.rs
    `HEADER`), which is the whole reason `samples()` exists.
    """
    header = ("unix,iso,elapsed_s,tag,requests,errors,reconnects,count,"
              "min_us,mean_us,p50_us,p90_us,p99_us,max_us")
    lines = [header]
    first = rows[0][0] if rows else 0
    for unix, requests, errors, reconnects in rows:
        lines.append(f"{unix},2026-09-24T00:00:00Z,{unix - first:.3f},lat,"
                     f"{requests},{errors},{reconnects},1,1,1,1,1,1,1")
    return "\n".join(lines) + "\n"


def snmp_csv(**counters: int) -> str:
    names = sorted(counters)
    return ",".join(names) + "\n" + ",".join(str(counters[n]) for n in names) + "\n"


class Collected:
    """A local run directory as `cmd_run` would have downloaded it."""

    def __init__(self, state: dict, files: dict[str, str]) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name)
        self.state = state
        for name, text in files.items():
            (self.path / name).write_text(text)

    def __enter__(self) -> "Collected":
        return self

    def __exit__(self, *_exc: object) -> None:
        self._tmp.cleanup()


def a_state(**overrides) -> dict:
    state = {
        "runid": "f-server-restart-rr-20260924T000000Z",
        "case": "server-restart",
        "pair": "rr",
        "host": "fake-host",
        "config": "s1",
        "client_impl": "rust",
        "server_impl": "rust",
        "build": "rust rev abc",
        "server_build": "rust rev abc",
        "tunnel": str(failure.TUNNEL_PORT),
        "names": ["f-server-restart-rr-20260924T000000Z-srv1",
                  "f-server-restart-rr-20260924T000000Z-cli1",
                  "f-server-restart-rr-20260924T000000Z-w"],
        "events": [],
    }
    state.update(overrides)
    return state


# --------------------------------------------------------------------------------------------
# the case table
# --------------------------------------------------------------------------------------------


class CaseTableTests(unittest.TestCase):
    def test_every_case_has_a_unique_name_and_covers_a_plan_bullet(self):
        names = [case.name for case in failure.CASES]
        self.assertEqual(len(names), len(set(names)))
        for case in failure.CASES:
            self.assertTrue(case.covers.endswith("."), case.name)
            self.assertGreater(case.duration, 0)
            self.assertTrue(case.expect, f"{case.name} asserts nothing")

    def test_every_check_names_a_metric_the_analysis_can_produce(self):
        """A typo in a metric name would read as `None` and fail every run for the wrong reason.

        The guard is the *set of keys* `metrics()` builds, gathered from a run that exercises
        every branch of it (an event timeline, a recovery, and errors spread over time).
        """
        with Collected(
            a_state(events=[{"at": 20, "unix": 1020.0, "action": "stop-server",
                             "arg": "TERM", "label": "stop-server TERM"},
                            {"at": 24, "unix": 1024.0, "action": "start-server",
                             "arg": "", "label": "start-server"}]),
            {
                "ping-lat.csv": ping_csv([(1000.0 + n, n * 5, n, n) for n in range(80)]),
                "snmp-cli1.csv": snmp_csv(ActiveOpens=4, CurrEstab=1),
                "snmp-srv1.csv": snmp_csv(PassiveOpens=4, CurrEstab=1),
            },
        ) as run:
            produced = set(failure.metrics(run.state, run.path))
        for case in failure.CASES:
            for check in case.expect:
                self.assertIn(check.metric, produced,
                              f"{case.name}: no metric named {check.metric!r}")

    def test_a_case_that_sets_netem_names_a_profile_the_host_implements(self):
        """The profile has to exist in `lab-netns.sh`, not merely in `lab.py`'s tuple."""
        script = (REPO / "tools/lab/server/lab-netns.sh").read_text()
        for case in failure.CASES:
            profiles = [case.netem] + [event.arg for event in case.events
                                       if event.action == "netem"]
            for profile in profiles:
                self.assertIn(profile, lab.PROFILES, case.name)
                self.assertRegex(script, rf"\n\s+{re.escape(profile)}\) echo ",
                                 f"lab-netns.sh has no {profile} profile")

    def test_the_log_checks_name_a_real_end(self):
        for case in failure.CASES:
            for check in case.expect_log:
                self.assertIn(check.side, ("cli", "srv"), case.name)

    def test_events_are_in_order_and_inside_the_case(self):
        for case in failure.CASES:
            offsets = [event.at for event in case.events]
            self.assertEqual(offsets, sorted(offsets), case.name)
            for offset in offsets:
                self.assertLess(offset, case.duration, case.name)

    def test_no_case_uses_a_port_below_four_thousand(self):
        """tools/lab/README.md rule 4 — `lab-start.sh` refuses one, but not until the run starts."""
        ports = [failure.TUNNEL_PORT, failure.LISTEN_PORT, failure.PINGPONG_PORT,
                 failure.REFUSED_PORT, failure.SINK_PORT,
                 failure.TUNNEL_PORT + failure.TUNNEL_PORT_COUNT - 1]
        for port in ports:
            self.assertGreaterEqual(port, 4000)

    def test_the_recovery_cases_outlast_the_sixty_second_keepalive_path(self):
        """09.3 measured 64.89 s. A case that ended at 90 s would time the wait, not the tunnel."""
        for name in ("server-restart", "server-sigkill", "blackhole"):
            case = failure.CASES_BY_NAME[name]
            last = max(event.at for event in case.events)
            self.assertGreaterEqual(case.duration - last, 90, name)

    def test_the_shipped_settle_values_are_not_the_zeroed_test_ones(self):
        self.assertGreater(_REAL_SETTLE, 0)
        self.assertGreater(_REAL_SNMP_SETTLE, 0)
        self.assertTrue(_REAL_WAIT_FOR_EVENTS,
                        "a real run must walk the timeline in real time")


# --------------------------------------------------------------------------------------------
# the timeline
# --------------------------------------------------------------------------------------------


class TimelineTests(unittest.TestCase):
    def a_run(self, case_name: str, pair=("rust", "rust")) -> tuple[lab_test.FakeRunner, dict]:
        runner = lab_test.FakeRunner()
        run = failure.CaseRun(runner, failure.CASES_BY_NAME[case_name], pair[0], pair[1],
                              config="s1", stamp="20260924T000000Z")
        # The timeline narrates itself to stdout as it fires; a suite of 36 tests would
        # otherwise print it 12 times between the dots.
        with redirect_stdout(io.StringIO()):
            state = run.run(lab.BuildProvenance())
        return runner, state

    def test_a_restart_starts_a_second_generation_with_its_own_log_and_snmp(self):
        runner, state = self.a_run("server-restart")
        started = runner.started()
        self.assertIn("f-server-restart-rr-20260924T000000Z-srv1", started)
        self.assertIn("f-server-restart-rr-20260924T000000Z-srv2", started)
        # The first server's log must survive the restart: `lab-start.sh` truncates
        # logs/<name>.log, so a reused name would erase everything before the fault.
        self.assertNotEqual(started.count("f-server-restart-rr-20260924T000000Z-srv1"), 2)
        snmp = [arg for call in runner.lab_calls("start") for arg in call
                if "snmp-srv" in str(arg)]
        self.assertTrue(any("snmp-srv-a.csv" in arg for arg in snmp))
        self.assertTrue(any("snmp-srv-b.csv" in arg for arg in snmp))
        self.assertEqual([event["label"] for event in state["events"]],
                         ["stop-server TERM", "start-server"])

    def test_the_server_is_stopped_with_the_signal_the_case_names(self):
        runner, _ = self.a_run("server-sigkill")
        stops = runner.lab_calls("stop")
        self.assertIn(("lab", "stop", "--signal", "KILL",
                       "f-server-sigkill-rr-20260924T000000Z-srv1"), stops)

    def test_the_client_case_kills_and_restarts_the_client_only(self):
        runner, _ = self.a_run("client-sigkill")
        self.assertIn(("lab", "stop", "--signal", "KILL",
                       "f-client-sigkill-rr-20260924T000000Z-cli1"),
                      runner.lab_calls("stop"))
        self.assertIn("f-client-sigkill-rr-20260924T000000Z-cli2", runner.started())

    def test_the_blackhole_case_sets_and_clears_the_netem_profile(self):
        runner, _ = self.a_run("blackhole")
        netns = [call[2:] for call in runner.lab_calls("netns")]
        self.assertIn(("set", "blackhole"), netns)
        self.assertIn(("set", "clean"), netns)
        self.assertLess(netns.index(("set", "blackhole")), netns.index(("set", "clean")))

    def an_aborting_run(self, case_name: str, fail_on):
        """A run that raises mid-timeline, as a Ctrl-C or any `LabError` would.

        `fail_on` fires once, so the restore that follows is allowed to run — which is the
        whole point: the driver's cleanup path has to reach the host even after a failure.
        """
        class Aborting(lab_test.FakeRunner):
            armed = True

            def lab(self, *argv, **kwargs):
                if self.armed and fail_on(argv):
                    self.armed = False
                    raise failure.LabError("interrupted")
                return super().lab(*argv, **kwargs)

        runner = Aborting()
        run = failure.CaseRun(runner, failure.CASES_BY_NAME[case_name], "rust", "rust",
                              config="s1", stamp="20260924T000000Z")
        with redirect_stdout(io.StringIO()):
            with self.assertRaises(failure.LabError):
                run.run(lab.BuildProvenance())
            # What `cmd_run`'s `finally` and `emergency_stop` both do, and all they do.
            run.stop_everything()
        return runner

    def test_an_aborted_blackhole_run_still_clears_the_netem_profile(self):
        """Ctrl-C inside the fault window must not leave the namespaces at `loss 100%`."""
        # The abort lands on the event that would have healed the path, so the run gives up
        # with the namespaces still at `loss 100%`.
        runner = self.an_aborting_run(
            "blackhole", lambda argv: argv[:3] == ("netns", "set", "clean"))
        netns = [call[2:] for call in runner.lab_calls("netns")]
        self.assertEqual(netns[-1], ("set", "clean"))

    def test_an_aborted_sink_run_still_takes_the_sink_route_down(self):
        runner = self.an_aborting_run("target-blackholed", lambda argv: argv[0] == "wait")
        self.assertEqual([call[2:] for call in runner.lab_calls("netns")][-1],
                         ("sink", "down"))

    def test_the_unreachable_target_case_puts_the_sink_route_up_and_takes_it_down(self):
        runner, state = self.a_run("target-blackholed")
        netns = [call[2:] for call in runner.lab_calls("netns")]
        self.assertIn(("sink", "up"), netns)
        self.assertIn(("sink", "down"), netns)
        self.assertEqual(state["target_addr"],
                         f"{failure.SINK_ADDR}:{failure.SINK_PORT}")
        # No echo target: the point of the case is that nothing answers.
        self.assertNotIn("f-target-blackholed-rr-20260924T000000Z-tgt", runner.started())

    def test_the_refused_target_case_points_the_tunnel_at_a_closed_port(self):
        runner, state = self.a_run("target-refused")
        self.assertEqual(state["target_addr"], f"127.0.0.1:{failure.REFUSED_PORT}")
        self.assertNotIn(("sink", "up"),
                         [call[2:] for call in runner.lab_calls("netns")])
        self.assertNotIn("f-target-refused-rr-20260924T000000Z-tgt", runner.started())

    def test_a_healthy_case_starts_the_echo_target_first(self):
        runner, _ = self.a_run("autoexpire")
        started = runner.started()
        self.assertEqual(started[0], "f-autoexpire-rr-20260924T000000Z-tgt")
        self.assertEqual(started[1:4], ["f-autoexpire-rr-20260924T000000Z-srv1",
                                        "f-autoexpire-rr-20260924T000000Z-cli1",
                                        "f-autoexpire-rr-20260924T000000Z-w"])

    def test_everything_started_is_stopped_and_collected(self):
        runner, state = self.a_run("server-restart")
        stopped = set()
        for call in runner.lab_calls("stop"):
            stopped.update(arg for arg in call[2:] if arg.startswith("f-"))
        for name in runner.started():
            self.assertIn(name, stopped, f"{name} was left running")
        collected = [call for call in runner.lab_calls("collect") if len(call) > 3]
        self.assertTrue(collected)
        for name in state["names"]:
            self.assertIn(name, collected[-1])

    def test_the_port_range_case_spans_the_whole_range_on_both_ends(self):
        runner, _ = self.a_run("portrange")
        spec = f"{failure.TUNNEL_PORT}-{failure.TUNNEL_PORT + failure.TUNNEL_PORT_COUNT - 1}"
        starts = [" ".join(str(a) for a in call) for call in runner.lab_calls("start")]
        self.assertTrue(any(f"-l :{spec}" in line for line in starts))
        self.assertTrue(any(f"-r 10.200.0.2:{spec}" in line for line in starts))

    def test_the_mixed_pair_runs_a_go_client_against_a_rust_server(self):
        runner, state = self.a_run("client-sigkill", pair=("go", "rust"))
        self.assertEqual(state["pair"], "gr")
        starts = [" ".join(str(a) for a in call) for call in runner.lab_calls("start")]
        self.assertTrue(any("bin/go/kg-client" in line for line in starts))
        self.assertTrue(any("bin/rust/kr-server" in line for line in starts))

    def test_the_case_flags_reach_the_command_line(self):
        runner, _ = self.a_run("autoexpire")
        starts = [" ".join(str(a) for a in call) for call in runner.lab_calls("start")]
        client = [line for line in starts if "kr-client" in line][0]
        self.assertIn("-autoexpire 30", client)
        self.assertIn("-scavengettl 15", client)
        # S1 is still underneath it.
        self.assertIn("-sndwnd 8192", client)

    def test_an_unprovenanced_host_refuses_the_run_before_anything_starts(self):
        runner = lab_test.FakeRunner()
        runner.stamps["rust"] = ""
        run = failure.CaseRun(runner, failure.CASES_BY_NAME["client-sigkill"], "rust", "rust",
                              config="s1", stamp="20260924T000000Z")
        with self.assertRaisesRegex(lab.LabError, "unprovenanced"):
            run.run(lab.BuildProvenance())
        self.assertEqual(runner.started(), [])

    def test_a_tcp_case_starts_both_ends_as_root_with_the_flag(self):
        """`--tcp` needs raw sockets and its own `filter/OUTPUT` chain (Step 10.5)."""
        runner, _ = self.a_run("tcp-server-restart")
        starts = [list(call[2:]) for call in runner.lab_calls("start")]
        tunnels = [call for call in starts
                   if any("kr-client" in str(a) or "kr-server" in str(a) for a in call)]
        self.assertTrue(tunnels)
        for call in tunnels:
            self.assertIn("--root", call)
            self.assertIn("-tcp", call)
        # The workload and the echo target are ordinary processes and must NOT be root.
        others = [call for call in starts if call not in tunnels]
        for call in others:
            self.assertNotIn("--root", call)

    def test_a_case_that_only_one_pair_can_answer_says_so(self):
        for case in failure.CASES:
            if case.only_pairs:
                self.assertTrue(case.skip_reason, case.name)
                for code in case.only_pairs:
                    self.assertIn(code, failure.PAIR_CODES.values(), case.name)
                self.assertFalse(case.runs_pair("gg"), case.name)
        # V22 is the reason, and the report has to carry it rather than silently show one row.
        with tempfile.TemporaryDirectory() as name:
            tmp = Path(name)
            case = failure.CASES_BY_NAME["tcp-server-restart"]
            state = a_state(case=case.name, pair="rr", runid="f-tcp-server-restart-rr-s")
            directory = tmp / state["runid"]
            directory.mkdir()
            (directory / "ping-lat.csv").write_text(ping_csv([(1000.0, 5, 0, 0)]))
            text = failure.report([state], [directory])
        self.assertIn("Runs only as RR, RG", text)
        self.assertIn("V22", text)

    def test_the_ssh_that_waits_outlasts_the_workload_it_waits_for(self):
        """`Runner.lab` defaults to a two-minute ssh timeout, and a timeout there *raises*.

        Every recovery case is longer than two minutes, so the default aborted a 16-run
        campaign at its first case — after the run had already been started on the host.
        """

        class Recording(lab_test.FakeRunner):
            waits: list[tuple[int, float | None]] = []

            def lab(self, script: str, *args: str, check: bool = True,
                    timeout: float | None = 120.0):
                if script == "wait":
                    self.waits.append((int(args[1]), timeout))
                return super().lab(script, *args, check=check, timeout=timeout)

        runner = Recording()
        runner.waits = []
        case = failure.CASES_BY_NAME["server-restart"]
        run = failure.CaseRun(runner, case, "rust", "rust", config="s1", stamp="s")
        with redirect_stdout(io.StringIO()):
            run.run(lab.BuildProvenance())
        self.assertEqual(len(runner.waits), 1)
        wanted, allowed = runner.waits[0]
        self.assertGreaterEqual(wanted, case.duration)
        self.assertIsNotNone(allowed)
        self.assertGreater(allowed, wanted)

    def test_an_unknown_action_is_refused_rather_than_silently_skipped(self):
        runner = lab_test.FakeRunner()
        case = failure.CASES_BY_NAME["client-sigkill"]
        run = failure.CaseRun(runner, case, "rust", "rust", config="s1", stamp="s")
        with self.assertRaisesRegex(lab.LabError, "unknown action"):
            run.apply(failure.Event(1, "detonate"))


# --------------------------------------------------------------------------------------------
# the arithmetic
# --------------------------------------------------------------------------------------------


class MetricsTests(unittest.TestCase):
    def test_cumulative_counters_become_per_interval_deltas(self):
        with Collected(a_state(), {"ping-lat.csv": ping_csv(
                [(1000.0, 5, 0, 0), (1001.0, 10, 0, 0), (1002.0, 10, 1, 1)])}) as run:
            series = failure.samples(run.path)
        self.assertEqual([s.d_requests for s in series], [5, 5, 0])
        self.assertEqual([s.d_errors for s in series], [0, 0, 1])

    def test_a_recovery_is_measured_from_the_repair_and_an_outage_from_the_fault(self):
        # Traffic to t=1019, nothing while the server is down and the session is still
        # believed alive, back at t=1085 — the ~60 s keepalive path 09.3 measured.
        rows = []
        requests = 0
        for second in range(0, 120):
            if second < 20 or second >= 85:
                requests += 5
            rows.append((1000.0 + second, requests, 0, 0))
        events = [{"at": 20, "unix": 1020.0, "action": "stop-server", "arg": "TERM",
                   "label": "stop-server TERM"},
                  {"at": 24, "unix": 1024.0, "action": "start-server", "arg": "",
                   "label": "start-server"}]
        with Collected(a_state(events=events), {"ping-lat.csv": ping_csv(rows)}) as run:
            values = failure.metrics(run.state, run.path)
        self.assertAlmostEqual(values["outage_s"], 66.0, places=1)
        self.assertAlmostEqual(values["recovery_from_fault_s"], 65.0, places=1)
        self.assertAlmostEqual(values["recovery_from_heal_s"], 61.0, places=1)
        self.assertEqual(values["post_heal_requests"], 175)
        self.assertEqual(values["max_gap_s"], 66.0)

    def test_a_row_that_straddles_the_fault_is_not_counted_as_traffic_after_it(self):
        """A live SIGKILL run reported a **one-second** outage next to a forty-second gap.

        The row at `fault + 0.8 s` covers the second the kill happened in, so its requests
        completed *before* it. Counted as "after", it makes the outage look like the gap between
        two adjacent rows.
        """
        rows = []
        requests = 0
        for second in range(0, 90):
            if second < 20 or second >= 60:
                requests += 5
            rows.append((1000.0 + second, requests, 0, 0))
        # The kill lands 0.2 s before the row at t=1020.
        events = [{"at": 20, "unix": 1019.8, "action": "stop-server", "arg": "KILL",
                   "label": "stop-server KILL"}]
        with Collected(a_state(events=events), {"ping-lat.csv": ping_csv(rows)}) as run:
            values = failure.metrics(run.state, run.path)
        self.assertAlmostEqual(values["outage_s"], 41.0, places=1)
        self.assertAlmostEqual(values["max_gap_s"], 41.0, places=1)

    def test_a_run_that_never_recovers_reports_no_recovery_rather_than_zero(self):
        rows = [(1000.0 + n, 5 * min(n, 20), 0, 0) for n in range(60)]
        events = [{"at": 20, "unix": 1020.0, "action": "stop-server", "arg": "KILL",
                   "label": "stop-server KILL"}]
        with Collected(a_state(events=events), {"ping-lat.csv": ping_csv(rows)}) as run:
            values = failure.metrics(run.state, run.path)
        self.assertIsNone(values["recovery_from_fault_s"])
        self.assertIsNone(values["recovery_from_heal_s"])
        self.assertEqual(values["post_heal_requests"], 0)
        # And the check built on it fails, rather than passing on a missing number.
        row = failure.Check("recovery_from_heal_s", 0, 110).evaluate(values)
        self.assertFalse(row["ok"])

    def test_the_error_spacing_separates_a_refused_dial_from_a_ten_second_timeout(self):
        slow = [(1000.0 + n, 0, n // 10, n // 10) for n in range(80)]
        with Collected(a_state(), {"ping-lat.csv": ping_csv(slow)}) as run:
            values = failure.metrics(run.state, run.path)
        self.assertAlmostEqual(values["median_error_interval_s"], 10.0, places=1)

        fast = [(1000.0 + n, 0, 4 * n, 4 * n) for n in range(40)]
        with Collected(a_state(), {"ping-lat.csv": ping_csv(fast)}) as run:
            values = failure.metrics(run.state, run.path)
        self.assertLessEqual(values["median_error_interval_s"], 1.0)

    def test_the_error_spacing_is_a_median_and_not_a_mean(self):
        """A burst of refusals with one long gap: the mean would read as a dialTimeout.

        Nineteen errors a second apart and then a single 40 s gap — an RST storm interrupted
        once. The median is 1 s, which is what `target-refused` is checked against; the mean is
        about 3 s and would still pass, but on a longer pause it would drift into the 8-14 s
        band `target-blackholed` uses and the two failure modes would stop being separable.
        """
        rows = [(1000.0 + n, 0, min(n, 20), 0) for n in range(20)]
        rows += [(1060.0, 0, 21, 0), (1061.0, 0, 22, 0)]
        with Collected(a_state(), {"ping-lat.csv": ping_csv(rows)}) as run:
            values = failure.metrics(run.state, run.path)
        self.assertAlmostEqual(values["median_error_interval_s"], 1.0, places=1)
        self.assertTrue(failure.Check("median_error_interval_s", 0, 2).evaluate(values)["ok"])

    def test_the_snmp_counters_come_from_the_newest_generation_of_each_end(self):
        """And "newest" is by modification time, not by name.

        These are the names a 2026-09-25 run actually produced: `-snmplog` is a Go time layout,
        so the first server's `snmp-srv1.csv` became `snmp-srv9.csv` (layout `1` = month) and
        the restarted one's `snmp-srv2.csv` became `snmp-srv25.csv` (layout `2` = day). Sorted
        alphabetically that reads the pre-restart counters as the run's answer.
        """
        with Collected(a_state(), {
            "ping-lat.csv": ping_csv([(1000.0, 1, 0, 0)]),
            "snmp-cli9.csv": snmp_csv(ActiveOpens=1, CurrEstab=1),
            "snmp-srv9.csv": snmp_csv(PassiveOpens=1, CurrEstab=1),
            "snmp-srv25.csv": snmp_csv(PassiveOpens=7, CurrEstab=2),
        }) as run:
            import os
            newest = run.path / "snmp-srv25.csv"
            os.utime(run.path / "snmp-srv9.csv", (1000, 1000))
            os.utime(newest, (2000, 2000))
            values = failure.metrics(run.state, run.path)
        self.assertEqual(values["server_passive_opens"], 7)
        self.assertEqual(values["client_active_opens"], 1)

    def test_the_snmplog_name_cannot_be_eaten_by_the_go_time_layout(self):
        """kcptun formats the file part of `-snmplog` (reference/kcptun/std/snmp.go:56)."""
        for generation, suffix in ((1, "a"), (2, "b"), (3, "c")):
            self.assertEqual(failure.CaseRun.snmp_suffix(generation), suffix)
        runner = lab_test.FakeRunner()
        run = failure.CaseRun(runner, failure.CASES_BY_NAME["server-restart"], "rust", "rust",
                              config="s1", stamp="s")
        for argv in (run.server_argv(2), run.client_argv(2)):
            path = argv[argv.index("-snmplog") + 1]
            name = path.rsplit("/", 1)[-1]
            self.assertNotRegex(name, r"\d", f"{name} carries a Go layout token")

    def test_the_workload_result_line_wins_over_the_last_csv_row(self):
        """The CSV's last row is written a moment before the run ends; `RESULT` is the total."""
        state = a_state()
        with Collected(state, {
            "ping-lat.csv": ping_csv([(1000.0, 10, 1, 1)]),
            f"{state['runid']}-w.log": 'ping: t=1s\nRESULT {"kind":"ping","requests":12,'
                                       '"errors":2,"reconnects":2,"rtt_p50_us":1500}\n',
        }) as run:
            values = failure.metrics(run.state, run.path)
        self.assertEqual(values["requests"], 12)
        self.assertEqual(values["errors"], 2)
        self.assertAlmostEqual(values["rtt_p50_ms"], 1.5, places=3)

    def test_log_checks_count_every_generation_of_the_named_end(self):
        state = a_state(names=["f-x-rr-s-cli1", "f-x-rr-s-cli2", "f-x-rr-s-srv1"])
        with Collected(state, {
            "f-x-rr-s-cli1.log": "scavenger: session closed due to ttl: 1\n",
            "f-x-rr-s-cli2.log": "scavenger: session closed due to ttl: 2\n"
                                 "scavenger: session closed due to ttl: 3\n",
            "f-x-rr-s-srv1.log": "scavenger: session closed due to ttl: 4\n",
        }) as run:
            hits = failure.log_hits(run.path, run.state, "cli",
                                    "scavenger: session closed due to ttl:")
        self.assertEqual(hits, 3)

    def test_the_dialled_ports_come_out_of_the_client_log_and_are_range_checked(self):
        """The port-range case's only real assertion, so the parse has to be exercised.

        A client that parsed `-r host:29904-29907` but always dialled `MinPort` passes every
        other metric here unchanged. `createConn()` picks the port per dial
        (reference/kcptun/client/dial.go:56-63) and the only record of its choice is the
        `on connection:` line. The fixture names two ports of the range and one outside it.
        """
        low = failure.TUNNEL_PORT
        high = failure.TUNNEL_PORT + failure.TUNNEL_PORT_COUNT - 1
        state = a_state(names=["f-x-rr-s-cli1", "f-x-rr-s-cli2", "f-x-rr-s-srv1"],
                        tunnel=f"{low}-{high}")
        with Collected(state, {
            "ping-lat.csv": ping_csv([(1000.0, 1, 0, 0)]),
            "f-x-rr-s-cli1.log":
                f"2026/09/25 00:54:08 main.rs:766: smux version: 2 on connection: "
                f"0.0.0.0:57654 -> 10.200.0.2:{high}\n"
                f"2026/09/25 00:54:57 main.rs:766: smux version: 2 on connection: "
                f"0.0.0.0:53150 -> 10.200.0.2:{low}\n",
            # A second generation, and a dial outside the range: the check must see both.
            "f-x-rr-s-cli2.log":
                f"2026/09/25 00:55:47 main.go:473: smux version: 2 on connection: "
                f"0.0.0.0:59230 -> 10.200.0.2:{high + 5}\n",
            # The server's log must not be counted: it names its own peers.
            "f-x-rr-s-srv1.log":
                "2026/09/25 00:55:47 main.rs:1: on connection: a -> 10.200.0.2:1\n",
        }) as run:
            ports = failure.dialled_ports(run.path, run.state)
            values = failure.metrics(run.state, run.path)
        self.assertEqual(ports, [high, low, high + 5])
        self.assertEqual(values["distinct_remote_ports"], 3)
        self.assertEqual(values["remote_ports_out_of_range"], 1)
        self.assertFalse(failure.Check("remote_ports_out_of_range", 0, 0)
                         .evaluate(values)["ok"])

    def test_a_single_port_run_is_in_range_and_an_unknown_range_fails_the_check(self):
        state = a_state(names=["f-x-rr-s-cli1"], tunnel=str(failure.TUNNEL_PORT))
        files = {
            "ping-lat.csv": ping_csv([(1000.0, 1, 0, 0)]),
            "f-x-rr-s-cli1.log": f"on connection: 0.0.0.0:1 -> 10.200.0.2:"
                                 f"{failure.TUNNEL_PORT}\n",
        }
        with Collected(state, files) as run:
            values = failure.metrics(run.state, run.path)
        self.assertEqual(values["remote_ports_out_of_range"], 0)
        self.assertEqual(values["distinct_remote_ports"], 1)
        # "No data" is not evidence: a run whose state does not say which range it used
        # reports `None`, and `Check.evaluate` fails on it rather than reading it as zero.
        no_range = a_state(names=["f-x-rr-s-cli1"])
        del no_range["tunnel"]
        with Collected(no_range, files) as run:
            values = failure.metrics(run.state, run.path)
        self.assertIsNone(values["remote_ports_out_of_range"])
        self.assertFalse(failure.Check("remote_ports_out_of_range", 0, 0)
                         .evaluate(values)["ok"])

    def test_re_connecting_is_counted_on_every_run_not_only_where_it_is_checked(self):
        """UDP reports 0 and `--tcp` reports the retries, in the same column.

        Over UDP `createConn()` cannot fail (09.3), so the count is the absence `server-restart`
        asserts. Under `--tcp` `dial()` does a real `tcpraw.Dial()`
        (reference/kcptun/client/dial.go:67), which fails with ENETUNREACH while the path is
        blackholed, and `waitConn` (client/main.go:505) logs each retry. Reporting the count
        everywhere is what makes that difference an assertion instead of a grep.
        """
        state = a_state(names=["f-x-rr-s-cli1"])
        with Collected(state, {"ping-lat.csv": ping_csv([(1000.0, 1, 0, 0)]),
                               "f-x-rr-s-cli1.log": "smux version: 2 on connection: a -> b:1\n"}
                       ) as run:
            self.assertEqual(failure.metrics(run.state, run.path)["client_re_connecting"], 0)
        with Collected(state, {
            "ping-lat.csv": ping_csv([(1000.0, 1, 0, 0)]),
            "f-x-rr-s-cli1.log":
                "2026/09/25 01:07:22 main.rs:805: re-connecting: dial(): tcpraw.Dial(): "
                "dial tcp 10.200.0.2:29904: connect: no route to host\n"
                "2026/09/25 01:07:25 main.rs:805: re-connecting: dial(): tcpraw.Dial(): "
                "dial tcp 10.200.0.2:29904: connect: no route to host\n",
        }) as run:
            values = failure.metrics(run.state, run.path)
            rows = failure.verdict(failure.CASES_BY_NAME["tcp-blackhole"], run.state, values,
                                   run.path)["checks"]
        self.assertEqual(values["client_re_connecting"], 2)
        row = [r for r in rows if "re-connecting" in r["metric"]][0]
        self.assertTrue(row["ok"])
        self.assertEqual(row["value"], 2)

    def test_an_absent_line_check_fails_when_the_line_is_there(self):
        """The `re-connecting:` check: a mechanism that must NOT fire."""
        case = failure.CASES_BY_NAME["server-restart"]
        absent = [check for check in case.expect_log if check.absent]
        self.assertTrue(absent, "the restart case no longer checks for an absence")
        state = a_state(names=["f-x-rr-s-cli1"])
        for text, ok in (("nothing to see\n", True),
                         ("2026/09/25 re-connecting: dial(): x\n", False)):
            with Collected(state, {"f-x-rr-s-cli1.log": text,
                                   "ping-lat.csv": ping_csv([(1000.0, 1, 0, 0)])}) as run:
                rows = failure.verdict(case, run.state, failure.metrics(run.state, run.path),
                                       run.path)["checks"]
            row = [r for r in rows if "re-connecting" in r["metric"]][0]
            self.assertEqual(row["ok"], ok, text)

    def test_a_missing_csv_produces_no_metrics_rather_than_an_exception(self):
        with Collected(a_state(), {}) as run:
            values = failure.metrics(run.state, run.path)
        self.assertEqual(values["intervals"], 0)
        self.assertIsNone(values["requests"])


# --------------------------------------------------------------------------------------------
# verdicts and the report
# --------------------------------------------------------------------------------------------


def a_pair_of_runs(tmp: Path) -> tuple[list[dict], list[Path]]:
    """One GG run and one RR run of `server-restart`, collected under `tmp`."""
    rows = []
    requests = 0
    for second in range(0, 120):
        if second < 20 or second >= 85:
            requests += 5
        rows.append((1000.0 + second, requests, 0, 0))
    events = [{"at": 20, "unix": 1020.0, "action": "stop-server", "arg": "TERM",
               "label": "stop-server TERM"},
              {"at": 24, "unix": 1024.0, "action": "start-server", "arg": "",
               "label": "start-server"}]
    states, directories = [], []
    for pair, client, server in (("gg", "go", "go"), ("rr", "rust", "rust")):
        runid = f"f-server-restart-{pair}-s"
        state = a_state(pair=pair, client_impl=client, server_impl=server,
                        runid=runid, events=events,
                        names=[f"{runid}-srv1", f"{runid}-cli1", f"{runid}-srv2",
                               f"{runid}-w"])
        directory = tmp / runid
        directory.mkdir()
        (directory / "ping-lat.csv").write_text(ping_csv(rows))
        # The case asserts the re-dial the client logs; without it every run "fails" for a
        # reason the fixture invented.
        (directory / f"{runid}-cli1.log").write_text(
            "2026/09/25 00:23:12 main.go:473: smux version: 2 on connection: a -> b\n"
            "2026/09/25 00:24:12 main.go:473: smux version: 2 on connection: c -> b\n")
        (directory / "snmp-cli1.csv").write_text(snmp_csv(ActiveOpens=2, CurrEstab=1))
        (directory / "state.json").write_text(json.dumps(state))
        states.append(state)
        directories.append(directory)
    return states, directories


class ReportTests(unittest.TestCase):
    def test_the_report_puts_both_implementations_in_one_table_per_case(self):
        with tempfile.TemporaryDirectory() as name:
            states, directories = a_pair_of_runs(Path(name))
            text = failure.report(states, directories)
        self.assertIn("## Server restarted (SIGTERM) during traffic", text)
        self.assertIn("| GG |", text)
        self.assertIn("| RR |", text)
        self.assertIn("t+20s stop-server TERM", text)
        self.assertIn("2 of 2 runs met every check.", text)
        self.assertNotIn("**FAIL**", text)

    def test_a_failed_check_is_named_in_the_table_and_the_verdict(self):
        with tempfile.TemporaryDirectory() as name:
            tmp = Path(name)
            states, directories = a_pair_of_runs(tmp)
            # Rust never recovers: the traffic stops at t=20 and stays stopped.
            rows = [(1000.0 + n, 5 * min(n, 20), 0, 0) for n in range(120)]
            (directories[1] / "ping-lat.csv").write_text(ping_csv(rows))
            text = failure.report(states, directories)
        self.assertIn("**FAIL**", text)
        self.assertIn("server-restart/rr: FAIL", text)
        self.assertIn("1 of 2 runs met every check.", text)

    def test_an_error_marker_in_a_collected_log_reaches_the_report(self):
        with tempfile.TemporaryDirectory() as name:
            tmp = Path(name)
            states, directories = a_pair_of_runs(tmp)
            marker = directories[1] / "f-server-restart-rr-s-cli1.log"
            marker.write_text(marker.read_text() + "2026/09/24 panic: runtime error\n")
            text = failure.report(states, directories)
        self.assertIn("log marker", text)
        self.assertIn("panic", text)

    def test_an_unprovenanced_run_is_banner_marked(self):
        with tempfile.TemporaryDirectory() as name:
            states, directories = a_pair_of_runs(Path(name))
            states[1]["client_build_detail"] = {"problem": "no stamp", "host": "fake-host"}
            text = failure.report(states, directories)
        self.assertIn("UNPROVENANCED", text)


class CliTests(unittest.TestCase):
    def test_cases_lists_every_case_and_its_cost(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            failure.main(["cases"])
        printed = buffer.getvalue()
        for case in failure.CASES:
            self.assertIn(case.name, printed)

    def test_report_concatenates_several_sessions_into_one_document(self):
        """11.5's own document spans two sessions, so `report` has to take two.

        The eight two-arm cases and the two `--tcp` RR-only cases were separate `run`
        invocations, hence separate session directories. A `report` that resolved exactly one
        could only be followed by moving run directories between sessions by hand, and a
        document nobody can regenerate from the command it prints is not reproducible.
        """
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            states, directories = a_pair_of_runs(root)
            first = root / "20260101T000000Z-failure"
            second = root / "20260101T010000Z-failure"
            for session in (first, second):
                session.mkdir()
            for state, directory in zip(states, directories):
                directory.rename((first if state["pair"] == "gg" else second) / directory.name)
            out = root / "tables.md"
            code = failure.main(["--runs-dir", str(root), "report", "20260101T000000Z",
                                 "20260101T010000Z", "--out", str(out)])
            text = out.read_text()
            # A name that resolves to nothing is still refused, rather than quietly dropped
            # from the concatenation — a session missing from a published document is exactly
            # the kind of silence this command exists to prevent.
            with self.assertRaisesRegex(lab.LabError, "matches 0 sessions"):
                failure.cmd_report(None, argparse.Namespace(
                    runs_dir=str(root), session=["20260101T000000Z", "no-such"], out=None))
        self.assertEqual(code, 0)
        self.assertIn("2 runs.", text)
        self.assertIn("| GG |", text)
        self.assertIn("| RR |", text)
        self.assertIn("2 of 2 runs met every check.", text)

    def test_an_unknown_case_is_refused_by_name(self):
        with self.assertRaisesRegex(lab.LabError, "unknown case"):
            failure.selected_cases(["no-such-case"])

    def test_the_pair_spec_is_parsed_in_the_order_given(self):
        self.assertEqual(failure.selected_pairs("rr,gg"),
                         [("rust", "rust"), ("go", "go")])
        with self.assertRaisesRegex(lab.LabError, "unknown pair"):
            failure.selected_pairs("xx")


if __name__ == "__main__":
    unittest.main(verbosity=1)
