#!/usr/bin/env python3
"""Tests for tools/lab/lab.py and tools/lab/deploy.sh. Run with `python3 tools/lab/lab_test.py`.

The cargo gate cannot cover a python script, and a scenario runner that is only ever exercised
by running a six-hour soak is not covered at all. These tests substitute a fake `Runner` for
ssh, so the whole flow — preflight, netns, start order, waiting, SIGUSR1, stop, collect, report
— is checked without a lab host, and the parts that turn collected files into a report are
checked against files written by hand.

`DeployTests` goes one step further and runs the real `deploy.sh` against stub `ssh`, `scp` and
`cargo` commands in a throwaway root, because the architecture it picks is only observable at
the moment a binary refuses to start on the host — hours into a run.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import lab  # noqa: E402  (the import needs the path above)


# --------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------


MINIMAL = {
    "name": "unit",
    "workloads": [{"type": "ping", "tag": "lat", "duration": 5}],
}

#: `finish_run` waits a real second for the SIGUSR1 SNMP dump to reach the process log. Most of
#: this file drives a non-dry `FakeRunner` through it, so the suite used to pay that second per
#: test — ~25 s of wall clock inside `cargo test --workspace`, the slowest target in the gate.
#: Zeroed for the whole module and restored afterwards; the shipped value is asserted below so
#: that zeroing it here cannot quietly become zeroing it in a real run.
_REAL_SNMP_SETTLE = lab.SNMP_SETTLE_SECONDS


def setUpModule() -> None:
    lab.SNMP_SETTLE_SECONDS = 0


def tearDownModule() -> None:
    lab.SNMP_SETTLE_SECONDS = _REAL_SNMP_SETTLE


#: The sha256 the fake host reports for each deployed binary. A stamp that records these is
#: provenanced; one that records anything else describes a file that is not the one that would
#: run, which is the 11.3 failure exactly.
FAKE_SHA = {
    "kr-client": "11" * 32,
    "kr-server": "22" * 32,
    "kg-client": "33" * 32,
    "kg-server": "44" * 32,
    "kr-pingpong": "55" * 32,
    "kr-labsample": "66" * 32,
}

FAKE_COMMIT = "0123456789abcdef0123456789abcdef01234567"


def stamp_text(kind: str = "rust", *, target: str = "x86_64-unknown-linux-gnu",
               libc: str = "glibc 2.17", profile: str = "release",
               binaries: tuple[str, ...] = ("kr-client", "kr-server"),
               commit: str = FAKE_COMMIT, sha: dict[str, str] | None = None,
               drop: tuple[str, ...] = ()) -> str:
    """A `deploy.sh` build stamp, as the fake host would hold it.

    `drop` removes fields, which is how a half-written stamp is exercised.
    """
    fields = {
        "kind": kind,
        "host": "x86_64",
        "target": target,
        "libc": libc,
        "profile": profile,
        "commit": commit,
        "revision": commit[:7],
        "tree": "clean",
        "deployed": "2026-09-24T10:00:00Z",
        "binaries": " ".join(binaries),
    }
    for name in binaries:
        fields[f"sha256.{name}"] = (sha or FAKE_SHA)[name]
    fields["summary"] = (f"host x86_64, {kind} {target} ({libc}), profile {profile}, "
                         f"rev {commit[:7]}, deployed 2026-09-24T10:00:00Z")
    return "".join(f"{k}={v}\n" for k, v in fields.items() if k not in drop)


class FakeRunner(lab.Runner):
    """A `Runner` that records commands instead of running them."""

    def __init__(self, host: str = "fake-host") -> None:
        super().__init__(host)
        self.calls: list[tuple[str, ...]] = []
        self.next_pid = 1000
        self.fetched: list[tuple[str, Path]] = []
        self.netns_status = ""
        #: The fakes handed out by `peer()`, by host — how a two-host WAN run is observed.
        self.peers: dict[str, "FakeRunner"] = {}
        #: What `cat bin/<family>/BUILD.txt` answers, per family, and what `sha256sum` reports
        #: for each deployed binary. A test makes a host unprovenanced by emptying or
        #: rewriting one of these.
        self.stamps: dict[str, str] = {
            "rust": stamp_text("rust"),
            "go": stamp_text("go", target="linux/amd64", libc="none", profile="reference",
                             binaries=("kg-client", "kg-server")),
            "lab": stamp_text("lab", binaries=("kr-pingpong", "kr-labsample")),
            "legacy": "",
        }
        self.hashes: dict[str, str] = dict(FAKE_SHA)

    def peer(self, host: str) -> "FakeRunner":
        if host == self.host:
            return self
        if host not in self.peers:
            self.peers[host] = type(self)(host)
        return self.peers[host]

    def ssh(self, command: str, *, check: bool = True, timeout: float | None = 120.0):
        self.calls.append(("ssh", command))
        if command.strip() == "uptime":
            return lab.Result(
                [], 0, f" 21:30:01 up 3 days, load average: 0.10, 0.20, 0.30 [{self.host}]\n", "")
        if "loadavg" in command:
            return lab.Result([], 0, "0.12 0.20 0.30 1/500 1234\n", "")
        if "taken-at.txt" in command:
            return lab.Result([], 0, "2026-09-23T09:00:00Z\n", "")
        if "rmem_max" in command:
            return lab.Result([], 0, "212992\n212992\n", "")
        if "BUILD.txt" in command:
            family = "legacy"
            for name in ("rust", "go", "lab"):
                if f"/bin/{name}/BUILD.txt" in command:
                    family = name
            return lab.Result([], 0, self.stamps.get(family, ""), "")
        if command.startswith("sha256sum "):
            name = command.split()[1].strip('"').rsplit("/", 1)[-1]
            digest = self.hashes.get(name, "")
            return lab.Result([], 0, f"{digest}  {name}\n" if digest else "", "")
        if ".pid" in command:
            # One "<name> <pid> <exe>" line per requested PID file. The names are read out of
            # the paths the command cats, because that is what `Runner.pids` actually builds —
            # reading them out of shell quoting instead silently matched nothing, and every
            # sampler command line in these tests then had no `--pid` at all to assert on.
            lines = []
            for name in re.findall(r"/run/([A-Za-z0-9._-]+)\.pid", command):
                self.next_pid += 1
                lines.append(f"{name} {self.next_pid} /home/u/kcptun-lab/bin/x")
            return lab.Result([], 0, "\n".join(lines) + "\n", "")
        return lab.Result([], 0, "", "")

    def lab(self, script: str, *args: str, check: bool = True,
            timeout: float | None = 120.0):
        self.calls.append(("lab", script, *args))
        if script == "netns" and args[:1] == ("status",):
            return lab.Result([], 0, self.netns_status, "")
        return lab.Result([], 0, "", "")

    def local(self, argv, *, check: bool = True, timeout: float | None = 900.0, env=None):
        self.calls.append(("local", *argv))
        return lab.Result(list(argv), 0, "", "")

    def fetch_dir(self, remote_dir: str, local_dir: Path) -> None:
        self.fetched.append((remote_dir, local_dir))

    # -- assertions ---------------------------------------------------------------------------

    def lab_calls(self, script: str) -> list[tuple[str, ...]]:
        return [c for c in self.calls if c[0] == "lab" and c[1] == script]

    def started(self) -> list[str]:
        """The process names passed to lab-start.sh, in order."""
        names = []
        for call in self.lab_calls("start"):
            args = list(call[2:])
            if args[:1] == ["--netns"]:
                args = args[2:]
            names.append(args[0])
        return names


def run_args(**overrides):
    """An argparse namespace as `cmd_run` expects it."""
    import argparse

    defaults = dict(
        host="fake-host", runs_dir="", dry_run=False, verbose=False, command="run",
        scenario="", detach=False, repetitions=None, pair=None, max_load=1.0, wait_load=0,
        force=False, report=None, no_report=True, slack=10, max_log_bytes=4096,
        server_host=None, server_addr=None, allow_unprovenanced=False, config=None, netem=None,
        bitrate=None,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# --------------------------------------------------------------------------------------------
# scenario validation
# --------------------------------------------------------------------------------------------


class ScenarioTests(unittest.TestCase):
    def test_a_minimal_scenario_gets_sensible_defaults(self):
        scenario = lab.parse_scenario(MINIMAL)
        self.assertEqual(scenario.name, "unit")
        self.assertEqual(scenario.config, "s1")
        self.assertEqual(scenario.netem, "clean")
        self.assertEqual(scenario.pairs, [("rust", "rust")])
        self.assertEqual(scenario.target, "pingpong")
        self.assertEqual(scenario.total_duration, 5)
        self.assertEqual(scenario.key, "labkey")

    def test_total_duration_accounts_for_a_delayed_workload(self):
        scenario = lab.parse_scenario({
            "name": "x",
            "workloads": [
                {"type": "ping", "tag": "a", "duration": 30},
                {"type": "bulk", "tag": "b", "duration": 20, "start_after": 25},
            ],
        })
        self.assertEqual(scenario.total_duration, 45)

    def test_iperf3_cannot_share_a_scenario_with_the_pingpong_workloads(self):
        with self.assertRaisesRegex(lab.LabError, "exactly one target"):
            lab.parse_scenario({
                "name": "x",
                "workloads": [
                    {"type": "iperf3", "tag": "a", "duration": 5},
                    {"type": "ping", "tag": "b", "duration": 5},
                ],
            })

    def test_an_iperf3_only_scenario_targets_iperf3(self):
        scenario = lab.parse_scenario({
            "name": "x", "workloads": [{"type": "iperf3", "tag": "a", "duration": 5}],
        })
        self.assertEqual(scenario.target, "iperf3")

    def test_every_invalid_scenario_is_refused_by_field_name(self):
        cases = {
            "name": {"name": "has space", "workloads": MINIMAL["workloads"]},
            "config": {"name": "x", "config": "s9", "workloads": MINIMAL["workloads"]},
            "netem": {"name": "x", "netem": "nope", "workloads": MINIMAL["workloads"]},
            "pairs": {"name": "x", "pairs": [["rust", "c"]], "workloads": MINIMAL["workloads"]},
            "workloads": {"name": "x", "workloads": []},
            "tunnel_port": {"name": "x", "tunnel_port": 80, "workloads": MINIMAL["workloads"]},
            "listen_port": {"name": "x", "listen_port": 1234, "workloads": MINIMAL["workloads"]},
            "unknown": {"name": "x", "nonsense": 1, "workloads": MINIMAL["workloads"]},
            "key": {"name": "x", "client_flags": {"key": "k"},
                    "workloads": MINIMAL["workloads"]},
        }
        for what, raw in cases.items():
            with self.subTest(what=what):
                with self.assertRaises(lab.LabError):
                    lab.parse_scenario(raw)

    def test_a_duplicate_or_malformed_workload_tag_is_refused(self):
        for workloads in (
            [{"type": "ping", "tag": "a", "duration": 5},
             {"type": "bulk", "tag": "a", "duration": 5}],
            [{"type": "ping", "tag": "a b", "duration": 5}],
            [{"type": "nope", "tag": "a", "duration": 5}],
            [{"type": "ping", "tag": "a", "duration": 0}],
            [{"type": "ping", "tag": "a", "duration": 5, "start_after": -1}],
        ):
            with self.subTest(workloads=workloads):
                with self.assertRaises(lab.LabError):
                    lab.parse_scenario({"name": "x", "workloads": workloads})

    def test_the_scenarios_in_the_repository_all_parse(self):
        directory = Path(__file__).resolve().parent / "scenarios"
        files = sorted(directory.glob("*.json"))
        self.assertTrue(files, "no scenarios to check")
        for path in files:
            with self.subTest(path=path.name):
                scenario = lab.load_scenario(path)
                self.assertTrue(scenario.workloads)
                self.assertLessEqual(scenario.total_duration, 8 * 3600)

    def test_the_soak_scenario_is_what_plan_11_4_asks_for(self):
        scenario = lab.load_scenario(
            Path(__file__).resolve().parent / "scenarios" / "soak-s1-wan50.json"
        )
        self.assertEqual(scenario.netem, "wan50")
        self.assertEqual(scenario.config, "s1")
        self.assertEqual(scenario.sample_interval, 60)
        self.assertEqual(scenario.snmp_period, 60)
        self.assertGreaterEqual(scenario.total_duration, 6 * 3600)
        # DECISIONS D28: the soak runs the PRODUCTION closewait default (server 30 s), because
        # that linger is the mechanism most likely to accumulate descriptors — `closewait 0`
        # would remove the thing being measured. The headroom comes from lab-start.sh's
        # `ulimit -n 65536` instead. (This assertion used to demand `closewait 0`; it was left
        # behind when D28 changed the scenario, and lab_test.py is not in the cargo gate.)
        self.assertNotIn("closewait", scenario.server_flags)
        self.assertNotIn("closewait", lab.merged_flags(scenario, "server"))
        churn = next(w for w in scenario.workloads if w.type == "churn")
        self.assertEqual(churn.options["rate"], 20)
        self.assertEqual(churn.options["min_bytes"], "10k")
        self.assertEqual(churn.options["max_bytes"], "1m")
        self.assertEqual(churn.options["long_lived"], 10)
        self.assertTrue(churn.options["burst_every"] > 0)


# --------------------------------------------------------------------------------------------
# command lines
# --------------------------------------------------------------------------------------------


class CommandLineTests(unittest.TestCase):
    def plan(self, raw=None) -> lab.RunPlan:
        scenario = lab.parse_scenario(raw or MINIMAL)
        return lab.plan_runs(scenario, "20260923T120000Z")[0]

    def test_flags_render_go_style(self):
        self.assertEqual(
            lab.render_flags({"mode": "normal", "nocomp": True, "quiet": False, "conn": 4}),
            ["-mode", "normal", "-nocomp", "-conn", "4"],
        )

    def test_scenario_flags_override_the_configuration(self):
        scenario = lab.parse_scenario({
            **MINIMAL, "config": "s1", "client_flags": {"conn": 1, "autoexpire": 60},
        })
        flags = lab.merged_flags(scenario, "client")
        self.assertEqual(flags["conn"], 1)
        self.assertEqual(flags["autoexpire"], 60)
        self.assertEqual(flags["crypt"], "xor")
        self.assertEqual(lab.merged_flags(scenario, "server")["sockbuf"], 67108868)

    def test_the_run_id_names_the_pair_and_the_repetition(self):
        scenario = lab.parse_scenario({
            **MINIMAL, "pairs": [["go", "go"], ["rust", "rust"], ["go", "rust"]],
            "repetitions": 2,
        })
        runs = lab.plan_runs(scenario, "STAMP")
        self.assertEqual(
            [r.runid for r in runs],
            ["unit-gg-r1-STAMP", "unit-rr-r1-STAMP", "unit-gr-r1-STAMP",
             "unit-gg-r2-STAMP", "unit-rr-r2-STAMP", "unit-gr-r2-STAMP"],
        )
        # Interleaved: every pair runs once before any pair runs twice.
        self.assertEqual([r.repetition for r in runs], [1, 1, 1, 2, 2, 2])

    def test_the_client_and_server_command_lines(self):
        plan = self.plan()
        server = plan.server_argv()
        self.assertEqual(server[0], "$HOME/kcptun-lab/bin/rust/kr-server")
        self.assertIn("-l", server)
        self.assertEqual(server[server.index("-l") + 1], ":29900")
        self.assertEqual(server[server.index("-t") + 1], "127.0.0.1:22600")
        self.assertEqual(server[server.index("-key") + 1], "labkey")
        self.assertEqual(server[server.index("-crypt") + 1], "xor")

        client = plan.client_argv()
        self.assertEqual(client[0], "$HOME/kcptun-lab/bin/rust/kr-client")
        self.assertEqual(client[client.index("-l") + 1], "127.0.0.1:12948")
        self.assertEqual(client[client.index("-r") + 1], "10.200.0.2:29900")
        self.assertEqual(client[client.index("-conn") + 1], "4")

    def test_a_go_pair_uses_the_go_binaries(self):
        plan = self.plan({**MINIMAL, "pairs": [["go", "go"]]})
        self.assertEqual(plan.client_argv()[0], "$HOME/kcptun-lab/bin/go/kg-client")
        self.assertEqual(plan.server_argv()[0], "$HOME/kcptun-lab/bin/go/kg-server")

    def test_no_argument_anywhere_names_a_port_below_4000(self):
        # lab-start.sh refuses one, but finding out at 3 a.m. six hours in is not the plan.
        plan = self.plan({**MINIMAL, "workloads": [
            {"type": "iperf3", "tag": "up", "duration": 5},
        ]})
        import re

        argvs = [plan.client_argv(), plan.server_argv(), plan.target_argv(),
                 plan.sampler_argv({plan.client_name: 42}),
                 plan.workload_argv(plan.scenario.workloads[0])]
        for argv in argvs:
            for arg in argv:
                for match in re.finditer(r":(\d{1,5})\b", arg):
                    self.assertGreaterEqual(int(match.group(1)), 4000, f"{arg} in {argv}")

    def test_the_snmp_log_file_name_carries_no_go_time_layout_token(self):
        # kcptun runs the FILE part of -snmplog through Go's reference-time formatter, so a
        # digit in the name would be rewritten into a date. Only the directory may carry one.
        for plan in (self.plan(), self.plan({**MINIMAL, "pairs": [["go", "go"]]})):
            for argv in (plan.client_argv(), plan.server_argv()):
                path = argv[argv.index("-snmplog") + 1]
                directory, _, filename = path.rpartition("/")
                self.assertTrue(directory.endswith(plan.runid), path)
                self.assertFalse(any(c.isdigit() for c in filename), filename)
                for token in ("Jan", "Mon", "MST", "PM", "pm"):
                    self.assertNotIn(token, filename)

    def test_the_sampler_watches_every_process_it_was_given_a_pid_for(self):
        plan = self.plan()
        argv = plan.sampler_argv({plan.client_name: 11, plan.server_name: 22})
        self.assertIn("--pid", argv)
        self.assertIn("cli=11", argv)
        self.assertIn("srv=22", argv)
        self.assertNotIn("tgt=", " ".join(argv))
        self.assertIn(f"cli=$HOME/kcptun-lab/logs/{plan.client_name}.log", argv)
        # …and it must still be expandable once quoted for the remote shell: a single-quoted
        # `'cli=$HOME/...'` reaches lab-start.sh as a literal `$HOME`, the sampler opens a path
        # that does not exist, and the log cap silently never fires (blank `log_bytes` column).
        quoted = lab.remote_quote(f"cli=$HOME/kcptun-lab/logs/{plan.client_name}.log")
        self.assertEqual(quoted,
                         f'cli="$HOME/kcptun-lab/logs/{plan.client_name}.log"')
        # It must outlive the traffic, then stop by itself.
        self.assertGreater(int(argv[argv.index("--duration") + 1]),
                           plan.scenario.total_duration)
        self.assertEqual(argv[argv.index("--interval") + 1], "60")

    def test_the_target_outlives_the_traffic(self):
        plan = self.plan()
        argv = plan.target_argv()
        self.assertEqual(argv[0], "$HOME/kcptun-lab/bin/lab/kr-pingpong")
        self.assertGreater(int(argv[argv.index("--duration") + 1]),
                           plan.scenario.total_duration)

    def test_workload_options_become_flags(self):
        plan = self.plan({**MINIMAL, "workloads": [{
            "type": "churn", "tag": "c", "duration": 7, "rate": 20,
            "min_bytes": "10k", "max_bytes": "1m", "verify": True, "size_dist": "log",
        }]})
        argv = plan.workload_argv(plan.scenario.workloads[0])
        self.assertEqual(argv[:2], ["$HOME/kcptun-lab/bin/lab/kr-pingpong", "churn"])
        self.assertEqual(argv[argv.index("--min-bytes") + 1], "10k")
        self.assertEqual(argv[argv.index("--size-dist") + 1], "log")
        self.assertIn("--verify", argv)
        self.assertEqual(argv[argv.index("--duration") + 1], "7")
        self.assertEqual(argv[argv.index("--tag") + 1], "c")

    def test_iperf3_options_map_to_iperf3_flags(self):
        plan = self.plan({**MINIMAL, "workloads": [{
            "type": "iperf3", "tag": "down", "duration": 30,
            "reverse": True, "parallel": 4, "omit": 2, "bitrate": "50M",
        }]})
        argv = plan.workload_argv(plan.scenario.workloads[0])
        self.assertEqual(argv[:2], ["iperf3", "-c"])
        self.assertEqual(argv[argv.index("-p") + 1], "12948")
        self.assertEqual(argv[argv.index("-t") + 1], "30")
        self.assertIn("-R", argv)
        self.assertEqual(argv[argv.index("-P") + 1], "4")
        self.assertEqual(argv[argv.index("-b") + 1], "50M")
        self.assertIn("--logfile", argv)

    def test_an_unknown_iperf3_option_is_refused(self):
        plan = self.plan({**MINIMAL, "workloads": [{
            "type": "iperf3", "tag": "x", "duration": 5, "nonsense": 1,
        }]})
        with self.assertRaises(lab.LabError):
            plan.workload_argv(plan.scenario.workloads[0])

    def test_remote_quoting_keeps_home_expandable(self):
        self.assertEqual(lab.remote_quote("$HOME/kcptun-lab/x"), '"$HOME/kcptun-lab/x"')
        self.assertEqual(lab.remote_quote("a b"), "'a b'")
        self.assertEqual(lab.remote_quote("-l"), "-l")
        # `label=path` values (`--log cli=$HOME/...`) expand too — see the sampler test.
        self.assertEqual(lab.remote_quote("cli=$HOME/kcptun-lab/x"), 'cli="$HOME/kcptun-lab/x"')
        # …but only for a plain label; anything else is quoted whole so the shell cannot see it.
        self.assertEqual(lab.remote_quote("a;b=$HOME/x"), "'a;b=$HOME/x'")
        self.assertEqual(lab.remote_quote("cli=$HOME"), "'cli=$HOME'")


# --------------------------------------------------------------------------------------------
# the run flow
# --------------------------------------------------------------------------------------------


class RunFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.scenario_path = self.root / "s.json"
        self.scenario_path.write_text(json.dumps({
            "name": "unit", "settle": 0, "sample_interval": 5, "snmp_period": 5,
            "workloads": [{"type": "ping", "tag": "lat", "duration": 1}],
        }))

    def do_run(self, **overrides) -> tuple[FakeRunner, object]:
        runner = FakeRunner()
        args = run_args(scenario=str(self.scenario_path),
                        runs_dir=str(self.root / "runs"), **overrides)
        self.assertEqual(lab.cmd_run(runner, args), 0)
        return runner, args

    def test_a_dry_run_writes_nothing_on_the_laptop(self):
        # `--dry-run` previews commands. It used to still create the run directory and its
        # state.json, and (with reports on) drop an empty, fabricated report into the
        # git-tracked docs/lab-results/ — a file `git status` then offers to commit.
        runs = self.root / "runs"
        report = self.root / "report.md"
        runner = FakeRunner()
        runner.dry_run = True
        args = run_args(scenario=str(self.scenario_path), runs_dir=str(runs),
                        dry_run=True, no_report=False, report=str(report))
        self.assertEqual(lab.cmd_run(runner, args), 0)
        self.assertFalse(runs.exists(), sorted(p.name for p in self.root.iterdir()))
        self.assertFalse(report.exists())

    def test_a_run_starts_stops_and_collects_in_the_right_order(self):
        runner, args = self.do_run()
        started = runner.started()
        self.assertEqual(len(started), 5, started)
        self.assertTrue(started[0].endswith("-tgt"), started)
        self.assertTrue(started[1].endswith("-srv"), started)
        self.assertTrue(started[2].endswith("-cli"), started)
        self.assertTrue(started[3].endswith("-smp"), started)
        self.assertTrue(started[4].endswith("-w0"), started)

        scripts = [c[1] for c in runner.calls if c[0] == "lab"]
        # The read-only preflight port check comes first, then the netem profile, and only then
        # is anything started.
        self.assertEqual(scripts[0], "baseline")
        self.assertEqual(runner.lab_calls("baseline")[0][2], "--ports-only")
        self.assertEqual(scripts[1], "netns")
        self.assertIn("collect", scripts)
        self.assertIn("wait", scripts)
        self.assertIn("signal", scripts)
        self.assertIn("stop", scripts)
        # SIGUSR1 (the SNMP dump) must come before the processes are stopped.
        self.assertLess(scripts.index("signal"), scripts.index("stop"))
        # ... and the collection after.
        self.assertGreater(len(scripts) - 1 - scripts[::-1].index("collect"),
                           scripts.index("stop"))

    def test_the_tunnel_ends_run_in_their_own_namespaces(self):
        runner, _ = self.do_run()
        placement = {}
        for call in runner.lab_calls("start"):
            args = list(call[2:])
            netns = None
            if args[:1] == ["--netns"]:
                netns, args = args[1], args[2:]
            placement[args[0].rsplit("-", 1)[1]] = netns
        self.assertEqual(placement["tgt"], "kr-srv")
        self.assertEqual(placement["srv"], "kr-srv")
        self.assertEqual(placement["cli"], "kr-cli")
        self.assertEqual(placement["w0"], "kr-cli")
        # The sampler reads /proc, which is not namespaced; it stays outside.
        self.assertIsNone(placement["smp"])

    def test_only_usr1_is_ever_signalled(self):
        runner, _ = self.do_run()
        for call in runner.lab_calls("signal"):
            self.assertEqual(call[2], "USR1")

    def test_stop_only_names_processes_this_run_started(self):
        runner, _ = self.do_run()
        started = set(runner.started()) | {n for n in runner.started()}
        for call in runner.lab_calls("stop"):
            for name in call[2:]:
                self.assertTrue(name.startswith("unit-rr-r1-"), name)
            self.assertNotIn("--all", call)
        self.assertTrue(started)

    def test_a_detached_run_starts_and_leaves_a_state_file_behind(self):
        runner, args = self.do_run(detach=True)
        self.assertEqual([c[1] for c in runner.calls if c[0] == "lab" and c[1] == "stop"], [])
        states = list((self.root / "runs").glob("*/*/state.json"))
        self.assertEqual(len(states), 1)
        state = json.loads(states[0].read_text())
        self.assertEqual(state["scenario"], "unit")
        self.assertEqual(len(state["names"]), 5)
        self.assertTrue(state["remote_dir"].endswith(state["runid"]))
        # Which host and which artefact, recorded with the run rather than in somebody's notes:
        # the same numbers mean opposite things for a musl build and a glibc one (D07).
        self.assertEqual(state["host"], "fake-host")
        self.assertIn("x86_64-unknown-linux-gnu (glibc 2.17)", state["build"])

        # `collect` finishes it: signal, stop, collect, fetch.
        later = FakeRunner()
        collect_args = run_args(command="collect", runid=state["runid"],
                                runs_dir=str(self.root / "runs"), wait=False)
        self.assertEqual(lab.cmd_collect(later, collect_args), 0)
        scripts = [c[1] for c in later.calls if c[0] == "lab"]
        self.assertEqual(scripts.count("signal"), 1)
        self.assertIn("stop", scripts)
        self.assertEqual(len(later.fetched), 1)

    def test_a_real_run_still_waits_for_the_snmp_dump(self):
        # This module zeroes `SNMP_SETTLE_SECONDS` so the suite does not pay a real second in
        # every test that reaches `finish_run`. A real run must still give the SIGUSR1 dump time
        # to reach the process log before the tunnel is stopped, or the run's closing SNMP
        # totals are simply missing, so the shipped value is asserted here.
        self.assertGreaterEqual(_REAL_SNMP_SETTLE, 1.0)
        self.assertEqual(lab.SNMP_SETTLE_SECONDS, 0)

    def test_detaching_a_multi_run_scenario_is_refused(self):
        self.scenario_path.write_text(json.dumps({
            "name": "unit", "repetitions": 2,
            "workloads": [{"type": "ping", "tag": "lat", "duration": 1}],
        }))
        runner = FakeRunner()
        args = run_args(scenario=str(self.scenario_path), detach=True,
                        runs_dir=str(self.root / "runs"))
        with self.assertRaisesRegex(lab.LabError, "--detach"):
            lab.cmd_run(runner, args)
        self.assertEqual(runner.lab_calls("start"), [])

    def test_a_busy_host_stops_the_run_unless_forced(self):
        class Busy(FakeRunner):
            def load_average(self):
                return 3.5

        runner = Busy()
        args = run_args(scenario=str(self.scenario_path), runs_dir=str(self.root / "runs"))
        with self.assertRaisesRegex(lab.LabError, "load average"):
            lab.cmd_run(runner, args)
        self.assertEqual(runner.lab_calls("start"), [])

        forced = Busy()
        lab.cmd_run(forced, run_args(scenario=str(self.scenario_path),
                                     runs_dir=str(self.root / "runs"), force=True))
        self.assertTrue(forced.lab_calls("start"))

    def test_an_existing_namespace_is_reprofiled_rather_than_recreated(self):
        runner = FakeRunner()
        runner.netns_status = "kr-cli\nkr-srv\n"
        lab.cmd_run(runner, run_args(scenario=str(self.scenario_path),
                                     runs_dir=str(self.root / "runs")))
        netns_calls = [c[2] for c in runner.lab_calls("netns")]
        self.assertIn("set", netns_calls)
        self.assertNotIn("up", netns_calls)

    def test_the_pair_override_selects_one_pair(self):
        runner, _ = self.do_run(pair="go:rust")
        self.assertTrue(all("unit-gr-" in name for name in runner.started()),
                        runner.started())
        with self.assertRaises(lab.LabError):
            lab.cmd_run(FakeRunner(), run_args(scenario=str(self.scenario_path),
                                               runs_dir=str(self.root / "runs"),
                                               pair="go:perl"))


# --------------------------------------------------------------------------------------------
# Build provenance (12.0)
# --------------------------------------------------------------------------------------------


class ProvenanceTests(unittest.TestCase):
    """A run that cannot name the binary it is about to execute must not start.

    11.3 ran 27 WAN runs whose `server_build` was the empty string, because the stamp lived one
    directory above the binaries and the far host's `kr-server` had none beside it. Nothing
    failed and nothing shouted, so a whole campaign — including its headline 0.75x — cannot be
    attributed to any revision. Every test here is that failure, refused.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.scenario_path = self.root / "s.json"
        self.scenario_path.write_text(json.dumps({
            "name": "unit", "settle": 0, "sample_interval": 5, "snmp_period": 5,
            "workloads": [{"type": "ping", "tag": "lat", "duration": 1}],
        }))

    def args(self, **overrides):
        return run_args(scenario=str(self.scenario_path),
                        runs_dir=str(self.root / "runs"), **overrides)

    def run_ok(self, runner=None, **overrides) -> FakeRunner:
        runner = runner or FakeRunner()
        self.assertEqual(lab.cmd_run(runner, self.args(**overrides)), 0)
        return runner

    def refused(self, runner, **overrides) -> str:
        with self.assertRaises(lab.LabError) as caught:
            lab.cmd_run(runner, self.args(**overrides))
        # Refused before anything happened on the host: no baseline, no namespace, no process.
        self.assertEqual(runner.lab_calls("start"), [])
        self.assertEqual(runner.lab_calls("baseline"), [])
        self.assertEqual(runner.lab_calls("netns"), [])
        # ...and nothing on the laptop either. An empty session directory per failed attempt
        # would accumulate under runs/ and make `find_session` ambiguous ("matches N sessions").
        runs = self.root / "runs"
        self.assertEqual(sorted(p.name for p in runs.glob("*")) if runs.exists() else [], [])
        return str(caught.exception)

    def states(self, runner_runs_dir: Path) -> list[dict]:
        return [json.loads(p.read_text())
                for p in sorted(runner_runs_dir.glob("*/*/state.json"))]

    def test_a_missing_build_stamp_refuses_the_run(self):
        runner = FakeRunner()
        runner.stamps["rust"] = ""
        message = self.refused(runner)
        self.assertIn("unprovenanced", message)
        self.assertIn("bin/rust/BUILD.txt", message)

    def test_the_refusal_says_which_deployment_would_fix_it(self):
        runner = FakeRunner()
        runner.stamps["rust"] = ""
        message = self.refused(runner)
        # The wrapper, not `deploy.sh`: the script has no `--host` (it exits 2 with "unknown
        # argument"), and dropping the flag to make it run would deploy to $KCPTUN_LAB_HOST,
        # whose default is lab-arm64 — the production box, not the one that was refused.
        self.assertIn("tools/lab/lab.py --host fake-host deploy --rust", message)
        self.assertNotIn("deploy.sh --host", message)

    def test_the_remedy_is_a_command_line_the_wrapper_actually_accepts(self):
        # Parsed back with lab.py's own parser: a refusal's one actionable line is worth
        # nothing if pasting it is an argparse error — or, worse, a deployment to a host
        # nobody named.
        runner = FakeRunner()
        runner.stamps["rust"] = ""
        line = next(l for l in self.refused(runner).splitlines() if "Redeploy it:" in l)
        remedy = line.split("Redeploy it:", 1)[1].split()
        self.assertEqual(remedy[0], "tools/lab/lab.py")
        parsed = lab.build_parser().parse_args(remedy[1:])
        self.assertEqual(parsed.host, "fake-host")
        self.assertEqual(parsed.command, "deploy")
        self.assertTrue(parsed.rust)

    def test_the_remedy_keeps_a_glibc_host_on_glibc(self):
        # A stamp that resolved says which libc is deployed there; a redeploy without `--gnu`
        # would quietly swap the host to static musl, whose RSS after a burst is a different
        # measurement altogether (DECISIONS D07). The musl case must not acquire the flag.
        runner = FakeRunner()
        runner.hashes["kr-server"] = "99" * 32
        self.assertIn("tools/lab/lab.py --host fake-host deploy --rust --gnu",
                      self.refused(runner))
        musl = FakeRunner()
        musl.stamps["rust"] = stamp_text("rust", target="x86_64-unknown-linux-musl",
                                         libc="static musl")
        musl.hashes["kr-server"] = "99" * 32
        message = self.refused(musl)
        self.assertIn("tools/lab/lab.py --host fake-host deploy --rust", message)
        self.assertNotIn("--gnu", message)

    def test_an_unstamped_glibc_host_is_not_redeployed_as_musl(self):
        # The case this gate actually fires on: no per-family stamp at all, which is every host
        # deployed before 12.0. The stamp's own `libc` is empty there, so a remedy built from
        # it alone omits `--gnu` — and `deploy.sh` defaults to static musl, whose allocator
        # returns 4.9% of a burst where glibc returns 95.6% (DECISIONS D07). Following the
        # refusal's own instruction would therefore change what Step 12 is measuring. The
        # pre-12.0 aggregate line is not provenance, but it does say `glibc 2.17`, and that is
        # enough to keep the remedy from making the substitution.
        runner = FakeRunner()
        runner.stamps["rust"] = ""
        runner.stamps["legacy"] = ("host x86_64, rust x86_64-unknown-linux-gnu (glibc 2.17), "
                                   "profile release, rev 03afc40-dirty\n")
        message = self.refused(runner)
        line = next(l for l in message.splitlines() if "Redeploy it:" in l)
        parsed = lab.build_parser().parse_args(line.split("Redeploy it:", 1)[1].split()[1:])
        self.assertEqual(parsed.host, "fake-host")
        self.assertTrue(parsed.rust)
        self.assertTrue(parsed.gnu)
        # The glibc version as well: `--gnu` alone targets deploy.sh's default, which is a
        # different binary from the one a host deployed with `--glibc 2.39` is running.
        self.assertEqual(parsed.glibc, "2.17")

    def test_an_unstamped_host_that_says_nothing_admits_the_remedy_may_flip_its_libc(self):
        # Nothing on the host names a libc, so the remedy cannot know which one to ask for.
        # Guessing is what the previous test refuses to do; saying so is the alternative,
        # because a bare `deploy --rust` here IS deploy.sh's musl default.
        runner = FakeRunner()
        runner.stamps["rust"] = ""
        message = self.refused(runner)
        self.assertIn("deploy.sh defaults to static musl", message)
        self.assertIn("--gnu", message)
        # ...and the caveat is prose on its own line, never trailing the pasteable command.
        line = next(l for l in message.splitlines() if "Redeploy it:" in l)
        self.assertNotIn("--gnu", line)
        lab.build_parser().parse_args(line.split("Redeploy it:", 1)[1].split()[1:])

    def test_a_profiling_host_is_not_quietly_rebuilt_as_release(self):
        # `--profile profiling` is different codegen and carries the symbols `perf` wants;
        # `deploy.sh` defaults to `release`, so a resolved stamp's profile is carried back too.
        runner = FakeRunner()
        runner.stamps["rust"] = stamp_text("rust", profile="profiling")
        runner.hashes["kr-server"] = "99" * 32
        line = next(l for l in self.refused(runner).splitlines() if "Redeploy it:" in l)
        parsed = lab.build_parser().parse_args(line.split("Redeploy it:", 1)[1].split()[1:])
        self.assertEqual(parsed.profile, "profiling")
        # A `release` host must not acquire the flag, or every refusal grows noise.
        plain = FakeRunner()
        plain.hashes["kr-server"] = "99" * 32
        self.assertNotIn("--profile", self.refused(plain))

    def test_the_pre_12_0_aggregate_stamp_is_not_accepted_in_its_place(self):
        # What lab-arm64 actually had during 11.3: one bin/BUILD.txt describing whatever was
        # copied last, and nothing at all beside the kr-server that ran.
        runner = FakeRunner()
        runner.stamps["rust"] = ""
        runner.stamps["legacy"] = ("host aarch64, rust aarch64-unknown-linux-musl (static "
                                   "musl), profile release, rev 03afc40-dirty\n")
        message = self.refused(runner)
        self.assertIn("pre-12.0 aggregate", message)
        self.assertIn("not this binary", message)

    def test_a_stamp_missing_a_required_field_names_the_field(self):
        for field_name in ("commit", "libc", "target", "deployed"):
            with self.subTest(field=field_name):
                runner = FakeRunner()
                runner.stamps["rust"] = stamp_text("rust", drop=(field_name,))
                self.assertIn(f"records no {field_name}", self.refused(runner))

    def test_a_stamp_written_outside_a_checkout_is_refused(self):
        # deploy.sh writes `commit=unknown` when it cannot reach git; that is not a revision.
        runner = FakeRunner()
        runner.stamps["rust"] = stamp_text("rust", commit="unknown")
        self.assertIn("not a revision", self.refused(runner))

    def test_a_stamp_for_another_family_of_binaries_is_refused(self):
        runner = FakeRunner()
        runner.stamps["rust"] = stamp_text("go", target="linux/amd64", libc="none",
                                           binaries=("kg-client", "kg-server"))
        self.assertIn("describes a 'go' deployment", self.refused(runner))

    def test_a_binary_replaced_without_redeploying_is_caught_by_its_hash(self):
        # The stamp is fresh and complete; the file beside it is somebody else's build. This is
        # the case a stamp alone cannot catch, and the one 11.3's kr-server actually was.
        runner = FakeRunner()
        runner.hashes["kr-server"] = "99" * 32
        message = self.refused(runner)
        self.assertIn("kr-server", message)
        self.assertIn("replaced without redeploying", message)

    def test_a_binary_the_host_cannot_hash_is_refused(self):
        runner = FakeRunner()
        runner.hashes.pop("kr-client")
        self.assertIn("could not be hashed", self.refused(runner))

    def test_a_stamp_that_records_no_hash_for_the_binary_is_refused(self):
        runner = FakeRunner()
        runner.stamps["rust"] = stamp_text("rust", drop=("sha256.kr-server",))
        self.assertIn("no sha256 for kr-server", self.refused(runner))

    def test_each_end_is_checked_against_its_own_implementations_stamp(self):
        # A GR pair runs a Go client and a Rust server: an unstamped Go deployment must refuse
        # the run even though the Rust one is perfect.
        runner = FakeRunner()
        runner.stamps["go"] = ""
        message = self.refused(runner, pair="go:rust")
        self.assertIn("go client", message)
        self.assertIn("bin/go/BUILD.txt", message)

    def test_unstamped_lab_tools_refuse_the_run_too(self):
        # `kr-labsample` takes every RSS and CPU number and `kr-pingpong` every latency
        # percentile; an unidentified instrument is an unidentified measurement.
        runner = FakeRunner()
        runner.stamps["lab"] = ""
        message = self.refused(runner)
        self.assertIn("lab sampler", message)
        self.assertIn("tools/lab/lab.py --host fake-host deploy --tools", message)

    def test_the_pingpong_target_is_checked_as_well_as_the_sampler(self):
        # The scenario's target is `kr-pingpong`; it is what every latency percentile is
        # measured against, so a swapped one is as disqualifying as a swapped tunnel.
        runner = FakeRunner()
        runner.hashes["kr-pingpong"] = "99" * 32
        message = self.refused(runner)
        self.assertIn("kr-pingpong", message)
        self.assertIn("replaced without redeploying", message)

    def test_a_run_records_the_commit_libc_and_hash_of_both_ends(self):
        runner = self.run_ok(pair="go:rust")
        state, = self.states(self.root / "runs")
        client = state["client_build_detail"]
        server = state["server_build_detail"]
        tools = state["tools_build_detail"]
        self.assertEqual(tools["kind"], "lab")
        self.assertEqual(tools["sha256"], FAKE_SHA["kr-labsample"])
        self.assertEqual(client["kind"], "go")
        self.assertEqual(client["commit"], FAKE_COMMIT)
        self.assertEqual(client["libc"], "none")
        self.assertEqual(client["sha256"], FAKE_SHA["kg-client"])
        self.assertTrue(client["binary"].endswith("/kg-client"), client["binary"])
        self.assertEqual(server["kind"], "rust")
        self.assertEqual(server["libc"], "glibc 2.17")
        self.assertEqual(server["sha256"], FAKE_SHA["kr-server"])
        self.assertTrue(server["binary"].endswith("/kr-server"), server["binary"])
        self.assertNotIn("problem", client)
        self.assertNotIn("problem", server)
        # The one-line summaries every existing report quotes are still there and non-empty.
        self.assertIn("linux/amd64", state["build"])
        self.assertIn("x86_64-unknown-linux-gnu (glibc 2.17)", state["server_build"])
        self.assertTrue(runner.started())

    def test_the_stamp_is_read_once_per_host_and_side_not_once_per_run(self):
        runner = self.run_ok(repetitions=3)
        reads = [c for c in runner.calls if c[0] == "ssh" and "BUILD.txt" in c[1]]
        # Two stamp files for three runs: bin/rust/BUILD.txt and bin/lab/BUILD.txt. Both lab
        # tools are described by the one file, so it is read once however many binaries it
        # covers; the per-binary hashes are still checked individually.
        self.assertEqual(len(reads), 2, reads)
        hashed = sorted(c[1].split()[1].strip('"').rsplit("/", 1)[-1]
                        for c in runner.calls if c[0] == "ssh" and c[1].startswith("sha256sum"))
        self.assertEqual(hashed, ["kr-client", "kr-labsample", "kr-pingpong", "kr-server"])

    def test_a_dry_run_needs_no_deployment_at_all(self):
        runner = FakeRunner()
        runner.dry_run = True
        runner.stamps = {}
        runner.hashes = {}
        self.assertEqual(lab.cmd_run(runner, self.args(dry_run=True)), 0)

    def test_allow_unprovenanced_runs_but_stamps_the_report(self):
        report = self.root / "report.md"
        runner = FakeRunner()
        runner.stamps["rust"] = ""
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.run_ok(runner, allow_unprovenanced=True, no_report=False, report=str(report))
        warnings = [line for line in stderr.getvalue().splitlines() if "WARNING" in line]
        # Once per artefact, not once per run: a 12-run session would otherwise bury it.
        self.assertEqual(len(warnings), 2, warnings)  # rust client, rust server
        text = report.read_text()
        self.assertIn("UNPROVENANCED", text)
        self.assertIn("no build stamp", text)
        state, = self.states(self.root / "runs")
        self.assertIn("problem", state["server_build_detail"])

    def test_an_unprovenanced_pingpong_reaches_the_report_it_takes_the_numbers_for(self):
        # The gate demanded a stamp for `kr-pingpong` but recorded only the four keys in
        # BUILD_DETAIL_KEYS, so a swapped target beside an intact `kr-labsample` produced a
        # report with no banner at all — `--allow-unprovenanced` promising a marker and then
        # printing a clean document. That is 11.3's failure shape inside 11.3's own fix, for
        # the instrument that emits every latency percentile.
        report = self.root / "report.md"
        runner = FakeRunner()
        runner.hashes["kr-pingpong"] = "99" * 32
        with contextlib.redirect_stderr(io.StringIO()):
            self.run_ok(runner, allow_unprovenanced=True, no_report=False, report=str(report))
        text = report.read_text()
        self.assertIn("UNPROVENANCED", text)
        self.assertIn("kr-pingpong", text)
        self.assertIn("pingpong artefact", text)
        self.assertIn("replaced without redeploying", text)
        state, = self.states(self.root / "runs")
        self.assertIn("problem", state["target_build_detail"])
        # ...and only the target: `kr-labsample` shares the stamp file but is a different file
        # on disk, and it hashed correctly, so it is not smeared with the target's problem.
        self.assertNotIn("problem", state["tools_build_detail"])

    def test_a_clean_report_names_the_pingpong_that_produced_its_percentiles(self):
        # The other half: with everything provenanced the report must still say *which*
        # `kr-pingpong` — it is both the echo target and the workload — or the latency rows
        # are quotable but not checkable, which is what 12.0 exists to stop.
        report = self.root / "report.md"
        self.run_ok(no_report=False, report=str(report))
        text = report.read_text()
        self.assertNotIn("UNPROVENANCED", text)
        self.assertIn("pingpong artefact", text)
        self.assertIn("kr-pingpong", text)
        self.assertIn(FAKE_SHA["kr-pingpong"][:16], text)
        state, = self.states(self.root / "runs")
        self.assertEqual(state["target_build_detail"]["sha256"], FAKE_SHA["kr-pingpong"])
        self.assertEqual(state["target_build_detail"]["kind"], "lab")
        # One host, one file: the netns arrangement echoes and measures with the same binary,
        # so a second entry would have the banner name one problem twice.
        self.assertNotIn("server_target_build_detail", state)

    def test_an_iperf3_target_records_no_pingpong_artefact_at_all(self):
        # `iperf3` is the host's own package and carries no stamp of ours, so the two target
        # keys are simply absent — and `artefact_lines` must stay silent rather than claim the
        # run predates 12.0.
        self.scenario_path.write_text(json.dumps({
            "name": "unit", "settle": 0, "sample_interval": 5, "snmp_period": 5,
            "workloads": [{"type": "iperf3", "tag": "bulk", "duration": 1}],
        }))
        report = self.root / "report.md"
        self.run_ok(no_report=False, report=str(report))
        state, = self.states(self.root / "runs")
        self.assertNotIn("target_build_detail", state)
        text = report.read_text()
        self.assertNotIn("UNPROVENANCED", text)
        self.assertNotIn("pingpong artefact", text)

    def test_a_report_from_a_state_written_before_12_0_says_the_artefact_is_unknown(self):
        lines = lab.artefact_lines({"runid": "old"}, "server")
        self.assertIn("not recorded", lines[0])
        self.assertIn("12.0", lines[0])

    def test_a_report_regenerated_from_a_pre_12_0_state_is_marked_unprovenanced(self):
        # Exactly the shape of 11.3's 27 states: a client summary, an empty `server_build` and
        # no identity for either end. `lab.py report` on one must not read as a measurement.
        state = {
            "runid": "old-rr-r1-STAMP", "scenario": "wan", "host": "cli-host", "mode": "wan",
            "server_host": "srv-host", "server_addr": "203.0.113.7", "config": "s1",
            "netem": "none (real path)", "client_impl": "rust", "server_impl": "rust",
            "repetition": 1, "target": "pingpong", "started_iso": "2026-09-23T21:40:15Z",
            "total_duration": 60, "client_argv": ["kr-client"], "server_argv": ["kr-server"],
            "build": "host x86_64, rust x86_64-unknown-linux-gnu (glibc 2.17)",
            "server_build": "", "workloads": [],
        }
        text = lab.markdown_report([state], [self.root])
        self.assertIn("UNPROVENANCED", text)
        self.assertIn("predates the 12.0 build stamp", text)

    def test_the_comparison_table_is_marked_unprovenanced_too(self):
        # `lab.py compare --report` is what a WAN rung is actually quoted from — 11.3's 0.75x
        # reached a document through this command, not through `markdown_report`. A session it
        # cannot attribute must not produce a table that reads as a clean measurement.
        import argparse

        impl = {"g": "go", "r": "rust"}
        session = self.root / "runs" / "20260923T230000Z-wan-s1-bulk"
        for index, pair in enumerate(("gg", "rr")):
            directory = session / f"wan-{pair}-r1-STAMP"
            directory.mkdir(parents=True)
            (directory / "state.json").write_text(json.dumps({
                "runid": directory.name, "scenario": "wan", "host": "cli-host", "mode": "wan",
                "server_host": "srv-host", "config": "s1", "netem": "none (real path)",
                "client_impl": impl[pair[0]], "server_impl": impl[pair[1]],
                "repetition": 1, "started_unix": index, "build": "host x86_64, rust …",
                "server_build": "", "workloads": [],
            }))
        report = self.root / "rung.md"
        args = argparse.Namespace(runs_dir=str(self.root / "runs"),
                                  session="20260923T230000Z", report=str(report))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(lab.cmd_compare(FakeRunner(), args), 0)
        for text in (out.getvalue(), report.read_text()):
            self.assertIn("UNPROVENANCED", text)
            self.assertIn("predates the 12.0 build stamp", text)
            # The table itself is still there, below the warning and not instead of it.
            self.assertLess(text.index("UNPROVENANCED"), text.index("### wan"))

    def test_a_provenanced_comparison_carries_no_warning(self):
        import argparse

        self.run_ok(no_report=False, report=str(self.root / "r.md"))
        session, = (self.root / "runs").glob("*")
        args = argparse.Namespace(runs_dir=str(self.root / "runs"),
                                  session=session.name, report=None)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(lab.cmd_compare(FakeRunner(), args), 0)
        text = out.getvalue()
        self.assertNotIn("UNPROVENANCED", text)
        # ...and it says what it *is*, not only what it is not. `compare` is the table a rung
        # is quoted from, so the provenanced half of 12.0 has to reach this document too: a
        # number read here weeks later must still name the artefact that produced it.
        self.assertIn("Artefacts:", text)
        self.assertIn(FAKE_COMMIT[:12], text)
        self.assertIn("glibc 2.17", text)
        self.assertIn("x86_64-unknown-linux-gnu", text)
        self.assertIn("`fake-host`", text)
        # One entry per distinct build, not one per end: client, server and both lab tools are
        # the same commit here, so the line stays short.
        self.assertEqual(text.count("rust `"), 1)
        self.assertLess(text.index("Medians over"), text.index("Artefacts:"))

    def test_an_unreachable_host_says_so_rather_than_asking_for_a_redeploy(self):
        # The provenance gate now runs before `preflight`, so it is the first thing a host that
        # is down, renamed or key-rejected fails. Telling the operator to redeploy would send
        # them at a command that fails the same way.
        class Unreachable(FakeRunner):
            def ssh(self, command, *, check=True, timeout=120.0):
                self.calls.append(("ssh", command))
                return lab.Result([], 255, "", "ssh: connect to host fake-host port 22: "
                                              "Connection refused\n")

        message = self.refused(Unreachable())
        self.assertIn("cannot read", message)
        self.assertIn("Connection refused", message)
        self.assertNotIn("Redeploy it", message)

    def test_a_host_that_disappears_between_the_stamp_and_the_hash_says_so_too(self):
        # The narrower half of the same case: the stamp read succeeded, so the host was up a
        # moment ago, and then ssh failed on `sha256sum`. `|| true` means a non-zero code can
        # only be ssh itself, so "could not be hashed (missing, or no sha256sum)" would be a
        # wrong diagnosis with a redeploy line attached that would fail the same way.
        class HashUnreachable(FakeRunner):
            def ssh(self, command, *, check=True, timeout=120.0):
                if command.startswith("sha256sum "):
                    self.calls.append(("ssh", command))
                    return lab.Result([], 255, "", "client_loop: send disconnect: "
                                                   "Broken pipe\n")
                return super().ssh(command, check=check, timeout=timeout)

        message = self.refused(HashUnreachable())
        self.assertIn("cannot hash", message)
        self.assertIn("Broken pipe", message)
        self.assertNotIn("Redeploy it", message)
        self.assertNotIn("could not be hashed", message)


# --------------------------------------------------------------------------------------------
# WAN mode: two hosts, the real path between them (step 11.3)
# --------------------------------------------------------------------------------------------


WAN_SCENARIO = {
    "name": "wan", "mode": "wan", "settle": 0, "sample_interval": 5, "snmp_period": 5,
    "server_host": "srv-host", "server_addr": "203.0.113.7",
    "workloads": [{"type": "ping", "tag": "lat", "duration": 1}],
}


class WanScenarioTests(unittest.TestCase):
    def test_a_real_path_cannot_carry_a_netem_profile(self):
        # netem lives on the namespace lab's veths. Accepting it here would print an impairment
        # profile in the report that the run never had.
        with self.assertRaisesRegex(lab.LabError, "real path"):
            lab.parse_scenario({**WAN_SCENARIO, "netem": "wan50"})

    def test_an_unknown_mode_is_refused_by_name(self):
        with self.assertRaisesRegex(lab.LabError, "mode"):
            lab.parse_scenario({**WAN_SCENARIO, "mode": "telepathy"})

    def test_wan_mode_needs_two_hosts_and_an_address(self):
        scenario = lab.parse_scenario({**WAN_SCENARIO, "server_addr": ""})
        with self.assertRaisesRegex(lab.LabError, "address the client dials"):
            lab.check_runnable(scenario, "cli-host")
        scenario = lab.parse_scenario({**WAN_SCENARIO, "server_host": ""})
        with self.assertRaisesRegex(lab.LabError, "ssh host"):
            lab.check_runnable(scenario, "cli-host")
        scenario = lab.parse_scenario(WAN_SCENARIO)
        with self.assertRaisesRegex(lab.LabError, "two hosts"):
            lab.check_runnable(scenario, "srv-host")
        lab.check_runnable(scenario, "cli-host")  # the valid case raises nothing

    def test_a_netns_scenario_needs_neither(self):
        lab.check_runnable(lab.parse_scenario(MINIMAL), "fake-host")

    def test_the_client_dials_the_real_address_and_nothing_is_namespaced(self):
        scenario = lab.parse_scenario(WAN_SCENARIO)
        plan = lab.RunPlan("wan-rr-r1-x", scenario, "rust", "rust", 1)
        self.assertIn("203.0.113.7:29900", plan.client_argv())
        self.assertEqual(plan.server_dial_addr, "203.0.113.7")
        self.assertEqual(plan.client_host_names,
                         ["wan-rr-r1-x-cli", "wan-rr-r1-x-smp", "wan-rr-r1-x-w0"])
        self.assertEqual(plan.server_host_names,
                         ["wan-rr-r1-x-tgt", "wan-rr-r1-x-srv", "wan-rr-r1-x-smps"])
        # Everything is still owned by the run, so Ctrl-C stops all of it.
        self.assertEqual(sorted(plan.names),
                         sorted(plan.client_host_names + plan.server_host_names))

    def test_a_netns_run_still_puts_everything_on_one_host(self):
        plan = lab.RunPlan("unit-rr-r1-x", lab.parse_scenario(MINIMAL), "rust", "rust", 1)
        self.assertEqual(plan.client_host_names, plan.names)
        self.assertEqual(plan.server_host_names, [])
        self.assertIn(f"{lab.SERVER_IP}:29900", plan.client_argv())

    def test_a_port_range_is_rendered_on_both_ends(self):
        # step 11.3 asks for a `conn 4` port-range run (29900-29903). Both ends have to
        # agree: kcptun's multiport client spreads its `conn` sessions over exactly that range.
        scenario = lab.parse_scenario({**WAN_SCENARIO, "tunnel_port_count": 4})
        plan = lab.RunPlan("wan-rr-r1-x", scenario, "rust", "rust", 1)
        self.assertEqual(scenario.tunnel_spec, "29900-29903")
        self.assertEqual(scenario.tunnel_ports, [29900, 29901, 29902, 29903])
        self.assertIn("203.0.113.7:29900-29903", plan.client_argv())
        self.assertIn(":29900-29903", plan.server_argv())

    def test_a_port_range_may_not_leave_the_sanctioned_block(self):
        with self.assertRaisesRegex(lab.LabError, "29900-29920"):
            lab.parse_scenario({**WAN_SCENARIO, "tunnel_port": 29918,
                                "tunnel_port_count": 6})
        with self.assertRaisesRegex(lab.LabError, "tunnel_port_count"):
            lab.parse_scenario({**WAN_SCENARIO, "tunnel_port_count": 0})


class WanRunFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.scenario_path = self.root / "wan.json"
        self.scenario_path.write_text(json.dumps(WAN_SCENARIO))

    def do_run(self, **overrides):
        runner = FakeRunner("cli-host")
        args = run_args(host="cli-host", scenario=str(self.scenario_path),
                        runs_dir=str(self.root / "runs"), **overrides)
        self.assertEqual(lab.cmd_run(runner, args), 0)
        return runner, runner.peers["srv-host"], args

    def test_each_end_is_started_on_its_own_host_with_no_namespace(self):
        client, server, _ = self.do_run()
        self.assertEqual([n.rsplit("-", 1)[1] for n in client.started()],
                         ["cli", "smp", "w0"])
        self.assertEqual([n.rsplit("-", 1)[1] for n in server.started()],
                         ["tgt", "srv", "smps"])
        for runner in (client, server):
            for call in runner.lab_calls("start"):
                self.assertNotIn("--netns", call, call)

    def test_the_server_artefact_is_resolved_on_the_server_host(self):
        # The 11.3 regression itself: the client host was stamped and the server host was not,
        # and the run recorded `server_build: ""` for all 27 runs rather than stopping.
        client, server, _ = self.do_run()
        state = json.loads(next((self.root / "runs").glob("*/*/state.json")).read_text())
        self.assertEqual(state["server_build_detail"]["host"], "srv-host")
        self.assertEqual(state["server_build_detail"]["sha256"], FAKE_SHA["kr-server"])
        self.assertTrue(any("BUILD.txt" in c[1] for c in server.calls if c[0] == "ssh"))
        # /proc is per machine, so each host samples with its own kr-labsample; both are named.
        self.assertEqual(state["tools_build_detail"]["host"], "cli-host")
        self.assertEqual(state["server_tools_build_detail"]["host"], "srv-host")

    def test_an_unstamped_server_host_refuses_the_whole_wan_run(self):
        runner = FakeRunner("cli-host")
        runner.peer("srv-host").stamps["rust"] = ""
        args = run_args(host="cli-host", scenario=str(self.scenario_path),
                        runs_dir=str(self.root / "runs"))
        with self.assertRaises(lab.LabError) as caught:
            lab.cmd_run(runner, args)
        message = str(caught.exception)
        self.assertIn("srv-host", message)
        self.assertIn("rust server", message)
        self.assertEqual(runner.lab_calls("start"), [])
        self.assertEqual(runner.peers["srv-host"].lab_calls("start"), [])

    def test_the_measuring_end_of_a_latency_run_is_hashed_on_the_client_host(self):
        # `kr-pingpong` runs on *both* hosts in a WAN run: the echo target on the server, and
        # the workload that emits every percentile on the client. Only the server's copy used
        # to be hashed, so a stale client binary beside a fresh stamp — the exact 11.3 shape —
        # produced numbers from an unidentified instrument and the run was accepted.
        runner = FakeRunner("cli-host")
        runner.hashes["kr-pingpong"] = "99" * 32
        args = run_args(host="cli-host", scenario=str(self.scenario_path),
                        runs_dir=str(self.root / "runs"))
        with self.assertRaises(lab.LabError) as caught:
            lab.cmd_run(runner, args)
        message = str(caught.exception)
        self.assertIn("cli-host", message)
        self.assertIn("kr-pingpong", message)
        self.assertIn("replaced without redeploying", message)
        self.assertEqual(runner.lab_calls("start"), [])

    def test_the_client_hosts_pingpong_is_hashed_once_and_recorded_as_provenanced(self):
        client, server, _ = self.do_run()
        for runner in (client, server):
            hashed = [c[1].split()[1].strip('"').rsplit("/", 1)[-1]
                      for c in runner.calls if c[0] == "ssh" and c[1].startswith("sha256sum")]
            self.assertEqual(hashed.count("kr-pingpong"), 1, (runner.host, hashed))
        # Hashing it is only half: the stamp has to be *recorded*, per host, or a swapped
        # target that `--allow-unprovenanced` let through reaches no report at all.
        state = json.loads(next((self.root / "runs").glob("*/*/state.json")).read_text())
        self.assertEqual(state["target_build_detail"]["host"], "cli-host")
        self.assertEqual(state["server_target_build_detail"]["host"], "srv-host")
        for key in ("target_build_detail", "server_target_build_detail"):
            self.assertTrue(state[key]["binary"].endswith("/kr-pingpong"), state[key])
            self.assertEqual(state[key]["sha256"], FAKE_SHA["kr-pingpong"])

    def test_a_swapped_target_on_either_wan_host_is_named_in_the_report(self):
        # Two machines, two `kr-pingpong` files, and each must be able to reach the banner on
        # its own: the echo end and the measuring end fail independently.
        for host in ("cli-host", "srv-host"):
            with self.subTest(host=host):
                tmp = tempfile.TemporaryDirectory()
                self.addCleanup(tmp.cleanup)
                report = Path(tmp.name) / "report.md"
                runner = FakeRunner("cli-host")
                runner.peer("srv-host")
                target = runner if host == "cli-host" else runner.peers["srv-host"]
                target.hashes["kr-pingpong"] = "99" * 32
                args = run_args(host="cli-host", scenario=str(self.scenario_path),
                                runs_dir=str(Path(tmp.name) / "runs"),
                                allow_unprovenanced=True, no_report=False,
                                report=str(report))
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(lab.cmd_run(runner, args), 0)
                text = report.read_text()
                self.assertIn("UNPROVENANCED", text)
                self.assertIn("kr-pingpong", text)
                self.assertIn(host, text)
    def test_both_hosts_of_a_real_path_are_checked_for_a_clamped_sockbuf(self):
        # 11.2 found the kernel's `rmem_max` capable of inverting a cell's conclusion, and the
        # committed 11.3 results were measured on hosts whose ceiling was never read. A WAN
        # path cannot be re-run afterwards under a raised ceiling, so the warning has to be at
        # preflight — and on *both* ends, because each host clamps its own half of `-sockbuf`.
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            self.do_run()
        text = errors.getvalue()
        self.assertIn("cli-host net.core.rmem_max is 212992", text)
        self.assertIn("srv-host net.core.rmem_max is 212992", text)
        # Each host is warned about the end it actually runs, not about both.
        self.assertNotIn("cli-host net.core.rmem_max is 212992, so the server's", text)
        self.assertNotIn("srv-host net.core.rmem_max is 212992, so the client's", text)

    def test_no_netem_is_applied_to_a_real_path(self):
        client, server, _ = self.do_run()
        # Not even a `netns status`: the lab host may be running somebody else's namespace lab
        # (a detached soak), and `netns set` would re-shape *their* veths mid-run.
        self.assertEqual(client.lab_calls("netns"), [])
        self.assertEqual(server.lab_calls("netns"), [])

    def test_each_host_is_preflighted_for_the_ports_it_actually_binds(self):
        client, server, _ = self.do_run()
        client_ports = [c[3:] for c in client.lab_calls("baseline") if c[2] == "--ports-only"]
        server_ports = [c[3:] for c in server.lab_calls("baseline") if c[2] == "--ports-only"]
        self.assertEqual(client_ports, [("12948",)])
        # The tunnel port and the pingpong target are the server host's.
        self.assertEqual(server_ports, [("22600", "29900")])

    def test_both_ends_are_sampled_because_proc_is_per_machine(self):
        client, server, _ = self.do_run()
        client_sampler = [c for c in client.lab_calls("start") if "-smp" in c[2]][0]
        server_sampler = [c for c in server.lab_calls("start") if "-smps" in c[2]][0]
        self.assertIn("cli=1001", " ".join(client_sampler))
        self.assertNotIn("srv=", " ".join(client_sampler))
        joined = " ".join(server_sampler)
        self.assertIn("srv=", joined)
        self.assertIn("tgt=", joined)
        self.assertNotIn("cli=", joined)

    def test_both_tunnel_ends_get_their_snmp_dump_on_their_own_host(self):
        client, server, _ = self.do_run()
        self.assertEqual([c[2:] for c in client.lab_calls("signal")],
                         [("USR1", *[n for n in client.started() if n.endswith("-cli")])])
        self.assertEqual([c[2:] for c in server.lab_calls("signal")],
                         [("USR1", *[n for n in server.started() if n.endswith("-srv")])])

    def test_each_host_stops_and_collects_only_its_own_processes(self):
        client, server, _ = self.do_run()
        for runner, owned in ((client, set(client.started())),
                              (server, set(server.started()))):
            stopped = {n for call in runner.lab_calls("stop") for n in call[2:]}
            self.assertTrue(stopped)
            self.assertEqual(stopped - owned, set(), f"{runner.host} stopped a foreign process")

    def test_the_server_halfs_artefacts_land_in_their_own_directory(self):
        client, server, _ = self.do_run()
        self.assertEqual(len(client.fetched), 1)
        self.assertEqual(len(server.fetched), 1)
        # Both machines write a proc.csv; without the subdirectory one would overwrite the other.
        self.assertEqual(server.fetched[0][1].name, lab.SERVER_SUBDIR)
        self.assertEqual(server.fetched[0][1].parent, client.fetched[0][1])

    def test_uptime_is_recorded_on_both_ends_before_and_after(self):
        client, _server, _ = self.do_run(no_report=True)
        state = json.loads(
            next((self.root / "runs").glob("*/*/state.json")).read_text())
        for when in ("uptime_before", "uptime_after"):
            self.assertEqual(sorted(state[when]), ["cli-host", "srv-host"], when)
            self.assertIn("[cli-host]", state[when]["cli-host"])
            self.assertIn("[srv-host]", state[when]["srv-host"])

    def test_the_command_line_can_point_a_scenario_at_another_path(self):
        # One WAN scenario, six rungs of the RTT ladder: the path is a property of the session.
        self.scenario_path.write_text(json.dumps(
            {k: v for k, v in WAN_SCENARIO.items()
             if k not in ("server_host", "server_addr")}))
        client, _, _ = self.do_run(server_host="srv-host", server_addr="198.51.100.9")
        argv = " ".join(
            c for call in client.lab_calls("start") for c in call if "kr-client" in c
            or c == "-r")
        self.assertIn("198.51.100.9:29900", " ".join(
            " ".join(call) for call in client.lab_calls("start")))
        self.assertTrue(argv)

    def test_a_mode_switch_needs_both_halves_of_the_path(self):
        self.scenario_path.write_text(json.dumps(
            {k: v for k, v in WAN_SCENARIO.items()
             if k not in ("server_host", "server_addr")}))
        runner = FakeRunner("cli-host")
        args = run_args(host="cli-host", scenario=str(self.scenario_path),
                        runs_dir=str(self.root / "runs"), server_host="srv-host")
        with self.assertRaisesRegex(lab.LabError, "address the client dials"):
            lab.cmd_run(runner, args)
        self.assertEqual(runner.lab_calls("start"), [])

    def test_promoting_a_netem_scenario_to_a_real_path_is_refused(self):
        # `parse_scenario` refuses `mode: wan` + netem, but `cmd_run` sets the mode *after*
        # parsing, on --server-host/--server-addr — which is how every rung in the runbook is
        # started. Checked only at parse time, this ran the whole campaign with no impairment
        # applied and no error at all, from a scenario whose own name says `wan50`.
        self.scenario_path.write_text(json.dumps(
            {"name": "wan", "netem": "wan50", "settle": 0,
             "workloads": [{"type": "ping", "tag": "lat", "duration": 1}]}))
        runner = FakeRunner("cli-host")
        args = run_args(host="cli-host", scenario=str(self.scenario_path),
                        runs_dir=str(self.root / "runs"),
                        server_host="srv-host", server_addr="198.51.100.9")
        with self.assertRaisesRegex(lab.LabError, "real path"):
            lab.cmd_run(runner, args)
        self.assertEqual(runner.lab_calls("start"), [])
        self.assertEqual(runner.peers, {})

    def test_a_failed_collect_still_stops_the_server_host(self):
        # `cmd_collect` — the only way to finish a detached WAN run — has no `finally`. With the
        # server stopped after the client's collect and tar download, a raising collect (or a
        # Ctrl-C mid-download) left `<runid>-srv` and `<runid>-tgt` up for ever on the other
        # machine: `lab-start.sh` nohups them with no timeout, and only the sampler and the
        # pingpong target expire on their own.
        self.do_run(detach=True)
        state = json.loads(next((self.root / "runs").glob("*/*/state.json")).read_text())

        class CollectFails(FakeRunner):
            def lab(self, script, *args, check=True, timeout=120.0):
                result = super().lab(script, *args, check=check, timeout=timeout)
                if script == "collect" and self.host == "cli-host":
                    raise lab.LabError("collect exploded")
                return result

        later = CollectFails("cli-host")
        collect_args = run_args(host="cli-host", command="collect", runid=state["runid"],
                                runs_dir=str(self.root / "runs"), wait=False)
        with self.assertRaisesRegex(lab.LabError, "collect exploded"):
            lab.cmd_collect(later, collect_args)
        peer = later.peers["srv-host"]
        stopped_server = {n for call in peer.lab_calls("stop") for n in call[2:]}
        self.assertTrue(any(n.endswith("-srv") for n in stopped_server), stopped_server)
        self.assertTrue(any(n.endswith("-tgt") for n in stopped_server), stopped_server)
        stopped_client = {n for call in later.lab_calls("stop") for n in call[2:]}
        self.assertTrue(any(n.endswith("-cli") for n in stopped_client), stopped_client)

    def test_an_interrupt_while_a_run_is_starting_still_stops_both_ends(self):
        # The window that actually bit: SIGINT arrived between the server host's first
        # `lab-start.sh` and `start_run` returning, so the laptop held no state for the run and
        # stopped nothing — a kcptun server, its target and a client left up on two machines.
        class InterruptOnServerStart(FakeRunner):
            def lab(self, script, *args, check=True, timeout=120.0):
                result = super().lab(script, *args, check=check, timeout=timeout)
                if script == "start" and args and args[0].endswith("-srv"):
                    raise KeyboardInterrupt
                return result

        client = InterruptOnServerStart("cli-host")
        args = run_args(host="cli-host", scenario=str(self.scenario_path),
                        runs_dir=str(self.root / "runs"))
        with self.assertRaises(KeyboardInterrupt):
            lab.cmd_run(client, args)
        server = client.peers["srv-host"]
        stopped_client = {n for call in client.lab_calls("stop") for n in call[2:]}
        stopped_server = {n for call in server.lab_calls("stop") for n in call[2:]}
        self.assertTrue(any(n.endswith("-cli") for n in stopped_client), stopped_client)
        self.assertTrue(any(n.endswith("-srv") for n in stopped_server), stopped_server)
        self.assertTrue(any(n.endswith("-tgt") for n in stopped_server), stopped_server)
        # Only this run's names, on each host, and never `--all`.
        for name in stopped_client | stopped_server:
            self.assertIn("wan-rr-r1-", name)

    def test_a_detached_wan_run_is_collected_from_both_hosts(self):
        client, _, _ = self.do_run(detach=True)
        state_path = next((self.root / "runs").glob("*/*/state.json"))
        state = json.loads(state_path.read_text())
        self.assertEqual(state["mode"], "wan")
        self.assertEqual(state["server_host"], "srv-host")
        self.assertEqual(state["server_addr"], "203.0.113.7")
        self.assertEqual(state["netem"], "none (real path)")

        later = FakeRunner("cli-host")
        collect_args = run_args(host="cli-host", command="collect", runid=state["runid"],
                                runs_dir=str(self.root / "runs"), wait=False)
        self.assertEqual(lab.cmd_collect(later, collect_args), 0)
        peer = later.peers["srv-host"]
        self.assertEqual(len(later.fetched), 1)
        self.assertEqual(len(peer.fetched), 1)
        self.assertEqual(peer.fetched[0][1].name, lab.SERVER_SUBDIR)
        # `collect` learns the closing uptime, so the state file has to be rewritten.
        self.assertIn("uptime_after", json.loads(state_path.read_text()))

    def test_the_detach_hint_names_the_host_the_run_was_started_on(self):
        # The line `run --detach` prints is the line a user pastes hours later. Without
        # `--host` it addresses `DEFAULT_HOST`, which for every WAN rung but one is the wrong
        # machine.
        runner = FakeRunner("cli-host")
        args = run_args(host="cli-host", scenario=str(self.scenario_path),
                        runs_dir=str(self.root / "runs"), detach=True)
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            self.assertEqual(lab.cmd_run(runner, args), 0)
        self.assertIn("lab.py --host cli-host collect", printed.getvalue())

    def test_collecting_a_detached_wan_run_from_the_wrong_host_is_refused(self):
        # `--host` defaults to `lab-arm64` and only the *server* host is recovered from the
        # state, so collecting a WAN run without naming its client host addressed the default
        # machine instead: `stop` found no pid files there, `collect`/`fetch_dir` then failed on
        # a log directory that does not exist, and the real `<runid>-cli` on the host that does
        # have it was left running — `lab-start.sh` nohups it with no timeout. `start_run`
        # records `host`, so the mismatch is detectable before anything is touched.
        self.do_run(detach=True)
        state = json.loads(next((self.root / "runs").glob("*/*/state.json")).read_text())
        self.assertEqual(state["host"], "cli-host")

        for command, extra in (("collect", {"wait": False}), ("status", {})):
            wrong = FakeRunner("lab-arm64")
            args = run_args(host="lab-arm64", command=command, runid=state["runid"],
                            runs_dir=str(self.root / "runs"), **extra)
            with self.assertRaisesRegex(lab.LabError, "cli-host") as caught:
                getattr(lab, f"cmd_{command}")(wrong, args)
            self.assertIn("--host cli-host", str(caught.exception))
            # Nothing was done on either machine: no signal, no stop, no collect, no peer.
            self.assertEqual(wrong.calls, [], command)
            self.assertEqual(wrong.peers, {}, command)

    def test_a_state_written_before_wan_mode_existed_still_collects(self):
        # A soak started from an older checkout has no `mode` and no per-host name lists; it must
        # still be collectable, from the one host it ran on.
        local = self.root / "old"
        local.mkdir()
        state = {
            "runid": "soak-rr-r1-old", "scenario": "soak", "source": "", "config": "s1",
            "netem": "wan50", "client_impl": "rust", "server_impl": "rust", "repetition": 1,
            "target": "pingpong", "host": "fake-host", "build": "", "started_unix": 0,
            "started_iso": "2026-09-23T20:23:33Z", "total_duration": 60,
            "names": ["soak-rr-r1-old-tgt", "soak-rr-r1-old-srv", "soak-rr-r1-old-cli"],
            "pids": {}, "workloads": [], "client_argv": [], "server_argv": [],
            "target_argv": [], "remote_dir": "$HOME/kcptun-lab/logs/soak-rr-r1-old",
        }
        (local / "state.json").write_text(json.dumps(state))
        runner = FakeRunner()
        lab.finish_run(runner, state, local, max_log_bytes=4096)
        self.assertEqual(runner.peers, {})
        stopped = {n for call in runner.lab_calls("stop") for n in call[2:]}
        self.assertEqual(stopped, set(state["names"]))
        self.assertEqual(len(runner.fetched), 1)


# --------------------------------------------------------------------------------------------
# reading results and writing the report
# --------------------------------------------------------------------------------------------


PROC_CSV = """\
unix,iso,elapsed_s,tag,label,pid,state,rss_kb,hwm_kb,rss_anon_kb,rss_file_kb,vmsize_kb,threads,\
fds,utime_ticks,stime_ticks,cpu_ticks,cpu_pct,minflt,majflt,vol_ctxt,nonvol_ctxt,load1,\
log_bytes,log_truncations
1790000000,2026-09-20T00:00:00Z,0.001,run,cli,101,S,5000,5200,3000,2000,400000,9,24,10,5,15,,\
100,0,10,1,0.10,1024,0
1790000060,2026-09-20T00:01:00Z,60.001,run,cli,101,S,5200,5400,3100,2100,400000,9,26,60,20,80,\
1.083,200,0,20,2,0.20,2048,0
1790000000,2026-09-20T00:00:00Z,0.002,run,srv,102,S,9000,9100,7000,2000,500000,9,30,20,10,30,,\
300,0,30,3,0.10,1024,0
1790000060,2026-09-20T00:01:00Z,60.002,run,srv,102,S,9100,9200,7100,2000,500000,9,31,80,40,120,\
1.500,400,0,40,4,0.20,4096,1
"""

SNMP_CSV = """\
Unix,BytesSent,BytesReceived,MaxConn,ActiveOpens,PassiveOpens,CurrEstab,InErrs,InCsumErrors,\
KCPInErrors,InPkts,OutPkts,InSegs,OutSegs,RetransSegs,FastRetransSegs,EarlyRetransSegs,LostSegs,\
RepeatSegs,FECFullShardSet,FECRecovered,FECErrs
1790000000,0,0,1,1,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
1790000060,1000,2000,4,4,0,3,0,0,0,50,60,70,80,5,2,0,1,0,0,7,0
"""

#: The same file as a real run writes it: the first record is already well into the traffic.
SNMP_CSV_WARM = """\
Unix,BytesSent,BytesReceived,MaxConn,ActiveOpens,PassiveOpens,CurrEstab,InErrs,InCsumErrors,\
KCPInErrors,InPkts,OutPkts,InSegs,OutSegs,RetransSegs,FastRetransSegs,EarlyRetransSegs,LostSegs,\
RepeatSegs,FECFullShardSet,FECRecovered,FECErrs
1790176063,1684227,1917944,4,4,0,4,0,0,0,1500,1600,1700,1800,11,3,0,2,0,0,9,0
1790176103,1380898567,1345288505,4,4,0,4,0,0,0,900000,980000,990000,1000000,900,150,0,80,0,0,77,0
"""


class ResultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_process_metrics_summarise_first_and_last_sample(self):
        (self.dir / "proc.csv").write_text(PROC_CSV)
        metrics = lab.process_metrics(self.dir / "proc.csv")
        self.assertEqual(set(metrics), {"cli", "srv"})
        cli = metrics["cli"]
        self.assertEqual(cli["samples"], 2)
        self.assertEqual(cli["rss_kb_first"], 5000)
        self.assertEqual(cli["rss_kb_last"], 5200)
        self.assertEqual(cli["rss_growth_kb"], 200)
        self.assertEqual(cli["hwm_kb"], 5400)
        self.assertEqual(cli["fd_growth"], 2)
        self.assertAlmostEqual(cli["cpu_seconds"], 0.65)
        self.assertEqual(metrics["srv"]["log_truncations"], 1)

    # -- leak slopes (11.1b): the soak's actual acceptance criterion --------------------------

    def _proc_csv(self, samples, label="cli", interval=60) -> Path:
        """`samples` is a list of `(rss_kb, fds_or_None)`, one per `interval` seconds."""
        head = ("unix,iso,elapsed_s,tag,label,pid,state,rss_kb,hwm_kb,rss_anon_kb,rss_file_kb,"
                "vmsize_kb,threads,fds,utime_ticks,stime_ticks,cpu_ticks,cpu_pct,minflt,majflt,"
                "vol_ctxt,nonvol_ctxt,load1,log_bytes,log_truncations")
        rows = [head]
        for i, (rss, fds) in enumerate(samples):
            elapsed = i * interval
            rows.append(f"{1790000000 + elapsed},2026-09-20T00:00:00Z,{elapsed}.0,run,{label},"
                        f"101,S,{rss},{rss},0,0,0,9,{'' if fds is None else fds},"
                        f"{i},0,{i},,0,0,0,0,0.1,0,0")
        path = self.dir / "proc.csv"
        path.write_text("\n".join(rows) + "\n")
        return path

    def test_a_process_that_is_flat_after_warm_up_has_a_zero_slope(self):
        # Rises 40 MB over the first ten minutes, then sits still for five hours. first→last
        # says +40 MB and looks alarming; the slope says the plateau it actually is.
        samples = [(4000 + 4000 * i, 20 + i) for i in range(11)]           # warm-up
        samples += [(44000, 30)] * 300                                     # five hours flat
        metrics = lab.process_metrics(self._proc_csv(samples))["cli"]
        self.assertEqual(metrics["rss_growth_kb"], 40000)
        self.assertAlmostEqual(metrics["rss_slope_kb_h"], 0.0, places=6)
        self.assertAlmostEqual(metrics["fd_slope_h"], 0.0, places=6)
        # 311 samples a minute apart is a 5 h 11 m run, so a tenth of it (1860 s) is the
        # cutoff rather than the ten-minute floor — and the plateau starts well before that.
        self.assertEqual(metrics["slope_from_s"], 1860.0)

    def test_a_steady_climb_is_reported_as_kilobytes_per_hour(self):
        # 100 kB every 60 s = 6000 kB/h, and one descriptor every 60 s = 60/h.
        samples = [(10000 + 100 * i, 20 + i) for i in range(360)]
        metrics = lab.process_metrics(self._proc_csv(samples))["cli"]
        self.assertAlmostEqual(metrics["rss_slope_kb_h"], 6000.0, places=3)
        self.assertAlmostEqual(metrics["fd_slope_h"], 60.0, places=3)

    def test_a_run_too_short_to_leave_warm_up_reports_no_slope(self):
        metrics = lab.process_metrics(self._proc_csv([(5000, 20)] * 5))["cli"]
        self.assertIsNone(metrics["rss_slope_kb_h"])
        self.assertIsNone(metrics["fd_slope_h"])
        self.assertEqual(metrics["slope_samples"], 0)
        self.assertEqual(lab.format_slope(None), "—")

    def test_a_missing_fd_column_loses_the_fd_slope_and_not_the_rss_one(self):
        metrics = lab.process_metrics(self._proc_csv([(5000, None)] * 60))["cli"]
        self.assertAlmostEqual(metrics["rss_slope_kb_h"], 0.0, places=6)
        self.assertIsNone(metrics["fd_slope_h"])

    def test_the_warm_up_window_grows_with_the_run(self):
        # A tenth of a ten-hour run is an hour, which is later than the ten-minute floor.
        self.assertAlmostEqual(lab.leak_slopes([(t * 60.0, 1.0, 1.0) for t in range(600)])
                               ["slope_from_s"], 3594.0)
        # A tenth of a one-hour run is six minutes, so the floor wins.
        self.assertEqual(lab.leak_slopes([(t * 60.0, 1.0, 1.0) for t in range(60)])
                         ["slope_from_s"], lab.WARMUP_SECONDS)

    def test_a_six_hour_soak_collected_after_twenty_minutes_reports_no_slope(self):
        # The trap this guards: the warm-up window used to be a tenth of the samples that had
        # arrived, so a 6 h soak collected early got a 600 s cutoff, cleared MIN_SLOPE_SAMPLES
        # after ~15 min, and printed a gradient fitted entirely to its own warm-up under a line
        # calling it the acceptance criterion. The intended length decides the window.
        samples = [(4000 + 400 * i, 20 + i) for i in range(20)]   # 20 min, still climbing
        metrics = lab.process_metrics(self._proc_csv(samples), 21600)["cli"]
        self.assertIsNone(metrics["rss_slope_kb_h"])
        self.assertIsNone(metrics["fd_slope_h"])
        self.assertEqual(metrics["slope_samples"], 0)
        self.assertEqual(metrics["slope_span_s"], 1140.0)
        # The same samples with no intended duration fall back to the observed span, which is
        # exactly the behaviour that made the number wrong.
        self.assertIsNotNone(lab.process_metrics(self._proc_csv(samples))["cli"]
                             ["rss_slope_kb_h"])

    def test_the_intended_duration_sizes_the_window_even_when_the_run_completed(self):
        # 6 h of samples, intended 6 h: a tenth of 21600 s, not of the 21540 s observed.
        series = [(t * 60.0, 1.0, 1.0) for t in range(360)]
        self.assertEqual(lab.leak_slopes(series, 21600)["slope_from_s"], 2160.0)
        self.assertAlmostEqual(lab.leak_slopes(series)["slope_from_s"], 2154.0)

    def test_a_flat_line_has_no_gradient_rather_than_a_wrong_one(self):
        self.assertIsNone(lab.least_squares_slope([]))
        self.assertIsNone(lab.least_squares_slope([(1.0, 2.0)]))
        # Every sample at the same instant: there is no gradient to fit.
        self.assertIsNone(lab.least_squares_slope([(5.0, 1.0), (5.0, 9.0)]))

    def test_post_mortem_rows_do_not_poison_the_summary(self):
        # labsample writes a `state=X` row with zeroed counters when a process is gone, purely to
        # timestamp the exit. Folding it in would report "RSS 5200 -> 0" and a negative CPU time
        # for every run whose sampler ticks while the processes are being stopped.
        dead = ("1790000120,2026-09-20T00:02:00Z,120.001,run,cli,101,X,0,0,0,0,0,0,,0,0,0,,"
                "0,0,0,0,0.20,2048,0\n")
        (self.dir / "proc.csv").write_text(PROC_CSV + dead)
        cli = lab.process_metrics(self.dir / "proc.csv")["cli"]
        self.assertEqual(cli["samples"], 3)
        self.assertIn("X", cli["states"])
        self.assertEqual(cli["rss_kb_last"], 5200)
        self.assertEqual(cli["rss_growth_kb"], 200)
        self.assertEqual(cli["fd_growth"], 2)
        self.assertAlmostEqual(cli["cpu_seconds"], 0.65)

        # A label with nothing BUT post-mortem rows still renders (the report formats every
        # number with `:.0f`, which a None would blow up on).
        (self.dir / "dead.csv").write_text(PROC_CSV.splitlines(keepends=True)[0] + dead)
        only_dead = lab.process_metrics(self.dir / "dead.csv")["cli"]
        self.assertEqual(only_dead["states"], "X")
        self.assertEqual(only_dead["rss_kb_first"], 0.0)
        self.assertEqual(only_dead["cpu_seconds"], 0.0)

    def test_a_blank_fd_cell_is_not_read_as_a_collapse_to_zero(self):
        # labsample leaves `fds` empty when `count_fds` fails on a process that is still alive
        # (it exited between the two /proc reads, or the sampler hit EMFILE). Reading that as 0
        # printed "fds 26 -> 0 (-26)", and fd growth is half of the 11.4 soak criterion.
        blank = ("1790000120,2026-09-20T00:02:00Z,120.001,run,cli,101,S,5300,5400,3100,2100,"
                 "400000,9,,70,25,95,0.25,200,0,20,2,0.20,2048,0\n")
        (self.dir / "proc.csv").write_text(PROC_CSV + blank)
        cli = lab.process_metrics(self.dir / "proc.csv")["cli"]
        self.assertEqual(cli["samples"], 3)
        self.assertEqual(cli["fds_last"], 26)
        self.assertEqual(cli["fd_growth"], 2)
        self.assertEqual(cli["fds_max"], 26)
        # The rest of that row is perfectly good and is still counted.
        self.assertEqual(cli["rss_kb_last"], 5300)
        self.assertAlmostEqual(cli["cpu_seconds"], 0.80)

    def test_missing_files_produce_empty_summaries_rather_than_crashing(self):
        self.assertEqual(lab.process_metrics(self.dir / "nope.csv"), {})
        self.assertEqual(lab.snmp_totals(self.dir / "nope.csv"), {})
        self.assertEqual(lab.result_lines(self.dir / "nope.log"), [])
        self.assertIsNone(lab.iperf3_summary(self.dir / "nope.json"))
        self.assertEqual(lab.scan_logs(self.dir), [])

    def test_snmp_totals_are_the_last_records_absolute_counters(self):
        (self.dir / "snmp-cli.csv").write_text(SNMP_CSV)
        snmp = lab.snmp_totals(self.dir / "snmp-cli.csv")
        self.assertEqual(snmp["BytesSent"], 1000)
        self.assertEqual(snmp["RetransSegs"], 5)
        self.assertEqual(snmp["FECRecovered"], 7)
        self.assertEqual(snmp["CurrEstab"], 3)
        self.assertEqual(snmp["CurrEstabMax"], 3)
        self.assertEqual(snmp["ActiveOpens"], 4)
        self.assertEqual(snmp["MaxConn"], 4)
        self.assertEqual(snmp["_records"], 2)

    def test_the_traffic_of_the_first_snmp_period_is_not_thrown_away(self):
        # The real shape: neither `-snmplog` logger writes at t=0, so the FIRST record is already
        # non-zero and holds one whole `-snmpperiod` of traffic. The counters are process-global
        # and start at zero with the fresh processes a run launches, so the LAST record is the
        # run's total; a `last - first` delta would silently drop that first period.
        (self.dir / "snmp-cli.csv").write_text(SNMP_CSV_WARM)
        snmp = lab.snmp_totals(self.dir / "snmp-cli.csv")
        self.assertEqual(snmp["BytesSent"], 1_380_898_567)
        self.assertEqual(snmp["RetransSegs"], 900)
        self.assertEqual(snmp["FECRecovered"], 77)
        self.assertEqual(snmp["_records"], 2)

    def test_result_lines_are_picked_out_of_a_noisy_log(self):
        (self.dir / "w.log").write_text(
            "2026-09-20T00:00:00Z ping: starting\n"
            "RESULT {\"kind\":\"ping\",\"rtt_p50_us\":1500.0,\"requests\":10,\"errors\":0}\n"
            "RESULT not-json\n"
        )
        found = lab.result_lines(self.dir / "w.log")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["rtt_p50_us"], 1500.0)

    def test_iperf3_json_is_reduced_to_the_numbers_a_report_quotes(self):
        (self.dir / "iperf3-up.json").write_text(json.dumps({
            "start": {"test_start": {"reverse": 0}},
            "end": {
                "sum_sent": {"seconds": 30.0, "bits_per_second": 1.2e8, "retransmits": 17,
                             "bytes": 450000000},
                "sum_received": {"seconds": 30.0, "bits_per_second": 1.1e8,
                                 "bytes": 412500000},
            },
        }))
        summary = lab.iperf3_summary(self.dir / "iperf3-up.json")
        self.assertAlmostEqual(summary["received_mbit_s"], 110.0)
        self.assertEqual(summary["retransmits"], 17)
        self.assertFalse(summary["reverse"])

    def test_log_scanning_reports_real_problems_and_ignores_the_expected_ones(self):
        (self.dir / "a.log").write_text(
            "stream opened in: 1 out: 2\n"
            "SetReadBuffer: set udp 127.0.0.1:29900: setsockopt: invalid argument\n"
            "panic: runtime error\n"
        )
        notes = lab.scan_logs(self.dir)
        self.assertEqual(len(notes), 1)
        self.assertIn("panic", notes[0])

    def test_log_scanning_is_bounded(self):
        (self.dir / "a.log").write_text("fatal: nope\n" * 1000)
        notes = lab.scan_logs(self.dir)
        self.assertLessEqual(len(notes), 41)
        self.assertIn("suppressed", notes[-1])

    def test_the_report_holds_the_workload_metrics_and_snmp(self):
        state = {
            "runid": "unit-rr-r1-STAMP", "scenario": "unit", "host": "fake-host",
            "config": "s1", "netem": "wan50", "client_impl": "rust", "server_impl": "rust",
            "repetition": 1, "target": "pingpong", "started_iso": "2026-09-20T00:00:00Z",
            "total_duration": 60, "client_argv": ["kr-client"], "server_argv": ["kr-server"],
            "workloads": [
                {"name": "unit-rr-r1-STAMP-w0", "tag": "lat", "type": "ping",
                 "duration": 60, "start_after": 0, "argv": []},
                {"name": "unit-rr-r1-STAMP-w1", "tag": "churn", "type": "churn",
                 "duration": 60, "start_after": 0, "argv": []},
            ],
        }
        (self.dir / "proc.csv").write_text(PROC_CSV)
        (self.dir / "snmp-cli.csv").write_text(SNMP_CSV)
        (self.dir / "snmp-srv.csv").write_text(SNMP_CSV)
        (self.dir / "unit-rr-r1-STAMP-w0.log").write_text(
            'RESULT {"kind":"ping","rtt_p50_us":1500.0,"rtt_p90_us":2000.0,'
            '"rtt_p99_us":9000.0,"rtt_max_us":12000.0,"requests":400,"errors":0}\n'
        )
        (self.dir / "unit-rr-r1-STAMP-w1.log").write_text(
            'RESULT {"kind":"churn","opened":800,"completed":800,"mbit_s":31.5,'
            '"errors":0,"timeouts":0,"long_lived_ok":120}\n'
        )
        text = lab.markdown_report([state], [self.dir])
        self.assertIn("# Lab results — unit", text)
        self.assertIn("## unit-rr-r1-STAMP", text)
        self.assertIn("p50 1.50 ms", text)
        self.assertIn("800/800 streams", text)
        self.assertIn("| cli | 2 |", text)
        self.assertIn("| RetransSegs | 5 | 5 |", text)
        self.assertIn("No error markers", text)
        # Two samples is deep inside warm-up, so the slope columns are present but empty, and
        # the report says why rather than printing a gradient fitted to two points.
        self.assertIn("RSS slope kB/h", text)
        self.assertIn("Too few samples after warm-up", text)

    def test_the_report_prints_the_command_that_produced_each_number(self):
        # 11.3's caveat 4 — "if a future rung reports a flat 400.0, the cap has become the
        # measurement" — could only be checked by opening state.json, because the report
        # printed the tunnel's argv and never the workload's. A number and the command that
        # produced it belong on the same page.
        state = {
            "runid": "unit-rr-r1-STAMP", "scenario": "unit", "host": "fake-host",
            "config": "s1", "netem": "clean", "client_impl": "rust", "server_impl": "rust",
            "repetition": 1, "target": "iperf3", "started_iso": "2026-09-20T00:00:00Z",
            "total_duration": 60, "client_argv": ["kr-client"], "server_argv": ["kr-server"],
            "workloads": [
                {"name": "unit-rr-r1-STAMP-w0", "tag": "up", "type": "iperf3",
                 "duration": 60, "start_after": 0,
                 "argv": ["iperf3", "-c", "127.0.0.1", "-t", "60", "-b", "900M"]},
            ],
        }
        text = lab.markdown_report([state], [self.dir])
        self.assertIn("| workload | result | command |", text)
        self.assertIn("`iperf3 -c 127.0.0.1 -t 60 -b 900M`", text)

    def test_the_report_prints_the_socket_buffer_ceilings_every_number_depends_on(self):
        # D32 makes the ceiling a validity precondition — an S1 run (`-sockbuf 8388608`) on a
        # host whose `net.core.rmem_max` is the stock 212992 measures the ceiling and must be
        # discarded. `matrix_report` printed it and `markdown_report` did not, so the three
        # 11.3b WAN detail pages carried numbers whose precondition was checkable only from a
        # `state.json` under the gitignored `lab-runs/`.
        state = self.wan_state()
        state["socket_buffer_limits"] = {
            "cli-host": {"rmem_max": 8388608, "wmem_max": 67108864},
            "srv-host": {"rmem_max": 8388608, "wmem_max": 67108864},
        }
        text = lab.markdown_report([state], [self.dir])
        self.assertIn("rmem_max 8388608", text)
        self.assertIn("wmem_max 67108864", text)
        self.assertIn("silently clamped", text)

    def test_a_report_of_runs_without_ceilings_says_how_many_it_has(self):
        # Pre-D32 states have no ceilings at all; a mixed session must not imply the recorded
        # ones cover the runs that predate them, and an all-unrecorded one prints nothing.
        recorded, missing = self.wan_state(), self.wan_state()
        recorded["socket_buffer_limits"] = {"cli-host": {"rmem_max": 212992,
                                                         "wmem_max": 212992}}
        text = lab.markdown_report([recorded, missing], [self.dir, self.dir])
        self.assertIn("rmem_max 212992", text)
        self.assertIn("recorded for 1 of 2 runs", text)
        self.assertNotIn("silently clamped", lab.markdown_report([missing], [self.dir]))

    def test_a_workload_recorded_before_the_command_column_says_so(self):
        # Pre-12.0 states have no `argv`; the column must not invent one.
        state = {
            "runid": "unit-rr-r1-STAMP", "scenario": "unit", "host": "fake-host",
            "config": "s1", "netem": "clean", "client_impl": "rust", "server_impl": "rust",
            "repetition": 1, "target": "iperf3", "started_iso": "2026-09-20T00:00:00Z",
            "total_duration": 60, "client_argv": ["kr-client"], "server_argv": ["kr-server"],
            "workloads": [{"name": "unit-rr-r1-STAMP-w0", "tag": "up", "type": "iperf3",
                           "duration": 60, "start_after": 0}],
        }
        self.assertIn("| (not recorded) |", lab.markdown_report([state], [self.dir]))

    def wan_state(self) -> dict:
        return {
            "runid": "wan-rr-r1-STAMP", "scenario": "wan", "host": "cli-host",
            "mode": "wan", "server_host": "srv-host", "server_addr": "203.0.113.7",
            "config": "s1", "netem": "none (real path)", "client_impl": "rust",
            "server_impl": "rust", "repetition": 1, "target": "pingpong",
            "started_iso": "2026-09-20T00:00:00Z", "total_duration": 60,
            "client_argv": ["kr-client"], "server_argv": ["kr-server"],
            "build": "rust x86_64-unknown-linux-gnu", "server_build": "rust aarch64-linux",
            "uptime_before": {"cli-host": "load average: 0.10",
                              "srv-host": "load average: 0.31"},
            "uptime_after": {"cli-host": "load average: 0.55",
                             "srv-host": "load average: 0.62"},
            "workloads": [{"name": "wan-rr-r1-STAMP-w0", "tag": "lat", "type": "ping",
                           "duration": 60, "start_after": 0, "argv": []}],
        }

    def test_a_wan_report_names_both_hosts_and_refuses_to_imply_reproducibility(self):
        state = self.wan_state()
        (self.dir / "wan-rr-r1-STAMP-w0.log").write_text(
            'RESULT {"kind":"ping","rtt_p50_us":95000.0,"rtt_p90_us":99000.0,'
            '"rtt_p99_us":120000.0,"rtt_max_us":300000.0,"requests":600,"errors":0}\n')
        text = lab.markdown_report([state], [self.dir])
        self.assertIn("client host `cli-host`", text)
        self.assertIn("server host `srv-host`", text)
        self.assertIn("203.0.113.7", text)
        # The caveat that makes the numbers honest, in the generated file rather than in a
        # commit message nobody re-reads.
        self.assertIn("not reproducible between sessions", text)
        self.assertIn("GG, RR, GR, RG", text)
        # Both artefacts, because the two ends of a WAN run are different machines and, on the
        # 81.9 ms and 131.1 ms rungs, different architectures.
        self.assertIn("rust x86_64-unknown-linux-gnu", text)
        self.assertIn("rust aarch64-linux", text)
        for when in ("before", "after"):
            self.assertIn(f"uptime {when}, `cli-host`", text)
            self.assertIn(f"uptime {when}, `srv-host`", text)

    def test_a_wan_report_merges_the_two_machines_proc_and_snmp_files(self):
        state = self.wan_state()
        server_dir = self.dir / lab.SERVER_SUBDIR
        server_dir.mkdir()
        # Each machine samples only its own processes, so the client's file holds `cli` and the
        # server's holds `srv` — and both are called proc.csv.
        rows = PROC_CSV.splitlines()
        header, body = rows[0], rows[1:]
        (self.dir / "proc.csv").write_text(
            "\n".join([header] + [r for r in body if ",srv," not in r]) + "\n")
        (server_dir / "proc.csv").write_text(
            "\n".join([header] + [r for r in body if ",srv," in r]) + "\n")
        (self.dir / "snmp-cli.csv").write_text(SNMP_CSV)
        (server_dir / "snmp-srv.csv").write_text(SNMP_CSV)
        (server_dir / "wan-rr-r1-STAMP-srv.log").write_text("panic: on the server\n")

        merged = lab.collected_process_metrics(self.dir)
        self.assertEqual(sorted(merged), ["cli", "srv"])
        text = lab.markdown_report([state], [self.dir])
        self.assertIn("| cli | 2 |", text)
        self.assertIn("| srv | 2 |", text)
        self.assertIn("| RetransSegs | 5 | 5 |", text)
        # A crash on the far end is the one most easily missed; it must reach the notes.
        self.assertIn("panic: on the server", text)

    def compare_session(self, goodputs: dict[str, list[float]]) -> tuple[str, list, list]:
        """A session of iperf3 runs: `goodputs` maps a pair code to its repetitions."""
        states, directories = [], []
        started = 1790000000
        for code, values in goodputs.items():
            client = "go" if code[0] == "G" else "rust"
            server = "go" if code[1] == "G" else "rust"
            for index, value in enumerate(values, start=1):
                runid = f"wan-{code.lower()}-r{index}-STAMP"
                directory = self.dir / runid
                directory.mkdir()
                (directory / "iperf3-up.json").write_text(json.dumps({
                    "start": {"test_start": {"reverse": 0}},
                    "end": {"sum_sent": {"seconds": 60.0, "bits_per_second": value * 1e6,
                                         "retransmits": 3, "bytes": 1},
                            "sum_received": {"seconds": 60.0, "bits_per_second": value * 1e6,
                                             "bytes": 1}},
                }))
                (directory / "snmp-cli.csv").write_text(SNMP_CSV)
                started += 130
                states.append({
                    "runid": runid, "scenario": "wan", "host": "cli-host", "mode": "wan",
                    "server_host": "srv-host", "server_addr": "203.0.113.7", "config": "s1",
                    "netem": "none (real path)", "client_impl": client, "server_impl": server,
                    "repetition": index, "target": "iperf3", "started_unix": started,
                    "started_iso": "2026-09-20T00:00:00Z", "total_duration": 130,
                    "client_argv": [], "server_argv": [],
                    "workloads": [{"name": f"{runid}-w0", "tag": "up", "type": "iperf3",
                                   "duration": 60, "start_after": 0, "argv": []}],
                })
                directories.append(directory)
        return lab.compare_report(states, directories), states, directories

    def test_a_comparison_quotes_the_median_per_pair_and_the_rust_go_ratio(self):
        text, _, _ = self.compare_session({"GG": [100.0, 110.0, 120.0],
                                           "RR": [130.0, 140.0, 150.0]})
        self.assertIn("| iperf3/up | Mbit/s | 110 | 140 |", text)
        # The number 11.2's acceptance criterion is written in terms of, computed rather than
        # left to the reader: 140/110.
        self.assertIn("1.27×", text)
        self.assertIn("3×GG", text)
        self.assertIn("3×RR", text)

    def test_a_comparison_says_where_the_runs_came_from_and_over_what(self):
        text, _, _ = self.compare_session({"GG": [10.0], "RR": [10.0]})
        self.assertIn("`cli-host` → `srv-host`", text)
        self.assertIn("config S1", text)
        self.assertIn("interleaved", text)

    def test_a_pair_that_did_not_run_is_a_dash_and_never_a_zero(self):
        # A rung where only GG and RG could run (the Rust server end was pinned by somebody
        # else's soak) must not report RR as 0 Mbit/s.
        text, _, _ = self.compare_session({"GG": [100.0], "RG": [90.0]})
        self.assertIn("| GG | RG |", text)
        self.assertNotIn("| RR |", text)
        # With no RR column there is no ratio to print.
        self.assertIn("| — |", text)

    def test_the_snmp_counters_a_wan_rung_is_read_from_are_in_the_table(self):
        text, _, _ = self.compare_session({"GG": [100.0], "RR": [100.0]})
        for counter in ("RetransSegs", "FastRetransSegs", "LostSegs", "FECRecovered",
                        "FECErrs"):
            self.assertIn(counter, text)
        self.assertIn("| client |", text)

    def test_a_multi_run_report_leads_with_the_comparison(self):
        text, states, directories = self.compare_session({"GG": [100.0], "RR": [130.0]})
        report = lab.markdown_report(states, directories)
        self.assertIn("## Comparison", report)
        self.assertIn("| iperf3/up | Mbit/s | 100 | 130 |", report)
        # ...and the per-run sections are still below it, as the evidence for it.
        self.assertLess(report.index("## Comparison"), report.index("## wan-gg-r1-STAMP"))

    def test_a_single_run_report_has_no_comparison_to_make(self):
        _, states, directories = self.compare_session({"RR": [130.0]})
        self.assertNotIn("## Comparison", lab.markdown_report(states, directories))

    def test_a_session_is_found_by_prefix_and_its_runs_ordered_as_they_ran(self):
        import argparse

        session = self.dir / "20260923T230000Z-wan-s1-bulk"
        for name in ("wan-rr-r2-STAMP", "wan-gg-r1-STAMP"):
            run = session / name
            run.mkdir(parents=True)
            (run / "state.json").write_text(json.dumps({"runid": name}))
        args = argparse.Namespace(runs_dir=str(self.dir))
        found = lab.find_session(args, "20260923T230000Z")
        self.assertEqual([path.name for path in found],
                         ["wan-gg-r1-STAMP", "wan-rr-r2-STAMP"])
        with self.assertRaisesRegex(lab.LabError, "no session"):
            lab.find_session(args, "nothing-like-this")

    def test_two_proc_files_that_do_overlap_are_both_kept(self):
        # Never expected — the label sets are disjoint by construction — but silently dropping
        # one machine's samples would be the worst possible way to find out otherwise.
        server_dir = self.dir / lab.SERVER_SUBDIR
        server_dir.mkdir()
        (self.dir / "proc.csv").write_text(PROC_CSV)
        (server_dir / "proc.csv").write_text(PROC_CSV)
        self.assertEqual(sorted(lab.collected_process_metrics(self.dir)),
                         ["cli", "cli+", "srv", "srv+"])

    def test_a_long_run_report_quotes_the_slopes_it_is_accepted_on(self):
        state = {
            "runid": "soak-rr-r1-STAMP", "scenario": "soak", "host": "fake-host",
            "config": "s1", "netem": "wan50", "client_impl": "rust", "server_impl": "rust",
            "repetition": 1, "target": "pingpong", "started_iso": "2026-09-20T00:00:00Z",
            "total_duration": 21600, "client_argv": ["kr-client"], "server_argv": ["kr-server"],
            "workloads": [],
        }
        # Six hours of samples: a flat client and a client-shaped leak of 600 kB/h on the server.
        self._proc_csv([(40000, 600)] * 360, label="cli")
        flat = (self.dir / "proc.csv").read_text()
        self._proc_csv([(40000 + 10 * i, 600 + i) for i in range(360)], label="srv")
        leaking = (self.dir / "proc.csv").read_text().split("\n", 1)[1]
        (self.dir / "proc.csv").write_text(flat + leaking)
        text = lab.markdown_report([state], [self.dir])
        self.assertRegex(text, r"\| cli \|.*\| \+0\.0 \|")
        self.assertRegex(text, r"\| srv \|.*\| \+600\.0 \|")
        self.assertIn("samples taken after warm-up", text)
        # A tenth of the intended 21600 s, not of the 21540 s of samples.
        self.assertIn("from 2160 s", text)

    def test_a_soak_collected_early_says_so_instead_of_quoting_a_warm_up_gradient(self):
        state = {
            "runid": "soak-rr-r1-STAMP", "scenario": "soak", "host": "lab-x86-2",
            "build": "host x86_64, rust x86_64-unknown-linux-gnu (glibc 2.17)",
            "config": "s1", "netem": "wan50", "client_impl": "rust", "server_impl": "rust",
            "repetition": 1, "target": "pingpong", "started_iso": "2026-09-20T00:00:00Z",
            "total_duration": 21600, "client_argv": ["kr-client"], "server_argv": ["kr-server"],
            "workloads": [],
        }
        self._proc_csv([(40000 + 400 * i, 600 + i) for i in range(20)], label="cli")
        text = lab.markdown_report([state], [self.dir])
        self.assertIn("Too few samples after warm-up", text)
        self.assertIn("collected before warm-up ended", text)
        self.assertIn("1140 s of samples against an intended 21600 s", text)
        # The table is still printed, with an empty slope column rather than a wrong one.
        self.assertRegex(text, r"\| cli \|.*\| — \|")
        # Which host and which artefact, so two runs reported together can be told apart.
        self.assertIn("host `lab-x86-2`", text)
        self.assertIn("x86_64-unknown-linux-gnu (glibc 2.17)", text)

    def test_a_run_shorter_than_warm_up_is_not_called_collected_early(self):
        state = {
            "runid": "smoke", "scenario": "smoke", "host": "h", "config": "s1",
            "netem": "clean", "client_impl": "rust", "server_impl": "rust", "repetition": 1,
            "target": "pingpong", "started_iso": "2026-09-20T00:00:00Z", "total_duration": 60,
            "client_argv": [], "server_argv": [], "workloads": [],
        }
        (self.dir / "proc.csv").write_text(PROC_CSV)
        text = lab.markdown_report([state], [self.dir])
        self.assertIn("Too few samples after warm-up", text)
        self.assertNotIn("collected before warm-up ended", text)
        self.assertIn("build `(not recorded)`", text)

    def test_a_report_survives_a_run_that_produced_nothing(self):
        state = {
            "runid": "empty", "scenario": "unit", "host": "h", "config": "s1", "netem": "clean",
            "client_impl": "rust", "server_impl": "go", "repetition": 1, "target": "iperf3",
            "started_iso": "2026-09-20T00:00:00Z", "total_duration": 1,
            "client_argv": [], "server_argv": [],
            "workloads": [{"name": "empty-w0", "tag": "up", "type": "iperf3",
                           "duration": 1, "start_after": 0, "argv": []}],
        }
        text = lab.markdown_report([state], [self.dir])
        self.assertIn("no iperf3 report", text)


# --------------------------------------------------------------------------------------------
# deployment: which architecture, which libc (11.1b)
# --------------------------------------------------------------------------------------------


DEPLOY_SH = Path(lab.__file__).resolve().parent / "deploy.sh"

#: Every binary `deploy.sh --go` expects to find for one GOARCH, named as `reference/bin` names
#: them. Only `client` is checked by the script; the rest prove the glob strips the right suffix.
GO_PEERS = ("client", "server", "kcpecho", "smuxecho", "qppcheck", "snappycheck")


class DeployTests(unittest.TestCase):
    """`deploy.sh`, run for real with ssh, scp and cargo replaced by stubs.

    A wrong choice here is invisible until a run log says `Exec format error` or
    `GLIBC_2.39 not found`, which on a six-hour soak means six wasted hours.
    """

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        # A throwaway repository root, so a test can never build into (or copy out of) the real
        # target/ directory.
        self.root = self.tmp / "root"
        (self.root / "tools" / "lab").mkdir(parents=True)
        shutil.copy2(DEPLOY_SH, self.root / "tools" / "lab" / "deploy.sh")
        self.refbin = self.root / "reference" / "bin"
        self.refbin.mkdir(parents=True)
        # What tools/fetch-reference.sh leaves beside them. This — not this repository's HEAD —
        # is what identifies a Go reference binary: reference/ is a gitignored symlink to a
        # checkout shared between worktrees, and fetching a new one changes nothing in git.
        self.versions = self.root / "reference" / "VERSIONS.txt"
        self.versions.write_text(
            "kcptun v0.0.0-20260208051026-39935d5307f0\n"
            "  module zip sha256 c6340091d4b3fc93b414b4189f24157be064ff7cacb1a15b84e44162f1c1\n"
            "vendored modules (reference/kcptun/vendor/modules.txt):\n"
            "  github.com/xtaci/kcp-go/v5 v5.6.66\n"
            "built with go version go1.27.1 darwin/arm64\n")
        for goarch in ("arm64", "amd64"):
            for peer in GO_PEERS:
                self._exe(self.refbin / f"{peer}_linux_{goarch}", f"#!/bin/sh\necho {goarch}\n")
        self.stub = self.tmp / "stub"
        self.stub.mkdir()
        self.log = self.tmp / "calls.log"
        #: Everything deploy.sh wrote to a BUILD.txt, each block headed by the ssh command line
        #: that carried it — the stamps a later run's provenance check will read.
        self.stamps = self.tmp / "stamps.log"

    def _exe(self, path: Path, text: str) -> None:
        path.write_text(text)
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def _stubs(self, uname: str) -> None:
        """ssh answers `uname -m` with `uname`; scp and cargo just record what they were given.

        A `BUILD.txt` write is the one ssh invocation with something on stdin, so that branch —
        and only that branch — reads it: an unconditional `cat` would block on the test
        runner's own stdin for the `uname -m` round trip.
        """
        self._exe(self.stub / "ssh", f'''#!/bin/sh
echo "ssh $*" >> "{self.log}"
case "$*" in
  *BUILD.txt*) echo "=== stamp $*" >> "{self.stamps}"; cat >> "{self.stamps}" ;;
  *) echo {uname} ;;
esac
''')
        self._exe(self.stub / "scp", f'#!/bin/sh\necho "scp $*" >> "{self.log}"\n')
        # cargo records its arguments and then produces the artefacts the script will copy.
        self._exe(self.stub / "cargo", f'''#!/bin/sh
echo "cargo $*" >> "{self.log}"
target=""
while [ $# -gt 0 ]; do
  case "$1" in --target) target="$2"; shift ;; esac
  shift
done
# cargo-zigbuild strips the glibc suffix again when it places the output.
dir="{self.root}/target/${{target%%.[0-9]*}}/release"
mkdir -p "$dir"
for b in kcptun-client kcptun-server pingpong labsample; do : > "$dir/$b"; done
''')

    def _deploy(self, *args: str, uname: str = "x86_64", expect: int = 0) -> str:
        self._stubs(uname)
        env = dict(os.environ)
        env["PATH"] = f"{self.stub}:{env['PATH']}"
        env["KCPTUN_LAB_HOST"] = "fake-host"
        env.pop("KCPTUN_LAB_ARCH", None)
        env.pop("KCPTUN_LAB_GLIBC", None)
        proc = subprocess.run([str(self.root / "tools" / "lab" / "deploy.sh"), *args],
                              env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, expect, proc.stdout + proc.stderr)
        # A run rejected during argument parsing never reaches ssh, so there is no call log.
        calls = self.log.read_text() if self.log.exists() else ""
        return proc.stdout + proc.stderr + "\n" + calls

    def test_auto_follows_the_host_so_an_x86_box_gets_amd64_and_x86_64_builds(self):
        out = self._deploy("--go", "--rust", uname="x86_64")
        self.assertIn("--target x86_64-unknown-linux-musl", out)
        self.assertIn("Go reference (linux/amd64)", out)
        # The Go binaries are copied under kg-<name>, with the GOARCH suffix stripped.
        self.assertRegex(out, r"scp .*kg-client .*kg-server")
        self.assertNotIn("_linux_arm64", out)
        self.assertNotIn("_linux_amd64", out.split("Go reference", 1)[1])

    def test_auto_on_test_usa_still_does_exactly_what_it_did_before(self):
        out = self._deploy("--go", "--rust", uname="aarch64")
        self.assertIn("--target aarch64-unknown-linux-musl", out)
        self.assertNotIn("_linux_amd64", out)

    def test_an_explicit_arch_that_the_host_cannot_execute_is_refused(self):
        out = self._deploy("--arch", "aarch64", "--rust", uname="x86_64", expect=2)
        self.assertIn("refusing", out)
        self.assertNotIn("cargo", self.log.read_text())

    def test_gnu_targets_the_glibc_version_the_release_ships(self):
        # DECISIONS D07 / tools/release.sh: .2.17, which runs on Ubuntu 22.04 as well as 24.04.
        out = self._deploy("--rust", "--gnu", uname="x86_64")
        self.assertIn("--target x86_64-unknown-linux-gnu.2.17", out)
        self.assertIn("glibc 2.17", out)

    def test_the_glibc_version_can_be_raised_for_a_host_that_has_it(self):
        out = self._deploy("--rust", "--gnu", "--glibc", "2.39", uname="aarch64")
        self.assertIn("--target aarch64-unknown-linux-gnu.2.39", out)

    def test_the_lab_tools_are_built_for_the_same_target_as_the_tunnel(self):
        out = self._deploy("--rust", "--tools", "--gnu", uname="x86_64")
        built = [line for line in self.log.read_text().splitlines() if line.startswith("cargo ")]
        self.assertEqual(len(built), 2)
        for line in built:
            self.assertIn("--target x86_64-unknown-linux-gnu.2.17", line)
        self.assertIn("kr-pingpong", out)

    def test_a_missing_go_reference_for_the_selected_arch_says_which_file(self):
        for peer in GO_PEERS:
            (self.refbin / f"{peer}_linux_amd64").unlink()
        out = self._deploy("--go", uname="x86_64", expect=1)
        self.assertIn("client_linux_amd64", out)
        self.assertIn("fetch-reference.sh", out)

    def test_the_deployment_records_what_it_deployed(self):
        # docs/lab-results/ has to be able to say, a week later, which artefact produced a
        # number: D07 measured glibc returning 95.6% of a burst where musl returns 4.9%.
        out = self._deploy("--go", "--rust", "--gnu", uname="x86_64")
        self.assertIn("BUILD.txt", out)
        self.assertIn("rust x86_64-unknown-linux-gnu (glibc 2.17)", out)
        self.assertIn("go linux/amd64", out)
        self.assertIn("profile release", out)

    def test_a_scripts_only_deployment_claims_no_build(self):
        out = self._deploy("--scripts", uname="x86_64")
        self.assertNotIn("BUILD.txt", out)

    def test_an_unknown_architecture_is_named_in_the_error(self):
        out = self._deploy("--rust", uname="riscv64", expect=2)
        self.assertIn("riscv64", out)

    def test_a_build_from_a_dirty_tree_says_so_in_the_recorded_revision(self):
        # Lab binaries are routinely cross-built from a working tree that is ahead of HEAD, and
        # a bare commit id would tell a later reader to check that commit out and expect the
        # same binary.
        git = ["git", "-c", "user.email=l@b", "-c", "user.name=lab", "-C", str(self.root)]
        subprocess.run(["git", "-C", str(self.root), "init", "-q"], check=True)
        subprocess.run([*git, "add", "-A"], check=True)
        subprocess.run([*git, "commit", "-qm", "lab"], check=True)
        clean = self._deploy("--go", uname="x86_64")
        self.assertNotIn("-dirty", clean)
        (self.root / "tools" / "lab" / "scratch.txt").write_text("uncommitted\n")
        dirty = self._deploy("--go", uname="x86_64")
        self.assertIn("-dirty", dirty)

    def _stamp(self, remote_dir: str) -> dict[str, str]:
        """The fields of the stamp written to `~/kcptun-lab/<remote_dir>/BUILD.txt`.

        Parsed with `lab.parse_build_stamp`, so what `deploy.sh` writes is read here by exactly
        the code that refuses a run — the two halves of 12.0 cannot drift apart silently.
        """
        text = self.stamps.read_text() if self.stamps.exists() else ""
        blocks: dict[str, list[str]] = {}
        header = ""
        for line in text.splitlines():
            if line.startswith("=== stamp "):
                header = line
                blocks[header] = []
            elif header:
                blocks[header].append(line)
        for head, body in blocks.items():
            if f"kcptun-lab/{remote_dir}/BUILD.txt" in head:
                fields, summary = lab.parse_build_stamp("\n".join(body))
                return {**fields, "summary": summary}
        return {}

    def test_every_directory_that_receives_a_binary_is_stamped_beside_it(self):
        # 11.3's server host had one stamp a directory above a kr-server that no deployment had
        # replaced, and `server_build` was empty in all 27 runs. The stamp now lives with the
        # binaries it describes — and there is one per family, not one per deployment.
        self._deploy("--go", "--rust", "--tools", uname="x86_64")
        self.assertEqual(self._stamp("bin/rust")["kind"], "rust")
        self.assertEqual(self._stamp("bin/go")["kind"], "go")
        self.assertEqual(self._stamp("bin/lab")["kind"], "lab")
        # The old aggregate path still holds something for whoever knows it, marked as what it
        # is: a manifest of one deployment, not a description of any particular binary.
        aggregate = self._stamp("bin")
        self.assertEqual(aggregate["kind"], "deployment")
        self.assertEqual(aggregate["stamps"], "bin/rust bin/lab bin/go")

    def test_both_tunnel_binaries_are_named_and_hashed_in_the_rust_stamp(self):
        self._deploy("--rust", uname="x86_64")
        stamp = self._stamp("bin/rust")
        self.assertEqual(stamp["binaries"], "kr-client kr-server")
        empty = hashlib.sha256(b"").hexdigest()  # the cargo stub produces empty artefacts
        self.assertEqual(stamp["sha256.kr-client"], empty)
        self.assertEqual(stamp["sha256.kr-server"], empty)
        for field_name in lab.REQUIRED_BUILD_FIELDS:
            self.assertTrue(stamp.get(field_name), field_name)

    def test_the_stamp_survives_every_architecture_and_libc_combination(self):
        # A server-only host is deployed with exactly these flags, and each combination used to
        # be a chance to leave one side of a comparison unattributable.
        for uname, arch, gnu in (("x86_64", "x86_64", False), ("x86_64", "x86_64", True),
                                 ("aarch64", "aarch64", False), ("aarch64", "aarch64", True)):
            with self.subTest(arch=arch, gnu=gnu):
                self.log.unlink(missing_ok=True)
                self.stamps.unlink(missing_ok=True)
                args = ["--rust", "--arch", arch] + (["--gnu"] if gnu else [])
                self._deploy(*args, uname=uname)
                stamp = self._stamp("bin/rust")
                libc = "glibc 2.17" if gnu else "static musl"
                triple = f"{arch}-unknown-linux-{'gnu' if gnu else 'musl'}"
                self.assertEqual(stamp["target"], triple)
                self.assertEqual(stamp["libc"], libc)
                self.assertEqual(stamp["binaries"], "kr-client kr-server")
                self.assertIn(triple, stamp["summary"])

    def test_the_go_stamp_names_the_go_binaries_and_links_no_libc(self):
        self._deploy("--go", uname="aarch64")
        stamp = self._stamp("bin/go")
        self.assertEqual(stamp["target"], "linux/arm64")
        self.assertEqual(stamp["libc"], "none")
        for peer in GO_PEERS:
            self.assertIn(f"kg-{peer}", stamp["binaries"])
            self.assertIn(f"sha256.kg-{peer}", stamp)

    def test_the_go_stamp_names_the_reference_it_came_from_not_this_repositorys_commit(self):
        # `commit` is this tree's HEAD, and this tree does not contain reference/ at all: it is
        # a gitignored symlink to a checkout shared between worktrees, so the commit says when
        # the deployment happened, not what was deployed. reference/VERSIONS.txt does.
        self._deploy("--go", uname="aarch64")
        stamp = self._stamp("bin/go")
        self.assertEqual(stamp["reference_version"], "v0.0.0-20260208051026-39935d5307f0")
        self.assertEqual(stamp["go_toolchain"], "go1.27.1")
        # ...and the fields lab.py requires are untouched by the addition.
        for field_name in lab.REQUIRED_BUILD_FIELDS:
            self.assertTrue(stamp.get(field_name), field_name)

    def test_a_missing_versions_file_is_recorded_as_unknown_not_omitted(self):
        # A field that is simply absent reads as "nobody thought about this", which is how an
        # empty `server_build` went 27 runs deep in 11.3.
        self.versions.unlink()
        self._deploy("--go", uname="aarch64")
        stamp = self._stamp("bin/go")
        self.assertEqual(stamp["reference_version"], "unknown")
        self.assertEqual(stamp["go_toolchain"], "unknown")

    def test_only_the_go_stamp_carries_the_reference_fields(self):
        # The Rust binaries ARE this tree, so `commit` identifies them and a reference version
        # beside them would be noise pointing at the wrong provenance.
        self._deploy("--rust", "--tools", uname="x86_64")
        for remote_dir in ("bin/rust", "bin/lab"):
            self.assertNotIn("reference_version", self._stamp(remote_dir), remote_dir)

    def test_the_lab_tools_stamp_covers_the_workload_driver_and_the_sampler(self):
        self._deploy("--tools", uname="x86_64")
        stamp = self._stamp("bin/lab")
        self.assertEqual(stamp["binaries"], "kr-labsample kr-pingpong")  # glob order
        self.assertIn("sha256.kr-labsample", stamp)
        self.assertIn("sha256.kr-pingpong", stamp)

    def test_a_scripts_only_deployment_writes_no_stamp_anywhere(self):
        self._deploy("--scripts", uname="x86_64")
        self.assertFalse(self.stamps.exists())

    def test_the_stamp_carries_the_full_commit_and_says_when_the_tree_was_dirty(self):
        git = ["git", "-c", "user.email=l@b", "-c", "user.name=lab", "-C", str(self.root)]
        subprocess.run(["git", "-C", str(self.root), "init", "-q"], check=True)
        subprocess.run([*git, "add", "-A"], check=True)
        subprocess.run([*git, "commit", "-qm", "lab"], check=True)
        head = subprocess.run(["git", "-C", str(self.root), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
        self._deploy("--rust", uname="x86_64")
        clean = self._stamp("bin/rust")
        self.assertEqual(clean["commit"], head)
        self.assertEqual(clean["tree"], "clean")
        self.assertEqual(clean["revision"], head[:7])

        self.stamps.unlink()
        (self.root / "tools" / "lab" / "scratch.txt").write_text("uncommitted\n")
        self._deploy("--rust", uname="x86_64")
        dirty = self._stamp("bin/rust")
        self.assertEqual(dirty["commit"], head)
        self.assertEqual(dirty["tree"], "dirty")
        self.assertTrue(dirty["revision"].endswith("-dirty"), dirty["revision"])

    def test_a_flag_typed_without_its_value_says_which_flag(self):
        # Under `set -u` the shell would otherwise abort with `$2: unbound variable`, which does
        # not say which flag was mistyped, and these are the flags a person types by hand when
        # pointing the lab at a new box.
        for flag in ("--arch", "--glibc", "--profile"):
            with self.subTest(flag=flag):
                out = self._deploy("--rust", flag, uname="x86_64", expect=2)
                self.assertIn(flag, out)
                self.assertNotIn("unbound variable", out)


class DeployFlagTests(unittest.TestCase):
    """`lab.py deploy` has to hand the new choices on to `deploy.sh`."""

    def _argv(self, *args: str) -> list[str]:
        parser = lab.build_parser()
        parsed = parser.parse_args(["deploy", *args])
        runner = FakeRunner()
        self.assertEqual(lab.cmd_deploy(runner, parsed), 0)
        local = [c for c in runner.calls if c[0] == "local"]
        self.assertEqual(len(local), 1)
        return list(local[0][1:])

    def test_the_default_deploy_passes_no_architecture_at_all(self):
        argv = self._argv()
        self.assertTrue(argv[0].endswith("deploy.sh"))
        self.assertEqual(argv[1:], [])

    def test_the_architecture_libc_and_profile_are_passed_through(self):
        argv = self._argv("--rust", "--gnu", "--arch", "x86_64", "--glibc", "2.35",
                          "--profile", "profiling")
        self.assertEqual(argv[1:], ["--rust", "--gnu", "--arch", "x86_64",
                                    "--glibc", "2.35", "--profile", "profiling"])


class MatrixTests(unittest.TestCase):
    """step 11.2: many sessions, one per (config, netem) cell, read as one table."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.started = 1790000000

    def cell(self, config: str, netem: str, goodputs: dict[str, list[float]],
             *, snmp: str = SNMP_CSV, snmp_srv: str | None = None,
             proc: bool = False, stamp: str = "STAMP",
             sockbuf: dict[str, int] | None = None) -> None:
        """One cell's runs on disk, as `lab.py run --config --netem` would leave them."""
        limits = sockbuf or {"rmem_max": 212992, "wmem_max": 212992}
        for code, values in goodputs.items():
            client = "go" if code[0] == "G" else "rust"
            server = "go" if code[1] == "G" else "rust"
            for index, value in enumerate(values, start=1):
                runid = f"bulk-{config}-{netem}-{code.lower()}-r{index}-{stamp}"
                directory = self.dir / f"{stamp}-bulk-{config}-{netem}" / runid
                directory.mkdir(parents=True)
                (directory / "iperf3-up.json").write_text(json.dumps({
                    "start": {"test_start": {"reverse": 0}},
                    "end": {"sum_sent": {"seconds": 30.0, "bits_per_second": value * 1e6,
                                         "retransmits": 3, "bytes": 1},
                            "sum_received": {"seconds": 30.0, "bits_per_second": value * 1e6,
                                             "bytes": 1}},
                }))
                (directory / "snmp-cli.csv").write_text(snmp)
                (directory / "snmp-srv.csv").write_text(snmp_srv or snmp)
                if proc:
                    (directory / "proc.csv").write_text(PROC_CSV)
                self.started += 90
                (directory / "state.json").write_text(json.dumps({
                    "runid": runid, "scenario": f"bulk-{config}-{netem}", "host": "lab-host",
                    "source": "tools/lab/scenarios/bulk-iperf3.json",
                    "mode": "netns", "config": config, "netem": netem,
                    "build": "rust x86_64-unknown-linux-gnu (glibc 2.17), rev abc1234",
                    "client_impl": client, "server_impl": server, "repetition": index,
                    "target": "iperf3", "started_unix": self.started,
                    "started_iso": "2026-09-24T00:00:00Z", "total_duration": 65,
                    "client_argv": [], "server_argv": [],
                    "socket_buffer_limits": {"lab-host": limits},
                    "workloads": [{"name": f"{runid}-w0", "tag": "up", "type": "iperf3",
                                   "duration": 30, "start_after": 0, "argv": []}],
                }))

    def report(self, prefix: str = "STAMP-bulk") -> str:
        import argparse

        args = argparse.Namespace(runs_dir=str(self.dir), sessions=[prefix], report=None)
        directories = []
        for name in args.sessions:
            for session in lab.find_matrix_sessions(args, name):
                directories.extend(sorted(path.parent
                                          for path in session.glob("*/state.json")))
        states = [json.loads((path / "state.json").read_text()) for path in directories]
        order = sorted(range(len(states)), key=lambda i: states[i].get("started_unix", 0))
        return lab.matrix_report([states[i] for i in order], [directories[i] for i in order])

    def test_cells_are_ordered_by_configuration_then_by_impairment(self):
        # Sessions land on disk in whatever order the campaign ran them; the table is read as a
        # ladder of impairment, so tools/lab/README.md's order is the one that matters.
        self.cell("s1", "lossy10", {"GG": [10.0], "RR": [10.0]})
        self.cell("s1", "clean", {"GG": [100.0], "RR": [100.0]})
        self.cell("s1", "wan50", {"GG": [50.0], "RR": [50.0]})
        text = self.report()
        where = {profile: text.index(f"| S1 | {profile} | bulk-iperf3 |")
                 for profile in ("clean", "wan50", "lossy10")}
        self.assertLess(where["clean"], where["wan50"])
        self.assertLess(where["wan50"], where["lossy10"])

    def test_a_cell_that_meets_the_acceptance_ratio_is_marked_ok(self):
        self.cell("s1", "clean", {"GG": [100.0, 100.0], "RR": [98.0, 98.0]})
        row = [line for line in self.report().splitlines()
               if line.startswith("| S1 | clean | bulk-iperf3 | up |")]
        self.assertEqual(len(row), 1, row)
        self.assertIn("0.98×", row[0])
        self.assertIn("| ok |", row[0])

    def test_a_cell_below_the_acceptance_ratio_is_flagged_rather_than_averaged_away(self):
        # 0.80x is the case the step exists to catch. It must be visible in the row itself,
        # not left for the reader to divide two columns.
        self.cell("s1", "lossy10", {"GG": [100.0], "RR": [80.0]})
        row = [line for line in self.report().splitlines()
               if line.startswith("| S1 | lossy10 | bulk-iperf3 | up |")][0]
        self.assertIn("0.80×", row)
        self.assertIn("**investigate**", row)

    def test_a_cell_missing_a_pair_has_no_ratio_and_no_verdict(self):
        # Never a 0.00x verdict from a pair that did not run: that reads as a catastrophic
        # regression rather than as missing data.
        self.cell("s1", "burst", {"GG": [100.0], "GR": [90.0]})
        row = [line for line in self.report().splitlines()
               if line.startswith("| S1 | burst | bulk-iperf3 | up |")][0]
        self.assertNotIn("×", row)
        self.assertIn("| — | — |", row)

    def test_the_matrix_reports_tunnel_cpu_per_delivered_bit(self):
        # PROC_CSV: cli 0.65 s + srv 0.90 s of CPU = 1.55 s, over 100 Mbit/s x 30 s = 3000
        # Mbit, so 1000 x 1.55 / 3000 = 0.5167 ms/Mbit. That ratio is how D29's flush-scan cost
        # is read on a host whose throughput is itself CPU-bound.
        self.cell("s1", "lossy2", {"GG": [100.0], "RR": [100.0]}, proc=True)
        text = self.report()
        self.assertIn("### Tunnel CPU per delivered bit", text)
        cpu_section = text.split("### Tunnel CPU per delivered bit")[1].split("###")[0]
        row = [line for line in cpu_section.splitlines()
               if line.startswith("| S1 | lossy2 | bulk-iperf3 |")][0]
        self.assertIn("0.52", row)
        self.assertIn("1.00×", row)

    def test_the_retransmission_figures_are_attributed_per_side_and_per_pair(self):
        # SNMP_CSV's last record: OutSegs 80, RetransSegs 5 (2 of them fast), LostSegs 1,
        # RepeatSegs 0 — so 6.25 % retransmitted and 40 % of that fast.
        self.cell("s1", "wan50", {"GG": [10.0], "RR": [10.0]})
        text = self.report()
        self.assertIn("### Retransmission attribution", text)
        self.assertIn("| S1 | wan50 | bulk-iperf3 | client | retrans % | 6.25 | 6.25 |", text)
        self.assertIn("| S1 | wan50 | bulk-iperf3 | client | fast % of retrans | 40 | 40 |", text)
        self.assertIn("| S1 | wan50 | bulk-iperf3 | server | retrans % | 6.25 | 6.25 |", text)

    def test_the_duplicate_ratio_pairs_one_ends_duplicates_with_the_others_timeouts(self):
        # RepeatSegs is a receive-side counter and LostSegs a send-side one, so a ratio taken
        # within one process compares a duplicate to a timeout that did not cause it. The
        # server here RECEIVES 30 duplicates while the client TIMES OUT on 3 segments: 10x, and
        # the storm is spurious. Taken per side it would have read 30/2 and 6/3.
        client = SNMP_CSV.replace(
            "1790000060,1000,2000,4,4,0,3,0,0,0,50,60,70,80,5,2,0,1,0,0,7,0",
            "1790000060,1000,2000,4,4,0,3,0,0,0,50,60,70,80,5,2,0,3,6,0,7,0")
        server = SNMP_CSV.replace(
            "1790000060,1000,2000,4,4,0,3,0,0,0,50,60,70,80,5,2,0,1,0,0,7,0",
            "1790000060,1000,2000,4,4,0,3,0,0,0,50,60,70,80,5,2,0,2,30,0,7,0")
        self.cell("s1", "wan50", {"GG": [10.0], "RR": [10.0]},
                  snmp=client, snmp_srv=server)
        text = self.report()
        prefix = "| S1 | wan50 | bulk-iperf3 | both |"
        self.assertIn(f"{prefix} server dups / client lost | 10 | 10 |", text)
        self.assertIn(f"{prefix} client dups / server lost | 3 | 3 |", text)

    def latency_cell(self, netem: str, percentiles: dict[str, list[float]]) -> None:
        """A `latency` cell: one idle probe and one against a competing flow, per pair."""
        for code, values in percentiles.items():
            client = "go" if code[0] == "G" else "rust"
            server = "go" if code[1] == "G" else "rust"
            for index, p50_us in enumerate(values, start=1):
                runid = f"lat-s1-{netem}-{code.lower()}-r{index}-STAMP"
                directory = self.dir / f"STAMP-lat-s1-{netem}" / runid
                directory.mkdir(parents=True)
                workloads = []
                for tag, scale in (("lat64", 1.0), ("lat64load", 10.0)):
                    name = f"{runid}-w{len(workloads)}"
                    (directory / f"{name}.log").write_text(
                        "RESULT " + json.dumps({
                            "rtt_p50_us": p50_us * scale, "rtt_p90_us": p50_us * scale * 2,
                            "rtt_p99_us": p50_us * scale * 4,
                            "rtt_max_us": p50_us * scale * 8, "errors": 0,
                        }) + "\n")
                    workloads.append({"name": name, "tag": tag, "type": "ping",
                                      "duration": 30, "start_after": 0, "argv": []})
                self.started += 90
                (directory / "state.json").write_text(json.dumps({
                    "runid": runid, "scenario": f"lat-s1-{netem}", "host": "lab-host",
                    "source": "tools/lab/scenarios/latency.json",
                    "mode": "netns", "config": "s1", "netem": netem, "build": "b",
                    "client_impl": client, "server_impl": server, "repetition": index,
                    "target": "pingpong", "started_unix": self.started,
                    "started_iso": "2026-09-24T00:00:00Z", "total_duration": 65,
                    "client_argv": [], "server_argv": [], "workloads": workloads,
                }))

    def test_the_latency_table_keeps_the_idle_and_the_loaded_probe_apart(self):
        import argparse

        self.latency_cell("wan50", {"GG": [200.0], "RR": [100.0]})
        args = argparse.Namespace(runs_dir=str(self.dir), sessions=["STAMP-lat"], report=None)
        directories = []
        for session in lab.find_matrix_sessions(args, "STAMP-lat"):
            directories.extend(sorted(path.parent for path in session.glob("*/state.json")))
        states = [json.loads((path / "state.json").read_text()) for path in directories]
        text = lab.matrix_report(states, directories)
        # 200 us and 100 us idle; ten times that under the competing flow. Averaging the two
        # probes into one row is exactly what the scenario splits them to avoid.
        self.assertIn("| S1 | wan50 | lat64 | p50 ms | 0.20 | 0.10 | 0.50× |", text)
        self.assertIn("| S1 | wan50 | lat64load | p50 ms | 2 | 1 | 0.50× |", text)
        # Lower is better here, so the reader is told which way the ratio points.
        self.assertIn("RR/GG below 1 is Rust ahead", text)

    def test_a_clean_campaign_says_so_and_a_dirty_one_names_the_run(self):
        # "The mixed pairs complete without errors" is half of 11.2's acceptance criterion, and
        # a campaign driven with --no-report has no per-session report to find it in.
        self.cell("s1", "clean", {"GG": [100.0], "RR": [100.0]})
        self.assertIn("None, in any of the 2 runs.", self.report())
        run = next((self.dir / "STAMP-bulk-s1-clean").glob("*-rr-*"))
        (run / "cli.log").write_text("all fine\npanic: runtime error: index out of range\n")
        text = self.report()
        self.assertIn("1 of 2 runs matched an error marker", text)
        self.assertIn("panic: runtime error", text)

    def test_the_matrix_says_the_numbers_are_relative_and_names_the_build(self):
        # A table of throughputs measured with both ends on one box invites being read as an
        # absolute figure, and a table with no build behind it cannot be attributed at all.
        self.cell("s1", "clean", {"GG": [100.0], "RR": [100.0]})
        text = self.report()
        self.assertIn("share **one host**", text)
        self.assertIn("glibc 2.17", text)
        # ...and neither can one whose -sockbuf the kernel quietly shrank by 40x.
        self.assertIn("lab-host rmem_max 212992", text)
        # One ceiling behind every run: the preamble has said it, so a column repeating it in
        # every row would be noise.
        self.assertNotIn("ceiling rmem/wmem", text)

    def test_two_socket_buffer_ceilings_are_kept_apart_rather_than_averaged(self):
        # The campaign and the controlled re-run of three of its cells were the same host, the
        # same scenario file, the same config and the same profiles on the same day — every
        # component of the cell key, and every component of the session-name prefix `lab.py
        # matrix` selects on. Only the kernel's `rmem_max` differed, and it is what the whole
        # 11.2 result turned on: a median across the two is a number no experiment produced.
        self.cell("s1", "clean", {"GG": [581.0], "RR": [499.0]})
        self.cell("s1", "clean", {"GG": [722.0], "RR": [1047.0]}, stamp="RAISED",
                  sockbuf={"rmem_max": 8388608, "wmem_max": 67108864})
        text = self.report("bulk-s1-clean")
        self.assertIn("2 cells, 4 runs", text)
        self.assertIn("| S1 | clean | 212992/212992 | bulk-iperf3 | up | 581 | 499 | "
                      "0.86× | **investigate** |", text)
        self.assertIn("| S1 | clean | 8388608/67108864 | bulk-iperf3 | up | 722 | 1,047 | "
                      "1.45× | ok |", text)
        # Merged, these read 652 / 773 = 1.19x and are stamped `ok`: a passing verdict for an
        # experiment nobody ran, sitting on top of one that fails.
        self.assertNotIn("1.19×", text)
        self.assertIn("More than one ceiling is represented here", text)

    def test_a_share_with_no_retransmissions_behind_it_is_not_reported_as_zero(self):
        # "0 % of the retransmissions were fast" and "there were no retransmissions" are
        # opposite readings of the same cell, and the second one is what an empty denominator
        # means. format_number's contract: None is "—", never 0.
        quiet = SNMP_CSV.replace(",5,2,0,1,0,0,7,0", ",0,0,0,0,0,0,7,0")
        self.cell("s1", "clean", {"GG": [100.0], "RR": [100.0]}, snmp=quiet)
        text = self.report()
        self.assertIn("| S1 | clean | bulk-iperf3 | client | retrans % | 0 | 0 |", text)
        self.assertIn("| S1 | clean | bulk-iperf3 | client | fast % of retrans | — | — |", text)

    def test_the_session_counters_are_in_the_table_that_evidences_no_stuck_sessions(self):
        # "No stuck sessions" is one of step 11.2's four acceptance criteria and the only
        # one with no artefact behind it: lab-runs/ is gitignored, so a claim about CurrEstab
        # that no committed table carries cannot be checked by anyone afterwards.
        # SNMP_CSV: MaxConn 4, CurrEstab 1 then 3 — so peak 3 and end 3.
        self.cell("s1", "clean", {"GG": [100.0], "RR": [100.0]})
        text = self.report()
        self.assertIn("| S1 | clean | bulk-iperf3 | client | MaxConn | 4 | 4 |", text)
        self.assertIn("| S1 | clean | bulk-iperf3 | client | CurrEstab (peak) | 3 | 3 |", text)
        self.assertIn("| S1 | clean | bulk-iperf3 | client | CurrEstab (end) | 3 | 3 |", text)


class MatrixOverrideTests(unittest.TestCase):
    """`run --config/--netem`: 11.2's two axes belong on the command line, not in 28 files."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def scenario(self, **extra) -> str:
        path = self.root / "s.json"
        path.write_text(json.dumps({
            "name": "bulk", "settle": 0, "sample_interval": 5, "snmp_period": 5,
            "workloads": [{"type": "ping", "tag": "lat", "duration": 1}], **extra,
        }))
        return str(path)

    def test_both_axes_go_into_the_names_the_run_leaves_on_disk(self):
        runner = FakeRunner()
        args = run_args(scenario=self.scenario(), runs_dir=str(self.root / "runs"),
                        config="s3", netem="lossy10")
        self.assertEqual(lab.cmd_run(runner, args), 0)
        # The session directory, the run id and every pid file name the cell, so two cells of
        # one campaign are still distinguishable once they are only files.
        sessions = [p.name for p in (self.root / "runs").iterdir()]
        self.assertEqual(len(sessions), 1, sessions)
        self.assertTrue(sessions[0].endswith("-bulk-s3-lossy10"), sessions[0])
        self.assertTrue(all(name.startswith("bulk-s3-lossy10-")
                            for name in runner.started()),
                        runner.started())
        # ...and the flags really are S3's, not the file's S1 default.
        client = [c for c in runner.lab_calls("start") if "-cli" in " ".join(c)][0]
        self.assertIn("aes-128-gcm", client)
        self.assertIn("fast3", client)

    def test_a_host_that_will_shrink_the_sockbuf_says_so_before_the_run(self):
        # The S1 profile asks for -sockbuf 8388608 and a stock Ubuntu box gives 212992. On the
        # 11.2 matrix that clamp was the entire S1 lossy10 result, so it cannot be silent.
        runner = FakeRunner()
        args = run_args(scenario=self.scenario(), runs_dir=str(self.root / "runs"),
                        config="s1", netem="lossy10")
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            self.assertEqual(lab.cmd_run(runner, args), 0)
        text = errors.getvalue()
        # Both ceilings, because -sockbuf sets SO_SNDBUF and SO_RCVBUF alike.
        self.assertIn("net.core.rmem_max is 212992", text)
        self.assertIn("net.core.wmem_max is 212992", text)
        self.assertIn("receive buffer", text)
        self.assertIn("send buffer", text)
        self.assertIn("39x smaller than asked for", text)
        # ...and the ceiling is on the record, not only on somebody's terminal.
        state = json.loads(next((self.root / "runs").glob("*/*/state.json")).read_text())
        self.assertEqual(state["socket_buffer_limits"]["fake-host"],
                         {"rmem_max": 212992, "wmem_max": 212992})

    def test_the_netem_override_is_refused_on_a_real_path(self):
        # parse_scenario refuses `mode: wan` with a netem profile; the override must not be a
        # way round it, or the report claims an impairment the run never had.
        runner = FakeRunner()
        args = run_args(scenario=self.scenario(mode="wan", server_host="b", server_addr="1.2.3.4"),
                        runs_dir=str(self.root / "runs"), netem="lossy2")
        with self.assertRaisesRegex(lab.LabError, "cannot apply netem|real path"):
            lab.cmd_run(runner, args)
        self.assertEqual(runner.started(), [])

    def test_a_run_refuses_a_host_that_cannot_say_what_it_deployed(self):
        # 11.3's 131 ms rung was measured with `server_build` empty in all 27 runs, and the
        # result cannot be attributed to this tree's binary. An unattributable number is worse
        # than a run that did not happen, so the run does not start.
        class Blank(FakeRunner):
            def ssh(self, command, *, check=True, timeout=120.0):
                if "BUILD.txt" in command:
                    self.calls.append(("ssh", command))
                    return lab.Result([], 0, "", "")
                return super().ssh(command, check=check, timeout=timeout)

        runner = Blank()
        args = run_args(scenario=self.scenario(), runs_dir=str(self.root / "runs"))
        with self.assertRaisesRegex(lab.LabError, "BUILD.txt"):
            lab.cmd_run(runner, args)
        self.assertEqual(runner.started(), [])


class BitrateOverrideTests(unittest.TestCase):
    """`run --bitrate`: the iperf3 guard rail belongs to the path, not to the scenario file.

    400M never binds on 11.3's 131 ms rung and binds hard on the 95 ms one (a Go client alone
    drives 631 Mbit/s there), and a cap that binds makes every implementation report the cap —
    which is how 11.3's first attempt produced four pairs all reporting exactly 60.0 Mbit/s.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def scenario(self, workloads) -> str:
        path = self.root / "s.json"
        path.write_text(json.dumps({
            "name": "bulk", "settle": 0, "sample_interval": 5, "snmp_period": 5,
            "workloads": workloads,
        }))
        return str(path)

    def iperf_scenario(self) -> str:
        return self.scenario([
            {"type": "iperf3", "tag": "up", "duration": 1, "bitrate": "400M"},
            {"type": "iperf3", "tag": "down", "duration": 1, "reverse": True},
        ])

    def test_the_override_reaches_every_iperf3_workload_of_the_session(self):
        # Both directions and every pair share one cap: a cap that applied to one arm and not
        # the other would be a handicap rather than a guard rail.
        runner = FakeRunner()
        args = run_args(scenario=self.iperf_scenario(), runs_dir=str(self.root / "runs"),
                        bitrate="900M")
        self.assertEqual(lab.cmd_run(runner, args), 0)
        state = json.loads(next((self.root / "runs").glob("*/*/state.json")).read_text())
        for workload in state["workloads"]:
            argv = workload["argv"]
            self.assertIn("-b", argv)
            self.assertEqual(argv[argv.index("-b") + 1], "900M")
        # It replaces the file's cap rather than being appended beside it.
        self.assertEqual(state["workloads"][0]["argv"].count("-b"), 1)
        self.assertNotIn("400M", state["workloads"][0]["argv"])

    def test_the_cap_is_not_part_of_the_name_because_it_is_not_an_axis(self):
        # --config/--netem name the cell they measure; the cap is a guard rail that must never
        # bind, so it would only make two sessions of the same cell look like different ones.
        runner = FakeRunner()
        args = run_args(scenario=self.iperf_scenario(), runs_dir=str(self.root / "runs"),
                        bitrate="900M")
        self.assertEqual(lab.cmd_run(runner, args), 0)
        sessions = [p.name for p in (self.root / "runs").iterdir()]
        self.assertTrue(sessions[0].endswith("-bulk"), sessions[0])

    def test_a_scenario_with_nothing_to_cap_is_refused_rather_than_ignored(self):
        # -b is an iperf3 flag. Silently dropping it would leave a session believing it ran
        # under a cap it never had.
        runner = FakeRunner()
        args = run_args(scenario=self.scenario([{"type": "ping", "tag": "lat", "duration": 1}]),
                        runs_dir=str(self.root / "runs"), bitrate="900M")
        with self.assertRaisesRegex(lab.LabError, "no iperf3 workload"):
            lab.cmd_run(runner, args)
        self.assertEqual(runner.started(), [])

    def test_the_run_says_out_loud_that_the_guard_rail_was_moved(self):
        runner = FakeRunner()
        args = run_args(scenario=self.iperf_scenario(), runs_dir=str(self.root / "runs"),
                        bitrate="900M")
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            self.assertEqual(lab.cmd_run(runner, args), 0)
        self.assertIn("-b 900M", errors.getvalue())

    def test_without_the_override_the_scenario_keeps_its_own_cap(self):
        runner = FakeRunner()
        args = run_args(scenario=self.iperf_scenario(), runs_dir=str(self.root / "runs"))
        self.assertEqual(lab.cmd_run(runner, args), 0)
        state = json.loads(next((self.root / "runs").glob("*/*/state.json")).read_text())
        up, down = state["workloads"]
        self.assertEqual(up["argv"][up["argv"].index("-b") + 1], "400M")
        self.assertNotIn("-b", down["argv"])


class SshRetryTests(unittest.TestCase):
    """Every lab host is a VPS under continuous ssh brute force; a dropped key exchange is not
    a reason to abandon a twelve-run cell half way through."""

    def result(self, code: int, out: str = "", err: str = "") -> lab.Result:
        return lab.Result(["ssh"], code, out, err)

    def test_a_key_exchange_that_never_completed_is_retried(self):
        err = ("kex_exchange_identification: read: Connection reset by peer\n"
               "Connection reset by <lab-x86-2-ip> port 22\n")
        self.assertTrue(lab.ssh_should_retry(self.result(255, "", err)))

    def test_a_remote_command_that_failed_is_never_retried(self):
        # 255 is ssh's own; anything else is the command's exit status, whatever it printed.
        self.assertFalse(lab.ssh_should_retry(
            self.result(1, "", "lab: lab port(s) already in use: 5201")))
        # A mid-session drop may have run the command, so it is not in the marker list.
        self.assertFalse(lab.ssh_should_retry(
            self.result(255, "", "client_loop: send disconnect: Broken pipe")))
        # ...and neither is a *remote* program that merely printed a matching phrase.
        self.assertFalse(lab.ssh_should_retry(
            self.result(255, "connection refused\n", "connection refused\n")))
        self.assertFalse(lab.ssh_should_retry(self.result(0, "fine", "")))

    def test_ssh_gives_up_after_the_backoff_and_reports_the_real_error(self):
        calls = []
        runner = lab.Runner("host-under-attack")

        def once(argv, command, timeout):
            calls.append(command)
            return lab.Result(list(argv), 255, "",
                              "kex_exchange_identification: read: Connection reset by peer")

        runner._ssh_once = once
        slept: list[float] = []
        real_sleep, lab.time.sleep = lab.time.sleep, slept.append
        try:
            with self.assertRaisesRegex(lab.LabError, "kex_exchange_identification"):
                runner.ssh("uptime")
        finally:
            lab.time.sleep = real_sleep
        # One attempt plus one per backoff step, and it waited between them rather than
        # hammering an sshd that is already refusing connections.
        self.assertEqual(len(calls), 1 + len(lab.SSH_RETRY_BACKOFF))
        self.assertEqual(slept, list(lab.SSH_RETRY_BACKOFF))

    def test_a_retry_that_connects_returns_the_command_output(self):
        outcomes = [
            lab.Result(["ssh"], 255, "", "Connection reset by 1.2.3.4 port 22"),
            lab.Result(["ssh"], 0, "0.12 0.20 0.30 1/500 1234\n", ""),
        ]
        runner = lab.Runner("flaky")
        runner._ssh_once = lambda argv, command, timeout: outcomes.pop(0)
        real_sleep, lab.time.sleep = lab.time.sleep, lambda _s: None
        try:
            result = runner.ssh("cat /proc/loadavg")
        finally:
            lab.time.sleep = real_sleep
        self.assertTrue(result.ok)
        self.assertIn("0.12", result.out)
        self.assertEqual(outcomes, [])


class ClampedSockbufWarningTests(unittest.TestCase):
    """docs/DECISIONS.md D32's preflight mitigation: the warning that has to fire for S2 too.

    `warn_clamped_sockbuf` used to read `merged_flags(...)["sockbuf"]` and skip the side when
    the flag was absent. S2/S3/S4 name no `-sockbuf`, so on a stock host they were clamped
    twentyfold and `lab.py` — the tool every 11.x campaign, soak and matrix runs through — said
    nothing about it. That silence is what produced a withdrawn benchmark page.
    """

    def warnings(self, config: str, **extra) -> str:
        scenario = lab.parse_scenario({**MINIMAL, "config": config, **extra})
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            # `FakeRunner` answers the stock 212992 for both ceilings.
            lab.warn_clamped_sockbuf(FakeRunner("stock-host"), scenario)
        return errors.getvalue()

    def test_the_default_matches_the_go_flag(self):
        # reference/kcptun/client/main.go:185-188, server/main.go:176-179, both
        # `Value: 4194304 // default socket buffer size in bytes`.
        self.assertEqual(lab.DEFAULT_SOCKBUF, 4194304)

    def test_a_configuration_that_names_no_sockbuf_is_still_warned_about(self):
        text = self.warnings("s2")
        self.assertIn("stock-host net.core.rmem_max is 212992", text)
        self.assertIn("stock-host net.core.wmem_max is 212992", text)
        self.assertIn("default -sockbuf of 4194304", text)
        self.assertIn("kcptun's own", text)
        self.assertIn("20x smaller than asked for", text)
        for side in ("client", "server"):
            self.assertIn(f"so the {side}'s", text)

    def test_an_explicit_sockbuf_is_reported_as_the_flag_not_as_a_default(self):
        text = self.warnings("s1")
        self.assertIn("so the client's -sockbuf 8388608", text)
        self.assertNotIn("kcptun's own", text)

    def test_a_scenario_override_beats_the_default(self):
        text = self.warnings("s2", client_flags={"sockbuf": 33554432})
        self.assertIn("so the client's -sockbuf 33554432", text)
        # The server still names none of its own, so there it is the default that is clamped.
        self.assertIn("so the server's default -sockbuf of 4194304", text)

    def test_bench_py_warns_from_the_same_constant(self):
        # Two tools holding two copies of 4194304 is how one of them goes on warning about the
        # wrong clamp after the other has been corrected.
        sys.path.insert(0, str(lab.REPO / "tools" / "bench"))
        try:
            import bench
        finally:
            sys.path.pop(0)
        self.assertIs(bench.DEFAULT_SOCKBUF, lab.DEFAULT_SOCKBUF)


class MatrixScenarioTests(unittest.TestCase):
    """The two workload files 11.2's campaign crosses its axes over."""

    def scenario(self, name: str) -> lab.Scenario:
        path = lab.REPO / "tools" / "lab" / "scenarios" / f"{name}.json"
        return lab.parse_scenario(json.loads(path.read_text()), source=str(path))

    def test_the_latency_scenario_probes_an_idle_tunnel_and_a_loaded_one(self):
        path = lab.REPO / "tools" / "lab" / "scenarios" / "latency.json"
        scenario = lab.parse_scenario(json.loads(path.read_text()), source=str(path))
        by_tag = {w.tag: w for w in scenario.workloads}
        self.assertEqual(set(by_tag), {"lat64", "comp", "lat64load"})
        # The idle probe finishes before the competing flow starts...
        self.assertEqual(by_tag["lat64"].start_after, 0)
        self.assertLessEqual(by_tag["lat64"].duration, by_tag["comp"].start_after)
        # ...and the loaded probe runs exactly over the competing flow, not around it.
        self.assertEqual(by_tag["lat64load"].start_after, by_tag["comp"].start_after)
        self.assertEqual(by_tag["lat64load"].duration, by_tag["comp"].duration)
        self.assertEqual(by_tag["lat64"].options["size"], 64)
        self.assertEqual(by_tag["lat64load"].options["size"], 64)
        # All four pairs, interleaved, three repetitions (step 11.2).
        self.assertEqual(scenario.pairs,
                         [("go", "go"), ("rust", "rust"), ("go", "rust"), ("rust", "go")])
        self.assertEqual(scenario.repetitions, 3)
        # iperf3 cannot share a tunnel whose target is `pingpong serve`; this file must not try.
        self.assertEqual(scenario.target, "pingpong")

    def test_the_capped_bulk_control_differs_from_the_uncapped_one_only_in_the_cap(self):
        # It is a control, so anything else that differs makes the pair uncomparable — and the
        # whole point of it is that `clean` on a one-vCPU host otherwise measures the core.
        free = self.scenario("bulk-iperf3")
        capped = self.scenario("bulk-capped")
        self.assertEqual(free.config, capped.config)
        self.assertEqual(free.pairs, capped.pairs)
        self.assertEqual(free.repetitions, capped.repetitions)
        self.assertEqual(free.total_duration, capped.total_duration)
        for one, other in zip(free.workloads, capped.workloads):
            self.assertEqual((one.type, one.tag, one.duration, one.start_after),
                             (other.type, other.tag, other.duration, other.start_after))
            self.assertNotIn("bitrate", one.options)
            self.assertEqual(other.options["bitrate"], "250M")
        # Two scenarios that shared a name would share pid files and session directories.
        self.assertNotEqual(free.name, capped.name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
