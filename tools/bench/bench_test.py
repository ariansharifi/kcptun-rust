#!/usr/bin/env python3
"""Tests for tools/bench/bench.py. Run with `python3 tools/bench/bench_test.py`.

The harness decides which runs happen and then turns their files into the page a performance
claim is quoted from, so the two things worth testing are *what it plans* and *what it says
about what it found*. Neither needs a lab host: the planning half is pure, and the reporting
half reads a directory of `state.json`, `proc.csv`, `snmp-cli.csv` and workload logs, which the
tests write by hand.

The reporting assertions are deliberately about honesty rather than formatting: a `-` where
nothing was measured, a `·` where a cross pair is deliberately not measured, a refusal below
five repetitions, a banner when a build could not be named, and a CSV that reproduces every
median in the page. Those are the properties that decide whether a number can be quoted;
column widths are not.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
import tempfile
import unittest
import unittest.mock
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import bench  # noqa: E402  (the import needs the path above)


MINIMAL = {
    "name": "unit",
    "env": "unit-env",
    "configs": ["s1"],
    "metrics": ["bulk-up"],
    "repetitions": 5,
    "duration": 10,
}


def campaign(**overrides: object) -> bench.Campaign:
    raw = dict(MINIMAL)
    raw.update(overrides)
    return bench.parse_campaign(raw, source="unit.json")


def namespace(**overrides: object) -> argparse.Namespace:
    """The argparse namespace `write_outputs` and `lab_command` read."""
    args = argparse.Namespace(
        host="test-host", runs_dir="", docs_dir=None, env_title=None,
        lab_arg=[], wait_load=bench.DEFAULT_WAIT_LOAD, dry_run=False,
        allow_few_repetitions=False, allow_clamped_sockbuf=False,
        stop_on_error=False, keep_going=False,
    )
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


# --------------------------------------------------------------------------------------------
# Campaign parsing and the grid it plans
# --------------------------------------------------------------------------------------------


class CampaignTests(unittest.TestCase):
    def test_the_grid_is_every_configuration_times_every_metric(self) -> None:
        plan = campaign(configs=["s1", "s2"], metrics=["bulk-up", "latency"])
        self.assertEqual(
            plan.cells,
            [("s1", "bulk-up"), ("s1", "latency"),
             ("s2", "bulk-up"), ("s2", "latency")],
        )

    def test_every_cell_is_a_scenario_lab_py_itself_accepts(self) -> None:
        # The point of validating through `lab.parse_scenario` rather than re-checking the
        # ports and workload rules here: one implementation of the rules, not two.
        plan = campaign(configs=sorted(bench.lab.CONFIGS), metrics=sorted(bench.METRICS))
        for config, metric in plan.cells:
            scenario = bench.lab.parse_scenario(plan.scenario(config, metric))
            self.assertEqual(scenario.config, config)
            self.assertTrue(scenario.workloads)

    def test_cross_pairs_run_only_for_throughput_families(self) -> None:
        for name, metric in bench.METRICS.items():
            pairs = {(c, s) for c, s in metric.pairs}
            if pairs == set(bench.ALL_PAIRS):
                self.assertIn("goodput_mbit_s", metric.measures, name)
            else:
                self.assertEqual(pairs, set(bench.SAME_PAIRS), name)

    def test_a_cross_pair_never_shows_a_cpu_or_memory_row(self) -> None:
        for key in bench.CROSS_MEASURES:
            self.assertNotIn("cpu", key)
            self.assertNotIn("rss", key)
            self.assertNotIn("hwm", key)

    def test_durations_are_substituted_into_the_workloads(self) -> None:
        loaded = bench.METRICS["latency-loaded"].render_workloads(30)
        self.assertEqual([w["duration"] for w in loaded], [30, 26])
        self.assertEqual(loaded[1]["start_after"], 2)

    def test_an_unknown_field_names_itself(self) -> None:
        with self.assertRaises(bench.BenchError) as caught:
            campaign(reptitions=5)
        self.assertIn("reptitions", str(caught.exception))

    def test_an_unknown_metric_lists_the_ones_there_are(self) -> None:
        with self.assertRaises(bench.BenchError) as caught:
            campaign(metrics=["bulk-sideways"])
        self.assertIn("bulk-up", str(caught.exception))

    def test_an_unknown_configuration_is_refused(self) -> None:
        with self.assertRaises(bench.BenchError):
            campaign(configs=["s9"])

    def test_a_name_that_could_not_be_a_directory_is_refused(self) -> None:
        with self.assertRaises(bench.BenchError):
            campaign(name="../escape")

    def test_an_environment_slug_is_required(self) -> None:
        raw = dict(MINIMAL)
        del raw["env"]
        with self.assertRaises(bench.BenchError):
            bench.parse_campaign(raw)

    def test_a_wan_campaign_carries_its_second_host_into_every_scenario(self) -> None:
        plan = campaign(mode="wan", server_host="lab-arm64", server_addr="10.0.0.1",
                        netem="clean")
        scenario = bench.lab.parse_scenario(plan.scenario("s1", "bulk-up"))
        self.assertTrue(scenario.is_wan)
        self.assertEqual(scenario.server_host, "lab-arm64")

    def test_a_wan_campaign_that_asks_for_netem_is_refused(self) -> None:
        # `lab.py` refuses it; this asserts that the refusal reaches the campaign parser rather
        # than surfacing hours later, when the page would already claim an impairment profile.
        with self.assertRaises(bench.BenchError):
            campaign(mode="wan", server_host="lab-arm64", server_addr="10.0.0.1",
                     netem="wan50")


# --------------------------------------------------------------------------------------------
# The command line each row is produced by
# --------------------------------------------------------------------------------------------


class CommandTests(unittest.TestCase):
    def test_the_command_names_the_host_the_scenario_and_the_runs_directory(self) -> None:
        plan = campaign()
        argv = bench.lab_command(plan, "lab-x86-1", Path("/tmp/s/unit-s1-bulk-up.json"),
                                 Path("/tmp/s"))
        self.assertIn("--host", argv)
        self.assertEqual(argv[argv.index("--host") + 1], "lab-x86-1")
        self.assertIn("--no-report", argv)

    def test_a_cell_waits_for_the_host_instead_of_forcing_past_it(self) -> None:
        argv = bench.lab_command(campaign(), "h", Path("s.json"), Path("/tmp/s"))
        self.assertIn("--wait-load", argv)
        self.assertNotIn("--force", argv)

    def test_a_wan_campaign_passes_both_ends_on_the_command_line(self) -> None:
        plan = campaign(mode="wan", server_host="lab-arm64", server_addr="10.0.0.1")
        argv = bench.lab_command(plan, "lab-x86-1", Path("s.json"), Path("/tmp/s"))
        self.assertEqual(argv[argv.index("--server-host") + 1], "lab-arm64")
        self.assertEqual(argv[argv.index("--server-addr") + 1], "10.0.0.1")


# --------------------------------------------------------------------------------------------
# Harvesting a collected run
# --------------------------------------------------------------------------------------------


def write_run(session: Path, runid: str, *, client: str, server: str, repetition: int,
              goodput_bits: float, bytes_moved: int, cpu_ticks: tuple[int, int],
              rss_kb: tuple[int, int], snmp: dict[str, int] | None = None,
              stamp: bool = True, limits: dict[str, int] | None = None) -> Path:
    """One collected run on disk, exactly as `lab.py collect` leaves it.

    `limits` is what `lab.Runner.socket_buffer_limits` recorded; `None` is a run that recorded
    nothing, which is what every run taken before 11.2 looks like.
    """
    directory = session / runid
    directory.mkdir(parents=True, exist_ok=True)
    detail = {"kind": "rust", "commit": "0" * 40, "libc": "glibc 2.17",
              "target": "x86_64-unknown-linux-gnu", "host": "test-host",
              "sha256": "a" * 64}
    state = {
        "runid": runid, "scenario": "unit", "config": "s1", "mode": "netns",
        "client_impl": client, "server_impl": server, "repetition": repetition,
        "target": "iperf3", "host": "test-host", "server_host": "test-host",
        "started_unix": 1000 + repetition, "started_iso": "2026-09-24T00:00:00Z",
        "total_duration": 10,
        "workloads": [{"name": f"{runid}-w0", "tag": "up", "type": "iperf3",
                       "duration": 10, "start_after": 0}],
    }
    if stamp:
        state["client_build_detail"] = dict(detail)
        state["server_build_detail"] = dict(detail)
        state["tools_build_detail"] = dict(detail)
    else:
        state["client_build_detail"] = {"kind": "rust", "problem": "no BUILD.txt"}
    if limits is not None:
        state["socket_buffer_limits"] = {"test-host": dict(limits)}
    (directory / "state.json").write_text(json.dumps(state), encoding="utf-8")

    (directory / "iperf3-up.json").write_text(json.dumps({
        "start": {"test_start": {"reverse": 0}},
        "end": {
            "sum_sent": {"seconds": 10.0, "bits_per_second": goodput_bits,
                         "bytes": bytes_moved, "retransmits": 7},
            "sum_received": {"seconds": 10.0, "bits_per_second": goodput_bits,
                             "bytes": bytes_moved},
        },
    }), encoding="utf-8")

    header = ("tag,label,elapsed_s,state,rss_kb,hwm_kb,cpu_ticks,cpu_pct,fds,threads,"
              "log_truncations\n")
    rows = [header]
    for index, label in enumerate(("cli", "srv")):
        rows.append(f"{runid},{label},0,S,{rss_kb[index]},{rss_kb[index]},0,0,10,4,0\n")
        rows.append(f"{runid},{label},10,S,{rss_kb[index]},{rss_kb[index]},"
                    f"{cpu_ticks[index]},50,10,4,0\n")
    (directory / "proc.csv").write_text("".join(rows), encoding="utf-8")

    counters = {"RetransSegs": 0, "FastRetransSegs": 0, "LostSegs": 0, "RepeatSegs": 0}
    counters.update(snmp or {})
    names = ",".join(counters)
    values = ",".join(str(v) for v in counters.values())
    (directory / "snmp-cli.csv").write_text(f"time,{names}\n0,{values}\n", encoding="utf-8")
    return directory


class HarvestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_cpu_per_gb_divides_by_the_bytes_the_workload_moved(self) -> None:
        session = self.root / "20260924T000000Z-unit-s1-bulk-up"
        directory = write_run(session, "unit-rr-r1", client="rust", server="rust",
                              repetition=1, goodput_bits=8e8, bytes_moved=2_000_000_000,
                              cpu_ticks=(400, 200), rss_kb=(1000, 2000))
        values = bench.harvest(json.loads((directory / "state.json").read_text()), directory)
        # 400 ticks at 100 Hz = 4.0 CPU s over 2 GB.
        self.assertAlmostEqual(values["cpu_s_per_gb_cli"], 2.0)
        self.assertAlmostEqual(values["cpu_s_per_gb_srv"], 1.0)
        self.assertAlmostEqual(values["cpu_s_per_gb_total"], 3.0)
        self.assertAlmostEqual(values["cpu_s_cli"], 4.0)
        self.assertAlmostEqual(values["goodput_mbit_s"], 800.0)
        self.assertEqual(values["rss_kb_srv"], 2000.0)

    def test_a_missing_measurement_is_absent_rather_than_zero(self) -> None:
        session = self.root / "20260924T000000Z-unit-s1-bulk-up"
        directory = write_run(session, "unit-rr-r1", client="rust", server="rust",
                              repetition=1, goodput_bits=1e8, bytes_moved=1_000_000,
                              cpu_ticks=(10, 10), rss_kb=(1, 1))
        (directory / "snmp-cli.csv").unlink()
        values = bench.harvest(json.loads((directory / "state.json").read_text()), directory)
        self.assertNotIn("retrans_segs_cli", values)

    def test_both_ends_snmp_counters_are_harvested(self) -> None:
        # A download cell's retransmission lives in the SERVER's log; harvesting only the
        # client's would leave that table empty and read as "no retransmission".
        session = self.root / "20260924T000000Z-unit-s1-bulk-down"
        directory = write_run(session, "unit-rr-r1", client="rust", server="rust",
                              repetition=1, goodput_bits=1e8, bytes_moved=1_000_000,
                              cpu_ticks=(10, 10), rss_kb=(1, 1), snmp={"RetransSegs": 4})
        (directory / "snmp-srv.csv").write_text("time,RetransSegs\n0,900\n", encoding="utf-8")
        values = bench.harvest(json.loads((directory / "state.json").read_text()), directory)
        self.assertEqual(values["retrans_segs_cli"], 4.0)
        self.assertEqual(values["retrans_segs_srv"], 900.0)

    def test_retrans_segs_decomposes_into_the_counters_printed_beneath_it(self) -> None:
        # kcp-go adds `LostSegs + FastRetransSegs + EarlyRetransSegs` into `RetransSegs` in one
        # `flush` (the "counter updates" block of
        # reference/kcptun/vendor/github.com/xtaci/kcp-go/v5/kcp.go), so the total decomposes
        # exactly. An earlier version of `SNMP_KEYS` harvested two of the three, and every
        # `RetransSegs` row on the baseline pages carried a visible remainder that read as
        # unattributable retransmission: the one thing those rows exist to attribute.
        session = self.root / "20260924T000000Z-unit-s1-bulk-up"
        directory = write_run(
            session, "unit-gg-r1", client="go", server="go", repetition=1,
            goodput_bits=1e8, bytes_moved=1_000_000, cpu_ticks=(10, 10), rss_kb=(1, 1),
            snmp={"RetransSegs": 206_518, "FastRetransSegs": 137_520,
                  "EarlyRetransSegs": 4_419, "LostSegs": 64_579})
        values = bench.harvest(json.loads((directory / "state.json").read_text()), directory)
        for key in ("retrans_segs_cli", "fast_retrans_segs_cli", "early_retrans_segs_cli",
                    "lost_segs_cli"):
            self.assertIn(key, values, key)
            self.assertIn(key, bench.MEASURES, key)
            self.assertIn(key, bench.SNMP_MEASURES, key)
        self.assertEqual(
            values["fast_retrans_segs_cli"] + values["early_retrans_segs_cli"]
            + values["lost_segs_cli"],
            values["retrans_segs_cli"])

    def test_pingpong_byte_counters_are_preferred_to_the_derived_rate(self) -> None:
        session = self.root / "s"
        directory = session / "run"
        directory.mkdir(parents=True)
        state = {"workloads": [{"name": "run-w0", "tag": "load", "type": "bulk",
                                "duration": 10, "start_after": 0}]}
        (directory / "run-w0.log").write_text(
            'RESULT {"kind":"bulk","tag":"load","mbit_s":80.0,"elapsed_s":10.0,'
            '"bytes_up":60000000,"bytes_down":40000000}\n', encoding="utf-8")
        self.assertEqual(bench.transferred_bytes(state, directory), 100_000_000.0)


# --------------------------------------------------------------------------------------------
# The page and the CSV
# --------------------------------------------------------------------------------------------


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "20260924T000000Z-bench-unit"
        self.docs = Path(self.tmp.name) / "docs"
        self.addCleanup(self.tmp.cleanup)
        self.plan = campaign()
        self.session = self.root / "20260924T000001Z-unit-s1-bulk-up"

    def populate(self, *, stamp: bool = True, repetitions: int = 5,
                 limits: dict[str, int] | None = None) -> None:
        # GG is the slower arm on purpose, so the RR/GG ratio has a direction to get right.
        for repetition in range(1, repetitions + 1):
            for pair, (client, server), bits, ticks in (
                ("gg", ("go", "go"), 1.0e8, (200, 200)),
                ("rr", ("rust", "rust"), 2.0e8, (100, 100)),
                ("gr", ("go", "rust"), 1.5e8, (150, 150)),
                ("rg", ("rust", "go"), 1.4e8, (150, 150)),
            ):
                write_run(self.session, f"unit-{pair}-r{repetition}", client=client,
                          server=server, repetition=repetition, goodput_bits=bits,
                          bytes_moved=1_000_000_000, cpu_ticks=ticks, rss_kb=(1000, 1000),
                          snmp={"RetransSegs": 5}, stamp=stamp, limits=limits)

    def render(self, **overrides: object) -> str:
        args = namespace(docs_dir=str(self.docs), **overrides)
        meta = {"campaign": "unit", "env": "unit-env", "host": "test-host",
                "date": "2026-09-24", "started_iso": "s", "finished_iso": "f"}
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            bench.write_outputs(self.plan, self.root, meta, args)
        return (self.docs / "2026-09-24-unit-env.md").read_text(encoding="utf-8")

    def test_the_page_names_the_pairs_and_gets_the_ratio_direction_right(self) -> None:
        self.populate()
        page = self.render()
        self.assertIn("| GG | RR | GR | RG | RR/GG |", page)
        # Goodput doubled: higher is better, so the ratio is a tick.
        self.assertIn("2.00x ✓", page)
        # CPU halved: lower is better, so that ratio is a tick too.
        self.assertIn("0.50x ✓", page)

    def test_a_ratio_of_two_cells_that_both_print_as_zero_is_not_a_ratio(self) -> None:
        measure = bench.MEASURES["retrans_pct_cli"]
        self.assertEqual(bench.ratio_cell(0.004, 0.006, measure), "n/a")
        self.assertEqual(bench.ratio_cell(4.0, 6.0, measure), "0.67x ✓")

    def test_a_ratio_of_two_single_digit_segment_counts_is_not_a_verdict(self) -> None:
        # `1 -> 3` segments over a 20-second run is noise; the first baseline page printed four
        # rows of it as "3.00x ✗" and they read as findings.
        self.assertEqual(bench.ratio_cell(0.0, 1.0, bench.MEASURES["retrans_segs_srv"]), "n/a")
        self.assertEqual(bench.ratio_cell(3.0, 1.0, bench.MEASURES["retrans_segs_cli"]), "n/a")
        self.assertEqual(bench.ratio_cell(0.0, 12_640.0, bench.MEASURES["repeat_segs_srv"]),
                         "0.00x ✓")
        self.assertEqual(bench.ratio_cell(17_314.0, 5_039.0, bench.MEASURES["repeat_segs_srv"]),
                         "3.44x ✗")
        # A count that is *meant* to be small keeps its ratio: three completed streams against
        # six is the measurement, not noise around it.
        self.assertEqual(bench.ratio_cell(3.0, 6.0, bench.MEASURES["streams"]), "0.50x ✗")

    def test_a_neutral_counter_gets_no_tick_or_cross(self) -> None:
        ratio = bench.ratio_cell(1500.0, 1000.0, bench.MEASURES["out_segs_cli"])
        self.assertEqual(ratio, "1.50x")

    def test_a_cross_pair_row_is_a_dot_for_everything_but_throughput(self) -> None:
        self.populate()
        page = self.render()
        cpu_row = next(line for line in page.splitlines()
                       if line.startswith("| CPU per GB, client"))
        self.assertEqual(cpu_row.count("·"), 2)
        goodput_row = next(line for line in page.splitlines() if line.startswith("| goodput"))
        self.assertNotIn("·", goodput_row)

    def test_every_median_in_the_page_is_reproducible_from_the_csv(self) -> None:
        self.populate()
        self.render()
        with (self.docs / "2026-09-24-unit-env.csv").open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(sorted(bench.CSV_COLUMNS), sorted(rows[0]))
        goodput = [float(row["value"]) for row in rows
                   if row["measurement"] == "goodput_mbit_s" and row["pair"] == "RR"]
        self.assertEqual(len(goodput), 5)
        self.assertAlmostEqual(bench.lab.median(goodput), 200.0)

    def test_a_counter_wider_than_six_figures_is_not_rounded_in_the_csv(self) -> None:
        # `f"{v:.6g}"` wrote an `OutSegs` of 1 470 402 as `1.47040e+06` while the page printed
        # the exact integer: the page's own evidence could no longer reproduce the page. Every
        # segment counter crosses 1e6 on a 20-second bulk cell.
        for repetition in range(1, 6):
            for pair, (client, server) in (("gg", ("go", "go")), ("rr", ("rust", "rust")),
                                           ("gr", ("go", "rust")), ("rg", ("rust", "go"))):
                write_run(self.session, f"unit-{pair}-r{repetition}", client=client,
                          server=server, repetition=repetition, goodput_bits=1.0e8,
                          bytes_moved=1_000_000_000, cpu_ticks=(200, 200), rss_kb=(1000, 1000),
                          snmp={"OutSegs": 12_345_678, "RetransSegs": 1_234_567})
        page = self.render()
        with (self.docs / "2026-09-24-unit-env.csv").open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        for key, expected in (("out_segs_cli", 12_345_678), ("retrans_segs_cli", 1_234_567)):
            values = [row["value"] for row in rows if row["measurement"] == key]
            self.assertEqual(len(values), 20)
            self.assertEqual(set(values), {str(expected)})
            # The page cell is the median of exactly those strings, read back as numbers.
            median = bench.lab.median([float(v) for v in values])
            self.assertIn(f"| {bench.MEASURES[key].format(median)} |", page)
        self.assertIn("| OutSegs, client | segments | 12,345,678 |", page)

    def test_a_fractional_value_keeps_more_than_six_significant_figures(self) -> None:
        self.assertEqual(bench.csv_value(1_470_402.0), "1470402")
        self.assertEqual(bench.csv_value(0.0), "0")
        self.assertEqual(float(bench.csv_value(123456.789012)), 123456.789012)
        # 12 significant figures, not 6: a retransmitted share of 10.0000008 % stays distinct
        # from 10 %.
        self.assertNotEqual(bench.csv_value(10.0000008), bench.csv_value(10.0))

    def test_a_page_built_from_unprovenanced_runs_says_so_first(self) -> None:
        self.populate(stamp=False)
        page = self.render()
        self.assertIn("UNPROVENANCED", page.split("## Method")[0])

    def test_a_page_built_from_provenanced_runs_names_the_artefacts(self) -> None:
        self.populate()
        page = self.render()
        self.assertIn("Artefacts:", page)
        self.assertIn("0" * 12, page)

    def test_a_binary_built_from_a_modified_tree_is_flagged(self) -> None:
        self.populate()
        for path in sorted(self.session.glob("*/state.json")):
            state = json.loads(path.read_text())
            state["client_build_detail"]["revision"] = "0000000-dirty"
            path.write_text(json.dumps(state), encoding="utf-8")
        page = self.render()
        self.assertIn("Built from a modified tree", page)
        self.assertIn("0000000-dirty", page)

    def test_the_page_carries_the_command_that_produced_each_table(self) -> None:
        self.populate()
        page = self.render()
        self.assertIn("tools/lab/lab.py", page)
        self.assertIn("unit-s1-bulk-up.json", page)

    def test_a_regenerated_page_prints_the_command_the_run_recorded(self) -> None:
        # The "Produced by:" block has to be what ran, not what a fresh argparse namespace
        # rebuilds: `report --campaign` is invoked without the original `--lab-arg` and
        # `--wait-load`, so a rebuilt line silently drops a `--force` the run really carried.
        # step 12 rule 2 asks for the exact command, and this is the exact command.
        self.populate()
        recorded = ("tools/lab/lab.py --host test-host run unit-s1-bulk-up.json "
                    "--no-report --wait-load 600 --force")
        args = namespace(docs_dir=str(self.docs))
        meta = {"campaign": "unit", "env": "unit-env", "host": "test-host",
                "date": "2026-09-24", "started_iso": "s", "finished_iso": "f",
                "cells": [{"config": "s1", "metric": "bulk-up", "command": recorded}]}
        with redirect_stdout(io.StringIO()):
            bench.write_outputs(self.plan, self.root, meta, args)
        page = (self.docs / "2026-09-24-unit-env.md").read_text(encoding="utf-8")
        self.assertIn(recorded, page)

    def test_the_spread_of_the_headline_measurement_is_shown(self) -> None:
        self.populate()
        page = self.render()
        self.assertIn("| pair | runs | min | median | max | every run |", page)

    def test_a_cell_with_no_runs_says_so_instead_of_printing_an_empty_table(self) -> None:
        page = self.render()
        self.assertIn("Not run.", page)

    def test_a_failed_cell_is_named_on_the_page(self) -> None:
        self.populate()
        args = namespace(docs_dir=str(self.docs))
        meta = {"campaign": "unit", "env": "unit-env", "host": "test-host",
                "date": "2026-09-24", "failures": ["s1 x bulk-up (lab.py exit 1)"]}
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            bench.write_outputs(self.plan, self.root, meta, args)
        page = (self.docs / "2026-09-24-unit-env.md").read_text(encoding="utf-8")
        self.assertIn("Cells that did not complete", page)
        self.assertIn("lab.py exit 1", page)

    def test_a_cell_short_of_five_runs_carries_its_count(self) -> None:
        self.populate(repetitions=3)
        page = self.render()
        goodput_row = next(line for line in page.splitlines() if line.startswith("| goodput"))
        self.assertIn("(3)", goodput_row)

    def test_observations_written_after_the_run_reach_the_page(self) -> None:
        self.populate()
        self.plan = campaign(observations=["RR beat GG because the box was warm."])
        page = self.render()
        self.assertIn("## Observations", page)
        self.assertIn("because the box was warm", page)

    def test_the_flags_block_is_rendered_from_lab_configs(self) -> None:
        self.populate()
        page = self.render()
        # Straight out of `lab.CONFIGS["s1"]`, so it cannot drift from what the runs used.
        self.assertIn("-crypt xor", page)
        self.assertIn("-sndwnd 8192", page)


# --------------------------------------------------------------------------------------------
# The command line
# --------------------------------------------------------------------------------------------


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.path = self.dir / "unit.json"

    def write(self, **overrides: object) -> str:
        raw = dict(MINIMAL)
        raw.update(overrides)
        self.path.write_text(json.dumps(raw), encoding="utf-8")
        return str(self.path)

    def run_main(self, argv: list[str]) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = bench.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_fewer_than_five_repetitions_is_refused_by_default(self) -> None:
        path = self.write(repetitions=3)
        code, _, err = self.run_main(["--runs-dir", str(self.dir), "run", path])
        self.assertEqual(code, 2)
        self.assertIn("step 12 rule 1", err)

    def test_fewer_repetitions_may_be_forced_for_a_shakedown(self) -> None:
        path = self.write(repetitions=1)
        code, out, _ = self.run_main([
            "--runs-dir", str(self.dir), "run", path, "--allow-few-repetitions", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertIn("dry run", out)

    def ceiling(self, limits: dict[str, int]):
        """Answer the preflight's one ssh without one, so the refusal is testable offline."""
        return unittest.mock.patch.object(
            bench.lab.Runner, "socket_buffer_limits", lambda _self: dict(limits))

    def test_a_campaign_on_a_stock_ceiling_host_is_refused_before_it_runs(self) -> None:
        # D32 is a rule about results; enforced only when the results are read, it costs a
        # campaign. 12.1's S1 grid was 1h24m of a 1-vCPU box and had to be discarded.
        path = self.write()
        with self.ceiling(STOCK):
            code, _, err = self.run_main(["--runs-dir", str(self.dir), "run", path])
        self.assertEqual(code, 2)
        self.assertIn("docs/DECISIONS.md D32", err)
        self.assertIn("--allow-clamped-sockbuf", err)
        self.assertEqual(list(self.dir.glob("*-bench-*")), [])

    def test_the_clamp_may_be_measured_on_purpose(self) -> None:
        err = io.StringIO()
        with self.ceiling(STOCK), redirect_stderr(err):
            bench.preflight_sockbuf(campaign(), namespace(allow_clamped_sockbuf=True))
        self.assertIn("smaller than asked for", err.getvalue())

    def test_a_raised_ceiling_warns_about_the_server_clamp_and_does_not_refuse(self) -> None:
        err = io.StringIO()
        with self.ceiling(RAISED), redirect_stderr(err):
            bench.preflight_sockbuf(campaign(), namespace())
        self.assertIn("`s1` server asks for 67,108,868 B", err.getvalue())
        self.assertNotIn("client asks", err.getvalue())

    def test_a_host_that_cannot_answer_is_not_treated_as_a_raised_ceiling(self) -> None:
        err = io.StringIO()
        with unittest.mock.patch.object(bench.lab.Runner, "socket_buffer_limits",
                                        lambda _self: {}), redirect_stderr(err):
            bench.preflight_sockbuf(campaign(), namespace())
        self.assertIn("could not read net.core.rmem_max", err.getvalue())

    def test_a_dry_run_starts_nothing_and_prints_every_cell(self) -> None:
        path = self.write(configs=["s1", "s2"], metrics=["bulk-up", "latency"])
        code, out, _ = self.run_main([
            "--runs-dir", str(self.dir), "run", path, "--dry-run"])
        self.assertEqual(code, 0)
        self.assertEqual(out.count("tools/lab/lab.py"), 4)

    def test_scenarios_expands_the_grid_without_touching_a_host(self) -> None:
        path = self.write(metrics=["bulk-up", "latency"])
        out_dir = self.dir / "scenarios"
        code, _, _ = self.run_main(["scenarios", path, "--out", str(out_dir)])
        self.assertEqual(code, 0)
        self.assertEqual(sorted(p.name for p in out_dir.glob("*.json")),
                         ["unit-s1-bulk-up.json", "unit-s1-latency.json"])

    def test_metrics_lists_the_families(self) -> None:
        code, out, _ = self.run_main(["metrics"])
        self.assertEqual(code, 0)
        for name in bench.METRICS:
            self.assertIn(name, out)

    def test_a_bad_campaign_file_is_reported_not_raised(self) -> None:
        self.path.write_text("{ not json", encoding="utf-8")
        code, _, err = self.run_main(["run", str(self.path), "--dry-run"])
        self.assertEqual(code, 2)
        self.assertIn("bench:", err)

    def test_report_refuses_a_campaign_file_for_a_different_campaign(self) -> None:
        root = self.dir / "20260101T000000Z-bench-unit"
        root.mkdir()
        (root / "campaign.json").write_text(
            json.dumps({"campaign": dict(MINIMAL, source=""), "meta": {"date": "2026-01-01"}}),
            encoding="utf-8")
        other = self.write(name="elsewhere")
        code, _, err = self.run_main([
            "--docs-dir", str(self.dir / "docs"), "report", str(root), "--campaign", other])
        self.assertEqual(code, 2)
        self.assertIn("elsewhere", err)

    def test_report_refuses_a_campaign_file_whose_grid_was_edited(self) -> None:
        # `report --campaign` is the documented way to land an observation written after the
        # runs. It re-reads the committed file, so an edit to a *grid* field would be printed
        # into the Method table as a statement about runs that never happened: `repetitions`
        # raised from 3 to 5 would produce a page claiming five runs per pair, with the
        # under-replication banner gone, from three.
        root = self.dir / "20260101T000000Z-bench-unit"
        root.mkdir()
        (root / "campaign.json").write_text(
            json.dumps({"campaign": dict(MINIMAL, repetitions=3, source=""),
                        "meta": {"date": "2026-01-01"}}),
            encoding="utf-8")
        edited = self.write(repetitions=5)
        code, _, err = self.run_main([
            "--docs-dir", str(self.dir / "docs"), "report", str(root), "--campaign", edited])
        self.assertEqual(code, 2)
        self.assertIn("repetitions", err)

    def test_report_lets_an_observation_written_afterwards_through(self) -> None:
        # The other half of the rule above: prose *may* be re-read, and is what --campaign is
        # for. Only the grid is frozen.
        root = self.dir / "20260101T000000Z-bench-unit"
        root.mkdir()
        (root / "campaign.json").write_text(
            json.dumps({"campaign": dict(MINIMAL, source=""), "meta": {"date": "2026-01-01"}}),
            encoding="utf-8")
        edited = self.write(observations=["Written after the runs finished."])
        code, _, err = self.run_main([
            "--docs-dir", str(self.dir / "docs"), "report", str(root), "--campaign", edited])
        self.assertEqual(code, 0, err)
        page = (self.dir / "docs" / "2026-01-01-unit-env.md").read_text(encoding="utf-8")
        self.assertIn("Written after the runs finished.", page)

    def test_report_refuses_a_directory_that_is_not_a_campaign(self) -> None:
        code, _, err = self.run_main(["report", str(self.dir)])
        self.assertEqual(code, 2)
        self.assertIn("campaign.json", err)


class HostDetailTests(unittest.TestCase):
    """The method table's machine line. Which libc a run used is load-bearing (D07)."""

    def test_a_field_the_host_cannot_answer_does_not_shift_the_others(self) -> None:
        # aarch64: /proc/cpuinfo has no `model name`, so the model line is empty. Parsed by
        # position, the glibc version landed in the CPU-model slot and the libc slot was empty.
        line = bench.format_host_detail(
            "uname=Linux 6.17.0-1020-oracle aarch64\n"
            "cpus=2\n"
            "memkb=12165608\n"
            "model=\n"
            "libc=ldd (Ubuntu GLIBC 2.39-0ubuntu8.9) 2.39\n")
        self.assertEqual(
            line,
            "Linux 6.17.0-1020-oracle aarch64, 2 vCPU, "
            "ldd (Ubuntu GLIBC 2.39-0ubuntu8.9) 2.39, 11.6 GiB")

    def test_a_missing_cpu_count_does_not_become_the_memory_size(self) -> None:
        line = bench.format_host_detail("uname=Linux 5.15.0 x86_64\ncpus=\nmemkb=2039820\n"
                                        "model=Intel(R) Xeon(R) CPU\nlibc=\n")
        self.assertEqual(line, "Linux 5.15.0 x86_64, Intel(R) Xeon(R) CPU, 1.9 GiB")
        self.assertNotIn("vCPU", line)

    def test_every_field_the_command_promises_is_labelled(self) -> None:
        for key in ("uname", "cpus", "memkb", "model", "libc"):
            self.assertIn(f'echo "{key}=', bench.HOST_DETAIL_COMMAND)


#: What a tuned lab host carries (`/etc/sysctl.d/99-kcptun-lab.conf` on lab-arm64, lab-x86-1 and
#: lab-x86-2), and what a stock Ubuntu box carries. S1's server asks for 67,108,868 B, so even
#: the raised ceiling clamps it, which is the case the page must *not* call invalid.
RAISED = {"rmem_max": 8388608, "wmem_max": 67108864}
STOCK = {"rmem_max": 212992, "wmem_max": 212992}


class SocketBufferTests(unittest.TestCase):
    """docs/DECISIONS.md D32 on the page: what the kernel granted, and when to refuse to read on.

    The 12.1 baseline was taken on a host at the stock ceiling and neither of its pages recorded
    the ceiling at all, so rows D32 says to *discard* were quotable. Every assertion here is
    about that: the row exists unconditionally, an unrecorded ceiling is said out loud rather
    than passed over, and a stock ceiling leads the page with a refusal to interpret.
    """

    def test_a_configuration_with_no_sockbuf_flag_still_asks_for_kcptuns_default(self) -> None:
        # The S2 trap. S2 passes no `-sockbuf`, which reads as "asks for nothing" and is why S2
        # looked exempt from D32, but kcptun's flag defaults to 4 MiB and the binary always
        # calls SetReadBuffer/SetWriteBuffer with it, so on a stock host S2 is clamped 20x too.
        self.assertEqual(bench.DEFAULT_SOCKBUF, 4194304)
        self.assertEqual(bench.config_sockbuf("s2", "client"), (bench.DEFAULT_SOCKBUF, True))
        self.assertEqual(bench.config_sockbuf("s1", "client"), (8388608, False))
        clamps = bench.sockbuf_clamps(["s2"], {"h": {(STOCK["rmem_max"], STOCK["wmem_max"])}})
        self.assertTrue(clamps)
        self.assertTrue(all(clamp.stock for clamp in clamps))

    def test_a_raised_ceiling_honours_s1s_client_and_still_clamps_its_server(self) -> None:
        clamps = bench.sockbuf_clamps(["s1"], {"h": {(RAISED["rmem_max"], RAISED["wmem_max"])}})
        self.assertEqual(sorted({(c.side, c.sysctl) for c in clamps}),
                         [("server", "rmem_max"), ("server", "wmem_max")])
        self.assertFalse(any(clamp.stock for clamp in clamps))

    def test_only_the_side_a_host_actually_runs_is_checked_against_its_ceiling(self) -> None:
        # On a WAN campaign the two ends are two machines with their own ceilings. Checking the
        # client's `-sockbuf` against the *server* host's `rmem_max` would print a clamp naming
        # a host that never ran that flag, and could refuse a campaign over it.
        by_host = {"cli-host": {(RAISED["rmem_max"], RAISED["wmem_max"])},
                   "srv-host": {(STOCK["rmem_max"], STOCK["wmem_max"])}}
        sides = {"cli-host": {"client"}, "srv-host": {"server"}}
        clamps = bench.sockbuf_clamps(["s1"], by_host, sides)
        self.assertEqual(sorted({(c.host, c.side) for c in clamps}), [("srv-host", "server")])
        # The client's 8,388,608 B is honoured by its own 8 MiB ceiling and is never weighed
        # against the stock host it does not run on.
        self.assertFalse(any(c.side == "client" for c in clamps))
        # Without the mapping every host is checked against both sides, which is what a netns
        # campaign wants and what a run that did not record its hosts has to fall back to.
        both = bench.sockbuf_clamps(["s1"], by_host)
        self.assertEqual(sorted({(c.host, c.side) for c in both}),
                         [("cli-host", "server"), ("srv-host", "client"),
                          ("srv-host", "server")])

    def test_the_sides_are_read_back_out_of_the_runs(self) -> None:
        netns = {"mode": "netns", "host": "one-host", "server_host": "one-host"}
        self.assertEqual(bench.recorded_sides([netns]), {"one-host": {"client", "server"}})
        wan = {"mode": "wan", "host": "cli-host", "server_host": "srv-host"}
        self.assertEqual(bench.recorded_sides([wan]),
                         {"cli-host": {"client"}, "srv-host": {"server"}})
        # A run that recorded no hosts contributes nothing, so `sockbuf_clamps` falls back to
        # checking both sides rather than silently checking neither.
        self.assertEqual(bench.recorded_sides([{"runid": "r1"}]), {})

    def test_the_preflight_maps_each_campaign_host_to_the_end_it_will_run(self) -> None:
        self.assertEqual(bench.campaign_sides(campaign(), "test-host"),
                         {"test-host": {"client", "server"}})
        wan = campaign()
        wan.mode = bench.lab.MODE_WAN
        wan.server_host = "srv-host"
        self.assertEqual(bench.campaign_sides(wan, "cli-host"),
                         {"cli-host": {"client"}, "srv-host": {"server"}})

    def test_the_method_row_says_not_recorded_rather_than_nothing(self) -> None:
        row = bench.socket_buffer_row(["s1"], [{"runid": "r1"}])
        self.assertIn("socket-buffer ceilings", row)
        self.assertIn("**not recorded**", row)
        self.assertIn("D32", row)

    def test_the_method_row_prints_what_the_kernel_actually_grants(self) -> None:
        state = {"socket_buffer_limits": {"test-host": dict(RAISED)}}
        row = bench.socket_buffer_row(["s1"], [state])
        self.assertIn("`rmem_max` 8,388,608", row)
        self.assertIn("`s1` client 8,388,608 → honoured", row)
        self.assertIn("`s1` server 67,108,868 → **8,388,608**", row)
        # The footnote is keyed off the flag, not off an asterisk in the rendered text: the bold
        # markers round a clamped figure are asterisks too, and scanning for one printed the
        # kcptun-default footnote on a grid whose every side names `-sockbuf` explicitly.
        self.assertNotIn("An asterisk is kcptun's own default", row)
        self.assertIn("An asterisk is kcptun's own default",
                      bench.socket_buffer_row(["s1", "s2"], [state]))

    def test_a_stock_ceiling_leads_the_page_with_a_refusal_to_interpret(self) -> None:
        state = {"socket_buffer_limits": {"test-host": dict(STOCK)}}
        banner = bench.socket_buffer_banner(["s1"], [state] * 5)
        self.assertTrue(banner)
        self.assertIn("INVALID UNDER docs/DECISIONS.md D32", banner[0])
        self.assertIn("discard it", banner[0])

    def test_a_clamp_at_a_raised_ceiling_is_a_note_not_an_invalidation(self) -> None:
        state = {"socket_buffer_limits": {"test-host": dict(RAISED)}}
        banner = bench.socket_buffer_banner(["s1"], [state] * 5)
        self.assertTrue(banner)
        self.assertNotIn("INVALID", banner[0])
        self.assertIn("raised ceiling", banner[0])

    def test_a_ceiling_that_no_run_recorded_is_said_out_loud(self) -> None:
        banner = bench.socket_buffer_banner(["s1"], [{"runid": "r1"}] * 5)
        self.assertIn("CEILING NOT RECORDED", banner[0])

    def test_two_ceilings_in_one_campaign_are_not_quietly_averaged(self) -> None:
        states = [{"socket_buffer_limits": {"test-host": dict(STOCK)}},
                  {"socket_buffer_limits": {"test-host": dict(RAISED)}}]
        banner = bench.socket_buffer_banner(["s1"], states)
        self.assertIn("NOT ALL TAKEN UNDER THE SAME SOCKET-BUFFER CEILING", banner[0])
        self.assertIn("A median across two ceilings", banner[0])

    def test_the_page_carries_the_ceiling_row_and_the_banner(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name) / "20260924T000000Z-bench-unit"
        session = root / "20260924T000001Z-unit-s1-bulk-up"
        for repetition in range(1, 6):
            for pair, (client, server) in (("gg", ("go", "go")), ("rr", ("rust", "rust"))):
                write_run(session, f"unit-{pair}-r{repetition}", client=client, server=server,
                          repetition=repetition, goodput_bits=1e8, bytes_moved=10**9,
                          cpu_ticks=(100, 100), rss_kb=(1000, 1000), limits=STOCK)
        docs = Path(tmp.name) / "docs"
        args = namespace(docs_dir=str(docs))
        meta = {"campaign": "unit", "env": "unit-env", "host": "test-host",
                "date": "2026-09-24", "started_iso": "s", "finished_iso": "f"}
        with redirect_stdout(io.StringIO()):
            bench.write_outputs(campaign(), root, meta, args)
        page = (docs / "2026-09-24-unit-env.md").read_text(encoding="utf-8")
        self.assertIn("| socket-buffer ceilings |", page)
        self.assertIn("INVALID UNDER docs/DECISIONS.md D32", page)
        # The banner is above the tables, not a footnote under them.
        self.assertLess(page.index("INVALID UNDER"), page.index("## Method"))


class ShippedCampaignTests(unittest.TestCase):
    """Every campaign file in the repository has to parse, and to meet step 12 rule 1."""

    def test_the_shipped_campaigns_parse_and_are_replicated_enough(self) -> None:
        directory = bench.REPO / "tools" / "bench" / "campaigns"
        files = sorted(directory.glob("*.json"))
        self.assertTrue(files, f"no campaigns under {directory}")
        for path in files:
            plan = bench.load_campaign(path)
            self.assertGreaterEqual(plan.repetitions, bench.MIN_REPETITIONS, path.name)
            self.assertTrue(plan.cells, path.name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
