#!/usr/bin/env python3
"""Benchmark harness for Step 12.1 (step 12): the scenario x metric grid.

Runs **on the laptop**, on top of :mod:`tools/lab/lab.py`, and drives one or two Linux lab hosts
over ssh. Python standard library only.

    tools/bench/bench.py metrics                              # what can be measured
    tools/bench/bench.py scenarios tools/bench/campaigns/baseline.json
    tools/bench/bench.py --host lab-x86-1 run tools/bench/campaigns/baseline.json
    tools/bench/bench.py report lab-runs/20260924T093000Z-bench-baseline

A **campaign** is a grid: one *cell* per (scenario config, metric family). ``run`` turns each
cell into a `lab.py` scenario file, hands it to `lab.py run`, and then reduces every collected
run into one page:

* ``docs/benchmarks/<date>-<env>.md``: one table per configuration, one row per measurement,
  one column per implementation pair, medians across the repetitions, plus the ``RR/GG`` ratio
  that the Definition of Done in step 12 is written in terms of;
* ``docs/benchmarks/<date>-<env>.csv``: the **raw** long-format rows behind those medians (one
  row per config, metric, pair, repetition and measurement). Nothing in the page is a number
  the CSV cannot reproduce.

Why it is shaped like this
--------------------------

step 12 "Rules for every optimisation" is the whole design:

1. **Median of >= 5 runs, A/B interleaved.** One cell is one `lab.py` invocation with every pair
   in it, and `lab.plan_runs` interleaves the pairs inside each repetition (GG, RR, GR, RG, then
   again). Background drift on a 1-vCPU box therefore hits both implementations equally.
   `run` *refuses* a campaign with fewer than `MIN_REPETITIONS` repetitions unless
   ``--allow-few-repetitions`` is given, and a page produced that way says so in its first
   paragraph: a single run presented as a measurement is the failure this harness exists to
   prevent.
2. **The exact command per row.** Every table is followed by the literal command that produced
   it, and the generated scenario files are kept beside the raw runs.
3. GG and RR get the whole grid; **GR and RG are throughput only** (step 12.1), because a
   cross pair's CPU and RSS columns describe two different implementations in the same row and
   are read as a comparison they are not.

What a metric family is
-----------------------

`METRICS` below. Each one names the workloads a cell runs, which implementation pairs it is
worth running, and which measurements are harvested from it. CPU-seconds per GB and RSS are not
separate cells: they come out of `proc.csv` of the *same* runs that measure goodput, which is
the only way the CPU number describes the traffic the goodput number describes.

Safety
------

Nothing here talks to a lab host directly. Every remote action goes through `lab.py`, which goes
through the guarded server-side helpers (tools/lab/README.md): only ``kr-*``/``kg-*``/``iperf3`` are
started, no port below 4000 is accepted, processes are stopped only by PID file after
``/proc/<pid>/exe`` is verified, and netem only ever touches our own veths. `run` also inherits
`lab.py`'s build-stamp provenance check (12.0), so a cell whose binaries cannot be named refuses
to start.
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "lab"))

import lab  # noqa: E402  (the path has to be set up first)

#: Where the generated page and its raw CSV land.
DOCS = REPO / "docs" / "benchmarks"

#: step 12 rule 1: "Report the median of >= 5 runs, interleaving A/B runs to cancel noise."
MIN_REPETITIONS = 5

#: How long a cell waits for the host's load average to fall below `lab.py`'s threshold before
#: it gives up. Generous on purpose: on a 1-vCPU box the 1-minute load average after a saturating
#: cell takes minutes to decay, and the alternative to waiting is `--force`, which measures the
#: previous cell.
DEFAULT_WAIT_LOAD = 600

#: Implementation pairs, in the order a table shows them.
PAIR_ORDER = ("GG", "RR", "GR", "RG")

#: The four pairs, as `lab.py` spells them.
ALL_PAIRS = (("go", "go"), ("rust", "rust"), ("go", "rust"), ("rust", "go"))
#: GG and RR only, everything that is not throughput (step 12.1).
SAME_PAIRS = (("go", "go"), ("rust", "rust"))

#: kcptun's own `-sockbuf` default, in bytes, `lab.py` owns it, this is the same object.
#:
#: From `reference/kcptun/client/main.go:185-188` and `reference/kcptun/server/main.go:176-179`,
#: both ``Value: 4194304 // default socket buffer size in bytes``. It is applied to the UDP
#: socket with `SetReadBuffer(config.SockBuf)` *and* `SetWriteBuffer(config.SockBuf)`
#: (`client/main.go:467-471`, `server/main.go:412-416`), so a configuration that passes no
#: `-sockbuf` at all is **not** asking for a small buffer: it is asking for 4 MiB, 20x the stock
#: `net.core.rmem_max` of `STOCK_SOCKET_CEILING`. S1 is the loud case because it asks for 8 MiB
#: explicitly, but S2/S3/S4 are clamped on a stock host too, which is why this is a constant
#: read out of the Go source rather than an absent flag treated as "no request".
#:
#: Bound to `lab.DEFAULT_SOCKBUF` rather than written out a second time: `lab.py` is what every
#: 11.x campaign, soak and matrix actually runs through, and its `warn_clamped_sockbuf` warns
#: from this same number, so the two tools cannot drift into warning about different clamps.
DEFAULT_SOCKBUF = lab.DEFAULT_SOCKBUF

#: The stock Linux value of `net.core.rmem_max`, in bytes.
#:
#: docs/DECISIONS.md D32 is written against this number: `setsockopt(SO_RCVBUF)` is silently
#: clamped to it, and on a host carrying it one 65 s S1 run lost 95,133 datagrams to
#: `UdpRcvbufErrors` for Go and 223,293 for Rust, while the same run at lab-arm64's 8 MiB ceiling
#: lost **zero** and three failing cells inverted. D32's rule, "any future S1 measurement on a
#: host with a stock ceiling is invalid and must be discarded, not interpreted", is enforced by
#: `socket_buffer_banner` on the page and by `cmd_run` before a campaign starts.
STOCK_SOCKET_CEILING = 212992

#: The two ceilings, and which half of `-sockbuf` each one caps.
SOCKET_CEILINGS = (("rmem_max", "receive"), ("wmem_max", "send"))


class BenchError(RuntimeError):
    """Anything that should stop the campaign with a readable message."""


# --------------------------------------------------------------------------------------------
# Measurements
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Measure:
    """One number a row of the table holds.

    `better` is the direction that is *better*, and it is what decides how the ``RR/GG`` ratio
    is annotated: a ratio of 0.5 is a win for CPU and a loss for goodput, and a table that
    leaves the reader to work that out per row is a table that gets misquoted.
    """

    key: str
    label: str
    unit: str
    #: ``"high"``, ``"low"`` or ``"neutral"``. Neutral is for a counter that is neither good nor
    #: bad on its own, `OutSegs` is larger for the arm that moved more data, and ticking it as
    #: a loss would be a lie told by the table rather than by the number.
    better: str
    digits: int = 2
    #: Below this, the ``RR/GG`` ratio is `n/a` rather than a number with a verdict attached.
    #:
    #: A segment counter that reaches 3 over a 20-second run is noise, and ``1 -> 3`` printed as
    #: "3.00x ✗" is a verdict on noise. Four of the crossed rows of the first x86_64 baseline page
    #: were of exactly that kind, and they made the page's counter disagreement look three times
    #: larger than it was. Only the retransmission-family counters carry a floor: `OutSegs` never
    #: gets near it, and for `streams completed` or an error count a small number is the
    #: measurement rather than noise around it.
    noise_floor: float = 0.0

    def format(self, value: float | None) -> str:
        if value is None:
            return "-"
        if self.digits == 0:
            return f"{value:,.0f}"
        return f"{value:,.{self.digits}f}"


#: The `noise_floor` of the retransmission-family segment counters.
#:
#: Chosen as a round number rather than derived: two digits of segments over a 20-second bulk cell
#: is somewhere below a tenth of a percent of `OutSegs` on every box in the lab, and no conclusion
#: in this repository has ever rested on one. Anything that matters is five or six digits.
SEGMENT_NOISE_FLOOR = 100.0

#: Every measurement this harness can harvest, by key. `METRICS` names subsets of these.
MEASURES: dict[str, Measure] = {
    m.key: m
    for m in (
        Measure("goodput_mbit_s", "goodput", "Mbit/s", "high", 1),
        Measure("tcp_retransmits", "TCP retransmits", "segments", "low", 0, SEGMENT_NOISE_FLOOR),
        Measure("cpu_s_per_gb_cli", "CPU per GB, client", "s/GB", "low", 2),
        Measure("cpu_s_per_gb_srv", "CPU per GB, server", "s/GB", "low", 2),
        Measure("cpu_s_per_gb_total", "CPU per GB, both ends", "s/GB", "low", 2),
        Measure("cpu_s_cli", "CPU over the run, client", "s", "low", 2),
        Measure("cpu_s_srv", "CPU over the run, server", "s", "low", 2),
        Measure("rss_kb_cli", "RSS, client", "kB", "low", 0),
        Measure("rss_kb_srv", "RSS, server", "kB", "low", 0),
        Measure("hwm_kb_cli", "peak VmHWM, client", "kB", "low", 0),
        Measure("hwm_kb_srv", "peak VmHWM, server", "kB", "low", 0),
        Measure("rtt_p50_ms", "latency p50", "ms", "low", 2),
        Measure("rtt_p90_ms", "latency p90", "ms", "low", 2),
        Measure("rtt_p99_ms", "latency p99", "ms", "low", 2),
        Measure("rtt_max_ms", "latency max", "ms", "low", 2),
        Measure("rtt_errors", "latency errors", "count", "low", 0),
        Measure("streams", "streams completed", "count", "high", 0),
        Measure("stream_errors", "stream errors", "count", "low", 0),
        Measure("out_segs_cli", "OutSegs, client", "segments", "neutral", 0),
        Measure("out_segs_srv", "OutSegs, server", "segments", "neutral", 0),
        Measure("retrans_pct_cli", "retransmitted share, client", "% of OutSegs", "low", 1),
        Measure("retrans_pct_srv", "retransmitted share, server", "% of OutSegs", "low", 1),
        Measure("retrans_segs_cli", "RetransSegs, client", "segments", "low", 0,
                SEGMENT_NOISE_FLOOR),
        Measure("retrans_segs_srv", "RetransSegs, server", "segments", "low", 0,
                SEGMENT_NOISE_FLOOR),
        Measure("fast_retrans_segs_cli", "FastRetransSegs, client", "segments", "low", 0,
                SEGMENT_NOISE_FLOOR),
        Measure("fast_retrans_segs_srv", "FastRetransSegs, server", "segments", "low", 0,
                SEGMENT_NOISE_FLOOR),
        Measure("early_retrans_segs_cli", "EarlyRetransSegs, client", "segments", "low", 0,
                SEGMENT_NOISE_FLOOR),
        Measure("early_retrans_segs_srv", "EarlyRetransSegs, server", "segments", "low", 0,
                SEGMENT_NOISE_FLOOR),
        Measure("lost_segs_cli", "LostSegs, client", "segments", "low", 0, SEGMENT_NOISE_FLOOR),
        Measure("lost_segs_srv", "LostSegs, server", "segments", "low", 0, SEGMENT_NOISE_FLOOR),
        Measure("repeat_segs_cli", "RepeatSegs received by the client", "segments", "low", 0,
                SEGMENT_NOISE_FLOOR),
        Measure("repeat_segs_srv", "RepeatSegs received by the server", "segments", "low", 0,
                SEGMENT_NOISE_FLOOR),
    )
}

#: Measurements a **cross** pair (GR, RG) may show. step 12.1 gives GR/RG throughput only:
#: a CPU or RSS row for GR would put a Go client's number and a Rust server's number in one cell
#: and invite exactly the comparison it cannot support.
CROSS_MEASURES = ("goodput_mbit_s", "tcp_retransmits")

#: Harvested from `proc.csv` in every cell, so that every goodput number has the CPU and memory
#: of the processes that produced it beside it.
RESOURCE_MEASURES = (
    "cpu_s_per_gb_cli", "cpu_s_per_gb_srv", "cpu_s_per_gb_total",
    "rss_kb_cli", "rss_kb_srv", "hwm_kb_cli", "hwm_kb_srv",
)

#: The same, for a family that moves almost no data. Dividing a tunnel's CPU by the 64-byte
#: probes of a latency cell produces a per-GB number in the thousands that says nothing about
#: efficiency, so an idle-ish family reports **absolute** CPU seconds over the run instead,
#: which is what "idle cost" in step 12's metric table actually means.
IDLE_RESOURCE_MEASURES = (
    "cpu_s_cli", "cpu_s_srv", "rss_kb_cli", "rss_kb_srv", "hwm_kb_cli", "hwm_kb_srv",
)

#: The KCP counters quoted beside a goodput row, **from both ends**.
#:
#: Both, because every one of them is a property of one side only and which side that is depends
#: on the direction of the workload. `RetransSegs`, `FastRetransSegs` and `LostSegs` are the
#: *sender's*, so on a download cell they live in the server's log and the client's column is
#: near zero; `RepeatSegs` counts duplicates the *receiver* got, which is how much the peer sent
#: needlessly. Harvesting only the client's log (as the first version of this file did) leaves a
#: download table with no retransmission data at all, and invites reading the client's empty
#: column as "no retransmission".
#:
#: **All three components of `RetransSegs` are here.** One `flush` adds `LostSegs +
#: FastRetransSegs + EarlyRetransSegs` into `RetransSegs` (the "counter updates" block of
#: `flush`, reference/kcptun/vendor/github.com/xtaci/kcp-go/v5/kcp.go), so the total decomposes
#: exactly, and only exactly when all three are printed. An earlier version of this tuple
#: quoted two of them, which left every `RetransSegs` row on the baseline pages with a visible
#: remainder (9.5% of the total on one of them) that read as unattributable retransmission,
#: which is the one thing these rows exist to attribute. `lab.py`'s `COMPARE_SNMP` says the
#: same thing for the same reason.
SNMP_MEASURES = (
    "out_segs_cli", "out_segs_srv",
    "retrans_pct_cli", "retrans_pct_srv",
    "retrans_segs_cli", "retrans_segs_srv",
    "fast_retrans_segs_cli", "fast_retrans_segs_srv",
    "early_retrans_segs_cli", "early_retrans_segs_srv",
    "lost_segs_cli", "lost_segs_srv",
    "repeat_segs_cli", "repeat_segs_srv",
)

#: `snmp_totals` key -> measurement key suffix.
SNMP_KEYS = {
    "OutSegs": "out_segs",
    "RetransSegs": "retrans_segs",
    "FastRetransSegs": "fast_retrans_segs",
    "EarlyRetransSegs": "early_retrans_segs",
    "LostSegs": "lost_segs",
    "RepeatSegs": "repeat_segs",
}


# --------------------------------------------------------------------------------------------
# Metric families
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Metric:
    """One column of the grid: the workloads of a cell and what is read out of it."""

    name: str
    description: str
    #: Which implementation pairs this family is run for.
    pairs: tuple[tuple[str, str], ...]
    #: `lab.py` workload dictionaries, rendered with the campaign's durations substituted.
    workloads: tuple[dict[str, Any], ...]
    #: Measurement keys, in table order.
    measures: tuple[str, ...]

    def render_workloads(self, duration: int) -> list[dict[str, Any]]:
        """The scenario's workloads, with ``"duration": 0`` replaced by the campaign's."""
        out = []
        for workload in self.workloads:
            item = dict(workload)
            for key in ("duration", "start_after"):
                value = item.get(key)
                if isinstance(value, str) and value.startswith("$"):
                    item[key] = _substitute(value, duration)
            out.append(item)
        return out


def _substitute(expression: str, duration: int) -> int:
    """``$d``, ``$d-4``, ``$d/2`` against the campaign's workload duration.

    Deliberately tiny: a campaign file never reaches this, only the `METRICS` table below, and a
    general expression evaluator in a benchmark harness is a way to be surprised later.
    """
    body = expression[1:]
    if body == "d":
        return duration
    if body.startswith("d-"):
        return max(1, duration - int(body[2:]))
    if body.startswith("d/"):
        return max(1, duration // int(body[2:]))
    raise BenchError(f"internal: cannot substitute {expression!r}")


METRICS: dict[str, Metric] = {
    metric.name: metric
    for metric in (
        Metric(
            "bulk-up",
            "one TCP stream through the tunnel, client to server (iperf3, forward)",
            ALL_PAIRS,
            ({"type": "iperf3", "tag": "up", "duration": "$d", "omit": 2},),
            ("goodput_mbit_s", "tcp_retransmits", *RESOURCE_MEASURES, *SNMP_MEASURES),
        ),
        Metric(
            "bulk-down",
            "one TCP stream through the tunnel, server to client (iperf3 -R)",
            ALL_PAIRS,
            ({"type": "iperf3", "tag": "down", "duration": "$d", "omit": 2,
              "reverse": True},),
            ("goodput_mbit_s", "tcp_retransmits", *RESOURCE_MEASURES, *SNMP_MEASURES),
        ),
        Metric(
            "bulk-par-up",
            "eight parallel TCP streams, client to server (iperf3 -P 8)",
            ALL_PAIRS,
            ({"type": "iperf3", "tag": "parup", "duration": "$d", "omit": 2,
              "parallel": 8},),
            ("goodput_mbit_s", "tcp_retransmits", *RESOURCE_MEASURES, *SNMP_MEASURES),
        ),
        Metric(
            "bulk-par-down",
            "eight parallel TCP streams, server to client (iperf3 -P 8 -R)",
            ALL_PAIRS,
            ({"type": "iperf3", "tag": "pardown", "duration": "$d", "omit": 2,
              "parallel": 8, "reverse": True},),
            ("goodput_mbit_s", "tcp_retransmits", *RESOURCE_MEASURES, *SNMP_MEASURES),
        ),
        Metric(
            "latency",
            "64-byte ping/pong through an otherwise idle tunnel",
            SAME_PAIRS,
            ({"type": "ping", "tag": "idle", "duration": "$d", "size": 64},),
            ("rtt_p50_ms", "rtt_p90_ms", "rtt_p99_ms", "rtt_max_ms", "rtt_errors",
             *IDLE_RESOURCE_MEASURES),
        ),
        Metric(
            "latency-loaded",
            "the same ping/pong while a bulk flow saturates the same tunnel",
            SAME_PAIRS,
            (
                {"type": "bulk", "tag": "load", "duration": "$d"},
                {"type": "ping", "tag": "loaded", "duration": "$d-4", "start_after": 2,
                 "size": 64},
            ),
            ("rtt_p50_ms", "rtt_p90_ms", "rtt_p99_ms", "rtt_max_ms", "rtt_errors",
             "goodput_mbit_s", *RESOURCE_MEASURES, *SNMP_MEASURES),
        ),
        Metric(
            "churn",
            "short streams opened and closed continuously (smux and session setup cost)",
            SAME_PAIRS,
            ({"type": "churn", "tag": "churn", "duration": "$d", "rate": 20,
              "max_bytes": "64k"},),
            ("streams", "stream_errors", "goodput_mbit_s", *RESOURCE_MEASURES,
             *SNMP_MEASURES),
        ),
    )
}


# --------------------------------------------------------------------------------------------
# Campaigns
# --------------------------------------------------------------------------------------------


@dataclass
class Campaign:
    """A grid of cells, and everything the generated page has to state about itself."""

    name: str
    #: Slug for the page name: ``docs/benchmarks/<date>-<env>.md``.
    env: str
    description: str = ""
    configs: tuple[str, ...] = ("s1",)
    metrics: tuple[str, ...] = ("bulk-up",)
    repetitions: int = MIN_REPETITIONS
    duration: int = 20
    mode: str = lab.MODE_NETNS
    netem: str = "clean"
    server_host: str = ""
    server_addr: str = ""
    sample_interval: int = 5
    snmp_period: int = 10
    settle: int = 5
    #: Seconds of quiet between cells. A 1-vCPU host that has just been saturated carries a
    #: 1-minute load average well above 1.0 for minutes afterwards, and `lab.py`'s preflight
    #: (tools/lab/README.md rule 6) then refuses the next cell. Waiting is the honest fix: the next
    #: cell should not start while the previous one's processes are still being reaped.
    cooldown: int = 60
    tunnel_port: int = lab.DEFAULT_TUNNEL_PORT
    listen_port: int = lab.DEFAULT_LISTEN_PORT
    pingpong_port: int = lab.DEFAULT_PINGPONG_PORT
    client_flags: dict[str, Any] = field(default_factory=dict)
    server_flags: dict[str, Any] = field(default_factory=dict)
    notes: tuple[str, ...] = ()
    #: Paragraphs rendered as an "Observations" section at the end of the page. They are written
    #: *after* the campaign has run, that is the point of `report --campaign`: the reading of a
    #: result belongs in the committed campaign file beside the grid that produced it, so the
    #: page stays regenerable from the raw runs instead of being hand-edited afterwards.
    observations: tuple[str, ...] = ()
    source: str = ""

    @property
    def cells(self) -> list[tuple[str, str]]:
        """Every (config, metric) pair, in the order they are run."""
        return [(config, metric) for config in self.configs for metric in self.metrics]

    def cell_name(self, config: str, metric: str) -> str:
        """The scenario name of one cell: it becomes a directory and PID file names."""
        return f"{self.name}-{config}-{metric}"

    def scenario(self, config: str, metric: str) -> dict[str, Any]:
        """The `lab.py` scenario dictionary for one cell."""
        family = METRICS[metric]
        raw: dict[str, Any] = {
            "name": self.cell_name(config, metric),
            "description": f"{self.description or self.name}: {config} x {metric} "
                           f"- {family.description}",
            "config": config,
            "mode": self.mode,
            "netem": self.netem,
            "pairs": [list(pair) for pair in family.pairs],
            "repetitions": self.repetitions,
            "settle": self.settle,
            "sample_interval": self.sample_interval,
            "snmp_period": self.snmp_period,
            "tunnel_port": self.tunnel_port,
            "listen_port": self.listen_port,
            "pingpong_port": self.pingpong_port,
            "workloads": family.render_workloads(self.duration),
        }
        if self.mode == lab.MODE_WAN:
            raw["server_host"] = self.server_host
            raw["server_addr"] = self.server_addr
        if self.client_flags:
            raw["client_flags"] = dict(self.client_flags)
        if self.server_flags:
            raw["server_flags"] = dict(self.server_flags)
        return raw


CAMPAIGN_FIELDS = {f.name for f in dataclasses.fields(Campaign)} - {"source"}

#: The only fields `report --campaign` may pick up from an edited campaign file.
#:
#: They are the *reading* of the result and the prose around it, which is written after the runs
#: are in and which `report --campaign` exists to let in. Every other field describes what ran,
#: `repetitions`, `duration`, `configs`, `metrics`, `mode`, `netem`, `settle`, the ports, the
#: flags, and is printed into the Method table and used by the under-replication banner as if
#: it were a statement about the runs on disk. Editing `repetitions` from 3 to 5 and
#: regenerating would otherwise produce a page claiming five runs per pair, with the banner
#: gone, from three. `cmd_report` refuses that; this set is what it allows through.
REREADABLE_FIELDS = {"description", "notes", "observations", "source"}


def parse_campaign(raw: dict[str, Any], source: str = "") -> Campaign:
    """Validates a campaign dictionary. Every error names the field."""
    unknown = set(raw) - CAMPAIGN_FIELDS
    if unknown:
        raise BenchError(f"unknown campaign field(s): {', '.join(sorted(unknown))}")

    name = str(raw.get("name") or "").strip()
    if not name or not all(c.isalnum() or c in "._-" for c in name) or not name[0].isalnum():
        raise BenchError("name: must be [A-Za-z0-9._-] and start alphanumeric "
                         "(it becomes a directory and PID file names)")

    env = str(raw.get("env") or "").strip()
    if not env or not all(c.isalnum() or c in "._-" for c in env):
        raise BenchError("env: required, [A-Za-z0-9._-] "
                         "(it names docs/benchmarks/<date>-<env>.md)")

    configs = tuple(str(c).lower() for c in raw.get("configs", ["s1"]))
    if not configs:
        raise BenchError("configs: at least one is required")
    for config in configs:
        if config not in lab.CONFIGS:
            raise BenchError(f"configs: {config!r} is not one of "
                             f"{', '.join(sorted(lab.CONFIGS))}")

    metrics = tuple(str(m) for m in raw.get("metrics", ["bulk-up"]))
    if not metrics:
        raise BenchError("metrics: at least one is required")
    for metric in metrics:
        if metric not in METRICS:
            raise BenchError(f"metrics: {metric!r} is not one of "
                             f"{', '.join(sorted(METRICS))}")

    mode = str(raw.get("mode", lab.MODE_NETNS)).lower()
    if mode not in lab.MODES:
        raise BenchError(f"mode: {mode!r} is not one of {', '.join(lab.MODES)}")

    campaign = Campaign(
        name=name,
        env=env,
        description=str(raw.get("description", "")),
        configs=configs,
        metrics=metrics,
        repetitions=int(raw.get("repetitions", MIN_REPETITIONS)),
        duration=int(raw.get("duration", 20)),
        mode=mode,
        netem=str(raw.get("netem", "clean")),
        server_host=str(raw.get("server_host", "")),
        server_addr=str(raw.get("server_addr", "")),
        sample_interval=int(raw.get("sample_interval", 5)),
        snmp_period=int(raw.get("snmp_period", 10)),
        settle=int(raw.get("settle", 5)),
        cooldown=int(raw.get("cooldown", 60)),
        tunnel_port=int(raw.get("tunnel_port", lab.DEFAULT_TUNNEL_PORT)),
        listen_port=int(raw.get("listen_port", lab.DEFAULT_LISTEN_PORT)),
        pingpong_port=int(raw.get("pingpong_port", lab.DEFAULT_PINGPONG_PORT)),
        client_flags=dict(raw.get("client_flags", {})),
        server_flags=dict(raw.get("server_flags", {})),
        notes=tuple(str(note) for note in raw.get("notes", ())),
        observations=tuple(str(item) for item in raw.get("observations", ())),
        source=source,
    )
    if campaign.repetitions < 1:
        raise BenchError("repetitions: must be at least 1")
    if campaign.duration < 5:
        raise BenchError("duration: must be at least 5 seconds")
    if campaign.cooldown < 0:
        raise BenchError("cooldown: must not be negative")
    # Every cell has to be a scenario `lab.py` itself accepts: the ports, the netem profile, the
    # workload options and the iperf3-versus-pingpong rule are all checked there, and checking
    # them here as well would be a second copy to drift.
    for config, metric in campaign.cells:
        try:
            lab.parse_scenario(campaign.scenario(config, metric),
                               source=f"{source} [{config} x {metric}]")
        except lab.LabError as exc:
            raise BenchError(f"{config} x {metric}: {exc}") from exc
    return campaign


def load_campaign(path: Path) -> Campaign:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BenchError(f"{path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise BenchError(f"{path}: want an object at the top level")
    try:
        return parse_campaign(raw, source=str(path))
    except BenchError as exc:
        raise BenchError(f"{path}: {exc}") from exc


# --------------------------------------------------------------------------------------------
# Harvesting one run
# --------------------------------------------------------------------------------------------


def transferred_bytes(state: dict[str, Any], directory: Path) -> float:
    """How many bytes the workloads moved through the tunnel, for the per-GB columns.

    The workload's own accounting, never the SNMP byte counters: those count what went over the
    wire, which includes retransmissions, FEC parity and the KCP and crypto headers. Dividing
    CPU by *those* would credit an implementation for the redundancy it emitted.
    """
    total = 0.0
    for workload in state.get("workloads", []):
        if workload["type"] == "iperf3":
            summary = lab.iperf3_summary(directory / f"iperf3-{workload['tag']}.json")
            if summary and not summary.get("error") and summary.get("bytes"):
                total += float(summary["bytes"])
            continue
        results = lab.result_lines(directory / f"{workload['name']}.log")
        if not results:
            continue
        result = results[-1]
        # `kr-pingpong`'s bulk and churn RESULT lines carry both directions explicitly
        # (`bytes_up`, `bytes_down`); the rate is a derived field and is only used when the
        # byte counters are missing, so that this never disagrees with `mbit_s` by rounding.
        counted = [float(result[key]) for key in ("bytes_up", "bytes_down")
                   if result.get(key) is not None]
        if counted:
            total += sum(counted)
        elif result.get("mbit_s") is not None:
            elapsed = float(result.get("elapsed_s") or workload["duration"])
            total += float(result["mbit_s"]) * 1e6 / 8.0 * elapsed
    return total


def harvest(state: dict[str, Any], directory: Path) -> dict[str, float]:
    """Every measurement of one collected run, as ``key -> value``.

    A key that is missing is genuinely *not measured* and prints as ``-``; nothing here
    substitutes a zero, because "the FEC counters were all zero" and "this run has no FEC
    counters" are different facts and only one of them is a result.
    """
    out: dict[str, float] = {}

    for workload in state.get("workloads", []):
        metrics = lab.workload_metrics(workload, directory)
        if workload["type"] == "iperf3":
            if "Mbit/s" in metrics:
                out["goodput_mbit_s"] = metrics["Mbit/s"]
            if "TCP retrans" in metrics:
                out["tcp_retransmits"] = metrics["TCP retrans"]
        elif workload["type"] == "ping":
            for source, key in (("p50 ms", "rtt_p50_ms"), ("p90 ms", "rtt_p90_ms"),
                                ("p99 ms", "rtt_p99_ms"), ("max ms", "rtt_max_ms"),
                                ("errors", "rtt_errors")):
                if source in metrics:
                    out[key] = metrics[source]
        elif workload["type"] == "bulk":
            if "Mbit/s" in metrics:
                out["goodput_mbit_s"] = metrics["Mbit/s"]
        elif workload["type"] == "churn":
            if "streams" in metrics:
                out["streams"] = metrics["streams"]
            if "errors" in metrics:
                out["stream_errors"] = metrics["errors"]
            if "Mbit/s" in metrics:
                out["goodput_mbit_s"] = metrics["Mbit/s"]

    processes = lab.collected_process_metrics(directory, state.get("total_duration"))
    gigabytes = transferred_bytes(state, directory) / 1e9
    cpu_total = 0.0
    cpu_seen = False
    for label, key in (("cli", "cli"), ("srv", "srv")):
        entry = processes.get(label)
        if not entry:
            continue
        out[f"rss_kb_{key}"] = float(entry["rss_kb_last"])
        out[f"hwm_kb_{key}"] = float(entry["hwm_kb"])
        cpu = float(entry["cpu_seconds"])
        out[f"cpu_s_{key}"] = cpu
        cpu_total += cpu
        cpu_seen = True
        if gigabytes > 0:
            out[f"cpu_s_per_gb_{key}"] = cpu / gigabytes
    if cpu_seen and gigabytes > 0:
        out["cpu_s_per_gb_total"] = cpu_total / gigabytes

    # A WAN run keeps the server's half under `server/`; `lab.run_files` finds either layout.
    for side in ("cli", "srv"):
        for snmp in lab.run_files(directory, f"snmp-{side}.csv"):
            totals = lab.snmp_totals(snmp)
            for source, key in SNMP_KEYS.items():
                if source in totals:
                    out[f"{key}_{side}"] = float(totals[source])
        # The share of what this end sent that was a retransmission. kcp-go counts every
        # outgoing segment in `OutSegs` (kcp.go:191) and adds `LostSegs + FastRetransSegs +
        # EarlyRetransSegs` into `RetransSegs` in the same `flush`, so the two divide. A raw
        # `RetransSegs` cannot be compared between two implementations that moved different
        # amounts of data in the same 20 seconds; the share can.
        sent = out.get(f"out_segs_{side}")
        retransmitted = out.get(f"retrans_segs_{side}")
        if sent and retransmitted is not None:
            out[f"retrans_pct_{side}"] = 100.0 * retransmitted / sent
    return out


@dataclass
class Sample:
    """One (cell, pair, repetition) run, harvested."""

    config: str
    metric: str
    pair: str
    repetition: int
    runid: str
    started_iso: str
    values: dict[str, float]


def collect_cell(session: Path, config: str, metric: str) -> list[Sample]:
    """Every collected run of one cell, in the order it ran."""
    samples: list[Sample] = []
    for directory in sorted(path.parent for path in session.glob("*/state.json")):
        state = json.loads((directory / "state.json").read_text(encoding="utf-8"))
        samples.append(Sample(
            config=config,
            metric=metric,
            pair=lab.pair_code(state),
            repetition=int(state.get("repetition", 1)),
            runid=str(state.get("runid", directory.name)),
            started_iso=str(state.get("started_iso", "")),
            values=harvest(state, directory),
        ))
    samples.sort(key=lambda s: (s.repetition, PAIR_ORDER.index(s.pair)
                                if s.pair in PAIR_ORDER else 9))
    return samples


# --------------------------------------------------------------------------------------------
# The page
# --------------------------------------------------------------------------------------------


def medians(samples: Sequence[Sample], pair: str, key: str) -> tuple[float | None, int]:
    """The median of one measurement over a pair's repetitions, and how many there were."""
    values = [s.values[key] for s in samples if s.pair == pair and key in s.values]
    return lab.median(values), len(values)


def ratio_cell(rr: float | None, gg: float | None, measure: Measure) -> str:
    """``RR/GG`` with the direction spelt out: 0.5 is a win for one row and a loss for the next.

    Three outcomes, kept distinct on purpose: ``-`` when one of the two was not measured, ``n/a``
    when the ratio would be a verdict on nothing, and the ratio otherwise.

    A ratio is "a verdict on nothing" in two ways. Go's median is zero, or prints as zero: the
    ratio is undefined rather than infinite, and the two cells beside it already say which side
    was zero. Or *both* medians are below the measure's `noise_floor`: ``1 -> 3`` segments over
    a 20-second run is noise, and printing it as "3.00x ✗" attaches a verdict to it that the
    reader then has to discount by hand.
    """
    if rr is None or gg is None:
        return "-"
    # Not only `gg == 0`: a ratio computed from two values that both *print* as zero is a number
    # the reader cannot check against the cells beside it, and on a counter like the idle end's
    # retransmission share it reads as a 35 % win over nothing at all.
    if gg == 0 or set(measure.format(gg)) <= {"0", ".", ",", "-"}:
        return "n/a"
    if max(rr, gg) < measure.noise_floor:
        return "n/a"
    value = rr / gg
    if measure.better == "neutral":
        return f"{value:.2f}x"
    good = value >= 1.0 if measure.better == "high" else value <= 1.0
    return f"{value:.2f}x {'✓' if good else '✗'}"


def cell_table(samples: Sequence[Sample], metric: Metric) -> list[str]:
    """One metric family's table: a row per measurement, a column per pair."""
    pairs = [lab.IMPLS[c] + lab.IMPLS[s] for c, s in metric.pairs]
    pairs = [p.upper() for p in pairs]
    present = [p for p in PAIR_ORDER if p in pairs]
    header = ["measurement", "unit", *present, "RR/GG"]
    lines = ["| " + " | ".join(header) + " |",
             "|" + "|".join(["---"] + ["---:"] * (len(header) - 1)) + "|"]
    for key in metric.measures:
        measure = MEASURES[key]
        cells: list[str] = []
        values: dict[str, float | None] = {}
        for pair in present:
            if pair in ("GR", "RG") and key not in CROSS_MEASURES:
                # step 12.1: cross pairs are throughput only.
                values[pair] = None
                cells.append("·")
                continue
            value, count = medians(samples, pair, key)
            values[pair] = value
            cells.append(measure.format(value) + (f" ({count})" if 0 < count < MIN_REPETITIONS
                                                  else ""))
        if all(cell in ("-", "·") for cell in cells):
            continue
        lines.append("| " + " | ".join([
            measure.label, measure.unit, *cells,
            ratio_cell(values.get("RR"), values.get("GG"), measure),
        ]) + " |")
    return lines


def spread_table(samples: Sequence[Sample], metric: Metric) -> list[str]:
    """The headline measurement's every run, so a median can be checked against its spread.

    A median with no spread beside it cannot be told from a lucky single run, and this project
    has already had one table (the 12.2d ``in_order`` rows) read as noise when it was two clean
    modes. The headline is the first measurement of the family.
    """
    key = metric.measures[0]
    measure = MEASURES[key]
    pairs = [p for p in PAIR_ORDER
             if p in {(lab.IMPLS[c] + lab.IMPLS[s]).upper() for c, s in metric.pairs}]
    lines = [f"The spread behind those medians: every run of *{measure.label}* "
             f"({measure.unit}), in the order it ran:", ""]
    lines.append("| pair | runs | min | median | max | every run |")
    lines.append("|---|---:|---:|---:|---:|---|")
    for pair in pairs:
        ordered = [s for s in samples if s.pair == pair and key in s.values]
        ordered.sort(key=lambda s: s.repetition)
        values = [s.values[key] for s in ordered]
        if not values:
            lines.append(f"| {pair} | 0 | - | - | - | - |")
            continue
        every = ", ".join(measure.format(value) for value in values)
        lines.append(f"| {pair} | {len(values)} | {measure.format(min(values))} | "
                     f"{measure.format(lab.median(values))} | {measure.format(max(values))} | "
                     f"{every} |")
    lines.append("")
    return lines


# --------------------------------------------------------------------------------------------
# Socket-buffer ceilings (docs/DECISIONS.md D32)
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Clamp:
    """One `-sockbuf` request the kernel will silently shrink, and by how much."""

    config: str
    side: str
    host: str
    sysctl: str
    what: str
    wanted: int
    ceiling: int
    defaulted: bool

    @property
    def stock(self) -> bool:
        """Is the ceiling doing the shrinking the stock Linux one D32 invalidates?"""
        return self.ceiling <= STOCK_SOCKET_CEILING

    def describe(self) -> str:
        asked = f"{self.wanted:,} B" + (" (kcptun's default)" if self.defaulted else "")
        # `s1`'s server asks for 67,108,868 against a `wmem_max` of 67,108,864: a four-byte
        # shortfall that "1x smaller than asked for" describes both accurately and uselessly.
        # A factor is the right unit for 20x and the wrong one for 1.00006x.
        if self.wanted < self.ceiling * 1.05:
            shortfall = f"{self.wanted - self.ceiling:,} B short"
        else:
            shortfall = f"{self.wanted / self.ceiling:.0f}x smaller than asked for"
        return (f"`{self.config}` {self.side} asks for {asked}, `{self.host}` "
                f"`net.core.{self.sysctl}` is {self.ceiling:,} B, so the {self.what} buffer is "
                f"{shortfall}")


def config_sockbuf(config: str, side: str) -> tuple[int, bool]:
    """What one side of a configuration asks `setsockopt` for, and whether it said so.

    A configuration that passes no `-sockbuf` still requests `DEFAULT_SOCKBUF`: kcptun's flag
    has a default and the binary always calls `SetReadBuffer`/`SetWriteBuffer` with it. Treating
    an absent flag as "no request" is exactly how S2 looked exempt from D32 when it is not.
    """
    base = lab.CONFIGS[config]
    flags: dict[str, Any] = {**base["common"], **base.get(side, {})}
    wanted = flags.get("sockbuf")
    if isinstance(wanted, int):
        return wanted, False
    return DEFAULT_SOCKBUF, True


def recorded_ceilings(states: Sequence[dict[str, Any]]) -> tuple[dict[str, set[tuple[int, int]]],
                                                                 int]:
    """Every distinct ``(rmem_max, wmem_max)`` pair each host recorded, and how many runs did not.

    `lab.py` reads both limits before every run and keeps them in `state.json`; a run that
    predates that, or whose host could not be read, contributes to the *missing* count rather
    than to a ceiling, because what a run does not say about itself is not something this page
    may assume.
    """
    by_host: dict[str, set[tuple[int, int]]] = {}
    missing = 0
    for state in states:
        limits = state.get("socket_buffer_limits") or {}
        if not limits:
            missing += 1
            continue
        for host, values in limits.items():
            rmem = values.get("rmem_max")
            wmem = values.get("wmem_max")
            by_host.setdefault(str(host), set()).add(
                (int(rmem) if isinstance(rmem, int) else -1,
                 int(wmem) if isinstance(wmem, int) else -1))
    return by_host, missing


def recorded_sides(states: Sequence[dict[str, Any]]) -> dict[str, set[str]]:
    """Which half of the tunnel each host actually ran, from the runs themselves.

    A netns run has both ends in two namespaces of one machine, so that host is checked against
    both sides' `-sockbuf`. A WAN run has one end on each machine and the two carry their own
    ceilings, so checking the client's request against the *server* host's `rmem_max` names a
    host that never ran that flag. `lab.warn_clamped_sockbuf` takes the sides explicitly for the
    same reason; here they are read back out of `state.json`'s `host`/`server_host`.
    """
    sides: dict[str, set[str]] = {}
    for state in states:
        client = str(state.get("host") or "")
        server = str(state.get("server_host") or client) if lab.state_is_wan(state) else client
        for host, side in ((client, "client"), (server, "server")):
            if host:
                sides.setdefault(host, set()).add(side)
    return sides


def campaign_sides(campaign: Campaign, client_host: str) -> dict[str, set[str]]:
    """`recorded_sides` for a campaign that has not run yet, from the recipe, not from states.

    The preflight has to know this before a single run exists, and it is the same mapping
    `lab.py` passes to `warn_clamped_sockbuf` when it preflights a WAN pair.
    """
    if campaign.mode == lab.MODE_WAN and campaign.server_host:
        if campaign.server_host == client_host:
            return {client_host: {"client", "server"}}
        return {client_host: {"client"}, campaign.server_host: {"server"}}
    return {client_host: {"client", "server"}}


def sockbuf_clamps(configs: Sequence[str],
                   by_host: dict[str, set[tuple[int, int]]],
                   sides: dict[str, set[str]] | None = None) -> list[Clamp]:
    """Every (configuration, side, host, ceiling) the kernel will shrink, worst first.

    `sides` says which ends each host runs (`recorded_sides`). A host missing from it is checked
    against both, which is the conservative reading for a run that did not record its hosts and
    the right one for every netns campaign.
    """
    clamps: list[Clamp] = []
    for config in configs:
        if config not in lab.CONFIGS:
            continue
        for host, ceilings in sorted(by_host.items()):
            host_sides = (sides or {}).get(host) or {"client", "server"}
            for side in ("client", "server"):
                if side not in host_sides:
                    continue
                wanted, defaulted = config_sockbuf(config, side)
                for rmem, wmem in sorted(ceilings):
                    for limit, (sysctl, what) in zip((rmem, wmem), SOCKET_CEILINGS):
                        if limit > 0 and wanted > limit:
                            clamps.append(Clamp(config, side, host, sysctl, what,
                                                wanted, limit, defaulted))
    clamps.sort(key=lambda c: (-(c.wanted / c.ceiling), c.config, c.side, c.sysctl))
    return clamps


def ceiling_summary(by_host: dict[str, set[tuple[int, int]]]) -> str:
    """The method table's ceiling cell: one phrase per host, per distinct pair it recorded."""
    parts = []
    for host, ceilings in sorted(by_host.items()):
        for rmem, wmem in sorted(ceilings):
            rendered = ", ".join(
                f"`{sysctl}` {value:,}" if value > 0 else f"`{sysctl}` not readable"
                for value, (sysctl, _) in zip((rmem, wmem), SOCKET_CEILINGS))
            parts.append(f"`{host}` {rendered}")
    return "; ".join(parts)


def socket_buffer_row(configs: Sequence[str], states: Sequence[dict[str, Any]]) -> str:
    """The method-table row. Absent, this whole class of defect is invisible on the page.

    The 12.1 baseline was taken on a host at the stock ceiling and neither page recorded it, so
    D32-invalid S1 rows were quotable for a day. The row is therefore unconditional: it prints
    "**not recorded**" rather than nothing when no run carried the limits.
    """
    by_host, missing = recorded_ceilings(states)
    if not by_host:
        return ("| socket-buffer ceilings | **not recorded**: `-sockbuf` is silently clamped to "
                "`net.core.rmem_max`/`wmem_max` and no run here says what they were "
                "(docs/DECISIONS.md D32) |")
    summary = ceiling_summary(by_host)
    if missing:
        summary += f": recorded for {len(states) - missing} of {len(states)} runs"
    summary += (": `setsockopt(SO_RCVBUF)`/`SO_SNDBUF` is silently clamped to these "
                "(docs/DECISIONS.md D32)")
    clamps = sockbuf_clamps(configs, by_host, recorded_sides(states))
    granted = []
    any_default = False
    for config in configs:
        if config not in lab.CONFIGS:
            continue
        for side in ("client", "server"):
            wanted, defaulted = config_sockbuf(config, side)
            any_default = any_default or defaulted
            hit = [c for c in clamps if c.config == config and c.side == side]
            asked = f"{wanted:,}" + ("*" if defaulted else "")
            if hit:
                worst = min(c.ceiling for c in hit)
                granted.append(f"`{config}` {side} {asked} → **{worst:,}**")
            else:
                granted.append(f"`{config}` {side} {asked} → honoured")
    note = " Requested `-sockbuf` → what the kernel grants: " + "; ".join(granted) + "."
    # From the flag, not from a `*` in the rendered text: the bold markers round `**8,388,608**`
    # are asterisks too, and scanning for one printed the footnote on a grid that has no default
    # in it.
    if any_default:
        note += (f" An asterisk is kcptun's own default of {DEFAULT_SOCKBUF:,} B, which a "
                 "configuration that passes no `-sockbuf` still asks for.")
    return f"| socket-buffer ceilings | {summary}.{note} |"


def socket_buffer_banner(configs: Sequence[str], states: Sequence[dict[str, Any]]) -> list[str]:
    """The block the page leads with when its numbers are conditioned on a clamped buffer.

    Three separate failures, three separate wordings, because they are not equally bad:

    * **nothing recorded**: the page cannot rule the defect in or out, which is the state the
      12.1 pages were published in;
    * **more than one ceiling in one campaign**: a median across two of them is a number no
      experiment produced (`lab.py`'s impairment matrix splits its cells for the same reason);
    * **clamped at the stock ceiling**: D32 says discard, not interpret, so the banner says
      invalid rather than merely noting it.

    A clamp at a *raised* ceiling is a condition of the experiment, not a defect: lab-arm64 runs
    S1 with the server's 64 MiB request capped at 8 MiB and D32 measured zero `UdpRcvbufErrors`
    there. It gets a plain note, because crying wolf on the tuned hosts is how a real warning
    stops being read.
    """
    if not states:
        return []
    by_host, missing = recorded_ceilings(states)
    if not by_host:
        return ["> ⚠ **SOCKET-BUFFER CEILING NOT RECORDED: this page cannot rule out "
                "docs/DECISIONS.md D32.** `-sockbuf` is silently clamped to "
                "`net.core.rmem_max`/`wmem_max`, and on a host at the stock "
                f"{STOCK_SOCKET_CEILING:,} B ceiling that clamp alone inverted three cells of "
                "the 11.2 matrix. None of these runs recorded the limits, so whether these "
                "numbers measure the implementations or the host is not decidable from this "
                "page."]
    lines: list[str] = []
    mixed = sorted(host for host, ceilings in by_host.items() if len(ceilings) > 1)
    if mixed or missing:
        detail = []
        if mixed:
            detail.append("more than one ceiling was in force on " +
                          ", ".join(f"`{host}`" for host in mixed))
        if missing:
            detail.append(f"{missing} of {len(states)} runs recorded no ceiling at all")
        lines.append("> ⚠ **THE RUNS BEHIND THIS PAGE WERE NOT ALL TAKEN UNDER THE SAME "
                     "SOCKET-BUFFER CEILING**: " + "; and ".join(detail) +
                     ". A median across two ceilings is a number no experiment produced; the "
                     "cells below do not separate them, so nothing here is quotable until the "
                     "runs are split.")
    clamps = sockbuf_clamps(configs, by_host, recorded_sides(states))
    stock = [c for c in clamps if c.stock]
    if stock:
        affected = sorted({c.config for c in stock})
        lines.append("> ⚠ **INVALID UNDER docs/DECISIONS.md D32: do not interpret "
                     + ", ".join(f"`{c}`" for c in affected) +
                     ", discard it.** The host is at the stock "
                     f"{STOCK_SOCKET_CEILING:,} B socket-buffer ceiling, so what these "
                     "configurations measure is the ceiling: " +
                     "; ".join(c.describe() for c in stock[:4]) +
                     ("; …" if len(stock) > 4 else "") + ".")
    elif clamps:
        lines.append("> **Note: `-sockbuf` is clamped here, at a raised ceiling.** "
                     + "; ".join(c.describe() for c in clamps) +
                     ". That is the same clamp lab-arm64 runs under, where D32 measured zero "
                     "`UdpRcvbufErrors` over a 65 s S1 run, so it is a stated condition of "
                     "these numbers rather than a reason to discard them.")
    # Each entry is its own block quote, so they need a blank line between them or Markdown
    # runs them together into one paragraph.
    separated: list[str] = []
    for line in lines:
        if separated:
            separated.append("")
        separated.append(line)
    return separated


def build_lines(states: Sequence[dict[str, Any]]) -> list[str]:
    """What actually ran, named from the build stamps `lab.py` recorded (12.0).

    `lab.compare_artefacts` prints the commit, which is what a reader wants, but a stamp also
    records the *revision*, and a revision ending in ``-dirty`` means the binary was built from
    a tree that was not the commit it names. That is precisely the kind of "named but not
    actually attributable" artefact 12.0 exists to catch, so it gets its own line rather than
    being rounded off into a clean-looking hash.
    """
    lines = list(lab.compare_artefacts(states))
    dirty: dict[str, set[str]] = {}
    for state in states:
        for key in lab.BUILD_DETAIL_KEYS:
            detail = state.get(key) or {}
            revision = str(detail.get("revision", ""))
            if revision.endswith("-dirty"):
                dirty.setdefault(revision, set()).add(str(detail.get("kind", "?")))
    if dirty:
        described = "; ".join(f"`{revision}` ({', '.join(sorted(kinds))})"
                              for revision, kinds in sorted(dirty.items()))
        where = lines.index("") if "" in lines else len(lines)
        lines[where:where] = [
            "",
            f"**Built from a modified tree:** {described}. The commit above names the base, not "
            "the tree the binary was built from; check what differed before treating these "
            "numbers as that commit's.",
        ]
    return lines


def report(campaign: Campaign, cells: dict[tuple[str, str], list[Sample]],
           meta: dict[str, Any]) -> str:
    """The Markdown page: methodology first, then one section per configuration."""
    date = meta.get("date", time.strftime("%Y-%m-%d"))
    few = campaign.repetitions < MIN_REPETITIONS
    out: list[str] = []
    out.append(f"# Go vs Rust end to end: {meta.get('env_title', campaign.env)}, {date}")
    out.append("")
    if few:
        out.append(f"> **UNDER-REPLICATED.** This campaign ran {campaign.repetitions} "
                   f"repetition(s) per cell, fewer than the {MIN_REPETITIONS} that "
                   "step 12 rule 1 requires. Every median below is over that "
                   "many runs and must not be quoted as a measurement.")
        out.append("")
    for note in meta.get("banner", ()):
        out.append(note)
    if meta.get("banner"):
        out.append("")
    out.append(campaign.description or "")
    out.append("")

    out.append("## Method")
    out.append("")
    out.append("| | |")
    out.append("|---|---|")
    out.append(f"| campaign | `{Path(campaign.source).name or campaign.name}` |")
    out.append(f"| client host | `{meta.get('host', '?')}`: {meta.get('host_detail', '')} |")
    if campaign.mode == lab.MODE_WAN:
        out.append(f"| server host | `{campaign.server_host}` at `{campaign.server_addr}` |")
        out.append("| path | the real Internet path between them, no netem |")
    else:
        out.append("| arrangement | both tunnel ends in the `kr-cli`/`kr-srv` namespaces of one "
                   f"host, netem profile `{campaign.netem}` |")
    out.append(f"| configurations | {', '.join(f'`{c}`' for c in campaign.configs)} "
               f"({_config_note(campaign.configs)}) |")
    out.append(f"| metric families | {', '.join(f'`{m}`' for m in campaign.metrics)} |")
    out.append(f"| repetitions | {campaign.repetitions} per pair per cell, "
               "A/B interleaved (GG, RR, GR, RG, then again) |")
    out.append(f"| workload duration | {campaign.duration} s |")
    # Unconditional, and above `iperf3`: `-sockbuf` is capped by the host without a word from
    # the kernel, and a page that does not say what the cap was cannot be checked against D32.
    out.append(socket_buffer_row(campaign.configs, meta.get("states", [])))
    if meta.get("iperf3_detail"):
        out.append(f"| iperf3 | {meta['iperf3_detail']}: the host's own package, which "
                   "carries no build stamp of ours |")
    out.append(f"| started | {meta.get('started_iso', '?')} |")
    out.append(f"| finished | {meta.get('finished_iso', '?')} |")
    out.append(f"| runs harvested | {sum(len(rows) for rows in cells.values())} |")
    out.append("")
    # A cell that failed has to be on the page, not only in the terminal of whoever ran it: a
    # page with a "Not run." section and no explanation reads as a grid that was never planned.
    failures = meta.get("failures") or ()
    if failures:
        out.append("> **Cells that did not complete:** " + "; ".join(failures)
                   + ". Their sections below say `Not run.` or carry fewer runs than the rest.")
        out.append("")
    for line in build_lines(meta.get("states", [])):
        out.append(line)
    out.append("Read before quoting anything here:")
    out.append("")
    out.append("* Every cell is a **median over the repetitions of one session**, and the pairs "
               "inside a session were interleaved, so the columns share whatever the box was "
               "doing. Medians from two different sessions are not comparable, on a shared "
               "box, and on a real path, absolutely not.")
    out.append("* `RR/GG` is annotated ✓ when Rust is on the better side of Go for **that** "
               "row's direction (high is better for goodput and stream counts, low for CPU, "
               "memory, latency and retransmissions).")
    out.append("* A `·` cell is one that is deliberately not measured: step 12.1 gives the "
               "cross pairs (GR, RG) throughput only, because a CPU or RSS row for a mixed "
               "pair describes two different implementations at once.")
    out.append("* A `-` cell is **not measured**, never measured-as-zero. An `n/a` ratio is one "
               "the two cells beside it cannot support: either Go's median is zero, so the "
               "ratio is undefined rather than infinite, or both medians are segment counts "
               f"below {SEGMENT_NOISE_FLOOR:.0f} over the whole run, where a ratio would be a "
               "verdict on noise. A number in parentheses after a cell is the number of runs "
               f"behind it when that is fewer than the {MIN_REPETITIONS} the plan requires.")
    out.append("* CPU per GB divides the process's own `utime + stime` by the bytes the "
               "*workload* moved, not by the bytes that went over the wire: charging an "
               "implementation only for the goodput it delivered is what makes FEC and "
               "retransmission show up as cost rather than as credit.")
    out.append("* `RetransSegs` **decomposes**: one `flush` adds `LostSegs + FastRetransSegs + "
               "EarlyRetransSegs` into it, so all three components are printed beneath it and "
               "a `RetransSegs` row with an unexplained remainder means a counter is missing "
               "from this page rather than that some retransmission is unattributable. The "
               "three are medians of their own five runs, so they sum to the `RetransSegs` "
               "median only to within the run-to-run spread, not exactly; the per-run rows in "
               "the CSV do sum exactly.")
    for note in campaign.notes:
        out.append(f"* {note}")
    out.append("")

    for config in campaign.configs:
        out.append(f"## Configuration `{config}`: {_config_title(config)}")
        out.append("")
        out.append("```")
        out.append(_config_flags(config))
        out.append("```")
        out.append("")
        for metric_name in campaign.metrics:
            metric = METRICS[metric_name]
            samples = cells.get((config, metric_name), [])
            out.append(f"### `{metric_name}`: {metric.description}")
            out.append("")
            if not samples:
                out.append("Not run.")
                out.append("")
                continue
            out.extend(cell_table(samples, metric))
            out.append("")
            out.extend(spread_table(samples, metric))
            out.append("Produced by:")
            out.append("")
            out.append("```sh")
            out.append(meta.get("commands", {}).get(
                (config, metric_name), "# command not recorded"))
            out.append("```")
            out.append("")

    if campaign.observations:
        out.append("## Observations")
        out.append("")
        for paragraph in campaign.observations:
            out.append(paragraph)
            out.append("")

    out.append("## Raw data")
    out.append("")
    out.append(f"Every number above is a median of the rows in [`{date}-{campaign.env}.csv`]"
               f"({date}-{campaign.env}.csv): one row per configuration, metric, pair, "
               "repetition and measurement. The run directories the CSV names are under "
               "`lab-runs/` (gitignored) on the machine that ran the campaign, one `state.json`, "
               "`proc.csv`, `snmp-*.csv` and workload log per run.")
    out.append("")
    out.append("The CSV is the **complete** record and is wider than the tables: it carries the "
               "cross pairs' CPU and memory rows, which the tables deliberately do not show "
               "(see the `·` note above). They are data, not a comparison: a GR row's CPU is a "
               "Go client's and a Rust server's added together, so anything read out of them "
               "is a lead to be confirmed, never a result.")
    out.append("")
    out.append("Regenerate the page and the CSV from those directories without re-running "
               "anything:")
    out.append("")
    out.append("```sh")
    out.append(f"tools/bench/bench.py report {meta.get('runs_dir', '<campaign directory>')}")
    out.append("```")
    out.append("")
    return "\n".join(out) + "\n"


def _config_title(config: str) -> str:
    return {
        "s1": "the user's production profile",
        "s2": "kcptun's own defaults",
        "s3": "fast3 with AEAD and FEC",
        "s4": "a stream cipher without FEC",
    }.get(config, config)


def _config_note(configs: Sequence[str]) -> str:
    return ", ".join(f"{c} = {_config_title(c)}" for c in configs)


def _config_flags(config: str) -> str:
    """The flags a configuration renders to, from `lab.CONFIGS`, never a copy by hand."""
    base = lab.CONFIGS[config]
    common = " ".join(lab.render_flags(base["common"]))
    client = " ".join(lab.render_flags(base["client"]))
    server = " ".join(lab.render_flags(base["server"]))
    lines = [f"both   {common}"]
    if client:
        lines.append(f"client {client}")
    if server:
        lines.append(f"server {server}")
    return "\n".join(lines)


CSV_COLUMNS = ("config", "metric", "pair", "repetition", "runid", "started_iso",
               "measurement", "value", "unit")


def csv_value(value: float) -> str:
    """One raw value, rendered so that nothing is lost.

    The CSV is the page's evidence: every generated page says "every number above is a median of
    the rows in this file", so a value has to round-trip. An earlier version wrote
    ``f"{value:.6g}"``, which is harmless for a goodput in the hundreds and silently wrong for a
    counter: an `OutSegs` of 1 470 402 came out as ``1.47040e+06`` while the page beside it
    printed ``1,470,402``, a number its own CSV could no longer reproduce. Counters cross 1e6
    routinely on a 20-second bulk cell (`OutSegs`, `RetransSegs`, `LostSegs`, `RepeatSegs`,
    `VmHWM` in kB), so this was the common case rather than the corner one. Integers are written
    as integers; everything else gets 12 significant figures, which is finer than any instrument
    on this page resolves.
    """
    if float(value).is_integer():
        return f"{value:.0f}"
    return f"{value:.12g}"


def write_csv(path: Path, campaign: Campaign,
              cells: dict[tuple[str, str], list[Sample]]) -> int:
    """The raw long-format rows behind every median. Returns how many were written."""
    rows = 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_COLUMNS)
        for config in campaign.configs:
            for metric_name in campaign.metrics:
                for sample in cells.get((config, metric_name), []):
                    for key in METRICS[metric_name].measures:
                        if key not in sample.values:
                            continue
                        measure = MEASURES[key]
                        writer.writerow([
                            config, metric_name, sample.pair, sample.repetition,
                            sample.runid, sample.started_iso, key,
                            csv_value(sample.values[key]), measure.unit,
                        ])
                        rows += 1
    return rows


# --------------------------------------------------------------------------------------------
# Running a campaign
# --------------------------------------------------------------------------------------------


def lab_command(campaign: Campaign, host: str, scenario_path: Path,
                runs_dir: Path, extra: Sequence[str] = (),
                wait_load: int = DEFAULT_WAIT_LOAD) -> list[str]:
    """The `lab.py run` command line one cell is produced by: printed into the page verbatim."""
    argv = [
        _relative(REPO / "tools" / "lab" / "lab.py"),
        "--host", host,
        "--runs-dir", _relative(runs_dir),
        "run", _relative(scenario_path),
        "--no-report",
        # Not `--force`: the preflight exists because these boxes have one or two cores, and a
        # cell that starts while the previous one's load is still decaying measures the decay.
        # Waiting for the host to go quiet is the only version of this that produces a number.
        "--wait-load", str(wait_load),
    ]
    if campaign.mode == lab.MODE_WAN:
        argv += ["--server-host", campaign.server_host,
                 "--server-addr", campaign.server_addr]
    argv += list(extra)
    return argv


def _relative(path: Path) -> str:
    """A repository-relative path when possible, so the printed command is pasteable."""
    try:
        return str(Path(path).resolve().relative_to(REPO))
    except ValueError:
        return str(path)


#: What `host_detail` asks the machine, as ``key=value`` lines.
#:
#: Labelled rather than positional, and every key emits a line even when its command produces
#: nothing. An earlier version ran the five commands bare and parsed the output by position,
#: which breaks on any host where one of them is silent: `grep 'model name' /proc/cpuinfo` prints
#: nothing on aarch64, so every later field shifted up by one and the aarch64 page ended up with
#: the glibc version sitting in the CPU-model slot and no libc at all. With `nproc` missing
#: instead it would have printed `MemTotal` as the vCPU count. Given D07, which libc a run used
#: is load-bearing metadata and must not be able to land in the wrong slot.
HOST_DETAIL_COMMAND = (
    'echo "uname=$(uname -srm)"; '
    'echo "cpus=$(nproc 2>/dev/null)"; '
    'echo "memkb=$(awk \'/MemTotal/{print $2}\' /proc/meminfo 2>/dev/null)"; '
    'echo "model=$(grep -m1 \'model name\' /proc/cpuinfo 2>/dev/null | cut -d: -f2-)"; '
    'echo "libc=$(ldd --version 2>/dev/null | head -1)"'
)


def format_host_detail(text: str) -> str:
    """The method table's machine line, from `HOST_DETAIL_COMMAND`'s ``key=value`` output."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() in ("uname", "cpus", "memkb", "model", "libc"):
            fields[key.strip()] = value.strip()
    memory = ""
    try:
        memory = f", {int(fields.get('memkb', '')) / 1024 / 1024:.1f} GiB"
    except ValueError:
        pass
    parts = [fields.get("uname", "")]
    if fields.get("cpus"):
        parts.append(f"{fields['cpus']} vCPU")
    if fields.get("model"):
        parts.append(fields["model"])
    if fields.get("libc"):
        parts.append(fields["libc"])
    return f"{', '.join(p for p in parts if p)}{memory}"


def host_detail(host: str) -> str:
    """One line about the machine, read from it (uname and /proc), for the method table."""
    try:
        text = subprocess.run(
            ["ssh", *lab.SSH_OPTS, host, HOST_DETAIL_COMMAND],
            capture_output=True, text=True, timeout=60, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    return format_host_detail(text)


def iperf3_detail(host: str) -> str:
    """The host's `iperf3`, named and hashed.

    A step 12.0 note records this as an open gap: `lab.py` invokes `iperf3` by bare
    name, so it is whatever the distribution installed, and its version, path and hash appear in
    no `BUILD.txt`, no `state.json` and no report, while it is the instrument behind every
    goodput row. A campaign cannot give it a build stamp, but it can at least say which file it
    was, so that two pages taken months apart can be told apart when they disagree.
    """
    try:
        text = subprocess.run(
            ["ssh", *lab.SSH_OPTS, host,
             "command -v iperf3 && iperf3 --version | head -1 && sha256sum $(command -v iperf3)"],
            capture_output=True, text=True, timeout=60, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) < 2:
        return ""
    path, version = lines[0], lines[1]
    digest = lines[2].split()[0] if len(lines) > 2 else ""
    return f"{version} at `{path}`" + (f", sha256 `{digest[:16]}…`" if digest else "")


def preflight_sockbuf(campaign: Campaign, args: argparse.Namespace) -> None:
    """Refuse, before anything runs, a campaign the host's socket-buffer ceiling would invalidate.

    D32 is a rule about results ("discard, not interpret"), and a rule about results that is
    only enforced when the results are read costs a campaign. 12.1's S1 grid was 1h24m of a
    1-vCPU box's time and had to be thrown away. This is the same check `lab.py`'s
    `warn_clamped_sockbuf` prints per run, promoted to a refusal for the stock ceiling, where
    D32 says the numbers are not interpretable at all.

    A clamp at a *raised* ceiling is only warned about: it is what lab-arm64 runs under.
    """
    sides = campaign_sides(campaign, args.host)
    by_host: dict[str, set[tuple[int, int]]] = {}
    for host in sides:
        try:
            limits = lab.Runner(host).socket_buffer_limits()
        except lab.LabError:
            limits = {}
        if not limits:
            print(f"bench: ⚠ could not read net.core.rmem_max/wmem_max on {host}; the page "
                  "will say the ceiling was not recorded", file=sys.stderr)
            continue
        by_host[host] = {(int(limits.get("rmem_max", -1)), int(limits.get("wmem_max", -1)))}
    clamps = sockbuf_clamps(campaign.configs, by_host, sides)
    for clamp in clamps:
        print(f"bench: ⚠ {clamp.describe()}", file=sys.stderr)
    stock = [clamp for clamp in clamps if clamp.stock]
    if stock and not args.allow_clamped_sockbuf:
        affected = ", ".join(sorted({clamp.config for clamp in stock}))
        raise BenchError(
            f"socket-buffer ceiling: {stock[0].host} is at the stock "
            f"{stock[0].ceiling:,} B `net.core.{stock[0].sysctl}`, so {affected} would measure "
            "the host rather than the implementations. docs/DECISIONS.md D32: any such "
            "measurement is invalid and must be discarded, not interpreted: raise the ceiling "
            "(`/etc/sysctl.d/99-kcptun-lab.conf`, 8388608 / 67108864, as lab-arm64, lab-x86-1 "
            "and lab-x86-2 carry) or pass --allow-clamped-sockbuf to measure the clamp on "
            "purpose; the page it writes leads with an INVALID banner.")


def cmd_run(args: argparse.Namespace) -> int:
    campaign = load_campaign(Path(args.campaign))
    if campaign.repetitions < MIN_REPETITIONS and not args.allow_few_repetitions:
        raise BenchError(
            f"repetitions: {campaign.repetitions} is fewer than the {MIN_REPETITIONS} "
            "step 12 rule 1 requires (medians of >= 5, A/B interleaved). "
            "Pass --allow-few-repetitions for a dry shakedown; the page it writes says so in "
            "its first paragraph.")
    if campaign.mode == lab.MODE_WAN and not (campaign.server_host and campaign.server_addr):
        raise BenchError("mode wan: the campaign needs server_host and server_addr")
    if not args.dry_run:
        preflight_sockbuf(campaign, args)

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    root = Path(args.runs_dir).expanduser().resolve() / f"{stamp}-bench-{campaign.name}"
    scenarios = root / "scenarios"
    scenarios.mkdir(parents=True, exist_ok=True)

    started_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    # The command is recorded per cell **as it is about to be run**, not rebuilt later from an
    # `argparse` namespace: `report --campaign` is invoked without the original `--lab-arg` and
    # `--wait-load`, and a rebuilt line would quietly drop a `--force` that the run actually
    # carried. step 12 rule 2 asks for the exact command, and the exact command is this one.
    plan: list[dict[str, str]] = []
    for config, metric in campaign.cells:
        path = scenarios / f"{campaign.cell_name(config, metric)}.json"
        path.write_text(json.dumps(campaign.scenario(config, metric), indent=2) + "\n",
                        encoding="utf-8")
        argv = lab_command(campaign, args.host, path, root, args.lab_arg, args.wait_load)
        plan.append({"config": config, "metric": metric, "scenario": str(path),
                     "command": " ".join(argv)})

    meta = {
        "campaign": campaign.name,
        "env": campaign.env,
        "env_title": args.env_title or campaign.env,
        "host": args.host,
        "host_detail": "" if args.dry_run else host_detail(args.host),
        "iperf3_detail": "" if args.dry_run else iperf3_detail(args.host),
        "date": time.strftime("%Y-%m-%d"),
        "started_iso": started_iso,
        "runs_dir": _relative(root),
        "source": campaign.source,
        "cells": plan,
    }
    (root / "campaign.json").write_text(
        json.dumps({"campaign": dataclasses.asdict(campaign), "meta": meta}, indent=2) + "\n",
        encoding="utf-8")

    total = len(campaign.cells)
    failures: list[str] = []
    for index, (config, metric) in enumerate(campaign.cells, start=1):
        argv = lab_command(campaign, args.host, scenarios /
                           f"{campaign.cell_name(config, metric)}.json", root, args.lab_arg,
                           args.wait_load)
        runs = campaign.repetitions * len(METRICS[metric].pairs)
        print(f"bench: [{index}/{total}] {config} x {metric}, {runs} runs")
        print(f"bench:     {' '.join(argv)}", flush=True)
        if args.dry_run:
            continue
        completed = subprocess.run([sys.executable, *argv], cwd=REPO, check=False)
        if completed.returncode != 0:
            failures.append(f"{config} x {metric} (lab.py exit {completed.returncode})")
            print(f"bench: {config} x {metric} FAILED; continuing with the rest",
                  file=sys.stderr, flush=True)
            if args.stop_on_error:
                break
        if campaign.cooldown and index < total:
            print(f"bench:     cooling down {campaign.cooldown}s before the next cell",
                  flush=True)
            time.sleep(campaign.cooldown)
    if args.dry_run:
        print(f"bench: dry run, {total} cell(s) planned under {root}")
        return 0

    meta["finished_iso"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    meta["failures"] = failures
    (root / "campaign.json").write_text(
        json.dumps({"campaign": dataclasses.asdict(campaign), "meta": meta}, indent=2) + "\n",
        encoding="utf-8")
    write_outputs(campaign, root, meta, args)
    if failures:
        print("bench: cells that failed: " + "; ".join(failures), file=sys.stderr)
    return 0 if not failures or args.keep_going else 1


def session_for(root: Path, campaign: Campaign, config: str, metric: str) -> Path | None:
    """The `lab.py` session directory of one cell: ``<stamp>-<cell name>``.

    The **last** one, when a cell was run more than once into the same campaign directory (a
    failed cell re-run by hand, say). Merging them would silently mix two sessions' conditions
    into one median, which is the one thing a per-session comparison may not do.
    """
    name = campaign.cell_name(config, metric)
    matches = sorted(path for path in root.glob(f"*-{name}") if path.is_dir())
    return matches[-1] if matches else None


def write_outputs(campaign: Campaign, root: Path, meta: dict[str, Any],
                  args: argparse.Namespace) -> list[Path]:
    """Harvest every cell, then write the page and the raw CSV."""
    cells: dict[tuple[str, str], list[Sample]] = {}
    states: list[dict[str, Any]] = []
    for config, metric in campaign.cells:
        session = session_for(root, campaign, config, metric)
        if session is None:
            continue
        samples = collect_cell(session, config, metric)
        if samples:
            cells[(config, metric)] = samples
        for directory in sorted(path.parent for path in session.glob("*/state.json")):
            states.append(json.loads((directory / "state.json").read_text(encoding="utf-8")))
    meta = dict(meta)
    meta["states"] = states
    # Two things can make a page unquotable before a single table is read: an artefact that
    # cannot be named (12.0) and a socket-buffer ceiling that measured the host instead of the
    # implementations (D32). Both lead the page.
    meta["banner"] = list(lab.unprovenanced_banner(states)) + socket_buffer_banner(
        campaign.configs, states)
    # What `run` recorded when it ran the cell wins over anything rebuilt here. `report
    # --campaign` runs with a fresh namespace whose `--lab-arg` and `--wait-load` are the
    # defaults, so rebuilding is how a `--force` that the run really carried disappears from a
    # regenerated page. The rebuild is kept only for a campaign directory written before this
    # field existed, where there is nothing else to print.
    recorded = {(cell.get("config"), cell.get("metric")): cell["command"]
                for cell in meta.get("cells", []) if cell.get("command")}
    meta["commands"] = {
        (config, metric): recorded.get((config, metric)) or " ".join(lab_command(
            campaign, meta.get("host", "?"),
            root / "scenarios" / f"{campaign.cell_name(config, metric)}.json",
            root, args.lab_arg, getattr(args, "wait_load", DEFAULT_WAIT_LOAD)))
        for config, metric in campaign.cells
    }

    date = meta.get("date") or time.strftime("%Y-%m-%d")
    docs = Path(args.docs_dir).expanduser().resolve() if args.docs_dir else DOCS
    page = docs / f"{date}-{campaign.env}.md"
    raw = docs / f"{date}-{campaign.env}.csv"
    page.parent.mkdir(parents=True, exist_ok=True)
    page.write_text(report(campaign, cells, meta), encoding="utf-8")
    rows = write_csv(raw, campaign, cells)
    runs = sum(len(samples) for samples in cells.values())
    print(f"bench: {runs} run(s) harvested into {_relative(page)} "
          f"and {rows} CSV row(s) into {_relative(raw)}")
    return [page, raw]


def cmd_report(args: argparse.Namespace) -> int:
    root = Path(args.directory).expanduser().resolve()
    stored = root / "campaign.json"
    if not stored.exists():
        raise BenchError(f"{root}: no campaign.json, is this a bench campaign directory?")
    blob = json.loads(stored.read_text(encoding="utf-8"))
    as_run = parse_campaign(
        {k: v for k, v in blob["campaign"].items() if k in CAMPAIGN_FIELDS},
        source=blob["campaign"].get("source", ""))
    if args.campaign:
        # Re-read the committed campaign file, so that an `observations` or `notes` paragraph
        # written after the runs finished reaches the page. The grid itself must not have
        # changed: the cells are matched by name against the directories on disk, and a cell
        # that is no longer in the file is simply not harvested.
        campaign = load_campaign(Path(args.campaign))
        if campaign.name != as_run.name:
            raise BenchError(
                f"{args.campaign} is campaign {campaign.name!r}, but {root} holds "
                f"{as_run.name!r}")
        differences = [
            f"{field}={getattr(campaign, field)!r}, but {_relative(root)} was run with "
            f"{getattr(as_run, field)!r}"
            for field in sorted(CAMPAIGN_FIELDS - REREADABLE_FIELDS)
            if getattr(campaign, field) != getattr(as_run, field)
        ]
        if differences:
            raise BenchError(
                f"{args.campaign} no longer describes the runs it would be reported over: "
                + "; ".join(f"it says {item}" for item in differences)
                + ". Editing the grid and regenerating would print a Method table that "
                  "describes a campaign nobody ran; re-run it instead, or drop --campaign to "
                  "report the stored one.")
    else:
        campaign = as_run
    meta = dict(blob.get("meta", {}))
    if args.env_title:
        meta["env_title"] = args.env_title
    meta["runs_dir"] = _relative(root)
    write_outputs(campaign, root, meta, args)
    return 0


def cmd_scenarios(args: argparse.Namespace) -> int:
    """Print (or write) the `lab.py` scenarios a campaign expands to, without running anything."""
    campaign = load_campaign(Path(args.campaign))
    out = Path(args.out).expanduser().resolve() if args.out else None
    if out:
        out.mkdir(parents=True, exist_ok=True)
    for config, metric in campaign.cells:
        scenario = campaign.scenario(config, metric)
        text = json.dumps(scenario, indent=2) + "\n"
        if out:
            (out / f"{scenario['name']}.json").write_text(text, encoding="utf-8")
        else:
            print(f"# {scenario['name']}")
            print(text, end="")
    if out:
        print(f"bench: {len(campaign.cells)} scenario(s) written to {out}")
    return 0


def cmd_metrics(_args: argparse.Namespace) -> int:
    print("Metric families (a cell is one configuration x one family):\n")
    for name, metric in METRICS.items():
        pairs = ", ".join((lab.IMPLS[c] + lab.IMPLS[s]).upper() for c, s in metric.pairs)
        print(f"  {name:<16} {metric.description}")
        print(f"  {'':<16} pairs: {pairs}")
        print(f"  {'':<16} measures: {', '.join(metric.measures)}\n")
    print("Configurations: " + ", ".join(f"{c} ({_config_title(c)})"
                                         for c in sorted(lab.CONFIGS)))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bench.py",
        description="Step 12.1 benchmark harness: the scenario x metric grid, on top of lab.py")
    parser.add_argument("--host", default=os.environ.get("KCPTUN_LAB_HOST", lab.DEFAULT_HOST),
                        help="ssh host the client end runs on (default %(default)s)")
    parser.add_argument("--runs-dir", default=str(REPO / "lab-runs"),
                        help="where the raw runs are kept (default %(default)s)")
    parser.add_argument("--docs-dir", default=None,
                        help="where the page and CSV are written (default docs/benchmarks)")
    parser.add_argument("--env-title", default=None,
                        help="human title for the environment, used in the page heading")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run a campaign and write its page")
    run.add_argument("campaign")
    run.add_argument("--dry-run", action="store_true",
                     help="print the cells and the lab.py command lines, run nothing")
    run.add_argument("--allow-few-repetitions", action="store_true",
                     help=f"run with fewer than {MIN_REPETITIONS} repetitions; the page says so")
    run.add_argument("--allow-clamped-sockbuf", action="store_true",
                     help="run even though the host's net.core.rmem_max/wmem_max would shrink "
                          "the scenario's -sockbuf to the stock ceiling; the page says so")
    run.add_argument("--stop-on-error", action="store_true",
                     help="stop at the first cell that fails instead of running the rest")
    run.add_argument("--keep-going", action="store_true",
                     help="exit 0 even when a cell failed (the page still names the failures)")
    run.add_argument("--wait-load", type=int, default=DEFAULT_WAIT_LOAD, metavar="SECONDS",
                     help="how long each cell waits for the host to go quiet "
                          "(default %(default)s)")
    run.add_argument("--lab-arg", action="append", default=[], metavar="ARG",
                     help="extra argument passed through to every `lab.py run` "
                          "(repeatable, e.g. --lab-arg --force)")
    run.set_defaults(func=cmd_run)

    report_cmd = sub.add_parser("report",
                                help="rebuild the page and CSV from a collected campaign")
    report_cmd.add_argument("directory")
    report_cmd.add_argument("--campaign", default=None, metavar="PATH",
                            help="re-read the campaign file instead of the copy stored in the "
                                 "campaign directory, so notes and observations written after "
                                 "the runs finished reach the page")
    report_cmd.add_argument("--lab-arg", action="append", default=[], metavar="ARG",
                            help=argparse.SUPPRESS)
    report_cmd.add_argument("--wait-load", type=int, default=DEFAULT_WAIT_LOAD,
                            help=argparse.SUPPRESS)
    report_cmd.set_defaults(func=cmd_report)

    scenarios = sub.add_parser("scenarios",
                               help="expand a campaign into lab.py scenarios and stop")
    scenarios.add_argument("campaign")
    scenarios.add_argument("--out", default=None, help="write them here instead of stdout")
    scenarios.set_defaults(func=cmd_scenarios)

    sub.add_parser("metrics", help="list the metric families and configurations"
                   ).set_defaults(func=cmd_metrics)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (BenchError, lab.LabError) as exc:
        print(f"bench: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
