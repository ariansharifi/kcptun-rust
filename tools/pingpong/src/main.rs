//! `pingpong` — the workload driver for the Step 11 network lab.
//!
//! It runs on the lab host, on both sides of the tunnel:
//!
//! ```text
//!  ns kr-cli                                     ns kr-srv
//!  pingpong ping|bulk|churn  --TCP-->  kcptun client ==UDP==> kcptun server --TCP--> pingpong serve
//!           --connect 127.0.0.1:12948                                  -t 127.0.0.1:22600
//! ```
//!
//! `iperf3` covers plain bulk goodput with its own JSON report; this tool covers what iperf3
//! cannot: request/response latency percentiles through the tunnel, and the stream **churn**
//! the 11.4 soak needs (open and close ~20 streams a second for six hours, alongside long-lived
//! streams and periodic bursts). Every mode is bounded by `--duration`, writes an append-only
//! CSV as it goes, and ends with a single `RESULT {json}` line that `tools/lab/lab.py` parses
//! out of the log.
//!
//! Development-only: this binary is never part of a release. It is deployed to the lab host as
//! `kr-pingpong`, which is what `lab-start.sh`'s `kr-*` allow-list requires.

mod bulk;
mod churn;
mod ping;
mod report;
mod serve;

use std::process::ExitCode;

use kcptun_pingpong::Result;
use kcptun_pingpong::args::Args;

/// Flags that stand alone; everything else takes a value.
const BOOL_FLAGS: &[&str] = &["verify", "help"];

const USAGE: &str = "\
pingpong — lab workload driver (development only)

usage:
  pingpong serve  --listen ADDR [--duration S] [--report-interval S] [--threads N] [--seed N]
  pingpong ping   --connect ADDR [--size N] [--duration S] [--conns N] [--interval-ms N]
                  [--warmup S] [--out CSV] [--report-interval S] [--verify] [--tag NAME]
  pingpong bulk   --connect ADDR [--bytes N] [--streams N] [--direction up|down|both]
                  [--duration S] [--out CSV] [--tag NAME]
  pingpong churn  --connect ADDR [--rate R] [--min-bytes N] [--max-bytes N]
                  [--size-dist log|uniform] [--direction up|down|both] [--max-inflight N]
                  [--long-lived N] [--long-lived-bytes N] [--long-lived-interval S]
                  [--burst-every S] [--burst-streams N] [--burst-bytes N]
                  [--duration S] [--out CSV] [--report-interval S] [--verify] [--tag NAME]

Sizes accept k/m/g suffixes (`--max-bytes 1m`). `--duration 0` means \"until killed\", which
only `serve` should ever be given. Every run prints one `RESULT {…}` line when it finishes.

`ping --size` is capped at 1 MiB: ECHO is lock-step, so a request larger than the tunnel's
in-flight window deadlocks both ends — use `bulk` for large transfers.
";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match run(argv) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("pingpong: {err}");
            ExitCode::from(1)
        }
    }
}

fn run(argv: Vec<String>) -> Result<()> {
    let args = Args::parse(argv, BOOL_FLAGS)?;
    if args.has("help") || args.command == "help" || args.command.is_empty() {
        print!("{USAGE}");
        return Ok(());
    }
    match args.command.as_str() {
        "serve" => serve::main(&args),
        "ping" => ping::main(&args),
        "bulk" => bulk::main(&args),
        "churn" => churn::main(&args),
        other => Err(format!("unknown subcommand {other:?}\n\n{USAGE}").into()),
    }
}

/// Builds the runtime every mode runs on.
///
/// The lab host has two cores and they belong to the tunnel under test, not to the load
/// generator: the default of two worker threads is deliberate, and `--threads` exists so a run
/// that turns out to be driver-bound can be re-run with more and the difference seen.
fn runtime(args: &Args) -> Result<tokio::runtime::Runtime> {
    let threads: usize = args.parsed_or("threads", 2)?;
    if threads == 0 {
        return Err("--threads must be at least 1".into());
    }
    Ok(tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()?)
}
