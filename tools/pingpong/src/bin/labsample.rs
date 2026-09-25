//! `labsample` — periodic `/proc` sampling of the processes under test.
//!
//! Plan 11.4 asks for a sample every 60 s of *RSS, CPU%, fd count, session count and SNMP
//! deltas*. The last two come from the tunnel binaries themselves (`-snmplog` writes a CSV whose
//! `CurrEstab` column is the live session count), so this tool covers the first three plus the
//! things that make a six-hour run interpretable: `VmHWM` (the peak RSS a Rust process never
//! gives back — see `docs/benchmarks/memory.md`), thread count, context switches, page faults
//! and the host's load average.
//!
//! It runs **outside** the network namespaces, as the same user as the processes it watches, and
//! it never signals, kills or otherwise touches them: it only reads `/proc`.
//!
//! Why a Rust binary rather than a shell or python loop on the host:
//!
//! - `lab-stop.sh` verifies `/proc/<pid>/exe` against the recorded command before killing
//!   anything, and an interpreter breaks that check (`/usr/bin/python3` records, `python3.12`
//!   runs — the trap found in 12.3a). A compiled binary deployed as `kr-labsample` records and
//!   runs as exactly the same path.
//! - The sampler must not itself leak over six hours: every file is opened and closed inside one
//!   sample, the CSV is appended and flushed per row, and log watching reads a bounded amount.
//!
//! Linux only, by nature. Everything it parses is unit-tested on any platform
//! (`kcptun_pingpong::proc`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use kcptun_pingpong::args::{Args, parse_size};
use kcptun_pingpong::csv::{CsvAppender, f3};
use kcptun_pingpong::proc::{self, Stat, Status};
use kcptun_pingpong::{Result, timefmt};

const BOOL_FLAGS: &[&str] = &["help"];

const FLAGS: &[&str] = &[
    "out",
    "interval",
    "duration",
    "pid",
    "log",
    "log-cap-bytes",
    "clock-ticks",
    "tag",
    "help",
];

const USAGE: &str = "\
labsample — /proc sampler for the network lab (development only)

usage:
  labsample --out proc.csv --pid LABEL=PID [--pid LABEL=PID...] [--log LABEL=PATH...]
            [--interval S] [--duration S] [--log-cap-bytes N] [--clock-ticks N] [--tag NAME]

One CSV row per watched process per interval, appended and flushed as it goes, so a dropped ssh
session or a reboot costs at most the row in flight. A process that has exited is still sampled
(state `X`) until every watched process is gone.
";

/// Columns of the sample CSV.
const HEADER: &[&str] = &[
    "unix",
    "iso",
    "elapsed_s",
    "tag",
    "label",
    "pid",
    "state",
    "rss_kb",
    "hwm_kb",
    "rss_anon_kb",
    "rss_file_kb",
    "vmsize_kb",
    "threads",
    "fds",
    "utime_ticks",
    "stime_ticks",
    "cpu_ticks",
    "cpu_pct",
    "minflt",
    "majflt",
    "vol_ctxt",
    "nonvol_ctxt",
    "load1",
    "log_bytes",
    "log_truncations",
];

/// What is known about one watched process between samples.
#[derive(Debug, Default, Clone)]
struct Previous {
    cpu_ticks: u64,
    at: Option<Instant>,
}

/// One watched log file.
#[derive(Debug)]
struct Watched {
    path: PathBuf,
    truncations: u64,
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match run(argv) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("labsample: {err}");
            ExitCode::from(1)
        }
    }
}

fn run(argv: Vec<String>) -> Result<()> {
    let args = Args::parse(argv, BOOL_FLAGS)?;
    if args.has("help") || args.command == "help" {
        print!("{USAGE}");
        return Ok(());
    }
    args.reject_unknown(FLAGS)?;

    let out = PathBuf::from(args.req("out")?);
    let interval = Duration::from_secs(args.parsed_or("interval", 60u64)?.max(1));
    let duration = Duration::from_secs(args.parsed_or("duration", 3600u64)?);
    let tag = args.str_or("tag", "")?.to_string();
    let clock_ticks: f64 = args.parsed_or("clock-ticks", 100.0)?;
    if !(clock_ticks.is_finite() && clock_ticks > 0.0) {
        return Err("--clock-ticks must be a positive number".into());
    }
    let log_cap = match args.opt("log-cap-bytes")? {
        None => 0,
        Some(raw) => parse_size(raw)?,
    };

    let mut pids: Vec<(String, i64)> = Vec::new();
    for (label, value) in args.pairs("pid")? {
        let pid: i64 = value
            .parse()
            .map_err(|e| format!("--pid {label}={value}: {e}"))?;
        if pid <= 0 {
            return Err(format!("--pid {label}={value}: not a pid").into());
        }
        pids.push((label, pid));
    }
    if pids.is_empty() {
        return Err("at least one --pid LABEL=PID is required".into());
    }

    let mut logs: BTreeMap<String, Watched> = BTreeMap::new();
    for (label, path) in args.pairs("log")? {
        logs.insert(
            label,
            Watched {
                path: PathBuf::from(path),
                truncations: 0,
            },
        );
    }

    sample_loop(Config {
        out,
        interval,
        duration,
        tag,
        clock_ticks,
        log_cap,
        pids,
        logs,
    })
}

struct Config {
    out: PathBuf,
    interval: Duration,
    duration: Duration,
    tag: String,
    clock_ticks: f64,
    log_cap: u64,
    pids: Vec<(String, i64)>,
    logs: BTreeMap<String, Watched>,
}

fn sample_loop(mut cfg: Config) -> Result<()> {
    let mut csv = CsvAppender::open(&cfg.out, HEADER)?;
    let started = Instant::now();
    let deadline = (!cfg.duration.is_zero()).then(|| started + cfg.duration);
    let mut previous: BTreeMap<String, Previous> = BTreeMap::new();
    let mut gone_rounds = 0u32;

    say(&format!(
        "labsample: watching {} process(es) every {}s for {}s -> {}",
        cfg.pids.len(),
        cfg.interval.as_secs(),
        cfg.duration.as_secs(),
        cfg.out.display()
    ));

    loop {
        let now_instant = Instant::now();
        let unix = timefmt::unix_now();
        let load1 = read_to_string("/proc/loadavg")
            .as_deref()
            .and_then(proc::parse_loadavg)
            .map(|(one, _, _)| one);

        let mut alive = 0usize;
        for (label, pid) in &cfg.pids {
            let sample = read_process(*pid);
            let running = sample.is_some();
            if running {
                alive += 1;
            }
            let (mut stat, status, fds) = sample.unwrap_or_default();
            if !running {
                // `X` is what `ps` calls a dead process; the row is kept so the CSV shows
                // exactly when the process went away rather than simply ending.
                stat.state = 'X';
            }
            let entry = previous.entry(label.clone()).or_default();
            let cpu_ticks = stat.cpu_ticks();
            let cpu_pct = match (entry.at, cpu_ticks >= entry.cpu_ticks) {
                (Some(at), true) => {
                    let seconds = now_instant.duration_since(at).as_secs_f64();
                    if seconds > 0.0 {
                        Some(
                            (cpu_ticks - entry.cpu_ticks) as f64 / cfg.clock_ticks / seconds
                                * 100.0,
                        )
                    } else {
                        None
                    }
                }
                // The first sample has nothing to diff against, and a counter that fell means
                // the pid was reused — either way there is no rate to report.
                _ => None,
            };
            entry.cpu_ticks = cpu_ticks;
            entry.at = Some(now_instant);

            let watched = cfg.logs.get_mut(label);
            let (log_bytes, truncations) = match watched {
                None => (None, 0),
                Some(watched) => {
                    let size = watch_log(watched, cfg.log_cap);
                    (size, watched.truncations)
                }
            };

            let row = vec![
                unix.to_string(),
                timefmt::iso8601_utc(unix),
                f3(started.elapsed().as_secs_f64()),
                cfg.tag.clone(),
                label.clone(),
                pid.to_string(),
                stat.state.to_string(),
                status.vm_rss_kb.to_string(),
                status.vm_hwm_kb.to_string(),
                status.rss_anon_kb.to_string(),
                status.rss_file_kb.to_string(),
                status.vm_size_kb.to_string(),
                status.threads.to_string(),
                fds.map_or_else(String::new, |n| n.to_string()),
                stat.utime.to_string(),
                stat.stime.to_string(),
                cpu_ticks.to_string(),
                cpu_pct.map_or_else(String::new, f3),
                stat.minflt.to_string(),
                stat.majflt.to_string(),
                status.voluntary_ctxt_switches.to_string(),
                status.nonvoluntary_ctxt_switches.to_string(),
                load1.map_or_else(String::new, f3),
                log_bytes.map_or_else(String::new, |n| n.to_string()),
                truncations.to_string(),
            ];
            csv.row(&row)?;
        }

        if alive == 0 {
            gone_rounds += 1;
            // Two consecutive empty rounds: everything we watch has exited, and the timeline
            // already records when. Staying alive would only leave a process behind.
            if gone_rounds >= 2 {
                say("labsample: every watched process has exited");
                break;
            }
        } else {
            gone_rounds = 0;
        }

        if let Some(at) = deadline
            && Instant::now() + cfg.interval > at
        {
            break;
        }
        std::thread::sleep(cfg.interval);
    }
    say(&format!(
        "labsample: finished, rows in {}",
        cfg.out.display()
    ));
    Ok(())
}

/// Reads one process's `/proc` entries; `None` when it is gone.
fn read_process(pid: i64) -> Option<(Stat, Status, Option<usize>)> {
    let stat = proc::parse_stat(&read_to_string(&format!("/proc/{pid}/stat"))?)?;
    let status = read_to_string(&format!("/proc/{pid}/status"))
        .as_deref()
        .map(proc::parse_status)
        .unwrap_or_default();
    Some((stat, status, count_fds(pid)))
}

/// Counts open file descriptors. `None` when the directory cannot be read (a different user, or
/// the process exited between the two reads) — an empty cell, never a misleading zero.
fn count_fds(pid: i64) -> Option<usize> {
    let mut n = 0usize;
    for entry in std::fs::read_dir(format!("/proc/{pid}/fd")).ok()? {
        // A descriptor closed mid-walk is normal; only a hard error ends the count.
        match entry {
            Ok(_) => n += 1,
            Err(_) => continue,
        }
    }
    Some(n)
}

/// Returns a watched log's size, truncating it when it is past the cap.
///
/// The tunnel binaries log per stream unless `-quiet` is set, and 20 streams/s for six hours is
/// hundreds of megabytes. `--log-cap-bytes` is the guard: the file is truncated in place and the
/// CSV records that it happened, so a run can never fill the lab host's disk and a reader of the
/// results can always see whether anything was lost.
///
/// This only works because the writer holds the file with `O_APPEND` (`lab-start.sh` opens every
/// process log with `>>`). A writer without it keeps its own file offset across our `set_len(0)`
/// and re-extends the file to `offset + n` on its next write, leaving a hole of NUL bytes in
/// front — the size never falls below the cap, so the truncation fires again every interval and
/// the log's head becomes unreadable.
fn watch_log(watched: &mut Watched, cap: u64) -> Option<u64> {
    let size = std::fs::metadata(&watched.path).ok()?.len();
    if cap > 0 && size > cap {
        match std::fs::OpenOptions::new().write(true).open(&watched.path) {
            Ok(file) => {
                if file.set_len(0).is_ok() {
                    watched.truncations += 1;
                    say(&format!(
                        "labsample: truncated {} at {size} bytes (cap {cap})",
                        watched.path.display()
                    ));
                    return Some(0);
                }
            }
            Err(err) => say(&format!(
                "labsample: cannot truncate {}: {err}",
                watched.path.display()
            )),
        }
    }
    Some(size)
}

/// Reads a file, or `None` if it cannot be read (the usual case: the process is gone).
fn read_to_string(path: &str) -> Option<String> {
    std::fs::read_to_string(Path::new(path)).ok()
}

/// A timestamped progress line.
fn say(message: &str) {
    println!("{} {message}", timefmt::iso8601_utc(timefmt::unix_now()));
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn a_sampler_needs_at_least_one_pid() {
        let err = run(argv("--out /dev/null")).expect_err("must fail");
        assert!(err.to_string().contains("--pid"), "{err}");
    }

    #[test]
    fn pids_must_be_positive_numbers() {
        assert!(run(argv("--out /dev/null --pid cli=0")).is_err());
        assert!(run(argv("--out /dev/null --pid cli=-1")).is_err());
        assert!(run(argv("--out /dev/null --pid cli=abc")).is_err());
        assert!(run(argv("--out /dev/null --pid cli")).is_err());
    }

    #[test]
    fn unknown_flags_and_bad_clock_ticks_are_refused() {
        assert!(run(argv("--out x --pid a=1 --nope 1")).is_err());
        assert!(run(argv("--out x --pid a=1 --clock-ticks 0")).is_err());
    }

    #[test]
    fn help_is_free_of_side_effects() {
        run(argv("--help")).expect("help");
    }

    #[test]
    fn a_log_is_truncated_only_once_it_passes_the_cap() {
        let dir = std::env::temp_dir().join(format!("kr-labsample-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("watched.log");
        std::fs::write(&path, vec![b'x'; 1000]).expect("write");
        let mut watched = Watched {
            path: path.clone(),
            truncations: 0,
        };

        assert_eq!(
            watch_log(&mut watched, 0),
            Some(1000),
            "cap 0 never truncates"
        );
        assert_eq!(watch_log(&mut watched, 4096), Some(1000), "under the cap");
        assert_eq!(watched.truncations, 0);
        assert_eq!(watch_log(&mut watched, 500), Some(0), "over the cap");
        assert_eq!(watched.truncations, 1);
        assert_eq!(std::fs::metadata(&path).expect("stat").len(), 0);

        let mut missing = Watched {
            path: dir.join("nothing.log"),
            truncations: 0,
        };
        assert_eq!(watch_log(&mut missing, 10), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_sampler_can_read_its_own_process() {
        let pid = i64::from(std::process::id());
        let (stat, status, fds) = read_process(pid).expect("own process");
        assert!(stat.num_threads >= 1);
        assert!(status.vm_rss_kb > 0);
        assert!(fds.unwrap_or(0) >= 3, "stdin, stdout and stderr at least");
        assert_eq!(read_process(i64::MAX), None, "no such pid");
    }
}
