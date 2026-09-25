//! Flags, stop signalling and result reporting shared by the workload modes.

use std::future::Future;
use std::io::Write as _;
use std::net::{SocketAddr, ToSocketAddrs as _};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use kcptun_pingpong::Result;
use kcptun_pingpong::args::{Args, parse_size};
use kcptun_pingpong::timefmt;
use tokio::sync::watch;

/// The flags every mode understands.
#[derive(Debug, Clone)]
pub struct Common {
    /// A label for the `RESULT` line and the CSV, so a scenario with several workloads can tell
    /// them apart.
    pub tag: String,
    /// How long to run. `Duration::ZERO` means "until killed".
    pub duration: Duration,
    /// How often an interval row is appended to the CSV.
    pub report_interval: Duration,
    /// Where the interval rows go.
    pub out: Option<PathBuf>,
    /// Seed for payloads and workload choices.
    pub seed: u64,
}

impl Common {
    /// Reads the shared flags.
    pub fn from_args(args: &Args, default_duration: u64) -> Result<Self> {
        let duration: u64 = args.parsed_or("duration", default_duration)?;
        let report_interval: u64 = args.parsed_or("report-interval", 60)?;
        if report_interval == 0 {
            return Err("--report-interval must be at least 1".into());
        }
        let seed = match args.opt("seed")? {
            Some(raw) => raw
                .parse()
                .map_err(|e| format!("--seed: bad value {raw:?}: {e}"))?,
            None => kcptun_pingpong::rng::SplitMix64::from_clock().next_u64(),
        };
        Ok(Self {
            tag: args.str_or("tag", "")?.to_string(),
            duration: Duration::from_secs(duration),
            report_interval: Duration::from_secs(report_interval),
            out: args.opt("out")?.map(PathBuf::from),
            seed,
        })
    }

    /// When the run should stop, or `None` when it runs until killed.
    pub fn deadline(&self, from: Instant) -> Option<Instant> {
        if self.duration.is_zero() {
            None
        } else {
            Some(from + self.duration)
        }
    }
}

/// Resolves `host:port`, refusing anything that does not name exactly one usable address.
pub fn resolve(addr: &str) -> Result<SocketAddr> {
    addr.to_socket_addrs()
        .map_err(|e| format!("--connect {addr:?}: {e}"))?
        .next()
        .ok_or_else(|| format!("--connect {addr:?}: resolved to no address").into())
}

/// Reads a size flag with its `k`/`m`/`g` suffix.
pub fn size_flag(args: &Args, name: &str, default: u64) -> Result<u64> {
    match args.opt(name)? {
        None => Ok(default),
        Some(raw) => Ok(parse_size(raw).map_err(|e| format!("--{name}: {e}"))?),
    }
}

/// The direction a transfer runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Client to server (`UP`).
    Up,
    /// Server to client (`DN`).
    Down,
    /// Alternating, starting with `UP`.
    Both,
}

impl Direction {
    /// Parses the `--direction` flag.
    pub fn from_args(args: &Args, default: Direction) -> Result<Self> {
        match args.opt("direction")? {
            None => Ok(default),
            Some("up") => Ok(Direction::Up),
            Some("down") => Ok(Direction::Down),
            Some("both") => Ok(Direction::Both),
            Some(other) => Err(format!("--direction {other:?}: want up, down or both").into()),
        }
    }

    /// The direction the `n`-th transfer of this run uses.
    pub fn nth(&self, n: u64) -> Direction {
        match self {
            Direction::Both if n.is_multiple_of(2) => Direction::Up,
            Direction::Both => Direction::Down,
            other => *other,
        }
    }

    /// The name used in CSV and JSON output.
    pub fn name(&self) -> &'static str {
        match self {
            Direction::Up => "up",
            Direction::Down => "down",
            Direction::Both => "both",
        }
    }
}

/// A stop flag shared by every task of a run.
pub fn stop_channel() -> (watch::Sender<bool>, watch::Receiver<bool>) {
    watch::channel(false)
}

/// Resolves once the run has been told to stop.
pub async fn wait_stop(rx: &mut watch::Receiver<bool>) {
    loop {
        let stopped = *rx.borrow_and_update();
        if stopped {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// True once the run has been told to stop.
pub fn is_stopped(rx: &watch::Receiver<bool>) -> bool {
    *rx.borrow()
}

/// Sleeps, unless the run is stopped first. Returns false when it was stopped.
///
/// Every backoff and pacing sleep in the workloads goes through this, so a run always ends
/// within its own grace period instead of within its longest sleep.
pub async fn sleep_or_stop(how_long: Duration, stop: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(how_long) => true,
        () = wait_stop(stop) => false,
    }
}

/// How long a dial may take before it is abandoned, where the mode has no flag of its own.
///
/// The dial target is always the kcptun client's own listener on loopback, which accepts or
/// refuses at once, so this never fires in a healthy run. It matters when 11.5 blackholes the
/// path or restarts a peer: the kernel's own connect timeout is minutes, far longer than the
/// slack `lab.py` allows a workload to finish in, and a task parked in `connect` would hold up
/// the whole mode's `RESULT` line.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// What became of a piece of work run under [`bounded`].
#[derive(Debug, PartialEq, Eq)]
pub enum Bounded<T> {
    /// The work finished on its own.
    Done(T),
    /// The work ran past its limit and was dropped.
    TimedOut,
    /// The run was stopped while the work was still in flight; the caller returns.
    Stopped,
}

/// Runs `work` with a time limit, abandoning it as soon as the run is stopped.
///
/// Every dial and every request goes through this. Without it a worker parked in `connect` keeps
/// its mode's `run` blocked in `worker.await` long after the stop flag was set, and the run ends
/// on `lab.py`'s patience instead of on its own grace period.
pub async fn bounded<T>(
    limit: Duration,
    work: impl Future<Output = T>,
    stop: &mut watch::Receiver<bool>,
) -> Bounded<T> {
    tokio::select! {
        outcome = tokio::time::timeout(limit, work) => match outcome {
            Ok(value) => Bounded::Done(value),
            Err(_) => Bounded::TimedOut,
        },
        () = wait_stop(stop) => Bounded::Stopped,
    }
}

/// Prints the single machine-readable line `lab.py` looks for.
///
/// One line, on stdout, prefixed so that it is found in a log that also holds warnings. The
/// fields are already-encoded JSON pairs; `kind` and `tag` are added here.
pub fn print_result(kind: &str, common: &Common, fields: &str) {
    let line = format!(
        "RESULT {{\"kind\":\"{}\",\"tag\":\"{}\",\"unix\":{},\"iso\":\"{}\",{fields}}}",
        json_escape(kind),
        json_escape(&common.tag),
        timefmt::unix_now(),
        timefmt::iso8601_utc(timefmt::unix_now()),
    );
    println!("{line}");
    let _ = std::io::stdout().flush();
}

/// Escapes a string for a JSON literal.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Bits per second from a byte count and an elapsed time.
pub fn mbit_per_s(bytes: u64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        return 0.0;
    }
    (bytes as f64 * 8.0) / secs / 1e6
}

/// Prints a progress line, always with a timestamp so a six-hour log can be read.
pub fn say(message: &str) {
    println!("{} {message}", timefmt::iso8601_utc(timefmt::unix_now()));
    let _ = std::io::stdout().flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Args {
        Args::parse(s.split_whitespace().map(str::to_string), &["verify"]).expect("parses")
    }

    #[test]
    fn common_flags_have_sane_defaults_and_a_stable_seed() {
        let a = args("ping --tag bulk-up --duration 30 --seed 7");
        let c = Common::from_args(&a, 10).expect("common");
        assert_eq!(c.tag, "bulk-up");
        assert_eq!(c.duration, Duration::from_secs(30));
        assert_eq!(c.report_interval, Duration::from_secs(60));
        assert_eq!(c.seed, 7);
        assert!(c.out.is_none());
        let now = Instant::now();
        assert_eq!(c.deadline(now), Some(now + Duration::from_secs(30)));
    }

    #[test]
    fn a_zero_duration_means_until_killed() {
        let c = Common::from_args(&args("serve --duration 0"), 3600).expect("common");
        assert!(c.duration.is_zero());
        assert_eq!(c.deadline(Instant::now()), None);
    }

    #[test]
    fn a_zero_report_interval_is_refused() {
        assert!(Common::from_args(&args("ping --report-interval 0"), 10).is_err());
    }

    #[test]
    fn directions_alternate_only_for_both() {
        let both = Direction::from_args(&args("churn --direction both"), Direction::Up)
            .expect("direction");
        assert_eq!(both.nth(0), Direction::Up);
        assert_eq!(both.nth(1), Direction::Down);
        assert_eq!(both.nth(2), Direction::Up);
        let up = Direction::from_args(&args("churn"), Direction::Up).expect("direction");
        assert_eq!(up.nth(1), Direction::Up);
        assert!(Direction::from_args(&args("churn --direction sideways"), Direction::Up).is_err());
    }

    #[test]
    fn sizes_come_through_the_suffix_parser() {
        let a = args("churn --max-bytes 1m");
        assert_eq!(size_flag(&a, "max-bytes", 0).expect("size"), 1024 * 1024);
        assert_eq!(size_flag(&a, "min-bytes", 4096).expect("size"), 4096);
        assert!(size_flag(&args("churn --max-bytes huge"), "max-bytes", 0).is_err());
    }

    #[test]
    fn json_strings_are_escaped() {
        assert_eq!(json_escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
        assert_eq!(json_escape("bell\u{7}"), "bell\\u0007");
    }

    #[test]
    fn goodput_is_megabits_per_second() {
        assert_eq!(mbit_per_s(1_000_000, Duration::from_secs(1)), 8.0);
        assert_eq!(mbit_per_s(1_000_000, Duration::ZERO), 0.0);
    }

    #[tokio::test]
    async fn the_stop_flag_releases_every_waiter() {
        let (tx, rx) = stop_channel();
        let mut a = rx.clone();
        let mut b = rx;
        assert!(!is_stopped(&a));
        let joined = tokio::spawn(async move { wait_stop(&mut a).await });
        tx.send_replace(true);
        joined.await.expect("task");
        wait_stop(&mut b).await;
        assert!(is_stopped(&b));
    }

    #[tokio::test(start_paused = true)]
    async fn sleep_or_stop_returns_false_when_the_run_ends_first() {
        let (tx, mut rx) = stop_channel();
        let waiter =
            tokio::spawn(async move { sleep_or_stop(Duration::from_secs(3600), &mut rx).await });
        tokio::time::sleep(Duration::from_millis(10)).await;
        tx.send_replace(true);
        assert!(!waiter.await.expect("task"), "the stop flag must win");

        let (_tx, mut rx2) = stop_channel();
        assert!(sleep_or_stop(Duration::from_millis(1), &mut rx2).await);
    }

    #[tokio::test(start_paused = true)]
    async fn bounded_work_yields_to_the_stop_flag_and_to_its_own_limit() {
        // A dial that never completes: the shape of `connect` to a blackholed path. The stop
        // flag has to win, or the worker outlives the run.
        let (tx, mut rx) = stop_channel();
        let waiter = tokio::spawn(async move {
            bounded(
                Duration::from_secs(3600),
                std::future::pending::<u8>(),
                &mut rx,
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        tx.send_replace(true);
        assert_eq!(waiter.await.expect("task"), Bounded::Stopped);

        // With the run still going, the limit is what ends it.
        let (_tx, mut rx2) = stop_channel();
        assert_eq!(
            bounded(
                Duration::from_secs(30),
                std::future::pending::<u8>(),
                &mut rx2
            )
            .await,
            Bounded::TimedOut
        );

        // Work that finishes in time comes back untouched.
        let (_tx, mut rx3) = stop_channel();
        assert_eq!(
            bounded(Duration::from_secs(30), async { 7u8 }, &mut rx3).await,
            Bounded::Done(7)
        );
    }

    #[tokio::test]
    async fn waiting_on_a_dropped_sender_returns_rather_than_hanging() {
        let (tx, mut rx) = stop_channel();
        drop(tx);
        wait_stop(&mut rx).await;
    }
}
