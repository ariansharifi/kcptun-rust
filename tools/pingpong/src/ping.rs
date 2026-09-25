//! `pingpong ping`: request/response latency through the tunnel.
//!
//! One connection (or `--conns` of them) sends `ECHO <size>` and waits for the same bytes back,
//! over and over, and the round-trip times go into a [`Histogram`]. This is the latency half of
//! the 11.2 matrix ("30 s pingpong (64 B) with and without a competing bulk flow") and the
//! latency signal of the 11.4 soak, where what matters is not the percentile of one 30-second
//! run but whether the percentiles drift over six hours.
//!
//! A broken connection is not a failure: the tunnel is *expected* to lose sessions when the
//! path is blackholed or a `-autoexpire` rotation happens. The loop counts the error, reconnects
//! and carries on, which is exactly the behaviour 11.5 wants to observe.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kcptun_pingpong::args::Args;
use kcptun_pingpong::csv::{CsvAppender, f3};
use kcptun_pingpong::hist::Histogram;
use kcptun_pingpong::net::{Client, shared_payload};
use kcptun_pingpong::proto::Request;
use kcptun_pingpong::timefmt;
use kcptun_pingpong::{Result, args::parse_size};

use crate::report::{self, Common};

const FLAGS: &[&str] = &[
    "connect",
    "size",
    "duration",
    "conns",
    "interval-ms",
    "warmup",
    "out",
    "report-interval",
    "verify",
    "tag",
    "threads",
    "seed",
];

/// Columns of the interval CSV.
const HEADER: &[&str] = &[
    "unix",
    "iso",
    "elapsed_s",
    "tag",
    "requests",
    "errors",
    "reconnects",
    "count",
    "min_us",
    "mean_us",
    "p50_us",
    "p90_us",
    "p99_us",
    "max_us",
];

/// Largest `--size` `ping` accepts.
///
/// `ECHO` is lock-step: [`net::request`] writes all N bytes and only then starts reading, while
/// the target echoes as it reads. Once the return path fills the socket buffers and the smux
/// window, the target blocks in `write_all`, stops reading, and the client blocks in `write_all`
/// too: a deadlock that `ping` (which has no per-request timeout, by design: a stalled RTT is
/// data) would show only as a run that ends with no samples. 1 MiB is comfortably under the
/// smallest in-flight window in the 11.2 matrix (S2's `streambuf 2097152`); anything larger is
/// what `bulk` is for.
const MAX_PING_SIZE: u64 = 1 << 20;

#[derive(Debug, Default)]
struct State {
    interval: Histogram,
    total: Histogram,
    requests: u64,
    errors: u64,
    reconnects: u64,
}

/// Entry point for the subcommand.
pub fn main(args: &Args) -> Result<()> {
    args.reject_unknown(FLAGS)?;
    let common = Common::from_args(args, 30)?;
    if common.duration.is_zero() {
        return Err("--duration 0 is not allowed for ping".into());
    }
    let addr = report::resolve(args.req("connect")?)?;
    let size = parse_size(args.str_or("size", "64")?)?;
    if size > MAX_PING_SIZE {
        return Err(format!(
            "--size {size} is above the {MAX_PING_SIZE}-byte limit: ECHO is lock-step, so a size \
             above the tunnel's in-flight window deadlocks: use `bulk` for large transfers"
        )
        .into());
    }
    let conns: usize = args.parsed_or("conns", 1)?;
    if conns == 0 {
        return Err("--conns must be at least 1".into());
    }
    let interval_ms: u64 = args.parsed_or("interval-ms", 0)?;
    let warmup = Duration::from_secs(args.parsed_or("warmup", 2)?);
    let verify = args.has("verify");

    crate::runtime(args)?.block_on(run(Config {
        addr,
        size,
        conns,
        pace: Duration::from_millis(interval_ms),
        warmup,
        verify,
        common,
    }))
}

struct Config {
    addr: std::net::SocketAddr,
    size: u64,
    conns: usize,
    pace: Duration,
    warmup: Duration,
    verify: bool,
    common: Common,
}

async fn run(cfg: Config) -> Result<()> {
    let addr = cfg.addr;
    let state = Arc::new(Mutex::new(State::default()));
    let payload = shared_payload(
        cfg.common.seed,
        usize::try_from(cfg.size.max(1)).unwrap_or(1 << 16),
    );
    let (stop_tx, stop_rx) = report::stop_channel();
    let started = Instant::now();

    report::say(&format!(
        "ping: {} x {} B -> {} for {}s (warmup {}s)",
        cfg.conns,
        cfg.size,
        addr,
        cfg.common.duration.as_secs(),
        cfg.warmup.as_secs()
    ));

    let mut workers = Vec::with_capacity(cfg.conns);
    for _ in 0..cfg.conns {
        workers.push(tokio::spawn(connection(
            addr,
            Request::Echo(cfg.size),
            Arc::clone(&payload),
            Arc::clone(&state),
            cfg.pace,
            cfg.warmup,
            cfg.verify,
            started,
            stop_rx.clone(),
        )));
    }

    let reporter = tokio::spawn(reporting(
        Arc::clone(&state),
        cfg.common.clone(),
        stop_rx.clone(),
        started,
    ));

    tokio::time::sleep(cfg.common.duration).await;
    stop_tx.send_replace(true);
    for worker in workers {
        let _ = worker.await;
    }
    let _ = reporter.await;

    let (summary, requests, errors, reconnects) = {
        let state = state.lock().map_err(|_| "ping state poisoned")?;
        (
            state.total.summary_us(),
            state.requests,
            state.errors,
            state.reconnects,
        )
    };
    report::print_result(
        "ping",
        &cfg.common,
        &format!(
            "\"target\":\"{}\",\"size\":{},\"conns\":{},\"elapsed_s\":{:.3},\"requests\":{},\
             \"errors\":{},\"reconnects\":{},{}",
            report::json_escape(&addr.to_string()),
            cfg.size,
            cfg.conns,
            started.elapsed().as_secs_f64(),
            requests,
            errors,
            reconnects,
            summary.json_fields("rtt_"),
        ),
    );
    Ok(())
}

/// One connection's request loop: connect, echo until told to stop, reconnect on error.
// Nine parameters, all of them plain values this loop needs; bundling them into a struct would
// only move the list somewhere else.
#[allow(clippy::too_many_arguments)]
async fn connection(
    addr: std::net::SocketAddr,
    request: Request,
    payload: Arc<Vec<u8>>,
    state: Arc<Mutex<State>>,
    pace: Duration,
    warmup: Duration,
    verify: bool,
    started: Instant,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let scratch = usize::try_from(request.payload_in())
        .unwrap_or(1 << 16)
        .clamp(4096, 1 << 16);
    let mut client: Option<Client> = None;
    while !report::is_stopped(&stop) {
        if client.is_none() {
            // A bare `connect().await` here would park this task for the kernel's own connect
            // timeout when the path is blackholed (11.5), and `run`'s `worker.await` would wait
            // for it long after the stop flag was set. A timeout counts as a connect error.
            let dialed = report::bounded(
                report::CONNECT_TIMEOUT,
                Client::connect(addr, Arc::clone(&payload), scratch),
                &mut stop,
            )
            .await;
            match dialed {
                report::Bounded::Stopped => return,
                report::Bounded::Done(Ok(fresh)) => client = Some(fresh),
                report::Bounded::Done(Err(_)) | report::Bounded::TimedOut => {
                    if let Ok(mut state) = state.lock() {
                        state.errors += 1;
                    }
                    if !report::sleep_or_stop(Duration::from_millis(250), &mut stop).await {
                        return;
                    }
                    continue;
                }
            }
        }
        let Some(active) = client.as_mut() else {
            continue;
        };
        let result = tokio::select! {
            r = active.request(request, verify) => r,
            () = report::wait_stop(&mut stop) => return,
        };
        match result {
            Ok(rtt) => {
                if let Ok(mut state) = state.lock() {
                    state.requests += 1;
                    if started.elapsed() >= warmup {
                        let ns = u64::try_from(rtt.as_nanos()).unwrap_or(u64::MAX);
                        state.interval.record(ns);
                        state.total.record(ns);
                    }
                }
            }
            Err(_) => {
                if let Ok(mut state) = state.lock() {
                    state.errors += 1;
                    state.reconnects += 1;
                }
                client = None;
                if !report::sleep_or_stop(Duration::from_millis(250), &mut stop).await {
                    return;
                }
                continue;
            }
        }
        if !pace.is_zero() && !report::sleep_or_stop(pace, &mut stop).await {
            return;
        }
    }
}

/// Appends one CSV row and prints one line per interval.
async fn reporting(
    state: Arc<Mutex<State>>,
    common: Common,
    mut stop: tokio::sync::watch::Receiver<bool>,
    started: Instant,
) {
    let mut csv = match common.out.as_ref() {
        None => None,
        Some(path) => match CsvAppender::open(path, HEADER) {
            Ok(csv) => Some(csv),
            Err(err) => {
                report::say(&format!("ping: cannot write {}: {err}", path.display()));
                None
            }
        },
    };
    let mut ticker = tokio::time::interval(common.report_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;
    loop {
        let last = tokio::select! {
            _ = ticker.tick() => false,
            () = report::wait_stop(&mut stop) => true,
        };
        let Ok(mut locked) = state.lock() else { return };
        let summary = locked.interval.summary_us();
        locked.interval.reset();
        let (requests, errors, reconnects) = (locked.requests, locked.errors, locked.reconnects);
        drop(locked);

        let now = timefmt::unix_now();
        report::say(&format!(
            "ping: t={:.0}s n={} p50={:.0}us p90={:.0}us p99={:.0}us max={:.0}us errors={}",
            started.elapsed().as_secs_f64(),
            summary.count,
            summary.p50,
            summary.p90,
            summary.p99,
            summary.max,
            errors
        ));
        if let Some(csv) = csv.as_mut() {
            let row = vec![
                now.to_string(),
                timefmt::iso8601_utc(now),
                f3(started.elapsed().as_secs_f64()),
                common.tag.clone(),
                requests.to_string(),
                errors.to_string(),
                reconnects.to_string(),
                summary.count.to_string(),
                f3(summary.min),
                f3(summary.mean),
                f3(summary.p50),
                f3(summary.p90),
                f3(summary.p99),
                f3(summary.max),
            ];
            if let Err(err) = csv.row(&row) {
                report::say(&format!("ping: csv write failed: {err}"));
            }
        }
        if last {
            return;
        }
    }
}
