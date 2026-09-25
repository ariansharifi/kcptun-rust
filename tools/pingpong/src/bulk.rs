//! `pingpong bulk` — a bulk flow through the tunnel, without iperf3.
//!
//! `iperf3` remains the authority on goodput (11.2 quotes its JSON), but it cannot share the
//! tunnel with this tool: a kcptun server forwards to exactly one `-t` target, so a scenario
//! whose target is `pingpong serve` needs its own way to make a competing bulk flow. That is
//! what this mode is for — "30 s pingpong (64 B) **with** a competing bulk flow" in 11.2, and
//! the periodic bursts of the 11.4 soak.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kcptun_pingpong::Result;
use kcptun_pingpong::args::Args;
use kcptun_pingpong::csv::{CsvAppender, f3};
use kcptun_pingpong::hist::Histogram;
use kcptun_pingpong::net::{CHUNK, Client, shared_payload};
use kcptun_pingpong::proto::Request;
use kcptun_pingpong::timefmt;

use crate::report::{self, Common, Direction};

const FLAGS: &[&str] = &[
    "connect",
    "bytes",
    "streams",
    "direction",
    "duration",
    "out",
    "report-interval",
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
    "direction",
    "transfers",
    "errors",
    "bytes_up",
    "bytes_down",
    "interval_mbit_s",
    "transfer_p50_us",
    "transfer_p99_us",
];

#[derive(Debug, Default)]
struct State {
    transfers: u64,
    errors: u64,
    bytes_up: u64,
    bytes_down: u64,
    interval_bytes: u64,
    interval: Histogram,
}

/// Entry point for the subcommand.
pub fn main(args: &Args) -> Result<()> {
    args.reject_unknown(FLAGS)?;
    let common = Common::from_args(args, 30)?;
    if common.duration.is_zero() {
        return Err("--duration 0 is not allowed for bulk".into());
    }
    let addr = report::resolve(args.req("connect")?)?;
    let bytes = report::size_flag(args, "bytes", 8 << 20)?;
    if bytes == 0 {
        return Err("--bytes must be greater than 0".into());
    }
    let streams: usize = args.parsed_or("streams", 1)?;
    if streams == 0 {
        return Err("--streams must be at least 1".into());
    }
    let direction = Direction::from_args(args, Direction::Up)?;
    crate::runtime(args)?.block_on(run(addr, bytes, streams, direction, common))
}

async fn run(
    addr: std::net::SocketAddr,
    bytes: u64,
    streams: usize,
    direction: Direction,
    common: Common,
) -> Result<()> {
    report::say(&format!(
        "bulk: {streams} x {bytes} B {} -> {addr} for {}s",
        direction.name(),
        common.duration.as_secs()
    ));
    let state = Arc::new(Mutex::new(State::default()));
    let payload = shared_payload(common.seed, CHUNK);
    let (stop_tx, stop_rx) = report::stop_channel();
    let started = Instant::now();

    let mut workers = Vec::with_capacity(streams);
    for index in 0..streams {
        workers.push(tokio::spawn(stream(
            addr,
            bytes,
            direction.nth(index as u64),
            Arc::clone(&payload),
            Arc::clone(&state),
            stop_rx.clone(),
        )));
    }
    let reporter = tokio::spawn(reporting(
        Arc::clone(&state),
        common.clone(),
        stop_rx.clone(),
        started,
        direction,
    ));

    tokio::time::sleep(common.duration).await;
    stop_tx.send_replace(true);
    for worker in workers {
        let _ = worker.await;
    }
    let _ = reporter.await;
    let elapsed = started.elapsed();

    let (transfers, errors, up, down) = {
        let state = state.lock().map_err(|_| "bulk state poisoned")?;
        (
            state.transfers,
            state.errors,
            state.bytes_up,
            state.bytes_down,
        )
    };
    report::print_result(
        "bulk",
        &common,
        &format!(
            "\"target\":\"{}\",\"direction\":\"{}\",\"streams\":{},\"bytes_each\":{},\
             \"elapsed_s\":{:.3},\"transfers\":{},\"errors\":{},\"bytes_up\":{},\
             \"bytes_down\":{},\"mbit_s\":{:.3},\"up_mbit_s\":{:.3},\"down_mbit_s\":{:.3}",
            report::json_escape(&addr.to_string()),
            direction.name(),
            streams,
            bytes,
            elapsed.as_secs_f64(),
            transfers,
            errors,
            up,
            down,
            report::mbit_per_s(up + down, elapsed),
            report::mbit_per_s(up, elapsed),
            report::mbit_per_s(down, elapsed),
        ),
    );
    Ok(())
}

/// One stream: transfer after transfer on one connection until the run stops.
async fn stream(
    addr: std::net::SocketAddr,
    bytes: u64,
    direction: Direction,
    payload: Arc<Vec<u8>>,
    state: Arc<Mutex<State>>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let request = match direction {
        Direction::Down => Request::Down(bytes),
        _ => Request::Up(bytes),
    };
    let mut client: Option<Client> = None;
    while !report::is_stopped(&stop) {
        if client.is_none() {
            // Bounded like `ping`'s dial: a connect that never returns would otherwise hold
            // `run`'s join loop open past the end of the run. A timeout counts as an error.
            let dialed = report::bounded(
                report::CONNECT_TIMEOUT,
                Client::connect(addr, Arc::clone(&payload), CHUNK),
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
            r = active.request(request, false) => r,
            () = report::wait_stop(&mut stop) => return,
        };
        match result {
            Ok(took) => {
                if let Ok(mut state) = state.lock() {
                    state.transfers += 1;
                    state.interval_bytes += bytes;
                    match direction {
                        Direction::Down => state.bytes_down += bytes,
                        _ => state.bytes_up += bytes,
                    }
                    state
                        .interval
                        .record(u64::try_from(took.as_nanos()).unwrap_or(u64::MAX));
                }
            }
            Err(_) => {
                if let Ok(mut state) = state.lock() {
                    state.errors += 1;
                }
                client = None;
                if !report::sleep_or_stop(Duration::from_millis(250), &mut stop).await {
                    return;
                }
            }
        }
    }
}

async fn reporting(
    state: Arc<Mutex<State>>,
    common: Common,
    mut stop: tokio::sync::watch::Receiver<bool>,
    started: Instant,
    direction: Direction,
) {
    let mut csv = match common.out.as_ref() {
        None => None,
        Some(path) => match CsvAppender::open(path, HEADER) {
            Ok(csv) => Some(csv),
            Err(err) => {
                report::say(&format!("bulk: cannot write {}: {err}", path.display()));
                None
            }
        },
    };
    let mut ticker = tokio::time::interval(common.report_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;
    let mut window_started = Instant::now();
    loop {
        let last = tokio::select! {
            _ = ticker.tick() => false,
            () = report::wait_stop(&mut stop) => true,
        };
        let window = window_started.elapsed();
        window_started = Instant::now();
        let Ok(mut locked) = state.lock() else { return };
        let summary = locked.interval.summary_us();
        let interval_bytes = locked.interval_bytes;
        locked.interval.reset();
        locked.interval_bytes = 0;
        let (transfers, errors, up, down) = (
            locked.transfers,
            locked.errors,
            locked.bytes_up,
            locked.bytes_down,
        );
        drop(locked);

        let rate = report::mbit_per_s(interval_bytes, window);
        report::say(&format!(
            "bulk: t={:.0}s transfers={transfers} errors={errors} {rate:.1} Mbit/s",
            started.elapsed().as_secs_f64(),
        ));
        if let Some(csv) = csv.as_mut() {
            let now = timefmt::unix_now();
            let row = vec![
                now.to_string(),
                timefmt::iso8601_utc(now),
                f3(started.elapsed().as_secs_f64()),
                common.tag.clone(),
                direction.name().to_string(),
                transfers.to_string(),
                errors.to_string(),
                up.to_string(),
                down.to_string(),
                f3(rate),
                f3(summary.p50),
                f3(summary.p99),
            ];
            if let Err(err) = csv.row(&row) {
                report::say(&format!("bulk: csv write failed: {err}"));
            }
        }
        if last {
            return;
        }
    }
}
