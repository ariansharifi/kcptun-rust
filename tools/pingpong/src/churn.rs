//! `pingpong churn` — the workload the 11.4 soak is built on.
//!
//! Plan 11.4: *"continuous churn (open/close 20 streams/s, each 10 KB–1 MB) + 10 long-lived
//! streams + periodic bulk bursts"*. Three generators run side by side, all bounded:
//!
//! | generator | what it does | why the soak needs it |
//! |---|---|---|
//! | churn | opens a connection every `1/rate` s, transfers `min..max` bytes, closes it | this is the leak detector: 20 streams/s for six hours is 430 000 smux streams, so 4 kB lost per stream becomes a straight line instead of allocator noise |
//! | long-lived | `--long-lived` connections that echo a little every `--long-lived-interval` s | keeps sessions alive across the 30 s smux keepalive and the 5 s scavenger, and proves an old stream still works after hours of churn |
//! | bursts | every `--burst-every` s, `--burst-streams` transfers of `--burst-bytes` | drives the window up and back down repeatedly, so the peak-and-release behaviour of the allocator is exercised more than twice |
//!
//! Sizes are drawn **log-uniformly** by default (see [`SplitMix64::log_uniform`]): drawn
//! uniformly, 10 kB–1 MB would average 505 kB and the "churn" would really be a bulk test.
//!
//! Two bounds keep the driver itself honest over six hours: `--max-inflight` caps concurrent
//! streams (a refusal is counted, never queued, so the harness cannot run out of file
//! descriptors), and `--stream-timeout` caps how long one stream may take (a stream stuck on a
//! blackholed path is abandoned and counted rather than held forever).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kcptun_pingpong::Result;
use kcptun_pingpong::args::Args;
use kcptun_pingpong::csv::{CsvAppender, f3};
use kcptun_pingpong::hist::Histogram;
use kcptun_pingpong::net::{CHUNK, Client, shared_payload};
use kcptun_pingpong::proto::Request;
use kcptun_pingpong::rng::SplitMix64;
use kcptun_pingpong::timefmt;
use tokio::sync::watch;

use crate::report::{self, Common, Direction};

const FLAGS: &[&str] = &[
    "connect",
    "rate",
    "min-bytes",
    "max-bytes",
    "size-dist",
    "direction",
    "max-inflight",
    "stream-timeout",
    "long-lived",
    "long-lived-bytes",
    "long-lived-interval",
    "burst-every",
    "burst-streams",
    "burst-bytes",
    "duration",
    "out",
    "report-interval",
    "verify",
    "tag",
    "threads",
    "seed",
];

/// Columns of the interval CSV. Cumulative and per-interval columns are named apart so a plot
/// of the soak cannot accidentally mix them.
const HEADER: &[&str] = &[
    "unix",
    "iso",
    "elapsed_s",
    "tag",
    "opened",
    "completed",
    "errors",
    "timeouts",
    "refused",
    "inflight",
    "bytes_up",
    "bytes_down",
    "long_lived_ok",
    "long_lived_errors",
    "bursts",
    "interval_streams",
    "interval_mbit_s",
    "stream_p50_us",
    "stream_p90_us",
    "stream_p99_us",
    "stream_max_us",
];

/// Cumulative counters, written by many tasks.
#[derive(Debug, Default)]
struct Counters {
    opened: AtomicU64,
    completed: AtomicU64,
    errors: AtomicU64,
    timeouts: AtomicU64,
    refused: AtomicU64,
    inflight: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    long_lived_ok: AtomicU64,
    long_lived_errors: AtomicU64,
    bursts: AtomicU64,
}

/// Per-interval accumulators, reset by the reporter.
#[derive(Debug, Default)]
struct Window {
    streams: u64,
    bytes: u64,
    latency: Histogram,
}

/// Everything a churn task needs.
struct Shared {
    addr: std::net::SocketAddr,
    payload: Arc<Vec<u8>>,
    counters: Arc<Counters>,
    window: Arc<Mutex<Window>>,
    stream_timeout: Duration,
    verify: bool,
}

/// Entry point for the subcommand.
pub fn main(args: &Args) -> Result<()> {
    args.reject_unknown(FLAGS)?;
    let common = Common::from_args(args, 300)?;
    if common.duration.is_zero() {
        return Err("--duration 0 is not allowed for churn".into());
    }
    let addr = report::resolve(args.req("connect")?)?;
    let rate: f64 = args.parsed_or("rate", 20.0)?;
    if !(rate.is_finite() && rate > 0.0 && rate <= 10_000.0) {
        return Err("--rate must be between 0 and 10000 streams per second".into());
    }
    let min_bytes = report::size_flag(args, "min-bytes", 10 * 1024)?;
    let max_bytes = report::size_flag(args, "max-bytes", 1024 * 1024)?;
    if min_bytes == 0 || max_bytes < min_bytes {
        return Err("--min-bytes must be > 0 and --max-bytes at least --min-bytes".into());
    }
    let log_sizes = match args.str_or("size-dist", "log")? {
        "log" => true,
        "uniform" => false,
        other => return Err(format!("--size-dist {other:?}: want log or uniform").into()),
    };
    let cfg = Config {
        rate,
        min_bytes,
        max_bytes,
        log_sizes,
        direction: Direction::from_args(args, Direction::Both)?,
        max_inflight: args.parsed_or("max-inflight", 100)?,
        stream_timeout: Duration::from_secs(args.parsed_or("stream-timeout", 120)?),
        long_lived: args.parsed_or("long-lived", 10)?,
        long_lived_bytes: report::size_flag(args, "long-lived-bytes", 1024)?,
        long_lived_interval: Duration::from_secs(args.parsed_or("long-lived-interval", 5)?),
        burst_every: Duration::from_secs(args.parsed_or("burst-every", 300)?),
        burst_streams: args.parsed_or("burst-streams", 4)?,
        burst_bytes: report::size_flag(args, "burst-bytes", 8 << 20)?,
        verify: args.has("verify"),
        common,
    };
    if cfg.max_inflight == 0 {
        return Err("--max-inflight must be at least 1".into());
    }
    crate::runtime(args)?.block_on(run(addr, cfg))
}

#[derive(Clone)]
struct Config {
    rate: f64,
    min_bytes: u64,
    max_bytes: u64,
    log_sizes: bool,
    direction: Direction,
    max_inflight: u64,
    stream_timeout: Duration,
    long_lived: usize,
    long_lived_bytes: u64,
    long_lived_interval: Duration,
    burst_every: Duration,
    burst_streams: usize,
    burst_bytes: u64,
    verify: bool,
    common: Common,
}

async fn run(addr: std::net::SocketAddr, cfg: Config) -> Result<()> {
    report::say(&format!(
        "churn: {} -> {addr} at {:.1} streams/s of {}..{} B ({}), {} long-lived, \
         bursts {}x{} B every {}s, for {}s",
        cfg.direction.name(),
        cfg.rate,
        cfg.min_bytes,
        cfg.max_bytes,
        if cfg.log_sizes {
            "log-uniform"
        } else {
            "uniform"
        },
        cfg.long_lived,
        cfg.burst_streams,
        cfg.burst_bytes,
        cfg.burst_every.as_secs(),
        cfg.common.duration.as_secs(),
    ));

    let shared = Arc::new(Shared {
        addr,
        payload: shared_payload(cfg.common.seed, CHUNK),
        counters: Arc::new(Counters::default()),
        window: Arc::new(Mutex::new(Window::default())),
        stream_timeout: cfg.stream_timeout,
        verify: cfg.verify,
    });
    let (stop_tx, stop_rx) = report::stop_channel();
    let started = Instant::now();

    let mut tasks = Vec::new();
    tasks.push(tokio::spawn(open_streams(
        Arc::clone(&shared),
        cfg.clone(),
        stop_rx.clone(),
    )));
    for _ in 0..cfg.long_lived {
        tasks.push(tokio::spawn(long_lived(
            Arc::clone(&shared),
            cfg.long_lived_bytes,
            cfg.long_lived_interval,
            stop_rx.clone(),
        )));
    }
    if cfg.burst_streams > 0 && !cfg.burst_every.is_zero() {
        tasks.push(tokio::spawn(bursts(
            Arc::clone(&shared),
            cfg.burst_every,
            cfg.burst_streams,
            cfg.burst_bytes,
            stop_rx.clone(),
        )));
    }
    let reporter = tokio::spawn(reporting(
        Arc::clone(&shared),
        cfg.common.clone(),
        stop_rx.clone(),
        started,
    ));

    tokio::time::sleep(cfg.common.duration).await;
    stop_tx.send_replace(true);
    for task in tasks {
        let _ = task.await;
    }
    // Streams already in flight are given a moment to finish before the totals are read.
    let grace = Instant::now() + Duration::from_secs(10);
    while shared.counters.inflight.load(Ordering::Relaxed) > 0 && Instant::now() < grace {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = reporter.await;

    let c = &shared.counters;
    let elapsed = started.elapsed();
    let up = c.bytes_up.load(Ordering::Relaxed);
    let down = c.bytes_down.load(Ordering::Relaxed);
    report::print_result(
        "churn",
        &cfg.common,
        &format!(
            "\"target\":\"{}\",\"rate\":{:.3},\"min_bytes\":{},\"max_bytes\":{},\
             \"elapsed_s\":{:.3},\"opened\":{},\"completed\":{},\"errors\":{},\"timeouts\":{},\
             \"refused\":{},\"inflight_at_end\":{},\"bytes_up\":{},\"bytes_down\":{},\
             \"mbit_s\":{:.3},\"long_lived_ok\":{},\"long_lived_errors\":{},\"bursts\":{}",
            report::json_escape(&addr.to_string()),
            cfg.rate,
            cfg.min_bytes,
            cfg.max_bytes,
            elapsed.as_secs_f64(),
            c.opened.load(Ordering::Relaxed),
            c.completed.load(Ordering::Relaxed),
            c.errors.load(Ordering::Relaxed),
            c.timeouts.load(Ordering::Relaxed),
            c.refused.load(Ordering::Relaxed),
            c.inflight.load(Ordering::Relaxed),
            up,
            down,
            report::mbit_per_s(up + down, elapsed),
            c.long_lived_ok.load(Ordering::Relaxed),
            c.long_lived_errors.load(Ordering::Relaxed),
            c.bursts.load(Ordering::Relaxed),
        ),
    );
    Ok(())
}

/// Opens one short stream per tick, at `--rate` per second.
async fn open_streams(shared: Arc<Shared>, cfg: Config, mut stop: watch::Receiver<bool>) {
    let period = Duration::from_secs_f64(1.0 / cfg.rate);
    let mut ticker = tokio::time::interval(period);
    // `Delay` keeps the rate steady after a hiccup; `Burst` would fire a catch-up storm at the
    // one moment the tunnel is already struggling, which is not what the soak is measuring.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut rng = SplitMix64::new(cfg.common.seed ^ 0x5FE1_AB1E);
    let mut nth = 0u64;
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            () = report::wait_stop(&mut stop) => return,
        }
        let inflight = shared.counters.inflight.load(Ordering::Relaxed);
        if inflight >= cfg.max_inflight {
            shared.counters.refused.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let bytes = if cfg.log_sizes {
            rng.log_uniform(cfg.min_bytes, cfg.max_bytes)
        } else {
            rng.uniform(cfg.min_bytes, cfg.max_bytes)
        };
        let request = match cfg.direction.nth(nth) {
            Direction::Down => Request::Down(bytes),
            _ => Request::Up(bytes),
        };
        nth = nth.wrapping_add(1);
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            one_stream(&shared, request, true).await;
        });
    }
}

/// Connects, performs one request, closes. `record` keeps burst traffic out of the churn
/// latency histogram, which would otherwise be dominated by the bursts' size.
async fn one_stream(shared: &Shared, request: Request, record: bool) {
    shared.counters.opened.fetch_add(1, Ordering::Relaxed);
    shared.counters.inflight.fetch_add(1, Ordering::Relaxed);
    let started = Instant::now();
    let attempt = tokio::time::timeout(shared.stream_timeout, async {
        let mut client = Client::connect(
            shared.addr,
            Arc::clone(&shared.payload),
            CHUNK.min(usize::try_from(request.payload_in().max(4096)).unwrap_or(CHUNK)),
        )
        .await?;
        client.request(request, shared.verify).await
    })
    .await;
    match attempt {
        Ok(Ok(_)) => {
            shared.counters.completed.fetch_add(1, Ordering::Relaxed);
            match request {
                Request::Down(n) => {
                    shared.counters.bytes_down.fetch_add(n, Ordering::Relaxed);
                }
                Request::Up(n) | Request::Echo(n) => {
                    shared.counters.bytes_up.fetch_add(n, Ordering::Relaxed);
                }
            }
            if record && let Ok(mut window) = shared.window.lock() {
                window.streams += 1;
                window.bytes += request.payload_in() + request.payload_out();
                window
                    .latency
                    .record(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
            }
        }
        Ok(Err(_)) => {
            shared.counters.errors.fetch_add(1, Ordering::Relaxed);
        }
        Err(_) => {
            shared.counters.timeouts.fetch_add(1, Ordering::Relaxed);
        }
    }
    shared.counters.inflight.fetch_sub(1, Ordering::Relaxed);
}

/// One connection that stays open for the whole run, echoing a little at a time.
async fn long_lived(
    shared: Arc<Shared>,
    bytes: u64,
    every: Duration,
    mut stop: watch::Receiver<bool>,
) {
    let request = Request::Echo(bytes);
    let mut client: Option<Client> = None;
    while !report::is_stopped(&stop) {
        if client.is_none() {
            // `--stream-timeout` bounds the dial as well as the request, the way `one_stream`
            // already bounds both: a task parked in `connect` would keep the whole churn mode
            // from joining its workers at the end of a six-hour soak.
            let dialed = report::bounded(
                shared.stream_timeout,
                Client::connect(shared.addr, Arc::clone(&shared.payload), CHUNK.min(1 << 16)),
                &mut stop,
            )
            .await;
            match dialed {
                report::Bounded::Stopped => return,
                report::Bounded::Done(Ok(fresh)) => client = Some(fresh),
                report::Bounded::Done(Err(_)) | report::Bounded::TimedOut => {
                    shared
                        .counters
                        .long_lived_errors
                        .fetch_add(1, Ordering::Relaxed);
                    if !report::sleep_or_stop(every, &mut stop).await {
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
            r = tokio::time::timeout(shared.stream_timeout, active.request(request, shared.verify)) => r,
            () = report::wait_stop(&mut stop) => return,
        };
        match result {
            Ok(Ok(_)) => {
                shared
                    .counters
                    .long_lived_ok
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                shared
                    .counters
                    .long_lived_errors
                    .fetch_add(1, Ordering::Relaxed);
                client = None;
            }
        }
        if !report::sleep_or_stop(every, &mut stop).await {
            return;
        }
    }
}

/// A periodic bulk burst: several large transfers at once, then quiet again.
async fn bursts(
    shared: Arc<Shared>,
    every: Duration,
    streams: usize,
    bytes: u64,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        if !report::sleep_or_stop(every, &mut stop).await {
            return;
        }
        shared.counters.bursts.fetch_add(1, Ordering::Relaxed);
        let mut running = Vec::with_capacity(streams * 2);
        for index in 0..streams {
            let request = if index.is_multiple_of(2) {
                Request::Up(bytes)
            } else {
                Request::Down(bytes)
            };
            let shared = Arc::clone(&shared);
            running.push(tokio::spawn(async move {
                one_stream(&shared, request, false).await;
            }));
        }
        for task in running {
            let _ = task.await;
        }
    }
}

async fn reporting(
    shared: Arc<Shared>,
    common: Common,
    mut stop: watch::Receiver<bool>,
    started: Instant,
) {
    let mut csv = match common.out.as_ref() {
        None => None,
        Some(path) => match CsvAppender::open(path, HEADER) {
            Ok(csv) => Some(csv),
            Err(err) => {
                report::say(&format!("churn: cannot write {}: {err}", path.display()));
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
        let window_elapsed = window_started.elapsed();
        window_started = Instant::now();
        let (streams, bytes, latency) = match shared.window.lock() {
            Err(_) => return,
            Ok(mut window) => {
                let snapshot = (window.streams, window.bytes, window.latency.summary_us());
                window.streams = 0;
                window.bytes = 0;
                window.latency.reset();
                snapshot
            }
        };
        let c = &shared.counters;
        let rate = report::mbit_per_s(bytes, window_elapsed);
        report::say(&format!(
            "churn: t={:.0}s opened={} completed={} errors={} timeouts={} refused={} \
             inflight={} {rate:.1} Mbit/s p50={:.0}us p99={:.0}us",
            started.elapsed().as_secs_f64(),
            c.opened.load(Ordering::Relaxed),
            c.completed.load(Ordering::Relaxed),
            c.errors.load(Ordering::Relaxed),
            c.timeouts.load(Ordering::Relaxed),
            c.refused.load(Ordering::Relaxed),
            c.inflight.load(Ordering::Relaxed),
            latency.p50,
            latency.p99,
        ));
        if let Some(csv) = csv.as_mut() {
            let now = timefmt::unix_now();
            let row = vec![
                now.to_string(),
                timefmt::iso8601_utc(now),
                f3(started.elapsed().as_secs_f64()),
                common.tag.clone(),
                c.opened.load(Ordering::Relaxed).to_string(),
                c.completed.load(Ordering::Relaxed).to_string(),
                c.errors.load(Ordering::Relaxed).to_string(),
                c.timeouts.load(Ordering::Relaxed).to_string(),
                c.refused.load(Ordering::Relaxed).to_string(),
                c.inflight.load(Ordering::Relaxed).to_string(),
                c.bytes_up.load(Ordering::Relaxed).to_string(),
                c.bytes_down.load(Ordering::Relaxed).to_string(),
                c.long_lived_ok.load(Ordering::Relaxed).to_string(),
                c.long_lived_errors.load(Ordering::Relaxed).to_string(),
                c.bursts.load(Ordering::Relaxed).to_string(),
                streams.to_string(),
                f3(rate),
                f3(latency.p50),
                f3(latency.p90),
                f3(latency.p99),
                f3(latency.max),
            ];
            if let Err(err) = csv.row(&row) {
                report::say(&format!("churn: csv write failed: {err}"));
            }
        }
        if last {
            return;
        }
    }
}
