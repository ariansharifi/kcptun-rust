//! `pingpong serve` — the target behind the tunnel.
//!
//! This is what the kcptun server's `-t` points at when a scenario's workload is `ping`, `bulk`
//! or `churn` (a scenario that runs `iperf3` points `-t` at `iperf3 -s` instead). It answers the
//! three verbs of [`kcptun_pingpong::proto`] and counts what it served.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use kcptun_pingpong::Result;
use kcptun_pingpong::args::Args;
use kcptun_pingpong::net::{self, CHUNK, shared_payload};
use tokio::io::BufReader;
use tokio::net::TcpListener;

use crate::report::{self, Common};

const FLAGS: &[&str] = &[
    "listen",
    "duration",
    "report-interval",
    "idle-timeout",
    "buffer-bytes",
    "threads",
    "seed",
    "tag",
];

/// Counters shared by every connection task.
#[derive(Debug, Default)]
struct Counters {
    accepted: AtomicU64,
    live: AtomicU64,
    requests: AtomicU64,
    errors: AtomicU64,
    accept_errors: AtomicU64,
}

/// Entry point for the subcommand.
pub fn main(args: &Args) -> Result<()> {
    args.reject_unknown(FLAGS)?;
    let common = Common::from_args(args, 3600)?;
    let listen = args.req("listen")?.to_string();
    let idle: u64 = args.parsed_or("idle-timeout", 300)?;
    let idle = (idle > 0).then(|| Duration::from_secs(idle));
    // Per-connection, so it is deliberately modest: the churn workload keeps hundreds of
    // connections open and this buffer is the only thing allocated for each of them.
    let buffer = usize::try_from(report::size_flag(args, "buffer-bytes", 16 * 1024)?)
        .unwrap_or(CHUNK)
        .clamp(4096, CHUNK);
    crate::runtime(args)?.block_on(run(listen, common, idle, buffer))
}

async fn run(listen: String, common: Common, idle: Option<Duration>, buffer: usize) -> Result<()> {
    let listener = TcpListener::bind(&listen)
        .await
        .map_err(|e| format!("listen on {listen}: {e}"))?;
    let bound = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;
    report::say(&format!(
        "serve: listening on {bound} (idle timeout {}, duration {}s, {buffer} B per connection)",
        idle.map_or("off".to_string(), |d| format!("{}s", d.as_secs())),
        common.duration.as_secs()
    ));

    // One payload for every connection; see `net::serve_connection`.
    let payload = shared_payload(common.seed, CHUNK);

    let counters = Arc::new(Counters::default());
    let (stop_tx, stop_rx) = report::stop_channel();
    let started = Instant::now();

    let reporter = tokio::spawn(progress(
        Arc::clone(&counters),
        common.report_interval,
        stop_rx.clone(),
        started,
    ));

    let deadline = common.deadline(started);
    let mut accept_rx = stop_rx.clone();
    loop {
        let accepted = tokio::select! {
            result = listener.accept() => result,
            () = sleep_until(deadline) => break,
            () = report::wait_stop(&mut accept_rx) => break,
        };
        match accepted {
            Ok((stream, _peer)) => {
                counters.accepted.fetch_add(1, Ordering::Relaxed);
                counters.live.fetch_add(1, Ordering::Relaxed);
                let counters = Arc::clone(&counters);
                let payload = Arc::clone(&payload);
                tokio::spawn(async move {
                    let _ = stream.set_nodelay(true);
                    let (reader, mut writer) = stream.into_split();
                    let mut reader = BufReader::with_capacity(buffer, reader);
                    match net::serve_connection(&mut reader, &mut writer, &payload, buffer, idle)
                        .await
                    {
                        Ok(served) => {
                            counters.requests.fetch_add(served, Ordering::Relaxed);
                        }
                        Err(_) => {
                            counters.errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    counters.live.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(err) => {
                // A failed accept is usually a transient fd shortage; count it, pause briefly
                // so the loop cannot spin, and keep serving.
                counters.accept_errors.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(100)).await;
                let _ = err;
            }
        }
    }

    stop_tx.send_replace(true);
    drop(listener);
    // Give connections that are mid-transfer a moment to finish before the summary.
    let grace = Instant::now() + Duration::from_secs(5);
    while counters.live.load(Ordering::Relaxed) > 0 && Instant::now() < grace {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = reporter.await;

    report::print_result(
        "serve",
        &common,
        &format!(
            "\"listen\":\"{}\",\"elapsed_s\":{:.3},\"accepted\":{},\"requests\":{},\
             \"conn_errors\":{},\"accept_errors\":{},\"live_at_end\":{}",
            report::json_escape(&bound.to_string()),
            started.elapsed().as_secs_f64(),
            counters.accepted.load(Ordering::Relaxed),
            counters.requests.load(Ordering::Relaxed),
            counters.errors.load(Ordering::Relaxed),
            counters.accept_errors.load(Ordering::Relaxed),
            counters.live.load(Ordering::Relaxed),
        ),
    );
    Ok(())
}

/// Sleeps until `deadline`, or forever when there is none.
async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at.into()).await,
        None => std::future::pending().await,
    }
}

/// One progress line per interval — bounded output for an unattended run.
async fn progress(
    counters: Arc<Counters>,
    every: Duration,
    mut stop: tokio::sync::watch::Receiver<bool>,
    started: Instant,
) {
    let mut ticker = tokio::time::interval(every);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            () = report::wait_stop(&mut stop) => return,
        }
        report::say(&format!(
            "serve: t={:.0}s accepted={} live={} requests={} conn_errors={} accept_errors={}",
            started.elapsed().as_secs_f64(),
            counters.accepted.load(Ordering::Relaxed),
            counters.live.load(Ordering::Relaxed),
            counters.requests.load(Ordering::Relaxed),
            counters.errors.load(Ordering::Relaxed),
            counters.accept_errors.load(Ordering::Relaxed),
        ));
    }
}
