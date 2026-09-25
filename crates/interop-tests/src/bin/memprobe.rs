//! Memory probe: does a KCP burst give its memory back? (plan 12.3b)
//!
//! `docs/benchmarks/memory.md` §4 measured that a Rust kcptun process which has once moved
//! 512 MB keeps ~100 MB of RSS for at least 600 s with every stream closed, where Go's scavenger
//! returns most of it. That measurement could not say **why**, because it only had RSS:
//!
//! - **(a) the program retains capacity**: pools, grown rings, queues and per-session buffers
//!   that never shrink, so the bytes are still *live* on the heap; or
//! - **(b) the allocator keeps freed arenas mapped**: the bytes are free as far as the program
//!   is concerned, but no page ever goes back to the kernel.
//!
//! This binary separates the two by sampling **live heap bytes and RSS at the same instants**:
//!
//! - built normally it overrides nothing, so RSS is the honest production number;
//! - built with `--features dhat` it installs [`dhat::Alloc`], whose `curr_bytes` is exactly the
//!   live heap, and writes `dhat-heap.json` with per-callsite attribution.
//!
//! Live heap falling back to the idle level while RSS stays at the peak is (b); live heap staying
//! high is (a), and the dhat JSON then names the sites.
//!
//! The workload is the S1 production profile of step 12: one echo server and
//! `--sessions` dialled sessions, each echoing `--bytes` (so each byte crosses the wire twice, as
//! in memory.md's "up then down"), `-crypt xor -mtu 1390 -sndwnd 8192 -rcvwnd 8192 -mode normal`.
//!
//! # Which layer: `--smux`
//!
//! Two modes, because the two questions are different:
//!
//! - **default: raw KCP.** The burst runs straight over [`UdpSession`], so what is measured is
//!   the KCP rings, the `rcv_buf` heap, the packet pool and the allocator, with nothing above
//!   them. This is the mode that sized the 85 % / 15 % split.
//! - **`--smux`: the shape of the product.** Each session is wrapped in a
//!   [`KcpConn`] and a `kcptun_smux` session with S1's `-smuxver 2 -smuxbuf 16777216
//!   -streambuf 16777216 -framesize 8192 -keepalive 10`, so the burst also carries the smux
//!   token bucket, the shaper and the per-stream receive buffers, **and the keepalive**. That
//!   last one is not a detail: smux writes an 8-byte `cmdNOP` per session every 10 s for as long
//!   as the session lives, every one of them goes through `UdpSession::write`, and every one of
//!   them moves `DEFAULT_SNMP.bytes_sent`. A probe without smux never sees that traffic, so it
//!   cannot tell whether [`kcptun_kcp::memory::trim_when_idle`]'s idea of "quiet" survives
//!   contact with a real client. Run `--smux --auto-trim` to answer that.
//!
//!   In `--smux` mode the streams are closed at the end of the burst but the sessions are
//!   **kept** through the whole decay, which is what a kcptun client does: it only scavenges a
//!   zero-stream session after `-scavengettl` (600 s), and never if the session is reused.
//!
//! # `--idle`: the per-session slope (plan 12.3c)
//!
//! `--idle` replaces the burst with a staircase: it dials `--sessions` client sessions in stages
//! (1, 2, 4, … up to the requested count) against a UDP sink that reads and discards, and samples
//! after every stage. No byte is ever transferred, so what the staircase measures is the cost of
//! *existing*, exactly the slope `docs/benchmarks/memory.md` §3 fitted across two whole processes
//! (698 kB per client session in Rust against 243 kB in Go), but within one process and with the
//! live heap beside the RSS.
//!
//! That pairing is the point. A stage that raises the live heap and the RSS by the same amount is
//! memory the program asked for and touched; a stage that raises the RSS by *more* than the heap
//! is the allocator faulting pages the program never reads, which is the failure mode
//! `docs/porting-guide.md` warns about for `vec![0u8; N]` and which Go avoids for free (its
//! allocator knows a fresh span is already zero and skips the memset).
//!
//! `--churn G` runs that staircase `G` times over, closing and dropping every session between
//! generations. A staircase on its own only ever *allocates*, so it says nothing about the
//! session a client replaces when one dies (an error, `-autoexpire`, the 600 s scavenger): the
//! replacement's receive batch is a `calloc` of a block the allocator has just been handed back,
//! and whether it still gets a fresh untouched mapping is allocator policy. glibc raises its
//! dynamic `mmap` threshold to the size of the first large mapped chunk it frees, so the second
//! generation is the one that matters there. Phase names are prefixed `genN-` when `G > 1`.
//!
//! Output is CSV on stdout, one row per sample:
//!
//! ```text
//! phase,t_ms,rss_kb,peak_rss_kb,heap_curr_b,heap_max_b,pool_parked
//! ```
//!
//! Example:
//!
//! ```sh
//! cargo run --release -p kcptun-interop-tests --bin memprobe -- \
//!     --sessions 4 --bytes 134217728 --auto-trim --decay 180 --interval 30
//! cargo run --release -p kcptun-interop-tests --bin memprobe -- \
//!     --smux --sessions 4 --bytes 134217728 --auto-trim --decay 180 --interval 30
//! cargo run --release -p kcptun-interop-tests --bin memprobe --features dhat -- \
//!     --bytes 16777216 --dump-at-close
//! cargo run --release -p kcptun-interop-tests --bin memprobe --features dhat -- \
//!     --idle --sessions 16 --dump-at-close
//! cargo run --release -p kcptun-interop-tests --bin memprobe -- \
//!     --idle --sessions 16 --settle 3 --churn 3
//! ```
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kcptun_interop_tests::kcp::{KcpCase, RustClientRun, RustEchoServer, SOCKBUF, run_rust_client};
use kcptun_kcp::bufpool;
use kcptun_kcp::{Listener, UdpSession};
use kcptun_smux::session::Session;
use kcptun_smux::stream::Stream;
use kcptun_std::kcpconn::KcpConn;
use kcptun_testkit::servers::PrngStream;

#[cfg(feature = "dhat")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// Parsed command line.
struct Args {
    /// Bytes echoed per session (each one crosses the link twice).
    bytes: u64,
    /// Sessions dialled in parallel.
    sessions: usize,
    /// Seconds to keep sampling after the burst.
    decay: u64,
    /// Seconds between samples during the decay.
    interval: u64,
    /// Keep the sessions open through the decay instead of closing them.
    keep: bool,
    /// Call `kcptun_kcp::memory::trim()` once the decay is over and sample again.
    trim: bool,
    /// Spawn `kcptun_kcp::memory::trim_when_idle`, the task the binaries run, so that the decay
    /// rows show what a shipped process does by itself rather than what one explicit trim does.
    auto_trim: bool,
    /// Stop as soon as the burst is over and the sessions are closed, while the *sessions* are
    /// still alive. Under `--features dhat` that makes dhat's "at t-end" snapshot the retained
    /// state, so `dhat-heap.json` attributes what the program is still holding.
    dump_at_close: bool,
    /// Run the burst through smux over KCP, with S1's smux buffers and keepalive, instead of
    /// straight over KCP (see the module docs).
    smux: bool,
    /// Replace the burst with the idle staircase of plan 12.3c (see the module docs): dial
    /// `sessions` sessions in stages against a sink, transfer nothing, sample after each stage.
    idle: bool,
    /// Seconds to let a stage of the `--idle` staircase settle before it is sampled.
    settle: u64,
    /// How many times to run the `--idle` staircase, closing and dropping every session in
    /// between: generation 2 onwards measures what a *replacement* session costs (see the module
    /// docs). 1 is the plain staircase.
    churn: usize,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            bytes: 128 * 1024 * 1024,
            sessions: 4,
            decay: 120,
            interval: 30,
            keep: false,
            trim: true,
            auto_trim: false,
            dump_at_close: false,
            smux: false,
            idle: false,
            settle: 2,
            churn: 1,
        }
    }
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args::default();
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let mut value = || argv.next().ok_or_else(|| format!("{flag}: missing value"));
        match flag.as_str() {
            "--bytes" => args.bytes = value()?.parse().map_err(|e| format!("--bytes: {e}"))?,
            "--sessions" => {
                args.sessions = value()?.parse().map_err(|e| format!("--sessions: {e}"))?;
            }
            "--decay" => args.decay = value()?.parse().map_err(|e| format!("--decay: {e}"))?,
            "--interval" => {
                args.interval = value()?.parse().map_err(|e| format!("--interval: {e}"))?;
            }
            "--keep" => args.keep = true,
            "--no-trim" => args.trim = false,
            "--auto-trim" => args.auto_trim = true,
            "--dump-at-close" => args.dump_at_close = true,
            "--smux" => args.smux = true,
            "--idle" => args.idle = true,
            "--settle" => args.settle = value()?.parse().map_err(|e| format!("--settle: {e}"))?,
            "--churn" => args.churn = value()?.parse().map_err(|e| format!("--churn: {e}"))?,
            "-h" | "--help" => {
                println!(
                    "memprobe [--bytes N] [--sessions N] [--decay SECS] [--interval SECS] \
                     [--keep] [--no-trim] [--auto-trim] [--dump-at-close] [--smux] \
                     [--idle [--settle SECS] [--churn GENERATIONS]]"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if args.sessions == 0 {
        return Err("--sessions must be at least 1".to_string());
    }
    if args.interval == 0 {
        return Err("--interval must be at least 1".to_string());
    }
    if args.churn == 0 {
        return Err("--churn must be at least 1".to_string());
    }
    if args.churn > 1 && !args.idle {
        return Err("--churn needs --idle".to_string());
    }
    if args.idle && args.smux {
        // The staircase wants the *client* slope on its own. A smux session needs a peer that
        // accepts, and an accepted session in the same process would be counted into every stage.
        return Err("--idle and --smux are exclusive".to_string());
    }
    Ok(args)
}

// ---------------------------------------------------------------------------------------------
// Sampling
// ---------------------------------------------------------------------------------------------

/// Resident set size and its high-water mark, in kB.
#[derive(Clone, Copy, Default)]
struct Rss {
    rss_kb: u64,
    peak_kb: u64,
}

/// Reads `VmRSS`/`VmHWM` on Linux; elsewhere asks `ps` for RSS and keeps the peak itself.
#[cfg(target_os = "linux")]
fn read_rss(seen_peak: u64) -> Rss {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |name: &str| -> u64 {
        status
            .lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };
    let rss_kb = field("VmRSS:");
    Rss {
        rss_kb,
        peak_kb: field("VmHWM:").max(seen_peak),
    }
}

#[cfg(not(target_os = "linux"))]
fn read_rss(seen_peak: u64) -> Rss {
    let pid = std::process::id();
    let rss_kb = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    Rss {
        rss_kb,
        peak_kb: rss_kb.max(seen_peak),
    }
}

/// Live and peak heap bytes, when a profiling allocator is installed.
#[cfg(feature = "dhat")]
fn heap() -> (i64, i64) {
    let stats = dhat::HeapStats::get();
    (stats.curr_bytes as i64, stats.max_bytes as i64)
}

#[cfg(not(feature = "dhat"))]
fn heap() -> (i64, i64) {
    (-1, -1)
}

/// Prints one CSV row and carries the peak forward.
fn sample(phase: &str, start: Instant, peak: &mut u64) {
    let rss = read_rss(*peak);
    *peak = rss.peak_kb;
    let (curr, max) = heap();
    println!(
        "{phase},{},{},{},{curr},{max},{}",
        start.elapsed().as_millis(),
        rss.rss_kb,
        rss.peak_kb,
        bufpool::default_pool().parked(),
    );
}

// ---------------------------------------------------------------------------------------------
// Workload
// ---------------------------------------------------------------------------------------------

/// The S1 production profile at the KCP layer.
fn production_case() -> KcpCase {
    KcpCase::new()
        .crypt("xor")
        .fec(0, 0)
        .mtu(1390)
        .windows(8192, 8192)
        .mode("normal")
}

/// The S1 production profile at the smux layer: `-smuxver 2 -smuxbuf 16777216 -streambuf
/// 16777216`, kcptun's default `-framesize 8192` and its default `-keepalive 10`.
///
/// Built through kcptun's own `BuildSmuxConfig`, so the probe cannot drift from what the
/// binaries do, including `keep_alive_disabled` staying false, which is the whole point of the
/// `--smux` mode.
// Go: kcptun/std/smuxcfg.go:BuildSmuxConfig
fn production_smux_config() -> Result<kcptun_smux::Config, String> {
    kcptun_std::smuxcfg::build_smux_config(2, 16_777_216, 16_777_216, 8_192, 10)
        .map(kcptun_smux::Config::from)
        .map_err(|e| format!("smux config: {e}"))
}

/// Applies `case` to a dialled or accepted session, in kcptun's `serveListener` order.
fn apply_case(session: &UdpSession, case: &KcpCase) {
    let [nodelay, interval, resend, nc] = case.nodelay_params();
    session.set_stream_mode(true);
    session.set_write_delay(false);
    session.set_no_delay(
        nodelay as isize,
        interval as isize,
        resend as isize,
        nc as isize,
    );
    session.set_mtu(case.mtu as isize);
    session.set_window_size(case.sndwnd as isize, case.rcvwnd as isize);
    session.set_ack_no_delay(case.acknodelay);
    session.set_rate_limit(0);
    let _ = session.set_dscp(0);
    let _ = session.set_read_buffer(SOCKBUF);
    let _ = session.set_write_buffer(SOCKBUF);
}

// ---------------------------------------------------------------------------------------------
// The `--smux` workload: the shape of the product
// ---------------------------------------------------------------------------------------------

/// A smux-over-KCP echo server: a kcptun server's `serveListener` → `handleMux` without the TCP
/// hop to the target, so the smux layer is exercised and the proxy is not.
///
/// Dropping it closes the listener and stops accepting, which releases every accepted session.
// Go: kcptun/server/main.go:serveListener(), handleMux()
struct SmuxEchoServer {
    listener: Arc<Listener>,
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl SmuxEchoServer {
    fn start(
        listen: SocketAddr,
        case: &KcpCase,
        config: kcptun_smux::Config,
    ) -> Result<SmuxEchoServer, String> {
        // No `socket_creation_guard` here: the probe is one process binding an ephemeral port
        // and never spawns a Go peer, so there is no fd race for the guard to serialise.
        let listener = Listener::listen_with_options(
            &listen.to_string(),
            case.block(),
            case.ds as isize,
            case.ps as isize,
        )
        .map_err(|e| format!("listen: {e}"))?;
        let addr = listener.addr().map_err(|e| format!("listen addr: {e}"))?;
        let _ = listener.set_dscp(0);
        let _ = listener.set_read_buffer(SOCKBUF);
        let _ = listener.set_write_buffer(SOCKBUF);

        let case = case.clone();
        let task = tokio::spawn({
            let listener = Arc::clone(&listener);
            async move {
                while let Ok(session) = listener.accept().await {
                    apply_case(&session, &case);
                    let Ok(mux) = kcptun_smux::mux::server(KcpConn::new(session), Some(config))
                    else {
                        return;
                    };
                    tokio::spawn(serve_session(mux));
                }
            }
        });
        Ok(SmuxEchoServer {
            listener,
            addr,
            task,
        })
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for SmuxEchoServer {
    fn drop(&mut self) {
        let _ = self.listener.close();
        self.task.abort();
    }
}

/// Accepts and echoes every stream of one session (Go's `serveConn`).
async fn serve_session(session: Session<KcpConn>) {
    while let Ok(stream) = session.accept_stream().await {
        tokio::spawn(echo_stream(stream));
    }
}

/// kcptun's `std.Pipe` order: copy until the peer's FIN, then `CloseWrite`, then `Close`.
/// `read_chunk` + `write_bytes` is Go's `io.Copy` `WriterTo` fast path, so an idle echo stream
/// costs no per-stream copy buffer.
async fn echo_stream(stream: Stream) {
    while let Ok(Some(chunk)) = stream.read_chunk().await {
        if stream.write_bytes(&chunk).await.is_err() {
            break;
        }
    }
    let _ = stream.close_write().await;
    let _ = stream.close().await;
}

/// Dials one KCP session, wraps it in smux, echoes `bytes` through one stream, closes the
/// stream and **returns the session still open**: the state a kcptun client is in between
/// bursts, keepalive and all.
async fn smux_session_burst(
    addr: SocketAddr,
    case: &KcpCase,
    config: kcptun_smux::Config,
    seed: u64,
    bytes: u64,
) -> Result<Session<KcpConn>, String> {
    let session = UdpSession::dial_with_options(
        &addr.to_string(),
        case.block(),
        case.ds as isize,
        case.ps as isize,
    )
    .map_err(|e| format!("dial: {e}"))?;
    apply_case(&session, case);

    let mux = kcptun_smux::mux::client(KcpConn::new(session), Some(config))
        .map_err(|e| format!("smux client: {e}"))?;
    let stream = Arc::new(
        mux.open_stream()
            .await
            .map_err(|e| format!("open_stream: {e}"))?,
    );

    // Write everything and half-close, then read the echo back and verify it against the same
    // deterministic stream. The peer copies until the FIN, so the read ends by itself.
    let writer = tokio::spawn({
        let stream = Arc::clone(&stream);
        async move {
            let mut src = PrngStream::new(seed, bytes);
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = src.fill(&mut buf);
                if n == 0 {
                    break;
                }
                stream
                    .write(&buf[..n])
                    .await
                    .map_err(|e| format!("write: {e}"))?;
            }
            stream
                .close_write()
                .await
                .map_err(|e| format!("close_write: {e}"))
        }
    });

    let mut expected = PrngStream::new(seed, bytes);
    let mut expbuf = vec![0u8; 64 * 1024];
    let mut buf = vec![0u8; 64 * 1024];
    let mut received = 0u64;
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                let want = expected.fill(&mut expbuf[..n]);
                if want != n || expbuf[..n] != buf[..n] {
                    return Err(format!("echo mismatch around byte {received}"));
                }
                received += n as u64;
            }
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    writer.await.map_err(|e| format!("writer task: {e}"))??;
    if received != bytes {
        return Err(format!("echoed {received} of {bytes} bytes"));
    }

    let _ = stream.close().await;
    Ok(mux)
}

// ---------------------------------------------------------------------------------------------
// The `--idle` workload: what a session costs just by existing (plan 12.3c)
// ---------------------------------------------------------------------------------------------

/// A UDP socket that reads and discards, so the staircase's sessions have somewhere to point.
///
/// An idle KCP session writes nothing: `flush` has no segments, no acks and no probe to send,
/// so the sink is there for the one case that is not "nothing": a `sendto` to an *unbound*
/// loopback port would come back as an ICMP port-unreachable, and the session's socket would then
/// report `ECONNREFUSED` on a later call and colour the measurement with an error path.
struct UdpSink {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl UdpSink {
    async fn start() -> Result<UdpSink, String> {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(|e| format!("sink bind: {e}"))?;
        let addr = socket.local_addr().map_err(|e| format!("sink addr: {e}"))?;
        let task = tokio::spawn(async move {
            // One MTU-sized buffer, allocated once: the sink must not be part of what the
            // staircase measures.
            let mut buf = vec![0u8; 2048];
            while socket.recv_from(&mut buf).await.is_ok() {}
        });
        Ok(UdpSink { addr, task })
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for UdpSink {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The stages of the staircase: 0, 1, 2, 4, … up to and including `sessions`.
///
/// Powers of two rather than every integer because the interesting quantity is a slope over a
/// decade, and because each stage costs `--settle` seconds.
fn idle_stages(sessions: usize) -> Vec<usize> {
    let mut stages = vec![0usize];
    let mut n = 1usize;
    while n < sessions {
        stages.push(n);
        n *= 2;
    }
    stages.push(sessions);
    stages.dedup();
    stages
}

/// Dials `--sessions` idle client sessions in stages and samples after each one.
///
/// Every session gets the S1 profile through [`apply_case`], is dialled exactly as
/// `kcptun-client` dials one (`UdpSession::dial_with_options`, so it owns its socket, its read
/// loop, its tx pipeline and its updater), and is then left completely alone.
/// With `--churn G` the whole staircase runs `G` times, every session being closed and dropped
/// between generations. That second generation is the only thing here that measures a
/// *replacement* session, which is what a client dials after one dies, and it is the case where
/// an allocator can stop giving the receive batch a fresh untouched mapping (see the module
/// docs). Phase names are prefixed `genN-` when more than one generation runs, so a one-
/// generation CSV keeps the column names §7 of `docs/benchmarks/memory.md` was written against.
async fn idle_staircase(
    args: &Args,
    case: &KcpCase,
    start: Instant,
    peak: &mut u64,
) -> Result<Held, String> {
    let sink = UdpSink::start().await?;
    let addr = sink.addr().to_string();
    let settle = Duration::from_secs(args.settle);

    let mut sessions: Vec<Arc<UdpSession>> = Vec::with_capacity(args.sessions);
    for generation in 1..=args.churn {
        let tag = if args.churn > 1 {
            format!("gen{generation}-")
        } else {
            String::new()
        };
        for stage in idle_stages(args.sessions) {
            while sessions.len() < stage {
                let session = UdpSession::dial_with_options(
                    &addr,
                    case.block(),
                    case.ds as isize,
                    case.ps as isize,
                )
                .map_err(|e| format!("dial: {e}"))?;
                apply_case(&session, case);
                sessions.push(session);
            }
            tokio::time::sleep(settle).await;
            sample(&format!("{tag}sessions{stage}"), start, peak);
        }

        if generation < args.churn {
            // `close` cancels `die`, which is what ends the read loop task and frees the
            // `RecvBatch` it owns; dropping the `Arc` alone would not, since the tasks hold
            // clones of it. An already-closed session is not an error here.
            for session in sessions.drain(..) {
                let _ = session.close();
            }
            // Long enough for the cancelled tasks to be reaped before the next generation dials.
            tokio::time::sleep(settle).await;
            sample(&format!("{tag}dropped"), start, peak);
        }
    }
    Ok(Held::Idle(sink, sessions))
}

/// What the burst leaves alive through the decay.
///
/// The variant matters more than it looks: in `--smux` mode the sessions are still up, so their
/// keepalive is still writing, which is precisely the condition that decides whether
/// `memory::trim_when_idle` ever fires.
enum Held {
    /// Raw-KCP mode. `--keep` holds the echo listener; otherwise nothing survives the burst.
    Kcp(Option<RustEchoServer>),
    /// smux mode: the echo server and the client's `--sessions` sessions, streams closed.
    Smux(SmuxEchoServer, Vec<Session<KcpConn>>),
    /// `--idle` mode: the sink task and every session of the staircase, none of which has ever
    /// carried a byte.
    Idle(UdpSink, Vec<Arc<UdpSession>>),
}

impl std::fmt::Display for Held {
    /// What the decay rows below are measuring against, logged once so a CSV can be read back
    /// without knowing which flags produced it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Held::Kcp(server) => write!(
                f,
                "raw KCP, echo listener {}",
                if server.is_some() { "held" } else { "closed" }
            ),
            Held::Smux(server, sessions) => write!(
                f,
                "smux over KCP on {}, {} sessions held open, {} streams still in them",
                server.addr(),
                sessions.len(),
                sessions.iter().map(Session::num_streams).sum::<usize>(),
            ),
            Held::Idle(sink, sessions) => write!(
                f,
                "idle staircase, {} sessions dialled at the sink on {}, no bytes transferred",
                sessions.len(),
                sink.addr(),
            ),
        }
    }
}

fn main() -> Result<(), String> {
    let args = parse_args()?;
    #[cfg(feature = "dhat")]
    let dhat = dhat::Profiler::new_heap();

    // The binaries' own runtime (D01: one worker per CPU, `GOMAXPROCS` honoured), so that the
    // probe measures the thread layout a shipped process has.
    let runtime = kcptun_std::runtime::build().map_err(|e| format!("runtime: {e}"))?;
    let result = runtime.block_on(run(&args));

    // With `--dump-at-close` the sessions, the runtime and its tasks are all still alive here,
    // which is the whole point: the profiler's report then describes what the program retains
    // after a burst rather than what is left once everything has been dropped.
    #[cfg(feature = "dhat")]
    drop(dhat);
    if args.dump_at_close {
        // Skip the orderly runtime shutdown for the same reason.
        result.as_ref().map_err(|e| eprintln!("memprobe: {e}")).ok();
        std::process::exit(i32::from(result.is_err()));
    }
    result
}

async fn run(args: &Args) -> Result<(), String> {
    let start = Instant::now();
    let mut peak = 0u64;
    println!("phase,t_ms,rss_kb,peak_rss_kb,heap_curr_b,heap_max_b,pool_parked");

    if args.auto_trim {
        tokio::spawn(kcptun_kcp::memory::trim_when_idle(Duration::from_secs(
            args.interval,
        )));
    }

    let case = production_case();
    // Loopback, an ephemeral port: the probe is a single process and never listens outside it.
    let listen: SocketAddr = "127.0.0.1:0"
        .parse()
        .map_err(|e| format!("listen addr: {e}"))?;
    sample("start", start, &mut peak);

    let held = if args.idle {
        idle_staircase(args, &case, start, &mut peak).await?
    } else if args.smux {
        smux_burst(args, &case, listen, start, &mut peak).await?
    } else {
        kcp_burst(args, &case, listen, start, &mut peak).await?
    };
    eprintln!("memprobe: into the decay with {held}");
    if args.dump_at_close {
        // Deliberately never dropped: `main` exits the process from here, and the point of the
        // flag is that dhat's "at t-end" snapshot sees everything the burst left alive: the
        // smux sessions above all. A leak in the last microsecond of a measurement binary.
        std::mem::forget(held);
        return Ok(());
    }

    let deadline = Instant::now() + Duration::from_secs(args.decay);
    while Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(args.interval)).await;
        let secs = start.elapsed().as_secs();
        sample(&format!("decay+{secs}s"), start, &mut peak);
    }

    if args.trim {
        let freed = kcptun_kcp::memory::trim();
        eprintln!("memprobe: trim() -> {freed}");
        tokio::time::sleep(Duration::from_millis(500)).await;
        sample("after-trim", start, &mut peak);
        tokio::time::sleep(Duration::from_secs(5)).await;
        sample("after-trim+5s", start, &mut peak);
    }
    // Held until here on purpose: in `--smux` mode this is what keeps the keepalive ticking
    // through every decay sample above.
    drop(held);
    Ok(())
}

/// The default workload: `--sessions` echoes straight over KCP, nothing above it.
async fn kcp_burst(
    args: &Args,
    case: &KcpCase,
    listen: SocketAddr,
    start: Instant,
    peak: &mut u64,
) -> Result<Held, String> {
    let server = RustEchoServer::start(listen, case, Some(Duration::from_secs(120)))
        .map_err(|e| format!("echo server: {e}"))?;
    let addr = server.addr();
    tokio::time::sleep(Duration::from_secs(1)).await;
    sample("idle", start, peak);

    // The burst: `sessions` echoes in parallel, each `bytes` long in each direction.
    let mut clients = Vec::with_capacity(args.sessions);
    for i in 0..args.sessions {
        let case = case.clone();
        let run = RustClientRun::new(addr, args.bytes)
            .seed(i as u64 + 1)
            .timeout(Duration::from_secs(600));
        clients.push(tokio::spawn(
            async move { run_rust_client(&run, &case).await },
        ));
    }
    let mut ok = true;
    for client in clients {
        let report = client.await.map_err(|e| format!("client task: {e}"))?;
        if !report.ok {
            ok = false;
            eprintln!(
                "memprobe: session failed: received {} of {} bytes: {}",
                report.received,
                report.bytes,
                report.error.as_deref().unwrap_or("verification mismatch")
            );
        }
    }
    if !ok {
        return Err("memprobe: at least one session did not complete".to_string());
    }
    sample("burst-end", start, peak);

    // The sessions are closed by `run_rust_client` returning, unless the caller asked to keep the
    // server's accepted sessions alive (`--keep` keeps the listener from reaping them early).
    if args.keep {
        return Ok(Held::Kcp(Some(server)));
    }
    drop(server);
    tokio::time::sleep(Duration::from_millis(500)).await;
    sample("closed", start, peak);
    Ok(Held::Kcp(None))
}

/// The `--smux` workload: the same burst through smux over KCP, with the streams closed at the
/// end and the sessions (and their keepalive) kept for the whole decay.
async fn smux_burst(
    args: &Args,
    case: &KcpCase,
    listen: SocketAddr,
    start: Instant,
    peak: &mut u64,
) -> Result<Held, String> {
    let config = production_smux_config()?;
    let server = SmuxEchoServer::start(listen, case, config)?;
    let addr = server.addr();
    tokio::time::sleep(Duration::from_secs(1)).await;
    sample("idle", start, peak);

    let mut clients = Vec::with_capacity(args.sessions);
    for i in 0..args.sessions {
        let case = case.clone();
        let bytes = args.bytes;
        clients.push(tokio::spawn(async move {
            smux_session_burst(addr, &case, config, i as u64 + 1, bytes).await
        }));
    }
    let mut sessions = Vec::with_capacity(args.sessions);
    let mut failure = None;
    for client in clients {
        match client.await.map_err(|e| format!("client task: {e}"))? {
            Ok(session) => sessions.push(session),
            Err(e) => {
                eprintln!("memprobe: session failed: {e}");
                failure.get_or_insert(e);
            }
        }
    }
    if let Some(e) = failure {
        return Err(format!(
            "memprobe: at least one session did not complete: {e}"
        ));
    }
    sample("burst-end", start, peak);

    // Every stream is closed; the sessions are not. `--keep` has no meaning here, because
    // keeping the sessions *is* the mode.
    tokio::time::sleep(Duration::from_millis(500)).await;
    sample("closed", start, peak);
    Ok(Held::Smux(server, sessions))
}
