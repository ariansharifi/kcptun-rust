//! Loopback echo throughput and CPU baseline of the KCP session layer, Rust↔Rust against
//! Go↔Go (plan step 05.9).
//!
//! One measurement is one echo of `bytes` payload over a loopback KCP session: the client
//! writes the deterministic stream in `chunk`-sized `Write`s, the server writes back everything
//! it reads, and the client verifies every byte. Both implementations run the *same* peers the
//! interop suite uses, so a number here describes the port, not a bespoke benchmark:
//!
//! | Side | Server | Client | CPU counted with |
//! |---|---|---|---|
//! | `rs` | [`RustEchoServer`] in this process | [`run_rust_client`] in this process | `getrusage(RUSAGE_SELF)` |
//! | `go` | `kcpecho server` | `kcpecho client` | `getrusage(RUSAGE_CHILDREN)` |
//!
//! The wall time is the client's own dial-to-last-byte time (process start-up is outside it on
//! both sides) and the CPU is *both* endpoints together: one process for Rust, two for Go.
//! Four caveats follow from that and matter when reading the table:
//!
//! - The two timing windows are *not* exactly the same span. Go's `kcpecho client` starts its
//!   clock after `DialWithOptions` and after `k.block()` (PBKDF2, 4096 rounds) and the option
//!   setters; [`run_rust_client`] starts its clock before all of that, so the Rust window also
//!   contains key derivation, the socket bind and the setters. That is on the order of a
//!   millisecond per run (under 1 % of a half-second run) and it counts *against* Rust.
//! - Rust's client and server share one tokio runtime and one address space, Go's are two
//!   processes with a runtime each, so Go pays two runtime start-ups (single-digit
//!   milliseconds) while Rust may win a little on locality. Step 12 splits the two endpoints.
//! - The CPU includes what the *harness* work costs on each side: generating the stream and
//!   verifying and hashing the echo, because both clients do exactly that
//!   (`peer.Stream`/`peer.Verifier` in Go, `PrngStream`/`Verifier` here).
//! - Wall time on a loaded machine is far noisier than CPU time, which is why every group is
//!   repeated and reported as a median *with its min and max* ([`spread_table`]): a median of
//!   three noisy samples is not a measurement to two decimal places.
//!
//! Profiles ([`profiles`]) are kcptun's defaults (`aes`, FEC 10/3) and the production setting
//! this port is aimed at (`xor`, no FEC, 8192-packet windows, MTU 1390); message sizes are
//! [`MESSAGE_SIZES`] and payloads [`DEFAULT_PAYLOADS`]. More than one payload size is measured
//! on purpose: the two profiles do not behave alike, and the production one used to be *payload
//! dependent*: it had a degradation band, worst at 8 MiB on every host measured, which two
//! steps of the tx path removed ([`DEFAULT_PAYLOADS`] has the measurements and the history), so
//! a single hard-coded payload would report whichever regime it happened to land in, and the two
//! payloads are what keeps that band from coming back unnoticed. The three message sizes are kcp-go's
//! `BenchmarkEchoSpeed4K/64K/512K` family. The numbers are a smoke baseline for Step 12, not a
//! tuned benchmark: loopback has no loss and no RTT, so they say what the implementations cost, not
//! what a link would deliver.

use std::fmt;
use std::io;
use std::path::Path;
use std::time::Duration;

use kcptun_testkit::cpu::{self, CpuTime};
use kcptun_testkit::ports;

use crate::bins::Impl;
use crate::kcp::{KcpCase, RustClientRun, RustEchoServer, run_rust_client};
use crate::kcpecho::{self, ClientRun};

/// Payload sizes per `Write`/`Read` call, the `-chunk` of `kcpecho client`: 4 KiB is a
/// small-message workload (many KCP segments per write, ~3 datagrams at MTU 1350) and 64 KiB is
/// kcptun's bulk case (smux's largest frames are 8 KiB, but a fast TCP copy writes much more).
pub const MESSAGE_SIZES: [usize; 3] = [4 * 1024, 64 * 1024, 512 * 1024];

/// Payloads echoed per measurement, unless the caller overrides them. Two sizes, not one,
/// because the production profile (`xor`, no FEC, 8192-packet windows, MTU 1390) **had** a
/// degradation band that a single payload would either sit inside or miss entirely, while the
/// default profile never had one. Both payloads stay in the sweep as the regression test for
/// that band.
///
/// The band was the port's, not the protocol's: one `flush()` emits a whole send window, and
/// the surplus over the session's packet channel was dropped after KCP had already counted it
/// as transmitted, so the transfer stepped through retransmission timeouts (Deviations V13 and
/// **V18**). Two steps removed it: 05.10 widened the channel to the window, 12.2a replaced
/// dropping with backpressure in `Kcp::flush` and returned the channel to Go's 2048, and the
/// state of the production profile at each of them is, as rs/go throughput for 4 KiB / 64 KiB /
/// 512 KiB messages (above 1.00x Rust is faster):
///
/// | payload | host | 05.9 (drop, 2048) | 05.10 (drop, 8192) | 12.2a (backpressure, 2048) |
/// |---|---|---|---|---|
/// |  8 MiB | macOS arm64 | 0.25x / 0.19x /: | 1.88x / 1.56x / 1.53x | 1.82x / 1.69x / 1.70x |
/// | 32 MiB | macOS arm64 | 1.53x / 1.20x /: | 2.33x / 2.36x / 2.42x | 2.74x / 2.83x / 2.63x |
/// |  8 MiB | lab-arm64 aarch64 | 0.34x / 0.26x /: | 1.17x / 1.17x / 0.96x | 1.32x / 1.10x / 1.03x |
/// | 32 MiB | lab-arm64 aarch64 | 0.70x / 0.63x /: | 0.77x / 0.77x / 0.70x | 1.12x / 1.38x / 1.02x |
///
/// The 2 vCPU Linux host is where it mattered: widening the channel alone left 32 MiB at
/// 0.70-0.77x Go and CPU per GB *above* Go's (1.04-1.15x), and backpressure is what turns that
/// into 1.02-1.38x at 0.68-0.86x CPU per GB. The default profile is unchanged by all of this
/// (1.77-1.99x Go at 0.54-0.56x CPU per GB on lab-arm64, 1.22-1.42x at 0.33-0.48x on macOS),
/// which is the point: the checks are inert until the channel actually fills.
///
/// Hosts: macOS 27.0 arm64, 10 cores, release build, medians of 3 runs (load average 1.5-2.9;
/// wall time on a busy laptop is noisy, so read the min-max columns); lab-arm64 (Ubuntu 24.04,
/// aarch64 Neoverse-N1, 2 vCPU), load average 0.11 at the start of each sweep, release build
/// cross-compiled with `cargo-zigbuild`, medians of 3 runs. CPU seconds per GB compare the two
/// implementations *within* one host only: the two hosts have different CPUs, so the
/// CPU-ratio difference between them is a per-host observation, not a trend.
pub const DEFAULT_PAYLOADS: [u64; 2] = [8 * 1024 * 1024, 32 * 1024 * 1024];

/// Measurements per (implementation, profile, payload, message size) combination; the reported
/// number is their median, always next to the min and max of the same group.
pub const DEFAULT_REPEATS: usize = 3;

/// Deadline of one run, on both sides (`kcpecho client -timeout`, and the Rust session
/// deadline).
pub const RUN_TIMEOUT: Duration = Duration::from_secs(120);

/// How long a server waits on an idle session before reaping it, passed to both sides
/// (`kcpecho server -idle`, and [`RustEchoServer::start`]).
///
/// Deliberately short. Closing the Rust listener does not close the sessions it already
/// accepted, but it does hand every one of them the `use of closed network connection` read
/// error (recorded in step 05.7), which releases their blocked reads, so the echo tasks
/// of [`RustEchoServer`] close their sessions right after [`measure_rust`]'s `server.close()`.
/// This timeout is the backstop for a session whose peer vanished before that, and it stops such
/// a session from still waking its update and tx tasks inside a *later* measurement's CPU
/// window; the Go server gets the same value. Runs are sub-second on loopback and a stalled one
/// steps in retransmission timeouts of a few hundred milliseconds, so this is far above any
/// legitimate gap in a live session.
pub const IDLE: Duration = Duration::from_secs(5);

/// Time the harness waits after the client is done before it stops counting CPU, so that the
/// last ACKs and the final flush of both endpoints are included on both sides.
const SETTLE: Duration = Duration::from_millis(200);

/// One named KCP configuration to measure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// Short name for the table (`default`, `production`).
    pub name: &'static str,
    /// The configuration itself, applied identically to both implementations.
    pub case: KcpCase,
}

/// kcptun's defaults as the client ships them: `-crypt aes`, FEC 10/3, MTU 1350, windows
/// 128/512, `-mode fast`.
// Go: kcptun client/main.go (cli flag defaults)
pub fn default_profile() -> Profile {
    Profile {
        name: "default",
        case: KcpCase::new(),
    }
}

/// The configuration this port is aimed at in production: `-crypt xor` (near-free packet
/// crypto), no FEC, 8192-packet windows on both sides and MTU 1390.
pub fn production_profile() -> Profile {
    Profile {
        name: "production",
        case: KcpCase::new()
            .crypt("xor")
            .fec(0, 0)
            .windows(8192, 8192)
            .mtu(1390),
    }
}

/// The profiles the smoke run measures, in table order.
pub fn profiles() -> [Profile; 2] {
    [default_profile(), production_profile()]
}

/// What one echo run cost.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Measurement {
    /// Which implementation ran both endpoints.
    pub implementation: Impl,
    /// [`Profile::name`].
    pub profile: &'static str,
    /// Bytes per `Write` call.
    pub chunk: usize,
    /// Payload echoed (one direction; the link carries it twice).
    pub bytes: u64,
    /// The client's own dial-to-last-byte time.
    pub duration: Duration,
    /// CPU of both endpoints together.
    pub cpu: CpuTime,
}

impl Measurement {
    /// Payload throughput in MiB/s, counting the payload once (the wire carries `2 × bytes`).
    pub fn mib_per_sec(&self) -> f64 {
        let secs = self.duration.as_secs_f64();
        if secs <= 0.0 {
            return 0.0;
        }
        self.bytes as f64 / (1024.0 * 1024.0) / secs
    }

    /// CPU seconds both endpoints spent per GB (10⁹ bytes) of echoed payload.
    pub fn cpu_secs_per_gb(&self) -> f64 {
        if self.bytes == 0 {
            return 0.0;
        }
        self.cpu.total().as_secs_f64() * 1e9 / self.bytes as f64
    }

    /// One line for the progress log, e.g.
    /// `rs default   4 KiB  32 MiB in 1.234 s = 25.9 MiB/s, 0.500 s cpu (…) = 14.9 CPU s/GB`.
    ///
    /// The payload is labelled with [`size_label`], as the tables are, so that a
    /// `KCPTUN_BENCH_BYTES` override below 1 MiB still prints its own size.
    pub fn line(&self) -> String {
        format!(
            "{:<2} {:<10} {:>6}  {} in {:.3} s = {:.1} MiB/s, {} = {:.2} CPU s/GB",
            self.implementation.tag(),
            self.profile,
            size_label(self.chunk as u64),
            size_label(self.bytes),
            self.duration.as_secs_f64(),
            self.mib_per_sec(),
            self.cpu,
            self.cpu_secs_per_gb(),
        )
    }
}

impl fmt::Display for Measurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.line())
    }
}

/// `4 KiB`, `64 KiB`, `32 MiB`, … for the tables.
pub fn size_label(bytes: u64) -> String {
    if bytes >= 1024 * 1024 && bytes.is_multiple_of(1024 * 1024) {
        format!("{} MiB", bytes / (1024 * 1024))
    } else if bytes >= 1024 && bytes.is_multiple_of(1024) {
        format!("{} KiB", bytes / 1024)
    } else {
        format!("{bytes} B")
    }
}

/// Median, min and max of one metric over the repeats of a group.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Stat {
    /// Median of the repeats: the headline number.
    pub median: f64,
    /// Smallest repeat.
    pub min: f64,
    /// Largest repeat.
    pub max: f64,
}

impl Stat {
    /// Median, min and max of `values`; all zero for an empty slice.
    pub fn of(values: &[f64]) -> Stat {
        Stat {
            median: median(values),
            min: values.iter().copied().fold(f64::INFINITY, f64::min),
            max: values.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        }
        .or_zero(values.is_empty())
    }

    fn or_zero(self, empty: bool) -> Stat {
        if empty {
            Stat {
                median: 0.0,
                min: 0.0,
                max: 0.0,
            }
        } else {
            self
        }
    }

    /// `min-max` at `digits` decimals, for the column next to the median.
    pub fn range_label(&self, digits: usize) -> String {
        format!("{:.digits$}-{:.digits$}", self.min, self.max)
    }
}

/// The repeats of one (implementation, profile, payload, message size) group, summarised.
#[derive(Clone, Debug, PartialEq)]
pub struct Summary {
    /// Which implementation.
    pub implementation: Impl,
    /// [`Profile::name`].
    pub profile: &'static str,
    /// Payload echoed per run.
    pub bytes: u64,
    /// Bytes per `Write` call.
    pub chunk: usize,
    /// How many measurements went into the statistics.
    pub runs: usize,
    /// Payload throughput, MiB/s.
    pub mib_per_sec: Stat,
    /// CPU seconds per GB of payload.
    pub cpu_secs_per_gb: Stat,
}

/// Median of `values`; the mean of the two middle values for an even count. Returns 0 for an
/// empty slice.
pub fn median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut v = values.to_vec();
    v.sort_by(f64::total_cmp);
    let mid = v.len() / 2;
    if v.len().is_multiple_of(2) {
        (v[mid - 1] + v[mid]) / 2.0
    } else {
        v[mid]
    }
}

/// Groups `measurements` by (profile, payload, message size, implementation): keeping the order
/// they were measured in, and summarises each group.
pub fn summarise(measurements: &[Measurement]) -> Vec<Summary> {
    let mut out: Vec<Summary> = Vec::new();
    for m in measurements {
        let key = (m.profile, m.bytes, m.chunk, m.implementation);
        if out
            .iter()
            .any(|s| (s.profile, s.bytes, s.chunk, s.implementation) == key)
        {
            continue;
        }
        let group: Vec<&Measurement> = measurements
            .iter()
            .filter(|o| (o.profile, o.bytes, o.chunk, o.implementation) == key)
            .collect();
        let rates: Vec<f64> = group.iter().map(|o| o.mib_per_sec()).collect();
        let cpu: Vec<f64> = group.iter().map(|o| o.cpu_secs_per_gb()).collect();
        out.push(Summary {
            implementation: m.implementation,
            profile: m.profile,
            bytes: m.bytes,
            chunk: m.chunk,
            runs: group.len(),
            mib_per_sec: Stat::of(&rates),
            cpu_secs_per_gb: Stat::of(&cpu),
        });
    }
    out
}

/// Column widths of [`comparison_table`], shared by the header, the rule and every row so that
/// the table always lines up.
const TABLE_WIDTHS: [usize; 11] = [11, 7, 7, 5, 9, 9, 6, 11, 11, 6, 22];

/// Column widths of [`spread_table`].
const SPREAD_WIDTHS: [usize; 8] = [11, 7, 7, 4, 5, 9, 15, 22];

/// One table line: the first cell left-aligned, the rest right-aligned, one space between
/// columns. A cell wider than its column pushes the rest right rather than being truncated.
fn table_row(widths: &[usize], cells: &[String]) -> String {
    let mut line = String::new();
    for (i, (cell, w)) in cells.iter().zip(widths.iter().copied()).enumerate() {
        if i > 0 {
            line.push(' ');
        }
        if i == 0 {
            line.push_str(&format!("{cell:<w$}"));
        } else {
            line.push_str(&format!("{cell:>w$}"));
        }
    }
    line.push('\n');
    line
}

/// `-` rule under a header of `widths`.
fn table_rule(widths: &[usize]) -> String {
    let cells: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    table_row(widths, &cells)
}

/// The (profile, payload, message size) rows both tables use, in measurement order.
fn table_rows(summaries: &[Summary]) -> Vec<(&'static str, u64, usize)> {
    let mut rows: Vec<(&'static str, u64, usize)> = Vec::new();
    for s in summaries {
        if !rows.contains(&(s.profile, s.bytes, s.chunk)) {
            rows.push((s.profile, s.bytes, s.chunk));
        }
    }
    rows
}

/// The Rust-versus-Go table: one row per (profile, payload, message size), with the medians of
/// both implementations and the Rust/Go ratios (throughput: higher is better for Rust; CPU:
/// lower is better). A missing side prints `-`.
///
/// The last column repeats the two implementations' throughput *ranges* over the repeats, so
/// that the `rs/go` ratio next to it cannot be read as more precise than the samples behind it;
/// [`spread_table`] gives the same for CPU.
pub fn comparison_table(measurements: &[Measurement]) -> String {
    let summaries = summarise(measurements);
    let find = |profile: &'static str, bytes: u64, chunk: usize, imp: Impl| -> Option<&Summary> {
        summaries.iter().find(|s| {
            s.profile == profile && s.bytes == bytes && s.chunk == chunk && s.implementation == imp
        })
    };
    let num = |v: Option<f64>, digits: usize| match v {
        Some(v) => format!("{v:.digits$}"),
        None => "-".to_string(),
    };
    let ratio = |a: Option<f64>, b: Option<f64>| match (a, b) {
        (Some(a), Some(b)) if b > 0.0 => format!("{:.2}x", a / b),
        _ => "-".to_string(),
    };
    let range = |s: Option<&Summary>| match s {
        Some(s) => s.mib_per_sec.range_label(1),
        None => "-".to_string(),
    };

    let mut out = table_row(
        &TABLE_WIDTHS,
        &[
            "profile".into(),
            "payload".into(),
            "msg".into(),
            "runs".into(),
            "rs MiB/s".into(),
            "go MiB/s".into(),
            "rs/go".into(),
            "rs CPU/GB".into(),
            "go CPU/GB".into(),
            "rs/go".into(),
            "MiB/s rs | go range".into(),
        ],
    );
    out.push_str(&table_rule(&TABLE_WIDTHS));
    for (profile, bytes, chunk) in table_rows(&summaries) {
        let rs = find(profile, bytes, chunk, Impl::Rust);
        let go = find(profile, bytes, chunk, Impl::Go);
        let runs = rs.map_or(0, |s| s.runs).max(go.map_or(0, |s| s.runs));
        out.push_str(&table_row(
            &TABLE_WIDTHS,
            &[
                profile.to_string(),
                size_label(bytes),
                size_label(chunk as u64),
                runs.to_string(),
                num(rs.map(|s| s.mib_per_sec.median), 1),
                num(go.map(|s| s.mib_per_sec.median), 1),
                ratio(
                    rs.map(|s| s.mib_per_sec.median),
                    go.map(|s| s.mib_per_sec.median),
                ),
                num(rs.map(|s| s.cpu_secs_per_gb.median), 2),
                num(go.map(|s| s.cpu_secs_per_gb.median), 2),
                ratio(
                    rs.map(|s| s.cpu_secs_per_gb.median),
                    go.map(|s| s.cpu_secs_per_gb.median),
                ),
                format!("{} | {}", range(rs), range(go)),
            ],
        ));
    }
    out
}

/// Per-group min, median and max of both metrics, one row per (profile, payload, message size,
/// implementation): the spread behind every median of [`comparison_table`].
pub fn spread_table(measurements: &[Measurement]) -> String {
    let summaries = summarise(measurements);
    let mut out = table_row(
        &SPREAD_WIDTHS,
        &[
            "profile".into(),
            "payload".into(),
            "msg".into(),
            "impl".into(),
            "runs".into(),
            "MiB/s med".into(),
            "MiB/s min-max".into(),
            "CPU/GB med min-max".into(),
        ],
    );
    out.push_str(&table_rule(&SPREAD_WIDTHS));
    for (profile, bytes, chunk) in table_rows(&summaries) {
        for s in summaries
            .iter()
            .filter(|s| s.profile == profile && s.bytes == bytes && s.chunk == chunk)
        {
            out.push_str(&table_row(
                &SPREAD_WIDTHS,
                &[
                    profile.to_string(),
                    size_label(bytes),
                    size_label(chunk as u64),
                    s.implementation.tag().to_string(),
                    s.runs.to_string(),
                    format!("{:.1}", s.mib_per_sec.median),
                    s.mib_per_sec.range_label(1),
                    format!(
                        "{:.2} {}",
                        s.cpu_secs_per_gb.median,
                        s.cpu_secs_per_gb.range_label(2)
                    ),
                ],
            ));
        }
    }
    out
}

/// Runs one Rust↔Rust echo and measures it.
///
/// Must be called from inside a tokio runtime, and it must be the only work that runtime is
/// doing: the CPU reading covers the whole process. The echo server is started and closed
/// inside the call, so nothing survives it but the port allocation.
pub async fn measure_rust(
    profile: &Profile,
    chunk: usize,
    bytes: u64,
) -> Result<Measurement, String> {
    let addr = ports::allocate(1).addr(0);
    // Counted from before the server exists, because the Go side's `RUSAGE_CHILDREN` reading
    // starts before its server process does: both include binding the socket and deriving the
    // key (PBKDF2, 4096 rounds) on both endpoints.
    let before = self_cpu()?;
    let server = RustEchoServer::start(addr, &profile.case, Some(IDLE))
        .map_err(|e| format!("rust echo server on {addr}: {e}"))?;
    let run = RustClientRun {
        remote: server.addr(),
        bytes,
        seed: 1,
        chunk,
        timeout: RUN_TIMEOUT,
    };
    let report = run_rust_client(&run, &profile.case).await;
    // Settle, then tear down, then read: the same order as `measure_go`, so that the listener
    // close falls inside this window just as the Go server's kill falls inside that one.
    tokio::time::sleep(SETTLE).await;
    server.close();
    let cpu = self_cpu()?.saturating_sub(before);

    if !report.ok || report.sha256 != report.expected_sha256 {
        return Err(format!(
            "rust echo failed ({}): received {} of {} bytes, error {:?}",
            profile.case.label(),
            report.received,
            report.bytes,
            report.error
        ));
    }
    Ok(Measurement {
        implementation: Impl::Rust,
        profile: profile.name,
        chunk,
        bytes,
        duration: Duration::from_millis(report.duration_ms as u64),
        cpu,
    })
}

/// Runs one Go↔Go echo (`kcpecho server` plus `kcpecho client`, `bin` being the binary
/// [`go_bin`](crate::go_bin) found) and measures it.
///
/// Blocking, and it must be the only place reaping children while it runs: the CPU reading is
/// `RUSAGE_CHILDREN`, which counts every child this process waits for.
pub fn measure_go(
    bin: &Path,
    profile: &Profile,
    chunk: usize,
    bytes: u64,
) -> Result<Measurement, String> {
    let listen = ports::allocate(1).addr(0);
    let before = children_cpu()?;

    // `-idle` is passed explicitly rather than left to `kcpecho`'s default, so that both servers
    // get their idle timeout from `IDLE` and a change to the Go default cannot desynchronise
    // them (`KcpCase::kcpecho_args`).
    let mut server_args = profile.case.kcpecho_args();
    server_args.push("-idle".into());
    server_args.push(IDLE.as_secs().to_string());
    let (mut server, _printed) = kcpecho::start_server(bin, listen, server_args)
        .map_err(|e| format!("kcpecho server on {listen}: {e}"))?;
    let run = ClientRun::new(listen, bytes).timeout_secs(RUN_TIMEOUT.as_secs());
    let mut args = profile.case.kcpecho_args();
    args.push("-chunk".into());
    args.push(chunk.to_string());
    let outcome = kcpecho::run_client(bin, &run, args).map_err(|e| format!("kcpecho client: {e}"));

    // Both processes must be reaped before the counter is read, and the server must have had
    // the same settling time the Rust side gets.
    std::thread::sleep(SETTLE);
    let killed = server.kill();
    let cpu = children_cpu()?.saturating_sub(before);

    let outcome = outcome?;
    killed.map_err(|e| format!("kcpecho server: {e}"))?;
    let report = outcome
        .report
        .ok_or_else(|| format!("kcpecho client printed no report; log:\n{}", outcome.log))?;
    if !report.ok || report.sha256 != report.expected_sha256 {
        return Err(format!(
            "go echo failed ({}): received {} of {} bytes, error {:?}",
            profile.case.label(),
            report.received,
            report.bytes,
            report.error
        ));
    }
    Ok(Measurement {
        implementation: Impl::Go,
        profile: profile.name,
        chunk,
        bytes,
        duration: Duration::from_millis(report.duration_ms.max(0) as u64),
        cpu,
    })
}

fn self_cpu() -> Result<CpuTime, String> {
    cpu::self_cpu().map_err(|e: io::Error| format!("getrusage(RUSAGE_SELF): {e}"))
}

fn children_cpu() -> Result<CpuTime, String> {
    cpu::children_cpu().map_err(|e: io::Error| format!("getrusage(RUSAGE_CHILDREN): {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A measurement of exactly 1 GB (10⁹ B), so that `cpu_secs_per_gb` is the CPU seconds and
    /// the arithmetic in the assertions stays readable.
    fn measurement(
        imp: Impl,
        profile: &'static str,
        chunk: usize,
        ms: u64,
        cpu_ms: u64,
    ) -> Measurement {
        Measurement {
            implementation: imp,
            profile,
            chunk,
            bytes: 1_000_000_000,
            duration: Duration::from_millis(ms),
            cpu: CpuTime {
                user: Duration::from_millis(cpu_ms),
                system: Duration::ZERO,
            },
        }
    }

    /// The same with an explicit payload, for the grouping and labelling tests.
    fn sized(
        imp: Impl,
        profile: &'static str,
        bytes: u64,
        chunk: usize,
        ms: u64,
        cpu_ms: u64,
    ) -> Measurement {
        Measurement {
            bytes,
            ..measurement(imp, profile, chunk, ms, cpu_ms)
        }
    }

    #[test]
    fn the_profiles_are_kcptun_defaults_and_the_production_setting() {
        let [default, production] = profiles();
        assert_eq!(default.name, "default");
        assert_eq!(
            default.case.label(),
            "crypt=aes fec=10/3 mtu=1350 wnd=128/512 acknodelay=off mode=fast",
        );
        assert_eq!(production.name, "production");
        assert_eq!(
            production.case.label(),
            "crypt=xor fec=0/0 mtu=1390 wnd=8192/8192 acknodelay=off mode=fast",
        );
        // Both sides are configured from the same case, so the Go flags must spell it out too.
        let args = production.case.kcpecho_args().join(" ");
        assert!(args.contains("-crypt xor"), "{args}");
        assert!(args.contains("-ds 0 -ps 0"), "{args}");
        assert!(args.contains("-mtu 1390"), "{args}");
        assert!(args.contains("-sndwnd 8192 -rcvwnd 8192"), "{args}");
    }

    #[test]
    fn throughput_and_cpu_per_gb_are_per_payload_byte() {
        // 1 GB (10^9 B) echoed in 2 s with 3 s of CPU.
        let m = measurement(Impl::Rust, "default", 4096, 2000, 3000);
        assert!(
            (m.mib_per_sec() - 476.837).abs() < 0.01,
            "{}",
            m.mib_per_sec()
        );
        assert!(
            (m.cpu_secs_per_gb() - 3.0).abs() < 1e-9,
            "{}",
            m.cpu_secs_per_gb()
        );
        assert!(m.line().starts_with("rs default     4 KiB"), "{}", m.line());
        assert!(m.line().contains("CPU s/GB"), "{}", m.line());

        // A payload that is not a whole number of MiB must be labelled, not truncated:
        // `KCPTUN_BENCH_BYTES` may name any size, including one below 1 MiB.
        let mut small = m.clone();
        small.bytes = 512 * 1024;
        assert!(small.line().contains("512 KiB in"), "{}", small.line());
        let mut odd = m.clone();
        odd.bytes = 1536 * 1024;
        assert!(odd.line().contains("1536 KiB in"), "{}", odd.line());

        // Degenerate inputs must not divide by zero.
        let mut zero = m.clone();
        zero.duration = Duration::ZERO;
        zero.bytes = 0;
        assert_eq!(zero.mib_per_sec(), 0.0);
        assert_eq!(zero.cpu_secs_per_gb(), 0.0);
    }

    #[test]
    fn median_of_odd_and_even_counts() {
        assert!((median(&[3.0, 1.0, 2.0]) - 2.0).abs() < 1e-9);
        assert!((median(&[4.0, 1.0, 3.0, 2.0]) - 2.5).abs() < 1e-9);
        assert!((median(&[7.5]) - 7.5).abs() < 1e-9);
        assert_eq!(median(&[]), 0.0);
    }

    #[test]
    fn summaries_take_the_median_per_group_in_measurement_order() {
        let ms = vec![
            measurement(Impl::Rust, "default", 4096, 1000, 1000),
            measurement(Impl::Go, "default", 4096, 4000, 8000),
            measurement(Impl::Rust, "default", 4096, 2000, 3000),
            measurement(Impl::Rust, "default", 4096, 4000, 2000),
            measurement(Impl::Go, "default", 4096, 2000, 4000),
            measurement(Impl::Go, "default", 4096, 8000, 6000),
        ];
        let s = summarise(&ms);
        assert_eq!(s.len(), 2, "one summary per (profile, payload, size, impl)");
        assert_eq!(s[0].implementation, Impl::Rust, "measurement order is kept");
        assert_eq!(s[0].runs, 3);
        // Durations 1/2/4 s for 1 GB: statistics are per metric, not per run.
        assert!(
            (s[0].mib_per_sec.median - 476.837).abs() < 0.01,
            "{:?}",
            s[0]
        );
        assert!((s[0].mib_per_sec.min - 238.418).abs() < 0.01, "{:?}", s[0]);
        assert!((s[0].mib_per_sec.max - 953.674).abs() < 0.01, "{:?}", s[0]);
        assert!(
            (s[0].cpu_secs_per_gb.median - 2.0).abs() < 1e-9,
            "{:?}",
            s[0]
        );
        assert!((s[0].cpu_secs_per_gb.min - 1.0).abs() < 1e-9, "{:?}", s[0]);
        assert!((s[0].cpu_secs_per_gb.max - 3.0).abs() < 1e-9, "{:?}", s[0]);
        assert_eq!(s[1].implementation, Impl::Go);
        assert!(
            (s[1].cpu_secs_per_gb.median - 6.0).abs() < 1e-9,
            "{:?}",
            s[1]
        );
    }

    #[test]
    fn summaries_keep_payload_sizes_apart() {
        let mib = 1024 * 1024;
        let ms = vec![
            // 8 MiB in 1 s = 8 MiB/s, 32 MiB in 8 s = 4 MiB/s.
            sized(Impl::Rust, "production", 8 * mib, 4096, 1000, 1000),
            sized(Impl::Rust, "production", 32 * mib, 4096, 8000, 1000),
            sized(Impl::Rust, "production", 8 * mib, 4096, 1000, 1000),
        ];
        let s = summarise(&ms);
        assert_eq!(s.len(), 2, "a payload size is part of the group key: {s:?}");
        assert_eq!((s[0].bytes, s[0].runs), (8 * mib, 2));
        assert_eq!((s[1].bytes, s[1].runs), (32 * mib, 1));
        // Which is the whole point of measuring more than one payload: a size that behaves
        // differently must not be folded into the other size's median.
        assert!(
            s[0].mib_per_sec.median > s[1].mib_per_sec.median * 1.9,
            "{s:?}"
        );
    }

    #[test]
    fn stats_carry_the_spread_and_survive_an_empty_group() {
        let s = Stat::of(&[2.0, 5.0, 3.0]);
        assert!((s.median - 3.0).abs() < 1e-9);
        assert!((s.min - 2.0).abs() < 1e-9);
        assert!((s.max - 5.0).abs() < 1e-9);
        assert_eq!(s.range_label(1), "2.0-5.0");
        assert_eq!(
            Stat::of(&[]),
            Stat {
                median: 0.0,
                min: 0.0,
                max: 0.0
            },
            "an empty group must not report infinities",
        );
    }

    #[test]
    fn the_table_pairs_both_implementations_and_marks_a_missing_side() {
        let mib = 1024 * 1024;
        let ms = vec![
            sized(Impl::Rust, "default", 8 * mib, 4096, 1000, 2000),
            sized(Impl::Go, "default", 8 * mib, 4096, 2000, 6000),
            sized(Impl::Rust, "production", 32 * mib, 65536, 1000, 1000),
        ];
        let table = comparison_table(&ms);
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines.len(), 4, "header, rule and two rows:\n{table}");
        assert!(
            lines[2].starts_with("default       8 MiB   4 KiB"),
            "{}",
            lines[2]
        );
        // Rust is twice as fast and a third of the CPU here.
        assert!(lines[2].contains("2.00x"), "{}", lines[2]);
        assert!(lines[2].contains("0.33x"), "{}", lines[2]);
        assert!(
            lines[3].starts_with("production   32 MiB  64 KiB"),
            "{}",
            lines[3]
        );
        assert!(
            lines[3].contains("-"),
            "the missing Go side prints a dash: {}",
            lines[3]
        );
        let width = lines[0].chars().count();
        assert!(
            lines.iter().all(|l| l.chars().count() == width),
            "every line is as wide as the header:\n{table}"
        );
        assert_eq!(comparison_table(&[]).lines().count(), 2, "header only");
    }

    #[test]
    fn the_table_shows_the_range_behind_every_median() {
        let mib = 1024 * 1024;
        // 8 MiB in 1 s and in 2 s: 8.0 and 4.0 MiB/s, median 6.0; 1 s and 2 s of CPU for
        // 8 MiB = 119.21 and 238.42 CPU s/GB, median 178.81.
        let ms = vec![
            sized(Impl::Rust, "default", 8 * mib, 4096, 1000, 1000),
            sized(Impl::Rust, "default", 8 * mib, 4096, 2000, 2000),
        ];
        let row = comparison_table(&ms).lines().nth(2).unwrap().to_string();
        assert!(row.contains("6.0"), "the median: {row}");
        assert!(row.contains("4.0-8.0"), "next to its range: {row}");

        let spread = spread_table(&ms);
        let lines: Vec<&str> = spread.lines().collect();
        assert_eq!(lines.len(), 3, "header, rule, one row per impl:\n{spread}");
        assert!(lines[2].contains("4.0-8.0"), "{}", lines[2]);
        assert!(
            lines[2].contains("178.81 119.21-238.42"),
            "CPU median and range: {}",
            lines[2]
        );
        let width = lines[0].chars().count();
        assert!(
            lines.iter().all(|l| l.chars().count() == width),
            "every line is as wide as the header:\n{spread}"
        );
    }

    #[test]
    fn size_labels_are_binary() {
        assert_eq!(size_label(4096), "4 KiB");
        assert_eq!(size_label(64 * 1024), "64 KiB");
        assert_eq!(size_label(8 * 1024 * 1024), "8 MiB");
        assert_eq!(size_label(512 * 1024), "512 KiB");
        assert_eq!(size_label(1536 * 1024), "1536 KiB", "not a whole MiB");
        assert_eq!(size_label(1000), "1000 B");
    }
}
