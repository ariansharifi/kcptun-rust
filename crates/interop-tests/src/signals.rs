//! Signals, SNMP output and exit behaviour (plan step 09.6): what a running `kcptun-client` or
//! `kcptun-server` does when it is signalled, and what it leaves in its `-snmplog` file.
//!
//! ```text
//! reference/bin/client_darwin_arm64 ─┐                    ┌─ SIGUSR1 ─▶ `KCP SNMP:&{…}` (30 fields)
//!                                    ├─ start, then ──────┼─ SIGTERM ─▶ exit status
//! target/release/kcptun-client      ─┘                    └─ `-snmplog` ─▶ CSV header + rows
//! ```
//!
//! | Item | Purpose |
//! |---|---|
//! | [`Instance`] | one binary of one implementation, in its own directory, ready to be signalled |
//! | [`Snapshot`] | the `&{BytesSent:0 …}` of a `KCP SNMP:` line, parsed |
//! | [`SnmpCsv`] | a `-snmplog` file, parsed |
//! | [`Termination`] | how a signalled process ended, and how long it took |
//!
//! Go's side of all three:
//!
//! - `kcptun/std/signal.go`: `sigHandler()` logs `KCP SNMP:%+v` on `SIGUSR1`, and on
//!   `SIGTERM`/`SIGINT` runs `postProcess()` and then kills itself **with `SIGTERM`**, so the
//!   process is *signalled*, never *exited*, in both cases. `EXIT_WAIT` (5 s) is the fallback
//!   `os.Exit(0)` that only runs if the re-raise did not end the process: reaching it is a
//!   failure, which is why [`Termination::elapsed`] is asserted against [`EXIT_WAIT`].
//! - `kcp-go/v5 snmp.go`: `Snmp.Header()`/`ToSlice()` (the CSV columns) and the struct field
//!   order (the `%+v` order); the two differ, and [`kcptun_kcp::snmp`] keeps both.
//! - `kcptun/std/snmp.go`: `SnmpLogger`/`writeSnmpRecord`: a header in an empty file, then one
//!   record per tick, into `filepath.Split(path)`'s directory plus the *formatted* file name.
//!
//! An [`Instance`] is configured so that it needs no peer: the client dials nothing until an
//! application connects, and the server's target is never reached. Both therefore sit at
//! all-zero counters, which is what lets the tests compare Go's `KCP SNMP:` line and CSV rows
//! with ours **byte for byte**. The counters under real traffic are covered by the Rust↔Rust
//! tunnel case in `tests/signals.rs`.
//!
//! Signals are Unix-only (Go excludes `std/signal.go` on Windows, and so does our port), so this
//! module and its tests are `#[cfg(unix)]`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use kcptun_kcp::snmp::{DEFAULT_SNMP, SNMP_FIELDS, SnmpSnapshot};
use kcptun_testkit::ports::{self, PortBlock};
use kcptun_testkit::proc::{Proc, ProcError};

use crate::bins::{BinNotFound, Impl, bin};
use crate::clidiff::{Exit, exit_of};
use crate::matrix::Side;

/// Go's `EXIT_WAIT`: the fallback `os.Exit(0)` armed when a termination signal arrives. A
/// process that is still alive after this did **not** die of the re-raised `SIGTERM`.
// Go: kcptun/std/signal.go:EXIT_WAIT
pub const EXIT_WAIT: Duration = Duration::from_secs(5);

/// The last line of both implementations' start-up block; after it the signal handler, the SNMP
/// logger and the listeners are all up.
// Go: kcptun/client/main.go, server/main.go, log.Println("key derivation done") right before
// the SnmpLogger goroutine is started.
const READY: &str = "key derivation done";

/// How long a binary may take to reach [`READY`].
const START_TIMEOUT: Duration = Duration::from_secs(20);

/// How long a signalled process may take to do what the signal asks. Comfortably past
/// [`EXIT_WAIT`], so that a process falling back to `os.Exit(0)` is *observed* rather than
/// timing the test out.
pub const SIGNAL_TIMEOUT: Duration = Duration::from_secs(20);

/// How often a log or a process state is polled.
const POLL: Duration = Duration::from_millis(20);

/// The `-key` the instances use. Any value does; it is passed explicitly so that an exported
/// `KCPTUN_KEY` cannot change what is being compared.
pub const KEY: &str = "kcptun-rust 09.6";

/// The prefix of the line `SIGUSR1` produces.
// Go: kcptun/std/signal.go:sigHandler(), log.Printf("KCP SNMP:%+v", kcp.DefaultSnmp.Copy())
pub const SNMP_MARKER: &str = "KCP SNMP:";

/// The `-snmplog` argument every instance is given: Go's reference layout for `YYYYMMDD`, so the
/// file lands next to it as `snmp-<today>.log`.
pub const SNMP_LOG_LAYOUT: &str = "snmp-20060102.log";

// ---------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------

/// Why an instance could not be run or watched.
#[derive(Debug)]
pub enum SignalError {
    /// A binary was not found (build it, or set `KCPTUN_RS_BIN_DIR`/`KCPTUN_GO_BIN_DIR`).
    Bin(BinNotFound),
    /// An I/O error: spawning, signalling, or reading the run's directory.
    Io(io::Error),
    /// The process died or went quiet while something was being waited for.
    Proc(ProcError),
    /// The run produced something that cannot be read as what it should be (a `-snmplog` file
    /// that is missing, doubled or malformed).
    Parse(String),
}

impl std::fmt::Display for SignalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignalError::Bin(e) => write!(f, "{e}"),
            SignalError::Io(e) => write!(f, "{e}"),
            SignalError::Proc(e) => write!(f, "{e}"),
            SignalError::Parse(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for SignalError {}

impl From<BinNotFound> for SignalError {
    fn from(e: BinNotFound) -> Self {
        SignalError::Bin(e)
    }
}

impl From<io::Error> for SignalError {
    fn from(e: io::Error) -> Self {
        SignalError::Io(e)
    }
}

impl From<ProcError> for SignalError {
    fn from(e: ProcError) -> Self {
        SignalError::Proc(e)
    }
}

// ---------------------------------------------------------------------------------------
// One running binary
// ---------------------------------------------------------------------------------------

/// How a signalled process ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Termination {
    /// The wait status, as [`Exit`] renders it. Go's handler makes this `signal 15` for
    /// `SIGTERM` **and** for `SIGINT`.
    pub exit: Exit,
    /// Time between the signal and the process being reaped.
    pub elapsed: Duration,
}

/// One `kcptun-client` or `kcptun-server` of one implementation, running in its own directory
/// with a configuration that needs no peer.
///
/// The process is killed and reaped when this value is dropped, so a panicking or timing-out
/// test leaves nothing behind.
#[derive(Debug)]
pub struct Instance {
    proc: Proc,
    dir: PathBuf,
    implementation: Impl,
    side: Side,
    argv: Vec<String>,
    ports: PortBlock,
}

impl Instance {
    /// Starts `side`'s binary of `implementation` in `dir`, with `extra` appended to the flags,
    /// and waits until it has finished starting up.
    ///
    /// The flags are the minimum that starts a tunnel end: the client listens on an ephemeral
    /// TCP port and points at a UDP port nobody serves; the server listens on an allocated UDP
    /// port with a target nobody serves. Neither sends a packet before an application connects,
    /// which is what keeps the SNMP counters at zero.
    pub fn start(
        implementation: Impl,
        side: Side,
        dir: &Path,
        extra: &[&str],
    ) -> Result<Instance, SignalError> {
        fs::create_dir_all(dir)?;
        let block = ports::allocate(2);
        let mut argv: Vec<String> = match side {
            Side::Client => vec![
                "-l".to_string(),
                "127.0.0.1:0".to_string(),
                "-r".to_string(),
                block.addr(0).to_string(),
            ],
            Side::Server => vec![
                "-l".to_string(),
                block.addr(0).to_string(),
                "-t".to_string(),
                block.addr(1).to_string(),
            ],
        };
        argv.extend(["-key".to_string(), KEY.to_string()]);
        argv.extend(extra.iter().map(|s| (*s).to_string()));

        let program = bin(implementation, side.bin_name())?;
        let mut proc = Proc::builder(&program)
            .name(format!("{}-{}", side.bin_name(), implementation.tag()))
            .args(&argv)
            .current_dir(dir)
            // An exported KCPTUN_KEY in the shell that runs the tests would otherwise decide
            // what these processes do.
            .env_remove("KCPTUN_KEY")
            .spawn()?;
        proc.wait_for_log_line(READY, START_TIMEOUT)?;

        Ok(Instance {
            proc,
            dir: dir.to_path_buf(),
            implementation,
            side,
            argv,
            ports: block,
        })
    }

    /// Which implementation this is.
    pub fn implementation(&self) -> Impl {
        self.implementation
    }

    /// Which binary this is.
    pub fn side(&self) -> Side {
        self.side
    }

    /// The command line, for failure messages.
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    /// The ports the instance was given (`-r` for a client, `-l` and `-t` for a server).
    pub fn ports(&self) -> PortBlock {
        self.ports
    }

    /// The run's private directory, which is also the process's working directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Everything the process has logged so far.
    pub fn log(&self) -> String {
        self.proc.log()
    }

    /// The process itself.
    pub fn proc(&mut self) -> &mut Proc {
        &mut self.proc
    }

    /// Sends a signal by `kill(1)` name (`USR1`, `TERM`, `INT`).
    pub fn signal(&mut self, signal: &str) -> Result<(), SignalError> {
        Ok(self.proc.signal(signal)?)
    }

    /// Waits until the log holds `n` complete `KCP SNMP:` lines and returns their `&{…}` bodies.
    pub fn wait_for_snapshots(&mut self, n: usize) -> Result<Vec<Snapshot>, SignalError> {
        wait_for_snapshots(&mut self.proc, n, SIGNAL_TIMEOUT)
    }

    /// Sends `signal` and waits for the process to be reaped, reporting how it ended and how
    /// long that took.
    pub fn terminate(&mut self, signal: &str) -> Result<Termination, SignalError> {
        terminate(&mut self.proc, signal, SIGNAL_TIMEOUT)
    }

    /// The names of the files in the run's directory, sorted.
    pub fn files(&self) -> Result<Vec<String>, SignalError> {
        let mut names: Vec<String> = fs::read_dir(&self.dir)?
            .map(|e| Ok(e?.file_name().to_string_lossy().into_owned()))
            .collect::<io::Result<Vec<_>>>()?;
        names.sort();
        Ok(names)
    }

    /// The one `-snmplog` file in the run's directory, parsed.
    ///
    /// Exactly one is expected: `SNMP_LOG_LAYOUT` renders to one name per day, and a run of a
    /// few seconds cannot cross midnight twice.
    pub fn snmp_csv(&self) -> Result<SnmpCsv, SignalError> {
        let mut found: Vec<String> = self
            .files()?
            .into_iter()
            .filter(|n| n.starts_with("snmp-") && n.ends_with(".log"))
            .collect();
        match found.len() {
            1 => {
                let name = found.remove(0);
                let text = fs::read_to_string(self.dir.join(&name))?;
                SnmpCsv::parse(&name, &text).map_err(SignalError::Parse)
            }
            _ => Err(SignalError::Parse(format!(
                "{} left {found:?} in {}, wanted exactly one snmp log",
                self.proc.name(),
                self.dir.display()
            ))),
        }
    }
}

/// Sends `signal` to `proc` and waits for it to be reaped, reporting how it ended and how long
/// that took. Blocking; an async test uses [`terminate_async`].
pub fn terminate(
    proc: &mut Proc,
    signal: &str,
    timeout: Duration,
) -> Result<Termination, SignalError> {
    proc.signal(signal)?;
    let sent = Instant::now();
    match proc.wait_timeout(timeout)? {
        Some(status) => Ok(Termination {
            exit: exit_of(status),
            elapsed: sent.elapsed(),
        }),
        None => Err(termination_timeout(proc, signal, timeout)),
    }
}

/// [`terminate`] for an async test: the waiting between polls is a `tokio::time::sleep` rather
/// than a thread sleep. Sending the signal (a short `kill(1)` spawn, reaped on the spot) still
/// blocks the worker thread briefly.
pub async fn terminate_async(
    proc: &mut Proc,
    signal: &str,
    timeout: Duration,
) -> Result<Termination, SignalError> {
    proc.signal(signal)?;
    let sent = Instant::now();
    loop {
        if let Some(status) = proc.try_wait()? {
            return Ok(Termination {
                exit: exit_of(status),
                elapsed: sent.elapsed(),
            });
        }
        if sent.elapsed() >= timeout {
            return Err(termination_timeout(proc, signal, timeout));
        }
        tokio::time::sleep(POLL).await;
    }
}

fn termination_timeout(proc: &Proc, signal: &str, timeout: Duration) -> SignalError {
    SignalError::Proc(ProcError::Timeout {
        name: proc.name().to_string(),
        waiting_for: format!("the exit that SIG{signal} asks for, within {timeout:?}"),
        log_tail: proc.log_tail(),
    })
}

/// Waits until `proc`'s log holds `n` complete `KCP SNMP:` lines. Blocking; the async tests use
/// [`wait_for_snapshots_async`].
pub fn wait_for_snapshots(
    proc: &mut Proc,
    n: usize,
    timeout: Duration,
) -> Result<Vec<Snapshot>, SignalError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(found) = poll_snapshots(proc, n)? {
            return Ok(found);
        }
        if Instant::now() >= deadline {
            return Err(snapshot_timeout(proc, n, timeout));
        }
        std::thread::sleep(POLL);
    }
}

/// [`wait_for_snapshots`] for an async test: the waiting between polls is a `tokio::time::sleep`
/// rather than a thread sleep. Each poll itself still reads the whole log file on the worker
/// thread.
pub async fn wait_for_snapshots_async(
    proc: &mut Proc,
    n: usize,
    timeout: Duration,
) -> Result<Vec<Snapshot>, SignalError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(found) = poll_snapshots(proc, n)? {
            return Ok(found);
        }
        if Instant::now() >= deadline {
            return Err(snapshot_timeout(proc, n, timeout));
        }
        tokio::time::sleep(POLL).await;
    }
}

/// One look at the log: `Some` once it holds `n` parsable snapshots.
fn poll_snapshots(proc: &mut Proc, n: usize) -> Result<Option<Vec<Snapshot>>, SignalError> {
    // The status is read first: once the process has exited, everything it wrote is in the log.
    let status = proc.try_wait()?;
    let log = proc.log();
    let found = snapshots(&log);
    if found.len() >= n {
        return Ok(Some(found));
    }
    if let Some(status) = status {
        return Err(SignalError::Proc(ProcError::Exited {
            name: proc.name().to_string(),
            status,
            waiting_for: waiting_for(found.len(), n),
            log_tail: proc.log_tail(),
        }));
    }
    Ok(None)
}

fn snapshot_timeout(proc: &mut Proc, n: usize, timeout: Duration) -> SignalError {
    let have = snapshots(&proc.log()).len();
    SignalError::Proc(ProcError::Timeout {
        name: proc.name().to_string(),
        waiting_for: format!("{} within {timeout:?}", waiting_for(have, n)),
        log_tail: proc.log_tail(),
    })
}

/// `"SNMP snapshot 2 of 3 (SIGUSR1)"`, for the two messages above.
fn waiting_for(have: usize, want: usize) -> String {
    format!("SNMP snapshot {} of {want} (SIGUSR1)", have + 1)
}

// ---------------------------------------------------------------------------------------
// The SIGUSR1 line
// ---------------------------------------------------------------------------------------

/// The counters of one `KCP SNMP:&{…}` line, in the order they were printed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// The `&{…}` body exactly as it was printed, so a test can compare two implementations'
    /// lines byte for byte (parsing alone would forgive a stray space).
    pub raw: String,
    /// `(name, value)` per field, in printed order.
    pub fields: Vec<(String, u64)>,
}

impl Snapshot {
    /// Parses a whole log line, or just its `&{…}` part.
    ///
    /// Go prints `log.Printf("KCP SNMP:%+v", …)` over a `*Snmp`, i.e. `&{Name:value …}` with a
    /// single space between the fields and the struct's own field order.
    pub fn parse(line: &str) -> Result<Snapshot, String> {
        let body = match line.split_once(SNMP_MARKER) {
            Some((_, rest)) => rest,
            None => line,
        }
        .trim();
        let inner = body
            .strip_prefix("&{")
            .and_then(|b| b.strip_suffix('}'))
            .ok_or_else(|| format!("{body:?} is not a Go %+v of a *Snmp"))?;

        let mut fields = Vec::with_capacity(SNMP_FIELDS);
        for item in inner.split(' ') {
            let (name, value) = item
                .split_once(':')
                .ok_or_else(|| format!("{item:?} in {body:?} is not `Name:value`"))?;
            let value: u64 = value
                .parse()
                .map_err(|e| format!("{item:?} in {body:?}: {e}"))?;
            fields.push((name.to_string(), value));
        }
        Ok(Snapshot {
            raw: body.to_string(),
            fields,
        })
    }

    /// The field names, in printed order.
    pub fn names(&self) -> Vec<&str> {
        self.fields.iter().map(|(n, _)| n.as_str()).collect()
    }

    /// One counter by name.
    pub fn get(&self, name: &str) -> Option<u64> {
        self.fields.iter().find(|(n, _)| n == name).map(|(_, v)| *v)
    }

    /// Every counter that is not zero, in printed order.
    pub fn nonzero(&self) -> Vec<(&str, u64)> {
        self.fields
            .iter()
            .filter(|(_, v)| *v != 0)
            .map(|(n, v)| (n.as_str(), *v))
            .collect()
    }

    /// Checks that this is all 30 counters, named and ordered as Go's struct declares them,
    /// which is the order `%+v` prints and therefore the whole content of the `SIGUSR1` line.
    // Go: kcp-go/v5@v5.6.66 snmp.go:Snmp (field order), fmt %+v
    pub fn check_go_shape(&self) -> Result<(), String> {
        if self.names() != SnmpSnapshot::FIELD_NAMES {
            return Err(format!(
                "fields {:?}, wanted Go's {:?}",
                self.names(),
                SnmpSnapshot::FIELD_NAMES
            ));
        }
        Ok(())
    }
}

/// Every complete `KCP SNMP:` line of `log`, parsed, in order.
///
/// A line still being written is skipped rather than reported: the log is read while the process
/// keeps appending to it, so the last line can be half there.
pub fn snapshots(log: &str) -> Vec<Snapshot> {
    log.lines()
        .filter(|l| l.contains(SNMP_MARKER))
        .filter_map(|l| Snapshot::parse(l).ok())
        .collect()
}

// ---------------------------------------------------------------------------------------
// The -snmplog file
// ---------------------------------------------------------------------------------------

/// A parsed `-snmplog` file: the header line and one row per tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnmpCsv {
    /// The file's name, which carries the formatted date.
    pub name: String,
    /// The header fields (`Unix` plus `kcp.DefaultSnmp.Header()`).
    pub header: Vec<String>,
    /// The rows, as written.
    pub rows: Vec<Vec<String>>,
}

impl SnmpCsv {
    /// Splits `text` into a header and rows.
    ///
    /// A plain `split(',')`: no SNMP header name or counter can contain a comma, a quote or a
    /// newline, so Go's `csv.Writer` never quotes one (the quoting rules themselves are ported
    /// and unit-tested in `kcptun_std::snmp`).
    pub fn parse(name: &str, text: &str) -> Result<SnmpCsv, String> {
        let mut lines = text.lines();
        let header = lines
            .next()
            .ok_or_else(|| format!("{name} is empty"))?
            .split(',')
            .map(str::to_string)
            .collect();
        let rows = lines
            .map(|l| l.split(',').map(str::to_string).collect())
            .collect();
        Ok(SnmpCsv {
            name: name.to_string(),
            header,
            rows,
        })
    }

    /// The `Unix` column of every row.
    pub fn timestamps(&self) -> Result<Vec<u64>, String> {
        self.rows
            .iter()
            .map(|row| {
                row.first()
                    .ok_or_else(|| format!("{}: empty row", self.name))?
                    .parse::<u64>()
                    .map_err(|e| format!("{}: Unix column: {e}", self.name))
            })
            .collect()
    }

    /// The counter columns of every row (everything but `Unix`).
    pub fn counters(&self) -> Vec<&[String]> {
        self.rows
            .iter()
            .map(|row| row.get(1..).unwrap_or(&[]))
            .collect()
    }

    /// Everything about this file that does not match what Go writes, given the current time in
    /// unix seconds. An empty list means it is exactly Go's shape.
    ///
    /// Checked: the name (`snmp-<8 digits>.log`, the rendering of [`SNMP_LOG_LAYOUT`]), the
    /// header (`Unix` plus `kcp.DefaultSnmp.Header()`), at least `min_rows` rows of 31 decimal
    /// fields each, and a `Unix` column that is in the present and never goes backwards.
    // Go: kcptun/std/snmp.go:writeSnmpRecord(), kcp-go/v5@v5.6.66 snmp.go:Snmp.Header()
    pub fn problems(&self, now_unix: u64, min_rows: usize) -> Vec<String> {
        let mut problems = Vec::new();
        if !is_dated_snmp_name(&self.name) {
            problems.push(format!(
                "file name {:?} is not {SNMP_LOG_LAYOUT} formatted (snmp-<8 digits>.log)",
                self.name
            ));
        }
        if self.header != expected_header() {
            problems.push(format!(
                "header {:?}, wanted {:?}",
                self.header,
                expected_header()
            ));
        }
        if self.rows.len() < min_rows {
            problems.push(format!(
                "{} row(s), wanted at least {min_rows}",
                self.rows.len()
            ));
        }
        for (i, row) in self.rows.iter().enumerate() {
            if row.len() != SNMP_FIELDS + 1 {
                problems.push(format!(
                    "row {}: {} field(s), wanted {}",
                    i + 1,
                    row.len(),
                    SNMP_FIELDS + 1
                ));
                continue;
            }
            if let Some(bad) = row
                .iter()
                .find(|f| f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit()))
            {
                problems.push(format!("row {}: {bad:?} is not a number", i + 1));
            }
        }
        match self.timestamps() {
            Ok(times) => {
                // `writeSnmpRecord` writes `time.Now().Unix()`, so every row is from this run.
                // Five minutes of slack covers a slow machine and a coarse clock.
                for (i, t) in times.iter().enumerate() {
                    if t.abs_diff(now_unix) > 300 {
                        problems.push(format!(
                            "row {}: Unix {t} is not within five minutes of {now_unix}",
                            i + 1
                        ));
                    }
                }
                if times.windows(2).any(|w| w[1] < w[0]) {
                    problems.push(format!("Unix column goes backwards: {times:?}"));
                }
            }
            Err(e) => problems.push(e),
        }
        problems
    }
}

/// The CSV header both implementations write: `Unix` followed by `kcp.DefaultSnmp.Header()`.
// Go: kcptun/std/snmp.go:writeSnmpRecord()
pub fn expected_header() -> Vec<String> {
    let mut header = vec!["Unix".to_string()];
    header.extend(DEFAULT_SNMP.header());
    header
}

/// Whether `name` is what [`SNMP_LOG_LAYOUT`] renders to: `snmp-YYYYMMDD.log`.
pub fn is_dated_snmp_name(name: &str) -> bool {
    match name
        .strip_prefix("snmp-")
        .and_then(|n| n.strip_suffix(".log"))
    {
        Some(date) => date.len() == 8 && date.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

/// The current time in unix seconds, for [`SnmpCsv::problems`].
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "signals_tests.rs"]
mod tests;
