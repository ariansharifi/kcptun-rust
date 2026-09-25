//! Startup-log and CLI differential harness (plan step 09.5): run the same command line through
//! the Go reference binary and through ours, and compare stdout, stderr and the exit status.
//!
//! ```text
//! reference/bin/client_darwin_arm64 -l 127.0.0.1:0 -r 127.0.0.1:22000   ─┐
//!                                                                        ├─▶ normalise ─▶ compare
//! target/release/kcptun-client      -l 127.0.0.1:0 -r 127.0.0.1:22000   ─┘
//! ```
//!
//! | Item | Purpose |
//! |---|---|
//! | [`CliCase`] | one command line, its environment, its JSON config and what it is expected to do |
//! | [`run_case`] | runs it twice (Go, then ours) in two private directories and captures everything |
//! | [`normalise`] | strips what cannot match, and *only* that (see below) |
//! | [`check`] | applies the case's [`Expect`] and reports every difference it did not authorise |
//! | [`Deviation`] | the closed set of allowed differences, each one a numbered entry in `docs/DECISIONS.md` |
//!
//! **Normalisation** ([`normalise`]) removes four things, all of which are the test's own noise:
//!
//! 1. Go's `log` header — `2026/09/23 11:29:59 ` — because the two runs happen at different
//!    instants;
//! 2. the `file:line` that follows it in a `SELFBUILD` build, which is **deviation V08** (Go's
//!    source position against ours). The tokens are not discarded: they are returned separately
//!    so [`check`] can assert that Go's are `*.go:N`, ours are `*.rs:N`, and that neither side
//!    stamped more log lines than its own deviation accounts for (none at all for an identical
//!    case, one for most deviations, three for V07);
//! 3. the run's private directory, which appears in a `-c`, `-log`, `-snmplog` or unix-socket
//!    path, and in the error message when one of those fails;
//! 4. the program's own name in the `USAGE:` line of the help text (`client_darwin_arm64` against
//!    `kcptun-client`, D18), and the ephemeral port in `listening on:` when the case asked for
//!    port 0.
//!
//! Everything else is compared byte for byte, including the order of the lines, which stream each
//! one came out of, and the exit status.
//!
//! **Allowed differences.** A case is either [`Expect::Identical`] or it names exactly one
//! [`Deviation`], and each deviation is checked by its own predicate in [`check`]: a case that
//! deviates in any other way, or that stops deviating, fails. The list is closed on purpose —
//! step 09 allows the CLI differential to differ only where a
//! numbered decision says so.
//!
//! Needs both implementations' binaries; the tests in `tests/cli_diff.rs` are `#[ignore]`:
//!
//! ```sh
//! cargo build --release -p kcptun-client -p kcptun-server
//! cargo test -p kcptun-interop-tests --test cli_diff -- --ignored --nocapture
//! ```

use std::fmt;
use std::fs;
use std::io;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kcptun_testkit::ports::{self, PortBlock};
use kcptun_testkit::proc::Proc;
use kcptun_testkit::socket_creation_guard;

use crate::bins::{BinNotFound, Impl, bin};
use crate::matrix::Side;

/// How long a case that is expected to exit may take to do so.
const EXIT_TIMEOUT: Duration = Duration::from_secs(20);
/// How long a case that keeps running may take to print its first byte.
const START_TIMEOUT: Duration = Duration::from_secs(20);
/// How long the output of a running process must stand still before it counts as complete.
const IDLE: Duration = Duration::from_millis(400);
/// How often the process and its output are polled.
const POLL: Duration = Duration::from_millis(20);

// ---------------------------------------------------------------------------------------
// Allowed differences
// ---------------------------------------------------------------------------------------

/// A difference between the two implementations that a numbered decision allows.
///
/// This is the whole list: [`check`] proves the difference it names and fails on anything else,
/// so a new deviation cannot appear here without a `docs/DECISIONS.md` entry to go with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Deviation {
    /// **V06** — a usage error exits **2** here and **0** in Go. The text is identical.
    V06UsageExitStatus,
    /// **V07** — `datashard + parityshard > 256` is refused at startup; Go silently switches to
    /// klauspost's Leopard GF(2^16) codec and runs on, emitting parity no kcptun receiver can
    /// decode.
    V07FecShardsExceed256,
    /// **V08** — the `file:line` a `SELFBUILD` build puts in the log header is a Rust source
    /// position, not a Go one. Present in every case that logs at all, so it is checked for every
    /// case rather than named by one.
    V08FileAndLine,
    /// **V14** — `MST` in a `-snmplog` file *name* renders as the zone's numeric offset here and
    /// as its tzdb abbreviation in Go.
    V14SnmpLogZone,
    /// **V15** — a `-QPPCount` that does not fit in `uint16` is rejected at startup; Go truncates
    /// it and runs (into a divide by zero for 65536, with a single pad and no warning above that).
    V15QppCountTruncates,
    /// **V19** — a `-conn` that truncates to **zero** is rejected at startup; Go runs and divides
    /// by zero at the first accepted connection. Only that case: `-conn 65537` runs here exactly
    /// as it does in Go.
    V19ConnTruncatesToZero,
    /// **V20** — after a fatal error Go prints the message and then a Go stack trace; we print the
    /// message line only. The first line is byte-identical.
    V20NoStackTrace,
    /// **V21** — `--pprof` in a build without the optional `pprof` feature logs one extra line,
    /// [`PPROF_NOT_AVAILABLE`], which Go never prints (D23). Every other byte is unchanged, and a
    /// `--features pprof` build has no difference at all — that half is an
    /// [`Expect::Identical`] case, see `tests/cli_diff.rs`.
    V21PprofNotAvailable,
}

impl Deviation {
    /// The `docs/DECISIONS.md` identifier.
    pub fn id(self) -> &'static str {
        match self {
            Deviation::V06UsageExitStatus => "V06",
            Deviation::V07FecShardsExceed256 => "V07",
            Deviation::V08FileAndLine => "V08",
            Deviation::V14SnmpLogZone => "V14",
            Deviation::V15QppCountTruncates => "V15",
            Deviation::V19ConnTruncatesToZero => "V19",
            Deviation::V20NoStackTrace => "V20",
            Deviation::V21PprofNotAvailable => "V21",
        }
    }
}

impl fmt::Display for Deviation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// The line a build without the optional `pprof` feature logs for `--pprof` (**V21**).
///
/// It is `kcptun_std::pprof::NOT_AVAILABLE`, spelled out rather than imported on purpose: this
/// module compares our output with Go's, so a change to that constant has to show up here as a
/// difference instead of silently moving along with it. `kcptun-std`'s own
/// `test_start_without_feature_logs_not_available` pins the two spellings together.
pub const PPROF_NOT_AVAILABLE: &str = "pprof: not available in this build";

/// The two lines Go logs where **V07** stops us, and which prove it carried on past the shard
/// count instead of rejecting it.
// Go: kcptun/client/main.go:385-387, kcptun/server/main.go:342-344
const KEY_DERIVATION: [&str; 2] = ["initiating key derivation", "key derivation done"];

/// What a case's two runs are expected to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect {
    /// Identical stdout, stderr and exit status (after [`normalise`]).
    Identical,
    /// Identical but for one named, numbered deviation, which [`check`] proves.
    Deviates(Deviation),
}

// ---------------------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------------------

/// One command line, run through both implementations.
///
/// The arguments may use three placeholders, so that the two runs stay independent of each other
/// and of whatever else is using the machine:
///
/// | Token | Replaced with |
/// |---|---|
/// | `{dir}` | the run's own private directory (it is also the process's working directory) |
/// | `{config}` | `{dir}/config.json`, holding [`json`](CliCase::json) |
/// | `{portN}` | the `N`-th port of a block allocated by [`kcptun_testkit::ports`] |
///
/// Both runs of a case get the *same* ports (they never run at the same time) and *different*
/// directories, which [`normalise`] puts back together.
#[derive(Clone, Debug)]
pub struct CliCase {
    /// Test-visible name, also the directory name; unique across the suite.
    pub name: &'static str,
    /// Which binary to run.
    pub side: Side,
    /// Arguments, with the placeholders above.
    pub args: Vec<String>,
    /// Extra environment variables.
    pub env: Vec<(String, String)>,
    /// JSON written to `{config}` before the run.
    pub json: Option<String>,
    /// Whether the Go run is expected to keep running (rather than exit on its own).
    pub runs: bool,
    /// Minimum time a running process is left alone before its output counts as complete; the
    /// default is zero (the idle detector decides), `-snmpperiod` needs more.
    pub settle: Duration,
    /// What the comparison must find.
    pub expect: Expect,
    /// A file in `{dir}` whose contents are normalised and compared as well (`-log`).
    pub compare_file: Option<&'static str>,
    /// Forces the `listening on:` port to be masked for a case that asks for port 0 somewhere
    /// [`ephemeral_listen`](Self::ephemeral_listen) cannot see it, such as inside a JSON config.
    pub ephemeral: bool,
    /// Bind `{port0}` (UDP, `127.0.0.1`) for the duration of both runs, so the listener fails.
    pub hold_port0: bool,
}

impl CliCase {
    /// A `kcptun-client` case with the defaults: expects identical output, and a process that
    /// exits by itself.
    pub fn client<I, S>(name: &'static str, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::new(name, Side::Client, args)
    }

    /// A `kcptun-server` case; see [`client`](Self::client).
    pub fn server<I, S>(name: &'static str, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::new(name, Side::Server, args)
    }

    fn new<I, S>(name: &'static str, side: Side, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        CliCase {
            name,
            side,
            args: args.into_iter().map(Into::into).collect(),
            env: Vec::new(),
            json: None,
            runs: false,
            settle: Duration::ZERO,
            expect: Expect::Identical,
            compare_file: None,
            ephemeral: false,
            hold_port0: false,
        }
    }

    /// Marks the case as one that starts a tunnel and keeps running (so it is killed once its
    /// output stands still).
    pub fn runs(mut self) -> Self {
        self.runs = true;
        self
    }

    /// Leaves a running process alone for at least `settle` before its output counts as complete.
    pub fn settle(mut self, settle: Duration) -> Self {
        self.settle = settle;
        self
    }

    /// Sets an environment variable for both runs.
    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.env.push((key.to_string(), value.to_string()));
        self
    }

    /// The JSON written to `{config}` before the run.
    pub fn json(mut self, json: impl Into<String>) -> Self {
        self.json = Some(json.into());
        self
    }

    /// Names the deviation this case is expected to show.
    pub fn deviates(mut self, deviation: Deviation) -> Self {
        self.expect = Expect::Deviates(deviation);
        self
    }

    /// Also compares the (normalised) contents of `{dir}/<name>`.
    pub fn compare_file(mut self, name: &'static str) -> Self {
        self.compare_file = Some(name);
        self
    }

    /// Holds `{port0}` (UDP) during both runs.
    pub fn hold_port0(mut self) -> Self {
        self.hold_port0 = true;
        self
    }

    /// Masks the `listening on:` port although no argument says `:0` (a JSON config does).
    pub fn ephemeral(mut self) -> Self {
        self.ephemeral = true;
        self
    }

    /// The logical binary name (`client` or `server`).
    pub fn bin_name(&self) -> &'static str {
        self.side.bin_name()
    }

    /// How many ports the arguments ask for: one past the highest `{portN}` used.
    pub fn port_count(&self) -> u16 {
        let mut n = 0;
        for arg in &self.args {
            for i in 0..10u16 {
                if arg.contains(&format!("{{port{i}}}")) {
                    n = n.max(i + 1);
                }
            }
        }
        n
    }

    /// Whether the case asked for an ephemeral local port, so `listening on:` cannot match.
    pub fn ephemeral_listen(&self) -> bool {
        self.ephemeral || self.args.iter().any(|a| a.ends_with(":0"))
    }

    /// The arguments with the placeholders filled in for one run.
    fn expand(&self, dir: &Path, ports: Option<PortBlock>) -> Vec<String> {
        let dir_s = dir.display().to_string();
        let config = dir.join("config.json").display().to_string();
        self.args
            .iter()
            .map(|arg| {
                let mut arg = arg.replace("{config}", &config).replace("{dir}", &dir_s);
                if let Some(block) = ports {
                    for i in 0..block.count() {
                        arg = arg.replace(&format!("{{port{i}}}"), &block.port(i).to_string());
                    }
                }
                arg
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------------------

/// How a process ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// Exited with this status (Go's `os.Exit(-1)` is 255).
    Code(i32),
    /// Killed by this signal without our doing.
    Signal(i32),
    /// Still running when the harness stopped watching, and killed by it.
    Running,
}

impl fmt::Display for Exit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Exit::Code(c) => write!(f, "exit {c}"),
            Exit::Signal(s) => write!(f, "signal {s}"),
            Exit::Running => f.write_str("still running"),
        }
    }
}

/// What one run produced, normalised.
#[derive(Clone, Debug)]
pub struct Run {
    /// Which implementation this was.
    pub implementation: Impl,
    /// The command line, as it was passed.
    pub argv: Vec<String>,
    /// Normalised stdout, by line.
    pub stdout: Vec<String>,
    /// Normalised stderr, by line.
    pub stderr: Vec<String>,
    /// How it ended.
    pub exit: Exit,
    /// The `file:line` tokens stripped from the log headers, in the order they appeared (V08).
    pub locations: Vec<String>,
    /// The names of the files found in the run's directory afterwards, sorted.
    pub files: Vec<String>,
    /// Normalised contents of [`CliCase::compare_file`], if the case named one.
    pub file_lines: Vec<String>,
}

impl Run {
    /// stdout and stderr as they would be read, for a failure message.
    pub fn transcript(&self) -> String {
        let mut s = String::new();
        for line in &self.stdout {
            s.push_str("  out| ");
            s.push_str(line);
            s.push('\n');
        }
        for line in &self.stderr {
            s.push_str("  err| ");
            s.push_str(line);
            s.push('\n');
        }
        s
    }
}

/// Why a case could not be run at all (as opposed to producing a difference).
#[derive(Debug)]
pub enum RunError {
    /// A binary was not found.
    Bin(BinNotFound),
    /// A directory, the config file or the held socket could not be prepared.
    Io(io::Error),
    /// The process did not print anything, or did not exit, in time.
    Timeout(String),
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunError::Bin(e) => write!(f, "{e}"),
            RunError::Io(e) => write!(f, "{e}"),
            RunError::Timeout(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for RunError {}

impl From<io::Error> for RunError {
    fn from(e: io::Error) -> Self {
        RunError::Io(e)
    }
}

impl From<BinNotFound> for RunError {
    fn from(e: BinNotFound) -> Self {
        RunError::Bin(e)
    }
}

/// Runs `case` through both implementations, Go first, in two directories under `root`.
///
/// The two runs never overlap, so they can share the allocated ports; a case that needs a port to
/// be busy ([`CliCase::hold_port0`]) gets a socket that outlives both of them.
pub fn run_case(case: &CliCase, root: &Path) -> Result<(Run, Run), RunError> {
    let ports = match case.port_count() {
        0 => None,
        n => Some(ports::allocate(n)),
    };
    let hold = match (case.hold_port0, ports) {
        (true, Some(block)) => {
            let _fd = socket_creation_guard();
            Some(UdpSocket::bind(block.addr(0))?)
        }
        _ => None,
    };

    let go = run_one(case, Impl::Go, root, ports)?;
    let rust = run_one(case, Impl::Rust, root, ports)?;
    drop(hold);
    Ok((go, rust))
}

/// One half of [`run_case`].
fn run_one(
    case: &CliCase,
    implementation: Impl,
    root: &Path,
    ports: Option<PortBlock>,
) -> Result<Run, RunError> {
    let dir = run_dir(root, case, implementation)?;
    if let Some(json) = &case.json {
        fs::write(dir.join("config.json"), json)?;
    }
    let argv = case.expand(&dir, ports);
    let program = bin(implementation, case.bin_name())?;

    let mut builder = Proc::builder(&program)
        .name(format!("{}-{}", case.name, implementation.tag()))
        .args(&argv)
        .current_dir(&dir)
        .split_output()
        // The key is a flag with an environment default; an exported KCPTUN_KEY in the shell
        // that runs the tests would silently change every case.
        .env_remove("KCPTUN_KEY");
    for (k, v) in &case.env {
        builder = builder.env(k, v);
    }
    let mut proc = builder.spawn()?;

    // A process that is expected to keep going is watched until its output stands still; one that
    // is expected to exit is waited for. `watch_until_idle` reports an exit it did not expect
    // faithfully, so a wrong guess still produces a comparison rather than an error.
    let exit = if keeps_running(case, implementation) {
        watch_until_idle(&mut proc, case, &dir)?
    } else {
        wait_for_exit(&mut proc, case)?
    };

    let norm = Norm {
        dir: &dir,
        program: &program,
        ephemeral_listen: case.ephemeral_listen(),
    };
    let (stdout, mut locations) = normalise(&proc.stdout_text(), &norm);
    let (stderr, err_locations) = normalise(&proc.stderr_text(), &norm);
    locations.extend(err_locations);

    let file_lines = match case.compare_file {
        Some(name) => normalise(&fs::read_to_string(dir.join(name))?, &norm).0,
        None => Vec::new(),
    };
    let mut files: Vec<String> = fs::read_dir(&dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    files.sort();

    Ok(Run {
        implementation,
        argv,
        stdout,
        stderr,
        exit,
        locations,
        files,
        file_lines,
    })
}

/// Whether this run is expected to start a tunnel and keep running.
///
/// It is the case's own answer, except for the three deviations that stop **our** binary where Go
/// carries on: V07's shard count, rejected at the FEC check, and V15's `-QPPCount` and V19's
/// `-conn`, both rejected at the `uint16` cast.
fn keeps_running(case: &CliCase, implementation: Impl) -> bool {
    if !case.runs {
        return false;
    }
    let rejected_here = matches!(
        case.expect,
        Expect::Deviates(Deviation::V07FecShardsExceed256)
            | Expect::Deviates(Deviation::V15QppCountTruncates)
            | Expect::Deviates(Deviation::V19ConnTruncatesToZero)
    );
    implementation == Impl::Go || !rejected_here
}

/// `<root>/<case><tag>`, created empty. Kept short: a unix socket path lives in it, and
/// `sun_path` is 104 bytes on macOS.
fn run_dir(root: &Path, case: &CliCase, implementation: Impl) -> io::Result<PathBuf> {
    let dir = root.join(format!("{}{}", short_name(case.name), implementation.tag()));
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// A short, stable directory name for a case: the first letter of every `_`-separated word,
/// plus four hex digits of an FNV-1a hash of the whole name.
///
/// The hash is what keeps two cases that start alike apart; the initials are only there to make
/// a failed run's directory recognisable. It is short because a unix socket lives inside that
/// directory and `sun_path` is 104 bytes on macOS. `tests/cli_diff.rs` asserts that the names it
/// produces stay unique across the suite.
pub fn short_name(name: &str) -> String {
    let mut hash: u32 = 0x811c_9dc5;
    for b in name.bytes() {
        hash = (hash ^ u32::from(b)).wrapping_mul(0x0100_0193);
    }
    let mut s: String = name.split('_').filter_map(|w| w.chars().next()).collect();
    s.push_str(&format!("{:04x}", hash & 0xffff));
    s
}

/// Waits for a process that is expected to exit on its own.
fn wait_for_exit(proc: &mut Proc, case: &CliCase) -> Result<Exit, RunError> {
    match proc.wait_timeout(EXIT_TIMEOUT)? {
        Some(status) => Ok(exit_of(status)),
        None => Err(RunError::Timeout(format!(
            "{}: {} did not exit within {EXIT_TIMEOUT:?}; output so far:\n{}",
            case.name,
            proc.name(),
            proc.log_tail()
        ))),
    }
}

/// Watches a process that is expected to keep running: returns once its output has stood still
/// for [`IDLE`] (and the case's `settle` has passed), or once it exits by itself.
///
/// "Output" includes the file a `-log` case redirects the whole block into, which is the only
/// thing such a run writes at all.
fn watch_until_idle(proc: &mut Proc, case: &CliCase, dir: &Path) -> Result<Exit, RunError> {
    let redirect = case.compare_file.map(|name| dir.join(name));
    let start = Instant::now();
    let mut size = 0usize;
    let mut changed = start;
    loop {
        if let Some(status) = proc.try_wait()? {
            return Ok(exit_of(status));
        }
        let mut now = proc.stdout_text().len() + proc.stderr_text().len();
        if let Some(path) = &redirect {
            now += fs::metadata(path).map(|m| m.len() as usize).unwrap_or(0);
        }
        if now != size {
            size = now;
            changed = Instant::now();
        }
        let idle = changed.elapsed() >= IDLE;
        let settled = start.elapsed() >= case.settle;
        if size != 0 && idle && settled {
            proc.kill()?;
            return Ok(Exit::Running);
        }
        if size == 0 && start.elapsed() >= START_TIMEOUT {
            return Err(RunError::Timeout(format!(
                "{}: {} printed nothing within {START_TIMEOUT:?}",
                case.name,
                proc.name()
            )));
        }
        if start.elapsed() >= EXIT_TIMEOUT {
            return Err(RunError::Timeout(format!(
                "{}: {} never stopped printing; output so far:\n{}",
                case.name,
                proc.name(),
                proc.log_tail()
            )));
        }
        std::thread::sleep(POLL);
    }
}

/// An `ExitStatus` as an [`Exit`].
pub fn exit_of(status: std::process::ExitStatus) -> Exit {
    match status.code() {
        Some(code) => Exit::Code(code),
        #[cfg(unix)]
        None => Exit::Signal(std::os::unix::process::ExitStatusExt::signal(&status).unwrap_or(0)),
        #[cfg(not(unix))]
        None => Exit::Signal(0),
    }
}

// ---------------------------------------------------------------------------------------
// Normalisation
// ---------------------------------------------------------------------------------------

/// What one run's output has to be told about itself before it can be compared.
#[derive(Clone, Copy, Debug)]
pub struct Norm<'a> {
    /// The run's private directory, replaced by `{dir}`.
    pub dir: &'a Path,
    /// The program, whose file name appears in the `USAGE:` line of the help text.
    pub program: &'a Path,
    /// Whether `listening on:` carries an ephemeral port.
    pub ephemeral_listen: bool,
}

/// Strips the log header, the run's directory, the program name and an ephemeral port from
/// `text`, and returns the lines together with the `file:line` tokens it removed (V08).
///
/// See the [module docs](self) for what is removed and why. Nothing else is touched: a trailing
/// space, an empty line and the order of the lines all survive.
pub fn normalise(text: &str, norm: &Norm<'_>) -> (Vec<String>, Vec<String>) {
    let dir = norm.dir.display().to_string();
    let program = norm
        .program
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut lines = Vec::new();
    let mut locations = Vec::new();
    for raw in text.lines() {
        let (body, location) = strip_log_header(raw);
        if let Some(location) = location {
            locations.push(location.to_string());
        }
        let mut line = body.replace(&dir, "{dir}");
        line = strip_program_name(&line, &program);
        if norm.ephemeral_listen {
            line = mask_listening_port(&line);
        }
        lines.push(line);
    }
    (lines, locations)
}

/// Splits Go's `log` header off a line: `2026/09/23 11:29:59 ` and, in a `SELFBUILD` build, the
/// `file:line: ` that follows it. Returns the rest of the line and the `file:line` token.
// Go: log/log.go:(*Logger).formatHeader() with Ldate|Ltime|Lshortfile
fn strip_log_header(line: &str) -> (&str, Option<&str>) {
    let Some(rest) = strip_timestamp(line) else {
        return (line, None);
    };
    match rest.split_once(": ") {
        Some((token, body)) if is_file_line(token) => (body, Some(token)),
        _ => (rest, None),
    }
}

/// `YYYY/MM/DD HH:MM:SS `, or `None` when the line does not start with one.
fn strip_timestamp(line: &str) -> Option<&str> {
    const SHAPE: &str = "dddd/dd/dd dd:dd:dd ";
    let b = line.as_bytes();
    if b.len() < SHAPE.len() {
        return None;
    }
    for (i, want) in SHAPE.bytes().enumerate() {
        let ok = match want {
            b'd' => b[i].is_ascii_digit(),
            other => b[i] == other,
        };
        if !ok {
            return None;
        }
    }
    Some(&line[SHAPE.len()..])
}

/// Whether `token` is a `main.go:316`-shaped source position (Go's, or deviation V08's Rust one).
fn is_file_line(token: &str) -> bool {
    let Some((file, line)) = token.rsplit_once(':') else {
        return false;
    };
    !file.contains(' ')
        && (file.ends_with(".go") || file.ends_with(".rs"))
        && !line.is_empty()
        && line.bytes().all(|b| b.is_ascii_digit())
}

/// Replaces the program's own name in the help text's `USAGE:` line (D18: our binaries are
/// `kcptun-client`/`kcptun-server`, Go's are `client_<goos>_<goarch>`).
// Go: urfave/cli@v1.22.17 app.go:Setup() — `HelpName: filepath.Base(os.Args[0])`
fn strip_program_name(line: &str, program: &str) -> String {
    match line
        .strip_prefix("   ")
        .and_then(|l| l.strip_prefix(program))
    {
        Some(rest) if rest.starts_with(' ') || rest.is_empty() => format!("   {{prog}}{rest}"),
        _ => line.to_string(),
    }
}

/// Masks the port of a `listening on: <host>:<port>` line, which a `-l host:0` case cannot pin.
fn mask_listening_port(line: &str) -> String {
    let Some(addr) = line.strip_prefix("listening on: ") else {
        return line.to_string();
    };
    match addr.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            format!("listening on: {host}:{{port}}")
        }
        _ => line.to_string(),
    }
}

// ---------------------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------------------

/// Compares the two runs of `case` and returns a report of every difference the case did not
/// authorise. `Ok(())` means the case passed.
///
/// Whatever the expectation, three things are always checked: the `file:line` tokens are V08 and
/// nothing else (Go's end in `.go`, ours in `.rs`, and there are equally many), the files left
/// behind in the two directories have the same names, and the file a case named with
/// [`CliCase::compare_file`] has the same contents.
pub fn check(case: &CliCase, go: &Run, rust: &Run) -> Result<(), String> {
    let mut problems = Vec::new();

    match case.expect {
        Expect::Identical => {
            diff_lines("stdout", &go.stdout, &rust.stdout, &mut problems);
            diff_lines("stderr", &go.stderr, &rust.stderr, &mut problems);
            if go.exit != rust.exit {
                problems.push(format!("exit status: Go {}, ours {}", go.exit, rust.exit));
            }
        }
        Expect::Deviates(deviation) => {
            check_deviation(deviation, go, rust, &mut problems);
        }
    }

    check_v08(case.expect, go, rust, &mut problems);

    if case.expect != Expect::Deviates(Deviation::V14SnmpLogZone) && go.files != rust.files {
        problems.push(format!(
            "files left behind: Go {:?}, ours {:?}",
            go.files, rust.files
        ));
    }
    if case.compare_file.is_some() {
        diff_lines("log file", &go.file_lines, &rust.file_lines, &mut problems);
    }

    if problems.is_empty() {
        return Ok(());
    }
    Err(format!(
        "case {} ({} {})\n{}\nGo ({}):\n{}ours ({}):\n{}",
        case.name,
        rust.implementation,
        rust.argv.join(" "),
        problems
            .iter()
            .map(|p| format!("  - {p}"))
            .collect::<Vec<_>>()
            .join("\n"),
        go.exit,
        go.transcript(),
        rust.exit,
        rust.transcript(),
    ))
}

/// **Deviation V08**, asserted for every case: the header's source position is the only part of
/// the header that differs, Go's is a Go file and ours is a Rust file, and both implementations
/// stamped the same number of lines.
fn check_v08(expect: Expect, go: &Run, rust: &Run, problems: &mut Vec<String>) {
    for (run, ext) in [(go, ".go"), (rust, ".rs")] {
        if let Some(bad) = run
            .locations
            .iter()
            .find(|l| !l.rsplit_once(':').is_some_and(|(f, _)| f.ends_with(ext)))
        {
            problems.push(format!(
                "V08: {} logged a `{bad}` header, which is not a {ext} source position",
                run.implementation
            ));
        }
    }
    // Different counts mean one side logged a line the other did not, which the line comparison
    // reports only when the text differs: a line printed on the same stream with the same text but
    // without a header would otherwise slip through, because the header is stripped before the
    // comparison. An identical case therefore has to stamp exactly as many lines on both sides;
    // a deviating one is allowed the gap its own deviation accounts for.
    let (a, b) = (go.locations.len(), rust.locations.len());
    if a.abs_diff(b) > log_line_slack(expect) {
        problems.push(format!(
            "V08: Go stamped {a} log lines with a source position, ours {b}"
        ));
    }
}

/// How far apart the two sides' stamped-line counts may be, for [`check_v08`].
///
/// Every deviation but one is a single line on one side. V07 is the exception: our binary stops at
/// the FEC check, one line before Go's key derivation, so Go stamps the two derivation lines —
/// and, on the server, the `Listening on:` line of the listener it goes on to open — against our
/// single fatal one. [`check_fec_rejected_at_startup`] pins those lines exactly, so the slack here
/// is not what holds V07 in place.
fn log_line_slack(expect: Expect) -> usize {
    match expect {
        Expect::Identical => 0,
        Expect::Deviates(Deviation::V07FecShardsExceed256) => 3,
        Expect::Deviates(_) => 1,
    }
}

/// Proves the one difference a case is allowed, and that it differs in no other way.
fn check_deviation(deviation: Deviation, go: &Run, rust: &Run, problems: &mut Vec<String>) {
    match deviation {
        // V06: same text on both streams, Go exits 0, we exit 2.
        Deviation::V06UsageExitStatus => {
            diff_lines("stdout", &go.stdout, &rust.stdout, problems);
            diff_lines("stderr", &go.stderr, &rust.stderr, problems);
            if !go.stdout.first().is_some_and(|l| {
                l.starts_with("Incorrect Usage.") || l.starts_with("Incorrect Usage ")
            }) {
                problems.push("V06: Go did not print `Incorrect Usage.`".to_string());
            }
            if go.exit != Exit::Code(0) {
                problems.push(format!("V06: Go exited {} instead of 0", go.exit));
            }
            if rust.exit != Exit::Code(2) {
                problems.push(format!("V06: we exited {} instead of 2", rust.exit));
            }
        }
        // V07: identical up to the FEC check, where we stop with one line and Go carries on into
        // the key derivation.
        Deviation::V07FecShardsExceed256 => {
            check_fec_rejected_at_startup(go, rust, problems);
        }
        // V08 is checked for every case; a case that names it asserts that it really is there.
        Deviation::V08FileAndLine => {
            diff_lines("stdout", &go.stdout, &rust.stdout, problems);
            diff_lines("stderr", &go.stderr, &rust.stderr, problems);
            if go.exit != rust.exit {
                problems.push(format!("exit status: Go {}, ours {}", go.exit, rust.exit));
            }
            if go.locations.is_empty() {
                problems.push("V08: no log header carried a source position".to_string());
            }
            if go.locations == rust.locations {
                problems
                    .push("V08: the source positions are identical, so V08 is gone".to_string());
            }
        }
        // V14: same output, but the `-snmplog` file is named after the zone's abbreviation in Go
        // and after its numeric offset here.
        Deviation::V14SnmpLogZone => {
            diff_lines("stdout", &go.stdout, &rust.stdout, problems);
            diff_lines("stderr", &go.stderr, &rust.stderr, problems);
            if go.exit != rust.exit {
                problems.push(format!("exit status: Go {}, ours {}", go.exit, rust.exit));
            }
            check_v14_file_names(go, rust, problems);
        }
        // V15 / V19: identical up to the point of the cast, where we stop with one extra line.
        Deviation::V15QppCountTruncates => {
            check_rejected_at_startup("QPPCount ", go, rust, problems);
        }
        Deviation::V19ConnTruncatesToZero => {
            check_rejected_at_startup("conn ", go, rust, problems);
        }
        // V20: our last line is Go's first fatal line, and everything Go prints after it is a Go
        // stack trace.
        Deviation::V20NoStackTrace => {
            diff_lines("stdout", &go.stdout, &rust.stdout, problems);
            if go.exit != rust.exit {
                problems.push(format!("exit status: Go {}, ours {}", go.exit, rust.exit));
            }
            check_v20_stack_trace(go, rust, problems);
        }
        // V21: our stderr is Go's with one extra line in it, and both binaries run on.
        Deviation::V21PprofNotAvailable => {
            diff_lines("stdout", &go.stdout, &rust.stdout, problems);
            check_one_extra_line(PPROF_NOT_AVAILABLE, go, rust, problems);
            if go.exit != rust.exit {
                problems.push(format!("exit status: Go {}, ours {}", go.exit, rust.exit));
            }
        }
    }
}

/// V07: our stderr is Go's up to the FEC check plus one line naming both flags and the limit, and
/// Go's carries on into the key derivation it reaches *because* it accepts the shard count (plus,
/// on the server, the `Listening on:` line of the listener it then opens).
///
/// The final line is asserted against reedsolomon's own text, which the port keeps
/// (`kcptun_kcp::rs::Error::MaxShardNum`), prefixed with the two flag values.
// Go: klauspost/reedsolomon@v1.13.0 reedsolomon.go:ErrMaxShardNum — the text `New()` never
// actually returns above 256 shards, because it builds the Leopard codec instead (V07).
fn check_fec_rejected_at_startup(go: &Run, rust: &Run, problems: &mut Vec<String>) {
    diff_lines("stdout", &go.stdout, &rust.stdout, problems);
    let Some((last, head)) = rust.stderr.split_last() else {
        problems.push("nothing was logged".to_string());
        return;
    };
    if go.stderr.len() < head.len() {
        problems.push(format!(
            "V07: Go logged {} stderr lines, fewer than the {} we logged before the rejection",
            go.stderr.len(),
            head.len()
        ));
        return;
    }
    let (shared, carried_on) = go.stderr.split_at(head.len());
    diff_lines("stderr (up to the rejection)", shared, head, problems);
    if carried_on.len() < KEY_DERIVATION.len()
        || carried_on[..KEY_DERIVATION.len()] != KEY_DERIVATION[..]
    {
        problems.push(format!(
            "V07: Go did not carry on into the key derivation, it logged {carried_on:?}"
        ));
    } else if let Some(bad) = carried_on[KEY_DERIVATION.len()..]
        .iter()
        .find(|l| !l.starts_with("Listening on: "))
    {
        problems.push(format!(
            "V07: {bad:?} after the key derivation is not the server's listener line"
        ));
    }
    if !(last.starts_with("datashard ")
        && last
            .contains("exceeds 256: cannot create Encoder with more than 256 data+parity shards"))
    {
        problems.push(format!(
            "expected a final `datashard <n> + parityshard <m> exceeds 256: …` line, got {last:?}"
        ));
    }
    if go.exit != Exit::Running {
        problems.push(format!("Go {} instead of running on", go.exit));
    }
    if rust.exit != Exit::Code(1) {
        problems.push(format!("we exited {} instead of 1 (log.Fatal)", rust.exit));
    }
}

/// V21: our stderr is Go's with exactly one line inserted, that line is `extra`, and where it sits
/// does not matter — the client logs it last, the server logs it before its `Listening on:` line.
fn check_one_extra_line(extra: &str, go: &Run, rust: &Run, problems: &mut Vec<String>) {
    if rust.stderr.len() != go.stderr.len() + 1 {
        problems.push(format!(
            "expected exactly one stderr line more than Go's {}, got {}",
            go.stderr.len(),
            rust.stderr.len()
        ));
        diff_lines("stderr", &go.stderr, &rust.stderr, problems);
        return;
    }
    let at = rust
        .stderr
        .iter()
        .zip(&go.stderr)
        .position(|(a, b)| a != b)
        .unwrap_or(go.stderr.len());
    let mut without = rust.stderr.clone();
    let line = without.remove(at);
    if line != extra {
        problems.push(format!(
            "expected the one extra line to be {extra:?}, got {line:?}"
        ));
    }
    diff_lines(
        "stderr (without the extra line)",
        &go.stderr,
        &without,
        problems,
    );
}

/// V15 and V19: Go runs on, we print Go's lines plus one message naming the flag, and exit 1
/// (`log.Fatal`).
fn check_rejected_at_startup(flag: &str, go: &Run, rust: &Run, problems: &mut Vec<String>) {
    diff_lines("stdout", &go.stdout, &rust.stdout, problems);
    let Some((last, head)) = rust.stderr.split_last() else {
        problems.push("nothing was logged".to_string());
        return;
    };
    diff_lines("stderr", &go.stderr, head, problems);
    if !(last.starts_with(flag) && last.contains("does not fit in uint16")) {
        problems.push(format!(
            "expected a final `{flag}<n> does not fit in uint16: …` line, got {last:?}"
        ));
    }
    if go.exit != Exit::Running {
        problems.push(format!("Go {} instead of running on", go.exit));
    }
    if rust.exit != Exit::Code(1) {
        problems.push(format!("we exited {} instead of 1 (log.Fatal)", rust.exit));
    }
}

/// V14: one `-snmplog` file on each side, named `snmp-<zone>.log`, where Go's `<zone>` is the
/// tzdb abbreviation of the local zone and ours is Go's own numeric fallback for a zone with no
/// name.
///
/// The case's `-snmplog` value is `snmp-MST.log`, so the zone token is the whole of the name
/// between the fixed prefix and suffix, whatever the local offset is.
fn check_v14_file_names(go: &Run, rust: &Run, problems: &mut Vec<String>) {
    let [go_name] = &go.files[..] else {
        problems.push(format!("V14: Go wrote {:?}, wanted one file", go.files));
        return;
    };
    let [rs_name] = &rust.files[..] else {
        problems.push(format!("V14: we wrote {:?}, wanted one file", rust.files));
        return;
    };
    let (Some(go_zone), Some(rs_zone)) = (zone_token(go_name), zone_token(rs_name)) else {
        problems.push(format!(
            "V14: {go_name} and {rs_name} are not both `snmp-<zone>.log`"
        ));
        return;
    };
    if go_zone == rs_zone {
        problems.push(format!(
            "V14: both wrote {go_name}, so the zone deviation is gone"
        ));
    }
    if !(!go_zone.is_empty() && go_zone.chars().all(|c| c.is_ascii_alphabetic())) {
        problems.push(format!(
            "V14: Go's zone token {go_zone:?} is not a tzdb abbreviation"
        ));
    }
    if !(rs_zone.starts_with('+') || rs_zone.starts_with('-')) {
        problems.push(format!(
            "V14: our zone token {rs_zone:?} is not Go's numeric fallback"
        ));
    }
}

/// The `<zone>` of an `snmp-<zone>.log` file name.
fn zone_token(name: &str) -> Option<&str> {
    name.strip_prefix("snmp-")?.strip_suffix(".log")
}

/// V20: our stderr is Go's, cut short before the stack trace, and what Go printed after it really
/// is one (`pkg.Func` / tab-indented `file:line` pairs).
fn check_v20_stack_trace(go: &Run, rust: &Run, problems: &mut Vec<String>) {
    let n = rust.stderr.len();
    if go.stderr.len() <= n {
        problems.push(format!(
            "V20: Go printed {} stderr lines and we printed {n}, so there is no stack trace",
            go.stderr.len()
        ));
        return;
    }
    diff_lines(
        "stderr (up to the trace)",
        &go.stderr[..n],
        &rust.stderr,
        problems,
    );
    let trace = &go.stderr[n..];
    if !trace.len().is_multiple_of(2) {
        problems.push(format!(
            "V20: {} trailing lines are not frame/position pairs: {trace:?}",
            trace.len()
        ));
    }
    for (i, line) in trace.iter().enumerate() {
        // `github.com/xtaci/kcp-go/v5.ListenWithOptions` then
        // `\tgithub.com/xtaci/kcp-go/v5@v5.6.66/sess.go:1388`, all the way down to `runtime.goexit`.
        let looks_right = if i.is_multiple_of(2) {
            !line.starts_with('\t') && line.contains('.') && !line.contains(' ')
        } else {
            line.starts_with('\t') && line.contains(':')
        };
        if !looks_right {
            problems.push(format!("V20: {line:?} does not belong to a Go stack trace"));
        }
    }
}

/// Reports the first few differing lines of two normalised streams.
fn diff_lines(what: &str, go: &[String], rust: &[String], problems: &mut Vec<String>) {
    if go == rust {
        return;
    }
    let mut reported = 0;
    for i in 0..go.len().max(rust.len()) {
        let (a, b) = (go.get(i), rust.get(i));
        if a == b {
            continue;
        }
        problems.push(format!(
            "{what} line {}: Go {:?}, ours {:?}",
            i + 1,
            a.map(String::as_str).unwrap_or("<none>"),
            b.map(String::as_str).unwrap_or("<none>")
        ));
        reported += 1;
        if reported == 5 {
            problems.push(format!(
                "{what}: {} lines against {}, further differences not shown",
                go.len(),
                rust.len()
            ));
            break;
        }
    }
}

// ---------------------------------------------------------------------------------------
// Running a whole group
// ---------------------------------------------------------------------------------------

/// Runs every case in `cases` and panics with every failure at once.
///
/// The caller owns `root` (a `tempfile::tempdir()`), so a failing run's directory survives until
/// the test ends.
#[track_caller]
pub fn run_all(cases: &[CliCase], root: &Path) {
    let mut failures = Vec::new();
    let mut passed = Vec::new();
    for case in cases {
        match run_case(case, root) {
            Ok((go, rust)) => match check(case, &go, &rust) {
                Ok(()) => passed.push(match case.expect {
                    Expect::Identical => format!("{} (identical)", case.name),
                    Expect::Deviates(d) => format!("{} ({d})", case.name),
                }),
                Err(report) => failures.push(report),
            },
            Err(e) => failures.push(format!("case {}: {e}", case.name)),
        }
    }
    println!("{} case(s) passed:", passed.len());
    for p in &passed {
        println!("  - {p}");
    }
    assert!(
        failures.is_empty(),
        "{} of {} case(s) differed:\n\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n\n")
    );
}

#[cfg(test)]
mod tests;
