//! Logging in the format of Go's standard `log` package, as the kcptun binaries produce it.
//!
//! Go sources:
//! - Go standard library `log/log.go` (Go 1.27.1) — the flag bits, [`format_header`]'s layout
//!   and `Logger.Output`'s "append a newline unless the message already has one" rule;
//! - `kcptun/client/main.go:60-64`, `kcptun/server/main.go:65-69` —
//!   `log.SetFlags(log.LstdFlags | log.Lshortfile)` when `VERSION == "SELFBUILD"`, plain
//!   `LstdFlags` otherwise (Go's default);
//! - `kcptun/client/main.go:305-311`, `kcptun/server/main.go:290-296` — the `-log` file,
//!   `os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)` followed by `log.SetOutput(f)`;
//! - `kcptun/client/main.go:checkError`, `kcptun/server/main.go:checkError` — `log.Printf("%+v\n",
//!   err)` and `os.Exit(-1)`, which is status **255** on unix;
//! - `fatih/color@v1.18.0 color.go:Red`, `colorPrint`, `Color.Set`/`Unset` and the `NoColor`
//!   initialiser — the red QPP and `scavengettl` warnings.
//!
//! The two message shapes Go uses are `log.Println` (operands joined with single spaces, newline
//! appended) and `log.Printf` (a format string, newline only when it is missing); they are
//! [`logln!`](crate::logln) and [`logf!`](crate::logf) here.
//!
//! **Deviation V08**: with `Lshortfile` the header carries the **Rust** source file and line of the
//! call site instead of Go's. Everything else about the header is byte for byte Go's.

use std::fmt::{self, Display, Write as _};
use std::io::{IsTerminal as _, Write};
use std::panic::Location;
use std::sync::{Mutex, MutexGuard, OnceLock};

use chrono::{Datelike as _, Local, Offset as _, TimeZone as _, Timelike as _};

use crate::config::go_error_text;

// ---------------------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------------------

/// `2009/01/23` — the date in the local time zone.
// Go: log/log.go:Ldate
pub const LDATE: u32 = 1 << 0;
/// `01:23:23` — the time in the local time zone.
// Go: log/log.go:Ltime
pub const LTIME: u32 = 1 << 1;
/// `01:23:23.123123` — microsecond resolution. Assumes [`LTIME`].
// Go: log/log.go:Lmicroseconds
pub const LMICROSECONDS: u32 = 1 << 2;
/// `/a/b/c/d.rs:23` — the full file name and the line number.
// Go: log/log.go:Llongfile
pub const LLONGFILE: u32 = 1 << 3;
/// `d.rs:23` — the final file name element and the line number; overrides [`LLONGFILE`].
// Go: log/log.go:Lshortfile
pub const LSHORTFILE: u32 = 1 << 4;
/// Use UTC rather than the local time zone for [`LDATE`] and [`LTIME`].
// Go: log/log.go:LUTC
pub const LUTC: u32 = 1 << 5;
/// Move the prefix from the start of the line to just before the message.
// Go: log/log.go:Lmsgprefix
pub const LMSGPREFIX: u32 = 1 << 6;
/// Initial values for the standard logger: date and time, no file or line.
// Go: log/log.go:LstdFlags
pub const LSTD_FLAGS: u32 = LDATE | LTIME;

/// Exit status of [`fatal`], Go's `log.Fatal` → `os.Exit(1)`.
pub const EXIT_FATAL: i32 = 1;
/// Exit status of [`check_error`]: Go's `os.Exit(-1)`, which unix reports as 255.
pub const EXIT_CHECK_ERROR: i32 = 255;

/// The flags the binaries start with.
///
/// Go's `log` package starts at `LstdFlags`; both `main()`s add `Lshortfile` when the build is a
/// self-build, "to simplify debugging self-built binaries".
// Go: kcptun/client/main.go:60-64, kcptun/server/main.go:65-69
pub const fn default_flags() -> u32 {
    if crate::version::is_selfbuild() {
        LSTD_FLAGS | LSHORTFILE
    } else {
        LSTD_FLAGS
    }
}

// ---------------------------------------------------------------------------------------
// The instant a line is stamped with
// ---------------------------------------------------------------------------------------

/// A `time.Time` reduced to what the header needs: the instant, plus the local zone's offset at
/// that instant so that [`LUTC`] can still undo it.
// Go: time.Time as log's `Output` passes it to `formatHeader`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Time {
    /// Seconds since the unix epoch.
    pub unix_secs: i64,
    /// Nanoseconds within the second, `0..1_000_000_000`.
    pub nanos: u32,
    /// Seconds the local zone is ahead of UTC at this instant.
    pub offset_secs: i32,
}

impl Time {
    /// The current instant in the local time zone.
    // Go: time.Now()
    pub fn now() -> Time {
        let now = Local::now();
        Time {
            unix_secs: now.timestamp(),
            nanos: now.timestamp_subsec_nanos(),
            offset_secs: now.offset().fix().local_minus_utc(),
        }
    }

    /// A fixed instant, with the local zone's offset **at that instant** (so historical dates and
    /// daylight-saving changes render the way Go renders them).
    // Go: time.Unix(secs, nanos)
    pub fn at_local(unix_secs: i64, nanos: u32) -> Time {
        let offset_secs = match Local.timestamp_opt(unix_secs, 0) {
            chrono::offset::LocalResult::Single(t) => t.offset().fix().local_minus_utc(),
            // Ambiguous (the hour a zone repeats): Go's `time.Unix` never is, because it maps an
            // absolute instant; `timestamp_opt` only reports the two candidates for the local
            // wall clock, so the earlier one is the instant's own offset.
            chrono::offset::LocalResult::Ambiguous(t, _) => t.offset().fix().local_minus_utc(),
            chrono::offset::LocalResult::None => 0,
        };
        Time {
            unix_secs,
            nanos,
            offset_secs,
        }
    }

    /// The broken-down calendar fields, in UTC when `utc` is set and in the local zone otherwise.
    fn fields(&self, utc: bool) -> Fields {
        let secs = if utc {
            self.unix_secs
        } else {
            self.unix_secs.saturating_add(i64::from(self.offset_secs))
        };
        // Out of chrono's range (year ±262143) — no real clock reaches it; keep the epoch rather
        // than panicking, since a logger must never take the process down.
        let t = chrono::DateTime::from_timestamp(secs, 0)
            .unwrap_or(chrono::DateTime::UNIX_EPOCH)
            .naive_utc();
        Fields {
            year: t.year(),
            month: t.month(),
            day: t.day(),
            hour: t.hour(),
            minute: t.minute(),
            second: t.second(),
            nanosecond: self.nanos,
        }
    }
}

/// Broken-down calendar fields, Go's `t.Date()`, `t.Clock()` and `t.Nanosecond()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fields {
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    nanosecond: u32,
}

#[cfg(test)]
thread_local! {
    /// The clock the logger stamps lines with. Tests replace it per thread; Go's logger always
    /// reads the wall clock.
    static TEST_TIME: std::cell::Cell<Option<Time>> = const { std::cell::Cell::new(None) };
}

/// Pins the timestamp of this thread's log lines, or releases it again with `None`.
#[cfg(test)]
pub(crate) fn set_test_time(t: Option<Time>) {
    TEST_TIME.with(|c| c.set(t));
}

#[cfg(test)]
fn current_time() -> Time {
    TEST_TIME.with(|c| c.get()).unwrap_or_else(Time::now)
}

#[cfg(not(test))]
fn current_time() -> Time {
    Time::now()
}

// ---------------------------------------------------------------------------------------
// The global logger
// ---------------------------------------------------------------------------------------

/// Where log lines go. Go's `log.SetOutput` takes any `io.Writer`; the standard logger starts at
/// `os.Stderr`.
enum Output {
    /// The process's standard error, Go's default.
    Stderr,
    /// Anything else: the `-log` file, or a sink a test installed.
    Writer(Box<dyn Write + Send>),
}

/// Everything `log.Logger` protects with its mutex.
// Go: log/log.go:Logger
struct Logger {
    out: Output,
    prefix: String,
    flag: u32,
}

static LOGGER: Mutex<Logger> = Mutex::new(Logger {
    out: Output::Stderr,
    prefix: String::new(),
    flag: default_flags(),
});

/// Locks the logger, recovering from a panic that happened while another thread held it: a
/// poisoned lock must not silence the logs (and never leaves the state half-written, as each line
/// is formatted and written under one lock acquisition).
fn logger() -> MutexGuard<'static, Logger> {
    LOGGER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The flags of the standard logger.
// Go: log.Flags()
pub fn flags() -> u32 {
    logger().flag
}

/// Sets the flags of the standard logger.
// Go: log.SetFlags()
pub fn set_flags(flag: u32) {
    logger().flag = flag;
}

/// The prefix of the standard logger (kcptun never sets one).
// Go: log.Prefix()
pub fn prefix() -> String {
    logger().prefix.clone()
}

/// Sets the prefix of the standard logger.
// Go: log.SetPrefix()
pub fn set_prefix(prefix: &str) {
    logger().prefix = prefix.to_string();
}

/// Sends log output to `w`.
// Go: log.SetOutput()
pub fn set_output(w: Box<dyn Write + Send>) {
    logger().out = Output::Writer(w);
}

/// Sends log output back to standard error, where Go's standard logger starts.
// Go: log.SetOutput(os.Stderr)
pub fn set_output_stderr() {
    logger().out = Output::Stderr;
}

/// Serialises every test that redirects the process-wide logger: this module's own tests and
/// those of [`crate::snmp`] and [`crate::signal`], which read back what the logger wrote.
#[cfg(test)]
pub(crate) static TEST_LOCK: Mutex<()> = Mutex::new(());

/// The `-log` file could not be opened. Go hands the `*PathError` to `checkError`, which prints
/// `open /var/log/kcptun.log: permission denied` and exits 255.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("open {path}: {err}")]
pub struct LogFileError {
    /// The path as it was given on the command line.
    pub path: String,
    /// The operating system's message, in Go's spelling.
    pub err: String,
}

/// Redirects log output to `path`, appending to it, exactly like the `-log` flag.
///
/// The file stays open for the lifetime of the process, as Go's `defer f.Close()` in `main` does.
// Go: kcptun/client/main.go:305-311, kcptun/server/main.go:290-296
pub fn set_output_file(path: &str) -> Result<(), LogFileError> {
    let mut opts = std::fs::OpenOptions::new();
    // Go: os.O_RDWR|os.O_CREATE|os.O_APPEND — `append` implies write, and `read` makes it O_RDWR.
    opts.read(true).append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // Go: perm 0666, which the process umask reduces as usual.
        opts.mode(0o666);
    }
    let file = opts.open(path).map_err(|err| LogFileError {
        path: path.to_string(),
        err: go_error_text(&err),
    })?;
    set_output(Box::new(file));
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------------------

/// Appends `i` to `buf`, zero padded to at least `wid` digits (`wid < 0` means no padding).
// Go: log/log.go:itoa
fn itoa(buf: &mut String, i: u32, wid: i32) {
    let wid = usize::try_from(wid).unwrap_or(0);
    let text = i.to_string();
    for _ in text.len()..wid {
        buf.push('0');
    }
    buf.push_str(&text);
}

/// Go's `Lshortfile` shortening: everything after the **last** `/`, except that index 0 is never
/// looked at, so `"/main.go"` keeps its slash. Only `/` separates, as in Go.
// Go: log/log.go:formatHeader
fn short_file(file: &str) -> &str {
    let bytes = file.as_bytes();
    let mut i = bytes.len().saturating_sub(1);
    while i > 0 {
        if bytes[i] == b'/' {
            return &file[i + 1..];
        }
        i -= 1;
    }
    file
}

/// Writes the header — prefix, date, time, file and line — in Go's order.
// Go: log/log.go:formatHeader
fn format_header(buf: &mut String, t: Time, prefix: &str, flag: u32, file: &str, line: u32) {
    if flag & LMSGPREFIX == 0 {
        buf.push_str(prefix);
    }
    if flag & (LDATE | LTIME | LMICROSECONDS) != 0 {
        let f = t.fields(flag & LUTC != 0);
        if flag & LDATE != 0 {
            // Go's itoa takes an int; a year is never negative on a real clock.
            itoa(buf, u32::try_from(f.year).unwrap_or(0), 4);
            buf.push('/');
            itoa(buf, f.month, 2);
            buf.push('/');
            itoa(buf, f.day, 2);
            buf.push(' ');
        }
        if flag & (LTIME | LMICROSECONDS) != 0 {
            itoa(buf, f.hour, 2);
            buf.push(':');
            itoa(buf, f.minute, 2);
            buf.push(':');
            itoa(buf, f.second, 2);
            if flag & LMICROSECONDS != 0 {
                buf.push('.');
                itoa(buf, f.nanosecond / 1_000, 6);
            }
            buf.push(' ');
        }
    }
    if flag & (LSHORTFILE | LLONGFILE) != 0 {
        let file = if flag & LSHORTFILE != 0 {
            short_file(file)
        } else {
            file
        };
        buf.push_str(file);
        buf.push(':');
        itoa(buf, line, -1);
        buf.push_str(": ");
    }
    if flag & LMSGPREFIX != 0 {
        buf.push_str(prefix);
    }
}

/// Writes one log line: the header, the message, and a newline when the message lacks one.
///
/// The line is formatted and written under a single lock acquisition, with one `write_all`, so
/// concurrent callers never interleave. (Go formats outside `outMu`, reading prefix and flag from
/// atomics; this cold path keeps one critical section instead.) Write errors are dropped, as Go's
/// `log.Print*` drop the error `Output` returns.
// Go: log/log.go:Logger.Output
pub fn output(file: &str, line: u32, msg: &str) {
    let now = current_time();
    let mut logger = logger();
    let mut buf = String::with_capacity(msg.len() + 48);
    format_header(&mut buf, now, &logger.prefix, logger.flag, file, line);
    buf.push_str(msg);
    // Go tests the assembled buffer, not the message: `len(*buf) == 0 || (*buf)[len(*buf)-1] != '\n'`.
    if !buf.ends_with('\n') {
        buf.push('\n');
    }
    let bytes = buf.as_bytes();
    let _ = match &mut logger.out {
        Output::Stderr => {
            let mut err = std::io::stderr().lock();
            err.write_all(bytes).and_then(|()| err.flush())
        }
        Output::Writer(w) => w.write_all(bytes).and_then(|()| w.flush()),
    };
}

// ---------------------------------------------------------------------------------------
// Print entry points
// ---------------------------------------------------------------------------------------

/// `log.Println`: the operands separated by single spaces, with a newline appended.
///
/// Called through [`logln!`](crate::logln), which supplies the call site.
// Go: log.Println → fmt.Sprintln
pub fn println_at(file: &str, line: u32, operands: &[&dyn Display]) {
    let mut msg = String::new();
    for (i, operand) in operands.iter().enumerate() {
        if i > 0 {
            msg.push(' ');
        }
        // Writing into a String cannot fail; a Display implementation that returns an error is
        // the caller's bug, and losing that operand is better than taking the process down.
        let _ = write!(msg, "{operand}");
    }
    msg.push('\n');
    output(file, line, &msg);
}

/// `log.Printf`: the formatted message, with a newline appended only when it has none.
///
/// Called through [`logf!`](crate::logf), which supplies the call site.
// Go: log.Printf → fmt.Sprintf
pub fn printf_at(file: &str, line: u32, args: fmt::Arguments<'_>) {
    match args.as_str() {
        Some(s) => output(file, line, s),
        None => output(file, line, &fmt::format(args)),
    }
}

/// Logs the operands like `log.Println` and appends a newline.
///
/// ```
/// # use kcptun_std::logln;
/// # let (snd_wnd, rcv_wnd) = (128, 512);
/// logln!("sndwnd:", snd_wnd, "rcvwnd:", rcv_wnd); // 2026/03/23 13:00:00 main.rs:4: sndwnd: 128 rcvwnd: 512
/// ```
#[macro_export]
macro_rules! logln {
    () => {
        $crate::log::println_at(::core::file!(), ::core::line!(), &[])
    };
    ($($operand:expr),+ $(,)?) => {
        $crate::log::println_at(
            ::core::file!(),
            ::core::line!(),
            &[$(&$operand as &dyn ::core::fmt::Display),+],
        )
    };
}

/// Logs a formatted message like `log.Printf`, appending a newline only when it has none.
///
/// ```
/// # use kcptun_std::logf;
/// # let rate_limit = -5;
/// logf!("ratelimit {rate_limit} is negative, falling back to 0");
/// ```
#[macro_export]
macro_rules! logf {
    ($($arg:tt)*) => {
        $crate::log::printf_at(::core::file!(), ::core::line!(), ::core::format_args!($($arg)*))
    };
}

// ---------------------------------------------------------------------------------------
// Fatal paths
// ---------------------------------------------------------------------------------------

/// Logs `msg` and terminates the process with status 1.
///
/// Go's `log.Fatal(v ...any)` renders its operands with `fmt.Sprint`, which inserts a space only
/// between two operands that are *both* non-strings; the call sites pass a message that already
/// reads correctly, so they are written out here:
///
/// | Go | Rust |
/// |---|---|
/// | `log.Fatal("conn must be greater than 0")` | `fatal("conn must be greater than 0")` |
/// | `log.Fatal("unsupported smux version:", config.SmuxVer)` | `fatal(&format!("unsupported smux version:{ver}"))` |
/// | `log.Fatal(err)` | `fatal(&err.to_string())` |
/// | `log.Fatalf("%+v", err)` (`client/main.go:427`) | `fatal(&format!("{err}"))` |
///
/// There is no `fatalf!` macro: the only `log.Fatalf` call site uses `%+v`, which is the same as
/// `%v` for the values it sees (see [`check_error`]), so `format!` at the call site suffices.
// Go: log/log.go:Fatal — Output(2, fmt.Sprint(v...)) then os.Exit(1)
#[track_caller]
pub fn fatal(msg: &str) -> ! {
    let caller = Location::caller();
    output(caller.file(), caller.line(), msg);
    // Go's `postProcess` runs on the signal path only, so a `log.Fatal` there leaves tcpraw's
    // iptables rules behind. This port runs the registered exit hooks on every exit path it
    // controls (step 10.4); with none registered — every test, and every binary
    // before `signal::register_iptables_reset()` — it does nothing.
    crate::signal::post_process();
    std::process::exit(EXIT_FATAL)
}

/// Unwraps `result`, or logs the error and terminates the process with status 255.
///
/// Go prints the error with `%+v`. Most call sites (`client/main.go:293,308,324,326,329,331`,
/// `server/main.go:282,293`) hand it a plain `os`, `net` or `encoding/json` error, where `%+v` is
/// the same as `%v` — which is what this port's error types render, since their `Display` carries
/// Go's exact text.
///
/// `server/main.go:383,394` are different: `kcp.ServeConn` and `kcp.ListenWithOptions` return
/// `github.com/pkg/errors` values (`errors.WithStack`), so Go's `%+v` prints the message line and
/// then a Go stack trace. This port prints the message line only, with Go's exact text, since a Go
/// runtime stack has no meaning in a Rust binary; the deviation is awaiting its own entry in
/// docs/DECISIONS.md. See `crates/server/src/main_tests.rs`
/// (`listen_failures_read_like_gos_net_operror`) for the reproduction.
// Go: kcptun/client/main.go:checkError, kcptun/server/main.go:checkError
#[track_caller]
pub fn check_error<T, E: Display>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(err) => {
            let caller = Location::caller();
            // Go: log.Printf("%+v\n", err) — the trailing newline is already there, so Output
            // adds none.
            output(caller.file(), caller.line(), &format!("{err}\n"));
            // As in `fatal`: the exit hooks run on this path too, so a server that already has
            // a tcpraw listener does not leave its rules behind when the UDP bind fails.
            crate::signal::post_process();
            std::process::exit(EXIT_CHECK_ERROR)
        }
    }
}

// ---------------------------------------------------------------------------------------
// Red warnings
// ---------------------------------------------------------------------------------------

/// ANSI SGR sequence `fatih/color` writes before a red message (`FgRed` = 31).
// Go: fatih/color@v1.18.0 color.go:Color.format, escape + "[31m"
const RED: &str = "\x1b[31m";
/// The sequence it writes afterwards: `Unset` always uses the generic reset, not the per-attribute
/// one from `unformat`.
// Go: fatih/color@v1.18.0 color.go:Unset
const RESET: &str = "\x1b[0m";

/// Go's package-level `color.NoColor`, computed once per process as its initialiser is.
static NO_COLOR: OnceLock<bool> = OnceLock::new();

/// Decides `color.NoColor` from the environment and whether standard output is a terminal.
// Go: fatih/color@v1.18.0 color.go:18-23 (NoColor) and color.go:39-41 (noColorIsSet)
fn no_color_from(no_color_env: Option<&str>, term_env: Option<&str>, stdout_is_tty: bool) -> bool {
    no_color_env.is_some_and(|v| !v.is_empty()) || term_env == Some("dumb") || !stdout_is_tty
}

/// Whether colour is disabled for this process.
fn no_color() -> bool {
    *NO_COLOR.get_or_init(|| {
        no_color_from(
            std::env::var("NO_COLOR").ok().as_deref(),
            std::env::var("TERM").ok().as_deref(),
            std::io::stdout().is_terminal(),
        )
    })
}

/// The exact bytes `color.Red(msg)` writes: the newline is appended to the message *before* the
/// colour wraps it, so the reset follows the newline. Verified against the pinned
/// `fatih/color@v1.18.0` on a pty: `1b 5b 33 31 6d` … `0a` `1b 5b 30 6d`, and the plain message
/// when standard output is a pipe, when `NO_COLOR` is set or when `TERM=dumb`.
///
/// `colorPrint` passes the message to `Print` (not `Printf`) when it has no operands, so a `%` in
/// the message is never interpreted — as here.
// Go: fatih/color@v1.18.0 color.go:colorPrint + Color.Print (Set, Fprint, unset)
fn color_red_bytes(msg: &str, no_color: bool) -> String {
    let mut out = String::with_capacity(msg.len() + RED.len() + RESET.len() + 1);
    if !no_color {
        out.push_str(RED);
    }
    out.push_str(msg);
    if !msg.ends_with('\n') {
        out.push('\n');
    }
    if !no_color {
        out.push_str(RESET);
    }
    out
}

/// Prints `msg` to standard output in red, plainly when standard output is not a terminal.
///
/// Used for the QPP suggestions and the `scavengettl` warning, which Go prints with `color.Red`.
// Go: fatih/color@v1.18.0 color.go:Red, used in kcptun/client/main.go and kcptun/server/main.go
pub fn color_red(msg: &str) {
    let text = color_red_bytes(msg, no_color());
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(text.as_bytes()).and_then(|()| out.flush());
}

#[cfg(test)]
#[path = "log_tests.rs"]
mod tests;
