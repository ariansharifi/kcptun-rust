//! Tests for [`crate::log`].
//!
//! The expected header strings are the ones Go printed for the same inputs: a probe program
//! running Go 1.27.1's `log` package over every flag combination kcptun can produce
//! (`log.SetFlags(...)`, `log.SetPrefix(...)`, `log.Println`, `log.Printf`), with the timestamps
//! taken from `LOCAL_TIME_GOLDENS` below. Those goldens come from
//! `time.Unix(e, 123456789).Format("2006/01/02 15:04:05[.000000]")` run under the same `TZ`, so
//! `test_local_time_matches_go` checks this port's calendar conversion: daylight-saving
//! transitions and half-hour zones included, against Go's.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use kcptun_testkit::proc::Proc;

use super::*;

// ---------------------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------------------

// The lock that serialises the tests touching the process-wide logger is `super::TEST_LOCK`
// (imported by the glob below): it lives in `log.rs` because the `snmp` and `signal` tests
// redirect the same logger and take the same lock.

/// Restores the logger (output, flags, prefix and the injected clock) when it is dropped.
struct Fixture {
    _guard: MutexGuard<'static, ()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        set_output_stderr();
        set_flags(default_flags());
        set_prefix("");
        set_test_time(None);
    }
}

fn fixture() -> Fixture {
    let guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    set_output_stderr();
    set_flags(default_flags());
    set_prefix("");
    set_test_time(None);
    Fixture { _guard: guard }
}

/// A log sink a test can read back.
#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn new() -> Capture {
        Capture(Arc::new(Mutex::new(Vec::new())))
    }

    fn install(&self) {
        set_output(Box::new(self.clone()));
    }

    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Runs `body` with the logger writing into a fresh capture and returns what it wrote.
fn capture(body: impl FnOnce()) -> String {
    let sink = Capture::new();
    sink.install();
    body();
    set_output_stderr();
    sink.text()
}

/// The instant every golden below is stamped with: 2026-03-23T12:00:00.123456789Z, seen from a
/// zone one hour ahead of UTC (Europe/Berlin in March), so the local rendering is 13:00:00.
const GOLDEN_TIME: Time = Time {
    unix_secs: 1_774_267_200,
    nanos: 123_456_789,
    offset_secs: 3600,
};

// ---------------------------------------------------------------------------------------
// Header format
// ---------------------------------------------------------------------------------------

/// Every flag combination, against the bytes Go's `log` package wrote for the same input.
#[test]
fn test_format_header_golden() {
    let _f = fixture();
    set_test_time(Some(GOLDEN_TIME));

    // (flags, prefix, file, line, message, expected line)
    let cases: &[(u32, &str, &str, u32, &str, &str)] = &[
        (
            LSTD_FLAGS,
            "",
            "main.go",
            30,
            "version: SELFBUILD\n",
            "2026/03/23 13:00:00 version: SELFBUILD\n",
        ),
        (
            LSTD_FLAGS | LSHORTFILE,
            "",
            "crates/std/src/log.rs",
            30,
            "version: SELFBUILD\n",
            "2026/03/23 13:00:00 log.rs:30: version: SELFBUILD\n",
        ),
        (
            LSTD_FLAGS | LLONGFILE,
            "",
            "crates/std/src/log.rs",
            40,
            "longfile\n",
            "2026/03/23 13:00:00 crates/std/src/log.rs:40: longfile\n",
        ),
        (
            LSTD_FLAGS | LMICROSECONDS | LSHORTFILE,
            "",
            "crates/std/src/log.rs",
            42,
            "micro\n",
            "2026/03/23 13:00:00.123456 log.rs:42: micro\n",
        ),
        (
            LTIME,
            "",
            "log.rs",
            44,
            "time only\n",
            "13:00:00 time only\n",
        ),
        (
            LDATE,
            "",
            "log.rs",
            46,
            "date only\n",
            "2026/03/23 date only\n",
        ),
        (0, "", "log.rs", 48, "no flags\n", "no flags\n"),
        (
            LSTD_FLAGS | LSHORTFILE,
            "pfx: ",
            "log.rs",
            51,
            "with prefix\n",
            "pfx: 2026/03/23 13:00:00 log.rs:51: with prefix\n",
        ),
        (
            LSTD_FLAGS | LSHORTFILE | LMSGPREFIX,
            "pfx: ",
            "log.rs",
            53,
            "with msgprefix\n",
            "2026/03/23 13:00:00 log.rs:53: pfx: with msgprefix\n",
        ),
        (
            LSTD_FLAGS | LUTC,
            "",
            "log.rs",
            55,
            "utc\n",
            "2026/03/23 12:00:00 utc\n",
        ),
        // Go appends the newline only when the assembled buffer lacks one, so a prefix that
        // already ends in a newline plus an empty message stays a single line.
        (0, "pfx\n", "log.rs", 57, "", "pfx\n"),
    ];

    for &(flag, prefix, file, line, msg, want) in cases {
        set_flags(flag);
        set_prefix(prefix);
        let got = capture(|| output(file, line, msg));
        assert_eq!(got, want, "flags {flag:#x} prefix {prefix:?}");
    }
}

/// Go pads the year to four digits, the month, day, hour, minute and second to two, the
/// microseconds to six, and leaves the line number unpadded.
#[test]
fn test_itoa_padding() {
    let mut buf = String::new();
    itoa(&mut buf, 7, 4);
    buf.push(' ');
    itoa(&mut buf, 12345, 2);
    buf.push(' ');
    itoa(&mut buf, 42, -1);
    buf.push(' ');
    itoa(&mut buf, 0, 6);
    assert_eq!(buf, "0007 12345 42 000000");
}

/// Go's shortening looks for `/` from the end but never inspects index 0, so a path that is just
/// `/name` keeps its slash.
#[test]
fn test_short_file() {
    assert_eq!(short_file("crates/std/src/log.rs"), "log.rs");
    assert_eq!(short_file("log.rs"), "log.rs");
    assert_eq!(short_file("/main.go"), "/main.go");
    assert_eq!(short_file("a/b"), "b");
    assert_eq!(short_file("trailing/"), "");
    assert_eq!(short_file(""), "");
}

/// `Lshortfile` is added only for self-builds, exactly like both `main()`s.
#[test]
fn test_default_flags_follow_version() {
    let want = if crate::VERSION == "SELFBUILD" {
        LSTD_FLAGS | LSHORTFILE
    } else {
        LSTD_FLAGS
    };
    assert_eq!(default_flags(), want);
    assert_eq!(LSTD_FLAGS, 3, "Go: Ldate|Ltime");
    assert_eq!(LSHORTFILE, 16, "Go: Lshortfile");
}

// ---------------------------------------------------------------------------------------
// Println / Printf semantics
// ---------------------------------------------------------------------------------------

/// `fmt.Sprintln`: single spaces between all operands, one trailing newline.
#[test]
fn test_println_semantics() {
    let _f = fixture();
    set_test_time(Some(GOLDEN_TIME));
    set_flags(LSTD_FLAGS);

    const TS: &str = "2026/03/23 13:00:00 ";
    assert_eq!(
        capture(|| logln!("sndwnd:", 128, "rcvwnd:", 512)),
        format!("{TS}sndwnd: 128 rcvwnd: 512\n")
    );
    assert_eq!(
        capture(|| logln!("compression:", true)),
        format!("{TS}compression: true\n")
    );
    assert_eq!(
        capture(|| logln!("nodelay parameters:", 1, 10, 2, 1)),
        format!("{TS}nodelay parameters: 1 10 2 1\n")
    );
    // Go: log.Println() → fmt.Sprintln() → "\n", so the line is just the header.
    assert_eq!(capture(|| logln!()), format!("{TS}\n"));
    assert_eq!(capture(|| logln!("")), format!("{TS}\n"));
    // Operands that already contain spaces are not touched.
    assert_eq!(capture(|| logln!("a b", "c")), format!("{TS}a b c\n"));
}

/// `fmt.Sprintf` plus `Output`'s rule: a newline is appended only when the message has none.
#[test]
fn test_printf_semantics() {
    let _f = fixture();
    set_test_time(Some(GOLDEN_TIME));
    set_flags(LSTD_FLAGS);

    const TS: &str = "2026/03/23 13:00:00 ";
    assert_eq!(
        capture(|| logf!("Listening on: {}/tcp", "127.0.0.1:4000")),
        format!("{TS}Listening on: 127.0.0.1:4000/tcp\n")
    );
    // Go: checkError's log.Printf("%+v\n", err), the newline is already there.
    assert_eq!(
        capture(|| logf!("{}\n", "open /nope: no such file or directory")),
        format!("{TS}open /nope: no such file or directory\n")
    );
    assert_eq!(
        capture(|| logf!("ratelimit {} is negative, falling back to 0", -5)),
        format!("{TS}ratelimit -5 is negative, falling back to 0\n")
    );
    // A format string without arguments takes the `as_str` shortcut; same output.
    assert_eq!(capture(|| logf!("plain")), format!("{TS}plain\n"));
    assert_eq!(capture(|| logf!("")), format!("{TS}\n"));
}

/// The macros stamp the call site (Deviation V08: the Rust file and line, not Go's).
#[test]
fn test_macros_report_call_site() {
    let _f = fixture();
    set_test_time(Some(GOLDEN_TIME));
    set_flags(LSTD_FLAGS | LSHORTFILE);

    let (line_no, got) = (line!(), capture(|| logln!("call site")));
    assert_eq!(
        got,
        format!("2026/03/23 13:00:00 log_tests.rs:{line_no}: call site\n")
    );

    let (line_no, got) = (line!(), capture(|| logf!("call {}", "site")));
    assert_eq!(
        got,
        format!("2026/03/23 13:00:00 log_tests.rs:{line_no}: call site\n")
    );
}

// ---------------------------------------------------------------------------------------
// Output redirection
// ---------------------------------------------------------------------------------------

/// `-log` opens with `O_RDWR|O_CREATE|O_APPEND` and mode 0666: existing content survives, every
/// run appends, and the permissions are the ones `os.OpenFile(..., 0666)` asks for.
#[test]
fn test_log_file_redirection_and_append() {
    let _f = fixture();
    set_test_time(Some(GOLDEN_TIME));
    set_flags(LSTD_FLAGS);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kcptun.log");
    std::fs::write(&path, "earlier run\n").unwrap();
    let name = path.to_str().unwrap();

    set_output_file(name).unwrap();
    logln!("first");
    // A second open of the same file (a restart) must not truncate it either.
    set_output_file(name).unwrap();
    logln!("second");
    set_output_stderr();
    // Output no longer goes to the file.
    logln!("log test: back on stderr, not in the file");

    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        text,
        "earlier run\n\
         2026/03/23 13:00:00 first\n\
         2026/03/23 13:00:00 second\n"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // `File::create` uses the same 0666 request, so both land on `0666 & !umask`.
        let reference = dir.path().join("reference");
        std::fs::File::create(&reference).unwrap();
        let mode =
            |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&path), mode(&reference));
    }
}

/// A `-log` path that cannot be opened produces Go's `*PathError` text for `checkError`.
#[test]
fn test_log_file_open_error() {
    let _f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("no-such-dir").join("kcptun.log");
    let err = set_output_file(missing.to_str().unwrap()).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("open {}: no such file or directory", missing.display())
    );
    // The logger keeps its previous output.
    assert!(!capture(|| logln!("still logging")).is_empty());
}

/// Lines from many threads arrive whole: never a header without its message, never two messages
/// on one line. The sink is a real file, so nothing but the logger's own lock serialises them.
#[test]
fn test_concurrent_writes_do_not_interleave() {
    let _f = fixture();
    set_flags(LSTD_FLAGS | LSHORTFILE);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("concurrent.log");
    set_output_file(path.to_str().unwrap()).unwrap();

    const THREADS: usize = 8;
    const LINES: usize = 250;
    std::thread::scope(|scope| {
        for id in 0..THREADS {
            scope.spawn(move || {
                let payload = "x".repeat(200 + id);
                for n in 0..LINES {
                    logln!("thread", id, n, &payload);
                }
            });
        }
    });
    set_output_stderr();

    let text = std::fs::read_to_string(&path).unwrap();
    let mut seen = vec![0usize; THREADS];
    let mut lines = 0;
    for line in text.lines() {
        // "YYYY/MM/DD HH:MM:SS log_tests.rs:NNN: thread <id> <n> xxx..."
        assert!(line.len() > 20, "short line {line:?}");
        let (timestamp, rest) = line.split_at(20);
        assert!(
            is_timestamp(timestamp.trim_end()),
            "bad timestamp in {line:?}"
        );
        let (site, body) = rest.split_once(": ").expect("file:line prefix");
        let (file, number) = site.split_once(':').expect("file:line prefix");
        assert_eq!(file, "log_tests.rs");
        assert!(number.parse::<u32>().is_ok(), "bad line number in {line:?}");
        let fields: Vec<&str> = body.split(' ').collect();
        assert_eq!(fields.len(), 4, "bad message in {line:?}");
        assert_eq!(fields[0], "thread");
        let id: usize = fields[1].parse().expect("thread id");
        let n: usize = fields[2].parse().expect("line number");
        assert_eq!(n, seen[id], "thread {id} lines out of order");
        seen[id] += 1;
        assert_eq!(
            fields[3],
            "x".repeat(200 + id),
            "truncated payload in {line:?}"
        );
        lines += 1;
    }
    assert_eq!(lines, THREADS * LINES);
    assert!(seen.iter().all(|&n| n == LINES), "{seen:?}");
}

/// True for `YYYY/MM/DD HH:MM:SS`.
fn is_timestamp(s: &str) -> bool {
    let shape = "0000/00/00 00:00:00";
    s.len() == shape.len()
        && s.bytes().zip(shape.bytes()).all(|(c, p)| {
            if p == b'0' {
                c.is_ascii_digit()
            } else {
                c == p
            }
        })
}

// ---------------------------------------------------------------------------------------
// Red warnings
// ---------------------------------------------------------------------------------------

/// `color.NoColor`'s initialiser: `NO_COLOR` set to anything non-empty, `TERM=dumb`, or standard
/// output not being a terminal.
#[test]
fn test_no_color_rules() {
    // (NO_COLOR, TERM, stdout is a tty) -> NoColor
    let cases: &[(Option<&str>, Option<&str>, bool, bool)] = &[
        (None, Some("xterm-256color"), true, false),
        (None, None, true, false),
        (Some(""), Some("xterm"), true, false),
        (Some("1"), Some("xterm"), true, true),
        (Some("0"), Some("xterm"), true, true),
        (None, Some("dumb"), true, true),
        (None, Some("xterm"), false, true),
        (None, None, false, true),
    ];
    for &(no_color, term, tty, want) in cases {
        assert_eq!(
            no_color_from(no_color, term, tty),
            want,
            "{no_color:?} {term:?} tty={tty}"
        );
    }
}

/// What `color.Red` puts on the wire: the newline is appended before the colour wraps the
/// message, so the reset comes after it. Without colour the message is printed plainly.
#[test]
fn test_color_red_bytes() {
    assert_eq!(
        color_red_bytes("QPP requires more pads", false),
        "\x1b[31mQPP requires more pads\n\x1b[0m"
    );
    assert_eq!(
        color_red_bytes("QPP requires more pads", true),
        "QPP requires more pads\n"
    );
    // A message that already ends in a newline gets no second one.
    assert_eq!(
        color_red_bytes("warning\n", false),
        "\x1b[31mwarning\n\x1b[0m"
    );
    assert_eq!(color_red_bytes("warning\n", true), "warning\n");
    assert_eq!(color_red_bytes("", true), "\n");
}

/// Under the test harness standard output is a pipe, so `color_red` must fall back to plain
/// text; it must also never panic when nobody reads the pipe.
#[test]
fn test_color_red_without_tty() {
    assert!(
        !std::io::stdout().is_terminal(),
        "the test harness must not hand out a terminal"
    );
    assert!(
        no_color(),
        "colour must be off when stdout is not a terminal"
    );
    color_red("scavengettl is not effective");
}

// ---------------------------------------------------------------------------------------
// Local time, exit codes: run in a child process
// ---------------------------------------------------------------------------------------

/// Environment variable that turns [`subprocess_helper`] into the child this file needs.
const HELPER_ENV: &str = "KCPTUN_LOG_TEST_HELPER";

/// Instants the local-time goldens cover: the epoch, a half-second-precision date, the two sides
/// of the 2025 northern and southern daylight-saving switches, a leap day, and far future dates.
const GOLDEN_EPOCHS: &[i64] = &[
    0,
    1,
    1_234_567_890,
    1_609_459_199,
    1_741_503_599,
    1_741_503_600,
    1_762_063_199,
    1_762_063_200,
    951_782_400,
    4_102_444_800,
    1_774_267_200,
];

/// `time.Unix(e, 123456789).Format("2006/01/02 15:04:05")` and `"...05.000000"`, printed by Go
/// 1.27.1 under each `TZ`, in the order of [`GOLDEN_EPOCHS`].
const LOCAL_TIME_GOLDENS: &[(&str, &[&str])] = &[
    (
        "UTC",
        &[
            "1970/01/01 00:00:00",
            "1970/01/01 00:00:01",
            "2009/02/13 23:31:30",
            "2020/12/31 23:59:59",
            "2025/03/09 06:59:59",
            "2025/03/09 07:00:00",
            "2025/11/02 05:59:59",
            "2025/11/02 06:00:00",
            "2000/02/29 00:00:00",
            "2100/01/01 00:00:00",
            "2026/03/23 12:00:00",
        ],
    ),
    (
        "Asia/Kolkata",
        &[
            "1970/01/01 05:30:00",
            "1970/01/01 05:30:01",
            "2009/02/14 05:01:30",
            "2021/01/01 05:29:59",
            "2025/03/09 12:29:59",
            "2025/03/09 12:30:00",
            "2025/11/02 11:29:59",
            "2025/11/02 11:30:00",
            "2000/02/29 05:30:00",
            "2100/01/01 05:30:00",
            "2026/03/23 17:30:00",
        ],
    ),
    (
        "America/New_York",
        &[
            "1969/12/31 19:00:00",
            "1969/12/31 19:00:01",
            "2009/02/13 18:31:30",
            "2020/12/31 18:59:59",
            "2025/03/09 01:59:59",
            "2025/03/09 03:00:00",
            "2025/11/02 01:59:59",
            "2025/11/02 01:00:00",
            "2000/02/28 19:00:00",
            "2099/12/31 19:00:00",
            "2026/03/23 08:00:00",
        ],
    ),
    (
        "Europe/Berlin",
        &[
            "1970/01/01 01:00:00",
            "1970/01/01 01:00:01",
            "2009/02/14 00:31:30",
            "2021/01/01 00:59:59",
            "2025/03/09 07:59:59",
            "2025/03/09 08:00:00",
            "2025/11/02 06:59:59",
            "2025/11/02 07:00:00",
            "2000/02/29 01:00:00",
            "2100/01/01 01:00:00",
            "2026/03/23 13:00:00",
        ],
    ),
    (
        "Australia/Lord_Howe",
        &[
            "1970/01/01 10:00:00",
            "1970/01/01 10:00:01",
            "2009/02/14 10:31:30",
            "2021/01/01 10:59:59",
            "2025/03/09 17:59:59",
            "2025/03/09 18:00:00",
            "2025/11/02 16:59:59",
            "2025/11/02 17:00:00",
            "2000/02/29 11:00:00",
            "2100/01/01 11:00:00",
            "2026/03/23 23:00:00",
        ],
    ),
    (
        "Asia/Kathmandu",
        &[
            "1970/01/01 05:30:00",
            "1970/01/01 05:30:01",
            "2009/02/14 05:16:30",
            "2021/01/01 05:44:59",
            "2025/03/09 12:44:59",
            "2025/03/09 12:45:00",
            "2025/11/02 11:44:59",
            "2025/11/02 11:45:00",
            "2000/02/29 05:45:00",
            "2100/01/01 05:45:00",
            "2026/03/23 17:45:00",
        ],
    ),
];

/// The child process behind the tests below: it either renders the goldens under the `TZ` it was
/// given, or takes one of the two paths that end the process.
#[test]
fn subprocess_helper() {
    let Ok(mode) = std::env::var(HELPER_ENV) else {
        return; // the ordinary test run: nothing to do
    };
    match mode.as_str() {
        "times" => {
            let mut out = String::new();
            for &epoch in GOLDEN_EPOCHS {
                let t = Time::at_local(epoch, 123_456_789);
                let mut std_fmt = String::new();
                format_header(&mut std_fmt, t, "", LSTD_FLAGS, "", 0);
                let mut micro_fmt = String::new();
                format_header(&mut micro_fmt, t, "", LSTD_FLAGS | LMICROSECONDS, "", 0);
                let _ = writeln!(
                    out,
                    "GOLDEN\t{epoch}\t{}\t{}",
                    std_fmt.trim_end(),
                    micro_fmt.trim_end()
                );
            }
            print!("{out}");
            let _ = std::io::stdout().flush();
        }
        // Go: client/main.go:297 log.Fatal("conn must be greater than 0")
        "fatal" => {
            register_exit_marker();
            end_harness_line();
            fatal("conn must be greater than 0")
        }
        // Go: checkError(err) on a missing -c file
        "check_error" => {
            register_exit_marker();
            end_harness_line();
            let err: Result<(), String> =
                Err("open /etc/kcptun.json: no such file or directory".to_string());
            check_error(err);
        }
        other => panic!("unknown helper mode {other:?}"),
    }
}

/// The marker the two fatal helpers print from an exit hook.
///
/// Go's `postProcess` runs on the signal path only, so a `log.Fatal` there leaves tcpraw's
/// iptables rules in place; this port runs the registered hooks on the fatal paths too
/// (step 10.4), and this is what proves it in a real process.
const EXIT_HOOK_MARKER: &str = "exit hook ran";

/// Registers a hook that prints [`EXIT_HOOK_MARKER`] where the binaries register tcpraw's
/// `iptables_reset`.
fn register_exit_marker() {
    crate::signal::register_exit_hook(|| {
        // stderr is a file here, and the child dies immediately after: flush.
        eprintln!("{EXIT_HOOK_MARKER}");
        let _ = std::io::stderr().flush();
    });
}

/// The test harness leaves `test log::tests::subprocess_helper ... ` on standard output without
/// a newline, and the child's two streams share one log file; this ends that line so the log
/// line the parent checks starts at a line boundary.
fn end_harness_line() {
    let _ = std::io::stdout().flush();
    eprintln!();
}

/// Runs this test binary's [`subprocess_helper`] in `mode`, returning its exit code and output.
fn run_helper(mode: &str, env: &[(&str, &str)]) -> (Option<i32>, String) {
    let exe = std::env::current_exe().expect("test executable");
    let mut builder = Proc::builder(exe)
        .name(format!("log-helper-{mode}"))
        .args([
            "log::tests::subprocess_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(HELPER_ENV, mode);
    for &(key, value) in env {
        builder = builder.env(key, value);
    }
    let mut child = builder.spawn().expect("spawn helper");
    let status = child
        .wait_timeout(Duration::from_secs(60))
        .expect("wait for helper")
        .expect("helper exited");
    let log = child.log();
    (status.code(), log)
}

/// This port's local-time conversion, including daylight-saving switches and half-hour zones,
/// renders exactly like Go's.
#[test]
fn test_local_time_matches_go() {
    let mut zones = 0;
    for &(zone, expected) in LOCAL_TIME_GOLDENS {
        if !std::path::Path::new("/usr/share/zoneinfo")
            .join(zone)
            .exists()
        {
            eprintln!("skipping {zone}: no zoneinfo on this host");
            continue;
        }
        zones += 1;
        let (code, log) = run_helper("times", &[("TZ", zone)]);
        assert_eq!(code, Some(0), "helper failed for {zone}:\n{log}");
        // The harness prints its own progress line before the first golden, on the same line.
        let got: Vec<&str> = log
            .lines()
            .filter_map(|l| l.find("GOLDEN\t").map(|i| &l[i..]))
            .collect();
        assert_eq!(
            got.len(),
            GOLDEN_EPOCHS.len(),
            "helper output for {zone}:\n{log}"
        );
        for (line, (&epoch, &want)) in got.iter().zip(GOLDEN_EPOCHS.iter().zip(expected)) {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 4, "{line:?}");
            assert_eq!(fields[1], epoch.to_string(), "{line:?}");
            assert_eq!(fields[2], want, "{zone} {epoch}");
            assert_eq!(fields[3], format!("{want}.123456"), "{zone} {epoch}");
        }
    }
    assert!(zones > 0, "no time zone database on this host");
}

/// `log.Fatal` logs the message and exits 1.
#[test]
fn test_fatal_exits_1() {
    let (code, log) = run_helper("fatal", &[]);
    assert_eq!(code, Some(EXIT_FATAL), "{log}");
    let line = log
        .lines()
        .find(|l| l.contains("conn must be greater than 0"))
        .unwrap_or_else(|| panic!("message missing:\n{log}"));
    assert!(
        line.len() > 20 && is_timestamp(&line[..19]),
        "no timestamp in {line:?}"
    );
    if default_flags() & LSHORTFILE != 0 {
        assert!(
            line.contains("log_tests.rs:"),
            "call site missing in {line:?}"
        );
    }
    assert!(line.ends_with("conn must be greater than 0"), "{line:?}");
    // The exit hooks run before the process goes: on a `--tcp` server this is where tcpraw's
    // iptables rules are removed.
    assert!(
        log.lines().any(|l| l == EXIT_HOOK_MARKER),
        "the exit hooks did not run:\n{log}"
    );
}

/// `checkError` prints the error and exits with `os.Exit(-1)`, status 255.
#[test]
fn test_check_error_exits_255() {
    let (code, log) = run_helper("check_error", &[]);
    assert_eq!(code, Some(EXIT_CHECK_ERROR), "{log}");
    let line = log
        .lines()
        .find(|l| l.contains("open /etc/kcptun.json"))
        .unwrap_or_else(|| panic!("message missing:\n{log}"));
    assert!(
        line.ends_with("open /etc/kcptun.json: no such file or directory"),
        "{line:?}"
    );
    // Go's "%+v\n" already ends the line: no blank line follows.
    let next = log
        .lines()
        .skip_while(|l| !l.contains("open /etc/kcptun.json"))
        .nth(1);
    assert_ne!(next, Some(""), "an extra newline was added:\n{log}");
    // As in `test_fatal_exits_1`: the exit hooks run on this path too.
    assert!(
        log.lines().any(|l| l == EXIT_HOOK_MARKER),
        "the exit hooks did not run:\n{log}"
    );
}
