//! Unit tests for the CLI differential harness: the normaliser and the deviation checks, over
//! transcripts captured from the real binaries. These need no processes, so unlike
//! `tests/cli_diff.rs` they are **not** `#[ignore]` and run in the gate.

use std::path::Path;

use super::*;

/// A `Run` built from two transcripts, as [`run_one`] would produce it.
fn run(implementation: Impl, stdout: &str, stderr: &str, exit: Exit) -> Run {
    let norm = Norm {
        dir: Path::new("/tmp/nonexistent-dir"),
        program: Path::new(match implementation {
            Impl::Go => "client_darwin_arm64",
            Impl::Rust => "kcptun-client",
        }),
        ephemeral_listen: true,
    };
    let (stdout, mut locations) = normalise(stdout, &norm);
    let (stderr, err_locations) = normalise(stderr, &norm);
    locations.extend(err_locations);
    Run {
        implementation,
        argv: vec!["-l".into(), "127.0.0.1:0".into()],
        stdout,
        stderr,
        exit,
        locations,
        files: Vec::new(),
        file_lines: Vec::new(),
    }
}

fn go(stdout: &str, stderr: &str, exit: Exit) -> Run {
    run(Impl::Go, stdout, stderr, exit)
}

fn rust(stdout: &str, stderr: &str, exit: Exit) -> Run {
    run(Impl::Rust, stdout, stderr, exit)
}

/// The problems `check` reported, or an empty vector when the case passed.
fn problems(case: &CliCase, a: &Run, b: &Run) -> Vec<String> {
    match check(case, a, b) {
        Ok(()) => Vec::new(),
        Err(report) => report
            .lines()
            .filter_map(|l| l.strip_prefix("  - "))
            .map(str::to_string)
            .collect(),
    }
}

// ---------------------------------------------------------------------------------------
// Normalisation
// ---------------------------------------------------------------------------------------

#[test]
fn the_log_header_is_stripped_and_the_source_position_kept() {
    let norm = Norm {
        dir: Path::new("/nope"),
        program: Path::new("client_darwin_arm64"),
        ephemeral_listen: false,
    };
    let (lines, locations) = normalise(
        "2026/09/23 11:29:59 main.go:316: version: SELFBUILD\n\
         2026/09/23 11:29:59 main.go:356: snmplog: \n",
        &norm,
    );
    assert_eq!(lines, ["version: SELFBUILD", "snmplog: "]);
    assert_eq!(locations, ["main.go:316", "main.go:356"]);
}

#[test]
fn a_line_that_is_not_a_log_line_is_left_alone() {
    let norm = Norm {
        dir: Path::new("/nope"),
        program: Path::new("kcptun-client"),
        ephemeral_listen: false,
    };
    // Help text, a Go stack-trace frame, and a message whose first word ends in a colon.
    let (lines, locations) = normalise(
        "Incorrect Usage. flag needs an argument: -mtu\n\
         github.com/xtaci/kcp-go/v5.ListenWithOptions\n\
         \tgithub.com/xtaci/kcp-go/v5@v5.6.66/sess.go:1388\n\
         2026/09/23 11:32:06 main.rs:322: SetReadBuffer: set udp [::]:29900: setsockopt: invalid argument\n",
        &norm,
    );
    assert_eq!(
        lines,
        [
            "Incorrect Usage. flag needs an argument: -mtu",
            "github.com/xtaci/kcp-go/v5.ListenWithOptions",
            "\tgithub.com/xtaci/kcp-go/v5@v5.6.66/sess.go:1388",
            "SetReadBuffer: set udp [::]:29900: setsockopt: invalid argument",
        ]
    );
    // Only the header's position is a location; the one inside the trace frame is content.
    assert_eq!(locations, ["main.rs:322"]);
}

#[test]
fn the_run_directory_and_the_program_name_are_masked() {
    let norm = Norm {
        dir: Path::new("/var/folders/q0/T/tmp1/cd9go"),
        program: Path::new("/somewhere/client_darwin_arm64"),
        ephemeral_listen: false,
    };
    let (lines, _) = normalise(
        "2026/09/23 11:29:59 main.go:554: open /var/folders/q0/T/tmp1/cd9go/nope.json: no such file or directory\n\
         USAGE:\n\
         \u{20}  client_darwin_arm64 [global options] command [command options] [arguments...]\n",
        &norm,
    );
    assert_eq!(
        lines,
        [
            "open {dir}/nope.json: no such file or directory",
            "USAGE:",
            "   {prog} [global options] command [command options] [arguments...]",
        ]
    );
}

#[test]
fn only_an_ephemeral_listening_port_is_masked() {
    let fixed = Norm {
        dir: Path::new("/nope"),
        program: Path::new("kcptun-client"),
        ephemeral_listen: false,
    };
    let ephemeral = Norm {
        ephemeral_listen: true,
        ..fixed
    };
    let text = "2026/09/23 11:29:59 main.rs:225: listening on: 127.0.0.1:61835\n\
                2026/09/23 11:29:59 main.rs:340: remote address: 127.0.0.1:24001\n";
    assert_eq!(
        normalise(text, &fixed).0,
        [
            "listening on: 127.0.0.1:61835",
            "remote address: 127.0.0.1:24001"
        ]
    );
    assert_eq!(
        normalise(text, &ephemeral).0,
        [
            "listening on: 127.0.0.1:{port}",
            // Only `listening on:` is ephemeral; every other address is the one we passed in.
            "remote address: 127.0.0.1:24001"
        ]
    );
}

#[test]
fn a_unix_listener_line_keeps_its_path() {
    let norm = Norm {
        dir: Path::new("/tmp/t/cu9go"),
        program: Path::new("kcptun-client"),
        ephemeral_listen: true,
    };
    let (lines, _) = normalise(
        "2026/09/23 11:29:59 main.rs:225: listening on: /tmp/t/cu9go/c.sock\n",
        &norm,
    );
    assert_eq!(lines, ["listening on: {dir}/c.sock"]);
}

// ---------------------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------------------

#[test]
fn placeholders_drive_the_port_block_and_are_expanded_once() {
    let case = CliCase::server(
        "server_range",
        ["-l", "127.0.0.1:{port0}-{port2}", "-c", "{config}"],
    );
    assert_eq!(case.port_count(), 3);
    assert!(!case.ephemeral_listen());

    let block = ports::allocate(3);
    let args = case.expand(Path::new("/tmp/d"), Some(block));
    assert_eq!(
        args,
        [
            "-l".to_string(),
            format!("127.0.0.1:{}-{}", block.port(0), block.port(2)),
            "-c".to_string(),
            "/tmp/d/config.json".to_string(),
        ]
    );

    let none = CliCase::client("client_defaults", ["-l", "127.0.0.1:0"]);
    assert_eq!(none.port_count(), 0);
    assert!(none.ephemeral_listen());
}

#[test]
fn only_the_three_startup_rejections_stop_our_binary_early() {
    let runs = CliCase::client("c", ["-l", "127.0.0.1:0"]).runs();
    assert!(keeps_running(&runs, Impl::Go) && keeps_running(&runs, Impl::Rust));

    let v07 = runs.clone().deviates(Deviation::V07FecShardsExceed256);
    assert!(keeps_running(&v07, Impl::Go) && !keeps_running(&v07, Impl::Rust));
    let v15 = runs.clone().deviates(Deviation::V15QppCountTruncates);
    assert!(keeps_running(&v15, Impl::Go) && !keeps_running(&v15, Impl::Rust));
    let v19 = runs.clone().deviates(Deviation::V19ConnTruncatesToZero);
    assert!(keeps_running(&v19, Impl::Go) && !keeps_running(&v19, Impl::Rust));

    // V21 changes nothing about the process: both sides run on.
    let v21 = runs.clone().deviates(Deviation::V21PprofNotAvailable);
    assert!(keeps_running(&v21, Impl::Go) && keeps_running(&v21, Impl::Rust));

    // A case that exits is waited for on both sides, deviation or not.
    let exits = CliCase::client("c", ["-v"]).deviates(Deviation::V06UsageExitStatus);
    assert!(!keeps_running(&exits, Impl::Go) && !keeps_running(&exits, Impl::Rust));
}

#[test]
fn run_directories_are_short_and_distinct() {
    // macOS `sun_path` is 104 bytes, and the socket lives inside the run directory.
    let name = short_name("client_unix_listener_and_a_very_long_name");
    assert!(name.len() <= 16, "{name:?} is too long for sun_path");
    // Names that share their initials, and even their length, still get different directories.
    assert_ne!(short_name("client_defaults"), short_name("server_defaults"));
    assert_ne!(
        short_name("client_conn_65536"),
        short_name("client_conn_65537")
    );
    assert_eq!(short_name("client_defaults"), short_name("client_defaults"));
}

// ---------------------------------------------------------------------------------------
// The comparison, and each allowed deviation
// ---------------------------------------------------------------------------------------

/// The startup block of `client -l 127.0.0.1:0 -r 127.0.0.1:24001`, shortened.
const STARTUP: &str = "2026/09/23 11:29:59 main.go:316: version: SELFBUILD\n\
                       2026/09/23 11:29:59 main.go:335: listening on: 127.0.0.1:61834\n\
                       2026/09/23 11:29:59 main.go:387: key derivation done\n";
/// The same lines out of our binary: same text, Rust source positions (V08).
const STARTUP_RS: &str = "2026/09/23 11:30:00 main.rs:214: version: SELFBUILD\n\
                          2026/09/23 11:30:00 main.rs:225: listening on: 127.0.0.1:61835\n\
                          2026/09/23 11:30:00 main.rs:166: key derivation done\n";

#[test]
fn identical_output_passes_and_a_changed_line_does_not() {
    let case = CliCase::client("c", ["-l", "127.0.0.1:0"]).runs();
    let a = go("", STARTUP, Exit::Running);
    let b = rust("", STARTUP_RS, Exit::Running);
    assert_eq!(problems(&case, &a, &b), Vec::<String>::new());

    let changed = rust(
        "",
        &STARTUP_RS.replace("key derivation done", "key derivation finished"),
        Exit::Running,
    );
    assert_eq!(
        problems(&case, &a, &changed),
        ["stderr line 3: Go \"key derivation done\", ours \"key derivation finished\""]
    );
}

#[test]
fn a_different_exit_status_is_a_difference_of_its_own() {
    let case = CliCase::client("c", ["-l", "127.0.0.1:0"]).runs();
    let a = go("", STARTUP, Exit::Running);
    let b = rust("", STARTUP_RS, Exit::Code(1));
    assert_eq!(
        problems(&case, &a, &b),
        ["exit status: Go still running, ours exit 1"]
    );
}

#[test]
fn v08_is_asserted_for_every_case_whatever_it_expects() {
    let case = CliCase::client("c", ["-l", "127.0.0.1:0"]).runs();
    // A Go binary logging a Rust source position, or ours logging a Go one, is not V08.
    let a = go(
        "",
        &STARTUP.replace("main.go:316", "main.rs:316"),
        Exit::Running,
    );
    let b = rust("", STARTUP_RS, Exit::Running);
    assert_eq!(
        problems(&case, &a, &b),
        ["V08: go logged a `main.rs:316` header, which is not a .go source position"]
    );
}

#[test]
fn v06_wants_the_same_text_with_a_different_status() {
    let usage = "Incorrect Usage. flag provided but not defined: -nosuchflag\n\nNAME:\n";
    let case = CliCase::client("c", ["-nosuchflag"]).deviates(Deviation::V06UsageExitStatus);
    let a = go(usage, "", Exit::Code(0));
    let b = rust(usage, "", Exit::Code(2));
    assert_eq!(problems(&case, &a, &b), Vec::<String>::new());

    // Exiting 0 like Go would mean the deviation is gone and the allow-list is stale.
    let same = rust(usage, "", Exit::Code(0));
    assert_eq!(
        problems(&case, &a, &same),
        ["V06: we exited exit 0 instead of 2"]
    );
    // A different usage message is not covered by V06.
    let other = rust(&usage.replace("-nosuchflag", "-other"), "", Exit::Code(2));
    assert_eq!(
        problems(&case, &a, &other).len(),
        1,
        "the text difference must be reported"
    );
}

#[test]
fn v15_and_v19_add_exactly_one_line_and_exit_one() {
    let v15 = CliCase::client("c", ["-QPPCount", "65536"])
        .runs()
        .deviates(Deviation::V15QppCountTruncates);
    let a = go("", STARTUP, Exit::Running);
    let b = rust(
        "",
        &format!(
            "{STARTUP_RS}2026/09/23 11:30:00 main.rs:129: QPPCount 65536 does not fit in uint16: \
             kcptun would truncate it to 0\n"
        ),
        Exit::Code(1),
    );
    assert_eq!(problems(&v15, &a, &b), Vec::<String>::new());

    // Running on like Go does (or stopping for another reason) is not V15.
    let ran_on = rust("", STARTUP_RS, Exit::Running);
    assert_eq!(
        problems(&v15, &a, &ran_on),
        [
            "stderr line 3: Go \"key derivation done\", ours \"<none>\"",
            "expected a final `QPPCount <n> does not fit in uint16: …` line, got \"key derivation \
             done\"",
            "we exited still running instead of 1 (log.Fatal)",
        ]
    );

    let v19 = CliCase::client("c", ["-conn", "65536"])
        .runs()
        .deviates(Deviation::V19ConnTruncatesToZero);
    let conn = rust(
        "",
        &format!(
            "{STARTUP_RS}2026/09/23 11:30:00 main.rs:190: conn 65536 does not fit in uint16: \
             kcptun would truncate it to 0\n"
        ),
        Exit::Code(1),
    );
    assert_eq!(problems(&v19, &a, &conn), Vec::<String>::new());
}

/// The startup block a 257-shard case produces, shortened, in both flavours.
const FEC_GO: &str = "2026/09/23 13:04:05 main.go:316: version: SELFBUILD\n\
                      2026/09/23 13:04:05 main.go:345: datashard: 255 parityshard: 2\n";
const FEC_RS: &str = "2026/09/23 13:04:19 main.rs:214: version: SELFBUILD\n\
                      2026/09/23 13:04:19 main.rs:241: datashard: 255 parityshard: 2\n";
/// Our line at the FEC check, and the two Go reaches instead.
const FEC_FATAL: &str = "2026/09/23 13:04:19 main.rs:160: datashard 255 + parityshard 2 exceeds \
                         256: cannot create Encoder with more than 256 data+parity shards\n";
const FEC_DERIVATION: &str = "2026/09/23 13:04:05 main.go:385: initiating key derivation\n\
                              2026/09/23 13:04:05 main.go:387: key derivation done\n";

#[test]
fn v07_stops_us_where_go_carries_on_into_the_key_derivation() {
    let case = CliCase::client("c", ["-datashard", "255", "-parityshard", "2"])
        .runs()
        .deviates(Deviation::V07FecShardsExceed256);
    let a = go("", &format!("{FEC_GO}{FEC_DERIVATION}"), Exit::Running);
    let b = rust("", &format!("{FEC_RS}{FEC_FATAL}"), Exit::Code(1));
    assert_eq!(problems(&case, &a, &b), Vec::<String>::new());

    // The server reaches its listener as well, which is the one further line V07 allows.
    let server_case = CliCase::server("s", ["-datashard", "255", "-parityshard", "2"])
        .runs()
        .deviates(Deviation::V07FecShardsExceed256);
    let listening = "2026/09/23 13:07:52 main.go:392: Listening on: 127.0.0.1:19311/udp\n";
    let served = go(
        "",
        &format!("{FEC_GO}{FEC_DERIVATION}{listening}"),
        Exit::Running,
    );
    assert_eq!(problems(&server_case, &served, &b), Vec::<String>::new());

    // Anything else Go logs past the rejection is not "it accepted the shard count and ran".
    let noise = go(
        "",
        &format!("{FEC_GO}{FEC_DERIVATION}2026/09/23 13:07:52 main.go:402: something else\n"),
        Exit::Running,
    );
    assert_eq!(
        problems(&case, &noise, &b),
        ["V07: \"something else\" after the key derivation is not the server's listener line"]
    );

    // A Go binary that stopped too would mean the deviation is gone.
    let stopped = go("", FEC_GO, Exit::Code(1));
    assert_eq!(
        problems(&case, &stopped, &b),
        [
            "V07: Go did not carry on into the key derivation, it logged []",
            "Go exit 1 instead of running on",
        ]
    );
}

#[test]
fn v07_wants_our_final_line_to_name_both_flags_and_the_limit() {
    let case = CliCase::client("c", ["-datashard", "255", "-parityshard", "2"])
        .runs()
        .deviates(Deviation::V07FecShardsExceed256);
    let a = go("", &format!("{FEC_GO}{FEC_DERIVATION}"), Exit::Running);
    let vague = rust(
        "",
        &format!("{FEC_RS}2026/09/23 13:04:19 main.rs:160: too many shards\n"),
        Exit::Code(1),
    );
    assert_eq!(
        problems(&case, &a, &vague),
        [
            "expected a final `datashard <n> + parityshard <m> exceeds 256: …` line, got \"too \
             many shards\"",
        ]
    );
}

#[test]
fn v21_is_one_extra_line_and_nothing_else() {
    let case = CliCase::client("c", ["--pprof"])
        .runs()
        .deviates(Deviation::V21PprofNotAvailable);
    let extra = "2026/09/23 13:05:11 pprof.rs:98: pprof: not available in this build\n";
    let a = go("", STARTUP, Exit::Running);
    let b = rust("", &format!("{STARTUP_RS}{extra}"), Exit::Running);
    assert_eq!(problems(&case, &a, &b), Vec::<String>::new());

    // The server logs it in the middle, before its listener line; the position is not the point.
    let listening = "2026/09/23 13:09:01 main.go:392: Listening on: 127.0.0.1:19321/udp\n";
    let listening_rs = "2026/09/23 13:09:07 main.rs:204: Listening on: 127.0.0.1:19321/udp\n";
    let served = go("", &format!("{STARTUP}{listening}"), Exit::Running);
    let ours = rust(
        "",
        &format!("{STARTUP_RS}{extra}{listening_rs}"),
        Exit::Running,
    );
    assert_eq!(problems(&case, &served, &ours), Vec::<String>::new());

    // No extra line at all is a `--features pprof` build, which is an identical case, not this one.
    let identical = rust("", STARTUP_RS, Exit::Running);
    assert_eq!(
        problems(&case, &a, &identical),
        ["expected exactly one stderr line more than Go's 3, got 3"]
    );

    // Any other extra line is a difference V21 does not cover.
    let other = rust(
        "",
        &format!(
            "{STARTUP_RS}2026/09/23 13:05:11 pprof.rs:86: pprof server: listen tcp :6060: bind: \
             address already in use\n"
        ),
        Exit::Running,
    );
    assert_eq!(
        problems(&case, &a, &other),
        [
            "expected the one extra line to be \"pprof: not available in this build\", got \
             \"pprof server: listen tcp :6060: bind: address already in use\"",
        ]
    );
}

#[test]
fn v20_accepts_a_go_stack_trace_and_nothing_else() {
    let fatal = "2026/09/23 11:31:57 main.go:544: listen udp 127.0.0.1:24777: bind: address already in use\n\
                 github.com/xtaci/kcp-go/v5.ListenWithOptions\n\
                 \tgithub.com/xtaci/kcp-go/v5@v5.6.66/sess.go:1388\n\
                 main.main\n\
                 \tgithub.com/xtaci/kcptun/server/main.go:402\n";
    let ours = "2026/09/23 11:31:58 main.rs:205: listen udp 127.0.0.1:24777: bind: address already in use\n";
    let case =
        CliCase::server("s", ["-l", "127.0.0.1:{port0}"]).deviates(Deviation::V20NoStackTrace);
    let a = go("", fatal, Exit::Code(255));
    let b = rust("", ours, Exit::Code(255));
    assert_eq!(problems(&case, &a, &b), Vec::<String>::new());

    // The first line must still match byte for byte.
    let other = rust(
        "",
        &ours.replace("address already in use", "address in use"),
        Exit::Code(255),
    );
    assert_eq!(problems(&case, &a, &other).len(), 1);

    // Trailing lines that are not a stack trace are a real difference.
    let first_line = fatal.lines().next().expect("fatal line");
    let noise = go(
        "",
        &format!("{first_line}\nsomething else entirely\n"),
        Exit::Code(255),
    );
    assert_eq!(
        problems(&case, &noise, &b),
        [
            "V20: 1 trailing lines are not frame/position pairs: [\"something else entirely\"]",
            "V20: \"something else entirely\" does not belong to a Go stack trace",
        ]
    );
}

#[test]
fn v14_wants_one_differently_named_snmp_file_on_each_side() {
    let case = CliCase::server("s", ["-snmplog", "snmp-MST.log"])
        .runs()
        .deviates(Deviation::V14SnmpLogZone);
    let mut a = go("", STARTUP, Exit::Running);
    let mut b = rust("", STARTUP_RS, Exit::Running);
    a.files = vec!["snmp-BST.log".to_string()];
    b.files = vec!["snmp-+0100.log".to_string()];
    assert_eq!(problems(&case, &a, &b), Vec::<String>::new());

    // A zone that agreed would mean V14 is gone; so would an abbreviation on our side.
    let mut same = b.clone();
    same.files = vec!["snmp-BST.log".to_string()];
    assert_eq!(
        problems(&case, &a, &same),
        [
            "V14: both wrote snmp-BST.log, so the zone deviation is gone",
            "V14: our zone token \"BST\" is not Go's numeric fallback",
        ]
    );
}

#[test]
fn files_left_behind_are_compared_for_every_other_case() {
    let case = CliCase::client("c", ["-log", "{dir}/out.log"]).runs();
    let a = go("", STARTUP, Exit::Running);
    let mut b = rust("", STARTUP_RS, Exit::Running);
    b.files = vec!["out.log".to_string()];
    assert_eq!(
        problems(&case, &a, &b),
        ["files left behind: Go [], ours [\"out.log\"]"]
    );
}
