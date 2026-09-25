//! Startup-log and CLI differential against the Go binaries (plan step 09.5).
//!
//! Every case below is one command line run through `reference/bin/{client,server}_*` and through
//! our `kcptun-client`/`kcptun-server`, with stdout, stderr and the exit status compared line by
//! line after [`normalise`](kcptun_interop_tests::clidiff::normalise) has taken out the timestamp,
//! the `file:line`, the run's own directory and an ephemeral port.
//!
//! | Test | Cases |
//! |---|---|
//! | `cli_diff_client_startup_matches_go` | the client's defaults, every `-mode`, JSON configs, the env key, base-0 ints, a unix listener, a port range, QPP warnings, `-log`, and the two fatal checks |
//! | `cli_diff_server_startup_matches_go` | the server's defaults, a listen range, a wildcard listener, `-sockbuf -1`, QPP, a unix target, the production profile |
//! | `cli_diff_v06_usage_errors_exit_2` | **V06**: identical usage text, exit 2 instead of 0 |
//! | `cli_diff_v07_more_than_256_fec_shards_are_rejected_at_startup` | **V07**: refused here, Go runs on with Leopard parity |
//! | `cli_diff_v08_the_log_header_carries_our_source_position` | **V08**: `main.rs:214` where Go has `main.go:316` |
//! | `cli_diff_v14_snmplog_file_name_carries_the_zone_offset` | **V14**: `snmp-+0100.log` where Go writes `snmp-BST.log` |
//! | `cli_diff_v15_qppcount_beyond_uint16_is_rejected_at_startup` | **V15**: 65536 and 65537 refused; Go truncates and runs |
//! | `cli_diff_v19_conn_that_truncates_to_zero_is_rejected_at_startup` | **V19**: 65536 refused, 65537 runs (in the identical group) |
//! | `cli_diff_v20_go_prints_a_stack_trace_after_a_fatal_error` | **V20**: our fatal line is Go's, without the trace |
//! | `cli_diff_v21_pprof_without_the_feature_logs_one_extra_line` | **V21**: `pprof: not available in this build`, or nothing at all in a `--features pprof` build |
//!
//! Those eight V-numbers are the **whole** allow-list: a case that differs in any other way fails,
//! and so does one whose deviation has disappeared. Nothing is deliberately left uncovered;
//! `pprof_and_oversized_fec_appear_only_in_the_cases_that_pin_them` keeps the two newest entries
//! from leaking into a case that does not assert them.
//!
//! Needs both implementations' binaries, hence `#[ignore]`:
//!
//! ```sh
//! cargo build --release -p kcptun-client -p kcptun-server
//! cargo test -p kcptun-interop-tests --test cli_diff -- --ignored --nocapture
//! ```

use std::collections::BTreeSet;
use std::time::Duration;

use kcptun_interop_tests::clidiff::{CliCase, Deviation, Expect, run_all, short_name};

/// The client's remote address in a JSON config, which cannot hold an allocated port. Nothing is
/// dialled at startup (the client dials when a local connection arrives), so it is never used.
const JSON_REMOTE: &str = "127.0.0.1:19001";

/// A key long enough for QPP's `QPPMinimumSeedLength(8)` of 211 bytes.
fn long_key() -> String {
    "0123456789abcdef".repeat(19)
}

/// Whether the binaries under test carry the optional `pprof` feature (D23).
///
/// V21 has two halves: without the feature `--pprof` logs one extra line, and **with** it the
/// output is byte-identical to Go. The first is what a normal run checks; set `KCPTUN_RS_PPROF=1`
/// together with `KCPTUN_RS_BIN_DIR` pointing at such a build to check the second:
///
/// ```sh
/// cargo build --release -p kcptun-client -p kcptun-server \
///     --features kcptun-client/pprof,kcptun-server/pprof --target-dir target/pprof
/// KCPTUN_RS_BIN_DIR=$PWD/target/pprof/release KCPTUN_RS_PPROF=1 \
///     cargo test -p kcptun-interop-tests --test cli_diff -- --ignored cli_diff_v21 --nocapture
/// ```
fn pprof_feature_build() -> bool {
    matches!(std::env::var("KCPTUN_RS_PPROF"), Ok(v) if !v.is_empty() && v != "0")
}

// ---------------------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------------------

/// The client's base arguments: an ephemeral local listener and a remote nothing answers.
fn client_base() -> Vec<String> {
    ["-l", "127.0.0.1:0", "-r", "127.0.0.1:{port0}"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// The server's base arguments.
fn server_base() -> Vec<String> {
    ["-l", "127.0.0.1:{port0}", "-t", "127.0.0.1:{port1}"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// A client case with [`client_base`] plus `extra`.
fn client(name: &'static str, extra: &[&str]) -> CliCase {
    let mut args = client_base();
    args.extend(extra.iter().map(|s| s.to_string()));
    CliCase::client(name, args)
}

/// A server case with [`server_base`] plus `extra`.
fn server(name: &'static str, extra: &[&str]) -> CliCase {
    let mut args = server_base();
    args.extend(extra.iter().map(|s| s.to_string()));
    CliCase::server(name, args)
}

/// Client cases whose output must be identical.
fn client_cases() -> Vec<CliCase> {
    vec![
        // kcptun's defaults: aes, snappy, FEC 10/3, smux v2, mode fast.
        client("client_defaults", &[]).runs(),
        // Every mode preset, which rewrites `nodelay parameters:` and `sndwnd:`/`rcvwnd:`.
        client("client_mode_fast2", &["-mode", "fast2"]).runs(),
        client("client_mode_fast3", &["-mode", "fast3"]).runs(),
        client("client_mode_normal", &["-mode", "normal"]).runs(),
        client(
            "client_mode_manual",
            &[
                "-mode",
                "manual",
                "-nodelay",
                "1",
                "-interval",
                "10",
                "-resend",
                "2",
                "-nc",
                "1",
            ],
        )
        .runs(),
        // A different cipher, no compression, smux v1, DSCP and pacing.
        client(
            "client_crypt_and_transport",
            &[
                "-crypt",
                "salsa20",
                "-nocomp",
                "-quiet",
                "-smuxver",
                "1",
                "-dscp",
                "46",
                "-ratelimit",
                "1000000",
                "-mtu",
                "1400",
            ],
        )
        .runs(),
        // Go's `flag` parses ints with base 0: octal, hex and binary literals all count.
        client(
            "client_octal_and_hex_ints",
            &[
                "-mtu", "01350", "-sndwnd", "0x100", "-rcvwnd", "0777", "-smuxbuf", "0x400000",
                "-conn", "0b10",
            ],
        )
        .runs(),
        // `--key` has an environment default, and QPP reports the key's length.
        client("client_env_key", &["-QPP"])
            .env("KCPTUN_KEY", "an-environment-secret")
            .runs(),
        // JSON with Go's case-insensitive key matching, and an unknown key that is ignored.
        CliCase::client("client_json_mixed_case", ["-c", "{config}"])
            .json(format!(
                r#"{{"LocalAddr":"127.0.0.1:0","RemoteAddr":"{JSON_REMOTE}","MTU":1400,
                    "SndWnd":256,"crypt":"xor","NoComp":true,"smuxver":1,"KEY":"json-key",
                    "Mode":"normal","datashard":0,"parityshard":0,"NoSuchKey":"ignored"}}"#
            ))
            .ephemeral()
            .runs(),
        // "-c ... will override the command from shell": the JSON wins over the flags.
        CliCase::client(
            "client_json_overrides_the_command_line",
            ["-mtu", "1300", "-crypt", "aes-128", "-c", "{config}"],
        )
        .json(format!(
            r#"{{"localaddr":"127.0.0.1:0","remoteaddr":"{JSON_REMOTE}","mtu":1200}}"#
        ))
        .ephemeral()
        .runs(),
        // A string where an int belongs, and a number that is not integral: both are fatal.
        CliCase::client("client_json_wrong_type", ["-c", "{config}"]).json(format!(
            r#"{{"localaddr":"127.0.0.1:0","remoteaddr":"{JSON_REMOTE}","mtu":"1400"}}"#
        )),
        CliCase::client("client_json_non_integer", ["-c", "{config}"]).json(format!(
            r#"{{"localaddr":"127.0.0.1:0","remoteaddr":"{JSON_REMOTE}","sndwnd":300.5}}"#
        )),
        CliCase::client("client_json_missing_file", ["-c", "{dir}/nope.json"]),
        // A local listener that is not a `host:port` is a unix socket.
        CliCase::client(
            "client_unix_listener",
            ["-l", "{dir}/c.sock", "-r", "127.0.0.1:{port0}"],
        )
        .runs(),
        // kcptun's multiport syntax on the remote side.
        client(
            "client_remote_port_range",
            &["-r", "127.0.0.1:{port0}-{port2}"],
        )
        .runs(),
        // The two QPP warnings: a key that is too short, and a pad count that is not prime.
        client("client_qpp_short_key", &["-QPP", "-key", "short"]).runs(),
        client(
            "client_qpp_count_not_prime",
            &["-QPP", "-QPPCount", "60", "-key", long_key().as_str()],
        )
        .runs(),
        // The red two-line warning when a session can outlive its own expiry.
        client(
            "client_scavengettl_above_autoexpire",
            &["-autoexpire", "10", "-scavengettl", "30"],
        )
        .runs(),
        client(
            "client_conn_4_and_expiry",
            &[
                "-conn",
                "4",
                "-autoexpire",
                "30",
                "-scavengettl",
                "10",
                "-keepalive",
                "3",
            ],
        )
        .runs(),
        // V07 stays narrow: 256 shards is the most klauspost's `New()` still builds the classic
        // codec for, so it is the last configuration a kcptun peer can decode — and it starts
        // here exactly as it does in Go. 257 is the deviation, one shard further on.
        client(
            "client_fec_256_shards",
            &["-datashard", "253", "-parityshard", "3"],
        )
        .runs(),
        // V19 stays narrow: 65537 truncates to 1 and runs one tunnel, exactly as in Go.
        client("client_conn_65537", &["-conn", "65537"]).runs(),
        // `-log` moves the whole block into a file, so stderr must be empty on both sides.
        client("client_log_to_file", &["-log", "{dir}/out.log"])
            .runs()
            .compare_file("out.log"),
        // The two startup checks that end the process.
        client("client_smuxver_3", &["-smuxver", "3"]),
        client("client_conn_0", &["-conn", "0"]),
        CliCase::client("client_version", ["-v"]),
        CliCase::client("client_help", ["-h"]),
    ]
}

/// Server cases whose output must be identical.
fn server_cases() -> Vec<CliCase> {
    vec![
        server("server_defaults", &[]).runs(),
        // A listen range binds every port in it and logs one `Listening on:` line per port.
        server(
            "server_listen_port_range",
            &["-l", "127.0.0.1:{port0}-{port2}"],
        )
        .runs(),
        // A wildcard listener (`[::]`), manual mode and the rest of the server-only flags.
        server(
            "server_wildcard_and_manual_mode",
            &[
                "-l",
                ":{port0}",
                "-mode",
                "manual",
                "-acknodelay",
                "-closewait",
                "5",
                "-nodelay",
                "1",
                "-interval",
                "20",
                "-resend",
                "0",
                "-nc",
                "1",
            ],
        )
        .runs(),
        // A `-sockbuf` the kernel refuses: the failure is logged, not fatal, and its text is a
        // `*net.OpError` (`set udp <addr>: setsockopt: invalid argument`). On Linux both kernels
        // accept the value and neither side logs anything, which is just as good a comparison.
        server("server_sockbuf_setsockopt_error", &["-sockbuf", "-1"]).runs(),
        server(
            "server_qpp_with_a_long_key",
            &["-QPP", "-QPPCount", "61", "-key", long_key().as_str()],
        )
        .runs(),
        // A unix target: the server splits `host:port` and falls back to `unix` when it cannot.
        CliCase::server(
            "server_unix_target",
            ["-l", "127.0.0.1:{port0}", "-t", "{dir}/t.sock"],
        )
        .runs(),
        // The production profile of step 09's interop matrix, minus what needs a peer.
        server(
            "server_production_profile",
            &[
                "-mode",
                "normal",
                "-crypt",
                "xor",
                "-mtu",
                "1390",
                "-sndwnd",
                "8192",
                "-rcvwnd",
                "8192",
                "-smuxver",
                "2",
                "-smuxbuf",
                "16777216",
                "-streambuf",
                "16777216",
                "-datashard",
                "0",
                "-parityshard",
                "0",
                "-nocomp",
                "-quiet",
                "-sockbuf",
                "67108868",
            ],
        )
        .runs(),
        server("server_smuxver_3", &["-smuxver", "3"]),
        CliCase::server("server_version", ["-v"]),
        CliCase::server("server_help", ["-h"]),
    ]
}

/// **V06**: the usage errors. Go prints the message plus the whole help text and exits **0**;
/// we print the same bytes and exit **2**.
fn v06_cases() -> Vec<CliCase> {
    vec![
        CliCase::client("client_bad_flag", ["-nosuchflag"]).deviates(Deviation::V06UsageExitStatus),
        // A flag whose value is missing, and a boolean flag with a value that is not one.
        CliCase::client("client_missing_value", ["-l", "127.0.0.1:0", "-mtu"])
            .deviates(Deviation::V06UsageExitStatus),
        CliCase::client("client_bad_bool", ["-nocomp=maybe"])
            .deviates(Deviation::V06UsageExitStatus),
        CliCase::server("server_bad_flag", ["-nosuchflag"]).deviates(Deviation::V06UsageExitStatus),
    ]
}

/// **V07**: `datashard + parityshard` above 256. Go's `reedsolomon.New` quietly hands the
/// configuration to the Leopard GF(2^16) codec and the binary runs on, emitting parity that
/// kcp-go's own `newFECDecoder` refuses; we stop at the FEC check instead, one line before the key
/// derivation, and exit 1.
///
/// Both binaries carry the check, and their output has a different shape either side of it: the
/// client's last line is `key derivation done`, the server goes on to log `Listening on:` as well.
fn v07_cases() -> Vec<CliCase> {
    vec![
        client(
            "client_fec_257_shards",
            &["-datashard", "255", "-parityshard", "2"],
        )
        .runs()
        .deviates(Deviation::V07FecShardsExceed256),
        server(
            "server_fec_257_shards",
            &["-datashard", "255", "-parityshard", "2"],
        )
        .runs()
        .deviates(Deviation::V07FecShardsExceed256),
    ]
}

/// **V08**: the `file:line` of a `SELFBUILD` build. Every case proves it in passing; this one
/// names it, so the allow-list entry cannot go stale unnoticed.
fn v08_cases() -> Vec<CliCase> {
    vec![
        client("client_log_header", &[])
            .runs()
            .deviates(Deviation::V08FileAndLine),
    ]
}

/// **V14**: `MST` in a `-snmplog` file name.
fn v14_cases() -> Vec<CliCase> {
    vec![
        server(
            "server_snmplog_zone",
            &["-snmplog", "snmp-MST.log", "-snmpperiod", "1"],
        )
        .runs()
        // Pin the zone: the deviation is about the *token*, and tzdb abbreviations are numeric in
        // many zones (`TZ=Asia/Novosibirsk` makes Go write `snmp-+07.log`), which would fail the
        // "Go's token is an abbreviation" assertion on a perfectly healthy host. Both sides honour
        // TZ, so America/Denver gives Go `snmp-MDT.log` and us `snmp--0600.log`.
        .env("TZ", "America/Denver")
        // std.SnmpLogger creates the file on the first tick of a 1 s ticker, so leave both
        // processes enough room to reach it even when the suite's threads are all spawning.
        .settle(Duration::from_millis(3000))
        .deviates(Deviation::V14SnmpLogZone),
    ]
}

/// **V15**: a `-QPPCount` that does not fit in `uint16`, in both its flavours.
fn v15_cases() -> Vec<CliCase> {
    vec![
        // 65536 truncates to 0: Go builds the pad and divides by zero on the first encrypted byte.
        client("client_qppcount_65536", &["-QPP", "-QPPCount", "65536"])
            .runs()
            .deviates(Deviation::V15QppCountTruncates),
        // 65537 truncates to 1: Go passes every check on the pre-cast int, warns about nothing,
        // and runs with a single pad. The key is long enough that Go really does print no
        // warning at all, which is the point of the wide check.
        client(
            "client_qppcount_65537",
            &["-QPP", "-QPPCount", "65537", "-key", long_key().as_str()],
        )
        .runs()
        .deviates(Deviation::V15QppCountTruncates),
    ]
}

/// **V19**: a `-conn` that truncates to zero.
fn v19_cases() -> Vec<CliCase> {
    vec![
        client("client_conn_65536", &["-conn", "65536"])
            .runs()
            .deviates(Deviation::V19ConnTruncatesToZero),
    ]
}

/// **V20**: the stack trace Go adds after a fatal error. The port is held by the harness, so the
/// listener's `bind` fails on both sides.
fn v20_cases() -> Vec<CliCase> {
    vec![
        server("server_bind_address_in_use", &[])
            .hold_port0()
            .deviates(Deviation::V20NoStackTrace),
    ]
}

/// **V21**: `--pprof` in a build without the optional `pprof` feature. The flag is accepted either
/// way (D23), so the whole difference is one extra line — last on the client, and before
/// `Listening on:` on the server, which is why both binaries have a case.
///
/// In a `--features pprof` build there is no difference at all, and the very same command lines
/// are expected to be byte-identical to Go; see [`pprof_feature_build`] for how to run that half.
/// Both runs bind Go's fixed `:6060`, so the two cases share the test that runs them sequentially.
fn v21_cases() -> Vec<CliCase> {
    [
        client("client_pprof", &["--pprof"]).runs(),
        server("server_pprof", &["--pprof"]).runs(),
    ]
    .into_iter()
    .map(|case| {
        if pprof_feature_build() {
            case
        } else {
            case.deviates(Deviation::V21PprofNotAvailable)
        }
    })
    .collect()
}

/// Every case in the suite.
fn all_cases() -> Vec<CliCase> {
    let mut cases = client_cases();
    cases.extend(server_cases());
    cases.extend(v06_cases());
    cases.extend(v07_cases());
    cases.extend(v08_cases());
    cases.extend(v14_cases());
    cases.extend(v15_cases());
    cases.extend(v19_cases());
    cases.extend(v20_cases());
    cases.extend(v21_cases());
    cases
}

// ---------------------------------------------------------------------------------------
// The differential itself
// ---------------------------------------------------------------------------------------

/// Runs one group in its own directory tree, which survives until the test ends.
#[track_caller]
fn run_group(cases: &[CliCase]) {
    let root = tempfile::Builder::new()
        .prefix("kcptun-clidiff-")
        .tempdir()
        .expect("temp dir");
    run_all(cases, root.path());
}

#[test]
#[ignore = "needs both implementations: tools/fetch-reference.sh and cargo build --release -p kcptun-client -p kcptun-server"]
fn cli_diff_client_startup_matches_go() {
    run_group(&client_cases());
}

#[test]
#[ignore = "needs both implementations: tools/fetch-reference.sh and cargo build --release -p kcptun-client -p kcptun-server"]
fn cli_diff_server_startup_matches_go() {
    run_group(&server_cases());
}

#[test]
#[ignore = "needs both implementations: tools/fetch-reference.sh and cargo build --release -p kcptun-client -p kcptun-server"]
fn cli_diff_v06_usage_errors_exit_2() {
    run_group(&v06_cases());
}

#[test]
#[ignore = "needs both implementations: tools/fetch-reference.sh and cargo build --release -p kcptun-client -p kcptun-server"]
fn cli_diff_v07_more_than_256_fec_shards_are_rejected_at_startup() {
    run_group(&v07_cases());
}

#[test]
#[ignore = "needs both implementations: tools/fetch-reference.sh and cargo build --release -p kcptun-client -p kcptun-server"]
fn cli_diff_v08_the_log_header_carries_our_source_position() {
    run_group(&v08_cases());
}

#[test]
#[ignore = "needs both implementations: tools/fetch-reference.sh and cargo build --release -p kcptun-client -p kcptun-server"]
fn cli_diff_v14_snmplog_file_name_carries_the_zone_offset() {
    run_group(&v14_cases());
}

#[test]
#[ignore = "needs both implementations: tools/fetch-reference.sh and cargo build --release -p kcptun-client -p kcptun-server"]
fn cli_diff_v15_qppcount_beyond_uint16_is_rejected_at_startup() {
    run_group(&v15_cases());
}

#[test]
#[ignore = "needs both implementations: tools/fetch-reference.sh and cargo build --release -p kcptun-client -p kcptun-server"]
fn cli_diff_v19_conn_that_truncates_to_zero_is_rejected_at_startup() {
    run_group(&v19_cases());
}

#[test]
#[ignore = "needs both implementations: tools/fetch-reference.sh and cargo build --release -p kcptun-client -p kcptun-server"]
fn cli_diff_v20_go_prints_a_stack_trace_after_a_fatal_error() {
    run_group(&v20_cases());
}

/// Without the `pprof` feature this asserts the one extra line; with it (`KCPTUN_RS_PPROF=1` and
/// `KCPTUN_RS_BIN_DIR` on that build) it asserts V21's other claim, that the feature build is
/// byte-identical to Go.
#[test]
#[ignore = "needs both implementations: tools/fetch-reference.sh and cargo build --release -p kcptun-client -p kcptun-server"]
fn cli_diff_v21_pprof_without_the_feature_logs_one_extra_line() {
    run_group(&v21_cases());
}

// ---------------------------------------------------------------------------------------
// The case table itself (no processes, so these run in the gate)
// ---------------------------------------------------------------------------------------

#[test]
fn the_case_table_is_well_formed() {
    let cases = all_cases();
    assert!(
        cases.len() >= 30,
        "the plan asks for about 30 cases, this is {}",
        cases.len()
    );
    let names: BTreeSet<&str> = cases.iter().map(|c| c.name).collect();
    assert_eq!(names.len(), cases.len(), "case names must be unique");
    // Each case runs in `<root>/<short_name><tag>`, so those have to be unique too or one case
    // would wipe another's directory (and with it the evidence of a failure).
    let dirs: BTreeSet<String> = cases.iter().map(|c| short_name(c.name)).collect();
    assert_eq!(
        dirs.len(),
        cases.len(),
        "run directory names must be unique"
    );
    for case in &cases {
        assert!(
            case.name.starts_with("client_") || case.name.starts_with("server_"),
            "{} does not say which binary it runs",
            case.name
        );
        // A case that holds a port must ask for one, and a JSON case must pass it on.
        assert!(!case.hold_port0 || case.port_count() > 0, "{}", case.name);
        assert_eq!(
            case.json.is_some(),
            case.args.iter().any(|a| a.contains("{config}")),
            "{} must use {{config}} exactly when it has JSON",
            case.name
        );
    }
}

#[test]
fn every_allowed_deviation_has_a_case_and_no_other_difference_is_allowed() {
    let mut wanted = vec![
        Deviation::V06UsageExitStatus,
        Deviation::V07FecShardsExceed256,
        Deviation::V08FileAndLine,
        Deviation::V14SnmpLogZone,
        Deviation::V15QppCountTruncates,
        Deviation::V19ConnTruncatesToZero,
        Deviation::V20NoStackTrace,
    ];
    // V21 is the one entry whose case depends on the build under test: with the optional `pprof`
    // feature the difference is gone and the same command lines are expected to be identical.
    if !pprof_feature_build() {
        wanted.push(Deviation::V21PprofNotAvailable);
    }
    let found: BTreeSet<Deviation> = all_cases()
        .iter()
        .filter_map(|c| match c.expect {
            Expect::Deviates(d) => Some(d),
            Expect::Identical => None,
        })
        .collect();
    assert_eq!(
        found,
        wanted.into_iter().collect::<BTreeSet<_>>(),
        "the allow-list and the case table have drifted apart"
    );
}

/// `--pprof` and a shard count above 256 each produce a difference all by themselves (V21 and
/// V07), so no *other* case may reach them: one that switched either on in passing would turn a
/// pinned deviation into an untested one, and would be reported against whatever that case is
/// really about.
///
/// Both settings can arrive through the command line **or** through a `-c` config, which is what
/// [`case_pprof`] and [`case_fec`] read — the arguments *and* [`CliCase::json`], with Go's
/// defaults underneath. A guard that only scanned the joined argv would miss a JSON config that
/// said `{"pprof": true}` or `{"datashard": 255, "parityshard": 2}`.
#[test]
fn pprof_and_oversized_fec_appear_only_in_the_cases_that_pin_them() {
    let pprof_pinned: BTreeSet<&str> = v21_cases().iter().map(|c| c.name).collect();
    let fec_pinned: BTreeSet<&str> = v07_cases().iter().map(|c| c.name).collect();
    for case in &all_cases() {
        assert!(
            !case_pprof(case) || pprof_pinned.contains(case.name),
            "{}: `--pprof` is deviation V21; only its own cases may ask for it",
            case.name
        );
        let (data, parity) = case_fec(case);
        assert!(
            data + parity <= 256 || fec_pinned.contains(case.name),
            "{}: datashard {data} + parityshard {parity} is deviation V07; only its own cases \
             may ask for it",
            case.name
        );
    }
}

/// Whether `case` ends up with the profiling server on, from its arguments or its JSON config.
// Go: kcptun/client/main.go:247-250 — cli.BoolFlag{Name: "pprof"}, default false.
fn case_pprof(case: &CliCase) -> bool {
    let from_args = case.args.iter().any(|arg| {
        let flag = arg.trim_start_matches('-');
        match flag.split_once('=') {
            // Go's `flag` package: `-pprof=false` and `-pprof=0` leave it off.
            Some((name, value)) => name == "pprof" && value != "false" && value != "0",
            None => flag == "pprof",
        }
    });
    from_args
        || json_field(case, "pprof")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
}

/// The `datashard`/`parityshard` `case` ends up with: Go's defaults, then its arguments, then its
/// JSON config, which overrides the command line (`-c ... will override the command from shell`).
// Go: kcptun/client/main.go:140-150 — cli.IntFlag{Name: "datashard,ds", Value: 10} and
// {Name: "parityshard,ps", Value: 3}.
fn case_fec(case: &CliCase) -> (i64, i64) {
    let (mut data, mut parity) = (10, 3);
    let mut args = case.args.iter();
    while let Some(arg) = args.next() {
        let flag = arg.trim_start_matches('-');
        let (name, inline) = match flag.split_once('=') {
            Some((name, value)) => (name, Some(value.to_string())),
            None => (flag, None),
        };
        let slot = match name {
            "datashard" | "ds" => &mut data,
            "parityshard" | "ps" => &mut parity,
            _ => continue,
        };
        if let Some(value) = inline
            .or_else(|| args.next().cloned())
            .and_then(|v| v.parse().ok())
        {
            *slot = value;
        }
    }
    if let Some(v) = json_field(case, "datashard").and_then(|v| v.as_i64()) {
        data = v;
    }
    if let Some(v) = json_field(case, "parityshard").and_then(|v| v.as_i64()) {
        parity = v;
    }
    (data, parity)
}

/// The value `key` has in `case`'s JSON config, matched the way Go matches a struct tag: the exact
/// name first, then case-insensitively — which is why `client_json_mixed_case` works at all.
///
/// Every case's JSON has to parse, including the ones whose *values* are deliberately wrong.
// Go: encoding/json decode.go:object() — "prefer an exact match but fall back to a case-insensitive one"
fn json_field(case: &CliCase, key: &str) -> Option<serde_json::Value> {
    let json = case.json.as_ref()?;
    let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(json)
        .unwrap_or_else(|e| panic!("{}: the case's JSON must parse: {e}", case.name));
    map.get(key)
        .or_else(|| {
            map.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .map(|(_, v)| v)
        })
        .cloned()
}
