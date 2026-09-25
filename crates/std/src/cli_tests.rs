//! Tests for [`crate::cli`].
//!
//! `vectors_cli_*` replay `testdata/vectors/cli.json`, which `tools/govectors` produced by
//! running the pinned urfave/cli v1.22.17 over the same flag table: every case carries the
//! bytes Go wrote, the values its action saw and the exit code it would have used. The unit
//! tests below spell out the same rules against a hand-written table, and cover the helpers
//! (`strconv`, `text/tabwriter`, `filepath.Base`) directly.

use std::collections::{BTreeMap, HashMap};

use serde::Deserialize;

use super::*;

// ---------------------------------------------------------------------------------------
// Golden vectors
// ---------------------------------------------------------------------------------------

/// One flag of the vector file's app definition.
#[derive(Debug, Deserialize)]
struct VecFlag {
    name: String,
    kind: String,
    #[serde(default)]
    value: serde_json::Value,
    #[serde(default)]
    usage: String,
    #[serde(default)]
    env: String,
    #[serde(default)]
    hidden: bool,
}

/// The `app` field of the vector file's first case: the table every case is parsed against.
#[derive(Debug, Deserialize)]
struct VecApp {
    name: String,
    help_name: String,
    usage: String,
    version: String,
    flags: Vec<VecFlag>,
}

/// One recorded `cli.App.Run`.
#[derive(Debug, Deserialize)]
struct VecCase {
    name: String,
    #[serde(default)]
    env: BTreeMap<String, String>,
    args: Vec<String>,
    #[serde(default)]
    stdout: String,
    #[serde(default)]
    stderr: String,
    #[serde(default)]
    err: String,
    #[serde(default)]
    exit: Option<i32>,
    action: bool,
    #[serde(default)]
    values: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    set: Vec<String>,
    #[serde(default)]
    rest: Vec<String>,
}

impl VecApp {
    /// Builds the [`App`] the vectors were generated with.
    fn app(&self) -> App<'_> {
        let flags = self.flags.iter().map(|f| {
            let spec = match f.kind.as_str() {
                "string" => FlagSpec::str_flag(&f.name, f.value.as_str().unwrap_or(""), &f.usage),
                "int" => FlagSpec::int_flag(&f.name, f.value.as_i64().unwrap_or(0), &f.usage),
                "bool" => FlagSpec::bool_flag(&f.name, &f.usage),
                other => panic!("unknown flag kind {other}"),
            };
            let spec = if f.env.is_empty() {
                spec
            } else {
                spec.env(&f.env)
            };
            if f.hidden { spec.hidden() } else { spec }
        });
        App::new(
            &self.name,
            self.help_name.clone(),
            &self.usage,
            &self.version,
            flags,
        )
    }

    /// Every flag name of the table, in declaration order (aliases included).
    fn names(&self) -> Vec<(&str, &str)> {
        let mut out = Vec::new();
        for f in &self.flags {
            for n in f.name.split(',') {
                out.push((n.trim_matches(' '), f.kind.as_str()));
            }
        }
        out
    }
}

/// The app definition and every recorded run.
fn load_cases() -> (VecApp, Vec<VecCase>) {
    let file = kcptun_testkit::vectors!("cli");
    let cases: Vec<VecCase> = file.cases.iter().map(|c| c.to::<VecCase>()).collect();
    let app: VecApp = file.case("app").field("app");
    (app, cases)
}

#[test]
fn vectors_cli_run() {
    let (def, cases) = load_cases();
    let app = def.app();
    let names = def.names();

    for case in &cases {
        let env: HashMap<String, String> = case.env.clone().into_iter().collect();
        let run = app.run(&case.args, &env);

        assert_eq!(run.stdout, case.stdout, "case {}: stdout", case.name);
        assert_eq!(run.stderr, case.stderr, "case {}: stderr", case.name);
        if !case.err.is_empty() {
            assert!(
                run.stdout.contains(&case.err) || run.stderr.contains(&case.err),
                "case {}: Go's error text {:?} appears nowhere in the output",
                case.name,
                case.err
            );
        }

        match &run.outcome {
            RunOutcome::Action(ctx) => {
                assert!(
                    case.action,
                    "case {}: the action ran but Go's did not",
                    case.name
                );
                for &(name, kind) in &names {
                    let want = case
                        .values
                        .get(name)
                        .unwrap_or_else(|| panic!("case {}: no value for {name}", case.name));
                    match kind {
                        "string" => assert_eq!(
                            ctx.string(name),
                            want.as_str().expect("string value"),
                            "case {}: value of {name}",
                            case.name
                        ),
                        "int" => assert_eq!(
                            ctx.int(name),
                            want.as_i64().expect("int value"),
                            "case {}: value of {name}",
                            case.name
                        ),
                        "bool" => assert_eq!(
                            ctx.bool(name),
                            want.as_bool().expect("bool value"),
                            "case {}: value of {name}",
                            case.name
                        ),
                        other => panic!("unknown kind {other}"),
                    }
                }
                let set: Vec<&str> = names
                    .iter()
                    .map(|(n, _)| *n)
                    .filter(|n| ctx.is_set(n))
                    .collect();
                assert_eq!(set, case.set, "case {}: IsSet", case.name);
                assert_eq!(
                    ctx.args(),
                    case.rest,
                    "case {}: remaining arguments",
                    case.name
                );
            }
            RunOutcome::Exit(code) => {
                assert!(
                    !case.action,
                    "case {}: Go ran the action, we exited",
                    case.name
                );
                // Deviation V06: where Go returns an error from App.Run (and kcptun's main
                // ignores it, exiting 0) we exit with USAGE_ERROR_EXIT_CODE.
                let want = match case.exit {
                    Some(c) => c,
                    None if case.err.is_empty() => 0,
                    None => USAGE_ERROR_EXIT_CODE,
                };
                assert_eq!(*code, want, "case {}: exit code", case.name);
            }
        }
    }
    assert!(
        cases.len() > 50,
        "expected the full cli vector set, got {}",
        cases.len()
    );
}

/// The rendered help of the vector app, byte for byte (`-h` output of the pinned urfave/cli).
#[test]
fn vectors_cli_help_render() {
    let (def, _) = load_cases();
    assert_eq!(def.app().render_help(), help_vector_stdout());
}

/// The `-h` output the pinned urfave/cli produced for the vector app.
fn help_vector_stdout() -> String {
    kcptun_testkit::vectors!("cli")
        .case("app")
        .field::<String>("stdout")
}

// ---------------------------------------------------------------------------------------
// A small hand-written app, used by the unit tests
// ---------------------------------------------------------------------------------------

const TEST_FLAGS: &[FlagSpec<'static>] = &[
    FlagSpec::str_flag("localaddr,l", ":12948", "local listen address"),
    FlagSpec::str_flag("key", "it's a secrect", "pre-shared secret").env("KCPTUN_KEY"),
    FlagSpec::str_flag(
        "log",
        "",
        "specify a log file to output, default goes to stderr",
    ),
    FlagSpec::int_flag("mtu", 1350, "set maximum transmission unit for UDP packets"),
    FlagSpec::int_flag(
        "datashard,ds",
        10,
        "set reed-solomon erasure coding - datashard",
    ),
    FlagSpec::bool_flag("nocomp", "disable compression"),
    FlagSpec::int_flag("nodelay", 0, "").hidden(),
    FlagSpec::str_flag("c", "", "config from json file"),
];

fn test_app() -> App<'static> {
    App::new(
        "kcptun",
        "PROGRAM",
        "client(with SMUX)",
        "SELFBUILD",
        TEST_FLAGS.to_vec(),
    )
}

/// Runs the test app with `argv` (without the program name) and an empty environment.
fn run(args: &[&str]) -> Run {
    run_env(args, &[])
}

fn run_env(args: &[&str], env: &[(&str, &str)]) -> Run {
    let mut argv = vec!["PROGRAM".to_string()];
    argv.extend(args.iter().map(|a| (*a).to_string()));
    let env: HashMap<String, String> = env
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    test_app().run(&argv, &env)
}

/// Runs the test app and returns the context, failing if it did not reach the action.
#[track_caller]
fn ctx(args: &[&str]) -> Context {
    match run(args).outcome {
        RunOutcome::Action(c) => c,
        RunOutcome::Exit(code) => panic!("expected the action to run, exited {code}"),
    }
}

/// Runs the test app and returns the `Incorrect Usage.` line, failing if it succeeded.
#[track_caller]
fn usage_error(args: &[&str]) -> String {
    let r = run(args);
    match r.outcome {
        RunOutcome::Exit(code) => assert_eq!(code, USAGE_ERROR_EXIT_CODE),
        RunOutcome::Action(_) => panic!("expected a usage error, the action ran"),
    }
    let line = r.stdout.lines().next().unwrap_or_default().to_string();
    assert!(
        r.stdout.contains("\nNAME:\n"),
        "the full help must follow the error"
    );
    line
}

// ---------------------------------------------------------------------------------------
// Flag syntax
// ---------------------------------------------------------------------------------------

#[test]
fn single_and_double_dash_and_equals_are_equivalent() {
    for args in [
        ["-mtu", "1300"].as_slice(),
        ["--mtu", "1300"].as_slice(),
        ["-mtu=1300"].as_slice(),
        ["--mtu=1300"].as_slice(),
    ] {
        assert_eq!(ctx(args).int("mtu"), 1300, "{args:?}");
    }
}

#[test]
fn value_may_look_like_a_flag() {
    assert_eq!(ctx(&["-key", "-mtu"]).string("key"), "-mtu");
}

#[test]
fn string_flag_accepts_an_empty_value() {
    let c = ctx(&["-key="]);
    assert_eq!(c.string("key"), "");
    assert!(c.is_set("key"));
}

#[test]
fn bad_flag_syntax() {
    assert_eq!(
        usage_error(&["---mtu"]),
        "Incorrect Usage. bad flag syntax: ---mtu"
    );
    assert_eq!(
        usage_error(&["-=1"]),
        "Incorrect Usage. bad flag syntax: -=1"
    );
}

#[test]
fn flag_names_are_case_sensitive() {
    assert_eq!(
        usage_error(&["-MTU", "1"]),
        "Incorrect Usage. flag provided but not defined: -MTU"
    );
}

#[test]
fn unknown_flag_stops_at_the_first_one() {
    // The second, invalid, flag is never reached.
    assert_eq!(
        usage_error(&["-bad", "-mtu", "abc"]),
        "Incorrect Usage. flag provided but not defined: -bad"
    );
}

#[test]
fn missing_value() {
    assert_eq!(
        usage_error(&["-mtu"]),
        "Incorrect Usage. flag needs an argument: -mtu"
    );
    assert_eq!(
        usage_error(&["--key"]),
        "Incorrect Usage. flag needs an argument: -key"
    );
    assert_eq!(
        usage_error(&["-datashard=4", "-mtu"]),
        "Incorrect Usage. flag needs an argument: -mtu"
    );
}

// ---------------------------------------------------------------------------------------
// Integers: strconv.ParseInt(s, 0, 64)
// ---------------------------------------------------------------------------------------

#[test]
fn int_values_use_base_zero() {
    for (arg, want) in [
        ("1350", 1350),
        ("01350", 744), // leading zero: octal
        ("0o17", 15),   // explicit octal prefix
        ("0x100", 256), // hex
        ("0XfF", 255),  // hex, either case
        ("0b1010", 10), // binary
        ("0", 0),
        ("1_350", 1350), // underscores are allowed in base 0
        ("0x_10", 16),   // ... including right after the base prefix
        ("+42", 42),
        ("-16", -16),
        ("-0x10", -16),
        ("9223372036854775807", i64::MAX),
        ("-9223372036854775808", i64::MIN),
    ] {
        assert_eq!(ctx(&["-mtu", arg]).int("mtu"), want, "-mtu {arg}");
    }
}

#[test]
fn int_parse_errors() {
    for arg in [
        "abc", "", "0x", "09", "13.5", " 1350", "_1350", "1350_", "1__350", "1350abc",
    ] {
        assert_eq!(
            usage_error(&[&format!("-mtu={arg}")]),
            format!(
                "Incorrect Usage. invalid value {} for flag -mtu: parse error",
                go_quote(arg)
            ),
            "-mtu={arg}"
        );
    }
}

#[test]
fn int_range_errors() {
    for arg in [
        "9223372036854775808",
        "99999999999999999999",
        "-9223372036854775809",
    ] {
        assert_eq!(
            usage_error(&["-mtu", arg]),
            format!(
                "Incorrect Usage. invalid value {} for flag -mtu: value out of range",
                go_quote(arg)
            ),
            "-mtu {arg}"
        );
    }
}

#[test]
fn parse_int_matches_go() {
    assert_eq!(parse_int_base0("0xFFFFFFFFFFFFFFFF"), Err(NumError::Range));
    assert_eq!(parse_int_base0("-"), Err(NumError::Syntax));
    assert_eq!(parse_int_base0("+"), Err(NumError::Syntax));
    assert_eq!(parse_int_base0("00"), Ok(0));
    assert_eq!(parse_int_base0("0_0"), Ok(0));
    assert_eq!(parse_int_base0("0b_1"), Ok(1));
    assert_eq!(parse_int_base0("_0b1"), Err(NumError::Syntax));
    assert_eq!(parse_int_base0("0x1p2"), Err(NumError::Syntax));
    assert_eq!(parse_int_base0("١٢٣"), Err(NumError::Syntax)); // non-ASCII digits
}

// ---------------------------------------------------------------------------------------
// Booleans: strconv.ParseBool
// ---------------------------------------------------------------------------------------

#[test]
fn bool_without_a_value_is_true() {
    assert!(ctx(&["-nocomp"]).bool("nocomp"));
    assert!(!ctx(&[]).bool("nocomp"));
}

#[test]
fn bool_parse_bool_forms() {
    for v in ["1", "t", "T", "true", "TRUE", "True"] {
        assert!(
            ctx(&[&format!("-nocomp={v}")]).bool("nocomp"),
            "-nocomp={v}"
        );
    }
    for v in ["0", "f", "F", "false", "FALSE", "False"] {
        assert!(
            !ctx(&[&format!("-nocomp={v}")]).bool("nocomp"),
            "-nocomp={v}"
        );
    }
}

#[test]
fn bool_invalid_value() {
    for v in ["yes", "", "TrUe", "2"] {
        assert_eq!(
            usage_error(&[&format!("-nocomp={v}")]),
            format!(
                "Incorrect Usage. invalid boolean value {} for -nocomp: parse error",
                go_quote(v)
            ),
            "-nocomp={v}"
        );
    }
}

#[test]
fn bool_with_a_separate_word_stops_parsing() {
    // The kcptun trap: "-nocomp false -mtu 1234" enables compression's opposite and leaves
    // everything after it as positional arguments.
    let c = ctx(&["-nocomp", "false", "-mtu", "1234"]);
    assert!(c.bool("nocomp"));
    assert_eq!(c.int("mtu"), 1350);
    assert_eq!(c.args(), ["false", "-mtu", "1234"]);
}

// ---------------------------------------------------------------------------------------
// Where parsing stops
// ---------------------------------------------------------------------------------------

#[test]
fn parsing_stops_at_the_first_non_flag() {
    let c = ctx(&["extra", "-mtu", "999"]);
    assert_eq!(c.int("mtu"), 1350);
    assert_eq!(c.args(), ["extra", "-mtu", "999"]);

    let c = ctx(&["-mtu", "1400", "extra", "-datashard", "7"]);
    assert_eq!(c.int("mtu"), 1400);
    assert_eq!(c.int("datashard"), 10);
    assert_eq!(c.args(), ["extra", "-datashard", "7"]);
}

#[test]
fn a_lone_dash_and_an_empty_argument_are_positional() {
    assert_eq!(ctx(&["-", "-mtu", "999"]).args(), ["-", "-mtu", "999"]);
    assert_eq!(ctx(&["", "-mtu", "999"]).args(), ["", "-mtu", "999"]);
}

#[test]
fn double_dash_terminates_the_flags() {
    let c = ctx(&["-mtu", "1400", "--", "-mtu", "999"]);
    assert_eq!(c.int("mtu"), 1400);
    // "--" itself is consumed.
    assert_eq!(c.args(), ["-mtu", "999"]);
    assert_eq!(ctx(&["--", "-mtu", "999"]).int("mtu"), 1350);
}

// ---------------------------------------------------------------------------------------
// Aliases
// ---------------------------------------------------------------------------------------

#[test]
fn aliases_share_a_value() {
    let c = ctx(&["-l", "host:1", "-ds", "4"]);
    assert_eq!(c.string("localaddr"), "host:1");
    assert_eq!(c.string("l"), "host:1");
    assert_eq!(c.int("datashard"), 4);
    assert_eq!(c.int("ds"), 4);
    assert!(c.is_set("localaddr") && c.is_set("l") && c.is_set("ds") && c.is_set("datashard"));
}

#[test]
fn repeating_one_alias_keeps_the_last_value() {
    assert_eq!(ctx(&["-l", "a", "-l", "b"]).string("localaddr"), "b");
}

#[test]
fn two_forms_of_the_same_flag_are_rejected() {
    let r = run(&["-l", "x", "-localaddr", "y"]);
    assert!(matches!(r.outcome, RunOutcome::Exit(USAGE_ERROR_EXIT_CODE)));
    // Note: no "Incorrect Usage." prefix and no blank line, unlike a parse error.
    assert!(
        r.stdout
            .starts_with("Cannot use two forms of the same flag: l localaddr\nNAME:\n"),
        "unexpected output: {:?}",
        &r.stdout[..80.min(r.stdout.len())]
    );
}

#[test]
fn the_normalize_error_wins_over_a_parse_error() {
    let r = run(&["-l", "x", "-localaddr", "y", "-nosuchflag"]);
    assert!(
        r.stdout
            .starts_with("Cannot use two forms of the same flag: ")
    );
}

// ---------------------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------------------

#[test]
fn env_var_provides_the_default_and_the_flag_overrides_it() {
    let c = match run_env(&[], &[("KCPTUN_KEY", "from-env")]).outcome {
        RunOutcome::Action(c) => c,
        RunOutcome::Exit(code) => panic!("exited {code}"),
    };
    assert_eq!(c.string("key"), "from-env");
    // Go reports an env-provided flag as "set".
    assert!(c.is_set("key"));

    let c = match run_env(&["-key", "from-flag"], &[("KCPTUN_KEY", "from-env")]).outcome {
        RunOutcome::Action(c) => c,
        RunOutcome::Exit(code) => panic!("exited {code}"),
    };
    assert_eq!(c.string("key"), "from-flag");
}

#[test]
fn an_empty_env_var_still_counts_as_set() {
    let c = match run_env(&[], &[("KCPTUN_KEY", "")]).outcome {
        RunOutcome::Action(c) => c,
        RunOutcome::Exit(code) => panic!("exited {code}"),
    };
    assert_eq!(c.string("key"), "");
    assert!(c.is_set("key"));
}

#[test]
fn without_the_env_var_the_declared_default_applies() {
    let c = ctx(&[]);
    assert_eq!(c.string("key"), "it's a secrect");
    assert!(!c.is_set("key"));
}

// ---------------------------------------------------------------------------------------
// Hidden flags
// ---------------------------------------------------------------------------------------

#[test]
fn hidden_flags_parse_but_are_not_listed() {
    assert_eq!(ctx(&["-nodelay", "1"]).int("nodelay"), 1);
    assert!(!test_app().render_help().contains("nodelay"));
}

// ---------------------------------------------------------------------------------------
// Help and version
// ---------------------------------------------------------------------------------------

#[test]
fn help_flags_and_command() {
    let help = test_app().render_help();
    for args in [
        ["-h"].as_slice(),
        ["--help"].as_slice(),
        ["help"].as_slice(),
        ["h"].as_slice(),
        ["-h", "extra"].as_slice(),
        ["-mtu", "1400", "-h"].as_slice(),
    ] {
        let r = run(args);
        assert!(matches!(r.outcome, RunOutcome::Exit(0)), "{args:?}");
        assert_eq!(r.stdout, help, "{args:?}");
    }
    // An explicit false is not a help request.
    assert!(matches!(
        run(&["--help=false"]).outcome,
        RunOutcome::Action(_)
    ));
}

#[test]
fn help_command_with_a_topic() {
    let r = run(&["help", "help"]);
    assert!(matches!(r.outcome, RunOutcome::Exit(0)));
    assert_eq!(
        r.stdout,
        "NAME:\n    - Shows a list of commands or help for one command\n\nUSAGE:\n    [command]\n"
    );

    let r = run(&["help", "foo"]);
    assert!(matches!(
        r.outcome,
        RunOutcome::Exit(NO_HELP_TOPIC_EXIT_CODE)
    ));
    assert_eq!(r.stderr, "No help topic for 'foo'\n");
    assert_eq!(r.stdout, "");
}

#[test]
fn version_flags() {
    for args in [["-v"].as_slice(), ["--version"].as_slice()] {
        let r = run(args);
        assert!(matches!(r.outcome, RunOutcome::Exit(0)));
        assert_eq!(r.stdout, "kcptun version SELFBUILD\n");
    }
    // Help is checked before the version.
    assert_eq!(run(&["-v", "-h"]).stdout, test_app().render_help());
}

#[test]
fn help_layout() {
    assert_eq!(
        test_app().render_help(),
        concat!(
            "NAME:\n",
            "   kcptun - client(with SMUX)\n",
            "\n",
            "USAGE:\n",
            "   PROGRAM [global options] command [command options] [arguments...]\n",
            "\n",
            "VERSION:\n",
            "   SELFBUILD\n",
            "\n",
            "COMMANDS:\n",
            "   help, h  Shows a list of commands or help for one command\n",
            "\n",
            "GLOBAL OPTIONS:\n",
            "   --localaddr value, -l value    local listen address (default: \":12948\")\n",
            "   --key value                    pre-shared secret (default: \"it's a secrect\") \
             [$KCPTUN_KEY]\n",
            "   --log value                    specify a log file to output, default goes to \
             stderr\n",
            "   --mtu value                    set maximum transmission unit for UDP packets \
             (default: 1350)\n",
            "   --datashard value, --ds value  set reed-solomon erasure coding - datashard \
             (default: 10)\n",
            "   --nocomp                       disable compression\n",
            "   -c value                       config from json file\n",
            "   --help, -h                     show help\n",
            "   --version, -v                  print the version\n",
        )
    );
}

// ---------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------

#[test]
fn stringify_flag_shapes() {
    let cases = [
        (
            FlagSpec::str_flag("localaddr,l", ":12948", "local listen address"),
            "--localaddr value, -l value\tlocal listen address (default: \":12948\")",
        ),
        (
            FlagSpec::str_flag("remoteaddr, r", "vps:29900", "kcp server address"),
            "--remoteaddr value, -r value\tkcp server address (default: \"vps:29900\")",
        ),
        (
            FlagSpec::str_flag("log", "", "specify a log file"),
            "--log value\tspecify a log file",
        ),
        (
            FlagSpec::int_flag("dscp", 0, "set DSCP(6bit)"),
            "--dscp value\tset DSCP(6bit) (default: 0)",
        ),
        (
            FlagSpec::bool_flag("nocomp", "disable compression"),
            "--nocomp\tdisable compression",
        ),
        (
            FlagSpec::str_flag("c", "", "config from json file"),
            "-c value\tconfig from json file",
        ),
        (
            FlagSpec::str_flag("key", "k", "secret").env("KCPTUN_KEY"),
            "--key value\tsecret (default: \"k\") [$KCPTUN_KEY]",
        ),
        (
            FlagSpec::str_flag("key", "k", "secret").env("A,B"),
            "--key value\tsecret (default: \"k\") [$A, $B]",
        ),
        // A back-quoted word in the usage becomes the placeholder.
        (
            FlagSpec::str_flag("addr", "", "listen on `host:port`"),
            "--addr host:port\tlisten on host:port",
        ),
        (FlagSpec::bool_flag("QPP", ""), "--QPP\t"),
    ];
    for (flag, want) in cases {
        assert_eq!(stringify_flag(&flag), want, "{}", flag.name);
    }
}

#[test]
fn each_name_trims_spaces() {
    assert_eq!(
        each_name("remoteaddr, r").collect::<Vec<_>>(),
        ["remoteaddr", "r"]
    );
    assert_eq!(
        each_name("localaddr,l").collect::<Vec<_>>(),
        ["localaddr", "l"]
    );
    assert_eq!(each_name("key").collect::<Vec<_>>(), ["key"]);
}

#[test]
fn go_quote_matches_strconv() {
    assert_eq!(go_quote("abc"), "\"abc\"");
    assert_eq!(go_quote("it's a secrect"), "\"it's a secrect\"");
    assert_eq!(go_quote("a\tb"), "\"a\\tb\"");
    assert_eq!(go_quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
    assert_eq!(go_quote("\x00\x1f\x7f"), "\"\\x00\\x1f\\x7f\"");
    assert_eq!(go_quote("é\u{a0}x"), "\"é\\u00a0x\"");
    assert_eq!(go_quote("\u{1f600}"), "\"\u{1f600}\"");
}

#[test]
fn filepath_base_matches_go() {
    for (path, want) in [
        ("", "."),
        ("/", "/"),
        ("///", "/"),
        ("client_darwin_arm64", "client_darwin_arm64"),
        ("/usr/local/bin/kcptun-client", "kcptun-client"),
        ("./kcptun-client", "kcptun-client"),
        ("dir/", "dir"),
    ] {
        assert_eq!(filepath_base(path), want, "{path}");
    }
}

#[test]
fn tabwriter_aligns_column_blocks() {
    // One block: the longest cell (5) plus the padding (2) sets the width.
    assert_eq!(
        tabwriter::format("ab\t1\ncdefg\t2\n"),
        "ab     1\ncdefg  2\n"
    );
    // A line without a tab breaks the block, so the two groups align independently.
    assert_eq!(
        tabwriter::format("ab\t1\nhead\ncdefg\t2\n"),
        "ab  1\nhead\ncdefg  2\n"
    );
    // The last cell of a line is never padded.
    assert_eq!(tabwriter::format("a\tb\n"), "a  b\n");
    // Cell widths count characters, not bytes.
    assert_eq!(tabwriter::format("éé\t1\nab\t2\n"), "éé  1\nab  2\n");
    // Three columns.
    assert_eq!(
        tabwriter::format("a\tbb\tc\nxxx\td\te\n"),
        "a    bb  c\nxxx  d   e\n"
    );
}

// ---------------------------------------------------------------------------------------
// The real Go binaries' help text
// ---------------------------------------------------------------------------------------

/// `reference/bin/client_<os>_<arch> -h`, with the program name normalised; captured by
/// `tools/gen-cli-golden.sh`.
const GO_CLIENT_HELP: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/golden/cli/client_help.txt"
));
/// `reference/bin/server_<os>_<arch> -h`, likewise.
const GO_SERVER_HELP: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/golden/cli/server_help.txt"
));

/// Splits one aligned help line back into its two tab-separated cells, at the padding
/// `text/tabwriter` inserted; `None` for a line that was never part of a column block.
fn untabbed(line: &str) -> Option<String> {
    let body = line.strip_prefix("   ")?;
    if body.starts_with(' ') {
        return None;
    }
    // The first cell never contains two spaces in a row, so the first run of them is the
    // padding Go added.
    let i = body.find("  ")?;
    Some(format!("   {}\t{}", &body[..i], body[i..].trim_start()))
}

/// The column widths of the real client and server tables (40+ flags, the longest name being
/// `--parityshard value, --ps value`) are reproduced exactly by the tabwriter port: taking Go's
/// own output apart at the padding and running the cells back through it returns it unchanged.
///
/// Step 08.2 adds the other half of this comparison: `App::render_help()` of the real client
/// and server flag tables against these same two files.
#[test]
fn golden_go_help_layout_is_reproduced() {
    for (name, text) in [("client", GO_CLIENT_HELP), ("server", GO_SERVER_HELP)] {
        assert!(
            text.ends_with('\n'),
            "{name}: help text must end with a newline"
        );
        let mut source = String::new();
        for line in text.split('\n') {
            match untabbed(line) {
                Some(cells) => source.push_str(&cells),
                None => source.push_str(line),
            }
            source.push('\n');
        }
        source.pop(); // split('\n') already accounted for the trailing newline
        assert_eq!(tabwriter::format(&source), text, "{name}");
    }
}

/// The sections urfave's `AppHelpTemplate` produces, in order, are the ones we render.
#[test]
fn golden_go_help_sections() {
    for (name, text) in [("client", GO_CLIENT_HELP), ("server", GO_SERVER_HELP)] {
        let headings: Vec<&str> = text
            .lines()
            .filter(|l| l.ends_with(':') && !l.starts_with(' '))
            .collect();
        assert_eq!(
            headings,
            [
                "NAME:",
                "USAGE:",
                "VERSION:",
                "COMMANDS:",
                "GLOBAL OPTIONS:"
            ],
            "{name}"
        );
        assert!(text.contains("   help, h  Shows a list of commands or help for one command\n"));
        assert!(
            text.contains("\n   --help, -h  "),
            "{name}: help flag is listed"
        );
        assert!(
            text.contains("\n   --version, -v  "),
            "{name}: version flag is listed"
        );
        // Hidden flags never appear.
        for hidden in [
            "--acknodelay",
            "--nodelay",
            "--interval",
            "--resend",
            "--nc ",
        ] {
            assert!(!text.contains(hidden), "{name}: {hidden} must be hidden");
        }
    }
    // One-letter names get a single dash, and the env hint is rendered.
    assert!(GO_CLIENT_HELP.contains("\n   -c value  "));
    assert!(GO_CLIENT_HELP.contains(" [$KCPTUN_KEY]\n"));

    // ... and the port builds those very lines out of the same two cells. The full table lands
    // in 08.2; these are the three shapes: an env-backed default, an alias pair, and a
    // one-letter name with no default.
    for (spec, line) in [
        (
            FlagSpec::str_flag(
                "key",
                "it's a secrect",
                "pre-shared secret between client and server",
            )
            .env("KCPTUN_KEY"),
            "   --key value                      pre-shared secret between client and server \
             (default: \"it's a secrect\") [$KCPTUN_KEY]",
        ),
        (
            FlagSpec::int_flag(
                "parityshard, ps",
                3,
                "set reed-solomon erasure coding - parityshard",
            ),
            "   --parityshard value, --ps value  set reed-solomon erasure coding - parityshard \
             (default: 3)",
        ),
        (
            FlagSpec::str_flag(
                "c",
                "",
                "config from json file, which will override the command from shell",
            ),
            "   -c value                         config from json file, which will override the \
             command from shell",
        ),
    ] {
        assert!(
            GO_CLIENT_HELP.contains(&format!("\n{line}\n")),
            "golden file changed: {line}"
        );
        let rendered = stringify_flag(&spec);
        let (names, usage) = rendered.split_once('\t').expect("names\\tusage cells");
        assert!(line.starts_with(&format!("   {names} ")), "names: {names}");
        assert!(line.ends_with(usage), "usage: {usage}");
    }

    // The COMMANDS section the port renders is the one Go's binaries print.
    assert!(
        test_app()
            .render_help()
            .contains("COMMANDS:\n   help, h  Shows a list of commands or help for one command\n")
    );
}
