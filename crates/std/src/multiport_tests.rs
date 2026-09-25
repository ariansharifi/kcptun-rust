//! Tests for [`crate::multiport`] and [`crate::goaddr`].
//!
//! `testdata/vectors/multiport.json` (area `multiport`) holds both parsers: `tools/govectors`
//! ran kcptun's own `std.ParseMultiPort` — a verbatim copy of `std/multiport.go`, regexp
//! included — and Go's `net.SplitHostPort` over the address tables in
//! `tools/govectors/multiport.go` and recorded host, ports and error text for each. The two
//! `vectors_*` tests below replay them; the unit tests spell out the quirks a reader would
//! otherwise have to dig out of the vector file.

use serde::Deserialize;

use super::*;
use crate::goaddr;

/// One recorded call, of either function (`func` says which).
#[derive(Debug, Deserialize)]
struct VecCase {
    name: String,
    func: String,
    addr: String,
    ok: bool,
    #[serde(default)]
    host: String,
    /// `SplitHostPort` only.
    #[serde(default)]
    port: String,
    /// `ParseMultiPort` only.
    #[serde(default)]
    minport: u64,
    #[serde(default)]
    maxport: u64,
    #[serde(default)]
    err: String,
}

fn load_cases() -> Vec<VecCase> {
    let file = kcptun_testkit::vectors!("multiport");
    assert!(!file.is_empty(), "the multiport area has no cases");
    file.cases.iter().map(|c| c.to::<VecCase>()).collect()
}

#[test]
fn vectors_multiport_parse() {
    let mut seen = 0;
    for case in load_cases() {
        if case.func != "ParseMultiPort" {
            continue;
        }
        seen += 1;
        match parse(&case.addr) {
            Ok(got) => {
                assert!(case.ok, "case {}: Go failed with {:?}", case.name, case.err);
                assert_eq!(
                    (got.host.as_str(), got.min_port, got.max_port),
                    (case.host.as_str(), case.minport, case.maxport),
                    "case {}",
                    case.name
                );
            }
            Err(err) => {
                assert!(!case.ok, "case {}: Go succeeded", case.name);
                assert_eq!(err.to_string(), case.err, "case {}: error text", case.name);
            }
        }
    }
    assert!(seen > 0, "no ParseMultiPort cases");
}

#[test]
fn vectors_multiport_split_host_port() {
    let mut seen = 0;
    for case in load_cases() {
        if case.func != "SplitHostPort" {
            continue;
        }
        seen += 1;
        match goaddr::split_host_port(&case.addr) {
            Ok((host, port)) => {
                assert!(case.ok, "case {}: Go failed with {:?}", case.name, case.err);
                assert_eq!(
                    (host, port),
                    (case.host.as_str(), case.port.as_str()),
                    "case {}",
                    case.name
                );
            }
            Err(err) => {
                assert!(!case.ok, "case {}: Go succeeded", case.name);
                assert_eq!(err.to_string(), case.err, "case {}: error text", case.name);
            }
        }
    }
    assert!(seen > 0, "no SplitHostPort cases");
}

#[test]
fn parses_the_shapes_the_flag_tables_default_to() {
    // The server's default -listen and the client's default -remoteaddr.
    assert_eq!(
        parse(":29900"),
        Ok(MultiPort {
            host: String::new(),
            min_port: 29900,
            max_port: 29900,
        })
    );
    assert_eq!(
        parse("vps:29900"),
        Ok(MultiPort {
            host: "vps".to_string(),
            min_port: 29900,
            max_port: 29900,
        })
    );
    assert_eq!(
        parse("1.2.3.4:3000-4000"),
        Ok(MultiPort {
            host: "1.2.3.4".to_string(),
            min_port: 3000,
            max_port: 4000,
        })
    );
}

#[test]
fn greedy_host_takes_everything_before_the_last_colon() {
    // (.*) is greedy, so an IPv6 address without brackets still parses, with the last group of
    // digits as the port.
    assert_eq!(
        parse("2001:db8::1:443").map(|m| m.host),
        Ok("2001:db8::1".to_string())
    );
    assert_eq!(parse("host:80:90").map(|m| m.min_port), Ok(90));
    // Unanchored on both sides: junk before the host is part of it, junk after the ports is
    // ignored.
    assert_eq!(
        parse("junk a:1-2").map(|m| m.host),
        Ok("junk a".to_string())
    );
    assert_eq!(
        parse("a:1-2junk").map(|m| (m.min_port, m.max_port)),
        Ok((1, 2))
    );
}

#[test]
fn at_most_five_digits_per_port() {
    // "123456" is 12345 followed by 6, which then fails the range check - Go's behaviour, kept.
    assert_eq!(
        parse("host:123456").unwrap_err().to_string(),
        "invalid port range specified: minport:12345 -> maxport 6"
    );
    // The dash is outside the third group, so a trailing dash leaves a single port.
    assert_eq!(parse("a:1-").map(|m| (m.min_port, m.max_port)), Ok((1, 1)));
    // Atoi is base 10, never octal.
    assert_eq!(parse("a:012").map(|m| m.min_port), Ok(12));
}

#[test]
fn range_check_rejects_zero_reversed_and_too_large() {
    for (addr, text) in [
        (
            "a:0",
            "invalid port range specified: minport:0 -> maxport 0",
        ),
        (
            "a:5-3",
            "invalid port range specified: minport:5 -> maxport 3",
        ),
        (
            "x:65536",
            "invalid port range specified: minport:65536 -> maxport 65536",
        ),
        (
            "a:1-0",
            "invalid port range specified: minport:1 -> maxport 0",
        ),
    ] {
        assert_eq!(parse(addr).unwrap_err().to_string(), text, "{addr}");
    }
}

#[test]
fn addresses_without_a_port_are_malformed() {
    for addr in [
        "nocolon",
        "",
        ":",
        "a:",
        "/tmp/kcptun.sock",
        "unix:/tmp/x.sock",
    ] {
        assert_eq!(
            parse(addr).unwrap_err().to_string(),
            format!("malformed address:{addr}"),
            "{addr}"
        );
    }
}

#[test]
fn dot_does_not_match_a_newline() {
    // Like Go's regexp, `.` stops at '\n', so the match starts after it.
    assert_eq!(parse("a\nb:80").map(|m| m.host), Ok("b".to_string()));
}

#[test]
fn odd_input_never_panics() {
    // Both parsers index by byte, like Go, so multi-byte characters around the ASCII bytes they
    // look for must not split a character. -l, -t, -listen and -remoteaddr come from the command
    // line or the JSON config, so any string is possible.
    let wide = ["é", "€", "🦀"];
    for w in wide {
        for b in 0u8..=127 {
            let c = b as char;
            for addr in [
                format!("{w}{c}"),
                format!("{c}{w}"),
                format!("{w}:{c}8{w}"),
                format!("[{w}]:{c}"),
                format!("{w}:8{c}0-{w}9"),
                format!(":{w}{c}"),
            ] {
                let _ = parse(&addr);
                let _ = goaddr::split_host_port(&addr);
            }
        }
    }
    // A few shapes that used to break naive ports.
    for addr in ["[", "]", "[]", "::", ":::", "[:]", "\u{0}:80", "a:\u{0}"] {
        let _ = parse(addr);
        let _ = goaddr::split_host_port(addr);
    }
}
