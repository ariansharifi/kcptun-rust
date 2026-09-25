//! Tests for [`crate::gotime`].
//!
//! `vectors_timefmt_format` replays `testdata/vectors/timefmt.json`, which `tools/govectors`
//! produced by calling Go 1.27.1's `time.Time.Format` on six instants in four fixed zones over
//! every reference-layout token, the layout constants of the `time` package and a set of
//! `-snmplog`-shaped file names. The unit tests below name the behaviour that the vectors
//! encode in bulk and cover what a fixed instant cannot reach.

use serde::Deserialize;

use super::*;

/// One recorded `time.Time.Format` call.
#[derive(Debug, Deserialize)]
struct VecCase {
    name: String,
    layout: String,
    unix: i64,
    nanos: u32,
    zone: String,
    offset: i32,
    #[serde(default)]
    out: String,
}

#[test]
fn vectors_timefmt_format() {
    let file = kcptun_testkit::vectors!("timefmt");
    assert!(!file.is_empty(), "the timefmt area has no cases");
    for case in file.cases.iter().map(|c| c.to::<VecCase>()) {
        let t = Time::new(case.unix, case.nanos, case.offset, &case.zone);
        assert_eq!(
            format(&case.layout, &t),
            case.out,
            "case {}: layout {:?}",
            case.name,
            case.layout
        );
    }
}

/// 2026-09-22T15:04:05.123456789Z, the instant most vectors use, in UTC.
fn t0() -> Time {
    Time::new(1_790_089_445, 123_456_789, 0, "UTC")
}

#[test]
fn snmplog_file_names() {
    // What -snmplog is actually used for.
    let t = Time::new(1_790_089_445, 0, -7 * 3600, "MST");
    assert_eq!(
        format("kcptun-snmp-20060102.log", &t),
        "kcptun-snmp-20260922.log"
    );
    assert_eq!(
        format("/var/log/kcptun/2006/01/02/snmp.log", &t),
        "/var/log/kcptun/2026/09/22/snmp.log"
    );
    // A name with no token at all is copied through.
    assert_eq!(format("snmp.log", &t), "snmp.log");
    // ... but "pm" in a file name is a token, so this one rotates between two names a day.
    assert_eq!(format("snmp-pm.log", &t), "snmp-am.log");
}

#[test]
fn scanner_quirks() {
    let t = t0();
    // "Mon"/"Jan" followed by a lower-case letter are literals; "January" is not.
    assert_eq!(format("Month", &t), "Month");
    assert_eq!(format("Janx", &t), "Janx");
    assert_eq!(format("Januaryx", &t), "Septemberx");
    // "_2006" is a literal underscore plus the year, not the space-padded day.
    assert_eq!(format("_2006", &t), "_2026");
    // A digit right after the zeros means the run is not a fraction: ".00" is literal and "01"
    // is the zero-padded month.
    assert_eq!(format(".0001", &t), ".0009");
    // Only the leftmost "-0700" matches.
    assert_eq!(format("--0700", &t), "-+0000");
    // An unknown layout is copied verbatim, and an empty one stays empty.
    assert_eq!(format("kcptun", &t), "kcptun");
    assert_eq!(format("", &t), "");
}

#[test]
fn twelve_hour_clock_and_am_pm() {
    let midnight = Time::new(1_767_225_600, 0, 0, "UTC"); // 2026-01-01T00:00:00Z
    assert_eq!(format("3:04:05PM", &midnight), "12:00:00AM");
    assert_eq!(format("03pm", &midnight), "12am");
    let noon = Time::new(1_767_268_800, 0, 0, "UTC"); // 2026-01-01T12:00:00Z
    assert_eq!(format("3:04:05PM", &noon), "12:00:00PM");
    assert_eq!(format("15", &noon), "12");
}

#[test]
fn fractional_seconds() {
    let t = t0();
    // ".0" keeps the zeros, ".9" drops them.
    assert_eq!(format(".000000000", &t), ".123456789");
    assert_eq!(format(".999999999", &t), ".123456789");
    // The comma separator is a token of its own.
    assert_eq!(format(",000", &t), ",123");
    // A zero nanosecond leaves nothing at all behind for ".9", including the separator.
    let whole = Time::new(1_790_089_445, 0, 0, "UTC");
    assert_eq!(format("05.999", &whole), "05");
    assert_eq!(format("05.000", &whole), "05.000");
    // Trailing zeros inside the requested width are trimmed, the separator survives.
    let tenth = Time::new(1_790_089_445, 120_000_000, 0, "UTC");
    assert_eq!(format("05.999", &tenth), "05.12");
    assert_eq!(format("05.000", &tenth), "05.120");
    // Fewer than nine digits truncate rather than round.
    assert_eq!(format(".00", &t), ".12");
    // A nanosecond that only shows up beyond the requested width trims away entirely.
    let one_nano = Time::new(1_790_089_445, 1, 0, "UTC");
    assert_eq!(format("05.9", &one_nano), "05");
    assert_eq!(format("05.999999999", &one_nano), "05.000000001");
}

#[test]
fn zone_tokens() {
    let utc = t0();
    // The Z-forms print "Z" at offset zero, the numeric forms never do.
    assert_eq!(format("Z0700", &utc), "Z");
    assert_eq!(format("Z07:00", &utc), "Z");
    assert_eq!(format("-0700", &utc), "+0000");
    assert_eq!(format("MST", &utc), "UTC");

    let mst = Time::new(1_790_089_445, 0, -7 * 3600, "MST");
    assert_eq!(format("Z0700", &mst), "-0700");
    assert_eq!(format("-07:00", &mst), "-07:00");
    assert_eq!(format("-07", &mst), "-07");
    assert_eq!(format("MST", &mst), "MST");

    // An offset that is not a whole number of minutes: only the …0000 forms show the seconds.
    let lmt = Time::new(1_790_089_445, 0, 3781, "LMT");
    assert_eq!(format("-070000", &lmt), "+010301");
    assert_eq!(format("-07:00:00", &lmt), "+01:03:01");
    assert_eq!(format("-0700", &lmt), "+0103");

    // Without a zone name, "MST" falls back to the numeric form - which is what Time::now()
    // produces, since chrono cannot tell us the local zone's abbreviation.
    let unnamed = Time::new(1_790_089_445, 0, 5 * 3600 + 1800, "");
    assert_eq!(format("MST", &unnamed), "+0530");
    assert_eq!(format("MST", &Time::new(0, 0, -150 * 60, "")), "-0230");
}

#[test]
fn padding_and_widths() {
    // 2006-01-02T03:04:05Z, Go's own reference time: every field is single-digit.
    let t = Time::new(1_136_171_045, 0, 0, "UTC");
    assert_eq!(format("1 2 3 4 5", &t), "1 2 3 4 5");
    assert_eq!(format("01 02 03 04 05", &t), "01 02 03 04 05");
    assert_eq!(format("_2|__2|002", &t), " 2|  2|002");
    assert_eq!(
        format("Monday Mon January Jan", &t),
        "Monday Mon January Jan"
    );
    // A year below 1000 is padded to four digits, "06" shows the last two.
    let year6 = Time::new(-61_972_387_200, 0, 0, "UTC");
    assert_eq!(format("2006-01-02 06", &year6), "0006-03-05 06");
}

#[test]
fn year_day_widths() {
    // 2026-12-31: the last day of a common year.
    let t = Time::new(1_798_761_599, 0, 0, "UTC");
    assert_eq!(format("__2 002", &t), "365 365");
    // 2024-02-29: a leap day.
    let leap = Time::new(1_709_208_000, 0, 0, "UTC");
    assert_eq!(format("Jan _2 002", &leap), "Feb 29 060");
}

#[test]
fn out_of_range_instants_do_not_panic() {
    // chrono's calendar stops at year ±262143; a file name is not worth a panic, so the epoch
    // is used instead. No clock reaches these values.
    for secs in [
        i64::MIN,
        i64::MAX,
        -100_000_000_000_000,
        100_000_000_000_000,
    ] {
        let t = Time::new(secs, 0, 3600, "X");
        assert!(!format("2006-01-02T15:04:05", &t).is_empty());
    }
}

#[test]
fn now_has_the_local_offset_and_no_zone_name() {
    let before = chrono::Local::now().format("%Y-%m-%d").to_string();
    let now = Time::now();
    let after = chrono::Local::now().format("%Y-%m-%d").to_string();
    assert!(now.zone_name.is_empty(), "see Time::now's documentation");
    // Some plausible wall clock (2020-01-01 .. 2100-01-01) and a real zone offset.
    assert!((1_577_836_800..4_102_444_800).contains(&now.unix_secs));
    assert!(now.offset_secs.abs() <= 26 * 3600);
    assert!(now.nanos < 1_000_000_000);
    // The date it renders is the local one. Bracketed, so a run across local midnight cannot
    // make the comparison flaky.
    let got = format("2006-01-02", &now);
    assert!(
        got == before || got == after,
        "{got} not in {before}..{after}"
    );
}

#[test]
fn multi_byte_characters_never_split_a_token() {
    // The scanner works on bytes, like Go's; every index it slices at is the position of an
    // ASCII byte it just matched, so a multi-byte character next to a token must not panic or
    // corrupt the output. Every byte that can start a token, combined with every ASCII byte and
    // a two-, three- and four-byte character.
    let t = t0();
    let wide = ["é", "€", "🦀"];
    for start in b"JM0123_45PpZ-.,".iter().map(|&c| c as char) {
        for tail in 0u8..=127 {
            let tail = tail as char;
            for w in wide {
                for layout in [
                    format!("{start}{tail}{w}"),
                    format!("{w}{start}{tail}"),
                    format!("{start}{w}{tail}"),
                    format!("{w}{start}{w}{tail}{w}"),
                ] {
                    let out = format(&layout, &t);
                    // Whatever comes out, it is a valid string (the call did not panic) and a
                    // layout without any token is copied verbatim.
                    assert!(out.len() >= wide_bytes(&layout), "layout {layout:?}");
                }
            }
        }
    }
}

/// How many bytes of `layout` belong to characters the scanner can never consume (anything
/// outside ASCII), and which therefore have to survive into the output.
fn wide_bytes(layout: &str) -> usize {
    layout
        .chars()
        .filter(|c| !c.is_ascii())
        .map(char::len_utf8)
        .sum()
}
