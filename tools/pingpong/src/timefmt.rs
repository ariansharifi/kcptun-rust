//! UTC timestamps, without a date dependency.
//!
//! Every CSV carries both the raw unix second (what a plotter wants) and an ISO-8601 UTC string
//! (what a human reading a six-hour soak wants). `chrono` is in the workspace but with
//! `default-features = false`, so it has no clock; rather than widen a dependency for a dev
//! tool, the civil-date conversion is done here: it is twenty lines and it is testable.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the unix epoch, or 0 if the clock is before it.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Formats unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn iso8601_utc(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let secs_of_day = unix % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// Days since 1970-01-01 to a civil date.
///
/// Howard Hinnant's `civil_from_days`, the same algorithm the C++20 `<chrono>` proposal uses
/// (<https://howardhinnant.github.io/date_algorithms.html>), valid for the whole `i64` range.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// A compact `YYYYmmdd-HHMMSS` stamp, for file and directory names.
pub fn stamp_utc(unix: u64) -> String {
    let iso = iso8601_utc(unix);
    let mut out = String::with_capacity(15);
    for c in iso.chars() {
        match c {
            '-' | ':' | 'Z' => {}
            'T' => out.push('-'),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_instants_format_correctly() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601_utc(1), "1970-01-01T00:00:01Z");
        // 2026-09-23T12:34:56Z, checked against `date -u -r 1790166896`.
        assert_eq!(iso8601_utc(1_790_166_896), "2026-09-23T12:34:56Z");
        // A leap day, and the last second of a year.
        assert_eq!(iso8601_utc(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(iso8601_utc(1_767_225_599), "2025-12-31T23:59:59Z");
    }

    #[test]
    fn stamps_are_filename_safe() {
        assert_eq!(stamp_utc(1_790_166_896), "20260923-123456");
        assert!(!stamp_utc(unix_now()).contains(':'));
    }

    #[test]
    fn every_day_of_a_leap_year_round_trips() {
        // 2024-01-01T00:00:00Z
        let start = 1_704_067_200u64;
        let mut seen = Vec::new();
        for day in 0..366 {
            seen.push(iso8601_utc(start + day * 86_400));
        }
        assert_eq!(seen[0], "2024-01-01T00:00:00Z");
        assert_eq!(seen[59], "2024-02-29T00:00:00Z");
        assert_eq!(seen[365], "2024-12-31T00:00:00Z");
        seen.dedup();
        assert_eq!(seen.len(), 366, "every day is distinct");
    }

    #[test]
    fn the_clock_is_after_the_epoch() {
        assert!(unix_now() > 1_700_000_000);
    }
}
