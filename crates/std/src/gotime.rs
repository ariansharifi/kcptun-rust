//! Port of Go's reference-layout time formatting, `time.Time.Format`.
//!
//! Go sources (Go 1.27.1):
//! - `time/format.go:nextStdChunk`: the layout scanner, token by token and quirk by quirk;
//! - `time/format.go:(Time).appendFormat`, `appendInt`, `appendNano`, `stdFracSecond`,
//!   `digitsLen`, `separator`, `startsWithLowerCase`, `isDigit`;
//! - `time/time.go:longMonthNames`, `longDayNames`: the English month and weekday names;
//! - `kcptun/std/snmp.go:56`: kcptun's only use of a user-supplied layout:
//!   `os.OpenFile(logdir+time.Now().Format(logfile), ...)`, the `-snmplog` file name.
//!
//! Every reference-layout token Go knows is implemented; none is left out. The scanner's
//! surprises are part of the port, because `-snmplog` file names run through it:
//! `Month` and `Janx` stay literal, `_2006` is an underscore plus the year, `.0001` is the
//! literal `.00` followed by the zero-padded month, and a file called `snmp-pm.log` is written
//! as `snmp-am.log` before noon.
//!
//! What a [`Time`] carries is Go's `time.Time` reduced to what `Format` reads: the instant, the
//! zone offset and the zone's abbreviation. See [`Time::now`] for the one thing the port cannot
//! reproduce: the abbreviation of the machine's local zone.

use chrono::{Datelike as _, Local, Offset as _, Timelike as _};

/// Go: `time/time.go:longMonthNames`, indexed by month - 1.
const LONG_MONTH_NAMES: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// Go: `time/time.go:longDayNames`, indexed by `Weekday` (Sunday == 0).
const LONG_DAY_NAMES: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];

// ---------------------------------------------------------------------------------------
// The instant that is formatted
// ---------------------------------------------------------------------------------------

/// A `time.Time` reduced to what [`format`] reads.
///
/// The wall clock it renders is `unix_secs + offset_secs`, so an instant plus the zone it is
/// shown in, exactly like Go's `Time.locabs()`.
// Go: time.Time as appendFormat sees it (name, offset, abs)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Time {
    /// Seconds since the unix epoch.
    pub unix_secs: i64,
    /// Nanoseconds within the second, `0..1_000_000_000`.
    pub nanos: u32,
    /// Seconds the zone is ahead of UTC at this instant.
    pub offset_secs: i32,
    /// The zone's abbreviation (`UTC`, `CEST`, …), as the `MST` token prints it. When it is
    /// empty, `MST` falls back to the numeric form, which is what Go does for a zone without a
    /// name.
    pub zone_name: String,
}

impl Time {
    /// An instant in a zone given by its offset and abbreviation.
    // Go: time.Unix(sec, nsec).In(time.FixedZone(name, offset))
    pub fn new(unix_secs: i64, nanos: u32, offset_secs: i32, zone_name: impl Into<String>) -> Time {
        Time {
            unix_secs,
            nanos,
            offset_secs,
            zone_name: zone_name.into(),
        }
    }

    /// The current instant in the machine's local zone.
    ///
    /// The zone **abbreviation is left empty**: `chrono`'s `Local` exposes the offset but not
    /// the name the tz database gives it, and this crate is `#![forbid(unsafe_code)]`, so it
    /// cannot ask libc either. Every token except `MST` is therefore exactly Go's; a layout
    /// containing `MST` renders as `+0200` where Go writes `CEST`. kcptun passes a layout to
    /// `Format` only for the `-snmplog` file name, so this is visible only if a user puts `MST`
    /// into that name.
    // Go: time.Now()
    pub fn now() -> Time {
        let now = Local::now();
        Time {
            unix_secs: now.timestamp(),
            nanos: now.timestamp_subsec_nanos(),
            offset_secs: now.offset().fix().local_minus_utc(),
            zone_name: String::new(),
        }
    }

    /// The broken-down wall clock of this instant in its own zone.
    fn fields(&self) -> Fields {
        let secs = self.unix_secs.saturating_add(i64::from(self.offset_secs));
        // Out of chrono's range (year ±262143); no clock and no `-snmplog` rotation reaches it,
        // and a file name is not worth a panic, so fall back to the epoch as log.rs does.
        let t = chrono::DateTime::from_timestamp(secs, 0)
            .unwrap_or(chrono::DateTime::UNIX_EPOCH)
            .naive_utc();
        Fields {
            year: i64::from(t.year()),
            month: t.month(),
            day: t.day(),
            yday: t.ordinal(),
            hour: t.hour(),
            minute: t.minute(),
            second: t.second(),
            // Go's Weekday has Sunday == 0, like chrono's num_days_from_sunday().
            weekday: t.weekday().num_days_from_sunday() as usize,
        }
    }
}

/// The calendar fields `appendFormat` computes from the absolute time.
// Go: absDays.date(), absDays.yearYday(), absDays.weekday(), absClock
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fields {
    year: i64,
    month: u32,
    day: u32,
    yday: u32,
    hour: u32,
    minute: u32,
    second: u32,
    weekday: usize,
}

// ---------------------------------------------------------------------------------------
// The layout scanner
// ---------------------------------------------------------------------------------------

/// One reference-layout token.
// Go: time/format.go's std* constants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Std {
    /// `January`
    LongMonth,
    /// `Jan`
    Month,
    /// `1`
    NumMonth,
    /// `01`
    ZeroMonth,
    /// `Monday`
    LongWeekDay,
    /// `Mon`
    WeekDay,
    /// `2`
    Day,
    /// `_2`
    UnderDay,
    /// `02`
    ZeroDay,
    /// `__2`
    UnderYearDay,
    /// `002`
    ZeroYearDay,
    /// `15`
    Hour,
    /// `3`
    Hour12,
    /// `03`
    ZeroHour12,
    /// `4`
    Minute,
    /// `04`
    ZeroMinute,
    /// `5`
    Second,
    /// `05`
    ZeroSecond,
    /// `2006`
    LongYear,
    /// `06`
    Year,
    /// `PM` (`upper`) and `pm`
    Pm {
        /// `PM`/`AM` rather than `pm`/`am`.
        upper: bool,
    },
    /// `MST`
    Tz,
    /// The ten numeric zone tokens, `-07…` and `Z07…`.
    NumTz {
        /// A `Z…` token: prints `Z` when the offset is zero.
        iso: bool,
        /// `…07:00…`: the parts are separated by colons.
        colon: bool,
        /// `-07` / `Z07`: hours only.
        short: bool,
        /// `…0000` / `…00:00`: the offset's seconds are printed too.
        seconds: bool,
    },
    /// `.0…`, `,0…` (`trim == false`) and `.9…`, `,9…` (`trim == true`).
    FracSecond {
        /// Drop trailing zeros and, if nothing is left, the separator.
        trim: bool,
        /// How many digits the layout asked for (Go masks this to 12 bits).
        digits: usize,
        /// The separator is `,` rather than `.`.
        comma: bool,
    },
}

/// Go: `time/format.go:std0x`, the tokens `01`…`06`.
const STD_0X: [Std; 6] = [
    Std::ZeroMonth,
    Std::ZeroDay,
    Std::ZeroHour12,
    Std::ZeroMinute,
    Std::ZeroSecond,
    Std::Year,
];

/// Whether `s` starts with a lower-case letter. Prevents matching `Month` when looking for
/// `Mon`.
// Go: time/format.go:startsWithLowerCase
fn starts_with_lower_case(s: &str) -> bool {
    match s.as_bytes().first() {
        Some(&c) => c.is_ascii_lowercase(),
        None => false,
    }
}

/// Whether byte `i` of `s` is a decimal digit (false past the end).
// Go: time/format.go:isDigit
fn is_digit(s: &[u8], i: usize) -> bool {
    match s.get(i) {
        Some(&c) => c.is_ascii_digit(),
        None => false,
    }
}

/// Go's `stdFracSecond` digit mask: `n & 0xfff`.
// Go: time/format.go:stdFracSecond, digitsLen
const FRAC_DIGITS_MASK: usize = 0xfff;

/// Finds the first reference-layout token in `layout` and returns the literal text before it,
/// the token and the rest of the layout. `None` means no token is left, and then the whole
/// remaining layout is the prefix.
///
/// Every index used below is the position of an ASCII byte that has just been matched (or one
/// past such a byte), so the string slices never split a multi-byte character; Go scans bytes
/// the same way.
// Go: time/format.go:nextStdChunk
fn next_std_chunk(layout: &str) -> (&str, Option<Std>, &str) {
    let b = layout.as_bytes();
    let n = b.len();
    for i in 0..n {
        match b[i] {
            b'J' => {
                // January, Jan
                if n >= i + 3 && &b[i..i + 3] == b"Jan" {
                    if n >= i + 7 && &b[i..i + 7] == b"January" {
                        return (&layout[..i], Some(Std::LongMonth), &layout[i + 7..]);
                    }
                    if !starts_with_lower_case(&layout[i + 3..]) {
                        return (&layout[..i], Some(Std::Month), &layout[i + 3..]);
                    }
                }
            }
            b'M' => {
                // Monday, Mon, MST
                if n >= i + 3 {
                    if &b[i..i + 3] == b"Mon" {
                        if n >= i + 6 && &b[i..i + 6] == b"Monday" {
                            return (&layout[..i], Some(Std::LongWeekDay), &layout[i + 6..]);
                        }
                        if !starts_with_lower_case(&layout[i + 3..]) {
                            return (&layout[..i], Some(Std::WeekDay), &layout[i + 3..]);
                        }
                    }
                    if &b[i..i + 3] == b"MST" {
                        return (&layout[..i], Some(Std::Tz), &layout[i + 3..]);
                    }
                }
            }
            b'0' => {
                // 01, 02, 03, 04, 05, 06, 002
                if n >= i + 2 && (b'1'..=b'6').contains(&b[i + 1]) {
                    let std = STD_0X[usize::from(b[i + 1] - b'1')];
                    return (&layout[..i], Some(std), &layout[i + 2..]);
                }
                if n >= i + 3 && b[i + 1] == b'0' && b[i + 2] == b'2' {
                    return (&layout[..i], Some(Std::ZeroYearDay), &layout[i + 3..]);
                }
            }
            b'1' => {
                // 15, 1
                if n >= i + 2 && b[i + 1] == b'5' {
                    return (&layout[..i], Some(Std::Hour), &layout[i + 2..]);
                }
                return (&layout[..i], Some(Std::NumMonth), &layout[i + 1..]);
            }
            b'2' => {
                // 2006, 2
                if n >= i + 4 && &b[i..i + 4] == b"2006" {
                    return (&layout[..i], Some(Std::LongYear), &layout[i + 4..]);
                }
                return (&layout[..i], Some(Std::Day), &layout[i + 1..]);
            }
            b'_' => {
                // _2, _2006, __2
                if n >= i + 2 && b[i + 1] == b'2' {
                    // _2006 is really a literal _, followed by stdLongYear
                    if n >= i + 5 && &b[i + 1..i + 5] == b"2006" {
                        return (&layout[..i + 1], Some(Std::LongYear), &layout[i + 5..]);
                    }
                    return (&layout[..i], Some(Std::UnderDay), &layout[i + 2..]);
                }
                if n >= i + 3 && b[i + 1] == b'_' && b[i + 2] == b'2' {
                    return (&layout[..i], Some(Std::UnderYearDay), &layout[i + 3..]);
                }
            }
            b'3' => return (&layout[..i], Some(Std::Hour12), &layout[i + 1..]),
            b'4' => return (&layout[..i], Some(Std::Minute), &layout[i + 1..]),
            b'5' => return (&layout[..i], Some(Std::Second), &layout[i + 1..]),
            b'P' => {
                // PM
                if n >= i + 2 && b[i + 1] == b'M' {
                    return (
                        &layout[..i],
                        Some(Std::Pm { upper: true }),
                        &layout[i + 2..],
                    );
                }
            }
            b'p' => {
                // pm
                if n >= i + 2 && b[i + 1] == b'm' {
                    return (
                        &layout[..i],
                        Some(Std::Pm { upper: false }),
                        &layout[i + 2..],
                    );
                }
            }
            b'-' => {
                // -070000, -07:00:00, -0700, -07:00, -07
                for &(pat, colon, short, seconds) in &[
                    (&b"-070000"[..], false, false, true),
                    (&b"-07:00:00"[..], true, false, true),
                    (&b"-0700"[..], false, false, false),
                    (&b"-07:00"[..], true, false, false),
                    (&b"-07"[..], false, true, false),
                ] {
                    if n >= i + pat.len() && &b[i..i + pat.len()] == pat {
                        let std = Std::NumTz {
                            iso: false,
                            colon,
                            short,
                            seconds,
                        };
                        return (&layout[..i], Some(std), &layout[i + pat.len()..]);
                    }
                }
            }
            b'Z' => {
                // Z070000, Z07:00:00, Z0700, Z07:00, Z07
                for &(pat, colon, short, seconds) in &[
                    (&b"Z070000"[..], false, false, true),
                    (&b"Z07:00:00"[..], true, false, true),
                    (&b"Z0700"[..], false, false, false),
                    (&b"Z07:00"[..], true, false, false),
                    (&b"Z07"[..], false, true, false),
                ] {
                    if n >= i + pat.len() && &b[i..i + pat.len()] == pat {
                        let std = Std::NumTz {
                            iso: true,
                            colon,
                            short,
                            seconds,
                        };
                        return (&layout[..i], Some(std), &layout[i + pat.len()..]);
                    }
                }
            }
            // ,000, or .000, or ,999, or .999 - repeated digits for fractional seconds.
            // Go tests the digit inside the case body; a guard says the same and keeps the
            // fall-through to the next byte.
            c @ (b'.' | b',') if i + 1 < n && (b[i + 1] == b'0' || b[i + 1] == b'9') => {
                let ch = b[i + 1];
                let mut j = i + 1;
                while j < n && b[j] == ch {
                    j += 1;
                }
                // String of digits must end here - only fractional second is all digits.
                if !is_digit(b, j) {
                    let std = Std::FracSecond {
                        trim: ch == b'9',
                        digits: (j - (i + 1)) & FRAC_DIGITS_MASK,
                        comma: c == b',',
                    };
                    return (&layout[..i], Some(std), &layout[j..]);
                }
            }
            _ => {}
        }
    }
    (layout, None, "")
}

// ---------------------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------------------

/// The hour on a twelve-hour clock: noon is 12PM, midnight is 12AM.
// Go: time/format.go:appendFormat, cases stdHour12 and stdZeroHour12
fn hour12(hour: u32) -> u32 {
    let hr = hour % 12;
    if hr == 0 { 12 } else { hr }
}

/// Appends `x` in decimal, zero-padded to at least `width` digits.
// Go: time/format.go:appendInt
fn append_int(out: &mut String, x: i64, width: usize) {
    let u = if x < 0 {
        out.push('-');
        x.unsigned_abs()
    } else {
        x as u64
    };
    let text = u.to_string();
    for _ in text.len()..width {
        out.push('0');
    }
    out.push_str(&text);
}

/// Appends the fractional second: the separator followed by `digits` digits of `nanosec`,
/// with trailing zeros (and then the separator) removed when `trim` is set.
// Go: time/format.go:appendNano
fn append_nano(out: &mut String, nanosec: u32, trim: bool, digits: usize, comma: bool) {
    if trim && (digits == 0 || nanosec == 0) {
        return;
    }
    let dot = if comma { ',' } else { '.' };
    out.push(dot);
    // Go: appendInt(b, nanosec, 9) followed by b = b[:len(b)-9+n] when n < 9. More than nine
    // digits are simply not truncated, so the fraction is never longer than nine digits.
    let nanos = format!("{nanosec:09}");
    // `digits.min(nanos.len())` only matters for a `nanos` field out of Go's 0..1e9 range,
    // which `time.Time` cannot hold; it keeps an out-of-range value from panicking here.
    let mut frac = if digits < 9 {
        &nanos[..digits.min(nanos.len())]
    } else {
        &nanos[..]
    };
    if trim {
        // Go trims the whole buffer, but the separator it just appended always stops the loop.
        frac = frac.trim_end_matches('0');
        if frac.is_empty() {
            out.pop();
            return;
        }
    }
    out.push_str(frac);
}

/// Renders `t` in the reference layout `layout`, Go's `Time.Format`.
// Go: time/format.go:(Time).Format, (Time).appendFormat
pub fn format(layout: &str, t: &Time) -> String {
    let f = t.fields();
    let offset = i64::from(t.offset_secs);
    let mut out = String::with_capacity(layout.len() + 16);
    let mut layout = layout;

    // Each iteration generates one std value.
    while !layout.is_empty() {
        let (prefix, std, suffix) = next_std_chunk(layout);
        out.push_str(prefix);
        let Some(std) = std else { break };
        layout = suffix;

        match std {
            Std::Year => {
                let y = f.year.abs();
                append_int(&mut out, y % 100, 2);
            }
            Std::LongYear => append_int(&mut out, f.year, 4),
            Std::Month => out.push_str(&LONG_MONTH_NAMES[f.month as usize - 1][..3]),
            Std::LongMonth => out.push_str(LONG_MONTH_NAMES[f.month as usize - 1]),
            Std::NumMonth => append_int(&mut out, i64::from(f.month), 0),
            Std::ZeroMonth => append_int(&mut out, i64::from(f.month), 2),
            Std::WeekDay => out.push_str(&LONG_DAY_NAMES[f.weekday][..3]),
            Std::LongWeekDay => out.push_str(LONG_DAY_NAMES[f.weekday]),
            Std::Day => append_int(&mut out, i64::from(f.day), 0),
            Std::UnderDay => {
                if f.day < 10 {
                    out.push(' ');
                }
                append_int(&mut out, i64::from(f.day), 0);
            }
            Std::ZeroDay => append_int(&mut out, i64::from(f.day), 2),
            Std::UnderYearDay => {
                if f.yday < 100 {
                    out.push(' ');
                    if f.yday < 10 {
                        out.push(' ');
                    }
                }
                append_int(&mut out, i64::from(f.yday), 0);
            }
            Std::ZeroYearDay => append_int(&mut out, i64::from(f.yday), 3),
            Std::Hour => append_int(&mut out, i64::from(f.hour), 2),
            Std::Hour12 => append_int(&mut out, i64::from(hour12(f.hour)), 0),
            Std::ZeroHour12 => append_int(&mut out, i64::from(hour12(f.hour)), 2),
            Std::Minute => append_int(&mut out, i64::from(f.minute), 0),
            Std::ZeroMinute => append_int(&mut out, i64::from(f.minute), 2),
            Std::Second => append_int(&mut out, i64::from(f.second), 0),
            Std::ZeroSecond => append_int(&mut out, i64::from(f.second), 2),
            Std::Pm { upper } => out.push_str(match (f.hour >= 12, upper) {
                (true, true) => "PM",
                (false, true) => "AM",
                (true, false) => "pm",
                (false, false) => "am",
            }),
            Std::NumTz {
                iso,
                colon,
                short,
                seconds,
            } => {
                // Ugly special case. We cheat and take the "Z" variants to mean "the time zone
                // as formatted for ISO 8601".
                if offset == 0 && iso {
                    out.push('Z');
                } else {
                    let mut zone = offset / 60; // convert to minutes
                    let mut absoffset = offset;
                    if zone < 0 {
                        out.push('-');
                        zone = -zone;
                        absoffset = -absoffset;
                    } else {
                        out.push('+');
                    }
                    append_int(&mut out, zone / 60, 2);
                    if colon {
                        out.push(':');
                    }
                    if !short {
                        append_int(&mut out, zone % 60, 2);
                    }
                    // append seconds if appropriate
                    if seconds {
                        if colon {
                            out.push(':');
                        }
                        append_int(&mut out, absoffset % 60, 2);
                    }
                }
            }
            Std::Tz => {
                if !t.zone_name.is_empty() {
                    out.push_str(&t.zone_name);
                } else {
                    // No time zone known for this time, but we must print one. Use the -0700
                    // format.
                    let mut zone = offset / 60; // convert to minutes
                    if zone < 0 {
                        out.push('-');
                        zone = -zone;
                    } else {
                        out.push('+');
                    }
                    append_int(&mut out, zone / 60, 2);
                    append_int(&mut out, zone % 60, 2);
                }
            }
            Std::FracSecond {
                trim,
                digits,
                comma,
            } => append_nano(&mut out, t.nanos, trim, digits, comma),
        }
    }
    out
}

#[cfg(test)]
#[path = "gotime_tests.rs"]
mod tests;
