//! The `-snmplog` CSV logger.
//!
//! Go sources:
//! - `kcptun/std/snmp.go` — `SnmpLogger` (the ticker loop) and `writeSnmpRecord` (one record);
//! - `kcp-go/v5@v5.6.66 snmp.go` — `DefaultSnmp.Header()` and `ToSlice()`, ported in
//!   [`kcptun_kcp::snmp`];
//! - Go standard library `encoding/csv` (Go 1.27.1) `writer.go:Writer.Write`,
//!   `fieldNeedsQuotes` — the record encoder, reproduced in `write_csv_record` below;
//! - Go standard library `path/filepath` `path.go:Split` — the directory/file split that decides
//!   which part of `-snmplog` goes through [`crate::gotime::format`].
//!
//! Both halves of the path matter: `-snmplog /var/log/kcptun/snmp-2006-01-02.log` writes
//! `/var/log/kcptun/snmp-2026-09-22.log`, and the file rotates by itself when the formatted name
//! changes. Only the **file** part is formatted, so a reference-layout token in a directory name
//! is left alone.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::time::Duration;

use kcptun_kcp::snmp::{DEFAULT_SNMP, Snmp};

use crate::config::go_error_text;
use crate::gotime;
use crate::logln;

/// What [`write_snmp_record`] can fail with, in the wording of the Go `*os.PathError` that
/// `SnmpLogger` prints after `snmp logger:`.
#[derive(Debug, thiserror::Error)]
pub enum SnmpLogError {
    /// `os.OpenFile` failed: `open /var/log/snmp.log: permission denied`.
    #[error("open {path}: {err}")]
    Open { path: String, err: String },
    /// The record could not be written: `write /var/log/snmp.log: no space left on device`.
    #[error("write {path}: {err}")]
    Write { path: String, err: String },
}

/// Appends an SNMP record to `path` every `interval` seconds, forever.
///
/// A no-op when `path` is empty or `interval <= 0`, like Go — the binaries call it
/// unconditionally (`go std.SnmpLogger(config.SnmpLog, config.SnmpPeriod)`) and it returns at once
/// when `-snmplog` is unset. Write failures are logged as `snmp logger: <err>` and the loop
/// continues, so a full disk or a vanished directory never stops the tunnel.
///
/// The caller spawns it (`tokio::spawn(snmp_logger(...))` for Go's `go SnmpLogger(...)`).
// Go: kcptun/std/snmp.go:SnmpLogger()
pub async fn snmp_logger(path: String, interval: i64) {
    if path.is_empty() || interval <= 0 {
        return;
    }
    // Go: time.NewTicker(time.Duration(interval) * time.Second). Go's multiplication overflows
    // its int64 nanoseconds above ~292 years and panics in NewTicker; saturating here keeps the
    // absurd setting harmless instead (the tick simply never comes).
    let period = Duration::from_secs(interval.unsigned_abs());
    let mut ticker = tokio::time::interval(period);
    // A Go ticker keeps its original schedule and silently drops ticks nobody received (its
    // channel holds one); `Skip` is tokio's spelling of that. tokio's first tick is immediate,
    // Go's is one period away, so the first one is consumed here.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        // Deviation V13: the local zone abbreviation is unavailable, so an `MST` token in the
        // file name renders numerically (`+0200`) where Go writes `CEST`.
        if let Err(err) = write_snmp_record(&path, &gotime::Time::now(), &DEFAULT_SNMP) {
            // Go: log.Println("snmp logger:", err)
            logln!("snmp logger:", err);
        }
    }
}

/// Writes one CSV record: the unix seconds of `now`, then every counter of `snmp`.
///
/// `path` is split into a directory and a file name; the file name goes through
/// [`gotime::format`] (so `-snmplog` can carry a date layout) and the record is appended to
/// `dir + formatted`. The CSV header is written first whenever the file is empty, which covers
/// both a new file and a rotated name.
///
/// **Deviation V13.** The clock [`snmp_logger`] passes carries no zone abbreviation, so a file
/// name containing the `MST` reference token renders Go's numeric fallback (`snmp-+0200.log`)
/// instead of Go's `snmp-CEST.log`. Every other layout token is exact, and a caller that has the
/// abbreviation (`gotime::Time::new`) gets Go's output for `MST` too.
///
/// Go reads the clock twice — once for the file name, once for the `Unix` column — so a record
/// written in the microsecond around midnight can land in yesterday's file with today's
/// timestamp. Taking one instant for both is the only difference, and it is the sane reading of
/// what the code means.
// Go: kcptun/std/snmp.go:writeSnmpRecord()
pub fn write_snmp_record(path: &str, now: &gotime::Time, snmp: &Snmp) -> Result<(), SnmpLogError> {
    // Go: logdir, logfile := filepath.Split(path); only logfile is formatted.
    let (logdir, logfile) = filepath_split(path);
    let name = format!("{logdir}{}", gotime::format(logfile, now));

    // Go: os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o666);
    }
    let mut file = options.open(&name).map_err(|e| SnmpLogError::Open {
        path: name.clone(),
        err: go_error_text(&e),
    })?;

    let mut record = String::new();
    // Go: `if stat, err := f.Stat(); err == nil && stat.Size() == 0` — a failed Stat writes no
    // header rather than reporting an error.
    if file.metadata().map(|m| m.len() == 0).unwrap_or(false) {
        let mut header = Vec::with_capacity(1 + kcptun_kcp::snmp::SNMP_FIELDS);
        header.push("Unix".to_string());
        header.extend(snmp.header());
        write_csv_record(&mut record, &header);
    }
    let mut row = Vec::with_capacity(1 + kcptun_kcp::snmp::SNMP_FIELDS);
    row.push(now.unix_secs.to_string());
    row.extend(snmp.to_slice());
    write_csv_record(&mut record, &row);

    // Go's csv.Writer buffers into a 4096-byte bufio.Writer and flushes once at the end; a header
    // plus a row stay well under that, so Go also reaches the file in a single write.
    file.write_all(record.as_bytes())
        .map_err(|e| SnmpLogError::Write {
            path: name,
            err: go_error_text(&e),
        })
}

/// Splits `path` after the final separator, so that `dir + file == path`.
///
/// Go's `filepath.Split`. On Windows both `\` and `/` separate (volume names are not special-cased
/// here: `-snmplog C:snmp.log` would be treated as a plain relative name, which Go's `VolumeName`
/// would keep in the directory part. The name is then formatted as a whole, and no reference
/// layout token can match `C:`, so the file lands in the same place either way).
// Go: path/filepath/path.go:Split()
fn filepath_split(path: &str) -> (&str, &str) {
    let is_separator = |c: char| c == '/' || (cfg!(windows) && c == '\\');
    match path.rfind(is_separator) {
        // The separator is one byte, so the split point is inside no multi-byte character.
        Some(i) => path.split_at(i + 1),
        None => ("", path),
    }
}

/// Appends one CSV record (fields, commas, `\n`) to `out`, like Go's `csv.Writer.Write` with its
/// defaults (`Comma: ','`, `UseCRLF: false`).
///
/// SNMP headers and counters never need quoting; the rules are ported anyway so that the encoder
/// is the same one Go has, whatever a future field holds.
// Go: encoding/csv/writer.go:Writer.Write()
fn write_csv_record(out: &mut String, fields: &[String]) {
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        if !field_needs_quotes(field) {
            out.push_str(field);
            continue;
        }
        out.push('"');
        let mut rest = field.as_str();
        while !rest.is_empty() {
            let i = rest.find(['"', '\r', '\n']).unwrap_or(rest.len());
            let (verbatim, tail) = rest.split_at(i);
            out.push_str(verbatim);
            rest = tail;
            let mut chars = rest.chars();
            match chars.next() {
                // Go doubles the quote, keeps a bare `\r` and writes `\n` as itself while
                // `UseCRLF` is false.
                Some('"') => out.push_str("\"\""),
                Some('\r') => out.push('\r'),
                Some('\n') => out.push('\n'),
                Some(_) | None => {}
            }
            rest = chars.as_str();
        }
        out.push('"');
    }
    out.push('\n');
}

/// Whether `field` has to be quoted.
// Go: encoding/csv/writer.go:Writer.fieldNeedsQuotes()
fn field_needs_quotes(field: &str) -> bool {
    if field.is_empty() {
        return false;
    }
    // Go: `\.` would otherwise be read back as the "end of data" marker of some CSV dialects.
    if field == "\\." {
        return true;
    }
    if field.contains([',', '"', '\r', '\n']) {
        return true;
    }
    // Go: unicode.IsSpace on the first rune. Rust's `char::is_whitespace` is the same
    // White_Space property, NBSP and NEL included.
    field.starts_with(char::is_whitespace)
}

#[cfg(test)]
#[path = "snmp_tests.rs"]
mod tests;
