//! Tests for [`crate::snmp`].
//!
//! The expected CSV is what Go's `encoding/csv` writes for the same records: comma-separated
//! fields, `\n` line endings, no quoting for the plain identifiers and decimal numbers that SNMP
//! produces. The header and its order come from `kcptun_kcp::snmp`, which the `snmp` golden
//! vectors of Step 03 already pin to Go's `DefaultSnmp.Header()`/`ToSlice()`.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kcptun_kcp::snmp::Snmp;

use super::*;
use crate::log;

/// 2026-03-23T12:00:00Z, the instant `log`'s goldens use.
const T0: i64 = 1_774_267_200;

/// A UTC instant, so the file names below do not depend on the machine's zone.
fn utc(unix_secs: i64) -> gotime::Time {
    gotime::Time::new(unix_secs, 0, 0, "UTC")
}

/// Counters with a few distinguishable values.
fn filled_snmp() -> Snmp {
    let snmp = Snmp::new();
    snmp.bytes_sent.store(11, Ordering::Relaxed);
    snmp.bytes_received.store(22, Ordering::Relaxed);
    snmp.oob_packets.store(33, Ordering::Relaxed);
    snmp
}

// ---------------------------------------------------------------------------------------
// One record
// ---------------------------------------------------------------------------------------

/// The header line the real `std.SnmpLogger` wrote, captured from the pinned Go sources on
/// 2026-09-22 (`go run -mod=vendor` over `reference/kcptun`, kcp-go v5.6.66).
const GO_HEADER: &str = "Unix,BytesSent,BytesReceived,MaxConn,ActiveOpens,PassiveOpens,CurrEstab,\
InErrs,InCsumErrors,KCPInErrors,InPkts,OutPkts,InSegs,OutSegs,InBytes,OutBytes,RetransSegs,\
FastRetransSegs,EarlyRetransSegs,LostSegs,RepeatSegs,FECFullShards,FECParityShards,FECErrs,\
FECRecovered,FECShardSet,FECShardMin,RingBufferSndQueue,RingBufferRcvQueue,RingBufferSndBuffer,\
OOBPackets";

#[test]
fn test_write_snmp_record_shape() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snmp.log");
    let snmp = filled_snmp();

    write_snmp_record(path.to_str().unwrap(), &utc(T0), &snmp).unwrap();

    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    assert_eq!(lines.len(), 2, "header and one row: {text:?}");

    let want_header = format!("Unix,{}\n", snmp.header().join(","));
    assert_eq!(
        want_header,
        format!("{GO_HEADER}\n"),
        "Go's header, verbatim"
    );
    assert_eq!(lines[0], want_header);
    assert_eq!(
        lines[1].split(',').count(),
        1 + kcptun_kcp::snmp::SNMP_FIELDS
    );
    let want_row = format!("{T0},{}\n", snmp.to_slice().join(","));
    assert_eq!(lines[1], want_row);
    // The values land in Go's ToSlice order, which is not the struct order.
    assert!(want_row.starts_with(&format!("{T0},11,22,")), "{want_row}");
    assert!(want_row.ends_with(",33\n"), "{want_row}");
}

#[test]
fn test_write_snmp_record_writes_the_header_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snmp.log");
    let path = path.to_str().unwrap();
    let snmp = filled_snmp();

    write_snmp_record(path, &utc(T0), &snmp).unwrap();
    write_snmp_record(path, &utc(T0 + 1), &snmp).unwrap();
    write_snmp_record(path, &utc(T0 + 2), &snmp).unwrap();

    let text = std::fs::read_to_string(path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 4);
    assert!(lines[0].starts_with("Unix,BytesSent,"));
    assert_eq!(lines[1].split(',').next(), Some(T0.to_string().as_str()));
    assert_eq!(
        lines[2].split(',').next(),
        Some((T0 + 1).to_string().as_str())
    );
    assert_eq!(
        lines[3].split(',').next(),
        Some((T0 + 2).to_string().as_str())
    );
}

/// Only the file part of the path goes through the layout formatter, and a new name starts with
/// a new header: that is all the "rotation" `-snmplog` has.
#[test]
fn test_write_snmp_record_rotates_by_file_name() {
    let dir = tempfile::tempdir().unwrap();
    // The directory name contains `01`, a reference layout token: it must be left alone.
    let sub = dir.path().join("01-logs");
    std::fs::create_dir(&sub).unwrap();
    let path = sub.join("snmp-2006-01-02.log");
    let path = path.to_str().unwrap();
    let snmp = filled_snmp();

    write_snmp_record(path, &utc(T0), &snmp).unwrap();
    write_snmp_record(path, &utc(T0 + 3600), &snmp).unwrap();
    write_snmp_record(path, &utc(T0 + 86_400), &snmp).unwrap();

    let day1 = std::fs::read_to_string(sub.join("snmp-2026-03-23.log")).unwrap();
    let day2 = std::fs::read_to_string(sub.join("snmp-2026-03-24.log")).unwrap();
    assert_eq!(day1.lines().count(), 3, "header plus two rows: {day1}");
    assert_eq!(day2.lines().count(), 2, "header plus one row: {day2}");
    assert!(day2.starts_with("Unix,BytesSent,"));
    assert!(sub.join("snmp-2026-03-23.log").exists());
}

#[test]
fn test_write_snmp_record_open_error_text() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nowhere").join("snmp.log");
    let path = path.to_str().unwrap();

    let err = write_snmp_record(path, &utc(T0), &Snmp::new()).unwrap_err();
    // Go: `open /tmp/…/nowhere/snmp.log: no such file or directory`
    assert_eq!(
        err.to_string(),
        format!("open {path}: no such file or directory")
    );
}

#[test]
fn test_filepath_split() {
    assert_eq!(
        filepath_split("/var/log/snmp.log"),
        ("/var/log/", "snmp.log")
    );
    assert_eq!(filepath_split("snmp.log"), ("", "snmp.log"));
    assert_eq!(filepath_split("/snmp.log"), ("/", "snmp.log"));
    assert_eq!(filepath_split("dir/"), ("dir/", ""));
    assert_eq!(filepath_split(""), ("", ""));
}

// ---------------------------------------------------------------------------------------
// The CSV encoder
// ---------------------------------------------------------------------------------------

/// The quoting rules of Go's `csv.Writer`, which SNMP data never triggers but the encoder
/// carries anyway.
#[test]
fn test_write_csv_record_quoting() {
    let record = |fields: &[&str]| {
        let mut out = String::new();
        write_csv_record(
            &mut out,
            &fields.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
        );
        out
    };

    assert_eq!(record(&["Unix", "BytesSent"]), "Unix,BytesSent\n");
    assert_eq!(record(&[]), "\n");
    assert_eq!(record(&["", ""]), ",\n");
    assert_eq!(record(&["a,b"]), "\"a,b\"\n");
    assert_eq!(record(&["say \"hi\""]), "\"say \"\"hi\"\"\"\n");
    assert_eq!(record(&["two\nlines"]), "\"two\nlines\"\n");
    assert_eq!(record(&["cr\rlf"]), "\"cr\rlf\"\n");
    assert_eq!(record(&[" leading"]), "\" leading\"\n");
    assert_eq!(record(&["trailing "]), "trailing \n");
    assert_eq!(record(&["\\."]), "\"\\.\"\n");
}

// ---------------------------------------------------------------------------------------
// The ticker loop
// ---------------------------------------------------------------------------------------

/// Go returns at once when `-snmplog` is unset or `-snmpperiod` is not positive.
#[tokio::test(start_paused = true)]
async fn test_snmp_logger_is_a_noop_when_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snmp.log");
    let path = path.to_str().unwrap().to_string();

    snmp_logger(String::new(), 60).await;
    snmp_logger(path.clone(), 0).await;
    snmp_logger(path.clone(), -1).await;

    assert!(!std::path::Path::new(&path).exists());
}

/// One record per period, starting one period in (Go's ticker, not tokio's immediate first tick).
///
/// The real `std.SnmpLogger(path, 1)` was run for 2.5 s against the pinned Go sources and wrote a
/// header plus **two** rows, which is what this port does for the same 2.5 s, see
/// `test_snmp_logger_reports_errors_and_continues`, which counts two attempts over the same span.
#[tokio::test(start_paused = true)]
async fn test_snmp_logger_writes_one_record_per_period() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snmp.log");
    let logger = tokio::spawn(snmp_logger(path.to_str().unwrap().to_string(), 1));

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!path.exists(), "nothing is written before the first tick");

    tokio::time::sleep(Duration::from_millis(3_000)).await;
    logger.abort();

    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.lines().count(), 4, "header plus three rows: {text}");
    assert!(text.starts_with("Unix,BytesSent,"));
}

/// A failing write is reported once per period and the loop keeps going.
///
/// The logger is process-wide, so the lock is taken around the whole runtime rather than across
/// an `await`.
#[test]
fn test_snmp_logger_reports_errors_and_continues() {
    let _guard = log::TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let sink = Capture::new();
    log::set_output(Box::new(sink.clone()));

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nowhere").join("snmp.log");
    let path = path.to_str().unwrap().to_string();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap();
    runtime.block_on(async {
        let logger = tokio::spawn(snmp_logger(path.clone(), 1));
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        logger.abort();
    });
    log::set_output_stderr();

    let text = sink.text();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "one line per period: {text}");
    for line in lines {
        assert!(
            line.ends_with(&format!(
                "snmp logger: open {path}: no such file or directory"
            )),
            "{line}"
        );
    }
}

/// A log sink the test can read back (the logger is process-wide, hence [`log::TEST_LOCK`]).
#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    fn new() -> Capture {
        Capture(Arc::new(Mutex::new(Vec::new())))
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
