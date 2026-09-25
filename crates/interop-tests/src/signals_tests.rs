//! Unit tests for [`crate::signals`]: the parsers, on output captured from the **Go** binaries.
//!
//! These need no binary and no network, so they run in the ordinary gate and keep the parsers
//! honest even when `tests/signals.rs` is not run.

use super::*;

/// A `SIGUSR1` line of `reference/bin/client_darwin_arm64`, copied verbatim (2026-09-23; an idle
/// client, so every counter is zero).
const GO_SIGUSR1_LINE: &str = "2026/09/23 12:28:51 signal.go:56: KCP SNMP:&{BytesSent:0 \
    BytesReceived:0 MaxConn:0 ActiveOpens:0 PassiveOpens:0 CurrEstab:0 InErrs:0 InCsumErrors:0 \
    KCPInErrors:0 InPkts:0 OutPkts:0 InSegs:0 OutSegs:0 InBytes:0 OutBytes:0 RetransSegs:0 \
    FastRetransSegs:0 EarlyRetransSegs:0 LostSegs:0 RepeatSegs:0 FECFullShardSet:0 \
    FECRecovered:0 FECErrs:0 FECParityShards:0 FECShardSet:0 FECShardMin:0 RingBufferSndQueue:0 \
    RingBufferRcvQueue:0 RingBufferSndBuffer:0 OOBPackets:0}";

/// The `-snmplog` file `reference/bin/client_darwin_arm64` wrote with `-snmpperiod 1`, copied
/// verbatim (2026-09-23).
const GO_SNMP_CSV: &str = "\
Unix,BytesSent,BytesReceived,MaxConn,ActiveOpens,PassiveOpens,CurrEstab,InErrs,InCsumErrors,\
KCPInErrors,InPkts,OutPkts,InSegs,OutSegs,InBytes,OutBytes,RetransSegs,FastRetransSegs,\
EarlyRetransSegs,LostSegs,RepeatSegs,FECFullShards,FECParityShards,FECErrs,FECRecovered,\
FECShardSet,FECShardMin,RingBufferSndQueue,RingBufferRcvQueue,RingBufferSndBuffer,OOBPackets
1790162929,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
1790162930,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
1790162931,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
";

/// The unix second of the last row of [`GO_SNMP_CSV`], so `problems` sees it as a fresh file.
const GO_SNMP_CSV_NOW: u64 = 1_790_162_931;

// ---------------------------------------------------------------------------------------
// The SIGUSR1 line
// ---------------------------------------------------------------------------------------

#[test]
fn test_go_sigusr1_line_is_all_thirty_counters_in_struct_order() {
    let snapshot = Snapshot::parse(GO_SIGUSR1_LINE).expect("Go's own line parses");
    assert_eq!(snapshot.fields.len(), SNMP_FIELDS);
    snapshot.check_go_shape().expect("Go's own field order");
    assert!(snapshot.raw.starts_with("&{BytesSent:0 "));
    assert!(snapshot.raw.ends_with(" OOBPackets:0}"));
    assert_eq!(snapshot.get("FECShardMin"), Some(0));
    assert_eq!(snapshot.get("NoSuchCounter"), None);
    assert_eq!(snapshot.nonzero(), Vec::new());
}

/// Our own `SnmpSnapshot` renders the same line, which is what the differential asserts live.
#[test]
fn test_our_display_round_trips_through_the_parser() {
    let snapshot = SnmpSnapshot {
        bytes_sent: 4096,
        out_pkts: 7,
        ..Default::default()
    };
    let parsed = Snapshot::parse(&format!("{SNMP_MARKER}{snapshot}")).expect("our own line");
    parsed.check_go_shape().expect("our own field order");
    assert_eq!(parsed.get("BytesSent"), Some(4096));
    assert_eq!(parsed.nonzero(), [("BytesSent", 4096), ("OutPkts", 7)]);
    assert_eq!(parsed.raw, format!("{snapshot}"));
}

#[test]
fn test_field_order_is_checked_not_just_the_names() {
    let mut snapshot = Snapshot::parse(GO_SIGUSR1_LINE).expect("parses");
    snapshot.fields.swap(0, 1);
    let err = snapshot.check_go_shape().expect_err("swapped fields");
    assert!(err.contains("wanted Go's"), "{err}");

    let mut short = Snapshot::parse(GO_SIGUSR1_LINE).expect("parses");
    short.fields.pop();
    short.check_go_shape().expect_err("29 fields");
}

#[test]
fn test_malformed_lines_are_rejected() {
    for line in [
        "",
        "KCP SNMP:",
        "KCP SNMP:{BytesSent:0}",
        "KCP SNMP:&{BytesSent:0",
        "KCP SNMP:&{BytesSent}",
        "KCP SNMP:&{BytesSent:-1}",
        // The half-written line a log can end with while the process keeps appending.
        "2026/09/23 12:28:51 signal.go:56: KCP SNMP:&{BytesSent:0 BytesRec",
    ] {
        assert!(Snapshot::parse(line).is_err(), "{line:?} must not parse");
    }
}

#[test]
fn test_snapshots_takes_every_complete_line_in_order() {
    let one = SnmpSnapshot {
        bytes_sent: 1,
        ..Default::default()
    };
    let two = SnmpSnapshot {
        bytes_sent: 2,
        ..Default::default()
    };
    let log = format!(
        "listening on: 127.0.0.1:1\n\
         2026/09/23 12:28:51 signal.go:56: {SNMP_MARKER}{one}\n\
         2026/09/23 12:28:52 signal.rs:94: {SNMP_MARKER}{two}\n\
         2026/09/23 12:28:53 signal.rs:94: {SNMP_MARKER}&{{BytesSent:3 Bytes"
    );
    let found = snapshots(&log);
    assert_eq!(found.len(), 2, "the half-written last line is skipped");
    assert_eq!(found[0].get("BytesSent"), Some(1));
    assert_eq!(found[1].get("BytesSent"), Some(2));
}

// ---------------------------------------------------------------------------------------
// The -snmplog file
// ---------------------------------------------------------------------------------------

#[test]
fn test_go_snmp_csv_has_the_expected_shape() {
    let csv = SnmpCsv::parse("snmp-20260923.log", GO_SNMP_CSV).expect("Go's own file parses");
    assert_eq!(csv.header, expected_header());
    assert_eq!(csv.header.len(), SNMP_FIELDS + 1);
    assert_eq!(csv.rows.len(), 3);
    assert_eq!(
        csv.timestamps().unwrap(),
        [1_790_162_929, 1_790_162_930, GO_SNMP_CSV_NOW]
    );
    assert!(csv.counters().iter().all(|c| c.len() == SNMP_FIELDS));
    assert!(csv.counters().iter().all(|c| c.iter().all(|v| v == "0")));
    assert_eq!(csv.problems(GO_SNMP_CSV_NOW, 3), Vec::<String>::new());
}

/// The header is `Unix` plus `kcp.DefaultSnmp.Header()`, whose `FECFullShards` and FEC ordering
/// differ from the struct order of the `SIGUSR1` line: both orders are pinned here.
#[test]
fn test_expected_header_is_gos_header_not_the_struct_order() {
    let header = expected_header();
    assert_eq!(header[0], "Unix");
    assert_eq!(header[1..], DEFAULT_SNMP.header()[..]);
    assert_eq!(header[21], "FECFullShards");
    assert_eq!(
        &header[22..25],
        ["FECParityShards", "FECErrs", "FECRecovered"]
    );
    // The struct order the SIGUSR1 line uses is the other one.
    assert_eq!(
        &SnmpSnapshot::FIELD_NAMES[20..24],
        [
            "FECFullShardSet",
            "FECRecovered",
            "FECErrs",
            "FECParityShards"
        ]
    );
}

#[test]
fn test_csv_problems_name_every_deviation() {
    let good = SnmpCsv::parse("snmp-20260923.log", GO_SNMP_CSV).expect("parses");

    let mut wrong_name = good.clone();
    wrong_name.name = "snmp-20060102.log.log".to_string();
    assert_eq!(wrong_name.problems(GO_SNMP_CSV_NOW, 1).len(), 1);

    let mut wrong_header = good.clone();
    wrong_header.header[1] = "BytesSend".to_string();
    assert!(
        wrong_header.problems(GO_SNMP_CSV_NOW, 1)[0].contains("header"),
        "{:?}",
        wrong_header.problems(GO_SNMP_CSV_NOW, 1)
    );

    let mut short_row = good.clone();
    short_row.rows[1].pop();
    assert!(short_row.problems(GO_SNMP_CSV_NOW, 1)[0].contains("row 2"));

    let mut not_a_number = good.clone();
    not_a_number.rows[0][5] = "n/a".to_string();
    assert!(not_a_number.problems(GO_SNMP_CSV_NOW, 1)[0].contains("\"n/a\""));

    let mut backwards = good.clone();
    backwards.rows.reverse();
    assert!(
        backwards
            .problems(GO_SNMP_CSV_NOW, 1)
            .iter()
            .any(|p| p.contains("backwards"))
    );

    let stale = good.clone();
    assert_eq!(
        stale.problems(GO_SNMP_CSV_NOW + 3600, 1).len(),
        3,
        "one per row"
    );

    assert!(
        good.problems(GO_SNMP_CSV_NOW, 4)[0].contains("3 row(s), wanted at least 4"),
        "too few rows is a problem"
    );
}

#[test]
fn test_empty_file_is_an_error_not_a_panic() {
    assert!(SnmpCsv::parse("snmp-20260923.log", "").is_err());
    let header_only = SnmpCsv::parse(
        "snmp-20260923.log",
        &format!("{}\n", GO_SNMP_CSV.lines().next().unwrap()),
    )
    .expect("a file with a header and no row yet");
    assert!(header_only.rows.is_empty());
    assert_eq!(header_only.timestamps().unwrap(), Vec::<u64>::new());
}

#[test]
fn test_dated_snmp_names() {
    assert!(is_dated_snmp_name("snmp-20260923.log"));
    // The layout itself passes, and must: `20060102` is Go's reference date, so a name that was
    // never formatted is shaped exactly like one that was. The live tests tell them apart by
    // comparing Go's file name with ours.
    assert!(is_dated_snmp_name(SNMP_LOG_LAYOUT));
    for name in [
        "snmp-2026092.log",   // seven digits
        "snmp-202609233.log", // nine
        "snmp-.log",
        "snmp-20260923.txt",
        "out.log",
    ] {
        assert!(!is_dated_snmp_name(name), "{name:?} must not pass");
    }
}

#[test]
fn test_now_unix_is_now() {
    // Sanity, not precision: the clock is past 2020 and not in the far future.
    let now = now_unix();
    assert!((1_577_836_800..4_102_444_800).contains(&now), "{now}");
}
