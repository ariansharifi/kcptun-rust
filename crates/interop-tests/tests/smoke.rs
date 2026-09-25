//! Harness smoke test: the Go `kcpecho` peer talks to itself (Go↔Go) through the runner, which
//! proves binary resolution, process spawning, port allocation and report parsing work before
//! any Rust protocol code exists. Needs `reference/bin` (`tools/fetch-reference.sh`), hence
//! `#[ignore]`:
//!
//! ```sh
//! cargo test -p kcptun-interop-tests -- --ignored
//! ```

use kcptun_interop_tests::kcpecho::{self, ClientRun};
use kcptun_interop_tests::{Case, go_bin};
use kcptun_testkit::ports;
use kcptun_testkit::servers::PrngStream;

/// Bytes echoed per case: enough for many KCP windows and FEC groups, still well under a
/// second on loopback.
const BYTES: u64 = 2 * 1024 * 1024;

fn smoke_cases() -> Vec<Case> {
    vec![
        // kcptun's defaults: AES with FEC 10/3, mode fast.
        Case::new(),
        // `none`: nonce+CRC32 header with no cipher (NoneBlockCrypt), no FEC, mode fast3.
        Case::new().crypt("none").fec(0, 0).mode("fast3"),
        // `null`: no BlockCrypt at all, so no nonce/CRC header (plain KCP), no FEC.
        Case::new().crypt("null").fec(0, 0),
        // Stream cipher with a small FEC group, mode normal, smaller MTU.
        Case::new()
            .crypt("salsa20")
            .fec(3, 2)
            .mode("normal")
            .mtu(1200),
        // AEAD cipher without FEC.
        Case::new().crypt("aes-128-gcm").fec(0, 0),
    ]
}

#[test]
#[ignore = "needs reference/bin (tools/fetch-reference.sh)"]
fn interop_go_go_kcpecho_smoke() {
    let bin = go_bin("kcpecho").unwrap_or_else(|e| panic!("{e}"));
    for (i, case) in smoke_cases().into_iter().enumerate() {
        let seed = 100 + i as u64;
        let listen = ports::allocate(1).addr(0);
        let args = case.kcpecho_args();
        let (_server, printed) = kcpecho::start_server(&bin, listen, &args)
            .unwrap_or_else(|e| panic!("[{case}] server: {e}"));
        assert_eq!(printed, listen.to_string(), "[{case}] server address");

        let run = ClientRun::new(listen, BYTES).seed(seed).timeout_secs(60);
        let out = kcpecho::run_client(&bin, &run, &args)
            .unwrap_or_else(|e| panic!("[{case}] client: {e}"));
        let report = out
            .report
            .as_ref()
            .unwrap_or_else(|| panic!("[{case}] no JSON report; client log:\n{}", out.log));
        assert!(
            report.ok && out.exit_code == Some(0),
            "[{case}] exit {:?}, report {report:?}; client log:\n{}",
            out.exit_code,
            out.log
        );
        assert_eq!(report.bytes, BYTES as i64, "[{case}]");
        assert_eq!(report.received, BYTES as i64, "[{case}]");
        assert_eq!(report.mismatch_offset, -1, "[{case}]");
        assert_eq!(report.error, None, "[{case}]");
        assert_eq!(report.crypt, case.crypt, "[{case}] effective cipher");
        // The Go stream and testkit's PrngStream are the same bytes.
        let expected = PrngStream::sha256_hex(seed, BYTES);
        assert_eq!(report.expected_sha256, expected, "[{case}] stream hash");
        assert_eq!(report.sha256, expected, "[{case}] echo hash");
        assert!(
            report.snmp_counter("BytesSent").unwrap_or(0) >= BYTES,
            "[{case}] snmp {:?}",
            report.snmp
        );
        eprintln!("ok [{case}] {} ms", report.duration_ms);
    }
}

#[test]
#[ignore = "needs reference/bin (tools/fetch-reference.sh)"]
fn interop_go_bin_resolution() {
    // Every Go program the later interop steps rely on is present.
    for name in [
        "client",
        "server",
        "kcpecho",
        "smuxecho",
        "snappycheck",
        "qppcheck",
    ] {
        let p = go_bin(name).unwrap_or_else(|e| panic!("{e}"));
        assert!(p.is_file(), "{}", p.display());
    }
}
