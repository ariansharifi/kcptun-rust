//! smux interoperability with the Go reference (plan step 06.5).
//!
//! Both directions over TCP loopback, with `tools/gointerop/cmd/smuxecho` (pinned smux
//! v1.5.55) as the Go peer:
//!
//! | Test | Go side | Rust side |
//! |---|---|---|
//! | `interop_smux_rust_client_go_server` | `smuxecho server` | `run_rust_client` |
//! | `interop_smux_go_client_rust_server` | `smuxecho client` | [`RustEchoServer`] |
//! | `interop_smux_v11_early_close_write_rust_client_go_server` | `smuxecho server` | half-closing client |
//!
//! The matrix is the plan's: protocol version 1 and 2, `-framesize` 1024 / 8192 / 65535,
//! `-streambuf` 64 KiB / 2 MiB, 1 and 256 streams, every transfer verified by SHA-256 of the
//! deterministic stream both implementations produce.
//!
//! Needs the Go binaries (`tools/fetch-reference.sh`), hence `#[ignore]`:
//!
//! ```sh
//! cargo test -p kcptun-interop-tests --test smux -- --ignored --nocapture
//! ```

use std::time::Instant;

use kcptun_interop_tests::go_bin;
use kcptun_interop_tests::smuxecho::{
    ClientRun, CloseWriteOrder, RustEchoServer, SmuxSettings, run_go_client, run_rust_client,
    start_go_server,
};
use kcptun_testkit::ports;

/// Bytes per stream, by stream count: one big transfer, or many small ones.
fn bytes_for(streams: usize) -> u64 {
    if streams == 1 { 1 << 20 } else { 32 << 10 }
}

/// The plan's matrix: version × frame size × stream buffer × stream count.
fn matrix() -> Vec<(SmuxSettings, usize)> {
    let mut cases = Vec::new();
    for version in [1, 2] {
        for framesize in [1024, 8192, 65535] {
            for streambuf in [64 * 1024, 2 * 1024 * 1024] {
                for streams in [1, 256] {
                    cases.push((
                        SmuxSettings::default()
                            .version(version)
                            .framesize(framesize)
                            .streambuf(streambuf),
                        streams,
                    ));
                }
            }
        }
    }
    cases
}

/// A label for assertion messages.
fn label(s: &SmuxSettings, streams: usize) -> String {
    format!(
        "ver={} framesize={} streambuf={} streams={}",
        s.version, s.framesize, s.streambuf, streams
    )
}

/// A current-thread runtime is not enough: the Go peer and the Rust session run at the same
/// time and 256 streams keep several tasks busy.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime")
}

/// A Rust smux client against the Go `smuxecho` server, over the whole matrix.
#[test]
#[ignore = "needs reference/bin (tools/fetch-reference.sh)"]
fn interop_smux_rust_client_go_server() {
    let bin = go_bin("smuxecho").unwrap_or_else(|e| panic!("{e}"));
    let rt = runtime();

    for (i, (settings, streams)) in matrix().into_iter().enumerate() {
        let what = label(&settings, streams);
        let listen = ports::allocate(1).addr(0);
        let (_server, printed) = start_go_server(&bin, listen, &settings)
            .unwrap_or_else(|e| panic!("[{what}] go server: {e}"));
        assert_eq!(printed, listen.to_string(), "[{what}] server address");

        let bytes = bytes_for(streams);
        let run = ClientRun::new(listen, streams, bytes).seed(1000 + i as u64 * 1000);
        let started = Instant::now();
        // kcptun's `std.Pipe` order: half-close as soon as everything has been sent. The Go
        // peer is the writer here, so its own half-close bug is not in play; the Rust client
        // is the reader that must keep its buffered data (deviation V11).
        let results = rt
            .block_on(run_rust_client(&run, &settings, CloseWriteOrder::Early))
            .unwrap_or_else(|e| panic!("[{what}] rust client: {e}"));

        assert_eq!(results.len(), streams, "[{what}]");
        for r in &results {
            assert!(
                r.ok,
                "[{what}] stream {} (id {}): {:?}, received {} of {bytes}",
                r.index, r.id, r.error, r.received
            );
            assert_eq!(r.received, bytes, "[{what}] stream {}", r.index);
            assert_eq!(
                r.sha256, r.expected_sha256,
                "[{what}] stream {} echo hash",
                r.index
            );
        }
        eprintln!(
            "ok [{what}] {} bytes in {} ms",
            bytes * streams as u64,
            started.elapsed().as_millis()
        );
    }
}

/// Go's own end-of-stream race: after the Go client's `CloseWrite`, the peer's FIN closes both
/// `chFinEvent` and `die`, and `waitRead`'s `select` picks between them at random, so a Go
/// reader that happens to be blocked reports this instead of `io.EOF` for a stream that ended
/// normally. Reproduced Go↔Go with `smuxecho` alone (2 of 5 runs with 256 streams), so it is
/// accepted here as long as every byte arrived and the hash matches. The Rust port answers in
/// a fixed order and always ends in EOF.
const GO_FIN_RACE: &str = "read: io: read/write on closed pipe";

/// The Go `smuxecho` client against a Rust smux echo server, over the whole matrix.
///
/// The Go client half-closes only after the whole echo has arrived (its default), because the
/// other order runs into Go's own data-loss bug on the Go *reader*, which is what deviation
/// V11 fixes on the Rust side and cannot be fixed from here.
#[test]
#[ignore = "needs reference/bin (tools/fetch-reference.sh)"]
fn interop_smux_go_client_rust_server() {
    let bin = go_bin("smuxecho").unwrap_or_else(|e| panic!("{e}"));
    let rt = runtime();

    for (i, (settings, streams)) in matrix().into_iter().enumerate() {
        let what = label(&settings, streams);
        let listen = ports::allocate(1).addr(0);
        let server = rt
            .block_on(RustEchoServer::start(listen, &settings))
            .unwrap_or_else(|e| panic!("[{what}] rust server: {e}"));
        assert_eq!(server.addr(), listen, "[{what}] server address");

        let bytes = bytes_for(streams);
        let run = ClientRun::new(listen, streams, bytes).seed(9000 + i as u64 * 1000);
        let started = Instant::now();
        let out = run_go_client(&bin, &run, &settings, Vec::<String>::new())
            .unwrap_or_else(|e| panic!("[{what}] go client: {e}"));
        let report = out
            .report
            .as_ref()
            .unwrap_or_else(|| panic!("[{what}] no JSON report; client log:\n{}", out.log));
        assert_eq!(
            report.error, None,
            "[{what}] run failed; client log:\n{}",
            out.log
        );
        assert_eq!(report.streams, streams as i64, "[{what}]");
        assert_eq!(report.results.len(), streams, "[{what}]");
        let mut go_fin_races = 0;
        for r in &report.results {
            if !r.ok && r.error.as_deref() == Some(GO_FIN_RACE) && r.received == bytes as i64 {
                go_fin_races += 1;
            } else {
                assert!(
                    r.ok && r.received == bytes as i64,
                    "[{what}] stream {}: {:?}, received {} of {bytes}",
                    r.index,
                    r.error,
                    r.received
                );
            }
            // The Go client verified the bytes; the hash pins the same stream on both sides.
            let expected = kcptun_testkit::servers::PrngStream::sha256_hex(r.seed, bytes);
            assert_eq!(r.sha256, expected, "[{what}] stream {} echo hash", r.index);
        }
        if go_fin_races > 0 {
            eprintln!(
                "note [{what}] {go_fin_races} of {streams} Go streams hit Go's own \
                 EOF/ErrClosedPipe race after their CloseWrite (all bytes arrived)"
            );
        } else {
            assert_eq!(out.exit_code, Some(0), "[{what}] client log:\n{}", out.log);
        }
        assert_eq!(server.connections(), 1, "[{what}] connections accepted");
        eprintln!(
            "ok [{what}] {} bytes in {} ms",
            bytes * streams as u64,
            started.elapsed().as_millis()
        );
    }
}

/// Deviation **V11** against the real Go peer: the Rust client sends, half-closes straight
/// away (kcptun's `std.Pipe` order), and the Go `smuxecho` server echoes and then FINs. The
/// FIN reaches a Rust stream that has already closed its write side and still holds unread
/// data: the state where smux v1.5.55 discards it. Every byte must arrive.
///
/// Direction: this proves the **Rust** reader keeps the data while the **Go** peer behaves
/// exactly as it does in production. The mirror image (a Go client with `-early-closewrite`
/// against a Rust server) exercises the bug inside Go and is therefore not asserted here; see
/// `tools/gointerop/README.md`.
#[test]
#[ignore = "needs reference/bin (tools/fetch-reference.sh)"]
fn interop_smux_v11_early_close_write_rust_client_go_server() {
    let bin = go_bin("smuxecho").unwrap_or_else(|e| panic!("{e}"));
    let rt = runtime();

    // The sizes of the original reproduction (`smuxecho client -early-closewrite -streams 8
    // -bytes 3000000`), with kcptun's own smux settings.
    const STREAMS: usize = 8;
    const BYTES: u64 = 3_000_000;

    for version in [1, 2] {
        let settings = SmuxSettings::default().version(version);
        let what = format!("v11 ver={version}");
        let listen = ports::allocate(1).addr(0);
        let (_server, printed) = start_go_server(&bin, listen, &settings)
            .unwrap_or_else(|e| panic!("[{what}] go server: {e}"));
        assert_eq!(printed, listen.to_string(), "[{what}] server address");

        let run = ClientRun::new(listen, STREAMS, BYTES).seed(4200 + version as u64);
        let results = rt
            .block_on(run_rust_client(&run, &settings, CloseWriteOrder::Early))
            .unwrap_or_else(|e| panic!("[{what}] rust client: {e}"));

        let mut buffered_total = 0usize;
        for r in &results {
            assert!(
                r.ok,
                "[{what}] stream {} truncated: {:?}, received {} of {BYTES}",
                r.index, r.error, r.received
            );
            assert_eq!(r.received, BYTES, "[{what}] stream {}", r.index);
            assert_eq!(r.sha256, r.expected_sha256, "[{what}] stream {}", r.index);
            buffered_total += r.buffered_at_fin;
        }
        // Without unread data at the moment the FIN arrives the test would pass vacuously:
        // that buffer is exactly what smux v1.5.55 throws away.
        assert!(
            buffered_total > 0,
            "[{what}] no stream had unread data when the Go peer's FIN arrived; \
             the V11 state was not exercised"
        );
        eprintln!(
            "ok [{what}] {} streams × {BYTES} bytes, {buffered_total} bytes were still \
             buffered when the Go peer's FIN arrived (smux v1.5.55 would have dropped them)",
            results.len()
        );
    }
}
