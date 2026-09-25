//! Regression test for deviation **V11** (plan step 06.5, `docs/DECISIONS.md`).
//!
//! In smux v1.5.55 (and current upstream) a stream that has called `CloseWrite` is torn down as
//! soon as the peer's FIN arrives: `fin()` → `tryHalfCloseCleanup` → `sess.streamClosed` →
//! `recycleTokens`, which **drops every received byte that has not been read yet**, so the
//! reader sees EOF early. kcptun's `std.Pipe` half-closes in exactly that order
//! (`copy; CloseWrite; Close`), which is why a Go tunnel can truncate the response to a client
//! that shut its write side down early.
//!
//! The port removes the stream from the session map and releases its writers, but keeps the
//! buffered data readable until it has been drained. These tests pin that down: the client
//! sends, calls [`Stream::close_write`](kcptun_smux::stream::Stream::close_write) straight away
//! (the `Pipe` order), the peer echoes and then FINs, and **every byte must still arrive**.
//!
//! The wait for the peer's FIN before the first read is what makes the race deterministic: at
//! that moment the whole echo is buffered and unread, which is precisely the state Go discards.
//!
//! The Go peer has the same bug when *it* is the reader, so the matching interop test
//! (`crates/interop-tests/tests/smux.rs`) can only run in the direction where **Rust** is the
//! half-closing reader: Rust client ↔ Go `smuxecho` server.
//!
//! Reproduction of the Go behaviour: `smuxecho client -early-closewrite -streams 8
//! -bytes 3000000` (see `tools/gointerop/README.md`).

mod harness;

use std::sync::Arc;

use harness::{PATIENCE, in_time, payload, wait_until};
use kcptun_smux::conn::SmuxConn;
use kcptun_smux::mux::{Config, default_config};
use kcptun_smux::session::Session;
use kcptun_smux::stream::Stream;

/// Streams opened in parallel, as in the `smuxecho` reproduction.
const STREAMS: usize = 8;

/// Bytes per stream. Small enough that all `STREAMS` echoes fit in the session's token bucket
/// and in one stream's version-2 window, so the peer can finish and send its FIN while nothing
/// has been read yet: the state V11 is about.
const BYTES: usize = 128 * 1024;

/// kcptun's own smux settings (`-smuxbuf 4194304 -streambuf 2097152 -framesize 8192`), which is
/// the configuration the bug was found with.
fn kcptun_config(version: isize) -> Config {
    Config {
        version,
        max_receive_buffer: 4 * 1024 * 1024,
        max_stream_buffer: 2 * 1024 * 1024,
        max_frame_size: 8192,
        ..default_config()
    }
}

/// kcptun's `std.Pipe` half-close order on the echoing side: copy until the peer's FIN, then
/// `CloseWrite`, then `Close`.
// Go: kcptun std/copy.go:Pipe, mirrored by tools/gointerop/cmd/smuxecho:echoStream
async fn pipe_echo(stream: Stream) {
    let mut buf = vec![0u8; 65536];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if stream.write(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = stream.close_write().await;
    let _ = stream.close().await;
}

/// Sends `BYTES`, half-closes immediately (the `Pipe` order), waits for the peer's FIN and only
/// then reads: every byte must still be there, followed by the end of the stream.
async fn send_half_close_and_drain(stream: Stream, seed: u64) {
    let data = payload(seed, BYTES);
    let stream = Arc::new(stream);

    let writer = {
        let stream = Arc::clone(&stream);
        let data = data.clone();
        tokio::spawn(async move {
            stream.write(&data).await.expect("write");
            // kcptun's Pipe order: half-close as soon as everything has been sent, without
            // waiting for the response.
            stream.close_write().await.expect("close_write");
        })
    };
    in_time("writer", writer).await.expect("join");

    // The peer's FIN arrives while the whole echo is buffered and unread. This is where Go
    // throws the data away.
    wait_until("peer FIN", || stream.got_fin()).await;
    assert_eq!(
        stream.buffered_len(),
        BYTES,
        "the whole echo should be buffered and unread when the FIN arrives"
    );

    let mut got = Vec::with_capacity(BYTES);
    let mut buf = vec![0u8; 65536];
    loop {
        let n = in_time("read", stream.read(&mut buf))
            .await
            .expect("read after half-close");
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got.len(), BYTES, "echo truncated after half-close");
    assert_eq!(got, data, "echo corrupted after half-close");
}

/// Rust↔Rust: the client half-closes early, the Rust peer echoes with kcptun's `Pipe` order.
/// This is the direction the Go peer gets wrong.
#[tokio::test]
async fn v11_early_close_write_keeps_the_whole_echo() {
    async fn body<C: SmuxConn>(cli: Session<C>, srv: Session<C>) {
        // The peer: an accept loop with kcptun's Pipe echo.
        tokio::spawn(async move {
            loop {
                let Ok(stream) = srv.accept_stream().await else {
                    return;
                };
                tokio::spawn(pipe_echo(stream));
            }
        });

        let mut tasks = Vec::with_capacity(STREAMS);
        for i in 0..STREAMS {
            let stream = cli.open_stream().await.expect("open");
            tasks.push(tokio::spawn(send_half_close_and_drain(
                stream,
                0x5eed_0011 + i as u64,
            )));
        }
        for t in tasks {
            in_time("stream", t).await.expect("join");
        }

        // Both sides half-closed, so the streams are gone from the map (Go's
        // tryHalfCloseCleanup) even though their data was delivered in full.
        wait_until("streams cleaned up", || cli.num_streams() == 0).await;
        cli.close().await.expect("close");
    }

    for version in [1, 2] {
        both_transports!(kcptun_config(version), body);
    }
}

/// The same race with the roles swapped: the *accepted* (server-side) stream half-closes early
/// and the opening side echoes. The fix must not depend on which end opened the stream.
#[tokio::test]
async fn v11_early_close_write_on_an_accepted_stream() {
    async fn body<C: SmuxConn>(cli: Session<C>, srv: Session<C>) {
        tokio::spawn(async move {
            loop {
                let Ok(stream) = cli.accept_stream().await else {
                    return;
                };
                tokio::spawn(pipe_echo(stream));
            }
        });

        let mut tasks = Vec::with_capacity(STREAMS);
        for i in 0..STREAMS {
            let stream = srv.open_stream().await.expect("open");
            tasks.push(tokio::spawn(send_half_close_and_drain(
                stream,
                0x5eed_0012 + i as u64,
            )));
        }
        for t in tasks {
            in_time("stream", t).await.expect("join");
        }
        srv.close().await.expect("close");
    }

    for version in [1, 2] {
        both_transports!(kcptun_config(version), body);
    }
}

/// A sanity check on the constants: [`PATIENCE`] must outlast the transfers above.
#[test]
fn patience_is_long_enough() {
    assert!(PATIENCE.as_secs() >= 5);
}
