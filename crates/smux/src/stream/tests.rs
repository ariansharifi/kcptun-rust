//! Tests of the stream, ported from `reference/latest/smux/stream_test.go` and
//! `session_test.go` where a Go test exists, plus cases that pin down what the port has to do
//! and Go never checks: the exact `cmdUPD` frames version 2 emits, the order of `cmdPSH` and
//! `cmdFIN` on the wire, the token accounting of a closed stream, and deviation V11.
//!
//! Two kinds of fixture are used: a pair of real sessions over one [`tokio::io::duplex`] pipe
//! (`session_pair`), and a single session whose peer is hand-written (`Peer`), so that the
//! bytes it sends and receives are visible frame by frame.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use kcptun_testkit::rng::{Pcg, rand_bytes};
use tokio::io::DuplexStream;
use tokio::time::{Instant, sleep, timeout};

use super::*;
use crate::conn::{SmuxConn, SplitConn};
use crate::frame::{CMD_FIN, CMD_PSH, CMD_SYN, CMD_UPD, HEADER_SIZE, RawHeader, UpdHeader};
use crate::mux::{Config, client, default_config, server};
use crate::session::Session;

/// Enough room that a test peer never blocks a session's send task unless it means to.
const PIPE_CAPACITY: usize = 1 << 20;

/// How long a test waits for something that should happen immediately.
const PATIENCE: Duration = Duration::from_secs(5);

/// A configuration with the keepalive off, so only the frames a test causes appear on the wire.
fn quiet_config(version: isize) -> Config {
    Config {
        version,
        keep_alive_disabled: true,
        ..default_config()
    }
}

/// Two sessions of the same configuration, talking to each other over one in-memory pipe.
fn session_pair(
    config: Config,
) -> (
    Session<SplitConn<DuplexStream>>,
    Session<SplitConn<DuplexStream>>,
) {
    let (ours, theirs) = tokio::io::duplex(PIPE_CAPACITY);
    let cli = client(SplitConn::new(ours), Some(config)).expect("client");
    let srv = server(SplitConn::new(theirs), Some(config)).expect("server");
    (cli, srv)
}

/// A session whose peer is driven with hand-built frames.
fn peered(config: Config) -> (Session<SplitConn<DuplexStream>>, Peer) {
    let (ours, theirs) = tokio::io::duplex(PIPE_CAPACITY);
    let session = server(SplitConn::new(ours), Some(config)).expect("server");
    (session, Peer::new(theirs))
}

/// The far end of the pipe, driven with hand-built frames.
struct Peer {
    conn: SplitConn<DuplexStream>,
}

impl Peer {
    fn new(stream: DuplexStream) -> Peer {
        Peer {
            conn: SplitConn::new(stream),
        }
    }

    /// Writes a well-formed frame.
    async fn write_frame(&self, ver: u8, cmd: u8, sid: u32, data: &[u8]) {
        let mut out = RawHeader::new(ver, cmd, data.len() as u16, sid)
            .as_bytes()
            .to_vec();
        out.extend_from_slice(data);
        self.conn.write_all(&out).await.expect("peer write");
    }

    async fn read_exact(&self, n: usize) -> io::Result<Vec<u8>> {
        let mut out = vec![0u8; n];
        let mut done = 0;
        while done < n {
            let got = self.conn.read(&mut out[done..]).await?;
            if got == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
            }
            done += got;
        }
        Ok(out)
    }

    /// Reads one frame: the header, then exactly the payload its length field announces.
    async fn read_frame(&self) -> (RawHeader, Vec<u8>) {
        let head = self.read_exact(HEADER_SIZE).await.expect("header");
        let header = RawHeader::from_bytes(&head).expect("full header");
        let payload = self
            .read_exact(usize::from(header.length()))
            .await
            .expect("payload");
        (header, payload)
    }

    /// Opens a stream from this side and returns the accepted one.
    async fn open(&self, session: &Session<SplitConn<DuplexStream>>, ver: u8, sid: u32) -> Stream {
        self.write_frame(ver, CMD_SYN, sid, &[]).await;
        timeout(PATIENCE, session.accept_stream())
            .await
            .expect("accept in time")
            .expect("accept")
    }
}

/// Polls `check` until it holds, so a test never sleeps longer than it must.
async fn wait_until(what: &str, mut check: impl FnMut() -> bool) {
    timeout(PATIENCE, async {
        while !check() {
            tokio::task::yield_now().await;
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

/// `n` deterministic pseudo-random bytes.
fn payload(seed: u64, n: usize) -> Vec<u8> {
    rand_bytes(&mut Pcg::new(0x5eed_5eed, seed), n)
}

/// Reads exactly `want` bytes, failing if the stream ends early.
async fn read_exact_from(stream: &Stream, want: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(want);
    let mut buf = vec![0u8; 4096];
    while out.len() < want {
        let n = stream.read(&mut buf).await.expect("read");
        assert_ne!(n, 0, "unexpected EOF after {} of {want} bytes", out.len());
        out.extend_from_slice(&buf[..n]);
    }
    out
}

/// Reads until EOF.
async fn read_to_end(stream: &Stream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await.expect("read");
        if n == 0 {
            return out;
        }
        out.extend_from_slice(&buf[..n]);
    }
}

// ---------------------------------------------------------------------------------------
// Read and write, end to end
// ---------------------------------------------------------------------------------------

/// Go: `TestEcho`, write, echo, read back, for both protocol versions.
// Go: reference/latest/smux/session_test.go:TestEcho
#[tokio::test]
async fn test_echo() {
    for version in [1, 2] {
        let (cli, srv) = session_pair(quiet_config(version));
        tokio::spawn(async move {
            let stream = srv.accept_stream().await.expect("accept");
            let mut buf = vec![0u8; 65536];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        if stream.write(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });

        let stream = cli.open_stream().await.expect("open");
        let sent = payload(version as u64, 200_000);
        stream.write(&sent).await.expect("write");
        let got = read_exact_from(&stream, sent.len()).await;
        assert_eq!(got, sent, "version {version}");
    }
}

/// A read buffer smaller than one frame is filled from the front of the receive buffer, frame
/// by frame, and never crosses a frame boundary (Go's `consumeFront` copies from one buffer).
// Go: reference/latest/smux/session_test.go:TestTinyReadBuffer
#[tokio::test]
async fn test_tiny_read_buffer() {
    let (session, peer) = peered(quiet_config(1));
    let stream = peer.open(&session, 1, 3).await;
    peer.write_frame(1, CMD_PSH, 3, b"hello").await;
    peer.write_frame(1, CMD_PSH, 3, b"world").await;

    let mut buf = [0u8; 3];
    let mut got = Vec::new();
    for _ in 0..4 {
        let n = timeout(PATIENCE, stream.read(&mut buf))
            .await
            .expect("read in time")
            .expect("read");
        assert!(n <= 3);
        got.extend_from_slice(&buf[..n]);
    }
    // 3 + 2 (rest of "hello") + 3 + 2 (rest of "world")
    assert_eq!(got, b"helloworld");
}

/// An empty buffer reads nothing and an empty slice writes nothing, exactly as Go returns
/// `(0, nil)` for both: the write check even precedes the closed-write check.
#[tokio::test]
async fn empty_buffers_are_no_ops() {
    let (session, peer) = peered(quiet_config(1));
    let stream = peer.open(&session, 1, 3).await;

    assert_eq!(stream.read(&mut []).await.expect("read"), 0);
    assert_eq!(stream.write(&[]).await.expect("write"), 0);
    stream.close_write().await.expect("close_write");
    assert_eq!(
        stream.write(&[]).await.expect("write"),
        0,
        "Go checks the empty input before the closed write side"
    );
    assert_eq!(stream.write(b"x").await, Err(Error::ClosedPipe));
}

/// A version-1 write splits into `MaxFrameSize` pieces and returns only once every one of them
/// has reached the connection.
// Go: smux@v1.5.55 stream.go:writeV1()
#[tokio::test]
async fn write_splits_into_frame_size_pieces() {
    let config = Config {
        max_frame_size: 1024,
        ..quiet_config(1)
    };
    let (session, peer) = peered(config);
    let stream = peer.open(&session, 1, 3).await;

    let sent = payload(7, 2600);
    let n = timeout(PATIENCE, stream.write(&sent))
        .await
        .expect("write in time")
        .expect("write");
    assert_eq!(n, sent.len());

    let mut got = Vec::new();
    for want in [1024usize, 1024, 552] {
        let (header, data) = peer.read_frame().await;
        assert_eq!(header.cmd(), CMD_PSH);
        assert_eq!(header.stream_id(), 3);
        assert_eq!(header.version(), 1);
        assert_eq!(data.len(), want);
        got.extend_from_slice(&data);
    }
    assert_eq!(got, sent);
}

/// `write_bytes` is `write` without the per-frame copy; the frames on the wire are the same.
#[tokio::test]
async fn write_bytes_produces_the_same_frames() {
    let config = Config {
        max_frame_size: 1024,
        ..quiet_config(1)
    };
    let (session, peer) = peered(config);
    let stream = peer.open(&session, 1, 3).await;

    let sent = Bytes::from(payload(8, 1500));
    let n = timeout(PATIENCE, stream.write_bytes(&sent))
        .await
        .expect("write in time")
        .expect("write");
    assert_eq!(n, sent.len());

    let mut got = Vec::new();
    for _ in 0..2 {
        let (header, data) = peer.read_frame().await;
        assert_eq!(header.cmd(), CMD_PSH);
        got.extend_from_slice(&data);
    }
    assert_eq!(got, sent);
}

// ---------------------------------------------------------------------------------------
// Version-2 flow control
// ---------------------------------------------------------------------------------------

/// Version 2 sends `cmdUPD` on the first read and again once half the stream buffer has been
/// consumed, carrying the running `numRead` and the configured window. Version 1 sends none.
// Go: smux@v1.5.55 stream.go:tryReadV2() / sendWindowUpdate()
#[tokio::test]
async fn v2_window_updates_follow_the_reader() {
    let config = Config {
        version: 2,
        max_stream_buffer: 4096,
        ..quiet_config(2)
    };
    let (session, peer) = peered(config);
    let stream = peer.open(&session, 2, 3).await;

    // First read: an update is due whatever its size.
    peer.write_frame(2, CMD_PSH, 3, &[1u8; 100]).await;
    assert_eq!(read_exact_from(&stream, 100).await.len(), 100);
    let (header, data) = peer.read_frame().await;
    assert_eq!(header.cmd(), CMD_UPD);
    assert_eq!(header.stream_id(), 3);
    assert_eq!(header.version(), 2);
    let upd = UpdHeader::from_bytes(&data).expect("upd payload");
    assert_eq!((upd.consumed(), upd.window()), (100, 4096));

    // Below half the buffer: no update.
    peer.write_frame(2, CMD_PSH, 3, &[2u8; 1000]).await;
    assert_eq!(read_exact_from(&stream, 1000).await.len(), 1000);

    // Crossing half the buffer (2048) sends the next one, with the running total.
    peer.write_frame(2, CMD_PSH, 3, &[3u8; 1100]).await;
    assert_eq!(read_exact_from(&stream, 1100).await.len(), 1100);
    let (header, data) = peer.read_frame().await;
    assert_eq!(header.cmd(), CMD_UPD);
    let upd = UpdHeader::from_bytes(&data).expect("upd payload");
    assert_eq!((upd.consumed(), upd.window()), (2200, 4096));
}

/// A version-1 stream never sends `cmdUPD`: the next frame the peer sees is the FIN.
#[tokio::test]
async fn v1_sends_no_window_update() {
    let (session, peer) = peered(quiet_config(1));
    let stream = peer.open(&session, 1, 3).await;

    peer.write_frame(1, CMD_PSH, 3, &[1u8; 100]).await;
    assert_eq!(read_exact_from(&stream, 100).await.len(), 100);
    stream.close_write().await.expect("close_write");

    let (header, _) = peer.read_frame().await;
    assert_eq!(header.cmd(), CMD_FIN);
}

/// The version-2 writer stops at the peer's window and resumes on `cmdUPD`.
// Go: reference/latest/smux/stream_internal_test.go:TestStreamUpdateNotifiesWriter (behaviour)
#[tokio::test]
async fn test_stream_update_notifies_writer() {
    let (session, peer) = peered(quiet_config(2));
    let stream = Arc::new(peer.open(&session, 2, 3).await);

    let total = 300_000usize;
    let sent = payload(11, total);
    let writer = {
        let stream = Arc::clone(&stream);
        let sent = sent.clone();
        tokio::spawn(async move { stream.write(&sent).await })
    };

    // The initial peer window is 262144, which is exactly 8 frames of 32768.
    let mut got = Vec::new();
    for _ in 0..8 {
        let (header, data) = peer.read_frame().await;
        assert_eq!(header.cmd(), CMD_PSH);
        got.extend_from_slice(&data);
    }
    assert_eq!(got.len(), INITIAL_PEER_WINDOW as usize);
    sleep(Duration::from_millis(50)).await;
    assert!(!writer.is_finished(), "the window must block the writer");

    // Acknowledge everything and advertise a 64 KiB window: the rest fits.
    peer.write_frame(
        2,
        CMD_UPD,
        3,
        UpdHeader::new(INITIAL_PEER_WINDOW, 65536).as_bytes(),
    )
    .await;

    while got.len() < total {
        let (header, data) = peer.read_frame().await;
        assert_eq!(header.cmd(), CMD_PSH);
        got.extend_from_slice(&data);
    }
    assert_eq!(got, sent);
    let n = timeout(PATIENCE, writer)
        .await
        .expect("write finishes")
        .expect("task")
        .expect("write");
    assert_eq!(n, total);
}

/// A peer that acknowledges more than it was ever sent is rejected with `ErrConsumed`.
// Go: smux@v1.5.55 stream.go:writeV2() (inflight < 0)
#[tokio::test]
async fn write_v2_rejects_an_over_consuming_peer() {
    let (session, peer) = peered(quiet_config(2));
    let stream = peer.open(&session, 2, 3).await;

    peer.write_frame(2, CMD_UPD, 3, UpdHeader::new(100, 65536).as_bytes())
        .await;
    wait_until("update observed", || stream.peer_state() == (100, 65536)).await;

    assert_eq!(stream.write(b"payload").await, Err(Error::Consumed));
}

/// A window whose high bit is set makes Go's `int32(peerWindow) - inflight` wrap into a large
/// positive window; the port must wrap identically instead of overflowing.
// Go: smux@v1.5.55 stream.go:writeV2() (MODULAR ARITHMETIC)
#[tokio::test]
async fn write_v2_wraps_a_window_with_the_high_bit_set() {
    let (session, peer) = peered(quiet_config(2));
    let stream = peer.open(&session, 2, 3).await;

    assert_eq!(stream.write(b"payload").await, Ok(7));
    let (header, data) = peer.read_frame().await;
    assert_eq!(header.cmd(), CMD_PSH);
    assert_eq!(&data[..], b"payload");

    // 0x8000_0000 narrows to int32::MIN, and `int32::MIN - 7` wraps to 0x7fff_fff9 > 0, so Go
    // keeps sending. A panic here would be reachable straight from the wire.
    peer.write_frame(2, CMD_UPD, 3, UpdHeader::new(0, 0x8000_0000).as_bytes())
        .await;
    wait_until("update observed", || {
        stream.peer_state() == (0, 0x8000_0000)
    })
    .await;

    assert_eq!(stream.write(b"more").await, Ok(4));
    let (header, data) = peer.read_frame().await;
    assert_eq!(header.cmd(), CMD_PSH);
    assert_eq!(&data[..], b"more");
}

// ---------------------------------------------------------------------------------------
// FIN, half-close and deviation V11
// ---------------------------------------------------------------------------------------

/// A FIN that arrives while data is still buffered must not cut the reader short: the data is
/// delivered first and EOF follows (smux issue #82).
// Go: smux@v1.5.55 stream.go:waitRead() (BUGFIX for issue #82)
#[tokio::test]
async fn fin_delivers_buffered_data_before_eof() {
    let (session, peer) = peered(quiet_config(1));
    let stream = peer.open(&session, 1, 3).await;

    peer.write_frame(1, CMD_PSH, 3, b"hello").await;
    peer.write_frame(1, CMD_FIN, 3, &[]).await;
    wait_until("fin observed", || stream.got_fin()).await;

    assert_eq!(read_to_end(&stream).await, b"hello");
}

/// `close_write` sends the FIN as a **data** frame, so it stays behind the stream's payload,
/// and reading keeps working afterwards. A second call reports `io.ErrClosedPipe`.
// Go: smux@v1.5.55 stream.go:CloseWrite()
#[tokio::test]
async fn close_write_sends_fin_after_the_data() {
    let config = Config {
        max_frame_size: 1024,
        ..quiet_config(1)
    };
    let (session, peer) = peered(config);
    let stream = peer.open(&session, 1, 3).await;

    stream.write(&[9u8; 2000]).await.expect("write");
    stream.close_write().await.expect("close_write");

    for want in [1024usize, 976] {
        let (header, data) = peer.read_frame().await;
        assert_eq!(header.cmd(), CMD_PSH);
        assert_eq!(data.len(), want);
    }
    let (header, _) = peer.read_frame().await;
    assert_eq!(header.cmd(), CMD_FIN);

    // The write side is gone, the read side is not.
    assert_eq!(stream.write(b"x").await, Err(Error::ClosedPipe));
    assert_eq!(stream.close_write().await, Err(Error::ClosedPipe));
    assert!(!stream.is_closed(), "the peer has not sent its own FIN");
    peer.write_frame(1, CMD_PSH, 3, b"late").await;
    assert_eq!(read_exact_from(&stream, 4).await, b"late");
}

/// Both FINs together end the stream: it leaves the session map and its readers see EOF.
// Go: smux@v1.5.55 stream.go:tryHalfCloseCleanup()
#[tokio::test]
async fn both_fins_close_the_stream() {
    let (session, peer) = peered(quiet_config(1));
    let stream = peer.open(&session, 1, 3).await;
    assert_eq!(session.num_streams(), 1);

    stream.close_write().await.expect("close_write");
    assert_eq!(session.num_streams(), 1);
    peer.write_frame(1, CMD_FIN, 3, &[]).await;

    wait_until("stream closed", || stream.is_closed()).await;
    assert_eq!(session.num_streams(), 0);
    assert_eq!(read_to_end(&stream).await, b"");
}

/// **Deviation V11.** Go's `tryHalfCloseCleanup` reaches `recycleTokens`, which throws away
/// everything received but not yet read, so a peer that half-closes early loses the answer.
/// Here the data stays readable until the reader has drained it.
#[tokio::test]
async fn v11_half_close_keeps_buffered_data() {
    for version in [1, 2] {
        let (session, peer) = peered(quiet_config(version));
        let ver = version as u8;
        let stream = peer.open(&session, ver, 3).await;

        // kcptun's Pipe order: half-close as soon as this side is done writing.
        stream.close_write().await.expect("close_write");
        let (header, _) = peer.read_frame().await;
        assert_eq!(header.cmd(), CMD_FIN);

        // The answer arrives, and only then the peer's FIN.
        let answer = payload(21 + version as u64, 5000);
        for chunk in answer.chunks(1000) {
            peer.write_frame(ver, CMD_PSH, 3, chunk).await;
        }
        peer.write_frame(ver, CMD_FIN, 3, &[]).await;

        wait_until("half-close cleanup", || stream.is_closed()).await;
        assert_eq!(session.num_streams(), 0, "the stream has left the map");

        // Go would have discarded all 5000 bytes here.
        assert_eq!(read_to_end(&stream).await, answer, "version {version}");
    }
}

/// The drain path must reach the same answer as `read`: `write_to` has no `die` short-circuit
/// of its own (Go's `writeTo` has none either), so only the fixed order in `wait_read` keeps a
/// half-closed stream from ending in `io.ErrClosedPipe` instead of its data.
#[tokio::test]
async fn v11_write_to_drains_a_half_closed_stream() {
    for version in [1, 2] {
        let (session, peer) = peered(quiet_config(version));
        let ver = version as u8;
        let stream = peer.open(&session, ver, 3).await;
        stream.close_write().await.expect("close_write");
        let (header, _) = peer.read_frame().await;
        assert_eq!(header.cmd(), CMD_FIN);

        let answer = payload(71 + version as u64, 5000);
        for chunk in answer.chunks(1000) {
            peer.write_frame(ver, CMD_PSH, 3, chunk).await;
        }
        peer.write_frame(ver, CMD_FIN, 3, &[]).await;
        wait_until("half-close cleanup", || stream.is_closed()).await;

        let mut sink: Vec<u8> = Vec::new();
        let n = timeout(PATIENCE, stream.write_to(&mut sink))
            .await
            .expect("write_to in time")
            .expect("write_to");
        assert_eq!(n, answer.len() as u64, "version {version}");
        assert_eq!(sink, answer);
    }
}

/// The same deviation for a reader that is already blocked when the cleanup runs: Go's
/// `waitRead` would pick `die` and report `io.ErrClosedPipe`.
#[tokio::test]
async fn v11_half_close_wakes_a_blocked_reader_with_the_data() {
    let (session, peer) = peered(quiet_config(1));
    let stream = Arc::new(peer.open(&session, 1, 3).await);
    stream.close_write().await.expect("close_write");
    let (header, _) = peer.read_frame().await;
    assert_eq!(header.cmd(), CMD_FIN);

    let reader = {
        let stream = Arc::clone(&stream);
        tokio::spawn(async move { read_to_end(&stream).await })
    };
    sleep(Duration::from_millis(20)).await;

    peer.write_frame(1, CMD_PSH, 3, b"answer").await;
    peer.write_frame(1, CMD_FIN, 3, &[]).await;

    let got = timeout(PATIENCE, reader)
        .await
        .expect("reader finishes")
        .expect("task");
    assert_eq!(got, b"answer");
}

/// The V11 regression the plan asks for, between two real sessions: the client half-closes as
/// soon as it is done writing (kcptun's `Pipe` order) and must still receive the whole answer.
#[tokio::test]
async fn v11_early_close_write_echo_delivers_everything() {
    for version in [1, 2] {
        let (cli, srv) = session_pair(quiet_config(version));
        let request = payload(31 + version as u64, 1000);
        let answer = payload(41 + version as u64, 200_000);

        let echo = {
            let answer = answer.clone();
            let want = request.clone();
            tokio::spawn(async move {
                let stream = srv.accept_stream().await.expect("accept");
                assert_eq!(read_to_end(&stream).await, want);
                stream.write(&answer).await.expect("write");
                stream.close_write().await.expect("close_write");
                // Hold the session (and the stream) until the client is done.
                stream.closed().await;
            })
        };

        let stream = cli.open_stream().await.expect("open");
        stream.write(&request).await.expect("write");
        stream.close_write().await.expect("close_write");

        // Let the answer and the peer's FIN pile up before reading a single byte: this is
        // exactly the state in which Go discards the buffer.
        wait_until("peer fin", || stream.got_fin()).await;
        assert!(stream.is_closed(), "both FINs have been exchanged");

        assert_eq!(read_to_end(&stream).await, answer, "version {version}");
        timeout(PATIENCE, echo).await.expect("echo done").ok();
    }
}

// ---------------------------------------------------------------------------------------
// Close, tokens and Drop
// ---------------------------------------------------------------------------------------

/// `close` sends a FIN, empties the receive buffer back into the token bucket exactly once, and
/// reports `io.ErrClosedPipe` on a second call.
// Go: smux@v1.5.55 stream.go:Close()
#[tokio::test]
async fn close_returns_tokens_exactly_once() {
    let (session, peer) = peered(quiet_config(1));
    let budget = session.shared().bucket();
    let stream = peer.open(&session, 1, 3).await;

    peer.write_frame(1, CMD_PSH, 3, &[1u8; 32]).await;
    wait_until("push buffered", || stream.buffered_len() == 32).await;
    assert_eq!(session.shared().bucket(), budget - 32);

    stream.close().await.expect("close");
    let (header, _) = peer.read_frame().await;
    assert_eq!(header.cmd(), CMD_FIN);
    assert_eq!(session.shared().bucket(), budget);
    assert_eq!(session.num_streams(), 0);
    assert_eq!(stream.buffered_len(), 0);

    assert_eq!(stream.close().await, Err(Error::ClosedPipe));
    assert_eq!(session.shared().bucket(), budget);
    drop(stream);
    assert_eq!(session.shared().bucket(), budget, "tokens returned once");
}

/// After a full close the write side reports `io.ErrClosedPipe` and the read side is at EOF:
/// `close` is the one path that does throw buffered data away (deviation V11 keeps only the
/// half-close cleanup non-destructive).
// Go: smux@v1.5.55 stream.go:Close() / checkWriteClosed() / tryReadV1()
#[tokio::test]
async fn write_and_read_after_close() {
    let (session, peer) = peered(quiet_config(1));
    let stream = peer.open(&session, 1, 3).await;
    peer.write_frame(1, CMD_PSH, 3, b"unread").await;
    wait_until("push buffered", || stream.buffered_len() == 6).await;

    stream.close().await.expect("close");
    let (header, _) = peer.read_frame().await;
    assert_eq!(header.cmd(), CMD_FIN);

    assert_eq!(stream.write(b"x").await, Err(Error::ClosedPipe));
    let mut buf = [0u8; 8];
    assert_eq!(stream.read(&mut buf).await.expect("read"), 0);
    assert_eq!(stream.read_chunk().await.expect("read_chunk"), None);
    drop(session);
}

/// Dropping the last handle closes the stream: Go's finalizer on accepted streams, made
/// deterministic. The FIN goes out on a detached task, and the synchronous half, leaving the
/// map and giving the tokens back: has already happened when `drop` returns.
#[tokio::test]
async fn dropping_the_last_handle_closes_the_stream() {
    let (session, peer) = peered(quiet_config(1));
    let budget = session.shared().bucket();
    let stream = peer.open(&session, 1, 3).await;
    peer.write_frame(1, CMD_PSH, 3, &[1u8; 32]).await;
    wait_until("push buffered", || stream.buffered_len() == 32).await;

    drop(stream);
    assert_eq!(session.num_streams(), 0);
    assert_eq!(session.shared().bucket(), budget);

    let (header, _) = timeout(PATIENCE, peer.read_frame())
        .await
        .expect("fin in time");
    assert_eq!(header.cmd(), CMD_FIN);
    assert_eq!(header.stream_id(), 3);
}

/// A stream the session closed is already dead, so dropping its handle sends no second FIN.
#[tokio::test]
async fn dropping_a_session_closed_stream_sends_no_fin() {
    let (session, peer) = peered(quiet_config(1));
    let stream = peer.open(&session, 1, 3).await;

    session.close().await.expect("close");
    assert!(stream.is_closed());
    assert_eq!(stream.close().await, Err(Error::ClosedPipe));
    drop(stream);

    // The connection is closed, so the peer sees the end of the stream rather than a FIN.
    let mut buf = [0u8; 8];
    let got = timeout(PATIENCE, peer.conn.read(&mut buf))
        .await
        .expect("peer read in time");
    assert!(matches!(got, Ok(0) | Err(_)), "no frame after the close");
}

/// Closing the session releases blocked readers and writers of its streams.
// Go: smux@v1.5.55 session.go:Close() -> stream.sessionClose()
#[tokio::test]
async fn session_close_releases_a_blocked_reader() {
    let (session, peer) = peered(quiet_config(1));
    let stream = Arc::new(peer.open(&session, 1, 3).await);
    let reader = {
        let stream = Arc::clone(&stream);
        tokio::spawn(async move {
            let mut buf = [0u8; 16];
            stream.read(&mut buf).await
        })
    };
    sleep(Duration::from_millis(20)).await;

    session.close().await.expect("close");
    let got = timeout(PATIENCE, reader)
        .await
        .expect("reader finishes")
        .expect("task");
    assert_eq!(got, Err(Error::ClosedPipe));
}

/// A blocked version-2 writer is released when the session dies.
#[tokio::test]
async fn session_close_releases_a_blocked_writer() {
    let (session, peer) = peered(quiet_config(2));
    let stream = Arc::new(peer.open(&session, 2, 3).await);
    let writer = {
        let stream = Arc::clone(&stream);
        tokio::spawn(async move { stream.write(&[7u8; 300_000]).await })
    };

    // Drain the initial window so the writer parks.
    let mut seen = 0usize;
    while seen < INITIAL_PEER_WINDOW as usize {
        let (_, data) = peer.read_frame().await;
        seen += data.len();
    }
    sleep(Duration::from_millis(20)).await;
    assert!(!writer.is_finished());

    session.close().await.expect("close");
    let got = timeout(PATIENCE, writer)
        .await
        .expect("writer finishes")
        .expect("task");
    assert_eq!(got, Err(Error::ClosedPipe));
}

/// `close_write` releases a version-2 writer that is parked on the window, with
/// `io.ErrClosedPipe`.
#[tokio::test]
async fn close_write_releases_a_blocked_writer() {
    let (session, peer) = peered(quiet_config(2));
    let stream = Arc::new(peer.open(&session, 2, 3).await);
    let writer = {
        let stream = Arc::clone(&stream);
        tokio::spawn(async move { stream.write(&[7u8; 300_000]).await })
    };

    let mut seen = 0usize;
    while seen < INITIAL_PEER_WINDOW as usize {
        let (_, data) = peer.read_frame().await;
        seen += data.len();
    }
    sleep(Duration::from_millis(20)).await;
    assert!(!writer.is_finished());

    stream.close_write().await.expect("close_write");
    let got = timeout(PATIENCE, writer)
        .await
        .expect("writer finishes")
        .expect("task");
    assert_eq!(got, Err(Error::ClosedPipe));
    drop(session);
}

// ---------------------------------------------------------------------------------------
// Deadlines
// ---------------------------------------------------------------------------------------

/// A read deadline in the past, and one set while a reader is already blocked, both produce
/// `ErrTimeout`.
// Go: reference/latest/smux/session_test.go:TestReadDeadline
#[tokio::test]
async fn test_read_deadline() {
    let (session, peer) = peered(quiet_config(1));
    let stream = Arc::new(peer.open(&session, 1, 3).await);

    stream.set_read_deadline(Some(Instant::now() + Duration::from_millis(30)));
    let mut buf = [0u8; 16];
    assert_eq!(stream.read(&mut buf).await, Err(Error::Timeout));

    // Clearing it lets a read block again; setting one wakes it.
    stream.set_read_deadline(None);
    let reader = {
        let stream = Arc::clone(&stream);
        tokio::spawn(async move {
            let mut buf = [0u8; 16];
            stream.read(&mut buf).await
        })
    };
    sleep(Duration::from_millis(20)).await;
    assert!(!reader.is_finished());
    stream.set_read_deadline(Some(Instant::now() + Duration::from_millis(10)));
    let got = timeout(PATIENCE, reader)
        .await
        .expect("reader finishes")
        .expect("task");
    assert_eq!(got, Err(Error::Timeout));
}

/// A write deadline releases a version-2 writer parked on the peer's window.
// Go: reference/latest/smux/session_test.go:TestWriteDeadline
#[tokio::test]
async fn test_write_deadline() {
    let (session, peer) = peered(quiet_config(2));
    let stream = Arc::new(peer.open(&session, 2, 3).await);
    let writer = {
        let stream = Arc::clone(&stream);
        tokio::spawn(async move { stream.write(&[7u8; 300_000]).await })
    };

    let mut seen = 0usize;
    while seen < INITIAL_PEER_WINDOW as usize {
        let (_, data) = peer.read_frame().await;
        seen += data.len();
    }
    sleep(Duration::from_millis(20)).await;
    assert!(!writer.is_finished());

    stream.set_write_deadline(Some(Instant::now() + Duration::from_millis(10)));
    let got = timeout(PATIENCE, writer)
        .await
        .expect("writer finishes")
        .expect("task");
    assert_eq!(got, Err(Error::Timeout));
    drop(session);
}

// ---------------------------------------------------------------------------------------
// The drain path
// ---------------------------------------------------------------------------------------

/// `write_to` drains the stream into a writer and stops at EOF, for both versions, and version
/// 2 keeps sending its window updates while it does.
// Go: reference/latest/smux/session_test.go:TestWriteTo / TestWriteToV2
#[tokio::test]
async fn test_write_to() {
    for version in [1, 2] {
        let (cli, srv) = session_pair(quiet_config(version));
        let sent = payload(51 + version as u64, 200_000);

        let echo = {
            let sent = sent.clone();
            tokio::spawn(async move {
                let stream = srv.accept_stream().await.expect("accept");
                // Wait for the request before answering: a peer that answers a bare SYN can
                // beat `open_stream`'s registration of the stream, in this port and in Go
                // alike (`recvLoop` drops frames for an unknown id).
                assert_eq!(read_exact_from(&stream, 1).await, b"?");
                stream.write(&sent).await.expect("write");
                stream.close_write().await.expect("close_write");
                stream.closed().await;
            })
        };

        let stream = cli.open_stream().await.expect("open");
        stream.write(b"?").await.expect("write");
        let mut sink: Vec<u8> = Vec::new();
        let n = timeout(PATIENCE, stream.write_to(&mut sink))
            .await
            .expect("write_to finishes")
            .expect("write_to");
        assert_eq!(n, sent.len() as u64, "version {version}");
        assert_eq!(sink, sent);
        drop(stream);
        timeout(PATIENCE, echo).await.expect("echo done").ok();
    }
}

/// `read_chunk` hands out the frame payloads the session received, without copying them, and
/// returns `Ok(None)` at the end.
#[tokio::test]
async fn read_chunk_hands_out_whole_frames() {
    let (session, peer) = peered(quiet_config(2));
    let stream = peer.open(&session, 2, 3).await;
    let budget = session.shared().bucket();

    peer.write_frame(2, CMD_PSH, 3, b"first").await;
    peer.write_frame(2, CMD_PSH, 3, b"second").await;
    peer.write_frame(2, CMD_FIN, 3, &[]).await;

    let first = timeout(PATIENCE, stream.read_chunk())
        .await
        .expect("chunk in time")
        .expect("chunk");
    assert_eq!(first.as_deref(), Some(&b"first"[..]));
    let second = stream.read_chunk().await.expect("chunk");
    assert_eq!(second.as_deref(), Some(&b"second"[..]));
    assert_eq!(stream.read_chunk().await.expect("chunk"), None);
    assert_eq!(session.shared().bucket(), budget, "tokens returned");

    // The first read owes the peer a window update.
    let (header, data) = peer.read_frame().await;
    assert_eq!(header.cmd(), CMD_UPD);
    let upd = UpdHeader::from_bytes(&data).expect("upd payload");
    assert_eq!(upd.consumed(), 5);
}

// ---------------------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------------------

/// Many streams at once, each echoing its own payload: the frames of different streams must
/// not mix up.
// Go: reference/latest/smux/session_test.go:TestParallel / TestParallelV2
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parallel() {
    for version in [1, 2] {
        let (cli, srv) = session_pair(quiet_config(version));
        let srv = Arc::new(srv);
        let acceptor = {
            let srv = Arc::clone(&srv);
            tokio::spawn(async move {
                while let Ok(stream) = srv.accept_stream().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 8192];
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => {
                                    if stream.write(&buf[..n]).await.is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                    });
                }
            })
        };

        let cli = Arc::new(cli);
        let mut tasks = Vec::new();
        for i in 0..32u64 {
            let cli = Arc::clone(&cli);
            tasks.push(tokio::spawn(async move {
                let stream = cli.open_stream().await.expect("open");
                let sent = payload(100 + i, 20_000);
                stream.write(&sent).await.expect("write");
                let got = read_exact_from(&stream, sent.len()).await;
                assert_eq!(got, sent);
            }));
        }
        for task in tasks {
            timeout(PATIENCE, task)
                .await
                .expect("stream finishes")
                .expect("task");
        }
        acceptor.abort();
    }
}

/// Two writers on one stream interleave their frames without corrupting either payload: every
/// frame that reaches the wire is a contiguous piece of one of them.
// Go: smux@v1.5.55 stream.go:Write() ("frames may interleave in random way")
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_writers_produce_whole_frames() {
    let config = Config {
        max_frame_size: 1024,
        ..quiet_config(1)
    };
    let (session, peer) = peered(config);
    let stream = Arc::new(peer.open(&session, 1, 3).await);

    let a = {
        let stream = Arc::clone(&stream);
        tokio::spawn(async move { stream.write(&[0xaa_u8; 4096]).await })
    };
    let b = {
        let stream = Arc::clone(&stream);
        tokio::spawn(async move { stream.write(&[0xbb_u8; 4096]).await })
    };

    let mut seen = 0usize;
    while seen < 8192 {
        let (header, data) = peer.read_frame().await;
        assert_eq!(header.cmd(), CMD_PSH);
        assert!(
            data.iter().all(|&b| b == 0xaa) || data.iter().all(|&b| b == 0xbb),
            "a frame mixed two writers"
        );
        seen += data.len();
    }
    assert_eq!(a.await.expect("task").expect("write"), 4096);
    assert_eq!(b.await.expect("task").expect("write"), 4096);
}

/// `write` must not return before the frame has reached the connection: that is the
/// backpressure the proxy relies on.
// Go: step 06 "Pitfalls"
#[tokio::test]
async fn write_waits_for_the_connection() {
    // One byte of pipe capacity, so the send task cannot get a whole frame out until the peer
    // reads it.
    let (ours, theirs) = tokio::io::duplex(1);
    let session = server(SplitConn::new(ours), Some(quiet_config(1))).expect("server");
    let peer = Peer::new(theirs);
    let stream = Arc::new(peer.open(&session, 1, 3).await);

    let writer = {
        let stream = Arc::clone(&stream);
        tokio::spawn(async move { stream.write(b"backpressure").await })
    };
    sleep(Duration::from_millis(30)).await;
    assert!(!writer.is_finished(), "write returned before the wire");

    let (header, data) = peer.read_frame().await;
    assert_eq!(header.cmd(), CMD_PSH);
    assert_eq!(data, b"backpressure");
    let n = timeout(PATIENCE, writer)
        .await
        .expect("write finishes")
        .expect("task")
        .expect("write");
    assert_eq!(n, data.len());
}

// ---------------------------------------------------------------------------------------
// The receive buffer and the internal read/write helpers
//
// Ported from `reference/latest/smux/stream_test.go` (the `bufferRing` tests) and
// `stream_internal_test.go`, which reach into the same unexported state.
//
// The two `stream_internal_test.go` tests with no counterpart below:
// `TestWriteV2ConsumedError` is covered by `write_v2_rejects_an_over_consuming_peer` earlier in
// this file, and `TestStopTimer` exercises a Go `time.Timer` helper that has no Rust
// equivalent (tokio timers are dropped, never stopped by hand).
// ---------------------------------------------------------------------------------------

/// Go: `TestBufferRingPushPopOrder`, `TestBufferRingEmptyPop`, `TestBufferRingGrow` and
/// `TestNewBufferRingMinCapacity`: Go's `bufferRing` is a hand-written ring of `[]byte`
/// slices, this port's [`StreamBuf`] a `VecDeque<Bytes>`. Growth and the minimum capacity are
/// therefore the container's business; what has to hold is the order, the byte count and the
/// empty pop.
// Go: reference/latest/smux/stream_test.go:TestBufferRingPushPopOrder / TestBufferRingGrow /
// TestBufferRingEmptyPop, stream_internal_test.go:TestNewBufferRingMinCapacity
#[test]
fn test_buffer_ring_push_pop_order() {
    let mut r = StreamBuf::default();
    assert_eq!(r.pop(), None, "expected empty pop");
    assert_eq!(r.len, 0);

    r.chunks.push_back(Bytes::from_static(&[1]));
    r.chunks.push_back(Bytes::from_static(&[2]));
    r.len = 2;
    assert_eq!(r.pop().as_deref(), Some([1].as_slice()));

    // Push past the initial capacity: the order of what is already queued does not change.
    r.chunks.push_back(Bytes::from_static(&[3]));
    r.len += 1;
    assert_eq!(r.pop().as_deref(), Some([2].as_slice()));
    assert_eq!(r.pop().as_deref(), Some([3].as_slice()));
    assert_eq!(r.pop(), None, "ring not empty after pops");
    assert_eq!(r.len, 0);

    // consume_front hands out the front buffer piece by piece and drops it once it is spent.
    let mut r = StreamBuf::default();
    r.chunks.push_back(Bytes::from_static(b"abcd"));
    r.chunks.push_back(Bytes::from_static(b"ef"));
    r.len = 6;
    let mut out = [0u8; 3];
    assert_eq!(r.consume_front(&mut out), 3);
    assert_eq!(&out, b"abc");
    assert_eq!(r.len, 3);
    let mut out = [0u8; 8];
    assert_eq!(r.consume_front(&mut out), 1, "stops at the frame boundary");
    assert_eq!(&out[..1], b"d");
    assert_eq!(r.consume_front(&mut out), 2);
    assert_eq!(&out[..2], b"ef");
    assert_eq!(r.len, 0);
    assert_eq!(r.consume_front(&mut out), 0, "empty buffer");
}

/// A bare stream on a live session, like Go's `newUnitTestStream`.
// Go: reference/latest/smux/stream_internal_test.go:newUnitTestStream
fn unit_test_stream(
    version: isize,
) -> (
    Session<SplitConn<DuplexStream>>,
    Peer,
    Arc<SessionShared>,
    Arc<StreamInner>,
) {
    let (session, peer) = peered(quiet_config(version));
    let shared = Arc::clone(session.shared());
    let inner = StreamInner::new(1, &shared);
    (session, peer, shared, inner)
}

/// Go: `TestStreamWaitReadTimeout`.
// Go: reference/latest/smux/stream_internal_test.go:TestStreamWaitReadTimeout
#[tokio::test]
async fn test_stream_wait_read_timeout() {
    let (_session, _peer, shared, s) = unit_test_stream(1);
    *lock(&s.read_deadline) = Some(Instant::now() + Duration::from_millis(20));
    match s.wait_read(&shared).await {
        WaitRead::Failed(Error::Timeout) => {}
        other => panic!("expected ErrTimeout, got {:?}", DebugWait(other)),
    }
}

/// Go: `TestStreamWaitReadFinWithBufferedData`, the peer's FIN with data still buffered is a
/// wakeup, not an EOF (smux issue #82).
// Go: reference/latest/smux/stream_internal_test.go:TestStreamWaitReadFinWithBufferedData
#[tokio::test]
async fn test_stream_wait_read_fin_with_buffered_data() {
    let (_session, _peer, shared, s) = unit_test_stream(1);
    s.push_bytes(Bytes::from_static(b"abc"));
    s.fin(&shared);

    match s.wait_read(&shared).await {
        WaitRead::Wakeup => {}
        other => panic!("expected a wakeup after fin, got {:?}", DebugWait(other)),
    }

    let mut buf = [0u8; 3];
    match s.try_read(&shared, &mut buf).await {
        TryRead::Read(3) => {}
        other => panic!("read failed: {:?}", DebugTry(other)),
    }
    assert_eq!(&buf, b"abc", "read mismatch");
}

/// Go: `TestStreamRecycleTokens`.
// Go: reference/latest/smux/stream_internal_test.go:TestStreamRecycleTokens
#[test]
fn test_stream_recycle_tokens() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let _guard = rt.enter();
    let (_session, _peer, _shared, s) = unit_test_stream(1);
    s.push_bytes(Bytes::from_static(b"hello"));
    s.push_bytes(Bytes::from_static(b"world!"));
    assert_eq!(s.recycle_tokens(), 11, "unexpected recycled bytes");
    assert_eq!(s.buffered_len(), 0, "expected an empty buffer");
}

/// Go: `TestStreamWaitReadClosed`.
// Go: reference/latest/smux/stream_internal_test.go:TestStreamWaitReadClosed
#[tokio::test]
async fn test_stream_wait_read_closed() {
    let (_session, _peer, shared, s) = unit_test_stream(1);
    assert!(s.close_die());
    match s.wait_read(&shared).await {
        WaitRead::Failed(Error::ClosedPipe) => {}
        other => panic!("expected io.ErrClosedPipe, got {:?}", DebugWait(other)),
    }
}

/// Go: `TestStreamSetDeadlineWakesUp`, setting a deadline wakes the blocked reader and writer,
/// so they pick the new value up.
// Go: reference/latest/smux/stream_internal_test.go:TestStreamSetDeadlineWakesUp
#[tokio::test]
async fn test_stream_set_deadline_wakes_up() {
    let (session, peer, _shared, _s) = unit_test_stream(1);
    let stream = Arc::new(peer.open(&session, 1, 3).await);

    let reader = {
        let stream = Arc::clone(&stream);
        tokio::spawn(async move {
            let mut buf = [0u8; 8];
            stream.read(&mut buf).await
        })
    };
    // The reader is blocked; a deadline in the past must wake it with a timeout.
    sleep(Duration::from_millis(10)).await;
    assert!(!reader.is_finished());
    stream.set_deadline(Some(Instant::now() - Duration::from_secs(1)));
    let err = timeout(PATIENCE, reader)
        .await
        .expect("reader wakes up")
        .expect("task")
        .expect_err("read must time out");
    assert_eq!(err, Error::Timeout);
}

/// Go: `TestSendWindowUpdateTimeout`, a `cmdUPD` inherits the read deadline.
// Go: reference/latest/smux/stream_internal_test.go:TestSendWindowUpdateTimeout
#[tokio::test]
async fn test_send_window_update_timeout() {
    let (_session, _peer, shared, s) = unit_test_stream(2);
    *lock(&s.read_deadline) = Some(Instant::now() - Duration::from_secs(1));
    assert_eq!(
        s.send_window_update(&shared, 1)
            .await
            .expect_err("expected ErrTimeout"),
        Error::Timeout
    );
}

/// Go: `TestWriteV2ClosedPipe`.
// Go: reference/latest/smux/stream_internal_test.go:TestWriteV2ClosedPipe
#[tokio::test]
async fn test_write_v2_closed_pipe() {
    let (_session, _peer, shared, s) = unit_test_stream(2);
    assert!(s.close_write_side());
    assert_eq!(
        s.write(&shared, Chunks::Slice(b"x"))
            .await
            .expect_err("expected io.ErrClosedPipe"),
        Error::ClosedPipe
    );
}

/// Go: `TestWriteV2TimeoutWhenWindowZero`, with no window left, the write deadline decides.
// Go: reference/latest/smux/stream_internal_test.go:TestWriteV2TimeoutWhenWindowZero
#[tokio::test]
async fn test_write_v2_timeout_when_window_zero() {
    let (_session, _peer, shared, s) = unit_test_stream(2);
    s.peer_window.store(0, Ordering::Release);
    *lock(&s.write_deadline) = Some(Instant::now() - Duration::from_secs(1));
    assert_eq!(
        s.write(&shared, Chunks::Slice(b"data"))
            .await
            .expect_err("expected ErrTimeout"),
        Error::Timeout
    );
}

/// `Debug` wrappers, so a failing assertion can print the enums (which are internal and carry
/// no `Debug` of their own).
struct DebugWait(WaitRead);

impl std::fmt::Debug for DebugWait {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            WaitRead::Wakeup => f.write_str("Wakeup"),
            WaitRead::Eof => f.write_str("Eof"),
            WaitRead::Failed(e) => write!(f, "Failed({e})"),
        }
    }
}

struct DebugTry(TryRead);

impl std::fmt::Debug for DebugTry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            TryRead::Read(n) => write!(f, "Read({n})"),
            TryRead::Eof => f.write_str("Eof"),
            TryRead::WouldBlock => f.write_str("WouldBlock"),
        }
    }
}

/// A reader blocked when the peer's FIN completes a half-close must see the end of the stream,
/// not a broken pipe.
///
/// The FIN closes `fin_event` and, because this side had already half-closed, `die` as well
/// (`try_half_close_cleanup`). Go's `waitRead` selects between the two at random and reports
/// `io.ErrClosedPipe` when it picks `die`: reproduced Go↔Go with `smuxecho` (2 of 5 runs with
/// 256 streams). This port answers in a fixed order, so the stream always ends in EOF.
// Go: smux@v1.5.55 stream.go:waitRead() (the random select), docs/DECISIONS.md V11
#[tokio::test]
async fn a_blocked_reader_sees_eof_when_the_half_close_completes() {
    for version in [1, 2] {
        let (session, peer) = peered(quiet_config(version));
        let stream = Arc::new(peer.open(&session, version as u8, 3).await);
        stream.close_write().await.expect("close_write");
        let (header, _) = peer.read_frame().await;
        assert_eq!(header.cmd(), CMD_FIN);

        let reader = {
            let stream = Arc::clone(&stream);
            tokio::spawn(async move {
                let mut buf = [0u8; 16];
                stream.read(&mut buf).await
            })
        };
        // Make sure the reader is parked in `wait_read` before the FIN arrives.
        sleep(Duration::from_millis(20)).await;
        assert!(!reader.is_finished(), "the reader should be blocked");

        peer.write_frame(version as u8, CMD_FIN, 3, &[]).await;
        let n = timeout(PATIENCE, reader)
            .await
            .expect("reader wakes up")
            .expect("task")
            .expect("the stream ended cleanly, not with a broken pipe");
        assert_eq!(n, 0, "end of stream");
        wait_until("stream removed from the session", || {
            session.num_streams() == 0
        })
        .await;
    }
}
