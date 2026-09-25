//! Tests of the session, ported from `reference/latest/smux/session_test.go` (the parts that do
//! not need `Stream::read`/`Stream::write`, which arrive in 06.4) plus cases that pin down what
//! `recvLoop` does with hand-built frames — Go has no test for the V01 length validation, for
//! the token bucket, or for the class ordering as it appears on the wire.
//!
//! Most tests drive one Rust session against a hand-written peer over [`tokio::io::duplex`], so
//! the exact bytes in both directions are visible. Go's keepalive tests run at 1 s / 2 s / 3 s;
//! the ports use a tenth of that with the same ratios, and the full-length versions are kept as
//! `#[ignore]`d `long_*` tests (porting guide §8).

use std::io;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use kcptun_testkit::rng::{Pcg, rand_bytes};
use tokio::io::DuplexStream;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, sleep, timeout};

use super::*;
use crate::conn::SplitConn;
use crate::frame::INITIAL_PEER_WINDOW;
use crate::mux::{client, default_config, server};

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

/// A session connection over an in-memory pipe, plus the raw other end.
fn pipe(capacity: usize) -> (SplitConn<DuplexStream>, Peer) {
    let (ours, theirs) = tokio::io::duplex(capacity);
    (SplitConn::new(ours), Peer::new(theirs))
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

    async fn write_bytes(&self, bytes: &[u8]) {
        self.conn.write_all(bytes).await.expect("peer write");
    }

    /// Writes a well-formed frame.
    async fn write_frame(&self, ver: u8, cmd: u8, sid: u32, data: &[u8]) {
        self.write_bytes(&raw_frame(ver, cmd, sid, data.len() as u16, data))
            .await;
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
    async fn read_frame(&self) -> io::Result<(RawHeader, Vec<u8>)> {
        let head = self.read_exact(HEADER_SIZE).await?;
        let header = RawHeader::from_bytes(&head).expect("full header");
        let payload = self.read_exact(usize::from(header.length())).await?;
        Ok((header, payload))
    }

    /// Stops sending, leaving the session's own writes working: the session sees EOF on its
    /// read side only, which is what these tests are about.
    async fn close(&self) {
        self.conn.close_write().await.expect("peer close");
    }
}

/// A frame whose header length field is `length`, whatever `data` actually is: the only way to
/// build the frames DECISIONS V01 rejects.
fn raw_frame(ver: u8, cmd: u8, sid: u32, length: u16, data: &[u8]) -> Vec<u8> {
    let mut out = RawHeader::new(ver, cmd, length, sid).as_bytes().to_vec();
    out.extend_from_slice(data);
    out
}

/// Go's `blockWriteConn`: reads work, writes never finish.
// Go: reference/latest/smux/session_test.go:blockWriteConn
struct BlockWriteConn {
    inner: SplitConn<DuplexStream>,
}

impl SmuxConn for BlockWriteConn {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf).await
    }

    async fn write_all(&self, _buf: &[u8]) -> io::Result<()> {
        std::future::pending().await
    }

    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }
}

/// A connection whose writes fail immediately.
struct FailWriteConn {
    inner: SplitConn<DuplexStream>,
}

impl SmuxConn for FailWriteConn {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf).await
    }

    async fn write_all(&self, _buf: &[u8]) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe"))
    }

    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }
}

/// A frame with a payload, for `write_frame_internal`.
fn data_frame(ver: u8, cmd: u8, sid: u32, payload: &'static [u8]) -> OwnedFrame {
    OwnedFrame::with_data(ver, cmd, sid, Payload::Data(Bytes::from_static(payload)))
}

/// Waits until `check` holds, or fails after [`PATIENCE`].
async fn wait_until(what: &str, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while !check() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        sleep(Duration::from_millis(5)).await;
    }
}

// ---------------------------------------------------------------------------------------
// Constants and classes
// ---------------------------------------------------------------------------------------

#[test]
fn constants_match_go() {
    assert_eq!(DEFAULT_ACCEPT_BACKLOG, 1024);
    assert_eq!(MIN_SHAPER_NOTIFY_SIZE, 16);
    assert_eq!(MAX_SHAPER_SIZE, 1024);
    assert_eq!(OPEN_CLOSE_TIMEOUT, Duration::from_secs(30));
}

#[test]
fn control_sorts_before_data() {
    assert!(ClassId::Ctrl < ClassId::Data);
    assert_eq!(ClassId::Ctrl as i32, 0);
    assert_eq!(ClassId::Data as i32, 1);
}

/// Go passes `*Session` and `*Stream` between goroutines freely; the port must be able to do
/// the same across tasks (kcptun holds one session per tunnel and a stream per proxied
/// connection).
#[test]
fn sessions_and_streams_cross_task_boundaries() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Session<SplitConn<DuplexStream>>>();
    assert_send_sync::<Stream>();
    assert_send_sync::<Error>();
}

// ---------------------------------------------------------------------------------------
// Construction and stream ids
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn client_and_server_reject_a_bad_config() {
    let bad = Config {
        version: 3,
        ..default_config()
    };
    let (conn, _peer) = pipe(PIPE_CAPACITY);
    let err = client(conn, Some(bad)).expect_err("rejected");
    assert_eq!(err.to_string(), "unsupported protocol version");

    let (conn, _peer) = pipe(PIPE_CAPACITY);
    let err = server(conn, Some(bad)).expect_err("rejected");
    assert_eq!(err.to_string(), "unsupported protocol version");
}

/// `nextStreamID` starts at 1 on the client and is advanced *before* use, so the first stream
/// the client opens is 3.
#[tokio::test]
async fn client_opens_odd_ids_starting_at_three() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let session = client(conn, Some(quiet_config(1))).expect("client");

    // The handles are kept: dropping one closes its stream and puts a `cmdFIN` on the wire.
    let mut streams = Vec::new();
    for expected in [3u32, 5, 7] {
        let stream = session.open_stream().await.expect("open");
        assert_eq!(stream.id(), expected);
        let (header, payload) = peer.read_frame().await.expect("syn");
        assert_eq!(header.version(), 1);
        assert_eq!(header.cmd(), CMD_SYN);
        assert_eq!(header.stream_id(), expected);
        assert_eq!(header.length(), 0);
        assert!(payload.is_empty());
        streams.push(stream);
    }
    assert_eq!(session.num_streams(), 3);
}

/// `nextStreamID` starts at 0 on the server, so the first stream it opens is 2.
#[tokio::test]
async fn server_opens_even_ids_starting_at_two() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let session = server(conn, Some(quiet_config(1))).expect("server");

    let mut streams = Vec::new();
    for expected in [2u32, 4, 6] {
        let stream = session.open_stream().await.expect("open");
        assert_eq!(stream.id(), expected);
        let (header, _) = peer.read_frame().await.expect("syn");
        assert_eq!(header.stream_id(), expected);
        streams.push(stream);
    }
}

#[tokio::test]
async fn open_stream_uses_the_configured_version() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let session = client(conn, Some(quiet_config(2))).expect("client");
    session.open_stream().await.expect("open");
    let (header, _) = peer.read_frame().await.expect("syn");
    assert_eq!(header.version(), 2);
    assert_eq!(header.cmd(), CMD_SYN);
}

/// Go sets `goAway` once `nextStreamID + 2` would wrap, and every later call fails without
/// touching the connection.
#[tokio::test]
async fn open_stream_reports_go_away_on_id_overflow() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let session = client(conn, Some(quiet_config(1))).expect("client");

    // The last two ids that still fit: `nextStreamID + 2` does not wrap for either.
    session.shared().set_next_stream_id(u32::MAX - 4);
    for expected in [u32::MAX - 2, u32::MAX] {
        let stream = session.open_stream().await.expect("open");
        assert_eq!(stream.id(), expected);
        let (header, _) = peer.read_frame().await.expect("syn");
        assert_eq!(header.stream_id(), expected);
    }

    // The next one would wrap.
    assert_eq!(session.open_stream().await.err(), Some(Error::GoAway));
    // goAway is sticky.
    assert_eq!(session.open_stream().await.err(), Some(Error::GoAway));
    assert_eq!(
        Error::GoAway.to_string(),
        "stream id overflows, should start a new connection"
    );
}

#[tokio::test]
async fn open_stream_after_close_returns_closed_pipe() {
    let (conn, _peer) = pipe(PIPE_CAPACITY);
    let session = client(conn, Some(quiet_config(1))).expect("client");
    session.close().await.expect("close");
    assert_eq!(session.open_stream().await.err(), Some(Error::ClosedPipe));
}

// ---------------------------------------------------------------------------------------
// Accept
// ---------------------------------------------------------------------------------------

/// Go: `TestSessionOpenAccept`, plus `TestStreamID`.
#[tokio::test]
async fn test_session_open_accept() {
    let (a, b) = tokio::io::duplex(PIPE_CAPACITY);
    let srv = server(SplitConn::new(a), Some(quiet_config(1))).expect("server");
    let cli = client(SplitConn::new(b), Some(quiet_config(1))).expect("client");

    let opened = cli.open_stream().await.expect("open");
    let accepted = timeout(PATIENCE, srv.accept_stream())
        .await
        .expect("accept in time")
        .expect("accept");
    assert_ne!(accepted.id(), 0, "an accepted stream never has id 0");
    assert_eq!(accepted.id(), opened.id());
    assert_eq!(srv.num_streams(), 1);
}

/// A second `cmdSYN` for an id the session already knows is ignored (Go checks the map first).
#[tokio::test]
async fn duplicate_syn_is_not_accepted_twice() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let session = server(conn, Some(quiet_config(1))).expect("server");

    peer.write_frame(1, CMD_SYN, 3, &[]).await;
    peer.write_frame(1, CMD_SYN, 3, &[]).await;
    let stream = timeout(PATIENCE, session.accept_stream())
        .await
        .expect("accept in time")
        .expect("accept");
    assert_eq!(stream.id(), 3);

    session.set_deadline(Some(Instant::now() + Duration::from_millis(100)));
    assert_eq!(session.accept_stream().await.err(), Some(Error::Timeout));
    assert_eq!(session.num_streams(), 1);
}

/// Go: `TestSessionSetDeadline`, plus the `ErrTimeout` branch of `AcceptStream`.
#[tokio::test]
async fn test_session_set_deadline() {
    let (conn, _peer) = pipe(PIPE_CAPACITY);
    let session = server(conn, Some(quiet_config(1))).expect("server");

    session.set_deadline(Some(Instant::now() + Duration::from_millis(50)));
    let err = timeout(PATIENCE, session.accept_stream())
        .await
        .expect("accept returns")
        .expect_err("timeout");
    assert_eq!(err, Error::Timeout);
    assert_eq!(err.to_string(), "timeout");
    assert!(err.is_timeout());
    assert!(err.is_temporary());

    // No deadline (Go's zero time.Time) disables it again.
    session.set_deadline(None);
    assert!(
        timeout(Duration::from_millis(100), session.accept_stream())
            .await
            .is_err(),
        "accept should block again once the deadline is cleared"
    );
}

#[tokio::test]
async fn accept_after_close_returns_closed_pipe() {
    let (conn, _peer) = pipe(PIPE_CAPACITY);
    let session = server(conn, Some(quiet_config(1))).expect("server");
    session.close().await.expect("close");
    let err = timeout(PATIENCE, session.accept_stream())
        .await
        .expect("accept returns")
        .expect_err("closed");
    assert_eq!(err, Error::ClosedPipe);
    assert_eq!(err.to_string(), "io: read/write on closed pipe");
}

/// The backlog holds Go's `defaultAcceptBacklog` streams before `recvLoop` has to wait.
#[tokio::test]
async fn accept_backlog_holds_the_go_default() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let session = server(conn, Some(quiet_config(1))).expect("server");

    let mut batch = Vec::new();
    for i in 0..DEFAULT_ACCEPT_BACKLOG {
        batch.extend_from_slice(&raw_frame(1, CMD_SYN, (2 * i + 1) as u32, 0, &[]));
    }
    peer.write_bytes(&batch).await;
    wait_until("all SYNs registered", || {
        session.num_streams() == DEFAULT_ACCEPT_BACKLOG
    })
    .await;

    for i in 0..DEFAULT_ACCEPT_BACKLOG {
        let stream = timeout(PATIENCE, session.accept_stream())
            .await
            .expect("accept in time")
            .expect("accept");
        assert_eq!(stream.id(), (2 * i + 1) as u32);
    }
}

// ---------------------------------------------------------------------------------------
// recvLoop: protocol validation (DECISIONS V01)
// ---------------------------------------------------------------------------------------

/// The error a session reports after the peer sent `bytes`.
async fn protocol_failure(version: isize, bytes: Vec<u8>) -> Error {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let session = server(conn, Some(quiet_config(version))).expect("server");
    peer.write_bytes(&bytes).await;
    timeout(PATIENCE, session.accept_stream())
        .await
        .expect("accept returns")
        .expect_err("error")
}

#[tokio::test]
async fn wrong_protocol_version_kills_the_session() {
    let err = protocol_failure(1, raw_frame(2, CMD_SYN, 3, 0, &[])).await;
    assert_eq!(err, Error::InvalidProtocol);
    assert_eq!(err.to_string(), "invalid protocol");
}

/// DECISIONS V01: the post-pin fix rejects `cmdSYN`, `cmdFIN` and `cmdNOP` with a payload.
/// Pinned v1.5.55 accepts them and then mis-frames the rest of the connection.
#[tokio::test]
async fn v01_rejects_syn_fin_nop_with_a_payload() {
    for cmd in [CMD_SYN, CMD_FIN, CMD_NOP] {
        let err = protocol_failure(1, raw_frame(1, cmd, 3, 4, b"junk")).await;
        assert_eq!(err, Error::InvalidProtocol, "cmd {cmd}");
    }
}

/// DECISIONS V01: `cmdUPD` must carry exactly `szCmdUPD` bytes.
#[tokio::test]
async fn v01_rejects_upd_with_a_wrong_length() {
    for length in [0u16, 4, 9] {
        let err = protocol_failure(2, raw_frame(2, CMD_UPD, 3, length, &[0u8; 9])).await;
        assert_eq!(err, Error::InvalidProtocol, "length {length}");
    }
}

#[tokio::test]
async fn upd_on_a_version_1_session_is_a_protocol_error() {
    let err = protocol_failure(1, raw_frame(1, CMD_UPD, 3, SZ_CMD_UPD as u16, &[0u8; 8])).await;
    assert_eq!(err, Error::InvalidProtocol);
}

#[tokio::test]
async fn unknown_command_is_a_protocol_error() {
    for cmd in [5u8, 6, 200, 255] {
        let err = protocol_failure(1, raw_frame(1, cmd, 3, 0, &[])).await;
        assert_eq!(err, Error::InvalidProtocol, "cmd {cmd}");
    }
}

/// `io.ReadFull` reports `EOF` when the stream ends on a frame boundary and `unexpected EOF`
/// when it ends part-way through one (porting guide §4).
#[tokio::test]
async fn socket_read_error_carries_go_s_eof_texts() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let session = server(conn, Some(quiet_config(1))).expect("server");
    peer.close().await;
    let err = timeout(PATIENCE, session.accept_stream())
        .await
        .expect("accept returns")
        .expect_err("error");
    assert_eq!(err.to_string(), "EOF");

    let (conn, peer) = pipe(PIPE_CAPACITY);
    let session = server(conn, Some(quiet_config(1))).expect("server");
    peer.write_bytes(&[1, 0, 0]).await;
    peer.close().await;
    let err = timeout(PATIENCE, session.accept_stream())
        .await
        .expect("accept returns")
        .expect_err("error");
    assert_eq!(err.to_string(), "unexpected EOF");
}

/// A socket read error also releases `OpenStream`, which Go handles in its post-SYN `select`.
#[tokio::test]
async fn socket_read_error_reaches_open_stream() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let session = client(conn, Some(quiet_config(1))).expect("client");
    peer.close().await;
    wait_until("read error observed", || {
        session.shared().socket_read_error.is_set()
    })
    .await;
    let err = session.open_stream().await.expect_err("error");
    assert_eq!(err.to_string(), "EOF");
}

/// Go: `TestRandomFrame` — random bytes may kill the session, but must never make it panic or
/// wedge, and writing on the dead session still returns promptly.
#[tokio::test]
async fn test_random_frame() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let session = client(conn, Some(quiet_config(1))).expect("client");
    let mut rng = Pcg::new(0x5359_4e43, 0x0606_0003);
    for _ in 0..100 {
        let n = rng.below(1024) as usize;
        peer.write_bytes(&rand_bytes(&mut rng, n)).await;
    }
    // Whatever the session made of that, it must not wedge.
    let _ = timeout(Duration::from_millis(200), session.accept_stream()).await;
    drop(session);

    let (conn, _peer) = pipe(PIPE_CAPACITY);
    let session = client(conn, Some(quiet_config(1))).expect("client");
    session.close().await.expect("close");
    for _ in 0..100 {
        let cmd = rng.next_u32() as u8;
        let sid = rng.next_u32();
        let err = timeout(
            PATIENCE,
            session
                .shared()
                .write_control_frame(OwnedFrame::new(1, cmd, sid)),
        )
        .await
        .expect("write returns")
        .expect_err("closed");
        // Go's `select` picks at random among the ready cases, and so does this one: `die` is
        // already closed, but the send loop may still have popped the request and hit the
        // closed connection first. Either way the writer is released with an error, which is
        // all Go's test (which ignores the value) needs.
        assert!(
            matches!(err, Error::ClosedPipe | Error::Io(_)),
            "unexpected error: {err:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------
// recvLoop: frame handling
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn push_buffers_the_payload_and_deducts_tokens() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let session = server(conn, Some(quiet_config(1))).expect("server");
    let budget = session.shared().bucket();

    peer.write_frame(1, CMD_SYN, 3, &[]).await;
    let stream = timeout(PATIENCE, session.accept_stream())
        .await
        .expect("accept in time")
        .expect("accept");

    peer.write_frame(1, CMD_PSH, 3, b"hello").await;
    peer.write_frame(1, CMD_PSH, 3, b" world").await;
    wait_until("both pushes buffered", || stream.buffered_len() == 11).await;
    assert_eq!(session.shared().bucket(), budget - 11);
}

/// Go skips a zero-length `cmdPSH` with `continue`; the session keeps running.
#[tokio::test]
async fn zero_length_push_is_ignored() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let session = server(conn, Some(quiet_config(1))).expect("server");
    let budget = session.shared().bucket();

    peer.write_frame(1, CMD_PSH, 3, &[]).await;
    peer.write_frame(1, CMD_SYN, 3, &[]).await;
    let stream = timeout(PATIENCE, session.accept_stream())
        .await
        .expect("accept in time")
        .expect("accept");
    assert_eq!(stream.buffered_len(), 0);
    assert_eq!(session.shared().bucket(), budget);
}

/// Data for a stream the session does not know is read and dropped, and costs no tokens.
#[tokio::test]
async fn push_to_an_unknown_stream_is_dropped() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let session = server(conn, Some(quiet_config(1))).expect("server");
    let budget = session.shared().bucket();

    peer.write_frame(1, CMD_PSH, 99, b"orphan").await;
    peer.write_frame(1, CMD_SYN, 3, &[]).await;
    let stream = timeout(PATIENCE, session.accept_stream())
        .await
        .expect("accept in time")
        .expect("accept");
    assert_eq!(stream.id(), 3);
    assert_eq!(session.shared().bucket(), budget);
}

/// Both paths of the buffered reader deliver a payload whole: one smaller than
/// [`RECV_BUFFER_SIZE`] (32 KiB), which is copied through the buffer, and the maximum-size
/// payload (65535 bytes), which is strictly larger than the buffer and so bypasses it.
#[tokio::test]
async fn large_push_payloads_are_read_whole() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let session = server(conn, Some(quiet_config(1))).expect("server");

    peer.write_frame(1, CMD_SYN, 3, &[]).await;
    let stream = timeout(PATIENCE, session.accept_stream())
        .await
        .expect("accept in time")
        .expect("accept");

    // Buffered path: shorter than the receive buffer.
    let small: Vec<u8> = (0..RECV_BUFFER_SIZE - 1).map(|i| i as u8).collect();
    peer.write_frame(1, CMD_PSH, 3, &small).await;
    wait_until("buffered push arrives", || {
        stream.buffered_len() == small.len()
    })
    .await;
    assert_eq!(stream.buffered_bytes(), small);

    // Bypass path: strictly larger than the receive buffer.
    let big: Vec<u8> = (0..65535usize).map(|i| (i >> 3) as u8).collect();
    assert!(big.len() > RECV_BUFFER_SIZE, "must exercise the bypass");
    peer.write_frame(1, CMD_PSH, 3, &big).await;
    wait_until("large push buffered", || {
        stream.buffered_len() == small.len() + big.len()
    })
    .await;
    let mut want = small.clone();
    want.extend_from_slice(&big);
    assert_eq!(stream.buffered_bytes(), want);
}

/// `cmdFIN` marks the peer's end of data; because this side has not half-closed,
/// `tryHalfCloseCleanup` does nothing and the stream stays in the session.
#[tokio::test]
async fn fin_marks_the_stream_without_removing_it() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let session = server(conn, Some(quiet_config(1))).expect("server");

    peer.write_frame(1, CMD_SYN, 3, &[]).await;
    let stream = timeout(PATIENCE, session.accept_stream())
        .await
        .expect("accept in time")
        .expect("accept");
    assert!(!stream.got_fin());

    peer.write_frame(1, CMD_FIN, 3, &[]).await;
    wait_until("fin observed", || stream.got_fin()).await;
    assert!(!stream.is_closed(), "the half-close needs both FINs");
    assert_eq!(session.num_streams(), 1);

    // A FIN for an unknown stream is a no-op, and the session keeps reading.
    peer.write_frame(1, CMD_FIN, 99, &[]).await;
    peer.write_frame(1, CMD_SYN, 5, &[]).await;
    let other = timeout(PATIENCE, session.accept_stream())
        .await
        .expect("accept in time")
        .expect("accept");
    assert_eq!(other.id(), 5);
}

/// `cmdUPD` stores what the peer consumed and its window; the initial guess is Go's
/// `initialPeerWindow`.
#[tokio::test]
async fn upd_updates_the_peer_window() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let session = server(conn, Some(quiet_config(2))).expect("server");

    peer.write_frame(2, CMD_SYN, 3, &[]).await;
    let stream = timeout(PATIENCE, session.accept_stream())
        .await
        .expect("accept in time")
        .expect("accept");
    assert_eq!(stream.peer_state(), (0, INITIAL_PEER_WINDOW));

    peer.write_frame(2, CMD_UPD, 3, UpdHeader::new(4096, 65536).as_bytes())
        .await;
    wait_until("update observed", || stream.peer_state() == (4096, 65536)).await;

    // An update for an unknown stream is a no-op.
    peer.write_frame(2, CMD_UPD, 99, UpdHeader::new(1, 2).as_bytes())
        .await;
    peer.write_frame(2, CMD_SYN, 5, &[]).await;
    let other = timeout(PATIENCE, session.accept_stream())
        .await
        .expect("accept in time")
        .expect("accept");
    assert_eq!(other.id(), 5);
}

/// The token bucket stops `recvLoop`: once it is exhausted nothing more is processed, and
/// returning tokens restarts it.
#[tokio::test]
async fn token_bucket_blocks_and_unblocks_the_receive_loop() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let config = Config {
        max_receive_buffer: 16,
        max_stream_buffer: 16,
        ..quiet_config(1)
    };
    let session = server(conn, Some(config)).expect("server");

    peer.write_frame(1, CMD_SYN, 3, &[]).await;
    let stream = timeout(PATIENCE, session.accept_stream())
        .await
        .expect("accept in time")
        .expect("accept");

    peer.write_frame(1, CMD_PSH, 3, &[7u8; 16]).await;
    wait_until("bucket drained", || session.shared().bucket() == 0).await;

    // The next SYN is on the wire but must not be processed while the bucket is empty.
    peer.write_frame(1, CMD_SYN, 5, &[]).await;
    sleep(Duration::from_millis(100)).await;
    assert_eq!(session.num_streams(), 1, "recvLoop must be parked");

    // Returning tokens wakes it.
    session.shared().return_tokens(16);
    let other = timeout(PATIENCE, session.accept_stream())
        .await
        .expect("accept in time")
        .expect("accept");
    assert_eq!(other.id(), 5);
    assert_eq!(stream.buffered_len(), 16);
}

/// Deviation V11 / "never leak tokens": whatever a stream never delivered goes back to the
/// bucket exactly once, whether it is the handle or the session map that lets go of it last.
#[tokio::test]
async fn dropping_a_stream_returns_its_tokens() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let session = server(conn, Some(quiet_config(1))).expect("server");
    let budget = session.shared().bucket();

    peer.write_frame(1, CMD_SYN, 3, &[]).await;
    let stream = timeout(PATIENCE, session.accept_stream())
        .await
        .expect("accept in time")
        .expect("accept");
    peer.write_frame(1, CMD_PSH, 3, &[1u8; 32]).await;
    wait_until("push buffered", || stream.buffered_len() == 32).await;
    assert_eq!(session.shared().bucket(), budget - 32);

    // Dropping the last handle closes the stream: it leaves the map and pays its tokens back.
    drop(stream);
    assert_eq!(session.shared().bucket(), budget);
    assert_eq!(session.num_streams(), 0);
    // A second removal cannot double-count them.
    session.shared().stream_closed(3);
    assert_eq!(session.shared().bucket(), budget);

    // The other order: the session removes the stream first (the half-close cleanup does this,
    // deviation V11), and the handle pays the remainder back when it goes.
    peer.write_frame(1, CMD_SYN, 5, &[]).await;
    let stream = timeout(PATIENCE, session.accept_stream())
        .await
        .expect("accept in time")
        .expect("accept");
    peer.write_frame(1, CMD_PSH, 5, &[1u8; 32]).await;
    wait_until("push buffered", || stream.buffered_len() == 32).await;
    session.shared().stream_closed(5);
    assert_eq!(session.shared().bucket(), budget - 32, "still readable");
    drop(stream);
    assert_eq!(session.shared().bucket(), budget);
}

// ---------------------------------------------------------------------------------------
// sendLoop and writeFrameInternal
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn test_write_frame_internal_payload_length() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let session = client(conn, Some(quiet_config(1))).expect("client");

    let n = session
        .shared()
        .write_frame_internal(data_frame(1, CMD_PSH, 3, b"payload"), None, ClassId::Data)
        .await
        .expect("write");
    assert_eq!(n, b"payload".len());

    let (header, payload) = peer.read_frame().await.expect("frame");
    assert_eq!(header.cmd(), CMD_PSH);
    assert_eq!(header.stream_id(), 3);
    assert_eq!(header.length(), 7);
    assert_eq!(payload, b"payload");

    // An empty control frame reports 0 (Go: `n -= headerSize`, floored at 0).
    let n = session
        .shared()
        .write_frame_internal(OwnedFrame::new(1, CMD_FIN, 3), None, ClassId::Data)
        .await
        .expect("write");
    assert_eq!(n, 0);
    let (header, _) = peer.read_frame().await.expect("frame");
    assert_eq!(header.cmd(), CMD_FIN);
}

/// Go: `TestWriteStreamAfterConnectionClose` — a failing connection surfaces as the stored
/// write error and stops the send loop.
#[tokio::test]
async fn test_write_stream_after_connection_close() {
    let (ours, _peer) = tokio::io::duplex(PIPE_CAPACITY);
    let conn = FailWriteConn {
        inner: SplitConn::new(ours),
    };
    let session = client(conn, Some(quiet_config(1))).expect("client");

    let err = timeout(PATIENCE, session.open_stream())
        .await
        .expect("open returns")
        .expect_err("write failed");
    assert_eq!(err.to_string(), "broken pipe");

    // Later writers get the same stored error rather than blocking.
    let err = timeout(
        PATIENCE,
        session
            .shared()
            .write_frame_internal(OwnedFrame::new(1, CMD_NOP, 0), None, ClassId::Ctrl),
    )
    .await
    .expect("write returns")
    .expect_err("write failed");
    assert_eq!(err.to_string(), "broken pipe");
}

/// Go: the "deadline occur" block of `TestWriteFrameInternal`.
#[tokio::test]
async fn test_write_frame_internal_deadline() {
    let (ours, _peer) = tokio::io::duplex(PIPE_CAPACITY);
    let conn = BlockWriteConn {
        inner: SplitConn::new(ours),
    };
    let session = client(conn, Some(quiet_config(1))).expect("client");

    let err = timeout(
        PATIENCE,
        session.shared().write_frame_internal(
            OwnedFrame::new(1, CMD_NOP, 0),
            Some(Instant::now()),
            ClassId::Ctrl,
        ),
    )
    .await
    .expect("write returns")
    .expect_err("timeout");
    assert_eq!(err, Error::Timeout);
}

/// Go: the last block of `TestWriteFrameInternal` — a session that dies while a write is
/// waiting releases the writer with `io.ErrClosedPipe`.
#[tokio::test]
async fn test_write_frame_internal_released_by_close() {
    let (ours, _peer) = tokio::io::duplex(PIPE_CAPACITY);
    let conn = BlockWriteConn {
        inner: SplitConn::new(ours),
    };
    let session = Arc::new(client(conn, Some(quiet_config(1))).expect("client"));

    let writer = tokio::spawn({
        let shared = Arc::clone(session.shared());
        async move {
            shared
                .write_frame_internal(OwnedFrame::new(1, CMD_NOP, 0), None, ClassId::Ctrl)
                .await
        }
    });
    sleep(Duration::from_millis(50)).await;
    session.close().await.expect("close");

    let err = timeout(PATIENCE, writer)
        .await
        .expect("writer returns")
        .expect("join")
        .expect_err("closed");
    assert_eq!(err, Error::ClosedPipe);
}

/// The admission bound: Go detaches the shaper channel at `maxShaperSize` pending requests, the
/// port holds that many semaphore permits (D15). With the connection blocked, one request is in
/// flight and [`MAX_SHAPER_SIZE`] wait; the next writer has to wait for a slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shaper_admission_is_bounded() {
    let (ours, _peer) = tokio::io::duplex(PIPE_CAPACITY);
    let conn = BlockWriteConn {
        inner: SplitConn::new(ours),
    };
    let session = client(conn, Some(quiet_config(1))).expect("client");
    let shared = Arc::clone(session.shared());

    let mut writers = Vec::new();
    for _ in 0..=MAX_SHAPER_SIZE {
        let shared = Arc::clone(&shared);
        writers.push(tokio::spawn(async move {
            shared
                .write_frame_internal(OwnedFrame::new(1, CMD_NOP, 0), None, ClassId::Ctrl)
                .await
        }));
    }
    wait_until("shaper queue full", || {
        lock(&shared.shaper).len() >= MAX_SHAPER_SIZE
    })
    .await;

    // The next writer cannot get a slot, so its deadline fires in the first `select!`.
    let err = timeout(
        PATIENCE,
        shared.write_frame_internal(
            OwnedFrame::new(1, CMD_NOP, 0),
            Some(Instant::now() + Duration::from_millis(200)),
            ClassId::Ctrl,
        ),
    )
    .await
    .expect("write returns")
    .expect_err("timeout");
    assert_eq!(err, Error::Timeout);

    for writer in writers {
        writer.abort();
    }
}

/// End-to-end proof of the shaper's class rule on the wire: a control frame queued *after* a
/// data frame of the same stream still goes out first.
#[tokio::test]
async fn control_frames_overtake_data_frames_on_the_wire() {
    // A tiny pipe, so the send loop blocks inside the first frame.
    let (conn, peer) = pipe(16);
    let session = client(conn, Some(quiet_config(1))).expect("client");
    let shared = Arc::clone(session.shared());

    let first = tokio::spawn({
        let shared = Arc::clone(&shared);
        async move {
            shared
                .write_frame_internal(
                    OwnedFrame::with_data(
                        1,
                        CMD_PSH,
                        3,
                        Payload::Data(Bytes::from(vec![0xaa; 100])),
                    ),
                    None,
                    ClassId::Data,
                )
                .await
        }
    });
    sleep(Duration::from_millis(50)).await;

    let data = tokio::spawn({
        let shared = Arc::clone(&shared);
        async move {
            shared
                .write_frame_internal(data_frame(1, CMD_PSH, 3, b"D"), None, ClassId::Data)
                .await
        }
    });
    sleep(Duration::from_millis(50)).await;

    let ctrl = tokio::spawn({
        let shared = Arc::clone(&shared);
        async move {
            shared
                .write_frame_internal(data_frame(1, CMD_UPD, 3, b"C"), None, ClassId::Ctrl)
                .await
        }
    });
    sleep(Duration::from_millis(50)).await;

    let (h1, p1) = peer.read_frame().await.expect("frame 1");
    assert_eq!((h1.cmd(), p1.len()), (CMD_PSH, 100));
    let (h2, p2) = peer.read_frame().await.expect("frame 2");
    assert_eq!((h2.cmd(), p2.as_slice()), (CMD_UPD, b"C".as_slice()));
    let (h3, p3) = peer.read_frame().await.expect("frame 3");
    assert_eq!((h3.cmd(), p3.as_slice()), (CMD_PSH, b"D".as_slice()));

    for writer in [first, data, ctrl] {
        timeout(PATIENCE, writer)
            .await
            .expect("writer returns")
            .expect("join")
            .expect("write");
    }
}

// ---------------------------------------------------------------------------------------
// Keepalive
// ---------------------------------------------------------------------------------------

/// The keepalive `cmdNOP` is a control frame on stream 0 carrying the session's version.
#[tokio::test]
async fn keepalive_sends_nop_on_stream_zero() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let config = Config {
        keep_alive_disabled: false,
        keep_alive_interval: Duration::from_millis(50),
        keep_alive_timeout: Duration::from_secs(30),
        ..quiet_config(2)
    };
    let _session = client(conn, Some(config)).expect("client");

    for _ in 0..3 {
        let (header, payload) = timeout(PATIENCE, peer.read_frame())
            .await
            .expect("nop in time")
            .expect("nop");
        assert_eq!(header.version(), 2);
        assert_eq!(header.cmd(), CMD_NOP);
        assert_eq!(header.stream_id(), 0);
        assert_eq!(header.length(), 0);
        assert!(payload.is_empty());
    }
}

/// Go: `TestKeepAliveTimeout` (1 s / 2 s / 3 s), run at a tenth of the durations.
#[tokio::test]
async fn test_keep_alive_timeout() {
    let (conn, _peer) = pipe(PIPE_CAPACITY);
    let config = Config {
        keep_alive_disabled: false,
        keep_alive_interval: Duration::from_millis(100),
        keep_alive_timeout: Duration::from_millis(200),
        ..quiet_config(1)
    };
    let session = client(conn, Some(config)).expect("client");
    wait_until("keepalive timeout closes the session", || {
        session.is_closed()
    })
    .await;
}

/// Go: `TestKeepAliveBlockWriteTimeout` — a keepalive stuck in `Write` must still time the
/// session out, because the frame's deadline is the ping ticker itself.
///
/// The assertion is a *bound*, not a poll: the session must be gone one keepalive timeout after
/// it started (here at 400 ms, checked at 600 ms), exactly as in Go. Polling for several seconds
/// would pass even if a wedged session survived a random number of timeout periods, which is the
/// weakened form of the bug this Go test was written for.
#[tokio::test]
async fn test_keep_alive_block_write_timeout() {
    let (ours, _peer) = tokio::io::duplex(PIPE_CAPACITY);
    let conn = BlockWriteConn {
        inner: SplitConn::new(ours),
    };
    let keep_alive_timeout = Duration::from_millis(400);
    let config = Config {
        keep_alive_disabled: false,
        keep_alive_interval: Duration::from_millis(200),
        keep_alive_timeout,
        ..quiet_config(1)
    };
    let session = client(conn, Some(config)).expect("client");
    sleep(3 * keep_alive_timeout / 2).await;
    assert!(
        session.is_closed(),
        "a blocked keepalive must still time out"
    );
}

/// Traffic keeps the session alive: `recvLoop` sets `sessionIsActive` on every header.
///
/// The traffic period (~20 ms) is kept far below the keepalive timeout (500 ms): tests run in
/// parallel, each on its own current-thread runtime, so a scheduling stall of a few tens of
/// milliseconds must not be able to close the session and fail the test.
#[tokio::test]
async fn keepalive_does_not_close_an_active_session() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let config = Config {
        keep_alive_disabled: false,
        keep_alive_interval: Duration::from_millis(50),
        keep_alive_timeout: Duration::from_millis(500),
        ..quiet_config(1)
    };
    let session = server(conn, Some(config)).expect("server");

    let deadline = Instant::now() + Duration::from_millis(1200);
    while Instant::now() < deadline {
        peer.write_frame(1, CMD_NOP, 0, &[]).await;
        // Drain the session's own keepalive NOPs so the pipe cannot fill up.
        let _ = timeout(Duration::from_millis(10), peer.read_frame()).await;
        sleep(Duration::from_millis(10)).await;
    }
    assert!(!session.is_closed(), "traffic must keep the session alive");
}

/// Go's CAS branch: while the bucket is empty `recvLoop` is parked, so the session must not be
/// closed for lack of traffic.
#[tokio::test]
async fn keepalive_does_not_close_while_the_bucket_is_empty() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let config = Config {
        keep_alive_disabled: false,
        keep_alive_interval: Duration::from_millis(50),
        keep_alive_timeout: Duration::from_millis(100),
        max_receive_buffer: 16,
        max_stream_buffer: 16,
        ..quiet_config(1)
    };
    let session = server(conn, Some(config)).expect("server");

    peer.write_frame(1, CMD_SYN, 3, &[]).await;
    let _stream = timeout(PATIENCE, session.accept_stream())
        .await
        .expect("accept in time")
        .expect("accept");
    peer.write_frame(1, CMD_PSH, 3, &[7u8; 16]).await;
    wait_until("bucket drained", || session.shared().bucket() == 0).await;

    // Several keepalive timeouts pass with no traffic at all.
    sleep(Duration::from_millis(500)).await;
    assert!(
        !session.is_closed(),
        "a session whose recvLoop is parked on an empty bucket must stay open"
    );
}

// ---------------------------------------------------------------------------------------
// Close
// ---------------------------------------------------------------------------------------

/// Go: `TestIsClose` and `TestSessionDoubleClose`.
#[tokio::test]
async fn test_session_double_close() {
    let (conn, _peer) = pipe(PIPE_CAPACITY);
    let session = client(conn, Some(quiet_config(1))).expect("client");
    assert!(!session.is_closed());
    session.close().await.expect("first close");
    assert!(session.is_closed());
    assert_eq!(session.close().await.err(), Some(Error::ClosedPipe));
}

/// Go: `TestNumStreamAfterClose`.
#[tokio::test]
async fn test_num_stream_after_close() {
    let (conn, _peer) = pipe(PIPE_CAPACITY);
    let session = client(conn, Some(quiet_config(1))).expect("client");
    let _stream = session.open_stream().await.expect("open");
    assert_eq!(session.num_streams(), 1);
    session.close().await.expect("close");
    assert_eq!(session.num_streams(), 0);
}

/// `Session::close` calls `sessionClose` on every stream.
#[tokio::test]
async fn close_releases_every_stream() {
    let (conn, _peer) = pipe(PIPE_CAPACITY);
    let session = client(conn, Some(quiet_config(1))).expect("client");
    let a = session.open_stream().await.expect("open");
    let b = session.open_stream().await.expect("open");
    assert!(!a.is_closed());

    session.close().await.expect("close");
    assert!(a.is_closed());
    assert!(b.is_closed());
    timeout(PATIENCE, a.closed()).await.expect("die resolves");
}

/// Go: `TestSessionCloseChan`.
#[tokio::test]
async fn test_session_close_chan() {
    let (conn, _peer) = pipe(PIPE_CAPACITY);
    let session = client(conn, Some(quiet_config(1))).expect("client");
    assert!(
        timeout(Duration::from_millis(50), session.closed())
            .await
            .is_err(),
        "closed() must not resolve before the session closes"
    );
    session.close().await.expect("close");
    timeout(PATIENCE, session.closed())
        .await
        .expect("closed() resolves");
}

/// Closing the session closes the connection, which the peer sees as EOF.
#[tokio::test]
async fn close_closes_the_connection() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let session = client(conn, Some(quiet_config(1))).expect("client");
    session.close().await.expect("close");
    let mut buf = [0u8; 8];
    let n = timeout(PATIENCE, peer.conn.read(&mut buf))
        .await
        .expect("read returns")
        .expect("read");
    assert_eq!(n, 0, "the peer should see EOF");
}

/// Dropping the session closes it, so its tasks do not outlive the handle (porting guide §6).
#[tokio::test]
async fn dropping_the_session_closes_it() {
    let (conn, _peer) = pipe(PIPE_CAPACITY);
    let session = client(conn, Some(quiet_config(1))).expect("client");
    let shared = Arc::clone(session.shared());
    assert!(!shared.is_closed());
    drop(session);
    assert!(shared.is_closed());
}

// ---------------------------------------------------------------------------------------
// Addresses and bulk traffic
// ---------------------------------------------------------------------------------------

/// Go: `TestSessionAddrNonNetConn` / `TestStreamAddrNonNetConn` — a connection with no address
/// reports none.
#[tokio::test]
async fn test_session_addr_non_net_conn() {
    let (conn, _peer) = pipe(PIPE_CAPACITY);
    let session = client(conn, Some(quiet_config(1))).expect("client");
    assert_eq!(session.local_addr(), None);
    assert_eq!(session.remote_addr(), None);
    let stream = session.open_stream().await.expect("open");
    assert_eq!(stream.local_addr(), None);
    assert_eq!(stream.remote_addr(), None);
}

/// Go: `TestSessionAddr` / `TestStreamAddr`, over a loopback TCP connection.
#[tokio::test]
async fn test_session_addr() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let accepting = tokio::spawn(async move { listener.accept().await.expect("accept").0 });
    let cli = TcpStream::connect(addr).await.expect("connect");
    let srv = accepting.await.expect("join");

    let server_session = server(SplitConn::tcp(srv), Some(quiet_config(1))).expect("server");
    let client_session = client(SplitConn::tcp(cli), Some(quiet_config(1))).expect("client");

    assert!(server_session.local_addr().is_some());
    assert!(server_session.remote_addr().is_some());
    assert_eq!(client_session.remote_addr(), Some(addr));

    let stream = client_session.open_stream().await.expect("open");
    assert_eq!(stream.local_addr(), client_session.local_addr());
    assert_eq!(stream.remote_addr(), Some(addr));

    let accepted = timeout(PATIENCE, server_session.accept_stream())
        .await
        .expect("accept in time")
        .expect("accept");
    assert_eq!(accepted.id(), stream.id());
}

/// Many frames arriving in one write must all be processed: that is what the buffered reader
/// has to get right.
#[tokio::test]
async fn many_frames_in_one_write_are_all_processed() {
    let (conn, peer) = pipe(PIPE_CAPACITY);
    let session = server(conn, Some(quiet_config(1))).expect("server");

    let mut batch = Vec::new();
    for i in 0..200u32 {
        batch.extend_from_slice(&raw_frame(1, CMD_SYN, 2 * i + 1, 0, &[]));
        batch.extend_from_slice(&raw_frame(1, CMD_PSH, 2 * i + 1, 4, b"data"));
        batch.extend_from_slice(&raw_frame(1, CMD_NOP, 0, 0, &[]));
    }
    peer.write_bytes(&batch).await;

    for i in 0..200u32 {
        let stream = timeout(PATIENCE, session.accept_stream())
            .await
            .expect("accept in time")
            .expect("accept");
        assert_eq!(stream.id(), 2 * i + 1);
        wait_until("payload buffered", || stream.buffered_len() == 4).await;
    }
}

// ---------------------------------------------------------------------------------------
// Long-running ports of Go's original durations
// ---------------------------------------------------------------------------------------

/// Go's `TestKeepAliveTimeout` at its original 1 s / 2 s / 3 s.
#[tokio::test]
#[ignore = "long: Go's original keepalive durations"]
async fn long_test_keep_alive_timeout() {
    let (conn, _peer) = pipe(PIPE_CAPACITY);
    let config = Config {
        keep_alive_disabled: false,
        keep_alive_interval: Duration::from_secs(1),
        keep_alive_timeout: Duration::from_secs(2),
        ..quiet_config(1)
    };
    let session = client(conn, Some(config)).expect("client");
    sleep(Duration::from_secs(3)).await;
    assert!(session.is_closed(), "keepalive-timeout failed");
}

/// Go's `TestKeepAliveBlockWriteTimeout` at its original durations.
#[tokio::test]
#[ignore = "long: Go's original keepalive durations"]
async fn long_test_keep_alive_block_write_timeout() {
    let (ours, _peer) = tokio::io::duplex(PIPE_CAPACITY);
    let conn = BlockWriteConn {
        inner: SplitConn::new(ours),
    };
    let config = Config {
        keep_alive_disabled: false,
        keep_alive_interval: Duration::from_secs(1),
        keep_alive_timeout: Duration::from_secs(2),
        ..quiet_config(1)
    };
    let session = client(conn, Some(config)).expect("client");
    sleep(Duration::from_secs(3)).await;
    assert!(session.is_closed(), "keepalive-timeout failed");
}
