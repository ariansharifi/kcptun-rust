//! Tests for [`crate::pipe`].
//!
//! `test_pipe_bidirectional` is the port of Go's `TestPipeBidirectional`
//! (`kcptun/std/copy_test.go`), with `net.Pipe()` replaced by [`tokio::io::duplex`]. The rest
//! cover what Go's test does not: the half-close, the `closewait` delay, how errors come back,
//! and the promise of D17 that an idle connection holds no copy buffer.
//!
//! `test_pipe_over_tcp_and_unix_sockets` runs the same shutdown sequence over the two socket
//! types this crate implements [`HalfCloseWrite`] for, since `poll_close_write` must be a real
//! `shutdown(SHUT_WR)` there and nothing else would notice if it were not.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, duplex};
use tokio::time::Instant;

use super::*;

// ---------------------------------------------------------------------------------------
// A connection the test can watch and break
// ---------------------------------------------------------------------------------------

/// What the pipe did to an end of the connection, and when.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Event {
    name: &'static str,
    kind: Kind,
    at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    CloseWrite,
    Close,
}

/// How this end misbehaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    /// Every read fails with this kind.
    Read(io::ErrorKind),
    /// Every write fails with this kind.
    Write(io::ErrorKind),
    /// Every write accepts nothing, which no `io.Writer` may do.
    WriteZero,
    /// Writes succeed but the flush fails — a buffering destination losing the tail, which is why
    /// the `Flushing` phase exists at all (Step 09's smux stream and QPP wrapper).
    Flush(io::ErrorKind),
}

/// One end of a duplex pair, recording the pipe's shutdown calls.
struct TestConn {
    name: &'static str,
    inner: DuplexStream,
    log: Arc<Mutex<Vec<Event>>>,
    fault: Fault,
    closed_write: bool,
}

impl TestConn {
    fn record(&self, kind: Kind) {
        self.log
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(Event {
                name: self.name,
                kind,
                at: Instant::now(),
            });
    }
}

impl tokio::io::AsyncRead for TestConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Fault::Read(kind) = this.fault {
            return Poll::Ready(Err(io::Error::new(kind, "test read fault")));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TestConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.fault {
            Fault::Write(kind) => Poll::Ready(Err(io::Error::new(kind, "test write fault"))),
            Fault::WriteZero => Poll::Ready(Ok(0)),
            _ => Pin::new(&mut this.inner).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Fault::Flush(kind) = this.fault {
            return Poll::Ready(Err(io::Error::new(kind, "test flush fault")));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl HalfCloseWrite for TestConn {
    fn poll_close_write(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.closed_write {
            this.closed_write = true;
            this.record(Kind::CloseWrite);
        }
        // A duplex stream's shutdown closes the writing half only, like TCP's SHUT_WR.
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().record(Kind::Close);
        Poll::Ready(Ok(()))
    }
}

/// A watched end plus the raw other end of the same duplex pair.
fn conn(
    name: &'static str,
    log: &Arc<Mutex<Vec<Event>>>,
    fault: Fault,
) -> (TestConn, DuplexStream) {
    let (ours, theirs) = duplex(4096);
    (
        TestConn {
            name,
            inner: ours,
            log: Arc::clone(log),
            fault,
            closed_write: false,
        },
        theirs,
    )
}

fn events(log: &Arc<Mutex<Vec<Event>>>) -> Vec<Event> {
    log.lock().unwrap_or_else(|p| p.into_inner()).clone()
}

fn event(log: &Arc<Mutex<Vec<Event>>>, name: &str, kind: Kind) -> Option<Event> {
    events(log)
        .into_iter()
        .find(|e| e.name == name && e.kind == kind)
}

/// A pool with room for a handful of buffers; small buffers make short reads easy to count.
fn test_pool() -> BufPool {
    BufPool::new(4, 64)
}

// ---------------------------------------------------------------------------------------
// Copying
// ---------------------------------------------------------------------------------------

/// Go: kcptun/std/copy_test.go:TestPipeBidirectional
#[tokio::test]
async fn test_pipe_bidirectional() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let (alice_server, mut alice_client) = conn("alice", &log, Fault::None);
    let (bob_server, mut bob_client) = conn("bob", &log, Fault::None);
    let pool = test_pool();

    let piped = pipe_with_pool(alice_server, bob_server, 0, &pool);
    let driver = async {
        alice_client.write_all(b"hello bob").await.unwrap();
        let mut got = [0u8; 9];
        bob_client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello bob");

        bob_client.write_all(b"hi alice").await.unwrap();
        let mut got = [0u8; 8];
        alice_client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hi alice");

        // Go's test closes both client ends to end the pipe.
        drop(alice_client);
        drop(bob_client);
    };
    let ((err_a, err_b), ()) = tokio::join!(piped, driver);

    err_a.unwrap();
    err_b.unwrap();
    // Both directions half-closed their destination, and both ends were closed afterwards.
    assert!(event(&log, "alice", Kind::CloseWrite).is_some());
    assert!(event(&log, "bob", Kind::CloseWrite).is_some());
    assert!(event(&log, "alice", Kind::Close).is_some());
    assert!(event(&log, "bob", Kind::Close).is_some());
    assert!(pool.allocated() <= 2, "one buffer per direction at most");
    assert_eq!(pool.outstanding(), 0);
}

/// A payload much larger than one copy buffer, to exercise the read/write loop.
#[tokio::test]
async fn test_pipe_copies_more_than_one_buffer() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let (alice_server, mut alice_client) = conn("alice", &log, Fault::None);
    let (bob_server, mut bob_client) = conn("bob", &log, Fault::None);
    let pool = test_pool();
    let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();

    let piped = pipe_with_pool(alice_server, bob_server, 0, &pool);
    let driver = async {
        let sent = payload.clone();
        let writer = tokio::spawn(async move {
            alice_client.write_all(&sent).await.unwrap();
            alice_client.shutdown().await.unwrap();
            alice_client
        });
        let mut got = vec![0u8; payload.len()];
        bob_client.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload);
        assert_eq!(
            bob_client.read(&mut [0u8; 1]).await.unwrap(),
            0,
            "EOF after the half-close"
        );
        let alice_client = writer.await.unwrap();
        drop(bob_client);
        drop(alice_client);
    };
    let ((err_a, err_b), ()) = tokio::join!(piped, driver);

    err_a.unwrap();
    err_b.unwrap();
    assert!(
        pool.allocated() <= 2,
        "buffers are reused: {}",
        pool.allocated()
    );
    assert_eq!(pool.outstanding(), 0);
}

// ---------------------------------------------------------------------------------------
// Half-close
// ---------------------------------------------------------------------------------------

/// The end of one direction must not take the other one down: that is what `CloseWrite` buys.
#[tokio::test]
async fn test_pipe_half_close_keeps_the_reverse_direction_open() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let (alice_server, mut alice_client) = conn("alice", &log, Fault::None);
    let (bob_server, mut bob_client) = conn("bob", &log, Fault::None);
    let pool = test_pool();

    let piped = pipe_with_pool(alice_server, bob_server, 0, &pool);
    let driver = async {
        // Alice is done sending.
        alice_client.shutdown().await.unwrap();
        assert_eq!(
            bob_client.read(&mut [0u8; 1]).await.unwrap(),
            0,
            "bob sees EOF"
        );

        // Bob can still answer, and alice still receives.
        bob_client.write_all(b"late reply").await.unwrap();
        let mut got = [0u8; 10];
        alice_client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"late reply");

        drop(bob_client);
        drop(alice_client);
    };
    let ((err_a, err_b), ()) = tokio::join!(piped, driver);

    err_a.unwrap();
    err_b.unwrap();
    let bob_cw = event(&log, "bob", Kind::CloseWrite).expect("bob was half-closed");
    let alice_cw = event(&log, "alice", Kind::CloseWrite).expect("alice was half-closed");
    assert!(bob_cw.at <= alice_cw.at, "bob's direction ended first");
}

/// The same sequence over real TCP sockets, driven through [`pipe`] itself — the public entry
/// point, and the only test that uses the process-wide buffer pool rather than a per-test one.
#[tokio::test]
async fn test_pipe_uses_the_process_wide_pool() {
    let (mut alice_client, alice_server) = tcp_pair().await;
    let (bob_server, mut bob_client) = tcp_pair().await;

    let piped = pipe(alice_server, bob_server, 0);
    let driver = async {
        alice_client.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        bob_client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");

        // A real shutdown(SHUT_WR) must travel through the pipe as a shutdown, not a close.
        alice_client.shutdown().await.unwrap();
        assert_eq!(
            bob_client.read(&mut [0u8; 1]).await.unwrap(),
            0,
            "the far end sees EOF"
        );

        bob_client.write_all(b"pong").await.unwrap();
        let mut got = [0u8; 4];
        alice_client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"pong", "the reverse direction still receives");

        bob_client.shutdown().await.unwrap();
        assert_eq!(
            alice_client.read(&mut [0u8; 1]).await.unwrap(),
            0,
            "the near end sees EOF"
        );
    };
    let ((err_a, err_b), ()) = tokio::join!(piped, driver);

    err_a.unwrap();
    err_b.unwrap();
}

/// The same sequence over the socket types this module implements [`HalfCloseWrite`] for — a TCP
/// end and a unix-socket end at once, which is what the client does with `-l /path/to.sock`.
///
/// Unix only, because the unix half of it is: [`HalfCloseWrite`] is implemented for
/// `tokio::net::UnixStream` under `#[cfg(unix)]` (deviation V09 — tokio has no `UnixStream` on
/// Windows), and `-l`/`-t` reject a unix path there for the same reason.
#[cfg(unix)]
#[tokio::test]
async fn test_pipe_over_tcp_and_unix_sockets() {
    let (mut alice_client, alice_server) = tcp_pair().await;
    let (bob_server, mut bob_client) = {
        let _guard = kcptun_testkit::socket_creation_guard();
        tokio::net::UnixStream::pair().unwrap()
    };

    let piped = pipe(alice_server, bob_server, 0);
    let driver = async {
        alice_client.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        bob_client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");

        // A real shutdown(SHUT_WR) must travel through the pipe as a shutdown, not a close.
        alice_client.shutdown().await.unwrap();
        assert_eq!(
            bob_client.read(&mut [0u8; 1]).await.unwrap(),
            0,
            "the unix end sees EOF"
        );

        bob_client.write_all(b"pong").await.unwrap();
        let mut got = [0u8; 4];
        alice_client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"pong", "the TCP end still receives");

        bob_client.shutdown().await.unwrap();
        assert_eq!(
            alice_client.read(&mut [0u8; 1]).await.unwrap(),
            0,
            "the TCP end sees EOF"
        );
    };
    let ((err_a, err_b), ()) = tokio::join!(piped, driver);

    err_a.unwrap();
    err_b.unwrap();
}

/// A connected pair of local TCP sockets.
async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let listener = {
        let _guard = kcptun_testkit::socket_creation_guard();
        std::net::TcpListener::bind("127.0.0.1:0").unwrap()
    };
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    let (client, accepted) = tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
    (client.unwrap(), accepted.unwrap().0)
}

/// `-closewait` delays the half-close by that many seconds, per direction.
#[tokio::test(start_paused = true)]
async fn test_pipe_close_wait_delays_the_half_close() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let (alice_server, mut alice_client) = conn("alice", &log, Fault::None);
    let (bob_server, mut bob_client) = conn("bob", &log, Fault::None);
    let pool = test_pool();

    let piped = pipe_with_pool(alice_server, bob_server, 3, &pool);
    let driver = async {
        let started = Instant::now();
        alice_client.shutdown().await.unwrap();
        assert_eq!(bob_client.read(&mut [0u8; 1]).await.unwrap(), 0);
        let waited = Instant::now() - started;
        assert_eq!(
            waited,
            Duration::from_secs(3),
            "the half-close waits out closewait"
        );
        drop(bob_client);
        drop(alice_client);
        started
    };
    let ((err_a, err_b), started) = tokio::join!(piped, driver);

    err_a.unwrap();
    err_b.unwrap();
    let bob_cw = event(&log, "bob", Kind::CloseWrite).unwrap();
    assert_eq!(bob_cw.at - started, Duration::from_secs(3));
    // The second direction waits its own closewait after bob's end went away.
    let alice_cw = event(&log, "alice", Kind::CloseWrite).unwrap();
    assert_eq!(alice_cw.at - bob_cw.at, Duration::from_secs(3));
}

/// A non-positive `closewait` waits not at all (Go: `if closeWait > 0`).
#[tokio::test(start_paused = true)]
async fn test_pipe_close_wait_zero_does_not_wait() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let (alice_server, mut alice_client) = conn("alice", &log, Fault::None);
    let (bob_server, mut bob_client) = conn("bob", &log, Fault::None);
    let pool = test_pool();

    let piped = pipe_with_pool(alice_server, bob_server, 0, &pool);
    let driver = async {
        let started = Instant::now();
        alice_client.shutdown().await.unwrap();
        assert_eq!(bob_client.read(&mut [0u8; 1]).await.unwrap(), 0);
        assert_eq!(Instant::now() - started, Duration::ZERO);
        drop(bob_client);
        drop(alice_client);
    };
    let ((err_a, err_b), ()) = tokio::join!(piped, driver);

    err_a.unwrap();
    err_b.unwrap();
}

// ---------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------

/// A read error belongs to the direction that read: Go's `errA` is `alice -> bob`.
#[tokio::test]
async fn test_pipe_reports_read_error() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let (alice_server, alice_client) =
        conn("alice", &log, Fault::Read(io::ErrorKind::ConnectionReset));
    let (bob_server, bob_client) = conn("bob", &log, Fault::None);
    let pool = test_pool();

    let piped = pipe_with_pool(alice_server, bob_server, 0, &pool);
    let driver = async {
        drop(bob_client);
        drop(alice_client);
    };
    let ((err_a, err_b), ()) = tokio::join!(piped, driver);

    let err_a = err_a.expect_err("alice's reads fail");
    assert_eq!(err_a.kind(), io::ErrorKind::ConnectionReset);
    err_b.unwrap();
    // The failed direction still half-closes its destination.
    assert!(event(&log, "bob", Kind::CloseWrite).is_some());
}

/// A write error belongs to the direction that wrote.
#[tokio::test]
async fn test_pipe_reports_write_error() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let (alice_server, mut alice_client) = conn("alice", &log, Fault::None);
    let (bob_server, bob_client) = conn("bob", &log, Fault::Write(io::ErrorKind::BrokenPipe));
    let pool = test_pool();

    let piped = pipe_with_pool(alice_server, bob_server, 0, &pool);
    let driver = async {
        alice_client.write_all(b"ping").await.unwrap();
        drop(bob_client);
        drop(alice_client);
    };
    let ((err_a, err_b), ()) = tokio::join!(piped, driver);

    assert_eq!(
        err_a.expect_err("the write to bob fails").kind(),
        io::ErrorKind::BrokenPipe
    );
    err_b.unwrap();
}

/// A destination that accepts nothing is Go's `io.ErrShortWrite`: `io.copyBuffer` sees a
/// `(0, nil)` write, leaves `ew == nil`, trips `nr != nw` and ends the copy with `short write`,
/// which the call sites log as `pipe: short write in: … out: …`. The same text reaches the log
/// here, carried by the nearest `ErrorKind`, `WriteZero`.
#[tokio::test]
async fn test_pipe_reports_write_zero() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let (alice_server, mut alice_client) = conn("alice", &log, Fault::None);
    let (bob_server, bob_client) = conn("bob", &log, Fault::WriteZero);
    let pool = test_pool();

    let piped = pipe_with_pool(alice_server, bob_server, 0, &pool);
    let driver = async {
        alice_client.write_all(b"ping").await.unwrap();
        drop(bob_client);
        drop(alice_client);
    };
    let ((err_a, err_b), ()) = tokio::join!(piped, driver);

    let err_a = err_a.expect_err("a zero-length write is an error");
    assert_eq!(err_a.kind(), io::ErrorKind::WriteZero);
    // Go: io.ErrShortWrite.Error()
    assert_eq!(err_a.to_string(), "short write");
    err_b.unwrap();
    assert_eq!(
        pool.outstanding(),
        0,
        "the buffer goes back even on failure"
    );
}

/// The `Flushing` phase has no counterpart in Go's `copy.go`: it exists for destinations that
/// buffer, where Go's unbuffered `Write` would have failed inside `Copy` itself. So a failing
/// flush is the tail of the copy failing, and it must reach the caller's `pipe: <err>` line
/// instead of being swallowed into a successful direction.
#[tokio::test]
async fn test_pipe_reports_flush_error() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let (alice_server, mut alice_client) = conn("alice", &log, Fault::None);
    let (bob_server, mut bob_client) = conn("bob", &log, Fault::Flush(io::ErrorKind::BrokenPipe));
    let pool = test_pool();

    let piped = pipe_with_pool(alice_server, bob_server, 0, &pool);
    let driver = async {
        alice_client.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        bob_client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        drop(bob_client);
        drop(alice_client);
    };
    let ((err_a, err_b), ()) = tokio::join!(piped, driver);

    let err_a = err_a.expect_err("the flush to bob fails");
    assert_eq!(err_a.kind(), io::ErrorKind::BrokenPipe);
    err_b.unwrap();
}

/// …but it must not overwrite the error the copy already has: Go reports what `Copy` returned.
#[tokio::test]
async fn test_pipe_flush_error_does_not_mask_the_copy_error() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let (alice_server, alice_client) =
        conn("alice", &log, Fault::Read(io::ErrorKind::ConnectionReset));
    let (bob_server, bob_client) = conn("bob", &log, Fault::Flush(io::ErrorKind::BrokenPipe));
    let pool = test_pool();

    let piped = pipe_with_pool(alice_server, bob_server, 0, &pool);
    let driver = async {
        drop(bob_client);
        drop(alice_client);
    };
    let ((err_a, err_b), ()) = tokio::join!(piped, driver);

    assert_eq!(
        err_a.expect_err("the read from alice fails").kind(),
        io::ErrorKind::ConnectionReset,
        "the copy's own error wins over the later flush failure"
    );
    err_b.unwrap();
}

// ---------------------------------------------------------------------------------------
// Buffers (D17)
// ---------------------------------------------------------------------------------------

/// An idle connection must hold no copy buffer: the buffer is taken for a read and handed back
/// the moment the read finds nothing.
#[tokio::test(start_paused = true)]
async fn test_pipe_holds_no_buffer_while_idle() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let (alice_server, mut alice_client) = conn("alice", &log, Fault::None);
    let (bob_server, mut bob_client) = conn("bob", &log, Fault::None);
    let pool = test_pool();

    let piped = pipe_with_pool(alice_server, bob_server, 0, &pool);
    let driver = async {
        // Let both directions park on their reads.
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(pool.allocated() >= 1, "a read did take a buffer");
        assert_eq!(pool.outstanding(), 0, "…and gave it straight back");

        alice_client.write_all(b"data").await.unwrap();
        let mut got = [0u8; 4];
        bob_client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"data");

        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(
            pool.outstanding(),
            0,
            "nothing is held once the data is through"
        );
        assert!(pool.allocated() <= 2, "one buffer per direction at most");

        drop(alice_client);
        drop(bob_client);
    };
    let ((err_a, err_b), ()) = tokio::join!(piped, driver);

    err_a.unwrap();
    err_b.unwrap();
    assert_eq!(pool.outstanding(), 0);
}

/// The pool hands the same buffer out again, and a full pool simply drops the extra.
#[test]
fn test_buf_pool_reuses_and_bounds() {
    let pool = BufPool::new(1, 8);
    let mut first = pool.get();
    assert_eq!(first.len(), 8);
    first[0] = 7;
    assert_eq!(pool.outstanding(), 1);
    drop(first);
    assert_eq!(pool.outstanding(), 0);

    let reused = pool.get();
    assert_eq!(reused[0], 7, "the same buffer comes back");
    assert_eq!(pool.allocated(), 1, "nothing new was allocated");
    let extra = pool.get();
    assert_eq!(
        pool.allocated(),
        2,
        "the pool was empty, so this one is new"
    );

    // Only one buffer fits, so returning both keeps one and drops the other.
    drop(reused);
    drop(extra);
    assert_eq!(pool.outstanding(), 0);
    let (_kept, _fresh) = (pool.get(), pool.get());
    assert_eq!(
        pool.allocated(),
        3,
        "the buffer the full pool dropped is gone"
    );
    assert_eq!(pool.outstanding(), 2);
}

/// Capacity 0 is raised to 1 (`ArrayQueue` cannot be empty), so the pool still works and keeps
/// one buffer for reuse.
#[test]
fn test_buf_pool_zero_capacity() {
    let pool = BufPool::new(0, 4);
    let buf = pool.get();
    assert_eq!(buf.len(), 4);
    drop(buf);
    assert_eq!(pool.outstanding(), 0);

    // The returned buffer was kept, not freed.
    let reused = pool.get();
    assert_eq!(pool.allocated(), 1);
    drop(reused);
}

// ---------------------------------------------------------------------------------------
// The frame-drain fast path (Go: Copy preferring io.WriterTo)
// ---------------------------------------------------------------------------------------

/// A source that hands over whole frames, the way a smux stream does.
///
/// [`poll_read`](tokio::io::AsyncRead::poll_read) records that it was called and reports the end
/// of the stream: the pipe must never reach it for a [`HalfCloseWrite::FRAME_SOURCE`].
struct FrameConn {
    frames: std::collections::VecDeque<bytes::Bytes>,
    /// What the pipe wrote into this end.
    written: Arc<Mutex<Vec<u8>>>,
    /// Set if the buffered path was taken after all.
    read_polled: Arc<Mutex<bool>>,
    closed_write: Arc<Mutex<bool>>,
    /// Accept at most this many bytes per write, so a frame needs several.
    write_limit: usize,
}

impl FrameConn {
    fn new(frames: Vec<&[u8]>, write_limit: usize) -> FrameConn {
        FrameConn {
            frames: frames
                .into_iter()
                .map(bytes::Bytes::copy_from_slice)
                .collect(),
            written: Arc::new(Mutex::new(Vec::new())),
            read_polled: Arc::new(Mutex::new(false)),
            closed_write: Arc::new(Mutex::new(false)),
            write_limit,
        }
    }
}

impl tokio::io::AsyncRead for FrameConn {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        *self.read_polled.lock().unwrap_or_else(|p| p.into_inner()) = true;
        Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for FrameConn {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let n = buf.len().min(self.write_limit);
        self.written
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        HalfCloseWrite::poll_close_write(self, cx)
    }
}

impl HalfCloseWrite for FrameConn {
    const FRAME_SOURCE: bool = true;

    fn poll_read_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<bytes::Bytes>>> {
        Poll::Ready(Ok(self.get_mut().frames.pop_front()))
    }

    fn poll_close_write(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        *self.closed_write.lock().unwrap_or_else(|p| p.into_inner()) = true;
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn test_pipe_drains_a_frame_source_without_a_copy_buffer() {
    let pool = test_pool();
    let alice = FrameConn::new(vec![b"hello ", b"frame ", b"world"], usize::MAX);
    // A destination that takes 3 bytes at a time, so every frame needs several writes and the
    // retry must hand back the same slice.
    let bob = FrameConn::new(vec![b"reply"], 3);
    let (alice_got, bob_got) = (Arc::clone(&alice.written), Arc::clone(&bob.written));
    let alice_read = Arc::clone(&alice.read_polled);
    let bob_closed = Arc::clone(&bob.closed_write);

    let (err_a, err_b) = pipe_with_pool(alice, bob, 0, &pool).await;
    assert!(err_a.is_ok(), "{err_a:?}");
    assert!(err_b.is_ok(), "{err_b:?}");

    assert_eq!(
        &*bob_got.lock().expect("written"),
        b"hello frame world",
        "the frames arrive whole and in order"
    );
    assert_eq!(&*alice_got.lock().expect("written"), b"reply");
    assert!(
        !*alice_read.lock().expect("read_polled"),
        "a frame source must never be read into a copy buffer"
    );
    assert!(*bob_closed.lock().expect("closed_write"), "half-closed");
    // D17, sharpened: with frames on both sides the pipe allocates nothing at all.
    assert_eq!(pool.allocated(), 0);
    assert_eq!(pool.outstanding(), 0);
}

#[tokio::test]
async fn test_pipe_frame_source_to_a_buffered_destination() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let pool = test_pool();
    // One frame much larger than the duplex pipe, so the destination takes it in pieces.
    let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    let alice = FrameConn::new(vec![b"head", &payload], usize::MAX);
    let alice_read = Arc::clone(&alice.read_polled);
    let (bob, mut peer) = conn("bob", &log, Fault::None);

    let reader = tokio::spawn(async move {
        let mut got = Vec::new();
        peer.read_to_end(&mut got).await.expect("read");
        got
    });
    let (err_a, err_b) = pipe_with_pool(alice, bob, 0, &pool).await;
    assert!(err_a.is_ok(), "{err_a:?}");
    assert!(err_b.is_ok(), "{err_b:?}");

    let mut expected = b"head".to_vec();
    expected.extend_from_slice(&payload);
    assert_eq!(reader.await.expect("reader"), expected);
    assert!(!*alice_read.lock().expect("read_polled"));
    // Only the reverse direction (the duplex source) ever needs a pooled buffer.
    assert_eq!(pool.allocated(), 1);
    assert_eq!(pool.outstanding(), 0);
    assert!(event(&log, "bob", Kind::CloseWrite).is_some());
}
