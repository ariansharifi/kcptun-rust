//! Tests for [`crate::pipe`].
//!
//! `test_pipe_bidirectional` is the port of Go's `TestPipeBidirectional`
//! (`kcptun/std/copy_test.go`), with `net.Pipe()` replaced by [`tokio::io::duplex`]. The rest
//! cover what Go's test does not: the teardown rules of deviation V24 (the grace, the probes of
//! a parked pipe, the stall rule, when a close becomes a reset), how errors come back, and the
//! promise of D17 that an idle connection holds no copy buffer.
//!
//! Most cases run on tokio's paused clock with in-memory ends whose probe answers are set by the
//! test ([`Knobs`]), so every deadline is checked to the second. The last sections run the rules
//! against what they were written for: real TCP and unix sockets, and a real smux session pair.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, duplex};
use tokio::time::Instant;

use super::*;

// ---------------------------------------------------------------------------------------
// A connection the test can watch, break and describe
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
    /// [`PipeEnd::abort`]: the close will be a reset.
    Abort,
    /// The pipe dropped the end, which is its close.
    Drop,
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
    /// Writes succeed but the flush fails: a buffering destination losing the tail, which is why
    /// the `Flushing` phase exists at all (the QPP wrapper's staged ciphertext).
    Flush(io::ErrorKind),
}

/// What an end's [`PipeEnd::probe`] and [`PipeEnd::undelivered`] answer; the test changes it
/// while the pipe runs.
#[derive(Debug, Default)]
struct Knobs {
    failed: Option<io::ErrorKind>,
    finished: bool,
    starving: bool,
    unsent: Option<usize>,
    progress: Option<Progress>,
    undelivered: bool,
    /// How many times the pipe probed this end.
    probes: usize,
}

type SharedKnobs = Arc<Mutex<Knobs>>;

fn knobs(k: &SharedKnobs) -> std::sync::MutexGuard<'_, Knobs> {
    k.lock().unwrap_or_else(|p| p.into_inner())
}

/// One end of a duplex pair, recording what the pipe did to it.
struct TestConn {
    name: &'static str,
    inner: DuplexStream,
    log: Arc<Mutex<Vec<Event>>>,
    fault: Fault,
    knobs: SharedKnobs,
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

impl Drop for TestConn {
    fn drop(&mut self) {
        self.record(Kind::Drop);
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

impl PipeEnd for TestConn {
    fn probe(&self) -> Probe {
        let mut k = knobs(&self.knobs);
        k.probes += 1;
        Probe {
            failed: k.failed.map(io::Error::from),
            finished: k.finished,
            starving: k.starving,
            unsent: k.unsent,
            progress: k.progress.unwrap_or(Progress::Fine),
        }
    }

    fn undelivered(&self) -> bool {
        knobs(&self.knobs).undelivered
    }

    fn abort(&self) {
        self.record(Kind::Abort);
    }
}

/// A watched end, the raw other end of the same duplex pair, and the end's knobs.
fn conn(
    name: &'static str,
    log: &Arc<Mutex<Vec<Event>>>,
    fault: Fault,
) -> (TestConn, DuplexStream, SharedKnobs) {
    let (ours, theirs) = duplex(4096);
    let shared = SharedKnobs::default();
    (
        TestConn {
            name,
            inner: ours,
            log: Arc::clone(log),
            fault,
            knobs: Arc::clone(&shared),
        },
        theirs,
        shared,
    )
}

fn new_log() -> Arc<Mutex<Vec<Event>>> {
    Arc::new(Mutex::new(Vec::new()))
}

fn event(log: &Arc<Mutex<Vec<Event>>>, name: &str, kind: Kind) -> Option<Event> {
    log.lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .find(|e| e.name == name && e.kind == kind)
        .cloned()
}

fn aborted(log: &Arc<Mutex<Vec<Event>>>, name: &str) -> bool {
    event(log, name, Kind::Abort).is_some()
}

/// A pool with room for a handful of buffers; small buffers make short reads easy to count.
fn test_pool() -> BufPool {
    BufPool::new(4, 64)
}

/// Runs `piped` and reports when it returned.
async fn timed<F: Future>(piped: F) -> (F::Output, Instant) {
    let out = piped.await;
    (out, Instant::now())
}

/// Fills `w` until it would block, so the direction writing into the other end of `w`'s pair
/// parks. The duplex pairs here hold 4096 bytes.
async fn fill<W: tokio::io::AsyncWrite + Unpin>(w: &mut W) {
    let chunk = [0x5au8; 1024];
    while tokio::time::timeout(Duration::from_millis(10), w.write_all(&chunk))
        .await
        .is_ok()
    {}
}

// ---------------------------------------------------------------------------------------
// Copying
// ---------------------------------------------------------------------------------------

/// Go: kcptun/std/copy_test.go:TestPipeBidirectional
#[tokio::test]
async fn test_pipe_bidirectional() {
    let log = new_log();
    let (alice_server, mut alice_client, _) = conn("alice", &log, Fault::None);
    let (bob_server, mut bob_client, _) = conn("bob", &log, Fault::None);
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
    // Both ends were closed, and nothing was thrown away, so neither close is a reset.
    assert!(event(&log, "alice", Kind::Drop).is_some());
    assert!(event(&log, "bob", Kind::Drop).is_some());
    assert!(!aborted(&log, "alice") && !aborted(&log, "bob"));
    assert!(pool.allocated() <= 2, "one buffer per direction at most");
    assert_eq!(pool.outstanding(), 0);
}

/// A payload much larger than one copy buffer, to exercise the read/write loop.
#[tokio::test]
async fn test_pipe_copies_more_than_one_buffer() {
    let log = new_log();
    let (alice_server, mut alice_client, _) = conn("alice", &log, Fault::None);
    let (bob_server, mut bob_client, _) = conn("bob", &log, Fault::None);
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
            "EOF once the source has ended"
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
// Teardown (V24): closewait, then both ends
// ---------------------------------------------------------------------------------------

/// The end of one direction ends the connection: with `closewait` 0 both ends are closed at
/// once, and the other direction's late answer has nowhere to go. A half-close is not carried
/// across any more.
#[tokio::test(start_paused = true)]
async fn test_pipe_one_finished_direction_closes_both_ends() {
    let log = new_log();
    let (alice_server, mut alice_client, _) = conn("alice", &log, Fault::None);
    let (bob_server, mut bob_client, _) = conn("bob", &log, Fault::None);
    let pool = test_pool();

    let piped = timed(pipe_with_pool(alice_server, bob_server, 0, &pool));
    let driver = async {
        let started = Instant::now();
        // Alice is done sending; bob sees the end because the pipe closed his end.
        alice_client.shutdown().await.unwrap();
        assert_eq!(bob_client.read(&mut [0u8; 1]).await.unwrap(), 0);
        assert_eq!(Instant::now(), started, "closewait 0 waits for nothing");

        // Bob answers into a closed connection, and alice never sees it.
        let _ = bob_client.write_all(b"late reply").await;
        assert_eq!(alice_client.read(&mut [0u8; 16]).await.unwrap(), 0);
        started
    };
    let (((err_a, err_b), ended), started) = tokio::join!(piped, driver);

    err_a.unwrap();
    err_b.unwrap();
    assert_eq!(ended, started);
    assert_eq!(
        event(&log, "alice", Kind::Drop).map(|e| e.at),
        event(&log, "bob", Kind::Drop).map(|e| e.at),
        "both ends close together"
    );
    assert!(!aborted(&log, "alice") && !aborted(&log, "bob"));
}

/// `-closewait` is the grace between the first direction finishing and both ends closing. The
/// other direction keeps working during it.
// Go (before 2026): Pipe() sleeps closeWait after the first copy returns, then closes both.
#[tokio::test(start_paused = true)]
async fn test_pipe_close_wait_is_the_grace_before_both_ends_close() {
    let log = new_log();
    let (alice_server, mut alice_client, _) = conn("alice", &log, Fault::None);
    let (bob_server, mut bob_client, _) = conn("bob", &log, Fault::None);
    let pool = test_pool();

    let piped = timed(pipe_with_pool(alice_server, bob_server, 3, &pool));
    let driver = async {
        let started = Instant::now();
        alice_client.shutdown().await.unwrap();

        // During the grace bob's answer still reaches alice.
        tokio::time::sleep(Duration::from_secs(1)).await;
        bob_client.write_all(b"late").await.unwrap();
        let mut got = [0u8; 4];
        alice_client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"late");

        // Bob sees the end only when the grace runs out.
        assert_eq!(bob_client.read(&mut [0u8; 1]).await.unwrap(), 0);
        assert_eq!(Instant::now() - started, Duration::from_secs(3));
        started
    };
    let (((err_a, err_b), ended), started) = tokio::join!(piped, driver);

    err_a.unwrap();
    err_b.unwrap();
    assert_eq!(ended - started, Duration::from_secs(3));
    let alice_closed = event(&log, "alice", Kind::Drop).unwrap();
    assert_eq!(alice_closed.at - started, Duration::from_secs(3));
}

/// The grace is an upper bound: once both directions have finished there is nothing left to
/// wait for, so the pipe ends then.
#[tokio::test(start_paused = true)]
async fn test_pipe_ends_early_when_both_directions_finish() {
    let log = new_log();
    let (alice_server, mut alice_client, _) = conn("alice", &log, Fault::None);
    let (bob_server, mut bob_client, _) = conn("bob", &log, Fault::None);
    let pool = test_pool();

    let piped = timed(pipe_with_pool(alice_server, bob_server, 30, &pool));
    let driver = async {
        let started = Instant::now();
        alice_client.shutdown().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        bob_client.shutdown().await.unwrap();
        started
    };
    let (((err_a, err_b), ended), started) = tokio::join!(piped, driver);

    err_a.unwrap();
    err_b.unwrap();
    assert_eq!(ended - started, Duration::from_secs(1));
}

/// A non-positive `closewait` waits not at all (Go: `if closeWait > 0`).
#[tokio::test(start_paused = true)]
async fn test_pipe_negative_close_wait_does_not_wait() {
    let log = new_log();
    let (alice_server, mut alice_client, _) = conn("alice", &log, Fault::None);
    let (bob_server, _bob_client, _) = conn("bob", &log, Fault::None);
    let pool = test_pool();

    let piped = timed(pipe_with_pool(alice_server, bob_server, -5, &pool));
    let driver = async {
        let started = Instant::now();
        alice_client.shutdown().await.unwrap();
        started
    };
    let (((err_a, err_b), ended), started) = tokio::join!(piped, driver);
    err_a.unwrap();
    err_b.unwrap();
    assert_eq!(ended, started);
}

// ---------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------

/// A read error belongs to the direction that read: Go's `errA` is `alice -> bob`.
#[tokio::test]
async fn test_pipe_reports_read_error() {
    let log = new_log();
    let (alice_server, alice_client, _) =
        conn("alice", &log, Fault::Read(io::ErrorKind::ConnectionReset));
    let (bob_server, bob_client, _) = conn("bob", &log, Fault::None);
    let pool = test_pool();

    let piped = pipe_with_pool(alice_server, bob_server, 0, &pool);
    let ((err_a, err_b), ()) = tokio::join!(piped, async {});
    drop((alice_client, bob_client));

    let err_a = err_a.expect_err("alice's reads fail");
    assert_eq!(err_a.kind(), io::ErrorKind::ConnectionReset);
    err_b.unwrap();
    // The failed direction ends the connection.
    assert!(event(&log, "bob", Kind::Drop).is_some());
}

/// A write error belongs to the direction that wrote.
#[tokio::test]
async fn test_pipe_reports_write_error() {
    let log = new_log();
    let (alice_server, mut alice_client, _) = conn("alice", &log, Fault::None);
    let (bob_server, bob_client, _) = conn("bob", &log, Fault::Write(io::ErrorKind::BrokenPipe));
    let pool = test_pool();

    let piped = pipe_with_pool(alice_server, bob_server, 0, &pool);
    let driver = async {
        alice_client.write_all(b"ping").await.unwrap();
        drop(bob_client);
        alice_client
    };
    let ((err_a, err_b), _alice_client) = tokio::join!(piped, driver);

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
    let log = new_log();
    let (alice_server, mut alice_client, _) = conn("alice", &log, Fault::None);
    let (bob_server, bob_client, _) = conn("bob", &log, Fault::WriteZero);
    let pool = test_pool();

    let piped = pipe_with_pool(alice_server, bob_server, 0, &pool);
    let driver = async {
        alice_client.write_all(b"ping").await.unwrap();
        drop(bob_client);
        alice_client
    };
    let ((err_a, err_b), _alice_client) = tokio::join!(piped, driver);

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
    let log = new_log();
    let (alice_server, mut alice_client, _) = conn("alice", &log, Fault::None);
    let (bob_server, mut bob_client, _) =
        conn("bob", &log, Fault::Flush(io::ErrorKind::BrokenPipe));
    let pool = test_pool();

    let piped = pipe_with_pool(alice_server, bob_server, 0, &pool);
    let driver = async {
        alice_client.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        bob_client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        (alice_client, bob_client)
    };
    let ((err_a, err_b), _clients) = tokio::join!(piped, driver);

    let err_a = err_a.expect_err("the flush to bob fails");
    assert_eq!(err_a.kind(), io::ErrorKind::BrokenPipe);
    err_b.unwrap();
}

/// …but it must not overwrite the error the copy already has: Go reports what `Copy` returned.
#[tokio::test]
async fn test_pipe_flush_error_does_not_mask_the_copy_error() {
    let log = new_log();
    let (alice_server, alice_client, _) =
        conn("alice", &log, Fault::Read(io::ErrorKind::ConnectionReset));
    let (bob_server, bob_client, _) = conn("bob", &log, Fault::Flush(io::ErrorKind::BrokenPipe));
    let pool = test_pool();

    let (err_a, err_b) = pipe_with_pool(alice_server, bob_server, 0, &pool).await;
    drop((alice_client, bob_client));

    assert_eq!(
        err_a.expect_err("the read from alice fails").kind(),
        io::ErrorKind::ConnectionReset,
        "the copy's own error wins over the later flush failure"
    );
    err_b.unwrap();
}

// ---------------------------------------------------------------------------------------
// A parked pipe (V24 rules 5 and 6)
// ---------------------------------------------------------------------------------------

/// A pipe whose `alice -> bob` direction is parked: bob's reader never reads, so the duplex
/// toward it fills and the pipe's write into bob waits. Returns the pipe's two raw peers and
/// both ends' knobs.
struct Parked {
    alice_client: DuplexStream,
    _bob_client: DuplexStream,
    alice: SharedKnobs,
    bob: SharedKnobs,
}

fn parked_pair(log: &Arc<Mutex<Vec<Event>>>) -> (TestConn, TestConn, Parked) {
    let (alice_server, alice_client, alice) = conn("alice", log, Fault::None);
    let (bob_server, bob_client, bob) = conn("bob", log, Fault::None);
    (
        alice_server,
        bob_server,
        Parked {
            alice_client,
            _bob_client: bob_client,
            alice,
            bob,
        },
    )
}

/// Rule 5: an end that fails while nothing reads it (a TCP reset behind a write waiting for
/// credit) ends the pipe at the next probe, and is the result of the direction reading it.
#[tokio::test(start_paused = true)]
async fn test_pipe_a_source_failing_while_parked_ends_the_pipe() {
    let log = new_log();
    let (alice, bob, mut parked) = parked_pair(&log);
    let pool = test_pool();

    let piped = timed(pipe_with_pool(alice, bob, 0, &pool));
    let driver = async {
        fill(&mut parked.alice_client).await;
        // Parked and quiet: nothing to end the pipe for, however long it takes.
        tokio::time::sleep(Duration::from_secs(600)).await;
        let failed_at = Instant::now();
        knobs(&parked.alice).failed = Some(io::ErrorKind::ConnectionReset);
        (failed_at, parked)
    };
    let (((err_a, err_b), ended), (failed_at, parked)) = tokio::join!(piped, driver);

    assert_eq!(
        err_a
            .expect_err("the reset is alice's direction's result")
            .kind(),
        io::ErrorKind::ConnectionReset
    );
    err_b.unwrap();
    let delay = ended - failed_at;
    assert!(
        delay <= Timing::DEFAULT.watch,
        "seen at the next probe, {delay:?} later"
    );
    // The parked direction still held bytes for bob, so bob's close is a reset.
    assert!(aborted(&log, "bob"));
    assert!(knobs(&parked.bob).probes > 0);
}

/// The grace a probe starts is armed once: a failure that keeps showing on every later probe
/// does not push the end of the pipe back.
#[tokio::test(start_paused = true)]
async fn test_pipe_a_failure_starts_the_grace_once() {
    let log = new_log();
    let (alice, bob, mut parked) = parked_pair(&log);
    let pool = test_pool();

    let piped = timed(pipe_with_pool(alice, bob, 10, &pool));
    let driver = async {
        let started = Instant::now();
        fill(&mut parked.alice_client).await;
        tokio::time::sleep_until(started + Duration::from_millis(5_500)).await;
        knobs(&parked.alice).failed = Some(io::ErrorKind::ConnectionReset);
        (started, parked)
    };
    let (((err_a, _err_b), ended), (started, _parked)) = tokio::join!(piped, driver);

    assert!(err_a.is_err());
    // Probed at 6 s, which starts the 10 s grace.
    assert_eq!(ended - started, Duration::from_secs(16));
}

/// Rule 6: once the source has said it will send nothing more, a destination that takes
/// nothing for the stall limit (30 s for a socket) ends the pipe, with `i/o timeout`, and the
/// data still owed to it is thrown away with a reset.
#[tokio::test(start_paused = true)]
async fn test_pipe_stalls_out_after_the_source_finished() {
    let log = new_log();
    let (alice, bob, mut parked) = parked_pair(&log);
    let pool = test_pool();

    let piped = timed(pipe_with_pool(alice, bob, 0, &pool));
    let driver = async {
        let started = Instant::now();
        fill(&mut parked.alice_client).await;
        knobs(&parked.alice).finished = true;
        (started, parked)
    };
    let (((err_a, err_b), ended), (started, _parked)) = tokio::join!(piped, driver);

    let err_a = err_a.expect_err("the stalled direction reports it");
    assert_eq!(err_a.kind(), io::ErrorKind::TimedOut);
    assert_eq!(err_a.to_string(), "i/o timeout");
    err_b.unwrap();
    let after = ended - started;
    assert!(
        (Duration::from_secs(30)..=Duration::from_secs(31)).contains(&after),
        "ended after {after:?}"
    );
    assert!(
        aborted(&log, "bob"),
        "the dropped data turns bob's close into a reset"
    );
    assert!(!aborted(&log, "alice"));
}

/// A longer `closewait` lengthens the stall limit; it never shortens it.
#[tokio::test(start_paused = true)]
async fn test_pipe_stall_limit_follows_a_longer_close_wait() {
    let log = new_log();
    let (alice, bob, mut parked) = parked_pair(&log);
    let pool = test_pool();

    let piped = timed(pipe_with_pool(alice, bob, 60, &pool));
    let driver = async {
        let started = Instant::now();
        fill(&mut parked.alice_client).await;
        knobs(&parked.alice).finished = true;
        (started, parked)
    };
    let (((err_a, _), ended), (started, _parked)) = tokio::join!(piped, driver);

    assert_eq!(err_a.unwrap_err().kind(), io::ErrorKind::TimedOut);
    let after = ended - started;
    assert!(
        (Duration::from_secs(60)..=Duration::from_secs(61)).contains(&after),
        "ended after {after:?}"
    );
}

/// A reader the kernel can see consuming is alive, however slowly it goes: every probe that
/// finds the destination's send queue smaller restarts the stall clock.
#[tokio::test(start_paused = true)]
async fn test_pipe_a_draining_send_queue_is_progress() {
    let log = new_log();
    let (alice, bob, mut parked) = parked_pair(&log);
    let pool = test_pool();

    let piped = timed(pipe_with_pool(alice, bob, 0, &pool));
    let driver = async {
        let started = Instant::now();
        knobs(&parked.bob).unsent = Some(10_000);
        fill(&mut parked.alice_client).await;
        knobs(&parked.alice).finished = true;
        // One window reopened every 20 s, for two minutes.
        for step in 1..=6u64 {
            tokio::time::sleep_until(started + Duration::from_secs(20 * step)).await;
            knobs(&parked.bob).unsent = Some(10_000 - 1_000 * step as usize);
        }
        (started, parked)
    };
    let (((err_a, _), ended), (started, _parked)) = tokio::join!(piped, driver);

    assert_eq!(err_a.unwrap_err().kind(), io::ErrorKind::TimedOut);
    // The last shrink was seen at the probe at 120 s or 121 s; 30 s later the pipe ends.
    let after = ended - started;
    assert!(
        (Duration::from_secs(150)..=Duration::from_secs(152)).contains(&after),
        "ended after {after:?}"
    );
}

/// Without an end signal a parked direction is backpressure, not a stall: a reader may pause for
/// as long as it likes while the far end is still there.
#[tokio::test(start_paused = true)]
async fn test_pipe_a_parked_direction_alone_is_backpressure() {
    let log = new_log();
    let (alice, bob, mut parked) = parked_pair(&log);
    let pool = test_pool();

    fill(&mut parked.alice_client).await;
    let piped = pipe_with_pool(alice, bob, 0, &pool);
    let outcome = tokio::time::timeout(Duration::from_secs(3600), piped).await;
    assert!(outcome.is_err(), "the pipe ended on its own: {outcome:?}");
}

/// A source starving its session (smux: no frame of any stream is read until it is drained) is
/// stalled out exactly like one whose peer has finished.
#[tokio::test(start_paused = true)]
async fn test_pipe_a_starving_source_stalls_out() {
    let log = new_log();
    let (alice, bob, mut parked) = parked_pair(&log);
    let pool = test_pool();

    let piped = timed(pipe_with_pool(alice, bob, 0, &pool));
    let driver = async {
        let started = Instant::now();
        fill(&mut parked.alice_client).await;
        knobs(&parked.alice).starving = true;
        (started, parked)
    };
    let (((err_a, _), ended), (started, _parked)) = tokio::join!(piped, driver);

    assert_eq!(err_a.unwrap_err().kind(), io::ErrorKind::TimedOut);
    let after = ended - started;
    assert!(
        (Duration::from_secs(30)..=Duration::from_secs(31)).contains(&after),
        "ended after {after:?}"
    );
}

/// A smux destination's reader shows progress only as credit, half a window at a time, so its
/// stall limit is longer: two minutes, or half the window at 16 KiB/s when that is longer.
#[tokio::test(start_paused = true)]
async fn test_pipe_a_credit_destination_is_given_longer() {
    let log = new_log();
    let (alice, bob, mut parked) = parked_pair(&log);
    let pool = test_pool();

    let piped = timed(pipe_with_pool(alice, bob, 0, &pool));
    let driver = async {
        let started = Instant::now();
        knobs(&parked.bob).progress = Some(Progress::Credit {
            window: 16 * 1024 * 1024,
        });
        fill(&mut parked.alice_client).await;
        knobs(&parked.alice).finished = true;
        (started, parked)
    };
    let (((err_a, _), ended), (started, _parked)) = tokio::join!(piped, driver);

    assert_eq!(err_a.unwrap_err().kind(), io::ErrorKind::TimedOut);
    let after = ended - started;
    assert!(
        (Duration::from_secs(512)..=Duration::from_secs(513)).contains(&after),
        "ended after {after:?}"
    );
}

#[test]
fn test_timing_stall_limits() {
    let t = Timing::DEFAULT;
    assert_eq!(t.stall_limit(Progress::Fine, 0), Duration::from_secs(30));
    assert_eq!(t.stall_limit(Progress::Fine, -1), Duration::from_secs(30));
    assert_eq!(t.stall_limit(Progress::Fine, 45), Duration::from_secs(45));
    // smux's initial window, and kcptun's default `-streambuf` of 2 MiB: the 120 s floor.
    let credit = |window| Progress::Credit { window };
    assert_eq!(t.stall_limit(credit(262_144), 0), Duration::from_secs(120));
    assert_eq!(t.stall_limit(credit(2 << 20), 0), Duration::from_secs(120));
    // 16 MiB: 8 MiB at 16 KiB/s.
    assert_eq!(t.stall_limit(credit(16 << 20), 0), Duration::from_secs(512));
    assert_eq!(
        t.stall_limit(credit(16 << 20), 600),
        Duration::from_secs(600)
    );
    assert_eq!(Timing::default(), Timing::DEFAULT);
}

/// An idle connection costs nothing: no direction is parked, so the pipe never probes.
#[tokio::test(start_paused = true)]
async fn test_pipe_probes_nothing_while_idle() {
    let log = new_log();
    let (alice_server, alice_client, alice) = conn("alice", &log, Fault::None);
    let (bob_server, bob_client, bob) = conn("bob", &log, Fault::None);
    let pool = test_pool();

    let piped = pipe_with_pool(alice_server, bob_server, 0, &pool);
    let outcome = tokio::time::timeout(Duration::from_secs(600), piped).await;
    assert!(outcome.is_err(), "an idle pipe ends only when an end does");
    assert_eq!(knobs(&alice).probes, 0);
    assert_eq!(knobs(&bob).probes, 0);
    drop((alice_client, bob_client));
}

// ---------------------------------------------------------------------------------------
// Which closes are resets (rule 4)
// ---------------------------------------------------------------------------------------

/// The grace runs out while a direction still holds data for its destination: that data is
/// thrown away, so the destination's close is a reset, and the other end's close is not.
#[tokio::test(start_paused = true)]
async fn test_pipe_resets_the_end_whose_data_is_thrown_away() {
    let log = new_log();
    let (alice_server, mut alice_client, _) = conn("alice", &log, Fault::None);
    let (bob_server, mut bob_client, _) = conn("bob", &log, Fault::None);
    let pool = test_pool();

    let piped = pipe_with_pool(alice_server, bob_server, 2, &pool);
    let driver = async {
        // Bob sends more than alice's reader will ever take, so `bob -> alice` parks...
        fill(&mut bob_client).await;
        // ...and alice ends her side, which starts the grace.
        alice_client.shutdown().await.unwrap();
        (alice_client, bob_client)
    };
    let ((err_a, err_b), _clients) = tokio::join!(piped, driver);

    err_a.unwrap();
    err_b.unwrap();
    assert!(aborted(&log, "alice"), "bytes for alice were dropped");
    assert!(!aborted(&log, "bob"));
}

/// A source that still had data its reader never took (a smux stream's unread buffer, or a
/// stream cut off by its session) makes the other end's close a reset too.
#[tokio::test]
async fn test_pipe_resets_when_the_source_had_undelivered_data() {
    let log = new_log();
    let (alice_server, alice_client, alice) = conn("alice", &log, Fault::None);
    let (bob_server, bob_client, _) = conn("bob", &log, Fault::None);
    let pool = test_pool();
    knobs(&alice).undelivered = true;

    drop(alice_client);
    let (err_a, err_b) = pipe_with_pool(alice_server, bob_server, 0, &pool).await;
    err_a.unwrap();
    err_b.unwrap();
    assert!(aborted(&log, "bob"));
    assert!(!aborted(&log, "alice"));
    drop(bob_client);
}

// ---------------------------------------------------------------------------------------
// Buffers (D17)
// ---------------------------------------------------------------------------------------

/// An idle connection must hold no copy buffer: the buffer is taken for a read and handed back
/// the moment the read finds nothing.
#[tokio::test(start_paused = true)]
async fn test_pipe_holds_no_buffer_while_idle() {
    let log = new_log();
    let (alice_server, mut alice_client, _) = conn("alice", &log, Fault::None);
    let (bob_server, mut bob_client, _) = conn("bob", &log, Fault::None);
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
/// of the stream: the pipe must never reach it for a [`PipeEnd::FRAME_SOURCE`].
struct FrameConn {
    frames: std::collections::VecDeque<bytes::Bytes>,
    /// What the pipe wrote into this end.
    written: Arc<Mutex<Vec<u8>>>,
    /// Set if the buffered path was taken after all.
    read_polled: Arc<Mutex<bool>>,
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

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl PipeEnd for FrameConn {
    const FRAME_SOURCE: bool = true;

    fn poll_read_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<bytes::Bytes>>> {
        Poll::Ready(Ok(self.get_mut().frames.pop_front()))
    }

    fn probe(&self) -> Probe {
        Probe {
            failed: None,
            finished: self.frames.is_empty(),
            starving: false,
            unsent: None,
            progress: Progress::Credit { window: 262_144 },
        }
    }

    fn undelivered(&self) -> bool {
        !self.frames.is_empty()
    }

    fn abort(&self) {}
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
    // D17, sharpened: with frames on both sides the pipe allocates nothing at all.
    assert_eq!(pool.allocated(), 0);
    assert_eq!(pool.outstanding(), 0);
}

#[tokio::test]
async fn test_pipe_frame_source_to_a_buffered_destination() {
    let log = new_log();
    let pool = test_pool();
    // One frame much larger than the duplex pipe, so the destination takes it in pieces.
    let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    let alice = FrameConn::new(vec![b"head", &payload], usize::MAX);
    let alice_read = Arc::clone(&alice.read_polled);
    let (bob, mut peer, _) = conn("bob", &log, Fault::None);

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
    assert!(!aborted(&log, "bob"), "every frame was delivered");
}

// ---------------------------------------------------------------------------------------
// Real sockets
// ---------------------------------------------------------------------------------------

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

/// Polls `f` every 10 ms until it holds, for up to 5 s: a socket event reaches tokio's driver
/// asynchronously.
async fn eventually(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..500 {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    f()
}

/// Real TCP sockets through [`pipe`] itself: the public entry point, and the only test that uses
/// the process-wide buffer pool rather than a per-test one.
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

        // The end of alice's data ends the connection: both far ends see it closed.
        alice_client.shutdown().await.unwrap();
        assert_eq!(bob_client.read(&mut [0u8; 1]).await.unwrap(), 0);
        assert_eq!(alice_client.read(&mut [0u8; 1]).await.unwrap(), 0);
    };
    let ((err_a, err_b), ()) = tokio::join!(piped, driver);

    err_a.unwrap();
    err_b.unwrap();
}

/// The same over the two socket types the binaries hand the pipe at once: a TCP end and a
/// unix-socket end, which is what the client does with `-l /path/to.sock`.
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

        bob_client.write_all(b"pong").await.unwrap();
        let mut got = [0u8; 4];
        alice_client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"pong");

        bob_client.shutdown().await.unwrap();
        assert_eq!(alice_client.read(&mut [0u8; 1]).await.unwrap(), 0);
        assert_eq!(bob_client.read(&mut [0u8; 1]).await.unwrap(), 0);
    };
    let ((err_a, err_b), ()) = tokio::join!(piped, driver);

    err_a.unwrap();
    err_b.unwrap();
}

/// A TCP probe sees a FIN and an RST that arrived behind data nobody has read, without reading
/// anything: tokio keeps both bits once its driver has seen them.
#[tokio::test]
async fn test_a_tcp_probe_sees_fin_and_reset_behind_unread_data() {
    // FIN.
    let (mut client, server) = tcp_pair().await;
    let fresh = server.probe();
    assert!(fresh.failed.is_none() && !fresh.finished && !fresh.starving);
    assert_eq!(fresh.progress, Progress::Fine);
    #[cfg(unix)]
    assert_eq!(fresh.unsent, Some(0));
    client.write_all(b"unread").await.unwrap();
    client.shutdown().await.unwrap();
    assert!(
        eventually(|| server.probe().finished).await,
        "the FIN never showed"
    );
    assert!(server.probe().failed.is_none(), "a FIN is not a failure");
    // The probe consumed nothing.
    let mut server = server;
    let mut got = Vec::new();
    server.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"unread");

    // RST.
    let (mut client, server) = tcp_pair().await;
    client.write_all(b"unread").await.unwrap();
    client.set_zero_linger().unwrap();
    drop(client);
    assert!(
        eventually(|| server.probe().failed.is_some()).await,
        "the reset never showed"
    );
    // The error is named once; later probes still see the failure.
    assert!(server.probe().failed.is_some());
}

/// A unix-socket probe sees its peer go away.
#[cfg(unix)]
#[tokio::test]
async fn test_a_unix_probe_sees_the_peer_close() {
    let (ours, theirs) = {
        let _guard = kcptun_testkit::socket_creation_guard();
        tokio::net::UnixStream::pair().unwrap()
    };
    assert!(!ours.probe().finished);
    drop(theirs);
    assert!(eventually(|| ours.probe().finished).await);
    assert!(!ours.undelivered());
}

/// Fast clocks for the tests that run in real time.
const FAST: Timing = Timing {
    watch: Duration::from_millis(50),
    socket_stall: Duration::from_millis(500),
    credit_stall: Duration::from_millis(500),
    credit_rate: u32::MAX,
};

/// The production failure, at the scale of one pipe: the application resets its connection
/// while the pipe is parked writing to a destination that takes nothing. The pipe reads nothing
/// from the application then, so only the probe can see the reset.
#[tokio::test]
async fn test_a_reset_reaches_a_parked_pipe() {
    let log = new_log();
    let (mut app, tcp_end) = tcp_pair().await;
    let (stuck, _stuck_peer, _) = conn("stuck", &log, Fault::None);

    let piped =
        tokio::spawn(
            async move { pipe_with(tcp_end, stuck, 0, &BufPool::new(4, 4096), FAST).await },
        );
    // More than the duplex and the socket buffers can hold.
    let chunk = vec![0u8; 64 * 1024];
    while tokio::time::timeout(Duration::from_millis(100), app.write_all(&chunk))
        .await
        .is_ok()
    {}
    app.set_zero_linger().unwrap();
    drop(app);

    let (err_a, err_b) = tokio::time::timeout(Duration::from_secs(5), piped)
        .await
        .expect("the reset ends the pipe")
        .expect("pipe task");
    assert_eq!(
        err_a.expect_err("reported as the application's").kind(),
        io::ErrorKind::ConnectionReset
    );
    err_b.unwrap();
}

/// [`PipeEnd::abort`] really is a reset: the reader gets `ECONNRESET`, not a clean short stream.
#[tokio::test]
async fn test_an_aborted_tcp_end_resets_its_reader() {
    let log = new_log();
    let (alice, alice_client, alice_knobs) = conn("alice", &log, Fault::None);
    let (tcp_end, mut reader) = tcp_pair().await;
    knobs(&alice_knobs).undelivered = true;
    drop(alice_client);

    let (err_a, err_b) = pipe(alice, tcp_end, 0).await;
    err_a.unwrap();
    err_b.unwrap();
    let got = reader.read(&mut [0u8; 16]).await;
    assert_eq!(
        got.expect_err("a reset, not EOF").kind(),
        io::ErrorKind::ConnectionReset
    );
}

// ---------------------------------------------------------------------------------------
// Real smux streams
// ---------------------------------------------------------------------------------------

/// The leak as production saw it. The application uploads more than the stream window, so the
/// pipe parks waiting for credit, and then the far end drops the stream: its `cmdFIN` arrives,
/// no credit ever will. v0.2.1 waited here forever with the TCP socket half-closed and unread;
/// now the stream's end reaches the other direction, which finishes and ends the pipe.
#[tokio::test]
async fn test_a_stream_dropped_by_its_peer_ends_a_pipe_waiting_for_credit() {
    use crate::smuxio::tests::{session_pair, stream_pair};

    let (cli, srv) = session_pair(2);
    let (ours, theirs) = stream_pair(&cli, &srv).await;
    let (mut app, tcp_end) = tcp_pair().await;

    let piped =
        tokio::spawn(async move { pipe_with(tcp_end, ours, 0, default_buf_pool(), FAST).await });
    let chunk = vec![0u8; 64 * 1024];
    let mut sent = 0;
    while sent < 1 << 20
        && tokio::time::timeout(Duration::from_millis(200), app.write_all(&chunk))
            .await
            .is_ok()
    {
        sent += chunk.len();
    }
    // The peer never read a byte; now it goes away.
    drop(theirs);

    let (err_a, err_b) = tokio::time::timeout(Duration::from_secs(5), piped)
        .await
        .expect("the peer's FIN ends the pipe")
        .expect("pipe task");
    // The parked upload is cut, not failed; the download ended cleanly.
    err_a.unwrap();
    err_b.unwrap();
    // The application's connection is closed.
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), app.read_to_end(&mut rest))
        .await
        .expect("the application sees its connection end");
    drop((cli, srv));
}

/// Requirement 4 at the scale of one pipe: the session dies while the pipe is parked writing to
/// an application that does not read, and the application sends nothing, so no read or write of
/// the pipe touches the stream. The probe sees the stream has no future, the stall rule ends the
/// pipe, and the reset tells the application its data was cut.
#[tokio::test]
async fn test_a_dead_session_ends_a_pipe_parked_on_its_socket() {
    use crate::smuxio::tests::{session_pair, stream_pair};

    let (cli, srv) = session_pair(2);
    let (ours, mut theirs) = stream_pair(&cli, &srv).await;
    let (app, tcp_end) = tcp_pair().await;

    let piped =
        tokio::spawn(async move { pipe_with(ours, tcp_end, 0, default_buf_pool(), FAST).await });
    // The peer sends until the stream window and the socket buffers are full.
    let writer = tokio::spawn(async move {
        let chunk = vec![0u8; 64 * 1024];
        loop {
            if theirs.write_all(&chunk).await.is_err() {
                break;
            }
        }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = cli.close().await;

    let (err_a, err_b) = tokio::time::timeout(Duration::from_secs(5), piped)
        .await
        .expect("the dead session ends the pipe")
        .expect("pipe task");
    assert_eq!(
        err_a.expect_err("the stalled direction says so").kind(),
        io::ErrorKind::TimedOut
    );
    err_b.unwrap();
    let mut app = app;
    let mut got = Vec::new();
    let read = app.read_to_end(&mut got).await;
    assert_eq!(
        read.expect_err("the cut is a reset").kind(),
        io::ErrorKind::ConnectionReset
    );
    writer.abort();
    drop(srv);
}

/// A congested session cannot hold a finished pipe's socket open. The session's connection
/// takes nothing (its peer never reads), so a `cmdFIN` could wait 30 s for the send task; the
/// pipe drops its ends instead of waiting for it, and the socket is closed at once.
#[tokio::test]
async fn test_teardown_never_waits_for_a_fin_it_cannot_send() {
    use kcptun_smux::conn::SplitConn;

    let (ours_conn, _never_read) = duplex(16 * 1024);
    let cli = kcptun_smux::client(
        SplitConn::new(ours_conn),
        Some(crate::smuxio::tests::test_config(2)),
    )
    .expect("session");
    let stream = crate::smuxio::SmuxStream::new(cli.open_stream().await.expect("open"));
    let (mut app, tcp_end) = tcp_pair().await;

    let piped =
        tokio::spawn(async move { pipe_with(tcp_end, stream, 0, default_buf_pool(), FAST).await });
    let chunk = vec![0u8; 64 * 1024];
    while tokio::time::timeout(Duration::from_millis(200), app.write_all(&chunk))
        .await
        .is_ok()
    {}
    app.set_zero_linger().unwrap();
    drop(app);

    let (err_a, _err_b) = tokio::time::timeout(Duration::from_secs(5), piped)
        .await
        .expect("teardown does not wait for the FIN")
        .expect("pipe task");
    assert_eq!(err_a.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
}

/// Streams that hold all of their session's receive buffer between them starve it: no frame of
/// any stream is read, not even a `cmdFIN`, so the FIN rule can never fire. The starvation rule
/// ends the stalled pipes, their tokens go back, and the session reads again.
#[tokio::test]
async fn test_streams_starving_their_session_are_ended_and_the_session_recovers() {
    use kcptun_smux::conn::SplitConn;

    // `-smuxbuf` equal to `-streambuf`, as in the production report.
    let config = kcptun_smux::Config {
        max_receive_buffer: 65_536,
        max_stream_buffer: 65_536,
        ..crate::smuxio::tests::test_config(2)
    };
    let (a, b) = duplex(1 << 20);
    let cli = kcptun_smux::client(SplitConn::new(a), Some(config)).expect("client");
    let srv = kcptun_smux::server(SplitConn::new(b), Some(config)).expect("server");

    let log = new_log();
    let mut pipes = Vec::new();
    let mut peers = Vec::new();
    for i in 0..2 {
        let (ours, theirs) = crate::smuxio::tests::stream_pair(&cli, &srv).await;
        let name = if i == 0 { "app0" } else { "app1" };
        let (app_end, app_peer, _) = conn(name, &log, Fault::None);
        peers.push(app_peer);
        pipes.push(tokio::spawn(async move {
            pipe_with(ours, app_end, 0, default_buf_pool(), FAST).await
        }));
        // The far side fills this stream's window; the application never reads.
        let mut theirs = theirs;
        tokio::spawn(async move {
            let chunk = vec![1u8; 16 * 1024];
            while theirs.write_all(&chunk).await.is_ok() {}
        });
    }

    for piped in pipes {
        let (err_a, _err_b) = tokio::time::timeout(Duration::from_secs(10), piped)
            .await
            .expect("a starving stream is ended")
            .expect("pipe task");
        assert_eq!(err_a.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
    assert!(aborted(&log, "app0") && aborted(&log, "app1"));

    // The tokens are back, so a new stream's data gets through.
    let (mut ours, mut theirs) = tokio::time::timeout(
        Duration::from_secs(10),
        crate::smuxio::tests::stream_pair(&cli, &srv),
    )
    .await
    .expect("the session reads frames again");
    theirs.write_all(b"alive").await.expect("write");
    let mut got = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(10), ours.read_exact(&mut got))
        .await
        .expect("data arrives")
        .expect("read");
    assert_eq!(&got, b"alive");
    drop(peers);
}
