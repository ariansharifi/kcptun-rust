//! The bidirectional proxy pipe, and the buffer pool it copies through.
//!
//! Go source: `kcptun/std/copy.go`, `Pipe()` and `Copy()`. Call sites:
//! `kcptun/client/main.go:540` and `kcptun/server/main.go:530`,
//! `err1, err2 := std.Pipe(s1, s2, closeWait)`, which log every error that is not `io.EOF` as
//! `pipe: <err> in: <a> out: <b>`.
//!
//! Go runs two goroutines per proxied connection, one per direction, each with its own pooled
//! copy buffer. Here both directions live in **one task** (DECISIONS D17): [`pipe`] is a single
//! future that polls the two copies, so a connection costs one task instead of two and no
//! synchronisation between the halves is needed. The buffer is taken from a [`BufPool`] **only
//! once a read is ready to produce data** and goes straight back when the socket has nothing:
//! an idle connection holds no copy buffer at all, which Go's `io.CopyBuffer` cannot say.
//!
//! # Teardown (deviation V24, DECISIONS D35)
//!
//! **When either direction finishes, both ends are closed `close_wait` seconds later.** That is
//! what Go kcptun did until its 2026 `Pipe` switched to a per-direction half-close
//! (`closeWriter.CloseWrite()`), and what this module did up to v0.2.1. The half-close version
//! leaks: smux v1.5.55's `writeV2` waits for window credit without waking on the peer's
//! `cmdFIN`, so once the peer drops a stream, the direction writing into it waits forever, the
//! pipe never returns, and the TCP socket the other direction has already half-closed sits in
//! FIN-WAIT-2 (and later TCP_CLOSE) with its receive queue charged to `tcp_mem`. In production
//! that pinned a server at the host's TCP memory limit.
//!
//! 1. A direction is **finished** when its source reached EOF and everything read from it has
//!    been written (and flushed), or when any read, write or flush failed: that error is the
//!    direction's result, Go's `errA`/`errB`.
//! 2. The first finished direction starts the **grace**, `close_wait` seconds (none when it is
//!    not positive, like Go's `if closeWait > 0`). The other direction keeps copying meanwhile.
//!    The pipe ends when the grace runs out, or as soon as both directions have finished.
//! 3. Nothing is half-closed any more. A smux stream cannot really be half-closed anyway: its
//!    one `cmdFIN` cannot say whether the sender still reads.
//! 4. Ending the pipe **drops** both ends. A socket is `close(2)`d at once; a smux stream leaves
//!    its session synchronously and returns its unread tokens, and its `cmdFIN` follows its data
//!    from a detached task (`Drop for kcptun_smux::Stream`). Nothing waits for that frame, so a
//!    congested session cannot hold the socket open behind it. If data owed to a socket's reader
//!    is being thrown away (a direction still holds bytes, or its smux source still has data
//!    buffered or was cut off by its session dying), a TCP socket is **reset** instead
//!    ([`PipeEnd::abort`]), so the truncation reaches the application as `ECONNRESET` rather than
//!    a clean but short stream. A unix socket and a smux stream have no reset to send, so their
//!    readers see a normal end of stream either way.
//!
//! Rule 2 alone does not end every pipe, because a direction can wait on its destination
//! forever without either end telling it anything. While a direction is **parked** (its last
//! write or flush returned `Pending`) the pipe probes both ends once per [`Timing::watch`]
//! ([`PipeEnd::probe`]), without reading or writing them:
//!
//! 5. **A failed end** (a socket that was reset or timed out by TCP keepalive) counts as its
//!    direction finishing: it starts the grace and is that direction's result. A parked direction
//!    does not read its source, so it would not see the RST itself.
//! 6. **A stall after the far end has stopped:** a direction parked on a **socket** whose source
//!    will send nothing more (a smux `cmdFIN`, a dead session, a failed session receive side), or
//!    whose source is a smux stream starving its session (the session's receive buffer is spent
//!    and this stream holds at least a quarter of it, so no frame of any stream is read, not
//!    even a `cmdFIN`), ends the pipe once that has been true, and nothing has moved in either
//!    direction, for the stall limit: `close_wait`, but at least [`Timing::socket_stall`] (30 s).
//!    The stalled direction reports `i/o timeout`, and the socket is reset (rule 4). "Moved"
//!    means a byte written by either direction, or the socket's kernel send queue shrinking: a
//!    reader the kernel can see consuming is alive however slowly it goes. The clock starts at
//!    the later of the last movement and the first probe that saw the end signal, and a
//!    starvation that lifts in between starts it again, so a reader that was merely paused is
//!    given the full limit after the far end stops, and a brief dip in a busy session ends
//!    nothing.
//!
//!    A direction parked on a **smux stream** is never ended this way. Its reader's progress
//!    shows only as credit, granted once per half window, so a slow reader cannot be told from a
//!    stuck one; and ending it could only send a `cmdFIN`, which the far application would read
//!    as a complete stream. Such a pipe ends when the stream's peer goes (its `cmdFIN` ends the
//!    other direction), when the session dies, or when the socket fails (rule 5).
//!
//! What this gives up, deliberately: an application that half-closes and then waits for an
//! answer gets its connection closed `close_wait` seconds after its half-close (immediately with
//! the client's default of 0), exactly as with Go kcptun before 2026; that includes the part of
//! an answer still on its way when the application half-closed. And a reader that takes nothing
//! for 30 s after the far end has stopped, or while its unread data starves its session, loses
//! the tail it never read.
//!
//! Step 09.1 added the other half of Go's `Copy`, the `io.WriterTo` fast path: a source whose
//! [`PipeEnd::FRAME_SOURCE`] is `true` is drained frame by frame through
//! [`poll_read_frame`](PipeEnd::poll_read_frame) and never takes a copy buffer at all.
//! [`SmuxStream`](crate::smuxio::SmuxStream) is such a source (Go:
//! [`Stream::write_to`](kcptun_smux::Stream::write_to)); the QPP wrapper is not, exactly as in
//! Go, where `QPPPort` has no `WriteTo`.

use std::future::Future;
use std::io;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::{Buf as _, Bytes};
use crossbeam_queue::ArrayQueue;
use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf, Ready};
use tokio::time::{Instant, Sleep};

// ---------------------------------------------------------------------------------------
// Buffer pool
// ---------------------------------------------------------------------------------------

/// Size of one copy buffer, and so the largest read a direction issues.
///
/// Go's `std.Copy` uses a 4 KiB pooled buffer, but only where neither side offers `WriteTo` or
/// `ReadFrom`. `Copy` prefers `src.(io.WriterTo)`, so a TCP source goes through
/// `(*net.TCPConn).WriteTo`, whose `splice` fast path applies only when the destination is another
/// `*TCPConn` (and it sizes the pipe at 1 MiB: `internal/poll/splice_linux.go`,
/// `maxSpliceSize = 1<<20`). For kcptun's TCP<->smux pairs it falls through to `genericWriteTo` ->
/// `io.Copy`, whose default buffer is 32 KiB (`io/io.go:418`), so Go's pooled 4 KiB `bufSize` is
/// not what the real TCP path uses. 32 KiB is the same amount of work per
/// syscall, and with buffers pooled and handed out only on demand (D17) the memory it costs is
/// paid by active connections only. Step 12 tunes this against the Go binaries.
pub const COPY_BUF_SIZE: usize = 32 * 1024;

/// How many buffers the process-wide pool keeps for reuse; beyond this, a returned buffer is
/// dropped. Buffers are allocated on demand, so this is a ceiling, not a reservation.
pub const DEFAULT_POOL_CAPACITY: usize = 1024;

/// A pool of copy buffers.
///
/// Go: `copy.go:bufPool`, a `sync.Pool` of 4 KiB slices. This one is bounded and lock-free, like
/// the packet-buffer pool of D06, and counts what it hands out so that tests can prove buffers are
/// not held while a connection is idle.
// Go: kcptun/std/copy.go:bufPool
pub struct BufPool {
    free: ArrayQueue<Box<[u8]>>,
    buf_size: usize,
    outstanding: AtomicUsize,
    allocated: AtomicUsize,
}

impl BufPool {
    /// A pool that keeps up to `capacity` buffers of `buf_size` bytes.
    pub fn new(capacity: usize, buf_size: usize) -> BufPool {
        BufPool {
            // `ArrayQueue::new` panics on 0, so a capacity of 0 is raised to 1: such a pool still
            // works, and keeps one buffer for reuse rather than none.
            free: ArrayQueue::new(capacity.max(1)),
            buf_size,
            outstanding: AtomicUsize::new(0),
            allocated: AtomicUsize::new(0),
        }
    }

    /// Takes a buffer, reusing a returned one when there is one. The buffer goes back to the pool
    /// when the handle is dropped.
    ///
    /// The contents are whatever the previous user left; every caller fills before it reads.
    pub fn get(&self) -> PooledBuf<'_> {
        let buf = self.free.pop().unwrap_or_else(|| {
            self.allocated.fetch_add(1, Ordering::Relaxed);
            vec![0u8; self.buf_size].into_boxed_slice()
        });
        self.outstanding.fetch_add(1, Ordering::Relaxed);
        PooledBuf {
            pool: self,
            buf: Some(buf),
        }
    }

    /// How many buffers are checked out right now.
    pub fn outstanding(&self) -> usize {
        self.outstanding.load(Ordering::Relaxed)
    }

    /// How many buffers this pool has ever allocated: the high-water mark of concurrent use.
    pub fn allocated(&self) -> usize {
        self.allocated.load(Ordering::Relaxed)
    }
}

/// A buffer borrowed from a [`BufPool`], returned when it is dropped.
pub struct PooledBuf<'p> {
    pool: &'p BufPool,
    /// Always `Some` until [`Drop`] takes it.
    buf: Option<Box<[u8]>>,
}

impl Deref for PooledBuf<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.buf
            .as_deref()
            .expect("the buffer is taken only by Drop")
    }
}

impl DerefMut for PooledBuf<'_> {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.buf
            .as_deref_mut()
            .expect("the buffer is taken only by Drop")
    }
}

impl Drop for PooledBuf<'_> {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            self.pool.outstanding.fetch_sub(1, Ordering::Relaxed);
            // A full pool drops the buffer, like `sync.Pool` dropping on GC.
            let _ = self.pool.free.push(buf);
        }
    }
}

/// The process-wide copy-buffer pool, Go's package-level `bufPool`.
pub fn default_buf_pool() -> &'static BufPool {
    static POOL: OnceLock<BufPool> = OnceLock::new();
    POOL.get_or_init(|| BufPool::new(DEFAULT_POOL_CAPACITY, COPY_BUF_SIZE))
}

// ---------------------------------------------------------------------------------------
// The ends of a pipe
// ---------------------------------------------------------------------------------------

/// How a destination shows that its reader is taking data, which decides whether the stall rule
/// may ever call that reader stuck (module docs, rule 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    /// A socket: every window its reader reopens shows in [`Probe::unsent`] (on Linux, in steps of
    /// roughly the reader's receive window divided by 16, or one segment, whichever is larger).
    Fine,
    /// A smux v2 stream: its reader's progress arrives as credit, one `cmdUPD` per half window
    /// consumed, so a slow reader can show nothing for minutes. The stall rule leaves it alone.
    Credit,
}

/// What a pipe learns about one of its ends without reading or writing it ([`PipeEnd::probe`]).
#[derive(Debug)]
pub struct Probe {
    /// The connection has failed: reset by its peer, or timed out by TCP keepalive. The error is
    /// what the pipe reports for the direction that reads this end.
    pub failed: Option<io::Error>,
    /// The far side will send nothing more on this end: a socket's FIN arrived, or a smux stream
    /// got its `cmdFIN`, was closed, or lost its session. What is already queued stays readable.
    pub finished: bool,
    /// This end holds received data its reader has not taken while its session's receive buffer
    /// is spent, so the session reads nothing else until this end is drained (smux only).
    pub starving: bool,
    /// Bytes written into this end that its reader has not consumed yet (the kernel send queue),
    /// when the platform can tell.
    pub unsent: Option<usize>,
    /// How progress shows when this end is a direction's destination.
    pub progress: Progress,
}

/// A connection [`pipe`] can copy between: readable, writable, and inspectable without being
/// read.
///
/// Go's `Pipe` takes an `io.ReadWriteCloser`. Deviation V24 needs three things Go never asks
/// for: a look at an end while no direction is reading it ([`probe`](Self::probe)), whether
/// ending now would throw away data meant for the other end's reader
/// ([`undelivered`](Self::undelivered)), and a way to make the close abortive
/// ([`abort`](Self::abort)). They have no default, so that a wrapper (the QPP stream) has to
/// forward them instead of silently reporting nothing.
///
/// Implemented for [`tokio::net::TcpStream`] and [`tokio::net::UnixStream`] here, and for
/// [`SmuxStream`](crate::smuxio::SmuxStream) and `QppStream` (`crate::qpp`, feature `qpp`) in
/// their own modules.
pub trait PipeEnd: AsyncRead + AsyncWrite {
    /// Whether this type drains whole frames through
    /// [`poll_read_frame`](Self::poll_read_frame) instead of being read into a copy buffer.
    ///
    /// Go's `Copy` asks the same question at run time, `if wt, ok := src.(io.WriterTo)`, and a
    /// smux stream answers yes: `stream.WriteTo(dst)` hands each received frame straight to the
    /// destination without ever filling a copy buffer. The QPP wrapper answers no: it has no
    /// `WriteTo` in Go either, so a QPP stream takes the buffered path here as it does there.
    // Go: kcptun/std/copy.go:Copy(), `if wt, ok := src.(io.WriterTo)`
    const FRAME_SOURCE: bool = false;

    /// The next received frame, or `None` at the end of the stream.
    ///
    /// Only called when [`FRAME_SOURCE`](Self::FRAME_SOURCE) is `true`; the default is the
    /// answer for a type that has no frames, and [`pipe`] never asks it. An empty frame means
    /// "nothing this time", not the end of the stream.
    // Go: smux@v1.5.55 stream.go:stream.WriteTo(), the body of its read loop
    fn poll_read_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<Bytes>>> {
        Poll::Ready(Ok(None))
    }

    /// Looks at this end without reading or writing it. The pipe calls it at most once per
    /// [`Timing::watch`], and only while one of its directions is parked.
    fn probe(&self) -> Probe;

    /// Whether ending the pipe now would throw away data this end received for the other end's
    /// reader, or this end's data was cut off before its real end: for a smux stream, data
    /// received and not yet taken, or a stream whose session died before the peer's `cmdFIN`.
    /// A socket keeps nothing of its own, so it answers `false`.
    fn undelivered(&self) -> bool;

    /// Makes dropping this end an abortive close: a TCP socket sends RST and frees its queues
    /// instead of sending a FIN behind data its reader will never take. Ends with no such thing
    /// ignore it: a smux stream has no reset frame (its peer sees the `cmdFIN` of the drop), and
    /// a unix socket has none either (its reader sees a clean end of stream), so neither can tell
    /// its reader that data was thrown away.
    fn abort(&self);
}

/// The readiness tokio has already recorded for a socket, without waiting and without consuming
/// anything. tokio keeps `READ_CLOSED` and `ERROR` once the driver has seen them (only the
/// read/write bits are ever cleared, and only by an I/O call), so a FIN or an RST that arrived
/// behind unread data still shows. The future is polled once with a no-op waker and dropped,
/// which leaves no waiter behind.
fn socket_readiness<F: Future<Output = io::Result<Ready>>>(ready: F) -> Ready {
    let mut ready = std::pin::pin!(ready);
    match ready.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(Ok(ready)) => ready,
        _ => Ready::EMPTY,
    }
}

/// [`PipeEnd::probe`] for a socket, from its recorded readiness.
///
/// `ERROR` is raised only for the hard error of a dead connection (Linux `tcp_poll`: `sk_err`),
/// never for the transient ICMP errors that `SO_ERROR` also reports and clears (`sk_err_soft`),
/// so `SO_ERROR` is read only after `ERROR` is seen, and only to name the cause.
fn probe_socket(
    ready: Ready,
    take_error: impl FnOnce() -> io::Result<Option<io::Error>>,
    unsent: Option<usize>,
) -> Probe {
    Probe {
        failed: ready.is_error().then(|| {
            take_error()
                .ok()
                .flatten()
                .unwrap_or_else(|| io::Error::from(io::ErrorKind::ConnectionReset))
        }),
        finished: ready.is_read_closed(),
        starving: false,
        unsent,
        progress: Progress::Fine,
    }
}

/// The socket's unconsumed send queue, or `None` where the platform cannot tell.
#[cfg(unix)]
fn send_queue_len<S: std::os::fd::AsFd>(socket: &S) -> Option<usize> {
    kcptun_kcp::sockinfo::send_queue_len(socket.as_fd())
        .ok()
        .flatten()
}

impl PipeEnd for tokio::net::TcpStream {
    fn probe(&self) -> Probe {
        let ready = socket_readiness(self.ready(Interest::READABLE | Interest::ERROR));
        #[cfg(unix)]
        let unsent = send_queue_len(self);
        #[cfg(not(unix))]
        let unsent = None;
        probe_socket(ready, || self.take_error(), unsent)
    }

    fn undelivered(&self) -> bool {
        false
    }

    fn abort(&self) {
        // `SO_LINGER {on, 0}`: the close then sends RST and discards both queues, so a reader
        // that stopped reading neither gets a clean EOF after a short stream nor keeps an orphan
        // holding a full send buffer alive for minutes.
        let _ = self.set_zero_linger();
    }
}

/// The unix socket the client accepts on when `-l` is a path, and the server dials when `-t` is.
#[cfg(unix)]
impl PipeEnd for tokio::net::UnixStream {
    fn probe(&self) -> Probe {
        let ready = socket_readiness(self.ready(Interest::READABLE | Interest::ERROR));
        probe_socket(ready, || self.take_error(), send_queue_len(self))
    }

    fn undelivered(&self) -> bool {
        false
    }

    fn abort(&self) {}
}

// ---------------------------------------------------------------------------------------
// Pipe
// ---------------------------------------------------------------------------------------

/// The pipe's clocks (deviation V24). [`Timing::DEFAULT`] is what the binaries run; tests shrink
/// it so that a stall does not take half a minute of real time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    /// How often a pipe with a parked direction probes its ends.
    pub watch: Duration,
    /// The shortest stall the stall rule waits out before ending a pipe whose stalled
    /// destination is a socket.
    pub socket_stall: Duration,
}

impl Timing {
    /// What the binaries run.
    pub const DEFAULT: Timing = Timing {
        watch: Duration::from_secs(1),
        socket_stall: Duration::from_secs(30),
    };

    /// How long the stall rule waits, with `-closewait` set to `close_wait`, before ending a pipe
    /// whose stalled destination shows progress this way; `None` for a destination it never ends
    /// a pipe on (a smux stream). `-closewait` can only lengthen it.
    pub fn stall_limit(&self, progress: Progress, close_wait: i64) -> Option<Duration> {
        match progress {
            Progress::Fine => Some(self.socket_stall.max(close_wait_duration(close_wait))),
            Progress::Credit => None,
        }
    }
}

impl Default for Timing {
    fn default() -> Timing {
        Timing::DEFAULT
    }
}

/// `-closewait` as a duration; values `<= 0` mean none, like Go's `if closeWait > 0`.
fn close_wait_duration(close_wait: i64) -> Duration {
    Duration::from_secs(close_wait.max(0).unsigned_abs())
}

/// Copies between `alice` and `bob` until the connection is over, and returns what each
/// direction reported.
///
/// `close_wait` is `-closewait` in seconds: how long the pipe goes on after the first direction
/// finishes, before both ends are closed (module docs). Values `<= 0` mean no wait, like Go's
/// `if closeWait > 0 { time.Sleep(...) }`.
///
/// The returned pair is Go's `(errA, errB)`: `errA` for `alice -> bob`, `errB` for
/// `bob -> alice`. A source that ends cleanly, and a direction still copying when the pipe ends,
/// yield `Ok(())` (Go's `io.Copy` swallows `io.EOF` the same way); anything else (a read error, a
/// write error, a peer reset, a stall) is the `Err` the caller logs.
///
/// Both ends are consumed and closed, as Go closes both before `Pipe` returns.
// Go: kcptun/std/copy.go:Pipe()
pub async fn pipe<A, B>(alice: A, bob: B, close_wait: i64) -> (io::Result<()>, io::Result<()>)
where
    A: PipeEnd + Unpin,
    B: PipeEnd + Unpin,
{
    pipe_with(alice, bob, close_wait, default_buf_pool(), Timing::DEFAULT).await
}

/// [`pipe`], copying through `pool` instead of the process-wide one.
// Go: kcptun/std/copy.go:Pipe()
pub async fn pipe_with_pool<A, B>(
    alice: A,
    bob: B,
    close_wait: i64,
    pool: &BufPool,
) -> (io::Result<()>, io::Result<()>)
where
    A: PipeEnd + Unpin,
    B: PipeEnd + Unpin,
{
    pipe_with(alice, bob, close_wait, pool, Timing::DEFAULT).await
}

/// [`pipe`], copying through `pool` and running on `timing`'s clocks.
// Go: kcptun/std/copy.go:Pipe()
pub async fn pipe_with<A, B>(
    mut alice: A,
    mut bob: B,
    close_wait: i64,
    pool: &BufPool,
    timing: Timing,
) -> (io::Result<()>, io::Result<()>)
where
    A: PipeEnd + Unpin,
    B: PipeEnd + Unpin,
{
    // Go: go streamCopy(bob, alice, &errA); go streamCopy(alice, bob, &errB)
    let mut a_to_b = Transfer::new(pool);
    let mut b_to_a = Transfer::new(pool);
    let mut life = Lifetime::new(close_wait, timing);
    std::future::poll_fn(|cx| {
        let _ = a_to_b.poll_transfer(cx, &mut alice, &mut bob);
        let _ = b_to_a.poll_transfer(cx, &mut bob, &mut alice);
        life.poll(cx, &mut a_to_b, &mut b_to_a, &alice, &bob)
    })
    .await;

    // Go: alice.Close(); bob.Close(), both errors discarded. Dropping is the close for every end
    // (rule 4): nothing waits for a smux `cmdFIN`, which a congested session could hold for 30 s.
    // Data owed to a socket's reader that is about to be thrown away makes that close a reset.
    if a_to_b.holds_data() || alice.undelivered() {
        bob.abort();
    }
    if b_to_a.holds_data() || bob.undelivered() {
        alice.abort();
    }
    let results = (a_to_b.into_result(), b_to_a.into_result());
    drop(alice);
    drop(bob);
    results
}

/// Where one direction is in its life.
enum Phase {
    /// Reading the source and writing the destination.
    Copying,
    /// The copy is over; flushing whatever the destination buffered.
    Flushing,
    /// Finished; `result` is final unless the pipe reports a stall on it.
    Done,
}

/// One direction of the pipe: Go's `streamCopy` goroutine as a state machine.
// Go: kcptun/std/copy.go:Pipe.streamCopy()
struct Transfer<'p> {
    pool: &'p BufPool,
    /// Held only between a read that produced data and the write that drains it, and while a
    /// read is in flight. A direction waiting for its source to speak holds nothing (D17).
    buf: Option<PooledBuf<'p>>,
    /// Bytes `pos..cap` of `buf` are read and not yet written.
    pos: usize,
    cap: usize,
    /// The frame a [`PipeEnd::FRAME_SOURCE`] handed over, still being written out. Such a
    /// direction never takes a buffer from the pool at all: the bytes the source already owns
    /// go straight to the destination, which is what Go's `WriteTo` fast path does.
    frame: Option<Bytes>,
    /// Whether a write has happened since the last flush, so that a destination which buffers
    /// does not hold data while the source is quiet. tokio's `io::copy` keeps the same flag
    /// (`CopyBuffer::need_flush`) for the same reason; Go never needs it, because its
    /// destinations are unbuffered connections.
    need_flush: bool,
    phase: Phase,
    /// Whether the last poll ended waiting for the destination to take data (a write or a flush
    /// returned `Pending`). The pipe probes its ends only while a direction is parked.
    parked: bool,
    /// When the destination last took bytes, or when the pipe started.
    moved_at: Instant,
    /// Go: `*err`, the result of `Copy(dst, src)`. The first error sticks.
    result: io::Result<()>,
}

impl<'p> Transfer<'p> {
    fn new(pool: &'p BufPool) -> Transfer<'p> {
        Transfer {
            pool,
            buf: None,
            pos: 0,
            cap: 0,
            frame: None,
            need_flush: false,
            phase: Phase::Copying,
            parked: false,
            moved_at: Instant::now(),
            result: Ok(()),
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.phase, Phase::Done)
    }

    /// Whether bytes read from the source have not all been written to the destination.
    fn holds_data(&self) -> bool {
        self.frame.is_some() || self.pos < self.cap
    }

    /// Records `err` as this direction's result unless it already has one, Go's `*err`. Used
    /// for what the pipe sees from outside the copy too (a reset source, a stall): the copy
    /// itself carries on until the pipe ends.
    fn report(&mut self, err: io::Error) {
        if self.result.is_ok() {
            self.result = Err(err);
        }
    }

    /// The copy failed: record why and move on to the flush.
    fn fail(&mut self, err: io::Error) {
        self.report(err);
        self.end_copy();
    }

    /// The copy is over (cleanly or not): drop the buffer and move on to the shutdown sequence.
    fn end_copy(&mut self) {
        self.buf = None;
        self.pos = 0;
        self.cap = 0;
        self.frame = None;
        self.phase = Phase::Flushing;
    }

    /// The destination took `n > 0` bytes.
    fn wrote(&mut self) {
        self.need_flush = true;
        self.moved_at = Instant::now();
    }

    /// The destination is not ready: wait for it, and let the pipe know.
    fn park(&mut self) -> Poll<()> {
        self.parked = true;
        Poll::Pending
    }

    fn into_result(self) -> io::Result<()> {
        self.result
    }

    /// The source has gone quiet, so this is where a buffering destination would otherwise sit
    /// on data indefinitely: nothing polls it again until the source speaks. Flush it, as
    /// tokio's `io::copy` does on the same edge. A failed flush is the tail of the copy failing,
    /// which Go's unbuffered `Write` would have reported from `Copy` itself.
    fn flush_while_quiet<D>(&mut self, cx: &mut Context<'_>, dst: &mut D) -> Option<io::Error>
    where
        D: AsyncWrite + Unpin,
    {
        self.parked = false;
        if !self.need_flush {
            return None;
        }
        match Pin::new(dst).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                self.need_flush = false;
                None
            }
            Poll::Ready(Err(e)) => Some(e),
            Poll::Pending => {
                self.parked = true;
                None
            }
        }
    }

    /// Drives this direction as far as it can go without blocking.
    fn poll_transfer<S, D>(&mut self, cx: &mut Context<'_>, src: &mut S, dst: &mut D) -> Poll<()>
    where
        S: PipeEnd + Unpin,
        D: PipeEnd + Unpin,
    {
        loop {
            match &mut self.phase {
                // Go: `Copy` prefers `src.(io.WriterTo)`, i.e. `stream.WriteTo(dst)` for a smux
                // stream: received frames are written out as they are, with no copy buffer
                // between them. The branch is decided at compile time by the source type, the
                // way Go decides it by the type assertion.
                Phase::Copying if S::FRAME_SOURCE => {
                    if let Some(frame) = &self.frame {
                        let written = match Pin::new(&mut *dst).poll_write(cx, frame) {
                            Poll::Ready(written) => written,
                            Poll::Pending => return self.park(),
                        };
                        self.parked = false;
                        match written {
                            // Go: `io.ErrShortWrite`, as in the buffered branch below.
                            Ok(0) => self.fail(short_write()),
                            Ok(n) => {
                                let frame = self.frame.as_mut().expect("just checked");
                                frame.advance(n);
                                if frame.is_empty() {
                                    self.frame = None;
                                }
                                self.wrote();
                            }
                            Err(e) => self.fail(e),
                        }
                        continue;
                    }

                    match Pin::new(&mut *src).poll_read_frame(cx) {
                        Poll::Pending => {
                            // As in the buffered branch: a destination that buffers must not sit
                            // on data while the source is quiet.
                            if let Some(e) = self.flush_while_quiet(cx, dst) {
                                self.fail(e);
                                continue;
                            }
                            return Poll::Pending;
                        }
                        // An empty frame is not the end of the stream; ask again.
                        Poll::Ready(Ok(Some(frame))) if frame.is_empty() => {}
                        Poll::Ready(Ok(Some(frame))) => self.frame = Some(frame),
                        // Go: `WriteTo` returns `(n, io.EOF)`, which `Copy` reports as a clean end.
                        Poll::Ready(Ok(None)) => self.end_copy(),
                        Poll::Ready(Err(e)) => self.fail(e),
                    }
                }
                Phase::Copying => {
                    if self.pos < self.cap {
                        // Go's `io.Copy` demands the whole slice in one `Write` and calls a
                        // short one `io.ErrShortWrite`; `AsyncWrite` is allowed to take part of
                        // it, so the rest is offered again.
                        let written = {
                            let buf = self.buf.as_ref().expect("filled by the read below");
                            match Pin::new(&mut *dst).poll_write(cx, &buf[self.pos..self.cap]) {
                                Poll::Ready(written) => written,
                                Poll::Pending => return self.park(),
                            }
                        };
                        self.parked = false;
                        match written {
                            // Go: `io.copyBuffer` leaves `ew == nil` for a `(0, nil)` write and
                            // then trips `nr != nw`, so `Pipe` returns `io.ErrShortWrite` and the
                            // call sites log `pipe: short write in: … out: …`.
                            Ok(0) => self.fail(short_write()),
                            Ok(n) => {
                                self.pos += n;
                                self.wrote();
                            }
                            Err(e) => self.fail(e),
                        }
                        continue;
                    }

                    // Nothing pending: take a buffer, read, and give it straight back if the
                    // source has nothing to say.
                    let buf = self.buf.get_or_insert_with(|| self.pool.get());
                    let mut read_buf = ReadBuf::new(&mut buf[..]);
                    let read = Pin::new(&mut *src).poll_read(cx, &mut read_buf);
                    let filled = read_buf.filled().len();
                    match read {
                        // tokio's contract forbids a `Pending` that filled the buffer, but this
                        // trait is implemented by other crates (Step 09: smux, the QPP wrapper),
                        // so keep any bytes instead of dropping them: the read registered a waker
                        // and the next poll writes them out.
                        Poll::Pending => {
                            if filled == 0 {
                                self.buf = None;
                            } else {
                                self.pos = 0;
                                self.cap = filled;
                            }
                            if let Some(e) = self.flush_while_quiet(cx, dst) {
                                self.fail(e);
                                continue;
                            }
                            return Poll::Pending;
                        }
                        // Go: `nr == 0, err == io.EOF`, the copy ends with no error.
                        Poll::Ready(Ok(())) if filled == 0 => self.end_copy(),
                        Poll::Ready(Ok(())) => {
                            self.pos = 0;
                            self.cap = filled;
                        }
                        Poll::Ready(Err(e)) => self.fail(e),
                    }
                }
                Phase::Flushing => {
                    // Go writes straight to the connection and never flushes; a destination that
                    // buffers (the QPP wrapper's staged ciphertext) needs this before it is done.
                    // A flush failure is the tail of the copy failing, so it becomes this
                    // direction's result, unless the copy already has an error to report.
                    let flushed = match Pin::new(&mut *dst).poll_flush(cx) {
                        Poll::Ready(flushed) => flushed,
                        Poll::Pending => return self.park(),
                    };
                    self.parked = false;
                    if let Err(e) = flushed {
                        self.report(e);
                    }
                    self.phase = Phase::Done;
                }
                Phase::Done => {
                    self.parked = false;
                    return Poll::Ready(());
                }
            }
        }
    }
}

/// Go's `io.ErrShortWrite`, carried by the nearest `ErrorKind`.
fn short_write() -> io::Error {
    io::Error::new(io::ErrorKind::WriteZero, "short write")
}

/// Go's `os.ErrDeadlineExceeded` text, for a direction the stall rule ended.
fn stalled() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")
}

/// Whether the pipe is still open, or running out its grace.
enum Life {
    Open,
    /// The grace that ends in teardown; `None` when `close_wait <= 0`.
    Closing(Option<Pin<Box<Sleep>>>),
}

/// The rules that decide when the pipe ends (module docs, rules 2, 5 and 6).
struct Lifetime {
    close_wait: i64,
    timing: Timing,
    life: Life,
    /// The probe ticker, polled only while a direction is parked and the pipe is open.
    watch: Option<Pin<Box<Sleep>>>,
    /// Whether the previous poll left the ticker running.
    watching: bool,
    /// The send-queue sizes the last probe saw (alice, bob), so a shrink counts as progress.
    unsent: [Option<usize>; 2],
    /// When a probe last saw a send queue shrink.
    drained_at: Option<Instant>,
    /// When a probe first saw the current end signal of each direction (`alice -> bob`,
    /// `bob -> alice`) while it was parked; cleared when a probe finds the signal gone.
    signalled_at: [Option<Instant>; 2],
}

/// The shortest probe period [`Lifetime`] accepts: a zero [`Timing::watch`] would re-arm an
/// already expired timer forever and never yield.
const MIN_WATCH: Duration = Duration::from_millis(1);

impl Lifetime {
    fn new(close_wait: i64, timing: Timing) -> Lifetime {
        Lifetime {
            close_wait,
            timing: Timing {
                watch: timing.watch.max(MIN_WATCH),
                ..timing
            },
            life: Life::Open,
            watch: None,
            watching: false,
            unsent: [None; 2],
            drained_at: None,
            signalled_at: [None; 2],
        }
    }

    /// Starts the grace, once: a later trigger never moves its deadline (rule 2).
    // Go: if closeWait > 0 { time.Sleep(time.Duration(closeWait) * time.Second) }
    fn begin_closing(&mut self) {
        if matches!(self.life, Life::Open) {
            self.watch = None;
            self.life = Life::Closing(
                (self.close_wait > 0)
                    .then(|| Box::pin(tokio::time::sleep(close_wait_duration(self.close_wait)))),
            );
        }
    }

    /// `Ready` once the pipe must end.
    fn poll<A, B>(
        &mut self,
        cx: &mut Context<'_>,
        ab: &mut Transfer<'_>,
        ba: &mut Transfer<'_>,
        alice: &A,
        bob: &B,
    ) -> Poll<()>
    where
        A: PipeEnd,
        B: PipeEnd,
    {
        if ab.is_done() && ba.is_done() {
            return Poll::Ready(());
        }
        if ab.is_done() || ba.is_done() {
            self.begin_closing();
        }
        loop {
            if let Life::Closing(grace) = &mut self.life {
                return match grace {
                    Some(grace) => grace.as_mut().poll(cx),
                    None => Poll::Ready(()),
                };
            }
            if !ab.parked && !ba.parked {
                // Every end is being polled by some read, so a reset or a dead session wakes the
                // copy itself; an idle pipe costs no timer.
                self.watching = false;
                return Poll::Pending;
            }
            let now = Instant::now();
            let period = self.timing.watch;
            let tick = self
                .watch
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(period)));
            if !self.watching {
                // The first park after a quiet spell gets a full period, so a park that ends at
                // once costs no probe.
                if tick.deadline() <= now {
                    tick.as_mut().reset(now + period);
                }
                self.watching = true;
            }
            if tick.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            tick.as_mut().reset(now + period);
            if self.check(ab, ba, alice, bob, now) {
                return Poll::Ready(());
            }
            // Loop: polls the re-armed ticker (registering its waker), or the grace a failure
            // has just started.
        }
    }

    /// One probe of both ends (rules 5 and 6). `true` when the pipe must end now.
    fn check<A, B>(
        &mut self,
        ab: &mut Transfer<'_>,
        ba: &mut Transfer<'_>,
        alice: &A,
        bob: &B,
        now: Instant,
    ) -> bool
    where
        A: PipeEnd,
        B: PipeEnd,
    {
        let mut at_alice = alice.probe();
        let mut at_bob = bob.probe();

        // Rule 5: a failed end counts as the direction reading it finishing.
        let mut failed = false;
        if let Some(err) = at_alice.failed.take() {
            ab.report(err);
            failed = true;
        }
        if let Some(err) = at_bob.failed.take() {
            ba.report(err);
            failed = true;
        }
        if failed {
            self.begin_closing();
            return false;
        }

        // A send queue that shrank since the last probe is a reader taking data.
        for (seen, unsent) in self.unsent.iter_mut().zip([at_alice.unsent, at_bob.unsent]) {
            if let (Some(before), Some(after)) = (*seen, unsent)
                && after < before
            {
                self.drained_at = Some(now);
            }
            *seen = unsent;
        }
        let mut moved_at = ab.moved_at.max(ba.moved_at);
        if let Some(drained_at) = self.drained_at {
            moved_at = moved_at.max(drained_at);
        }

        // Rule 6: a parked direction whose source has stopped, or starves its session, ends the
        // pipe once that has lasted, with nothing moving, for its destination's stall limit.
        let ab_limit = self.timing.stall_limit(at_bob.progress, self.close_wait);
        if self.stall_expired(0, ab, &at_alice, ab_limit, moved_at, now) {
            ab.report(stalled());
            return true;
        }
        let ba_limit = self.timing.stall_limit(at_alice.progress, self.close_wait);
        if self.stall_expired(1, ba, &at_bob, ba_limit, moved_at, now) {
            ba.report(stalled());
            return true;
        }
        false
    }

    /// Rule 6 for one direction: records when its end signal was first seen, and says whether the
    /// stall limit has run out since then (and since the last movement).
    fn stall_expired(
        &mut self,
        dir: usize,
        transfer: &Transfer<'_>,
        source: &Probe,
        limit: Option<Duration>,
        moved_at: Instant,
        now: Instant,
    ) -> bool {
        let signalled = transfer.parked && (source.finished || source.starving);
        let Some(limit) = limit.filter(|_| signalled) else {
            self.signalled_at[dir] = None;
            return false;
        };
        let since = *self.signalled_at[dir].get_or_insert(now);
        now.saturating_duration_since(moved_at.max(since)) >= limit
    }
}

#[cfg(test)]
#[path = "pipe_tests.rs"]
mod tests;
