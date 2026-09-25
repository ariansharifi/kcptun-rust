//! The bidirectional proxy pipe, and the buffer pool it copies through.
//!
//! Go source: `kcptun/std/copy.go`, `Pipe()`, `Copy()` and the `closeWriter` interface.
//! Call sites: `kcptun/client/main.go:540` and `kcptun/server/main.go:530`,
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
//! What each direction does, in Go's order:
//! 1. copy until the source ends (EOF) or either side errors: that error is the direction's
//!    result;
//! 2. sleep `close_wait` seconds if it is positive;
//! 3. half-close the destination ([`HalfCloseWrite::poll_close_write`], Go's `CloseWrite()`), so
//!    the peer sees the end of the stream while the other direction keeps running.
//!
//! When both directions are done, both ends are closed ([`HalfCloseWrite::poll_close`], then the
//! values are dropped) and the two results are returned as `(err_a, err_b)`. A clean EOF is
//! `Ok(())`, so Go's `if err != nil && !errors.Is(err, io.EOF)` becomes "log every `Err`".
//!
//! Note the half-close ordering caveat recorded for smux in plan step 06.4: `CloseWrite` before
//! the peer's FIN can truncate a smux stream. That is the Go behaviour, `close_wait` is the knob
//! Go offers against it, and nothing here changes it.
//!
//! The half-close is reached through the [`HalfCloseWrite`] trait rather than named types, which
//! keeps this module independent of the smux stream API: step 07.3 implements the trait for
//! [`SmuxStream`](crate::smuxio::SmuxStream) and for `QppStream` (`crate::qpp`, feature `qpp`)
//! (deviation V04: the QPP wrapper forwards `close_write` instead of falling back to a full
//! close), and nothing below had to change.
//!
//! Step 09.1 added the other half of Go's `Copy`, the `io.WriterTo` fast path: a source whose
//! [`HalfCloseWrite::FRAME_SOURCE`] is `true` is drained frame by frame through
//! [`poll_read_frame`](HalfCloseWrite::poll_read_frame) and never takes a copy buffer at all.
//! [`SmuxStream`](crate::smuxio::SmuxStream) is such a source (Go:
//! [`Stream::write_to`](kcptun_smux::Stream::write_to)); the QPP wrapper is not, exactly as in
//! Go, where `QPPPort` has no `WriteTo`.

use std::io;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::{Buf as _, Bytes};
use crossbeam_queue::ArrayQueue;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

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
// The half-close interface
// ---------------------------------------------------------------------------------------

/// A connection [`pipe`] can copy between: readable, writable, and able to signal "no more data
/// from me" without tearing the connection down.
///
/// Go's `Pipe` takes `io.ReadWriteCloser` and asks at run time whether the value also has
/// `CloseWrite()`:
///
/// ```go
/// if cw, ok := dst.(closeWriter); ok { cw.CloseWrite() } else { dst.Close() }
/// ```
///
/// Here that question is answered by the implementation: a type with a real half-close implements
/// [`poll_close_write`](Self::poll_close_write) with it, and a type without one implements it as
/// its full close: the same two branches, decided where the knowledge is.
///
/// Implemented for [`tokio::net::TcpStream`] and [`tokio::net::UnixStream`] here, and as of step
/// 07.3 for [`SmuxStream`](crate::smuxio::SmuxStream) and `QppStream` (`crate::qpp`, feature
/// `qpp`, V04) in their own modules.
pub trait HalfCloseWrite: AsyncRead + AsyncWrite {
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

    /// Shuts the writing half down: the peer reads EOF, this side can still receive.
    ///
    /// Go ignores the error this returns, and so does [`pipe`].
    // Go: kcptun/std/copy.go:closeWriter.CloseWrite()
    fn poll_close_write(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>>;

    /// Closes the connection completely.
    ///
    /// The default does nothing, for the types whose close is the drop that follows it: a
    /// `TcpStream` closes its descriptor when it goes out of scope. Types whose close has to be
    /// awaited (a smux stream returning its tokens and sending FIN) override it.
    // Go: io.Closer.Close()
    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// tokio's `poll_shutdown` for a TCP socket is `shutdown(SHUT_WR)`: exactly Go's
/// `(*net.TCPConn).CloseWrite`.
impl HalfCloseWrite for tokio::net::TcpStream {
    fn poll_close_write(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(self, cx)
    }
}

/// Same for a unix-domain socket, which the client accepts on when `-l` is a path.
#[cfg(unix)]
impl HalfCloseWrite for tokio::net::UnixStream {
    fn poll_close_write(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(self, cx)
    }
}

// ---------------------------------------------------------------------------------------
// Pipe
// ---------------------------------------------------------------------------------------

/// Copies between `alice` and `bob` until both directions end, and returns their results.
///
/// `close_wait` is `-closewait` in seconds: how long a direction waits after its source ended
/// before half-closing the destination. Values `<= 0` mean no wait, like Go's
/// `if closeWait > 0 { time.Sleep(...) }`.
///
/// The returned pair is Go's `(errA, errB)`: `errA` for `alice -> bob`, `errB` for `bob -> alice`.
/// A source that ends cleanly yields `Ok(())` (Go's `io.Copy` swallows `io.EOF` the same way);
/// anything else (a read error, a write error, a peer reset) is the `Err` the caller logs.
///
/// Both ends are consumed and closed, as Go closes both after its `WaitGroup` returns.
// Go: kcptun/std/copy.go:Pipe()
pub async fn pipe<A, B>(alice: A, bob: B, close_wait: i64) -> (io::Result<()>, io::Result<()>)
where
    A: HalfCloseWrite + Unpin,
    B: HalfCloseWrite + Unpin,
{
    pipe_with_pool(alice, bob, close_wait, default_buf_pool()).await
}

/// [`pipe`], copying through `pool` instead of the process-wide one.
// Go: kcptun/std/copy.go:Pipe()
pub async fn pipe_with_pool<A, B>(
    mut alice: A,
    mut bob: B,
    close_wait: i64,
    pool: &BufPool,
) -> (io::Result<()>, io::Result<()>)
where
    A: HalfCloseWrite + Unpin,
    B: HalfCloseWrite + Unpin,
{
    // Go: go streamCopy(bob, alice, &errA); go streamCopy(alice, bob, &errB); wg.Wait()
    let mut a_to_b = Transfer::new(pool, close_wait);
    let mut b_to_a = Transfer::new(pool, close_wait);
    std::future::poll_fn(|cx| {
        let ab = a_to_b.poll_transfer(cx, &mut alice, &mut bob);
        let ba = b_to_a.poll_transfer(cx, &mut bob, &mut alice);
        if ab.is_ready() && ba.is_ready() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;

    // Go: alice.Close(); bob.Close(), both errors discarded. Dropping the values afterwards is
    // what closes the descriptors.
    let _ = std::future::poll_fn(|cx| Pin::new(&mut alice).poll_close(cx)).await;
    let _ = std::future::poll_fn(|cx| Pin::new(&mut bob).poll_close(cx)).await;

    (a_to_b.result, b_to_a.result)
}

/// Where one direction is in its life.
enum Phase {
    /// Reading the source and writing the destination.
    Copying,
    /// The copy is over; flushing whatever the destination buffered.
    Flushing,
    /// Waiting out `close_wait` before the half-close.
    Waiting(Pin<Box<Sleep>>),
    /// Half-closing the destination.
    Closing,
    /// Finished; `result` is final.
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
    /// The frame a [`HalfCloseWrite::FRAME_SOURCE`] handed over, still being written out. Such
    /// a direction never takes a buffer from the pool at all: the bytes the source already owns
    /// go straight to the destination, which is what Go's `WriteTo` fast path does.
    frame: Option<Bytes>,
    /// Whether a write has happened since the last flush, so that a destination which buffers
    /// does not hold data while the source is quiet. tokio's `io::copy` keeps the same flag
    /// (`CopyBuffer::need_flush`) for the same reason; Go never needs it, because its
    /// destinations are unbuffered connections.
    need_flush: bool,
    close_wait: i64,
    phase: Phase,
    /// Go: `*err`, the result of `Copy(dst, src)`.
    result: io::Result<()>,
}

impl<'p> Transfer<'p> {
    fn new(pool: &'p BufPool, close_wait: i64) -> Transfer<'p> {
        Transfer {
            pool,
            buf: None,
            pos: 0,
            cap: 0,
            frame: None,
            need_flush: false,
            close_wait,
            phase: Phase::Copying,
            result: Ok(()),
        }
    }

    /// The copy is over (cleanly or not): drop the buffer and move on to the shutdown sequence.
    fn end_copy(&mut self) {
        self.buf = None;
        self.pos = 0;
        self.cap = 0;
        self.frame = None;
        self.phase = Phase::Flushing;
    }

    /// Drives this direction as far as it can go without blocking.
    fn poll_transfer<S, D>(&mut self, cx: &mut Context<'_>, src: &mut S, dst: &mut D) -> Poll<()>
    where
        S: HalfCloseWrite + Unpin,
        D: HalfCloseWrite + Unpin,
    {
        loop {
            match &mut self.phase {
                // Go: `Copy` prefers `src.(io.WriterTo)`, i.e. `stream.WriteTo(dst)` for a smux
                // stream: received frames are written out as they are, with no copy buffer
                // between them. The branch is decided at compile time by the source type, the
                // way Go decides it by the type assertion.
                Phase::Copying if S::FRAME_SOURCE => {
                    if self.frame.is_some() {
                        let written = {
                            let frame = self.frame.as_ref().expect("just checked");
                            ready!(Pin::new(&mut *dst).poll_write(cx, frame))
                        };
                        match written {
                            // Go: `io.ErrShortWrite`, as in the buffered branch below.
                            Ok(0) => {
                                self.result =
                                    Err(io::Error::new(io::ErrorKind::WriteZero, "short write"));
                                self.end_copy();
                            }
                            Ok(n) => {
                                let frame = self.frame.as_mut().expect("just checked");
                                frame.advance(n);
                                if frame.is_empty() {
                                    self.frame = None;
                                }
                                self.need_flush = true;
                            }
                            Err(e) => {
                                self.result = Err(e);
                                self.end_copy();
                            }
                        }
                        continue;
                    }

                    match Pin::new(&mut *src).poll_read_frame(cx) {
                        Poll::Pending => {
                            // As in the buffered branch: a destination that buffers must not sit
                            // on data while the source is quiet.
                            if self.need_flush {
                                match Pin::new(&mut *dst).poll_flush(cx) {
                                    Poll::Ready(Ok(())) => self.need_flush = false,
                                    Poll::Ready(Err(e)) => {
                                        self.result = Err(e);
                                        self.end_copy();
                                        continue;
                                    }
                                    Poll::Pending => {}
                                }
                            }
                            return Poll::Pending;
                        }
                        // An empty frame is not the end of the stream; ask again.
                        Poll::Ready(Ok(Some(frame))) if frame.is_empty() => {}
                        Poll::Ready(Ok(Some(frame))) => self.frame = Some(frame),
                        // Go: `WriteTo` returns `(n, io.EOF)`, which `Copy` reports as a clean end.
                        Poll::Ready(Ok(None)) => self.end_copy(),
                        Poll::Ready(Err(e)) => {
                            self.result = Err(e);
                            self.end_copy();
                        }
                    }
                }
                Phase::Copying => {
                    if self.pos < self.cap {
                        // Go's `io.Copy` demands the whole slice in one `Write` and calls a
                        // short one `io.ErrShortWrite`; `AsyncWrite` is allowed to take part of
                        // it, so the rest is offered again.
                        let written = {
                            let buf = self.buf.as_ref().expect("filled by the read below");
                            ready!(Pin::new(&mut *dst).poll_write(cx, &buf[self.pos..self.cap]))
                        };
                        match written {
                            Ok(0) => {
                                // Go: `io.copyBuffer` leaves `ew == nil` for a `(0, nil)` write
                                // and then trips `nr != nw`, so `Pipe` returns `io.ErrShortWrite`
                                // and the call sites log `pipe: short write in: … out: …`.
                                self.result = Err(io::Error::new(
                                    io::ErrorKind::WriteZero,
                                    // Go: io.ErrShortWrite
                                    "short write",
                                ));
                                self.end_copy();
                            }
                            Ok(n) => {
                                self.pos += n;
                                self.need_flush = true;
                            }
                            Err(e) => {
                                self.result = Err(e);
                                self.end_copy();
                            }
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
                            // The source has gone quiet, so this is where a buffering
                            // destination would otherwise sit on data indefinitely: nothing
                            // polls it again until the source speaks. Flush it, as tokio's
                            // `io::copy` does on the same edge.
                            if self.need_flush {
                                match Pin::new(&mut *dst).poll_flush(cx) {
                                    Poll::Ready(Ok(())) => self.need_flush = false,
                                    Poll::Ready(Err(e)) => {
                                        // The tail of the copy failed; Go's unbuffered `Write`
                                        // would have reported it from `Copy` itself.
                                        self.result = Err(e);
                                        self.end_copy();
                                        continue;
                                    }
                                    Poll::Pending => {}
                                }
                            }
                            return Poll::Pending;
                        }
                        // Go: `nr == 0, err == io.EOF`, the copy ends with no error.
                        Poll::Ready(Ok(())) if filled == 0 => self.end_copy(),
                        Poll::Ready(Ok(())) => {
                            self.pos = 0;
                            self.cap = filled;
                        }
                        Poll::Ready(Err(e)) => {
                            self.result = Err(e);
                            self.end_copy();
                        }
                    }
                }
                Phase::Flushing => {
                    // Go writes straight to the connection and never flushes; a destination that
                    // buffers (a smux stream's frame writer) needs this before the half-close.
                    // A flush failure is the tail of the copy failing, which Go's unbuffered
                    // `Write` would have reported from `Copy` itself, so it becomes this
                    // direction's result, unless the copy already has an error to report.
                    if let Err(e) = ready!(Pin::new(&mut *dst).poll_flush(cx))
                        && self.result.is_ok()
                    {
                        self.result = Err(e);
                    }
                    // Go: if closeWait > 0 { time.Sleep(time.Duration(closeWait) * time.Second) }
                    self.phase = if self.close_wait > 0 {
                        Phase::Waiting(Box::pin(tokio::time::sleep(Duration::from_secs(
                            self.close_wait.unsigned_abs(),
                        ))))
                    } else {
                        Phase::Closing
                    };
                }
                Phase::Waiting(sleep) => {
                    ready!(sleep.as_mut().poll(cx));
                    self.phase = Phase::Closing;
                }
                Phase::Closing => {
                    // Go: cw.CloseWrite(), or dst.Close() for a type without half-close, which
                    // is how such a type implements this. Either way the error is dropped.
                    let _ = ready!(Pin::new(&mut *dst).poll_close_write(cx));
                    self.phase = Phase::Done;
                    return Poll::Ready(());
                }
                Phase::Done => return Poll::Ready(()),
            }
        }
    }
}

#[cfg(test)]
#[path = "pipe_tests.rs"]
mod tests;
