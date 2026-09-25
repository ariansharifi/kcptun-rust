//! Streams multiplexed inside a session (port of `stream.go`).
//!
//! **Back-pointer (internal, no wire effect).** Go's `stream` holds `sess *Session` and the
//! session's map holds the stream, a cycle the GC breaks. In Rust the map owns
//! `Arc<StreamInner>` and the stream keeps only a [`Weak`] back to the session, so nothing
//! leaks; every session-driven entry point is handed `&SessionShared` directly and the `Weak` is
//! upgraded only by [`Drop`], which has no argument to take it from. The [`Stream`] handle the
//! caller owns holds the session strongly, exactly like Go's `stream.sess`.
//!
//! **Buffers.** Go pushes `*[]byte` buffers from a power-of-two `sync.Pool` allocator and
//! returns them on read. Received payloads here are [`Bytes`] allocated at the frame's exact
//! length (plan 06 "Buffers"); revisit pooling in step 12.
//!
//! **EOF.** Go's `Read` reports the end of the stream as `(0, io.EOF)` and `WriteTo` as
//! `(n, io.EOF)`. The port uses the Rust convention instead: [`Stream::read`] returns `Ok(0)`,
//! [`Stream::read_chunk`] returns `Ok(None)` and [`Stream::write_to`] returns `Ok(n)`. Every
//! other error keeps Go's value and text.
//!
//! **Wake-ups.** `reader_wakeup`, `writer_wakeup` and `update_event` are Go's capacity-1 notify
//! channels: [`Notify::notify_one`] stores one permit, so a signal sent between a state check
//! and the following wait is not lost. `die`, `fin_event` and `write_closed` are Go's *closed*
//! channels, and a [`CancellationToken`] stays ready once cancelled, so nothing needs to be
//! notified alongside them. Notifying anyway would be worse than redundant: two ready branches
//! of the same `select!` are picked at random, so a blocked reader would see `io.ErrClosedPipe`
//! or EOF at random when the session closes.
//!
//! **Write counts.** Go's `Write` returns `(sent, err)`, so a caller can see how much of a
//! partially written buffer reached the connection. A Rust `Result` carries one or the other,
//! so a failed write reports only the error; in every failure but a write deadline the session
//! is dead anyway.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Weak};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::error::Error;
use crate::frame::{CMD_FIN, CMD_PSH, CMD_UPD, INITIAL_PEER_WINDOW, UpdHeader};
use crate::session::{
    ClassId, OPEN_CLOSE_TIMEOUT, OwnedFrame, Payload, SessionShared, deadline_at, lock,
};

/// The received-data buffer of one stream: whole frame payloads in arrival order, plus the
/// version-2 read counters Go keeps under the same `bufferLock`.
///
/// Go uses a `bufferRing` of `[]byte` slices and re-slices the front buffer as it is consumed;
/// [`Bytes::advance`](bytes::Buf::advance) on the front element is the same operation without
/// the pool bookkeeping.
// Go: smux@v1.5.55 stream.go:bufferRing (+ stream.numRead/incr)
#[derive(Debug, Default)]
pub(crate) struct StreamBuf {
    /// Frame payloads, oldest first. Never contains an empty payload.
    pub(crate) chunks: VecDeque<Bytes>,
    /// Sum of the lengths in `chunks`: the bytes this stream owes the session's token bucket.
    pub(crate) len: usize,
    /// Bytes read from this stream so far (protocol version 2).
    // Go: smux@v1.5.55 stream.go:stream.numRead
    num_read: u32,
    /// Bytes read since the last `cmdUPD` was sent (protocol version 2).
    // Go: smux@v1.5.55 stream.go:stream.incr
    incr: u32,
}

impl StreamBuf {
    /// Copies the front payload into `b` and drops it once it is fully consumed.
    // Go: smux@v1.5.55 stream.go:bufferRing.consumeFront()
    fn consume_front(&mut self, b: &mut [u8]) -> usize {
        let Some(front) = self.chunks.front_mut() else {
            return 0;
        };
        let n = front.len().min(b.len());
        b[..n].copy_from_slice(&front[..n]);
        front.advance(n);
        if front.is_empty() {
            self.chunks.pop_front();
        }
        self.len -= n;
        n
    }

    /// Takes the whole front payload, without copying it.
    // Go: smux@v1.5.55 stream.go:bufferRing.pop()
    fn pop(&mut self) -> Option<Bytes> {
        let chunk = self.chunks.pop_front()?;
        self.len -= chunk.len();
        Some(chunk)
    }

    /// Version-2 read accounting: returns the `consumed` value a `cmdUPD` should carry, or 0
    /// when none is due.
    ///
    /// Go runs this inside the `bufferLock` critical section of `tryReadV2` and `writeToV2`,
    /// including when nothing was read (`n == 0`), which is why it is called unconditionally.
    // Go: smux@v1.5.55 stream.go:tryReadV2() / writeToV2()
    fn account_read(&mut self, n: usize, max_stream_buffer: isize) -> u32 {
        let n = n as u32;
        // Go's uint32 counters wrap (porting guide §3).
        self.num_read = self.num_read.wrapping_add(n);
        self.incr = self.incr.wrapping_add(n);

        // In an ideal environment:
        // If more than half of the buffer has been consumed, send a read ACK to the peer.
        // With the ACK round-trip time taken into account, a continuous data stream
        // will not slow down due to waiting for ACKs, as long as the consumer
        // continues reading data.
        //
        // `num_read == n` indicates that this is the initial read.
        if self.incr >= (max_stream_buffer / 2) as u32 || self.num_read == n {
            let consumed = self.num_read;
            self.incr = 0; // reset incr counter
            consumed
        } else {
            0
        }
    }
}

/// What a non-blocking read attempt produced. Go encodes the three outcomes as `(n, nil)`,
/// `(0, io.EOF)` and `(0, ErrWouldBlock)`.
// Go: smux@v1.5.55 stream.go:tryReadV1() / tryReadV2()
enum TryRead {
    /// `n` bytes were delivered.
    Read(usize),
    /// The stream is dead and its buffer is empty.
    Eof,
    /// Nothing to deliver yet.
    WouldBlock,
}

/// Why a blocked reader woke up.
// Go: smux@v1.5.55 stream.go:waitRead()
enum WaitRead {
    /// Something may have changed; try again.
    Wakeup,
    /// End of the peer's data.
    Eof,
    /// The read failed.
    Failed(Error),
}

/// The payload of one write call, as the frame splitter sees it.
///
/// Go's `frame.data` points into the caller's buffer and stays valid because `Write` blocks
/// until `sendLoop` has written the frame. A queued request here crosses to the send task, so
/// each frame needs an owned payload: a `&[u8]` is copied once per frame, while a [`Bytes`] is
/// only sliced (the zero-copy path for step 09's proxy).
enum Chunks<'a> {
    /// A borrowed buffer; every frame is copied out of it.
    Slice(&'a [u8]),
    /// A reference-counted buffer; every frame is a slice of it.
    Shared(&'a Bytes),
}

impl Chunks<'_> {
    fn len(&self) -> usize {
        match self {
            Chunks::Slice(b) => b.len(),
            Chunks::Shared(b) => b.len(),
        }
    }

    /// The payload of one frame: `size` bytes starting at `off`.
    fn chunk(&self, off: usize, size: usize) -> Bytes {
        match self {
            Chunks::Slice(b) => Bytes::copy_from_slice(&b[off..off + size]),
            Chunks::Shared(b) => b.slice(off..off + size),
        }
    }
}

/// The shared state of one stream.
///
/// The session's map and every [`Stream`] handle hold an `Arc` of this.
// Go: smux@v1.5.55 stream.go:stream
#[derive(Debug)]
pub(crate) struct StreamInner {
    /// Stream identifier.
    // Go: smux@v1.5.55 stream.go:stream.id
    id: u32,
    /// The session this stream belongs to; see the module docs for why it is weak.
    // Go: smux@v1.5.55 stream.go:stream.sess
    sess: Weak<SessionShared>,
    /// `byte(config.Version)`: the version every frame this stream writes carries.
    version: u8,
    /// Largest payload one `cmdPSH` may carry (`config.MaxFrameSize`).
    // Go: smux@v1.5.55 stream.go:stream.frameSize
    frame_size: usize,
    /// Received payloads plus the version-2 read counters.
    // Go: smux@v1.5.55 stream.go:stream.bufferRing (guarded by bufferLock)
    buffer: std::sync::Mutex<StreamBuf>,
    /// Signalled when data arrives or the read deadline changes.
    // Go: smux@v1.5.55 stream.go:stream.chReaderWakeup
    reader_wakeup: Notify,
    /// Signalled when the write deadline changes.
    // Go: smux@v1.5.55 stream.go:stream.chWriterWakeup
    writer_wakeup: Notify,
    /// Signalled when the peer's window may have grown (`cmdUPD`).
    // Go: smux@v1.5.55 stream.go:stream.chUpdate
    update_event: Notify,
    /// Set once the stream is fully closed (locally, by the session, or by both FINs).
    // Go: smux@v1.5.55 stream.go:stream.die
    die: CancellationToken,
    /// Guards [`StreamInner::die`], so exactly one caller observes the transition.
    // Go: smux@v1.5.55 stream.go:stream.dieOnce
    die_once: AtomicBool,
    /// Set once the peer's `cmdFIN` has arrived.
    // Go: smux@v1.5.55 stream.go:stream.chFinEvent / finEventOnce
    fin_event: CancellationToken,
    /// Set once this side has sent its `cmdFIN` (half-close).
    // Go: smux@v1.5.55 stream.go:stream.chWriteClosed
    write_closed: CancellationToken,
    /// Guards [`StreamInner::write_closed`], so `close_write` reports a double half-close.
    // Go: smux@v1.5.55 stream.go:stream.writeClosedOnce
    write_closed_once: AtomicBool,
    /// Bytes handed to the session for this stream (protocol version 2).
    // Go: smux@v1.5.55 stream.go:stream.numWritten
    num_written: AtomicU32,
    /// Bytes the peer reports having consumed (protocol version 2).
    // Go: smux@v1.5.55 stream.go:stream.peerConsumed
    peer_consumed: AtomicU32,
    /// The peer's advertised receive window (protocol version 2).
    // Go: smux@v1.5.55 stream.go:stream.peerWindow
    peer_window: AtomicU32,
    /// Read deadline; `None` is Go's zero `time.Time`, i.e. no deadline.
    // Go: smux@v1.5.55 stream.go:stream.readDeadline
    read_deadline: std::sync::Mutex<Option<Instant>>,
    /// Write deadline.
    // Go: smux@v1.5.55 stream.go:stream.writeDeadline
    write_deadline: std::sync::Mutex<Option<Instant>>,
}

impl StreamInner {
    // Go: smux@v1.5.55 stream.go:newStream()
    pub(crate) fn new(id: u32, sess: &Arc<SessionShared>) -> Arc<StreamInner> {
        let config = sess.config();
        Arc::new(StreamInner {
            id,
            sess: Arc::downgrade(sess),
            version: config.version as u8,
            frame_size: config.max_frame_size as usize,
            buffer: std::sync::Mutex::new(StreamBuf::default()),
            reader_wakeup: Notify::new(),
            writer_wakeup: Notify::new(),
            update_event: Notify::new(),
            die: CancellationToken::new(),
            die_once: AtomicBool::new(false),
            fin_event: CancellationToken::new(),
            write_closed: CancellationToken::new(),
            write_closed_once: AtomicBool::new(false),
            num_written: AtomicU32::new(0),
            peer_consumed: AtomicU32::new(0),
            peer_window: AtomicU32::new(INITIAL_PEER_WINDOW),
            read_deadline: std::sync::Mutex::new(None),
            write_deadline: std::sync::Mutex::new(None),
        })
    }

    /// The stream's identifier.
    // Go: smux@v1.5.55 stream.go:stream.ID()
    pub(crate) fn id(&self) -> u32 {
        self.id
    }

    /// Appends a received payload. Called by `recvLoop` with the session's stream lock held.
    // Go: smux@v1.5.55 stream.go:stream.pushBytes()
    pub(crate) fn push_bytes(&self, data: Bytes) {
        let mut buf = lock(&self.buffer);
        buf.len += data.len();
        buf.chunks.push_back(data);
    }

    /// Bytes buffered but not yet read.
    pub(crate) fn buffered_len(&self) -> usize {
        lock(&self.buffer).len
    }

    /// Wakes a blocked reader.
    // Go: smux@v1.5.55 stream.go:stream.wakeupReader()
    pub(crate) fn wakeup_reader(&self) {
        self.reader_wakeup.notify_one();
    }

    /// Wakes a blocked writer.
    // Go: smux@v1.5.55 stream.go:stream.wakeupWriter()
    pub(crate) fn wakeup_writer(&self) {
        self.writer_wakeup.notify_one();
    }

    /// Closes [`StreamInner::die`], reporting whether this call was the one that did it.
    // Go: smux@v1.5.55 stream.go:stream.dieOnce.Do()
    fn close_die(&self) -> bool {
        let first = self
            .die_once
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if first {
            self.die.cancel();
        }
        first
    }

    /// Closes [`StreamInner::write_closed`], reporting whether this call was the one that did
    /// it.
    // Go: smux@v1.5.55 stream.go:stream.writeClosedOnce.Do()
    fn close_write_side(&self) -> bool {
        let first = self
            .write_closed_once
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if first {
            self.write_closed.cancel();
        }
        first
    }

    /// Handles a `cmdUPD` from the peer: record what it consumed and how large its window is,
    /// then wake the writer.
    // Go: smux@v1.5.55 stream.go:stream.update()
    pub(crate) fn update(&self, consumed: u32, window: u32) {
        self.peer_consumed.store(consumed, Ordering::Release);
        self.peer_window.store(window, Ordering::Release);
        self.update_event.notify_one();
    }

    /// Handles a `cmdFIN` from the peer: EOF for the reader, and, if this side has already sent
    /// its own FIN, the end of the stream.
    // Go: smux@v1.5.55 stream.go:stream.fin()
    pub(crate) fn fin(&self, sess: &SessionShared) {
        self.fin_event.cancel();
        self.try_half_close_cleanup(sess);
    }

    /// Removes the stream from the session once both sides have sent their `cmdFIN`.
    ///
    /// **Deviation V11.** Go's `streamClosed` then calls `recycleTokens`, which *discards* data
    /// that arrived but was never read, so a peer that half-closes its write side can lose the
    /// response. Here the stream leaves the session map (later frames for the id are dropped,
    /// as in Go) and its writers are released, but the buffered data stays readable until the
    /// reader drains it; the tokens go back to the bucket as the data is read, and the
    /// remainder when the last handle is dropped ([`Drop for StreamInner`](StreamInner#impl-Drop-for-StreamInner)).
    /// [`StreamInner::wait_read`] carries the other half of the deviation.
    // Go: smux@v1.5.55 stream.go:stream.tryHalfCloseCleanup()
    pub(crate) fn try_half_close_cleanup(&self, sess: &SessionShared) {
        if !self.fin_event.is_cancelled() || !self.write_closed.is_cancelled() {
            return;
        }
        self.close_die();
        sess.stream_closed(self.id);
    }

    /// The session is closing: unblock everyone on this stream.
    // Go: smux@v1.5.55 stream.go:stream.sessionClose()
    pub(crate) fn session_close(&self) {
        self.close_die();
    }

    /// Resolves once the stream is closed.
    // Go: smux@v1.5.55 stream.go:stream.GetDieCh()
    pub(crate) async fn closed(&self) {
        self.die.cancelled().await;
    }

    /// Whether the stream is closed.
    pub(crate) fn is_closed(&self) -> bool {
        self.die.is_cancelled()
    }

    /// Whether the peer's `cmdFIN` has arrived.
    // Go: smux@v1.5.55 stream.go:stream.chFinEvent
    pub(crate) fn got_fin(&self) -> bool {
        self.fin_event.is_cancelled()
    }

    /// Drops everything still buffered and reports how many tokens that frees.
    ///
    /// Go calls this from `streamClosed` for every close, which is what deviation V11 is about;
    /// here only an explicit close — [`StreamInner::close`] and [`Drop for
    /// Stream`](Stream#impl-Drop-for-Stream), where the caller has said it wants nothing more —
    /// and the final [`Drop`] use it.
    // Go: smux@v1.5.55 stream.go:stream.recycleTokens()
    fn recycle_tokens(&self) -> usize {
        let mut buf = lock(&self.buffer);
        buf.chunks.clear();
        std::mem::take(&mut buf.len)
    }

    // -----------------------------------------------------------------------------------
    // Read
    // -----------------------------------------------------------------------------------

    /// Reads into `b`, blocking until data arrives, the stream ends or it fails.
    ///
    /// Returns `Ok(0)` for Go's `io.EOF` (see the module docs), and `Ok(0)` for an empty `b`,
    /// exactly as Go's `Read` returns `(0, nil)` for one.
    // Go: smux@v1.5.55 stream.go:stream.Read()
    async fn read(&self, sess: &SessionShared, b: &mut [u8]) -> Result<usize, Error> {
        if b.is_empty() {
            return Ok(0);
        }
        loop {
            match self.try_read(sess, b).await {
                TryRead::Read(n) => return Ok(n),
                TryRead::Eof => return Ok(0),
                TryRead::WouldBlock => match self.wait_read(sess).await {
                    WaitRead::Wakeup => {}
                    WaitRead::Eof => return Ok(0),
                    WaitRead::Failed(err) => return Err(err),
                },
            }
        }
    }

    /// One non-blocking read attempt. Versions 1 and 2 differ only in the window update the
    /// latter may owe the peer, so Go's `tryReadV1` and `tryReadV2` are one function here.
    // Go: smux@v1.5.55 stream.go:tryReadV1() / tryReadV2()
    async fn try_read(&self, sess: &SessionShared, b: &mut [u8]) -> TryRead {
        let v2 = sess.config().version == 2;

        // A critical section to copy data from buffers to b
        let (n, notify_consumed) = {
            let mut buf = lock(&self.buffer);
            let n = buf.consume_front(b);
            let notify = if v2 {
                buf.account_read(n, sess.config().max_stream_buffer)
            } else {
                0
            };
            (n, notify)
        };

        // return tokens to session to allow more data to be received
        if n > 0 {
            sess.return_tokens(n);
            // send window update if necessary
            if notify_consumed > 0 {
                // Go returns `(n, err)` here, delivering the bytes *and* the failure. A Rust
                // `Result` holds one or the other, and dropping `n` bytes that have already
                // left the buffer would lose data, so the failure is dropped instead: every
                // reason a window update can fail (the session died, the connection's write
                // side broke, the read deadline expired) is sticky, so the next call that has
                // to block reports it.
                let _ = self.send_window_update(sess, notify_consumed).await;
            }
            return TryRead::Read(n);
        }

        // even if the stream has been closed, we try to deliver all buffered data first.
        // only when there's no data left in buffer, we return EOF to reader.
        if self.die.is_cancelled() {
            TryRead::Eof
        } else {
            TryRead::WouldBlock
        }
    }

    /// Blocks until a read event occurs, the stream ends, or it fails.
    ///
    /// Go's `select` picks at random between the cases that are ready together, so the same
    /// state can produce `io.EOF` or `io.ErrClosedPipe` from one run to the next — which, with
    /// deviation V11, would decide at random whether a half-closed stream's data survives.
    /// Everything already true when the wait starts is therefore answered in a fixed order
    /// first: buffered data, then the peer's FIN, then a failed connection, then the close.
    /// Each outcome is one Go's `select` could have produced.
    // Go: smux@v1.5.55 stream.go:waitRead()
    async fn wait_read(&self, sess: &SessionShared) -> WaitRead {
        if !lock(&self.buffer).chunks.is_empty() {
            return WaitRead::Wakeup;
        }
        if self.fin_event.is_cancelled() {
            // BUGFIX(xtaci): Fix for https://github.com/xtaci/smux/issues/82
            return WaitRead::Eof;
        }
        if let Some(err) = sess.socket_read_error() {
            return WaitRead::Failed(err);
        }
        if let Some(err) = sess.proto_error() {
            return WaitRead::Failed(err);
        }
        if self.die.is_cancelled() {
            return WaitRead::Failed(Error::ClosedPipe);
        }

        let deadline = *lock(&self.read_deadline);
        tokio::select! {
            // notify some data has arrived, or closed
            () = self.reader_wakeup.notified() => WaitRead::Wakeup,
            () = self.fin_event.cancelled() => {
                // BUGFIX(xtaci): Fix for https://github.com/xtaci/smux/issues/82
                if lock(&self.buffer).chunks.is_empty() {
                    WaitRead::Eof
                } else {
                    WaitRead::Wakeup
                }
            }
            err = sess.wait_socket_read_error() => WaitRead::Failed(err),
            err = sess.wait_proto_error() => WaitRead::Failed(err),
            () = deadline_at(deadline) => WaitRead::Failed(Error::Timeout),
            () = self.die.cancelled() => {
                // **Deviation V11.** Go reports `io.ErrClosedPipe` as soon as `die` is closed.
                // A stream closed by `tryHalfCloseCleanup` may still hold received data, and
                // Go's own `select` picks this branch at random against the FIN one, so a
                // blocked reader loses it. Buffered data is delivered first here; the next
                // attempt returns EOF once the buffer has run dry.
                if lock(&self.buffer).chunks.is_empty() {
                    if self.fin_event.is_cancelled() {
                        // Both directions are closed, which is why `die` fired
                        // (`try_half_close_cleanup`): the peer's FIN is the end of the data,
                        // so this is the end of the stream and not a broken pipe. Go's
                        // `select` decides between the two at random, and a Go reader blocked
                        // at that moment reports `io.ErrClosedPipe` for a stream that ended
                        // perfectly normally (reproduced Go↔Go with `smuxecho`, 2 of 5 runs
                        // with 256 streams). The same fixed order as above.
                        WaitRead::Eof
                    } else {
                        WaitRead::Failed(Error::ClosedPipe)
                    }
                } else {
                    WaitRead::Wakeup
                }
            }
        }
    }

    /// Takes the next whole payload out of the receive buffer, without copying it.
    ///
    /// This is [`StreamInner::read`] one frame at a time: the token accounting and the
    /// version-2 window update are the same, only the copy into the caller's buffer is gone.
    /// `Ok(None)` is the end of the stream.
    // Go: smux@v1.5.55 stream.go:stream.Read() + writeToV1()/writeToV2() (the pop half)
    async fn read_chunk(&self, sess: &SessionShared) -> Result<Option<Bytes>, Error> {
        loop {
            let (chunk, notify_consumed) = self.pop_chunk(sess);
            if let Some(chunk) = chunk {
                sess.return_tokens(chunk.len());
                if notify_consumed > 0 {
                    // See `try_read` for why the error is dropped once bytes were delivered.
                    let _ = self.send_window_update(sess, notify_consumed).await;
                }
                return Ok(Some(chunk));
            }
            if self.die.is_cancelled() {
                return Ok(None);
            }
            match self.wait_read(sess).await {
                WaitRead::Wakeup => {}
                WaitRead::Eof => return Ok(None),
                WaitRead::Failed(err) => return Err(err),
            }
        }
    }

    /// The critical section `writeToV1`/`writeToV2` share: pop the front payload and run the
    /// version-2 accounting on its length (on 0 when the ring is empty, exactly as Go does).
    // Go: smux@v1.5.55 stream.go:writeToV1() / writeToV2()
    fn pop_chunk(&self, sess: &SessionShared) -> (Option<Bytes>, u32) {
        let mut buf = lock(&self.buffer);
        let chunk = buf.pop();
        let notify = if sess.config().version == 2 {
            let len = chunk.as_ref().map_or(0, Bytes::len);
            buf.account_read(len, sess.config().max_stream_buffer)
        } else {
            0
        };
        (chunk, notify)
    }

    /// Drains the stream into `w` until it ends or either side fails, returning the number of
    /// bytes written. Go reports the end of the stream as `(n, io.EOF)`; here it is `Ok(n)`.
    // Go: smux@v1.5.55 stream.go:stream.WriteTo() / writeToV1() / writeToV2()
    async fn write_to<W>(&self, sess: &SessionShared, w: &mut W) -> Result<u64, Error>
    where
        W: AsyncWrite + Unpin + ?Sized,
    {
        let mut n: u64 = 0;
        loop {
            // get the next buffer to write
            let (chunk, notify_consumed) = self.pop_chunk(sess);

            let Some(chunk) = chunk else {
                match self.wait_read(sess).await {
                    WaitRead::Wakeup => continue,
                    WaitRead::Eof => return Ok(n),
                    WaitRead::Failed(err) => return Err(err),
                }
            };

            // write the buffer to w. Go calls `w.Write` once and counts what it reports;
            // `write_all` loops instead, which is what every caller of `WriteTo` wants and
            // what Go's `io.Copy` destinations do anyway.
            let written = w.write_all(&chunk).await;
            // NOTE: WriteTo is a reader, so we need to return tokens here
            sess.return_tokens(chunk.len());
            match written {
                Ok(()) => n += chunk.len() as u64,
                Err(err) => return Err(err.into()),
            }

            // send window update
            if notify_consumed > 0 {
                self.send_window_update(sess, notify_consumed).await?;
            }
        }
    }

    /// Tells the peer how much of its data has been consumed and how large this side's window
    /// is. Control class, so it overtakes queued data frames.
    // Go: smux@v1.5.55 stream.go:sendWindowUpdate()
    async fn send_window_update(&self, sess: &SessionShared, consumed: u32) -> Result<(), Error> {
        let deadline = *lock(&self.read_deadline);
        let window = sess.config().max_stream_buffer as u32;
        let frame = OwnedFrame::with_data(
            self.version,
            CMD_UPD,
            self.id,
            Payload::Upd(*UpdHeader::new(consumed, window).as_bytes()),
        );
        // <-- NOTE(x): use control channel
        sess.write_frame_internal(frame, deadline, ClassId::Ctrl)
            .await?;
        Ok(())
    }

    // -----------------------------------------------------------------------------------
    // Write
    // -----------------------------------------------------------------------------------

    /// Whether the write side is still open.
    // Go: smux@v1.5.55 stream.go:checkWriteClosed()
    fn check_write_closed(&self) -> Result<(), Error> {
        if self.write_closed.is_cancelled() || self.die.is_cancelled() {
            Err(Error::ClosedPipe)
        } else {
            Ok(())
        }
    }

    /// Writes `src` to the peer, returning once every frame has been handed to the connection.
    ///
    /// Concurrent writers interleave their frames in an unspecified order, as in Go.
    // Go: smux@v1.5.55 stream.go:stream.Write()
    async fn write(&self, sess: &SessionShared, src: Chunks<'_>) -> Result<usize, Error> {
        // check empty input
        if src.len() == 0 {
            return Ok(0);
        }
        // check if stream write side has closed
        self.check_write_closed()?;

        if sess.config().version == 2 {
            self.write_v2(sess, src).await
        } else {
            self.write_v1(sess, src).await
        }
    }

    /// Version 1: split into `frameSize` pieces and send them all.
    // Go: smux@v1.5.55 stream.go:writeV1()
    async fn write_v1(&self, sess: &SessionShared, src: Chunks<'_>) -> Result<usize, Error> {
        // create write deadline timer. Go builds it once, before the first frame, so a
        // `SetWriteDeadline` during the call does not move it.
        let deadline = *lock(&self.write_deadline);

        // frame split and transmit
        let mut sent = 0;
        let mut off = 0;
        while off < src.len() {
            let size = (src.len() - off).min(self.frame_size);
            sent += self
                .write_frame(sess, src.chunk(off, size), size, deadline)
                .await?;
            off += size;
        }
        Ok(sent)
    }

    /// Version 2: the same split, inside the peer's sliding window.
    // Go: smux@v1.5.55 stream.go:writeV2()
    async fn write_v2(&self, sess: &SessionShared, src: Chunks<'_>) -> Result<usize, Error> {
        let mut sent = 0;
        let mut off = 0;
        loop {
            // Go resets one reused `time.Timer` on every pass, so a `SetWriteDeadline` between
            // two window waits takes effect. `deadline_at` registers a fresh tokio timer
            // instead of resetting one; the timer wheel makes that O(1), and the wait only
            // happens when the window is exhausted.
            let deadline = *lock(&self.write_deadline);

            // per stream sliding window control
            // [.... [consumed... numWritten] ... win... ]
            // [.... [consumed...................+rmtwnd]]
            // note:
            // even if uint32 overflow, this math still works:
            // eg1: uint32(0) - uint32(math.MaxUint32) = 1
            // eg2: int32(uint32(0) - uint32(1)) = -1
            //
            // basicially, you can take it as a MODULAR ARITHMETIC
            let inflight = self
                .num_written
                .load(Ordering::Acquire)
                .wrapping_sub(self.peer_consumed.load(Ordering::Acquire))
                as i32;
            if inflight < 0 {
                // security check for malformed data
                return Err(Error::Consumed);
            }

            // make sure you understand 'win' is calculated in modular arithmetic(2^32(4GB))
            //
            // `wrapping_sub`: Go's `int32(peerWindow) - inflight` wraps silently, and
            // `peerWindow` is unvalidated peer input (cmdUPD), so a hostile window such as
            // 0x8000_0000 must wrap here exactly as in Go rather than trip the overflow checks
            // of debug/test/fuzz builds (docs/porting-guide.md §3 wrapping arithmetic, §5 never
            // panic on network input).
            let win = (self.peer_window.load(Ordering::Acquire) as i32).wrapping_sub(inflight);

            if win > 0 {
                // determine how many bytes to send
                let end = off + (src.len() - off).min(win as usize);

                // frame split and transmit
                while off < end {
                    // splitting frame
                    let size = (end - off).min(self.frame_size);
                    // transmit of frame
                    sent += self
                        .write_frame(sess, src.chunk(off, size), size, deadline)
                        .await?;
                    off += size;
                }
            }

            // all data has been sent
            if off >= src.len() {
                return Ok(sent);
            }

            // If there is remaining data to be sent,
            // wait until the stream is closed, the window changes, or the deadline is reached.
            // This blocking behavior propagates flow control back to the upper layer
            // (backpressure).
            tokio::select! {
                // wakeup
                () = self.writer_wakeup.notified() => {}
                // local write closed (half-close)
                () = self.write_closed.cancelled() => return Err(Error::ClosedPipe),
                () = self.die.cancelled() => return Err(Error::ClosedPipe),
                () = deadline_at(deadline) => return Err(Error::Timeout),
                err = sess.wait_socket_write_error() => return Err(err),
                // notify of remote data consuming and window update
                () = self.update_event.notified() => {}
            }
        }
    }

    /// Queues one `cmdPSH` and waits until the send task has written it — the backpressure the
    /// proxy relies on. `numWritten` grows before the result is inspected, as in Go.
    // Go: smux@v1.5.55 stream.go:writeV1() / writeV2() (the writeFrameInternal call)
    async fn write_frame(
        &self,
        sess: &SessionShared,
        data: Bytes,
        size: usize,
        deadline: Option<Instant>,
    ) -> Result<usize, Error> {
        let frame = OwnedFrame::with_data(self.version, CMD_PSH, self.id, Payload::Data(data));
        let result = sess
            .write_frame_internal(frame, deadline, ClassId::Data)
            .await;
        self.num_written.fetch_add(size as u32, Ordering::AcqRel);
        result
    }

    // -----------------------------------------------------------------------------------
    // Close
    // -----------------------------------------------------------------------------------

    /// Half-close: stop writing, tell the peer, keep reading.
    // Go: smux@v1.5.55 stream.go:stream.CloseWrite()
    async fn close_write(&self, sess: &SessionShared) -> Result<(), Error> {
        if !self.close_write_side() {
            return Err(Error::ClosedPipe);
        }

        // send FIN to notify the peer that we are done writing
        let result = self.write_fin(sess).await;
        self.try_half_close_cleanup(sess);
        result
    }

    /// Full close: both directions, plus a `cmdFIN` for the peer.
    // Go: smux@v1.5.55 stream.go:stream.Close()
    async fn close(&self, sess: &SessionShared) -> Result<(), Error> {
        if !self.close_die() {
            return Err(Error::ClosedPipe);
        }
        // also close the write side if not already closed
        self.close_write_side();

        // send FIN in order
        let result = self.write_fin(sess).await;
        self.stream_closed(sess);
        result
    }

    /// Sends this side's `cmdFIN`. **Data** class, so it stays ordered behind the stream's
    /// payload, with the 30-second open/close deadline.
    // Go: smux@v1.5.55 stream.go:CloseWrite() / Close() (NOTE(x): use data channel, EOF as data)
    async fn write_fin(&self, sess: &SessionShared) -> Result<(), Error> {
        let frame = OwnedFrame::new(self.version, CMD_FIN, self.id);
        sess.write_frame_internal(
            frame,
            Some(Instant::now() + OPEN_CLOSE_TIMEOUT),
            ClassId::Data,
        )
        .await
        .map(|_| ())
    }

    /// Leaves the session and gives the tokens of whatever was never read back to the bucket.
    ///
    /// Go's `Session.streamClosed` does both at once; deviation V11 splits them, so that only
    /// an explicit close throws received data away.
    // Go: smux@v1.5.55 session.go:streamClosed()
    fn stream_closed(&self, sess: &SessionShared) {
        let n = self.recycle_tokens();
        if n > 0 {
            sess.return_tokens(n);
        }
        sess.stream_closed(self.id);
    }

    /// Test hook: what the last `cmdUPD` said (consumed bytes, peer window).
    #[cfg(test)]
    pub(crate) fn peer_state(&self) -> (u32, u32) {
        (
            self.peer_consumed.load(Ordering::Acquire),
            self.peer_window.load(Ordering::Acquire),
        )
    }

    /// Test hook: a copy of everything buffered, so the session tests can check that payloads
    /// arrived intact without draining them.
    #[cfg(test)]
    pub(crate) fn buffered_bytes(&self) -> Vec<u8> {
        let buf = lock(&self.buffer);
        let mut out = Vec::with_capacity(buf.len);
        for chunk in &buf.chunks {
            out.extend_from_slice(chunk);
        }
        out
    }
}

/// Returns whatever the reader never consumed to the session's token bucket. Go leaks nothing
/// here because `recycleTokens` runs inside `streamClosed`; deviation V11 moves the remainder to
/// this point so the data stays readable for as long as somebody holds the stream.
impl Drop for StreamInner {
    fn drop(&mut self) {
        let n = match self.buffer.get_mut() {
            Ok(buf) => std::mem::take(&mut buf.len),
            Err(poisoned) => std::mem::take(&mut poisoned.into_inner().len),
        };
        if n > 0
            && let Some(sess) = self.sess.upgrade()
        {
            sess.return_tokens(n);
        }
    }
}

/// A multiplexed stream, the handle callers own.
///
/// Go wraps `*stream` in a `Stream` struct only so that a `runtime.SetFinalizer` can close an
/// accepted stream the application forgot about (`session.go:AcceptStream`; the same finalizer
/// is commented out for `OpenStream` because of smux issue #997, where the GC closed streams
/// that were still in use). [`Drop`] does that deterministically here, for opened and accepted
/// streams alike.
///
/// Every method takes `&self`, like Go's `net.Conn`: one task may read while another writes.
// Go: smux@v1.5.55 stream.go:Stream
pub struct Stream {
    inner: Arc<StreamInner>,
    /// Keeps the session state alive for as long as a caller holds the stream (Go's `stream`
    /// holds `sess *Session` strongly for the same reason).
    sess: Arc<SessionShared>,
}

impl Stream {
    pub(crate) fn new(inner: Arc<StreamInner>, sess: Arc<SessionShared>) -> Stream {
        Stream { inner, sess }
    }

    /// The stream's identifier.
    // Go: smux@v1.5.55 stream.go:stream.ID()
    pub fn id(&self) -> u32 {
        self.inner.id()
    }

    /// Reads into `buf`, blocking until data arrives or the stream ends.
    ///
    /// Returns `Ok(0)` at the end of the stream (Go's `io.EOF`) and for an empty `buf`.
    // Go: smux@v1.5.55 stream.go:stream.Read()
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, Error> {
        self.inner.read(&self.sess, buf).await
    }

    /// Takes the next received frame payload whole, without copying it, blocking until one
    /// arrives. `Ok(None)` is the end of the stream.
    ///
    /// This is the drain path for the proxy (step 09): the same token accounting and the same
    /// version-2 window updates as [`read`](Self::read), but the buffer the session received
    /// goes straight to the caller.
    pub async fn read_chunk(&self) -> Result<Option<Bytes>, Error> {
        self.inner.read_chunk(&self.sess).await
    }

    /// Drains the stream into `w` until it ends or either side fails, returning how many bytes
    /// were written. Go reports the end of the stream as `(n, io.EOF)`; here it is `Ok(n)`.
    // Go: smux@v1.5.55 stream.go:stream.WriteTo()
    pub async fn write_to<W>(&self, w: &mut W) -> Result<u64, Error>
    where
        W: AsyncWrite + Unpin + ?Sized,
    {
        self.inner.write_to(&self.sess, w).await
    }

    /// Writes `buf` to the peer, returning once every frame of it has been handed to the
    /// connection.
    // Go: smux@v1.5.55 stream.go:stream.Write()
    pub async fn write(&self, buf: &[u8]) -> Result<usize, Error> {
        self.inner.write(&self.sess, Chunks::Slice(buf)).await
    }

    /// [`write`](Self::write) without the per-frame copy: every frame is a slice of `buf`.
    pub async fn write_bytes(&self, buf: &Bytes) -> Result<usize, Error> {
        self.inner.write(&self.sess, Chunks::Shared(buf)).await
    }

    /// Closes the write side: the peer gets a `cmdFIN` and sees the end of this side's data,
    /// while reading here keeps working. Further writes return [`Error::ClosedPipe`], and so
    /// does a second call.
    // Go: smux@v1.5.55 stream.go:stream.CloseWrite()
    pub async fn close_write(&self) -> Result<(), Error> {
        self.inner.close_write(&self.sess).await
    }

    /// Closes the stream in both directions. A second call returns [`Error::ClosedPipe`], like
    /// Go's `dieOnce`.
    // Go: smux@v1.5.55 stream.go:stream.Close()
    pub async fn close(&self) -> Result<(), Error> {
        self.inner.close(&self.sess).await
    }

    /// Sets the read deadline; `None` disables it. Blocked readers wake up, so they pick the
    /// new value up.
    // Go: smux@v1.5.55 stream.go:stream.SetReadDeadline()
    pub fn set_read_deadline(&self, deadline: Option<Instant>) {
        *lock(&self.inner.read_deadline) = deadline;
        self.inner.wakeup_reader();
    }

    /// Sets the write deadline; `None` disables it.
    // Go: smux@v1.5.55 stream.go:stream.SetWriteDeadline()
    pub fn set_write_deadline(&self, deadline: Option<Instant>) {
        *lock(&self.inner.write_deadline) = deadline;
        self.inner.wakeup_writer();
    }

    /// Sets both deadlines.
    // Go: smux@v1.5.55 stream.go:stream.SetDeadline()
    pub fn set_deadline(&self, deadline: Option<Instant>) {
        self.set_read_deadline(deadline);
        self.set_write_deadline(deadline);
    }

    /// The session's local address, or `None` when the connection has none.
    // Go: smux@v1.5.55 stream.go:stream.LocalAddr()
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.sess.local_addr()
    }

    /// The session's remote address, or `None` when the connection has none.
    // Go: smux@v1.5.55 stream.go:stream.RemoteAddr()
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.sess.remote_addr()
    }

    /// Resolves once the stream is closed. Go hands out the channel itself (`GetDieCh`); here
    /// the future is what a caller selects on.
    // Go: smux@v1.5.55 stream.go:stream.GetDieCh()
    pub async fn closed(&self) {
        self.inner.closed().await;
    }

    /// Whether the stream is closed.
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Bytes received but not yet read.
    ///
    /// Not part of Go's API; the tests and the proxy's accounting need to see the receive
    /// buffer.
    pub fn buffered_len(&self) -> usize {
        self.inner.buffered_len()
    }

    /// Whether the peer has sent its `cmdFIN` (end of the peer's data).
    // Go: smux@v1.5.55 stream.go:stream.chFinEvent
    pub fn got_fin(&self) -> bool {
        self.inner.got_fin()
    }

    /// Test hook: what the last `cmdUPD` said (consumed bytes, peer window).
    #[cfg(test)]
    pub(crate) fn peer_state(&self) -> (u32, u32) {
        self.inner.peer_state()
    }

    /// Test hook: a copy of everything buffered but not yet read.
    #[cfg(test)]
    pub(crate) fn buffered_bytes(&self) -> Vec<u8> {
        self.inner.buffered_bytes()
    }
}

/// Closes a stream whose last handle goes away, so a forgotten stream cannot pin session
/// resources.
///
/// Go attaches `runtime.SetFinalizer(wrapper, func(s *Stream) { s.Close() })` to accepted
/// streams (`session.go:AcceptStream`) and leaves opened ones to the application, because a
/// finalizer that ran while the application still held the stream was a real bug (smux issue
/// #997). `Drop` has neither problem — it runs exactly when the last handle is gone, and never
/// while one exists — so both kinds of stream get it.
///
/// What Go's `Close` does synchronously happens here synchronously: `die` and the write side are
/// closed, the tokens of unread data go back to the bucket, and the stream leaves the session
/// map. The `cmdFIN` is sent by a detached task, because `Drop` cannot await. Without a tokio
/// runtime (a handle dropped after the runtime is gone) only the synchronous half runs, and the
/// session is being torn down in that case anyway.
impl Drop for Stream {
    fn drop(&mut self) {
        if !self.inner.close_die() {
            // Already closed — by `close`, by the session, or by the half-close cleanup, each
            // of which has sent, or deliberately not sent, its own FIN.
            return;
        }
        self.inner.close_write_side();
        self.inner.stream_closed(&self.sess);

        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let sess = Arc::clone(&self.sess);
        let frame = OwnedFrame::new(self.inner.version, CMD_FIN, self.inner.id);
        handle.spawn(async move {
            let _ = sess
                .write_frame_internal(
                    frame,
                    Some(Instant::now() + OPEN_CLOSE_TIMEOUT),
                    ClassId::Data,
                )
                .await;
        });
    }
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stream")
            .field("id", &self.id())
            .field("closed", &self.is_closed())
            .field("buffered", &self.buffered_len())
            .finish()
    }
}

#[cfg(test)]
mod tests;
