//! The multiplexed session: open/accept, the receive and send loops, keepalive and close.
//!
//! Port of `session.go`. Go runs four goroutines per session (`shaperLoop`, `recvLoop`,
//! `sendLoop`, `keepalive`); the port runs three tokio tasks, because `shaperLoop` is merged
//! into the shaper queue itself (DECISIONS D15): writers push into a
//! [`ShaperQueue`](crate::ShaperQueue) behind the session's mutex and the send task pops from
//! it, so the frame order is unchanged and one task hop disappears.
//!
//! What maps to what:
//!
//! | Go | Rust |
//! |---|---|
//! | `die chan struct{}` + `dieOnce` | a `CancellationToken` guarded by the `closed` flag |
//! | `chSocketReadError` + `socketReadError atomic.Value` | [`ErrorSlot`] |
//! | `bucketNotify chan struct{}` (cap 1) | `Notify::notify_one` (one stored permit, same semantics) |
//! | `shaper chan writeRequest` (cap `maxShaperSize`) | a `Semaphore` of [`MAX_SHAPER_SIZE`] permits |
//! | `chAccepts chan *stream` (cap `defaultAcceptBacklog`) | an `mpsc` channel of the same capacity |
//! | `result chan writeResult` (pooled) | a `oneshot` channel per request |
//!
//! Two internal differences, neither visible on the wire:
//!
//! - `recv_loop` reads through a [`RECV_BUFFER_SIZE`]-byte buffered reader instead of issuing an
//!   `io.ReadFull` per header and per payload. The session may therefore hold up to one buffer
//!   of not-yet-processed bytes beyond what the token bucket admits.
//! - The receive and send loops also wake on `die`, so a session whose connection never fails
//!   still releases its tasks. Go relies on `Close()` closing the connection to unblock them,
//!   which a `Drop` cannot do because closing is asynchronous.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use crate::conn::SmuxConn;
use crate::error::Error;
use crate::frame::{
    CMD_FIN, CMD_NOP, CMD_PSH, CMD_SYN, CMD_UPD, HEADER_SIZE, RawHeader, SZ_CMD_UPD, UpdHeader,
};
use crate::mux::Config;
use crate::shaper::{ShaperQueue, WriteRequest};
use crate::stream::{Stream, StreamInner};

// Go: smux@v1.5.55 session.go:defaultAcceptBacklog
/// Streams the peer may open before `accept_stream` has to take them.
pub const DEFAULT_ACCEPT_BACKLOG: usize = 1024;

// Go: smux@v1.5.55 session.go:minShaperNotifySize
/// Queue length above which Go's `shaperLoop` notifies the send loop even though more requests
/// are already waiting in the channel. The port merges `shaperLoop` into the shaper queue
/// itself (DECISIONS D15), so it only documents the batching Go does; the frame order is
/// unaffected.
pub const MIN_SHAPER_NOTIFY_SIZE: usize = 16;

// Go: smux@v1.5.55 session.go:maxShaperSize
/// Pending write requests the shaper admits before writers have to wait.
pub const MAX_SHAPER_SIZE: usize = 1024;

// Go: smux@v1.5.55 session.go:openCloseTimeout
/// Deadline for the `cmdSYN` of `open_stream` and the `cmdFIN` of `close`/`close_write`.
pub const OPEN_CLOSE_TIMEOUT: Duration = Duration::from_secs(30);

/// Size of `recv_loop`'s buffered reader. Go issues one `io.ReadFull` per header and one per
/// payload; reading ahead into this buffer is an internal optimisation (plan 06 "Design").
///
/// It is deliberately smaller than the largest frame payload (`max_frame_size` is capped at
/// 65535 by `verify_config`), so that a big payload is read straight into the stream's buffer
/// instead of being copied through this one; see [`BufConnReader::read_full`].
const RECV_BUFFER_SIZE: usize = 32 * 1024;

/// Priority class of a write request. Control frames (`cmdSYN`, `cmdUPD`, and the `cmdNOP`
/// keepalive on stream 0) go before data frames (`cmdPSH` and, so it stays ordered behind the
/// stream's data, `cmdFIN`) of the same stream.
///
/// The discriminants are Go's, and the ordering is the one `shaperHeap.Less` uses.
// Go: smux@v1.5.55 session.go:CLASSID (CLSCTRL, CLSDATA)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClassId {
    /// Prioritized control signal.
    Ctrl = 0,
    /// Stream data.
    Data = 1,
}

/// Locks a mutex that is only ever held for short, panic-free critical sections, recovering the
/// data if a previous holder panicked anyway. A poisoned lock would otherwise take the whole
/// session down, which Go's `sync.Mutex` never does.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The payload of a queued frame.
///
/// Go's `Frame.data` points into the caller's buffer and stays valid because `Write` blocks
/// until `sendLoop` has written the frame. A queued request here crosses to another task, so it
/// owns its payload; the control frames that carry none, and the 8-byte `cmdUPD` payload, are
/// kept inline so no session ever allocates for them.
// Go: smux@v1.5.55 frame.go:Frame.data
#[derive(Clone, Debug)]
pub(crate) enum Payload {
    /// No payload (`cmdSYN`, `cmdFIN`, `cmdNOP`).
    Empty,
    /// A `cmdUPD` payload.
    Upd([u8; SZ_CMD_UPD]),
    /// A `cmdPSH` payload.
    Data(Bytes),
}

impl Payload {
    /// The payload bytes.
    pub(crate) fn as_slice(&self) -> &[u8] {
        match self {
            Payload::Empty => &[],
            Payload::Upd(b) => b.as_slice(),
            Payload::Data(b) => b.as_ref(),
        }
    }
}

/// A frame waiting to be written, with an owned payload.
// Go: smux@v1.5.55 frame.go:Frame
#[derive(Clone, Debug)]
pub(crate) struct OwnedFrame {
    /// Protocol version.
    pub(crate) ver: u8,
    /// Command (`CMD_*`).
    pub(crate) cmd: u8,
    /// Stream id.
    pub(crate) sid: u32,
    /// Payload.
    pub(crate) data: Payload,
}

impl OwnedFrame {
    /// A frame without a payload.
    // Go: smux@v1.5.55 frame.go:newFrame()
    pub(crate) fn new(ver: u8, cmd: u8, sid: u32) -> OwnedFrame {
        OwnedFrame {
            ver,
            cmd,
            sid,
            data: Payload::Empty,
        }
    }

    /// A frame with a payload.
    pub(crate) fn with_data(ver: u8, cmd: u8, sid: u32, data: Payload) -> OwnedFrame {
        OwnedFrame {
            ver,
            cmd,
            sid,
            data,
        }
    }
}

/// What the shaper carries besides the ordering keys: the frame and where to report the result.
// Go: smux@v1.5.55 session.go:writeRequest
struct RequestBody {
    frame: OwnedFrame,
    result: oneshot::Sender<Result<usize, Error>>,
    /// Admission slot, released as soon as the request leaves the queue.
    permit: OwnedSemaphorePermit,
}

/// A once-set error with a broadcast wake-up: Go's `atomic.Value` plus `sync.Once` plus closed
/// channel, in one place.
// Go: smux@v1.5.55 session.go:socketReadError/chSocketReadError/socketReadErrorOnce
#[derive(Debug, Default)]
struct ErrorSlot {
    err: OnceLock<Error>,
    token: CancellationToken,
}

impl ErrorSlot {
    /// Stores `err` if this is the first call, then wakes the waiters (Go's order: store into
    /// the `atomic.Value`, then close the channel).
    fn set(&self, err: Error) {
        if self.err.set(err).is_ok() {
            self.token.cancel();
        }
    }

    /// The stored error, if any.
    fn get(&self) -> Option<Error> {
        self.err.get().cloned()
    }

    /// Whether the slot has been set.
    fn is_set(&self) -> bool {
        self.token.is_cancelled()
    }

    /// Resolves with the error once the slot is set, and never otherwise.
    async fn wait(&self) -> Error {
        self.token.cancelled().await;
        // `set` publishes the value before cancelling, so this is always `Some`.
        self.get().unwrap_or(Error::ClosedPipe)
    }
}

/// The next stream id this side may use, with Go's exhaustion flag.
// Go: smux@v1.5.55 session.go:Session.nextStreamID/goAway (guarded by nextStreamIDLock)
#[derive(Debug)]
struct NextStreamId {
    id: u32,
    go_away: bool,
}

/// Everything about a session that does not depend on the connection type.
///
/// Streams hold this, not [`Session`], so a [`Stream`] is not generic over the connection.
// Go: smux@v1.5.55 session.go:Session
pub(crate) struct SessionShared {
    config: Config,
    /// `byte(config.Version)`: the version every frame this session writes carries, and the one
    /// every frame it accepts must match.
    version: u8,
    local_addr: Option<SocketAddr>,
    remote_addr: Option<SocketAddr>,

    next_stream_id: Mutex<NextStreamId>,

    // Go: smux@v1.5.55 session.go:Session.bucket/bucketNotify
    bucket: AtomicI32,
    bucket_notify: Notify,

    // Go: smux@v1.5.55 session.go:Session.streams/streamLock
    streams: Mutex<HashMap<u32, Arc<StreamInner>>>,

    // Go: smux@v1.5.55 session.go:Session.die/dieOnce/closed
    die: CancellationToken,
    closed: AtomicBool,

    socket_read_error: ErrorSlot,
    socket_write_error: ErrorSlot,
    proto_error: ErrorSlot,

    // Go: smux@v1.5.55 session.go:Session.chAccepts
    accepts_tx: mpsc::Sender<Arc<StreamInner>>,
    accepts_rx: tokio::sync::Mutex<mpsc::Receiver<Arc<StreamInner>>>,

    // Go: smux@v1.5.55 session.go:Session.sessionIsActive
    session_is_active: AtomicBool,
    // Go: smux@v1.5.55 session.go:Session.acceptDeadline
    accept_deadline: Mutex<Option<Instant>>,

    // Go: smux@v1.5.55 session.go:Session.requestID/shaper/sq/chShaperPending
    request_id: AtomicU32,
    shaper: Mutex<ShaperQueue<RequestBody>>,
    shaper_pending: Notify,
    shaper_slots: Arc<Semaphore>,
}

impl SessionShared {
    // Go: smux@v1.5.55 session.go:newSession()
    fn new(
        config: Config,
        client: bool,
        local_addr: Option<SocketAddr>,
        remote_addr: Option<SocketAddr>,
    ) -> SessionShared {
        let (accepts_tx, accepts_rx) = mpsc::channel(DEFAULT_ACCEPT_BACKLOG);
        SessionShared {
            version: config.version as u8,
            local_addr,
            remote_addr,
            next_stream_id: Mutex::new(NextStreamId {
                id: if client { 1 } else { 0 },
                go_away: false,
            }),
            bucket: AtomicI32::new(config.max_receive_buffer as i32),
            bucket_notify: Notify::new(),
            streams: Mutex::new(HashMap::new()),
            die: CancellationToken::new(),
            closed: AtomicBool::new(false),
            socket_read_error: ErrorSlot::default(),
            socket_write_error: ErrorSlot::default(),
            proto_error: ErrorSlot::default(),
            accepts_tx,
            accepts_rx: tokio::sync::Mutex::new(accepts_rx),
            session_is_active: AtomicBool::new(false),
            accept_deadline: Mutex::new(None),
            request_id: AtomicU32::new(0),
            shaper: Mutex::new(ShaperQueue::new()),
            shaper_pending: Notify::new(),
            shaper_slots: Arc::new(Semaphore::new(MAX_SHAPER_SIZE)),
            config,
        }
    }

    /// The session's configuration.
    pub(crate) fn config(&self) -> &Config {
        &self.config
    }

    /// Resolves with the connection's read error once `recv_loop` has stored one.
    // Go: smux@v1.5.55 session.go:Session.chSocketReadError/socketReadError
    pub(crate) async fn wait_socket_read_error(&self) -> Error {
        self.socket_read_error.wait().await
    }

    /// Resolves with the connection's write error once `send_loop` has stored one.
    // Go: smux@v1.5.55 session.go:Session.chSocketWriteError/socketWriteError
    pub(crate) async fn wait_socket_write_error(&self) -> Error {
        self.socket_write_error.wait().await
    }

    /// Resolves with the protocol error once `recv_loop` has stored one.
    // Go: smux@v1.5.55 session.go:Session.chProtoError/protoError
    pub(crate) async fn wait_proto_error(&self) -> Error {
        self.proto_error.wait().await
    }

    /// The connection's read error, if one has been stored (Go's already-closed
    /// `chSocketReadError` case of a `select`).
    // Go: smux@v1.5.55 session.go:Session.socketReadError
    pub(crate) fn socket_read_error(&self) -> Option<Error> {
        self.socket_read_error.get()
    }

    /// The protocol error, if one has been stored.
    // Go: smux@v1.5.55 session.go:Session.protoError
    pub(crate) fn proto_error(&self) -> Option<Error> {
        self.proto_error.get()
    }

    /// The local address of the underlying connection, if it has one.
    // Go: smux@v1.5.55 session.go:Session.LocalAddr()
    pub(crate) fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// The remote address of the underlying connection, if it has one.
    // Go: smux@v1.5.55 session.go:Session.RemoteAddr()
    pub(crate) fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    /// Wakes `recv_loop` when tokens are available.
    // Go: smux@v1.5.55 session.go:notifyBucket()
    fn notify_bucket(&self) {
        self.bucket_notify.notify_one();
    }

    // Go: smux@v1.5.55 session.go:notifyReadError()
    fn notify_read_error(&self, err: Error) {
        self.socket_read_error.set(err);
    }

    // Go: smux@v1.5.55 session.go:notifyWriteError()
    fn notify_write_error(&self, err: Error) {
        self.socket_write_error.set(err);
    }

    // Go: smux@v1.5.55 session.go:notifyProtoError()
    fn notify_proto_error(&self, err: Error) {
        self.proto_error.set(err);
    }

    /// Returns `n` tokens to the bucket after a reader consumed that many bytes.
    // Go: smux@v1.5.55 session.go:returnTokens()
    pub(crate) fn return_tokens(&self, n: usize) {
        let n = n as i32;
        if self.bucket.fetch_add(n, Ordering::AcqRel).wrapping_add(n) > 0 {
            self.notify_bucket();
        }
    }

    /// Removes a stream that has finished.
    ///
    /// **Deviation V11.** Go also calls `stream.recycleTokens()` here, discarding data that
    /// arrived but was never read. Here the buffered data stays with the stream and its tokens
    /// come back as it is read, or when the last handle is dropped.
    // Go: smux@v1.5.55 session.go:streamClosed()
    pub(crate) fn stream_closed(&self, sid: u32) {
        lock(&self.streams).remove(&sid);
    }

    /// Whether the session is closed.
    // Go: smux@v1.5.55 session.go:IsClosed()
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Number of currently open streams.
    // Go: smux@v1.5.55 session.go:NumStreams()
    pub(crate) fn num_streams(&self) -> usize {
        if self.is_closed() {
            return 0;
        }
        lock(&self.streams).len()
    }

    /// Sets the deadline used by `accept_stream`. `None` disables it (Go: the zero `time.Time`).
    // Go: smux@v1.5.55 session.go:SetDeadline()
    pub(crate) fn set_deadline(&self, deadline: Option<Instant>) {
        *lock(&self.accept_deadline) = deadline;
    }

    /// Resolves once the session is closed.
    // Go: smux@v1.5.55 session.go:CloseChan()
    pub(crate) async fn closed(&self) {
        self.die.cancelled().await;
    }

    /// Opens a new stream: allocate the id, send `cmdSYN`, then register it.
    // Go: smux@v1.5.55 session.go:OpenStream()
    pub(crate) async fn open_stream(self: &Arc<Self>) -> Result<Stream, Error> {
        if self.is_closed() {
            return Err(Error::ClosedPipe);
        }

        // generate stream id
        let sid = {
            let mut next = lock(&self.next_stream_id);
            if next.go_away {
                return Err(Error::GoAway);
            }
            // check for stream id overflow
            if next.id.wrapping_add(2) < next.id {
                next.go_away = true;
                return Err(Error::GoAway);
            }
            // allocate next stream id
            next.id = next.id.wrapping_add(2);
            next.id
        };

        let stream = StreamInner::new(sid, self);

        self.write_control_frame(OwnedFrame::new(self.version, CMD_SYN, sid))
            .await?;

        // Go takes streamLock and then runs a `select` whose `default` registers the stream;
        // all three failure cases are plain flag checks here.
        let mut streams = lock(&self.streams);
        if self.socket_read_error.is_set() {
            return Err(self.socket_read_error.get().unwrap_or(Error::ClosedPipe));
        }
        if self.socket_write_error.is_set() {
            return Err(self.socket_write_error.get().unwrap_or(Error::ClosedPipe));
        }
        if self.die.is_cancelled() {
            return Err(Error::ClosedPipe);
        }
        streams.insert(sid, Arc::clone(&stream));
        drop(streams);
        Ok(Stream::new(stream, Arc::clone(self)))
    }

    /// Blocks until the peer opens a stream.
    // Go: smux@v1.5.55 session.go:AcceptStream()
    pub(crate) async fn accept_stream(self: &Arc<Self>) -> Result<Stream, Error> {
        let deadline = *lock(&self.accept_deadline);
        // The receiver is locked only inside the branch, so a cancelled accept (deadline, die)
        // releases it, and Go's concurrent `AcceptStream` keeps working.
        let accepted = async {
            let mut rx = self.accepts_rx.lock().await;
            rx.recv().await
        };

        tokio::select! {
            stream = accepted => match stream {
                Some(inner) => Ok(Stream::new(inner, Arc::clone(self))),
                // Unreachable: the session itself holds the sender.
                None => Err(Error::ClosedPipe),
            },
            () = deadline_at(deadline) => Err(Error::Timeout),
            err = self.socket_read_error.wait() => Err(err),
            err = self.proto_error.wait() => Err(err),
            () = self.die.cancelled() => Err(Error::ClosedPipe),
        }
    }

    /// Writes a control frame with the 30-second open/close deadline.
    // Go: smux@v1.5.55 session.go:writeControlFrame()
    pub(crate) async fn write_control_frame(&self, frame: OwnedFrame) -> Result<usize, Error> {
        self.write_frame_internal(
            frame,
            Some(Instant::now() + OPEN_CLOSE_TIMEOUT),
            ClassId::Ctrl,
        )
        .await
    }

    /// Queues a frame and waits until the send task has written it, returning the number of
    /// payload bytes written.
    ///
    /// The two `select!`s are Go's two `select` statements: the first is admission into the
    /// shaper (Go: `s.shaper <- req`, bounded by the channel's capacity; here a semaphore of
    /// [`MAX_SHAPER_SIZE`] permits, D15), the second waits for the result. Both also abort on
    /// `die`, on a socket write error and on the deadline. Like Go, a request that was already
    /// queued when the caller gives up stays queued and its result is discarded.
    // Go: smux@v1.5.55 session.go:writeFrameInternal()
    pub(crate) async fn write_frame_internal(
        &self,
        frame: OwnedFrame,
        deadline: Option<Instant>,
        class: ClassId,
    ) -> Result<usize, Error> {
        // Go: atomic.AddUint32 returns the incremented value, so the first request has seq 1.
        let seq = self
            .request_id
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        let sid = frame.sid;
        let (tx, rx) = oneshot::channel();

        let permit = {
            let acquire = Arc::clone(&self.shaper_slots).acquire_owned();
            tokio::select! {
                permit = acquire => match permit {
                    Ok(permit) => permit,
                    // Unreachable: the semaphore is never closed.
                    Err(_) => return Err(Error::ClosedPipe),
                },
                () = self.die.cancelled() => return Err(Error::ClosedPipe),
                err = self.socket_write_error.wait() => return Err(err),
                () = deadline_at(deadline) => return Err(Error::Timeout),
            }
        };

        lock(&self.shaper).push(WriteRequest {
            class,
            sid,
            seq,
            body: RequestBody {
                frame,
                result: tx,
                permit,
            },
        });
        self.shaper_pending.notify_one();

        tokio::select! {
            result = rx => match result {
                Ok(result) => result,
                // The send task dropped the sender without answering, which only happens once
                // it has stopped; the write-error slot carries the reason, if there is one.
                Err(_) => Err(self.socket_write_error.get().unwrap_or(Error::ClosedPipe)),
            },
            () = self.die.cancelled() => Err(Error::ClosedPipe),
            err = self.socket_write_error.wait() => Err(err),
            () = deadline_at(deadline) => Err(Error::Timeout),
        }
    }

    /// The shared half of `Close`: mark the session dead and release every stream. Returns
    /// whether this call was the one that closed it (Go's `dieOnce`).
    // Go: smux@v1.5.55 session.go:Close()
    fn close_shared(&self) -> bool {
        if self
            .closed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        self.die.cancel();

        // Go keeps the entries in the map; NumStreams reports 0 once the session is closed.
        for stream in lock(&self.streams).values() {
            stream.session_close();
        }
        true
    }

    /// Test hook: place the stream-id counter near the `uint32` wrap, so `open_stream` can be
    /// driven into [`Error::GoAway`] without opening four billion streams.
    #[cfg(test)]
    pub(crate) fn set_next_stream_id(&self, id: u32) {
        lock(&self.next_stream_id).id = id;
    }

    /// Test hook: the current token bucket.
    #[cfg(test)]
    pub(crate) fn bucket(&self) -> i32 {
        self.bucket.load(Ordering::Acquire)
    }
}

/// A future that resolves at `deadline`, or never when there is none (Go's nil
/// `<-chan time.Time`, which blocks forever in a `select`).
pub(crate) async fn deadline_at(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// A multiplexed session over `C`.
///
/// Dropping the session closes it, so its tasks do not outlive it. Go has no equivalent (the
/// goroutines live until the connection fails), but a leaked task is worse than a leaked
/// reference; porting guide §6. Hold the session in an `Arc` to share it.
// Go: smux@v1.5.55 session.go:Session
pub struct Session<C: SmuxConn> {
    shared: Arc<SessionShared>,
    conn: Arc<C>,
}

impl<C: SmuxConn> Session<C> {
    // Go: smux@v1.5.55 session.go:newSession()
    pub(crate) fn new(config: Config, conn: C, client: bool) -> Session<C> {
        let conn = Arc::new(conn);
        let shared = Arc::new(SessionShared::new(
            config,
            client,
            conn.local_addr(),
            conn.remote_addr(),
        ));

        tokio::spawn(recv_loop(Arc::clone(&shared), Arc::clone(&conn)));
        tokio::spawn(send_loop(Arc::clone(&shared), Arc::clone(&conn)));
        if !config.keep_alive_disabled {
            tokio::spawn(keepalive(Arc::clone(&shared), Arc::clone(&conn)));
        }

        Session { shared, conn }
    }

    /// Opens a new stream.
    // Go: smux@v1.5.55 session.go:OpenStream()
    pub async fn open_stream(&self) -> Result<Stream, Error> {
        self.shared.open_stream().await
    }

    /// Blocks until the peer opens a stream.
    // Go: smux@v1.5.55 session.go:AcceptStream()
    pub async fn accept_stream(&self) -> Result<Stream, Error> {
        self.shared.accept_stream().await
    }

    /// Closes the session, every stream in it, and the underlying connection. A second call
    /// returns [`Error::ClosedPipe`], like Go's `dieOnce`.
    // Go: smux@v1.5.55 session.go:Close()
    pub async fn close(&self) -> Result<(), Error> {
        close_session(&self.shared, &*self.conn).await
    }

    /// Whether the session is closed.
    // Go: smux@v1.5.55 session.go:IsClosed()
    pub fn is_closed(&self) -> bool {
        self.shared.is_closed()
    }

    /// Number of currently open streams (0 once the session is closed).
    // Go: smux@v1.5.55 session.go:NumStreams()
    pub fn num_streams(&self) -> usize {
        self.shared.num_streams()
    }

    /// Sets the deadline `accept_stream` uses. `None` disables it.
    // Go: smux@v1.5.55 session.go:SetDeadline()
    pub fn set_deadline(&self, deadline: Option<Instant>) {
        self.shared.set_deadline(deadline);
    }

    /// Resolves once the session is closed. Go hands out the `die` channel itself
    /// (`CloseChan`); here the future is what a caller selects on.
    // Go: smux@v1.5.55 session.go:CloseChan()
    pub async fn closed(&self) {
        self.shared.closed().await;
    }

    /// The local address of the underlying connection, if it has one.
    // Go: smux@v1.5.55 session.go:LocalAddr()
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.shared.local_addr()
    }

    /// The remote address of the underlying connection, if it has one.
    // Go: smux@v1.5.55 session.go:RemoteAddr()
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.shared.remote_addr()
    }

    /// The configuration this session runs with.
    pub fn config(&self) -> &Config {
        self.shared.config()
    }

    /// The state streams share with the session; the tests reach into it.
    #[cfg(test)]
    pub(crate) fn shared(&self) -> &Arc<SessionShared> {
        &self.shared
    }
}

impl<C: SmuxConn> std::fmt::Debug for Session<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("version", &self.shared.version)
            .field("closed", &self.is_closed())
            .field("num_streams", &self.num_streams())
            .field("remote_addr", &self.remote_addr())
            .finish()
    }
}

impl<C: SmuxConn> Drop for Session<C> {
    fn drop(&mut self) {
        // `conn.close()` cannot be awaited here; the tasks exit on `die` and drop the last
        // `Arc<C>`, which closes the connection.
        self.shared.close_shared();
    }
}

/// `Session::close`, also usable from the keepalive task, which owns the connection but no
/// `Session`.
// Go: smux@v1.5.55 session.go:Close()
async fn close_session<C: SmuxConn>(shared: &SessionShared, conn: &C) -> Result<(), Error> {
    if !shared.close_shared() {
        return Err(Error::ClosedPipe);
    }
    conn.close().await.map_err(Error::from)
}

/// A buffered reader over a [`SmuxConn`].
///
/// Go's `recvLoop` issues an `io.ReadFull` per 8-byte header and one per payload. Reading ahead
/// into one buffer turns the header reads into memory copies; payloads at least as large as the
/// buffer bypass it and are read straight into their destination.
struct BufConnReader<C> {
    conn: Arc<C>,
    buf: Box<[u8]>,
    pos: usize,
    cap: usize,
}

impl<C: SmuxConn> BufConnReader<C> {
    fn new(conn: Arc<C>, size: usize) -> BufConnReader<C> {
        BufConnReader {
            conn,
            buf: vec![0u8; size].into_boxed_slice(),
            pos: 0,
            cap: 0,
        }
    }

    /// Fills `out` completely, with `io.ReadFull`'s errors: `EOF` when the stream ended before
    /// any byte of `out` was produced, `unexpected EOF` when it ended part-way through.
    // Go: io.ReadFull, as used by session.go:recvLoop()
    async fn read_full(&mut self, out: &mut [u8]) -> io::Result<()> {
        let mut done = 0;
        while done < out.len() {
            if self.pos == self.cap {
                // Payloads at least as large as the buffer skip it entirely.
                if out.len() - done >= self.buf.len() {
                    let n = self.conn.read(&mut out[done..]).await?;
                    if n == 0 {
                        return Err(eof_error(done));
                    }
                    done += n;
                    continue;
                }
                self.pos = 0;
                self.cap = 0;
                let n = self.conn.read(&mut self.buf).await?;
                if n == 0 {
                    return Err(eof_error(done));
                }
                self.cap = n;
            }
            let take = (self.cap - self.pos).min(out.len() - done);
            out[done..done + take].copy_from_slice(&self.buf[self.pos..self.pos + take]);
            self.pos += take;
            done += take;
        }
        Ok(())
    }
}

/// `io.EOF` or `io.ErrUnexpectedEOF`, with Go's texts (porting guide §4).
fn eof_error(read_so_far: usize) -> io::Error {
    if read_so_far == 0 {
        io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")
    } else {
        io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
    }
}

/// Runs `f` unless the session dies first.
async fn or_die<T>(die: &CancellationToken, f: impl Future<Output = T>) -> Option<T> {
    tokio::select! {
        value = f => Some(value),
        () = die.cancelled() => None,
    }
}

/// Reads frames from the connection while the token bucket allows it.
// Go: smux@v1.5.55 session.go:recvLoop()
// Go (post-pin fix, V01): smux@v1.5.57 session.go:recvLoop() (length validation)
async fn recv_loop<C: SmuxConn>(shared: Arc<SessionShared>, conn: Arc<C>) {
    let mut reader = BufConnReader::new(conn, RECV_BUFFER_SIZE);
    let mut hdr = [0u8; HEADER_SIZE];
    let mut upd = [0u8; SZ_CMD_UPD];

    loop {
        // Wait until we have tokens or the session is closed.
        while shared.bucket.load(Ordering::Acquire) <= 0 && !shared.is_closed() {
            let notified = shared.bucket_notify.notified();
            tokio::pin!(notified);
            // Register before re-checking, so a return of tokens cannot be missed.
            notified.as_mut().enable();
            if shared.bucket.load(Ordering::Acquire) > 0 || shared.is_closed() {
                break;
            }
            tokio::select! {
                () = notified => {}
                // Go returns here so that Accept and OpenStream are unblocked by `die` itself.
                () = shared.die.cancelled() => return,
            }
        }

        // As long as we have tokens, try to read frames: the header first.
        match or_die(&shared.die, reader.read_full(&mut hdr)).await {
            None => return,
            Some(Err(err)) => {
                shared.notify_read_error(err.into());
                return;
            }
            Some(Ok(())) => {}
        }

        // Mark the session as active.
        shared.session_is_active.store(true, Ordering::Release);

        // Validate the protocol version, the command, and — per DECISIONS V01 — the payload
        // length. Go spreads these over the version check and the command switch; every branch
        // ends in the same `ErrInvalidProtocol` and the same shutdown.
        let header = RawHeader::from_array(hdr);
        if header.check_protocol(shared.version).is_err() {
            shared.notify_proto_error(Error::InvalidProtocol);
            return;
        }

        let sid = header.stream_id();
        match header.cmd() {
            CMD_NOP => {}
            // stream opening
            CMD_SYN => {
                let accepted = {
                    let mut streams = lock(&shared.streams);
                    match streams.entry(sid) {
                        Entry::Occupied(_) => None,
                        Entry::Vacant(slot) => {
                            let stream = StreamInner::new(sid, &shared);
                            slot.insert(Arc::clone(&stream));
                            Some(stream)
                        }
                    }
                };

                if let Some(accepted) = accepted
                    && or_die(&shared.die, shared.accepts_tx.send(accepted))
                        .await
                        .is_none()
                {
                    return;
                }
            }
            // stream closing
            CMD_FIN => {
                let stream = lock(&shared.streams).get(&sid).cloned();
                if let Some(stream) = stream {
                    // fin unblocks the readers and writers
                    stream.fin(&shared);
                }
            }
            // data frame
            CMD_PSH => {
                let length = usize::from(header.length());
                if length == 0 {
                    continue;
                }

                // read payload from the underlying connection
                let mut payload = vec![0u8; length];
                match or_die(&shared.die, reader.read_full(&mut payload)).await {
                    None => return,
                    Some(Err(err)) => {
                        shared.notify_read_error(err.into());
                        return;
                    }
                    Some(Ok(())) => {}
                }

                // push data to the corresponding stream
                let streams = lock(&shared.streams);
                if let Some(stream) = streams.get(&sid) {
                    stream.push_bytes(Bytes::from(payload));
                    // deduct tokens from the bucket
                    shared.bucket.fetch_sub(length as i32, Ordering::AcqRel);
                    stream.wakeup_reader();
                }
                // Data for a missing or closed stream is dropped and costs no tokens.
                drop(streams);
            }
            // a window update signal (v2 only). `check_protocol` already rejected `cmdUPD` on a
            // v1 session and any length other than szCmdUPD.
            CMD_UPD => {
                match or_die(&shared.die, reader.read_full(&mut upd)).await {
                    None => return,
                    Some(Err(err)) => {
                        shared.notify_read_error(err.into());
                        return;
                    }
                    Some(Ok(())) => {}
                }

                let stream = lock(&shared.streams).get(&sid).cloned();
                if let Some(stream) = stream {
                    let upd = UpdHeader::from_array(upd);
                    stream.update(upd.consumed(), upd.window());
                }
            }
            // Unreachable: `check_protocol` rejects every other command.
            _ => {
                shared.notify_proto_error(Error::InvalidProtocol);
                return;
            }
        }
    }
}

/// Writes queued frames to the connection, in the shaper's order.
// Go: smux@v1.5.55 session.go:sendLoop()
async fn send_loop<C: SmuxConn>(shared: Arc<SessionShared>, conn: Arc<C>) {
    loop {
        let pending = shared.shaper_pending.notified();
        tokio::pin!(pending);
        // Register before checking the queue, so a push cannot be missed.
        pending.as_mut().enable();
        if lock(&shared.shaper).is_empty() {
            tokio::select! {
                () = pending => {}
                () = shared.die.cancelled() => return,
            }
        }

        loop {
            let Some(request) = lock(&shared.shaper).pop() else {
                break;
            };
            let RequestBody {
                frame,
                result,
                permit,
            } = request.body;
            // The request has left the queue: let another writer in.
            drop(permit);

            let payload_len = frame.data.as_slice().len();
            let header = RawHeader::new(frame.ver, frame.cmd, payload_len as u16, frame.sid);

            let written = {
                let bufs: [&[u8]; 2] = [header.as_bytes().as_slice(), frame.data.as_slice()];
                match or_die(&shared.die, conn.write_all_vectored(&bufs)).await {
                    Some(written) => written,
                    None => return,
                }
            };

            // Go: `n -= headerSize; if n < 0 { n = 0 }`.
            let outcome = match written {
                Ok(n) => Ok(n.saturating_sub(HEADER_SIZE)),
                Err(err) => Err(Error::from(err)),
            };
            let failure = outcome.clone().err();
            // The caller may have given up already; Go writes into a buffered channel that
            // nobody reads any more.
            let _ = result.send(outcome);

            // store conn error
            if let Some(err) = failure {
                shared.notify_write_error(err);
                return;
            }
        }
    }
}

/// Sends `cmdNOP` every interval and closes the session when nothing arrives for a timeout.
// Go: smux@v1.5.55 session.go:keepalive()
async fn keepalive<C: SmuxConn>(shared: Arc<SessionShared>, conn: Arc<C>) {
    let interval = shared.config.keep_alive_interval;
    let timeout = shared.config.keep_alive_timeout;

    // Go's time.Ticker does not fire immediately, and a slow receiver misses ticks rather than
    // getting a burst of them: `interval_at(now + period, period)` with `Skip` is that schedule.
    let mut ping = tokio::time::interval_at(Instant::now() + interval, interval);
    ping.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut expiry = tokio::time::interval_at(Instant::now() + timeout, timeout);
    expiry.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ping.tick() => {
                // Go: `writeFrameInternal(newFrame(...), tickerPing.C, CLSCTRL)` — the deadline
                // *is* the ping ticker's channel, so a keepalive write that cannot get through
                // gives up at the next ping tick **and consumes that tick**. Racing the write
                // against `ping.tick()` reproduces both halves. Consuming the tick matters: an
                // explicit instant would leave the tick pending, so on a wedged connection the
                // ping and the timeout would become ready at the same moment and `select!`
                // would choose at random, letting the session survive a random multiple of
                // KeepAliveTimeout instead of exactly one.
                // Dropping the write future is what Go's timeout does as well: a request that
                // was already queued stays queued and its result is discarded.
                let frame = OwnedFrame::new(shared.version, CMD_NOP, 0);
                let write = shared.write_frame_internal(frame, None, ClassId::Ctrl);
                tokio::pin!(write);
                tokio::select! {
                    _ = &mut write => {}
                    // `Interval::tick` is cancel-safe, and the outer `select!` has already
                    // dropped its own borrow of `ping` before this body runs.
                    _ = ping.tick() => {}
                }
                // force a wakeup signal to the recvLoop
                shared.notify_bucket();
            }
            _ = expiry.tick() => {
                if shared
                    .session_is_active
                    .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    // recvLoop may block while the bucket is empty; in that case the session
                    // must not be closed.
                    if shared.bucket.load(Ordering::Acquire) > 0 {
                        let _ = close_session(&shared, &*conn).await;
                        return;
                    }
                }
            }
            () = shared.die.cancelled() => return,
        }
    }
}

#[cfg(test)]
mod tests;
