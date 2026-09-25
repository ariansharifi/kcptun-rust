//! The KCP session (port of kcp-go `sess.go:UDPSession`).
//!
//! ```text
//! network ─▶ decryption ─▶ CRC32 ─▶ FEC decoding ─▶ KCP input ─▶ stream ─▶ application
//! ```
//!
//! [`UdpSession::packet_input`] (decryption and integrity) and [`UdpSession::kcp_input`] (FEC
//! demux, OOB delivery and the KCP state machine) are the **incoming** half of that pipeline; the
//! outgoing half lives in [`crate::tx`]. On top of them sits the `net.Conn` surface Go exposes:
//! [`UdpSession::read`], [`UdpSession::write`]/[`UdpSession::write_buffers`],
//! [`UdpSession::close`], the deadlines and every setter and getter of `sess.go`. [`Updater`]
//! is the per-session flush timer Go drives from its global `SystemTimedSched` (DECISIONS D03),
//! and [`ReadLoop`] is the client's `readLoop` goroutine, which filters datagrams by source
//! address before feeding them to `packet_input`. [`UdpSession::dial_with_options`] and
//! [`UdpSession::new_conn`] put session and tasks together, as Go's `newUDPSession` does; the
//! listener — which shares one socket and one monitor task between its sessions, so that an
//! accepted session has no read loop of its own — follows in 05.7.
//!
//! Layout, following DECISIONS D02, which is Go's layout with Rust names:
//!
//! - [`SessionState`] is everything Go guards with `s.mu`: the KCP state machine, the FEC
//!   decoder, the stream reassembly buffer and the `ackNoDelay`/`writeDelay` flags. Nothing in
//!   it does I/O, crypto or `.await`, so it sits behind a `std::sync::Mutex`.
//! - The cipher and the packet-length checks are **outside** the lock, exactly as in Go: a
//!   packet that fails to decrypt never touches the session state.
//! - `chReadEvent`/`chWriteEvent`, Go's buffered notify channels of capacity 1, are
//!   [`tokio::sync::Notify`]; `notify_one` stores one permit, which is the same semantics
//!   (porting guide §6).
//! - `callbackForOOB`, Go's `atomic.Value`, is an `RwLock<Option<OobCallback>>`. The handler is
//!   only read for `0x00F3` packets, which are rare, and the `Arc` is cloned out before the
//!   callback runs so that a handler may re-register itself (Go's `atomic.Value` allows that
//!   too).
//!
//! Go holds `s.mu` across `notifyReadEvent`/`notifyWriteEvent`; here the two flags are computed
//! under the lock and the notifications are sent after it is released. That cannot lose a
//! wake-up: a waiter enables its `Notified` future *before* re-checking the state under the lock
//! (porting guide §6), and `notify_one` leaves a permit behind when nobody is waiting.
//!
//! [`UdpSession::read`] and [`UdpSession::write_buffers`] block exactly where Go's `Read` and
//! `WriteBuffers` block, and they reproduce Go's `RESET_TIMER` deadline handling: a wake-up from
//! the read or write event re-reads the deadline, which is how
//! [`set_read_deadline`](UdpSession::set_read_deadline) and friends (which notify the event)
//! change the timeout of a call that is already in flight.
#![forbid(unsafe_code)]

use std::future;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, Weak};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::addr;
use crate::bufpool::{self, BufferPool};
use crate::clock::{Clock, SystemClock};
use crate::crypt::{CRC_SIZE, CRYPT_HEADER_SIZE, MTU_LIMIT, NONCE_SIZE, PacketCrypt};
use crate::error_slot::ErrorSlot;
use crate::fec::{
    self, FEC_HEADER_SIZE_PLUS2, FecDecoder, FecEncoder, TYPE_DATA, TYPE_OOB, TYPE_PARITY,
};
use crate::io::UdpPacketConn;
use crate::kcp::{
    IKCP_FLUSH_FULL, IKCP_MTU_DEF, IKCP_OVERHEAD, IKCP_PACKET_FEC, IKCP_PACKET_REGULAR, Kcp,
    KcpLogType, LogOutput, Output,
};
use crate::packet_conn::{BATCH_SIZE, PacketConn, RecvBatch, invalid_operation};
use crate::snmp::DEFAULT_SNMP;
use crate::tx::{self, SendOutcome, SendRequest, TxConfig, TxHandle, TxPipeline, TxShared};

/// Size of the KCP `conv` field, which follows the FEC header of a data or OOB packet.
// Go: kcp-go/v5@v5.6.66 sess.go:convSize
pub const CONV_SIZE: usize = 4;

/// Shortest packet the session accepts after decryption.
///
/// Go writes `min(IKCP_OVERHEAD, fecHeaderSizePlus2+convSize)`, i.e. `min(24, 12)`: an OOB
/// packet may carry an empty payload, so the limit is the OOB framing, not a KCP segment.
// Go: kcp-go/v5@v5.6.66 sess.go:packetInput()
pub const MIN_PACKET_SIZE: usize = if (IKCP_OVERHEAD as usize) < FEC_HEADER_SIZE_PLUS2 + CONV_SIZE {
    IKCP_OVERHEAD as usize
} else {
    FEC_HEADER_SIZE_PLUS2 + CONV_SIZE
};

/// Offset of the 16-bit FEC type inside a decrypted packet.
///
/// Go: "16bit kcp cmd [81-84] and frg [0-255] will not overlap with FEC type 0x00f1 0x00f2", so
/// the same two bytes are a plain KCP `cmd`/`frg` pair or an FEC type.
// Go: kcp-go/v5@v5.6.66 sess.go:kcpInput() (`binary.LittleEndian.Uint16(data[4:])`)
const FEC_FLAG_OFFSET: usize = 4;

/// A handler for received out-of-band packets, invoked synchronously on the input path.
///
/// It must not block: Go documents that "the callback is responsible for ensuring non-blocking
/// behavior".
// Go: kcp-go/v5@v5.6.66 sess.go:OOBCallBackType
pub type OobCallback = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// Go's `errors.New("OOB requires FEC to be enabled")`.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetOOBHandler()
fn oob_requires_fec() -> io::Error {
    io::Error::other("OOB requires FEC to be enabled")
}

/// Go's `errors.New("OOB payload too large")`.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SendOOB()
fn oob_payload_too_large() -> io::Error {
    io::Error::other("OOB payload too large")
}

/// Go's `errTimeout`, the `net.Error` whose `Timeout()` and `Temporary()` are both true.
///
/// [`is_timeout`] is the `Timeout()` of callers; `Temporary()` has no Rust counterpart and no
/// caller in kcptun.
// Go: kcp-go/v5@v5.6.66 sess.go:timeoutError
pub fn timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "timeout")
}

/// Whether `err` is a deadline expiry, i.e. Go's `net.Error.Timeout()`.
pub fn is_timeout(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::TimedOut
}

/// Go's `io.ErrClosedPipe`, returned by every operation on a closed session.
// Go: go1.27.1 io/io.go:ErrClosedPipe
pub fn closed_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "io: read/write on closed pipe")
}

/// The listener an accepted session belongs to (Go's `UDPSession.l`).
///
/// Only [`close`](UdpSession::close) uses it, to take the session out of the listener's session
/// map; the listener itself arrives in 05.7. A session holds a [`Weak`] reference so that the
/// listener → session → listener cycle (which Go's GC copes with) cannot leak.
// Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).closeSession()
pub trait SessionOwner: Send + Sync + 'static {
    /// Removes the session for `remote`, returning whether one was there (Go's `ret`).
    fn close_session(&self, remote: SocketAddr) -> bool;
}

/// Why a session could not be created.
///
/// Go's `newUDPSession` cannot fail: a bad shard count silently disables FEC (Deviation V07) and
/// an MTU that does not fit the headers panics with `Overhead too large`.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The FEC codec could not be built for the configured shard counts (Deviation V07).
    #[error(transparent)]
    Fec(#[from] fec::Error),
    /// The crypto and FEC headers leave less than KCP's minimum MTU. Go panics here.
    // Go: kcp-go/v5@v5.6.66 sess.go:newUDPSession() (`panic("Overhead too large")`)
    #[error("Overhead too large")]
    OverheadTooLarge,
}

/// Go's dial functions return `(*UDPSession, error)` with a plain `error`, so the two ways of
/// failing to build a session (both unreachable through the dial, see [`SessionError`]) join the
/// socket errors of [`dial_with_options`](UdpSession::dial_with_options) in one `io::Error`,
/// keeping their message.
impl From<SessionError> for io::Error {
    fn from(err: SessionError) -> io::Error {
        io::Error::other(err)
    }
}

/// Everything a session needs to be built.
///
/// Go passes these to `newUDPSession(conv, dataShards, parityShards, l, conn, ownConn, remote,
/// block)`.
pub struct SessionConfig<C = SystemClock> {
    /// Conversation id, equal on both peers.
    pub conv: u32,
    /// FEC data shards per group; `0` (or negative) disables FEC.
    pub data_shards: isize,
    /// FEC parity shards per group; `0` (or negative) disables FEC.
    pub parity_shards: isize,
    /// The socket packets go out on (shared with the listener for accepted sessions).
    pub conn: Arc<dyn PacketConn>,
    /// Go's `ownConn`: true when the session created `conn` itself, so that
    /// [`close`](UdpSession::close) closes it.
    pub own_conn: bool,
    /// Go's `l`: the listener that accepted this session, or `None` for a dialled one.
    pub listener: Option<Weak<dyn SessionOwner>>,
    /// The peer.
    pub remote: SocketAddr,
    /// The packet cipher, or `None` for `-crypt null`.
    pub block: Option<PacketCrypt>,
    /// Where packet buffers come from and go back to.
    pub pool: Arc<BufferPool>,
    /// The millisecond clock; the same instance drives the KCP state machine and the FEC
    /// encoder's continuity check.
    pub clock: C,
    /// Go's `die`: closed when the session closes.
    pub die: CancellationToken,
}

/// The state Go guards with `UDPSession.mu`.
// Go: kcp-go/v5@v5.6.66 sess.go:UDPSession (the fields protected by `mu`)
pub struct SessionState<C = SystemClock> {
    /// The KCP ARQ state machine.
    pub(crate) kcp: Kcp<KcpOutput, C>,
    /// The FEC decoder, `None` until a FEC packet arrives on a session without FEC.
    pub(crate) fec_decoder: Option<FecDecoder>,
    /// Go's `recvbuf`: "kcp receiving is based on packets, recvbuf turns packets into stream".
    /// Holds the last message [`read`](UdpSession::read) could not hand over in one piece.
    pub(crate) recvbuf: Vec<u8>,
    /// Go's `bufptr`, as an index: `recvbuf[bufptr..]` is what is left of that message.
    pub(crate) bufptr: usize,
    /// Go's `ackNoDelay`: acknowledge every incoming packet immediately (testing).
    pub(crate) ack_no_delay: bool,
    /// Go's `writeDelay`: leave the flush after a `Write` to the update task (bulk transfer).
    pub(crate) write_delay: bool,
}

impl<C: Clock> SessionState<C> {
    /// Go's `len(s.bufptr)`: bytes of the last message still waiting for a reader.
    ///
    /// `bufptr <= recvbuf.len()` holds everywhere (the partial-read branch is the only place
    /// that sets it, right after resizing `recvbuf`), so the saturation never triggers.
    fn bufptr_len(&self) -> usize {
        debug_assert!(self.bufptr <= self.recvbuf.len());
        self.recvbuf.len().saturating_sub(self.bufptr)
    }
}

/// The KCP output callback: copies the segment into a pooled buffer, leaving room for the
/// crypto and FEC headers, and hands it to the tx task without ever blocking.
///
/// It runs **under** the session mutex, so it must not do anything but that (D04).
// Go: kcp-go/v5@v5.6.66 sess.go:newUDPSession() (the `NewKCP` output closure)
pub struct KcpOutput {
    tx: TxHandle,
    header_size: usize,
}

impl Output for KcpOutput {
    fn output(&mut self, buf: &[u8]) {
        // A basic check for the minimum packet size.
        if buf.len() < IKCP_OVERHEAD as usize {
            return;
        }
        let size = self.header_size + buf.len();
        if size > MTU_LIMIT {
            // Go slices a 1500-byte pool buffer here and would panic. Unreachable: `set_mtu`
            // subtracts `header_size` (and the AEAD overhead) from the KCP MTU.
            debug_assert!(
                size <= MTU_LIMIT,
                "KCP segment {size} exceeds the MTU limit"
            );
            return;
        }
        let mut packet = self.tx.pool().get(size);
        packet.as_mut_slice()[self.header_size..].copy_from_slice(buf);
        // Full channel: the packet is dropped and its buffer recycled by `Drop`; KCP
        // retransmits it. `flush` stops before that happens (Deviation V18, see `capacity`
        // below). See Deviation V05 in `crate::tx` for Go's extra `die` race.
        let _ = self.tx.send(SendRequest::data(packet));
    }

    /// **Deviation V18:** the free slots of the tx channel, so that `Kcp::flush` stops emitting
    /// before a burst larger than the channel starts being dropped (`crate::tx` module docs).
    fn capacity(&self) -> usize {
        self.tx.capacity()
    }
}

/// A KCP session over a packet connection.
///
/// Held in an `Arc`: the tx task, the read loop and the update task all share it.
// Go: kcp-go/v5@v5.6.66 sess.go:UDPSession
pub struct UdpSession<C = SystemClock> {
    /// Go's `mu` and everything it guards.
    state: Mutex<SessionState<C>>,
    /// Go's `block`: the packet cipher, read without the lock on the input path.
    block: Option<PacketCrypt>,
    /// Go's `headerSize`: crypto header plus, when FEC is on, `fecHeaderSizePlus2`.
    header_size: usize,
    /// Go's `fecEncoder != nil`. The encoder itself lives in the tx task.
    fec_enabled: bool,
    /// Go's `kcp.conv`, copied out so that `get_conv` needs no lock (nor does Go's).
    conv: u32,
    /// Go's `conn`: the socket, shared with the listener for an accepted session.
    conn: Arc<dyn PacketConn>,
    /// Go's `ownConn`.
    own_conn: bool,
    /// Go's `l`, the listener that accepted this session.
    listener: Option<Weak<dyn SessionOwner>>,
    /// Go's `remote`.
    remote: SocketAddr,
    /// Go's `chReadEvent`.
    read_notify: Notify,
    /// Go's `chWriteEvent`.
    write_notify: Notify,
    /// Go's `rd`: the read deadline, `None` for Go's zero `time.Time`.
    rd: Mutex<Option<Instant>>,
    /// Go's `wd`: the write deadline.
    wd: Mutex<Option<Instant>>,
    /// Go's `die`, closed by [`close`](UdpSession::close).
    die: CancellationToken,
    /// Go's `dieOnce`: only the first `Close` does the work, the rest get `io.ErrClosedPipe`.
    die_once: AtomicBool,
    /// Go's `socketReadError` + `chSocketReadError`, filled by the read loop (05.6) or the
    /// listener's monitor (05.7). The write half lives in [`TxShared`].
    read_error: ErrorSlot,
    /// Go's `callbackForOOB`.
    oob_handler: RwLock<Option<OobCallback>>,
    /// Go's `chPostProcessing`, the producer end.
    tx: TxHandle,
}

impl<C: Clock + Clone> UdpSession<C> {
    /// Builds a session and the tx task that drains its packet channel; the caller spawns
    /// [`TxPipeline::run`].
    ///
    /// Go additionally starts the post-processing goroutine (the caller spawns
    /// [`TxPipeline::run`]), the client read loop (05.6) and the per-session updater (the
    /// caller spawns [`UdpSession::updater`]`.run()`; without it nothing retransmits).
    // Go: kcp-go/v5@v5.6.66 sess.go:newUDPSession()
    pub fn new(
        config: SessionConfig<C>,
    ) -> Result<(Arc<UdpSession<C>>, TxPipeline<C>), SessionError> {
        // Additional header size introduced by encryption.
        let mut header_size = match config.block.as_ref() {
            None => 0,
            Some(PacketCrypt::Aead(aead)) => aead.nonce_size(),
            Some(PacketCrypt::Block(_)) => CRYPT_HEADER_SIZE,
        };

        // FEC codec initialization.
        let fec_decoder = FecDecoder::new(config.data_shards, config.parity_shards);
        let fec_encoder = FecEncoder::new(config.data_shards, config.parity_shards, header_size)?;

        // Additional header size introduced by FEC.
        let fec_enabled = fec_encoder.is_some();
        if fec_enabled {
            header_size += FEC_HEADER_SIZE_PLUS2;
        }

        let (tx, pipeline) = tx::channel(TxConfig {
            conn: Arc::clone(&config.conn),
            remote: config.remote,
            block: config.block.clone(),
            fec_encoder,
            pool: config.pool,
            clock: config.clock.clone(),
            die: config.die.clone(),
        });

        let mut kcp = Kcp::with_clock(
            config.conv,
            KcpOutput {
                tx: tx.clone(),
                header_size,
            },
            config.clock,
        );

        // Set Default MTU. Go panics with "Overhead too large" when it does not fit.
        if !set_kcp_mtu(
            &mut kcp,
            IKCP_MTU_DEF as isize,
            header_size,
            config.block.as_ref(),
        ) {
            return Err(SessionError::OverheadTooLarge);
        }

        let session = Arc::new(UdpSession {
            state: Mutex::new(SessionState {
                kcp,
                fec_decoder,
                // Go: `sess.recvbuf = make([]byte, mtuLimit)` with a nil `bufptr`; the index
                // form of an empty `bufptr` is "past the end of recvbuf".
                recvbuf: vec![0u8; MTU_LIMIT],
                bufptr: MTU_LIMIT,
                ack_no_delay: false,
                write_delay: false,
            }),
            block: config.block,
            header_size,
            fec_enabled,
            conv: config.conv,
            conn: config.conn,
            own_conn: config.own_conn,
            listener: config.listener,
            remote: config.remote,
            read_notify: Notify::new(),
            write_notify: Notify::new(),
            rd: Mutex::new(None),
            wd: Mutex::new(None),
            die: config.die,
            die_once: AtomicBool::new(false),
            read_error: ErrorSlot::new(),
            oob_handler: RwLock::new(None),
            tx,
        });

        // Go counts the open here, before the read loop and the updater start. The dial
        // (05.6) and the listener (05.7) only decide which of the two "opens" counters moves,
        // which `s.l` already says.
        if session.listener.is_none() {
            DEFAULT_SNMP.active_opens.fetch_add(1, Ordering::Relaxed);
        } else {
            DEFAULT_SNMP.passive_opens.fetch_add(1, Ordering::Relaxed);
        }
        let currestab = DEFAULT_SNMP.curr_estab.fetch_add(1, Ordering::Relaxed) + 1;
        let maxconn = DEFAULT_SNMP.max_conn.load(Ordering::Relaxed);
        if currestab > maxconn {
            let _ = DEFAULT_SNMP.max_conn.compare_exchange(
                maxconn,
                currestab,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }

        Ok((session, pipeline))
    }

    /// Builds a session and starts every task it needs: the tx pipeline (Go's `postProcess`
    /// goroutine), the per-session updater, and — for a dialled session, i.e. one without a
    /// listener — the read loop.
    ///
    /// This is the rest of Go's `newUDPSession`, and thus what
    /// [`dial_with_options`](UdpSession::dial_with_options), [`new_conn`](UdpSession::new_conn)
    /// and (in 05.7) the listener build their sessions with. The SNMP accounting
    /// (`ActiveOpens`/`PassiveOpens`, `CurrEstab`, `MaxConn`) happens in [`new`](Self::new).
    ///
    /// Must be called from within a tokio runtime. The tasks it spawns all end when the session's
    /// `die` token is cancelled, and none of them keeps the session alive; without a
    /// [`close`](Self::close) the updater (it has a timer) and the tx pipeline (its channel
    /// closes) still retire on their own once the last session handle is gone, but the read loop
    /// only leaves its pending receive on `die` or when a datagram arrives — so a dialled session
    /// must be closed to retire it. Note also that the socket fd is released when the last handle
    /// to the session (and thus to its [`PacketConn`]) drops, not inside `close`, which only marks
    /// an owned connection closed (05.1); Go's `Close` frees the port at once.
    // Go: kcp-go/v5@v5.6.66 sess.go:newUDPSession()
    pub fn start(config: SessionConfig<C>) -> Result<Arc<UdpSession<C>>, SessionError> {
        let (session, pipeline) = UdpSession::new(config)?;

        // Create post-processing goroutine.
        tokio::spawn(pipeline.run());

        if session.listener.is_none() {
            // It's a client connection: a listener's sessions share its socket and its monitor
            // task, and must not read from it themselves.
            tokio::spawn(session.read_loop().run());
        }

        // Start per-session updater.
        tokio::spawn(session.updater().run());

        Ok(session)
    }
}

impl UdpSession<SystemClock> {
    /// Connects to the remote address `raddr` on the network "udp", with packet encryption and
    /// FEC.
    ///
    /// `block` is the block encryption algorithm to encrypt packets, `None` for `-crypt null`.
    /// `data_shards`/`parity_shards` specify how many parity packets will be generated following
    /// the data packets; `0` disables FEC.
    ///
    /// The socket is a **wildcard, unconnected** one of the remote's family (`udp4` for an IPv4
    /// remote, else a dual-stack socket), exactly as in Go, and the session owns it: closing the
    /// session closes the socket.
    ///
    /// Name resolution blocks (Go's does too) and follows Go's `ResolveUDPAddr`, which prefers
    /// the first IPv4 answer; call it before entering the hot path.
    ///
    /// Must be called from within a tokio runtime (see [`start`](Self::start)).
    // Go: kcp-go/v5@v5.6.66 sess.go:DialWithOptions()
    pub fn dial_with_options(
        raddr: &str,
        block: Option<PacketCrypt>,
        data_shards: isize,
        parity_shards: isize,
    ) -> io::Result<Arc<UdpSession>> {
        // Network type detection, and `net.ListenUDP(network, nil)` on the family it picks.
        let udpaddr = addr::resolve_udp_addr("udp", raddr)?;
        let conn = UdpPacketConn::dial_socket(&udpaddr)?;

        // Go keeps the resolved `*net.UDPAddr` as the remote and lets the socket layer encode it
        // for its family on every send (`ipToSockaddr`), which `UdpPacketConn` does too; so the
        // session stores the address in its own family, the form `RemoteAddr` prints.
        let remote = udpaddr.to_socket_addr(!udpaddr.is_ipv4())?;

        let convid = random_conv();
        UdpSession::new_conn(
            convid,
            remote,
            block,
            data_shards,
            parity_shards,
            true,
            Arc::new(conn),
        )
    }

    /// Establishes a session and talks the KCP protocol over an existing packet connection
    /// (`tcpraw`'s, in Step 10).
    ///
    /// `own_conn` says whether the session closes `conn` when it closes. Both peers must use the
    /// same `convid`; [`dial_with_options`](Self::dial_with_options) draws a random one.
    ///
    /// Must be called from within a tokio runtime (see [`start`](Self::start)).
    // Go: kcp-go/v5@v5.6.66 sess.go:NewConn4()
    pub fn new_conn(
        convid: u32,
        raddr: SocketAddr,
        block: Option<PacketCrypt>,
        data_shards: isize,
        parity_shards: isize,
        own_conn: bool,
        conn: Arc<dyn PacketConn>,
    ) -> io::Result<Arc<UdpSession>> {
        Ok(UdpSession::start(SessionConfig {
            conv: convid,
            data_shards,
            parity_shards,
            conn,
            own_conn,
            listener: None,
            remote: raddr,
            block,
            // Go's single `defaultBufferPool`, shared by every session in the process.
            pool: Arc::clone(bufpool::default_pool()),
            clock: SystemClock,
            die: CancellationToken::new(),
        })?)
    }
}

/// A conversation id for a new session: four random bytes.
///
/// Go reads them from `crypto/rand` (`binary.Read(rand.Reader, binary.LittleEndian, &convid)`),
/// and so do we: conv ids come from the OS RNG, exactly as DECISIONS D14 prescribes (only packet
/// nonces take the per-thread CSPRNG of [`crate::entropy::fill_nonce`]). This runs once per
/// session, so the syscall is irrelevant. The byte order Go names does not matter for four
/// uniformly random bytes.
///
/// Go ignores the `binary.Read` error and dials with whatever `convid` holds, so a failure of the
/// OS RNG must not fail the dial either: it falls back to the per-thread CSPRNG, which is seeded
/// from the OS and still unpredictable.
// Go: kcp-go/v5@v5.6.66 sess.go:DialWithOptions(), NewConn2()
fn random_conv() -> u32 {
    let mut convid = [0u8; 4];
    if getrandom::fill(&mut convid).is_err() {
        use rand::Rng as _;
        rand::rng().fill_bytes(&mut convid);
    }
    u32::from_le_bytes(convid)
}

impl<C: Clock> UdpSession<C> {
    /// The state Go guards with `s.mu`.
    ///
    /// A poisoned mutex is recovered rather than propagated: the session state is plain data and
    /// nothing in this crate can leave it half-updated (no `.await`, no allocation loop and no
    /// panic on network input inside the critical section).
    pub(crate) fn lock(&self) -> MutexGuard<'_, SessionState<C>> {
        self.state.lock().unwrap_or_else(|err| err.into_inner())
    }

    /// Go's `headerSize`: bytes reserved in front of every packet for the crypto and FEC
    /// headers.
    pub fn header_size(&self) -> usize {
        self.header_size
    }

    /// Whether FEC is enabled (Go's `fecEncoder != nil`), which is also what OOB requires.
    pub fn fec_enabled(&self) -> bool {
        self.fec_enabled
    }

    /// The producer end of the packet channel (Go's `chPostProcessing`).
    pub fn tx(&self) -> &TxHandle {
        &self.tx
    }

    /// Resolves when there may be data to read (Go's `chReadEvent`).
    pub fn read_notify(&self) -> &Notify {
        &self.read_notify
    }

    /// Resolves when the send window may have room (Go's `chWriteEvent`).
    pub fn write_notify(&self) -> &Notify {
        &self.write_notify
    }

    /// The state shared with the tx task: `dup`, the rate limiter and the socket write error.
    pub fn tx_shared(&self) -> &Arc<TxShared> {
        self.tx.shared()
    }

    /// Go's `socketReadError` + `chSocketReadError`: the first error the socket reported while
    /// reading. The read loop (05.6) and the listener (05.7) fill it, which unblocks
    /// [`read`](Self::read).
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).notifyReadError()
    pub fn read_error(&self) -> &ErrorSlot {
        &self.read_error
    }

    /// Records a socket read error and wakes everybody blocked in [`read`](Self::read).
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).notifyReadError()
    pub fn notify_read_error(&self, err: io::Error) {
        self.read_error.set(err);
    }

    /// Go's `die`: cancelled by [`close`](Self::close).
    pub fn die(&self) -> &CancellationToken {
        &self.die
    }

    /// Whether the session has been closed.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).isClosed()
    pub fn is_closed(&self) -> bool {
        self.die.is_cancelled()
    }

    // ---------------------------------------------------------------------------------------
    // Read
    // ---------------------------------------------------------------------------------------

    /// Reads one chunk of the stream into `b`, blocking until there is something to return.
    ///
    /// Returns as soon as *any* bytes are available, like Go's `Read` (and `io.Reader`): a
    /// message longer than `b` is served over several calls, the remainder waiting in
    /// `recvbuf`/`bufptr`.
    ///
    /// Errors: [`timeout`] once the read deadline passes, the socket read error if one was
    /// recorded, and [`closed_pipe`] after [`close`](Self::close). Data already queued is
    /// returned even after the session is closed, which is what Go's `TestClose` drains.
    ///
    /// Go's quirk, reproduced: `RESET_TIMER` re-reads the deadline only when the call *started*
    /// with one (`if timeout != nil`), so a [`set_read_deadline`](Self::set_read_deadline) on a
    /// `Read` that began without a deadline has no effect until that call returns.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).Read()
    pub async fn read(&self, b: &mut [u8]) -> io::Result<usize> {
        // Go's `RESET_TIMER` label: every wake-up from the read event re-reads the deadline,
        // so `SetReadDeadline` (which notifies that event) retimes a call already in flight.
        loop {
            let deadline = self.read_deadline();

            loop {
                // Register before looking at the state, so a packet arriving in between still
                // wakes this call (porting guide §6). Go's cap-1 channel holds the same one
                // token; consuming it here rather than in the `select` only means one fewer
                // spurious wake-up.
                let notified = self.read_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();

                if let Some(n) = self.try_read(b) {
                    return Ok(n);
                }

                // If it runs here, that means we have to block the call, and wait until the
                // next data packet arrives.
                tokio::select! {
                    () = notified => {
                        if deadline.is_some() {
                            break; // Go: `goto RESET_TIMER`
                        }
                    }
                    () = sleep_until(deadline) => return Err(timeout()),
                    () = self.read_error.wait() => return Err(self.read_error_or_closed()),
                    () = self.die.cancelled() => return Err(closed_pipe()),
                }
            }
        }
    }

    /// One non-blocking pass of [`read`](Self::read): `Some(n)` when it could serve the call.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).Read() (the body of the `for` loop)
    fn try_read(&self, b: &mut [u8]) -> Option<usize> {
        let mut guard = self.lock();
        let state = &mut *guard;

        // bufptr points to the current position of recvbuf, if previous 'b' is insufficient to
        // accommodate the data, the remaining data will be stored in bufptr for next read.
        if state.bufptr_len() > 0 {
            let n = copy(b, &state.recvbuf[state.bufptr..]);
            state.bufptr += n;
            drop(guard);
            DEFAULT_SNMP
                .bytes_received
                .fetch_add(n as u64, Ordering::Relaxed);
            return Some(n);
        }

        // Peek data size from kcp.
        let size = state.kcp.peek_size();
        if size > 0 {
            let size = size as usize;

            // If 'b' is large enough to accommodate the data, read directly from kcp.recv() to
            // 'b', like 'DMA'.
            if b.len() >= size {
                state.kcp.recv(b);
                drop(guard);
                DEFAULT_SNMP
                    .bytes_received
                    .fetch_add(size as u64, Ordering::Relaxed);
                return Some(size);
            }

            // Otherwise, read to recvbuf first, then copy to 'b'. Dynamically adjust the buffer
            // size to the maximum of 'packet size' when necessary.
            if state.recvbuf.capacity() < size {
                // Usually recvbuf has a size of maximum packet size.
                state.recvbuf = vec![0u8; size];
            }

            // Resize the length of recvbuf to match the data size (Go re-slices; `kcp.recv`
            // overwrites all `size` bytes either way).
            state.recvbuf.resize(size, 0);
            state.kcp.recv(&mut state.recvbuf); // read data to recvbuf first
            let n = copy(b, &state.recvbuf); // then copy bytes to 'b' as many as possible
            state.bufptr = n; // pointer update

            drop(guard);
            DEFAULT_SNMP
                .bytes_received
                .fetch_add(n as u64, Ordering::Relaxed);
            return Some(n);
        }

        None
    }

    // ---------------------------------------------------------------------------------------
    // Write
    // ---------------------------------------------------------------------------------------

    /// Writes `b` to the peer, blocking while the send window is full.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).Write()
    pub async fn write(&self, b: &[u8]) -> io::Result<usize> {
        self.write_buffers(&[b]).await
    }

    /// Writes a vector of byte slices to the underlying connection.
    ///
    /// Either every slice is queued (and the total length returned) or none is: KCP splits them
    /// into `mss`-sized segments itself, and the send window is only checked once, before the
    /// whole vector, exactly as Go does.
    ///
    /// The deadline behaves as in [`read`](Self::read), `RESET_TIMER` quirk included.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).WriteBuffers()
    pub async fn write_buffers(&self, v: &[&[u8]]) -> io::Result<usize> {
        // Go's `RESET_TIMER` label; see `read`.
        loop {
            let deadline = self.write_deadline();

            loop {
                let notified = self.write_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();

                // Check for connection close and socket error.
                if self.tx.shared().write_error().is_set() {
                    return Err(self.write_error_or_closed());
                }
                if self.die.is_cancelled() {
                    return Err(closed_pipe());
                }

                if let Some(n) = self.try_write(v) {
                    return Ok(n);
                }

                // If it runs here, that means we have to block the call, and wait until the
                // transmit buffer becomes available again.
                tokio::select! {
                    () = notified => {
                        if deadline.is_some() {
                            break; // Go: `goto RESET_TIMER`
                        }
                    }
                    () = sleep_until(deadline) => return Err(timeout()),
                    () = self.tx.shared().write_error().wait() => {
                        return Err(self.write_error_or_closed());
                    }
                    () = self.die.cancelled() => return Err(closed_pipe()),
                }
            }
        }
    }

    /// One non-blocking pass of [`write_buffers`](Self::write_buffers).
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).WriteBuffers() (the body of the `for` loop)
    fn try_write(&self, v: &[&[u8]]) -> Option<usize> {
        let mut guard = self.lock();
        let state = &mut *guard;

        // Make sure write does not overflow the max sliding window on both sides.
        let waitsnd = state.kcp.wait_snd();
        if waitsnd >= state.kcp.snd_wnd as usize {
            return None;
        }

        // Transmit all data sequentially, make sure every packet size is within 'mss'.
        let mut n = 0usize;
        for b in v {
            n += b.len();
            let mut b = *b;
            // Handle each slice for packet splitting.
            loop {
                let mss = state.kcp.mss as usize;
                if b.len() <= mss {
                    state.kcp.send(b);
                    break;
                }
                state.kcp.send(&b[..mss]);
                b = &b[mss..];
            }
        }

        let waitsnd = state.kcp.wait_snd();
        if waitsnd >= state.kcp.snd_wnd as usize || !state.write_delay {
            // Put the packets on the wire immediately if the inflight window is full or if
            // we've specified write no delay (no merging of outgoing bytes): we don't have to
            // wait until the periodical update() procedure uncorks.
            state.kcp.flush(IKCP_FLUSH_FULL);
        }

        drop(guard);
        DEFAULT_SNMP
            .bytes_sent
            .fetch_add(n as u64, Ordering::Relaxed);
        Some(n)
    }

    // ---------------------------------------------------------------------------------------
    // Close
    // ---------------------------------------------------------------------------------------

    /// Closes the connection. The second and later calls return [`closed_pipe`], as Go's
    /// `dieOnce` makes them.
    ///
    /// **Deviation V05.** Go closes `die` first and flushes afterwards, and its output callback
    /// races `die` against the packet channel, so the final flush reaches the wire only about
    /// half the time. Here the flush is queued *before* `die` is cancelled, and the tx task
    /// drains what is queued before it exits (`TxPipeline::run`), so the last packets are
    /// always sent. The only visible consequence of the reordering is that a concurrent
    /// [`write`](Self::write) can still be accepted during that final flush (Go's `die` is
    /// already closed by then); its data is flushed with the rest rather than lost.
    ///
    /// Go's `dieOnce` is a `sync.Once`, so a concurrent second `Close` only returns once `die`
    /// is closed; here it returns as soon as the flag is taken, which can be before
    /// `die.cancel()`, before the final flush and before the socket is closed.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).Close()
    pub fn close(&self) -> io::Result<()> {
        if self.die_once.swap(true, Ordering::AcqRel) {
            return Err(closed_pipe());
        }

        DEFAULT_SNMP.curr_estab.fetch_sub(1, Ordering::Relaxed);

        // Try best to send all queued messages, especially the data in txqueue.
        self.lock().kcp.flush(IKCP_FLUSH_FULL);

        // Deviation V05: after the flush, never before it.
        self.die.cancel();

        if let Some(listener) = self.listener.as_ref() {
            // Belongs to a listener.
            if let Some(listener) = listener.upgrade() {
                listener.close_session(self.remote);
            }
            return Ok(());
        }

        if self.own_conn {
            // Client socket close.
            return self.conn.close();
        }

        Ok(())
    }

    // ---------------------------------------------------------------------------------------
    // Addresses and deadlines
    // ---------------------------------------------------------------------------------------

    /// The local network address of the socket.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).LocalAddr()
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.conn.local_addr()
    }

    /// The remote network address.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).RemoteAddr()
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote
    }

    /// Sets both deadlines. `None` is Go's zero `time.Time`: no deadline.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetDeadline()
    pub fn set_deadline(&self, t: Option<Instant>) -> io::Result<()> {
        *self.rd.lock().unwrap_or_else(|err| err.into_inner()) = t;
        *self.wd.lock().unwrap_or_else(|err| err.into_inner()) = t;
        // Wake the blocked callers so that they re-read the deadline (Go's RESET_TIMER).
        self.read_notify.notify_one();
        self.write_notify.notify_one();
        Ok(())
    }

    /// Sets the deadline of [`read`](Self::read).
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetReadDeadline()
    pub fn set_read_deadline(&self, t: Option<Instant>) -> io::Result<()> {
        *self.rd.lock().unwrap_or_else(|err| err.into_inner()) = t;
        self.read_notify.notify_one();
        Ok(())
    }

    /// Sets the deadline of [`write`](Self::write)/[`write_buffers`](Self::write_buffers).
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetWriteDeadline()
    pub fn set_write_deadline(&self, t: Option<Instant>) -> io::Result<()> {
        *self.wd.lock().unwrap_or_else(|err| err.into_inner()) = t;
        self.write_notify.notify_one();
        Ok(())
    }

    fn read_deadline(&self) -> Option<Instant> {
        *self.rd.lock().unwrap_or_else(|err| err.into_inner())
    }

    fn write_deadline(&self) -> Option<Instant> {
        *self.wd.lock().unwrap_or_else(|err| err.into_inner())
    }

    /// The recorded socket read error; [`closed_pipe`] if the slot was emptied under us, which
    /// cannot happen ([`ErrorSlot`] is write-once).
    fn read_error_or_closed(&self) -> io::Error {
        self.read_error.io_error().unwrap_or_else(closed_pipe)
    }

    /// The recorded socket write error, see [`read_error_or_closed`](Self::read_error_or_closed).
    fn write_error_or_closed(&self) -> io::Error {
        self.tx
            .shared()
            .write_error()
            .io_error()
            .unwrap_or_else(closed_pipe)
    }

    // ---------------------------------------------------------------------------------------
    // Setters and getters
    // ---------------------------------------------------------------------------------------

    /// Delays the `flush()` of a write until the next update interval (bulk transfer).
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetWriteDelay()
    pub fn set_write_delay(&self, delay: bool) {
        self.lock().write_delay = delay;
    }

    /// Sets the maximum window sizes, in segments.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetWindowSize()
    pub fn set_window_size(&self, sndwnd: isize, rcvwnd: isize) {
        self.lock().kcp.wnd_size(sndwnd, rcvwnd);
    }

    /// Sets the maximum transmission unit (not including the UDP header), returning whether KCP
    /// accepted it. The crypto and FEC headers (and the AEAD tag) come off the value first, so
    /// that a full packet still fits `mtu` bytes on the wire.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetMtu()
    pub fn set_mtu(&self, mtu: isize) -> bool {
        let mut guard = self.lock();
        set_kcp_mtu(&mut guard.kcp, mtu, self.header_size, self.block.as_ref())
    }

    /// Toggles stream mode (deprecated in Go, but what kcptun runs with).
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetStreamMode()
    pub fn set_stream_mode(&self, enable: bool) {
        self.lock().kcp.stream = i32::from(enable);
    }

    /// Flushes an ack for every incoming packet instead of waiting for the next interval.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetACKNoDelay()
    pub fn set_ack_no_delay(&self, nodelay: bool) {
        self.lock().ack_no_delay = nodelay;
    }

    /// Duplicates every outgoing packet `dup` extra times (deprecated; testing only).
    ///
    /// Go takes an `int` and loops `for i := 0; i < s.dup; i++`, so a negative value behaves
    /// like `0`; `usize` says the same thing.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetDUP()
    pub fn set_dup(&self, dup: usize) {
        self.tx.shared().set_dup(dup);
    }

    /// Calls `nodelay()` of KCP.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetNoDelay()
    pub fn set_no_delay(&self, nodelay: isize, interval: isize, resend: isize, nc: isize) {
        self.lock().kcp.nodelay(nodelay, interval, resend, nc);
    }

    /// Sets the 6-bit DSCP field of the IPv4 header, or the 8-bit traffic class of the IPv6 one.
    ///
    /// It has no effect if the session was accepted from a listener, whose socket is shared.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetDSCP()
    pub fn set_dscp(&self, dscp: i32) -> io::Result<()> {
        // Go holds `s.mu` across the setsockopt, so that it cannot race `Control`.
        let _guard = self.lock();
        if self.listener.is_some() {
            return Err(invalid_operation());
        }
        self.conn.set_dscp(dscp)
    }

    /// Sets the socket read buffer; no effect if the session was accepted from a listener.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetReadBuffer()
    pub fn set_read_buffer(&self, bytes: usize) -> io::Result<()> {
        let _guard = self.lock();
        if self.listener.is_some() {
            return Err(invalid_operation());
        }
        self.conn.set_read_buffer(bytes)
    }

    /// Sets the socket write buffer; no effect if the session was accepted from a listener.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetWriteBuffer()
    pub fn set_write_buffer(&self, bytes: usize) -> io::Result<()> {
        let _guard = self.lock();
        if self.listener.is_some() {
            return Err(invalid_operation());
        }
        self.conn.set_write_buffer(bytes)
    }

    /// Sets the rate limit of this session in bytes per second; `0` disables rate limiting.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetRateLimit()
    pub fn set_rate_limit(&self, bytes_per_second: u32) {
        self.tx.shared().set_rate_limit(bytes_per_second);
    }

    /// Configures the KCP trace logger (events only with the `trace` feature).
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetLogger()
    pub fn set_logger(&self, mask: KcpLogType, logger: Option<LogOutput>) {
        self.lock().kcp.set_logger(mask, logger);
    }

    /// The conversation id of this session.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).GetConv()
    pub fn get_conv(&self) -> u32 {
        self.conv
    }

    /// The current retransmission timeout, in milliseconds.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).GetRTO()
    pub fn get_rto(&self) -> u32 {
        self.lock().kcp.rx_rto
    }

    /// The current smoothed RTT, in milliseconds.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).GetSRTT()
    pub fn get_srtt(&self) -> i32 {
        self.lock().kcp.rx_srtt
    }

    /// The current RTT variance, in milliseconds.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).GetSRTTVar()
    pub fn get_srttvar(&self) -> i32 {
        self.lock().kcp.rx_rttvar
    }

    /// The largest payload [`send_oob`](Self::send_oob) accepts, or `0` without FEC.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).GetOOBMaxSize()
    pub fn get_oob_max_size(&self) -> usize {
        if !self.fec_enabled {
            return 0;
        }
        // Packet layout: | conv (4B) | OOB payload |
        self.lock().kcp.mtu as usize - CONV_SIZE
    }

    /// Sends an out-of-band packet: unreliable, unordered, unacknowledged, and outside both FEC
    /// and the KCP data path.
    ///
    /// The payload must fit one packet ([`get_oob_max_size`](Self::get_oob_max_size)). A full
    /// send queue drops the packet silently, OOB delivery being best-effort by design.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SendOOB()
    pub fn send_oob(&self, data: &[u8]) -> io::Result<()> {
        if !self.fec_enabled {
            return Err(oob_requires_fec());
        }

        // Lock the session during OOB packet construction.
        let guard = self.lock();

        // Packet layout: | conv (4B) | OOB payload |
        let size = CONV_SIZE + data.len();
        if size > guard.kcp.mtu as usize {
            return Err(oob_payload_too_large());
        }
        if size + self.header_size > MTU_LIMIT {
            // As in `KcpOutput::output`: the pool clamps to `MTU_LIMIT` and the copy below
            // would panic. Unreachable: `set_mtu` subtracts `header_size` (and the AEAD
            // overhead) from the KCP MTU, so `mtu + header_size <= MTU_LIMIT`.
            debug_assert!(
                size + self.header_size <= MTU_LIMIT,
                "OOB packet {} exceeds the MTU limit",
                size + self.header_size
            );
            return Err(oob_payload_too_large());
        }

        // Allocate a buffer with reserved header space; `header_size` includes the space the
        // FEC encoder needs for the OOB header it writes in the tx task.
        let mut buf = self.tx.pool().get(size + self.header_size);
        let body = &mut buf.as_mut_slice()[self.header_size..];
        // Encode the conversation ID, then the payload right after it.
        body[..CONV_SIZE].copy_from_slice(&guard.kcp.conv.to_le_bytes());
        body[CONV_SIZE..].copy_from_slice(data);

        // Enqueue the packet for post-processing: OOB framing, encryption and transmission,
        // bypassing FEC and KCP. Deviation V05 again — Go races the queueing against `die`.
        match self.tx.send(SendRequest::oob(buf)) {
            SendOutcome::Queued | SendOutcome::Dropped => Ok(()),
            SendOutcome::Closed => Err(closed_pipe()),
        }
    }

    /// Registers the out-of-band handler, or clears it with `None`.
    ///
    /// Go stores a no-op function for a `nil` callback so that the `atomic.Value` stays
    /// non-nil; storing `None` here has the same observable effect (the payload is dropped).
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetOOBHandler()
    pub fn set_oob_handler(&self, callback: Option<OobCallback>) -> io::Result<()> {
        if !self.fec_enabled {
            return Err(oob_requires_fec());
        }
        let mut slot = self
            .oob_handler
            .write()
            .unwrap_or_else(|err| err.into_inner());
        *slot = callback;
        Ok(())
    }

    /// The registered out-of-band handler.
    ///
    /// The `Arc` is cloned out so the lock is released before the callback runs: a handler may
    /// then call [`set_oob_handler`](Self::set_oob_handler), as it may with Go's `atomic.Value`.
    fn oob_handler(&self) -> Option<OobCallback> {
        self.oob_handler
            .read()
            .unwrap_or_else(|err| err.into_inner())
            .clone()
    }

    /// The incoming packet pipeline: `network -> [decryption ->] [crc32 ->] [FEC ->] [KCP input
    /// ->] stream -> application`.
    ///
    /// `data` is one datagram, decrypted **in place** (Go decrypts into the same buffer and
    /// re-slices it). Anything that fails a check is dropped; the relevant SNMP counter is
    /// moved first.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).packetInput()
    pub fn packet_input(&self, data: &mut [u8]) {
        let Some(data) = decrypt(self.block.as_ref(), data) else {
            return;
        };

        // Basic check for minimum packet size.
        // NOTE: OOB allows sending small packets and even empty packets.
        if data.len() < MIN_PACKET_SIZE {
            DEFAULT_SNMP.kcp_in_errors.fetch_add(1, Ordering::Relaxed);
            return;
        }

        self.kcp_input(data);
    }

    /// Feeds a decrypted and crc32-checked packet into KCP, handling FEC and OOB.
    ///
    /// `data` must be at least [`MIN_PACKET_SIZE`] bytes, which both call sites guarantee
    /// ([`packet_input`](Self::packet_input) and, in 05.7, the listener's demux). Go indexes
    /// `data[4:]` and `data[12:]` unconditionally and would panic on a shorter packet; here the
    /// packet is dropped instead (porting guide §5).
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).kcpInput()
    pub fn kcp_input(&self, data: &[u8]) {
        DEFAULT_SNMP.in_pkts.fetch_add(1, Ordering::Relaxed);
        DEFAULT_SNMP
            .in_bytes
            .fetch_add(data.len() as u64, Ordering::Relaxed);

        // 16bit kcp cmd [81-84] and frg [0-255] will not overlap with FEC type 0x00f1 0x00f2.
        let Some(flag) = data.get(FEC_FLAG_OFFSET..FEC_FLAG_OFFSET + 2) else {
            return;
        };
        let fec_flag = u16::from_le_bytes([flag[0], flag[1]]);

        match fec_flag {
            // Packet with FEC.
            TYPE_DATA | TYPE_PARITY => {
                if data.len() < FEC_HEADER_SIZE_PLUS2 {
                    DEFAULT_SNMP.in_errs.fetch_add(1, Ordering::Relaxed);
                    return;
                }

                let mut kcp_in_errors = 0u64;
                let mut guard = self.lock();
                let state = &mut *guard;

                // If the FEC decoder is not initialized, create one with default parameters
                // (lazy initialization).
                if state.fec_decoder.is_none() {
                    state.fec_decoder = FecDecoder::new(1, 1);
                }

                // KCP input for data packets: only data packets are fed into kcp directly,
                // parity packets are only used for recovery.
                if fec_flag == TYPE_DATA
                    && state.kcp.input(
                        &data[FEC_HEADER_SIZE_PLUS2..],
                        IKCP_PACKET_REGULAR,
                        state.ack_no_delay,
                    ) != 0
                {
                    kcp_in_errors += 1;
                }

                // FEC decoding. Go dereferences `s.fecDecoder` unconditionally, which `(1, 1)`
                // always makes non-nil; the `None` arm here is unreachable.
                let recovers = state
                    .fec_decoder
                    .as_mut()
                    .map_or_else(Vec::new, |decoder| decoder.decode(data));

                // If there are some packets recovered from FEC, feed them into kcp.
                for r in &recovers {
                    if r.len() >= 2 {
                        // Must be larger than 2 bytes.
                        let sz = usize::from(u16::from_le_bytes([r[0], r[1]]));
                        if sz <= r.len()
                            && sz >= 2
                            && state
                                .kcp
                                .input(&r[2..sz], IKCP_PACKET_FEC, state.ack_no_delay)
                                != 0
                        {
                            kcp_in_errors += 1;
                        }
                    }
                    // Go recycles the buffer here; `recovers` owns them and drops them below.
                }

                let wake = Wakeups::of(state);
                drop(guard);
                self.wake(wake);

                if kcp_in_errors > 0 {
                    DEFAULT_SNMP
                        .kcp_in_errors
                        .fetch_add(kcp_in_errors, Ordering::Relaxed);
                }
            }
            TYPE_OOB => {
                // Count received OOB packet.
                DEFAULT_SNMP.oob_packets.fetch_add(1, Ordering::Relaxed);
                // If an OOB callback is registered, invoke it synchronously. The callback is
                // responsible for ensuring non-blocking behavior.
                if let Some(callback) = self.oob_handler() {
                    // Data layout: | FEC header (fecHeaderSizePlus2) | conv (4B) | OOB payload |
                    if let Some(payload) = data.get(FEC_HEADER_SIZE_PLUS2 + CONV_SIZE..) {
                        callback(payload);
                    }
                }
            }
            // Packet without FEC.
            _ => {
                let mut guard = self.lock();
                let state = &mut *guard;

                if state
                    .kcp
                    .input(data, IKCP_PACKET_REGULAR, state.ack_no_delay)
                    != 0
                {
                    DEFAULT_SNMP.kcp_in_errors.fetch_add(1, Ordering::Relaxed);
                }

                let wake = Wakeups::of(state);
                drop(guard);
                self.wake(wake);
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Update (flush scheduling)
    // ---------------------------------------------------------------------------------------

    /// One pass of the per-session updater: flushes everything that is due and returns how many
    /// milliseconds to wait before the next pass.
    ///
    /// That is `flush`'s hint: KCP's `interval`, or less when a retransmission timeout falls
    /// earlier. It is never 0 (`flush` only lowers `interval` to a *positive* rto), so the
    /// caller's timer always makes progress.
    ///
    /// Go notifies the write event while still holding `s.mu`; here the flag is computed under
    /// the lock and the notification sent after it, as everywhere else in this module.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).update()
    fn update(&self) -> u32 {
        let mut guard = self.lock();
        let state = &mut *guard;

        let interval = state.kcp.flush(IKCP_FLUSH_FULL);
        let waitsnd = state.kcp.wait_snd();
        let notify_write = waitsnd < state.kcp.snd_wnd as usize;

        drop(guard);
        if notify_write {
            self.write_notify.notify_one();
        }
        interval
    }

    /// Gives back the buffer capacity a burst left behind, and reports whether anything was
    /// released. This session's update task calls it every
    /// [`SESSION_SHRINK_INTERVAL`](crate::memory::SESSION_SHRINK_INTERVAL); [`crate::memory`]
    /// explains why it exists at all.
    ///
    /// Only what is unused **at this instant** goes back — a KCP queue that is empty right now,
    /// a stream reassembly buffer the reader has fully consumed — so the session keeps working
    /// exactly as before and nothing received-but-not-read is disturbed.
    ///
    /// That is a weaker property than "only idle sessions are touched", and deliberately so: both
    /// `rcv_queue` (see [`Kcp::shrink_idle_buffers`](crate::kcp::Kcp::shrink_idle_buffers)) and
    /// `recvbuf` below are empty at most instants *between reads* of a session that is running at
    /// full rate, so a busy session can give an array back on one tick and regrow it. The cost is
    /// a handful of reallocations per session per 30 s and is negligible next to the transfer
    /// causing it; it is called out because a reader would otherwise expect no capacity
    /// oscillation under load.
    pub fn shrink_idle(&self) -> bool {
        let mut guard = self.lock();
        let state = &mut *guard;
        let mut shrunk = state.kcp.shrink_idle_buffers();

        // `recvbuf` grows to the largest message that did not fit the reader's buffer in one
        // piece, and is never given back. Once the reader has consumed it (`bufptr` has reached
        // the end) it holds nothing, and Go re-allocates its own `recvbuf` from scratch whenever
        // a bigger message arrives, so dropping it costs at most that same allocation.
        if state.bufptr >= state.recvbuf.len() && state.recvbuf.capacity() > MTU_LIMIT {
            state.recvbuf = Vec::new();
            state.bufptr = 0;
            shrunk = true;
        }
        shrunk
    }

    /// Builds this session's update task; the caller spawns [`Updater::run`].
    ///
    /// Go schedules it inside `newUDPSession` with `SystemTimedSched.Put(sess.update,
    /// time.Now())`, so the first flush happens immediately; [`Updater::run`] does the same.
    // Go: kcp-go/v5@v5.6.66 sess.go:newUDPSession() ("start per-session updater")
    pub fn updater(self: &Arc<Self>) -> Updater<C> {
        Updater {
            session: Arc::downgrade(self),
            die: self.die.clone(),
        }
    }

    /// Builds this session's read loop; the caller spawns [`ReadLoop::run`].
    ///
    /// Only a **dialled** session has one: Go starts `go sess.readLoop()` in `newUDPSession`
    /// when `l == nil`, while the sessions a listener accepts are fed by its single monitor
    /// task (05.7).
    // Go: kcp-go/v5@v5.6.66 sess.go:newUDPSession() (`go sess.readLoop()`)
    pub fn read_loop(self: &Arc<Self>) -> ReadLoop<C> {
        ReadLoop {
            session: Arc::downgrade(self),
            conn: Arc::clone(&self.conn),
            // Go: `if s.remote != nil { src = s.remote.(*net.UDPAddr) }`.
            filter: SourceFilter::new(Some(self.remote)),
            die: self.die.clone(),
        }
    }

    /// Sends the notifications Go sends at the end of both `kcpInput` branches.
    fn wake(&self, wake: Wakeups) {
        // To notify the readers to receive the data if there's any.
        if wake.read {
            self.read_notify.notify_one();
        }
        // To notify the writers if the window size allows to send more packets and the remote
        // window size is not full.
        if wake.write {
            self.write_notify.notify_one();
        }
    }
}

/// The per-session flush timer: Go's `update()` plus the slice of `SystemTimedSched` that
/// reschedules it (DECISIONS D03).
///
/// Go keeps one global scheduler of `runtime.NumCPU()` goroutines, each holding a heap of timed
/// closures; every session re-registers `s.update` at `time.Now() + interval` at the end of
/// every pass. One tokio task per session is the same "self-synchronized timed scheduling" with
/// tokio's O(1) timer wheel instead of a shared heap: the deadline is taken *after* the flush,
/// exactly as Go's `time.Now().Add(…)` is, so a slow flush shifts the next one by the same
/// amount in both implementations and neither accumulates drift from the sleep itself.
///
/// The task flushes and, every [`memory::SESSION_SHRINK_INTERVAL`](crate::memory::SESSION_SHRINK_INTERVAL),
/// calls [`UdpSession::shrink_idle`] under the same lock. The flush itself does no work that can
/// block: the KCP output callback ([`KcpOutput`]) only copies each segment into a pooled buffer
/// and `try_send`s it to the tx task, so no syscall, no crypto and no blocking happens under the
/// session mutex (D04). The shrink pass reallocates and drops the ring backing arrays under that
/// same lock, which is bounded work on an idle session.
///
/// Three differences from Go, none visible on the wire:
///
/// - **It holds a [`Weak`] reference.** Go's scheduler owns the `s.update` closure, and with it
///   the session, until `Close` — a session that is dropped without being closed keeps flushing
///   (and keeps its socket) forever. Here the task retires at its next wake-up once the last
///   handle is gone, which also drops the [`TxHandle`] inside the session and lets the tx task
///   finish.
/// - **It stops as soon as `die` is cancelled** instead of waiting for the pending timer and
///   finding `die` closed when it fires. [`UdpSession::close`] has already queued the final
///   flush by then (Deviation V05), so there is nothing left for that last pass to do.
/// - **It gives capacity back.** Every 30 s it calls [`UdpSession::shrink_idle`], which releases
///   the ring, `rcv_buf`, `acklist` and `recvbuf` capacity a burst grew. kcp-go's `update()` does
///   nothing of the kind — there the replaced arrays simply become garbage (plan 12.3,
///   [`crate::memory`]).
pub struct Updater<C = SystemClock> {
    /// The session to flush, weakly (see above).
    session: Weak<UdpSession<C>>,
    /// Go's `die`, cloned so that the task can wait on it without holding the session.
    die: CancellationToken,
}

impl<C: Clock> Updater<C> {
    /// Flushes the session every `interval` milliseconds until it closes.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).update() and timedsched.go:TimedSched.sched()
    pub async fn run(self) {
        // Next time the session is asked to give back the capacity a burst left behind
        // (`shrink_idle`). This task already wakes on the session's own schedule, holds the only
        // long-lived reference to it that is allowed to touch the lock periodically, and runs
        // for exactly as long as the session lives, so the housekeeping belongs here rather than
        // in a second timer per session. See `crate::memory`.
        let mut next_shrink = Instant::now() + crate::memory::SESSION_SHRINK_INTERVAL;
        loop {
            // Go: `select { case <-s.die: /* stop rescheduling */ default: … }`.
            if self.die.is_cancelled() {
                return;
            }
            let Some(session) = self.session.upgrade() else {
                return;
            };

            let interval = session.update();

            let now = Instant::now();
            if now >= next_shrink {
                session.shrink_idle();
                next_shrink = now + crate::memory::SESSION_SHRINK_INTERVAL;
            }

            // Self-synchronized timed scheduling, from the moment the flush finished:
            // `SystemTimedSched.Put(s.update, time.Now().Add(interval * time.Millisecond))`.
            let next = Instant::now() + Duration::from_millis(u64::from(interval));
            // Never sleep holding a session alive; `die` is enough to wake up on.
            drop(session);

            tokio::select! {
                () = self.die.cancelled() => return,
                () = tokio::time::sleep_until(next) => {}
            }
        }
    }
}

/// The client's read loop: Go's `readLoop` goroutine, which is the only reader of a dialled
/// session's socket.
///
/// It receives a batch of datagrams, drops the ones that did not come from the session's peer
/// and hands the rest to [`UdpSession::packet_input`], which decrypts them **in place** in the
/// receive slot (as Go decrypts into its own `msgs[i].Buffers[0]`). The slots are allocated once
/// and reused, like Go's `msgs := make([]ipv4.Message, batchSize)`; off Linux Go reads into a
/// single `mtuLimit` buffer instead, where the per-packet path of [`crate::io`] still fills the
/// whole batch with whatever the socket has queued, so the slots are never wasted.
///
/// Two differences from Go, neither visible on the wire:
///
/// - **It holds a [`Weak`] reference**, for the reason given on [`Updater`]: the loop must not
///   be what keeps a session (and its socket) alive.
/// - **It stops as soon as `die` is cancelled** instead of waiting for the socket close to fail
///   the pending receive. Go's `conn.Close()` unblocks `ReadFrom`; [`crate::io::UdpPacketConn`]
///   only marks the connection closed (and drops the fd with its last handle), so the loop needs
///   the token to leave its receive. A batch already read when `die` fires is dropped, which is
///   also what Go's `if s.isClosed() { return }` right after the receive does with it.
///
/// Because those are its only two wake-ups, a dialled session that is dropped without
/// [`UdpSession::close`] leaves this loop parked in `recv_batch` until a datagram arrives, holding
/// its [`PacketConn`] — and therefore the UDP port — for as long as it waits. (Go leaks the same
/// way: `readLoop` blocks in `ReadFrom` and `SystemTimedSched` keeps the session.)
pub struct ReadLoop<C = SystemClock> {
    /// The session to feed, weakly (see above).
    session: Weak<UdpSession<C>>,
    /// Go's `s.conn`, kept here so that the loop can receive without holding the session.
    conn: Arc<dyn PacketConn>,
    /// Go's `src`/`srcStr` pair.
    filter: SourceFilter,
    /// Go's `die`.
    die: CancellationToken,
}

impl<C: Clock> ReadLoop<C> {
    /// Reads from the socket until the session closes or the socket fails.
    // Go: kcp-go/v5@v5.6.66 readloop_linux.go:(*UDPSession).readLoop(),
    // readloop.go:(*UDPSession).defaultReadLoop()
    pub async fn run(mut self) {
        let mut msgs = RecvBatch::new(BATCH_SIZE);

        loop {
            let count = tokio::select! {
                // `die` first: a closing session must not start another batch.
                biased;
                () = self.die.cancelled() => return,
                result = self.conn.recv_batch(&mut msgs) => match result {
                    Ok(count) => count,
                    Err(err) => {
                        // Go: `s.notifyReadError(errors.WithStack(err)); return`, which is what
                        // unblocks everybody in `Read`.
                        if let Some(session) = self.session.upgrade() {
                            session.notify_read_error(err);
                        }
                        return;
                    }
                },
            };

            let Some(session) = self.session.upgrade() else {
                return;
            };
            if session.is_closed() {
                return;
            }

            for mut msg in msgs.iter_mut().take(count) {
                // Make sure the packet is from the same source.
                if !self.filter.accept(msg.addr()) {
                    continue;
                }
                // Source and size have been validated.
                session.packet_input(msg.data_mut());
            }
        }
    }
}

/// The read loop's source filter: every datagram must come from the session's peer, and the
/// rest are counted as `InErrs` and dropped.
///
/// Go carries the peer as a `*net.UDPAddr` (`src`) or, when `s.remote` is some other `net.Addr`,
/// as its string form (`srcStr`); the two collapse here, every address in this port being a
/// [`SocketAddr`]. Comparison is Go's `sameUDPAddr`: port, zone and `net.IP.Equal`, which makes
/// `::ffff:a.b.c.d` equal to `a.b.c.d` (see [`addr::same_udp_addr`]) — that is what lets a
/// dual-stack socket talk to an IPv4 peer.
// Go: kcp-go/v5@v5.6.66 readloop.go:sameUDPAddr() and the filter in both read loops
#[derive(Clone, Copy, Debug)]
struct SourceFilter {
    /// Go's `src`: the peer, `None` while the session has no remote yet.
    src: Option<SocketAddr>,
}

impl SourceFilter {
    fn new(remote: Option<SocketAddr>) -> SourceFilter {
        SourceFilter { src: remote }
    }

    /// Whether a datagram from `addr` belongs to this session; `InErrs` is moved for every one
    /// that does not, as Go does.
    fn accept(&mut self, addr: Option<SocketAddr>) -> bool {
        let Some(src) = self.src else {
            // Go: "set source address if nil" — a session built without a remote adopts the
            // first sender. Only `newUDPSession(…, remote: nil)` reaches it; no kcp-go entry
            // point (and no caller here) passes a nil remote.
            self.src = addr;
            return true;
        };

        // Go: `udp, ok := msg.Addr.(*net.UDPAddr); if !ok || !sameUDPAddr(src, udp)`. A failed
        // type assertion is a datagram whose sender cannot be compared with the remote, which
        // here is one the transport did not report an address for.
        if addr.is_some_and(|addr| addr::same_udp_addr(src, addr)) {
            return true;
        }
        DEFAULT_SNMP.in_errs.fetch_add(1, Ordering::Relaxed);
        false
    }
}

/// Which notifications one `kcp_input` call owes, decided under the lock and sent after it.
#[derive(Clone, Copy, Debug)]
struct Wakeups {
    read: bool,
    write: bool,
}

impl Wakeups {
    // Go: kcp-go/v5@v5.6.66 sess.go:kcpInput() (the `PeekSize`/`WaitSnd` tail of both branches)
    fn of<C: Clock>(state: &SessionState<C>) -> Wakeups {
        Wakeups {
            read: state.kcp.peek_size() > 0,
            write: state.kcp.wait_snd() < state.kcp.snd_wnd as usize,
        }
    }
}

/// Go's `copy(dst, src)`: moves `min(len(dst), len(src))` bytes and returns how many.
fn copy(dst: &mut [u8], src: &[u8]) -> usize {
    let n = dst.len().min(src.len());
    dst[..n].copy_from_slice(&src[..n]);
    n
}

/// Go's `case <-c:` where `c` is `nil` for a session without a deadline: never resolves.
///
/// A deadline in the past resolves immediately, as Go's `time.NewTimer(time.Until(t))` does.
pub(crate) async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => future::pending().await,
    }
}

/// Decrypts and integrity-checks one datagram in place, following `docs/WIRE-FORMAT.md` §2.
///
/// Returns the plaintext payload, or `None` when the packet is dropped (`InCsumErrors` is moved
/// for a failed check, but not for a packet that is too short to hold a crypto header — Go
/// returns silently there).
// Go: kcp-go/v5@v5.6.66 sess.go:packetInput() / Listener.packetInput(), the `switch block`
pub(crate) fn decrypt<'a>(block: Option<&PacketCrypt>, data: &'a mut [u8]) -> Option<&'a [u8]> {
    match block {
        // -crypt null: no crypto layer at all.
        None => Some(data),
        Some(PacketCrypt::Aead(aead)) => {
            if data.len() < aead.nonce_size() + aead.overhead() {
                return None;
            }
            match aead.open_in_place(data) {
                Ok(plaintext) => Some(plaintext),
                Err(_) => {
                    DEFAULT_SNMP.in_csum_errors.fetch_add(1, Ordering::Relaxed);
                    None
                }
            }
        }
        Some(PacketCrypt::Block(block)) => {
            // Decryption and crc32 check.
            if data.len() < CRYPT_HEADER_SIZE {
                return None;
            }
            block.decrypt(data);
            let data = &data[NONCE_SIZE..];

            let (checksum, payload) = data.split_at(CRC_SIZE);
            let checksum = u32::from_le_bytes(
                checksum
                    .try_into()
                    .expect("split_at(CRC_SIZE) yields CRC_SIZE bytes"),
            );
            if crc32fast::hash(payload) != checksum {
                DEFAULT_SNMP.in_csum_errors.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            Some(payload)
        }
    }
}

/// Applies Go's `SetMtu` arithmetic to the KCP state machine and reports whether it took.
///
/// Shared by [`UdpSession::set_mtu`] and the constructor, which calls `SetMtu(IKCP_MTU_DEF)`
/// before anything else because `headerSize` decides the largest segment KCP may emit.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetMtu()
fn set_kcp_mtu<C: Clock>(
    kcp: &mut Kcp<KcpOutput, C>,
    mtu: isize,
    header_size: usize,
    block: Option<&PacketCrypt>,
) -> bool {
    let mut mtu = mtu.min(MTU_LIMIT as isize);
    mtu -= header_size as isize;
    if let Some(aead) = block.and_then(PacketCrypt::as_aead) {
        mtu -= aead.overhead() as isize;
    }
    kcp.set_mtu(mtu) == 0
}

#[cfg(test)]
mod dial_tests;
#[cfg(test)]
mod go_tests;
#[cfg(test)]
mod tests;
