//! The KCP listener (port of kcp-go `sess.go:Listener` and the `monitor` of `readloop*.go`).
//!
//! ```text
//! socket ─▶ monitor task ─▶ packet_input(data, from) ─┬─▶ existing session .kcp_input()
//!                                                     └─▶ new session ─▶ accept queue
//! ```
//!
//! One socket, one monitor task and a map of sessions keyed by the peer address: that is the
//! whole server side of kcp-go. [`Listener::packet_input`] is the demux, and it follows
//! `docs/WIRE-FORMAT.md` §5 exactly: decrypt, pull `conv`/`sn` out of whatever framing the
//! packet uses, route it to the session that owns the address, and only let an unknown
//! conversation create a session when the accept backlog has room.
//!
//! The sessions a listener accepts differ from a dialled one ([`UdpSession::dial_with_options`])
//! in three ways, all of them Go's:
//!
//! - they **share the listener's socket** for transmission (`Arc<dyn PacketConn>`, `ownConn =
//!   false`), so closing one must not close the socket;
//! - they have **no read loop**: this monitor is the only reader of that socket, and a second
//!   one would steal its datagrams. [`UdpSession::start`] arranges that by looking at
//!   `SessionConfig::listener`;
//! - their [`close`](UdpSession::close) takes them out of [`Listener`]'s map through
//!   [`SessionOwner`] (Go's `Listener.closeSession`), so the address can be used again.
//!
//! Differences from Go, none of them visible on the wire:
//!
//! - **Map keys are canonicalised** with [`addr::canonical`]. Go keys the map by
//!   `net.Addr.String()`, and a Go `*net.UDPAddr` prints `::ffff:a.b.c.d` as `a.b.c.d`; Rust's
//!   [`SocketAddr`] does not, so a dual-stack listener would otherwise hold two keys for one
//!   peer.
//! - **The monitor stops on the `die` token.** Go's never looks at `l.die`: it stops because
//!   `Close` closes the socket and the pending `ReadFrom` fails, which is also what propagates
//!   `use of closed network connection` to every session. [`crate::io::UdpPacketConn::close`]
//!   only marks the connection closed (05.1) and does not wake a parked receive, so the monitor
//!   watches the token instead and, when the listener owned the socket, reports the very error
//!   Go's failing `ReadFrom` would have reported. For a listener built with
//!   [`Listener::serve_conn`] (`ownConn = false`, Step 10's tcpraw) Go leaves the monitor running
//!   after `Close` and keeps feeding its sessions; here the monitor retires and no error is
//!   reported, the same task-lifetime choice [`crate::session::ReadLoop`] makes.
//! - **The accept queue is a deque plus a [`Notify`]** rather than a `chan *UDPSession` of
//!   capacity [`ACCEPT_BACKLOG`]. It is multi-consumer like Go's channel (several tasks may sit
//!   in [`accept`](Listener::accept)), and `notify_one` stores a permit exactly as a buffered
//!   channel does. Where Go's `select` picks at random between a queued session and any of its
//!   other arms, [`accept`](Listener::accept) always hands out the queued session first: it is
//!   preferred over the closed `die` token *and* over a recorded socket read error, that is over
//!   every other arm of Go's `select`.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, Weak};

use tokio::sync::Notify;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::addr;
use crate::bufpool::{self, BufferPool};
use crate::clock::{Clock, SystemClock};
use crate::crypt::PacketCrypt;
use crate::error_slot::ErrorSlot;
use crate::fec::{FEC_HEADER_SIZE_PLUS2, FecEncoder, TYPE_DATA, TYPE_OOB, TYPE_PARITY};
use crate::io::UdpPacketConn;
use crate::kcp::{IKCP_OVERHEAD, IKCP_SN_OFFSET};
use crate::packet_conn::{BATCH_SIZE, PacketConn, RecvBatch, invalid_operation};
use crate::session::{
    CONV_SIZE, MIN_PACKET_SIZE, SessionConfig, SessionError, SessionOwner, UdpSession, closed_pipe,
    decrypt, sleep_until, timeout,
};

/// How many accepted-but-not-yet-[`accept`](Listener::accept)ed sessions the listener queues
/// before it starts dropping the packets that would create new ones.
// Go: kcp-go/v5@v5.6.66 sess.go:acceptBacklog
pub const ACCEPT_BACKLOG: usize = 128;

/// Everything a listener needs to be built; the counterpart of [`SessionConfig`].
///
/// Go's `serveConn(block, dataShards, parityShards, conn, ownConn)` takes the same five values
/// and hardcodes the buffer pool and the clock, which are explicit here so that tests (and Step
/// 12 experiments) can supply their own.
pub struct ListenerConfig<C = SystemClock> {
    /// The packet cipher, or `None` for `-crypt null`.
    pub block: Option<PacketCrypt>,
    /// FEC data shards per group; `0` (or negative) disables FEC.
    pub data_shards: isize,
    /// FEC parity shards per group; `0` (or negative) disables FEC.
    pub parity_shards: isize,
    /// The socket every session of this listener shares.
    pub conn: Arc<dyn PacketConn>,
    /// Go's `ownConn`: true when the listener created `conn` itself, so that
    /// [`close`](Listener::close) closes it.
    pub own_conn: bool,
    /// Where the sessions' packet buffers come from.
    pub pool: Arc<BufferPool>,
    /// The millisecond clock handed to every accepted session.
    pub clock: C,
}

/// A server which will be waiting to accept incoming connections.
// Go: kcp-go/v5@v5.6.66 sess.go:Listener
pub struct Listener<C = SystemClock> {
    /// Go's `block`: block encryption.
    block: Option<PacketCrypt>,
    /// Go's `dataShards`: FEC data shard.
    data_shards: isize,
    /// Go's `parityShards`: FEC parity shard.
    parity_shards: isize,
    /// Go's `conn`: the underlying packet connection.
    conn: Arc<dyn PacketConn>,
    /// Go's `ownConn`: true if we created `conn` internally, false if provided by caller.
    own_conn: bool,
    /// Go's `sessions` + `sessionLock`: all sessions accepted by this Listener.
    sessions: RwLock<HashMap<SocketAddr, Arc<UdpSession<C>>>>,
    /// Deviation V23: the same sessions indexed by conversation id, consulted only when the
    /// address lookup misses, so that a peer whose datagrams arrive from more than one address
    /// keeps one session instead of opening one per address. Go has no such index.
    by_conv: RwLock<HashMap<u32, Arc<UdpSession<C>>>>,
    /// Deviation V23: when set, the conv index is never consulted and a new address means a new
    /// session, exactly as in Go. Sampled once, at construction.
    strict_source: bool,
    /// Go's `chAccepts`: the `Listen()` backlog (see the module header).
    accepts: Mutex<VecDeque<Arc<UdpSession<C>>>>,
    /// Wakes one task blocked in [`accept`](Listener::accept), like a send on `chAccepts`.
    accept_notify: Notify,
    /// Go's `die`: notifies that the listener has closed.
    die: CancellationToken,
    /// Go's `dieOnce`: only the first `Close` does the work.
    die_once: AtomicBool,
    /// Go's `socketReadError` + `chSocketReadError` + `socketReadErrorOnce`.
    read_error: ErrorSlot,
    /// Go's `rd`: the read deadline of [`accept`](Listener::accept).
    rd: Mutex<Option<Instant>>,
    /// Where the accepted sessions take their packet buffers from.
    pool: Arc<BufferPool>,
    /// The clock every accepted session runs on.
    clock: C,
}

impl<C: Clock + Clone> Listener<C> {
    /// Builds a listener and the monitor task that feeds it; the caller spawns
    /// [`Monitor::run`].
    ///
    /// Go's `serveConn` does both at once (`go l.monitor()`); the split exists so that tests can
    /// drive [`packet_input`](Self::packet_input) by hand, as [`UdpSession::new`] lets them drive
    /// the session's input pipeline.
    ///
    /// Errors: the shard counts are validated once, here, so that no accepted session can fail to
    /// build later (Deviation V07: `data_shards + parity_shards > 256` has no codec). Go's
    /// `ServeConn`/`ListenWithOptions` likewise return `(*Listener, error)`.
    // Go: kcp-go/v5@v5.6.66 sess.go:serveConn()
    pub fn new(config: ListenerConfig<C>) -> io::Result<(Arc<Listener<C>>, Monitor<C>)> {
        // Deviation V07, checked up front: every accepted session builds the same encoder.
        FecEncoder::new(config.data_shards, config.parity_shards, 0).map_err(SessionError::from)?;
        let listener = Arc::new(Listener {
            block: config.block,
            data_shards: config.data_shards,
            parity_shards: config.parity_shards,
            conn: config.conn,
            own_conn: config.own_conn,
            sessions: RwLock::new(HashMap::new()),
            by_conv: RwLock::new(HashMap::new()),
            strict_source: crate::session::strict_source(),
            accepts: Mutex::new(VecDeque::new()),
            accept_notify: Notify::new(),
            die: CancellationToken::new(),
            die_once: AtomicBool::new(false),
            read_error: ErrorSlot::new(),
            rd: Mutex::new(None),
            pool: config.pool,
            clock: config.clock,
        });
        let monitor = Monitor {
            listener: Arc::downgrade(&listener),
            conn: Arc::clone(&listener.conn),
            die: listener.die.clone(),
            own_conn: listener.own_conn,
        };
        Ok((listener, monitor))
    }

    /// Builds a listener and starts its monitor task, the whole of Go's `serveConn`.
    ///
    /// Must be called from within a tokio runtime.
    ///
    /// Errors: as [`new`](Self::new).
    // Go: kcp-go/v5@v5.6.66 sess.go:serveConn() (`go l.monitor()`)
    pub fn start(config: ListenerConfig<C>) -> io::Result<Arc<Listener<C>>> {
        let (listener, monitor) = Listener::new(config)?;
        tokio::spawn(monitor.run());
        Ok(listener)
    }
}

impl Listener<SystemClock> {
    /// Listens for incoming KCP packets addressed to the local address `laddr` on the network
    /// "udp", without encryption and FEC.
    ///
    /// Must be called from within a tokio runtime (see [`start`](Self::start)).
    // Go: kcp-go/v5@v5.6.66 sess.go:Listen()
    pub fn listen(laddr: &str) -> io::Result<Arc<Listener>> {
        Listener::listen_with_options(laddr, None, 0, 0)
    }

    /// Listens for incoming KCP packets addressed to the local address `laddr` on the network
    /// "udp" with packet encryption.
    ///
    /// `block` is the block encryption algorithm to encrypt packets, `None` for `-crypt null`.
    /// `data_shards`/`parity_shards` specify how many parity packets will be generated following
    /// the data packets; `0` disables FEC.
    ///
    /// `":29900"` (or any wildcard host) binds a **dual-stack** socket, so the listener serves
    /// IPv4 and IPv6 peers on one port, exactly as Go's `net.ListenUDP("udp", …)` does.
    ///
    /// Must be called from within a tokio runtime (see [`start`](Self::start)).
    // Go: kcp-go/v5@v5.6.66 sess.go:ListenWithOptions()
    pub fn listen_with_options(
        laddr: &str,
        block: Option<PacketCrypt>,
        data_shards: isize,
        parity_shards: isize,
    ) -> io::Result<Arc<Listener>> {
        let conn = UdpPacketConn::listen(laddr)?;
        Listener::serve(block, data_shards, parity_shards, Arc::new(conn), true)
    }

    /// Serves the KCP protocol for a single packet connection supplied by the caller (Step 10's
    /// tcpraw), which the listener does **not** own: [`close`](Self::close) leaves it open.
    ///
    /// Must be called from within a tokio runtime (see [`start`](Self::start)).
    ///
    /// Errors: as [`new`](Self::new); Go's `ServeConn` returns `(*Listener, error)` too, with the
    /// error always `nil`.
    // Go: kcp-go/v5@v5.6.66 sess.go:ServeConn()
    pub fn serve_conn(
        block: Option<PacketCrypt>,
        data_shards: isize,
        parity_shards: isize,
        conn: Arc<dyn PacketConn>,
    ) -> io::Result<Arc<Listener>> {
        Listener::serve(block, data_shards, parity_shards, conn, false)
    }

    /// Go's unexported `serveConn`, the body both entry points share.
    // Go: kcp-go/v5@v5.6.66 sess.go:serveConn()
    fn serve(
        block: Option<PacketCrypt>,
        data_shards: isize,
        parity_shards: isize,
        conn: Arc<dyn PacketConn>,
        own_conn: bool,
    ) -> io::Result<Arc<Listener>> {
        Listener::start(ListenerConfig {
            block,
            data_shards,
            parity_shards,
            conn,
            own_conn,
            // Go's single `defaultBufferPool`, shared by every session in the process.
            pool: Arc::clone(bufpool::default_pool()),
            clock: SystemClock,
        })
    }
}

impl<C: Clock + Clone> Listener<C> {
    // ---------------------------------------------------------------------------------------
    // Packet input stage
    // ---------------------------------------------------------------------------------------

    /// The demux: decrypts one datagram from `addr` and routes it to the session that owns that
    /// address, creating one when the packet carries an unknown conversation id.
    ///
    /// `data` is decrypted **in place**, as Go's is. The rules are `docs/WIRE-FORMAT.md` §5:
    ///
    /// - the conversation id and the KCP sequence number are read out of whichever framing the
    ///   packet uses (FEC data, FEC parity, OOB or plain KCP);
    /// - a packet for an existing session is fed to it when its conv matches, or when no conv
    ///   could be read at all (FEC parity, which belongs to the address);
    /// - a **conv mismatch** only resets the session when `sn == 0`, i.e. for the first segment
    ///   of a new conversation; anything else is dropped, so a stale packet cannot tear down a
    ///   live session;
    /// - a new session is created only while the accept backlog has room.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).packetInput()
    pub fn packet_input(self: &Arc<Self>, data: &mut [u8], addr: SocketAddr) {
        // Go compares `net.Addr.String()`, where `::ffff:a.b.c.d` prints as `a.b.c.d`; see the
        // module header.
        let addr = addr::canonical(addr);

        let Some(data) = decrypt(self.block.as_ref(), data) else {
            return;
        };

        // Basic check for minimum packet size.
        // NOTE: OOB allows sending small packets and even empty packets.
        if data.len() < MIN_PACKET_SIZE {
            return;
        }

        // Look for existing session.
        let existing = self.session(addr);

        let mut conv = 0u32;
        let mut sn = 0u32;
        let mut has_conv = false;

        // Try to get conversation id from the packet. 16bit kcp cmd [81-84] and frg [0-255] will
        // not overlap with FEC type 0x00f1 0x00f2.
        let fec_flag = le_u16(data, 4);

        match fec_flag {
            TYPE_DATA => {
                // Data packet of FEC, conversation id inside.
                if data.len() >= FEC_HEADER_SIZE_PLUS2 + IKCP_OVERHEAD as usize {
                    has_conv = true;
                    conv = le_u32(data, FEC_HEADER_SIZE_PLUS2);
                    sn = le_u32(data, FEC_HEADER_SIZE_PLUS2 + IKCP_SN_OFFSET);
                }
            }
            // Parity packet of FEC, no conversation id inside.
            TYPE_PARITY => {}
            TYPE_OOB => {
                // OOB packets always carry the conversation ID immediately after the FEC header.
                // Data layout: | FEC header (fecHeaderSizePlus2) | conv (4B) | OOB payload |
                //
                // `MIN_PACKET_SIZE` is `fecHeaderSizePlus2 + convSize`, so the id is always
                // there. Go leaves `sn` at 0 here, which makes an OOB packet with a mismatched
                // conv a reset: reproduced, quirk included.
                debug_assert!(data.len() >= FEC_HEADER_SIZE_PLUS2 + CONV_SIZE);
                has_conv = true;
                conv = le_u32(data, FEC_HEADER_SIZE_PLUS2);
            }
            _ => {
                // Packet without FEC. Basic check for minimum kcp packet size.
                if data.len() < IKCP_OVERHEAD as usize {
                    return;
                }
                has_conv = true;
                conv = le_u32(data, 0);
                sn = le_u32(data, IKCP_SN_OFFSET);
            }
        }

        // Deviation V23: an address we have never seen may still belong to a session we already
        // hold, the peer having simply answered from somewhere else. The conv decides, and only
        // after `decrypt` has passed, so with any cipher but `-crypt null` a forged packet has
        // to survive a CRC32 or an AEAD tag before it can reach a session this way.
        //
        // The session's own remote is left untouched, so replies keep going where they always
        // went: this lets a peer *send* from a second address, not move to one. A parity packet
        // carries no conv (`has_conv` is false), so those are still dropped from an unknown
        // address, costing that source its FEC redundancy but not its data.
        let existing = match existing {
            None if has_conv && !self.strict_source => self.session_by_conv(conv),
            found => found,
        };

        // On an existing connection.
        if let Some(session) = existing {
            // If we have a valid conversation id or we cannot get conversation id from the
            // packet, just feed the data into the existing session.
            if !has_conv || conv == session.get_conv() {
                session.kcp_input(data);
                return;
            }
            // Conversation id mismatched, only accept reset packet with sn == 0.
            if sn != 0 {
                return;
            }
            // Close will remove the session from listener's session map, so we can create a new
            // session with the same addr below. (`close` only fails when the session was already
            // closed, which leaves the map entry to `close_session` either way.)
            let _ = session.close();
        }

        // The connection does not exist, try to create a new one. But if we don't have a valid
        // conversation id, nothing we can do here except dropping the packet.
        if !has_conv {
            return;
        }

        // Now we have a valid conversation id here without a session object, create a new
        // session. Do not let the new sessions overwhelm accept queue.
        if self.accepts().len() >= ACCEPT_BACKLOG {
            return;
        }

        // New session. `PassiveOpens`, `CurrEstab` and `MaxConn` are moved inside
        // `UdpSession::new`, which reads them off `SessionConfig::listener` (Go counts them in
        // `newUDPSession` the same way).
        let owner: Arc<dyn SessionOwner> = Arc::clone(self) as Arc<dyn SessionOwner>;
        let session = UdpSession::start(SessionConfig {
            conv,
            data_shards: self.data_shards,
            parity_shards: self.parity_shards,
            conn: Arc::clone(&self.conn),
            own_conn: false,
            listener: Some(Arc::downgrade(&owner)),
            remote: addr,
            block: self.block.clone(),
            pool: Arc::clone(&self.pool),
            clock: self.clock.clone(),
            die: CancellationToken::new(),
        });
        // Go's `newUDPSession` cannot fail; both failure modes are unreachable here (the default
        // MTU always fits, and a shard count no codec can serve (Deviation V07) is rejected by
        // `Listener::new`). Dropping the packet is the no-panic substitution.
        let Ok(session) = session else {
            return;
        };

        session.kcp_input(data);
        self.sessions_mut().insert(addr, Arc::clone(&session));
        self.register_conv(&session);
        self.push_accept(session);
    }

    // ---------------------------------------------------------------------------------------
    // Accept
    // ---------------------------------------------------------------------------------------

    /// Waits for the next session and returns it.
    ///
    /// Go's `Accept` hands back a `net.Conn` and `AcceptKCP` the concrete `*UDPSession`; there is
    /// one return type here, so this is both.
    ///
    /// Errors: [`timeout`] once the deadline set by
    /// [`set_read_deadline`](Self::set_read_deadline) passes, the socket read error if the
    /// monitor recorded one, and [`closed_pipe`] after [`close`](Self::close).
    ///
    /// Go's quirk, reproduced: the deadline is read **once**, when the call starts, so a
    /// `SetReadDeadline` on an `AcceptKCP` that is already blocked has no effect on it (unlike
    /// [`UdpSession::read`], which re-reads it at every wake-up).
    // Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).Accept(), (*Listener).AcceptKCP()
    pub async fn accept(&self) -> io::Result<Arc<UdpSession<C>>> {
        let deadline = *self.rd();

        loop {
            // Register before looking at the queue, so a session pushed in between still wakes
            // this call (porting guide §6).
            let notified = self.accept_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            if let Some(session) = self.accepts().pop_front() {
                return Ok(session);
            }

            tokio::select! {
                () = notified => {}
                () = sleep_until(deadline) => return Err(timeout()),
                () = self.read_error.wait() => {
                    return Err(self.read_error.io_error().unwrap_or_else(closed_pipe));
                }
                () = self.die.cancelled() => return Err(closed_pipe()),
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Close and error propagation
    // ---------------------------------------------------------------------------------------

    /// Stops listening on the UDP address, and closes the socket if the listener owns it.
    ///
    /// The second and later calls return [`closed_pipe`], as Go's `dieOnce` makes them. The
    /// sessions already accepted are **not** closed (Go does not close them either) but they
    /// stop receiving, and on an owned socket they are handed the same
    /// `use of closed network connection` error Go's monitor propagates when its `ReadFrom`
    /// fails (see the module header).
    // Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).Close()
    pub fn close(&self) -> io::Result<()> {
        if self.die_once.swap(true, Ordering::AcqRel) {
            return Err(closed_pipe());
        }
        self.die.cancel();

        if self.own_conn {
            return self.conn.close();
        }
        Ok(())
    }

    /// Whether the listener has been closed.
    pub fn is_closed(&self) -> bool {
        self.die.is_cancelled()
    }

    /// Go's `die`, cancelled by [`close`](Self::close).
    pub fn die(&self) -> &CancellationToken {
        &self.die
    }

    /// Records the first socket read error and propagates it to every session, which is what
    /// releases readers blocked in [`UdpSession::read`].
    // Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).notifyReadError()
    pub fn notify_read_error(&self, err: io::Error) {
        // Go's `socketReadErrorOnce`.
        if !self.read_error.set(err) {
            return;
        }

        // Propagate read error to all sessions.
        let sessions = self.sessions();
        for session in sessions.values() {
            if let Some(err) = self.read_error.io_error() {
                session.notify_read_error(err);
            }
        }
    }

    /// The first error the socket reported while reading (Go's `socketReadError`).
    pub fn read_error(&self) -> &ErrorSlot {
        &self.read_error
    }

    /// Notifies the listener that a session has closed, removing it from the map.
    ///
    /// This is [`SessionOwner::close_session`]; [`UdpSession::close`] calls it.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).closeSession()
    fn remove_session(&self, remote: SocketAddr) -> bool {
        let removed = self.sessions_mut().remove(&remote);
        // Deviation V23: drop the conv alias with it, but only while it still points at *this*
        // session, after a collision the alias belongs to the session that won it, and must
        // outlive the one that did not.
        if let Some(session) = removed.as_ref() {
            let conv = session.get_conv();
            let mut by_conv = self.by_conv_mut();
            if by_conv
                .get(&conv)
                .is_some_and(|held| Arc::ptr_eq(held, session))
            {
                by_conv.remove(&conv);
            }
        }
        removed.is_some()
    }

    // ---------------------------------------------------------------------------------------
    // Addresses, deadlines and socket options
    // ---------------------------------------------------------------------------------------

    /// The listener's network address.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).Addr()
    pub fn addr(&self) -> io::Result<SocketAddr> {
        self.conn.local_addr()
    }

    /// Sets the deadline associated with the listener. `None` is Go's zero `time.Time`: no
    /// deadline.
    ///
    /// Go calls `SetWriteDeadline` too and drops its `invalid operation`, which is why this
    /// always returns `Ok`.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).SetDeadline()
    pub fn set_deadline(&self, t: Option<Instant>) -> io::Result<()> {
        let _ = self.set_read_deadline(t);
        let _ = self.set_write_deadline(t);
        Ok(())
    }

    /// Sets the deadline of [`accept`](Self::accept); it only applies to calls started
    /// afterwards.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).SetReadDeadline()
    pub fn set_read_deadline(&self, t: Option<Instant>) -> io::Result<()> {
        *self.rd() = t;
        Ok(())
    }

    /// A listener never writes, so Go returns `invalid operation`.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).SetWriteDeadline()
    pub fn set_write_deadline(&self, _t: Option<Instant>) -> io::Result<()> {
        Err(invalid_operation())
    }

    /// Sets the socket read buffer for the Listener.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).SetReadBuffer()
    pub fn set_read_buffer(&self, bytes: usize) -> io::Result<()> {
        self.conn.set_read_buffer(bytes)
    }

    /// Sets the socket write buffer for the Listener.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).SetWriteBuffer()
    pub fn set_write_buffer(&self, bytes: usize) -> io::Result<()> {
        self.conn.set_write_buffer(bytes)
    }

    /// Sets the 6-bit DSCP field of the IPv4 header, or the 8-bit traffic class of the IPv6 one
    /// (Deviation V03).
    ///
    /// Unlike [`UdpSession::set_dscp`] this takes no lock: Go's `Listener` has no `mu` to hold.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).SetDSCP()
    pub fn set_dscp(&self, dscp: i32) -> io::Result<()> {
        self.conn.set_dscp(dscp)
    }

    // ---------------------------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------------------------

    /// How many sessions the listener holds (Go's `len(l.sessions)`), for statistics and tests.
    pub fn session_count(&self) -> usize {
        self.sessions().len()
    }

    /// The session registered for `remote`, if any.
    ///
    /// The address is canonicalised, so the caller may pass whatever form the socket reported.
    pub fn session(&self, remote: SocketAddr) -> Option<Arc<UdpSession<C>>> {
        self.sessions()
            .get(&addr::canonical(remote))
            .map(Arc::clone)
    }

    /// Deviation V23: the session holding conversation `conv`, whatever address it was created
    /// for.
    pub fn session_by_conv(&self, conv: u32) -> Option<Arc<UdpSession<C>>> {
        self.by_conv().get(&conv).map(Arc::clone)
    }

    /// Adds `session` to the Deviation V23 conv index.
    ///
    /// A conv is four bytes from the OS RNG, so two live sessions sharing one is an accident of
    /// about one in 2^32 rather than a case to design around. When it does happen the first
    /// session keeps the alias and the second stays reachable by address alone, which is all
    /// either of them gets under Go's rules anyway.
    fn register_conv(&self, session: &Arc<UdpSession<C>>) {
        self.by_conv_mut()
            .entry(session.get_conv())
            .or_insert_with(|| Arc::clone(session));
    }

    /// Queues a session for [`accept`](Self::accept), Go's `l.chAccepts <- s`.
    fn push_accept(&self, session: Arc<UdpSession<C>>) {
        self.accepts().push_back(session);
        self.accept_notify.notify_one();
    }

    /// A poisoned lock is recovered rather than propagated, as in [`crate::session`]: everything
    /// these locks guard is plain data that no panic can leave half-updated.
    fn sessions(&self) -> std::sync::RwLockReadGuard<'_, HashMap<SocketAddr, Arc<UdpSession<C>>>> {
        self.sessions.read().unwrap_or_else(|err| err.into_inner())
    }

    fn sessions_mut(
        &self,
    ) -> std::sync::RwLockWriteGuard<'_, HashMap<SocketAddr, Arc<UdpSession<C>>>> {
        self.sessions.write().unwrap_or_else(|err| err.into_inner())
    }

    fn by_conv(&self) -> std::sync::RwLockReadGuard<'_, HashMap<u32, Arc<UdpSession<C>>>> {
        self.by_conv.read().unwrap_or_else(|err| err.into_inner())
    }

    fn by_conv_mut(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<u32, Arc<UdpSession<C>>>> {
        self.by_conv.write().unwrap_or_else(|err| err.into_inner())
    }

    fn accepts(&self) -> MutexGuard<'_, VecDeque<Arc<UdpSession<C>>>> {
        self.accepts.lock().unwrap_or_else(|err| err.into_inner())
    }

    fn rd(&self) -> MutexGuard<'_, Option<Instant>> {
        self.rd.lock().unwrap_or_else(|err| err.into_inner())
    }
}

// Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).closeSession()
impl<C: Clock + Clone> SessionOwner for Listener<C> {
    fn close_session(&self, remote: SocketAddr) -> bool {
        self.remove_session(remote)
    }
}

/// The listener's monitor: Go's `monitor` goroutine, the only reader of the shared socket.
///
/// It receives a batch of datagrams and hands each one, with its sender, to
/// [`Listener::packet_input`], which decrypts it in place in the receive slot. Like
/// [`crate::session::ReadLoop`] it holds a [`Weak`] reference, so that the task cannot be what
/// keeps a listener (and its socket) alive, and it leaves on the `die` token, see the module
/// header for how that maps onto Go's "the socket close fails `ReadFrom`".
pub struct Monitor<C = SystemClock> {
    /// The listener to feed, weakly (see above).
    listener: Weak<Listener<C>>,
    /// Go's `l.conn`, kept here so that the task can receive without holding the listener.
    conn: Arc<dyn PacketConn>,
    /// Go's `l.die`.
    die: CancellationToken,
    /// Go's `l.ownConn`; decides whether leaving on `die` means the socket was closed.
    own_conn: bool,
}

impl<C: Clock + Clone> Monitor<C> {
    /// Reads from the socket until the listener closes or the socket fails.
    // Go: kcp-go/v5@v5.6.66 readloop_linux.go:(*Listener).monitor(),
    // readloop.go:(*Listener).defaultMonitor()
    pub async fn run(self) {
        let mut msgs = RecvBatch::new(BATCH_SIZE);

        loop {
            let count = tokio::select! {
                // `die` first: a closing listener must not start another batch.
                biased;
                () = self.die.cancelled() => {
                    if self.own_conn && let Some(listener) = self.listener.upgrade() {
                        // What Go's pending `ReadFrom` returns once `Close` shut the socket,
                        // and thus what its monitor propagates to every session.
                        listener.notify_read_error(crate::io::closed());
                    }
                    return;
                }
                result = self.conn.recv_batch(&mut msgs) => match result {
                    Ok(count) => count,
                    Err(err) => {
                        // Go: `l.notifyReadError(errors.WithStack(err)); return`.
                        if let Some(listener) = self.listener.upgrade() {
                            listener.notify_read_error(err);
                        }
                        return;
                    }
                },
            };

            let Some(listener) = self.listener.upgrade() else {
                return;
            };

            for mut msg in msgs.iter_mut().take(count) {
                // Go's `msg.Addr` always names a sender; a transport that reports none gives a
                // datagram the session map cannot be keyed by, so it is dropped. No
                // `PacketConn` in this workspace produces one.
                let Some(addr) = msg.addr() else {
                    continue;
                };
                listener.packet_input(msg.data_mut(), addr);
            }
        }
    }
}

/// Go's `binary.LittleEndian.Uint16(data[offset:])`, `0` where Go would panic.
///
/// Every call site has checked the length first (porting guide §5).
fn le_u16(data: &[u8], offset: usize) -> u16 {
    data.get(offset..offset + 2)
        .map_or(0, |b| u16::from_le_bytes([b[0], b[1]]))
}

/// Go's `binary.LittleEndian.Uint32(data[offset:])`, `0` where Go would panic.
fn le_u32(data: &[u8], offset: usize) -> u32 {
    data.get(offset..offset + 4)
        .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[cfg(test)]
mod tests;
