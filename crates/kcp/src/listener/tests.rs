//! Tests of the listener (05.7): the demux of `docs/WIRE-FORMAT.md` §5, the accept queue and
//! the shared socket.
//!
//! Most tests drive [`Listener::packet_input`] by hand over a fake [`PacketConn`], the way
//! `session/tests.rs` drives the session's input pipeline, and build the datagrams byte by byte
//! so that every branch of the conv/sn extraction can be hit on purpose. The two tests that need
//! the real thing ([`two_clients_multiplexed_over_one_socket`] and the monitor tests) run over a
//! loopback socket or a fake one that fails on demand.
//!
//! `DEFAULT_SNMP` is process-global, so every test that moves a counter holds `SNMP_TEST_LOCK`
//! (the convention from 03.3), and the ones that assert exact deltas hold it for writing. Note
//! 174: `CurrEstab` is never reset between tests, so only deltas may be asserted.
#![allow(
    clippy::await_holding_lock,
    reason = "SNMP_TEST_LOCK serialises whole test bodies; see session/tests.rs"
)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex as StdMutex;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use super::*;
use crate::crypt::new_aes_block_crypt;
use crate::fec::{FEC_HEADER_SIZE, OOB_SEQID};
use crate::kcp::{IKCP_CMD_PUSH, SNMP_TEST_LOCK};
use crate::packet_conn::{BoxFuture, TxMsg};
use crate::session::{is_timeout, timeout};
use crate::snmp::DEFAULT_SNMP;

/// Longest a test waits for a task to get somewhere.
const LIMIT: Duration = Duration::from_secs(20);

fn snmp_read() -> std::sync::RwLockReadGuard<'static, ()> {
    SNMP_TEST_LOCK.read().unwrap_or_else(|e| e.into_inner())
}

fn snmp_write() -> std::sync::RwLockWriteGuard<'static, ()> {
    SNMP_TEST_LOCK.write().unwrap_or_else(|e| e.into_inner())
}

fn counter(c: &std::sync::atomic::AtomicU64) -> u64 {
    c.load(Ordering::Relaxed)
}

fn addr_of(s: &str) -> SocketAddr {
    s.parse().expect("literal address")
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

/// Waits until `cond` holds, failing the test after [`LIMIT`].
async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let wait = async {
        while !cond() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };
    tokio::time::timeout(LIMIT, wait)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

fn aes_crypt() -> PacketCrypt {
    PacketCrypt::Block(new_aes_block_crypt(&[7u8; 32]).expect("aes-256 key"))
}

/// `len` bytes with a recognisable pattern.
fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
}

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

/// A [`PacketConn`] that records what the listener's sessions send, and whose receive parks until
/// [`FakeConn::fail`] arms it.
#[derive(Debug, Default)]
struct FakeConn {
    /// Every datagram the accepted sessions put on this shared socket.
    sent: StdMutex<Vec<(Vec<u8>, SocketAddr)>>,
    /// Releases the pending receive with a socket error.
    armed: tokio::sync::Notify,
    /// How often `recv_batch` was entered, so a test can tell the monitor is parked.
    recvs: AtomicUsize,
    /// Set by `close()`.
    closed: AtomicBool,
    /// Option setters, with their values.
    options: StdMutex<Vec<(&'static str, i64)>>,
}

impl FakeConn {
    /// The error the monitor will see, Go's `errors.WithStack(err)` from `ReadFrom`.
    fn error() -> io::Error {
        io::Error::new(io::ErrorKind::ConnectionReset, "connection reset by peer")
    }

    fn fail(&self) {
        self.armed.notify_one();
    }

    fn sent(&self) -> Vec<(Vec<u8>, SocketAddr)> {
        self.sent.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn options(&self) -> Vec<(&'static str, i64)> {
        self.options
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn record(&self, name: &'static str, value: i64) {
        self.options
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((name, value));
    }
}

impl PacketConn for FakeConn {
    fn recv_batch<'a>(&'a self, _batch: &'a mut RecvBatch) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async move {
            self.recvs.fetch_add(1, Ordering::SeqCst);
            self.armed.notified().await;
            Err(FakeConn::error())
        })
    }

    fn send_batch<'a>(&'a self, msgs: &'a [TxMsg<'a>]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async move {
            let mut sent = self.sent.lock().unwrap_or_else(|e| e.into_inner());
            for msg in msgs {
                sent.push((msg.data.to_vec(), msg.addr));
            }
            Ok(msgs.len())
        })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(loopback(29900))
    }

    fn set_read_buffer(&self, bytes: usize) -> io::Result<()> {
        self.record("read_buffer", bytes as i64);
        Ok(())
    }

    fn set_write_buffer(&self, bytes: usize) -> io::Result<()> {
        self.record("write_buffer", bytes as i64);
        Ok(())
    }

    fn set_dscp(&self, dscp: i32) -> io::Result<()> {
        self.record("dscp", i64::from(dscp));
        Ok(())
    }

    fn close(&self) -> io::Result<()> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return Err(invalid_operation());
        }
        Ok(())
    }
}

/// A listener over a [`FakeConn`] whose monitor task is **not** started: the test feeds
/// [`Listener::packet_input`] itself.
fn listener_without_monitor(
    block: Option<PacketCrypt>,
    data_shards: isize,
    parity_shards: isize,
) -> (Arc<Listener>, Arc<FakeConn>) {
    let conn = Arc::new(FakeConn::default());
    let (listener, monitor) = Listener::new(ListenerConfig {
        block,
        data_shards,
        parity_shards,
        conn: Arc::clone(&conn) as Arc<dyn PacketConn>,
        own_conn: true,
        pool: BufferPool::new(512),
        clock: SystemClock,
    })
    .expect("the listener must build");
    drop(monitor);
    (listener, conn)
}

// ---------------------------------------------------------------------------------------------
// Packet builders (`docs/WIRE-FORMAT.md` §1 and §3)
// ---------------------------------------------------------------------------------------------

/// One plain KCP segment: `conv` at offset 0, `sn` at [`IKCP_SN_OFFSET`].
// Go: kcp-go/v5@v5.6.66 kcp.go:(*segment).encode()
fn kcp_packet(conv: u32, sn: u32, body: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; IKCP_OVERHEAD as usize];
    packet[0..4].copy_from_slice(&conv.to_le_bytes());
    packet[4] = IKCP_CMD_PUSH; // cmd; frg stays 0, so data[4..6] is no FEC type
    packet[6..8].copy_from_slice(&128u16.to_le_bytes()); // wnd
    packet[12..16].copy_from_slice(&sn.to_le_bytes());
    packet[20..24].copy_from_slice(&(body.len() as u32).to_le_bytes());
    packet.extend_from_slice(body);
    packet
}

/// A FEC data packet: `| seqid | typeData | size | KCP segment |`.
// Go: kcp-go/v5@v5.6.66 fec.go:fecEncoder.sealData()
fn fec_data_packet(seqid: u32, conv: u32, sn: u32, body: &[u8]) -> Vec<u8> {
    let inner = kcp_packet(conv, sn, body);
    let mut packet = fec_header(seqid, TYPE_DATA, inner.len() + 2);
    packet.extend_from_slice(&inner);
    packet
}

/// A FEC parity packet: no conversation id anywhere in it.
// Go: kcp-go/v5@v5.6.66 fec.go:fecEncoder.sealParity()
fn fec_parity_packet(seqid: u32, len: usize) -> Vec<u8> {
    let mut packet = vec![0u8; FEC_HEADER_SIZE + len];
    packet[0..4].copy_from_slice(&seqid.to_le_bytes());
    packet[4..6].copy_from_slice(&TYPE_PARITY.to_le_bytes());
    packet
}

/// An OOB packet: `| seqid | typeOOB | size | conv | payload |`.
// Go: kcp-go/v5@v5.6.66 fec.go:fecEncoder.sealOOB(), sess.go:(*UDPSession).SendOOB()
fn oob_packet(conv: u32, body: &[u8]) -> Vec<u8> {
    let mut packet = fec_header(OOB_SEQID, TYPE_OOB, CONV_SIZE + body.len() + 2);
    packet.extend_from_slice(&conv.to_le_bytes());
    packet.extend_from_slice(body);
    packet
}

fn fec_header(seqid: u32, flag: u16, size: usize) -> Vec<u8> {
    let mut packet = vec![0u8; FEC_HEADER_SIZE_PLUS2];
    packet[0..4].copy_from_slice(&seqid.to_le_bytes());
    packet[4..6].copy_from_slice(&flag.to_le_bytes());
    packet[6..8].copy_from_slice(&(size as u16).to_le_bytes());
    packet
}

/// Feeds one datagram to the listener the way the monitor does.
fn input(listener: &Arc<Listener>, packet: &[u8], from: SocketAddr) {
    let mut packet = packet.to_vec();
    listener.packet_input(&mut packet, from);
}

// ---------------------------------------------------------------------------------------------
// Demux: conv and sn extraction
// ---------------------------------------------------------------------------------------------

/// A plain KCP packet carries its conv at offset 0 and its sn at offset 12, so it creates a
/// session, is fed to it, and the session is queued for `Accept`.
// Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).packetInput() (the `default` case)
#[tokio::test(flavor = "current_thread")]
async fn a_plain_kcp_packet_creates_a_session() {
    let _snmp = snmp_read();
    let (listener, _conn) = listener_without_monitor(None, 0, 0);
    let peer = addr_of("192.0.2.7:29900");

    input(&listener, &kcp_packet(0x1234_5678, 0, b"hello"), peer);

    assert_eq!(listener.session_count(), 1);
    let session = tokio::time::timeout(LIMIT, listener.accept())
        .await
        .expect("accept must not block")
        .expect("a session");
    assert_eq!(session.get_conv(), 0x1234_5678);
    assert_eq!(session.remote_addr(), peer);

    // The packet reached KCP: it is the first segment of the stream.
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(LIMIT, session.read(&mut buf))
        .await
        .expect("the payload must already be there")
        .expect("read");
    assert_eq!(&buf[..n], b"hello");

    listener.close().expect("close");
}

/// A FEC data packet carries the conv after the FEC header, and the sn after that, but only
/// once it is long enough to hold a whole KCP segment (`fecHeaderSizePlus2 + IKCP_OVERHEAD`).
/// A shorter one has no conv at all, so it cannot create a session.
// Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).packetInput() (`case typeData`)
#[tokio::test(flavor = "current_thread")]
async fn a_fec_data_packet_carries_the_conv_after_the_fec_header() {
    let _snmp = snmp_read();
    let (listener, _conn) = listener_without_monitor(None, 10, 3);
    let peer = addr_of("192.0.2.8:29900");

    // 8 + 24 - 1 bytes: one byte short of a conv.
    let short = fec_data_packet(0, 99, 0, b"");
    let short = &short[..FEC_HEADER_SIZE_PLUS2 + IKCP_OVERHEAD as usize - 1];
    assert!(short.len() >= MIN_PACKET_SIZE, "it passes the size check");
    input(&listener, short, peer);
    assert_eq!(listener.session_count(), 0, "no conv, no session");

    // Exactly 8 + 24 bytes: the shortest packet with a conv.
    let exact = fec_data_packet(0, 99, 0, b"");
    assert_eq!(exact.len(), FEC_HEADER_SIZE_PLUS2 + IKCP_OVERHEAD as usize);
    input(&listener, &exact, peer);
    assert_eq!(listener.session_count(), 1);
    assert_eq!(
        listener.session(peer).expect("session").get_conv(),
        99,
        "the conv comes from data[8..12]"
    );

    listener.close().expect("close");
}

/// A parity packet has no conv anywhere, so it can only be routed to a session that already owns
/// the address: it never creates one.
// Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).packetInput() (`case typeParity`)
#[tokio::test(flavor = "current_thread")]
async fn a_parity_packet_never_creates_a_session() {
    let _snmp = snmp_write();
    let (listener, _conn) = listener_without_monitor(None, 10, 3);
    let peer = addr_of("192.0.2.9:29900");

    let in_pkts = counter(&DEFAULT_SNMP.in_pkts);
    input(&listener, &fec_parity_packet(1, 64), peer);
    assert_eq!(listener.session_count(), 0, "no conv, nothing to create");
    assert_eq!(
        counter(&DEFAULT_SNMP.in_pkts),
        in_pkts,
        "a dropped packet never reaches kcp_input"
    );

    // With a session on that address the very same packet is delivered to it.
    input(&listener, &fec_data_packet(0, 4242, 0, b"x"), peer);
    assert_eq!(listener.session_count(), 1);
    let in_pkts = counter(&DEFAULT_SNMP.in_pkts);
    input(&listener, &fec_parity_packet(1, 64), peer);
    assert_eq!(
        counter(&DEFAULT_SNMP.in_pkts),
        in_pkts + 1,
        "the parity packet is fed to the session that owns the address"
    );

    listener.close().expect("close");
}

/// An OOB packet carries the conv right after the FEC header and has no sn at all, so Go's `sn`
/// stays 0, which makes a mismatching OOB packet a reset. Both halves are pinned here.
// Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).packetInput() (`case typeOOB`)
#[tokio::test(flavor = "current_thread")]
async fn an_oob_packet_carries_the_conv_after_the_fec_header() {
    let _snmp = snmp_read();
    let (listener, _conn) = listener_without_monitor(None, 10, 3);
    let peer = addr_of("192.0.2.11:29900");

    input(&listener, &oob_packet(7, b"ping"), peer);
    let first = listener
        .session(peer)
        .expect("an OOB packet creates a session");
    assert_eq!(first.get_conv(), 7);

    // The shortest OOB packet there is: header plus conv, no payload.
    let empty = oob_packet(7, b"");
    assert_eq!(empty.len(), MIN_PACKET_SIZE);
    input(&listener, &empty, peer);
    assert_eq!(listener.session_count(), 1, "same conv, same session");

    // Go leaves `sn` at 0 for OOB, so a different conv resets the session.
    input(&listener, &oob_packet(8, b"ping"), peer);
    let second = listener.session(peer).expect("a new session");
    assert_eq!(second.get_conv(), 8);
    assert!(first.is_closed(), "the old session was reset");

    listener.close().expect("close");
}

/// A packet that is not FEC-framed must still hold a whole KCP header, or it is dropped before
/// any conv is read. Below `min(IKCP_OVERHEAD, fecHeaderSizePlus2+convSize)` it never even gets
/// that far.
// Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).packetInput()
#[tokio::test(flavor = "current_thread")]
async fn a_short_packet_without_fec_framing_is_dropped() {
    let _snmp = snmp_read();
    let (listener, _conn) = listener_without_monitor(None, 0, 0);
    let peer = addr_of("192.0.2.12:29900");

    // Shorter than the minimum packet size (12 bytes).
    input(&listener, &kcp_packet(1, 0, b"")[..11], peer);
    // Long enough to be looked at, too short to be a KCP segment.
    input(&listener, &kcp_packet(1, 0, b"")[..23], peer);
    assert_eq!(listener.session_count(), 0);

    input(&listener, &kcp_packet(1, 0, b""), peer);
    assert_eq!(listener.session_count(), 1, "24 bytes are enough");

    listener.close().expect("close");
}

// ---------------------------------------------------------------------------------------------
// Demux: routing and the conv reset rule
// ---------------------------------------------------------------------------------------------

/// The rule of `docs/WIRE-FORMAT.md` §5: a packet whose conv does not match the session that
/// owns the address is dropped, unless `sn == 0`, which closes the old session and opens a new
/// one for the same peer.
// Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).packetInput()
#[tokio::test(flavor = "current_thread")]
async fn a_conv_mismatch_resets_the_session_only_when_sn_is_zero() {
    let _snmp = snmp_write();
    let (listener, _conn) = listener_without_monitor(None, 0, 0);
    let peer = addr_of("192.0.2.13:29900");

    input(&listener, &kcp_packet(100, 0, b"first"), peer);
    let first = listener.session(peer).expect("a session");
    assert_eq!(first.get_conv(), 100);

    // A different conv with sn != 0: dropped, and the old session survives untouched.
    let in_pkts = counter(&DEFAULT_SNMP.in_pkts);
    input(&listener, &kcp_packet(200, 1, b"stale"), peer);
    assert_eq!(
        counter(&DEFAULT_SNMP.in_pkts),
        in_pkts,
        "a mismatching packet is dropped, not fed to anybody"
    );
    assert!(!first.is_closed());
    assert_eq!(listener.session(peer).expect("session").get_conv(), 100);

    // The same conv with sn == 0: a reset.
    input(&listener, &kcp_packet(200, 0, b"reset"), peer);
    let second = listener.session(peer).expect("a new session");
    assert_eq!(second.get_conv(), 200);
    assert!(first.is_closed(), "the old session is closed by the reset");
    assert_eq!(listener.session_count(), 1, "one session per address");

    // Both sessions were queued for Accept, in order.
    let first_accepted = listener.accept().await.expect("the first session");
    let second_accepted = listener.accept().await.expect("the second session");
    assert_eq!(first_accepted.get_conv(), 100);
    assert_eq!(second_accepted.get_conv(), 200);

    listener.close().expect("close");
}

/// Two peers on one socket are two sessions, each fed only its own datagrams.
// Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).packetInput()
#[tokio::test(flavor = "current_thread")]
async fn packets_are_demultiplexed_by_remote_address() {
    let _snmp = snmp_read();
    let (listener, _conn) = listener_without_monitor(None, 0, 0);
    let a = addr_of("192.0.2.20:1000");
    let b = addr_of("192.0.2.21:1001");

    input(&listener, &kcp_packet(1, 0, b"a0"), a);
    input(&listener, &kcp_packet(2, 0, b"b0"), b);
    assert_eq!(listener.session_count(), 2);

    let sa = listener.session(a).expect("session a");
    let sb = listener.session(b).expect("session b");
    assert_ne!(sa.get_conv(), sb.get_conv());

    let mut buf = [0u8; 16];
    let n = sa.read(&mut buf).await.expect("read a");
    assert_eq!(&buf[..n], b"a0");
    let n = sb.read(&mut buf).await.expect("read b");
    assert_eq!(&buf[..n], b"b0");

    listener.close().expect("close");
}

/// Deviation V23, on by default: a datagram from an address the listener has never seen joins
/// the session that already holds its conv instead of opening a second one, and that session
/// keeps replying where it always did. This is what lets a peer send from more than one address.
// Deviation V23 (docs/DECISIONS.md)
#[tokio::test(flavor = "current_thread")]
async fn a_second_source_address_joins_the_session_holding_its_conv() {
    let _snmp = snmp_read();
    let (listener, _conn) = listener_without_monitor(None, 0, 0);
    let first = addr_of("192.0.2.20:1000");
    let second = addr_of("198.51.100.9:2000");

    input(&listener, &kcp_packet(7, 0, b"a0"), first);
    assert_eq!(listener.session_count(), 1);

    input(&listener, &kcp_packet(7, 1, b"a1"), second);
    assert_eq!(
        listener.session_count(),
        1,
        "the second address must not open a session of its own"
    );

    let session = listener.session(first).expect("the original session");
    assert_eq!(
        session.remote_addr(),
        first,
        "the listener keeps replying to the address the session was created for"
    );
    assert!(
        listener.session(second).is_none(),
        "the alias is a lookup, not a second map entry"
    );
    assert!(Arc::ptr_eq(
        &listener.session_by_conv(7).expect("the conv index"),
        &session
    ));

    let mut buf = [0u8; 16];
    let n = session.read(&mut buf).await.expect("read the first");
    assert_eq!(&buf[..n], b"a0");
    let n = session.read(&mut buf).await.expect("read the second");
    assert_eq!(&buf[..n], b"a1", "the second address's payload got through");

    listener.close().expect("close");
}

/// `-strictsource` puts Go's rule back: a new address is a new session, whatever conv it carries.
// Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).packetInput() (`l.sessions[addr.String()]`)
#[tokio::test(flavor = "current_thread")]
async fn strict_source_opens_a_session_per_address() {
    // The write guard: the policy is process-wide, so nothing else may run beside this.
    let _snmp = snmp_write();
    let _strict = crate::session::StrictSourceGuard::on();

    let (listener, _conn) = listener_without_monitor(None, 0, 0);
    let first = addr_of("192.0.2.20:1000");
    let second = addr_of("198.51.100.9:2000");

    input(&listener, &kcp_packet(7, 0, b"a0"), first);
    input(&listener, &kcp_packet(7, 0, b"a1"), second);

    assert_eq!(listener.session_count(), 2, "one session per address");
    assert_eq!(
        listener
            .session(second)
            .expect("the second session")
            .get_conv(),
        7
    );

    listener.close().expect("close");
}

/// The conv index does not outlive its session: once the session closes, the next packet with
/// that conv is a new conversation again, wherever it comes from.
// Deviation V23 (docs/DECISIONS.md)
#[tokio::test(flavor = "current_thread")]
async fn closing_a_session_drops_its_conv_alias() {
    let _snmp = snmp_read();
    let (listener, _conn) = listener_without_monitor(None, 0, 0);
    let first = addr_of("192.0.2.20:1000");
    let second = addr_of("198.51.100.9:2000");

    input(&listener, &kcp_packet(7, 0, b"a0"), first);
    let session = listener.session(first).expect("the session");
    session.close().expect("close the session");

    assert!(
        listener.session_by_conv(7).is_none(),
        "the alias goes with the session"
    );

    input(&listener, &kcp_packet(7, 0, b"b0"), second);
    assert_eq!(listener.session_count(), 1);
    let fresh = listener.session(second).expect("a new session");
    assert!(!Arc::ptr_eq(&fresh, &session));

    listener.close().expect("close");
}

/// The map is keyed by the canonical address, so the IPv4-mapped form a dual-stack socket
/// reports for an IPv4 peer is the same session. Go gets this for free: `net.UDPAddr.String()`
/// prints `::ffff:a.b.c.d` as `a.b.c.d`.
// Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).packetInput() (`l.sessions[addr.String()]`)
#[tokio::test(flavor = "current_thread")]
async fn an_ipv4_mapped_source_is_the_same_session() {
    let _snmp = snmp_read();
    let (listener, _conn) = listener_without_monitor(None, 0, 0);
    let mapped = addr_of("[::ffff:192.0.2.30]:29900");
    let plain = addr_of("192.0.2.30:29900");

    input(&listener, &kcp_packet(5, 0, b"one"), mapped);
    assert_eq!(listener.session_count(), 1);
    let session = listener.session(plain).expect("keyed by the IPv4 form");
    assert_eq!(session.remote_addr(), plain);

    // The same peer seen as plain IPv4 must not create a second session.
    input(&listener, &kcp_packet(5, 1, b"two"), plain);
    assert_eq!(listener.session_count(), 1);

    listener.close().expect("close");
}

/// `Accept` never hands out more than [`ACCEPT_BACKLOG`] pending sessions: once the queue is
/// full the packets that would create new ones are dropped, while the sessions already accepted
/// keep working.
// Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).packetInput() (`len(l.chAccepts) >= cap(...)`)
#[tokio::test(flavor = "current_thread")]
async fn the_accept_backlog_stops_new_sessions() {
    let _snmp = snmp_read();
    let (listener, _conn) = listener_without_monitor(None, 0, 0);

    for i in 0..ACCEPT_BACKLOG + 8 {
        let peer = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            10_000 + i as u16,
        );
        input(&listener, &kcp_packet(i as u32 + 1, 0, b"x"), peer);
    }

    assert_eq!(
        listener.session_count(),
        ACCEPT_BACKLOG,
        "the backlog caps the number of sessions a listener creates"
    );
    assert_eq!(listener.accepts().len(), ACCEPT_BACKLOG);

    // Draining one slot lets the next packet through.
    let first = listener.accept().await.expect("a session");
    assert_eq!(first.get_conv(), 1);
    let late = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)), 9_000);
    input(&listener, &kcp_packet(0xdead, 0, b"x"), late);
    assert_eq!(listener.session_count(), ACCEPT_BACKLOG + 1);
    assert_eq!(
        listener.session(late).expect("the late session").get_conv(),
        0xdead
    );

    listener.close().expect("close");
}

/// `Close` on an accepted session takes it out of the listener's map (Go's `closeSession`), so
/// the address is free again.
// Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).closeSession(), (*UDPSession).Close()
#[tokio::test(flavor = "current_thread")]
async fn closing_a_session_removes_it_from_the_listener() {
    let _snmp = snmp_read();
    let (listener, conn) = listener_without_monitor(None, 0, 0);
    let peer = addr_of("192.0.2.40:29900");

    input(&listener, &kcp_packet(3, 0, b"x"), peer);
    let session = listener.session(peer).expect("a session");

    assert!(listener.close_session(peer), "the entry was there");
    assert!(!listener.close_session(peer), "and only once");
    assert_eq!(listener.session_count(), 0);

    // A session's own Close goes through the same path and must not close the shared socket.
    input(&listener, &kcp_packet(4, 0, b"x"), peer);
    let second = listener.session(peer).expect("a new session");
    second.close().expect("close");
    assert_eq!(listener.session_count(), 0);
    assert!(
        !conn.closed.load(Ordering::SeqCst),
        "an accepted session shares the listener's socket and must not close it"
    );

    drop(session);
    listener.close().expect("close");
    assert!(conn.closed.load(Ordering::SeqCst), "the listener owns it");
}

// ---------------------------------------------------------------------------------------------
// Accept, deadlines and close
// ---------------------------------------------------------------------------------------------

/// `AcceptKCP` honours the deadline set by `SetReadDeadline`, with Go's exact error. Go reads the
/// deadline **once**, when the call starts, so changing it afterwards does not retime a blocked
/// `Accept`, unlike `UDPSession.Read`, which has a `RESET_TIMER` loop.
// Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).AcceptKCP(), (*Listener).SetReadDeadline()
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn accept_returns_timeout_after_the_read_deadline() {
    let _snmp = snmp_read();
    let (listener, _conn) = listener_without_monitor(None, 0, 0);

    // No deadline: the call blocks (checked by the timeout around it below).
    assert!(
        tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .is_err(),
        "without a deadline Accept waits forever"
    );

    listener
        .set_read_deadline(Some(Instant::now() + Duration::from_secs(1)))
        .expect("set_read_deadline");
    let accept = tokio::spawn({
        let listener = Arc::clone(&listener);
        async move { listener.accept().await.map(|_| ()) }
    });
    // Let the call start and read the deadline, then clear it: Go's quirk says it has no effect.
    tokio::time::sleep(Duration::from_millis(10)).await;
    listener
        .set_read_deadline(None)
        .expect("set_read_deadline(None)");

    let err = tokio::time::timeout(LIMIT, accept)
        .await
        .expect("the deadline must fire")
        .expect("the task must not panic")
        .expect_err("timeout");
    assert!(is_timeout(&err));
    assert_eq!(err.to_string(), timeout().to_string());

    // A deadline already in the past fires at once, and a fresh call sees the cleared deadline.
    listener
        .set_deadline(Some(Instant::now() - Duration::from_secs(1)))
        .expect("set_deadline");
    assert!(is_timeout(
        &listener
            .accept()
            .await
            .map(|_| ())
            .expect_err("already expired")
    ));

    listener.close().expect("close");
}

/// A listener never writes, so `SetWriteDeadline` is `invalid operation`; `SetDeadline` sets the
/// read deadline and swallows that error, as Go does.
// Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).SetWriteDeadline(), (*Listener).SetDeadline()
#[tokio::test(flavor = "current_thread")]
async fn set_write_deadline_is_an_invalid_operation() {
    let _snmp = snmp_read();
    let (listener, _conn) = listener_without_monitor(None, 0, 0);

    let err = listener
        .set_write_deadline(None)
        .expect_err("a listener never writes");
    assert_eq!(err.to_string(), "invalid operation");
    listener
        .set_deadline(None)
        .expect("SetDeadline returns nil");

    listener.close().expect("close");
}

/// `Close` is idempotent in effect but reports the second call, exactly like Go's `dieOnce`, and
/// it releases everybody blocked in `Accept` with `io.ErrClosedPipe`.
// Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).Close()
#[tokio::test(flavor = "current_thread")]
async fn close_wakes_accept_and_reports_the_second_call() {
    let _snmp = snmp_read();
    let (listener, conn) = listener_without_monitor(None, 0, 0);

    let accept = tokio::spawn({
        let listener = Arc::clone(&listener);
        async move { listener.accept().await.map(|_| ()) }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    listener.close().expect("the first close");
    assert!(listener.is_closed());
    assert!(conn.closed.load(Ordering::SeqCst), "an owned socket closes");

    let err = tokio::time::timeout(LIMIT, accept)
        .await
        .expect("the blocked accept must return")
        .expect("the task must not panic")
        .expect_err("closed");
    assert_eq!(err.to_string(), "io: read/write on closed pipe");

    let err = listener.close().expect_err("the second close");
    assert_eq!(err.to_string(), "io: read/write on closed pipe");
}

/// A listener built with `ServeConn` does not own its connection, so `Close` leaves the socket
/// open for the caller (Step 10's tcpraw).
// Go: kcp-go/v5@v5.6.66 sess.go:ServeConn(), (*Listener).Close()
#[tokio::test(flavor = "current_thread")]
async fn serve_conn_does_not_close_a_borrowed_socket() {
    let _snmp = snmp_read();
    let conn = Arc::new(FakeConn::default());
    let listener = Listener::serve_conn(None, 0, 0, Arc::clone(&conn) as Arc<dyn PacketConn>)
        .expect("the listener must build");

    listener.close().expect("close");
    assert!(
        !conn.closed.load(Ordering::SeqCst),
        "the caller owns the connection"
    );
}

/// A shard count no codec can serve (Deviation V07) is refused once, when the listener is built,
/// so that [`Listener::packet_input`] can never fail to create a session. Go's `newUDPSession`
/// cannot fail, and its `ServeConn` returns `(*Listener, error)` all the same.
// Go: kcp-go/v5@v5.6.66 sess.go:ServeConn()
#[tokio::test(flavor = "current_thread")]
async fn an_impossible_shard_count_is_refused_when_the_listener_is_built() {
    let _snmp = snmp_read();
    let conn = Arc::new(FakeConn::default());
    let err = Listener::serve_conn(None, 300, 300, Arc::clone(&conn) as Arc<dyn PacketConn>)
        .err()
        .expect("V07: > 256 shards");
    assert_eq!(
        err.to_string(),
        "cannot create Encoder with more than 256 data+parity shards"
    );
    assert!(
        !conn.closed.load(Ordering::SeqCst),
        "the caller's connection is left alone"
    );
}

/// Closing the listener stops the monitor and hands every session the same
/// `use of closed network connection` Go's failing `ReadFrom` reports, which releases their
/// blocked readers.
// Go: kcp-go/v5@v5.6.66 readloop.go:(*Listener).defaultMonitor(),
// sess.go:(*Listener).notifyReadError()
#[tokio::test(flavor = "current_thread")]
async fn closing_the_listener_propagates_to_its_sessions() {
    let _snmp = snmp_read();
    let conn = Arc::new(FakeConn::default());
    let listener = Listener::start(ListenerConfig {
        block: None,
        data_shards: 0,
        parity_shards: 0,
        conn: Arc::clone(&conn) as Arc<dyn PacketConn>,
        own_conn: true,
        pool: BufferPool::new(64),
        clock: SystemClock,
    })
    .expect("the listener must build");
    // The monitor is parked in `recv_batch`.
    wait_for("the monitor to start reading", || {
        conn.recvs.load(Ordering::SeqCst) > 0
    })
    .await;

    let peer = addr_of("192.0.2.50:29900");
    input(&listener, &kcp_packet(6, 0, b""), peer);
    let session = listener.session(peer).expect("a session");

    let reader = tokio::spawn({
        let session = Arc::clone(&session);
        async move {
            let mut buf = [0u8; 64];
            session.read(&mut buf).await.map(|_| ())
        }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    listener.close().expect("close");

    let err = tokio::time::timeout(LIMIT, reader)
        .await
        .expect("the blocked read must return")
        .expect("the task must not panic")
        .expect_err("the socket is gone");
    assert_eq!(err.to_string(), "use of closed network connection");
    assert_eq!(
        listener
            .read_error()
            .io_error()
            .expect("recorded")
            .to_string(),
        "use of closed network connection"
    );
    // The session itself is not closed by the listener; Go leaves it in the map too.
    assert!(!session.is_closed());
    assert_eq!(listener.session_count(), 1);
}

/// Go's `notifyReadError`: a failing socket ends the monitor, is recorded once, and is handed to
/// every session the listener holds.
// Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).notifyReadError()
#[tokio::test(flavor = "current_thread")]
async fn a_socket_read_error_reaches_every_session() {
    let _snmp = snmp_read();
    let conn = Arc::new(FakeConn::default());
    let listener = Listener::start(ListenerConfig {
        block: None,
        data_shards: 0,
        parity_shards: 0,
        conn: Arc::clone(&conn) as Arc<dyn PacketConn>,
        own_conn: true,
        pool: BufferPool::new(64),
        clock: SystemClock,
    })
    .expect("the listener must build");
    wait_for("the monitor to start reading", || {
        conn.recvs.load(Ordering::SeqCst) > 0
    })
    .await;

    let a = addr_of("192.0.2.60:1");
    let b = addr_of("192.0.2.61:2");
    input(&listener, &kcp_packet(1, 0, b""), a);
    input(&listener, &kcp_packet(2, 0, b""), b);
    let sa = listener.session(a).expect("session a");
    let sb = listener.session(b).expect("session b");
    // Drain the backlog: `accept` hands out a queued session before it looks at the error slot.
    for _ in 0..2 {
        listener.accept().await.expect("a queued session");
    }

    conn.fail();

    wait_for("the error to reach both sessions", || {
        sa.read_error().is_set() && sb.read_error().is_set()
    })
    .await;
    for session in [&sa, &sb] {
        let err = session.read_error().io_error().expect("recorded");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(err.to_string(), "connection reset by peer");
    }

    // A blocked Accept is released with the same error, and it stays the recorded one.
    let err = tokio::time::timeout(LIMIT, listener.accept())
        .await
        .expect("accept must return")
        .map(|_| ())
        .expect_err("the socket error");
    assert_eq!(err.to_string(), "connection reset by peer");

    listener.notify_read_error(io::Error::other("later"));
    assert_eq!(
        listener
            .read_error()
            .io_error()
            .expect("recorded")
            .to_string(),
        "connection reset by peer",
        "the first error wins (socketReadErrorOnce)"
    );

    listener.close().expect("close");
}

/// Go's `socketReadErrorOnce`: the first error recorded wins and every later one is ignored.
///
/// A session created after the error is not notified, but the monitor has already returned by
/// then, so no such session can appear: Go behaves the same way.
// Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).notifyReadError()
#[tokio::test(flavor = "current_thread")]
async fn the_listener_records_the_read_error_once() {
    let _snmp = snmp_read();
    let (listener, _conn) = listener_without_monitor(None, 0, 0);

    listener.notify_read_error(io::Error::new(io::ErrorKind::TimedOut, "first"));
    listener.notify_read_error(io::Error::other("second"));
    let err = listener.read_error().io_error().expect("recorded");
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert_eq!(err.to_string(), "first");

    listener.close().expect("close");
}

// ---------------------------------------------------------------------------------------------
// Socket options and addresses
// ---------------------------------------------------------------------------------------------

/// The listener's option setters go straight to the shared socket; unlike `UDPSession`'s they
/// take no lock, Go's `Listener` having no `mu`.
// Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).SetReadBuffer(), SetWriteBuffer(), SetDSCP(), Addr()
#[tokio::test(flavor = "current_thread")]
async fn the_option_setters_reach_the_socket() {
    let _snmp = snmp_read();
    let (listener, conn) = listener_without_monitor(None, 0, 0);

    listener.set_read_buffer(1 << 20).expect("set_read_buffer");
    listener
        .set_write_buffer(1 << 21)
        .expect("set_write_buffer");
    listener.set_dscp(46).expect("set_dscp");
    assert_eq!(
        conn.options(),
        vec![
            ("read_buffer", 1 << 20),
            ("write_buffer", 1 << 21),
            ("dscp", 46)
        ]
    );
    assert_eq!(listener.addr().expect("addr"), loopback(29900));

    // An accepted session shares that socket, so Go refuses the per-session setters on it.
    let peer = addr_of("192.0.2.70:29900");
    input(&listener, &kcp_packet(8, 0, b""), peer);
    let session = listener.session(peer).expect("a session");
    for err in [
        session.set_dscp(46).expect_err("dscp"),
        session.set_read_buffer(1 << 20).expect_err("read buffer"),
        session.set_write_buffer(1 << 20).expect_err("write buffer"),
    ] {
        assert_eq!(err.to_string(), "invalid operation");
    }
    assert_eq!(conn.options().len(), 3, "and nothing reached the socket");

    listener.close().expect("close");
}

// ---------------------------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------------------------

/// Every session a listener creates is a `PassiveOpens`, not an `ActiveOpens`, and it moves
/// `CurrEstab`/`MaxConn` like any other. Closing it gives `CurrEstab` back.
// Go: kcp-go/v5@v5.6.66 sess.go:newUDPSession()
#[tokio::test(flavor = "current_thread")]
async fn accepted_sessions_count_as_passive_opens() {
    let _snmp = snmp_write();
    let (listener, _conn) = listener_without_monitor(None, 0, 0);

    let passive = counter(&DEFAULT_SNMP.passive_opens);
    let active = counter(&DEFAULT_SNMP.active_opens);
    let estab = counter(&DEFAULT_SNMP.curr_estab);

    let a = addr_of("192.0.2.80:1");
    let b = addr_of("192.0.2.81:2");
    input(&listener, &kcp_packet(1, 0, b""), a);
    input(&listener, &kcp_packet(2, 0, b""), b);

    assert_eq!(counter(&DEFAULT_SNMP.passive_opens) - passive, 2);
    assert_eq!(counter(&DEFAULT_SNMP.active_opens), active);
    assert_eq!(counter(&DEFAULT_SNMP.curr_estab) - estab, 2);
    assert!(counter(&DEFAULT_SNMP.max_conn) >= counter(&DEFAULT_SNMP.curr_estab));

    // The reset rule closes one session and opens another: +1 passive open, CurrEstab unchanged.
    input(&listener, &kcp_packet(3, 0, b""), a);
    assert_eq!(counter(&DEFAULT_SNMP.passive_opens) - passive, 3);
    assert_eq!(counter(&DEFAULT_SNMP.curr_estab) - estab, 2);

    listener.session(a).expect("a").close().expect("close a");
    listener.session(b).expect("b").close().expect("close b");
    assert_eq!(counter(&DEFAULT_SNMP.curr_estab), estab);

    listener.close().expect("close");
}

/// A packet that fails its integrity check never reaches the demux, so it creates no session,
/// the listener decrypts with its own copy of the cipher, exactly as a session does.
// Go: kcp-go/v5@v5.6.66 sess.go:(*Listener).packetInput() (the `switch block`)
#[tokio::test(flavor = "current_thread")]
async fn a_corrupt_packet_creates_no_session() {
    let _snmp = snmp_write();
    let (listener, _conn) = listener_without_monitor(Some(aes_crypt()), 0, 0);
    let peer = addr_of("192.0.2.90:29900");

    let csum = counter(&DEFAULT_SNMP.in_csum_errors);
    // 32 bytes of noise: long enough for the crypto header, wrong in every other way.
    input(&listener, &payload(1, 32), peer);
    assert_eq!(listener.session_count(), 0);
    assert_eq!(counter(&DEFAULT_SNMP.in_csum_errors) - csum, 1);

    listener.close().expect("close");
}

// ---------------------------------------------------------------------------------------------
// End to end
// ---------------------------------------------------------------------------------------------

/// The whole server side over a real socket: two dialled clients, one listener, AES-CFB and
/// FEC(10,3). Each client's messages come back from its own accepted session, which proves the
/// demux, the shared tx socket and the missing read loop all work together.
// Go: kcp-go/v5@v5.6.66 sess.go:ListenWithOptions(), AcceptKCP(), DialWithOptions()
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_clients_multiplexed_over_one_socket() {
    let _snmp = snmp_read();

    let listener =
        Listener::listen_with_options("127.0.0.1:0", Some(aes_crypt()), 10, 3).expect("listen");
    let server_addr = listener.addr().expect("the listener address");

    // Go's `for { conn, _ := l.AcceptKCP(); go echo(conn) }`.
    let server = tokio::spawn({
        let listener = Arc::clone(&listener);
        async move {
            while let Ok(session) = listener.accept().await {
                // kcptun's default `-mode fast`.
                session.set_no_delay(0, 30, 2, 1);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    while let Ok(n) = session.read(&mut buf).await {
                        if session.write(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                });
            }
        }
    });

    let mut clients = Vec::new();
    for _ in 0..2 {
        let client =
            UdpSession::dial_with_options(&server_addr.to_string(), Some(aes_crypt()), 10, 3)
                .expect("dial");
        client.set_no_delay(0, 30, 2, 1);
        clients.push(client);
    }

    let mut buf = vec![0u8; 4096];
    for round in 0..4u8 {
        for (i, client) in clients.iter().enumerate() {
            let msg = payload(round.wrapping_add(i as u8 * 33), 1000);
            assert_eq!(client.write(&msg).await.expect("write"), msg.len());
            let n = tokio::time::timeout(LIMIT, client.read(&mut buf))
                .await
                .expect("the echo must come back")
                .expect("read");
            assert_eq!(&buf[..n], &msg[..], "client {i}, round {round}");
        }
    }

    assert_eq!(
        listener.session_count(),
        2,
        "one session per client address"
    );

    for client in &clients {
        client.close().expect("close the client");
    }
    listener.close().expect("close the listener");
    server.abort();
}

/// A `Monitor` whose listener has been dropped retires instead of keeping it alive, the same
/// choice `ReadLoop` makes (note 165).
#[tokio::test(flavor = "current_thread")]
async fn the_monitor_does_not_keep_the_listener_alive() {
    let _snmp = snmp_read();
    let conn = Arc::new(FakeConn::default());
    let listener = Listener::start(ListenerConfig {
        block: None,
        data_shards: 0,
        parity_shards: 0,
        conn: Arc::clone(&conn) as Arc<dyn PacketConn>,
        own_conn: true,
        pool: BufferPool::new(64),
        clock: SystemClock,
    })
    .expect("the listener must build");
    let weak = Arc::downgrade(&listener);
    wait_for("the monitor to start reading", || {
        conn.recvs.load(Ordering::SeqCst) > 0
    })
    .await;

    drop(listener);
    assert!(weak.upgrade().is_none(), "the monitor holds only a Weak");

    // And the task leaves as soon as its receive returns.
    conn.fail();
    wait_for("the monitor to retire", || Arc::strong_count(&conn) == 1).await;
    assert!(conn.sent().is_empty(), "a monitor never transmits");
}
