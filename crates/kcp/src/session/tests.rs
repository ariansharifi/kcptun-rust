//! Tests of the input pipeline (05.3): every packet the 05.2 tx pipeline produces is fed back
//! into a peer session through [`UdpSession::packet_input`], so the two halves are checked
//! against each other over a fake [`PacketConn`] that captures datagrams instead of sending
//! them.
//!
//! `DEFAULT_SNMP` is process-global, so every test that moves a counter holds `SNMP_TEST_LOCK`
//! (the convention from 03.3), and the ones that assert exact deltas hold it for writing. Each
//! test runs its own current-thread runtime, so keeping the guard across the awaits of one test
//! body cannot deadlock.
#![allow(
    clippy::await_holding_lock,
    reason = "SNMP_TEST_LOCK serialises whole test bodies; see above"
)]

use std::future;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::time::Duration;

use kcptun_testkit::VirtualClock;

use super::*;
use crate::crypt::{
    AeadCrypt, new_aes_block_crypt, new_aes_gcm_crypt, new_none_block_crypt,
    new_salsa20_block_crypt,
};
use crate::fec::{FEC_HEADER_SIZE, OOB_SEQID};
use crate::kcp::{IKCP_FLUSH_FULL, IKCP_RTO_DEF, SNMP_TEST_LOCK};
use crate::packet_conn::{BoxFuture, RecvBatch, TxMsg, invalid_operation};

/// Every session test talks to this peer.
const REMOTE: &str = "192.0.2.10:29900";

/// Longest a test waits for the tx pipeline to catch up.
const LIMIT: Duration = Duration::from_secs(20);

fn remote() -> SocketAddr {
    REMOTE.parse().expect("literal address")
}

fn snmp_read() -> std::sync::RwLockReadGuard<'static, ()> {
    SNMP_TEST_LOCK.read().unwrap_or_else(|e| e.into_inner())
}

fn snmp_write() -> std::sync::RwLockWriteGuard<'static, ()> {
    SNMP_TEST_LOCK.write().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

/// A deterministic [`Clock`] both peers share, so the FEC encoder always sees a continuous
/// stream (no wall-clock gap can skip a parity group on a slow machine).
#[derive(Clone)]
struct TestClock(VirtualClock);

impl TestClock {
    fn new() -> TestClock {
        TestClock(VirtualClock::new())
    }
}

impl Clock for TestClock {
    fn now_ms(&self) -> u32 {
        self.0.now_ms()
    }
}

/// A [`PacketConn`] that records what a session sends instead of putting it on the wire.
#[derive(Debug, Default)]
struct CaptureConn {
    packets: StdMutex<Vec<Vec<u8>>>,
    /// Makes `send_batch` fail, so that the tx task fills the session's write-error slot.
    fail_sends: AtomicBool,
    /// Set by `close()`, to check that a dialled session closes its own socket.
    closed: AtomicBool,
    /// How often an option setter was called, with the value.
    options: StdMutex<Vec<(&'static str, i64)>>,
}

impl CaptureConn {
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Vec<u8>>> {
        self.packets.lock().unwrap_or_else(|e| e.into_inner())
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

    fn count(&self) -> usize {
        self.lock().len()
    }

    /// Removes and returns everything captured so far.
    fn take(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.lock())
    }

    async fn wait_for(&self, n: usize) {
        let wait = async {
            while self.count() < n {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        };
        tokio::time::timeout(LIMIT, wait)
            .await
            .unwrap_or_else(|_| panic!("only {} of {n} packets were sent", self.count()));
    }
}

impl PacketConn for CaptureConn {
    fn recv_batch<'a>(&'a self, _batch: &'a mut RecvBatch) -> BoxFuture<'a, io::Result<usize>> {
        // The read loop is 05.6; these tests feed `packet_input` by hand.
        Box::pin(future::pending())
    }

    fn send_batch<'a>(&'a self, msgs: &'a [TxMsg<'a>]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async move {
            if self.fail_sends.load(Ordering::Relaxed) {
                return Err(io::Error::new(io::ErrorKind::HostUnreachable, "no route"));
            }
            let mut packets = self.lock();
            for msg in msgs {
                packets.push(msg.data.to_vec());
            }
            Ok(msgs.len())
        })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok("127.0.0.1:1".parse().expect("literal address"))
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

/// A stand-in for the 05.7 listener: records the sessions closed through it.
#[derive(Debug, Default)]
struct StubListener {
    closed: StdMutex<Vec<SocketAddr>>,
}

impl SessionOwner for StubListener {
    fn close_session(&self, remote: SocketAddr) -> bool {
        self.closed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(remote);
        true
    }
}

/// One session plus the socket that captures its outgoing datagrams.
struct Peer {
    session: Arc<UdpSession<TestClock>>,
    conn: Arc<CaptureConn>,
    die: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
    /// The 05.5 update task, spawned on demand by [`Peer::start_updater`].
    update: Option<tokio::task::JoinHandle<()>>,
}

impl Peer {
    fn start(
        conv: u32,
        block: Option<PacketCrypt>,
        fec: Option<(isize, isize)>,
        clock: &TestClock,
    ) -> Peer {
        Peer::start_with(conv, block, fec, clock, None)
    }

    /// A session that a listener accepted: `l != nil`, and the socket is not its own.
    ///
    /// The caller keeps `listener` alive, the session only holding a [`Weak`] to it.
    fn start_accepted(conv: u32, clock: &TestClock, listener: &Arc<StubListener>) -> Peer {
        let owner: Arc<dyn SessionOwner> = Arc::clone(listener) as Arc<dyn SessionOwner>;
        Peer::start_with(conv, None, None, clock, Some(Arc::downgrade(&owner)))
    }

    fn start_with(
        conv: u32,
        block: Option<PacketCrypt>,
        fec: Option<(isize, isize)>,
        clock: &TestClock,
        listener: Option<Weak<dyn SessionOwner>>,
    ) -> Peer {
        let conn = Arc::new(CaptureConn::default());
        let die = CancellationToken::new();
        let (data_shards, parity_shards) = fec.unwrap_or((0, 0));
        let own_conn = listener.is_none();
        let (session, pipeline) = UdpSession::new(SessionConfig {
            conv,
            data_shards,
            parity_shards,
            conn: Arc::clone(&conn) as Arc<dyn PacketConn>,
            own_conn,
            listener,
            remote: remote(),
            block,
            pool: BufferPool::new(4096),
            clock: clock.clone(),
            die: die.clone(),
        })
        .expect("a default session always fits the MTU");
        {
            let mut state = session.lock();
            // Go's default is false, where the per-session update task flushes the ack list.
            // Most tests here drive `flush` by hand and never start that task, so without
            // `-acknodelay` (which kcptun exposes as a flag) nothing would ever flush the acks.
            // Tests that do start one via `Peer::start_updater` may set this back to `false`.
            state.ack_no_delay = true;
            // kcptun's default `-mode fast`: nodelay=0, interval=30, resend=2, nc=1. `nc=1`
            // (no congestion window) matters here because `flush` only raises `cwnd` from 0 to
            // 1 at its very end, so the first flush of a fresh session would otherwise send
            // nothing.
            assert_eq!(state.kcp.nodelay(0, 30, 2, 1), 0);
        }
        Peer {
            session,
            conn,
            die,
            task: Some(tokio::spawn(pipeline.run())),
            update: None,
        }
    }

    /// Starts the per-session update task, which Go schedules inside `newUDPSession`.
    // Go: kcp-go/v5@v5.6.66 sess.go:newUDPSession() (`SystemTimedSched.Put(sess.update, now)`)
    fn start_updater(&mut self) {
        assert!(self.update.is_none(), "one update task per session");
        self.update = Some(tokio::spawn(self.session.updater().run()));
    }

    /// How often `flush()` has run on this session (every caller, not just the updater).
    fn flushes(&self) -> usize {
        self.session.lock().kcp.flush_calls.len()
    }

    /// The flush types of every recorded `flush()` call.
    fn flush_types(&self) -> Vec<crate::kcp::FlushType> {
        self.session
            .lock()
            .kcp
            .flush_calls
            .iter()
            .map(|call| call.flush_type)
            .collect()
    }

    /// Queues `data` as one KCP message and flushes it, which drives the output callback.
    fn send(&self, data: &[u8]) {
        let mut state = self.session.lock();
        assert_eq!(state.kcp.send(data), 0, "kcp.send must accept the payload");
        state.kcp.flush(IKCP_FLUSH_FULL);
    }

    /// The next complete message KCP has for the application (05.4's `Read`, by hand).
    fn recv(&self) -> Option<Vec<u8>> {
        let mut state = self.session.lock();
        let size = state.kcp.peek_size();
        if size <= 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        assert_eq!(state.kcp.recv(&mut buf), size);
        Some(buf)
    }

    /// Everything still queued for the application.
    fn drain(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(msg) = self.recv() {
            out.push(msg);
        }
        out
    }

    /// Waits until the tx pipeline has emitted `n` datagrams, then takes them.
    async fn take(&self, n: usize) -> Vec<Vec<u8>> {
        self.conn.wait_for(n).await;
        self.conn.take()
    }

    async fn shutdown(&mut self) {
        self.die.cancel();
        if let Some(task) = self.update.take() {
            tokio::time::timeout(LIMIT, task)
                .await
                .expect("the update task must exit on die")
                .expect("the update task must not panic");
        }
        if let Some(task) = self.task.take() {
            tokio::time::timeout(LIMIT, task)
                .await
                .expect("the tx task must exit on die")
                .expect("the tx task must not panic");
        }
    }
}

/// Feeds datagrams into a session the way the read loop (05.6) will.
fn deliver(to: &Peer, packets: &[Vec<u8>]) {
    for packet in packets {
        let mut packet = packet.clone();
        to.session.packet_input(&mut packet);
    }
}

/// Lets `from`'s tx task drain everything it has queued, then delivers the datagrams to `to`.
///
/// Used where the number of datagrams is not obvious (FEC parity arrives in bursts); the tests
/// with a known count use [`Peer::take`] instead.
async fn pump(from: &Peer, to: &Peer) -> usize {
    let drained = async {
        // Two consecutive idle turns: the first says the channel is empty, the second that the
        // batch the task had already taken has reached the socket.
        let mut idle = 0;
        while idle < 2 {
            tokio::time::sleep(Duration::from_millis(1)).await;
            idle = if from.session.tx().queued() == 0 {
                idle + 1
            } else {
                0
            };
        }
    };
    tokio::time::timeout(LIMIT, drained)
        .await
        .expect("the tx task must drain its channel");
    let packets = from.conn.take();
    deliver(to, &packets);
    packets.len()
}

/// `len` bytes with a recognisable pattern.
fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
}

fn aes_crypt() -> PacketCrypt {
    PacketCrypt::Block(new_aes_block_crypt(&[7u8; 32]).expect("aes-256 key"))
}

fn none_crypt() -> PacketCrypt {
    PacketCrypt::Block(new_none_block_crypt(&[]).expect("none cipher"))
}

fn salsa20_crypt() -> PacketCrypt {
    PacketCrypt::Block(new_salsa20_block_crypt(&[3u8; 32]).expect("salsa20 key"))
}

fn gcm_crypt() -> PacketCrypt {
    new_aes_gcm_crypt(&[9u8; 16]).expect("aes-128-gcm key")
}

// ---------------------------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------------------------

/// Go's `newUDPSession` header arithmetic: crypto header, plus `fecHeaderSizePlus2` when FEC is
/// on, and `SetMtu(IKCP_MTU_DEF)` takes the AEAD tag off the KCP MTU as well.
// Go: kcp-go/v5@v5.6.66 sess.go:newUDPSession() / SetMtu()
#[tokio::test(flavor = "current_thread")]
async fn header_size_and_mtu_follow_the_crypt_and_fec_settings() {
    let _snmp = snmp_read();
    let clock = TestClock::new();

    let mut plain = Peer::start(1, None, None, &clock);
    assert_eq!(plain.session.header_size(), 0);
    assert!(!plain.session.fec_enabled());
    assert_eq!(plain.session.lock().kcp.mtu, IKCP_MTU_DEF);

    let mut cfb = Peer::start(1, Some(aes_crypt()), Some((10, 3)), &clock);
    assert_eq!(
        cfb.session.header_size(),
        CRYPT_HEADER_SIZE + FEC_HEADER_SIZE_PLUS2
    );
    assert!(cfb.session.fec_enabled());
    assert_eq!(
        cfb.session.lock().kcp.mtu,
        IKCP_MTU_DEF - (CRYPT_HEADER_SIZE + FEC_HEADER_SIZE_PLUS2) as u32
    );

    let mut aead = Peer::start(1, Some(gcm_crypt()), None, &clock);
    assert_eq!(aead.session.header_size(), AeadCrypt::NONCE);
    assert_eq!(
        aead.session.lock().kcp.mtu,
        IKCP_MTU_DEF - (AeadCrypt::NONCE + AeadCrypt::OVERHEAD) as u32
    );

    plain.shutdown().await;
    cfb.shutdown().await;
    aead.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// Round trip: tx pipeline (05.2) -> packet_input -> kcp_input
// ---------------------------------------------------------------------------------------------

/// Sends one message from `a` to `b` through the real tx pipeline and the real input pipeline.
async fn round_trip(block: Option<PacketCrypt>, fec: Option<(isize, isize)>) {
    let clock = TestClock::new();
    let mut a = Peer::start(0x1234_5678, block.clone(), fec, &clock);
    let mut b = Peer::start(0x1234_5678, block, fec, &clock);

    let data = payload(1, 300);
    a.send(&data);
    let packets = a.take(1).await;
    assert_eq!(packets.len(), 1, "one KCP segment, one datagram");
    deliver(&b, &packets);

    assert_eq!(b.recv().as_deref(), Some(data.as_slice()));

    // The ACK travels back the same way and retires the segment from the send buffer.
    let acks = b.take(1).await;
    deliver(&a, &acks);
    assert_eq!(a.session.lock().kcp.wait_snd(), 0, "the segment was acked");

    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn round_trip_null_crypt() {
    let _snmp = snmp_read();
    round_trip(None, None).await;
}

#[tokio::test(flavor = "current_thread")]
async fn round_trip_cfb_crypt() {
    let _snmp = snmp_read();
    round_trip(Some(aes_crypt()), None).await;
}

#[tokio::test(flavor = "current_thread")]
async fn round_trip_salsa20_crypt() {
    let _snmp = snmp_read();
    round_trip(Some(salsa20_crypt()), None).await;
}

#[tokio::test(flavor = "current_thread")]
async fn round_trip_none_crypt_keeps_the_crc_header() {
    let _snmp = snmp_read();
    round_trip(Some(none_crypt()), None).await;
}

#[tokio::test(flavor = "current_thread")]
async fn round_trip_aead_crypt() {
    let _snmp = snmp_read();
    round_trip(Some(gcm_crypt()), None).await;
}

#[tokio::test(flavor = "current_thread")]
async fn round_trip_with_fec() {
    let _snmp = snmp_read();
    round_trip(Some(aes_crypt()), Some((10, 3))).await;
}

#[tokio::test(flavor = "current_thread")]
async fn round_trip_aead_with_fec() {
    let _snmp = snmp_read();
    round_trip(Some(gcm_crypt()), Some((10, 3))).await;
}

// ---------------------------------------------------------------------------------------------
// FEC demux and recovery
// ---------------------------------------------------------------------------------------------

/// A complete FEC group with one data shard lost: the parity shards rebuild it and the
/// recovered packet reaches KCP as `IKCP_PACKET_FEC`, so the application sees all three
/// messages.
// Go: kcp-go/v5@v5.6.66 sess.go:kcpInput() (`s.fecDecoder.decode` and the `r[2:sz]` loop)
#[tokio::test(flavor = "current_thread")]
async fn fec_recovers_a_lost_data_shard() {
    let _snmp = snmp_write();
    let before = DEFAULT_SNMP.fec_recovered.load(Ordering::Relaxed);
    let clock = TestClock::new();
    let mut a = Peer::start(7, Some(aes_crypt()), Some((3, 2)), &clock);
    let mut b = Peer::start(7, Some(aes_crypt()), Some((3, 2)), &clock);

    // Three messages of different lengths, so the group's shards need zero padding.
    let msgs = [payload(1, 300), payload(2, 60), payload(3, 180)];
    for msg in &msgs {
        a.send(msg);
    }
    // 3 data shards + 2 parity shards.
    let packets = a.take(5).await;
    assert_eq!(packets.len(), 5);

    // Every datagram carries the FEC header; the first three are data, the last two parity.
    let fec_type = |pkt: &[u8], block: &PacketCrypt| {
        let mut copy = pkt.to_vec();
        block.as_block().expect("cfb").decrypt(&mut copy);
        let hdr = CRYPT_HEADER_SIZE + FEC_HEADER_SIZE - 2;
        u16::from_le_bytes([copy[hdr], copy[hdr + 1]])
    };
    let aes = aes_crypt();
    let types: Vec<u16> = packets.iter().map(|p| fec_type(p, &aes)).collect();
    assert_eq!(
        types,
        vec![TYPE_DATA, TYPE_DATA, TYPE_DATA, TYPE_PARITY, TYPE_PARITY]
    );

    // The middle data shard never arrives.
    let delivered: Vec<Vec<u8>> = packets
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, p)| p.clone())
        .collect();
    deliver(&b, &delivered);

    assert_eq!(b.drain(), msgs.to_vec(), "the lost message was recovered");
    assert!(
        DEFAULT_SNMP.fec_recovered.load(Ordering::Relaxed) > before,
        "FECRecovered must move"
    );

    a.shutdown().await;
    b.shutdown().await;
}

/// A session created without FEC still demuxes FEC packets: Go lazily builds a `(1, 1)`
/// decoder the first time one arrives, and feeds the data shards to KCP.
// Go: kcp-go/v5@v5.6.66 sess.go:kcpInput() (`if s.fecDecoder == nil { newFECDecoder(1, 1) }`)
#[tokio::test(flavor = "current_thread")]
async fn a_session_without_fec_creates_a_decoder_lazily() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(11, None, Some((10, 3)), &clock);
    let mut b = Peer::start(11, None, None, &clock);

    assert!(b.session.lock().fec_decoder.is_none());

    let data = payload(5, 128);
    a.send(&data);
    let packets = a.take(1).await;
    deliver(&b, &packets);

    {
        let state = b.session.lock();
        let decoder = state.fec_decoder.as_ref().expect("lazily created");
        assert_eq!((decoder.data_shards(), decoder.parity_shards()), (1, 1));
    }
    assert_eq!(b.recv().as_deref(), Some(data.as_slice()));

    a.shutdown().await;
    b.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// Out-of-band packets
// ---------------------------------------------------------------------------------------------

/// Queues an OOB packet (`| conv (4B) | payload |` after the session's header space).
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SendOOB()
fn send_oob(peer: &Peer, payload: &[u8]) {
    peer.session
        .send_oob(payload)
        .expect("FEC is enabled and the payload fits one packet");
}

/// An OOB packet is counted, never reaches KCP, and its payload is handed to the registered
/// callback with the FEC header and the conv stripped.
// Go: kcp-go/v5@v5.6.66 sess.go:kcpInput() (`case typeOOB`)
#[tokio::test(flavor = "current_thread")]
async fn oob_packets_reach_the_handler() {
    let _snmp = snmp_write();
    let before = DEFAULT_SNMP.oob_packets.load(Ordering::Relaxed);
    let clock = TestClock::new();
    let mut a = Peer::start(21, Some(aes_crypt()), Some((10, 3)), &clock);
    let mut b = Peer::start(21, Some(aes_crypt()), Some((10, 3)), &clock);

    let seen = Arc::new(StdMutex::new(Vec::<Vec<u8>>::new()));
    let sink = Arc::clone(&seen);
    b.session
        .set_oob_handler(Some(Arc::new(move |data: &[u8]| {
            sink.lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(data.to_vec());
        })))
        .expect("FEC is enabled");

    let oob = payload(9, 40);
    send_oob(&a, &oob);
    let packets = a.take(1).await;

    // The OOB packet carries the reserved seqid and the OOB type, and is not FEC-protected.
    {
        let mut plain = packets[0].clone();
        aes_crypt().as_block().expect("cfb").decrypt(&mut plain);
        let fec = &plain[CRYPT_HEADER_SIZE..];
        assert_eq!(
            u32::from_le_bytes(fec[..4].try_into().expect("4")),
            OOB_SEQID
        );
        assert_eq!(u16::from_le_bytes([fec[4], fec[5]]), TYPE_OOB);
    }

    deliver(&b, &packets);

    assert_eq!(
        *seen.lock().unwrap_or_else(|e| e.into_inner()),
        vec![oob.clone()]
    );
    assert_eq!(
        DEFAULT_SNMP.oob_packets.load(Ordering::Relaxed) - before,
        1,
        "OOBPackets"
    );
    assert_eq!(b.recv(), None, "OOB never reaches the KCP stream");

    a.shutdown().await;
    b.shutdown().await;
}

/// Without a handler the packet is still counted and dropped (Go's `callbackForOOB` is nil).
#[tokio::test(flavor = "current_thread")]
async fn oob_without_a_handler_is_only_counted() {
    let _snmp = snmp_write();
    let before = DEFAULT_SNMP.oob_packets.load(Ordering::Relaxed);
    let clock = TestClock::new();
    let mut a = Peer::start(22, None, Some((10, 3)), &clock);
    let mut b = Peer::start(22, None, Some((10, 3)), &clock);

    send_oob(&a, &payload(4, 16));
    let packets = a.take(1).await;
    deliver(&b, &packets);

    assert_eq!(DEFAULT_SNMP.oob_packets.load(Ordering::Relaxed) - before, 1);
    assert_eq!(b.recv(), None);

    a.shutdown().await;
    b.shutdown().await;
}

/// An empty OOB payload is legal: it is why the minimum packet size is 12 and not 24.
// Go: kcp-go/v5@v5.6.66 sess.go:packetInput() ("OOB allows sending small packets and even
//     empty packets")
#[tokio::test(flavor = "current_thread")]
async fn an_empty_oob_payload_reaches_the_handler() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(23, None, Some((10, 3)), &clock);
    let mut b = Peer::start(23, None, Some((10, 3)), &clock);

    let seen = Arc::new(AtomicU64::new(0));
    let hits = Arc::clone(&seen);
    b.session
        .set_oob_handler(Some(Arc::new(move |data: &[u8]| {
            assert!(data.is_empty());
            hits.fetch_add(1, Ordering::Relaxed);
        })))
        .expect("FEC is enabled");

    send_oob(&a, b"");
    let packets = a.take(1).await;
    assert_eq!(packets[0].len(), FEC_HEADER_SIZE_PLUS2 + CONV_SIZE);
    deliver(&b, &packets);

    assert_eq!(seen.load(Ordering::Relaxed), 1);

    a.shutdown().await;
    b.shutdown().await;
}

/// Go refuses to register a handler when FEC is off, because OOB reuses the FEC header.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetOOBHandler()
#[tokio::test(flavor = "current_thread")]
async fn set_oob_handler_requires_fec() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut peer = Peer::start(24, None, None, &clock);

    let err = peer
        .session
        .set_oob_handler(Some(Arc::new(|_: &[u8]| {})))
        .expect_err("FEC is disabled");
    assert_eq!(err.to_string(), "OOB requires FEC to be enabled");

    peer.shutdown().await;
}

/// Clearing the handler stops delivery but not the counting.
#[tokio::test(flavor = "current_thread")]
async fn clearing_the_oob_handler_stops_delivery() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(25, None, Some((10, 3)), &clock);
    let mut b = Peer::start(25, None, Some((10, 3)), &clock);

    let hits = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&hits);
    b.session
        .set_oob_handler(Some(Arc::new(move |_: &[u8]| {
            counter.fetch_add(1, Ordering::Relaxed);
        })))
        .expect("FEC is enabled");
    send_oob(&a, b"first");
    deliver(&b, &a.take(1).await);
    assert_eq!(hits.load(Ordering::Relaxed), 1);

    b.session.set_oob_handler(None).expect("FEC is enabled");
    send_oob(&a, b"second");
    deliver(&b, &a.take(1).await);
    assert_eq!(hits.load(Ordering::Relaxed), 1);

    a.shutdown().await;
    b.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// Integrity failures and short packets
// ---------------------------------------------------------------------------------------------

/// A flipped bit anywhere after the CRC breaks the checksum: `InCsumErrors` moves and nothing
/// reaches KCP.
// Go: kcp-go/v5@v5.6.66 sess.go:packetInput() (the `default:` block branch)
#[tokio::test(flavor = "current_thread")]
async fn a_corrupt_crc_is_counted_and_dropped() {
    let _snmp = snmp_write();
    let clock = TestClock::new();
    let mut a = Peer::start(31, Some(aes_crypt()), None, &clock);
    let mut b = Peer::start(31, Some(aes_crypt()), None, &clock);

    a.send(&payload(1, 64));
    let mut packets = a.take(1).await;
    let last = packets[0].len() - 1;
    packets[0][last] ^= 0x80;

    let before = DEFAULT_SNMP.in_csum_errors.load(Ordering::Relaxed);
    let before_pkts = DEFAULT_SNMP.in_pkts.load(Ordering::Relaxed);
    deliver(&b, &packets);

    assert_eq!(
        DEFAULT_SNMP.in_csum_errors.load(Ordering::Relaxed) - before,
        1,
        "InCsumErrors"
    );
    assert_eq!(
        DEFAULT_SNMP.in_pkts.load(Ordering::Relaxed),
        before_pkts,
        "a dropped packet never reaches kcp_input"
    );
    assert_eq!(b.recv(), None);

    a.shutdown().await;
    b.shutdown().await;
}

/// The same for AEAD: a tampered tag fails `Open`, which is also `InCsumErrors` in Go.
// Go: kcp-go/v5@v5.6.66 sess.go:packetInput() (the `*aeadCrypt` branch)
#[tokio::test(flavor = "current_thread")]
async fn a_corrupt_aead_tag_is_counted_and_dropped() {
    let _snmp = snmp_write();
    let clock = TestClock::new();
    let mut a = Peer::start(32, Some(gcm_crypt()), None, &clock);
    let mut b = Peer::start(32, Some(gcm_crypt()), None, &clock);

    a.send(&payload(1, 64));
    let mut packets = a.take(1).await;
    let last = packets[0].len() - 1;
    packets[0][last] ^= 0x01;

    let before = DEFAULT_SNMP.in_csum_errors.load(Ordering::Relaxed);
    let before_pkts = DEFAULT_SNMP.in_pkts.load(Ordering::Relaxed);
    deliver(&b, &packets);

    assert_eq!(
        DEFAULT_SNMP.in_csum_errors.load(Ordering::Relaxed) - before,
        1,
        "InCsumErrors"
    );
    assert_eq!(DEFAULT_SNMP.in_pkts.load(Ordering::Relaxed), before_pkts);
    assert_eq!(b.recv(), None);

    a.shutdown().await;
    b.shutdown().await;
}

/// Shorter than the crypto header: dropped without any counter, exactly as Go returns early.
// Go: kcp-go/v5@v5.6.66 sess.go:packetInput() (`len(data) < cryptHeaderSize` /
//     `nonceSize+block.Overhead()`)
#[tokio::test(flavor = "current_thread")]
async fn packets_shorter_than_the_crypto_header_are_dropped_silently() {
    let _snmp = snmp_write();
    let clock = TestClock::new();
    let mut cfb = Peer::start(33, Some(aes_crypt()), None, &clock);
    let mut aead = Peer::start(33, Some(gcm_crypt()), None, &clock);

    let before = DEFAULT_SNMP.copy();
    for len in [0, 1, CRYPT_HEADER_SIZE - 1] {
        cfb.session.packet_input(&mut vec![0u8; len]);
    }
    for len in [0, 1, AeadCrypt::NONCE + AeadCrypt::OVERHEAD - 1] {
        aead.session.packet_input(&mut vec![0u8; len]);
    }
    let after = DEFAULT_SNMP.copy();

    assert_eq!(after.in_csum_errors, before.in_csum_errors, "InCsumErrors");
    assert_eq!(after.kcp_in_errors, before.kcp_in_errors, "KCPInErrors");
    assert_eq!(after.in_pkts, before.in_pkts, "InPkts");

    cfb.shutdown().await;
    aead.shutdown().await;
}

/// A decrypted packet below `min(IKCP_OVERHEAD, fecHeaderSizePlus2+convSize)` is a
/// `KCPInErrors`, not a KCP input at all.
// Go: kcp-go/v5@v5.6.66 sess.go:packetInput() (the minimum-size check)
#[tokio::test(flavor = "current_thread")]
async fn packets_below_the_minimum_size_count_kcp_in_errors() {
    let _snmp = snmp_write();
    assert_eq!(MIN_PACKET_SIZE, 12);
    let clock = TestClock::new();
    let mut peer = Peer::start(34, None, None, &clock);

    let before = DEFAULT_SNMP.copy();
    for len in 0..MIN_PACKET_SIZE {
        peer.session.packet_input(&mut vec![0u8; len]);
    }
    let after = DEFAULT_SNMP.copy();

    assert_eq!(
        after.kcp_in_errors - before.kcp_in_errors,
        MIN_PACKET_SIZE as u64,
        "KCPInErrors, one per short packet"
    );
    assert_eq!(after.in_pkts, before.in_pkts, "InPkts is untouched");

    peer.shutdown().await;
}

/// The `len(data) < fecHeaderSizePlus2` guard inside `kcpInput` counts `InErrs`. It is
/// unreachable through `packet_input` (12 > 8), so it is exercised through the entry point the
/// listener (05.7) uses.
// Go: kcp-go/v5@v5.6.66 sess.go:kcpInput() (`case typeData, typeParity`)
#[tokio::test(flavor = "current_thread")]
async fn a_truncated_fec_packet_counts_in_errs() {
    let _snmp = snmp_write();
    let clock = TestClock::new();
    let mut peer = Peer::start(35, None, Some((10, 3)), &clock);

    let mut packet = vec![0u8; FEC_HEADER_SIZE_PLUS2 - 1];
    packet[FEC_FLAG_OFFSET..FEC_FLAG_OFFSET + 2].copy_from_slice(&TYPE_DATA.to_le_bytes());

    let before = DEFAULT_SNMP.copy();
    peer.session.kcp_input(&packet);
    let after = DEFAULT_SNMP.copy();

    assert_eq!(after.in_errs - before.in_errs, 1, "InErrs");
    assert_eq!(after.in_pkts - before.in_pkts, 1, "InPkts still counts it");
    assert_eq!(after.kcp_in_errors, before.kcp_in_errors, "KCPInErrors");
    assert!(
        peer.session.lock().fec_decoder.is_some(),
        "the session was configured with FEC"
    );

    peer.shutdown().await;
}

/// A well-sized but nonsense KCP packet is a `KCPInErrors`.
// Go: kcp-go/v5@v5.6.66 sess.go:kcpInput() (the `default:` branch)
#[tokio::test(flavor = "current_thread")]
async fn a_malformed_kcp_packet_counts_kcp_in_errors() {
    let _snmp = snmp_write();
    let clock = TestClock::new();
    let mut peer = Peer::start(36, None, None, &clock);

    // Right conv, but `cmd` is not one of PUSH/ACK/WASK/WINS.
    let mut packet = vec![0u8; IKCP_OVERHEAD as usize];
    packet[..4].copy_from_slice(&36u32.to_le_bytes());
    packet[4] = 99;

    let before = DEFAULT_SNMP.copy();
    peer.session.packet_input(&mut packet);
    let after = DEFAULT_SNMP.copy();

    assert_eq!(after.kcp_in_errors - before.kcp_in_errors, 1, "KCPInErrors");
    assert_eq!(after.in_pkts - before.in_pkts, 1, "InPkts");
    assert_eq!(
        after.in_bytes - before.in_bytes,
        IKCP_OVERHEAD as u64,
        "InBytes"
    );

    peer.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// Counters and wake-ups
// ---------------------------------------------------------------------------------------------

/// `InPkts`/`InBytes` count every packet that survives decryption, FEC packets included.
// Go: kcp-go/v5@v5.6.66 sess.go:kcpInput()
#[tokio::test(flavor = "current_thread")]
async fn kcp_input_counts_in_pkts_and_in_bytes() {
    let _snmp = snmp_write();
    let clock = TestClock::new();
    let mut a = Peer::start(41, Some(aes_crypt()), Some((3, 2)), &clock);
    let mut b = Peer::start(41, Some(aes_crypt()), Some((3, 2)), &clock);

    for _ in 0..3 {
        a.send(&payload(1, 100));
    }
    let packets = a.take(5).await;

    let before = DEFAULT_SNMP.copy();
    deliver(&b, &packets);
    let after = DEFAULT_SNMP.copy();

    assert_eq!(after.in_pkts - before.in_pkts, 5, "InPkts");
    // The crypto header is stripped before counting; the FEC header is not.
    let expected: u64 = packets
        .iter()
        .map(|p| (p.len() - CRYPT_HEADER_SIZE) as u64)
        .sum();
    assert_eq!(after.in_bytes - before.in_bytes, expected, "InBytes");

    a.shutdown().await;
    b.shutdown().await;
}

/// Incoming data wakes a reader; an incoming ACK that frees the send window wakes a writer.
// Go: kcp-go/v5@v5.6.66 sess.go:kcpInput() (`notifyReadEvent` / `notifyWriteEvent`)
#[tokio::test(flavor = "current_thread")]
async fn input_notifies_readers_and_writers() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(42, None, None, &clock);
    let mut b = Peer::start(42, None, None, &clock);

    // Nothing has arrived yet, so no permit is waiting.
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            b.session.read_notify().notified()
        )
        .await
        .is_err(),
        "no read event before any input"
    );

    a.send(&payload(1, 64));
    deliver(&b, &a.take(1).await);

    tokio::time::timeout(LIMIT, b.session.read_notify().notified())
        .await
        .expect("a readable session must notify readers");
    // Space in the send window is always announced, whether or not anybody waits.
    tokio::time::timeout(LIMIT, b.session.write_notify().notified())
        .await
        .expect("an open send window must notify writers");

    a.shutdown().await;
    b.shutdown().await;
}

/// A packet for another conversation is rejected by KCP and counted, and never wakes a reader.
// Go: kcp-go/v5@v5.6.66 kcp.go:Input() (`conv != kcp.conv`)
#[tokio::test(flavor = "current_thread")]
async fn a_packet_for_another_conv_is_rejected() {
    let _snmp = snmp_write();
    let clock = TestClock::new();
    let mut a = Peer::start(51, Some(aes_crypt()), None, &clock);
    let mut b = Peer::start(52, Some(aes_crypt()), None, &clock);

    a.send(&payload(1, 64));
    let packets = a.take(1).await;

    let before = DEFAULT_SNMP.copy();
    deliver(&b, &packets);
    let after = DEFAULT_SNMP.copy();

    assert_eq!(after.kcp_in_errors - before.kcp_in_errors, 1, "KCPInErrors");
    assert_eq!(b.recv(), None);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            b.session.read_notify().notified()
        )
        .await
        .is_err(),
        "a rejected packet must not wake a reader"
    );

    a.shutdown().await;
    b.shutdown().await;
}

/// A longer exchange in both directions, with FEC and AEAD on: every message arrives intact and
/// in order.
#[tokio::test(flavor = "current_thread")]
async fn a_bidirectional_exchange_delivers_everything_in_order() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(61, Some(gcm_crypt()), Some((4, 2)), &clock);
    let mut b = Peer::start(61, Some(gcm_crypt()), Some((4, 2)), &clock);

    let msgs: Vec<Vec<u8>> = (0..12u8)
        .map(|i| payload(i, 200 + usize::from(i)))
        .collect();
    for msg in &msgs {
        a.send(msg);
        assert!(pump(&a, &b).await > 0);
        // Drive b's acknowledgements back so the send window never fills.
        pump(&b, &a).await;
    }
    assert_eq!(b.drain(), msgs);

    for msg in msgs.iter().rev() {
        b.send(msg);
        assert!(pump(&b, &a).await > 0);
        pump(&a, &b).await;
    }
    let reversed: Vec<Vec<u8>> = msgs.iter().rev().cloned().collect();
    assert_eq!(a.drain(), reversed);

    a.shutdown().await;
    b.shutdown().await;
}

/// Recovered shards are fed to KCP as `IKCP_PACKET_FEC`, not as regular packets.
///
/// The distinction is observable: `Kcp::input` only counts `RepeatSegs` (and only updates
/// `rmt_wnd`) for `IKCP_PACKET_REGULAR`. A `(1, 1)` group makes a duplicate easy to stage -
/// decoding a group empties its heap and clears the dedup marks, so with one data shard the
/// parity packet decodes the group again and hands back the data shard KCP already has
/// (a step 04.5 note). Feeding that shard as `IKCP_PACKET_REGULAR` moves `RepeatSegs`;
/// feeding it as `IKCP_PACKET_FEC`, as Go does, must not.
// Go: kcp-go/v5@v5.6.66 sess.go:kcpInput() (`s.kcp.Input(r[2:sz], false, s.ackNoDelay)`)
#[tokio::test(flavor = "current_thread")]
async fn recovered_shards_enter_kcp_as_fec_packets() {
    let _snmp = snmp_write();
    let clock = TestClock::new();
    let mut a = Peer::start(31, None, Some((1, 1)), &clock);
    // `b` has no FEC of its own, so it builds the lazy `(1, 1)` decoder on the first packet.
    let mut b = Peer::start(31, None, None, &clock);

    let msgs = [payload(1, 100), payload(2, 100)];
    for msg in &msgs {
        a.send(msg);
    }
    // Data shard, its parity shard, and the next group's data shard.
    let packets = a.take(3).await;

    let repeats = DEFAULT_SNMP.repeat_segs.load(Ordering::Relaxed);
    let recovered = DEFAULT_SNMP.fec_recovered.load(Ordering::Relaxed);
    deliver(&b, &packets);

    assert_eq!(b.drain(), msgs.to_vec());
    assert_eq!(
        DEFAULT_SNMP.fec_recovered.load(Ordering::Relaxed) - recovered,
        1,
        "the parity packet decodes the group again and returns the first data shard"
    );
    assert_eq!(
        DEFAULT_SNMP.repeat_segs.load(Ordering::Relaxed) - repeats,
        0,
        "a duplicate arriving as IKCP_PACKET_FEC is not counted in RepeatSegs"
    );

    a.shutdown().await;
    b.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// 05.4: Read
// ---------------------------------------------------------------------------------------------

/// Spawns a `read` into a buffer of `len` bytes, returning what it produced.
fn spawn_read(peer: &Peer, len: usize) -> tokio::task::JoinHandle<io::Result<Vec<u8>>> {
    let session = Arc::clone(&peer.session);
    tokio::spawn(async move {
        let mut buf = vec![0u8; len];
        let n = session.read(&mut buf).await?;
        buf.truncate(n);
        Ok(buf)
    })
}

/// Spawns a `write` of `data`.
fn spawn_write(peer: &Peer, data: Vec<u8>) -> tokio::task::JoinHandle<io::Result<usize>> {
    let session = Arc::clone(&peer.session);
    tokio::spawn(async move { session.write(&data).await })
}

/// Sends one message end to end and reads it back with `Read`, `BytesReceived` included.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).Read()
#[tokio::test(flavor = "current_thread")]
async fn read_returns_a_whole_message_without_blocking() {
    let _snmp = snmp_write();
    let clock = TestClock::new();
    let mut a = Peer::start(101, None, None, &clock);
    let mut b = Peer::start(101, None, None, &clock);

    let data = payload(5, 400);
    a.send(&data);
    deliver(&b, &a.take(1).await);

    let before = DEFAULT_SNMP.bytes_received.load(Ordering::Relaxed);
    let mut buf = vec![0u8; 1024];
    let n = b.session.read(&mut buf).await.expect("data is queued");
    assert_eq!(n, data.len());
    assert_eq!(&buf[..n], data.as_slice());
    assert_eq!(
        DEFAULT_SNMP.bytes_received.load(Ordering::Relaxed) - before,
        data.len() as u64
    );

    a.shutdown().await;
    b.shutdown().await;
}

/// A buffer smaller than the message: the remainder waits in `recvbuf`/`bufptr` and the next
/// calls serve it, without another packet.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).Read() (the `bufptr` branch); sess_test.go:
//     TestTinyBufferReceiver
#[tokio::test(flavor = "current_thread")]
async fn read_serves_a_long_message_through_tiny_buffers() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(102, None, None, &clock);
    let mut b = Peer::start(102, None, None, &clock);

    let data = payload(11, 20);
    a.send(&data);
    deliver(&b, &a.take(1).await);

    let mut got = Vec::new();
    for expect in [7usize, 7, 6] {
        let mut buf = vec![0u8; 7];
        let n = b.session.read(&mut buf).await.expect("bufptr has data");
        assert_eq!(n, expect, "Read returns as much as the buffer holds");
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, data);

    // Nothing is left over, and the next read blocks.
    assert_eq!(b.session.lock().bufptr_len(), 0);
    let reader = spawn_read(&b, 7);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), reader)
            .await
            .is_err(),
        "the stream is drained, so Read must block"
    );

    a.shutdown().await;
    b.shutdown().await;
}

/// `recvbuf` grows to the largest message seen (Go: `if cap(s.recvbuf) < size`).
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).Read()
#[tokio::test(flavor = "current_thread")]
async fn read_grows_recvbuf_for_a_message_larger_than_the_mtu() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(103, None, None, &clock);
    let mut b = Peer::start(103, None, None, &clock);

    // One KCP message of 4000 bytes: three fragments, reassembled by `peek_size`/`recv`.
    let data = payload(13, 4000);
    a.send(&data);
    deliver(&b, &a.take(3).await);

    let mut buf = vec![0u8; 10];
    let n = b.session.read(&mut buf).await.expect("data is queued");
    assert_eq!(n, 10);
    assert_eq!(b.session.lock().recvbuf.len(), data.len());
    assert_eq!(b.session.lock().bufptr_len(), data.len() - 10);

    let mut rest = vec![0u8; data.len()];
    let n = b.session.read(&mut rest).await.expect("bufptr has data");
    assert_eq!(n, data.len() - 10);
    assert_eq!(&buf[..10], &data[..10]);
    assert_eq!(&rest[..n], &data[10..]);

    a.shutdown().await;
    b.shutdown().await;
}

/// A blocked `Read` is woken by the packet that completes a message.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).Read() (`case <-s.chReadEvent:`)
#[tokio::test(flavor = "current_thread")]
async fn read_blocks_until_data_arrives() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(104, None, None, &clock);
    let mut b = Peer::start(104, None, None, &clock);

    let reader = spawn_read(&b, 1024);
    tokio::task::yield_now().await;
    assert!(!reader.is_finished(), "nothing has arrived yet");

    let data = payload(17, 128);
    a.send(&data);
    deliver(&b, &a.take(1).await);

    let got = tokio::time::timeout(LIMIT, reader)
        .await
        .expect("the reader must be woken")
        .expect("task")
        .expect("read");
    assert_eq!(got, data);

    a.shutdown().await;
    b.shutdown().await;
}

/// The read deadline makes a blocked `Read` fail with Go's `timeout` error.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).Read() (`case <-c:`); sess_test.go:TestTimeout
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn read_times_out_at_the_deadline() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut b = Peer::start(105, None, None, &clock);

    b.session
        .set_read_deadline(Some(Instant::now() + Duration::from_secs(1)))
        .expect("set_read_deadline");

    let started = Instant::now();
    let mut buf = vec![0u8; 10];
    let err = b.session.read(&mut buf).await.expect_err("deadline passed");
    assert_eq!(err.to_string(), "timeout");
    assert!(is_timeout(&err));
    assert!(started.elapsed() >= Duration::from_secs(1));

    // A deadline in the past fires at once, like Go's `time.NewTimer(time.Until(t))`.
    b.session
        .set_read_deadline(Some(Instant::now() - Duration::from_secs(5)))
        .expect("set_read_deadline");
    assert!(is_timeout(
        &b.session.read(&mut buf).await.expect_err("deadline passed")
    ));

    // Clearing it makes `Read` block again.
    b.session
        .set_read_deadline(None)
        .expect("set_read_deadline");
    let reader = spawn_read(&b, 10);
    assert!(
        tokio::time::timeout(Duration::from_secs(30), reader)
            .await
            .is_err(),
        "without a deadline Read waits forever"
    );

    b.shutdown().await;
}

/// Go's `RESET_TIMER`: a read event makes a blocked `Read` re-read the deadline, which is how a
/// `SetReadDeadline` during the call takes effect (the setter notifies the event).
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).Read() (`goto RESET_TIMER`)
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn changing_the_read_deadline_retimes_a_blocked_read() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut b = Peer::start(106, None, None, &clock);

    b.session
        .set_read_deadline(Some(Instant::now() + Duration::from_secs(600)))
        .expect("set_read_deadline");
    let reader = spawn_read(&b, 10);
    tokio::task::yield_now().await;

    // Bring the deadline forward: the call must now fail well before the original one.
    let started = Instant::now();
    b.session
        .set_read_deadline(Some(Instant::now() + Duration::from_millis(50)))
        .expect("set_read_deadline");
    let err = tokio::time::timeout(Duration::from_secs(60), reader)
        .await
        .expect("the new deadline must apply")
        .expect("task")
        .expect_err("deadline passed");
    assert!(is_timeout(&err));
    assert!(started.elapsed() < Duration::from_secs(60));

    b.shutdown().await;
}

/// Go's other half of `RESET_TIMER`: when `Read` was entered without a deadline, `timeout` is
/// nil and a read event never re-reads `s.rd`, so a deadline set during the call is ignored
/// until the call returns. The quirk is reproduced deliberately.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).Read() (`if timeout != nil`)
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_deadline_set_after_a_read_began_without_one_is_ignored() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(107, None, None, &clock);
    let mut b = Peer::start(107, None, None, &clock);

    let reader = spawn_read(&b, 64);
    tokio::task::yield_now().await;

    b.session
        .set_read_deadline(Some(Instant::now() + Duration::from_millis(10)))
        .expect("set_read_deadline");

    let mut reader = reader;
    assert!(
        tokio::time::timeout(Duration::from_secs(5), &mut reader)
            .await
            .is_err(),
        "Go keeps waiting: the timer of this call was never created"
    );

    // It is still a live reader: data wakes it.
    let data = payload(19, 32);
    a.send(&data);
    deliver(&b, &a.take(1).await);
    let got = tokio::time::timeout(LIMIT, reader)
        .await
        .expect("the reader must be woken")
        .expect("task")
        .expect("read");
    assert_eq!(got, data);

    a.shutdown().await;
    b.shutdown().await;
}

/// A socket read error unblocks `Read` and is handed to the caller (Go's `chSocketReadError`).
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).Read() (`case <-s.chSocketReadError:`)
#[tokio::test(flavor = "current_thread")]
async fn read_fails_with_the_socket_read_error() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut b = Peer::start(108, None, None, &clock);

    let reader = spawn_read(&b, 10);
    tokio::task::yield_now().await;
    b.session
        .notify_read_error(io::Error::new(io::ErrorKind::NotConnected, "socket gone"));

    let err = tokio::time::timeout(LIMIT, reader)
        .await
        .expect("the reader must be woken")
        .expect("task")
        .expect_err("the socket failed");
    assert_eq!(err.kind(), io::ErrorKind::NotConnected);
    assert_eq!(err.to_string(), "socket gone");

    // Later calls see it too (Go's channel stays closed).
    let mut buf = [0u8; 10];
    assert_eq!(
        b.session
            .read(&mut buf)
            .await
            .expect_err("the socket failed")
            .to_string(),
        "socket gone"
    );

    b.shutdown().await;
}

/// Go's `TestClose` drain: data that arrived before `Close` is still readable afterwards, and
/// only once it is exhausted does `Read` report the closed pipe.
// Go: kcp-go/v5@v5.6.66 sess_test.go:TestClose (the "write->close->drain->read" part)
#[tokio::test(flavor = "current_thread")]
async fn read_drains_queued_data_after_close_and_then_fails() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(109, None, None, &clock);
    let mut b = Peer::start(109, None, None, &clock);

    let data = payload(23, 64);
    a.send(&data);
    deliver(&b, &a.take(1).await);

    b.session.close().expect("first close");

    let mut buf = vec![0u8; 64];
    let n = b.session.read(&mut buf).await.expect("closed conn drains");
    assert_eq!(&buf[..n], data.as_slice());

    let err = b.session.read(&mut buf).await.expect_err("drained");
    assert_eq!(err.to_string(), "io: read/write on closed pipe");

    a.shutdown().await;
    b.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// 05.4: Write
// ---------------------------------------------------------------------------------------------

/// `Write` splits its argument into `mss`-sized KCP messages and returns the total length.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).WriteBuffers() (the splitting loop)
#[tokio::test(flavor = "current_thread")]
async fn write_splits_the_payload_at_mss() {
    let _snmp = snmp_write();
    let clock = TestClock::new();
    let mut a = Peer::start(110, None, None, &clock);
    let mut b = Peer::start(110, None, None, &clock);

    let mss = a.session.lock().kcp.mss as usize;
    let data = payload(29, 2 * mss + 7);

    let before = DEFAULT_SNMP.bytes_sent.load(Ordering::Relaxed);
    let n = a.session.write(&data).await.expect("the window is empty");
    assert_eq!(n, data.len(), "Write returns everything it accepted");
    assert_eq!(
        DEFAULT_SNMP.bytes_sent.load(Ordering::Relaxed) - before,
        data.len() as u64
    );

    // Three segments, so three datagrams, and (message mode) three messages on the far side.
    deliver(&b, &a.take(3).await);
    assert_eq!(
        b.drain(),
        vec![
            data[..mss].to_vec(),
            data[mss..2 * mss].to_vec(),
            data[2 * mss..].to_vec(),
        ]
    );

    a.shutdown().await;
    b.shutdown().await;
}

/// `WriteBuffers` queues every slice under one window check and returns their total length.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).WriteBuffers(); sess_test.go:TestSendVector
#[tokio::test(flavor = "current_thread")]
async fn write_buffers_queues_every_slice() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(111, None, None, &clock);
    let mut b = Peer::start(111, None, None, &clock);

    let first = payload(31, 10);
    let second = payload(37, 200);
    let n = a
        .session
        .write_buffers(&[&first, &second])
        .await
        .expect("the window is empty");
    assert_eq!(n, first.len() + second.len());

    // One flush, so `flush` packs both segments into a single datagram.
    deliver(&b, &a.take(1).await);
    assert_eq!(b.drain(), vec![first, second]);

    a.shutdown().await;
    b.shutdown().await;
}

/// A full send window blocks `Write` until an ack retires a segment.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).WriteBuffers() (`case <-s.chWriteEvent:`)
#[tokio::test(flavor = "current_thread")]
async fn write_blocks_until_the_send_window_opens() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(112, None, None, &clock);
    let mut b = Peer::start(112, None, None, &clock);

    // One segment in flight is already the whole window.
    a.session.set_window_size(1, 128);
    let first = payload(41, 50);
    assert_eq!(
        a.session.write(&first).await.expect("empty window"),
        first.len()
    );
    assert_eq!(a.session.lock().kcp.wait_snd(), 1);

    let second = payload(43, 50);
    let writer = spawn_write(&a, second.clone());
    tokio::task::yield_now().await;
    assert!(!writer.is_finished(), "the window is full");

    // Deliver the segment, bring back the ack: `wait_snd` drops and the writer is notified.
    deliver(&b, &a.take(1).await);
    deliver(&a, &b.take(1).await);

    let n = tokio::time::timeout(LIMIT, writer)
        .await
        .expect("the writer must be woken")
        .expect("task")
        .expect("write");
    assert_eq!(n, second.len());

    deliver(&b, &a.take(1).await);
    assert_eq!(b.drain(), vec![first, second]);

    a.shutdown().await;
    b.shutdown().await;
}

/// The write deadline makes a blocked `Write` fail with Go's `timeout` error, and a wake-up
/// re-reads it (Go's `RESET_TIMER`).
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).WriteBuffers() (`case <-c:`)
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn write_times_out_at_the_deadline() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(113, None, None, &clock);

    a.session.set_window_size(1, 128);
    a.session
        .write(&payload(47, 10))
        .await
        .expect("empty window");

    a.session
        .set_write_deadline(Some(Instant::now() + Duration::from_secs(1)))
        .expect("set_write_deadline");
    let started = Instant::now();
    let err = a
        .session
        .write(&payload(53, 10))
        .await
        .expect_err("the window stays full");
    assert_eq!(err.to_string(), "timeout");
    assert!(is_timeout(&err));
    assert!(started.elapsed() >= Duration::from_secs(1));

    // `SetDeadline` sets both, and a blocked writer picks the new one up.
    a.session
        .set_deadline(Some(Instant::now() + Duration::from_secs(600)))
        .expect("set_deadline");
    let writer = spawn_write(&a, payload(59, 10));
    tokio::task::yield_now().await;
    a.session
        .set_deadline(Some(Instant::now() + Duration::from_millis(50)))
        .expect("set_deadline");
    let err = tokio::time::timeout(Duration::from_secs(60), writer)
        .await
        .expect("the new deadline must apply")
        .expect("task")
        .expect_err("the window stays full");
    assert!(is_timeout(&err));

    a.shutdown().await;
}

/// A socket write error unblocks `Write` and is handed to the caller.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).WriteBuffers() (`case <-s.chSocketWriteError:`)
#[tokio::test(flavor = "current_thread")]
async fn write_fails_with_the_socket_write_error() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(114, None, None, &clock);

    a.session.set_window_size(1, 128);
    a.session
        .write(&payload(61, 10))
        .await
        .expect("empty window");
    let writer = spawn_write(&a, payload(67, 10));
    tokio::task::yield_now().await;

    // What the tx task does when `send_batch` fails.
    a.session
        .tx_shared()
        .write_error()
        .set(io::Error::new(io::ErrorKind::HostUnreachable, "no route"));

    let err = tokio::time::timeout(LIMIT, writer)
        .await
        .expect("the writer must be woken")
        .expect("task")
        .expect_err("the socket failed");
    assert_eq!(err.kind(), io::ErrorKind::HostUnreachable);
    assert_eq!(err.to_string(), "no route");

    // And every later call fails before even looking at the window.
    assert_eq!(
        a.session
            .write(b"x")
            .await
            .expect_err("the socket failed")
            .to_string(),
        "no route"
    );

    a.shutdown().await;
}

/// End to end: a failing socket fills the write-error slot from the tx task, and the next
/// `Write` reports it.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).tx() → notifyWriteError()
#[tokio::test(flavor = "current_thread")]
async fn a_failing_socket_surfaces_on_the_next_write() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(115, None, None, &clock);
    a.conn.fail_sends.store(true, Ordering::Relaxed);

    // The first write succeeds: the failure happens in the tx task afterwards.
    a.session.write(&payload(71, 10)).await.expect("queued");

    let slot = Arc::clone(&a.session);
    tokio::time::timeout(LIMIT, async move {
        while !slot.tx_shared().write_error().is_set() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the tx task must record the error");

    assert_eq!(
        a.session
            .write(&payload(73, 10))
            .await
            .expect_err("the socket failed")
            .to_string(),
        "no route"
    );

    a.shutdown().await;
}

/// `SetWriteDelay(true)` leaves the flush to the update task; `false` uncorks immediately.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).WriteBuffers() (`|| !s.writeDelay`)
#[tokio::test(flavor = "current_thread")]
async fn write_delay_defers_the_flush() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(116, None, None, &clock);
    let mut b = Peer::start(116, None, None, &clock);

    // The KCP output callback runs inside `write`, so a flush would have queued a packet by
    // the time it returns.
    a.session.set_write_delay(true);
    let first = payload(79, 10);
    a.session.write(&first).await.expect("queued");
    assert_eq!(a.session.tx().queued(), 0, "the flush was deferred");

    a.session.set_write_delay(false);
    let second = payload(83, 10);
    a.session.write(&second).await.expect("queued");

    // The flush now uncorks both messages, packed into one datagram.
    deliver(&b, &a.take(1).await);
    assert_eq!(b.drain(), vec![first, second]);

    a.shutdown().await;
    b.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// 05.4: Close
// ---------------------------------------------------------------------------------------------

/// Go's `TestClose`: the second `Close` fails, and so does every write afterwards.
// Go: kcp-go/v5@v5.6.66 sess_test.go:TestClose; sess.go:(*UDPSession).Close()
#[tokio::test(flavor = "current_thread")]
async fn close_is_idempotent_and_stops_writes() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(117, None, None, &clock);

    assert!(!a.session.is_closed());
    a.session.close().expect("first close");
    assert!(a.session.is_closed());
    assert_eq!(
        a.session
            .close()
            .expect_err("double close misbehavior")
            .to_string(),
        "io: read/write on closed pipe"
    );

    let err = a
        .session
        .write(&[0u8; 10])
        .await
        .expect_err("write after close misbehavior");
    assert_eq!(err.to_string(), "io: read/write on closed pipe");
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

    // A blocked reader is released as well.
    a.shutdown().await;
}

/// A reader blocked when `Close` arrives is released with the closed-pipe error.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).Read() (`case <-s.die:`)
#[tokio::test(flavor = "current_thread")]
async fn close_releases_blocked_readers_and_writers() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(118, None, None, &clock);

    a.session.set_window_size(1, 128);
    a.session
        .write(&payload(89, 10))
        .await
        .expect("empty window");

    let reader = spawn_read(&a, 10);
    let writer = spawn_write(&a, payload(97, 10));
    tokio::task::yield_now().await;
    a.session.close().expect("first close");

    for (what, err) in [
        (
            "read",
            tokio::time::timeout(LIMIT, reader)
                .await
                .expect("reader woken")
                .expect("task")
                .expect_err("closed"),
        ),
        (
            "write",
            tokio::time::timeout(LIMIT, writer)
                .await
                .expect("writer woken")
                .expect("task")
                .map(|_| 0u8)
                .expect_err("closed"),
        ),
    ] {
        assert_eq!(
            err.to_string(),
            "io: read/write on closed pipe",
            "{what} must report the closed pipe"
        );
    }

    a.shutdown().await;
}

/// Deviation V05: the final flush is queued before `die` is signalled, so the last packets
/// always reach the wire (Go sends them about half the time).
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).Close() (`s.kcp.flush(IKCP_FLUSH_FULL)`)
#[tokio::test(flavor = "current_thread")]
async fn close_flushes_what_is_still_queued() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(119, None, None, &clock);
    let mut b = Peer::start(119, None, None, &clock);

    // With `writeDelay` nothing has been flushed when `Close` runs.
    a.session.set_write_delay(true);
    let data = payload(101, 64);
    a.session.write(&data).await.expect("queued");
    assert_eq!(a.session.tx().queued(), 0);

    a.session.close().expect("first close");
    deliver(&b, &a.take(1).await);
    assert_eq!(b.drain(), vec![data]);

    a.shutdown().await;
    b.shutdown().await;
}

/// A dialled session owns its socket and closes it; an accepted one hands itself back to the
/// listener and leaves the shared socket alone.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).Close() (`s.l != nil` / `s.ownConn`)
#[tokio::test(flavor = "current_thread")]
async fn close_closes_an_owned_socket_but_defers_to_the_listener() {
    let _snmp = snmp_read();
    let clock = TestClock::new();

    let mut dialled = Peer::start(120, None, None, &clock);
    dialled.session.close().expect("first close");
    assert!(dialled.conn.closed.load(Ordering::SeqCst), "own socket");

    let listener = Arc::new(StubListener::default());
    let mut accepted = Peer::start_accepted(121, &clock, &listener);
    accepted.session.close().expect("first close");
    assert!(
        !accepted.conn.closed.load(Ordering::SeqCst),
        "the listener's socket is shared"
    );
    assert_eq!(
        *listener.closed.lock().unwrap_or_else(|e| e.into_inner()),
        vec![remote()]
    );

    dialled.shutdown().await;
    accepted.shutdown().await;
}

/// `CurrEstab`, `MaxConn` and the "opens" counters follow Go's `newUDPSession`/`Close`.
// Go: kcp-go/v5@v5.6.66 sess.go:newUDPSession() / (*UDPSession).Close()
#[tokio::test(flavor = "current_thread")]
async fn opening_and_closing_moves_the_connection_counters() {
    let _snmp = snmp_write();
    let clock = TestClock::new();
    let estab = DEFAULT_SNMP.curr_estab.load(Ordering::Relaxed);
    let active = DEFAULT_SNMP.active_opens.load(Ordering::Relaxed);
    let passive = DEFAULT_SNMP.passive_opens.load(Ordering::Relaxed);

    let mut dialled = Peer::start(122, None, None, &clock);
    let listener = Arc::new(StubListener::default());
    let mut accepted = Peer::start_accepted(123, &clock, &listener);

    assert_eq!(DEFAULT_SNMP.curr_estab.load(Ordering::Relaxed) - estab, 2);
    assert_eq!(
        DEFAULT_SNMP.active_opens.load(Ordering::Relaxed) - active,
        1
    );
    assert_eq!(
        DEFAULT_SNMP.passive_opens.load(Ordering::Relaxed) - passive,
        1
    );
    assert!(DEFAULT_SNMP.max_conn.load(Ordering::Relaxed) >= estab + 2);

    dialled.session.close().expect("first close");
    accepted.session.close().expect("first close");
    assert_eq!(DEFAULT_SNMP.curr_estab.load(Ordering::Relaxed), estab);
    // A second `Close` must not move the counter again.
    assert!(dialled.session.close().is_err());
    assert_eq!(DEFAULT_SNMP.curr_estab.load(Ordering::Relaxed), estab);

    dialled.shutdown().await;
    accepted.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// 05.4: Setters and getters
// ---------------------------------------------------------------------------------------------

/// Every setter that only forwards to the KCP state machine.
// Go: kcp-go/v5@v5.6.66 sess.go:SetWriteDelay/SetWindowSize/SetStreamMode/SetACKNoDelay/
//     SetNoDelay/SetDUP/SetRateLimit
#[tokio::test(flavor = "current_thread")]
async fn setters_reach_the_state_they_configure() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(124, None, None, &clock);

    a.session.set_write_delay(true);
    assert!(a.session.lock().write_delay);
    a.session.set_write_delay(false);
    assert!(!a.session.lock().write_delay);

    a.session.set_window_size(1024, 512);
    assert_eq!(a.session.lock().kcp.snd_wnd, 1024);
    assert_eq!(a.session.lock().kcp.rcv_wnd, 512);

    a.session.set_stream_mode(true);
    assert_eq!(a.session.lock().kcp.stream, 1);
    a.session.set_stream_mode(false);
    assert_eq!(a.session.lock().kcp.stream, 0);

    a.session.set_ack_no_delay(false);
    assert!(!a.session.lock().ack_no_delay);
    a.session.set_ack_no_delay(true);
    assert!(a.session.lock().ack_no_delay);

    a.session.set_no_delay(1, 10, 2, 1);
    {
        let state = a.session.lock();
        assert_eq!(state.kcp.nodelay, 1);
        assert_eq!(state.kcp.interval, 10);
        assert_eq!(state.kcp.fastresend, 2);
        assert_eq!(state.kcp.nocwnd, 1);
    }

    a.session.set_dup(2);
    assert_eq!(a.session.tx_shared().dup(), 2);

    assert!(a.session.tx_shared().limiter().is_unlimited());
    a.session.set_rate_limit(125_000);
    assert!(!a.session.tx_shared().limiter().is_unlimited());
    assert!((a.session.tx_shared().limiter().limit() - 125_000.0).abs() < f64::EPSILON);
    a.session.set_rate_limit(0);
    assert!(a.session.tx_shared().limiter().is_unlimited());

    a.shutdown().await;
}

/// `SetMtu` caps at the 1500-byte limit, takes the headers (and the AEAD tag) off and reports
/// whether KCP accepted the result.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetMtu()
#[tokio::test(flavor = "current_thread")]
async fn set_mtu_subtracts_the_headers_and_reports_failure() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut plain = Peer::start(125, None, None, &clock);
    let mut aead = Peer::start(126, Some(gcm_crypt()), Some((10, 3)), &clock);

    assert!(plain.session.set_mtu(1200));
    assert_eq!(plain.session.lock().kcp.mtu, 1200);
    // min(mtuLimit, mtu)
    assert!(plain.session.set_mtu(4000));
    assert_eq!(plain.session.lock().kcp.mtu, MTU_LIMIT as u32);
    // Below KCP's minimum (50): rejected, and the MTU is left alone.
    assert!(!plain.session.set_mtu(40));
    assert_eq!(plain.session.lock().kcp.mtu, MTU_LIMIT as u32);

    let overhead = aead.session.header_size() + AeadCrypt::OVERHEAD;
    assert!(aead.session.set_mtu(1400));
    assert_eq!(aead.session.lock().kcp.mtu, 1400 - overhead as u32);

    plain.shutdown().await;
    aead.shutdown().await;
}

/// The three socket options are `invalid operation` on a session accepted from a listener, and
/// reach the socket on a dialled one.
// Go: kcp-go/v5@v5.6.66 sess.go:SetDSCP/SetReadBuffer/SetWriteBuffer
#[tokio::test(flavor = "current_thread")]
async fn socket_options_are_refused_for_accepted_sessions() {
    let _snmp = snmp_read();
    let clock = TestClock::new();

    let mut dialled = Peer::start(127, None, None, &clock);
    dialled.session.set_dscp(46).expect("own socket");
    dialled
        .session
        .set_read_buffer(4_194_304)
        .expect("own socket");
    dialled
        .session
        .set_write_buffer(4_194_304)
        .expect("own socket");
    assert_eq!(
        dialled.conn.options(),
        vec![
            ("dscp", 46),
            ("read_buffer", 4_194_304),
            ("write_buffer", 4_194_304),
        ]
    );

    let listener = Arc::new(StubListener::default());
    let mut accepted = Peer::start_accepted(128, &clock, &listener);
    for err in [
        accepted.session.set_dscp(46).expect_err("accepted"),
        accepted
            .session
            .set_read_buffer(1024)
            .expect_err("accepted"),
        accepted
            .session
            .set_write_buffer(1024)
            .expect_err("accepted"),
    ] {
        assert_eq!(err.to_string(), "invalid operation");
    }
    assert!(accepted.conn.options().is_empty());

    dialled.shutdown().await;
    accepted.shutdown().await;
}

/// The getters read what KCP holds, without changing it.
// Go: kcp-go/v5@v5.6.66 sess.go:GetConv/GetRTO/GetSRTT/GetSRTTVar/LocalAddr/RemoteAddr
#[tokio::test(flavor = "current_thread")]
async fn getters_report_the_session_state() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(0xdead_beef, None, None, &clock);

    assert_eq!(a.session.get_conv(), 0xdead_beef);
    assert_eq!(a.session.get_rto(), IKCP_RTO_DEF);
    assert_eq!(a.session.get_srtt(), 0);
    assert_eq!(a.session.get_srttvar(), 0);
    assert_eq!(a.session.remote_addr(), remote());
    assert_eq!(
        a.session.local_addr().expect("local addr"),
        "127.0.0.1:1".parse::<SocketAddr>().expect("literal")
    );

    {
        let mut state = a.session.lock();
        state.kcp.rx_rto = 321;
        state.kcp.rx_srtt = 42;
        state.kcp.rx_rttvar = 7;
    }
    assert_eq!(a.session.get_rto(), 321);
    assert_eq!(a.session.get_srtt(), 42);
    assert_eq!(a.session.get_srttvar(), 7);

    a.shutdown().await;
}

/// `SendOOB` needs FEC, refuses a payload larger than one packet, and otherwise reaches the
/// peer's handler.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SendOOB() / GetOOBMaxSize()
#[tokio::test(flavor = "current_thread")]
async fn send_oob_checks_fec_and_the_payload_size() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut plain = Peer::start(129, Some(aes_crypt()), None, &clock);
    let mut fec = Peer::start(130, Some(aes_crypt()), Some((10, 3)), &clock);

    assert_eq!(plain.session.get_oob_max_size(), 0);
    assert_eq!(
        plain
            .session
            .send_oob(b"x")
            .expect_err("no FEC")
            .to_string(),
        "OOB requires FEC to be enabled"
    );

    let max = fec.session.get_oob_max_size();
    assert_eq!(max, fec.session.lock().kcp.mtu as usize - CONV_SIZE);
    assert_eq!(
        fec.session
            .send_oob(&vec![0u8; max + 1])
            .expect_err("too large")
            .to_string(),
        "OOB payload too large"
    );
    fec.session
        .send_oob(&vec![0u8; max])
        .expect("exactly one packet");
    assert_eq!(fec.take(1).await.len(), 1);

    // The boundary case: at the maximum MTU a full-size OOB packet is exactly `MTU_LIMIT`
    // bytes once the header space is added, so the packet must still be built, not rejected.
    assert!(fec.session.set_mtu(1500));
    let max = fec.session.get_oob_max_size();
    assert_eq!(max, fec.session.lock().kcp.mtu as usize - CONV_SIZE);
    assert_eq!(
        fec.session
            .send_oob(&vec![0u8; max + 1])
            .expect_err("too large")
            .to_string(),
        "OOB payload too large"
    );
    fec.session
        .send_oob(&vec![0u8; max])
        .expect("exactly one packet");
    assert_eq!(fec.take(1).await.len(), 1);

    plain.shutdown().await;
    fec.shutdown().await;
}

/// A concurrency smoke test on the multi-threaded runtime: a writer, a reader and two relay
/// tasks moving datagrams, so that `Read`, `Write` and `kcp_input` run on different threads and
/// the notify/lock protocol is exercised under real contention.
///
/// The send window (32 segments) is far smaller than the transfer, so `Write` blocks and is
/// woken by the acks the peer sends; the receive window is large enough that the peer never has
/// to advertise a zero window (which only the 05.5 update task could reopen).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_and_write_concurrently_over_a_relay() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(200, Some(aes_crypt()), None, &clock);
    let mut b = Peer::start(200, Some(aes_crypt()), None, &clock);
    b.session.set_window_size(128, 1024);

    let stop = CancellationToken::new();
    let relays = [
        spawn_relay(&a.conn, &b.session, &stop),
        spawn_relay(&b.conn, &a.session, &stop),
    ];

    const MESSAGES: usize = 100;
    const SIZE: usize = 1000;

    let writer = {
        let session = Arc::clone(&a.session);
        tokio::spawn(async move {
            for i in 0..MESSAGES {
                let msg = payload(i as u8, SIZE);
                assert_eq!(session.write(&msg).await.expect("write"), SIZE);
            }
        })
    };
    let reader = {
        let session = Arc::clone(&b.session);
        tokio::spawn(async move {
            let mut got = Vec::with_capacity(MESSAGES * SIZE);
            let mut buf = vec![0u8; 4096];
            while got.len() < MESSAGES * SIZE {
                let n = session.read(&mut buf).await.expect("read");
                got.extend_from_slice(&buf[..n]);
            }
            got
        })
    };

    tokio::time::timeout(LIMIT, writer)
        .await
        .expect("the writer must finish")
        .expect("task");
    let got = tokio::time::timeout(LIMIT, reader)
        .await
        .expect("the reader must finish")
        .expect("task");

    let mut want = Vec::with_capacity(MESSAGES * SIZE);
    for i in 0..MESSAGES {
        want.extend_from_slice(&payload(i as u8, SIZE));
    }
    assert_eq!(got, want);

    stop.cancel();
    for relay in relays {
        relay.await.expect("relay task");
    }
    a.shutdown().await;
    b.shutdown().await;
}

/// Moves everything `from` has sent into `to`, until `stop` is cancelled.
fn spawn_relay(
    from: &Arc<CaptureConn>,
    to: &Arc<UdpSession<TestClock>>,
    stop: &CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let from = Arc::clone(from);
    let to = Arc::clone(to);
    let stop = stop.clone();
    tokio::spawn(async move {
        while !stop.is_cancelled() {
            for mut packet in from.take() {
                to.packet_input(&mut packet);
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
}

// ---------------------------------------------------------------------------------------------
// 05.5: The update task
// ---------------------------------------------------------------------------------------------

/// The flush interval `Peer::start_with` configures (kcptun's default `-mode fast`).
const UPDATE_INTERVAL: Duration = Duration::from_millis(30);

/// Lets every spawned task (the updater and the tx pipeline) run until it parks again.
///
/// With `start_paused` the clock only moves where a test says so, so a bounded number of yields
/// is enough: one flush hands its packets to the tx task, which encrypts and writes them in a
/// handful of polls and never waits for a timer (the rate limiter is unlimited here).
async fn settle() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

/// Moves the paused tokio clock *and* the session's millisecond clock by `d`, then lets the
/// tasks that woke up run.
///
/// Both clocks have to move together: tokio's drives `sleep_until` in the update task, the
/// session's drives KCP's own timestamps and retransmission timers.
async fn advance(clock: &TestClock, d: Duration) {
    clock.0.advance(d.as_millis() as u64);
    tokio::time::advance(d).await;
    settle().await;
}

/// The update task runs immediately, then once per KCP interval, and an idle session puts
/// nothing on the wire (KCP has no keepalive: an idle `flush(FULL)` has nothing to send).
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).update(); timedsched.go:TimedSched.sched()
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn update_task_flushes_an_idle_session_at_the_kcp_interval() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(120, None, None, &clock);
    // Go's default. The harness turns it on because 05.3/05.4 had no update task to flush the
    // ack list; with the task in place the session can run exactly as kcptun does.
    a.session.set_ack_no_delay(false);

    let before = a.flushes();
    a.start_updater();
    settle().await;
    // Go: `SystemTimedSched.Put(sess.update, time.Now())`, the first pass is immediate.
    assert_eq!(a.flushes(), before + 1, "the first flush is immediate");

    // One millisecond short of the interval, nothing has happened yet.
    advance(&clock, UPDATE_INTERVAL - Duration::from_millis(1)).await;
    assert_eq!(
        a.flushes(),
        before + 1,
        "no flush before the interval is up"
    );
    advance(&clock, Duration::from_millis(1)).await;
    assert_eq!(a.flushes(), before + 2);

    // And it keeps that cadence without drifting.
    for i in 3..=12 {
        advance(&clock, UPDATE_INTERVAL).await;
        assert_eq!(a.flushes(), before + i, "exactly one flush per interval");
    }

    assert!(
        a.flush_types().iter().all(|kind| *kind == IKCP_FLUSH_FULL),
        "update() always flushes with IKCP_FLUSH_FULL"
    );
    assert_eq!(
        a.conn.count(),
        0,
        "an idle session must stay silent: no keepalives, no probes"
    );

    a.shutdown().await;
}

/// Data that `Write` left queued (`-writedelay`) goes out on the next update tick.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).WriteBuffers() (the `writeDelay` branch) and
//     sess.go:(*UDPSession).update()
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn update_task_flushes_data_left_by_a_delayed_write() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(121, None, None, &clock);
    let mut b = Peer::start(121, None, None, &clock);
    a.session.set_write_delay(true);

    a.start_updater();
    settle().await;
    assert_eq!(a.conn.count(), 0, "an idle session sends nothing");

    let msg = payload(41, 100);
    assert_eq!(a.session.write(&msg).await.expect("queued"), msg.len());
    settle().await;
    assert_eq!(
        a.conn.count(),
        0,
        "with write_delay the flush is the update task's job"
    );

    // Not before the interval is up...
    advance(&clock, UPDATE_INTERVAL - Duration::from_millis(1)).await;
    assert_eq!(a.conn.count(), 0);
    // ...and then in that very tick, all the way onto the wire.
    advance(&clock, Duration::from_millis(1)).await;
    let packets = a.conn.take();
    assert_eq!(packets.len(), 1, "one datagram for one segment");
    deliver(&b, &packets);
    assert_eq!(b.drain(), vec![msg]);

    a.shutdown().await;
    b.shutdown().await;
}

/// Each pass notifies the writers when the send window has room, which is how a `Write` that
/// blocked on a full window is released even if no packet arrives to do it.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).update() (`if waitsnd < int(s.kcp.snd_wnd)`)
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn update_task_wakes_a_writer_once_the_window_has_room() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(122, None, None, &clock);

    // One segment in flight is already the whole window.
    a.session.set_window_size(1, 128);
    a.start_updater();
    settle().await;

    assert_eq!(a.session.write(b"a").await.expect("the window is empty"), 1);
    let blocked = spawn_write(&a, b"b".to_vec());
    settle().await;
    assert!(!blocked.is_finished(), "the send window is full");

    // Reopen the window without touching KCP's state: nothing here notifies the writer, so
    // only the update task's `waitsnd < snd_wnd` check can release it.
    a.session.set_window_size(1024, 128);
    settle().await;
    assert!(
        !blocked.is_finished(),
        "nothing has notified the writer yet"
    );

    advance(&clock, UPDATE_INTERVAL).await;
    let n = tokio::time::timeout(LIMIT, blocked)
        .await
        .expect("the update task must wake the writer")
        .expect("task")
        .expect("the window has room now");
    assert_eq!(n, 1);

    a.shutdown().await;
}

/// `Close` stops the task, and nothing flushes afterwards. The task holds a `Weak`, so it also
/// cannot keep a closed session alive.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).update() (`select { case <-s.die: }`)
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn update_task_stops_when_the_session_closes() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(123, None, None, &clock);
    a.start_updater();
    settle().await;
    let flushes = a.flushes();
    let weak = Arc::downgrade(&a.session);

    a.session.close().expect("first close");
    // Go's task stays in the scheduler until its timer fires and only then sees `die`; this one
    // leaves at once, `Close` having already queued the final flush (Deviation V05).
    let update = a.update.take().expect("spawned above");
    tokio::time::timeout(LIMIT, update)
        .await
        .expect("the update task must stop on close")
        .expect("the update task must not panic");
    assert_eq!(a.flushes(), flushes + 1, "only Close's own final flush");

    // Several intervals later there is still nothing new.
    advance(&clock, 4 * UPDATE_INTERVAL).await;
    assert_eq!(a.flushes(), flushes + 1);

    a.shutdown().await;
    drop(a);
    assert!(
        weak.upgrade().is_none(),
        "no task may outlive the session it flushes"
    );
}

/// A session dropped without `Close` retires the task instead of flushing forever, which is the
/// one thing the `Weak` reference buys over Go's scheduler-owned closure.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn update_task_retires_when_the_last_session_handle_is_dropped() {
    let _snmp = snmp_read();
    let clock = TestClock::new();
    let mut a = Peer::start(124, None, None, &clock);
    a.start_updater();
    settle().await;

    let update = a.update.take().expect("spawned above");
    let Peer {
        session, die, task, ..
    } = a;
    let weak = Arc::downgrade(&session);
    drop(session);
    assert!(
        weak.upgrade().is_none(),
        "the update task must not hold a strong reference"
    );

    advance(&clock, UPDATE_INTERVAL).await;
    tokio::time::timeout(LIMIT, update)
        .await
        .expect("the update task must retire with the session")
        .expect("the update task must not panic");

    // The tx task ends with the channel whose only sender lived in the session.
    die.cancel();
    tokio::time::timeout(LIMIT, task.expect("spawned by Peer::start"))
        .await
        .expect("the tx task must exit")
        .expect("the tx task must not panic");
}

/// `shrink_idle` (plan 12.3) hands back the ring capacity and the stream reassembly buffer that a
/// burst left behind, keeps everything that is still in use, and leaves the session working.
#[tokio::test]
async fn shrink_idle_returns_what_a_burst_left_behind() {
    let clock = TestClock::new();
    let peer = Peer::start(1, None, None, &clock);

    // A session that has done nothing has nothing to give back.
    assert!(!peer.session.shrink_idle());

    let (fresh_snd_queue, fresh_rcv_queue, fresh_snd_buf) = {
        let state = peer.session.lock();
        (
            state.kcp.snd_queue.max_len(),
            state.kcp.rcv_queue.max_len(),
            state.kcp.snd_buf.max_len(),
        )
    };

    // A burst: the production window, thousands of queued segments, and a large message that did
    // not fit a reader's buffer in one piece (`recvbuf`), fully consumed.
    {
        let mut state = peer.session.lock();
        state.kcp.wnd_size(8192, 8192);
        for i in 0..4000u32 {
            assert_eq!(state.kcp.send(&[i as u8; 500]), 0);
        }
        state.recvbuf = vec![0u8; 64 * 1024];
        state.bufptr = 64 * 1024;
    }
    assert!(peer.session.lock().kcp.snd_queue.max_len() > fresh_snd_queue);

    // The queues are full, so only the consumed `recvbuf` can go.
    assert!(peer.session.shrink_idle());
    {
        let state = peer.session.lock();
        assert_eq!(state.recvbuf.capacity(), 0);
        assert_eq!(state.bufptr, 0);
        assert!(
            state.kcp.snd_queue.max_len() > fresh_snd_queue,
            "still busy"
        );
    }

    // Drain, as an acknowledged session would, and the rings go too.
    {
        let mut state = peer.session.lock();
        state.kcp.snd_queue.clear();
        state.kcp.snd_buf.clear();
        state.kcp.rcv_queue.clear();
    }
    assert!(peer.session.shrink_idle());
    {
        let state = peer.session.lock();
        assert_eq!(state.kcp.snd_queue.max_len(), fresh_snd_queue);
        assert_eq!(state.kcp.rcv_queue.max_len(), fresh_rcv_queue);
        assert_eq!(state.kcp.snd_buf.max_len(), fresh_snd_buf);
    }

    // Nothing left to do, and the session still carries data.
    assert!(!peer.session.shrink_idle());
    let before = peer.conn.count();
    peer.send(b"after the shrink");
    tokio::time::timeout(LIMIT, peer.conn.wait_for(before + 1))
        .await
        .expect("the packet must still go out after a shrink");
}

/// A `recvbuf` that still holds unread bytes is never dropped: that would lose data the reader
/// has not seen.
#[tokio::test]
async fn shrink_idle_keeps_a_recvbuf_the_reader_has_not_finished() {
    let clock = TestClock::new();
    let peer = Peer::start(2, None, None, &clock);
    {
        let mut state = peer.session.lock();
        state.recvbuf = vec![7u8; 64 * 1024];
        // Half read.
        state.bufptr = 32 * 1024;
    }

    assert!(!peer.session.shrink_idle());
    let state = peer.session.lock();
    assert_eq!(state.recvbuf.len(), 64 * 1024);
    assert_eq!(state.bufptr, 32 * 1024);
    assert!(state.recvbuf[32 * 1024..].iter().all(|&b| b == 7));
}
