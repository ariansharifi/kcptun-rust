//! Tests of the tx pipeline: every packet that comes out of [`TxPipeline::run`] is checked
//! byte for byte against `docs/WIRE-FORMAT.md` §2, on a fake [`PacketConn`] that captures the
//! datagrams a real socket would send.
//!
//! `DEFAULT_SNMP` is process-global, so every test that moves a counter holds
//! `SNMP_TEST_LOCK` (the convention from 03.3), and the few that assert exact deltas hold it for
//! writing. Each test runs its own current-thread runtime, so keeping that guard across the
//! awaits of one test body cannot deadlock: readers never block each other, and a writer only
//! waits for test bodies that always finish.
#![allow(
    clippy::await_holding_lock,
    reason = "SNMP_TEST_LOCK serialises whole test bodies; see above"
)]

use std::future;
use std::sync::Mutex;
use std::sync::RwLockReadGuard;
use std::time::{Duration, Instant};

use kcptun_testkit::VirtualClock;

use super::*;
use crate::crypt::{
    AeadCrypt, CRC_SIZE, MTU_LIMIT, new_aes_block_crypt, new_aes_gcm_crypt, new_none_block_crypt,
};
use crate::fec::{
    FEC_HEADER_SIZE, FEC_HEADER_SIZE_PLUS2, FecDecoder, OOB_SEQID, TYPE_DATA, TYPE_OOB, TYPE_PARITY,
};
use crate::kcp::SNMP_TEST_LOCK;
use crate::packet_conn::{BoxFuture, RecvBatch, invalid_operation};
use crate::rate::BURST;

/// Every session test talks to this peer.
const REMOTE: &str = "192.0.2.10:29900";

/// Longest a test waits for the pipeline to catch up.
const LIMIT: Duration = Duration::from_secs(20);

/// Byte a packet buffer is filled with before the pipeline runs: anything still 0xee on the wire
/// is a byte the pipeline forgot to write (Go's pool hands out dirty buffers too).
const POISON: u8 = 0xee;

fn remote() -> SocketAddr {
    REMOTE.parse().expect("literal address")
}

fn snmp_read() -> RwLockReadGuard<'static, ()> {
    SNMP_TEST_LOCK.read().unwrap_or_else(|e| e.into_inner())
}

fn snmp_write() -> std::sync::RwLockWriteGuard<'static, ()> {
    SNMP_TEST_LOCK.write().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------------------------
// A PacketConn that records what the pipeline sends
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Captured {
    /// Every datagram, in the order it was handed to the socket.
    packets: Vec<(Vec<u8>, SocketAddr)>,
    /// Messages accepted per `send_batch` call.
    batches: Vec<usize>,
    /// Messages accepted per call; `None` accepts the whole batch (a complete `sendmmsg`).
    max_per_call: Option<usize>,
    /// Fail every call after this many have succeeded (Go: `WriteBatch` returning an error).
    fail_after: Option<usize>,
    calls: usize,
}

#[derive(Debug, Default)]
struct FakeConn {
    inner: Mutex<Captured>,
}

impl FakeConn {
    fn lock(&self) -> std::sync::MutexGuard<'_, Captured> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn packets(&self) -> Vec<Vec<u8>> {
        self.lock()
            .packets
            .iter()
            .map(|(data, _)| data.clone())
            .collect()
    }

    fn addrs(&self) -> Vec<SocketAddr> {
        self.lock().packets.iter().map(|(_, addr)| *addr).collect()
    }

    fn batches(&self) -> Vec<usize> {
        self.lock().batches.clone()
    }

    fn count(&self) -> usize {
        self.lock().packets.len()
    }

    fn set_max_per_call(&self, n: usize) {
        self.lock().max_per_call = Some(n);
    }

    fn fail_after(&self, n: usize) {
        self.lock().fail_after = Some(n);
    }

    /// Waits until at least `n` datagrams have been captured.
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

impl PacketConn for FakeConn {
    fn recv_batch<'a>(
        &'a self,
        _batch: &'a mut RecvBatch,
    ) -> BoxFuture<'a, std::io::Result<usize>> {
        // The tx pipeline never reads; a session's read loop is 05.6.
        Box::pin(future::pending())
    }

    fn send_batch<'a>(&'a self, msgs: &'a [TxMsg<'a>]) -> BoxFuture<'a, std::io::Result<usize>> {
        Box::pin(async move {
            let mut inner = self.lock();
            if let Some(limit) = inner.fail_after
                && inner.calls >= limit
            {
                inner.calls += 1;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::HostUnreachable,
                    "sendto: no route to host",
                ));
            }
            inner.calls += 1;
            let n = inner.max_per_call.unwrap_or(msgs.len()).min(msgs.len());
            for msg in &msgs[..n] {
                inner.packets.push((msg.data.to_vec(), msg.addr));
            }
            inner.batches.push(n);
            Ok(n)
        })
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok("127.0.0.1:1".parse().expect("literal address"))
    }

    fn set_read_buffer(&self, _bytes: usize) -> std::io::Result<()> {
        Err(invalid_operation())
    }

    fn set_write_buffer(&self, _bytes: usize) -> std::io::Result<()> {
        Err(invalid_operation())
    }

    fn set_dscp(&self, _dscp: i32) -> std::io::Result<()> {
        Err(invalid_operation())
    }

    fn close(&self) -> std::io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

/// A tx pipeline with its fake socket, buffer pool and clock.
struct Harness {
    handle: TxHandle,
    conn: Arc<FakeConn>,
    pool: Arc<BufferPool>,
    clock: VirtualClock,
    die: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
    /// Bytes reserved in front of every packet: crypto header plus FEC header.
    header_size: usize,
}

/// Go's `headerSize`: the crypto header, plus 8 bytes when FEC is on.
// Go: kcp-go/v5@v5.6.66 sess.go:newUDPSession()
fn crypto_header(block: Option<&PacketCrypt>) -> usize {
    match block {
        None => 0,
        Some(PacketCrypt::Aead(aead)) => aead.nonce_size(),
        Some(PacketCrypt::Block(_)) => CRYPT_HEADER_SIZE,
    }
}

fn build(
    block: Option<PacketCrypt>,
    fec: Option<(isize, isize)>,
) -> (Harness, TxPipeline<impl Clock>) {
    let crypto_header = crypto_header(block.as_ref());
    let fec_encoder = fec.map(|(ds, ps)| {
        FecEncoder::new(ds, ps, crypto_header)
            .expect("valid shard counts")
            .expect("FEC enabled")
    });
    let header_size = crypto_header
        + if fec_encoder.is_some() {
            FEC_HEADER_SIZE_PLUS2
        } else {
            0
        };

    let conn = Arc::new(FakeConn::default());
    let pool = BufferPool::new(4096);
    let die = CancellationToken::new();
    let clock = VirtualClock::new();
    let (handle, pipeline) = channel(TxConfig {
        conn: Arc::clone(&conn) as Arc<dyn PacketConn>,
        remote: remote(),
        block,
        fec_encoder,
        pool: Arc::clone(&pool),
        clock: {
            let clock = clock.clone();
            move || clock.now_ms()
        },
        die: die.clone(),
    });
    let harness = Harness {
        handle,
        conn,
        pool,
        clock,
        die,
        task: None,
        header_size,
    };
    (harness, pipeline)
}

impl Harness {
    /// A running pipeline.
    fn start(block: Option<PacketCrypt>, fec: Option<(isize, isize)>) -> Harness {
        let (mut harness, pipeline) = build(block, fec);
        harness.task = Some(tokio::spawn(pipeline.run()));
        harness
    }

    /// The same, but the pipeline is never spawned, so nothing drains the channel.
    fn stalled(
        block: Option<PacketCrypt>,
        fec: Option<(isize, isize)>,
    ) -> (Harness, TxPipeline<impl Clock>) {
        build(block, fec)
    }

    /// Builds a request the way the KCP output callback does: a pooled buffer with
    /// `header_size` bytes of room in front of the payload, poisoned so that any byte the
    /// pipeline fails to write is visible on the wire.
    // Go: kcp-go/v5@v5.6.66 sess.go:newUDPSession() (`Get()[:size+headerSize]`, `copy(bts[hs:])`)
    fn request(&self, payload: &[u8]) -> SendRequest {
        let mut buf = self.pool.get(self.header_size + payload.len());
        buf.full_mut().fill(POISON);
        buf.as_mut_slice()[self.header_size..].copy_from_slice(payload);
        SendRequest::data(buf)
    }

    fn send(&self, payload: &[u8]) -> SendOutcome {
        self.handle.send(self.request(payload))
    }

    /// An OOB request: `| conv (4B) | payload |` after the header (Go's `SendOOB`).
    fn send_oob(&self, conv: u32, payload: &[u8]) -> SendOutcome {
        let mut buf = self.pool.get(self.header_size + 4 + payload.len());
        buf.full_mut().fill(POISON);
        let body = &mut buf.as_mut_slice()[self.header_size..];
        body[..4].copy_from_slice(&conv.to_le_bytes());
        body[4..].copy_from_slice(payload);
        self.handle.send(SendRequest::oob(buf))
    }

    /// Closes the session and waits for the pipeline to finish draining (Deviation V05).
    async fn shutdown(&mut self) {
        self.die.cancel();
        if let Some(task) = self.task.take() {
            tokio::time::timeout(LIMIT, task)
                .await
                .expect("the tx task must exit on die")
                .expect("the tx task must not panic");
        }
    }
}

/// A KCP-sized payload: `len` bytes with a recognisable pattern.
fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
}

fn aes_crypt() -> PacketCrypt {
    PacketCrypt::Block(new_aes_block_crypt(&[7u8; 32]).expect("aes-256 key"))
}

fn none_crypt() -> PacketCrypt {
    PacketCrypt::Block(new_none_block_crypt(&[]).expect("none cipher"))
}

fn gcm_crypt() -> PacketCrypt {
    new_aes_gcm_crypt(&[9u8; 16]).expect("aes-128-gcm key")
}

/// Feeds the captured FEC frames (the packets with their crypto layer removed) to a decoder with
/// frame `lost` held back, and reports whether the decoder gave that frame's payload back.
fn recovers_lost_shard(ds: usize, ps: usize, frames: &[&[u8]], lost: usize, data: &[u8]) -> bool {
    let mut decoder = FecDecoder::new(ds as isize, ps as isize).expect("decoder");
    let mut recovered = Vec::new();
    for (i, frame) in frames.iter().enumerate() {
        if i == lost {
            continue; // lost on the network
        }
        recovered.extend(decoder.decode(frame));
    }
    // A recovered shard is `| size (2B) | payload |`, padded to the group's longest shard.
    recovered.iter().any(|shard| {
        let size = u16::from_le_bytes(shard[0..2].try_into().expect("2")) as usize;
        size >= 2 && size <= shard.len() && shard[2..size] == *data
    })
}

// ---------------------------------------------------------------------------------------------
// Packet layout (docs/WIRE-FORMAT.md §2)
// ---------------------------------------------------------------------------------------------

/// `-crypt null`: the KCP bytes reach the socket untouched, and go to `s.remote`.
#[tokio::test(flavor = "current_thread")]
async fn null_crypt_sends_the_packet_verbatim() {
    let _snmp = snmp_read();
    let mut h = Harness::start(None, None);
    assert_eq!(h.header_size, 0);

    let data = payload(1, 64);
    assert_eq!(h.send(&data), SendOutcome::Queued);
    h.conn.wait_for(1).await;

    assert_eq!(h.conn.packets(), vec![data]);
    assert_eq!(h.conn.addrs(), vec![remote()]);
    h.shutdown().await;
}

/// `-crypt none`: the identity cipher, so the packet is `nonce(16) | crc32(4) | payload` in
/// clear text. The checksum is CRC-32/IEEE over everything after it, stored little-endian.
#[tokio::test(flavor = "current_thread")]
async fn none_crypt_writes_a_random_nonce_and_crc32() {
    let _snmp = snmp_read();
    let mut h = Harness::start(Some(none_crypt()), None);
    assert_eq!(h.header_size, CRYPT_HEADER_SIZE);

    let data = payload(2, 100);
    h.send(&data);
    h.send(&data);
    h.conn.wait_for(2).await;

    let packets = h.conn.packets();
    for pkt in &packets {
        assert_eq!(pkt.len(), CRYPT_HEADER_SIZE + data.len());
        assert_eq!(&pkt[CRYPT_HEADER_SIZE..], &data[..], "payload is unchanged");
        let crc = u32::from_le_bytes(
            pkt[NONCE_SIZE..CRYPT_HEADER_SIZE]
                .try_into()
                .expect("4 bytes"),
        );
        assert_eq!(crc, crc32fast::hash(&pkt[CRYPT_HEADER_SIZE..]));
        assert_eq!(CRC_SIZE, 4);
        // Pin the polynomial, not just the range: the standard CRC-32/IEEE check value, i.e.
        // Go's crc32.ChecksumIEEE([]byte("123456789")).
        assert_eq!(crc32fast::hash(b"123456789"), 0xcbf4_3926);
        assert!(
            pkt[..NONCE_SIZE].iter().any(|&b| b != POISON),
            "the nonce must be overwritten with random bytes"
        );
    }
    assert_ne!(
        packets[0][..NONCE_SIZE],
        packets[1][..NONCE_SIZE],
        "every packet gets a fresh nonce"
    );
    h.shutdown().await;
}

/// `-crypt aes`: the same layout, but the whole buffer (nonce included) is encrypted, so
/// decrypting has to give back the checksum and the payload.
#[tokio::test(flavor = "current_thread")]
async fn aes_crypt_encrypts_the_whole_packet() {
    let _snmp = snmp_read();
    let mut h = Harness::start(Some(aes_crypt()), None);

    let data = payload(3, 137);
    h.send(&data);
    h.conn.wait_for(1).await;

    let mut pkt = h.conn.packets().remove(0);
    assert_eq!(pkt.len(), CRYPT_HEADER_SIZE + data.len());
    assert_ne!(
        &pkt[CRYPT_HEADER_SIZE..],
        &data[..],
        "ciphertext on the wire"
    );

    let PacketCrypt::Block(block) = aes_crypt() else {
        unreachable!("aes is a block cipher")
    };
    block.decrypt(&mut pkt);
    assert_eq!(&pkt[CRYPT_HEADER_SIZE..], &data[..]);
    let crc = u32::from_le_bytes(
        pkt[NONCE_SIZE..CRYPT_HEADER_SIZE]
            .try_into()
            .expect("4 bytes"),
    );
    assert_eq!(crc, crc32fast::hash(&data));
    h.shutdown().await;
}

/// `-crypt aes-128-gcm`: a 12-byte nonce, no checksum, and the packet grows by the 16-byte tag.
#[tokio::test(flavor = "current_thread")]
async fn aead_crypt_seals_the_packet_in_place() {
    let _snmp = snmp_read();
    let mut h = Harness::start(Some(gcm_crypt()), None);
    assert_eq!(h.header_size, AeadCrypt::NONCE);

    let data = payload(4, 200);
    h.send(&data);
    h.conn.wait_for(1).await;

    let mut pkt = h.conn.packets().remove(0);
    assert_eq!(
        pkt.len(),
        AeadCrypt::NONCE + data.len() + AeadCrypt::OVERHEAD
    );
    assert!(pkt[..AeadCrypt::NONCE].iter().any(|&b| b != POISON));

    let PacketCrypt::Aead(aead) = gcm_crypt() else {
        unreachable!("aes-128-gcm is an AEAD")
    };
    let plain = aead.open_in_place(&mut pkt).expect("authenticates");
    assert_eq!(plain, &data[..]);
    h.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// FEC, duplicates and OOB
// ---------------------------------------------------------------------------------------------

/// With FEC on, every packet carries the 8-byte FEC header (seqid, type, size) and the parity
/// shards of a completed group follow the packet that completed it. The captured bytes are fed
/// to a decoder, which must recover a dropped data shard from them.
#[tokio::test(flavor = "current_thread")]
async fn fec_queues_data_packets_then_parity() {
    let _snmp = snmp_read();
    let (ds, ps) = (3usize, 2usize);
    let mut h = Harness::start(None, Some((ds as isize, ps as isize)));
    assert_eq!(h.header_size, FEC_HEADER_SIZE_PLUS2);

    let payloads: Vec<Vec<u8>> = (0..ds).map(|i| payload(10 * i as u8, 40 + 7 * i)).collect();
    for data in &payloads {
        h.send(data);
        // A group is only protected when its packets are less than 500 ms apart.
        h.clock.advance(1);
    }
    h.conn.wait_for(ds + ps).await;
    let packets = h.conn.packets();
    assert_eq!(packets.len(), ds + ps, "3 data shards and 2 parity shards");

    // Data shards: seqid 0..3, type 0xf1, size = len - payloadOffset, then the KCP bytes.
    for (i, (pkt, data)) in packets[..ds].iter().zip(&payloads).enumerate() {
        assert_eq!(pkt.len(), FEC_HEADER_SIZE_PLUS2 + data.len());
        assert_eq!(
            u32::from_le_bytes(pkt[0..4].try_into().expect("4")),
            i as u32
        );
        assert_eq!(
            u16::from_le_bytes(pkt[4..6].try_into().expect("2")),
            TYPE_DATA
        );
        assert_eq!(
            u16::from_le_bytes(pkt[6..8].try_into().expect("2")) as usize,
            pkt.len() - FEC_HEADER_SIZE,
        );
        assert_eq!(&pkt[FEC_HEADER_SIZE_PLUS2..], &data[..]);
    }

    // Parity shards: seqid 3 and 4, type 0xf2, all of the group's longest length.
    let max_size = packets[..ds].iter().map(Vec::len).max().expect("group");
    for (k, pkt) in packets[ds..].iter().enumerate() {
        assert_eq!(pkt.len(), max_size);
        assert_eq!(
            u32::from_le_bytes(pkt[0..4].try_into().expect("4")),
            (ds + k) as u32
        );
        assert_eq!(
            u16::from_le_bytes(pkt[4..6].try_into().expect("2")),
            TYPE_PARITY
        );
    }

    // The bytes really are a usable FEC group: drop the middle data shard and recover it.
    let frames: Vec<&[u8]> = packets.iter().map(Vec::as_slice).collect();
    assert!(
        recovers_lost_shard(ds, ps, &frames, 1, &payloads[1]),
        "FEC must recover the dropped data shard"
    );
    h.shutdown().await;
}

/// The parity shards get the same crypto treatment as data packets, which is the one place where
/// this port deliberately diverges from Go: Go seals `ecc[k]` in place inside the encoder's shard
/// cache and copies it into a pooled buffer afterwards, while [`TxPipeline::process`] copies
/// first and seals the copy. The bytes on the wire must be indistinguishable — a fresh 16-byte
/// nonce, CRC-32/IEEE over everything after the crypto header, and the whole buffer encrypted —
/// or a Go peer counts every parity packet as `InCsumErrors` and FEC never recovers anything.
#[tokio::test(flavor = "current_thread")]
async fn parity_shards_are_sealed_like_data_packets() {
    let _snmp = snmp_read();
    let (ds, ps) = (3usize, 2usize);
    let mut h = Harness::start(Some(aes_crypt()), Some((ds as isize, ps as isize)));
    assert_eq!(h.header_size, CRYPT_HEADER_SIZE + FEC_HEADER_SIZE_PLUS2);

    let payloads: Vec<Vec<u8>> = (0..ds).map(|i| payload(20 * i as u8, 40 + 7 * i)).collect();
    for data in &payloads {
        h.send(data);
        h.clock.advance(1);
    }
    h.conn.wait_for(ds + ps).await;
    let mut packets = h.conn.packets();
    assert_eq!(packets.len(), ds + ps, "3 data shards and 2 parity shards");

    let PacketCrypt::Block(block) = aes_crypt() else {
        unreachable!("aes is a block cipher")
    };
    let mut nonces = Vec::new();
    for pkt in &mut packets {
        block.decrypt(pkt);
        let crc = u32::from_le_bytes(
            pkt[NONCE_SIZE..CRYPT_HEADER_SIZE]
                .try_into()
                .expect("4 bytes"),
        );
        assert_eq!(
            crc,
            crc32fast::hash(&pkt[CRYPT_HEADER_SIZE..]),
            "CRC-32/IEEE over everything after the crypto header, little-endian"
        );
        nonces.push(pkt[..NONCE_SIZE].to_vec());
    }
    nonces.sort_unstable();
    nonces.dedup();
    assert_eq!(
        nonces.len(),
        ds + ps,
        "every packet, parity included, carries its own random nonce"
    );

    // Parity shards: seqid 3 and 4, type 0xf2, padded to the group's longest data shard.
    let max_size = packets[..ds].iter().map(Vec::len).max().expect("group");
    for (k, pkt) in packets[ds..].iter().enumerate() {
        assert_eq!(pkt.len(), max_size);
        let fec = &pkt[CRYPT_HEADER_SIZE..];
        assert_eq!(
            u32::from_le_bytes(fec[0..4].try_into().expect("4")),
            (ds + k) as u32
        );
        assert_eq!(
            u16::from_le_bytes(fec[4..6].try_into().expect("2")),
            TYPE_PARITY
        );
    }

    // And the decrypted group still recovers a dropped data shard.
    let frames: Vec<&[u8]> = packets
        .iter()
        .map(|pkt| &pkt[CRYPT_HEADER_SIZE..])
        .collect();
    assert!(
        recovers_lost_shard(ds, ps, &frames, 1, &payloads[1]),
        "FEC must recover the dropped data shard from the decrypted parity"
    );
    h.shutdown().await;
}

/// The same for an AEAD: a parity shard is sealed in its own pooled buffer, so it leaves the
/// pipeline `max_size + 16` bytes long and authenticates under the group's own nonce.
#[tokio::test(flavor = "current_thread")]
async fn aead_parity_shards_grow_by_the_tag() {
    let _snmp = snmp_read();
    let (ds, ps) = (3usize, 2usize);
    let mut h = Harness::start(Some(gcm_crypt()), Some((ds as isize, ps as isize)));
    assert_eq!(h.header_size, AeadCrypt::NONCE + FEC_HEADER_SIZE_PLUS2);

    let payloads: Vec<Vec<u8>> = (0..ds).map(|i| payload(30 * i as u8, 60 + 9 * i)).collect();
    for data in &payloads {
        h.send(data);
        h.clock.advance(1);
    }
    h.conn.wait_for(ds + ps).await;
    let mut packets = h.conn.packets();
    assert_eq!(packets.len(), ds + ps);

    // `max_size` is the length of the longest *sealed* data shard before its tag.
    let max_size = packets[..ds]
        .iter()
        .map(|pkt| pkt.len() - AeadCrypt::OVERHEAD)
        .max()
        .expect("group");
    for pkt in &packets[ds..] {
        assert_eq!(
            pkt.len(),
            max_size + AeadCrypt::OVERHEAD,
            "a parity shard is padded to the group and then grows by the tag"
        );
    }

    let mut nonces = Vec::new();
    for pkt in &packets {
        nonces.push(pkt[..AeadCrypt::NONCE].to_vec());
    }
    nonces.sort_unstable();
    nonces.dedup();
    assert_eq!(nonces.len(), ds + ps, "every packet gets a fresh nonce");

    let PacketCrypt::Aead(aead) = gcm_crypt() else {
        unreachable!("aes-128-gcm is an AEAD")
    };
    let frames: Vec<Vec<u8>> = packets
        .iter_mut()
        .map(|pkt| {
            aead.open_in_place(pkt)
                .expect("every packet, parity included, authenticates")
                .to_vec()
        })
        .collect();

    for (k, frame) in frames[ds..].iter().enumerate() {
        assert_eq!(frame.len(), max_size - AeadCrypt::NONCE);
        assert_eq!(
            u32::from_le_bytes(frame[0..4].try_into().expect("4")),
            (ds + k) as u32
        );
        assert_eq!(
            u16::from_le_bytes(frame[4..6].try_into().expect("2")),
            TYPE_PARITY
        );
    }

    let frames: Vec<&[u8]> = frames.iter().map(Vec::as_slice).collect();
    assert!(
        recovers_lost_shard(ds, ps, &frames, 0, &payloads[0]),
        "FEC must recover the dropped data shard from the opened parity"
    );
    h.shutdown().await;
}

/// `SetDUP(n)` sends n extra copies of every packet, queued right after the original and before
/// the parity shards (Go's append order in `postProcess`).
#[tokio::test(flavor = "current_thread")]
async fn dup_copies_follow_the_original_and_precede_parity() {
    let _snmp = snmp_read();
    let mut h = Harness::start(None, Some((2, 1)));
    h.handle.shared().set_dup(2);
    assert_eq!(h.handle.shared().dup(), 2);

    let first = payload(1, 32);
    let second = payload(2, 48);
    h.send(&first);
    h.clock.advance(1);
    h.send(&second);
    // 2 packets x (1 original + 2 dups) + 1 parity shard.
    h.conn.wait_for(7).await;

    let packets = h.conn.packets();
    assert_eq!(packets.len(), 7);
    assert_eq!(packets[0], packets[1], "dup copies are byte-identical");
    assert_eq!(packets[0], packets[2]);
    assert_eq!(&packets[0][FEC_HEADER_SIZE_PLUS2..], &first[..]);
    assert_eq!(packets[3], packets[4]);
    assert_eq!(packets[3], packets[5]);
    assert_eq!(&packets[3][FEC_HEADER_SIZE_PLUS2..], &second[..]);
    assert_eq!(
        u16::from_le_bytes(packets[6][4..6].try_into().expect("2")),
        TYPE_PARITY,
        "the parity shard comes last"
    );
    h.shutdown().await;
}

/// An OOB packet gets the OOB seqid and type, never becomes part of a FEC group, and produces
/// no parity of its own.
#[tokio::test(flavor = "current_thread")]
async fn oob_packets_are_sealed_with_the_oob_header() {
    let _snmp = snmp_read();
    let mut h = Harness::start(Some(none_crypt()), Some((2, 1)));
    assert_eq!(h.header_size, CRYPT_HEADER_SIZE + FEC_HEADER_SIZE_PLUS2);

    let data = payload(5, 24);
    assert_eq!(h.send_oob(0xdead_beef, &data), SendOutcome::Queued);
    h.conn.wait_for(1).await;
    let pkt = h.conn.packets().remove(0);

    let fec = &pkt[CRYPT_HEADER_SIZE..];
    assert_eq!(
        u32::from_le_bytes(fec[0..4].try_into().expect("4")),
        OOB_SEQID
    );
    assert_eq!(
        u16::from_le_bytes(fec[4..6].try_into().expect("2")),
        TYPE_OOB
    );
    assert_eq!(
        u16::from_le_bytes(fec[6..8].try_into().expect("2")) as usize,
        fec.len() - FEC_HEADER_SIZE
    );
    assert_eq!(
        u32::from_le_bytes(fec[8..12].try_into().expect("4")),
        0xdead_beef,
        "the OOB body starts with the conv"
    );
    assert_eq!(&fec[12..], &data[..]);

    // Two data packets still complete their own group: the OOB packet consumed no seqid.
    h.send(&payload(6, 10));
    h.clock.advance(1);
    h.send(&payload(7, 10));
    h.conn.wait_for(4).await;
    let packets = h.conn.packets();
    let seqid = |pkt: &Vec<u8>| {
        u32::from_le_bytes(
            pkt[CRYPT_HEADER_SIZE..CRYPT_HEADER_SIZE + 4]
                .try_into()
                .expect("4"),
        )
    };
    assert_eq!(seqid(&packets[1]), 0);
    assert_eq!(seqid(&packets[2]), 1);
    assert_eq!(seqid(&packets[3]), 2);
    h.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// Batching, pacing and accounting
// ---------------------------------------------------------------------------------------------

/// Go transmits when the channel runs empty or the queue holds `maxBatchSize` messages. On a
/// current-thread runtime the pipeline cannot run until the test awaits, so 100 queued packets
/// come out as one full batch of 64 and a remainder of 36.
#[tokio::test(flavor = "current_thread")]
async fn batches_are_capped_at_max_batch_size() {
    let _snmp = snmp_read();
    let mut h = Harness::start(None, None);

    let data = payload(8, 50);
    for _ in 0..100 {
        assert_eq!(h.send(&data), SendOutcome::Queued);
    }
    assert_eq!(h.handle.queued(), 100);
    h.conn.wait_for(100).await;

    assert_eq!(h.conn.batches(), vec![MAX_BATCH_SIZE, 36]);
    assert_eq!(MAX_BATCH_SIZE, 64);
    h.shutdown().await;
}

/// A socket that accepts only part of a batch (a short `sendmmsg`) must be called again with the
/// rest, exactly as Go's `txqueue = txqueue[n:]` loop does.
#[tokio::test(flavor = "current_thread")]
async fn partial_batches_are_resent() {
    let _snmp = snmp_read();
    let mut h = Harness::start(None, None);
    h.conn.set_max_per_call(3);

    let payloads: Vec<Vec<u8>> = (0..10).map(|i| payload(i, 16 + i as usize)).collect();
    for data in &payloads {
        h.send(data);
    }
    h.conn.wait_for(10).await;

    assert_eq!(h.conn.packets(), payloads, "same packets, same order");
    assert_eq!(h.conn.batches(), vec![3, 3, 3, 1]);
    h.shutdown().await;
}

/// A write error is recorded once, wakes whoever waits on it, and stops the batch (Go's
/// `notifyWriteError` + `break`). Later batches keep the first error.
#[tokio::test(flavor = "current_thread")]
async fn write_errors_are_recorded_once_and_wake_waiters() {
    let _snmp = snmp_read();
    let mut h = Harness::start(None, None);
    let shared = Arc::clone(h.handle.shared());
    assert!(!shared.write_error().is_set());

    let waiter = {
        let shared = Arc::clone(&shared);
        tokio::spawn(async move { shared.write_error().wait().await })
    };
    tokio::task::yield_now().await;

    h.conn.fail_after(0);
    h.send(&payload(9, 20));
    tokio::time::timeout(LIMIT, waiter)
        .await
        .expect("the waiter must be woken")
        .expect("task");

    let err = shared.write_error().io_error().expect("error recorded");
    assert_eq!(err.kind(), std::io::ErrorKind::HostUnreachable);
    assert_eq!(err.to_string(), "sendto: no route to host");
    assert_eq!(h.conn.count(), 0, "nothing reached the wire");

    // A second failure does not replace the first.
    h.send(&payload(10, 20));
    tokio::task::yield_now().await;
    assert_eq!(
        shared.write_error().io_error().expect("error").to_string(),
        "sendto: no route to host"
    );
    h.shutdown().await;
}

/// `OutPkts` and `OutBytes` count what actually went out, including dup copies and parity.
#[tokio::test(flavor = "current_thread")]
async fn snmp_counts_packets_and_bytes_sent() {
    let _snmp = snmp_write();
    let before_pkts = DEFAULT_SNMP.out_pkts.load(Ordering::Relaxed);
    let before_bytes = DEFAULT_SNMP.out_bytes.load(Ordering::Relaxed);

    let mut h = Harness::start(None, None);
    h.handle.shared().set_dup(1);
    let data = payload(11, 70);
    h.send(&data);
    h.send(&data);
    h.conn.wait_for(4).await;

    assert_eq!(
        DEFAULT_SNMP.out_pkts.load(Ordering::Relaxed) - before_pkts,
        4
    );
    assert_eq!(
        DEFAULT_SNMP.out_bytes.load(Ordering::Relaxed) - before_bytes,
        4 * data.len() as u64
    );
    h.shutdown().await;
}

/// Nothing is counted (and nothing is sent) when the socket fails.
#[tokio::test(flavor = "current_thread")]
async fn snmp_is_not_advanced_by_a_failed_batch() {
    let _snmp = snmp_write();
    let before = DEFAULT_SNMP.out_pkts.load(Ordering::Relaxed);
    let mut h = Harness::start(None, None);
    h.conn.fail_after(0);
    h.send(&payload(12, 30));
    h.shutdown().await;
    assert_eq!(DEFAULT_SNMP.out_pkts.load(Ordering::Relaxed), before);
}

/// The rate limiter is charged for the whole batch in bytes: once the burst is spent, the next
/// batch waits.
#[tokio::test(flavor = "current_thread")]
async fn rate_limit_paces_the_batch() {
    let _snmp = snmp_read();
    let mut h = Harness::start(None, None);
    h.handle.shared().set_rate_limit(100_000);
    // Spend the initial burst, as a session that has been sending for a while would have.
    let limiter = h.handle.shared().limiter();
    assert_eq!(limiter.reserve_n(Instant::now(), BURST), Duration::ZERO);

    let data = payload(13, 1400);
    let start = Instant::now();
    h.send(&data);
    h.conn.wait_for(1).await;
    let elapsed = start.elapsed();
    // 1400 bytes at 100 kB/s is 14 ms; allow for a coarse timer but require real pacing.
    assert!(
        elapsed >= Duration::from_millis(8),
        "sent after {elapsed:?}"
    );

    // Without a limit the same packet goes out immediately.
    h.handle.shared().set_rate_limit(0);
    assert!(h.handle.shared().limiter().is_unlimited());
    let start = Instant::now();
    h.send(&data);
    h.conn.wait_for(2).await;
    assert!(start.elapsed() < Duration::from_millis(500));
    h.shutdown().await;
}

// ---------------------------------------------------------------------------------------------
// Buffer lifetime and shutdown
// ---------------------------------------------------------------------------------------------

/// Every buffer the pipeline touches goes back to the pool: the packet, its dup copies and the
/// parity shards.
#[tokio::test(flavor = "current_thread")]
async fn buffers_are_recycled_after_transmit() {
    let _snmp = snmp_read();
    let mut h = Harness::start(None, Some((2, 1)));
    h.handle.shared().set_dup(1);

    for i in 0..10 {
        h.send(&payload(i, 100));
        h.clock.advance(1);
    }
    // 10 packets + 10 dups + 5 parity shards.
    h.conn.wait_for(25).await;
    h.shutdown().await;

    let stats = h.pool.stats();
    assert_eq!(stats.gets, 25, "one buffer per datagram");
    assert_eq!(stats.recycled, 25, "and every one of them came back");
    assert_eq!(stats.discarded, 0);
    assert_eq!(
        h.pool.parked(),
        25,
        "and is parked, ready for the next packets"
    );
}

/// A full channel drops the packet and recycles its buffer instead of blocking the KCP output
/// callback, which runs under the session lock.
#[tokio::test(flavor = "current_thread")]
async fn a_full_channel_drops_and_recycles() {
    let (h, pipeline) = Harness::stalled(None, None);
    let data = payload(14, 64);
    for i in 0..DEV_BACKLOG {
        assert_eq!(h.send(&data), SendOutcome::Queued, "packet {i}");
    }
    assert_eq!(h.handle.queued(), DEV_BACKLOG);

    let before = h.pool.stats();
    assert_eq!(h.send(&data), SendOutcome::Dropped);
    let after = h.pool.stats();
    assert_eq!(after.gets, before.gets + 1);
    assert_eq!(
        after.recycled + after.discarded,
        before.recycled + before.discarded + 1,
        "the dropped packet's buffer must be released at once"
    );

    // Once the pipeline is gone the session learns that it is closed.
    drop(pipeline);
    assert_eq!(h.send(&data), SendOutcome::Closed);
}

/// Deviation V18: [`TxHandle::capacity`] is the free-slot count `Kcp::flush` stops on. It falls
/// to zero exactly when the next `send` would be dropped, and a closed channel reports
/// [`usize::MAX`] so that a session whose tx task has gone keeps flushing (and dropping) rather
/// than stalling for good.
#[tokio::test(flavor = "current_thread")]
async fn capacity_reports_the_free_slots_and_ignores_a_closed_channel() {
    let (h, pipeline) = Harness::stalled(None, None);
    let data = payload(21, 64);
    assert_eq!(h.handle.capacity(), DEV_BACKLOG, "an idle channel is empty");
    for i in 0..DEV_BACKLOG {
        assert_eq!(h.send(&data), SendOutcome::Queued, "packet {i}");
        assert_eq!(
            h.handle.capacity(),
            DEV_BACKLOG - i - 1,
            "one slot fewer after packet {i}"
        );
    }
    assert_eq!(h.handle.capacity(), 0, "the next send would be dropped");
    assert_eq!(h.send(&data), SendOutcome::Dropped);

    drop(pipeline);
    assert_eq!(
        h.handle.capacity(),
        usize::MAX,
        "a closed channel never frees its permits again"
    );
}

/// Everything already queued when the session dies is still sent, like Go's `postProcess`, which
/// blocks its `die` case while `chPostProcessing` is non-empty. (What Go drops on close is the
/// packet still being handed over, because its output callback races `die` against the channel
/// send; [`TxHandle::send`] does not — Deviation V05.)
#[tokio::test(flavor = "current_thread")]
async fn queued_packets_are_drained_on_die() {
    let _snmp = snmp_read();
    let mut h = Harness::start(None, None);

    let payloads: Vec<Vec<u8>> = (0..200).map(|i| payload(i as u8, 20 + i % 30)).collect();
    for data in &payloads {
        assert_eq!(h.send(data), SendOutcome::Queued);
    }
    // Close before the pipeline has had any chance to run.
    h.die.cancel();
    h.shutdown().await;

    assert_eq!(h.conn.packets(), payloads, "no packet may be lost on close");
}

/// An idle pipeline exits on `die` without sending anything.
#[tokio::test(flavor = "current_thread")]
async fn idle_pipeline_exits_on_die() {
    let mut h = Harness::start(None, None);
    h.shutdown().await;
    assert_eq!(h.conn.count(), 0);
}

/// Dropping the session's handles ends the task as well, without losing what was queued (in Go
/// the goroutine would stay parked on the channel forever).
#[tokio::test(flavor = "current_thread")]
async fn dropping_the_handle_ends_the_task() {
    let _snmp = snmp_read();
    let (h, pipeline) = Harness::stalled(None, None);
    let task = tokio::spawn(pipeline.run());
    h.send(&payload(15, 10));

    let conn = Arc::clone(&h.conn);
    let clone = h.handle.clone();
    drop(clone);
    drop(h); // the last sender

    tokio::time::timeout(LIMIT, task)
        .await
        .expect("the task must exit when the channel closes")
        .expect("task");
    assert_eq!(conn.count(), 1, "the queued packet is still sent");
}

/// A packet that fills the MTU still fits after the AEAD tag is appended.
#[tokio::test(flavor = "current_thread")]
async fn largest_aead_packet_fits_the_buffer() {
    let _snmp = snmp_read();
    let mut h = Harness::start(Some(gcm_crypt()), Some((2, 1)));
    // Go: kcp.mtu = min(1500, mtu) - headerSize - 16, so the largest buffer the output callback
    // ever hands over is mtuLimit - AEAD overhead.
    let data = payload(16, MTU_LIMIT - AeadCrypt::OVERHEAD - h.header_size);
    h.send(&data);
    h.conn.wait_for(1).await;

    let mut pkt = h.conn.packets().remove(0);
    assert_eq!(pkt.len(), MTU_LIMIT);
    let PacketCrypt::Aead(aead) = gcm_crypt() else {
        unreachable!("aes-128-gcm is an AEAD")
    };
    let plain = aead.open_in_place(&mut pkt).expect("authenticates");
    assert_eq!(&plain[FEC_HEADER_SIZE_PLUS2..], &data[..]);
    h.shutdown().await;
}
