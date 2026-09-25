//! Ports of kcp-go's `sess_test.go` (reference/latest, kcp-go v5.6.72), asserting the **pinned**
//! v5.6.66 behaviour the port implements: the pinned behaviour is what these ports assert, and
//! the only post-pin change to `Read`/`WriteBuffers` is the `RESET_TIMER` timer reuse, which no
//! ported test exercises. (`postProcess` also dropped its `panic(err)` on `limiter.WaitN`
//! post-pin; that one is adopted as V01 and these tests do walk it via `set_rate_limit`.)
//! They run the real thing: a
//! [`Listener`] on loopback with its monitor task, dialled [`UdpSession`]s with their read loops,
//! tx pipelines and update tasks: the whole of Step 05 end to end.
//!
//! Adaptations to the port, all of them noted at the tests:
//!
//! - **Ports.** Go's `nextPort()` hands out fixed ports from 10001 up; here every listener binds
//!   `127.0.0.1:0` and the client dials the address it reports, so parallel test threads (and
//!   parallel `cargo test` processes) never collide.
//! - **Sizes.** Go echoes 100 MB per `*SendRecv` test and takes minutes. The ports echo
//!   [`ECHO_BYTES`] (4 MiB) with proportionally smaller chunks; [`test_1gb_echo`] keeps Go's
//!   gigabyte and is `#[ignore]`, as is the full 1024-client fan-out. Go's `Test6GBEcho` is not
//!   ported (it is `Test1GBEcho` with a bigger constant).
//! - **Randomness.** Go seeds `math/rand` from the wall clock and re-derives the expected bytes
//!   from the same seed. The ports use the testkit [`Pcg`] with a fixed seed per test, so a
//!   failure is reproducible. The expected stream is regenerated with [`ChunkGen`], which replays
//!   the writer's exact sequence of chunk lengths and `fill_bytes` calls (the PRNG draws whole
//!   8-byte words, so the bytes do depend on where the chunks end).
//! - **Waits.** Where Go sleeps a whole second or two to let something happen, the ports sleep
//!   the shortest time that is still far above a loopback round trip, or poll for the condition.
//!
//! `DEFAULT_SNMP` is process-global, so every test holds `SNMP_TEST_LOCK` for reading (the
//! convention from 03.3); none of them asserts a counter. Because the sessions' background tasks
//! outlive the `close()` that stops them, every test also ends with [`settle`], still inside the
//! guard's scope, so that no straggler moves a counter for a test that holds the lock for
//! writing.
#![allow(
    clippy::await_holding_lock,
    reason = "SNMP_TEST_LOCK serialises whole test bodies; see session/tests.rs"
)]

use std::sync::atomic::AtomicU64;

use kcptun_testkit::rng::Pcg;
use sha1::Sha1;

use super::*;
use crate::crypt::{new_aes_gcm_crypt, new_salsa20_block_crypt, new_triple_des_block_crypt};
use crate::kcp::{IKCP_LOG_ALL, SNMP_TEST_LOCK};
use crate::listener::Listener;

/// Longest a test waits for a single read, write or accept.
const LIMIT: Duration = Duration::from_secs(60);

/// Bytes echoed by the `*SendRecv` ports. Go uses 100 MB, which takes minutes; 4 MiB is still
/// hundreds of KCP windows and dozens of FEC groups, and runs in well under a second.
const ECHO_BYTES: u64 = 4 * 1024 * 1024;

/// Largest chunk the `*SendRecv` ports read or write, scaled from Go's 1 MiB by the same factor
/// as [`ECHO_BYTES`], so the number of calls stays comparable (Go: ~100, here: ~64).
const ECHO_CHUNK_MAX: usize = 64 * 1024;

fn snmp_read() -> std::sync::RwLockReadGuard<'static, ()> {
    SNMP_TEST_LOCK.read().unwrap_or_else(|e| e.into_inner())
}

/// How long a test lets the sessions' background tasks retire before it returns, *while it still
/// holds `SNMP_TEST_LOCK`*.
///
/// `close()` cancels the session's `die` token and closes its socket, but the read loop, the tx
/// pipeline and the updater can still be one iteration behind, and a straggler that decodes one
/// more FEC packet moves `DEFAULT_SNMP`. If that happened after the test dropped its read guard
/// it would corrupt the deltas of whichever test holds the lock for writing, which it did, in
/// about one run in ten, in `fec::vector_tests::vectors_fec_decoder`. Far above a loopback round
/// trip and paid in parallel with the other tests, so it costs no measurable wall time.
const SETTLE: Duration = Duration::from_millis(250);

/// Waits [`SETTLE`]; see there. Every test ends with `settle().await` inside its guard's scope.
async fn settle() {
    tokio::time::sleep(SETTLE).await;
}

/// Go's package-level `pass`: `pbkdf2.Key([]byte("testkey"), []byte("testsalt"), 4096, 32,
/// sha1.New)`.
// Go: kcp-go@v5.6.72 sess_test.go:pass
fn pass() -> [u8; 32] {
    pbkdf2::pbkdf2_hmac_array::<Sha1, 32>(b"testkey", b"testsalt", 4096)
}

fn salsa20() -> PacketCrypt {
    PacketCrypt::Block(new_salsa20_block_crypt(&pass()).expect("salsa20 key"))
}

/// Go's `TestCFBSendRecv` calls `NewTripleDESBlockCrypt(pass)` with all 32 bytes, which
/// `des.NewTripleDESCipher` rejects with `KeySizeError`; Go drops the error, so `block1`/`block2`
/// are nil and the Go test in fact runs with no packet crypto at all. The port trims the key to
/// the 24 bytes 3DES wants, so the CFB path is actually exercised.
// Go: kcp-go@v5.6.72 sess_test.go:TestCFBSendRecv(); crypt.go:NewTripleDESBlockCrypt()
fn triple_des() -> PacketCrypt {
    PacketCrypt::Block(new_triple_des_block_crypt(&pass()[..24]).expect("3des key"))
}

/// Go's `NewAESGCMCrypt(pass)` with the full 32-byte `pass`, i.e. AES-256-GCM.
// Go: kcp-go@v5.6.72 sess_test.go:TestAEADSendRecv()
fn aes_gcm() -> PacketCrypt {
    new_aes_gcm_crypt(&pass()).expect("aes-256-gcm key")
}

// -------------------------------------------------------------------------------------------
// Harness: the echo server, the client dial and the deterministic stream
// -------------------------------------------------------------------------------------------

/// One end of an echo test: the listener, the task that accepts and echoes, and its address.
struct EchoServer {
    listener: Arc<Listener>,
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
    /// Bytes echoed over every accepted session, so a test can wait for the server to be done.
    echoed: Arc<AtomicU64>,
}

impl EchoServer {
    /// Go's `echoServer()`: `listenEcho` (FEC **10/1**, note the asymmetry with the client's
    /// 10/3), the listener socket options, and one `handleEcho` goroutine per accepted session.
    // Go: kcp-go@v5.6.72 sess_test.go:echoServer(), listenEcho(), handleEcho()
    fn start(block: Option<PacketCrypt>) -> EchoServer {
        let listener = Listener::listen_with_options("127.0.0.1:0", block, 10, 1).expect("listen");
        let addr = listener.addr().expect("listener address");
        listener
            .set_read_buffer(4 * 1024 * 1024)
            .expect("listener read buffer");
        listener
            .set_write_buffer(4 * 1024 * 1024)
            .expect("listener write buffer");
        // Go logs the error and carries on; a DSCP the kernel refuses must not fail the test.
        let _ = listener.set_dscp(46);

        let echoed = Arc::new(AtomicU64::new(0));
        let task = tokio::spawn({
            let listener = Arc::clone(&listener);
            let echoed = Arc::clone(&echoed);
            async move {
                while let Ok(session) = listener.accept().await {
                    // Go's "coverage test": both return `invalid operation` for an accepted
                    // session, and Go drops the error.
                    let _ = session.set_read_buffer(4 * 1024 * 1024);
                    let _ = session.set_write_buffer(4 * 1024 * 1024);
                    tokio::spawn(handle_echo(session, Arc::clone(&echoed)));
                }
            }
        });
        EchoServer {
            listener,
            addr,
            task,
            echoed,
        }
    }

    fn echoed(&self) -> u64 {
        self.echoed.load(Ordering::Relaxed)
    }

    /// Go's `defer l.Close()`. Closing the listener hands every accepted session the socket read
    /// error, which ends the `handle_echo` tasks too.
    fn close(self) {
        let _ = self.listener.close();
        self.task.abort();
    }
}

/// Go's `handleEcho`: the per-session options in Go's order, then read/write until an error.
// Go: kcp-go@v5.6.72 sess_test.go:handleEcho()
async fn handle_echo(conn: Arc<UdpSession>, echoed: Arc<AtomicU64>) {
    conn.set_stream_mode(true);
    conn.set_window_size(1024, 1024);
    conn.set_no_delay(1, 10, 2, 1);
    let _ = conn.set_dscp(46);
    conn.set_mtu(1400);
    conn.set_ack_no_delay(false);
    let hour = Instant::now() + Duration::from_secs(3600);
    let _ = conn.set_read_deadline(Some(hour));
    let _ = conn.set_write_deadline(Some(hour));
    conn.set_rate_limit(200 * 1024 * 1024);

    let mut buf = vec![0u8; 512 * 1024];
    loop {
        let Ok(n) = conn.read(&mut buf).await else {
            return;
        };
        if conn.write(&buf[..n]).await.is_err() {
            return;
        }
        echoed.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// Go's `dialEcho`: FEC 10/3 and the setter sequence, including the `SetMtu(1600)` that Go
/// clamps to the packet limit and the two `SetACKNoDelay` calls.
// Go: kcp-go@v5.6.72 sess_test.go:dialEcho()
fn dial_echo(addr: SocketAddr, block: Option<PacketCrypt>) -> Arc<UdpSession> {
    let sess = UdpSession::dial_with_options(&addr.to_string(), block, 10, 3).expect("dial");
    sess.set_stream_mode(true);
    sess.set_window_size(1024, 1024);
    let _ = sess.set_read_buffer(16 * 1024 * 1024);
    let _ = sess.set_write_buffer(16 * 1024 * 1024);
    sess.set_no_delay(1, 10, 2, 1);
    assert!(sess.set_mtu(1400), "1400 is a usable MTU");
    // Go's `SetMtu` starts with `mtu = min(mtuLimit, mtu)`, so an over-large MTU is clamped to
    // 1500 and accepted rather than refused; the next call puts 1400 back.
    assert!(sess.set_mtu(1600), "1600 is clamped to the 1500 byte limit");
    assert!(sess.set_mtu(1400));
    sess.set_ack_no_delay(true);
    sess.set_ack_no_delay(false);
    sess.set_rate_limit(200 * 1024 * 1024);
    // Go passes a real logger; trace events are only produced with the `trace` feature, so the
    // sink here just proves the call works on a live session.
    sess.set_logger(IKCP_LOG_ALL, Some(Box::new(|_, _| {})));
    sess
}

/// Reads exactly `buf.len()` bytes, Go's `io.ReadFull`.
async fn read_full(sess: &UdpSession, buf: &mut [u8]) -> io::Result<usize> {
    let want = buf.len();
    let mut got = 0;
    while got < want {
        let n = tokio::time::timeout(LIMIT, sess.read(&mut buf[got..]))
            .await
            .unwrap_or_else(|_| panic!("read of {want} bytes timed out after {got}"))?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        got += n;
    }
    Ok(got)
}

/// The deterministic chunk stream both the writer and the verifier of an echo test replay:
/// chunk `i` is `1 + below(chunk_max)` bytes long (clamped so the total is exactly `n`) and is
/// filled by one [`Pcg::fill_bytes`] call. Two generators with the same seed produce the same
/// chunks, so the reader can regenerate what the writer sent without sharing state.
struct ChunkGen {
    data: Pcg,
    lengths: Pcg,
    produced: u64,
    n: u64,
    chunk_max: usize,
}

impl ChunkGen {
    fn new(seed: u64, n: u64, chunk_max: usize) -> ChunkGen {
        ChunkGen {
            data: Pcg::new(seed, 0),
            lengths: Pcg::new(seed.wrapping_add(1), 0),
            produced: 0,
            n,
            chunk_max,
        }
    }

    /// The next chunk, or `None` once `n` bytes have been produced.
    // Go: kcp-go@v5.6.72 sess_test.go:randomEchoTest() (`length := lenRand.Intn(1<<20) + 1`)
    fn next_chunk(&mut self) -> Option<Vec<u8>> {
        if self.produced >= self.n {
            return None;
        }
        let mut length = self.lengths.below(self.chunk_max as u64) as usize + 1;
        if self.produced + length as u64 > self.n {
            length = (self.n - self.produced) as usize;
        }
        let mut chunk = vec![0u8; length];
        self.data.fill_bytes(&mut chunk);
        self.produced += length as u64;
        Some(chunk)
    }
}

/// Feeds a verifier the expected bytes of a [`ChunkGen`] as they are needed.
struct Expected {
    source: ChunkGen,
    pending: Vec<u8>,
    offset: u64,
}

impl Expected {
    fn new(seed: u64, n: u64, chunk_max: usize) -> Expected {
        Expected {
            source: ChunkGen::new(seed, n, chunk_max),
            pending: Vec::new(),
            offset: 0,
        }
    }

    /// Asserts that `got` is the next stretch of the expected stream.
    #[track_caller]
    fn check(&mut self, got: &[u8]) {
        while self.pending.len() < got.len() {
            let chunk = self
                .source
                .next_chunk()
                .expect("the peer sent more bytes than the stream holds");
            self.pending.extend_from_slice(&chunk);
        }
        for (i, (&g, &w)) in got.iter().zip(self.pending.iter()).enumerate() {
            assert_eq!(g, w, "data mismatch at byte {}", self.offset + i as u64);
        }
        self.pending.drain(..got.len());
        self.offset += got.len() as u64;
    }
}

// -------------------------------------------------------------------------------------------
// Deadlines
// -------------------------------------------------------------------------------------------

/// A deadline that has already passed fails the next read.
///
/// Go sets the deadline 1 s out and waits 2 s; the port uses 200 ms and 500 ms, the same ordering
/// three orders of magnitude above a loopback round trip.
// Go: kcp-go@v5.6.72 sess_test.go:TestTimeout()
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_timeout() {
    let _snmp = snmp_read();
    let server = EchoServer::start(Some(salsa20()));
    let cli = dial_echo(server.addr, Some(salsa20()));

    let mut buf = [0u8; 10];
    cli.set_deadline(Some(Instant::now() + Duration::from_millis(200)))
        .expect("set the deadline");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let err = cli.read(&mut buf).await.expect_err("the deadline passed");
    assert!(is_timeout(&err), "{err:?}");
    assert_eq!(err.to_string(), "timeout");

    cli.close().expect("close");
    server.close();
    settle().await;
}

// -------------------------------------------------------------------------------------------
// Echo with every kind of packet crypto
// -------------------------------------------------------------------------------------------

/// Go's `randomEchoTest`: a writer task sends `n` bytes of the seeded stream in random chunks
/// while the reader reads the echo back in independently sized random chunks and compares it byte
/// for byte.
// Go: kcp-go@v5.6.72 sess_test.go:randomEchoTest()
async fn random_echo_test(cli: &Arc<UdpSession>, n: u64, chunk_max: usize, seed: u64) {
    let writer = tokio::spawn({
        let cli = Arc::clone(cli);
        async move {
            let mut source = ChunkGen::new(seed, n, chunk_max);
            let mut sent = 0u64;
            while let Some(chunk) = source.next_chunk() {
                let written = cli.write(&chunk).await.expect("write");
                assert_eq!(written, chunk.len(), "write must accept the whole payload");
                sent += written as u64;
            }
            sent
        }
    });

    let mut expected = Expected::new(seed, n, chunk_max);
    let mut lengths = Pcg::new(seed.wrapping_add(2), 0);
    let mut rcvbuf = vec![0u8; chunk_max];
    let mut received = 0u64;
    while received < n {
        let mut length = lengths.below(chunk_max as u64) as usize + 1;
        if received + length as u64 > n {
            length = (n - received) as usize;
        }
        let read = tokio::time::timeout(LIMIT, cli.read(&mut rcvbuf[..length]))
            .await
            .unwrap_or_else(|_| panic!("read timed out after {received} of {n} bytes"))
            .expect("read");
        expected.check(&rcvbuf[..read]);
        received += read as u64;
    }
    assert_eq!(received, n);
    assert_eq!(writer.await.expect("the writer task"), n);
}

/// The full pipeline with a CFB block cipher (3DES).
// Go: kcp-go@v5.6.72 sess_test.go:TestCFBSendRecv()
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cfb_send_recv() {
    let _snmp = snmp_read();
    let server = EchoServer::start(Some(triple_des()));
    let cli = dial_echo(server.addr, Some(triple_des()));
    cli.set_write_delay(true);
    random_echo_test(&cli, ECHO_BYTES, ECHO_CHUNK_MAX, 0x3de5).await;
    cli.close().expect("close");
    server.close();
    settle().await;
}

/// The full pipeline with the salsa20 stream cipher.
// Go: kcp-go@v5.6.72 sess_test.go:TestSalsa20SendRecv()
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_salsa20_send_recv() {
    let _snmp = snmp_read();
    let server = EchoServer::start(Some(salsa20()));
    let cli = dial_echo(server.addr, Some(salsa20()));
    cli.set_write_delay(true);
    random_echo_test(&cli, ECHO_BYTES, ECHO_CHUNK_MAX, 0x5a15a).await;
    cli.close().expect("close");
    server.close();
    settle().await;
}

/// The full pipeline with AEAD (AES-256-GCM), whose overhead shrinks the MSS.
// Go: kcp-go@v5.6.72 sess_test.go:TestAEADSendRecv()
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_aead_send_recv() {
    let _snmp = snmp_read();
    let server = EchoServer::start(Some(aes_gcm()));
    let cli = dial_echo(server.addr, Some(aes_gcm()));
    cli.set_write_delay(true);
    random_echo_test(&cli, ECHO_BYTES, ECHO_CHUNK_MAX, 0xaead).await;
    cli.close().expect("close");
    server.close();
    settle().await;
}

/// The full pipeline with no packet crypto at all (`-crypt null`): no nonce, no CRC.
// Go: kcp-go@v5.6.72 sess_test.go:TestPlainTextSendRecv()
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_plain_text_send_recv() {
    let _snmp = snmp_read();
    let server = EchoServer::start(None);
    let cli = dial_echo(server.addr, None);
    cli.set_write_delay(true);
    random_echo_test(&cli, ECHO_BYTES, ECHO_CHUNK_MAX, 0x91a11).await;
    cli.close().expect("close");
    server.close();
    settle().await;
}

/// Go's gigabyte echo, with Go's chunk sizes. Minutes of loopback traffic, hence `#[ignore]`:
///
/// ```sh
/// cargo test -p kcptun-kcp --release test_1gb_echo -- --ignored --nocapture
/// ```
// Go: kcp-go@v5.6.72 sess_test.go:Test1GBEcho()
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "echoes 1 GiB over loopback; run explicitly"]
async fn test_1gb_echo() {
    let _snmp = snmp_read();
    let server = EchoServer::start(None);
    let cli = dial_echo(server.addr, None);
    cli.set_write_delay(true);
    let start = std::time::Instant::now();
    random_echo_test(&cli, 1024 * 1024 * 1024, 1024 * 1024, 0x19b).await;
    eprintln!("1 GiB echoed in {:?}", start.elapsed());
    cli.close().expect("close");
    server.close();
    settle().await;
}

// -------------------------------------------------------------------------------------------
// WriteBuffers
// -------------------------------------------------------------------------------------------

/// `write_buffers` accepts both slices in one call and returns their total length, and the bytes
/// come back in order.
///
/// Go clamps the second length against the byte count from *before* the first slice, so its
/// writer overshoots `N` by up to one chunk and the reader leaves the remainder unread. The port
/// clamps the pair as a whole, which sends exactly `N` bytes (the last call may therefore pass an
/// empty second slice: `write_buffers` must skip it and still return the first slice's length).
// Go: kcp-go@v5.6.72 sess_test.go:TestSendVector(), randomEchoVectorTest()
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_send_vector() {
    let _snmp = snmp_read();
    let server = EchoServer::start(Some(salsa20()));
    let cli = dial_echo(server.addr, Some(salsa20()));
    cli.set_write_delay(false);

    const N: u64 = ECHO_BYTES;
    const SEED: u64 = 0x7ec;

    let writer = tokio::spawn({
        let cli = Arc::clone(&cli);
        async move {
            let mut source = ChunkGen::new(SEED, N, ECHO_CHUNK_MAX);
            let mut sent = 0u64;
            let mut pairs = 0u64;
            while let Some(first) = source.next_chunk() {
                let second = source.next_chunk().unwrap_or_default();
                let v: [&[u8]; 2] = [&first, &second];
                let n = cli.write_buffers(&v).await.expect("write_buffers");
                assert_eq!(
                    n,
                    first.len() + second.len(),
                    "WriteBuffers must accept every slice"
                );
                sent += n as u64;
                pairs += 1;
            }
            (sent, pairs)
        }
    });

    let mut expected = Expected::new(SEED, N, ECHO_CHUNK_MAX);
    let mut lengths = Pcg::new(SEED.wrapping_add(2), 0);
    let mut rcvbuf = vec![0u8; ECHO_CHUNK_MAX];
    let mut received = 0u64;
    while received < N {
        let mut length = lengths.below(ECHO_CHUNK_MAX as u64) as usize + 1;
        if received + length as u64 > N {
            length = (N - received) as usize;
        }
        let read = tokio::time::timeout(LIMIT, cli.read(&mut rcvbuf[..length]))
            .await
            .unwrap_or_else(|_| panic!("read timed out after {received} of {N} bytes"))
            .expect("read");
        expected.check(&rcvbuf[..read]);
        received += read as u64;
    }
    let (sent, pairs) = writer.await.expect("the writer task");
    assert_eq!(sent, N);
    assert!(
        pairs > 1,
        "the test must exercise more than one vector write"
    );

    cli.close().expect("close");
    server.close();
    settle().await;
}

// -------------------------------------------------------------------------------------------
// Tiny buffers
// -------------------------------------------------------------------------------------------

/// A peer that reads two bytes at a time still echoes a 7-byte stream correctly: stream mode
/// splits and rejoins messages across `read` calls.
// Go: kcp-go@v5.6.72 sess_test.go:TestTinyBufferReceiver(), tinyBufferEchoServer()
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_tiny_buffer_receiver() {
    let _snmp = snmp_read();

    // Go's `listenTinyBufferEcho`: salsa20, FEC 10/3, and `handleTinyBufferEcho`, which only
    // sets stream mode and reads into a 2-byte buffer.
    let listener =
        Listener::listen_with_options("127.0.0.1:0", Some(salsa20()), 10, 3).expect("listen");
    let addr = listener.addr().expect("listener address");
    let server = tokio::spawn({
        let listener = Arc::clone(&listener);
        async move {
            while let Ok(session) = listener.accept().await {
                tokio::spawn(async move {
                    session.set_stream_mode(true);
                    let mut buf = [0u8; 2];
                    loop {
                        let Ok(n) = session.read(&mut buf).await else {
                            return;
                        };
                        if session.write(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                });
            }
        }
    });

    // Go's `dialTinyBufferEcho`: no setters at all, so KCP's own defaults apply (interval 100 ms,
    // windows 32/32, no ACK-nodelay).
    let cli =
        UdpSession::dial_with_options(&addr.to_string(), Some(salsa20()), 10, 3).expect("dial");

    const N: usize = 100;
    let mut snd = 0u8;
    let mut rcv = 0u8;
    let mut sndbuf = [0u8; 7];
    let mut rcvbuf = [0u8; 7];
    for _ in 0..N {
        for b in &mut sndbuf {
            *b = snd;
            snd = snd.wrapping_add(1);
        }
        cli.write(&sndbuf).await.expect("write");
        let n = read_full(&cli, &mut rcvbuf).await.expect("read_full");
        for &b in &rcvbuf[..n] {
            assert_eq!(b, rcv, "the echo must be the stream we sent");
            rcv = rcv.wrapping_add(1);
        }
    }

    cli.close().expect("close");
    let _ = listener.close();
    server.abort();
    settle().await;
}

// -------------------------------------------------------------------------------------------
// Close
// -------------------------------------------------------------------------------------------

/// Closing twice fails the second time, a write after close fails, and a close after a write
/// still lets the reader drain what has already arrived before it fails.
// Go: kcp-go@v5.6.72 sess_test.go:TestClose()
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_close() {
    let _snmp = snmp_read();
    let server = EchoServer::start(Some(salsa20()));

    let cli = dial_echo(server.addr, Some(salsa20()));
    // Double close.
    cli.close().expect("the first close succeeds");
    let err = cli.close().expect_err("double close misbehavior");
    assert_eq!(err.to_string(), "io: read/write on closed pipe");

    // Write after close.
    let buf = [0u8; 10];
    let err = cli
        .write(&buf)
        .await
        .expect_err("write after close misbehavior");
    assert_eq!(err.to_string(), "io: read/write on closed pipe");

    // Write, close, read, read.
    let cli = dial_echo(server.addr, Some(salsa20()));
    assert_eq!(cli.write(&buf).await.expect("write misbehavior"), buf.len());

    // Go sleeps 2 s "until data arrival". `close()` closes the socket and stops the read loop,
    // so an echo still in flight would be lost and the drain below would fail; wait for the
    // server to write the echo and then for the bytes to be in this session's KCP receive
    // queue, instead of guessing a duration.
    let echoed = async {
        while server.echoed() < buf.len() as u64 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };
    tokio::time::timeout(LIMIT, echoed)
        .await
        .expect("the server must echo the 10 bytes");
    let arrived = async {
        loop {
            let peek = cli.lock().kcp.peek_size();
            if peek > 0 {
                return peek;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };
    let peek = tokio::time::timeout(LIMIT, arrived)
        .await
        .expect("the echo must reach the client's KCP");
    assert_eq!(peek, buf.len() as isize, "the whole echo is queued");

    cli.close().expect("close");
    let mut drained = [0u8; 10];
    let n = read_full(&cli, &mut drained)
        .await
        .expect("closed conn drain bytes failed");
    assert_eq!(n, buf.len());
    assert_eq!(drained, buf);

    // After the drain, reading fails.
    let err = cli
        .read(&mut drained)
        .await
        .expect_err("write->close->drain->read misbehavior");
    assert_eq!(err.to_string(), "io: read/write on closed pipe");

    server.close();
    settle().await;
}

// -------------------------------------------------------------------------------------------
// Many parallel clients
// -------------------------------------------------------------------------------------------

/// Go's `echo_tester`: send `msgcount` messages of `msglen` bytes and read exactly that many
/// bytes back.
// Go: kcp-go@v5.6.72 sess_test.go:echo_tester()
async fn echo_tester(cli: &Arc<UdpSession>, msglen: usize, msgcount: usize) {
    let sender = tokio::spawn({
        let cli = Arc::clone(cli);
        async move {
            let buf = vec![0u8; msglen];
            for _ in 0..msgcount {
                cli.write(&buf).await.expect("write");
            }
        }
    });

    let mut nrecv = 0usize;
    let mut buf = vec![0u8; msglen];
    while nrecv < msglen * msgcount {
        let n = tokio::time::timeout(LIMIT, cli.read(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("read timed out after {nrecv} bytes"))
            .expect("read");
        nrecv += n;
    }
    sender.await.expect("the sender task");
}

/// One echo server, `clients` sessions in parallel, 64 messages of 64 bytes each.
// Go: kcp-go@v5.6.72 sess_test.go:parallel_client()
async fn parallel_clients(clients: usize) {
    let server = EchoServer::start(Some(salsa20()));
    let mut tasks = Vec::with_capacity(clients);
    for _ in 0..clients {
        let addr = server.addr;
        tasks.push(tokio::spawn(async move {
            let cli = dial_echo(addr, Some(salsa20()));
            echo_tester(&cli, 64, 64).await;
            cli.close().expect("close");
        }));
    }
    for (i, t) in tasks.into_iter().enumerate() {
        t.await.unwrap_or_else(|e| panic!("client {i}: {e}"));
    }
    server.close();
    settle().await;
}

/// Go's numbers: 1024 concurrent sessions. Each dialled session owns a UDP socket and a 256-slot
/// receive batch (note 19, ~384 KB), so this needs more than 1024 file descriptors and about
/// 0.4 GB of memory. It runs in under a second, but lab-arm64's soft `ulimit -n` is 1024
/// (tools/lab/README.md S1), so it is `#[ignore]` rather than part of the default suite:
///
/// ```sh
/// cargo test -p kcptun-kcp --release test_parallel_1024 -- --ignored
/// ```
// Go: kcp-go@v5.6.72 sess_test.go:TestParallel1024CLIENT_64BMSG_64CNT()
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "1024 UDP sockets (above lab-arm64's soft ulimit -n) and ~0.4 GB of receive batches"]
async fn test_parallel_1024_client_64bmsg_64cnt() {
    let _snmp = snmp_read();
    parallel_clients(1024).await;
}

/// The same fan-out at a size the default suite can afford, so the scenario is covered on every
/// run.
// Go: kcp-go@v5.6.72 sess_test.go:TestParallel1024CLIENT_64BMSG_64CNT() (scaled down)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_parallel_64_client_64bmsg_64cnt() {
    let _snmp = snmp_read();
    parallel_clients(64).await;
}
