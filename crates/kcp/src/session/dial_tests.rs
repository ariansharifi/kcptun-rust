//! Tests of the client dial and its read loop (05.6).
//!
//! Where `session/tests.rs` drives [`UdpSession::packet_input`] by hand over a fake socket, these
//! run the real thing: [`UdpSession::dial_with_options`] binds a wildcard UDP socket, spawns the
//! three tasks of Go's `newUDPSession`, and the [`ReadLoop`] carries datagrams from the socket
//! into the session. The echo test therefore exercises the whole pipeline of Step 05 end to end
//! (KCP, FEC, AES-CFB, batch I/O, update task) between two sessions on loopback.
//!
//! `DEFAULT_SNMP` is process-global, so every test that moves a counter holds `SNMP_TEST_LOCK`
//! (the convention from 03.3), and the ones that assert exact deltas hold it for writing.
#![allow(
    clippy::await_holding_lock,
    reason = "SNMP_TEST_LOCK serialises whole test bodies; see session/tests.rs"
)]

use std::future;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::AtomicUsize;

use super::*;
use crate::crypt::new_aes_block_crypt;
use crate::io::UdpPacketConn;
use crate::kcp::SNMP_TEST_LOCK;
use crate::packet_conn::{BoxFuture, TxMsg};

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

/// Reads one message from `session`, failing the test after [`LIMIT`].
async fn read_msg(session: &UdpSession, buf: &mut [u8]) -> usize {
    tokio::time::timeout(LIMIT, session.read(buf))
        .await
        .expect("a message must arrive")
        .expect("read must not fail")
}

/// `len` bytes with a recognisable pattern.
fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
}

fn aes_crypt() -> PacketCrypt {
    PacketCrypt::Block(new_aes_block_crypt(&[7u8; 32]).expect("aes-256 key"))
}

/// Go's `net.ResolveUDPAddr` on a literal, for the addresses spelled out in these tests.
fn addr(s: &str) -> SocketAddr {
    s.parse().expect("literal address")
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

/// A [`PacketConn`] whose receive blocks until [`BlockedConn::fail`] arms it, at which point it
/// reports a socket error — the two states a read loop can be in without a peer.
#[derive(Debug, Default)]
struct BlockedConn {
    /// Releases the pending receive with an error.
    armed: Notify,
    /// Counts what the tx task sent, to show the pipeline is alive.
    sent: AtomicUsize,
    /// Set by `close()`: an owned socket is closed with its session.
    closed: AtomicBool,
}

impl BlockedConn {
    /// The error the read loop will see, Go's `errors.WithStack(err)` from `ReadFrom`.
    fn error() -> io::Error {
        io::Error::new(io::ErrorKind::ConnectionReset, "connection reset by peer")
    }

    fn fail(&self) {
        self.armed.notify_one();
    }
}

impl PacketConn for BlockedConn {
    fn recv_batch<'a>(&'a self, _batch: &'a mut RecvBatch) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async move {
            self.armed.notified().await;
            Err(BlockedConn::error())
        })
    }

    fn send_batch<'a>(&'a self, msgs: &'a [TxMsg<'a>]) -> BoxFuture<'a, io::Result<usize>> {
        self.sent.fetch_add(msgs.len(), Ordering::Relaxed);
        Box::pin(future::ready(Ok(msgs.len())))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(loopback(1))
    }

    fn set_read_buffer(&self, _bytes: usize) -> io::Result<()> {
        Ok(())
    }

    fn set_write_buffer(&self, _bytes: usize) -> io::Result<()> {
        Ok(())
    }

    fn set_dscp(&self, _dscp: i32) -> io::Result<()> {
        Ok(())
    }

    fn close(&self) -> io::Result<()> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return Err(invalid_operation());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// Source filter
// ---------------------------------------------------------------------------------------------

/// Go's filter around `packetInput`: only the peer's datagrams are fed to the session, the rest
/// are `InErrs`. An IPv4-mapped source is the same peer (`net.IP.Equal`), which is what a
/// dual-stack socket reports for an IPv4 peer.
// Go: kcp-go/v5@v5.6.66 readloop.go:sameUDPAddr(), (*UDPSession).defaultReadLoop()
#[test]
fn source_filter_accepts_only_the_remote() {
    let _snmp = snmp_write();
    let remote = addr("192.0.2.10:29900");
    let mut filter = SourceFilter::new(Some(remote));
    let before = counter(&DEFAULT_SNMP.in_errs);

    assert!(filter.accept(Some(remote)));
    assert!(filter.accept(Some(addr("[::ffff:192.0.2.10]:29900"))));

    // A different port, a different address, and a datagram the transport reported no sender
    // for (Go's failed `msg.Addr.(*net.UDPAddr)` type assertion).
    assert!(!filter.accept(Some(addr("192.0.2.10:29901"))));
    assert!(!filter.accept(Some(addr("192.0.2.11:29900"))));
    assert!(!filter.accept(None));

    assert_eq!(counter(&DEFAULT_SNMP.in_errs) - before, 3);
}

/// Go's "set source address if nil": a session built without a remote takes the first sender as
/// its peer and filters everything after it. No kcp-go entry point creates such a session.
// Go: kcp-go/v5@v5.6.66 readloop.go:(*UDPSession).defaultReadLoop()
#[test]
fn source_filter_without_a_remote_adopts_the_first_sender() {
    let _snmp = snmp_write();
    let first = addr("192.0.2.10:29900");
    let other = addr("192.0.2.11:29900");
    let mut filter = SourceFilter::new(None);
    let before = counter(&DEFAULT_SNMP.in_errs);

    assert!(filter.accept(Some(first)));
    assert_eq!(filter.src, Some(first));
    assert!(filter.accept(Some(first)));
    assert!(!filter.accept(Some(other)));

    assert_eq!(counter(&DEFAULT_SNMP.in_errs) - before, 1);
}

// ---------------------------------------------------------------------------------------------
// Dial
// ---------------------------------------------------------------------------------------------

/// The socket family and the local address follow Go: `udp4` (AF_INET) for an IPv4 remote, the
/// dual-stack `udp` socket otherwise, both bound to the wildcard with an ephemeral port. The
/// remote keeps the family `ResolveUDPAddr` returned it in.
// Go: kcp-go/v5@v5.6.66 sess.go:DialWithOptions()
#[tokio::test(flavor = "current_thread")]
async fn dial_binds_a_wildcard_socket_of_the_remote_family() {
    let _snmp = snmp_read();

    let v4 = UdpSession::dial_with_options("127.0.0.1:65535", None, 0, 0).expect("dial an IPv4");
    let local = v4.local_addr().expect("the local address");
    assert!(
        matches!(local, SocketAddr::V4(_)),
        "an IPv4 remote gives an AF_INET socket, got {local}"
    );
    assert!(local.ip().is_unspecified(), "the wildcard address");
    assert_ne!(local.port(), 0, "an ephemeral port");
    assert_eq!(v4.remote_addr(), loopback(65535));
    v4.close().expect("close");

    let v6 = UdpSession::dial_with_options("[::1]:65535", None, 0, 0).expect("dial an IPv6");
    let local = v6.local_addr().expect("the local address");
    assert!(local.ip().is_unspecified(), "the wildcard address");
    // AF_INET6 (dual-stack) unless this host has no usable IPv6 stack, where `addr::listen_udp`
    // falls back to AF_INET exactly as Go's `favoriteAddrFamily` does.
    assert_eq!(v6.remote_addr(), addr("[::1]:65535"));
    v6.close().expect("close");
}

/// `DialWithOptions` draws the conversation id from the OS CSPRNG, and every dial owns its own
/// socket. The connection accounting of `newUDPSession` (`ActiveOpens`, `CurrEstab`, `MaxConn`)
/// happens once per session, and `Close` gives `CurrEstab` back.
// Go: kcp-go/v5@v5.6.66 sess.go:DialWithOptions(), newUDPSession()
#[tokio::test(flavor = "current_thread")]
async fn dial_counts_an_active_open_and_draws_a_random_conv() {
    let _snmp = snmp_write();
    let active_opens = counter(&DEFAULT_SNMP.active_opens);
    let passive_opens = counter(&DEFAULT_SNMP.passive_opens);
    let curr_estab = counter(&DEFAULT_SNMP.curr_estab);

    let a = UdpSession::dial_with_options("127.0.0.1:65535", None, 0, 0).expect("dial");
    let b = UdpSession::dial_with_options("127.0.0.1:65535", None, 0, 0).expect("dial");

    assert_eq!(counter(&DEFAULT_SNMP.active_opens) - active_opens, 2);
    assert_eq!(counter(&DEFAULT_SNMP.curr_estab) - curr_estab, 2);
    assert!(counter(&DEFAULT_SNMP.max_conn) >= counter(&DEFAULT_SNMP.curr_estab));
    // A dialled session is an active open, never a passive one (Go's `if sess.l == nil`).
    assert_eq!(counter(&DEFAULT_SNMP.passive_opens), passive_opens);

    // 1 in 2^32 that two draws collide; the point is that the id is not a constant.
    assert_ne!(a.get_conv(), b.get_conv(), "conv is drawn per session");
    assert_ne!(
        a.local_addr().expect("local").port(),
        b.local_addr().expect("local").port(),
        "each dial binds its own socket"
    );

    a.close().expect("close");
    b.close().expect("close");
    assert_eq!(counter(&DEFAULT_SNMP.curr_estab), curr_estab);
}

// ---------------------------------------------------------------------------------------------
// Read loop
// ---------------------------------------------------------------------------------------------

/// The whole of Step 05 on loopback: a dialled session and one built with `NewConn4` on a bound
/// socket echo messages to each other through the real read loops, tx pipelines and update
/// tasks, with AES-CFB and FEC(10,3) on.
// Go: kcp-go/v5@v5.6.66 sess.go:DialWithOptions(), NewConn4(), readloop.go
#[tokio::test(flavor = "current_thread")]
async fn dial_and_read_loop_echo_over_a_real_socket() {
    let _snmp = snmp_read();

    // The "server": a socket bound on loopback, plus the session that answers on it.
    let server_conn =
        Arc::new(UdpPacketConn::listen("127.0.0.1:0").expect("bind the server socket"));
    let server_addr = server_conn.local_addr().expect("the server address");

    let client = UdpSession::dial_with_options(&server_addr.to_string(), Some(aes_crypt()), 10, 3)
        .expect("dial");
    assert_eq!(client.remote_addr(), server_addr);

    // The client socket is a wildcard one, so the address the server must answer to is loopback
    // with the client's port (the server would normally learn it from the first datagram).
    let client_addr = loopback(client.local_addr().expect("the client address").port());
    let server = UdpSession::new_conn(
        client.get_conv(),
        client_addr,
        Some(aes_crypt()),
        10,
        3,
        true,
        Arc::clone(&server_conn) as Arc<dyn PacketConn>,
    )
    .expect("new_conn");

    // kcptun's default `-mode fast` on both ends: without `nc=1` the first flush of a fresh
    // session sends nothing and every message waits for the next update interval.
    client.set_no_delay(0, 30, 2, 1);
    server.set_no_delay(0, 30, 2, 1);

    let mut buf = vec![0u8; 4096];
    for i in 0..8u8 {
        let msg = payload(i, 1200);
        assert_eq!(client.write(&msg).await.expect("client write"), msg.len());

        let n = read_msg(&server, &mut buf).await;
        assert_eq!(&buf[..n], &msg[..], "message {i} reached the server");
        assert_eq!(server.write(&buf[..n]).await.expect("server write"), n);

        let n = read_msg(&client, &mut buf).await;
        assert_eq!(&buf[..n], &msg[..], "message {i} came back");
    }

    client.close().expect("close the client");
    server.close().expect("close the server");
}

/// A datagram from anywhere but the peer is counted as `InErrs` and never reaches KCP; the same
/// bytes from the peer are accepted (`InPkts`), which is what tells the two apart.
// Go: kcp-go/v5@v5.6.66 readloop.go:(*UDPSession).defaultReadLoop()
#[tokio::test(flavor = "current_thread")]
async fn packets_from_another_source_are_counted_and_dropped() {
    let _snmp = snmp_write();

    // A bound socket, so that the port cannot be handed to anybody else; it never answers.
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind the peer socket");
    let peer_addr = peer.local_addr().expect("the peer address");

    let session = UdpSession::dial_with_options(&peer_addr.to_string(), None, 0, 0).expect("dial");
    let client_addr = loopback(session.local_addr().expect("the local address").port());

    let in_errs = counter(&DEFAULT_SNMP.in_errs);
    let in_pkts = counter(&DEFAULT_SNMP.in_pkts);

    // Same host, different port: not this session's peer.
    let intruder = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind the intruder socket");
    intruder
        .send_to(&[0u8; 32], client_addr)
        .await
        .expect("send from the wrong source");
    wait_for("the intruder's datagram to be counted", || {
        counter(&DEFAULT_SNMP.in_errs) == in_errs + 1
    })
    .await;
    assert_eq!(
        counter(&DEFAULT_SNMP.in_pkts),
        in_pkts,
        "a foreign datagram must not reach kcp_input"
    );

    // The very same bytes from the peer go through.
    peer.send_to(&[0u8; 32], client_addr)
        .await
        .expect("send from the peer");
    wait_for("the peer's datagram to reach the session", || {
        counter(&DEFAULT_SNMP.in_pkts) == in_pkts + 1
    })
    .await;
    assert_eq!(
        counter(&DEFAULT_SNMP.in_errs),
        in_errs + 1,
        "the peer's datagram is not an InErr"
    );

    session.close().expect("close");
}

/// Go's `notifyReadError`: a failing socket ends the read loop and releases everybody blocked in
/// `Read` with that error.
// Go: kcp-go/v5@v5.6.66 readloop.go:(*UDPSession).defaultReadLoop(),
// sess.go:(*UDPSession).notifyReadError()
#[tokio::test(flavor = "current_thread")]
async fn a_socket_read_error_reaches_a_blocked_read() {
    let _snmp = snmp_read();
    let conn = Arc::new(BlockedConn::default());
    let session = UdpSession::new_conn(
        7,
        loopback(29900),
        None,
        0,
        0,
        true,
        Arc::clone(&conn) as Arc<dyn PacketConn>,
    )
    .expect("new_conn");

    let reader = tokio::spawn({
        let session = Arc::clone(&session);
        async move {
            let mut buf = [0u8; 64];
            session.read(&mut buf).await
        }
    });
    // Let the reader park on the read event; the error is delivered either way (the slot holds
    // it), but this is the case the test is about.
    tokio::time::sleep(Duration::from_millis(20)).await;

    conn.fail();

    let err = tokio::time::timeout(LIMIT, reader)
        .await
        .expect("the blocked read must return")
        .expect("the reader must not panic")
        .expect_err("the socket error");
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(err.to_string(), "connection reset by peer");
    assert!(session.read_error().io_error().is_some());

    session.close().expect("close");
}

/// Closing a session stops all three of its tasks and hands the socket back: the read loop
/// leaves its pending receive on `die` (Go relies on the socket close failing `ReadFrom`), and
/// nothing holds the session alive afterwards.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).Close()
#[tokio::test(flavor = "current_thread")]
async fn close_stops_every_task_and_releases_the_socket() {
    let _snmp = snmp_read();
    let conn = Arc::new(BlockedConn::default());
    let session = UdpSession::new_conn(
        9,
        loopback(29900),
        None,
        0,
        0,
        true,
        Arc::clone(&conn) as Arc<dyn PacketConn>,
    )
    .expect("new_conn");
    let weak = Arc::downgrade(&session);

    // The session, the read loop and the tx pipeline each hold the connection.
    wait_for("the tasks to take their socket handle", || {
        Arc::strong_count(&conn) == 4
    })
    .await;

    assert_eq!(
        conn.sent.load(Ordering::Relaxed),
        0,
        "an idle session puts nothing on the wire"
    );
    // The tx pipeline is alive: what `Write` hands to KCP reaches the socket.
    session.write(&payload(3, 16)).await.expect("write");
    wait_for("the segment to go out", || {
        conn.sent.load(Ordering::Relaxed) > 0
    })
    .await;

    session.close().expect("first close");
    assert!(
        conn.closed.load(Ordering::SeqCst),
        "an owned socket is closed with the session"
    );
    assert!(session.is_closed());
    drop(session);

    wait_for("the tasks to exit", || Arc::strong_count(&conn) == 1).await;
    assert!(
        weak.upgrade().is_none(),
        "no task may keep the session alive"
    );
}

/// A stand-in for the 05.7 listener; `close_session` is all a session asks of it.
#[derive(Debug)]
struct StubOwner;

impl SessionOwner for StubOwner {
    fn close_session(&self, _remote: SocketAddr) -> bool {
        true
    }
}

/// Only a dialled session gets a read loop. Go starts `go sess.readLoop()` in `newUDPSession`
/// just when `sess.l == nil`: an accepted session shares its listener's socket and monitor task,
/// and a second reader on that socket would steal its datagrams.
// Go: kcp-go/v5@v5.6.66 sess.go:newUDPSession() (`if sess.l == nil`)
#[tokio::test(flavor = "current_thread")]
async fn an_accepted_session_gets_no_read_loop() {
    let _snmp = snmp_read();
    let conn = Arc::new(BlockedConn::default());
    let owner: Arc<dyn SessionOwner> = Arc::new(StubOwner);
    let session = UdpSession::start(SessionConfig {
        conv: 11,
        data_shards: 0,
        parity_shards: 0,
        conn: Arc::clone(&conn) as Arc<dyn PacketConn>,
        own_conn: false,
        listener: Some(Arc::downgrade(&owner)),
        remote: loopback(29900),
        block: None,
        pool: Arc::clone(bufpool::default_pool()),
        clock: SystemClock,
        die: CancellationToken::new(),
    })
    .expect("start an accepted session");

    // Test + session + tx pipeline; the dialled case reaches 4 because of the read loop.
    wait_for("the tx task to take its socket handle", || {
        Arc::strong_count(&conn) == 3
    })
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        Arc::strong_count(&conn),
        3,
        "an accepted session must not start a read loop"
    );

    session.close().expect("close");
}
