//! Loopback tests for the UDP [`PacketConn`] implementation.
//!
//! Every batch test runs twice: once over the batched syscalls (`recvmmsg`/`sendmmsg`, Linux
//! only) and once over the per-packet path, which is what Go does when the connection has no
//! `batchConn`. On a non-Linux host both runs take the per-packet path.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use socket2::SockRef;
use tokio::time::timeout;

use super::*;
use crate::crypt::MTU_LIMIT;
use crate::packet_conn::{BATCH_SIZE, RecvBatch, TxMsg, invalid_operation};

/// Datagrams per round-trip test.
const COUNT: usize = 1000;

const LIMIT: Duration = Duration::from_secs(20);

fn conn(laddr: &str, batch_io: bool) -> UdpPacketConn {
    let mut conn = UdpPacketConn::listen(laddr).expect("listen");
    conn.set_batch_io(batch_io);
    // kcptun's default -sockbuf; the kernel caps it at rmem_max/wmem_max, as it does for Go.
    conn.set_read_buffer(4 << 20).expect("SO_RCVBUF");
    conn.set_write_buffer(4 << 20).expect("SO_SNDBUF");
    conn
}

fn payload(i: usize) -> Vec<u8> {
    let len = 8 + (i * 13) % 200;
    let mut buf = vec![0u8; len];
    buf[..4].copy_from_slice(&(i as u32).to_be_bytes());
    buf[4..8].copy_from_slice(&(len as u32).to_be_bytes());
    for (k, b) in buf[8..].iter_mut().enumerate() {
        *b = (i + k) as u8;
    }
    buf
}

/// Sends every message, looping over partial batches exactly as the tx task must.
async fn send_all(conn: &UdpPacketConn, msgs: &[TxMsg<'_>]) {
    let mut rest = msgs;
    while !rest.is_empty() {
        let n = conn.send_batch(rest).await.expect("send_batch");
        assert!(
            n > 0 && n <= rest.len(),
            "send_batch returned {n} for {} msgs",
            rest.len()
        );
        rest = &rest[n..];
    }
}

async fn round_trip(batch_io: bool) {
    let receiver = Arc::new(conn("127.0.0.1:0", batch_io));
    let sender = conn("127.0.0.1:0", batch_io);
    let dst = receiver.local_addr().expect("local addr");
    let src = sender.local_addr().expect("local addr");

    let reader = tokio::spawn({
        let receiver = Arc::clone(&receiver);
        async move {
            let mut batch = RecvBatch::new(BATCH_SIZE);
            let mut got: Vec<(Vec<u8>, SocketAddr)> = Vec::with_capacity(COUNT);
            let mut batches = 0usize;
            while got.len() < COUNT {
                let n = receiver.recv_batch(&mut batch).await.expect("recv_batch");
                assert!(n > 0 && n <= batch.len());
                batches += 1;
                for slot in batch.iter_mut().take(n) {
                    got.push((slot.data().to_vec(), slot.addr().expect("source address")));
                }
            }
            (got, batches)
        }
    });

    let payloads: Vec<Vec<u8>> = (0..COUNT).map(payload).collect();
    // Go's tx task batches up to maxBatchSize (64) messages per syscall.
    for chunk in payloads.chunks(64) {
        let msgs: Vec<TxMsg<'_>> = chunk.iter().map(|p| TxMsg::new(p, dst)).collect();
        send_all(&sender, &msgs).await;
    }

    let (got, batches) = timeout(LIMIT, reader)
        .await
        .expect("timed out")
        .expect("reader task");
    assert_eq!(got.len(), COUNT);
    for (i, (data, from)) in got.iter().enumerate() {
        assert_eq!(data, &payloads[i], "datagram {i}");
        assert_eq!(*from, src, "source of datagram {i}");
    }
    assert!(batches <= COUNT, "{batches} batches for {COUNT} datagrams");
}

#[tokio::test]
async fn round_trip_1000_datagrams_batched() {
    round_trip(true).await;
}

#[tokio::test]
async fn round_trip_1000_datagrams_per_packet() {
    round_trip(false).await;
}

/// Datagrams already queued on the socket come back in one batch: one `recvmmsg` on Linux, one
/// drain of the receive queue elsewhere.
async fn batched_receive(batch_io: bool) {
    const QUEUED: usize = 200;
    let receiver = conn("127.0.0.1:0", batch_io);
    let sender = conn("127.0.0.1:0", batch_io);
    let dst = receiver.local_addr().expect("local addr");

    let payloads: Vec<Vec<u8>> = (0..QUEUED).map(payload).collect();
    for chunk in payloads.chunks(64) {
        let msgs: Vec<TxMsg<'_>> = chunk.iter().map(|p| TxMsg::new(p, dst)).collect();
        send_all(&sender, &msgs).await;
    }

    let mut batch = RecvBatch::new(BATCH_SIZE);
    let mut got = 0;
    let mut largest = 0;
    while got < QUEUED {
        let n = timeout(LIMIT, receiver.recv_batch(&mut batch))
            .await
            .expect("timed out")
            .expect("recv_batch");
        for (k, slot) in batch.iter_mut().take(n).enumerate() {
            assert_eq!(slot.data(), &payloads[got + k][..], "datagram {}", got + k);
        }
        got += n;
        largest = largest.max(n);
    }
    assert_eq!(got, QUEUED);
    assert!(largest > 1, "every batch held a single datagram");
}

#[tokio::test]
async fn batched_receive_drains_the_queue() {
    batched_receive(true).await;
}

#[tokio::test]
async fn batched_receive_drains_the_queue_per_packet() {
    batched_receive(false).await;
}

async fn one_datagram(batch_io: bool, len: usize) -> Vec<u8> {
    let receiver = conn("127.0.0.1:0", batch_io);
    let sender = conn("127.0.0.1:0", batch_io);
    let dst = receiver.local_addr().expect("local addr");
    let data = vec![0xA5u8; len];
    send_all(&sender, &[TxMsg::new(&data, dst)]).await;

    let mut batch = RecvBatch::new(2);
    let n = timeout(LIMIT, receiver.recv_batch(&mut batch))
        .await
        .expect("timed out");
    assert_eq!(n.expect("recv_batch"), 1);
    batch.slot_mut(0).expect("slot 0").data().to_vec()
}

/// A full-size packet must survive, and anything longer is truncated to the slot, as Go's
/// `mtuLimit`-sized read buffer does.
#[tokio::test]
async fn datagram_size_limit() {
    for batch_io in [true, false] {
        assert_eq!(one_datagram(batch_io, MTU_LIMIT).await.len(), MTU_LIMIT);
        assert_eq!(
            one_datagram(batch_io, MTU_LIMIT + 500).await.len(),
            MTU_LIMIT
        );
        assert_eq!(one_datagram(batch_io, 1).await.len(), 1);
    }
}

/// An empty batch or `msgs` is a no-op, not a syscall.
#[tokio::test]
async fn empty_batches() {
    let conn = conn("127.0.0.1:0", true);
    let mut empty = RecvBatch::new(0);
    assert_eq!(conn.recv_batch(&mut empty).await.expect("empty recv"), 0);
    assert_eq!(conn.send_batch(&[]).await.expect("empty send"), 0);
}

/// A dual-stack listener (`":0"`) receives from an IPv4 peer as `::ffff:a.b.c.d` and can reply to
/// it, which is what the listener's session map relies on.
#[tokio::test]
async fn wildcard_listener_talks_ipv4() {
    let server = conn(":0", true);
    let local = server.local_addr().expect("local addr");
    if !matches!(local, SocketAddr::V6(_)) {
        // No usable IPv6 stack: `listen_udp` fell back to 0.0.0.0.
        return;
    }
    let client = conn("127.0.0.1:0", true);
    let dst = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), local.port());
    send_all(&client, &[TxMsg::new(b"ping", dst)]).await;

    let mut batch = RecvBatch::new(4);
    let n = timeout(LIMIT, server.recv_batch(&mut batch))
        .await
        .expect("timed out");
    assert_eq!(n.expect("recv_batch"), 1);
    let first = batch.slot_mut(0).expect("slot 0");
    assert_eq!(first.data(), b"ping");
    let from = first.addr().expect("source address");
    assert!(
        matches!(from, SocketAddr::V6(_)),
        "expected an IPv4-mapped address, got {from}"
    );
    assert_eq!(
        addr::canonical(from),
        client.local_addr().expect("local addr")
    );

    // Replying to the mapped address from the dual-stack socket must reach the IPv4 client.
    send_all(&server, &[TxMsg::new(b"pong", from)]).await;
    let n = timeout(LIMIT, client.recv_batch(&mut batch))
        .await
        .expect("timed out");
    assert_eq!(n.expect("recv_batch"), 1);
    assert_eq!(batch.slot_mut(0).expect("slot 0").data(), b"pong");
}

/// The client socket family follows the remote address, as Go's `DialWithOptions` does.
#[tokio::test]
async fn dial_socket_family() {
    let raddr = addr::resolve_udp_addr("udp", "1.2.3.4:29900").expect("v4 remote");
    let conn = UdpPacketConn::dial_socket(&raddr).expect("dial socket");
    let local = conn.local_addr().expect("local addr");
    assert!(matches!(local, SocketAddr::V4(_)), "{local}");
    assert!(local.ip().is_unspecified());

    let raddr = addr::resolve_udp_addr("udp", "[2001:db8::1]:29900").expect("v6 remote");
    let conn = UdpPacketConn::dial_socket(&raddr).expect("dial socket");
    let local = conn.local_addr().expect("local addr");
    if matches!(local, SocketAddr::V6(_)) {
        assert!(local.ip().is_unspecified());
    }
}

#[tokio::test]
async fn socket_option_setters() {
    let conn = UdpPacketConn::listen("127.0.0.1:0").expect("listen");
    let sock = SockRef::from(conn.socket());

    let before = sock.recv_buffer_size().expect("SO_RCVBUF");
    conn.set_read_buffer(1 << 20).expect("set_read_buffer");
    assert!(sock.recv_buffer_size().expect("SO_RCVBUF") >= before);

    let before = sock.send_buffer_size().expect("SO_SNDBUF");
    conn.set_write_buffer(1 << 20).expect("set_write_buffer");
    assert!(sock.send_buffer_size().expect("SO_SNDBUF") >= before);

    // DSCP 46 (EF) on an IPv4 socket: IP_TOS = 46 << 2 = 184.
    conn.set_dscp(46).expect("set_dscp");
    assert_eq!(sock.tos_v4().expect("IP_TOS"), 184);
    conn.set_dscp(0).expect("set_dscp(0)");
    assert_eq!(sock.tos_v4().expect("IP_TOS"), 0);
}

/// Deviation V03: the IPv6 traffic class carries `dscp << 2`, not Go's raw `dscp`.
// socket2 has no `tclass_v6` on Windows, mirroring the `#[cfg(not(windows))]` on the setter.
#[cfg(not(windows))]
#[tokio::test]
async fn set_dscp_ipv6_traffic_class() {
    let conn = match UdpPacketConn::listen("[::1]:0") {
        Ok(conn) => conn,
        Err(_) => return, // no IPv6 stack
    };
    conn.set_dscp(46).expect("set_dscp");
    let tclass = SockRef::from(conn.socket())
        .tclass_v6()
        .expect("IPV6_TCLASS");
    assert_eq!(tclass, if GO_RAW_IPV6_TCLASS { 46 } else { 184 });
}

#[tokio::test]
async fn close_is_reported_once() {
    let conn = conn("127.0.0.1:0", true);
    conn.close().expect("first close");

    let err = conn.close().expect_err("second close");
    assert_eq!(err.to_string(), "use of closed network connection");
    let err = conn
        .recv_batch(&mut RecvBatch::new(1))
        .await
        .expect_err("recv after close");
    assert_eq!(err.to_string(), "use of closed network connection");
    let dst = conn.local_addr().expect("local addr");
    let err = conn
        .send_batch(&[TxMsg::new(b"x", dst)])
        .await
        .expect_err("send after close");
    assert_eq!(err.to_string(), "use of closed network connection");
}

#[test]
fn error_texts_match_go() {
    assert_eq!(invalid_operation().to_string(), "invalid operation");
    assert_eq!(closed().to_string(), "use of closed network connection");
}

/// The batch path is only ever enabled on Linux (Go: `platform_generic.go` has no `batchConn`).
#[tokio::test]
async fn batch_io_is_linux_only() {
    let mut conn = UdpPacketConn::listen("127.0.0.1:0").expect("listen");
    assert_eq!(conn.batch_io(), cfg!(target_os = "linux"));
    conn.set_batch_io(true);
    assert_eq!(conn.batch_io(), cfg!(target_os = "linux"));
    conn.set_batch_io(false);
    assert!(!conn.batch_io());
}

/// A session accepted by a listener holds its socket as `Arc<dyn PacketConn>`; the trait must
/// stay dyn-compatible and usable from several tasks.
#[tokio::test]
async fn packet_conn_object_safety() {
    let server: Arc<dyn PacketConn> = Arc::new(conn("127.0.0.1:0", true));
    let client: Arc<dyn PacketConn> = Arc::new(conn("127.0.0.1:0", true));
    let dst = server.local_addr().expect("local addr");

    let task = tokio::spawn({
        let server = Arc::clone(&server);
        async move {
            let mut batch = RecvBatch::new(4);
            let n = server.recv_batch(&mut batch).await.expect("recv_batch");
            (n, batch.slot_mut(0).expect("slot 0").data().to_vec())
        }
    });

    let data = b"through the trait object".to_vec();
    let msgs = [TxMsg::new(&data, dst)];
    let mut rest = &msgs[..];
    while !rest.is_empty() {
        rest = &rest[client.send_batch(rest).await.expect("send_batch")..];
    }

    let (n, got) = timeout(LIMIT, task)
        .await
        .expect("timed out")
        .expect("reader task");
    assert_eq!(n, 1);
    assert_eq!(got, data);
    assert!(server.set_read_buffer(1 << 20).is_ok());
    assert!(server.set_write_buffer(1 << 20).is_ok());
    assert!(server.set_dscp(0).is_ok());
    assert!(server.close().is_ok());
}
