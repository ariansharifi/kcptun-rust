//! The fake-TCP connection as a KCP transport: [`kcptun_kcp::PacketConn`] for [`TcpConn`].
//!
//! This is the seam `--tcp` runs through. Go hands `tcpraw.Dial`'s or `tcpraw.Listen`'s
//! `*tcpraw.TCPConn` straight to `kcp.NewConn4` / `kcp.ServeConn`, which take a
//! `net.PacketConn`; kcp-go then asks the connection whether it also implements `batchConn`
//! (`ReadBatch`/`WriteBatch`, i.e. `recvmmsg`/`sendmmsg`) and a tcpraw connection does not, so
//! every datagram goes through `ReadFrom`/`WriteTo`, one at a time.
//!
//! [`PacketConn`] is this port's merged batch interface, so the batch methods here are that same
//! per-packet path with a loop around it: [`recv_batch`](PacketConn::recv_batch) fills exactly
//! one slot per call, and [`send_batch`](PacketConn::send_batch) walks the messages in order. Only
//! `kcptun_kcp::io::UdpPacketConn` has a real batch syscall underneath.
//!
//! The option setters and `close` are Go's `tcpConn` methods, which kcp-go reaches through its
//! `setDSCP` / `setReadBuffer` / `setWriteBuffer` interface checks
//! (`sess.go:(*UDPSession).SetDSCP()` and friends): a tcpraw connection satisfies all three, so
//! the UDP-socket fallbacks in kcp-go are never taken for `--tcp`.
//!
//! Go reference: `kcp-go/v5@v5.6.66 sess.go`, `readloop.go`, `tx.go`;
//! `tcpraw@v1.2.32 tcp_linux.go`.

use std::io;
use std::net::SocketAddr;

use kcptun_kcp::packet_conn::{BoxFuture, PacketConn, RecvBatch, TxMsg};

use crate::TcpConn;

#[cfg(target_os = "linux")]
// Go: kcp-go/v5@v5.6.66 sess.go — the `net.PacketConn` a session or listener is built on
impl PacketConn for TcpConn {
    /// Waits for one datagram and puts it in the first slot.
    ///
    /// Go's non-batch read loop reads one packet per `ReadFrom` and hands it to `packetInput`
    /// immediately; there is nothing to batch, because the next datagram is not there yet — the
    /// capture loop delivers them one by one through an (effectively) unbuffered channel.
    // Go: kcp-go/v5@v5.6.66 readloop.go:(*UDPSession).defaultReadLoop()
    fn recv_batch<'a>(&'a self, batch: &'a mut RecvBatch) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async move {
            // The contract's one case for `0`: nowhere to put a datagram.
            let Some(mut slot) = batch.slot_mut(0) else {
                return Ok(0);
            };
            let (n, addr) = self.recv_from(slot.buf_mut()).await?;
            slot.set_received(n, Some(addr));
            Ok(1)
        })
    }

    /// Sends the messages one after another, stopping at the first failure.
    ///
    /// Go's `tx.go` loops over `txqueue` with `WriteTo` and gives up on the first error, having
    /// counted what went out; the caller resends the rest. An error is returned only when
    /// nothing was sent, as [`PacketConn`]'s contract says.
    // Go: kcp-go/v5@v5.6.66 tx.go:(*UDPSession).defaultTx()
    fn send_batch<'a>(&'a self, msgs: &'a [TxMsg<'a>]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async move {
            let mut sent = 0;
            for msg in msgs {
                // `send_to` reports a datagram it could not place in a flow as sent, exactly as
                // Go does ("assume this packet has lost, without notification").
                if let Err(err) = self.send_to(msg.data, msg.addr).await {
                    if sent == 0 {
                        return Err(err);
                    }
                    break;
                }
                sent += 1;
            }
            Ok(sent)
        })
    }

    /// The local address of the real TCP connection (dialled) or listener (listening), which is
    /// also the source port of every crafted segment.
    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).LocalAddr()
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(TcpConn::local_addr(self))
    }

    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).SetReadBuffer()
    fn set_read_buffer(&self, bytes: usize) -> io::Result<()> {
        TcpConn::set_read_buffer(self, bytes)
    }

    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).SetWriteBuffer()
    fn set_write_buffer(&self, bytes: usize) -> io::Result<()> {
        TcpConn::set_write_buffer(self, bytes)
    }

    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).SetDSCP()
    fn set_dscp(&self, dscp: i32) -> io::Result<()> {
        TcpConn::set_dscp(self, dscp)
    }

    /// Closes the connection, which is what removes its `filter/OUTPUT` rules.
    ///
    /// **It blocks** while `iptables`/`ip6tables` run, exactly as Go's `Close` blocks the
    /// goroutine that calls it: a client session closes its own connection here
    /// (`kcp.NewConn4(..., ownConn: true)`), and the rules have to be gone when it returns.
    /// Calling it twice is harmless and reports nothing, as Go's `dieOnce` does — unlike the UDP
    /// transport, whose second `close` answers `use of closed network connection`.
    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).Close()
    fn close(&self) -> io::Result<()> {
        TcpConn::close(self)
    }
}

/// The stub's [`TcpConn`] is uninhabited, so every method here is unreachable; the impl exists
/// only so that the `--tcp` code of the client and the server compiles unchanged on a platform
/// Go's tcpraw does not build for, where `dial` and `listen` fail with `os not supported` before
/// any connection can be made.
#[cfg(not(target_os = "linux"))]
impl PacketConn for TcpConn {
    fn recv_batch<'a>(&'a self, _batch: &'a mut RecvBatch) -> BoxFuture<'a, io::Result<usize>> {
        match *self {}
    }

    fn send_batch<'a>(&'a self, _msgs: &'a [TxMsg<'a>]) -> BoxFuture<'a, io::Result<usize>> {
        match *self {}
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        match *self {}
    }

    fn set_read_buffer(&self, _bytes: usize) -> io::Result<()> {
        match *self {}
    }

    fn set_write_buffer(&self, _bytes: usize) -> io::Result<()> {
        match *self {}
    }

    fn set_dscp(&self, _dscp: i32) -> io::Result<()> {
        match *self {}
    }

    fn close(&self) -> io::Result<()> {
        match *self {}
    }
}

/// The one thing that holds on every platform: a tcpraw connection **is** a KCP transport, so
/// the `--tcp` code of the client and the server compiles and links the same way everywhere. Off
/// Linux the connection is uninhabited, so this is all there is to check.
#[cfg(test)]
mod type_tests {
    use super::*;

    #[test]
    fn a_tcpraw_connection_is_a_packet_conn() {
        fn assert_packet_conn<T: PacketConn>() {}
        assert_packet_conn::<TcpConn>();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::conn::test_support::detached_conn;

    /// The peer every case below writes to.
    fn peer() -> SocketAddr {
        "203.0.113.9:29900".parse().expect("literal")
    }

    /// A batch of sends becomes one `WriteTo` per message, and a flow with no raw handle
    /// swallows them exactly as Go's `WriteTo` does — the datagrams count as sent.
    #[tokio::test]
    async fn send_batch_sends_every_message() {
        let conn = detached_conn();
        let msgs = [
            TxMsg::new(b"one", peer()),
            TxMsg::new(b"two", peer()),
            TxMsg::new(b"three", peer()),
        ];
        assert_eq!(PacketConn::send_batch(&conn, &msgs).await.expect("sent"), 3);
    }

    /// A closed connection reports `EOF` from both directions, and the error surfaces because
    /// nothing was sent.
    #[tokio::test]
    async fn a_closed_connection_reports_eof_from_both_batch_methods() {
        let conn = detached_conn();
        conn.close().expect("close");

        let msgs = [TxMsg::new(b"one", peer())];
        let err = PacketConn::send_batch(&conn, &msgs)
            .await
            .expect_err("closed");
        assert_eq!(err.to_string(), "EOF");

        let mut slots = RecvBatch::new(4);
        let err = PacketConn::recv_batch(&conn, &mut slots)
            .await
            .expect_err("closed");
        assert_eq!(err.to_string(), "EOF");
    }

    /// An empty batch is the one case that may return `0`, and it must not wait for a datagram.
    #[tokio::test]
    async fn an_empty_receive_batch_returns_zero() {
        let conn = detached_conn();
        let mut slots = RecvBatch::new(0);
        assert_eq!(
            PacketConn::recv_batch(&conn, &mut slots)
                .await
                .expect("no slots"),
            0
        );
    }

    /// The transport reports the address of the real TCP connection, and the option setters of a
    /// connection with no raw sockets succeed without doing anything — Go's empty
    /// `for k := range conn.handles`.
    #[tokio::test]
    async fn the_setters_of_a_handleless_connection_succeed() {
        let conn = detached_conn();
        assert_eq!(
            PacketConn::local_addr(&conn).expect("addr"),
            conn.local_addr()
        );
        PacketConn::set_dscp(&conn, 46).expect("dscp");
        PacketConn::set_read_buffer(&conn, 4 << 20).expect("rcvbuf");
        PacketConn::set_write_buffer(&conn, 4 << 20).expect("sndbuf");
    }

    /// A KCP session or listener holds its transport as `Arc<dyn PacketConn>`; a tcpraw
    /// connection has to fit there.
    #[test]
    fn a_connection_is_a_dyn_packet_conn() {
        let conn: std::sync::Arc<dyn PacketConn> = std::sync::Arc::new(detached_conn());
        assert_eq!(
            conn.local_addr().expect("addr").to_string(),
            "127.0.0.1:29900"
        );
    }
}
