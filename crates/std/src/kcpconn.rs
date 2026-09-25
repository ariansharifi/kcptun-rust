//! The KCP session as the byte-stream connection smux runs over.
//!
//! Go needs no adapter: `kcp.UDPSession` is a `net.Conn`, so `smux.Server(conn, cfg)` and
//! `std.NewCompStream(conn)` take it directly (`kcptun/server/main.go:serveListener`,
//! `kcptun/client/main.go:createConn`). In this port smux asks for
//! [`SmuxConn`], so [`KcpConn`] is the one-line bridge, including the
//! scatter-gather write, which is the reason `SmuxConn::write_all_vectored` exists:
//!
//! ```text
//! smux session  <-->  KcpConn (or CompStream<KcpConn>)  <-->  kcptun_kcp::UdpSession
//!               SmuxConn                                 read/write_buffers/close
//! ```
//!
//! Go's `sendLoop` picks the vectored path at run time (`if s.writev, ok := conn.(writeVer)`),
//! which for a `*kcp.UDPSession` is `WriteBuffers`: a frame header and its payload are queued as
//! one KCP send instead of two. [`KcpConn::write_all_vectored`] is that path.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use kcptun_kcp::UdpSession;
use kcptun_smux::SmuxConn;

/// A KCP session presented to smux (and to [`CompStream`](crate::comp::CompStream)) as a byte
/// stream.
///
/// Cheap to build and to hold: it is an [`Arc`] of the session the listener accepted or the
/// client dialled.
// Go: kcptun/server/main.go:serveListener, `go handleMux(_Q_, conn, config)` with a *kcp.UDPSession
pub struct KcpConn {
    /// Go's `conn`, the accepted or dialled `*kcp.UDPSession`.
    session: Arc<UdpSession>,
}

impl KcpConn {
    /// Wraps `session`.
    pub fn new(session: Arc<UdpSession>) -> KcpConn {
        KcpConn { session }
    }

    /// The session below smux, for the setters `main` applies to it.
    pub fn session(&self) -> &Arc<UdpSession> {
        &self.session
    }
}

impl SmuxConn for KcpConn {
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).Read(), reached through smux's io.ReadFull
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.session.read(buf).await
    }

    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).Write(), one segment queue, all or nothing
    async fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        self.session.write_buffers(&[buf]).await.map(|_| ())
    }

    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).WriteBuffers(), smux session.go:sendLoop()
    async fn write_all_vectored(&self, bufs: &[&[u8]]) -> io::Result<usize> {
        self.session.write_buffers(bufs).await
    }

    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).Close(), called by smux Session.Close()
    async fn close(&self) -> io::Result<()> {
        self.session.close()
    }

    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).LocalAddr()
    fn local_addr(&self) -> Option<SocketAddr> {
        self.session.local_addr().ok()
    }

    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).RemoteAddr()
    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.session.remote_addr())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kcptun_kcp::Listener;

    /// A session pair on loopback, with no crypto and no FEC.
    async fn session_pair() -> (Arc<Listener>, KcpConn, KcpConn) {
        let listener = Listener::listen_with_options("127.0.0.1:0", None, 0, 0).expect("listen");
        let addr = listener.addr().expect("addr");
        let client = UdpSession::dial_with_options(&addr.to_string(), None, 0, 0).expect("dial");
        // The server side appears only once the first packet arrives.
        client.write(b"hello").await.expect("write");
        let server = listener.accept().await.expect("accept");
        let mut got = [0u8; 5];
        let n = server.read(&mut got).await.expect("read");
        assert_eq!(&got[..n], b"hello");
        (listener, KcpConn::new(client), KcpConn::new(server))
    }

    #[tokio::test]
    async fn round_trip_through_the_smux_conn_api() {
        let (_lis, client, server) = session_pair().await;

        client.write_all(b"ping").await.expect("write_all");
        let mut buf = [0u8; 16];
        let n = server.read(&mut buf).await.expect("read");
        assert_eq!(&buf[..n], b"ping");

        // The vectored path is what smux's sendLoop uses for a header plus its payload.
        let n = server
            .write_all_vectored(&[b"he", b"ader", b"payload"])
            .await
            .expect("write_all_vectored");
        assert_eq!(n, 13);
        let mut got = Vec::new();
        while got.len() < 13 {
            let n = client.read(&mut buf).await.expect("read");
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, b"headerpayload");
    }

    #[tokio::test]
    async fn addresses_are_the_sessions() {
        let (_lis, client, server) = session_pair().await;
        assert_eq!(
            client.remote_addr(),
            Some(server.local_addr().expect("local"))
        );
        assert!(client.local_addr().is_some());
        assert!(server.remote_addr().is_some());
    }

    #[tokio::test]
    async fn close_is_the_sessions_close() {
        let (_lis, client, _server) = session_pair().await;
        client.close().await.expect("close");
        // Go's dieOnce: the second Close reports the broken pipe.
        assert!(client.close().await.is_err());
    }
}
