//! The byte stream a session multiplexes over.
//!
//! Go's `Session` takes an `io.ReadWriteCloser` and, in `sendLoop`, type-asserts it to
//! `interface{ WriteBuffers(v [][]byte) (int, error) }` to get scatter-gather writes when the
//! connection supports them (kcp-go's `UDPSession` does). [`SmuxConn`] is the same contract:
//! [`write_all_vectored`](SmuxConn::write_all_vectored) has a default implementation that
//! concatenates into one buffer and calls [`write_all`](SmuxConn::write_all): Go's non-
//! `WriteBuffers` path, `copy(buf[headerSize:], data)` followed by a single `Write`, and the
//! KCP session (step 09) overrides it with its native `write_buffers`.
//!
//! Every method takes `&self` because the receive task, the send task and the keepalive task
//! use the connection concurrently, exactly as Go's three goroutines share one `net.Conn`.
//!
//! Go: `smux@v1.5.55 session.go:Session.conn` / `sendLoop()`.

use std::future::Future;
use std::io::{self, IoSlice};
use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Largest number of `IoSlice`s handed to one vectored write. The session always writes exactly
/// two (header and payload); the loop in [`SplitConn::write_all_vectored`] only needs a bound so
/// it can gather on the stack.
const MAX_IOV: usize = 8;

/// The connection a [`Session`](crate::Session) runs over: a reliable, ordered byte stream.
///
/// Implementors must be safe to use from several tasks at once. Reads are only ever issued by
/// the session's receive task and writes only by its send task, so an implementation may
/// serialise each direction with its own lock (as [`SplitConn`] does); it must not serialise
/// reads against writes, or the session deadlocks.
// Go: smux@v1.5.55 session.go:Session.conn (io.ReadWriteCloser + optional WriteBuffers)
pub trait SmuxConn: Send + Sync + 'static {
    /// Reads into `buf`, returning the number of bytes read. `Ok(0)` means end of stream.
    // Go: io.Reader.Read, used by session.go:recvLoop() through io.ReadFull
    fn read(&self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send;

    /// Writes all of `buf`.
    // Go: io.Writer.Write, used by session.go:sendLoop()
    fn write_all(&self, buf: &[u8]) -> impl Future<Output = io::Result<()>> + Send;

    /// Writes all of `bufs` in order, returning the total number of bytes written.
    ///
    /// The default implementation concatenates and calls [`write_all`](Self::write_all), which
    /// is what Go does for a connection without `WriteBuffers`. Implementations backed by a
    /// scatter-gather write (`writev`, kcp-go's `WriteBuffers`) should override it.
    ///
    /// Unlike Go's `Write`, a failure reports no byte count: `sendLoop` therefore delivers
    /// `n = 0` with the error, where Go may deliver the bytes of a partially written frame. The
    /// difference is only visible in the count a failed `Stream::write` returns alongside the
    /// error, and the session is dead either way (`notifyWriteError`).
    // Go: smux@v1.5.55 session.go:sendLoop() (WriteBuffers fast path / copy+Write fallback)
    fn write_all_vectored(&self, bufs: &[&[u8]]) -> impl Future<Output = io::Result<usize>> + Send {
        async move {
            let total: usize = bufs.iter().map(|b| b.len()).sum();
            let mut joined = Vec::with_capacity(total);
            for b in bufs {
                joined.extend_from_slice(b);
            }
            self.write_all(&joined).await?;
            Ok(total)
        }
    }

    /// Closes the connection.
    // Go: io.Closer.Close, called by session.go:Session.Close()
    fn close(&self) -> impl Future<Output = io::Result<()>> + Send;

    /// The local address, or `None` when the connection has none. Go returns `nil` unless the
    /// connection implements `LocalAddr() net.Addr`.
    // Go: smux@v1.5.55 session.go:Session.LocalAddr()
    fn local_addr(&self) -> Option<SocketAddr> {
        None
    }

    /// The remote address, or `None` when the connection has none.
    // Go: smux@v1.5.55 session.go:Session.RemoteAddr()
    fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }
}

/// A [`SmuxConn`] over any tokio stream, split into an independently locked read half and write
/// half.
///
/// This is what the session uses on top of a TCP connection or an in-memory
/// [`duplex`](tokio::io::duplex) pipe. Step 09's KCP session implements [`SmuxConn`] directly,
/// because it has a native scatter-gather write.
///
/// Both halves live in an `Option` so that [`close`](SmuxConn::close) can drop them: Go's
/// `Session.Close()` ends in `s.conn.Close()`, which closes the socket in both directions and
/// releases the descriptor there and then. Shutting the write half down alone would leave the
/// read half (and the descriptor) alive until the last `Arc<SplitConn>` was dropped, which for
/// a closed session kept in a map (kcptun's server keeps them) can be much later.
///
/// `close` waits for the read lock, so a task that is reading must be told to stop first. The
/// session guarantees this: `Session::close` cancels `die` before it calls `conn.close()`, and
/// every read in `recv_loop` is cancelled by `die`.
pub struct SplitConn<S: AsyncRead + AsyncWrite + Send + 'static> {
    reader: Mutex<Option<ReadHalf<S>>>,
    writer: Mutex<Option<WriteHalf<S>>>,
    local_addr: Option<SocketAddr>,
    remote_addr: Option<SocketAddr>,
}

/// Go's `net.ErrClosed`, returned by any I/O on a connection that has been closed.
fn err_closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "use of closed network connection",
    )
}

impl<S: AsyncRead + AsyncWrite + Send + 'static> SplitConn<S> {
    /// Wraps `stream` without addresses (`LocalAddr`/`RemoteAddr` report `None`, like Go for a
    /// connection that is not a `net.Conn`).
    pub fn new(stream: S) -> Self {
        Self::with_addrs(stream, None, None)
    }

    /// Wraps `stream` and reports the given addresses.
    pub fn with_addrs(
        stream: S,
        local_addr: Option<SocketAddr>,
        remote_addr: Option<SocketAddr>,
    ) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        SplitConn {
            reader: Mutex::new(Some(reader)),
            writer: Mutex::new(Some(writer)),
            local_addr,
            remote_addr,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Send + 'static> SplitConn<S> {
    /// Half-closes: shuts the write direction down without dropping the connection, so the peer
    /// sees EOF while this side can still read. Go's `TCPConn.CloseWrite()`; the tests use it to
    /// model a peer that stopped sending.
    #[cfg(test)]
    pub(crate) async fn close_write(&self) -> io::Result<()> {
        let mut slot = self.writer.lock().await;
        match slot.as_mut() {
            Some(writer) => writer.shutdown().await,
            None => Err(err_closed()),
        }
    }
}

impl SplitConn<TcpStream> {
    /// Wraps a TCP connection, filling in its local and peer address.
    pub fn tcp(stream: TcpStream) -> Self {
        let local_addr = stream.local_addr().ok();
        let remote_addr = stream.peer_addr().ok();
        Self::with_addrs(stream, local_addr, remote_addr)
    }
}

impl<S: AsyncRead + AsyncWrite + Send + Sync + 'static> SmuxConn for SplitConn<S> {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut reader = self.reader.lock().await;
        let reader = reader.as_mut().ok_or_else(err_closed)?;
        reader.read(buf).await
    }

    async fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        let mut writer = self.writer.lock().await;
        let writer = writer.as_mut().ok_or_else(err_closed)?;
        writer.write_all(buf).await
    }

    /// Scatter-gather write, so the header and the payload reach the socket in one syscall when
    /// the stream supports it (tokio falls back to writing the first slice otherwise, which the
    /// loop below handles).
    async fn write_all_vectored(&self, bufs: &[&[u8]]) -> io::Result<usize> {
        let total: usize = bufs.iter().map(|b| b.len()).sum();
        let mut writer = self.writer.lock().await;
        let writer = writer.as_mut().ok_or_else(err_closed)?;

        // `i` is the first buffer that still has bytes to write and `off` the offset inside it.
        let mut i = 0usize;
        let mut off = 0usize;
        while i < bufs.len() {
            if off == bufs[i].len() {
                i += 1;
                off = 0;
                continue;
            }

            // Gather the remaining buffers, on the stack: the session writes two.
            let mut iov = [IoSlice::new(&[]); MAX_IOV];
            iov[0] = IoSlice::new(&bufs[i][off..]);
            let mut k = 1;
            let mut j = i + 1;
            while k < MAX_IOV && j < bufs.len() {
                if !bufs[j].is_empty() {
                    iov[k] = IoSlice::new(bufs[j]);
                    k += 1;
                }
                j += 1;
            }

            let mut written = writer.write_vectored(&iov[..k]).await?;
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write whole buffer",
                ));
            }
            while written > 0 && i < bufs.len() {
                let remaining = bufs[i].len() - off;
                if written >= remaining {
                    written -= remaining;
                    i += 1;
                    off = 0;
                } else {
                    off += written;
                    written = 0;
                }
            }
        }
        Ok(total)
    }

    /// Shuts the write half down and then drops both halves, which closes the underlying stream
    /// and releases its descriptor: Go's `conn.Close()`, not a half-close. Further reads and
    /// writes report `net.ErrClosed`.
    async fn close(&self) -> io::Result<()> {
        let result = {
            let mut slot = self.writer.lock().await;
            // `take` drops the write half whatever the shutdown returns, as in Go, where
            // Close() releases the socket even when the FIN cannot be sent.
            match slot.take() {
                Some(mut writer) => writer.shutdown().await,
                None => Err(err_closed()),
            }
        };
        // Taking the read half closes the stream for good. A reader holding this lock must
        // already have been told to stop; see the type's documentation.
        *self.reader.lock().await = None;
        result
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// A connection that has no vectored write, so the default `write_all_vectored` (Go's
    /// `copy` + single `Write`) is exercised.
    struct PlainConn {
        inner: Mutex<Vec<u8>>,
    }

    impl SmuxConn for PlainConn {
        async fn read(&self, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }

        async fn write_all(&self, buf: &[u8]) -> io::Result<()> {
            self.inner.lock().await.extend_from_slice(buf);
            Ok(())
        }

        async fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn default_write_all_vectored_concatenates() {
        let conn = PlainConn {
            inner: Mutex::new(Vec::new()),
        };
        let n = conn
            .write_all_vectored(&[b"head".as_slice(), b"".as_slice(), b"tail".as_slice()])
            .await
            .expect("write");
        assert_eq!(n, 8);
        assert_eq!(&*conn.inner.lock().await, b"headtail");
        assert_eq!(conn.local_addr(), None);
        assert_eq!(conn.remote_addr(), None);
    }

    #[tokio::test]
    async fn split_conn_round_trip() {
        let (a, b) = duplex(4096);
        let conn = SplitConn::new(a);
        let peer = SplitConn::new(b);

        let n = conn
            .write_all_vectored(&[b"01234567".as_slice(), b"payload".as_slice()])
            .await
            .expect("write");
        assert_eq!(n, 15);

        let mut got = [0u8; 15];
        let mut read = 0;
        while read < got.len() {
            read += peer.read(&mut got[read..]).await.expect("read");
        }
        assert_eq!(&got, b"01234567payload");
    }

    /// A vectored write longer than one duplex buffer has to loop and re-slice.
    #[tokio::test]
    async fn split_conn_vectored_write_loops_over_partial_writes() {
        let (a, b) = duplex(64);
        let conn = SplitConn::new(a);
        let peer = SplitConn::new(b);

        let head = vec![7u8; 100];
        let tail = vec![9u8; 300];
        let reader = tokio::spawn(async move {
            let mut got = vec![0u8; 400];
            let mut read = 0;
            while read < got.len() {
                let n = peer.read(&mut got[read..]).await.expect("read");
                assert_ne!(n, 0, "unexpected eof");
                read += n;
            }
            got
        });

        let n = conn
            .write_all_vectored(&[head.as_slice(), tail.as_slice()])
            .await
            .expect("write");
        assert_eq!(n, 400);

        let got = reader.await.expect("join");
        assert!(got[..100].iter().all(|&b| b == 7));
        assert!(got[100..].iter().all(|&b| b == 9));
    }

    #[tokio::test]
    async fn split_conn_close_is_visible_as_eof() {
        let (a, b) = duplex(64);
        let conn = SplitConn::new(a);
        let peer = SplitConn::new(b);
        conn.close().await.expect("close");
        let mut buf = [0u8; 8];
        assert_eq!(peer.read(&mut buf).await.expect("read"), 0);
    }

    /// Go's `conn.Close()` closes the socket in both directions; the local end must therefore be
    /// fully closed, not half-closed with a live read half holding the descriptor.
    #[tokio::test]
    async fn split_conn_close_releases_both_halves() {
        let (a, b) = duplex(64);
        let conn = SplitConn::new(a);
        let peer = SplitConn::new(b);
        peer.write_all(b"unread").await.expect("write");

        conn.close().await.expect("close");

        let mut buf = [0u8; 8];
        // Not "read the pending bytes" and not "EOF": the half is gone.
        let err = conn.read(&mut buf).await.expect_err("read after close");
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
        let err = conn.write_all(b"x").await.expect_err("write after close");
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
        let err = conn
            .write_all_vectored(&[b"x".as_slice()])
            .await
            .expect_err("vectored write after close");
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
        let err = conn.close().await.expect_err("second close");
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);

        // And the peer sees the close.
        assert_eq!(peer.read(&mut buf).await.expect("read"), 0);
    }
}
