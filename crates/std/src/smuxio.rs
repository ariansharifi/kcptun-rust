//! A tokio [`AsyncRead`]/[`AsyncWrite`] view of a smux stream, with Go's `CloseWrite`.
//!
//! [`crate::pipe::pipe`] and `QppStream` (`crate::qpp`, feature `qpp`) are written against
//! tokio's poll-based traits, because the other end of every proxied connection is a
//! `TcpStream`. A
//! [`kcptun_smux::Stream`] instead exposes Go's `net.Conn` shape as `async fn`s on `&self`
//! (`read`, `write`, `close_write`, `close`), which is what the smux port needed internally.
//! [`SmuxStream`] is the adapter between the two: it keeps the in-flight future between polls,
//! so a `Pending` never loses a partially consumed frame.
//!
//! ```text
//! TCP  <-->  pipe  <-->  QppStream<SmuxStream>  <-->  smux::Stream
//!            ^ AsyncRead + AsyncWrite + HalfCloseWrite ^ async fn on &self
//! ```
//!
//! step 08 left this for step 09 (the pipe's doc comment says so), but
//! step 07.3 needs it to wrap a real smux stream in QPP, so it lands here. Step 09.1 added the
//! other piece, the `smux -> TCP` frame-drain fast path (Go gets it from `io.Copy` preferring
//! `io.WriterTo`, i.e. [`Stream::write_to`](kcptun_smux::Stream::write_to)): it is
//! [`HalfCloseWrite::poll_read_frame`] below, which [`pipe`](crate::pipe::pipe) uses in place of
//! `poll_read` whenever the source is a smux stream. This adapter is the general path.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use kcptun_smux::{Error, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::pipe::HalfCloseWrite;

/// A future of one smux operation, kept across polls so cancelling a poll cannot drop data.
type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// A [`kcptun_smux::Stream`] as a tokio stream.
///
/// # Contract
///
/// After [`poll_write`](AsyncWrite::poll_write) returns `Pending`, the caller must retry with
/// the same slice: the bytes were copied into the in-flight write, and the retry finishes that
/// write rather than starting a new one. `write_all`, and therefore
/// [`pipe`](crate::pipe::pipe), do exactly that.
pub struct SmuxStream {
    /// Shared so that the operation futures can be `'static`; the smux stream itself is happy
    /// to be used from several tasks, like Go's `net.Conn`.
    stream: Arc<Stream>,
    /// The tail of a received frame that did not fit into the last caller buffer.
    pending: Option<Bytes>,
    /// The in-flight `read_chunk`.
    read_fut: Option<BoxFut<Result<Option<Bytes>, Error>>>,
    /// The in-flight `write_bytes`, with the length it was given.
    write_fut: Option<(usize, BoxFut<Result<usize, Error>>)>,
    /// The in-flight `close_write`.
    close_write_fut: Option<BoxFut<Result<(), Error>>>,
    /// The in-flight `close`.
    close_fut: Option<BoxFut<Result<(), Error>>>,
    /// Whether the peer's end of data has been seen.
    eof: bool,
    /// Whether `close_write` has been issued; a second one returns `io: read/write on closed
    /// pipe` in Go, and a half-close is idempotent here instead.
    write_closed: bool,
    /// Whether `close` has been issued, for the same reason.
    closed: bool,
}

impl SmuxStream {
    /// Wraps `stream`.
    pub fn new(stream: Stream) -> SmuxStream {
        SmuxStream {
            stream: Arc::new(stream),
            pending: None,
            read_fut: None,
            write_fut: None,
            close_write_fut: None,
            close_fut: None,
            eof: false,
            write_closed: false,
            closed: false,
        }
    }

    /// The wrapped stream. Reading or writing it directly bypasses the buffered frame tail.
    pub fn inner(&self) -> &Stream {
        &self.stream
    }

    /// The stream's identifier, for the `stream opened in: … out: …(id)` log lines.
    pub fn id(&self) -> u32 {
        self.stream.id()
    }

    /// The session's local address.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.stream.local_addr()
    }

    /// The session's remote address.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.stream.remote_addr()
    }

    /// Polls the future in `slot`, starting it from `stream` with `start` when there is none.
    fn poll_op<F, Fut>(
        slot: &mut Option<BoxFut<Result<(), Error>>>,
        stream: &Arc<Stream>,
        cx: &mut Context<'_>,
        start: F,
    ) -> Poll<io::Result<()>>
    where
        F: FnOnce(Arc<Stream>) -> Fut,
        Fut: Future<Output = Result<(), Error>> + Send + 'static,
    {
        let fut = slot.get_or_insert_with(|| Box::pin(start(Arc::clone(stream))));
        let r = ready!(fut.as_mut().poll(cx));
        *slot = None;
        Poll::Ready(r.map_err(io::Error::from))
    }
}

impl AsyncRead for SmuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if let Some(chunk) = me.pending.as_mut() {
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                chunk.advance(n);
                if chunk.is_empty() {
                    me.pending = None;
                }
                return Poll::Ready(Ok(()));
            }
            if me.eof || buf.remaining() == 0 {
                // No space, or the peer's data ended: filling nothing is tokio's EOF.
                return Poll::Ready(Ok(()));
            }

            let poll = {
                let fut = me.read_fut.get_or_insert_with(|| {
                    let stream = Arc::clone(&me.stream);
                    Box::pin(async move { stream.read_chunk().await })
                });
                fut.as_mut().poll(cx)
            };
            let r = ready!(poll);
            me.read_fut = None;
            match r {
                Ok(Some(chunk)) if chunk.is_empty() => {}
                Ok(Some(chunk)) => me.pending = Some(chunk),
                Ok(None) => {
                    me.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Err(e) => return Poll::Ready(Err(e.into())),
            }
        }
    }
}

impl AsyncWrite for SmuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if let Some((len, fut)) = me.write_fut.as_mut() {
            let len = *len;
            let r = ready!(fut.as_mut().poll(cx));
            me.write_fut = None;
            return Poll::Ready(r.map(|n| n.min(len)).map_err(io::Error::from));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let len = buf.len();
        let stream = Arc::clone(&me.stream);
        let data = Bytes::copy_from_slice(buf);
        let mut fut: BoxFut<Result<usize, Error>> =
            Box::pin(async move { stream.write_bytes(&data).await });
        match fut.as_mut().poll(cx) {
            Poll::Ready(r) => Poll::Ready(r.map(|n| n.min(len)).map_err(io::Error::from)),
            Poll::Pending => {
                me.write_fut = Some((len, fut));
                Poll::Pending
            }
        }
    }

    /// smux writes straight into the session's shaper queue; there is nothing to flush.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// Shutting the write side down is Go's `CloseWrite` (one `cmdFIN`), like
    /// `poll_shutdown` on a `TcpStream`.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        HalfCloseWrite::poll_close_write(self, cx)
    }
}

impl HalfCloseWrite for SmuxStream {
    /// A smux stream is Go's `io.WriterTo`, so [`pipe`](crate::pipe::pipe) drains it frame by
    /// frame instead of reading it into a copy buffer.
    // Go: smux@v1.5.55 stream.go:stream.WriteTo(), selected by kcptun/std/copy.go:Copy()
    const FRAME_SOURCE: bool = true;

    /// Hands over the next received frame whole, with the same token accounting and version-2
    /// window updates [`poll_read`](AsyncRead::poll_read) performs — it is the same
    /// [`read_chunk`](kcptun_smux::Stream::read_chunk), without the copy into the caller's
    /// buffer.
    // Go: smux@v1.5.55 stream.go:stream.WriteTo() — the read half of its loop
    fn poll_read_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<Bytes>>> {
        let me = self.get_mut();
        // A frame tail left by `poll_read` is delivered first, so mixing the two cannot
        // reorder the stream.
        if let Some(chunk) = me.pending.take() {
            return Poll::Ready(Ok(Some(chunk)));
        }
        if me.eof {
            return Poll::Ready(Ok(None));
        }
        let poll = {
            let fut = me.read_fut.get_or_insert_with(|| {
                let stream = Arc::clone(&me.stream);
                Box::pin(async move { stream.read_chunk().await })
            });
            fut.as_mut().poll(cx)
        };
        let r = ready!(poll);
        me.read_fut = None;
        match r {
            Ok(Some(chunk)) => Poll::Ready(Ok(Some(chunk))),
            Ok(None) => {
                me.eof = true;
                Poll::Ready(Ok(None))
            }
            Err(e) => Poll::Ready(Err(e.into())),
        }
    }

    // Go: smux@v1.5.55 stream.go:stream.CloseWrite()
    fn poll_close_write(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if me.write_closed {
            return Poll::Ready(Ok(()));
        }
        let r = ready!(SmuxStream::poll_op(
            &mut me.close_write_fut,
            &me.stream,
            cx,
            |s| async move { s.close_write().await }
        ));
        me.write_closed = true;
        Poll::Ready(r)
    }

    // Go: smux@v1.5.55 stream.go:stream.Close()
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if me.closed {
            return Poll::Ready(Ok(()));
        }
        let r = ready!(SmuxStream::poll_op(
            &mut me.close_fut,
            &me.stream,
            cx,
            |s| async move { s.close().await }
        ));
        me.closed = true;
        Poll::Ready(r)
    }
}

// `pub(crate)` so that `qpp_tests.rs` can build the same in-memory smux pair.
#[cfg(test)]
#[path = "smuxio_tests.rs"]
pub(crate) mod tests;
