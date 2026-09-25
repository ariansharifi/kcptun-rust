//! UDP packet I/O: the [`PacketConn`] implementation sessions and listeners run on.
//!
//! Mirrors kcp-go's split between a batched Linux path and a per-packet path everywhere else:
//!
//! | Go | here |
//! |---|---|
//! | `readloop_linux.go` (`ReadBatch` → `recvmmsg`) | `batch_linux` |
//! | `tx_linux.go` (`WriteBatch` → `sendmmsg`) | `batch_linux` |
//! | `readloop.go:defaultReadLoop` (`ReadFrom`) | `generic` |
//! | `tx.go:defaultTx` (`WriteTo`) | `generic` |
//! | `platform_linux.go` (`batchConn == nil` → default path) | [`UdpPacketConn::set_batch_io`] |
//!
//! Go reads the batch straight into the read loop; here [`PacketConn::recv_batch`] hands the
//! batch back to the caller, which keeps the loop (source filter, demux) out of the I/O layer.
//!
//! This is one of the three modules allowed to use `unsafe` (see `docs/porting-guide.md` §5), and
//! all of it is in `batch_linux`: the `recvmmsg`/`sendmmsg` calls and the `mmsghdr` arrays they
//! need. Everything else here is safe code over `tokio::net::UdpSocket` and `socket2`.

use std::io;
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use socket2::SockRef;
use tokio::net::UdpSocket;

use crate::addr::{self, UdpAddr};
use crate::packet_conn::{BoxFuture, PacketConn, RecvBatch, TxMsg, invalid_operation};

#[cfg(target_os = "linux")]
mod batch_linux;
mod generic;

#[cfg(test)]
mod tests;

/// Deviation V03: Go's `SetDSCP` writes the raw DSCP value into the IPv6 traffic class
/// (`ipv6.SetTrafficClass(dscp)`) while shifting it by 2 for IPv4 (`ipv4.SetTOS(dscp << 2)`), so
/// on IPv6 the code point ends up in the wrong bits and the two low bits become a bogus ECN
/// codepoint. We shift on both. Flip this to `true` for bit-exact Go marking.
///
/// **This is the single switch for V03 in the whole workspace.** `kcptun-tcpraw`'s raw handles
/// mark their own `IPV6_TCLASS` (`--tcp` never touches a UDP socket) and read this constant too,
/// so flipping it here moves both transports back onto Go's behaviour at once.
// Only the IPv6 half of `set_dscp` and the IPv6 test read it, and both are compiled out on
// Windows, where socket2 offers no `set_tclass_v6`/`tclass_v6`.
pub const GO_RAW_IPV6_TCLASS: bool = false;

/// A UDP socket as a [`PacketConn`].
///
/// The socket is **unconnected**, like Go's (`net.ListenUDP`, never `DialUDP`), so one client
/// socket can be used for a session whose peer address is only checked in the read loop.
pub struct UdpPacketConn {
    socket: UdpSocket,
    /// Whether the socket is AF_INET6: destinations are encoded for the socket's family, as Go's
    /// `ipToSockaddr` does, so a dual-stack socket sends to `::ffff:a.b.c.d`.
    v6: bool,
    /// Go's `platform.batchConn != nil`: use `recvmmsg`/`sendmmsg` instead of the per-packet
    /// path. Always false off Linux.
    batch_io: bool,
    closed: AtomicBool,
    #[cfg(target_os = "linux")]
    rx: Mutex<batch_linux::RecvScratch>,
    #[cfg(target_os = "linux")]
    tx: Mutex<batch_linux::SendBatch>,
}

impl UdpPacketConn {
    /// Wraps an already bound socket (which is made non-blocking).
    pub fn from_std(socket: std::net::UdpSocket) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        Self::from_tokio(UdpSocket::from_std(socket)?)
    }

    /// Wraps an already bound tokio socket.
    pub fn from_tokio(socket: UdpSocket) -> io::Result<Self> {
        let v6 = matches!(socket.local_addr()?, SocketAddr::V6(_));
        Ok(UdpPacketConn {
            socket,
            v6,
            batch_io: cfg!(target_os = "linux"),
            closed: AtomicBool::new(false),
            #[cfg(target_os = "linux")]
            rx: Mutex::new(batch_linux::RecvScratch::new()),
            #[cfg(target_os = "linux")]
            tx: Mutex::new(batch_linux::SendBatch::new()),
        })
    }

    /// Binds a listening socket for `laddr` with Go's semantics: `":29900"` gives a dual-stack
    /// `[::]` socket serving IPv4 and IPv6.
    // Go: kcp-go/v5@v5.6.66 sess.go:ListenWithOptions()
    pub fn listen(laddr: &str) -> io::Result<Self> {
        let udpaddr = addr::resolve_udp_addr("udp", laddr)?;
        Self::from_std(addr::listen_udp("udp", Some(&udpaddr))?)
    }

    /// Binds the client socket for a session to `raddr`: a wildcard `udp4` socket when the remote
    /// is IPv4, else a dual-stack one.
    // Go: kcp-go/v5@v5.6.66 sess.go:DialWithOptions()
    pub fn dial_socket(raddr: &UdpAddr) -> io::Result<Self> {
        Self::from_std(addr::listen_udp(addr::dial_network(raddr), None)?)
    }

    /// The underlying socket.
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Whether the batched syscalls are in use (Go's `platform.batchConn != nil`).
    pub fn batch_io(&self) -> bool {
        self.batch_io
    }

    /// Switches the batched syscalls off (or on again on Linux), like Go falling back to
    /// `defaultReadLoop`/`defaultTx` when the connection has no `batchConn`. Mainly for tests and
    /// benchmarks: both paths must behave the same.
    pub fn set_batch_io(&mut self, on: bool) {
        self.batch_io = on && cfg!(target_os = "linux");
    }

    /// Receives a batch of datagrams; see [`PacketConn::recv_batch`] for the contract.
    pub async fn recv_batch(&self, batch: &mut RecvBatch) -> io::Result<usize> {
        if batch.is_empty() {
            return Ok(0);
        }
        self.check_open()?;

        #[cfg(target_os = "linux")]
        if self.batch_io {
            use std::os::fd::AsRawFd;
            let fd = self.socket.as_raw_fd();
            return self
                .socket
                .async_io(tokio::io::Interest::READABLE, || {
                    lock(&self.rx).recvmmsg(fd, batch)
                })
                .await;
        }

        generic::recv_batch(&self.socket, batch).await
    }

    /// Sends a batch of datagrams; see [`PacketConn::send_batch`] for the contract.
    pub async fn send_batch(&self, msgs: &[TxMsg<'_>]) -> io::Result<usize> {
        if msgs.is_empty() {
            return Ok(0);
        }
        self.check_open()?;

        #[cfg(target_os = "linux")]
        if self.batch_io {
            use std::os::fd::AsRawFd;
            let fd = self.socket.as_raw_fd();
            return self
                .socket
                .async_io(tokio::io::Interest::WRITABLE, || {
                    lock(&self.tx).sendmmsg(fd, msgs, self.v6)
                })
                .await;
        }

        generic::send_batch(&self.socket, msgs, self.v6).await
    }

    /// Sets `SO_RCVBUF`. As in Go there is no `SO_RCVBUFFORCE`, so the kernel silently caps the
    /// value at `net.core.rmem_max`.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetReadBuffer() → net.UDPConn.SetReadBuffer()
    pub fn set_read_buffer(&self, bytes: usize) -> io::Result<()> {
        SockRef::from(&self.socket).set_recv_buffer_size(bytes)
    }

    /// Sets `SO_SNDBUF` (capped by the kernel at `net.core.wmem_max`, as in Go).
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetWriteBuffer() → net.UDPConn.SetWriteBuffer()
    pub fn set_write_buffer(&self, bytes: usize) -> io::Result<()> {
        SockRef::from(&self.socket).set_send_buffer_size(bytes)
    }

    /// Sets the DSCP code point: `IP_TOS = dscp << 2` for IPv4 and `IPV6_TCLASS = dscp << 2` for
    /// IPv6 (deviation V03; Go writes the raw value into `IPV6_TCLASS`). Both are attempted, as
    /// Go does, and the call succeeds if either of them did; otherwise it is Go's
    /// `invalid operation`.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetDSCP(), (*Listener).SetDSCP()
    pub fn set_dscp(&self, dscp: i32) -> io::Result<()> {
        let socket = SockRef::from(&self.socket);
        // Go passes a Go `int` to setsockopt, which truncates it to the C `int` the kernel takes.
        let tos = (i64::from(dscp) << 2) as i32;

        let mut succeed = false;
        if socket.set_tos_v4(tos as u32).is_ok() {
            succeed = true;
        }
        // socket2 has no `set_tclass_v6` on Windows, so the IPv6 half is compiled out there.
        // Go behaves the same way: `ipv6/sys_windows.go`'s `sockOpts` has no `ssoTrafficClass`
        // entry, so `SetTrafficClass` returns `errNotImplemented` and `SetDSCP` succeeds on the
        // strength of the IPv4 call alone.
        #[cfg(not(windows))]
        {
            let tclass = if GO_RAW_IPV6_TCLASS { dscp } else { tos };
            if socket.set_tclass_v6(tclass as u32).is_ok() {
                succeed = true;
            }
        }
        if succeed {
            Ok(())
        } else {
            Err(invalid_operation())
        }
    }

    /// Marks the connection closed: further I/O fails and the second call reports it, like Go's
    /// `net.UDPConn.Close`.
    ///
    /// The file descriptor is released when the last handle is dropped. Unlike Go's `Close`, this
    /// does **not** wake a task already parked in [`recv_batch`](Self::recv_batch): sessions and
    /// listeners stop their loops on their `die` token, which is also what makes the final
    /// flush of V05 deterministic.
    pub fn close(&self) -> io::Result<()> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return Err(closed());
        }
        Ok(())
    }

    fn check_open(&self) -> io::Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            Err(closed())
        } else {
            Ok(())
        }
    }
}

impl PacketConn for UdpPacketConn {
    fn recv_batch<'a>(&'a self, batch: &'a mut RecvBatch) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(UdpPacketConn::recv_batch(self, batch))
    }

    fn send_batch<'a>(&'a self, msgs: &'a [TxMsg<'a>]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(UdpPacketConn::send_batch(self, msgs))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn set_read_buffer(&self, bytes: usize) -> io::Result<()> {
        UdpPacketConn::set_read_buffer(self, bytes)
    }

    fn set_write_buffer(&self, bytes: usize) -> io::Result<()> {
        UdpPacketConn::set_write_buffer(self, bytes)
    }

    fn set_dscp(&self, dscp: i32) -> io::Result<()> {
        UdpPacketConn::set_dscp(self, dscp)
    }

    fn close(&self) -> io::Result<()> {
        UdpPacketConn::close(self)
    }
}

/// Go's `errors.New("use of closed network connection")` (`net.ErrClosed`).
// Go: go1.27.1 net/net.go:ErrClosed
pub(crate) fn closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "use of closed network connection",
    )
}

/// The batch scratch space is only ever touched inside the synchronous `try_io` closure, never
/// across an `.await`.
///
/// `rx` is uncontended: a connection has exactly one read loop. `tx` is **not**: 05.7 gives every
/// accepted session an `Arc<dyn PacketConn>` onto the listener's socket, so all of a listener's
/// tx tasks serialize on this one mutex across the `sendmmsg` syscall. Go has no such queue,
/// `x/net internal/socket/rawconn_mmsg.go:sendMsgs` takes its `mmsghdr`/`iovec` scratch from
/// `mmsghdr_unix.go:defaultMmsgTmpsPool` (a per-P `sync.Pool`) per `WriteBatch`. Giving the send
/// path per-call scratch (a small pool next to the 05.2 bufpool, or a thread-local) is a 05.7 /
/// Step 12 item.
///
/// A poisoned lock can only mean a panic while rebuilding the `mmsghdr` array, which leaves no
/// invariant behind (every field is rewritten before each syscall).
#[cfg(target_os = "linux")]
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
