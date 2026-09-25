//! Batched UDP I/O on Linux: `recvmmsg` and `sendmmsg`.
//!
//! Go gets this from `x/net/ipv4` (or `ipv6`): `readloop_linux.go` calls `ReadBatch` on a
//! `batchSize` array of `ipv4.Message`, each with one `mtuLimit`-byte buffer, and `tx_linux.go`
//! calls `WriteBatch` until the queue is empty. Both end in `recvmmsg`/`sendmmsg`.
//!
//! The `mmsghdr`, `iovec` and address arrays are allocated once per connection and reused; only
//! the buffer pointers, lengths and address slots are rewritten before each syscall, so a batch
//! of up to 256 datagrams costs one syscall and no allocation.
//!
//! This is the only `unsafe` in the UDP I/O layer (`docs/porting-guide.md` §5).

use std::io;
use std::mem;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::ptr;

use socket2::{SockAddr, SockAddrStorage};

use crate::addr;
use crate::packet_conn::{RecvBatch, TxMsg};

/// An all-zero `mmsghdr` (a plain C struct of pointers, integers and padding, for which all-zero
/// is a valid value; every field used by the syscall is written before each call).
fn zeroed_mmsghdr() -> libc::mmsghdr {
    // SAFETY: `libc::mmsghdr` is a `repr(C)` aggregate of integers, raw pointers and padding,
    // none of which have niches, so the all-zero bit pattern is a valid value.
    unsafe { mem::zeroed() }
}

/// Reusable `recvmmsg` scratch space: the `mmsghdr`, `iovec` and address arrays the syscall
/// needs, which are *not* the datagram buffers (those live in the caller's
/// [`RecvBatch`](crate::packet_conn::RecvBatch)).
// Go: kcp-go/v5@v5.6.66 readloop_linux.go → x/net/ipv4 `ReadBatch` (its own `mmsghdr` array)
pub(crate) struct RecvScratch {
    msgs: Vec<libc::mmsghdr>,
    iovecs: Vec<libc::iovec>,
    names: Vec<libc::sockaddr_storage>,
}

// SAFETY: the raw pointers in `msgs` point into `iovecs` and `names` (owned by the same value)
// and into the caller's slots, and they are rewritten before every syscall, so they are never
// read after the value moves to another thread. The scratch space itself is plain data.
unsafe impl Send for RecvScratch {}

impl RecvScratch {
    pub(crate) fn new() -> Self {
        RecvScratch {
            msgs: Vec::new(),
            iovecs: Vec::new(),
            names: Vec::new(),
        }
    }

    fn reserve(&mut self, n: usize) {
        if self.msgs.len() < n {
            self.msgs.resize_with(n, zeroed_mmsghdr);
            self.iovecs.resize(
                n,
                libc::iovec {
                    iov_base: ptr::null_mut(),
                    iov_len: 0,
                },
            );
            // SAFETY: `sockaddr_storage` is a `repr(C)` byte buffer with an integer family
            // field; all-zero is a valid value (and is what the kernel overwrites).
            self.names.resize_with(n, || unsafe { mem::zeroed() });
        }
    }

    /// Receives up to `batch.len()` datagrams into `batch`, returning how many arrived.
    ///
    /// The socket must be non-blocking: `recvmmsg` then returns as soon as the first datagram is
    /// in, or fails with `EAGAIN` when the queue is empty, which is what
    /// [`tokio::net::UdpSocket::async_io`] needs to re-arm the readiness.
    // Go: kcp-go/v5@v5.6.66 readloop_linux.go:(*UDPSession).readLoop() → ipv4.PacketConn.ReadBatch
    pub(crate) fn recvmmsg(&mut self, fd: RawFd, batch: &mut RecvBatch) -> io::Result<usize> {
        let n = batch.len();
        debug_assert!(n > 0);
        self.reserve(n);

        for (i, mut slot) in batch.iter_mut().enumerate() {
            let buf = slot.buf_mut();
            self.iovecs[i] = libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            };
        }

        let names = self.names.as_mut_ptr();
        let iovecs = self.iovecs.as_mut_ptr();
        for (i, msg) in self.msgs[..n].iter_mut().enumerate() {
            // SAFETY: `i < n` and both arrays hold at least `n` initialised elements
            // (`reserve(n)` above), so both offsets are in bounds of their allocation.
            let (name, iovec) = unsafe { (names.add(i), iovecs.add(i)) };
            msg.msg_len = 0;
            msg.msg_hdr.msg_name = name.cast();
            msg.msg_hdr.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            msg.msg_hdr.msg_iov = iovec;
            msg.msg_hdr.msg_iovlen = 1 as _;
            msg.msg_hdr.msg_control = ptr::null_mut();
            msg.msg_hdr.msg_controllen = 0 as _;
            msg.msg_hdr.msg_flags = 0;
        }

        let count = loop {
            // SAFETY: `fd` is a valid socket for the duration of the call (the caller holds the
            // `UdpSocket`), `msgs` points to `n` initialised `mmsghdr`s, each describing one
            // iovec into a distinct live slot buffer and one address slot of
            // `sockaddr_storage` size. No timeout is passed (null is the documented "none").
            let ret = unsafe {
                libc::recvmmsg(
                    fd,
                    self.msgs.as_mut_ptr(),
                    n as libc::c_uint,
                    0,
                    ptr::null_mut(),
                )
            };
            if ret >= 0 {
                break ret as usize;
            }
            let err = io::Error::last_os_error();
            // Go's runtime restarts an interrupted syscall; so do we.
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        };

        let count = count.min(n);
        for (i, mut slot) in batch.iter_mut().enumerate().take(count) {
            let received = self.msgs[i].msg_len as usize;
            let from = socket_addr(&self.names[i], self.msgs[i].msg_hdr.msg_namelen);
            slot.set_received(received, from);
        }
        Ok(count)
    }
}

/// Reusable `sendmmsg` scratch space.
// Go: kcp-go/v5@v5.6.66 tx_linux.go (the `txqueue` handed to `WriteBatch`)
pub(crate) struct SendBatch {
    msgs: Vec<libc::mmsghdr>,
    iovecs: Vec<libc::iovec>,
    names: Vec<SockAddr>,
}

// SAFETY: as for `RecvScratch`, the raw pointers are rewritten before every syscall and never
// read after a move; `SockAddr` is plain data.
unsafe impl Send for SendBatch {}

impl SendBatch {
    pub(crate) fn new() -> Self {
        SendBatch {
            msgs: Vec::new(),
            iovecs: Vec::new(),
            names: Vec::new(),
        }
    }

    fn reserve(&mut self, n: usize) {
        if self.msgs.len() < n {
            self.msgs.resize_with(n, zeroed_mmsghdr);
            self.iovecs.resize(
                n,
                libc::iovec {
                    iov_base: ptr::null_mut(),
                    iov_len: 0,
                },
            );
        }
    }

    /// Sends up to `msgs.len()` datagrams, returning how many the kernel accepted.
    ///
    /// A short count is a partial batch: the caller resends the remainder, as Go's `tx` does.
    // Go: kcp-go/v5@v5.6.66 tx_linux.go:(*UDPSession).tx() → ipv4.PacketConn.WriteBatch
    pub(crate) fn sendmmsg(
        &mut self,
        fd: RawFd,
        msgs: &[TxMsg<'_>],
        v6: bool,
    ) -> io::Result<usize> {
        let n = msgs.len();
        debug_assert!(n > 0);
        self.reserve(n);

        // Destinations are encoded for the socket's family, like Go's `ipToSockaddr`.
        self.names.clear();
        for msg in msgs {
            self.names
                .push(SockAddr::from(addr::to_family(msg.addr, v6)?));
        }
        // One address per message; never fewer, so the headers below are all initialised.
        debug_assert_eq!(self.names.len(), n);
        let n = n.min(self.names.len());

        for (i, msg) in msgs[..n].iter().enumerate() {
            self.iovecs[i] = libc::iovec {
                iov_base: msg.data.as_ptr().cast_mut().cast(),
                iov_len: msg.data.len(),
            };
        }

        let iovecs = self.iovecs.as_mut_ptr();
        for (i, (msg, name)) in self.msgs[..n].iter_mut().zip(&self.names).enumerate() {
            // SAFETY: `i < n` and `iovecs` holds at least `n` initialised elements
            // (`reserve(n)` above), so the offset is in bounds of the allocation.
            let iovec = unsafe { iovecs.add(i) };
            msg.msg_len = 0;
            msg.msg_hdr.msg_name = name.as_ptr().cast_mut().cast();
            msg.msg_hdr.msg_namelen = name.len();
            msg.msg_hdr.msg_iov = iovec;
            msg.msg_hdr.msg_iovlen = 1 as _;
            msg.msg_hdr.msg_control = ptr::null_mut();
            msg.msg_hdr.msg_controllen = 0 as _;
            msg.msg_hdr.msg_flags = 0;
        }

        loop {
            // SAFETY: `fd` is a valid socket for the duration of the call, and `msgs` points to
            // `n` initialised `mmsghdr`s, each describing one iovec over a live payload of
            // `msgs[i]` and one address that lives in `self.names` for the whole call. The
            // kernel only reads through these pointers.
            let ret = unsafe { libc::sendmmsg(fd, self.msgs.as_mut_ptr(), n as libc::c_uint, 0) };
            if ret >= 0 {
                return Ok((ret as usize).min(n));
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }
}

/// Converts a kernel-filled `sockaddr_storage` into a [`SocketAddr`] (`None` for a family we do
/// not speak, which a UDP socket never reports).
fn socket_addr(storage: &libc::sockaddr_storage, len: libc::socklen_t) -> Option<SocketAddr> {
    let len = len.min(size_of::<libc::sockaddr_storage>() as libc::socklen_t);
    let mut owned = SockAddrStorage::zeroed();
    // SAFETY: `SockAddrStorage` is a `repr(transparent)` wrapper around `sockaddr_storage`, so
    // that is a valid view type for it, and the copy is between two values of the same type.
    unsafe { *owned.view_as::<libc::sockaddr_storage>() = *storage };
    // SAFETY: the kernel wrote an address of `len` bytes (clamped to the storage size above)
    // into `storage`, which we just copied verbatim, so family and length agree.
    let addr = unsafe { SockAddr::new(owned, len) };
    addr.as_socket()
}
