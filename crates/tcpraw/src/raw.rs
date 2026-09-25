//! The raw `IPPROTO_TCP` sockets tcpraw crafts its segments on.
//!
//! Go uses `net.DialIP("ip:tcp", nil, &net.IPAddr{IP: raddr.IP})` for a dialled connection and
//! `net.ListenIP("ip:tcp", …)` per interface address for a listening one. Both are
//! `socket(AF_INET|AF_INET6, SOCK_RAW, IPPROTO_TCP)` with Go's runtime poller behind them; here
//! the socket is created with [`socket2`], set non-blocking and driven by tokio's
//! [`AsyncFd`](tokio::io::unix::AsyncFd), which is the same "block the task, not the thread"
//! behaviour Go's `Read`/`Write` have.
//!
//! Two things the kernel does are worth remembering:
//!
//! - an **IPv4** raw socket prepends the IP header to every read, which
//!   [`strip_ipv4_header`](crate::tcp::strip_ipv4_header) removes, exactly where Go's
//!   `(*net.IPConn).ReadFromIP` removes it. An IPv6 one delivers the TCP header directly.
//! - on send the kernel builds the IP header itself (`IP_HDRINCL` is off, as in Go), so only the
//!   TCP segment is written.
//!
//! Opening one needs `CAP_NET_RAW`.
//!
//! Go reference: `tcpraw@v1.2.32 tcp_linux.go`, `go1.27.1 net/iprawsock_posix.go`.

use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;

// Go's `syscall.Errno.Error()`. It lives in `addr` so that the platform-independent half of the
// crate — and its tests, which run everywhere — can spell an errno Go's way too.
use crate::addr::errno_text;

/// One raw socket, plus the two facts its users need about it: which family it speaks and which
/// local address the kernel gave it (the source address of the checksum's pseudo-header, Go's
/// `e.handle.LocalAddr()`).
#[derive(Debug)]
pub struct RawHandle {
    fd: AsyncFd<Socket>,
    v4: bool,
    local_ip: IpAddr,
    /// Whether the socket is `connect(2)`ed to one peer, i.e. whether it came from
    /// [`RawHandle::dial`]. Go asks the same question as `conn.tcpconn != nil` and writes with
    /// `Write` instead of `WriteToIP` when the answer is yes.
    connected: bool,
}

impl RawHandle {
    /// Opens a raw socket **connected** to `remote`, so that the kernel delivers only that peer's
    /// TCP traffic and a plain `send` reaches it.
    ///
    /// This is Go's `net.DialIP("ip:tcp", nil, &net.IPAddr{IP: raddr.IP})`, whose failures it
    /// also spells Go's way — `dial ip:tcp 203.0.113.1: socket: operation not permitted` is what
    /// a client without `CAP_NET_RAW` logs, on both sides of the port (see [`ip_op_error`]).
    // Go: tcpraw@v1.2.32 tcp_linux.go:Dial()
    pub fn dial(remote: IpAddr) -> io::Result<RawHandle> {
        // The family is Go's `favoriteAddrFamily`: an IPv4-mapped address gives an `AF_INET`
        // socket, and `ipToSockaddr` then builds a `sockaddr_in` from its four bytes. Connecting
        // an `AF_INET` socket to the mapped form instead fails with `EAFNOSUPPORT`, so the
        // address is unmapped here, exactly where Go unmaps it.
        let remote = crate::addr::unmap_ip(remote);
        let v4 = crate::addr::is_ipv4(remote);
        let domain = if v4 { Domain::IPV4 } else { Domain::IPV6 };
        let socket =
            new_raw_socket(domain).map_err(|err| ip_op_error("dial", remote, "socket", &err))?;
        socket
            .connect(&SockAddr::from(SocketAddr::new(remote, 0)))
            .map_err(|err| ip_op_error("dial", remote, "connect", &err))?;
        RawHandle::from_socket(socket, v4, true)
    }

    /// Opens a raw socket **bound** to one local address, so that the kernel delivers the TCP
    /// traffic addressed to it and every send names its destination.
    ///
    /// This is Go's `net.ListenIP("ip:tcp", &net.IPAddr{IP: ip})`, which `Listen` calls once per
    /// interface address (or once for the address it was given). Its failures carry Go's text:
    /// `listen ip:tcp 10.0.0.1: socket: operation not permitted` (see [`ip_op_error`]).
    // Go: tcpraw@v1.2.32 tcp_linux.go:Listen()
    pub fn listen(local: IpAddr) -> io::Result<RawHandle> {
        // As in `dial`: the family follows `IP.To4()`, and an `AF_INET` socket is bound to the
        // 4-byte form of an IPv4-mapped address, which is what Go's `ipToSockaddr` produces.
        let local = crate::addr::unmap_ip(local);
        let v4 = crate::addr::is_ipv4(local);
        let domain = if v4 { Domain::IPV4 } else { Domain::IPV6 };
        let socket =
            new_raw_socket(domain).map_err(|err| ip_op_error("listen", local, "socket", &err))?;
        socket
            .bind(&SockAddr::from(SocketAddr::new(local, 0)))
            .map_err(|err| ip_op_error("listen", local, "bind", &err))?;
        RawHandle::from_socket(socket, v4, false)
    }

    /// Wraps an already-configured non-blocking raw socket, reading back the local address the
    /// kernel picked for it.
    fn from_socket(socket: Socket, v4: bool, connected: bool) -> io::Result<RawHandle> {
        let local_ip = socket
            .local_addr()?
            .as_socket()
            .map(|addr| addr.ip())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "raw socket has no IP local address",
                )
            })?;
        Ok(RawHandle {
            fd: AsyncFd::new(socket)?,
            v4,
            local_ip,
            connected,
        })
    }

    /// The local address of this socket: the source address of every segment it sends.
    // Go: tcpraw@v1.2.32 tcp_linux.go:WriteTo() (`e.handle.LocalAddr().(*net.IPAddr).IP`)
    pub fn local_ip(&self) -> IpAddr {
        self.local_ip
    }

    /// Whether this is an `AF_INET` socket, i.e. whether reads carry an IPv4 header.
    pub fn is_v4(&self) -> bool {
        self.v4
    }

    /// The socket itself, so that the port of Go's `TestSettings` can read back the options the
    /// setters below wrote. Test-only: nothing in the crate needs the socket directly.
    #[cfg(test)]
    pub(crate) fn socket(&self) -> &Socket {
        self.fd.get_ref()
    }

    /// Waits for one packet and returns its length and the address it came from.
    ///
    /// For an IPv4 socket the buffer still starts with the IP header; the caller strips it, as
    /// Go's `ReadFromIP` does, and must therefore be handed the **whole** buffer.
    // Go: tcpraw@v1.2.32 tcp_linux.go:captureFlow() (`handle.ReadFromIP(buf)`)
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, IpAddr)> {
        loop {
            let mut guard = self.fd.readable().await?;
            // SAFETY: `MaybeUninit<u8>` has the same size and alignment as `u8`, and every
            // initialised byte is a valid `MaybeUninit<u8>`, so the reborrow is sound. `recv_from`
            // only writes into the slice and reports how much it wrote; no byte is ever read back
            // out of it as an initialised `u8` without having been written first.
            let uninit = unsafe { &mut *(buf as *mut [u8] as *mut [MaybeUninit<u8>]) };
            match guard.try_io(|inner| inner.get_ref().recv_from(uninit)) {
                Ok(Ok((n, from))) => {
                    let ip = from.as_socket().map(|addr| addr.ip()).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "packet from a non-IP address")
                    })?;
                    return Ok((n, ip));
                }
                Ok(Err(err)) => return Err(err),
                // Spurious readiness: wait again.
                Err(_would_block) => continue,
            }
        }
    }

    /// Sends one crafted segment to `dst`.
    ///
    /// A **dialled** handle is connected to its one peer and writes with `send(2)`, a
    /// **listening** one names the destination with `sendto(2)`. Go makes the same distinction in
    /// `WriteTo` — `if conn.tcpconn != nil { e.handle.Write(…) } else { e.handle.WriteToIP(…,
    /// &net.IPAddr{IP: raddr.IP}) }` — which is exactly "did this handle come from `Dial`".
    // Go: tcpraw@v1.2.32 tcp_linux.go:WriteTo()
    pub async fn send_to(&self, buf: &[u8], dst: IpAddr) -> io::Result<usize> {
        if self.connected {
            return self.send(buf).await;
        }
        // As on the bind and connect paths: an `AF_INET` socket takes the 4-byte form.
        let dst = SockAddr::from(SocketAddr::new(crate::addr::unmap_ip(dst), 0));
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send_to(buf, &dst)) {
                Ok(result) => return result,
                // Spurious readiness: wait again.
                Err(_would_block) => continue,
            }
        }
    }

    /// Sets the DSCP code point of the packets this socket sends.
    ///
    /// Go sets **one** option per handle, the one its family has: `IP_TOS` on an `AF_INET`
    /// socket and `IPV6_TCLASS` on an `AF_INET6` one — unlike kcp-go's UDP path, which tries
    /// both on the same socket and succeeds if either of them works.
    ///
    /// **Deviation V03**: the IPv6 value is `dscp << 2` here, where Go writes the raw DSCP into
    /// `IPV6_TCLASS` and so shifts the code point down and takes the ECN bits from DSCP's low two
    /// bits. `kcptun_kcp::io::UdpPacketConn::set_dscp` deviates in the same place for the same
    /// reason, and both read the one switch that reverts it,
    /// [`kcptun_kcp::io::GO_RAW_IPV6_TCLASS`].
    ///
    /// The error is spelled Go's way. `setDSCP` calls `syscall.SetsockoptInt` directly and hands
    /// the bare `syscall.Errno` back, with no `*net.OpError` around it — see [`errno_error`].
    // Go: tcpraw@v1.2.32 tcp_linux.go:setDSCP()
    pub fn set_dscp(&self, dscp: i32) -> io::Result<()> {
        // Go hands setsockopt a Go `int`, which the kernel reads as a C `int`.
        let tos = (i64::from(dscp) << 2) as i32;
        let socket = self.fd.get_ref();
        let result = if self.v4 {
            socket.set_tos_v4(tos as u32)
        } else {
            // Deviation V03: Go passes `dscp`, not `dscp << 2`, on this branch. The constant is
            // `kcptun-kcp`'s, so one edit reverts V03 for the UDP and the fake-TCP transport
            // together.
            let tclass = if kcptun_kcp::io::GO_RAW_IPV6_TCLASS {
                dscp
            } else {
                tos
            };
            socket.set_tclass_v6(tclass as u32)
        };
        result.map_err(|err| errno_error(&err))
    }

    /// Sets the size of this socket's receive buffer (`SO_RCVBUF`).
    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).SetReadBuffer() (`conn.handles[k].SetReadBuffer`)
    pub fn set_read_buffer(&self, bytes: usize) -> io::Result<()> {
        self.fd
            .get_ref()
            .set_recv_buffer_size(bytes)
            .map_err(|err| self.setsockopt_error(&err))
    }

    /// Sets the size of this socket's send buffer (`SO_SNDBUF`).
    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).SetWriteBuffer()
    // (`conn.handles[k].SetWriteBuffer`)
    pub fn set_write_buffer(&self, bytes: usize) -> io::Result<()> {
        self.fd
            .get_ref()
            .set_send_buffer_size(bytes)
            .map_err(|err| self.setsockopt_error(&err))
    }

    /// The text a failed `setsockopt` on a `*net.IPConn` carries: Go's `*net.OpError`,
    /// `set ip <local ip>: setsockopt: <errno>`.
    ///
    /// `SetReadBuffer` and `SetWriteBuffer` go through the `net` package, which wraps every
    /// socket-option failure this way. The network name is `ip`, not `ip:tcp`: `parseNetwork`
    /// splits the protocol off before `internetSocket` stores the name in the file descriptor.
    /// The address is the socket's `*net.IPAddr`, a bare IP with no port.
    // Go: go1.27.1 net/sockopt_posix.go:setReadBuffer(), net/net.go:(*OpError).Error()
    fn setsockopt_error(&self, err: &io::Error) -> io::Error {
        io::Error::new(
            err.kind(),
            format!(
                "set ip {ip}: setsockopt: {text}",
                ip = crate::addr::ip_string(self.local_ip),
                text = errno_text(err)
            ),
        )
    }

    /// Sends one crafted segment to the address this socket is connected to.
    // Go: tcpraw@v1.2.32 tcp_linux.go:WriteTo() (`e.handle.Write(e.buf.Bytes())`)
    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send(buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

/// An errno as Go prints a bare `syscall.Errno`, spelled from Go's own `syscall` table
/// (`kcptun_kcp::goerrno`, DECISIONS D30) — the platform's C message only for an error the table
/// has no entry for.
///
/// The error deliberately carries **no** `raw_os_error`, only the kind and the text: a socket
/// option that fails on a tcpraw connection is logged by the binaries exactly as Go logs it
/// (`log.Println("SetDSCP:", err)`), and `kcptun_std::mainutil::setsockopt_error` decides between
/// "print it bare" and "wrap it in a UDP `*net.OpError`" on `raw_os_error()`. Wrapping would be
/// wrong here: the socket is neither a UDP socket nor the one whose address the caller knows.
// Go: go1.27.1 syscall/syscall_unix.go:(Errno).Error()
fn errno_error(err: &io::Error) -> io::Error {
    io::Error::new(err.kind(), errno_text(err))
}

/// A failed syscall on an `ip:tcp` socket, spelled the way Go's `net` package spells it:
/// `<op> ip:tcp <ip>: <syscall>: <errno>`.
///
/// `net.DialIP` and `net.ListenIP` wrap what the kernel refused in
/// `&net.OpError{Op: "dial"|"listen", Net: "ip:tcp", Addr: &net.IPAddr{…},
/// Err: os.NewSyscallError("socket"|"connect"|"bind", errno)}`, and tcpraw returns that error
/// unchanged — so a client that lacks `CAP_NET_RAW` logs
/// `dial(): tcpraw.Dial(): dial ip:tcp 203.0.113.1: socket: operation not permitted` in Go and,
/// with this, here too. The network is `ip`**`:tcp`** because `net.DialIP` builds the `OpError`
/// with the name it was called with, before `parseNetwork` splits the protocol off.
///
/// The `io::ErrorKind` is kept, so a caller can still tell the errno class apart; only the text
/// changes.
// Go: go1.27.1 net/iprawsock.go:DialIP(), ListenIP(), net/net.go:(*OpError).Error(),
//     os/error.go:(*SyscallError).Error()
pub(crate) fn ip_op_error(op: &str, ip: IpAddr, syscall: &str, err: &io::Error) -> io::Error {
    io::Error::new(
        err.kind(),
        format!(
            "{op} ip:tcp {addr}: {syscall}: {text}",
            addr = crate::addr::ip_string(ip),
            text = errno_text(err)
        ),
    )
}

/// Creates the non-blocking `IPPROTO_TCP` raw socket both constructors start from, with the
/// options Go's `net` package sets on one.
// Go: go1.27.1 net/sock_posix.go:socket(), net/sockopt_linux.go:setDefaultSockopts()
fn new_raw_socket(domain: Domain) -> io::Result<Socket> {
    let socket = Socket::new(domain, Type::RAW, Some(Protocol::TCP))?;
    // Go: setDefaultSockopts() — "allow broadcast" on every `SOCK_RAW` socket, and its error is
    // returned. (`IPV6_V6ONLY` is explicitly *not* set on a raw socket, so an AF_INET6 handle
    // keeps the kernel default; tcpraw never sends an IPv4 datagram through one.)
    socket.set_broadcast(true)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `EPERM`, the errno a raw socket without `CAP_NET_RAW` answers with.
    const EPERM: i32 = 1;

    /// A failed socket option is spelled the way Go's bare `syscall.Errno` is, and carries no
    /// `raw_os_error` — which is what stops the binaries wrapping it in a UDP `*net.OpError`.
    #[test]
    fn a_socket_option_error_reads_like_gos_errno() {
        let err = errno_error(&io::Error::from_raw_os_error(EPERM));
        assert_eq!(err.to_string(), "operation not permitted");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.raw_os_error().is_none());
    }

    /// A raw socket that cannot be opened reads exactly as Go's `net.DialIP`/`net.ListenIP`
    /// report it — the line the client logs after `re-connecting: dial(): tcpraw.Dial():` and the
    /// one the server logs beside `Listening on:` when `--tcp` has no `CAP_NET_RAW`.
    #[test]
    fn a_failed_raw_socket_reads_like_gos_net_op_error() {
        let eperm = io::Error::from_raw_os_error(EPERM);
        // Go: dial ip:tcp 203.0.113.1: socket: operation not permitted
        assert_eq!(
            ip_op_error(
                "dial",
                "203.0.113.1".parse().expect("literal"),
                "socket",
                &eperm
            )
            .to_string(),
            "dial ip:tcp 203.0.113.1: socket: operation not permitted"
        );
        // Go: listen ip:tcp 10.0.0.1: socket: operation not permitted
        assert_eq!(
            ip_op_error(
                "listen",
                "10.0.0.1".parse().expect("literal"),
                "socket",
                &eperm
            )
            .to_string(),
            "listen ip:tcp 10.0.0.1: socket: operation not permitted"
        );
        // An IPv6 address is Go's `net.IP.String()`, with no brackets: an `*net.IPAddr` has no
        // port to separate.
        assert_eq!(
            ip_op_error(
                "listen",
                "2001:db8::1".parse().expect("literal"),
                "bind",
                &eperm
            )
            .to_string(),
            "listen ip:tcp 2001:db8::1: bind: operation not permitted"
        );
    }

    /// The errno class survives the rewrite, so a caller can still tell the failures apart.
    #[test]
    fn a_wrapped_op_error_keeps_its_error_kind() {
        let err = ip_op_error(
            "dial",
            "203.0.113.1".parse().expect("literal"),
            "connect",
            &io::Error::from_raw_os_error(EPERM),
        );
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }
}
