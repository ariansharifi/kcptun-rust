//! The client's local listener: Go's `net.ListenTCP` / `net.ListenUnix` block.
//!
//! Go picks between the two by asking `net.SplitHostPort` whether `-localaddr` is a `host:port`
//! (`client/main.go:317-332`), resolves it, binds, and prints `listener.Addr()` — the address the
//! socket really got, so `-l :12948` logs `[::]:12948` while a failing bind names the *resolved*
//! address, `listen tcp :12948: bind: address already in use`. Both are reproduced here.
//!
//! The family rules are Go's `favoriteAddrFamily`, the same ones `kcptun_kcp::addr::listen_udp`
//! implements for the UDP side: a wildcard address gets a dual-stack `AF_INET6` socket (with
//! `IPV6_V6ONLY` off, and an `AF_INET` fallback for a kernel with no usable IPv6 stack), anything
//! else the family of the address itself. `SO_REUSEADDR` is set on every listener, as Go's
//! `setDefaultListenerSockopts` does.

use std::io;

use kcptun_kcp::addr::{self, UdpAddr};
use kcptun_std::mainutil::op_error;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

/// The backlog `listen(2)` is given.
///
/// Go computes `listenerBacklog()` from `net.core.somaxconn` (Linux) or `kern.ipc.somaxconn`
/// (BSD/macOS) once per process. Both kernels clamp a larger request to that same maximum, so
/// asking for more than either default is equivalent without reading `/proc` or `sysctl`.
// Go: go1.27.1 net/sock_linux.go:maxListenerBacklog(), net/sock_bsd.go:maxListenerBacklog()
const LISTEN_BACKLOG: i32 = 4096;

/// The syscall a failed `accept` names in Go's `*net.OpError`.
// Go: go1.27.1 internal/poll/sock_cloexec_linux.go (accept4), internal/poll/sys_cloexec.go
#[cfg(target_os = "linux")]
const ACCEPT_SYSCALL: &str = "accept4";
/// The syscall a failed `accept` names in Go's `*net.OpError`.
#[cfg(not(target_os = "linux"))]
const ACCEPT_SYSCALL: &str = "accept";

/// The listener `-localaddr` asks for.
// Go: kcptun/client/main.go:317 — `var listener net.Listener`
#[derive(Debug)]
pub enum LocalListener {
    /// `net.ListenTCP("tcp", addr)`, with `listener.Addr()` pre-rendered.
    Tcp { listener: TcpListener, addr: String },
    /// `net.ListenUnix("unix", addr)`; the address is the path, verbatim as Go keeps it.
    #[cfg(unix)]
    Unix {
        listener: UnixListener,
        path: String,
    },
}

/// One accepted local client.
// Go: the `net.Conn` of `listener.Accept()`
#[derive(Debug)]
pub enum LocalConn {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl LocalListener {
    /// `listener.Addr()` as `log.Println` renders it.
    pub fn addr_string(&self) -> String {
        match self {
            LocalListener::Tcp { addr, .. } => addr.clone(),
            #[cfg(unix)]
            LocalListener::Unix { path, .. } => path.clone(),
        }
    }

    /// Go's `listener.Accept()`, with the peer address already rendered as `%v`.
    ///
    /// Go's `fd.accept` retries `EINTR` and `ECONNABORTED` itself and only hands real failures to
    /// `Accept`; tokio surfaces them, so they are retried here instead — without that, a peer
    /// that resets between the SYN and the `accept` would take the whole client down through
    /// `log.Fatalf`.
    // Go: kcptun/client/main.go:425, go1.27.1 net/fd_unix.go:(*netFD).accept()
    pub async fn accept(&self) -> Result<(LocalConn, String), String> {
        loop {
            match self {
                LocalListener::Tcp { listener, addr } => match listener.accept().await {
                    Ok((stream, peer)) => {
                        // Go turns Nagle off on every accepted TCP connection; tokio does not,
                        // and the error is dropped there too.
                        // Go: net/tcpsock_posix.go:newTCPConn() — `setNoDelay(fd, true)`
                        let _ = stream.set_nodelay(true);
                        // A dual-stack listener (`-l :12948`) reports an IPv4 peer as
                        // `::ffff:a.b.c.d`; Go's `net.IP.String()` unmaps it and prints the
                        // dotted quad, Rust's `SocketAddr` does not. The same string goes into
                        // `stream opened`, `pipe:` and `stream closed`.
                        // Go: go1.27.1 net/ip.go:(IP).String()
                        return Ok((LocalConn::Tcp(stream), addr::canonical(peer).to_string()));
                    }
                    Err(err) if is_retryable(&err) => continue,
                    Err(err) => {
                        return Err(op_error("accept", "tcp", Some(addr), ACCEPT_SYSCALL, &err));
                    }
                },
                #[cfg(unix)]
                LocalListener::Unix { listener, path } => match listener.accept().await {
                    // Go's `RemoteAddr()` for an accepted unix connection is the peer's name,
                    // which is empty for the unnamed sockets clients normally use — so the log
                    // line really does read `stream opened in:  out: …`.
                    Ok((stream, peer)) => {
                        let name = peer
                            .as_pathname()
                            .map_or_else(String::new, |p| p.display().to_string());
                        return Ok((LocalConn::Unix(stream), name));
                    }
                    Err(err) if is_retryable(&err) => continue,
                    Err(err) => {
                        return Err(op_error("accept", "unix", Some(path), ACCEPT_SYSCALL, &err));
                    }
                },
            }
        }
    }
}

/// Whether Go's own accept loop would have retried instead of returning this error.
// Go: go1.27.1 net/fd_unix.go:(*netFD).accept() — EINTR and ECONNABORTED continue
fn is_retryable(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
    )
}

/// Go's `net.ResolveTCPAddr` + `net.ListenTCP`.
// Go: kcptun/client/main.go:328-331
pub fn listen_tcp(local_addr: &str) -> Result<LocalListener, String> {
    let laddr = resolve_tcp_addr(local_addr)?;
    let listener = bind_tcp(&laddr)
        .map_err(|err| op_error("listen", "tcp", Some(&laddr.to_string()), "bind", &err))?;
    // Go has no step here (`net.ListenTCP` hands back a ready listener), so there is no
    // `*net.OpError` to name — but this text reaches a `log.Fatalf` line, so its errno is
    // spelled from Go's table like every other one (D30).
    let listener =
        TcpListener::from_std(listener).map_err(|err| kcptun_std::config::go_error_text(&err))?;
    // Go logs `listener.Addr()`, the address the socket actually bound.
    let addr = listener
        .local_addr()
        .map_or_else(|_| laddr.to_string(), |a| a.to_string());
    Ok(LocalListener::Tcp { listener, addr })
}

/// Go's `net.ResolveUnixAddr` + `net.ListenUnix`.
///
/// `ResolveUnixAddr("unix", path)` cannot fail, so only the bind reports anything. Unlike Go on
/// Linux, a path beginning with `@` is **not** turned into an abstract socket address here: it
/// becomes a file of that name. Nothing in kcptun's documentation uses one, and the translation
/// lives in Go's `syscall.SockaddrUnix`, not in kcptun.
// Go: kcptun/client/main.go:323-326, go1.27.1 syscall/syscall_linux.go (the `@` translation)
#[cfg(unix)]
pub fn listen_unix(local_addr: &str) -> Result<LocalListener, String> {
    let listener = UnixListener::bind(local_addr).map_err(|err| {
        // Go: go1.27.1 syscall/syscall_unix.go:(*SockaddrUnix).sockaddr() — a path that does not
        // fit in `sun_path` is EINVAL, so Go prints `bind: invalid argument`. Rust's `std`
        // pre-checks the same threshold but answers a bare `InvalidInput` with a text of its own
        // (`path must be shorter than SUN_LEN`), so the errno is put back here.
        let err = if err.raw_os_error().is_none() && err.kind() == io::ErrorKind::InvalidInput {
            io::Error::from_raw_os_error(libc::EINVAL)
        } else {
            err
        };
        op_error("listen", "unix", Some(local_addr), "bind", &err)
    })?;
    Ok(LocalListener::Unix {
        listener,
        path: local_addr.to_string(),
    })
}

/// Deviation V09: no unix-domain sockets off unix.
#[cfg(not(unix))]
pub fn listen_unix(local_addr: &str) -> Result<LocalListener, String> {
    Err(format!("listen unix {local_addr}: os not supported"))
}

/// Go's `net.ResolveTCPAddr("tcp", address)`.
///
/// The resolver is `kcptun_kcp::addr`'s, which is a port of the same `internetAddrList` Go uses
/// for both protocols; only the network name differs, and it is visible in exactly one error
/// text — the one for a port that is not a number, where Go consults `/etc/services` and this
/// port does not (see the module docs of `crates/kcp/src/addr.rs`). That text is rewritten here
/// so `-l host:http` reports Go's `address tcp/http: unknown port` rather than `udp/http`.
// Go: go1.27.1 net/tcpsock.go:ResolveTCPAddr()
fn resolve_tcp_addr(address: &str) -> Result<UdpAddr, String> {
    addr::resolve_udp_addr("udp", address).map_err(|err| {
        let text = err.to_string();
        match text.strip_prefix("address udp/") {
            Some(rest) => format!("address tcp/{rest}"),
            None => text,
        }
    })
}

/// `net.ListenTCP`'s socket, with Go's family choice and default listener socket options.
// Go: go1.27.1 net/tcpsock.go:ListenTCP(), net/ipsock_posix.go:favoriteAddrFamily()
fn bind_tcp(laddr: &UdpAddr) -> io::Result<std::net::TcpListener> {
    if laddr.is_wildcard() {
        // Go: `if supportsIPv4map() || !supportsIPv4() { return AF_INET6, false }` — the
        // dual-stack socket, with an AF_INET fallback for a kernel that has no IPv6 at all.
        match bind_tcp_family(Domain::IPV6, false, laddr) {
            Err(err) if is_no_ipv6_stack(&err) => bind_tcp_family(Domain::IPV4, false, laddr),
            other => other,
        }
    } else {
        // Go: `laddr.family()` — the family of the address being bound.
        let v6 = !laddr.is_ipv4();
        bind_tcp_family(if v6 { Domain::IPV6 } else { Domain::IPV4 }, false, laddr)
    }
}

fn bind_tcp_family(
    domain: Domain,
    only_v6: bool,
    laddr: &UdpAddr,
) -> io::Result<std::net::TcpListener> {
    let v6 = domain == Domain::IPV6;
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    // Go: net/sockopt_linux.go:setDefaultSockopts() — the IPV6_V6ONLY error is dropped ("some
    // operating systems never admit this option").
    if v6 {
        let _ = socket.set_only_v6(only_v6);
    }
    // Go: net/sockopt_posix.go:setDefaultListenerSockopts() — SO_REUSEADDR on every listener.
    socket.set_reuse_address(true)?;
    socket.bind(&laddr.to_socket_addr(v6)?.into())?;
    socket.listen(LISTEN_BACKLOG)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

/// Reports whether `err` is what Go's capability probe reads as "this kernel has no usable IPv6
/// stack", the only reason `favoriteAddrFamily` answers AF_INET for a wildcard listen. Anything
/// else — the port being taken, a policy denial — is a real error of this bind.
// Go: go1.27.1 net/ipsock_posix.go:(*ipStackCapabilities).probe()
fn is_no_ipv6_stack(err: &io::Error) -> bool {
    if err.kind() == io::ErrorKind::AddrNotAvailable {
        return true;
    }
    #[cfg(unix)]
    {
        matches!(
            err.raw_os_error(),
            Some(libc::EAFNOSUPPORT) | Some(libc::EPROTONOSUPPORT)
        )
    }
    #[cfg(not(unix))]
    {
        false
    }
}
