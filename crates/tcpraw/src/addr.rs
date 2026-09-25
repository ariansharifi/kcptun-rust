//! Go `net` address semantics for the TCP addresses tcpraw resolves and keys its flow table by.
//!
//! `Dial` takes a `network`/`address` pair and resolves it with `net.ResolveTCPAddr`, whose
//! behaviour kcptun deployments depend on: the port is numeric, a bare host name prefers the
//! **first IPv4** answer unless it was written as a bracketed IPv6 literal, and `"tcp4"`/`"tcp6"`
//! restrict the family. `std`'s `ToSocketAddrs` returns the resolver's own order instead, so the
//! preference is applied here.
//!
//! The flow table is keyed by the peer address. Go keys it by `net.Addr.String()`, and
//! `net.IP.String()` prints `::ffff:a.b.c.d` as `a.b.c.d`, so the key a captured segment produces
//! and the key `WriteTo` looks up always agree; Rust's `SocketAddr` keeps the two forms apart, so
//! [`canonical`] unmaps them first.
//!
//! Go reference: `go1.27.1 net/{tcpsock.go,ipsock.go,lookup.go,port.go,ip.go}`,
//! `tcpraw@v1.2.32 tcp_linux.go:Dial()`.
//!
//! This duplicates a little of `kcptun-kcp::addr` (the same Go functions, for UDP). The TCP half
//! was written here while the two crates were independent; `kcptun-tcpraw` now depends on
//! `kcptun-kcp` for the `PacketConn` trait, so the duplication is no longer forced by the
//! dependency graph: it is simply not worth the churn of undoing while the module is covered by
//! its own tests and its Go counterparts differ in the network prefix.
//!
//! TODO: fold the shared helpers back into `kcptun-kcp`,
//! `pub use kcptun_kcp::addr::{split_host_port, canonical, ip_string, is_ipv4, unmap_ip};`,
//! keeping only `resolve_tcp_addr`/`for_resolve`/`with_zone` here, or generalise
//! `kcptun_kcp::addr::resolve_udp_addr` over the `udp`/`tcp` network prefix and call that.
#![forbid(unsafe_code)]

use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, ToSocketAddrs};

/// Resolves `address` for `network` (`""`, `"tcp"`, `"tcp4"` or `"tcp6"`) the way Go's
/// `net.ResolveTCPAddr` does: split, parse the port, take the literal IP or look the host name
/// up, filter by the network's family and prefer IPv4 unless the host was a bracketed IPv6
/// literal.
///
/// The lookup blocks, as Go's does; `Dial` runs it once, before anything else.
///
/// Go's `TCPAddr` has a nil `IP` for an address without a host (`":29900"`), which `DialTCP` then
/// turns into the wildcard; the equivalent `0.0.0.0` is returned here, since a `SocketAddr`
/// cannot express "no IP".
// Go: go1.27.1 net/tcpsock.go:ResolveTCPAddr(), net/ipsock.go:(*Resolver).internetAddrList()
pub fn resolve_tcp_addr(network: &str, address: &str) -> io::Result<SocketAddr> {
    let network = match network {
        // Go: "a hint wildcard for Go 1.0 undocumented behavior".
        "" => "tcp",
        "tcp" | "tcp4" | "tcp6" => network,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown network {other}"),
            ));
        }
    };

    // Go: net/ipsock.go:(*Resolver).internetAddrList().
    let (host, port) = if address.is_empty() {
        ("", 0)
    } else {
        let (host, port) = split_host_port(address)?;
        (host, lookup_port(network, port)?)
    };
    if host.is_empty() {
        return Ok(SocketAddr::V4(SocketAddrV4::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            port,
        )));
    }

    // A literal address is used as it stands; anything else is a name for the resolver (Go:
    // `lookupIPAddr` parses the host with `netip.ParseAddr` first, zone included).
    let (literal, zone) = match host.parse::<IpAddr>() {
        Ok(ip) => (Some(ip), ""),
        Err(_) => match split_zone(host) {
            (addr, zone) if !zone.is_empty() => match addr.parse::<IpAddr>() {
                Ok(ip) => (Some(ip), zone),
                Err(_) => (None, ""),
            },
            _ => (None, ""),
        },
    };
    let ips = match literal {
        Some(ip) => vec![ip],
        None => lookup_ip(host)?,
    };

    let Some(ip) = for_resolve(network, address, &ips) else {
        return Err(addr_error(host, "no suitable address found"));
    };
    Ok(with_zone(ip, port, zone))
}

/// Builds the `SocketAddr` for an address, carrying an IPv6 zone into the scope id.
///
/// An interface name is translated by the system resolver (`getaddrinfo` understands
/// `fe80::1%eth0`), which keeps this module free of `unsafe`; an unknown name gives scope 0, the
/// unscoped address, exactly what a miss in Go's `zoneCache` produces.
// Go: go1.27.1 net/ipsock_posix.go:ipToSockaddrInet6(), net/interface.go:zoneCache.index()
fn with_zone(ip: IpAddr, port: u16, zone: &str) -> SocketAddr {
    if zone.is_empty() || !matches!(ip, IpAddr::V6(_)) {
        return SocketAddr::new(ip, port);
    }
    let scope = match zone.parse::<u32>() {
        Ok(index) => index,
        Err(_) => format!("[fe80::1%{zone}]:0")
            .to_socket_addrs()
            .ok()
            .and_then(|mut it| it.next())
            .map(|a| match a {
                SocketAddr::V6(a) => a.scope_id(),
                SocketAddr::V4(_) => 0,
            })
            .unwrap_or(0),
    };
    match ip {
        IpAddr::V6(v6) => SocketAddr::V6(std::net::SocketAddrV6::new(v6, port, 0, scope)),
        IpAddr::V4(_) => SocketAddr::new(ip, port),
    }
}

/// Picks the address `ResolveTCPAddr` would return from a resolver's answers: keep only the
/// family the network allows, then prefer the first IPv4 answer unless the address was written as
/// a bracketed IPv6 literal, in which case prefer the first non-IPv4 one. If neither matches, the
/// first remaining answer wins; `None` means the filter left nothing.
// Go: go1.27.1 net/ipsock.go:filterAddrList(), (addrList).forResolve(), (addrList).first()
fn for_resolve(network: &str, address: &str, ips: &[IpAddr]) -> Option<IpAddr> {
    let allowed = |ip: &IpAddr| match network {
        "tcp4" => is_ipv4(*ip),
        "tcp6" => !is_ipv4(*ip),
        _ => true,
    };
    let first = *ips.iter().find(|ip| allowed(ip))?;
    let want6 = address.contains('[');
    Some(
        ips.iter()
            .copied()
            .find(|ip| allowed(ip) && if want6 { !is_ipv4(*ip) } else { is_ipv4(*ip) })
            .unwrap_or(first),
    )
}

/// Splits a `"host:port"` string into host and port, exactly like Go's `net.SplitHostPort`,
/// including its error texts (`missing port in address`, `too many colons in address`, …).
///
/// `Dial` uses it on the address it is given. Go also splits `tcpconn.LocalAddr().String()` with
/// it to obtain the `-s`/`--sport` operands of the iptables rule; this port takes those from the
/// `SocketAddr` directly, because Rust's `Display` prints an IPv4-mapped address in a form
/// `iptables` rejects (see [`ip_string`]).
// Go: go1.27.1 net/ipsock.go:SplitHostPort()
pub fn split_host_port(hostport: &str) -> io::Result<(&str, &str)> {
    const MISSING_PORT: &str = "missing port in address";
    const TOO_MANY_COLONS: &str = "too many colons in address";

    let (j, k, host);
    // The port starts after the last colon.
    let Some(i) = hostport.rfind(':') else {
        return Err(addr_error(hostport, MISSING_PORT));
    };

    if hostport.starts_with('[') {
        // Expect the first ']' just before the last ':'.
        let Some(end) = hostport.find(']') else {
            return Err(addr_error(hostport, "missing ']' in address"));
        };
        if end + 1 == hostport.len() {
            // There can't be a ':' behind the ']' now.
            return Err(addr_error(hostport, MISSING_PORT));
        } else if end + 1 != i {
            // Either ']' isn't followed by a colon, or it is followed by a colon that is not the
            // last one.
            if hostport.as_bytes()[end + 1] == b':' {
                return Err(addr_error(hostport, TOO_MANY_COLONS));
            }
            return Err(addr_error(hostport, MISSING_PORT));
        }
        host = &hostport[1..end];
        // There can't be a '[' resp. ']' before these positions.
        (j, k) = (1, end + 1);
    } else {
        host = &hostport[..i];
        if host.contains(':') {
            return Err(addr_error(hostport, TOO_MANY_COLONS));
        }
        (j, k) = (0, 0);
    }
    if hostport[j..].contains('[') {
        return Err(addr_error(hostport, "unexpected '[' in address"));
    }
    if hostport[k..].contains(']') {
        return Err(addr_error(hostport, "unexpected ']' in address"));
    }

    Ok((host, &hostport[i + 1..]))
}

/// Go's `LookupPort` restricted to numeric ports.
///
/// Go additionally consults `/etc/services` for named ports; kcptun's `-r` is always numeric, and
/// a name produces the same `unknown port` error Go gives for a name that is not in the services
/// database.
// Go: go1.27.1 net/lookup.go:(*Resolver).LookupPort(), net/port.go:parsePort()
fn lookup_port(network: &str, service: &str) -> io::Result<u16> {
    // Go: "Lock in the legacy behavior that an empty string means port 0."
    if service.is_empty() {
        return Ok(0);
    }
    let (neg, digits) = match service.as_bytes().first() {
        Some(b'+') => (false, &service[1..]),
        Some(b'-') => (true, &service[1..]),
        _ => (false, service),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(addr_error(&format!("{network}/{service}"), "unknown port"));
    }
    // Go clamps overflowing values instead of failing; either way they fail the range check
    // below with `Addr: service`, so saturating is equivalent.
    let port: i64 = digits.parse::<i64>().unwrap_or(i64::MAX);
    let port = if neg { -port } else { port };
    if !(0..=65535).contains(&port) {
        return Err(addr_error(service, "invalid port"));
    }
    Ok(port as u16)
}

/// Looks a host name up, keeping the resolver's order ([`for_resolve`] applies Go's preference).
// Go: go1.27.1 net/lookup.go:(*Resolver).lookupIPAddr(), net/net.go:(*DNSError).Error()
fn lookup_ip(host: &str) -> io::Result<Vec<IpAddr>> {
    // Port 0 keeps this a pure name lookup; `to_socket_addrs` needs one. A failed lookup carries
    // Go's `*net.DNSError` text, which kcptun logs verbatim, instead of the platform's
    // getaddrinfo message.
    let addrs: Vec<IpAddr> = (host, 0u16)
        .to_socket_addrs()
        .map_err(|_| no_such_host(host))?
        .map(|a| a.ip())
        .collect();
    if addrs.is_empty() {
        return Err(no_such_host(host));
    }
    Ok(addrs)
}

/// Go's `(&DNSError{Err: errNoSuchHost.Error(), Name: host}).Error()`.
// Go: go1.27.1 net/net.go:(*DNSError).Error(), net/dnsclient_unix.go:errNoSuchHost
fn no_such_host(host: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("lookup {host}: no such host"),
    )
}

/// Go's `net.AddrError`: `address <addr>: <err>`.
// Go: go1.27.1 net/net.go:(*AddrError).Error()
fn addr_error(addr: &str, err: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("address {addr}: {err}"),
    )
}

/// Creates the real TCP listener of a listening tcpraw connection, like Go's
/// `net.ListenTCP(network, laddr)`, with Go's family choice: `"tcp4"` → `AF_INET`, `"tcp6"` →
/// `AF_INET6` with `IPV6_V6ONLY`, and `"tcp"` → a **dual-stack** `AF_INET6` socket whenever the
/// local address is the wildcard (`0.0.0.0` or `[::]`), else the family of the local address.
///
/// This is why `kcptun-server -l :29900 --tcp` serves IPv4 and IPv6 peers on one socket, exactly
/// as the Go binary does: `ResolveTCPAddr(":29900")` has no IP at all (`0.0.0.0` here, since a
/// `SocketAddr` cannot express "no IP"), `favoriteAddrFamily` answers `AF_INET6` with
/// `IPV6_V6ONLY` off, and `ipToSockaddrInet6` turns the IPv4 wildcard into `::`.
///
/// Go decides between the dual-stack socket and an `AF_INET` one by probing the kernel once
/// (`supportsIPv4map()`, `supportsIPv4()`); this tries the dual-stack socket and falls back only
/// on the errors that probe would have seen as "no usable IPv6 stack", which is also how
/// `kcptun-kcp`'s UDP listener reads them. Every other error: the port being taken, a policy
/// denial: is returned unchanged.
///
/// The returned listener is non-blocking, ready for `tokio::net::TcpListener::from_std`.
// Go: go1.27.1 net/tcpsock.go:ListenTCP(), net/ipsock_posix.go:favoriteAddrFamily(),
//     net/sock_posix.go:(*netFD).listenStream()
pub fn listen_tcp(network: &str, laddr: SocketAddr) -> io::Result<std::net::TcpListener> {
    match network {
        "tcp4" => bind_tcp(false, false, laddr),
        "tcp6" => bind_tcp(true, true, laddr),
        // Go: "a hint wildcard for Go 1.0 undocumented behavior".
        "" | "tcp" => {
            if laddr.ip().is_unspecified() {
                // Go: `if supportsIPv4map() || !supportsIPv4() { return AF_INET6, false }`.
                match bind_tcp(true, false, laddr) {
                    Err(err) if is_no_ipv6_stack(&err) => bind_tcp(false, false, laddr),
                    other => other,
                }
            } else {
                // Go: `laddr.family()`, the family of the address being bound.
                bind_tcp(!is_ipv4(laddr.ip()), false, laddr)
            }
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown network {other}"),
        )),
    }
}

/// Creates one socket of the given family, applies the options Go applies to a stream listener
/// and binds and listens on `laddr`.
// Go: go1.27.1 net/sock_posix.go:socket(), (*netFD).listenStream(),
//     net/sockopt_linux.go:setDefaultSockopts(), setDefaultListenerSockopts()
fn bind_tcp(v6: bool, only_v6: bool, laddr: SocketAddr) -> io::Result<std::net::TcpListener> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};

    let domain = if v6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if v6 {
        // Go: net/sockopt_linux.go:setDefaultSockopts(), the IPV6_V6ONLY error is dropped
        // ("some operating systems never admit this option"), so a dual-stack listen degrades to
        // an IPv6-only one rather than failing.
        let _ = socket.set_only_v6(only_v6);
    }
    // Go: setDefaultListenerSockopts(), "allow reuse of recently-used addresses". This error Go
    // does return.
    socket.set_reuse_address(true)?;
    socket.bind(&SockAddr::from(bind_addr(v6, laddr)?))?;
    socket.listen(listener_backlog())?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

/// Re-encodes the local address for a socket of the given family, like Go's `ipToSockaddr`: on an
/// `AF_INET6` socket the IPv4 wildcard becomes `::` and any other IPv4 address becomes
/// IPv4-mapped, and on an `AF_INET` socket an IPv4-mapped address is unmapped while a genuine
/// IPv6 one is Go's `non-IPv4 address` error.
// Go: go1.27.1 net/ipsock_posix.go:ipToSockaddrInet4(), ipToSockaddrInet6()
fn bind_addr(v6: bool, laddr: SocketAddr) -> io::Result<SocketAddr> {
    let port = laddr.port();
    if v6 {
        // Go: "when the IP node supports IPv4-mapped IPv6 address, we allow a listener to listen
        // to the wildcard address of both IP addressing spaces by specifying IPv6 wildcard
        // address": `if len(ip) == 0 || ip.Equal(IPv4zero) { ip = IPv6zero }`.
        let ip = match laddr.ip() {
            IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            IpAddr::V4(v4) => IpAddr::V6(v4.to_ipv6_mapped()),
            v6 @ IpAddr::V6(_) => v6,
        };
        return Ok(SocketAddr::new(ip, port));
    }
    match unmap_ip(laddr.ip()) {
        ip @ IpAddr::V4(_) => Ok(SocketAddr::new(ip, port)),
        ip @ IpAddr::V6(_) => Err(addr_error(&ip.to_string(), "non-IPv4 address")),
    }
}

/// Reports whether `err` is what Go's capability probe reads as "this kernel has no usable IPv6
/// stack", and thus the only reason `favoriteAddrFamily` would answer `AF_INET` for a wildcard
/// listen: the `AF_INET6` socket cannot be created at all, or binding an IPv6 address on it
/// yields `EADDRNOTAVAIL` (what `net.ipv6.conf.all.disable_ipv6=1` produces).
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

/// The `listen(2)` backlog Go passes: `/proc/sys/net/core/somaxconn` when it can be read and is
/// neither zero nor unparsable, else `SOMAXCONN`.
///
/// Go truncates a value the kernel could not store: `maxAckBacklog` is 65535 on Linux < 4.1 and
/// 2^32-1 from 4.1 on, and Go picks between the two by reading the running kernel's version.
/// This port deliberately applies the pre-4.1 cap of 65535 unconditionally instead of parsing
/// `uname(2)`: it is the conservative end of Go's own range, a `somaxconn` above 65535 is rare,
/// and the kernel clamps the backlog to `somaxconn` anyway, so the resulting accept queue
/// differs from Go's only on a host tuned above 65535, where 65535 pending connections is
/// already far more than kcptun's single listener can have outstanding.
///
/// The value is parsed as a `u32`, as Go parses it, so that a huge `somaxconn` caps rather than
/// failing to parse and falling back to `SOMAXCONN`.
// Go: go1.27.1 net/sock_linux.go:maxListenerBacklog(), net/sock_posix.go:listenerBacklog()
fn listener_backlog() -> i32 {
    #[cfg(target_os = "linux")]
    if let Ok(text) = std::fs::read_to_string("/proc/sys/net/core/somaxconn") {
        // Go: `l, ok := fd.readLine(); f := getFields(l); n, _, ok := dtoi(f[0])`, then
        // `if n == 0 || !ok { return syscall.SOMAXCONN }`.
        if let Some(field) = text
            .lines()
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .next()
            && let Ok(n) = field.parse::<u32>()
            && n != 0
        {
            return n.min((1 << 16) - 1) as i32;
        }
    }
    #[cfg(unix)]
    {
        libc::SOMAXCONN
    }
    #[cfg(not(unix))]
    {
        128
    }
}

/// Splits `"fe80::1%eth0"` into `("fe80::1", "eth0")`.
// Go: go1.27.1 net/ipsock.go:splitHostZone()
fn split_zone(host: &str) -> (&str, &str) {
    match host.rfind('%') {
        Some(i) => (&host[..i], &host[i + 1..]),
        None => (host, ""),
    }
}

/// Canonicalises a peer address for use as a flow-table key: an IPv4-mapped IPv6 address becomes
/// the plain IPv4 address, so that the key a captured segment produces and the key `WriteTo` is
/// handed are the same one.
///
/// Go needs no such call: its key is `net.Addr.String()`, and `net.IP.String()` already prints
/// `::ffff:a.b.c.d` as `a.b.c.d`.
// Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).lockflow() (`key := addr.String()`)
pub fn canonical(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(a) => match a.ip().to_ipv4_mapped() {
            Some(ip) if a.scope_id() == 0 => SocketAddr::V4(SocketAddrV4::new(ip, a.port())),
            _ => addr,
        },
        SocketAddr::V4(_) => addr,
    }
}

/// The `*net.TCPAddr` that `Listen`'s failing `net.ListenTCP` names, printed as Go prints it.
///
/// Go's `net.ListenTCP` builds its `*net.OpError` around `laddr.opAddr()`, the very
/// `*net.TCPAddr` that `net.ResolveTCPAddr` returned, and that address has a **nil `IP`** when
/// the argument had no host, which `(*TCPAddr).String()` renders as an empty host: `-l :29900`
/// gives `listen tcp :29900: …`. [`resolve_tcp_addr`] cannot carry a nil IP in a `SocketAddr`
/// and flattens it to `0.0.0.0`, so the original `address` is consulted here to put the empty
/// host back.
///
/// Anything else is the resolved address, unmapped the way `net.IP.String()` prints it
/// (`JoinHostPort` brackets an IPv6 host), which is what `SocketAddr`'s `Display` does once
/// [`canonical`] has unmapped it. An IPv6 zone prints as the numeric scope id rather than the
/// interface name Go prints, the same limitation `dial`'s `connect` error has.
// Go: go1.27.1 net/tcpsock.go:ListenTCP(), (*TCPAddr).String(), net/ipsock.go:JoinHostPort(),
//     net/ip.go:ipEmptyString()
pub fn listen_addr_string(address: &str, laddr: SocketAddr) -> String {
    // Go: `internetAddrList` leaves `IP` nil for an empty host, and for an empty address it never
    // looks one up at all.
    let no_host =
        address.is_empty() || split_host_port(address).is_ok_and(|(host, _)| host.is_empty());
    if no_host {
        // Go: `JoinHostPort("", itoa(a.Port))`.
        return format!(":{}", laddr.port());
    }
    canonical(laddr).to_string()
}

/// The text a failed [`listen_tcp`] carries, spelled the way Go's `net` package spells it:
/// `listen <network> <laddr>: bind: <errno>`.
///
/// `net.ListenTCP` wraps what the kernel refused in
/// `&net.OpError{Op: "listen", Net: network, Addr: laddr.opAddr(),
/// Err: os.NewSyscallError("bind", errno)}`, and tcpraw's `Listen` returns that error unchanged,
/// so a `--tcp` server whose TCP port is already taken logs
/// `listen tcp :29900: bind: address already in use` in Go and, with this, here too. That is the
/// one failure a *privileged* `--tcp` server actually hits: the raw sockets succeed and the real
/// listener is what collides.
///
/// The syscall is named `bind` because that is the one that fails in practice (`address already
/// in use`, `permission denied`, `cannot assign requested address`); a `socket` or `setsockopt`
/// failure inside the same call would be named differently by Go. `kcptun_std`'s UDP counterpart,
/// `kcptun-server`'s `listen_error`, makes the same choice for the same reason.
///
/// Only a **syscall** failure is wrapped. The other error [`listen_tcp`] can return is the
/// `unknown network …` one, which Go builds without a `*os.SyscallError`, and which is in any
/// case unreachable, because [`resolve_tcp_addr`] has already rejected the same set of networks
/// with the same text before `Listen` gets here.
///
/// The `io::ErrorKind` is kept, so a caller can still tell the errno class apart; only the text
/// changes.
// Go: go1.27.1 net/tcpsock.go:ListenTCP(), net/net.go:(*OpError).Error(),
//     os/error.go:(*SyscallError).Error(), tcpraw@v1.2.32 tcp_linux.go:Listen()
pub fn listen_op_error(
    network: &str,
    address: &str,
    laddr: SocketAddr,
    err: io::Error,
) -> io::Error {
    if err.raw_os_error().is_none() {
        return err;
    }
    io::Error::new(
        err.kind(),
        format!(
            // Go's `OpError.Net` is the network string the caller passed, not a normalised one.
            "listen {network} {addr}: bind: {text}",
            addr = listen_addr_string(address, laddr),
            text = errno_text(&err)
        ),
    )
}

/// Go's `syscall.Errno.Error()`, spelled from Go's own errno table (**DECISIONS D30**).
///
/// `kcptun_kcp::goerrno` holds the table; `kcptun_std::config::go_error_text` is the same call
/// on the other side of the dependency graph (`kcptun-std` depends on *this* crate, because its
/// exit hook runs `iptables_reset`, so the shared part sits below both).
// Go: go1.27.1 syscall/syscall_unix.go:(Errno).Error()
pub(crate) fn errno_text(err: &io::Error) -> String {
    kcptun_kcp::goerrno::go_error_text(err)
}

/// Go's `net.IP.String()` for the families tcpraw uses: an IPv4-mapped IPv6 address prints as the
/// IPv4 address it wraps. This is what goes into the `-d` operand of the iptables rule.
// Go: go1.27.1 net/ip.go:(IP).String()
pub fn ip_string(ip: IpAddr) -> String {
    unmap_ip(ip).to_string()
}

/// Go's `IP.To4() != nil`: a plain IPv4 address, or an IPv4-mapped IPv6 one.
// Go: go1.27.1 net/ip.go:(IP).To4()
pub fn is_ipv4(ip: IpAddr) -> bool {
    matches!(unmap_ip(ip), IpAddr::V4(_))
}

/// Turns an IPv4-mapped IPv6 address into the IPv4 address it wraps, leaving everything else
/// alone.
///
/// Go's `net` package unmaps wherever an address meets a socket: `ipToSockaddr` builds a
/// `sockaddr_in` from a mapped address once `favoriteAddrFamily` has picked `AF_INET` for it, so
/// an `AF_INET` socket never sees the mapped form. Rust's `SocketAddr` keeps it, so the callers
/// that hand an address to a syscall or to `iptables` unmap it here first.
// Go: go1.27.1 net/ip.go:(IP).To4(), net/ipsock_posix.go:ipToSockaddr()
pub fn unmap_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        IpAddr::V4(_) => ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `net.SplitHostPort` on the forms `Dial` meets: the address it is given and the local
    /// address of the established connection.
    #[test]
    fn split_host_port_matches_go() {
        assert_eq!(
            split_host_port("192.168.1.5:54321").expect("v4"),
            ("192.168.1.5", "54321")
        );
        assert_eq!(split_host_port("[::1]:443").expect("v6"), ("::1", "443"));
        assert_eq!(
            split_host_port("[fe80::1%eth0]:443").expect("zone"),
            ("fe80::1%eth0", "443")
        );
        assert_eq!(
            split_host_port("example.com:80").expect("name"),
            ("example.com", "80")
        );
        assert_eq!(split_host_port(":29900").expect("wildcard"), ("", "29900"));

        for (input, want) in [
            ("1.2.3.4", "address 1.2.3.4: missing port in address"),
            ("::1:443", "address ::1:443: too many colons in address"),
            ("[::1]", "address [::1]: missing port in address"),
            ("[::1:443", "address [::1:443: missing ']' in address"),
        ] {
            assert_eq!(
                split_host_port(input).expect_err(input).to_string(),
                want,
                "{input}"
            );
        }
    }

    /// Literal addresses resolve without a lookup, and the port is parsed with Go's texts.
    #[test]
    fn resolve_tcp_addr_literals() {
        assert_eq!(
            resolve_tcp_addr("tcp", "192.168.1.5:29900").expect("v4"),
            "192.168.1.5:29900".parse::<SocketAddr>().expect("literal")
        );
        assert_eq!(
            resolve_tcp_addr("tcp", "[2001:db8::1]:29900").expect("v6"),
            "[2001:db8::1]:29900"
                .parse::<SocketAddr>()
                .expect("literal")
        );
        // The empty network is Go's "tcp" wildcard hint.
        assert_eq!(
            resolve_tcp_addr("", "127.0.0.1:1").expect("empty network"),
            "127.0.0.1:1".parse::<SocketAddr>().expect("literal")
        );
        assert_eq!(
            resolve_tcp_addr("udp", "127.0.0.1:1")
                .expect_err("wrong network")
                .to_string(),
            "unknown network udp"
        );
        assert_eq!(
            resolve_tcp_addr("tcp", "127.0.0.1:http")
                .expect_err("named port")
                .to_string(),
            "address tcp/http: unknown port"
        );
        assert_eq!(
            resolve_tcp_addr("tcp", "127.0.0.1:70000")
                .expect_err("range")
                .to_string(),
            "address 70000: invalid port"
        );
    }

    /// The family filter and the IPv4 preference of `addrList.forResolve`.
    #[test]
    fn for_resolve_prefers_ipv4_unless_bracketed() {
        let v4: IpAddr = "1.2.3.4".parse().expect("literal");
        let v6: IpAddr = "2001:db8::1".parse().expect("literal");

        // Resolver order v6, v4: Go still takes the IPv4 answer for "tcp".
        assert_eq!(for_resolve("tcp", "host:80", &[v6, v4]), Some(v4));
        // A bracketed literal flips the preference.
        assert_eq!(for_resolve("tcp", "[::1]:80", &[v4, v6]), Some(v6));
        // Only one family left after the filter: the first allowed answer wins.
        assert_eq!(for_resolve("tcp6", "host:80", &[v4, v6]), Some(v6));
        assert_eq!(for_resolve("tcp4", "host:80", &[v6, v4]), Some(v4));
        assert_eq!(for_resolve("tcp4", "host:80", &[v6]), None);
        // No IPv4 answer and no bracket: the first allowed one.
        assert_eq!(for_resolve("tcp", "host:80", &[v6]), Some(v6));
    }

    /// Flow-table keys: `::ffff:a.b.c.d` and `a.b.c.d` are one address, as `net.IP.String()`
    /// makes them.
    #[test]
    fn canonical_unmaps_ipv4_mapped_addresses() {
        let mapped: SocketAddr = "[::ffff:10.0.0.1]:29900".parse().expect("literal");
        let plain: SocketAddr = "10.0.0.1:29900".parse().expect("literal");
        assert_eq!(canonical(mapped), plain);
        assert_eq!(canonical(plain), plain);

        let v6: SocketAddr = "[2001:db8::1]:29900".parse().expect("literal");
        assert_eq!(canonical(v6), v6);

        assert_eq!(ip_string(mapped.ip()), "10.0.0.1");
        assert!(is_ipv4(mapped.ip()));
        assert!(!is_ipv4(v6.ip()));

        // What the raw socket is connected to: an `AF_INET` socket needs the 4-byte form.
        assert_eq!(unmap_ip(mapped.ip()), plain.ip());
        assert_eq!(unmap_ip(plain.ip()), plain.ip());
        assert_eq!(unmap_ip(v6.ip()), v6.ip());
    }

    /// `ipToSockaddr` for a listening socket: the IPv4 wildcard becomes `::` on an `AF_INET6`
    /// socket, any other IPv4 address becomes IPv4-mapped, and a genuine IPv6 address on an
    /// `AF_INET` socket is Go's `non-IPv4 address`.
    #[test]
    fn bind_addr_matches_ip_to_sockaddr() {
        let wildcard: SocketAddr = "0.0.0.0:29900".parse().expect("literal");
        assert_eq!(
            bind_addr(true, wildcard).expect("dual stack"),
            "[::]:29900".parse().expect("literal")
        );
        assert_eq!(bind_addr(false, wildcard).expect("v4"), wildcard);

        let v4: SocketAddr = "192.168.1.5:29900".parse().expect("literal");
        assert_eq!(
            bind_addr(true, v4).expect("mapped"),
            "[::ffff:192.168.1.5]:29900".parse().expect("literal")
        );

        let v6: SocketAddr = "[2001:db8::1]:29900".parse().expect("literal");
        assert_eq!(bind_addr(true, v6).expect("v6"), v6);
        assert_eq!(
            bind_addr(false, v6).expect_err("v6 on AF_INET").to_string(),
            "address 2001:db8::1: non-IPv4 address"
        );

        // An IPv4-mapped address is unmapped for an `AF_INET` socket, as `IP.To4()` does.
        let mapped: SocketAddr = "[::ffff:10.0.0.1]:29900".parse().expect("literal");
        assert_eq!(
            bind_addr(false, mapped).expect("unmapped"),
            "10.0.0.1:29900".parse().expect("literal")
        );
    }

    /// A wildcard `"tcp"` listen binds one **dual-stack** socket, which is what makes
    /// `-l :29900 --tcp` serve IPv4 peers on an `[::]` listener, exactly as the Go binary does.
    ///
    /// The port is kernel-assigned and the socket lives for a few milliseconds (the same
    /// short-lived wildcard bind the `kcptun-kcp` dual-stack tests make).
    #[test]
    fn listen_tcp_binds_a_dual_stack_wildcard() {
        let laddr = resolve_tcp_addr("tcp", ":0").expect("wildcard");
        assert_eq!(laddr, "0.0.0.0:0".parse::<SocketAddr>().expect("literal"));

        let listener = listen_tcp("tcp", laddr).expect("listen");
        let local = listener.local_addr().expect("addr");
        assert!(
            matches!(local, SocketAddr::V6(_)),
            "the wildcard listener is AF_INET6: {local}"
        );
        assert!(local.ip().is_unspecified());

        // An IPv4 client reaches it, i.e. IPV6_V6ONLY is off.
        let port = local.port();
        let client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("v4 connect");
        let (accepted, peer) = accept_blocking(&listener).expect("accept");
        assert_eq!(
            canonical(peer).ip(),
            "127.0.0.1".parse::<IpAddr>().expect("literal"),
            "the IPv4 peer arrives IPv4-mapped"
        );
        drop((client, accepted, listener));
    }

    /// The explicit networks pick the family without probing, and `"tcp6"` is IPv6-only.
    #[test]
    fn listen_tcp_honours_the_network_suffix() {
        let v4 = listen_tcp("tcp4", "127.0.0.1:0".parse().expect("literal")).expect("tcp4");
        assert!(matches!(v4.local_addr().expect("addr"), SocketAddr::V4(_)));

        let v6 = listen_tcp("tcp6", "[::1]:0".parse().expect("literal")).expect("tcp6");
        assert!(matches!(v6.local_addr().expect("addr"), SocketAddr::V6(_)));

        // A specified IPv4 address on `"tcp"` gives an AF_INET socket, not a dual-stack one.
        let plain = listen_tcp("tcp", "127.0.0.1:0".parse().expect("literal")).expect("tcp");
        assert!(matches!(
            plain.local_addr().expect("addr"),
            SocketAddr::V4(_)
        ));

        assert_eq!(
            listen_tcp("udp", "127.0.0.1:0".parse().expect("literal"))
                .expect_err("wrong network")
                .to_string(),
            "unknown network udp"
        );
    }

    /// `accept` on the non-blocking listener `listen_tcp` returns, for the test above: it is
    /// handed to tokio in production, and polled here.
    fn accept_blocking(
        listener: &std::net::TcpListener,
    ) -> io::Result<(std::net::TcpStream, SocketAddr)> {
        for _ in 0..1000 {
            match listener.accept() {
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                other => return other,
            }
        }
        Err(io::Error::new(io::ErrorKind::TimedOut, "no connection"))
    }

    /// The backlog is a positive number on every host: either `somaxconn` or `SOMAXCONN`.
    #[test]
    fn listener_backlog_is_positive() {
        assert!(listener_backlog() > 0);
        assert!(listener_backlog() < 1 << 16);
    }

    /// An error that is not an errno keeps its text (only the first letter is lowered).
    #[test]
    fn a_non_errno_keeps_its_text() {
        let err = io::Error::new(io::ErrorKind::InvalidInput, "Nothing to do");
        assert_eq!(errno_text(&err), "nothing to do");
    }

    /// Go's `laddr.opAddr()` is the *resolved* `*net.TCPAddr`, whose nil `IP` prints as an empty
    /// host, so `-l :29900` keeps its empty host and does not become `0.0.0.0`.
    #[test]
    fn listen_addr_string_restores_gos_nil_ip() {
        let wildcard = resolve_tcp_addr("tcp", ":29900").expect("wildcard");
        assert_eq!(listen_addr_string(":29900", wildcard), ":29900");

        // An address that really named the wildcard prints it, as Go's 4-byte `IPv4zero` does.
        let named = resolve_tcp_addr("tcp", "0.0.0.0:29900").expect("named wildcard");
        assert_eq!(listen_addr_string("0.0.0.0:29900", named), "0.0.0.0:29900");

        // `JoinHostPort` brackets an IPv6 host.
        let v6 = resolve_tcp_addr("tcp6", "[::1]:29900").expect("v6");
        assert_eq!(listen_addr_string("[::1]:29900", v6), "[::1]:29900");

        // A name is printed as what it resolved to, which is what Go's `OpError` carries.
        let named = resolve_tcp_addr("tcp4", "localhost:29900").expect("localhost");
        assert_eq!(
            listen_addr_string("localhost:29900", named),
            "127.0.0.1:29900"
        );

        // `net.IP.String()` unmaps, so an IPv4-mapped address never reaches the log bracketed.
        let mapped: SocketAddr = "[::ffff:10.0.0.1]:29900".parse().expect("literal");
        assert_eq!(
            listen_addr_string("[::ffff:10.0.0.1]:29900", mapped),
            "10.0.0.1:29900"
        );

        // An empty address is Go's zero `TCPAddr`: nil IP, port 0.
        let empty = resolve_tcp_addr("tcp", "").expect("empty");
        assert_eq!(listen_addr_string("", empty), ":0");
    }

    /// The failure a privileged `--tcp` server actually hits reads exactly as Go's
    /// `net.ListenTCP` reports it: the line `kcptun-server` logs beside `Listening on:` when the
    /// raw sockets came up but the TCP port is taken.
    #[test]
    fn a_failed_tcp_bind_reads_like_gos_net_op_error() {
        // A genuine `EADDRINUSE` from the kernel, so the errno text is the platform's own:
        // `SO_REUSEADDR` (which `bind_tcp` sets, as Go does) never lets a second socket bind to
        // an actively listening one.
        let taken = listen_tcp("tcp4", "127.0.0.1:0".parse().expect("literal")).expect("first");
        let port = taken.local_addr().expect("addr").port();
        let same: SocketAddr = format!("127.0.0.1:{port}").parse().expect("literal");
        let err = listen_tcp("tcp4", same).expect_err("second bind on the same port");
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);

        // Go: `listen tcp4 127.0.0.1:<port>: bind: address already in use`.
        let wrapped = listen_op_error("tcp4", &same.to_string(), same, err);
        assert_eq!(wrapped.kind(), io::ErrorKind::AddrInUse);
        assert_eq!(
            wrapped.to_string(),
            format!("listen tcp4 127.0.0.1:{port}: bind: address already in use")
        );

        // The line a `--tcp` server prints for the flag it is actually started with: Go's nil
        // `TCPAddr.IP` keeps the host empty.
        let err = listen_tcp("tcp4", same).expect_err("second bind on the same port");
        let laddr = resolve_tcp_addr("tcp", ":29900").expect("wildcard");
        assert_eq!(
            listen_op_error("tcp", ":29900", laddr, err).to_string(),
            "listen tcp :29900: bind: address already in use"
        );
        drop(taken);

        // An error without an errno is the `unknown network …` one, which Go builds without a
        // `*os.SyscallError`: it is passed through untouched.
        let plain = io::Error::new(io::ErrorKind::InvalidInput, "unknown network udp");
        assert_eq!(
            listen_op_error("udp", ":29900", laddr, plain).to_string(),
            "unknown network udp"
        );
    }
}
