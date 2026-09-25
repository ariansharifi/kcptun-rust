//! Go `net` address semantics for UDP sockets.
//!
//! kcp-go never touches sockets directly: it resolves and binds through the Go standard library
//! (`sess.go`: `net.ResolveUDPAddr("udp", laddr)` + `net.ListenUDP("udp", udpaddr)` for a
//! listener, `net.ListenUDP("udp4"|"udp", nil)` for a dialer). That standard library carries
//! behaviour kcptun deployments depend on, and which Rust's `std` does not reproduce:
//!
//! - `":29900"` (empty host) binds the **dual-stack** wildcard `[::]` with `IPV6_V6ONLY = 0`, so
//!   one listener serves IPv4 and IPv6 (`favoriteAddrFamily`). `std`'s `UdpSocket::bind` would
//!   pick AF_INET for `0.0.0.0` and an IPv6-only socket for `[::]`.
//! - resolving a hostname prefers the **first IPv4** answer unless the address was written as a
//!   bracketed IPv6 literal (`addrList.forResolve`); `std` returns the resolver's order.
//! - a destination address is encoded for the **socket's** family, so a dual-stack socket sends
//!   to `::ffff:a.b.c.d` (`ipToSockaddr`); `sendto` with a `sockaddr_in` on an AF_INET6 socket
//!   would fail with `EAFNOSUPPORT`.
//! - `net.IP.Equal` and `net.IP.String` treat `::ffff:a.b.c.d` and `a.b.c.d` as the same address,
//!   which is what makes the listener's session map and the read loop's source filter work for
//!   IPv4 peers of a dual-stack socket.
//!
//! Go reference: `go1.27.1/src/net/{ipsock.go,ipsock_posix.go,udpsock.go,udpsock_posix.go}` and
//! kcp-go/v5@v5.6.66 `sess.go` / `readloop.go`.
//!
//! **Port parsing** is numeric only: Go additionally consults `/etc/services` for named ports
//! (`LookupPort`), which kcptun never uses (`-l`/`-r` carry numeric ports). A named port yields
//! Go's `address udp/<name>: unknown port` error, the same error Go produces when the name is not
//! in the services database.
#![forbid(unsafe_code)]

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};

use socket2::{Domain, Protocol, Socket, Type};

#[cfg(test)]
mod tests;

/// A resolved UDP address, the port and the optional IPv6 zone kept apart as Go does.
///
/// `ip` is `None` for the wildcard address (Go's `UDPAddr.IP == nil`, printed as `":port"`),
/// which is what `ResolveUDPAddr` returns for `":29900"` or for the empty string.
// Go: go1.27.1 net/udpsock.go:UDPAddr
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct UdpAddr {
    /// The address, or `None` for the wildcard (Go's nil `IP`).
    pub ip: Option<IpAddr>,
    /// The port.
    pub port: u16,
    /// The IPv6 zone (scope) name, empty when there is none.
    pub zone: String,
}

impl UdpAddr {
    /// A wildcard address with the given port (Go's `&UDPAddr{Port: port}`).
    pub fn wildcard(port: u16) -> Self {
        UdpAddr {
            ip: None,
            port,
            zone: String::new(),
        }
    }

    /// Reports whether the address is the wildcard: no IP, or an unspecified one.
    // Go: go1.27.1 net/udpsock_posix.go:(*UDPAddr).isWildcard()
    pub fn is_wildcard(&self) -> bool {
        match self.ip {
            None => true,
            Some(ip) => ip.is_unspecified(),
        }
    }

    /// Reports whether the address is an IPv4 one, Go's `IP.To4() != nil`: a plain IPv4 address
    /// or an IPv4-mapped IPv6 address.
    // Go: go1.27.1 net/ip.go:(IP).To4()
    pub fn is_ipv4(&self) -> bool {
        self.ip.is_some_and(is_ipv4)
    }

    /// The address as a [`SocketAddr`] of the socket family `v6` selects, like Go encoding a
    /// destination for a socket of that family.
    ///
    /// See [`to_family`]; the wildcard IP becomes `0.0.0.0` or `[::]`.
    pub fn to_socket_addr(&self, v6: bool) -> io::Result<SocketAddr> {
        ip_to_sockaddr(v6, self.ip, self.port, &self.zone)
    }
}

// Go: go1.27.1 net/udpsock.go:(*UDPAddr).String()
impl fmt::Display for UdpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = match self.ip {
            // Go's ipEmptyString: a nil IP prints as the empty string.
            None => String::new(),
            Some(ip) => ip_string(ip),
        };
        let host = if self.zone.is_empty() {
            host
        } else {
            format!("{host}%{zone}", zone = self.zone)
        };
        // Go's JoinHostPort brackets a host that contains a colon.
        if host.contains(':') {
            write!(f, "[{host}]:{port}", port = self.port)
        } else {
            write!(f, "{host}:{port}", port = self.port)
        }
    }
}

/// Splits a `"host:port"` string into host and port, exactly like Go's `net.SplitHostPort`,
/// including its error texts (`missing port in address`, `too many colons in address`, …).
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

/// Resolves `address` for `network` (`""`, `"udp"`, `"udp4"` or `"udp6"`) the way Go's
/// `net.ResolveUDPAddr` does: split, parse the port, take the literal IP or look the host name up,
/// filter by the network's family and prefer IPv4 unless the host was a bracketed IPv6 literal.
///
/// Name lookups block (Go's does too); resolve before entering the hot path.
// Go: go1.27.1 net/udpsock.go:ResolveUDPAddr()
pub fn resolve_udp_addr(network: &str, address: &str) -> io::Result<UdpAddr> {
    let network = match network {
        // Go: "a hint wildcard for Go 1.0 undocumented behavior".
        "" => "udp",
        "udp" | "udp4" | "udp6" => network,
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
        return Ok(UdpAddr::wildcard(port));
    }

    // A literal address (with its optional zone) is used as it stands; anything else is a name
    // for the resolver (Go: lookupIPAddr parses `netip.ParseAddr(host)` first, zone included).
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
    Ok(UdpAddr {
        ip: Some(ip),
        port,
        zone: zone.to_string(),
    })
}

/// Picks the address `ResolveUDPAddr` would return from a resolver's answers: keep only the
/// family the network allows, then prefer the first IPv4 answer unless the address was written as
/// a bracketed IPv6 literal, in which case prefer the first non-IPv4 one. If neither matches, the
/// first remaining answer wins; `None` means the filter left nothing.
// Go: go1.27.1 net/ipsock.go:filterAddrList(), (addrList).forResolve(), (addrList).first()
fn for_resolve(network: &str, address: &str, ips: &[IpAddr]) -> Option<IpAddr> {
    let allowed = |ip: &IpAddr| match network {
        "udp4" => is_ipv4(*ip),
        "udp6" => !is_ipv4(*ip),
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

/// The network kcp-go dials `raddr` on: `"udp4"` for an IPv4 remote (so the socket is AF_INET),
/// otherwise `"udp"` (a dual-stack AF_INET6 socket).
// Go: kcp-go/v5@v5.6.66 sess.go:DialWithOptions()
pub fn dial_network(raddr: &UdpAddr) -> &'static str {
    if raddr.is_ipv4() { "udp4" } else { "udp" }
}

/// Creates and binds a UDP socket like Go's `net.ListenUDP(network, laddr)`, with Go's family
/// choice: `"udp4"` → AF_INET, `"udp6"` → AF_INET6 with `IPV6_V6ONLY`, and `"udp"` → a
/// dual-stack AF_INET6 socket whenever the local address is the wildcard (`nil`, `0.0.0.0` or
/// `[::]`), else the family of the local address.
///
/// Go decides between the dual-stack socket and an AF_INET one by probing the kernel once
/// (`supportsIPv4map()`, `supportsIPv4()`), then lets the real bind error through; this tries the
/// dual-stack socket and falls back to `0.0.0.0` only when the failure is one the probe would
/// have seen as "no usable IPv6 stack" ([`is_no_ipv6_stack`]), which gives the same outcome.
/// Every other error (`address already in use`, `permission denied`, …) is returned unchanged,
/// so a wildcard listener never silently degrades to IPv4-only.
///
/// The returned socket is non-blocking, ready for [`tokio::net::UdpSocket::from_std`].
// Go: go1.27.1 net/udpsock.go:ListenUDP(), net/ipsock_posix.go:favoriteAddrFamily()
pub fn listen_udp(network: &str, laddr: Option<&UdpAddr>) -> io::Result<std::net::UdpSocket> {
    let wildcard = laddr.is_none_or(UdpAddr::is_wildcard);
    match network {
        "udp4" => bind_udp(Domain::IPV4, false, laddr),
        "udp6" => bind_udp(Domain::IPV6, true, laddr),
        "" | "udp" => {
            if wildcard {
                // Go: `if supportsIPv4map() || !supportsIPv4() { return AF_INET6, false }`.
                match bind_udp(Domain::IPV6, false, laddr) {
                    Err(err) if is_no_ipv6_stack(&err) => bind_udp(Domain::IPV4, false, laddr),
                    other => other,
                }
            } else {
                // Go: `laddr.family()`, the family of the address being bound.
                let v6 = !laddr.is_some_and(UdpAddr::is_ipv4);
                bind_udp(if v6 { Domain::IPV6 } else { Domain::IPV4 }, false, laddr)
            }
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown network {other}"),
        )),
    }
}

/// Reports whether `err` is what Go's capability probe reads as "this kernel has no usable IPv6
/// stack", and thus the only reason `favoriteAddrFamily` would answer AF_INET for a wildcard
/// listen: the AF_INET6 socket cannot be created at all, or binding an IPv6 address on it yields
/// `EADDRNOTAVAIL` (what `net.ipv6.conf.all.disable_ipv6=1` produces). Anything else: the port
/// being taken, a policy denial: is a real error of this bind and must reach the caller.
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

fn bind_udp(
    domain: Domain,
    only_v6: bool,
    laddr: Option<&UdpAddr>,
) -> io::Result<std::net::UdpSocket> {
    let v6 = domain == Domain::IPV6;
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    // Go: go1.27.1 net/sockopt_linux.go:setDefaultSockopts(), the IPV6_V6ONLY error is dropped
    // ("some operating systems never admit this option"), so a dual-stack listen degrades to an
    // IPv6-only one rather than failing.
    if v6 {
        let _ = socket.set_only_v6(only_v6);
    }
    // Go: go1.27.1 net/sockopt_linux.go:setDefaultSockopts(), every SOCK_DGRAM socket may
    // broadcast; unlike the option above Go does return this error.
    socket.set_broadcast(true)?;
    let bind = match laddr {
        Some(laddr) => ip_to_sockaddr(v6, laddr.ip, laddr.port, &laddr.zone)?,
        None => ip_to_sockaddr(v6, None, 0, "")?,
    };
    socket.bind(&bind.into())?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

/// Re-encodes `addr` for a socket of the given family, like Go's `ipToSockaddr`: on an AF_INET6
/// socket an IPv4 destination becomes IPv4-mapped (`::ffff:a.b.c.d`), and on an AF_INET socket an
/// IPv4-mapped destination is unmapped. A genuine IPv6 address cannot be sent from an AF_INET
/// socket, which is Go's `non-IPv4 address` error.
// Go: go1.27.1 net/ipsock_posix.go:ipToSockaddr()
pub fn to_family(addr: SocketAddr, v6: bool) -> io::Result<SocketAddr> {
    match (addr, v6) {
        (SocketAddr::V4(a), true) => Ok(SocketAddr::V6(SocketAddrV6::new(
            a.ip().to_ipv6_mapped(),
            a.port(),
            0,
            0,
        ))),
        (SocketAddr::V6(a), false) => match a.ip().to_ipv4_mapped() {
            Some(ip) => Ok(SocketAddr::V4(SocketAddrV4::new(ip, a.port()))),
            None => Err(addr_error(
                &ip_string(IpAddr::V6(*a.ip())),
                "non-IPv4 address",
            )),
        },
        _ => Ok(addr),
    }
}

/// Canonicalises an address for use as a map key or in a log line: an IPv4-mapped IPv6 address
/// (what a dual-stack socket reports for an IPv4 peer) becomes the plain IPv4 address.
///
/// Go needs no such call: `net.IP.Equal` compares `::ffff:a.b.c.d` equal to `a.b.c.d` and
/// `net.IP.String` prints both as `a.b.c.d`, so the listener's `map[string]*UDPSession` and the
/// log lines are already in canonical form. Rust's `SocketAddr` compares and prints them apart.
pub fn canonical(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(a) => match a.ip().to_ipv4_mapped() {
            Some(ip) if a.scope_id() == 0 => SocketAddr::V4(SocketAddrV4::new(ip, a.port())),
            _ => addr,
        },
        SocketAddr::V4(_) => addr,
    }
}

/// Reports whether two addresses denote the same UDP peer: same port, same zone and, by Go's
/// `net.IP.Equal`, the same address with `::ffff:a.b.c.d` equal to `a.b.c.d`.
///
/// This is the client read loop's source filter.
// Go: kcp-go/v5@v5.6.66 readloop.go:sameUDPAddr()
pub fn same_udp_addr(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port() && scope_id(a) == scope_id(b) && ip_equal(a.ip(), b.ip())
}

/// Go's `net.IP.Equal`: an IPv4-mapped IPv6 address equals the IPv4 address it wraps.
// Go: go1.27.1 net/ip.go:(IP).Equal()
pub fn ip_equal(a: IpAddr, b: IpAddr) -> bool {
    unmap(a) == unmap(b)
}

/// Go's `net.IP.String()` for the address families we use: an IPv4-mapped IPv6 address prints as
/// the IPv4 address it wraps.
// Go: go1.27.1 net/ip.go:(IP).String()
pub fn ip_string(ip: IpAddr) -> String {
    unmap(ip).to_string()
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        IpAddr::V4(_) => ip,
    }
}

fn scope_id(addr: SocketAddr) -> u32 {
    match addr {
        SocketAddr::V6(a) => a.scope_id(),
        SocketAddr::V4(_) => 0,
    }
}

/// Go's `IP.To4() != nil`: a plain IPv4 address, or an IPv4-mapped IPv6 one.
fn is_ipv4(ip: IpAddr) -> bool {
    matches!(unmap(ip), IpAddr::V4(_))
}

/// Splits `"fe80::1%eth0"` into `("fe80::1", "eth0")`.
// Go: go1.27.1 net/ipsock.go:splitHostZone()
fn split_zone(host: &str) -> (&str, &str) {
    match host.rfind('%') {
        Some(i) => (&host[..i], &host[i + 1..]),
        None => (host, ""),
    }
}

/// Go's `LookupPort` restricted to numeric ports (see the module docs).
// Go: go1.27.1 net/lookup.go:(*Resolver).LookupPort(), net/port.go:parsePort()
fn lookup_port(network: &str, service: &str) -> io::Result<u16> {
    // Go: "Lock in the legacy behavior that an empty string means port 0."
    if service.is_empty() {
        return Ok(0);
    }
    let (neg, digits) = match service.strip_prefix('+') {
        Some(rest) => (false, rest),
        None => match service.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, service),
        },
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        // Go falls back to the services database here; kcptun only uses numeric ports, and this
        // is the error Go returns when the name is not in it.
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

/// Looks a host name up, keeping the resolver's order (the caller applies Go's IPv4 preference).
// Go: go1.27.1 net/lookup.go:(*Resolver).lookupIPAddr(), net/net.go:(*DNSError).Error()
fn lookup_ip(host: &str) -> io::Result<Vec<IpAddr>> {
    // Port 0 keeps this a pure name lookup; `to_socket_addrs` needs one.
    //
    // A failed lookup carries Go's `*net.DNSError` text, which kcptun logs verbatim
    // (`client/main.go:checkError`), instead of the platform's getaddrinfo message. Go's other
    // DNSError variants (`server misbehaving`, `i/o timeout`) are not distinguishable through
    // `std`, so every resolver failure maps to the common `no such host` text. Go's
    // `lookupIPAddr` never returns an empty list without an error, so the empty case reports the
    // same thing.
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

/// Go's `ipToSockaddr`, with the wildcard and zone handling of `ipToSockaddrInet4/6`.
// Go: go1.27.1 net/ipsock_posix.go:ipToSockaddrInet4(), ipToSockaddrInet6()
fn ip_to_sockaddr(v6: bool, ip: Option<IpAddr>, port: u16, zone: &str) -> io::Result<SocketAddr> {
    if v6 {
        // Go: "if len(ip) == 0 || ip.Equal(IPv4zero) { ip = IPv6zero }".
        let ip = match ip {
            None => Ipv6Addr::UNSPECIFIED,
            Some(IpAddr::V4(v4)) if v4.is_unspecified() => Ipv6Addr::UNSPECIFIED,
            Some(IpAddr::V4(v4)) => v4.to_ipv6_mapped(),
            Some(IpAddr::V6(v6)) => v6,
        };
        Ok(SocketAddr::V6(SocketAddrV6::new(
            ip,
            port,
            0,
            scope_id_for(zone),
        )))
    } else {
        let ip = match ip {
            None => Ipv4Addr::UNSPECIFIED,
            Some(ip) => match unmap(ip) {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(v6) => return Err(addr_error(&v6.to_string(), "non-IPv4 address")),
            },
        };
        Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    }
}

/// Translates an IPv6 zone into a scope id. Numeric zones are used directly; an interface name is
/// resolved by the system resolver (`getaddrinfo` understands `fe80::1%eth0`), which avoids a
/// `libc::if_nametoindex` call in this `unsafe`-free module. An unknown name gives scope 0, the
/// unscoped address, exactly what Go's `zoneCache` miss produces.
// Go: go1.27.1 net/interface.go:zoneCache.index()
fn scope_id_for(zone: &str) -> u32 {
    if zone.is_empty() {
        return 0;
    }
    if let Ok(index) = zone.parse::<u32>() {
        return index;
    }
    let probe = format!("[fe80::1%{zone}]:0");
    probe
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
        .map(scope_id)
        .unwrap_or(0)
}

/// Go's `net.AddrError`: `address <addr>: <err>`.
// Go: go1.27.1 net/net.go:(*AddrError).Error()
fn addr_error(addr: &str, err: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("address {addr}: {err}"),
    )
}
