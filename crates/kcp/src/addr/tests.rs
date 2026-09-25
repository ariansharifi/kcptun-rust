//! Unit tests for the Go address semantics.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::*;

fn v4(s: &str) -> IpAddr {
    IpAddr::V4(s.parse::<Ipv4Addr>().expect("IPv4 literal"))
}

fn v6(s: &str) -> IpAddr {
    IpAddr::V6(s.parse::<Ipv6Addr>().expect("IPv6 literal"))
}

fn sa(s: &str) -> SocketAddr {
    s.parse::<SocketAddr>().expect("socket address literal")
}

// Go: go1.27.1 net/ipsock_test.go:TestSplitHostPort
#[test]
fn test_split_host_port() {
    let ok = [
        ("localhost:http", "localhost", "http"),
        ("localhost:80", "localhost", "80"),
        ("localhost%lo0:http", "localhost%lo0", "http"),
        ("[localhost%lo0]:80", "localhost%lo0", "80"),
        ("127.0.0.1:http", "127.0.0.1", "http"),
        ("127.0.0.1:80", "127.0.0.1", "80"),
        ("[::1]:http", "::1", "http"),
        ("[::1]:80", "::1", "80"),
        ("[::1%lo0]:http", "::1%lo0", "http"),
        ("[::1%lo0]:80", "::1%lo0", "80"),
        (":http", "", "http"),
        (":80", "", "80"),
        ("golang.org:", "golang.org", ""),
        ("127.0.0.1:", "127.0.0.1", ""),
        ("[::1]:", "::1", ""),
        ("golang.org:https%foo", "golang.org", "https%foo"),
    ];
    for (input, host, port) in ok {
        assert_eq!(
            split_host_port(input).expect(input),
            (host, port),
            "{input}"
        );
    }

    let bad = [
        ("golang.org", "missing port in address"),
        ("127.0.0.1", "missing port in address"),
        ("[::1]", "missing port in address"),
        ("[fe80::1%lo0]", "missing port in address"),
        ("[localhost%lo0]", "missing port in address"),
        ("localhost%lo0", "missing port in address"),
        ("::1", "too many colons in address"),
        ("fe80::1%lo0", "too many colons in address"),
        ("fe80::1%lo0:80", "too many colons in address"),
        ("[foo:bar]", "missing port in address"),
        ("[foo:bar]baz", "missing port in address"),
        ("[foo]bar:baz", "missing port in address"),
        ("[foo]:[bar]:baz", "too many colons in address"),
        ("[foo]:[bar]baz", "unexpected '[' in address"),
        ("foo[bar]:baz", "unexpected '[' in address"),
        ("foo]bar:baz", "unexpected ']' in address"),
        ("[::1", "missing ']' in address"),
    ];
    for (input, want) in bad {
        let err = split_host_port(input).expect_err(input).to_string();
        assert_eq!(err, format!("address {input}: {want}"), "{input}");
    }
}

#[test]
fn test_lookup_port() {
    assert_eq!(lookup_port("udp", "").expect("empty port"), 0);
    assert_eq!(lookup_port("udp", "29900").expect("numeric port"), 29900);
    assert_eq!(lookup_port("udp", "+80").expect("signed port"), 80);
    assert_eq!(lookup_port("udp", "65535").expect("max port"), 65535);
    assert_eq!(
        lookup_port("udp", "65536")
            .expect_err("out of range")
            .to_string(),
        "address 65536: invalid port"
    );
    assert_eq!(
        lookup_port("udp", "-1").expect_err("negative").to_string(),
        "address -1: invalid port"
    );
    assert_eq!(
        lookup_port("udp", "99999999999999999999")
            .expect_err("overflow")
            .to_string(),
        "address 99999999999999999999: invalid port"
    );
    // Numeric ports only (see the module docs): this is Go's error for an unknown service name.
    assert_eq!(
        lookup_port("udp", "http")
            .expect_err("named port")
            .to_string(),
        "address udp/http: unknown port"
    );
}

#[test]
fn resolve_wildcard() {
    for input in ["", ":29900"] {
        let addr = resolve_udp_addr("udp", input).expect(input);
        assert_eq!(addr.ip, None);
        assert!(addr.is_wildcard(), "{input}");
        assert!(!addr.is_ipv4(), "{input}");
    }
    assert_eq!(
        resolve_udp_addr("udp", ":29900").expect("wildcard").port,
        29900
    );
    assert_eq!(resolve_udp_addr("udp", "").expect("empty").port, 0);
    assert_eq!(
        resolve_udp_addr("udp", ":29900")
            .expect("wildcard")
            .to_string(),
        ":29900"
    );
}

#[test]
fn resolve_literals() {
    let addr = resolve_udp_addr("udp", "1.2.3.4:29900").expect("ipv4 literal");
    assert_eq!(
        addr,
        UdpAddr {
            ip: Some(v4("1.2.3.4")),
            port: 29900,
            zone: String::new()
        }
    );
    assert!(addr.is_ipv4());
    assert_eq!(addr.to_string(), "1.2.3.4:29900");
    assert_eq!(dial_network(&addr), "udp4");

    let addr = resolve_udp_addr("udp", "[fe80::1%lo0]:29900").expect("ipv6 literal with zone");
    assert_eq!(addr.ip, Some(v6("fe80::1")));
    assert_eq!(addr.zone, "lo0");
    assert_eq!(addr.to_string(), "[fe80::1%lo0]:29900");
    assert_eq!(dial_network(&addr), "udp");

    // Go's To4(): an IPv4-mapped literal is an IPv4 address.
    let addr = resolve_udp_addr("udp", "[::ffff:1.2.3.4]:1").expect("mapped literal");
    assert!(addr.is_ipv4());
    assert_eq!(dial_network(&addr), "udp4");
    assert_eq!(addr.to_string(), "1.2.3.4:1");

    // Wildcards keep their family for the socket, but still count as wildcards.
    assert!(
        resolve_udp_addr("udp", "0.0.0.0:1")
            .expect("v4 wildcard")
            .is_wildcard()
    );
    assert!(
        resolve_udp_addr("udp", "[::]:1")
            .expect("v6 wildcard")
            .is_wildcard()
    );

    // Family filter (Go's filterAddrList).
    assert_eq!(
        resolve_udp_addr("udp4", "[::1]:1")
            .expect_err("v6 on udp4")
            .to_string(),
        "address ::1: no suitable address found"
    );
    assert_eq!(
        resolve_udp_addr("udp6", "127.0.0.1:1")
            .expect_err("v4 on udp6")
            .to_string(),
        "address 127.0.0.1: no suitable address found"
    );
    assert_eq!(
        resolve_udp_addr("udp5", ":1")
            .expect_err("bad network")
            .to_string(),
        "unknown network udp5"
    );
    assert_eq!(
        resolve_udp_addr("udp", "127.0.0.1")
            .expect_err("no port")
            .to_string(),
        "address 127.0.0.1: missing port in address"
    );
}

// Go: go1.27.1 net/ipsock.go:(addrList).forResolve(), IPv4 first, unless the address is a
// bracketed IPv6 literal.
#[test]
fn test_for_resolve() {
    let mixed = [v6("2001:db8::1"), v4("1.2.3.4"), v4("5.6.7.8")];
    assert_eq!(for_resolve("udp", "host:1", &mixed), Some(v4("1.2.3.4")));
    assert_eq!(
        for_resolve("udp", "[host]:1", &mixed),
        Some(v6("2001:db8::1"))
    );
    assert_eq!(for_resolve("udp4", "host:1", &mixed), Some(v4("1.2.3.4")));
    assert_eq!(
        for_resolve("udp6", "host:1", &mixed),
        Some(v6("2001:db8::1"))
    );

    // No match for the preference: Go's `first` falls back to the first element of the list.
    let only6 = [v6("2001:db8::1"), v6("2001:db8::2")];
    assert_eq!(
        for_resolve("udp", "host:1", &only6),
        Some(v6("2001:db8::1"))
    );
    let only4 = [v4("1.2.3.4")];
    assert_eq!(for_resolve("udp", "[host]:1", &only4), Some(v4("1.2.3.4")));

    // Everything filtered out.
    assert_eq!(for_resolve("udp6", "host:1", &only4), None);
    assert_eq!(for_resolve("udp4", "host:1", &only6), None);

    // An IPv4-mapped answer is IPv4 for the filter and the preference.
    let mapped = [v6("2001:db8::1"), v6("::ffff:1.2.3.4")];
    assert_eq!(
        for_resolve("udp", "host:1", &mapped),
        Some(v6("::ffff:1.2.3.4"))
    );
    assert_eq!(
        for_resolve("udp6", "host:1", &mapped),
        Some(v6("2001:db8::1"))
    );
}

#[test]
fn resolve_localhost_prefers_ipv4() {
    // `localhost` resolves to 127.0.0.1 and/or ::1 depending on the host's configuration; Go
    // picks IPv4 whenever the resolver offers one.
    let addr = resolve_udp_addr("udp", "localhost:29900").expect("localhost");
    assert_eq!(addr.port, 29900);
    let ips = lookup_ip("localhost").expect("localhost lookup");
    if ips.iter().copied().any(is_ipv4) {
        assert!(addr.is_ipv4(), "expected an IPv4 address, got {addr}");
    }
}

#[test]
fn test_canonical_and_equality() {
    // What a dual-stack socket reports for an IPv4 peer.
    let mapped = sa("[::ffff:127.0.0.1]:29900");
    let plain = sa("127.0.0.1:29900");
    assert_eq!(canonical(mapped), plain);
    assert_eq!(canonical(plain), plain);
    assert_eq!(canonical(sa("[::1]:29900")), sa("[::1]:29900"));
    assert_eq!(ip_string(v6("::ffff:1.2.3.4")), "1.2.3.4");
    assert_eq!(ip_string(v6("2001:db8::1")), "2001:db8::1");

    // Go: readloop.go:sameUDPAddr() over net.IP.Equal.
    assert!(same_udp_addr(mapped, plain));
    assert!(same_udp_addr(plain, mapped));
    assert!(!same_udp_addr(plain, sa("127.0.0.1:29901")));
    assert!(!same_udp_addr(plain, sa("127.0.0.2:29900")));
    assert!(!same_udp_addr(sa("[::1]:1"), sa("127.0.0.1:1")));
    // Different zones are different addresses.
    let zone1 = SocketAddr::V6(std::net::SocketAddrV6::new(v6_raw("fe80::1"), 1, 0, 1));
    let zone2 = SocketAddr::V6(std::net::SocketAddrV6::new(v6_raw("fe80::1"), 1, 0, 2));
    assert!(!same_udp_addr(zone1, zone2));
    assert!(same_udp_addr(zone1, zone1));
}

fn v6_raw(s: &str) -> Ipv6Addr {
    s.parse::<Ipv6Addr>().expect("IPv6 literal")
}

// Go: go1.27.1 net/ipsock_posix.go:ipToSockaddr()
#[test]
fn test_to_family() {
    // A dual-stack socket sends to an IPv4 peer through the mapped address.
    assert_eq!(
        to_family(sa("1.2.3.4:1"), true).expect("map"),
        sa("[::ffff:1.2.3.4]:1")
    );
    assert_eq!(
        to_family(sa("[::ffff:1.2.3.4]:1"), false).expect("unmap"),
        sa("1.2.3.4:1")
    );
    assert_eq!(
        to_family(sa("1.2.3.4:1"), false).expect("v4"),
        sa("1.2.3.4:1")
    );
    assert_eq!(
        to_family(sa("[2001:db8::1]:1"), true).expect("v6"),
        sa("[2001:db8::1]:1")
    );
    assert_eq!(
        to_family(sa("[2001:db8::1]:1"), false)
            .expect_err("v6 on a v4 socket")
            .to_string(),
        "address 2001:db8::1: non-IPv4 address"
    );
}

#[test]
fn wildcard_listener_is_dual_stack() {
    let addr = resolve_udp_addr("udp", ":0").expect("wildcard");
    let socket = listen_udp("udp", Some(&addr)).expect("listen wildcard");
    let local = socket.local_addr().expect("local addr");
    match local {
        SocketAddr::V6(v6) => {
            assert!(v6.ip().is_unspecified());
            let sock = socket2::SockRef::from(&socket);
            assert!(!sock.only_v6().expect("only_v6"), "IPV6_V6ONLY must be off");
        }
        // Only on a host without a usable IPv6 stack (the fallback path).
        SocketAddr::V4(v4) => assert!(v4.ip().is_unspecified()),
    }

    // `0.0.0.0` is a wildcard too, so Go binds it dual-stack as well.
    let addr = resolve_udp_addr("udp", "0.0.0.0:0").expect("v4 wildcard");
    let socket = listen_udp("udp", Some(&addr)).expect("listen v4 wildcard");
    assert!(
        socket
            .local_addr()
            .expect("local addr")
            .ip()
            .is_unspecified()
    );
}

#[test]
fn listen_families() {
    let socket = listen_udp("udp4", None).expect("udp4");
    assert!(matches!(
        socket.local_addr().expect("local addr"),
        SocketAddr::V4(_)
    ));
    // Go: net/sockopt_linux.go:setDefaultSockopts() sets SO_BROADCAST on every SOCK_DGRAM socket.
    assert!(
        socket2::SockRef::from(&socket)
            .broadcast()
            .expect("broadcast")
    );

    let socket = listen_udp("udp6", None).expect("udp6");
    let local = socket.local_addr().expect("local addr");
    assert!(matches!(local, SocketAddr::V6(_)));
    assert!(socket2::SockRef::from(&socket).only_v6().expect("only_v6"));

    // A non-wildcard address keeps its own family.
    let addr = resolve_udp_addr("udp", "127.0.0.1:0").expect("loopback");
    let socket = listen_udp("udp", Some(&addr)).expect("listen loopback");
    assert!(matches!(
        socket.local_addr().expect("local addr"),
        SocketAddr::V4(_)
    ));

    assert!(listen_udp("udp5", None).is_err());
    // An IPv6 address cannot be bound on an AF_INET socket.
    let addr = resolve_udp_addr("udp", "[::1]:0").expect("v6 loopback");
    assert!(listen_udp("udp4", Some(&addr)).is_err());
}

/// A wildcard listen must report a real bind failure instead of quietly falling back to an
/// IPv4-only socket: Go's `net.ListenUDP("udp", ":port")` returns `address already in use` here.
#[test]
fn listen_wildcard_reports_bind_error() {
    let v6 = resolve_udp_addr("udp6", "[::1]:0").expect("v6 loopback");
    let Ok(held) = listen_udp("udp6", Some(&v6)) else {
        // No IPv6 stack on this host; the fallback under test cannot be exercised.
        return;
    };
    let port = held.local_addr().expect("local addr").port();

    let err = listen_udp("udp", Some(&UdpAddr::wildcard(port)))
        .expect_err("wildcard bind over a held port must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse, "{err}");
}

#[test]
fn test_dial_network() {
    assert_eq!(
        dial_network(&resolve_udp_addr("udp", "1.2.3.4:1").expect("v4")),
        "udp4"
    );
    assert_eq!(
        dial_network(&resolve_udp_addr("udp", "[2001:db8::1]:1").expect("v6")),
        "udp"
    );
    // Go's DialWithOptions uses `udpaddr.IP.To4() == nil`, so a wildcard remote is dual-stack.
    assert_eq!(dial_network(&UdpAddr::wildcard(1)), "udp");
}
