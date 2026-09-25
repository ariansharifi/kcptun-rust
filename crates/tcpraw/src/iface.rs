//! The interface addresses a listening connection opens its raw sockets on.
//!
//! Go's `Listen` walks `net.Interfaces()` and, for every interface, the `*net.IPNet` entries of
//! `iface.Addrs()`, opening one raw socket per address — loopback and IPv6 included, and with no
//! filter on the interface flags, so the addresses of a down interface are tried as well.
//!
//! On Linux both of Go's calls are one `RTM_GETADDR` netlink dump; `getifaddrs(3)` is glibc's
//! (and musl's) wrapper around exactly that dump, so it yields the same set of addresses in the
//! same per-interface order. The zone of an IPv6 link-local address is dropped here because Go
//! drops it too: a `net.IPNet` has no `Zone` field, so `net.ListenIP("ip:tcp", &net.IPAddr{IP:
//! ipaddr.IP})` binds `fe80::1` with `sin6_scope_id = 0` — which the kernel usually refuses, and
//! `Listen` then simply records the error and carries on with the other addresses.
//!
//! Go reference: `tcpraw@v1.2.32 tcp_linux.go:Listen()`, `go1.27.1
//! net/interface_linux.go:interfaceAddrTable()`.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Every IPv4 and IPv6 address of every interface, in the order `getifaddrs(3)` reports them.
///
/// Addresses of other families (`AF_PACKET` on Linux, `AF_LINK` on the BSDs) are skipped, which
/// is what Go's `if ipaddr, ok := addr.(*net.IPNet); ok` does — its address table only ever holds
/// `*net.IPNet` for IP families and `*net.IPAddr` never appears from `interfaceAddrTable`.
///
/// Duplicates are **not** removed: Go keeps whatever the kernel lists, so an address configured
/// on two interfaces gives two raw sockets there and here alike.
// Go: tcpraw@v1.2.32 tcp_linux.go:Listen() (`net.Interfaces()` + `iface.Addrs()`)
pub fn interface_addrs() -> io::Result<Vec<IpAddr>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` takes a pointer to a caller-owned `*mut ifaddrs`, which is what is
    // passed. On success (0) it stores the head of a freshly allocated list there, released by
    // the `freeifaddrs` below; on failure it stores nothing and there is nothing to release.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut addrs = Vec::new();
    let mut node = head;
    // No early return inside this loop: `head` has to reach `freeifaddrs` below.
    while !node.is_null() {
        // SAFETY: `node` is either the head of the list `getifaddrs` just built or a pointer
        // taken from a previous node's `ifa_next`, and the whole list stays alive and unmodified
        // until `freeifaddrs` runs after the loop. The reference is dropped before the next
        // iteration reassigns `node`.
        let entry = unsafe { &*node };
        if let Some(ip) = sockaddr_ip(entry.ifa_addr) {
            addrs.push(ip);
        }
        node = entry.ifa_next;
    }

    // SAFETY: `head` is the list `getifaddrs` returned above, it has not been freed, and no
    // pointer into it is used after this call (`addrs` holds copies).
    unsafe { libc::freeifaddrs(head) };
    Ok(addrs)
}

/// Reads the IP address out of a `sockaddr`, or `None` for a null pointer or any family other
/// than `AF_INET`/`AF_INET6`.
fn sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        // `ifa_addr` is null for an interface without an address, which glibc still lists.
        return None;
    }

    // SAFETY: every `sockaddr` starts with `sa_family`, whatever the family; the pointer comes
    // from `getifaddrs` and points at a live, correctly aligned `sockaddr` of at least that size.
    // The read is unaligned-safe, so no alignment assumption is made about the concrete family
    // struct either.
    let family = unsafe { std::ptr::read_unaligned(std::ptr::addr_of!((*sa).sa_family)) };

    match i32::from(family) {
        libc::AF_INET => {
            // SAFETY: the family says this `sockaddr` is a `sockaddr_in`, which is how
            // `getifaddrs` allocated it, so reading that many bytes stays inside the allocation.
            let sin: libc::sockaddr_in = unsafe { std::ptr::read_unaligned(sa.cast()) };
            // `s_addr` is in network byte order.
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                sin.sin_addr.s_addr,
            ))))
        }
        libc::AF_INET6 => {
            // SAFETY: as above, with the family saying `sockaddr_in6`.
            let sin6: libc::sockaddr_in6 = unsafe { std::ptr::read_unaligned(sa.cast()) };
            // Go drops the scope id with the rest of the zone; see the module docs.
            Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every host has at least a loopback address, and every address that comes back is one of
    /// the two IP families — nothing else may leak out of the `sockaddr` decoding.
    #[test]
    fn interface_addrs_lists_the_loopback_address() {
        let addrs = interface_addrs().expect("getifaddrs");
        assert!(
            addrs.iter().any(|ip| ip.is_loopback()),
            "no loopback address among {addrs:?}"
        );
        for ip in &addrs {
            assert!(
                matches!(ip, IpAddr::V4(_) | IpAddr::V6(_)),
                "unexpected family in {ip:?}"
            );
        }
    }

    /// The list is stable between two calls and is not truncated or leaked into by the walk.
    #[test]
    fn interface_addrs_is_repeatable() {
        let first = interface_addrs().expect("getifaddrs");
        let second = interface_addrs().expect("getifaddrs");
        assert_eq!(first, second);
        assert!(!first.is_empty());
    }

    /// A null `ifa_addr` (an interface without an address) is skipped rather than decoded.
    #[test]
    fn a_null_sockaddr_yields_nothing() {
        assert_eq!(sockaddr_ip(std::ptr::null()), None);
    }

    /// `sockaddr_in`/`sockaddr_in6` are decoded the way the kernel fills them in: the IPv4
    /// address is in network byte order and the IPv6 one is a byte array.
    #[test]
    fn sockaddr_ip_decodes_both_families() {
        // SAFETY: `sockaddr_in` and `sockaddr_in6` are plain C structs of integers and byte
        // arrays, for which an all-zero bit pattern is valid.
        let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_addr.s_addr = u32::from(Ipv4Addr::new(192, 168, 1, 5)).to_be();
        let ip = sockaddr_ip(std::ptr::from_ref(&sin).cast());
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))));

        // SAFETY: see above.
        let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        sin6.sin6_addr.s6_addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
        sin6.sin6_scope_id = 7;
        let ip = sockaddr_ip(std::ptr::from_ref(&sin6).cast());
        assert_eq!(
            ip,
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
            "the scope id is dropped, as Go's *net.IPNet drops the zone"
        );

        // A family tcpraw has no use for (AF_UNIX stands in for AF_PACKET/AF_LINK, which libc
        // does not define on every platform this file compiles on).
        // SAFETY: see above.
        let mut other: libc::sockaddr = unsafe { std::mem::zeroed() };
        other.sa_family = libc::AF_UNIX as libc::sa_family_t;
        assert_eq!(sockaddr_ip(std::ptr::from_ref(&other)), None);
    }
}
