//! The TCP checksum and its IPv4/IPv6 pseudo-header.
//!
//! tcpraw does not compute checksums itself: it hands gopacket a `layers.IPv4` or `layers.IPv6`
//! through `SetNetworkLayerForChecksum` and serialises with `ComputeChecksums: true`. The
//! arithmetic below is therefore a port of gopacket's, including the way it splits the work:
//! [`PseudoHeader::partial_checksum`] sums only the addresses (gopacket's
//! `pseudoheaderChecksum`), and [`compute_checksum`] adds the protocol number and the segment
//! length (gopacket's `computeChecksum`) before folding over the bytes.
//!
//! Go reference: `gopacket@v1.1.19 layers/tcpip.go`, used from
//! `tcpraw@v1.2.32 tcp_linux.go:WriteTo()`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// Go: gopacket@v1.1.19 layers/ip_protocol.go:IPProtocolTCP
/// IP protocol number of TCP, the value that goes into the pseudo-header.
pub const IP_PROTOCOL_TCP: u8 = 6;

/// The network layer a TCP segment's checksum is computed over.
///
/// Go builds a throwaway `layers.IPv4{Protocol: TCP, SrcIP: …, DstIP: …}` or
/// `layers.IPv6{NextHeader: TCP, SrcIP: …, DstIP: …}` per write; only the two addresses are ever
/// read by the checksum, so this carries just those.
// Go: tcpraw@v1.2.32 tcp_linux.go:WriteTo() (the `layers.IPv4` / `layers.IPv6` it builds)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PseudoHeader {
    /// IPv4 pseudo-header: source and destination address.
    V4 {
        /// Source address (the raw handle's local address in Go).
        src: Ipv4Addr,
        /// Destination address.
        dst: Ipv4Addr,
    },
    /// IPv6 pseudo-header: source and destination address.
    V6 {
        /// Source address (the raw handle's local address in Go).
        src: Ipv6Addr,
        /// Destination address.
        dst: Ipv6Addr,
    },
}

impl PseudoHeader {
    /// Builds the pseudo-header for a segment from `src` to `dst`, choosing the family the way
    /// Go does: `raddr.IP.To4() != nil` selects IPv4, so an IPv4-mapped IPv6 address
    /// (`::ffff:a.b.c.d`) is treated as IPv4: `net.IP.To4()` and [`Ipv6Addr::to_ipv4_mapped`]
    /// accept exactly the same forms.
    ///
    /// Returns `None` when the two addresses end up in different families, which Go cannot
    /// express (it takes the source from the handle that is already bound to the right family).
    // Go: tcpraw@v1.2.32 tcp_linux.go:WriteTo() (`if raddr.IP.To4() != nil { … } else { … }`)
    pub fn new(src: IpAddr, dst: IpAddr) -> Option<Self> {
        match (to_v4(src), to_v4(dst)) {
            (Some(src), Some(dst)) => Some(PseudoHeader::V4 { src, dst }),
            (None, None) => match (src, dst) {
                (IpAddr::V6(src), IpAddr::V6(dst)) => Some(PseudoHeader::V6 { src, dst }),
                // Unreachable: `to_v4` returns `Some` for every `IpAddr::V4`.
                _ => None,
            },
            _ => None,
        }
    }

    /// The pseudo-header's contribution to the checksum: the addresses only, as 16-bit
    /// big-endian words, unfolded.
    ///
    /// The protocol number and the segment length are added by [`compute_checksum`], exactly
    /// where gopacket adds them.
    // Go: gopacket@v1.1.19 layers/tcpip.go:IPv4.pseudoheaderChecksum() / IPv6.pseudoheaderChecksum()
    pub fn partial_checksum(&self) -> u32 {
        let mut csum: u32 = 0;
        match self {
            PseudoHeader::V4 { src, dst } => {
                let (src, dst) = (src.octets(), dst.octets());
                csum += (u32::from(src[0]) + u32::from(src[2])) << 8;
                csum += u32::from(src[1]) + u32::from(src[3]);
                csum += (u32::from(dst[0]) + u32::from(dst[2])) << 8;
                csum += u32::from(dst[1]) + u32::from(dst[3]);
            }
            PseudoHeader::V6 { src, dst } => {
                let (src, dst) = (src.octets(), dst.octets());
                for i in (0..16).step_by(2) {
                    csum += u32::from(src[i]) << 8;
                    csum += u32::from(src[i + 1]);
                    csum += u32::from(dst[i]) << 8;
                    csum += u32::from(dst[i + 1]);
                }
            }
        }
        csum
    }
}

/// Go's `net.IP.To4()`: the address as IPv4 if it is one, including the IPv4-mapped IPv6 form.
fn to_v4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    }
}

/// The RFC 1071 one's-complement checksum of `data`, continuing from the partial sum `csum`.
///
/// Odd lengths are handled Go's way: the last byte counts as the high half of a word.
///
/// The accumulator is added with `wrapping_add` because Go's `uint32` wraps silently. It cannot
/// actually wrap for any segment a raw socket can carry (65535 bytes contribute at most
/// `2^31 - 2^15`, and the pseudo-header at most `32 * 0xffff`), but a debug build must not panic
/// on a hostile length either (porting guide §5).
// Go: gopacket@v1.1.19 layers/tcpip.go:tcpipChecksum()
pub fn tcpip_checksum(data: &[u8], csum: u32) -> u16 {
    let mut csum = csum;
    let (words, remainder) = data.as_chunks::<2>();
    for w in words {
        csum = csum.wrapping_add(u32::from(w[0]) << 8);
        csum = csum.wrapping_add(u32::from(w[1]));
    }
    // Go's `if len(data)%2 == 1 { csum += uint32(data[length]) << 8 }`.
    if let Some(&last) = remainder.first() {
        csum = csum.wrapping_add(u32::from(last) << 8);
    }
    while csum > 0xffff {
        csum = (csum >> 16) + (csum & 0xffff);
    }
    !(csum as u16)
}

/// The TCP (or UDP) checksum of `header_and_payload`, which must be the serialised transport
/// header plus its payload with the checksum field **zeroed**.
///
/// `protocol` is the upper-layer protocol number ([`IP_PROTOCOL_TCP`] here).
// Go: gopacket@v1.1.19 layers/tcpip.go:tcpipchecksum.computeChecksum()
pub fn compute_checksum(header_and_payload: &[u8], pseudo: &PseudoHeader, protocol: u8) -> u16 {
    // Go: `length := uint32(len(headerAndPayload))`, a truncating conversion, kept as one.
    let length = header_and_payload.len() as u32;
    let mut csum = pseudo.partial_checksum();
    csum = csum.wrapping_add(u32::from(protocol));
    csum = csum.wrapping_add(length & 0xffff);
    csum = csum.wrapping_add(length >> 16);
    tcpip_checksum(header_and_payload, csum)
}

/// Whether a received segment's checksum is correct.
///
/// Summing a whole valid segment (checksum field included) gives `0xffff`, whose complement is
/// `0`. Go never verifies incoming checksums: the kernel has already done it for the flows
/// tcpraw cares about, so this exists for tests and for the pcap comparison of Step 10.5.
pub fn verify_checksum(header_and_payload: &[u8], pseudo: &PseudoHeader) -> bool {
    compute_checksum(header_and_payload, pseudo, IP_PROTOCOL_TCP) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known answers for the pseudo-header sum, computed by hand from
    /// `layers/tcpip.go:IPv4.pseudoheaderChecksum`: the two 16-bit halves of each address.
    #[test]
    fn pseudo_header_v4_known_answer() {
        let ph = PseudoHeader::V4 {
            src: Ipv4Addr::new(192, 168, 1, 2),
            dst: Ipv4Addr::new(203, 0, 113, 5),
        };
        // 0xc0a8 + 0x0102 + 0xcb00 + 0x7105
        assert_eq!(ph.partial_checksum(), 0xc0a8 + 0x0102 + 0xcb00 + 0x7105);
    }

    #[test]
    fn pseudo_header_v6_known_answer() {
        let ph = PseudoHeader::V6 {
            src: "2001:db8::1"
                .parse()
                .expect("literal is a valid IPv6 address"),
            dst: "2001:db8::abcd"
                .parse()
                .expect("literal is a valid IPv6 address"),
        };
        // src words: 2001 0db8 0000 0000 0000 0000 0000 0001
        // dst words: 2001 0db8 0000 0000 0000 0000 0000 abcd
        let want = 0x2001 + 0x0db8 + 0x0001 + 0x2001 + 0x0db8 + 0xabcd;
        assert_eq!(ph.partial_checksum(), want);
    }

    /// RFC 1071's own worked example: the 8 bytes 00 01 f2 03 f4 f5 f6 f7 sum to 0xddf2, so the
    /// checksum is 0x220d.
    #[test]
    fn tcpip_checksum_rfc1071_example() {
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(tcpip_checksum(&data, 0), 0x220d);
    }

    /// An odd-length buffer pads on the right (the last byte is the high half of a word), and an
    /// empty buffer only folds the incoming partial sum. Go's loop bound (`len(data) - 1`) makes
    /// the empty case work by underflowing into a negative `int`; the port uses `as_chunks::<2>`,
    /// which must behave the same.
    #[test]
    fn tcpip_checksum_odd_and_empty() {
        assert_eq!(tcpip_checksum(&[0xab], 0), !0xab00u16);
        assert_eq!(tcpip_checksum(&[], 0), 0xffff);
        assert_eq!(tcpip_checksum(&[], 0x1_0001), !2u16);
    }

    /// `to_v4` follows `net.IP.To4()`: IPv4-mapped counts, IPv4-compatible (`::a.b.c.d`) and
    /// anything else does not.
    #[test]
    fn pseudo_header_family_selection_matches_go_to4() {
        let v4: IpAddr = "10.0.0.1".parse().expect("valid");
        let mapped: IpAddr = "::ffff:10.0.0.2".parse().expect("valid");
        let v6: IpAddr = "2001:db8::1".parse().expect("valid");
        assert_eq!(
            PseudoHeader::new(v4, mapped),
            Some(PseudoHeader::V4 {
                src: Ipv4Addr::new(10, 0, 0, 1),
                dst: Ipv4Addr::new(10, 0, 0, 2),
            })
        );
        assert!(matches!(
            PseudoHeader::new(v6, v6),
            Some(PseudoHeader::V6 { .. })
        ));
        // `::10.0.0.2` is IPv4-compatible, not IPv4-mapped: Go's To4() returns nil for it.
        let compat: IpAddr = "::10.0.0.2".parse().expect("valid");
        assert!(matches!(
            PseudoHeader::new(compat, v6),
            Some(PseudoHeader::V6 { .. })
        ));
        assert_eq!(PseudoHeader::new(v4, v6), None);
    }
}
