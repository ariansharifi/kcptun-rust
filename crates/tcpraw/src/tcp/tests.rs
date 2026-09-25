//! Tests for the segment codec.
//!
//! # Where the golden segments come from
//!
//! `GO_*` below are real gopacket output. They were produced by a throwaway Go program that
//! reproduces `tcpraw@v1.2.32 tcp_linux.go:WriteTo()` — the same `layers.TCP` fields, the same
//! `[NOP, NOP, Timestamps]` fingerprint from `fingerprints.go`, the same
//! `gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}` and the same
//! `SetNetworkLayerForChecksum(&layers.IPv4{…})` / `IPv6` — against the pinned
//! `gopacket@v1.1.19` from `reference/kcptun/vendor`:
//!
//! ```go
//! opts := []layers.TCPOption{{OptionType: 1}, {OptionType: 1},
//!     {OptionType: 8, OptionLength: 10, OptionData: make([]byte, tsDataLen)}}
//! binary.BigEndian.PutUint32(opts[2].OptionData[:4], tsval)
//! binary.BigEndian.PutUint32(opts[2].OptionData[4:8], tsecr)
//! tcp := layers.TCP{SrcPort: …, DstPort: …, Seq: …, Ack: …, Window: 65535,
//!     PSH: true, ACK: true, Options: opts}
//! tcp.SetNetworkLayerForChecksum(&layers.IPv4{Protocol: layers.IPProtocolTCP, SrcIP: …, DstIP: …})
//! gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true,
//!     ComputeChecksums: true}, &tcp, gopacket.Payload(payload))
//! ```
//!
//! `tsDataLen = 8` is what this port emits (Deviation **V10**, upstream `cbf9635`), `tsDataLen
//! = 10` is what pinned v1.2.32 emits: a malformed length-12 timestamp option, two padding
//! bytes and a 36-byte header. Both are covered, because both must parse and the port's own
//! output must differ from pinned Go's in exactly that one way. The pcap comparison against a
//! live Go peer follows in Step 10.5.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;

use super::*;
use crate::checksum::{tcpip_checksum, verify_checksum};
use crate::fingerprint::FingerPrint;

// ---------------------------------------------------------------------------------------------
// Golden segments (see the module comment for how they were produced).
// ---------------------------------------------------------------------------------------------

/// V10 form, IPv4: 192.168.1.2:54321 -> 203.0.113.5:4000, 20-byte payload. 32-byte header.
const GO_V10_IPV4: &str = "d4310fa011223344556677888018ffff5acb00000101080a0badf00ddeadbeef\
                           6b637074756e206f7665722066616b6520544350";
/// Pinned v1.2.32 form of the same segment: length-12 TS option, 2 pad bytes, 36-byte header.
const GO_PINNED_IPV4: &str = "d4310fa011223344556677889018ffff4ac500000101080c0badf00ddeadbeef\
                              000000006b637074756e206f7665722066616b6520544350";
/// V10 form, IPv6: [2001:db8::1]:54321 -> [2001:db8::abcd]:4000, same payload.
const GO_V10_IPV6: &str = "d4310fa011223344556677888018ffff513b00000101080a0badf00ddeadbeef\
                           6b637074756e206f7665722066616b6520544350";
/// Pinned form, IPv6.
const GO_PINNED_IPV6: &str = "d4310fa011223344556677889018ffff413500000101080c0badf00ddeadbeef\
                              000000006b637074756e206f7665722066616b6520544350";
/// V10 form, IPv4, **empty** payload: 10.0.0.1:1 -> 10.0.0.2:65535, all-zero seq/ack/timestamps.
const GO_V10_IPV4_EMPTY: &str = "0001ffff00000000000000008018ffff62b200000101080a\
                                 0000000000000000";
/// V10 form, IPv4, **odd** payload length (exercises the checksum's trailing byte).
const GO_V10_IPV4_ODD: &str = "30390fa000000001000000028018ffff4f6800000101080a\
                               00000003000000046f6464";
/// Pinned form of the same odd-length segment.
const GO_PINNED_IPV4_ODD: &str = "30390fa000000001000000029018ffff3f6200000101080c\
                                  0000000300000004000000006f6464";
/// V10 form, IPv6, odd payload, every sequence and timestamp field at its maximum.
const GO_V10_IPV6_ODD: &str = "9c400fa0fffffffffffffffe8018ffff4c4d00000101080a\
                               ffffffffffffffff00ff7f8001";

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("golden segment is valid hex")
}

fn v4(s: &str) -> Ipv4Addr {
    s.parse().expect("test literal is a valid IPv4 address")
}

fn v6(s: &str) -> Ipv6Addr {
    s.parse().expect("test literal is a valid IPv6 address")
}

/// The fingerprint options with `ts_data_len` bytes of timestamp data: 8 is what this port
/// emits (V10), 10 is pinned Go's malformed option.
fn fingerprint_options(ts_data_len: usize, ts_val: u32, ts_ecr: u32) -> Vec<TcpOption> {
    let mut data = vec![0u8; ts_data_len];
    data[..4].copy_from_slice(&ts_val.to_be_bytes());
    data[4..8].copy_from_slice(&ts_ecr.to_be_bytes());
    vec![
        TcpOption::single(OPTION_KIND_NOP),
        TcpOption::single(OPTION_KIND_NOP),
        TcpOption {
            kind: OPTION_KIND_TIMESTAMPS,
            length: 10,
            data,
        },
    ]
}

/// Serialises exactly what `WriteTo` would for one datagram.
#[allow(clippy::too_many_arguments)]
fn write_to(
    pseudo: &PseudoHeader,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    ts_val: u32,
    ts_ecr: u32,
    ts_data_len: usize,
    payload: &[u8],
) -> (TcpHeader, Vec<u8>) {
    let mut header = TcpHeader {
        src_port,
        dst_port,
        seq,
        ack,
        window: 65535,
        flags: TcpFlags::PSH | TcpFlags::ACK,
        ..TcpHeader::default()
    };
    let options = fingerprint_options(ts_data_len, ts_val, ts_ecr);
    let mut out = Vec::new();
    let n = serialize(&mut header, &options, payload, pseudo, &mut out);
    assert_eq!(n, out.len());
    (header, out)
}

const PAYLOAD: &[u8] = b"kcptun over fake TCP";

// ---------------------------------------------------------------------------------------------
// Serialisation against gopacket
// ---------------------------------------------------------------------------------------------

/// Deviation **V10**: the port's own output. 12 bytes of options, no padding, data offset 8.
#[test]
fn serialize_matches_go_v10_ipv4() {
    let pseudo = PseudoHeader::V4 {
        src: v4("192.168.1.2"),
        dst: v4("203.0.113.5"),
    };
    let (header, out) = write_to(
        &pseudo,
        54321,
        4000,
        0x1122_3344,
        0x5566_7788,
        0x0bad_f00d,
        0xdead_beef,
        8,
        PAYLOAD,
    );
    assert_eq!(hex::encode(&out), GO_V10_IPV4);
    assert_eq!(header.data_offset, 8);
    assert_eq!(header.checksum, 0x5acb);
    assert!(verify_checksum(&out, &pseudo));
}

/// The same segment as pinned tcpraw v1.2.32 emits it: the codec reproduces gopacket for the
/// malformed length-12 option too, so V10 is the *only* difference between the two senders.
#[test]
fn serialize_matches_go_pinned_ipv4() {
    let pseudo = PseudoHeader::V4 {
        src: v4("192.168.1.2"),
        dst: v4("203.0.113.5"),
    };
    let (header, out) = write_to(
        &pseudo,
        54321,
        4000,
        0x1122_3344,
        0x5566_7788,
        0x0bad_f00d,
        0xdead_beef,
        10,
        PAYLOAD,
    );
    assert_eq!(hex::encode(&out), GO_PINNED_IPV4);
    // 1 + 1 + (2 + 10) = 14 bytes of options, padded to 16: a 36-byte header.
    assert_eq!(header.data_offset, 9);
    assert_eq!(
        &out[32..36],
        &[0, 0, 0, 0],
        "TS tail plus two padding bytes"
    );
    assert!(verify_checksum(&out, &pseudo));
}

#[test]
fn serialize_matches_go_v10_ipv6() {
    let pseudo = PseudoHeader::V6 {
        src: v6("2001:db8::1"),
        dst: v6("2001:db8::abcd"),
    };
    let (header, out) = write_to(
        &pseudo,
        54321,
        4000,
        0x1122_3344,
        0x5566_7788,
        0x0bad_f00d,
        0xdead_beef,
        8,
        PAYLOAD,
    );
    assert_eq!(hex::encode(&out), GO_V10_IPV6);
    assert_eq!(header.checksum, 0x513b);
    assert!(verify_checksum(&out, &pseudo));
    // Only the pseudo-header differs between the two families.
    assert_eq!(&out[..16], &unhex(GO_V10_IPV4)[..16]);
}

#[test]
fn serialize_matches_go_pinned_ipv6() {
    let pseudo = PseudoHeader::V6 {
        src: v6("2001:db8::1"),
        dst: v6("2001:db8::abcd"),
    };
    let (_, out) = write_to(
        &pseudo,
        54321,
        4000,
        0x1122_3344,
        0x5566_7788,
        0x0bad_f00d,
        0xdead_beef,
        10,
        PAYLOAD,
    );
    assert_eq!(hex::encode(&out), GO_PINNED_IPV6);
    assert!(verify_checksum(&out, &pseudo));
}

/// An empty datagram still produces a full header (KCP never sends one, but `WriteTo` would).
#[test]
fn serialize_matches_go_empty_payload() {
    let pseudo = PseudoHeader::V4 {
        src: v4("10.0.0.1"),
        dst: v4("10.0.0.2"),
    };
    let (_, out) = write_to(&pseudo, 1, 65535, 0, 0, 0, 0, 8, &[]);
    assert_eq!(hex::encode(&out), GO_V10_IPV4_EMPTY);
    assert_eq!(out.len(), 32);
    assert!(verify_checksum(&out, &pseudo));
}

/// Odd payload lengths take the checksum's trailing-byte branch, in both header forms.
#[test]
fn serialize_matches_go_odd_payload() {
    let pseudo = PseudoHeader::V4 {
        src: v4("10.0.0.1"),
        dst: v4("10.0.0.2"),
    };
    let (_, out) = write_to(&pseudo, 12345, 4000, 1, 2, 3, 4, 8, b"odd");
    assert_eq!(hex::encode(&out), GO_V10_IPV4_ODD);
    assert!(verify_checksum(&out, &pseudo));

    let (_, out) = write_to(&pseudo, 12345, 4000, 1, 2, 3, 4, 10, b"odd");
    assert_eq!(hex::encode(&out), GO_PINNED_IPV4_ODD);
    assert!(verify_checksum(&out, &pseudo));

    let pseudo6 = PseudoHeader::V6 {
        src: v6("fe80::1"),
        dst: v6("fe80::2"),
    };
    let (_, out) = write_to(
        &pseudo6,
        40000,
        4000,
        0xffff_ffff,
        0xffff_fffe,
        0xffff_ffff,
        0xffff_ffff,
        8,
        &[0x00, 0xff, 0x7f, 0x80, 0x01],
    );
    assert_eq!(hex::encode(&out), GO_V10_IPV6_ODD);
    assert!(verify_checksum(&out, &pseudo6));
}

/// The real fingerprint, driven the way `WriteTo` drives it, produces the V10 golden segment.
#[test]
fn fingerprint_write_path_matches_go_v10() {
    let mut fp = FingerPrint::linux();
    fp.make_option_with(0x0bad_f00d, 0xdead_beef);
    let mut header = TcpHeader {
        src_port: 54321,
        dst_port: 4000,
        seq: 0x1122_3344,
        ack: 0x5566_7788,
        window: fp.window,
        flags: TcpFlags::PSH | TcpFlags::ACK,
        ..TcpHeader::default()
    };
    let pseudo = PseudoHeader::V4 {
        src: v4("192.168.1.2"),
        dst: v4("203.0.113.5"),
    };
    let mut out = Vec::new();
    serialize(&mut header, &fp.options, PAYLOAD, &pseudo, &mut out);
    assert_eq!(hex::encode(&out), GO_V10_IPV4);
}

/// `serialize` clears the buffer first, like `gopacket.SerializeLayers`, so a flow's reused
/// `e.buf` never leaks the previous segment.
#[test]
fn serialize_clears_the_buffer() {
    let pseudo = PseudoHeader::V4 {
        src: v4("10.0.0.1"),
        dst: v4("10.0.0.2"),
    };
    let options = fingerprint_options(8, 3, 4);
    let mut header = TcpHeader {
        src_port: 12345,
        dst_port: 4000,
        seq: 1,
        ack: 2,
        window: 65535,
        flags: TcpFlags::PSH | TcpFlags::ACK,
        ..TcpHeader::default()
    };
    let mut out = vec![0xaa; 4096];
    serialize(&mut header, &options, b"odd", &pseudo, &mut out);
    assert_eq!(hex::encode(&out), GO_V10_IPV4_ODD);
}

// ---------------------------------------------------------------------------------------------
// Parsing Go-produced segments
// ---------------------------------------------------------------------------------------------

/// Parsing what pinned Go sends: 36-byte header, `PSH|ACK`, window 65535, and a timestamp
/// option with **10** bytes of data. Go itself only accepts this length; the port accepts it
/// and the standard one (V10).
#[test]
fn decode_go_pinned_segment() {
    let data = unhex(GO_PINNED_IPV4);
    let seg = Segment::decode(&data).expect("valid segment");
    assert_eq!(seg.header.src_port, 54321);
    assert_eq!(seg.header.dst_port, 4000);
    assert_eq!(seg.header.seq, 0x1122_3344);
    assert_eq!(seg.header.ack, 0x5566_7788);
    assert_eq!(seg.header.data_offset, 9);
    assert_eq!(seg.header.flags, TcpFlags::PSH | TcpFlags::ACK);
    assert!(seg.header.flags.psh() && seg.header.flags.ack());
    assert!(!seg.header.flags.syn() && !seg.header.flags.fin());
    assert_eq!(seg.header.window, 65535);
    assert_eq!(seg.header.urgent, 0);
    assert_eq!(seg.payload, PAYLOAD);

    let options: Vec<_> = seg.options().collect();
    // gopacket pads with zero bytes, so the walk ends on an EndList option — exactly what Go's
    // own decoder reports for a segment its own encoder produced.
    assert_eq!(options.len(), 4);
    assert_eq!(options[0].kind, OPTION_KIND_NOP);
    assert_eq!(options[1].kind, OPTION_KIND_NOP);
    assert_eq!(options[2].kind, OPTION_KIND_TIMESTAMPS);
    assert_eq!(options[2].length, 12, "pinned Go's malformed length");
    assert_eq!(options[2].data.len(), 10);
    assert_eq!(options[3].kind, OPTION_KIND_END_LIST);

    assert_eq!(
        seg.timestamps(),
        Some(Timestamps {
            ts_val: 0x0bad_f00d,
            ts_ecr: 0xdead_beef,
        })
    );
    let pseudo = PseudoHeader::V4 {
        src: v4("192.168.1.2"),
        dst: v4("203.0.113.5"),
    };
    assert!(verify_checksum(&data, &pseudo));
}

/// Parsing what this port (and upstream `cbf9635`) sends: 32-byte header, standard length-10
/// timestamp option.
#[test]
fn decode_go_v10_segment() {
    let data = unhex(GO_V10_IPV4);
    let seg = Segment::decode(&data).expect("valid segment");
    assert_eq!(seg.header.data_offset, 8);
    assert_eq!(seg.payload, PAYLOAD);
    let options: Vec<_> = seg.options().collect();
    assert_eq!(options.len(), 3);
    assert_eq!(options[2].length, 10);
    assert_eq!(options[2].data.len(), 8);
    assert_eq!(
        seg.timestamps(),
        Some(Timestamps {
            ts_val: 0x0bad_f00d,
            ts_ecr: 0xdead_beef,
        })
    );
}

/// The IPv6 golden segments parse identically: the family only changes the checksum.
#[test]
fn decode_go_ipv6_segments() {
    for (hexs, offset) in [(GO_V10_IPV6, 8u8), (GO_PINNED_IPV6, 9)] {
        let data = unhex(hexs);
        let seg = Segment::decode(&data).expect("valid segment");
        assert_eq!(seg.header.data_offset, offset);
        assert_eq!(seg.payload, PAYLOAD);
        assert_eq!(seg.timestamps().map(|t| t.ts_val), Some(0x0bad_f00d));
        let pseudo = PseudoHeader::V6 {
            src: v6("2001:db8::1"),
            dst: v6("2001:db8::abcd"),
        };
        assert!(verify_checksum(&data, &pseudo));
    }
}

/// An empty-payload segment decodes to an empty payload, not to a parse error.
#[test]
fn decode_empty_payload() {
    let data = unhex(GO_V10_IPV4_EMPTY);
    let seg = Segment::decode(&data).expect("valid segment");
    assert!(seg.payload.is_empty());
    assert_eq!(seg.timestamps(), Some(Timestamps::default()));
}

/// A real Linux SYN carries `MSS, SACK-permitted, timestamps, NOP, window scale`; a real
/// segment may also end its option area with `EndList` plus padding. The walk must find the
/// timestamps in both, and stop at `EndList`.
#[test]
fn decode_real_stack_option_layouts() {
    // MSS 1460, SACK permitted, TS(3735928559, 0), NOP, WS 7 -> 20 bytes of options.
    let mut data = vec![0u8; 20];
    data[2..4].copy_from_slice(&4000u16.to_be_bytes());
    data[12] = 10 << 4; // data offset 10 = 40 bytes
    data[13] = TcpFlags::SYN.bits() as u8;
    let options: &[u8] = &[
        2, 4, 0x05, 0xb4, // MSS 1460
        4, 2, // SACK permitted
        8, 10, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, // timestamps
        1, // NOP
        3, 3, 7, // window scale 7
    ];
    data.extend_from_slice(options);
    data.extend_from_slice(b"payload");

    let seg = Segment::decode(&data).expect("valid segment");
    assert!(seg.header.flags.syn());
    assert_eq!(seg.payload, b"payload");
    let kinds: Vec<u8> = seg.options().map(|o| o.kind).collect();
    assert_eq!(kinds, vec![2, 4, 8, 1, 3]);
    assert_eq!(
        seg.timestamps(),
        Some(Timestamps {
            ts_val: 0xdead_beef,
            ts_ecr: 0,
        })
    );

    // Same, but the options end with EndList and a padding byte.
    let mut data = vec![0u8; 20];
    data[12] = 8 << 4; // 32 bytes: 12 bytes of options
    data.extend_from_slice(&[8, 10, 0, 0, 0, 1, 0, 0, 0, 2]);
    data.extend_from_slice(&[0, 0xff]); // EndList, then ignored padding
    data.extend_from_slice(b"x");
    let seg = Segment::decode(&data).expect("valid segment");
    let kinds: Vec<u8> = seg.options().map(|o| o.kind).collect();
    assert_eq!(kinds, vec![8, OPTION_KIND_END_LIST]);
    assert_eq!(
        seg.timestamps(),
        Some(Timestamps {
            ts_val: 1,
            ts_ecr: 2,
        })
    );
    assert_eq!(seg.payload, b"x");
}

/// A timestamp option of any other length is ignored, as in Go, and the walk keeps going.
#[test]
fn decode_ignores_timestamps_of_other_lengths() {
    let mut data = vec![0u8; 20];
    data[12] = 8 << 4;
    data.extend_from_slice(&[8, 6, 0, 0, 0, 9]); // 4 bytes of data: not a timestamp we accept
    data.extend_from_slice(&[1, 1, 1, 1, 1, 1]);
    let seg = Segment::decode(&data).expect("valid segment");
    assert_eq!(seg.timestamps(), None);
    assert_eq!(seg.options().count(), 7);
}

/// Only the first timestamp option counts (Go breaks out of the loop).
#[test]
fn decode_takes_the_first_timestamp_option() {
    let mut data = vec![0u8; 20];
    data[12] = 10 << 4;
    data.extend_from_slice(&[8, 10, 0, 0, 0, 1, 0, 0, 0, 1]);
    data.extend_from_slice(&[8, 10, 0, 0, 0, 2, 0, 0, 0, 2]);
    let seg = Segment::decode(&data).expect("valid segment");
    assert_eq!(seg.timestamps().map(|t| t.ts_val), Some(1));
}

// ---------------------------------------------------------------------------------------------
// Malformed input (porting guide §5: never panic, and behave like Go)
// ---------------------------------------------------------------------------------------------

/// Under 20 bytes is the one case the port rejects: Go hands `captureFlow` an all-zero header,
/// whose destination port 0 can never match the capture filter.
#[test]
fn decode_rejects_short_buffers() {
    for len in 0..MIN_HEADER_LEN {
        let data = vec![0xff; len];
        assert_eq!(
            Segment::decode(&data),
            Err(ParseError::HeaderTooShort(len)),
            "len {len}"
        );
    }
    assert_eq!(
        ParseError::HeaderTooShort(3).to_string(),
        "Invalid TCP header. Length 3 less than 20"
    );
}

/// gopacket registers the layer before reporting a bad data offset, so tcpraw still reads the
/// header fields and sees an empty payload and no options. Reproduced here.
#[test]
fn decode_bad_data_offset_keeps_the_header() {
    for offset in [0u8, 1, 4] {
        let mut data = vec![0u8; 40];
        data[2..4].copy_from_slice(&4000u16.to_be_bytes());
        data[12] = offset << 4;
        data[13] = TcpFlags::PSH.bits() as u8;
        let seg = Segment::decode(&data).expect("header is still usable");
        assert_eq!(seg.header.dst_port, 4000);
        assert_eq!(seg.header.data_offset, offset);
        assert!(seg.header.flags.psh());
        assert!(seg.payload.is_empty());
        assert_eq!(seg.options().count(), 0);
        assert_eq!(seg.timestamps(), None);
    }

    // Data offset past the end of the buffer: same treatment.
    let mut data = vec![0u8; 24];
    data[12] = 15 << 4; // claims 60 bytes
    let seg = Segment::decode(&data).expect("header is still usable");
    assert_eq!(seg.header.data_offset, 15);
    assert!(seg.payload.is_empty());
    assert_eq!(seg.options().count(), 0);

    // Exactly the buffer length is fine and yields an empty payload.
    let mut data = vec![0u8; 24];
    data[12] = 6 << 4;
    let seg = Segment::decode(&data).expect("valid segment");
    assert_eq!(seg.option_bytes.len(), 4);
    assert!(seg.payload.is_empty());
}

/// A malformed option ends the walk but is itself reported (gopacket appends it before it
/// returns the error), and the payload — assigned before the options are parsed — stays
/// readable, so such a segment is still delivered.
///
/// The expected `(kind, length, data length)` triples were read off gopacket itself, by
/// decoding these very option areas with `gopacket.NewPacket(buf, layers.LayerTypeTCP,
/// DecodeOptions{NoCopy: true, Lazy: true})` — `captureFlow`'s own call — and printing
/// `tcp.Options`.
#[test]
fn decode_malformed_options_keep_the_payload() {
    // A NOP, then option kind 8 with a length byte of 1 (< 2). Go reports [1/1/0, 8/1/0].
    let mut data = vec![0u8; 20];
    data[12] = 7 << 4;
    data.extend_from_slice(&[1, 8, 1, 0, 0, 0, 0, 0]);
    data.extend_from_slice(b"still here");
    let seg = Segment::decode(&data).expect("valid header");
    let options: Vec<_> = seg
        .options()
        .map(|o| (o.kind, o.length, o.data.len()))
        .collect();
    assert_eq!(options, vec![(OPTION_KIND_NOP, 1, 0), (8, 1, 0)]);
    assert_eq!(seg.timestamps(), None);
    assert_eq!(seg.payload, b"still here");

    // Option length past the end of the option area. Go reports [8/40/0].
    let mut data = vec![0u8; 20];
    data[12] = 6 << 4;
    data.extend_from_slice(&[8, 40, 0, 0]);
    data.extend_from_slice(b"still here");
    let seg = Segment::decode(&data).expect("valid header");
    let options: Vec<_> = seg
        .options()
        .map(|o| (o.kind, o.length, o.data.len()))
        .collect();
    assert_eq!(options, vec![(8, 40, 0)]);
    assert_eq!(seg.timestamps(), None);
    assert_eq!(seg.payload, b"still here");

    // A kind byte with no room for its length byte: the option is reported with length 0.
    let mut data = vec![0u8; 20];
    data[12] = 6 << 4;
    data.extend_from_slice(&[1, 1, 1, 8]);
    data.extend_from_slice(b"still here");
    let seg = Segment::decode(&data).expect("valid header");
    let options: Vec<_> = seg
        .options()
        .map(|o| (o.kind, o.length, o.data.len()))
        .collect();
    assert_eq!(
        options,
        vec![
            (OPTION_KIND_NOP, 1, 0),
            (OPTION_KIND_NOP, 1, 0),
            (OPTION_KIND_NOP, 1, 0),
            (8, 0, 0),
        ]
    );
    assert_eq!(seg.payload, b"still here");
}

// ---------------------------------------------------------------------------------------------
// Flags, sequence arithmetic and IPv4 header stripping
// ---------------------------------------------------------------------------------------------

/// The flag bits sit where `flagsAndOffset()` puts them, `NS` included (low bit of byte 12).
#[test]
fn flags_round_trip_through_the_wire_word() {
    let all = [
        (TcpFlags::FIN, 0x0001u16),
        (TcpFlags::SYN, 0x0002),
        (TcpFlags::RST, 0x0004),
        (TcpFlags::PSH, 0x0008),
        (TcpFlags::ACK, 0x0010),
        (TcpFlags::URG, 0x0020),
        (TcpFlags::ECE, 0x0040),
        (TcpFlags::CWR, 0x0080),
        (TcpFlags::NS, 0x0100),
    ];
    let pseudo = PseudoHeader::V4 {
        src: v4("10.0.0.1"),
        dst: v4("10.0.0.2"),
    };
    for (flag, bits) in all {
        assert_eq!(flag.bits(), bits);
        let mut header = TcpHeader {
            flags: flag,
            ..TcpHeader::default()
        };
        let mut out = Vec::new();
        serialize(&mut header, &[], b"x", &pseudo, &mut out);
        assert_eq!(out[12], (5 << 4) | ((bits >> 8) as u8));
        assert_eq!(out[13], bits as u8);
        let seg = Segment::decode(&out).expect("valid segment");
        assert_eq!(seg.header.flags, flag);
        assert_eq!(seg.header.data_offset, 5);
    }
    let combined = TcpFlags::PSH | TcpFlags::ACK;
    assert_eq!(combined.bits(), 0x18);
    assert_eq!(format!("{combined:?}"), "PSH|ACK");
    assert_eq!(format!("{:?}", TcpFlags::NONE), "NONE");
    assert_eq!(TcpFlags::from_bits(0xf1ff).bits(), 0x01ff);
}

/// `nextSeq` counts the payload plus one for each of `SYN` and `FIN`, and wraps like Go's
/// `uint32`.
#[test]
fn next_seq_counts_payload_syn_and_fin() {
    let cases = [
        (TcpFlags::ACK, 10u32, 100u32, 110u32),
        (TcpFlags::SYN, 0, 100, 101),
        (TcpFlags::FIN, 4, 100, 105),
        (TcpFlags::SYN | TcpFlags::FIN, 0, 100, 102),
        (TcpFlags::PSH, 3, 0xffff_ffff, 2),
    ];
    let pseudo = PseudoHeader::V4 {
        src: v4("10.0.0.1"),
        dst: v4("10.0.0.2"),
    };
    for (flags, payload_len, seq, want) in cases {
        let payload = vec![0x5a; payload_len as usize];
        let mut header = TcpHeader {
            seq,
            flags,
            ..TcpHeader::default()
        };
        let mut out = Vec::new();
        serialize(&mut header, &[], &payload, &pseudo, &mut out);
        let seg = Segment::decode(&out).expect("valid segment");
        assert_eq!(seg.next_seq(), want, "{flags:?} {payload_len} {seq}");
    }
}

/// The Go runtime's `stripIPv4Header`, byte for byte: only a well-formed IPv4 header of at
/// least 20 bytes that fits in the buffer is removed.
#[test]
fn strip_ipv4_header_matches_go() {
    // IHL 5: a 20-byte header in front of a 4-byte body.
    let mut buf = vec![0u8; 64];
    buf[0] = 0x45;
    buf[20..24].copy_from_slice(b"tcp!");
    assert_eq!(strip_ipv4_header(24, &mut buf), 4);
    assert_eq!(&buf[..4], b"tcp!");

    // IHL 6: a 24-byte header (one option word).
    let mut buf = vec![0u8; 64];
    buf[0] = 0x46;
    buf[24..28].copy_from_slice(b"tcp!");
    assert_eq!(strip_ipv4_header(28, &mut buf), 4);
    assert_eq!(&buf[..4], b"tcp!");

    // Not IPv4 (version nibble 6): untouched, as an AF_INET6 raw read needs no stripping.
    let mut buf = vec![0u8; 64];
    buf[0] = 0x65;
    buf[1] = 0xab;
    assert_eq!(strip_ipv4_header(40, &mut buf), 40);
    assert_eq!(buf[1], 0xab);

    // IHL < 5: untouched.
    let mut buf = vec![0u8; 64];
    buf[0] = 0x44;
    buf[1] = 0xab;
    assert_eq!(strip_ipv4_header(40, &mut buf), 40);
    assert_eq!(buf[1], 0xab);

    // Header longer than the buffer: untouched.
    let mut buf = vec![0u8; 20];
    buf[0] = 0x4f; // IHL 15 -> 60 bytes
    assert_eq!(strip_ipv4_header(20, &mut buf), 20);

    // Buffer shorter than a header: untouched.
    let mut buf = vec![0x45u8; 19];
    assert_eq!(strip_ipv4_header(19, &mut buf), 19);

    // A read shorter than the header it claims. Go would return a negative length and the
    // caller would panic slicing with it; the port saturates at zero.
    let mut buf = vec![0u8; 64];
    buf[0] = 0x45;
    assert_eq!(strip_ipv4_header(8, &mut buf), 0);
}

/// A whole IPv4 raw read: strip the IP header, then parse what is left.
#[test]
fn strip_then_decode_an_ipv4_raw_read() {
    let segment = unhex(GO_V10_IPV4);
    let mut buf = vec![0u8; 2048];
    buf[0] = 0x45;
    buf[9] = IP_PROTOCOL_TCP;
    buf[12..16].copy_from_slice(&v4("192.168.1.2").octets());
    buf[16..20].copy_from_slice(&v4("203.0.113.5").octets());
    buf[20..20 + segment.len()].copy_from_slice(&segment);

    let n = strip_ipv4_header(20 + segment.len(), &mut buf);
    assert_eq!(n, segment.len());
    let seg = Segment::decode(&buf[..n]).expect("valid segment");
    assert_eq!(seg.payload, PAYLOAD);
    assert_eq!(seg.header.dst_port, 4000);
}

// ---------------------------------------------------------------------------------------------
// Round-trips and properties
// ---------------------------------------------------------------------------------------------

/// Everything `WriteTo` puts into a segment comes back out of `captureFlow`'s parse.
#[test]
fn round_trip_header_options_and_payload() {
    let pseudo = PseudoHeader::V4 {
        src: v4("198.51.100.7"),
        dst: v4("203.0.113.9"),
    };
    for payload_len in [0usize, 1, 2, 3, 20, 1024, 1472] {
        let payload: Vec<u8> = (0..payload_len).map(|i| (i * 7 + 1) as u8).collect();
        let (header, out) = write_to(
            &pseudo,
            29900,
            29901,
            0x0102_0304,
            0x0506_0708,
            0x1111_1111,
            0x2222_2222,
            8,
            &payload,
        );
        let seg = Segment::decode(&out).expect("valid segment");
        assert_eq!(seg.header, header);
        assert_eq!(seg.payload, &payload[..]);
        assert_eq!(
            seg.timestamps(),
            Some(Timestamps {
                ts_val: 0x1111_1111,
                ts_ecr: 0x2222_2222,
            })
        );
        assert!(verify_checksum(&out, &pseudo));
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Serialise then parse: every field survives, the checksum verifies, and the header is
    /// 32 bytes for every input.
    #[test]
    fn prop_serialize_decode_round_trip(
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
        seq in any::<u32>(),
        ack in any::<u32>(),
        ts_val in any::<u32>(),
        ts_ecr in any::<u32>(),
        v6_family in any::<bool>(),
        payload in proptest::collection::vec(any::<u8>(), 0..1500),
    ) {
        let pseudo = if v6_family {
            PseudoHeader::V6 { src: v6("fd00::1"), dst: v6("fd00::2") }
        } else {
            PseudoHeader::V4 { src: v4("192.0.2.1"), dst: v4("192.0.2.2") }
        };
        let (header, out) = write_to(
            &pseudo, src_port, dst_port, seq, ack, ts_val, ts_ecr, 8, &payload,
        );
        prop_assert_eq!(header.data_offset, 8);
        prop_assert_eq!(out.len(), 32 + payload.len());
        prop_assert!(verify_checksum(&out, &pseudo));

        let seg = Segment::decode(&out).expect("a serialised segment always parses");
        prop_assert_eq!(seg.header, header);
        prop_assert_eq!(seg.payload, &payload[..]);
        prop_assert_eq!(seg.next_seq(), seq.wrapping_add(payload.len() as u32));
        prop_assert_eq!(
            seg.timestamps(),
            Some(Timestamps { ts_val, ts_ecr })
        );
    }

    /// Arbitrary bytes off the wire never panic, and never yield a payload or options outside
    /// the buffer (porting guide §5). The real fuzz target is added with the raw sockets in
    /// Step 10.2.
    #[test]
    fn prop_decode_arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..300)) {
        match Segment::decode(&data) {
            Err(ParseError::HeaderTooShort(n)) => prop_assert_eq!(n, data.len()),
            Ok(seg) => {
                prop_assert!(seg.option_bytes.len() + seg.payload.len() + MIN_HEADER_LEN
                    <= data.len());
                // Walking the options must terminate and stay inside the option area.
                let total: usize = seg.options().map(|o| o.data.len()).sum();
                prop_assert!(total <= seg.option_bytes.len());
                let _ = seg.timestamps();
                let _ = seg.next_seq();
            }
        }
    }

    /// `strip_ipv4_header` never panics and never grows the read.
    #[test]
    fn prop_strip_ipv4_header_never_panics(
        mut buf in proptest::collection::vec(any::<u8>(), 0..80),
        n in 0usize..80,
    ) {
        let len = buf.len();
        let out = strip_ipv4_header(n, &mut buf);
        prop_assert!(out <= n);
        prop_assert_eq!(buf.len(), len);
    }

    /// The checksum of a correctly serialised segment always verifies to zero, and flipping any
    /// single byte of it is detected (one's-complement sums miss no single-byte change).
    #[test]
    fn prop_checksum_detects_single_byte_corruption(
        payload in proptest::collection::vec(any::<u8>(), 1..200),
        index in 0usize..200,
        delta in 1u8..=255,
    ) {
        let pseudo = PseudoHeader::V4 { src: v4("192.0.2.1"), dst: v4("192.0.2.2") };
        let (_, mut out) = write_to(&pseudo, 1234, 4321, 7, 8, 9, 10, 8, &payload);
        prop_assert!(verify_checksum(&out, &pseudo));
        let index = index % out.len();
        out[index] = out[index].wrapping_add(delta);
        prop_assert!(!verify_checksum(&out, &pseudo));
    }
}

/// The checksum of the golden segments, recomputed from the parsed header: the value in the
/// segment is what `tcpipChecksum` produces over the pseudo-header, the zeroed header and the
/// payload.
#[test]
fn checksum_known_answers_from_the_golden_segments() {
    for (hexs, pseudo, want) in [
        (
            GO_V10_IPV4,
            PseudoHeader::V4 {
                src: v4("192.168.1.2"),
                dst: v4("203.0.113.5"),
            },
            0x5acbu16,
        ),
        (
            GO_PINNED_IPV4,
            PseudoHeader::V4 {
                src: v4("192.168.1.2"),
                dst: v4("203.0.113.5"),
            },
            0x4ac5,
        ),
        (
            GO_V10_IPV6,
            PseudoHeader::V6 {
                src: v6("2001:db8::1"),
                dst: v6("2001:db8::abcd"),
            },
            0x513b,
        ),
        (
            GO_PINNED_IPV6,
            PseudoHeader::V6 {
                src: v6("2001:db8::1"),
                dst: v6("2001:db8::abcd"),
            },
            0x4135,
        ),
        (
            GO_V10_IPV4_ODD,
            PseudoHeader::V4 {
                src: v4("10.0.0.1"),
                dst: v4("10.0.0.2"),
            },
            0x4f68,
        ),
        (
            GO_V10_IPV6_ODD,
            PseudoHeader::V6 {
                src: v6("fe80::1"),
                dst: v6("fe80::2"),
            },
            0x4c4d,
        ),
    ] {
        let mut data = unhex(hexs);
        assert_eq!(u16::from_be_bytes([data[16], data[17]]), want);
        data[16] = 0;
        data[17] = 0;
        assert_eq!(
            crate::checksum::compute_checksum(&data, &pseudo, IP_PROTOCOL_TCP),
            want,
            "{hexs}"
        );
        // The same sum, reached through the low-level entry point.
        let partial = pseudo
            .partial_checksum()
            .wrapping_add(u32::from(IP_PROTOCOL_TCP))
            .wrapping_add(data.len() as u32);
        assert_eq!(tcpip_checksum(&data, partial), want);
    }
}

/// An option list longer than 40 bytes overflows the 4-bit data offset. gopacket truncates it
/// silently — `uint8(16)` in the struct, a nibble of `0` on the wire, no error — and so does the
/// port. Checked against gopacket@v1.1.19 with 39 NOPs plus a 2-byte option (41 option bytes, 3
/// padding bytes): `DataOffset=16`, bytes 12..14 `0018`, and its own decoder then reports data
/// offset 0 and an empty payload.
///
/// tcpraw's fingerprint is 12 or 14 option bytes, so this is unreachable in the port itself; the
/// behaviour is pinned here because the fuzz harness re-serialises option lists an attacker
/// chose, and because a reviewer should see that the overflow is Go's, not the port's.
#[test]
fn serialize_truncates_a_data_offset_past_15_like_gopacket() {
    let mut options: Vec<TcpOption> = (0..39)
        .map(|_| TcpOption::single(OPTION_KIND_NOP))
        .collect();
    options.push(TcpOption::with_data(OPTION_KIND_TIMESTAMPS, Vec::new()));
    let pseudo = PseudoHeader::V4 {
        src: v4("192.0.2.1"),
        dst: v4("192.0.2.2"),
    };
    let mut header = TcpHeader {
        src_port: 1,
        dst_port: 2,
        window: 65535,
        flags: TcpFlags::PSH | TcpFlags::ACK,
        ..TcpHeader::default()
    };
    let mut out = Vec::new();
    serialize(&mut header, &options, b"hi", &pseudo, &mut out);
    assert_eq!(header.data_offset, 16);
    assert_eq!(out.len(), 66, "20 + 41 options + 3 padding + 2 payload");
    assert_eq!(&out[12..14], &[0x00, 0x18], "the nibble wrapped to 0");
    assert_eq!(
        hex::encode(&out),
        "0001000200000000000000000018fffffd1300000101010101010101010101010101010101\
         0101010101010101010101010101010101010101010108020000006869"
    );
    // And the segment is then unreadable, exactly as gopacket's own decoder finds it.
    let seg = Segment::decode(&out).expect("header is still usable");
    assert_eq!(seg.header.data_offset, 0);
    assert!(seg.payload.is_empty());
}

/// Decoding a Go-produced segment and serialising it again reproduces the original bytes, for
/// both the V10 and the pinned option layout: the two halves of the codec agree with gopacket on
/// the same bytes, not just with each other.
#[test]
fn reserialize_go_segments_byte_for_byte() {
    let cases = [
        (
            GO_V10_IPV4,
            PseudoHeader::V4 {
                src: v4("192.168.1.2"),
                dst: v4("203.0.113.5"),
            },
        ),
        (
            GO_PINNED_IPV4,
            PseudoHeader::V4 {
                src: v4("192.168.1.2"),
                dst: v4("203.0.113.5"),
            },
        ),
        (
            GO_V10_IPV6,
            PseudoHeader::V6 {
                src: v6("2001:db8::1"),
                dst: v6("2001:db8::abcd"),
            },
        ),
        (
            GO_PINNED_IPV6,
            PseudoHeader::V6 {
                src: v6("2001:db8::1"),
                dst: v6("2001:db8::abcd"),
            },
        ),
        (
            GO_PINNED_IPV4_ODD,
            PseudoHeader::V4 {
                src: v4("10.0.0.1"),
                dst: v4("10.0.0.2"),
            },
        ),
    ];
    for (hexs, pseudo) in cases {
        let data = unhex(hexs);
        let seg = Segment::decode(&data).expect("valid segment");
        // The EndList option a padded segment ends on is padding, not an option to re-emit.
        let options: Vec<TcpOption> = seg
            .options()
            .take_while(|o| o.kind != OPTION_KIND_END_LIST)
            .map(|o| {
                if o.data.is_empty() {
                    TcpOption::single(o.kind)
                } else {
                    TcpOption::with_data(o.kind, o.data.to_vec())
                }
            })
            .collect();
        let mut header = seg.header;
        let mut out = Vec::new();
        serialize(&mut header, &options, seg.payload, &pseudo, &mut out);
        assert_eq!(hex::encode(&out), hexs);
        assert_eq!(header, seg.header, "data offset and checksum unchanged");
    }
}

/// `PseudoHeader::new` picks the family the way `WriteTo` does.
#[test]
fn pseudo_header_from_socket_addresses() {
    let src: IpAddr = "192.168.1.2".parse().expect("valid");
    let dst: IpAddr = "203.0.113.5".parse().expect("valid");
    let pseudo = PseudoHeader::new(src, dst).expect("same family");
    let data = unhex(GO_V10_IPV4);
    assert!(verify_checksum(&data, &pseudo));
}
