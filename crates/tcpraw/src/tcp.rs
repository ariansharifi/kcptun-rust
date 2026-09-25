//! The TCP segment codec: header and options, serialise and parse.
//!
//! tcpraw builds its segments with gopacket (`gopacket.SerializeLayers(buf, opts, &tcpHeader,
//! gopacket.Payload(p))` with `SerializeOptions{FixLengths: true, ComputeChecksums: true}`) and
//! parses captured ones with `gopacket.NewPacket(buf[:n], layers.LayerTypeTCP, …)`. This module
//! is a port of the two gopacket routines that implements, plus the IPv4 raw-read header
//! stripping the Go runtime does inside `(*net.IPConn).ReadFromIP`.
//!
//! Go reference: `gopacket@v1.1.19 layers/tcp.go` (`TCP.SerializeTo`, `TCP.DecodeFromBytes`),
//! `tcpraw@v1.2.32 tcp_linux.go` (`WriteTo`, `captureFlow`), `go1.27.1 net/iprawsock_posix.go`
//! (`stripIPv4Header`).

use std::fmt;
use std::ops::{BitOr, BitOrAssign};

use crate::checksum::{IP_PROTOCOL_TCP, PseudoHeader, compute_checksum};

// Go: gopacket@v1.1.19 layers/tcp.go:TCP.DecodeFromBytes() (`if len(data) < 20`)
/// Size of a TCP header without options: the smallest a segment can be.
pub const MIN_HEADER_LEN: usize = 20;

// Go: gopacket@v1.1.19 layers/tcp.go:TCPOptionKindEndList
/// Option kind 0: end of the option list. Consumes one byte; the rest of the option area is
/// padding.
pub const OPTION_KIND_END_LIST: u8 = 0;
// Go: gopacket@v1.1.19 layers/tcp.go:TCPOptionKindNop
/// Option kind 1: one byte of padding.
pub const OPTION_KIND_NOP: u8 = 1;
// Go: gopacket@v1.1.19 layers/tcp.go:TCPOptionKindTimestamps
/// Option kind 8: RFC 7323 timestamps, 8 bytes of data (TSval, TSecr) in a length-10 option.
pub const OPTION_KIND_TIMESTAMPS: u8 = 8;

/// The nine TCP flag bits, as they sit in the 16-bit "data offset and flags" word.
///
/// gopacket keeps them as nine `bool` fields (`FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS`);
/// they become one bit set here because Go's `Ack` (the acknowledgement number) and `ACK` (the
/// flag) would collide as snake_case field names. The bit values are `flagsAndOffset()`'s.
// Go: gopacket@v1.1.19 layers/tcp.go:TCP.flagsAndOffset()
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct TcpFlags(u16);

impl TcpFlags {
    /// No flags set.
    pub const NONE: TcpFlags = TcpFlags(0);
    /// `FIN`: the sender has finished sending.
    pub const FIN: TcpFlags = TcpFlags(0x0001);
    /// `SYN`: synchronise sequence numbers.
    pub const SYN: TcpFlags = TcpFlags(0x0002);
    /// `RST`: reset the connection.
    pub const RST: TcpFlags = TcpFlags(0x0004);
    /// `PSH`: push the data to the application. tcpraw carries its datagrams in `PSH` segments.
    pub const PSH: TcpFlags = TcpFlags(0x0008);
    /// `ACK`: the acknowledgement field is significant.
    pub const ACK: TcpFlags = TcpFlags(0x0010);
    /// `URG`: the urgent pointer is significant.
    pub const URG: TcpFlags = TcpFlags(0x0020);
    /// `ECE`: ECN echo.
    pub const ECE: TcpFlags = TcpFlags(0x0040);
    /// `CWR`: congestion window reduced.
    pub const CWR: TcpFlags = TcpFlags(0x0080);
    /// `NS`: ECN nonce sum. Unlike the other eight this bit lives in the low bit of byte 12,
    /// next to the data offset.
    pub const NS: TcpFlags = TcpFlags(0x0100);

    /// All nine defined bits.
    const ALL: u16 = 0x01ff;

    /// The raw bits, as they appear in the low nine bits of the flags-and-offset word.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// The flags of a flags-and-offset word; the data-offset nibble is masked off.
    pub const fn from_bits(bits: u16) -> TcpFlags {
        TcpFlags(bits & TcpFlags::ALL)
    }

    /// Whether every bit of `other` is set.
    pub const fn contains(self, other: TcpFlags) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether `SYN` is set. `SYN` and `FIN` each consume one sequence number, which is why
    /// `captureFlow` looks at them.
    pub const fn syn(self) -> bool {
        self.contains(TcpFlags::SYN)
    }

    /// Whether `FIN` is set.
    pub const fn fin(self) -> bool {
        self.contains(TcpFlags::FIN)
    }

    /// Whether `PSH` is set: only these segments carry tcpraw datagrams.
    pub const fn psh(self) -> bool {
        self.contains(TcpFlags::PSH)
    }

    /// Whether `ACK` is set.
    pub const fn ack(self) -> bool {
        self.contains(TcpFlags::ACK)
    }
}

impl BitOr for TcpFlags {
    type Output = TcpFlags;
    fn bitor(self, rhs: TcpFlags) -> TcpFlags {
        TcpFlags(self.0 | rhs.0)
    }
}

impl BitOrAssign for TcpFlags {
    fn bitor_assign(&mut self, rhs: TcpFlags) {
        self.0 |= rhs.0;
    }
}

impl fmt::Debug for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const NAMES: [(TcpFlags, &str); 9] = [
            (TcpFlags::FIN, "FIN"),
            (TcpFlags::SYN, "SYN"),
            (TcpFlags::RST, "RST"),
            (TcpFlags::PSH, "PSH"),
            (TcpFlags::ACK, "ACK"),
            (TcpFlags::URG, "URG"),
            (TcpFlags::ECE, "ECE"),
            (TcpFlags::CWR, "CWR"),
            (TcpFlags::NS, "NS"),
        ];
        if self.0 == 0 {
            return f.write_str("NONE");
        }
        let mut first = true;
        for (flag, name) in NAMES {
            if self.contains(flag) {
                if !first {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        Ok(())
    }
}

/// A TCP header without its options.
///
/// The field names are gopacket's `layers.TCP` ones; `data_offset` and `checksum` are outputs of
/// [`serialize`] (Go serialises with `FixLengths` and `ComputeChecksums`, which overwrite both).
// Go: gopacket@v1.1.19 layers/tcp.go:TCP
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpHeader {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Sequence number.
    pub seq: u32,
    /// Acknowledgement number.
    pub ack: u32,
    /// Header length in 32-bit words, 5..=15. Recomputed by [`serialize`].
    pub data_offset: u8,
    /// The flag bits.
    pub flags: TcpFlags,
    /// Receive window. tcpraw always sends the Linux fingerprint's 65535.
    pub window: u16,
    /// Header checksum. Recomputed by [`serialize`].
    pub checksum: u16,
    /// Urgent pointer. tcpraw never sets it.
    pub urgent: u16,
}

impl TcpHeader {
    /// The flags-and-offset word: `data_offset` in the top nibble, the flags below it.
    // Go: gopacket@v1.1.19 layers/tcp.go:TCP.flagsAndOffset()
    fn flags_and_offset(&self) -> u16 {
        (u16::from(self.data_offset) << 12) | self.flags.bits()
    }
}

/// One TCP option to serialise.
///
/// `length` is kept for fidelity with Go's fingerprint table (`{8, 10, make([]byte, 8)}`), but
/// [`serialize`] recomputes it as `data.len() + 2`, because tcpraw serialises with
/// `FixLengths: true`.
// Go: gopacket@v1.1.19 layers/tcp.go:TCPOption
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TcpOption {
    /// Option kind.
    pub kind: u8,
    /// Option length as declared by the caller; ignored on serialisation.
    pub length: u8,
    /// Option data (everything after the kind and length bytes).
    pub data: Vec<u8>,
}

impl TcpOption {
    /// A single-byte option (kind 0 or 1): no length byte, no data.
    pub fn single(kind: u8) -> TcpOption {
        TcpOption {
            kind,
            length: 0,
            data: Vec::new(),
        }
    }

    /// An option with data; `length` is set to the RFC value `data.len() + 2`, truncated to a
    /// byte exactly as gopacket's `uint8(len(o.OptionData) + 2)` is.
    pub fn with_data(kind: u8, data: Vec<u8>) -> TcpOption {
        let length = (data.len() + 2) as u8;
        TcpOption { kind, length, data }
    }

    /// The number of bytes this option occupies on the wire, as `SerializeTo` counts them.
    // Go: gopacket@v1.1.19 layers/tcp.go:TCP.SerializeTo() (the `optionLength` loop)
    fn wire_len(&self) -> usize {
        match self.kind {
            OPTION_KIND_END_LIST | OPTION_KIND_NOP => 1,
            _ => 2 + self.data.len(),
        }
    }
}

/// Serialises `header` + `options` + `payload` into `out`, computing the data offset, the
/// padding and the checksum, and returns the number of bytes written.
///
/// `out` is cleared first, like `gopacket.SerializeLayers`, which calls `SerializeBuffer.Clear()`
/// before it serialises (tcpraw reuses one buffer per flow, `e.buf`). `header.data_offset` and
/// `header.checksum` are updated, as gopacket updates `t.DataOffset` and `t.Checksum` in place.
///
/// Padding follows gopacket: when the options do not end on a 4-byte boundary, `4 - (len % 4)`
/// **zero** bytes are appended (gopacket's `lotsOfZeros`), not `NOP`/`EndList` bytes. That is
/// what produces the two trailing `00 00` bytes of a pinned-Go tcpraw segment, which its own
/// decoder then reports as a fourth, `EndList` option.
///
/// The padding is recomputed on every call. gopacket only *assigns* `t.Padding` when the
/// options need padding, so a reused `layers.TCP` (tcpraw keeps one per flow, `e.tcpHeader`)
/// would keep a stale padding if its option list ever shrank. It cannot: the option list is the
/// connection's fixed fingerprint, so the two behaviours agree on every segment tcpraw sends.
// Go: gopacket@v1.1.19 layers/tcp.go:TCP.SerializeTo(), with tcpraw's
// gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
pub fn serialize(
    header: &mut TcpHeader,
    options: &[TcpOption],
    payload: &[u8],
    pseudo: &PseudoHeader,
    out: &mut Vec<u8>,
) -> usize {
    let option_length: usize = options.iter().map(TcpOption::wire_len).sum();
    let padding = match option_length % 4 {
        0 => 0,
        rem => 4 - rem,
    };
    // Go: `t.DataOffset = uint8((len(t.Padding) + optionLength + 20) / 4)`, a truncating
    // conversion. gopacket does not check that the offset fits the 4-bit field either, with
    // more than 40 bytes of options it serialises an offset of 16 as a nibble of 0 and reports
    // no error (verified against gopacket@v1.1.19; see the tests). With tcpraw's fingerprint
    // the offset is always 8 (V10) or 9 (pinned Go).
    header.data_offset = ((padding + option_length + MIN_HEADER_LEN) / 4) as u8;

    let header_len = MIN_HEADER_LEN + option_length + padding;
    out.clear();
    out.reserve(header_len + payload.len());
    out.resize(header_len, 0);

    out[0..2].copy_from_slice(&header.src_port.to_be_bytes());
    out[2..4].copy_from_slice(&header.dst_port.to_be_bytes());
    out[4..8].copy_from_slice(&header.seq.to_be_bytes());
    out[8..12].copy_from_slice(&header.ack.to_be_bytes());
    out[12..14].copy_from_slice(&header.flags_and_offset().to_be_bytes());
    out[14..16].copy_from_slice(&header.window.to_be_bytes());
    // Bytes 16..18 (the checksum) stay zero until it has been computed, as in gopacket.
    out[18..20].copy_from_slice(&header.urgent.to_be_bytes());

    let mut start = MIN_HEADER_LEN;
    for o in options {
        out[start] = o.kind;
        match o.kind {
            OPTION_KIND_END_LIST | OPTION_KIND_NOP => start += 1,
            _ => {
                // FixLengths: the declared length is replaced by the real one, truncated to a
                // byte as Go's `uint8(len(o.OptionData) + 2)` is.
                out[start + 1] = (o.data.len() + 2) as u8;
                out[start + 2..start + 2 + o.data.len()].copy_from_slice(&o.data);
                start += o.data.len() + 2;
            }
        }
    }
    // The padding bytes are already zero (`resize`), which is gopacket's `copy(bytes[start:],
    // t.Padding)` with `t.Padding = lotsOfZeros[:4-rem]`.

    out.extend_from_slice(payload);

    let csum = compute_checksum(out, pseudo, IP_PROTOCOL_TCP);
    header.checksum = csum;
    out[16..18].copy_from_slice(&csum.to_be_bytes());
    out.len()
}

/// Why a captured buffer could not be read as a TCP segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// Fewer than 20 bytes: not even a header without options.
    ///
    /// gopacket's message, kept verbatim. Go hands `captureFlow` an all-zero `layers.TCP` in
    /// this case (the layer is registered before the error is returned), whose `DstPort` is 0
    /// and so never matches the port filter; dropping the buffer here is the same behaviour,
    /// because a bound socket's port is never 0.
    // Go: gopacket@v1.1.19 layers/tcp.go:TCP.DecodeFromBytes()
    #[error("Invalid TCP header. Length {0} less than 20")]
    HeaderTooShort(usize),
}

/// A parsed TCP segment: the fixed header, the raw option bytes and the payload.
///
/// **Faithfulness note.** gopacket registers the decoded layer *before* it returns a decode
/// error, so `captureFlow` goes on to use a segment whose options or data offset are malformed.
/// [`Segment::decode`] reproduces that: only a buffer shorter than [`MIN_HEADER_LEN`] is
/// rejected. A data offset below 5, or past the end of the buffer, yields the header with **no**
/// options and an **empty** payload (gopacket returns before it assigns `Contents`/`Payload`),
/// and a malformed option ends the option walk while the payload (already assigned) stays
/// readable. Each case was checked against gopacket itself; see the tests.
// Go: gopacket@v1.1.19 layers/tcp.go:TCP.DecodeFromBytes()
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment<'a> {
    /// The 20-byte fixed header.
    pub header: TcpHeader,
    /// The option area: the bytes between the fixed header and the payload.
    pub option_bytes: &'a [u8],
    /// The payload, i.e. one tcpraw datagram on a `PSH` segment.
    pub payload: &'a [u8],
}

impl<'a> Segment<'a> {
    /// Parses a segment. `data` starts at the TCP header: an IPv6 raw socket delivers it that
    /// way, and for IPv4 [`strip_ipv4_header`] has removed the IP header first.
    // Go: gopacket@v1.1.19 layers/tcp.go:TCP.DecodeFromBytes()
    pub fn decode(data: &'a [u8]) -> Result<Segment<'a>, ParseError> {
        if data.len() < MIN_HEADER_LEN {
            return Err(ParseError::HeaderTooShort(data.len()));
        }
        let header = TcpHeader {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            seq: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            ack: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            data_offset: data[12] >> 4,
            // The eight flag bits of byte 13, plus NS from the low bit of byte 12.
            flags: TcpFlags::from_bits(u16::from(data[13]) | (u16::from(data[12] & 0x01) << 8)),
            window: u16::from_be_bytes([data[14], data[15]]),
            checksum: u16::from_be_bytes([data[16], data[17]]),
            urgent: u16::from_be_bytes([data[18], data[19]]),
        };

        // Go returns an error for both of these, after the layer has been registered and with
        // Contents/Payload still nil; the caller then sees an empty payload and no options.
        let data_start = usize::from(header.data_offset) * 4;
        if header.data_offset < 5 || data_start > data.len() {
            return Ok(Segment {
                header,
                option_bytes: &[],
                payload: &[],
            });
        }
        Ok(Segment {
            header,
            option_bytes: &data[MIN_HEADER_LEN..data_start],
            payload: &data[data_start..],
        })
    }

    /// Walks the option area.
    pub fn options(&self) -> Options<'a> {
        Options {
            data: self.option_bytes,
        }
    }

    /// The peer's RFC 7323 timestamp option, if it sent one.
    ///
    /// Go accepts only 10 bytes of option data, the malformed length its own pinned version
    /// emits. **Deviation V10:** the port accepts 8 bytes (the standard option, which upstream
    /// `cbf9635` and every real TCP stack send) as well, so both Go versions and the kernel's own
    /// segments are understood. Like Go, the first match wins and later timestamp options are
    /// ignored.
    // Go: tcpraw@v1.2.32 tcp_linux.go:captureFlow() (the `tcp.Options` loop)
    pub fn timestamps(&self) -> Option<Timestamps> {
        for opt in self.options() {
            if opt.kind == OPTION_KIND_TIMESTAMPS && (opt.data.len() == 8 || opt.data.len() == 10) {
                return Some(Timestamps {
                    ts_val: u32::from_be_bytes([
                        opt.data[0],
                        opt.data[1],
                        opt.data[2],
                        opt.data[3],
                    ]),
                    ts_ecr: u32::from_be_bytes([
                        opt.data[4],
                        opt.data[5],
                        opt.data[6],
                        opt.data[7],
                    ]),
                });
            }
        }
        None
    }

    /// The sequence number the peer expects next, i.e. this segment's `seq` advanced over the
    /// sequence space it consumes: its payload, plus one for `SYN` and one for `FIN`.
    // Go: tcpraw@v1.2.32 tcp_linux.go:captureFlow() (`nextSeq`)
    pub fn next_seq(&self) -> u32 {
        let mut next_seq = self.header.seq.wrapping_add(self.payload.len() as u32);
        if self.header.flags.syn() {
            next_seq = next_seq.wrapping_add(1);
        }
        if self.header.flags.fin() {
            next_seq = next_seq.wrapping_add(1);
        }
        next_seq
    }
}

/// An RFC 7323 timestamp option's two values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timestamps {
    /// The sender's clock. tcpraw echoes it back as the next segment's TSecr.
    pub ts_val: u32,
    /// The last TSval the sender had received from us.
    pub ts_ecr: u32,
}

/// One option from a parsed segment, borrowing its data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OptionRef<'a> {
    /// Option kind.
    pub kind: u8,
    /// Option length byte: 1 for the single-byte kinds, as gopacket reports them.
    pub length: u8,
    /// Option data (`length - 2` bytes), empty for the single-byte kinds.
    pub data: &'a [u8],
}

/// Iterator over a segment's options.
///
/// Yields exactly the options gopacket's `OPTIONS` loop puts into `tcp.Options`, so a Rust and a
/// Go capture loop see the same list:
///
/// - an `EndList` option ends the walk after it has been yielded (Go records the rest of the
///   option area as `Padding`), which is why a segment from pinned tcpraw, whose option area is
///   padded with zero bytes, reports a fourth, `EndList` option;
/// - a malformed option is **still yielded**, with an empty data slice, and then ends the walk.
///   Go appends the option to `tcp.Options` before it returns the decode error, and tcpraw
///   ignores that error and keeps whatever was parsed. Such an option never has 8 or 10 bytes of
///   data, so it can never be mistaken for a timestamp.
// Go: gopacket@v1.1.19 layers/tcp.go:TCP.DecodeFromBytes() (the `OPTIONS` loop)
#[derive(Clone, Copy, Debug)]
pub struct Options<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for Options<'a> {
    type Item = OptionRef<'a>;

    fn next(&mut self) -> Option<OptionRef<'a>> {
        let data = self.data;
        let &kind = data.first()?;
        match kind {
            OPTION_KIND_END_LIST => {
                // Go records the rest as Padding and stops.
                self.data = &[];
                Some(OptionRef {
                    kind,
                    length: 1,
                    data: &[],
                })
            }
            OPTION_KIND_NOP => {
                self.data = &data[1..];
                Some(OptionRef {
                    kind,
                    length: 1,
                    data: &[],
                })
            }
            _ => {
                if data.len() < 2 {
                    // Go: "Invalid TCP option length. Length %d less than 2", but the option,
                    // with its length byte never assigned, is already in `tcp.Options`.
                    self.data = &[];
                    return Some(OptionRef {
                        kind,
                        length: 0,
                        data: &[],
                    });
                }
                let length = data[1];
                if length < 2 || usize::from(length) > data.len() {
                    // Go: "Invalid TCP option length %d < 2" / "… exceeds remaining %d bytes",
                    // again after the option (with this length and no data) was appended.
                    self.data = &[];
                    return Some(OptionRef {
                        kind,
                        length,
                        data: &[],
                    });
                }
                let end = usize::from(length);
                self.data = &data[end..];
                Some(OptionRef {
                    kind,
                    length,
                    data: &data[2..end],
                })
            }
        }
    }
}

/// Removes the IPv4 header an `AF_INET` raw socket prepends to every read, and returns the
/// remaining length. `n` is the number of bytes the read returned, `buf` the whole buffer it was
/// read into.
///
/// This is the Go runtime's own `stripIPv4Header`, which `(*net.IPConn).ReadFromIP` applies
/// before tcpraw sees the data; an `AF_INET6` raw socket delivers the TCP header directly and
/// needs no equivalent. The header is only removed when the buffer really starts with an IPv4
/// header of at least 20 bytes that fits, so a short or malformed read is passed through
/// unchanged.
///
/// Go compares the header length against `len(b)`, the whole buffer, not against `n`, and can
/// therefore return a negative length for a read shorter than the header it claims; the port
/// saturates at 0 instead (a raw socket never delivers such a read, and the porting guide's §5
/// forbids panicking on input).
// Go: go1.27.1 net/iprawsock_posix.go:stripIPv4Header()
pub fn strip_ipv4_header(n: usize, buf: &mut [u8]) -> usize {
    if buf.len() < MIN_HEADER_LEN {
        return n;
    }
    let l = usize::from(buf[0] & 0x0f) << 2;
    if MIN_HEADER_LEN > l || l > buf.len() {
        return n;
    }
    if buf[0] >> 4 != 4 {
        return n;
    }
    buf.copy_within(l.., 0);
    n.saturating_sub(l)
}

#[cfg(test)]
mod tests;
