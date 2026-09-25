//! smux frames: the commands, the 8-byte header codec and the `cmdUPD` payload.
//!
//! Port of `frame.go`. Wire layout (little-endian, `docs/WIRE-FORMAT.md` §7):
//!
//! ```text
//! 0 ver u8 | 1 cmd u8 | 2 length u16 LE | 4 sid u32 LE | 8 payload (`length` bytes)
//! ```
//!
//! Go's `Frame` carries a `[]byte` that points into the writer's buffer, so [`Frame`] borrows
//! its payload too; the send path never copies a payload before it reaches the connection.

use std::fmt;

use crate::error::Error;

// Go: smux@v1.5.55 frame.go:cmdSYN
/// Stream open.
pub const CMD_SYN: u8 = 0;
// Go: smux@v1.5.55 frame.go:cmdFIN
/// Stream close, a.k.a. EOF mark.
pub const CMD_FIN: u8 = 1;
// Go: smux@v1.5.55 frame.go:cmdPSH
/// Data push.
pub const CMD_PSH: u8 = 2;
// Go: smux@v1.5.55 frame.go:cmdNOP
/// No operation (the keepalive, always on stream id 0).
pub const CMD_NOP: u8 = 3;
// Go: smux@v1.5.55 frame.go:cmdUPD
/// Window update: bytes consumed by the remote peer (protocol version 2 only).
pub const CMD_UPD: u8 = 4;

// Go: smux@v1.5.55 frame.go:szCmdUPD
/// Payload size of [`CMD_UPD`]: `|4B data consumed (ACK)|4B window size (WINDOW)|`.
pub const SZ_CMD_UPD: usize = 8;

// Go: smux@v1.5.55 frame.go:initialPeerWindow
/// Initial guess of the peer's receive window in protocol version 2, a slow start. Until the
/// first [`CMD_UPD`] arrives a writer may have this many bytes in flight.
pub const INITIAL_PEER_WINDOW: u32 = 262144;

// Go: smux@v1.5.55 frame.go:sizeOfVer
/// Size of the version field.
pub const SIZE_OF_VER: usize = 1;
// Go: smux@v1.5.55 frame.go:sizeOfCmd
/// Size of the command field.
pub const SIZE_OF_CMD: usize = 1;
// Go: smux@v1.5.55 frame.go:sizeOfLength
/// Size of the length field.
pub const SIZE_OF_LENGTH: usize = 2;
// Go: smux@v1.5.55 frame.go:sizeOfSid
/// Size of the stream id field.
pub const SIZE_OF_SID: usize = 4;
// Go: smux@v1.5.55 frame.go:headerSize
/// Size of a frame header.
pub const HEADER_SIZE: usize = SIZE_OF_VER + SIZE_OF_CMD + SIZE_OF_SID + SIZE_OF_LENGTH;

/// One frame to be multiplexed into the connection: a header plus a borrowed payload.
// Go: smux@v1.5.55 frame.go:Frame
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Frame<'a> {
    /// Protocol version.
    pub ver: u8,
    /// Command (`CMD_*`).
    pub cmd: u8,
    /// Stream id.
    pub sid: u32,
    /// Payload; its length is the header's length field.
    pub data: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Creates a frame with the given version, command and stream id, and no payload.
    // Go: smux@v1.5.55 frame.go:newFrame()
    pub const fn new(version: u8, cmd: u8, sid: u32) -> Frame<'static> {
        Frame {
            ver: version,
            cmd,
            sid,
            data: &[],
        }
    }

    /// Creates a frame with a payload (Go assigns `frame.data` after `newFrame`).
    pub const fn with_data(version: u8, cmd: u8, sid: u32, data: &'a [u8]) -> Frame<'a> {
        Frame {
            ver: version,
            cmd,
            sid,
            data,
        }
    }

    /// The 8-byte header of this frame, exactly as Go's `sendLoop` fills it.
    ///
    /// Like Go (`binary.LittleEndian.PutUint16(buf[2:], uint16(len(request.frame.data)))`), a
    /// payload longer than 65535 bytes would be described by a truncated length field. No
    /// session can build such a frame: [`verify_config`](crate::mux::verify_config) caps
    /// `max_frame_size` at [`MAX_FRAME_SIZE_LIMIT`](crate::mux::MAX_FRAME_SIZE_LIMIT) and the
    /// only other payload smux sends is the 8-byte [`UpdHeader`].
    // Go: smux@v1.5.55 session.go:sendLoop() (header fill)
    pub fn header(&self) -> RawHeader {
        RawHeader::new(self.ver, self.cmd, self.data.len() as u16, self.sid)
    }

    /// Number of bytes [`encode_to`](Self::encode_to) appends.
    pub const fn encoded_len(&self) -> usize {
        HEADER_SIZE + self.data.len()
    }

    /// Appends the header and the payload to `out`: the single `Write` call Go's `sendLoop`
    /// makes when the connection has no `WriteBuffers` method.
    // Go: smux@v1.5.55 session.go:sendLoop()
    pub fn encode_to(&self, out: &mut Vec<u8>) {
        out.reserve(self.encoded_len());
        out.extend_from_slice(self.header().as_bytes());
        out.extend_from_slice(self.data);
    }
}

/// A frame header as it appears on the wire.
// Go: smux@v1.5.55 frame.go:rawHeader
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RawHeader([u8; HEADER_SIZE]);

impl RawHeader {
    /// Encodes the four header fields.
    // Go: smux@v1.5.55 session.go:sendLoop() (header fill)
    pub const fn new(version: u8, cmd: u8, length: u16, sid: u32) -> Self {
        let l = length.to_le_bytes();
        let s = sid.to_le_bytes();
        RawHeader([version, cmd, l[0], l[1], s[0], s[1], s[2], s[3]])
    }

    /// Wraps the 8 header bytes.
    pub const fn from_array(b: [u8; HEADER_SIZE]) -> Self {
        RawHeader(b)
    }

    /// Decodes the header at the start of `b`, or `None` if `b` is shorter than
    /// [`HEADER_SIZE`]. Never panics.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let head: [u8; HEADER_SIZE] = b.get(..HEADER_SIZE)?.try_into().ok()?;
        Some(RawHeader(head))
    }

    /// The protocol version field.
    // Go: smux@v1.5.55 frame.go:rawHeader.Version()
    pub const fn version(&self) -> u8 {
        self.0[0]
    }

    /// The command field (`CMD_*`).
    // Go: smux@v1.5.55 frame.go:rawHeader.Cmd()
    pub const fn cmd(&self) -> u8 {
        self.0[1]
    }

    /// The payload length field.
    // Go: smux@v1.5.55 frame.go:rawHeader.Length()
    pub const fn length(&self) -> u16 {
        u16::from_le_bytes([self.0[2], self.0[3]])
    }

    /// The stream id field.
    // Go: smux@v1.5.55 frame.go:rawHeader.StreamID()
    pub const fn stream_id(&self) -> u32 {
        u32::from_le_bytes([self.0[4], self.0[5], self.0[6], self.0[7]])
    }

    /// The header bytes.
    pub const fn as_bytes(&self) -> &[u8; HEADER_SIZE] {
        &self.0
    }

    /// Checks the header against the session's protocol `version`, exactly as `recvLoop` does
    /// before acting on a frame: the version must match, `cmdSYN`/`cmdFIN`/`cmdNOP` must carry
    /// no payload, `cmdUPD` needs version 2 and exactly [`SZ_CMD_UPD`] bytes, and an unknown
    /// command is a protocol error. `cmdPSH` accepts any length (a zero-length push is ignored
    /// by the caller, not rejected).
    ///
    /// The length checks are the post-pin upstream fix adopted as DECISIONS V01; the pinned
    /// v1.5.55 accepts (and then mis-frames) a `cmdSYN` with a payload.
    // Go: smux@v1.5.55 session.go:recvLoop() (version check and command switch)
    // Go (post-pin fix, V01): smux@v1.5.57 session.go:recvLoop() (length validation)
    pub fn check_protocol(&self, version: u8) -> Result<(), Error> {
        if self.version() != version {
            return Err(Error::InvalidProtocol);
        }
        match self.cmd() {
            CMD_NOP | CMD_SYN | CMD_FIN => {
                if self.length() != 0 {
                    return Err(Error::InvalidProtocol);
                }
                Ok(())
            }
            CMD_PSH => Ok(()),
            CMD_UPD => {
                if version != 2 {
                    return Err(Error::InvalidProtocol);
                }
                if usize::from(self.length()) != SZ_CMD_UPD {
                    return Err(Error::InvalidProtocol);
                }
                Ok(())
            }
            _ => Err(Error::InvalidProtocol),
        }
    }
}

impl fmt::Display for RawHeader {
    // Go: smux@v1.5.55 frame.go:rawHeader.String()
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Version:{} Cmd:{} StreamID:{} Length:{}",
            self.version(),
            self.cmd(),
            self.stream_id(),
            self.length()
        )
    }
}

/// The payload of a [`CMD_UPD`] frame: how many bytes the sender has consumed and how large
/// its receive window is.
// Go: smux@v1.5.55 frame.go:updHeader
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UpdHeader([u8; SZ_CMD_UPD]);

impl UpdHeader {
    /// Encodes `consumed` and `window`.
    // Go: smux@v1.5.55 stream.go:sendWindowUpdate()
    pub const fn new(consumed: u32, window: u32) -> Self {
        let c = consumed.to_le_bytes();
        let w = window.to_le_bytes();
        UpdHeader([c[0], c[1], c[2], c[3], w[0], w[1], w[2], w[3]])
    }

    /// Decodes the payload at the start of `b`, or `None` if `b` is shorter than
    /// [`SZ_CMD_UPD`]. Never panics.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let head: [u8; SZ_CMD_UPD] = b.get(..SZ_CMD_UPD)?.try_into().ok()?;
        Some(UpdHeader(head))
    }

    /// Bytes the peer has consumed on this stream.
    // Go: smux@v1.5.55 frame.go:updHeader.Consumed()
    pub const fn consumed(&self) -> u32 {
        u32::from_le_bytes([self.0[0], self.0[1], self.0[2], self.0[3]])
    }

    /// The peer's receive window for this stream.
    // Go: smux@v1.5.55 frame.go:updHeader.Window()
    pub const fn window(&self) -> u32 {
        u32::from_le_bytes([self.0[4], self.0[5], self.0[6], self.0[7]])
    }

    /// Wraps the 8 payload bytes, as `recvLoop` does after reading them into its `updHeader`.
    pub const fn from_array(b: [u8; SZ_CMD_UPD]) -> Self {
        UpdHeader(b)
    }

    /// The payload bytes.
    pub const fn as_bytes(&self) -> &[u8; SZ_CMD_UPD] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_go() {
        assert_eq!(
            (CMD_SYN, CMD_FIN, CMD_PSH, CMD_NOP, CMD_UPD),
            (0, 1, 2, 3, 4)
        );
        assert_eq!(HEADER_SIZE, 8);
        assert_eq!(SZ_CMD_UPD, 8);
        assert_eq!(INITIAL_PEER_WINDOW, 262144);
    }

    #[test]
    fn header_round_trip() {
        let h = RawHeader::new(2, CMD_PSH, 0x1234, 0xdead_beef);
        assert_eq!(h.as_bytes(), &[2, 2, 0x34, 0x12, 0xef, 0xbe, 0xad, 0xde]);
        assert_eq!(h.version(), 2);
        assert_eq!(h.cmd(), CMD_PSH);
        assert_eq!(h.length(), 0x1234);
        assert_eq!(h.stream_id(), 0xdead_beef);
        assert_eq!(RawHeader::from_bytes(h.as_bytes()), Some(h));
        assert_eq!(RawHeader::from_array(*h.as_bytes()), h);
        // Trailing bytes are the payload, not part of the header.
        let mut long = h.as_bytes().to_vec();
        long.extend_from_slice(b"payload");
        assert_eq!(RawHeader::from_bytes(&long), Some(h));
    }

    #[test]
    fn short_input_decodes_to_none() {
        for n in 0..HEADER_SIZE {
            assert_eq!(RawHeader::from_bytes(&vec![0u8; n]), None, "len {n}");
        }
        for n in 0..SZ_CMD_UPD {
            assert_eq!(UpdHeader::from_bytes(&vec![0u8; n]), None, "len {n}");
        }
    }

    #[test]
    fn frame_encodes_header_then_payload() {
        let f = Frame::with_data(1, CMD_PSH, 3, b"hello");
        assert_eq!(f.encoded_len(), HEADER_SIZE + 5);
        let mut out = Vec::new();
        f.encode_to(&mut out);
        assert_eq!(out, b"\x01\x02\x05\x00\x03\x00\x00\x00hello");
        assert_eq!(RawHeader::from_bytes(&out), Some(f.header()));

        let empty = Frame::new(2, CMD_SYN, 7);
        assert_eq!(empty.data, b"");
        let mut out = Vec::new();
        empty.encode_to(&mut out);
        assert_eq!(out, [2, 0, 0, 0, 7, 0, 0, 0]);
    }

    #[test]
    fn upd_header_round_trip() {
        let u = UpdHeader::new(0x0102_0304, 65536);
        assert_eq!(u.as_bytes(), &[4, 3, 2, 1, 0, 0, 1, 0]);
        assert_eq!((u.consumed(), u.window()), (0x0102_0304, 65536));
        assert_eq!(UpdHeader::from_bytes(u.as_bytes()), Some(u));
    }

    // Go: rawHeader.String()
    #[test]
    fn header_display_matches_go() {
        let h = RawHeader::new(1, CMD_PSH, 1024, 42);
        assert_eq!(h.to_string(), "Version:1 Cmd:2 StreamID:42 Length:1024");
    }

    #[test]
    fn check_protocol_rejects_version_mismatch() {
        for cmd in [CMD_SYN, CMD_FIN, CMD_PSH, CMD_NOP] {
            let h = RawHeader::new(1, cmd, 0, 1);
            assert!(h.check_protocol(1).is_ok());
            assert!(matches!(h.check_protocol(2), Err(Error::InvalidProtocol)));
        }
    }

    // V01: SYN/FIN/NOP must carry no payload, UPD exactly szCmdUPD bytes.
    #[test]
    fn check_protocol_rejects_bad_lengths() {
        for cmd in [CMD_SYN, CMD_FIN, CMD_NOP] {
            assert!(RawHeader::new(1, cmd, 0, 5).check_protocol(1).is_ok());
            for len in [1u16, 8, 65535] {
                assert!(
                    matches!(
                        RawHeader::new(1, cmd, len, 5).check_protocol(1),
                        Err(Error::InvalidProtocol)
                    ),
                    "cmd {cmd} len {len}"
                );
            }
        }
        // PSH accepts any length, including 0 (recvLoop skips it).
        for len in [0u16, 1, 65535] {
            assert!(RawHeader::new(2, CMD_PSH, len, 5).check_protocol(2).is_ok());
        }
        for len in [0u16, 7, 9, 65535] {
            assert!(
                matches!(
                    RawHeader::new(2, CMD_UPD, len, 5).check_protocol(2),
                    Err(Error::InvalidProtocol)
                ),
                "upd len {len}"
            );
        }
        assert!(
            RawHeader::new(2, CMD_UPD, SZ_CMD_UPD as u16, 5)
                .check_protocol(2)
                .is_ok()
        );
    }

    #[test]
    fn check_protocol_rejects_upd_in_v1_and_unknown_commands() {
        // A v1 session rejects cmdUPD before looking at the length.
        assert!(matches!(
            RawHeader::new(1, CMD_UPD, SZ_CMD_UPD as u16, 5).check_protocol(1),
            Err(Error::InvalidProtocol)
        ));
        for cmd in 5u8..=255 {
            assert!(
                matches!(
                    RawHeader::new(1, cmd, 0, 5).check_protocol(1),
                    Err(Error::InvalidProtocol)
                ),
                "cmd {cmd}"
            );
        }
    }
}
