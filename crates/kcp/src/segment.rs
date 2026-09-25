//! KCP segment and its 24-byte header codec (port of the `segment` type in kcp-go `kcp.go`).
//!
//! Wire layout (little-endian, `docs/WIRE-FORMAT.md` §3):
//!
//! ```text
//! 0 conv u32 | 4 cmd u8 | 5 frg u8 | 6 wnd u16 | 8 ts u32 | 12 sn u32 | 16 una u32 | 20 len u32 | 24 data
//! ```
//!
//! # Payload buffer ([`SegmentData`])
//!
//! Go takes segment payloads from a pool of 1500-byte (`mtuLimit`) buffers
//! (`defaultBufferPool.Get()[:size]`) and returns them in `recycleSegment`, so stream-mode
//! `Send` can append into the last queued segment up to `mss` without reallocating. The port
//! uses a plain `Vec<u8>` behind the [`SegmentData`] alias; the KCP code (Step 03.2) allocates
//! it with enough capacity for stream-mode appends (`mss`). Step 05/12 can swap the alias for a
//! pooled buffer type; KCP semantics must not depend on the choice (step 03, Design).
#![forbid(unsafe_code)]

use std::sync::atomic::Ordering;

use crate::kcp::{
    IKCP_OVERHEAD, ikcp_decode8u, ikcp_decode16u, ikcp_decode32u, ikcp_encode8u, ikcp_encode16u,
    ikcp_encode32u,
};
use crate::snmp::DEFAULT_SNMP;

/// Payload buffer of a [`Segment`]; see the module docs for why it is a `Vec<u8>`.
pub type SegmentData = Vec<u8>;

/// Header size as `usize`, for slicing.
const OVERHEAD: usize = IKCP_OVERHEAD as usize;

/// One KCP segment: the header fields sent on the wire plus the sender's retransmission state.
// Go: kcp-go/v5@v5.6.66 kcp.go:segment
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Segment {
    /// Conversation id.
    pub conv: u32,
    /// Command (`IKCP_CMD_*`).
    pub cmd: u8,
    /// Fragment countdown in message mode (0 in stream mode).
    pub frg: u8,
    /// Sender's free receive window.
    pub wnd: u16,
    /// Send timestamp (echoed in ACKs).
    pub ts: u32,
    /// Sequence number.
    pub sn: u32,
    /// Sender's `rcv_nxt` (cumulative ack).
    pub una: u32,
    /// Retransmission timeout (not on the wire).
    pub rto: u32,
    /// Number of transmissions (not on the wire).
    pub xmit: u32,
    /// Time of the next retransmission (not on the wire).
    pub resendts: u32,
    /// Number of later segments acknowledged before this one (not on the wire).
    pub fastack: u32,
    /// Set once the segment has been acknowledged (not on the wire).
    pub acked: u32,
    /// Payload; its length is the header's `len` field.
    pub data: SegmentData,
}

impl Segment {
    /// Writes the 24-byte header into the start of `ptr` and returns the rest of `ptr`, like
    /// Go. The payload is not written (the caller copies `data` after the header). Increments
    /// `DEFAULT_SNMP.out_segs`.
    ///
    /// # Panics
    /// If `ptr` is shorter than [`IKCP_OVERHEAD`], like Go; the flush code reserves the space
    /// first (`makeSpace`), so this is never reachable from network input.
    // Go: kcp-go/v5@v5.6.66 kcp.go:segment.encode()
    pub fn encode<'a>(&self, ptr: &'a mut [u8]) -> &'a mut [u8] {
        let ptr = ikcp_encode32u(ptr, self.conv);
        let ptr = ikcp_encode8u(ptr, self.cmd);
        let ptr = ikcp_encode8u(ptr, self.frg);
        let ptr = ikcp_encode16u(ptr, self.wnd);
        let ptr = ikcp_encode32u(ptr, self.ts);
        let ptr = ikcp_encode32u(ptr, self.sn);
        let ptr = ikcp_encode32u(ptr, self.una);
        // uint32(len(seg.data)): payloads are at most mss bytes, so this never truncates.
        let ptr = ikcp_encode32u(ptr, self.data.len() as u32);
        // atomic.AddUint64: a statistics counter, so relaxed ordering is enough.
        DEFAULT_SNMP.out_segs.fetch_add(1, Ordering::Relaxed);
        ptr
    }
}

/// A decoded segment header, with the fields in wire order (`len` is the payload length the
/// header announces, not yet checked against the packet).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SegmentHeader {
    /// Conversation id.
    pub conv: u32,
    /// Command (`IKCP_CMD_*`).
    pub cmd: u8,
    /// Fragment countdown.
    pub frg: u8,
    /// Sender's free receive window.
    pub wnd: u16,
    /// Timestamp.
    pub ts: u32,
    /// Sequence number.
    pub sn: u32,
    /// Cumulative ack.
    pub una: u32,
    /// Announced payload length.
    pub len: u32,
}

impl SegmentHeader {
    /// Decodes the header at the start of `data`, reading the fields in the same order as Go's
    /// `KCP.Input` (which decodes inline with `ikcp_decode*`). Returns the header and the bytes
    /// after it, or `None` if `data` is shorter than [`IKCP_OVERHEAD`]. Never panics.
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.Input() (header decoding part)
    pub fn decode(data: &[u8]) -> Option<(SegmentHeader, &[u8])> {
        if data.len() < OVERHEAD {
            return None;
        }
        let mut h = SegmentHeader::default();
        let data = ikcp_decode32u(data, &mut h.conv);
        let data = ikcp_decode8u(data, &mut h.cmd);
        let data = ikcp_decode8u(data, &mut h.frg);
        let data = ikcp_decode16u(data, &mut h.wnd);
        let data = ikcp_decode32u(data, &mut h.ts);
        let data = ikcp_decode32u(data, &mut h.sn);
        let data = ikcp_decode32u(data, &mut h.una);
        let data = ikcp_decode32u(data, &mut h.len);
        Some((h, data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kcp::IKCP_CMD_ACK;
    use kcptun_testkit::{assert_hex_eq, vectors};
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct SegParams {
        conv: u32,
        cmd: u8,
        frg: u8,
        wnd: u16,
        ts: u32,
        sn: u32,
        una: u32,
        len: u32,
    }

    impl SegParams {
        fn header(&self) -> SegmentHeader {
            SegmentHeader {
                conv: self.conv,
                cmd: self.cmd,
                frg: self.frg,
                wnd: self.wnd,
                ts: self.ts,
                sn: self.sn,
                una: self.una,
                len: self.len,
            }
        }

        fn segment(&self, data: Vec<u8>) -> Segment {
            Segment {
                conv: self.conv,
                cmd: self.cmd,
                frg: self.frg,
                wnd: self.wnd,
                ts: self.ts,
                sn: self.sn,
                una: self.una,
                // Retransmission state is not on the wire; make sure it is ignored.
                rto: 0xA5A5_A5A5,
                xmit: 7,
                resendts: 0xFFFF_FFFF,
                fastack: 3,
                acked: 1,
                data,
            }
        }
    }

    /// Holds `crate::kcp::SNMP_TEST_LOCK` for reading while encoding, so tests
    /// in kcp.rs that assert exact `out_segs` deltas under the write lock are
    /// not disturbed by these encodes.
    fn snmp_read() -> std::sync::RwLockReadGuard<'static, ()> {
        crate::kcp::SNMP_TEST_LOCK
            .read()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Encodes `seg` into a buffer with trailing space and checks the returned rest.
    fn encode_header(seg: &Segment) -> Vec<u8> {
        let _snmp = snmp_read();
        let mut buf = vec![0xEEu8; OVERHEAD + 5];
        let rest_len = seg.encode(&mut buf).len();
        assert_eq!(rest_len, 5);
        assert_eq!(&buf[OVERHEAD..], &[0xEE; 5], "encode wrote past the header");
        buf.truncate(OVERHEAD);
        buf
    }

    #[test]
    fn vectors_kcp_segment_encode() {
        let file = vectors!("kcp");
        let mut n = 0;
        for case in file.cases_with_prefix("segment/") {
            let p: SegParams = case.field("params");
            let data = case.input();
            assert_eq!(data.len(), p.len as usize, "case {}", case.name);
            let seg = p.segment(data.clone());
            assert_hex_eq!(encode_header(&seg), case.output(), "case {}", case.name);

            // decode(header ‖ data) gives the fields and the payload back.
            let mut wire = case.output();
            wire.extend_from_slice(&data);
            let (h, rest) = SegmentHeader::decode(&wire).expect("24+ bytes");
            assert_eq!(h, p.header(), "case {}", case.name);
            assert_eq!(rest, &data[..], "case {}", case.name);
            n += 1;
        }
        assert_eq!(n, 17);
    }

    #[derive(Debug, Deserialize)]
    struct RealAckParams {
        conv: u32,
        push: Vec<SegParams>,
        acks: Vec<SegParams>,
        outputs: Vec<usize>,
        input_ret: i32,
    }

    /// Decodes a packet of segments into headers (checking each payload fits).
    fn decode_all(mut pkt: &[u8]) -> Vec<(SegmentHeader, Vec<u8>)> {
        let mut out = Vec::new();
        while let Some((h, rest)) = SegmentHeader::decode(pkt) {
            let (data, rest) = rest.split_at(h.len as usize);
            out.push((h, data.to_vec()));
            pkt = rest;
        }
        assert!(pkt.is_empty(), "trailing bytes");
        out
    }

    /// Packets produced by (and fed to) the real kcp-go state machine decode to the recorded
    /// fields, and encoding those fields reproduces the bytes.
    #[test]
    fn vectors_kcp_real_ack() {
        let file = vectors!("kcp");
        let mut n = 0;
        for case in file.cases_with_prefix("real_ack/") {
            let p: RealAckParams = case.field("params");
            assert_eq!(p.input_ret, 0, "case {}", case.name);
            for (label, pkt, want) in [
                ("in", case.input(), &p.push),
                ("out", case.output(), &p.acks),
            ] {
                let segs = decode_all(&pkt);
                assert_eq!(segs.len(), want.len(), "case {} {label}", case.name);
                let mut re = Vec::new();
                for ((h, data), w) in segs.into_iter().zip(want) {
                    assert_eq!(h, w.header(), "case {} {label}", case.name);
                    assert_eq!(h.conv, p.conv, "case {} {label}", case.name);
                    re.extend_from_slice(&encode_header(&w.segment(data.clone())));
                    re.extend_from_slice(&data);
                }
                assert_hex_eq!(re, pkt, "case {} {label}", case.name);
            }
            for a in &p.acks {
                assert_eq!(a.cmd, IKCP_CMD_ACK, "case {}", case.name);
            }
            assert_eq!(p.outputs.iter().sum::<usize>(), case.output().len());
            n += 1;
        }
        assert_eq!(n, 5);
    }

    #[test]
    fn encode_increments_out_segs() {
        // Other tests encode concurrently, so only a lower bound can be checked.
        let _snmp = snmp_read();
        let before = DEFAULT_SNMP.out_segs.load(Ordering::Relaxed);
        let mut buf = [0u8; OVERHEAD];
        for _ in 0..3 {
            let _ = Segment::default().encode(&mut buf);
        }
        assert!(DEFAULT_SNMP.out_segs.load(Ordering::Relaxed) >= before + 3);
    }

    #[test]
    fn decode_rejects_short_input_without_panicking() {
        for len in 0..OVERHEAD {
            assert!(
                SegmentHeader::decode(&vec![0xFF; len]).is_none(),
                "len {len}"
            );
        }
        let (h, rest) = SegmentHeader::decode(&[0u8; OVERHEAD]).expect("exactly 24 bytes");
        assert_eq!(h, SegmentHeader::default());
        assert!(rest.is_empty());
    }

    #[test]
    #[should_panic]
    fn encode_into_short_buffer_panics_like_go() {
        let _snmp = snmp_read();
        let mut buf = [0u8; OVERHEAD - 1];
        let _ = Segment::default().encode(&mut buf);
    }
}
