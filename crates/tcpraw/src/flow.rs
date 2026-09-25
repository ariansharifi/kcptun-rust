//! The flow table: one entry per peer 5-tuple, holding the TCP state the crafted segments are
//! built from.
//!
//! A flow is created on first sight of a peer, by a captured segment or by a `WriteTo` to an
//! address not seen yet, and carries:
//!
//! - `conn`: the **real** kernel TCP connection of this 5-tuple, if there is one. A flow without
//!   it is an *orphan*: some other traffic reached the raw socket on our port, so nothing may be
//!   delivered from it and it expires after 5 s instead of a minute.
//! - `handle`: which raw socket saw this peer, i.e. which one has to send to it. A flow without
//!   a handle cannot be written to at all, and `WriteTo` then reports the packet as sent and
//!   drops it, as Go does.
//! - `seq`/`ack`/`ts_ecr`: taken from the peer's own segments so that the crafted ones continue
//!   the kernel's real conversation.
//!
//! Go keeps `handle` as the `*net.IPConn` pointer; this port stores its index in the connection's
//! `handles` vector, which keeps this module free of socket types (and therefore testable on
//! every platform).
//!
//! Go reference: `tcpraw@v1.2.32 tcp_linux.go` (`tcpFlow`, `lockflow`, `captureFlow`, `WriteTo`,
//! `cleaner`).
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use socket2::SockRef;

use crate::addr;
use crate::checksum::PseudoHeader;
use crate::fingerprint::FingerPrint;
use crate::tcp::{Segment, TcpFlags, TcpHeader, serialize};

/// How long a flow with a real TCP connection survives without traffic.
// Go: tcpraw@v1.2.32 tcp_linux.go:expire (`time.Minute`)
pub const EXPIRE: Duration = Duration::from_secs(60);

/// How long an orphan flow (no real TCP connection) survives without traffic.
// Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).cleaner() (`ttl = 5 * time.Second`)
pub const ORPHAN_EXPIRE: Duration = Duration::from_secs(5);

/// How often the cleaner looks for expired flows.
// Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).cleaner() (`time.NewTicker(5 * time.Second)`)
pub const CLEANER_INTERVAL: Duration = Duration::from_secs(5);

/// The TCP state of one peer 5-tuple.
// Go: tcpraw@v1.2.32 tcp_linux.go:tcpFlow
#[derive(Debug)]
pub struct TcpFlow {
    /// The real kernel TCP connection of this flow; `None` makes the flow an orphan.
    pub conn: Option<Arc<RealConn>>,
    /// Index into the connection's `handles` of the raw socket that serves this peer.
    pub handle: Option<usize>,
    /// Sequence number of the next crafted segment, tracked from the peer's acknowledgements.
    pub seq: u32,
    /// Acknowledgement number of the next crafted segment.
    pub ack: u32,
    /// The peer's last TSval, echoed back as our TSecr.
    pub ts_ecr: u32,
    /// When this flow was last touched; the cleaner expires it from here.
    pub ts: Instant,
    /// The serialisation buffer, reused per segment (Go's `e.buf`).
    pub buf: Vec<u8>,
}

impl TcpFlow {
    /// A fresh entry, as `lockflow` creates one on first visit.
    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).lockflow() (`e = new(tcpFlow); e.ts = time.Now()`)
    pub fn new(now: Instant) -> TcpFlow {
        TcpFlow {
            conn: None,
            handle: None,
            seq: 0,
            ack: 0,
            ts_ecr: 0,
            ts: now,
            buf: Vec::new(),
        }
    }

    /// Folds a captured segment into the flow and reports whether the flow was an **orphan**,
    /// i.e. had no real TCP connection when the segment arrived.
    ///
    /// Go decides `orphan` first, then updates, then records the handle, in that order, so a
    /// segment that creates the flow is itself never delivered.
    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).captureFlow() (the `lockflow` closure)
    pub fn capture_update(&mut self, seg: &Segment<'_>, handle: usize, now: Instant) -> bool {
        // Go: "make sure it's related to net.TCPConn", else mark as orphan.
        let orphan = self.conn.is_none();

        // Go: "to keep track of TCP header related to this source".
        self.ts = now;
        if seg.header.flags.ack() {
            self.seq = seg.header.ack;
        }

        // Go: "Parse TCP options to get Timestamp", the first timestamp option wins.
        if let Some(ts) = seg.timestamps() {
            self.ts_ecr = ts.ts_val;
        }

        // Go: "Update ACK". `next_seq` counts the payload plus one for SYN and one for FIN.
        let next_seq = seg.next_seq();
        if next_seq != seg.header.seq {
            // Go: "If we have payload or flags that consume sequence space, update ack", but
            // only from a fresh flow or from the segment that is exactly in order, so a
            // retransmission or a reorder cannot drag the acknowledgement backwards.
            if self.ack == 0 || self.ack == seg.header.seq {
                self.ack = next_seq;
            }
        }

        self.handle = Some(handle);
        orphan
    }

    /// Builds the crafted segment for `payload` into `out` and advances `seq` past it.
    ///
    /// `src_ip` is the local address of the raw socket that will send it (Go's
    /// `e.handle.LocalAddr()`), needed for the checksum's pseudo-header. `fingerprint` is the
    /// connection's single `fingerPrint` clone, whose timestamp option is rewritten here: Go
    /// keeps one per `tcpConn`, shared by every flow and only ever touched under the flow lock.
    ///
    /// Returns `false` and writes nothing when the local and the remote address are in different
    /// families, which cannot happen for a real handle: Go reaches gopacket's `Invalid src IP`
    /// error there, **ignores** it (`gopacket.SerializeLayers`'s return value is discarded) and
    /// then writes whatever the buffer happened to hold. Refusing to send is the one safe
    /// reading of that.
    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).WriteTo() (the `lockflow` closure)
    pub fn build_segment(
        &mut self,
        fingerprint: &mut FingerPrint,
        lport: u16,
        raddr: SocketAddr,
        src_ip: IpAddr,
        payload: &[u8],
        out: &mut Vec<u8>,
    ) -> bool {
        let Some(pseudo) = PseudoHeader::new(src_ip, raddr.ip()) else {
            return false;
        };

        // Go reuses one `layers.TCP` per flow and assigns exactly these fields; everything else
        // (SYN/FIN/RST/URG/ECE/CWR/NS, the urgent pointer) stays zero, and the data offset and
        // the checksum are recomputed by the serialiser.
        let mut header = TcpHeader {
            src_port: lport,
            dst_port: raddr.port(),
            seq: self.seq,
            ack: self.ack,
            flags: TcpFlags::PSH | TcpFlags::ACK,
            window: fingerprint.window,
            ..TcpHeader::default()
        };
        fingerprint.make_option(self.ts_ecr);
        serialize(&mut header, &fingerprint.options, payload, &pseudo, out);

        // Go: `e.seq += uint32(len(p))`, after the write and regardless of whether it failed.
        self.seq = self.seq.wrapping_add(payload.len() as u32);
        true
    }
}

/// Removes every expired flow from `table` and returns the real connections that have to be shut
/// down, in Go's order: set TTL 64 first, then close, so the kernel's FIN actually leaves the
/// host instead of being dropped by our own iptables rule.
///
/// The caller passes `now`, which keeps the expiry testable without sleeping.
// Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).cleaner()
pub fn sweep(table: &mut HashMap<SocketAddr, TcpFlow>, now: Instant) -> Vec<Arc<RealConn>> {
    let mut closing = Vec::new();
    table.retain(|_, v| {
        let ttl = if v.conn.is_none() {
            // Go: "Short expire for orphans".
            ORPHAN_EXPIRE
        } else {
            EXPIRE
        };
        if now.saturating_duration_since(v.ts) > ttl {
            if let Some(conn) = v.conn.take() {
                closing.push(conn);
            }
            false
        } else {
            true
        }
    });
    closing
}

/// The real kernel TCP connection behind a flow: the socket that owns the 5-tuple and keeps the
/// kernel's TCP state alive, with its TTL pinned to 1 so that nothing it sends escapes the host.
///
/// Nothing is ever read from it: a task drains and discards whatever arrives, as Go's
/// `io.Copy(ioutil.Discard, tcpconn)` does, and nothing is ever written to it.
// Go: tcpraw@v1.2.32 tcp_linux.go:tcpFlow.conn (`*net.TCPConn`)
#[derive(Debug)]
pub struct RealConn {
    stream: tokio::net::TcpStream,
}

impl RealConn {
    /// Wraps an established connection.
    pub fn new(stream: tokio::net::TcpStream) -> RealConn {
        RealConn { stream }
    }

    /// The underlying socket, for the discard task.
    pub fn stream(&self) -> &tokio::net::TcpStream {
        &self.stream
    }

    /// Sets the TTL (IPv4) or hop limit (IPv6) of everything the kernel sends on this socket.
    ///
    /// The family is chosen from the **local** address, as Go's `addr.IP.To4() == nil` does.
    // Go: tcpraw@v1.2.32 tcp_linux.go:setTTL()
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        let local = self.stream.local_addr()?;
        let sock = SockRef::from(&self.stream);
        if addr::is_ipv4(local.ip()) {
            sock.set_ttl_v4(ttl)
        } else {
            sock.set_unicast_hops_v6(ttl)
        }
    }

    /// Restores a normal TTL and closes the connection, the sequence Go runs from the cleaner and
    /// from `Close`.
    ///
    /// The socket is shut down rather than closed outright: the file descriptor is owned by this
    /// value and released when the last [`Arc`] to it goes, which is as soon as the flow entry is
    /// gone and the discard task has seen the end of the stream. Both directions are shut down,
    /// so the peer gets the same FIN Go's `Close` sends: now with TTL 64, so it survives the
    /// iptables rule.
    // Go: tcpraw@v1.2.32 tcp_linux.go:(*tcpConn).cleaner(), (*tcpConn).Close()
    pub fn close(&self) {
        let _ = self.set_ttl(64);
        let _ = SockRef::from(&self.stream).shutdown(std::net::Shutdown::Both);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

    use crate::tcp::{MIN_HEADER_LEN, OPTION_KIND_TIMESTAMPS, TcpOption};

    const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 5);
    const REMOTE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);

    fn peer() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(REMOTE), 29900)
    }

    /// Serialises a segment from the peer's point of view, so `capture_update` can be fed real
    /// bytes rather than a hand-built struct.
    fn peer_segment(
        seq: u32,
        ack: u32,
        flags: TcpFlags,
        ts: Option<(u32, u32)>,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut header = TcpHeader {
            src_port: 29900,
            dst_port: 54321,
            seq,
            ack,
            flags,
            window: 65535,
            ..TcpHeader::default()
        };
        let options = match ts {
            Some((val, ecr)) => {
                let mut data = Vec::with_capacity(8);
                data.extend_from_slice(&val.to_be_bytes());
                data.extend_from_slice(&ecr.to_be_bytes());
                vec![
                    TcpOption::single(crate::tcp::OPTION_KIND_NOP),
                    TcpOption::single(crate::tcp::OPTION_KIND_NOP),
                    TcpOption::with_data(OPTION_KIND_TIMESTAMPS, data),
                ]
            }
            None => Vec::new(),
        };
        let pseudo = PseudoHeader::new(IpAddr::V4(REMOTE), IpAddr::V4(LOCAL)).expect("same family");
        let mut out = Vec::new();
        serialize(&mut header, &options, payload, &pseudo, &mut out);
        out
    }

    /// The handshake's final ACK gives the flow its sequence number, and a data segment moves
    /// the acknowledgement on by the payload length.
    #[test]
    fn capture_update_tracks_seq_ack_and_tsecr() {
        let now = Instant::now();
        let mut flow = TcpFlow::new(now);
        flow.conn = None;

        // SYN|ACK of the handshake: ACK carries our next sequence number, SYN consumes one.
        let bytes = peer_segment(
            1000,
            5000,
            TcpFlags::SYN | TcpFlags::ACK,
            Some((0x1111_1111, 7)),
            &[],
        );
        let seg = Segment::decode(&bytes).expect("decode");
        let orphan = flow.capture_update(&seg, 3, now);
        assert!(orphan, "a flow without a real conn is an orphan");
        assert_eq!(flow.seq, 5000, "seq follows the peer's ACK");
        assert_eq!(flow.ack, 1001, "SYN consumes one sequence number");
        assert_eq!(flow.ts_ecr, 0x1111_1111, "TSecr echoes the peer's TSval");
        assert_eq!(flow.handle, Some(3));

        // A data segment in order: ack advances by the payload length.
        let bytes = peer_segment(
            1001,
            5000,
            TcpFlags::PSH | TcpFlags::ACK,
            Some((0x2222_2222, 9)),
            b"0123456789",
        );
        let seg = Segment::decode(&bytes).expect("decode");
        flow.capture_update(&seg, 3, now);
        assert_eq!(flow.ack, 1011);
        assert_eq!(flow.ts_ecr, 0x2222_2222);

        // FIN also consumes one.
        let bytes = peer_segment(1011, 5000, TcpFlags::FIN | TcpFlags::ACK, None, &[]);
        let seg = Segment::decode(&bytes).expect("decode");
        flow.capture_update(&seg, 3, now);
        assert_eq!(flow.ack, 1012);
        assert_eq!(
            flow.ts_ecr, 0x2222_2222,
            "a segment without timestamps leaves TSecr alone"
        );
    }

    /// A segment that consumes no sequence space leaves `ack` alone, and one that is out of order
    /// cannot drag it backwards.
    #[test]
    fn capture_update_ignores_out_of_order_and_empty_segments() {
        let now = Instant::now();
        let mut flow = TcpFlow::new(now);
        flow.ack = 1011;

        // A bare ACK: nextSeq == seq, so Go's `if nextSeq != tcp.Seq` never fires.
        let bytes = peer_segment(500, 6000, TcpFlags::ACK, None, &[]);
        let seg = Segment::decode(&bytes).expect("decode");
        flow.capture_update(&seg, 0, now);
        assert_eq!(flow.ack, 1011);
        assert_eq!(flow.seq, 6000, "an ACK still updates seq");

        // A retransmission of an earlier segment: `e.ack != tcp.Seq`, so ack stays.
        let bytes = peer_segment(
            1001,
            6000,
            TcpFlags::PSH | TcpFlags::ACK,
            None,
            b"0123456789",
        );
        let seg = Segment::decode(&bytes).expect("decode");
        flow.capture_update(&seg, 0, now);
        assert_eq!(flow.ack, 1011);

        // The next in-order segment does advance it.
        let bytes = peer_segment(1011, 6000, TcpFlags::PSH | TcpFlags::ACK, None, b"abc");
        let seg = Segment::decode(&bytes).expect("decode");
        flow.capture_update(&seg, 0, now);
        assert_eq!(flow.ack, 1014);
    }

    /// A segment without the ACK flag leaves `seq` alone, and the wrap is Go's `uint32` wrap.
    #[test]
    fn capture_update_wraps_the_sequence_space() {
        let now = Instant::now();
        let mut flow = TcpFlow::new(now);
        flow.seq = 42;

        let bytes = peer_segment(7, 999, TcpFlags::NONE, None, b"xy");
        let seg = Segment::decode(&bytes).expect("decode");
        flow.capture_update(&seg, 0, now);
        assert_eq!(flow.seq, 42, "no ACK flag, no seq update");
        assert_eq!(flow.ack, 9);

        // seq = 0xffff_ffff, payload of 3 bytes and a FIN: 0xffff_ffff + 3 + 1 wraps to 3.
        let mut flow = TcpFlow::new(now);
        let bytes = peer_segment(0xffff_ffff, 0, TcpFlags::FIN | TcpFlags::PSH, None, b"abc");
        let seg = Segment::decode(&bytes).expect("decode");
        flow.capture_update(&seg, 0, now);
        assert_eq!(flow.ack, 3);
    }

    /// The crafted segment carries the flow's state: our port, the peer's port, PSH|ACK, the
    /// fingerprint's window and timestamp option, and a valid checksum.
    #[test]
    fn build_segment_uses_the_flow_state() {
        let mut flow = TcpFlow::new(Instant::now());
        flow.seq = 5000;
        flow.ack = 1011;
        flow.ts_ecr = 0x2222_2222;
        let mut fp = FingerPrint::linux();
        let mut out = Vec::new();

        let payload = b"kcp packet";
        assert!(flow.build_segment(&mut fp, 54321, peer(), IpAddr::V4(LOCAL), payload, &mut out));

        let seg = Segment::decode(&out).expect("decode");
        assert_eq!(seg.header.src_port, 54321);
        assert_eq!(seg.header.dst_port, 29900);
        assert_eq!(seg.header.seq, 5000);
        assert_eq!(seg.header.ack, 1011);
        assert_eq!(seg.header.flags, TcpFlags::PSH | TcpFlags::ACK);
        assert_eq!(seg.header.window, 65535);
        assert_eq!(seg.header.urgent, 0);
        // V10: NOP, NOP, TS(8 bytes of data) is a 32-byte header, data offset 8.
        assert_eq!(seg.header.data_offset, 8);
        assert_eq!(seg.payload, payload);
        assert_eq!(
            seg.timestamps().map(|ts| ts.ts_ecr),
            Some(0x2222_2222),
            "the peer's TSval is echoed back"
        );
        let pseudo = PseudoHeader::new(IpAddr::V4(LOCAL), IpAddr::V4(REMOTE)).expect("same family");
        assert!(crate::checksum::verify_checksum(&out, &pseudo));
        assert_eq!(out.len(), MIN_HEADER_LEN + 12 + payload.len());

        // Go advances the sequence number by the payload length after every write.
        assert_eq!(flow.seq, 5000 + payload.len() as u32);
        flow.seq = u32::MAX;
        out.clear();
        assert!(flow.build_segment(&mut fp, 54321, peer(), IpAddr::V4(LOCAL), b"ab", &mut out));
        assert_eq!(flow.seq, 1, "the sequence space wraps");
    }

    /// Mismatched address families produce no segment at all (see `build_segment`'s docs).
    #[test]
    fn build_segment_refuses_a_family_mismatch() {
        let mut flow = TcpFlow::new(Instant::now());
        let mut fp = FingerPrint::linux();
        let mut out = vec![0xaa; 4];
        let v6: SocketAddr = "[2001:db8::1]:29900".parse().expect("literal");
        assert!(!flow.build_segment(&mut fp, 1, v6, IpAddr::V4(LOCAL), b"x", &mut out));
        assert_eq!(out, vec![0xaa; 4], "the buffer is untouched");
        assert_eq!(flow.seq, 0, "and the sequence number does not move");
    }

    /// Flows expire after a minute, orphans after five seconds, and an expiring flow hands its
    /// real connection back to the caller to be closed.
    #[test]
    fn sweep_expires_orphans_sooner() {
        let t0 = Instant::now();
        let mut table = HashMap::new();
        table.insert(SocketAddr::new(IpAddr::V4(REMOTE), 1), TcpFlow::new(t0));
        table.insert(SocketAddr::new(IpAddr::V4(REMOTE), 2), TcpFlow::new(t0));

        // Nothing is due yet.
        assert!(sweep(&mut table, t0 + Duration::from_secs(5)).is_empty());
        assert_eq!(table.len(), 2);

        // Both are orphans (no real conn): gone just after 5 s, and none of them yields a
        // connection to close.
        let closing = sweep(&mut table, t0 + ORPHAN_EXPIRE + Duration::from_millis(1));
        assert!(closing.is_empty());
        assert!(table.is_empty());
    }

    /// The expiry boundary is Go's strict `>`, and a flow that is touched again survives.
    #[test]
    fn sweep_uses_the_last_touch() {
        let t0 = Instant::now();
        let mut table = HashMap::new();
        let key = SocketAddr::new(IpAddr::V4(REMOTE), 1);
        table.insert(key, TcpFlow::new(t0));

        // Exactly at the limit the flow stays: Go tests `now.Sub(v.ts) > ttl`.
        assert!(sweep(&mut table, t0 + ORPHAN_EXPIRE).is_empty());
        assert_eq!(table.len(), 1);

        // A captured segment refreshes `ts` and buys another five seconds.
        let bytes = peer_segment(1, 2, TcpFlags::ACK, None, &[]);
        let seg = Segment::decode(&bytes).expect("decode");
        let refreshed = t0 + Duration::from_secs(4);
        table
            .get_mut(&key)
            .expect("flow")
            .capture_update(&seg, 0, refreshed);
        sweep(&mut table, t0 + Duration::from_secs(8));
        assert_eq!(table.len(), 1, "only four seconds since the last segment");
        sweep(
            &mut table,
            refreshed + ORPHAN_EXPIRE + Duration::from_millis(1),
        );
        assert!(table.is_empty(), "five seconds after the last segment");
    }

    /// A flow with a real connection gets the full minute.
    #[tokio::test]
    async fn sweep_gives_connected_flows_a_minute() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accept = tokio::spawn(async move { listener.accept().await });
        let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let (_peer, _) = accept.await.expect("join").expect("accept");

        let t0 = Instant::now();
        let mut table = HashMap::new();
        let mut flow = TcpFlow::new(t0);
        flow.conn = Some(Arc::new(RealConn::new(stream)));
        table.insert(SocketAddr::new(IpAddr::V4(REMOTE), 1), flow);

        // Well past the orphan limit, nowhere near a minute.
        assert!(sweep(&mut table, t0 + Duration::from_secs(30)).is_empty());
        assert_eq!(table.len(), 1);

        let closing = sweep(&mut table, t0 + EXPIRE + Duration::from_millis(1));
        assert_eq!(closing.len(), 1, "the real connection is handed back");
        assert!(table.is_empty());
        // Restoring the TTL must work on a live socket; closing is idempotent.
        closing[0].set_ttl(64).expect("set ttl");
        closing[0].close();
        closing[0].close();
    }
}
