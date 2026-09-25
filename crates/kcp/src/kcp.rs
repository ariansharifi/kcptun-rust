//! The KCP ARQ state machine (port of kcp-go `kcp.go`).
//!
//! This module holds the protocol constants, the small arithmetic and byte-order helpers of
//! `kcp.go` and the [`Kcp`] state machine itself. The segment type lives in [`crate::segment`],
//! the receive heap in [`crate::heap`] and the queues in [`crate::ringbuffer`].
//!
//! Go `int` parameters and results of the public API map to `isize` (Go's `int` is 64-bit on
//! every supported platform); counts that cannot be negative use `usize`.
//!
//! The trace logger (`SetLogger`/`debugLog`) only produces events with the `trace` Cargo
//! feature, like Go's `debug` build tag.
//!
//! Constants are typed for their main use in Go (the `KCP` fields are `uint32`, `segment.cmd` is
//! `uint8`, `IKCP_SN_OFFSET` indexes a byte slice); Go's untyped constants adapt to every use, so
//! the call sites cast where Go mixes types.
#![forbid(unsafe_code)]

use std::fmt;
use std::sync::atomic::Ordering;

use crate::clock::{Clock, SystemClock};
use crate::heap::SegmentHeap;
use crate::ringbuffer::RingBuffer;
use crate::segment::{Segment, SegmentData, SegmentHeader};
use crate::snmp::DEFAULT_SNMP;

// Go: kcp-go/v5@v5.6.66 kcp.go:const (IKCP_*)
/// No-delay minimum RTO (ms).
pub const IKCP_RTO_NDL: u32 = 30;
/// Normal minimum RTO (ms).
pub const IKCP_RTO_MIN: u32 = 100;
/// Initial RTO (ms).
pub const IKCP_RTO_DEF: u32 = 200;
/// Maximum RTO (ms).
pub const IKCP_RTO_MAX: u32 = 60000;
/// cmd: push data.
pub const IKCP_CMD_PUSH: u8 = 81;
/// cmd: ack.
pub const IKCP_CMD_ACK: u8 = 82;
/// cmd: window probe (ask).
pub const IKCP_CMD_WASK: u8 = 83;
/// cmd: window size (tell).
pub const IKCP_CMD_WINS: u8 = 84;
/// Probe flag: need to send `IKCP_CMD_WASK`.
pub const IKCP_ASK_SEND: u32 = 1;
/// Probe flag: need to send `IKCP_CMD_WINS`.
pub const IKCP_ASK_TELL: u32 = 2;
/// Default send window (segments).
pub const IKCP_WND_SND: u32 = 32;
/// Default receive window (segments).
pub const IKCP_WND_RCV: u32 = 32;
/// Default MTU (bytes).
pub const IKCP_MTU_DEF: u32 = 1400;
/// Duplicate-ACK threshold constant (unused by kcp-go's logic, kept for completeness).
pub const IKCP_ACK_FAST: u32 = 3;
/// Default update interval (ms).
pub const IKCP_INTERVAL: u32 = 100;
/// Segment header size (bytes).
pub const IKCP_OVERHEAD: u32 = 24;
/// Retransmissions of one segment after which the link is considered dead.
pub const IKCP_DEADLINK: u32 = 20;
/// Initial slow-start threshold.
pub const IKCP_THRESH_INIT: u32 = 2;
/// Minimum slow-start threshold.
pub const IKCP_THRESH_MIN: u32 = 2;
/// 500 ms to probe the window size.
pub const IKCP_PROBE_INIT: u32 = 500;
/// Up to 120 s to probe the window.
pub const IKCP_PROBE_LIMIT: u32 = 120000;
/// Byte offset of `sn` in a segment header.
pub const IKCP_SN_OFFSET: usize = 12;

/// Free slots [`Output::capacity`] must report before [`Kcp::flush`] writes one more segment
/// into its packet buffer (**Deviation V18**; not in Go, which drops what does not fit).
///
/// Two, because writing a segment commits `flush` to at most two [`Output::output`] calls: the
/// packet `make_space` may have to close first, and the one the final `flush_buffer` owes for
/// what stays in the buffer. Stopping while two slots are left therefore guarantees that no
/// packet `flush` has already committed to is dropped.
pub const OUTPUT_ROOM: usize = 2;

/// Origin of an input packet: received directly, or recovered by FEC.
// Go: kcp-go/v5@v5.6.66 kcp.go:PacketType
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(i8)]
pub enum PacketType {
    /// `IKCP_PACKET_REGULAR` (0): a packet received from the network.
    Regular = 0,
    /// `IKCP_PACKET_FEC` (1): a packet recovered by FEC. It does not update `rmt_wnd` or the
    /// RTT, and duplicates are not counted in `RepeatSegs`.
    Fec = 1,
}

/// Go's `IKCP_PACKET_REGULAR`.
pub const IKCP_PACKET_REGULAR: PacketType = PacketType::Regular;
/// Go's `IKCP_PACKET_FEC`.
pub const IKCP_PACKET_FEC: PacketType = PacketType::Fec;

/// What `flush` sends.
// Go: kcp-go/v5@v5.6.66 kcp.go:FlushType
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(i8)]
pub enum FlushType {
    /// `IKCP_FLUSH_ACKONLY` (1): only pending ACKs.
    AckOnly = 1,
    /// `IKCP_FLUSH_FULL` (2): ACKs, probes and data.
    Full = 2,
}

/// Go's `IKCP_FLUSH_ACKONLY`.
pub const IKCP_FLUSH_ACKONLY: FlushType = FlushType::AckOnly;
/// Go's `IKCP_FLUSH_FULL`.
pub const IKCP_FLUSH_FULL: FlushType = FlushType::Full;

/// Bit mask selecting the events of the optional trace logger.
// Go: kcp-go/v5@v5.6.66 kcp.go:KCPLogType
pub type KcpLogType = i32;

// Go: kcp-go/v5@v5.6.66 kcp.go:const (IKCP_LOG_*)
/// Log packets written by `output`.
pub const IKCP_LOG_OUTPUT: KcpLogType = 1 << 0;
/// Log segments read by `input`.
pub const IKCP_LOG_INPUT: KcpLogType = 1 << 1;
/// Log `send` calls.
pub const IKCP_LOG_SEND: KcpLogType = 1 << 2;
/// Log `recv` calls.
pub const IKCP_LOG_RECV: KcpLogType = 1 << 3;
/// Log outgoing ACKs.
pub const IKCP_LOG_OUT_ACK: KcpLogType = 1 << 4;
/// Log outgoing PUSH segments.
pub const IKCP_LOG_OUT_PUSH: KcpLogType = 1 << 5;
/// Log outgoing window probes.
pub const IKCP_LOG_OUT_WASK: KcpLogType = 1 << 6;
/// Log outgoing window tells.
pub const IKCP_LOG_OUT_WINS: KcpLogType = 1 << 7;
/// Log incoming ACKs.
pub const IKCP_LOG_IN_ACK: KcpLogType = 1 << 8;
/// Log incoming PUSH segments.
pub const IKCP_LOG_IN_PUSH: KcpLogType = 1 << 9;
/// Log incoming window probes.
pub const IKCP_LOG_IN_WASK: KcpLogType = 1 << 10;
/// Log incoming window tells.
pub const IKCP_LOG_IN_WINS: KcpLogType = 1 << 11;
/// Every output event.
pub const IKCP_LOG_OUTPUT_ALL: KcpLogType =
    IKCP_LOG_OUTPUT | IKCP_LOG_OUT_ACK | IKCP_LOG_OUT_PUSH | IKCP_LOG_OUT_WASK | IKCP_LOG_OUT_WINS;
/// Every input event.
pub const IKCP_LOG_INPUT_ALL: KcpLogType =
    IKCP_LOG_INPUT | IKCP_LOG_IN_ACK | IKCP_LOG_IN_PUSH | IKCP_LOG_IN_WASK | IKCP_LOG_IN_WINS;
/// Every event.
pub const IKCP_LOG_ALL: KcpLogType =
    IKCP_LOG_OUTPUT_ALL | IKCP_LOG_INPUT_ALL | IKCP_LOG_SEND | IKCP_LOG_RECV;

/// Encodes an 8-bit unsigned int and returns the rest of `p`. Panics if `p` is empty (like Go);
/// callers reserve space first.
// Go: kcp-go/v5@v5.6.66 kcp.go:ikcp_encode8u()
pub fn ikcp_encode8u(p: &mut [u8], c: u8) -> &mut [u8] {
    p[0] = c;
    &mut p[1..]
}

/// Decodes an 8-bit unsigned int into `c` and returns the rest of `p`. Panics if `p` is empty
/// (like Go); callers check the length first.
// Go: kcp-go/v5@v5.6.66 kcp.go:ikcp_decode8u()
pub fn ikcp_decode8u<'a>(p: &'a [u8], c: &mut u8) -> &'a [u8] {
    *c = p[0];
    &p[1..]
}

/// Encodes a 16-bit unsigned int (little-endian) and returns the rest of `p`.
// Go: kcp-go/v5@v5.6.66 kcp.go:ikcp_encode16u()
pub fn ikcp_encode16u(p: &mut [u8], w: u16) -> &mut [u8] {
    p[..2].copy_from_slice(&w.to_le_bytes());
    &mut p[2..]
}

/// Decodes a 16-bit unsigned int (little-endian) into `w` and returns the rest of `p`.
// Go: kcp-go/v5@v5.6.66 kcp.go:ikcp_decode16u()
pub fn ikcp_decode16u<'a>(p: &'a [u8], w: &mut u16) -> &'a [u8] {
    *w = u16::from_le_bytes([p[0], p[1]]);
    &p[2..]
}

/// Encodes a 32-bit unsigned int (little-endian) and returns the rest of `p`.
// Go: kcp-go/v5@v5.6.66 kcp.go:ikcp_encode32u()
pub fn ikcp_encode32u(p: &mut [u8], l: u32) -> &mut [u8] {
    p[..4].copy_from_slice(&l.to_le_bytes());
    &mut p[4..]
}

/// Decodes a 32-bit unsigned int (little-endian) into `l` and returns the rest of `p`.
// Go: kcp-go/v5@v5.6.66 kcp.go:ikcp_decode32u()
pub fn ikcp_decode32u<'a>(p: &'a [u8], l: &mut u32) -> &'a [u8] {
    *l = u32::from_le_bytes([p[0], p[1], p[2], p[3]]);
    &p[4..]
}

/// Smaller of two `u32`.
// Go: kcp-go/v5@v5.6.66 kcp.go:_imin_()
#[inline]
pub fn _imin_(a: u32, b: u32) -> u32 {
    if a <= b { a } else { b }
}

/// Larger of two `u32`.
// Go: kcp-go/v5@v5.6.66 kcp.go:_imax_()
#[inline]
pub fn _imax_(a: u32, b: u32) -> u32 {
    if a >= b { a } else { b }
}

/// `min(max(lower, middle), upper)`: when `lower > upper` the result is `upper`.
// Go: kcp-go/v5@v5.6.66 kcp.go:_ibound_()
#[inline]
pub fn _ibound_(lower: u32, middle: u32, upper: u32) -> u32 {
    _imin_(_imax_(lower, middle), upper)
}

/// Signed distance `later - earlier` of two wrapping timestamps or sequence numbers.
// Go: kcp-go/v5@v5.6.66 kcp.go:_itimediff()
#[inline]
pub fn _itimediff(later: u32, earlier: u32) -> i32 {
    later.wrapping_sub(earlier) as i32
}

/// Receives every packet the state machine wants to put on the wire (Go's `output_callback`).
///
/// Go calls `output(buffer, size)`; the port calls [`Output::output`] with `buffer[..size]`,
/// at exactly the same points. Any `FnMut(&[u8])` closure is an `Output`.
// Go: kcp-go/v5@v5.6.66 kcp.go:output_callback
pub trait Output {
    /// Sends one packet (one or more encoded segments).
    fn output(&mut self, buf: &[u8]);

    /// How many more packets [`output`](Output::output) takes before it starts dropping them;
    /// [`usize::MAX`] (the default) for a sink that never drops, which every `Output` but the
    /// session's is.
    ///
    /// **Deviation V18**, not in Go: kcp-go's output callback hands each packet to a 2048-deep
    /// channel with a non-blocking send and **drops** it when that channel is full
    /// (`sess.go:newUDPSession`), so one `flush()` of a large send window can lose most of a
    /// burst, and, because the segment was already marked as transmitted, wait out a
    /// retransmission timeout for every lost packet. [`Kcp::flush`] asks this *before* it
    /// touches a segment and stops emitting instead, leaving the rest for the next flush. The
    /// checks are inert while the sink has room, so an `Output` that never fills up sees
    /// byte-identical behaviour.
    // Not in Go (see above); the session implements it in `crate::session::KcpOutput`.
    fn capacity(&self) -> usize {
        usize::MAX
    }
}

impl<F> Output for F
where
    F: FnMut(&[u8]),
{
    fn output(&mut self, buf: &[u8]) {
        self(buf)
    }
}

/// Trace logger (Go's `logoutput_callback`, `func(msg string, args ...any)`): receives the
/// event name (`"[KCP SEND]"`, …) and Go's alternating key/value arguments as pairs. It is only
/// called when the crate is built with the `trace` feature (Go: build tag `debug`).
// Go: kcp-go/v5@v5.6.66 kcp.go:logoutput_callback
pub type LogOutput = Box<dyn Fn(&str, &[(&str, &dyn fmt::Debug)]) + Send + Sync>;

/// A pending acknowledgement: the `sn` and `ts` of a received PUSH segment.
// Go: kcp-go/v5@v5.6.66 kcp.go:ackItem
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct AckItem {
    /// Sequence number to acknowledge.
    pub sn: u32,
    /// Timestamp of the acknowledged segment (echoed back for RTT measurement).
    pub ts: u32,
}

/// Emits a trace event through [`Kcp::debug_log`] when the `trace` feature is enabled; compiles
/// to nothing otherwise (Go: `kcp_trace_on.go` / `kcp_trace_off.go`). Arguments are Go's
/// key/value pairs.
///
/// The `@fields logmask, log;` form takes the two logger fields instead of the whole `Kcp`, for
/// call sites that hold a mutable borrow of another field (the `flush()` retransmit loop).
macro_rules! debug_log {
    (@fields $mask:expr, $log:expr; $logtype:expr $(, $k:literal, $v:expr)* $(,)?) => {
        #[cfg(feature = "trace")]
        {
            debug_log_to($mask, $log, $logtype, &[$(($k, &$v as &dyn ::std::fmt::Debug)),*]);
        }
    };
    ($kcp:expr, $logtype:expr $(, $k:literal, $v:expr)* $(,)?) => {
        #[cfg(feature = "trace")]
        {
            $kcp.debug_log($logtype, &[$(($k, &$v as &dyn ::std::fmt::Debug)),*]);
        }
    };
}

/// One KCP connection: the ARQ state machine of kcp-go.
///
/// `O` receives the packets to send ([`Output`]); `C` is the millisecond [`Clock`], read
/// wherever Go calls `currentMs()` (DECISIONS D16).
///
/// Field names and types are Go's. They are `pub(crate)` so the session layer (Step 05) can
/// read and tune them under its lock, as `sess.go` does.
// Go: kcp-go/v5@v5.6.66 kcp.go:KCP
pub struct Kcp<O, C = SystemClock> {
    /// Conversation id; both peers must use the same value.
    pub(crate) conv: u32,
    /// Maximum transmission unit of one output packet (bytes, without UDP/FEC/crypto headers).
    pub(crate) mtu: u32,
    /// Maximum segment payload: `mtu - IKCP_OVERHEAD`.
    pub(crate) mss: u32,
    /// Connection state: `0xFFFFFFFF` once a segment exceeded `dead_link` transmissions.
    pub(crate) state: u32,

    /// First unacknowledged sequence number.
    pub(crate) snd_una: u32,
    /// Next sequence number to assign.
    pub(crate) snd_nxt: u32,
    /// Next sequence number expected from the peer.
    pub(crate) rcv_nxt: u32,

    /// Slow-start threshold.
    pub(crate) ssthresh: u32,

    /// RTT variance (ms).
    pub(crate) rx_rttvar: i32,
    /// Smoothed RTT (ms).
    pub(crate) rx_srtt: i32,

    /// Retransmission timeout (ms).
    pub(crate) rx_rto: u32,
    /// Minimum RTO (ms): `IKCP_RTO_MIN`, or `IKCP_RTO_NDL` in no-delay mode.
    pub(crate) rx_minrto: u32,

    /// Send window (segments).
    pub(crate) snd_wnd: u32,
    /// Receive window (segments).
    pub(crate) rcv_wnd: u32,
    /// Peer's advertised receive window.
    pub(crate) rmt_wnd: u32,
    /// Congestion window.
    pub(crate) cwnd: u32,
    /// Pending window probe flags (`IKCP_ASK_SEND`, `IKCP_ASK_TELL`).
    pub(crate) probe: u32,

    /// Flush interval (ms).
    pub(crate) interval: u32,
    /// Time of the next scheduled flush.
    pub(crate) ts_flush: u32,

    /// No-delay mode (non-zero: `rx_minrto = IKCP_RTO_NDL` and gentler RTO backoff).
    pub(crate) nodelay: u32,
    /// Set once `update()` has run.
    pub(crate) updated: u32,

    /// Time of the next window probe.
    pub(crate) ts_probe: u32,
    /// Current window probe interval.
    pub(crate) probe_wait: u32,

    /// Transmissions after which the link is considered dead.
    pub(crate) dead_link: u32,
    /// Congestion-avoidance byte counter.
    pub(crate) incr: u32,

    /// Fast-retransmit threshold (duplicate ACK count; 0 disables).
    pub(crate) fastresend: i32,

    /// Non-zero disables congestion control.
    pub(crate) nocwnd: i32,
    /// Non-zero selects stream mode (no message boundaries, `frg = 0`).
    pub(crate) stream: i32,

    /// Trace events passed to the logger.
    pub(crate) logmask: KcpLogType,

    /// Segments waiting to enter the send window.
    pub(crate) snd_queue: RingBuffer<Segment>,
    /// In-order segments ready for `recv`.
    pub(crate) rcv_queue: RingBuffer<Segment>,
    /// Segments sent and not yet acknowledged.
    pub(crate) snd_buf: RingBuffer<Segment>,
    /// Out-of-order received segments.
    pub(crate) rcv_buf: SegmentHeap,

    /// ACKs to send on the next flush.
    pub(crate) acklist: Vec<AckItem>,

    /// Flush buffer, `(mtu + IKCP_OVERHEAD) * 3` bytes.
    pub(crate) buffer: Vec<u8>,
    /// Packet sink.
    pub(crate) output: O,

    /// Trace logger (see [`LogOutput`]).
    pub(crate) log: Option<LogOutput>,

    /// Millisecond clock (Go: the package-level `currentMs()`).
    pub(crate) clock: C,

    /// What the last [`flush`](Kcp::flush) learnt about `snd_buf` (Decision D29).
    pub(crate) flush_scan: FlushScan,

    /// Every `flush()` call, recorded for the unit tests of its callers.
    #[cfg(test)]
    pub(crate) flush_calls: Vec<FlushCall>,

    /// How many full flushes skipped part of `snd_buf` (Decision D29), and how many segments
    /// they left untouched in total. Tests use it to show that a run exercises the skip at
    /// all: a differential test against the naive scan proves nothing if it never fires.
    #[cfg(test)]
    pub(crate) scan_skipped: (u64, u64),

    /// What the ACK path made of `snd_buf` (Decision D31), for the same reason.
    #[cfg(test)]
    pub(crate) ack_index: AckIndex,
}

/// How often the ACK path found its segment by computing the ring offset rather than searching
/// for it (**Decision D31**), counted for the tests only.
///
/// `misses` is the interesting one: it counts the times `snd_buf` did not hold the segment
/// where its sequence number says it must, and the ACK fell back to kcp-go's linear scan.
/// Nothing a peer can send makes that happen: `snd_buf` is contiguous in `sn` by construction,
/// so a randomised trace that ends with `misses > 0` has found a broken invariant rather
/// than a slow path.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct AckIndex {
    /// ACKs whose segment the offset found. [`Kcp::parse_ack`] and [`Kcp::parse_fastack`] ask
    /// separately, so one acknowledged sequence number counts twice.
    pub(crate) hits: u64,
    /// ACKs that fell back to the scan.
    pub(crate) misses: u64,
    /// Segments [`Kcp::parse_ack`] did not have to walk over to reach its own.
    pub(crate) skipped: u64,
}

/// A lower bound on the retransmission times of the segments a [`FlushScan`] covers.
///
/// A *lower* bound is all [`Kcp::flush`] needs and all that can be kept cheaply: every event
/// between two flushes either leaves the covered segments alone or takes one away (an ACK, or
/// `una` passing it), and taking one away can only push the true minimum later.
// Not in Go (Decision D29).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScanBound {
    /// Nothing is known: the next full flush has to look at every segment.
    Unknown,
    /// No transmitted segment is waiting for an acknowledgement.
    Nothing,
    /// No transmitted, unacknowledged segment is due to be retransmitted before this time.
    NotBefore(u32),
}

/// What [`Kcp::flush`] knows about `snd_buf` from the last time it scanned it, so that the next
/// flush can leave the front of the window untouched (**Decision D29**, plan step 12.2c).
///
/// Go rescans the whole send buffer on every flush: every write, every update tick and every
/// ACK that advances `una`, which is 8192 segments (512 kB of `Segment`) per call at the
/// production window. Nothing in that scan can change unless a segment falls due, a duplicate
/// ACK arrives, or a segment is (re)transmitted, and all three are visible here.
///
/// Every field is **conservative**: it may claim less than is true (which costs a full scan and
/// nothing else), never more. [`ScanBound::Unknown`] and `no_fastack == false` are always safe.
// Not in Go (Decision D29).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FlushScan {
    /// When the earliest transmitted, unacknowledged segment can fall due.
    pub(crate) due: ScanBound,
    /// `false` if some transmitted segment may be waiting for a fast or early retransmit
    /// (`0 < fastack < 0xFFFFFFFF`). Only a scan can set it back to `true`.
    pub(crate) no_fastack: bool,
    /// How many segments at the **tail** of `snd_buf` have never been transmitted
    /// (`xmit == 0`). They are a contiguous suffix; see [`Kcp::flush`] for why, and for the
    /// check that gives up the whole optimisation if they ever are not.
    pub(crate) unsent: usize,
    /// Master switch for the `snd_buf` optimisations of plan step 12.2. `false` makes every
    /// flush scan the whole of `snd_buf` (D29) and every ACK search it segment by segment
    /// (D31), which together are the naive line-by-line port of kcp-go and the permanent
    /// oracle of DECISIONS D25.
    ///
    /// It lives here, in what D29 already keeps about `snd_buf`, because D31 rests on the
    /// same ring: one switch, one summary, and no second structure that could disagree with
    /// this one.
    pub(crate) enabled: bool,
}

impl Default for FlushScan {
    fn default() -> Self {
        FlushScan {
            due: ScanBound::Unknown,
            no_fastack: false,
            unsent: 0,
            enabled: true,
        }
    }
}

impl ScanBound {
    /// A bound covering both halves of a partially scanned `snd_buf`.
    fn merge(self, other: ScanBound) -> ScanBound {
        match (self, other) {
            (ScanBound::Unknown, _) | (_, ScanBound::Unknown) => ScanBound::Unknown,
            (ScanBound::Nothing, b) => b,
            (a, ScanBound::Nothing) => a,
            (ScanBound::NotBefore(a), ScanBound::NotBefore(b)) => {
                ScanBound::NotBefore(if _itimediff(b, a) < 0 { b } else { a })
            }
        }
    }
}

impl FlushScan {
    /// Whether the segments this covers are provably a no-op for a flush at `current` with
    /// this flush `interval`, so that it can skip them.
    ///
    /// Two things have to hold for every covered segment, and both are exactly the conditions
    /// the scan loop would evaluate:
    ///
    /// 1. **It would not be sent.** It has been transmitted (`xmit != 0`), it is not due
    ///    (`resendts` is still ahead of `current`) and it has no duplicate ACKs pending, so
    ///    none of the four retransmit branches fires and nothing, not `xmit`, not `resendts`,
    ///    not `fastack`, not the output: is touched.
    /// 2. **It would not lower `nextUpdate`.** `nextUpdate` starts at `interval` and only ever
    ///    takes a *smaller* `resendts - current`, so a covered segment at least `interval` ms
    ///    from falling due cannot change it, whatever the segments that *are* scanned do.
    fn can_skip(&self, current: u32, interval: u32) -> bool {
        if !self.enabled || !self.no_fastack {
            return false;
        }
        match self.due {
            ScanBound::Unknown => false,
            ScanBound::Nothing => true,
            // The loop's own test, `rto := _itimediff(segment.resendts, current)` followed by
            // `if rto > 0 && uint32(rto) < nextUpdate`, with nextUpdate still at `interval`.
            ScanBound::NotBefore(ts) => {
                let rto = _itimediff(ts, current);
                rto > 0 && (rto as u32) >= interval
            }
        }
    }
}

/// A recorded `flush()` call (unit tests only): the flush type and the state `flush()` sees
/// on entry.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FlushCall {
    pub(crate) flush_type: FlushType,
    pub(crate) acklist: Vec<AckItem>,
    pub(crate) snd_buf_fastack: Vec<u32>,
    pub(crate) probe: u32,
}

/// `DEFAULT_SNMP` is process-global and unit tests run in parallel: tests that change the
/// counters (e.g. by calling `input()`) hold a read lock, tests that assert exact deltas hold
/// the write lock.
#[cfg(test)]
pub(crate) static SNMP_TEST_LOCK: std::sync::RwLock<()> = std::sync::RwLock::new(());

impl<O: Output> Kcp<O, SystemClock> {
    /// Creates a KCP state machine on the production clock.
    ///
    /// `conv` must be equal on both peers, or else data is silently rejected. `output` is called
    /// whenever there is data to be sent on the wire.
    // Go: kcp-go/v5@v5.6.66 kcp.go:NewKCP()
    pub fn new(conv: u32, output: O) -> Self {
        Self::with_clock(conv, output, SystemClock)
    }
}

impl<O: Output, C: Clock> Kcp<O, C> {
    /// Creates a KCP state machine reading time from `clock` (for example a virtual clock in
    /// simulations), with Go's defaults:
    ///
    /// ```
    /// use kcptun_kcp::kcp::Kcp;
    /// let vc = kcptun_testkit::VirtualClock::new();
    /// let mut kcp = Kcp::with_clock(1, |_: &[u8]| {}, { let c = vc.clone(); move || c.now_ms() });
    /// assert_eq!(kcp.send(b"hello"), 0);
    /// assert_eq!(kcp.wait_snd(), 1);
    /// ```
    // Go: kcp-go/v5@v5.6.66 kcp.go:NewKCP()
    pub fn with_clock(conv: u32, output: O, clock: C) -> Self {
        let mtu = IKCP_MTU_DEF;
        Kcp {
            conv,
            mtu,
            mss: mtu - IKCP_OVERHEAD,
            state: 0,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            ssthresh: IKCP_THRESH_INIT,
            rx_rttvar: 0,
            rx_srtt: 0,
            rx_rto: IKCP_RTO_DEF,
            rx_minrto: IKCP_RTO_MIN,
            snd_wnd: IKCP_WND_SND,
            rcv_wnd: IKCP_WND_RCV,
            rmt_wnd: IKCP_WND_RCV,
            cwnd: 0,
            probe: 0,
            interval: IKCP_INTERVAL,
            ts_flush: IKCP_INTERVAL,
            nodelay: 0,
            updated: 0,
            ts_probe: 0,
            probe_wait: 0,
            dead_link: IKCP_DEADLINK,
            incr: 0,
            fastresend: 0,
            nocwnd: 0,
            stream: 0,
            logmask: 0,
            snd_queue: RingBuffer::new(IKCP_WND_SND as usize * 2),
            rcv_queue: RingBuffer::new(IKCP_WND_RCV as usize * 2),
            snd_buf: RingBuffer::new(IKCP_WND_SND as usize * 2),
            rcv_buf: SegmentHeap::new(),
            acklist: Vec::new(),
            buffer: vec![0; ((mtu + IKCP_OVERHEAD) * 3) as usize],
            output,
            log: None,
            clock,
            flush_scan: FlushScan::default(),
            #[cfg(test)]
            flush_calls: Vec::new(),
            #[cfg(test)]
            scan_skipped: (0, 0),
            #[cfg(test)]
            ack_index: AckIndex::default(),
        }
    }

    /// Creates a segment with a zeroed payload of `size` bytes.
    ///
    /// Go slices a pooled 1500-byte (`mtuLimit`) buffer, so stream-mode `send` can later append
    /// up to `mss` bytes in place. The `Vec` gets capacity `max(mss, size)` for the same reason.
    /// (Go panics if `size` exceeds 1500, which only a KCP-level `SetMtu` above 1524 could cause;
    /// the session caps the MTU at 1500. The port just allocates.)
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.newSegment()
    fn new_segment(&self, size: usize) -> Segment {
        let mut data = SegmentData::with_capacity((self.mss as usize).max(size));
        data.resize(size, 0);
        Segment {
            data,
            ..Segment::default()
        }
    }

    /// Releases a segment's payload (Go returns it to the buffer pool and sets `data = nil`).
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.recycleSegment()
    pub(crate) fn recycle_segment(seg: &mut Segment) {
        drop(std::mem::take(&mut seg.data));
    }

    /// Gives back the capacity the queues grew to during a burst, and reports whether anything
    /// was released. It touches no segment, counter or timer that `flush` or `input` reads, so
    /// it cannot change what goes on the wire (D25).
    ///
    /// With the production window (`-sndwnd 8192 -rcvwnd 8192`) one burst takes `snd_buf` and
    /// `rcv_queue` to 8192 slots each and `rcv_buf` to as much as the receive window: about 1 MB
    /// of arrays per session that a `RingBuffer` (Go's as much as this port's) never gives
    /// back. A Go process gets it back anyway, because the *replaced* arrays become garbage;
    /// here [`crate::memory`] says when to ask and a session's update task does the asking (plan
    /// 12.3, `docs/benchmarks/memory.md` §4).
    ///
    /// Only a queue that is empty **at this instant** gives anything back: a queue with something
    /// in it is in use, and shrinking it would lose nothing but would make the next burst copy
    /// the elements again. Nothing received-but-not-read is ever disturbed, so the shrink cannot
    /// change behaviour, but "empty at this instant" is not the same as "this session is idle",
    /// and the difference is worth stating:
    ///
    /// - `snd_queue` and `snd_buf` are empty only when everything sent has been acknowledged, so
    ///   in practice only a session between bursts releases those.
    /// - `rcv_queue` is **routinely empty in the middle of a full-rate transfer**: [`Self::recv`]
    ///   drains it completely, and a reader that keeps up leaves it at zero between windows. A
    ///   busy session whose 30 s
    ///   [`SESSION_SHRINK_INTERVAL`](crate::memory::SESSION_SHRINK_INTERVAL) tick lands on such a
    ///   moment gives its 8192-slot array back and regrows it through the `grow` doublings and
    ///   +10 % steps as the window refills. That is a few reallocations and about half a megabyte
    ///   of `Segment` moves, per session, at most once per 30 s: measured as negligible against
    ///   the transfer that is running, but it is capacity oscillation under load rather than a
    ///   change that only touches idle sessions.
    ///
    /// The same applies to
    /// [`UdpSession::shrink_idle`](crate::session::UdpSession::shrink_idle)'s `recvbuf`.
    pub fn shrink_idle_buffers(&mut self) -> bool {
        let mut shrunk = false;
        if self.snd_queue.is_empty() {
            shrunk |= self.snd_queue.shrink_to(IKCP_WND_SND as usize * 2);
        }
        if self.snd_buf.is_empty() {
            shrunk |= self.snd_buf.shrink_to(IKCP_WND_SND as usize * 2);
        }
        if self.rcv_queue.is_empty() {
            shrunk |= self.rcv_queue.shrink_to(IKCP_WND_RCV as usize * 2);
        }
        if self.rcv_buf.is_empty() {
            shrunk |= self.rcv_buf.shrink();
        }
        // `acklist` is cleared by every flush but keeps the capacity of the largest burst of
        // acks it ever held: one entry per received segment, so up to the receive window.
        if self.acklist.is_empty() && self.acklist.capacity() > IKCP_WND_RCV as usize {
            // `Vec::shrink_to` is documented as a non-binding hint, so measure the capacity
            // rather than assume the hint was taken: every other arm above reports what it
            // actually released, and `UdpSession::shrink_idle` returns this bool as its own.
            let before = self.acklist.capacity();
            self.acklist.shrink_to(IKCP_WND_RCV as usize);
            shrunk |= self.acklist.capacity() < before;
        }
        shrunk
    }

    /// Size of the next message in the receive queue, or -1 if no complete message is queued.
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.PeekSize()
    pub fn peek_size(&self) -> isize {
        let Some(seg) = self.rcv_queue.peek() else {
            return -1;
        };

        if seg.frg == 0 {
            return seg.data.len() as isize;
        }

        // Go: `int(seg.frg+1)` adds in uint8, so frg = 255 (only from a peer; our own sends
        // use at most 254) wraps to 0 and never returns -1 here.
        if self.rcv_queue.len() < usize::from(seg.frg.wrapping_add(1)) {
            return -1;
        }

        let mut length = 0isize;
        for seg in &self.rcv_queue {
            length += seg.data.len() as isize;
            if seg.frg == 0 {
                break;
            }
        }
        length
    }

    /// Receives one message (message mode) or one run of queued segments up to a `frg == 0`
    /// segment into `buffer`.
    ///
    /// Returns the number of bytes read, -1 when there is no readable data, or -2 if
    /// `buffer` is smaller than [`peek_size`](Self::peek_size).
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.Recv()
    pub fn recv(&mut self, buffer: &mut [u8]) -> isize {
        let peeksize = self.peek_size();
        if peeksize < 0 {
            return -1;
        }

        if peeksize as usize > buffer.len() {
            return -2;
        }

        let mut fast_recover = false;
        if self.rcv_queue.len() >= self.rcv_wnd as usize {
            fast_recover = true;
        }

        // merge fragment
        let mut n = 0usize;
        while let Some(mut seg) = self.rcv_queue.pop() {
            // Pops exactly the segments peek_size() summed (both stop at the first frg == 0,
            // or at the end of the queue), so they fit: n + len <= peeksize <= buffer.len().
            let len = seg.data.len();
            buffer[n..n + len].copy_from_slice(&seg.data);
            n += len;
            Self::recycle_segment(&mut seg);
            if seg.frg == 0 {
                debug_log!(
                    self,
                    IKCP_LOG_RECV,
                    "stream",
                    self.stream,
                    "conv",
                    self.conv,
                    "sn",
                    seg.sn,
                    "ts",
                    seg.ts,
                    "datalen",
                    n
                );
                break;
            }
        }

        // move available data from rcv_buf -> rcv_queue
        // Go pops the heap and pushes the segment back if it does not fit; the port does the
        // same (not a peek) so the heap layout stays identical to Go's.
        while let Some(seg) = self.rcv_buf.pop() {
            if seg.sn == self.rcv_nxt && self.rcv_queue.len() < self.rcv_wnd as usize {
                self.rcv_queue.push(seg);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            } else {
                // push back segment
                self.rcv_buf.push(seg);
                break;
            }
        }

        // fast recover
        if self.rcv_queue.len() < self.rcv_wnd as usize && fast_recover {
            // ready to send back IKCP_CMD_WINS in flush: tell remote my window size
            self.probe |= IKCP_ASK_TELL;
        }
        n as isize
    }

    /// Queues `buffer` for sending. Returns 0 on success, -1 if `buffer` is empty, or -2 if it
    /// needs more than 255 segments. In stream mode, bytes are first appended to the last
    /// queued segment (up to `mss`), even when -2 is then returned for the rest (as in Go).
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.Send()
    pub fn send(&mut self, mut buffer: &[u8]) -> isize {
        if buffer.is_empty() {
            return -1;
        }

        debug_log!(
            self,
            IKCP_LOG_SEND,
            "stream",
            self.stream,
            "conv",
            self.conv,
            "datalen",
            buffer.len()
        );

        let mss = self.mss as usize;

        // append to previous segment in streaming mode (if possible)
        if self.stream != 0 {
            // Go ranges over ForEachReverse and breaks after the first element: only the last
            // queued segment is considered.
            if let Some(seg) = self.snd_queue.iter_mut().next_back()
                && seg.data.len() < mss
            {
                let capacity = mss - seg.data.len();
                let extend = buffer.len().min(capacity);
                seg.data.extend_from_slice(&buffer[..extend]);
                buffer = &buffer[extend..];
            }

            if buffer.is_empty() {
                return 0;
            }
        }

        let mut count = if buffer.len() <= mss {
            1
        } else {
            buffer.len().div_ceil(mss) // (len + mss - 1) / mss
        };

        if count > 255 {
            return -2;
        }

        if count == 0 {
            count = 1;
        }

        for i in 0..count {
            let size = buffer.len().min(mss);
            let mut seg = self.new_segment(size);
            seg.data.copy_from_slice(&buffer[..size]);
            if self.stream == 0 {
                // message mode; count <= 255, so this fits in u8
                seg.frg = (count - i - 1) as u8;
            } else {
                // stream mode
                seg.frg = 0;
            }

            self.snd_queue.push(seg);
            buffer = &buffer[size..];
        }
        0
    }

    /// Updates the smoothed RTT, its variance and the RTO from one RTT sample (RFC 6298, with
    /// an 8x smaller variance weight for samples below `srtt - rttvar`).
    ///
    /// All `int32` arithmetic wraps like Go's.
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.update_ack()
    pub(crate) fn update_ack(&mut self, rtt: i32) {
        // https://tools.ietf.org/html/rfc6298
        if self.rx_srtt == 0 {
            self.rx_srtt = rtt;
            self.rx_rttvar = rtt >> 1;
        } else {
            let mut delta = rtt.wrapping_sub(self.rx_srtt);
            self.rx_srtt = self.rx_srtt.wrapping_add(delta >> 3);
            if delta < 0 {
                delta = delta.wrapping_neg();
            }
            if rtt < self.rx_srtt.wrapping_sub(self.rx_rttvar) {
                // if the new RTT sample is below the bottom of the range of
                // what an RTT measurement is expected to be.
                // give an 8x reduced weight versus its normal weighting
                self.rx_rttvar = self
                    .rx_rttvar
                    .wrapping_add(delta.wrapping_sub(self.rx_rttvar) >> 5);
            } else {
                self.rx_rttvar = self
                    .rx_rttvar
                    .wrapping_add(delta.wrapping_sub(self.rx_rttvar) >> 2);
            }
        }
        // uint32(rx_srtt) + _imax_(interval, uint32(rx_rttvar)<<2): bit-preserving casts, the
        // shift drops high bits and the sum wraps, as in Go.
        let rto =
            (self.rx_srtt as u32).wrapping_add(_imax_(self.interval, (self.rx_rttvar as u32) << 2));
        self.rx_rto = _ibound_(self.rx_minrto, rto, IKCP_RTO_MAX);
    }

    /// Sets `snd_una` to the first segment still in `snd_buf`, or to `snd_nxt` if it is empty.
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.shrink_buf()
    pub(crate) fn shrink_buf(&mut self) {
        if let Some(seg) = self.snd_buf.peek() {
            self.snd_una = seg.sn;
        } else {
            self.snd_una = self.snd_nxt;
        }
    }

    /// Where the segment with sequence number `sn` sits in `snd_buf`, **computed** from `sn`
    /// rather than searched for (**Decision D31**, plan step 12.2d), or `None` when the ring
    /// does not hold that segment there.
    ///
    /// `snd_buf` holds the segments `snd_una ..< snd_nxt` in ascending order with no gaps, so
    /// the one carrying `sn` is at offset `sn - snd_una`:
    ///
    /// - [`flush`](Self::flush) is the only thing that puts a segment in, always at the tail
    ///   and always with `sn = snd_nxt` immediately before `snd_nxt` is incremented, so the
    ///   sequence numbers ascend by one and `snd_nxt` is one past the last;
    /// - [`parse_una`](Self::parse_una) is the only thing that takes one out, always a prefix
    ///   from the head ([`RingBuffer::discard`]), so no gap can open in the middle;
    /// - an ACK only writes `acked` and frees the payload; it never removes or reorders;
    /// - [`shrink_buf`](Self::shrink_buf) sets `snd_una` to the head's `sn`, and Go's `Input`
    ///   calls it before every `parse_ack`/`parse_fastack`, so `snd_una` is that offset's
    ///   origin.
    ///
    /// The offset is **checked, not trusted**: the segment found there must carry `sn`. Every
    /// other case: a sequence number outside the ring, a ring shorter than the offset, or an
    /// invariant broken by something not in the list above: returns `None`, and the caller
    /// falls back to kcp-go's linear scan, which is correct whatever the ring holds. What the
    /// check alone cannot establish is that the scan would have *reached* that offset (it
    /// stops at the first segment past `sn`), and that is why debug builds compare every hit
    /// with [`scan_for_sn`](Self::scan_for_sn), the scan it replaces.
    // Not in Go (Decision D31).
    fn snd_buf_offset(&mut self, sn: u32) -> Option<usize> {
        if !self.flush_scan.enabled {
            // DECISIONS D25: the naive line-by-line scan is the oracle.
            return None;
        }
        // A sequence number before `snd_una` wraps to something far larger than any ring, so
        // the length check below covers it as well.
        let offset = sn.wrapping_sub(self.snd_una) as usize;
        let hit = self.snd_buf.get(offset).is_some_and(|seg| seg.sn == sn);
        #[cfg(test)]
        if hit {
            self.ack_index.hits += 1;
        } else {
            self.ack_index.misses += 1;
        }
        hit.then_some(offset)
    }

    /// The offset kcp-go's linear scan stops on for `sn`: the segment it acknowledges, or
    /// `None` when it runs past `sn` (or off the end) without finding one.
    ///
    /// This is the search [`snd_buf_offset`](Self::snd_buf_offset) replaces, kept both as its
    /// fallback and, in debug builds, as the check on every offset it computes.
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.parse_ack() (the loop).
    fn scan_for_sn(&self, sn: u32) -> Option<usize> {
        for (i, seg) in self.snd_buf.iter().enumerate() {
            if sn == seg.sn {
                return Some(i);
            }
            if _itimediff(sn, seg.sn) < 0 {
                return None;
            }
        }
        None
    }

    /// Handles an ACK for `sn`: marks the segment acknowledged and frees its payload, but leaves
    /// it in `snd_buf` until `una` passes it (removing from the middle of the ring would shift
    /// every later segment).
    ///
    /// Decision D31: the segment is addressed by its sequence number instead of being searched
    /// for, which is what makes a selective ACK for the far end of an 8192-segment window cost
    /// the same as one for the near end.
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.parse_ack()
    pub(crate) fn parse_ack(&mut self, sn: u32) {
        if _itimediff(sn, self.snd_una) < 0 || _itimediff(sn, self.snd_nxt) >= 0 {
            return;
        }

        let at = match self.snd_buf_offset(sn) {
            Some(offset) => {
                debug_assert_eq!(
                    self.scan_for_sn(sn),
                    Some(offset),
                    "the ring offset of sn {sn} is not where the scan stops (snd_una {}, \
                     snd_nxt {})",
                    self.snd_una,
                    self.snd_nxt
                );
                #[cfg(test)]
                {
                    self.ack_index.skipped += offset as u64;
                }
                Some(offset)
            }
            None => self.scan_for_sn(sn),
        };
        if let Some(seg) = at.and_then(|at| self.snd_buf.get_mut(at)) {
            // mark and free space, but leave the segment here,
            // and wait until `una` to delete this, then we don't
            // have to shift the segments behind forward,
            // which is an expensive operation for large window
            seg.acked = 1;
            Self::recycle_segment(seg);
        }
    }

    /// One segment's share of Go's `parse_fastack` loop: a segment the scan reaches, which is
    /// not the acknowledged one itself. Split out so that the offset path of Decision D31 and
    /// the fallback scan cannot drift apart.
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.parse_fastack() (the loop body).
    #[inline]
    fn bump_fastack(
        seg: &mut Segment,
        ts: u32,
        fastresend: u32,
        should_fast_ack: &mut isize,
        bumped: &mut bool,
    ) {
        if _itimediff(seg.ts, ts) <= 0 && seg.fastack != 0xFFFF_FFFF {
            seg.fastack = seg.fastack.wrapping_add(1);
            // Go raises `fastack` on acknowledged segments too, and flush skips those
            // before it looks at it, so they are not a reason to rescan.
            *bumped |= seg.acked == 0;
            if seg.fastack >= fastresend {
                *should_fast_ack = 1;
            }
        }
    }

    /// Counts the ACK for `sn` (sent at `ts`) as a duplicate ACK for every earlier segment sent
    /// no later than `ts`. Returns 1 if a segment reached the fast-retransmit threshold, else 0.
    /// Segments with `fastack == 0xFFFFFFFF` (already fast-retransmitted, waiting for their
    /// RTO) are not counted.
    ///
    /// Decision D31: the segments Go's loop reaches are exactly those *before* `sn`, it skips
    /// the one that carries `sn` and stops at the first one past it, so the ring offset of
    /// `sn` is the bound, and the two sequence-number tests come out of the loop body. The
    /// work left is proportional to how far into the window the ACK reaches, which no index
    /// can remove: every one of those segments has its `fastack` raised.
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.parse_fastack()
    pub(crate) fn parse_fastack(&mut self, sn: u32, ts: u32) -> isize {
        let mut should_fast_ack = 0;
        if _itimediff(sn, self.snd_una) < 0 || _itimediff(sn, self.snd_nxt) >= 0 {
            return 0;
        }

        // uint32(kcp.fastresend): a negative threshold becomes a huge one, as in Go.
        let fastresend = self.fastresend as u32;
        // Decision D29: a segment whose `fastack` this raises above zero may be fast- or
        // early-retransmitted by the next flush, so that flush may not skip it.
        let mut bumped = false;
        match self.snd_buf_offset(sn) {
            Some(offset) => {
                debug_assert_eq!(
                    self.scan_for_sn(sn),
                    Some(offset),
                    "the ring offset of sn {sn} is not where the scan stops (snd_una {}, \
                     snd_nxt {})",
                    self.snd_una,
                    self.snd_nxt
                );
                for seg in self.snd_buf.iter_mut_to(offset) {
                    Self::bump_fastack(seg, ts, fastresend, &mut should_fast_ack, &mut bumped);
                }
            }
            None => {
                self.snd_buf.for_each(|seg| {
                    if _itimediff(sn, seg.sn) < 0 {
                        return false;
                    }
                    if sn != seg.sn {
                        Self::bump_fastack(seg, ts, fastresend, &mut should_fast_ack, &mut bumped);
                    }
                    true
                });
            }
        }
        if bumped {
            self.flush_scan.no_fastack = false;
        }

        should_fast_ack
    }

    /// Removes every segment before `una` (the peer's cumulative ack) from `snd_buf` and
    /// returns how many were removed.
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.parse_una()
    pub(crate) fn parse_una(&mut self, una: u32) -> usize {
        let mut count = 0;
        self.snd_buf.for_each(|seg| {
            if _itimediff(una, seg.sn) > 0 {
                Self::recycle_segment(seg);
                count += 1;
                true
            } else {
                false
            }
        });
        self.snd_buf.discard(count);
        // Decision D29: the never-transmitted segments are the tail of the ring and this only
        // removes from its head, so the suffix can only get shorter, by the whole of it when
        // a peer claims `una` for segments we have not sent yet.
        self.flush_scan.unsent = self.flush_scan.unsent.min(self.snd_buf.len());
        count
    }

    /// Queues an ACK for `sn`, echoing `ts`.
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.ack_push()
    pub(crate) fn ack_push(&mut self, sn: u32, ts: u32) {
        self.acklist.push(AckItem { sn, ts });
    }

    /// Stores a received PUSH segment in `rcv_buf` (unless it is out of the receive window or
    /// already there), then moves the in-order segments to `rcv_queue`. Returns `true` if the
    /// segment was a repeat (or out of window).
    ///
    /// Go passes the segment with `data` still aliasing the input packet ("delayed data
    /// copying") and copies it into a pool buffer only when the segment is inserted. The port
    /// passes the header fields in `newseg` (with an empty, unallocated `data`) and the payload
    /// as the borrowed `data`, and copies it at the same point. (Go's pool buffers hold 1500
    /// bytes, so Go would panic on a payload above 1500 bytes; that cannot come from a UDP
    /// packet of at most 1500 bytes, and the port just copies.)
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.parse_data()
    pub(crate) fn parse_data(&mut self, mut newseg: Segment, data: &[u8]) -> bool {
        let sn = newseg.sn;
        if _itimediff(sn, self.rcv_nxt.wrapping_add(self.rcv_wnd)) >= 0
            || _itimediff(sn, self.rcv_nxt) < 0
        {
            return true;
        }

        let mut repeat = false;
        if !self.rcv_buf.has(sn) {
            // replicate the content if it's new
            newseg.data = SegmentData::from(data);

            // insert the new segment into rcv_buf
            self.rcv_buf.push(newseg);
        } else {
            repeat = true;
        }

        // move available data from rcv_buf -> rcv_queue
        // (Go pops and pushes back the head that does not fit, as recv() does.)
        while let Some(seg) = self.rcv_buf.pop() {
            if seg.sn == self.rcv_nxt && self.rcv_queue.len() < self.rcv_wnd as usize {
                self.rcv_queue.push(seg);
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            } else {
                // push back segment
                self.rcv_buf.push(seg);
                break;
            }
        }

        repeat
    }

    /// Feeds one received packet (one or more segments) into the state machine.
    ///
    /// `pkt_type` tells whether the packet came from the network ([`PacketType::Regular`]) or
    /// was recovered by FEC ([`PacketType::Fec`]); only regular packets update the peer window
    /// (`rmt_wnd`) and the RTT, and count duplicates in `RepeatSegs`. `ack_no_delay` flushes
    /// pending ACKs immediately.
    ///
    /// Returns 0 on success, -1 if the packet is shorter than a segment header or a segment has
    /// another `conv`, -2 if a segment's payload is truncated, or -3 for an unknown command.
    /// On an error return, the segments before the bad one have already been processed (as in
    /// Go), but `InSegs`, the RTT, the congestion window and the flush are skipped.
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.Input()
    pub fn input(&mut self, mut data: &[u8], pkt_type: PacketType, ack_no_delay: bool) -> isize {
        let snd_una = self.snd_una;
        if data.len() < IKCP_OVERHEAD as usize {
            return -1;
        }

        let mut latest: u32 = 0; // the latest ack packet
        let mut update_rtt = 0;
        let mut in_segs: u64 = 0;
        let mut flush_segments: isize = 0; // signal to flush segments

        // Go loops until len(data) < IKCP_OVERHEAD and decodes the header field by field;
        // SegmentHeader::decode does both (None: fewer than 24 bytes left).
        while let Some((h, rest)) = SegmentHeader::decode(data) {
            data = rest;
            let SegmentHeader {
                conv,
                cmd,
                frg,
                wnd,
                ts,
                sn,
                una,
                len: length,
            } = h;

            if conv != self.conv {
                return -1;
            }

            debug_log!(
                self,
                IKCP_LOG_INPUT,
                "conv",
                conv,
                "cmd",
                cmd,
                "frg",
                frg,
                "wnd",
                wnd,
                "ts",
                ts,
                "sn",
                sn,
                "una",
                una,
                "len",
                length,
                "datalen",
                data.len()
            );

            // Go: len(data) < int(length); int is 64-bit, so compare without truncating.
            if (data.len() as u64) < u64::from(length) {
                return -2;
            }
            // length <= data.len() now, so it fits in usize.
            let length = length as usize;

            if cmd != IKCP_CMD_PUSH
                && cmd != IKCP_CMD_ACK
                && cmd != IKCP_CMD_WASK
                && cmd != IKCP_CMD_WINS
            {
                return -3;
            }

            // only trust window updates from regular packets. i.e: latest update
            if pkt_type == IKCP_PACKET_REGULAR {
                self.rmt_wnd = u32::from(wnd);
            }
            if self.parse_una(una) > 0 {
                flush_segments |= 1;
            }
            self.shrink_buf();

            if cmd == IKCP_CMD_ACK {
                debug_log!(
                    self,
                    IKCP_LOG_IN_ACK,
                    "conv",
                    conv,
                    "sn",
                    sn,
                    "una",
                    una,
                    "ts",
                    ts,
                    "rto",
                    self.rx_rto
                );
                self.parse_ack(sn);
                flush_segments |= self.parse_fastack(sn, ts);
                update_rtt |= 1;
                latest = ts;
            } else if cmd == IKCP_CMD_PUSH {
                let mut repeat = true;
                if _itimediff(sn, self.rcv_nxt.wrapping_add(self.rcv_wnd)) < 0 {
                    self.ack_push(sn, ts);
                    if _itimediff(sn, self.rcv_nxt) >= 0 {
                        let seg = Segment {
                            conv,
                            cmd,
                            frg,
                            wnd,
                            ts,
                            sn,
                            una,
                            ..Segment::default()
                        };
                        repeat = self.parse_data(seg, &data[..length]); // delayed data copying
                    }
                }
                if pkt_type == IKCP_PACKET_REGULAR && repeat {
                    // atomic.AddUint64: a statistics counter, so relaxed ordering is enough.
                    DEFAULT_SNMP.repeat_segs.fetch_add(1, Ordering::Relaxed);
                }
                debug_log!(
                    self,
                    IKCP_LOG_IN_PUSH,
                    "conv",
                    conv,
                    "sn",
                    sn,
                    "una",
                    una,
                    "ts",
                    ts,
                    "packettype",
                    pkt_type as i8,
                    "repeat",
                    repeat
                );
            } else if cmd == IKCP_CMD_WASK {
                // ready to send back IKCP_CMD_WINS in Ikcp_flush
                // tell remote my window size
                self.probe |= IKCP_ASK_TELL;
                debug_log!(self, IKCP_LOG_IN_WASK, "conv", conv, "wnd", wnd, "ts", ts);
            } else {
                // cmd == IKCP_CMD_WINS (checked above; Go's final `else { return -3 }` is
                // unreachable for the same reason).
                debug_log!(self, IKCP_LOG_IN_WINS, "conv", conv, "wnd", wnd, "ts", ts);
            }

            in_segs += 1;
            data = &data[length..];
        }
        DEFAULT_SNMP.in_segs.fetch_add(in_segs, Ordering::Relaxed);

        // update rtt with the latest ts
        // ignore the FEC packet
        if update_rtt != 0 && pkt_type == IKCP_PACKET_REGULAR {
            let current = self.clock.now_ms();
            if _itimediff(current, latest) >= 0 {
                self.update_ack(_itimediff(current, latest));
            }
        }

        // cwnd update when packet arrived
        if self.nocwnd == 0 && _itimediff(self.snd_una, snd_una) > 0 && self.cwnd < self.rmt_wnd {
            let mss = self.mss;
            if self.cwnd < self.ssthresh {
                self.cwnd = self.cwnd.wrapping_add(1);
                self.incr = self.incr.wrapping_add(mss);
            } else {
                if self.incr < mss {
                    self.incr = mss;
                }
                // incr >= mss here, and mss = mtu - 24 >= 26 (set_mtu rejects mtu < 50), so
                // the division cannot be by zero.
                self.incr = self
                    .incr
                    .wrapping_add((mss.wrapping_mul(mss) / self.incr).wrapping_add(mss / 16));
                if self.cwnd.wrapping_add(1).wrapping_mul(mss) <= self.incr {
                    // Go's branch structure, kept verbatim (clippy prefers checked_div).
                    #[allow(clippy::manual_checked_ops)]
                    if mss > 0 {
                        self.cwnd = self.incr.wrapping_add(mss).wrapping_sub(1) / mss;
                    } else {
                        self.cwnd = self.incr.wrapping_add(mss).wrapping_sub(1);
                    }
                }
            }
            if self.cwnd > self.rmt_wnd {
                self.cwnd = self.rmt_wnd;
                self.incr = self.rmt_wnd.wrapping_mul(mss);
            }
        }

        // Determine if we need to flush data segments or acks
        if flush_segments != 0 {
            // If window has slided or, a fastack should be triggered,
            // Flush immediately. In previous implementations, we only
            // send out fastacks when interval timeouts, so the resending packets
            // have to wait until then. Now, we try to flush as soon as we can.
            self.flush(IKCP_FLUSH_FULL);
        } else if self.acklist.len() >= (self.mtu / IKCP_OVERHEAD) as usize {
            // clocking
            // This serves as the clock for low-latency network.(i.e. the latency is less than the interval.)
            // If the other end is waiting for confirmations, it has to want until the interval timeouts then
            // the flush() is triggered to send out the una & acks. In low-latency network, the interval time is too long to wait,
            // so acks have to be sent out immediately when there are too many.
            self.flush(IKCP_FLUSH_ACKONLY);
        } else if ack_no_delay && !self.acklist.is_empty() {
            // testing(xtaci): ack immediately if acNoDelay is set
            self.flush(IKCP_FLUSH_ACKONLY);
        }
        0
    }

    /// Free receive window advertised to the peer: `rcv_wnd - rcv_queue.len()`, or 0.
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.wnd_unused()
    pub(crate) fn wnd_unused(&self) -> u16 {
        if self.rcv_queue.len() < self.rcv_wnd as usize {
            // uint16(int(rcv_wnd) - len): truncates like Go for windows above 65535.
            return (self.rcv_wnd as usize - self.rcv_queue.len()) as u16;
        }
        0
    }

    /// Flushes pending ACKs, window probes and data segments through the output callback, and
    /// returns the time (ms, at most `interval`) until the nearest retransmission timeout, the
    /// hint the session uses to schedule the next flush.
    ///
    /// [`IKCP_FLUSH_ACKONLY`] sends the ACK list and the window probes only;
    /// [`IKCP_FLUSH_FULL`] also moves segments from `snd_queue` into the send window and
    /// (re)transmits them, and updates the congestion window.
    ///
    /// Encoded segments are packed into the flush buffer and `output` is called whenever the
    /// next one would make the packet exceed `mtu` (Go's `makeSpace`), and once more at the end
    /// for the rest (Go's deferred `flushBuffer`).
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.flush()
    pub(crate) fn flush(&mut self, flush_type: FlushType) -> u32 {
        #[cfg(test)]
        self.flush_calls.push(FlushCall {
            flush_type,
            acklist: self.acklist.clone(),
            snd_buf_fastack: self.snd_buf.iter().map(|s| s.fastack).collect(),
            probe: self.probe,
        });

        let mut seg = Segment {
            conv: self.conv,
            cmd: IKCP_CMD_ACK,
            wnd: self.wnd_unused(),
            una: self.rcv_nxt,
            ..Segment::default()
        };

        // Go: `buffer := kcp.buffer; ptr := buffer`, where `ptr` is the unwritten tail. The port
        // keeps the number of bytes written instead, Go's `size := len(buffer) - len(ptr)`.
        let mut size: usize = 0;

        // makeSpace makes room for writing
        // (Go: the makeSpace closure; it calls output even when size is 0.)
        macro_rules! make_space {
            ($space:expr) => {{
                let space: usize = $space;
                if size + space > self.mtu as usize {
                    self.output.output(&self.buffer[..size]);
                    size = 0;
                }
            }};
        }

        // flush bytes in buffer if there is any
        // (Go: the flushBuffer closure.)
        macro_rules! flush_buffer {
            () => {{
                if size > 0 {
                    self.output.output(&self.buffer[..size]);
                }
            }};
        }

        // Go: `ptr = seg.encode(ptr)` (header only; the caller copies the payload).
        macro_rules! encode {
            ($seg:expr) => {{
                let rest = $seg.encode(&mut self.buffer[size..]).len();
                size = self.buffer.len() - rest;
            }};
        }

        // Deviation V18: room for one more segment in the output, which is the session's
        // bounded packet channel (`crate::tx`). Writing a segment into `buffer` commits to
        // OUTPUT_ROOM output calls: the one `make_space` may do now, and the one the final
        // `flush_buffer` owes for whatever stays in the buffer. Below that, nothing more is
        // emitted and nothing is consumed: the acks stay in `acklist`, the probe bits stay in
        // `probe` and the segments stay exactly as they were, for the next flush.
        // (Not in Go, which drops the surplus instead; see `Output::capacity`.)
        macro_rules! has_room {
            () => {
                self.output.capacity() >= OUTPUT_ROOM
            };
        }

        /*
         * flush acknowledges
         */
        if flush_type == IKCP_FLUSH_ACKONLY || flush_type == IKCP_FLUSH_FULL {
            let acklist_len = self.acklist.len();
            // Deviation V18: acks handled so far; the rest are kept for the next flush. Go
            // clears the whole list here whether or not its packets made it out.
            let mut acks_done = 0usize;
            for (i, ack) in self.acklist.iter().enumerate() {
                if !has_room!() {
                    break;
                }
                make_space!(IKCP_OVERHEAD as usize);
                // filter jitters caused by bufferbloat
                if _itimediff(ack.sn, self.rcv_nxt) >= 0 || acklist_len - 1 == i {
                    (seg.sn, seg.ts) = (ack.sn, ack.ts);
                    encode!(seg);
                    debug_log!(@fields self.logmask, &self.log; IKCP_LOG_OUT_ACK,
                        "conv", seg.conv, "sn", seg.sn, "una", seg.una, "ts", seg.ts);
                }
                acks_done = i + 1;
            }
            // Go: `kcp.acklist = kcp.acklist[0:0]`.
            if acks_done == acklist_len {
                self.acklist.clear();
            } else {
                self.acklist.drain(..acks_done);
            }
        }

        // probe window size (if remote window size equals zero)
        if self.rmt_wnd == 0 {
            let current = self.clock.now_ms();
            if self.probe_wait == 0 {
                self.probe_wait = IKCP_PROBE_INIT;
                self.ts_probe = current.wrapping_add(self.probe_wait);
            } else if _itimediff(current, self.ts_probe) >= 0 {
                if self.probe_wait < IKCP_PROBE_INIT {
                    self.probe_wait = IKCP_PROBE_INIT;
                }
                self.probe_wait += self.probe_wait / 2;
                if self.probe_wait > IKCP_PROBE_LIMIT {
                    self.probe_wait = IKCP_PROBE_LIMIT;
                }
                self.ts_probe = current.wrapping_add(self.probe_wait);
                self.probe |= IKCP_ASK_SEND;
            }
        } else {
            self.ts_probe = 0;
            self.probe_wait = 0;
        }

        /*
         * flush window probing commands
         */
        // (`seg` keeps the sn/ts of the last ACK written above, as in Go.)
        // Deviation V18: probe bits that were written out; a probe left unsent because the
        // output is full keeps its bit and goes out on the next flush instead of being dropped.
        let mut probe_done = 0u32;
        if (self.probe & IKCP_ASK_SEND) != 0 && has_room!() {
            probe_done |= IKCP_ASK_SEND;
            seg.cmd = IKCP_CMD_WASK;
            make_space!(IKCP_OVERHEAD as usize);
            encode!(seg);
            debug_log!(
                self,
                IKCP_LOG_OUT_WASK,
                "conv",
                seg.conv,
                "wnd",
                seg.wnd,
                "ts",
                seg.ts
            );
        }

        // flush window probing commands
        if (self.probe & IKCP_ASK_TELL) != 0 && has_room!() {
            probe_done |= IKCP_ASK_TELL;
            seg.cmd = IKCP_CMD_WINS;
            make_space!(IKCP_OVERHEAD as usize);
            encode!(seg);
            debug_log!(
                self,
                IKCP_LOG_OUT_WINS,
                "conv",
                seg.conv,
                "wnd",
                seg.wnd,
                "ts",
                seg.ts
            );
        }

        // Go: `kcp.probe = 0`, the same, unless V18 held a probe back above.
        self.probe &= !probe_done;

        // calculate window size
        let mut cwnd = _imin_(self.snd_wnd, self.rmt_wnd);
        if self.nocwnd == 0 {
            cwnd = _imin_(self.cwnd, cwnd);
        }

        // sliding window, controlled by snd_nxt && sna_una+cwnd
        // Decision D29: how long the never-transmitted tail of `snd_buf` was before this
        // loop lengthened it (normally 0; V18 backpressure is what leaves one behind).
        let unsent_before = self.flush_scan.unsent;
        let mut new_segs_count = 0;
        loop {
            if _itimediff(self.snd_nxt, self.snd_una.wrapping_add(cwnd)) >= 0 {
                break;
            }

            let Some(mut newseg) = self.snd_queue.pop() else {
                break;
            };

            newseg.conv = self.conv;
            newseg.cmd = IKCP_CMD_PUSH;
            newseg.sn = self.snd_nxt;
            self.snd_buf.push(newseg);
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            new_segs_count += 1;
        }

        // calculate resent
        let mut resent = self.fastresend as u32;
        if self.fastresend <= 0 {
            resent = 0xffff_ffff;
        }

        /*
         * flush segments
         */
        let mut current = self.clock.now_ms();
        let (mut change, mut lost_segs, mut fast_retrans_segs, mut early_retrans_segs) =
            (0u64, 0u64, 0u64, 0u64);
        let mut next_update = self.interval;

        // Deviation V18: set once a segment had to be left unsent because the output is full.
        // From there on the loop only computes `next_update`: every branch below that touches
        // a segment also sends it, so skipping them is exactly "send nothing more".
        let mut backpressured = false;

        // Decision D29 (plan 12.2c): how many segments at the head of `snd_buf` this flush
        // leaves untouched. [`FlushScan::can_skip`] states what makes that identical to
        // scanning them, and the last scan's `unsent` says where the segments that must be
        // looked at start: the never-transmitted ones are a contiguous **suffix** of the ring,
        // because segments are only ever pushed at the tail (with `xmit == 0`), removed at the
        // head, and transmitted from head to tail by this very loop, whose `xmit == 0` branch
        // sends every one it reaches until V18 backpressure stops it for good. The scan below
        // re-derives the suffix and gives the optimisation up (`ScanBound::Unknown`) if it ever
        // finds it broken, so the invariant is checked rather than trusted.
        let unsent_now = unsent_before + new_segs_count;
        let mut skipped = 0usize;
        if flush_type == IKCP_FLUSH_FULL && self.flush_scan.can_skip(current, self.interval) {
            skipped = self.snd_buf.len().saturating_sub(unsent_now);
        }
        #[cfg(test)]
        if skipped > 0 {
            self.scan_skipped.0 += 1;
            self.scan_skipped.1 += skipped as u64;
        }
        // What this flush learns about the segments it does look at. `min_rto` is the smallest
        // `resendts - current` of a transmitted, unacknowledged segment: the very value the
        // loop already works out for `next_update`, and the two flags are branchless, so the
        // summary costs three register operations per segment and the scan it cannot spare
        // stays as fast as the naive one. `scan_unsent` is a plain count, not a trailing run:
        // *where* the never-transmitted segments are is settled after the loop, by walking back
        // from the tail over as many segments as there turn out to be (normally none).
        let scan_base = current;
        let mut min_rto = i32::MAX;
        let mut scan_fastack = false;
        let mut scan_unsent = 0usize;

        // How many never-transmitted segments this flush leaves behind.
        macro_rules! note_tail {
            ($segment:expr) => {{
                scan_unsent += usize::from($segment.xmit == 0);
            }};
        }

        // The whole summary. `$rto` is `resendts - current` for a transmitted, unacknowledged
        // segment and `i32::MAX` for one with no retransmission time to contribute.
        macro_rules! note_scanned {
            ($segment:expr, $rto:expr) => {{
                note_tail!($segment);
                // 0 < fastack < 0xFFFFFFFF, without the two branches.
                scan_fastack |= $segment.fastack.wrapping_sub(1) < 0xFFFF_FFFE;
                min_rto = min_rto.min($rto);
            }};
        }

        if flush_type == IKCP_FLUSH_FULL {
            for segment in self.snd_buf.iter_mut_from(skipped) {
                let mut needsend = false;
                if segment.acked == 1 {
                    // An acknowledged segment is not retransmitted whatever its `fastack` says
                    // (`parse_fastack` raises that one too), so it constrains nothing.
                    note_tail!(segment);
                    continue;
                }

                // Deviation V18: whether this segment would be (re)transmitted, decided before
                // anything is written to it: the four conditions are the four branches below,
                // in the same order and reading only state none of them has written yet (the
                // `debug_assert` after the chain keeps the two in step). Stopping here leaves
                // `xmit`, `rto`, `resendts` and `fastack` untouched, so the next flush sends the
                // segment as if this one had never looked at it; dropping it after the branch
                // ran would instead cost a full retransmission timeout.
                let would_send = !backpressured
                    && (segment.xmit == 0
                        || (segment.fastack >= resent && segment.fastack != 0xFFFF_FFFF)
                        || (segment.fastack > 0
                            && segment.fastack != 0xFFFF_FFFF
                            && new_segs_count == 0)
                        || _itimediff(current, segment.resendts) >= 0);
                if would_send && !has_room!() {
                    backpressured = true;
                }

                if backpressured {
                    // get the nearest rto (the only thing left to do for this segment)
                    let rto = _itimediff(segment.resendts, current);
                    if rto > 0 && (rto as u32) < next_update {
                        next_update = rto as u32;
                    }
                    // A segment left unsent by V18 backpressure still has the `resendts` of a
                    // segment that was never transmitted (0), which says nothing about when it
                    // falls due.
                    note_scanned!(segment, if segment.xmit == 0 { i32::MAX } else { rto });
                    continue;
                }

                if segment.xmit == 0 {
                    // initial transmit
                    needsend = true;
                    segment.rto = self.rx_rto;
                    segment.resendts = current.wrapping_add(segment.rto);
                } else if segment.fastack >= resent && segment.fastack != 0xFFFF_FFFF {
                    // fast retransmit
                    needsend = true;
                    segment.fastack = 0xFFFF_FFFF; // must wait until RTO to reset
                    segment.rto = self.rx_rto;
                    segment.resendts = current.wrapping_add(segment.rto);
                    change += 1;
                    fast_retrans_segs += 1;
                } else if segment.fastack > 0
                    && segment.fastack != 0xFFFF_FFFF
                    && new_segs_count == 0
                {
                    // early retransmit
                    needsend = true;
                    segment.fastack = 0xFFFF_FFFF;
                    segment.rto = self.rx_rto;
                    segment.resendts = current.wrapping_add(segment.rto);
                    change += 1;
                    early_retrans_segs += 1;
                } else if _itimediff(current, segment.resendts) >= 0 {
                    // RTO
                    needsend = true;
                    if self.nodelay == 0 {
                        segment.rto = segment.rto.wrapping_add(self.rx_rto);
                    } else {
                        segment.rto = segment.rto.wrapping_add(self.rx_rto / 2);
                    }
                    segment.fastack = 0;
                    segment.resendts = current.wrapping_add(segment.rto);
                    lost_segs += 1;
                }

                // Deviation V18: the predicate above must be exactly this chain's outcome, or
                // backpressure would stop on a segment the chain would have left alone (or,
                // worse, let one through after the output filled up).
                debug_assert_eq!(
                    needsend, would_send,
                    "the V18 backpressure predicate and the retransmit branches disagree"
                );

                if needsend {
                    current = self.clock.now_ms();
                    segment.xmit = segment.xmit.wrapping_add(1);
                    segment.ts = current;
                    segment.wnd = seg.wnd;
                    segment.una = seg.una;

                    let need = IKCP_OVERHEAD as usize + segment.data.len();
                    make_space!(need);
                    // Go panics here if a segment does not fit into the whole buffer, which only
                    // happens when set_mtu shrank the MTU below a third of a queued segment's
                    // size. The port grows the buffer instead (nothing observable changes: the
                    // oversized packet is written as Go would write it if it had the room).
                    if size + need > self.buffer.len() {
                        self.buffer.resize(size + need, 0);
                    }
                    encode!(segment);
                    self.buffer[size..size + segment.data.len()].copy_from_slice(&segment.data);
                    size += segment.data.len();

                    debug_log!(@fields self.logmask, &self.log; IKCP_LOG_OUT_PUSH,
                        "conv", segment.conv, "sn", segment.sn, "frg", segment.frg,
                        "una", segment.una, "ts", segment.ts, "xmit", segment.xmit,
                        "datalen", segment.data.len());

                    if segment.xmit >= self.dead_link {
                        self.state = 0xFFFF_FFFF;
                    }
                }

                // get the nearest rto
                let rto = _itimediff(segment.resendts, current);
                if rto > 0 && (rto as u32) < next_update {
                    next_update = rto as u32;
                }
                // Every segment that reaches here has been transmitted: the `xmit == 0` branch
                // above always sends, and the one case where it does not: V18 backpressure,
                // left through the arm above.
                debug_assert!(
                    segment.xmit > 0,
                    "an unsent segment reached the end of the scan"
                );
                note_scanned!(segment, rto);
            }

            // Decision D29: fold what was scanned into what is known about the rest. The
            // skipped head keeps the bound the scan that covered it left (still a *lower*
            // bound: since then segments can only have been acknowledged or dropped by `una`,
            // and both only push the earliest retransmission later) and contributes no fastack,
            // because `can_skip` would have refused otherwise.
            let head = if skipped > 0 {
                self.flush_scan.due
            } else {
                ScanBound::Nothing
            };
            // `min_rto` was measured against a `current` that a send may have moved forward,
            // and `scan_base` is where it started, so this can only land at or before the true
            // earliest retransmission, which is the direction a bound may be wrong in.
            let scan_due = if min_rto == i32::MAX {
                ScanBound::Nothing
            } else {
                ScanBound::NotBefore(scan_base.wrapping_add_signed(min_rto))
            };
            self.flush_scan.due = head.merge(scan_due);
            self.flush_scan.no_fastack = !scan_fastack;

            // Where the `scan_unsent` never-transmitted segments are: the run of them at the
            // tail. This stops at the first transmitted segment, so it touches at most one
            // segment more than there are unsent ones: normally exactly one.
            let mut tail = 0usize;
            for segment in self.snd_buf.iter().rev() {
                if segment.xmit != 0 {
                    break;
                }
                tail += 1;
            }
            self.flush_scan.unsent = tail;
            if scan_unsent != tail {
                // The never-transmitted segments are not one run at the tail after all, so the
                // suffix this flush skipped from cannot be trusted next time. Nothing above has
                // gone wrong: this flush scanned from `skipped`, which the *previous* scan
                // vouched for, but no flush may skip anything until a full scan has seen the
                // whole ring again.
                self.flush_scan.due = ScanBound::Unknown;
                self.flush_scan.unsent = 0;
            }
        } else {
            // An ack-only flush still admits segments from `snd_queue` (as Go does: only the
            // retransmission loop is `IKCP_FLUSH_FULL`-only), so the unsent tail grows.
            self.flush_scan.unsent = unsent_now;
        }

        // counter updates
        // (atomic.AddUint64 on statistics counters: relaxed ordering is enough.)
        let mut sum = lost_segs;
        if lost_segs > 0 {
            DEFAULT_SNMP
                .lost_segs
                .fetch_add(lost_segs, Ordering::Relaxed);
        }
        if fast_retrans_segs > 0 {
            DEFAULT_SNMP
                .fast_retrans_segs
                .fetch_add(fast_retrans_segs, Ordering::Relaxed);
            sum += fast_retrans_segs;
        }
        if early_retrans_segs > 0 {
            DEFAULT_SNMP
                .early_retrans_segs
                .fetch_add(early_retrans_segs, Ordering::Relaxed);
            sum += early_retrans_segs;
        }
        if sum > 0 {
            DEFAULT_SNMP.retrans_segs.fetch_add(sum, Ordering::Relaxed);
        }

        // cwnd update
        if self.nocwnd == 0 {
            // update ssthresh
            // rate halving, https://tools.ietf.org/html/rfc6937
            if change > 0 {
                let inflight = self.snd_nxt.wrapping_sub(self.snd_una);
                self.ssthresh = (inflight / 2).max(IKCP_THRESH_MIN);
                self.cwnd = self.ssthresh.wrapping_add(resent);
                self.incr = self.cwnd.wrapping_mul(self.mss);
            }

            // congestion control, https://tools.ietf.org/html/rfc5681
            if lost_segs > 0 {
                self.ssthresh = (cwnd / 2).max(IKCP_THRESH_MIN);
                self.cwnd = 1;
                self.incr = self.mss;
            }

            if self.cwnd < 1 {
                self.cwnd = 1;
                self.incr = self.mss;
            }
        }

        // Go: the deferred function (runs on return, after everything above).
        flush_buffer!();
        DEFAULT_SNMP
            .ring_buffer_snd_queue
            .store(self.snd_queue.len() as u64, Ordering::Relaxed);
        DEFAULT_SNMP
            .ring_buffer_rcv_queue
            .store(self.rcv_queue.len() as u64, Ordering::Relaxed);
        DEFAULT_SNMP
            .ring_buffer_snd_buffer
            .store(self.snd_buf.len() as u64, Ordering::Relaxed);

        next_update
    }

    /// Advances the timer: runs a full [`flush`](Self::flush) whenever `interval` has elapsed
    /// since the last one (deprecated in Go, where the session drives `flush` directly; kept
    /// for simulations). Call it every 10–100 ms, or when [`check`](Self::check) says so.
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.Update()
    pub fn update(&mut self) {
        let mut slap: i32;

        let current = self.clock.now_ms();
        if self.updated == 0 {
            self.updated = 1;
            self.ts_flush = current;
        }

        slap = _itimediff(current, self.ts_flush);

        if !(-10000..10000).contains(&slap) {
            self.ts_flush = current;
            slap = 0;
        }

        if slap >= 0 {
            self.ts_flush = self.ts_flush.wrapping_add(self.interval);
            if _itimediff(current, self.ts_flush) >= 0 {
                self.ts_flush = current.wrapping_add(self.interval);
            }
            self.flush(IKCP_FLUSH_FULL);
        }
    }

    /// Returns the timestamp (ms, on the KCP clock) at which [`update`](Self::update) should
    /// next be called if there is no `input`/`send` in between: now if an update is due or a
    /// segment's retransmission time has passed, otherwise the nearest of the next flush and
    /// the next retransmission, at most `interval` away (deprecated in Go; kept for
    /// simulations).
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.Check()
    pub fn check(&self) -> u32 {
        let current = self.clock.now_ms();
        let mut ts_flush = self.ts_flush;
        // (Go also initialises tm_flush = 0x7fffffff and minimal = 0; both are assigned before
        // their first read.)
        let mut tm_packet: i32 = 0x7fff_ffff;
        if self.updated == 0 {
            return current;
        }

        if _itimediff(current, ts_flush) >= 10000 || _itimediff(current, ts_flush) < -10000 {
            ts_flush = current;
        }

        if _itimediff(current, ts_flush) >= 0 {
            return current;
        }

        let tm_flush = _itimediff(ts_flush, current);

        // (Go ranges over every segment, acknowledged ones included.)
        for seg in self.snd_buf.iter() {
            let diff = _itimediff(seg.resendts, current);
            if diff <= 0 {
                return current;
            }
            if diff < tm_packet {
                tm_packet = diff;
            }
        }

        let mut minimal = tm_packet as u32;
        if tm_packet >= tm_flush {
            minimal = tm_flush as u32;
        }
        if minimal >= self.interval {
            minimal = self.interval;
        }

        current.wrapping_add(minimal)
    }

    /// Changes the MTU (default 1400). Returns -1 (and changes nothing) if `mtu < 50`.
    ///
    /// The pinned rule is kept (`mtu < 50 || mtu < IKCP_OVERHEAD`; DECISIONS V01 does not adopt
    /// the later upstream change). The flush buffer is reallocated to `(mtu + 24) * 3` bytes.
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.SetMtu()
    pub fn set_mtu(&mut self, mtu: isize) -> isize {
        if mtu < 50 || mtu < IKCP_OVERHEAD as isize {
            return -1;
        }

        self.mtu = mtu as u32;
        self.mss = self.mtu.wrapping_sub(IKCP_OVERHEAD);
        // Go: make([]byte, (mtu+IKCP_OVERHEAD)*3). An absurd mtu fails the allocation in both.
        let size = mtu.saturating_add(IKCP_OVERHEAD as isize).saturating_mul(3);
        self.buffer = vec![0; size as usize];
        0
    }

    /// Sets the no-delay options; a negative argument leaves that option unchanged.
    ///
    /// - `nodelay`: 0 disables (default), non-zero enables (`rx_minrto` 30 ms instead of 100);
    /// - `interval`: update interval in ms (default 100), clamped to `10..=5000`;
    /// - `resend`: fast-retransmit threshold (0 disables);
    /// - `nc`: 1 disables congestion control.
    ///
    /// Fastest: `nodelay(1, 20, 2, 1)`. Always returns 0.
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.NoDelay()
    pub fn nodelay(&mut self, nodelay: isize, interval: isize, resend: isize, nc: isize) -> isize {
        if nodelay >= 0 {
            self.nodelay = nodelay as u32;
            if nodelay != 0 {
                self.rx_minrto = IKCP_RTO_NDL;
            } else {
                self.rx_minrto = IKCP_RTO_MIN;
            }
        }
        if interval >= 0 {
            let interval = interval.clamp(10, 5000);
            self.interval = interval as u32;
        }
        if resend >= 0 {
            self.fastresend = resend as i32;
        }
        if nc >= 0 {
            self.nocwnd = nc as i32;
        }
        0
    }

    /// Sets the maximum send and receive windows (default 32 each); values `<= 0` leave the
    /// window unchanged. Always returns 0.
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.WndSize()
    pub fn wnd_size(&mut self, sndwnd: isize, rcvwnd: isize) -> isize {
        if sndwnd > 0 {
            self.snd_wnd = sndwnd as u32;
        }
        if rcvwnd > 0 {
            self.rcv_wnd = rcvwnd as u32;
        }
        0
    }

    /// Number of segments waiting to be sent or acknowledged (`snd_buf` + `snd_queue`).
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.WaitSnd()
    pub fn wait_snd(&self) -> usize {
        self.snd_buf.len() + self.snd_queue.len()
    }

    /// Configures the trace logger: `None` disables tracing (mask 0); otherwise the events in
    /// `mask` are passed to `logger`. Events are only produced with the `trace` feature.
    // Go: kcp-go/v5@v5.6.66 kcp.go:KCP.SetLogger()
    pub fn set_logger(&mut self, mask: KcpLogType, logger: Option<LogOutput>) {
        let Some(logger) = logger else {
            self.logmask = 0;
            return;
        };
        self.logmask = mask;
        self.log = Some(logger);
    }

    /// Passes a trace event to the logger if `logtype` is in the mask.
    // Go: kcp-go/v5@v5.6.66 kcp_trace_on.go:KCP.debugLog()
    #[cfg(feature = "trace")]
    pub(crate) fn debug_log(&self, logtype: KcpLogType, args: &[(&str, &dyn fmt::Debug)]) {
        debug_log_to(self.logmask, &self.log, logtype, args);
    }
}

/// The body of [`Kcp::debug_log`], taking the logger fields (see the `@fields` form of
/// `debug_log!`).
// Go: kcp-go/v5@v5.6.66 kcp_trace_on.go:KCP.debugLog()
#[cfg(feature = "trace")]
fn debug_log_to(
    logmask: KcpLogType,
    log: &Option<LogOutput>,
    logtype: KcpLogType,
    args: &[(&str, &dyn fmt::Debug)],
) {
    if logmask & logtype == 0 {
        return;
    }

    let msg = match logtype {
        IKCP_LOG_OUTPUT => "[KCP OUTPUT]",
        IKCP_LOG_INPUT => "[KCP INPUT]",
        IKCP_LOG_SEND => "[KCP SEND]",
        IKCP_LOG_RECV => "[KCP RECV]",
        IKCP_LOG_OUT_ACK => "[KCP OUTPUT ACK]",
        IKCP_LOG_OUT_PUSH => "[KCP OUTPUT PUSH]",
        IKCP_LOG_OUT_WASK => "[KCP OUTPUT WASK]",
        IKCP_LOG_OUT_WINS => "[KCP OUTPUT WINS]",
        IKCP_LOG_IN_ACK => "[KCP INPUT ACK]",
        IKCP_LOG_IN_PUSH => "[KCP INPUT PUSH]",
        IKCP_LOG_IN_WASK => "[KCP INPUT WASK]",
        IKCP_LOG_IN_WINS => "[KCP INPUT WINS]",
        _ => "",
    };
    if let Some(log) = log {
        log(msg, args);
    }
}

impl<O, C> fmt::Debug for Kcp<O, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Kcp")
            .field("conv", &self.conv)
            .field("mtu", &self.mtu)
            .field("mss", &self.mss)
            .field("state", &self.state)
            .field("snd_una", &self.snd_una)
            .field("snd_nxt", &self.snd_nxt)
            .field("rcv_nxt", &self.rcv_nxt)
            .field("snd_wnd", &self.snd_wnd)
            .field("rcv_wnd", &self.rcv_wnd)
            .field("rmt_wnd", &self.rmt_wnd)
            .field("cwnd", &self.cwnd)
            .field("rx_rto", &self.rx_rto)
            .field("snd_queue", &self.snd_queue.len())
            .field("snd_buf", &self.snd_buf.len())
            .field("rcv_queue", &self.rcv_queue.len())
            .field("rcv_buf", &self.rcv_buf.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kcptun_testkit::vectors;

    #[test]
    fn vectors_kcp_constants() {
        let file = vectors!("kcp");
        let case = file.case("constants");
        let params = case.params();
        let ours: &[(&str, i64)] = &[
            ("IKCP_RTO_NDL", IKCP_RTO_NDL.into()),
            ("IKCP_RTO_MIN", IKCP_RTO_MIN.into()),
            ("IKCP_RTO_DEF", IKCP_RTO_DEF.into()),
            ("IKCP_RTO_MAX", IKCP_RTO_MAX.into()),
            ("IKCP_CMD_PUSH", IKCP_CMD_PUSH.into()),
            ("IKCP_CMD_ACK", IKCP_CMD_ACK.into()),
            ("IKCP_CMD_WASK", IKCP_CMD_WASK.into()),
            ("IKCP_CMD_WINS", IKCP_CMD_WINS.into()),
            ("IKCP_ASK_SEND", IKCP_ASK_SEND.into()),
            ("IKCP_ASK_TELL", IKCP_ASK_TELL.into()),
            ("IKCP_WND_SND", IKCP_WND_SND.into()),
            ("IKCP_WND_RCV", IKCP_WND_RCV.into()),
            ("IKCP_MTU_DEF", IKCP_MTU_DEF.into()),
            ("IKCP_ACK_FAST", IKCP_ACK_FAST.into()),
            ("IKCP_INTERVAL", IKCP_INTERVAL.into()),
            ("IKCP_OVERHEAD", IKCP_OVERHEAD.into()),
            ("IKCP_DEADLINK", IKCP_DEADLINK.into()),
            ("IKCP_THRESH_INIT", IKCP_THRESH_INIT.into()),
            ("IKCP_THRESH_MIN", IKCP_THRESH_MIN.into()),
            ("IKCP_PROBE_INIT", IKCP_PROBE_INIT.into()),
            ("IKCP_PROBE_LIMIT", IKCP_PROBE_LIMIT.into()),
            ("IKCP_SN_OFFSET", IKCP_SN_OFFSET as i64),
            ("IKCP_PACKET_REGULAR", IKCP_PACKET_REGULAR as i64),
            ("IKCP_PACKET_FEC", IKCP_PACKET_FEC as i64),
            ("IKCP_FLUSH_ACKONLY", IKCP_FLUSH_ACKONLY as i64),
            ("IKCP_FLUSH_FULL", IKCP_FLUSH_FULL as i64),
            ("IKCP_LOG_OUTPUT", IKCP_LOG_OUTPUT.into()),
            ("IKCP_LOG_INPUT", IKCP_LOG_INPUT.into()),
            ("IKCP_LOG_SEND", IKCP_LOG_SEND.into()),
            ("IKCP_LOG_RECV", IKCP_LOG_RECV.into()),
            ("IKCP_LOG_OUT_ACK", IKCP_LOG_OUT_ACK.into()),
            ("IKCP_LOG_OUT_PUSH", IKCP_LOG_OUT_PUSH.into()),
            ("IKCP_LOG_OUT_WASK", IKCP_LOG_OUT_WASK.into()),
            ("IKCP_LOG_OUT_WINS", IKCP_LOG_OUT_WINS.into()),
            ("IKCP_LOG_IN_ACK", IKCP_LOG_IN_ACK.into()),
            ("IKCP_LOG_IN_PUSH", IKCP_LOG_IN_PUSH.into()),
            ("IKCP_LOG_IN_WASK", IKCP_LOG_IN_WASK.into()),
            ("IKCP_LOG_IN_WINS", IKCP_LOG_IN_WINS.into()),
            ("IKCP_LOG_OUTPUT_ALL", IKCP_LOG_OUTPUT_ALL.into()),
            ("IKCP_LOG_INPUT_ALL", IKCP_LOG_INPUT_ALL.into()),
            ("IKCP_LOG_ALL", IKCP_LOG_ALL.into()),
            ("RINGBUFFER_MIN", crate::ringbuffer::RINGBUFFER_MIN as i64),
            ("RINGBUFFER_EXP", crate::ringbuffer::RINGBUFFER_EXP as i64),
        ];
        assert_eq!(params.len(), ours.len(), "constant count");
        for (name, value) in ours {
            let go = params
                .get(*name)
                .and_then(|v| v.as_i64())
                .unwrap_or_else(|| panic!("{name} missing from vectors"));
            assert_eq!(*value, go, "{name}");
        }
    }

    #[test]
    fn vectors_kcp_itimediff() {
        let file = vectors!("kcp");
        let mut n = 0;
        for case in file.cases_with_prefix("itimediff/") {
            let later: u32 = case.param("later");
            let earlier: u32 = case.param("earlier");
            let want: i32 = case.param("want");
            assert_eq!(_itimediff(later, earlier), want, "case {}", case.name);
            n += 1;
        }
        assert_eq!(n, 28);
    }

    #[test]
    fn vectors_kcp_ibound() {
        let file = vectors!("kcp");
        let mut n = 0;
        for case in file.cases_with_prefix("ibound/") {
            let (lower, middle, upper): (u32, u32, u32) = (
                case.param("lower"),
                case.param("middle"),
                case.param("upper"),
            );
            assert_eq!(
                _ibound_(lower, middle, upper),
                case.param::<u32>("want"),
                "case {}",
                case.name
            );
            n += 1;
        }
        assert_eq!(n, 9);
    }

    #[test]
    fn min_max_match_go_on_ties() {
        assert_eq!(_imin_(3, 3), 3);
        assert_eq!(_imax_(3, 3), 3);
        assert_eq!(_imin_(0, u32::MAX), 0);
        assert_eq!(_imax_(0, u32::MAX), u32::MAX);
    }

    #[test]
    fn codec_helpers_round_trip() {
        let mut buf = [0u8; 7];
        let rest = ikcp_encode8u(&mut buf, 0xAB);
        let rest = ikcp_encode16u(rest, 0x1234);
        let rest = ikcp_encode32u(rest, 0xDEADBEEF);
        assert!(rest.is_empty());
        assert_eq!(buf, [0xAB, 0x34, 0x12, 0xEF, 0xBE, 0xAD, 0xDE]);

        let (mut c, mut w, mut l) = (0u8, 0u16, 0u32);
        let rest = ikcp_decode8u(&buf, &mut c);
        let rest = ikcp_decode16u(rest, &mut w);
        let rest = ikcp_decode32u(rest, &mut l);
        assert!(rest.is_empty());
        assert_eq!((c, w, l), (0xAB, 0x1234, 0xDEADBEEF));
    }
}

#[cfg(test)]
mod kcp_tests {
    use super::*;

    type TestKcp = Kcp<fn(&[u8]), fn() -> u32>;

    fn discard(_: &[u8]) {}
    fn zero_clock() -> u32 {
        0
    }

    fn new_kcp() -> TestKcp {
        Kcp::with_clock(0x1234_5678, discard as fn(&[u8]), zero_clock as fn() -> u32)
    }

    /// Deterministic payload: byte i is `(i * 7 + salt) as u8`.
    fn payload(len: usize, salt: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(7).wrapping_add(salt))
            .collect()
    }

    fn seg(sn: u32, frg: u8, data: Vec<u8>) -> Segment {
        Segment {
            sn,
            frg,
            data,
            ..Segment::default()
        }
    }

    fn queued(q: &RingBuffer<Segment>) -> Vec<(u8, usize)> {
        q.iter().map(|s| (s.frg, s.data.len())).collect()
    }

    fn concat(q: &RingBuffer<Segment>) -> Vec<u8> {
        q.iter().flat_map(|s| s.data.iter().copied()).collect()
    }

    // ---- NewKCP ----

    #[test]
    fn new_has_go_defaults() {
        let k = new_kcp();
        assert_eq!(k.conv, 0x1234_5678);
        assert_eq!(k.snd_wnd, IKCP_WND_SND);
        assert_eq!(k.rcv_wnd, IKCP_WND_RCV);
        assert_eq!(k.rmt_wnd, IKCP_WND_RCV);
        assert_eq!(k.mtu, IKCP_MTU_DEF);
        assert_eq!(k.mss, 1376);
        assert_eq!(k.buffer.len(), (1400 + 24) * 3);
        assert_eq!(k.rx_rto, IKCP_RTO_DEF);
        assert_eq!(k.rx_minrto, IKCP_RTO_MIN);
        assert_eq!(k.interval, IKCP_INTERVAL);
        assert_eq!(k.ts_flush, IKCP_INTERVAL);
        assert_eq!(k.ssthresh, IKCP_THRESH_INIT);
        assert_eq!(k.dead_link, IKCP_DEADLINK);
        // Ring capacities: WND*2 slots, one kept empty.
        assert_eq!(k.snd_buf.max_len(), 63);
        assert_eq!(k.rcv_queue.max_len(), 63);
        assert_eq!(k.snd_queue.max_len(), 63);
        assert!(k.rcv_buf.is_empty());
        // Zero values.
        for v in [
            k.state,
            k.snd_una,
            k.snd_nxt,
            k.rcv_nxt,
            k.cwnd,
            k.probe,
            k.nodelay,
            k.updated,
            k.ts_probe,
            k.probe_wait,
            k.incr,
        ] {
            assert_eq!(v, 0);
        }
        assert_eq!((k.rx_rttvar, k.rx_srtt), (0, 0));
        assert_eq!((k.fastresend, k.nocwnd, k.stream, k.logmask), (0, 0, 0, 0));
        assert!(k.acklist.is_empty());
        assert!(k.log.is_none());
        assert_eq!(k.peek_size(), -1);
        assert_eq!(k.wait_snd(), 0);
    }

    #[test]
    fn new_uses_system_clock_and_closures() {
        let mut out: Vec<Vec<u8>> = Vec::new();
        {
            let mut k = Kcp::new(7, |b: &[u8]| out.push(b.to_vec()));
            assert_eq!(k.conv, 7);
            k.output.output(b"xy");
            let _ = k.clock.now_ms();
            assert!(format!("{k:?}").starts_with("Kcp { conv: 7, mtu: 1400"));
        }
        assert_eq!(out, vec![b"xy".to_vec()]);
    }

    #[test]
    fn new_segment_reserves_mss_for_stream_appends() {
        let k = new_kcp();
        let s = k.new_segment(10);
        assert_eq!(s.data, vec![0; 10]);
        assert!(s.data.capacity() >= k.mss as usize);
        assert_eq!((s.frg, s.sn, s.xmit, s.acked), (0, 0, 0, 0));
        // Larger than mss (not reachable from send, which caps at mss): still allocated.
        assert_eq!(k.new_segment(2000).data.len(), 2000);

        let mut s = k.new_segment(5);
        TestKcp::recycle_segment(&mut s);
        assert!(s.data.is_empty());
        assert_eq!(s.data.capacity(), 0);
    }

    // ---- Send ----

    #[test]
    fn send_empty_returns_minus_one() {
        let mut k = new_kcp();
        assert_eq!(k.send(&[]), -1);
        k.stream = 1;
        assert_eq!(k.send(&[]), -1);
        assert_eq!(k.wait_snd(), 0);
    }

    #[test]
    fn send_message_mode_fragments() {
        let mss = 1376;
        for (len, want) in [
            (1, vec![(0, 1)]),
            (mss - 1, vec![(0, mss - 1)]),
            (mss, vec![(0, mss)]),
            (mss + 1, vec![(1, mss), (0, 1)]),
            (2 * mss, vec![(1, mss), (0, mss)]),
            (3 * mss - 5, vec![(2, mss), (1, mss), (0, mss - 5)]),
        ] {
            let mut k = new_kcp();
            let data = payload(len, 3);
            assert_eq!(k.send(&data), 0, "len {len}");
            assert_eq!(queued(&k.snd_queue), want, "len {len}");
            assert_eq!(concat(&k.snd_queue), data, "len {len}");
            assert_eq!(k.wait_snd(), want.len());
        }
    }

    #[test]
    fn send_message_mode_never_appends() {
        let mut k = new_kcp();
        assert_eq!(k.send(b"abc"), 0);
        assert_eq!(k.send(b"de"), 0);
        assert_eq!(queued(&k.snd_queue), vec![(0, 3), (0, 2)]);
    }

    #[test]
    fn send_count_limit_is_255_segments() {
        let mss = 1376;
        let mut k = new_kcp();
        let data = payload(255 * mss, 1);
        assert_eq!(k.send(&data), 0);
        assert_eq!(k.snd_queue.len(), 255);
        let frgs: Vec<u8> = k.snd_queue.iter().map(|s| s.frg).collect();
        assert_eq!(frgs, (0..=254u8).rev().collect::<Vec<_>>());
        assert_eq!(concat(&k.snd_queue), data);

        let mut k = new_kcp();
        assert_eq!(k.send(&payload(255 * mss + 1, 1)), -2);
        assert_eq!(k.wait_snd(), 0);

        // Stream mode has the same limit.
        k.stream = 1;
        assert_eq!(k.send(&payload(255 * mss + 1, 1)), -2);
        assert_eq!(k.wait_snd(), 0);
        assert_eq!(k.send(&payload(255 * mss, 1)), 0);
        assert!(k.snd_queue.iter().all(|s| s.frg == 0));
        assert_eq!(k.snd_queue.len(), 255);
    }

    #[test]
    fn send_stream_mode_appends_into_last_segment() {
        let mss = 1376;
        let mut k = new_kcp();
        k.stream = 1;
        let a = payload(10, 1);
        let b = payload(20, 2);
        assert_eq!(k.send(&a), 0);
        // Fully absorbed by the last segment: no new segment.
        assert_eq!(k.send(&b), 0);
        assert_eq!(queued(&k.snd_queue), vec![(0, 30)]);

        // Fill the last segment up to mss, then continue in new segments with frg = 0.
        let c = payload(mss + 100, 3);
        assert_eq!(k.send(&c), 0);
        assert_eq!(queued(&k.snd_queue), vec![(0, mss), (0, 130)]);
        let mut all = a.clone();
        all.extend_from_slice(&b);
        all.extend_from_slice(&c);
        assert_eq!(concat(&k.snd_queue), all);

        // A full last segment is skipped.
        let mut k = new_kcp();
        k.stream = 1;
        assert_eq!(k.send(&payload(mss, 4)), 0);
        assert_eq!(k.send(b"z"), 0);
        assert_eq!(queued(&k.snd_queue), vec![(0, mss), (0, 1)]);
    }

    #[test]
    fn send_stream_mode_only_considers_the_last_segment() {
        let mut k = new_kcp();
        k.stream = 1;
        assert_eq!(k.set_mtu(50), 0); // mss 26
        assert_eq!(k.send(&payload(10, 1)), 0);
        assert_eq!(k.send(&payload(16, 2)), 0);
        assert_eq!(queued(&k.snd_queue), vec![(0, 26)]);
        assert_eq!(k.send(&payload(26, 3)), 0);
        assert_eq!(queued(&k.snd_queue), vec![(0, 26), (0, 26)]);
        // Both segments now have room, but only the last one is extended.
        assert_eq!(k.set_mtu(1400), 0);
        assert_eq!(k.send(&payload(4, 4)), 0);
        assert_eq!(queued(&k.snd_queue), vec![(0, 26), (0, 30)]);

        // A last segment larger than a (reduced) mss is not extended.
        assert_eq!(k.set_mtu(50), 0);
        assert_eq!(k.send(b"q"), 0);
        assert_eq!(queued(&k.snd_queue), vec![(0, 26), (0, 30), (0, 1)]);
    }

    #[test]
    fn send_stream_mode_keeps_partial_append_on_minus_two() {
        let mss = 1376;
        let mut k = new_kcp();
        k.stream = 1;
        assert_eq!(k.send(&payload(10, 1)), 0);
        // mss-10 bytes fill the last segment, the remaining 255*mss+1 need 256 segments.
        let big = payload(mss - 10 + 255 * mss + 1, 2);
        assert_eq!(k.send(&big), -2);
        assert_eq!(queued(&k.snd_queue), vec![(0, mss)]);
        assert_eq!(&concat(&k.snd_queue)[10..], &big[..mss - 10]);
    }

    // ---- PeekSize ----

    #[test]
    fn peek_size_branches() {
        let mut k = new_kcp();
        assert_eq!(k.peek_size(), -1, "empty");

        k.rcv_queue.push(seg(0, 0, payload(7, 0)));
        assert_eq!(k.peek_size(), 7, "frg 0");

        let mut k = new_kcp();
        k.rcv_queue.push(seg(0, 2, payload(5, 0)));
        k.rcv_queue.push(seg(1, 1, payload(6, 0)));
        assert_eq!(k.peek_size(), -1, "incomplete message");
        k.rcv_queue.push(seg(2, 0, payload(3, 0)));
        assert_eq!(k.peek_size(), 14, "complete message");
        // A following message is not counted.
        k.rcv_queue.push(seg(3, 1, payload(100, 0)));
        k.rcv_queue.push(seg(4, 0, payload(100, 0)));
        assert_eq!(k.peek_size(), 14);
    }

    #[test]
    fn peek_size_frg_255_wraps_like_go() {
        // Go computes int(seg.frg+1) in uint8: 255 + 1 == 0, so the completeness check never
        // fails and the sum runs to the first frg == 0 or the end of the queue.
        let mut k = new_kcp();
        k.rcv_queue.push(seg(0, 255, payload(4, 0)));
        assert_eq!(k.peek_size(), 4);
        k.rcv_queue.push(seg(1, 3, payload(5, 0)));
        assert_eq!(k.peek_size(), 9);
        k.rcv_queue.push(seg(2, 0, payload(6, 0)));
        k.rcv_queue.push(seg(3, 0, payload(50, 0)));
        assert_eq!(k.peek_size(), 15);

        let mut buf = [0u8; 15];
        assert_eq!(k.recv(&mut buf), 15);
        assert_eq!(k.rcv_queue.len(), 1);
    }

    // ---- Recv ----

    #[test]
    fn recv_empty_and_short_buffer() {
        let mut k = new_kcp();
        let mut buf = [0u8; 100];
        assert_eq!(k.recv(&mut buf), -1);

        k.rcv_queue.push(seg(0, 1, payload(60, 0)));
        assert_eq!(k.recv(&mut buf), -1, "incomplete message");
        k.rcv_queue.push(seg(1, 0, payload(41, 1)));
        assert_eq!(k.recv(&mut buf), -2, "101 > 100");
        assert_eq!(k.rcv_queue.len(), 2, "nothing consumed on -2");
        assert_eq!(k.probe, 0);

        let mut buf = [0u8; 101];
        assert_eq!(k.recv(&mut buf), 101);
        let mut want = payload(60, 0);
        want.extend_from_slice(&payload(41, 1));
        assert_eq!(&buf[..], &want[..]);
        assert!(k.rcv_queue.is_empty());
        assert_eq!(k.recv(&mut buf), -1);
    }

    #[test]
    fn recv_reads_one_message_at_a_time() {
        let mut k = new_kcp();
        k.rcv_queue.push(seg(0, 0, payload(3, 1)));
        k.rcv_queue.push(seg(1, 1, payload(4, 2)));
        k.rcv_queue.push(seg(2, 0, payload(5, 3)));
        let mut buf = [0xEEu8; 64];
        assert_eq!(k.recv(&mut buf), 3);
        assert_eq!(&buf[..3], &payload(3, 1)[..]);
        assert_eq!(buf[3], 0xEE, "no write past the message");
        assert_eq!(k.recv(&mut buf), 9);
        let mut want = payload(4, 2);
        want.extend_from_slice(&payload(5, 3));
        assert_eq!(&buf[..9], &want[..]);
        assert_eq!(k.recv(&mut buf), -1);
    }

    #[test]
    fn recv_zero_length_segment() {
        let mut k = new_kcp();
        k.rcv_queue.push(seg(0, 0, Vec::new()));
        let mut buf = [0u8; 0];
        assert_eq!(k.peek_size(), 0);
        assert_eq!(k.recv(&mut buf), 0);
        assert!(k.rcv_queue.is_empty());
    }

    #[test]
    fn recv_moves_in_order_segments_from_rcv_buf() {
        let mut k = new_kcp();
        assert_eq!(k.wnd_size(0, 4), 0);
        k.rcv_nxt = 10;
        k.rcv_queue.push(seg(8, 0, payload(1, 8)));
        k.rcv_queue.push(seg(9, 0, payload(1, 9)));
        for sn in [13, 11, 10] {
            k.rcv_buf.push(seg(sn, 0, payload(1, sn as u8)));
        }
        let mut buf = [0u8; 8];
        assert_eq!(k.recv(&mut buf), 1);
        assert_eq!(buf[0], 8);
        let sns: Vec<u32> = k.rcv_queue.iter().map(|s| s.sn).collect();
        assert_eq!(sns, vec![9, 10, 11]);
        assert_eq!(k.rcv_nxt, 12);
        assert_eq!(k.rcv_buf.len(), 1);
        assert!(k.rcv_buf.has(13), "out-of-order segment pushed back");
        assert_eq!(k.probe, 0, "queue was below rcv_wnd: no fast recover");
    }

    #[test]
    fn recv_move_stops_at_rcv_wnd() {
        let mut k = new_kcp();
        assert_eq!(k.wnd_size(0, 2), 0);
        k.rcv_nxt = 10;
        k.rcv_queue.push(seg(8, 0, payload(1, 8)));
        k.rcv_queue.push(seg(9, 0, payload(1, 9)));
        k.rcv_buf.push(seg(10, 0, payload(1, 10)));
        k.rcv_buf.push(seg(11, 0, payload(1, 11)));
        let mut buf = [0u8; 8];
        assert_eq!(k.recv(&mut buf), 1);
        let sns: Vec<u32> = k.rcv_queue.iter().map(|s| s.sn).collect();
        assert_eq!(sns, vec![9, 10]);
        assert_eq!(k.rcv_nxt, 11);
        assert!(k.rcv_buf.has(11) && k.rcv_buf.len() == 1);
        // The queue was full before and is full again: no window update needed.
        assert_eq!(k.probe, 0);
    }

    #[test]
    fn recv_move_wraps_rcv_nxt() {
        let mut k = new_kcp();
        k.rcv_nxt = u32::MAX;
        k.rcv_queue.push(seg(u32::MAX - 1, 0, payload(2, 0)));
        k.rcv_buf.push(seg(0, 0, payload(1, 0)));
        k.rcv_buf.push(seg(u32::MAX, 0, payload(1, 0)));
        let mut buf = [0u8; 2];
        assert_eq!(k.recv(&mut buf), 2);
        let sns: Vec<u32> = k.rcv_queue.iter().map(|s| s.sn).collect();
        assert_eq!(sns, vec![u32::MAX, 0]);
        assert_eq!(k.rcv_nxt, 1);
        assert!(k.rcv_buf.is_empty());
    }

    #[test]
    fn recv_fast_recover_sets_ask_tell() {
        let mut k = new_kcp();
        assert_eq!(k.wnd_size(0, 2), 0);
        k.probe = IKCP_ASK_SEND;
        k.rcv_queue.push(seg(0, 0, payload(1, 0)));
        k.rcv_queue.push(seg(1, 0, payload(1, 1)));
        assert_eq!(k.wnd_unused(), 0);
        let mut buf = [0u8; 1];
        assert_eq!(k.recv(&mut buf), 1);
        assert_eq!(k.probe, IKCP_ASK_SEND | IKCP_ASK_TELL);
        assert_eq!(k.wnd_unused(), 1);

        // Queue not full before the read: no fast recover.
        let mut k = new_kcp();
        assert_eq!(k.wnd_size(0, 3), 0);
        k.rcv_queue.push(seg(0, 0, payload(1, 0)));
        k.rcv_queue.push(seg(1, 0, payload(1, 1)));
        assert_eq!(k.recv(&mut buf), 1);
        assert_eq!(k.probe, 0);

        // Over-full queue (rcv_wnd lowered afterwards) that stays full: no probe.
        let mut k = new_kcp();
        for sn in 0..4 {
            k.rcv_queue.push(seg(sn, 0, payload(1, 0)));
        }
        assert_eq!(k.wnd_size(0, 2), 0);
        assert_eq!(k.recv(&mut buf), 1);
        assert_eq!(k.rcv_queue.len(), 3);
        assert_eq!(k.probe, 0);
        // -1/-2 returns never touch the probe.
        let mut k = new_kcp();
        assert_eq!(k.wnd_size(0, 1), 0);
        k.rcv_queue.push(seg(0, 0, payload(5, 0)));
        assert_eq!(k.recv(&mut buf), -2);
        assert_eq!(k.probe, 0);
    }

    #[test]
    fn send_then_recv_round_trip_message_and_stream() {
        for stream in [0, 1] {
            let mut tx = new_kcp();
            let mut rx = new_kcp();
            tx.stream = stream;
            rx.stream = stream;
            let msgs = [payload(3000, 1), payload(1, 2), payload(1376, 3)];
            for m in &msgs {
                assert_eq!(tx.send(m), 0);
            }
            // Deliver the queued segments in order, as flush()/input() will.
            while let Some(s) = tx.snd_queue.pop() {
                rx.rcv_queue.push(s);
            }
            let mut got = Vec::new();
            let mut reads = 0;
            let mut buf = vec![0u8; 4096];
            loop {
                let n = rx.recv(&mut buf);
                if n < 0 {
                    assert_eq!(n, -1);
                    break;
                }
                got.extend_from_slice(&buf[..n as usize]);
                reads += 1;
            }
            assert_eq!(got, msgs.concat(), "stream {stream}");
            if stream == 0 {
                assert_eq!(reads, 3, "message boundaries kept");
            } else {
                // 3000 + 1 + 1376 bytes packed into mss-sized segments, one per read.
                assert_eq!(reads, 4376usize.div_ceil(1376));
            }
        }
    }

    // ---- wnd_unused / WaitSnd ----

    #[test]
    fn wnd_unused_branches() {
        let mut k = new_kcp();
        assert_eq!(k.wnd_unused(), 32);
        for sn in 0..5 {
            k.rcv_queue.push(seg(sn, 0, Vec::new()));
        }
        assert_eq!(k.wnd_unused(), 27);
        assert_eq!(k.wnd_size(0, 5), 0);
        assert_eq!(k.wnd_unused(), 0, "queue == rcv_wnd");
        assert_eq!(k.wnd_size(0, 3), 0);
        assert_eq!(k.wnd_unused(), 0, "queue > rcv_wnd");
        // uint16 truncation of large windows, as in Go.
        let mut k = new_kcp();
        assert_eq!(k.wnd_size(0, 70000), 0);
        assert_eq!(k.wnd_unused(), (70000u32 as u16));
    }

    #[test]
    fn wait_snd_counts_queue_and_buffer() {
        let mut k = new_kcp();
        assert_eq!(k.send(&payload(3 * 1376, 0)), 0);
        assert_eq!(k.wait_snd(), 3);
        let s = k.snd_queue.pop().expect("queued");
        k.snd_buf.push(s);
        assert_eq!(k.wait_snd(), 3);
        k.snd_buf.push(seg(9, 0, Vec::new()));
        assert_eq!(k.wait_snd(), 4);
    }

    // ---- SetMtu / NoDelay / WndSize ----

    #[test]
    fn set_mtu_bounds_and_buffer() {
        let mut k = new_kcp();
        for bad in [isize::MIN, -1, 0, 23, 24, 49] {
            assert_eq!(k.set_mtu(bad), -1, "mtu {bad}");
            assert_eq!((k.mtu, k.mss, k.buffer.len()), (1400, 1376, 4272));
        }
        assert_eq!(k.set_mtu(50), 0);
        assert_eq!((k.mtu, k.mss, k.buffer.len()), (50, 26, 222));
        assert_eq!(k.set_mtu(1500), 0);
        assert_eq!((k.mtu, k.mss, k.buffer.len()), (1500, 1476, 4572));
        assert!(k.buffer.iter().all(|&b| b == 0));
        // mss follows the new mtu for fragmentation.
        assert_eq!(k.set_mtu(100), 0);
        assert_eq!(k.send(&payload(77, 0)), 0);
        assert_eq!(queued(&k.snd_queue), vec![(1, 76), (0, 1)]);
    }

    // Go: kcp-go@v5.6.72 kcp_test.go:TestSetMtuBoundary, adapted to the pinned rule. v5.6.72
    // rejects only `mtu <= IKCP_OVERHEAD` (so 25 is its minimum valid MTU, mss 1); the pinned
    // v5.6.66 rejects `mtu < 50 || mtu < IKCP_OVERHEAD`, which DECISIONS V01 keeps. The cases
    // between 25 and 49 therefore expect -1 here.
    #[test]
    fn test_set_mtu_boundary() {
        let mut k = new_kcp();
        let tests: [(&str, isize, isize); 9] = [
            ("negative", -1, -1),
            ("zero", 0, -1),
            ("below overhead", IKCP_OVERHEAD as isize - 1, -1),
            ("equal overhead", IKCP_OVERHEAD as isize, -1),
            (
                "one above overhead (valid in v5.6.72 only)",
                IKCP_OVERHEAD as isize + 1,
                -1,
            ),
            ("just below the pinned minimum", 49, -1),
            ("pinned minimum", 50, 0),
            ("typical MTU", 1400, 0),
            ("mtuLimit", 1500, 0),
        ];
        for (name, mtu, want) in tests {
            assert_eq!(k.set_mtu(mtu), want, "{name}: set_mtu({mtu})");
        }

        // mss is derived from a valid mtu.
        assert_eq!(k.set_mtu(1400), 0);
        assert_eq!(k.mss, 1400 - IKCP_OVERHEAD);

        // The minimum valid MTU (50) yields mss 26.
        assert_eq!(k.set_mtu(50), 0);
        assert_eq!(k.mss, 26);

        // A rejected mtu leaves mtu and mss unchanged.
        assert_eq!(k.set_mtu(IKCP_OVERHEAD as isize + 1), -1);
        assert_eq!((k.mtu, k.mss), (50, 26));
    }

    #[test]
    fn nodelay_sets_and_clamps() {
        let mut k = new_kcp();
        assert_eq!(k.nodelay(1, 20, 2, 1), 0);
        assert_eq!((k.nodelay, k.rx_minrto, k.interval), (1, IKCP_RTO_NDL, 20));
        assert_eq!((k.fastresend, k.nocwnd), (2, 1));

        // Negative arguments leave everything unchanged.
        assert_eq!(k.nodelay(-1, -1, -1, -1), 0);
        assert_eq!((k.nodelay, k.rx_minrto, k.interval), (1, IKCP_RTO_NDL, 20));
        assert_eq!((k.fastresend, k.nocwnd), (2, 1));

        assert_eq!(k.nodelay(0, 40, 0, 0), 0);
        assert_eq!((k.nodelay, k.rx_minrto, k.interval), (0, IKCP_RTO_MIN, 40));
        assert_eq!((k.fastresend, k.nocwnd), (0, 0));

        // Any non-zero nodelay selects the no-delay minimum RTO and is stored as is.
        assert_eq!(k.nodelay(2, -1, -1, -1), 0);
        assert_eq!((k.nodelay, k.rx_minrto), (2, IKCP_RTO_NDL));

        for (interval, want) in [
            (0, 10),
            (9, 10),
            (10, 10),
            (11, 11),
            (5000, 5000),
            (5001, 5000),
        ] {
            assert_eq!(k.nodelay(-1, interval, -1, -1), 0);
            assert_eq!(k.interval, want, "interval {interval}");
        }
        assert_eq!((k.nodelay, k.rx_minrto), (2, IKCP_RTO_NDL));
    }

    #[test]
    fn wnd_size_only_positive() {
        let mut k = new_kcp();
        assert_eq!(k.wnd_size(128, 256), 0);
        assert_eq!((k.snd_wnd, k.rcv_wnd), (128, 256));
        assert_eq!(k.wnd_size(0, -5), 0);
        assert_eq!((k.snd_wnd, k.rcv_wnd), (128, 256));
        assert_eq!(k.wnd_size(-1, 1), 0);
        assert_eq!((k.snd_wnd, k.rcv_wnd), (128, 1));
        assert_eq!(k.wnd_size(1, 0), 0);
        assert_eq!((k.snd_wnd, k.rcv_wnd), (1, 1));
        // rmt_wnd is the peer's window and is not touched.
        assert_eq!(k.rmt_wnd, IKCP_WND_RCV);
    }

    // ---- SetLogger ----

    #[test]
    fn set_logger_mask() {
        let mut k = new_kcp();
        k.set_logger(IKCP_LOG_ALL, Some(Box::new(|_, _| {})));
        assert_eq!(k.logmask, IKCP_LOG_ALL);
        assert!(k.log.is_some());
        k.set_logger(IKCP_LOG_ALL, None);
        assert_eq!(k.logmask, 0);
    }

    #[cfg(feature = "trace")]
    #[test]
    fn trace_logger_receives_send_and_recv_events() {
        use std::sync::{Arc, Mutex};
        let events: Arc<Mutex<Vec<String>>> = Arc::default();
        let mut k = new_kcp();
        let sink = Arc::clone(&events);
        k.set_logger(
            IKCP_LOG_SEND | IKCP_LOG_RECV,
            Some(Box::new(move |msg, args| {
                let kv: Vec<String> = args.iter().map(|(k, v)| format!("{k}={v:?}")).collect();
                sink.lock()
                    .expect("lock")
                    .push(format!("{msg} {}", kv.join(" ")));
            })),
        );
        assert_eq!(k.send(b"hello"), 0);
        k.rcv_queue.push(seg(5, 0, b"hi".to_vec()));
        let mut buf = [0u8; 8];
        assert_eq!(k.recv(&mut buf), 2);
        assert_eq!(
            *events.lock().expect("lock"),
            vec![
                "[KCP SEND] stream=0 conv=305419896 datalen=5".to_string(),
                "[KCP RECV] stream=0 conv=305419896 sn=5 ts=0 datalen=2".to_string(),
            ]
        );
        // Events outside the mask are dropped.
        k.set_logger(IKCP_LOG_INPUT, Some(Box::new(|_, _| panic!("masked"))));
        assert_eq!(k.send(b"x"), 0);
    }

    /// `shrink_idle_buffers` gives back what a burst grew and nothing that is still in use, and
    /// the KCP keeps working afterwards (plan 12.3).
    #[test]
    fn shrink_idle_buffers_returns_what_a_burst_grew() {
        let mut k = new_kcp();
        k.wnd_size(8192, 8192);
        k.set_mtu(1390);

        // A fresh KCP has nothing to give back.
        assert!(!k.shrink_idle_buffers());
        let fresh_snd_queue = k.snd_queue.max_len();
        let fresh_rcv_queue = k.rcv_queue.max_len();
        let fresh_snd_buf = k.snd_buf.max_len();

        // Queue far more than the starting rings hold, and receive an out-of-order burst so that
        // `rcv_buf` grows too. `rcv_buf` keeps the segments (nothing is in order), which is why
        // it is drained explicitly below.
        for i in 0..4000u32 {
            k.send(&payload(1000, i as u8));
        }
        for sn in (1..2000u32).rev() {
            let data = payload(8, sn as u8);
            k.parse_data(seg(sn, 0, data.clone()), &data);
        }
        assert!(k.snd_queue.max_len() > fresh_snd_queue);
        assert!(k.rcv_buf.capacity() > 0);

        // Still busy: the queues hold data, so nothing is given back.
        assert!(!k.shrink_idle_buffers());
        assert!(k.snd_queue.max_len() > fresh_snd_queue);

        // Drain everything, as an acknowledged and fully read session would.
        k.snd_queue.clear();
        k.snd_buf.clear();
        k.rcv_queue.clear();
        while k.rcv_buf.pop().is_some() {}
        k.acklist.clear();

        assert!(k.shrink_idle_buffers());
        assert_eq!(k.snd_queue.max_len(), fresh_snd_queue);
        assert_eq!(k.rcv_queue.max_len(), fresh_rcv_queue);
        assert_eq!(k.snd_buf.max_len(), fresh_snd_buf);
        assert_eq!(k.rcv_buf.capacity(), 0);

        // Idempotent, and the state machine is unharmed.
        assert!(!k.shrink_idle_buffers());
        assert_eq!(k.send(&payload(2000, 9)), 0);
        assert_eq!(k.wait_snd(), 2);
        assert!(k.flush(IKCP_FLUSH_FULL) > 0);
    }
}

/// Tests for `input()` and its helpers (`update_ack`, `shrink_buf`, `parse_ack`,
/// `parse_fastack`, `parse_una`, `ack_push`, `parse_data`).
///
/// The tests inspect the state and the recorded [`FlushCall`]s. Where a flush is triggered,
/// the state `flush()` changes (the ACK list, `fastack`) is checked in the recorded call rather
/// than afterwards, and sent segments get a far `resendts` so flush does not retransmit them.
/// (Written while `flush()` was still a placeholder; the port of `input()` was checked against
/// the pinned Go code on a 2400-step random trace with the same placeholder flush: identical
/// state after every step.)
#[cfg(test)]
mod input_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU32;
    use std::sync::{RwLockReadGuard, RwLockWriteGuard};

    const CONV: u32 = 0x0A0B_0C0D;
    const MSS: u32 = 1376;

    #[derive(Clone, Default)]
    struct TestClock(Arc<AtomicU32>);

    impl TestClock {
        fn set(&self, ms: u32) {
            self.0.store(ms, Ordering::Relaxed);
        }
    }

    impl Clock for TestClock {
        fn now_ms(&self) -> u32 {
            self.0.load(Ordering::Relaxed)
        }
    }

    type TestKcp = Kcp<fn(&[u8]), TestClock>;

    fn discard(_: &[u8]) {}

    fn new_kcp() -> (TestKcp, TestClock) {
        let clock = TestClock::default();
        let k = Kcp::with_clock(CONV, discard as fn(&[u8]), clock.clone());
        (k, clock)
    }

    fn snmp_read() -> RwLockReadGuard<'static, ()> {
        SNMP_TEST_LOCK.read().unwrap_or_else(|e| e.into_inner())
    }

    fn snmp_write() -> RwLockWriteGuard<'static, ()> {
        SNMP_TEST_LOCK.write().unwrap_or_else(|e| e.into_inner())
    }

    fn input(k: &mut TestKcp, pkt: &[u8], pkt_type: PacketType, ack_no_delay: bool) -> isize {
        let _g = snmp_read();
        k.input(pkt, pkt_type, ack_no_delay)
    }

    /// Regular packet, no ack-no-delay.
    fn input_reg(k: &mut TestKcp, pkt: &[u8]) -> isize {
        input(k, pkt, IKCP_PACKET_REGULAR, false)
    }

    /// A segment header to encode (payload passed to `enc`).
    #[derive(Clone, Copy)]
    struct H {
        conv: u32,
        cmd: u8,
        frg: u8,
        wnd: u16,
        ts: u32,
        sn: u32,
        una: u32,
    }

    /// Defaults: our conv, WINS, wnd 32, everything else 0.
    fn h() -> H {
        H {
            conv: CONV,
            cmd: IKCP_CMD_WINS,
            frg: 0,
            wnd: 32,
            ts: 0,
            sn: 0,
            una: 0,
        }
    }

    impl H {
        fn enc(self, data: &[u8]) -> Vec<u8> {
            self.enc_len(data, data.len() as u32)
        }

        /// Encodes with an explicit `len` field (which may lie about the payload).
        fn enc_len(self, data: &[u8], len: u32) -> Vec<u8> {
            let mut b = Vec::with_capacity(24 + data.len());
            b.extend_from_slice(&self.conv.to_le_bytes());
            b.push(self.cmd);
            b.push(self.frg);
            b.extend_from_slice(&self.wnd.to_le_bytes());
            b.extend_from_slice(&self.ts.to_le_bytes());
            b.extend_from_slice(&self.sn.to_le_bytes());
            b.extend_from_slice(&self.una.to_le_bytes());
            b.extend_from_slice(&len.to_le_bytes());
            b.extend_from_slice(data);
            b
        }
    }

    fn ack(sn: u32, ts: u32, una: u32) -> Vec<u8> {
        H {
            cmd: IKCP_CMD_ACK,
            sn,
            ts,
            una,
            ..h()
        }
        .enc(&[])
    }

    fn push(sn: u32, ts: u32, data: &[u8]) -> Vec<u8> {
        H {
            cmd: IKCP_CMD_PUSH,
            sn,
            ts,
            ..h()
        }
        .enc(data)
    }

    /// Puts `n` sent segments (sn = snd_nxt.., ts = ts0 + i, 10-byte payload, xmit 1, far
    /// resendts) into `snd_buf`, as flush() would.
    fn sent(k: &mut TestKcp, n: u32, ts0: u32) {
        for i in 0..n {
            let mut data = k.new_segment(10).data;
            data.fill(i as u8);
            k.snd_buf.push(Segment {
                conv: CONV,
                cmd: IKCP_CMD_PUSH,
                sn: k.snd_nxt,
                ts: ts0.wrapping_add(i),
                xmit: 1,
                rto: 200,
                resendts: 0x7FFF_FFFF,
                data,
                ..Segment::default()
            });
            k.snd_nxt = k.snd_nxt.wrapping_add(1);
        }
    }

    fn snd_sns(k: &TestKcp) -> Vec<u32> {
        k.snd_buf.iter().map(|s| s.sn).collect()
    }

    fn fastacks(k: &TestKcp) -> Vec<u32> {
        k.snd_buf.iter().map(|s| s.fastack).collect()
    }

    fn rcv_queue_sns(k: &TestKcp) -> Vec<u32> {
        k.rcv_queue.iter().map(|s| s.sn).collect()
    }

    fn rcv_buf_sns(k: &TestKcp) -> Vec<u32> {
        let mut v: Vec<u32> = k.rcv_buf.segments().iter().map(|s| s.sn).collect();
        v.sort_unstable();
        v
    }

    fn flush_types(k: &TestKcp) -> Vec<FlushType> {
        k.flush_calls.iter().map(|c| c.flush_type).collect()
    }

    fn acks(items: &[(u32, u32)]) -> Vec<AckItem> {
        items.iter().map(|&(sn, ts)| AckItem { sn, ts }).collect()
    }

    // ---- early returns ----

    #[test]
    fn input_short_packet_returns_minus_one() {
        let (mut k, _) = new_kcp();
        for len in [0, 1, 23] {
            let pkt = h().enc(&[]);
            assert_eq!(input_reg(&mut k, &pkt[..len]), -1, "len {len}");
        }
        assert_eq!(k.rmt_wnd, IKCP_WND_RCV);
        assert!(k.flush_calls.is_empty());
        // Exactly one header is enough.
        assert_eq!(input_reg(&mut k, &h().enc(&[])), 0);
    }

    #[test]
    fn input_conv_mismatch_returns_minus_one_after_processing_earlier_segments() {
        let (mut k, clock) = new_kcp();
        clock.set(1000);
        sent(&mut k, 3, 900);
        let mut pkt = H {
            cmd: IKCP_CMD_WASK,
            una: 1,
            wnd: 7,
            ..h()
        }
        .enc(&[]);
        pkt.extend(ack(1, 950, 1));
        pkt.extend(
            H {
                conv: CONV + 1,
                ..h()
            }
            .enc(&[]),
        );
        pkt.extend(push(0, 1, b"x"));
        assert_eq!(input(&mut k, &pkt, IKCP_PACKET_REGULAR, true), -1);
        // The segments before the bad one took effect ...
        assert_eq!(k.probe, IKCP_ASK_TELL);
        assert_eq!(k.rmt_wnd, 32, "wnd of the ACK (2nd segment)");
        assert_eq!(snd_sns(&k), vec![1, 2]);
        assert_eq!(k.snd_una, 1);
        assert_eq!(k.snd_buf.peek().map(|s| s.acked), Some(1));
        // ... but nothing after the loop runs: no RTT, no cwnd growth, no flush.
        assert_eq!((k.rx_srtt, k.rx_rto), (0, IKCP_RTO_DEF));
        assert_eq!(k.cwnd, 0);
        assert!(k.flush_calls.is_empty());
        // The segment after the bad one was not processed.
        assert!(k.rcv_queue.is_empty() && k.acklist.is_empty());

        // A mismatch in the first segment changes nothing.
        let (mut k, _) = new_kcp();
        let bad = H {
            conv: 0,
            cmd: IKCP_CMD_WASK,
            wnd: 3,
            ..h()
        }
        .enc(&[]);
        assert_eq!(input_reg(&mut k, &bad), -1);
        assert_eq!((k.probe, k.rmt_wnd), (0, 32));
    }

    #[test]
    fn input_truncated_payload_returns_minus_two() {
        let (mut k, _) = new_kcp();
        let mut pkt = H { wnd: 9, ..h() }.enc(&[]);
        pkt.extend(
            H {
                cmd: IKCP_CMD_PUSH,
                wnd: 1,
                ..h()
            }
            .enc_len(b"abcd", 5),
        );
        assert_eq!(input_reg(&mut k, &pkt), -2);
        assert_eq!(k.rmt_wnd, 9, "the truncated segment's wnd is not applied");
        assert!(k.rcv_queue.is_empty() && k.acklist.is_empty());

        // A huge length (u32::MAX) is just truncated, no overflow.
        let pkt = H {
            cmd: IKCP_CMD_PUSH,
            ..h()
        }
        .enc_len(b"abcd", u32::MAX);
        assert_eq!(input_reg(&mut k, &pkt), -2);
        // Exact length is fine.
        let pkt = H {
            cmd: IKCP_CMD_PUSH,
            ..h()
        }
        .enc_len(b"abcd", 4);
        assert_eq!(input_reg(&mut k, &pkt), 0);
        assert_eq!(k.rcv_queue.len(), 1);
    }

    #[test]
    fn input_unknown_cmd_returns_minus_three_before_touching_state() {
        for cmd in [0u8, 80, 85, 255] {
            let (mut k, _) = new_kcp();
            sent(&mut k, 2, 0);
            let pkt = H {
                cmd,
                wnd: 5,
                una: 2,
                ..h()
            }
            .enc(&[]);
            assert_eq!(input_reg(&mut k, &pkt), -3, "cmd {cmd}");
            assert_eq!(k.rmt_wnd, 32, "cmd {cmd}: rmt_wnd untouched");
            assert_eq!(snd_sns(&k), vec![0, 1], "cmd {cmd}: una not parsed");
            assert!(k.flush_calls.is_empty());
        }
    }

    #[test]
    fn input_ignores_trailing_bytes_shorter_than_a_header() {
        let (mut k, _) = new_kcp();
        let mut pkt = H {
            cmd: IKCP_CMD_WASK,
            ..h()
        }
        .enc(&[]);
        pkt.extend_from_slice(&[0xFF; 23]);
        assert_eq!(input_reg(&mut k, &pkt), 0);
        assert_eq!(k.probe, IKCP_ASK_TELL);
    }

    #[test]
    fn input_counters_in_segs_and_repeat_segs() {
        let _g = snmp_write();
        let in0 = DEFAULT_SNMP.in_segs.load(Ordering::Relaxed);
        let rep0 = DEFAULT_SNMP.repeat_segs.load(Ordering::Relaxed);
        let delta = || {
            (
                DEFAULT_SNMP.in_segs.load(Ordering::Relaxed) - in0,
                DEFAULT_SNMP.repeat_segs.load(Ordering::Relaxed) - rep0,
            )
        };
        let (mut k, _) = new_kcp();
        k.rcv_nxt = 10;

        // 4 segments: new data, WASK, duplicate (old sn), out of window.
        let mut pkt = push(10, 0, b"a");
        pkt.extend(
            H {
                cmd: IKCP_CMD_WASK,
                ..h()
            }
            .enc(&[]),
        );
        pkt.extend(push(9, 0, b"b"));
        pkt.extend(push(11 + 32, 0, b"c")); // rcv_nxt is 11 by then
        assert_eq!(k.input(&pkt, IKCP_PACKET_REGULAR, false), 0);
        assert_eq!(delta(), (4, 2));

        // Out-of-order data, then a duplicate held in rcv_buf.
        assert_eq!(k.input(&push(13, 0, b"d"), IKCP_PACKET_REGULAR, false), 0);
        assert_eq!(k.input(&push(13, 0, b"d"), IKCP_PACKET_REGULAR, false), 0);
        assert_eq!(delta(), (6, 3));

        // FEC-recovered repeats count as input segments but not as repeats.
        assert_eq!(k.input(&push(13, 0, b"d"), IKCP_PACKET_FEC, false), 0);
        assert_eq!(k.input(&push(1, 0, b"e"), IKCP_PACKET_FEC, false), 0);
        assert_eq!(delta(), (8, 3));

        // Error returns skip InSegs entirely (even for the good segments before), but a
        // repeat before the error is already counted.
        let mut pkt = push(9, 0, b"f");
        pkt.extend(H { cmd: 99, ..h() }.enc(&[]));
        assert_eq!(k.input(&pkt, IKCP_PACKET_REGULAR, false), -3);
        assert_eq!(delta(), (8, 4));
        assert_eq!(k.input(&[0u8; 10], IKCP_PACKET_REGULAR, false), -1);
        assert_eq!(delta(), (8, 4));
    }

    // ---- rmt_wnd, una, shrink_buf ----

    #[test]
    fn input_rmt_wnd_only_from_regular_packets_last_segment_wins() {
        let (mut k, _) = new_kcp();
        let mut pkt = H { wnd: 100, ..h() }.enc(&[]);
        pkt.extend(H { wnd: 7, ..h() }.enc(&[]));
        assert_eq!(input_reg(&mut k, &pkt), 0);
        assert_eq!(k.rmt_wnd, 7);

        assert_eq!(
            input(
                &mut k,
                &H { wnd: 50, ..h() }.enc(&[]),
                IKCP_PACKET_FEC,
                false
            ),
            0
        );
        assert_eq!(k.rmt_wnd, 7, "FEC packets do not update rmt_wnd");

        // Every command carries the window, even out-of-window data and zero.
        let pkt = H {
            cmd: IKCP_CMD_PUSH,
            sn: 1000,
            wnd: 0,
            ..h()
        }
        .enc(b"z");
        assert_eq!(input_reg(&mut k, &pkt), 0);
        assert_eq!(k.rmt_wnd, 0);
        let pkt = H {
            wnd: u16::MAX,
            ..h()
        }
        .enc(&[]);
        assert_eq!(input_reg(&mut k, &pkt), 0);
        assert_eq!(k.rmt_wnd, 65535);
    }

    #[test]
    fn parse_una_removes_segments_before_una() {
        let (mut k, _) = new_kcp();
        sent(&mut k, 5, 0);
        assert_eq!(k.parse_una(0), 0);
        assert_eq!(k.parse_una(3), 3);
        assert_eq!(snd_sns(&k), vec![3, 4]);
        assert_eq!(k.snd_una, 0, "parse_una does not move snd_una");
        k.shrink_buf();
        assert_eq!(k.snd_una, 3);
        // An una past snd_nxt removes everything (and stops there).
        assert_eq!(k.parse_una(100), 2);
        assert!(k.snd_buf.is_empty());
        k.shrink_buf();
        assert_eq!(k.snd_una, 5, "empty snd_buf: snd_una = snd_nxt");
        assert_eq!(k.parse_una(200), 0);
    }

    #[test]
    fn parse_una_wraps() {
        let (mut k, _) = new_kcp();
        k.snd_una = u32::MAX - 1;
        k.snd_nxt = u32::MAX - 1;
        sent(&mut k, 4, 0); // sn MAX-1, MAX, 0, 1
        assert_eq!(snd_sns(&k), vec![u32::MAX - 1, u32::MAX, 0, 1]);
        assert_eq!(k.parse_una(u32::MAX - 1), 0);
        assert_eq!(k.parse_una(1), 3);
        k.shrink_buf();
        assert_eq!(k.snd_una, 1);
    }

    #[test]
    fn input_una_advance_triggers_full_flush() {
        let (mut k, _) = new_kcp();
        sent(&mut k, 4, 0);
        // una is processed for every command, here a WINS.
        let pkt = H { una: 2, ..h() }.enc(&[]);
        assert_eq!(input_reg(&mut k, &pkt), 0);
        assert_eq!(snd_sns(&k), vec![2, 3]);
        assert_eq!(k.snd_una, 2);
        assert_eq!(flush_types(&k), vec![IKCP_FLUSH_FULL]);

        // una not advancing: no flush.
        assert_eq!(input_reg(&mut k, &H { una: 2, ..h() }.enc(&[])), 0);
        assert_eq!(input_reg(&mut k, &H { una: 1, ..h() }.enc(&[])), 0);
        assert_eq!(k.flush_calls.len(), 1);
        assert_eq!(k.snd_una, 2);

        // FEC packets process una as well.
        assert_eq!(
            input(
                &mut k,
                &H { una: 3, ..h() }.enc(&[]),
                IKCP_PACKET_FEC,
                false
            ),
            0
        );
        assert_eq!(snd_sns(&k), vec![3]);
        assert_eq!(flush_types(&k), vec![IKCP_FLUSH_FULL; 2]);
    }

    #[test]
    fn input_shrink_buf_on_empty_snd_buf_moves_snd_una_without_flush() {
        // A stale snd_una with an empty snd_buf is pulled up to snd_nxt by any packet; the
        // cwnd grows but nothing was removed, so there is no flush (as in Go).
        let (mut k, _) = new_kcp();
        k.snd_nxt = 3;
        assert_eq!(input_reg(&mut k, &h().enc(&[])), 0);
        assert_eq!(k.snd_una, 3);
        assert_eq!((k.cwnd, k.incr), (1, MSS));
        assert!(k.flush_calls.is_empty());
    }

    // ---- ACK: parse_ack / parse_fastack / RTT ----

    #[test]
    fn parse_ack_marks_and_frees_but_keeps_segment() {
        let (mut k, _) = new_kcp();
        sent(&mut k, 4, 0);
        k.parse_ack(2);
        let s = k.snd_buf.iter().nth(2).expect("segment 2");
        assert_eq!((s.sn, s.acked), (2, 1));
        assert!(
            s.data.is_empty() && s.data.capacity() == 0,
            "payload recycled"
        );
        assert_eq!(snd_sns(&k), vec![0, 1, 2, 3]);
        let acked: Vec<u32> = k.snd_buf.iter().map(|s| s.acked).collect();
        assert_eq!(acked, vec![0, 0, 1, 0]);

        // Out of [snd_una, snd_nxt): ignored.
        k.snd_una = 1;
        k.parse_ack(0);
        k.parse_ack(4);
        k.parse_ack(u32::MAX);
        assert_eq!(
            k.snd_buf.peek().map(|s| (s.acked, s.data.len())),
            Some((0, 10))
        );

        // In range but not present (the scan stops at the first larger sn).
        let (mut k, _) = new_kcp();
        sent(&mut k, 4, 0);
        let _ = k.parse_una(1); // remove sn 0; snd_una stays 0
        k.snd_buf.iter_mut().for_each(|s| s.sn += 1); // sn 2, 3, 4: sn 1 missing
        k.parse_ack(1);
        assert!(k.snd_buf.iter().all(|s| s.acked == 0));
    }

    #[test]
    fn parse_fastack_counts_earlier_segments_sent_no_later_than_ts() {
        let (mut k, _) = new_kcp();
        k.fastresend = 2;
        sent(&mut k, 5, 100); // ts 100..=104
        assert_eq!(k.parse_fastack(3, 103), 0);
        assert_eq!(fastacks(&k), vec![1, 1, 1, 0, 0]);
        assert_eq!(k.parse_fastack(3, 103), 1, "threshold 2 reached");
        assert_eq!(fastacks(&k), vec![2, 2, 2, 0, 0]);

        // Only segments with ts <= the ACK's ts (wrapping) are counted.
        let (mut k, _) = new_kcp();
        k.fastresend = 2;
        sent(&mut k, 5, u32::MAX - 1); // ts MAX-1, MAX, 0, 1, 2
        assert_eq!(k.parse_fastack(4, u32::MAX), 0);
        assert_eq!(fastacks(&k), vec![1, 1, 0, 0, 0]);

        // The sentinel 0xFFFFFFFF (already fast-retransmitted) is left alone.
        let (mut k, _) = new_kcp();
        k.fastresend = 1;
        sent(&mut k, 3, 0);
        k.snd_buf.iter_mut().next().expect("seg").fastack = 0xFFFF_FFFF;
        assert_eq!(k.parse_fastack(2, 10), 1, "sn 1 reached 1");
        assert_eq!(fastacks(&k), vec![0xFFFF_FFFF, 1, 0]);
        k.snd_buf.iter_mut().nth(1).expect("seg").fastack = 0xFFFF_FFFF;
        assert_eq!(k.parse_fastack(2, 10), 0, "nothing counted");

        // Out of [snd_una, snd_nxt): nothing.
        let (mut k, _) = new_kcp();
        sent(&mut k, 3, 0);
        k.snd_una = 1;
        assert_eq!(k.parse_fastack(0, 10), 0);
        assert_eq!(k.parse_fastack(3, 10), 0);
        assert_eq!(fastacks(&k), vec![0, 0, 0]);
    }

    #[test]
    fn parse_fastack_threshold_zero_and_negative() {
        // fastresend 0 (default): any counted segment reaches the threshold.
        let (mut k, _) = new_kcp();
        sent(&mut k, 2, 0);
        assert_eq!(k.parse_fastack(1, 0), 1);
        // ... but nothing counted, nothing reported.
        assert_eq!(k.parse_fastack(0, 0), 0);
        // Negative: uint32(fastresend) is huge, never reached.
        let (mut k, _) = new_kcp();
        k.fastresend = -1;
        sent(&mut k, 2, 0);
        for _ in 0..5 {
            assert_eq!(k.parse_fastack(1, 0), 0);
        }
        assert_eq!(fastacks(&k), vec![5, 0]);
    }

    #[test]
    fn input_ack_fastack_triggers_full_flush() {
        let (mut k, clock) = new_kcp();
        clock.set(200);
        k.fastresend = 2;
        sent(&mut k, 5, 100);
        assert_eq!(input_reg(&mut k, &ack(3, 103, 0)), 0);
        assert!(k.flush_calls.is_empty(), "fastack 1 < 2");
        assert_eq!(fastacks(&k), vec![1, 1, 1, 0, 0]);
        assert_eq!(input_reg(&mut k, &ack(4, 104, 0)), 0);
        assert_eq!(flush_types(&k), vec![IKCP_FLUSH_FULL]);
        assert_eq!(k.flush_calls[0].snd_buf_fastack, vec![2, 2, 2, 1, 0]);
        let acked: Vec<u32> = k.snd_buf.iter().map(|s| s.acked).collect();
        assert_eq!(acked, vec![0, 0, 0, 1, 1]);
        assert_eq!(k.snd_una, 0);
        assert!(k.acklist.is_empty(), "ACKs are not acknowledged");
    }

    #[test]
    fn update_ack_rfc6298_branches() {
        let (mut k, _) = new_kcp();
        // First sample: srtt = rtt, rttvar = rtt / 2.
        k.update_ack(80);
        assert_eq!((k.rx_srtt, k.rx_rttvar, k.rx_rto), (80, 40, 80 + 160));
        // Normal branch: srtt += delta/8, rttvar += (|delta| - rttvar)/4.
        k.update_ack(200);
        assert_eq!((k.rx_srtt, k.rx_rttvar, k.rx_rto), (95, 60, 95 + 240));
        // Sample below srtt - rttvar: rttvar weight 1/32 (arithmetic shifts on negatives).
        k.update_ack(0);
        // delta = -95 -> srtt += -95 >> 3 = -12 -> 83; |delta| = 95; 0 < 83 - 60;
        // rttvar += (95 - 60) >> 5 = 1.
        assert_eq!((k.rx_srtt, k.rx_rttvar, k.rx_rto), (83, 61, 83 + 244));
        // The same sample on the normal branch would have added (95 - 60) >> 2 = 8.
        let (mut k2, _) = new_kcp();
        k2.rx_srtt = 95;
        k2.rx_rttvar = 60;
        k2.update_ack(70); // delta -25 -> srtt 91; 70 >= 91 - 60 -> normal branch
        assert_eq!((k2.rx_srtt, k2.rx_rttvar), (91, 60 + ((25 - 60) >> 2)));
        assert_eq!(k2.rx_rttvar, 51);

        // rto = srtt + max(interval, 4 * rttvar), bounded to [rx_minrto, IKCP_RTO_MAX].
        let (mut k, _) = new_kcp();
        k.update_ack(1); // 1 + max(100, 0)
        assert_eq!(k.rx_rto, 101);
        let (mut k, _) = new_kcp();
        assert_eq!(k.nodelay(-1, 10, -1, -1), 0);
        k.update_ack(4); // 4 + max(10, 8) = 14 -> rx_minrto 100
        assert_eq!(k.rx_rto, IKCP_RTO_MIN);
        let (mut k, _) = new_kcp();
        k.update_ack(100_000);
        assert_eq!(k.rx_rto, IKCP_RTO_MAX);
    }

    #[test]
    fn update_ack_wraps_like_go() {
        let (mut k, _) = new_kcp();
        k.update_ack(i32::MAX);
        assert_eq!((k.rx_srtt, k.rx_rttvar), (i32::MAX, 0x3FFF_FFFF));
        // uint32(srtt) + (uint32(rttvar) << 2) wraps to 0x7FFFFFFB -> capped.
        assert_eq!(k.rx_rto, IKCP_RTO_MAX);
        k.update_ack(0);
        // delta = -MAX -> srtt = MAX + (-MAX >> 3) = 0x6FFFFFFF; low branch;
        // rttvar += (MAX - 0x3FFFFFFF) >> 5 = 0x2000000.
        assert_eq!((k.rx_srtt, k.rx_rttvar), (0x6FFF_FFFF, 0x41FF_FFFF));
        assert_eq!(k.rx_rto, IKCP_RTO_MAX);
        // delta = i32::MIN: |delta| wraps to itself, no panic.
        let (mut k, _) = new_kcp();
        k.rx_srtt = 1;
        k.update_ack(i32::MIN.wrapping_add(1));
        // Values printed by the pinned Go code for the same calls.
        assert_eq!(
            (k.rx_srtt, k.rx_rttvar, k.rx_rto),
            (-268_435_455, -67_108_864, 60000)
        );
    }

    #[test]
    fn input_rtt_uses_latest_ack_ts_of_regular_packets() {
        let (mut k, clock) = new_kcp();
        clock.set(1000);
        sent(&mut k, 4, 0);
        // Two ACKs: the last one's ts is used (not the largest).
        let mut pkt = ack(1, 950, 0);
        pkt.extend(ack(2, 900, 0));
        assert_eq!(input_reg(&mut k, &pkt), 0);
        assert_eq!((k.rx_srtt, k.rx_rttvar, k.rx_rto), (100, 50, 300));

        // FEC-recovered ACKs never update the RTT.
        let (mut k, clock) = new_kcp();
        clock.set(1000);
        sent(&mut k, 2, 0);
        assert_eq!(input(&mut k, &ack(1, 900, 0), IKCP_PACKET_FEC, false), 0);
        assert_eq!((k.rx_srtt, k.rx_rto), (0, IKCP_RTO_DEF));
        assert_eq!(k.snd_buf.iter().nth(1).map(|s| s.acked), Some(1));

        // No ACK in the packet: no update.
        assert_eq!(input_reg(&mut k, &h().enc(&[])), 0);
        assert_eq!(k.rx_srtt, 0);

        // Any ACK counts, even one outside the send window.
        assert_eq!(input_reg(&mut k, &ack(77, 990, 0)), 0);
        assert_eq!((k.rx_srtt, k.rx_rttvar), (10, 5));

        // A ts in the future (current < latest) is ignored; a zero RTT is a sample.
        let (mut k, clock) = new_kcp();
        clock.set(1000);
        assert_eq!(input_reg(&mut k, &ack(0, 1001, 0)), 0);
        assert_eq!((k.rx_srtt, k.rx_rto), (0, IKCP_RTO_DEF));
        assert_eq!(input_reg(&mut k, &ack(0, 1000, 0)), 0);
        assert_eq!((k.rx_srtt, k.rx_rttvar, k.rx_rto), (0, 0, 100));

        // Clock wrap: current 5, ts 0xFFFFFFF0 -> rtt 21.
        let (mut k, clock) = new_kcp();
        clock.set(5);
        assert_eq!(input_reg(&mut k, &ack(0, 0xFFFF_FFF0, 0)), 0);
        assert_eq!((k.rx_srtt, k.rx_rttvar), (21, 10));
    }

    // ---- cwnd growth ----

    /// A packet acknowledging sn 0 via una (cwnd grows only when snd_una advances).
    fn una1(wnd: u16) -> Vec<u8> {
        H { una: 1, wnd, ..h() }.enc(&[])
    }

    #[test]
    fn input_cwnd_slow_start() {
        let (mut k, _) = new_kcp();
        sent(&mut k, 3, 0);
        assert_eq!(input_reg(&mut k, &una1(32)), 0);
        assert_eq!((k.cwnd, k.incr, k.ssthresh), (1, MSS, 2));
        assert_eq!(input_reg(&mut k, &H { una: 2, ..h() }.enc(&[])), 0);
        assert_eq!((k.cwnd, k.incr), (2, 2 * MSS));
        assert_eq!(flush_types(&k), vec![IKCP_FLUSH_FULL; 2]);
        // cwnd == ssthresh now: the next advance is congestion avoidance.
        assert_eq!(input_reg(&mut k, &H { una: 3, ..h() }.enc(&[])), 0);
        // incr = 2752 + 1376*1376/2752 + 86 = 3526; 3 * 1376 > 3526: cwnd stays.
        assert_eq!((k.cwnd, k.incr), (2, 3526));
    }

    #[test]
    fn input_cwnd_congestion_avoidance() {
        // incr below mss is raised to mss first: 1376 + 1376 + 86.
        let (mut k, _) = new_kcp();
        sent(&mut k, 2, 0);
        k.cwnd = 2;
        assert_eq!(input_reg(&mut k, &una1(32)), 0);
        assert_eq!((k.cwnd, k.incr), (2, 2838));

        // incr = 4128 + 1893376/4128 (458) + 86 = 4672 >= 3 * 1376 -> cwnd = ceil(4672/1376).
        let (mut k, _) = new_kcp();
        sent(&mut k, 2, 0);
        k.cwnd = 2;
        k.incr = 3 * MSS;
        assert_eq!(input_reg(&mut k, &una1(32)), 0);
        assert_eq!((k.cwnd, k.incr), (4, 4672));
    }

    #[test]
    fn input_cwnd_capped_at_rmt_wnd() {
        // Same as above but the packet advertises wnd 3 (applied before the cwnd update).
        let (mut k, _) = new_kcp();
        sent(&mut k, 2, 0);
        k.cwnd = 2;
        k.incr = 3 * MSS;
        assert_eq!(input_reg(&mut k, &una1(3)), 0);
        assert_eq!((k.cwnd, k.incr), (3, 3 * MSS));

        // cwnd >= rmt_wnd: no growth at all.
        let (mut k, _) = new_kcp();
        sent(&mut k, 2, 0);
        k.cwnd = 5;
        k.incr = 7;
        assert_eq!(input_reg(&mut k, &una1(5)), 0);
        assert_eq!((k.cwnd, k.incr), (5, 7));

        // A FEC packet keeps the old rmt_wnd (32), so its wnd 0 does not cap.
        let (mut k, _) = new_kcp();
        sent(&mut k, 2, 0);
        assert_eq!(input(&mut k, &una1(0), IKCP_PACKET_FEC, false), 0);
        assert_eq!((k.rmt_wnd, k.cwnd, k.incr), (32, 1, MSS));
    }

    #[test]
    fn input_cwnd_unchanged_without_progress_or_with_nocwnd() {
        // ACKs that do not move snd_una do not grow the window.
        // fastresend = -1 so the ACK does not trigger a FULL flush (whose tail would set cwnd).
        let (mut k, _) = new_kcp();
        k.fastresend = -1;
        sent(&mut k, 3, 0);
        assert_eq!(input_reg(&mut k, &ack(1, 0, 0)), 0);
        assert_eq!((k.cwnd, k.incr), (0, 0));
        assert!(k.flush_calls.is_empty());

        let (mut k, _) = new_kcp();
        assert_eq!(k.nodelay(-1, -1, -1, 1), 0);
        sent(&mut k, 3, 0);
        assert_eq!(input_reg(&mut k, &una1(32)), 0);
        assert_eq!((k.cwnd, k.incr), (0, 0));
        assert_eq!(flush_types(&k), vec![IKCP_FLUSH_FULL], "still flushes");
    }

    #[test]
    fn input_cwnd_grows_across_sn_wrap() {
        let (mut k, _) = new_kcp();
        k.snd_una = u32::MAX - 1;
        k.snd_nxt = u32::MAX - 1;
        sent(&mut k, 4, 0); // MAX-1, MAX, 0, 1
        assert_eq!(input_reg(&mut k, &H { una: 1, ..h() }.enc(&[])), 0);
        assert_eq!(k.snd_una, 1);
        assert_eq!(snd_sns(&k), vec![1]);
        assert_eq!((k.cwnd, k.incr), (1, MSS));
    }

    // ---- PUSH: ack_push / parse_data ----

    #[test]
    fn input_push_in_order_goes_to_rcv_queue() {
        let (mut k, _) = new_kcp();
        let pkt = H {
            cmd: IKCP_CMD_PUSH,
            frg: 1,
            wnd: 9,
            ts: 77,
            sn: 0,
            una: 5,
            ..h()
        }
        .enc(b"abc");
        assert_eq!(input_reg(&mut k, &pkt), 0);
        assert_eq!(k.rcv_nxt, 1);
        assert_eq!(k.acklist, acks(&[(0, 77)]));
        let s = k.rcv_queue.peek().expect("queued");
        let want = Segment {
            conv: CONV,
            cmd: IKCP_CMD_PUSH,
            frg: 1,
            wnd: 9,
            ts: 77,
            sn: 0,
            una: 5,
            data: b"abc".to_vec(),
            ..Segment::default()
        };
        assert_eq!(*s, want);
        assert!(k.rcv_buf.is_empty());
        assert!(k.flush_calls.is_empty(), "ACKs wait for the next flush");
    }

    #[test]
    fn input_push_out_of_order_is_reassembled() {
        let (mut k, _) = new_kcp();
        assert_eq!(input_reg(&mut k, &push(2, 12, b"c")), 0);
        assert_eq!(k.rcv_nxt, 0);
        assert_eq!(rcv_buf_sns(&k), vec![2]);
        assert!(k.rcv_queue.is_empty());
        assert_eq!(input_reg(&mut k, &push(0, 10, b"a")), 0);
        assert_eq!((rcv_queue_sns(&k), rcv_buf_sns(&k)), (vec![0], vec![2]));
        // Filling the gap drains rcv_buf in order.
        assert_eq!(input_reg(&mut k, &push(1, 11, b"b")), 0);
        assert_eq!(rcv_queue_sns(&k), vec![0, 1, 2]);
        assert!(k.rcv_buf.is_empty() && !k.rcv_buf.has(2), "marks in sync");
        assert_eq!(k.rcv_nxt, 3);
        assert_eq!(k.acklist, acks(&[(2, 12), (0, 10), (1, 11)]));
        let mut buf = [0u8; 8];
        assert_eq!(k.recv(&mut buf), 1);
        assert_eq!(k.recv(&mut buf[1..]), 1);
        assert_eq!(k.recv(&mut buf[2..]), 1);
        assert_eq!(&buf[..3], b"abc");
    }

    #[test]
    fn input_push_duplicate_and_old_segments() {
        let (mut k, _) = new_kcp();
        assert_eq!(input_reg(&mut k, &push(3, 1, b"first")), 0);
        // Duplicate of a buffered segment: acked again, data not replaced.
        assert_eq!(input_reg(&mut k, &push(3, 2, b"second")), 0);
        assert_eq!(k.rcv_buf.len(), 1);
        assert_eq!(
            k.rcv_buf.peek().map(|s| s.data.clone()),
            Some(b"first".to_vec())
        );
        // Already delivered (sn < rcv_nxt): acked, not stored.
        k.rcv_nxt = 10;
        k.rcv_buf = SegmentHeap::new();
        assert_eq!(input_reg(&mut k, &push(9, 3, b"old")), 0);
        assert_eq!(input_reg(&mut k, &push(0, 4, b"old")), 0);
        assert!(k.rcv_buf.is_empty() && k.rcv_queue.is_empty());
        assert_eq!(k.acklist, acks(&[(3, 1), (3, 2), (9, 3), (0, 4)]));
    }

    #[test]
    fn input_push_receive_window_bounds() {
        let (mut k, _) = new_kcp();
        assert_eq!(k.wnd_size(0, 4), 0);
        k.rcv_nxt = 100;
        // rcv_nxt + rcv_wnd is outside the window: not even acked.
        assert_eq!(input_reg(&mut k, &push(104, 1, b"x")), 0);
        assert!(k.acklist.is_empty() && k.rcv_buf.is_empty());
        // The last slot is inside.
        assert_eq!(input_reg(&mut k, &push(103, 2, b"y")), 0);
        assert_eq!(k.acklist, acks(&[(103, 2)]));
        assert_eq!(rcv_buf_sns(&k), vec![103]);
    }

    #[test]
    fn input_push_window_wraps() {
        let (mut k, _) = new_kcp();
        k.rcv_nxt = u32::MAX;
        assert_eq!(input_reg(&mut k, &push(0, 1, b"b")), 0);
        assert_eq!(input_reg(&mut k, &push(u32::MAX, 0, b"a")), 0);
        assert_eq!(rcv_queue_sns(&k), vec![u32::MAX, 0]);
        assert_eq!(k.rcv_nxt, 1);
        // rcv_nxt + rcv_wnd wraps too: 32 is inside [1, 33), 33 is not.
        assert_eq!(input_reg(&mut k, &push(32, 2, b"c")), 0);
        assert_eq!(input_reg(&mut k, &push(33, 3, b"d")), 0);
        assert_eq!(rcv_buf_sns(&k), vec![32]);
    }

    #[test]
    fn input_push_stays_in_rcv_buf_while_rcv_queue_is_full() {
        let (mut k, _) = new_kcp();
        assert_eq!(k.wnd_size(0, 2), 0);
        assert_eq!(input_reg(&mut k, &push(0, 0, b"a")), 0);
        assert_eq!(input_reg(&mut k, &push(1, 0, b"b")), 0);
        assert_eq!(rcv_queue_sns(&k), vec![0, 1]);
        // In window (2 < 2 + 2) but rcv_queue already holds rcv_wnd segments.
        assert_eq!(input_reg(&mut k, &push(2, 0, b"c")), 0);
        assert_eq!(rcv_buf_sns(&k), vec![2]);
        assert_eq!(k.rcv_nxt, 2);
        // recv() frees a slot and moves it over.
        let mut buf = [0u8; 4];
        assert_eq!(k.recv(&mut buf), 1);
        assert_eq!(rcv_queue_sns(&k), vec![1, 2]);
        assert!(k.rcv_buf.is_empty());
    }

    #[test]
    fn parse_data_direct() {
        let (mut k, _) = new_kcp();
        let hdr = |sn| Segment {
            sn,
            ..Segment::default()
        };
        assert!(!k.parse_data(hdr(1), b"b"));
        assert!(k.parse_data(hdr(1), b"B"), "repeat");
        assert!(!k.parse_data(hdr(0), b"a"));
        assert!(k.parse_data(hdr(0), b"a"), "below rcv_nxt");
        assert!(k.parse_data(hdr(2 + 32), b"z"), "outside the window");
        assert_eq!(concat_queue(&k), b"ab");
        assert_eq!(k.rcv_nxt, 2);
        assert!(k.acklist.is_empty(), "parse_data does not ack");
    }

    fn concat_queue(k: &TestKcp) -> Vec<u8> {
        k.rcv_queue.iter().flat_map(|s| s.data.clone()).collect()
    }

    // ---- WASK / WINS ----

    #[test]
    fn input_wask_sets_ask_tell_and_wins_only_updates_window() {
        let (mut k, _) = new_kcp();
        k.probe = IKCP_ASK_SEND;
        let pkt = H {
            cmd: IKCP_CMD_WASK,
            wnd: 3,
            ..h()
        }
        .enc(&[]);
        assert_eq!(input_reg(&mut k, &pkt), 0);
        assert_eq!(k.probe, IKCP_ASK_SEND | IKCP_ASK_TELL);
        assert_eq!(k.rmt_wnd, 3);
        // FEC-recovered probes are answered too.
        let (mut k, _) = new_kcp();
        assert_eq!(input(&mut k, &pkt, IKCP_PACKET_FEC, true), 0);
        assert_eq!(k.probe, IKCP_ASK_TELL);
        assert!(
            k.flush_calls.is_empty(),
            "no ACKs: ack_no_delay does not flush"
        );

        let (mut k, _) = new_kcp();
        assert_eq!(input_reg(&mut k, &H { wnd: 0, ..h() }.enc(b"ignored")), 0);
        assert_eq!((k.probe, k.rmt_wnd), (0, 0));
        assert!(k.acklist.is_empty() && k.rcv_queue.is_empty() && k.flush_calls.is_empty());
    }

    // ---- flush decision ----

    #[test]
    fn input_flush_ackonly_when_acklist_reaches_mtu_over_24() {
        // mtu 1400: 1400 / 24 = 58 pending ACKs flush.
        let (mut k, _) = new_kcp();
        k.rcv_nxt = 1000;
        let mut pkt = Vec::new();
        for i in 0..57 {
            pkt.extend(push(999, i, &[]));
        }
        assert_eq!(input_reg(&mut k, &pkt), 0);
        assert_eq!(k.acklist.len(), 57);
        assert!(k.flush_calls.is_empty());
        assert_eq!(input_reg(&mut k, &push(999, 57, &[])), 0);
        assert_eq!(flush_types(&k), vec![IKCP_FLUSH_ACKONLY]);
        assert_eq!(k.flush_calls[0].acklist.len(), 58);

        // mtu 50: 2 ACKs are enough.
        let (mut k, _) = new_kcp();
        assert_eq!(k.set_mtu(50), 0);
        assert_eq!(input_reg(&mut k, &push(0, 0, b"a")), 0);
        assert!(k.flush_calls.is_empty());
        assert_eq!(input_reg(&mut k, &push(1, 0, b"b")), 0);
        assert_eq!(flush_types(&k), vec![IKCP_FLUSH_ACKONLY]);
    }

    #[test]
    fn input_flush_ackonly_with_ack_no_delay() {
        let (mut k, _) = new_kcp();
        assert_eq!(
            input(&mut k, &push(0, 5, b"a"), IKCP_PACKET_REGULAR, true),
            0
        );
        assert_eq!(flush_types(&k), vec![IKCP_FLUSH_ACKONLY]);
        assert_eq!(k.flush_calls[0].acklist, acks(&[(0, 5)]));
        // Out-of-window data produces no ACK: no flush.
        let (mut k, _) = new_kcp();
        assert_eq!(
            input(&mut k, &push(40, 5, b"a"), IKCP_PACKET_REGULAR, true),
            0
        );
        assert!(k.flush_calls.is_empty());
        // ACK-only packets do not queue ACKs either (fast retransmit disabled so the ACK
        // does not trigger a full flush).
        k.fastresend = -1;
        sent(&mut k, 2, 0);
        assert_eq!(input(&mut k, &ack(1, 0, 0), IKCP_PACKET_REGULAR, true), 0);
        assert!(k.flush_calls.is_empty());
    }

    #[test]
    fn input_full_flush_takes_precedence_and_is_called_once() {
        let (mut k, _) = new_kcp();
        sent(&mut k, 3, 0);
        let mut pkt = push(0, 5, b"a");
        pkt.extend(H { una: 2, ..h() }.enc(&[]));
        assert_eq!(input(&mut k, &pkt, IKCP_PACKET_REGULAR, true), 0);
        assert_eq!(flush_types(&k), vec![IKCP_FLUSH_FULL]);
        assert_eq!(k.flush_calls[0].acklist, acks(&[(0, 5)]));
    }

    #[test]
    fn input_mixed_packet() {
        // One packet with every command, as a peer's flush() produces.
        let (mut k, clock) = new_kcp();
        clock.set(500);
        sent(&mut k, 4, 400);
        let mut pkt = ack(1, 450, 1);
        pkt.extend(push(0, 20, b"hello"));
        pkt.extend(
            H {
                cmd: IKCP_CMD_WASK,
                una: 1,
                ..h()
            }
            .enc(&[]),
        );
        pkt.extend(
            H {
                cmd: IKCP_CMD_WINS,
                una: 1,
                wnd: 16,
                ..h()
            }
            .enc(&[]),
        );
        assert_eq!(input_reg(&mut k, &pkt), 0);
        assert_eq!(snd_sns(&k), vec![1, 2, 3]);
        assert_eq!(k.snd_buf.peek().map(|s| s.acked), Some(1));
        assert_eq!(k.snd_una, 1);
        assert_eq!(k.rmt_wnd, 16);
        // flush() (03.4) consumes probe, so check the value it sees on entry.
        assert_eq!(k.flush_calls[0].probe, IKCP_ASK_TELL);
        assert_eq!((k.rx_srtt, k.rx_rttvar), (50, 25));
        assert_eq!((k.cwnd, k.incr), (1, MSS));
        assert_eq!(rcv_queue_sns(&k), vec![0]);
        assert_eq!(flush_types(&k), vec![IKCP_FLUSH_FULL]);
        assert_eq!(k.flush_calls[0].acklist, acks(&[(0, 20)]));
    }
    #[cfg(feature = "trace")]
    #[test]
    fn trace_logger_receives_input_events() {
        use std::sync::Mutex;
        let events: Arc<Mutex<Vec<String>>> = Arc::default();
        let (mut k, _) = new_kcp();
        let sink = Arc::clone(&events);
        k.set_logger(
            IKCP_LOG_INPUT_ALL,
            Some(Box::new(move |msg, args| {
                let kv: Vec<String> = args.iter().map(|(k, v)| format!("{k}={v:?}")).collect();
                sink.lock()
                    .expect("lock")
                    .push(format!("{msg} {}", kv.join(" ")));
            })),
        );
        let mut pkt = push(0, 5, b"ab");
        pkt.extend(ack(9, 6, 0));
        pkt.extend(
            H {
                cmd: IKCP_CMD_WASK,
                ts: 7,
                ..h()
            }
            .enc(&[]),
        );
        pkt.extend(H { ts: 8, ..h() }.enc(&[]));
        assert_eq!(input_reg(&mut k, &pkt), 0);
        let got = events.lock().expect("lock").clone();
        assert_eq!(
            got,
            vec![
                "[KCP INPUT] conv=168496141 cmd=81 frg=0 wnd=32 ts=5 sn=0 una=0 len=2 datalen=74",
                "[KCP INPUT PUSH] conv=168496141 sn=0 una=0 ts=5 packettype=0 repeat=false",
                "[KCP INPUT] conv=168496141 cmd=82 frg=0 wnd=32 ts=6 sn=9 una=0 len=0 datalen=48",
                "[KCP INPUT ACK] conv=168496141 sn=9 una=0 ts=6 rto=200",
                "[KCP INPUT] conv=168496141 cmd=83 frg=0 wnd=32 ts=7 sn=0 una=0 len=0 datalen=24",
                "[KCP INPUT WASK] conv=168496141 wnd=32 ts=7",
                "[KCP INPUT] conv=168496141 cmd=84 frg=0 wnd=32 ts=8 sn=0 una=0 len=0 datalen=0",
                "[KCP INPUT WINS] conv=168496141 wnd=32 ts=8",
            ]
        );
    }
}

/// Tests for `flush()`, `update()` and `check()`.
///
/// Every branch of Go's `flush()` has a test here. The port was also compared with the pinned Go
/// code (kcp.go with `currentMs()` replaced by a fake clock that optionally advances on every
/// read) on 36 random traces of 4000 operations each (send / input / flush / recv / update /
/// check / config changes, clock start near 0 and near the u32 wrap): identical output packets,
/// return values and state after every operation.
#[cfg(test)]
mod flush_tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU32;
    use std::sync::{RwLockReadGuard, RwLockWriteGuard};

    const CONV: u32 = 0x0102_0304;
    const MSS: u32 = 1376;
    const T0: u32 = 1000;

    /// A settable clock that advances by `step` ms on every read (0 by default), to observe
    /// exactly where `flush()` reads it.
    #[derive(Clone, Default)]
    struct TestClock {
        now: Arc<AtomicU32>,
        step: Arc<AtomicU32>,
    }

    impl TestClock {
        fn set(&self, ms: u32) {
            self.now.store(ms, Ordering::Relaxed);
        }

        fn get(&self) -> u32 {
            self.now.load(Ordering::Relaxed)
        }

        fn set_step(&self, step: u32) {
            self.step.store(step, Ordering::Relaxed);
        }
    }

    impl Clock for TestClock {
        fn now_ms(&self) -> u32 {
            let v = self.now.load(Ordering::Relaxed);
            self.now.store(
                v.wrapping_add(self.step.load(Ordering::Relaxed)),
                Ordering::Relaxed,
            );
            v
        }
    }

    type Sink = Rc<RefCell<Vec<Vec<u8>>>>;
    type BoxOutput = Box<dyn FnMut(&[u8])>;
    type TestKcp = Kcp<BoxOutput, TestClock>;

    struct Fixture {
        k: TestKcp,
        clock: TestClock,
        out: Sink,
    }

    impl Fixture {
        /// Drains the packets written by `output` so far.
        fn packets(&self) -> Vec<Vec<u8>> {
            std::mem::take(&mut *self.out.borrow_mut())
        }

        fn flush(&mut self, flush_type: FlushType) -> u32 {
            let _g = snmp_read();
            self.k.flush(flush_type)
        }
    }

    /// A fresh KCP at `T0` ms.
    fn fixture() -> Fixture {
        let clock = TestClock::default();
        clock.set(T0);
        let out: Sink = Rc::default();
        let sink = Rc::clone(&out);
        let output: BoxOutput = Box::new(move |b: &[u8]| sink.borrow_mut().push(b.to_vec()));
        let k = Kcp::with_clock(CONV, output, clock.clone());
        Fixture { k, clock, out }
    }

    fn snmp_read() -> RwLockReadGuard<'static, ()> {
        SNMP_TEST_LOCK.read().unwrap_or_else(|e| e.into_inner())
    }

    fn snmp_write() -> RwLockWriteGuard<'static, ()> {
        SNMP_TEST_LOCK.write().unwrap_or_else(|e| e.into_inner())
    }

    /// Decodes every segment of an output packet.
    fn segs(pkt: &[u8]) -> Vec<(SegmentHeader, Vec<u8>)> {
        let mut v = Vec::new();
        let mut d = pkt;
        while let Some((h, rest)) = SegmentHeader::decode(d) {
            let n = h.len as usize;
            v.push((h, rest[..n].to_vec()));
            d = &rest[n..];
        }
        assert!(d.is_empty(), "trailing bytes in output packet");
        v
    }

    /// (cmd, sn, ts) of every segment of every packet, flattened.
    fn cmds(pkts: &[Vec<u8>]) -> Vec<(u8, u32, u32)> {
        pkts.iter()
            .flat_map(|p| segs(p))
            .map(|(h, _)| (h.cmd, h.sn, h.ts))
            .collect()
    }

    fn sizes(pkts: &[Vec<u8>]) -> Vec<usize> {
        pkts.iter().map(Vec::len).collect()
    }

    /// Puts an already-sent segment (xmit 1, rto 200, 10-byte payload) into `snd_buf`.
    fn in_flight(k: &mut TestKcp, resendts: u32, fastack: u32) {
        k.snd_buf.push(Segment {
            conv: CONV,
            cmd: IKCP_CMD_PUSH,
            sn: k.snd_nxt,
            ts: T0 - 100,
            xmit: 1,
            rto: 200,
            resendts,
            fastack,
            data: vec![k.snd_nxt as u8; 10],
            ..Segment::default()
        });
        k.snd_nxt = k.snd_nxt.wrapping_add(1);
    }

    fn xmits(k: &TestKcp) -> Vec<u32> {
        k.snd_buf.iter().map(|s| s.xmit).collect()
    }

    fn fastacks(k: &TestKcp) -> Vec<u32> {
        k.snd_buf.iter().map(|s| s.fastack).collect()
    }

    const FAR: u32 = T0 + 100_000;

    // ---- empty flushes, cwnd floor ----

    #[test]
    fn flush_empty_sends_nothing_and_returns_interval() {
        let mut f = fixture();
        assert_eq!(f.k.cwnd, 0);
        assert_eq!(f.flush(IKCP_FLUSH_FULL), IKCP_INTERVAL);
        assert!(f.packets().is_empty());
        // cwnd floor
        assert_eq!((f.k.cwnd, f.k.incr), (1, MSS));
        assert_eq!(f.flush(IKCP_FLUSH_ACKONLY), IKCP_INTERVAL);
        assert!(f.packets().is_empty());
    }

    #[test]
    fn flush_nocwnd_leaves_cwnd_alone() {
        let mut f = fixture();
        f.k.nodelay(-1, -1, -1, 1);
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!((f.k.cwnd, f.k.incr), (0, 0));
    }

    // ---- acknowledgements ----

    #[test]
    fn flush_ackonly_emits_acks_and_clears_the_list() {
        let mut f = fixture();
        f.k.rcv_nxt = 3;
        f.k.rcv_queue.push(Segment::default()); // wnd_unused = 31
        f.k.acklist = vec![AckItem { sn: 3, ts: 11 }, AckItem { sn: 5, ts: 12 }];
        assert_eq!(f.flush(IKCP_FLUSH_ACKONLY), IKCP_INTERVAL);
        let pkts = f.packets();
        assert_eq!(sizes(&pkts), vec![48]);
        let s = segs(&pkts[0]);
        let expect = |sn, ts| SegmentHeader {
            conv: CONV,
            cmd: IKCP_CMD_ACK,
            frg: 0,
            wnd: 31,
            ts,
            sn,
            una: 3,
            len: 0,
        };
        assert_eq!(s[0].0, expect(3, 11));
        assert_eq!(s[1].0, expect(5, 12));
        assert!(f.k.acklist.is_empty());
    }

    #[test]
    fn flush_bufferbloat_filter_keeps_new_acks_and_the_last_one() {
        let mut f = fixture();
        f.k.rcv_nxt = 10;
        f.k.acklist = [(5, 1), (12, 2), (10, 3), (3, 4), (8, 5)]
            .iter()
            .map(|&(sn, ts)| AckItem { sn, ts })
            .collect();
        f.flush(IKCP_FLUSH_FULL);
        // 5 and 3 are below rcv_nxt (already acked by una); 8 is below too but is the last entry.
        assert_eq!(
            cmds(&f.packets()),
            vec![
                (IKCP_CMD_ACK, 12, 2),
                (IKCP_CMD_ACK, 10, 3),
                (IKCP_CMD_ACK, 8, 5)
            ]
        );
        assert!(f.k.acklist.is_empty());
    }

    #[test]
    fn flush_bufferbloat_filter_uses_wrapping_comparison() {
        let mut f = fixture();
        f.k.rcv_nxt = u32::MAX - 1;
        f.k.acklist = [
            (u32::MAX - 3, 1),
            (1, 2),
            (u32::MAX - 1, 3),
            (u32::MAX - 5, 4),
        ]
        .iter()
        .map(|&(sn, ts)| AckItem { sn, ts })
        .collect();
        f.flush(IKCP_FLUSH_ACKONLY);
        assert_eq!(
            cmds(&f.packets()),
            vec![
                (IKCP_CMD_ACK, 1, 2),
                (IKCP_CMD_ACK, u32::MAX - 1, 3),
                (IKCP_CMD_ACK, u32::MAX - 5, 4)
            ]
        );
    }

    #[test]
    fn flush_single_old_ack_is_still_sent() {
        let mut f = fixture();
        f.k.rcv_nxt = 10;
        f.k.acklist = vec![AckItem { sn: 2, ts: 7 }];
        f.flush(IKCP_FLUSH_ACKONLY);
        assert_eq!(cmds(&f.packets()), vec![(IKCP_CMD_ACK, 2, 7)]);
    }

    #[test]
    fn flush_splits_acks_and_data_at_mtu() {
        let mut f = fixture();
        f.k.cwnd = 8;
        // 60 ACKs: 58 fit into 1400 bytes (1392), the 59th starts a new packet.
        f.k.acklist = (0..60).map(|i| AckItem { sn: i, ts: i }).collect();
        // A full-size segment (24 + 1376 = 1400 bytes) does not fit after the last 2 ACKs.
        assert_eq!(f.k.send(&vec![0xAB; MSS as usize]), 0);
        // A small segment after it needs another packet (1400 + 29 > mtu).
        assert_eq!(f.k.send(b"small"), 0);
        f.flush(IKCP_FLUSH_FULL);
        let pkts = f.packets();
        assert_eq!(sizes(&pkts), vec![58 * 24, 2 * 24, 1400, 24 + 5]);
        let c = cmds(&pkts);
        assert_eq!(c.len(), 62);
        assert!(c[..60].iter().all(|&(cmd, _, _)| cmd == IKCP_CMD_ACK));
        assert_eq!(c[59].1, 59);
        let s = segs(&pkts[2]);
        assert_eq!(s[0].0.sn, 0);
        assert_eq!(s[0].1, vec![0xAB; MSS as usize]);
        assert_eq!(segs(&pkts[3])[0].1, b"small");
    }

    #[test]
    fn flush_packs_segments_up_to_mtu() {
        let mut f = fixture();
        f.k.set_mtu(100); // mss 76
        f.k.cwnd = 8;
        for _ in 0..3 {
            assert_eq!(f.k.send(&[1; 20]), 0);
        }
        f.k.acklist = vec![AckItem { sn: 0, ts: 0 }];
        f.flush(IKCP_FLUSH_FULL);
        // 24 (ack) + 44 + 44 = 112 > 100: ack + one segment, then two segments (88).
        assert_eq!(sizes(&f.packets()), vec![68, 88]);
    }

    #[test]
    fn flush_exact_mtu_fit_does_not_split() {
        let mut f = fixture();
        f.k.cwnd = 8;
        // 1 ACK (24) + a segment with 1352 bytes (24 + 1352) = 1400 = mtu.
        f.k.acklist = vec![AckItem { sn: 0, ts: 0 }];
        assert_eq!(f.k.send(&vec![7; 1352]), 0);
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!(sizes(&f.packets()), vec![1400]);
    }

    #[test]
    fn flush_segment_larger_than_the_buffer_after_mtu_shrink() {
        // Go panics here (a 1400-byte segment does not fit into the 222-byte buffer of mtu 50);
        // the port grows the buffer. Go's makeSpace also outputs an empty packet first, because
        // it compares size + space with mtu even when nothing is buffered.
        let mut f = fixture();
        f.k.cwnd = 1;
        assert_eq!(f.k.send(&vec![9; MSS as usize]), 0);
        assert_eq!(f.k.set_mtu(50), 0);
        assert_eq!(f.k.buffer.len(), 222);
        f.flush(IKCP_FLUSH_FULL);
        let pkts = f.packets();
        assert_eq!(sizes(&pkts), vec![0, 1400]);
        assert_eq!(segs(&pkts[1])[0].1, vec![9; MSS as usize]);
    }

    // ---- window probing ----

    #[test]
    fn flush_probe_wait_starts_at_500_and_grows_by_half() {
        let mut f = fixture();
        f.k.rmt_wnd = 0;
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!((f.k.probe_wait, f.k.ts_probe), (IKCP_PROBE_INIT, T0 + 500));
        assert_eq!(f.k.probe, 0);
        assert!(f.packets().is_empty(), "no WASK before ts_probe");

        f.clock.set(T0 + 499);
        f.flush(IKCP_FLUSH_FULL);
        assert!(f.packets().is_empty());
        assert_eq!((f.k.probe_wait, f.k.ts_probe), (500, T0 + 500));

        f.clock.set(T0 + 500);
        f.flush(IKCP_FLUSH_ACKONLY); // probing does not depend on the flush type
        assert_eq!((f.k.probe_wait, f.k.ts_probe), (750, T0 + 1250));
        let pkts = f.packets();
        assert_eq!(cmds(&pkts), vec![(IKCP_CMD_WASK, 0, 0)]);
        assert_eq!(segs(&pkts[0])[0].0.wnd, 32);
        assert_eq!(f.k.probe, 0, "probe is reset after sending");

        f.clock.set(T0 + 1250);
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!((f.k.probe_wait, f.k.ts_probe), (1125, T0 + 2375));
        f.clock.set(T0 + 2375);
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!(f.k.probe_wait, 1687);
    }

    #[test]
    fn flush_probe_wait_is_capped_at_120s() {
        let mut f = fixture();
        f.k.rmt_wnd = 0;
        f.flush(IKCP_FLUSH_FULL);
        let mut waits = vec![f.k.probe_wait];
        for _ in 0..20 {
            f.clock.set(f.k.ts_probe);
            f.flush(IKCP_FLUSH_FULL);
            waits.push(f.k.probe_wait);
        }
        assert_eq!(
            &waits[..16],
            &[
                500, 750, 1125, 1687, 2530, 3795, 5692, 8538, 12807, 19210, 28815, 43222, 64833,
                97249, 120000, 120000
            ]
        );
        assert!(waits[16..].iter().all(|&w| w == IKCP_PROBE_LIMIT));
        assert_eq!(f.k.ts_probe, f.clock.get() + IKCP_PROBE_LIMIT);
        assert_eq!(cmds(&f.packets()).len(), 20);
    }

    #[test]
    fn flush_probe_wait_below_init_is_raised_first() {
        let mut f = fixture();
        f.k.rmt_wnd = 0;
        f.k.probe_wait = 100;
        f.k.ts_probe = T0;
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!((f.k.probe_wait, f.k.ts_probe), (750, T0 + 750));
        assert_eq!(cmds(&f.packets()), vec![(IKCP_CMD_WASK, 0, 0)]);
    }

    #[test]
    fn flush_probe_timing_wraps() {
        let mut f = fixture();
        f.clock.set(u32::MAX - 100);
        f.k.rmt_wnd = 0;
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!(f.k.ts_probe, 399);
        f.clock.set(398);
        f.flush(IKCP_FLUSH_FULL);
        assert!(f.packets().is_empty());
        f.clock.set(399);
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!(cmds(&f.packets()), vec![(IKCP_CMD_WASK, 0, 0)]);
    }

    #[test]
    fn flush_open_remote_window_resets_probing() {
        let mut f = fixture();
        f.k.rmt_wnd = 0;
        f.flush(IKCP_FLUSH_FULL);
        assert_ne!(f.k.probe_wait, 0);
        f.k.rmt_wnd = 5;
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!((f.k.probe_wait, f.k.ts_probe), (0, 0));
    }

    #[test]
    fn flush_zero_remote_window_sends_no_data() {
        let mut f = fixture();
        f.k.rmt_wnd = 0;
        f.k.cwnd = 8;
        f.k.send(b"data");
        f.flush(IKCP_FLUSH_FULL);
        assert!(f.packets().is_empty());
        assert_eq!((f.k.snd_queue.len(), f.k.snd_buf.len()), (1, 0));
    }

    #[test]
    fn flush_wask_and_wins_follow_the_acks_and_reuse_the_last_ack_fields() {
        let mut f = fixture();
        f.k.rcv_nxt = 4;
        f.k.acklist = vec![AckItem { sn: 6, ts: 70 }, AckItem { sn: 7, ts: 99 }];
        f.k.probe = IKCP_ASK_SEND | IKCP_ASK_TELL;
        f.flush(IKCP_FLUSH_ACKONLY);
        let pkts = f.packets();
        // Go reuses the ACK template segment: WASK/WINS carry the last ACK's sn and ts.
        assert_eq!(
            cmds(&pkts),
            vec![
                (IKCP_CMD_ACK, 6, 70),
                (IKCP_CMD_ACK, 7, 99),
                (IKCP_CMD_WASK, 7, 99),
                (IKCP_CMD_WINS, 7, 99)
            ]
        );
        let s = segs(&pkts[0]);
        assert!(
            s.iter()
                .all(|(h, _)| h.una == 4 && h.wnd == 32 && h.conv == CONV)
        );
        assert_eq!(f.k.probe, 0);
    }

    #[test]
    fn flush_wins_alone() {
        let mut f = fixture();
        f.k.probe = IKCP_ASK_TELL;
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!(cmds(&f.packets()), vec![(IKCP_CMD_WINS, 0, 0)]);
        assert_eq!(f.k.probe, 0);
    }

    #[test]
    fn flush_probe_starts_a_new_packet_when_full() {
        let mut f = fixture();
        f.k.acklist = (0..58).map(|i| AckItem { sn: i, ts: 0 }).collect();
        f.k.probe = IKCP_ASK_TELL;
        f.flush(IKCP_FLUSH_ACKONLY);
        assert_eq!(sizes(&f.packets()), vec![1392, 24]);
    }

    // ---- sliding window ----

    #[test]
    fn flush_first_flush_moves_nothing_because_cwnd_starts_at_0() {
        let mut f = fixture();
        f.k.send(b"a");
        f.flush(IKCP_FLUSH_FULL);
        assert!(f.packets().is_empty());
        assert_eq!(
            (f.k.snd_queue.len(), f.k.snd_buf.len(), f.k.cwnd),
            (1, 0, 1)
        );
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!(cmds(&f.packets()), vec![(IKCP_CMD_PUSH, 0, T0)]);
    }

    #[test]
    fn flush_window_is_min_of_snd_wnd_rmt_wnd_and_cwnd() {
        let mut f = fixture();
        for _ in 0..10 {
            f.k.send(b"x");
        }
        f.k.cwnd = 3;
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!((f.k.snd_buf.len(), f.k.snd_nxt), (3, 3));

        f.k.snd_una = 2; // pretend 0 and 1 were acked (snd_una + cwnd = 5)
        f.k.rmt_wnd = 4; // min(32, 4, 3) = 3
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!(f.k.snd_nxt, 5);

        f.k.nodelay(-1, -1, -1, 1); // nocwnd: min(snd_wnd, rmt_wnd) = 4
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!(f.k.snd_nxt, 6);
        f.k.wnd_size(1, -1); // snd_wnd 1 < rmt_wnd
        f.k.snd_una = 6;
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!(f.k.snd_nxt, 7);
    }

    #[test]
    fn flush_ackonly_moves_segments_but_does_not_send_them() {
        let mut f = fixture();
        f.k.cwnd = 4;
        f.k.send(b"one");
        f.k.send(b"two");
        f.flush(IKCP_FLUSH_ACKONLY);
        assert!(f.packets().is_empty());
        assert_eq!(xmits(&f.k), vec![0, 0]);
        let s: Vec<_> = f.k.snd_buf.iter().map(|s| (s.conv, s.cmd, s.sn)).collect();
        assert_eq!(s, vec![(CONV, IKCP_CMD_PUSH, 0), (CONV, IKCP_CMD_PUSH, 1)]);
    }

    #[test]
    fn flush_sn_wraps() {
        let mut f = fixture();
        f.k.cwnd = 4;
        f.k.snd_una = u32::MAX;
        f.k.snd_nxt = u32::MAX;
        f.k.send(b"a");
        f.k.send(b"b");
        f.flush(IKCP_FLUSH_FULL);
        let sns: Vec<u32> = cmds(&f.packets()).iter().map(|c| c.1).collect();
        assert_eq!(sns, vec![u32::MAX, 0]);
        assert_eq!(f.k.snd_nxt, 1);
    }

    // ---- transmission ----

    #[test]
    fn flush_initial_transmit_fills_header_and_retransmission_state() {
        let mut f = fixture();
        f.k.cwnd = 4;
        f.k.rcv_nxt = 3;
        f.k.send(b"hello");
        assert_eq!(f.flush(IKCP_FLUSH_FULL), IKCP_INTERVAL);
        let pkts = f.packets();
        let s = segs(&pkts[0]);
        assert_eq!(
            s[0].0,
            SegmentHeader {
                conv: CONV,
                cmd: IKCP_CMD_PUSH,
                frg: 0,
                wnd: 32,
                ts: T0,
                sn: 0,
                una: 3,
                len: 5,
            }
        );
        assert_eq!(s[0].1, b"hello");
        let g = f.k.snd_buf.peek().unwrap();
        assert_eq!((g.xmit, g.rto, g.resendts, g.ts), (1, 200, T0 + 200, T0));
        assert_eq!((g.wnd, g.una), (32, 3));

        // The RTO hint is below a longer interval.
        f.k.nodelay(-1, 5000, -1, -1);
        f.clock.set(T0 + 50);
        assert_eq!(f.flush(IKCP_FLUSH_FULL), 150);
        assert!(f.packets().is_empty(), "not due yet");
    }

    #[test]
    fn flush_rereads_the_clock_before_each_send() {
        let mut f = fixture();
        f.k.cwnd = 4;
        f.k.nodelay(-1, 5000, -1, -1);
        f.k.send(b"a");
        f.k.send(b"b");
        f.clock.set_step(1);
        // Reads: 1000 (current), 1001 (before sending sn 0), 1002 (before sending sn 1).
        let next = f.flush(IKCP_FLUSH_FULL);
        let segs: Vec<(u32, u32)> = f.k.snd_buf.iter().map(|s| (s.ts, s.resendts)).collect();
        // resendts uses the current value read before the send; ts the re-read one.
        assert_eq!(segs, vec![(T0 + 1, T0 + 200), (T0 + 2, T0 + 201)]);
        // The RTO hint is computed against the re-read clock: 1200 - 1001, 1201 - 1002.
        assert_eq!(next, 199);
        assert_eq!(
            cmds(&f.packets()),
            vec![(IKCP_CMD_PUSH, 0, T0 + 1), (IKCP_CMD_PUSH, 1, T0 + 2)]
        );
        assert_eq!(f.clock.get(), T0 + 3);
    }

    #[test]
    fn flush_does_not_read_the_clock_in_the_loop_when_nothing_is_sent() {
        let mut f = fixture();
        f.k.cwnd = 4;
        in_flight(&mut f.k, FAR, 0);
        f.clock.set_step(1);
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!(
            f.clock.get(),
            T0 + 1,
            "only the `current` read before the loop"
        );
        f.k.rmt_wnd = 0;
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!(f.clock.get(), T0 + 3, "plus the probe read");
        f.flush(IKCP_FLUSH_ACKONLY);
        assert_eq!(
            f.clock.get(),
            T0 + 5,
            "ACKONLY still reads it once for the loop"
        );
    }

    #[test]
    fn flush_skips_acked_segments() {
        let mut f = fixture();
        f.k.cwnd = 4;
        f.k.nodelay(-1, 5000, -1, -1);
        in_flight(&mut f.k, T0, 0); // due, but acked
        f.k.snd_buf.peek_mut().unwrap().acked = 1;
        in_flight(&mut f.k, T0 + 300, 0);
        // The acked segment's resendts (T0 + 10 < T0 + 300) is not a hint either.
        f.k.snd_buf.peek_mut().unwrap().resendts = T0 + 10;
        assert_eq!(f.flush(IKCP_FLUSH_FULL), 300);
        assert!(f.packets().is_empty());
        assert_eq!(xmits(&f.k), vec![1, 1]);
    }

    #[test]
    fn flush_fast_retransmit() {
        let _g = snmp_write();
        let before = DEFAULT_SNMP.copy();
        let mut f = fixture();
        f.k.nodelay(-1, -1, 2, -1); // fastresend 2
        f.k.cwnd = 8;
        f.k.rx_rto = 300;
        in_flight(&mut f.k, FAR, 2); // fast retransmit
        in_flight(&mut f.k, FAR, 1); // below the threshold (no early retransmit: new segment)
        in_flight(&mut f.k, FAR, 0xFFFF_FFFF); // already fast-retransmitted: wait for RTO
        in_flight(&mut f.k, FAR, 5); // also above the threshold
        f.k.send(b"new");
        f.k.flush(IKCP_FLUSH_FULL);
        assert_eq!(
            cmds(&f.packets()),
            vec![
                (IKCP_CMD_PUSH, 0, T0),
                (IKCP_CMD_PUSH, 3, T0),
                (IKCP_CMD_PUSH, 4, T0)
            ]
        );
        assert_eq!(xmits(&f.k), vec![2, 1, 1, 2, 1]);
        assert_eq!(
            fastacks(&f.k),
            vec![0xFFFF_FFFF, 1, 0xFFFF_FFFF, 0xFFFF_FFFF, 0]
        );
        let g = f.k.snd_buf.peek().unwrap();
        assert_eq!((g.rto, g.resendts, g.ts), (300, T0 + 300, T0));
        // Rate halving: inflight 5 -> ssthresh max(2, 2), cwnd = ssthresh + resent.
        assert_eq!((f.k.ssthresh, f.k.cwnd, f.k.incr), (2, 4, 4 * MSS));
        let after = DEFAULT_SNMP.copy();
        assert_eq!(after.fast_retrans_segs - before.fast_retrans_segs, 2);
        assert_eq!(after.retrans_segs - before.retrans_segs, 2);
        assert_eq!(after.early_retrans_segs - before.early_retrans_segs, 0);
        assert_eq!(after.lost_segs - before.lost_segs, 0);
        assert_eq!(after.out_segs - before.out_segs, 3);
    }

    #[test]
    fn flush_fast_retransmit_rate_halving_uses_inflight() {
        let mut f = fixture();
        f.k.nodelay(-1, -1, 3, -1);
        f.k.cwnd = 32;
        for _ in 0..20 {
            in_flight(&mut f.k, FAR, 0);
        }
        f.k.snd_buf.peek_mut().unwrap().fastack = 3;
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!((f.k.ssthresh, f.k.cwnd, f.k.incr), (10, 13, 13 * MSS));
    }

    #[test]
    fn flush_fastresend_disabled_never_fast_retransmits() {
        let mut f = fixture();
        f.k.cwnd = 8;
        in_flight(&mut f.k, FAR, 1000);
        f.k.send(b"new"); // blocks early retransmit
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!(xmits(&f.k), vec![1, 1]);
        assert_eq!(fastacks(&f.k), vec![1000, 0]);
    }

    #[test]
    fn flush_early_retransmit_when_no_new_segments() {
        let _g = snmp_write();
        let before = DEFAULT_SNMP.copy();
        let mut f = fixture();
        f.k.nodelay(-1, -1, 3, -1);
        f.k.cwnd = 8;
        in_flight(&mut f.k, FAR, 1); // early retransmit (1 < fastresend 3)
        in_flight(&mut f.k, FAR, 0xFFFF_FFFF);
        in_flight(&mut f.k, FAR, 0);
        f.k.flush(IKCP_FLUSH_FULL);
        assert_eq!(cmds(&f.packets()), vec![(IKCP_CMD_PUSH, 0, T0)]);
        assert_eq!(xmits(&f.k), vec![2, 1, 1]);
        assert_eq!(fastacks(&f.k), vec![0xFFFF_FFFF, 0xFFFF_FFFF, 0]);
        assert_eq!(f.k.snd_buf.peek().unwrap().resendts, T0 + 200);
        // change > 0: inflight 3 -> ssthresh 2, cwnd 2 + 3.
        assert_eq!((f.k.ssthresh, f.k.cwnd), (2, 5));
        let after = DEFAULT_SNMP.copy();
        assert_eq!(after.early_retrans_segs - before.early_retrans_segs, 1);
        assert_eq!(after.retrans_segs - before.retrans_segs, 1);
        assert_eq!(after.fast_retrans_segs - before.fast_retrans_segs, 0);
    }

    #[test]
    fn flush_early_retransmit_with_fastresend_disabled_wraps_cwnd() {
        // resent = 0xFFFFFFFF, so Go's cwnd = ssthresh + resent wraps to ssthresh - 1.
        let mut f = fixture();
        f.k.cwnd = 8;
        in_flight(&mut f.k, FAR, 1);
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!(xmits(&f.k), vec![2]);
        assert_eq!((f.k.ssthresh, f.k.cwnd, f.k.incr), (2, 1, MSS));
    }

    #[test]
    fn flush_no_early_retransmit_when_new_segments_were_queued() {
        let mut f = fixture();
        f.k.nodelay(-1, -1, 3, -1);
        f.k.cwnd = 8;
        in_flight(&mut f.k, FAR, 1);
        f.k.send(b"new");
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!(xmits(&f.k), vec![1, 1]);
        assert_eq!(cmds(&f.packets()), vec![(IKCP_CMD_PUSH, 1, T0)]);
        assert_eq!(f.k.cwnd, 8, "no change");
    }

    #[test]
    fn flush_rto_retransmit_backs_off_and_collapses_cwnd() {
        let _g = snmp_write();
        let before = DEFAULT_SNMP.copy();
        let mut f = fixture();
        f.k.cwnd = 10;
        f.k.rx_rto = 150;
        in_flight(&mut f.k, T0, 0xFFFF_FFFF); // due exactly now
        in_flight(&mut f.k, T0 + 1, 0); // not due yet
        f.k.flush(IKCP_FLUSH_FULL);
        assert_eq!(cmds(&f.packets()), vec![(IKCP_CMD_PUSH, 0, T0)]);
        let g = f.k.snd_buf.peek().unwrap();
        // rto 200 + rx_rto; fastack reset to 0.
        assert_eq!(
            (g.xmit, g.rto, g.resendts, g.fastack),
            (2, 350, T0 + 350, 0)
        );
        // Loss: ssthresh = max(cwnd / 2, 2) of the flush window (min(32, 32, 10)), cwnd 1.
        assert_eq!((f.k.ssthresh, f.k.cwnd, f.k.incr), (5, 1, MSS));
        let after = DEFAULT_SNMP.copy();
        assert_eq!(after.lost_segs - before.lost_segs, 1);
        assert_eq!(after.retrans_segs - before.retrans_segs, 1);
        // The ring buffer gauges are updated on every flush.
        assert_eq!(after.ring_buffer_snd_buffer, 2);
        assert_eq!(after.ring_buffer_snd_queue, 0);
        assert_eq!(after.ring_buffer_rcv_queue, 0);
    }

    #[test]
    fn flush_rto_backoff_in_nodelay_mode_is_half_rx_rto() {
        let mut f = fixture();
        f.k.nodelay(1, -1, -1, -1);
        f.k.cwnd = 2;
        f.k.rx_rto = 150;
        in_flight(&mut f.k, T0 - 5, 0);
        f.flush(IKCP_FLUSH_FULL);
        let g = f.k.snd_buf.peek().unwrap();
        assert_eq!((g.rto, g.resendts), (275, T0 + 275));
        // ssthresh = max(2 / 2, 2)
        assert_eq!((f.k.ssthresh, f.k.cwnd), (2, 1));
    }

    #[test]
    fn flush_rto_with_nocwnd_keeps_cwnd() {
        let mut f = fixture();
        f.k.nodelay(-1, -1, -1, 1);
        f.k.cwnd = 10;
        f.k.ssthresh = 7;
        in_flight(&mut f.k, T0, 0);
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!(xmits(&f.k), vec![2]);
        assert_eq!((f.k.ssthresh, f.k.cwnd), (7, 10));
    }

    #[test]
    fn flush_loss_overrides_rate_halving_in_the_same_flush() {
        let mut f = fixture();
        f.k.nodelay(-1, -1, 2, -1);
        f.k.cwnd = 10;
        in_flight(&mut f.k, FAR, 2); // fast retransmit -> change
        in_flight(&mut f.k, T0, 0); // RTO -> lost
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!(xmits(&f.k), vec![2, 2]);
        assert_eq!((f.k.ssthresh, f.k.cwnd, f.k.incr), (5, 1, MSS));
    }

    #[test]
    fn flush_rto_hint_is_the_nearest_positive_resendts() {
        let mut f = fixture();
        f.k.cwnd = 8;
        f.k.nodelay(-1, 5000, -1, -1);
        in_flight(&mut f.k, T0 + 300, 0);
        in_flight(&mut f.k, T0 + 50, 0);
        in_flight(&mut f.k, T0 + 80, 0);
        assert_eq!(f.flush(IKCP_FLUSH_FULL), 50);
        f.k.nodelay(-1, 30, -1, -1);
        assert_eq!(f.flush(IKCP_FLUSH_FULL), 30, "capped at interval");
        // ACKONLY does not look at snd_buf.
        f.k.nodelay(-1, 5000, -1, -1);
        assert_eq!(f.flush(IKCP_FLUSH_ACKONLY), 5000);
    }

    #[test]
    fn flush_rto_hint_across_the_clock_wrap() {
        let mut f = fixture();
        f.clock.set(u32::MAX - 10);
        f.k.cwnd = 8;
        f.k.nodelay(-1, 5000, -1, -1);
        in_flight(&mut f.k, 39, 0);
        assert_eq!(f.flush(IKCP_FLUSH_FULL), 50);
        assert!(f.packets().is_empty());
        f.clock.set(39);
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!(xmits(&f.k), vec![2]);
    }

    #[test]
    fn flush_dead_link_marks_state() {
        let mut f = fixture();
        f.k.cwnd = 8;
        f.k.dead_link = 3;
        in_flight(&mut f.k, T0, 0);
        f.k.snd_buf.peek_mut().unwrap().xmit = 1;
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!((xmits(&f.k), f.k.state), (vec![2], 0));
        f.clock.set(f.k.snd_buf.peek().unwrap().resendts);
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!((xmits(&f.k), f.k.state), (vec![3], 0xFFFF_FFFF));
        // The segment keeps being retransmitted; the session layer acts on the state.
        f.clock.set(f.k.snd_buf.peek().unwrap().resendts);
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!(xmits(&f.k), vec![4]);
    }

    #[test]
    fn flush_dead_link_on_initial_transmit() {
        let mut f = fixture();
        f.k.cwnd = 8;
        f.k.dead_link = 1;
        f.k.send(b"a");
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!(f.k.state, 0xFFFF_FFFF);
    }

    #[test]
    fn flush_retransmission_uses_the_current_window_and_una() {
        let mut f = fixture();
        f.k.cwnd = 8;
        in_flight(&mut f.k, T0, 0);
        f.k.rcv_nxt = 42;
        f.k.rcv_queue.push(Segment::default());
        f.k.rcv_queue.push(Segment::default());
        f.flush(IKCP_FLUSH_FULL);
        let pkts = f.packets();
        let (h, data) = &segs(&pkts[0])[0];
        assert_eq!((h.wnd, h.una, h.ts, h.sn), (30, 42, T0, 0));
        assert_eq!(data, &vec![0u8; 10]);
        let g = f.k.snd_buf.peek().unwrap();
        assert_eq!((g.wnd, g.una, g.ts), (30, 42, T0));
    }

    #[test]
    fn flush_updates_ring_buffer_gauges() {
        let _g = snmp_write();
        let mut f = fixture();
        f.k.cwnd = 1;
        f.k.send(b"a");
        f.k.send(b"b");
        f.k.send(b"c");
        f.k.rcv_queue.push(Segment::default());
        f.k.flush(IKCP_FLUSH_ACKONLY);
        let s = DEFAULT_SNMP.copy();
        assert_eq!(
            (
                s.ring_buffer_snd_queue,
                s.ring_buffer_rcv_queue,
                s.ring_buffer_snd_buffer
            ),
            (2, 1, 1)
        );
    }

    // ---- update / check ----

    #[test]
    fn update_first_call_flushes_and_schedules() {
        let mut f = fixture();
        {
            let _g = snmp_read();
            f.k.update();
        }
        assert_eq!((f.k.updated, f.k.ts_flush), (1, T0 + IKCP_INTERVAL));
        assert_eq!(f.k.flush_calls.len(), 1);
        assert_eq!(f.k.flush_calls[0].flush_type, IKCP_FLUSH_FULL);

        // Not due yet.
        f.clock.set(T0 + 99);
        {
            let _g = snmp_read();
            f.k.update();
        }
        assert_eq!(f.k.flush_calls.len(), 1);

        // Due: ts_flush advances by one interval.
        f.clock.set(T0 + 150);
        {
            let _g = snmp_read();
            f.k.update();
        }
        assert_eq!((f.k.flush_calls.len(), f.k.ts_flush), (2, T0 + 200));

        // Late by more than an interval: rescheduled from now.
        f.clock.set(T0 + 450);
        {
            let _g = snmp_read();
            f.k.update();
        }
        assert_eq!((f.k.flush_calls.len(), f.k.ts_flush), (3, T0 + 550));
    }

    #[test]
    fn update_resynchronises_after_large_jumps() {
        let mut f = fixture();
        let _g = snmp_read();
        f.k.update();
        // 10 s late or more: slap reset to 0, flush now, next at now + interval.
        f.clock.set(T0 + 100 + 10_000);
        f.k.update();
        assert_eq!(f.k.ts_flush, T0 + 10_100 + 100);
        assert_eq!(f.k.flush_calls.len(), 2);
        // 9999 ms late: normal path (ts_flush += interval, then rescheduled from now).
        f.clock.set(f.k.ts_flush + 9_999);
        let now = f.clock.get();
        f.k.update();
        assert_eq!(f.k.ts_flush, now + 100);
        // Clock went back by more than 10 s: resynchronised and flushed.
        let back = f.k.ts_flush.wrapping_sub(10_001);
        f.clock.set(back);
        f.k.update();
        assert_eq!((f.k.ts_flush, f.k.flush_calls.len()), (back + 100, 4));
        // Back by less than 10 s: nothing.
        f.clock.set(back + 100 - 9_999);
        f.k.update();
        assert_eq!(f.k.flush_calls.len(), 4);
    }

    #[test]
    fn update_sends_queued_data() {
        let mut f = fixture();
        f.k.send(b"hi");
        let _g = snmp_read();
        f.k.update(); // cwnd 0 -> 1
        f.clock.set(T0 + 100);
        f.k.update();
        assert_eq!(cmds(&f.packets()), vec![(IKCP_CMD_PUSH, 0, T0 + 100)]);
    }

    #[test]
    fn check_branches() {
        let mut f = fixture();
        assert_eq!(f.k.check(), T0, "before the first update");
        f.k.updated = 1;
        f.k.ts_flush = T0 + 60;
        assert_eq!(f.k.check(), T0 + 60, "next flush");
        f.k.ts_flush = T0;
        assert_eq!(f.k.check(), T0, "flush due");
        f.k.ts_flush = T0 + 20_000;
        assert_eq!(f.k.check(), T0, "far future ts_flush is resynchronised");
        f.k.ts_flush = T0.wrapping_sub(20_000);
        assert_eq!(f.k.check(), T0, "far past");
        f.k.ts_flush = T0 + 9_999;
        assert_eq!(f.k.check(), T0 + IKCP_INTERVAL, "capped at interval");

        f.k.ts_flush = T0 + 60;
        in_flight(&mut f.k, T0 + 30, 0);
        in_flight(&mut f.k, T0 + 40, 0);
        assert_eq!(f.k.check(), T0 + 30, "nearest resendts");
        // Go also looks at acknowledged segments.
        in_flight(&mut f.k, T0, 0);
        f.k.snd_buf.iter_mut().last().unwrap().acked = 1;
        assert_eq!(f.k.check(), T0, "a segment is due");
        f.k.snd_buf.iter_mut().last().unwrap().resendts = T0 + 90;
        f.k.ts_flush = T0 + 20;
        assert_eq!(f.k.check(), T0 + 20, "flush before any resend");
        f.k.ts_flush = T0 + 30;
        assert_eq!(f.k.check(), T0 + 30, "tie");
    }

    #[test]
    fn check_does_not_change_state_and_wraps() {
        let mut f = fixture();
        f.clock.set(u32::MAX - 5);
        f.k.updated = 1;
        f.k.ts_flush = 20;
        assert_eq!(f.k.check(), 20);
        assert_eq!(f.k.ts_flush, 20);
    }

    #[cfg(feature = "trace")]
    #[test]
    fn trace_logger_receives_output_events() {
        use std::sync::Mutex;
        let events: Arc<Mutex<Vec<String>>> = Arc::default();
        let mut f = fixture();
        let sink = Arc::clone(&events);
        f.k.set_logger(
            IKCP_LOG_OUTPUT_ALL,
            Some(Box::new(move |msg, args| {
                let kv: Vec<String> = args.iter().map(|(k, v)| format!("{k}={v:?}")).collect();
                sink.lock()
                    .expect("lock")
                    .push(format!("{msg} {}", kv.join(" ")));
            })),
        );
        f.k.cwnd = 4;
        f.k.rcv_nxt = 2;
        f.k.acklist = vec![AckItem { sn: 1, ts: 5 }, AckItem { sn: 2, ts: 6 }];
        f.k.probe = IKCP_ASK_SEND | IKCP_ASK_TELL;
        f.k.send(b"abc");
        f.flush(IKCP_FLUSH_FULL);
        assert_eq!(
            *events.lock().expect("lock"),
            vec![
                "[KCP OUTPUT ACK] conv=16909060 sn=2 una=2 ts=6",
                "[KCP OUTPUT WASK] conv=16909060 wnd=32 ts=6",
                "[KCP OUTPUT WINS] conv=16909060 wnd=32 ts=6",
                "[KCP OUTPUT PUSH] conv=16909060 sn=0 frg=0 una=2 ts=1000 xmit=1 datalen=3",
            ]
        );
    }
}

#[cfg(test)]
mod trace_tests;

#[cfg(test)]
mod sim_tests;

#[cfg(test)]
mod backpressure_tests;

#[cfg(test)]
mod scan_tests;

#[cfg(test)]
mod ack_index_tests;
