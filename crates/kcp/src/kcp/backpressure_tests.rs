//! Tx-channel backpressure: [`Output::capacity`] and what [`Kcp::flush`] does with it
//! (**Deviation V18**, plan step 12.2a).
//!
//! The session hands every packet to a bounded channel ([`crate::tx`]). Go drops what does not
//! fit, *after* KCP has marked the segment as transmitted, so each dropped packet of a burst
//! costs a retransmission timeout — with `-sndwnd 8192` one `flush()` can emit four times the
//! channel's depth. `flush` therefore stops before touching a segment it cannot hand over, and
//! keeps the acks and probe bits it could not write out.
//!
//! The tests here model that channel exactly ([`TxChannel`]): a queue of at most `limit`
//! packets, drained by a "tx task" at a fixed rate, with the three policies that matter —
//! [`Policy::Unbounded`] (every other `Output` in the crate, which never drops and reports
//! [`usize::MAX`]), [`Policy::Drop`] (Go's, and this port's before V18) and
//! [`Policy::Backpressure`] (V18).
//!
//! Three things are checked:
//!
//! 1. **Inertness** — a channel that never fills up must behave exactly like no channel at all:
//!    the same packets, byte for byte, and the same state after randomised two-endpoint traces
//!    over a lossy, reordering link (DECISIONS D25; the golden traces of [`super::trace_tests`]
//!    and the pinned summaries of [`super::sim_tests`] cover the same ground against Go).
//! 2. **Nothing is lost** — an ack, a window probe or a segment that does not fit is deferred,
//!    not dropped, and a deferred segment is left bit-for-bit as it was.
//! 3. **The cliff is gone** — the same bulk transfer that spends its time in retransmission
//!    timeouts under [`Policy::Drop`] runs without a single retransmission under
//!    [`Policy::Backpressure`].

use super::*;
use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};
use std::rc::Rc;
use std::sync::RwLockReadGuard;

use kcptun_testkit::VirtualClock;
use kcptun_testkit::netsim::{Duplex, LinkConfig};

use super::trace_tests::{state_digest, state_words};

/// These tests only read the process-global SNMP counters; tests asserting exact deltas hold
/// the write lock (see [`SNMP_TEST_LOCK`]).
fn snmp_read() -> RwLockReadGuard<'static, ()> {
    SNMP_TEST_LOCK.read().unwrap_or_else(|e| e.into_inner())
}

/// What an [`Output`] does when its queue is full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Policy {
    /// No bound at all: what every `Output` in the crate but the session's is.
    Unbounded,
    /// Go's `sess.go` output callback (and this port before V18): report unlimited room and
    /// drop whatever does not fit.
    Drop,
    /// Deviation V18: report the free slots, so that `flush` stops emitting in time.
    Backpressure,
}

/// The session's packet channel (`crate::tx`) as a test [`Output`].
#[derive(Debug)]
struct ChannelState {
    queue: VecDeque<Vec<u8>>,
    limit: usize,
    policy: Policy,
    /// Packets the channel refused (Go's silent drop).
    dropped: u64,
    /// Deepest the queue ever got.
    high_water: usize,
    /// PUSH sequence numbers `output` has seen, and how many it saw twice — KCP's own view of
    /// a retransmission, which counts the packets the channel then threw away too.
    push_sns: HashSet<u32>,
    retrans: u64,
}

/// Handle on a [`ChannelState`]: the `Kcp` owns one, the "tx task" of the simulation the other.
#[derive(Clone, Debug)]
struct TxChannel(Rc<RefCell<ChannelState>>);

impl TxChannel {
    fn new(policy: Policy, limit: usize) -> TxChannel {
        TxChannel(Rc::new(RefCell::new(ChannelState {
            queue: VecDeque::new(),
            limit: if policy == Policy::Unbounded {
                usize::MAX
            } else {
                limit
            },
            policy,
            dropped: 0,
            high_water: 0,
            push_sns: HashSet::new(),
            retrans: 0,
        })))
    }

    /// The "tx task": takes up to `n` packets off the queue.
    fn drain(&self, n: usize) -> Vec<Vec<u8>> {
        let mut state = self.0.borrow_mut();
        let n = n.min(state.queue.len());
        state.queue.drain(..n).collect()
    }

    fn queued(&self) -> usize {
        self.0.borrow().queue.len()
    }

    fn dropped(&self) -> u64 {
        self.0.borrow().dropped
    }

    fn high_water(&self) -> usize {
        self.0.borrow().high_water
    }

    /// PUSH segments KCP handed to the output more than once.
    fn retrans(&self) -> u64 {
        self.0.borrow().retrans
    }
}

impl Output for TxChannel {
    fn output(&mut self, buf: &[u8]) {
        let mut state = self.0.borrow_mut();
        for h in headers(buf) {
            if h.cmd == IKCP_CMD_PUSH && !state.push_sns.insert(h.sn) {
                state.retrans += 1;
            }
        }
        if state.queue.len() >= state.limit {
            state.dropped += 1;
            return;
        }
        state.queue.push_back(buf.to_vec());
        state.high_water = state.high_water.max(state.queue.len());
    }

    fn capacity(&self) -> usize {
        let state = self.0.borrow();
        match state.policy {
            // Go reports nothing, so `flush` cannot know; it fills the buffer and loses the rest.
            Policy::Unbounded | Policy::Drop => usize::MAX,
            Policy::Backpressure => state.limit - state.queue.len(),
        }
    }
}

/// The virtual clock as a [`Clock`], the way [`super::sim_tests`] injects it.
type SimClock = Box<dyn Fn() -> u32 + Send + Sync>;
type TestKcp = Kcp<TxChannel, SimClock>;

fn sim_clock(vc: &VirtualClock) -> SimClock {
    let vc = vc.clone();
    Box::new(move || vc.now_ms())
}

const CONV: u32 = 0x0102_0304;
const T0: u64 = 1000;

/// A KCP at `T0` ms whose output is a channel of `limit` packets under `policy`.
fn fixture(policy: Policy, limit: usize) -> (TestKcp, TxChannel, VirtualClock) {
    let clock = VirtualClock::starting_at(T0);
    let chan = TxChannel::new(policy, limit);
    let kcp = Kcp::with_clock(CONV, chan.clone(), sim_clock(&clock));
    (kcp, chan, clock)
}

/// Decodes every segment header of a packet.
fn headers(pkt: &[u8]) -> Vec<SegmentHeader> {
    let mut v = Vec::new();
    let mut rest = pkt;
    while let Some((h, tail)) = SegmentHeader::decode(rest) {
        v.push(h);
        rest = &tail[h.len as usize..];
    }
    assert!(rest.is_empty(), "trailing bytes in an output packet");
    v
}

/// `(cmd, sn)` of every segment of every queued packet.
fn queued_segments(chan: &TxChannel) -> Vec<(u8, u32)> {
    chan.0
        .borrow()
        .queue
        .iter()
        .flat_map(|p| headers(p))
        .map(|h| (h.cmd, h.sn))
        .collect()
}

/// `(xmit, rto, resendts, fastack, ts)` of every segment in the send buffer.
fn snd_buf_state(k: &TestKcp) -> Vec<(u32, u32, u32, u32, u32)> {
    k.snd_buf
        .iter()
        .map(|s| (s.xmit, s.rto, s.resendts, s.fastack, s.ts))
        .collect()
}

// ---------------------------------------------------------------------------------------
// Acks
// ---------------------------------------------------------------------------------------

/// Acks that do not fit are kept in `acklist` instead of being dropped, and go out on the next
/// flush. Go clears the whole list whether or not its packets made it out.
#[test]
fn acks_that_do_not_fit_are_kept_for_the_next_flush() {
    let _g = snmp_read();
    // 1400 bytes of MTU hold 58 acks. With three free slots the loop writes two full packets
    // and stops with one slot left, which the trailing `flush_buffer` uses for the ack it had
    // already started a third packet with: three packets out, none dropped.
    let (mut k, chan, _clock) = fixture(Policy::Backpressure, 3);
    let acks_per_packet = (k.mtu / IKCP_OVERHEAD) as usize;
    let total = acks_per_packet * 4;
    k.rcv_nxt = 1;
    for sn in 1..=total as u32 {
        k.acklist.push(AckItem { sn, ts: 100 + sn });
    }

    k.flush(IKCP_FLUSH_ACKONLY);
    let written = 2 * acks_per_packet + 1;
    assert_eq!(chan.queued(), 3, "three free slots, three packets");
    assert_eq!(chan.dropped(), 0, "no ack may be dropped");
    assert_eq!(
        k.acklist.len(),
        total - written,
        "the acks that did not fit are still pending"
    );
    assert_eq!(
        k.acklist[0],
        AckItem {
            sn: written as u32 + 1,
            ts: 100 + written as u32 + 1,
        },
        "the pending list resumes exactly where the flush stopped"
    );

    // The tx task drains, and the rest goes out over the following flushes.
    let mut sent: Vec<(u8, u32)> = Vec::new();
    for _ in 0..8 {
        for pkt in chan.drain(16) {
            sent.extend(headers(&pkt).iter().map(|h| (h.cmd, h.sn)));
        }
        k.flush(IKCP_FLUSH_ACKONLY);
    }
    for pkt in chan.drain(16) {
        sent.extend(headers(&pkt).iter().map(|h| (h.cmd, h.sn)));
    }
    assert!(k.acklist.is_empty(), "every ack was eventually written");
    assert_eq!(chan.dropped(), 0);
    let want: Vec<(u8, u32)> = (1..=total as u32).map(|sn| (IKCP_CMD_ACK, sn)).collect();
    assert_eq!(sent, want, "every ack goes out exactly once, in order");
}

/// The same flush with Go's policy: the surplus acks are written into packets that the channel
/// throws away, and `acklist` is cleared regardless — the peer never hears about them.
#[test]
fn go_drops_the_acks_that_do_not_fit() {
    let _g = snmp_read();
    let (mut k, chan, _clock) = fixture(Policy::Drop, 3);
    let acks_per_packet = (k.mtu / IKCP_OVERHEAD) as usize;
    let total = acks_per_packet * 4;
    k.rcv_nxt = 1;
    for sn in 1..=total as u32 {
        k.acklist.push(AckItem { sn, ts: 100 + sn });
    }

    k.flush(IKCP_FLUSH_ACKONLY);
    assert_eq!(chan.queued(), 3);
    assert_eq!(chan.dropped(), 1, "the fourth packet of acks is lost");
    assert!(k.acklist.is_empty(), "Go clears the list either way");
}

/// An `acklist` that does not fill a whole packet is still written out completely, and the
/// bufferbloat filter (old acks are skipped, except the last) counts a skipped ack as handled.
#[test]
fn a_short_acklist_is_flushed_in_one_go_and_old_acks_are_still_filtered() {
    let _g = snmp_read();
    let (mut k, chan, _clock) = fixture(Policy::Backpressure, 8);
    k.rcv_nxt = 100;
    for sn in [10, 20, 100, 101] {
        k.acklist.push(AckItem { sn, ts: sn });
    }

    k.flush(IKCP_FLUSH_ACKONLY);
    assert!(k.acklist.is_empty());
    assert_eq!(chan.dropped(), 0);
    assert_eq!(
        queued_segments(&chan),
        vec![(IKCP_CMD_ACK, 100), (IKCP_CMD_ACK, 101)],
        "the two stale acks are filtered, as they are without backpressure"
    );
}

// ---------------------------------------------------------------------------------------
// Window probes
// ---------------------------------------------------------------------------------------

/// A window probe that does not fit keeps its bit in `probe` and goes out on the next flush;
/// Go clears `probe` and loses it until `probe_wait` fires again (up to 120 s).
#[test]
fn window_probes_that_do_not_fit_keep_their_bit() {
    let _g = snmp_read();
    let (mut k, chan, _clock) = fixture(Policy::Backpressure, 1);
    k.rmt_wnd = 0;
    k.probe = IKCP_ASK_SEND | IKCP_ASK_TELL;

    k.flush(IKCP_FLUSH_FULL);
    assert_eq!(chan.queued(), 0, "one free slot is not enough room");
    assert_eq!(chan.dropped(), 0);
    assert_eq!(
        k.probe,
        IKCP_ASK_SEND | IKCP_ASK_TELL,
        "both probes are still pending"
    );

    // With room, both go out and the bits are cleared exactly as Go's `kcp.probe = 0` does.
    let (mut k, chan, _clock) = fixture(Policy::Backpressure, 8);
    k.rmt_wnd = 0;
    k.probe = IKCP_ASK_SEND | IKCP_ASK_TELL;
    k.flush(IKCP_FLUSH_FULL);
    assert_eq!(
        queued_segments(&chan),
        vec![(IKCP_CMD_WASK, 0), (IKCP_CMD_WINS, 0)]
    );
    assert_eq!(k.probe, 0);
}

// ---------------------------------------------------------------------------------------
// Segments
// ---------------------------------------------------------------------------------------

/// A segment that does not fit is left **untouched** — no `xmit`, no `rto`, no `resendts`, no
/// `ts` — so the next flush sends it as the initial transmit it still is.
#[test]
fn a_deferred_segment_is_not_marked_as_transmitted() {
    let _g = snmp_read();
    // One mss-sized segment per packet, four free slots: the loop writes three and stops with
    // one slot left, which the trailing `flush_buffer` uses for the fourth.
    let (mut k, chan, _clock) = fixture(Policy::Backpressure, 4);
    k.wnd_size(64, 64);
    k.rmt_wnd = 64;
    k.nocwnd = 1;
    for i in 0..16u32 {
        assert_eq!(k.send(&vec![i as u8; k.mss as usize]), 0);
    }

    k.flush(IKCP_FLUSH_FULL);
    assert_eq!(chan.dropped(), 0, "backpressure never drops");
    assert_eq!(chan.queued(), 4);
    assert_eq!(
        k.snd_buf.len(),
        16,
        "the whole window still moves into snd_buf, as in Go"
    );
    let state = snd_buf_state(&k);
    for (i, s) in state.iter().enumerate() {
        if i < 4 {
            assert_eq!(s.0, 1, "segment {i} was sent once");
        } else {
            assert_eq!(
                *s,
                (0, 0, 0, 0, 0),
                "segment {i} must be untouched: no xmit, rto, resendts, fastack or ts"
            );
        }
    }

    // Drain and flush again: the deferred segments are initial transmits, not retransmissions.
    let mut sns: Vec<u32> = chan
        .drain(usize::MAX)
        .iter()
        .flat_map(|p| headers(p))
        .map(|h| h.sn)
        .collect();
    for _ in 0..8 {
        k.flush(IKCP_FLUSH_FULL);
        sns.extend(
            chan.drain(usize::MAX)
                .iter()
                .flat_map(|p| headers(p))
                .map(|h| h.sn),
        );
    }
    assert_eq!(sns, (0..16).collect::<Vec<u32>>(), "each sn sent once");
    assert!(
        k.snd_buf.iter().all(|s| s.xmit == 1),
        "no segment was transmitted twice"
    );
    assert_eq!(chan.dropped(), 0);
}

/// Go's policy on the same trace: the segments the channel refuses are marked as transmitted
/// and their `resendts` is set, so they are only sent again a retransmission timeout later —
/// and then count as losses.
#[test]
fn go_marks_dropped_segments_as_transmitted() {
    let _g = snmp_read();
    let (mut k, chan, clock) = fixture(Policy::Drop, 4);
    k.wnd_size(64, 64);
    k.rmt_wnd = 64;
    k.nocwnd = 1;
    for i in 0..16u32 {
        assert_eq!(k.send(&vec![i as u8; k.mss as usize]), 0);
    }

    k.flush(IKCP_FLUSH_FULL);
    assert_eq!(chan.queued(), 4);
    assert_eq!(chan.dropped(), 12, "twelve packets are silently lost");
    assert!(
        k.snd_buf.iter().all(|s| s.xmit == 1),
        "KCP believes it sent all sixteen"
    );

    // Nothing more goes out until the RTO of those segments expires.
    chan.drain(usize::MAX);
    k.flush(IKCP_FLUSH_FULL);
    assert_eq!(chan.queued(), 0, "the lost segments are not due yet");
    let rto = k.snd_buf.iter().next().expect("snd_buf").rto;
    clock.advance(u64::from(rto) + 1);
    k.flush(IKCP_FLUSH_FULL);
    assert!(
        chan.queued() > 0,
        "only the retransmission timeout puts them back on the wire"
    );
    assert!(
        k.snd_buf.iter().take(4).all(|s| s.xmit == 2),
        "and they count as retransmissions"
    );
}

/// With room for everything, backpressure changes nothing: same packets, same segment state as
/// an unbounded output.
#[test]
fn a_flush_that_fits_is_identical_to_an_unbounded_output() {
    let _g = snmp_read();
    let mut runs = Vec::new();
    for policy in [Policy::Unbounded, Policy::Backpressure] {
        let (mut k, chan, _clock) = fixture(policy, 4096);
        k.wnd_size(64, 64);
        k.rmt_wnd = 64;
        k.nocwnd = 1;
        for i in 0..16u32 {
            assert_eq!(k.send(&vec![i as u8; 700]), 0);
        }
        let interval = k.flush(IKCP_FLUSH_FULL);
        runs.push((
            interval,
            chan.drain(usize::MAX),
            snd_buf_state(&k),
            state_words(&k),
        ));
    }
    assert_eq!(runs[0].0, runs[1].0, "same next-update hint");
    assert_eq!(runs[0].1, runs[1].1, "byte-identical packets");
    assert_eq!(runs[0].2, runs[1].2, "identical send-buffer state");
    assert_eq!(runs[0].3, runs[1].3, "identical KCP state");
}

/// `Output::capacity` is only consulted for segments that would actually go out: a flush that
/// sends nothing (everything acked, nothing due) must not stop early even with a full channel.
#[test]
fn a_full_channel_does_not_stop_a_flush_that_sends_nothing() {
    let _g = snmp_read();
    let (mut k, chan, clock) = fixture(Policy::Backpressure, 2);
    k.wnd_size(64, 64);
    k.rmt_wnd = 64;
    k.nocwnd = 1;
    k.interval = 500; // above the RTO, so that the RTO is the number flush returns
    for i in 0..4u32 {
        assert_eq!(k.send(&[i as u8; 100]), 0);
    }
    k.flush(IKCP_FLUSH_FULL);
    assert_eq!(chan.queued(), 1, "all four segments fit into one packet");

    // The channel now has one free slot (below OUTPUT_ROOM), but nothing is due: the flush
    // still returns the nearest RTO, which is what the session schedules on.
    clock.advance(50);
    let rto = k.snd_buf.iter().next().expect("snd_buf").rto;
    let next = k.flush(IKCP_FLUSH_FULL);
    assert_eq!(chan.queued(), 1, "nothing was sent");
    assert_eq!(chan.dropped(), 0);
    assert_eq!(next, rto - 50, "the nearest retransmission timeout");
}

/// Even when it stops early, the flush keeps reporting the nearest retransmission timeout of
/// the segments it did not reach, so the session's timer is unchanged.
#[test]
fn a_backpressured_flush_still_reports_the_nearest_rto() {
    let _g = snmp_read();
    let (mut k, chan, clock) = fixture(Policy::Backpressure, 3);
    k.wnd_size(64, 64);
    k.rmt_wnd = 64;
    k.nocwnd = 1;
    k.interval = 500; // above the RTO, so that the RTO is the number flush returns
    for i in 0..8u32 {
        assert_eq!(k.send(&vec![i as u8; k.mss as usize]), 0);
    }
    // Three packets go out; the rest is deferred, with resendts still 0.
    k.flush(IKCP_FLUSH_FULL);
    assert_eq!(chan.queued(), 3);
    let rto = k.snd_buf.iter().next().expect("snd_buf").rto;

    // A flush 10 ms later still has no room, and the sent segments' RTO is the nearest event.
    clock.advance(10);
    let next = k.flush(IKCP_FLUSH_FULL);
    assert_eq!(chan.queued(), 3, "still no room");
    assert_eq!(
        next,
        rto - 10,
        "the hint comes from the segments the flush did send"
    );
}

// ---------------------------------------------------------------------------------------
// Two endpoints over a link
// ---------------------------------------------------------------------------------------

/// One endpoint of [`run_sim`].
struct Endpoint {
    kcp: TestKcp,
    chan: TxChannel,
    next_flush: u64,
    /// Every packet that left the channel, in order.
    wire: Vec<Vec<u8>>,
    to_send: Vec<u8>,
    sent: usize,
    received: Vec<u8>,
    /// What every `flush` on this endpoint returned, in order.
    next_update: Vec<u32>,
}

/// One simulation: two endpoints, each sending `payload` bytes to the other over a `Duplex`
/// link, with their output channels drained at `drain` packets per virtual millisecond.
#[derive(Clone, Copy, Debug)]
pub(super) struct SimCfg {
    pub(super) seed: u64,
    pub(super) policy: Policy,
    /// Depth of each endpoint's channel.
    pub(super) limit: usize,
    /// Packets the "tx task" moves onto the link per virtual millisecond.
    pub(super) drain: usize,
    pub(super) payload: usize,
    /// Bytes per `Write` call.
    pub(super) chunk: usize,
    pub(super) snd_wnd: isize,
    pub(super) rcv_wnd: isize,
    pub(super) nodelay: [isize; 4],
    pub(super) loss: f64,
    pub(super) delay: u64,
    pub(super) ack_no_delay: bool,
    /// Decision D29: whether `flush` may skip the part of `snd_buf` it has already scanned.
    /// `false` is the naive line-by-line scan, the permanent oracle of DECISIONS D25.
    pub(super) fast_path: bool,
}

impl SimCfg {
    /// kcptun's production profile, scaled down: `-mode normal`-like timings, no congestion
    /// window, windows large enough that one flush overruns a small channel.
    pub(super) fn production(seed: u64, policy: Policy) -> SimCfg {
        SimCfg {
            seed,
            policy,
            limit: 128,
            drain: 16,
            payload: 1024 * 1024,
            chunk: 64 * 1024,
            snd_wnd: 1024,
            rcv_wnd: 1024,
            nodelay: [0, 40, 2, 1],
            loss: 0.0,
            delay: 5,
            ack_no_delay: false,
            fast_path: true,
        }
    }
}

/// What one [`run_sim`] did.
pub(super) struct SimResult {
    pub(super) end_ms: u64,
    pub(super) wire: [Vec<Vec<u8>>; 2],
    pub(super) state: [[u32; 32]; 2],
    /// Per endpoint: the whole state, segment by segment — what Decision D31's `parse_ack`
    /// and `parse_fastack` write, which the scalar words above do not cover.
    pub(super) digest: [u64; 2],
    pub(super) retrans: [u64; 2],
    pub(super) dropped: [u64; 2],
    pub(super) high_water: [usize; 2],
    /// Per endpoint: full flushes that skipped part of `snd_buf`, and segments skipped.
    pub(super) scan_skipped: [(u64, u64); 2],
    /// Per endpoint: what the ACK path made of `snd_buf` (Decision D31).
    pub(super) ack_index: [AckIndex; 2],
    /// Per endpoint: what every `flush` returned, in order — the scheduling hint, which the
    /// D29 skip must reproduce exactly.
    pub(super) next_update: [Vec<u32>; 2],
}

/// Runs `cfg` to completion (both endpoints have received the whole payload) on a virtual
/// clock, stepping one millisecond at a time. Panics if that takes more than `limit_ms`.
pub(super) fn run_sim(cfg: SimCfg, limit_ms: u64) -> SimResult {
    let clock = VirtualClock::new();
    let mut link = Duplex::symmetric(
        LinkConfig::new(cfg.seed)
            .delay(cfg.delay)
            .loss(cfg.loss)
            .reorder(if cfg.loss > 0.0 { 0.05 } else { 0.0 }, 7),
    );
    let mut eps: Vec<Endpoint> = (0..2)
        .map(|i| {
            let chan = TxChannel::new(cfg.policy, cfg.limit);
            let mut kcp = Kcp::with_clock(CONV, chan.clone(), sim_clock(&clock));
            assert_eq!(kcp.set_mtu(1400), 0);
            let [nd, iv, rs, nc] = cfg.nodelay;
            kcp.nodelay(nd, iv, rs, nc);
            kcp.wnd_size(cfg.snd_wnd, cfg.rcv_wnd);
            kcp.stream = 1;
            kcp.flush_scan.enabled = cfg.fast_path;
            // A deterministic, endpoint-specific byte stream.
            let to_send: Vec<u8> = (0..cfg.payload)
                .map(|n| (n as u64).wrapping_mul(0x9E37_79B9).wrapping_add(i as u64) as u8)
                .collect();
            Endpoint {
                kcp,
                chan,
                next_flush: 0,
                wire: Vec::new(),
                to_send,
                sent: 0,
                received: Vec::new(),
                next_update: Vec::new(),
            }
        })
        .collect();

    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let now = clock.now_ms_u64();

        // 1. The tx task of each endpoint: drain the channel onto the link.
        for (i, ep) in eps.iter_mut().enumerate() {
            for pkt in ep.chan.drain(cfg.drain) {
                let out = if i == 0 {
                    &mut link.a_to_b
                } else {
                    &mut link.b_to_a
                };
                out.send(now, &pkt);
                ep.wire.push(pkt);
            }
        }

        // 2. Delivery.
        for (i, ep) in eps.iter_mut().enumerate() {
            let pkts = if i == 0 {
                link.b_to_a.poll(now)
            } else {
                link.a_to_b.poll(now)
            };
            for pkt in pkts {
                ep.kcp.input(&pkt, IKCP_PACKET_REGULAR, cfg.ack_no_delay);
            }
        }

        // 3. The application: read everything, then write while the window allows it
        //    (`UDPSession.Read`/`Write` with writeDelay off, so every write flushes).
        for ep in eps.iter_mut() {
            while ep.kcp.peek_size() > 0 {
                let n = ep.kcp.recv(&mut buf);
                assert!(n > 0, "recv returned {n}");
                ep.received.extend_from_slice(&buf[..n as usize]);
            }
            let mut wrote = false;
            while ep.sent < ep.to_send.len()
                && ep.kcp.wait_snd() < ep.kcp.snd_wnd as usize
                && !wrote
            {
                let end = (ep.sent + cfg.chunk).min(ep.to_send.len());
                let mut data = &ep.to_send[ep.sent..end];
                let mss = ep.kcp.mss as usize;
                while !data.is_empty() {
                    let n = data.len().min(mss);
                    assert_eq!(ep.kcp.send(&data[..n]), 0);
                    data = &data[n..];
                }
                ep.sent = end;
                wrote = true;
            }
            if wrote {
                let next = ep.kcp.flush(IKCP_FLUSH_FULL);
                ep.next_update.push(next);
            }
        }

        // 4. The update timer.
        for ep in eps.iter_mut() {
            if ep.next_flush <= now {
                let interval = ep.kcp.flush(IKCP_FLUSH_FULL);
                ep.next_update.push(interval);
                ep.next_flush = now + u64::from(interval);
            }
        }

        if eps
            .iter()
            .all(|ep| ep.received.len() == ep.to_send.len() && ep.chan.queued() == 0)
        {
            break;
        }
        assert!(now < limit_ms, "not finished after {limit_ms} ms");
        clock.set(now + 1);
    }

    for (i, ep) in eps.iter().enumerate() {
        assert_eq!(
            ep.received,
            eps[1 - i].to_send,
            "endpoint {i} received corrupted data"
        );
    }
    let end_ms = clock.now_ms_u64();
    SimResult {
        end_ms,
        wire: [eps[0].wire.clone(), eps[1].wire.clone()],
        state: [state_words(&eps[0].kcp), state_words(&eps[1].kcp)],
        digest: [state_digest(&eps[0].kcp), state_digest(&eps[1].kcp)],
        retrans: [eps[0].chan.retrans(), eps[1].chan.retrans()],
        dropped: [eps[0].chan.dropped(), eps[1].chan.dropped()],
        high_water: [eps[0].chan.high_water(), eps[1].chan.high_water()],
        scan_skipped: [eps[0].kcp.scan_skipped, eps[1].kcp.scan_skipped],
        ack_index: [eps[0].kcp.ack_index, eps[1].kcp.ack_index],
        next_update: [eps[0].next_update.clone(), eps[1].next_update.clone()],
    }
}

/// The defect V13 recorded, end to end: with Go's policy a send window four times the channel's
/// depth spends the transfer in retransmission timeouts; with backpressure not one segment is
/// sent twice, and the same bytes arrive in a fraction of the time.
#[test]
fn backpressure_removes_the_retransmission_cliff_of_a_large_send_window() {
    let _g = snmp_read();
    let drop = run_sim(SimCfg::production(7, Policy::Drop), 600_000);
    let back = run_sim(SimCfg::production(7, Policy::Backpressure), 600_000);

    // 1 MiB in 1376-byte segments is 763 of them, and Go's policy has to send nine out of ten
    // twice: the first flush of each burst emits a whole 1024-segment window, the channel takes
    // 128 and the rest is dropped after KCP has already counted it as transmitted.
    assert!(
        drop.retrans[0] > 500 && drop.dropped[0] > 500,
        "Go's policy must show the defect: dropped {:?}, retransmitted {:?}",
        drop.dropped,
        drop.retrans
    );
    assert_eq!(back.dropped, [0, 0], "backpressure never drops a packet");
    assert_eq!(
        back.retrans,
        [0, 0],
        "and never retransmits on a lossless link"
    );
    println!(
        "drop: end={} retrans={:?} dropped={:?} | back: end={} retrans={:?}",
        drop.end_ms, drop.retrans, drop.dropped, back.end_ms, back.retrans
    );
    assert!(
        back.end_ms * 2 < drop.end_ms,
        "backpressure must be far faster: {} ms against {} ms",
        back.end_ms,
        drop.end_ms
    );
    assert!(
        back.high_water.iter().all(|&h| h <= 128),
        "the channel bounds the burst: {:?}",
        back.high_water
    );
}

/// DECISIONS D25: the V18 checks must be **inert** when the channel never fills up. Randomised
/// two-endpoint traces over a lossy, reordering link produce byte-identical packets and
/// identical state with an unbounded output and with a backpressured channel large enough that
/// `capacity()` never falls below `OUTPUT_ROOM`.
#[test]
fn a_channel_that_never_fills_is_byte_identical_to_an_unbounded_output() {
    let _g = snmp_read();
    for seed in 1..=12u64 {
        let base = SimCfg {
            seed,
            policy: Policy::Unbounded,
            limit: usize::MAX,
            // Drained completely every millisecond, so the queue never approaches the bound.
            drain: usize::MAX,
            payload: 192 * 1024,
            chunk: if seed % 3 == 0 { 4 * 1024 } else { 64 * 1024 },
            snd_wnd: if seed % 2 == 0 { 128 } else { 512 },
            rcv_wnd: 512,
            nodelay: if seed % 4 == 0 {
                [1, 10, 2, 1]
            } else {
                [0, 40, 2, 1]
            },
            loss: 0.02 * (seed % 5) as f64,
            delay: 5 + seed % 20,
            ack_no_delay: seed % 2 == 0,
            fast_path: true,
        };
        let unbounded = run_sim(base, 600_000);
        let bounded = run_sim(
            SimCfg {
                policy: Policy::Backpressure,
                limit: 1 << 20,
                ..base
            },
            600_000,
        );

        assert_eq!(bounded.dropped, [0, 0], "seed {seed}: nothing may be full");
        assert_eq!(
            unbounded.end_ms, bounded.end_ms,
            "seed {seed}: same end of transfer"
        );
        assert_eq!(unbounded.state, bounded.state, "seed {seed}: same state");
        for i in 0..2 {
            assert_eq!(
                unbounded.wire[i], bounded.wire[i],
                "seed {seed}: endpoint {i} put different bytes on the wire"
            );
        }
    }
}

/// Backpressure must not make a *lossy* link worse: the same randomised traces with a channel
/// small enough to fill up still deliver every byte, and never drop a packet locally.
#[test]
fn a_small_channel_on_a_lossy_link_still_delivers_everything() {
    let _g = snmp_read();
    for seed in 1..=8u64 {
        let cfg = SimCfg {
            seed,
            policy: Policy::Backpressure,
            limit: 16,
            drain: 4,
            payload: 96 * 1024,
            chunk: 16 * 1024,
            snd_wnd: 256,
            rcv_wnd: 256,
            nodelay: [0, 40, 2, 1],
            loss: 0.05,
            delay: 10,
            ack_no_delay: seed % 2 == 0,
            fast_path: true,
        };
        // `run_sim` verifies the payload of both endpoints itself.
        let result = run_sim(cfg, 600_000);
        assert_eq!(result.dropped, [0, 0], "seed {seed}: local drops");
        assert!(
            result.high_water.iter().all(|&h| h <= 16),
            "seed {seed}: the channel bound was exceeded: {:?}",
            result.high_water
        );
    }
}
