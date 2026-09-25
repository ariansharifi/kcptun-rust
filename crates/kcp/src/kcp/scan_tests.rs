//! Skipping the part of `snd_buf` that a flush has already scanned (**Decision D29**, plan
//! step 12.2c).
//!
//! Go rescans the whole send buffer on every flush: every write, every update tick and every
//! ACK that advances `una`. At the production window (`-sndwnd 8192`) that is 8192
//! `Segment`s, 512 kB, per call, and `docs/benchmarks/kcp.md` measured it at 8.16 µs on the M5
//! and 30.8 µs on lab-arm64's Neoverse-N1: the dominant KCP-level cost of the profile.
//!
//! [`FlushScan`] is what makes leaving that scan out safe. It records three things about the
//! segments a flush has looked at: when the earliest of them can fall due, whether any is
//! waiting for a fast or early retransmit, and how long the never-transmitted tail is, and
//! every one of them is **conservative**: it may claim less than is true, which costs a full
//! scan and nothing else, and it can never claim more.
//!
//! What this module has to establish is therefore not that the skip is fast but that it is
//! **inert**, which is DECISIONS D25: the naive line-by-line scan stays in the code as the
//! oracle (`FlushScan::enabled == false`) and the optimised flush must produce identical
//! packets, identical state and the identical `nextUpdate` hint on randomised traces. So:
//!
//! 1. [`same_as_oracle`] runs every unit test below twice, once each way, and compares the
//!    bytes on the wire, the scalar state and every value `flush` returned. Each test then
//!    asserts *how much* was skipped, because a differential test against a skip that never
//!    fires proves nothing.
//! 2. [`the_skip_is_byte_identical_to_the_naive_scan`] does the same over the randomised
//!    two-endpoint traces of [`super::backpressure_tests`]: lossy, reordering links, real
//!    retransmissions and real fast retransmits.
//! 3. The golden Go traces of [`super::trace_tests`] and the pinned summaries of
//!    [`super::sim_tests`] cover the same ground against Go itself, unchanged.

use super::*;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::RwLockReadGuard;

use kcptun_testkit::VirtualClock;

use super::backpressure_tests::{Policy, SimCfg, run_sim};
use super::trace_tests::{state_digest, state_words};

/// These tests only read the process-global SNMP counters; tests asserting exact deltas hold
/// the write lock (see [`SNMP_TEST_LOCK`]).
fn snmp_read() -> RwLockReadGuard<'static, ()> {
    SNMP_TEST_LOCK.read().unwrap_or_else(|e| e.into_inner())
}

type ScanClock = Box<dyn Fn() -> u32 + Send + Sync>;
type ScanOutput = Box<dyn FnMut(&[u8])>;
pub(super) type ScanKcp = Kcp<ScanOutput, ScanClock>;
/// Every packet the KCP handed to its output, in order.
type Sink = Rc<RefCell<Vec<Vec<u8>>>>;

pub(super) const CONV: u32 = 0x0102_0304;
pub(super) const T0: u64 = 1000;
/// Payload of a full segment at the default MTU of 1400.
const MSS: usize = 1400 - IKCP_OVERHEAD as usize;
/// Segments per burst: enough that a skipped scan is obviously a skipped scan.
pub(super) const WND: usize = 256;

/// A KCP at `T0` ms on kcptun's `-mode normal` timings (`nodelay 0 40 2 1`), stream mode, a
/// send and receive window of [`WND`] and a peer window already known, so that one `flush`
/// admits and sends a whole burst.
pub(super) fn fixture() -> (ScanKcp, Sink, VirtualClock) {
    let clock = VirtualClock::starting_at(T0);
    let sink: Sink = Rc::new(RefCell::new(Vec::new()));
    let out = {
        let sink = sink.clone();
        Box::new(move |p: &[u8]| sink.borrow_mut().push(p.to_vec())) as ScanOutput
    };
    let tick = {
        let clock = clock.clone();
        Box::new(move || clock.now_ms()) as ScanClock
    };
    let mut kcp = Kcp::with_clock(CONV, out, tick);
    kcp.nodelay(0, 40, 2, 1);
    kcp.wnd_size(WND as isize, WND as isize);
    kcp.rmt_wnd = WND as u32;
    kcp.stream = 1;
    (kcp, sink, clock)
}

/// What an [`oracle_run`] found out about the optimised run.
pub(super) struct OracleRun {
    /// Flushes that skipped part of `snd_buf`, and segments skipped (Decision D29).
    pub(super) skipped: (u64, u64),
    /// What the ACK path made of `snd_buf` (Decision D31).
    pub(super) ack_index: AckIndex,
}

/// Runs `script` on two otherwise identical `Kcp`s: one with the `snd_buf` optimisations of
/// plan step 12.2, one with the naive line-by-line scans of DECISIONS D25, and asserts that
/// they are indistinguishable: the same packets byte for byte, the same state down to every
/// segment's `fastack`, and the same `nextUpdate` from every flush (the hint the session
/// schedules on, so a wrong one changes when the next flush happens).
///
/// It holds the SNMP read lock for both runs, so a `script` must **not** take it again: a
/// second `read()` on a thread that already holds one deadlocks as soon as a writer queues up
/// behind it, which is `std::sync::RwLock`'s documented behaviour and not a hypothetical.
pub(super) fn oracle_run(script: impl Fn(&mut ScanKcp, &VirtualClock) -> Vec<u32>) -> OracleRun {
    let _g = snmp_read();
    let mut wire: Vec<Vec<Vec<u8>>> = Vec::new();
    let mut state: Vec<[u32; 32]> = Vec::new();
    let mut digest: Vec<u64> = Vec::new();
    let mut hints: Vec<Vec<u32>> = Vec::new();
    let mut run = OracleRun {
        skipped: (0, 0),
        ack_index: AckIndex::default(),
    };
    for fast_path in [true, false] {
        let (mut kcp, sink, clock) = fixture();
        kcp.flush_scan.enabled = fast_path;
        hints.push(script(&mut kcp, &clock));
        if fast_path {
            run.skipped = kcp.scan_skipped;
            run.ack_index = kcp.ack_index;
        } else {
            assert_eq!(kcp.scan_skipped, (0, 0), "the oracle may not skip anything");
            assert_eq!(
                kcp.ack_index,
                AckIndex::default(),
                "the oracle may not compute a ring offset"
            );
        }
        wire.push(sink.borrow().clone());
        state.push(state_words(&kcp));
        digest.push(state_digest(&kcp));
    }
    assert_eq!(
        wire[0], wire[1],
        "the fast path changed the bytes on the wire"
    );
    assert_eq!(state[0], state[1], "the fast path changed the state");
    assert_eq!(
        digest[0], digest[1],
        "the fast path changed a segment (sn, ts, rto, xmit, resendts, fastack or acked)"
    );
    assert_eq!(
        hints[0], hints[1],
        "the fast path changed a nextUpdate hint"
    );
    run
}

/// [`oracle_run`] for the Decision D29 tests, which only look at what was skipped.
fn same_as_oracle(script: impl Fn(&mut ScanKcp, &VirtualClock) -> Vec<u32>) -> (u64, u64) {
    oracle_run(script).skipped
}

/// Queues `n` full segments.
pub(super) fn send_burst(kcp: &mut ScanKcp, n: usize) {
    let data = vec![0x5A; MSS];
    for _ in 0..n {
        assert_eq!(kcp.send(&data), 0);
    }
}

/// The ACK packet acknowledging `sns`, with `una` (echoing `ts`), as a kcp-go receiver packs
/// it. A `una` of `None` means "nothing cumulative yet" (selective ACKs only).
pub(super) fn ack_packet(sns: &[u32], una: u32, ts: u32) -> Vec<u8> {
    sns.iter()
        .flat_map(|&sn| {
            crate::internals::fuzz::encode_segment(
                CONV,
                IKCP_CMD_ACK,
                0,
                WND as u16,
                ts,
                sn,
                una,
                &[],
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------------------
// What the summary lets a flush leave alone, and what pulls it back
// ---------------------------------------------------------------------------------------

/// The plain case: a window that has been transmitted and is not due is scanned once and then
/// left alone by every flush until one of its segments comes within an `interval` of falling
/// due, which is where `nextUpdate` would start to depend on it.
#[test]
fn an_undue_window_is_scanned_once_and_then_skipped() {
    let skipped = same_as_oracle(|k, clock| {
        let mut hints = Vec::new();
        send_burst(k, WND - 1);
        // Sends the whole burst: rx_rto is still IKCP_RTO_DEF, so everything falls due at
        // T0 + 200 and nothing can be skipped on the way out.
        hints.push(k.flush(IKCP_FLUSH_FULL));
        // Update ticks while the acknowledgements are in flight. T0 + 160 is exactly one
        // interval (40 ms) before the RTO and still skippable: `nextUpdate` starts at the
        // interval and only ever takes a strictly smaller value.
        for at in [T0 + 40, T0 + 80, T0 + 120, T0 + 159, T0 + 160] {
            clock.set(at);
            hints.push(k.flush(IKCP_FLUSH_FULL));
        }
        // From T0 + 161 on the segments decide `nextUpdate`, so they have to be looked at.
        for at in [T0 + 161, T0 + 199, T0 + 200] {
            clock.set(at);
            hints.push(k.flush(IKCP_FLUSH_FULL));
        }
        hints
    });
    assert_eq!(
        skipped,
        (5, 5 * (WND as u64 - 1)),
        "the five flushes at least an interval away from the RTO skip the whole window"
    );
}

/// `nextUpdate` is `interval` while the window is far from due and counts down once it is not,
/// whether or not the scan was skipped: the property that makes skipping safe, stated on its
/// own so that a regression names itself.
#[test]
fn the_scheduling_hint_is_the_interval_until_a_segment_is_within_one() {
    let _g = snmp_read();
    let (mut k, _sink, clock) = fixture();
    send_burst(&mut k, WND - 1);
    assert_eq!(
        k.flush(IKCP_FLUSH_FULL),
        40,
        "one interval away at the start"
    );
    for (at, want) in [
        (T0 + 159, 40),
        (T0 + 160, 40),
        (T0 + 161, 39),
        (T0 + 199, 1),
        (T0 + 200, 40),
    ] {
        clock.set(at);
        assert_eq!(k.flush(IKCP_FLUSH_FULL), want, "at {at}");
    }
}

/// The case the production profile actually spends its time in: an ACK advances `una`, a few
/// segments are admitted from `snd_queue`, and they are transmitted **without** looking at the
/// several thousand segments still in flight ahead of them.
#[test]
fn newly_admitted_segments_are_sent_without_rescanning_the_window() {
    let skipped = same_as_oracle(|k, clock| {
        let mut hints = Vec::new();
        send_burst(k, 2 * WND);
        // The first flush admits and sends a window; the rest stays in snd_queue.
        hints.push(k.flush(IKCP_FLUSH_FULL));
        assert_eq!(k.snd_buf.len(), WND);
        assert_eq!(k.snd_queue.len(), WND);
        // 58 acks, as one 1400-byte packet from a kcp-go receiver carries.
        clock.set(T0 + 20);
        let sns: Vec<u32> = (0..58).collect();
        assert_eq!(
            k.input(&ack_packet(&sns, 58, T0 as u32), IKCP_PACKET_REGULAR, false),
            0
        );
        // `input` flushes itself when `una` advances; 58 segments follow the 198 still in
        // flight, none of which is due.
        hints.push(k.flush(IKCP_FLUSH_FULL));
        assert_eq!(k.snd_buf.len(), WND);
        hints
    });
    assert_eq!(
        skipped.0, 2,
        "the flush inside input() and the one after it both skip"
    );
    assert_eq!(
        skipped.1,
        (WND as u64 - 58) + WND as u64,
        "the first leaves everything but the newly admitted tail untouched, \
         the second (which has nothing to admit) the whole window"
    );
}

/// A duplicate ACK raises `fastack` on the segments before it, so the next flush may have to
/// fast- or early-retransmit one and has to look at all of them again.
#[test]
fn a_duplicate_ack_makes_the_next_flush_scan_again() {
    let skipped = same_as_oracle(|k, clock| {
        let mut hints = Vec::new();
        send_burst(k, WND - 1);
        hints.push(k.flush(IKCP_FLUSH_FULL));
        clock.set(T0 + 20);
        hints.push(k.flush(IKCP_FLUSH_FULL)); // skips: nothing has happened
        assert!(k.flush_scan.no_fastack);

        // Segment 0 was lost, so its successor is acknowledged selectively and `una` stays at
        // 0. That raises `fastack` on segment 0: one short of the fast-retransmit threshold,
        // so `input` does not flush and the duplicate ack is still outstanding.
        assert_eq!(
            k.input(&ack_packet(&[1], 0, T0 as u32), IKCP_PACKET_REGULAR, false),
            0
        );
        assert!(
            !k.flush_scan.no_fastack,
            "a pending duplicate ack has to be visible to the next flush"
        );

        // This one has to scan: it early-retransmits segment 0 and clears its `fastack`.
        clock.set(T0 + 30);
        hints.push(k.flush(IKCP_FLUSH_FULL));
        assert!(
            k.flush_scan.no_fastack,
            "and then there is nothing left to act on"
        );
        clock.set(T0 + 40);
        hints.push(k.flush(IKCP_FLUSH_FULL));
        hints
    });
    assert_eq!(
        skipped,
        (2, 2 * (WND as u64 - 1)),
        "the flush between the duplicate ack and the retransmit scans; the others skip"
    );
}

/// A segment that is genuinely due is retransmitted at the same moment either way: the bound
/// keeps a flush at the RTO from skipping, and the two runs of [`same_as_oracle`] would differ
/// in the bytes on the wire if it did not.
#[test]
fn a_segment_that_falls_due_is_retransmitted_on_time() {
    let skipped = same_as_oracle(|k, clock| {
        let mut hints = Vec::new();
        send_burst(k, WND - 1);
        hints.push(k.flush(IKCP_FLUSH_FULL));
        // Nothing is acknowledged; the whole window falls due at T0 + 200 and is sent again,
        // with the RTO backed off, then falls due once more.
        for at in [T0 + 100, T0 + 200, T0 + 300, T0 + 600] {
            clock.set(at);
            hints.push(k.flush(IKCP_FLUSH_FULL));
        }
        assert!(
            k.snd_buf.iter().all(|s| s.xmit >= 3),
            "every segment was retransmitted twice"
        );
        hints
    });
    assert_eq!(
        skipped,
        (2, 2 * (WND as u64 - 1)),
        "the flushes between the retransmissions skip; the ones at the RTO do not"
    );
}

/// An ack-only flush still admits segments from `snd_queue` (Go's `flush` only makes the
/// *retransmission* loop `IKCP_FLUSH_FULL`-only), so the never-transmitted tail grows without
/// the scan running. The next full flush has to send exactly those.
#[test]
fn an_ack_only_flush_counts_the_segments_it_admits() {
    let skipped = same_as_oracle(|k, clock| {
        let mut hints = Vec::new();
        send_burst(k, 8);
        hints.push(k.flush(IKCP_FLUSH_FULL));
        clock.set(T0 + 10);
        send_burst(k, 5);
        // Admits the five but sends nothing.
        hints.push(k.flush(IKCP_FLUSH_ACKONLY));
        assert_eq!(k.snd_buf.len(), 13);
        assert_eq!(k.flush_scan.unsent, 5);
        clock.set(T0 + 20);
        hints.push(k.flush(IKCP_FLUSH_FULL));
        assert!(
            k.snd_buf.iter().all(|s| s.xmit == 1),
            "every admitted segment has been transmitted once"
        );
        hints
    });
    assert_eq!(
        skipped,
        (1, 8),
        "the full flush skips the eight already sent"
    );
}

/// A peer that claims `una` for segments we have not transmitted yet drops them from
/// `snd_buf`, and the never-transmitted tail cannot be longer than what is left.
#[test]
fn an_una_past_what_we_sent_shortens_the_unsent_tail() {
    let _g = snmp_read();
    let (mut k, _sink, _clock) = fixture();
    send_burst(&mut k, 4);
    // Admitted (sn 0..4, snd_nxt = 4) but not transmitted.
    k.flush(IKCP_FLUSH_ACKONLY);
    assert_eq!((k.snd_buf.len(), k.flush_scan.unsent), (4, 4));

    // A regular packet whose `una` covers all four.
    let pkt = crate::internals::fuzz::encode_segment(
        CONV,
        IKCP_CMD_ACK,
        0,
        WND as u16,
        T0 as u32,
        0,
        4,
        &[],
    );
    assert_eq!(k.input(&pkt, IKCP_PACKET_REGULAR, false), 0);
    assert_eq!(k.snd_buf.len(), 0);
    assert_eq!(
        k.flush_scan.unsent, 0,
        "the tail cannot outlive the segments it counted"
    );
}

/// 12.3b's [`Kcp::shrink_idle_buffers`] hands `snd_buf` a new, smaller array when the ring is
/// empty. The summary holds no capacity, address or index of that array, only counts and a
/// timestamp, so a shrink cannot invalidate it, and a session that bursts, drains, shrinks
/// and bursts again is still byte-identical to the oracle and still skips.
#[test]
fn shrinking_an_idle_send_buffer_neither_breaks_nor_defeats_the_skip() {
    let skipped = same_as_oracle(|k, clock| {
        let mut hints = Vec::new();
        let grown = {
            send_burst(k, WND - 1);
            hints.push(k.flush(IKCP_FLUSH_FULL));
            k.snd_buf.max_len()
        };
        assert!(grown >= WND - 1);

        // Everything is acknowledged and the ring empties.
        clock.set(T0 + 20);
        let sns: Vec<u32> = (0..WND as u32 - 1).collect();
        assert_eq!(
            k.input(
                &ack_packet(&sns, WND as u32 - 1, T0 as u32),
                IKCP_PACKET_REGULAR,
                false
            ),
            0
        );
        assert_eq!(k.snd_buf.len(), 0);
        assert_eq!(k.flush_scan.unsent, 0);

        assert!(
            k.shrink_idle_buffers(),
            "the empty rings gave their arrays back"
        );
        assert!(k.snd_buf.max_len() < grown);

        // A second burst through the regrown ring.
        clock.set(T0 + 100);
        send_burst(k, WND - 1);
        hints.push(k.flush(IKCP_FLUSH_FULL));
        clock.set(T0 + 120);
        hints.push(k.flush(IKCP_FLUSH_FULL));
        hints
    });
    assert_eq!(
        skipped,
        (1, WND as u64 - 1),
        "the burst after the shrink is scanned once and then skipped"
    );
}

/// The `internals` escape hatch replaces `snd_buf` wholesale (kcp-go's `BenchmarkFlush` does
/// the same), which nothing can keep a summary across. Handing the ring out resets it, so the
/// next full flush scans every segment.
#[test]
fn replacing_the_send_buffer_resets_the_summary() {
    let _g = snmp_read();
    let (mut k, _sink, clock) = fixture();
    send_burst(&mut k, WND - 1);
    k.flush(IKCP_FLUSH_FULL);
    clock.set(T0 + 20);
    k.flush(IKCP_FLUSH_FULL);
    assert_eq!(k.scan_skipped, (1, WND as u64 - 1));

    let far = k.clock.now_ms().wrapping_add(10_000_000);
    let snd_buf = crate::internals::snd_buf_mut(&mut k);
    assert_eq!(snd_buf.len(), WND - 1);
    for seg in snd_buf.iter_mut() {
        seg.resendts = far;
    }
    clock.set(T0 + 30);
    k.flush(IKCP_FLUSH_FULL);
    assert_eq!(
        k.scan_skipped,
        (1, WND as u64 - 1),
        "the flush right after the hatch scans"
    );
    clock.set(T0 + 40);
    k.flush(IKCP_FLUSH_FULL);
    assert_eq!(
        k.scan_skipped,
        (2, 2 * (WND as u64 - 1)),
        "and the one after that skips again"
    );
}

// ---------------------------------------------------------------------------------------
// The summary's own arithmetic
// ---------------------------------------------------------------------------------------

/// [`FlushScan::can_skip`] is the whole safety argument in four lines, so it gets its own
/// table: nothing is skipped without a bound, without `no_fastack`, or inside one `interval`
/// of the earliest retransmission, and `_itimediff` decides "earliest", so the answer is the
/// same across the `u32` wrap.
#[test]
fn can_skip_needs_a_bound_no_fastack_and_a_whole_interval() {
    let scan = |due, no_fastack| FlushScan {
        due,
        no_fastack,
        unsent: 0,
        enabled: true,
    };
    let now = 0xFFFF_FF00u32; // 256 ms before the wrap

    assert!(!scan(ScanBound::Unknown, true).can_skip(now, 40));
    assert!(scan(ScanBound::Nothing, true).can_skip(now, 40));
    assert!(!scan(ScanBound::Nothing, false).can_skip(now, 40));

    // Exactly one interval away is far enough: `nextUpdate` starts at `interval` and only
    // takes a strictly smaller value.
    assert!(scan(ScanBound::NotBefore(now.wrapping_add(40)), true).can_skip(now, 40));
    assert!(!scan(ScanBound::NotBefore(now.wrapping_add(39)), true).can_skip(now, 40));
    assert!(!scan(ScanBound::NotBefore(now.wrapping_add(39)), true).can_skip(now, 40));
    // Across the wrap, and in the past.
    assert!(scan(ScanBound::NotBefore(now.wrapping_add(5000)), true).can_skip(now, 40));
    assert!(!scan(ScanBound::NotBefore(now.wrapping_sub(1)), true).can_skip(now, 40));
    assert!(!scan(ScanBound::NotBefore(now), true).can_skip(now, 40));
    // The switch of DECISIONS D25.
    assert!(
        !FlushScan {
            enabled: false,
            ..scan(ScanBound::Nothing, true)
        }
        .can_skip(now, 40)
    );
}

/// `merge` keeps the earlier of two bounds by `_itimediff`, so a bound covering a partially
/// scanned `snd_buf` stays a bound across the `u32` wrap.
#[test]
fn a_bound_keeps_the_earliest_time_across_the_wrap() {
    let late = 0xFFFF_FFF0u32;
    let early = 0xFFFF_FF00u32;
    let wrapped = 0x0000_0010u32; // later than both

    assert_eq!(
        ScanBound::NotBefore(late).merge(ScanBound::NotBefore(early)),
        ScanBound::NotBefore(early)
    );
    assert_eq!(
        ScanBound::NotBefore(early).merge(ScanBound::NotBefore(wrapped)),
        ScanBound::NotBefore(early)
    );
    assert_eq!(
        ScanBound::Nothing.merge(ScanBound::NotBefore(late)),
        ScanBound::NotBefore(late)
    );
    assert_eq!(
        ScanBound::NotBefore(late).merge(ScanBound::Nothing),
        ScanBound::NotBefore(late)
    );
    assert_eq!(
        ScanBound::Unknown.merge(ScanBound::NotBefore(late)),
        ScanBound::Unknown
    );
    assert_eq!(
        ScanBound::NotBefore(late).merge(ScanBound::Unknown),
        ScanBound::Unknown
    );
    assert_eq!(
        ScanBound::Nothing.merge(ScanBound::Nothing),
        ScanBound::Nothing
    );
}

/// A fresh `Kcp` knows nothing, so its first full flush scans everything.
#[test]
fn a_new_kcp_starts_without_a_summary() {
    let (k, _sink, _clock) = fixture();
    assert_eq!(k.flush_scan.due, ScanBound::Unknown);
    assert!(!k.flush_scan.no_fastack);
    assert_eq!(k.flush_scan.unsent, 0);
    assert!(k.flush_scan.enabled, "on by default");
}

/// The skip rests on the never-transmitted segments being a contiguous **suffix** of
/// `snd_buf`. Every scan re-derives that suffix and compares it with the total, so a
/// `snd_buf` that breaks the invariant gives the optimisation up rather than mis-skipping.
#[test]
fn an_unsent_segment_in_the_middle_gives_the_optimisation_up() {
    let _g = snmp_read();
    let (mut k, _sink, clock) = fixture();
    send_burst(&mut k, 8);
    k.flush(IKCP_FLUSH_FULL);
    clock.set(T0 + 10);
    k.flush(IKCP_FLUSH_FULL);
    assert_eq!(k.scan_skipped, (1, 8), "the skip works to begin with");

    // Something no code path produces: an untransmitted segment with transmitted ones behind
    // it. It is marked acknowledged so that the scan leaves it as it found it: a scan that
    // simply transmits such a segment repairs the ring and needs no safety net.
    {
        let seg = k.snd_buf.iter_mut().nth(2).expect("segment 2");
        seg.xmit = 0;
        seg.acked = 1;
    }
    k.flush_scan.due = ScanBound::Unknown; // force the scan that has to notice

    clock.set(T0 + 20);
    k.flush(IKCP_FLUSH_FULL);
    assert_eq!(
        k.flush_scan.due,
        ScanBound::Unknown,
        "the scan found the untransmitted segments not to be a suffix"
    );
    assert_eq!(k.flush_scan.unsent, 0);
    clock.set(T0 + 30);
    k.flush(IKCP_FLUSH_FULL);
    assert_eq!(k.scan_skipped, (1, 8), "and nothing is skipped after it");
}

// ---------------------------------------------------------------------------------------
// Randomised two-endpoint traces (DECISIONS D25)
// ---------------------------------------------------------------------------------------

/// The D25 differential test: over randomised two-endpoint traces on lossy, reordering links,
/// with real retransmissions, fast retransmissions and window probes: the optimised flush puts
/// exactly the same bytes on the wire as the naive one, ends in the same state, returns the
/// same `nextUpdate` from every call and finishes at the same virtual millisecond.
#[test]
fn the_skip_is_byte_identical_to_the_naive_scan() {
    let _g = snmp_read();
    let mut total_skipped = 0u64;
    for seed in 1..=12u64 {
        let base = SimCfg {
            seed,
            policy: Policy::Unbounded,
            limit: usize::MAX,
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
        let fast = run_sim(base, 600_000);
        let oracle = run_sim(
            SimCfg {
                fast_path: false,
                ..base
            },
            600_000,
        );

        assert_eq!(
            oracle.scan_skipped,
            [(0, 0), (0, 0)],
            "seed {seed}: the oracle may not skip anything"
        );
        assert_eq!(
            fast.end_ms, oracle.end_ms,
            "seed {seed}: the transfer ended at a different time"
        );
        assert_eq!(fast.state, oracle.state, "seed {seed}: different state");
        assert_eq!(
            fast.retrans, oracle.retrans,
            "seed {seed}: a different retransmission decision"
        );
        for i in 0..2 {
            assert_eq!(
                fast.wire[i], oracle.wire[i],
                "seed {seed}: endpoint {i} put different bytes on the wire"
            );
            assert_eq!(
                fast.next_update[i], oracle.next_update[i],
                "seed {seed}: endpoint {i} returned a different nextUpdate"
            );
            assert!(
                fast.scan_skipped[i].0 > 0,
                "seed {seed}: endpoint {i} never skipped, so this proves nothing"
            );
            total_skipped += fast.scan_skipped[i].1;
        }
    }
    assert!(
        total_skipped > 100_000,
        "the twelve traces skipped only {total_skipped} segments"
    );
}

/// The same under V18 backpressure, where flushes stop in the middle of `snd_buf` and leave a
/// never-transmitted tail behind them: the one case that makes the unsent suffix longer than
/// what the last admission added.
#[test]
fn the_skip_is_byte_identical_under_backpressure() {
    let _g = snmp_read();
    for seed in 1..=8u64 {
        let base = SimCfg {
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
        let fast = run_sim(base, 600_000);
        let oracle = run_sim(
            SimCfg {
                fast_path: false,
                ..base
            },
            600_000,
        );

        assert_eq!(fast.end_ms, oracle.end_ms, "seed {seed}: end of transfer");
        assert_eq!(fast.state, oracle.state, "seed {seed}: state");
        assert_eq!(fast.dropped, [0, 0], "seed {seed}: local drops");
        assert_eq!(
            fast.high_water, oracle.high_water,
            "seed {seed}: channel high water"
        );
        for i in 0..2 {
            assert_eq!(
                fast.wire[i], oracle.wire[i],
                "seed {seed}: endpoint {i} put different bytes on the wire"
            );
            assert_eq!(
                fast.next_update[i], oracle.next_update[i],
                "seed {seed}: endpoint {i} returned a different nextUpdate"
            );
        }
    }
}
