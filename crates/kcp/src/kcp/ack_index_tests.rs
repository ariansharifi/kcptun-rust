//! Addressing an acknowledged segment by its sequence number instead of searching for it
//! (**Decision D31**, plan step 12.2d).
//!
//! `input` calls `parse_ack` and `parse_fastack` once per acknowledged segment, and a
//! 1400-byte ACK packet from a kcp-go receiver carries 58 of them. Both walk `snd_buf` from
//! the head until they reach the sequence number, so a *selective* ACK for the far end of the
//! production window (`-sndwnd 8192`) walks thousands of segments (twice) and a window
//! acknowledged around a single hole costs O(window²). `docs/benchmarks/kcp.md` measured
//! exactly that as the worst case of the whole suite: `input_ack/sack/8192` at 42.9 ms on the
//! M5 against 0.53 ms for the same window acknowledged in order.
//!
//! `snd_buf` holds the segments `snd_una ..< snd_nxt` in ascending order with no gaps, so the
//! segment an ACK names is at offset `sn - snd_una`: [`Kcp::snd_buf_offset`] states why, in
//! terms of the four places that touch the ring. `parse_ack` then needs no search at all, and
//! `parse_fastack` gets its bound without testing every segment for it (the work it has left
//! is one `fastack` per segment before `sn`, which no index can remove).
//!
//! What this module has to establish is that the offset is **the same answer** the scan gives,
//! which is DECISIONS D25 and the same bar as D29 next door:
//!
//! 1. Debug builds check every computed offset against [`Kcp::scan_for_sn`]: the scan it
//!    replaces, on every ACK of every test in this crate, the golden Go traces included.
//! 2. [`super::scan_tests::oracle_run`] runs the tests below twice, with the optimisations on
//!    and with the naive line-by-line scans of D25, and compares the bytes on the wire, the
//!    state down to every segment's `fastack`, and every `nextUpdate`. Each test then asserts
//!    that the offset path really fired, because a differential test against a path that is
//!    never taken proves nothing.
//! 3. [`the_ack_index_is_byte_identical_to_the_naive_scan`] does the same over randomised
//!    two-endpoint traces biased towards loss, reordering and duplicate ACKs, where an
//!    off-by-one in this code would hide.
//! 4. The ring is never expected to break the invariant, so the fallback is the safety net
//!    rather than a path in use: every trace here asserts `misses == 0`, and the two
//!    hand-built rings below are the only ones in the crate that miss.

use super::*;
use std::sync::RwLockReadGuard;

use super::scan_tests::{T0, WND, ack_packet, fixture, oracle_run, send_burst};

use super::backpressure_tests::{Policy, SimCfg, run_sim};

/// These tests only read the process-global SNMP counters (see [`SNMP_TEST_LOCK`]).
fn snmp_read() -> RwLockReadGuard<'static, ()> {
    SNMP_TEST_LOCK.read().unwrap_or_else(|e| e.into_inner())
}

/// ACKs per packet from a kcp-go receiver's flush, at the fixture's 1400-byte MTU.
const ACKS_PER_PACKET: usize = 1400 / IKCP_OVERHEAD as usize;

// ---------------------------------------------------------------------------------------
// The offset against the scan, on real traffic
// ---------------------------------------------------------------------------------------

/// The expensive shape, and the one this sub-step exists for: a window with a hole at its
/// head. Every ACK after the hole is selective, so `una` never advances, `parse_ack` has to
/// reach ever deeper into the window and `parse_fastack` raises `fastack` on everything before
/// it. The offsets must produce exactly the packets and the state the scan produces.
#[test]
fn a_window_acknowledged_around_a_hole_is_identical_to_the_naive_scan() {
    let run = oracle_run(|k, clock| {
        let mut hints = vec![];
        send_burst(k, WND - 1);
        hints.push(k.flush(IKCP_FLUSH_FULL));

        // Segment 0 was lost, so `una` stays at 0 and every ACK is selective.
        clock.set(T0 + 20);
        let sns: Vec<u32> = (1..WND as u32 - 1).collect();
        for chunk in sns.chunks(ACKS_PER_PACKET) {
            assert_eq!(
                k.input(&ack_packet(chunk, 0, T0 as u32), IKCP_PACKET_REGULAR, false),
                0
            );
        }
        // Segment 0 is the only one left unacknowledged, and it has been retransmitted.
        assert_eq!(k.snd_buf.len(), WND - 1);
        assert_eq!(k.snd_buf.peek().expect("segment 0").sn, 0);
        assert!(k.snd_buf.peek().expect("segment 0").xmit >= 2);
        assert_eq!(k.snd_buf.iter().filter(|s| s.acked == 0).count(), 1);
        hints.push(k.flush(IKCP_FLUSH_FULL));
        hints
    });

    let acks = WND as u64 - 2;
    assert_eq!(
        run.ack_index.misses, 0,
        "the send buffer is contiguous, so every offset must land"
    );
    assert_eq!(
        run.ack_index.hits,
        2 * acks,
        "parse_ack and parse_fastack each compute one offset per ack"
    );
    assert_eq!(
        run.ack_index.skipped,
        (1..WND as u64 - 1).sum::<u64>(),
        "each ack's segment sits that many places into the window"
    );
}

/// The ordinary case costs nothing here *or* in Go, and it is worth stating why: a kcp-go
/// receiver puts its cumulative `una` into every ACK of the packet, and `input` applies that
/// `una` (`parse_una`, then `shrink_buf`) before it looks at the command. The acknowledged
/// segments are gone from `snd_buf` by the time `parse_ack` sees their sequence numbers, so
/// the guard both functions start with rejects every one of them and nothing reaches the
/// offset at all. That, not the length of the scan, is why `input_ack/in_order` is two orders
/// of magnitude faster than `input_ack/sack` in `docs/benchmarks/kcp.md`.
#[test]
fn a_cumulative_una_retires_the_segments_before_the_acks_are_parsed() {
    let run = oracle_run(|k, clock| {
        let mut hints = vec![];
        send_burst(k, WND - 1);
        hints.push(k.flush(IKCP_FLUSH_FULL));
        clock.set(T0 + 20);
        let sns: Vec<u32> = (0..WND as u32 - 1).collect();
        for chunk in sns.chunks(ACKS_PER_PACKET) {
            let una = chunk[chunk.len() - 1] + 1;
            assert_eq!(
                k.input(
                    &ack_packet(chunk, una, T0 as u32),
                    IKCP_PACKET_REGULAR,
                    false
                ),
                0
            );
        }
        assert_eq!(k.snd_buf.len(), 0, "the whole window is acknowledged");
        hints
    });
    assert_eq!(
        run.ack_index,
        AckIndex::default(),
        "every ack was retired by its own packet's una"
    );
}

/// ACKs whose packet `una` lags behind them: the receiver's `rcv_nxt` had not caught up when
/// it packed the packet, which is what a reordered or partly lost round produces: do reach
/// the ACK path, at offsets just past the head.
#[test]
fn acknowledgements_ahead_of_una_are_found_just_past_the_head() {
    let run = oracle_run(|k, clock| {
        let mut hints = vec![];
        send_burst(k, WND - 1);
        hints.push(k.flush(IKCP_FLUSH_FULL));
        clock.set(T0 + 20);
        let sns: Vec<u32> = (0..WND as u32 - 1).collect();
        for chunk in sns.chunks(ACKS_PER_PACKET) {
            // `una` covers everything before this packet, nothing in it.
            assert_eq!(
                k.input(
                    &ack_packet(chunk, chunk[0], T0 as u32),
                    IKCP_PACKET_REGULAR,
                    false
                ),
                0
            );
        }
        assert_eq!(
            k.snd_buf.len(),
            (WND - 1) % ACKS_PER_PACKET,
            "the last packet's own acks are all that is left"
        );
        hints
    });
    assert_eq!(run.ack_index.misses, 0);
    assert_eq!(
        run.ack_index.hits,
        2 * (WND as u64 - 1),
        "every ack is inside the window this time"
    );
    // Each packet's acks sit at offsets 0, 1, 2, … from its own `una`.
    let full = (WND - 1) / ACKS_PER_PACKET;
    let rest = (WND - 1) % ACKS_PER_PACKET;
    let sum = |n: usize| (n as u64) * (n as u64 - 1) / 2;
    assert_eq!(
        run.ack_index.skipped,
        full as u64 * sum(ACKS_PER_PACKET) + sum(rest),
        "an ack never reaches further than its own packet"
    );
}

/// The window straddles the `u32` wrap of the sequence number space. `sn - snd_una` is a
/// wrapping subtraction and the offsets have to be the same as before the wrap.
#[test]
fn the_offset_is_computed_across_the_sequence_number_wrap() {
    const FIRST: u32 = u32::MAX - 15;
    const N: u32 = 64;
    let run = oracle_run(|k, clock| {
        // Start 16 short of the wrap, so `snd_buf` holds 0xFFFF_FFF0 ..= 0x0000_002F.
        k.snd_una = FIRST;
        k.snd_nxt = FIRST;
        send_burst(k, N as usize);
        let mut hints = vec![k.flush(IKCP_FLUSH_FULL)];
        assert_eq!(k.snd_buf.peek().expect("first segment").sn, FIRST);
        assert_eq!(k.snd_nxt, FIRST.wrapping_add(N));

        // Acknowledge everything but the first, from the back: every ACK is selective and the
        // offsets run from 63 down to 1, across the wrap.
        clock.set(T0 + 20);
        for i in (1..N).rev() {
            let sn = FIRST.wrapping_add(i);
            assert_eq!(
                k.input(
                    &ack_packet(&[sn], FIRST, T0 as u32),
                    IKCP_PACKET_REGULAR,
                    false
                ),
                0
            );
        }
        assert_eq!(k.snd_buf.iter().filter(|s| s.acked == 0).count(), 1);
        assert_eq!(k.snd_una, FIRST, "the hole holds `una` where it is");
        hints.push(k.flush(IKCP_FLUSH_FULL));
        hints
    });
    assert_eq!(run.ack_index.misses, 0, "the wrap must not miss");
    assert_eq!(run.ack_index.hits, 2 * (N as u64 - 1));
    assert_eq!(run.ack_index.skipped, (1..N as u64).sum::<u64>());
}

/// A sequence number outside `snd_una ..< snd_nxt`: a stale ACK for a segment already
/// removed, or one for a segment never sent: is rejected by the guard both functions start
/// with, exactly as in Go: no offset is computed and nothing is touched.
#[test]
fn an_acknowledgement_outside_the_window_is_rejected_before_the_offset() {
    let _g = snmp_read();
    let (mut k, _sink, _clock) = fixture();
    send_burst(&mut k, 8);
    k.flush(IKCP_FLUSH_FULL);
    // Acknowledge sn 0..3 cumulatively, so 0..3 leave the ring.
    assert_eq!(
        k.input(
            &ack_packet(&[0, 1, 2, 3], 4, T0 as u32),
            IKCP_PACKET_REGULAR,
            false
        ),
        0
    );
    assert_eq!((k.snd_una, k.snd_nxt, k.snd_buf.len()), (4, 8, 4));
    let before = state_of(&k);
    let index_before = k.ack_index;

    for sn in [0u32, 3, 8, 9, u32::MAX] {
        k.parse_ack(sn);
        assert_eq!(k.parse_fastack(sn, T0 as u32), 0, "sn {sn}");
    }
    assert_eq!(
        state_of(&k),
        before,
        "an out-of-window ack changed a segment"
    );
    assert_eq!(
        k.ack_index, index_before,
        "the guard returns before the offset is computed"
    );
}

/// The same acknowledgement twice (a duplicate ACK, or an ACK that crossed a retransmission):
/// the second is idempotent for `parse_ack` and counts again for `parse_fastack`, exactly as
/// the scan does.
#[test]
fn a_repeated_acknowledgement_counts_again_for_fastack_only() {
    let run = oracle_run(|k, clock| {
        let mut hints = vec![];
        send_burst(k, 16);
        hints.push(k.flush(IKCP_FLUSH_FULL));
        clock.set(T0 + 20);
        // sn 9 acknowledged three times over, with `una` stuck at 0: `fastack` on 0..9 goes
        // up every time, and segment 9 stays acknowledged with its payload freed.
        for _ in 0..3 {
            assert_eq!(
                k.input(&ack_packet(&[9], 0, T0 as u32), IKCP_PACKET_REGULAR, false),
                0
            );
        }
        hints.push(k.flush(IKCP_FLUSH_FULL));
        hints
    });
    assert_eq!(run.ack_index.misses, 0);
    assert_eq!(run.ack_index.hits, 6, "three acks, two lookups each");
    assert_eq!(
        run.ack_index.skipped, 27,
        "sn 9 is nine places in, three times"
    );
}

/// `parse_fastack` must not count the ACK's own segment, must not count one sent *after* the
/// acknowledged one (`seg.ts > ts`), and must leave a segment already waiting for its RTO
/// (`fastack == 0xFFFF_FFFF`) alone. The bound from the offset changes which segments the loop
/// reaches, so the three exclusions get their own test.
#[test]
fn fastack_counts_exactly_the_segments_the_scan_counts() {
    let _g = snmp_read();
    let ts = T0 as u32 + 50;
    let mut both = Vec::new();
    for fast_path in [true, false] {
        let (mut k, _sink, _clock) = fixture();
        k.flush_scan.enabled = fast_path;
        send_burst(&mut k, 6);
        k.flush(IKCP_FLUSH_FULL);
        // sn 0 is waiting for its RTO after a fast retransmit; sn 2 was retransmitted later
        // than the segment that is about to be acknowledged; sn 3 is the acknowledged one.
        for (i, seg) in k.snd_buf.iter_mut().enumerate() {
            seg.ts = ts - 1;
            seg.fastack = if i == 0 { 0xFFFF_FFFF } else { 0 };
        }
        k.snd_buf.get_mut(2).expect("sn 2").ts = ts + 1;

        let first = k.parse_fastack(3, ts);
        let after_first: Vec<u32> = k.snd_buf.iter().map(|s| s.fastack).collect();
        // A second ACK for the same segment takes sn 1 to the fast-retransmit threshold,
        // which is what `input` turns into an immediate flush.
        let second = k.parse_fastack(3, ts);
        let after_second: Vec<u32> = k.snd_buf.iter().map(|s| s.fastack).collect();
        assert_eq!(k.ack_index.misses, 0);
        both.push((first, after_first, second, after_second));
    }

    assert_eq!(
        both[0].0, 0,
        "one duplicate ack is below fastresend = 2, so nothing is signalled"
    );
    assert_eq!(
        both[0].1,
        vec![0xFFFF_FFFF, 1, 0, 0, 0, 0],
        "only sn 1 is counted: 0 waits for its RTO, 2 is newer, 3 is the ack itself, \
         4 and 5 are past it"
    );
    assert_eq!(both[0].2, 1, "the second duplicate ack reaches fastresend");
    assert_eq!(both[0].3, vec![0xFFFF_FFFF, 2, 0, 0, 0, 0]);
    assert_eq!(
        both[0], both[1],
        "the offset path and kcp-go's scan disagree about the exclusions"
    );
}

// ---------------------------------------------------------------------------------------
// The fallback, and the invariant it protects
// ---------------------------------------------------------------------------------------

/// A `snd_buf` whose sequence numbers are not contiguous, which no code path produces, since
/// `flush` only appends `snd_nxt` and `parse_una` only discards a prefix: makes the offset
/// land on the wrong segment or past the end. The lookup checks the segment it finds, misses,
/// and the ACK falls back to kcp-go's scan, which decides.
#[test]
fn a_send_buffer_with_a_gap_falls_back_to_the_scan() {
    let _g = snmp_read();
    // Past the end: the offset of sn 15 is 5, the ring holds 3.
    let mut k = hand_built(&[10, 11, 15], 10, 16);
    k.parse_ack(15);
    assert_eq!(
        k.snd_buf.iter().map(|s| s.acked).collect::<Vec<_>>(),
        vec![0, 0, 1],
        "the scan found it where the offset could not"
    );
    assert_eq!(k.ack_index, AckIndex::default_with_misses(1));

    assert_eq!(k.parse_fastack(15, T0 as u32), 0);
    assert_eq!(
        k.snd_buf.iter().map(|s| s.fastack).collect::<Vec<_>>(),
        vec![1, 1, 0],
        "the two segments before it are counted, it is not"
    );
    assert_eq!(k.ack_index.misses, 2);

    // Inside the ring but on the wrong segment: the offset of sn 12 is 2, which holds 13.
    let mut k = hand_built(&[10, 12, 13], 10, 14);
    k.parse_ack(12);
    assert_eq!(
        k.snd_buf.iter().map(|s| s.acked).collect::<Vec<_>>(),
        vec![0, 1, 0]
    );
    assert_eq!(k.ack_index, AckIndex::default_with_misses(1));
}

/// The one thing the offset cannot check for itself: that the scan would have *reached* it.
/// The scan stops at the first segment past `sn`, so a ring holding a larger sequence number
/// in front of `sn` would make the two disagree, and debug builds catch it on every lookup.
/// Nothing produces such a ring; this test exists to show that the net is real.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "is not where the scan stops")]
fn an_out_of_order_send_buffer_trips_the_debug_check() {
    let _g = snmp_read();
    // The offset of sn 12 is 2 and the segment there does carry sn 12, but kcp-go's scan
    // would have stopped at sn 15 and left it alone.
    let mut k = hand_built(&[10, 15, 12], 10, 16);
    k.parse_ack(12);
}

/// A `Kcp` whose `snd_buf` is these sequence numbers in this order, with `snd_una` and
/// `snd_nxt` as given. Only the tests above build one: every real ring is contiguous.
fn hand_built(sns: &[u32], snd_una: u32, snd_nxt: u32) -> scan_tests::ScanKcp {
    let (mut k, _sink, _clock) = fixture();
    for &sn in sns {
        k.snd_buf.push(Segment {
            sn,
            xmit: 1,
            ..Segment::default()
        });
    }
    k.snd_una = snd_una;
    k.snd_nxt = snd_nxt;
    k
}

impl AckIndex {
    /// `AckIndex::default()` with `misses`, for the two tests that expect one.
    fn default_with_misses(misses: u64) -> AckIndex {
        AckIndex {
            misses,
            ..AckIndex::default()
        }
    }
}

/// Every send-buffer field an ACK can write.
fn state_of(k: &scan_tests::ScanKcp) -> Vec<(u32, u32, u32, u32, usize)> {
    k.snd_buf
        .iter()
        .map(|s| (s.sn, s.fastack, s.acked, s.ts, s.data.len()))
        .collect()
}

// ---------------------------------------------------------------------------------------
// Randomised two-endpoint traces (DECISIONS D25)
// ---------------------------------------------------------------------------------------

/// The D25 differential test for the ACK path, on links that lose, reorder and duplicate,
/// where a selective ACK reaches deep into the window and an off-by-one in the offset would
/// show up as one `fastack` too many or too few. The optimised endpoints must put exactly the
/// same bytes on the wire as the naive ones, end in the same state segment by segment, return
/// the same `nextUpdate` from every flush and finish at the same virtual millisecond.
///
/// The traces are the D29 ones biased towards loss: 5 % to 20 % in each direction (kcp-go's
/// link model reorders 5 % of what survives on any lossy link), which is what keeps `una`
/// behind and forces the selective path both ends spend this test in.
#[test]
fn the_ack_index_is_byte_identical_to_the_naive_scan() {
    let _g = snmp_read();
    let mut total_skipped = 0u64;
    let mut total_hits = 0u64;
    for seed in 1..=12u64 {
        let base = SimCfg {
            seed,
            policy: Policy::Unbounded,
            limit: usize::MAX,
            drain: usize::MAX,
            payload: 256 * 1024,
            chunk: if seed % 3 == 0 { 4 * 1024 } else { 64 * 1024 },
            snd_wnd: if seed % 2 == 0 { 256 } else { 1024 },
            rcv_wnd: 1024,
            nodelay: if seed % 4 == 0 {
                [1, 10, 2, 1]
            } else {
                [0, 40, 2, 1]
            },
            // Heavier than D29's traces: a hole in the window on nearly every burst.
            loss: 0.05 + 0.05 * (seed % 4) as f64,
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
            oracle.ack_index,
            [AckIndex::default(); 2],
            "seed {seed}: the oracle may not compute a ring offset"
        );
        assert_eq!(
            fast.end_ms, oracle.end_ms,
            "seed {seed}: the transfer ended at a different time"
        );
        assert_eq!(fast.state, oracle.state, "seed {seed}: different state");
        assert_eq!(
            fast.digest, oracle.digest,
            "seed {seed}: a segment differs (sn, ts, rto, xmit, resendts, fastack or acked)"
        );
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
            assert_eq!(
                fast.ack_index[i].misses, 0,
                "seed {seed}: endpoint {i} found a send buffer that is not contiguous"
            );
            assert!(
                fast.ack_index[i].hits > 0,
                "seed {seed}: endpoint {i} never computed an offset, so this proves nothing"
            );
            total_hits += fast.ack_index[i].hits;
            total_skipped += fast.ack_index[i].skipped;
        }
    }
    println!("ack index over the twelve traces: {total_hits} hits, {total_skipped} skipped");
    assert!(
        total_hits > 5_000,
        "the twelve traces only acknowledged {total_hits} times"
    );
    assert!(
        total_skipped > 200_000,
        "the traces never acknowledged deep into a window: {total_skipped} segments skipped, \
         so the selective path is untested"
    );
}
