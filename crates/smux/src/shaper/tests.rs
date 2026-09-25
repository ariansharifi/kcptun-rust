//! Tests of the shaper, ported from `reference/latest/smux/shaper_test.go` (identical to the
//! pinned v1.5.55 file) plus the ordering cases the Go tests only log.
//!
//! Go's `TestShaper`/`TestShaper2` print the pop order and assert nothing; the ports assert the
//! order Go produces. `TestShaperQueueFairness` and `TestShaperQueue_FastWriteSlowRead` run for
//! 10 s each in Go: the ports run for 1 s with the consumer scaled by the same factor, and the
//! full-length versions are kept as `#[ignore]`d `long_*` tests (porting guide §8).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use kcptun_testkit::rng::{Pcg, fnv1a64};

use super::*;
use crate::frame::{CMD_PSH, Frame};

/// A request with no body, Go's `writeRequest{class: …, seq: …, frame: Frame{sid: …}}`.
fn req(class: ClassId, sid: u32, seq: u32) -> WriteRequest<()> {
    WriteRequest {
        class,
        sid,
        seq,
        body: (),
    }
}

/// The `(sid, seq)` pairs a queue yields until it runs dry.
fn drain(sq: &mut ShaperQueue<()>) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    while let Some(r) = sq.pop() {
        out.push((r.sid, r.seq));
    }
    out
}

// Go: shaper_test.go:TestShaper()
#[test]
fn test_shaper() {
    // Go's writeRequest zero value has class CLSCTRL and sid 0.
    let mut reqs = ShaperHeap::new();
    for seq in [5, 4, 3, 2, 1] {
        reqs.push(req(ClassId::Ctrl, 0, seq));
    }

    let mut order = Vec::new();
    while let Some(w) = reqs.pop() {
        order.push((w.sid, w.seq));
    }
    assert_eq!(order, vec![(0, 1), (0, 2), (0, 3), (0, 4), (0, 5)]);
}

// Go: shaper_test.go:TestShaper2()
#[test]
fn test_shaper2() {
    let mut reqs = ShaperHeap::new();
    reqs.push(req(ClassId::Ctrl, 10, 6)); // ctrl 1
    for seq in [5, 4, 3, 2, 1] {
        reqs.push(req(ClassId::Data, 0, seq)); // stream 0
    }
    reqs.push(req(ClassId::Ctrl, 11, 7)); // ctrl 2

    let mut order = Vec::new();
    while let Some(w) = reqs.pop() {
        order.push((w.sid, w.seq));
    }
    // Control frames first (by seq), then the data frames in sequence order.
    assert_eq!(
        order,
        vec![(10, 6), (11, 7), (0, 1), (0, 2), (0, 3), (0, 4), (0, 5)]
    );
}

// Go: shaper_test.go:TestShaperQueue_PopBoundary()
#[test]
fn test_shaper_queue_pop_boundary() {
    let mut sq: ShaperQueue<()> = ShaperQueue::new();

    // 1. Empty Queue
    assert!(sq.pop().is_none(), "Pop on empty queue should return false");

    // 2. Single Stream Lifecycle
    // Push 2 items to Stream 10
    sq.push(req(ClassId::Ctrl, 10, 1));
    sq.push(req(ClassId::Ctrl, 10, 2));

    assert_eq!(sq.len(), 2, "Expected len 2");

    // Pop 1
    let r = sq.pop().expect("queue holds two requests");
    assert_eq!((r.sid, r.seq), (10, 1), "Expected sid 10 seq 1");
    // Check internals
    assert_eq!(sq.num_streams(), 1, "Expected 1 stream in map");
    assert_eq!(sq.rr_list.len(), 1, "Expected 1 item in rrList");

    // Pop 2 (Stream becomes empty)
    let r = sq.pop().expect("queue holds one request");
    assert_eq!((r.sid, r.seq), (10, 2), "Expected sid 10 seq 2");
    // Check internals - should be cleaned up
    assert_eq!(sq.num_streams(), 0, "Expected 0 streams in map");
    assert_eq!(sq.rr_list.len(), 0, "Expected 0 items in rrList");
    assert!(sq.next.is_none(), "Expected next to be nil");
    assert_eq!(sq.len(), 0);

    // Pop empty again
    assert!(sq.pop().is_none(), "Pop on empty queue should return false");
}

// Go: shaper_test.go:TestShaperQueue_MultiStreamRemoval()
#[test]
fn test_shaper_queue_multi_stream_removal() {
    let mut sq: ShaperQueue<()> = ShaperQueue::new();

    // Setup:
    // Stream 10: 1 item
    // Stream 20: 2 items
    // Stream 30: 1 item
    // Push order matters for the initial round-robin order; new streams are appended.
    // Order in list: 10, 20, 30
    sq.push(req(ClassId::Ctrl, 10, 1));
    sq.push(req(ClassId::Ctrl, 20, 1));
    sq.push(req(ClassId::Ctrl, 20, 2));
    sq.push(req(ClassId::Ctrl, 30, 1));

    // Current List: [10, 20, 30], next: 10

    // 1. Pop Stream 10 (seq 1). Stream 10 becomes empty and should be removed.
    // Next should move to 20.
    let r = sq.pop().expect("stream 10 has a request");
    assert_eq!(r.sid, 10, "Expected sid 10");
    assert!(
        !sq.streams.contains_key(&10),
        "Stream 10 should be removed from the map"
    );
    assert_eq!(sq.rr_list.len(), 2, "Expected list len 2");

    // 2. Pop Stream 20 (seq 1). Stream 20 has 1 left. Next should move to 30.
    let r = sq.pop().expect("stream 20 has requests");
    assert_eq!((r.sid, r.seq), (20, 1), "Expected sid 20 seq 1");
    assert_eq!(sq.rr_list.len(), 2, "Expected list len 2");

    // 3. Pop Stream 30 (seq 1). Stream 30 becomes empty and removed.
    // Next should wrap around to 20.
    let r = sq.pop().expect("stream 30 has a request");
    assert_eq!(r.sid, 30, "Expected sid 30");
    assert!(
        !sq.streams.contains_key(&30),
        "Stream 30 should be removed from the map"
    );
    assert_eq!(sq.rr_list.len(), 1, "Expected list len 1");

    // 4. Pop Stream 20 (seq 2). Stream 20 becomes empty and removed. List becomes empty.
    let r = sq.pop().expect("stream 20 has its second request");
    assert_eq!((r.sid, r.seq), (20, 2), "Expected sid 20 seq 2");
    assert_eq!(sq.rr_list.len(), 0, "Expected list len 0");
    assert!(sq.next.is_none(), "Expected next to be nil");
    assert!(sq.is_empty());
}

// Go: shaper_test.go:TestShaperHeap_MemoryLeak()
//
// Pinned smux v1.5.55 already clears the vacated backing-array slot in `shaperHeap.Pop` so the
// popped frame's payload is not kept alive. The Rust equivalent is that the heap holds no
// reference to a popped request: `Vec::pop` moves it out, and dropping it releases the payload.
// An `Arc` payload makes that observable.
#[test]
fn test_shaper_heap_memory_leak() {
    let payload: Arc<Vec<u8>> = Arc::new(vec![0u8; 100]);
    let mut h: ShaperHeap<Arc<Vec<u8>>> = ShaperHeap::new();

    h.push(WriteRequest {
        class: ClassId::Data,
        sid: 1,
        seq: 1,
        body: Arc::clone(&payload),
    });
    assert_eq!(h.len(), 1, "Heap len should be 1");
    assert_eq!(Arc::strong_count(&payload), 2);

    let popped = h.pop().expect("heap holds one request");
    assert_eq!(popped.sid, 1, "Incorrect popped item");
    assert_eq!(h.len(), 0, "Heap len should be 0");
    // The heap's backing array no longer references the payload.
    assert_eq!(Arc::strong_count(&payload), 2);
    drop(popped);
    assert_eq!(Arc::strong_count(&payload), 1);

    // The same for a whole queue: emptying a stream drops its heap.
    let mut sq: ShaperQueue<Arc<Vec<u8>>> = ShaperQueue::new();
    for seq in 0..8 {
        sq.push(WriteRequest {
            class: ClassId::Data,
            sid: 7,
            seq,
            body: Arc::clone(&payload),
        });
    }
    assert_eq!(Arc::strong_count(&payload), 9);
    while let Some(r) = sq.pop() {
        drop(r);
    }
    assert_eq!(Arc::strong_count(&payload), 1);
    assert_eq!(sq.num_streams(), 0);
}

// Go: shaper_test.go:TestShaperIsEmpty()
#[test]
fn test_shaper_is_empty() {
    let mut sq: ShaperQueue<()> = ShaperQueue::new();
    assert!(sq.is_empty(), "ShaperQueue should be empty");

    // Go: writeRequest{frame: newFrame(1, cmdPSH, 1)}
    let f = Frame::new(1, CMD_PSH, 1);
    sq.push(req(ClassId::Ctrl, f.sid, 0));
    assert!(!sq.is_empty(), "ShaperQueue should not be empty");
    assert_eq!(sq.len(), 1);
}

// ---------------------------------------------------------------------------------------------
// Ordering cases the Go tests do not cover (the frame order on the wire, WIRE-FORMAT §7).
// ---------------------------------------------------------------------------------------------

/// Round-robin serves one frame per stream per turn, in the order the streams first queued.
#[test]
fn round_robin_serves_one_frame_per_stream() {
    let mut sq: ShaperQueue<()> = ShaperQueue::new();
    for seq in 0..3 {
        sq.push(req(ClassId::Data, 1, seq));
    }
    sq.push(req(ClassId::Data, 2, 100));
    sq.push(req(ClassId::Data, 3, 200));

    assert_eq!(
        drain(&mut sq),
        vec![(1, 0), (2, 100), (3, 200), (1, 1), (1, 2)]
    );
}

/// A stream id that queues its first frame while the cursor is mid-cycle joins at the back of
/// the round-robin list, so the ids the cursor has not reached yet are still served first. This
/// is what distinguishes Go's list-plus-cursor from a queue that re-appends the id it served.
#[test]
fn new_stream_joins_at_the_back_of_the_cycle() {
    let mut sq: ShaperQueue<()> = ShaperQueue::new();
    for sid in [10u32, 20, 30] {
        sq.push(req(ClassId::Data, sid, sid));
        sq.push(req(ClassId::Data, sid, sid + 1));
    }

    // Serve 10; the cursor now points at 20.
    assert_eq!(sq.pop().map(|r| r.sid), Some(10));
    // 40 appears now: it goes behind 30, not in front of 20.
    sq.push(req(ClassId::Data, 40, 400));

    let rest: Vec<u32> = std::iter::from_fn(|| sq.pop().map(|r| r.sid)).collect();
    assert_eq!(rest, vec![20, 30, 40, 10, 20, 30]);
}

/// Inside one stream the class decides first: a `cmdSYN`/`cmdUPD` queued after data still goes
/// out first, while a `cmdFIN` (DATA class) stays behind the stream's data. Across streams the
/// class means nothing — a control frame does not overtake another stream's turn.
#[test]
fn class_orders_within_a_stream_only() {
    let mut sq: ShaperQueue<()> = ShaperQueue::new();
    sq.push(req(ClassId::Data, 1, 0)); // PSH
    sq.push(req(ClassId::Data, 1, 1)); // PSH
    sq.push(req(ClassId::Data, 1, 2)); // FIN: DATA class, stays last
    sq.push(req(ClassId::Ctrl, 1, 3)); // UPD: CTRL class, jumps ahead
    sq.push(req(ClassId::Data, 2, 4)); // another stream's data

    assert_eq!(
        drain(&mut sq),
        vec![(1, 3), (2, 4), (1, 0), (1, 1), (1, 2)],
        "ctrl first inside stream 1, but stream 2 keeps its round-robin turn"
    );
}

/// The sequence compare wraps (`_itimediff`), so a request queued just before the `u32` wrap
/// still precedes the ones queued after it.
#[test]
fn sequence_numbers_compare_wrapping() {
    let mut sq: ShaperQueue<()> = ShaperQueue::new();
    for seq in [2u32, 0, u32::MAX, 1, u32::MAX - 1] {
        sq.push(req(ClassId::Data, 1, seq));
    }
    assert_eq!(
        drain(&mut sq),
        vec![(1, u32::MAX - 1), (1, u32::MAX), (1, 0), (1, 1), (1, 2)]
    );
    assert_eq!(itimediff(0, u32::MAX), 1);
    assert_eq!(itimediff(u32::MAX, 0), -1);
}

/// Stream 0 (the keepalive `cmdNOP`) is an ordinary round-robin member.
#[test]
fn keepalive_stream_zero_has_no_global_priority() {
    let mut sq: ShaperQueue<()> = ShaperQueue::new();
    sq.push(req(ClassId::Data, 3, 0));
    sq.push(req(ClassId::Data, 3, 1));
    sq.push(req(ClassId::Ctrl, 0, 2)); // NOP on sid 0, CLSCTRL
    assert_eq!(drain(&mut sq), vec![(3, 0), (0, 2), (3, 1)]);
}

/// Slots of removed stream ids are reused, so a long-lived session does not grow the list slab.
#[test]
fn rr_list_slots_are_reused() {
    let mut sq: ShaperQueue<()> = ShaperQueue::new();
    for round in 0..1000u32 {
        sq.push(req(ClassId::Data, round, round));
        sq.push(req(ClassId::Data, round + 1, round));
        assert!(sq.pop().is_some());
        assert!(sq.pop().is_some());
    }
    assert!(sq.is_empty());
    assert_eq!(sq.num_streams(), 0);
    assert_eq!(sq.rr_list.len(), 0);
    assert!(sq.rr_list.slots.len() <= 2, "slab should stay tiny");
}

// ---------------------------------------------------------------------------------------------
// Differential trace against the pinned Go shaper.
// ---------------------------------------------------------------------------------------------

/// Builds a deterministic push/pop trace and returns its transcript.
///
/// The generator uses `kcptun_testkit::rng::Pcg`, which is bit-for-bit Go's `math/rand/v2`
/// `rand.NewPCG`, so the very same trace can be replayed against the Go `shaperQueue`.
fn diff_transcript() -> String {
    let sids = [0u32, 3, 5, 7, 9, 11];
    let mut p = Pcg::new(0x5359_4e43, 0x5348_4150);
    let mut seq = u32::MAX - 5;
    let mut sq: ShaperQueue<()> = ShaperQueue::new();
    let mut t = String::new();

    for _ in 0..400 {
        if p.below(100) < 60 {
            let sid = sids[p.below(sids.len() as u64) as usize];
            let class = if p.below(4) == 0 {
                ClassId::Ctrl
            } else {
                ClassId::Data
            };
            sq.push(req(class, sid, seq));
            t.push_str(&format!("P {} {} {}", sid, class as i32, seq));
            seq = seq.wrapping_add(1);
        } else if let Some(r) = sq.pop() {
            t.push_str(&format!("O {} {} {}", r.sid, r.class as i32, r.seq));
        } else {
            t.push('E');
        }
        t.push_str(&format!("|{},{}\n", sq.len(), sq.num_streams()));
    }
    while let Some(r) = sq.pop() {
        t.push_str(&format!(
            "O {} {} {}|{},{}\n",
            r.sid,
            r.class as i32,
            r.seq,
            sq.len(),
            sq.num_streams()
        ));
    }
    t.push_str(&format!(
        "END|{},{},{}\n",
        sq.len(),
        sq.num_streams(),
        sq.next.is_none()
    ));
    t
}

/// Replays a 400-operation trace (mixed classes, six stream ids, sequence numbers crossing the
/// `u32` wrap) and compares the transcript — every pop, the queue length and the number of live
/// stream heaps after each operation — with the pinned Go `shaperQueue`.
///
/// The expected digest comes from an ad-hoc `go test` run of the same trace against a copy of
/// `reference/kcptun/vendor/github.com/xtaci/smux` (porting guide §1; the harness is throwaway,
/// the trace generator above is its Rust half and `math/rand/v2` makes both sides draw the same
/// numbers).
#[test]
fn trace_matches_pinned_go_shaper() {
    let t = diff_transcript();
    assert_eq!(t.len(), 6641, "transcript length");
    assert_eq!(
        fnv1a64(t.as_bytes()),
        4_738_545_340_901_715_818,
        "transcript digest (Go TestShaperDiffTrace)"
    );
    // Spot checks from the Go run's printed pop order, including the wrap.
    let pops: Vec<&str> = t
        .lines()
        .filter(|l| l.starts_with('O'))
        .map(|l| l.split('|').next().unwrap_or(l))
        .collect();
    assert_eq!(pops.len(), 222);
    assert_eq!(pops[0], "O 5 1 4294967290");
    assert_eq!(pops[7], "O 11 0 1");
    assert_eq!(pops[pops.len() - 1], "O 5 1 214");
}

// ---------------------------------------------------------------------------------------------
// Fairness under concurrency (ported from Go, with shortened durations).
// ---------------------------------------------------------------------------------------------

struct FairnessResult {
    counts: Vec<u64>,
    remaining: usize,
}

/// The shared part of Go's two fairness tests: `streams` producer threads push into one
/// `Mutex<ShaperQueue>` (the session's layout, DECISIONS D15) while a single consumer thread
/// pops, and every pop is counted per stream.
///
/// `producer_pause` returns the pause after each push, `consumer_pause` the pause between pops
/// (Go's ticker and its `time.Sleep`, which behave the same at these rates). `max_backlog`
/// bounds one stream's pending requests; `None` is Go's unbounded behaviour.
fn fairness_run(
    streams: u32,
    duration: Duration,
    producer_pause: fn(&mut Pcg) -> Duration,
    consumer_pause: Duration,
    max_backlog: Option<u64>,
) -> FairnessResult {
    let sq: Arc<Mutex<ShaperQueue<()>>> = Arc::new(Mutex::new(ShaperQueue::new()));
    let send_count = Arc::new(Mutex::new(vec![0u64; streams as usize]));
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();

    // Producers: each stream pushes packets.
    for sid in 0..streams {
        let sq = Arc::clone(&sq);
        let send_count = Arc::clone(&send_count);
        let stop = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            let mut rng = Pcg::new(0x9e37_79b9_7f4a_7c15, u64::from(sid) + 1);
            let mut seq = 0u32;
            while !stop.load(Ordering::Relaxed) {
                if let Some(limit) = max_backlog {
                    let popped = send_count.lock().unwrap()[sid as usize];
                    if u64::from(seq) - popped >= limit {
                        thread::sleep(Duration::from_micros(200));
                        continue;
                    }
                }
                sq.lock().unwrap().push(req(ClassId::Data, sid, seq));
                seq = seq.wrapping_add(1);
                let pause = producer_pause(&mut rng);
                if !pause.is_zero() {
                    thread::sleep(pause);
                }
            }
        }));
    }

    // Consumer: a slow network, one pop per tick.
    {
        let sq = Arc::clone(&sq);
        let send_count = Arc::clone(&send_count);
        let stop = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                thread::sleep(consumer_pause);
                let popped = sq.lock().unwrap().pop();
                if let Some(r) = popped {
                    send_count.lock().unwrap()[r.sid as usize] += 1;
                }
            }
        }));
    }

    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        h.join().expect("fairness worker panicked");
    }

    let counts = send_count.lock().unwrap().clone();
    let remaining = sq.lock().unwrap().len();
    FairnessResult { counts, remaining }
}

/// Go's fairness check: no stream may be more than `avg/tolerance_div` away from the average.
fn assert_fair(result: &FairnessResult, tolerance_div: u64) {
    let total: u64 = result.counts.iter().sum();
    let streams = result.counts.len() as u64;
    let avg = total / streams;
    let tolerance = avg / tolerance_div;
    // Go prints the same final report (`=== FINAL COUNTS ===`); visible with --nocapture.
    println!(
        "counts={:?} avg={avg} tolerance={tolerance} queue remaining={}",
        result.counts, result.remaining
    );
    assert!(
        avg > 10,
        "too few pops to judge fairness: {:?}",
        result.counts
    );
    for (sid, &c) in result.counts.iter().enumerate() {
        assert!(
            c >= avg - tolerance && c <= avg + tolerance,
            "stream {sid} unfair: got {c}, avg {avg}, counts {:?}, queue remaining {}",
            result.counts,
            result.remaining
        );
    }
}

/// Go: `rand.Intn(300)` microseconds.
fn pause_up_to_300us(rng: &mut Pcg) -> Duration {
    Duration::from_micros(rng.below(300))
}

/// Go: `1 * time.Microsecond`.
fn pause_1us(_rng: &mut Pcg) -> Duration {
    Duration::from_micros(1)
}

// Go: shaper_test.go:TestShaperQueueFairness()
// Go runs 10 s with one pop every 10 ms; this runs 1 s with one pop every millisecond.
#[test]
fn test_shaper_queue_fairness() {
    let result = fairness_run(
        10,
        Duration::from_secs(1),
        pause_up_to_300us,
        Duration::from_millis(1),
        None,
    );
    assert_fair(&result, 4); // 25%, as in Go
}

// Go: shaper_test.go:TestShaperQueue_FastWriteSlowRead()
// Go runs 10 s with a 15 ms consumer pause; this runs 1 s with 1.5 ms. Go's producers push
// without any bound, which would queue millions of requests in a Rust build where
// `thread::sleep(1µs)` really is that short, so each producer stops at 512 pending requests of
// its own stream — the streams stay backlogged, which is what the test is about.
#[test]
fn test_shaper_queue_fast_write_slow_read() {
    let result = fairness_run(
        10,
        Duration::from_secs(1),
        pause_1us,
        Duration::from_micros(1500),
        Some(512),
    );
    assert_fair(&result, 3); // 33%, as in Go
}

// Go: shaper_test.go:TestShaperQueueFairness(), at Go's own duration and rate.
#[test]
#[ignore = "10 s (Go's duration); run with --ignored"]
fn long_shaper_queue_fairness() {
    let result = fairness_run(
        10,
        Duration::from_secs(10),
        pause_up_to_300us,
        Duration::from_millis(10),
        None,
    );
    assert_fair(&result, 4);
}

// Go: shaper_test.go:TestShaperQueue_FastWriteSlowRead(), at Go's own duration and rate.
#[test]
#[ignore = "10 s (Go's duration); run with --ignored"]
fn long_shaper_queue_fast_write_slow_read() {
    let result = fairness_run(
        10,
        Duration::from_secs(10),
        pause_1us,
        Duration::from_millis(15),
        Some(512),
    );
    assert_fair(&result, 3);
}
