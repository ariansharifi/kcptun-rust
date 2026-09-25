//! Ports of kcp-go's `autotune_test.go` (every test of the latest upstream file; the detector
//! logic is unchanged since the pinned v5.6.66, only comments differ) and the Go golden vectors
//! of the `autotune` area.
//!
//! Where a Go test only asserts `> 0` or logs the result, the port additionally asserts the
//! exact value the pinned Go code returns (recorded by running the verbatim kcpcopy of
//! `autotune.go`).

use super::*;
use crate::gosort::coverage;
use kcptun_testkit::vectors;

/// Feeds `signals[i]` (0 or 1) with seq `i` to a fresh detector.
fn tune_from(signals: &[u32]) -> AutoTune {
    let mut tune = AutoTune::new();
    for (i, &signal) in signals.iter().enumerate() {
        tune.sample(signal != 0, i as u32);
    }
    tune
}

/// Go: `TestAutoTune.testGroup`.
#[track_caller]
fn test_group(gid: i32, signals: &[u32], expected_false: i32, expected_true: i32) {
    let mut tune = tune_from(signals);
    assert_eq!(
        tune.find_period(true),
        expected_true,
        "group {gid} {signals:?} (true)"
    );
    assert_eq!(
        tune.find_period(false),
        expected_false,
        "group {gid} {signals:?} (false)"
    );
}

/// Simulates a pop by advancing head (removes the oldest element), as the Go tests do.
fn pop(tune: &mut AutoTune) {
    tune.head = (tune.head + 1) % MAX_AUTO_TUNE_SAMPLES;
    tune.count -= 1;
}

/// A signal of `true_duration` ones then `false_duration` zeros, repeated, starting at seq
/// `base`, `n` samples.
fn sample_periodic(tune: &mut AutoTune, base: u32, n: usize, true_duration: usize, period: usize) {
    for i in 0..n {
        tune.sample(i % period < true_duration, base.wrapping_add(i as u32));
    }
}

// Go: kcp-go@v5.6.72 autotune_test.go:TestAutoTune
#[test]
fn test_auto_tune() {
    test_group(1, &[0, 0, 0, 0, 0, 0], -1, -1);
    test_group(2, &[0, 1, 0, 1, 0, 1], 1, 1);
    test_group(3, &[1, 0, 1, 0, 0, 1], 1, 1);
    test_group(4, &[1, 0, 0, 0, 0, 1], 4, -1);
    test_group(5, &[1, 1, 1, 1, 1, 1], -1, -1);
    test_group(6, &[1, 1, 0, 1, 1, 0], 1, 2);
    test_group(7, &[0, 1, 1, 1, 0, 1], 1, 3);
    test_group(8, &[1, 1, 1, 1, 1, 1], -1, -1);
    test_group(9, &[0, 1, 1, 1, 1, 0], -1, 4);
    test_group(10, &[0, 0, 1, 1, 0, 0], -1, 2);
    test_group(11, &[0, 0, 0, 1, 1, 1], -1, -1);
    test_group(12, &[0, 0, 0, 0, 0, 1], -1, -1);
    test_group(13, &[1, 0, 0, 0, 0, 1], 4, -1);
    test_group(14, &[1, 0, 0, 0, 0, 0], -1, -1);
}

// Go: kcp-go@v5.6.72 autotune_test.go:TestAutoTuneEdge
#[test]
fn test_auto_tune_edge() {
    test_group(0, &[], -1, -1); // empty signals
    test_group(2, &[1], -1, -1); // 1 signal
    test_group(3, &[1, 0], -1, -1); // 2 signals
    test_group(4, &[1, 0, 1], 1, -1); // 3 signals
}

// Go: kcp-go@v5.6.72 autotune_test.go:TestAutoTuneOverflow
#[test]
fn test_auto_tune_overflow() {
    let mut tune = AutoTune::new();
    for i in 0..1024u32 {
        tune.sample(!(i as usize).is_multiple_of(MAX_AUTO_TUNE_SAMPLES), i);
        assert!(tune.count <= MAX_AUTO_TUNE_SAMPLES);
    }
    assert_eq!(tune.count, MAX_AUTO_TUNE_SAMPLES);
    assert_eq!(tune.count(), MAX_AUTO_TUNE_SAMPLES);
    // 1024 = 3 * 258 + 250: the ring has been overwritten, tail and head coincide.
    assert_eq!(tune.head, 1024 % MAX_AUTO_TUNE_SAMPLES);
    assert_eq!(tune.tail, tune.head);
}

// Go: kcp-go@v5.6.72 autotune_test.go:TestAutoTunePop
#[test]
fn test_auto_tune_pop() {
    let mut tune = tune_from(&[0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0]);
    assert_eq!(tune.find_period(false), 2);
    assert_eq!(tune.find_period(true), 2);

    pop(&mut tune);
    assert_eq!(tune.find_period(false), 2);
    assert_eq!(tune.find_period(true), 1);

    // after popping more
    pop(&mut tune);
    pop(&mut tune);
    pop(&mut tune);
    assert_eq!(tune.find_period(false), 1);
    assert_eq!(tune.find_period(true), 1);
}

// Go: kcp-go@v5.6.72 autotune_test.go:TestAutoTuneRingBufferWrapAround
#[test]
fn test_auto_tune_ring_buffer_wrap_around() {
    // (name, period, total samples, bit, exact pinned-Go result)
    let cases = [
        ("Period3_2xBuffer", 3, MAX_AUTO_TUNE_SAMPLES * 2, true, 1),
        ("Period5_3xBuffer", 5, MAX_AUTO_TUNE_SAMPLES * 3, true, 2),
        ("Period7_4xBuffer", 7, MAX_AUTO_TUNE_SAMPLES * 4, true, 3),
        ("Period10_2xBuffer", 10, MAX_AUTO_TUNE_SAMPLES * 2, true, 5),
        (
            "Period3_2xBuffer_False",
            3,
            MAX_AUTO_TUNE_SAMPLES * 2,
            false,
            2,
        ),
        (
            "Period5_3xBuffer_False",
            5,
            MAX_AUTO_TUNE_SAMPLES * 3,
            false,
            3,
        ),
    ];
    for (name, period, total, bit, go_result) in cases {
        let mut tune = AutoTune::new();
        let half_period = (period / 2).max(1);
        // Generate periodic signal: N samples of 1, then N samples of 0
        sample_periodic(&mut tune, 0, total, half_period, period);
        assert_eq!(tune.count, MAX_AUTO_TUNE_SAMPLES, "{name}");
        let found = tune.find_period(bit);
        assert!(found > 0, "{name}: should find a valid period");
        assert_eq!(found, go_result, "{name}");
    }
}

// Go: kcp-go@v5.6.72 autotune_test.go:TestAutoTuneStablePeriodAfterOverwrite
#[test]
fn test_auto_tune_stable_period_after_overwrite() {
    let mut tune = AutoTune::new();
    let period = 6;
    let true_duration = 3;
    let mut periods_found = Vec::new();
    for i in 0..MAX_AUTO_TUNE_SAMPLES * 5 {
        tune.sample(i % period < true_duration, i as u32);
        if tune.count == MAX_AUTO_TUNE_SAMPLES && i % 50 == 0 {
            let p = tune.find_period(true);
            if p > 0 {
                periods_found.push(p);
            }
        }
    }
    assert!(
        !periods_found.is_empty(),
        "should have found periods during sampling"
    );
    // Pinned Go finds 3 at all 20 checks.
    assert_eq!(periods_found, vec![3; 20]);
}

// Go: kcp-go@v5.6.72 autotune_test.go:TestAutoTuneVariousPeriodsFull
#[test]
fn test_auto_tune_various_periods_full() {
    for period in [2usize, 4, 6, 8, 10, 12, 16, 20, 32, 50] {
        let mut tune = AutoTune::new();
        let true_duration = (period / 2).max(1);
        sample_periodic(
            &mut tune,
            0,
            MAX_AUTO_TUNE_SAMPLES + 100,
            true_duration,
            period,
        );
        assert_eq!(tune.count, MAX_AUTO_TUNE_SAMPLES);
        let period_true = tune.find_period(true);
        let period_false = tune.find_period(false);
        assert!(period_true > 0 || period_false > 0, "period {period}");
        // Pinned Go: both equal half the period.
        let half = (period / 2) as i32;
        assert_eq!((period_true, period_false), (half, half), "period {period}");
    }
}

// Go: kcp-go@v5.6.72 autotune_test.go:TestAutoTuneContinuousOverwrite
#[test]
fn test_auto_tune_continuous_overwrite() {
    let mut tune = AutoTune::new();
    let n = MAX_AUTO_TUNE_SAMPLES;

    // First phase: fill with period 4 signal
    sample_periodic(&mut tune, 0, n, 2, 4);
    assert_eq!(tune.count, n);
    let p1 = tune.find_period(true);
    assert!(p1 > 0, "should find period in phase 1");

    // Second phase: continue with period 6 signal
    sample_periodic(&mut tune, n as u32, n, 3, 6);
    let p2 = tune.find_period(true);
    assert!(p2 > 0, "should find period in phase 2");

    // Third phase: continue with period 8 signal
    sample_periodic(&mut tune, (n * 2) as u32, n, 4, 8);
    let p3 = tune.find_period(true);
    assert!(p3 > 0, "should find period in phase 3");

    // Pinned Go: 2, 3, 4.
    assert_eq!((p1, p2, p3), (2, 3, 4));
}

// Go: kcp-go@v5.6.72 autotune_test.go:TestAutoTunePeriodChangeAfterOverwrite
#[test]
fn test_auto_tune_period_change_after_overwrite() {
    // (name, old true, old false, new true, new false, expected new true, expected new false)
    let cases = [
        ("Period_2to4", 1, 1, 2, 2, 2, 2),
        ("Period_4to2", 2, 2, 1, 1, 1, 1),
        ("Period_4to8", 2, 2, 4, 4, 4, 4),
        ("Period_8to4", 4, 4, 2, 2, 2, 2),
        ("Period_6to10", 3, 3, 5, 5, 5, 5),
        ("Period_10to6", 5, 5, 3, 3, 3, 3),
        ("Period_3to7", 1, 2, 3, 4, 3, 4),
        ("Period_Asym2T4F_to_5T3F", 2, 4, 5, 3, 5, 3),
    ];
    for (name, old_t, old_f, new_t, new_f, exp_t, exp_f) in cases {
        let mut tune = AutoTune::new();
        let n = MAX_AUTO_TUNE_SAMPLES;

        // Phase 1: Fill buffer completely with old period signal
        sample_periodic(&mut tune, 0, n, old_t, old_t + old_f);
        assert_eq!(
            tune.find_period(true),
            old_t as i32,
            "{name}: old true period"
        );
        assert_eq!(
            tune.find_period(false),
            old_f as i32,
            "{name}: old false period"
        );

        // Phase 2: Overwrite with new period signal
        sample_periodic(&mut tune, n as u32, n, new_t, new_t + new_f);
        assert_eq!(tune.find_period(true), exp_t, "{name}: new true period");
        assert_eq!(tune.find_period(false), exp_f, "{name}: new false period");
    }
}

// Go: kcp-go@v5.6.72 autotune_test.go:TestAutoTuneMultiplePeriodChanges
#[test]
fn test_auto_tune_multiple_period_changes() {
    let mut tune = AutoTune::new();
    let period_sequence = [(2, 2), (3, 3), (5, 5), (1, 1), (4, 4), (2, 6), (7, 3)];
    let mut seq = 0u32;
    for (phase, (true_duration, false_duration)) in period_sequence.into_iter().enumerate() {
        let period = true_duration + false_duration;
        for i in 0..MAX_AUTO_TUNE_SAMPLES {
            tune.sample(i % period < true_duration, seq);
            seq = seq.wrapping_add(1);
        }
        let phase = phase + 1;
        assert_eq!(
            tune.find_period(true),
            true_duration as i32,
            "phase {phase}: true period"
        );
        assert_eq!(
            tune.find_period(false),
            false_duration as i32,
            "phase {phase}: false period"
        );
    }
}

// Go: kcp-go@v5.6.72 autotune_test.go:TestAutoTuneGradualPeriodTransition
#[test]
fn test_auto_tune_gradual_period_transition() {
    let mut tune = AutoTune::new();
    let n = MAX_AUTO_TUNE_SAMPLES;

    // First: fill with period 4 (2T+2F)
    sample_periodic(&mut tune, 0, n, 2, 4);
    assert_eq!(tune.find_period(true), 2);
    assert_eq!(tune.find_period(false), 2);

    // Now gradually replace with period 6 (3T+3F)
    let mut transition_complete_true = None;
    let mut transition_complete_false = None;
    for i in 0..n {
        tune.sample(i % 6 < 3, (n + i) as u32);
        if i % 10 == 0 && i > 0 {
            let found_true = tune.find_period(true);
            let found_false = tune.find_period(false);
            // Pinned Go: the first complete pulse is still an old one at every check.
            assert_eq!((found_true, found_false), (2, 2), "sample {i}");
            if found_true == 3 && transition_complete_true.is_none() {
                transition_complete_true = Some(i);
            }
            if found_false == 3 && transition_complete_false.is_none() {
                transition_complete_false = Some(i);
            }
        }
    }
    assert_eq!(
        (transition_complete_true, transition_complete_false),
        (None, None)
    );

    // After full overwrite, should definitely find new period for both
    assert_eq!(
        tune.find_period(true),
        3,
        "after full overwrite, new true period"
    );
    assert_eq!(
        tune.find_period(false),
        3,
        "after full overwrite, new false period"
    );
}

// Go: kcp-go@v5.6.72 autotune_test.go:TestAutoTuneExactPeriodAfterWrap
#[test]
fn test_auto_tune_exact_period_after_wrap() {
    let cases = [
        ("1T_1F", 1, 1, 1, 1),
        ("2T_2F", 2, 2, 2, 2),
        ("3T_3F", 3, 3, 3, 3),
        ("4T_4F", 4, 4, 4, 4),
        ("5T_5F", 5, 5, 5, 5),
        ("2T_4F", 2, 4, 2, 4),
        ("4T_2F", 4, 2, 4, 2),
        ("3T_6F", 3, 6, 3, 6),
        ("6T_3F", 6, 3, 6, 3),
    ];
    for (name, true_duration, false_duration, exp_true, exp_false) in cases {
        let mut tune = AutoTune::new();
        let period = true_duration + false_duration;
        sample_periodic(
            &mut tune,
            0,
            MAX_AUTO_TUNE_SAMPLES * 3,
            true_duration,
            period,
        );
        assert_eq!(tune.count, MAX_AUTO_TUNE_SAMPLES, "{name}");
        assert_eq!(tune.find_period(true), exp_true, "{name}: true period");
        assert_eq!(tune.find_period(false), exp_false, "{name}: false period");
    }
}

// Go: kcp-go@v5.6.72 autotune_test.go:TestAutoTuneSequenceWrapAround
#[test]
fn test_auto_tune_sequence_wrap_around() {
    let mut tune = AutoTune::new();
    // Start from a high sequence number close to uint32 max
    let start_seq = 0xFFFF_FFFFu32 - 100;
    sample_periodic(&mut tune, start_seq, MAX_AUTO_TUNE_SAMPLES + 50, 2, 4);
    // Go only logs these; the pinned code returns 2 and 2 (the wrapping comparison and the
    // wrapping `seq + 1` keep the run continuous across 2^32).
    assert_eq!(tune.find_period(true), 2);
    assert_eq!(tune.find_period(false), 2);
}

/// `find_period` leaves the ring untouched and gives the same answer when repeated.
#[test]
fn find_period_is_repeatable() {
    let mut tune = tune_from(&[1, 1, 0, 1, 1, 0, 1, 1, 0]);
    let before = (tune.pulses, tune.head, tune.tail, tune.count);
    for _ in 0..3 {
        assert_eq!(tune.find_period(true), 2);
        assert_eq!(tune.find_period(false), 1);
    }
    assert_eq!((tune.pulses, tune.head, tune.tail, tune.count), before);
}

/// Decodes the 5-byte `seq (u32 LE), bit` records of the vector file.
fn decode_pulses(b: &[u8]) -> Vec<Pulse> {
    assert_eq!(b.len() % 5, 0, "pulse records are 5 bytes");
    b.as_chunks::<5>()
        .0
        .iter()
        .map(|c| Pulse {
            seq: u32::from_le_bytes([c[0], c[1], c[2], c[3]]),
            bit: match c[4] {
                0 => false,
                1 => true,
                v => panic!("bad bit byte {v}"),
            },
        })
        .collect()
}

/// Every case of `autotune.json`: the same FindPeriod results as the pinned Go code, and the
/// same sorted order (Go's `sort.Slice`, including ties and cyclic comparisons). Also checks that
/// the vectors reach every rare path of the ported pdqsort.
#[test]
fn vectors_autotune() {
    let file = vectors!("autotune");
    assert_eq!(file.len(), 13 * 8);
    coverage::reset();
    for case in file.cases_with_prefix("") {
        let name = &case.name;
        let samples = decode_pulses(&case.bytes("samples"));
        let pops: usize = case.get("pops").map_or(0, |_| case.field("pops"));
        let count: usize = case.field("count");
        let find_true: i32 = case.field("find_true");
        let find_false: i32 = case.field("find_false");

        let mut tune = AutoTune::new();
        for p in &samples {
            tune.sample(p.bit, p.seq);
        }
        for _ in 0..pops {
            pop(&mut tune);
        }
        assert_eq!(tune.count, count, "{name}: count");

        assert_eq!(
            tune.find_period(true),
            find_true,
            "{name}: find_period(true)"
        );
        let sorted_true = tune.sort_cache[..count].to_vec();
        assert_eq!(
            tune.find_period(false),
            find_false,
            "{name}: find_period(false)"
        );
        if count >= 3 {
            let want = decode_pulses(&case.bytes("sorted"));
            assert_eq!(sorted_true.len(), want.len(), "{name}: sorted length");
            if let Some(i) = (0..want.len()).find(|&i| sorted_true[i] != want[i]) {
                panic!(
                    "{name}: sorted order differs from Go at {i}: got {:?}, want {:?}",
                    sorted_true[i], want[i]
                );
            }
            assert_eq!(
                &tune.sort_cache[..count],
                &want[..],
                "{name}: sorted (false)"
            );
        } else {
            assert!(case.get("sorted").is_none(), "{name}");
        }
    }
    for (path, counter) in [
        ("heapSort", &coverage::HEAP_SORT),
        ("breakPatterns", &coverage::BREAK_PATTERNS),
        ("decreasingHint", &coverage::DECREASING_HINT),
        ("partitionEqual", &coverage::PARTITION_EQUAL),
        (
            "partialInsertionSort sorted",
            &coverage::PARTIAL_INSERTION_SORTED,
        ),
        (
            "partialInsertionSort shift",
            &coverage::PARTIAL_INSERTION_SHIFT,
        ),
    ] {
        assert!(counter.with(|c| c.get()) > 0, "vectors never reach {path}");
    }
}
