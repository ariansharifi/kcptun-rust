//! Unit tests of the FEC decoder: construction limits, recovery of 1..=ps lost data shards
//! (with the session's consumer contract), parity-only loss, duplicates, reordering across
//! groups, `paws`, discarding of old shard sets, the newest-shard-id wrap compare, auto-tuning
//! (retune on a parameter change, reset without a change, blocking while no period is found)
//! and robustness against arbitrary input. The Go golden decoder scenarios are in
//! `vector_tests.rs`.

use std::collections::BTreeSet;
use std::sync::{RwLockReadGuard, RwLockWriteGuard};

use super::*;
use crate::kcp::SNMP_TEST_LOCK;
use crate::snmp::SnmpSnapshot;
use proptest::prelude::*;

fn snmp_read() -> RwLockReadGuard<'static, ()> {
    SNMP_TEST_LOCK.read().unwrap_or_else(|e| e.into_inner())
}

fn snmp_write() -> RwLockWriteGuard<'static, ()> {
    SNMP_TEST_LOCK.write().unwrap_or_else(|e| e.into_inner())
}

fn decoder(ds: isize, ps: isize) -> FecDecoder {
    FecDecoder::new(ds, ps).expect("valid shard counts")
}

fn le16(b: &[u8]) -> usize {
    usize::from(u16::from_le_bytes([b[0], b[1]]))
}

/// A FEC stream as the peer's encoder sends it (header offset 0, so every packet starts at
/// the FEC header, which is what `decode` takes).
struct Stream {
    /// All packets (data and parity) in seqid order.
    packets: Vec<Vec<u8>>,
    /// The KCP bytes of every data packet, by seqid.
    kcp: HashMap<u32, Vec<u8>>,
}

impl Stream {
    fn seqid(&self, i: usize) -> u32 {
        fec_seqid(&self.packets[i])
    }

    /// The packet with this seqid.
    fn by_seqid(&self, seqid: u32) -> &[u8] {
        self.packets
            .iter()
            .find(|p| fec_seqid(p) == seqid)
            .expect("seqid in stream")
    }

    /// What `decode` must return for the lost data packet `seqid`: its RS shard (from the size
    /// field) zero-padded to the longest shard of its group.
    fn expected_shard(&self, seqid: u32, ds: u32, ps: u32) -> Vec<u8> {
        let group = seqid / (ds + ps) * (ds + ps);
        let max = (group..group + ds)
            .map(|s| self.by_seqid(s).len() - FEC_HEADER_SIZE)
            .max()
            .expect("group");
        let mut s = self.by_seqid(seqid)[FEC_HEADER_SIZE..].to_vec();
        s.resize(max, 0);
        s
    }
}

/// Encodes `groups` complete groups of `(ds, ps)` with packets of varying size (KCP bytes
/// derived from the seqid), 1 ms apart so every group, including the first, gets its parity.
fn stream(ds: isize, ps: isize, groups: usize) -> Stream {
    let mut enc = FecEncoder::new(ds, ps, 0)
        .expect("valid shard counts")
        .expect("FEC enabled");
    let mut packets = Vec::new();
    let mut kcp = HashMap::new();
    let start = 1_000_000i64;
    // Skip Go's first-group quirk (with ds == 1 the first group's parity is skipped).
    enc.ts_latest_packet = start - 1;
    for n in 0..groups * ds.unsigned_abs() {
        let now = start + n as i64;
        let len = 24 + (n * 37) % 300;
        let body: Vec<u8> = (0..len).map(|i| (n * 7 + i * 13) as u8).collect();
        let mut b = vec![0u8; FEC_HEADER_SIZE_PLUS2];
        b.extend_from_slice(&body);
        let parity: Vec<Vec<u8>> = enc
            .encode(&mut b, MAX_FEC_ENCODE_LATENCY, now)
            .expect("valid packet")
            .iter()
            .map(<[u8]>::to_vec)
            .collect();
        kcp.insert(fec_seqid(&b), body);
        packets.push(b);
        packets.extend(parity);
    }
    assert_eq!(packets.len(), groups * (ds + ps).unsigned_abs());
    Stream { packets, kcp }
}

/// Applies the session's consumer contract (Go `sess.go:kcpInput`) to a recovered shard: the
/// KCP bytes, or `None` if the size field is out of range.
fn consume(r: &[u8]) -> Option<&[u8]> {
    if r.len() < 2 {
        return None;
    }
    let sz = le16(r);
    (2..=r.len()).contains(&sz).then(|| &r[2..sz])
}

/// Counter deltas between two snapshots (FEC fields only; gauges as absolute values).
#[derive(Debug, Default, PartialEq, Eq)]
struct FecCounters {
    full_shard_set: u64,
    recovered: u64,
    errs: u64,
    parity_shards: u64,
}

fn delta(before: &SnmpSnapshot, after: &SnmpSnapshot) -> FecCounters {
    FecCounters {
        full_shard_set: after.fec_full_shard_set - before.fec_full_shard_set,
        recovered: after.fec_recovered - before.fec_recovered,
        errs: after.fec_errs - before.fec_errs,
        parity_shards: after.fec_parity_shards - before.fec_parity_shards,
    }
}

#[test]
fn new_returns_none_unless_valid() {
    for (ds, ps) in [
        (0, 1),
        (1, 0),
        (0, 0),
        (-1, 3),
        (3, -1),
        (200, 57),
        (256, 1),
        (1, 256),
    ] {
        assert!(FecDecoder::new(ds, ps).is_none(), "({ds},{ps})");
    }
    for (ds, ps) in [(1, 1), (10, 3), (200, 56), (128, 128), (255, 1), (1, 255)] {
        let dec = FecDecoder::new(ds, ps).expect("valid");
        let size = (ds + ps) as u32;
        assert_eq!(dec.data_shards(), ds as usize);
        assert_eq!(dec.parity_shards(), ps as usize);
        assert_eq!(dec.paws, 0xffff_ffff / size * size);
        assert_eq!(dec.decode_cache.len(), (ds + ps) as usize);
        assert_eq!(dec.flag_cache.len(), (ds + ps) as usize);
        assert!(dec.shard_set.is_empty());
    }
}

#[test]
fn no_loss_counts_full_shard_sets_and_parity() {
    let _g = snmp_write();
    let (ds, ps, groups) = (10, 3, 4);
    let s = stream(ds, ps, groups);
    let mut dec = decoder(ds, ps);
    let before = DEFAULT_SNMP.copy();
    for p in &s.packets {
        assert!(dec.decode(p).is_empty());
    }
    let after = DEFAULT_SNMP.copy();
    assert_eq!(
        delta(&before, &after),
        FecCounters {
            full_shard_set: groups as u64,
            parity_shards: (groups * 3) as u64,
            ..FecCounters::default()
        }
    );
    assert_eq!(dec.newest_shard_id, (groups - 1) as u32);
    assert_eq!(after.fec_shard_min, (groups - 1) as u64);
    assert_eq!(after.fec_shard_set, groups as u64);
    // Every group's data was popped; the 3 parity packets of each group stay stored.
    for heap in dec.shard_set.values() {
        assert_eq!(heap.len(), 3);
    }
}

#[test]
fn recovers_one_to_ps_losses() {
    let _g = snmp_write();
    for (ds, ps) in [(1isize, 1isize), (2, 1), (3, 2), (4, 4), (10, 3), (20, 5)] {
        let (dsu, psu) = (ds.unsigned_abs() as u32, ps.unsigned_abs() as u32);
        let s = stream(ds, ps, 3);
        for losses in 1..=psu {
            // Lose `losses` data shards per group, at different positions per group.
            for pattern in 0..3u32 {
                let lost: BTreeSet<u32> = (0..3u32)
                    .flat_map(|g| {
                        (0..losses).map(move |i| {
                            let pos = match pattern {
                                0 => i,                   // first ones
                                1 => dsu - 1 - (i % dsu), // last ones
                                _ => (i * 7 + g) % dsu,   // scattered
                            };
                            g * (dsu + psu) + pos
                        })
                    })
                    .collect();
                if lost.len() != (3 * losses) as usize {
                    continue; // pattern collided for tiny ds
                }
                let mut dec = decoder(ds, ps);
                let before = DEFAULT_SNMP.copy();
                let mut got: HashMap<u32, Vec<u8>> = HashMap::new();
                for (i, p) in s.packets.iter().enumerate() {
                    if lost.contains(&s.seqid(i)) {
                        continue;
                    }
                    let group = s.seqid(i) / (dsu + psu) * (dsu + psu);
                    for r in dec.decode(p) {
                        // Identify the recovered seqid by content.
                        let seqid = lost
                            .iter()
                            .copied()
                            .filter(|&l| l / (dsu + psu) * (dsu + psu) == group)
                            .find(|&l| s.expected_shard(l, dsu, psu) == r)
                            .unwrap_or_else(|| panic!("({ds},{ps}) unexpected shard"));
                        assert!(r.capacity() >= MTU_LIMIT);
                        assert_eq!(consume(&r), Some(&s.kcp[&seqid][..]));
                        assert!(got.insert(seqid, r).is_none(), "recovered twice");
                    }
                }
                assert_eq!(
                    got.keys().copied().collect::<BTreeSet<_>>(),
                    lost,
                    "({ds},{ps}) losses {losses} pattern {pattern}"
                );
                let after = DEFAULT_SNMP.copy();
                let d = delta(&before, &after);
                assert_eq!(d.recovered, lost.len() as u64);
                assert_eq!(d.errs, 0);
                assert_eq!(d.full_shard_set, 0);
            }
        }
    }
}

#[test]
fn more_than_ps_losses_are_not_recovered() {
    let _g = snmp_write();
    let (ds, ps) = (10, 3);
    let s = stream(ds, ps, 1);
    let mut dec = decoder(ds, ps);
    let before = DEFAULT_SNMP.copy();
    for (i, p) in s.packets.iter().enumerate() {
        if i < 4 {
            continue; // 4 data shards lost
        }
        assert!(dec.decode(p).is_empty());
    }
    let d = delta(&before, &DEFAULT_SNMP.copy());
    assert_eq!(d.recovered, 0);
    assert_eq!(d.errs, 0);
    assert_eq!(d.full_shard_set, 0);
    assert_eq!(dec.shard_set[&0].len(), 9);
}

#[test]
fn parity_only_loss_is_a_full_shard_set() {
    let _g = snmp_write();
    let (ds, ps) = (4, 2);
    let s = stream(ds, ps, 2);
    let mut dec = decoder(ds, ps);
    let before = DEFAULT_SNMP.copy();
    for p in &s.packets {
        if fec_flag(p) == TYPE_PARITY {
            continue;
        }
        assert!(dec.decode(p).is_empty());
    }
    let d = delta(&before, &DEFAULT_SNMP.copy());
    assert_eq!(
        d,
        FecCounters {
            full_shard_set: 2,
            ..FecCounters::default()
        }
    );
    assert!(dec.shard_set.values().all(|h| h.len() == 0));
}

#[test]
fn duplicates_are_ignored() {
    let _g = snmp_write();
    let (ds, ps) = (4, 2);
    let s = stream(ds, ps, 1);
    let mut dec = decoder(ds, ps);
    let before = DEFAULT_SNMP.copy();
    // data 0, 0, 1, parity 4, 4, 1: the duplicates change nothing.
    let order = [0usize, 0, 1, 4, 4, 1];
    for &i in &order {
        assert!(dec.decode(&s.packets[i]).is_empty());
    }
    assert_eq!(dec.shard_set[&0].len(), 3);
    let d = delta(&before, &DEFAULT_SNMP.copy());
    assert_eq!(d.parity_shards, 1, "duplicate parity is not counted");
    // The 4th distinct shard (data 3) completes the group: data 2 is recovered.
    let r = dec.decode(&s.packets[3]);
    assert_eq!(r.len(), 1);
    assert_eq!(consume(&r[0]), Some(&s.kcp[&2][..]));
}

#[test]
fn packets_after_a_decoded_group_are_stored_again() {
    // Go quirk kept: popping clears the marks and the empty heap stays in the shard set, so
    // a packet of an already decoded group is not a duplicate. With ds == 1 every later
    // packet of the group completes it again.
    let _g = snmp_write();
    let s = stream(1, 1, 1);
    let mut dec = decoder(1, 1);
    let before = DEFAULT_SNMP.copy();
    assert!(dec.decode(&s.packets[0]).is_empty()); // data: full shard set
    // parity alone completes the group again and "recovers" the data shard
    let r = dec.decode(&s.packets[1]);
    assert_eq!(r.len(), 1);
    assert_eq!(consume(&r[0]), Some(&s.kcp[&0][..]));
    assert!(dec.decode(&s.packets[0]).is_empty()); // a repeat of the data: full again
    let d = delta(&before, &DEFAULT_SNMP.copy());
    assert_eq!(d.full_shard_set, 2);
    assert_eq!(d.recovered, 1);

    let s = stream(4, 2, 1);
    let mut dec = decoder(4, 2);
    for p in &s.packets[..4] {
        assert!(dec.decode(p).is_empty());
    }
    assert_eq!(dec.shard_set[&0].len(), 0);
    assert!(dec.decode(&s.packets[2]).is_empty());
    assert_eq!(dec.shard_set[&0].len(), 1);
}

#[test]
fn reorder_across_groups() {
    let _g = snmp_write();
    let (ds, ps) = (5isize, 2isize);
    let n = 7u32;
    let s = stream(ds, ps, 3);
    // Lose data 1 of group 0, data 0 and 4 of group 1, data 3 of group 2; deliver groups
    // interleaved and in reverse order within the interleave.
    let lost: BTreeSet<u32> = [1, n, n + 4, 2 * n + 3].into_iter().collect();
    let mut order: Vec<u32> = Vec::new();
    for pos in (0..n).rev() {
        for g in [2u32, 0, 1] {
            order.push(g * n + pos);
        }
    }
    let mut dec = decoder(ds, ps);
    let mut got = BTreeSet::new();
    for seqid in order {
        if lost.contains(&seqid) {
            continue;
        }
        let group = seqid / n * n;
        for r in dec.decode(s.by_seqid(seqid)) {
            let found = (group..group + 5)
                .find(|&l| s.expected_shard(l, 5, 2) == r)
                .expect("recovered shard is a data shard of the group");
            assert_eq!(consume(&r), Some(&s.kcp[&found][..]));
            assert!(got.insert(found));
        }
    }
    // Each group is decoded when its 5th packet arrives (reverse order: parity 6, 5, then
    // data 4, 3, 2 or so), so the data shards that were lost *or had not arrived yet* are
    // recovered: group 0 {0, 1}, group 1 {7, 11}, group 2 {14, 17}.
    assert!(got.is_superset(&lost));
    assert_eq!(got, [0, 1, 7, 11, 14, 17].into_iter().collect());
    assert_eq!(dec.newest_shard_id, 2);
}

#[test]
fn paws_rejects_large_seqids() {
    let _g = snmp_read();
    let mut dec = decoder(10, 3);
    let paws = dec.paws;
    assert_eq!(paws, 0xffff_ffff / 13 * 13);
    for seqid in [paws, paws + 1, u32::MAX] {
        let mut p = vec![0u8; 20];
        p[..4].copy_from_slice(&seqid.to_le_bytes());
        p[4..6].copy_from_slice(&TYPE_DATA.to_le_bytes());
        let count = dec.auto_tune.count();
        assert!(dec.decode(&p).is_empty());
        // sampled for auto-tuning before the paws check
        assert_eq!(dec.auto_tune.count(), count + 1);
        assert!(dec.shard_set.is_empty());
        assert!(!dec.should_tune);
    }
    // the last valid seqid is accepted (position 7 of its group: data)
    let mut p = vec![0u8; 20];
    p[..4].copy_from_slice(&(paws - 6).to_le_bytes());
    p[4..6].copy_from_slice(&TYPE_DATA.to_le_bytes());
    assert!(dec.decode(&p).is_empty());
    assert_eq!(dec.shard_set.len(), 1);
    // ... but its group start, paws - 13, is "older" than group 0 (negative wrapping
    // difference), so newest_shard_id stays 0.
    assert_eq!(dec.newest_shard_id, 0);
}

#[test]
fn short_packets_are_ignored() {
    let _g = snmp_read();
    let mut dec = decoder(2, 1);
    for len in 0..FEC_HEADER_SIZE {
        assert!(dec.decode(&vec![0xf1; len]).is_empty());
    }
    assert_eq!(dec.auto_tune.count(), 0);
    assert!(dec.shard_set.is_empty());
}

#[test]
fn empty_shards_fail_reconstruction() {
    // Packets of exactly the FEC header: every shard is empty, so ReconstructData fails with
    // ErrShardNoData and FECErrs is counted.
    let _g = snmp_write();
    let mut dec = decoder(2, 1);
    let before = DEFAULT_SNMP.copy();
    let mut data = vec![0u8; 6];
    data[4..6].copy_from_slice(&TYPE_DATA.to_le_bytes());
    let mut parity = vec![0u8; 6];
    parity[..4].copy_from_slice(&2u32.to_le_bytes());
    parity[4..6].copy_from_slice(&TYPE_PARITY.to_le_bytes());
    assert!(dec.decode(&data).is_empty());
    assert!(dec.decode(&parity).is_empty());
    let d = delta(&before, &DEFAULT_SNMP.copy());
    assert_eq!(
        d,
        FecCounters {
            errs: 1,
            parity_shards: 1,
            ..FecCounters::default()
        }
    );
    assert!(dec.decode_cache.iter().all(|s| s.buf.is_empty()));
}

#[test]
fn consumer_contract_bounds() {
    // sz = LE16(r[0..2]); r[2..sz] is fed to KCP only if 2 <= sz <= len(r).
    assert_eq!(consume(&[0xff, 0xff, 1, 2]), None);
    assert_eq!(consume(&[1, 0, 1, 2]), None);
    assert_eq!(consume(&[2, 0, 1, 2]), Some(&[][..]));
    assert_eq!(consume(&[4, 0, 1, 2]), Some(&[1u8, 2][..]));
    assert_eq!(consume(&[5, 0, 1, 2]), None);
    assert_eq!(consume(&[2]), None);
}

#[test]
fn old_shard_sets_are_discarded() {
    let _g = snmp_write();
    let (ds, ps) = (4isize, 2isize);
    let n = 6u32;
    let s = stream(ds, ps, 8);
    let mut dec = decoder(ds, ps);
    // one data packet of groups 0..=3
    for g in 0..4 {
        assert!(dec.decode(s.by_seqid(g * n)).is_empty());
    }
    assert_eq!(dec.shard_set.len(), 4);
    assert_eq!(DEFAULT_SNMP.copy().fec_shard_set, 4);
    // group 4: group 0 is 4 groups older (4*6 > 3*6) and discarded, group 1 (3*6) is kept
    assert!(dec.decode(s.by_seqid(4 * n)).is_empty());
    assert_eq!(dec.newest_shard_id, 4);
    let keys: BTreeSet<u32> = dec.shard_set.keys().copied().collect();
    assert_eq!(keys, [1, 2, 3, 4].into_iter().collect());
    let snap = DEFAULT_SNMP.copy();
    assert_eq!(snap.fec_shard_set, 4);
    assert_eq!(snap.fec_shard_min, 4);

    // A late packet of group 0 creates a set (FECShardSet++), which is discarded right away.
    let before = DEFAULT_SNMP.copy();
    assert!(dec.decode(s.by_seqid(1)).is_empty());
    assert!(!dec.shard_set.contains_key(&0));
    assert_eq!(DEFAULT_SNMP.copy().fec_shard_set, 4);
    assert_eq!(before.fec_shard_set, 4);

    // Jumping to group 7 drops everything but groups 4..=7.
    assert!(dec.decode(s.by_seqid(7 * n + 1)).is_empty());
    let keys: BTreeSet<u32> = dec.shard_set.keys().copied().collect();
    assert_eq!(keys, [4, 7].into_iter().collect());
    assert_eq!(dec.newest_shard_id, 7);
}

#[test]
fn newest_shard_id_uses_the_wrapping_compare() {
    let _g = snmp_read();
    let mut dec = decoder(10, 3);
    let paws = dec.paws; // 4294967287, 9 below 2^32
    let last_group = paws / 13 - 1;
    let pkt = |seqid: u32| {
        let mut p = vec![0u8; 16];
        p[..4].copy_from_slice(&seqid.to_le_bytes());
        p[4..6].copy_from_slice(&TYPE_DATA.to_le_bytes());
        p
    };
    // From 0, the last group before paws is "older" (negative wrapping difference).
    assert!(dec.decode(&pkt(last_group * 13)).is_empty());
    assert_eq!(dec.newest_shard_id, 0);
    // Group 0 stays newest; the last group is kept (0 - (paws - 13) wraps to 22 <= 39).
    assert!(dec.decode(&pkt(1)).is_empty());
    assert_eq!(dec.newest_shard_id, 0);
    let keys: BTreeSet<u32> = dec.shard_set.keys().copied().collect();
    assert_eq!(keys, [0, last_group].into_iter().collect());
    // Group 1 is newer.
    assert!(dec.decode(&pkt(13)).is_empty());
    assert_eq!(dec.newest_shard_id, 1);

    // Coming from the middle of the seqid space, a seqid 2^31 groups ahead is "older".
    let mut dec = decoder(10, 3);
    assert!(dec.decode(&pkt(13 * 1000)).is_empty());
    assert_eq!(dec.newest_shard_id, 1000);
    assert!(
        dec.decode(&pkt(13 * 1000 + 0x8000_0000 / 13 * 13 + 13))
            .is_empty()
    );
    assert_eq!(dec.newest_shard_id, 1000);
}

#[test]
fn retune_on_parameter_change() {
    let _g = snmp_write();
    // The decoder expects (10,3), the peer sends (5,2).
    let s = stream(5, 2, 12);
    let mut dec = decoder(10, 3);
    let mut i = 0;
    // seqid 5 (parity in (5,2)) sits at a data position of (10,3): out of sync from there.
    while i < s.packets.len() && dec.data_shards() == 10 {
        let r = dec.decode(&s.packets[i]);
        assert!(r.is_empty());
        if s.seqid(i) < 5 {
            assert!(!dec.should_tune);
        } else if dec.data_shards() == 10 {
            assert!(dec.should_tune, "seqid {}", s.seqid(i));
        }
        i += 1;
    }
    // Periods are found once the samples show a full data pulse (7..=11) and the parity
    // pulse after it: the packet with seqid 12 applies (5,2).
    assert_eq!(s.seqid(i - 1), 12);
    assert_eq!((dec.data_shards(), dec.parity_shards()), (5, 2));
    assert!(!dec.should_tune);
    assert!(dec.shard_set.is_empty());
    assert_eq!(dec.paws, 0xffff_ffff / 7 * 7);
    assert_eq!(dec.decode_cache.len(), 7);
    assert_eq!(dec.flag_cache.len(), 7);
    // newest_shard_id is not reset (Go), it stays in (10,3) units.
    assert_eq!(dec.newest_shard_id, 0);

    // From the next packet on, groups decode with the new parameters: lose one data shard in
    // each of the remaining complete groups.
    let before = DEFAULT_SNMP.copy();
    let first_full = s.seqid(i).div_ceil(7) * 7;
    let lost: BTreeSet<u32> = (first_full..s.packets.len() as u32)
        .step_by(7)
        .map(|g| g + 2)
        .collect();
    let mut got = BTreeSet::new();
    for p in &s.packets[i..] {
        let seqid = fec_seqid(p);
        if lost.contains(&seqid) {
            continue;
        }
        for r in dec.decode(p) {
            let g = seqid / 7 * 7;
            assert_eq!(r, s.expected_shard(g + 2, 5, 2));
            assert!(got.insert(g + 2));
        }
    }
    assert!(!lost.is_empty());
    assert_eq!(got, lost);
    assert_eq!(
        delta(&before, &DEFAULT_SNMP.copy()).recovered,
        lost.len() as u64
    );
}

#[test]
fn retune_with_same_parameters_only_resets_the_flag() {
    let _g = snmp_read();
    let s = stream(5, 2, 6);
    let mut dec = decoder(5, 2);
    for p in &s.packets[..21] {
        assert!(dec.decode(p).is_empty());
    }
    // A mismatched packet (parity type at data position 21) sets should_tune; the periods
    // found are the current ones, so only the flag is reset, and that packet is dropped.
    let mut bogus = s.packets[21].clone();
    bogus[4..6].copy_from_slice(&TYPE_PARITY.to_le_bytes());
    let sets = dec.shard_set.len();
    assert!(dec.decode(&bogus).is_empty());
    assert!(!dec.should_tune);
    assert_eq!((dec.data_shards(), dec.parity_shards()), (5, 2));
    assert_eq!(dec.shard_set.len(), sets, "shard sets kept");
    assert!(!dec.shard_set.contains_key(&3), "bogus packet not stored");
    // The next packets are decoded normally again (group 3 minus data 21 and 22: recovered
    // from its parity).
    let mut got = Vec::new();
    for p in &s.packets[23..28] {
        got.extend(dec.decode(p));
    }
    assert_eq!(got.len(), 2);
    let mut kcp: Vec<&[u8]> = got.iter().map(|r| consume(r).expect("size")).collect();
    kcp.sort();
    let mut want = vec![&s.kcp[&21][..], &s.kcp[&22][..]];
    want.sort();
    assert_eq!(kcp, want);
}

#[test]
fn out_of_sync_without_period_drops_packets() {
    let _g = snmp_read();
    let s = stream(10, 3, 2);
    let mut dec = decoder(10, 3);
    // The first packet is a parity packet at a data position; with < 3 samples (and no pulse
    // edges afterwards) no period is found, so every packet is dropped while should_tune.
    let mut p = s.packets[10].clone();
    p[..4].copy_from_slice(&0u32.to_le_bytes());
    assert!(dec.decode(&p).is_empty());
    assert!(dec.should_tune);
    for p in &s.packets[1..10] {
        assert!(dec.decode(p).is_empty());
        assert!(dec.should_tune);
    }
    assert!(dec.shard_set.is_empty());
    assert_eq!((dec.data_shards(), dec.parity_shards()), (10, 3));
}

#[test]
fn oversized_packets_do_not_panic() {
    let _g = snmp_read();
    let mut dec = decoder(1, 1);
    let mut p = vec![0x5a; 4000];
    p[..4].copy_from_slice(&0u32.to_le_bytes());
    p[4..6].copy_from_slice(&TYPE_DATA.to_le_bytes());
    assert!(dec.decode(&p).is_empty());
    let mut q = vec![0x33; 3000];
    q[..4].copy_from_slice(&1u32.to_le_bytes());
    q[4..6].copy_from_slice(&TYPE_PARITY.to_le_bytes());
    let r = dec.decode(&q);
    // (1,1) parity is the data shard itself: recovered = parity bytes zero-padded
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].len(), 3000 - FEC_HEADER_SIZE);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Random losses, duplicates and reordering within groups: every recovered shard is one of
    /// the group's data shards (exact bytes), and every lost data shard of a group that
    /// lost at most `ps` shards in total is recovered. (A shard may be recovered more than
    /// once: popping a group clears its duplicate marks, as in Go.)
    #[test]
    fn prop_decode_stream(
        ds in 1isize..12,
        ps in 1isize..5,
        seed in any::<u64>(),
        loss_pct in 0u64..40,
        dup_pct in 0u64..20,
    ) {
        let _g = snmp_read();
        let (dsu, psu) = (ds.unsigned_abs() as u32, ps.unsigned_abs() as u32);
        let n = dsu + psu;
        let s = stream(ds, ps, 6);
        let mut rng = seed | 1;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng % 100
        };
        let mut delivered: Vec<usize> = Vec::new();
        let mut lost = BTreeSet::new();
        for i in 0..s.packets.len() {
            if next() < loss_pct {
                lost.insert(s.seqid(i));
                continue;
            }
            delivered.push(i);
            if next() < dup_pct {
                delivered.push(i);
            }
        }
        // swap neighbours inside each group only (keeps every group within the window)
        for k in 1..delivered.len() {
            if next() < 30
                && s.seqid(delivered[k]) / n == s.seqid(delivered[k - 1]) / n
            {
                delivered.swap(k, k - 1);
            }
        }
        let mut dec = decoder(ds, ps);
        let mut got: HashMap<u32, usize> = HashMap::new();
        for &i in &delivered {
            let group = s.seqid(i) / n * n;
            for r in dec.decode(&s.packets[i]) {
                // A data shard that has not arrived yet (reordered) is recovered too.
                let seqid = (group..group + dsu)
                    .find(|&l| s.expected_shard(l, dsu, psu) == r)
                    .expect("recovered shard is a data shard of the group");
                prop_assert_eq!(consume(&r), Some(&s.kcp[&seqid][..]));
                *got.entry(seqid).or_default() += 1;
            }
        }
        for g in 0..6u32 {
            let lost_in_group = (g * n..(g + 1) * n).filter(|l| lost.contains(l)).count();
            let lost_data: Vec<u32> =
                (g * n..g * n + dsu).filter(|l| lost.contains(l)).collect();
            if lost_in_group as u32 <= psu {
                for l in &lost_data {
                    prop_assert!(got.contains_key(l), "group {} seqid {} not recovered", g, l);
                }
            }
        }
    }

    /// Arbitrary packets never panic and keep the decoder consistent.
    #[test]
    fn prop_decode_arbitrary_input(
        ds in 1isize..20,
        ps in 1isize..8,
        pkts in proptest::collection::vec(
            (0u32..200, prop_oneof![Just(TYPE_DATA), Just(TYPE_PARITY), any::<u16>()],
             proptest::collection::vec(any::<u8>(), 0..64)),
            0..300,
        ),
    ) {
        let _g = snmp_read();
        let mut dec = decoder(ds, ps);
        for (seqid, flag, body) in pkts {
            let mut p = seqid.to_le_bytes().to_vec();
            p.extend_from_slice(&flag.to_le_bytes());
            p.extend_from_slice(&body);
            for r in dec.decode(&p) {
                let _ = consume(&r);
            }
            prop_assert_eq!(dec.decode_cache.len(), dec.data_shards() + dec.parity_shards());
            prop_assert_eq!(dec.flag_cache.len(), dec.decode_cache.len());
            prop_assert!(dec.shard_set.len() <= MAX_SHARD_SETS + 1);
        }
    }
}
