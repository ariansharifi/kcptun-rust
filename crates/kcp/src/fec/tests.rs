//! Unit tests of the FEC encoder: construction (incl. V07), data/parity/OOB sealing, the parity
//! skip rule and its first-group quirk, `paws` wrap, variable packet sizes and parity
//! correctness against the RS codec. The Go golden sequences are in `vector_tests.rs`, the
//! ported `fec_test.go` tests in `go_tests.rs`.

use super::*;
use proptest::prelude::*;

/// Go's `cryptHeaderSize` (nonce 16 + crc32 4), the usual `header_offset` of an encrypted session.
const CRYPT_HEADER_SIZE: usize = 20;

fn encoder(ds: isize, ps: isize, offset: usize) -> FecEncoder {
    FecEncoder::new(ds, ps, offset)
        .expect("valid shard counts")
        .expect("FEC enabled")
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn le16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

/// seqid and type of the FEC header of `pkt`.
fn header(enc: &FecEncoder, pkt: &[u8]) -> (u32, u16) {
    let h = &pkt[enc.header_offset()..];
    (le32(h), le16(&h[4..]))
}

/// A packet of `len` bytes whose bytes after the FEC header are `fill, fill+1, ...` and whose
/// header region is `0xEE` (to see what the encoder writes).
fn packet(enc: &FecEncoder, len: usize, fill: u8) -> Vec<u8> {
    let mut b = vec![0xEEu8; len];
    for (i, x) in b.iter_mut().enumerate().skip(enc.payload_offset() + 2) {
        *x = fill.wrapping_add(i as u8);
    }
    b
}

/// Encodes one packet and returns copies of the parity shards.
fn encode(enc: &mut FecEncoder, b: &mut [u8], now: i64) -> Vec<Vec<u8>> {
    enc.encode(b, MAX_FEC_ENCODE_LATENCY, now)
        .expect("valid packet")
        .iter()
        .map(<[u8]>::to_vec)
        .collect()
}

/// The RS shards (from the size field on) of a group's data packets, zero-padded to the
/// longest.
fn padded_data_shards(enc: &FecEncoder, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let po = enc.payload_offset();
    let max = data.iter().map(Vec::len).max().expect("non-empty group");
    data.iter()
        .map(|p| {
            let mut s = p[po..].to_vec();
            s.resize(max - po, 0);
            s
        })
        .collect()
}

/// Checks the parity of a group: header, length, bytes equal to a direct RS encode of the
/// zero-padded data shards, and that every single data loss (and `ps` data losses) is
/// recovered by `reconstruct_data`.
fn check_group(enc: &FecEncoder, data: &[Vec<u8>], parity: &[Vec<u8>], first_seqid: u32) {
    let ds = enc.data_shards();
    let ps = enc.parity_shards();
    let po = enc.payload_offset();
    assert_eq!(data.len(), ds);
    assert_eq!(parity.len(), ps);
    let max = data.iter().map(Vec::len).max().expect("non-empty group");
    let shards = padded_data_shards(enc, data);

    let mut expect: Vec<Vec<u8>> = shards.clone();
    expect.extend((0..ps).map(|_| vec![0u8; max - po]));
    Codec::new(ds, ps)
        .expect("codec")
        .encode(&mut expect)
        .expect("encode");

    for (k, p) in parity.iter().enumerate() {
        assert_eq!(p.len(), max, "parity {k} length");
        assert_eq!(
            header(enc, p),
            (
                first_seqid.wrapping_add((ds + k) as u32) % enc.paws,
                TYPE_PARITY
            ),
            "parity {k} header"
        );
        assert_eq!(&p[po..], &expect[ds + k][..], "parity {k} bytes");
    }

    // Recovery: lose data shard i (and, with ps >= 2, further ones) and rebuild.
    let mut codec = Codec::new(ds, ps).expect("codec");
    for lost in 0..ds {
        let mut rx: Vec<Vec<u8>> = shards.clone();
        rx.extend(parity.iter().map(|p| p[po..].to_vec()));
        for j in 0..ps.min(ds) {
            rx[(lost + j) % ds].clear();
        }
        codec.reconstruct_data(&mut rx).expect("reconstruct");
        for (i, s) in rx.iter().take(ds).enumerate() {
            assert_eq!(s, &shards[i], "recovered data shard {i}");
            // The size field of a recovered shard gives back the original payload.
            let sz = usize::from(le16(s));
            assert_eq!(sz, data[i].len() - po);
            assert_eq!(&s[2..sz], &data[i][po + 2..]);
        }
    }
}

#[test]
fn new_disabled_unless_both_shard_counts_positive() {
    for (ds, ps) in [(0, 0), (0, 3), (10, 0), (-1, 3), (10, -1), (isize::MIN, 1)] {
        assert!(
            FecEncoder::new(ds, ps, 0).expect("not an error").is_none(),
            "({ds},{ps})"
        );
    }
}

#[test]
fn new_rejects_more_than_256_shards_v07() {
    for (ds, ps) in [
        (200, 57),
        (1, 256),
        (256, 1),
        (isize::MAX, 1),
        (1, isize::MAX),
    ] {
        let err = FecEncoder::new(ds, ps, 0).expect_err("V07: > 256 shards");
        assert_eq!(err, Error::Codec(rs::Error::MaxShardNum), "({ds},{ps})");
        assert_eq!(
            err.to_string(),
            "cannot create Encoder with more than 256 data+parity shards"
        );
    }
    for (ds, ps) in [(200, 56), (1, 255), (255, 1), (128, 128)] {
        let enc = encoder(ds, ps, 0);
        assert_eq!(enc.shard_size, 256);
        assert_eq!(enc.paws, 0xffff_ff00);
    }
}

#[test]
fn new_sets_paws_offsets_and_cache() {
    let enc = encoder(10, 3, CRYPT_HEADER_SIZE);
    assert_eq!(enc.data_shards(), 10);
    assert_eq!(enc.parity_shards(), 3);
    assert_eq!(enc.shard_size, 13);
    // 0xffffffff / 13 * 13
    assert_eq!(enc.paws, 4_294_967_287);
    assert_eq!(enc.paws % 13, 0);
    assert_eq!(enc.header_offset(), 20);
    assert_eq!(enc.payload_offset(), 26);
    assert_eq!(enc.next, 0);
    assert_eq!(enc.shard_cache.len(), 13);
    assert!(enc.shard_cache.iter().all(|s| s.len() == MTU_LIMIT));

    for (ds, ps) in [(1, 1), (2, 1), (3, 2), (7, 7), (20, 5), (100, 100)] {
        let enc = encoder(ds, ps, 0);
        let n = (ds + ps) as u32;
        assert_eq!(enc.paws, u32::MAX / n * n);
        assert!(u32::MAX - enc.paws < n);
    }
}

#[test]
fn encode_seals_data_packets() {
    let mut enc = encoder(3, 2, CRYPT_HEADER_SIZE);
    for (i, len) in [100usize, 28, 1500].into_iter().enumerate() {
        let orig = packet(&enc, len, i as u8);
        let mut b = orig.clone();
        let ps = encode(&mut enc, &mut b, 10 * i as i64);
        assert_eq!(ps.is_empty(), i < 2);
        // Crypto header room untouched.
        assert_eq!(&b[..CRYPT_HEADER_SIZE], &orig[..CRYPT_HEADER_SIZE]);
        assert_eq!(header(&enc, &b), (i as u32, TYPE_DATA));
        assert_eq!(&b[20..26], &[i as u8, 0, 0, 0, 0xf1, 0x00][..]);
        // size = len(b[payloadOffset:]) = 2 + len(KCP bytes)
        assert_eq!(usize::from(le16(&b[26..])), len - 26);
        // KCP bytes untouched.
        assert_eq!(&b[28..], &orig[28..]);
    }
}

#[test]
fn encode_emits_correct_parity() {
    for (ds, ps, offset) in [(1, 1, 0), (2, 1, 0), (3, 2, 20), (10, 3, 20), (4, 4, 16)] {
        let mut enc = encoder(ds, ps, offset);
        let mut now = 1_000;
        let mut seqid = 0u32;
        for group in 0..4 {
            let mut data = Vec::new();
            let mut parity = Vec::new();
            for i in 0..ds {
                let len = enc.payload_offset() + 2 + (group * 131 + i as usize * 37) % 1400;
                let mut b = packet(&enc, len, (group * 7 + i as usize) as u8);
                parity = encode(&mut enc, &mut b, now);
                now += 10;
                assert_eq!(header(&enc, &b), (seqid + i as u32, TYPE_DATA));
                data.push(b);
                if i + 1 < ds {
                    assert!(parity.is_empty());
                }
            }
            if ds == 1 && group == 0 {
                // First group of a (1, ps) encoder: Go's tsLatestPacket starts at 0, so the
                // first packet is always "non-continuous" and its parity is skipped.
                assert!(parity.is_empty(), "({ds},{ps}) first group skipped");
            } else {
                check_group(&enc, &data, &parity, seqid);
            }
            seqid += (ds + ps) as u32;
            assert_eq!(enc.next, seqid);
        }
    }
}

#[test]
fn first_group_with_one_data_shard_is_skipped() {
    // Whatever the clock's origin: 0 (a fresh monotonic clock), a UnixMilli-like value, or
    // negative.
    for start in [
        0i64,
        1,
        499,
        1_758_000_000_000,
        -1_000_000,
        i64::MIN / 4,
        i64::MAX,
    ] {
        let mut enc = encoder(1, 2, 0);
        let mut b = packet(&enc, 100, 1);
        assert!(encode(&mut enc, &mut b, start).is_empty(), "start {start}");
        assert_eq!(header(&enc, &b), (0, TYPE_DATA));
        assert_eq!(enc.next, 3, "skip_parity consumed seqids 1 and 2");

        // The next packet within 500 ms gets its parity.
        let mut b = packet(&enc, 100, 2);
        let now = start.saturating_add(1);
        let ps = encode(&mut enc, &mut b, now);
        assert_eq!(header(&enc, &b), (3, TYPE_DATA));
        if now > start {
            check_group(&enc, &[b], &ps, 3);
        } else {
            // i64::MAX saturates: same timestamp, gap 0 < 500.
            assert_eq!(ps.len(), 2);
        }
        assert_eq!(enc.next, 6);
    }
}

#[test]
fn first_group_with_several_data_shards_is_not_skipped() {
    // Only the gap before the group's last packet matters, so with ds >= 2 the start value is
    // irrelevant when the packets are close together.
    let mut enc = encoder(3, 1, 0);
    let mut data = Vec::new();
    let mut ps = Vec::new();
    for (i, now) in [0i64, 100, 200].into_iter().enumerate() {
        let mut b = packet(&enc, 50 + i, i as u8);
        ps = encode(&mut enc, &mut b, now);
        data.push(b);
    }
    check_group(&enc, &data, &ps, 0);
}

#[test]
fn skip_rule_boundary_is_rto() {
    // Parity iff now - ts(previous call) < rto.
    for (gap, rto, want) in [
        (499, 500, true),
        (500, 500, false),
        (501, 500, false),
        (0, 500, true),
        (-5, 500, true), // clock went backwards (not with a monotonic clock): continuous
        (49, 50, true),
        (50, 50, false),
        (0, 0, false),
    ] {
        let mut enc = encoder(2, 1, 0);
        let mut b0 = packet(&enc, 60, 0);
        enc.encode(&mut b0, rto, 10_000).expect("encode");
        let mut b1 = packet(&enc, 70, 1);
        let ps: Vec<Vec<u8>> = enc
            .encode(&mut b1, rto, 10_000 + gap)
            .expect("encode")
            .iter()
            .map(<[u8]>::to_vec)
            .collect();
        assert_eq!(!ps.is_empty(), want, "gap {gap} rto {rto}");
        assert_eq!(enc.next, 3, "seqids consumed either way");
        if want {
            check_group(&enc, &[b0, b1], &ps, 0);
        }
    }
}

#[test]
fn ts_latest_is_updated_on_every_call() {
    let mut enc = encoder(3, 2, 0);
    let run = |enc: &mut FecEncoder, times: [i64; 3]| -> (u32, usize) {
        let first = enc.next;
        let mut n = 0;
        for (i, t) in times.into_iter().enumerate() {
            let mut b = packet(enc, 40 + i, 0);
            n = encode(enc, &mut b, t).len();
        }
        (first, n)
    };
    // Every gap < 500 although the group spans 800 ms: parity.
    assert_eq!(run(&mut enc, [0, 400, 800]), (0, 2));
    // Last gap 600: skipped although the first gap is small.
    assert_eq!(run(&mut enc, [1_000, 1_100, 1_700]), (5, 0));
    // Gap 600 inside the group, but the last gap is 100: parity.
    assert_eq!(run(&mut enc, [2_000, 2_600, 2_700]), (10, 2));
    // A gap between groups (500 before the first packet) does not matter.
    assert_eq!(run(&mut enc, [3_200, 3_210, 3_220]), (15, 2));
    assert_eq!(enc.next, 20);
}

/// Encoder part of Go's TestFECRTOAndSkipParity (kcp-go/v5@v5.6.66 fec_test.go), with the sleeps
/// replaced by timestamps, continued for one more group; the full port is
/// `go_tests::test_fec_rto_and_skip_parity`.
#[test]
fn rto_and_skip_parity_seqids() {
    const RTO: u32 = 50;
    let mut enc = encoder(3, 2, 0);
    let seq = |enc: &mut FecEncoder, now: i64| -> (u32, Vec<u32>) {
        let mut b = vec![0u8; 100];
        let ps = enc.encode(&mut b, RTO, now).expect("encode");
        (le32(&b), ps.iter().map(le32).collect())
    };
    // Scenario 1: 3 packets quickly.
    assert_eq!(seq(&mut enc, 0), (0, vec![]));
    assert_eq!(seq(&mut enc, 1), (1, vec![]));
    assert_eq!(seq(&mut enc, 2), (2, vec![3, 4]));
    // Scenario 2: 2 packets quickly, then a gap > RTO before the 3rd.
    assert_eq!(seq(&mut enc, 3), (5, vec![]));
    assert_eq!(seq(&mut enc, 4), (6, vec![]));
    assert_eq!(seq(&mut enc, 4 + 100), (7, vec![]));
    // Scenario 3: the seqids of the skipped parity (8, 9) are not reused.
    assert_eq!(seq(&mut enc, 105), (10, vec![]));
    assert_eq!(seq(&mut enc, 106), (11, vec![]));
    assert_eq!(seq(&mut enc, 107), (12, vec![13, 14]));
}

#[test]
fn variable_packet_sizes_are_zero_padded() {
    let mut enc = encoder(4, 2, CRYPT_HEADER_SIZE);
    // Group 1: full-size packets fill the cache with non-zero bytes.
    let mut now = 0;
    let mut data = Vec::new();
    let mut ps = Vec::new();
    for i in 0..4 {
        let mut b = vec![0xAAu8; MTU_LIMIT];
        now += 1;
        ps = encode(&mut enc, &mut b, now);
        data.push(b);
        assert_eq!(ps.is_empty(), i < 3);
    }
    check_group(&enc, &data, &ps, 0);
    assert!(ps.iter().all(|p| p.len() == MTU_LIMIT));

    // Group 2: much shorter packets of different lengths; the stale 0xAA tails must be cleared
    // up to the new max size, and the parity is as long as the longest packet.
    let lens = [28usize, 300, 29, 170];
    let mut data = Vec::new();
    for (i, len) in lens.into_iter().enumerate() {
        let mut b = packet(&enc, len, 0x40 + i as u8);
        now += 1;
        ps = encode(&mut enc, &mut b, now);
        data.push(b);
    }
    check_group(&enc, &data, &ps, 6);
    assert!(ps.iter().all(|p| p.len() == 300));

    // Group 3: the longest packet first, the shortest possible one last.
    let lens = [700usize, 28, 699, 28];
    let mut data = Vec::new();
    for (i, len) in lens.into_iter().enumerate() {
        let mut b = packet(&enc, len, 0x80 + i as u8);
        now += 1;
        ps = encode(&mut enc, &mut b, now);
        data.push(b);
    }
    check_group(&enc, &data, &ps, 12);
    assert!(ps.iter().all(|p| p.len() == 700));

    // Group 4 (skipped) does not disturb the lengths of group 5.
    for len in [1500usize, 1500, 1500, 1500] {
        let mut b = packet(&enc, len, 1);
        now += 1_000;
        assert!(encode(&mut enc, &mut b, now).is_empty());
    }
    let mut data = Vec::new();
    for len in [40usize, 50, 45, 30] {
        let mut b = packet(&enc, len, 2);
        now += 1;
        ps = encode(&mut enc, &mut b, now);
        data.push(b);
    }
    check_group(&enc, &data, &ps, 24);
    assert!(ps.iter().all(|p| p.len() == 50));
}

#[test]
fn paws_wrap() {
    // Like Go's TestFECPAWS: start at the last group before paws; the next group starts at 0.
    let (ds, ps) = (10usize, 3usize);
    let mut enc = encoder(ds as isize, ps as isize, 0);
    let shard_size = (ds + ps) as u32;
    enc.next = enc.paws - shard_size;
    let start = enc.next;

    let mut seqids = Vec::new();
    let mut now = 0;
    for group in 0..2u32 {
        let mut data = Vec::new();
        let mut parity = Vec::new();
        let first = enc.next;
        for i in 0..ds {
            let mut b = vec![0u8; 1500];
            b[8..12].copy_from_slice(&(i as u32 + 100 * group).to_le_bytes());
            now += 1;
            parity = encode(&mut enc, &mut b, now);
            seqids.push(le32(&b));
            data.push(b);
        }
        seqids.extend(parity.iter().map(|p| le32(p)));
        check_group(&enc, &data, &parity, first);
    }
    let want: Vec<u32> = (0..shard_size)
        .map(|i| start + i)
        .chain(0..shard_size)
        .collect();
    assert_eq!(seqids, want);
    assert_eq!(seqids[12], enc.paws - 1);
    assert_eq!(enc.next, shard_size);
}

#[test]
fn paws_wrap_with_skipped_parity() {
    // skip_parity also wraps: the parity seqids of the last group are skipped, the next data
    // packet gets seqid 0.
    let mut enc = encoder(3, 2, 0);
    enc.next = enc.paws - 5;
    let paws = enc.paws;
    for (i, now) in [0i64, 1, 1_000].into_iter().enumerate() {
        let mut b = vec![0u8; 64];
        assert!(encode(&mut enc, &mut b, now).is_empty());
        assert_eq!(le32(&b), paws - 5 + i as u32);
    }
    assert_eq!(enc.next, 0);
    let mut b = vec![0u8; 64];
    encode(&mut enc, &mut b, 1_001);
    assert_eq!(le32(&b), 0);

    // With ds + ps = 256 the wrap is at 0xffffff00.
    let mut enc = encoder(255, 1, 0);
    enc.next = enc.paws - 256;
    let mut last = Vec::new();
    for i in 0..255 {
        let mut b = vec![0u8; 12];
        last = encode(&mut enc, &mut b, i);
    }
    assert_eq!(
        last.iter().map(|p| le32(p)).collect::<Vec<_>>(),
        vec![0xffff_feff]
    );
    assert_eq!(enc.next, 0);
}

#[test]
fn oob_sealing() {
    let mut enc = encoder(3, 2, 8);
    // A data packet first, so the group is half full.
    let mut d0 = packet(&enc, 100, 0);
    encode(&mut enc, &mut d0, 0);

    let orig = packet(&enc, 77, 9);
    let mut b = orig.clone();
    enc.encode_oob(&mut b).expect("oob");
    assert_eq!(&b[..8], &orig[..8], "crypto header room untouched");
    assert_eq!(&b[8..14], &[0xff, 0xff, 0xff, 0xff, 0xf3, 0x00][..]);
    assert_eq!(header(&enc, &b), (OOB_SEQID, TYPE_OOB));
    assert_eq!(usize::from(le16(&b[14..])), 77 - 14);
    assert_eq!(&b[16..], &orig[16..]);

    // OOB packets take no seqid and are not part of a group.
    assert_eq!(enc.next, 1);
    assert_eq!(enc.shard_count, 1);
    let mut d1 = packet(&enc, 90, 1);
    encode(&mut enc, &mut d1, 1);
    let mut d2 = packet(&enc, 80, 2);
    let ps = encode(&mut enc, &mut d2, 2);
    assert_eq!(header(&enc, &d2), (2, TYPE_DATA));
    check_group(&enc, &[d0, d1, d2], &ps, 0);

    // Minimal OOB packet: just the headers, size 2.
    let mut b = vec![0u8; 16];
    enc.encode_oob(&mut b).expect("oob");
    assert_eq!(le16(&b[14..]), 2);
    // Without a crypto header.
    let enc = encoder(1, 1, 0);
    let mut b = vec![0u8; 8];
    enc.encode_oob(&mut b).expect("oob");
    assert_eq!(b, [0xff, 0xff, 0xff, 0xff, 0xf3, 0, 2, 0]);
}

#[test]
fn packet_length_errors_leave_state_unchanged() {
    let mut enc = encoder(2, 1, CRYPT_HEADER_SIZE);
    let mut b0 = packet(&enc, 100, 0);
    encode(&mut enc, &mut b0, 0);
    let (next, count, max, ts) = (
        enc.next,
        enc.shard_count,
        enc.max_size,
        enc.ts_latest_packet,
    );

    for len in [0usize, 20, 26, 27] {
        let mut b = vec![0x11u8; len];
        assert_eq!(
            enc.encode(&mut b, MAX_FEC_ENCODE_LATENCY, 1)
                .map(|p| p.len()),
            Err(Error::PacketTooShort { len, min: 28 })
        );
        assert!(b.iter().all(|&x| x == 0x11));
        assert_eq!(
            enc.encode_oob(&mut b),
            Err(Error::PacketTooShort { len, min: 28 })
        );
        assert!(b.iter().all(|&x| x == 0x11));
    }
    let mut b = vec![0x11u8; MTU_LIMIT + 1];
    let err = enc
        .encode(&mut b, MAX_FEC_ENCODE_LATENCY, 1)
        .map(|p| p.len())
        .expect_err("too large");
    assert_eq!(
        err,
        Error::PacketTooLarge {
            len: 1501,
            max: 1500
        }
    );
    assert_eq!(
        err.to_string(),
        "FEC packet too large: 1501 bytes, at most 1500"
    );
    assert!(b.iter().all(|&x| x == 0x11));
    assert_eq!(
        (
            enc.next,
            enc.shard_count,
            enc.max_size,
            enc.ts_latest_packet
        ),
        (next, count, max, ts)
    );
    // OOB packets have no upper bound (they are not cached).
    enc.encode_oob(&mut b).expect("large oob");

    // The limits themselves are accepted.
    let mut b1 = packet(&enc, 28, 1);
    let ps = encode(&mut enc, &mut b1, 1);
    check_group(&enc, &[b0, b1], &ps, 0);
    let mut b2 = packet(&enc, MTU_LIMIT, 2);
    encode(&mut enc, &mut b2, 2);
    let mut b3 = packet(&enc, 28, 3);
    let ps = encode(&mut enc, &mut b3, 3);
    check_group(&enc, &[b2, b3], &ps, 3);

    // A header offset leaving no room for a packet: every packet is rejected.
    let mut enc = encoder(1, 1, MTU_LIMIT);
    let mut b = vec![0u8; MTU_LIMIT];
    assert!(matches!(
        enc.encode(&mut b, MAX_FEC_ENCODE_LATENCY, 0)
            .map(|p| p.len()),
        Err(Error::PacketTooShort { .. })
    ));
}

#[test]
fn parity_shards_api() {
    let mut enc = encoder(2, 3, 4);
    let mut b0 = packet(&enc, 40, 0);
    {
        let none = enc.encode(&mut b0, 500, 0).expect("encode");
        assert!(none.is_empty());
        assert_eq!(none.len(), 0);
        assert_eq!(none.shard_len(), 0);
        assert!(none.get(0).is_none());
        assert_eq!(none.iter().len(), 0);
    }
    let mut b1 = packet(&enc, 55, 1);
    let ps = enc.encode(&mut b1, 500, 1).expect("encode");
    assert!(!ps.is_empty());
    assert_eq!(ps.len(), 3);
    assert_eq!(ps.shard_len(), 55);
    assert!(ps.get(3).is_none());
    let via_get: Vec<&[u8]> = (0..3).map(|k| ps.get(k).expect("shard")).collect();
    let via_iter: Vec<&[u8]> = ps.iter().collect();
    let via_into: Vec<&[u8]> = ps.into_iter().collect();
    assert_eq!(via_get, via_iter);
    assert_eq!(via_get, via_into);
    let mut it = ps.iter();
    assert_eq!(it.len(), 3);
    it.next();
    assert_eq!(it.size_hint(), (2, Some(2)));
    for (k, p) in ps.iter().enumerate() {
        assert_eq!(p.len(), 55);
        assert_eq!(le32(&p[4..]), 2 + k as u32);
        assert_eq!(le16(&p[8..]), TYPE_PARITY);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Random shard counts, header offsets, packet lengths and gaps: seqids follow the
    /// data/parity pattern, parity is emitted exactly when the last gap is < 500 ms (never for
    /// the first group with ds == 1), and every emitted group is correct and recoverable.
    #[test]
    fn prop_encoder_groups(
        ds in 1usize..=12,
        ps in 1usize..=6,
        offset in prop::sample::select(vec![0usize, 4, 16, 20]),
        lens in prop::collection::vec(0usize..=1472, 1..=60),
        gaps in prop::collection::vec(prop_oneof![0i64..=499, 500i64..=2000], 60),
    ) {
        let mut enc = encoder(ds as isize, ps as isize, offset);
        let min = enc.payload_offset() + 2;
        let mut now = 123_456i64;
        let mut seqid = 0u32;
        let mut data = Vec::new();
        for (n, &l) in lens.iter().enumerate() {
            let len = (min + l).min(MTU_LIMIT);
            let mut b = packet(&enc, len, n as u8);
            let gap = gaps[n];
            now += gap;
            let parity = encode(&mut enc, &mut b, now);
            prop_assert_eq!(header(&enc, &b), (seqid, TYPE_DATA));
            data.push(b);
            seqid += 1;
            if data.len() == ds {
                let first = seqid - ds as u32;
                let want = gap < 500 && n > 0;
                prop_assert_eq!(!parity.is_empty(), want);
                if want {
                    check_group(&enc, &data, &parity, first);
                }
                data.clear();
                seqid += ps as u32;
            } else {
                prop_assert!(parity.is_empty());
            }
            prop_assert_eq!(enc.next, seqid);
        }
    }
}

/// SHA-1 over every data packet and parity shard of a scripted 60-packet stream (lengths
/// `off + 8 + n*397 % 1450`, bytes `n*31 + i*7`, 700 ms gap before every 17th packet, else
/// `n % 5 * 30` ms), as produced by a verbatim copy of kcp-go v5.6.66 `fecEncoder` (with the
/// `time.Now().UnixMilli()` call replaced by the same timestamps, starting at 1758000000000 with
/// `tsLatestPacket = 0`) and the vendored klauspost/reedsolomon v1.13.0. The digests are
/// recomputed from `tools/govectors/internal/kcpcopy/fec.go` by the Go test
/// `TestFecStreamDigestsOfRustTest` (tools/govectors/fec_test.go); the golden sequences in
/// `vector_tests.rs` check the same code byte for byte. Parity header bytes before
/// `header_offset` are the zeros of a fresh cache in both.
#[test]
fn stream_digest_matches_go_copy() {
    use sha1::{Digest, Sha1};
    for (ds, ps, off, want) in [
        (1, 1, 0usize, "cc7ea35974b31cb24d6517567e62252337ff9fa8"),
        (3, 2, 20, "db8b8b95641e447e0fb5cad9495eae40c1d39d54"),
        (10, 3, 16, "06cf35815b9900e647b5f9b4b9975d7dfecbd12b"),
        (4, 4, 0, "dbcb48fdb82f03727b9870a134d16b1d49879242"),
    ] {
        let mut enc = encoder(ds, ps, off);
        let mut h = Sha1::new();
        let mut now = 1_758_000_000_000i64;
        for n in 0..60usize {
            let l = (off + 8 + (n * 397) % 1450).min(1500);
            let mut b: Vec<u8> = (0..l).map(|i| (n * 31 + i * 7) as u8).collect();
            if n % 17 == 16 {
                now += 700;
            } else {
                now += (n % 5 * 30) as i64;
            }
            let parity = enc.encode(&mut b, 500, now).expect("encode");
            h.update(&b);
            for p in parity {
                h.update(p);
            }
        }
        assert_eq!(hex::encode(h.finalize()), want, "({ds},{ps},{off})");
    }
}
