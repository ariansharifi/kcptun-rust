//! Ports of kcp-go's `fec_test.go` (reference/latest, kcp-go v5.6.72; `fec.go` is unchanged
//! since the pinned v5.6.66 apart from comments). Adaptations to the port:
//!
//! - Go sleeps and reads the wall clock inside `encode`; here the encoder gets a virtual
//!   millisecond clock advanced by the same (seeded) amounts, so the tests are deterministic and
//!   fast. Where Go only logs whether a group got parity, the ports also assert it.
//! - Go's `math/rand` (global or `NewSource(42)`) is replaced by the testkit PCG with fixed
//!   seeds; the tests hold for any random choice, like Go's.
//! - `decode` takes the packet from the FEC header on and returns owned buffers, so there is no
//!   `defaultBufferPool.Put`.

use std::collections::HashSet;
use std::sync::RwLockReadGuard;

use super::*;
use crate::kcp::SNMP_TEST_LOCK;
use kcptun_testkit::rng::Pcg;

/// These tests change the FEC SNMP counters but assert none of them.
fn snmp_read() -> RwLockReadGuard<'static, ()> {
    SNMP_TEST_LOCK.read().unwrap_or_else(|e| e.into_inner())
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn new_fec_encoder(ds: isize, ps: isize, offset: usize) -> FecEncoder {
    FecEncoder::new(ds, ps, offset)
        .expect("valid shard counts")
        .expect("FEC enabled")
}

fn new_fec_decoder(ds: isize, ps: isize) -> FecDecoder {
    FecDecoder::new(ds, ps).expect("valid shard counts")
}

/// Encodes one packet and copies the parity shards out (they alias the encoder's cache).
fn encode(enc: &mut FecEncoder, b: &mut [u8], rto: u32, now: i64) -> Vec<Vec<u8>> {
    enc.encode(b, rto, now)
        .expect("encode")
        .iter()
        .map(<[u8]>::to_vec)
        .collect()
}

// Go: kcp-go@v5.6.72 fec_test.go:TestFECEncodeConsecutive
#[test]
fn test_fec_encode_consecutive() {
    const DATA_SIZE: usize = 10;
    const PARITY_SIZE: usize = 3;
    const PAY_LOAD: usize = 1500;
    const RTO: u32 = 200;

    let mut encoder = new_fec_encoder(DATA_SIZE as isize, PARITY_SIZE as isize, 0);
    let mut rng = Pcg::new(0xfec0, 1);
    let mut now = 1_758_000_000_000i64;
    let mut group = 0;
    let mut sent = 0;
    let (mut with_parity, mut without_parity) = (0, 0);
    for i in 0..100 {
        if i % DATA_SIZE == 0 {
            group += 1;
        }

        let mut data = vec![0u8; PAY_LOAD];
        // Go: <-time.After(rand.Int()%300 ms)
        let duration = rng.below(300) as i64;
        now += duration;

        let ps = encode(&mut encoder, &mut data, RTO, now);
        sent += 1;

        if !ps.is_empty() {
            for (idx, p) in ps.iter().enumerate() {
                let seqid = le32(p);
                let expected = ((group - 1) * (DATA_SIZE + PARITY_SIZE) + DATA_SIZE + idx) as u32;
                assert_eq!(seqid, expected, "expected parity shard");
            }
            // (not in Go) parity only when the last gap was below rto
            assert!(
                duration < i64::from(RTO),
                "packet {sent}: parity after {duration} ms"
            );
            with_parity += 1;
            continue;
        }

        if sent % DATA_SIZE == 0 {
            // (not in Go) the group's parity was skipped because of the gap
            assert!(
                duration >= i64::from(RTO),
                "packet {sent}: no parity after {duration} ms"
            );
            without_parity += 1;
        }
    }
    assert_eq!(with_parity + without_parity, 10);
    assert!(with_parity > 0 && without_parity > 0);
}

// Go: kcp-go@v5.6.72 fec_test.go:TestFECDecodeLoss
#[test]
fn test_fec_decode_loss() {
    // Loses 3 random packets of every group of 10 data shards and 3 parity shards, so every
    // group of 13 packets can be recovered.
    const DATA_SHARDS: usize = 10;
    const PARITY_SHARDS: usize = 3;
    const GROUP_SIZE: usize = DATA_SHARDS + PARITY_SHARDS;
    const PAY_LOAD: usize = 1400;
    let _snmp = snmp_read();
    let mut decoder = new_fec_decoder(DATA_SHARDS as isize, PARITY_SHARDS as isize);
    let mut rng = Pcg::new(0xfec0, 2);
    let mut total_recovered = 0;
    let mut total_parity_lost = 0;

    for group in 0..100 {
        let mut losses = HashSet::new();
        let mut lost = 0;
        let mut parity_lost = 0;
        while lost < PARITY_SHARDS {
            let pos = rng.below(GROUP_SIZE as u64) as usize;
            if losses.insert(pos) {
                if pos >= DATA_SHARDS {
                    total_parity_lost += 1;
                    parity_lost += 1;
                }
                lost += 1;
            }
        }
        assert_eq!(losses.len(), PARITY_SHARDS);

        let mut recovered = 0;
        for i in 0..GROUP_SIZE {
            if losses.contains(&i) {
                continue;
            }
            let mut pkt = vec![0u8; PAY_LOAD];
            pkt[0..4].copy_from_slice(&((GROUP_SIZE * group + i) as u32).to_le_bytes());
            let flag = if i % GROUP_SIZE >= DATA_SHARDS {
                TYPE_PARITY
            } else {
                TYPE_DATA
            };
            pkt[4..6].copy_from_slice(&flag.to_le_bytes());

            let rec = decoder.decode(&pkt);
            total_recovered += rec.len();
            recovered += rec.len();
        }

        // the recovered packets should equal to the lost data packets
        assert_eq!(recovered, lost - parity_lost, "group {group}");
    }
    assert_eq!(total_recovered, 100 * PARITY_SHARDS - total_parity_lost);
}

// Go: kcp-go@v5.6.72 fec_test.go:TestFECDecodeVariablePacketSizes
#[test]
fn test_fec_decode_variable_packet_sizes() {
    const DATA_SHARDS: usize = 8;
    const PARITY_SHARDS: usize = 3;
    const GROUPS: usize = 32;
    const RTO: u32 = i32::MAX as u32; // Go: math.MaxInt32
    const MIN_PAYLOAD: usize = 8;
    const MAX_PAYLOAD: usize = 900;

    let _snmp = snmp_read();
    let mut encoder = new_fec_encoder(DATA_SHARDS as isize, PARITY_SHARDS as isize, 0);
    let mut decoder = new_fec_decoder(DATA_SHARDS as isize, PARITY_SHARDS as isize);

    let mut rnd = Pcg::new(42, 0);
    let mut total_lost = 0;
    let mut total_recovered = 0;
    let mut now = 1_758_000_000_000i64;

    let feed = |decoder: &mut FecDecoder, raw: &[u8], total_recovered: &mut usize| {
        let packet = raw.to_vec();
        for r in decoder.decode(&packet) {
            assert!(r.len() >= 2, "recovered shard too small: {}", r.len());
            let sz = usize::from(u16::from_le_bytes([r[0], r[1]]));
            assert!(
                sz <= r.len(),
                "invalid size {sz} for buffer len {}",
                r.len()
            );
            let payload = &r[2..sz];
            assert!(
                payload.len() >= MIN_PAYLOAD,
                "payload shorter than expected: {}",
                payload.len()
            );
            assert_eq!(sz, payload.len() + 2, "size field mismatch");

            let group_id = le32(payload) as usize;
            let shard_idx = le32(&payload[4..]) as usize;
            for (i, &b) in payload.iter().enumerate().skip(8) {
                let expected = ((group_id + shard_idx + i) & 0xff) as u8;
                assert_eq!(
                    b,
                    expected,
                    "content mismatch: group {group_id} shard {shard_idx} offset {}",
                    i - 8
                );
            }
            *total_recovered += 1;
        }
    };

    for group in 0..GROUPS {
        let losses: HashSet<usize> = [group % DATA_SHARDS, (group + 3) % DATA_SHARDS].into();

        for shard in 0..DATA_SHARDS {
            let payload_len =
                MIN_PAYLOAD + rnd.below((MAX_PAYLOAD - MIN_PAYLOAD + 1) as u64) as usize;
            let mut buf = vec![0u8; FEC_HEADER_SIZE_PLUS2 + payload_len];
            let payload = &mut buf[FEC_HEADER_SIZE_PLUS2..];
            payload[0..4].copy_from_slice(&(group as u32).to_le_bytes());
            payload[4..8].copy_from_slice(&(shard as u32).to_le_bytes());
            for (i, b) in payload.iter_mut().enumerate().skip(8) {
                *b = ((group + shard + i) & 0xff) as u8;
            }

            now += 1;
            let ps = encode(&mut encoder, &mut buf, RTO, now);
            if losses.contains(&shard) {
                total_lost += 1;
            } else {
                feed(&mut decoder, &buf, &mut total_recovered);
            }

            for p in &ps {
                feed(&mut decoder, p, &mut total_recovered);
            }
        }
    }

    assert_eq!(total_recovered, total_lost, "recoveries");
}

// Go: kcp-go@v5.6.72 fec_test.go:TestFECPAWS
#[test]
fn test_fec_paws() {
    const DATA_SHARDS: usize = 10;
    const PARITY_SHARDS: usize = 3;
    const SHARD_SIZE: usize = DATA_SHARDS + PARITY_SHARDS;
    const PAY_LOAD: usize = 1500;
    const RTO: u32 = 200;

    let _snmp = snmp_read();
    let mut encoder = new_fec_encoder(DATA_SHARDS as isize, PARITY_SHARDS as isize, 0);
    let mut decoder = new_fec_decoder(DATA_SHARDS as isize, PARITY_SHARDS as isize);

    // Start at the last group before the PAWS boundary (paws is a multiple of SHARD_SIZE), to
    // test the transition from the last group to the first.
    encoder.next = encoder.paws - SHARD_SIZE as u32;

    let mut packets: Vec<Vec<u8>> = Vec::new();
    let mut now = 1_758_000_000_000i64;

    // 1. The last group before PAWS: seqids [paws-SHARD_SIZE, paws-1]. The FEC header is at
    // 0..6, the size at 6..8, the payload from 8.
    for i in 0..DATA_SHARDS {
        let mut data = vec![0u8; PAY_LOAD];
        data[8..12].copy_from_slice(&(i as u32).to_le_bytes());
        now += 1;
        let ps = encode(&mut encoder, &mut data, RTO, now);
        packets.push(data);
        packets.extend(ps);
    }
    for (i, pkt) in packets.iter().enumerate() {
        let expected = encoder.paws - SHARD_SIZE as u32 + i as u32;
        assert_eq!(fec_seqid(pkt), expected, "Group 1");
    }

    // 2. The first group after PAWS: seqids [0, SHARD_SIZE-1].
    let start_idx = packets.len();
    for i in 0..DATA_SHARDS {
        let mut data = vec![0u8; PAY_LOAD];
        data[8..12].copy_from_slice(&(i as u32 + 100).to_le_bytes()); // different data
        now += 1;
        let ps = encode(&mut encoder, &mut data, RTO, now);
        packets.push(data);
        packets.extend(ps);
    }
    for (i, pkt) in packets[start_idx..].iter().enumerate() {
        assert_eq!(fec_seqid(pkt), i as u32, "Group 2");
    }

    // 3. Decode with the last data packet of group 1 (index 9, seqid paws-4) and the first data
    // packet of group 2 (index 13, seqid 0) lost.
    let dropped: HashSet<usize> = [9, 13].into();
    let mut recovered_count = 0;
    let mut values = Vec::new();
    for (i, pkt) in packets.iter().enumerate() {
        if dropped.contains(&i) {
            continue;
        }
        let recovered = decoder.decode(pkt);
        recovered_count += recovered.len();
        for r in recovered {
            // r[0:2] is the size, r[2:] the payload
            let val = le32(&r[2..]);
            assert!(val == 9 || val == 100, "Recovered unexpected data: {val}");
            values.push(val);
        }
    }

    assert_eq!(recovered_count, 2, "Expected 2 recovered packets");
    assert_eq!(values, [9, 100]);
}

// Go: kcp-go@v5.6.72 fec_test.go:TestFECRTOAndSkipParity
#[test]
fn test_fec_rto_and_skip_parity() {
    const DATA_SHARDS: usize = 3;
    const PARITY_SHARDS: usize = 2;
    const RTO: u32 = 50; // 50ms RTO

    let mut enc = new_fec_encoder(DATA_SHARDS as isize, PARITY_SHARDS as isize, 0);
    let get_seq = le32;
    let mut now = 1_758_000_000_000i64;
    let send = |enc: &mut FecEncoder, now: i64| {
        let mut p = vec![0u8; 100];
        let ps = encode(enc, &mut p, RTO, now);
        (p, ps)
    };

    // --- Scenario 1: Normal case (Time < RTO) ---
    let (p0, ps) = send(&mut enc, now);
    assert!(ps.is_empty(), "Expected no parity shards yet");
    assert_eq!(get_seq(&p0), 0);

    let (p1, ps) = send(&mut enc, now);
    assert!(ps.is_empty(), "Expected no parity shards yet");
    assert_eq!(get_seq(&p1), 1);

    // Packet 2 (triggers parity generation)
    let (p2, ps) = send(&mut enc, now);
    assert_eq!(ps.len(), PARITY_SHARDS);
    assert_eq!(get_seq(&p2), 2);
    assert_eq!(get_seq(&ps[0]), 3, "parity[0] seq");
    assert_eq!(get_seq(&ps[1]), 4, "parity[1] seq");

    // --- Scenario 2: Timeout case (Time > RTO) ---
    let (p3, ps) = send(&mut enc, now);
    assert!(ps.is_empty(), "Expected no parity shards yet");
    assert_eq!(get_seq(&p3), 5);

    let (p4, ps) = send(&mut enc, now);
    assert!(ps.is_empty(), "Expected no parity shards yet");
    assert_eq!(get_seq(&p4), 6);

    // Sleep longer than RTO
    now += i64::from(RTO) + 20;

    // Packet 5 (triggers the parity check, which skips)
    let (p5, ps) = send(&mut enc, now);
    assert!(ps.is_empty(), "Expected 0 parity shards due to timeout");
    assert_eq!(get_seq(&p5), 7);

    // --- Verify Sequence ID Growth after Skip ---
    // p5 got seq 7; skip_parity advanced next from 8 by PARITY_SHARDS (2) to 10.
    let (p6, _) = send(&mut enc, now);
    assert_eq!(get_seq(&p6), 10, "seq after skipped parity");
}

/// The recovered payloads of [`test_fec_decode_variable_packet_sizes`] are exactly the lost
/// ones (not in Go, which only counts them).
#[test]
fn test_fec_decode_variable_packet_sizes_recovers_the_lost_packets() {
    let _snmp = snmp_read();
    let mut encoder = new_fec_encoder(8, 3, 0);
    let mut decoder = new_fec_decoder(8, 3);
    let mut rnd = Pcg::new(42, 1);
    let mut lost = Vec::new();
    let mut got = HashSet::new();
    for group in 0..32usize {
        for shard in 0..8usize {
            let len = 8 + rnd.below(893) as usize;
            let mut buf = vec![0u8; FEC_HEADER_SIZE_PLUS2 + len];
            rnd.fill_bytes(&mut buf[FEC_HEADER_SIZE_PLUS2..]);
            let ps = encode(&mut encoder, &mut buf, MAX_FEC_ENCODE_LATENCY, group as i64);
            let mut inputs = ps;
            if shard == group % 8 || shard == (group + 3) % 8 {
                lost.push(buf[FEC_HEADER_SIZE_PLUS2..].to_vec());
            } else {
                inputs.insert(0, buf);
            }
            for p in inputs {
                for r in decoder.decode(&p) {
                    let sz = usize::from(u16::from_le_bytes([r[0], r[1]]));
                    got.insert(r[2..sz].to_vec());
                }
            }
        }
    }
    assert_eq!(lost.len(), 64);
    assert_eq!(got.len(), 64);
    assert!(lost.iter().all(|body| got.contains(body)));
}
