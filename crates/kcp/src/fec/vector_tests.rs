//! Go golden FEC sequences (`testdata/vectors/fec.json`, plan step 04.6, format in
//! `tools/govectors/README.md`, "Area fec"): the exact packets kcp-go v5.6.66's `fecEncoder`
//! writes for scripted packet lengths and times, and what its `fecDecoder` recovers (and counts)
//! from those streams under loss, duplication, reordering, truncation, crafted packets and
//! senders that change `(ds, ps)` mid-stream. Every byte and every deterministic SNMP counter
//! must match.

use serde::Deserialize;
use std::sync::RwLockWriteGuard;

use super::*;
use crate::kcp::SNMP_TEST_LOCK;
use kcptun_testkit::rng::{govectors_rng, rand_bytes};
use kcptun_testkit::vectors::{VectorFile, sha256_hex};
use kcptun_testkit::{assert_hex_eq, vectors};

fn snmp_write() -> RwLockWriteGuard<'static, ()> {
    SNMP_TEST_LOCK.write().unwrap_or_else(|e| e.into_inner())
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

#[derive(Deserialize)]
struct EncCase {
    name: String,
    ds: isize,
    ps: isize,
    offset: usize,
    rto: u32,
    #[serde(default)]
    next: u32,
    paws: u32,
    payload_stream: u64,
    packets: Vec<EncPacket>,
}

#[derive(Deserialize)]
struct EncPacket {
    len: usize,
    #[serde(default)]
    now: i64,
    #[serde(default)]
    oob: bool,
    out: String,
    #[serde(default)]
    parity: Vec<String>,
}

#[derive(Deserialize)]
struct Phase {
    ds: isize,
    ps: isize,
    next: u32,
    payload_stream: u64,
    lens: String,
    start: i64,
    step: i64,
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
struct Counters {
    fec_shard_set: u64,
    fec_parity_shards: u64,
    fec_full_shard_set: u64,
    fec_recovered: u64,
    fec_errs: u64,
    fec_shard_min: u64,
}

#[derive(Deserialize)]
struct DecCase {
    name: String,
    #[serde(default)]
    stream: Option<String>,
    #[serde(default)]
    phases: Vec<Phase>,
    #[serde(default)]
    stream_sha256: Option<String>,
    ds: isize,
    ps: isize,
    #[serde(default)]
    crafted: Vec<String>,
    feed: String,
    #[serde(default)]
    recovered: Vec<String>,
    #[serde(default)]
    tunes: Vec<String>,
    counters: Counters,
    final_ds: usize,
    final_ps: usize,
    shard_sets: usize,
}

/// One packet the sender put on the wire, from the FEC header on (after the crypto header
/// room).
struct WirePacket {
    b: Vec<u8>,
    oob: bool,
}

fn file() -> VectorFile {
    vectors!("fec")
}

/// The input packets of an encoder case: consecutive slices of one `rand_bytes` stream.
fn enc_inputs(c: &EncCase) -> Vec<Vec<u8>> {
    let total = c.packets.iter().map(|p| p.len).sum();
    let bytes = rand_bytes(&mut govectors_rng("fec", c.payload_stream), total);
    let mut at = 0;
    c.packets
        .iter()
        .map(|p| {
            at += p.len;
            bytes[at - p.len..at].to_vec()
        })
        .collect()
}

/// Runs an encoder case through the Rust encoder and checks every packet byte for byte.
/// Returns the wire stream (data packet, then its parity shards, per call).
fn run_encoder_case(c: &EncCase) -> Vec<WirePacket> {
    let name = &c.name;
    let mut enc = FecEncoder::new(c.ds, c.ps, c.offset)
        .expect("valid shard counts")
        .expect("FEC enabled");
    assert_eq!(enc.paws, c.paws, "{name}: paws");
    enc.next = c.next;
    let mut wire = Vec::new();
    for (i, (p, mut b)) in c.packets.iter().zip(enc_inputs(c)).enumerate() {
        if p.oob {
            let next = enc.next;
            enc.encode_oob(&mut b).expect("encode_oob");
            assert_eq!(enc.next, next, "{name}: packet {i}: OOB consumed a seqid");
            assert_hex_eq!(b, unhex(&p.out), "{name}: OOB packet {i}");
            wire.push(WirePacket {
                b: b[c.offset..].to_vec(),
                oob: true,
            });
            continue;
        }
        let parity: Vec<Vec<u8>> = enc
            .encode(&mut b, c.rto, p.now)
            .expect("encode")
            .iter()
            .map(<[u8]>::to_vec)
            .collect();
        assert_hex_eq!(b, unhex(&p.out), "{name}: data packet {i}");
        assert_eq!(
            parity.len(),
            p.parity.len(),
            "{name}: packet {i}: parity shard count"
        );
        wire.push(WirePacket {
            b: b[c.offset..].to_vec(),
            oob: false,
        });
        for (k, (got, want)) in parity.iter().zip(&p.parity).enumerate() {
            assert_hex_eq!(got, unhex(want), "{name}: packet {i}: parity {k}");
            wire.push(WirePacket {
                b: got[c.offset..].to_vec(),
                oob: false,
            });
        }
    }
    wire
}

/// Every encoder sequence: data packets (sealed seqid/type/size, the rest untouched), OOB
/// packets and parity shards (including the zeroed crypto header room of the shard cache) are
/// identical to Go's, with parity skipped exactly where Go skips it (the 500 ms rule at its
/// 499/500 boundary, a clock going backwards, and the `ds == 1` first-group quirk, which the
/// `i64::MIN / 2` start value reproduces against Go's 0) and seqids wrapping at `paws`.
#[test]
fn vectors_fec_encoder() {
    let file = file();
    let mut n = 0;
    for case in file.cases_with_prefix("encoder/") {
        let c: EncCase = case.to();
        let wire = run_encoder_case(&c);
        assert!(!wire.is_empty());
        n += 1;
    }
    assert_eq!(n, 4);
}

/// Builds the wire stream of an autotune case with the Rust encoder (checked byte for byte by
/// [`vectors_fec_encoder`]) and checks it against Go's digest.
fn phases_stream(name: &str, phases: &[Phase], want_sha256: &str) -> Vec<WirePacket> {
    let mut wire = Vec::new();
    let mut digest = Vec::new();
    for ph in phases {
        let lens: Vec<usize> = ph
            .lens
            .split(' ')
            .map(|l| l.parse().expect("length"))
            .collect();
        let total = lens.iter().sum();
        let bytes = rand_bytes(&mut govectors_rng("fec", ph.payload_stream), total);
        let mut enc = FecEncoder::new(ph.ds, ph.ps, 0)
            .expect("valid shard counts")
            .expect("FEC enabled");
        enc.next = ph.next;
        let mut at = 0;
        for (i, &len) in lens.iter().enumerate() {
            let mut b = bytes[at..at + len].to_vec();
            at += len;
            let now = ph.start + i as i64 * ph.step;
            let parity: Vec<Vec<u8>> = enc
                .encode(&mut b, MAX_FEC_ENCODE_LATENCY, now)
                .expect("encode")
                .iter()
                .map(<[u8]>::to_vec)
                .collect();
            for p in std::iter::once(b).chain(parity) {
                digest.extend_from_slice(&(p.len() as u16).to_le_bytes());
                digest.extend_from_slice(&p);
                wire.push(WirePacket { b: p, oob: false });
            }
        }
    }
    assert_eq!(sha256_hex(&digest), want_sha256, "{name}: stream digest");
    wire
}

/// Feeds a decoder case and checks every recovered shard, every retune, the counters and the
/// final decoder state.
fn run_decoder_case(file: &VectorFile, c: &DecCase) {
    let name = &c.name;
    let wire = match (&c.stream, &c.stream_sha256) {
        (Some(stream), None) => run_encoder_case(&file.case(stream).to::<EncCase>()),
        (None, Some(digest)) => phases_stream(name, &c.phases, digest),
        _ => panic!("{name}: needs either stream or phases"),
    };
    let crafted: Vec<Vec<u8>> = c.crafted.iter().map(|h| unhex(h)).collect();

    let mut dec = FecDecoder::new(c.ds, c.ps).expect("valid decoder");
    let _lock = snmp_write();
    // Go resets DefaultSnmp before each case: the gauges start at 0, the counters are deltas.
    DEFAULT_SNMP.fec_shard_set.store(0, Ordering::Relaxed);
    DEFAULT_SNMP.fec_shard_min.store(0, Ordering::Relaxed);
    let before = DEFAULT_SNMP.copy();

    let mut recovered = Vec::new();
    let mut tunes = Vec::new();
    let mut shards = (dec.data_shards(), dec.parity_shards());
    for (call, tok) in c.feed.split(' ').enumerate() {
        let pkt: &[u8] = if let Some(k) = tok.strip_prefix('c') {
            &crafted[k.parse::<usize>().expect("crafted index")]
        } else if let Some((i, cut)) = tok.split_once(':') {
            let p = &wire[i.parse::<usize>().expect("index")];
            assert!(!p.oob, "{name}: OOB packets never reach the decoder");
            &p.b[..cut.parse::<usize>().expect("cut")]
        } else {
            let p = &wire[tok.parse::<usize>().expect("index")];
            assert!(!p.oob, "{name}: OOB packets never reach the decoder");
            &p.b
        };
        for r in dec.decode(pkt) {
            recovered.push(format!("{call} {} {}", r.len(), sha256_hex(&r)));
        }
        let now = (dec.data_shards(), dec.parity_shards());
        if now != shards {
            shards = now;
            tunes.push(format!("{call} {} {}", now.0, now.1));
        }
    }

    // First differing recovery, for a readable failure.
    if let Some(i) =
        (0..recovered.len().min(c.recovered.len())).find(|&i| recovered[i] != c.recovered[i])
    {
        panic!(
            "{name}: recovered shard {i} differs: got {:?}, want {:?}",
            recovered[i], c.recovered[i]
        );
    }
    assert_eq!(recovered, c.recovered, "{name}: recovered shards");
    assert_eq!(tunes, c.tunes, "{name}: retunes");

    let after = DEFAULT_SNMP.copy();
    let got = Counters {
        fec_shard_set: after.fec_shard_set,
        fec_parity_shards: after.fec_parity_shards - before.fec_parity_shards,
        fec_full_shard_set: after.fec_full_shard_set - before.fec_full_shard_set,
        fec_recovered: after.fec_recovered - before.fec_recovered,
        fec_errs: after.fec_errs - before.fec_errs,
        fec_shard_min: after.fec_shard_min,
    };
    assert_eq!(got, c.counters, "{name}: SNMP counters");
    assert_eq!(
        (dec.data_shards(), dec.parity_shards(), dec.shard_set.len()),
        (c.final_ds, c.final_ps, c.shard_sets),
        "{name}: final (ds, ps, shard sets)"
    );
}

/// Every decoder scenario on the encoder streams: the same recovered shards after the same
/// calls, the same counters (`FECParityShards`, `FECFullShardSet`, `FECRecovered`, `FECErrs`,
/// and the `FECShardSet`/`FECShardMin` gauges) and the same final state as Go.
#[test]
fn vectors_fec_decoder() {
    let file = file();
    let mut n = 0;
    for case in file.cases_with_prefix("decoder/") {
        run_decoder_case(&file, &case.to());
        n += 1;
    }
    assert_eq!(n, 42);
}

/// Senders that switch `(ds, ps)` mid-stream ((10,3) -> (5,2), restarted seqids, a switch
/// back, a decoder configured differently from the start, and a lossy switch): the decoder
/// retunes after the same packet as Go's and then recovers the same shards.
#[test]
fn vectors_fec_autotune() {
    let file = file();
    let mut n = 0;
    for case in file.cases_with_prefix("autotune/") {
        run_decoder_case(&file, &case.to());
        n += 1;
    }
    assert_eq!(n, 5);
}

/// The vectors cover what they claim: skipped and emitted parity, OOB packets, the paws wrap,
/// recoveries, FECErrs, retunes and blocked tuning.
#[test]
fn vectors_fec_coverage() {
    let file = file();
    let mut skipped = 0;
    let mut oob = 0;
    let mut wrapped = false;
    for case in file.cases_with_prefix("encoder/") {
        let c: EncCase = case.to();
        let size = (c.ds + c.ps).unsigned_abs() as u32;
        for p in &c.packets {
            if p.oob {
                oob += 1;
                continue;
            }
            let seqid =
                u32::from_le_bytes(unhex(&p.out)[c.offset..c.offset + 4].try_into().unwrap());
            if seqid % size == c.ds.unsigned_abs() as u32 - 1 && p.parity.is_empty() {
                skipped += 1;
            }
            wrapped |= c.next != 0 && seqid < size;
        }
    }
    assert!(
        skipped >= 10 && oob == 3 && wrapped,
        "skipped {skipped}, oob {oob}"
    );
    let mut errs = 0;
    let mut recovered = 0;
    let mut tunes = 0;
    for case in file.cases_with_prefix("") {
        if case.name.starts_with("encoder/") {
            continue;
        }
        let c: DecCase = case.to();
        errs += c.counters.fec_errs;
        recovered += c.counters.fec_recovered;
        tunes += c.tunes.len();
    }
    assert!(
        errs >= 3 && recovered > 500 && tunes >= 6,
        "errs {errs}, recovered {recovered}, tunes {tunes}"
    );
}
