//! The `fec_decode` fuzz harness (plan step 04.6): a byte string picks the decoder's `(ds, ps)`
//! and then feeds it arbitrary packets, crafted FEC packets (valid-looking headers around live
//! seqids, garbage bodies) and the packets of an honest [`FecEncoder`] (possibly with other shard
//! counts, so the decoder has to auto-tune), lost, truncated, duplicated or reordered. Nothing may
//! panic.
//!
//! The cargo-fuzz target (`crates/kcp/fuzz/fuzz_targets/fec_decode.rs`) only calls
//! [`fec_decode`]; the harness lives here so this crate's tests run it over the seeds and the
//! regression inputs.
//!
//! # Input format
//!
//! Three selector bytes, then ops until the input is exhausted:
//!
//! - byte 0: decoder `ds` = `1 + b % 16`, or one of the large values `64, 128, 200, 249`
//!   (`b & 3`) when `b >= 0xFC`;
//! - byte 1: decoder `ps` = `1 + b % 8`, or one of `16, 56, 128, 232` when `b >= 0xFC` (with
//!   `ds + ps > 256`, [`FecDecoder::new`] must return `None` and the run ends).
//!   Building a large codec takes milliseconds (the 249x249 matrix inversion), so large shard
//!   counts are rare selector values to keep the fuzzer fast;
//! - byte 2: the honest sender uses the decoder's `(ds, ps)` when `b < 0x80`, otherwise
//!   `(1 + (b & 15), 1 + ((b >> 4) & 7))`.
//!
//! Every op is a tag byte (taken modulo [`NUM_FEC_OPS`]) followed by its little-endian
//! arguments; see [`FecOp`]. A truncated op at the end is dropped; a byte string field takes
//! what is left when the input ends first.
//!
//! After every `decode` the harness checks what holds in kcp-go too: a retune returns nothing,
//! at most `ds` shards come back, no recovered shard is longer than the longest packet seen so
//! far minus the FEC header, and the decoder's shard counts stay valid.
#![forbid(unsafe_code)]

use std::collections::VecDeque;

use crate::fec::{
    FEC_HEADER_SIZE, FecDecoder, FecEncoder, MAX_FEC_ENCODE_LATENCY, OOB_SEQID, TYPE_DATA,
    TYPE_OOB, TYPE_PARITY,
};

/// Number of op kinds; a tag byte selects `tag % NUM_FEC_OPS`.
pub const NUM_FEC_OPS: u8 = 8;

/// Upper bound on the packets waiting in the honest sender's queue; the oldest is dropped
/// beyond it.
pub const MAX_PENDING: usize = 1024;

/// Longest packet the honest sender produces (Go's `mtuLimit`).
const MAX_ENCODE_LEN: usize = 1500;

/// One harness step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FecOp {
    /// `decode(data)`: raw bytes (`u16` length, then the bytes).
    Raw { data: Vec<u8> },
    /// `decode(seqid | flag | body)` with `seqid = cursor + delta` (wrapping); the cursor then
    /// moves past it. `kind % 4`: 0 = data, 1 = parity, 2 = OOB (seqid `0xFFFFFFFF`), 3 =
    /// `flag` as given. Arguments `delta: i8, kind: u8, flag: u16`, then a `u16` body length and
    /// the body.
    Header {
        delta: i8,
        kind: u8,
        flag: u16,
        body: Vec<u8>,
    },
    /// Sets the crafted-header cursor (e.g. near `paws`, or into the honest sender's range).
    Jump { seq: u32 },
    /// The honest sender encodes a packet of `8 + len % 1493` bytes, `gap * 4` ms after its
    /// previous one (so the 500 ms parity skip is reachable); the data packet and any parity
    /// shards are queued.
    Encode { len: u16, gap: u8 },
    /// Removes queued packet `idx % queued` and decodes it, truncated to `cut` bytes when
    /// `0 < cut < len`.
    Deliver { idx: u8, cut: u16 },
    /// Removes queued packet `idx % queued` (lost).
    Drop { idx: u8 },
    /// Decodes a copy of queued packet `idx % queued` and keeps it queued (duplicate).
    Duplicate { idx: u8 },
    /// Decodes every queued packet in order and empties the queue.
    DeliverAll,
}

struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.data.split_first_chunk::<N>()?;
        self.data = rest;
        Some(*head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.array::<1>().map(|[b]| b)
    }

    fn u16(&mut self) -> Option<u16> {
        self.array().map(u16::from_le_bytes)
    }

    fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_le_bytes)
    }

    fn bytes(&mut self, n: usize) -> &'a [u8] {
        let (head, rest) = self.data.split_at(n.min(self.data.len()));
        self.data = rest;
        head
    }
}

impl FecOp {
    fn decode(r: &mut Reader<'_>) -> Option<FecOp> {
        Some(match r.u8()? % NUM_FEC_OPS {
            0 => {
                let len = usize::from(r.u16()?);
                FecOp::Raw {
                    data: r.bytes(len).to_vec(),
                }
            }
            1 => {
                let delta = r.u8()? as i8;
                let kind = r.u8()?;
                let flag = r.u16()?;
                let len = usize::from(r.u16()?);
                FecOp::Header {
                    delta,
                    kind,
                    flag,
                    body: r.bytes(len).to_vec(),
                }
            }
            2 => FecOp::Jump { seq: r.u32()? },
            3 => FecOp::Encode {
                len: r.u16()?,
                gap: r.u8()?,
            },
            4 => FecOp::Deliver {
                idx: r.u8()?,
                cut: r.u16()?,
            },
            5 => FecOp::Drop { idx: r.u8()? },
            6 => FecOp::Duplicate { idx: r.u8()? },
            _ => FecOp::DeliverAll,
        })
    }

    /// Appends the op in the input format.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let bytes = |out: &mut Vec<u8>, b: &[u8]| {
            let n = b.len().min(usize::from(u16::MAX));
            out.extend_from_slice(&(n as u16).to_le_bytes());
            out.extend_from_slice(&b[..n]);
        };
        match self {
            FecOp::Raw { data } => {
                out.push(0);
                bytes(out, data);
            }
            FecOp::Header {
                delta,
                kind,
                flag,
                body,
            } => {
                out.extend_from_slice(&[1, *delta as u8, *kind]);
                out.extend_from_slice(&flag.to_le_bytes());
                bytes(out, body);
            }
            FecOp::Jump { seq } => {
                out.push(2);
                out.extend_from_slice(&seq.to_le_bytes());
            }
            FecOp::Encode { len, gap } => {
                out.push(3);
                out.extend_from_slice(&len.to_le_bytes());
                out.push(*gap);
            }
            FecOp::Deliver { idx, cut } => {
                out.extend_from_slice(&[4, *idx]);
                out.extend_from_slice(&cut.to_le_bytes());
            }
            FecOp::Drop { idx } => out.extend_from_slice(&[5, *idx]),
            FecOp::Duplicate { idx } => out.extend_from_slice(&[6, *idx]),
            FecOp::DeliverAll => out.push(7),
        }
    }
}

/// Encodes the selector bytes and `ops` in the input format.
pub fn encode(selectors: [u8; 3], ops: &[FecOp]) -> Vec<u8> {
    let mut out = selectors.to_vec();
    for op in ops {
        op.encode(&mut out);
    }
    out
}

/// Decodes an input into its selector bytes and ops (`None` if shorter than 3 bytes).
pub fn decode(data: &[u8]) -> Option<([u8; 3], Vec<FecOp>)> {
    let mut r = Reader { data };
    let selectors = r.array::<3>()?;
    let mut ops = Vec::new();
    while let Some(op) = FecOp::decode(&mut r) {
        ops.push(op);
    }
    Some((selectors, ops))
}

/// The decoder's shard counts selected by the first two bytes.
pub fn decoder_shards(b0: u8, b1: u8) -> (isize, isize) {
    const LARGE_DS: [isize; 4] = [64, 128, 200, 249];
    const LARGE_PS: [isize; 4] = [16, 56, 128, 232];
    let ds = if b0 >= 0xfc {
        LARGE_DS[usize::from(b0 & 3)]
    } else {
        1 + isize::from(b0 % 16)
    };
    let ps = if b1 >= 0xfc {
        LARGE_PS[usize::from(b1 & 3)]
    } else {
        1 + isize::from(b1 % 8)
    };
    (ds, ps)
}

/// What one run did (for tests and seed checks).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FecRunStats {
    /// Ops executed.
    pub ops: usize,
    /// `decode` calls.
    pub decodes: usize,
    /// Recovered shards returned.
    pub recovered: usize,
    /// Recovered shards that pass the session's consumer check (`2 <= size <= len`).
    pub recovered_valid: usize,
    /// Changes of the decoder's `(ds, ps)`.
    pub retunes: usize,
    /// Packets the honest sender encoded.
    pub encoded: usize,
    /// Parity shards the honest sender emitted.
    pub parity: usize,
}

struct Harness {
    dec: FecDecoder,
    enc: Option<FecEncoder>,
    now: i64,
    cursor: u32,
    pending: VecDeque<Vec<u8>>,
    counter: u32,
    longest: usize,
    stats: FecRunStats,
}

impl Harness {
    fn decode(&mut self, pkt: &[u8]) {
        let before = (self.dec.data_shards(), self.dec.parity_shards());
        let recovered = self.dec.decode(pkt);
        self.stats.decodes += 1;
        self.longest = self.longest.max(pkt.len());
        let after = (self.dec.data_shards(), self.dec.parity_shards());
        assert!(
            after.0 >= 1 && after.1 >= 1 && after.0 + after.1 <= 256,
            "invalid shard counts {after:?}"
        );
        if after != before {
            self.stats.retunes += 1;
            assert!(recovered.is_empty(), "a retune returned shards");
        }
        assert!(
            recovered.len() <= before.0,
            "{} shards recovered with ds = {}",
            recovered.len(),
            before.0
        );
        for r in &recovered {
            assert!(
                r.len() + FEC_HEADER_SIZE <= self.longest,
                "recovered {} bytes, longest packet {}",
                r.len(),
                self.longest
            );
            if r.len() >= 2 {
                let sz = usize::from(u16::from_le_bytes([r[0], r[1]]));
                if (2..=r.len()).contains(&sz) {
                    self.stats.recovered_valid += 1;
                }
            }
        }
        self.stats.recovered += recovered.len();
    }

    fn take(&mut self, idx: u8) -> Option<Vec<u8>> {
        let n = self.pending.len();
        if n == 0 {
            return None;
        }
        self.pending.remove(usize::from(idx) % n)
    }

    fn queue(&mut self, pkt: Vec<u8>) {
        if self.pending.len() == MAX_PENDING {
            self.pending.pop_front();
        }
        self.pending.push_back(pkt);
    }

    fn step(&mut self, op: FecOp) {
        self.stats.ops += 1;
        match op {
            FecOp::Raw { data } => self.decode(&data),
            FecOp::Header {
                delta,
                kind,
                flag,
                body,
            } => {
                let (seqid, flag) = match kind % 4 {
                    0 => (self.cursor.wrapping_add(delta as u32), TYPE_DATA),
                    1 => (self.cursor.wrapping_add(delta as u32), TYPE_PARITY),
                    2 => (OOB_SEQID, TYPE_OOB),
                    _ => (self.cursor.wrapping_add(delta as u32), flag),
                };
                if kind % 4 != 2 {
                    self.cursor = seqid.wrapping_add(1);
                }
                let mut pkt = Vec::with_capacity(FEC_HEADER_SIZE + body.len());
                pkt.extend_from_slice(&seqid.to_le_bytes());
                pkt.extend_from_slice(&flag.to_le_bytes());
                pkt.extend_from_slice(&body);
                self.decode(&pkt);
            }
            FecOp::Jump { seq } => self.cursor = seq,
            FecOp::Encode { len, gap } => {
                let Some(enc) = self.enc.as_mut() else {
                    return;
                };
                let len = 8 + usize::from(len) % (MAX_ENCODE_LEN - 7);
                self.counter = self.counter.wrapping_add(1);
                let seed = self.counter;
                let mut b: Vec<u8> = (0..len)
                    .map(|i| (seed.wrapping_mul(31).wrapping_add(i as u32 * 7)) as u8)
                    .collect();
                self.now += i64::from(gap) * 4;
                let parity: Vec<Vec<u8>> =
                    match enc.encode(&mut b, MAX_FEC_ENCODE_LATENCY, self.now) {
                        Ok(ps) => ps.iter().map(<[u8]>::to_vec).collect(),
                        Err(e) => panic!("honest encode of {len} bytes failed: {e}"),
                    };
                self.stats.encoded += 1;
                self.stats.parity += parity.len();
                self.queue(b);
                for p in parity {
                    self.queue(p);
                }
            }
            FecOp::Deliver { idx, cut } => {
                if let Some(mut p) = self.take(idx) {
                    let cut = usize::from(cut);
                    if cut > 0 && cut < p.len() {
                        p.truncate(cut);
                    }
                    self.decode(&p);
                }
            }
            FecOp::Drop { idx } => {
                self.take(idx);
            }
            FecOp::Duplicate { idx } => {
                let n = self.pending.len();
                if n > 0 {
                    let p = self.pending[usize::from(idx) % n].clone();
                    self.decode(&p);
                }
            }
            FecOp::DeliverAll => {
                while let Some(p) = self.pending.pop_front() {
                    self.decode(&p);
                }
            }
        }
    }
}

/// Runs one fuzz input (see the module docs). Panics only on a harness invariant violation or
/// a panic inside the decoder.
pub fn fec_decode(data: &[u8]) -> FecRunStats {
    let Some((sel, ops)) = decode(data) else {
        return FecRunStats::default();
    };
    let (ds, ps) = decoder_shards(sel[0], sel[1]);
    let Some(dec) = FecDecoder::new(ds, ps) else {
        assert!(ds + ps > 256, "FecDecoder::new({ds}, {ps}) returned None");
        return FecRunStats::default();
    };
    let (eds, eps) = if sel[2] < 0x80 {
        (ds, ps)
    } else {
        (
            1 + isize::from(sel[2] & 15),
            1 + isize::from((sel[2] >> 4) & 7),
        )
    };
    let enc = FecEncoder::new(eds, eps, 0).expect("sender shard counts are valid");
    let mut h = Harness {
        dec,
        enc,
        now: 1_758_000_000_000,
        cursor: 0,
        pending: VecDeque::new(),
        counter: 0,
        longest: 0,
        stats: FecRunStats::default(),
    };
    for op in ops {
        h.step(op);
    }
    h.stats
}

/// Hand-made seeds: honest streams of several shard counts with loss, reordering, duplicates
/// and truncation; a sender that differs from the decoder (auto-tuning); crafted headers at and
/// above `paws`, empty shards and garbage; the large codecs.
pub fn fec_handcrafted_seeds() -> Vec<(&'static str, Vec<u8>)> {
    use FecOp::*;
    let group = |n: usize, gap: u8| -> Vec<FecOp> {
        (0..n)
            .map(|i| Encode {
                len: (i * 211 % 1400) as u16,
                gap,
            })
            .collect()
    };
    let lossy = |groups: usize| -> Vec<FecOp> {
        let mut ops = Vec::new();
        for g in 0..groups {
            ops.extend(group(10, 1));
            ops.push(Drop { idx: g as u8 });
            ops.push(Deliver {
                idx: 3,
                cut: if g % 3 == 0 { 40 } else { 0 },
            });
            ops.push(Duplicate { idx: 1 });
            ops.push(DeliverAll);
        }
        ops
    };
    let mut seeds = Vec::new();
    // (10,3) decoder and sender, one loss per group, truncation and duplicates.
    seeds.push(("lossy_10_3", encode([9, 2, 0], &lossy(8))));
    // (3,2) with a skipped parity group (a gap of 1020 ms).
    let mut ops = group(6, 1);
    ops.extend(group(3, 255));
    ops.extend(group(9, 1));
    ops.push(Drop { idx: 0 });
    ops.push(Drop { idx: 5 });
    ops.push(DeliverAll);
    seeds.push(("skip_3_2", encode([2, 1, 0], &ops)));
    // ds == 1: every parity packet decodes its group again.
    let mut ops = group(20, 2);
    ops.push(Drop { idx: 4 });
    ops.push(DeliverAll);
    seeds.push(("ds1", encode([0, 0, 0], &ops)));
    // The sender uses (5,2) while the decoder expects (10,3): auto-tuning.
    let mut ops = group(120, 1);
    ops.push(DeliverAll);
    ops.extend(lossy(4));
    seeds.push(("autotune_5_2", encode([9, 2, 0x94], &ops)));
    // Crafted packets around paws (for (10,3): 4294967287) and garbage.
    seeds.push((
        "crafted_paws",
        encode(
            [9, 2, 0],
            &[
                Jump {
                    seq: 4_294_967_287 - 26,
                },
                Header {
                    delta: 0,
                    kind: 0,
                    flag: 0,
                    body: vec![10, 0, 1, 2, 3, 4, 5, 6, 7, 8],
                },
                Header {
                    delta: 5,
                    kind: 1,
                    flag: 0,
                    body: vec![9; 12],
                },
                Header {
                    delta: 19,
                    kind: 0,
                    flag: 0,
                    body: vec![4, 0, 0xaa, 0xbb],
                },
                Header {
                    delta: 0,
                    kind: 2,
                    flag: 0,
                    body: vec![3, 0, 1],
                },
                Header {
                    delta: -3,
                    kind: 3,
                    flag: 0x1234,
                    body: vec![],
                },
                Raw {
                    data: vec![1, 2, 3],
                },
                Raw {
                    data: vec![0xff; 40],
                },
            ],
        ),
    ));
    // A shard set of header-only packets (reconstruction fails) for (3,2).
    let empty: Vec<FecOp> = [(0, 0), (0, 0), (1, 1)]
        .into_iter()
        .map(|(delta, kind)| Header {
            delta,
            kind,
            flag: 0,
            body: vec![],
        })
        .collect();
    seeds.push(("empty_shards", encode([2, 1, 0], &empty)));
    // Large codecs, (64, 7) and (16, 232), with one loss in the first group.
    let mut ops = group(70, 1);
    ops.push(Drop { idx: 3 });
    ops.push(DeliverAll);
    seeds.push(("large_64_7", encode([0xfc, 6, 0], &ops)));
    let mut ops = group(20, 1);
    ops.push(Drop { idx: 3 });
    ops.push(DeliverAll);
    seeds.push(("large_16_232", encode([0x0f, 0xff, 0], &ops)));
    seeds
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kcp::SNMP_TEST_LOCK;
    use kcptun_testkit::rng::Pcg;

    fn snmp_read() -> std::sync::RwLockReadGuard<'static, ()> {
        SNMP_TEST_LOCK.read().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn fec_fuzz_encode_decode_round_trip() {
        for (name, data) in fec_handcrafted_seeds() {
            let (sel, ops) = decode(&data).expect("seed decodes");
            assert_eq!(encode(sel, &ops), data, "{name}");
        }
    }

    #[test]
    fn fec_fuzz_handcrafted_seeds_run() {
        let _g = snmp_read();
        let seeds = fec_handcrafted_seeds();
        let stats: std::collections::HashMap<&str, FecRunStats> = seeds
            .iter()
            .map(|(name, data)| (*name, fec_decode(data)))
            .collect();
        assert!(stats["lossy_10_3"].recovered_valid >= 8, "{stats:?}");
        assert!(stats["skip_3_2"].recovered_valid >= 1, "{stats:?}");
        assert!(stats["ds1"].recovered_valid >= 10, "{stats:?}");
        assert!(stats["autotune_5_2"].retunes >= 1, "{stats:?}");
        assert!(stats["autotune_5_2"].recovered_valid >= 1, "{stats:?}");
        assert_eq!(stats["empty_shards"].recovered, 0, "{stats:?}");
        assert_eq!(stats["large_64_7"].recovered_valid, 1, "{stats:?}");
        // After the group decoded, every 16 later parity packets decode it again (Go quirk).
        assert!(stats["large_16_232"].recovered_valid > 16, "{stats:?}");
        for (name, s) in &stats {
            assert!(s.ops > 0, "{name}: {s:?}");
        }
    }

    /// Random inputs (uniform bytes and mutated seeds) never panic.
    #[test]
    fn fec_fuzz_any_bytes_run() {
        let _g = snmp_read();
        let mut rng = Pcg::new(0xfec, 0xf022);
        let seeds = fec_handcrafted_seeds();
        for i in 0..400 {
            let mut data = if i % 2 == 0 {
                let mut d = vec![0u8; rng.below(3000) as usize];
                rng.fill_bytes(&mut d);
                d
            } else {
                seeds[i / 2 % seeds.len()].1.clone()
            };
            for _ in 0..rng.below(16) {
                if data.is_empty() {
                    break;
                }
                let at = rng.below(data.len() as u64) as usize;
                data[at] = rng.next_u32() as u8;
            }
            fec_decode(&data);
        }
    }

    #[test]
    fn fec_fuzz_selectors() {
        assert_eq!(decoder_shards(0, 0), (1, 1));
        assert_eq!(decoder_shards(9, 2), (10, 3));
        assert_eq!(decoder_shards(0xfe, 0xfc), (200, 16));
        assert_eq!(decoder_shards(0xff, 0xff), (249, 232));
        assert_eq!(decoder_shards(0xfb, 0xfb), (12, 4));
        // ds + ps > 256: no decoder, empty stats
        assert_eq!(fec_decode(&[0xff, 0xff, 0, 7]), FecRunStats::default());
        assert_eq!(fec_decode(&[1, 2]), FecRunStats::default());
    }

    /// Writes the seed corpus of the `fec_decode` fuzz target to
    /// `crates/kcp/fuzz/seeds/fec_decode/`. Run after changing the harness format or the seeds:
    /// `cargo test -p kcptun-kcp --lib write_fec_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore = "writes the fuzz seed corpus into the source tree"]
    fn write_fec_fuzz_seeds() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/fec_decode");
        if dir.exists() {
            std::fs::remove_dir_all(&dir).expect("remove old seeds");
        }
        std::fs::create_dir_all(&dir).expect("create seed dir");
        for (name, data) in fec_handcrafted_seeds() {
            std::fs::write(dir.join(format!("hand_{name}")), data).expect("write seed");
        }
    }

    /// The committed seed corpus (`crates/kcp/fuzz/seeds/fec_decode/`) is exactly what
    /// [`write_fec_fuzz_seeds`] generates. The files are read at test time on purpose (this
    /// checks the on-disk corpus that libFuzzer reads, not embedded test data).
    #[test]
    fn fec_fuzz_seed_files_up_to_date() {
        const HINT: &str = "fec_decode fuzz seeds are stale; regenerate them with \
            `cargo test -p kcptun-kcp --lib write_fec_fuzz_seeds -- --ignored`";
        let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        // Test executables also run outside the source tree (tools/lab/remote-test.sh).
        if !crate_dir.join("Cargo.toml").exists() {
            eprintln!("fec_fuzz_seed_files_up_to_date: source tree not available, skipping");
            return;
        }
        let dir = crate_dir.join("fuzz/seeds/fec_decode");
        let want: std::collections::BTreeMap<String, Vec<u8>> = fec_handcrafted_seeds()
            .into_iter()
            .map(|(n, d)| (format!("hand_{n}"), d))
            .collect();
        let mut have = std::collections::BTreeMap::new();
        for entry in
            std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}; {HINT}", dir.display()))
        {
            let entry = entry.expect("seed dir entry");
            let name = entry.file_name().into_string().expect("seed file name");
            if name.starts_with('.') {
                continue; // e.g. macOS .DS_Store
            }
            have.insert(name, std::fs::read(entry.path()).expect("read seed"));
        }
        assert!(have == want, "{HINT}");
    }
}
