//! Go golden QPP vectors (`testdata/vectors/qpp.json`, plan step 07.2; format in
//! `tools/govectors/README.md`, "Area qpp"): the sizes `xtaci/qpp` v1.1.25 derives from the
//! number of qubits, the seed chunks and permutation matrices a seed produces, the state of a
//! freshly created PRNG and its next outputs, and the ciphertext of a 1 MiB stream encrypted in
//! four different chunkings.
//!
//! The Rust port must reproduce all of it byte for byte, and must decrypt the recorded
//! ciphertext back to the recorded plaintext.

use kcptun_testkit::rng::{govectors_rng, rand_bytes};
use kcptun_testkit::vectors;
use kcptun_testkit::vectors::{Blob, Case, VectorFile, sha256_hex};
use serde::Deserialize;

use super::*;

fn file() -> VectorFile {
    vectors!("qpp")
}

/// Rebuilds a case's seed: the recorded hex for a fixed seed, or `seed_len` bytes from the
/// govectors RNG stream that drew it.
#[track_caller]
fn seed_of(seed: &str, seed_stream: u64, seed_len: usize, name: &str) -> Vec<u8> {
    let bytes = if seed.is_empty() {
        assert_ne!(seed_stream, 0, "{name}: neither seed nor seed_stream");
        rand_bytes(&mut govectors_rng("qpp", seed_stream), seed_len)
    } else {
        hex::decode(seed).unwrap_or_else(|e| panic!("{name}: seed: {e}"))
    };
    assert_eq!(bytes.len(), seed_len, "{name}: seed length");
    bytes
}

/// One `minimum/qubits=N` case (`qppSizeCase` in `tools/govectors/qpp.go`).
#[derive(Deserialize)]
struct SizeCase {
    name: String,
    qubits: u8,
    seed_len: usize,
    minimum_pads: usize,
}

/// One `chunks/<seed>` case (`qppChunksCase`).
#[derive(Deserialize)]
struct ChunksCase {
    name: String,
    #[serde(default)]
    seed: String,
    #[serde(default)]
    seed_stream: u64,
    seed_len: usize,
    expanded: bool,
    chunks: usize,
    out: String,
}

/// One `pads/num_pads=N` case (`qppPadsCase`).
#[derive(Deserialize)]
struct PadsCase {
    name: String,
    seed: String,
    num_pads: u16,
    pad0: String,
    pads: Blob,
    rpads: Blob,
}

/// One `prng/<ctor>/<seed>` case (`qppPrngCase`).
#[derive(Deserialize)]
struct PrngCase {
    name: String,
    ctor: String,
    #[serde(default)]
    seed: String,
    #[serde(default)]
    seed_stream: u64,
    seed_len: usize,
    xoshiro: [u64; 4],
    seed64: u64,
    count: u8,
    outputs: Vec<u64>,
}

/// One `stream/<chunking>` case (`qppStreamCase`).
#[derive(Deserialize)]
struct StreamCase {
    name: String,
    seed: String,
    num_pads: u16,
    /// Piece size: 0 one whole call, -1 random pieces of 1..4096 bytes.
    chunk: i64,
    #[serde(default)]
    chunk_stream: u64,
    plain_stream: u64,
    plain: Blob,
    out: Blob,
    rand_after: RandState,
}

/// A `Rand` as the vectors record it (`qppRandState`).
#[derive(Deserialize)]
struct RandState {
    xoshiro: [u64; 4],
    seed64: u64,
    count: u8,
}

impl RandState {
    #[track_caller]
    fn assert_matches(&self, rand: &Rand, what: &str) {
        assert_eq!(rand.xoshiro(), self.xoshiro, "{what}: xoshiro state");
        assert_eq!(rand.seed64(), self.seed64, "{what}: seed64");
        assert_eq!(rand.count(), self.count, "{what}: count");
    }
}

/// The minimum seed length and pad count for every qubit width Go recorded.
#[test]
fn vectors_minimum_sizes() {
    let f = file();
    let cases: Vec<SizeCase> = f.cases_with_prefix("minimum/").map(Case::to).collect();
    assert_eq!(cases.len(), 15, "minimum cases");
    for c in &cases {
        assert_eq!(
            qpp_minimum_seed_length(c.qubits),
            c.seed_len,
            "{}: QPPMinimumSeedLength",
            c.name
        );
        assert_eq!(
            qpp_minimum_pads(c.qubits),
            c.minimum_pads,
            "{}: QPPMinimumPads",
            c.name
        );
    }
    // The two values the protocol actually uses.
    assert_eq!(qpp_minimum_seed_length(QUBITS), 211);
    assert_eq!(qpp_minimum_pads(QUBITS), 7);
}

/// `seed_to_chunks` for a short seed (PBKDF2-expanded first), a seed of exactly the expansion
/// threshold and one longer than the 224 bytes the seven chunks consume.
#[test]
fn vectors_seed_to_chunks() {
    let f = file();
    let cases: Vec<ChunksCase> = f.cases_with_prefix("chunks/").map(Case::to).collect();
    assert_eq!(cases.len(), 4, "chunks cases");
    for c in &cases {
        let seed = seed_of(&c.seed, c.seed_stream, c.seed_len, &c.name);
        assert_eq!(seed.len() < 32, c.expanded, "{}: expansion", c.name);

        let chunks = seed_to_chunks(&seed, QUBITS);
        assert_eq!(chunks.len(), c.chunks, "{}: chunk count", c.name);
        assert_eq!(
            hex::encode(chunks.concat()),
            c.out,
            "{}: chunks differ",
            c.name
        );
    }
}

/// The permutation matrices and their inverses, for pad counts whose ids span several binary
/// widths (the pad id goes into the HMAC message as `QPP_<binary>`).
#[test]
fn vectors_pads() {
    let f = file();
    let cases: Vec<PadsCase> = f.cases_with_prefix("pads/").map(Case::to).collect();
    assert_eq!(cases.len(), 4, "pads cases");
    for c in &cases {
        let seed = seed_of(&c.seed, 0, c.seed.len() / 2, &c.name);
        let qpp = QuantumPermutationPad::new(&seed, c.num_pads);
        assert_eq!(qpp.num_pads(), c.num_pads, "{}: num_pads", c.name);

        assert_eq!(hex::encode(qpp.pad(0)), c.pad0, "{}: first pad", c.name);
        c.pads
            .assert_matches(&qpp.pads_bytes(), &format!("{}: pads", c.name));
        c.rpads
            .assert_matches(&qpp.rpads_bytes(), &format!("{}: rpads", c.name));

        // Every pad is a permutation and every rpad its inverse (Go's TestPads).
        for i in 0..usize::from(c.num_pads) {
            let (pad, rpad) = (qpp.pad(i), qpp.rpad(i));
            for j in 0..MATRIX_BYTES {
                assert_eq!(rpad[usize::from(pad[j])], j as u8, "{}: pad {i}", c.name);
            }
        }
    }
}

/// The state both constructors produce and the outputs the generator goes on to give.
#[test]
fn vectors_prng() {
    let f = file();
    let cases: Vec<PrngCase> = f.cases_with_prefix("prng/").map(Case::to).collect();
    assert_eq!(cases.len(), 8, "prng cases");
    for c in &cases {
        let seed = seed_of(&c.seed, c.seed_stream, c.seed_len, &c.name);
        let mut rd = match c.ctor.as_str() {
            "create" => create_prng(&seed),
            "fast" => fast_prng(&seed),
            other => panic!("{}: unknown constructor {other:?}", c.name),
        };
        assert_eq!(rd.xoshiro(), c.xoshiro, "{}: xoshiro state", c.name);
        assert_eq!(rd.seed64(), c.seed64, "{}: seed64", c.name);
        assert_eq!(rd.count(), c.count, "{}: count", c.name);

        let outputs: Vec<u64> = (0..c.outputs.len()).map(|_| rd.next_u64()).collect();
        assert_eq!(outputs, c.outputs, "{}: outputs", c.name);
    }
}

/// A 1 MiB stream encrypted whole, byte by byte, in 7-byte pieces and in random pieces. All
/// four must give the same ciphertext as Go: the transform depends on the position in the
/// stream, not on how it is chopped up, and the recorded ciphertext must decrypt back.
#[test]
fn vectors_stream() {
    let f = file();
    let cases: Vec<StreamCase> = f.cases_with_prefix("stream/").map(Case::to).collect();
    assert_eq!(cases.len(), 4, "stream cases");
    for c in &cases {
        let seed = seed_of(&c.seed, 0, c.seed.len() / 2, &c.name);
        let plain = rand_bytes(&mut govectors_rng("qpp", c.plain_stream), c.plain.len);
        c.plain
            .assert_matches(&plain, &format!("{}: plaintext", c.name));

        // Encrypt with the default generator, in the recorded chunking.
        let mut qpp = QuantumPermutationPad::new(&seed, c.num_pads);
        let mut out = plain.clone();
        let mut rng = govectors_rng("qpp", c.chunk_stream);
        let mut off = 0;
        while off < out.len() {
            let n = match c.chunk {
                0 => out.len(),
                -1 => 1 + (rng.next_u64() % 4096) as usize,
                n => n as usize,
            }
            .min(out.len() - off);
            qpp.encrypt(&mut out[off..off + n]);
            off += n;
        }
        c.out
            .assert_matches(&out, &format!("{}: ciphertext", c.name));
        c.rand_after
            .assert_matches(qpp.enc_rand(), &format!("{}: generator", c.name));

        // The explicit-generator API must agree with the default one, in one call.
        let mut whole = plain.clone();
        let mut rand = create_prng(&seed);
        qpp.encrypt_with_prng(&mut whole, &mut rand);
        assert_eq!(
            sha256_hex(&whole),
            c.out.sha256,
            "{}: encrypt_with_prng differs",
            c.name
        );

        // And the ciphertext must decrypt back, both ways round.
        let mut back = out.clone();
        let mut rand = create_prng(&seed);
        qpp.decrypt_with_prng(&mut back, &mut rand);
        assert_eq!(back, plain, "{}: round trip", c.name);
        c.rand_after
            .assert_matches(&rand, &format!("{}: decryption generator", c.name));

        let mut back = out.clone();
        qpp.decrypt(&mut back);
        assert_eq!(back, plain, "{}: round trip (default generator)", c.name);
    }
}

/// Every case in the file is claimed by one of the tests above, so a group added to the
/// generator cannot sit unchecked.
#[test]
fn vectors_cover_every_case() {
    let f = file();
    assert_eq!(f.area, "qpp");
    assert_eq!(f.module("github.com/xtaci/qpp"), Some("v1.1.25"));
    let claimed = ["minimum/", "chunks/", "pads/", "prng/", "stream/"];
    for case in &f.cases {
        assert!(
            claimed.iter().any(|p| case.name.starts_with(p)),
            "case {} is not covered by any test",
            case.name
        );
    }
    assert_eq!(f.len(), 35, "case count");
}
