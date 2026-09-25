//! Go golden snappy vectors (`testdata/vectors/snappy.json`, plan step 07.1; format in
//! `tools/govectors/README.md`, "Area snappy"): the exact bytes kcptun's `CompStream` wrote for
//! a scripted sequence of writes, and what `golang/snappy`'s `Reader` made of a set of hand-made
//! streams — including every way one can be malformed.
//!
//! The Rust writer must produce those bytes for the same writes, and the Rust reader must
//! deliver the same prefix and stop with the same error text.

use kcptun_testkit::rng::{govectors_rng, rand_bytes};
use kcptun_testkit::vectors::{Blob, Case, VectorFile};
use kcptun_testkit::{assert_hex_eq, vectors};
use serde::Deserialize;

use super::tests::{decode_partial, decode_partial_sizes, encode, text};

fn file() -> VectorFile {
    vectors!("snappy")
}

/// One scripted sequence of writes (`snappyWriteCase` in `tools/govectors/snappy.go`).
#[derive(Deserialize)]
struct WriteCase {
    name: String,
    /// How the payload is built: `text`, `random` or `zeros`.
    kind: String,
    /// The `newRNG("snappy", stream)` that produced a `random` payload.
    #[serde(default)]
    stream: u64,
    /// Length of each `Write` call, in order.
    writes: Vec<usize>,
    /// Total payload length.
    len: usize,
    #[serde(default, rename = "in")]
    input: String,
    #[serde(default)]
    in_blob: Option<Blob>,
    #[serde(default)]
    out: String,
    #[serde(default)]
    out_blob: Option<Blob>,
}

impl WriteCase {
    /// Rebuilds the payload the Go generator wrote, and checks it against the recorded bytes so
    /// a divergence shows up here rather than as a mismatch of the framed output.
    fn payload(&self) -> Vec<u8> {
        let payload = match self.kind.as_str() {
            "text" => text(self.len),
            "random" => rand_bytes(&mut govectors_rng("snappy", self.stream), self.len),
            "zeros" => vec![0u8; self.len],
            other => panic!("{}: unknown payload kind {other:?}", self.name),
        };
        assert_eq!(payload.len(), self.len, "{}: payload length", self.name);
        match &self.in_blob {
            Some(blob) => blob.assert_matches(&payload, &self.name),
            None => assert_hex_eq!(
                payload,
                hex::decode(&self.input).expect("hex"),
                "case {}: payload",
                self.name
            ),
        }
        payload
    }
}

/// One framed stream handed to the reader (`snappyReadCase` in `tools/govectors/snappy.go`).
#[derive(Deserialize)]
struct ReadCase {
    name: String,
    #[serde(default, rename = "in")]
    input: String,
    /// The bytes Go's reader delivered before it stopped.
    #[serde(default)]
    out: String,
    /// Go's error text, empty for a clean end of stream.
    err: String,
}

// Every scripted sequence of writes must produce Go's bytes, byte for byte, and read back.
#[test]
fn vectors_snappy_writes() {
    let f = file();
    let cases: Vec<WriteCase> = f.cases_with_prefix("write/").map(Case::to).collect();
    assert!(cases.len() >= 14, "only {} write cases", cases.len());

    for c in &cases {
        let payload = c.payload();
        assert_eq!(
            c.writes.iter().sum::<usize>(),
            c.len,
            "{}: writes do not add up",
            c.name
        );

        // The same Write calls kcptun's CompStream made.
        let mut off = 0;
        let mut writes: Vec<&[u8]> = Vec::with_capacity(c.writes.len());
        for &n in &c.writes {
            writes.push(&payload[off..off + n]);
            off += n;
        }
        let got = encode(&writes);

        match &c.out_blob {
            Some(blob) => blob.assert_matches(&got, &c.name),
            None => assert_hex_eq!(
                got,
                hex::decode(&c.out).expect("hex"),
                "case {}: framed output",
                c.name
            ),
        }

        // And what we wrote decodes back to what we wrote.
        let (back, err) = decode_partial(&got, 1024);
        assert_eq!(err, None, "{}: decoding our own output", c.name);
        assert_hex_eq!(back, payload, "case {}: round trip", c.name);
    }
}

// Every hand-made stream must give the Rust reader the bytes Go's reader delivered, and the
// same error text (or no error).
#[test]
fn vectors_snappy_reads() {
    let f = file();
    let cases: Vec<ReadCase> = f
        .cases_with_prefix("read/")
        .chain(f.cases_with_prefix("error/"))
        .map(Case::to)
        .collect();
    assert!(cases.len() >= 30, "only {} read cases", cases.len());

    let mut errors = 0;
    for c in &cases {
        let framed = hex::decode(&c.input).expect("hex");
        let want = hex::decode(&c.out).expect("hex");
        // Several read sizes: the decoded bytes have to survive being served piecemeal, and a
        // chunk has to survive arriving in pieces.
        for read_size in [usize::MAX, 1, 7, 4096] {
            let (got, err) = decode_partial_sizes(&framed, read_size, 64);
            assert_hex_eq!(
                got,
                want,
                "case {} (read_size {read_size}): decoded bytes",
                c.name
            );
            match (&err, c.err.as_str()) {
                (None, "") => {}
                (Some(got_err), want_err) if !want_err.is_empty() => {
                    assert_eq!(
                        got_err, want_err,
                        "{} (read_size {read_size}): error",
                        c.name
                    );
                }
                (got_err, want_err) => panic!(
                    "{} (read_size {read_size}): error {got_err:?}, want {want_err:?}",
                    c.name
                ),
            }
        }
        if !c.err.is_empty() {
            errors += 1;
        }
    }
    assert!(errors >= 20, "only {errors} malformed streams");

    // The two error texts the reader can produce are Go's, and both are covered.
    let texts: std::collections::BTreeSet<&str> = cases
        .iter()
        .map(|c| c.err.as_str())
        .filter(|e| !e.is_empty())
        .collect();
    assert_eq!(
        texts,
        ["snappy: corrupt input", "snappy: unsupported input"]
            .into_iter()
            .collect()
    );
}
