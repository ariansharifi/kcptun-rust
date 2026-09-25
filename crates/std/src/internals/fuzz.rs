//! The `snappy_reader` fuzz harness (plan step 07.1): an arbitrary byte string is fed to a
//! [`CompStream`](crate::comp::CompStream) as if the peer had sent it through the KCP session.
//! Nothing may panic: corrupt input, unsupported input and the end of the stream are all fine
//! outcomes (porting guide §5: never panic on network input).
//!
//! The cargo-fuzz target (`crates/std/fuzz/fuzz_targets/snappy_reader.rs`) only calls
//! [`snappy_reader`]; the harness lives here so this crate's tests run it over the committed
//! seeds.
//!
//! # Input format
//!
//! Two selector bytes, then the framed stream:
//!
//! - byte 0:
//!   - bit 7: prepend the stream identifier chunk, so the fuzzer reaches the chunk loop without
//!     having to find the ten magic bytes itself (without it, anything but an identifier is
//!     rejected at once);
//!   - bits 0–6: how much one `read` hands the reader, `1 + b` bytes, or everything that is left
//!     when they are zero. Small values make a chunk arrive in pieces;
//! - byte 1: the buffer the caller reads into, `1 + b` bytes (1–256), so decoded bytes have to
//!   be served across several reads.
//!
//! Besides not panicking, the harness checks the reader's two sticky states: after an error
//! every later read must report that same error, and after the end of the stream every later
//! read must report the end again.

use std::io;
use std::sync::Mutex;

use kcptun_smux::SmuxConn;

use crate::comp::{CompStream, MAGIC_CHUNK};

/// The two selector bytes, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selector {
    /// Whether a valid stream identifier chunk is put in front of the input.
    pub identifier: bool,
    /// Bytes one inner `read` hands out, `None` for "everything that is left".
    pub chunk: Option<usize>,
    /// Size of the buffer the caller reads into.
    pub read_buf: usize,
}

impl Selector {
    /// Decodes the two selector bytes.
    pub fn decode(sel: u8, read_buf: u8) -> Selector {
        Selector {
            identifier: sel & 0x80 != 0,
            chunk: match sel & 0x7f {
                0 => None,
                n => Some(usize::from(n)),
            },
            read_buf: usize::from(read_buf) + 1,
        }
    }

    /// Builds the two selector bytes back (used to write the seed corpus).
    pub fn encode(identifier: bool, chunk: u8, read_buf: u8) -> [u8; 2] {
        [if identifier { 0x80 } else { 0 } | (chunk & 0x7f), read_buf]
    }
}

/// A connection that replays a fixed byte string and throws away everything written to it.
struct FuzzConn {
    data: Vec<u8>,
    pos: Mutex<usize>,
    chunk: Option<usize>,
}

impl SmuxConn for FuzzConn {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut pos = self.pos.lock().unwrap_or_else(|e| e.into_inner());
        let left = self.data.len().saturating_sub(*pos);
        if left == 0 || buf.is_empty() {
            return Ok(0); // end of the peer's data
        }
        let n = buf.len().min(left).min(self.chunk.unwrap_or(usize::MAX));
        buf[..n].copy_from_slice(&self.data[*pos..*pos + n]);
        *pos += n;
        Ok(n)
    }

    async fn write_all(&self, _buf: &[u8]) -> io::Result<()> {
        Ok(())
    }

    async fn close(&self) -> io::Result<()> {
        Ok(())
    }
}

/// Reads `data` as a framed snappy stream. Never panics; returns once the stream has ended or
/// the reader has failed.
pub fn snappy_reader(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let Some((&read_buf, body)) = rest.split_first() else {
        return;
    };
    let selector = Selector::decode(sel, read_buf);

    let mut framed = Vec::with_capacity(MAGIC_CHUNK.len() + body.len());
    if selector.identifier {
        framed.extend_from_slice(MAGIC_CHUNK);
    }
    framed.extend_from_slice(body);

    let runtime = match tokio::runtime::Builder::new_current_thread().build() {
        Ok(rt) => rt,
        Err(_) => return,
    };
    runtime.block_on(async move {
        let stream = CompStream::new(FuzzConn {
            data: framed,
            pos: Mutex::new(0),
            chunk: selector.chunk,
        });
        let mut buf = vec![0u8; selector.read_buf];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => {
                    // The end of the stream is sticky: Go's Reader keeps its io.EOF.
                    assert!(
                        matches!(stream.read(&mut buf).await, Ok(0)),
                        "a read after the end of the stream must report the end again"
                    );
                    return;
                }
                Ok(_) => {}
                Err(e) => {
                    // So is an error: Go's Reader returns r.err for ever.
                    let again = stream
                        .read(&mut buf)
                        .await
                        .expect_err("a read after an error must fail again");
                    assert_eq!(
                        again.to_string(),
                        e.to_string(),
                        "the reader reported a different error the second time"
                    );
                    return;
                }
            }
        }
    });
}

/// Hand-made seeds: a valid stream of each chunk type, the skippable and reserved types, and
/// every shape of damage the reader has to reject.
pub fn snappy_reader_handcrafted_seeds() -> Vec<(String, Vec<u8>)> {
    /// Masked CRC-32C, as the framing format defines it (Go: `c>>15|c<<17` plus the mask).
    fn crc(b: &[u8]) -> u32 {
        crc32c::crc32c(b).rotate_right(15).wrapping_add(0xa282_ead8)
    }

    /// One chunk: type, 24-bit little-endian length, body.
    fn chunk(chunk_type: u8, body: &[u8]) -> Vec<u8> {
        let n = body.len();
        let mut out = vec![chunk_type, n as u8, (n >> 8) as u8, (n >> 16) as u8];
        out.extend_from_slice(body);
        out
    }

    /// A data chunk: the checksum of `checksummed`, then `body`.
    fn data_chunk(chunk_type: u8, checksummed: &[u8], body: &[u8]) -> Vec<u8> {
        let mut payload = crc(checksummed).to_le_bytes().to_vec();
        payload.extend_from_slice(body);
        chunk(chunk_type, &payload)
    }

    /// A chunk header that promises a length the stream does not contain.
    fn header(chunk_type: u8, len: usize) -> Vec<u8> {
        vec![chunk_type, len as u8, (len >> 8) as u8, (len >> 16) as u8]
    }

    /// Seed = the selector bytes plus the stream.
    fn seed(head: [u8; 2], parts: &[&[u8]]) -> Vec<u8> {
        let mut out = head.to_vec();
        for p in parts {
            out.extend_from_slice(p);
        }
        out
    }

    // Selector shorthands: (identifier, inner read size, read buffer).
    let whole = Selector::encode(true, 0, 255); // identifier prepended, read everything
    let piecemeal = Selector::encode(true, 3, 0); // 3 bytes in, 1 byte out
    let raw = Selector::encode(false, 0, 255); // the input must carry its own identifier

    let payload = b"payload".as_slice();
    let good = data_chunk(0x01, payload, payload);
    // A compressed chunk the library would write: "aaaa..." as a literal plus a copy.
    let text = vec![b'a'; 300];
    let block = {
        let mut b = vec![0u8; 400];
        let n = snap::raw::Encoder::new()
            .compress(&text, &mut b)
            .expect("compress");
        b.truncate(n);
        b
    };
    let compressed = data_chunk(0x00, &text, &block);

    vec![
        ("empty".into(), whole.to_vec()),
        ("identifier_only".into(), raw.to_vec()),
        ("uncompressed".into(), seed(whole, &[&good])),
        ("compressed".into(), seed(whole, &[&compressed])),
        (
            "both_piecemeal".into(),
            seed(piecemeal, &[&compressed, &good]),
        ),
        (
            "full_stream".into(),
            seed(raw, &[MAGIC_CHUNK, &compressed, &good, MAGIC_CHUNK, &good]),
        ),
        ("no_identifier".into(), seed(raw, &[&good])),
        (
            "skippable".into(),
            seed(
                whole,
                &[&chunk(0x80, b"skip"), &chunk(0xfe, &[0; 64]), &good],
            ),
        ),
        ("reserved_type".into(), seed(whole, &[&chunk(0x02, b"")])),
        (
            "chunk_too_long".into(),
            seed(whole, &[&header(0x00, 76495)]),
        ),
        (
            "uncompressed_over_max_block".into(),
            seed(whole, &[&header(0x01, 65536 + 5), &[0, 0, 0, 0]]),
        ),
        (
            "bad_checksum".into(),
            seed(whole, &[&data_chunk(0x01, b"other", payload)]),
        ),
        (
            "truncated_body".into(),
            seed(whole, &[&header(0x01, 14), b"abc"]),
        ),
        (
            "short_chunk".into(),
            seed(whole, &[&chunk(0x00, b"abc"), &good]),
        ),
        (
            "bad_block".into(),
            seed(whole, &[&data_chunk(0x00, b"", &[0xff; 11])]),
        ),
        (
            "literal_too_long".into(),
            seed(whole, &[&data_chunk(0x00, b"", &[0x0a, 0x24, b'a', b'b'])]),
        ),
        (
            "empty_bodies".into(),
            seed(
                whole,
                &[
                    &data_chunk(0x01, b"", b""),
                    &data_chunk(0x00, b"", &[0x00]),
                    &good,
                ],
            ),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seeds are what the fuzzer starts from: every one of them must run cleanly.
    #[test]
    fn snappy_reader_seeds_run_clean() {
        for (name, data) in snappy_reader_handcrafted_seeds() {
            eprintln!("seed {name} ({} bytes)", data.len());
            snappy_reader(&data);
        }
    }

    /// Short and malformed inputs, including the ones shorter than the selector.
    #[test]
    fn snappy_reader_handles_short_and_random_input() {
        snappy_reader(&[]);
        snappy_reader(&[0]);
        snappy_reader(&[0, 0]);
        // Every selector combination over one small body.
        let body = b"\xff\x06\x00\x00sNaPpY\x01\x05\x00\x00\x00\x00\x00\x00x";
        for sel in 0..=255u8 {
            for read_buf in [0u8, 1, 33, 0xFF] {
                let mut data = vec![sel, read_buf];
                data.extend_from_slice(body);
                snappy_reader(&data);
            }
        }
        // A deterministic pseudo-random stream.
        let mut x = 0x1234_5678_9abc_def0u64;
        let mut data = vec![0u8; 4096];
        for b in &mut data {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (x >> 33) as u8;
        }
        for start in [0usize, 7, 123, 1000] {
            snappy_reader(&data[start..]);
        }
    }

    /// The selector encoding round-trips.
    #[test]
    fn selector_round_trips() {
        for identifier in [false, true] {
            for chunk in [0u8, 1, 64, 0x7f] {
                for read_buf in [0u8, 7, 255] {
                    let [sel, rb] = Selector::encode(identifier, chunk, read_buf);
                    let s = Selector::decode(sel, rb);
                    assert_eq!(s.identifier, identifier);
                    assert_eq!(s.chunk, (chunk != 0).then(|| usize::from(chunk)));
                    assert_eq!(s.read_buf, usize::from(read_buf) + 1);
                }
            }
        }
    }

    /// Writes the seed corpus into the source tree:
    /// `cargo test -p kcptun-std --lib write_snappy_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore = "writes the fuzz seed corpus into the source tree"]
    fn write_snappy_fuzz_seeds() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/snappy_reader");
        if dir.exists() {
            std::fs::remove_dir_all(&dir).expect("remove old seeds");
        }
        std::fs::create_dir_all(&dir).expect("create seed dir");
        for (name, data) in snappy_reader_handcrafted_seeds() {
            std::fs::write(dir.join(format!("hand_{name}")), data).expect("write seed");
        }
    }

    /// The committed seed corpus (`crates/std/fuzz/seeds/snappy_reader/`) is exactly what
    /// [`write_snappy_fuzz_seeds`] generates. The files are read at test time on purpose (this
    /// checks the on-disk corpus that libFuzzer reads, not embedded test data).
    #[test]
    fn snappy_fuzz_seed_files_up_to_date() {
        const HINT: &str = "snappy_reader fuzz seeds are stale; regenerate them with \
            `cargo test -p kcptun-std --lib write_snappy_fuzz_seeds -- --ignored`";
        let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        // Test executables also run outside the source tree (tools/lab/remote-test.sh).
        if !crate_dir.join("Cargo.toml").exists() {
            eprintln!("snappy_fuzz_seed_files_up_to_date: source tree not available, skipping");
            return;
        }
        let dir = crate_dir.join("fuzz/seeds/snappy_reader");
        let want: std::collections::BTreeMap<String, Vec<u8>> = snappy_reader_handcrafted_seeds()
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
