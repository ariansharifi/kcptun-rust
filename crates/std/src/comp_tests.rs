//! Unit and property tests for [`CompStream`](super::CompStream) (plan step 07.1).
//!
//! The golden comparison against Go's bytes is in `comp_vector_tests.rs`; this file covers the
//! framing rules, the reader's error paths and a round trip over an in-memory pair.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use kcptun_smux::SmuxConn;
use proptest::prelude::*;

use super::*;

/// A connection that replays a fixed byte string and records everything written to it.
///
/// `read_size` bounds how much one `read` hands out, so the reader's `readFull` loop is
/// exercised; `writes` keeps the calls apart, which is how the chunking is checked.
pub(super) struct MemConn {
    to_read: Mutex<VecDeque<u8>>,
    read_size: usize,
    writes: Mutex<Vec<Vec<u8>>>,
    closes: AtomicUsize,
    /// When set, every write fails with this error kind.
    write_error: Option<io::ErrorKind>,
}

impl MemConn {
    /// A connection with nothing to read.
    fn new() -> MemConn {
        MemConn::with_data(Vec::new(), usize::MAX)
    }

    /// A connection that replays `data`, at most `read_size` bytes per read.
    fn with_data(data: Vec<u8>, read_size: usize) -> MemConn {
        MemConn {
            to_read: Mutex::new(data.into()),
            read_size: read_size.max(1),
            writes: Mutex::new(Vec::new()),
            closes: AtomicUsize::new(0),
            write_error: None,
        }
    }

    /// A connection whose writes always fail.
    fn failing() -> MemConn {
        MemConn {
            write_error: Some(io::ErrorKind::BrokenPipe),
            ..MemConn::new()
        }
    }

    /// Everything written so far, concatenated.
    fn bytes(&self) -> Vec<u8> {
        self.writes().concat()
    }

    /// The individual `write_all` calls, in order.
    fn writes(&self) -> Vec<Vec<u8>> {
        self.writes.lock().expect("lock").clone()
    }
}

impl SmuxConn for MemConn {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut data = self.to_read.lock().expect("lock");
        let n = buf.len().min(data.len()).min(self.read_size);
        for (i, b) in data.drain(..n).enumerate() {
            buf[i] = b;
        }
        Ok(n)
    }

    async fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        if let Some(kind) = self.write_error {
            return Err(io::Error::new(kind, "broken pipe"));
        }
        self.writes.lock().expect("lock").push(buf.to_vec());
        Ok(())
    }

    async fn close(&self) -> io::Result<()> {
        self.closes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        Some("127.0.0.1:1".parse().expect("addr"))
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some("127.0.0.1:2".parse().expect("addr"))
    }
}

/// Framed bytes for the given writes, as a `CompStream` produces them.
pub(super) fn encode(writes: &[&[u8]]) -> Vec<u8> {
    encode_calls(writes).concat()
}

/// The same, but keeping the individual writes to the connection apart.
pub(super) fn encode_calls(writes: &[&[u8]]) -> Vec<Vec<u8>> {
    runtime().block_on(async {
        let stream = CompStream::new(MemConn::new());
        for w in writes {
            stream.write_all(w).await.expect("write");
        }
        stream.inner().writes()
    })
}

/// Decodes `framed`, handing the reader at most `read_size` bytes per read and asking for at
/// most `read_buf` bytes at a time.
pub(super) fn decode(framed: &[u8], read_size: usize, read_buf: usize) -> io::Result<Vec<u8>> {
    runtime().block_on(async {
        let stream = CompStream::new(MemConn::with_data(framed.to_vec(), read_size));
        let mut out = Vec::new();
        let mut buf = vec![0u8; read_buf.max(1)];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Ok(out);
            }
            out.extend_from_slice(&buf[..n]);
        }
    })
}

/// Decodes `framed`, returning the bytes delivered before the stream ended, and the text of
/// the error it ended with (`None` for a clean end of stream). This is what Go's `io.Copy` over
/// a `snappy.Reader` reports, which is how the golden read vectors were recorded.
pub(super) fn decode_partial(framed: &[u8], read_buf: usize) -> (Vec<u8>, Option<String>) {
    decode_partial_sizes(framed, usize::MAX, read_buf)
}

/// [`decode_partial`] with a bound on how much one inner read hands out.
pub(super) fn decode_partial_sizes(
    framed: &[u8],
    read_size: usize,
    read_buf: usize,
) -> (Vec<u8>, Option<String>) {
    runtime().block_on(async {
        let stream = CompStream::new(MemConn::with_data(framed.to_vec(), read_size));
        let mut out = Vec::new();
        let mut buf = vec![0u8; read_buf.max(1)];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => return (out, None),
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) => return (out, Some(e.to_string())),
            }
        }
    })
}

/// A current-thread runtime: nothing here waits for another task.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

/// `len` bytes of highly compressible text.
pub(super) fn text(len: usize) -> Vec<u8> {
    b"the quick brown fox jumps over the lazy dog. "
        .iter()
        .copied()
        .cycle()
        .take(len)
        .collect()
}

/// `len` bytes that snappy cannot compress (a 64-bit xorshift, so the test needs no RNG crate).
pub(super) fn random(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// One framed chunk with the given type and body (no checksum is added).
fn chunk(chunk_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![
        chunk_type,
        body.len() as u8,
        (body.len() >> 8) as u8,
        (body.len() >> 16) as u8,
    ];
    out.extend_from_slice(body);
    out
}

/// An uncompressed data chunk holding `data`, with a correct checksum.
fn uncompressed_chunk(data: &[u8]) -> Vec<u8> {
    let mut body = crc(data).to_le_bytes().to_vec();
    body.extend_from_slice(data);
    chunk(CHUNK_TYPE_UNCOMPRESSED_DATA, &body)
}

/// The stream identifier chunk.
fn identifier() -> Vec<u8> {
    MAGIC_CHUNK.to_vec()
}

/// The error text of a failed decode.
fn decode_err(framed: &[u8]) -> String {
    decode(framed, usize::MAX, 4096)
        .expect_err("decode should fail")
        .to_string()
}

// The masked CRC-32C is Castagnoli, not the IEEE CRC-32 of the KCP layer. CRC-32C("abc") is
// 0x364b3fb7 (the framing-format specification's example), and Go's mask
// `uint32(c>>15|c<<17) + 0xa282ead8` turns it into 0x21f1576e.
#[test]
fn masked_crc32c_matches_the_specification() {
    assert_eq!(crc32c::crc32c(b"abc"), 0x364b_3fb7);
    assert_eq!(crc(b"abc"), 0x21f1_576e);
    // The empty string has CRC-32C 0, so only the mask constant is left.
    assert_eq!(crc(b""), 0xa282_ead8);
}

// Go's `binary.Uvarint`, including the two overflow branches and the short-buffer case.
#[test]
fn uvarint_matches_go() {
    assert_eq!(uvarint(&[]), (0, 0));
    assert_eq!(uvarint(&[0x00]), (0, 1));
    assert_eq!(uvarint(&[0x7f]), (127, 1));
    assert_eq!(uvarint(&[0x80, 0x01]), (128, 2));
    assert_eq!(uvarint(&[0x80]), (0, 0)); // truncated
    assert_eq!(uvarint(&[0xff; 10]), (0, 0)); // 10 continuation bytes: the value is unfinished
    assert_eq!(uvarint(&[0xff; 11]), (0, -11)); // an 11th byte cannot belong to a uint64
    assert_eq!(
        uvarint(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02]),
        (0, -10) // value does not fit in 64 bits
    );
    assert_eq!(
        uvarint(&[0xff, 0xff, 0xff, 0xff, 0x0f]),
        (u64::from(u32::MAX), 5)
    );
}

// An empty write produces no bytes at all — not even the stream identifier. Go's
// `Writer.Write(nil)` buffers nothing and `Flush` returns early on an empty buffer.
#[tokio::test]
async fn an_empty_write_sends_nothing() {
    let stream = CompStream::new(MemConn::new());
    stream.write_all(&[]).await.expect("write");
    assert!(stream.inner().bytes().is_empty());
    assert_eq!(stream.inner().writes().len(), 0);

    // ... and the identifier still comes with the first real chunk.
    stream.write_all(b"hello").await.expect("write");
    assert_eq!(&stream.inner().bytes()[..MAGIC_CHUNK.len()], MAGIC_CHUNK);
}

// The identifier is part of the first chunk's write, and never repeated.
#[test]
fn the_stream_identifier_is_written_once_with_the_first_chunk() {
    let calls = encode_calls(&[b"first", b"second"]);
    assert_eq!(calls.len(), 2, "one write per chunk");
    assert!(calls[0].starts_with(MAGIC_CHUNK));
    assert!(!calls[1].starts_with(MAGIC_CHUNK));
    assert_eq!(calls[0].len(), MAGIC_CHUNK.len() + 4 + 4 + 5);
}

// Text compresses by far more than 12.5%, so it becomes a compressed chunk; random bytes do
// not, so they are stored as they are.
#[test]
fn the_chunk_type_follows_gos_12_5_percent_rule() {
    let compressible = text(4096);
    let out = encode(&[&compressible]);
    assert_eq!(out[MAGIC_CHUNK.len()], CHUNK_TYPE_COMPRESSED_DATA);
    assert!(out.len() < compressible.len() / 2, "len {}", out.len());

    let incompressible = random(4096, 7);
    let out = encode(&[&incompressible]);
    assert_eq!(out[MAGIC_CHUNK.len()], CHUNK_TYPE_UNCOMPRESSED_DATA);
    assert_eq!(out.len(), MAGIC_CHUNK.len() + 4 + 4 + incompressible.len());
    assert!(out.ends_with(&incompressible));

    // A single byte can never be compressed to less than 1 - 1/8 = 0 bytes.
    let out = encode(&[b"x"]);
    assert_eq!(out[MAGIC_CHUNK.len()], CHUNK_TYPE_UNCOMPRESSED_DATA);
}

// One write is split into 64 KiB chunks, each with its own connection write, and the chunk
// boundary falls exactly at 65536 bytes.
#[test]
fn a_write_longer_than_64_kib_is_split_into_chunks() {
    let payload = random(70000, 3);
    let calls = encode_calls(&[&payload]);
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[0].len(),
        MAGIC_CHUNK.len() + 4 + 4 + MAX_BLOCK_SIZE,
        "first chunk carries the identifier and a full block"
    );
    assert_eq!(calls[1].len(), 4 + 4 + (70000 - MAX_BLOCK_SIZE));
    assert_eq!(calls[1][0], CHUNK_TYPE_UNCOMPRESSED_DATA);

    // Exactly 65536 bytes still fit in one chunk (Go buffers them and flushes one block).
    let calls = encode_calls(&[&random(MAX_BLOCK_SIZE, 4)]);
    assert_eq!(calls.len(), 1);

    // One byte more needs two.
    let calls = encode_calls(&[&random(MAX_BLOCK_SIZE + 1, 5)]);
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].len(), 4 + 4 + 1);
}

// `write_all_vectored` must behave exactly like one `write_all` of the concatenation: smux's
// `sendLoop` has no `WriteBuffers` on a `CompStream`, so a header and its payload always land
// in the same chunk.
#[test]
fn a_vectored_write_becomes_one_chunk() {
    let header = random(8, 11);
    let payload = text(8184);
    let mut joined = header.clone();
    joined.extend_from_slice(&payload);
    let want = encode(&[&joined]);

    let got = runtime().block_on(async {
        let stream = CompStream::new(MemConn::new());
        let n = stream
            .write_all_vectored(&[&header, &payload])
            .await
            .expect("write");
        assert_eq!(n, header.len() + payload.len());
        assert_eq!(stream.inner().writes().len(), 1);
        stream.inner().bytes()
    });
    assert_eq!(got, want);
}

// A failed write is remembered: Go's `Writer.err` makes every later `Write` and `Flush` fail
// with the same error, including an empty one.
#[tokio::test]
async fn a_write_error_is_sticky() {
    let stream = CompStream::new(MemConn::failing());
    let err = stream.write_all(b"data").await.expect_err("write fails");
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    let err = stream.write_all(b"more").await.expect_err("still fails");
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    let err = stream
        .write_all(&[])
        .await
        .expect_err("even an empty write");
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
}

// Whatever the stream writes, it reads back — across chunk boundaries, with the reader fed in
// small pieces and asked for small pieces.
#[test]
fn a_stream_round_trips_through_the_reader() {
    for (read_size, read_buf) in [(usize::MAX, 65536), (1, 1), (7, 13), (4096, 100000)] {
        let payloads = [text(0), text(1), text(9000), random(70000, 9), text(65536)];
        let refs: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
        let framed = encode(&refs);
        let got = decode(&framed, read_size, read_buf).expect("decode");
        assert_eq!(got, payloads.concat(), "read_size={read_size}");
    }
}

// An empty framed stream is a clean end of data, not an error: `fill` is allowed to see EOF
// before the identifier.
#[test]
fn an_empty_stream_reads_as_eof() {
    assert_eq!(
        decode(&[], usize::MAX, 64).expect("decode"),
        Vec::<u8>::new()
    );
    assert_eq!(
        decode(&identifier(), usize::MAX, 64).expect("decode"),
        Vec::<u8>::new()
    );
}

// The stream identifier must come first (`ErrCorrupt`), even when the chunk that comes instead
// is well formed.
#[test]
fn the_identifier_must_come_first() {
    assert_eq!(
        decode_err(&uncompressed_chunk(b"data")),
        "snappy: corrupt input"
    );
    // A skippable chunk first is not allowed either.
    assert_eq!(decode_err(&chunk(0x80, b"pad")), "snappy: corrupt input");
}

// The identifier chunk itself is validated: length and body.
#[test]
fn a_damaged_identifier_is_corrupt_input() {
    assert_eq!(decode_err(&chunk(0xff, b"sNaPp")), "snappy: corrupt input");
    assert_eq!(decode_err(&chunk(0xff, b"snappy")), "snappy: corrupt input");
    assert_eq!(
        decode_err(&chunk(0xff, b"sNaPpY!")),
        "snappy: corrupt input"
    );
    assert_eq!(decode_err(&[0xff, 0x06, 0x00]), "snappy: corrupt input");
}

// Reserved unskippable chunk types (0x02-0x7f) end the stream with `ErrUnsupported`, while
// skippable ones (0x80-0xfd, and the padding type 0xfe) are ignored.
#[test]
fn reserved_chunks_are_rejected_and_skippable_ones_are_skipped() {
    for chunk_type in [0x02u8, 0x40, 0x7f] {
        let mut framed = identifier();
        framed.extend_from_slice(&chunk(chunk_type, b"body"));
        assert_eq!(decode_err(&framed), "snappy: unsupported input");
    }

    for chunk_type in [0x80u8, 0xfe, 0xfd] {
        let mut framed = identifier();
        framed.extend_from_slice(&chunk(chunk_type, &random(1000, 2)));
        framed.extend_from_slice(&uncompressed_chunk(b"payload"));
        assert_eq!(
            decode(&framed, 3, 64).expect("decode"),
            b"payload",
            "chunk type {chunk_type:#x}"
        );
    }
}

// A chunk longer than the reader's buffer is `ErrUnsupported`, whatever its type.
#[test]
fn an_over_long_chunk_is_unsupported() {
    let too_long = RBUF_LEN + 1;
    for chunk_type in [
        CHUNK_TYPE_COMPRESSED_DATA,
        CHUNK_TYPE_UNCOMPRESSED_DATA,
        0x80,
    ] {
        let mut framed = identifier();
        framed.extend_from_slice(&[
            chunk_type,
            too_long as u8,
            (too_long >> 8) as u8,
            (too_long >> 16) as u8,
        ]);
        assert_eq!(decode_err(&framed), "snappy: unsupported input");
    }
}

// A body that does not match its checksum, and a chunk too short to hold one.
#[test]
fn a_bad_checksum_is_corrupt_input() {
    let mut framed = identifier();
    let mut bad = uncompressed_chunk(b"payload");
    bad[4] ^= 0xff; // first checksum byte
    framed.extend_from_slice(&bad);
    assert_eq!(decode_err(&framed), "snappy: corrupt input");

    // The same for a compressed chunk: flip a byte of the compressed body.
    let mut framed = encode(&[&text(4096)]);
    let last = framed.len() - 1;
    framed[last] ^= 0xff;
    assert_eq!(decode_err(&framed), "snappy: corrupt input");

    // A data chunk shorter than the checksum it must contain.
    for chunk_type in [CHUNK_TYPE_COMPRESSED_DATA, CHUNK_TYPE_UNCOMPRESSED_DATA] {
        let mut framed = identifier();
        framed.extend_from_slice(&chunk(chunk_type, b"abc"));
        assert_eq!(decode_err(&framed), "snappy: corrupt input");
    }
}

// A stream that stops in the middle of a chunk is corrupt input, not a clean end.
#[test]
fn a_truncated_stream_is_corrupt_input() {
    let framed = encode(&[&text(4096)]);
    for cut in [
        MAGIC_CHUNK.len() + 2,
        MAGIC_CHUNK.len() + 4,
        framed.len() - 1,
    ] {
        assert_eq!(decode_err(&framed[..cut]), "snappy: corrupt input");
    }
    // Truncated inside an uncompressed body.
    let framed = encode(&[&random(64, 1)]);
    assert_eq!(
        decode_err(&framed[..framed.len() - 8]),
        "snappy: corrupt input"
    );
}

// A compressed chunk whose block is not decodable, and one that claims to decode to more than
// 64 KiB.
#[test]
fn a_damaged_block_is_rejected() {
    // Empty block: Go's `DecodedLen` fails on an empty buffer.
    let mut framed = identifier();
    framed.extend_from_slice(&chunk(CHUNK_TYPE_COMPRESSED_DATA, &crc(b"").to_le_bytes()));
    assert_eq!(decode_err(&framed), "snappy: corrupt input");

    // A varint length above 64 KiB: rejected before the block is decoded.
    let mut body = crc(b"").to_le_bytes().to_vec();
    body.extend_from_slice(&[0x81, 0x80, 0x04]); // 65537
    let mut framed = identifier();
    framed.extend_from_slice(&chunk(CHUNK_TYPE_COMPRESSED_DATA, &body));
    assert_eq!(decode_err(&framed), "snappy: corrupt input");

    // A well-formed length whose block ends too early: a literal that promises ten bytes and
    // has two (Go: the `x > uint32(len(src)-s)` check in decode_other.go).
    let mut body = crc(b"").to_le_bytes().to_vec();
    body.extend_from_slice(&[0x0a, 0x24, b'a', b'b']); // 10 bytes announced, 2 literal bytes
    let mut framed = identifier();
    framed.extend_from_slice(&chunk(CHUNK_TYPE_COMPRESSED_DATA, &body));
    assert_eq!(decode_err(&framed), "snappy: corrupt input");

    // A block that decodes to fewer bytes than its header promises.
    let mut body = crc(b"").to_le_bytes().to_vec();
    body.extend_from_slice(&[0x0a, 0x04, b'a', b'b']); // 10 announced, one 2-byte literal
    let mut framed = identifier();
    framed.extend_from_slice(&chunk(CHUNK_TYPE_COMPRESSED_DATA, &body));
    assert_eq!(decode_err(&framed), "snappy: corrupt input");
}

// An uncompressed chunk longer than the 64 KiB a block may decode to is corrupt input (it fits
// in the chunk buffer, so it is not the "unsupported" branch).
#[test]
fn an_uncompressed_chunk_over_64_kib_is_corrupt_input() {
    let n = MAX_BLOCK_SIZE + 1;
    let len = n + CHECKSUM_SIZE;
    let mut framed = identifier();
    framed.extend_from_slice(&[
        CHUNK_TYPE_UNCOMPRESSED_DATA,
        len as u8,
        (len >> 8) as u8,
        (len >> 16) as u8,
    ]);
    framed.extend_from_slice(&crc(&vec![0u8; n]).to_le_bytes());
    framed.extend_from_slice(&vec![0u8; n]);
    assert_eq!(decode_err(&framed), "snappy: corrupt input");
}

// Once the reader has failed, every later read reports the same error, and a clean end of
// stream keeps reporting the end.
#[test]
fn reader_errors_and_eof_are_sticky() {
    let good = encode(&[b"hi"]);
    runtime().block_on(async {
        let mut framed = identifier();
        framed.extend_from_slice(&chunk(0x02, b""));
        let stream = CompStream::new(MemConn::with_data(framed, usize::MAX));
        let mut buf = [0u8; 64];
        for _ in 0..3 {
            let err = stream.read(&mut buf).await.expect_err("unsupported");
            assert_eq!(err.to_string(), "snappy: unsupported input");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }

        let stream = CompStream::new(MemConn::with_data(good, usize::MAX));
        assert_eq!(stream.read(&mut buf).await.expect("read"), 2);
        for _ in 0..3 {
            assert_eq!(stream.read(&mut buf).await.expect("eof"), 0);
        }
    });
}

// `Close` and the addresses are the inner connection's (Go's `CompStream` delegates them).
#[tokio::test]
async fn close_and_addresses_are_delegated() {
    let stream = CompStream::new(MemConn::new());
    stream.close().await.expect("close");
    assert_eq!(stream.inner().closes.load(Ordering::Relaxed), 1);
    assert_eq!(stream.local_addr(), "127.0.0.1:1".parse().ok());
    assert_eq!(stream.remote_addr(), "127.0.0.1:2".parse().ok());
}

proptest! {
    // Any sequence of writes comes back as the concatenation of the writes, whatever the read
    // sizes are: the reader must serve decoded bytes across reads and across chunks.
    #[test]
    fn prop_comp_stream_round_trips(
        writes in proptest::collection::vec(
            prop_oneof![
                proptest::collection::vec(any::<u8>(), 0..2048),
                proptest::collection::vec(0u8..4, 0..70000),
            ],
            0..6,
        ),
        read_size in 1usize..8192,
        read_buf in 1usize..8192,
    ) {
        let refs: Vec<&[u8]> = writes.iter().map(Vec::as_slice).collect();
        let framed = encode(&refs);
        let got = decode(&framed, read_size, read_buf).expect("decode");
        prop_assert_eq!(got, writes.concat());
    }

    // The reader never panics on arbitrary input, and once it fails it stays failed. (The
    // `snappy_reader` fuzz target does the same with coverage feedback.)
    #[test]
    fn prop_reader_survives_arbitrary_input(
        framed in prop_oneof![
            proptest::collection::vec(any::<u8>(), 0..512),
            proptest::collection::vec(0u8..4, 0..512),
        ],
        read_size in 1usize..64,
    ) {
        let mut framed = framed;
        // Half the inputs start with a valid identifier, so the chunk loop is reached.
        if framed.first().is_some_and(|b| b % 2 == 0) {
            let mut with_header = MAGIC_CHUNK.to_vec();
            with_header.append(&mut framed);
            framed = with_header;
        }
        let _ = decode(&framed, read_size, 97);
    }
}
