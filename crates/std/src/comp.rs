//! kcptun's `CompStream`: the **framed** snappy stream that wraps the KCP session below smux
//! (plan step 07.1, `docs/WIRE-FORMAT.md` §6). `-nocomp` turns it off.
//!
//! Go builds it from `snappy.NewBufferedWriter` / `snappy.NewReader` and flushes after every
//! `Write`, so one smux frame becomes one snappy chunk (two for a frame longer than 64 KiB).
//! The framing is implemented here on top of `snap::raw::{Encoder, Decoder}` (DECISIONS D09):
//! `snap`'s own `write::FrameEncoder` buffers internally, is synchronous and would neither
//! reproduce Go's per-write chunking nor fit the async I/O this port uses. The block codec —
//! everything after the chunk header — is `snap`'s; it produces the same bytes as
//! `golang/snappy`, which `vectors_snappy_*` and `interop_snappy_*` check.
//!
//! ```text
//! stream identifier (once, first): ff 06 00 00 73 4e 61 50 70 59      ("sNaPpY")
//! chunk: type u8 | length u24 LE | body
//!   0x00 compressed   : masked_crc32c(uncompressed) u32 LE | snappy block
//!   0x01 uncompressed : masked_crc32c(data) u32 LE | data
//!   0x80-0xfd         : skippable
//!   0x02-0x7f         : reserved, unskippable -> "snappy: unsupported input"
//! ```
//!
//! Go: `kcptun/std/comp.go:CompStream`, `golang/snappy@v1.0.0 encode.go` (`Writer`),
//! `decode.go` (`Reader`) and `snappy.go` (constants, `crc`).

use std::io;
use std::net::SocketAddr;

use kcptun_smux::SmuxConn;
use tokio::sync::Mutex;

// Go: golang/snappy@v1.0.0 snappy.go:magicChunk / magicBody
/// The stream identifier chunk, written once before the first data chunk.
pub(crate) const MAGIC_CHUNK: &[u8] = b"\xff\x06\x00\x00sNaPpY";
/// The body of the stream identifier chunk.
const MAGIC_BODY: &[u8] = b"sNaPpY";

// Go: golang/snappy@v1.0.0 snappy.go:checksumSize / chunkHeaderSize
/// Size of the masked CRC-32C that precedes a chunk body.
const CHECKSUM_SIZE: usize = 4;
/// Size of the per-chunk header (type byte plus 24-bit length).
const CHUNK_HEADER_SIZE: usize = 4;

// Go: golang/snappy@v1.0.0 snappy.go:maxBlockSize
/// Largest amount of uncompressed data in one chunk, from the framing format spec.
const MAX_BLOCK_SIZE: usize = 65536;

// Go: golang/snappy@v1.0.0 snappy.go:maxEncodedLenOfMaxBlockSize
/// `MaxEncodedLen(MAX_BLOCK_SIZE)`, hard-coded as in Go so the buffer sizes are constants.
const MAX_ENCODED_LEN_OF_MAX_BLOCK_SIZE: usize = 76490;

// Go: golang/snappy@v1.0.0 snappy.go:obufHeaderLen / obufLen
/// Bytes the writer reserves in front of a chunk body: the stream identifier plus the chunk
/// header and checksum.
const OBUF_HEADER_LEN: usize = MAGIC_CHUNK.len() + CHECKSUM_SIZE + CHUNK_HEADER_SIZE;
/// Size of the writer's output buffer.
const OBUF_LEN: usize = OBUF_HEADER_LEN + MAX_ENCODED_LEN_OF_MAX_BLOCK_SIZE;

// Go: golang/snappy@v1.0.0 decode.go:NewReader() (`buf` and `decoded` sizes)
/// Size of the reader's chunk buffer; also the largest chunk length it accepts.
const RBUF_LEN: usize = MAX_ENCODED_LEN_OF_MAX_BLOCK_SIZE + CHECKSUM_SIZE;

// Go: golang/snappy@v1.0.0 snappy.go:chunkType*
/// Chunk type 0x00: the body is a snappy block.
const CHUNK_TYPE_COMPRESSED_DATA: u8 = 0x00;
/// Chunk type 0x01: the body is stored as it is.
const CHUNK_TYPE_UNCOMPRESSED_DATA: u8 = 0x01;
/// Chunk type 0xff: the stream identifier.
const CHUNK_TYPE_STREAM_IDENTIFIER: u8 = 0xff;
/// Chunk types up to this one are reserved and must not be skipped.
const CHUNK_TYPE_MAX_UNSKIPPABLE: u8 = 0x7f;

/// Masked CRC-32C of `b`, section 3 of the framing format.
///
/// Castagnoli, **not** the IEEE CRC-32 of the KCP packet layer.
// Go: golang/snappy@v1.0.0 snappy.go:crc()
fn crc(b: &[u8]) -> u32 {
    // Go writes the rotation as `uint32(c>>15|c<<17)`.
    crc32c::crc32c(b).rotate_right(15).wrapping_add(0xa282_ead8)
}

/// The errors `golang/snappy` reports, with its exact texts (porting guide §4).
// Go: golang/snappy@v1.0.0 decode.go:ErrCorrupt / ErrTooLarge / ErrUnsupported /
// errUnsupportedLiteralLength
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The input is not a valid framed stream (`ErrCorrupt`).
    #[error("snappy: corrupt input")]
    Corrupt,
    /// A block claims to decode to more than a machine word can address (`ErrTooLarge`).
    ///
    /// Go only reaches this on a 32-bit build (`decodedLen` checks `wordSize == 32`); it is kept
    /// so the error set is complete.
    #[error("snappy: decoded block is too large")]
    TooLarge,
    /// A chunk this version cannot handle (`ErrUnsupported`): a reserved unskippable chunk type,
    /// or a chunk longer than the reader's buffer.
    #[error("snappy: unsupported input")]
    Unsupported,
    /// A literal whose length does not fit in an `int` (`errUnsupportedLiteralLength`).
    ///
    /// Never produced by this port, on any target: `snap` reports a single corrupt-block error
    /// for every malformed block, so [`decode_error`] can only return [`Error::Corrupt`]. Go
    /// reaches it only on a 32-bit build, where `length = int(x) + 1` with `x = 0xffffffff`
    /// becomes exactly `0` and its test is `length <= 0`; such a chunk is reported here as
    /// "snappy: corrupt input" instead. The variant is kept so the error set is Go's.
    #[error("snappy: unsupported literal length")]
    UnsupportedLiteralLength,
}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}

/// What a snappy reader or writer remembers after it has failed.
///
/// Go keeps the `error` value itself in `Reader.err` / `Writer.err` and returns it from every
/// later call. An `io::Error` is not `Clone`, so an I/O failure is remembered as its kind and
/// text, which is what a caller sees; the original `source()` is lost.
#[derive(Clone, Debug)]
enum Sticky {
    /// The stream ended cleanly at a chunk boundary (Go's `io.EOF`).
    Eof,
    /// A snappy-level error.
    Snappy(Error),
    /// The connection below failed.
    Io(io::ErrorKind, String),
}

impl Sticky {
    /// The `io::Error` this state hands to a caller. [`Sticky::Eof`] has none: it is reported as
    /// `Ok(0)`, the Rust spelling of `io.EOF`.
    fn to_io(&self) -> io::Error {
        match self {
            // Only reached through `read`, which turns Eof into Ok(0) before calling this.
            Sticky::Eof => io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"),
            Sticky::Snappy(e) => (*e).into(),
            Sticky::Io(kind, msg) => io::Error::new(*kind, msg.clone()),
        }
    }

    /// Remembers `e` without consuming it, so the same error can also be returned.
    fn of_io(e: &io::Error) -> Sticky {
        Sticky::Io(e.kind(), e.to_string())
    }
}

impl From<io::Error> for Sticky {
    fn from(e: io::Error) -> Sticky {
        Sticky::Io(e.kind(), e.to_string())
    }
}

impl From<Error> for Sticky {
    fn from(e: Error) -> Sticky {
        Sticky::Snappy(e)
    }
}

/// The write half: `snappy.Writer` as `NewBufferedWriter` builds it, with Go's `Write` and
/// `Flush` collapsed into one pass (see [`CompStream::write_chunks`]).
// Go: golang/snappy@v1.0.0 encode.go:Writer
struct Writer {
    /// Buffer for the outgoing bytes: stream identifier, chunk header and body.
    obuf: Vec<u8>,
    /// Gather buffer for [`SmuxConn::write_all_vectored`], reused across calls.
    ibuf: Vec<u8>,
    /// Whether the stream identifier has been written.
    wrote_stream_header: bool,
    /// The block compressor.
    encoder: snap::raw::Encoder,
    /// Set once a write has failed; every later write reports it again.
    err: Option<Sticky>,
}

/// The read half: `snappy.Reader` and its chunk state machine.
// Go: golang/snappy@v1.0.0 decode.go:Reader
struct Reader {
    /// Bytes decoded from the current chunk; `decoded[i..j]` has not been handed out yet.
    decoded: Vec<u8>,
    /// Chunk buffer; its length is also the largest chunk the reader accepts.
    buf: Vec<u8>,
    /// Start of the undelivered bytes in `decoded`.
    i: usize,
    /// End of the undelivered bytes in `decoded`.
    j: usize,
    /// Whether the stream identifier chunk has been seen (it must come first).
    read_header: bool,
    /// Set once the stream has failed or ended; every later read reports it again.
    err: Option<Sticky>,
    /// The block decompressor.
    decoder: snap::raw::Decoder,
}

/// A [`SmuxConn`] that compresses everything written to it and decompresses everything read
/// from it, in Go's framed snappy format.
///
/// kcptun puts it between smux and the KCP session, so `conn` is the KCP session and the
/// smux frames are its payload.
// Go: kcptun/std/comp.go:CompStream
pub struct CompStream<C> {
    /// The connection the framed stream runs over.
    conn: C,
    /// Write state. The smux send task is the only writer, exactly as in Go.
    w: Mutex<Writer>,
    /// Read state. The smux receive task is the only reader.
    r: Mutex<Reader>,
}

impl<C: SmuxConn> CompStream<C> {
    // Go: kcptun/std/comp.go:NewCompStream()
    /// Wraps `conn`. Nothing is written until the first [`write_all`](SmuxConn::write_all): Go's
    /// buffered writer emits the stream identifier together with the first chunk.
    pub fn new(conn: C) -> CompStream<C> {
        CompStream {
            conn,
            w: Mutex::new(Writer {
                obuf: vec![0; OBUF_LEN],
                ibuf: Vec::new(),
                wrote_stream_header: false,
                encoder: snap::raw::Encoder::new(),
                err: None,
            }),
            r: Mutex::new(Reader {
                decoded: vec![0; MAX_BLOCK_SIZE],
                buf: vec![0; RBUF_LEN],
                i: 0,
                j: 0,
                read_header: false,
                err: None,
                decoder: snap::raw::Decoder::new(),
            }),
        }
    }

    /// The connection below the compression.
    pub fn inner(&self) -> &C {
        &self.conn
    }

    /// Splits `p` into chunks of at most 64 KiB and writes each one to the connection.
    ///
    /// This is Go's `Writer.Write` plus the `Flush` that `CompStream.Write` always calls right
    /// after it. Because `CompStream` flushes after every write, Go's input buffer is empty
    /// whenever `Write` is entered, so `Write` either copies `p` into it and flushes it
    /// (`len(p) <= 65536`) or hands the whole of `p` to `write` (which chunks it the same way):
    /// both paths produce the chunks this loop produces, for the same bytes.
    ///
    /// **Deviation from Go's call pattern (not from its bytes):** Go writes an uncompressed
    /// chunk with two `Write` calls on the connection — the header from `obuf`, then the
    /// caller's slice — while this copies the body into `obuf` and issues one write per chunk,
    /// as the plan asks. The KCP session below is a byte stream in stream mode, so the bytes on
    /// the wire are the same; only the number of `Write` calls differs.
    // Go: golang/snappy@v1.0.0 encode.go:Writer.write() / Writer.Write() / Writer.Flush()
    async fn write_chunks(&self, w: &mut Writer, mut p: &[u8]) -> io::Result<()> {
        if let Some(err) = &w.err {
            return Err(err.to_io());
        }
        while !p.is_empty() {
            // The stream identifier goes out with the first chunk, from the same buffer.
            let mut obuf_start = MAGIC_CHUNK.len();
            if !w.wrote_stream_header {
                w.wrote_stream_header = true;
                w.obuf[..MAGIC_CHUNK.len()].copy_from_slice(MAGIC_CHUNK);
                obuf_start = 0;
            }

            let n = p.len().min(MAX_BLOCK_SIZE);
            let (uncompressed, rest) = p.split_at(n);
            p = rest;
            let checksum = crc(uncompressed);

            // Compress, and discard the result unless it saves at least 12.5%.
            let compressed_len = match w
                .encoder
                .compress(uncompressed, &mut w.obuf[OBUF_HEADER_LEN..])
            {
                Ok(len) => len,
                // Unreachable: obuf holds max_compress_len(MAX_BLOCK_SIZE) bytes and a chunk is
                // never longer than that. Reported rather than asserted (porting guide §5).
                Err(e) => {
                    let err = io::Error::other(format!("snappy: compress: {e}"));
                    w.err = Some(Sticky::of_io(&err));
                    return Err(err);
                }
            };
            let (chunk_type, chunk_len, obuf_end) = if compressed_len >= n - n / 8 {
                w.obuf[OBUF_HEADER_LEN..OBUF_HEADER_LEN + n].copy_from_slice(uncompressed);
                (
                    CHUNK_TYPE_UNCOMPRESSED_DATA,
                    CHECKSUM_SIZE + n,
                    OBUF_HEADER_LEN + n,
                )
            } else {
                (
                    CHUNK_TYPE_COMPRESSED_DATA,
                    CHECKSUM_SIZE + compressed_len,
                    OBUF_HEADER_LEN + compressed_len,
                )
            };

            // The per-chunk header, right in front of the body.
            let h = MAGIC_CHUNK.len();
            w.obuf[h] = chunk_type;
            w.obuf[h + 1] = chunk_len as u8;
            w.obuf[h + 2] = (chunk_len >> 8) as u8;
            w.obuf[h + 3] = (chunk_len >> 16) as u8;
            w.obuf[h + 4..h + 8].copy_from_slice(&checksum.to_le_bytes());

            if let Err(e) = self.conn.write_all(&w.obuf[obuf_start..obuf_end]).await {
                w.err = Some(Sticky::of_io(&e));
                return Err(e);
            }
        }
        Ok(())
    }

    /// Decodes chunks until `decoded[i..j]` holds bytes to hand out, or the stream ends.
    // Go: golang/snappy@v1.0.0 decode.go:Reader.fill()
    async fn fill(&self, r: &mut Reader) -> Result<(), Sticky> {
        while r.i >= r.j {
            read_full(&self.conn, &mut r.buf[..CHUNK_HEADER_SIZE], true).await?;
            let chunk_type = r.buf[0];
            if !r.read_header {
                if chunk_type != CHUNK_TYPE_STREAM_IDENTIFIER {
                    return Err(Error::Corrupt.into());
                }
                r.read_header = true;
            }
            let chunk_len = usize::from(r.buf[1])
                | (usize::from(r.buf[2]) << 8)
                | (usize::from(r.buf[3]) << 16);
            if chunk_len > r.buf.len() {
                return Err(Error::Unsupported.into());
            }

            match chunk_type {
                // Section 4.2. Compressed data (chunk type 0x00).
                CHUNK_TYPE_COMPRESSED_DATA => {
                    if chunk_len < CHECKSUM_SIZE {
                        return Err(Error::Corrupt.into());
                    }
                    read_full(&self.conn, &mut r.buf[..chunk_len], false).await?;
                    let checksum = u32::from_le_bytes([r.buf[0], r.buf[1], r.buf[2], r.buf[3]]);
                    let block = CHECKSUM_SIZE..chunk_len;

                    let (n, header_len) = decoded_len(&r.buf[block.clone()])?;
                    if n > r.decoded.len() {
                        return Err(Error::Corrupt.into());
                    }
                    // Go parses the block's length header itself and hands the rest to `decode`;
                    // `snap` parses it again and, unlike Go's `binary.Uvarint`, refuses a
                    // non-canonical varint of more than five bytes. Writing the canonical
                    // encoding into the tail of the header region (it is never longer than the
                    // one that is there, so the block body is not touched) makes both read the
                    // same length and keeps Go's acceptance rule.
                    let mut varint = [0u8; MAX_VARINT_LEN64];
                    let canonical = put_uvarint(&mut varint, n as u64);
                    let start = block.start + header_len - canonical;
                    r.buf[start..start + canonical].copy_from_slice(&varint[..canonical]);
                    r.decoder
                        .decompress(&r.buf[start..block.end], &mut r.decoded[..n])
                        .map_err(decode_error)?;
                    if crc(&r.decoded[..n]) != checksum {
                        return Err(Error::Corrupt.into());
                    }
                    r.i = 0;
                    r.j = n;
                }

                // Section 4.3. Uncompressed data (chunk type 0x01).
                CHUNK_TYPE_UNCOMPRESSED_DATA => {
                    if chunk_len < CHECKSUM_SIZE {
                        return Err(Error::Corrupt.into());
                    }
                    read_full(&self.conn, &mut r.buf[..CHECKSUM_SIZE], false).await?;
                    let checksum = u32::from_le_bytes([r.buf[0], r.buf[1], r.buf[2], r.buf[3]]);
                    // Read straight into `decoded` rather than through `buf`.
                    let n = chunk_len - CHECKSUM_SIZE;
                    if n > r.decoded.len() {
                        return Err(Error::Corrupt.into());
                    }
                    read_full(&self.conn, &mut r.decoded[..n], false).await?;
                    if crc(&r.decoded[..n]) != checksum {
                        return Err(Error::Corrupt.into());
                    }
                    r.i = 0;
                    r.j = n;
                }

                // Section 4.1. Stream identifier (chunk type 0xff).
                CHUNK_TYPE_STREAM_IDENTIFIER => {
                    if chunk_len != MAGIC_BODY.len() {
                        return Err(Error::Corrupt.into());
                    }
                    read_full(&self.conn, &mut r.buf[..MAGIC_BODY.len()], false).await?;
                    if &r.buf[..MAGIC_BODY.len()] != MAGIC_BODY {
                        return Err(Error::Corrupt.into());
                    }
                }

                // Section 4.5. Reserved unskippable chunks (chunk types 0x02-0x7f).
                _ if chunk_type <= CHUNK_TYPE_MAX_UNSKIPPABLE => {
                    return Err(Error::Unsupported.into());
                }

                // Section 4.4. Padding (chunk type 0xfe) and section 4.6, reserved skippable
                // chunks (chunk types 0x80-0xfd).
                _ => read_full(&self.conn, &mut r.buf[..chunk_len], false).await?,
            }
        }
        Ok(())
    }
}

/// Fills `buf` from `conn`.
///
/// Go's `Reader.readFull`: a stream that ends exactly at a chunk boundary is the end of the
/// data when `allow_eof` is set ([`Sticky::Eof`], which [`CompStream::read`] reports as `Ok(0)`),
/// and corrupt input otherwise. A stream that ends in the middle of `buf` is always corrupt
/// input (Go's `io.ErrUnexpectedEOF`).
// Go: golang/snappy@v1.0.0 decode.go:Reader.readFull()
async fn read_full<C: SmuxConn>(conn: &C, buf: &mut [u8], allow_eof: bool) -> Result<(), Sticky> {
    // io.ReadFull never reads, and never fails, for an empty buffer.
    let mut got = 0;
    while got < buf.len() {
        match conn.read(&mut buf[got..]).await {
            Ok(0) if got == 0 && allow_eof => return Err(Sticky::Eof),
            Ok(0) => return Err(Error::Corrupt.into()),
            Ok(n) => got += n,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Length of the block `src` decodes to and the number of bytes its length header used, with
/// the errors Go's `decodedLen` reports.
// Go: golang/snappy@v1.0.0 decode.go:decodedLen()
fn decoded_len(src: &[u8]) -> Result<(usize, usize), Error> {
    let (v, n) = uvarint(src);
    if n <= 0 || v > 0xffff_ffff {
        return Err(Error::Corrupt);
    }
    // Go's `wordSize == 32` branch. On a 64-bit target this is dead code, as it is in Go.
    if usize::BITS == 32 && v > 0x7fff_ffff {
        return Err(Error::TooLarge);
    }
    Ok((v as usize, n as usize))
}

/// Go's `binary.MaxVarintLen64`: the most bytes a `uint64` varint can take.
// Go: go1.27.1 src/encoding/binary/varint.go:MaxVarintLen64
const MAX_VARINT_LEN64: usize = 10;

/// Writes `v` as a varint into `dst` and returns how many bytes it used. `dst` must hold
/// [`MAX_VARINT_LEN64`] bytes.
// Go: go1.27.1 src/encoding/binary/varint.go:PutUvarint()
fn put_uvarint(dst: &mut [u8; MAX_VARINT_LEN64], mut v: u64) -> usize {
    let mut i = 0;
    while v >= 0x80 {
        dst[i] = (v as u8) | 0x80;
        v >>= 7;
        i += 1;
    }
    dst[i] = v as u8;
    i + 1
}

/// Go's `binary.Uvarint`: the value and the number of bytes it used, `0` when `src` is too
/// short and a negative count when the value overflows 64 bits.
// Go: go1.27.1 src/encoding/binary/varint.go:Uvarint()
fn uvarint(src: &[u8]) -> (u64, isize) {
    let mut x: u64 = 0;
    let mut s: u32 = 0;
    for (i, &b) in src.iter().enumerate() {
        if i == MAX_VARINT_LEN64 {
            return (0, -((i as isize) + 1)); // overflow
        }
        if b < 0x80 {
            if i == MAX_VARINT_LEN64 - 1 && b > 1 {
                return (0, -((i as isize) + 1)); // overflow
            }
            return (x | (u64::from(b) << s), (i as isize) + 1);
        }
        x |= u64::from(b & 0x7f) << s;
        s += 7;
    }
    (0, 0)
}

/// Maps a `snap` block-decoder failure onto the error Go's `Decode` would return.
///
/// `snap` reports a single corrupt-block error, so every failure maps to [`Error::Corrupt`]:
/// a truncated literal or copy, an offset before the start of the output, a length that does
/// not fill the announced output. That is what Go returns too on a 64-bit build, where its
/// other failure code ([`Error::UnsupportedLiteralLength`]) is unreachable. On a 32-bit build
/// Go can report "snappy: unsupported literal length" for a `0xffffffff` literal tag where this
/// port reports "snappy: corrupt input"; the text is log-only and the session fails either way.
// Go: golang/snappy@v1.0.0 decode.go:Decode() / decode_other.go:decode()
fn decode_error(_e: snap::Error) -> Error {
    Error::Corrupt
}

/// The `SmuxConn` shape of Go's `CompStream`: `Read`, `Write` and `Close` are the compressed
/// stream's, the addresses are the inner connection's.
///
/// `write_all_vectored` gathers the slices and writes them as one `Write`, which is what smux's
/// `sendLoop` does for a connection without `WriteBuffers` — and `CompStream` has none, so a
/// header and its payload always end up in the same snappy chunk.
// Go: kcptun/std/comp.go:CompStream (net.Conn)
impl<C: SmuxConn> SmuxConn for CompStream<C> {
    // Go: kcptun/std/comp.go:CompStream.Read() -> golang/snappy decode.go:Reader.Read()
    async fn read(&self, p: &mut [u8]) -> io::Result<usize> {
        let mut r = self.r.lock().await;
        if let Some(err) = &r.err {
            return match err {
                Sticky::Eof => Ok(0),
                other => Err(other.to_io()),
            };
        }
        if let Err(e) = self.fill(&mut r).await {
            let out = match &e {
                Sticky::Eof => Ok(0),
                other => Err(other.to_io()),
            };
            r.err = Some(e);
            return out;
        }

        let n = p.len().min(r.j - r.i);
        p[..n].copy_from_slice(&r.decoded[r.i..r.i + n]);
        r.i += n;
        Ok(n)
    }

    // Go: kcptun/std/comp.go:CompStream.Write()
    async fn write_all(&self, p: &[u8]) -> io::Result<()> {
        let mut w = self.w.lock().await;
        self.write_chunks(&mut w, p).await
    }

    // Go: smux@v1.5.55 session.go:sendLoop() (the copy + single Write branch)
    async fn write_all_vectored(&self, bufs: &[&[u8]]) -> io::Result<usize> {
        let total: usize = bufs.iter().map(|b| b.len()).sum();
        let mut w = self.w.lock().await;
        // Taken out of the writer so the gather buffer and `obuf` can be borrowed at once; it
        // goes back before returning, so the allocation is reused by the next frame.
        let mut ibuf = std::mem::take(&mut w.ibuf);
        ibuf.clear();
        ibuf.reserve(total);
        for b in bufs {
            ibuf.extend_from_slice(b);
        }
        let result = self.write_chunks(&mut w, &ibuf).await;
        w.ibuf = ibuf;
        result.map(|()| total)
    }

    // Go: kcptun/std/comp.go:CompStream.Close()
    async fn close(&self) -> io::Result<()> {
        self.conn.close().await
    }

    // Go: kcptun/std/comp.go:CompStream.LocalAddr()
    fn local_addr(&self) -> Option<SocketAddr> {
        self.conn.local_addr()
    }

    // Go: kcptun/std/comp.go:CompStream.RemoteAddr()
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.conn.remote_addr()
    }
}

#[cfg(test)]
#[path = "comp_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "comp_vector_tests.rs"]
mod vector_tests;
