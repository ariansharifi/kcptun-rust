//! Tests for [`validate_qpp_params`](super::validate_qpp_params) and
//! [`QppStream`](super::QppStream) (plan step 07.3).
//!
//! The Go cross-check against `gointerop/qppcheck` lives in
//! `crates/interop-tests/tests/qpp.rs`; everything here is self-contained, including the two
//! round trips over a real in-memory smux session pair (protocol versions 1 and 2) and the
//! deviation V04 half-close.

use std::sync::Arc;
use std::time::Duration;

use kcptun_qpp::{QuantumPermutationPad, create_prng};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::*;
use crate::smuxio::SmuxStream;
use crate::smuxio::tests::{HalfCloseWriteExt, session_pair, stream_pair};

/// The key kcptun ships as the default; shorter than `QPPMinimumSeedLength(8)`, as most are.
const KEY: &str = "it's a secrect";

/// A 211-byte key, the shortest one `validate_qpp_params` does not warn about.
fn long_key() -> String {
    "k".repeat(211)
}

fn pad(count: u16) -> Arc<QuantumPermutationPad> {
    Arc::new(QuantumPermutationPad::new(KEY.as_bytes(), count))
}

/// The bytes `QppStream` should put on the wire for `data`, computed with the raw pad API.
fn expected_cipher(count: u16, data: &[u8]) -> Vec<u8> {
    let qpp = QuantumPermutationPad::new(KEY.as_bytes(), count);
    let mut prng = create_prng(KEY.as_bytes());
    let mut out = data.to_vec();
    qpp.encrypt_with_prng(&mut out, &mut prng);
    out
}

// ---------------------------------------------------------------------------------------
// ValidateQPPParams
// ---------------------------------------------------------------------------------------

#[test]
fn validate_rejects_a_non_positive_count() {
    // Go: `fmt.Errorf("QPPCount must be greater than 0 when QPP is enabled")`, then log.Fatal.
    const FATAL: &str = "QPPCount must be greater than 0 when QPP is enabled";
    for count in [0i64, -1, i64::MIN] {
        assert_eq!(validate_qpp_params(count, &long_key()), Err(FATAL.into()));
    }
}

#[test]
fn validate_accepts_a_prime_count_and_a_long_key_without_warnings() {
    assert_eq!(validate_qpp_params(61, &long_key()), Ok(Vec::new()));
    assert_eq!(validate_qpp_params(7, &long_key()), Ok(Vec::new()));
}

#[test]
fn validate_warns_about_a_short_key() {
    // Go: "QPP Warning: 'key' has size of %d bytes, required %d bytes at least".
    assert_eq!(
        validate_qpp_params(61, KEY),
        Ok(vec![
            "QPP Warning: 'key' has size of 14 bytes, required 211 bytes at least".to_string()
        ])
    );
    // 210 bytes still warns, 211 does not: the boundary is `len(key) < minSeedLength`.
    assert_eq!(
        validate_qpp_params(61, &"k".repeat(210)),
        Ok(vec![
            "QPP Warning: 'key' has size of 210 bytes, required 211 bytes at least".to_string()
        ])
    );
}

#[test]
fn validate_counts_key_bytes_not_characters() {
    // Go's `len(key)` on a string is its byte length; so is Rust's `str::len`.
    let key = "é".repeat(200); // 400 bytes, 200 characters
    assert_eq!(validate_qpp_params(61, &key), Ok(Vec::new()));
}

#[test]
fn validate_warns_about_too_few_pads() {
    // Go: "QPP Warning: QPPCount %d, required %d at least" (QPPMinimumPads(8) == 7).
    assert_eq!(
        validate_qpp_params(5, &long_key()),
        Ok(vec![
            "QPP Warning: QPPCount 5, required 7 at least".to_string()
        ])
    );
}

#[test]
fn validate_warns_when_the_count_shares_a_factor_with_eight() {
    // Go: gcd(count, qppPower) != 1, i.e. every even count.
    assert_eq!(
        validate_qpp_params(64, &long_key()),
        Ok(vec![
            "QPP Warning: QPPCount 64, choose a prime number for security".to_string()
        ])
    );
    // 2 is prime but still shares the factor 2 with 8 — Go warns anyway.
    assert_eq!(
        validate_qpp_params(2, &long_key()),
        Ok(vec![
            "QPP Warning: QPPCount 2, required 7 at least".to_string(),
            "QPP Warning: QPPCount 2, choose a prime number for security".to_string(),
        ])
    );
}

#[test]
fn validate_returns_all_three_warnings_in_go_order() {
    assert_eq!(
        validate_qpp_params(4, KEY),
        Ok(vec![
            "QPP Warning: 'key' has size of 14 bytes, required 211 bytes at least".to_string(),
            "QPP Warning: QPPCount 4, required 7 at least".to_string(),
            "QPP Warning: QPPCount 4, choose a prime number for security".to_string(),
        ])
    );
}

#[test]
fn validate_accepts_counts_beyond_what_kcptun_can_use() {
    // Go checks `count` as an `int` and only the call site narrows it to `uint16`, so 65537 is
    // "valid" here and becomes pad count 1 in `NewQPP`. Worth pinning: step 09 must reject the
    // truncation itself (`uint16(65536) == 0` makes Go's NewQPP panic on the first Encrypt).
    assert_eq!(validate_qpp_params(65537, &long_key()), Ok(Vec::new()));
    assert_eq!(
        validate_qpp_params(65536, &long_key())
            .expect("valid")
            .len(),
        1
    );
}

// ---------------------------------------------------------------------------------------
// A writer that can stall and accept only part of a write
// ---------------------------------------------------------------------------------------

/// Collects everything written, one `max` bytes at a time, stalling first when asked.
///
/// Go's `QPPPort` hands the caller's already-encrypted buffer to `smux.Stream.Write`, which
/// never short-writes. A tokio `poll_write` may, so this stands in for the awkward connection
/// and proves the write PRNG advances exactly once per byte.
struct Sink {
    out: Vec<u8>,
    max: usize,
    stalls: usize,
    /// Once this many bytes have been taken, every further write fails.
    fail_after: usize,
}

impl Sink {
    fn new(max: usize, stalls: usize) -> Sink {
        Sink {
            out: Vec::new(),
            max,
            stalls,
            fail_after: usize::MAX,
        }
    }

    /// A connection that breaks after `after` bytes, like a peer that went away mid-stream.
    fn failing(after: usize) -> Sink {
        Sink {
            fail_after: after,
            ..Sink::new(usize::MAX, 0)
        }
    }
}

impl AsyncWrite for Sink {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if me.stalls > 0 {
            me.stalls -= 1;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if me.out.len() >= me.fail_after {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "broken pipe",
            )));
        }
        let n = buf.len().min(me.max);
        me.out.extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Writes `data` through a `QppStream` in `chunks`-sized pieces and returns the wire bytes.
async fn encrypt_through_stream(count: u16, data: &[u8], chunks: &[usize], sink: Sink) -> Vec<u8> {
    let mut stream = QppStream::new(sink, pad(count), KEY.as_bytes());
    let mut rest = data;
    let mut i = 0;
    while !rest.is_empty() {
        let n = chunks[i % chunks.len()].min(rest.len());
        stream.write_all(&rest[..n]).await.expect("write");
        rest = &rest[n..];
        i += 1;
    }
    stream.flush().await.expect("flush");
    stream.inner().out.clone()
}

// ---------------------------------------------------------------------------------------
// QppStream
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn the_wire_bytes_are_the_pad_applied_to_the_whole_stream() {
    let data: Vec<u8> = (0..9_000u32).map(|i| (i % 253) as u8).collect();
    let got = encrypt_through_stream(61, &data, &[9_000], Sink::new(usize::MAX, 0)).await;
    assert_eq!(got, expected_cipher(61, &data));
}

#[tokio::test]
async fn the_ciphertext_does_not_depend_on_the_write_chunking() {
    let data: Vec<u8> = (0..20_000u32)
        .map(|i| (i.wrapping_mul(7) % 251) as u8)
        .collect();
    let want = expected_cipher(61, &data);
    for chunks in [
        vec![20_000usize],
        vec![1],
        vec![7],
        vec![1, 2, 3, 5, 8, 13, 4096],
        vec![4096, 1, 65535],
    ] {
        let got = encrypt_through_stream(61, &data, &chunks, Sink::new(usize::MAX, 0)).await;
        assert_eq!(got, want, "chunks {chunks:?}");
    }
}

#[tokio::test]
async fn a_short_or_stalling_connection_does_not_desynchronise_the_write_prng() {
    let data: Vec<u8> = (0..5_000u32).map(|i| (i % 249) as u8).collect();
    let want = expected_cipher(7, &data);
    // One byte per `poll_write`, plus a few `Pending`s before the first one is accepted.
    let got = encrypt_through_stream(7, &data, &[64, 1, 999], Sink::new(1, 3)).await;
    assert_eq!(got, want);
}

#[tokio::test]
async fn an_empty_write_is_accepted_without_touching_the_prng() {
    let mut stream = QppStream::new(Sink::new(usize::MAX, 0), pad(61), KEY.as_bytes());
    assert_eq!(stream.write(b"").await.expect("empty write"), 0);
    stream.write_all(b"abc").await.expect("write");
    stream.flush().await.expect("flush");
    assert_eq!(stream.inner().out, expected_cipher(61, b"abc"));
}

#[tokio::test]
async fn a_write_error_reaches_the_caller() {
    // Go returns the connection's error straight from `QPPPort.Write`; the wrapper reports it
    // from the write that hit it rather than deferring it to the flush, which `pipe` discards.
    let mut stream = QppStream::new(Sink::failing(10), pad(61), KEY.as_bytes());
    stream.write_all(b"0123456789").await.expect("first write");
    let err = stream
        .write_all(b"0123456789")
        .await
        .expect_err("the connection is broken");
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(err.to_string(), "broken pipe");
}

#[tokio::test]
async fn reading_decrypts_what_arrived_whatever_the_read_sizes_are() {
    let data: Vec<u8> = (0..30_000u32).map(|i| (i % 255) as u8).collect();
    let cipher = expected_cipher(61, &data);

    for read_size in [1usize, 3, 1500, 65536] {
        let (mut ours, mut theirs) = tokio::io::duplex(1 << 20);
        let writer = tokio::spawn({
            let cipher = cipher.clone();
            async move {
                theirs.write_all(&cipher).await.expect("feed");
                theirs.shutdown().await.expect("shutdown");
            }
        });

        let mut stream = QppStream::new(&mut ours, pad(61), KEY.as_bytes());
        let mut got = Vec::new();
        let mut buf = vec![0u8; read_size];
        loop {
            let n = stream.read(&mut buf).await.expect("read");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        writer.await.expect("writer task");
        assert_eq!(got, data, "read_size {read_size}");
    }
}

/// Fills at most `chunk` bytes and then reports `Pending`. tokio's own readers never do this,
/// but `S` is any stream and [`pipe`](crate::pipe::pipe) deliberately keeps such bytes.
struct PartialPendingReader {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
}

impl AsyncRead for PartialPendingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if me.pos >= me.data.len() {
            return Poll::Ready(Ok(()));
        }
        let n = me.chunk.min(me.data.len() - me.pos).min(buf.remaining());
        buf.put_slice(&me.data[me.pos..me.pos + n]);
        me.pos += n;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// Go decrypts `p[:n]` before `return n, err`, so bytes that arrived with a non-`Ok` result are
/// still decrypted and the read PRNG still advances over them. Anything else would leave
/// ciphertext in the caller's buffer and put this side permanently out of step with the peer.
#[tokio::test]
async fn a_pending_read_that_filled_the_buffer_is_still_decrypted() {
    let data: Vec<u8> = (0..2_000u32).map(|i| (i % 251) as u8).collect();
    let mut stream = QppStream::new(
        PartialPendingReader {
            data: expected_cipher(61, &data),
            pos: 0,
            chunk: 7,
        },
        pad(61),
        KEY.as_bytes(),
    );

    let mut got = Vec::new();
    let mut raw = vec![0u8; 64];
    while got.len() < data.len() {
        // What `pipe` does with a `Pending` that filled the buffer: keep the bytes.
        let mut chunk = Vec::new();
        std::future::poll_fn(|cx| {
            let mut buf = ReadBuf::new(&mut raw);
            let poll = Pin::new(&mut stream).poll_read(cx, &mut buf);
            if !buf.filled().is_empty() {
                chunk.extend_from_slice(buf.filled());
                return Poll::Ready(());
            }
            poll.map(|r| r.expect("read"))
        })
        .await;
        assert!(!chunk.is_empty(), "the reader always delivers something");
        got.extend_from_slice(&chunk);
    }
    assert_eq!(got, data);
}

#[tokio::test]
async fn a_pair_of_wrappers_round_trips_over_a_duplex_pipe() {
    let (a, b) = tokio::io::duplex(1 << 16);
    let mut alice = QppStream::new(a, pad(61), KEY.as_bytes());
    let mut bob = QppStream::new(b, pad(61), KEY.as_bytes());

    let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 241) as u8).collect();
    let sent = payload.clone();
    let writer = tokio::spawn(async move {
        alice.write_all(&sent).await.expect("write");
        alice.flush().await.expect("flush");
        alice.shutdown().await.expect("shutdown");
    });

    let mut got = Vec::new();
    bob.read_to_end(&mut got).await.expect("read to end");
    writer.await.expect("writer task");
    assert_eq!(got, payload);
}

// ---------------------------------------------------------------------------------------
// Over a real smux session pair
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn round_trip_over_an_in_memory_smux_pair() {
    for version in [1isize, 2] {
        let (cli, srv) = session_pair(version);
        let (a, b) = stream_pair(&cli, &srv).await;
        let mut a = QppStream::new(a, pad(61), KEY.as_bytes());
        let mut b = QppStream::new(b, pad(61), KEY.as_bytes());

        // Mixed write sizes on purpose: smux reframes them, so the reader sees a different
        // chunking from the writer's and only the stream position may decide the pad.
        let payload: Vec<u8> = (0..70_000u32).map(|i| (i % 239) as u8).collect();
        let sent = payload.clone();
        let writer = tokio::spawn(async move {
            for chunk in sent.chunks(1).take(8) {
                a.write_all(chunk).await.expect("byte write");
            }
            a.write_all(&sent[8..]).await.expect("bulk write");
            a.flush().await.expect("flush");
            HalfCloseWriteExt::close_write(&mut a).await.expect("fin");
            a
        });

        let mut got = Vec::new();
        b.read_to_end(&mut got).await.expect("read to end");
        let _a = writer.await.expect("writer task");
        assert_eq!(got, payload, "version {version}");
    }
}

/// Deviation V04: forwarding `close_write` must leave the reverse direction intact.
///
/// Go's `QPPPort` has no `CloseWrite`, so `std.Pipe` closes the whole stream instead and the
/// answer that is still in flight can be lost. Here the half-close is one `cmdFIN`: the peer
/// sees the end of this side's data and keeps replying.
#[tokio::test]
async fn v04_a_half_close_keeps_the_reverse_direction_alive() {
    for version in [1isize, 2] {
        let (cli, srv) = session_pair(version);
        let (a, b) = stream_pair(&cli, &srv).await;
        let mut a = QppStream::new(a, pad(61), KEY.as_bytes());
        let mut b = QppStream::new(b, pad(61), KEY.as_bytes());

        a.write_all(b"GET / HTTP/1.0\r\n\r\n")
            .await
            .expect("request");
        a.flush().await.expect("flush");
        HalfCloseWriteExt::close_write(&mut a).await.expect("fin");

        // The peer reads the request to its end, exactly as a proxied server would.
        let mut request = Vec::new();
        b.read_to_end(&mut request).await.expect("read request");
        assert_eq!(request, b"GET / HTTP/1.0\r\n\r\n", "version {version}");

        // …and the answer still gets through, decrypted, after the half-close.
        let answer: Vec<u8> = (0..50_000u32).map(|i| (i % 233) as u8).collect();
        let sent = answer.clone();
        let responder = tokio::spawn(async move {
            b.write_all(&sent).await.expect("answer");
            b.flush().await.expect("flush");
            HalfCloseWriteExt::close_write(&mut b).await.expect("fin");
            b
        });

        let mut got = Vec::new();
        a.read_to_end(&mut got).await.expect("read answer");
        let _b = responder.await.expect("responder task");
        assert_eq!(got, answer, "version {version}");

        // Both directions have ended, so smux has already torn the stream down: Go's `dieOnce`
        // makes this second close report `io: read/write on closed pipe`, and `pipe` discards
        // the value exactly as Go discards `alice.Close()`'s error.
        match HalfCloseWriteExt::close(&mut a).await {
            Ok(()) => {}
            Err(e) => assert_eq!(e.to_string(), "io: read/write on closed pipe"),
        }
    }
}

#[tokio::test]
async fn the_wrapper_is_usable_as_a_pipe_endpoint() {
    // `pipe` needs `HalfCloseWrite + Unpin`; this is a compile-time check that the wrapped
    // smux stream satisfies it, which is what step 09 wires up.
    fn assert_pipe_endpoint<T: HalfCloseWrite + Unpin>() {}
    assert_pipe_endpoint::<QppStream<SmuxStream>>();
    assert_pipe_endpoint::<QppStream<tokio::net::TcpStream>>();
}

// ---------------------------------------------------------------------------------------
// Through the real `pipe`
// ---------------------------------------------------------------------------------------

/// One end of a [`tokio::io::duplex`] pair as a [`pipe`] endpoint, standing in for the TCP side
/// of a proxied connection.
struct DuplexEnd(DuplexStream);

impl AsyncRead for DuplexEnd {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for DuplexEnd {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl HalfCloseWrite for DuplexEnd {
    fn poll_close_write(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

/// Regression: a `poll_write` may never report bytes the connection has not taken.
///
/// `pipe` goes straight back to reading its source after a `Ready(Ok(n))`, and returns `Pending`
/// when the source has nothing — it never polls the destination again by itself. So if this
/// wrapper answered `Ok(buf.len())` while the ciphertext was still in `obuf`, the last chunk of a
/// transfer would sit there for as long as the source stayed quiet, which for a proxied request
/// is forever.
///
/// smux v2 with more than `INITIAL_PEER_WINDOW` (262144) bytes makes it deterministic:
/// `SmuxStream::poll_write` pends on the send task's oneshot (`write_frame_internal`) and
/// `write_v2` enqueues nothing at all once the peer window is exhausted.
#[tokio::test]
async fn the_pipe_delivers_the_last_chunk_when_the_source_goes_quiet() {
    let (cli, srv) = session_pair(2);
    let (a, b) = stream_pair(&cli, &srv).await;
    let qa = QppStream::new(a, pad(61), KEY.as_bytes());
    let mut qb = QppStream::new(b, pad(61), KEY.as_bytes());

    let (mut source, pipe_end) = tokio::io::duplex(1 << 20);
    let piped = tokio::spawn(async move { crate::pipe::pipe(DuplexEnd(pipe_end), qa, 0).await });

    let payload: Vec<u8> = (0..400_000u32).map(|i| (i % 251) as u8).collect();
    source.write_all(&payload).await.expect("feed the pipe");
    // `source` stays open and silent from here on: nothing but the pipe itself will drive the
    // destination again.

    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(20), qb.read_exact(&mut got))
        .await
        .expect("no byte may be stranded in the wrapper")
        .expect("read");
    assert_eq!(got, payload);

    // Wind both directions down so the pipe returns: EOF on the source, then EOF from the peer.
    drop(source);
    HalfCloseWriteExt::close_write(&mut qb).await.expect("fin");
    let (err_a, err_b) = tokio::time::timeout(Duration::from_secs(20), piped)
        .await
        .expect("the pipe ends")
        .expect("pipe task");
    err_a.expect("source -> smux");
    err_b.expect("smux -> source");
}

// ---------------------------------------------------------------------------------------
// The Go test
// ---------------------------------------------------------------------------------------

/// Go: kcptun/std/qpp_test.go:TestQPPPortRoundTrip — `net.Pipe()` becomes
/// [`tokio::io::duplex`]. The pad seed and the PRNG seed differ on purpose, which pins that
/// [`QppStream::new`] seeds the two [`Rand`]s from its `seed` argument and not from the pad.
#[tokio::test]
async fn test_qpp_port_round_trip() {
    let pad = Arc::new(QuantumPermutationPad::new(b"pad-seed", 16));
    let seed = b"session-seed";

    let (alice_conn, bob_conn) = tokio::io::duplex(1 << 16);
    let mut alice = QppStream::new(alice_conn, Arc::clone(&pad), seed);
    let mut bob = QppStream::new(bob_conn, Arc::clone(&pad), seed);

    // Go: t.Run("alice to bob", ...) then t.Run("bob to alice", ...).
    assert_round_trip(&mut alice, &mut bob, b"encrypted hello").await;
    assert_round_trip(&mut bob, &mut alice, b"reply payload").await;
}

/// Go: kcptun/std/qpp_test.go:assertRoundTrip.
async fn assert_round_trip<W, R>(writer: &mut W, reader: &mut R, payload: &[u8])
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    writer.write_all(payload).await.expect("write failed");
    writer.flush().await.expect("flush");
    let mut buf = vec![0u8; payload.len()];
    reader
        .read_exact(&mut buf)
        .await
        .expect("read encrypted payload");
    assert_eq!(buf, payload, "payload mismatch");
}
