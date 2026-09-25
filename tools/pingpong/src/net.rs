//! The framed transfers both ends of [`crate::proto`] perform.
//!
//! Everything here is generic over `AsyncBufRead`/`AsyncWrite`, so the server loop and the
//! client request path are exercised by ordinary in-process tests as well as over the tunnel.
//!
//! Two properties matter for a six-hour run and are enforced here rather than left to the
//! caller: every read is **bounded** (a header can never grow past [`proto::MAX_HEADER`], a
//! payload never past the byte count its header named), and every buffer is **reused** (one
//! 64 KiB scratch per connection, never a per-request allocation).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{
    AsyncBufRead, AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWrite,
    AsyncWriteExt as _, BufReader,
};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::proto::{self, MAX_HEADER, Request};
use crate::rng::SplitMix64;

/// Size of the per-connection scratch and payload buffers.
pub const CHUNK: usize = 64 * 1024;

/// Reads one header line, without its trailing newline.
///
/// `Ok(None)` means the peer closed cleanly between requests, which is how a connection ends.
pub async fn read_header<R>(reader: &mut R) -> io::Result<Option<String>>
where
    R: AsyncBufRead + Unpin,
{
    let mut line: Vec<u8> = Vec::with_capacity(MAX_HEADER);
    loop {
        // Never copy more than the header limit out of the buffer, so a peer that sends
        // megabytes without a newline costs one comparison per byte and nothing else.
        let (used, complete) = {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                if line.is_empty() {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "eof inside a request header",
                ));
            }
            let room = MAX_HEADER.saturating_sub(line.len()).max(1);
            let window = &available[..available.len().min(room)];
            match window.iter().position(|&b| b == b'\n') {
                Some(i) => {
                    line.extend_from_slice(&window[..=i]);
                    (i + 1, true)
                }
                None => {
                    line.extend_from_slice(window);
                    (window.len(), false)
                }
            }
        };
        reader.consume(used);
        if complete {
            break;
        }
        if line.len() >= MAX_HEADER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("request header longer than {MAX_HEADER} bytes"),
            ));
        }
    }
    let text = String::from_utf8(line)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "request header is not utf-8"))?;
    Ok(Some(text.trim_end_matches(['\r', '\n']).to_string()))
}

/// Reads exactly `n` bytes and throws them away.
pub async fn drain_exact<R>(reader: &mut R, n: u64, scratch: &mut [u8]) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    if scratch.is_empty() {
        return Err(io::Error::other("empty scratch buffer"));
    }
    let mut left = n;
    while left > 0 {
        let want = usize::try_from(left)
            .unwrap_or(scratch.len())
            .min(scratch.len());
        reader.read_exact(&mut scratch[..want]).await?;
        left -= want as u64;
    }
    Ok(())
}

/// Reads exactly `n` bytes, optionally checking them against `expected` (repeated as needed).
pub async fn read_exact_checked<R>(
    reader: &mut R,
    n: u64,
    scratch: &mut [u8],
    expected: Option<&[u8]>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let Some(expected) = expected else {
        return drain_exact(reader, n, scratch).await;
    };
    if expected.is_empty() || scratch.is_empty() {
        return drain_exact(reader, n, scratch).await;
    }
    let mut done = 0u64;
    while done < n {
        let left = n - done;
        let want = usize::try_from(left)
            .unwrap_or(scratch.len())
            .min(scratch.len());
        reader.read_exact(&mut scratch[..want]).await?;
        for (i, got) in scratch[..want].iter().enumerate() {
            let offset = usize::try_from((done + i as u64) % expected.len() as u64).unwrap_or(0);
            if *got != expected[offset] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("payload differs at byte {}", done + i as u64),
                ));
            }
        }
        done += want as u64;
    }
    Ok(())
}

/// Writes exactly `n` bytes, cycling through `payload`.
pub async fn write_exact<W>(writer: &mut W, n: u64, payload: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if payload.is_empty() {
        return Err(io::Error::other("empty payload buffer"));
    }
    let mut left = n;
    let mut offset = 0usize;
    while left > 0 {
        let want = usize::try_from(left)
            .unwrap_or(payload.len())
            .min(payload.len() - offset);
        writer.write_all(&payload[offset..offset + want]).await?;
        left -= want as u64;
        offset = (offset + want) % payload.len();
    }
    Ok(())
}

/// Copies exactly `n` bytes from `reader` to `writer` (the server's `ECHO`).
pub async fn copy_exact<R, W>(
    reader: &mut R,
    writer: &mut W,
    n: u64,
    scratch: &mut [u8],
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if scratch.is_empty() {
        return Err(io::Error::other("empty scratch buffer"));
    }
    let mut left = n;
    while left > 0 {
        let want = usize::try_from(left)
            .unwrap_or(scratch.len())
            .min(scratch.len());
        reader.read_exact(&mut scratch[..want]).await?;
        writer.write_all(&scratch[..want]).await?;
        left -= want as u64;
    }
    Ok(())
}

/// Serves one connection until the peer closes it or something goes wrong.
///
/// `payload` is the shared buffer a `DN` transfer is written from — shared, because the churn
/// workload has hundreds of connections open at once and a per-connection copy of it cost the
/// target 125 MB of RSS in the first lab run of this code. Only `scratch_len` bytes are
/// allocated per connection, for the bytes that arrive.
///
/// `idle` bounds how long the connection may sit **between** requests, never how long a
/// transfer may take, so a long-lived stream that echoes once every five seconds is safe while
/// a peer that vanished without a FIN — a real possibility when the tunnel under test is being
/// restarted or blackholed — cannot hold a file descriptor for the rest of a six-hour run.
pub async fn serve_connection<R, W>(
    reader: &mut R,
    writer: &mut W,
    payload: &[u8],
    scratch_len: usize,
    idle: Option<Duration>,
) -> io::Result<u64>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut scratch = vec![0u8; scratch_len.max(4096)];
    let mut served = 0u64;
    loop {
        let next = match idle {
            None => read_header(reader).await?,
            Some(limit) => match tokio::time::timeout(limit, read_header(reader)).await {
                Ok(result) => result?,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("idle for more than {limit:?} between requests"),
                    ));
                }
            },
        };
        let Some(line) = next else { break };
        let request = proto::parse_request(&line)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        match request {
            Request::Echo(n) => copy_exact(reader, writer, n, &mut scratch).await?,
            Request::Up(n) => {
                drain_exact(reader, n, &mut scratch).await?;
                writer.write_all(proto::ack(n).as_bytes()).await?;
            }
            Request::Down(n) => write_exact(writer, n, payload).await?,
        }
        writer.flush().await?;
        served += 1;
    }
    Ok(served)
}

/// Performs one request from the client side.
///
/// When `verify` is set, an `ECHO` reply is compared byte for byte with what was sent — the
/// tunnel is supposed to be lossless, and a soak that silently corrupted a stream would
/// otherwise look healthy.
pub async fn request<R, W>(
    reader: &mut R,
    writer: &mut W,
    req: Request,
    payload: &[u8],
    scratch: &mut [u8],
    verify: bool,
) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    writer.write_all(req.header().as_bytes()).await?;
    if req.payload_out() > 0 {
        write_exact(writer, req.payload_out(), payload).await?;
    }
    writer.flush().await?;
    match req {
        Request::Echo(n) => {
            let expected = if verify { Some(payload) } else { None };
            read_exact_checked(reader, n, scratch, expected).await?;
        }
        Request::Down(n) => drain_exact(reader, n, scratch).await?,
        Request::Up(n) => {
            let line = read_header(reader)
                .await?
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no ack"))?;
            let acked = proto::parse_ack(&line)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if acked != n {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("ack says {acked} bytes, sent {n}"),
                ));
            }
        }
    }
    Ok(())
}

/// One client connection, with the buffers its requests reuse.
///
/// The payload is shared (`Arc`): it is written, never read back, so every connection in a
/// churn run points at the same 64 KiB of pseudo-random bytes instead of holding its own. Only
/// the scratch buffer, which received bytes land in, is per connection.
#[derive(Debug)]
pub struct Client {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    payload: Arc<Vec<u8>>,
    scratch: Vec<u8>,
}

impl Client {
    /// Connects, disables Nagle and sizes the buffers.
    ///
    /// `TCP_NODELAY` is not a nicety here: a 64-byte pingpong measured through a Nagle-delayed
    /// socket would report the delayed-ACK timer instead of the tunnel's latency.
    pub async fn connect(
        addr: SocketAddr,
        payload: Arc<Vec<u8>>,
        scratch_len: usize,
    ) -> io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        let (reader, writer) = stream.into_split();
        Ok(Self {
            reader: BufReader::with_capacity(scratch_len.max(4096), reader),
            writer,
            payload,
            scratch: vec![0u8; scratch_len.max(4096)],
        })
    }

    /// Performs one request and returns how long it took.
    pub async fn request(&mut self, req: Request, verify: bool) -> io::Result<Duration> {
        let started = Instant::now();
        request(
            &mut self.reader,
            &mut self.writer,
            req,
            &self.payload,
            &mut self.scratch,
            verify,
        )
        .await?;
        Ok(started.elapsed())
    }
}

/// A shared buffer of pseudo-random bytes for every client of one run to write from.
pub fn shared_payload(seed: u64, len: usize) -> Arc<Vec<u8>> {
    let mut payload = vec![0u8; len.max(1)];
    SplitMix64::new(seed).fill(&mut payload);
    Arc::new(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn echo_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (r, mut w) = stream.into_split();
                    let mut r = BufReader::with_capacity(CHUNK, r);
                    let payload = shared_payload(99, 8192);
                    let _ = serve_connection(&mut r, &mut w, &payload, 8192, None).await;
                });
            }
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn every_verb_round_trips_over_a_real_socket() {
        let (addr, server) = echo_server().await;
        let stream = TcpStream::connect(addr).await.expect("connect");
        let (r, mut w) = stream.into_split();
        let mut r = BufReader::with_capacity(CHUNK, r);
        let mut payload = vec![0u8; CHUNK];
        SplitMix64::new(1).fill(&mut payload);
        let mut scratch = vec![0u8; CHUNK];

        for req in [
            Request::Echo(64),
            Request::Echo(0),
            Request::Up(200_000),
            Request::Down(200_000),
            Request::Echo(200_000),
        ] {
            request(&mut r, &mut w, req, &payload, &mut scratch, true)
                .await
                .unwrap_or_else(|e| panic!("{req:?}: {e}"));
        }
        drop(w);
        server.abort();
    }

    #[tokio::test]
    async fn the_client_helper_reuses_one_connection_for_many_requests() {
        let (addr, server) = echo_server().await;
        let payload = shared_payload(5, 8192);
        let mut client = Client::connect(addr, payload, 8192).await.expect("connect");
        let mut total = Duration::ZERO;
        for _ in 0..16 {
            total += client.request(Request::Echo(64), true).await.expect("echo");
        }
        assert!(total > Duration::ZERO, "requests must take measurable time");
        server.abort();
    }

    #[tokio::test]
    async fn a_closed_connection_between_requests_is_not_an_error() {
        let mut reader = BufReader::new(&b""[..]);
        let mut sink: Vec<u8> = Vec::new();
        let payload = shared_payload(0, 4096);
        assert_eq!(
            serve_connection(&mut reader, &mut sink, &payload, 4096, None)
                .await
                .ok(),
            Some(0)
        );
    }

    #[tokio::test]
    async fn an_oversized_header_is_refused_instead_of_buffered() {
        let junk = vec![b'A'; 4096];
        let mut reader = BufReader::new(&junk[..]);
        let err = read_header(&mut reader).await.expect_err("must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn a_truncated_header_reports_eof() {
        let mut reader = BufReader::new(&b"ECHO 4"[..]);
        let err = read_header(&mut reader).await.expect_err("must fail");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_connection_is_dropped_once_the_limit_passes() {
        let (client, server) = tokio::io::duplex(1024);
        let serving = tokio::spawn(async move {
            let (r, mut w) = tokio::io::split(server);
            let mut r = BufReader::new(r);
            let payload = shared_payload(0, 4096);
            serve_connection(
                &mut r,
                &mut w,
                &payload,
                4096,
                Some(Duration::from_secs(30)),
            )
            .await
        });
        // Hold the connection open without sending anything.
        tokio::time::sleep(Duration::from_secs(90)).await;
        let err = serving
            .await
            .expect("task")
            .expect_err("the idle limit must fire");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        drop(client);
    }

    #[tokio::test]
    async fn an_unknown_verb_ends_the_connection_with_invalid_data() {
        let mut reader = BufReader::new(&b"NOPE 1\n"[..]);
        let mut sink: Vec<u8> = Vec::new();
        let payload = shared_payload(0, 4096);
        let err = serve_connection(&mut reader, &mut sink, &payload, 4096, None)
            .await
            .expect_err("must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn verification_catches_a_corrupted_echo() {
        let payload = vec![7u8; 16];
        let wrong = [8u8; 16];
        let mut reader = BufReader::new(&wrong[..]);
        let mut scratch = vec![0u8; 64];
        let err = read_exact_checked(&mut reader, 16, &mut scratch, Some(&payload))
            .await
            .expect_err("must fail");
        assert!(
            err.to_string().contains("payload differs at byte 0"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn write_exact_cycles_through_the_payload_buffer() {
        let payload = [1u8, 2, 3];
        let mut out: Vec<u8> = Vec::new();
        write_exact(&mut out, 7, &payload).await.expect("write");
        assert_eq!(out, vec![1, 2, 3, 1, 2, 3, 1]);
        assert!(write_exact(&mut out, 1, &[]).await.is_err());
    }
}
