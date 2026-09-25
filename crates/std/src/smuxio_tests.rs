//! Tests for the smux → tokio adapter (plan step 07.3; the piece plan step 08.5 left for the
//! proxy). They run a real smux session pair over [`tokio::io::duplex`].

use std::time::Duration;

use kcptun_smux::conn::SplitConn;
use kcptun_smux::{Config, Session, client, default_config, server};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::*;

/// Enough capacity that the tests never deadlock on the in-memory pipe.
const PIPE_CAPACITY: usize = 1 << 20;

/// A config with keepalive off, so a slow test cannot time the session out.
pub(crate) fn test_config(version: isize) -> Config {
    Config {
        version,
        keep_alive_disabled: true,
        keep_alive_interval: Duration::from_secs(10),
        keep_alive_timeout: Duration::from_secs(30),
        ..default_config()
    }
}

/// A connected smux pair over an in-memory duplex pipe.
pub(crate) fn session_pair(
    version: isize,
) -> (
    Session<SplitConn<DuplexStream>>,
    Session<SplitConn<DuplexStream>>,
) {
    let (a, b) = tokio::io::duplex(PIPE_CAPACITY);
    let cli = client(SplitConn::new(a), Some(test_config(version))).expect("client session");
    let srv = server(SplitConn::new(b), Some(test_config(version))).expect("server session");
    (cli, srv)
}

/// An opened/accepted stream pair, already wrapped for tokio.
pub(crate) async fn stream_pair(
    cli: &Session<SplitConn<DuplexStream>>,
    srv: &Session<SplitConn<DuplexStream>>,
) -> (SmuxStream, SmuxStream) {
    let opened = cli.open_stream().await.expect("open");
    // v1 sends no frame on open, so nudge the peer into accepting.
    opened.write(b"\x00").await.expect("hello");
    let accepted = srv.accept_stream().await.expect("accept");
    let mut hello = [0u8; 1];
    let mut accepted = SmuxStream::new(accepted);
    accepted.read_exact(&mut hello).await.expect("hello read");
    assert_eq!(hello, [0u8]);
    (SmuxStream::new(opened), accepted)
}

#[tokio::test]
async fn round_trip_over_a_smux_pair() {
    for version in [1isize, 2] {
        let (cli, srv) = session_pair(version);
        let (mut a, mut b) = stream_pair(&cli, &srv).await;

        let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        a.write_all(&payload).await.expect("write");
        a.flush().await.expect("flush");

        let mut got = vec![0u8; payload.len()];
        b.read_exact(&mut got).await.expect("read");
        assert_eq!(got, payload, "version {version}");
    }
}

#[tokio::test]
async fn a_half_close_ends_the_peer_read_without_closing_the_stream() {
    let (cli, srv) = session_pair(1);
    let (mut a, mut b) = stream_pair(&cli, &srv).await;

    a.write_all(b"question").await.expect("write");
    a.flush().await.expect("flush");
    HalfCloseWriteExt::close_write(&mut a).await.expect("fin");

    let mut got = Vec::new();
    b.read_to_end(&mut got).await.expect("read to end");
    assert_eq!(got, b"question");

    // The reverse direction is still open.
    b.write_all(b"answer").await.expect("reverse write");
    b.flush().await.expect("reverse flush");
    let mut back = [0u8; 6];
    a.read_exact(&mut back).await.expect("reverse read");
    assert_eq!(&back, b"answer");
}

#[tokio::test]
async fn a_repeated_half_close_is_not_an_error() {
    let (cli, srv) = session_pair(1);
    let (mut a, _b) = stream_pair(&cli, &srv).await;
    HalfCloseWriteExt::close_write(&mut a).await.expect("fin");
    HalfCloseWriteExt::close_write(&mut a)
        .await
        .expect("second fin");
    a.shutdown().await.expect("shutdown after fin");
}

/// `poll_close_write` / `poll_close` as futures, so the tests read like the rest of the file.
pub(crate) trait HalfCloseWriteExt: HalfCloseWrite + Unpin {
    fn close_write(&mut self) -> impl Future<Output = io::Result<()>> {
        std::future::poll_fn(move |cx| Pin::new(&mut *self).poll_close_write(cx))
    }

    // Only `qpp_tests.rs` calls this one, so it is dead in a build without the `qpp` feature.
    #[cfg_attr(not(feature = "qpp"), allow(dead_code))]
    fn close(&mut self) -> impl Future<Output = io::Result<()>> {
        std::future::poll_fn(move |cx| Pin::new(&mut *self).poll_close(cx))
    }
}

impl<T: HalfCloseWrite + Unpin + ?Sized> HalfCloseWriteExt for T {}

// ---------------------------------------------------------------------------------------
// The frame-drain fast path (step 09.1; Go: io.Copy preferring stream.WriteTo)
// ---------------------------------------------------------------------------------------

/// One `poll_read_frame`, as a future.
async fn read_frame(s: &mut SmuxStream) -> io::Result<Option<bytes::Bytes>> {
    std::future::poll_fn(|cx| std::pin::Pin::new(&mut *s).poll_read_frame(cx)).await
}

#[tokio::test]
async fn frames_are_drained_whole_and_end_with_none() {
    for version in [1isize, 2] {
        let (cli, srv) = session_pair(version);
        let (mut a, mut b) = stream_pair(&cli, &srv).await;
        const { assert!(<SmuxStream as HalfCloseWrite>::FRAME_SOURCE) };

        // Two writes, each one frame (well under the 32 KiB default frame size).
        a.write_all(b"first").await.expect("write");
        a.flush().await.expect("flush");
        a.write_all(b"second").await.expect("write");
        a.flush().await.expect("flush");
        HalfCloseWriteExt::close_write(&mut a).await.expect("fin");

        let mut got = Vec::new();
        while let Some(frame) = read_frame(&mut b).await.expect("frame") {
            assert!(!frame.is_empty(), "version {version}");
            got.extend_from_slice(&frame);
        }
        assert_eq!(got, b"firstsecond", "version {version}");
        // The end of the stream is reported again, not a hang.
        assert!(read_frame(&mut b).await.expect("frame").is_none());
    }
}

#[tokio::test]
async fn a_frame_tail_left_by_poll_read_is_delivered_first() {
    let (cli, srv) = session_pair(2);
    let (mut a, mut b) = stream_pair(&cli, &srv).await;

    a.write_all(b"abcdefgh").await.expect("write");
    a.flush().await.expect("flush");

    // A short read leaves the rest of the frame buffered in the adapter.
    let mut head = [0u8; 3];
    b.read_exact(&mut head).await.expect("read");
    assert_eq!(&head, b"abc");

    let tail = read_frame(&mut b).await.expect("frame").expect("tail");
    assert_eq!(&tail[..], b"defgh");
}
