//! The session tests of Go's smux, ported (plan step 06.5).
//!
//! Every test is named after the Go test it comes from and runs over both transports of
//! [`harness`]: an in-memory [`tokio::io::duplex`] pipe and a TCP loopback connection (Go always
//! uses TCP). Tests that only make sense on one transport say so.
//!
//! Go reference: `reference/latest/smux/session_test.go`, `mux_test.go`.
//!
//! Not ported here, because the Rust port has no equivalent or a unit test covers it directly:
//! `TestWriteStreamAfterConnectionClose` (needs `session.conn`; the unit test
//! `test_write_stream_after_connection_close` in `src/session/tests.rs` uses a failing
//! connection), `TestFrameString` (`RawHeader`'s `Display`, tested in `src/frame.rs`),
//! `TestWriteFrameInternal` (reaches into `session.writeFrameInternal`; its deadline block is
//! `test_write_frame_internal_deadline` and its `die` block
//! `test_write_frame_internal_released_by_close`, both in `src/session/tests.rs`) and the
//! benchmarks (step 06.6).

mod harness;

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use harness::{
    config, duplex_pair, in_time, payload, quiet_config, stream_pair, tcp_conn_pair, tcp_pair,
};
use kcptun_smux::conn::{SmuxConn, SplitConn};
use kcptun_smux::error::Error;
use kcptun_smux::frame::{CMD_FIN, CMD_NOP, CMD_PSH, CMD_SYN, HEADER_SIZE, RawHeader};
use kcptun_smux::mux::{Config, ConfigError, client, default_config, server};
use kcptun_smux::session::Session;
use kcptun_testkit::rng::{Pcg, rand_bytes};
use tokio::io::AsyncWriteExt;
use tokio::time::{Instant, sleep};

// ---------------------------------------------------------------------------------------
// Echo round trips
// ---------------------------------------------------------------------------------------

/// Go: `TestEcho`, a hundred short messages, written and read back one at a time.
// Go: reference/latest/smux/session_test.go:TestEcho
#[tokio::test]
async fn test_echo() {
    async fn body<C: SmuxConn>(session: Session<C>) {
        let stream = session.open_stream().await.expect("open");
        const N: usize = 100;
        let mut buf = [0u8; 10];
        let mut sent = String::new();
        let mut received = String::new();
        for i in 0..N {
            let msg = format!("hello{i}");
            stream.write(msg.as_bytes()).await.expect("write");
            sent.push_str(&msg);
            let n = stream.read(&mut buf).await.expect("read");
            received.push_str(std::str::from_utf8(&buf[..n]).expect("utf8"));
        }
        assert_eq!(sent, received, "data mismatch");
        session.close().await.expect("close");
    }

    for version in [1, 2] {
        both_echo_servers!(config(version), body);
    }
}

/// Go: `TestTinyReadBuffer`, the same messages read six bytes at a time, so every frame is
/// consumed over several reads.
// Go: reference/latest/smux/session_test.go:TestTinyReadBuffer
#[tokio::test]
async fn test_tiny_read_buffer() {
    async fn body<C: SmuxConn>(session: Session<C>) {
        let stream = session.open_stream().await.expect("open");
        const N: usize = 100;
        let mut tiny = [0u8; 6];
        let mut sent = String::new();
        let mut received = String::new();
        for i in 0..N {
            let msg = format!("hello{i}");
            sent.push_str(&msg);
            let nsent = stream.write(msg.as_bytes()).await.expect("cannot write");
            let mut nrecv = 0;
            while nrecv < nsent {
                let n = stream
                    .read(&mut tiny)
                    .await
                    .expect("cannot read with tiny buffer");
                assert_ne!(n, 0, "unexpected EOF");
                nrecv += n;
                received.push_str(std::str::from_utf8(&tiny[..n]).expect("utf8"));
            }
        }
        assert_eq!(sent, received, "data mismatch");
        session.close().await.expect("close");
    }

    for version in [1, 2] {
        both_echo_servers!(config(version), body);
    }
}

/// Go: `TestServerEcho`, the *server* opens the stream and the client echoes it.
// Go: reference/latest/smux/session_test.go:TestServerEcho
#[tokio::test]
async fn test_server_echo() {
    async fn body<C: SmuxConn>(cli: Session<C>, srv: Session<C>) {
        // Client side: accept one stream and echo it (Go's main goroutine).
        let echo = tokio::spawn(async move {
            let stream = cli.accept_stream().await.expect("accept");
            let mut buf = vec![0u8; 65536];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        if stream.write(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });

        let stream = srv.open_stream().await.expect("open");
        let mut buf = [0u8; 10];
        for i in 0..100 {
            let msg = format!("hello{i}");
            stream.write(msg.as_bytes()).await.expect("write");
            let n = stream.read(&mut buf).await.expect("read");
            assert_eq!(&buf[..n], msg.as_bytes(), "echo mismatch");
        }
        stream.close().await.expect("close stream");
        srv.close().await.expect("close session");
        in_time("echo task", echo).await.expect("join");
    }

    both_transports!(config(1), body);
}

/// Go: `TestSendWithoutRecv`, a hundred writes with nothing read in between; the first read
/// still returns data.
// Go: reference/latest/smux/session_test.go:TestSendWithoutRecv
#[tokio::test]
async fn test_send_without_recv() {
    async fn body<C: SmuxConn>(session: Session<C>) {
        let stream = session.open_stream().await.expect("open");
        for i in 0..100 {
            stream
                .write(format!("hello{i}").as_bytes())
                .await
                .expect("write");
        }
        let mut buf = [0u8; 1];
        assert_eq!(stream.read(&mut buf).await.expect("read"), 1);
        stream.close().await.expect("close");
    }

    both_echo_servers!(config(1), body);
}

/// Go: `TestWriteTo` / `TestWriteToV2`, 1 MiB echoed back through the `WriteTo` fast path; the
/// peer closes the stream once it has echoed everything.
// Go: reference/latest/smux/session_test.go:TestWriteTo / TestWriteToV2
#[tokio::test]
async fn test_write_to() {
    const N: usize = 1 << 20;

    async fn body<C: SmuxConn>(cli: Session<C>, srv: Session<C>) {
        // Go's server goroutine: an accept loop (which keeps the session alive for as long as
        // the client needs it) whose streams are echoed until N bytes have come back, and then
        // closed.
        tokio::spawn(async move {
            loop {
                let Ok(stream) = srv.accept_stream().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    let mut num_bytes = 0usize;
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                if stream.write(&buf[..n]).await.is_err() {
                                    return;
                                }
                                num_bytes += n;
                                if num_bytes == N {
                                    let _ = stream.close().await;
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });

        let stream = cli.open_stream().await.expect("open");
        let sndbuf = payload(7, N);
        let writer = {
            let stream = Arc::new(stream);
            let sender = Arc::clone(&stream);
            let data = sndbuf.clone();
            let handle = tokio::spawn(async move { sender.write(&data).await });
            (stream, handle)
        };
        let (stream, handle) = writer;

        let mut rcvbuf: Vec<u8> = Vec::with_capacity(N);
        let nw = in_time("write_to", stream.write_to(&mut rcvbuf))
            .await
            .expect("write_to");
        assert_eq!(nw as usize, N, "WriteTo nw mismatch");
        assert_eq!(rcvbuf, sndbuf, "mismatched echo bytes");
        in_time("writer", handle)
            .await
            .expect("join")
            .expect("write");
    }

    for version in [1, 2] {
        both_transports!(config(version), body);
    }
}

/// Go: `TestSpeed`, 16 MiB over one stream, written in 8 KiB pieces while a reader drains it.
// Go: reference/latest/smux/session_test.go:TestSpeed
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_speed() {
    async fn body<C: SmuxConn>(session: Session<C>) {
        let stream = Arc::new(session.open_stream().await.expect("open"));
        let reader = Arc::clone(&stream);
        let start = Instant::now();
        let reading = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024 * 1024];
            let mut nrecv = 0usize;
            while nrecv < 4096 * 4096 {
                let n = reader.read(&mut buf).await.expect("read");
                assert_ne!(n, 0, "unexpected EOF after {nrecv} bytes");
                nrecv += n;
            }
            let _ = reader.close().await;
        });

        // Go ignores the write results here; the reader's byte count is the real assertion.
        let msg = vec![0x5au8; 8192];
        for _ in 0..2048 {
            let _ = stream.write(&msg).await;
        }
        in_time("reader", reading).await.expect("join");
        eprintln!("time for 16MB rtt {:?}", start.elapsed());
        session.close().await.expect("close");
    }

    both_echo_servers!(config(1), body);
}

/// Go: `TestParallel` / `TestParallelV2`, a thousand streams, each doing a hundred round trips.
// Go: reference/latest/smux/session_test.go:TestParallel / TestParallelV2
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_parallel() {
    async fn body<C: SmuxConn>(session: Session<C>) {
        const PAR: usize = 1000;
        const MESSAGES: usize = 100;
        let session = Arc::new(session);
        let mut tasks = Vec::with_capacity(PAR);
        for _ in 0..PAR {
            let stream = session.open_stream().await.expect("open");
            tasks.push(tokio::spawn(async move {
                let mut buf = [0u8; 20];
                for j in 0..MESSAGES {
                    let msg = format!("hello{j}");
                    if stream.write(msg.as_bytes()).await.is_err() {
                        break;
                    }
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
                let _ = stream.close().await;
            }));
        }
        eprintln!("created {} streams", session.num_streams());
        for t in tasks {
            in_time("stream task", t).await.expect("join");
        }
        session.close().await.expect("close");
    }

    for version in [1, 2] {
        both_echo_servers!(config(version), body);
    }
}

// ---------------------------------------------------------------------------------------
// Opening, accepting and closing
// ---------------------------------------------------------------------------------------

/// Go: `TestSessionOpenAccept`, one side opens, the other accepts.
// Go: reference/latest/smux/session_test.go:TestSessionOpenAccept
#[tokio::test]
async fn test_session_open_accept() {
    async fn body<C: SmuxConn>(cli: Session<C>, srv: Session<C>) {
        let (cs, ss) = stream_pair(&cli, &srv).await;
        assert_ne!(ss.id(), 0, "Stream ID should not be 0"); // Go: TestStreamID
        assert_eq!(cs.id(), ss.id());
        cli.close().await.expect("close client");
        srv.close().await.expect("close server");
    }

    both_transports!(config(1), body);
}

/// Go: `TestCloseThenOpen`, opening after a close fails.
// Go: reference/latest/smux/session_test.go:TestCloseThenOpen
#[tokio::test]
async fn test_close_then_open() {
    async fn body<C: SmuxConn>(session: Session<C>) {
        session.close().await.expect("close");
        assert_eq!(
            session.open_stream().await.expect_err("opened after close"),
            Error::ClosedPipe
        );
    }

    both_echo_servers!(config(1), body);
}

/// Go: `TestSessionDoubleClose` and `TestIsClose`.
// Go: reference/latest/smux/session_test.go:TestSessionDoubleClose / TestIsClose
#[tokio::test]
async fn test_session_double_close() {
    async fn body<C: SmuxConn>(session: Session<C>) {
        session.close().await.expect("close");
        assert!(session.is_closed(), "still open after close");
        assert_eq!(
            session
                .close()
                .await
                .expect_err("session double close doesn't return error"),
            Error::ClosedPipe
        );
    }

    both_echo_servers!(config(1), body);
}

/// Go: `TestStreamDoubleClose`.
// Go: reference/latest/smux/session_test.go:TestStreamDoubleClose
#[tokio::test]
async fn test_stream_double_close() {
    async fn body<C: SmuxConn>(session: Session<C>) {
        let stream = session.open_stream().await.expect("open");
        stream.close().await.expect("close");
        assert_eq!(
            stream
                .close()
                .await
                .expect_err("stream double close doesn't return error"),
            Error::ClosedPipe
        );
        session.close().await.expect("close session");
    }

    both_echo_servers!(config(1), body);
}

/// Go: `TestConcurrentClose`, a hundred streams closed concurrently with the session.
// Go: reference/latest/smux/session_test.go:TestConcurrentClose
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_close() {
    async fn body<C: SmuxConn>(session: Session<C>) {
        const NUM_STREAMS: usize = 100;
        let mut streams = Vec::with_capacity(NUM_STREAMS);
        for _ in 0..NUM_STREAMS {
            streams.push(session.open_stream().await.expect("open"));
        }
        let tasks: Vec<_> = streams
            .into_iter()
            .map(|s| tokio::spawn(async move { s.close().await }))
            .collect();
        session.close().await.expect("close session");
        for t in tasks {
            // Either the stream closed itself or the session got there first; both are fine,
            // nothing may panic or hang.
            let _ = in_time("stream close", t).await.expect("join");
        }
        assert_eq!(session.num_streams(), 0);
    }

    both_echo_servers!(config(1), body);
}

/// Go: `TestNumStreamAfterClose`.
// Go: reference/latest/smux/session_test.go:TestNumStreamAfterClose
#[tokio::test]
async fn test_num_stream_after_close() {
    async fn body<C: SmuxConn>(session: Session<C>) {
        let stream = session.open_stream().await.expect("open");
        assert_eq!(
            session.num_streams(),
            1,
            "wrong number of streams after opened"
        );
        session.close().await.expect("close");
        assert_eq!(
            session.num_streams(),
            0,
            "wrong number of streams after session closed"
        );
        drop(stream);
    }

    both_echo_servers!(config(1), body);
}

/// Go: `TestWriteAfterClose`.
// Go: reference/latest/smux/session_test.go:TestWriteAfterClose
#[tokio::test]
async fn test_write_after_close() {
    async fn body<C: SmuxConn>(session: Session<C>) {
        let stream = session.open_stream().await.expect("open");
        stream.close().await.expect("close");
        assert_eq!(
            stream
                .write(b"write after close")
                .await
                .expect_err("write after close failed"),
            Error::ClosedPipe
        );
    }

    both_echo_servers!(config(1), body);
}

/// Go: `TestReadStreamAfterSessionClose`.
// Go: reference/latest/smux/session_test.go:TestReadStreamAfterSessionClose
#[tokio::test]
async fn test_read_stream_after_session_close() {
    async fn body<C: SmuxConn>(session: Session<C>) {
        let stream = session.open_stream().await.expect("open");
        session.close().await.expect("close");
        // Go asserts only that the read fails; there it is `(0, io.EOF)`, which this port
        // spells `Ok(0)` (see the EOF note in `stream.rs`). A closed session must never hand
        // out data.
        let mut buf = [0u8; 10];
        match stream.read(&mut buf).await {
            Ok(0) => {}
            Ok(n) => panic!("read stream after session close succeeded: {n} bytes"),
            Err(e) => assert_eq!(e, Error::ClosedPipe),
        }
    }

    both_echo_servers!(config(1), body);
}

/// Go: `TestGetDieCh`, closing one end wakes the other end's die channel.
// Go: reference/latest/smux/session_test.go:TestGetDieCh
#[tokio::test]
async fn test_get_die_ch() {
    async fn body<C: SmuxConn>(cli: Session<C>, srv: Session<C>) {
        let (cs, ss) = stream_pair(&cli, &srv).await;
        let ss = Arc::new(ss);
        let reader = Arc::clone(&ss);
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while reader.read(&mut buf).await.is_ok_and(|n| n != 0) {}
            let _ = reader.close().await;
        });

        cs.close().await.expect("close client stream");
        in_time("die channel", ss.closed()).await;
        assert!(ss.is_closed());
    }

    both_transports!(config(1), body);
}

/// Go: `TestSessionCloseChan`, the close notification fires only after `Close`.
// Go: reference/latest/smux/session_test.go:TestSessionCloseChan
#[tokio::test]
async fn test_session_close_chan() {
    async fn body<C: SmuxConn>(_cli: Session<C>, srv: Session<C>) {
        assert!(
            tokio::time::timeout(Duration::from_millis(50), srv.closed())
                .await
                .is_err(),
            "CloseChan should not be closed yet"
        );
        srv.close().await.expect("close");
        in_time("CloseChan should be closed", srv.closed()).await;
    }

    both_transports!(config(1), body);
}

// ---------------------------------------------------------------------------------------
// Addresses, deadlines, errors
// ---------------------------------------------------------------------------------------

/// Go: `TestSessionAddr`, `TestStreamAddr`, a TCP session reports both addresses.
// Go: reference/latest/smux/session_test.go:TestSessionAddr / TestStreamAddr
#[tokio::test]
async fn test_session_addr() {
    let (cli, srv) = tcp_pair(config(1)).await;
    assert!(srv.local_addr().is_some(), "LocalAddr should not be nil");
    assert!(srv.remote_addr().is_some(), "RemoteAddr should not be nil");
    let (_cs, ss) = stream_pair(&cli, &srv).await;
    assert_eq!(ss.local_addr(), srv.local_addr());
    assert_eq!(ss.remote_addr(), srv.remote_addr());
    srv.close().await.expect("close");
}

/// Go: `TestSessionAddrNonNetConn`, `TestStreamAddrNonNetConn`, a connection without addresses
/// reports none (Go's `hiddenConn`; here any non-TCP [`SplitConn`]).
// Go: reference/latest/smux/session_test.go:TestSessionAddrNonNetConn / TestStreamAddrNonNetConn
#[tokio::test]
async fn test_session_addr_non_net_conn() {
    let (cli, srv) = duplex_pair(config(1));
    assert_eq!(srv.local_addr(), None, "LocalAddr should be nil");
    assert_eq!(srv.remote_addr(), None, "RemoteAddr should be nil");
    let (_cs, ss) = stream_pair(&cli, &srv).await;
    assert_eq!(ss.local_addr(), None);
    assert_eq!(ss.remote_addr(), None);
    srv.close().await.expect("close");
}

/// Go: `TestSessionSetDeadline`, an accept deadline in the past ends `Accept` with a timeout.
// Go: reference/latest/smux/session_test.go:TestSessionSetDeadline
#[tokio::test]
async fn test_session_set_deadline() {
    async fn body<C: SmuxConn>(_cli: Session<C>, srv: Session<C>) {
        srv.set_deadline(Some(Instant::now()));
        assert_eq!(
            in_time("accept deadline", srv.accept_stream())
                .await
                .expect_err("accept must time out"),
            Error::Timeout
        );
        srv.set_deadline(None);
        srv.close().await.expect("close");
    }

    both_transports!(config(1), body);
}

/// Go: `TestStreamSetDeadline`, `TestReadDeadline`, a read deadline in the past fails with
/// "timeout".
// Go: reference/latest/smux/session_test.go:TestReadDeadline / TestStreamSetDeadline
#[tokio::test]
async fn test_read_deadline() {
    async fn body<C: SmuxConn>(session: Session<C>) {
        let stream = session.open_stream().await.expect("open");
        const N: usize = 100;
        let mut buf = [0u8; 10];
        let mut read_err = None;
        for _ in 0..N {
            stream.set_read_deadline(Some(Instant::now() - Duration::from_secs(60)));
            if let Err(e) = stream.read(&mut buf).await {
                read_err = Some(e);
                break;
            }
        }
        let err = read_err.expect("No error when reading with past deadline");
        assert!(err.is_timeout(), "Wrong error: {err}");
        assert_eq!(err.to_string(), "timeout");
        session.close().await.expect("close");
    }

    both_echo_servers!(config(1), body);
}

/// Go: `TestWriteDeadline`, writing with a deadline in the past eventually fails with
/// "timeout" (the first writes may still succeed, as in Go).
// Go: reference/latest/smux/session_test.go:TestWriteDeadline
#[tokio::test]
async fn test_write_deadline() {
    async fn body<C: SmuxConn>(session: Session<C>) {
        let stream = session.open_stream().await.expect("open");
        let buf = [0u8; 10];
        let err = in_time("write deadline", async {
            loop {
                stream.set_write_deadline(Some(Instant::now() - Duration::from_secs(60)));
                if let Err(e) = stream.write(&buf).await {
                    return e;
                }
            }
        })
        .await;
        assert!(err.is_timeout(), "Wrong error: {err}");
        session.close().await.expect("close");
    }

    for version in [1, 2] {
        both_echo_servers!(config(version), body);
    }
}

/// Go: `TestTimeoutError`, the timeout error is a timeout, is temporary and prints "timeout".
// Go: reference/latest/smux/session_test.go:TestTimeoutError
#[test]
fn test_timeout_error() {
    let err = Error::Timeout;
    assert!(err.is_temporary(), "timeoutError should be temporary");
    assert!(err.is_timeout(), "timeoutError should be a timeout");
    assert_eq!(err.to_string(), "timeout");
}

// ---------------------------------------------------------------------------------------
// Keepalive
// ---------------------------------------------------------------------------------------

/// Go: `TestKeepAliveTimeout`, a peer that never answers kills the session.
// Go: reference/latest/smux/session_test.go:TestKeepAliveTimeout
#[tokio::test]
async fn test_keep_alive_timeout() {
    let cfg = Config {
        keep_alive_interval: Duration::from_secs(1),
        keep_alive_timeout: Duration::from_secs(2),
        ..default_config()
    };

    // A silent peer: the connection stays open, nothing is ever sent back.
    let (ours, theirs) = tokio::io::duplex(harness::PIPE_CAPACITY);
    let session = client(SplitConn::new(ours), Some(cfg)).expect("client");
    sleep(Duration::from_secs(3)).await;
    assert!(session.is_closed(), "keepalive-timeout failed");
    drop(theirs);

    let (raw, conn) = tcp_conn_pair().await;
    let session = client(SplitConn::tcp(conn), Some(cfg)).expect("client");
    sleep(Duration::from_secs(3)).await;
    assert!(session.is_closed(), "keepalive-timeout failed (tcp)");
    drop(raw);
}

/// Go: `TestKeepAliveBlockWriteTimeout`, a connection whose writes never complete must still
/// time out (in old smux versions the keepalive blocked forever in `writeFrame`).
// Go: reference/latest/smux/session_test.go:TestKeepAliveBlockWriteTimeout
#[tokio::test]
async fn test_keep_alive_block_write_timeout() {
    /// Go's `blockWriteConn`: every write sleeps for a day.
    struct BlockWriteConn<C: SmuxConn>(C);

    impl<C: SmuxConn> SmuxConn for BlockWriteConn<C> {
        async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf).await
        }

        async fn write_all(&self, _buf: &[u8]) -> io::Result<()> {
            std::future::pending().await
        }

        async fn write_all_vectored(&self, _bufs: &[&[u8]]) -> io::Result<usize> {
            std::future::pending().await
        }

        async fn close(&self) -> io::Result<()> {
            self.0.close().await
        }
    }

    let cfg = Config {
        keep_alive_interval: Duration::from_secs(1),
        keep_alive_timeout: Duration::from_secs(2),
        ..default_config()
    };

    let (raw, conn) = tcp_conn_pair().await;
    let session = client(BlockWriteConn(SplitConn::tcp(conn)), Some(cfg)).expect("client");
    sleep(Duration::from_secs(3)).await;
    assert!(session.is_closed(), "keepalive-timeout failed");
    drop(raw);
}

// ---------------------------------------------------------------------------------------
// Malformed input
// ---------------------------------------------------------------------------------------

/// Go: `TestRandomFrame`, junk, duplicate SYNs, random commands, random versions and a wrong
/// length field must never panic; the session ends in an error instead.
// Go: reference/latest/smux/session_test.go:TestRandomFrame
#[tokio::test]
async fn test_random_frame() {
    /// Feeds `bytes` to a fresh server session from a raw socket, then closes the socket and
    /// drains the session until it reports an error.
    async fn feed(label: &str, bytes: Vec<u8>) {
        let (mut raw, conn) = tcp_conn_pair().await;
        let session = server(SplitConn::tcp(conn), Some(quiet_config(1))).expect("server");
        raw.write_all(&bytes).await.expect("write junk");
        raw.shutdown().await.expect("shutdown");
        drop(raw);
        in_time(label, async {
            while session.accept_stream().await.is_ok() {}
        })
        .await;
        // The session survives as an object; closing it is still well defined.
        let _ = session.close().await;
    }

    let mut rng = Pcg::new(0x5eed_0006, 0x5eed_0005);
    let frame = |ver: u8, cmd: u8, sid: u32, data: &[u8]| {
        let mut out = RawHeader::new(ver, cmd, data.len() as u16, sid)
            .as_bytes()
            .to_vec();
        out.extend_from_slice(data);
        out
    };

    // pure random
    let mut junk = Vec::new();
    for _ in 0..100 {
        let n = (rng.next_u32() % 1024) as usize;
        junk.extend_from_slice(&rand_bytes(&mut rng, n));
    }
    feed("pure random", junk).await;

    // double syn
    let mut bytes = Vec::new();
    for _ in 0..100 {
        bytes.extend_from_slice(&frame(1, CMD_SYN, 1000, &[]));
    }
    feed("double syn", bytes).await;

    // random cmds
    let allcmds = [CMD_SYN, CMD_FIN, CMD_PSH, CMD_NOP];
    let mut bytes = Vec::new();
    for _ in 0..100 {
        let cmd = allcmds[(rng.next_u32() as usize) % allcmds.len()];
        bytes.extend_from_slice(&frame(1, cmd, rng.next_u32(), &[]));
    }
    feed("random cmds", bytes).await;

    // random cmds & sids
    let mut bytes = Vec::new();
    for _ in 0..100 {
        bytes.extend_from_slice(&frame(1, rng.next_u32() as u8, rng.next_u32(), &[]));
    }
    feed("random cmds and sids", bytes).await;

    // random version
    let mut bytes = Vec::new();
    for _ in 0..100 {
        bytes.extend_from_slice(&frame(
            rng.next_u32() as u8,
            rng.next_u32() as u8,
            rng.next_u32(),
            &[],
        ));
    }
    feed("random version", bytes).await;

    // incorrect size: the length field promises one byte more than follows
    let data_len = (rng.next_u32() % 1024) as usize;
    let data = rand_bytes(&mut rng, data_len);
    let mut bytes = RawHeader::new(1, CMD_PSH, data.len() as u16 + 1, rng.next_u32())
        .as_bytes()
        .to_vec();
    bytes.extend_from_slice(&data);
    assert_eq!(bytes.len(), HEADER_SIZE + data.len());
    feed("incorrect size", bytes).await;

    // writeFrame after die: every write on a closed session fails, none of them panics
    let (raw, conn) = tcp_conn_pair().await;
    let session = client(SplitConn::tcp(conn), Some(quiet_config(1))).expect("client");
    session.close().await.expect("close");
    for _ in 0..100 {
        assert_eq!(
            session.open_stream().await.expect_err("open after close"),
            Error::ClosedPipe
        );
    }
    drop(raw);
}

// ---------------------------------------------------------------------------------------
// Configuration (mux_test.go)
// ---------------------------------------------------------------------------------------

/// Go: `TestConfig`, every rejected configuration, and `Server`/`Client` refusing one.
// Go: reference/latest/smux/mux_test.go:TestConfig
#[tokio::test]
async fn test_config() {
    use kcptun_smux::mux::verify_config;

    verify_config(&default_config()).expect("the default config verifies");

    let cases: Vec<(Config, ConfigError)> = vec![
        (
            Config {
                keep_alive_interval: Duration::ZERO,
                ..default_config()
            },
            ConfigError::KeepAliveInterval,
        ),
        (
            Config {
                keep_alive_interval: Duration::from_secs(10),
                keep_alive_timeout: Duration::from_secs(5),
                ..default_config()
            },
            ConfigError::KeepAliveTimeout,
        ),
        (
            Config {
                max_frame_size: 0,
                ..default_config()
            },
            ConfigError::FrameSizeNotPositive,
        ),
        (
            Config {
                max_frame_size: 65536,
                ..default_config()
            },
            ConfigError::FrameSizeTooLarge,
        ),
        (
            Config {
                max_receive_buffer: 0,
                ..default_config()
            },
            ConfigError::ReceiveBufferNotPositive,
        ),
        (
            Config {
                max_stream_buffer: 0,
                ..default_config()
            },
            ConfigError::StreamBufferNotPositive,
        ),
        (
            Config {
                max_stream_buffer: 100,
                max_receive_buffer: 99,
                ..default_config()
            },
            ConfigError::StreamBufferAboveReceiveBuffer,
        ),
    ];

    for (cfg, want) in cases {
        assert_eq!(verify_config(&cfg), Err(want), "{cfg:?}");
        let (a, b) = tokio::io::duplex(64);
        assert_eq!(
            server(SplitConn::new(a), Some(cfg)).err(),
            Some(Error::Config(want)),
            "server started with wrong config"
        );
        assert_eq!(
            client(SplitConn::new(b), Some(cfg)).err(),
            Some(Error::Config(want)),
            "client started with wrong config"
        );
    }
}

/// Go: `TestConfigMaxReceiveBufferUpperBound`, `math.MaxInt32 + 1` is refused.
// Go: reference/latest/smux/mux_test.go:TestConfigMaxReceiveBufferUpperBound
#[tokio::test]
async fn test_config_max_receive_buffer_upper_bound() {
    use kcptun_smux::mux::{MAX_BUFFER_LIMIT, verify_config};

    let Some(too_large) = MAX_BUFFER_LIMIT.checked_add(1) else {
        return; // 32-bit isize: unrepresentable, exactly as Go's int would be
    };
    let cfg = Config {
        max_receive_buffer: too_large,
        ..default_config()
    };
    assert_eq!(
        verify_config(&cfg),
        Err(ConfigError::ReceiveBufferTooLarge),
        "expected verify failure for excessive MaxReceiveBuffer"
    );
    let (a, b) = tokio::io::duplex(64);
    assert!(
        server(SplitConn::new(a), Some(cfg)).is_err(),
        "server should reject excessive MaxReceiveBuffer"
    );
    assert!(
        client(SplitConn::new(b), Some(cfg)).is_err(),
        "client should reject excessive MaxReceiveBuffer"
    );
}

// ---------------------------------------------------------------------------------------
// Long transfers
// ---------------------------------------------------------------------------------------

/// Go: `TestRandomLengthRandomDataTransferV1` / `V2`, 1 GiB of random data in random-sized
/// pieces through an echoing peer.
// Go: reference/latest/smux/session_test.go:testRandomLength
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "transfers 1 GiB (Go: TestRandomLengthRandomDataTransfer*)"]
async fn long_test_random_length_random_data_transfer() {
    for version in [1, 2] {
        let session = harness::tcp_echo_client(config(version)).await;
        random_length_transfer(&session, 1 << 30).await;
        session.close().await.expect("close");
    }
}

/// Go: `Test8GBTransferV1` / `V2`.
// Go: reference/latest/smux/session_test.go:Test8GBTransferV1 / Test8GBTransferV2
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "transfers 8 GiB (Go: Test8GBTransfer*)"]
async fn long_test_8gb_transfer() {
    for version in [1, 2] {
        let session = harness::tcp_echo_client(config(version)).await;
        random_length_transfer(&session, 8 << 30).await;
        session.close().await.expect("close");
    }
}

/// Go's `testRandomLength`: a writer and a reader agree on the byte stream through a shared
/// seed, and use independently random chunk sizes.
// Go: reference/latest/smux/session_test.go:testRandomLength
async fn random_length_transfer<C: SmuxConn>(session: &Session<C>, n: u64) {
    const MAX_CHUNK: usize = 1 << 20;
    let stream = Arc::new(session.open_stream().await.expect("open"));

    let sent = Arc::new(AtomicUsize::new(0));
    let writer = {
        let stream = Arc::clone(&stream);
        let sent = Arc::clone(&sent);
        tokio::spawn(async move {
            let mut lens = Pcg::new(1, 2);
            let mut sndbuf = kcptun_testkit::servers::PrngStream::new(42, n);
            let mut buf = vec![0u8; MAX_CHUNK];
            let mut done = 0u64;
            while done < n {
                let mut length = (lens.below(MAX_CHUNK as u64) + 1).min(n - done) as usize;
                length = sndbuf.fill(&mut buf[..length]);
                stream.write(&buf[..length]).await.expect("write");
                done += length as u64;
                sent.store(done as usize, Ordering::Relaxed);
            }
        })
    };

    let mut lens = Pcg::new(3, 4);
    let mut expected = kcptun_testkit::servers::PrngStream::new(42, n);
    let mut expbuf = vec![0u8; MAX_CHUNK];
    let mut rcvbuf = vec![0u8; MAX_CHUNK];
    let mut received = 0u64;
    while received < n {
        let length = (lens.below(MAX_CHUNK as u64) + 1).min(n - received) as usize;
        let got = stream.read(&mut rcvbuf[..length]).await.expect("read");
        assert_ne!(got, 0, "unexpected EOF after {received} bytes");
        let want = expected.fill(&mut expbuf[..got]);
        assert_eq!(want, got);
        assert_eq!(
            rcvbuf[..got],
            expbuf[..got],
            "data mismatch around byte {received}"
        );
        received += got as u64;
    }
    writer.await.expect("join");
}
