//! The half-close tests of Go's smux, ported (plan step 06.5).
//!
//! Each runs over an in-memory [`tokio::io::duplex`] pipe and over TCP loopback (Go uses TCP).
//!
//! Go reference: `reference/latest/smux/stream_test.go`.
//!
//! `TestBufferRing*` and `TestNewBufferRingMinCapacity` are not here: Go's `bufferRing` is this
//! port's crate-private `StreamBuf`, so they are unit tests in `src/stream/tests.rs`.

mod harness;

use std::time::Duration;

use harness::{config, in_time, read_full, stream_pair, wait_until};
use kcptun_smux::conn::SmuxConn;
use kcptun_smux::error::Error;
use kcptun_smux::session::Session;
use tokio::time::Instant;

/// Go: `TestHalfCloseBasic` — `CloseWrite` sends the FIN, the peer sees EOF and can still write
/// back, and further writes on the half-closed side fail.
// Go: reference/latest/smux/stream_test.go:TestHalfCloseBasic
#[tokio::test]
async fn test_half_close_basic() {
    async fn body<C: SmuxConn>(cli: Session<C>, srv: Session<C>) {
        let (client_stream, server_stream) = stream_pair(&cli, &srv).await;

        let test_data = b"hello from client";
        client_stream
            .write(test_data)
            .await
            .expect("client write failed");
        client_stream
            .close_write()
            .await
            .expect("CloseWrite failed");

        let buf = read_full(&server_stream, test_data.len()).await;
        assert_eq!(buf, test_data, "data mismatch");

        // The peer's FIN ends the server's read side.
        let mut buf = [0u8; 64];
        assert_eq!(
            server_stream.read(&mut buf).await.expect("server read"),
            0,
            "expected EOF after CloseWrite"
        );

        // The server can still write back.
        let response = b"response from server";
        server_stream
            .write(response)
            .await
            .expect("server write failed after client CloseWrite");
        let got = read_full(&client_stream, response.len()).await;
        assert_eq!(got, response, "response mismatch");

        // The client's write side is gone.
        assert_eq!(
            client_stream
                .write(b"should fail")
                .await
                .expect_err("write after CloseWrite"),
            Error::ClosedPipe
        );

        cli.close().await.expect("close client");
        srv.close().await.expect("close server");
    }

    both_transports!(config(1), body);
}

/// Go: `TestHalfCloseDoubleCloseWrite` — the second `CloseWrite` reports a closed pipe.
// Go: reference/latest/smux/stream_test.go:TestHalfCloseDoubleCloseWrite
#[tokio::test]
async fn test_half_close_double_close_write() {
    async fn body<C: SmuxConn>(cli: Session<C>, srv: Session<C>) {
        let (client_stream, _server_stream) = stream_pair(&cli, &srv).await;
        client_stream
            .close_write()
            .await
            .expect("first CloseWrite failed");
        assert_eq!(
            client_stream
                .close_write()
                .await
                .expect_err("second CloseWrite"),
            Error::ClosedPipe
        );
        cli.close().await.expect("close client");
        srv.close().await.expect("close server");
    }

    both_transports!(config(1), body);
}

/// Go: `TestHalfCloseBidirectional` — both sides write, read the other's data, then half-close.
// Go: reference/latest/smux/stream_test.go:TestHalfCloseBidirectional
#[tokio::test]
async fn test_half_close_bidirectional() {
    async fn body<C: SmuxConn>(cli: Session<C>, srv: Session<C>) {
        let (client_stream, server_stream) = stream_pair(&cli, &srv).await;

        let client = tokio::spawn(async move {
            client_stream.write(b"client data").await.expect("write");
            let got = read_full(&client_stream, b"server data".len()).await;
            assert_eq!(got, b"server data", "client got wrong data");
            client_stream.close_write().await.expect("CloseWrite");
        });
        let server = tokio::spawn(async move {
            server_stream.write(b"server data").await.expect("write");
            let got = read_full(&server_stream, b"client data".len()).await;
            assert_eq!(got, b"client data", "server got wrong data");
            server_stream.close_write().await.expect("CloseWrite");
        });

        in_time("client side", client).await.expect("join");
        in_time("server side", server).await.expect("join");
        cli.close().await.expect("close client");
        srv.close().await.expect("close server");
    }

    both_transports!(config(1), body);
}

/// Go: `TestHalfCloseWithFullClose` — `Close` still works and is reported once; the peer reads
/// to EOF.
// Go: reference/latest/smux/stream_test.go:TestHalfCloseWithFullClose
#[tokio::test]
async fn test_half_close_with_full_close() {
    async fn body<C: SmuxConn>(cli: Session<C>, srv: Session<C>) {
        let (client_stream, server_stream) = stream_pair(&cli, &srv).await;
        client_stream.write(b"hello").await.expect("write");
        client_stream.close().await.expect("Close failed");
        assert_eq!(
            client_stream.close().await.expect_err("double Close"),
            Error::ClosedPipe
        );

        server_stream.set_read_deadline(Some(Instant::now() + Duration::from_secs(5)));
        let mut buf = [0u8; 100];
        loop {
            match server_stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) => panic!("unexpected error: {e}"),
            }
        }

        cli.close().await.expect("close client");
        srv.close().await.expect("close server");
    }

    both_transports!(config(1), body);
}

/// Go: `TestHalfCloseAutoCleanup` — once both sides have half-closed, the stream leaves both
/// session maps.
// Go: reference/latest/smux/stream_test.go:TestHalfCloseAutoCleanup
#[tokio::test]
async fn test_half_close_auto_cleanup() {
    async fn body<C: SmuxConn>(cli: Session<C>, srv: Session<C>) {
        let (client_stream, server_stream) = stream_pair(&cli, &srv).await;
        client_stream
            .close_write()
            .await
            .expect("client CloseWrite failed");
        server_stream
            .close_write()
            .await
            .expect("server CloseWrite failed");

        wait_until("streams cleaned up", || {
            cli.num_streams() == 0 && srv.num_streams() == 0
        })
        .await;

        cli.close().await.expect("close client");
        srv.close().await.expect("close server");
    }

    both_transports!(config(1), body);
}

/// Go: `TestHalfCloseV2` — the same handshake on a version-2 session, where the half-close also
/// has to keep the window updates flowing.
// Go: reference/latest/smux/stream_test.go:TestHalfCloseV2
#[tokio::test]
async fn test_half_close_v2() {
    async fn body<C: SmuxConn>(cli: Session<C>, srv: Session<C>) {
        let (client_stream, server_stream) = stream_pair(&cli, &srv).await;

        let test_data = b"hello v2";
        client_stream.write(test_data).await.expect("write");
        client_stream.close_write().await.expect("CloseWrite");

        let buf = read_full(&server_stream, test_data.len()).await;
        assert_eq!(buf, test_data, "data mismatch");
        let mut buf = [0u8; 64];
        assert_eq!(
            server_stream.read(&mut buf).await.expect("server read"),
            0,
            "expected EOF"
        );

        let response = b"response v2";
        server_stream
            .write(response)
            .await
            .expect("server write failed");
        let got = read_full(&client_stream, response.len()).await;
        assert_eq!(got, response, "response mismatch");

        cli.close().await.expect("close client");
        srv.close().await.expect("close server");
    }

    both_transports!(config(2), body);
}
