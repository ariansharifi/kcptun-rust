//! Tests for the `--pprof` HTTP endpoint (`--features pprof` only).
//!
//! They drive [`serve`] on an ephemeral port rather than `:6060`, so they never collide with a
//! running kcptun or with each other. The profile is collected for one second, which is the
//! shortest window `?seconds=` allows.

use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use super::server::{
    DEFAULT_SECONDS, MAX_HEAD, MAX_SECONDS, find_line_end, go_duration, is_temporary,
    parse_seconds, serve,
};

/// Starts the endpoint on an ephemeral port and returns it.
async fn start_test_server() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = serve(listener).await;
    });
    port
}

/// Sends one raw request and returns the whole response.
async fn request(port: u16, target: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let req = format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8_lossy(&response).into_owned()
}

/// A real CPU profile: 200, an `application/octet-stream` body that `go tool pprof` can read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_profile_endpoint() {
    let port = start_test_server().await;

    // Give the profiler something to sample while it runs.
    let busy = tokio::task::spawn_blocking(|| {
        let deadline = std::time::Instant::now() + Duration::from_millis(1200);
        let mut x: u64 = 0;
        while std::time::Instant::now() < deadline {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        }
        x
    });

    let response = request(port, "/debug/pprof/profile?seconds=1").await;
    busy.await.unwrap();

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response:?}");
    assert!(
        response.contains("Content-Type: application/octet-stream"),
        "{response:?}"
    );
    // Go: `attachment; filename="profile"`, with no RFC 5987 `filename*` parameter.
    assert!(
        response.contains("Content-Disposition: attachment; filename=\"profile\"\r\n"),
        "{response:?}"
    );
    assert!(
        response.contains("X-Content-Type-Options: nosniff"),
        "{response:?}"
    );

    let body_len: usize = response
        .split("\r\n")
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .and_then(|v| v.parse().ok())
        .unwrap();
    // An empty profile would still encode to a few bytes; a real one is far bigger.
    assert!(body_len > 32, "profile body is {body_len} bytes");
}

/// Anything else is a 404, like Go's `DefaultServeMux`; the index lists what there is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_routes() {
    let port = start_test_server().await;

    let index = request(port, "/debug/pprof/").await;
    assert!(index.starts_with("HTTP/1.1 200 OK\r\n"), "{index:?}");
    assert!(
        index.contains("/debug/pprof/profile?seconds=N"),
        "{index:?}"
    );

    for path in ["/debug/pprof/heap", "/nope", "/debug/pprof/profilex"] {
        let response = request(port, path).await;
        assert!(
            response.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "{path}: {response:?}"
        );
        assert!(response.ends_with("404 page not found\n"), "{response:?}");
        // Go's http.NotFound goes through http.Error, which sets nosniff too.
        assert!(
            response.contains("X-Content-Type-Options: nosniff"),
            "{response:?}"
        );
    }
}

/// A client that sends nothing, or an endless head, is dropped without a panic.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_malformed_requests_are_dropped() {
    let port = start_test_server().await;

    // Connect and close without sending a byte.
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    drop(stream);

    // A head without a line ending, longer than MAX_HEAD.
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let junk = vec![b'x'; MAX_HEAD + 1024];
    let _ = stream.write_all(&junk).await;
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response).await;
    assert!(response.is_empty(), "{response:?}");

    // The server is still serving.
    let response = request(port, "/nope").await;
    assert!(
        response.starts_with("HTTP/1.1 404 Not Found\r\n"),
        "{response:?}"
    );
}

/// [`parse_seconds`] on its own.
///
/// Go's `Profile` never rejects `?seconds=`: `sec, err := strconv.ParseInt(FormValue("seconds"),
/// 10, 64); if sec <= 0 || err != nil { sec = 30 }` (net/http/pprof/pprof.go:146-149), so every
/// bad value below is a 30-second profile with a 200, not a 400. Only the *named* profiles
/// (`handler.serveDeltaProfile`) answer `invalid value for "seconds" …`.
#[test]
fn test_parse_seconds() {
    assert_eq!(parse_seconds("seconds=5"), 5);
    assert_eq!(parse_seconds("seconds=+5"), 5);
    assert_eq!(parse_seconds("seconds=0005"), 5);
    assert_eq!(parse_seconds("debug=1&seconds=5"), 5);
    assert_eq!(parse_seconds("seconds=3600"), 3600);
    // Above the cap: still parsed, clamped by the caller (a documented deviation from Go).
    assert_eq!(parse_seconds("seconds=99999"), 99999);
    assert_eq!(parse_seconds("seconds=9223372036854775807"), i64::MAX);

    // Go's `FormValue` takes the first value for the key.
    assert_eq!(parse_seconds("seconds=5&seconds=9"), 5);

    // Everything Go falls back to 30 on: absent, empty, unparseable, out of range, <= 0.
    for query in [
        "",
        "debug=1",
        "seconds=",
        "seconds=x",
        "seconds=5x",
        "seconds=5.0",
        "seconds= 5",
        "seconds=0x5",
        "seconds=0",
        "seconds=-1",
        "seconds=-9223372036854775808",
        "seconds=9223372036854775808", // ErrRange for bitSize 64
    ] {
        assert_eq!(parse_seconds(query), DEFAULT_SECONDS, "{query:?}");
    }
}

/// The accept errors the loop retries instead of dying on: Go's `Errno.Temporary()` set, plus
/// `ECONNABORTED`, which Go's `internal/poll` retries inside `accept` itself.
#[test]
fn test_is_temporary_accept_errors() {
    use std::io::{Error, ErrorKind};

    for kind in [
        ErrorKind::Interrupted,       // EINTR
        ErrorKind::WouldBlock,        // EAGAIN / EWOULDBLOCK
        ErrorKind::TimedOut,          // ETIMEDOUT
        ErrorKind::ConnectionAborted, // ECONNABORTED
    ] {
        assert!(is_temporary(&Error::from(kind)), "{kind:?}");
    }
    // EMFILE / ENFILE arrive as raw errnos, with an `Uncategorized` kind.
    assert!(is_temporary(&Error::from_raw_os_error(24)));
    assert!(is_temporary(&Error::from_raw_os_error(23)));

    // Permanent: the listener really is gone, so `serve` returns and `--pprof` reports it.
    assert!(!is_temporary(&Error::from(ErrorKind::InvalidInput)));
    assert!(!is_temporary(&Error::from(ErrorKind::PermissionDenied)));
    assert!(!is_temporary(&Error::from_raw_os_error(9))); // EBADF
}

/// The retry delays Go's `http.Server.Serve` prints while backing off.
#[test]
fn test_go_duration() {
    assert_eq!(go_duration(Duration::from_millis(5)), "5ms");
    assert_eq!(go_duration(Duration::from_millis(10)), "10ms");
    assert_eq!(go_duration(Duration::from_millis(640)), "640ms");
    assert_eq!(go_duration(Duration::from_secs(1)), "1s");
}

/// The cap is the one this port applies on top of Go's parsing.
#[test]
fn test_max_seconds_cap() {
    assert_eq!(MAX_SECONDS, 3600);
    assert_eq!(parse_seconds("seconds=7200").min(MAX_SECONDS), MAX_SECONDS);
    assert_eq!(parse_seconds("seconds=60").min(MAX_SECONDS), 60);
}

/// The request-line scanner handles both line endings and a bare path.
#[test]
fn test_find_line_end() {
    assert_eq!(
        find_line_end(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        Some(14)
    );
    assert_eq!(find_line_end(b"GET / HTTP/1.1\nHost: x\n"), Some(14));
    assert_eq!(find_line_end(b"GET / HTTP/1.1"), None);
    assert_eq!(find_line_end(b"\n"), Some(0));
    assert_eq!(find_line_end(b""), None);
}
