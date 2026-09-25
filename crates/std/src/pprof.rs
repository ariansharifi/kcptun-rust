//! `--pprof`: the profiling endpoint, and what a build without it says instead (DECISIONS D23).
//!
//! Go sources:
//! - `kcptun/client/main.go:32`, `kcptun/server/main.go:33` — `_ "net/http/pprof"`, whose `init()`
//!   registers `/debug/pprof/...` on `http.DefaultServeMux`;
//! - `kcptun/client/main.go:247-250`, `kcptun/server/main.go:220-223` — the
//!   `cli.BoolFlag{Name: "pprof", Usage: "start profiling server on :6060"}`;
//! - `kcptun/client/main.go:394-401`, `kcptun/server/main.go:351-358`:
//!
//! ```go
//! if config.Pprof {
//!     go func() {
//!         if err := http.ListenAndServe(":6060", nil); err != nil {
//!             log.Println("pprof server:", err)
//!         }
//!     }()
//! }
//! ```
//!
//! **D23.** The flag itself is part of the command line and the JSON config, so it is always
//! accepted and always echoed by the startup log (`pprof: true`), exactly like Go. What it does
//! depends on the build:
//!
//! | Build | `--pprof` |
//! |---|---|
//! | `--features pprof` (Unix) | serves a CPU profile on `:6060` at `/debug/pprof/profile` |
//! | default (feature off), or Windows | logs [`NOT_AVAILABLE`] once at start-up and runs on |
//!
//! The feature is off by default because the profiler installs a `SIGPROF` timer and pulls in the
//! unwinding and protobuf machinery; the endpoint is meant for a build made to diagnose something.
//!
//! **Deviation from Go**: Go's `net/http/pprof` exposes a dozen profiles (`heap`, `goroutine`,
//! `block`, `mutex`, `trace`, …) that have no Rust counterpart. Only the CPU profile is served,
//! and it is the same protobuf, so `go tool pprof http://host:6060/debug/pprof/profile?seconds=30`
//! works unchanged against either binary.
//!
//! **Deviation from Go**: routing is looser than `http.DefaultServeMux`, which registers only
//! `GET /debug/pprof/`, `/cmdline`, `/profile`, `/symbol` and `/trace`
//! (`net/http/pprof/pprof.go:95-105`). Here `/` answers the plain-text index where Go answers
//! 404, `/debug/pprof` (no trailing slash) answers the index where Go answers
//! `301 Moved Permanently` to `/debug/pprof/`, and the request method is ignored, so
//! `POST /debug/pprof/profile` starts a profile where Go answers `405 Method Not Allowed`.
//! `go tool pprof` only ever issues `GET /debug/pprof/profile`, which behaves identically.
//!
//! **Deviation from Go**: `?seconds=` is capped at one hour. Go bounds the window only by the
//! server's `WriteTimeout`, which a `DefaultServeMux` server on `:6060` does not set, so
//! `go tool pprof -seconds 7200` really does profile a Go binary for two hours; here it profiles
//! for one, because the collector holds a blocking thread for the whole window. Everything below
//! the cap behaves exactly as Go does, including the fallback to 30 s for a missing, unparseable,
//! zero or negative value.
//!
//! **Deviation from Go**: with the `pprof` feature the endpoint is Unix-only. `pprof` 0.15 depends
//! unconditionally on `nix`, which does not build for Windows (D22 lists Windows as best effort),
//! so a Windows build logs [`NOT_AVAILABLE`] even with the feature on.

/// The address Go's profiling server listens on: every interface, port 6060.
// Go: kcptun/client/main.go:397, kcptun/server/main.go:354 — http.ListenAndServe(":6060", nil)
pub const ADDR: &str = ":6060";

/// Port of [`ADDR`].
pub const PORT: u16 = 6060;

/// The path `go tool pprof` fetches, and the only one this server answers with a profile.
// Go: net/http/pprof/pprof.go:init() — mux.HandleFunc("/debug/pprof/profile", Profile)
pub const PROFILE_PATH: &str = "/debug/pprof/profile";

/// What a build without the `pprof` feature logs when `--pprof` is given.
// Deviation D23: Go always has net/http/pprof compiled in.
pub const NOT_AVAILABLE: &str = "pprof: not available in this build";

/// Starts the profiling server when `--pprof` was given, like Go's `go http.ListenAndServe`.
///
/// Called once, from `main`, inside the tokio runtime ([`crate::runtime::build`]): with the
/// `pprof` feature it spawns the listener and returns immediately, and without it, it logs
/// [`NOT_AVAILABLE`] and returns. A failing listener is reported the way Go reports it,
/// `pprof server: listen tcp :6060: bind: address already in use`, and is not fatal.
// Go: kcptun/client/main.go:394-401, kcptun/server/main.go:351-358
pub fn start(enabled: bool) {
    if !enabled {
        return;
    }

    #[cfg(all(feature = "pprof", unix))]
    {
        tokio::spawn(async {
            if let Err(err) = server::listen_and_serve().await {
                // Go: log.Println("pprof server:", err)
                crate::logln!("pprof server:", err);
            }
        });
    }

    #[cfg(not(all(feature = "pprof", unix)))]
    {
        // Deviation D23: the flag is accepted, the profiler is simply not in this build (the
        // feature is off, or this is a Windows build, where `pprof`'s `nix` dependency does not
        // compile).
        crate::logln!(NOT_AVAILABLE);
    }
}

/// The HTTP server behind `--pprof`, present only with the `pprof` feature.
///
/// It is a deliberately small HTTP/1.1 responder rather than a web framework: one request per
/// connection, `Connection: close`, a bounded request head and exactly two routes. Nothing here
/// is on a data path, and the endpoint exists to be scraped by `go tool pprof`.
#[cfg(all(feature = "pprof", unix))]
mod server {
    use std::io;
    use std::time::Duration;

    use pprof::protos::Message as _;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

    use super::{ADDR, PORT, PROFILE_PATH};
    use crate::config::go_error_text;

    /// Samples per second. Go's runtime profiler is fixed at 100 Hz
    /// (`runtime/pprof.StartCPUProfile` → `SetCPUProfileRate(100)`), so a profile taken from
    /// either binary has the same resolution.
    const FREQUENCY: i32 = 100;

    /// Default duration of `/debug/pprof/profile`.
    // Go: net/http/pprof/pprof.go:146-149 — `if sec <= 0 || err != nil { sec = 30 }`, so this is
    // also what a missing, unparseable, zero or negative `?seconds=` gets.
    pub(super) const DEFAULT_SECONDS: i64 = 30;

    /// Upper bound on `?seconds=`.
    // Deviation (documented in the module docs): Go bounds the window by the server's
    // `WriteTimeout`, which a `DefaultServeMux` on `:6060` does not set. Here the collector holds
    // a blocking thread for the whole window, so a longer request is clamped, not rejected.
    pub(super) const MAX_SECONDS: i64 = 3600;

    /// Largest request head accepted, after which the connection is dropped.
    pub(super) const MAX_HEAD: usize = 8 * 1024;

    /// Frames from these libraries are dropped from the stacks, as pprof-rs recommends, so the
    /// profiler does not unwind through its own signal handler.
    const BLOCKLIST: &[&str] = &["libc", "libgcc", "pthread", "vdso"];

    /// Binds `:6060` and serves until the listener fails.
    // Go: http.ListenAndServe(":6060", nil)
    pub(super) async fn listen_and_serve() -> Result<(), String> {
        let listener = bind()
            .await
            // Go: net.Listen's error, e.g. `listen tcp :6060: bind: address already in use`.
            .map_err(|err| format!("listen tcp {ADDR}: bind: {}", go_error_text(&err)))?;
        serve(listener)
            .await
            .map_err(|err| format!("accept tcp {ADDR}: {}", go_error_text(&err)))
    }

    /// Go's `":6060"` means "every interface": a dual-stack `[::]` socket, falling back to IPv4
    /// where IPv6 is unavailable.
    async fn bind() -> io::Result<TcpListener> {
        match TcpListener::bind(("::", PORT)).await {
            Ok(listener) => Ok(listener),
            Err(_) => TcpListener::bind(("0.0.0.0", PORT)).await,
        }
    }

    /// Accept loop: one task per connection, like Go's `http.Server.Serve`.
    ///
    /// A temporary accept failure (`EINTR`, `EMFILE`, `ENFILE`, `EAGAIN`, `ETIMEDOUT`, an aborted
    /// connection) is retried with Go's 5 ms-doubling-to-1 s backoff instead of taking the
    /// endpoint down for the rest of the process's life; only a permanent error returns.
    // Go: net/http/server.go:3547-3578 — `tempDelay`, `ne.Temporary()`; syscall/syscall_unix.go:134
    pub(super) async fn serve(listener: TcpListener) -> io::Result<()> {
        let mut temp_delay = Duration::ZERO;
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(err) if is_temporary(&err) => {
                    // Go: `if tempDelay == 0 { 5ms } else { tempDelay *= 2 }`, capped at 1s.
                    temp_delay = if temp_delay.is_zero() {
                        Duration::from_millis(5)
                    } else {
                        (temp_delay * 2).min(Duration::from_secs(1))
                    };
                    // Go: log.Printf("http: Accept error: %v; retrying in %v", err, tempDelay)
                    crate::logf!(
                        "http: Accept error: {}; retrying in {}",
                        go_error_text(&err),
                        go_duration(temp_delay)
                    );
                    tokio::time::sleep(temp_delay).await;
                    continue;
                }
                Err(err) => return Err(err),
            };
            // Go: `tempDelay = 0` after a successful accept.
            temp_delay = Duration::ZERO;
            tokio::spawn(async move {
                // A broken client connection is not worth a log line (Go drops them silently).
                let _ = handle(stream).await;
            });
        }
    }

    /// The accept errors Go's `net.Error.Temporary()` reports as temporary, so the loop retries
    /// rather than dies.
    // Go: syscall/syscall_unix.go:134-140 — EINTR, EMFILE, ENFILE, EAGAIN, EWOULDBLOCK, ETIMEDOUT;
    // net/fd_unix.go retries ECONNABORTED inside `accept` itself.
    pub(super) fn is_temporary(err: &io::Error) -> bool {
        // `io::ErrorKind` has no variant for either, and both have the same value on Linux, macOS
        // and the BSDs — the only platforms this module is compiled for.
        /// `EMFILE`: the process is out of descriptors.
        const EMFILE: i32 = 24;
        /// `ENFILE`: the system is out of descriptors.
        const ENFILE: i32 = 23;

        matches!(
            err.kind(),
            io::ErrorKind::Interrupted
                | io::ErrorKind::WouldBlock
                | io::ErrorKind::TimedOut
                | io::ErrorKind::ConnectionAborted
        ) || matches!(err.raw_os_error(), Some(EMFILE | ENFILE))
    }

    /// A backoff delay the way Go's `time.Duration` prints one: the values here are whole
    /// milliseconds up to the 1 s cap.
    // Go: time/format.go:Duration.String
    pub(super) fn go_duration(d: Duration) -> String {
        if d >= Duration::from_secs(1) {
            format!("{}s", d.as_secs())
        } else {
            format!("{}ms", d.as_millis())
        }
    }

    /// Answers one request.
    async fn handle(mut stream: TcpStream) -> io::Result<()> {
        let Some(request_line) = read_request_line(&mut stream).await? else {
            return Ok(());
        };
        // `GET /debug/pprof/profile?seconds=5 HTTP/1.1`
        let target = request_line.split(' ').nth(1).unwrap_or("/");
        let (path, query) = target.split_once('?').unwrap_or((target, ""));

        match path {
            PROFILE_PATH => profile(&mut stream, query).await,
            "/" | "/debug/pprof" | "/debug/pprof/" => {
                let body = format!(
                    "kcptun profiling endpoint\n\n\
                     {PROFILE_PATH}?seconds=N  CPU profile (default {DEFAULT_SECONDS}s)\n\n\
                     go tool pprof http://<host>:{PORT}{PROFILE_PATH}?seconds=30\n"
                );
                respond(&mut stream, "200 OK", &[], body.as_bytes()).await
            }
            // Go: http.NotFound.
            _ => respond(&mut stream, "404 Not Found", &[], b"404 page not found\n").await,
        }
    }

    /// `/debug/pprof/profile`: collect for `?seconds=` and return the pprof protobuf.
    // Go: net/http/pprof/pprof.go:144-165
    async fn profile(stream: &mut TcpStream, query: &str) -> io::Result<()> {
        // Go never rejects the parameter here: anything that is not a positive integer becomes a
        // 30 s profile. (Only the *named* profiles, `handler.serveDeltaProfile`, answer 400.)
        // `parse_seconds` never returns anything below 1, so only the cap has to be applied.
        let seconds = parse_seconds(query).min(MAX_SECONDS) as u64;

        // The profiler sleeps for the whole window and unwinds at the end, so it runs on a
        // blocking thread rather than on a worker.
        let collected = tokio::task::spawn_blocking(move || collect(seconds)).await;
        match collected {
            // Go: pprof.go:155-156 — Content-Type and Content-Disposition are set before the
            // profile is started, with no RFC 5987 `filename*` parameter.
            Ok(Ok(body)) => {
                respond(
                    stream,
                    "200 OK",
                    &[
                        ("Content-Type", "application/octet-stream"),
                        ("Content-Disposition", "attachment; filename=\"profile\""),
                    ],
                    &body,
                )
                .await
            }
            // Go: serveError(w, http.StatusInternalServerError, "Could not enable CPU profiling: …")
            Ok(Err(err)) => {
                serve_error(
                    stream,
                    "500 Internal Server Error",
                    &format!("Could not enable CPU profiling: {err}"),
                )
                .await
            }
            Err(err) => {
                serve_error(
                    stream,
                    "500 Internal Server Error",
                    &format!("Could not enable CPU profiling: {err}"),
                )
                .await
            }
        }
    }

    /// Runs the CPU profiler for `seconds` and encodes the report as a pprof protobuf, the exact
    /// format `go tool pprof` expects from Go's endpoint.
    fn collect(seconds: u64) -> Result<Vec<u8>, String> {
        let guard = pprof::ProfilerGuardBuilder::default()
            .frequency(FREQUENCY)
            .blocklist(BLOCKLIST)
            .build()
            .map_err(|err| err.to_string())?;
        std::thread::sleep(Duration::from_secs(seconds));
        let report = guard.report().build().map_err(|err| err.to_string())?;
        let profile = report.pprof().map_err(|err| err.to_string())?;
        let mut body = Vec::new();
        profile
            .write_to_vec(&mut body)
            .map_err(|err| err.to_string())?;
        Ok(body)
    }

    /// `?seconds=N`, always a positive number of seconds.
    ///
    /// Go never fails this parameter: a missing, empty, unparseable, out-of-range, zero or
    /// negative value is silently a [`DEFAULT_SECONDS`] profile.
    // Go: net/http/pprof/pprof.go:146-149
    //   sec, err := strconv.ParseInt(r.FormValue("seconds"), 10, 64)
    //   if sec <= 0 || err != nil { sec = 30 }
    pub(super) fn parse_seconds(query: &str) -> i64 {
        // Go: `r.FormValue` returns the FIRST value for the key (`url.Values.Get`).
        let value = query
            .split('&')
            .find_map(|pair| pair.strip_prefix("seconds="));
        match value.and_then(parse_int) {
            // Go: `sec <= 0` falls back too, even though it parsed.
            Some(sec) if sec > 0 => sec,
            _ => DEFAULT_SECONDS,
        }
    }

    /// `strconv.ParseInt(s, 10, 64)`: an optional sign then decimal digits, nothing else, and
    /// `ErrRange` (here `None`) for anything an `int64` cannot hold.
    // Go: strconv/atoi.go:ParseInt
    fn parse_int(s: &str) -> Option<i64> {
        let (neg, digits) = match s.as_bytes().first() {
            Some(b'+') => (false, &s[1..]),
            Some(b'-') => (true, &s[1..]),
            _ => (false, s),
        };
        if digits.is_empty() {
            // Go: ErrSyntax.
            return None;
        }
        // Go: ErrRange above the `int64` bound — one more in magnitude for a negative value.
        let limit = if neg {
            i64::MAX as u64 + 1
        } else {
            i64::MAX as u64
        };
        let mut n: u64 = 0;
        for b in digits.bytes() {
            if !b.is_ascii_digit() {
                // Go: ErrSyntax.
                return None;
            }
            n = n.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
            if n > limit {
                // Go: ErrRange.
                return None;
            }
        }
        // `n == i64::MAX as u64 + 1` (only reachable when `neg`) is `i64::MIN`.
        Some(if neg {
            (n as i64).wrapping_neg()
        } else {
            n as i64
        })
    }

    /// Reads the request head and returns its first line, or `None` when the client sent nothing
    /// usable.
    async fn read_request_line(stream: &mut TcpStream) -> io::Result<Option<String>> {
        let mut head = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            // An oversized head is a client this endpoint has no business serving.
            if head.len() > MAX_HEAD {
                return Ok(None);
            }
            if let Some(line_end) = find_line_end(&head) {
                // The rest of the head is of no interest: there is no body to consume, and the
                // response closes the connection. Whatever is still in flight is consumed by
                // `drain` before the close, so the client never sees an RST.
                return Ok(String::from_utf8(head[..line_end].to_vec()).ok());
            }
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Ok(None);
            }
            head.extend_from_slice(&chunk[..n]);
        }
    }

    /// Index of the first `\r\n` or `\n`, i.e. the end of the request line.
    pub(super) fn find_line_end(buf: &[u8]) -> Option<usize> {
        let nl = buf.iter().position(|&b| b == b'\n')?;
        Some(if nl > 0 && buf[nl - 1] == b'\r' {
            nl - 1
        } else {
            nl
        })
    }

    /// Go's `serveError`: a plain-text error page with the pprof marker header.
    // Go: net/http/pprof/pprof.go:133-139 — Content-Type text/plain, X-Go-Pprof: 1, no
    // Content-Disposition, and `fmt.Fprintln` adds the newline.
    async fn serve_error(stream: &mut TcpStream, status: &str, txt: &str) -> io::Result<()> {
        let body = format!("{txt}\n");
        respond(
            stream,
            status,
            &[
                ("Content-Type", "text/plain; charset=utf-8"),
                ("X-Go-Pprof", "1"),
            ],
            body.as_bytes(),
        )
        .await
    }

    /// Writes a complete HTTP/1.1 response and closes the connection.
    ///
    /// `X-Content-Type-Options: nosniff` goes on every response, as it does in Go: `Profile` sets
    /// it before anything else, `Index` sets it too, and `http.Error` (behind `http.NotFound`)
    /// sets it as well.
    // Go: net/http/pprof/pprof.go:145, net/http/server.go:Error
    async fn respond(
        stream: &mut TcpStream,
        status: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> io::Result<()> {
        let mut head = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\
             X-Content-Type-Options: nosniff\r\n",
            body.len()
        );
        for (name, value) in headers {
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        if !headers.iter().any(|(name, _)| *name == "Content-Type") {
            head.push_str("Content-Type: text/plain; charset=utf-8\r\n");
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(body).await?;
        stream.flush().await?;
        drain(stream).await;
        stream.shutdown().await
    }

    /// Consumes whatever the client still has in flight before the socket is closed.
    ///
    /// [`read_request_line`] stops at the first `\n`, so the rest of the request head is usually
    /// still in the receive queue. Closing a socket with unread data makes the kernel send an RST
    /// rather than a FIN (Linux and the BSDs both do), and the client then sees `connection reset
    /// by peer` instead of the response it was given — which, for a 30 s profile, means losing
    /// it. Draining first turns that back into a clean close. Bounded in bytes and in time: this
    /// is part of closing the connection, not a read loop.
    async fn drain(stream: &mut TcpStream) {
        /// How long to wait for the rest of a head that may never arrive.
        const TIMEOUT: Duration = Duration::from_millis(200);

        let mut scratch = [0u8; 1024];
        let mut drained = 0usize;
        while drained < MAX_HEAD {
            match tokio::time::timeout(TIMEOUT, stream.read(&mut scratch)).await {
                Ok(Ok(n)) if n > 0 => drained += n,
                // EOF, a read error, or a client that simply stopped talking.
                _ => break,
            }
        }
    }
}

/// Tests for the endpoint above. Declared here rather than inside `server`, because a `#[path]`
/// inside an inline module block resolves against `src/pprof/server/` instead of `src/`.
// Two `cfg` attributes rather than `all(test, ...)`: clippy recognises a plain `cfg(test)` as
// test code, which is what `allow-unwrap-in-tests` keys on.
#[cfg(test)]
#[cfg(all(feature = "pprof", unix))]
#[path = "pprof_server_tests.rs"]
mod server_tests;

#[cfg(test)]
#[path = "pprof_tests.rs"]
mod tests;
