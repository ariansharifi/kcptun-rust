//! TCP test servers on `127.0.0.1` ephemeral ports: [`EchoServer`], [`SinkServer`] and
//! [`SourceServer`], plus stream helpers for the client side of a test.
//!
//! Every server runs on the current tokio runtime and stops when [`shutdown`](EchoServer::shutdown)
//! is awaited or the server value is dropped (open connections are closed as well). A
//! connection still open when the server stops is abandoned: its handler is dropped, so a
//! [`SinkServer`] records nothing for it (records only describe connections that ended on
//! their own). `shutdown` returns only after every connection task has finished.
//!
//! # The deterministic stream
//!
//! [`SourceServer`] and [`write_prng_stream`] send the byte stream of [`PrngStream`]: Go
//! `math/rand/v2` `rand.NewPCG(seed, 0)`, eight little-endian bytes per `Uint64`, truncated
//! to the length. A Go peer produces the same bytes with govectors' `randBytes`, so hashes can
//! be compared across languages.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::rng::Pcg;

const BUF_SIZE: usize = 64 * 1024;
/// First pause after a failed `accept` (e.g. `EMFILE`); doubles up to [`ACCEPT_BACKOFF_MAX`],
/// like Go's `net/http.Server`.
const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(5);
/// Longest pause between failed `accept`s.
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// The deterministic byte stream described in the [module docs](self).
#[derive(Clone, Debug)]
pub struct PrngStream {
    rng: Pcg,
    remaining: u64,
    word: [u8; 8],
    word_pos: usize,
}

impl PrngStream {
    /// A stream of `len` bytes for `seed`.
    pub fn new(seed: u64, len: u64) -> Self {
        PrngStream {
            rng: Pcg::new(seed, 0),
            remaining: len,
            word: [0; 8],
            word_pos: 8,
        }
    }

    /// Bytes not yet produced.
    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    /// Fills the front of `buf` with the next bytes and returns how many were written (0 at
    /// the end). The output does not depend on how the stream is split into calls.
    pub fn fill(&mut self, buf: &mut [u8]) -> usize {
        let n = buf
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        for b in &mut buf[..n] {
            if self.word_pos == 8 {
                self.word = self.rng.next_u64().to_le_bytes();
                self.word_pos = 0;
            }
            *b = self.word[self.word_pos];
            self.word_pos += 1;
        }
        self.remaining -= n as u64;
        n
    }

    /// The whole stream as a vector (for small lengths).
    pub fn to_vec(seed: u64, len: usize) -> Vec<u8> {
        let mut v = vec![0; len];
        PrngStream::new(seed, len as u64).fill(&mut v);
        v
    }

    /// Lower-case hex SHA-256 of the stream for `(seed, len)`.
    pub fn sha256_hex(seed: u64, len: u64) -> String {
        let mut s = PrngStream::new(seed, len);
        let mut h = Sha256::new();
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            let n = s.fill(&mut buf);
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        hex::encode(h.finalize())
    }
}

/// Writes the `(seed, len)` [`PrngStream`] to `w` (without closing it).
pub async fn write_prng_stream<W: AsyncWrite + Unpin>(
    w: &mut W,
    seed: u64,
    len: u64,
) -> io::Result<()> {
    let mut s = PrngStream::new(seed, len);
    let mut buf = vec![0u8; BUF_SIZE];
    loop {
        let n = s.fill(&mut buf);
        if n == 0 {
            return w.flush().await;
        }
        w.write_all(&buf[..n]).await?;
    }
}

/// Reads `r` to EOF and returns the byte count and lower-case hex SHA-256.
pub async fn hash_reader<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<(u64, String)> {
    let mut h = Sha256::new();
    let mut total = 0u64;
    let mut buf = vec![0u8; BUF_SIZE];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            return Ok((total, hex::encode(h.finalize())));
        }
        h.update(&buf[..n]);
        total += n as u64;
    }
}

/// Returns `conn` together with a duplicated std handle to the same socket.
fn split_closer(conn: TcpStream) -> io::Result<(TcpStream, std::net::TcpStream)> {
    let std_conn = conn.into_std()?;
    let closer = std_conn.try_clone()?;
    std_conn.set_nonblocking(true)?;
    Ok((TcpStream::from_std(std_conn)?, closer))
}

/// Accept loop and shutdown plumbing shared by the servers.
#[derive(Debug)]
struct Runner {
    addr: SocketAddr,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
    /// Closed (returns `None`) once the accept task and every connection task have ended:
    /// each of them holds a clone of the matching sender.
    done: mpsc::Receiver<()>,
}

impl Runner {
    async fn start<F, Fut>(handle: F) -> io::Result<Runner>
    where
        F: Fn(TcpStream) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let listener = {
            let _fd = crate::fd_lock(); // see FD_LOCK: keep the listener out of spawned children
            std::net::TcpListener::bind("127.0.0.1:0")?
        };
        listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(listener)?;
        let addr = listener.local_addr()?;
        let (stop, mut stop_rx) = watch::channel(false);
        let conn_stop = stop.subscribe();
        let (done_tx, done) = mpsc::channel::<()>(1);
        let task = tokio::spawn(async move {
            let mut backoff = Duration::ZERO;
            loop {
                let accepted = tokio::select! {
                    _ = stop_rx.wait_for(|s| *s) => return,
                    r = listener.accept() => r,
                };
                let conn = match accepted {
                    Ok((conn, _)) => {
                        backoff = Duration::ZERO;
                        conn
                    }
                    Err(_) => {
                        // Back off instead of spinning (e.g. EMFILE), still honouring stop.
                        backoff = (backoff * 2).clamp(ACCEPT_BACKOFF_MIN, ACCEPT_BACKOFF_MAX);
                        tokio::select! {
                            _ = stop_rx.wait_for(|s| *s) => return,
                            () = tokio::time::sleep(backoff) => continue,
                        }
                    }
                };
                let _ = conn.set_nodelay(true);
                // A second handle to the socket, to shut it down on stop even if a
                // child process inherited a copy of the fd (macOS, see FD_LOCK).
                let Ok((conn, closer)) = split_closer(conn) else {
                    continue;
                };
                let fut = handle(conn);
                let mut rx = conn_stop.clone();
                let done_tx = done_tx.clone();
                tokio::spawn(async move {
                    let _done = done_tx;
                    tokio::select! {
                        _ = rx.wait_for(|s| *s) => {
                            let _ = closer.shutdown(std::net::Shutdown::Both);
                        }
                        () = fut => {}
                    }
                });
            }
        });
        Ok(Runner {
            addr,
            stop,
            task: Some(task),
            done,
        })
    }

    /// Signals stop, then waits for the accept task and all connection tasks to end.
    async fn shutdown(&mut self) {
        let _ = self.stop.send(true);
        if let Some(t) = self.task.take() {
            let _ = t.await;
        }
        while self.done.recv().await.is_some() {}
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

/// Echoes every byte back on each connection; half-closes after the peer's EOF.
#[derive(Debug)]
pub struct EchoServer {
    runner: Runner,
    connections: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
}

impl EchoServer {
    /// Starts the server on `127.0.0.1` with an ephemeral port.
    pub async fn start() -> io::Result<Self> {
        let connections = Arc::new(AtomicU64::new(0));
        let bytes = Arc::new(AtomicU64::new(0));
        let (c, b) = (connections.clone(), bytes.clone());
        let runner = Runner::start(move |mut conn| {
            c.fetch_add(1, Ordering::SeqCst);
            let b = b.clone();
            async move {
                let mut buf = vec![0u8; BUF_SIZE];
                loop {
                    match conn.read(&mut buf).await {
                        Ok(0) => {
                            let _ = conn.shutdown().await;
                            return;
                        }
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                            b.fetch_add(n as u64, Ordering::SeqCst);
                        }
                        Err(_) => return,
                    }
                }
            }
        })
        .await?;
        Ok(EchoServer {
            runner,
            connections,
            bytes,
        })
    }

    /// Listening address.
    pub fn addr(&self) -> SocketAddr {
        self.runner.addr
    }

    /// Connections accepted so far.
    pub fn connections(&self) -> u64 {
        self.connections.load(Ordering::SeqCst)
    }

    /// Bytes echoed so far (all connections).
    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::SeqCst)
    }

    /// Stops accepting, closes open connections and waits until every server task has ended.
    pub async fn shutdown(mut self) {
        self.runner.shutdown().await;
    }
}

/// Result of one connection to a [`SinkServer`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SinkRecord {
    /// Bytes received.
    pub bytes: u64,
    /// Lower-case hex SHA-256 of the bytes received.
    pub sha256: String,
    /// The read error that ended the connection, if it did not end with a clean EOF.
    pub error: Option<String>,
}

/// Reads every connection to EOF, counting and hashing the bytes. One [`SinkRecord`] per
/// connection, in completion order.
#[derive(Debug)]
pub struct SinkServer {
    runner: Runner,
    total: Arc<AtomicU64>,
    records: watch::Receiver<Vec<SinkRecord>>,
}

impl SinkServer {
    /// Starts the server on `127.0.0.1` with an ephemeral port.
    pub async fn start() -> io::Result<Self> {
        let total = Arc::new(AtomicU64::new(0));
        let (rec_tx, records) = watch::channel(Vec::new());
        let rec_tx = Arc::new(rec_tx);
        let t = total.clone();
        let runner = Runner::start(move |mut conn| {
            let t = t.clone();
            let rec_tx = rec_tx.clone();
            async move {
                let mut h = Sha256::new();
                let mut n_total = 0u64;
                let mut buf = vec![0u8; BUF_SIZE];
                let error = loop {
                    match conn.read(&mut buf).await {
                        Ok(0) => break None,
                        Ok(n) => {
                            h.update(&buf[..n]);
                            n_total += n as u64;
                            t.fetch_add(n as u64, Ordering::SeqCst);
                        }
                        Err(e) => break Some(e.to_string()),
                    }
                };
                let rec = SinkRecord {
                    bytes: n_total,
                    sha256: hex::encode(h.finalize()),
                    error,
                };
                rec_tx.send_modify(|v| v.push(rec));
            }
        })
        .await?;
        Ok(SinkServer {
            runner,
            total,
            records,
        })
    }

    /// Listening address.
    pub fn addr(&self) -> SocketAddr {
        self.runner.addr
    }

    /// Bytes received so far over all connections (live, including open connections).
    pub fn total_bytes(&self) -> u64 {
        self.total.load(Ordering::SeqCst)
    }

    /// Records of the connections that have finished so far.
    pub fn records(&self) -> Vec<SinkRecord> {
        self.records.borrow().clone()
    }

    /// Waits until at least `n` connections have finished, then returns all records.
    pub async fn wait_for_records(
        &self,
        n: usize,
        timeout: Duration,
    ) -> io::Result<Vec<SinkRecord>> {
        let mut rx = self.records.clone();
        match tokio::time::timeout(timeout, rx.wait_for(|v| v.len() >= n)).await {
            Ok(Ok(v)) => Ok(v.clone()),
            Ok(Err(_)) => Err(io::Error::other("sink server stopped")),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "timed out after {timeout:?} waiting for {n} sink connections (have {})",
                    self.records.borrow().len()
                ),
            )),
        }
    }

    /// Stops accepting, closes open connections and waits until every server task has ended.
    pub async fn shutdown(mut self) {
        self.runner.shutdown().await;
    }
}

/// Sends the `(seed, len)` [`PrngStream`] on every connection, then half-closes and drains
/// the peer until EOF (so unread input never turns the close into a reset).
#[derive(Debug)]
pub struct SourceServer {
    runner: Runner,
    seed: u64,
    len: u64,
    completed: Arc<AtomicU64>,
}

impl SourceServer {
    /// Starts the server on `127.0.0.1` with an ephemeral port.
    pub async fn start(seed: u64, len: u64) -> io::Result<Self> {
        let completed = Arc::new(AtomicU64::new(0));
        let c = completed.clone();
        let runner = Runner::start(move |mut conn| {
            let c = c.clone();
            async move {
                if write_prng_stream(&mut conn, seed, len).await.is_err() {
                    return;
                }
                if conn.shutdown().await.is_err() {
                    return;
                }
                c.fetch_add(1, Ordering::SeqCst);
                let mut buf = vec![0u8; 4096];
                while matches!(conn.read(&mut buf).await, Ok(n) if n > 0) {}
            }
        })
        .await?;
        Ok(SourceServer {
            runner,
            seed,
            len,
            completed,
        })
    }

    /// Listening address.
    pub fn addr(&self) -> SocketAddr {
        self.runner.addr
    }

    /// Bytes sent per connection.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// True if the stream length is 0.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Stream seed.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// SHA-256 (lower-case hex) a client must see.
    pub fn expected_sha256(&self) -> String {
        PrngStream::sha256_hex(self.seed, self.len)
    }

    /// Connections to which the whole stream has been written.
    pub fn completed(&self) -> u64 {
        self.completed.load(Ordering::SeqCst)
    }

    /// Stops accepting, closes open connections and waits until every server task has ended.
    pub async fn shutdown(mut self) {
        self.runner.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::{govectors_rng, rand_bytes};
    use crate::vectors::sha256_hex;

    const T: Duration = Duration::from_secs(10);

    #[test]
    fn prng_stream_is_split_independent_and_matches_go_rand_bytes() {
        let whole = PrngStream::to_vec(42, 1001);
        let mut s = PrngStream::new(42, 1001);
        let mut parts = Vec::new();
        for chunk in [1usize, 7, 8, 13, 500, 1000] {
            let mut b = vec![0; chunk];
            let n = s.fill(&mut b);
            parts.extend_from_slice(&b[..n]);
        }
        assert_eq!(parts, whole);
        assert_eq!(s.remaining(), 0);
        // Same as govectors' randBytes(rand.New(rand.NewPCG(seed, 0)), n).
        assert_eq!(whole, rand_bytes(&mut Pcg::new(42, 0), 1001));
        assert_ne!(whole, rand_bytes(&mut govectors_rng("x", 0), 1001));
        assert_eq!(PrngStream::sha256_hex(42, 1001), sha256_hex(&whole));
        assert_eq!(
            PrngStream::sha256_hex(1, 0),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[tokio::test]
    async fn echo_round_trip_and_half_close() {
        let srv = EchoServer::start().await.unwrap();
        assert!(srv.addr().ip().is_loopback() && srv.addr().port() != 0);
        let conn = TcpStream::connect(srv.addr()).await.unwrap();
        let (mut r, mut w) = conn.into_split();
        let len = 300_000u64;
        let writer = tokio::spawn(async move {
            write_prng_stream(&mut w, 5, len).await.unwrap();
            w.shutdown().await.unwrap();
        });
        let (n, sha) = tokio::time::timeout(T, hash_reader(&mut r))
            .await
            .unwrap()
            .unwrap();
        writer.await.unwrap();
        assert_eq!(n, len);
        assert_eq!(sha, PrngStream::sha256_hex(5, len));
        assert_eq!(srv.connections(), 1);
        assert_eq!(srv.bytes(), len);
        srv.shutdown().await;
    }

    #[tokio::test]
    async fn sink_counts_and_hashes_each_connection() {
        let srv = SinkServer::start().await.unwrap();
        for (seed, len) in [(1u64, 0u64), (2, 70_000), (3, 1)] {
            let mut c = TcpStream::connect(srv.addr()).await.unwrap();
            write_prng_stream(&mut c, seed, len).await.unwrap();
            c.shutdown().await.unwrap();
            let mut rest = Vec::new();
            c.read_to_end(&mut rest).await.unwrap(); // server closes after our EOF
            assert!(rest.is_empty());
        }
        let recs = srv.wait_for_records(3, T).await.unwrap();
        let mut got: Vec<(u64, String)> =
            recs.iter().map(|r| (r.bytes, r.sha256.clone())).collect();
        got.sort();
        let mut want: Vec<(u64, String)> = [(1u64, 0u64), (2, 70_000), (3, 1)]
            .iter()
            .map(|&(s, l)| (l, PrngStream::sha256_hex(s, l)))
            .collect();
        want.sort();
        assert_eq!(got, want);
        assert!(recs.iter().all(|r| r.error.is_none()));
        assert_eq!(srv.total_bytes(), 70_001);
        assert_eq!(srv.records().len(), 3);
        srv.shutdown().await;
    }

    #[tokio::test]
    async fn sink_wait_times_out() {
        let srv = SinkServer::start().await.unwrap();
        let e = srv
            .wait_for_records(1, Duration::from_millis(50))
            .await
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn source_sends_expected_stream_to_each_client() {
        let srv = SourceServer::start(9, 200_000).await.unwrap();
        assert_eq!((srv.seed(), srv.len(), srv.is_empty()), (9, 200_000, false));
        for _ in 0..2 {
            let mut c = TcpStream::connect(srv.addr()).await.unwrap();
            let (n, sha) = tokio::time::timeout(T, hash_reader(&mut c))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(n, 200_000);
            assert_eq!(sha, srv.expected_sha256());
        }
        assert_eq!(srv.completed(), 2);
        srv.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_stops_accepting_and_closes_connections() {
        let srv = EchoServer::start().await.unwrap();
        let addr = srv.addr();
        let mut open = TcpStream::connect(addr).await.unwrap();
        open.write_all(b"ping").await.unwrap();
        let mut b = [0u8; 4];
        open.read_exact(&mut b).await.unwrap();
        srv.shutdown().await;
        // The open connection is closed by the server (EOF or reset).
        let r = tokio::time::timeout(T, open.read(&mut b)).await.unwrap();
        assert!(matches!(r, Ok(0) | Err(_)));
        // New connections are refused once the listener is gone.
        assert!(connect_refused(addr).await, "listener still accepting");
    }

    /// Reports whether a fresh connection to `addr` is refused.
    ///
    /// Under load on macOS, tokio's non-blocking connect can resolve `Ok`
    /// before `SO_ERROR` reflects the RST, which yields a socket that is
    /// already dead (`peer_addr` fails, or the first read returns EOF or an
    /// error). Such a connection counts as refused. A live listener (echo or
    /// sink) never closes a fresh idle connection, so the read times out
    /// and the connection counts as accepted.
    async fn connect_refused(addr: SocketAddr) -> bool {
        match TcpStream::connect(addr).await {
            Err(_) => true,
            Ok(mut c) => {
                if c.peer_addr().is_err() {
                    return true;
                }
                let mut b = [0u8; 1];
                matches!(
                    tokio::time::timeout(Duration::from_millis(200), c.read(&mut b)).await,
                    Ok(Ok(0) | Err(_))
                )
            }
        }
    }

    #[tokio::test]
    async fn sink_shutdown_abandons_open_connections_without_records() {
        let srv = SinkServer::start().await.unwrap();
        let rx = srv.records.clone();
        let total = srv.total.clone();
        let mut open = TcpStream::connect(srv.addr()).await.unwrap();
        open.write_all(b"partial").await.unwrap();
        tokio::time::timeout(T, async {
            while total.load(Ordering::SeqCst) < 7 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        srv.shutdown().await;
        // Every connection task has ended by now, and the cut connection left no record.
        assert!(rx.borrow().is_empty());
        let mut b = [0u8; 1];
        let r = tokio::time::timeout(T, open.read(&mut b)).await.unwrap();
        assert!(matches!(r, Ok(0) | Err(_)));
    }

    #[tokio::test]
    async fn drop_stops_server() {
        let srv = SinkServer::start().await.unwrap();
        let addr = srv.addr();
        let mut open = TcpStream::connect(addr).await.unwrap();
        open.write_all(b"data").await.unwrap();
        drop(srv);
        // Open connections are closed too.
        let mut b = [0u8; 4];
        let r = tokio::time::timeout(T, open.read(&mut b)).await.unwrap();
        assert!(matches!(r, Ok(0) | Err(_)));
        // The accept task sees the stop signal and drops the listener.
        let mut refused = false;
        for _ in 0..100 {
            if connect_refused(addr).await {
                refused = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(refused);
    }
}
