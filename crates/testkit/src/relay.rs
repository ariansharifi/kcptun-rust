//! Real-time lossy UDP relay, for driving a *live* peer (a Go process, another tokio task)
//! over an impaired path.
//!
//! [`netsim::Link`](crate::netsim) simulates a link on **virtual** time and is the right tool
//! for deterministic single-process simulations. It cannot be used against a real socket: a Go
//! `kcpecho` peer runs on the wall clock and nobody can step its time. [`Relay`] fills that
//! gap. It binds one UDP socket on `127.0.0.1`, forwards datagrams between the first peer that
//! writes to it (the *client*) and a fixed [`upstream`](Relay::upstream) address, and applies
//! the same impairments netem and [`netsim`](crate::netsim) do, per direction:
//!
//! 1. **loss**: the datagram is dropped with probability `loss`;
//! 2. **delay**: every datagram is held for `delay_ms`;
//! 3. **reorder**: with probability `reorder` a datagram is held for a further
//!    `reorder_delay_ms`, so later datagrams overtake it.
//!
//! Each held datagram is a separate task, so a non-zero `delay` may itself reorder: tests that
//! need an order-preserving delay must use [`netsim::Link`](crate::netsim) instead.
//!
//! Both peers keep seeing a single remote address (the relay's), so a KCP listener treats the
//! relayed traffic as one session and the relay needs no session tracking.
//!
//! **Determinism.** The PRNG ([`Pcg`], seeded from [`RelayConfig::seed`]) is drawn from in
//! arrival order by the single relay task, so a given sequence of arrivals always produces the
//! same drops. Arrival order itself comes from the network, so a relayed run is *not*
//! reproducible the way a [`netsim`](crate::netsim) simulation is; tests over a relay must
//! assert on outcomes (every byte arrived) and on counter ranges, never on an exact trace.
//!
//! ```no_run
//! # async fn f() -> std::io::Result<()> {
//! use kcptun_testkit::relay::{Relay, RelayConfig};
//! let upstream = "127.0.0.1:22000".parse().expect("addr");
//! let relay = Relay::start(upstream, RelayConfig::new(7).loss(0.05).reorder(0.02, 40)).await?;
//! let dial_here = relay.addr(); // point the client at this instead of `upstream`
//! # let _ = dial_here;
//! # Ok(())
//! # }
//! ```

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use crate::rng::Pcg;

/// Largest datagram the relay forwards; bigger ones are truncated by the kernel on receive and
/// counted as [`oversized`](RelayStats::oversized). KCP never sends more than
/// `kcptun_kcp::crypt::MTU_LIMIT` (1500) bytes.
pub const MAX_DATAGRAM: usize = 2048;

/// Socket buffer the relay asks the kernel for, in both directions: kcptun's `-sockbuf` default,
/// which both Rust peers and the Go `kcpecho` peer set on their own sockets.
///
/// Without it the relay would be the only socket in the path left at the kernel default
/// (`net.core.rmem_default` is 64 KiB on Linux, about 40 datagrams of headroom), and it would
/// drop a large share of a KCP flow *before* [`recv_from`](tokio::net::UdpSocket::recv_from) ever
/// saw it: loss the impairment model neither chose nor counted.
pub const SOCK_BUFFER: usize = 4 * 1024 * 1024;

/// Which way a datagram travels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Client → upstream.
    Up,
    /// Upstream → client.
    Down,
}

impl Direction {
    /// `"up"` or `"down"`.
    pub fn tag(self) -> &'static str {
        match self {
            Direction::Up => "up",
            Direction::Down => "down",
        }
    }
}

/// Impairments of a [`Relay`]. Build it with [`RelayConfig::new`] and the setters; the setters
/// change both directions, the `_up`/`_down` ones only one.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RelayConfig {
    /// PRNG seed; the only source of randomness.
    pub seed: u64,
    /// Client → upstream loss probability.
    pub loss_up: f64,
    /// Upstream → client loss probability.
    pub loss_down: f64,
    /// One-way delay in milliseconds, applied in both directions.
    pub delay_ms: u64,
    /// Probability that a datagram is held back by `reorder_delay_ms`.
    pub reorder: f64,
    /// Extra delay of a reordered datagram in milliseconds.
    pub reorder_delay_ms: u64,
}

#[track_caller]
fn check_probability(what: &str, p: f64) {
    assert!(
        (0.0..=1.0).contains(&p),
        "relay: {what} probability {p} is not in [0, 1]"
    );
}

impl RelayConfig {
    /// A perfect relay (no loss, delay or reordering) with the given seed.
    pub fn new(seed: u64) -> Self {
        RelayConfig {
            seed,
            loss_up: 0.0,
            loss_down: 0.0,
            delay_ms: 0,
            reorder: 0.0,
            reorder_delay_ms: 0,
        }
    }

    /// Sets the loss probability of both directions.
    pub fn loss(self, p: f64) -> Self {
        self.loss_up(p).loss_down(p)
    }

    /// Sets the client → upstream loss probability.
    pub fn loss_up(mut self, p: f64) -> Self {
        check_probability("loss", p);
        self.loss_up = p;
        self
    }

    /// Sets the upstream → client loss probability.
    pub fn loss_down(mut self, p: f64) -> Self {
        check_probability("loss", p);
        self.loss_down = p;
        self
    }

    /// Sets the one-way delay (milliseconds).
    pub fn delay(mut self, ms: u64) -> Self {
        self.delay_ms = ms;
        self
    }

    /// Holds a datagram for `extra_delay_ms` more with probability `p`, so later datagrams
    /// overtake it.
    pub fn reorder(mut self, p: f64, extra_delay_ms: u64) -> Self {
        check_probability("reorder", p);
        self.reorder = p;
        self.reorder_delay_ms = extra_delay_ms;
        self
    }

    /// The loss probability of `dir`.
    pub fn loss_of(&self, dir: Direction) -> f64 {
        match dir {
            Direction::Up => self.loss_up,
            Direction::Down => self.loss_down,
        }
    }
}

/// Per-direction counters of a [`Relay`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirStats {
    /// Datagrams received by the relay.
    pub received: u64,
    /// Bytes received by the relay.
    pub received_bytes: u64,
    /// Datagrams forwarded (a delayed one counts when it is handed to the socket).
    pub forwarded: u64,
    /// Datagrams dropped by the loss model.
    pub lost: u64,
    /// Datagrams held back for reordering.
    pub reordered: u64,
}

/// A snapshot of a [`Relay`]'s counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayStats {
    /// Client → upstream.
    pub up: DirStats,
    /// Upstream → client.
    pub down: DirStats,
    /// Datagrams from the upstream that arrived before any client did, so there was nowhere to
    /// send them.
    pub no_client: u64,
    /// Datagrams that filled the whole receive buffer and may have been truncated.
    pub oversized: u64,
    /// Sends that the socket refused.
    pub send_errors: u64,
}

impl RelayStats {
    /// Counters of one direction.
    pub fn dir(&self, dir: Direction) -> DirStats {
        match dir {
            Direction::Up => self.up,
            Direction::Down => self.down,
        }
    }

    /// Datagrams dropped in both directions.
    pub fn lost(&self) -> u64 {
        self.up.lost + self.down.lost
    }
}

/// The live counters behind [`RelayStats`].
#[derive(Debug, Default)]
struct Counters {
    up: AtomicDirStats,
    down: AtomicDirStats,
    no_client: AtomicU64,
    oversized: AtomicU64,
    send_errors: AtomicU64,
}

#[derive(Debug, Default)]
struct AtomicDirStats {
    received: AtomicU64,
    received_bytes: AtomicU64,
    forwarded: AtomicU64,
    lost: AtomicU64,
    reordered: AtomicU64,
}

impl AtomicDirStats {
    fn snapshot(&self) -> DirStats {
        DirStats {
            received: self.received.load(Ordering::Relaxed),
            received_bytes: self.received_bytes.load(Ordering::Relaxed),
            forwarded: self.forwarded.load(Ordering::Relaxed),
            lost: self.lost.load(Ordering::Relaxed),
            reordered: self.reordered.load(Ordering::Relaxed),
        }
    }
}

impl Counters {
    fn dir(&self, dir: Direction) -> &AtomicDirStats {
        match dir {
            Direction::Up => &self.up,
            Direction::Down => &self.down,
        }
    }

    fn snapshot(&self) -> RelayStats {
        RelayStats {
            up: self.up.snapshot(),
            down: self.down.snapshot(),
            no_client: self.no_client.load(Ordering::Relaxed),
            oversized: self.oversized.load(Ordering::Relaxed),
            send_errors: self.send_errors.load(Ordering::Relaxed),
        }
    }
}

/// A running lossy UDP relay. Dropping it stops the relay task and releases the socket.
#[derive(Debug)]
pub struct Relay {
    addr: SocketAddr,
    upstream: SocketAddr,
    cfg: RelayConfig,
    recv_buffer_size: usize,
    counters: Arc<Counters>,
    stopped: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl Relay {
    /// Binds a relay socket on `127.0.0.1` (ephemeral port) that forwards to `upstream`, and
    /// spawns its task. Point the client at [`addr`](Self::addr).
    pub async fn start(upstream: SocketAddr, cfg: RelayConfig) -> io::Result<Relay> {
        let socket = {
            let _guard = crate::fd_lock();
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            socket.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).into())?;
            socket
        };
        // The relay is a router, not a peer: it must not be the bottleneck. A kernel that
        // refuses the size (or caps it at `net.core.rmem_max`) is fine; the achieved value is
        // reported by `recv_buffer_size`.
        let _ = socket.set_recv_buffer_size(SOCK_BUFFER);
        let _ = socket.set_send_buffer_size(SOCK_BUFFER);
        let recv_buffer_size = socket.recv_buffer_size().unwrap_or(0);
        let socket = std::net::UdpSocket::from(socket);
        socket.set_nonblocking(true)?;
        let socket = Arc::new(UdpSocket::from_std(socket)?);
        let addr = socket.local_addr()?;
        let counters = Arc::new(Counters::default());
        let stopped = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(run(
            Arc::clone(&socket),
            upstream,
            cfg,
            Arc::clone(&counters),
            Arc::clone(&stopped),
        ));
        Ok(Relay {
            addr,
            upstream,
            cfg,
            recv_buffer_size,
            counters,
            stopped,
            task,
        })
    }

    /// The address clients send to.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The address datagrams are forwarded to.
    pub fn upstream(&self) -> SocketAddr {
        self.upstream
    }

    /// The impairments in force.
    pub fn config(&self) -> &RelayConfig {
        &self.cfg
    }

    /// The receive buffer the kernel actually granted (it may cap [`SOCK_BUFFER`] at
    /// `net.core.rmem_max`, and Linux reports twice what was asked for). Zero if the kernel would
    /// not say.
    pub fn recv_buffer_size(&self) -> usize {
        self.recv_buffer_size
    }

    /// The counters so far.
    pub fn stats(&self) -> RelayStats {
        self.counters.snapshot()
    }

    /// Stops the relay task and releases the socket. Datagrams still waiting out a delay are
    /// dropped.
    pub fn shutdown(self) {
        drop(self);
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        // The delayed-send tasks hold an `Arc<UdpSocket>` and cannot be aborted from here, so
        // the flag tells them not to send (and to drop their socket handle) when they wake.
        self.stopped.store(true, Ordering::Relaxed);
        self.task.abort();
    }
}

/// The relay task: receive, impair, forward. Ends when the socket fails (the relay was
/// dropped): an error on a single send is counted and the loop continues, as a real router
/// would.
async fn run(
    socket: Arc<UdpSocket>,
    upstream: SocketAddr,
    cfg: RelayConfig,
    counters: Arc<Counters>,
    stopped: Arc<AtomicBool>,
) {
    let mut rng = Pcg::new(cfg.seed, 0);
    let mut buf = vec![0u8; MAX_DATAGRAM];
    // The first peer that is not the upstream; every later datagram from the upstream goes
    // back to it. Only this task touches it.
    let mut client: Option<SocketAddr> = None;

    loop {
        let (n, from) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => return,
        };
        let (dir, to) = if from == upstream {
            match client {
                Some(to) => (Direction::Down, to),
                None => {
                    counters.no_client.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
        } else {
            client = Some(from);
            (Direction::Up, upstream)
        };

        let stats = counters.dir(dir);
        stats.received.fetch_add(1, Ordering::Relaxed);
        stats.received_bytes.fetch_add(n as u64, Ordering::Relaxed);
        if n == buf.len() {
            counters.oversized.fetch_add(1, Ordering::Relaxed);
        }

        if rng.chance(cfg.loss_of(dir)) {
            stats.lost.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        let mut hold_ms = cfg.delay_ms;
        if cfg.reorder_delay_ms > 0 && rng.chance(cfg.reorder) {
            hold_ms += cfg.reorder_delay_ms;
            stats.reordered.fetch_add(1, Ordering::Relaxed);
        }

        if hold_ms == 0 {
            match socket.send_to(&buf[..n], to).await {
                Ok(_) => stats.forwarded.fetch_add(1, Ordering::Relaxed),
                Err(_) => counters.send_errors.fetch_add(1, Ordering::Relaxed),
            };
        } else {
            let datagram = buf[..n].to_vec();
            let socket = Arc::clone(&socket);
            let counters = Arc::clone(&counters);
            let stopped = Arc::clone(&stopped);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(hold_ms)).await;
                if stopped.load(Ordering::Relaxed) {
                    return;
                }
                match socket.send_to(&datagram, to).await {
                    Ok(_) => counters.dir(dir).forwarded.fetch_add(1, Ordering::Relaxed),
                    Err(_) => counters.send_errors.fetch_add(1, Ordering::Relaxed),
                };
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// An upstream socket that echoes every datagram back to its sender.
    async fn echo_upstream() -> io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
        let socket = {
            let _guard = crate::fd_lock();
            std::net::UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?
        };
        socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(socket)?;
        let addr = socket.local_addr()?;
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                if socket.send_to(&buf[..n], from).await.is_err() {
                    return;
                }
            }
        });
        Ok((addr, task))
    }

    /// An upstream socket that swallows everything, so nothing travels back down.
    async fn sink_upstream() -> io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
        let socket = client_socket().await?;
        let addr = socket.local_addr()?;
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            while socket.recv_from(&mut buf).await.is_ok() {}
        });
        Ok((addr, task))
    }

    async fn client_socket() -> io::Result<UdpSocket> {
        let socket = {
            let _guard = crate::fd_lock();
            std::net::UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?
        };
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket)
    }

    /// Waits until `cond` holds, or fails the test after five seconds.
    async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    #[tokio::test]
    async fn a_perfect_relay_forwards_every_datagram_both_ways() {
        let (upstream, _echo) = echo_upstream().await.expect("upstream");
        let relay = Relay::start(upstream, RelayConfig::new(1))
            .await
            .expect("relay");
        assert_eq!(relay.upstream(), upstream);
        assert_eq!(relay.config().seed, 1);
        assert!(
            relay.recv_buffer_size() > 0,
            "the relay asks for a {SOCK_BUFFER}-byte receive buffer and reports what it got"
        );
        let cli = client_socket().await.expect("client");

        let mut buf = [0u8; 64];
        for i in 0..20u8 {
            cli.send_to(&[i; 10], relay.addr()).await.expect("send");
            let (n, from) = tokio::time::timeout(Duration::from_secs(5), cli.recv_from(&mut buf))
                .await
                .expect("echo in time")
                .expect("recv");
            assert_eq!(&buf[..n], &[i; 10]);
            assert_eq!(from, relay.addr(), "the client only ever sees the relay");
        }

        let stats = relay.stats();
        assert_eq!(stats.up.received, 20);
        assert_eq!(stats.up.forwarded, 20);
        assert_eq!(stats.up.received_bytes, 200);
        assert_eq!(stats.down.received, 20);
        assert_eq!(stats.down.forwarded, 20);
        assert_eq!(stats.lost(), 0);
        assert_eq!(stats.no_client, 0);
        assert_eq!(stats.oversized, 0);
        assert_eq!(stats.send_errors, 0);
        assert_eq!(stats.dir(Direction::Up), stats.up);
        assert_eq!(stats.dir(Direction::Down), stats.down);
    }

    #[tokio::test]
    async fn loss_drops_datagrams_of_the_configured_direction_only() {
        let (upstream, _echo) = echo_upstream().await.expect("upstream");
        // Everything client -> upstream is dropped, nothing the other way.
        let relay = Relay::start(upstream, RelayConfig::new(2).loss_up(1.0))
            .await
            .expect("relay");
        assert_eq!(relay.config().loss_of(Direction::Up), 1.0);
        assert_eq!(relay.config().loss_of(Direction::Down), 0.0);
        let cli = client_socket().await.expect("client");

        for _ in 0..10 {
            cli.send_to(b"x", relay.addr()).await.expect("send");
        }
        let mut buf = [0u8; 64];
        let quiet = tokio::time::timeout(Duration::from_millis(300), cli.recv_from(&mut buf)).await;
        assert!(quiet.is_err(), "nothing must reach the upstream");

        let stats = relay.stats();
        assert_eq!(stats.up.received, 10);
        assert_eq!(stats.up.lost, 10);
        assert_eq!(stats.up.forwarded, 0);
        assert_eq!(stats.down.received, 0);
    }

    #[tokio::test]
    async fn a_middling_loss_rate_drops_roughly_that_share() {
        // A sink upstream, so nothing comes back down and only the client's datagrams compete
        // for the relay's receive buffer.
        let (upstream, _sink) = sink_upstream().await.expect("upstream");
        let relay = Relay::start(upstream, RelayConfig::new(3).loss_up(0.5))
            .await
            .expect("relay");
        let cli = client_socket().await.expect("client");
        const N: u64 = 400;
        // Sent in small bursts, waiting for the relay to drain each one: the relay asks for a
        // `SOCK_BUFFER`-byte receive buffer but the kernel may cap it, and a kernel drop would be
        // counted as neither lost nor forwarded, so the assertion below would be meaningless.
        let mut sent = 0;
        while sent < N {
            for _ in 0..10 {
                cli.send_to(b"x", relay.addr()).await.expect("send");
                sent += 1;
            }
            wait_for("the relay to drain the burst", || {
                relay.stats().up.received >= sent
            })
            .await;
        }
        let stats = relay.stats();
        assert_eq!(stats.up.received, N, "every datagram arrived at the relay");
        assert_eq!(stats.up.lost + stats.up.forwarded, N);
        // Binomial(400, 0.5) is inside [150, 250] with overwhelming probability, and the seed is
        // fixed anyway.
        assert!(
            (150..=250).contains(&stats.up.lost),
            "lost {} of {N}",
            stats.up.lost
        );
    }

    #[tokio::test]
    async fn a_delay_holds_every_datagram() {
        let (upstream, _echo) = echo_upstream().await.expect("upstream");
        let relay = Relay::start(upstream, RelayConfig::new(4).delay(60))
            .await
            .expect("relay");
        let cli = client_socket().await.expect("client");
        let mut buf = [0u8; 64];
        let start = Instant::now();
        cli.send_to(b"ping", relay.addr()).await.expect("send");
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), cli.recv_from(&mut buf))
            .await
            .expect("echo in time")
            .expect("recv");
        assert_eq!(&buf[..n], b"ping");
        // 60 ms each way.
        assert!(
            start.elapsed() >= Duration::from_millis(110),
            "{:?}",
            start.elapsed()
        );
        assert_eq!(relay.stats().up.reordered, 0);
    }

    /// The relay draws once for loss and once for reordering per datagram, in arrival order.
    /// Returns a seed whose first three datagrams are reordered `[yes, no, no]`, i.e. the first
    /// one the relay sees is held back and the next two (the second datagram and the echo of it)
    /// are not: found here rather than hand-checked, so the test survives a PRNG change.
    fn seed_reordering_only_the_first(p: f64) -> u64 {
        for seed in 0..10_000 {
            let mut rng = Pcg::new(seed, 0);
            let mut reordered = [false; 3];
            for slot in &mut reordered {
                let _ = rng.chance(0.0); // the loss draw, consumed even at probability 0
                *slot = rng.chance(p);
            }
            if reordered == [true, false, false] {
                return seed;
            }
        }
        panic!("no seed below 10000 reorders only the first datagram");
    }

    #[tokio::test]
    async fn reordering_lets_later_datagrams_overtake() {
        let (upstream, _echo) = echo_upstream().await.expect("upstream");
        let seed = seed_reordering_only_the_first(0.5);
        let relay = Relay::start(upstream, RelayConfig::new(seed).reorder(0.5, 200))
            .await
            .expect("relay");
        let cli = client_socket().await.expect("client");

        // "first" is held back by 200 ms, "second" is sent 10 ms later and goes straight
        // through, so it overtakes with 190 ms to spare.
        cli.send_to(b"first", relay.addr()).await.expect("send");
        tokio::time::sleep(Duration::from_millis(10)).await;
        cli.send_to(b"second", relay.addr()).await.expect("send");

        let mut buf = [0u8; 64];
        let mut order: Vec<Vec<u8>> = Vec::new();
        for _ in 0..2 {
            let (n, _) = tokio::time::timeout(Duration::from_secs(5), cli.recv_from(&mut buf))
                .await
                .expect("both echoes in time")
                .expect("recv");
            order.push(buf[..n].to_vec());
        }
        assert_eq!(
            order,
            vec![b"second".to_vec(), b"first".to_vec()],
            "the held-back datagram must arrive last"
        );
        let stats = relay.stats();
        assert_eq!(stats.up.reordered, 1, "only 'first' was held back");
        assert_eq!(stats.up.forwarded, 2);
    }

    #[tokio::test]
    async fn datagrams_from_the_upstream_before_any_client_are_counted() {
        let up = client_socket().await.expect("upstream socket");
        let upstream = up.local_addr().expect("addr");
        let relay = Relay::start(upstream, RelayConfig::new(6))
            .await
            .expect("relay");
        up.send_to(b"early", relay.addr()).await.expect("send");
        let deadline = Instant::now() + Duration::from_secs(5);
        while relay.stats().no_client == 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let stats = relay.stats();
        assert_eq!(stats.no_client, 1);
        assert_eq!(
            stats.down.received, 0,
            "there was no direction to count it in"
        );
    }

    #[tokio::test]
    async fn dropping_the_relay_releases_the_port() {
        let (upstream, _echo) = echo_upstream().await.expect("upstream");
        let relay = Relay::start(upstream, RelayConfig::new(7))
            .await
            .expect("relay");
        let addr = relay.addr();
        assert_eq!(Direction::Up.tag(), "up");
        assert_eq!(Direction::Down.tag(), "down");
        relay.shutdown();
        // The task is aborted asynchronously; give it a moment, then the port must be free.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match std::net::UdpSocket::bind(addr) {
                Ok(_) => break,
                Err(e) if Instant::now() < deadline => {
                    let _ = e;
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(e) => panic!("port still busy: {e}"),
            }
        }
    }

    #[test]
    #[should_panic(expected = "relay: loss probability 1.5 is not in [0, 1]")]
    fn an_impossible_loss_probability_panics() {
        let _ = RelayConfig::new(0).loss(1.5);
    }

    #[test]
    #[should_panic(expected = "relay: reorder probability -0.1 is not in [0, 1]")]
    fn an_impossible_reorder_probability_panics() {
        let _ = RelayConfig::new(0).reorder(-0.1, 10);
    }
}
