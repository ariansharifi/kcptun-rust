//! The harness of `tests/teardown.rs`: process-level leak tests of the proxy pipe's teardown
//! (deviation V24, DECISIONS D35) on the real binaries, with per-process socket accounting from
//! [`kcptun_testkit::sockets`].
//!
//! ```text
//! app (the test) ──TCP──▶ kcptun-client ══KCP/smux══▶ kcptun-server ──TCP──▶ Target (the test)
//! ```
//!
//! | Item | Purpose |
//! |---|---|
//! | [`Rig`] | a [`Tunnel`] to a [`Target`], warmed up, with every process's baseline [`ProcSockets`] |
//! | [`Target`] | a scripted target: echo once, stall (never read), cut after N bytes, or flood |
//! | [`connect_app`], [`fill_until_blocked`], [`keep_sending`], [`reset`], [`read_then_close`] | the application side |
//! | [`Window`] | the bound a teardown must meet, named after the mechanism that ends it |
//! | [`Graces`], [`Buffers`], [`Pairing`] | `-closewait`, the buffer flags and the implementations of a case |
//!
//! # Baseline
//!
//! [`Rig::start`] sends one echo through the tunnel first, so that the client has brought up its
//! session (and with it its UDP socket), and waits until every process holds no connection and no
//! dead socket. What each process holds then (the client's listener, its UDP socket and the
//! runtime's unix sockets; the server's UDP listener and the same unix sockets) is its baseline,
//! and "back to baseline" ([`back_to`]) means the same descriptor count, the same listeners, no
//! TCP connection in any state (so no `FIN-WAIT-2` and no `CLOSE-WAIT` on the test ports) and no
//! dead socket. A case that kills one side lets the survivor end *below* its baseline, because
//! its session's UDP socket may go with the session.
//!
//! # Bounds
//!
//! Every bound comes from the mechanism that ends the pipe (module docs of
//! `kcptun_std::pipe`), with the production clocks read from the code rather than copied:
//!
//! | Mechanism | Bound after the triggering event |
//! |---|---|
//! | grace | `-closewait` of the side that first sees the end, after its peer's own teardown if the end reaches it through the stream |
//! | a reset seen while parked | at most one [`WATCH`] period, then the grace |
//! | stall / starvation rule | `max(-closewait, 30 s)` ([`SOCKET_STALL`]) after the last byte moved, for a socket destination; the kernel can still move a few bytes up to [`PERSIST_PROBE`] after the stalled reader's window closed |
//! | session death | smux keepalive: 20 to 60 s after the peer died ([`KEEPALIVE_TIMEOUT`] ticks, the peer's last ping at most [`KEEPALIVE_INTERVAL`] before), then both directions fail at once |
//!
//! [`SLACK`] (2 s) covers scheduling and the sampling period on top of each. Grace-driven
//! teardowns also have a lower bound, which is what shows *which* grace applied, so the cases run
//! with distinct `-closewait` values ([`Graces::EXPLICIT`]: client 2, server 3).

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use kcptun_testkit::socket_creation_guard;
use kcptun_testkit::sockets::{Polled, ProcSockets, TcpState, poll_until};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::bins::Impl;
use crate::e2e::{LocalEndpoint, Tunnel, panic_lines};
use crate::matrix::Case;

// ---------------------------------------------------------------------------------------
// Clocks
// ---------------------------------------------------------------------------------------

/// How often a pipe with a parked direction probes its ends (`Timing::DEFAULT.watch`).
pub const WATCH: Duration = kcptun_std::pipe::Timing::DEFAULT.watch;

/// The stall rule's floor for a socket destination (`Timing::DEFAULT.socket_stall`).
pub const SOCKET_STALL: Duration = kcptun_std::pipe::Timing::DEFAULT.socket_stall;

/// smux's `KeepAliveTimeout`, which `-keepalive` does not change: a session is closed on the
/// first tick of this period that finds no frame received since the previous one.
pub fn keepalive_timeout() -> Duration {
    kcptun_std::smuxcfg::SmuxConfig::default().keep_alive_timeout
}

/// [`keepalive_timeout`] as a constant, for bounds; checked against the code by a unit test.
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(30);

/// kcptun's default `-keepalive`: the peer pings this often, so its last frame before it died
/// is at most this old.
// Go: kcptun/client/main.go, server/main.go: cli.IntFlag{Name: "keepalive", Value: 10}
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Scheduling and sampling slack on top of every bound: the "closewait + ~2 s" of the leak
/// report.
pub const SLACK: Duration = Duration::from_secs(2);

/// How much earlier than a timer-driven lower bound a teardown may be observed: a sample is
/// timestamped when it starts, and `lsof` takes a while.
pub const EARLY: Duration = Duration::from_millis(500);

/// How long a write may make no progress before the pipeline behind it counts as full.
pub const FILL_QUIET: Duration = Duration::from_millis(1500);

/// How long after the pipeline filled its last byte may have moved: the buffers between the
/// stalled reader and the writer that noticed fill in that time. Only lower bounds use it.
pub const FILL_LAG: Duration = Duration::from_secs(3);

/// How long after a stalled reader's receive window closed the kernel can still move a few
/// bytes into it on its own, which the stall rule rightly counts as progress (it restarts its
/// clock). The sender keeps probing a zero window (macOS: every `TCPTV_PERSMIN`, 5 s, on
/// loopback; Linux: from one RTO, 200 ms, backing off), and once the receiver has compacted its
/// buffer the probe's answer opens a small window. Measured on macOS with a 16 KiB receive buffer
/// that is never read: 2192 more bytes accepted about 5 s after the last write went through (3.6 s
/// after a writer would have called the socket full, [`FILL_QUIET`] later), then nothing for a
/// minute. Only upper bounds of the stall rule use it.
pub const PERSIST_PROBE: Duration = Duration::from_secs(5);

/// The default `-closewait` of the client.
// Go: kcptun/client/main.go: cli.IntFlag{Name: "closewait", Value: 0}
pub const CLIENT_CLOSEWAIT_DEFAULT: u64 = 0;

/// The default `-closewait` of the server.
// Go: kcptun/server/main.go: cli.IntFlag{Name: "closewait", Value: 30}
pub const SERVER_CLOSEWAIT_DEFAULT: u64 = 30;

/// The stall rule's limit for a socket destination with `-closewait` `grace`.
pub fn socket_stall(grace: Duration) -> Duration {
    grace.max(SOCKET_STALL)
}

// ---------------------------------------------------------------------------------------
// Case parameters
// ---------------------------------------------------------------------------------------

/// The `-closewait` of each side; `None` leaves the binary's default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Graces {
    /// The client's `-closewait`.
    pub client: Option<u64>,
    /// The server's `-closewait`.
    pub server: Option<u64>,
}

impl Graces {
    /// Two distinct values, so that a measured teardown shows which side's grace applied.
    pub const EXPLICIT: Graces = Graces {
        client: Some(2),
        server: Some(3),
    };

    /// Both binaries' defaults: client 0, server 30.
    pub const DEFAULTS: Graces = Graces {
        client: None,
        server: None,
    };

    /// The client's grace in effect.
    pub fn client(self) -> Duration {
        Duration::from_secs(self.client.unwrap_or(CLIENT_CLOSEWAIT_DEFAULT))
    }

    /// The server's grace in effect.
    pub fn server(self) -> Duration {
        Duration::from_secs(self.server.unwrap_or(SERVER_CLOSEWAIT_DEFAULT))
    }

    fn flag(value: Option<u64>) -> Vec<String> {
        value
            .map(|s| vec!["-closewait".to_string(), s.to_string()])
            .unwrap_or_default()
    }
}

impl fmt::Display for Graces {
    /// `closewait client 2s server 30s (default)`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let default = |value: Option<u64>| if value.is_none() { " (default)" } else { "" };
        write!(
            f,
            "closewait client {}s{} server {}s{}",
            self.client().as_secs(),
            default(self.client),
            self.server().as_secs(),
            default(self.server),
        )
    }
}

/// `-streambuf`, `-smuxbuf` and the KCP windows (`-sndwnd`/`-rcvwnd`), small so that windows
/// fill within a second or two.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Buffers {
    /// `-streambuf`.
    pub streambuf: u32,
    /// `-smuxbuf`.
    pub smuxbuf: u32,
    /// `-sndwnd` and `-rcvwnd`, in packets.
    pub window: u32,
}

impl Buffers {
    /// `smuxbuf >= 2 * max(streambuf, 256 KiB) + framesize`: two stalled streams cannot spend a
    /// session's receive buffer, so a `cmdFIN` stays readable behind them.
    pub const ROOMY: Buffers = Buffers {
        streambuf: 256 * 1024,
        smuxbuf: 1024 * 1024,
        window: 64,
    };

    /// `smuxbuf == streambuf`, as in production (16 MiB each): one stalled stream spends the
    /// whole session's receive buffer, and then no frame of any stream is read.
    pub const STARVING: Buffers = Buffers {
        streambuf: 256 * 1024,
        smuxbuf: 256 * 1024,
        window: 64,
    };

    fn args(self) -> Vec<String> {
        [
            ("-streambuf", self.streambuf),
            ("-smuxbuf", self.smuxbuf),
            ("-sndwnd", self.window),
            ("-rcvwnd", self.window),
        ]
        .into_iter()
        .flat_map(|(flag, v)| [flag.to_string(), v.to_string()])
        .collect()
    }
}

/// Which implementation runs each side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pairing {
    /// The client.
    pub client: Impl,
    /// The server.
    pub server: Impl,
}

impl Pairing {
    /// Rust on both ends.
    pub const RUST: Pairing = Pairing {
        client: Impl::Rust,
        server: Impl::Rust,
    };
    /// A Rust client against the Go reference server.
    pub const RUST_CLIENT_GO_SERVER: Pairing = Pairing {
        client: Impl::Rust,
        server: Impl::Go,
    };
    /// The Go reference client against a Rust server.
    pub const GO_CLIENT_RUST_SERVER: Pairing = Pairing {
        client: Impl::Go,
        server: Impl::Rust,
    };
}

impl fmt::Display for Pairing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} client, {} server", self.client, self.server)
    }
}

/// Everything that configures one [`Rig`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RigSpec {
    /// The implementations.
    pub pairing: Pairing,
    /// `-closewait` of each side.
    pub graces: Graces,
    /// The buffer flags.
    pub buffers: Buffers,
}

impl RigSpec {
    /// `pairing` with explicit graces and roomy buffers: the usual case.
    pub fn new(pairing: Pairing) -> RigSpec {
        RigSpec {
            pairing,
            graces: Graces::EXPLICIT,
            buffers: Buffers::ROOMY,
        }
    }

    /// The same with other graces.
    pub fn graces(self, graces: Graces) -> RigSpec {
        RigSpec { graces, ..self }
    }

    /// The same with other buffers.
    pub fn buffers(self, buffers: Buffers) -> RigSpec {
        RigSpec { buffers, ..self }
    }

    /// The wire configuration both sides get: the production profile of the leak report
    /// (`-mode normal -crypt xor -mtu 1390 -nocomp`, smux v2, FEC 10/3), with small buffers.
    pub fn case(&self) -> Case {
        Case::new()
            .crypt("xor")
            .mode("normal")
            .mtu(1390)
            .nocomp(true)
            .extra_args(self.buffers.args())
    }
}

impl fmt::Display for RigSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}; {}; streambuf {} smuxbuf {} sndwnd/rcvwnd {}",
            self.pairing,
            self.graces,
            self.buffers.streambuf,
            self.buffers.smuxbuf,
            self.buffers.window
        )
    }
}

// ---------------------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------------------

/// The interval a teardown must fall in, measured from its triggering event, and the mechanism
/// that is expected to end it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Window {
    /// What ends the pipe, in words, for the report.
    pub mechanism: String,
    /// The earliest the mechanism can act (timer-driven ones only; zero otherwise).
    pub min: Duration,
    /// The latest, slack included.
    pub max: Duration,
}

impl Window {
    /// A window from `min` to `max` for `mechanism`.
    pub fn new(mechanism: impl Into<String>, min: Duration, max: Duration) -> Window {
        Window {
            mechanism: mechanism.into(),
            min,
            max,
        }
    }
}

impl fmt::Display for Window {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({:.1}..{:.1} s)",
            self.mechanism,
            self.min.as_secs_f64(),
            self.max.as_secs_f64()
        )
    }
}

/// Whether `now` is back to `base` (see the [module docs](self)). With `fewer_ok`, fewer
/// descriptors than the baseline also count, for a survivor whose session died.
pub fn back_to(base: &ProcSockets, now: &ProcSockets, fewer_ok: bool) -> bool {
    let fds_ok = if fewer_ok {
        now.fds() <= base.fds()
    } else {
        now.fds() == base.fds()
    };
    now.connections() == 0 && now.dead.is_empty() && now.listeners() == base.listeners() && fds_ok
}

// ---------------------------------------------------------------------------------------
// The target
// ---------------------------------------------------------------------------------------

/// How a connection is ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// `close(2)`. With received data still unread, Linux sends RST at once; macOS sends FIN
    /// and answers whatever arrives next with RST.
    Close,
    /// `SO_LINGER {on, 0}`, then `close(2)`: always an RST.
    Reset,
}

/// What a [`Target`] does with the connections it accepts from now on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Behaviour {
    /// Read exactly `len` bytes, send them back, close: a round trip that ends on its own.
    EchoOnce {
        /// Bytes to echo.
        len: usize,
    },
    /// Never read, never write; keep the connection until told to end it. With the target's
    /// small receive buffer, the window behind it fills quickly.
    Stall,
    /// Read `after` bytes, then end the connection with `end`.
    Cut {
        /// Bytes read before the end.
        after: u64,
        /// How it ends.
        end: End,
    },
    /// Write without pause and never read, until a write fails or it is told to end.
    Flood,
}

/// The receive and send buffers a [`Target`] gives its listener, inherited by every accepted
/// connection. Small, so that a stalled reader or writer blocks after a few KiB.
pub const TARGET_SOCKET_BUFFER: u32 = 16 * 1024;

/// One connection of a [`Target`], as last seen.
#[derive(Clone, Debug)]
pub struct TargetConn {
    /// Accept order, from 0.
    pub id: usize,
    /// What it was told to do.
    pub behaviour: Behaviour,
    /// Bytes read.
    pub read: u64,
    /// Bytes written.
    pub written: u64,
    /// How long since a byte last moved.
    pub quiet: Duration,
    /// When and why it ended, if it has.
    pub ended: Option<(Instant, String)>,
}

impl fmt::Display for TargetConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "conn {} {:?}: read {} B, wrote {} B, quiet {:.1} s",
            self.id,
            self.behaviour,
            self.read,
            self.written,
            self.quiet.as_secs_f64()
        )?;
        if let Some((_, why)) = &self.ended {
            write!(f, ", ended: {why}")?;
        }
        Ok(())
    }
}

/// Shared state of one target connection.
struct Conn {
    id: usize,
    behaviour: Behaviour,
    read: AtomicU64,
    written: AtomicU64,
    moved_at: Mutex<Instant>,
    ended: Mutex<Option<(Instant, String)>>,
    command: watch::Sender<Option<End>>,
}

impl Conn {
    fn moved(&self) {
        *lock(&self.moved_at) = Instant::now();
    }

    fn report(&self) -> TargetConn {
        TargetConn {
            id: self.id,
            behaviour: self.behaviour,
            read: self.read.load(Ordering::SeqCst),
            written: self.written.load(Ordering::SeqCst),
            quiet: lock(&self.moved_at).elapsed(),
            ended: lock(&self.ended).clone(),
        }
    }
}

/// Locks `m`, ignoring poisoning: nothing here leaves the data half-updated.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A TCP target on `127.0.0.1` whose connections follow a [`Behaviour`], and which can end every
/// open connection on command ([`end_all`](Self::end_all)). Dropping it stops it and resets every
/// connection still open.
pub struct Target {
    addr: SocketAddr,
    behaviour: Arc<Mutex<Behaviour>>,
    conns: Arc<Mutex<Vec<Arc<Conn>>>>,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl fmt::Debug for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Target").field("addr", &self.addr).finish()
    }
}

impl Target {
    /// Starts a target with [`TARGET_SOCKET_BUFFER`]-sized buffers, behaving as `behaviour`.
    pub async fn start(behaviour: Behaviour) -> io::Result<Target> {
        let listener = {
            // Created under the guard, so a binary spawned meanwhile cannot inherit it (macOS).
            let _fd = socket_creation_guard();
            let socket = TcpSocket::new_v4()?;
            // Set before listen(2): accepted sockets inherit both, and the receive buffer has to
            // be small already when the window scale is negotiated.
            socket.set_recv_buffer_size(TARGET_SOCKET_BUFFER)?;
            socket.set_send_buffer_size(TARGET_SOCKET_BUFFER)?;
            socket.bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
            socket.listen(64)?
        };
        let addr = listener.local_addr()?;
        let behaviour = Arc::new(Mutex::new(behaviour));
        let conns: Arc<Mutex<Vec<Arc<Conn>>>> = Arc::new(Mutex::new(Vec::new()));
        let (stop, mut stop_rx) = watch::channel(false);
        let task = {
            let behaviour = Arc::clone(&behaviour);
            let conns = Arc::clone(&conns);
            let stop_conns = stop.subscribe();
            tokio::spawn(async move {
                loop {
                    let accepted = tokio::select! {
                        _ = stop_rx.wait_for(|s| *s) => return,
                        r = listener.accept() => r,
                    };
                    let Ok((stream, _)) = accepted else {
                        // Accept errors (EMFILE) are not expected here; do not spin on one.
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    };
                    let _ = stream.set_nodelay(true);
                    let (command, command_rx) = watch::channel(None);
                    let conn = {
                        let mut list = lock(&conns);
                        let conn = Arc::new(Conn {
                            id: list.len(),
                            behaviour: *lock(&behaviour),
                            read: AtomicU64::new(0),
                            written: AtomicU64::new(0),
                            moved_at: Mutex::new(Instant::now()),
                            ended: Mutex::new(None),
                            command,
                        });
                        list.push(Arc::clone(&conn));
                        conn
                    };
                    tokio::spawn(serve_conn(stream, conn, command_rx, stop_conns.clone()));
                }
            })
        };
        Ok(Target {
            addr,
            behaviour,
            conns,
            stop,
            task,
        })
    }

    /// What connections accepted from now on do.
    pub fn set_behaviour(&self, behaviour: Behaviour) {
        *lock(&self.behaviour) = behaviour;
    }

    /// The listening address, as a `-t` value.
    pub fn target(&self) -> String {
        self.addr.to_string()
    }

    /// The listening port.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Every connection so far, in accept order.
    pub fn conns(&self) -> Vec<TargetConn> {
        lock(&self.conns).iter().map(|c| c.report()).collect()
    }

    /// One line per connection, for a log.
    pub fn report(&self) -> String {
        let conns = self.conns();
        if conns.is_empty() {
            return "no connections".to_string();
        }
        conns
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Polls the connections every 10 ms until `check` returns a value, or fails after
    /// `timeout` with every connection's state.
    pub async fn wait_for<T>(
        &self,
        what: &str,
        timeout: Duration,
        mut check: impl FnMut(&[TargetConn]) -> Option<T>,
    ) -> io::Result<T> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(v) = check(&self.conns()) {
                return Ok(v);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "target: timed out after {timeout:?} waiting for {what}:\n{}",
                        self.report()
                    ),
                ));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Waits until a [`Behaviour::Cut`] connection has ended itself, and returns when it did:
    /// the triggering instant of a "target closes" case.
    pub async fn cut(&self, timeout: Duration) -> io::Result<Instant> {
        self.wait_for("a connection to be cut", timeout, |conns| {
            conns.iter().find_map(|c| match (c.behaviour, &c.ended) {
                (Behaviour::Cut { .. }, Some((at, _))) => Some(*at),
                _ => None,
            })
        })
        .await
    }

    /// Waits until `n` [`Behaviour::Flood`] connections are open and none of them has written
    /// anything for `quiet`: the tunnel behind them is full.
    pub async fn flooded(&self, n: usize, quiet: Duration, timeout: Duration) -> io::Result<u64> {
        self.wait_for(&format!("{n} blocked floods"), timeout, |conns| {
            let floods: Vec<&TargetConn> = conns
                .iter()
                .filter(|c| c.behaviour == Behaviour::Flood && c.ended.is_none())
                .collect();
            (floods.len() >= n && floods.iter().all(|c| c.quiet >= quiet))
                .then(|| floods.iter().map(|c| c.written).sum())
        })
        .await
    }

    /// Waits until `n` connections have been accepted.
    pub async fn accepted(&self, n: usize, timeout: Duration) -> io::Result<()> {
        self.wait_for(&format!("{n} connections"), timeout, |conns| {
            (conns.len() >= n).then_some(())
        })
        .await
    }

    /// Ends every connection still open with `end`, and returns the instant before it did.
    pub fn end_all(&self, end: End) -> Instant {
        let at = Instant::now();
        for conn in lock(&self.conns).iter() {
            conn.command.send_replace(Some(end));
        }
        at
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        self.task.abort();
    }
}

/// Runs one target connection: its behaviour, until it ends on its own, is told to end, or the
/// target stops (then it is reset).
async fn serve_conn(
    mut stream: TcpStream,
    conn: Arc<Conn>,
    mut command: watch::Receiver<Option<End>>,
    mut stop: watch::Receiver<bool>,
) {
    let (end, why) = tokio::select! {
        r = behave(&mut stream, &conn) => r,
        end = async {
            // Copied out at once: the watch guard must not live across an await.
            let told = command.wait_for(Option::is_some).await.map(|end| *end);
            match told {
                Ok(end) => end,
                // The target is gone; `stop` ends the connection.
                Err(_) => std::future::pending().await,
            }
        } => (end, format!("told to {end:?}")),
        _ = stop.wait_for(|s| *s) => (Some(End::Reset), "target stopped".to_string()),
    };
    if end == Some(End::Reset) {
        let _ = stream.set_zero_linger();
    }
    drop(stream);
    *lock(&conn.ended) = Some((Instant::now(), why));
}

/// One connection's behaviour. Returns how to end the connection (`None`: it failed, just close
/// it) and why.
async fn behave(stream: &mut TcpStream, conn: &Conn) -> (Option<End>, String) {
    match conn.behaviour {
        Behaviour::EchoOnce { len } => {
            let mut buf = vec![0u8; len];
            if let Err(e) = stream.read_exact(&mut buf).await {
                return (None, format!("echo: read: {e}"));
            }
            conn.read.store(len as u64, Ordering::SeqCst);
            if let Err(e) = stream.write_all(&buf).await {
                return (None, format!("echo: write: {e}"));
            }
            conn.written.store(len as u64, Ordering::SeqCst);
            conn.moved();
            (Some(End::Close), "echoed".to_string())
        }
        Behaviour::Stall => std::future::pending().await,
        Behaviour::Cut { after, end } => {
            let mut buf = vec![0u8; 64 * 1024];
            let mut total = 0u64;
            while total < after {
                let want = usize::try_from(after - total)
                    .unwrap_or(buf.len())
                    .min(buf.len());
                match stream.read(&mut buf[..want]).await {
                    Ok(0) => return (None, format!("the tunnel ended it after {total} B")),
                    Ok(n) => {
                        total += n as u64;
                        conn.read.store(total, Ordering::SeqCst);
                        conn.moved();
                    }
                    Err(e) => return (None, format!("read failed after {total} B: {e}")),
                }
            }
            (Some(end), format!("{end:?} after reading {total} B"))
        }
        Behaviour::Flood => {
            let chunk = vec![0xa5u8; 64 * 1024];
            loop {
                match stream.write(&chunk).await {
                    Ok(0) => return (None, "write returned 0".to_string()),
                    Ok(n) => {
                        conn.written.fetch_add(n as u64, Ordering::SeqCst);
                        conn.moved();
                    }
                    Err(e) => {
                        let written = conn.written.load(Ordering::SeqCst);
                        return (None, format!("write failed after {written} B: {e}"));
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// The application side
// ---------------------------------------------------------------------------------------

/// Bytes [`fill_until_blocked`] writes at most before it calls the tunnel unbounded.
const FILL_LIMIT: u64 = 512 << 20;

/// Size of one application write.
const APP_CHUNK: usize = 64 * 1024;

/// Connects to the client's TCP listener as an application, with a receive buffer of `rcvbuf`
/// bytes if given (set before `connect(2)`, so the advertised window is small from the start).
pub async fn connect_app(endpoint: &LocalEndpoint, rcvbuf: Option<u32>) -> io::Result<TcpStream> {
    let addr = match endpoint {
        LocalEndpoint::Tcp(addr) => *addr,
        #[cfg(unix)]
        LocalEndpoint::Unix(path) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "the teardown cases use a TCP listener, not {}",
                    path.display()
                ),
            ));
        }
    };
    let socket = {
        // Created under the guard, so a binary spawned meanwhile cannot inherit it (macOS).
        let _fd = socket_creation_guard();
        let socket = TcpSocket::new_v4()?;
        if let Some(size) = rcvbuf {
            socket.set_recv_buffer_size(size)?;
        }
        socket
    };
    let stream = socket.connect(addr).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// What [`fill_until_blocked`] did.
#[derive(Debug)]
pub struct Filled {
    /// Bytes written.
    pub bytes: u64,
    /// The write error that ended it, if the connection failed instead of blocking.
    pub error: Option<io::Error>,
}

/// Writes until one write makes no progress for `quiet` (the tunnel behind `stream` is full),
/// or fails. More than [`FILL_LIMIT`] bytes is an error: something is draining the tunnel.
pub async fn fill_until_blocked(stream: &mut TcpStream, quiet: Duration) -> Filled {
    let chunk = vec![0x5au8; APP_CHUNK];
    let mut bytes = 0u64;
    loop {
        if bytes > FILL_LIMIT {
            return Filled {
                bytes,
                error: Some(io::Error::other(format!(
                    "wrote {bytes} B without blocking: the tunnel never filled"
                ))),
            };
        }
        // `write` is cancel-safe: a timed-out call wrote nothing.
        match tokio::time::timeout(quiet, stream.write(&chunk)).await {
            Err(_) => return Filled { bytes, error: None },
            Ok(Ok(0)) => {
                return Filled {
                    bytes,
                    error: Some(io::ErrorKind::WriteZero.into()),
                };
            }
            Ok(Ok(n)) => bytes += n as u64,
            Ok(Err(e)) => {
                return Filled {
                    bytes,
                    error: Some(e),
                };
            }
        }
    }
}

/// What [`keep_sending`] saw.
#[derive(Debug)]
pub struct Sent {
    /// Bytes written.
    pub bytes: u64,
    /// The error that ended the writes.
    pub error: io::Error,
    /// When it came.
    pub at: Instant,
}

/// Writes into `stream` until a write fails, then drops it: an application that keeps sending
/// whatever happens at the far end.
pub fn keep_sending(mut stream: TcpStream) -> JoinHandle<Sent> {
    tokio::spawn(async move {
        let chunk = vec![0x5au8; APP_CHUNK];
        let mut bytes = 0u64;
        loop {
            match stream.write(&chunk).await {
                Ok(0) => {
                    return Sent {
                        bytes,
                        error: io::ErrorKind::WriteZero.into(),
                        at: Instant::now(),
                    };
                }
                Ok(n) => bytes += n as u64,
                Err(error) => {
                    return Sent {
                        bytes,
                        error,
                        at: Instant::now(),
                    };
                }
            }
        }
    })
}

/// Resets `stream` (`SO_LINGER {on, 0}`, then `close(2)`), and returns the instant before.
pub fn reset(stream: TcpStream) -> io::Result<Instant> {
    let at = Instant::now();
    stream.set_zero_linger()?;
    drop(stream);
    Ok(at)
}

/// Reads `n` bytes from `stream` (whatever they are), then closes it with data still arriving,
/// and returns the instant before the close.
pub async fn read_then_close(mut stream: TcpStream, n: u64) -> io::Result<Instant> {
    let mut buf = vec![0u8; APP_CHUNK];
    let mut left = n;
    while left > 0 {
        let want = usize::try_from(left).unwrap_or(buf.len()).min(buf.len());
        match stream.read(&mut buf[..want]).await? {
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("the tunnel ended after {} of {n} B", n - left),
                ));
            }
            got => left -= got as u64,
        }
    }
    let at = Instant::now();
    drop(stream);
    Ok(at)
}

// ---------------------------------------------------------------------------------------
// The rig
// ---------------------------------------------------------------------------------------

/// Bytes of the warm-up echo.
const WARM_UP: usize = 4096;

/// How long the warm-up stream may take to go away, on top of the longer grace.
const SETTLE_SLACK: Duration = Duration::from_secs(5);

/// One side of the tunnel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// `kcptun-client`.
    Client,
    /// `kcptun-server`.
    Server,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Role::Client => "client",
            Role::Server => "server",
        })
    }
}

/// One process of a [`Rig`] and what it held before the case started.
#[derive(Clone, Debug)]
pub struct Watched {
    /// Which side it is.
    pub role: Role,
    /// Which implementation runs it.
    pub which: Impl,
    /// Its pid.
    pub pid: u32,
    /// Its sockets after the warm-up settled.
    pub base: ProcSockets,
}

impl Watched {
    /// `[go] client` / `[rs] server`: the log label of its samples.
    fn label(&self) -> String {
        format!("{} {}", self.which, self.role)
    }
}

/// A warmed-up tunnel to a [`Target`], with every process's baseline. See the
/// [module docs](self).
#[derive(Debug)]
pub struct Rig {
    /// The two processes.
    pub tunnel: Tunnel,
    /// The target behind the server.
    pub target: Target,
    /// How it was configured.
    pub spec: RigSpec,
    /// The client's listening port and the target's port: the "test ports".
    ports: Vec<u16>,
    client: Watched,
    server: Watched,
}

impl Rig {
    /// Starts the target and both binaries, sends one echo through, waits until both processes
    /// have let go of it, and takes their baselines.
    pub async fn start(spec: RigSpec) -> Rig {
        eprintln!("rig: {spec}");
        let target = Target::start(Behaviour::EchoOnce { len: WARM_UP })
            .await
            .unwrap_or_else(|e| panic!("target: {e}"));
        let mut tunnel = Tunnel::builder(target.target())
            .case(spec.case())
            .client_impl(spec.pairing.client)
            .server_impl(spec.pairing.server)
            .client_args(Graces::flag(spec.graces.client))
            .server_args(Graces::flag(spec.graces.server))
            .start()
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let local_port = match tunnel.local() {
            LocalEndpoint::Tcp(addr) => addr.port(),
            #[cfg(unix)]
            LocalEndpoint::Unix(_) => panic!("the teardown cases use a TCP listener"),
        };
        let ports = vec![local_port, target.port()];

        // Warm-up: one round trip brings the client's session up. The target closes after its
        // echo and the application right after reading it, so both pipes see both ends finish.
        let mut app = connect_app(tunnel.local(), None)
            .await
            .unwrap_or_else(|e| panic!("warm-up connect: {e}"));
        let payload = vec![0x42u8; WARM_UP];
        app.write_all(&payload)
            .await
            .unwrap_or_else(|e| panic!("warm-up write: {e}"));
        let mut echo = vec![0u8; WARM_UP];
        app.read_exact(&mut echo)
            .await
            .unwrap_or_else(|e| panic!("warm-up read: {e}"));
        assert_eq!(echo, payload, "warm-up echo");
        drop(app);

        let client_pid = tunnel.client().pid();
        let server_pid = tunnel.server().pid();
        let settle = spec.graces.client().max(spec.graces.server()) + SETTLE_SLACK;
        let since = Instant::now();
        let idle = |s: &ProcSockets| s.connections() == 0 && s.dead.is_empty();
        let client_label = format!("{} client settles", spec.pairing.client);
        let server_label = format!("{} server settles", spec.pairing.server);
        let (client, server) = tokio::join!(
            poll_until(&client_label, client_pid, &ports, since, settle, idle),
            poll_until(&server_label, server_pid, &ports, since, settle, idle),
        );
        for (polled, which, role) in [
            (&client, spec.pairing.client, Role::Client),
            (&server, spec.pairing.server, Role::Server),
        ] {
            if polled.met {
                continue;
            }
            // A Go process that keeps the warm-up stream is reported, not failed: only the Rust
            // side is under test. A Rust one that keeps it fails here, before the case.
            let msg = format!(
                "{which} {role} still holds the warm-up stream after {settle:?}: {polled:#?}"
            );
            if which == Impl::Rust {
                panic!("{msg}");
            }
            eprintln!("NOTE: {msg}");
        }
        let take_base = |polled: Polled, which: Impl, role: Role| -> ProcSockets {
            polled
                .last
                .unwrap_or_else(|| panic!("no baseline sample of the {which} {role}"))
        };
        let client = Watched {
            role: Role::Client,
            which: spec.pairing.client,
            pid: client_pid,
            base: take_base(client, spec.pairing.client, Role::Client),
        };
        let server = Watched {
            role: Role::Server,
            which: spec.pairing.server,
            pid: server_pid,
            base: take_base(server, spec.pairing.server, Role::Server),
        };
        eprintln!(
            "baseline {}: {}\nbaseline {}: {}",
            client.label(),
            client.base.summary(),
            server.label(),
            server.base.summary()
        );
        Rig {
            tunnel,
            target,
            spec,
            ports,
            client,
            server,
        }
    }

    /// The process of `role`.
    pub fn watched(&self, role: Role) -> &Watched {
        match role {
            Role::Client => &self.client,
            Role::Server => &self.server,
        }
    }

    /// The test ports: the client's listening port and the target's.
    pub fn ports(&self) -> &[u16] {
        &self.ports
    }

    /// Connects an application to the client.
    pub async fn connect_app(&self, rcvbuf: Option<u32>) -> TcpStream {
        connect_app(self.tunnel.local(), rcvbuf)
            .await
            .unwrap_or_else(|e| panic!("connect to the client: {e}"))
    }

    /// Waits until the process of `role` is back to its baseline within `window` of `since`.
    ///
    /// For a Rust process that is the assertion of a case: it panics, with the last sample and
    /// the baseline, if the process is not back by `window.max`, or is back before
    /// `window.min - EARLY` (another mechanism than the expected one ended the pipe). It returns
    /// how long it took. A Go process is only watched for as long and reported (`None`).
    pub async fn expect_back(
        &self,
        role: Role,
        since: Instant,
        window: &Window,
        fewer_ok: bool,
    ) -> Option<Duration> {
        let w = self.watched(role);
        let polled = poll_until(&w.label(), w.pid, &self.ports, since, window.max, |s| {
            back_to(&w.base, s, fewer_ok)
        })
        .await;
        let last = polled
            .last
            .as_ref()
            .map_or_else(|| "no sample".to_string(), ProcSockets::summary);
        if w.which == Impl::Go {
            if polled.met {
                eprintln!(
                    "{} (not asserted): back to its baseline after {:.2} s",
                    w.label(),
                    polled.elapsed.as_secs_f64()
                );
            } else {
                eprintln!(
                    "{} (not asserted): NOT back to its baseline {:.2} s after the event \
                     (a Rust {} would be: {window}); it holds: {last}",
                    w.label(),
                    polled.elapsed.as_secs_f64(),
                    w.role
                );
            }
            return None;
        }
        assert!(
            polled.met,
            "{} is not back to its baseline {:.2} s after the event; expected: {window}\n\
             error: {:?}\nlast:     {last}\nbaseline: {}\nFIN-WAIT-2 on the test ports: {}, \
             CLOSE-WAIT: {}, dead: {}\ntarget:\n{}",
            w.label(),
            polled.elapsed.as_secs_f64(),
            polled.error,
            w.base.summary(),
            polled
                .last
                .as_ref()
                .map_or(0, |s| s.in_state_on(TcpState::FinWait2, &self.ports)),
            polled
                .last
                .as_ref()
                .map_or(0, |s| s.in_state_on(TcpState::CloseWait, &self.ports)),
            polled.last.as_ref().map_or(0, |s| s.dead.len()),
            self.target.report(),
        );
        assert!(
            polled.elapsed + EARLY >= window.min,
            "{} was back to its baseline after {:.2} s, before the expected mechanism can act: \
             {window}",
            w.label(),
            polled.elapsed.as_secs_f64(),
        );
        eprintln!(
            "{}: back to its baseline after {:.2} s; expected: {window}",
            w.label(),
            polled.elapsed.as_secs_f64()
        );
        Some(polled.elapsed)
    }

    /// Samples the process of `role` once and logs it with `note`.
    pub async fn observe(&self, role: Role, note: &str) -> Option<ProcSockets> {
        let w = self.watched(role);
        let polled = poll_until(
            &format!("{} ({note})", w.label()),
            w.pid,
            &self.ports,
            Instant::now(),
            Duration::ZERO,
            |_| true,
        )
        .await;
        polled.last
    }

    /// Kills the process of `role` (SIGKILL) and returns the instant before.
    pub fn kill(&mut self, role: Role) -> Instant {
        let at = Instant::now();
        let killed = match role {
            Role::Client => self.tunnel.client().kill().map(drop),
            Role::Server => self.tunnel.stop_server(),
        };
        killed.unwrap_or_else(|e| panic!("kill the {role}: {e}"));
        at
    }

    /// The log of the process of `role`.
    pub fn log(&self, role: Role) -> String {
        match role {
            Role::Client => self.tunnel.client_log(),
            Role::Server => self.tunnel.server_log(),
        }
    }

    /// Fails unless a Rust process of `role` logged a line containing every one of `needles`:
    /// the trace of the mechanism that ended a pipe (`pipe:` and `i/o timeout` for the stall
    /// rule). A Go process is not checked.
    pub fn expect_logged(&self, role: Role, needles: &[&str]) {
        if self.watched(role).which != Impl::Rust {
            return;
        }
        let log = self.log(role);
        assert!(
            log.lines().any(|l| needles.iter().all(|n| l.contains(n))),
            "the {role} never logged a line with {needles:?}; its pipe lines:\n{}",
            pipe_lines(&log)
        );
    }

    /// Fails if the process of `role` has exited or logged a panic.
    pub fn expect_alive(&mut self, role: Role) {
        let proc = match role {
            Role::Client => self.tunnel.client(),
            Role::Server => self.tunnel.server(),
        };
        if let Ok(Some(status)) = proc.try_wait() {
            panic!("the {role} exited ({status}):\n{}", proc.log_tail());
        }
        let log = proc.log();
        let panics = panic_lines(&log);
        assert!(
            panics.is_empty(),
            "the {role} panicked:\n{}",
            panics.join("\n")
        );
    }

    /// Logs the target's connections and both processes' pipe lines.
    pub fn report(&self) {
        eprintln!("target:\n{}", self.target.report());
        for role in [Role::Client, Role::Server] {
            eprintln!(
                "{} pipe lines:\n{}",
                self.watched(role).label(),
                pipe_lines(&self.log(role))
            );
        }
    }
}

/// The `stream opened`, `stream closed` and `pipe:` lines of a log.
pub fn pipe_lines(log: &str) -> String {
    let lines: Vec<&str> = log
        .lines()
        .filter(|l| {
            l.contains("pipe:") || l.contains("stream opened") || l.contains("stream closed")
        })
        .collect();
    if lines.is_empty() {
        "  (none)".to_string()
    } else {
        lines
            .iter()
            .map(|l| format!("  {l}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bounds use constants; they must still be what the binaries run.
    #[test]
    fn clocks_match_the_code() {
        assert_eq!(keepalive_timeout(), KEEPALIVE_TIMEOUT);
        assert_eq!(WATCH, Duration::from_secs(1));
        assert_eq!(SOCKET_STALL, Duration::from_secs(30));
        assert_eq!(socket_stall(Duration::from_secs(3)), SOCKET_STALL);
        assert_eq!(
            socket_stall(Duration::from_secs(45)),
            Duration::from_secs(45)
        );
    }

    #[test]
    fn graces_and_buffers_render_as_flags() {
        assert_eq!(Graces::flag(Some(2)), ["-closewait", "2"]);
        assert!(Graces::flag(None).is_empty());
        assert_eq!(Graces::DEFAULTS.client(), Duration::ZERO);
        assert_eq!(Graces::DEFAULTS.server(), Duration::from_secs(30));
        assert_eq!(Graces::EXPLICIT.client(), Duration::from_secs(2));
        assert_eq!(Graces::EXPLICIT.server(), Duration::from_secs(3));
        assert_eq!(
            Buffers::ROOMY.args(),
            [
                "-streambuf",
                "262144",
                "-smuxbuf",
                "1048576",
                "-sndwnd",
                "64",
                "-rcvwnd",
                "64"
            ]
        );
        // Two stalled streams (case 3) cannot spend the roomy session buffer.
        let roomy = Buffers::ROOMY;
        assert!(roomy.smuxbuf >= 2 * roomy.streambuf.max(256 * 1024) + 8192);
        assert_eq!(Buffers::STARVING.smuxbuf, Buffers::STARVING.streambuf);
        let args = RigSpec::new(Pairing::RUST).case().client_args();
        for flag in ["-nocomp", "-streambuf", "-smuxbuf", "-sndwnd", "-rcvwnd"] {
            assert!(
                args.iter().any(|a| a == flag),
                "{flag} missing from {args:?}"
            );
        }
    }

    /// The baseline predicate: the same descriptors, the same listeners, no connection, nothing
    /// dead; fewer descriptors only when allowed.
    #[test]
    fn back_to_baseline() {
        use kcptun_testkit::sockets::{DeadSocket, TcpSocket};
        let listener = TcpSocket {
            fd: 9,
            local: "127.0.0.1:5000".into(),
            remote: None,
            state: TcpState::Listen,
            recv_q: None,
            send_q: None,
        };
        let base = ProcSockets {
            pid: 1,
            tcp: vec![listener.clone()],
            udp: 1,
            unix: 3,
            other: 0,
            dead: Vec::new(),
            system: Default::default(),
        };
        assert!(back_to(&base, &base, false));

        let mut fw2 = base.clone();
        fw2.tcp.push(TcpSocket {
            fd: 10,
            local: "127.0.0.1:5000".into(),
            remote: Some("127.0.0.1:6000".into()),
            state: TcpState::FinWait2,
            recv_q: Some(1 << 20),
            send_q: Some(0),
        });
        assert!(!back_to(&base, &fw2, true), "a FIN-WAIT-2 socket is held");

        let mut dead = base.clone();
        dead.dead.push(DeadSocket {
            fd: 11,
            inode: Some(7),
            detail: None,
        });
        assert!(!back_to(&base, &dead, true), "a dead socket is held");

        let mut fewer = base.clone();
        fewer.udp = 0;
        assert!(!back_to(&base, &fewer, false));
        assert!(
            back_to(&base, &fewer, true),
            "the session's UDP socket went"
        );

        let mut no_listener = base.clone();
        no_listener.tcp.clear();
        no_listener.udp = 2;
        assert!(!back_to(&base, &no_listener, true), "the listener went");
    }
}
