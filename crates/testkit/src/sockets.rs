//! Per-process socket accounting, for the leak tests of the proxy pipe (deviation V24, DECISIONS
//! D35): which sockets a process holds, which TCP state each one is in, and which of them are
//! **dead**, closed by the kernel while the process still holds the descriptor.
//!
//! The production leak of v0.2.1 showed in three places, and one [`ProcSockets`] sample reads all
//! three for one process:
//!
//! | Symptom | Linux | macOS |
//! |---|---|---|
//! | descriptors held | `/proc/<pid>/fd` links `socket:[inode]` | `lsof -F` file list |
//! | dead sockets (the `TCP_CLOSE` sockets whose descriptor is still open, which `ss` does not list) | socket inodes of `/proc/<pid>/fd` that are in none of the `/proc/<pid>/net/*` tables | TCP sockets `lsof` reports `CLOSED` with a peer address, or `TIME_WAIT` |
//! | `FIN-WAIT-2` / `CLOSE-WAIT` | the process's own TCP sockets (`/proc/<pid>/net/tcp{,6}` joined on inode) | `lsof -T qs`, field `TST=` |
//!
//! The Linux dead count is the per-process, exact form of the host-wide figure
//! `awk '/^TCP:/{print $9-$3}' /proc/net/sockstat` (TCP sockets allocated but not hashed). The
//! tables searched are `tcp`, `tcp6`, `udp`, `udp6`, `udplite`, `udplite6`, `raw`, `raw6`,
//! `icmp`, `icmp6`, `unix`, `netlink` and `packet`: a superset of the TCP, UDP and unix tables, so
//! that a live socket of another family is never mistaken for a dead one. A socket lingers in no
//! table in two other cases, both transient: between `socket(2)` and its `connect(2)` or
//! `listen(2)`, and on Linux a socket that received the peer's FIN after its own `shutdown(2)`
//! (the kernel moves the connection to a `TIME_WAIT` twin and the descriptor's socket to
//! `TCP_CLOSE`, which is also a descriptor open on a finished connection). macOS keeps such a
//! socket in `TIME_WAIT` instead, which is why that state counts as dead there.
//!
//! [`SystemTcp`] adds host-wide figures for the log only: on Linux the `TCP:` line of
//! `/proc/net/sockstat`, and on both platforms the states of every TCP socket on a set of watched
//! ports, whoever owns it (the `ss -tn state fin-wait-2` view; `netstat -an -p tcp` on macOS,
//! which some sandboxes answer with an empty list, and the view is then reported unavailable).
//! It includes orphans the kernel times out by itself and the test's own sockets, so nothing
//! asserts on it.
//!
//! [`poll_until`] samples a process until a predicate holds or a deadline passes and logs every
//! sample: what a leak test asserts with.
//!
//! On macOS every sample spawns `lsof` and `netstat` (about 50 ms). They are spawned under
//! [`socket_creation_guard`](crate::socket_creation_guard), as every spawn in this crate is, so
//! they cannot inherit a socket the test is creating at that instant.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

/// How often [`poll_until`] samples.
pub const POLL_INTERVAL: Duration = Duration::from_millis(250);

// ---------------------------------------------------------------------------------------
// TCP state
// ---------------------------------------------------------------------------------------

/// A TCP state, displayed as `ss` names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TcpState {
    /// `ESTABLISHED`.
    Established,
    /// `SYN_SENT`.
    SynSent,
    /// `SYN_RECV` (Linux also has `NEW_SYN_RECV`, reported as this).
    SynRecv,
    /// `FIN_WAIT1`.
    FinWait1,
    /// `FIN_WAIT2`: this end has sent its FIN and the peer has acknowledged it, but not closed.
    FinWait2,
    /// `TIME_WAIT`.
    TimeWait,
    /// `CLOSE` (Linux) / `CLOSED` (BSD).
    Closed,
    /// `CLOSE_WAIT`: the peer has sent its FIN, this end has not closed.
    CloseWait,
    /// `LAST_ACK`.
    LastAck,
    /// `LISTEN`.
    Listen,
    /// `CLOSING`.
    Closing,
    /// Anything else.
    Unknown,
}

impl TcpState {
    /// The `st` column of `/proc/net/tcp` (`include/net/tcp_states.h`).
    pub fn from_linux(st: u8) -> TcpState {
        match st {
            0x01 => TcpState::Established,
            0x02 => TcpState::SynSent,
            0x03 | 0x0C => TcpState::SynRecv,
            0x04 => TcpState::FinWait1,
            0x05 => TcpState::FinWait2,
            0x06 => TcpState::TimeWait,
            0x07 => TcpState::Closed,
            0x08 => TcpState::CloseWait,
            0x09 => TcpState::LastAck,
            0x0A => TcpState::Listen,
            0x0B => TcpState::Closing,
            _ => TcpState::Unknown,
        }
    }

    /// A BSD state name, as `lsof` (`TST=`) and macOS `netstat` print it.
    pub fn from_bsd(name: &str) -> TcpState {
        match name {
            "ESTABLISHED" => TcpState::Established,
            "SYN_SENT" => TcpState::SynSent,
            "SYN_RCVD" | "SYN_RECV" | "SYN_RECEIVED" => TcpState::SynRecv,
            "FIN_WAIT_1" | "FIN_WAIT1" => TcpState::FinWait1,
            "FIN_WAIT_2" | "FIN_WAIT2" => TcpState::FinWait2,
            "TIME_WAIT" => TcpState::TimeWait,
            "CLOSED" | "CLOSE" => TcpState::Closed,
            "CLOSE_WAIT" => TcpState::CloseWait,
            "LAST_ACK" => TcpState::LastAck,
            "LISTEN" => TcpState::Listen,
            "CLOSING" => TcpState::Closing,
            _ => TcpState::Unknown,
        }
    }

    /// The name `ss` prints.
    pub fn name(self) -> &'static str {
        match self {
            TcpState::Established => "ESTAB",
            TcpState::SynSent => "SYN-SENT",
            TcpState::SynRecv => "SYN-RECV",
            TcpState::FinWait1 => "FIN-WAIT-1",
            TcpState::FinWait2 => "FIN-WAIT-2",
            TcpState::TimeWait => "TIME-WAIT",
            TcpState::Closed => "CLOSED",
            TcpState::CloseWait => "CLOSE-WAIT",
            TcpState::LastAck => "LAST-ACK",
            TcpState::Listen => "LISTEN",
            TcpState::Closing => "CLOSING",
            TcpState::Unknown => "UNKNOWN",
        }
    }
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------------------
// One sample
// ---------------------------------------------------------------------------------------

/// A TCP socket a process holds and the kernel still tracks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpSocket {
    /// The descriptor the process holds it under.
    pub fd: u32,
    /// Local address, `host:port` (`*:*` for an unbound socket on macOS).
    pub local: String,
    /// Peer address; `None` for a listener or an unconnected socket.
    pub remote: Option<String>,
    /// Its state.
    pub state: TcpState,
    /// Bytes received and not read by the process (for a listener on Linux: the accept backlog).
    pub recv_q: Option<u64>,
    /// Bytes written and not yet acknowledged by the peer.
    pub send_q: Option<u64>,
}

impl TcpSocket {
    /// The local port, if the socket is bound.
    pub fn local_port(&self) -> Option<u16> {
        port_of(&self.local)
    }

    /// The peer's port, if the socket is connected.
    pub fn remote_port(&self) -> Option<u16> {
        self.remote.as_deref().and_then(port_of)
    }

    /// Whether its local or peer port is one of `ports` (any socket when `ports` is empty).
    pub fn on_ports(&self, ports: &[u16]) -> bool {
        ports.is_empty()
            || [self.local_port(), self.remote_port()]
                .into_iter()
                .flatten()
                .any(|p| ports.contains(&p))
    }
}

impl fmt::Display for TcpSocket {
    /// `FIN-WAIT-2 127.0.0.1:5000->127.0.0.1:6000 rq=1048576 sq=0 (fd 12)`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.state, self.local)?;
        if let Some(remote) = &self.remote {
            write!(f, "->{remote}")?;
        }
        if let Some(q) = self.recv_q {
            write!(f, " rq={q}")?;
        }
        if let Some(q) = self.send_q {
            write!(f, " sq={q}")?;
        }
        write!(f, " (fd {})", self.fd)
    }
}

/// A socket descriptor the process still holds although its connection is over (see the
/// [module docs](self) for how each platform tells).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeadSocket {
    /// The descriptor.
    pub fd: u32,
    /// The socket inode (Linux).
    pub inode: Option<u64>,
    /// The addresses and state the platform still reports for it (macOS).
    pub detail: Option<String>,
}

impl fmt::Display for DeadSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fd {}", self.fd)?;
        if let Some(inode) = self.inode {
            write!(f, " inode {inode}")?;
        }
        if let Some(detail) = &self.detail {
            write!(f, " {detail}")?;
        }
        Ok(())
    }
}

/// The `TCP:` line of `/proc/net/sockstat` (Linux).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sockstat {
    /// Hashed TCP sockets of the network namespace (`inuse`).
    pub inuse: i64,
    /// Sockets no process holds any more, still finishing their close (`orphan`).
    pub orphan: i64,
    /// `TIME_WAIT` sockets (`tw`).
    pub tw: i64,
    /// Every allocated TCP socket of the host (`alloc`).
    pub alloc: i64,
    /// Pages of TCP memory (`mem`).
    pub mem: i64,
}

impl Sockstat {
    /// `alloc - inuse`: TCP sockets allocated but not hashed. A process holding descriptors of
    /// closed connections grows it; so do sockets between `socket(2)` and `connect(2)`.
    pub fn unhashed(&self) -> i64 {
        self.alloc - self.inuse
    }
}

/// Host-wide TCP figures, logged next to every sample and never asserted on (see the
/// [module docs](self)).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SystemTcp {
    /// The `TCP:` line of `/proc/net/sockstat` (Linux only).
    pub sockstat: Option<Sockstat>,
    /// Every TCP socket on the watched ports, whoever owns it, by state; `None` when no ports
    /// were given or the host's table could not be read.
    pub on_ports: Option<BTreeMap<TcpState, usize>>,
}

impl SystemTcp {
    /// Sockets on the watched ports in `state` (0 when the view is unavailable).
    pub fn on_ports_in(&self, state: TcpState) -> usize {
        self.on_ports
            .as_ref()
            .and_then(|m| m.get(&state))
            .copied()
            .unwrap_or(0)
    }
}

/// The sockets one process holds, at one instant. Build it with [`ProcSockets::sample`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcSockets {
    /// The process.
    pub pid: u32,
    /// Its TCP sockets the kernel still tracks.
    pub tcp: Vec<TcpSocket>,
    /// Its UDP sockets.
    pub udp: usize,
    /// Its unix-domain sockets.
    pub unix: usize,
    /// Its sockets of any other family (raw, netlink, kernel control, ...).
    pub other: usize,
    /// Its dead sockets.
    pub dead: Vec<DeadSocket>,
    /// The host-wide view (logged only).
    pub system: SystemTcp,
}

impl ProcSockets {
    /// Samples the sockets of process `pid`: `/proc` on Linux, `lsof` (and `netstat` for the
    /// host-wide view) on macOS, an `Unsupported` error elsewhere. `ports` selects the sockets
    /// [`SystemTcp::on_ports`] counts; it does not restrict the process's own sockets.
    pub fn sample(pid: u32, ports: &[u16]) -> io::Result<ProcSockets> {
        imp::sample(pid, ports)
    }

    /// An empty sample of `pid`.
    fn empty(pid: u32) -> ProcSockets {
        ProcSockets {
            pid,
            tcp: Vec::new(),
            udp: 0,
            unix: 0,
            other: 0,
            dead: Vec::new(),
            system: SystemTcp::default(),
        }
    }

    /// Socket descriptors held, of every kind, dead ones included.
    pub fn fds(&self) -> usize {
        self.tcp.len() + self.udp + self.unix + self.other + self.dead.len()
    }

    /// Listening TCP sockets.
    pub fn listeners(&self) -> usize {
        self.in_state(TcpState::Listen)
    }

    /// TCP sockets that are not listeners: every connection, whatever its state.
    pub fn connections(&self) -> usize {
        self.tcp.len() - self.listeners()
    }

    /// TCP sockets in `state`.
    pub fn in_state(&self, state: TcpState) -> usize {
        self.tcp.iter().filter(|s| s.state == state).count()
    }

    /// TCP sockets in `state` whose local or peer port is one of `ports`.
    pub fn in_state_on(&self, state: TcpState, ports: &[u16]) -> usize {
        self.tcp
            .iter()
            .filter(|s| s.state == state && s.on_ports(ports))
            .count()
    }

    /// The TCP socket held under descriptor `fd`.
    pub fn tcp_fd(&self, fd: u32) -> Option<&TcpSocket> {
        self.tcp.iter().find(|s| s.fd == fd)
    }

    /// One line for a log:
    /// `fds 6: tcp 2 [LISTEN 127.0.0.1:5000 (fd 9); ESTAB ...] udp 1 unix 3 other 0 dead 0 | ...`.
    pub fn summary(&self) -> String {
        let mut s = format!("fds {}: tcp {} [", self.fds(), self.tcp.len());
        for (i, t) in self.tcp.iter().enumerate() {
            if i > 0 {
                s.push_str("; ");
            }
            s.push_str(&t.to_string());
        }
        s.push_str(&format!(
            "] udp {} unix {} other {} dead {}",
            self.udp,
            self.unix,
            self.other,
            self.dead.len()
        ));
        if !self.dead.is_empty() {
            s.push_str(" [");
            for (i, d) in self.dead.iter().enumerate() {
                if i > 0 {
                    s.push_str("; ");
                }
                s.push_str(&d.to_string());
            }
            s.push(']');
        }
        s.push_str(" | host:");
        if let Some(stat) = self.system.sockstat {
            s.push_str(&format!(
                " sockstat unhashed {} orphan {} tw {}",
                stat.unhashed(),
                stat.orphan,
                stat.tw
            ));
        }
        match &self.system.on_ports {
            Some(on_ports) => {
                s.push_str(" on ports {");
                for (i, (state, n)) in on_ports.iter().enumerate() {
                    if i > 0 {
                        s.push_str(", ");
                    }
                    s.push_str(&format!("{state}: {n}"));
                }
                s.push('}');
            }
            None => s.push_str(" on ports n/a"),
        }
        s
    }
}

// ---------------------------------------------------------------------------------------
// Polling
// ---------------------------------------------------------------------------------------

/// What [`poll_until`] saw.
#[derive(Clone, Debug)]
pub struct Polled {
    /// Whether the predicate held before the deadline.
    pub met: bool,
    /// From `since` to the last sample taken (the one that met the predicate, if any).
    pub elapsed: Duration,
    /// How many samples were taken.
    pub samples: usize,
    /// The last successful sample.
    pub last: Option<ProcSockets>,
    /// Why sampling failed, if it did (the process is gone, `lsof` is missing, ...).
    pub error: Option<String>,
}

/// Samples process `pid` every [`POLL_INTERVAL`] until `pred` holds for a sample or `within` has
/// passed since `since`, and logs every sample to stderr as `[<label>] +<seconds> <summary>`.
///
/// The first sample is taken at once, so a predicate that already holds costs one sample. A
/// failed sample ends the polling (it is logged, and reported in [`Polled::error`]): a process
/// that has exited stays exited. Each sample runs on tokio's blocking pool, so a slow `lsof`
/// never stalls the runtime.
pub async fn poll_until<F>(
    label: &str,
    pid: u32,
    ports: &[u16],
    since: Instant,
    within: Duration,
    mut pred: F,
) -> Polled
where
    F: FnMut(&ProcSockets) -> bool,
{
    let deadline = since + within;
    let mut samples = 0;
    let mut last = None;
    loop {
        let taken = Instant::now();
        let watched = ports.to_vec();
        let sampled = tokio::task::spawn_blocking(move || ProcSockets::sample(pid, &watched))
            .await
            .unwrap_or_else(|e| Err(io::Error::other(e)));
        let elapsed = taken.saturating_duration_since(since);
        samples += 1;
        match sampled {
            Ok(sample) => {
                let met = pred(&sample);
                eprintln!(
                    "[{label}] +{:.2}s {}{}",
                    elapsed.as_secs_f64(),
                    sample.summary(),
                    if met { "  <= met" } else { "" }
                );
                last = Some(sample);
                if met {
                    return Polled {
                        met,
                        elapsed,
                        samples,
                        last,
                        error: None,
                    };
                }
            }
            Err(e) => {
                eprintln!(
                    "[{label}] +{:.2}s sampling pid {pid} failed: {e}",
                    elapsed.as_secs_f64()
                );
                return Polled {
                    met: false,
                    elapsed,
                    samples,
                    last,
                    error: Some(e.to_string()),
                };
            }
        }
        if Instant::now() >= deadline {
            return Polled {
                met: false,
                elapsed,
                samples,
                last,
                error: None,
            };
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

// ---------------------------------------------------------------------------------------
// Parsers (pure, so they are unit-tested on every platform)
// ---------------------------------------------------------------------------------------

/// The port of a `host:port` string (`[v6]:port` included); `None` for `*` or no port.
pub fn port_of(addr: &str) -> Option<u16> {
    addr.rsplit_once(':')?.1.parse().ok()
}

/// The inode of a `/proc/<pid>/fd` link that names a socket (`socket:[12345]`).
pub fn parse_socket_link(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// One row of `/proc/net/{tcp,tcp6,udp,udp6,raw,...}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InetEntry {
    /// `local_address`.
    pub local: SocketAddr,
    /// `rem_address`.
    pub remote: SocketAddr,
    /// `st`, the kernel's state number ([`TcpState::from_linux`] for TCP).
    pub state: u8,
    /// `tx_queue`.
    pub tx_queue: u64,
    /// `rx_queue`.
    pub rx_queue: u64,
    /// `inode`; 0 for a socket no process holds (`TIME_WAIT`, orphans).
    pub inode: u64,
}

/// Decodes a `/proc/net/tcp` address, `0100007F:1F90`. The kernel prints the address's bytes as
/// native-endian 32-bit words (`%08X`), so they are read back the same way; the port is a plain
/// big-endian number.
fn decode_proc_addr(s: &str) -> Option<SocketAddr> {
    let (ip, port) = s.split_once(':')?;
    if !ip.is_ascii() {
        return None;
    }
    let port = u16::from_str_radix(port, 16).ok()?;
    let word = |i: usize| -> Option<[u8; 4]> {
        Some(
            u32::from_str_radix(ip.get(i * 8..i * 8 + 8)?, 16)
                .ok()?
                .to_ne_bytes(),
        )
    };
    let ip = match ip.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(0)?)),
        32 => {
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                bytes[i * 4..i * 4 + 4].copy_from_slice(&word(i)?);
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// Parses `/proc/net/{tcp,tcp6,udp,udp6,raw,...}`; the header and malformed rows are skipped.
pub fn parse_proc_net_inet(text: &str) -> Vec<InetEntry> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 || !f[0].ends_with(':') {
                return None;
            }
            let (tx, rx) = f[4].split_once(':')?;
            Some(InetEntry {
                local: decode_proc_addr(f[1])?,
                remote: decode_proc_addr(f[2])?,
                state: u8::from_str_radix(f[3], 16).ok()?,
                tx_queue: u64::from_str_radix(tx, 16).ok()?,
                rx_queue: u64::from_str_radix(rx, 16).ok()?,
                inode: f[9].parse().ok()?,
            })
        })
        .collect()
}

/// The inodes of `/proc/net/unix` (column 7: `Num RefCount Protocol Flags Type St Inode Path`).
pub fn parse_proc_net_unix(text: &str) -> Vec<u64> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 7 || !f[0].ends_with(':') {
                return None;
            }
            f[6].parse().ok()
        })
        .collect()
}

/// The inodes of a table whose last column is the inode (`/proc/net/netlink`,
/// `/proc/net/packet`); the header's last column is the word `Inode` and is skipped.
pub fn parse_proc_net_last_column(text: &str) -> Vec<u64> {
    text.lines()
        .filter_map(|line| line.split_whitespace().last()?.parse().ok())
        .collect()
}

/// The `TCP:` line of `/proc/net/sockstat`:
/// `TCP: inuse 5 orphan 0 tw 0 alloc 8 mem 1`.
pub fn parse_sockstat(text: &str) -> Option<Sockstat> {
    let line = text.lines().find(|l| l.starts_with("TCP:"))?;
    let words: Vec<&str> = line.split_whitespace().collect();
    let field = |name: &str| -> Option<i64> {
        let i = words.iter().position(|w| *w == name)?;
        words.get(i + 1)?.parse().ok()
    };
    Some(Sockstat {
        inuse: field("inuse")?,
        orphan: field("orphan").unwrap_or(0),
        tw: field("tw").unwrap_or(0),
        alloc: field("alloc")?,
        mem: field("mem").unwrap_or(0),
    })
}

/// The tables of one network namespace, as [`classify_proc`] needs them.
#[derive(Clone, Debug, Default)]
pub struct ProcTables {
    /// TCP rows by inode (rows with inode 0 are left out: no process holds them).
    pub tcp: HashMap<u64, InetEntry>,
    /// Every TCP row, for the host-wide view of the watched ports.
    pub tcp_rows: Vec<InetEntry>,
    /// UDP and UDP-Lite inodes.
    pub udp: HashSet<u64>,
    /// Unix-domain inodes.
    pub unix: HashSet<u64>,
    /// Raw, ICMP, netlink and packet inodes.
    pub other: HashSet<u64>,
}

/// Classifies the socket descriptors of a process, `(fd, inode)` from `/proc/<pid>/fd`, against
/// its namespace's tables: an inode in no table is a dead socket.
pub fn classify_proc(
    pid: u32,
    fds: &[(u32, u64)],
    tables: &ProcTables,
    ports: &[u16],
) -> ProcSockets {
    let mut out = ProcSockets::empty(pid);
    for &(fd, inode) in fds {
        if let Some(e) = tables.tcp.get(&inode) {
            let connected = !(e.remote.ip().is_unspecified() && e.remote.port() == 0);
            out.tcp.push(TcpSocket {
                fd,
                local: e.local.to_string(),
                remote: connected.then(|| e.remote.to_string()),
                state: TcpState::from_linux(e.state),
                recv_q: Some(e.rx_queue),
                send_q: Some(e.tx_queue),
            });
        } else if tables.udp.contains(&inode) {
            out.udp += 1;
        } else if tables.unix.contains(&inode) {
            out.unix += 1;
        } else if tables.other.contains(&inode) {
            out.other += 1;
        } else {
            out.dead.push(DeadSocket {
                fd,
                inode: Some(inode),
                detail: None,
            });
        }
    }
    out.tcp.sort_by_key(|s| s.fd);
    out.dead.sort_by_key(|d| d.fd);
    if !ports.is_empty() {
        let mut on_ports = BTreeMap::new();
        for e in &tables.tcp_rows {
            if ports.contains(&e.local.port()) || ports.contains(&e.remote.port()) {
                *on_ports.entry(TcpState::from_linux(e.state)).or_insert(0) += 1;
            }
        }
        out.system.on_ports = Some(on_ports);
    }
    out
}

/// One file of `lsof -F ftPTn` output.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LsofFile {
    /// The descriptor; `None` for `cwd`, `txt` and the like.
    pub fd: Option<u32>,
    /// `t`: `IPv4`, `IPv6`, `unix`, `REG`, `KQUEUE`, ...
    pub kind: String,
    /// `P`: `TCP`, `UDP`, ...
    pub proto: Option<String>,
    /// `n`: `127.0.0.1:5000->127.0.0.1:6000`, `*:*`, a path, ...
    pub name: Option<String>,
    /// `TST=`: the TCP state.
    pub state: Option<String>,
    /// `TQR=`: the receive queue.
    pub recv_q: Option<u64>,
    /// `TQS=`: the send queue.
    pub send_q: Option<u64>,
}

/// Parses `lsof -F ftPTn` output: one `f` line starts each file, the other fields follow it.
pub fn parse_lsof(text: &str) -> Vec<LsofFile> {
    let mut files = Vec::new();
    let mut current: Option<LsofFile> = None;
    for line in text.lines() {
        let Some(tag) = line.chars().next() else {
            continue;
        };
        let value = &line[tag.len_utf8()..];
        if tag == 'f' {
            files.extend(current.take());
            current = Some(LsofFile {
                fd: value.parse().ok(),
                ..LsofFile::default()
            });
            continue;
        }
        let Some(file) = current.as_mut() else {
            continue;
        };
        match tag {
            't' => file.kind = value.to_string(),
            'P' => file.proto = Some(value.to_string()),
            'n' => file.name = Some(value.to_string()),
            'T' => match value.split_once('=') {
                Some(("ST", v)) => file.state = Some(v.to_string()),
                Some(("QR", v)) => file.recv_q = v.parse().ok(),
                Some(("QS", v)) => file.send_q = v.parse().ok(),
                _ => {}
            },
            _ => {}
        }
    }
    files.extend(current);
    files
}

/// Classifies `lsof` output for one process. A TCP socket `lsof` reports `CLOSED` with a peer
/// address (the connection was reset or timed out) or `TIME_WAIT` (both sides have closed) is
/// dead: the descriptor is all that is left of it. `CLOSED` with no peer (`*:*`) is a socket
/// that has not connected yet.
pub fn classify_lsof(pid: u32, files: &[LsofFile]) -> ProcSockets {
    let mut out = ProcSockets::empty(pid);
    for file in files {
        let Some(fd) = file.fd else {
            continue;
        };
        match file.kind.as_str() {
            "IPv4" | "IPv6" => match file.proto.as_deref() {
                Some("TCP") => {
                    let name = file.name.as_deref().unwrap_or("");
                    let (local, remote) = match name.split_once("->") {
                        Some((l, r)) => (l.to_string(), Some(r.to_string())),
                        None => (name.to_string(), None),
                    };
                    let state = file
                        .state
                        .as_deref()
                        .map_or(TcpState::Unknown, TcpState::from_bsd);
                    let over = (state == TcpState::Closed && remote.is_some())
                        || state == TcpState::TimeWait;
                    if over {
                        out.dead.push(DeadSocket {
                            fd,
                            inode: None,
                            detail: Some(format!("{state} {name}")),
                        });
                    } else {
                        out.tcp.push(TcpSocket {
                            fd,
                            local,
                            remote,
                            state,
                            recv_q: file.recv_q,
                            send_q: file.send_q,
                        });
                    }
                }
                Some("UDP") => out.udp += 1,
                _ => out.other += 1,
            },
            "unix" => out.unix += 1,
            // lsof's names for the other socket families on Darwin: kernel control and event
            // sockets, network drivers, PF_KEY, routing, and any unknown domain.
            "systm" | "ndrv" | "key" | "rte" | "sock" => out.other += 1,
            _ => {}
        }
    }
    out.tcp.sort_by_key(|s| s.fd);
    out.dead.sort_by_key(|d| d.fd);
    out
}

/// The `(local port, peer port, state)` of every TCP row of BSD `netstat -an -p tcp`, where an
/// address is `host.port` (`*.*` when unbound).
pub fn parse_netstat_tcp(text: &str) -> Vec<(Option<u16>, Option<u16>, TcpState)> {
    let port = |addr: &str| -> Option<u16> { addr.rsplit_once('.')?.1.parse().ok() };
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 6 || !f[0].starts_with("tcp") {
                return None;
            }
            Some((port(f[3]), port(f[4]), TcpState::from_bsd(f[5])))
        })
        .collect()
}

// ---------------------------------------------------------------------------------------
// Platforms
// ---------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod imp {
    use super::*;

    /// The tables of the inet families, other than TCP, that only need their inodes.
    const UDP_TABLES: [&str; 4] = ["udp", "udp6", "udplite", "udplite6"];
    const OTHER_INET_TABLES: [&str; 4] = ["raw", "raw6", "icmp", "icmp6"];
    const OTHER_LAST_COLUMN_TABLES: [&str; 2] = ["netlink", "packet"];

    pub(super) fn sample(pid: u32, ports: &[u16]) -> io::Result<ProcSockets> {
        let fds = socket_fds(pid)?;
        // The process's own view of the network: its namespace, whatever the test's is.
        let net = format!("/proc/{pid}/net");
        // A table the kernel does not have (no IPv6, no UDP-Lite) has no sockets in it.
        let read =
            |name: &str| std::fs::read_to_string(format!("{net}/{name}")).unwrap_or_default();
        let mut tables = ProcTables::default();
        for name in ["tcp", "tcp6"] {
            for e in parse_proc_net_inet(&read(name)) {
                if e.inode != 0 {
                    tables.tcp.insert(e.inode, e);
                }
                tables.tcp_rows.push(e);
            }
        }
        for name in UDP_TABLES {
            tables
                .udp
                .extend(parse_proc_net_inet(&read(name)).iter().map(|e| e.inode));
        }
        tables.unix.extend(parse_proc_net_unix(&read("unix")));
        for name in OTHER_INET_TABLES {
            tables
                .other
                .extend(parse_proc_net_inet(&read(name)).iter().map(|e| e.inode));
        }
        for name in OTHER_LAST_COLUMN_TABLES {
            tables.other.extend(parse_proc_net_last_column(&read(name)));
        }
        let mut out = classify_proc(pid, &fds, &tables, ports);
        out.system.sockstat = parse_sockstat(&read("sockstat"));
        Ok(out)
    }

    /// `(fd, inode)` of every socket descriptor of `pid`. A descriptor closed between the
    /// directory listing and its `readlink` is skipped.
    fn socket_fds(pid: u32) -> io::Result<Vec<(u32, u64)>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(format!("/proc/{pid}/fd"))? {
            let Ok(entry) = entry else {
                continue;
            };
            let Some(fd) = entry.file_name().to_str().and_then(|s| s.parse().ok()) else {
                continue;
            };
            let Ok(link) = std::fs::read_link(entry.path()) else {
                continue;
            };
            if let Some(inode) = link.to_str().and_then(parse_socket_link) {
                out.push((fd, inode));
            }
        }
        Ok(out)
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use std::path::Path;
    use std::process::{Command, Output, Stdio};

    pub(super) fn sample(pid: u32, ports: &[u16]) -> io::Result<ProcSockets> {
        let pid_arg = pid.to_string();
        // -n -P: no name lookups; -w: no warnings; -a -p: this process only; -T qs: TCP state and
        // queue sizes; -F: one field per line.
        let lsof = run(
            &["/usr/sbin/lsof", "/usr/bin/lsof", "lsof"],
            &["-nP", "-w", "-a", "-p", &pid_arg, "-T", "qs", "-F", "ftPTn"],
        )?;
        let text = String::from_utf8_lossy(&lsof.stdout);
        // lsof exits 1 and prints nothing when the process has no open files, i.e. is gone.
        if !lsof.status.success() && text.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("lsof lists nothing for pid {pid}: the process is gone"),
            ));
        }
        let mut out = classify_lsof(pid, &parse_lsof(&text));
        if !ports.is_empty() {
            // The host-wide view is for the log, so a netstat that fails, or lists no TCP socket
            // at all, leaves it unavailable. (Some sandboxes hand a non-interactive netstat an
            // empty socket list; a real host always has at least the test's own sockets.)
            let rows = run(
                &["/usr/sbin/netstat", "/usr/bin/netstat", "netstat"],
                &["-an", "-p", "tcp"],
            )
            .map(|o| parse_netstat_tcp(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default();
            if !rows.is_empty() {
                let mut on_ports = BTreeMap::new();
                for (local, remote, state) in rows {
                    if [local, remote]
                        .into_iter()
                        .flatten()
                        .any(|p| ports.contains(&p))
                    {
                        *on_ports.entry(state).or_insert(0) += 1;
                    }
                }
                out.system.on_ports = Some(on_ports);
            }
        }
        Ok(out)
    }

    /// Runs the first of `programs` that exists (the last one through `PATH`). The spawn holds
    /// the crate's descriptor lock, as every spawn here does; the wait does not.
    fn run(programs: &[&str], args: &[&str]) -> io::Result<Output> {
        let program = programs
            .iter()
            .find(|p| Path::new(p).exists())
            .or(programs.last())
            .copied()
            .unwrap_or("lsof");
        let child = {
            let _fd = crate::fd_lock();
            Command::new(program)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
        }
        .map_err(|e| io::Error::new(e.kind(), format!("spawn {program}: {e}")))?;
        child.wait_with_output()
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod imp {
    use super::*;

    pub(super) fn sample(pid: u32, _ports: &[u16]) -> io::Result<ProcSockets> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("socket accounting of pid {pid} needs Linux (/proc) or macOS (lsof)"),
        ))
    }
}

#[cfg(test)]
#[path = "sockets_tests.rs"]
mod tests;
