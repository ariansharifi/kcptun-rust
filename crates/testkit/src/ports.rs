//! Allocation of free, consecutive port blocks for tests that need fixed ports (for example
//! kcptun's multiport syntax `host:22000-22003`, or a Go peer that must be told its port).
//!
//! Ports come from `[22000, 29000)`:
//! - well above 4000 (the lab hosts reserve the low ports; tools/lab/README.md forbids < 4000);
//! - clear of the ports lab-arm64's live services use (tools/lab/README.md: production kcptun
//!   clients on 127.0.0.1:21003-21509, our lab tunnels on 29900-29920, xray 49096/65001);
//! - below the *default* OS ephemeral ranges (Linux 32768-60999, macOS 49152-65535), so on
//!   default systems outgoing connections and `bind(:0)` never take a port inside a block.
//!   Hosts can differ: lab-arm64 uses `ip_local_port_range = 10000 62500`, and its production
//!   kcptun clients hold ephemeral UDP sockets inside this range. The bind probe below means we
//!   never collide with such sockets (and they never collide with ours); the only effect is a
//!   rare test flake if another process takes a port between our probe and our bind.
//!   tools/lab/README.md lists this range as the loopback-only interop test range.
//!
//! A block is only handed out when every port in it passes [`is_free`]: TCP and UDP each bind
//! on `127.0.0.1`, on `0.0.0.0` and (where IPv6 exists) on `[::]`, one after another. Probing
//! only `127.0.0.1` is not enough: on macOS/BSD a TCP listener with `SO_REUSEADDR` (std and Go
//! both set it) may bind `127.0.0.1:p` while another socket listens on `0.0.0.0:p` or a
//! dual-stack `[::]:p` (for example a Go kcptun `-l :p`), and the wildcard probes catch those.
//! Within one process a port is handed out at most once per pass over the range (a shared
//! cursor behind a mutex), so parallel tests never receive the same port. Separate test
//! processes start at different, pid-derived offsets and the bind probe catches the rest (it is
//! a snapshot: another process can still take a port between the probe and its use).

use std::io;
use std::net::{
    Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, UdpSocket,
};
use std::sync::Mutex;

use crate::rng::SplitMix64;

/// Lowest port ever allocated.
pub const PORT_MIN: u16 = 22000;
/// One past the highest port ever allocated.
pub const PORT_MAX: u16 = 29000;

/// Next candidate start port; `None` until first use (then seeded from the pid and time).
static CURSOR: Mutex<Option<u16>> = Mutex::new(None);

/// A block of consecutive ports that passed [`is_free`] (TCP and UDP) when allocated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortBlock {
    base: u16,
    count: u16,
}

impl PortBlock {
    /// First port.
    pub fn base(&self) -> u16 {
        self.base
    }

    /// Number of ports.
    pub fn count(&self) -> u16 {
        self.count
    }

    /// Last port (inclusive).
    pub fn last(&self) -> u16 {
        self.base + (self.count - 1)
    }

    /// The `i`-th port; panics if `i` is out of range.
    #[track_caller]
    pub fn port(&self, i: u16) -> u16 {
        assert!(
            i < self.count,
            "port index {i} out of block of {}",
            self.count
        );
        self.base + i
    }

    /// All ports in order.
    pub fn ports(&self) -> impl Iterator<Item = u16> + use<> {
        self.base..=self.last()
    }

    /// `127.0.0.1:<i-th port>`.
    #[track_caller]
    pub fn addr(&self, i: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port(i)))
    }

    /// kcptun's multiport range syntax, e.g. `22000-22003` (a single port for a block of 1).
    pub fn range_spec(&self) -> String {
        if self.count == 1 {
            self.base.to_string()
        } else {
            format!("{}-{}", self.base, self.last())
        }
    }
}

/// Returns true if `port` is free right now for TCP and UDP: each binds, one probe at a time,
/// on `127.0.0.1`, on `0.0.0.0` and on `[::]` (the IPv6 probes only fail the check with
/// `AddrInUse`, so hosts without IPv6 still work). See the [module docs](self) for why the
/// wildcard probes are needed. Callers creating sockets concurrently with process spawns
/// should hold [`socket_creation_guard`](crate::socket_creation_guard) (as [`allocate`] does).
pub fn is_free(port: u16) -> bool {
    let v4 = [
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)),
    ];
    let v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0));
    let v6_ok = |r: io::Result<()>| !matches!(r, Err(e) if e.kind() == io::ErrorKind::AddrInUse);
    // Each probe socket is dropped before the next bind, so probes never conflict with each
    // other (Linux refuses 0.0.0.0:p while this process holds 127.0.0.1:p).
    v4.iter().all(|a| TcpListener::bind(a).is_ok())
        && v6_ok(TcpListener::bind(v6).map(drop))
        && v4.iter().all(|a| UdpSocket::bind(a).is_ok())
        && v6_ok(UdpSocket::bind(v6).map(drop))
}

/// Allocates `n` consecutive ports free for TCP and UDP. Panics if `n` is 0 or no block is
/// free (which means the range is exhausted and a test is leaking ports).
#[track_caller]
pub fn allocate(n: u16) -> PortBlock {
    match try_allocate(n) {
        Some(b) => b,
        None => panic!("ports: no block of {n} free ports in [{PORT_MIN}, {PORT_MAX})"),
    }
}

/// Allocates one free port.
#[track_caller]
pub fn free_port() -> u16 {
    allocate(1).base()
}

/// Like [`allocate`], returning `None` instead of panicking.
pub fn try_allocate(n: u16) -> Option<PortBlock> {
    // A poisoned lock only means another test panicked while holding it; the cursor is still
    // a valid port number.
    let mut guard = CURSOR.lock().unwrap_or_else(|e| e.into_inner());
    let cursor = guard.unwrap_or_else(initial_cursor);
    let (block, next) = {
        let _fd = crate::fd_lock(); // probe sockets must not leak into spawned children
        scan(cursor, n, is_free)
    };
    *guard = Some(next);
    block
}

/// Searches one full pass over the range, starting at `cursor`, for `n` consecutive ports for
/// which `free` holds. Returns the block (if any) and the next cursor position.
fn scan(mut cursor: u16, n: u16, free: impl Fn(u16) -> bool) -> (Option<PortBlock>, u16) {
    let span = PORT_MAX - PORT_MIN;
    if !(PORT_MIN..PORT_MAX).contains(&cursor) {
        cursor = PORT_MIN;
    }
    if n == 0 || n > span {
        return (None, cursor);
    }
    let mut scanned: u32 = 0;
    while scanned < u32::from(span) {
        if u32::from(cursor) + u32::from(n) > u32::from(PORT_MAX) {
            // Not enough room before the end: wrap around.
            scanned += u32::from(PORT_MAX - cursor);
            cursor = PORT_MIN;
            continue;
        }
        match (cursor..cursor + n).find(|&p| !free(p)) {
            None => {
                let next = cursor + n;
                let next = if next >= PORT_MAX { PORT_MIN } else { next };
                return (
                    Some(PortBlock {
                        base: cursor,
                        count: n,
                    }),
                    next,
                );
            }
            Some(busy) => {
                // Skip past the busy port.
                scanned += u32::from(busy + 1 - cursor);
                cursor = busy + 1;
                if cursor >= PORT_MAX {
                    cursor = PORT_MIN;
                }
            }
        }
    }
    (None, cursor)
}

fn initial_cursor() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut sm = SplitMix64::new(u64::from(std::process::id()) ^ nanos.rotate_left(32));
    let span = u64::from(PORT_MAX - PORT_MIN);
    PORT_MIN + (sm.next_u64() % span) as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::thread;

    #[test]
    fn block_is_consecutive_free_and_in_range() {
        let b = allocate(4);
        assert!(b.base() >= PORT_MIN && b.last() < PORT_MAX);
        assert_eq!(b.count(), 4);
        assert_eq!(
            b.ports().collect::<Vec<_>>(),
            (b.base()..b.base() + 4).collect::<Vec<_>>()
        );
        assert_eq!(b.range_spec(), format!("{}-{}", b.base(), b.base() + 3));
        assert_eq!(b.addr(2).to_string(), format!("127.0.0.1:{}", b.base() + 2));
        // All ports really bind, for TCP and UDP at the same time.
        let _held: Vec<(TcpListener, UdpSocket)> = b
            .ports()
            .map(|p| {
                (
                    TcpListener::bind(("127.0.0.1", p)).unwrap(),
                    UdpSocket::bind(("127.0.0.1", p)).unwrap(),
                )
            })
            .collect();
        let one = allocate(1);
        assert_eq!(one.range_spec(), one.base().to_string());
        assert!(free_port() >= PORT_MIN);
    }

    #[test]
    fn parallel_allocations_never_overlap() {
        let handles: Vec<_> = (0..8)
            .map(|_| thread::spawn(|| (0..10).map(|_| allocate(3)).collect::<Vec<_>>()))
            .collect();
        let mut seen = HashSet::new();
        for h in handles {
            for b in h.join().unwrap() {
                for p in b.ports() {
                    assert!(seen.insert(p), "port {p} handed out twice");
                }
            }
        }
        assert_eq!(seen.len(), 8 * 10 * 3);
    }

    #[test]
    fn scan_skips_busy_ports_and_wraps() {
        let busy = [PORT_MIN + 5, PORT_MIN + 6, PORT_MAX - 1];
        let free = |p: u16| !busy.contains(&p);
        let (b, next) = scan(PORT_MIN + 3, 3, free);
        assert_eq!(b.unwrap().base(), PORT_MIN + 7);
        assert_eq!(next, PORT_MIN + 10);
        // Near the end: PORT_MAX-1 is busy and PORT_MAX-3.. does not fit, so wrap to the start.
        let (b, next) = scan(PORT_MAX - 3, 3, free);
        assert_eq!(b.unwrap().base(), PORT_MIN);
        assert_eq!(next, PORT_MIN + 3);
        // Exactly fitting at the end wraps the cursor.
        let (b, next) = scan(PORT_MAX - 2, 1, |_| true);
        assert_eq!(b.unwrap().base(), PORT_MAX - 2);
        assert_eq!(next, PORT_MAX - 1);
        let (_, next) = scan(PORT_MAX - 1, 1, |_| true);
        assert_eq!(next, PORT_MIN);
        // Nothing free: one pass, then give up.
        assert_eq!(scan(PORT_MIN + 100, 2, |_| false).0, None);
        // Out-of-range cursors restart at PORT_MIN.
        assert_eq!(scan(80, 1, |_| true).0.unwrap().base(), PORT_MIN);
    }

    #[test]
    fn is_free_requires_both_tcp_and_udp() {
        let p = free_port();
        // Keep children spawned by parallel tests from inheriting these sockets (see FD_LOCK).
        let _fd = crate::fd_lock();
        assert!(is_free(p));
        {
            let _udp = UdpSocket::bind(("127.0.0.1", p)).unwrap();
            assert!(!is_free(p), "a UDP-only bind must make the port busy");
        }
        {
            let _tcp = TcpListener::bind(("127.0.0.1", p)).unwrap();
            assert!(!is_free(p), "a TCP-only bind must make the port busy");
        }
        assert!(is_free(p));
    }

    #[test]
    fn is_free_detects_wildcard_listeners() {
        // std sets SO_REUSEADDR on TCP listeners; on macOS such a wildcard listener does not
        // stop a 127.0.0.1 bind, so only the wildcard probes can see it.
        let p = free_port();
        let _fd = crate::fd_lock();
        {
            let _tcp = TcpListener::bind(("0.0.0.0", p)).unwrap();
            assert!(
                !is_free(p),
                "a TCP listener on 0.0.0.0 must make the port busy"
            );
        }
        if let Ok(_tcp6) = TcpListener::bind(("::", p)) {
            assert!(
                !is_free(p),
                "a TCP listener on [::] must make the port busy"
            );
        }
        {
            let _udp = UdpSocket::bind(("0.0.0.0", p)).unwrap();
            assert!(
                !is_free(p),
                "a UDP socket on 0.0.0.0 must make the port busy"
            );
        }
        if let Ok(_udp6) = UdpSocket::bind(("::", p)) {
            assert!(!is_free(p), "a UDP socket on [::] must make the port busy");
        }
        assert!(is_free(p));
    }

    #[test]
    fn rejects_bad_sizes() {
        assert_eq!(try_allocate(0), None);
        assert_eq!(try_allocate(PORT_MAX - PORT_MIN + 1), None);
        assert_eq!(scan(PORT_MIN, 0, |_| true).0, None);
    }

    #[test]
    #[should_panic(expected = "out of block")]
    fn port_index_checked() {
        allocate(2).port(2);
    }
}
