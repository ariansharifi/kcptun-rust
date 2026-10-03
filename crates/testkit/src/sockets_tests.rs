//! Tests of [`super`]: the parsers against captured output (so the Linux code paths are checked
//! on macOS too), and, on Linux and macOS, a live sample of this test process's own sockets.

use super::*;

/// `/proc/net/tcp` of a little-endian host: a listener on 127.0.0.1:8080, a FIN-WAIT-2 socket
/// with 1 MiB unread, its CLOSE-WAIT peer, and a TIME-WAIT row no process holds (inode 0).
const PROC_TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 31337 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 0100007F:D431 05 00000000:00100000 00:00000000 00000000  1000        0 31338 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:D431 0100007F:1F90 08 00000000:00000000 00:00000000 00000000  1000        0 31339 1 0000000000000000 20 4 30 10 -1
   3: 0100007F:D432 0100007F:1F90 06 00000000:00000000 03:000016A8 00000000     0        0 0 3 0000000000000000
";

/// `/proc/net/tcp6`: a listener on [::1]:8081 and an established v4-mapped connection.
const PROC_TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 41000 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000100007F:1F92 0000000000000000FFFF00000100007F:C000 01 00000010:00000000 01:00000014 00000000  1000        0 41001 1 0000000000000000 20 4 30 10 -1
";

const PROC_UDP: &str = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  123: 00000000:5DC0 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 50001 2 0000000000000000 0
";

const PROC_UNIX: &str = "Num       RefCount Protocol Flags    Type St Inode Path
0000000000000000: 00000002 00000000 00010000 0001 01 22001 /run/systemd/notify
0000000000000000: 00000003 00000000 00000000 0001 03 22002
";

const PROC_NETLINK: &str =
    "sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode
0000000000000000 0   1234       00000000 0        0        0     2        0        33001
";

const SOCKSTAT: &str = "sockets: used 210
TCP: inuse 7 orphan 1 tw 2 alloc 12 mem 3
UDP: inuse 4 mem 1
UDPLITE: inuse 0
RAW: inuse 0
FRAG: inuse 0 memory 0
";

/// `lsof -nP -w -a -p <pid> -T qs -F ftPTn` on macOS: the files that are not sockets, a
/// listener, a FIN-WAIT-2 socket with 1000 bytes unread, a reset connection still held
/// (`CLOSED` with addresses), a TIME-WAIT socket still held, a socket not yet connected
/// (`CLOSED`, `*:*`), a UDP socket, two unix sockets and a kernel-control socket.
const LSOF: &str = "p94850
fcwd
tDIR
n/Users/someone
ftxt
tREG
n/usr/lib/dyld
f0
tCHR
n/dev/null
f3
tIPv4
PTCP
n127.0.0.1:55737
TST=LISTEN
TQR=0
TQS=0
f4
tKQUEUE
ncount=0, state=0xa
f5
tIPv4
PTCP
n127.0.0.1:55737->127.0.0.1:55738
TST=CLOSED
TQR=0
TQS=0
f6
tIPv4
PUDP
n*:64347
f7
tunix
n->0xbef859b834174420
f8
tunix
n->0xd0c79987b3c455a4
f9
tIPv4
PTCP
n*:*
TST=CLOSED
TQR=0
TQS=0
f10
tIPv4
PTCP
n127.0.0.1:55737->127.0.0.1:55739
TST=FIN_WAIT_2
TQR=1000
TQS=0
f11
tPIPE
n->0xa27f635ab22cb37b
f12
tIPv6
PTCP
n[::1]:5000->[::1]:6000
TST=TIME_WAIT
TQR=0
TQS=0
f13
tsystm
n[ctl com.apple.netsrc id 7 unit 20]
";

const NETSTAT: &str = "Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4    1000      0  127.0.0.1.55737        127.0.0.1.55739        FIN_WAIT_2
tcp4       0      0  127.0.0.1.55739        127.0.0.1.55737        CLOSE_WAIT
tcp4       0      0  127.0.0.1.55737        *.*                    LISTEN
tcp6       0      0  *.5000                 *.*                    LISTEN
tcp4       0      0  127.0.0.1.60000        127.0.0.1.60001        ESTABLISHED
udp4       0      0  *.5353                 *.*
";

#[test]
fn states_from_both_spellings() {
    assert_eq!(TcpState::from_linux(0x05), TcpState::FinWait2);
    assert_eq!(TcpState::from_linux(0x08), TcpState::CloseWait);
    assert_eq!(TcpState::from_linux(0x07), TcpState::Closed);
    assert_eq!(TcpState::from_linux(0x0A), TcpState::Listen);
    assert_eq!(TcpState::from_linux(0x0C), TcpState::SynRecv);
    assert_eq!(TcpState::from_linux(0x42), TcpState::Unknown);
    assert_eq!(TcpState::from_bsd("FIN_WAIT_2"), TcpState::FinWait2);
    assert_eq!(TcpState::from_bsd("CLOSE_WAIT"), TcpState::CloseWait);
    assert_eq!(TcpState::from_bsd("CLOSED"), TcpState::Closed);
    assert_eq!(TcpState::from_bsd("SYN_RCVD"), TcpState::SynRecv);
    assert_eq!(TcpState::from_bsd("nonsense"), TcpState::Unknown);
    assert_eq!(TcpState::FinWait2.to_string(), "FIN-WAIT-2");
    assert_eq!(TcpState::CloseWait.name(), "CLOSE-WAIT");
}

#[test]
fn ports_and_socket_links() {
    assert_eq!(port_of("127.0.0.1:8080"), Some(8080));
    assert_eq!(port_of("[::1]:5000"), Some(5000));
    assert_eq!(port_of("*:*"), None);
    assert_eq!(port_of("nothing"), None);
    assert_eq!(parse_socket_link("socket:[12345]"), Some(12345));
    assert_eq!(parse_socket_link("pipe:[12345]"), None);
    assert_eq!(parse_socket_link("anon_inode:[eventpoll]"), None);
    assert_eq!(parse_socket_link("socket:[nope]"), None);
}

#[test]
fn proc_net_tcp_rows() {
    let rows = parse_proc_net_inet(PROC_TCP);
    assert_eq!(rows.len(), 4, "the header is skipped");
    let ports: Vec<(u16, u16, u8, u64)> = rows
        .iter()
        .map(|e| (e.local.port(), e.remote.port(), e.state, e.inode))
        .collect();
    assert_eq!(
        ports,
        [
            (8080, 0, 0x0A, 31337),
            (8080, 54321, 0x05, 31338),
            (54321, 8080, 0x08, 31339),
            (54322, 8080, 0x06, 0),
        ]
    );
    assert_eq!(rows[1].rx_queue, 1 << 20, "1 MiB unread");
    assert_eq!(rows[1].tx_queue, 0);

    let rows6 = parse_proc_net_inet(PROC_TCP6);
    assert_eq!(rows6.len(), 2);
    assert_eq!(rows6[0].local.port(), 8081);
    assert_eq!(rows6[1].tx_queue, 0x10);
    // The words of an address are the kernel's native-endian view of the network-order bytes;
    // every Linux target this project supports (x86_64, aarch64) is little-endian.
    if cfg!(target_endian = "little") {
        assert_eq!(rows[0].local.to_string(), "127.0.0.1:8080");
        assert_eq!(rows6[0].local.to_string(), "[::1]:8081");
        assert_eq!(rows6[1].remote.to_string(), "[::ffff:127.0.0.1]:49152");
    }
}

#[test]
fn proc_net_other_tables_and_sockstat() {
    assert_eq!(parse_proc_net_unix(PROC_UNIX), [22001, 22002]);
    assert_eq!(parse_proc_net_last_column(PROC_NETLINK), [33001]);
    let udp: Vec<u64> = parse_proc_net_inet(PROC_UDP)
        .iter()
        .map(|e| e.inode)
        .collect();
    assert_eq!(udp, [50001]);

    let stat = parse_sockstat(SOCKSTAT).expect("TCP line");
    assert_eq!(
        stat,
        Sockstat {
            inuse: 7,
            orphan: 1,
            tw: 2,
            alloc: 12,
            mem: 3
        }
    );
    // What `awk '/^TCP:/{print $9-$3}' /proc/net/sockstat` prints.
    assert_eq!(stat.unhashed(), 5);
    assert_eq!(parse_sockstat("UDP: inuse 4 mem 1\n"), None);
}

#[test]
fn proc_classification_finds_the_dead_inode() {
    let mut tables = ProcTables::default();
    for e in parse_proc_net_inet(PROC_TCP)
        .into_iter()
        .chain(parse_proc_net_inet(PROC_TCP6))
    {
        if e.inode != 0 {
            tables.tcp.insert(e.inode, e);
        }
        tables.tcp_rows.push(e);
    }
    tables
        .udp
        .extend(parse_proc_net_inet(PROC_UDP).iter().map(|e| e.inode));
    tables.unix.extend(parse_proc_net_unix(PROC_UNIX));
    tables
        .other
        .extend(parse_proc_net_last_column(PROC_NETLINK));

    // fd 8 names a socket in no table: a TCP_CLOSE socket whose descriptor is still open.
    let fds = [
        (3, 31337),
        (4, 31338),
        (5, 41001),
        (6, 22002),
        (7, 50001),
        (8, 99999),
        (9, 33001),
    ];
    let s = classify_proc(42, &fds, &tables, &[8080]);
    assert_eq!(s.pid, 42);
    assert_eq!(s.fds(), 7);
    assert_eq!(s.tcp.len(), 3);
    assert_eq!((s.udp, s.unix, s.other), (1, 1, 1));
    assert_eq!(
        s.dead,
        [DeadSocket {
            fd: 8,
            inode: Some(99999),
            detail: None
        }]
    );
    assert_eq!(s.listeners(), 1);
    assert_eq!(s.connections(), 2);
    assert_eq!(s.in_state(TcpState::FinWait2), 1);
    assert_eq!(s.in_state_on(TcpState::FinWait2, &[8080]), 1);
    assert_eq!(s.in_state_on(TcpState::FinWait2, &[9]), 0);
    let fw2 = s.tcp_fd(4).expect("fd 4");
    assert_eq!(fw2.recv_q, Some(1 << 20));
    assert_eq!(fw2.local_port(), Some(8080));
    assert_eq!(fw2.remote_port(), Some(54321));
    assert_eq!(s.tcp_fd(3).expect("listener").remote, None);

    // The host-wide view counts every row on port 8080, whoever holds it.
    assert_eq!(s.system.on_ports_in(TcpState::Listen), 1);
    assert_eq!(s.system.on_ports_in(TcpState::FinWait2), 1);
    assert_eq!(s.system.on_ports_in(TcpState::CloseWait), 1);
    assert_eq!(s.system.on_ports_in(TcpState::TimeWait), 1);
    let summary = s.summary();
    assert!(summary.starts_with("fds 7: tcp 3 ["), "{summary}");
    assert!(summary.contains("dead 1 [fd 8 inode 99999]"), "{summary}");
    assert!(summary.contains("FIN-WAIT-2: 1"), "{summary}");
}

#[test]
fn lsof_classification_finds_closed_and_time_wait_holders() {
    let files = parse_lsof(LSOF);
    assert_eq!(files.len(), 14, "{files:#?}");
    assert_eq!(files[0].fd, None, "cwd has no descriptor number");
    let s = classify_lsof(7, &files);
    // The listener, the unconnected socket and the FIN-WAIT-2 socket are live TCP sockets.
    let live: Vec<(u32, TcpState)> = s.tcp.iter().map(|t| (t.fd, t.state)).collect();
    assert_eq!(
        live,
        [
            (3, TcpState::Listen),
            (9, TcpState::Closed),
            (10, TcpState::FinWait2)
        ]
    );
    let fw2 = s.tcp_fd(10).expect("fd 10");
    assert_eq!(fw2.local, "127.0.0.1:55737");
    assert_eq!(fw2.remote.as_deref(), Some("127.0.0.1:55739"));
    assert_eq!((fw2.recv_q, fw2.send_q), (Some(1000), Some(0)));
    assert_eq!(s.tcp_fd(9).expect("fd 9").remote, None);
    // The reset connection and the TIME-WAIT socket are what is left of finished connections.
    let dead: Vec<u32> = s.dead.iter().map(|d| d.fd).collect();
    assert_eq!(dead, [5, 12]);
    assert_eq!(
        s.dead[0].detail.as_deref(),
        Some("CLOSED 127.0.0.1:55737->127.0.0.1:55738")
    );
    assert_eq!((s.udp, s.unix, s.other), (1, 2, 1));
    assert_eq!(s.fds(), 3 + 2 + 1 + 2 + 1);
    assert_eq!(
        s.connections(),
        2,
        "the FIN-WAIT-2 and the unconnected socket"
    );
}

#[test]
fn netstat_rows() {
    let rows = parse_netstat_tcp(NETSTAT);
    assert_eq!(
        rows,
        [
            (Some(55737), Some(55739), TcpState::FinWait2),
            (Some(55739), Some(55737), TcpState::CloseWait),
            (Some(55737), None, TcpState::Listen),
            (Some(5000), None, TcpState::Listen),
            (Some(60000), Some(60001), TcpState::Established),
        ]
    );
}

/// A live sample of this process: a listener, a half-closed connection (`FIN-WAIT-2` on the
/// side that shut its write half down, `CLOSE-WAIT` on its peer), a connection its peer reset
/// while this side still holds it (dead), and a UDP socket, each found by its descriptor.
///
/// Every socket is made under [`socket_creation_guard`](crate::socket_creation_guard), so a
/// child that another test spawns at that moment cannot inherit one and keep it open (macOS).
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_sample_sees_half_closed_and_dead_sockets() {
    use std::io::Write as _;
    use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
    use std::os::fd::AsRawFd;

    let (listener, half, peer, held, reset, udp) = {
        let _fd = crate::socket_creation_guard();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = TcpStream::connect(addr).unwrap();
        let (half, _) = listener.accept().unwrap();
        let reset = TcpStream::connect(addr).unwrap();
        let (held, _) = listener.accept().unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        (listener, half, peer, held, reset, udp)
    };
    let port = listener.local_addr().unwrap().port();
    let fd = |s: &dyn AsRawFd| u32::try_from(s.as_raw_fd()).unwrap();
    let (fd_listener, fd_half, fd_peer, fd_held) = (fd(&listener), fd(&half), fd(&peer), fd(&held));

    // FIN-WAIT-2 with unread data: `half` sends its FIN and stops, its peer neither reads nor
    // closes. That is the shape of the v0.2.1 leak.
    (&peer).write_all(&[7u8; 1000]).unwrap();
    half.shutdown(Shutdown::Write).unwrap();
    // The peer resets the other connection; `held` keeps its descriptor.
    socket2::SockRef::from(&reset)
        .set_linger(Some(Duration::ZERO))
        .unwrap();
    drop(reset);

    let polled = poll_until(
        "self",
        std::process::id(),
        &[port],
        Instant::now(),
        Duration::from_secs(10),
        |s| {
            s.tcp_fd(fd_listener)
                .is_some_and(|t| t.state == TcpState::Listen)
                && s.tcp_fd(fd_half)
                    .is_some_and(|t| t.state == TcpState::FinWait2)
                && s.tcp_fd(fd_peer)
                    .is_some_and(|t| t.state == TcpState::CloseWait)
                && s.dead.iter().any(|d| d.fd == fd_held)
                && s.udp >= 1
        },
    )
    .await;
    assert!(polled.met, "{polled:#?}");
    let s = polled.last.expect("a sample");
    let half_sock = s.tcp_fd(fd_half).expect("half");
    assert_eq!(half_sock.local_port(), Some(port));
    assert_eq!(half_sock.recv_q, Some(1000), "the unread request");
    assert!(s.in_state_on(TcpState::FinWait2, &[port]) >= 1);
    assert!(s.in_state_on(TcpState::CloseWait, &[port]) >= 1);
    // The host-wide view sees the same pair on the port. It is always there on Linux; macOS's
    // netstat can come back empty in a sandbox, and the view is then unavailable, not wrong.
    if cfg!(target_os = "linux") || s.system.on_ports.is_some() {
        assert!(s.system.on_ports_in(TcpState::FinWait2) >= 1, "{s:#?}");
        assert!(s.system.on_ports_in(TcpState::CloseWait) >= 1, "{s:#?}");
    }
    #[cfg(target_os = "linux")]
    assert!(s.system.sockstat.is_some());
    drop((listener, half, peer, held, udp));
}

/// A process that does not exist fails the sample instead of looking empty.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn a_missing_process_fails_the_poll() {
    // Far above any real pid (Linux caps them at 2^22, macOS at 99999).
    let polled = poll_until(
        "gone",
        u32::MAX - 1,
        &[],
        Instant::now(),
        Duration::from_secs(5),
        |_| true,
    )
    .await;
    assert!(!polled.met);
    assert!(polled.error.is_some(), "{polled:#?}");
    assert_eq!(polled.samples, 1);
}
