//! Deterministic simulations: two [`Kcp`] endpoints over `kcptun_testkit::netsim` links on a
//! virtual clock (plan step 03.5).
//!
//! The endpoints are driven the way kcp-go's `UDPSession` drives KCP (`sess.go`): `write`
//! splits into mss-sized `send` calls when `wait_snd() < snd_wnd` and flushes at once
//! (`writeDelay` off), the update timer calls `flush(IKCP_FLUSH_FULL)` and re-arms after the
//! returned interval, and every received packet goes through `input(…, IKCP_PACKET_REGULAR,
//! ack_no_delay)` before the application reads (`peek_size`, `recv`).
//!
//! Every run is a pure function of its seeds, so besides integrity and bounded virtual time
//! each scenario pins a one-line summary of its counters (packets, retransmissions, probes,
//! end time, final RTT/window state). A behaviour change in the port shows up as a changed
//! summary in review; the golden traces (`trace_tests`) say whether Go agrees.

use super::*;
use std::cell::RefCell;
use std::collections::HashSet;
use std::fmt::Write as _;
use std::rc::Rc;
use std::sync::{RwLockReadGuard, RwLockWriteGuard};

use kcptun_testkit::VirtualClock;
use kcptun_testkit::netsim::{Duplex, LinkConfig};
use kcptun_testkit::rng::Pcg;

type Sink = Rc<RefCell<Vec<Vec<u8>>>>;
type SimClock = Box<dyn Fn() -> u32 + Send + Sync>;
type BoxOutput = Box<dyn FnMut(&[u8])>;
type SimKcp = Kcp<BoxOutput, SimClock>;

/// These simulations only change the process-global SNMP counters; tests asserting exact
/// counter deltas elsewhere hold the write lock (see `SNMP_TEST_LOCK`).
fn snmp_read() -> RwLockReadGuard<'static, ()> {
    SNMP_TEST_LOCK.read().unwrap_or_else(|e| e.into_inner())
}

fn snmp_write() -> RwLockWriteGuard<'static, ()> {
    SNMP_TEST_LOCK.write().unwrap_or_else(|e| e.into_inner())
}

/// Configuration of one endpoint (the session setters kcptun calls).
#[derive(Clone, Copy, Debug)]
struct PeerCfg {
    nodelay: [isize; 4],
    snd_wnd: isize,
    rcv_wnd: isize,
    mtu: isize,
    stream: bool,
    ack_no_delay: bool,
}

impl PeerCfg {
    /// kcp-go session defaults: message mode, windows 32/32, mtu 1400, interval 100.
    fn session_default() -> Self {
        PeerCfg {
            nodelay: [0, 100, 0, 0],
            snd_wnd: 32,
            rcv_wnd: 32,
            mtu: 1400,
            stream: false,
            ack_no_delay: false,
        }
    }

    fn nodelay(mut self, nodelay: isize, interval: isize, resend: isize, nc: isize) -> Self {
        self.nodelay = [nodelay, interval, resend, nc];
        self
    }

    fn wnd(mut self, snd: isize, rcv: isize) -> Self {
        self.snd_wnd = snd;
        self.rcv_wnd = rcv;
        self
    }

    fn mtu(mut self, mtu: isize) -> Self {
        self.mtu = mtu;
        self
    }

    fn stream(mut self) -> Self {
        self.stream = true;
        self
    }
}

/// What one endpoint put on the wire, from parsing its output packets.
#[derive(Clone, Debug, Default)]
struct WireStats {
    packets: u64,
    bytes: u64,
    push: u64,
    /// PUSH segments whose sn was sent before.
    retrans: u64,
    /// PUSH segments with `frg > 0` (message fragments).
    frags: u64,
    ack: u64,
    wask: u64,
    wins: u64,
    sent_sn: HashSet<u32>,
}

impl WireStats {
    fn record(&mut self, pkt: &[u8]) {
        self.packets += 1;
        self.bytes += pkt.len() as u64;
        let mut rest = pkt;
        while let Some((h, tail)) = SegmentHeader::decode(rest) {
            match h.cmd {
                IKCP_CMD_PUSH => {
                    self.push += 1;
                    if !self.sent_sn.insert(h.sn) {
                        self.retrans += 1;
                    }
                    if h.frg > 0 {
                        self.frags += 1;
                    }
                }
                IKCP_CMD_ACK => self.ack += 1,
                IKCP_CMD_WASK => self.wask += 1,
                IKCP_CMD_WINS => self.wins += 1,
                other => panic!("output segment with cmd {other}"),
            }
            rest = &tail[h.len as usize..];
        }
        assert!(rest.is_empty(), "trailing bytes in an output packet");
    }
}

/// One endpoint: its KCP, the packets it has output but not yet put on the link, its timer.
struct Peer {
    kcp: SimKcp,
    out: Sink,
    ack_no_delay: bool,
    next_flush: u64,
    wire: WireStats,
    input_errors: u64,
    /// Recv calls that returned -2 (buffer smaller than the next message).
    recv_too_small: u64,
}

impl Peer {
    fn new(conv: u32, vc: &VirtualClock, cfg: PeerCfg) -> Self {
        let out: Sink = Rc::default();
        let output: BoxOutput = {
            let out = out.clone();
            Box::new(move |b: &[u8]| out.borrow_mut().push(b.to_vec()))
        };
        let clock: SimClock = {
            let vc = vc.clone();
            Box::new(move || vc.now_ms())
        };
        let mut kcp = Kcp::with_clock(conv, output, clock);
        assert_eq!(kcp.set_mtu(cfg.mtu), 0);
        let [nd, iv, rs, nc] = cfg.nodelay;
        kcp.nodelay(nd, iv, rs, nc);
        kcp.wnd_size(cfg.snd_wnd, cfg.rcv_wnd);
        kcp.stream = i32::from(cfg.stream);
        Peer {
            kcp,
            out,
            ack_no_delay: cfg.ack_no_delay,
            next_flush: 0,
            wire: WireStats::default(),
            input_errors: 0,
            recv_too_small: 0,
        }
    }

    /// `UDPSession.Write` precondition: the send window is not full.
    fn can_write(&self) -> bool {
        self.kcp.wait_snd() < self.kcp.snd_wnd as usize
    }

    /// `UDPSession.Write` (writeDelay off): mss-sized `send` calls, then a full flush.
    fn write(&mut self, mut data: &[u8]) {
        let mss = self.kcp.mss as usize;
        while !data.is_empty() {
            let n = data.len().min(mss);
            assert_eq!(self.kcp.send(&data[..n]), 0);
            data = &data[n..];
        }
        self.kcp.flush(IKCP_FLUSH_FULL);
    }

    /// Sends one whole message (fragmented into `frg` segments in message mode), then flushes.
    fn send_message(&mut self, msg: &[u8]) {
        assert_eq!(self.kcp.send(msg), 0);
        self.kcp.flush(IKCP_FLUSH_FULL);
    }

    /// `UDPSession.Read` into `buf`: the next message (or stream chunk), if any. When `buf`
    /// is too small, the -2 is counted and the message is read into a buffer of the peeked
    /// size instead (Go reads it into `recvbuf`).
    fn read(&mut self, buf: &mut Vec<u8>) -> Option<usize> {
        let size = self.kcp.peek_size();
        if size <= 0 {
            return None;
        }
        let size = size as usize;
        if size > buf.len() {
            assert_eq!(self.kcp.recv(buf), -2);
            self.recv_too_small += 1;
            buf.resize(size, 0);
        }
        let n = self.kcp.recv(buf);
        assert_eq!(
            n, size as isize,
            "recv returned a different size than peek_size"
        );
        Some(size)
    }
}

/// Two peers (`a` = index 0, `b` = index 1) over a [`Duplex`] link on a virtual clock.
struct Sim {
    vc: VirtualClock,
    peers: [Peer; 2],
    link: Duplex,
}

impl Sim {
    fn new(conv: u32, a: PeerCfg, b: PeerCfg, link: Duplex) -> Self {
        let vc = VirtualClock::new();
        let peers = [Peer::new(conv, &vc, a), Peer::new(conv, &vc, b)];
        Sim { vc, peers, link }
    }

    fn now(&self) -> u64 {
        self.vc.now_ms_u64()
    }

    /// Moves everything peer `i` has output onto its link.
    fn transmit(&mut self, i: usize) {
        let now = self.now();
        let pkts = std::mem::take(&mut *self.peers[i].out.borrow_mut());
        let link = if i == 0 {
            &mut self.link.a_to_b
        } else {
            &mut self.link.b_to_a
        };
        for p in pkts {
            self.peers[i].wire.record(&p);
            link.send(now, &p);
        }
    }

    /// Runs until `app` returns true, calling it after every batch of events (it plays the
    /// application: reads and writes). Panics if that takes more than `limit_ms` of virtual
    /// time. Returns the virtual time at the end.
    fn run(&mut self, limit_ms: u64, mut app: impl FnMut(&mut [Peer; 2], u64) -> bool) -> u64 {
        loop {
            let now = self.now();
            // Deliveries due now, each followed by the application (sess notifies the reader
            // and writer after every input).
            for dir in 0..2 {
                let pkts = if dir == 0 {
                    self.link.a_to_b.poll(now)
                } else {
                    self.link.b_to_a.poll(now)
                };
                let to = 1 - dir;
                for p in pkts {
                    let peer = &mut self.peers[to];
                    let ack_no_delay = peer.ack_no_delay;
                    if peer.kcp.input(&p, IKCP_PACKET_REGULAR, ack_no_delay) != 0 {
                        peer.input_errors += 1;
                    }
                    self.transmit(to);
                }
            }
            // Update timers.
            for i in 0..2 {
                if self.peers[i].next_flush <= now {
                    let interval = self.peers[i].kcp.flush(IKCP_FLUSH_FULL);
                    self.peers[i].next_flush = now + u64::from(interval);
                    self.transmit(i);
                }
            }
            let done = app(&mut self.peers, now);
            self.transmit(0);
            self.transmit(1);
            if done {
                return now;
            }
            let mut next = self.peers[0].next_flush.min(self.peers[1].next_flush);
            if let Some(t) = self.link.next_event_time() {
                next = next.min(t);
            }
            assert!(
                next <= limit_ms,
                "not finished after {limit_ms} ms of virtual time"
            );
            self.vc.set(next.max(now));
        }
    }

    /// One-line summary of the run, pinned by each scenario.
    fn summary(&self, end: u64) -> String {
        let mut s = format!("end={end}ms");
        for (name, p) in ["a", "b"].iter().zip(&self.peers) {
            let w = &p.wire;
            let k = &p.kcp;
            write!(
                s,
                " {name}[pkts={} push={} re={} frg={} ack={} wask={} wins={} inerr={} r2={} srtt={} rto={} cwnd={} state={:x}]",
                w.packets,
                w.push,
                w.retrans,
                w.frags,
                w.ack,
                w.wask,
                w.wins,
                p.input_errors,
                p.recv_too_small,
                k.rx_srtt,
                k.rx_rto,
                k.cwnd,
                k.state
            )
            .expect("write to String");
        }
        let (ab, ba) = (self.link.a_to_b.stats(), self.link.b_to_a.stats());
        write!(
            s,
            " link[ab lost={} qd={} dup={} ro={} ba lost={} qd={} dup={} ro={}]",
            ab.lost,
            ab.queue_dropped,
            ab.duplicated,
            ab.reordered,
            ba.lost,
            ba.queue_dropped,
            ba.duplicated,
            ba.reordered
        )
        .expect("write to String");
        s
    }
}

/// A byte stream drawn from a PCG: the writer and the checking reader hold identical copies
/// and may take it in differently sized pieces.
struct Stream {
    rng: Pcg,
    left: usize,
    word: u64,
    avail: u32,
}

impl Stream {
    fn new(seed: u64, len: usize) -> Self {
        Stream {
            rng: Pcg::new(seed, 0x5354_5245_414d),
            left: len,
            word: 0,
            avail: 0,
        }
    }

    /// The next `min(n, left)` bytes.
    fn next(&mut self, n: usize) -> Vec<u8> {
        let n = n.min(self.left);
        self.left -= n;
        (0..n)
            .map(|_| {
                if self.avail == 0 {
                    self.word = self.rng.next_u64();
                    self.avail = 8;
                }
                let b = self.word as u8;
                self.word >>= 8;
                self.avail -= 1;
                b
            })
            .collect()
    }
}

// ---- Go TestLossyConn1-4 at the ARQ level ----

/// Go `testlink` without sessions: `a` writes a 64-byte message and waits for its echo, 16
/// times; `b` echoes everything it reads. lossyconn(loss, 100) has a 100 ms one-way delay.
/// The caller holds an SNMP lock.
// Go: kcp-go/v5@v5.6.66 kcp_test.go:testlink()
fn lossy_echo(seed: u64, loss: f64, nodelay: [isize; 4]) -> (Sim, u64) {
    const REPEAT: usize = 16; // Go: kcp_test.go:repeat
    let [nd, iv, rs, nc] = nodelay;
    let cfg = PeerCfg::session_default().nodelay(nd, iv, rs, nc);
    let link = Duplex::symmetric(LinkConfig::new(seed).delay(100).loss(loss));
    let mut sim = Sim::new(0x1EC0, cfg, cfg, link);

    let mut want = Stream::new(seed, REPEAT * 64);
    let mut src = Stream::new(seed, REPEAT * 64);
    let mut sent = 0;
    let mut echoed = 0;
    let mut buf_a = vec![0u8; 64];
    let mut buf_b = vec![0u8; 65536];
    let end = sim.run(600_000, |peers, _now| {
        // Server: echo whatever arrives.
        while let Some(n) = peers[1].read(&mut buf_b) {
            let msg = buf_b[..n].to_vec();
            peers[1].write(&msg);
        }
        // Client: io.ReadFull(s, buf[:64]) then the next Write.
        while let Some(n) = peers[0].read(&mut buf_a) {
            assert_eq!(buf_a[..n], want.next(n)[..], "echo corrupted");
            echoed += n;
        }
        if sent < REPEAT && echoed == sent * 64 && peers[0].can_write() {
            peers[0].write(&src.next(64));
            sent += 1;
        }
        echoed == REPEAT * 64
    });
    (sim, end)
}

// Go: kcp-go/v5@v5.6.66 kcp_test.go:TestLossyConn1
#[test]
fn test_lossy_conn1() {
    let _g = snmp_read();
    let (sim, end) = lossy_echo(1, 0.1, [1, 10, 2, 1]);
    assert_eq!(
        sim.summary(end),
        "end=6148ms a[pkts=38 push=22 re=6 frg=0 ack=16 wask=0 wins=0 inerr=0 r2=0 srtt=200 rto=210 cwnd=0 state=0] b[pkts=27 push=18 re=2 frg=0 ack=17 wask=0 wins=0 inerr=0 r2=0 srtt=200 rto=210 cwnd=0 state=0] link[ab lost=6 qd=0 dup=0 ro=0 ba lost=3 qd=0 dup=0 ro=0]"
    );
}

// Go: kcp-go/v5@v5.6.66 kcp_test.go:TestLossyConn2
#[test]
fn test_lossy_conn2() {
    let _g = snmp_read();
    let (sim, end) = lossy_echo(2, 0.2, [1, 10, 2, 1]);
    assert_eq!(
        sim.summary(end),
        "end=5822ms a[pkts=29 push=19 re=3 frg=0 ack=16 wask=0 wins=0 inerr=0 r2=0 srtt=200 rto=210 cwnd=0 state=0] b[pkts=43 push=25 re=9 frg=0 ack=18 wask=0 wins=0 inerr=0 r2=0 srtt=200 rto=210 cwnd=0 state=0] link[ab lost=3 qd=0 dup=0 ro=0 ba lost=13 qd=0 dup=0 ro=0]"
    );
}

// Go: kcp-go/v5@v5.6.66 kcp_test.go:TestLossyConn3
#[test]
fn test_lossy_conn3() {
    let _g = snmp_read();
    let (sim, end) = lossy_echo(3, 0.3, [1, 10, 2, 1]);
    assert_eq!(
        sim.summary(end),
        "end=5378ms a[pkts=40 push=23 re=7 frg=0 ack=17 wask=0 wins=0 inerr=0 r2=0 srtt=200 rto=212 cwnd=0 state=0] b[pkts=30 push=20 re=4 frg=0 ack=18 wask=0 wins=0 inerr=0 r2=0 srtt=200 rto=212 cwnd=0 state=0] link[ab lost=9 qd=0 dup=0 ro=0 ba lost=9 qd=0 dup=0 ro=0]"
    );
}

// Go: kcp-go/v5@v5.6.66 kcp_test.go:TestLossyConn4
#[test]
fn test_lossy_conn4() {
    let _g = snmp_read();
    let (sim, end) = lossy_echo(4, 0.1, [1, 10, 2, 0]);
    assert_eq!(
        sim.summary(end),
        "end=4012ms a[pkts=32 push=17 re=1 frg=0 ack=16 wask=0 wins=0 inerr=0 r2=0 srtt=200 rto=210 cwnd=6 state=0] b[pkts=33 push=17 re=1 frg=0 ack=16 wask=0 wins=0 inerr=0 r2=0 srtt=200 rto=210 cwnd=2 state=0] link[ab lost=3 qd=0 dup=0 ro=0 ba lost=3 qd=0 dup=0 ro=0]"
    );
}

/// The plan's `{0,40,0,0}` variant: no fast resend, congestion control on, 40 ms interval.
#[test]
fn sim_lossy_conn_nodelay_0_40_0_0() {
    let _g = snmp_read();
    let (sim, end) = lossy_echo(5, 0.1, [0, 40, 0, 0]);
    assert_eq!(
        sim.summary(end),
        "end=4732ms a[pkts=24 push=17 re=1 frg=0 ack=16 wask=0 wins=0 inerr=0 r2=0 srtt=200 rto=240 cwnd=6 state=0] b[pkts=35 push=20 re=4 frg=0 ack=16 wask=0 wins=0 inerr=0 r2=0 srtt=200 rto=240 cwnd=4 state=0] link[ab lost=3 qd=0 dup=0 ro=0 ba lost=6 qd=0 dup=0 ro=0]"
    );
}

// ---- Bulk stream transfers ----

/// kcptun's defaults: mode fast `{0,30,2,1}`, client sndwnd 128, server rcvwnd 512, mtu 1350,
/// stream mode. `a` sends `len` bytes to `b` in 32 KiB writes over a 20±5 ms link with the
/// given loss, 2% reordering (+15 ms) and 1% duplication.
fn bulk(seed: u64, len: usize, loss: f64) -> (Sim, u64) {
    let a = PeerCfg::session_default()
        .nodelay(0, 30, 2, 1)
        .wnd(128, 512)
        .mtu(1350)
        .stream();
    let b = a.wnd(512, 512);
    let cfg = LinkConfig::new(seed)
        .delay(20)
        .jitter(5)
        .loss(loss)
        .reorder(0.02, 15)
        .duplicate(0.01);
    let mut sim = Sim::new(0xB01C, a, b, Duplex::symmetric(cfg));

    let mut src = Stream::new(seed, len);
    let mut want = Stream::new(seed, len);
    let mut received = 0;
    let mut buf = vec![0u8; 65536];
    let _g = snmp_read();
    let end = sim.run(600_000, |peers, _now| {
        while src.left > 0 && peers[0].can_write() {
            let chunk = src.next(32 * 1024);
            peers[0].write(&chunk);
        }
        while let Some(n) = peers[1].read(&mut buf) {
            assert_eq!(buf[..n], want.next(n)[..], "stream corrupted at {received}");
            received += n;
        }
        received == len && peers[0].kcp.wait_snd() == 0
    });
    assert_eq!(peers_state(&sim), [0, 0]);
    (sim, end)
}

fn peers_state(sim: &Sim) -> [u32; 2] {
    [sim.peers[0].kcp.state, sim.peers[1].kcp.state]
}

const MB10: usize = 10 * 1024 * 1024;

#[test]
fn sim_bulk_10mb_loss_0() {
    let (sim, end) = bulk(10, MB10, 0.0);
    assert_eq!(
        sim.summary(end),
        "end=3856ms a[pkts=10844 push=10844 re=2845 frg=0 ack=0 wask=0 wins=0 inerr=0 r2=0 srtt=45 rto=100 cwnd=0 state=0] b[pkts=264 push=0 re=0 frg=0 ack=4804 wask=0 wins=0 inerr=0 r2=0 srtt=0 rto=200 cwnd=0 state=0] link[ab lost=0 qd=0 dup=105 ro=224 ba lost=0 qd=0 dup=2 ro=5]"
    );
}

#[test]
fn sim_bulk_10mb_loss_1() {
    let (sim, end) = bulk(11, MB10, 0.01);
    assert_eq!(
        sim.summary(end),
        "end=4643ms a[pkts=10575 push=10575 re=2576 frg=0 ack=0 wask=0 wins=0 inerr=0 r2=0 srtt=52 rto=100 cwnd=0 state=0] b[pkts=268 push=0 re=0 frg=0 ack=6000 wask=0 wins=0 inerr=0 r2=0 srtt=0 rto=200 cwnd=0 state=0] link[ab lost=107 qd=0 dup=100 ro=234 ba lost=2 qd=0 dup=6 ro=4]"
    );
}

#[test]
fn sim_bulk_10mb_loss_5() {
    let (sim, end) = bulk(15, MB10, 0.05);
    assert_eq!(
        sim.summary(end),
        "end=7936ms a[pkts=11174 push=11174 re=3175 frg=0 ack=0 wask=0 wins=0 inerr=0 r2=0 srtt=49 rto=100 cwnd=0 state=0] b[pkts=339 push=0 re=0 frg=0 ack=8655 wask=0 wins=0 inerr=0 r2=0 srtt=0 rto=200 cwnd=0 state=0] link[ab lost=627 qd=0 dup=85 ro=199 ba lost=14 qd=0 dup=2 ro=5]"
    );
}

#[test]
fn sim_bulk_10mb_loss_20() {
    let (sim, end) = bulk(20, MB10, 0.20);
    assert_eq!(
        sim.summary(end),
        "end=15877ms a[pkts=13454 push=13454 re=5455 frg=0 ack=0 wask=0 wins=0 inerr=0 r2=0 srtt=54 rto=100 cwnd=0 state=0] b[pkts=467 push=0 re=0 frg=0 ack=9793 wask=0 wins=0 inerr=0 r2=0 srtt=0 rto=200 cwnd=0 state=0] link[ab lost=2705 qd=0 dup=113 ro=192 ba lost=105 qd=0 dup=4 ro=9]"
    );
}

/// A 1 MB/s bottleneck with a 16-packet drop-tail queue and 1% loss. kcptun's fast mode
/// (`{0,30,2,1}`, no congestion window) floods it with a 256-segment window, so the queue
/// drops packets; the transfer still completes intact. With congestion control on
/// (`{0,40,2,0}`) the sender stays below the bottleneck rate and the queue never overflows.
#[test]
fn sim_bulk_bottleneck_queue() {
    let run = |nodelay: [isize; 4]| {
        let [nd, iv, rs, nc] = nodelay;
        let cfg = PeerCfg::session_default()
            .nodelay(nd, iv, rs, nc)
            .wnd(256, 256)
            .stream();
        let link = LinkConfig::new(30)
            .delay(30)
            .loss(0.01)
            .bandwidth(1_000_000)
            .queue_limit(16);
        let mut sim = Sim::new(0xCC, cfg, cfg, Duplex::symmetric(link));
        let len = 2 * 1024 * 1024;
        let mut src = Stream::new(30, len);
        let mut want = Stream::new(30, len);
        let mut received = 0;
        let mut buf = vec![0u8; 65536];
        let _g = snmp_read();
        let end = sim.run(600_000, |peers, _now| {
            while src.left > 0 && peers[0].can_write() {
                peers[0].write(&src.next(16 * 1024));
            }
            while let Some(n) = peers[1].read(&mut buf) {
                assert_eq!(buf[..n], want.next(n)[..]);
                received += n;
            }
            received == len && peers[0].kcp.wait_snd() == 0
        });
        let dropped = sim.link.a_to_b.stats().queue_dropped;
        (sim.summary(end), dropped)
    };
    let (fast, fast_dropped) = run([0, 30, 2, 1]);
    assert!(fast_dropped > 0, "the bottleneck never dropped: {fast}");
    assert_eq!(
        fast,
        "end=6991ms a[pkts=6622 push=6622 re=5087 frg=0 ack=0 wask=0 wins=0 inerr=0 r2=0 srtt=90 rto=120 cwnd=0 state=0] b[pkts=110 push=0 re=0 frg=0 ack=864 wask=0 wins=0 inerr=0 r2=0 srtt=0 rto=200 cwnd=0 state=0] link[ab lost=71 qd=5016 dup=0 ro=0 ba lost=0 qd=0 dup=0 ro=0]"
    );
    let (cc, cc_dropped) = run([0, 40, 2, 0]);
    assert_eq!(cc_dropped, 0, "{cc}");
    assert_eq!(
        cc,
        "end=15551ms a[pkts=1534 push=1534 re=9 frg=0 ack=0 wask=0 wins=0 inerr=0 r2=0 srtt=80 rto=120 cwnd=10 state=0] b[pkts=197 push=0 re=0 frg=0 ack=232 wask=0 wins=0 inerr=0 r2=0 srtt=0 rto=200 cwnd=1 state=0] link[ab lost=8 qd=0 dup=0 ro=0 ba lost=0 qd=0 dup=0 ro=0]"
    );
}

// ---- Window probing, dead link, message mode ----

/// `b` stops reading for 3 s with an 8-segment receive window: `a` sees `rmt_wnd == 0`, stops
/// sending data and probes (WASK every `probe_wait`, growing ×1.5 from 500 ms); `b` answers
/// with WINS, and its fast recover tells the window again when reading resumes.
#[test]
fn sim_zero_window_probe() {
    let a = PeerCfg::session_default().nodelay(1, 10, 2, 1).stream();
    let b = a.wnd(32, 8);
    let mut sim = Sim::new(
        0x2E80,
        a,
        b,
        Duplex::symmetric(LinkConfig::new(40).delay(10)),
    );
    let len = 256 * 1024;
    let mut src = Stream::new(40, len);
    let mut want = Stream::new(40, len);
    let mut received = 0;
    let mut buf = vec![0u8; 65536];
    let mut min_rmt_wnd = u32::MAX;
    let mut max_probe_wait = 0;
    let _g = snmp_read();
    let end = sim.run(600_000, |peers, now| {
        min_rmt_wnd = min_rmt_wnd.min(peers[0].kcp.rmt_wnd);
        max_probe_wait = max_probe_wait.max(peers[0].kcp.probe_wait);
        while src.left > 0 && peers[0].can_write() {
            peers[0].write(&src.next(8 * 1024));
        }
        let stalled = (100..3100).contains(&now);
        while !stalled && let Some(n) = peers[1].read(&mut buf) {
            assert_eq!(buf[..n], want.next(n)[..]);
            received += n;
        }
        received == len && peers[0].kcp.wait_snd() == 0
    });
    assert_eq!(min_rmt_wnd, 0, "the receive window never closed");
    // 500 -> 750 -> 1125 -> 1687: three probes fit into the 3 s stall.
    assert_eq!(max_probe_wait, 1687);
    assert!(sim.peers[0].wire.wask >= 3, "{}", sim.summary(end));
    assert!(sim.peers[1].wire.wins >= 3, "{}", sim.summary(end));
    assert_eq!(
        sim.summary(end),
        "end=3710ms a[pkts=210 push=207 re=16 frg=0 ack=0 wask=3 wins=0 inerr=0 r2=0 srtt=20 rto=30 cwnd=0 state=0] b[pkts=46 push=0 re=0 frg=0 ack=36 wask=0 wins=24 inerr=0 r2=0 srtt=0 rto=200 cwnd=0 state=0] link[ab lost=0 qd=0 dup=0 ro=0 ba lost=0 qd=0 dup=0 ro=0]"
    );
}

/// Everything `a` sends is lost: its first segment is retransmitted until `xmit` reaches
/// `dead_link` (20) and `state` becomes 0xFFFFFFFF. With nodelay 0 each RTO adds `rx_rto`
/// (200 ms, no RTT sample), so the 20th transmission happens at 19·20/2·200 ms = 38 s.
#[test]
fn sim_dead_link() {
    let cfg = PeerCfg::session_default().nodelay(0, 40, 2, 1).stream();
    let link = Duplex::new(
        LinkConfig::new(50).delay(20).loss(1.0),
        LinkConfig::new(51).delay(20),
    );
    let mut sim = Sim::new(0xDEAD, cfg, cfg, link);
    let _g = snmp_read();
    let mut wrote = false;
    let end = sim.run(600_000, |peers, _now| {
        if !wrote {
            peers[0].write(&[0x55; 3000]);
            wrote = true;
        }
        peers[0].kcp.state == 0xFFFF_FFFF
    });
    let first = sim.peers[0]
        .kcp
        .snd_buf
        .peek()
        .expect("unacknowledged segment");
    assert_eq!(first.xmit, IKCP_DEADLINK);
    assert_eq!(end, 38_000);
    assert_eq!(sim.peers[1].wire.packets, 0, "b never heard anything");
    assert_eq!(
        sim.summary(end),
        "end=38000ms a[pkts=60 push=60 re=57 frg=0 ack=0 wask=0 wins=0 inerr=0 r2=0 srtt=0 rto=200 cwnd=0 state=ffffffff] b[pkts=0 push=0 re=0 frg=0 ack=0 wask=0 wins=0 inerr=0 r2=0 srtt=0 rto=200 cwnd=0 state=0] link[ab lost=60 qd=0 dup=0 ro=0 ba lost=0 qd=0 dup=0 ro=0]"
    );
}

/// Message mode: messages of 1..=20·mss bytes are fragmented (`frg` counts down), delivered
/// whole and in order, and a reader buffer smaller than the next message gets -2 first.
#[test]
fn sim_message_mode_frg_and_recv_small_buffer() {
    let cfg = PeerCfg::session_default().wnd(128, 128);
    let link = LinkConfig::new(60)
        .delay(25)
        .jitter(10)
        .loss(0.05)
        .reorder(0.05, 30)
        .duplicate(0.02);
    let mut sim = Sim::new(0x3E55, cfg, cfg, Duplex::symmetric(link));
    const COUNT: usize = 200;
    let mss = 1376;
    let mut sizes = Pcg::new(60, 1);
    let mut src = Stream::new(61, usize::MAX);
    let mut want = Stream::new(61, usize::MAX);
    let mut want_sizes = Pcg::new(60, 1);
    let mut sent = 0;
    let mut got = 0;
    let mut buf = vec![0u8; 1000];
    let _g = snmp_read();
    let end = sim.run(600_000, |peers, _now| {
        while sent < COUNT && peers[0].can_write() {
            let n = 1 + sizes.below(20 * mss) as usize;
            peers[0].send_message(&src.next(n));
            sent += 1;
        }
        while let Some(n) = peers[1].read(&mut buf) {
            let expect = 1 + want_sizes.below(20 * mss) as usize;
            assert_eq!(n, expect, "message {got} has the wrong size");
            assert_eq!(buf[..n], want.next(n)[..], "message {got} corrupted");
            buf.truncate(1000);
            got += 1;
        }
        got == COUNT
    });
    assert!(sim.peers[0].wire.frags > 0);
    assert!(sim.peers[1].recv_too_small > 0);
    assert_eq!(
        sim.summary(end),
        "end=77055ms a[pkts=2353 push=2364 re=179 frg=2141 ack=0 wask=0 wins=0 inerr=0 r2=0 srtt=98 rto=198 cwnd=4 state=0] b[pkts=730 push=0 re=0 frg=0 ack=893 wask=0 wins=0 inerr=0 r2=190 srtt=0 rto=200 cwnd=1 state=0] link[ab lost=106 qd=0 dup=43 ro=122 ba lost=25 qd=0 dup=15 ro=39]"
    );
}

/// Message mode edge cases on a live pair: an empty send is -1, more than 255 fragments is
/// -2, exactly 255 fragments is accepted and delivered whole.
#[test]
fn sim_message_mode_fragment_limits() {
    let cfg = PeerCfg::session_default().wnd(512, 512);
    let mut sim = Sim::new(9, cfg, cfg, Duplex::symmetric(LinkConfig::new(70).delay(5)));
    let mss = sim.peers[0].kcp.mss as usize;
    assert_eq!(sim.peers[0].kcp.send(&[]), -1);
    assert_eq!(sim.peers[0].kcp.send(&vec![1; 255 * mss + 1]), -2);
    assert_eq!(sim.peers[0].kcp.wait_snd(), 0);
    let big: Vec<u8> = (0..255 * mss).map(|i| (i % 251) as u8).collect();
    assert_eq!(sim.peers[0].kcp.send(&big), 0);
    assert_eq!(sim.peers[0].kcp.wait_snd(), 255);
    let mut buf = vec![0u8; 1];
    let mut got = None;
    let _g = snmp_read();
    let end = sim.run(60_000, |peers, _now| {
        if let Some(n) = peers[1].read(&mut buf) {
            got = Some(n);
        }
        got.is_some()
    });
    assert_eq!(got, Some(big.len()));
    assert_eq!(buf, big);
    assert_eq!(sim.peers[1].recv_too_small, 1);
    // Slow start (congestion control is on by default) over a 10 ms RTT at the default
    // 100 ms interval.
    assert_eq!(end, 3810);
}

/// The simulations are deterministic: the same seed gives the same run, a different seed a
/// different one. The SNMP increments of a run are exact too (write lock held).
#[test]
fn sim_is_deterministic() {
    let _g = snmp_write();
    let before = DEFAULT_SNMP.copy();
    let (s1, e1) = lossy_echo(7, 0.1, [1, 10, 2, 1]);
    let mid = DEFAULT_SNMP.copy();
    let (s2, e2) = lossy_echo(7, 0.1, [1, 10, 2, 1]);
    let after = DEFAULT_SNMP.copy();
    assert_eq!(s1.summary(e1), s2.summary(e2));
    assert_eq!(
        mid.out_segs - before.out_segs,
        after.out_segs - mid.out_segs
    );
    assert_eq!(mid.in_segs - before.in_segs, after.in_segs - mid.in_segs);
    assert_eq!(
        mid.retrans_segs - before.retrans_segs,
        after.retrans_segs - mid.retrans_segs
    );
    // Every segment the two peers output was counted in OutSegs.
    let wire = |s: &Sim| {
        s.peers
            .iter()
            .map(|p| p.wire.push + p.wire.ack + p.wire.wask + p.wire.wins)
            .sum::<u64>()
    };
    assert_eq!(mid.out_segs - before.out_segs, wire(&s1));
    let (s3, e3) = lossy_echo(8, 0.1, [1, 10, 2, 1]);
    assert_ne!(s1.summary(e1), s3.summary(e3));
}
