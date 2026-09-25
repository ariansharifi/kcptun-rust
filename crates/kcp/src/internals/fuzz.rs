//! The `kcp_input` fuzz harness (plan step 03.6): a byte string drives a sequence of API calls
//! on a live [`Kcp`] (the target, `A`) and an honest peer (`B`), and nothing may panic.
//!
//! The cargo-fuzz target (`crates/kcp/fuzz/fuzz_targets/kcp_input.rs`) only calls
//! [`kcp_input`]; the harness lives here so this crate's tests can run it over the seed corpus
//! and the regression inputs, and so it can reach `flush()` and check internal invariants.
//!
//! # Input format
//!
//! `conv: u32 LE`, then ops until the input is exhausted. Every op is a tag byte (taken modulo
//! [`NUM_OPS`], so every byte value is an op) followed by its fixed-size little-endian
//! arguments; an `Input` op carries a `u16` length and then that many raw packet bytes (fewer if
//! the input ends first). A truncated op at the end is dropped. The format is decoded front to
//! back by hand, instead of with `arbitrary`, so that the seed corpus can be encoded exactly
//! ([`encode`]): the seeds replay kcp-go's recorded traffic (the golden traces of 03.5) and
//! hand-made segments of every kind.
//!
//! Besides raw packets (`Input`), the target receives crafted segments whose `sn`/`una` are
//! relative to its own state (`Segment`, which lets the fuzzer hit live sequence numbers) and the
//! real, possibly mutated or duplicated, packets of the honest peer (`Deliver`). The clock is
//! virtual and only moves with `Advance`.
//!
//! After every op the harness checks invariants that hold in kcp-go too: the send buffer holds
//! exactly the segments `snd_una..snd_nxt`, and the receive heap's duplicate marks match its
//! segments.
#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::kcp::{
    _itimediff, IKCP_CMD_ACK, IKCP_CMD_PUSH, IKCP_FLUSH_ACKONLY, IKCP_FLUSH_FULL, IKCP_PACKET_FEC,
    IKCP_PACKET_REGULAR, Kcp, PacketType, ikcp_encode8u, ikcp_encode16u, ikcp_encode32u,
};

/// Number of op kinds; a tag byte selects `tag % NUM_OPS`.
pub const NUM_OPS: u8 = 16;

/// Upper bound on the bytes passed to `send` in one run (both endpoints), so that one input
/// cannot queue unbounded data.
pub const MAX_SEND_BYTES: usize = 1 << 20;

/// Upper bound on the packets queued per direction; the oldest is dropped beyond it.
pub const MAX_QUEUED_PACKETS: usize = 256;

/// One harness step. Signed arguments are two's complement on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FuzzOp {
    /// `A.input(data, FEC if fec else REGULAR, ack_no_delay)`.
    Input {
        fec: bool,
        ack_no_delay: bool,
        data: Vec<u8>,
    },
    /// `A.send(len pattern bytes)`.
    Send { len: u16 },
    /// `A.flush(FULL if full else ACKONLY)`.
    Flush { full: bool },
    /// `A.recv(buffer of len bytes)`.
    Recv { len: u16 },
    /// Moves the shared virtual clock forward by `ms` (wrapping).
    Advance { ms: u32 },
    /// `A.update()`.
    Update,
    /// `A.check()`.
    Check,
    /// `A.peek_size()` and `A.wait_snd()`.
    Query,
    /// `A.set_mtu(mtu)`.
    SetMtu { mtu: u16 },
    /// `A.nodelay(nodelay, interval, resend, nc)`.
    NoDelay {
        nodelay: i8,
        interval: i16,
        resend: i8,
        nc: i8,
    },
    /// `A.wnd_size(snd, rcv)`.
    WndSize { snd: i32, rcv: i32 },
    /// `A.stream = stream` (Go: `UDPSession.SetStreamMode`).
    SetStream { stream: bool },
    /// `B.send(len pattern bytes)`.
    PeerSend { len: u16 },
    /// `B` reads everything it can, then `B.flush(FULL)`.
    PeerFlush,
    /// Takes packet `index % n` from the queue towards A (or towards B if `to_peer`), applies
    /// `mutation % 4` (0: none; 1: truncate to `pos % (len + 1)` bytes; 2: set byte `pos % len`
    /// to `val`; 3: deliver a copy and keep the packet queued) and inputs it there.
    Deliver {
        to_peer: bool,
        index: u8,
        mutation: u8,
        pos: u16,
        val: u8,
        fec: bool,
        ack_no_delay: bool,
    },
    /// Inputs one crafted segment with A's `conv` into A. `cmd < 0xF0` selects
    /// `IKCP_CMD_PUSH + cmd % 4`, larger values are used verbatim (invalid commands).
    /// `sn = base + sn_rel` with base `A.snd_una` for an ACK and `A.rcv_nxt` otherwise;
    /// `una = A.snd_una + una_rel`; `ts = now + ts_rel`; `len` payload bytes.
    Segment {
        cmd: u8,
        frg: u8,
        wnd: u16,
        ts_rel: i16,
        sn_rel: i16,
        una_rel: i16,
        len: u8,
        fec: bool,
        ack_no_delay: bool,
    },
}

// Op tags, in the order of `FuzzOp`.
const T_INPUT: u8 = 0;
const T_SEND: u8 = 1;
const T_FLUSH: u8 = 2;
const T_RECV: u8 = 3;
const T_ADVANCE: u8 = 4;
const T_UPDATE: u8 = 5;
const T_CHECK: u8 = 6;
const T_QUERY: u8 = 7;
const T_SETMTU: u8 = 8;
const T_NODELAY: u8 = 9;
const T_WNDSIZE: u8 = 10;
const T_STREAM: u8 = 11;
const T_PEERSEND: u8 = 12;
const T_PEERFLUSH: u8 = 13;
const T_DELIVER: u8 = 14;
const T_SEGMENT: u8 = 15;

/// Packs two booleans into the flag byte used by `Input`, `Deliver` and `Segment`.
fn flags(fec: bool, ack_no_delay: bool) -> u8 {
    u8::from(fec) | (u8::from(ack_no_delay) << 1)
}

fn unflags(b: u8) -> (bool, bool) {
    (b & 1 != 0, b & 2 != 0)
}

/// Front-to-back reader over the fuzz input.
struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.data.split_first_chunk::<N>()?;
        self.data = rest;
        Some(*head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.array::<1>().map(|[b]| b)
    }

    fn u16(&mut self) -> Option<u16> {
        self.array().map(u16::from_le_bytes)
    }

    fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_le_bytes)
    }

    /// Up to `n` bytes (fewer if the input ends).
    fn bytes(&mut self, n: usize) -> &'a [u8] {
        let (head, rest) = self.data.split_at(n.min(self.data.len()));
        self.data = rest;
        head
    }
}

impl FuzzOp {
    /// Decodes the next op, or `None` when the input is exhausted mid-op.
    fn decode(r: &mut Reader<'_>) -> Option<FuzzOp> {
        let op = match r.u8()? % NUM_OPS {
            T_INPUT => {
                let (fec, ack_no_delay) = unflags(r.u8()?);
                let len = r.u16()?;
                FuzzOp::Input {
                    fec,
                    ack_no_delay,
                    data: r.bytes(len as usize).to_vec(),
                }
            }
            T_SEND => FuzzOp::Send { len: r.u16()? },
            T_FLUSH => FuzzOp::Flush {
                full: r.u8()? & 1 != 0,
            },
            T_RECV => FuzzOp::Recv { len: r.u16()? },
            T_ADVANCE => FuzzOp::Advance { ms: r.u32()? },
            T_UPDATE => FuzzOp::Update,
            T_CHECK => FuzzOp::Check,
            T_QUERY => FuzzOp::Query,
            T_SETMTU => FuzzOp::SetMtu { mtu: r.u16()? },
            T_NODELAY => FuzzOp::NoDelay {
                nodelay: r.u8()? as i8,
                interval: r.u16()? as i16,
                resend: r.u8()? as i8,
                nc: r.u8()? as i8,
            },
            T_WNDSIZE => FuzzOp::WndSize {
                snd: r.u32()? as i32,
                rcv: r.u32()? as i32,
            },
            T_STREAM => FuzzOp::SetStream {
                stream: r.u8()? & 1 != 0,
            },
            T_PEERSEND => FuzzOp::PeerSend { len: r.u16()? },
            T_PEERFLUSH => FuzzOp::PeerFlush,
            T_DELIVER => {
                let to_peer = r.u8()? & 1 != 0;
                let index = r.u8()?;
                let mutation = r.u8()?;
                let pos = r.u16()?;
                let val = r.u8()?;
                let (fec, ack_no_delay) = unflags(r.u8()?);
                FuzzOp::Deliver {
                    to_peer,
                    index,
                    mutation,
                    pos,
                    val,
                    fec,
                    ack_no_delay,
                }
            }
            _ => {
                // T_SEGMENT (tag % NUM_OPS covers exactly the 16 tags).
                let cmd = r.u8()?;
                let frg = r.u8()?;
                let wnd = r.u16()?;
                let ts_rel = r.u16()? as i16;
                let sn_rel = r.u16()? as i16;
                let una_rel = r.u16()? as i16;
                let len = r.u8()?;
                let (fec, ack_no_delay) = unflags(r.u8()?);
                FuzzOp::Segment {
                    cmd,
                    frg,
                    wnd,
                    ts_rel,
                    sn_rel,
                    una_rel,
                    len,
                    fec,
                    ack_no_delay,
                }
            }
        };
        Some(op)
    }

    /// Appends the encoding of this op (the inverse of `decode`). An `Input` longer than
    /// 65535 bytes is cut to 65535.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            FuzzOp::Input {
                fec,
                ack_no_delay,
                data,
            } => {
                let data = &data[..data.len().min(u16::MAX as usize)];
                out.extend([T_INPUT, flags(*fec, *ack_no_delay)]);
                out.extend((data.len() as u16).to_le_bytes());
                out.extend_from_slice(data);
            }
            FuzzOp::Send { len } => {
                out.push(T_SEND);
                out.extend(len.to_le_bytes());
            }
            FuzzOp::Flush { full } => out.extend([T_FLUSH, u8::from(*full)]),
            FuzzOp::Recv { len } => {
                out.push(T_RECV);
                out.extend(len.to_le_bytes());
            }
            FuzzOp::Advance { ms } => {
                out.push(T_ADVANCE);
                out.extend(ms.to_le_bytes());
            }
            FuzzOp::Update => out.push(T_UPDATE),
            FuzzOp::Check => out.push(T_CHECK),
            FuzzOp::Query => out.push(T_QUERY),
            FuzzOp::SetMtu { mtu } => {
                out.push(T_SETMTU);
                out.extend(mtu.to_le_bytes());
            }
            FuzzOp::NoDelay {
                nodelay,
                interval,
                resend,
                nc,
            } => {
                out.extend([T_NODELAY, *nodelay as u8]);
                out.extend(interval.to_le_bytes());
                out.extend([*resend as u8, *nc as u8]);
            }
            FuzzOp::WndSize { snd, rcv } => {
                out.push(T_WNDSIZE);
                out.extend(snd.to_le_bytes());
                out.extend(rcv.to_le_bytes());
            }
            FuzzOp::SetStream { stream } => out.extend([T_STREAM, u8::from(*stream)]),
            FuzzOp::PeerSend { len } => {
                out.push(T_PEERSEND);
                out.extend(len.to_le_bytes());
            }
            FuzzOp::PeerFlush => out.push(T_PEERFLUSH),
            FuzzOp::Deliver {
                to_peer,
                index,
                mutation,
                pos,
                val,
                fec,
                ack_no_delay,
            } => {
                out.extend([T_DELIVER, u8::from(*to_peer), *index, *mutation]);
                out.extend(pos.to_le_bytes());
                out.extend([*val, flags(*fec, *ack_no_delay)]);
            }
            FuzzOp::Segment {
                cmd,
                frg,
                wnd,
                ts_rel,
                sn_rel,
                una_rel,
                len,
                fec,
                ack_no_delay,
            } => {
                out.extend([T_SEGMENT, *cmd, *frg]);
                out.extend(wnd.to_le_bytes());
                out.extend(ts_rel.to_le_bytes());
                out.extend(sn_rel.to_le_bytes());
                out.extend(una_rel.to_le_bytes());
                out.extend([*len, flags(*fec, *ack_no_delay)]);
            }
        }
    }
}

/// Encodes a harness input: `conv`, then `ops`.
pub fn encode(conv: u32, ops: &[FuzzOp]) -> Vec<u8> {
    let mut out = conv.to_le_bytes().to_vec();
    for op in ops {
        op.encode(&mut out);
    }
    out
}

/// Decodes a harness input into its `conv` and ops (`None` if shorter than 4 bytes).
pub fn decode(data: &[u8]) -> Option<(u32, Vec<FuzzOp>)> {
    let mut r = Reader { data };
    let conv = r.u32()?;
    let mut ops = Vec::new();
    while let Some(op) = FuzzOp::decode(&mut r) {
        ops.push(op);
    }
    Some((conv, ops))
}

/// Encodes one segment (header and payload) the way `segment.encode` lays it out, without
/// touching the SNMP counters.
#[allow(clippy::too_many_arguments)]
pub fn encode_segment(
    conv: u32,
    cmd: u8,
    frg: u8,
    wnd: u16,
    ts: u32,
    sn: u32,
    una: u32,
    data: &[u8],
) -> Vec<u8> {
    let mut buf = vec![0u8; 24];
    let p = ikcp_encode32u(&mut buf, conv);
    let p = ikcp_encode8u(p, cmd);
    let p = ikcp_encode8u(p, frg);
    let p = ikcp_encode16u(p, wnd);
    let p = ikcp_encode32u(p, ts);
    let p = ikcp_encode32u(p, sn);
    let p = ikcp_encode32u(p, una);
    ikcp_encode32u(p, data.len() as u32);
    buf.extend_from_slice(data);
    buf
}

/// What a run did (for the corpus tests; the fuzz target ignores it).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RunStats {
    /// Ops executed.
    pub ops: usize,
    /// `input` calls on A that returned 0.
    pub inputs_ok: usize,
    /// `input` calls on A that returned an error (-1, -2, -3).
    pub inputs_err: usize,
    /// Bytes A received through `recv`.
    pub recv_bytes: usize,
    /// Packets A passed to its output callback.
    pub outputs: usize,
    /// Whether A ended in the dead-link state.
    pub dead: bool,
}

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;
type FuzzOutput = Box<dyn FnMut(&[u8])>;
type FuzzClock = Box<dyn Fn() -> u32 + Send + Sync>;
type FuzzKcp = Kcp<FuzzOutput, FuzzClock>;

/// Largest `recv` buffer (the `len` of `Recv` is a `u16`).
const RECV_BUF: usize = u16::MAX as usize;

struct Harness {
    now: Arc<AtomicU32>,
    a: FuzzKcp,
    b: FuzzKcp,
    /// Packets output by B, waiting to be delivered to A.
    to_a: Queue,
    /// Packets output by A, waiting to be delivered to B.
    to_b: Queue,
    sent: usize,
    recv_buf: Vec<u8>,
    stats: RunStats,
}

fn endpoint(conv: u32, now: &Arc<AtomicU32>, queue: &Queue) -> FuzzKcp {
    let clock: FuzzClock = {
        let now = now.clone();
        Box::new(move || now.load(Ordering::Relaxed))
    };
    let output: FuzzOutput = {
        let queue = queue.clone();
        Box::new(move |buf: &[u8]| {
            let mut q = queue.borrow_mut();
            if q.len() >= MAX_QUEUED_PACKETS {
                q.pop_front();
            }
            q.push_back(buf.to_vec());
        })
    };
    Kcp::with_clock(conv, output, clock)
}

fn packet_type(fec: bool) -> PacketType {
    if fec {
        IKCP_PACKET_FEC
    } else {
        IKCP_PACKET_REGULAR
    }
}

/// Deterministic payload of `len` bytes.
fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// Asserts the invariants kcp-go maintains under any input.
fn check_invariants(k: &FuzzKcp, who: &str) {
    let in_flight = k.snd_nxt.wrapping_sub(k.snd_una);
    assert!(
        _itimediff(k.snd_nxt, k.snd_una) >= 0 && k.snd_buf.len() as u64 == u64::from(in_flight),
        "{who}: snd_buf holds {} segments, snd_una {} snd_nxt {}",
        k.snd_buf.len(),
        k.snd_una,
        k.snd_nxt
    );
    if let Some(first) = k.snd_buf.peek() {
        assert_eq!(
            first.sn, k.snd_una,
            "{who}: snd_buf does not start at snd_una"
        );
    }
    for seg in k.rcv_buf.segments() {
        assert!(
            k.rcv_buf.has(seg.sn),
            "{who}: rcv_buf sn {} unmarked",
            seg.sn
        );
    }
}

impl Harness {
    fn new(conv: u32) -> Self {
        let now = Arc::new(AtomicU32::new(0));
        let to_a: Queue = Rc::default();
        let to_b: Queue = Rc::default();
        let a = endpoint(conv, &now, &to_b);
        let mut b = endpoint(conv, &now, &to_a);
        // The honest peer: kcptun's "fast2"-like settings and a moderate window.
        b.nodelay(1, 20, 2, 1);
        b.wnd_size(256, 256);
        Harness {
            now,
            a,
            b,
            to_a,
            to_b,
            sent: 0,
            recv_buf: vec![0; RECV_BUF],
            stats: RunStats::default(),
        }
    }

    fn input_a(&mut self, data: &[u8], fec: bool, ack_no_delay: bool) {
        let before = self.to_b.borrow().len();
        if self.a.input(data, packet_type(fec), ack_no_delay) == 0 {
            self.stats.inputs_ok += 1;
        } else {
            self.stats.inputs_err += 1;
        }
        self.count_outputs(before);
    }

    fn count_outputs(&mut self, before: usize) {
        let after = self.to_b.borrow().len();
        // The queue may have dropped old packets; count at least what grew.
        self.stats.outputs += after.saturating_sub(before);
    }

    /// Bytes `send` may still accept this run.
    fn send_budget(&mut self, len: u16) -> Option<usize> {
        let len = len as usize;
        if self.sent + len > MAX_SEND_BYTES {
            return None;
        }
        self.sent += len;
        Some(len)
    }

    fn step(&mut self, op: FuzzOp) {
        let before = self.to_b.borrow().len();
        match op {
            FuzzOp::Input {
                fec,
                ack_no_delay,
                data,
            } => {
                self.input_a(&data, fec, ack_no_delay);
                return;
            }
            FuzzOp::Send { len } => {
                if let Some(len) = self.send_budget(len) {
                    self.a.send(&payload(len, 0xA5));
                }
            }
            FuzzOp::Flush { full } => {
                self.a.flush(if full {
                    IKCP_FLUSH_FULL
                } else {
                    IKCP_FLUSH_ACKONLY
                });
            }
            FuzzOp::Recv { len } => {
                let n = self.a.recv(&mut self.recv_buf[..len as usize]);
                if n > 0 {
                    self.stats.recv_bytes += n as usize;
                }
            }
            FuzzOp::Advance { ms } => {
                let now = self.now.load(Ordering::Relaxed);
                self.now.store(now.wrapping_add(ms), Ordering::Relaxed);
            }
            FuzzOp::Update => self.a.update(),
            FuzzOp::Check => {
                self.a.check();
            }
            FuzzOp::Query => {
                self.a.peek_size();
                self.a.wait_snd();
            }
            FuzzOp::SetMtu { mtu } => {
                self.a.set_mtu(mtu as isize);
            }
            FuzzOp::NoDelay {
                nodelay,
                interval,
                resend,
                nc,
            } => {
                self.a.nodelay(
                    nodelay as isize,
                    interval as isize,
                    resend as isize,
                    nc as isize,
                );
            }
            FuzzOp::WndSize { snd, rcv } => {
                self.a.wnd_size(snd as isize, rcv as isize);
            }
            FuzzOp::SetStream { stream } => self.a.stream = i32::from(stream),
            FuzzOp::PeerSend { len } => {
                if let Some(len) = self.send_budget(len) {
                    self.b.send(&payload(len, 0x5A));
                }
            }
            FuzzOp::PeerFlush => {
                while self.b.recv(&mut self.recv_buf) > 0 {}
                self.b.flush(IKCP_FLUSH_FULL);
            }
            FuzzOp::Deliver {
                to_peer,
                index,
                mutation,
                pos,
                val,
                fec,
                ack_no_delay,
            } => {
                let queue = if to_peer { &self.to_b } else { &self.to_a };
                let pkt = {
                    let mut q = queue.borrow_mut();
                    if q.is_empty() {
                        return;
                    }
                    let i = index as usize % q.len();
                    let mut pkt = if mutation % 4 == 3 {
                        q[i].clone()
                    } else {
                        q.remove(i).unwrap_or_default()
                    };
                    match mutation % 4 {
                        1 => pkt.truncate(pos as usize % (pkt.len() + 1)),
                        2 if !pkt.is_empty() => {
                            let at = pos as usize % pkt.len();
                            pkt[at] = val;
                        }
                        _ => {}
                    }
                    pkt
                };
                if to_peer {
                    // (B's input may flush ACKs towards A; nothing counts for A.)
                    self.b.input(&pkt, packet_type(fec), ack_no_delay);
                    return;
                }
                self.input_a(&pkt, fec, ack_no_delay);
                return;
            }
            FuzzOp::Segment {
                cmd,
                frg,
                wnd,
                ts_rel,
                sn_rel,
                una_rel,
                len,
                fec,
                ack_no_delay,
            } => {
                let cmd = if cmd < 0xF0 {
                    IKCP_CMD_PUSH + cmd % 4
                } else {
                    cmd
                };
                let base = if cmd == IKCP_CMD_ACK {
                    self.a.snd_una
                } else {
                    self.a.rcv_nxt
                };
                let now = self.now.load(Ordering::Relaxed);
                let seg = encode_segment(
                    self.a.conv,
                    cmd,
                    frg,
                    wnd,
                    now.wrapping_add(i32::from(ts_rel) as u32),
                    base.wrapping_add(i32::from(sn_rel) as u32),
                    self.a.snd_una.wrapping_add(i32::from(una_rel) as u32),
                    &payload(len as usize, frg),
                );
                self.input_a(&seg, fec, ack_no_delay);
                return;
            }
        }
        self.count_outputs(before);
    }

    fn finish_op(&mut self) {
        self.stats.ops += 1;
        check_invariants(&self.a, "A");
        check_invariants(&self.b, "B");
    }
}

/// Runs one fuzz input (see the module docs for the format). Panics only on a bug: a panic in
/// the KCP code, or a broken invariant.
pub fn kcp_input(data: &[u8]) -> RunStats {
    let mut r = Reader { data };
    let Some(conv) = r.u32() else {
        return RunStats::default();
    };
    let mut h = Harness::new(conv);
    while let Some(op) = FuzzOp::decode(&mut r) {
        h.step(op);
        h.finish_op();
    }
    h.stats.dead = h.a.state == 0xFFFF_FFFF;
    h.stats
}

/// Hand-made seeds: every segment kind, the input error paths, and short scripted exchanges
/// with the peer (fragments, window probing, retransmission, a dead link, MTU shrinking, the
/// clock wrapping). The seeds from kcp-go's golden traces are built in `kcp::trace_tests`.
pub fn handcrafted_seeds() -> Vec<(&'static str, Vec<u8>)> {
    use crate::kcp::{IKCP_CMD_WASK, IKCP_CMD_WINS};
    use FuzzOp::*;

    const CONV: u32 = 0x1122_3344;
    let seg = |cmd, frg, wnd, ts, sn, una, data: &[u8]| {
        encode_segment(CONV, cmd, frg, wnd, ts, sn, una, data)
    };
    let input = |data: Vec<u8>| Input {
        fec: false,
        ack_no_delay: false,
        data,
    };
    let deliver = |to_peer: bool, n: usize| {
        (0..n).map(move |_| Deliver {
            to_peer,
            index: 0,
            mutation: 0,
            pos: 0,
            val: 0,
            fec: false,
            ack_no_delay: false,
        })
    };
    let fast = NoDelay {
        nodelay: 1,
        interval: 10,
        resend: 2,
        nc: 1,
    };

    let mut seeds: Vec<(&'static str, Vec<FuzzOp>)> = Vec::new();

    seeds.push((
        "push_recv",
        vec![
            input(seg(IKCP_CMD_PUSH, 0, 32, 100, 0, 0, b"hello, kcp")),
            Recv { len: 64 },
            Flush { full: true },
        ],
    ));
    let mut multi = seg(IKCP_CMD_PUSH, 2, 32, 5, 0, 0, b"first");
    multi.extend(seg(IKCP_CMD_PUSH, 1, 32, 5, 1, 0, b"second"));
    multi.extend(seg(IKCP_CMD_PUSH, 0, 32, 5, 2, 0, b"third"));
    multi.extend(seg(IKCP_CMD_ACK, 0, 32, 5, 0, 0, b""));
    multi.extend(seg(IKCP_CMD_WASK, 0, 32, 5, 0, 0, b""));
    multi.extend(seg(IKCP_CMD_WINS, 0, 64, 5, 0, 0, b""));
    seeds.push((
        "all_cmds_one_packet",
        vec![
            input(multi),
            Query,
            Recv { len: 3 },
            Recv { len: 100 },
            Flush { full: true },
        ],
    ));
    seeds.push((
        "out_of_order_dup",
        vec![
            input(seg(IKCP_CMD_PUSH, 0, 32, 1, 2, 0, b"c")),
            input(seg(IKCP_CMD_PUSH, 0, 32, 1, 1, 0, b"b")),
            input(seg(IKCP_CMD_PUSH, 0, 32, 1, 1, 0, b"b")),
            Input {
                fec: true,
                ack_no_delay: true,
                data: seg(IKCP_CMD_PUSH, 0, 32, 1, 0, 0, b"a"),
            },
            Recv { len: 16 },
            Recv { len: 16 },
            Recv { len: 16 },
            Flush { full: false },
        ],
    ));
    let mut truncated = seg(IKCP_CMD_PUSH, 0, 32, 1, 0, 0, b"payload");
    truncated.truncate(27);
    let mut bad_cmd = seg(IKCP_CMD_PUSH, 0, 32, 1, 0, 0, b"");
    bad_cmd[4] = 99;
    seeds.push((
        "input_errors",
        vec![
            input(vec![0; 23]),
            input(encode_segment(
                CONV ^ 1,
                IKCP_CMD_PUSH,
                0,
                32,
                1,
                0,
                0,
                b"x",
            )),
            input(truncated),
            input(bad_cmd),
            input(Vec::new()),
        ],
    ));
    seeds.push((
        "exchange_stream",
        [
            vec![
                fast.clone(),
                SetStream { stream: true },
                Send { len: 20000 },
            ],
            vec![Flush { full: true }],
            deliver(true, 20).collect(),
            vec![PeerFlush],
            deliver(false, 10).collect(),
            vec![Recv { len: 4096 }, PeerSend { len: 3000 }, PeerFlush],
            deliver(false, 5).collect(),
            vec![Recv { len: 4096 }, Advance { ms: 50 }, Flush { full: true }],
        ]
        .concat(),
    ));
    seeds.push((
        "fragments_recv_small",
        [
            vec![PeerSend { len: 5000 }, PeerFlush],
            deliver(false, 5).collect(),
            vec![
                Query,
                Recv { len: 100 },
                Recv { len: 6000 },
                Flush { full: true },
            ],
            deliver(true, 2).collect(),
        ]
        .concat(),
    ));
    seeds.push((
        "lossy_retransmit",
        [
            vec![fast.clone(), Send { len: 8000 }, Flush { full: true }],
            vec![Deliver {
                to_peer: true,
                index: 0,
                mutation: 1,
                pos: 10,
                val: 0,
                fec: false,
                ack_no_delay: false,
            }],
            deliver(true, 5).collect(),
            vec![PeerFlush],
            vec![Deliver {
                to_peer: false,
                index: 0,
                mutation: 3,
                pos: 0,
                val: 0,
                fec: false,
                ack_no_delay: false,
            }],
            deliver(false, 3).collect(),
            vec![
                Flush { full: true },
                Advance { ms: 300 },
                Flush { full: true },
                Update,
                Check,
            ],
        ]
        .concat(),
    ));
    seeds.push((
        "zero_window_probe",
        vec![
            input(seg(IKCP_CMD_WINS, 0, 0, 1, 0, 0, b"")),
            Send { len: 100 },
            Flush { full: true },
            Advance { ms: 600 },
            Flush { full: true },
            Advance { ms: 1000 },
            Flush { full: true },
            input(seg(IKCP_CMD_WINS, 0, 32, 2, 0, 0, b"")),
            Flush { full: true },
        ],
    ));
    let mut dead = vec![Send { len: 10 }, Flush { full: true }];
    for _ in 0..24 {
        dead.extend([Advance { ms: 60_000 }, Flush { full: true }]);
    }
    seeds.push(("dead_link", dead));
    seeds.push((
        "mtu_shrink_after_send",
        vec![
            Send { len: 4000 },
            SetMtu { mtu: 50 },
            Flush { full: true },
            SetMtu { mtu: 49 },
            SetMtu { mtu: 1500 },
            Flush { full: true },
        ],
    ));
    seeds.push((
        "window_and_nodelay_edges",
        vec![
            WndSize { snd: -1, rcv: 0 },
            WndSize {
                snd: 70000,
                rcv: 70000,
            },
            NoDelay {
                nodelay: -1,
                interval: -5,
                resend: -1,
                nc: -1,
            },
            NoDelay {
                nodelay: 2,
                interval: 9000,
                resend: 0,
                nc: 0,
            },
            Send { len: 65535 },
            Flush { full: true },
            Segment {
                cmd: 1,
                frg: 0,
                wnd: 0xFFFF,
                ts_rel: 0,
                sn_rel: 3,
                una_rel: 0,
                len: 0,
                fec: false,
                ack_no_delay: true,
            },
            Segment {
                cmd: 1,
                frg: 0,
                wnd: 0xFFFF,
                ts_rel: -1,
                sn_rel: 0,
                una_rel: 2,
                len: 0,
                fec: false,
                ack_no_delay: false,
            },
            Flush { full: true },
        ],
    ));
    seeds.push((
        "clock_wrap",
        vec![
            Advance { ms: 0xFFFF_FF00 },
            Update,
            Send { len: 3000 },
            Update,
            Check,
            Advance { ms: 0x200 },
            Check,
            Update,
            Segment {
                cmd: 0,
                frg: 0,
                wnd: 32,
                ts_rel: -300,
                sn_rel: 0,
                una_rel: 0,
                len: 20,
                fec: false,
                ack_no_delay: false,
            },
            Recv { len: 64 },
        ],
    ));

    seeds
        .into_iter()
        .map(|(name, ops)| (name, encode(CONV, &ops)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kcp::SNMP_TEST_LOCK;

    fn snmp_read() -> std::sync::RwLockReadGuard<'static, ()> {
        SNMP_TEST_LOCK.read().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn fuzz_encode_decode_round_trip() {
        for (name, seed) in handcrafted_seeds() {
            let (conv, ops) = decode(&seed).expect("conv");
            assert_eq!(encode(conv, &ops), seed, "{name}");
        }
    }

    /// Every byte string is a valid input: short, empty, truncated ops and every tag.
    #[test]
    fn fuzz_any_bytes_run() {
        let _g = snmp_read();
        assert_eq!(kcp_input(&[]), RunStats::default());
        assert_eq!(kcp_input(&[1, 2, 3]), RunStats::default());
        for tag in 0..=255u8 {
            let mut data = vec![0x44, 0x33, 0x22, 0x11, tag];
            data.extend([0xFF; 3]);
            kcp_input(&data);
            // Truncated op: ignored.
            kcp_input(&[0x44, 0x33, 0x22, 0x11, tag]);
        }
        // A pseudo-random stream.
        let mut x: u32 = 0x1234_5678;
        let data: Vec<u8> = (0..20_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        for start in (0..data.len()).step_by(997) {
            kcp_input(&data[start..]);
        }
    }

    /// The hand-made seeds do what they are named for.
    #[test]
    fn fuzz_handcrafted_seeds_run() {
        let _g = snmp_read();
        let seeds = handcrafted_seeds();
        let stats = |name: &str| {
            let (_, data) = seeds.iter().find(|(n, _)| *n == name).expect("seed exists");
            kcp_input(data)
        };
        for (name, data) in &seeds {
            let s = kcp_input(data);
            assert_eq!(s.ops, decode(data).expect("conv").1.len(), "{name}");
        }
        let s = stats("push_recv");
        assert_eq!((s.inputs_ok, s.recv_bytes), (1, 10));
        let s = stats("all_cmds_one_packet");
        assert_eq!((s.inputs_ok, s.recv_bytes), (1, 16));
        let s = stats("out_of_order_dup");
        assert_eq!((s.inputs_ok, s.recv_bytes), (4, 3));
        let s = stats("input_errors");
        assert_eq!((s.inputs_ok, s.inputs_err), (0, 5));
        let s = stats("exchange_stream");
        // One ACK packet for the 15 segments sent, then the 3 segments of the reply.
        assert_eq!((s.inputs_ok, s.recv_bytes), (4, 3000), "{s:?}");
        let s = stats("fragments_recv_small");
        assert_eq!(s.recv_bytes, 5000, "{s:?}");
        assert!(stats("dead_link").dead);
        assert!(!stats("lossy_retransmit").dead);
    }

    /// `Deliver` mutations and duplicates reach the target.
    #[test]
    fn fuzz_deliver_mutations() {
        let _g = snmp_read();
        let mut ops = vec![FuzzOp::PeerSend { len: 6000 }, FuzzOp::PeerFlush];
        for mutation in 0..4 {
            ops.push(FuzzOp::Deliver {
                to_peer: false,
                index: 7,
                mutation,
                pos: 30,
                val: 0xEE,
                fec: false,
                ack_no_delay: true,
            });
        }
        let s = kcp_input(&encode(1, &ops));
        assert_eq!(s.ops, 6);
        assert_eq!(s.inputs_ok + s.inputs_err, 4);
        assert!(s.inputs_err >= 1, "the truncated packet is rejected: {s:?}");
    }
}
