//! KCP ARQ benchmarks (plan step 03.6), the Rust side of
//! `tools/govectors/internal/kcpcopy/bench_test.go`. They measure the naive, line-by-line port
//! of kcp-go's `kcp.go` and are the baseline for Step 12 (DECISIONS D25: no algorithmic
//! optimisation here). Results and methodology: `docs/benchmarks/kcp.md`.
//!
//! - `kcp/flush/snd_buf/<n>`: kcp-go's `BenchmarkFlush`. `snd_buf` is a ring of `n` slots
//!   holding `n - 1` segments that were sent once (`xmit = 1`) and whose retransmission time is
//!   far in the future, so a full flush only scans the window. `n` = 1024 (Go's bench) and 8192
//!   (the production window). One iteration is one `flush(IKCP_FLUSH_FULL)` under a mutex, as
//!   in Go.
//! - `kcp/flush/snd_buf_oracle/<n>`: the same with the Decision D29 scan skipping (plan 12.2c)
//!   turned off, which is the naive line-by-line port and the permanent oracle of DECISIONS
//!   D25. It is the "before" of the 12.2c measurement and stays comparable with Go's
//!   `BenchmarkFlush` for ever.
//! - `kcp/input_ack/{in_order,sack}/<w>`: ACK processing. A sender has `w` full-size segments in
//!   flight; one iteration inputs the ACK packets that acknowledge the whole window, 58 ACKs per
//!   1400-byte packet (what a kcp-go receiver's flush packs). `in_order`: each packet carries
//!   the receiver's cumulative `una` (the normal case), which retires the acknowledged segments
//!   before `parse_ack` ever sees them. `sack`: the first segment was lost, so `una` stays at 0
//!   and every ACK is selective (each packet also triggers a fast retransmit flush) — the case
//!   plan 12.2d addresses. Throughput is in ACKs.
//! - `kcp/input_ack/{in_order_oracle,sack_oracle}/<w>`: the same two scenarios with the Decision
//!   D29 and D31 fast paths turned off, which is the naive line-by-line port and the permanent
//!   oracle of DECISIONS D25. `sack_oracle` is the "before" of the 12.2d measurement and
//!   `in_order_oracle` the "before" of 12.2c's effect on the *ordinary* ACK path; both stay
//!   comparable with Go's `BenchmarkInputAck` for ever. `in_order` is untouched by D31 — the
//!   cumulative `una` retires a segment before `parse_ack` can see it — but it is **not**
//!   untouched by D29: `Kcp::input` flushes (`IKCP_FLUSH_FULL`) every time the send window
//!   slides, so every one of these packets costs a flush, which is what plan 12.2e found on the
//!   Neoverse-N1 (`docs/benchmarks/kcp.md` § 12.2e).
//! - `kcp/send_flush/64KiB`: a sender/receiver pair in stream mode with windows of 1024: one
//!   iteration sends 64 KiB, flushes, inputs every packet into the receiver, reads everything,
//!   flushes the receiver's ACKs and inputs them into the sender. Throughput is in payload
//!   bytes.
//!
//! The input and send benches use a fixed clock (no retransmission timer can fire, RTT = 0);
//! the flush bench uses the production clock like Go's.
//!
//! Run: `cargo bench -p kcptun-kcp --bench kcp`.

use std::cell::RefCell;
use std::hint::black_box;
use std::rc::Rc;
use std::sync::Mutex;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use kcptun_kcp::clock::current_ms;
use kcptun_kcp::internals::fuzz::encode_segment;
use kcptun_kcp::internals::{flush, set_fast_path, set_stream, snd_buf_mut};
use kcptun_kcp::kcp::{
    IKCP_CMD_ACK, IKCP_CMD_WINS, IKCP_FLUSH_FULL, IKCP_OVERHEAD, IKCP_PACKET_REGULAR, Kcp, Output,
};
use kcptun_kcp::ringbuffer::RingBuffer;
use kcptun_kcp::segment::Segment;

/// Window sizes: kcp-go's `BenchmarkFlush` ring (1024) and the production window (8192).
const WINDOWS: [usize; 2] = [1024, 8192];

/// How far in the future the flush bench's segments are due (ms). Go's `BenchmarkFlush` uses
/// 10 s, which a criterion run (and a long `-benchtime`) outlasts; both sides use 10^7 ms.
const FAR_FUTURE_MS: u32 = 10_000_000;

const CONV: u32 = 1;
/// The fixed clock value of the input and send benches.
const T0: u32 = 1_000_000;
/// kcp-go's default MTU (`IKCP_MTU_DEF`) and its segment payload size.
const MTU: usize = 1400;
const MSS: usize = MTU - IKCP_OVERHEAD as usize;
/// ACKs per packet from a kcp-go receiver's flush: `makeSpace` flushes when the next 24 bytes
/// would exceed the MTU.
const ACKS_PER_PACKET: usize = MTU / IKCP_OVERHEAD as usize;

fn fixed_clock() -> u32 {
    T0
}

// Go: kcp-go/v5@v5.6.66 kcp_test.go:BenchmarkFlush
fn bench_flush(c: &mut Criterion) {
    let mut group = c.benchmark_group("kcp/flush");
    for n in WINDOWS {
        for (name, fast_path) in [("snd_buf", true), ("snd_buf_oracle", false)] {
            let mut kcp = Kcp::new(1, |_: &[u8]| {});
            set_fast_path(&mut kcp, fast_path);
            let snd_buf = snd_buf_mut(&mut kcp);
            *snd_buf = RingBuffer::new(n);
            let resendts = current_ms().wrapping_add(FAR_FUTURE_MS);
            for _ in 0..snd_buf.max_len() {
                snd_buf.push(Segment {
                    xmit: 1,
                    resendts,
                    ..Segment::default()
                });
            }
            let kcp = Mutex::new(kcp);
            group.bench_function(BenchmarkId::new(name, n), |b| {
                b.iter(|| {
                    let mut k = kcp.lock().unwrap_or_else(|e| e.into_inner());
                    black_box(flush(&mut *k, IKCP_FLUSH_FULL))
                })
            });
        }
    }
    group.finish();
}

type Sender = Kcp<fn(&[u8]), fn() -> u32>;

fn discard(_: &[u8]) {}

/// A sender with `w` full-size segments in flight (sn 0..w, sent at `T0`), no congestion
/// window (`nc = 1`, as kcptun's fast modes) and a peer window of `w`. `fast_path` is
/// Decisions D29 and D31 (see [`set_fast_path`]).
fn in_flight_sender(w: usize, fast_path: bool) -> Sender {
    let mut k: Sender = Kcp::with_clock(CONV, discard as fn(&[u8]), fixed_clock as fn() -> u32);
    set_fast_path(&mut k, fast_path);
    k.nodelay(1, 10, 2, 1);
    k.wnd_size(w as isize, w as isize);
    // The receiver's window (rmt_wnd) comes from a regular packet.
    let wins = encode_segment(CONV, IKCP_CMD_WINS, 0, w as u16, T0, 0, 0, &[]);
    assert_eq!(k.input(&wins, IKCP_PACKET_REGULAR, false), 0);
    let data = vec![0x5A; MSS];
    for _ in 0..w {
        assert_eq!(k.send(&data), 0);
    }
    flush(&mut k, IKCP_FLUSH_FULL);
    assert_eq!(k.wait_snd(), w, "whole window in flight");
    k
}

/// The ACK packets acknowledging segments `first..w`, as a kcp-go receiver packs them.
/// `cumulative`: each packet's `una` is one past its last ACK (in-order delivery); otherwise
/// `una` is 0 (segment 0 lost).
fn ack_packets(first: usize, w: usize, cumulative: bool) -> Vec<Vec<u8>> {
    let sns: Vec<u32> = (first as u32..w as u32).collect();
    sns.chunks(ACKS_PER_PACKET)
        .map(|chunk| {
            let una = if cumulative {
                chunk[chunk.len() - 1] + 1
            } else {
                0
            };
            chunk
                .iter()
                .flat_map(|&sn| encode_segment(CONV, IKCP_CMD_ACK, 0, w as u16, T0, sn, una, &[]))
                .collect()
        })
        .collect()
}

fn bench_input_ack(c: &mut Criterion) {
    let mut group = c.benchmark_group("kcp/input_ack");
    group.sample_size(20);
    for (name, first, cumulative, fast_path) in [
        ("in_order", 0, true, true),
        ("in_order_oracle", 0, true, false),
        ("sack", 1, false, true),
        ("sack_oracle", 1, false, false),
    ] {
        for w in WINDOWS {
            let packets = ack_packets(first, w, cumulative);
            // Check once that the packets do what they should.
            let mut k = in_flight_sender(w, fast_path);
            for p in &packets {
                assert_eq!(k.input(p, IKCP_PACKET_REGULAR, false), 0);
            }
            assert_eq!(k.wait_snd(), if cumulative { 0 } else { w }, "{name}/{w}");

            group.throughput(Throughput::Elements((w - first) as u64));
            group.bench_function(BenchmarkId::new(name, w), |b| {
                b.iter_batched(
                    || in_flight_sender(w, fast_path),
                    |mut k| {
                        for p in &packets {
                            black_box(k.input(p, IKCP_PACKET_REGULAR, false));
                        }
                        k
                    },
                    BatchSize::PerIteration,
                )
            });
        }
    }
    group.finish();
}

/// Output sink of the send bench: packets appended to one buffer (no allocation per packet).
#[derive(Default)]
struct Packets {
    bytes: Vec<u8>,
    ends: Vec<usize>,
}

impl Packets {
    fn for_each(&self, mut f: impl FnMut(&[u8])) {
        let mut start = 0;
        for &end in &self.ends {
            f(&self.bytes[start..end]);
            start = end;
        }
    }

    fn clear(&mut self) {
        self.bytes.clear();
        self.ends.clear();
    }
}

#[derive(Clone, Default)]
struct Sink(Rc<RefCell<Packets>>);

impl Output for Sink {
    fn output(&mut self, buf: &[u8]) {
        let mut p = self.0.borrow_mut();
        p.bytes.extend_from_slice(buf);
        let end = p.bytes.len();
        p.ends.push(end);
    }
}

type Peer = Kcp<Sink, fn() -> u32>;

/// Bytes sent per iteration of the send bench.
const SEND_BYTES: usize = 64 * 1024;

struct Pair {
    a: Peer,
    b: Peer,
    a_out: Sink,
    b_out: Sink,
    msg: Vec<u8>,
    rbuf: Vec<u8>,
}

impl Pair {
    fn new() -> Self {
        let (a_out, b_out) = (Sink::default(), Sink::default());
        let peer = |out: &Sink| {
            let mut k: Peer = Kcp::with_clock(CONV, out.clone(), fixed_clock as fn() -> u32);
            k.nodelay(1, 10, 2, 1);
            k.wnd_size(1024, 1024);
            k
        };
        let (a, b) = (peer(&a_out), peer(&b_out));
        let mut pair = Pair {
            a,
            b,
            a_out,
            b_out,
            msg: vec![0xA5; SEND_BYTES],
            rbuf: vec![0; SEND_BYTES],
        };
        // kcptun's setting (Go: UDPSession.SetStreamMode(true) sets kcp.stream = 1).
        set_stream(&mut pair.a, true);
        set_stream(&mut pair.b, true);
        // Warm up: the first exchange teaches the sender the receiver's window (kcp-go starts
        // with rmt_wnd = 32, so 16 of the 48 segments wait for the second round); from the
        // third round on, every round moves exactly SEND_BYTES.
        let warm: usize = (0..2).map(|_| pair.round()).sum();
        assert_eq!(warm, 2 * SEND_BYTES);
        assert_eq!(pair.round(), SEND_BYTES);
        assert_eq!(pair.a.wait_snd(), 0);
        pair
    }

    /// One iteration; returns the bytes the receiver read.
    fn round(&mut self) -> usize {
        self.a.send(&self.msg);
        flush(&mut self.a, IKCP_FLUSH_FULL);
        {
            let b = &mut self.b;
            self.a_out.0.borrow().for_each(|p| {
                b.input(p, IKCP_PACKET_REGULAR, false);
            });
        }
        self.a_out.0.borrow_mut().clear();
        let mut got = 0;
        loop {
            let n = self.b.recv(&mut self.rbuf);
            if n < 0 {
                break;
            }
            got += n as usize;
        }
        flush(&mut self.b, IKCP_FLUSH_FULL);
        {
            let a = &mut self.a;
            self.b_out.0.borrow().for_each(|p| {
                a.input(p, IKCP_PACKET_REGULAR, false);
            });
        }
        self.b_out.0.borrow_mut().clear();
        // (In the steady state, the flush that the ACKs trigger in the sender has nothing to
        // send; in the warm-up it sends what the initial window held back, and those packets
        // go out with the next round.)
        got
    }
}

fn bench_send_flush(c: &mut Criterion) {
    let mut group = c.benchmark_group("kcp/send_flush");
    group.throughput(Throughput::Bytes(SEND_BYTES as u64));
    let mut pair = Pair::new();
    group.bench_function("64KiB", |b| b.iter(|| black_box(pair.round())));
    assert_eq!(pair.round(), SEND_BYTES, "steady state after the bench");
    assert_eq!(pair.a.wait_snd(), 0);
    group.finish();
}

criterion_group!(benches, bench_flush, bench_input_ack, bench_send_flush);
criterion_main!(benches);
