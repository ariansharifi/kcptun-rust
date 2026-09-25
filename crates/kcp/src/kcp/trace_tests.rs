//! Golden-trace replay: the `trace/<config>` cases of `testdata/vectors/kcp.json`.
//!
//! `tools/govectors` (`kcptrace.go`) ran two endpoints of the pinned kcp-go KCP (a verbatim
//! copy whose `currentMs()` reads an injected clock) over a deterministic lossy link and
//! recorded, per endpoint, every API call with the clock value, its arguments and its exact
//! results: the return value, every packet passed to the output callback, the number of clock
//! reads, and a digest of the whole KCP state afterwards. Here each endpoint is replayed alone,
//! call by call, on a clock set to the recorded value (advancing by the config's `clock_step`
//! on every read); input packets are taken from the peer's recorded output. Every result must
//! match byte for byte. A mismatch means the port deviates from Go: fix the port, never the
//! trace. The op format is documented in `tools/govectors/README.md` (group `trace`).

use super::*;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use kcptun_testkit::rng::{fnv1a64, govectors_rng, rand_bytes};
use kcptun_testkit::vectors;
use kcptun_testkit::vectors::sha256_hex;
use serde::Deserialize;

/// Names of [`state_words`], in order (Go: `kcpcopy.StateWordNames`).
pub(super) const STATE_WORD_NAMES: [&str; 32] = [
    "mtu",
    "mss",
    "state",
    "snd_una",
    "snd_nxt",
    "rcv_nxt",
    "ssthresh",
    "rx_rttvar",
    "rx_srtt",
    "rx_rto",
    "rx_minrto",
    "snd_wnd",
    "rcv_wnd",
    "rmt_wnd",
    "cwnd",
    "probe",
    "interval",
    "ts_flush",
    "nodelay",
    "updated",
    "ts_probe",
    "probe_wait",
    "dead_link",
    "incr",
    "fastresend",
    "nocwnd",
    "stream",
    "snd_queue_len",
    "rcv_queue_len",
    "snd_buf_len",
    "rcv_buf_len",
    "acklist_len",
];

/// The scalar state of `k` (Go: `kcpcopy.KCP.StateWords`).
pub(super) fn state_words<O, C>(k: &Kcp<O, C>) -> [u32; 32] {
    [
        k.mtu,
        k.mss,
        k.state,
        k.snd_una,
        k.snd_nxt,
        k.rcv_nxt,
        k.ssthresh,
        k.rx_rttvar as u32,
        k.rx_srtt as u32,
        k.rx_rto,
        k.rx_minrto,
        k.snd_wnd,
        k.rcv_wnd,
        k.rmt_wnd,
        k.cwnd,
        k.probe,
        k.interval,
        k.ts_flush,
        k.nodelay,
        k.updated,
        k.ts_probe,
        k.probe_wait,
        k.dead_link,
        k.incr,
        k.fastresend as u32,
        k.nocwnd as u32,
        k.stream as u32,
        k.snd_queue.len() as u32,
        k.rcv_queue.len() as u32,
        k.snd_buf.len() as u32,
        k.rcv_buf.len() as u32,
        k.acklist.len() as u32,
    ]
}

/// FNV-1a 64 of the state words, the queued/sent/received segments and the ACK list (Go:
/// `kcpcopy.KCP.StateDigest`, which documents the word order).
pub(super) fn state_digest<O, C>(k: &Kcp<O, C>) -> u64 {
    let mut words: Vec<u32> = state_words(k).to_vec();
    for seg in k.snd_queue.iter() {
        words.extend([u32::from(seg.frg), seg.data.len() as u32]);
    }
    for seg in k.snd_buf.iter() {
        words.extend([
            seg.sn,
            u32::from(seg.frg),
            seg.ts,
            u32::from(seg.wnd),
            seg.una,
            seg.rto,
            seg.xmit,
            seg.resendts,
            seg.fastack,
            seg.acked,
            seg.data.len() as u32,
        ]);
    }
    for seg in k.rcv_queue.iter() {
        words.extend([seg.sn, u32::from(seg.frg), seg.data.len() as u32]);
    }
    for seg in k.rcv_buf.segments() {
        words.extend([seg.sn, u32::from(seg.frg), seg.data.len() as u32]);
    }
    for ack in &k.acklist {
        words.extend([ack.sn, ack.ts]);
    }
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    fnv1a64(&bytes)
}

/// A clock set before each call that advances by `step` on every read and counts the reads.
#[derive(Clone, Default)]
struct TraceClock {
    now: Arc<AtomicU32>,
    step: u32,
    reads: Arc<AtomicU32>,
}

impl Clock for TraceClock {
    fn now_ms(&self) -> u32 {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.now.fetch_add(self.step, Ordering::Relaxed)
    }
}

/// One endpoint's recorded trace (Go: `traceEP`).
#[derive(Clone, Deserialize)]
struct TraceEp {
    payload_stream: u64,
    snmp: BTreeMap<String, u64>,
    gauges: Vec<u64>,
    #[serde(rename = "final")]
    final_words: Vec<u32>,
    ops: Vec<String>,
}

/// One parsed op: its name, `key=value` tokens and output packets, in order.
struct Op {
    name: String,
    kv: Vec<(String, String)>,
    outs: Vec<Vec<u8>>,
}

impl Op {
    fn parse(line: &str) -> Op {
        let mut tokens = line.split(' ');
        let name = tokens.next().expect("op name").to_string();
        let mut kv = Vec::new();
        let mut outs = Vec::new();
        for t in tokens {
            let (k, v) = t
                .split_once('=')
                .unwrap_or_else(|| panic!("bad token {t:?}"));
            if k == "o" {
                outs.push(hex::decode(v).expect("output hex"));
            } else {
                kv.push((k.to_string(), v.to_string()));
            }
        }
        Op { name, kv, outs }
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.kv
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    fn num<T: std::str::FromStr>(&self, key: &str) -> T
    where
        T::Err: fmt::Debug,
    {
        let v = self
            .get(key)
            .unwrap_or_else(|| panic!("{}: missing {key}", self.name));
        v.parse()
            .unwrap_or_else(|e| panic!("{}: bad {key}={v}: {e:?}", self.name))
    }

    fn args(&self) -> Vec<isize> {
        self.get("a")
            .expect("args")
            .split(',')
            .map(|x| x.parse().expect("arg"))
            .collect()
    }
}

/// Counters the KCP core increments, as recorded in `snmp` (Go: `traceSnmpFields`).
fn snmp_counters() -> BTreeMap<String, u64> {
    let s = DEFAULT_SNMP.copy();
    [
        ("InSegs", s.in_segs),
        ("OutSegs", s.out_segs),
        ("RepeatSegs", s.repeat_segs),
        ("LostSegs", s.lost_segs),
        ("FastRetransSegs", s.fast_retrans_segs),
        ("EarlyRetransSegs", s.early_retrans_segs),
        ("RetransSegs", s.retrans_segs),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}

type Sink = Rc<RefCell<Vec<Vec<u8>>>>;
type BoxOutput = Box<dyn FnMut(&[u8])>;

/// Replays one endpoint's ops and asserts every recorded result. Returns the number of ops.
fn replay(case: &str, side: &str, conv: u32, step: u32, ep: &TraceEp, peer: &[Op]) -> usize {
    let clock = TraceClock {
        step,
        ..TraceClock::default()
    };
    let sink: Sink = Rc::default();
    let out: BoxOutput = {
        let sink = sink.clone();
        Box::new(move |b: &[u8]| sink.borrow_mut().push(b.to_vec()))
    };
    let mut k = Kcp::with_clock(conv, out, clock.clone());
    let mut payload = govectors_rng("kcp", ep.payload_stream);

    let snmp_before = snmp_counters();
    for (i, line) in ep.ops.iter().enumerate() {
        let op = Op::parse(line);
        let at = || format!("{case} {side} op {i}: {line:.160}");
        clock.now.store(op.num("t"), Ordering::Relaxed);
        clock.reads.store(0, Ordering::Relaxed);
        sink.borrow_mut().clear();

        let mut recv_hash = None;
        let ret: Option<i64> = match op.name.as_str() {
            "setmtu" => Some(k.set_mtu(op.args()[0]) as i64),
            "nodelay" => {
                let a = op.args();
                Some(k.nodelay(a[0], a[1], a[2], a[3]) as i64)
            }
            "wndsize" => {
                let a = op.args();
                Some(k.wnd_size(a[0], a[1]) as i64)
            }
            "stream" => {
                // Go: UDPSession.SetStreamMode writes the field directly.
                k.stream = op.args()[0] as i32;
                None
            }
            "send" => {
                let data = rand_bytes(&mut payload, op.num("n"));
                Some(k.send(&data) as i64)
            }
            "input" => {
                let data = match (op.get("hex"), op.get("src")) {
                    (Some(h), _) => hex::decode(h).expect("input hex"),
                    (None, Some(src)) => {
                        let (o, j) = src.split_once('.').expect("src op.out");
                        let o: usize = o.parse().expect("src op");
                        let j: usize = j.parse().expect("src out");
                        let mut p = peer[o].outs[j].clone();
                        if op.get("cut").is_some() {
                            p.truncate(op.num("cut"));
                        }
                        p
                    }
                    (None, None) => panic!("{}: input without data", at()),
                };
                let pt = match op.num::<u8>("pt") {
                    0 => IKCP_PACKET_REGULAR,
                    1 => IKCP_PACKET_FEC,
                    v => panic!("{}: unknown pktType {v}", at()),
                };
                Some(k.input(&data, pt, op.num::<u8>("and") != 0) as i64)
            }
            "flush" => {
                let ft = match op.num::<u8>("ft") {
                    1 => IKCP_FLUSH_ACKONLY,
                    2 => IKCP_FLUSH_FULL,
                    v => panic!("{}: unknown flushType {v}", at()),
                };
                Some(i64::from(k.flush(ft)))
            }
            "update" => {
                k.update();
                None
            }
            "check" => Some(i64::from(k.check())),
            "recv" => {
                let mut buf = vec![0u8; op.num("n")];
                let n = k.recv(&mut buf);
                if n > 0 {
                    recv_hash = Some(sha256_hex(&buf[..n as usize])[..16].to_string());
                }
                Some(n as i64)
            }
            "peek" => Some(k.peek_size() as i64),
            "waitsnd" => Some(k.wait_snd() as i64),
            other => panic!("{}: unknown op {other}", at()),
        };

        if let Some(want) = op.get("ret") {
            assert_eq!(
                ret.map(|r| r.to_string()).as_deref(),
                Some(want),
                "{}: return value",
                at()
            );
        }
        assert_eq!(
            recv_hash.as_deref(),
            op.get("h"),
            "{}: received bytes",
            at()
        );
        let outs = std::mem::take(&mut *sink.borrow_mut());
        assert_eq!(
            outs.len(),
            op.outs.len(),
            "{}: number of output packets",
            at()
        );
        for (j, (got, want)) in outs.iter().zip(&op.outs).enumerate() {
            kcptun_testkit::assert_hex_eq!(got, want, "{}: output packet {j}", at());
        }
        assert_eq!(
            clock.reads.load(Ordering::Relaxed),
            op.num::<u32>("rd"),
            "{}: clock reads",
            at()
        );
        assert_eq!(
            format!("{:016x}", state_digest(&k)),
            op.get("st").expect("st"),
            "{}: state digest; state words now {:?}",
            at(),
            STATE_WORD_NAMES
                .iter()
                .zip(state_words(&k))
                .collect::<Vec<_>>()
        );
    }

    assert_eq!(
        state_words(&k).to_vec(),
        ep.final_words,
        "{case} {side}: final state"
    );
    let snmp_after = snmp_counters();
    let delta: BTreeMap<String, u64> = snmp_after
        .iter()
        .map(|(name, v)| (name.clone(), v - snmp_before[name]))
        .collect();
    assert_eq!(delta, ep.snmp, "{case} {side}: SNMP counter increments");
    if !ep.gauges.is_empty() {
        let s = DEFAULT_SNMP.copy();
        assert_eq!(
            vec![
                s.ring_buffer_snd_queue,
                s.ring_buffer_rcv_queue,
                s.ring_buffer_snd_buffer
            ],
            ep.gauges,
            "{case} {side}: RingBuffer gauges after the last flush"
        );
    }
    ep.ops.len()
}

/// Replays both endpoints of every `trace/` case. Holds the SNMP write lock, since the
/// counter increments and gauges are asserted exactly.
#[test]
fn vectors_kcp_trace() {
    let _g = SNMP_TEST_LOCK.write().unwrap_or_else(|e| e.into_inner());
    let file = vectors!("kcp");
    let mut cases = 0;
    let mut ops = 0;
    for case in file.cases_with_prefix("trace/") {
        let conv: u32 = case.param("conv");
        let step: u32 = case.param("clock_step");
        let a: TraceEp = case.field("a");
        let b: TraceEp = case.field("b");
        let a_ops: Vec<Op> = a.ops.iter().map(|l| Op::parse(l)).collect();
        let b_ops: Vec<Op> = b.ops.iter().map(|l| Op::parse(l)).collect();
        ops += replay(&case.name, "a", conv, step, &a, &b_ops);
        ops += replay(&case.name, "b", conv, step, &b, &a_ops);
        cases += 1;
    }
    assert_eq!(cases, 12, "trace cases");
    assert!(ops > 4000, "only {ops} ops replayed");
}

/// The replay notices a deviation: the same trace with one output byte, one return value, the
/// clock read count or the state digest of a single op changed fails at exactly that op.
#[test]
fn vectors_kcp_trace_replay_detects_changes() {
    let _g = SNMP_TEST_LOCK.write().unwrap_or_else(|e| e.into_inner());
    let file = vectors!("kcp");
    let case = file.case("trace/normal_w32_mtu1400");
    let conv: u32 = case.param("conv");
    let a: TraceEp = case.field("a");
    let b: TraceEp = case.field("b");
    let b_ops: Vec<Op> = b.ops.iter().map(|l| Op::parse(l)).collect();
    let flush = a
        .ops
        .iter()
        .position(|l| l.starts_with("flush") && l.contains(" o="))
        .expect("a flush with output");

    // The unmodified trace replays.
    replay("untampered", "a", conv, 0, &a, &b_ops);

    type Tamper = fn(&str) -> String;
    let tampers: [(&str, Tamper); 4] = [
        ("output byte", |l| {
            // Flip the last hex digit of the last output packet.
            let mut s = l.to_string();
            let c = s.pop().expect("non-empty");
            s.push(if c == '0' { '1' } else { '0' });
            s
        }),
        ("return value", |l| l.replacen(" ret=", " ret=9", 1)),
        ("clock reads", |l| l.replacen(" rd=", " rd=7", 1)),
        ("state digest", |l| {
            let (head, st) = l.split_once(" st=").expect("st");
            let (digest, tail) = st.split_at(16);
            let other = u64::from_str_radix(digest, 16).expect("hex") ^ 1;
            format!("{head} st={other:016x}{tail}")
        }),
    ];
    for (what, tamper) in tampers {
        let mut ep = a.clone();
        ep.ops[flush] = tamper(&ep.ops[flush]);
        assert_ne!(ep.ops[flush], a.ops[flush]);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            replay("tampered", "a", conv, 0, &ep, &b_ops)
        }));
        let msg = match r {
            Ok(_) => panic!("changed {what} was not detected"),
            Err(e) => e.downcast_ref::<String>().cloned().unwrap_or_default(),
        };
        assert!(
            msg.contains(&format!("tampered a op {flush}:")),
            "changed {what} detected at the wrong place: {msg}"
        );
    }
}

/// The traces cover what they are meant to: every command, every input error, FEC-typed and
/// truncated inputs, recv -1/-2, send -1/-2, every retransmission kind, a dead link, window
/// probing and the clock wrapping.
#[test]
fn vectors_kcp_trace_coverage() {
    let file = vectors!("kcp");
    let mut cmds = BTreeMap::<u8, usize>::new();
    let mut rets = BTreeMap::<String, usize>::new();
    let mut tokens = BTreeMap::<&str, usize>::new();
    let mut snmp = BTreeMap::<String, u64>::new();
    let mut dead = 0;
    let mut wrapped = false;
    for case in file.cases_with_prefix("trace/") {
        for side in ["a", "b"] {
            let ep: TraceEp = case.field(side);
            if ep.final_words[2] == 0xFFFF_FFFF {
                dead += 1;
            }
            for (k, v) in &ep.snmp {
                *snmp.entry(k.clone()).or_default() += v;
            }
            let mut last_t = None;
            for line in &ep.ops {
                let op = Op::parse(line);
                let t: u32 = op.num("t");
                if last_t.is_some_and(|l: u32| t < l) {
                    wrapped = true;
                }
                last_t = Some(t);
                if let Some(r) = op.get("ret") {
                    *rets
                        .entry(format!(
                            "{}:{}",
                            op.name,
                            if r.starts_with('-') { r } else { "ok" }
                        ))
                        .or_default() += 1;
                }
                for key in ["cut", "hex"] {
                    if op.get(key).is_some() {
                        *tokens.entry(key).or_default() += 1;
                    }
                }
                if op.get("pt") == Some("1") {
                    *tokens.entry("fec").or_default() += 1;
                }
                for p in &op.outs {
                    let mut rest = p.as_slice();
                    while let Some((h, tail)) = SegmentHeader::decode(rest) {
                        *cmds.entry(h.cmd).or_default() += 1;
                        rest = &tail[h.len as usize..];
                    }
                }
            }
        }
    }
    for cmd in [IKCP_CMD_PUSH, IKCP_CMD_ACK, IKCP_CMD_WASK, IKCP_CMD_WINS] {
        assert!(
            cmds.get(&cmd).is_some_and(|&n| n > 0),
            "cmd {cmd} never output: {cmds:?}"
        );
    }
    for r in [
        "input:-1", "input:-2", "input:-3", "recv:-1", "recv:-2", "send:-1", "send:-2",
    ] {
        assert!(rets.contains_key(r), "no {r}: {rets:?}");
    }
    for t in ["cut", "hex", "fec"] {
        assert!(tokens.contains_key(t), "no {t} input: {tokens:?}");
    }
    for c in [
        "LostSegs",
        "FastRetransSegs",
        "EarlyRetransSegs",
        "RepeatSegs",
    ] {
        assert!(snmp[c] > 0, "{c} is 0: {snmp:?}");
    }
    assert_eq!(dead, 1, "exactly the dead_link trace ends dead");
    assert!(wrapped, "no trace crosses the u32 clock wrap");
}

/// Maximum size of one fuzz seed built from a trace (a prefix of the endpoint's ops).
const FUZZ_SEED_MAX: usize = 16 * 1024;

/// The fuzz seeds taken from kcp-go's golden traces (plan 03.6): for every trace endpoint, a
/// prefix (at most [`FUZZ_SEED_MAX`] bytes) of its recorded calls as `kcp_input` harness ops.
/// The inputs are the packets the Go peer actually sent, and the clock follows the recorded
/// call times (the per-read `clock_step` is not reproduced), so the target walks through the
/// same states as the Go endpoint did.
fn fuzz_trace_seeds() -> Vec<(String, Vec<u8>)> {
    use crate::internals::fuzz::{FuzzOp, encode};

    let file = vectors!("kcp");
    let mut seeds = Vec::new();
    for case in file.cases_with_prefix("trace/") {
        let conv: u32 = case.param("conv");
        let a: TraceEp = case.field("a");
        let b: TraceEp = case.field("b");
        let a_ops: Vec<Op> = a.ops.iter().map(|l| Op::parse(l)).collect();
        let b_ops: Vec<Op> = b.ops.iter().map(|l| Op::parse(l)).collect();
        for (side, own, peer) in [("a", &a_ops, &b_ops), ("b", &b_ops, &a_ops)] {
            let mut ops = Vec::new();
            let mut len = 4;
            let mut now = 0u32;
            for op in own {
                let mut next = Vec::new();
                let t: u32 = op.num("t");
                if t != now {
                    next.push(FuzzOp::Advance {
                        ms: t.wrapping_sub(now),
                    });
                    now = t;
                }
                next.push(match op.name.as_str() {
                    "setmtu" => FuzzOp::SetMtu {
                        mtu: op.args()[0] as u16,
                    },
                    "nodelay" => {
                        let a = op.args();
                        FuzzOp::NoDelay {
                            nodelay: a[0] as i8,
                            interval: a[1] as i16,
                            resend: a[2] as i8,
                            nc: a[3] as i8,
                        }
                    }
                    "wndsize" => {
                        let a = op.args();
                        FuzzOp::WndSize {
                            snd: a[0] as i32,
                            rcv: a[1] as i32,
                        }
                    }
                    "stream" => FuzzOp::SetStream {
                        stream: op.args()[0] != 0,
                    },
                    "send" => FuzzOp::Send {
                        len: op.num::<usize>("n").min(u16::MAX as usize) as u16,
                    },
                    "input" => {
                        let data = match (op.get("hex"), op.get("src")) {
                            (Some(h), _) => hex::decode(h).expect("input hex"),
                            (None, Some(src)) => {
                                let (o, j) = src.split_once('.').expect("src op.out");
                                let o: usize = o.parse().expect("src op");
                                let j: usize = j.parse().expect("src out");
                                let mut p = peer[o].outs[j].clone();
                                if op.get("cut").is_some() {
                                    p.truncate(op.num("cut"));
                                }
                                p
                            }
                            (None, None) => panic!("input without data"),
                        };
                        FuzzOp::Input {
                            fec: op.num::<u8>("pt") == 1,
                            ack_no_delay: op.num::<u8>("and") != 0,
                            data,
                        }
                    }
                    "flush" => FuzzOp::Flush {
                        full: op.num::<u8>("ft") == 2,
                    },
                    "update" => FuzzOp::Update,
                    "check" => FuzzOp::Check,
                    "recv" => FuzzOp::Recv {
                        len: op.num::<usize>("n").min(u16::MAX as usize) as u16,
                    },
                    "peek" | "waitsnd" => FuzzOp::Query,
                    other => panic!("unknown op {other}"),
                });
                let add = encode(0, &next).len() - 4;
                if len + add > FUZZ_SEED_MAX {
                    break;
                }
                len += add;
                ops.extend(next);
            }
            let name = format!(
                "go_{}_{side}",
                case.name.trim_start_matches("trace/").replace('/', "_")
            );
            seeds.push((name, encode(conv, &ops)));
        }
    }
    seeds
}

/// The trace seeds are meaningful fuzz inputs: they run without a panic, and the target
/// accepts the Go peer's packets and receives data, as the recorded endpoint did.
#[test]
fn fuzz_trace_seeds_run() {
    let _g = SNMP_TEST_LOCK.read().unwrap_or_else(|e| e.into_inner());
    let seeds = fuzz_trace_seeds();
    assert_eq!(seeds.len(), 24);
    let mut receiving = 0;
    for (name, data) in &seeds {
        assert!(data.len() <= FUZZ_SEED_MAX, "{name}: {} bytes", data.len());
        let s = crate::internals::fuzz::kcp_input(data);
        assert!(s.ops > 10, "{name}: {s:?}");
        // (The dead-link trace's link drops everything.)
        assert!(
            s.inputs_ok > 0 || name.starts_with("go_dead_link_"),
            "{name}: {s:?}"
        );
        if s.recv_bytes > 0 {
            receiving += 1;
        }
    }
    assert!(receiving >= 18, "only {receiving} seeds receive data");
}

/// Writes the seed corpus of the `kcp_input` fuzz target (hand-made seeds and the trace seeds)
/// to `crates/kcp/fuzz/seeds/kcp_input/`. Run after changing the harness format or the traces:
/// `cargo test -p kcptun-kcp --lib write_fuzz_seeds -- --ignored`.
#[test]
#[ignore = "writes the fuzz seed corpus into the source tree"]
fn write_fuzz_seeds() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/kcp_input");
    if dir.exists() {
        std::fs::remove_dir_all(&dir).expect("remove old seeds");
    }
    std::fs::create_dir_all(&dir).expect("create seed dir");
    let hand = crate::internals::fuzz::handcrafted_seeds()
        .into_iter()
        .map(|(n, d)| (format!("hand_{n}"), d));
    for (name, data) in hand.chain(fuzz_trace_seeds()) {
        std::fs::write(dir.join(name), data).expect("write seed");
    }
}

/// The committed seed corpus (`crates/kcp/fuzz/seeds/kcp_input/`) is exactly what
/// [`write_fuzz_seeds`] generates, so a change to the harness format or to the traces cannot
/// leave stale seeds behind. The files are read at test time on purpose (this checks the
/// on-disk corpus that libFuzzer reads, not embedded test data).
#[test]
fn fuzz_seed_files_up_to_date() {
    const HINT: &str = "fuzz seeds are stale; regenerate them with \
        `cargo test -p kcptun-kcp --lib write_fuzz_seeds -- --ignored`";
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // Test executables are also run outside the source tree (tools/lab/remote-test.sh copies
    // them to lab-arm64). Only there is it acceptable to skip: when the crate's source tree is
    // present, the committed corpus must exist and match.
    if !crate_dir.join("Cargo.toml").exists() {
        eprintln!("fuzz_seed_files_up_to_date: source tree not available, skipping");
        return;
    }
    let dir = crate_dir.join("fuzz/seeds/kcp_input");
    let mut want: std::collections::BTreeMap<String, Vec<u8>> =
        crate::internals::fuzz::handcrafted_seeds()
            .into_iter()
            .map(|(n, d)| (format!("hand_{n}"), d))
            .chain(fuzz_trace_seeds())
            .collect();
    let mut have = std::collections::BTreeMap::new();
    for entry in
        std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}; {HINT}", dir.display()))
    {
        let entry = entry.expect("seed dir entry");
        let name = entry.file_name().into_string().expect("seed file name");
        if name.starts_with('.') {
            continue; // e.g. macOS .DS_Store
        }
        let data = std::fs::read(entry.path()).expect("read seed");
        have.insert(name, data);
    }
    let have_names: Vec<&String> = have.keys().collect();
    let want_names: Vec<&String> = want.keys().collect();
    assert_eq!(have_names, want_names, "seed file names differ; {HINT}");
    for (name, data) in have {
        let expected = want.remove(&name).expect("name checked above");
        assert!(data == expected, "seed {name} differs; {HINT}");
    }
}
