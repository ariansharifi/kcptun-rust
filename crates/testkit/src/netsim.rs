//! In-memory datagram link simulator driven by a virtual clock.
//!
//! A [`Link`] carries datagrams in one direction. The caller owns time: it passes the current
//! virtual time (milliseconds, e.g. [`VirtualClock::now_ms_u64`](crate::clock::VirtualClock))
//! to [`Link::send`] and [`Link::poll`], and uses [`Link::next_event_time`] to jump the clock
//! to the next delivery. Nothing here reads the wall clock or spawns tasks, so a simulation is
//! a pure function of its inputs: **the same seed and the same calls give the same delivery
//! trace**, on every platform and forever (the PRNG is this crate's own [`Pcg`]).
//!
//! Impairments, applied to each datagram in this order (similar to Linux netem):
//!
//! 1. **loss**: none, Bernoulli, or Gilbert-Elliott (two-state bursty loss);
//! 2. **queue limit**: drop-tail when the bottleneck queue already holds `queue_limit` packets;
//! 3. **bandwidth**: serialization at `bandwidth` bytes/s behind earlier packets (FIFO);
//! 4. **duplication**: with probability `duplicate` a second copy is delivered;
//! 5. per copy, **delay** plus uniform **jitter** in `[-jitter, +jitter]` (never negative), and
//!    with probability `reorder` an extra `reorder_delay` so the copy is overtaken by later
//!    packets.
//!
//! Times are kept internally in microseconds so serialization of small packets on fast links
//! is not rounded away; the API is in milliseconds, like KCP.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, VecDeque};

use crate::rng::{Pcg, SplitMix64};

const US_PER_MS: u64 = 1000;

/// Packet loss model.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum Loss {
    /// No random loss.
    #[default]
    None,
    /// Each packet is lost independently with this probability.
    Bernoulli(f64),
    /// Two-state bursty loss.
    GilbertElliott(GilbertElliott),
}

/// Gilbert-Elliott loss parameters. The chain starts in the good state. For each packet the
/// loss is decided with the current state's loss probability, then the state may change.
///
/// Mean burst length in the bad state is `1 / p_bad_to_good` packets; the stationary share of
/// bad-state packets is `p_good_to_bad / (p_good_to_bad + p_bad_to_good)`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GilbertElliott {
    /// Probability of moving from the good to the bad state after a packet.
    pub p_good_to_bad: f64,
    /// Probability of moving from the bad to the good state after a packet.
    pub p_bad_to_good: f64,
    /// Loss probability in the good state (often 0).
    pub loss_good: f64,
    /// Loss probability in the bad state (often 1).
    pub loss_bad: f64,
}

/// Configuration of a [`Link`]. Build it with [`LinkConfig::new`] and the setter methods.
#[derive(Clone, Debug, PartialEq)]
pub struct LinkConfig {
    /// PRNG seed; the only source of randomness.
    pub seed: u64,
    /// One-way propagation delay in milliseconds.
    pub delay_ms: u64,
    /// Uniform jitter bound in milliseconds (delay varies in `[delay-jitter, delay+jitter]`).
    pub jitter_ms: u64,
    /// Loss model.
    pub loss: Loss,
    /// Probability that a packet copy is held back by `reorder_delay_ms`.
    pub reorder: f64,
    /// Extra delay of reordered packets in milliseconds.
    pub reorder_delay_ms: u64,
    /// Probability that a packet is delivered twice.
    pub duplicate: f64,
    /// Bottleneck rate in bytes per second; `None` means unlimited (no serialization delay).
    pub bandwidth: Option<u64>,
    /// Maximum packets in the bottleneck queue (waiting for or undergoing serialization);
    /// further packets are dropped. Only has an effect together with `bandwidth`.
    pub queue_limit: Option<usize>,
}

impl LinkConfig {
    /// A perfect link (no delay, loss or limits) with the given seed.
    pub fn new(seed: u64) -> Self {
        LinkConfig {
            seed,
            delay_ms: 0,
            jitter_ms: 0,
            loss: Loss::None,
            reorder: 0.0,
            reorder_delay_ms: 0,
            duplicate: 0.0,
            bandwidth: None,
            queue_limit: None,
        }
    }

    /// Sets the one-way delay (ms).
    pub fn delay(mut self, ms: u64) -> Self {
        self.delay_ms = ms;
        self
    }

    /// Sets the jitter bound (ms).
    pub fn jitter(mut self, ms: u64) -> Self {
        self.jitter_ms = ms;
        self
    }

    /// Sets Bernoulli loss with probability `p`.
    pub fn loss(mut self, p: f64) -> Self {
        check_probability("loss", p);
        self.loss = if p > 0.0 {
            Loss::Bernoulli(p)
        } else {
            Loss::None
        };
        self
    }

    /// Sets Gilbert-Elliott loss.
    pub fn gilbert_elliott(mut self, ge: GilbertElliott) -> Self {
        check_probability("p_good_to_bad", ge.p_good_to_bad);
        check_probability("p_bad_to_good", ge.p_bad_to_good);
        check_probability("loss_good", ge.loss_good);
        check_probability("loss_bad", ge.loss_bad);
        self.loss = Loss::GilbertElliott(ge);
        self
    }

    /// Holds back a share `p` of packet copies by an extra `extra_delay_ms`.
    pub fn reorder(mut self, p: f64, extra_delay_ms: u64) -> Self {
        check_probability("reorder", p);
        self.reorder = p;
        self.reorder_delay_ms = extra_delay_ms;
        self
    }

    /// Duplicates a share `p` of packets.
    pub fn duplicate(mut self, p: f64) -> Self {
        check_probability("duplicate", p);
        self.duplicate = p;
        self
    }

    /// Limits the rate to `bytes_per_sec` (must be > 0).
    pub fn bandwidth(mut self, bytes_per_sec: u64) -> Self {
        assert!(bytes_per_sec > 0, "netsim: bandwidth must be positive");
        self.bandwidth = Some(bytes_per_sec);
        self
    }

    /// Limits the bottleneck queue to `packets` packets.
    pub fn queue_limit(mut self, packets: usize) -> Self {
        self.queue_limit = Some(packets);
        self
    }
}

#[track_caller]
fn check_probability(what: &str, p: f64) {
    assert!(
        (0.0..=1.0).contains(&p),
        "netsim: {what} probability {p} is not in [0, 1]"
    );
}

/// Counters of a [`Link`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkStats {
    /// Packets passed to [`Link::send`].
    pub sent: u64,
    /// Bytes passed to [`Link::send`].
    pub sent_bytes: u64,
    /// Packet copies handed out by [`Link::poll`].
    pub delivered: u64,
    /// Bytes handed out by [`Link::poll`].
    pub delivered_bytes: u64,
    /// Packets dropped by the loss model.
    pub lost: u64,
    /// Packets dropped because the queue was full.
    pub queue_dropped: u64,
    /// Extra copies created by duplication.
    pub duplicated: u64,
    /// Copies held back for reordering.
    pub reordered: u64,
}

/// A datagram handed out by [`Link::poll_timed`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    /// Scheduled delivery time in microseconds of virtual time.
    pub at_us: u64,
    /// Index of the [`Link::send`] call that produced it (starting at 0); duplicates share it.
    pub id: u64,
    /// The datagram.
    pub data: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Pending {
    at_us: u64,
    // Tie-breaker: copies scheduled for the same instant leave in scheduling order.
    order: u64,
    id: u64,
    data: Vec<u8>,
}

/// One direction of a simulated datagram link. See the [module docs](self).
#[derive(Debug)]
pub struct Link {
    cfg: LinkConfig,
    rng: Pcg,
    ge_bad: bool,
    // Serialization end times of packets still in the bottleneck queue (FIFO).
    queue: VecDeque<u64>,
    free_at_us: u64,
    heap: BinaryHeap<Reverse<Pending>>,
    next_id: u64,
    next_order: u64,
    stats: LinkStats,
}

impl Link {
    /// Creates a link with the given configuration.
    pub fn new(cfg: LinkConfig) -> Self {
        let mut sm = SplitMix64::new(cfg.seed);
        let rng = Pcg::new(sm.next_u64(), sm.next_u64());
        Link {
            cfg,
            rng,
            ge_bad: false,
            queue: VecDeque::new(),
            free_at_us: 0,
            heap: BinaryHeap::new(),
            next_id: 0,
            next_order: 0,
            stats: LinkStats::default(),
        }
    }

    /// The configuration.
    pub fn config(&self) -> &LinkConfig {
        &self.cfg
    }

    /// Counters so far.
    pub fn stats(&self) -> LinkStats {
        self.stats
    }

    /// Number of packet copies scheduled but not yet delivered.
    pub fn in_flight(&self) -> usize {
        self.heap.len()
    }

    /// Offers a datagram to the link at virtual time `now_ms`. Returns `false` if it was
    /// dropped (loss or full queue); a `true` packet may still be delayed, reordered or
    /// duplicated.
    ///
    /// `now_ms` should not decrease between calls; if it does, the earlier time is used for
    /// queue accounting and the packet is scheduled from `now_ms`.
    pub fn send(&mut self, now_ms: u64, data: &[u8]) -> bool {
        let now_us = now_ms.saturating_mul(US_PER_MS);
        let id = self.next_id;
        self.next_id += 1;
        self.stats.sent += 1;
        self.stats.sent_bytes += data.len() as u64;

        // 1. loss
        if self.lose() {
            self.stats.lost += 1;
            return false;
        }

        // 2. queue limit and 3. serialization
        let tx_end = match self.cfg.bandwidth {
            Some(bw) => {
                while self.queue.front().is_some_and(|&end| end <= now_us) {
                    self.queue.pop_front();
                }
                if self
                    .cfg
                    .queue_limit
                    .is_some_and(|limit| self.queue.len() >= limit)
                {
                    self.stats.queue_dropped += 1;
                    return false;
                }
                let bytes = data.len() as u64;
                let ser_us = bytes.saturating_mul(1_000_000).div_ceil(bw);
                let start = self.free_at_us.max(now_us);
                let end = start.saturating_add(ser_us);
                self.free_at_us = end;
                self.queue.push_back(end);
                end
            }
            None => now_us,
        };

        // 4. duplication
        let copies = if self.rng.chance(self.cfg.duplicate) {
            self.stats.duplicated += 1;
            2
        } else {
            1
        };

        // 5. delay, jitter, reordering
        for _ in 0..copies {
            let at_us = tx_end.saturating_add(self.propagation_us());
            let order = self.next_order;
            self.next_order += 1;
            self.heap.push(Reverse(Pending {
                at_us,
                order,
                id,
                data: data.to_vec(),
            }));
        }
        true
    }

    fn lose(&mut self) -> bool {
        match self.cfg.loss {
            Loss::None => false,
            Loss::Bernoulli(p) => self.rng.chance(p),
            Loss::GilbertElliott(ge) => {
                let p = if self.ge_bad {
                    ge.loss_bad
                } else {
                    ge.loss_good
                };
                let lost = self.rng.chance(p);
                let flip = if self.ge_bad {
                    ge.p_bad_to_good
                } else {
                    ge.p_good_to_bad
                };
                if self.rng.chance(flip) {
                    self.ge_bad = !self.ge_bad;
                }
                lost
            }
        }
    }

    fn propagation_us(&mut self) -> u64 {
        let delay = self.cfg.delay_ms.saturating_mul(US_PER_MS);
        let mut d = if self.cfg.jitter_ms > 0 {
            let j = self.cfg.jitter_ms.saturating_mul(US_PER_MS);
            let r = self.rng.below(j.saturating_mul(2).saturating_add(1));
            // delay + (r - j), floored at zero
            delay.saturating_add(r).saturating_sub(j)
        } else {
            delay
        };
        if self.cfg.reorder > 0.0 && self.rng.chance(self.cfg.reorder) {
            self.stats.reordered += 1;
            d = d.saturating_add(self.cfg.reorder_delay_ms.saturating_mul(US_PER_MS));
        }
        d
    }

    /// Returns the datagrams due at or before `now_ms`, in delivery order.
    pub fn poll(&mut self, now_ms: u64) -> Vec<Vec<u8>> {
        self.poll_timed(now_ms)
            .into_iter()
            .map(|d| d.data)
            .collect()
    }

    /// Like [`poll`](Self::poll), with delivery times and send ids (for traces).
    pub fn poll_timed(&mut self, now_ms: u64) -> Vec<Delivery> {
        let now_us = now_ms.saturating_mul(US_PER_MS);
        let mut out = Vec::new();
        while self.heap.peek().is_some_and(|Reverse(p)| p.at_us <= now_us) {
            let Some(Reverse(p)) = self.heap.pop() else {
                break;
            };
            self.stats.delivered += 1;
            self.stats.delivered_bytes += p.data.len() as u64;
            out.push(Delivery {
                at_us: p.at_us,
                id: p.id,
                data: p.data,
            });
        }
        out
    }

    /// The earliest virtual time (ms, rounded up) at which [`poll`](Self::poll) will return
    /// something, or `None` if nothing is in flight.
    pub fn next_event_time(&self) -> Option<u64> {
        self.heap
            .peek()
            .map(|Reverse(p)| p.at_us.div_ceil(US_PER_MS))
    }
}

/// Two independent links, one per direction, for a pair of endpoints `a` and `b`.
#[derive(Debug)]
pub struct Duplex {
    /// Carries datagrams from `a` to `b`.
    pub a_to_b: Link,
    /// Carries datagrams from `b` to `a`.
    pub b_to_a: Link,
}

impl Duplex {
    /// Both directions use `cfg`; the reverse direction gets a seed derived from `cfg.seed`
    /// so the two loss patterns are independent.
    pub fn symmetric(cfg: LinkConfig) -> Self {
        let mut back = cfg.clone();
        back.seed = SplitMix64::new(cfg.seed ^ 0x5eed_ba5e_0000_0001).next_u64();
        Duplex::new(cfg, back)
    }

    /// Uses separate configurations per direction.
    pub fn new(a_to_b: LinkConfig, b_to_a: LinkConfig) -> Self {
        Duplex {
            a_to_b: Link::new(a_to_b),
            b_to_a: Link::new(b_to_a),
        }
    }

    /// The earliest delivery time over both directions.
    pub fn next_event_time(&self) -> Option<u64> {
        match (self.a_to_b.next_event_time(), self.b_to_a.next_event_time()) {
            (Some(x), Some(y)) => Some(x.min(y)),
            (x, y) => x.or(y),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::VirtualClock;

    fn impaired(seed: u64) -> LinkConfig {
        LinkConfig::new(seed)
            .delay(40)
            .jitter(15)
            .gilbert_elliott(GilbertElliott {
                p_good_to_bad: 0.05,
                p_bad_to_good: 0.4,
                loss_good: 0.01,
                loss_bad: 0.8,
            })
            .reorder(0.1, 25)
            .duplicate(0.05)
            .bandwidth(500_000)
            .queue_limit(64)
    }

    /// Drives a link with a fixed send schedule on a virtual clock and returns the full trace.
    fn trace(cfg: LinkConfig) -> (Vec<(u64, u64, usize)>, LinkStats) {
        let clock = VirtualClock::new();
        let mut link = Link::new(cfg);
        let mut out = Vec::new();
        let mut sched = Pcg::new(99, 1); // the input schedule, independent of the link seed
        for i in 0..2000u64 {
            let len = 20 + sched.below(1400) as usize;
            let data = vec![(i % 251) as u8; len];
            link.send(clock.now_ms_u64(), &data);
            clock.advance(sched.below(3));
            for d in link.poll_timed(clock.now_ms_u64()) {
                out.push((d.at_us, d.id, d.data.len()));
            }
        }
        while let Some(t) = link.next_event_time() {
            clock.set(t);
            for d in link.poll_timed(clock.now_ms_u64()) {
                out.push((d.at_us, d.id, d.data.len()));
            }
        }
        (out, link.stats())
    }

    #[test]
    fn sim_same_seed_same_trace() {
        let (a, sa) = trace(impaired(7));
        let (b, sb) = trace(impaired(7));
        assert_eq!(a, b);
        assert_eq!(sa, sb);
        // Every impairment actually happened in this scenario.
        assert!(sa.lost > 0 && sa.queue_dropped > 0 && sa.duplicated > 0 && sa.reordered > 0);
        assert_eq!(
            sa.delivered,
            sa.sent - sa.lost - sa.queue_dropped + sa.duplicated
        );
        let (c, _) = trace(impaired(8));
        assert_ne!(a, c, "a different seed must give a different trace");
    }

    #[test]
    fn sim_trace_is_pinned() {
        // Pins the exact PRNG consumption so accidental changes to the simulator show up in
        // review (every later sim_* test depends on these traces staying stable).
        let (t, s) = trace(impaired(7));
        let text: String = t
            .iter()
            .map(|(at, id, len)| format!("{at},{id},{len};"))
            .collect();
        let digest = crate::vectors::sha256_hex(text.as_bytes());
        assert_eq!(
            (
                s.sent,
                s.lost,
                s.queue_dropped,
                s.duplicated,
                s.reordered,
                s.delivered
            ),
            PINNED_STATS,
            "stats changed"
        );
        assert_eq!(digest, PINNED_TRACE_SHA256, "trace changed");
    }

    const PINNED_STATS: (u64, u64, u64, u64, u64, u64) = (2000, 202, 297, 74, 155, 1575);
    const PINNED_TRACE_SHA256: &str =
        "d17ebf7572f1f1d112d201a744411155006ebaeb74b41702131ed8aa0b033a0b";

    #[test]
    fn perfect_link_delivers_immediately_in_order() {
        let mut l = Link::new(LinkConfig::new(1));
        assert!(l.send(5, b"a"));
        assert!(l.send(5, b"b"));
        assert_eq!(l.next_event_time(), Some(5));
        assert_eq!(l.poll(5), vec![b"a".to_vec(), b"b".to_vec()]);
        assert_eq!(l.next_event_time(), None);
        assert!(l.poll(100).is_empty());
    }

    #[test]
    fn fixed_delay() {
        let mut l = Link::new(LinkConfig::new(1).delay(30));
        l.send(10, b"x");
        assert!(l.poll(39).is_empty());
        assert_eq!(l.in_flight(), 1);
        assert_eq!(l.next_event_time(), Some(40));
        assert_eq!(l.poll(40), vec![b"x".to_vec()]);
    }

    #[test]
    fn jitter_stays_in_bounds_and_reorders() {
        let mut l = Link::new(LinkConfig::new(3).delay(50).jitter(20));
        for i in 0..1000u64 {
            l.send(i, &i.to_le_bytes());
        }
        let d = l.poll_timed(u64::MAX / 1000);
        assert_eq!(d.len(), 1000);
        let mut out_of_order = 0;
        for (k, x) in d.iter().enumerate() {
            let sent_us = x.id * 1000;
            let prop = x.at_us - sent_us;
            assert!((30_000..=70_000).contains(&prop), "propagation {prop}");
            if k > 0 && d[k - 1].id > x.id {
                out_of_order += 1;
            }
        }
        assert!(out_of_order > 0);
    }

    #[test]
    fn jitter_never_goes_negative() {
        let mut l = Link::new(LinkConfig::new(4).delay(2).jitter(10));
        for _ in 0..200 {
            l.send(100, b"p");
        }
        for d in l.poll_timed(1000) {
            assert!(d.at_us >= 100_000);
        }
    }

    #[test]
    fn bernoulli_loss_rate() {
        let mut l = Link::new(LinkConfig::new(5).loss(0.2));
        let ok = (0..10_000).filter(|_| l.send(0, b"p")).count();
        assert!((7_700..=8_300).contains(&ok), "delivered {ok}");
        assert_eq!(l.stats().lost, 10_000 - ok as u64);
        let mut none = Link::new(LinkConfig::new(5).loss(0.0));
        assert!((0..1000).all(|_| none.send(0, b"p")));
        let mut all = Link::new(LinkConfig::new(5).loss(1.0));
        assert!((0..1000).all(|_| !all.send(0, b"p")));
    }

    fn mean_burst(losses: &[bool]) -> f64 {
        let mut bursts = 0usize;
        let mut lost = 0usize;
        for (i, &l) in losses.iter().enumerate() {
            if l {
                lost += 1;
                if i == 0 || !losses[i - 1] {
                    bursts += 1;
                }
            }
        }
        lost as f64 / bursts.max(1) as f64
    }

    #[test]
    fn gilbert_elliott_loss_is_bursty() {
        let ge = GilbertElliott {
            p_good_to_bad: 0.02,
            p_bad_to_good: 0.25,
            loss_good: 0.0,
            loss_bad: 1.0,
        };
        let mut l = Link::new(LinkConfig::new(6).gilbert_elliott(ge));
        let losses: Vec<bool> = (0..50_000).map(|_| !l.send(0, b"p")).collect();
        let rate = losses.iter().filter(|&&x| x).count() as f64 / losses.len() as f64;
        // Stationary bad share 0.02 / 0.27 = 7.4%; mean burst 1 / 0.25 = 4 packets.
        assert!((0.055..0.095).contains(&rate), "rate {rate}");
        let burst = mean_burst(&losses);
        assert!((3.0..5.0).contains(&burst), "mean burst {burst}");

        let mut b = Link::new(LinkConfig::new(6).loss(rate));
        let bern: Vec<bool> = (0..50_000).map(|_| !b.send(0, b"p")).collect();
        assert!(mean_burst(&bern) < 1.3);
    }

    #[test]
    fn bandwidth_serializes_back_to_back() {
        // 1000 bytes at 100_000 B/s = 10 ms each.
        let mut l = Link::new(LinkConfig::new(7).delay(5).bandwidth(100_000));
        for _ in 0..3 {
            l.send(0, &[0u8; 1000]);
        }
        let times: Vec<u64> = l.poll_timed(1000).iter().map(|d| d.at_us).collect();
        assert_eq!(times, vec![15_000, 25_000, 35_000]);
        // After the queue drains, a new packet starts at its send time.
        l.send(100, &[0u8; 1000]);
        assert_eq!(l.next_event_time(), Some(115));
    }

    #[test]
    fn bandwidth_keeps_sub_millisecond_precision() {
        // 100 bytes at 1 MB/s = 100 us each: 10 packets finish at 1 ms, not 10 ms.
        let mut l = Link::new(LinkConfig::new(8).bandwidth(1_000_000));
        for _ in 0..10 {
            l.send(0, &[0u8; 100]);
        }
        assert_eq!(l.poll(1).len(), 10);
    }

    #[test]
    fn queue_limit_drops_tail() {
        let mut l = Link::new(LinkConfig::new(9).bandwidth(1000).queue_limit(4));
        let accepted: Vec<bool> = (0..6).map(|_| l.send(0, &[0u8; 100])).collect();
        assert_eq!(accepted, vec![true, true, true, true, false, false]);
        assert_eq!(l.stats().queue_dropped, 2);
        // First packet finishes serializing at 100 ms, freeing one slot.
        assert!(l.send(100, &[0u8; 100]));
        assert!(!l.send(100, &[0u8; 100]));
    }

    #[test]
    fn duplication_delivers_two_copies() {
        let mut l = Link::new(LinkConfig::new(10).duplicate(1.0));
        l.send(0, b"d");
        let d = l.poll_timed(0);
        assert_eq!(d.len(), 2);
        assert!(d.iter().all(|x| x.id == 0 && x.data == b"d"));
        assert_eq!(l.stats().duplicated, 1);
    }

    #[test]
    fn reorder_holds_packets_back() {
        let mut l = Link::new(LinkConfig::new(11).delay(10).reorder(0.3, 50));
        for i in 0..100u64 {
            l.send(i, &i.to_le_bytes());
        }
        let d = l.poll_timed(10_000);
        let ids: Vec<u64> = d.iter().map(|x| x.id).collect();
        assert!(ids.windows(2).any(|w| w[0] > w[1]));
        let held = d.iter().filter(|x| x.at_us - x.id * 1000 == 60_000).count() as u64;
        assert_eq!(held, l.stats().reordered);
        assert!(held > 10);
    }

    #[test]
    fn duplex_directions_are_independent() {
        let mut d = Duplex::symmetric(LinkConfig::new(12).loss(0.5).delay(10));
        let ab: Vec<bool> = (0..64).map(|_| d.a_to_b.send(0, b"x")).collect();
        let ba: Vec<bool> = (0..64).map(|_| d.b_to_a.send(0, b"x")).collect();
        assert_ne!(ab, ba);
        assert_eq!(d.next_event_time(), Some(10));
    }

    #[test]
    #[should_panic(expected = "not in [0, 1]")]
    fn invalid_probability_panics() {
        let _ = LinkConfig::new(0).loss(1.5);
    }
}
