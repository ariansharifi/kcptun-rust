//! FEC parameter auto-tuning: detects the period of data and parity shards in the received FEC
//! stream, so a decoder can follow a peer whose `(dataShards, parityShards)` differ from its own
//! (port of kcp-go `autotune.go`).
//!
//! The decoder samples every received FEC packet (bit `true` = data shard, `false` = parity
//! shard, tagged with its seqid) into a fixed ring of the latest [`MAX_AUTO_TUNE_SAMPLES`]
//! samples. [`AutoTune::find_period`] sorts a copy of the ring by seqid (wrapping comparison)
//! and measures the width of the first complete pulse of the requested bit in a run of
//! consecutive seqids: for `true` that is the data shard count, for `false` the parity count.
//!
//! The sort is Go's `sort.Slice` ([`crate::gosort`]), not a Rust standard sort: seqids come from
//! the network, may repeat (duplicate packets) or span more than 2^31 (garbage), and then only
//! Go's exact algorithm yields Go's order (and a Rust sort could panic). Seqids of one real FEC
//! stream are distinct and close together, so for them any correct sort gives the same order.
#![forbid(unsafe_code)]

use crate::gosort;
use crate::kcp::_itimediff;

/// Size of the sample ring.
// Go: kcp-go/v5@v5.6.66 autotune.go:maxAutoTuneSamples
pub const MAX_AUTO_TUNE_SAMPLES: usize = 258; // 256 + 2 extra for edge detection

/// One sample: a 0/1 signal with its sequence number.
// Go: kcp-go/v5@v5.6.66 autotune.go:pulse
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pulse {
    /// The signal (FEC: `true` = data shard, `false` = parity shard).
    pub bit: bool,
    /// Sequence number of the signal (FEC seqid).
    pub seq: u32,
}

impl Pulse {
    const ZERO: Pulse = Pulse { bit: false, seq: 0 };
}

/// Detects pulses in a signal, using a fixed-size ring of the latest samples (no allocation).
// Go: kcp-go/v5@v5.6.66 autotune.go:autoTune
#[derive(Clone, Debug)]
pub struct AutoTune {
    /// The sample ring.
    pulses: [Pulse; MAX_AUTO_TUNE_SAMPLES],
    /// Reusable copy of the ring for sorting.
    sort_cache: [Pulse; MAX_AUTO_TUNE_SAMPLES],
    /// Index of the oldest sample.
    head: usize,
    /// Next write position.
    tail: usize,
    /// Number of samples in the ring.
    count: usize,
}

impl Default for AutoTune {
    /// An empty detector (Go's zero value).
    fn default() -> Self {
        Self::new()
    }
}

impl AutoTune {
    /// An empty detector (Go's zero value `autoTune{}`).
    pub const fn new() -> Self {
        AutoTune {
            pulses: [Pulse::ZERO; MAX_AUTO_TUNE_SAMPLES],
            sort_cache: [Pulse::ZERO; MAX_AUTO_TUNE_SAMPLES],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Adds a sample; when the ring is full the oldest sample is discarded.
    // Go: kcp-go/v5@v5.6.66 autotune.go:autoTune.Sample()
    pub fn sample(&mut self, bit: bool, seq: u32) {
        // Write to current tail position
        self.pulses[self.tail] = Pulse { bit, seq };
        self.tail = (self.tail + 1) % MAX_AUTO_TUNE_SAMPLES;

        if self.count < MAX_AUTO_TUNE_SAMPLES {
            self.count += 1;
        } else {
            // Buffer is full, advance head (discard oldest)
            self.head = (self.head + 1) % MAX_AUTO_TUNE_SAMPLES;
        }
    }

    /// Finds the period of the given signal: the width of the first complete pulse of `bit`
    /// (from the edge where the signal becomes `bit` to the edge where it stops being `bit`) in
    /// the samples sorted by seqid. Returns -1 if there are fewer than 3 samples, if either edge
    /// is missing, or if the seqids before the right edge are not consecutive.
    ///
    /// ```text
    ///   Signal Level
    ///       |
    /// 1.0   |                 _____           _____
    ///       |                |     |         |     |
    /// 0.5   |      _____     |     |   _____ |     |   _____
    ///       |     |     |    |     |  |     ||     |  |     |
    /// 0.0 __|_____|     |____|     |__|     ||     |__|     |_____
    ///       |
    ///       |-----------------------------------------------------> Time
    ///            A     B    C     D  E     F     G  H     I
    /// ```
    // Go: kcp-go/v5@v5.6.66 autotune.go:autoTune.FindPeriod()
    pub fn find_period(&mut self, bit: bool) -> i32 {
        // Need at least 3 samples to detect a period (rising and falling edges)
        if self.count < 3 {
            return -1;
        }

        // Copy elements from ring buffer to sortCache for sorting and analysis.
        for i in 0..self.count {
            let idx = (self.head + i) % MAX_AUTO_TUNE_SAMPLES;
            self.sort_cache[i] = self.pulses[idx];
        }

        // Create a slice view over the cache for sorting
        let sorted = &mut self.sort_cache[..self.count];

        // Sort the copied data by sequence number (seq) to ensure linear order for period
        // calculation. Go: sort.Slice (unstable pdqsort), reproduced exactly by gosort::slice.
        gosort::slice(sorted, |a, b| _itimediff(a.seq, b.seq) < 0);
        let sorted = &*sorted;

        // left edge
        let mut left_edge: Option<usize> = None; // Go: leftEdge := -1
        let mut last_pulse = sorted[0];
        for (idx, &p) in sorted.iter().enumerate().skip(1) {
            if last_pulse.seq.wrapping_add(1) == p.seq {
                // continuous sequence
                if last_pulse.bit != bit && p.bit == bit {
                    // edge found
                    left_edge = Some(idx); // mark left edge(the changed bit position)
                    break;
                }
            } else {
                return -1;
            }
            last_pulse = p;
        }

        // no left edge found
        let Some(left_edge) = left_edge else {
            return -1;
        };

        // right edge
        let mut right_edge: Option<usize> = None; // Go: rightEdge := -1
        let mut last_pulse = sorted[left_edge];
        for (idx, &p) in sorted.iter().enumerate().skip(left_edge + 1) {
            if last_pulse.seq.wrapping_add(1) == p.seq {
                if last_pulse.bit == bit && p.bit != bit {
                    right_edge = Some(idx);
                    break;
                }
            } else {
                return -1;
            }
            last_pulse = p;
        }

        // no right edge found
        let Some(right_edge) = right_edge else {
            return -1;
        };

        // At most MAX_AUTO_TUNE_SAMPLES - 1, so the conversion is exact.
        (right_edge - left_edge) as i32
    }

    /// Number of samples in the ring.
    pub fn count(&self) -> usize {
        self.count
    }
}

#[cfg(test)]
mod tests;
