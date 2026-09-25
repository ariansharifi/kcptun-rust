//! The TCP fingerprint tcpraw's segments imitate: window, options and TTL of a Linux stack.
//!
//! Go reference: `tcpraw@v1.2.32 fingerprints.go`, with the post-pin timestamp fix from
//! `tcpraw@cbf9635` (DECISIONS **V10**, see [`FingerPrint::linux`]).

use std::sync::LazyLock;
use std::time::Instant;

use rand::RngExt as _;

use crate::tcp::{OPTION_KIND_NOP, OPTION_KIND_TIMESTAMPS, TcpOption};

/// Which stack a [`FingerPrint`] imitates. Go defines exactly one.
// Go: tcpraw@v1.2.32 fingerprints.go:FingerPrintType
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum FingerPrintType {
    /// A Linux TCP stack.
    #[default]
    Linux,
}

/// The header fields every crafted segment is filled with.
// Go: tcpraw@v1.2.32 fingerprints.go:fingerPrint
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FingerPrint {
    /// Which stack this imitates; selects how [`make_option`](FingerPrint::make_option) fills
    /// the options.
    pub kind: FingerPrintType,
    /// Receive window advertised in every segment.
    pub window: u16,
    /// The option list, serialised in this order.
    pub options: Vec<TcpOption>,
    /// The TTL a real segment of this stack would carry. tcpraw sets TTL 1 on the *kernel's*
    /// socket instead (so the kernel's own traffic is dropped by the iptables rule) and never
    /// reads this field; it is kept because the fingerprint is Go's.
    pub ttl: u16,
}

impl FingerPrint {
    /// The Linux fingerprint: window 65535 and the options `[NOP, NOP, Timestamps]`.
    ///
    /// Each call returns a fresh copy, matching Go's `fingerPrintLinux.Clone()` in `Dial` and
    /// `Listen`: the timestamp option's data is rewritten per segment, so connections must not
    /// share it.
    ///
    /// **Deviation V10.** Pinned tcpraw v1.2.32 builds the timestamp option with **10** bytes of
    /// option data, which gopacket serialises as a length-**12** option — malformed, and it pads
    /// the header out to 36 bytes (data offset 9). Upstream `cbf9635` fixed this to the standard
    /// 8 bytes of data (length 10, 32-byte header, data offset 8), which is what a real Linux
    /// stack sends and therefore what a fake-TCP fingerprint should send. The port emits the
    /// fixed form. Receivers locate the payload through the data offset, so both Go versions
    /// interoperate with it; the parser additionally accepts both option lengths
    /// (`Segment::timestamps`).
    // Go: tcpraw@v1.2.32 fingerprints.go:fingerPrintLinux (+ .Clone())
    // Go (post-pin fix, V10): tcpraw@cbf9635 fingerprints.go:fingerPrintLinux
    pub fn linux() -> FingerPrint {
        FingerPrint {
            kind: FingerPrintType::Linux,
            window: 65535,
            options: vec![
                TcpOption::single(OPTION_KIND_NOP),
                TcpOption::single(OPTION_KIND_NOP),
                // Go writes `{8, 10, make([]byte, 8)}`: the declared length stays 10 (the RFC
                // value) while the data is 8 bytes. Serialisation recomputes it anyway.
                TcpOption {
                    kind: OPTION_KIND_TIMESTAMPS,
                    length: 10,
                    data: vec![0; TS_OPTION_DATA_LEN],
                },
            ],
            ttl: 64,
        }
    }

    /// Refreshes the timestamp option in place: TSval from [`uptime_ms`], TSecr from the last
    /// TSval this flow saw from the peer.
    ///
    /// Like Go, the first timestamp option with the expected data length is filled and the walk
    /// stops; anything else is left alone.
    // Go: tcpraw@v1.2.32 fingerprints.go:makeOption()
    pub fn make_option(&mut self, ts_ecr: u32) {
        self.make_option_with(uptime_ms(), ts_ecr);
    }

    /// [`make_option`](Self::make_option) with an explicit TSval, so tests (and the golden
    /// vectors of Step 10.5) do not depend on the clock.
    pub fn make_option_with(&mut self, ts_val: u32, ts_ecr: u32) {
        match self.kind {
            FingerPrintType::Linux => {
                for o in &mut self.options {
                    if o.kind == OPTION_KIND_TIMESTAMPS && o.data.len() == TS_OPTION_DATA_LEN {
                        o.data[..4].copy_from_slice(&ts_val.to_be_bytes());
                        o.data[4..8].copy_from_slice(&ts_ecr.to_be_bytes());
                        break;
                    }
                }
            }
        }
    }
}

impl Default for FingerPrint {
    fn default() -> FingerPrint {
        FingerPrint::linux()
    }
}

/// Bytes of option data in the timestamp option this port emits: TSval and TSecr, i.e. the
/// standard length-10 option (Deviation V10; pinned Go uses 10 bytes here).
// Go (post-pin fix, V10): tcpraw@cbf9635 fingerprints.go:fingerPrintLinux
pub const TS_OPTION_DATA_LEN: usize = 8;

/// The simulated boot instant: when the process started, plus a random offset of 0..720 whole
/// hours, so TSval does not restart near zero and does not leak the real start time.
// Go (post-pin fix, V10): tcpraw@cbf9635 fingerprints.go:init()
static BOOT: LazyLock<(Instant, u64)> = LazyLock::new(|| {
    // Go: `bootTime = time.Now().Add(time.Duration(-rand.Intn(30*24)) * time.Hour)`
    let hours: u64 = rand::rng().random_range(0..30 * 24);
    (Instant::now(), hours * 3_600_000)
});

/// Milliseconds since the simulated boot, truncated to 32 bits: the TSval of every segment.
///
/// Go computes `uint32(time.Since(bootTime).Milliseconds())`. Wrapping every 49.7 days is
/// exactly what a real RFC 7323 timestamp does, and nothing interprets the value.
// Go (post-pin fix, V10): tcpraw@cbf9635 fingerprints.go:makeOption()
pub fn uptime_ms() -> u32 {
    let (start, offset_ms) = *BOOT;
    offset_ms.wrapping_add(start.elapsed().as_millis() as u64) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The V10 fingerprint: window 65535, `[NOP, NOP, TS(8 bytes of data)]`, TTL 64. The
    /// 8-byte data is what makes the serialised header 32 bytes instead of pinned Go's 36.
    #[test]
    fn linux_fingerprint_matches_upstream_fix() {
        let fp = FingerPrint::linux();
        assert_eq!(fp.kind, FingerPrintType::Linux);
        assert_eq!(fp.window, 65535);
        assert_eq!(fp.ttl, 64);
        assert_eq!(fp.options.len(), 3);
        assert_eq!(fp.options[0], TcpOption::single(OPTION_KIND_NOP));
        assert_eq!(fp.options[1], TcpOption::single(OPTION_KIND_NOP));
        assert_eq!(fp.options[2].kind, OPTION_KIND_TIMESTAMPS);
        assert_eq!(fp.options[2].length, 10);
        assert_eq!(fp.options[2].data, vec![0u8; 8]);
        // Option area: 1 + 1 + (2 + 8) = 12 bytes, a multiple of 4, so no padding and a
        // 32-byte header.
        let wire: usize = 1 + 1 + 2 + fp.options[2].data.len();
        assert_eq!(wire % 4, 0);
        assert_eq!((20 + wire) / 4, 8);
    }

    /// `makeOption` writes TSval then TSecr, big-endian, and leaves the NOPs untouched.
    #[test]
    fn make_option_writes_tsval_and_tsecr() {
        let mut fp = FingerPrint::linux();
        fp.make_option_with(0x0bad_f00d, 0xdead_beef);
        assert_eq!(
            fp.options[2].data,
            vec![0x0b, 0xad, 0xf0, 0x0d, 0xde, 0xad, 0xbe, 0xef]
        );
        assert!(fp.options[0].data.is_empty());
        assert!(fp.options[1].data.is_empty());

        // Overwritten in place on the next segment, no reallocation of the option list.
        fp.make_option_with(1, 2);
        assert_eq!(fp.options[2].data, vec![0, 0, 0, 1, 0, 0, 0, 2]);
        assert_eq!(fp.options.len(), 3);
    }

    /// A fingerprint whose timestamp option has a different data length is left alone, as Go's
    /// `len(options[i].OptionData) == 8` guard does.
    #[test]
    fn make_option_ignores_other_option_lengths() {
        let mut fp = FingerPrint::linux();
        fp.options[2].data = vec![0xff; 10];
        fp.make_option_with(1, 2);
        assert_eq!(fp.options[2].data, vec![0xff; 10]);
    }

    /// Each call hands out an independent copy (Go's `Clone()`), so two connections cannot
    /// overwrite each other's timestamps.
    #[test]
    fn linux_fingerprint_is_cloned_per_connection() {
        let mut a = FingerPrint::linux();
        let b = FingerPrint::linux();
        a.make_option_with(7, 9);
        assert_eq!(b.options[2].data, vec![0u8; 8]);
    }

    /// The TSval clock advances and never panics; the random boot offset is at most 720 hours,
    /// so the value stays a plain wrapping millisecond counter.
    #[test]
    fn uptime_ms_is_monotonic_within_a_process() {
        let a = uptime_ms();
        let b = uptime_ms();
        assert!(b.wrapping_sub(a) < 60_000, "a={a} b={b}");
    }
}
