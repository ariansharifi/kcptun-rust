//! Hidden access to KCP internals for the benchmarks and the fuzz targets (plan steps 03.6 and
//! 04.6).
//!
//! Only compiled with the `internals` Cargo feature (and in this crate's own tests). It is **not**
//! part of the public API and has no stability guarantee: the criterion benches
//! (`benches/kcp.rs`, which enable the feature through a dev-dependency on this crate) and the
//! cargo-fuzz crate (`fuzz/`) are separate crates, and they need what Go's own benchmarks reach
//! as package-internal code: the unexported `flush()` and the `snd_buf` field.
#![forbid(unsafe_code)]

pub mod fec_fuzz;
pub mod fuzz;

use crate::clock::Clock;
use crate::kcp::{FlushScan, FlushType, Kcp, Output};
use crate::ringbuffer::RingBuffer;
use crate::segment::Segment;

/// Calls the crate-private [`Kcp::flush`] (Go: the unexported `KCP.flush`, which kcp-go's
/// `BenchmarkFlush` and `sess.go` call directly).
pub fn flush<O: Output, C: Clock>(kcp: &mut Kcp<O, C>, flush_type: FlushType) -> u32 {
    kcp.flush(flush_type)
}

/// The send buffer of `kcp` (Go: `kcp.snd_buf`, which `BenchmarkFlush` replaces with a full ring
/// of synthetic segments).
///
/// Handing the ring out makes everything `flush` remembers about it (Decision D29) stale, so
/// this resets that summary: the next full flush scans every segment, as it does on a new `Kcp`.
pub fn snd_buf_mut<O, C>(kcp: &mut Kcp<O, C>) -> &mut RingBuffer<Segment> {
    kcp.flush_scan = FlushScan {
        enabled: kcp.flush_scan.enabled,
        ..FlushScan::default()
    };
    &mut kcp.snd_buf
}

/// Turns the `snd_buf` optimisations of plan step 12.2 on (the default) or off: `flush`
/// skipping the part of the ring it has already scanned (Decision D29) and the ACK path
/// addressing a segment by its sequence number (Decision D31). Off is the naive,
/// line-by-line port of kcp-go (the permanent oracle of DECISIONS D25) and the "before"
/// side of the 12.2c and 12.2d benchmarks.
pub fn set_fast_path<O, C>(kcp: &mut Kcp<O, C>, enabled: bool) {
    kcp.flush_scan.enabled = enabled;
}

/// Sets stream mode (Go: `UDPSession.SetStreamMode` writes `kcp.stream` directly; the session
/// of Step 05 lives in this crate and will do the same).
pub fn set_stream<O, C>(kcp: &mut Kcp<O, C>, stream: bool) {
    kcp.stream = i32::from(stream);
}
