//! Fuzz target `tcp_segment` (plan step 10.1): arbitrary bytes are handed to the segment codec
//! as if a raw socket had just delivered them. Nothing may panic, and the parser may never
//! point outside the buffer it was given.
//!
//! The harness and its input format live in `kcptun_tcpraw::internals::fuzz` (so the crate's own
//! tests run the seeds); see its module docs.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    kcptun_tcpraw::internals::fuzz::tcp_segment(data);
});
