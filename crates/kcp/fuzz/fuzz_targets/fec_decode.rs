//! Fuzz target `fec_decode` (plan step 04.6): a FEC decoder with fuzzer-chosen `(ds, ps)` fed
//! arbitrary packets, crafted FEC headers and an honest sender's (possibly lost, truncated,
//! duplicated or reordered) packets must never panic.
//!
//! The harness and its input format live in `kcptun_kcp::internals::fec_fuzz` (so the crate's
//! tests run the seeds and the crash regressions); see its module docs.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    kcptun_kcp::internals::fec_fuzz::fec_decode(data);
});
