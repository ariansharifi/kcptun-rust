//! Fuzz target `kcp_input` (plan step 03.6): a live KCP state machine driven by arbitrary
//! packets, sends, flushes, receives and clock advances must never panic.
//!
//! The harness and its input format live in `kcptun_kcp::internals::fuzz` (so the crate's
//! tests run the seed corpus and the crash regressions); see its module docs.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    kcptun_kcp::internals::fuzz::kcp_input(data);
});
