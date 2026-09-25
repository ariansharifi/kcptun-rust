//! Fuzz target `smux_recv` (plan step 06.5): an arbitrary byte string is fed to a live smux
//! session as if the peer had sent it. Nothing may panic: a protocol error, a socket error or
//! the end of the stream are all fine outcomes.
//!
//! The harness and its input format live in `kcptun_smux::internals::fuzz` (so the crate's own
//! tests run the seeds); see its module docs.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    kcptun_smux::internals::fuzz::smux_recv(data);
});
