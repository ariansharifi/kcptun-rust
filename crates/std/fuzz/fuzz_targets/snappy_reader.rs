//! Fuzz target `snappy_reader` (plan step 07.1): an arbitrary byte string is read as a framed
//! snappy stream, as if a peer had sent it through the KCP session under `CompStream`. Nothing
//! may panic — corrupt input, unsupported input and the end of the stream are all fine outcomes.
//!
//! The harness and its input format live in `kcptun_std::internals::fuzz` (so the crate's own
//! tests run the seeds); see its module docs.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    kcptun_std::internals::fuzz::snappy_reader(data);
});
