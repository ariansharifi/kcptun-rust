//! Rust port of [qpp](https://github.com/xtaci/qpp) v1.1.25: Quantum Permutation Pad.
//!
//! This crate is licensed under the GNU General Public License v3.0 because it is derived from
//! the GPL-3.0 `xtaci/qpp` library. See `LICENSE` in this directory and `NOTICE.md` at the
//! repository root.
//!
//! Go reference source: `reference/kcptun/vendor/github.com/xtaci/qpp/`.
//!
//! # What it does
//!
//! A [`QuantumPermutationPad`] holds `num_pads` permutations of the 256 byte values (and their
//! inverses). A [`Rand`] — an `xoshiro256**` generator seeded from the same key — selects one
//! pad per eight bytes of *stream position* and supplies a one-time-pad byte:
//!
//! ```text
//! encrypt byte at stream position p:  c = pads[k][b ^ (r >> 8*(p mod 8)) as u8]
//! decrypt:                            b = rpads[k][c] ^ (r >> 8*(p mod 8)) as u8
//! ```
//!
//! where `r` is the generator's current output and `k = (r as u16) % num_pads`. Because the
//! transform depends only on the position in the stream, encrypting a stream in one call or in
//! a thousand arbitrary pieces produces the same bytes, which is what lets kcptun apply it to a
//! smux stream whose reads and writes are chopped up by the network.
//!
//! ```
//! use kcptun_qpp::{QuantumPermutationPad, create_prng};
//!
//! let qpp = QuantumPermutationPad::new(b"it's a secrect", 61);
//! let (mut w, mut r) = (create_prng(b"it's a secrect"), create_prng(b"it's a secrect"));
//! let mut data = b"hello quantum world".to_vec();
//! qpp.encrypt_with_prng(&mut data[..7], &mut w);
//! qpp.encrypt_with_prng(&mut data[7..], &mut w);
//! qpp.decrypt_with_prng(&mut data, &mut r);
//! assert_eq!(data, b"hello quantum world");
//! ```
#![forbid(unsafe_code)]

mod bigint;
mod prng;
mod qpp;

pub use prng::{Rand, create_prng, fast_prng, xoshiro256ss};
pub use qpp::{
    CHUNK_DERIVE_LOOPS, CHUNK_DERIVE_SALT, MATRIX_BYTES, NATIVE_BYTE_LENGTH, PAD_SWITCH,
    PBKDF2_LOOPS, PM_SELECTOR_IDENTIFIER, PRNG_SALT, QUBITS, QuantumPermutationPad, SHUFFLE_SALT,
    qpp_minimum_pads, qpp_minimum_seed_length, seed_to_chunks,
};

#[cfg(test)]
#[path = "vector_tests.rs"]
mod vector_tests;
