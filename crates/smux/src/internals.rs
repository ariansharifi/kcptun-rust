//! Hidden access to smux internals for the fuzz targets (plan step 06.5).
//!
//! Only compiled with the `internals` Cargo feature (and in this crate's own tests). It is
//! **not** part of the public API and has no stability guarantee: the cargo-fuzz crate
//! (`fuzz/`) is a separate crate, so the harness it drives has to live somewhere it can reach,
//! and this crate's tests run the same harness over the committed seeds.
#![forbid(unsafe_code)]

pub mod fuzz;
