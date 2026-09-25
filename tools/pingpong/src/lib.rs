//! Shared pieces of the Step 11 lab tools.
//!
//! This crate is **development-only**: nothing here is part of the kcptun port, nothing is
//! published (`publish = false`) and no release artifact contains it. The Dockerfile and the
//! release workflow build `-p kcptun-client -p kcptun-server` by name, so adding this crate to
//! the workspace only adds it to the gate (`cargo fmt`/`clippy`/`test`), which is where it
//! belongs: the soak in 11.4 runs these binaries unattended for six hours.
//!
//! Two binaries use it:
//! - `pingpong` — the workload driver that runs *through* the tunnel (`serve`, `ping`, `bulk`,
//!   `churn`);
//! - `labsample` — the `/proc` sampler that watches the tunnel processes from outside.
//!
//! Everything that parses or formats is a pure function with unit tests, so the Linux-only
//! binary (`labsample` reads `/proc`) is still fully tested on macOS.

pub mod args;
pub mod csv;
pub mod hist;
pub mod net;
pub mod proc;
pub mod proto;
pub mod rng;
pub mod timefmt;

/// The error type the binaries bubble up to `main`.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A `Result` carrying [`BoxError`].
pub type Result<T> = std::result::Result<T, BoxError>;
