//! Go <-> Rust interoperability test runner.
//!
//! The library holds the harness; the tests live in `tests/` and are `#[ignore]` by default
//! because they need the Go reference binaries and interop peers built by
//! `tools/fetch-reference.sh` (and, from Step 05 on, our own release binaries):
//!
//! ```sh
//! cargo test -p kcptun-interop-tests -- --ignored            # laptop
//! tools/lab/deploy.sh --go                                   # lab-arm64 (kg-* binaries)
//! tools/lab/remote-test.sh -p kcptun-interop-tests -- --ignored
//! ```
//!
//! The two end-to-end suites are the exception: `tests/e2e.rs` and `tests/e2e_slow.rs` (step
//! 09.3) are Rust↔Rust only and need nothing but our own binaries.
//!
//! ```sh
//! cargo build --release -p kcptun-client -p kcptun-server
//! cargo test -p kcptun-interop-tests --test e2e -- --ignored        # ~15 s
//! cargo test -p kcptun-interop-tests --test e2e_slow -- --ignored   # ~70 s, 400 MB of traffic
//! ```
//!
//! | Module | Purpose |
//! |---|---|
//! | [`bins`] | locate Go (`KCPTUN_GO_BIN_DIR`) and Rust (`KCPTUN_RS_BIN_DIR`) binaries |
//! | [`matrix`] | [`Case`] (one kcptun configuration, Go-style flags) and pairwise [`Matrix`] expansion |
//! | [`clidiff`] | the startup-log and CLI differential of step 09.5: one command line, both implementations, compared |
//! | [`e2e`] | spawn a real `kcptun-client`/`kcptun-server` pair (either implementation) and talk through it (step 09.3) |
//! | [`interop_matrix`] | the Go<->Rust matrix of step 09.4: cases, workload, expectations and the report |
//! | [`signals`] | step 09.6: signals, the `SIGUSR1` SNMP line, `-snmplog` CSV and exit behaviour (Unix only) |
//! | [`kcpecho`] | drive the `kcpecho` Go peer (raw kcp-go echo) |
//! | [`kcp`](mod@kcp) | [`KcpCase`] plus the Rust echo server and client that face that peer |
//! | [`echo_bench`] | loopback echo throughput and CPU of Rust↔Rust against Go↔Go (step 05.9) |
//! | [`smuxecho`] | drive the `smuxecho` Go peer, and the Rust smux client/echo server |
//!
//! The crate also builds one binary, `kcptun-smuxecho` (`src/bin/smuxecho.rs`): the Rust
//! counterpart of the Go `smuxecho` peer, with the same flags, the same `listening on:` line
//! and the same JSON report, plus an `idle` mode for per-stream memory. It is what makes a
//! Rust<->Rust benchmark run (sub-step 06.6, step 12) the same shape as a Go<->Go one.
//!
//! Processes are spawned through `kcptun_testkit::proc` (captured logs, kill on drop) and
//! fixed ports come from `kcptun_testkit::ports` (`[22000, 29000)`, never below 4000).
#![forbid(unsafe_code)]

pub mod bins;
pub mod clidiff;
pub mod e2e;
pub mod echo_bench;
pub mod interop_matrix;
pub mod kcp;
pub mod kcpecho;
pub mod matrix;
/// Signals are excluded from Go's build on Windows (`std/signal.go` is
/// `//go:build linux || darwin || freebsd`), and so is this module.
#[cfg(unix)]
pub mod signals;
pub mod smuxecho;

pub use bins::{BinNotFound, Impl, bin, go_bin, rust_bin};
pub use e2e::{LocalEndpoint, LocalStream, ResponderServer, Tunnel, TunnelBuilder};
pub use echo_bench::{Measurement, Profile, measure_go, measure_rust, profiles};
pub use kcp::{
    CRYPT_MODES, KcpCase, RustClientReport, RustClientRun, RustEchoServer, run_rust_client,
};
pub use matrix::{Case, Dim, Matrix, Side};
