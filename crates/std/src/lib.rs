//! Rust port of kcptun's `std` package (Go reference `reference/kcptun/std/`): configuration,
//! Go-compatible command-line flags, logging, snappy framed compression, QPP stream wrapping,
//! multi-port addresses, SNMP logging, signal handling and bidirectional piping.
//!
//! It also holds the pieces `main()` needs that are not in Go's `std` package: the version
//! stamp ([`version`]), the tokio runtime the goroutines map onto ([`runtime`], D01) and the
//! `--pprof` endpoint ([`pprof`], D23).
#![forbid(unsafe_code)]

pub mod cli;
pub mod comp;
pub mod config;
pub mod crypt;
pub mod goaddr;
pub mod gojson;
pub mod gotime;
#[cfg(any(test, feature = "internals"))]
#[doc(hidden)]
pub mod internals;
pub mod kcpconn;
pub mod log;
pub mod mainutil;
pub mod multiport;
pub mod pipe;
pub mod pprof;
#[cfg(feature = "qpp")]
pub mod qpp;
pub mod runtime;
pub mod signal;
pub mod smuxcfg;
pub mod smuxio;
pub mod snmp;
pub mod version;

/// Go's `syscall` errno -> string table (DECISIONS D30), which every error renderer here
/// spells its errnos from. It lives in `kcptun-kcp` because `kcptun-std` depends on
/// `kcptun-tcpraw`, which needs the same table, and `kcptun-kcp` is the crate both reach.
pub use kcptun_kcp::goerrno;
pub use version::{APP_NAME, SELFBUILD, VERSION, is_selfbuild, version_string};
