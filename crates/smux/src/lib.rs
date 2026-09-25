//! Rust port of [smux](https://github.com/xtaci/smux) (pinned reference: v1.5.55, plus later
//! fixes that do not change the wire format): stream multiplexing over a reliable byte stream,
//! protocol versions 1 and 2.
//!
//! Go reference source: `reference/kcptun/vendor/github.com/xtaci/smux/`.
//! Wire format summary: `docs/WIRE-FORMAT.md` §7.
//!
//! - [`frame`]: the commands, the 8-byte header codec and the `cmdUPD` payload (`frame.go`).
//! - [`mux`]: [`Config`], [`default_config`], [`verify_config`] and the [`client`] / [`server`]
//!   constructors (`mux.go`).
//! - [`conn`]: [`SmuxConn`], the byte stream a session runs over, and [`SplitConn`], the adapter
//!   for tokio streams.
//! - [`session`]: [`Session`] — open/accept, the receive and send loops, keepalive and close
//!   (`session.go`).
//! - [`stream`]: [`Stream`], the multiplexed stream (`stream.go`).
//! - [`shaper`]: the write queue that decides the order of the frames (`shaper.go`).
//! - [`error`]: [`Error`], with Go's exact texts.
#![forbid(unsafe_code)]

pub mod conn;
pub mod error;
pub mod frame;
#[cfg(any(test, feature = "internals"))]
#[doc(hidden)]
pub mod internals;
pub mod mux;
pub mod session;
pub mod shaper;
pub mod stream;

pub use conn::{SmuxConn, SplitConn};
pub use error::Error;
pub use frame::{
    CMD_FIN, CMD_NOP, CMD_PSH, CMD_SYN, CMD_UPD, Frame, HEADER_SIZE, INITIAL_PEER_WINDOW,
    RawHeader, SZ_CMD_UPD, UpdHeader,
};
pub use mux::{Config, ConfigError, client, default_config, server, verify_config};
pub use session::{
    ClassId, DEFAULT_ACCEPT_BACKLOG, MAX_SHAPER_SIZE, MIN_SHAPER_NOTIFY_SIZE, OPEN_CLOSE_TIMEOUT,
    Session,
};
pub use shaper::{ShaperQueue, WriteRequest};
pub use stream::Stream;

#[cfg(test)]
mod vector_tests;
