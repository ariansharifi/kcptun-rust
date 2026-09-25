//! Rust port of [kcp-go](https://github.com/xtaci/kcp-go) (pinned reference: v5.6.66, plus later
//! fixes that do not change the wire format).
//!
//! Provides the KCP ARQ state machine, forward error correction (Reed-Solomon), packet
//! encryption, and the UDP session and listener used by kcptun.
//!
//! Go reference source: `reference/kcptun/vendor/github.com/xtaci/kcp-go/v5/`.
//! Wire format summary: `docs/WIRE-FORMAT.md`.
//!
//! `unsafe` is only permitted in the batched UDP I/O and SIMD modules, and every block needs a
//! `// SAFETY:` comment.

pub mod addr;
pub mod autotune;
pub mod bufpool;
pub mod clock;
pub mod crypt;
pub mod entropy;
pub mod error_slot;
pub mod fec;
pub mod goerrno;
pub(crate) mod gosort;
pub mod heap;
#[cfg(any(test, feature = "internals"))]
#[doc(hidden)]
pub mod internals;
pub mod io;
pub mod kcp;
pub mod listener;
pub mod memory;
pub mod packet_conn;
pub mod rate;
pub mod ringbuffer;
pub mod rs;
pub mod segment;
pub mod session;
pub mod snmp;
pub mod tx;

pub use bufpool::{BufferPool, PacketBuf};
pub use clock::{Clock, SystemClock};
pub use error_slot::ErrorSlot;
pub use io::UdpPacketConn;
pub use listener::{ACCEPT_BACKLOG, Listener, ListenerConfig, Monitor};
pub use packet_conn::{BATCH_SIZE, PacketConn, RecvBatch, RecvSlot, TxMsg};
pub use rate::Limiter;
pub use session::{ReadLoop, SessionConfig, SessionError, SessionOwner, UdpSession, Updater};
pub use snmp::DEFAULT_SNMP;
pub use tx::{SendOutcome, SendRequest, TxConfig, TxHandle, TxPipeline, TxShared};
