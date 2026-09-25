//! Rust port of [tcpraw](https://github.com/xtaci/tcpraw) (pinned reference: v1.2.32): a
//! packet-oriented connection that carries datagrams inside crafted TCP segments ("fake TCP").
//!
//! Linux only. On other platforms `dial` and `listen` fail with `os not supported`, like Go.
//!
//! Go reference source: `reference/kcptun/vendor/github.com/xtaci/tcpraw/`.
//!
//! `unsafe` is only permitted for the raw-socket system calls, for the `getifaddrs(3)` walk that
//! gives a listening connection its per-interface raw sockets (`std` exposes no interface list)
//! and for the `flock(2)` go-iptables takes on `/var/run/xtables.lock`; every block needs a
//! `// SAFETY:` comment.
//!
//! # Layout
//!
//! - [`checksum`] — the TCP checksum and the IPv4/IPv6 pseudo-header (gopacket's
//!   `layers/tcpip.go`).
//! - [`tcp`] — the segment codec: header and options, serialise and parse (gopacket's
//!   `layers/tcp.go`), plus the IPv4 raw-read header stripping the Go runtime does.
//! - [`fingerprint`] — the Linux fingerprint every crafted segment imitates (window, options,
//!   timestamps), including **Deviation V10**.
//! - [`addr`] — Go's `net.ResolveTCPAddr` and the address forms the flow table is keyed by.
//! - [`iptables`] — the `filter/OUTPUT` DROP rules and the slice of go-iptables that drives them.
//! - [`flow`] — the flow table: one entry per peer, holding the TCP state segments are built
//!   from, with the capture-side update, the segment builder and the expiry sweep.
//! - [`iface`] (Unix) — the interface addresses `listen` opens one raw socket per.
//! - `raw`, `conn` (Linux only) — the raw sockets and the connection that ties it all together.
//! - [`packet_conn`] — the connection as a KCP transport (`kcptun_kcp::PacketConn`), which is
//!   what `--tcp` hands to a KCP session or listener.
//!
//! Everything but `raw` and `conn` is platform-independent and is tested everywhere.
//!
//! # Segment layout
//!
//! One tcpraw datagram, as this port emits it (`docs/WIRE-FORMAT.md` §10):
//!
//! ```text
//! 0  src port u16 BE                          | 2  dst port u16 BE
//! 4  seq u32 BE
//! 8  ack u32 BE
//! 12 data offset (8) + flags (PSH|ACK) u16 BE | 14 window (65535) u16 BE
//! 16 checksum u16 BE                          | 18 urgent (0) u16 BE
//! 20 options: 01 01 08 0a <TSval u32 BE> <TSecr u32 BE>
//! 32 payload (one KCP packet)
//! ```

pub mod addr;
pub mod checksum;
pub mod fingerprint;
pub mod flow;
pub mod iptables;
pub mod packet_conn;
pub mod tcp;

#[cfg(unix)]
pub mod iface;

#[cfg(target_os = "linux")]
pub mod conn;
#[cfg(target_os = "linux")]
pub mod raw;

#[cfg(not(target_os = "linux"))]
mod stub;

// Hidden, unstable: the fuzz harness the cargo-fuzz crate in `fuzz/` drives.
#[doc(hidden)]
#[cfg(any(test, feature = "internals"))]
pub mod internals;

pub use checksum::{IP_PROTOCOL_TCP, PseudoHeader, compute_checksum, verify_checksum};
pub use fingerprint::{FingerPrint, FingerPrintType, uptime_ms};
pub use tcp::{
    MIN_HEADER_LEN, OptionRef, Options, ParseError, Segment, TcpFlags, TcpHeader, TcpOption,
    Timestamps, serialize, strip_ipv4_header,
};

#[cfg(target_os = "linux")]
pub use conn::{TcpConn, dial, iptables_reset, listen};
#[cfg(not(target_os = "linux"))]
pub use stub::{TcpConn, dial, iptables_reset, listen};
