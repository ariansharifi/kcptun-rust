//! The parts of `client/main.go` and `server/main.go` that are the same on both sides.
//!
//! Go keeps two nearly identical `main` packages, so the QPP block, the `net.OpError` texts and
//! the `%v` of a `net.Addr` are written twice there. Here `crates/client` and `crates/server` are
//! separate crates and cannot share a module of their own, so the duplicated pieces live here,
//! next to the rest of the `std` package they belong to:
//!
//! - the shared [`QuantumPermutationPad`](QppPad), built once per process, with the `uint16` cast
//!   of deviation V15 ([`check_qpp`], [`qpp_count_u16`], [`qpp_pad`]);
//! - [`op_error`] and [`setsockopt_error`], which spell a failed syscall the way Go's
//!   `*net.OpError` does (`listen udp :29900: bind: address already in use`);
//! - [`GoAddr`], the `%v` of a possibly-nil `net.Addr`;
//!
//! Everything that differs between the two binaries — the flag tables, the startup block, the
//! listeners and the proxy loops — stays in the binaries.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::{self, BaseConfig};
use crate::log;

/// The shared Quantum Permutation Pad, built once in `main` and used by every stream.
///
/// Without the `qpp` feature the type is uninhabited, so every `Some` arm is statically
/// impossible and `-QPP` is rejected at startup by [`check_qpp`].
// Go: kcptun/client/main.go:417, kcptun/server/main.go:342 —
// `var _Q_ *qpp.QuantumPermutationPad`
#[cfg(feature = "qpp")]
pub use crate::qpp::QuantumPermutationPad as QppPad;

/// The uninhabited stand-in for the pad in a build without the `qpp` feature.
#[cfg(not(feature = "qpp"))]
#[derive(Debug)]
pub enum QppPad {}

/// What a build without the `qpp` feature reports for `-QPP` (D19: the feature is on by default).
#[cfg(not(feature = "qpp"))]
pub const QPP_NOT_AVAILABLE: &str = "QPP: not available in this build";

// ---------------------------------------------------------------------------------------
// QPP
// ---------------------------------------------------------------------------------------

/// Go's QPP validation block.
///
/// Returns the configured pad count, or `None` when `-QPP` is off. Every failure path ends the
/// process, as Go's `log.Fatal` does. The count is handed on as Go's `int`: the `uint16` cast —
/// and deviation V15's rejection of it — lives further down, in [`qpp_pad`], exactly where Go's
/// `qpp.NewQPP` call does.
// Go: kcptun/client/main.go:362-371, kcptun/server/main.go:327-334
pub fn check_qpp(base: &BaseConfig) -> Option<i64> {
    if !base.qpp {
        return None;
    }

    #[cfg(not(feature = "qpp"))]
    {
        // D19: the GPL-3.0 pad is a default-on feature; a build without it cannot honour -QPP.
        log::fatal(QPP_NOT_AVAILABLE);
    }

    #[cfg(feature = "qpp")]
    {
        match crate::qpp::validate_qpp_params(base.qpp_count, &base.key) {
            Err(err) => log::fatal(&err),
            Ok(suggestions) => {
                for msg in suggestions {
                    log::color_red(&msg);
                }
            }
        }
        Some(base.qpp_count)
    }
}

/// The `uint16(config.QPPCount)` cast of Go's `qpp.NewQPP` call, with the truncation rejected.
///
/// **Deviation V15**, in its **wide** form: *every* count that does not fit in `uint16` is
/// refused, not only the ones that truncate to zero.
///
/// Go builds the pad with `uint16(config.QPPCount)`, so any count above 65535 is silently
/// something else. `-QPPCount 65536` truncates to **0**, which passes `ValidateQPPParams` (it
/// checks an `int`) and then makes Go's `NewQPP` divide by zero on the first encrypted byte,
/// i.e. on the first byte of user traffic. `-QPPCount 65537` truncates to **1**: it passes the
/// `minPads` and prime-number checks on the pre-cast `int`, prints **no warning at all**, and
/// then runs with a single pad — the truncation bypasses Go's own safety warnings, which is
/// exactly what those warnings exist to prevent. Both are configuration mistakes with no working
/// Go counterpart, so both are rejected at the cast, in [`qpp_pad`], naming the flag.
///
/// `validate_qpp_params` deliberately keeps Go's `int` semantics (it is a port of
/// `ValidateQPPParams`), and `kcptun_qpp::QuantumPermutationPad::new` asserts on 0 pads. Go
/// reaches this line only after the `unsupported smux version:` fatal, the key derivation and
/// the pprof block, so the rejection happens there too and those lines still come first.
///
/// `-conn` has no such property — `-conn 65537` simply runs one tunnel, as it does in Go — which
/// is why the client's `conn_u16` (V19) stays narrow and refuses only the divide-by-zero case.
/// The asymmetry is deliberate; see DECISIONS V15/V19 (the asymmetry was decided in step 09.1).
// Go: kcptun/client/main.go:419, kcptun/server/main.go:363 —
// `qpp.NewQPP([]byte(config.Key), uint16(config.QPPCount))`
#[cfg(feature = "qpp")]
pub fn qpp_count_u16(count: i64) -> Result<u16, String> {
    // Go's int -> uint16 conversion keeps the low 16 bits.
    let n = count as u16;
    if i64::from(n) != count {
        return Err(format!(
            "QPPCount {count} does not fit in uint16: kcptun would truncate it to {n}"
        ));
    }
    Ok(n)
}

/// Builds the process-wide pad, Go's `_Q_`, applying the `uint16` cast of deviation V15.
// Go: kcptun/client/main.go:417-420, kcptun/server/main.go:361-364
pub fn qpp_pad(base: &BaseConfig, count: Option<i64>) -> Option<Arc<QppPad>> {
    let count = count?;
    #[cfg(feature = "qpp")]
    {
        // Go: `uint16(config.QPPCount)` — see `qpp_count_u16` for why a truncating count is
        // rejected instead of silently reinterpreted.
        let count = match qpp_count_u16(count) {
            Ok(count) => count,
            Err(msg) => log::fatal(&msg),
        };
        Some(Arc::new(QppPad::new(base.key.as_bytes(), count)))
    }
    #[cfg(not(feature = "qpp"))]
    {
        // Unreachable: `check_qpp` has already exited for a build without the feature.
        let _ = (base, count);
        None
    }
}

// ---------------------------------------------------------------------------------------
// Go's net.OpError
// ---------------------------------------------------------------------------------------

/// The text a failed socket operation carries into `log.Println`, as Go's `*net.OpError` spells
/// it: `<op> <net> <addr>: <syscall>: <errno>`.
///
/// `addr` of `None` is Go's nil `Addr`, which `OpError.Error()` leaves out entirely, and an empty
/// `syscall` is an error Go does not wrap in an `os.SyscallError` (there is no `Source` address
/// anywhere in kcptun, so the `->` arm of Go's formatter has no counterpart here). The errno is
/// spelled by [`config::go_error_text`] from Go's own `syscall` table
/// ([`kcptun_kcp::goerrno`], DECISIONS D30); the platform's message is only the fallback for an
/// error that carries no errno.
// Go: go1.27.1 net/net.go:(*OpError).Error(), os/error.go:(*SyscallError).Error()
pub fn op_error(
    op: &str,
    network: &str,
    addr: Option<&str>,
    syscall: &str,
    err: &io::Error,
) -> String {
    let mut s = String::from(op);
    if !network.is_empty() {
        s.push(' ');
        s.push_str(network);
    }
    if let Some(addr) = addr {
        s.push(' ');
        s.push_str(addr);
    }
    s.push_str(": ");
    if !syscall.is_empty() {
        s.push_str(syscall);
        s.push_str(": ");
    }
    s.push_str(&config::go_error_text(err));
    s
}

/// The text a failed `SetDSCP`/`SetReadBuffer`/`SetWriteBuffer` carries into `log.Println`.
///
/// A `setsockopt` that fails on a `*net.UDPConn` comes back as a `*net.OpError` whose `Addr` is
/// the socket's local address as `getsockname` reports it, so `-l :29900 -sockbuf -1` prints
/// `SetReadBuffer: set udp [::]:29900: setsockopt: invalid argument`. A `nil` `Addr` is omitted
/// entirely by `OpError.Error()`; a bound socket always has one, so `local` of `None` only covers
/// a `getsockname` that fails.
///
/// `network` is Go's `c.fd.net`, the network name the socket was created with — **not** always
/// `"udp"`. The server's listening socket comes from `net.ListenUDP("udp", udpaddr)`, but the
/// client's comes from `net.ListenUDP(network, nil)` with `network == "udp4"` whenever the remote
/// is IPv4, so the same failure prints `set udp4 0.0.0.0:56625: …` there (verified against
/// `reference/bin/client_darwin_arm64 -sockbuf -1`).
///
/// Not every failure is a syscall, and Go logs the ones that are not exactly as they come.
/// `SetDSCP` answers `errInvalidOperation` when neither `IP_TOS` nor `IPV6_TCLASS` could be set,
/// and `SetReadBuffer`/`SetWriteBuffer` answer it for a transport that has no such option. A
/// `--tcp` transport is in the same position: `kcptun_tcpraw` spells its own `setsockopt`
/// failures the way Go's tcpraw spells them (a bare errno for `SetDSCP`, an `*net.OpError` over
/// `ip` for the buffers) and leaves no errno on them, precisely so that they reach the log
/// unwrapped. That is what an error with no errno gets here.
// Go: go1.27.1 net/sockopt_posix.go — &OpError{Op: "set", Net: c.fd.net, Addr: fd.laddr,
// Err: os.NewSyscallError("setsockopt", errno)}; kcp-go/v5@v5.6.66 sess.go:1251-1297, 1439
pub fn setsockopt_error(network: &str, local: Option<SocketAddr>, err: &io::Error) -> String {
    if err.raw_os_error().is_none() {
        return err.to_string();
    }
    let addr = local.map(|a| a.to_string());
    op_error("set", network, addr.as_deref(), "setsockopt", err)
}

/// A `net.Addr` printed with `%v`: the address, or `<nil>` for a connection that has none.
// Go: fmt's %v of a nil net.Addr interface value
pub struct GoAddr(pub Option<SocketAddr>);

impl std::fmt::Display for GoAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(addr) => write!(f, "{addr}"),
            None => f.write_str("<nil>"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `EADDRINUSE`, spelled out so `crates/std` keeps no `libc` dependency for one constant.
    /// Its text comes from Go's own `syscall` table (`kcptun_kcp::goerrno`, D30), so it reads
    /// `address already in use` on every target that table is carried for — a static musl
    /// build's `strerror` disagrees, which is exactly what D30 removed from the contract.
    #[cfg(target_os = "linux")]
    const EADDRINUSE: i32 = 98;
    #[cfg(all(unix, not(target_os = "linux")))]
    const EADDRINUSE: i32 = 48;
    #[cfg(not(unix))]
    const EADDRINUSE: i32 = 10048;

    /// `EINVAL`, likewise.
    const EINVAL: i32 = if cfg!(unix) { 22 } else { 10022 };

    #[test]
    fn op_errors_read_like_gos_net_operror() {
        let in_use = io::Error::from_raw_os_error(EADDRINUSE);
        assert_eq!(
            op_error("listen", "udp", Some("127.0.0.1:29900"), "bind", &in_use),
            "listen udp 127.0.0.1:29900: bind: address already in use"
        );
        // A wildcard address resolves to a nil IP, which Go prints as an empty host.
        assert_eq!(
            op_error("listen", "tcp", Some(":29900"), "bind", &in_use),
            "listen tcp :29900: bind: address already in use"
        );
        // Go's OpError leaves a nil Addr out altogether, and an unwrapped Err has no syscall.
        let refused = io::Error::from(io::ErrorKind::ConnectionRefused);
        assert_eq!(
            op_error("dial", "tcp", None, "", &refused),
            "dial tcp: connection refused"
        );
    }

    #[test]
    fn setsockopt_errors_name_the_socket() {
        let einval = io::Error::from_raw_os_error(EINVAL);
        assert_eq!(
            setsockopt_error("udp", Some("[::]:29900".parse().expect("addr")), &einval),
            "set udp [::]:29900: setsockopt: invalid argument"
        );
        // The client dials an IPv4 remote from a `net.ListenUDP("udp4", nil)` socket, so Go's
        // `OpError.Net` is `udp4` there.
        assert_eq!(
            setsockopt_error(
                "udp4",
                Some("0.0.0.0:56625".parse().expect("addr")),
                &einval
            ),
            "set udp4 0.0.0.0:56625: setsockopt: invalid argument"
        );
        // A getsockname that failed: Go's nil Addr.
        assert_eq!(
            setsockopt_error("udp", None, &einval),
            "set udp: setsockopt: invalid argument"
        );
        // kcp-go's errInvalidOperation is not a syscall error and is logged bare.
        assert_eq!(
            setsockopt_error("udp", None, &io::Error::other("invalid operation")),
            "invalid operation"
        );
    }

    // -----------------------------------------------------------------------------------
    // V15: the uint16 QPPCount cast
    // -----------------------------------------------------------------------------------

    #[cfg(feature = "qpp")]
    #[test]
    fn qpp_count_beyond_uint16_is_rejected_at_startup() {
        // Everything kcptun can actually use passes through unchanged.
        assert_eq!(qpp_count_u16(1), Ok(1));
        assert_eq!(qpp_count_u16(61), Ok(61));
        assert_eq!(qpp_count_u16(65535), Ok(65535));

        // Deviation V15, wide: 65536 truncates to 0 and divides by zero mid-traffic, ...
        assert_eq!(
            qpp_count_u16(65536),
            Err("QPPCount 65536 does not fit in uint16: kcptun would truncate it to 0".to_string())
        );
        assert_eq!(
            qpp_count_u16(131_072),
            Err(
                "QPPCount 131072 does not fit in uint16: kcptun would truncate it to 0".to_string()
            )
        );
        // ... and 65537 truncates to a single pad after passing every one of Go's checks on the
        // pre-cast int, so Go prints no warning at all and runs with the weakest possible pad.
        assert_eq!(
            qpp_count_u16(65537),
            Err("QPPCount 65537 does not fit in uint16: kcptun would truncate it to 1".to_string())
        );

        // `validate_qpp_params` keeps Go's int semantics, so it is this check, and only this
        // check, that stops a truncating value — for both of them, and with no warning for the
        // one that does not reach zero.
        assert!(crate::qpp::validate_qpp_params(65536, &"k".repeat(211)).is_ok());
        assert_eq!(
            crate::qpp::validate_qpp_params(65537, &"k".repeat(211)),
            Ok(Vec::new())
        );
    }

    #[cfg(feature = "qpp")]
    #[test]
    fn the_uint16_guard_runs_where_gos_cast_does() {
        // Go's cast is at `_Q_ = qpp.NewQPP(...)`, below the `unsupported smux version:` fatal,
        // the key derivation and the pprof block, so `check_qpp` must hand the raw count on
        // untouched and leave the rejection to `qpp_pad`. Otherwise `-QPPCount 65536 -smuxver 3`
        // would report the count instead of Go's `unsupported smux version:3`, and
        // `-QPPCount 65536` alone would swallow the `initiating key derivation` and
        // `Listening on:` lines that precede it.
        let mut base = crate::config::ServerConfig::defaults().base;
        base.qpp = true;
        base.qpp_count = 65536;
        base.key = "k".repeat(211);
        assert_eq!(check_qpp(&base), Some(65536));
    }

    #[cfg(feature = "qpp")]
    #[test]
    fn the_pad_is_built_exactly_when_qpp_is_on() {
        let mut base = crate::config::ClientConfig::defaults().base;
        base.key = "it's a secrect".to_string();
        assert!(qpp_pad(&base, None).is_none());
        assert!(qpp_pad(&base, Some(7)).is_some());
    }

    #[test]
    fn a_missing_address_prints_as_gos_nil() {
        assert_eq!(GoAddr(None).to_string(), "<nil>");
        assert_eq!(
            GoAddr(Some("127.0.0.1:1".parse().expect("addr"))).to_string(),
            "127.0.0.1:1"
        );
    }
}
