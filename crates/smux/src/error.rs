//! Errors of the smux port.
//!
//! Every message is Go's exact text (porting guide §4), because kcptun logs them and callers
//! compare them. Go reference: `smux@v1.5.55 session.go` (the `Err*` values and `timeoutError`).

use std::io;
use std::sync::Arc;

use crate::mux::ConfigError;

/// An error from a session or a stream.
///
/// `Clone` because Go stores the socket error once (`socketReadError atomic.Value`) and hands
/// the same value to every blocked caller; the Rust port clones it out of the slot instead,
/// which is why [`Error::Io`] wraps an [`Arc`].
#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    // Go: smux@v1.5.55 session.go:ErrInvalidProtocol
    /// The peer sent a frame this session cannot parse: a foreign protocol version, an unknown
    /// command, a `cmdUPD` on a version-1 session or a command with the wrong payload length
    /// (the last one is the post-pin fix, DECISIONS V01).
    #[error("invalid protocol")]
    InvalidProtocol,
    // Go: smux@v1.5.55 session.go:ErrConsumed
    /// A version-2 peer acknowledged more bytes than were ever written to the stream.
    #[error("peer consumed more than sent")]
    Consumed,
    // Go: smux@v1.5.55 session.go:ErrGoAway
    /// The session ran out of stream ids; the caller must open a new connection.
    #[error("stream id overflows, should start a new connection")]
    GoAway,
    // Go: smux@v1.5.55 session.go:ErrTimeout (timeoutError)
    /// A deadline expired. [`is_timeout`](Self::is_timeout) reports it, like Go's
    /// `net.Error.Timeout()`.
    #[error("timeout")]
    Timeout,
    // Go: smux@v1.5.55 session.go:ErrWouldBlock
    /// The operation would have blocked (internal to the read path in Go, where `tryReadV*`
    /// returns it to `Read`'s retry loop).
    #[error("operation would block on IO")]
    WouldBlock,
    // Go: io.ErrClosedPipe (returned by session and stream operations after a close)
    /// The session or the stream is closed, or its write side was half-closed.
    #[error("io: read/write on closed pipe")]
    ClosedPipe,
    /// The configuration was rejected (`smux.Client` / `smux.Server` return this from
    /// `VerifyConfig`).
    // Go: smux@v1.5.55 mux.go:VerifyConfig()
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// A read or write on the underlying connection failed. Go returns the connection's error
    /// unchanged, so the text is the underlying one.
    // Go: smux@v1.5.55 session.go:socketReadError / socketWriteError
    #[error("{0}")]
    Io(Arc<io::Error>),
}

impl Error {
    /// Whether this is a timeout, like Go's `net.Error.Timeout()`. kcptun branches on it, so a
    /// timeout from the underlying connection counts too.
    // Go: smux@v1.5.55 session.go:timeoutError.Timeout()
    pub fn is_timeout(&self) -> bool {
        match self {
            Error::Timeout => true,
            Error::Io(e) => e.kind() == io::ErrorKind::TimedOut,
            _ => false,
        }
    }

    /// Whether this is a temporary error, like Go's `net.Error.Temporary()`. Only
    /// [`Error::Timeout`] is temporary, exactly as in smux.
    // Go: smux@v1.5.55 session.go:timeoutError.Temporary()
    pub fn is_temporary(&self) -> bool {
        matches!(self, Error::Timeout)
    }
}

/// Equality over the variants. [`io::Error`] has no equality, so two [`Error::Io`] values are
/// equal when their kind and message are, which is what a caller comparing Go errors sees.
impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Error::InvalidProtocol, Error::InvalidProtocol)
            | (Error::Consumed, Error::Consumed)
            | (Error::GoAway, Error::GoAway)
            | (Error::Timeout, Error::Timeout)
            | (Error::WouldBlock, Error::WouldBlock)
            | (Error::ClosedPipe, Error::ClosedPipe) => true,
            (Error::Config(a), Error::Config(b)) => a == b,
            (Error::Io(a), Error::Io(b)) => a.kind() == b.kind() && a.to_string() == b.to_string(),
            _ => false,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(Arc::new(e))
    }
}

impl From<Error> for io::Error {
    /// Maps to the `io::ErrorKind` a Go caller would infer from the error, keeping the text.
    /// Used by the `AsyncRead`/`AsyncWrite` adapters.
    ///
    /// An [`Error::Io`] keeps the inner error's [`io::ErrorKind`], its text **and** its
    /// `raw_os_error()`, but not its concrete payload type: the inner error is shared behind an
    /// [`Arc`] (one socket error handed to every blocked caller, like Go's
    /// `socketReadError atomic.Value`), so it is always rebuilt rather than moved out. The
    /// conversion therefore behaves the same no matter how many clones exist.
    ///
    /// Carrying the errno across is what keeps **DECISIONS D30** reachable on this path: the
    /// binaries' `pipe:` line renders the `io::Error` a stream read or write failed with, and
    /// `kcptun_kcp::goerrno::go_error_text` can only consult Go's table for an error that still
    /// knows its errno. `io::Error::from_raw_os_error` reproduces the kind and the `Display` of
    /// the error it rebuilds, so nothing else about the conversion changes — and nothing in the
    /// tree downcasts an `io::Error` back to an [`Error`].
    fn from(e: Error) -> io::Error {
        match e {
            Error::Timeout => io::Error::new(io::ErrorKind::TimedOut, e),
            Error::WouldBlock => io::Error::new(io::ErrorKind::WouldBlock, e),
            Error::ClosedPipe => io::Error::new(io::ErrorKind::BrokenPipe, e),
            Error::InvalidProtocol | Error::Consumed => {
                io::Error::new(io::ErrorKind::InvalidData, e)
            }
            Error::GoAway | Error::Config(_) => io::Error::other(e),
            Error::Io(shared) => match shared.raw_os_error() {
                Some(errno) => io::Error::from_raw_os_error(errno),
                None => io::Error::new(shared.kind(), Error::Io(shared)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_match_go() {
        assert_eq!(Error::InvalidProtocol.to_string(), "invalid protocol");
        assert_eq!(Error::Consumed.to_string(), "peer consumed more than sent");
        assert_eq!(
            Error::GoAway.to_string(),
            "stream id overflows, should start a new connection"
        );
        assert_eq!(Error::Timeout.to_string(), "timeout");
        assert_eq!(Error::WouldBlock.to_string(), "operation would block on IO");
        assert_eq!(
            Error::ClosedPipe.to_string(),
            "io: read/write on closed pipe"
        );
    }

    #[test]
    fn timeout_predicates() {
        assert!(Error::Timeout.is_timeout());
        assert!(Error::Timeout.is_temporary());
        assert!(!Error::ClosedPipe.is_timeout());
        assert!(!Error::WouldBlock.is_temporary());
        let io_timeout = Error::from(io::Error::new(io::ErrorKind::TimedOut, "deadline"));
        assert!(io_timeout.is_timeout());
        assert!(!io_timeout.is_temporary());
        assert!(!Error::from(io::Error::other("boom")).is_timeout());
    }

    #[test]
    fn io_error_conversion_keeps_kind_and_text() {
        let e: io::Error = Error::Timeout.into();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert_eq!(e.to_string(), "timeout");
        let e: io::Error = Error::ClosedPipe.into();
        assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
        let e: io::Error = Error::InvalidProtocol.into();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);

        // A wrapped io error keeps its own kind and message.
        let inner = io::Error::new(io::ErrorKind::ConnectionReset, "reset by peer");
        let wrapped = Error::from(inner);
        assert_eq!(wrapped.to_string(), "reset by peer");
        let back: io::Error = wrapped.clone().into();
        assert_eq!(back.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(back.to_string(), "reset by peer");
        // The conversion does not depend on the Arc refcount: the last clone converts exactly
        // like a shared one.
        let back: io::Error = wrapped.into();
        assert_eq!(back.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(back.to_string(), "reset by peer");
    }

    #[test]
    fn io_error_conversion_keeps_the_errno() {
        // DECISIONS D30: `goerrno::go_error_text` reaches Go's table only through
        // `raw_os_error()`, so the errno of a socket failure has to survive the trip through the
        // `AsyncRead`/`AsyncWrite` adapters — that is what the binaries' `pipe:` line renders.
        // `EINVAL` is 22 on every platform this targets, spelled out so smux keeps no `libc`
        // dependency for one constant.
        let errno = 22;
        let direct = io::Error::from_raw_os_error(errno);
        let round_tripped: io::Error = Error::from(io::Error::from_raw_os_error(errno)).into();
        assert_eq!(round_tripped.raw_os_error(), Some(errno));
        assert_eq!(round_tripped.kind(), direct.kind());
        assert_eq!(round_tripped.to_string(), direct.to_string());
    }

    #[test]
    fn config_error_is_transparent() {
        let e = Error::from(ConfigError::UnsupportedVersion);
        assert_eq!(e.to_string(), "unsupported protocol version");
    }
}
