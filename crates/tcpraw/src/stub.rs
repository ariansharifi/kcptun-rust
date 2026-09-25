//! What the crate offers where there are no raw sockets and no iptables: nothing that works.
//!
//! Go ships a build-tagged stub for every non-Linux platform whose `Dial` and `Listen` return the
//! error `os not supported`; this is that stub. [`TcpConn`] is uninhabited, which is the type-level
//! statement that one can never be created here.
//!
//! Go reference: `tcpraw@v1.2.32 tcp_stub.go`.
#![forbid(unsafe_code)]

use std::io;

/// The connection that cannot exist on this platform.
// Go: tcpraw@v1.2.32 tcp_stub.go:TCPConn
#[derive(Debug)]
pub enum TcpConn {}

/// Always fails with Go's `os not supported`.
// Go: tcpraw@v1.2.32 tcp_stub.go:Dial()
pub async fn dial(_network: &str, _address: &str) -> io::Result<TcpConn> {
    Err(os_not_supported())
}

/// Always fails with Go's `os not supported`.
// Go: tcpraw@v1.2.32 tcp_stub.go:Listen()
pub async fn listen(_network: &str, _address: &str) -> io::Result<TcpConn> {
    Err(os_not_supported())
}

/// Nothing to reset: no connection was ever made, so no rule was ever installed.
///
/// Go has no counterpart at all (`clear.go` is `//go:build linux`) so the caller would not
/// compile there. kcptun's exit path is shared across platforms, so it gets a no-op here.
// Go: tcpraw@v1.2.32 clear.go:IPTablesReset() (Linux only)
pub fn iptables_reset() {}

// Go: tcpraw@v1.2.32 tcp_stub.go:errors.New("os not supported")
fn os_not_supported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "os not supported")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stub's error text is Go's, verbatim.
    #[tokio::test]
    async fn dial_reports_os_not_supported() {
        let err = dial("tcp", "127.0.0.1:29900")
            .await
            .expect_err("never succeeds");
        assert_eq!(err.to_string(), "os not supported");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        iptables_reset();
    }

    /// `Listen` has the same stub, with the same text.
    #[tokio::test]
    async fn listen_reports_os_not_supported() {
        let err = listen("tcp", ":29900").await.expect_err("never succeeds");
        assert_eq!(err.to_string(), "os not supported");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
