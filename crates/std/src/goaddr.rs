//! Port of Go's `net.SplitHostPort`, the address splitter kcptun uses to tell a `host:port`
//! from the path of a unix socket.
//!
//! Go sources:
//! - Go standard library `net/ipsock.go:SplitHostPort` (Go 1.27.1): the algorithm and all five
//!   error texts;
//! - `net/net.go:AddrError`: the `address <addr>: <why>` wrapping, which omits the prefix when
//!   the address is empty;
//! - `kcptun/client/main.go:319` and `kcptun/server/main.go:449`: the only call sites:
//!   ```go
//!   // client/main.go:319 (startup, for -l):
//!   if _, _, err := net.SplitHostPort(config.LocalAddr); err != nil {
//!       isUnix = true
//!   }
//!   // server/main.go:449 (inside handleMux, per accepted KCP session, for -t):
//!   if _, _, err := net.SplitHostPort(config.Target); err != nil {
//!       targetType = TGT_UNIX
//!   }
//!   ```
//!   so `-l` / `-t` becomes an AF_UNIX path exactly when this function fails. The results are
//!   otherwise thrown away: `ResolveTCPAddr` re-splits the address itself.
//!
//! Only the failure/success decision and the message matter for kcptun, but the port returns the
//! host and the port too, since it is no more work and makes the differential vectors complete.

use std::fmt;

/// The port is missing altogether.
// Go: net/ipsock.go:SplitHostPort missingPort
const MISSING_PORT: &str = "missing port in address";
/// An unbracketed address with more than one colon.
// Go: net/ipsock.go:SplitHostPort tooManyColons
const TOO_MANY_COLONS: &str = "too many colons in address";

/// Why an address could not be split, in Go's wording.
///
/// `Display` reproduces `AddrError.Error()`: `address <addr>: <err>`, or just `<err>` when the
/// address is empty (which is exactly what `SplitHostPort("")` reports).
// Go: net/net.go:AddrError
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrError {
    /// The address that could not be split.
    pub addr: String,
    /// The reason, one of Go's five constants.
    pub err: &'static str,
}

impl fmt::Display for AddrError {
    // Go: net/net.go:(*AddrError).Error
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.addr.is_empty() {
            f.write_str(self.err)
        } else {
            write!(f, "address {}: {}", self.addr, self.err)
        }
    }
}

impl std::error::Error for AddrError {}

/// The index of the last `b` in `s`, Go's `bytealg.LastIndexByteString`.
fn last_index_byte(s: &[u8], b: u8) -> Option<usize> {
    s.iter().rposition(|&c| c == b)
}

/// The index of the first `b` in `s`, Go's `bytealg.IndexByteString`.
fn index_byte(s: &[u8], b: u8) -> Option<usize> {
    s.iter().position(|&c| c == b)
}

/// Splits a network address of the form `host:port`, `host%zone:port`, `[host]:port` or
/// `[host%zone]:port` into host and port.
///
/// A literal IPv6 address must be bracketed; the brackets are removed from the host. Neither the
/// host nor the port is validated: `SplitHostPort("host:port")` succeeds.
///
/// The returned slices borrow from `hostport`, as Go's do.
// Go: net/ipsock.go:SplitHostPort
pub fn split_host_port(hostport: &str) -> Result<(&str, &str), AddrError> {
    let bytes = hostport.as_bytes();
    let addr_err = |why: &'static str| AddrError {
        addr: hostport.to_string(),
        err: why,
    };
    // Go: j, k := 0, 0
    let (j, k);
    let host;

    // The port starts after the last colon.
    let Some(i) = last_index_byte(bytes, b':') else {
        return Err(addr_err(MISSING_PORT));
    };

    // `i` exists, so the address is not empty and indexing byte 0 is safe (as it is in Go).
    if bytes[0] == b'[' {
        // Expect the first ']' just before the last ':'.
        let Some(end) = index_byte(bytes, b']') else {
            return Err(addr_err("missing ']' in address"));
        };
        if end + 1 == hostport.len() {
            // There can't be a ':' behind the ']' now.
            return Err(addr_err(MISSING_PORT));
        } else if end + 1 == i {
            // The expected result.
        } else {
            // Either ']' isn't followed by a colon, or it is followed by a colon that is not
            // the last one.
            if bytes[end + 1] == b':' {
                return Err(addr_err(TOO_MANY_COLONS));
            }
            return Err(addr_err(MISSING_PORT));
        }
        host = &hostport[1..end];
        // There can't be a '[' resp. ']' before these positions.
        (j, k) = (1, end + 1);
    } else {
        host = &hostport[..i];
        if index_byte(host.as_bytes(), b':').is_some() {
            return Err(addr_err(TOO_MANY_COLONS));
        }
        (j, k) = (0, 0);
    }

    if index_byte(&bytes[j..], b'[').is_some() {
        return Err(addr_err("unexpected '[' in address"));
    }
    if index_byte(&bytes[k..], b']').is_some() {
        return Err(addr_err("unexpected ']' in address"));
    }

    Ok((host, &hostport[i + 1..]))
}

/// Whether `addr` is an address `net.SplitHostPort` accepts, i.e. whether kcptun listens on TCP
/// rather than on a unix socket.
// Go: kcptun/client/main.go:319 (`isUnix = true` on failure) and kcptun/server/main.go:449, in
// handleMux, per accepted session (`targetType = TGT_UNIX` on failure)
pub fn is_host_port(addr: &str) -> bool {
    split_host_port(addr).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The golden vectors (testdata/vectors/multiport.json, area "multiport") cover the branches
    // in bulk; these check the shapes the two call sites depend on.

    #[test]
    fn unix_paths_are_rejected_and_addresses_are_accepted() {
        for addr in [
            "/tmp/kcptun.sock",
            "./kcptun.sock",
            "@abstract",
            "nocolon",
            "",
        ] {
            assert!(!is_host_port(addr), "{addr:?} should look like a unix path");
        }
        for addr in [
            ":29900",
            "127.0.0.1:12948",
            "[::1]:80",
            "vps:29900",
            "host:",
        ] {
            assert!(is_host_port(addr), "{addr:?} should look like host:port");
        }
    }

    #[test]
    fn error_text_omits_an_empty_address() {
        assert_eq!(
            split_host_port("").unwrap_err().to_string(),
            "missing port in address"
        );
        assert_eq!(
            split_host_port("x").unwrap_err().to_string(),
            "address x: missing port in address"
        );
    }

    #[test]
    fn borrowed_results() {
        let addr = String::from("[::1]:80");
        let (host, port) = split_host_port(&addr).expect("valid address");
        assert_eq!((host, port), ("::1", "80"));
    }
}
