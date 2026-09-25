//! Port of kcptun's multi-port address parser (`reference/kcptun/std/multiport.go`).
//!
//! The client's `-remoteaddr` and the server's `-listen` may name a range of UDP ports
//! (`IP:minport-maxport`), over which kcptun spreads its connections. Go parses them with one
//! unanchored regular expression and a hand-written range check, and the port reproduces both,
//! quirks included:
//!
//! - the pattern is `(.*)\:([0-9]{1,5})-?([0-9]{1,5})?`, applied with
//!   `FindStringSubmatch`, so it is **unanchored** and matches leftmost-first with a greedy
//!   `.*`: `host:80:90` has the host `host:80`, `junk a:1-2` the host `junk a`, and trailing
//!   text after the ports is ignored;
//! - at most five digits are taken per port, so `host:123456` parses as minport 12345 and
//!   maxport 6 — and is then rejected by the range check;
//! - `-?` is *outside* the third group, so `a:1-` is a valid single port.
//!
//! Go's `regexp` and the Rust `regex` crate implement the same leftmost-first semantics on the
//! same pattern, and `.` matches any character except `\n` in both, so the same sub-matches
//! come out; `testdata/vectors/multiport.json` proves it case by case against the Go code.

use std::sync::LazyLock;

use regex::Regex;

/// The address pattern, compiled once.
///
/// Note the escaped `\:`, which is redundant in both engines but kept verbatim so the pattern
/// can be compared with Go's at a glance.
// Go: kcptun/std/multiport.go:remoteAddrMatcher
static REMOTE_ADDR_MATCHER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(.*)\:([0-9]{1,5})-?([0-9]{1,5})?").expect("the address pattern is valid")
});

/// A parsed multi-port address: the host and an inclusive range of ports.
// Go: kcptun/std/multiport.go:MultiPort
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiPort {
    /// Everything before the last colon of the match, verbatim (brackets included).
    pub host: String,
    /// The first port of the range.
    pub min_port: u64,
    /// The last port of the range; equal to `min_port` for a single port.
    pub max_port: u64,
}

/// Why an address is not a usable multi-port address. The texts are Go's
/// `errors.Errorf` messages; kcptun prints them with `log.Println`, which shows the message
/// alone (the `github.com/pkg/errors` stack trace only appears under `%+v`).
// Go: kcptun/std/multiport.go:ParseMultiPort
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MultiPortError {
    /// The ports are out of order, zero, or above 65535.
    #[error("invalid port range specified: minport:{min_port} -> maxport {max_port}")]
    InvalidPortRange {
        /// The first port, as parsed (may be out of range).
        min_port: i64,
        /// The last port, as parsed (may be out of range).
        max_port: i64,
    },
    /// The address does not contain `:` followed by digits at all.
    #[error("malformed address:{addr}")]
    MalformedAddress {
        /// The address as it was given.
        addr: String,
    },
}

/// Parses a multiport listener or dialer address.
// Go: kcptun/std/multiport.go:ParseMultiPort
pub fn parse(addr: &str) -> Result<MultiPort, MultiPortError> {
    // Go: matches := remoteAddrMatcher.FindStringSubmatch(addr); if len(matches) >= 4 — the
    // pattern has three groups, so a match always has four entries and a miss none.
    if let Some(matches) = REMOTE_ADDR_MATCHER.captures(addr) {
        // Go: strconv.Atoi. Both groups are one to five decimal digits, so neither call can
        // fail; Go's `err` branches are unreachable and have no counterpart here.
        let min_port = atoi(matches.get(2).map_or("", |m| m.as_str()));
        let mut max_port = min_port;

        // multiport assignment
        let third = matches.get(3).map_or("", |m| m.as_str());
        if !third.is_empty() {
            max_port = atoi(third);
        }

        if (min_port > max_port)
            || min_port > 65535
            || max_port > 65535
            || min_port == 0
            || max_port == 0
        {
            return Err(MultiPortError::InvalidPortRange { min_port, max_port });
        }

        return Ok(MultiPort {
            host: matches.get(1).map_or("", |m| m.as_str()).to_string(),
            // Go: uint64(minPort) / uint64(maxPort); both are in 1..=65535 here.
            min_port: min_port as u64,
            max_port: max_port as u64,
        });
    }

    Err(MultiPortError::MalformedAddress {
        addr: addr.to_string(),
    })
}

/// `strconv.Atoi` for the one-to-five-digit groups of the pattern; Go's `int` is 64 bits.
fn atoi(digits: &str) -> i64 {
    digits
        .parse::<i64>()
        .expect("the pattern matched one to five decimal digits")
}

#[cfg(test)]
#[path = "multiport_tests.rs"]
mod tests;
