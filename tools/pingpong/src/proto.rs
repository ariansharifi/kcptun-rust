//! The request/response protocol `pingpong serve` speaks.
//!
//! It is deliberately the simplest thing that measures what Step 11 needs, and its one real
//! design rule is: **the byte count always goes first and nothing ever half-closes**. kcptun's
//! half-close path differs between the implementations (DECISIONS V04/V11, and Go's QPP port
//! has no `CloseWrite` at all), so a workload that ended a transfer with `shutdown(SHUT_WR)`
//! would measure that difference instead of the tunnel. Every exchange here is framed, both
//! peers always know how many bytes to read, and a connection ends by simply being dropped.
//!
//! ```text
//! ECHO <n>\n  + n bytes   ->   n bytes back          (latency)
//! UP <n>\n    + n bytes   ->   "OK <n>\n"            (client -> server bulk)
//! DN <n>\n                ->   n bytes               (server -> client bulk)
//! ```
//!
//! A connection may carry any number of requests, one after another.

/// Largest transfer a single request may name (256 MiB), so a corrupt or hostile header can
/// never make the server allocate or read without bound.
pub const MAX_BYTES: u64 = 256 << 20;

/// Longest header line accepted, including the newline.
pub const MAX_HEADER: usize = 32;

/// One request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// Send `n` bytes, receive the same `n` bytes back.
    Echo(u64),
    /// Send `n` bytes, receive `OK <n>`.
    Up(u64),
    /// Receive `n` bytes.
    Down(u64),
}

impl Request {
    /// The header line, newline included.
    pub fn header(&self) -> String {
        match self {
            Request::Echo(n) => format!("ECHO {n}\n"),
            Request::Up(n) => format!("UP {n}\n"),
            Request::Down(n) => format!("DN {n}\n"),
        }
    }

    /// How many bytes the requester sends after the header.
    pub fn payload_out(&self) -> u64 {
        match self {
            Request::Echo(n) | Request::Up(n) => *n,
            Request::Down(_) => 0,
        }
    }

    /// How many bytes of payload the requester reads back (the `OK` line is not payload).
    pub fn payload_in(&self) -> u64 {
        match self {
            Request::Echo(n) | Request::Down(n) => *n,
            Request::Up(_) => 0,
        }
    }
}

/// Parses one header line (with or without its trailing newline).
pub fn parse_request(line: &str) -> Result<Request, String> {
    let line = line.trim_end_matches(['\r', '\n']);
    let (verb, count) = line
        .split_once(' ')
        .ok_or_else(|| format!("malformed request {line:?}"))?;
    let n: u64 = count
        .parse()
        .map_err(|_| format!("malformed byte count in {line:?}"))?;
    if n > MAX_BYTES {
        return Err(format!("{n} bytes exceeds the {MAX_BYTES}-byte limit"));
    }
    match verb {
        "ECHO" => Ok(Request::Echo(n)),
        "UP" => Ok(Request::Up(n)),
        "DN" => Ok(Request::Down(n)),
        _ => Err(format!("unknown verb {verb:?}")),
    }
}

/// The acknowledgement a server sends after draining an `UP`.
pub fn ack(n: u64) -> String {
    format!("OK {n}\n")
}

/// Checks an `OK <n>` acknowledgement.
pub fn parse_ack(line: &str) -> Result<u64, String> {
    let line = line.trim_end_matches(['\r', '\n']);
    match line.split_once(' ') {
        Some(("OK", n)) => n.parse().map_err(|_| format!("malformed ack {line:?}")),
        _ => Err(format!("malformed ack {line:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_round_trip() {
        for r in [Request::Echo(64), Request::Up(1 << 20), Request::Down(0)] {
            assert_eq!(parse_request(&r.header()), Ok(r));
        }
    }

    #[test]
    fn payload_directions_are_right() {
        assert_eq!(Request::Echo(7).payload_out(), 7);
        assert_eq!(Request::Echo(7).payload_in(), 7);
        assert_eq!(Request::Up(7).payload_out(), 7);
        assert_eq!(Request::Up(7).payload_in(), 0);
        assert_eq!(Request::Down(7).payload_out(), 0);
        assert_eq!(Request::Down(7).payload_in(), 7);
    }

    #[test]
    fn rubbish_is_rejected_rather_than_trusted() {
        assert!(parse_request("").is_err());
        assert!(parse_request("ECHO").is_err());
        assert!(parse_request("ECHO x").is_err());
        assert!(parse_request("NOPE 1").is_err());
        assert!(parse_request(&format!("UP {}", MAX_BYTES + 1)).is_err());
        assert_eq!(
            parse_request(&format!("UP {MAX_BYTES}")),
            Ok(Request::Up(MAX_BYTES))
        );
    }

    #[test]
    fn acks_round_trip_and_reject_noise() {
        assert_eq!(parse_ack(&ack(4096)), Ok(4096));
        assert!(parse_ack("NO 1").is_err());
        assert!(parse_ack("OK").is_err());
        assert!(parse_ack("").is_err());
    }
}
