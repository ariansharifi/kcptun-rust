//! The `tcp_segment` fuzz harness (plan step 10.1): arbitrary bytes are handed to the codec as
//! if a raw socket had just delivered them. Nothing may panic, and nothing the sender chooses
//! may make the parser point outside the buffer.
//!
//! This is the path a hostile peer reaches without any handshake: an `AF_INET`/`AF_INET6` raw
//! socket receives every TCP segment on the host, so `captureFlow` parses whatever arrives
//! before the port filter has looked at it (porting guide §5).
//!
//! The cargo-fuzz target (`crates/tcpraw/fuzz/fuzz_targets/tcp_segment.rs`) only calls
//! [`tcp_segment`]; the harness lives here so this crate's tests run it over the committed
//! seeds.
//!
//! # Input format
//!
//! One selector byte, then the bytes the socket delivered:
//!
//! - bit 0: the read came from an IPv4 raw socket, so [`strip_ipv4_header`] runs first (the Go
//!   runtime does this inside `ReadFromIP`); otherwise the bytes start at the TCP header, as an
//!   IPv6 raw read does;
//! - bit 1: the pseudo-header used for the checksum work is IPv6 rather than IPv4;
//! - bit 2: the parsed segment is serialised again and re-parsed, which drives the write path
//!   with the options the input chose.
//!
//! An empty input is a zero-length read, which Go's capture loop also has to survive.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::checksum::{PseudoHeader, compute_checksum, verify_checksum};
use crate::tcp::{
    MIN_HEADER_LEN, OPTION_KIND_END_LIST, ParseError, Segment, TcpOption, serialize,
    strip_ipv4_header,
};

/// The selector byte, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selector {
    /// Strip an IPv4 header before parsing.
    pub ipv4_raw_read: bool,
    /// Which pseudo-header the checksum is computed against.
    pub pseudo: PseudoHeader,
    /// Serialise the parsed segment again and re-parse it.
    pub reserialize: bool,
}

impl Selector {
    /// Decodes the selector byte.
    pub fn from_byte(b: u8) -> Selector {
        Selector {
            ipv4_raw_read: b & 1 != 0,
            pseudo: if b & 2 != 0 {
                PseudoHeader::V6 {
                    src: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
                    dst: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
                }
            } else {
                PseudoHeader::V4 {
                    src: Ipv4Addr::new(192, 0, 2, 1),
                    dst: Ipv4Addr::new(192, 0, 2, 2),
                }
            },
            reserialize: b & 4 != 0,
        }
    }
}

/// One fuzz iteration: parse `data` as a raw-socket read and exercise everything `captureFlow`
/// (and, with bit 2, `WriteTo`) would do with the result.
pub fn tcp_segment(data: &[u8]) {
    let Some((&selector, rest)) = data.split_first() else {
        // A zero-length read: `gopacket.NewPacket` decodes nothing and `captureFlow` continues.
        assert!(Segment::decode(&[]).is_err());
        return;
    };
    let selector = Selector::from_byte(selector);

    let mut buf = rest.to_vec();
    let n = if selector.ipv4_raw_read {
        let n = strip_ipv4_header(buf.len(), &mut buf);
        assert!(n <= buf.len(), "stripping must not grow the read");
        n
    } else {
        buf.len()
    };
    let data = &buf[..n];

    let seg = match Segment::decode(data) {
        Err(ParseError::HeaderTooShort(len)) => {
            assert_eq!(len, data.len());
            return;
        }
        Ok(seg) => seg,
    };

    // Everything the parser reports must lie inside the buffer it was given.
    assert!(seg.option_bytes.len() + seg.payload.len() + MIN_HEADER_LEN <= data.len());
    let mut option_bytes = 0usize;
    for opt in seg.options() {
        option_bytes += opt.data.len();
        assert!(option_bytes <= seg.option_bytes.len(), "options overrun");
    }
    let _ = seg.timestamps();
    let _ = seg.next_seq();
    let _ = compute_checksum(data, &selector.pseudo, crate::checksum::IP_PROTOCOL_TCP);

    if !selector.reserialize {
        return;
    }

    // Feed the parsed options back into the write path. Padding shows up as an EndList option,
    // which is not an option to re-emit.
    let options: Vec<TcpOption> = seg
        .options()
        .take_while(|o| o.kind != OPTION_KIND_END_LIST)
        .map(|o| {
            if o.data.is_empty() {
                TcpOption::single(o.kind)
            } else {
                TcpOption::with_data(o.kind, o.data.to_vec())
            }
        })
        .collect();
    let mut header = seg.header;
    let payload = seg.payload.to_vec();
    let mut out = Vec::new();
    serialize(&mut header, &options, &payload, &selector.pseudo, &mut out);
    assert!(verify_checksum(&out, &selector.pseudo), "own checksum");

    let again = Segment::decode(&out).expect("a serialised segment is at least 20 bytes");
    if header.data_offset <= 0x0f {
        assert_eq!(again.header, header);
        assert_eq!(again.payload, &payload[..]);
    } else {
        // More than 40 bytes of options: the data offset does not fit its 4-bit field and is
        // truncated on the wire, so the segment is no longer readable. gopacket does exactly
        // the same, silently (see `tcp::serialize`); tcpraw's own fingerprint never gets near
        // this, but a re-serialised hostile option list can.
        assert_eq!(again.header.data_offset, header.data_offset & 0x0f);
    }
}

/// The committed seed corpus: short, structured inputs that reach every branch of the parser.
///
/// Names become the file names under `fuzz/seeds/tcp_segment/`.
pub fn tcp_segment_handcrafted_seeds() -> Vec<(&'static str, Vec<u8>)> {
    /// One Go-produced segment, prefixed with a selector byte.
    fn seed(selector: u8, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + body.len());
        v.push(selector);
        v.extend_from_slice(body);
        v
    }

    // The two segment layouts a Go peer sends (see the codec tests for their provenance).
    let v10: Vec<u8> = {
        let mut v = vec![
            0xd4, 0x31, 0x0f, 0xa0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x80, 0x18,
            0xff, 0xff, 0x5a, 0xcb, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x0b, 0xad, 0xf0, 0x0d,
            0xde, 0xad, 0xbe, 0xef,
        ];
        v.extend_from_slice(b"kcptun over fake TCP");
        v
    };
    let pinned: Vec<u8> = {
        let mut v = vec![
            0xd4, 0x31, 0x0f, 0xa0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x90, 0x18,
            0xff, 0xff, 0x4a, 0xc5, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0c, 0x0b, 0xad, 0xf0, 0x0d,
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00,
        ];
        v.extend_from_slice(b"kcptun over fake TCP");
        v
    };
    // The same V10 segment behind a 20-byte IPv4 header, as an AF_INET raw socket delivers it.
    let ipv4_read: Vec<u8> = {
        let mut v = vec![
            0x45, 0x00, 0x00, 0x34, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 0, 2, 1,
            192, 0, 2, 2,
        ];
        v.extend_from_slice(&v10);
        v
    };

    // A SYN with a real Linux option layout (MSS, SACK permitted, timestamps, NOP, window scale).
    let syn: Vec<u8> = vec![
        0x12, 0x34, 0x0f, 0xa0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xff,
        0xff, 0x00, 0x00, 0x00, 0x00, 2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0xde, 0xad, 0xbe, 0xef, 0, 0,
        0, 0, 1, 3, 3, 7,
    ];
    // A FIN|ACK with no options: the sequence-space arithmetic.
    let fin: Vec<u8> = vec![
        0x12, 0x34, 0x0f, 0xa0, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x50, 0x11, 0xff,
        0xff, 0x00, 0x00, 0x00, 0x00,
    ];
    // Data offset past the end of the buffer.
    let bad_offset: Vec<u8> = vec![
        0x12, 0x34, 0x0f, 0xa0, 0, 0, 0, 0, 0, 0, 0, 0, 0xf0, 0x18, 0xff, 0xff, 0, 0, 0, 0, 1, 1,
        1, 1,
    ];
    // An option whose length byte runs past the option area.
    let bad_option: Vec<u8> = vec![
        0x12, 0x34, 0x0f, 0xa0, 0, 0, 0, 0, 0, 0, 0, 0, 0x60, 0x18, 0xff, 0xff, 0, 0, 0, 0, 8, 40,
        0, 0, b'p', b'a', b'y',
    ];

    vec![
        ("v10", seed(0b100, &v10)),
        ("v10_v6", seed(0b110, &v10)),
        ("pinned", seed(0b100, &pinned)),
        ("ipv4_read", seed(0b101, &ipv4_read)),
        ("syn", seed(0b100, &syn)),
        ("fin", seed(0b000, &fin)),
        ("bad_offset", seed(0b100, &bad_offset)),
        ("bad_option", seed(0b100, &bad_option)),
        ("short", seed(0b001, &[0x45, 0x00, 0x00])),
        ("empty", Vec::new()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every committed seed runs clean.
    #[test]
    fn tcp_segment_seeds_run_clean() {
        for (_, data) in tcp_segment_handcrafted_seeds() {
            tcp_segment(&data);
        }
    }

    /// Short, empty and pseudo-random inputs, over every selector.
    #[test]
    fn tcp_segment_handles_short_and_random_input() {
        tcp_segment(&[]);
        for sel in 0..=7u8 {
            tcp_segment(&[sel]);
            for len in 0..40usize {
                let mut data = vec![sel];
                data.extend((0..len).map(|i| (i * 31 + 7) as u8));
                tcp_segment(&data);
            }
        }
        // A deterministic pseudo-random stream, chopped into segments of every length.
        let mut x = 0x1234_5678_9abc_def0u64;
        let mut bytes = vec![0u8; 2048];
        for b in &mut bytes {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
        for len in (1..bytes.len()).step_by(37) {
            tcp_segment(&bytes[..len]);
        }
    }

    /// Writes `fuzz/seeds/tcp_segment/`. Run it after changing the seed set:
    /// `cargo test -p kcptun-tcpraw --lib write_tcp_segment_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore = "writes the fuzz seed corpus into the source tree"]
    fn write_tcp_segment_fuzz_seeds() {
        let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        // Test executables also run outside the source tree, cross-built and as root (Step 10.5
        // runs this crate's privileged tests on the lab host through tools/lab/remote-test.sh).
        // There this path is the build machine's and does not exist, so writing it would create
        // a stray root-owned tree instead of the corpus.
        if !crate_dir.join("Cargo.toml").exists() {
            eprintln!("write_tcp_segment_fuzz_seeds: source tree not available, skipping");
            return;
        }
        let dir = crate_dir.join("fuzz/seeds/tcp_segment");
        if dir.exists() {
            std::fs::remove_dir_all(&dir).expect("remove old seeds");
        }
        std::fs::create_dir_all(&dir).expect("create seed dir");
        for (name, data) in tcp_segment_handcrafted_seeds() {
            std::fs::write(dir.join(format!("hand_{name}")), data).expect("write seed");
        }
    }

    /// The committed seed corpus is exactly what [`write_tcp_segment_fuzz_seeds`] generates.
    /// The files are read at test time on purpose: this checks the on-disk corpus libFuzzer
    /// reads, not embedded test data.
    #[test]
    fn tcp_segment_fuzz_seed_files_up_to_date() {
        const HINT: &str = "tcp_segment fuzz seeds are stale; regenerate them with \
            `cargo test -p kcptun-tcpraw --lib write_tcp_segment_fuzz_seeds -- --ignored`";
        let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        // Test executables also run outside the source tree (tools/lab/remote-test.sh).
        if !crate_dir.join("Cargo.toml").exists() {
            eprintln!(
                "tcp_segment_fuzz_seed_files_up_to_date: source tree not available, skipping"
            );
            return;
        }
        let dir = crate_dir.join("fuzz/seeds/tcp_segment");
        let want: std::collections::BTreeMap<String, Vec<u8>> = tcp_segment_handcrafted_seeds()
            .into_iter()
            .map(|(n, d)| (format!("hand_{n}"), d))
            .collect();
        let mut have = std::collections::BTreeMap::new();
        for entry in
            std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}; {HINT}", dir.display()))
        {
            let entry = entry.expect("seed dir entry");
            let name = entry.file_name().into_string().expect("seed file name");
            if name.starts_with('.') {
                continue; // e.g. macOS .DS_Store
            }
            have.insert(name, std::fs::read(entry.path()).expect("read seed"));
        }
        assert!(have == want, "{HINT}");
    }
}
