//! Go golden smux vectors (`testdata/vectors/smux.json`, plan step 06.1; format in
//! `tools/govectors/README.md`, "Area smux"): the exact frames xtaci/smux v1.5.55 wrote for
//! every command in both protocol versions, its `DefaultConfig`, every `VerifyConfig` branch
//! and the exact error texts. The Rust codec must produce the same bytes and the same errors.

use std::time::Duration;

use kcptun_testkit::rng::{govectors_rng, rand_bytes};
use kcptun_testkit::vectors::{Blob, Case, VectorFile};
use kcptun_testkit::{assert_hex_eq, vectors};
use serde::Deserialize;

use crate::error::Error;
use crate::frame::{
    CMD_FIN, CMD_NOP, CMD_PSH, CMD_SYN, CMD_UPD, Frame, HEADER_SIZE, INITIAL_PEER_WINDOW,
    RawHeader, SZ_CMD_UPD, UpdHeader,
};
use crate::mux::{Config, ConfigError, default_config, verify_config};

fn file() -> VectorFile {
    vectors!("smux")
}

/// One captured frame (`frameCase` in `tools/govectors/smux.go`).
#[derive(Deserialize)]
struct FrameCase {
    name: String,
    ver: u8,
    cmd: u8,
    sid: u32,
    len: usize,
    #[serde(default)]
    payload_stream: u64,
    #[serde(default)]
    consumed: Option<u32>,
    #[serde(default)]
    window: Option<u32>,
    #[serde(default)]
    out: String,
    #[serde(default)]
    out_blob: Option<Blob>,
}

impl FrameCase {
    /// The payload the Go session sent: taken from the recorded frame, or regenerated from the
    /// `newRNG("smux", payload_stream)` stream when the frame was stored as a [`Blob`].
    fn payload(&self) -> Vec<u8> {
        if self.out.is_empty() {
            assert_ne!(
                self.payload_stream, 0,
                "{}: blob case without a payload stream",
                self.name
            );
            rand_bytes(&mut govectors_rng("smux", self.payload_stream), self.len)
        } else {
            let raw = hex::decode(&self.out).expect("hex");
            raw[HEADER_SIZE..].to_vec()
        }
    }
}

fn frame_cases(f: &VectorFile) -> Vec<FrameCase> {
    f.cases_with_prefix("frame/").map(Case::to).collect()
}

// Every frame the Go library wrote must come out of the Rust encoder byte for byte, and the
// decoder must read back the fields the case declares.
#[test]
fn vectors_smux_frames() {
    let f = file();
    let cases = frame_cases(&f);
    assert!(cases.len() >= 12, "only {} frame cases", cases.len());

    for c in &cases {
        let payload = c.payload();
        assert_eq!(payload.len(), c.len, "{}: payload length", c.name);

        let frame = Frame::with_data(c.ver, c.cmd, c.sid, &payload);
        let mut got = Vec::new();
        frame.encode_to(&mut got);
        assert_eq!(got.len(), frame.encoded_len(), "{}", c.name);

        match (&c.out, &c.out_blob) {
            (out, None) if !out.is_empty() => {
                assert_hex_eq!(got, hex::decode(out).expect("hex"), "case {}", c.name);
            }
            (_, Some(blob)) => blob.assert_matches(&got, &c.name),
            _ => panic!("{}: neither out nor out_blob", c.name),
        }

        // Decoding the bytes we just produced must give the recorded fields back.
        let hdr = RawHeader::from_bytes(&got).expect("header");
        assert_eq!(hdr.version(), c.ver, "{}: version", c.name);
        assert_eq!(hdr.cmd(), c.cmd, "{}: cmd", c.name);
        assert_eq!(hdr.stream_id(), c.sid, "{}: sid", c.name);
        assert_eq!(usize::from(hdr.length()), c.len, "{}: length", c.name);
        assert_eq!(hdr, frame.header(), "{}: header", c.name);

        // Every captured frame is a valid frame of its own protocol version.
        assert_eq!(hdr.check_protocol(c.ver), Ok(()), "{}", c.name);
        assert_eq!(
            hdr.check_protocol(c.ver ^ 3),
            Err(Error::InvalidProtocol),
            "{}: foreign version accepted",
            c.name
        );

        if c.cmd == CMD_UPD {
            let upd = UpdHeader::from_bytes(&payload).expect("upd payload");
            assert_eq!(c.len, SZ_CMD_UPD, "{}", c.name);
            assert_eq!(Some(upd.consumed()), c.consumed, "{}: consumed", c.name);
            assert_eq!(Some(upd.window()), c.window, "{}: window", c.name);
            assert_eq!(
                UpdHeader::new(upd.consumed(), upd.window()),
                upd,
                "{}: re-encode",
                c.name
            );
        }
    }
}

// The vectors must cover every command, in both versions where the command exists.
#[test]
fn vectors_smux_frame_coverage() {
    let f = file();
    let cases = frame_cases(&f);
    let has = |ver: u8, cmd: u8| cases.iter().any(|c| c.ver == ver && c.cmd == cmd);
    for ver in [1u8, 2] {
        for cmd in [CMD_SYN, CMD_FIN, CMD_PSH, CMD_NOP] {
            assert!(has(ver, cmd), "no v{ver} case for cmd {cmd}");
        }
    }
    assert!(has(2, CMD_UPD), "no v2 cmdUPD case");
    assert!(!has(1, CMD_UPD), "cmdUPD is version 2 only");

    // The largest frame smux can emit, and a stream id near the u32 wrap.
    assert!(
        cases.iter().any(|c| c.len == 65535 && c.cmd == CMD_PSH),
        "no maximum-length PSH"
    );
    assert!(
        cases.iter().any(|c| c.sid > 0xffff_0000),
        "no high stream id"
    );
    // NOP always travels on stream 0.
    for c in cases.iter().filter(|c| c.cmd == CMD_NOP) {
        assert_eq!((c.sid, c.len), (0, 0), "{}", c.name);
    }
}

/// `smuxConfig` in `tools/govectors/smux.go`: Go's `int` sizes and nanosecond durations.
#[derive(Deserialize)]
struct WireConfig {
    version: i64,
    keep_alive_disabled: bool,
    keep_alive_interval_ns: i64,
    keep_alive_timeout_ns: i64,
    max_frame_size: i64,
    max_receive_buffer: i64,
    max_stream_buffer: i64,
}

impl WireConfig {
    /// The Rust [`Config`], or `None` when the Go configuration is unrepresentable: a negative
    /// duration ([`Duration`] is unsigned) or a size beyond this platform's `isize`.
    fn to_config(&self) -> Option<Config> {
        let interval = u64::try_from(self.keep_alive_interval_ns).ok()?;
        let timeout = u64::try_from(self.keep_alive_timeout_ns).ok()?;
        Some(Config {
            version: isize::try_from(self.version).ok()?,
            keep_alive_disabled: self.keep_alive_disabled,
            keep_alive_interval: Duration::from_nanos(interval),
            keep_alive_timeout: Duration::from_nanos(timeout),
            max_frame_size: isize::try_from(self.max_frame_size).ok()?,
            max_receive_buffer: isize::try_from(self.max_receive_buffer).ok()?,
            max_stream_buffer: isize::try_from(self.max_stream_buffer).ok()?,
        })
    }
}

#[derive(Deserialize)]
struct ConfigCase {
    name: String,
    config: WireConfig,
    err: String,
}

// verify_config must accept and reject exactly what Go's VerifyConfig does, with the same text.
#[test]
fn vectors_smux_verify_config() {
    let f = file();
    let cases: Vec<ConfigCase> = f.cases_with_prefix("config/").map(Case::to).collect();
    assert!(cases.len() >= 20, "only {} config cases", cases.len());

    let mut skipped: Vec<&ConfigCase> = Vec::new();
    for c in &cases {
        let Some(cfg) = c.config.to_config() else {
            skipped.push(c);
            continue;
        };
        let got = match verify_config(&cfg) {
            Ok(()) => String::new(),
            Err(e) => e.to_string(),
        };
        assert_eq!(got, c.err, "case {}", c.name);
    }

    // The only Go configuration the Rust types cannot express on any platform: a negative
    // keepalive interval, which VerifyConfig accepts and keepalive() then panics on (see
    // mux::Config).
    assert!(
        skipped
            .iter()
            .any(|c| c.name == "config/verify/keepalive_interval=-1s"),
        "the negative-keepalive case was not skipped"
    );
    // Anything else may only be skipped because a size does not fit this target's `isize`
    // (the golden data has values above 2147483647, which a 32-bit `isize` cannot hold).
    let fits = |v: i64| isize::try_from(v).is_ok();
    for c in &skipped {
        if c.name == "config/verify/keepalive_interval=-1s" {
            continue;
        }
        let w = &c.config;
        assert!(
            !fits(w.version)
                || !fits(w.max_frame_size)
                || !fits(w.max_receive_buffer)
                || !fits(w.max_stream_buffer),
            "case {} was skipped for an unexpected reason",
            c.name
        );
    }
}

// The default configuration must match Go's field by field.
#[test]
fn vectors_smux_default_config() {
    let f = file();
    let c: ConfigCase = f.case("config/default").to();
    assert_eq!(c.err, "");
    assert_eq!(c.config.to_config(), Some(default_config()));
}

// Every error text must be Go's, character for character.
#[test]
fn vectors_smux_error_texts() {
    let f = file();
    let c = f.case("errors");
    let text = |key: &str| c.param::<String>(key);

    assert_eq!(
        Error::InvalidProtocol.to_string(),
        text("ErrInvalidProtocol")
    );
    assert_eq!(Error::Consumed.to_string(), text("ErrConsumed"));
    assert_eq!(Error::GoAway.to_string(), text("ErrGoAway"));
    assert_eq!(Error::Timeout.to_string(), text("ErrTimeout"));
    assert_eq!(Error::WouldBlock.to_string(), text("ErrWouldBlock"));
    assert_eq!(Error::ClosedPipe.to_string(), text("io.ErrClosedPipe"));
    assert_eq!(
        Error::Timeout.is_timeout(),
        c.param::<bool>("ErrTimeout.Timeout")
    );
    assert_eq!(
        Error::Timeout.is_temporary(),
        c.param::<bool>("ErrTimeout.Temporary")
    );

    // The VerifyConfig texts come from the config cases; make sure each maps to a variant.
    let texts: Vec<String> = [
        ConfigError::UnsupportedVersion,
        ConfigError::KeepAliveInterval,
        ConfigError::KeepAliveTimeout,
        ConfigError::FrameSizeNotPositive,
        ConfigError::FrameSizeTooLarge,
        ConfigError::ReceiveBufferNotPositive,
        ConfigError::ReceiveBufferTooLarge,
        ConfigError::StreamBufferNotPositive,
        ConfigError::StreamBufferAboveReceiveBuffer,
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let seen: Vec<String> = f
        .cases_with_prefix("config/")
        .map(|c| c.field::<String>("err"))
        .filter(|e| !e.is_empty())
        .collect();
    for t in &texts {
        assert!(seen.contains(t), "no golden config case produces {t:?}");
    }
    for e in &seen {
        assert!(texts.contains(e), "unmapped VerifyConfig error {e:?}");
    }
}

/// `windowCase` in `tools/govectors/smux.go`.
#[derive(Deserialize)]
struct WindowCase {
    ver: u8,
    max_frame_size: usize,
    written: usize,
    lens: Vec<usize>,
    total: usize,
}

// A v2 writer whose peer never acknowledges stops after exactly initialPeerWindow bytes, split
// into max_frame_size pieces. Pins INITIAL_PEER_WINDOW for the stream port (06.4).
#[test]
fn vectors_smux_initial_peer_window() {
    let f = file();
    let c: WindowCase = f.case("flow/v2/initial_peer_window").to();
    assert_eq!(c.ver, 2);
    assert_eq!(c.total, INITIAL_PEER_WINDOW as usize);
    assert!(c.written > c.total, "the writer was never blocked");
    assert_eq!(c.lens.iter().sum::<usize>(), c.total);

    let mut want = Vec::new();
    let mut left = INITIAL_PEER_WINDOW as usize;
    while left > 0 {
        let n = left.min(c.max_frame_size);
        want.push(n);
        left -= n;
    }
    assert_eq!(c.lens, want);
}
