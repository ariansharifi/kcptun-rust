//! The `smux_recv` fuzz harness (plan step 06.5): an arbitrary byte string is fed to a live
//! session as if it came from the peer. Nothing may panic — a protocol error, a socket error or
//! the end of the stream are all fine outcomes.
//!
//! The cargo-fuzz target (`crates/smux/fuzz/fuzz_targets/smux_recv.rs`) only calls
//! [`smux_recv`]; the harness lives here so this crate's tests run it over the committed seeds.
//!
//! # Input format
//!
//! Two selector bytes, then the bytes the session reads from its connection:
//!
//! - byte 0, bit by bit:
//!   - bit 0: protocol version, 1 or 2;
//!   - bit 1: the session is a server (0) or a client (1), which decides which stream ids it
//!     accepts as new;
//!   - bit 2: keepalive off (0) or on with a one-second interval and a two-second timeout (1);
//!   - bits 3–4: `max_receive_buffer`, an index into [`BUCKETS`] — the small values make the
//!     receive loop wait for tokens;
//!   - bits 5–6: `max_frame_size`, an index into [`FRAME_SIZES`];
//!   - bit 7: accepted streams are drained (0) or echoed (1), which also exercises the write
//!     path, the shaper and the version-2 window;
//! - byte 1: how much of the input one `read` hands out: `1 + b % 64` bytes, or everything that
//!   is left when `b == 0xFF`. Small values make the session's buffered reader do the framing.
//!
//! Everything after them is the byte stream. When it runs out, the connection reports the end
//! of the stream, which ends the session's receive loop and therefore the run.
//!
//! A two-second watchdog bounds every run: nothing the peer can send may stall the session for
//! good, and a run that does stall is a finding rather than a hang.

use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::conn::SmuxConn;
use crate::mux::{Config, client, default_config, server};
use crate::session::Session;

/// `max_receive_buffer` values the selector chooses from. The small ones exhaust the token
/// bucket within a few frames, so the receive loop has to wait for a reader.
pub const BUCKETS: [isize; 4] = [4194304, 65536, 4096, 1024];

/// `max_frame_size` values the selector chooses from.
pub const FRAME_SIZES: [isize; 4] = [32768, 65535, 1024, 256];

/// Longest a single run may take. Only a stalled session can reach it.
const WATCHDOG: Duration = Duration::from_secs(2);

/// Largest buffer a drain or echo task reads into.
const READ_BUF: usize = 4096;

/// The two selector bytes, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selector {
    /// Session configuration.
    pub config: Config,
    /// Whether the session is the client side.
    pub client: bool,
    /// Whether accepted streams are echoed back (otherwise they are only drained).
    pub echo: bool,
    /// Bytes one `read` hands out, `None` for "everything that is left".
    pub chunk: Option<usize>,
}

impl Selector {
    /// Decodes the two selector bytes.
    pub fn decode(sel: u8, chunk: u8) -> Selector {
        let config = Config {
            version: if sel & 1 == 0 { 1 } else { 2 },
            keep_alive_disabled: sel & 4 == 0,
            keep_alive_interval: Duration::from_secs(1),
            keep_alive_timeout: Duration::from_secs(2),
            max_frame_size: FRAME_SIZES[usize::from((sel >> 5) & 3)],
            max_receive_buffer: BUCKETS[usize::from((sel >> 3) & 3)],
            ..default_config()
        };
        Selector {
            config: Config {
                // MaxStreamBuffer must not exceed MaxReceiveBuffer (VerifyConfig).
                max_stream_buffer: config.max_stream_buffer.min(config.max_receive_buffer),
                ..config
            },
            client: sel & 2 != 0,
            echo: sel & 128 != 0,
            chunk: if chunk == 0xFF {
                None
            } else {
                Some(1 + usize::from(chunk % 64))
            },
        }
    }

    /// Builds the two selector bytes back (used to write the seed corpus).
    pub fn encode(
        version: isize,
        client: bool,
        keepalive: bool,
        bucket: u8,
        frame: u8,
        echo: bool,
        chunk: u8,
    ) -> [u8; 2] {
        let mut sel = 0u8;
        if version == 2 {
            sel |= 1;
        }
        if client {
            sel |= 2;
        }
        if keepalive {
            sel |= 4;
        }
        sel |= (bucket & 3) << 3;
        sel |= (frame & 3) << 5;
        if echo {
            sel |= 128;
        }
        [sel, chunk]
    }
}

/// A connection that replays a fixed byte string to the session and throws away everything the
/// session writes.
struct FuzzConn {
    data: Vec<u8>,
    pos: Mutex<usize>,
    chunk: Option<usize>,
    written: AtomicUsize,
}

impl FuzzConn {
    fn new(data: Vec<u8>, chunk: Option<usize>) -> FuzzConn {
        FuzzConn {
            data,
            pos: Mutex::new(0),
            chunk,
            written: AtomicUsize::new(0),
        }
    }
}

impl SmuxConn for FuzzConn {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut pos = self.pos.lock().unwrap_or_else(|e| e.into_inner());
        let left = self.data.len().saturating_sub(*pos);
        if left == 0 || buf.is_empty() {
            return Ok(0); // end of the peer's data
        }
        let n = buf.len().min(left).min(self.chunk.unwrap_or(usize::MAX));
        buf[..n].copy_from_slice(&self.data[*pos..*pos + n]);
        *pos += n;
        Ok(n)
    }

    async fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        self.written.fetch_add(buf.len(), Ordering::Relaxed);
        Ok(())
    }

    async fn close(&self) -> io::Result<()> {
        Ok(())
    }
}

/// Feeds `data` to a session as if the peer had sent it. Never panics; returns once the session
/// has run out of input (or the watchdog fires).
pub fn smux_recv(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let Some((&chunk, body)) = rest.split_first() else {
        return;
    };
    let selector = Selector::decode(sel, chunk);

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return,
    };
    let body = body.to_vec();
    runtime.block_on(async move {
        let conn = FuzzConn::new(body, selector.chunk);
        let session = if selector.client {
            client(conn, Some(selector.config))
        } else {
            server(conn, Some(selector.config))
        };
        // VerifyConfig cannot fail for these selectors, but a future one might.
        let Ok(session) = session else { return };
        let _ = tokio::time::timeout(WATCHDOG, drain(session, selector.echo)).await;
    });
    // Dropping the runtime cancels the session's tasks.
}

/// Accepts every stream the input opens and reads it to its end, echoing it back when `echo` is
/// set. Streams are handled concurrently, so the receive loop never stalls on the token bucket
/// or on a full accept backlog.
///
/// The run ends when `accept_stream` fails, which is what the end of the input produces. The
/// stream tasks are not awaited: an echoing version-2 writer may be parked on a window the
/// input never opens (Go blocks there too, and only a write deadline would end it), and waiting
/// for the watchdog in that case would cost two seconds per input.
async fn drain<C: SmuxConn>(session: Session<C>, echo: bool) {
    while let Ok(stream) = session.accept_stream().await {
        tokio::spawn(async move {
            let mut buf = [0u8; READ_BUF];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if echo && stream.write(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = stream.close().await;
        });
    }
    // Let the stream tasks run once more, so a drain that is ready to finish does, and the
    // token accounting and the version-2 updates it triggers are exercised.
    tokio::task::yield_now().await;
}

/// Hand-made seeds: every command, both versions, the protocol-error paths, a starved token
/// bucket and an honest stream.
pub fn smux_recv_handcrafted_seeds() -> Vec<(String, Vec<u8>)> {
    use crate::frame::{CMD_FIN, CMD_NOP, CMD_PSH, CMD_SYN, CMD_UPD, RawHeader, UpdHeader};

    /// One encoded frame.
    fn frame(ver: u8, cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
        let mut out = RawHeader::new(ver, cmd, data.len() as u16, sid)
            .as_bytes()
            .to_vec();
        out.extend_from_slice(data);
        out
    }

    /// Seed = selector bytes + the concatenated frames.
    fn seed(head: [u8; 2], frames: Vec<Vec<u8>>) -> Vec<u8> {
        let mut out = head.to_vec();
        for f in frames {
            out.extend_from_slice(&f);
        }
        out
    }

    // Selector shorthands: (version, client, keepalive, bucket, frame size, echo, chunk).
    let v1_server = Selector::encode(1, false, false, 0, 0, false, 0xFF);
    let v1_server_echo = Selector::encode(1, false, false, 0, 2, true, 7);
    let v2_server = Selector::encode(2, false, false, 0, 0, false, 0xFF);
    let v2_server_echo = Selector::encode(2, false, false, 0, 0, true, 0xFF);
    let v1_client = Selector::encode(1, true, false, 0, 0, false, 0xFF);
    let v1_starved = Selector::encode(1, false, false, 3, 0, false, 0xFF);
    let v1_keepalive = Selector::encode(1, false, true, 0, 0, false, 3);

    // The empty input: two selector bytes and nothing to read.
    let mut seeds: Vec<(String, Vec<u8>)> = vec![("empty".into(), v1_server.to_vec())];

    // An honest version-1 stream: open, data, close.
    seeds.push((
        "v1_syn_psh_fin".into(),
        seed(
            v1_server,
            vec![
                frame(1, CMD_SYN, 1, &[]),
                frame(1, CMD_PSH, 1, b"hello smux"),
                frame(1, CMD_FIN, 1, &[]),
            ],
        ),
    ));

    // The same, echoed back through the write path, with a small frame size and tiny reads.
    seeds.push((
        "v1_echo_split_reads".into(),
        seed(
            v1_server_echo,
            vec![
                frame(1, CMD_SYN, 1, &[]),
                frame(1, CMD_PSH, 1, &[0x5a; 900]),
                frame(1, CMD_PSH, 1, &[0xa5; 100]),
                frame(1, CMD_FIN, 1, &[]),
            ],
        ),
    ));

    // Version 2, including a window update and the echo path that consumes it.
    seeds.push((
        "v2_syn_psh_upd".into(),
        seed(
            v2_server,
            vec![
                frame(2, CMD_SYN, 1, &[]),
                frame(2, CMD_PSH, 1, b"v2 data"),
                frame(2, CMD_UPD, 1, UpdHeader::new(7, 65536).as_bytes()),
                frame(2, CMD_FIN, 1, &[]),
            ],
        ),
    ));
    seeds.push((
        "v2_echo_window".into(),
        seed(
            v2_server_echo,
            vec![
                frame(2, CMD_SYN, 1, &[]),
                frame(2, CMD_UPD, 1, UpdHeader::new(0, 16).as_bytes()),
                frame(2, CMD_PSH, 1, &[7; 4096]),
                frame(2, CMD_UPD, 1, UpdHeader::new(4096, 1 << 20).as_bytes()),
            ],
        ),
    ));

    // A client session: the peer opens even ids.
    seeds.push((
        "v1_client_peer_opens".into(),
        seed(
            v1_client,
            vec![
                frame(1, CMD_SYN, 2, &[]),
                frame(1, CMD_PSH, 2, b"from the server"),
                frame(1, CMD_NOP, 0, &[]),
            ],
        ),
    ));

    // Protocol errors (DECISIONS V01 and the version check).
    seeds.push((
        "err_wrong_version".into(),
        seed(v1_server, vec![frame(9, CMD_SYN, 1, &[])]),
    ));
    seeds.push((
        "err_unknown_cmd".into(),
        seed(v1_server, vec![frame(1, 99, 1, &[])]),
    ));
    seeds.push((
        "err_syn_with_payload".into(),
        seed(v1_server, vec![frame(1, CMD_SYN, 1, b"nope")]),
    ));
    seeds.push((
        "err_nop_with_payload".into(),
        seed(v1_server, vec![frame(1, CMD_NOP, 0, b"nope")]),
    ));
    seeds.push((
        "err_upd_on_v1".into(),
        seed(
            v1_server,
            vec![
                frame(1, CMD_SYN, 1, &[]),
                frame(1, CMD_UPD, 1, UpdHeader::new(1, 2).as_bytes()),
            ],
        ),
    ));
    seeds.push((
        "err_upd_wrong_length".into(),
        seed(
            v2_server,
            vec![frame(2, CMD_SYN, 1, &[]), frame(2, CMD_UPD, 1, b"short")],
        ),
    ));

    // A PSH whose length field promises more than follows, and a zero-length PSH.
    let mut truncated = v1_server.to_vec();
    truncated.extend_from_slice(&frame(1, CMD_SYN, 1, &[]));
    truncated.extend_from_slice(RawHeader::new(1, CMD_PSH, 65535, 1).as_bytes());
    truncated.extend_from_slice(b"only a few bytes");
    seeds.push(("psh_truncated".into(), truncated));
    seeds.push((
        "psh_zero_length".into(),
        seed(
            v1_server,
            vec![frame(1, CMD_PSH, 1, &[]), frame(1, CMD_SYN, 1, &[])],
        ),
    ));

    // Data for a stream that was never opened, and a FIN for one that does not exist.
    seeds.push((
        "unknown_stream".into(),
        seed(
            v1_server,
            vec![
                frame(1, CMD_PSH, 7, b"nobody is listening"),
                frame(1, CMD_FIN, 7, &[]),
            ],
        ),
    ));

    // Many streams, and a duplicate SYN for one of them.
    let mut many = Vec::new();
    for sid in 1..40u32 {
        many.push(frame(1, CMD_SYN, sid, &[]));
    }
    many.push(frame(1, CMD_SYN, 1, &[]));
    seeds.push(("many_syn".into(), seed(v1_server, many)));

    // A 1 KiB token bucket with more data than fits: the receive loop has to wait for the
    // reader to return tokens.
    let mut flood = vec![frame(1, CMD_SYN, 1, &[])];
    for _ in 0..8 {
        flood.push(frame(1, CMD_PSH, 1, &[0x42; 1000]));
    }
    flood.push(frame(1, CMD_FIN, 1, &[]));
    seeds.push(("starved_bucket".into(), seed(v1_starved, flood)));

    // Keepalive on, so the session writes NOPs while it reads.
    seeds.push((
        "keepalive_nops".into(),
        seed(
            v1_keepalive,
            vec![
                frame(1, CMD_NOP, 0, &[]),
                frame(1, CMD_SYN, 1, &[]),
                frame(1, CMD_PSH, 1, b"tick"),
            ],
        ),
    ));

    seeds
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seeds are what the fuzzer starts from: every one of them must run cleanly.
    #[test]
    fn smux_recv_seeds_run_clean() {
        for (name, data) in smux_recv_handcrafted_seeds() {
            eprintln!("seed {name} ({} bytes)", data.len());
            smux_recv(&data);
        }
    }

    /// Short and malformed inputs, including the ones shorter than the selector.
    #[test]
    fn smux_recv_handles_short_and_random_input() {
        smux_recv(&[]);
        smux_recv(&[0]);
        smux_recv(&[0, 0]);
        // Every selector combination over one small body.
        let body = b"\x01\x00\x00\x00\x01\x00\x00\x00 trailing";
        for sel in 0..=255u8 {
            for chunk in [0u8, 1, 33, 0xFF] {
                let mut data = vec![sel, chunk];
                data.extend_from_slice(body);
                smux_recv(&data);
            }
        }
        // A deterministic pseudo-random stream.
        let mut x = 0x1234_5678_9abc_def0u64;
        let mut data = vec![0u8; 4096];
        for b in &mut data {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (x >> 33) as u8;
        }
        for start in [0usize, 7, 123, 1000] {
            smux_recv(&data[start..]);
        }
    }

    /// The selector encoding round-trips, and every configuration it produces verifies.
    #[test]
    fn selector_round_trips() {
        for version in [1, 2] {
            for bucket in 0..4u8 {
                for frame in 0..4u8 {
                    let [sel, chunk] =
                        Selector::encode(version, true, true, bucket, frame, true, 5);
                    let s = Selector::decode(sel, chunk);
                    assert_eq!(s.config.version, version);
                    assert!(s.client && s.echo);
                    assert!(!s.config.keep_alive_disabled);
                    assert_eq!(s.config.max_receive_buffer, BUCKETS[usize::from(bucket)]);
                    assert_eq!(s.config.max_frame_size, FRAME_SIZES[usize::from(frame)]);
                    assert_eq!(s.chunk, Some(6));
                    crate::mux::verify_config(&s.config).expect("selector config verifies");
                }
            }
        }
        let [sel, chunk] = Selector::encode(1, false, false, 0, 0, false, 0xFF);
        let s = Selector::decode(sel, chunk);
        assert_eq!(s.chunk, None);
        assert!(!s.client && !s.echo && s.config.keep_alive_disabled);
    }

    /// Writes the seed corpus into the source tree:
    /// `cargo test -p kcptun-smux --lib write_smux_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore = "writes the fuzz seed corpus into the source tree"]
    fn write_smux_fuzz_seeds() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/smux_recv");
        if dir.exists() {
            std::fs::remove_dir_all(&dir).expect("remove old seeds");
        }
        std::fs::create_dir_all(&dir).expect("create seed dir");
        for (name, data) in smux_recv_handcrafted_seeds() {
            std::fs::write(dir.join(format!("hand_{name}")), data).expect("write seed");
        }
    }

    /// The committed seed corpus (`crates/smux/fuzz/seeds/smux_recv/`) is exactly what
    /// [`write_smux_fuzz_seeds`] generates. The files are read at test time on purpose (this
    /// checks the on-disk corpus that libFuzzer reads, not embedded test data).
    #[test]
    fn smux_fuzz_seed_files_up_to_date() {
        const HINT: &str = "smux_recv fuzz seeds are stale; regenerate them with \
            `cargo test -p kcptun-smux --lib write_smux_fuzz_seeds -- --ignored`";
        let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        // Test executables also run outside the source tree (tools/lab/remote-test.sh).
        if !crate_dir.join("Cargo.toml").exists() {
            eprintln!("smux_fuzz_seed_files_up_to_date: source tree not available, skipping");
            return;
        }
        let dir = crate_dir.join("fuzz/seeds/smux_recv");
        let want: std::collections::BTreeMap<String, Vec<u8>> = smux_recv_handcrafted_seeds()
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
