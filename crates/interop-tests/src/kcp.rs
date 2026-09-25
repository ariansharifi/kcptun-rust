//! The Rust half of the raw-KCP interop suite: an echo server and an echo client built on
//! `kcptun-kcp`, configured exactly like the Go `kcpecho` peer (`tools/gointerop/cmd/kcpecho`),
//! plus the [`KcpCase`] that describes one configuration for both sides.
//!
//! `kcpecho` is kcptun's KCP layer with nothing above it: no smux, no compression, no QPP. Its
//! flags mirror kcptun's knobs, the key is derived with kcptun's PBKDF2 and the cipher is chosen
//! with kcptun's `SelectBlockCrypt`, and the session options are applied in kcptun's order. The
//! Rust peers here do the same through [`kcptun_std::crypt`] and [`kcptun_kcp`], so a mismatch
//! in a test is a mismatch in the port, not in the harness.
//!
//! | Direction | Server | Client |
//! |---|---|---|
//! | Rust → Go | `kcpecho server` ([`crate::kcpecho::start_server`]) | [`run_rust_client`] |
//! | Go → Rust | [`RustEchoServer`] | `kcpecho client` ([`crate::kcpecho::run_client`]) |
//!
//! Both clients send the same deterministic stream (testkit's `PrngStream`, which is Go's
//! `rand.NewPCG(seed, 0)` word by word), verify the echo byte for byte and report its SHA-256,
//! so the two directions are compared against the same expected hash.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use kcptun_kcp::crypt::PacketCrypt;
use kcptun_kcp::{Listener, UdpSession};
use kcptun_std::crypt::{derive_pass, select_block_crypt};
use kcptun_testkit::servers::PrngStream;
use sha2::{Digest, Sha256};

use crate::matrix::{MANUAL_MODE_DEFAULTS, mode_params};

/// `kcpecho`'s default `-key`, and the one every test uses.
// Go: tools/gointerop/cmd/kcpecho/main.go:kcpFlags.register() (`-key`)
pub const DEFAULT_KEY: &str = "it's a secrect";

/// `kcpecho`'s default `-sockbuf`, kcptun's own default too.
// Go: tools/gointerop/cmd/kcpecho/main.go:kcpFlags.register() (`-sockbuf`)
pub const SOCKBUF: usize = 4 * 1024 * 1024;

/// `kcpecho`'s echo buffer: larger than the biggest KCP message, so message mode returns whole
/// messages and stream mode is echoed unchanged.
// Go: tools/gointerop/cmd/kcpecho/main.go:echoBufSize
pub const ECHO_BUF_SIZE: usize = 512 * 1024;

/// Bytes per `write` call in [`run_rust_client`], `kcpecho`'s `-chunk` default.
// Go: tools/gointerop/cmd/kcpecho/main.go:runClient() (`-chunk`)
pub const DEFAULT_CHUNK: usize = 32 * 1024;

/// Every `-crypt` method kcptun accepts, in the order its `-crypt` usage string lists them
/// (`"aes, aes-128, aes-128-gcm, aes-192, salsa20, ..."`). `null` means no packet crypto at all;
/// every other name adds the 16-byte nonce and the CRC-32 (or, for `aes-128-gcm`, the AEAD nonce
/// and tag).
// Go: kcptun std/crypt.go:SelectBlockCrypt(), client/main.go:89 (cli flag "crypt" Usage)
pub const CRYPT_MODES: [&str; 15] = [
    "aes",
    "aes-128",
    "aes-128-gcm",
    "aes-192",
    "salsa20",
    "blowfish",
    "twofish",
    "cast5",
    "3des",
    "tea",
    "xtea",
    "xor",
    "sm4",
    "none",
    "null",
];

/// One raw-KCP configuration, for both the Go peer (through [`kcpecho_args`](Self::kcpecho_args))
/// and the Rust peers (through [`block`](Self::block) and the session setters).
///
/// The knobs that do not change the wire format or the session layout keep `kcpecho`'s defaults
/// and are not modelled: `-stream` (always on, as in kcptun), `-writedelay` (off), `-dscp` (0),
/// `-sockbuf` ([`SOCKBUF`]) and `-ratelimit` (0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KcpCase {
    /// `-crypt`.
    pub crypt: String,
    /// `-key`.
    pub key: String,
    /// `-ds`: FEC data shards (0 disables FEC).
    pub ds: u32,
    /// `-ps`: FEC parity shards.
    pub ps: u32,
    /// `-mtu`.
    pub mtu: u32,
    /// `-sndwnd`, on both sides.
    pub sndwnd: u32,
    /// `-rcvwnd`, on both sides.
    pub rcvwnd: u32,
    /// `-acknodelay`.
    pub acknodelay: bool,
    /// kcptun's `-mode`, expanded to `-nodelay -interval -resend -nc`.
    pub mode: String,
}

impl Default for KcpCase {
    /// kcptun's defaults with the kcptun **client**'s windows (128/512), which is what
    /// `kcpecho client` defaults to.
    // Go: kcptun client/main.go: cli flag Values; tools/gointerop/cmd/kcpecho/main.go
    fn default() -> Self {
        KcpCase {
            crypt: "aes".into(),
            key: DEFAULT_KEY.into(),
            ds: 10,
            ps: 3,
            mtu: 1350,
            sndwnd: 128,
            rcvwnd: 512,
            acknodelay: false,
            mode: "fast".into(),
        }
    }
}

impl KcpCase {
    /// kcptun's defaults; same as [`KcpCase::default`].
    pub fn new() -> Self {
        KcpCase::default()
    }

    /// Sets `-crypt`.
    pub fn crypt(mut self, crypt: impl Into<String>) -> Self {
        self.crypt = crypt.into();
        self
    }

    /// Sets `-ds` and `-ps`.
    pub fn fec(mut self, ds: u32, ps: u32) -> Self {
        self.ds = ds;
        self.ps = ps;
        self
    }

    /// Sets `-mtu`.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = mtu;
        self
    }

    /// Sets `-sndwnd` and `-rcvwnd`.
    pub fn windows(mut self, sndwnd: u32, rcvwnd: u32) -> Self {
        self.sndwnd = sndwnd;
        self.rcvwnd = rcvwnd;
        self
    }

    /// Sets `-acknodelay`.
    pub fn acknodelay(mut self, on: bool) -> Self {
        self.acknodelay = on;
        self
    }

    /// Sets `-mode`.
    pub fn mode(mut self, mode: impl Into<String>) -> Self {
        self.mode = mode.into();
        self
    }

    /// `(nodelay, interval, resend, nc)` of [`mode`](Self::mode), or kcptun's flag defaults for
    /// `manual` and unknown names.
    pub fn nodelay_params(&self) -> [u32; 4] {
        mode_params(&self.mode).unwrap_or(MANUAL_MODE_DEFAULTS)
    }

    /// Flags for `kcpecho server` and `kcpecho client` (the address flags are the caller's
    /// business). Every knob this type models is passed explicitly, so a change to `kcpecho`'s
    /// defaults cannot silently desynchronise the two sides; the knobs it does not model
    /// (`-stream`, `-writedelay`, `-dscp`, `-sockbuf`, `-ratelimit`) keep `kcpecho`'s defaults on
    /// the Go side and are mirrored by the constants above on the Rust side.
    // Go: tools/gointerop/cmd/kcpecho/main.go:kcpFlags.register()
    pub fn kcpecho_args(&self) -> Vec<String> {
        let [nodelay, interval, resend, nc] = self.nodelay_params();
        let mut a: Vec<String> = vec![
            "-crypt".into(),
            self.crypt.clone(),
            "-key".into(),
            self.key.clone(),
            "-ds".into(),
            self.ds.to_string(),
            "-ps".into(),
            self.ps.to_string(),
            "-mtu".into(),
            self.mtu.to_string(),
            "-sndwnd".into(),
            self.sndwnd.to_string(),
            "-rcvwnd".into(),
            self.rcvwnd.to_string(),
            "-nodelay".into(),
            nodelay.to_string(),
            "-interval".into(),
            interval.to_string(),
            "-resend".into(),
            resend.to_string(),
            "-nc".into(),
            nc.to_string(),
        ];
        if self.acknodelay {
            // A Go bool flag is set by its bare name; the default is false, so it is only ever
            // passed when on.
            a.push("-acknodelay".into());
        }
        a
    }

    /// The packet crypto for the Rust side: kcptun's PBKDF2 over [`key`](Self::key) and then
    /// `SelectBlockCrypt`, exactly what `kcpecho` does with `std.DeriveKey`/`std.SelectBlockCrypt`.
    // Go: tools/gointerop/cmd/kcpecho/main.go:kcpFlags.block()
    pub fn block(&self) -> Option<PacketCrypt> {
        select_block_crypt(&self.crypt, &derive_pass(&self.key)).block
    }

    /// The cipher name after kcptun's fallback for unknown `-crypt` values; this is what the
    /// `kcpecho` report prints as `crypt`.
    pub fn effective_crypt(&self) -> &'static str {
        select_block_crypt(&self.crypt, &derive_pass(&self.key)).method
    }

    /// A compact, unique, deterministic description for test output, e.g.
    /// `crypt=aes fec=10/3 mtu=1350 wnd=128/512 acknodelay=off mode=fast`.
    pub fn label(&self) -> String {
        format!(
            "crypt={} fec={}/{} mtu={} wnd={}/{} acknodelay={} mode={}",
            self.crypt,
            self.ds,
            self.ps,
            self.mtu,
            self.sndwnd,
            self.rcvwnd,
            if self.acknodelay { "on" } else { "off" },
            self.mode,
        )
    }
}

impl std::fmt::Display for KcpCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label())
    }
}

// ---------------------------------------------------------------------------------------------
// Rust echo server (the counterpart of `kcpecho server`)
// ---------------------------------------------------------------------------------------------

/// A running Rust KCP echo server. Dropping it (or [`close`](Self::close)) stops the accept task
/// and closes the listener, which releases every accepted session.
pub struct RustEchoServer {
    listener: Arc<Listener>,
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl RustEchoServer {
    /// Binds `listen` and starts echoing, applying `case` exactly as `kcpecho server` does:
    /// listener options first, then the per-session options in kcptun's `serveListener` order.
    ///
    /// `idle` bounds both reads and writes of a session, so a session whose client has gone is
    /// reaped (KCP has no close handshake); `None` never reaps.
    // Go: tools/gointerop/cmd/kcpecho/main.go:runServer(), echo()
    pub fn start(listen: SocketAddr, case: &KcpCase, idle: Option<Duration>) -> io::Result<Self> {
        let block = case.block();
        let listener = {
            // A listener bound on a fixed port while other test threads spawn Go peers must
            // hold the testkit fd lock (see `kcptun_testkit::socket_creation_guard`).
            let _fd = kcptun_testkit::socket_creation_guard();
            Listener::listen_with_options(
                &listen.to_string(),
                block,
                case.ds as isize,
                case.ps as isize,
            )?
        };
        let addr = listener.addr()?;
        // Go logs and carries on when any of the three fails.
        let _ = listener.set_dscp(0);
        let _ = listener.set_read_buffer(SOCKBUF);
        let _ = listener.set_write_buffer(SOCKBUF);

        let case = case.clone();
        let task = tokio::spawn({
            let listener = Arc::clone(&listener);
            async move {
                while let Ok(session) = listener.accept().await {
                    let [nodelay, interval, resend, nc] = case.nodelay_params();
                    session.set_stream_mode(true);
                    session.set_write_delay(false);
                    session.set_no_delay(
                        nodelay as isize,
                        interval as isize,
                        resend as isize,
                        nc as isize,
                    );
                    session.set_mtu(case.mtu as isize);
                    session.set_window_size(case.sndwnd as isize, case.rcvwnd as isize);
                    session.set_ack_no_delay(case.acknodelay);
                    session.set_rate_limit(0);
                    tokio::spawn(echo(session, idle));
                }
            }
        });
        Ok(RustEchoServer {
            listener,
            addr,
            task,
        })
    }

    /// The address the listener is bound to.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Number of sessions the listener currently holds.
    pub fn session_count(&self) -> usize {
        self.listener.session_count()
    }

    /// Stops accepting and closes the listener.
    pub fn close(self) {
        drop(self);
    }
}

impl Drop for RustEchoServer {
    fn drop(&mut self) {
        let _ = self.listener.close();
        self.task.abort();
    }
}

/// Writes back everything read, until an error or the idle timeout, then closes the session like
/// Go's `defer conn.Close()`, which drops it from the listener's session map, decrements
/// `CurrEstab` and queues the final flush of Deviation V05.
// Go: tools/gointerop/cmd/kcpecho/main.go:echo()
async fn echo(conn: Arc<UdpSession>, idle: Option<Duration>) {
    let mut buf = vec![0u8; ECHO_BUF_SIZE];
    loop {
        if let Some(idle) = idle {
            let _ = conn.set_deadline(Some(tokio::time::Instant::now() + idle));
        }
        let Ok(n) = conn.read(&mut buf).await else {
            break;
        };
        if n > 0 && conn.write(&buf[..n]).await.is_err() {
            break;
        }
    }
    let _ = conn.close();
}

// ---------------------------------------------------------------------------------------------
// Rust echo client (the counterpart of `kcpecho client`)
// ---------------------------------------------------------------------------------------------

/// Parameters of one [`run_rust_client`] call, mirroring `kcpecho client`'s flags.
#[derive(Clone, Copy, Debug)]
pub struct RustClientRun {
    /// `-remote`.
    pub remote: SocketAddr,
    /// `-bytes`.
    pub bytes: u64,
    /// `-seed`.
    pub seed: u64,
    /// `-chunk`.
    pub chunk: usize,
    /// `-timeout`, the session deadline covering the whole run.
    pub timeout: Duration,
}

impl RustClientRun {
    /// `bytes` bytes with seed 1, 32 KiB writes and a 60 s deadline.
    pub fn new(remote: SocketAddr, bytes: u64) -> Self {
        RustClientRun {
            remote,
            bytes,
            seed: 1,
            chunk: DEFAULT_CHUNK,
            timeout: Duration::from_secs(60),
        }
    }

    /// Sets the stream seed.
    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Sets the deadline.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// What [`run_rust_client`] found, with the same fields as `kcpecho`'s JSON report so that the
/// two directions can be asserted the same way.
// Go: tools/gointerop/cmd/kcpecho/main.go:clientReport
#[derive(Clone, Debug, PartialEq)]
pub struct RustClientReport {
    /// True if the whole stream came back unchanged and nothing failed.
    pub ok: bool,
    /// Bytes sent.
    pub bytes: u64,
    /// Bytes of echo received (and verified up to the first mismatch).
    pub received: u64,
    /// Wall time from dial to the end of the echo.
    pub duration_ms: u128,
    /// SHA-256 of the received echo.
    pub sha256: String,
    /// SHA-256 of the sent stream.
    pub expected_sha256: String,
    /// Effective cipher after kcptun's fallback for unknown names.
    pub crypt: String,
    /// Offset of the first wrong byte, -1 if none.
    pub mismatch_offset: i64,
    /// The error that ended the run, if any.
    pub error: Option<String>,
}

/// Checks received bytes against the expected stream as they arrive and hashes them, recording
/// the first mismatching offset.
// Go: tools/gointerop/internal/peer/stream.go:Verifier
struct Verifier {
    want: PrngStream,
    scratch: Vec<u8>,
    hash: Sha256,
    received: u64,
    expected: u64,
    mismatch: i64,
}

impl Verifier {
    fn new(seed: u64, n: u64) -> Verifier {
        Verifier {
            want: PrngStream::new(seed, n),
            scratch: Vec::new(),
            hash: Sha256::new(),
            received: 0,
            expected: n,
            mismatch: -1,
        }
    }

    /// Consumes received bytes; `Err` on the first byte that differs, or when more than `n`
    /// bytes arrive.
    fn write(&mut self, p: &[u8]) -> Result<(), String> {
        if p.is_empty() {
            return Ok(());
        }
        self.hash.update(p);
        if self.received + p.len() as u64 > self.expected {
            if self.mismatch < 0 {
                self.mismatch = self.expected as i64;
            }
            self.received += p.len() as u64;
            return Err(format!(
                "received {} bytes, more than the {} expected",
                self.received, self.expected
            ));
        }
        self.scratch.resize(p.len(), 0);
        let filled = self.want.fill(&mut self.scratch);
        debug_assert_eq!(filled, p.len(), "the expected stream ran out early");
        for (i, (&got, &want)) in p.iter().zip(self.scratch.iter()).enumerate() {
            if got != want {
                let off = self.received + i as u64;
                self.received += p.len() as u64;
                if self.mismatch < 0 {
                    self.mismatch = off as i64;
                }
                return Err(format!(
                    "data mismatch at offset {off}: got {got:#04x}, want {want:#04x}"
                ));
            }
        }
        self.received += p.len() as u64;
        Ok(())
    }

    fn done(&self) -> bool {
        self.mismatch < 0 && self.received == self.expected
    }

    fn sha256(&self) -> String {
        let digest = self.hash.clone().finalize();
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Runs the Rust counterpart of `kcpecho client` against `run.remote`: dial, apply `case` in
/// kcptun's `createConn` order, send the deterministic stream while verifying the echo, and
/// report.
///
/// Must be called from inside a tokio runtime (the session spawns its own tasks). Errors are
/// reported in [`RustClientReport::error`] rather than returned, so a failing case still yields
/// the counters and hashes that say what went wrong.
// Go: tools/gointerop/cmd/kcpecho/main.go:runClient()
pub async fn run_rust_client(run: &RustClientRun, case: &KcpCase) -> RustClientReport {
    let expected_sha256 = PrngStream::sha256_hex(run.seed, run.bytes);
    let crypt = case.effective_crypt().to_string();
    let start = std::time::Instant::now();

    let sess = {
        let _fd = kcptun_testkit::socket_creation_guard();
        UdpSession::dial_with_options(
            &run.remote.to_string(),
            case.block(),
            case.ds as isize,
            case.ps as isize,
        )
    };
    let sess = match sess {
        Ok(s) => s,
        Err(e) => {
            return RustClientReport {
                ok: false,
                bytes: run.bytes,
                received: 0,
                duration_ms: start.elapsed().as_millis(),
                sha256: String::new(),
                expected_sha256,
                crypt,
                mismatch_offset: -1,
                error: Some(format!("dial: {e}")),
            };
        }
    };

    let [nodelay, interval, resend, nc] = case.nodelay_params();
    sess.set_stream_mode(true);
    sess.set_write_delay(false);
    sess.set_no_delay(
        nodelay as isize,
        interval as isize,
        resend as isize,
        nc as isize,
    );
    sess.set_window_size(case.sndwnd as isize, case.rcvwnd as isize);
    sess.set_mtu(case.mtu as isize);
    sess.set_ack_no_delay(case.acknodelay);
    sess.set_rate_limit(0);
    let _ = sess.set_dscp(0);
    let _ = sess.set_read_buffer(SOCKBUF);
    let _ = sess.set_write_buffer(SOCKBUF);

    let deadline = tokio::time::Instant::now() + run.timeout;
    let _ = sess.set_deadline(Some(deadline));

    let writer = tokio::spawn({
        let sess = Arc::clone(&sess);
        let (bytes, seed, chunk) = (run.bytes, run.seed, run.chunk);
        async move {
            let mut src = PrngStream::new(seed, bytes);
            let mut buf = vec![0u8; chunk];
            loop {
                let n = src.fill(&mut buf);
                if n == 0 {
                    return Ok(());
                }
                if let Err(e) = sess.write(&buf[..n]).await {
                    return Err(format!("write: {e}"));
                }
            }
        }
    });

    let mut verifier = Verifier::new(run.seed, run.bytes);
    let mut run_err: Option<String> = None;
    let mut buf = vec![0u8; 64 * 1024];
    while !verifier.done() && run_err.is_none() {
        match sess.read(&mut buf).await {
            Ok(n) => {
                if let Err(e) = verifier.write(&buf[..n]) {
                    run_err = Some(e);
                }
            }
            Err(e) => run_err = Some(format!("read: {e}")),
        }
    }
    if run_err.is_none() {
        run_err = match writer.await {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(e),
            Err(e) => Some(format!("writer task: {e}")),
        };
    } else {
        writer.abort();
    }
    let duration_ms = start.elapsed().as_millis();
    let _ = sess.close();

    RustClientReport {
        ok: run_err.is_none() && verifier.done(),
        bytes: run.bytes,
        received: verifier.received,
        duration_ms,
        sha256: verifier.sha256(),
        expected_sha256,
        crypt,
        mismatch_offset: verifier.mismatch,
        error: run_err,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_case_matches_kcptun_and_kcpecho_defaults() {
        let c = KcpCase::new();
        assert_eq!(c.crypt, "aes");
        assert_eq!((c.ds, c.ps), (10, 3));
        assert_eq!(c.mtu, 1350);
        assert_eq!((c.sndwnd, c.rcvwnd), (128, 512));
        assert!(!c.acknodelay);
        assert_eq!(c.nodelay_params(), [0, 30, 2, 1], "mode fast");
        assert_eq!(
            c.label(),
            "crypt=aes fec=10/3 mtu=1350 wnd=128/512 acknodelay=off mode=fast"
        );
        assert_eq!(c.to_string(), c.label());
    }

    #[test]
    fn kcpecho_args_spell_out_every_knob() {
        let c = KcpCase::new()
            .crypt("salsa20")
            .fec(0, 0)
            .mtu(500)
            .windows(1024, 1024)
            .acknodelay(true)
            .mode("fast3");
        assert_eq!(
            c.kcpecho_args(),
            [
                "-crypt",
                "salsa20",
                "-key",
                DEFAULT_KEY,
                "-ds",
                "0",
                "-ps",
                "0",
                "-mtu",
                "500",
                "-sndwnd",
                "1024",
                "-rcvwnd",
                "1024",
                "-nodelay",
                "1",
                "-interval",
                "10",
                "-resend",
                "2",
                "-nc",
                "1",
                "-acknodelay",
            ]
        );
        assert!(
            !KcpCase::new()
                .kcpecho_args()
                .contains(&"-acknodelay".into()),
            "a bool flag that is off is left out"
        );
    }

    #[test]
    fn every_crypt_mode_builds_a_cipher() {
        for name in CRYPT_MODES {
            let c = KcpCase::new().crypt(name);
            assert_eq!(c.effective_crypt(), name, "no fallback for a known method");
            if name == "null" {
                assert!(c.block().is_none(), "null has no packet crypto");
            } else {
                assert!(c.block().is_some(), "{name} must build");
            }
        }
    }

    #[test]
    fn the_verifier_finds_the_first_wrong_byte() {
        let want = PrngStream::to_vec(7, 64);
        let mut v = Verifier::new(7, 64);
        v.write(&want[..32]).expect("the first half matches");
        assert!(!v.done());
        let mut bad = want[32..].to_vec();
        bad[5] ^= 0xff;
        let err = v.write(&bad).expect_err("a flipped byte must be caught");
        assert!(err.contains("data mismatch at offset 37"), "{err}");
        assert_eq!(v.mismatch, 37);

        let mut v = Verifier::new(7, 64);
        v.write(&want).expect("the whole stream matches");
        assert!(v.done());
        assert_eq!(v.sha256(), PrngStream::sha256_hex(7, 64));
        let err = v
            .write(b"extra")
            .expect_err("more than n bytes must be caught");
        assert!(err.contains("more than the 64 expected"), "{err}");
    }
}
