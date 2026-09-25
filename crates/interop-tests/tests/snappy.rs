//! Snappy framed-stream interoperability with the Go reference (plan step 07.1).
//!
//! `tools/gointerop/cmd/snappycheck` links the pinned `golang/snappy` v1.0.0 and kcptun's own
//! `CompStream` (a verbatim copy), so it frames and unframes exactly as kcptun does:
//!
//! | Test | Go side | Rust side |
//! |---|---|---|
//! | `interop_snappy_rust_writer_go_decoder` | `snappycheck decode` | [`CompStream`] writer |
//! | `interop_snappy_go_encoder_rust_reader` | `snappycheck encode` | [`CompStream`] reader |
//!
//! The second test also compares the **bytes**: for the same sequence of writes, the Rust
//! writer must produce byte-for-byte what Go's `CompStream.Write` + `Flush` produces, which is
//! what makes a mixed tunnel work at all.
//!
//! Needs the Go binaries (`tools/fetch-reference.sh`), hence `#[ignore]`:
//!
//! ```sh
//! cargo test -p kcptun-interop-tests --test snappy -- --ignored --nocapture
//! ```

use std::fs::File;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use kcptun_interop_tests::go_bin;
use kcptun_smux::SmuxConn;
use kcptun_std::comp::CompStream;
use sha2::{Digest, Sha256};

/// Longest a `snappycheck` run may take. It reads a file and exits, so this only bounds a hang.
const RUN_TIMEOUT: Duration = Duration::from_secs(60);

/// A connection that collects everything written to it and replays a fixed byte string.
struct MemConn {
    to_read: Mutex<(Vec<u8>, usize)>,
    read_size: usize,
    written: Mutex<Vec<u8>>,
}

impl MemConn {
    fn new(data: Vec<u8>, read_size: usize) -> MemConn {
        MemConn {
            to_read: Mutex::new((data, 0)),
            read_size,
            written: Mutex::new(Vec::new()),
        }
    }
}

impl SmuxConn for MemConn {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut state = self.to_read.lock().expect("lock");
        let (data, pos) = &mut *state;
        let n = buf.len().min(data.len() - *pos).min(self.read_size);
        buf[..n].copy_from_slice(&data[*pos..*pos + n]);
        *pos += n;
        Ok(n)
    }

    async fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        self.written.lock().expect("lock").extend_from_slice(buf);
        Ok(())
    }

    async fn close(&self) -> io::Result<()> {
        Ok(())
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        None
    }
}

/// A single-threaded runtime: the streams here never wait for another task.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

/// Frames `data` with a Rust `CompStream`, writing it in chunks whose sizes cycle through
/// `chunks`: the same script `snappycheck encode -chunk` follows.
fn rust_encode(data: &[u8], chunks: &[usize]) -> Vec<u8> {
    runtime().block_on(async {
        let stream = CompStream::new(MemConn::new(Vec::new(), usize::MAX));
        let mut rest = data;
        let mut i = 0;
        while !rest.is_empty() {
            let n = chunks[i % chunks.len()].min(rest.len());
            stream.write_all(&rest[..n]).await.expect("write");
            rest = &rest[n..];
            i += 1;
        }
        stream.inner().written.lock().expect("lock").clone()
    })
}

/// Decodes a framed stream with a Rust `CompStream`, reading `read_size` bytes at a time.
fn rust_decode(framed: &[u8], read_size: usize) -> io::Result<Vec<u8>> {
    runtime().block_on(async {
        let stream = CompStream::new(MemConn::new(framed.to_vec(), read_size));
        let mut out = Vec::new();
        let mut buf = vec![0u8; 9000];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Ok(out);
            }
            out.extend_from_slice(&buf[..n]);
        }
    })
}

/// Lower-case hex SHA-256, as the Go peers report it.
fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Runs `snappycheck <args>` with `stdin` from `input` and stdout to `output`, and returns its
/// exit code together with whatever it wrote to stderr.
fn run_snappycheck(bin: &Path, args: &[&str], input: &Path, output: &Path) -> (i32, String) {
    let stdin = File::open(input).expect("open input");
    let stdout = File::create(output).expect("create output");
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::piped());
    // macOS spawns inherit every descriptor that is not yet close-on-exec; the guard keeps a
    // socket another test thread is creating out of this child (see kcptun_testkit).
    let mut child = {
        let _fd = kcptun_testkit::socket_creation_guard();
        cmd.spawn().expect("spawn snappycheck")
    };

    let deadline = Instant::now() + RUN_TIMEOUT;
    let status = loop {
        match child.try_wait().expect("wait") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("snappycheck {args:?} did not finish within {RUN_TIMEOUT:?}");
            }
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    };
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        use std::io::Read;
        let _ = pipe.read_to_string(&mut stderr);
    }
    (status.code().unwrap_or(-1), stderr)
}

/// What `snappycheck decode` prints.
#[derive(serde::Deserialize)]
struct DecodeReport {
    ok: bool,
    len: u64,
    sha256: String,
    #[serde(default)]
    error: String,
}

/// Payloads worth sending through the framing, with the write scripts to send them with.
///
/// `chunks` cycles, exactly like `snappycheck -chunk`; 8200 is one smux frame (8192 payload
/// plus the 8-byte header) and 70000 spans two snappy chunks.
fn cases() -> Vec<(&'static str, Vec<u8>, Vec<usize>)> {
    vec![
        ("empty", Vec::new(), vec![8200]),
        ("text/1", text(1), vec![8200]),
        ("text/8200", text(8200), vec![8200]),
        ("text/70000", text(70000), vec![70000]),
        ("text/1mib/frames", text(1 << 20), vec![8200]),
        ("random/8200", random(8200, 1), vec![8200]),
        ("random/70000", random(70000, 2), vec![70000]),
        ("random/1mib/frames", random(1 << 20, 3), vec![8200]),
        (
            "mixed/uneven",
            mixed(300_000),
            vec![1, 7, 65535, 65536, 65537, 4096],
        ),
        ("mixed/one_write", mixed(200_000), vec![200_000]),
        ("zeros/65536", vec![0u8; 65536], vec![65536]),
    ]
}

/// Compressible filler.
fn text(len: usize) -> Vec<u8> {
    b"the quick brown fox jumps over the lazy dog. "
        .iter()
        .copied()
        .cycle()
        .take(len)
        .collect()
}

/// Incompressible filler (a 64-bit xorshift).
fn random(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// Alternating runs of compressible and incompressible bytes, so both chunk types appear.
fn mixed(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut seed = 5u64;
    while out.len() < len {
        out.extend_from_slice(&text(4096));
        out.extend_from_slice(&random(4096, seed));
        seed += 1;
    }
    out.truncate(len);
    out
}

/// The Rust writer's bytes must decode in Go, with the same length and SHA-256.
#[test]
#[ignore = "needs reference/bin (tools/fetch-reference.sh)"]
fn interop_snappy_rust_writer_go_decoder() {
    let bin = go_bin("snappycheck").unwrap_or_else(|e| panic!("{e}"));
    let dir = tempfile::tempdir().expect("tempdir");

    for (name, payload, chunks) in cases() {
        let framed = rust_encode(&payload, &chunks);
        let input = dir.path().join("framed.bin");
        let report_path = dir.path().join("report.json");
        let decoded_path = dir.path().join("decoded.bin");
        std::fs::write(&input, &framed).expect("write framed");

        let (code, stderr) = run_snappycheck(
            &bin,
            &["decode", "-o", decoded_path.to_str().expect("utf-8")],
            &input,
            &report_path,
        );
        let report_text = std::fs::read_to_string(&report_path).expect("read report");
        assert_eq!(
            code, 0,
            "{name}: snappycheck decode failed: {report_text}{stderr}"
        );
        let report: DecodeReport = serde_json::from_str(&report_text)
            .unwrap_or_else(|e| panic!("{name}: report {report_text:?}: {e}"));
        assert!(report.ok, "{name}: {}", report.error);
        assert_eq!(report.len, payload.len() as u64, "{name}: decoded length");
        assert_eq!(
            report.sha256,
            sha256_hex(&payload),
            "{name}: decoded sha256"
        );
        assert_eq!(
            std::fs::read(&decoded_path).expect("read decoded"),
            payload,
            "{name}: decoded bytes"
        );
        println!(
            "  rust -> go  {name:<20} {} -> {} bytes",
            payload.len(),
            framed.len()
        );
    }
}

/// Go's framed bytes must be what the Rust writer produces for the same writes, and the Rust
/// reader must decode them.
#[test]
#[ignore = "needs reference/bin (tools/fetch-reference.sh)"]
fn interop_snappy_go_encoder_rust_reader() {
    let bin = go_bin("snappycheck").unwrap_or_else(|e| panic!("{e}"));
    let dir = tempfile::tempdir().expect("tempdir");

    for (name, payload, chunks) in cases() {
        let input = dir.path().join("plain.bin");
        let framed_path = dir.path().join("framed.bin");
        std::fs::write(&input, &payload).expect("write plain");

        let chunk_arg = chunks
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let (code, stderr) = run_snappycheck(
            &bin,
            &["encode", "-chunk", &chunk_arg],
            &input,
            &framed_path,
        );
        assert_eq!(code, 0, "{name}: snappycheck encode failed: {stderr}");
        let go_framed = std::fs::read(&framed_path).expect("read framed");

        // Byte-for-byte identical framing, not just a stream Go can read back.
        let rust_framed = rust_encode(&payload, &chunks);
        assert_eq!(
            sha256_hex(&rust_framed),
            sha256_hex(&go_framed),
            "{name}: framed bytes differ (rust {} bytes, go {} bytes)",
            rust_framed.len(),
            go_framed.len()
        );

        // And Go's bytes decode here, fed in small pieces.
        for read_size in [usize::MAX, 1, 1337] {
            let decoded = rust_decode(&go_framed, read_size)
                .unwrap_or_else(|e| panic!("{name}: rust decode (read_size {read_size}): {e}"));
            assert_eq!(decoded.len(), payload.len(), "{name}: decoded length");
            assert_eq!(
                sha256_hex(&decoded),
                sha256_hex(&payload),
                "{name}: decoded bytes"
            );
        }
        println!(
            "  go -> rust  {name:<20} {} -> {} bytes",
            payload.len(),
            go_framed.len()
        );
    }
}
