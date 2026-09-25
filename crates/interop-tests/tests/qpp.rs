//! Quantum Permutation Pad interoperability with the Go reference (plan step 07.3).
//!
//! `tools/gointerop/cmd/qppcheck` links the pinned `xtaci/qpp` v1.1.25 and drives it exactly as
//! kcptun's `std.QPPPort` does: `qpp.NewQPP([]byte(key), uint16(pads))` for the pad and
//! `qpp.CreatePRNG([]byte(key))` for the direction's generator, both seeded with the **raw
//! `-key`**, then `EncryptWithPRNG` / `DecryptWithPRNG` over stdin in scripted chunk sizes.
//!
//! | Test | What it proves |
//! |---|---|
//! | `interop_qpp_rust_writer_go_decrypt` | Rust [`QppStream`] ciphertext == Go's, and Go decrypts it |
//! | `interop_qpp_go_encrypt_rust_reader` | a Rust [`QppStream`] reader recovers Go's ciphertext |
//! | `interop_qpp_chunkings_agree` | neither side's chunking changes a byte |
//!
//! The chunk sizes differ between the two sides on purpose: a smux stream reframes everything,
//! so the reader never sees the writer's boundaries, and only the position in the stream may
//! select the pad.
//!
//! Needs the Go binaries (`tools/fetch-reference.sh`), hence `#[ignore]`:
//!
//! ```sh
//! cargo test -p kcptun-interop-tests --test qpp -- --ignored --nocapture
//! ```
#![cfg(feature = "qpp")]

use std::fs::File;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use kcptun_interop_tests::go_bin;
use kcptun_std::qpp::{QppStream, QuantumPermutationPad};
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};

/// Longest a `qppcheck` run may take. It reads a file and exits, so this only bounds a hang.
const RUN_TIMEOUT: Duration = Duration::from_secs(60);

/// A single-threaded runtime: the streams here never wait for another task.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
}

/// Hands out `data` in reads whose sizes cycle through `sizes`, like `qppcheck -chunk`.
struct ChunkedReader {
    data: Vec<u8>,
    pos: usize,
    sizes: Vec<usize>,
    i: usize,
}

impl AsyncRead for ChunkedReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let want = me.sizes[me.i % me.sizes.len()];
        me.i += 1;
        let n = want.min(buf.remaining()).min(me.data.len() - me.pos);
        buf.put_slice(&me.data[me.pos..me.pos + n]);
        me.pos += n;
        Poll::Ready(Ok(()))
    }
}

fn pad(key: &str, pads: u16) -> Arc<QuantumPermutationPad> {
    Arc::new(QuantumPermutationPad::new(key.as_bytes(), pads))
}

/// Encrypts `data` with a Rust `QppStream`, writing it in `chunks`-sized pieces.
fn rust_encrypt(key: &str, pads: u16, data: &[u8], chunks: &[usize]) -> Vec<u8> {
    runtime().block_on(async {
        let mut stream = QppStream::new(Vec::<u8>::new(), pad(key, pads), key.as_bytes());
        let mut rest = data;
        let mut i = 0;
        while !rest.is_empty() {
            let n = chunks[i % chunks.len()].min(rest.len());
            stream.write_all(&rest[..n]).await.expect("write");
            rest = &rest[n..];
            i += 1;
        }
        stream.flush().await.expect("flush");
        stream.inner().clone()
    })
}

/// Decrypts `cipher` with a Rust `QppStream`, reading it in `chunks`-sized pieces.
fn rust_decrypt(key: &str, pads: u16, cipher: &[u8], chunks: &[usize]) -> Vec<u8> {
    runtime().block_on(async {
        let reader = ChunkedReader {
            data: cipher.to_vec(),
            pos: 0,
            sizes: chunks.to_vec(),
            i: 0,
        };
        let mut stream = QppStream::new(reader, pad(key, pads), key.as_bytes());
        let mut out = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut out)
            .await
            .expect("read to end");
        out
    })
}

/// Runs `qppcheck <mode>` over `input` and returns what it wrote to stdout.
fn run_qppcheck(
    bin: &Path,
    mode: &str,
    key: &str,
    pads: u16,
    chunks: &str,
    input: &[u8],
) -> Vec<u8> {
    let dir = tempfile::tempdir().expect("tempdir");
    let in_path = dir.path().join("in.bin");
    let out_path = dir.path().join("out.bin");
    std::fs::write(&in_path, input).expect("write input");

    let stdin = File::open(&in_path).expect("open input");
    let stdout = File::create(&out_path).expect("create output");
    let pads = pads.to_string();
    let mut cmd = Command::new(bin);
    cmd.args([mode, "-key", key, "-pads", &pads, "-chunk", chunks])
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::piped());
    // macOS spawns inherit every descriptor that is not yet close-on-exec; the guard keeps a
    // socket another test thread is creating out of this child (see kcptun_testkit).
    let mut child = {
        let _fd = kcptun_testkit::socket_creation_guard();
        cmd.spawn().expect("spawn qppcheck")
    };

    let deadline = Instant::now() + RUN_TIMEOUT;
    let status = loop {
        match child.try_wait().expect("wait") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("qppcheck {mode} did not finish within {RUN_TIMEOUT:?}");
            }
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    };
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        use std::io::Read;
        let _ = pipe.read_to_string(&mut stderr);
    }
    assert_eq!(
        status.code().unwrap_or(-1),
        0,
        "qppcheck {mode} failed: {stderr}"
    );
    std::fs::read(&out_path).expect("read output")
}

/// kcptun's default `-key`: 14 bytes, far below `QPPMinimumSeedLength(8)`, so the seed is
/// PBKDF2-expanded and every pad-derivation chunk comes out the same (progress note 07.2).
const SHORT_KEY: &str = "it's a secrect";

/// A key past the 211-byte minimum, where `seedToChunks` really does cycle over the seed.
fn long_key() -> String {
    // Deterministic, printable and 300 bytes long.
    (0..300u32)
        .map(|i| (b'!' + (i % 90) as u8) as char)
        .collect()
}

/// One interop case: the same payload encrypted on both sides, with deliberately different
/// chunkings.
struct Case {
    /// What an assertion message calls it.
    name: String,
    /// The raw `-key`, the QPP seed.
    key: String,
    /// `-QPPCount`.
    pads: u16,
    /// The plaintext.
    payload: Vec<u8>,
    /// Write/read sizes the Rust `QppStream` is driven with, cycled.
    rust_chunks: Vec<usize>,
    /// `qppcheck -chunk`.
    go_chunks: String,
}

fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    for (kname, key) in [
        ("short_key", SHORT_KEY.to_string()),
        ("long_key", long_key()),
    ] {
        for pads in [7u16, 61, 251] {
            for (pname, payload, rust_chunks, go_chunks) in [
                ("1b", bytes(1, 1), vec![1usize], "1"),
                ("7b", bytes(7, 2), vec![3], "1,2,4"),
                ("1k/whole", bytes(1024, 3), vec![1024], "4096"),
                ("1k/bytewise", bytes(1024, 4), vec![1], "7,1,13"),
                (
                    "64k/uneven",
                    bytes(65536, 5),
                    vec![1, 7, 4095, 65536],
                    "9999,1,5",
                ),
                ("1mib", bytes(1 << 20, 6), vec![8192], "4096,1,32768"),
            ] {
                out.push(Case {
                    name: format!("{kname}/pads={pads}/{pname}"),
                    key: key.clone(),
                    pads,
                    payload,
                    rust_chunks,
                    go_chunks: go_chunks.to_string(),
                });
            }
        }
    }
    out
}

/// Deterministic filler (a 64-bit xorshift), so a failure is reproducible.
fn bytes(len: usize, seed: u64) -> Vec<u8> {
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

/// The Rust writer must produce Go's exact ciphertext, and Go must decrypt it back.
#[test]
#[ignore = "needs reference/bin (tools/fetch-reference.sh)"]
fn interop_qpp_rust_writer_go_decrypt() {
    let bin = go_bin("qppcheck").unwrap_or_else(|e| panic!("{e}"));

    for case in cases() {
        let Case {
            name,
            key,
            pads,
            payload,
            rust_chunks,
            go_chunks,
        } = case;
        let rust_cipher = rust_encrypt(&key, pads, &payload, &rust_chunks);
        let go_cipher = run_qppcheck(&bin, "encrypt", &key, pads, &go_chunks, &payload);
        assert_eq!(
            rust_cipher.len(),
            payload.len(),
            "{name}: QPP must not change the length"
        );
        assert_eq!(rust_cipher, go_cipher, "{name}: ciphertext differs from Go");

        let back = run_qppcheck(&bin, "decrypt", &key, pads, &go_chunks, &rust_cipher);
        assert_eq!(back, payload, "{name}: Go could not decrypt the Rust bytes");
    }
}

/// A Rust reader must recover what Go encrypted, whatever the read sizes are.
#[test]
#[ignore = "needs reference/bin (tools/fetch-reference.sh)"]
fn interop_qpp_go_encrypt_rust_reader() {
    let bin = go_bin("qppcheck").unwrap_or_else(|e| panic!("{e}"));

    for case in cases() {
        let Case {
            name,
            key,
            pads,
            payload,
            rust_chunks,
            go_chunks,
        } = case;
        let go_cipher = run_qppcheck(&bin, "encrypt", &key, pads, &go_chunks, &payload);
        let back = rust_decrypt(&key, pads, &go_cipher, &rust_chunks);
        assert_eq!(back, payload, "{name}: Rust could not decrypt Go's bytes");
    }
}

/// Chunking is invisible on both sides: the pad depends on the stream position alone.
#[test]
#[ignore = "needs reference/bin (tools/fetch-reference.sh)"]
fn interop_qpp_chunkings_agree() {
    let bin = go_bin("qppcheck").unwrap_or_else(|e| panic!("{e}"));
    let key = long_key();
    let payload = bytes(100_000, 42);

    let reference = run_qppcheck(&bin, "encrypt", &key, 61, "100000", &payload);
    for gchunks in ["1", "7", "4096", "1,2,3,5,8,13,21,34"] {
        let go = run_qppcheck(&bin, "encrypt", &key, 61, gchunks, &payload);
        assert_eq!(go, reference, "go chunking {gchunks}");
    }
    for rchunks in [
        vec![100_000usize],
        vec![1],
        vec![7],
        vec![1, 2, 3, 5, 8, 13, 21, 34],
        vec![65535, 1, 4096],
    ] {
        let rust = rust_encrypt(&key, 61, &payload, &rchunks);
        assert_eq!(rust, reference, "rust chunking {rchunks:?}");
        let back = rust_decrypt(&key, 61, &reference, &rchunks);
        assert_eq!(back, payload, "rust decrypt chunking {rchunks:?}");
    }
}
