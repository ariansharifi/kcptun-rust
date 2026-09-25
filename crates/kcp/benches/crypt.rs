//! Packet crypto benchmarks (plan step 02.6), the Rust side of `tools/govectors/bench_test.go`.
//!
//! Every `-crypt` method except `null` (no crypto), on 1350-byte (kcptun's default MTU) and
//! 1500-byte (kcp-go's `mtuLimit`) packets. One iteration encrypts or decrypts one whole packet
//! in place, as the session does; throughput is in packet bytes. The ciphers are keyed exactly
//! like kcptun's `SelectBlockCrypt`: the pass is `PBKDF2-HMAC-SHA1("it's a secrect", "kcp-go",
//! 4096, 32)` and each method takes the same key prefix.
//!
//! `aes-128-gcm`: a packet of length L is `nonce(12) | plaintext(L - 28) | tag(16)`; "encrypt"
//! seals in place, "decrypt" copies a sealed packet into the buffer and opens it in place (the
//! Go bench does the same copy, since opening overwrites the ciphertext).
//!
//! Run: `cargo bench -p kcptun-kcp --bench crypt` (results: `docs/benchmarks/crypto.md`).

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use kcptun_kcp::crypt::{
    AeadCrypt, BlockCrypt, CryptError, PacketCrypt, new_aes_block_crypt, new_aes_gcm_crypt,
    new_blowfish_block_crypt, new_cast5_block_crypt, new_none_block_crypt, new_salsa20_block_crypt,
    new_simple_xor_block_crypt, new_sm4_block_crypt, new_tea_block_crypt,
    new_triple_des_block_crypt, new_twofish_block_crypt, new_xtea_block_crypt,
};

/// kcptun's default `-key` and key derivation (client/main.go, server/main.go).
const DEFAULT_KEY: &str = "it's a secrect";

/// Whole-packet lengths benchmarked.
const PACKET_LENS: [usize; 2] = [1350, 1500];

type NewFn = fn(&[u8]) -> Result<PacketCrypt, CryptError>;

/// Wraps a `BlockCrypt` constructor into a `PacketCrypt` one.
macro_rules! block {
    ($f:path) => {
        (|k: &[u8]| $f(k).map(PacketCrypt::from)) as NewFn
    };
}

/// `(method, key length, constructor)`, as in kcptun std/crypt.go's `cryptMethods` table.
fn methods() -> [(&'static str, usize, NewFn); 14] {
    [
        ("aes", 32, block!(new_aes_block_crypt)),
        ("aes-128", 16, block!(new_aes_block_crypt)),
        ("aes-192", 24, block!(new_aes_block_crypt)),
        ("aes-128-gcm", 16, new_aes_gcm_crypt as NewFn),
        ("salsa20", 32, block!(new_salsa20_block_crypt)),
        ("blowfish", 32, block!(new_blowfish_block_crypt)),
        ("twofish", 32, block!(new_twofish_block_crypt)),
        ("cast5", 16, block!(new_cast5_block_crypt)),
        ("3des", 24, block!(new_triple_des_block_crypt)),
        ("tea", 16, block!(new_tea_block_crypt)),
        ("xtea", 16, block!(new_xtea_block_crypt)),
        ("sm4", 16, block!(new_sm4_block_crypt)),
        ("xor", 32, block!(new_simple_xor_block_crypt)),
        ("none", 32, block!(new_none_block_crypt)),
    ]
}

fn pass() -> [u8; 32] {
    let mut pass = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(DEFAULT_KEY.as_bytes(), b"kcp-go", 4096, &mut pass);
    pass
}

/// A fixed, non-trivial pattern (same as the Go bench; content does not affect speed).
fn pattern(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| (i.wrapping_mul(131).wrapping_add(7)) as u8)
        .collect()
}

fn bench_block(c: &mut Criterion, dir: &str, method: &str, n: usize, block: &BlockCrypt) {
    let mut group = c.benchmark_group(format!("crypt/{dir}"));
    group.throughput(Throughput::Bytes(n as u64));
    let mut buf = pattern(n);
    group.bench_function(BenchmarkId::new(method, n), |b| {
        if dir == "encrypt" {
            b.iter(|| block.encrypt(black_box(&mut buf[..])));
        } else {
            b.iter(|| block.decrypt(black_box(&mut buf[..])));
        }
    });
    group.finish();
}

fn bench_aead(c: &mut Criterion, dir: &str, method: &str, n: usize, aead: &AeadCrypt) {
    let mut group = c.benchmark_group(format!("crypt/{dir}"));
    group.throughput(Throughput::Bytes(n as u64));
    let plain_len = n - AeadCrypt::OVERHEAD;
    let mut buf = pattern(n);
    group.bench_function(BenchmarkId::new(method, n), |b| {
        if dir == "encrypt" {
            b.iter(|| {
                let sealed = aead.seal_in_place(black_box(&mut buf[..]), plain_len);
                black_box(sealed).expect("buffer has room for the tag")
            });
        } else {
            let mut sealed = pattern(n);
            aead.seal_in_place(&mut sealed, plain_len)
                .expect("buffer has room for the tag");
            b.iter(|| {
                buf.copy_from_slice(&sealed);
                let plain = aead.open_in_place(black_box(&mut buf[..]));
                black_box(plain).map(|p| p.len()).expect("valid packet")
            });
        }
    });
    group.finish();
}

fn crypt(c: &mut Criterion) {
    let pass = pass();
    for dir in ["encrypt", "decrypt"] {
        for (method, key_len, new) in methods() {
            let crypt = new(&pass[..key_len]).expect("valid key");
            for n in PACKET_LENS {
                match &crypt {
                    PacketCrypt::Block(b) => bench_block(c, dir, method, n, b),
                    PacketCrypt::Aead(a) => bench_aead(c, dir, method, n, a),
                }
            }
        }
    }
}

criterion_group!(benches, crypt);
criterion_main!(benches);
