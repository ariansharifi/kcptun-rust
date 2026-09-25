//! Four AES-128-GCM backends behind one packet-shaped API, for the plan 12.2b evaluation.
//!
//! All of them do exactly what `kcptun_kcp::crypt::AeadCrypt` does, so the timings are
//! comparable with `crates/kcp/benches/crypt.rs` and with Go's `BenchmarkCrypt/*/aes-128-gcm`:
//! a packet of length `L` is `nonce(12) | AES-128-GCM(plaintext) | tag(16)`, there is no
//! additional data, and both directions work in place.
//!
//! - [`RustCryptoGcm`]  — `aes-gcm` 0.11, what the port ships today (DECISIONS D13).
//! - [`RingGcm`]        — `ring` 0.17, BoringSSL assembly.
//! - [`AwsLcGcm`]       — `aws-lc-rs` 1.18, AWS-LC (BoringSSL fork) assembly.
//! - [`FusedGcm`]       — our own single-pass AES-CTR + GHASH over the RustCrypto primitives.
//!
//! AES-GCM is fully specified, so a correct backend is a byte-for-byte replacement: the tests
//! below check all four against each other over a length sweep and against the published
//! GCM known answers. The conclusions are in `docs/benchmarks/crypto.md`.

use aes::Aes128;
use aes::cipher::{
    Array, BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser,
    KeyInit, ParBlocks, consts::U16,
};
use ghash::GHash;
use ghash::universal_hash::UniversalHash;

/// Nonce length, at the front of every packet.
pub const NONCE: usize = 12;
/// Tag length, appended to the ciphertext.
pub const TAG: usize = 16;

/// One AES-128-GCM backend, in the shape `kcptun_kcp::crypt::AeadCrypt` uses.
pub trait PacketAead {
    /// Keys the backend with a 16-byte AES-128 key.
    fn new(key: &[u8; 16]) -> Self;

    /// `buf[..len]` is `nonce(12) | plaintext`; afterwards `buf[..len + 16]` is
    /// `nonce | ciphertext | tag`. `buf` must have room for the tag.
    fn seal(&self, buf: &mut [u8], len: usize) -> usize;

    /// Opens `nonce(12) | ciphertext | tag(16)` in place, returning the plaintext, or `None`
    /// when it does not authenticate.
    fn open<'a>(&self, pkt: &'a mut [u8]) -> Option<&'a mut [u8]>;
}

// ---------------------------------------------------------------------------------------------
// 1. RustCrypto `aes-gcm` 0.11 — the implementation the port ships (crates/kcp/src/crypt/aead.rs).
// ---------------------------------------------------------------------------------------------

/// `aes-gcm` 0.11: AES-CTR over the whole packet, then GHASH over the whole packet.
pub struct RustCryptoGcm(aes_gcm::Aes128Gcm);

impl PacketAead for RustCryptoGcm {
    fn new(key: &[u8; 16]) -> Self {
        RustCryptoGcm(aes_gcm::Aes128Gcm::new(key.into()))
    }

    fn seal(&self, buf: &mut [u8], len: usize) -> usize {
        use aes_gcm::AeadInOut;
        let (nonce, rest) = split_seal(buf, len);
        let (plaintext, tag_out) = rest.split_at_mut(len - NONCE);
        let nonce = &*nonce;
        let tag = self
            .0
            .encrypt_inout_detached(nonce.into(), &[], plaintext.into())
            .expect("length is far below GCM's 2^36-byte limit");
        tag_out.copy_from_slice(&tag);
        len + TAG
    }

    fn open<'a>(&self, pkt: &'a mut [u8]) -> Option<&'a mut [u8]> {
        use aes_gcm::AeadInOut;
        let (nonce, ciphertext, tag) = split_open(pkt)?;
        self.0
            .decrypt_inout_detached(nonce.into(), &[], (&mut *ciphertext).into(), tag.into())
            .ok()?;
        Some(ciphertext)
    }
}

// ---------------------------------------------------------------------------------------------
// 2. ring 0.17 — BoringSSL's `aes_gcm_{enc,dec}_kernel` assembly.
// ---------------------------------------------------------------------------------------------

/// `ring` 0.17. `LessSafeKey` is the right primitive here: kcptun derives the nonce itself
/// (`entropy::fill_nonce`) instead of letting the AEAD sequence it.
pub struct RingGcm(ring::aead::LessSafeKey);

impl PacketAead for RingGcm {
    fn new(key: &[u8; 16]) -> Self {
        let unbound = ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, key)
            .expect("16 bytes is AES_128_GCM's key length");
        RingGcm(ring::aead::LessSafeKey::new(unbound))
    }

    fn seal(&self, buf: &mut [u8], len: usize) -> usize {
        let (nonce, rest) = split_seal(buf, len);
        let nonce = ring::aead::Nonce::assume_unique_for_key(*nonce);
        let (plaintext, tag_out) = rest.split_at_mut(len - NONCE);
        let tag = self
            .0
            .seal_in_place_separate_tag(nonce, ring::aead::Aad::empty(), plaintext)
            .expect("length is far below GCM's 2^36-byte limit");
        tag_out.copy_from_slice(tag.as_ref());
        len + TAG
    }

    fn open<'a>(&self, pkt: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let (nonce, rest) = pkt.split_first_chunk_mut::<NONCE>()?;
        let nonce = ring::aead::Nonce::assume_unique_for_key(*nonce);
        self.0
            .open_in_place(nonce, ring::aead::Aad::empty(), rest)
            .ok()
    }
}

// ---------------------------------------------------------------------------------------------
// 3. aws-lc-rs 1.18 — AWS-LC assembly, the ring-compatible API.
// ---------------------------------------------------------------------------------------------

/// `aws-lc-rs` 1.18. Note it has no AES-192-GCM, which `AeadCrypt` accepts (Go's
/// `NewAESGCMCrypt` picks the variant by key length), so adopting it would mean keeping
/// RustCrypto for 24-byte keys.
pub struct AwsLcGcm(aws_lc_rs::aead::LessSafeKey);

impl PacketAead for AwsLcGcm {
    fn new(key: &[u8; 16]) -> Self {
        let unbound = aws_lc_rs::aead::UnboundKey::new(&aws_lc_rs::aead::AES_128_GCM, key)
            .expect("16 bytes is AES_128_GCM's key length");
        AwsLcGcm(aws_lc_rs::aead::LessSafeKey::new(unbound))
    }

    fn seal(&self, buf: &mut [u8], len: usize) -> usize {
        let (nonce, rest) = split_seal(buf, len);
        let nonce = aws_lc_rs::aead::Nonce::assume_unique_for_key(*nonce);
        let (plaintext, tag_out) = rest.split_at_mut(len - NONCE);
        let tag = self
            .0
            .seal_in_place_separate_tag(nonce, aws_lc_rs::aead::Aad::empty(), plaintext)
            .expect("length is far below GCM's 2^36-byte limit");
        tag_out.copy_from_slice(tag.as_ref());
        len + TAG
    }

    fn open<'a>(&self, pkt: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let (nonce, rest) = pkt.split_first_chunk_mut::<NONCE>()?;
        let nonce = aws_lc_rs::aead::Nonce::assume_unique_for_key(*nonce);
        self.0
            .open_in_place(nonce, aws_lc_rs::aead::Aad::empty(), rest)
            .ok()
    }
}

// ---------------------------------------------------------------------------------------------
// 4. Our own fused AES-CTR + GHASH, in safe Rust.
// ---------------------------------------------------------------------------------------------

/// Counter blocks encrypted per AES call. Matches the `aes` crate's parallel width on ARMv8-AES
/// and AES-NI, and the 8-block groups Go's assembly kernel uses.
const LANES: usize = 8;

/// A single-pass AES-CTR + GHASH over the RustCrypto primitives.
///
/// `aes-gcm` runs AES-CTR over the whole packet and then GHASH over the whole packet; Go's
/// arm64/amd64 assembly interleaves them so the AES and the carry-less multiplies overlap. This
/// backend is the closest safe-Rust approximation: it walks the packet once in groups of
/// [`LANES`] blocks and, for each group, encrypts the counter blocks, XORs them in and hashes
/// the ciphertext before moving on, so the packet is touched once and the two instruction
/// streams sit next to each other. The whole loop runs inside one
/// `BlockCipherEncrypt::encrypt_with_backend` call, so the AES CPU-feature dispatch happens once
/// per packet (the same trick as `crypt::cfb`).
///
/// **Single-pass decryption releases unauthenticated plaintext.** Hashing and decrypting in the
/// same pass means the tag can only be checked once the whole packet has already been rewritten,
/// so [`FusedGcm::open`] leaves decrypted bytes in the caller's buffer even when it returns
/// `None`. That is inherent to the fused shape, and it differs from the shipping
/// `kcptun_kcp::crypt::AeadCrypt`: RustCrypto's two-pass `decrypt_inout_detached` verifies the tag
/// first and only then applies the keystream, so `open_in_place` leaves the packet untouched on
/// failure. (`ring` and `aws-lc-rs` document the same overwrite-on-failure behaviour as this
/// backend for their `open_in_place`.) A caller must therefore discard the buffer whenever `open`
/// fails — kcptun's receive path does, because it drops the packet — but adopting a fused kernel
/// for the product would have to accept that property deliberately rather than inherit it.
pub struct FusedGcm {
    aes: Aes128,
    /// GHASH keyed with `H = E_K(0^128)`; cloned per packet, since it carries the accumulator.
    ghash: GHash,
}

/// The engine, run as a RustCrypto "rank-2 closure" over the AES backend.
struct Fused<'a> {
    /// Plaintext on seal, ciphertext on open; overwritten in place.
    buf: &'a mut [u8],
    /// `nonce | 0x00000001`, GCM's `J0` for a 96-bit nonce.
    j0: [u8; 16],
    ghash: &'a mut GHash,
    /// Receives `E_K(J0)`, the tag mask.
    mask: &'a mut [u8; 16],
    decrypt: bool,
}

impl BlockSizeUser for Fused<'_> {
    type BlockSize = U16;
}

/// GHASHes the full blocks of `data` (its partial tail is handled by the caller).
#[inline(always)]
fn ghash_full(g: &mut GHash, data: &[u8]) {
    let (blocks, _) = data.as_chunks::<16>();
    g.update(Array::cast_slice_from_core(blocks));
}

/// XORs `ks` into the full blocks of `chunk`, 16 bytes at a time. Writing this as a byte-wise
/// loop costs 2.3x on the Neoverse-N1, where it does not auto-vectorise (see crypto.md).
#[inline(always)]
fn xor_blocks(chunk: &mut [u8], ks: &[[u8; 16]; LANES]) {
    let (blocks, _) = chunk.as_chunks_mut::<16>();
    for (b, k) in blocks.iter_mut().zip(ks.iter()) {
        *b = (u128::from_ne_bytes(*b) ^ u128::from_ne_bytes(*k)).to_ne_bytes();
    }
}

impl BlockCipherEncClosure for Fused<'_> {
    #[inline(always)]
    fn call<B: BlockCipherEncBackend<BlockSize = U16>>(self, backend: &B) {
        let Fused {
            buf,
            j0,
            ghash,
            mask,
            decrypt,
        } = self;

        // Tag mask E_K(J0). GCM counts the data blocks from J0 + 1.
        *mask = j0;
        backend.encrypt_block_inplace((&mut *mask).into());

        let n = buf.len();
        let full = n & !15;
        let mut ctr: u32 = 2;
        let mut off = 0usize;
        while off < full {
            let take = core::cmp::min(LANES * 16, full - off);
            let nb = take / 16;

            let mut ks = [[0u8; 16]; LANES];
            for k in ks.iter_mut().take(nb) {
                k[..NONCE].copy_from_slice(&j0[..NONCE]);
                k[NONCE..].copy_from_slice(&ctr.to_be_bytes());
                ctr = ctr.wrapping_add(1);
            }
            {
                let blocks = Array::<u8, U16>::cast_slice_from_core_mut(&mut ks[..nb]);
                let (par, tail) = ParBlocks::<B>::slice_as_chunks_mut(blocks);
                for p in par {
                    backend.encrypt_par_blocks_inplace(p);
                }
                backend.encrypt_tail_blocks_inplace(tail);
            }

            // GHASH always runs over the ciphertext: after the XOR when sealing, before it when
            // opening.
            let chunk = &mut buf[off..off + take];
            if decrypt {
                ghash_full(ghash, chunk);
                xor_blocks(chunk, &ks);
            } else {
                xor_blocks(chunk, &ks);
                ghash_full(ghash, chunk);
            }
            off += take;
        }

        if full < n {
            let mut k = [0u8; 16];
            k[..NONCE].copy_from_slice(&j0[..NONCE]);
            k[NONCE..].copy_from_slice(&ctr.to_be_bytes());
            backend.encrypt_block_inplace((&mut k).into());
            let tail = &mut buf[full..];
            if decrypt {
                ghash.update_padded(tail);
            }
            for (d, s) in tail.iter_mut().zip(k.iter()) {
                *d ^= *s;
            }
            if !decrypt {
                ghash.update_padded(tail);
            }
        }

        // Length block: 64-bit AAD bit length (zero here) then 64-bit ciphertext bit length.
        let mut len_block = ghash::Block::default();
        len_block[8..].copy_from_slice(&(n as u64 * 8).to_be_bytes());
        ghash.update(&[len_block]);
    }
}

impl FusedGcm {
    /// Seals or opens `buf` in place and returns the tag it computed.
    fn run(&self, nonce: &[u8; NONCE], buf: &mut [u8], decrypt: bool) -> [u8; 16] {
        let mut j0 = [0u8; 16];
        j0[..NONCE].copy_from_slice(nonce);
        j0[15] = 1;
        let mut ghash = self.ghash.clone();
        let mut mask = [0u8; 16];
        self.aes.encrypt_with_backend(Fused {
            buf,
            j0,
            ghash: &mut ghash,
            mask: &mut mask,
            decrypt,
        });
        let hash = ghash.finalize();
        let mut tag = [0u8; 16];
        for (t, (h, m)) in tag.iter_mut().zip(hash.iter().zip(mask.iter())) {
            *t = h ^ m;
        }
        tag
    }
}

impl PacketAead for FusedGcm {
    fn new(key: &[u8; 16]) -> Self {
        let aes = Aes128::new(key.into());
        let mut h = ghash::Key::default();
        aes.encrypt_block(&mut h);
        FusedGcm {
            ghash: GHash::new(&h),
            aes,
        }
    }

    fn seal(&self, buf: &mut [u8], len: usize) -> usize {
        let (nonce, rest) = split_seal(buf, len);
        let nonce = *nonce;
        let (plaintext, tag_out) = rest.split_at_mut(len - NONCE);
        let tag = self.run(&nonce, plaintext, false);
        tag_out.copy_from_slice(&tag);
        len + TAG
    }

    /// On failure `pkt` already holds the decrypted-but-unauthenticated bytes: the single pass
    /// rewrites the packet before the tag can be known. See the type's documentation; the
    /// shipping two-pass `AeadCrypt` does not do this.
    fn open<'a>(&self, pkt: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let (nonce, ciphertext, tag) = split_open(pkt)?;
        let nonce = *nonce;
        let expected = *tag;
        let got = self.run(&nonce, ciphertext, true);
        // Accumulate-then-test rather than an early exit. This is NOT a hardened constant-time
        // compare: unlike `subtle::ConstantTimeEq` (or Go's `subtle.ConstantTimeCompare`) it has
        // no optimisation barrier, so nothing stops LLVM reintroducing an early exit. A product
        // version would have to use `subtle`.
        let mut diff = 0u8;
        for (a, b) in got.iter().zip(expected.iter()) {
            diff |= a ^ b;
        }
        if diff == 0 { Some(ciphertext) } else { None }
    }
}

// ---------------------------------------------------------------------------------------------
// Diagnostics: the two halves of [`FusedGcm`], measured separately.
// ---------------------------------------------------------------------------------------------

/// The AES-CTR half and the GHASH half of [`FusedGcm`] on their own.
///
/// Comparing `ctr_only + ghash_only` with the fused loop and with Go says whether AES and the
/// carry-less multiplies are overlapping at all. They are not real AEADs; they exist only to be
/// timed (see docs/benchmarks/crypto.md, "Why the fused backend works on the M5 and not on
/// Linux").
pub struct Halves {
    aes: Aes128,
    ghash: GHash,
}

/// The CTR half: keystream generation and the XOR, no hashing.
struct CtrOnly<'a> {
    buf: &'a mut [u8],
    j0: [u8; 16],
}

impl BlockSizeUser for CtrOnly<'_> {
    type BlockSize = U16;
}

impl BlockCipherEncClosure for CtrOnly<'_> {
    #[inline(always)]
    fn call<B: BlockCipherEncBackend<BlockSize = U16>>(self, backend: &B) {
        let CtrOnly { buf, j0 } = self;
        let full = buf.len() & !15;
        let mut ctr: u32 = 2;
        let mut off = 0usize;
        while off < full {
            let take = core::cmp::min(LANES * 16, full - off);
            let nb = take / 16;
            let mut ks = [[0u8; 16]; LANES];
            for k in ks.iter_mut().take(nb) {
                k[..NONCE].copy_from_slice(&j0[..NONCE]);
                k[NONCE..].copy_from_slice(&ctr.to_be_bytes());
                ctr = ctr.wrapping_add(1);
            }
            let blocks = Array::<u8, U16>::cast_slice_from_core_mut(&mut ks[..nb]);
            let (par, tail) = ParBlocks::<B>::slice_as_chunks_mut(blocks);
            for p in par {
                backend.encrypt_par_blocks_inplace(p);
            }
            backend.encrypt_tail_blocks_inplace(tail);
            xor_blocks(&mut buf[off..off + take], &ks);
            off += take;
        }
    }
}

impl Halves {
    /// Keys both halves from a 16-byte AES-128 key.
    pub fn new(key: &[u8; 16]) -> Self {
        let aes = Aes128::new(key.into());
        let mut h = ghash::Key::default();
        aes.encrypt_block(&mut h);
        Halves {
            ghash: GHash::new(&h),
            aes,
        }
    }

    /// AES-CTR over `buf[NONCE..len]` with the nonce at `buf[..NONCE]`, in place.
    pub fn ctr_only(&self, buf: &mut [u8], len: usize) {
        let mut j0 = [0u8; 16];
        j0[..NONCE].copy_from_slice(&buf[..NONCE]);
        j0[15] = 1;
        self.aes.encrypt_with_backend(CtrOnly {
            buf: &mut buf[NONCE..len],
            j0,
        });
    }

    /// GHASH over `buf[NONCE..len]` in one `update_padded` call, as `aes-gcm` does it.
    pub fn ghash_whole(&self, buf: &[u8], len: usize) -> [u8; 16] {
        let mut g = self.ghash.clone();
        g.update_padded(&buf[NONCE..len]);
        g.finalize().into()
    }

    /// GHASH over `buf[NONCE..len]` in [`LANES`]-block groups, as [`FusedGcm`] does it.
    pub fn ghash_grouped(&self, buf: &[u8], len: usize) -> [u8; 16] {
        let mut g = self.ghash.clone();
        let data = &buf[NONCE..len];
        let (blocks, tail) = data.as_chunks::<16>();
        for group in blocks.chunks(LANES) {
            g.update(Array::cast_slice_from_core(group));
        }
        g.update_padded(tail);
        g.finalize().into()
    }
}

// ---------------------------------------------------------------------------------------------
// Shared packet splitting.
// ---------------------------------------------------------------------------------------------

/// Splits `buf[..len + TAG]` into the nonce and everything after it. Panics on a buffer too
/// small for the tag; the benchmarks always size it correctly (the real `AeadCrypt` returns an
/// error there).
fn split_seal(buf: &mut [u8], len: usize) -> (&mut [u8; NONCE], &mut [u8]) {
    assert!(len >= NONCE, "packet shorter than the nonce");
    let sealed = &mut buf[..len + TAG];
    sealed
        .split_first_chunk_mut::<NONCE>()
        .expect("len >= NONCE was just checked")
}

/// Splits a received packet into nonce, ciphertext and tag.
#[allow(clippy::type_complexity)]
fn split_open(pkt: &mut [u8]) -> Option<(&[u8; NONCE], &mut [u8], &[u8; TAG])> {
    let (nonce, rest) = pkt.split_first_chunk_mut::<NONCE>()?;
    let (ciphertext, tag) = rest.split_last_chunk_mut::<TAG>()?;
    Some((&*nonce, ciphertext, &*tag))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00,
    ];

    fn pattern(n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| (i.wrapping_mul(131).wrapping_add(7)) as u8)
            .collect()
    }

    fn seal_with<A: PacketAead>(plain_len: usize) -> Vec<u8> {
        let a = A::new(&KEY);
        let mut buf = pattern(NONCE + plain_len + TAG);
        let n = a.seal(&mut buf, NONCE + plain_len);
        assert_eq!(n, buf.len());
        buf
    }

    fn roundtrip_with<A: PacketAead>(sealed: &[u8], plain_len: usize) {
        let a = A::new(&KEY);
        let mut buf = sealed.to_vec();
        let opened = a.open(&mut buf).expect("authentic");
        assert_eq!(opened.len(), plain_len);
        assert_eq!(opened, &pattern(NONCE + plain_len)[NONCE..]);
    }

    /// The point of the whole exercise: a faster backend must not move a single byte.
    /// Lengths cover empty, sub-block, block-aligned, group-aligned and the two packet sizes the
    /// benchmark uses (1350 and 1500 minus nonce and tag).
    #[test]
    fn all_backends_agree() {
        for plain_len in [
            0, 1, 15, 16, 17, 31, 32, 127, 128, 129, 1000, 1322, 1338, 1472,
        ] {
            let reference = seal_with::<RustCryptoGcm>(plain_len);
            for (name, sealed) in [
                ("ring", seal_with::<RingGcm>(plain_len)),
                ("aws-lc-rs", seal_with::<AwsLcGcm>(plain_len)),
                ("fused", seal_with::<FusedGcm>(plain_len)),
            ] {
                assert_eq!(
                    hex::encode(&sealed),
                    hex::encode(&reference),
                    "{name} differs at plaintext length {plain_len}"
                );
            }
            roundtrip_with::<RustCryptoGcm>(&reference, plain_len);
            roundtrip_with::<RingGcm>(&reference, plain_len);
            roundtrip_with::<AwsLcGcm>(&reference, plain_len);
            roundtrip_with::<FusedGcm>(&reference, plain_len);
        }
    }

    /// McGrew & Viega, "The Galois/Counter Mode of Operation", test case 3 (AES-128, 96-bit IV,
    /// no AAD) — the same vector `crates/kcp/src/crypt/aead.rs` checks.
    #[test]
    fn gcm_spec_known_answer() {
        let key = hex::decode("feffe9928665731c6d6a8f9467308308").expect("hex");
        let nonce = hex::decode("cafebabefacedbaddecaf888").expect("hex");
        let plaintext = hex::decode(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        )
        .expect("hex");
        let want = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                    21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985\
                    4d5c2af327cd64a62cf35abd2ba6fab4";

        let key: [u8; 16] = key.try_into().expect("16-byte key");
        fn check<A: PacketAead>(key: &[u8; 16], nonce: &[u8], plaintext: &[u8], want: &str) {
            let a = A::new(key);
            let mut buf = nonce.to_vec();
            buf.extend_from_slice(plaintext);
            buf.resize(buf.len() + TAG, 0);
            let n = a.seal(&mut buf, NONCE + plaintext.len());
            assert_eq!(hex::encode(&buf[NONCE..n]), want);
            assert_eq!(a.open(&mut buf).expect("authentic"), plaintext);
        }
        check::<RustCryptoGcm>(&key, &nonce, &plaintext, want);
        check::<RingGcm>(&key, &nonce, &plaintext, want);
        check::<AwsLcGcm>(&key, &nonce, &plaintext, want);
        check::<FusedGcm>(&key, &nonce, &plaintext, want);
    }

    /// Every single-byte change anywhere in the packet must fail to open, and a packet shorter
    /// than nonce + tag must be rejected rather than panic.
    #[test]
    fn tampering_and_short_packets_are_rejected() {
        fn check<A: PacketAead>() {
            let a = A::new(&KEY);
            let sealed = seal_with::<A>(24);
            for i in 0..sealed.len() {
                let mut buf = sealed.clone();
                buf[i] ^= 0x80;
                assert!(a.open(&mut buf).is_none(), "byte {i} flipped but accepted");
            }
            for len in 0..NONCE + TAG {
                let mut buf = vec![0u8; len];
                assert!(a.open(&mut buf).is_none(), "length {len} accepted");
            }
        }
        check::<RustCryptoGcm>();
        check::<RingGcm>();
        check::<AwsLcGcm>();
        check::<FusedGcm>();
    }
}
