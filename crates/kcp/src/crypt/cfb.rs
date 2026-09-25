//! kcp-go's packet CFB mode: full-block cipher feedback with a fixed IV, applied in place to the
//! whole packet (nonce, crc and payload). See `docs/WIRE-FORMAT.md` §1.1.
//!
//! The engine is generic over the block cipher ([`CfbBlock`]) and its block size (8 or 16 bytes)
//! and is monomorphised per cipher. Unlike Go it keeps no scratch buffers in the cipher object
//! (the feedback register lives on the stack), so ciphers are `Sync` and need no locks.
//!
//! Performance (plan 02.6, `docs/benchmarks/crypto.md`):
//! - Encryption is inherently serial (`C_i` feeds `E` for block `i + 1`); it is a tight loop.
//! - Decryption only needs `E(C_{i-1})`, which depends on ciphertext alone, so [`decrypt`]
//!   computes the keystream in batches of [`LANES`] independent blocks with
//!   [`CfbBlock::encrypt_blocks`] and then XORs. For AES that is the pipelined 8-block
//!   ARMv8-AES / AES-NI path of the `aes` crate. The batch is a fixed-size local array so it
//!   stays in registers; a slice-based version measured 2.3 times slower than even the plain
//!   serial loop on the M5.
//! - RustCrypto ciphers run the whole packet inside one `encrypt_with_backend` call, so the
//!   CPU-feature dispatch happens once per packet and the hardware AES rounds are inlined into
//!   the loop (the backend code is compiled with the `aes` target feature enabled).

use cipher::consts::{U8, U16};
use cipher::{
    Array, BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser,
    ParBlocks,
};

/// The fixed CFB initial vector. 8-byte block ciphers use the first 8 bytes.
///
/// It is not secret and not a real IV: every packet starts with a random nonce, so the first
/// block of ciphertext is random anyway.
// Go: kcp-go/v5@v5.6.66 crypt.go:initialVector
pub(crate) const INITIAL_VECTOR: [u8; 16] = [
    167, 115, 79, 156, 18, 172, 27, 1, 164, 21, 242, 193, 252, 120, 230, 107,
];

/// Number of keystream blocks [`decrypt`] computes per [`CfbBlock::encrypt_blocks`] call. It
/// matches the `aes` crate's parallel width (8 blocks on ARMv8 and AES-NI) and Go's 8-way
/// unrolled loop.
pub(crate) const LANES: usize = 8;

/// A block cipher usable by the CFB engine: a block size of `BS` bytes (8 or 16) and forward
/// encryption. CFB never uses the inverse cipher.
///
/// Implemented for the hand-written ciphers (TEA, XTEA, Twofish, 3DES, SM4) in their own
/// modules and, through [`Backend`], for the RustCrypto ciphers.
// Go: kcp-go/v5@v5.6.66 crypt.go uses crypto/cipher.Block (BlockSize + Encrypt)
pub(crate) trait CfbBlock<const BS: usize> {
    /// Encrypts one block in place.
    fn encrypt_block(&self, block: &mut [u8; BS]);

    /// Encrypts [`LANES`] independent blocks in place. Implementations may interleave or
    /// pipeline them; the default encrypts one after the other (the CPU still overlaps the
    /// independent work).
    #[inline(always)]
    fn encrypt_blocks(&self, blocks: &mut [[u8; BS]; LANES]) {
        for b in blocks {
            self.encrypt_block(b);
        }
    }
}

/// A RustCrypto cipher backend seen as a [`CfbBlock`]. Only constructed inside
/// `encrypt_with_backend`, so the backend's target features are known to be available.
struct Backend<'a, B>(&'a B);

/// The engine run as a RustCrypto "rank-2 closure" over the cipher's backend.
struct WithBackend<'a, const BS: usize> {
    buf: &'a mut [u8],
    decrypt: bool,
}

/// Implements [`CfbBlock`] for [`Backend`] and the closure plumbing for one block size.
macro_rules! impl_backend {
    ($bs:literal, $size:ty) => {
        impl<B: BlockCipherEncBackend<BlockSize = $size>> CfbBlock<$bs> for Backend<'_, B> {
            #[inline(always)]
            fn encrypt_block(&self, block: &mut [u8; $bs]) {
                self.0.encrypt_block_inplace(block.into());
            }

            #[inline(always)]
            fn encrypt_blocks(&self, blocks: &mut [[u8; $bs]; LANES]) {
                let blocks = Array::<u8, $size>::cast_slice_from_core_mut(blocks);
                // AES: one 8-block parallel call; ciphers without a parallel path: 8 calls.
                let (par, tail) = ParBlocks::<B>::slice_as_chunks_mut(blocks);
                for p in par {
                    self.0.encrypt_par_blocks_inplace(p);
                }
                // Empty unless the parallel width does not divide LANES; it is shorter than the
                // width, as the backend requires.
                self.0.encrypt_tail_blocks_inplace(tail);
            }
        }

        impl BlockSizeUser for WithBackend<'_, $bs> {
            type BlockSize = $size;
        }

        impl BlockCipherEncClosure for WithBackend<'_, $bs> {
            #[inline(always)]
            fn call<B: BlockCipherEncBackend<BlockSize = $size>>(self, backend: &B) {
                if self.decrypt {
                    decrypt::<$bs, _>(&Backend(backend), self.buf);
                } else {
                    encrypt::<$bs, _>(&Backend(backend), self.buf);
                }
            }
        }
    };
}

impl_backend!(8, U8);
impl_backend!(16, U16);

/// Packet-level CFB for one cipher type with block size `BS`.
trait CfbCrypt<const BS: usize> {
    fn cfb_encrypt(&self, buf: &mut [u8]);
    fn cfb_decrypt(&self, buf: &mut [u8]);
}

/// RustCrypto ciphers: the engine runs inside one `encrypt_with_backend` call per packet.
macro_rules! impl_cfb_rustcrypto {
    ($bs:literal => $($ty:ty),+ $(,)?) => {$(
        impl CfbCrypt<$bs> for $ty {
            #[inline(always)]
            fn cfb_encrypt(&self, buf: &mut [u8]) {
                self.encrypt_with_backend(WithBackend::<$bs> { buf, decrypt: false });
            }

            #[inline(always)]
            fn cfb_decrypt(&self, buf: &mut [u8]) {
                self.encrypt_with_backend(WithBackend::<$bs> { buf, decrypt: true });
            }
        }
    )+};
}

impl_cfb_rustcrypto!(16 => aes::Aes128, aes::Aes192, aes::Aes256);
impl_cfb_rustcrypto!(8 => blowfish::Blowfish, cast5::Cast5);

/// Hand-written ciphers implement [`CfbBlock`] directly.
macro_rules! impl_cfb_own {
    ($bs:literal => $($ty:ty),+ $(,)?) => {$(
        impl CfbCrypt<$bs> for $ty {
            #[inline(always)]
            fn cfb_encrypt(&self, buf: &mut [u8]) {
                encrypt::<$bs, _>(self, buf);
            }

            #[inline(always)]
            fn cfb_decrypt(&self, buf: &mut [u8]) {
                decrypt::<$bs, _>(self, buf);
            }
        }
    )+};
}

impl_cfb_own!(16 => super::twofish::Cipher, super::sm4::Sm4Cipher);
impl_cfb_own!(8 => super::des::TripleDesCipher, super::tea::Tea, super::xtea::Xtea);

/// The concrete block ciphers used in CFB mode. One `match` per packet selects the
/// monomorphised engine.
// Go: kcp-go/v5@v5.6.66 crypt.go:blockCrypt (the cipher.Block it wraps)
#[derive(Clone)]
pub enum CfbCipher {
    /// AES-128 (`-crypt aes-128`, key `pass[0:16]`).
    Aes128(aes::Aes128),
    /// AES-192 (`-crypt aes-192`, key `pass[0:24]`).
    Aes192(aes::Aes192),
    /// AES-256 (`-crypt aes` and any unknown name, key `pass[0:32]`).
    Aes256(aes::Aes256),
    /// Blowfish, big-endian (`-crypt blowfish`, key `pass[0:32]`). Boxed: its key schedule is
    /// about 4 KiB.
    Blowfish(Box<blowfish::Blowfish>),
    /// Twofish (`-crypt twofish`, key `pass[0:32]`). Boxed: its key-dependent S-boxes are
    /// 4 KiB.
    Twofish(Box<super::twofish::Cipher>),
    /// CAST5 / CAST-128 (`-crypt cast5`, key `pass[0:16]`).
    Cast5(cast5::Cast5),
    /// Triple DES, EDE with three keys (`-crypt 3des`, key `pass[0:24]`).
    TripleDes(super::des::TripleDesCipher),
    /// SM4 (`-crypt sm4`, key `pass[0:16]`).
    Sm4(super::sm4::Sm4Cipher),
    /// TEA with 16 rounds (`-crypt tea`, key `pass[0:16]`).
    Tea(super::tea::Tea),
    /// XTEA (`-crypt xtea`, key `pass[0:16]`).
    Xtea(super::xtea::Xtea),
}

/// Expands to one `match` over every [`CfbCipher`] variant, binding the cipher to `$c` and
/// running `$body` with the block size `$bs` as a const.
macro_rules! dispatch {
    ($self:expr, |$c:ident, $bs:ident| $body:expr) => {
        match $self {
            CfbCipher::Aes128($c) => {
                const $bs: usize = 16;
                $body
            }
            CfbCipher::Aes192($c) => {
                const $bs: usize = 16;
                $body
            }
            CfbCipher::Aes256($c) => {
                const $bs: usize = 16;
                $body
            }
            CfbCipher::Blowfish(b) => {
                let $c = &**b;
                const $bs: usize = 8;
                $body
            }
            CfbCipher::Twofish(b) => {
                let $c = &**b;
                const $bs: usize = 16;
                $body
            }
            CfbCipher::Cast5($c) => {
                const $bs: usize = 8;
                $body
            }
            CfbCipher::TripleDes($c) => {
                const $bs: usize = 8;
                $body
            }
            CfbCipher::Sm4($c) => {
                const $bs: usize = 16;
                $body
            }
            CfbCipher::Tea($c) => {
                const $bs: usize = 8;
                $body
            }
            CfbCipher::Xtea($c) => {
                const $bs: usize = 8;
                $body
            }
        }
    };
}

impl CfbCipher {
    /// The cipher's block size in bytes (8 or 16).
    // Go: kcp-go/v5@v5.6.66 crypt.go:blockCrypt.blockSize
    pub fn block_size(&self) -> usize {
        dispatch!(self, |_c, BS| BS)
    }

    /// Encrypts `buf` in place.
    // Go: kcp-go/v5@v5.6.66 crypt.go:blockCrypt.Encrypt() -> encrypt()
    #[inline]
    pub fn encrypt(&self, buf: &mut [u8]) {
        dispatch!(self, |c, BS| CfbCrypt::<BS>::cfb_encrypt(c, buf))
    }

    /// Decrypts `buf` in place.
    // Go: kcp-go/v5@v5.6.66 crypt.go:blockCrypt.Decrypt() -> decrypt()
    #[inline]
    pub fn decrypt(&self, buf: &mut [u8]) {
        dispatch!(self, |c, BS| CfbCrypt::<BS>::cfb_decrypt(c, buf))
    }
}

impl std::fmt::Debug for CfbCipher {
    // Key schedules are secret: print only the algorithm.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            CfbCipher::Aes128(_) => "Aes128",
            CfbCipher::Aes192(_) => "Aes192",
            CfbCipher::Aes256(_) => "Aes256",
            CfbCipher::Blowfish(_) => "Blowfish",
            CfbCipher::Twofish(_) => "Twofish",
            CfbCipher::Cast5(_) => "Cast5",
            CfbCipher::TripleDes(_) => "TripleDes",
            CfbCipher::Sm4(_) => "Sm4",
            CfbCipher::Tea(_) => "Tea",
            CfbCipher::Xtea(_) => "Xtea",
        };
        f.debug_tuple(name).finish_non_exhaustive()
    }
}

/// `E(IV[0:BS])`, the first keystream block.
#[inline(always)]
fn initial_tbl<const BS: usize, C: CfbBlock<BS>>(block: &C) -> [u8; BS] {
    const { assert!(BS == 8 || BS == 16, "unsupported cipher block size") };
    let mut tbl = [0u8; BS];
    tbl.copy_from_slice(&INITIAL_VECTOR[..BS]);
    block.encrypt_block(&mut tbl);
    tbl
}

/// `dst[i] ^= src[i]` for `i < min(len)`, like Go's `subtle.XORBytes(dst, dst, src)`.
#[inline(always)]
fn xor_in_place(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= *s;
    }
}

/// CFB encryption in place: `C_i = P_i ^ t; t = E(C_i)` with `t = E(IV)` initially; a trailing
/// partial block is XORed with the first `len % BS` bytes of `t`.
///
/// Go's 8-way loop unrolling and `switch`/`fallthrough` tail are a manual optimisation of this
/// same serial loop; the result is identical for every length (including 0).
// Go: kcp-go/v5@v5.6.66 crypt.go:encrypt8(), encrypt16()
#[inline(always)]
pub(crate) fn encrypt<const BS: usize, C: CfbBlock<BS>>(block: &C, buf: &mut [u8]) {
    let mut tbl = initial_tbl(block);
    let (blocks, rem) = buf.as_chunks_mut::<BS>();
    for b in blocks {
        xor_in_place(b, &tbl);
        tbl = *b;
        block.encrypt_block(&mut tbl);
    }
    // case 0: subtle.XORBytes(dst[base:], src[base:], tbl) covers the partial block.
    xor_in_place(rem, &tbl);
}

/// CFB decryption in place: `P_i = C_i ^ E(C_{i-1})` with `C_{-1} = IV`; a trailing partial
/// block is XORed with the first `len % BS` bytes of `E(C_{n-1})` (`n` full blocks).
///
/// Go computes the same keystream serially, one `Encrypt` per block. Here each batch of
/// [`LANES`] full blocks copies its keystream inputs (the previous ciphertext blocks) into a
/// local array before the XOR overwrites them, and encrypts them with one
/// [`CfbBlock::encrypt_blocks`] call. The remaining (fewer than [`LANES`]) blocks use the serial
/// loop, whose keystream blocks are still independent of each other. The output is identical
/// for every length (including 0).
// Go: kcp-go/v5@v5.6.66 crypt.go:decrypt8(), decrypt16()
#[inline(always)]
pub(crate) fn decrypt<const BS: usize, C: CfbBlock<BS>>(block: &C, buf: &mut [u8]) {
    const { assert!(BS == 8 || BS == 16, "unsupported cipher block size") };
    // `x` is the next keystream input: IV, then the last ciphertext block of the previous batch.
    let mut x = [0u8; BS];
    x.copy_from_slice(&INITIAL_VECTOR[..BS]);

    let (blocks, rem) = buf.as_chunks_mut::<BS>();
    let (batches, tail) = blocks.as_chunks_mut::<LANES>();
    for batch in batches {
        let mut ks: [[u8; BS]; LANES] =
            std::array::from_fn(|i| if i == 0 { x } else { batch[i - 1] });
        x = batch[LANES - 1];
        block.encrypt_blocks(&mut ks);
        for (b, k) in batch.iter_mut().zip(&ks) {
            xor_in_place(b, k);
        }
    }

    if tail.is_empty() && rem.is_empty() {
        return;
    }
    let mut tbl = x;
    block.encrypt_block(&mut tbl);
    for b in tail {
        let mut next = *b;
        block.encrypt_block(&mut next);
        xor_in_place(b, &tbl);
        tbl = next;
    }
    // case 0: subtle.XORBytes(dst[base:], src[base:], tbl) covers the partial block.
    xor_in_place(rem, &tbl);
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A toy "cipher" `E(x) = rotate_left(x, 1) ^ k` for testing the engine's structure (IV
    /// slice, feedback, tail) independently of any real cipher.
    struct Toy(u8);

    impl<const BS: usize> CfbBlock<BS> for Toy {
        fn encrypt_block(&self, block: &mut [u8; BS]) {
            block.rotate_left(1);
            for b in block.iter_mut() {
                *b ^= self.0;
            }
        }
    }

    /// Straight transcription of WIRE-FORMAT.md §1.1, allocating and non-in-place.
    fn model_encrypt<const BS: usize>(c: &Toy, src: &[u8]) -> Vec<u8> {
        let mut t = [0u8; BS];
        t.copy_from_slice(&INITIAL_VECTOR[..BS]);
        CfbBlock::<BS>::encrypt_block(c, &mut t);
        let mut out = Vec::with_capacity(src.len());
        for chunk in src.chunks(BS) {
            let ct: Vec<u8> = chunk.iter().zip(&t).map(|(p, k)| p ^ k).collect();
            if ct.len() == BS {
                t.copy_from_slice(&ct);
                CfbBlock::<BS>::encrypt_block(c, &mut t);
            }
            out.extend_from_slice(&ct);
        }
        out
    }

    fn check_model<const BS: usize>(key: u8, data: &[u8]) {
        let c = Toy(key);
        let want = model_encrypt::<BS>(&c, data);
        let mut buf = data.to_vec();
        encrypt::<BS, _>(&c, &mut buf);
        assert_eq!(buf, want, "encrypt BS={BS} len={}", data.len());
        decrypt::<BS, _>(&c, &mut buf);
        assert_eq!(buf, data, "decrypt BS={BS} len={}", data.len());
    }

    #[test]
    fn engine_matches_model_all_small_lengths() {
        let data: Vec<u8> = (0..200u8).map(|i| i.wrapping_mul(37)).collect();
        for len in 0..=data.len() {
            check_model::<8>(0x5a, &data[..len]);
            check_model::<16>(0xa5, &data[..len]);
        }
    }

    #[test]
    fn eight_byte_ciphers_use_first_half_of_iv() {
        // With E = identity-like toy and an all-zero 8-byte packet, the ciphertext is E(IV[0:8]).
        let c = Toy(0);
        let mut buf = [0u8; 8];
        encrypt::<8, _>(&c, &mut buf);
        let mut want = [0u8; 8];
        want.copy_from_slice(&INITIAL_VECTOR[..8]);
        want.rotate_left(1);
        assert_eq!(buf, want);
    }

    #[test]
    fn empty_buffer_is_noop() {
        let c = Toy(7);
        let mut buf: [u8; 0] = [];
        encrypt::<16, _>(&c, &mut buf);
        decrypt::<8, _>(&c, &mut buf);
    }

    /// A toy cipher whose batched path encrypts the blocks in reverse order and counts the
    /// batches: decryption must not depend on the order within a batch.
    struct Batched {
        toy: Toy,
        batches: std::cell::Cell<usize>,
        blocks: std::cell::Cell<usize>,
    }

    impl<const BS: usize> CfbBlock<BS> for Batched {
        fn encrypt_block(&self, block: &mut [u8; BS]) {
            self.blocks.set(self.blocks.get() + 1);
            CfbBlock::<BS>::encrypt_block(&self.toy, block);
        }

        fn encrypt_blocks(&self, blocks: &mut [[u8; BS]; LANES]) {
            self.batches.set(self.batches.get() + 1);
            for b in blocks.iter_mut().rev() {
                self.encrypt_block(b);
            }
        }
    }

    fn check_batched<const BS: usize>(data: &[u8]) {
        let c = Batched {
            toy: Toy(0x3c),
            batches: std::cell::Cell::new(0),
            blocks: std::cell::Cell::new(0),
        };
        let mut buf = model_encrypt::<BS>(&c.toy, data);
        decrypt::<BS, _>(&c, &mut buf);
        assert_eq!(buf, data, "BS={BS} len={}", data.len());
        assert_eq!(
            c.batches.get(),
            data.len() / (BS * LANES),
            "BS={BS} len={}",
            data.len()
        );
        // One keystream block per full or partial block, plus at most one unused E(C_last)
        // when the packet ends after a serial tail on a block boundary (Go's serial loop
        // computes that one too, and E(IV) even for an empty packet).
        let needed = data.len().div_ceil(BS);
        let tail = (data.len() / BS) % LANES;
        let extra = usize::from(tail > 0 && data.len().is_multiple_of(BS));
        assert_eq!(c.blocks.get(), needed + extra, "BS={BS} len={}", data.len());
    }

    #[test]
    fn batched_decrypt_matches_model_all_small_lengths() {
        let data: Vec<u8> = (0..=300u16).map(|i| (i as u8).wrapping_mul(91)).collect();
        for len in 0..=data.len() {
            check_batched::<8>(&data[..len]);
            check_batched::<16>(&data[..len]);
        }
    }

    /// `aes` through the per-block `BlockCipherEncrypt` API: the reference for the backend
    /// adapter (single-block dispatch, no parallel blocks).
    struct PlainAes<'a, C>(&'a C);

    impl<C: BlockCipherEncrypt<BlockSize = U16>> CfbBlock<16> for PlainAes<'_, C> {
        fn encrypt_block(&self, block: &mut [u8; 16]) {
            self.0.encrypt_block(block.into());
        }
    }

    impl<C: BlockCipherEncrypt<BlockSize = U8>> CfbBlock<8> for PlainAes<'_, C> {
        fn encrypt_block(&self, block: &mut [u8; 8]) {
            self.0.encrypt_block(block.into());
        }
    }

    /// The `aes` crate uses the hardware AES instructions whenever the CPU has them: ARMv8 AES
    /// (always present on Apple silicon; detected at run time on Linux) and AES-NI on x86_64
    /// (detected at run time). Guards against a build that silently falls back to the
    /// software implementation (e.g. `--cfg aes_backend="soft"`), which is ~20x slower.
    #[test]
    fn aes_uses_hardware_when_available() {
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        assert!(aes::hardware_accelerated());
        #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
        assert_eq!(
            aes::hardware_accelerated(),
            std::arch::is_aarch64_feature_detected!("aes")
        );
        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            aes::hardware_accelerated(),
            std::arch::is_x86_feature_detected!("aes")
        );
    }

    proptest! {
        #[test]
        fn prop_engine_matches_model(key in any::<u8>(), data in proptest::collection::vec(any::<u8>(), 0..=1500)) {
            check_model::<8>(key, &data);
            check_model::<16>(key, &data);
        }

        #[test]
        fn prop_batched_decrypt_matches_model(data in proptest::collection::vec(any::<u8>(), 0..=1500)) {
            check_batched::<8>(&data);
            check_batched::<16>(&data);
        }

        /// The backend path (one `encrypt_with_backend` per packet, 8-block parallel keystream
        /// for decryption) equals the plain per-block engine, for AES and an 8-byte cipher.
        #[test]
        fn prop_backend_matches_plain_block_api(
            key in proptest::array::uniform32(any::<u8>()),
            data in proptest::collection::vec(any::<u8>(), 0..=1500),
        ) {
            use cipher::KeyInit;
            let aes = aes::Aes256::new(&key.into());
            let mut want = data.clone();
            encrypt::<16, _>(&PlainAes(&aes), &mut want);
            let c = CfbCipher::Aes256(aes.clone());
            let mut got = data.clone();
            c.encrypt(&mut got);
            prop_assert_eq!(&got, &want);
            c.decrypt(&mut got);
            prop_assert_eq!(&got, &data);

            let cast = cast5::Cast5::new_from_slice(&key[..16]).expect("16-byte key");
            let mut want = data.clone();
            encrypt::<8, _>(&PlainAes(&cast), &mut want);
            let c = CfbCipher::Cast5(cast);
            let mut got = data.clone();
            c.encrypt(&mut got);
            prop_assert_eq!(&got, &want);
            c.decrypt(&mut got);
            prop_assert_eq!(&got, &data);
        }
    }
}
