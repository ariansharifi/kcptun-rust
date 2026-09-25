//! Packet encryption (port of kcp-go `crypt.go`).
//!
//! Every packet is encrypted as a whole and in place: the 16-byte random nonce, the 4-byte CRC32
//! and the payload (see `docs/WIRE-FORMAT.md` §1–2). The cipher is chosen once per session and
//! dispatched once per packet through the [`BlockCrypt`] enum, so there is no dynamic dispatch in
//! the hot path.
//!
//! Go needs a mutex per direction because its ciphers share scratch buffers. Here the scratch
//! state lives on the stack, so a `BlockCrypt` is immutable after construction, `Send + Sync`,
//! and can be shared between tasks without locks.
#![forbid(unsafe_code)]

mod aead;
mod cfb;
pub mod des;
pub mod sm4;
pub mod tea;
pub mod twofish;
pub mod xtea;

pub use aead::{AeadCrypt, AeadError};
pub use cfb::CfbCipher;

use cipher::{KeyInit, KeyIvInit, StreamCipher};
use sha1::Sha1;

/// Salt of the PBKDF2 expansion that turns the key into the `xor` pad.
// Go: kcp-go/v5@v5.6.66 crypt.go:saltxor
pub const SALTXOR: &str = "sH3CIVoF#rWLtJo6";

/// Length of the `xor` pad: kcp-go's maximum packet size. Longer packets are only XORed over
/// their first `MTU_LIMIT` bytes.
// Go: kcp-go/v5@v5.6.66 sess.go:mtuLimit
pub const MTU_LIMIT: usize = 1500;

/// Size of the random nonce every [`BlockCrypt`] packet starts with (`docs/WIRE-FORMAT.md` §2.1).
// Go: kcp-go/v5@v5.6.66 sess.go:nonceSize
pub const NONCE_SIZE: usize = 16;

/// Size of the CRC-32/IEEE checksum that follows the nonce.
// Go: kcp-go/v5@v5.6.66 sess.go:crcSize
pub const CRC_SIZE: usize = 4;

/// Bytes a [`BlockCrypt`] packet carries before its payload: nonce and checksum.
// Go: kcp-go/v5@v5.6.66 sess.go:cryptHeaderSize
pub const CRYPT_HEADER_SIZE: usize = NONCE_SIZE + CRC_SIZE;

/// Errors from creating a packet cipher. The messages are Go's.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CryptError {
    /// The key has a length the cipher does not accept, e.g.
    /// `crypto/aes: invalid key size 17`.
    // Go: crypto/aes.KeySizeError, crypto/des.KeySizeError,
    //     golang.org/x/crypto/{blowfish,twofish,xtea}.KeySizeError (x/crypto@v0.47.0)
    #[error("crypto/{pkg}: invalid key size {size}")]
    KeySize {
        /// Go package name of the cipher (`aes`, `blowfish`, `twofish`, `des`, `xtea`).
        pkg: &'static str,
        /// The rejected key length in bytes.
        size: usize,
    },
    /// CAST5 key that is not exactly 16 bytes.
    // Go: golang.org/x/crypto/cast5@v0.47.0 cast5.go:NewCipher()
    #[error("CAST5: keys must be 16 bytes")]
    Cast5KeySize,
    /// SM4 key that is not exactly 16 bytes.
    // Go: github.com/tjfoc/gmsm/sm4@v1.4.1 sm4.go:NewCipher()
    #[error("SM4: invalid key size {size}")]
    Sm4KeySize {
        /// The rejected key length in bytes.
        size: usize,
    },
    /// TEA key that is not exactly 16 bytes.
    // Go: golang.org/x/crypto/tea@v0.47.0 cipher.go:NewCipherWithRounds()
    #[error("tea: incorrect key size")]
    TeaKeySize,
    /// TEA with an odd number of rounds.
    // Go: golang.org/x/crypto/tea@v0.47.0 cipher.go:NewCipherWithRounds()
    #[error("tea: odd number of rounds specified")]
    TeaOddRounds,
}

/// The per-session packet crypto, chosen by `-crypt`. `-crypt null` has no crypto at all and is
/// `Option<PacketCrypt>::None` at the session level.
///
/// The two kinds have different packet layouts (WIRE-FORMAT §2), so the session layer matches on
/// this enum, like Go's type switch on `*aeadCrypt`:
/// - [`PacketCrypt::Block`]: 16-byte nonce + 4-byte CRC32 header, the whole packet encrypted in
///   place with [`BlockCrypt::encrypt`] / [`BlockCrypt::decrypt`].
/// - [`PacketCrypt::Aead`]: 12-byte nonce, sealed payload plus a 16-byte tag, no CRC, with
///   [`AeadCrypt::seal_in_place`] / [`AeadCrypt::open_in_place`].
///
/// Unlike Go, the AEAD cipher is not a `BlockCrypt` whose `Encrypt` panics: the type system keeps
/// the two paths apart.
// Go: kcp-go/v5@v5.6.66 crypt.go:BlockCrypt (interface) and the `*aeadCrypt` type switches in
//     sess.go
#[derive(Clone, Debug)]
pub enum PacketCrypt {
    /// A whole-packet cipher (every `-crypt` value except `null` and `aes-128-gcm`).
    Block(BlockCrypt),
    /// AES-GCM (`-crypt aes-128-gcm`).
    Aead(AeadCrypt),
}

impl From<BlockCrypt> for PacketCrypt {
    fn from(block: BlockCrypt) -> Self {
        PacketCrypt::Block(block)
    }
}

impl From<AeadCrypt> for PacketCrypt {
    fn from(aead: AeadCrypt) -> Self {
        PacketCrypt::Aead(aead)
    }
}

impl PacketCrypt {
    /// The whole-packet cipher, or `None` for the AEAD mode.
    #[inline]
    pub fn as_block(&self) -> Option<&BlockCrypt> {
        match self {
            PacketCrypt::Block(b) => Some(b),
            PacketCrypt::Aead(_) => None,
        }
    }

    /// The AEAD, or `None` for a whole-packet cipher.
    #[inline]
    pub fn as_aead(&self) -> Option<&AeadCrypt> {
        match self {
            PacketCrypt::Aead(a) => Some(a),
            PacketCrypt::Block(_) => None,
        }
    }
}

/// A packet cipher: encrypts or decrypts a whole packet in place.
///
/// `-crypt null` has no cipher at all and is represented as `Option<BlockCrypt>::None` at the
/// session level.
// Go: kcp-go/v5@v5.6.66 crypt.go:BlockCrypt (interface)
#[derive(Clone, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "built once per session; keeping the CFB key schedule inline avoids a pointer \
              chase per packet (the ~4 KiB Blowfish and Twofish schedules and the xor pad \
              are boxed)"
)]
pub enum BlockCrypt {
    /// A block cipher in kcp-go's CFB mode (`aes`, `aes-128`, `aes-192`, ...).
    Cfb(CfbCipher),
    /// Salsa20/20 keyed by the 32-byte key, nonce = the first 8 packet bytes (`-crypt salsa20`).
    Salsa20(Salsa20Crypt),
    /// XOR with a 1500-byte pad derived from the key (`-crypt xor`).
    Xor(XorCrypt),
    /// Identity: the packet keeps its nonce and CRC header but is sent in clear (`-crypt none`).
    None,
}

impl BlockCrypt {
    /// Encrypts the whole packet `buf` in place.
    // Go: kcp-go/v5@v5.6.66 crypt.go:BlockCrypt.Encrypt(dst, src) with dst == src
    #[inline]
    pub fn encrypt(&self, buf: &mut [u8]) {
        match self {
            BlockCrypt::Cfb(c) => c.encrypt(buf),
            BlockCrypt::Salsa20(c) => c.xor_key_stream(buf),
            BlockCrypt::Xor(c) => c.xor(buf),
            BlockCrypt::None => {}
        }
    }

    /// Decrypts the whole packet `buf` in place.
    // Go: kcp-go/v5@v5.6.66 crypt.go:BlockCrypt.Decrypt(dst, src) with dst == src
    #[inline]
    pub fn decrypt(&self, buf: &mut [u8]) {
        match self {
            BlockCrypt::Cfb(c) => c.decrypt(buf),
            BlockCrypt::Salsa20(c) => c.xor_key_stream(buf),
            BlockCrypt::Xor(c) => c.xor(buf),
            BlockCrypt::None => {}
        }
    }
}

/// Salsa20/20 packet cipher. The first 8 bytes of the packet (part of the random nonce) are the
/// Salsa20 nonce and stay in clear; the keystream (block counter from 0) is XORed over the rest.
/// Encryption and decryption are the same operation.
// Go: kcp-go/v5@v5.6.66 crypt.go:salsa20BlockCrypt
#[derive(Clone)]
pub struct Salsa20Crypt {
    key: [u8; 32],
}

impl Salsa20Crypt {
    /// XORs the Salsa20 keystream for nonce `buf[0..8]` over `buf[8..]`, in place.
    /// Packets shorter than 8 bytes are left untouched (Go v5.6.66 would panic on them).
    // Go: kcp-go/v5@v5.6.66 crypt.go:salsa20BlockCrypt.Encrypt/Decrypt
    //     (salsa20.XORKeyStream(dst[8:], src[8:], src[:8], &c.key))
    // Go (post-pin fix, V01): kcp-go@v5.6.72 crypt.go: `if len(src) < 8 { return }`
    #[inline]
    pub fn xor_key_stream(&self, buf: &mut [u8]) {
        let Some((nonce, data)) = buf.split_first_chunk_mut::<8>() else {
            return;
        };
        let mut cipher = salsa20::Salsa20::new(&self.key.into(), (&*nonce).into());
        cipher.apply_keystream(data);
    }
}

impl std::fmt::Debug for Salsa20Crypt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("..")
    }
}

/// XOR packet "cipher": the packet is XORed with a fixed 1500-byte pad derived from the key.
/// Bytes past the pad length are left in clear, as in Go.
// Go: kcp-go/v5@v5.6.66 crypt.go:simpleXORBlockCrypt
#[derive(Clone)]
pub struct XorCrypt {
    /// `PBKDF2-HMAC-SHA1(key, SALTXOR, 32, MTU_LIMIT)`. Boxed to keep [`BlockCrypt`] small.
    xortbl: Box<[u8; MTU_LIMIT]>,
}

impl XorCrypt {
    /// The pad XORed over every packet.
    pub fn xortbl(&self) -> &[u8; MTU_LIMIT] {
        &self.xortbl
    }

    /// XORs the first `min(buf.len(), MTU_LIMIT)` bytes of `buf` with the pad, in place.
    // Go: kcp-go/v5@v5.6.66 crypt.go:simpleXORBlockCrypt.Encrypt/Decrypt
    //     (subtle.XORBytes(dst, src, c.xortbl): min(len(src), len(xortbl)) bytes)
    // Go (post-pin fix, V01): kcp-go@v5.6.72 crypt.go: `if len(src) == 0 { return }`
    #[inline]
    pub fn xor(&self, buf: &mut [u8]) {
        if buf.is_empty() {
            return;
        }
        for (b, k) in buf.iter_mut().zip(self.xortbl.iter()) {
            *b ^= k;
        }
    }
}

impl std::fmt::Debug for XorCrypt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("..")
    }
}

/// AES in CFB mode. The key length selects the variant: 16 bytes AES-128, 24 bytes AES-192,
/// 32 bytes AES-256. Any other length fails with Go's `crypto/aes: invalid key size N`.
// Go: kcp-go/v5@v5.6.66 crypt.go:NewAESBlockCrypt()
pub fn new_aes_block_crypt(key: &[u8]) -> Result<BlockCrypt, CryptError> {
    let err = || CryptError::KeySize {
        pkg: "aes",
        size: key.len(),
    };
    let cipher = match key.len() {
        16 => CfbCipher::Aes128(aes::Aes128::new_from_slice(key).map_err(|_| err())?),
        24 => CfbCipher::Aes192(aes::Aes192::new_from_slice(key).map_err(|_| err())?),
        32 => CfbCipher::Aes256(aes::Aes256::new_from_slice(key).map_err(|_| err())?),
        _ => return Err(err()),
    };
    Ok(BlockCrypt::Cfb(cipher))
}

/// SM4 in CFB mode. The key must be 16 bytes, otherwise Go's `SM4: invalid key size N`.
// Go: kcp-go/v5@v5.6.66 crypt.go:NewSM4BlockCrypt() (github.com/tjfoc/gmsm/sm4.NewCipher)
pub fn new_sm4_block_crypt(key: &[u8]) -> Result<BlockCrypt, CryptError> {
    let block = sm4::Sm4Cipher::new_cipher(key)?;
    Ok(BlockCrypt::Cfb(CfbCipher::Sm4(block)))
}

/// Twofish in CFB mode. The key must be 16, 24 or 32 bytes, otherwise Go's
/// `crypto/twofish: invalid key size N`.
// Go: kcp-go/v5@v5.6.66 crypt.go:NewTwofishBlockCrypt() (golang.org/x/crypto/twofish.NewCipher)
pub fn new_twofish_block_crypt(key: &[u8]) -> Result<BlockCrypt, CryptError> {
    let block = twofish::Cipher::new_cipher(key)?;
    Ok(BlockCrypt::Cfb(CfbCipher::Twofish(block)))
}

/// Triple DES (EDE, three independent keys `k1 | k2 | k3`) in CFB mode. The key must be 24
/// bytes, otherwise Go's `crypto/des: invalid key size N`. Weak keys are accepted, as in Go.
// Go: kcp-go/v5@v5.6.66 crypt.go:NewTripleDESBlockCrypt() (crypto/des.NewTripleDESCipher)
pub fn new_triple_des_block_crypt(key: &[u8]) -> Result<BlockCrypt, CryptError> {
    let block = des::TripleDesCipher::new_triple_des_cipher(key)?;
    Ok(BlockCrypt::Cfb(CfbCipher::TripleDes(block)))
}

/// CAST5 in CFB mode. The key must be exactly 16 bytes, otherwise Go's
/// `CAST5: keys must be 16 bytes` (RustCrypto would also accept 5..16 bytes with zero padding;
/// that is rejected here, as in Go).
// Go: kcp-go/v5@v5.6.66 crypt.go:NewCast5BlockCrypt() (golang.org/x/crypto/cast5.NewCipher)
pub fn new_cast5_block_crypt(key: &[u8]) -> Result<BlockCrypt, CryptError> {
    if key.len() != 16 {
        return Err(CryptError::Cast5KeySize);
    }
    let block = cast5::Cast5::new_from_slice(key).map_err(|_| CryptError::Cast5KeySize)?;
    Ok(BlockCrypt::Cfb(CfbCipher::Cast5(block)))
}

/// Blowfish (big-endian, as Go) in CFB mode. Like Go, keys of 1 to 56 bytes are accepted;
/// anything else fails with `crypto/blowfish: invalid key size N`.
// Go: kcp-go/v5@v5.6.66 crypt.go:NewBlowfishBlockCrypt() (golang.org/x/crypto/blowfish.NewCipher)
pub fn new_blowfish_block_crypt(key: &[u8]) -> Result<BlockCrypt, CryptError> {
    let err = || CryptError::KeySize {
        pkg: "blowfish",
        size: key.len(),
    };
    let k = key.len();
    if !(1..=56).contains(&k) {
        return Err(err());
    }
    // RustCrypto requires at least 4 bytes; Go allows 1..=3. Both key schedules read the key
    // cyclically (ExpandKey: `j++; if j >= len(key) { j = 0 }`), so repeating a short key a whole
    // number of times until it is at least 4 bytes long yields the identical schedule.
    let mut expanded = [0u8; 56];
    let n = k * 4usize.div_ceil(k);
    for (i, b) in expanded[..n].iter_mut().enumerate() {
        *b = key[i % k];
    }
    let block = blowfish::Blowfish::new_from_slice(&expanded[..n]).map_err(|_| err())?;
    Ok(BlockCrypt::Cfb(CfbCipher::Blowfish(Box::new(block))))
}

/// TEA with 16 rounds in CFB mode. The key must be 16 bytes, otherwise Go's
/// `tea: incorrect key size`.
// Go: kcp-go/v5@v5.6.66 crypt.go:NewTEABlockCrypt() (golang.org/x/crypto/tea.NewCipherWithRounds(key, 16))
pub fn new_tea_block_crypt(key: &[u8]) -> Result<BlockCrypt, CryptError> {
    let block = tea::Tea::new_cipher_with_rounds(key, 16)?;
    Ok(BlockCrypt::Cfb(CfbCipher::Tea(block)))
}

/// XTEA in CFB mode. The key must be 16 bytes, otherwise Go's `crypto/xtea: invalid key size N`.
// Go: kcp-go/v5@v5.6.66 crypt.go:NewXTEABlockCrypt() (golang.org/x/crypto/xtea.NewCipher)
pub fn new_xtea_block_crypt(key: &[u8]) -> Result<BlockCrypt, CryptError> {
    let block = xtea::Xtea::new_cipher(key)?;
    Ok(BlockCrypt::Cfb(CfbCipher::Xtea(block)))
}

/// Salsa20/20 with a 32-byte key. Like Go, the key is copied into a zeroed 32-byte array: shorter
/// keys are zero-padded, longer ones truncated. Never fails.
// Go: kcp-go/v5@v5.6.66 crypt.go:NewSalsa20BlockCrypt() (copy(c.key[:], key))
pub fn new_salsa20_block_crypt(key: &[u8]) -> Result<BlockCrypt, CryptError> {
    let mut k = [0u8; 32];
    let n = key.len().min(k.len());
    k[..n].copy_from_slice(&key[..n]);
    Ok(BlockCrypt::Salsa20(Salsa20Crypt { key: k }))
}

/// XOR with the pad `PBKDF2-HMAC-SHA1(key, SALTXOR, 32 iterations, MTU_LIMIT bytes)`. Any key
/// length is accepted; never fails.
// Go: kcp-go/v5@v5.6.66 crypt.go:NewSimpleXORBlockCrypt()
pub fn new_simple_xor_block_crypt(key: &[u8]) -> Result<BlockCrypt, CryptError> {
    let mut xortbl = Box::new([0u8; MTU_LIMIT]);
    pbkdf2::pbkdf2_hmac::<Sha1>(key, SALTXOR.as_bytes(), 32, &mut xortbl[..]);
    Ok(BlockCrypt::Xor(XorCrypt { xortbl }))
}

/// Identity "cipher" (packets keep the nonce/CRC header but are not encrypted). The key is
/// ignored; never fails.
// Go: kcp-go/v5@v5.6.66 crypt.go:NewNoneBlockCrypt()
// Go (post-pin fix, V01): kcp-go@v5.6.72 crypt.go:noneBlockCrypt empty-input guard (a no-op in
//     place, where Go only copies when dst != src)
pub fn new_none_block_crypt(_key: &[u8]) -> Result<BlockCrypt, CryptError> {
    Ok(BlockCrypt::None)
}

/// AES-GCM AEAD crypt (`-crypt aes-128-gcm`, keyed with `pass[0:16]`). The key must be 16, 24 or
/// 32 bytes (AES-128/192/256), otherwise Go's `crypto/aes: invalid key size N`.
// Go: kcp-go/v5@v5.6.66 crypt.go:NewAESGCMCrypt()
pub fn new_aes_gcm_crypt(key: &[u8]) -> Result<PacketCrypt, CryptError> {
    AeadCrypt::new(key).map(PacketCrypt::Aead)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kcptun_testkit::{assert_hex_eq, vectors};
    use proptest::prelude::*;

    const PACKET_LENGTHS: usize = 18;
    const PASS_IDS: usize = 2;

    type NewFn = fn(&[u8]) -> Result<BlockCrypt, CryptError>;

    /// Runs every `cfb/<method>/` vector: `Encrypt(in) == out` and `Decrypt(out) == in`, both in
    /// place. Returns the number of cases so callers can assert nothing was skipped.
    fn run_cfb_vectors(method: &str, want_key_len: usize, new: NewFn) -> usize {
        let file = vectors!("crypt");
        let prefix = format!("cfb/{method}/");
        let mut n = 0;
        for case in file.cases_with_prefix(&prefix) {
            assert_eq!(case.param::<String>("method"), method, "case {}", case.name);
            let key_len: usize = case.param("key_len");
            assert_eq!(key_len, want_key_len, "case {}", case.name);
            let pass = case.param_bytes("pass");
            let bc = new(&pass[..key_len]).expect("valid key");

            let input = case.input();
            let output = case.output();
            assert_eq!(input.len(), output.len(), "case {}", case.name);

            let mut buf = input.clone();
            bc.encrypt(&mut buf);
            assert_hex_eq!(buf, output, "encrypt {}", case.name);

            // In place on the same buffer that was just encrypted (Go's dst == src aliasing).
            bc.decrypt(&mut buf);
            assert_hex_eq!(buf, input, "decrypt(encrypt) {}", case.name);

            let mut buf = output.clone();
            bc.decrypt(&mut buf);
            assert_hex_eq!(buf, input, "decrypt {}", case.name);
            n += 1;
        }
        n
    }

    #[test]
    fn vectors_cfb_aes() {
        assert_eq!(
            run_cfb_vectors("aes", 32, new_aes_block_crypt),
            PACKET_LENGTHS * PASS_IDS
        );
    }

    #[test]
    fn vectors_cfb_aes_128() {
        assert_eq!(
            run_cfb_vectors("aes-128", 16, new_aes_block_crypt),
            PACKET_LENGTHS * PASS_IDS
        );
    }

    #[test]
    fn vectors_cfb_aes_192() {
        assert_eq!(
            run_cfb_vectors("aes-192", 24, new_aes_block_crypt),
            PACKET_LENGTHS * PASS_IDS
        );
    }

    #[test]
    fn vectors_cfb_blowfish() {
        let n = run_cfb_vectors("blowfish", 32, new_blowfish_block_crypt);
        assert_eq!(n, PACKET_LENGTHS * PASS_IDS);
    }

    #[test]
    fn vectors_cfb_twofish() {
        let n = run_cfb_vectors("twofish", 32, new_twofish_block_crypt);
        assert_eq!(n, PACKET_LENGTHS * PASS_IDS);
    }

    #[test]
    fn vectors_cfb_cast5() {
        let n = run_cfb_vectors("cast5", 16, new_cast5_block_crypt);
        assert_eq!(n, PACKET_LENGTHS * PASS_IDS);
    }

    #[test]
    fn vectors_cfb_3des() {
        let n = run_cfb_vectors("3des", 24, new_triple_des_block_crypt);
        assert_eq!(n, PACKET_LENGTHS * PASS_IDS);
    }

    #[test]
    fn vectors_cfb_sm4() {
        let n = run_cfb_vectors("sm4", 16, new_sm4_block_crypt);
        assert_eq!(n, PACKET_LENGTHS * PASS_IDS);
    }

    #[test]
    fn vectors_cfb_tea() {
        let n = run_cfb_vectors("tea", 16, new_tea_block_crypt);
        assert_eq!(n, PACKET_LENGTHS * PASS_IDS);
    }

    #[test]
    fn vectors_cfb_xtea() {
        let n = run_cfb_vectors("xtea", 16, new_xtea_block_crypt);
        assert_eq!(n, PACKET_LENGTHS * PASS_IDS);
    }

    #[test]
    fn vectors_cfb_salsa20() {
        let n = run_cfb_vectors("salsa20", 32, new_salsa20_block_crypt);
        assert_eq!(n, PACKET_LENGTHS * PASS_IDS);
    }

    #[test]
    fn vectors_cfb_xor() {
        let n = run_cfb_vectors("xor", 32, new_simple_xor_block_crypt);
        assert_eq!(n, PACKET_LENGTHS * PASS_IDS);
    }

    #[test]
    fn vectors_cfb_none() {
        let n = run_cfb_vectors("none", 32, new_none_block_crypt);
        assert_eq!(n, PACKET_LENGTHS * PASS_IDS);
        // Identity, checked explicitly (run_cfb_vectors only compares against Go's output).
        for case in vectors!("crypt").cases_with_prefix("cfb/none/") {
            assert_hex_eq!(case.input(), case.output(), "identity {}", case.name);
        }
    }

    #[test]
    fn vectors_xor_pad() {
        let file = vectors!("crypt");
        let mut n = 0;
        for case in file.cases_with_prefix("xor_pad/") {
            let pass = case.param_bytes("pass");
            let BlockCrypt::Xor(x) = new_simple_xor_block_crypt(&pass).expect("never fails") else {
                panic!("not xor")
            };
            let want = case.output();
            assert_eq!(want.len(), MTU_LIMIT, "case {}", case.name);
            assert_hex_eq!(x.xortbl(), want, "pad {}", case.name);

            // Encrypting zeros yields the pad itself.
            let mut buf = [0u8; MTU_LIMIT];
            BlockCrypt::Xor(x).encrypt(&mut buf);
            assert_hex_eq!(buf, want, "zeros {}", case.name);
            n += 1;
        }
        assert_eq!(n, PASS_IDS);
    }

    /// Salsa20 on packets shorter than the 8-byte nonce is a no-op (post-pin kcp-go fix, V01;
    /// v5.6.66 panics). Exactly 8 bytes: nothing to encrypt, also unchanged.
    #[test]
    fn salsa20_short_packet_guard() {
        let bc = new_salsa20_block_crypt(&[0x5au8; 32]).expect("never fails");
        for len in 0..=8 {
            let orig: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(37)).collect();
            let mut buf = orig.clone();
            bc.encrypt(&mut buf);
            assert_eq!(buf, orig, "encrypt len {len}");
            bc.decrypt(&mut buf);
            assert_eq!(buf, orig, "decrypt len {len}");
        }
        // From 9 bytes on, the nonce stays in clear and the rest is encrypted.
        let orig = [0u8; 9];
        let mut buf = orig;
        bc.encrypt(&mut buf);
        assert_eq!(buf[..8], orig[..8]);
        assert_ne!(
            buf[8], 0,
            "keystream byte (fixed key/nonce, known non-zero)"
        );
    }

    /// Go copies the key into a zeroed `[32]byte`: short keys are zero-padded, long keys
    /// truncated (`select_short/method=salsa20` covers a 16-byte key against Go).
    #[test]
    fn salsa20_key_copy_semantics() {
        let encrypt = |key: &[u8]| {
            let mut buf = [0x11u8; 64];
            new_salsa20_block_crypt(key)
                .expect("never fails")
                .encrypt(&mut buf);
            buf
        };
        let mut padded = [0u8; 32];
        padded[..16].copy_from_slice(&[9u8; 16]);
        assert_eq!(encrypt(&[9u8; 16]), encrypt(&padded));
        assert_eq!(encrypt(&[0u8; 0]), encrypt(&[0u8; 32]));
        let mut long = [3u8; 40];
        long[32..].fill(0xee);
        assert_eq!(encrypt(&long), encrypt(&[3u8; 32]));
    }

    /// Salsa20 keystream against the published Salsa20/20 test vector (ECRYPT set 1, vector 0:
    /// key 0x80 followed by 31 zero bytes, zero nonce), through the packet layout.
    #[test]
    fn salsa20_ecrypt_known_answer() {
        let mut key = [0u8; 32];
        key[0] = 0x80;
        let bc = new_salsa20_block_crypt(&key).expect("never fails");
        let mut buf = [0u8; 8 + 64];
        bc.encrypt(&mut buf);
        assert_eq!(
            hex::encode(&buf[8..]),
            "e3be8fdd8beca2e3ea8ef9475b29a6e7003951e1097a5c38d23b7a5fad9f6844\
             b22c97559e2723c7cbbd3fe4fc8d9a0744652a83e72a9c461876af4d7ef1a117"
        );
    }

    /// XOR covers only the first 1500 bytes; the rest of a longer buffer is left as is.
    #[test]
    fn xor_limited_to_pad_length() {
        let bc = new_simple_xor_block_crypt(b"k").expect("never fails");
        let BlockCrypt::Xor(x) = &bc else {
            panic!("not xor")
        };
        let pad = *x.xortbl();
        let mut buf = vec![0u8; MTU_LIMIT + 100];
        bc.encrypt(&mut buf);
        assert_eq!(buf[..MTU_LIMIT], pad[..]);
        assert!(buf[MTU_LIMIT..].iter().all(|&b| b == 0));
        let mut short = [0u8; 7];
        bc.encrypt(&mut short);
        assert_eq!(short[..], pad[..7]);
    }

    /// Empty packets: every mode is a no-op and does not panic (V01 guards for xor/none, and the
    /// salsa20 short-packet guard).
    #[test]
    fn empty_packet_guards() {
        let key = [0x33u8; 32];
        let ctors: [NewFn; 3] = [
            new_salsa20_block_crypt,
            new_simple_xor_block_crypt,
            new_none_block_crypt,
        ];
        for new in ctors {
            let bc = new(&key).expect("never fails");
            let mut buf: [u8; 0] = [];
            bc.encrypt(&mut buf);
            bc.decrypt(&mut buf);
        }
    }

    #[test]
    fn none_is_identity() {
        let bc = new_none_block_crypt(b"ignored").expect("never fails");
        let orig: Vec<u8> = (0..=255u8).collect();
        let mut buf = orig.clone();
        bc.encrypt(&mut buf);
        assert_eq!(buf, orig);
        bc.decrypt(&mut buf);
        assert_eq!(buf, orig);
    }

    #[test]
    fn stream_modes_never_fail_for_any_key_length() {
        for len in 0..=64 {
            let key = vec![0xa5u8; len];
            new_salsa20_block_crypt(&key).expect("salsa20");
            new_simple_xor_block_crypt(&key).expect("xor");
            new_none_block_crypt(&key).expect("none");
        }
    }

    #[test]
    fn packet_crypt_wraps_block() {
        let pc = PacketCrypt::from(new_none_block_crypt(&[]).expect("never fails"));
        assert!(matches!(pc.as_block(), Some(BlockCrypt::None)));
        assert!(pc.as_aead().is_none());
        let pc = new_aes_gcm_crypt(&[0u8; 16]).expect("valid AES key");
        assert!(pc.as_block().is_none());
        assert!(pc.as_aead().is_some());
        assert_eq!(format!("{pc:?}"), "Aead(Aes128Gcm(..))");
    }

    #[test]
    fn block_crypt_stays_small() {
        // Large key schedules (Blowfish) and the xor pad are boxed.
        assert!(
            std::mem::size_of::<BlockCrypt>() <= 1100,
            "{}",
            std::mem::size_of::<BlockCrypt>()
        );
    }

    /// Single-block known answers derived from the Go CFB vectors: the first ciphertext block is
    /// `P_0 ^ E(IV[0:8])`, so `in[0:8] ^ out[0:8]` is Go's `Encrypt(IV[0:8])` under the vector's
    /// key. Checks the hand-written block functions directly, outside the CFB engine.
    #[test]
    fn vectors_tea_xtea_single_block() {
        let file = vectors!("crypt");
        let mut n = 0;
        for method in ["tea", "xtea"] {
            for case in file.cases_with_prefix(&format!("cfb/{method}/")) {
                let key_len: usize = case.param("key_len");
                let key = &case.param_bytes("pass")[..key_len];
                let (input, output) = (case.input(), case.output());
                let mut keystream = [0u8; 8];
                for (k, (i, o)) in keystream.iter_mut().zip(input.iter().zip(&output)) {
                    *k = i ^ o;
                }
                let mut iv = [0u8; 8];
                iv.copy_from_slice(&cfb::INITIAL_VECTOR[..8]);

                // Encrypt(IV) == keystream, and Decrypt(keystream) == IV.
                let (mut enc, mut dec) = (iv, keystream);
                if method == "tea" {
                    let t = tea::Tea::new_cipher_with_rounds(key, 16).expect("valid");
                    t.encrypt(&mut enc);
                    t.decrypt(&mut dec);
                } else {
                    let x = xtea::Xtea::new_cipher(key).expect("valid");
                    x.encrypt(&mut enc);
                    x.decrypt(&mut dec);
                }
                assert_hex_eq!(enc, keystream, "encrypt {}", case.name);
                assert_hex_eq!(dec, iv, "decrypt {}", case.name);
                n += 1;
            }
        }
        assert_eq!(n, 2 * PACKET_LENGTHS * PASS_IDS);
    }

    /// Single-block Blowfish known answers from `golang.org/x/crypto/blowfish` for every key
    /// length class, including Go's 1..=3-byte keys that RustCrypto does not accept directly.
    /// Key = bytes `1..=n`, plaintext `0123456789abcdef`.
    #[test]
    fn blowfish_short_keys_match_x_crypto() {
        use cipher::BlockCipherEncrypt;
        let cases = [
            (1, "fa34ec4847b268b2"),
            (2, "b9abb2c629f4d313"),
            (3, "7277f8d8875bfee7"),
            (4, "233f5ee1e484ee26"),
            (5, "c27c55d0b4796e71"),
            (7, "b01a9eb4b5d6bb8d"),
            (32, "6fee22e5362d84e9"),
            (56, "d08f329bfcfd1564"),
        ];
        for (n, want) in cases {
            let key: Vec<u8> = (1..=n as u8).collect();
            let bc = new_blowfish_block_crypt(&key).expect("valid key");
            let BlockCrypt::Cfb(CfbCipher::Blowfish(b)) = bc else {
                panic!("not blowfish: {bc:?}")
            };
            let mut block = [0x01u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
            b.encrypt_block((&mut block).into());
            assert_eq!(hex::encode(block), want, "key len {n}");
        }
    }

    /// Every constructor: accepted key lengths, block size, and Go's error text otherwise.
    #[test]
    fn key_sizes_and_errors_match_go() {
        struct Case {
            new: NewFn,
            ok: fn(usize) -> bool,
            block_size: usize,
            err: fn(usize) -> String,
        }
        let cases = [
            Case {
                new: new_blowfish_block_crypt,
                ok: |n| (1..=56).contains(&n),
                block_size: 8,
                err: |n| format!("crypto/blowfish: invalid key size {n}"),
            },
            Case {
                new: new_twofish_block_crypt,
                ok: |n| matches!(n, 16 | 24 | 32),
                block_size: 16,
                err: |n| format!("crypto/twofish: invalid key size {n}"),
            },
            Case {
                new: new_cast5_block_crypt,
                ok: |n| n == 16,
                block_size: 8,
                err: |_| "CAST5: keys must be 16 bytes".to_owned(),
            },
            Case {
                new: new_triple_des_block_crypt,
                ok: |n| n == 24,
                block_size: 8,
                err: |n| format!("crypto/des: invalid key size {n}"),
            },
            Case {
                new: new_sm4_block_crypt,
                ok: |n| n == 16,
                block_size: 16,
                err: |n| format!("SM4: invalid key size {n}"),
            },
            Case {
                new: new_tea_block_crypt,
                ok: |n| n == 16,
                block_size: 8,
                err: |_| "tea: incorrect key size".to_owned(),
            },
            Case {
                new: new_xtea_block_crypt,
                ok: |n| n == 16,
                block_size: 8,
                err: |n| format!("crypto/xtea: invalid key size {n}"),
            },
        ];
        let key = [7u8; 64];
        for (i, c) in cases.iter().enumerate() {
            for len in 0..=key.len() {
                match (c.new)(&key[..len]) {
                    Ok(BlockCrypt::Cfb(cc)) => {
                        assert!((c.ok)(len), "case {i} len {len} accepted");
                        assert_eq!(cc.block_size(), c.block_size, "case {i}");
                    }
                    Ok(other) => panic!("case {i}: not a CFB cipher: {other:?}"),
                    Err(e) => {
                        assert!(!(c.ok)(len), "case {i} len {len}: {e}");
                        assert_eq!(e.to_string(), (c.err)(len), "case {i}");
                    }
                }
            }
        }
    }

    #[test]
    fn aes_key_sizes() {
        let key = [7u8; 40];
        for len in 0..=key.len() {
            let r = new_aes_block_crypt(&key[..len]);
            match len {
                16 | 24 | 32 => {
                    let Ok(BlockCrypt::Cfb(c)) = r else {
                        panic!("len {len}: {r:?}")
                    };
                    assert_eq!(c.block_size(), 16);
                }
                _ => {
                    let e = r.expect_err("invalid key size");
                    assert_eq!(e.to_string(), format!("crypto/aes: invalid key size {len}"));
                }
            }
        }
    }

    #[test]
    fn aes_variants_use_distinct_key_schedules() {
        // "aes-128" must use its own 16-byte key, not a truncated AES-256 schedule.
        let pass = [0x42u8; 32];
        let mut outs = Vec::new();
        for len in [16, 24, 32] {
            let bc = new_aes_block_crypt(&pass[..len]).expect("valid AES key");
            let mut buf = [0u8; 40];
            bc.encrypt(&mut buf);
            outs.push(buf);
        }
        assert_ne!(outs[0], outs[1]);
        assert_ne!(outs[1], outs[2]);
        assert_ne!(outs[0], outs[2]);
    }

    #[test]
    fn empty_packet_is_noop() {
        let bc = new_aes_block_crypt(&[1u8; 32]).expect("valid AES key");
        let mut buf: [u8; 0] = [];
        bc.encrypt(&mut buf);
        bc.decrypt(&mut buf);
    }

    #[test]
    fn block_crypt_is_send_sync() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<BlockCrypt>();
        assert_send_sync::<PacketCrypt>();
    }

    #[test]
    fn debug_does_not_leak_key() {
        let bc = new_aes_block_crypt(&[0xabu8; 16]).expect("valid AES key");
        assert_eq!(format!("{bc:?}"), "Cfb(Aes128(..))");
        let names: [(NewFn, &str); 7] = [
            (new_blowfish_block_crypt, "Cfb(Blowfish(..))"),
            (new_twofish_block_crypt, "Cfb(Twofish(..))"),
            (new_cast5_block_crypt, "Cfb(Cast5(..))"),
            (new_triple_des_block_crypt, "Cfb(TripleDes(..))"),
            (new_sm4_block_crypt, "Cfb(Sm4(..))"),
            (new_tea_block_crypt, "Cfb(Tea(..))"),
            (new_xtea_block_crypt, "Cfb(Xtea(..))"),
        ];
        let key = [0xabu8; 32];
        for (new, want) in names {
            let key_len = match want {
                "Cfb(TripleDes(..))" => 24,
                "Cfb(Blowfish(..))" | "Cfb(Twofish(..))" => 32,
                _ => 16,
            };
            let bc = new(&key[..key_len]).expect("valid key");
            assert_eq!(format!("{bc:?}"), want);
        }
        let stream: [(NewFn, &str); 3] = [
            (new_salsa20_block_crypt, "Salsa20(..)"),
            (new_simple_xor_block_crypt, "Xor(..)"),
            (new_none_block_crypt, "None"),
        ];
        for (new, want) in stream {
            let bc = new(&key).expect("never fails");
            assert_eq!(format!("{bc:?}"), want);
        }
    }

    /// The non-AES CFB constructors with the key length `select_block_crypt` gives them.
    fn other_cfb() -> impl Strategy<Value = (NewFn, usize)> {
        prop::sample::select(vec![
            (new_blowfish_block_crypt as NewFn, 32usize),
            (new_twofish_block_crypt, 32),
            (new_cast5_block_crypt, 16),
            (new_triple_des_block_crypt, 24),
            (new_sm4_block_crypt, 16),
            (new_tea_block_crypt, 16),
            (new_xtea_block_crypt, 16),
        ])
    }

    proptest! {
        #[test]
        fn prop_other_cfb_roundtrip(
            (new, key_len) in other_cfb(),
            key in proptest::collection::vec(any::<u8>(), 32),
            data in proptest::collection::vec(any::<u8>(), 0..=1500),
        ) {
            let bc = new(&key[..key_len]).expect("valid key");
            let mut buf = data.clone();
            bc.encrypt(&mut buf);
            if data.len() >= 16 {
                prop_assert_ne!(&buf, &data);
            }
            bc.decrypt(&mut buf);
            prop_assert_eq!(buf, data);
        }

        /// Blowfish keys of every length Go accepts (1..=56), including the short ones that are
        /// cyclically expanded for RustCrypto.
        #[test]
        fn prop_blowfish_any_key_roundtrip(
            key in proptest::collection::vec(any::<u8>(), 1..=56),
            data in proptest::collection::vec(any::<u8>(), 0..=200),
        ) {
            let bc = new_blowfish_block_crypt(&key).expect("valid key");
            let mut buf = data.clone();
            bc.encrypt(&mut buf);
            bc.decrypt(&mut buf);
            prop_assert_eq!(buf, data);
        }

        #[test]
        fn prop_stream_roundtrip(
            new in prop::sample::select(vec![
                new_salsa20_block_crypt as NewFn,
                new_simple_xor_block_crypt,
                new_none_block_crypt,
            ]),
            key in proptest::collection::vec(any::<u8>(), 0..=40),
            data in proptest::collection::vec(any::<u8>(), 0..=1600),
        ) {
            let bc = new(&key).expect("never fails");
            let mut buf = data.clone();
            bc.encrypt(&mut buf);
            bc.decrypt(&mut buf);
            prop_assert_eq!(buf, data);
        }

        /// XOR and Salsa20 are their own inverse, and the Salsa20 nonce bytes stay in clear.
        #[test]
        fn prop_stream_encrypt_is_decrypt(
            key in proptest::collection::vec(any::<u8>(), 32),
            data in proptest::collection::vec(any::<u8>(), 0..=1600),
        ) {
            for bc in [
                new_salsa20_block_crypt(&key).expect("never fails"),
                new_simple_xor_block_crypt(&key).expect("never fails"),
            ] {
                let (mut a, mut b) = (data.clone(), data.clone());
                bc.encrypt(&mut a);
                bc.decrypt(&mut b);
                prop_assert_eq!(&a, &b);
                if matches!(bc, BlockCrypt::Salsa20(_)) {
                    let n = data.len().min(8);
                    prop_assert_eq!(&a[..n], &data[..n]);
                }
            }
        }

        #[test]
        fn prop_aes_roundtrip(
            key_len in prop::sample::select(vec![16usize, 24, 32]),
            key in proptest::collection::vec(any::<u8>(), 32),
            data in proptest::collection::vec(any::<u8>(), 0..=1500),
        ) {
            let bc = new_aes_block_crypt(&key[..key_len]).expect("valid AES key");
            let mut buf = data.clone();
            bc.encrypt(&mut buf);
            if data.len() >= 16 {
                prop_assert_ne!(&buf, &data);
            }
            bc.decrypt(&mut buf);
            prop_assert_eq!(buf, data);
        }

        /// Encryption of a prefix is the prefix of the encryption (CFB is a prefix-preserving
        /// stream construction; checks the partial-tail handling against full blocks).
        #[test]
        fn prop_aes_prefix_consistent(
            key in proptest::collection::vec(any::<u8>(), 32),
            data in proptest::collection::vec(any::<u8>(), 0..=1500),
            cut in any::<prop::sample::Index>(),
        ) {
            let bc = new_aes_block_crypt(&key).expect("valid AES key");
            let mut full = data.clone();
            bc.encrypt(&mut full);
            let k = cut.index(data.len() + 1);
            let mut prefix = data[..k].to_vec();
            bc.encrypt(&mut prefix);
            prop_assert_eq!(&prefix[..], &full[..k]);
        }
    }
}
