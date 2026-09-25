//! AES-GCM packet AEAD (`-crypt aes-128-gcm`), port of kcp-go's `aeadCrypt`.
//!
//! Packet layout (WIRE-FORMAT §2.2): `[nonce(12) | AES-GCM(plaintext) | tag(16)]`, no additional
//! data and no CRC32. The plaintext is the FEC header (if any) followed by the KCP segments.
//!
//! Both directions work in place on the packet buffer, as Go does with `Seal(buf[:12], nonce,
//! buf[12:], nil)` and `Open(data[12:12], nonce, data[12:], nil)`.

use aes_gcm::aead::consts::U12;
use aes_gcm::{AeadInOut, AesGcm, KeyInit};

use super::CryptError;

/// Errors of the in-place AEAD operations. The messages are Go's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AeadError {
    /// The buffer has no room for the 16-byte tag after the plaintext (Go panics here), or the
    /// packet is shorter than the 12-byte nonce.
    // Go: kcp-go/v5@v5.6.66 crypt.go:aeadCrypt.Seal() panic text
    #[error("AEAD Seal allocated new slice, please increase MTU size")]
    SealBufferTooSmall,
    /// Authentication failed: tampered or truncated packet, wrong key, or a packet shorter than
    /// nonce + tag.
    // Go: crypto/cipher gcm.go:errOpen
    #[error("cipher: message authentication failed")]
    Open,
}

/// AES-192-GCM with the standard 96-bit nonce (RustCrypto names only the 128 and 256 variants).
type Aes192Gcm = AesGcm<aes::Aes192, U12>;

/// The AES key size, chosen by the key length as in Go's `aes.NewCipher`.
#[derive(Clone)]
enum Gcm {
    Aes128(aes_gcm::Aes128Gcm),
    Aes192(Aes192Gcm),
    Aes256(aes_gcm::Aes256Gcm),
}

/// AES-GCM packet AEAD. `-crypt aes-128-gcm` keys it with `pass[0:16]` (AES-128); like Go's
/// `NewAESGCMCrypt`, 24- and 32-byte keys select AES-192 and AES-256.
///
/// Immutable after construction, so it is `Send + Sync` and needs no lock (Go's `cipher.AEAD`
/// is also stateless).
// Go: kcp-go/v5@v5.6.66 crypt.go:aeadCrypt
#[derive(Clone)]
pub struct AeadCrypt {
    gcm: Gcm,
}

impl AeadCrypt {
    /// Nonce length in bytes, at the start of every packet.
    // Go: crypto/cipher gcm.go:gcmStandardNonceSize (aeadCrypt.NonceSize())
    pub const NONCE: usize = 12;
    /// Tag length in bytes, appended to the ciphertext.
    // Go: crypto/cipher gcm.go:gcmTagSize (aeadCrypt.Overhead())
    pub const OVERHEAD: usize = 16;

    /// Creates the AEAD from a 16-, 24- or 32-byte AES key; any other length fails with Go's
    /// `crypto/aes: invalid key size N`.
    // Go: kcp-go/v5@v5.6.66 crypt.go:NewAESGCMCrypt()
    pub fn new(key: &[u8]) -> Result<Self, CryptError> {
        let err = || CryptError::KeySize {
            pkg: "aes",
            size: key.len(),
        };
        let gcm = match key.len() {
            16 => Gcm::Aes128(aes_gcm::Aes128Gcm::new_from_slice(key).map_err(|_| err())?),
            24 => Gcm::Aes192(Aes192Gcm::new_from_slice(key).map_err(|_| err())?),
            32 => Gcm::Aes256(aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|_| err())?),
            _ => return Err(err()),
        };
        Ok(AeadCrypt { gcm })
    }

    /// Nonce length (always [`Self::NONCE`]); the packet header size in AEAD mode.
    // Go: kcp-go/v5@v5.6.66 crypt.go:aeadCrypt.NonceSize()
    #[inline]
    pub fn nonce_size(&self) -> usize {
        Self::NONCE
    }

    /// Bytes added by sealing (always [`Self::OVERHEAD`]); the session MTU shrinks by this.
    // Go: kcp-go/v5@v5.6.66 crypt.go:aeadCrypt.Overhead()
    #[inline]
    pub fn overhead(&self) -> usize {
        Self::OVERHEAD
    }

    /// Seals a packet in place. `buf[..len]` holds `[nonce(12) | plaintext]` (the caller fills
    /// the nonce, see `entropy::fill_nonce`); afterwards `buf[..len + 16]` is
    /// `[nonce | ciphertext | tag]` and that new length is returned.
    ///
    /// `buf` must have at least [`Self::OVERHEAD`] spare bytes after `len`, and `len` must be at
    /// least [`Self::NONCE`]. Go panics when the tag does not fit; this returns
    /// [`AeadError::SealBufferTooSmall`] and leaves `buf` unchanged.
    // Go: kcp-go/v5@v5.6.66 crypt.go:aeadCrypt.Seal(), called from sess.go:postProcess() as
    //     block.Seal(buf[:nonceSize], buf[:nonceSize], buf[nonceSize:], nil)
    pub fn seal_in_place(&self, buf: &mut [u8], len: usize) -> Result<usize, AeadError> {
        let sealed_len = len
            .checked_add(Self::OVERHEAD)
            .ok_or(AeadError::SealBufferTooSmall)?;
        if len < Self::NONCE || buf.len() < sealed_len {
            return Err(AeadError::SealBufferTooSmall);
        }
        let (nonce, rest) = buf[..sealed_len]
            .split_first_chunk_mut::<{ Self::NONCE }>()
            .ok_or(AeadError::SealBufferTooSmall)?;
        let (plaintext, tag_out) = rest.split_at_mut(len - Self::NONCE);
        let nonce = &*nonce;
        // Plaintext length is bounded by the buffer, far below GCM's 2^36-byte limit, so the
        // RustCrypto error is unreachable; it maps to the Go error rather than panicking.
        let tag = match &self.gcm {
            Gcm::Aes128(g) => g.encrypt_inout_detached(nonce.into(), &[], plaintext.into()),
            Gcm::Aes192(g) => g.encrypt_inout_detached(nonce.into(), &[], plaintext.into()),
            Gcm::Aes256(g) => g.encrypt_inout_detached(nonce.into(), &[], plaintext.into()),
        }
        .map_err(|_| AeadError::SealBufferTooSmall)?;
        tag_out.copy_from_slice(&tag);
        Ok(sealed_len)
    }

    /// Opens a received packet `[nonce(12) | ciphertext | tag(16)]` in place and returns the
    /// plaintext, which is `pkt[12..pkt.len() - 16]`.
    ///
    /// Fails with Go's `cipher: message authentication failed` when the packet is shorter than
    /// nonce + tag or does not authenticate (the session then counts `InCsumErrors` and drops
    /// it). On failure the contents of `pkt` are unspecified.
    // Go: kcp-go/v5@v5.6.66 crypt.go:aeadCrypt.Open(), called from sess.go:packetInput() as
    //     block.Open(data[nonceSize:nonceSize], data[:nonceSize], data[nonceSize:], nil)
    pub fn open_in_place<'a>(&self, pkt: &'a mut [u8]) -> Result<&'a mut [u8], AeadError> {
        // Go: sess.go:packetInput `len(data) < nonceSize+block.Overhead()` drop; crypto/cipher
        // gcm.go:Open also rejects ciphertext shorter than the tag with errOpen.
        let (nonce, rest) = pkt
            .split_first_chunk_mut::<{ Self::NONCE }>()
            .ok_or(AeadError::Open)?;
        let (ciphertext, tag) = rest
            .split_last_chunk_mut::<{ Self::OVERHEAD }>()
            .ok_or(AeadError::Open)?;
        let (nonce, tag) = (&*nonce, &*tag);
        match &self.gcm {
            Gcm::Aes128(g) => {
                g.decrypt_inout_detached(nonce.into(), &[], (&mut *ciphertext).into(), tag.into())
            }
            Gcm::Aes192(g) => {
                g.decrypt_inout_detached(nonce.into(), &[], (&mut *ciphertext).into(), tag.into())
            }
            Gcm::Aes256(g) => {
                g.decrypt_inout_detached(nonce.into(), &[], (&mut *ciphertext).into(), tag.into())
            }
        }
        .map_err(|_| AeadError::Open)?;
        Ok(ciphertext)
    }
}

impl std::fmt::Debug for AeadCrypt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.gcm {
            Gcm::Aes128(_) => "Aes128Gcm(..)",
            Gcm::Aes192(_) => "Aes192Gcm(..)",
            Gcm::Aes256(_) => "Aes256Gcm(..)",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kcptun_testkit::{assert_hex_eq, vectors};
    use proptest::prelude::*;

    const N: usize = AeadCrypt::NONCE;
    const T: usize = AeadCrypt::OVERHEAD;

    /// `[nonce | plaintext]` followed by `spare` zero bytes.
    fn packet(nonce: &[u8], plaintext: &[u8], spare: usize) -> Vec<u8> {
        let mut buf = nonce.to_vec();
        buf.extend_from_slice(plaintext);
        buf.resize(buf.len() + spare, 0);
        buf
    }

    /// Seals `plaintext` with `nonce` into an exactly sized buffer.
    fn seal(a: &AeadCrypt, nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut buf = packet(nonce, plaintext, T);
        let n = a
            .seal_in_place(&mut buf, N + plaintext.len())
            .expect("room for the tag");
        assert_eq!(n, buf.len());
        buf
    }

    #[test]
    fn vectors_aead() {
        let file = vectors!("crypt");
        let mut lens = Vec::new();
        for case in file.cases_with_prefix("aead/") {
            assert_eq!(case.param::<String>("method"), "aes-128-gcm");
            let key_len: usize = case.param("key_len");
            assert_eq!(key_len, 16, "case {}", case.name);
            let key = &case.param_bytes("pass")[..key_len];
            let nonce = case.param_bytes("nonce");
            assert_eq!(nonce.len(), N);
            let a = AeadCrypt::new(key).expect("valid key");
            let (plaintext, sealed) = (case.input(), case.output());
            assert_eq!(sealed.len(), N + plaintext.len() + T, "case {}", case.name);

            // Exactly sized buffer.
            assert_hex_eq!(seal(&a, &nonce, &plaintext), sealed, "seal {}", case.name);

            // Pooled-buffer style: a 1500-byte buffer with the packet at the front.
            let mut pool = packet(&nonce, &plaintext, 1500 - N - plaintext.len());
            let n = a
                .seal_in_place(&mut pool, N + plaintext.len())
                .expect("room for the tag");
            assert_hex_eq!(pool[..n], sealed, "seal pooled {}", case.name);
            assert!(pool[n..].iter().all(|&b| b == 0), "no write past the tag");

            let mut buf = sealed.clone();
            let opened = a.open_in_place(&mut buf).expect("authentic");
            assert_hex_eq!(opened, plaintext, "open {}", case.name);
            assert_hex_eq!(buf[..N], nonce, "nonce untouched {}", case.name);
            lens.push(plaintext.len());
        }
        lens.sort_unstable();
        assert_eq!(lens, [0, 0, 1, 1, 24, 24, 1314, 1314]);
    }

    /// Published GCM known answers (McGrew & Viega, "The Galois/Counter Mode of Operation",
    /// test cases 3, 9 and 15: no AAD, 96-bit IV) for all three key sizes Go accepts.
    #[test]
    fn gcm_spec_known_answers() {
        let nonce = hex::decode("cafebabefacedbaddecaf888").expect("hex");
        let plaintext = hex::decode(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        )
        .expect("hex");
        let cases = [
            (
                "feffe9928665731c6d6a8f9467308308",
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                 21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
                "4d5c2af327cd64a62cf35abd2ba6fab4",
                "Aes128Gcm(..)",
            ),
            (
                "feffe9928665731c6d6a8f9467308308feffe9928665731c",
                "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c\
                 7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256",
                "9924a7c8587336bfb118024db8674a14",
                "Aes192Gcm(..)",
            ),
            (
                "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
                 8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
                "b094dac5d93471bdec1a502270e3cc6c",
                "Aes256Gcm(..)",
            ),
        ];
        for (key, ct, tag, name) in cases {
            let a = AeadCrypt::new(&hex::decode(key).expect("hex")).expect("valid key");
            assert_eq!(format!("{a:?}"), name);
            let sealed = seal(&a, &nonce, &plaintext);
            assert_eq!(hex::encode(&sealed[N..N + plaintext.len()]), ct, "{name}");
            assert_eq!(hex::encode(&sealed[N + plaintext.len()..]), tag, "{name}");
            let mut buf = sealed;
            assert_eq!(a.open_in_place(&mut buf).expect("authentic"), plaintext);
        }
    }

    /// Every single-byte change anywhere in the packet (nonce, ciphertext or tag) fails to open.
    #[test]
    fn tampered_packet_fails_to_open() {
        let a = AeadCrypt::new(&[0x42u8; 16]).expect("valid key");
        let nonce = [7u8; N];
        let plaintext: Vec<u8> = (0..24u8).collect();
        let sealed = seal(&a, &nonce, &plaintext);
        for i in 0..sealed.len() {
            for flip in [0x01u8, 0x80, 0xff] {
                let mut buf = sealed.clone();
                buf[i] ^= flip;
                assert_eq!(
                    a.open_in_place(&mut buf).map(|p| p.to_vec()),
                    Err(AeadError::Open),
                    "byte {i} ^ {flip:#x}"
                );
            }
        }
        // Truncated, extended, or opened with another key or key size: all fail.
        let mut short = sealed[..sealed.len() - 1].to_vec();
        assert_eq!(a.open_in_place(&mut short).err(), Some(AeadError::Open));
        let mut long = sealed.clone();
        long.push(0);
        assert_eq!(a.open_in_place(&mut long).err(), Some(AeadError::Open));
        for key in [&[0x43u8; 16][..], &[0x42u8; 24][..], &[0x42u8; 32][..]] {
            let other = AeadCrypt::new(key).expect("valid key");
            let mut buf = sealed.clone();
            assert_eq!(other.open_in_place(&mut buf).err(), Some(AeadError::Open));
        }
        // The untouched packet still opens.
        let mut buf = sealed;
        assert_eq!(a.open_in_place(&mut buf).expect("authentic"), plaintext);
    }

    /// Packets shorter than nonce + tag (28 bytes) are rejected without panicking; 28 bytes is
    /// the sealed empty plaintext.
    #[test]
    fn too_short_packet_rejected() {
        let a = AeadCrypt::new(&[1u8; 16]).expect("valid key");
        for len in 0..N + T {
            let mut buf = vec![0u8; len];
            assert_eq!(
                a.open_in_place(&mut buf).err(),
                Some(AeadError::Open),
                "len {len}"
            );
        }
        let mut empty = seal(&a, &[9u8; N], &[]);
        assert_eq!(empty.len(), N + T);
        assert_eq!(
            a.open_in_place(&mut empty).expect("authentic"),
            &[] as &[u8]
        );
    }

    /// Go panics when the tag does not fit ("please increase MTU size"); here it is an error and
    /// the buffer is left as it was.
    #[test]
    fn seal_without_room_for_tag_fails() {
        let a = AeadCrypt::new(&[1u8; 16]).expect("valid key");
        let plaintext = [0x5au8; 40];
        for spare in 0..T {
            let mut buf = packet(&[3u8; N], &plaintext, spare);
            let orig = buf.clone();
            assert_eq!(
                a.seal_in_place(&mut buf, N + plaintext.len()),
                Err(AeadError::SealBufferTooSmall),
                "spare {spare}"
            );
            assert_eq!(buf, orig);
        }
        // Shorter than the nonce, and a length past the buffer end.
        let mut buf = [0u8; 64];
        for len in 0..N {
            assert_eq!(
                a.seal_in_place(&mut buf, len),
                Err(AeadError::SealBufferTooSmall)
            );
        }
        assert_eq!(
            a.seal_in_place(&mut buf, 100),
            Err(AeadError::SealBufferTooSmall)
        );
        assert_eq!(
            a.seal_in_place(&mut buf, usize::MAX),
            Err(AeadError::SealBufferTooSmall)
        );
        assert_eq!(
            AeadError::SealBufferTooSmall.to_string(),
            "AEAD Seal allocated new slice, please increase MTU size"
        );
        assert_eq!(
            AeadError::Open.to_string(),
            "cipher: message authentication failed"
        );
    }

    #[test]
    fn key_sizes_match_go() {
        let key = [7u8; 40];
        for len in 0..=key.len() {
            match AeadCrypt::new(&key[..len]) {
                Ok(a) => {
                    assert!(matches!(len, 16 | 24 | 32), "len {len}");
                    assert_eq!(a.nonce_size(), 12);
                    assert_eq!(a.overhead(), 16);
                }
                Err(e) => {
                    assert!(!matches!(len, 16 | 24 | 32), "len {len}");
                    assert_eq!(e.to_string(), format!("crypto/aes: invalid key size {len}"));
                }
            }
        }
    }

    #[test]
    fn aead_is_send_sync() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<AeadCrypt>();
    }

    proptest! {
        #[test]
        fn prop_aead_roundtrip(
            key_len in prop::sample::select(vec![16usize, 24, 32]),
            key in proptest::collection::vec(any::<u8>(), 32),
            nonce in proptest::array::uniform12(any::<u8>()),
            data in proptest::collection::vec(any::<u8>(), 0..=1500),
            extra in 0usize..64,
            flip in any::<prop::sample::Index>(),
        ) {
            let a = AeadCrypt::new(&key[..key_len]).expect("valid key");
            let mut buf = packet(&nonce, &data, T + extra);
            let n = a.seal_in_place(&mut buf, N + data.len()).expect("room for the tag");
            prop_assert_eq!(n, N + data.len() + T);
            prop_assert_eq!(&buf[..N], &nonce[..]);

            let mut tampered = buf[..n].to_vec();
            tampered[flip.index(n)] ^= 0x10;
            prop_assert_eq!(a.open_in_place(&mut tampered).err(), Some(AeadError::Open));

            let opened = a.open_in_place(&mut buf[..n]).expect("authentic");
            prop_assert_eq!(&opened[..], &data[..]);
        }
    }
}
