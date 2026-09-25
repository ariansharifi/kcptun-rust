//! Key derivation and crypt method selection (port of kcptun `std/crypt.go` and the PBKDF2 call
//! in `client/main.go` / `server/main.go`).

use kcptun_kcp::crypt::{self as kcp, CryptError, PacketCrypt};
use sha1::Sha1;

/// PBKDF2 salt used to derive the session key from `-key`.
// Go: kcptun client/main.go:SALT, server/main.go:SALT
pub const SALT: &str = "kcp-go";

/// PBKDF2 iteration count.
// Go: kcptun client/main.go:pbkdf2.Key(..., 4096, 32, sha1.New)
pub const PBKDF2_ITER: u32 = 4096;

/// Derives the 32-byte `pass` from the `-key` value:
/// `PBKDF2-HMAC-SHA1(key as UTF-8, "kcp-go", 4096, 32)`.
///
/// Every packet cipher key is a prefix of `pass`. QPP uses the raw key instead.
// Go: kcptun client/main.go and server/main.go:
//     pass := pbkdf2.Key([]byte(config.Key), []byte(SALT), 4096, 32, sha1.New)
pub fn derive_pass(key: &str) -> [u8; 32] {
    pbkdf2::pbkdf2_hmac_array::<Sha1, 32>(key.as_bytes(), SALT.as_bytes(), PBKDF2_ITER)
}

/// Constructor of one crypt method. `Ok(None)` means no crypto (`null`).
type BuildFn = fn(&[u8]) -> Result<Option<PacketCrypt>, CryptError>;

/// A supported `-crypt` method: its name, the key size it takes from `pass` (0 means the whole
/// `pass`) and its constructor.
// Go: kcptun std/crypt.go:cryptMethod
struct CryptMethod {
    name: &'static str,
    key_size: usize,
    build: BuildFn,
}

/// Wraps a `BlockCrypt` constructor as a [`BuildFn`].
macro_rules! block {
    ($new:path) => {
        |key: &[u8]| $new(key).map(|b| Some(PacketCrypt::Block(b)))
    };
}

/// Lookup table of supported methods (Go uses a map; lookup is by exact name either way).
// Go: kcptun std/crypt.go:cryptMethods
static CRYPT_METHODS: [CryptMethod; 14] = [
    CryptMethod {
        name: "null",
        key_size: 0,
        build: |_| Ok(None),
    },
    CryptMethod {
        name: "sm4",
        key_size: 16,
        build: block!(kcp::new_sm4_block_crypt),
    },
    CryptMethod {
        name: "tea",
        key_size: 16,
        build: block!(kcp::new_tea_block_crypt),
    },
    CryptMethod {
        name: "xor",
        key_size: 0,
        build: block!(kcp::new_simple_xor_block_crypt),
    },
    CryptMethod {
        name: "none",
        key_size: 0,
        build: block!(kcp::new_none_block_crypt),
    },
    CryptMethod {
        name: "aes-128",
        key_size: 16,
        build: block!(kcp::new_aes_block_crypt),
    },
    CryptMethod {
        name: "aes-192",
        key_size: 24,
        build: block!(kcp::new_aes_block_crypt),
    },
    CryptMethod {
        name: "blowfish",
        key_size: 0,
        build: block!(kcp::new_blowfish_block_crypt),
    },
    CryptMethod {
        name: "twofish",
        key_size: 0,
        build: block!(kcp::new_twofish_block_crypt),
    },
    CryptMethod {
        name: "cast5",
        key_size: 16,
        build: block!(kcp::new_cast5_block_crypt),
    },
    CryptMethod {
        name: "3des",
        key_size: 24,
        build: block!(kcp::new_triple_des_block_crypt),
    },
    CryptMethod {
        name: "xtea",
        key_size: 16,
        build: block!(kcp::new_xtea_block_crypt),
    },
    CryptMethod {
        name: "salsa20",
        key_size: 0,
        build: block!(kcp::new_salsa20_block_crypt),
    },
    CryptMethod {
        name: "aes-128-gcm",
        key_size: 16,
        build: |key| kcp::new_aes_gcm_crypt(key).map(Some),
    },
];

/// Result of [`select_block_crypt`].
#[derive(Clone, Debug)]
pub struct SelectedCrypt {
    /// The packet crypto; `None` means no crypto (`-crypt null`, or Go's quirk of a failed AES
    /// fallback, see [`select_block_crypt`]).
    pub block: Option<PacketCrypt>,
    /// The effective method name, for the startup log: the requested name, or `"aes"` after a
    /// fallback or for an unknown name.
    pub method: &'static str,
    /// The line Go logs with `log.Printf` while selecting, if any. Logging arrives with Step 08,
    /// so the caller logs it.
    pub warning: Option<String>,
}

/// Translates a `-crypt` name into the packet crypto keyed from `pass`, and reports the
/// effective name after fallbacks.
///
/// - Known method with a fixed key size `n`: key = `pass[..n]` when `pass` has at least `n`
///   bytes, otherwise the whole `pass`. Methods with key size 0 use the whole `pass`.
/// - The constructor fails: AES keyed with the whole `pass`, name `"aes"`, and a warning
///   `crypt: failed to create <method> cipher: <err>, falling back to aes`.
/// - Unknown name (including `""`): AES keyed with the whole `pass` (AES-256 for the usual 32-byte
///   pass), name `"aes"`. If that fails the warning is
///   `crypt: failed to create default aes cipher: <err>`.
///
/// As in Go, if the AES fallback itself fails (only possible when `pass` is not 16, 24 or 32
/// bytes, which `derive_pass` never produces) the result has no crypto but still says `"aes"`.
// Go: kcptun std/crypt.go:SelectBlockCrypt()
pub fn select_block_crypt(method: &str, pass: &[u8]) -> SelectedCrypt {
    if let Some(m) = CRYPT_METHODS.iter().find(|m| m.name == method) {
        let mut key = pass;
        if m.key_size > 0 && pass.len() >= m.key_size {
            key = &pass[..m.key_size];
        }
        return match (m.build)(key) {
            Ok(block) => SelectedCrypt {
                block,
                method: m.name,
                warning: None,
            },
            Err(err) => SelectedCrypt {
                // Go: `block, _ = kcp.NewAESBlockCrypt(pass)`; an error leaves block nil.
                block: kcp::new_aes_block_crypt(pass).ok().map(PacketCrypt::Block),
                method: "aes",
                warning: Some(format!(
                    "crypt: failed to create {method} cipher: {err}, falling back to aes"
                )),
            },
        };
    }
    // Default to AES for unknown methods.
    match kcp::new_aes_block_crypt(pass) {
        Ok(block) => SelectedCrypt {
            block: Some(PacketCrypt::Block(block)),
            method: "aes",
            warning: None,
        },
        Err(err) => SelectedCrypt {
            block: None,
            method: "aes",
            warning: Some(format!("crypt: failed to create default aes cipher: {err}")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kcptun_kcp::crypt::AeadCrypt;
    use kcptun_testkit::{assert_hex_eq, vectors};

    #[test]
    fn vectors_pbkdf2() {
        let file = vectors!("crypt");
        let mut n = 0;
        for case in file.cases_with_prefix("pbkdf2/") {
            assert_eq!(case.param::<String>("salt"), SALT, "case {}", case.name);
            assert_eq!(case.param::<u32>("iter"), PBKDF2_ITER, "case {}", case.name);
            assert_eq!(case.param::<usize>("dklen"), 32, "case {}", case.name);
            let key: String = case.param("key");
            assert_hex_eq!(key.as_bytes(), case.input(), "key bytes {}", case.name);
            assert_hex_eq!(derive_pass(&key), case.output(), "pass {}", case.name);
            n += 1;
        }
        assert_eq!(n, 6);
    }

    /// Key length `select_block_crypt` hands to the constructor (Go's `cryptMethods` rule).
    fn table_key_len(method: &str, pass_len: usize) -> usize {
        match CRYPT_METHODS.iter().find(|m| m.name == method) {
            Some(m) if m.name == "null" => 0,
            Some(m) if m.key_size > 0 && pass_len >= m.key_size => m.key_size,
            _ => pass_len,
        }
    }

    /// Runs the `select/` or `select_short/` group. Returns the number of cases checked.
    fn run_select_vectors(prefix: &str) -> usize {
        let file = vectors!("crypt");
        let mut n = 0;
        for case in file.cases_with_prefix(prefix) {
            let method: String = case.param("method");
            let pass = case.param_bytes("pass");
            let sel = select_block_crypt(&method, &pass);

            assert_eq!(
                sel.method,
                case.param::<String>("effective"),
                "case {}",
                case.name
            );
            let want_log = case.get("params").and_then(|p| p.get("log"));
            assert_eq!(
                sel.warning.as_deref(),
                want_log.and_then(|v| v.as_str()),
                "log {}",
                case.name
            );
            assert_eq!(
                table_key_len(&method, pass.len()),
                case.param::<usize>("key_len"),
                "key_len {}",
                case.name
            );

            let is_nil: bool = case.param("nil");
            assert_eq!(sel.block.is_none(), is_nil, "nil {}", case.name);
            match sel.block.as_ref() {
                None => {}
                Some(PacketCrypt::Block(bc)) => {
                    let input = case.input();
                    let mut buf = input.clone();
                    bc.encrypt(&mut buf);
                    assert_hex_eq!(buf, case.output(), "encrypt {}", case.name);
                    bc.decrypt(&mut buf);
                    assert_hex_eq!(buf, input, "decrypt {}", case.name);
                }
                Some(PacketCrypt::Aead(aead)) => {
                    // `in` is the plaintext, `out` = nonce | ciphertext | tag.
                    assert_eq!(method, "aes-128-gcm", "case {}", case.name);
                    let (plaintext, sealed) = (case.input(), case.output());
                    let mut buf = case.param_bytes("nonce");
                    assert_eq!(buf.len(), AeadCrypt::NONCE, "case {}", case.name);
                    buf.extend_from_slice(&plaintext);
                    let len = buf.len();
                    buf.resize(len + AeadCrypt::OVERHEAD, 0);
                    let n = aead.seal_in_place(&mut buf, len).expect("room for the tag");
                    assert_eq!(n, buf.len(), "case {}", case.name);
                    assert_hex_eq!(buf, sealed, "seal {}", case.name);
                    let opened = aead.open_in_place(&mut buf).expect("authentic");
                    assert_hex_eq!(opened, plaintext, "open {}", case.name);
                }
            }
            n += 1;
        }
        n
    }

    #[test]
    fn vectors_select() {
        // aes aes-128 aes-128-gcm aes-192 salsa20 blowfish twofish cast5 3des tea xtea xor sm4
        // none null bogus "".
        assert_eq!(run_select_vectors("select/"), 17);
    }

    #[test]
    fn vectors_select_short() {
        // 16-byte pass: 3des fails and falls back to aes (AES-128) with Go's log line.
        assert_eq!(run_select_vectors("select_short/"), 17);
    }

    /// Pass lengths `derive_pass` never produces, checked against the pinned Go
    /// `std.SelectBlockCrypt` (pass = bytes 1..=n): constructor failures, failed AES fallbacks
    /// that leave no crypto (Go's nil block), and the log lines.
    #[test]
    fn select_odd_pass_lengths_match_go() {
        let cases: &[(usize, &str, &str, bool, Option<&str>)] = &[
            (
                5,
                "3des",
                "aes",
                true,
                Some(
                    "crypt: failed to create 3des cipher: crypto/des: invalid key size 5, falling back to aes",
                ),
            ),
            (
                5,
                "bogus",
                "aes",
                true,
                Some("crypt: failed to create default aes cipher: crypto/aes: invalid key size 5"),
            ),
            (
                5,
                "tea",
                "aes",
                true,
                Some(
                    "crypt: failed to create tea cipher: tea: incorrect key size, falling back to aes",
                ),
            ),
            (
                5,
                "cast5",
                "aes",
                true,
                Some(
                    "crypt: failed to create cast5 cipher: CAST5: keys must be 16 bytes, falling back to aes",
                ),
            ),
            (
                5,
                "sm4",
                "aes",
                true,
                Some(
                    "crypt: failed to create sm4 cipher: SM4: invalid key size 5, falling back to aes",
                ),
            ),
            (
                5,
                "aes-128",
                "aes",
                true,
                Some(
                    "crypt: failed to create aes-128 cipher: crypto/aes: invalid key size 5, falling back to aes",
                ),
            ),
            (
                5,
                "aes-192",
                "aes",
                true,
                Some(
                    "crypt: failed to create aes-192 cipher: crypto/aes: invalid key size 5, falling back to aes",
                ),
            ),
            (
                5,
                "xtea",
                "aes",
                true,
                Some(
                    "crypt: failed to create xtea cipher: crypto/xtea: invalid key size 5, falling back to aes",
                ),
            ),
            (5, "blowfish", "blowfish", false, None),
            (
                5,
                "twofish",
                "aes",
                true,
                Some(
                    "crypt: failed to create twofish cipher: crypto/twofish: invalid key size 5, falling back to aes",
                ),
            ),
            (5, "salsa20", "salsa20", false, None),
            (5, "xor", "xor", false, None),
            (5, "null", "null", true, None),
            (
                5,
                "aes-128-gcm",
                "aes",
                true,
                Some(
                    "crypt: failed to create aes-128-gcm cipher: crypto/aes: invalid key size 5, falling back to aes",
                ),
            ),
            (
                20,
                "3des",
                "aes",
                true,
                Some(
                    "crypt: failed to create 3des cipher: crypto/des: invalid key size 20, falling back to aes",
                ),
            ),
            (
                20,
                "bogus",
                "aes",
                true,
                Some("crypt: failed to create default aes cipher: crypto/aes: invalid key size 20"),
            ),
            (20, "tea", "tea", false, None),
            (20, "cast5", "cast5", false, None),
            (20, "sm4", "sm4", false, None),
            (20, "aes-128", "aes-128", false, None),
            (
                20,
                "aes-192",
                "aes",
                true,
                Some(
                    "crypt: failed to create aes-192 cipher: crypto/aes: invalid key size 20, falling back to aes",
                ),
            ),
            (20, "xtea", "xtea", false, None),
            (20, "blowfish", "blowfish", false, None),
            (
                20,
                "twofish",
                "aes",
                true,
                Some(
                    "crypt: failed to create twofish cipher: crypto/twofish: invalid key size 20, falling back to aes",
                ),
            ),
            (20, "salsa20", "salsa20", false, None),
            (20, "xor", "xor", false, None),
            (20, "null", "null", true, None),
            (20, "aes-128-gcm", "aes-128-gcm", false, None),
            (24, "aes-128-gcm", "aes-128-gcm", false, None),
        ];
        for &(n, method, effective, is_nil, warning) in cases {
            let pass: Vec<u8> = (1..=n as u8).collect();
            let sel = select_block_crypt(method, &pass);
            assert_eq!(sel.method, effective, "{method} n={n}");
            assert_eq!(sel.block.is_none(), is_nil, "{method} n={n}");
            assert_eq!(sel.warning.as_deref(), warning, "{method} n={n}");
        }
    }

    /// The method table matches Go's `cryptMethods` (names and key sizes).
    #[test]
    fn crypt_methods_table_matches_go() {
        let want = [
            ("null", 0),
            ("sm4", 16),
            ("tea", 16),
            ("xor", 0),
            ("none", 0),
            ("aes-128", 16),
            ("aes-192", 24),
            ("blowfish", 0),
            ("twofish", 0),
            ("cast5", 16),
            ("3des", 24),
            ("xtea", 16),
            ("salsa20", 0),
            ("aes-128-gcm", 16),
        ];
        let got: Vec<_> = CRYPT_METHODS.iter().map(|m| (m.name, m.key_size)).collect();
        assert_eq!(got, want);
        // "aes" itself is not in the table: it is the unknown-name default.
        assert!(CRYPT_METHODS.iter().all(|m| m.name != "aes"));
    }

    /// Names are matched exactly (Go map lookup): no case folding or trimming.
    #[test]
    fn select_is_case_sensitive() {
        let pass = derive_pass("it's a secrect");
        for name in ["AES-128", "Salsa20", " xor", "null ", "NONE"] {
            let sel = select_block_crypt(name, &pass);
            assert_eq!(sel.method, "aes", "{name:?}");
            assert!(sel.warning.is_none());
            assert!(sel.block.is_some());
        }
    }

    #[test]
    fn derive_pass_default_key() {
        // The default `-key` value (sic), the pass used for every cfb/*/pass_id=0 vector.
        assert_eq!(
            derive_pass("it's a secrect"),
            [
                0x25, 0xd7, 0xd7, 0xbd, 0x51, 0x05, 0x07, 0x42, 0xd8, 0xd7, 0x91, 0xf2, 0xb6, 0x53,
                0xc6, 0xc8, 0xb2, 0x36, 0x6b, 0x7e, 0x25, 0xa1, 0x24, 0xcf, 0x7a, 0x2e, 0x12, 0xea,
                0xf4, 0xff, 0xa4, 0x44,
            ]
        );
    }
}
