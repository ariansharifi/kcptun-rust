//! Uses the testkit macros and types through the public paths, as dependent crates will.

use kcptun_testkit::netsim::{Link, LinkConfig};
use kcptun_testkit::{VirtualClock, assert_hex_eq, vectors};

#[test]
fn vectors_macro_embeds_from_calling_crate() {
    let file = vectors!("kcp");
    assert_eq!(file.area, "kcp");
    assert_eq!(file.module("github.com/xtaci/kcp-go/v5"), Some("v5.6.66"));
    assert_hex_eq!(Vec::<u8>::new(), [0u8; 0], "stub area {}", file.area);
}

/// The crypt area (plan 02.1) parses through testkit, with every group present and every byte
/// field valid hex of the documented length. The ciphers themselves are tested in kcptun-kcp.
#[test]
fn vectors_crypt_file_parses() {
    let file = vectors!("crypt");
    assert_eq!(file.module("github.com/xtaci/kcp-go/v5"), Some("v5.6.66"));
    let count = |prefix: &str| file.cases_with_prefix(prefix).count();
    assert_eq!(count("pbkdf2/"), 6);
    assert_eq!(count("xor_pad/"), 2);
    assert_eq!(count("select/"), 17);
    assert_eq!(count("select_short/"), 17);
    assert_eq!(count("cfb/"), 13 * 2 * 18);
    assert_eq!(count("aead/"), 2 * 4);
    assert_eq!(file.len(), 6 + 2 + 2 * 17 + 13 * 2 * 18 + 2 * 4);
    for case in &file.cases {
        let (input, output) = (case.input(), case.output());
        let group = case.name.split('/').next().unwrap_or_default();
        match group {
            "pbkdf2" => assert_eq!(output.len(), 32, "{}", case.name),
            "xor_pad" => assert_eq!(output.len(), 1500, "{}", case.name),
            "select" | "select_short" => {
                assert_eq!(input.len(), 64, "{}", case.name);
                let method: String = case.param("method");
                let nil: bool = case.param("nil");
                let want = match method.as_str() {
                    "null" => 0,
                    "aes-128-gcm" => 12 + 64 + 16,
                    _ => 64,
                };
                assert_eq!(output.len(), want, "{}", case.name);
                assert_eq!(nil, method == "null", "{}", case.name);
            }
            "cfb" => {
                assert_eq!(output.len(), input.len(), "{}", case.name);
                assert_eq!(case.param_bytes("pass").len(), 32, "{}", case.name);
            }
            "aead" => {
                let nonce = case.param_bytes("nonce");
                assert_eq!(output.len(), 12 + input.len() + 16, "{}", case.name);
                assert_hex_eq!(output[..12], nonce, "{}", case.name);
            }
            other => panic!("unexpected crypt group {other:?} in {}", case.name),
        }
    }
    let unknown = file.case("select/method=bogus");
    assert_eq!(unknown.param::<String>("effective"), "aes");
    assert_hex_eq!(
        unknown.output(),
        file.case("select/method=aes").output(),
        "bogus falls back to aes"
    );
}

#[test]
fn sim_clock_drives_link() {
    let clock = VirtualClock::new();
    let now = {
        let c = clock.clone();
        move || c.now_ms()
    };
    let mut link = Link::new(LinkConfig::new(1).delay(20));
    link.send(clock.now_ms_u64(), b"hello");
    let t = link.next_event_time().unwrap();
    clock.set(t);
    assert_eq!(now(), 20);
    assert_eq!(link.poll(clock.now_ms_u64()), vec![b"hello".to_vec()]);
}
