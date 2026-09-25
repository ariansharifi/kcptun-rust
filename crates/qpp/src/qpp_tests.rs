//! The tests of `qpp@v1.1.25 qpp_test.go`, ported (porting guide §8: named after the Go test),
//! plus unit and property tests of the parts Go only prints to the log.
//!
//! The golden comparison against Go's bytes is in `vector_tests.rs`; this file covers the
//! behaviour those vectors cannot pin: that any chunking of a stream gives the same result,
//! that every pad is a permutation whatever the seed, and the bookkeeping at the edges.
//!
//! Go seeds these tests from `crypto/rand`. Tests here must be reproducible (porting guide §8),
//! so the seeds and payloads come from `kcptun_testkit::rng` instead; nothing in QPP is
//! sensitive to *which* random seed is used, only to the seed being the same on both sides.

use kcptun_testkit::rng::{Pcg, rand_bytes};
use proptest::prelude::*;

use super::*;

/// The structured plaintext of `TestEncryptionChiSquare`: Genesis 1 as `qpp_test.go` embeds it.
/// Embedded, so the test binary runs anywhere (porting guide §8).
const BIBLE_TEXT: &str = include_str!("../../../testdata/golden/qpp/bible.txt");

/// A deterministic byte string, standing in for Go's `io.ReadFull(rand.Reader, ...)`.
fn random_bytes(stream: u64, n: usize) -> Vec<u8> {
    rand_bytes(&mut Pcg::new(0x9e37_79b9_7f4a_7c15, stream), n)
}

/// A deterministic 32-byte seed, standing in for Go's random seed.
fn random_seed(stream: u64) -> Vec<u8> {
    random_bytes(stream, 32)
}

// Go: qpp@v1.1.25 qpp_test.go:TestPads()
/// Every pad is a permutation of the 256 byte values and `rpads` holds its inverse.
#[test]
fn test_pads() {
    let num_pads: u16 = 8;
    let seed = random_seed(1);
    let qpp = QuantumPermutationPad::new(&seed, num_pads);
    assert_eq!(
        qpp.pads_bytes().len(),
        qpp.rpads_bytes().len(),
        "pads not equal"
    );

    for i in 0..usize::from(num_pads) {
        let (pad, rpad) = (qpp.pad(i), qpp.rpad(i));
        let mut seen = [false; MATRIX_BYTES];
        for j in 0..MATRIX_BYTES {
            assert_eq!(rpad[usize::from(pad[j])], j as u8, "not reservable");
            assert!(!seen[usize::from(pad[j])], "pad {i} is not a permutation");
            seen[usize::from(pad[j])] = true;
        }
    }
}

// Go: qpp@v1.1.25 qpp_test.go:TestEncryption()
/// A sender and a receiver built from the same seed agree on 64 KiB.
#[test]
fn test_encryption() {
    let seed = random_seed(2);
    let mut sender = QuantumPermutationPad::new(&seed, 1024);
    let mut receiver = QuantumPermutationPad::new(&seed, 1024);

    let original = random_bytes(3, 65536);
    let mut msg = original.clone();
    sender.encrypt(&mut msg);
    assert_ne!(original, msg, "not encrypted");
    receiver.decrypt(&mut msg);
    assert_eq!(original, msg, "not equal");
}

// Go: qpp@v1.1.25 qpp_test.go:TestEncryption2()
/// One pad set can do both directions: `encrypt` and `decrypt` drive separate generators.
#[test]
fn test_encryption2() {
    let seed = random_seed(4);
    let mut qpp = QuantumPermutationPad::new(&seed, 1024);

    let original = random_bytes(5, 65536);
    let mut msg = original.clone();
    qpp.encrypt(&mut msg);
    assert_ne!(original, msg, "not encrypted");
    qpp.decrypt(&mut msg);
    assert_eq!(original, msg, "not equal");
}

// Go: qpp@v1.1.25 qpp_test.go:TestEncryption3()
/// The two sides may cut the stream at different places: 3+5+4 encrypted, 9+1+2 decrypted.
#[test]
fn test_encryption3() {
    let seed = random_seed(6);
    let mut sender = QuantumPermutationPad::new(&seed, 1024);
    let mut receiver = QuantumPermutationPad::new(&seed, 1024);

    let original = random_bytes(7, 12);
    let mut msg = original.clone();

    // 12 == 3 + 5 + 4
    sender.encrypt(&mut msg[..3]);
    sender.encrypt(&mut msg[3..8]);
    sender.encrypt(&mut msg[8..]);
    assert_ne!(original, msg, "not encrypted");

    // 12 = 9 + 1 + 2
    receiver.decrypt(&mut msg[..9]);
    receiver.decrypt(&mut msg[9..10]);
    receiver.decrypt(&mut msg[10..]);
    assert_eq!(original, msg, "not equal");
}

// Go: qpp@v1.1.25 qpp_test.go:chiSquare()
/// Pearson's chi-squared statistic of the byte distribution, 255 degrees of freedom.
fn chi_square(msg: &[u8]) -> f64 {
    let mut freq = [0u64; 256];
    for &b in msg {
        freq[usize::from(b)] += 1;
    }
    let expected = msg.len() as f64 / 256.0;
    freq.iter()
        .map(|&f| {
            let d = f as f64 - expected;
            d * d / expected
        })
        .sum()
}

// Go: qpp@v1.1.25 qpp_test.go:TestEncryptionChiSquare(), testChiSquare()
/// The ciphertext of 1 MiB of English prose is flat whatever the pad count. Go writes the whole
/// 1..255 curve to a CSV and only logs it; this asserts what the curve is for: the statistic
/// drops from astronomical to the 255-degree-of-freedom range. 330 is the 99.9 % quantile.
#[test]
fn test_encryption_chi_square() {
    // 1 MB structured data, filled with bible text
    let mut original = vec![0u8; 1024 * 1024];
    for chunk in original.chunks_mut(BIBLE_TEXT.len()) {
        chunk.copy_from_slice(&BIBLE_TEXT.as_bytes()[..chunk.len()]);
    }
    let plain_chi = chi_square(&original);
    assert!(plain_chi > 1e6, "plaintext chi-squared is only {plain_chi}");

    for pads in [1u16, 7, 61, 101, 255] {
        let seed = random_seed(8 + u64::from(pads));
        let mut sender = QuantumPermutationPad::new(&seed, pads);
        let mut msg = original.clone();
        sender.encrypt(&mut msg);
        let chi = chi_square(&msg);
        assert!(chi < 330.0, "{pads} pads: chi-squared {chi}");
    }
}

// Go: qpp@v1.1.25 qpp_test.go:TestEncryptionRandLength()
/// Both sides cut the stream into random pieces of different sizes and still agree.
///
/// Go runs this over 1 GiB. 4 MiB crosses every branch of the transform tens of thousands of
/// times and keeps the gate fast; the 1 GiB case adds no new state.
#[test]
fn test_encryption_rand_length() {
    let seed = random_seed(9);
    let mut sender = QuantumPermutationPad::new(&seed, 1024);
    let mut receiver = QuantumPermutationPad::new(&seed, 1024);

    let original = random_bytes(10, 4 * 1024 * 1024);
    let mut msg = original.clone();

    let mut rng = Pcg::new(11, 12);
    let mut off = 0;
    while off < msg.len() {
        let l = (rng.next_u64() as usize % 257).min(msg.len() - off);
        sender.encrypt(&mut msg[off..off + l]);
        off += l;
        if l == 0 {
            // A zero-length piece must not advance the stream, so push on by hand.
            sender.encrypt(&mut msg[off..off + 1]);
            off += 1;
        }
    }
    assert_ne!(original, msg, "not encrypted");

    let mut off = 0;
    while off < msg.len() {
        let l = (rng.next_u64() as usize % 313).min(msg.len() - off);
        receiver.decrypt(&mut msg[off..off + l]);
        off += l;
        if l == 0 {
            receiver.decrypt(&mut msg[off..off + 1]);
            off += 1;
        }
    }
    assert_eq!(original, msg, "not equal");
}

// Go: qpp@v1.1.25 qpp_test.go:TestEncryptionMixedPRNG()
/// The same pad set driven by two explicitly created generators.
#[test]
fn test_encryption_mixed_prng() {
    let seed = random_seed(13);
    let qpp = QuantumPermutationPad::new(&seed, 1024);

    let original = random_bytes(14, 65536);
    let mut msg = original.clone();

    let mut rand_enc = create_prng(&seed);
    qpp.encrypt_with_prng(&mut msg, &mut rand_enc);
    assert_ne!(original, msg, "not encrypted");

    let mut rand_dec = create_prng(&seed);
    qpp.decrypt_with_prng(&mut msg, &mut rand_dec);
    assert_eq!(original, msg, "not equal");
}

// Go: qpp@v1.1.25 qpp_test.go:TestSeedToChunk()
/// The shape of `seed_to_chunks`: always seven 32-byte chunks for 8 qubits, whatever the seed.
///
/// Go only logs them. Two properties are worth asserting: a seed shorter than 32 bytes is
/// PBKDF2-expanded to exactly 32 bytes first, after which `seedIdx` reads those same 32 bytes
/// for every chunk — so **all seven chunks are identical** — while a seed whose length does not
/// divide 32 gives seven different ones.
#[test]
fn test_seed_to_chunk() {
    let seed = b"hello quantum world, hello quantum world, hello quantum world";
    let chunks = seed_to_chunks(seed, QUBITS);
    assert_eq!(chunks.len(), qpp_minimum_pads(QUBITS));
    assert_eq!(chunks.len(), 7, "chunk size");
    assert!(
        chunks.windows(2).any(|w| w[0] != w[1]),
        "61 does not divide 32, so the chunks must differ"
    );

    let short_seed = b"hello";
    let short_chunks = seed_to_chunks(short_seed, QUBITS);
    assert_eq!(short_chunks.len(), 7);
    assert!(
        short_chunks.windows(2).all(|w| w[0] == w[1]),
        "a seed expanded to exactly 32 bytes repeats in every chunk"
    );
    assert_ne!(short_chunks[0], chunks[0]);

    // A seed of exactly 32 bytes is used as is (no expansion), and also repeats.
    let exact: Vec<u8> = (0..32u8).collect();
    let exact_chunks = seed_to_chunks(&exact, QUBITS);
    assert!(exact_chunks.windows(2).all(|w| w[0] == w[1]));
    assert_ne!(exact_chunks[0], seed_to_chunks(&exact[..31], QUBITS)[0]);
}

// Go: qpp@v1.1.25 qpp_test.go:TestQPPMinimumSeedLength()
/// The minimum seed length and pad count for 1..15 qubits, the range Go prints.
#[test]
fn test_qpp_minimum_seed_length() {
    let want = [
        (1u8, 1usize, 1usize),
        (2, 1, 1),
        (3, 2, 1),
        (4, 6, 1),
        (5, 15, 1),
        (6, 37, 2),
        (7, 90, 3),
        (8, 211, 7),
        (9, 485, 16),
        (10, 1097, 35),
        (11, 2448, 77),
        (12, 5407, 169),
        (13, 11836, 370),
        (14, 25719, 804),
        (15, 55532, 1736),
    ];
    for (qubits, seed_len, pads) in want {
        assert_eq!(
            qpp_minimum_seed_length(qubits),
            seed_len,
            "QPPMinimumSeedLength({qubits})"
        );
        assert_eq!(qpp_minimum_pads(qubits), pads, "QPPMinimumPads({qubits})");
    }
    // Go's `1 << qubits` is an int: from 64 bits up it is 0, the factorial loop never runs and
    // the length falls back to 1.
    assert_eq!(qpp_minimum_seed_length(64), 1);
    assert_eq!(qpp_minimum_pads(64), 1);
}

// ---------------------------------------------------------------------------------------
// Unit tests of the pieces Go does not test directly.
// ---------------------------------------------------------------------------------------

/// `fill` is the identity permutation and `reverse` inverts it.
#[test]
fn fill_and_reverse_are_inverses() {
    let mut pad = [0u8; MATRIX_BYTES];
    fill(&mut pad);
    assert!(pad.iter().enumerate().all(|(i, &b)| b == i as u8));

    let mut rpad = [0u8; MATRIX_BYTES];
    reverse(&pad, &mut rpad);
    assert_eq!(rpad, pad);

    pad.swap(0, 255);
    reverse(&pad, &mut rpad);
    assert_eq!(rpad[0], 255);
    assert_eq!(rpad[255], 0);
}

/// The pad id goes into the HMAC message in **binary** (Go's `%b`), with no leading zeros.
/// Getting this wrong would silently produce different pads for every id above 1.
#[test]
fn pad_id_is_formatted_in_binary() {
    let f = |id: u16| format!("QPP_{id:b}");
    assert_eq!(f(0), "QPP_0");
    assert_eq!(f(1), "QPP_1");
    assert_eq!(f(5), "QPP_101");
    assert_eq!(f(60), "QPP_111100");
    assert_eq!(f(u16::MAX), "QPP_1111111111111111");
}

/// The byte-wise reduction agrees with a word-wise one, which carries the value through a
/// different arithmetic path.
#[test]
fn mod_big_endian_matches_word_arithmetic() {
    let word_wise = |sum: &[u8], m: u32| -> u32 {
        let mut rem = 0u128;
        for w in sum.as_chunks::<8>().0 {
            rem = ((rem << 64) | u128::from(u64::from_be_bytes(*w))) % u128::from(m);
        }
        rem as u32
    };
    let mut rng = Pcg::new(17, 18);
    for _ in 0..200 {
        let sum = rand_bytes(&mut rng, 32);
        for m in [1u32, 2, 3, 7, 61, 101, 255, 256] {
            assert_eq!(mod_big_endian(&sum, m), word_wise(&sum, m), "m = {m}");
        }
    }
    assert_eq!(mod_big_endian(&[0xff; 32], 1), 0);
    assert_eq!(mod_big_endian(&[0; 32], 256), 0);
}

/// An empty call is a no-op: it must not consume a byte of the stream, or the two sides would
/// drift apart the moment one of them wrote an empty buffer.
#[test]
fn empty_data_does_not_advance_the_generator() {
    let qpp = QuantumPermutationPad::new(b"seed", 7);
    let mut rand = create_prng(b"seed");
    let before = rand.clone();
    qpp.encrypt_with_prng(&mut [], &mut rand);
    qpp.decrypt_with_prng(&mut [], &mut rand);
    assert_eq!(rand, before);
}

/// `count` is the stream position modulo eight, however the stream was cut up.
#[test]
fn count_tracks_the_stream_position() {
    let qpp = QuantumPermutationPad::new(b"seed", 7);
    for pieces in [
        &[1usize, 1, 1][..],
        &[3, 5][..],
        &[7, 1][..],
        &[9][..],
        &[8][..],
    ] {
        let total: usize = pieces.iter().sum();
        let mut data = vec![0u8; total];
        let mut rand = create_prng(b"seed");
        let mut off = 0;
        for &n in pieces {
            qpp.encrypt_with_prng(&mut data[off..off + n], &mut rand);
            off += n;
        }
        assert_eq!(
            usize::from(rand.count()),
            total % usize::from(PAD_SWITCH),
            "pieces {pieces:?}"
        );
    }
}

/// A pad count of zero is rejected at construction rather than dividing by zero later.
#[test]
#[should_panic(expected = "numPads must be greater than 0")]
fn zero_pads_is_rejected() {
    let _ = QuantumPermutationPad::new(b"seed", 0);
}

/// The transform is position-based, so encrypting in one call and in a thousand pieces must
/// give the same bytes. This is what lets kcptun put QPP on a smux stream.
#[test]
fn prop_chunking_independent() {
    let qpp = QuantumPermutationPad::new(b"it's a secrect", 61);
    let mut rng = Pcg::new(19, 20);
    let plain = rand_bytes(&mut rng, 20_000);

    let mut whole = plain.clone();
    let mut rand = create_prng(b"it's a secrect");
    qpp.encrypt_with_prng(&mut whole, &mut rand);

    for _ in 0..20 {
        let mut chunked = plain.clone();
        let mut rand = create_prng(b"it's a secrect");
        let mut off = 0;
        while off < chunked.len() {
            let n = (1 + rng.next_u64() as usize % 64).min(chunked.len() - off);
            qpp.encrypt_with_prng(&mut chunked[off..off + n], &mut rand);
            off += n;
        }
        assert_eq!(chunked, whole);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Decryption undoes encryption for any data, pad count and pair of chunkings.
    #[test]
    fn prop_round_trip(
        seed in proptest::collection::vec(any::<u8>(), 0..40),
        num_pads in 1u16..=64,
        data in proptest::collection::vec(any::<u8>(), 0..600),
        enc_pieces in proptest::collection::vec(1usize..17, 1..40),
        dec_pieces in proptest::collection::vec(1usize..17, 1..40),
    ) {
        let qpp = QuantumPermutationPad::new(&seed, num_pads);

        let mut msg = data.clone();
        let mut enc = create_prng(&seed);
        let mut off = 0;
        for n in enc_pieces.iter().cycle() {
            if off >= msg.len() { break; }
            let n = (*n).min(msg.len() - off);
            qpp.encrypt_with_prng(&mut msg[off..off + n], &mut enc);
            off += n;
        }

        let mut dec = create_prng(&seed);
        let mut off = 0;
        for n in dec_pieces.iter().cycle() {
            if off >= msg.len() { break; }
            let n = (*n).min(msg.len() - off);
            qpp.decrypt_with_prng(&mut msg[off..off + n], &mut dec);
            off += n;
        }
        prop_assert_eq!(msg, data);
        prop_assert_eq!(enc, dec);
    }
}
