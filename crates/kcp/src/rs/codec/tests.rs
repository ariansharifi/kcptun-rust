//! Tests of the Reed-Solomon codec: Go golden vectors (`rs.json`), error cases, the inversion
//! cache, and a differential proptest against the `reed-solomon-erasure` crate (DECISIONS D08).

use super::*;
use kcptun_testkit::rng::{govectors_rng, rand_bytes};
use kcptun_testkit::vectors;
use kcptun_testkit::vectors::{Blob, Case};
use proptest::prelude::*;
use reed_solomon_erasure::galois_8::ReedSolomon;

/// Checks `actual` against the case field `key` (hex) or `<key>_blob` (a [`Blob`]). govectors
/// omits both for an empty byte string (`omitempty`).
#[track_caller]
fn check_bytes(case: &Case, key: &str, actual: &[u8]) {
    let blob_key = format!("{key}_blob");
    if case.get(key).is_some() {
        kcptun_testkit::assert_hex_eq!(actual, case.bytes(key), "{}: {key}", case.name);
    } else if case.get(&blob_key).is_some() {
        case.blob(&blob_key)
            .assert_matches(actual, &format!("{}: {key}", case.name));
    } else {
        assert!(actual.is_empty(), "{}: {key} should be empty", case.name);
    }
}

/// The data shards of an encode/reconstruct case, drawn like govectors' rsData.
fn case_data(case: &Case) -> (usize, usize, Vec<Vec<u8>>) {
    let ds: usize = case.field("ds");
    let ps: usize = case.field("ps");
    let len: usize = case.field("len");
    let stream: u64 = case.field("stream");
    let data = rand_bytes(&mut govectors_rng("rs", stream), ds * len);
    let shards = data.chunks(len).map(<[u8]>::to_vec).collect();
    (ds, ps, shards)
}

/// A codec using `kernel`.
fn codec_with(ds: usize, ps: usize, kernel: Kernel) -> Codec {
    let mut c = Codec::new(ds, ps).unwrap();
    c.set_kernel(kernel);
    assert_eq!(c.kernel(), kernel);
    c
}

/// Encodes `data` with a fresh codec, returning all shards.
fn encode_all(codec: &Codec, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let len = data[0].len();
    let mut shards: Vec<Vec<u8>> = data.to_vec();
    shards.resize(codec.total_shards(), vec![0; len]);
    codec.encode(&mut shards).unwrap();
    shards
}

#[test]
fn vectors_rs_matrix() {
    let file = vectors!("rs");
    let mut n = 0;
    for case in file.cases_with_prefix("matrix/") {
        let ds: usize = case.field("ds");
        let ps: usize = case.field("ps");
        let codec = Codec::new(ds, ps).unwrap();
        let m = codec.matrix().unwrap();
        assert_eq!((m.rows(), m.cols()), (ds + ps, ds));
        // The top square is the identity: data shards are stored unchanged.
        for r in 0..ds {
            for c in 0..ds {
                assert_eq!(m.get(r, c), u8::from(r == c), "{}: m[{r}][{c}]", case.name);
            }
        }
        let parity_rows: Vec<u8> = (ds..ds + ps).flat_map(|r| m.row(r).to_vec()).collect();
        check_bytes(case, "parity_rows", &parity_rows);
        n += 1;
    }
    assert_eq!(n, 10);
}

#[test]
fn vectors_rs_encode() {
    // Every kernel this CPU can run (scalar and SIMD) must reproduce the Go vectors.
    for kernel in Kernel::available() {
        run_vectors_rs_encode(kernel);
    }
}

fn run_vectors_rs_encode(kernel: Kernel) {
    let file = vectors!("rs");
    let mut codecs: HashMap<(usize, usize), Codec> = HashMap::new();
    let mut n = 0;
    for case in file.cases_with_prefix("encode/") {
        let (ds, ps, data) = case_data(case);
        let all: Vec<u8> = data.concat();
        assert_eq!(
            Blob::of(&all).sha256,
            case.field::<String>("data_sha256"),
            "{}: generated data differs from govectors",
            case.name
        );
        let codec = codecs
            .entry((ds, ps))
            .or_insert_with(|| codec_with(ds, ps, kernel));
        let shards = encode_all(codec, &data);
        assert_eq!(shards[..ds], data[..], "{}: data shards changed", case.name);
        check_bytes(case, "parity", &shards[ds..].concat());
        assert_eq!(codec.kernel(), kernel);

        // Same result through borrowed slices, with garbage in the parity buffers first.
        let mut bufs: Vec<Vec<u8>> = shards.clone();
        for p in &mut bufs[ds..] {
            p.fill(0xee);
        }
        let mut slices: Vec<&mut [u8]> = bufs.iter_mut().map(Vec::as_mut_slice).collect();
        codec.encode(&mut slices).unwrap();
        assert_eq!(bufs, shards, "{}: encode through &mut [u8]", case.name);
        n += 1;
    }
    assert_eq!(n, 50);
}

#[test]
fn vectors_rs_reconstruct() {
    // Every kernel this CPU can run (scalar and SIMD) must reproduce the Go vectors.
    for kernel in Kernel::available() {
        run_vectors_rs_reconstruct(kernel);
    }
}

fn run_vectors_rs_reconstruct(kernel: Kernel) {
    let file = vectors!("rs");
    let mut codecs: HashMap<(usize, usize), Codec> = HashMap::new();
    let mut n = 0;
    for case in file.cases_with_prefix("reconstruct/") {
        let (ds, ps, data) = case_data(case);
        let missing: Vec<usize> = case.field("missing");
        let recovered: Vec<usize> = case.field("recovered");
        let codec = codecs
            .entry((ds, ps))
            .or_insert_with(|| codec_with(ds, ps, kernel));
        let full = encode_all(codec, &data);

        // Option convention: None is a missing shard (Go nil).
        let mut shards: Vec<Option<Vec<u8>>> = full
            .iter()
            .enumerate()
            .map(|(i, s)| (!missing.contains(&i)).then(|| s.clone()))
            .collect();
        codec.reconstruct_data(&mut shards).unwrap();
        let mut got_recovered = Vec::new();
        let mut out = Vec::new();
        for (i, s) in shards.iter().enumerate() {
            match (i < ds, missing.contains(&i)) {
                (true, true) => {
                    got_recovered.push(i);
                    out.extend_from_slice(s.as_deref().unwrap());
                }
                (false, true) => assert!(s.is_none(), "{}: parity {i} filled", case.name),
                _ => assert_eq!(s.as_ref(), Some(&full[i]), "{}: shard {i}", case.name),
            }
        }
        assert_eq!(got_recovered, recovered, "{}", case.name);
        check_bytes(case, "out", &out);

        // Go convention: an empty Vec is missing; its capacity is reused (Go: shards[i][0:size]).
        let mut shards: Vec<Vec<u8>> = full
            .iter()
            .enumerate()
            .map(|(i, s)| {
                if missing.contains(&i) {
                    Vec::with_capacity(1500)
                } else {
                    s.clone()
                }
            })
            .collect();
        let ptrs: Vec<*const u8> = shards.iter().map(|s| s.as_ptr()).collect();
        codec.reconstruct_data(&mut shards).unwrap();
        for (i, s) in shards.iter().enumerate() {
            if i < ds {
                assert_eq!(s, &full[i], "{}: shard {i} (Vec)", case.name);
                assert_eq!(s.as_ptr(), ptrs[i], "{}: shard {i} reallocated", case.name);
            } else if missing.contains(&i) {
                assert!(s.is_empty(), "{}: parity {i} filled (Vec)", case.name);
            }
        }
        n += 1;
    }
    assert_eq!(n, 200);
}

#[test]
fn vectors_rs_errors() {
    let file = vectors!("rs");
    let mut n = 0;
    for case in file.cases_with_prefix("error/") {
        let op: String = case.field("op");
        let ds: usize = case.field("ds");
        let ps: usize = case.field("ps");
        let go_err: String = case.field("err");
        let got = match op.as_str() {
            "new" => match Codec::new(ds, ps) {
                Ok(_) => String::new(),
                Err(e) => e.to_string(),
            },
            "encode" | "reconstruct_data" => {
                let lens: Vec<usize> = case.field("shard_lens");
                let mut codec = Codec::new(ds, ps).unwrap();
                let mut shards: Vec<Vec<u8>> = lens.iter().map(|&l| vec![0x42; l]).collect();
                let res = if op == "encode" {
                    codec.encode(&mut shards)
                } else {
                    // The Option convention must give the same result.
                    let mut opt: Vec<Option<Vec<u8>>> = lens
                        .iter()
                        .map(|&l| (l > 0).then(|| vec![0x42; l]))
                        .collect();
                    let r = codec.reconstruct_data(&mut opt);
                    assert_eq!(r, codec.reconstruct_data(&mut shards), "{}", case.name);
                    r
                };
                match res {
                    Ok(()) => String::new(),
                    Err(e) => e.to_string(),
                }
            }
            other => panic!("{}: unknown op {other}", case.name),
        };
        if case.get("impl").and_then(|v| v.as_str()) == Some("*reedsolomon.leopardFF16") {
            // Deviation V07: Go switches to the Leopard GF(2^16) codec above 256 shards; this
            // port does not implement it and returns ErrMaxShardNum instead (see Codec::new).
            assert_eq!(go_err, "", "{}", case.name);
            assert_eq!(got, Error::MaxShardNum.to_string(), "{}", case.name);
        } else {
            assert_eq!(got, go_err, "{}", case.name);
        }
        n += 1;
    }
    assert_eq!(n, 21);
}

#[test]
fn new_errors() {
    assert_eq!(Codec::new(0, 1).unwrap_err(), Error::InvShardNum);
    assert_eq!(Codec::new(0, 0).unwrap_err(), Error::InvShardNum);
    // Go's order: the total is checked first.
    assert_eq!(Codec::new(0, 257).unwrap_err(), Error::MaxShardNum);
    assert_eq!(Codec::new(1, 256).unwrap_err(), Error::MaxShardNum);
    assert_eq!(Codec::new(usize::MAX, 2).unwrap_err(), Error::MaxShardNum);
    let c = Codec::new(255, 1).unwrap();
    assert_eq!(
        (c.data_shards(), c.parity_shards(), c.total_shards()),
        (255, 1, 256)
    );
    let c = Codec::new(3, 0).unwrap();
    assert!(c.matrix().is_none());
    assert_eq!(
        Error::InvShardNum.to_string(),
        "cannot create Encoder with less than one data shard or less than zero parity shards"
    );
    assert_eq!(
        Error::MaxShardNum.to_string(),
        "cannot create Encoder with more than 256 data+parity shards"
    );
}

#[test]
fn encode_and_reconstruct_errors() {
    let mut c = Codec::new(3, 2).unwrap();
    // Wrong shard count.
    let mut four = vec![vec![1u8; 4]; 4];
    assert_eq!(c.encode(&mut four), Err(Error::TooFewShards));
    assert_eq!(c.reconstruct_data(&mut four), Err(Error::TooFewShards));
    assert_eq!(Error::TooFewShards.to_string(), "too few shards given");
    // Size mismatch.
    let mut odd = vec![vec![1u8; 4], vec![1; 4], vec![1; 5], vec![1; 4], vec![1; 4]];
    assert_eq!(c.encode(&mut odd), Err(Error::ShardSize));
    assert_eq!(c.reconstruct_data(&mut odd), Err(Error::ShardSize));
    assert_eq!(Error::ShardSize.to_string(), "shard sizes do not match");
    // An empty shard is a size mismatch for encode, a missing shard for reconstruct.
    let mut holes = vec![vec![1u8; 4], vec![], vec![1; 4], vec![1; 4], vec![1; 4]];
    assert_eq!(c.encode(&mut holes), Err(Error::ShardSize));
    assert_eq!(c.reconstruct_data(&mut holes), Ok(()));
    // All empty.
    let mut empty = vec![Vec::<u8>::new(); 5];
    assert_eq!(c.encode(&mut empty), Err(Error::ShardNoData));
    assert_eq!(c.reconstruct_data(&mut empty), Err(Error::ShardNoData));
    assert_eq!(Error::ShardNoData.to_string(), "no shard data");
    // Too few present (3 missing, ps = 2).
    let mut few = vec![vec![], vec![], vec![1u8; 4], vec![], vec![1; 4]];
    assert_eq!(c.reconstruct_data(&mut few), Err(Error::TooFewShards));
    // Nothing was allocated for the missing shards on error.
    assert!(few[0].is_empty() && few[1].is_empty());
}

#[test]
fn no_parity_codec() {
    let mut c = Codec::new(3, 0).unwrap();
    let mut shards = vec![vec![7u8; 5]; 3];
    c.encode(&mut shards).unwrap();
    assert_eq!(shards, vec![vec![7u8; 5]; 3]);
    c.reconstruct_data(&mut shards).unwrap();
    shards[1].clear();
    assert_eq!(c.reconstruct_data(&mut shards), Err(Error::TooFewShards));
}

#[test]
fn large_shards_span_several_rounds() {
    // Longer than PER_ROUND with an unaligned tail: rounds must not change the result.
    let (ds, ps, len) = (5, 3, PER_ROUND * 2 + 777);
    let data: Vec<Vec<u8>> = (0..ds)
        .map(|i| rand_bytes(&mut govectors_rng("rs-test", i as u64), len))
        .collect();
    let mut c = Codec::new(ds, ps).unwrap();
    let full = encode_all(&c, &data);
    // Parity from the one-shot definition.
    let m = c.matrix().unwrap().clone();
    for p in 0..ps {
        for x in [0, PER_ROUND - 1, PER_ROUND, len - 1] {
            let want = (0..ds).fold(0u8, |acc, j| {
                acc ^ super::super::galois::gal_multiply(m.get(ds + p, j), data[j][x])
            });
            assert_eq!(full[ds + p][x], want, "parity {p} byte {x}");
        }
    }
    let mut shards: Vec<Option<Vec<u8>>> = full.iter().cloned().map(Some).collect();
    shards[0] = None;
    shards[3] = None;
    shards[6] = None;
    c.reconstruct_data(&mut shards).unwrap();
    assert_eq!(shards[0].as_ref(), Some(&full[0]));
    assert_eq!(shards[3].as_ref(), Some(&full[3]));
    assert!(shards[6].is_none());
}

#[test]
fn inversion_cache_keys_and_bound() {
    let (ds, ps, len) = (20, 5, 16);
    let data: Vec<Vec<u8>> = (0..ds)
        .map(|i| rand_bytes(&mut govectors_rng("rs-test", 100 + i as u64), len))
        .collect();
    let mut c = Codec::new(ds, ps).unwrap();
    let full = encode_all(&c, &data);
    let run = |c: &mut Codec, missing: &[usize]| {
        let mut shards: Vec<Option<Vec<u8>>> = full
            .iter()
            .enumerate()
            .map(|(i, s)| (!missing.contains(&i)).then(|| s.clone()))
            .collect();
        c.reconstruct_data(&mut shards).unwrap();
        for i in 0..ds {
            assert_eq!(shards[i].as_ref(), Some(&full[i]), "missing {missing:?}");
        }
    };
    // Nothing to do: no cache entry.
    run(&mut c, &[21, 22]);
    assert_eq!(c.inversion_cache_len(), 0);
    // The key is the invalid rows seen before ds valid rows (like Go's invalidIndices):
    // {0, 22} and {0} both stop at row 20 with only row 0 invalid.
    run(&mut c, &[0, 22]);
    assert_eq!(c.inversion_cache_len(), 1);
    run(&mut c, &[0]);
    assert_eq!(c.inversion_cache_len(), 1);
    run(&mut c, &[0, 20]);
    assert_eq!(c.inversion_cache_len(), 2);

    // More distinct patterns than the bound: the cache stays bounded and results stay right.
    let mut patterns = 0;
    'outer: for a in 0..ds {
        for b in a + 1..ds {
            for d in b + 1..ds {
                run(&mut c, &[a, b, d]);
                assert!(c.inversion_cache_len() <= INVERSION_CACHE_MAX);
                patterns += 1;
                if patterns > INVERSION_CACHE_MAX + 50 {
                    break 'outer;
                }
            }
        }
    }
    assert!(c.inversion_cache_len() <= INVERSION_CACHE_MAX);
}

#[test]
fn check_shards_semantics() {
    assert_eq!(check_shards([0, 3, 3].into_iter(), true), Ok(3));
    assert_eq!(
        check_shards([0, 3, 3].into_iter(), false),
        Err(Error::ShardSize)
    );
    assert_eq!(
        check_shards([0, 0].into_iter(), true),
        Err(Error::ShardNoData)
    );
    assert_eq!(check_shards([].into_iter(), true), Err(Error::ShardNoData));
    assert_eq!(
        check_shards([2, 3].into_iter(), true),
        Err(Error::ShardSize)
    );
}

/// `(ds, ps, len)` with `ds + ps <= 256`: mostly small codes, sometimes large ones.
fn code_shape() -> impl Strategy<Value = (usize, usize, usize)> {
    prop_oneof![
        4 => (1usize..=12, 1usize..=12, 1usize..=200),
        1 => (1usize..=200, 1usize..=56, 1usize..=64),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Parity and recovered data equal those of the reed-solomon-erasure crate (the same
    /// Backblaze/klauspost construction), for random codes, contents and erasures.
    #[test]
    fn prop_rs_matches_reed_solomon_erasure(
        (ds, ps, len) in code_shape(),
        seed in any::<u64>(),
        erase_seed in any::<u64>(),
    ) {
        let data: Vec<Vec<u8>> = (0..ds)
            .map(|i| rand_bytes(&mut govectors_rng("rs-prop", seed ^ i as u64), len))
            .collect();
        let mut ours = Codec::new(ds, ps).unwrap();
        let full = encode_all(&ours, &data);

        let oracle = ReedSolomon::new(ds, ps).unwrap();
        let mut theirs: Vec<Vec<u8>> = data.clone();
        theirs.resize(ds + ps, vec![0; len]);
        oracle.encode(&mut theirs).unwrap();
        prop_assert_eq!(&full, &theirs);

        // Erase up to ps shards (random count and positions).
        let mut rng = govectors_rng("rs-prop-erase", erase_seed);
        let count = 1 + rng.below(ps as u64) as usize;
        let mut order: Vec<usize> = (0..ds + ps).collect();
        for i in (1..order.len()).rev() {
            order.swap(i, rng.below(i as u64 + 1) as usize);
        }
        let missing = &order[..count];

        let mut a: Vec<Option<Vec<u8>>> = full
            .iter()
            .enumerate()
            .map(|(i, s)| (!missing.contains(&i)).then(|| s.clone()))
            .collect();
        let mut b = a.clone();
        ours.reconstruct_data(&mut a).unwrap();
        oracle.reconstruct_data(&mut b).unwrap();
        for i in 0..ds {
            prop_assert_eq!(a[i].as_ref(), Some(&full[i]));
            prop_assert_eq!(&a[i], &b[i]);
        }
        for (i, shard) in a.iter().enumerate().skip(ds) {
            prop_assert_eq!(shard.is_none(), missing.contains(&i));
        }
    }
}
