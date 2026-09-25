//! Golden vectors produced by `tools/govectors` (format: `tools/govectors/README.md`).
//!
//! Vector files are embedded at compile time so test binaries never read files at runtime and
//! run unchanged on lab-arm64 (porting guide §8). Use the [`vectors!`](crate::vectors!) macro from
//! any crate directly under `crates/`:
//!
//! ```ignore
//! let file = kcptun_testkit::vectors!("crypt");
//! for case in file.cases_with_prefix("aes/") {
//!     let out = encrypt(case.input());
//!     kcptun_testkit::assert_hex_eq!(out, case.output(), "case {}", case.name);
//! }
//! ```

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Embeds and parses `testdata/vectors/<area>.json` relative to the **calling** crate
/// (`$CARGO_MANIFEST_DIR/../../testdata/vectors/<area>.json`), returning a
/// [`VectorFile`](crate::vectors::VectorFile).
///
/// Panics (failing the test) if the file is malformed or its `area` is not `<area>`.
#[macro_export]
macro_rules! vectors {
    ($area:literal) => {
        $crate::vectors::VectorFile::load_embedded(
            $area,
            ::core::include_str!(::core::concat!(
                ::core::env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/vectors/",
                $area,
                ".json"
            )),
        )
    };
}

/// Asserts that two byte strings are equal. On failure the message gives the lengths, the first
/// mismatching offset and the surrounding bytes of both sides in hex.
///
/// Accepts anything that is `AsRef<[u8]>` (`Vec<u8>`, `&[u8]`, arrays, ...), and an optional
/// trailing format string like `assert_eq!`.
#[macro_export]
macro_rules! assert_hex_eq {
    ($left:expr, $right:expr $(,)?) => {
        $crate::vectors::assert_hex_eq_impl(
            ::core::convert::AsRef::<[u8]>::as_ref(&$left),
            ::core::convert::AsRef::<[u8]>::as_ref(&$right),
            ::core::option::Option::None,
        )
    };
    ($left:expr, $right:expr, $($arg:tt)+) => {
        $crate::vectors::assert_hex_eq_impl(
            ::core::convert::AsRef::<[u8]>::as_ref(&$left),
            ::core::convert::AsRef::<[u8]>::as_ref(&$right),
            ::core::option::Option::Some(::core::format_args!($($arg)+)),
        )
    };
}

/// Implementation of [`assert_hex_eq!`](crate::assert_hex_eq!).
#[track_caller]
pub fn assert_hex_eq_impl(left: &[u8], right: &[u8], msg: Option<fmt::Arguments<'_>>) {
    if let Some(diff) = hex_diff(left, right) {
        match msg {
            Some(m) => panic!("assertion `left == right` failed: {m}\n{diff}"),
            None => panic!("assertion `left == right` failed\n{diff}"),
        }
    }
}

/// Bytes shown on each side of the first mismatch.
const DIFF_CONTEXT: usize = 16;
/// Byte strings up to this length are also printed in full.
const DIFF_FULL_MAX: usize = 64;

/// Describes how `left` and `right` differ, or returns `None` when they are equal.
pub fn hex_diff(left: &[u8], right: &[u8]) -> Option<String> {
    if left == right {
        return None;
    }
    let common = left.len().min(right.len());
    let first = left
        .iter()
        .zip(right)
        .position(|(a, b)| a != b)
        .unwrap_or(common);
    let differing =
        left.iter().zip(right).filter(|(a, b)| a != b).count() + left.len().abs_diff(right.len());
    let start = first.saturating_sub(DIFF_CONTEXT);
    let end = first.saturating_add(DIFF_CONTEXT + 1);

    let mut s = format!(
        "first difference at offset {first} (0x{first:x}); left len {}, right len {}, \
         {differing} byte(s) differ\n",
        left.len(),
        right.len()
    );
    s += &format!(" left[{start}..]:  {}\n", window(left, right, start, end));
    s += &format!(" right[{start}..]: {}\n", window(right, left, start, end));
    s += "  (bytes in [] differ from the other side, .. marks a missing byte)";
    if left.len() <= DIFF_FULL_MAX && right.len() <= DIFF_FULL_MAX {
        s += &format!(
            "\n left:  {}\n right: {}",
            hex::encode(left),
            hex::encode(right)
        );
    }
    Some(s)
}

/// Renders `this[start..end]` as space-separated hex, bracketing bytes that differ from `other`.
fn window(this: &[u8], other: &[u8], start: usize, end: usize) -> String {
    let mut parts = Vec::new();
    for i in start..end.min(this.len().max(other.len())) {
        let part = match (this.get(i), other.get(i)) {
            (Some(a), Some(b)) if a == b => format!("{a:02x}"),
            (Some(a), _) => format!("[{a:02x}]"),
            (None, _) => "[..]".to_string(),
        };
        parts.push(part);
    }
    parts.join(" ")
}

/// Errors from parsing a vector file.
#[derive(Debug)]
pub enum VectorError {
    /// The JSON does not match the vector file format.
    Json(serde_json::Error),
    /// The JSON parsed but violates a format rule.
    Invalid(String),
}

impl fmt::Display for VectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VectorError::Json(e) => write!(f, "vector file: {e}"),
            VectorError::Invalid(s) => write!(f, "vector file: {s}"),
        }
    }
}

impl std::error::Error for VectorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VectorError::Json(e) => Some(e),
            VectorError::Invalid(_) => None,
        }
    }
}

/// A parsed `testdata/vectors/<area>.json` file.
// Go: tools/govectors/vecio.go:VectorFile
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorFile {
    /// Always `govectors`.
    pub generator: String,
    /// Go toolchain that produced the file, e.g. `go1.27.1`.
    pub go: String,
    /// Every module linked into the generator, path -> version.
    pub modules: BTreeMap<String, String>,
    /// Area name, equal to the file's base name.
    pub area: String,
    /// Cases in file order.
    pub cases: Vec<Case>,
}

impl VectorFile {
    /// Parses and validates a vector file (generator, unique non-empty case names).
    pub fn parse(json: &str) -> Result<Self, VectorError> {
        let file: VectorFile = serde_json::from_str(json).map_err(VectorError::Json)?;
        if file.generator != "govectors" {
            return Err(VectorError::Invalid(format!(
                "generator is {:?}, want \"govectors\"",
                file.generator
            )));
        }
        let mut seen = HashSet::new();
        for case in &file.cases {
            if case.name.is_empty() {
                return Err(VectorError::Invalid(format!(
                    "area {}: case with an empty name",
                    file.area
                )));
            }
            if !seen.insert(case.name.as_str()) {
                return Err(VectorError::Invalid(format!(
                    "area {}: duplicate case name {:?}",
                    file.area, case.name
                )));
            }
        }
        Ok(file)
    }

    /// Parses embedded vector data for `area`, panicking with a clear message on any error.
    /// Used by [`vectors!`](crate::vectors!).
    #[track_caller]
    pub fn load_embedded(area: &str, json: &str) -> Self {
        let file = match Self::parse(json) {
            Ok(f) => f,
            Err(e) => panic!("testdata/vectors/{area}.json: {e}"),
        };
        assert_eq!(
            file.area, area,
            "testdata/vectors/{area}.json declares area {:?}",
            file.area
        );
        file
    }

    /// Version of a linked Go module, e.g. `module("github.com/xtaci/kcp-go/v5")`.
    pub fn module(&self, path: &str) -> Option<&str> {
        self.modules.get(path).map(String::as_str)
    }

    /// The case called `name`, if any.
    pub fn get(&self, name: &str) -> Option<&Case> {
        self.cases.iter().find(|c| c.name == name)
    }

    /// The case called `name`; panics (listing the available names) if there is none.
    #[track_caller]
    pub fn case(&self, name: &str) -> &Case {
        match self.get(name) {
            Some(c) => c,
            None => {
                let names: Vec<&str> = self.cases.iter().map(|c| c.name.as_str()).collect();
                panic!(
                    "area {}: no case named {name:?} (have {} cases: {names:?})",
                    self.area,
                    names.len()
                )
            }
        }
    }

    /// Cases whose name starts with `prefix`, in file order.
    pub fn cases_with_prefix<'a>(&'a self, prefix: &'a str) -> impl Iterator<Item = &'a Case> {
        self.cases
            .iter()
            .filter(move |c| c.name.starts_with(prefix))
    }

    /// Number of cases.
    pub fn len(&self) -> usize {
        self.cases.len()
    }

    /// True if the area has no cases yet (a stub).
    pub fn is_empty(&self) -> bool {
        self.cases.is_empty()
    }
}

/// One vector case: a unique `name` plus arbitrary fields (`params`, `in`, `out`, or an
/// area-specific shape).
// Go: tools/govectors/vecio.go:Case (and area-specific case structs)
#[derive(Clone, Debug, Deserialize)]
pub struct Case {
    /// Unique name within the file, e.g. `aes/len=21`.
    pub name: String,
    /// All other fields, by key.
    #[serde(flatten)]
    pub fields: Map<String, Value>,
}

impl Case {
    /// Raw JSON value of field `key`.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.fields.get(key)
    }

    /// Decodes the hex string field `key`; `Err` if it is missing, not a string or not hex.
    pub fn try_bytes(&self, key: &str) -> Result<Vec<u8>, String> {
        let v = self
            .get(key)
            .ok_or_else(|| format!("case {:?}: no field {key:?}", self.name))?;
        decode_hex_value(v).map_err(|e| format!("case {:?}: field {key:?}: {e}", self.name))
    }

    /// Decodes the hex string field `key`, panicking with the case name on error.
    #[track_caller]
    pub fn bytes(&self, key: &str) -> Vec<u8> {
        self.try_bytes(key).unwrap_or_else(|e| panic!("{e}"))
    }

    /// The `in` bytes (empty if the field is absent, as Go omits empty `in`).
    #[track_caller]
    pub fn input(&self) -> Vec<u8> {
        self.bytes_or_empty("in")
    }

    /// The `out` bytes (empty if the field is absent, as Go omits empty `out`).
    #[track_caller]
    pub fn output(&self) -> Vec<u8> {
        self.bytes_or_empty("out")
    }

    #[track_caller]
    fn bytes_or_empty(&self, key: &str) -> Vec<u8> {
        if self.get(key).is_some() {
            self.bytes(key)
        } else {
            Vec::new()
        }
    }

    /// Deserializes field `key` into `T`, panicking with the case name on error.
    #[track_caller]
    pub fn field<T: DeserializeOwned>(&self, key: &str) -> T {
        let v = self
            .get(key)
            .unwrap_or_else(|| panic!("case {:?}: no field {key:?}", self.name));
        T::deserialize(v).unwrap_or_else(|e| panic!("case {:?}: field {key:?}: {e}", self.name))
    }

    /// The `params` object (empty if absent).
    pub fn params(&self) -> Map<String, Value> {
        match self.get("params") {
            Some(Value::Object(m)) => m.clone(),
            _ => Map::new(),
        }
    }

    /// Deserializes `params.<key>` into `T`, panicking with the case name on error.
    #[track_caller]
    pub fn param<T: DeserializeOwned>(&self, key: &str) -> T {
        let params = self.params();
        let v = params
            .get(key)
            .unwrap_or_else(|| panic!("case {:?}: no param {key:?}", self.name));
        T::deserialize(v).unwrap_or_else(|e| panic!("case {:?}: param {key:?}: {e}", self.name))
    }

    /// Decodes the hex string `params.<key>`, panicking with the case name on error.
    #[track_caller]
    pub fn param_bytes(&self, key: &str) -> Vec<u8> {
        let params = self.params();
        let v = params
            .get(key)
            .unwrap_or_else(|| panic!("case {:?}: no param {key:?}", self.name));
        decode_hex_value(v).unwrap_or_else(|e| panic!("case {:?}: param {key:?}: {e}", self.name))
    }

    /// Deserializes the whole case (including `name`) into an area-specific struct.
    #[track_caller]
    pub fn to<T: DeserializeOwned>(&self) -> T {
        let mut obj = self.fields.clone();
        obj.insert("name".to_string(), Value::String(self.name.clone()));
        T::deserialize(Value::Object(obj)).unwrap_or_else(|e| panic!("case {:?}: {e}", self.name))
    }

    /// Deserializes the [`Blob`] field `key`.
    #[track_caller]
    pub fn blob(&self, key: &str) -> Blob {
        self.field(key)
    }
}

fn decode_hex_value(v: &Value) -> Result<Vec<u8>, String> {
    match v {
        Value::String(s) => hex::decode(s).map_err(|e| format!("invalid hex: {e}")),
        other => Err(format!("expected a hex string, found {other}")),
    }
}

/// Summary of a large byte string: length, SHA-256 and the first/last 16 bytes.
// Go: tools/govectors/vecio.go:Blob
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Blob {
    /// Length in bytes.
    pub len: usize,
    /// Lower-case hex SHA-256 of all bytes.
    pub sha256: String,
    /// Hex of the first `min(len, 16)` bytes.
    pub head: String,
    /// Hex of the last `min(len, 16)` bytes.
    pub tail: String,
}

/// Bytes kept at each end of a [`Blob`].
// Go: tools/govectors/vecio.go:blobSampleLen
pub const BLOB_SAMPLE_LEN: usize = 16;

impl Blob {
    // Go: tools/govectors/vecio.go:newBlob()
    /// Summarises `b` exactly as govectors does.
    pub fn of(b: &[u8]) -> Self {
        let n = b.len().min(BLOB_SAMPLE_LEN);
        Blob {
            len: b.len(),
            sha256: sha256_hex(b),
            head: hex::encode(&b[..n]),
            tail: hex::encode(&b[b.len() - n..]),
        }
    }

    /// Asserts that `b` is the byte string this blob describes. The head/tail are compared
    /// first so a mismatch shows readable bytes rather than only two hashes.
    #[track_caller]
    pub fn assert_matches(&self, b: &[u8], what: &str) {
        let got = Blob::of(b);
        assert_eq!(got.len, self.len, "{what}: length");
        assert_eq!(got.head, self.head, "{what}: first bytes");
        assert_eq!(got.tail, self.tail, "{what}: last bytes");
        assert_eq!(got.sha256, self.sha256, "{what}: sha256");
    }
}

/// Lower-case hex SHA-256 of `b`.
pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    const AREAS: [&str; 11] = [
        "crypt",
        "fec",
        "autotune",
        "rs",
        "kcp",
        "smux",
        "snappy",
        "qpp",
        "config",
        "multiport",
        "timefmt",
    ];

    fn all_files() -> Vec<VectorFile> {
        vec![
            crate::vectors!("crypt"),
            crate::vectors!("fec"),
            crate::vectors!("autotune"),
            crate::vectors!("rs"),
            crate::vectors!("kcp"),
            crate::vectors!("smux"),
            crate::vectors!("snappy"),
            crate::vectors!("qpp"),
            crate::vectors!("config"),
            crate::vectors!("multiport"),
            crate::vectors!("timefmt"),
        ]
    }

    #[test]
    fn vectors_real_files_load_with_pinned_modules() {
        let files = all_files();
        for (file, area) in files.iter().zip(AREAS) {
            assert_eq!(file.area, area);
            assert_eq!(file.generator, "govectors");
            assert!(file.go.starts_with("go1."), "go = {}", file.go);
            assert_eq!(
                file.module("github.com/xtaci/kcp-go/v5"),
                Some("v5.6.66"),
                "{area}"
            );
            assert_eq!(file.module("github.com/xtaci/smux"), Some("v1.5.55"));
            assert_eq!(file.module("github.com/xtaci/qpp"), Some("v1.1.25"));
            assert_eq!(file.module("github.com/golang/snappy"), Some("v1.0.0"));
            assert_eq!(
                file.module("github.com/klauspost/reedsolomon"),
                Some("v1.13.0")
            );
            assert_eq!(file.module("golang.org/x/crypto"), Some("v0.47.0"));
            assert_eq!(file.len(), file.cases.len());
        }
    }

    const SAMPLE: &str = r#"{
  "generator": "govectors",
  "go": "go1.27.1",
  "modules": {"github.com/xtaci/kcp-go/v5": "v5.6.66"},
  "area": "sample",
  "cases": [
    { "name": "aes/len=3", "params": {"key": "000102", "mtu": 1350, "fec": true}, "in": "616263", "out": "ffee" },
    { "name": "aes/len=0", "params": {"key": "00"} },
    { "name": "qpp/pad", "pad": {"len": 3, "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "head": "616263", "tail": "616263"}, "count": 7 },
    { "name": "bad/hex", "in": "zz", "out": 5 }
  ]
}"#;

    #[test]
    fn parse_and_access_fields() {
        let f = VectorFile::parse(SAMPLE).unwrap();
        assert_eq!(f.area, "sample");
        assert_eq!(f.len(), 4);
        let c = f.case("aes/len=3");
        assert_eq!(c.input(), b"abc");
        assert_eq!(c.output(), vec![0xff, 0xee]);
        assert_eq!(c.param::<u32>("mtu"), 1350);
        assert!(c.param::<bool>("fec"));
        assert_eq!(c.param_bytes("key"), vec![0, 1, 2]);
        let empty = f.case("aes/len=0");
        assert!(empty.input().is_empty() && empty.output().is_empty());
        assert_eq!(f.cases_with_prefix("aes/").count(), 2);
        assert!(f.get("nope").is_none());

        let q = f.case("qpp/pad");
        assert_eq!(q.field::<u32>("count"), 7);
        q.blob("pad").assert_matches(b"abc", "pad");
        assert_eq!(q.blob("pad"), Blob::of(b"abc"));

        let bad = f.case("bad/hex");
        assert!(bad.try_bytes("in").unwrap_err().contains("invalid hex"));
        assert!(
            bad.try_bytes("out")
                .unwrap_err()
                .contains("expected a hex string")
        );
        assert!(bad.try_bytes("missing").unwrap_err().contains("no field"));
    }

    #[test]
    fn case_to_area_specific_struct() {
        #[derive(Deserialize)]
        struct PadCase {
            name: String,
            pad: Blob,
            count: u32,
        }
        let f = VectorFile::parse(SAMPLE).unwrap();
        let p: PadCase = f.case("qpp/pad").to();
        assert_eq!((p.name.as_str(), p.pad.len, p.count), ("qpp/pad", 3, 7));
    }

    #[test]
    #[should_panic(expected = "no case named \"missing\"")]
    fn missing_case_panics_with_name() {
        VectorFile::parse(SAMPLE).unwrap().case("missing");
    }

    #[test]
    #[should_panic(expected = "declares area \"sample\"")]
    fn load_embedded_checks_area() {
        VectorFile::load_embedded("crypt", SAMPLE);
    }

    #[test]
    fn parse_rejects_invalid_files() {
        let dup = SAMPLE.replace("aes/len=0", "aes/len=3");
        assert!(
            VectorFile::parse(&dup)
                .unwrap_err()
                .to_string()
                .contains("duplicate case name")
        );
        let gen_ = SAMPLE.replace("\"govectors\"", "\"other\"");
        assert!(
            VectorFile::parse(&gen_)
                .unwrap_err()
                .to_string()
                .contains("generator")
        );
        let unnamed = SAMPLE.replace("\"name\": \"aes/len=0\"", "\"name\": \"\"");
        assert!(
            VectorFile::parse(&unnamed)
                .unwrap_err()
                .to_string()
                .contains("empty name")
        );
        let extra = SAMPLE.replace("\"area\"", "\"extra\": 1, \"area\"");
        assert!(matches!(
            VectorFile::parse(&extra),
            Err(VectorError::Json(_))
        ));
        assert!(matches!(VectorFile::parse("{"), Err(VectorError::Json(_))));
    }

    #[test]
    fn blob_matches_go_new_blob() {
        // Go: newBlob([]byte("abc")) and a 40-byte input (head/tail are 16 bytes each).
        let b = Blob::of(b"abc");
        assert_eq!(b.head, "616263");
        assert_eq!(b.tail, "616263");
        let long: Vec<u8> = (0u8..40).collect();
        let b = Blob::of(&long);
        assert_eq!(b.len, 40);
        assert_eq!(b.head, hex::encode(&long[..16]));
        assert_eq!(b.tail, hex::encode(&long[24..]));
        let empty = Blob::of(b"");
        assert_eq!(
            empty.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!((empty.head.as_str(), empty.tail.as_str()), ("", ""));
    }

    #[test]
    #[should_panic(expected = "pad: first bytes")]
    fn blob_mismatch_reports_samples() {
        Blob::of(b"abc").assert_matches(b"abd", "pad");
    }

    #[test]
    fn hex_diff_reports_offset_and_context() {
        assert_eq!(hex_diff(b"abc", b"abc"), None);
        let left: Vec<u8> = (0u8..40).collect();
        let mut right = left.clone();
        right[20] = 0xff;
        let d = hex_diff(&left, &right).unwrap();
        assert!(
            d.starts_with(
                "first difference at offset 20 (0x14); left len 40, right len 40, 1 byte(s) differ"
            ),
            "{d}"
        );
        assert!(d.contains(" left[4..]:  04 05"), "{d}");
        assert!(d.contains("13 [14] 15"), "{d}");
        assert!(d.contains("13 [ff] 15"), "{d}");
        assert!(d.contains("\n left:  0001"), "{d}");

        // One side is a prefix of the other.
        let d = hex_diff(b"\x01\x02", b"\x01\x02\x03").unwrap();
        assert!(
            d.contains("offset 2 (0x2); left len 2, right len 3, 1 byte(s) differ"),
            "{d}"
        );
        assert!(d.contains(" left[0..]:  01 02 [..]"), "{d}");
        assert!(d.contains(" right[0..]: 01 02 [03]"), "{d}");

        // Long inputs are not printed in full.
        let big = vec![0u8; 100];
        let d = hex_diff(&big, &[0u8; 99]).unwrap();
        assert!(!d.contains("\n left:  "), "{d}");
    }

    #[test]
    fn assert_hex_eq_passes_on_equal_inputs() {
        crate::assert_hex_eq!(vec![1u8, 2], [1u8, 2]);
        crate::assert_hex_eq!(&b"ab"[..], b"ab", "case {}", "x");
    }

    #[test]
    #[should_panic(expected = "failed: case aes/1\nfirst difference at offset 1")]
    fn assert_hex_eq_panics_with_message() {
        crate::assert_hex_eq!(vec![1u8, 2], vec![1u8, 3], "case {}", "aes/1");
    }
}
