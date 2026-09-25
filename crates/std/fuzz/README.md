# kcptun-std fuzz targets

cargo-fuzz crate for `kcptun-std` (plan steps 07.1 and 08.2). It is not a member of the root
workspace (`exclude` in the root `Cargo.toml`); it has its own workspace and lock file and needs
nightly.

| Target | What it fuzzes |
|---|---|
| `snappy_reader` | The framed snappy reader behind `CompStream` (`kcptun_std::comp`), fed an arbitrary stream as if it came from the peer. Nothing may panic, and the reader's two sticky states must hold: after an error every later read reports that same error, and after the end of the stream every later read reports the end. Harness and input format: `kcptun_std::internals::fuzz`. |
| `config_json` | The `-c <file>` JSON reader (`kcptun_std::gojson` + `config::parse_json_bytes`), followed by `apply_mode` and the validation helpers. The first byte picks the client or the server field table, the rest is the file. Nothing may panic: no slice-bounds or UTF-8 boundary panic in the scanner, no arithmetic overflow in the shard or rate-limit checks. |

## Running

From `crates/std`:

```sh
cargo +nightly fuzz run -s none -a config_json fuzz/corpus/config_json fuzz/seeds/config_json \
  -- -max_total_time=600 -max_len=4096
cargo +nightly fuzz run -s none -a snappy_reader fuzz/corpus/snappy_reader \
  fuzz/seeds/snappy_reader -- -max_total_time=600 -max_len=16384
```

- `fuzz/corpus/<target>` (first directory, gitignored) receives the inputs libFuzzer finds;
  `fuzz/seeds/<target>` (committed) is only read.
- `-a` turns on debug assertions and overflow checks.
- `-s none`: the crate is `#![forbid(unsafe_code)]`, so AddressSanitizer adds nothing.

## `config_json` seeds

One file per shape the reader has to get right: a full configuration, mixed-case
keys, nulls, every kind of type error, truncated documents, bad escapes, invalid UTF-8 and a
deeply nested unknown key. `config_tests.rs:parser_survives_arbitrary_input` runs a
deterministic mutation sweep over the same shapes, so a plain `cargo test` also covers them.

`-max_len` bounds how deep a generated document can nest, so the deepest documents are not
reachable from here: `config_tests.rs:deep_nesting_hits_gos_max_depth` covers the parser's
depth limit (Go's `maxNestingDepth`, 10000) instead.

## `snappy_reader` seeds

One file per shape the reader has to get right: a valid stream of each chunk type, a stream
delivered in three-byte pieces, skippable and reserved chunk types, a chunk longer than the
reader's buffer, a body longer than a block may decode to, a flipped checksum, a truncated body
and three malformed blocks. They are generated from
`kcptun_std::internals::fuzz::snappy_reader_handcrafted_seeds`, and
`snappy_fuzz_seed_files_up_to_date` fails if the committed files drift from it:

```sh
cargo test -p kcptun-std --lib write_snappy_fuzz_seeds -- --ignored
```

`comp_tests.rs:prop_reader_survives_arbitrary_input` sweeps the same ground without coverage
feedback, so a plain `cargo test` also exercises it.
