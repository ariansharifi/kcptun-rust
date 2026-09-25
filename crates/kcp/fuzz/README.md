# kcptun-kcp fuzz targets

cargo-fuzz crate for `kcptun-kcp` (plan steps 03.6 and 04.6). It is not a member of the root workspace
(`exclude` in the root `Cargo.toml`); it has its own workspace and lock file and needs nightly.

| Target | What it fuzzes |
|---|---|
| `kcp_input` | A live `Kcp` driven by a byte string: raw input packets, crafted segments relative to its state, real (mutated, duplicated, reordered) packets from an honest peer, sends, full/ACK-only flushes, receives, `update`/`check`, MTU/window/no-delay/stream changes and clock advances. Nothing may panic, and the harness checks the send-buffer and receive-heap invariants after every op. |
| `fec_decode` | A `FecDecoder` with fuzzer-chosen `(ds, ps)` (up to 249 data shards; `ds + ps > 256` must be refused) fed raw packets, crafted FEC headers around a movable seqid cursor (data/parity/OOB/any type, garbage bodies, seqids at and above `paws`) and the packets of an honest `FecEncoder` (the same or different shard counts, so auto-tuning runs; parity skips via clock gaps), lost, truncated, duplicated and reordered. Nothing may panic; after every `decode` the harness checks that a retune returns nothing, at most `ds` shards are recovered and no recovered shard is longer than the longest packet seen minus the FEC header. |

The harnesses and their input formats are in `crates/kcp/src/internals/fuzz.rs` (`kcp_input`)
and `crates/kcp/src/internals/fec_fuzz.rs` (`fec_decode`)
(`kcptun_kcp::internals::{fuzz, fec_fuzz}`, behind the hidden `internals` feature), so the crate's
own tests run them over their seeds and over crash regressions.

## Running

From `crates/kcp`:

```sh
cargo +nightly fuzz run -s none -a kcp_input fuzz/corpus/kcp_input fuzz/seeds/kcp_input \
  -- -max_total_time=600 -max_len=16384
```

- `fuzz/corpus/kcp_input` (first directory, gitignored) receives the inputs libFuzzer finds;
  `fuzz/seeds/kcp_input` (committed) is only read.
- `-a` turns on debug assertions and **overflow checks**: Go's unsigned arithmetic wraps, so an
  arithmetic overflow panic means the port misses a `wrapping_*` somewhere.
- `-s none`: the code under test is safe Rust (`#![forbid(unsafe_code)]`), so AddressSanitizer
  adds nothing, and on macOS its allocator caches grow the process past libFuzzer's 2 GB RSS
  limit within a few minutes (a false out-of-memory report; without ASan the whole process,
  corpus included, holds steady below 200 MB). The default ASan build works for short runs.
- `-max_len=16384`: the largest seeds are 16 KiB prefixes of the golden traces.

`fec_decode` (plan step 04.6):

```sh
cargo +nightly fuzz run -s none -a fec_decode fuzz/corpus/fec_decode fuzz/seeds/fec_decode \
  -- -max_total_time=600
```

Large shard counts are rare selector values (building a 249-data-shard codec takes about 13 ms),
which keeps the run fast.

## Results

`kcp_input`: the plan's 10-minute run (the command above) finished with `Done 2157020 runs in 601 second(s)`,
cov 662, peak RSS 181 MB, and no crash. Details and the benchmarks: `docs/benchmarks/kcp.md`.

`fec_decode` (04.6, M5 laptop, the command above, starting from the committed seeds): `Done 493589
runs in 601 second(s)`, cov 794, ft 4809, corpus 786 inputs, peak RSS 42 MB, no crash.

## Seeds

`fuzz/seeds/kcp_input/` holds:

- `hand_*`: hand-made inputs (every command, the `input` error paths, fragments, retransmission,
  window probing, a dead link, MTU shrinking, clock wrap); `handcrafted_seeds()` in the harness.
- `go_<trace>_<side>`: each endpoint of the 12 golden kcp-go traces of 03.5
  (`testdata/vectors/kcp.json`, group `trace/`), as harness ops: the packets the Go peer really
  sent, the recorded calls and clock times (a prefix of at most 16 KiB).

Regenerate them after changing the harness format or the traces:

```sh
cargo test -p kcptun-kcp --lib write_fuzz_seeds -- --ignored
```

The test `fuzz_seed_files_up_to_date` fails when the committed seeds differ from what the
generator produces.

`fuzz/seeds/fec_decode/` holds the `hand_*` inputs of `fec_handcrafted_seeds()` (honest
streams with loss/truncation/duplicates, a skipped parity group, `ds == 1`, a (5,2) sender to a
(10,3) decoder, crafted headers around `paws`, a group of empty shards, large codecs).
Regenerate them with `cargo test -p kcptun-kcp --lib write_fec_fuzz_seeds -- --ignored`; the test
`fec_fuzz_seed_files_up_to_date` checks them.

## Crashes

A crash input goes into `fuzz/artifacts/<target>/`. Reproduce it with
`cargo +nightly fuzz run -s none -a <target> <file>`, minimise it with `cargo +nightly fuzz tmin`,
fix the port, and add the input as a regression test next to the harness tests
(`internals::fuzz::tests` or `internals::fec_fuzz::tests`), with the op sequence written out.
