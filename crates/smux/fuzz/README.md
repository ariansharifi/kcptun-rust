# kcptun-smux fuzz target

cargo-fuzz crate for `kcptun-smux` (plan step 06.5). It is not a member of the root workspace
(`exclude` in the root `Cargo.toml`); it has its own workspace and lock file and needs nightly.

| Target | What it fuzzes |
|---|---|
| `smux_recv` | A live `Session` reading a fuzzer-chosen byte string from its connection: two selector bytes pick the protocol version, the side (client or server), the keepalive, `max_receive_buffer` (down to 1 KiB, so the token bucket starves), `max_frame_size`, whether accepted streams are echoed (which also exercises the write path, the shaper and the version-2 window) and how much one `read` hands out. Everything after them is the peer's byte stream. Nothing may panic; a protocol error, a socket error or the end of the stream are all fine, and a two-second watchdog turns a stalled session into a finding instead of a hang. |

The harness and its input format are in `crates/smux/src/internals/fuzz.rs`
(`kcptun_smux::internals::fuzz`, behind the hidden `internals` feature), so the crate's own
tests run it over the seeds (`smux_recv_seeds_run_clean`) and over every selector combination
(`smux_recv_handles_short_and_random_input`).

## Running

From `crates/smux`:

```sh
cargo +nightly fuzz run -s none -a smux_recv fuzz/corpus/smux_recv fuzz/seeds/smux_recv \
  -- -max_total_time=120 -max_len=16384
```

- `fuzz/corpus/smux_recv` (first directory, gitignored) receives the inputs libFuzzer finds;
  `fuzz/seeds/smux_recv` (committed) is only read.
- `-a` turns on debug assertions and **overflow checks**: Go's unsigned arithmetic wraps, so an
  arithmetic overflow panic means the port misses a `wrapping_*` somewhere.
- `-s none`: the code under test is safe Rust (`#![forbid(unsafe_code)]`), so AddressSanitizer
  adds nothing, and on macOS its allocator caches grow the process past libFuzzer's 2 GB RSS
  limit within a few minutes (a false out-of-memory report).
- Every run builds a tokio runtime and starts the session's tasks, so an execution costs tens
  of microseconds; that is the price of fuzzing the real session rather than a parser.

Per `docs/porting-guide.md` §4, the in-step run is a **smoke** run of about two minutes; the long
campaigns belong to Step 11/12 and CI.

## Results

06.5 smoke run (M5 laptop, the command above, starting from the committed seeds):
`Done 2178121 runs in 130 second(s)`, cov 1894, ft 7764, corpus 587 inputs, peak RSS 35 MB,
about 17k executions per second, no crash and no timeout. (An earlier version of the harness
awaited the per-stream tasks, which parked on a version-2 window the input never opened and
made every such input wait out the watchdog: 26 executions per second. The harness now leaves
the stream tasks to the runtime, which the run ends anyway.)

## Seeds

`fuzz/seeds/smux_recv/` holds the `hand_*` inputs of `smux_recv_handcrafted_seeds()`: honest
version-1 and version-2 streams (SYN/PSH/UPD/FIN/NOP), an echoed stream with a small frame size
and tiny reads, a client-side session, every protocol-error path (wrong version, unknown
command, SYN/NOP with a payload, UPD on a version-1 session, UPD with the wrong length), a
truncated PSH, a zero-length PSH, frames for an unknown stream, forty SYNs with a duplicate, a
starved 1 KiB token bucket and a session with the keepalive on.

Regenerate them with `cargo test -p kcptun-smux --lib write_smux_fuzz_seeds -- --ignored`; the
test `smux_fuzz_seed_files_up_to_date` fails when the committed seeds differ from what the
generator produces.

## Crashes

A crash input goes into `fuzz/artifacts/smux_recv/`. Reproduce it with
`cargo +nightly fuzz run -s none -a smux_recv <file>`, minimise it with
`cargo +nightly fuzz tmin`, fix the port, and add the input as a regression test next to the
harness tests (`internals::fuzz::tests`).
