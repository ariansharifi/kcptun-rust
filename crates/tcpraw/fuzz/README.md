# kcptun-tcpraw fuzz target

cargo-fuzz crate for `kcptun-tcpraw` (plan step 10.1). It is not a member of the root workspace
(`exclude` in the root `Cargo.toml`); it has its own workspace and lock file and needs nightly.

| Target | What it fuzzes |
|---|---|
| `tcp_segment` | The segment codec on arbitrary bytes, as a raw socket would deliver them. One selector byte picks whether the read came from an `AF_INET` socket (so the IPv4 header is stripped first, like Go's `ReadFromIP`), which pseudo-header the checksum uses, and whether the parsed segment is serialised again and re-parsed, which drives the write path with an option list the input chose. Nothing may panic, and the parser may never report options or a payload outside the buffer it was given. |

This is the one parser in the crate that a peer reaches with no handshake at all: a raw socket
sees every TCP segment on the host, and `captureFlow` parses each one before the port filter has
looked at it (porting guide §5).

The harness and its input format are in `crates/tcpraw/src/internals/fuzz.rs`
(`kcptun_tcpraw::internals::fuzz`, behind the hidden `internals` feature), so the crate's own
tests run it over the seeds (`tcp_segment_seeds_run_clean`) and over short, empty and
pseudo-random inputs with every selector (`tcp_segment_handles_short_and_random_input`).

## Running

From `crates/tcpraw`:

```sh
mkdir -p fuzz/corpus/tcp_segment
cargo +nightly fuzz run -s none -a tcp_segment fuzz/corpus/tcp_segment fuzz/seeds/tcp_segment \
  -- -max_total_time=120 -max_len=4096
```

- `fuzz/corpus/tcp_segment` (first directory, gitignored) receives the inputs libFuzzer finds;
  `fuzz/seeds/tcp_segment` (committed) is only read. libFuzzer requires the corpus directory to
  exist.
- `-a` turns on debug assertions and **overflow checks**: Go's unsigned arithmetic wraps, so an
  arithmetic overflow panic means the port misses a `wrapping_*` somewhere.
- `-s none`: the codec is safe Rust, so AddressSanitizer adds nothing, and on macOS its
  allocator caches grow the process past libFuzzer's 2 GB RSS limit (a false out-of-memory
  report).

Per `docs/porting-guide.md` §4, the in-step run is a **smoke** run of about two minutes; the long
campaigns belong to Step 11/12 and CI.

## Results

10.1 smoke run (M5 laptop, the command above, starting from the committed seeds):
`Done 115472544 runs in 121 second(s)`, about 950k executions per second, corpus 189 inputs,
peak RSS 27 MB, no crash and no timeout. A follow-up run over that corpus reports
`cov: 165 ft: 328`.

The first run of the target did find one: with a re-serialised option list longer than 40 bytes
the data offset does not fit its 4-bit field. gopacket truncates it silently there too
(`DataOffset=16` in the struct, a nibble of `0` on the wire, no error, and its own decoder then
reads an empty segment), which was confirmed against `gopacket@v1.1.19` and is now pinned by
`serialize_truncates_a_data_offset_past_15_like_gopacket`. tcpraw's own fingerprint is 12 or 14
option bytes, so the port never reaches it.

## Seeds

`fuzz/seeds/tcp_segment/` holds the `hand_*` inputs of `tcp_segment_handcrafted_seeds()`: the
two segment layouts a Go peer sends (V10 and pinned v1.2.32, over IPv4 and IPv6 pseudo-headers),
one of them behind a real IPv4 header as an `AF_INET` raw read delivers it, a SYN with a Linux
option layout (MSS, SACK permitted, timestamps, NOP, window scale), a FIN|ACK with no options, a
data offset past the end of the buffer, an option length past the end of the option area, a
truncated IPv4 read and an empty read.

Regenerate them with
`cargo test -p kcptun-tcpraw --lib write_tcp_segment_fuzz_seeds -- --ignored`; the test
`tcp_segment_fuzz_seed_files_up_to_date` fails when the committed seeds differ from what the
generator produces.

## Crashes

A crash input goes into `fuzz/artifacts/tcp_segment/`. Reproduce it with
`cargo +nightly fuzz run -s none -a tcp_segment <file>`, minimise it with
`cargo +nightly fuzz tmin`, fix the port, and add the input as a regression test next to the
harness tests (`internals::fuzz::tests`) or in `tcp::tests`.
