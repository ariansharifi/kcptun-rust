# Porting guide and conventions

Rules for turning the Go reference into Rust in this repository. The goal is a **faithful**,
wire-compatible port that a reviewer can compare side by side with the Go source. Read this together
with the workflow summary in §10 below and with `docs/WIRE-FORMAT.md`.

## 1. Source of truth

| What | Where (after `tools/fetch-reference.sh`) |
|---|---|
| kcptun (client, server, std) | `reference/kcptun/{client,server,std}/` |
| kcp-go v5.6.66 | `reference/kcptun/vendor/github.com/xtaci/kcp-go/v5/` |
| smux v1.5.55 | `reference/kcptun/vendor/github.com/xtaci/smux/` |
| qpp v1.1.25 | `reference/kcptun/vendor/github.com/xtaci/qpp/` |
| tcpraw v1.2.32 | `reference/kcptun/vendor/github.com/xtaci/tcpraw/` |
| reedsolomon v1.13.0, snappy v1.0.0, x/crypto, gopacket | `reference/kcptun/vendor/...` |
| Latest upstream (post-pin fixes, tests) | `reference/latest/{kcp-go,smux,qpp,tcpraw}/` |
| Go binaries and interop peers | `reference/bin/*_{darwin_arm64,linux_arm64,linux_amd64}` |

The **pinned** versions define behaviour. The latest versions are consulted only for bug fixes that do
not change the wire format (DECISIONS V01), and each adopted fix is marked as such.

### Checking Go behaviour ad hoc
`reference/kcptun` has a complete `vendor/` directory, so a throwaway Go program can import the exact
pinned libraries:

```sh
mkdir -p reference/kcptun/zz_check && cat > reference/kcptun/zz_check/main.go <<'EOF'
package main
import ("fmt"; kcp "github.com/xtaci/kcp-go/v5")
func main() { fmt.Println(kcp.IKCP_OVERHEAD) }
EOF
(cd reference/kcptun && go run -mod=vendor ./zz_check)
```

`reference/` is gitignored, so nothing leaks into the repo. Anything worth keeping becomes a
`tools/govectors` vector instead.

## 2. Fidelity rules

1. **Port, don't redesign.** Keep Go's algorithm, order of operations, constants, branch structure and
   edge cases, including the quirks. A reviewer should be able to read both versions line by line.
2. **Same names.** Go fields and functions become snake_case with the same words (`snd_una`, `rx_rto`,
   `parse_fastack`, `shard_size`). Types keep Go's name in CamelCase (`Kcp`, `FecEncoder`, `Session`).
   One Rust module per Go file where practical.
3. **Provenance comment** directly above every ported item:
   ```rust
   // Go: kcp-go/v5@v5.6.66 kcp.go:flush()
   // Go (post-pin fix, V01): kcp-go@v5.6.72 ringbuffer.go:Discard()
   ```
4. **Deviations** (anything observable that differs from Go) need a DECISIONS.md entry (V-xx) and a
   comment at the site: `// Deviation V04: forward close_write through QPP (Go falls back to Close).`
   Purely internal choices (data structures, task layout) need a D-xx entry only when architectural.
5. **When in doubt, check Go**: run the Go code (§1) rather than guessing.

## 3. Integer and time semantics

- Go unsigned arithmetic wraps. Use `wrapping_add`/`wrapping_sub`/`wrapping_mul` wherever Go could
  overflow (sequence numbers, timestamps, window math, seqid).
- `_itimediff(later, earlier)` is `later.wrapping_sub(earlier) as i32`. Go's `int32(uint32)` is
  Rust's `as i32`, and `uint32(int32)` is `as u32` (both bit-preserving).
- Go's `x / y` and `x % y` on unsigned types match Rust. Signed division truncates in both.
- Go `min`/`max` builtins on the same type map to `.min()`/`.max()`, or `std::cmp`.
- **Time:** protocol code never calls `Instant::now()` directly. It uses an injected `Clock` (DECISIONS
  D16) so simulations are deterministic. Call the clock exactly where Go calls `currentMs()` or
  `time.Now()`.
- **FEC encoder clock (internal choice):** Go's `fecEncoder.encode` reads the wall clock
  (`time.Now().UnixMilli()`, i64) and starts `tsLatestPacket` at **0**, so the first comparison
  is always "≥ 500 ms" and, with `datashard == 1`, the first packet's parity is skipped.
  `FecEncoder::encode` instead takes `now_ms: i64` from the session's monotonic millisecond
  clock (which may start near 0), and `ts_latest_packet` starts at `i64::MIN / 2`: the quirk is
  kept for any real clock value, without depending on wall-clock jumps. The gap is computed
  with `saturating_sub` (Go: wrapping), identical for all real clock values. The value must
  **not wrap**: the `Clock` trait yields a wrapping `u32` (D16), so the session has to extend it
  to i64 (e.g. by accumulating `wrapping_sub` deltas); passing `now_ms() as i64` directly would
  treat one group per 49.7-day u32 wrap as continuous (one spurious parity burst).

## 4. Errors

- Library crates define `thiserror` enums. Messages reaching logs keep **Go's exact text**:

| Go | Text |
|---|---|
| `io.EOF` | `EOF` |
| `io.ErrClosedPipe` | `io: read/write on closed pipe` |
| `io.ErrUnexpectedEOF` | `unexpected EOF` |
| kcp-go `errTimeout` / smux `ErrTimeout` | `timeout` |
| kcp-go `errInvalidOperation` | `invalid operation` |
| kcp-go `errNotOwner` | `not the owner of this connection` |
| kcp-go OOB errors | `OOB requires FEC to be enabled`, `OOB payload too large` |
| smux `ErrInvalidProtocol` | `invalid protocol` |
| smux `ErrConsumed` | `peer consumed more than sent` |
| smux `ErrGoAway` | `stream id overflows, should start a new connection` |
| smux `ErrWouldBlock` | `operation would block on IO` |
| smux `VerifyConfig` | `unsupported protocol version`, `keep-alive interval must be positive`, `keep-alive timeout must be larger than keep-alive interval`, `max frame size must be positive`, `max frame size must not be larger than 65535`, `max receive buffer must be positive`, `max receive buffer cannot be larger than 2147483647`, `max stream buffer must be positive`, `max stream buffer must not be larger than max receive buffer`, `max stream buffer cannot be larger than 2147483647` |
| tcpraw | `operation not implemented`, `timeout`, `os not supported` |

- **An errno is spelled from Go's own table, never by the C library** (DECISIONS D30).
  `kcptun_kcp::goerrno::go_error_text` is the single renderer; `kcptun_std::config::go_error_text`,
  `kcptun_std::mainutil::{op_error, setsockopt_error}` and `kcptun_tcpraw::addr::errno_text` all go
  through it. Go does not call `strerror(3)` either: it renders `syscall.Errno` from
  `syscall/zerrors_<goos>_<goarch>.go` and falls back to `errno <n>`. A static musl build otherwise
  prints `bind: address in use` where Go and glibc print `bind: address already in use`. The table is
  generated from Go's source (`tools/gen-vectors.sh errno` + `tools/gen-errno-table.py`) and checked
  against `testdata/vectors/errno.json` for every target platform, on whatever host the gate runs on.
- Timeouts must be recognisable (`is_timeout()`), as Go's `net.Error.Timeout()` is used by callers.

## 5. Safety

- **Never panic on network input.** Every parser (KCP input, FEC decode, smux frames, snappy chunks,
  TCP segments, config files) is fuzzed (`cargo +nightly fuzz`, targets in `crates/<crate>/fuzz/`).
- `unwrap()` is linted (`clippy::unwrap_used`). Use `expect("…invariant…")` only for proven invariants,
  and say why in the message. Tests may unwrap.
- `unsafe` only in: batched UDP I/O (`kcptun-kcp::io`), SIMD kernels (`kcptun-kcp::rs::simd`), raw
  sockets, the `getifaddrs(3)` walk that gives a tcpraw listener its per-interface raw sockets
  (`kcptun-tcpraw::iface`, added in step 10.3: `std` exposes no interface list), the `flock(2)`
  go-iptables takes on `/var/run/xtables.lock` (`kcptun-tcpraw`), the one call that asks the global
  allocator to hand its free pages back to the kernel: glibc's `malloc_trim(0)`, in
  `kcptun-kcp::memory` (added in step 12.3, and the only such call left after 12.3d deleted the
  rejected mimalloc allocator; `libc` exposes no safe wrapper for it, and the one
  `#[global_allocator]` left in the tree (`dhat`'s, in the `memprobe` test binary) needs no
  `unsafe` at all), and,
  test code only, added in step 05.9: the two `getrusage(2)` calls
  of `kcptun-testkit::cpu`, which the benchmark harnesses need and `std` does not wrap. Every block
  has a `// SAFETY:` comment (`clippy::undocumented_unsafe_blocks`). All other crates
  `#![forbid(unsafe_code)]`; `kcptun-testkit` denies it instead, so that the exception is a single
  `#[allow]` on one function and nothing else in the crate can add any.

## 6. Async and concurrency

- tokio multi-thread runtime (D01). Never hold a `std`/`parking_lot` mutex across `.await`.
- Wake-up pattern (no lost wakeups):
  ```rust
  loop {
      let notified = inner.read_event.notified();
      tokio::pin!(notified);
      notified.as_mut().enable();          // register BEFORE checking state
      if let Some(n) = inner.try_read(buf)? { return Ok(n); }
      tokio::select! { _ = notified => {}, _ = die.cancelled() => return Err(closed()), /* deadline */ }
  }
  ```
- Go channels used as one-shot flags (`die`, `chSocketReadError`) become `CancellationToken` or
  `OnceLock` + `Notify`. Go's buffered notify channels of size 1 become `Notify::notify_one`, which
  stores one permit, the same semantics.
- Background tasks hold an `Arc` to the shared state and exit on the die token. `Drop` of the last
  user handle should close the object (like Go finalizers), without blocking.
- Keep work inside critical sections minimal: no syscalls, crypto or allocation loops (D02).

## 7. Performance rules

- No per-packet heap allocation in steady state: pooled 1500-byte packet buffers (D06), reused vectors.
- **A buffer Go leaves untouched must stay untouched here too.** Go's allocator knows a freshly
  mapped span is already zero and skips the clear, so `make([]byte, n)` costs no resident page until
  something writes to it; `vec![0u8; n]` is `calloc`, and for a *small* `n` every allocator here
  memsets it and faults the whole thing. Two measured cases: the per-stream copy buffer (06.6,
  a 32 KiB buffer became 35.2 kB of RSS per idle stream, fixed by allocating on demand, D17) and
  the per-session receive batch (12.3c: 256 × 1500 B faulted 384 kB per *idle* client session,
  fixed by making the batch one contiguous allocation big enough that glibc's and macOS's `calloc`
  serve it from a fresh mapping and skip the memset: `crates/kcp/src/packet_conn.rs`, `RecvBatch`).
  Neither form is free everywhere, and the allocator decides: musl's mallocng memsets at **every**
  size, and glibc stops giving the *replacement* of a freed large block a fresh mapping (its `mmap`
  threshold is dynamic), so a churning process drifts back towards the resident case. On-demand
  allocation is the only form that works on every allocator: `docs/benchmarks/memory.md` §7 has
  the measurements.
- Hot-path choices are driven by benchmarks against Go (`docs/benchmarks/`), not assumptions.
- Behaviour-preserving optimisations of protocol logic are differential-tested against the naive port
  (D25).

## 8. Tests

| Kind | Naming | Notes |
|---|---|---|
| Unit | any | next to the code (`#[cfg(test)] mod tests`) |
| Golden vectors | `vectors_*` | data from `tools/govectors` in `testdata/vectors/*.json`, **embedded with `include_str!`** |
| Deterministic simulation | `sim_*` | virtual clock and `testkit::netsim` |
| Property | `prop_*` | proptest |
| Interop with Go | `interop_*` | `#[ignore]`; needs `reference/bin` (`KCPTUN_GO_BIN_DIR`) |
| End-to-end | `e2e_*` | `#[ignore]`; spawns the real binaries (`cargo build --release -p kcptun-client -p kcptun-server`). `crates/interop-tests/tests/e2e.rs`, with the heavy and slow cases split into `e2e_slow.rs`; `signals.rs` (step 09.6: signals, `-snmplog` CSV, exit status) runs the same cases through the Go binaries too and compares |
| CLI / startup-log differential | `cli_diff_*` | `#[ignore]`; runs one command line through **both** implementations' binaries and compares stdout, stderr and the exit status. `crates/interop-tests/tests/cli_diff.rs` (step 09.5); the allowed differences are a closed list of numbered deviations |
| Dev-only tool binaries | `tool_*` | **not** `#[ignore]`d: runs a `tools/` binary reached through `CARGO_BIN_EXE_*`, so it needs no release build and no deployment and the gate can afford it (`tools/pingpong/tests/cli.rs`). The trade-off is that `CARGO_BIN_EXE_*` bakes in laptop paths, so these cannot travel to lab-arm64 via `tools/lab/remote-test.sh`, only for binaries that never ship |
| Long / soak | `long_*` | `#[ignore]` |
| Benchmarks | `benches/*.rs` | criterion; compare with Go and record in `docs/benchmarks/` |

- Tests must not depend on files at runtime (embed them). This way the same test executables run on
  lab-arm64 via `tools/lab/remote-test.sh`.
- Port the relevant Go tests (listed in each plan step) and name them after the Go test
  (`test_lossy_conn1` ↔ `TestLossyConn1`).
- Linux-only code (`recvmmsg`, tcpraw, signals) must also be tested on Linux:
  `tools/lab/remote-test.sh -p <crate>`.

## 9. Features

| Feature | Crates | Default | Meaning |
|---|---|---|---|
| `qpp` | std, client, server | on | QPP support (pulls in the GPL-3.0 `kcptun-qpp`) |
| `pprof` | std, client, server | off | CPU profiling endpoint for `--pprof` (D23), **Unix only**: `pprof` 0.15 depends on `nix`, so on Windows the feature still builds but the flag logs `pprof: not available in this build`. The client and server features forward to `kcptun-std/pprof`, which holds the server |
| `dhat` | interop-tests | off | Installs the dhat heap profiler as `memprobe`'s global allocator, so live heap bytes can be read beside RSS (step 12.3b). The only `#[global_allocator]` in the tree, and it is in a test binary: **no global allocator ships** (D07 rejected mimalloc and 12.3d deleted the feature; on Linux glibc `kcptun-kcp::memory` calls `malloc_trim(0)` instead) |
| `trace` | kcp | off | KCP trace logger events (`Kcp::set_logger`/`debug_log`), like kcp-go's `debug` build tag (`kcp_trace_on.go`) |

## 10. Workflow summary

1. Read the Go code being ported before writing any Rust.
2. Implement with tests: unit tests, golden vectors generated from Go, and interop tests against the
   real Go binaries wherever the behaviour is observable on the wire.
3. Gate: all three must pass before a commit: `cargo fmt --all -- --check`,
   `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`. Long tests are
   `#[ignore]`d and run explicitly.
4. **One commit per sub-step**: `[NN.M] scope: summary`, with a body naming the Go source
   (`Go: kcp-go@v5.6.66 kcp.go:flush`) and the test evidence. A sub-step beyond roughly 600 changed
   lines is split into `[NN.Ma]`/`[NN.Mb]` rather than batched. To find one:
   `git log --oneline --grep='\[03.4\]'`.
5. At the end of a step: `[NN] complete: …`, then merge the `step/NN-slug` branch into `main` with
   `git merge --no-ff`, so `main` shows one merge per step and the sub-step commits stay
   individually reviewable.
6. **Review and verification policy.** Each sub-step gets one thorough review pass: fidelity,
   correctness and safety, completeness. In-step fuzzing is a short **smoke** run of about two
   minutes; the long campaigns (10 min and up) run in CI. Per-step benchmarking is a quick
   measurement reported in the commit message; the full Go-versus-Rust write-ups live in
   `docs/benchmarks/`. Golden vectors, Go↔Rust interop tests and the gate are what prove
   compatibility, and they are never traded away.
7. **Never** commit `reference/`, `target/`, generated binaries, captures or secrets.
