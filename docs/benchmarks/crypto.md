# Packet crypto: Rust vs Go (plan 02.6)

Throughput of one whole-packet encryption or decryption for every `-crypt` method, Go kcp-go v5.6.66
against `kcptun-kcp::crypt`. The results drove the CFB decrypt batching and the replacement of three
RustCrypto ciphers (see *Changes*).

## Methodology

- **What is measured.** One iteration encrypts or decrypts one packet of 1350 bytes (kcptun's default
  MTU) or 1500 bytes (kcp-go's `mtuLimit`) **in place**, as the session does. The packet is nonce, crc and
  payload, all encrypted. Throughput is packet bytes per second, in MB/s (10^6 B/s, Go's unit).
- **Keys.** Both sides key the cipher like kcptun: the pass is `PBKDF2-HMAC-SHA1("it's a secrect",
  "kcp-go", 4096, 32)`. Go goes through `SelectBlockCrypt`; Rust calls the constructors with the same
  key prefix (the table in kcptun `std/crypt.go`).
- **aes-128-gcm.** A packet of length L is `nonce(12) | plaintext(L-28) | tag(16)`. "Encrypt" means
  `Seal` in place, with the sess.go call shape. "Decrypt" copies a sealed packet into the buffer, then
  runs `Open` in place. Opening overwrites the ciphertext, so both sides pay for that 1.3 KB copy.
- **Go:** `tools/govectors/bench_test.go` (`BenchmarkCrypt/<dir>/<method>/<len>`, `b.SetBytes(len)`,
  pinned modules). Laptop: `cd tools/govectors && go test -run '^$' -bench Crypt -benchtime 1s`
  (with `GOMODCACHE=$PWD/../../reference/gomod GOFLAGS=-modcacherw GOTOOLCHAIN=local`).
  lab-arm64: `GOOS=linux GOARCH=arm64 go test -c`, then `./kg-bench-crypt -test.run '^$' -test.bench
  Crypt/<dir> -test.benchtime 1s`.
- **Rust:** `crates/kcp/benches/crypt.rs` (criterion 0.8, `crypt/<dir>/<method>/<len>`), release
  profile (fat LTO, 1 CGU). Laptop: `cargo bench -p kcptun-kcp --bench crypt -- --noplot
  --warm-up-time 1 --measurement-time 2`. lab-arm64: `cargo-zigbuild test -p kcptun-kcp --bench crypt
  --release --no-run --target aarch64-unknown-linux-musl`, copied to `~/kcptun-lab/tests/bench/` as
  `kr-bench-crypt`, run with `--bench --noplot --warm-up-time 0.3 --measurement-time 1 crypt/<dir>`.
  Rust values are criterion medians.
- **Machines.**
  - Laptop: Apple **M5** (10 cores), macOS 27.0, Go 1.27.1 darwin/arm64, Rust 1.98.1.
  - lab-arm64: **Neoverse-N1**, 2 vCPU, Ubuntu 24.04 (kernel 6.17), shared with live services.
    Features include `aes pmull`. The load average was 0.2 to 1.2 during the runs. The runs were
    interleaved as Go encrypt, Rust encrypt, Go decrypt, Rust decrypt, each under 60 s (LAB.md §2).
    These numbers come from a single pass on a shared box, so treat them as ±5%.
- **Code.** Measured on the tree of the `[02.6]` commit (parent `1250f50`; `git log --grep '^\[02.6\]'`
  finds it). Go: kcp-go v5.6.66, x/crypto v0.47.0, gmsm v1.4.1, Go 1.27.1 stdlib `crypto/aes`,
  `crypto/des`, `crypto/cipher`.

## Acceptance

The plan's bar is decrypt ≥ 1.0× Go and encrypt ≥ 0.9× Go for every method.

- **Pass on both machines:** every CFB method, salsa20, xor and none.
- **Fail: aes-128-gcm.** On the M5 it reaches 0.84–0.88× Go for encrypt and 0.77–0.83× for decrypt.
  On the N1 it reaches 0.69–0.76× for encrypt and 0.68–0.74× for decrypt. The failing cells are
  **bold** in the tables. The reason is under *Open: AES-GCM*; the step 12.2b follow-up that tried
  to fix it, and why it was rejected, is the *12.2b* section at the end of this file.
  **The 0.84× M5 encrypt cell no longer reproduces**: the later 12.2b session measures 0.77–0.78×
  for the same case, so read the ranges here as 0.77–0.88×, and see *Results, 1350 B* under *12.2b*
  for the current M5 numbers.

## Results: laptop (Apple M5)

| method | enc Go | enc Rust | enc ×Go | dec Go | dec Rust | dec ×Go |
|---|---:|---:|---:|---:|---:|---:|
| **1350 B** | | | | | | |
| aes | 1,412 | 1,638 | 1.16 | 2,250 | 12,332 | 5.48 |
| aes-128 | 1,705 | 1,958 | 1.15 | 2,437 | 14,857 | 6.10 |
| aes-192 | 1,555 | 1,762 | 1.13 | 2,334 | 13,645 | 5.85 |
| aes-128-gcm | 7,799 | 6,519 | **0.84** | 7,538 | 5,827 | **0.77** |
| salsa20 | 785 | 1,186 | 1.51 | 784 | 1,155 | 1.47 |
| blowfish | 171 | 199 | 1.16 | 284 | 387 | 1.36 |
| twofish | 159 | 278 | 1.75 | 165 | 392 | 2.38 |
| cast5 | 167 | 176 | 1.05 | 189 | 329 | 1.74 |
| 3des | 52 | 55 | 1.05 | 56 | 59 | 1.05 |
| tea | 334 | 358 | 1.07 | 554 | 875 | 1.58 |
| xtea | 106 | 106 | 0.99 | 143 | 152 | 1.06 |
| sm4 | 143 | 182 | 1.28 | 151 | 250 | 1.65 |
| xor | 68,807 | 84,623 | 1.23 | 69,018 | 84,066 | 1.22 |
| none | 825,688 | 3,076,951 | 3.73 | 818,182 | 2,904,398 | 3.55 |
| **1500 B** | | | | | | |
| aes | 1,441 | 1,622 | 1.13 | 2,264 | 12,207 | 5.39 |
| aes-128 | 1,718 | 1,938 | 1.13 | 2,448 | 14,567 | 5.95 |
| aes-192 | 1,566 | 1,749 | 1.12 | 2,359 | 13,166 | 5.58 |
| aes-128-gcm | 7,937 | 7,023 | **0.88** | 7,515 | 6,275 | **0.83** |
| salsa20 | 768 | 1,154 | 1.50 | 768 | 1,127 | 1.47 |
| blowfish | 171 | 198 | 1.16 | 284 | 382 | 1.34 |
| twofish | 160 | 279 | 1.74 | 166 | 394 | 2.38 |
| cast5 | 167 | 176 | 1.05 | 189 | 329 | 1.74 |
| 3des | 52 | 55 | 1.04 | 56 | 59 | 1.05 |
| tea | 335 | 358 | 1.07 | 556 | 869 | 1.56 |
| xtea | 106 | 105 | 0.99 | 143 | 149 | 1.05 |
| sm4 | 144 | 183 | 1.27 | 152 | 251 | 1.65 |
| xor | 71,259 | 86,736 | 1.22 | 71,293 | 86,041 | 1.21 |
| none | 915,751 | 3,420,486 | 3.74 | 909,091 | 3,233,979 | 3.56 |

## Results: lab-arm64 (Neoverse-N1)

| method | enc Go | enc Rust | enc ×Go | dec Go | dec Rust | dec ×Go |
|---|---:|---:|---:|---:|---:|---:|
| **1350 B** | | | | | | |
| aes | 679 | 1,038 | 1.53 | 664 | 2,454 | 3.70 |
| aes-128 | 778 | 1,221 | 1.57 | 753 | 3,065 | 4.07 |
| aes-192 | 739 | 1,116 | 1.51 | 725 | 2,719 | 3.75 |
| aes-128-gcm | 2,200 | 1,528 | **0.69** | 2,109 | 1,442 | **0.68** |
| salsa20 | 301 | 726 | 2.41 | 300 | 730 | 2.44 |
| blowfish | 111 | 138 | 1.24 | 112 | 173 | 1.55 |
| twofish | 85 | 174 | 2.05 | 83 | 201 | 2.42 |
| cast5 | 105 | 120 | 1.15 | 104 | 144 | 1.39 |
| 3des | 29 | 36 | 1.25 | 29 | 37 | 1.26 |
| tea | 201 | 244 | 1.22 | 202 | 301 | 1.49 |
| xtea | 68 | 70 | 1.02 | 67 | 77 | 1.15 |
| sm4 | 90 | 123 | 1.37 | 88 | 137 | 1.55 |
| xor | 20,718 | 30,780 | 1.49 | 19,941 | 30,027 | 1.51 |
| none | 441,465 | 1,234,681 | 2.80 | 442,913 | 1,105,289 | 2.50 |
| **1500 B** | | | | | | |
| aes | 678 | 1,047 | 1.54 | 665 | 2,454 | 3.69 |
| aes-128 | 793 | 1,225 | 1.54 | 774 | 3,089 | 3.99 |
| aes-192 | 727 | 1,112 | 1.53 | 731 | 2,722 | 3.72 |
| aes-128-gcm | 2,157 | 1,639 | **0.76** | 2,093 | 1,543 | **0.74** |
| salsa20 | 288 | 694 | 2.41 | 291 | 713 | 2.45 |
| blowfish | 112 | 137 | 1.23 | 113 | 172 | 1.52 |
| twofish | 85 | 172 | 2.02 | 82 | 201 | 2.44 |
| cast5 | 104 | 120 | 1.16 | 105 | 143 | 1.36 |
| 3des | 28 | 36 | 1.26 | 29 | 37 | 1.25 |
| tea | 199 | 244 | 1.22 | 198 | 298 | 1.51 |
| xtea | 68 | 69 | 1.02 | 67 | 77 | 1.15 |
| sm4 | 88 | 124 | 1.40 | 87 | 138 | 1.58 |
| xor | 20,698 | 31,082 | 1.50 | 20,386 | 30,374 | 1.49 |
| none | 490,196 | 1,366,618 | 2.79 | 494,234 | 1,229,710 | 2.49 |

## Changes made in 02.6 (Rust before → after, M5, MB/s at 1350 B)

| Method | Direction | Before | After | Change |
|---|---|---:|---:|---|
| aes / aes-128 / aes-192 | decrypt | 9,400 / 10,400 / 11,500 | 12,300 / 14,900 / 13,600 | CFB decrypt batching (below) |
| twofish | enc / dec | 4 / 4 | 278 / 392 | port of x/crypto `twofish` (precomputed key-dependent S-boxes) instead of RustCrypto `twofish` 0.8 |
| 3des | enc / dec | 11 / 11 | 55 / 59 | port of Go `crypto/des` (`feistelBox` tables, bit-exchange IP/FP) instead of RustCrypto `des` 0.9 |
| sm4 | enc / dec | 114 / 140 | 182 / 250 | port of gmsm `sm4` (S-box and L merged into 4 word tables) instead of RustCrypto `sm4` 0.6 |

1. **CFB decrypt batching** (`crates/kcp/src/crypt/cfb.rs`). The decrypt keystream `E(C_{i-1})`
   depends only on ciphertext. For each run of 8 full blocks, the 8 keystream inputs (IV or the
   previous batch's last block, then the batch's first 7 blocks) are copied into a **fixed-size
   local array** before the XOR overwrites them. The array is encrypted with one
   `CfbBlock::encrypt_blocks` call, which for AES is the `aes` crate's 8-block parallel
   ARMv8-AES/AES-NI path. The remaining blocks (fewer than 8) and the partial tail use the serial loop.
   Measured variants, AES-256 decrypt of 1350 B on the M5:
   - plain serial loop: 144 ns;
   - batching over a slice-typed scratch buffer: 330 ns (2.3× *slower*, because it was not kept in
     registers);
   - fixed-size array batch: **103 ns**.

   Go's decrypt calls `Encrypt` once per block (assembly with a function call per block), so it
   reaches only 2.3 GB/s on the M5 and 0.66 GB/s on the N1.
2. **One CPU-feature dispatch per packet.** For the RustCrypto ciphers (AES, Blowfish, CAST5), the
   whole packet runs inside a single `BlockCipherEncrypt::encrypt_with_backend` call through a
   rank-2 closure. The `aes` crate's `#[target_feature(enable = "aes")]` backend then inlines the
   rounds into our loop, and the runtime-detection token is checked once per packet, not once per
   block. This matters on aarch64-linux and x86_64, where `aes` is not a compile-time target
   feature.
3. **Encrypt stays serial** (`C_i` feeds the next block), as in Go. It is a tight loop with the
   feedback register on the stack.
4. **Ported table-driven ciphers.** Twofish, 3DES and SM4 are now line-by-line ports of the Go
   implementations kcp-go links: x/crypto `twofish`, stdlib `crypto/des` and gmsm `sm4`. Their
   tables are built at compile time (`const fn`) where Go builds them at init, or copied from the
   Go literals. They are verified by:
   - the Go golden vectors (`vectors_cfb_*`);
   - Go's own known-answer tests (x/crypto `TestCipher`/`TestSbox`, `crypto/des`
     `encryptDESTests`/`encryptTripleDESTests`/permutation tests, GB/T 32907 SM4 examples);
   - differential proptests against the RustCrypto crates, now dev-dependencies only.

   Like Go, they use secret-indexed table lookups, so they are not constant time. These are
   legacy ciphers that kcptun offers only for compatibility. This is plan DECISIONS **D26**, which
   amends D13 (originally RustCrypto for Twofish/3DES/SM4).

## Hardware AES check

- `aes` 0.9.3 (`src/lib.rs` docs, `src/backends.rs`):
  - aarch64 uses the ARMv8 Cryptography Extensions: autodetected at run time on Linux and macOS
    via `cpufeatures`, and always present on Apple silicon, where the `aes` target feature is on
    by default for `aarch64-apple-darwin`.
  - x86/x86_64 uses AES-NI with runtime detection. VAES needs an explicit
    `--cfg aes_backend="avx256"|"avx512"`, which we do not set.
  - `--cfg aes_backend="soft"` would force the bitsliced software version; it is not set anywhere.
- Unit test `crypt::cfb::tests::aes_uses_hardware_when_available` asserts that
  `aes::hardware_accelerated()` equals the CPU's `aes` feature (true on the M5 and on lab-arm64).
- The measured numbers agree with hardware AES: CFB decrypt runs at 12–15 GB/s on the M5 and
  2.5–3.1 GB/s on the N1. Serial encrypt runs at 1.6–2.0 GB/s (M5) and 1.0–1.2 GB/s (N1), about
  8–10 ns per 16-byte block on the M5. That is the latency of the 10–14-round AESE/AESMC chain.
  The constant-time software fixslice backend would be an order of magnitude slower (not measured
  here).
- x86_64 was compile-checked only (`cargo test --target x86_64-apple-darwin` builds; no x86 host or
  Rosetta is available here).
- **xor**: the plain `zip` XOR loop is auto-vectorised (NEON). Checked in the release asm of the
  bench binary (`objdump -d` of `target/release/deps/crypt-*` built with `strip = false`): the
  `XorCrypt::xor` loop inlined into the `bench_block` closure is `ldp q0,q1 / ldp q2,q3 / ldp
  q4,q5 / ldp q6,q7`, four `eor.16b`, two `stp`, 64 bytes per iteration (trip count masked with
  `0x7c0`, i.e. `min(len, MTU_LIMIT)`). The CFB decrypt `xor_in_place` over the 128-byte keystream
  batch compiles to a `ldr q / eor.16b / str q` loop. It moves ~85 GB/s on the M5 (1350 B in
  16 ns), above Go's assembly `subtle.XORBytes`.
- **polyval** (GHASH for AES-GCM) uses the PMULL intrinsics backend on aarch64 (`polyval` 0.7.3
  `src/backend.rs`).

## Open: AES-GCM (below the bar)

RustCrypto `aes-gcm` 0.11 makes two passes over the packet: AES-CTR (8-block parallel ARMv8-AES),
then GHASH (PMULL, 8-block parallel). Go's arm64 `crypto/aes` GCM is hand-written assembly that
interleaves AES and PMULL in one pass. The gap is 12–23% on the M5 and 25–32% on the N1. It is
structural, and it cannot be closed with safe Rust against the current RustCrypto API.

Absolute speed is still 1.4–1.6 GB/s per core on the N1 and 5.8–7.0 GB/s on the M5, far above a
kcptun session's packet rate.

Follow-up (Step 12): benchmark a fused implementation, `ring` or `aws-lc-rs`, both BoringSSL-derived
assembly. Adopting one would be a DECISIONS change to D13, and it would add a C/asm build dependency
(zigbuild cross-builds would need checking). An alternative is to contribute an interleaved
aarch64 path upstream.

**That follow-up ran in step 12.2b, below. Outcome: no backend clears the bar on both machines,
so `crates/kcp` keeps RustCrypto `aes-gcm`.**

---

# 12.2b — AES-128-GCM: can the gap to Go be closed?

Step 12.2b asked for ≥ 1.0× Go for **both** seal and open at 1350 B on **both** machines, and named
three candidates: `ring`, `aws-lc-rs`, and an interleaved AES-CTR + GHASH implementation. All three
were built, verified byte-for-byte against RustCrypto and the GCM known answers, cross-built for
every DECISIONS D22 target (see *Cross-builds* below for the one caveat, which is criterion's and
not the crypto's), and measured against Go on the M5 and on lab-arm64.

**None of them clears the bar in all four cells.** `aws-lc-rs` wins on the M5 and loses on the N1;
`ring` wins on the N1 and loses on the M5; the fused safe-Rust backend matches `aws-lc-rs` on the M5
and cannot fuse at all on Linux. `crates/kcp/src/crypt/aead.rs` is unchanged.

The harness is `tools/bench/aes-gcm-eval/` (its own workspace and lock file, excluded from the root
workspace, so `ring` and `aws-lc-sys` never reach the product build, `cargo test --workspace` or
`cargo deny`). Its README has the exact commands.

## Candidates

1. **`ring` 0.17.14.** BoringSSL's `aes_gcm_{enc,dec}_kernel` assembly through `LessSafeKey`
   (kcptun derives the nonce itself, so the sequencing API would be wrong here).
2. **`aws-lc-rs` 1.18.1** (with `aws-lc-sys` 0.45.0). AWS-LC — a BoringSSL fork — with the
   ring-compatible API.
3. **Fused AES-CTR + GHASH, safe Rust** (`FusedGcm` in the harness). One pass over the packet in
   groups of 8 blocks: encrypt the 8 counter blocks with `aes`, XOR them in, GHASH the 8 ciphertext
   blocks, move on. The whole loop runs inside one `encrypt_with_backend` call, the same
   one-dispatch-per-packet trick as `crypt::cfb`.
   One property to carry forward if a fused kernel is ever revisited for the product: a single pass
   **rewrites the packet before the tag can be checked**, so a failed `open` leaves decrypted,
   unauthenticated plaintext in the caller's buffer. The shipping two-pass `AeadCrypt` does not —
   RustCrypto's `decrypt_inout_detached` verifies the tag first, so `open_in_place` leaves the
   buffer untouched on failure. (`ring` and `aws-lc-rs` overwrite on failure too, and say so.)
   kcptun drops a packet that fails to open, so nothing reads those bytes, but adopting a fused
   backend would mean accepting the property deliberately.

## Method

Same shape as the 02.6 measurement above: `benches/gcm.rs` mirrors `crates/kcp/benches/crypt.rs`
and Go's `BenchmarkCrypt/<dir>/aes-128-gcm/1350`, one whole packet per iteration, in place, with the
sealed-packet copy on the decrypt side. Five rounds per machine, each round running the Go binary
and then all four Rust backends, `-benchtime 2s` / `--measurement-time 2`; the numbers below are the
median of the five rounds' medians. Laptop load average 2.4–4.4, lab-arm64 0.12–1.09.

Two traps this measurement fell into, worth repeating for the next one:

- **Build the harness with the workspace's release profile** (fat LTO, 1 CGU). Without LTO the
  RustCrypto backend measures **40% slower** on the N1, because the `aes` backend no longer inlines
  into the CTR loop. The assembly backends barely move, so a non-LTO run flatters them enormously.
- **Never compare two different builds of the harness.** Adding an unrelated backend to the same
  binary moved RustCrypto by 13% on the M5 and 8% on the N1 through code layout alone. Only ratios
  taken inside one build (and against Go run in the same round) are meaningful.

## Results, 1350 B, ×Go (median of 5 interleaved rounds)

Go baselines: M5 encrypt 177.0 ns (7626 MB/s), decrypt 184.1 ns (7331 MB/s); N1 encrypt 607.2 ns
(2223 MB/s), decrypt 647.1 ns (2086 MB/s).

| backend | M5 enc | ×Go | M5 dec | ×Go | N1 enc | ×Go | N1 dec | ×Go |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| RustCrypto `aes-gcm` 0.11 (shipping) | 5,908 | **0.77** | 5,570 | **0.76** | 1,523 | **0.69** | 1,414 | **0.68** |
| `ring` 0.17.14 | 6,982 | **0.92** | 6,427 | **0.88** | 2,278 | 1.02 | 2,252 | 1.08 |
| `aws-lc-rs` 1.18.1 | 8,217 | 1.08 | 7,761 | 1.06 | 2,172 | **0.98** | 2,155 | 1.03 |
| fused AES-CTR+GHASH (safe Rust) | 8,200 | 1.08 | 8,454 | 1.15 | 1,484 | **0.67** | 1,409 | **0.68** |

Throughput in MB/s (10^6 B/s). Cells below 1.0× are **bold**. The shipping row agrees with
`crates/kcp/benches/crypt.rs` measured in the same session (5,988 / 5,555 on the M5, 1,525 / 1,434
on the N1), i.e. within 1.5%, which is what makes the harness comparable.

**This supersedes the M5 encrypt cell of the 02.6 table above.** 02.6 recorded 0.84× for M5 encrypt
at 1350 B; this session measures 0.77–0.78× for the same case, both in the harness and in
`crates/kcp/benches/crypt.rs` itself, and the lower value is what reproduces today. The 02.6 M5
decrypt cell (0.77×) and both N1 cells do reproduce. Nothing in `crypt::aead` changed between the
two sessions, so the difference is a laptop-state artefact, not a regression — but where the two
tables disagree, this one is current.

## Why the fused backend works on the M5 and not on Linux

Splitting it into its two halves — the `gcm/halves` group of the same harness — explains the whole
result. Per 1350-byte packet, median of 3 rounds:

| | M5 | N1 |
|---|---:|---:|
| AES-CTR pass alone (`ctr-only`) | 97.9 ns | 461.7 ns |
| GHASH pass alone (`ghash-grouped`) | 70.3 ns | 408.2 ns |
| sum | 168.2 ns | 869.9 ns |
| fused (measured) | 164.6 ns | 909.6 ns |
| Go's fused kernel | 177.0 ns | 607.2 ns |

On the N1 the fused loop is *slower* than the sum of its parts, and Go's kernel is 260 ns *faster*
than that sum. The reason is where the hardware instructions live. On `aarch64-apple-darwin` the
`aes` target feature is on by default, so the `aes` and `polyval` backends inline straight into our
loop and the AES and PMULL streams are scheduled together. On `aarch64-unknown-linux-*` (and on
x86_64) both crates detect their features at run time and put the hardware code behind
`#[target_feature]` functions, which LLVM cannot inline into each other. Every 8-block group
therefore pays two opaque calls, and the N1's reorder window is too small to overlap AES with PMULL
across them. An explicit one-group software pipeline (keystream for group *g+1* computed between
group *g*'s XOR and its GHASH) was tried and is **worse** on both machines — 195 ns on the M5 and
950 ns on the N1 — so it was not kept in the harness.

So the fused approach can only pay off where the crypto features are known at compile time — i.e.
on Apple silicon, which is the development machine, not a deployment target. Forcing
`-C target-feature=+aes` for Linux builds would produce binaries that fault on CPUs without the
extension, which is not acceptable for a release matrix like D22's.

One incidental finding from the same diagnosis, worth knowing for any future SIMD-ish loop: the
16-byte keystream XOR **must** be written as one `u128` operation. As a byte-wise
`zip(...).for_each(|d, s| *d ^= *s)` loop it does not auto-vectorise on aarch64-linux: the AES-CTR
pass went from 1.06 µs to 0.46 µs per packet on the N1 when it was rewritten as
`u128::from_ne_bytes(*b) ^ u128::from_ne_bytes(*k)`. The M5 hid almost all of it, which is exactly
why the laptop cannot be the only machine in the loop.

## The two assembly libraries: everything except the numbers checks out

Both were held to the sub-step's other three gates, and both pass:

- **Byte-exactness.** `tools/bench/aes-gcm-eval` has three tests: all four backends must seal
  identically over a length sweep (0, 1, 15, 16, 17, 31, 32, 127, 128, 129, 1000, 1322, 1338, 1472),
  the published GCM known answer (McGrew & Viega case 3) must match, and every single-bit flip and
  every short packet must be rejected. All green for all four.
- **Cross-builds.** Every D22 target was attempted, with both libraries in the graph.
  `cargo zigbuild --release --benches --target <t>` succeeds for `aarch64-unknown-linux-{musl,gnu}`,
  `x86_64-unknown-linux-{musl,gnu}`, `armv7-unknown-linux-{musleabihf,gnueabihf}`,
  `i686-unknown-linux-{musl,gnu}`, `x86_64-pc-windows-gnu` and `x86_64-unknown-freebsd`;
  `x86_64-apple-darwin` builds with plain `cargo build` on the macOS host, and `aarch64-apple-darwin`
  is the host itself. `aws-lc-sys` builds through zig's `cc` wrapper and never invokes CMake, and
  Windows needs its `prebuilt-nasm` feature — without it the build script panics looking for a
  local NASM.

  **The two ARMv6 tiers, `arm-unknown-linux-{musleabi,gnueabi}`, do not link the bench binary —
  and the cause is not the crypto.** `cargo zigbuild --release --lib` succeeds for both, i.e.
  `ring` and `aws-lc-sys` compile and archive fine for ARMv6. It is `--benches` that fails, at the
  link step, with `undefined symbol: fmaximum_num` / `fminimum_num` referenced from
  `criterion::plot::gnuplot_backend`: the C23 libm functions criterion 0.8 wants are missing from
  zig's bundled libc for the ARMv6 sub-target (the same zig builds armv7 without complaint). So
  ARMv6 is clean for a *product* build with either library, and only this measurement harness
  cannot be built for it. The MIPS tier-3 targets (`-Zbuild-std`, nightly) were not attempted.
- **Licences and supply chain.** `cargo deny check` (advisories, bans, licences, sources) is clean
  for both under the repo's `deny.toml`: `ring` declares `Apache-2.0 AND ISC`, `aws-lc-rs`
  `ISC AND (Apache-2.0 OR ISC)`, `aws-lc-sys` a conjunction that is also fully covered by the allow
  list. Weight: `ring` is 8.2 MB of sources and pulls in 4 crates (`untrusted`, `getrandom`,
  `cfg-if`, `libc`); `aws-lc-sys` is **68 MB** of vendored C and assembly (44 MB of build output per
  target) behind 3 crates; today's `aes-gcm` is 436 KB. Both make a **C compiler a hard build
  requirement** for a project that currently builds with `rustc` alone.
- One functional gap: neither library implements **AES-192-GCM**, which `AeadCrypt` accepts because
  Go's `NewAESGCMCrypt` picks the variant by key length. kcptun itself only ever passes a 16-byte
  key, but adopting either would mean keeping RustCrypto for 24-byte keys anyway.

## Verdict

Rejected, all three. The acceptance bar is ≥ 1.0× Go for seal and open on both machines and no
candidate meets it: `aws-lc-rs` is 0.98× for seal on the N1, `ring` is 0.88–0.92× on the M5, and the
fused backend is 0.67–0.68× on the N1. `aws-lc-rs` comes closest — it would turn a 23–32% deficit
into between −2% and +8% — but paying 68 MB of vendored C, a mandatory C toolchain and a second
crypto stack for a result that still misses the bar is not a trade this step should make on its
own; it is proposed as a DECISIONS entry instead.

Context for that decision: `-crypt aes-128-gcm` is scenario S3, not the production profile S1
(which uses `xor`), and even the shipping implementation moves 1.4 GB/s per core on the N1, orders
of magnitude above the packet rate of the 27-client mesh. The only avenue that could beat Go
everywhere is a hand-written interleaved AES + PMULL/CLMUL kernel behind our own
`#[target_feature]` function, i.e. `unsafe` intrinsics per architecture for a security-critical
primitive. That is out of scope here; contributing one to RustCrypto's `aes-gcm` upstream would
serve everyone better.
