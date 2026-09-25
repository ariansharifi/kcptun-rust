# AES-128-GCM backend evaluation (plan 12.2b)

`crates/kcp` reaches only 0.68–0.88× Go for `-crypt aes-128-gcm` (docs/benchmarks/crypto.md;
0.68–0.78× at the 1350 B size the 12.2b session measured).
Step 12.2b asked whether `ring`, `aws-lc-rs` or a hand-fused AES-CTR + GHASH closes that gap.
This directory is the harness that answered it. **Nothing we ship depends on it.**

It is its own workspace with its own lock file, like the `cargo-fuzz` crates, so `cargo build`,
`cargo test --workspace`, `cargo clippy --workspace` and `cargo deny` at the repo root never pull
in `ring` or `aws-lc-sys`. Building it needs a C compiler (both candidates compile C and
assembly); the repo itself still builds with `rustc` alone.

## Run it

```sh
cd tools/bench/aes-gcm-eval
cargo test --release                 # all four backends produce identical bytes
cargo bench -- --noplot --warm-up-time 0.5 --measurement-time 2 1350
```

**No CI job and no workspace command ever builds this crate**, so its tests cannot fail the gate:
they are hand-run, and `Cargo.lock` is checked in and pinned on purpose so the 12.2b measurement
stays reproducible. If the lock is ever refreshed — or `ring`, `aws-lc-rs` or `aes-gcm` move on —
re-run `cargo test --release` here by hand, because it is the only thing that keeps the four
backends byte-identical.

On lab-arm64, cross-build and copy as tools/lab/README.md requires (never build on the box):

```sh
cargo zigbuild --release --benches --target aarch64-unknown-linux-musl
scp "$(ls -t target/aarch64-unknown-linux-musl/release/deps/gcm-* | grep -v '\.d$' | head -1)" \
    lab-arm64:kcptun-lab/tests/bench/kr-bench-gcm
ssh lab-arm64 './kcptun-lab/tests/bench/kr-bench-gcm --bench --noplot \
      --warm-up-time 0.5 --measurement-time 2 1350'
ssh lab-arm64 'rm -rf ~/kcptun-lab/tests/bench'
```

Every DECISIONS D22 target was tried with `ring` and `aws-lc-sys` in the graph.
`cargo zigbuild --release --benches --target <t>` succeeds for `aarch64-unknown-linux-{musl,gnu}`,
`x86_64-unknown-linux-{musl,gnu}`, `armv7-unknown-linux-{musleabihf,gnueabihf}`,
`i686-unknown-linux-{musl,gnu}`, `x86_64-pc-windows-gnu` and `x86_64-unknown-freebsd`;
`x86_64-apple-darwin` builds with plain `cargo build` on the macOS host, and `aarch64-apple-darwin`
is the host. Windows needs the `prebuilt-nasm` feature — without it `aws-lc-sys` looks for a local
NASM and the build fails.

The exceptions are the two ARMv6 tiers, `arm-unknown-linux-{musleabi,gnueabi}`, and they are **this
crate's** problem, not the crypto's: `cargo zigbuild --release --lib --target <t>` succeeds for
both (so `ring` and `aws-lc-sys` do build for ARMv6), while `--benches` fails to link with
`undefined symbol: fmaximum_num` / `fminimum_num` from `criterion::plot::gnuplot_backend` — C23
libm entry points that zig's bundled libc does not provide for the ARMv6 sub-target. MIPS (tier 3,
`-Zbuild-std`) was not attempted.

Interleave the rounds with the Go binary (`tools/govectors`, cross-built with
`GOOS=linux GOARCH=arm64 go test -c`) and report medians — a single pass on a shared box is worth
±5%, and criterion's own numbers move by 10–15% with code layout alone, so never compare two
different builds of this crate against each other.

## What it measures

`benches/gcm.rs` mirrors `crates/kcp/benches/crypt.rs` and Go's
`BenchmarkCrypt/<dir>/aes-128-gcm/<len>`: one iteration seals or opens one whole 1350- or
1500-byte packet in place; the decrypt loop first copies a sealed packet in, because opening
overwrites the ciphertext (Go's bench pays for the same copy).

`src/lib.rs` holds the four backends behind one trait, plus the tests that keep the comparison
honest: a length sweep where all four must agree byte for byte, the published GCM known answer,
and single-bit tampering and short-packet rejection.

## Result

Rejected — see docs/benchmarks/crypto.md, section "12.2b". In short: `aws-lc-rs` wins on the M5
and `ring` wins on the Neoverse-N1, neither wins on both, and the fused safe-Rust backend beats
Go only where the `aes` and `polyval` hardware backends are compile-time features (Apple
silicon). `crates/kcp` keeps RustCrypto `aes-gcm`.
