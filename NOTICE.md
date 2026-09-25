# Notices and third-party attributions

kcptun-rust is a Rust port of **kcptun** and the Go libraries it is built on. The port follows the
pinned Go reference closely (see `docs/porting-guide.md` §2), so the original authors' copyright notices are
kept.

## Projects this code is derived from

| Project | Version ported | License | Used for |
|---|---|---|---|
| [xtaci/kcptun](https://github.com/xtaci/kcptun) (repository now removed; module served by proxy.golang.org) | `v0.0.0-20260208051026-39935d5307f0` | MIT, © 2016 xtaci | client, server, `std` package behaviour |
| [xtaci/kcp-go](https://github.com/xtaci/kcp-go) | v5.6.66 (+ later non-wire fixes) | MIT, © 2015 xtaci | KCP ARQ, FEC, crypto framing, sessions |
| [xtaci/smux](https://github.com/xtaci/smux) | v1.5.55 (+ later non-wire fixes) | MIT, © 2016-2017 xtaci | stream multiplexing |
| [xtaci/tcpraw](https://github.com/xtaci/tcpraw) | v1.2.32 (+ fingerprint fix `cbf9635`) | MIT, © 2019 xtaci | fake-TCP transport |
| [xtaci/qpp](https://github.com/xtaci/qpp) | v1.1.25 | **GPL-3.0**, © 2024 xtaci | Quantum Permutation Pad, in `crates/qpp` only |
| [klauspost/reedsolomon](https://github.com/klauspost/reedsolomon) | v1.13.0 | MIT, © 2015 Klaus Post, © 2015 Backblaze | Reed-Solomon matrix construction and codec behaviour |
| [skywind3000/kcp](https://github.com/skywind3000/kcp) | (via kcp-go) | MIT, © 2017 Lin Wei | original KCP protocol |
| [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) `twofish` | v0.47.0 | BSD-3-Clause, © 2011 The Go Authors | Twofish block cipher: `crates/kcp/src/crypt/twofish.rs` is a modified port (tables copied from the Go source) |
| Go standard library `crypto/des` | go1.27.1 | BSD-3-Clause, © 2010-2011 The Go Authors | DES / Triple DES: `crates/kcp/src/crypt/des.rs` is a modified port (tables copied from the Go source) |
| [tjfoc/gmsm](https://github.com/tjfoc/gmsm) `sm4` | v1.4.1 | Apache-2.0, © 2017 Suzhou Tongji Fintech Research Institute | SM4 block cipher: `crates/kcp/src/crypt/sm4.rs` is a modified port (see below) |

## Specifications and behaviour matched (no code copied)

| Project | License | What is matched |
|---|---|---|
| [golang/snappy](https://github.com/golang/snappy) v1.0.0 | BSD-3-Clause, © 2011 The Snappy-Go Authors | snappy framing format chunking rules |
| [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) v0.47.0 | BSD-3-Clause, © 2009 The Go Authors | TEA (16-round) and XTEA block ciphers, reproduced to be bit-compatible |
| Go standard library `flag`, `log`, `time`, `net` | BSD-3-Clause, © 2009 The Go Authors | command-line flag parsing, log format, time layouts, `SplitHostPort` |
| [urfave/cli](https://github.com/urfave/cli) v1.22.17 | MIT | help and usage output format |
| [google/gopacket](https://github.com/google/gopacket) v1.1.19 | BSD-3-Clause, © 2012 Google, Inc. | TCP header serialisation layout (tcpraw) |

## Apache-2.0 notice for SM4

`crates/kcp/src/crypt/sm4.rs` is derived from `github.com/tjfoc/gmsm/sm4/sm4.go` v1.4.1, "Copyright
Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved", licensed under the Apache License,
Version 2.0 (<http://www.apache.org/licenses/LICENSE-2.0>). Changes: translated from Go to Rust, the
combined S-box/L tables are generated at compile time instead of written as literals, the per-cipher
scratch buffers are replaced by stack state, and the ECB/CBC/CFB/OFB/GCM helpers and PEM utilities are
not ported.

Rust crate dependencies are listed in `Cargo.lock`. Their licences are checked with `cargo deny` (see
`deny.toml`).

## GPL-3.0 notice for QPP

`crates/qpp` is a derivative of GPL-3.0 licensed `xtaci/qpp` and is itself GPL-3.0 (full text in
`crates/qpp/LICENSE`). The `qpp` cargo feature is enabled by default, so the `kcptun-client` and
`kcptun-server` binaries built with default features are combined works distributed under the GPL-3.0,
just like the upstream Go kcptun binaries, which link the same GPL-3.0 library. Build with
`--no-default-features` to produce MIT-only binaries without QPP support.
