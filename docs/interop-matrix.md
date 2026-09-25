# Go ↔ Rust interop matrix

Plan step 09.4. Every case below runs the real `kcptun-client` and `kcptun-server` binaries on loopback in **all four pairings**: `go->rs` and `rs->go` are the interop crossings, `go->go` and `rs->rs` are **controls**. A control that fails means the harness is wrong, not the port — `go->go` runs no Rust at all.

Regenerate one platform's section (the others are kept):

```sh
cargo build --release -p kcptun-client -p kcptun-server
tools/fetch-reference.sh --skip-latest --skip-tests
KCPTUN_INTEROP_MATRIX_OUT=docs/interop-matrix.md \
  cargo test -p kcptun-interop-tests --test interop_matrix -- --ignored --nocapture interop_matrix_full
```

`ok` means every byte of every workload arrived and neither process logged anything unexpected. `ok (V11 a/b)` and `ok (V04+V11 a/b)` mean the same, except that the half-close probe was allowed to come back short and `a` of its `b` bytes did.

Those two tags are the **only** tolerated difference, they apply only to the half-close probe, and only with a **Go client**:

* **V11** — Go's smux discards received-but-unread data when the peer's FIN completes a half-close (`tryHalfCloseCleanup` → `streamClosed` → `recycleTokens`), so the answer is cut, usually at a frame boundary.
* **V04** — with `-QPP` on top, Go's `std.QPPPort` implements no `CloseWrite`, so kcptun's `Pipe` falls back to `Close()` and tears the whole stream down; nothing of the answer survives, hence the `0/…` rows.

Both reproduce in the `go->go` control. Every byte that *does* arrive is still checked against the expected stream, so a truncation can never hide corruption, and a **Rust client is held to a complete response against either server** — that is what V11 and V04 bought. `b/b` on a V11 row means the expected truncation happened not to occur that run: it is a race inside Go, not a difference between the peers. A V11 row is only ever a statement that what arrived was a correct prefix — `0/b` would be accepted too, so a run that produces one carries a note saying to compare it with its `go->go` control.

## Cases

| Case | Group | Configuration |
|---|---|---|
| `crypt/aes` | crypt | crypt=aes, everything else default |
| `crypt/aes-128` | crypt | crypt=aes-128, everything else default |
| `crypt/aes-192` | crypt | crypt=aes-192, everything else default |
| `crypt/aes-128-gcm` | crypt | crypt=aes-128-gcm, everything else default |
| `crypt/salsa20` | crypt | crypt=salsa20, everything else default |
| `crypt/blowfish` | crypt | crypt=blowfish, everything else default |
| `crypt/twofish` | crypt | crypt=twofish, everything else default |
| `crypt/cast5` | crypt | crypt=cast5, everything else default |
| `crypt/3des` | crypt | crypt=3des, everything else default |
| `crypt/tea` | crypt | crypt=tea, everything else default |
| `crypt/xtea` | crypt | crypt=xtea, everything else default |
| `crypt/xor` | crypt | crypt=xor, everything else default |
| `crypt/sm4` | crypt | crypt=sm4, everything else default |
| `crypt/none` | crypt | crypt=none, everything else default |
| `crypt/null` | crypt | crypt=null, everything else default |
| `pair/01` | pairwise | comp=snappy smuxver=1 fec=10/3 qpp=off mode=fast conn=1 mtu=1350 |
| `pair/02` | pairwise | comp=nocomp smuxver=2 fec=10/3 qpp=on/61 mode=fast3 conn=4 mtu=1400 |
| `pair/03` | pairwise | comp=snappy smuxver=2 fec=10/3 qpp=on/7 mode=normal conn=1 mtu=1400 |
| `pair/04` | pairwise | comp=nocomp smuxver=1 fec=10/3 qpp=off mode=manual 1 10 2 1 conn=4 mtu=1350 |
| `pair/05` | pairwise | comp=snappy smuxver=1 fec=off qpp=on/61 mode=fast conn=4 mtu=1400 |
| `pair/06` | pairwise | comp=snappy smuxver=2 fec=off qpp=off mode=fast3 conn=1 mtu=1350 |
| `pair/07` | pairwise | comp=nocomp smuxver=1 fec=off qpp=off mode=normal conn=1 mtu=1350 |
| `pair/08` | pairwise | comp=snappy smuxver=1 fec=off qpp=on/7 mode=manual 1 10 2 1 conn=1 mtu=1350 |
| `pair/09` | pairwise | comp=nocomp smuxver=2 fec=3/2 qpp=on/7 mode=fast conn=4 mtu=1350 |
| `pair/10` | pairwise | comp=snappy smuxver=1 fec=3/2 qpp=off mode=fast3 conn=1 mtu=1400 |
| `pair/11` | pairwise | comp=snappy smuxver=1 fec=3/2 qpp=on/61 mode=normal conn=1 mtu=1350 |
| `pair/12` | pairwise | comp=snappy smuxver=2 fec=3/2 qpp=on/61 mode=manual 1 10 2 1 conn=1 mtu=1400 |
| `pair/13` | pairwise | comp=snappy smuxver=1 fec=10/3-vs-5/2 qpp=off mode=fast conn=1 mtu=1350 |
| `pair/14` | pairwise | comp=nocomp smuxver=2 fec=10/3-vs-5/2 qpp=on/7 mode=fast3 conn=4 mtu=1400 |
| `pair/15` | pairwise | comp=snappy smuxver=1 fec=10/3-vs-5/2 qpp=on/61 mode=normal conn=4 mtu=1350 |
| `pair/16` | pairwise | comp=snappy smuxver=1 fec=10/3-vs-5/2 qpp=off mode=manual 1 10 2 1 conn=1 mtu=1350 |
| `production` | production | the plan's fixed production profile |

One case can be re-run on its own, in all four pairings, with `KCPTUN_INTEROP_MATRIX_FILTER=<case id>`.

<!-- platform: macos/aarch64 -->
## macos/aarch64 — 2026-09-23 10:03:31Z

**128/128** runs passed.

Workload per run: 20 MB each way on one bulk stream, 100 concurrent streams of 16 KiB each way, and a half-close probe that asks for 256 KiB after `shutdown(SHUT_WR)` (having waited 250ms first, so the answer and the peer's FIN are both buffered) — all SHA-256 verified, with both processes' logs scanned afterwards. The harness adds `-closewait 0` to the server so teardown is not delayed by 30 s per direction; nothing else is added to a case's flags.

### Binaries

| Binary | Path | `-v` | SHA-256 (first 8 bytes) |
|---|---|---|---|
| go client | `reference/bin/client_darwin_arm64` | kcptun version SELFBUILD | `2c350f06ee36952f` |
| go server | `reference/bin/server_darwin_arm64` | kcptun version SELFBUILD | `02dac930ec079bff` |
| rs client | `target/release/kcptun-client` | kcptun version SELFBUILD | `bdf0c44bda895860` |
| rs server | `target/release/kcptun-server` | kcptun version SELFBUILD | `9b40687351c9892e` |

### Results

| Case | go->rs | rs->go | go->go | rs->rs |
|---|---|---|---|---|
| `crypt/aes` | ok (V11 253952/262144) | ok | ok (V11 253952/262144) | ok |
| `crypt/aes-128` | ok (V11 253952/262144) | ok | ok (V11 262092/262144) | ok |
| `crypt/aes-192` | ok (V11 253952/262144) | ok | ok (V11 253952/262144) | ok |
| `crypt/aes-128-gcm` | ok (V11 253952/262144) | ok | ok (V11 253952/262144) | ok |
| `crypt/salsa20` | ok (V11 262144/262144) | ok | ok (V11 253900/262144) | ok |
| `crypt/blowfish` | ok (V11 253952/262144) | ok | ok (V11 253952/262144) | ok |
| `crypt/twofish` | ok (V11 253952/262144) | ok | ok (V11 253952/262144) | ok |
| `crypt/cast5` | ok (V11 262144/262144) | ok | ok (V11 253952/262144) | ok |
| `crypt/3des` | ok (V11 253952/262144) | ok | ok (V11 253952/262144) | ok |
| `crypt/tea` | ok (V11 253952/262144) | ok | ok (V11 253952/262144) | ok |
| `crypt/xtea` | ok (V11 253952/262144) | ok | ok (V11 253952/262144) | ok |
| `crypt/xor` | ok (V11 253952/262144) | ok | ok (V11 262144/262144) | ok |
| `crypt/sm4` | ok (V11 253952/262144) | ok | ok (V11 262144/262144) | ok |
| `crypt/none` | ok (V11 253952/262144) | ok | ok (V11 262144/262144) | ok |
| `crypt/null` | ok (V11 262144/262144) | ok | ok (V11 253952/262144) | ok |
| `pair/01` | ok (V11 253952/262144) | ok | ok (V11 253952/262144) | ok |
| `pair/02` | ok (V04+V11 0/262144) | ok | ok (V04+V11 0/262144) | ok |
| `pair/03` | ok (V04+V11 0/262144) | ok | ok (V04+V11 0/262144) | ok |
| `pair/04` | ok (V11 262092/262144) | ok | ok (V11 253952/262144) | ok |
| `pair/05` | ok (V04+V11 0/262144) | ok | ok (V04+V11 0/262144) | ok |
| `pair/06` | ok (V11 253952/262144) | ok | ok (V11 253952/262144) | ok |
| `pair/07` | ok (V11 262144/262144) | ok | ok (V11 253952/262144) | ok |
| `pair/08` | ok (V04+V11 0/262144) | ok | ok (V04+V11 0/262144) | ok |
| `pair/09` | ok (V04+V11 0/262144) | ok | ok (V04+V11 0/262144) | ok |
| `pair/10` | ok (V11 253900/262144) | ok | ok (V11 253900/262144) | ok |
| `pair/11` | ok (V04+V11 0/262144) | ok | ok (V04+V11 0/262144) | ok |
| `pair/12` | ok (V04+V11 0/262144) | ok | ok (V04+V11 0/262144) | ok |
| `pair/13` | ok (V11 262144/262144) | ok | ok (V11 262144/262144) | ok |
| `pair/14` | ok (V04+V11 0/262144) | ok | ok (V04+V11 0/262144) | ok |
| `pair/15` | ok (V04+V11 0/262144) | ok | ok (V04+V11 0/262144) | ok |
| `pair/16` | ok (V11 253952/262144) | ok | ok (V11 253952/262144) | ok |
| `production` | ok (V11 253952/262144) | ok | ok (V11 253952/262144) | ok |

### Time per pairing

| Pairing | Runs | Total | Slowest case |
|---|---|---|---|
| go->rs | 32 | 46 s | `crypt/sm4` at 23.0 s |
| rs->go | 32 | 53 s | `crypt/sm4` at 29.8 s |
| go->go | 32 | 86 s | `crypt/sm4` at 60.8 s |
| rs->rs | 32 | 22 s | `crypt/3des` at 1.2 s |

No failures.

<!-- platform: linux/aarch64 -->
## linux/aarch64 — 2026-09-23 10:07:12Z

**128/128** runs passed.

Workload per run: 20 MB each way on one bulk stream, 100 concurrent streams of 16 KiB each way, and a half-close probe that asks for 256 KiB after `shutdown(SHUT_WR)` (having waited 250ms first, so the answer and the peer's FIN are both buffered) — all SHA-256 verified, with both processes' logs scanned afterwards. The harness adds `-closewait 0` to the server so teardown is not delayed by 30 s per direction; nothing else is added to a case's flags.

### Binaries

| Binary | Path | `-v` | SHA-256 (first 8 bytes) |
|---|---|---|---|
| go client | `/home/ubuntu/kcptun-lab/bin/go/kg-client` | kcptun version SELFBUILD | `806638e1e87542ee` |
| go server | `/home/ubuntu/kcptun-lab/bin/go/kg-server` | kcptun version SELFBUILD | `5b20feb55d0296e7` |
| rs client | `/home/ubuntu/kcptun-lab/bin/rust/kr-client` | kcptun version SELFBUILD | `b03dcf01789826e2` |
| rs server | `/home/ubuntu/kcptun-lab/bin/rust/kr-server` | kcptun version SELFBUILD | `3a94cacc33b01db1` |

### Results

| Case | go->rs | rs->go | go->go | rs->rs |
|---|---|---|---|---|
| `crypt/aes` | ok (V11 135680/262144) | ok | ok (V11 184832/262144) | ok |
| `crypt/aes-128` | ok (V11 240128/262144) | ok | ok (V11 251904/262144) | ok |
| `crypt/aes-192` | ok (V11 201216/262144) | ok | ok (V11 238592/262144) | ok |
| `crypt/aes-128-gcm` | ok (V11 246784/262144) | ok | ok (V11 217600/262144) | ok |
| `crypt/salsa20` | ok (V11 253184/262144) | ok | ok (V11 237568/262144) | ok |
| `crypt/blowfish` | ok (V11 254976/262144) | ok | ok (V11 260096/262144) | ok |
| `crypt/twofish` | ok (V11 254976/262144) | ok | ok (V11 261376/262144) | ok |
| `crypt/cast5` | ok (V11 250368/262144) | ok | ok (V11 254976/262144) | ok |
| `crypt/3des` | ok (V11 258560/262144) | ok | ok (V11 253952/262144) | ok |
| `crypt/tea` | ok (V11 250624/262144) | ok | ok (V11 254976/262144) | ok |
| `crypt/xtea` | ok (V11 251904/262144) | ok | ok (V11 261376/262144) | ok |
| `crypt/xor` | ok (V11 207360/262144) | ok | ok (V11 8192/262144) | ok |
| `crypt/sm4` | ok (V11 258560/262144) | ok | ok (V11 254976/262144) | ok |
| `crypt/none` | ok (V11 254976/262144) | ok | ok (V11 209408/262144) | ok |
| `crypt/null` | ok (V11 209408/262144) | ok | ok (V11 170240/262144) | ok |
| `pair/01` | ok (V11 241152/262144) | ok | ok (V11 204800/262144) | ok |
| `pair/02` | ok (V04+V11 0/262144) | ok | ok (V04+V11 0/262144) | ok |
| `pair/03` | ok (V04+V11 0/262144) | ok | ok (V04+V11 0/262144) | ok |
| `pair/04` | ok (V11 152064/262144) | ok | ok (V11 252160/262144) | ok |
| `pair/05` | ok (V04+V11 0/262144) | ok | ok (V04+V11 0/262144) | ok |
| `pair/06` | ok (V11 71040/262144) | ok | ok (V11 192000/262144) | ok |
| `pair/07` | ok (V11 209408/262144) | ok | ok (V11 178432/262144) | ok |
| `pair/08` | ok (V04+V11 0/262144) | ok | ok (V04+V11 0/262144) | ok |
| `pair/09` | ok (V04+V11 0/262144) | ok | ok (V04+V11 0/262144) | ok |
| `pair/10` | ok (V11 247552/262144) | ok | ok (V11 193024/262144) | ok |
| `pair/11` | ok (V04+V11 0/262144) | ok | ok (V04+V11 0/262144) | ok |
| `pair/12` | ok (V04+V11 0/262144) | ok | ok (V04+V11 0/262144) | ok |
| `pair/13` | ok (V11 255488/262144) | ok | ok (V11 238592/262144) | ok |
| `pair/14` | ok (V04+V11 0/262144) | ok | ok (V04+V11 0/262144) | ok |
| `pair/15` | ok (V04+V11 0/262144) | ok | ok (V04+V11 0/262144) | ok |
| `pair/16` | ok (V11 143872/262144) | ok | ok (V11 229376/262144) | ok |
| `production` | ok (V11 190976/262144) | ok | ok (V11 197632/262144) | ok |

### Time per pairing

| Pairing | Runs | Total | Slowest case |
|---|---|---|---|
| go->rs | 32 | 45 s | `crypt/sm4` at 5.9 s |
| rs->go | 32 | 45 s | `crypt/sm4` at 4.9 s |
| go->go | 32 | 56 s | `crypt/sm4` at 11.7 s |
| rs->rs | 32 | 37 s | `crypt/3des` at 2.9 s |

No failures.

