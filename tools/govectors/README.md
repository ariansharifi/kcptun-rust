# govectors

A Go program that writes the golden test vectors in `testdata/vectors/`. It links the **exact**
library versions of the Go reference (`reference/kcptun/go.mod`): kcp-go v5.6.66, smux v1.5.55,
qpp v1.1.25, snappy v1.0.0, reedsolomon v1.13.0, x/crypto v0.47.0 and their pinned indirect
dependencies. The Rust tests embed these files with `include_str!` and must reproduce them exactly.

## Running

```sh
tools/gen-vectors.sh              # vet + test + build, regenerate everything, show git diff --stat
tools/gen-vectors.sh crypt kcp    # only some areas
tools/gen-vectors.sh --check      # fail if regeneration would change anything (CI); tree untouched
```

The script uses `reference/gomod` as the module cache (`GOMODCACHE`, filled by
`tools/fetch-reference.sh`), `GOTOOLCHAIN=local` and `GOFLAGS=-modcacherw`. The binary itself is
`govectors [-out DIR] all | AREA...` (default `-out testdata/vectors`, relative to the working
directory).

The generator refuses to run if any module in `pinned` (`deps.go`) is linked at a different
version or is replaced. `deps.go` also blank-imports every pinned library so that it is linked even
while its area is still a stub.

## Areas

| Area | File | Filled in by plan step |
|---|---|---|
| `crypt` | `crypt.json` | 02.1 |
| `fec` | `fec.json` | 04.6 |
| `autotune` | `autotune.json` | 04.3 |
| `rs` | `rs.json` | 04.1 |
| `kcp` | `kcp.json` | 03.1, 03.5 |
| `smux` | `smux.json` | 06.1 |
| `snappy` | `snappy.json` | 07.1 |
| `qpp` | `qpp.json` | 07.2 |
| `cli` | `cli.json` | 08.1 |
| `config` | `config.json` | 08.2 |
| `multiport` | `multiport.json` | 08.4 |
| `timefmt` | `timefmt.json` | 08.4 |
| `errno` | `errno.json` | 10.6 |

To fill an area in, replace its stub `gen<Area>` in `areas.go` (or move it to its own
`<area>.go`) with a function returning the cases in file order.

The `config`, `multiport` and `timefmt` areas exercise kcptun's own code (`std.ParseJSONConfig`,
multiport parsing, ...). Because the generator refuses `replace` directives, step 08 must copy the
needed std/client functions verbatim into `internal/` (with a provenance header), the same way
`internal/kcpcopy` is done, rather than importing `github.com/xtaci/kcptun` through a `replace`.

## Area `crypt` (02.1)

Produced by `crypt.go` with kcp-go v5.6.66's exported constructors, driven through
`internal/std/crypt.go`, a verbatim copy of kcptun `std/crypt.go` (`SelectBlockCrypt`; a test
keeps it byte-identical to `reference/kcptun/std/crypt.go`). `internal/std/key.go` holds kcptun's
key derivation (`pbkdf2.Key(key, "kcp-go", 4096, 32, sha1.New)`), `internal/std/keysize.go` reads
the `keySize` column of the copied table. All cases use `Case`; `params` fields are listed in
key order. Byte fields are hex. Two derived passes are used throughout, identified by `pass_id`:
0 = from kcptun's default key `it's a secrect`, 1 = from the fixed key
`q7Vt2mXe9LkR4pZs8WnB1cYh6GdJ3fUa` (`pbkdf2/default` and `pbkdf2/random32`).

| Group (name) | `params` | `in` | `out` |
|---|---|---|---|
| `pbkdf2/<label>` (`default`, `empty`, `a`, `cjk` = `中文密钥`, `k300` = 300×`k`, `random32`) | `key` (string), `salt` `kcp-go`, `iter` 4096, `dklen` 32 | UTF-8 bytes of `key` (absent when empty) | the 32-byte pass |
| `xor_pad/pass_id=<i>` | `pass_id`, `pass` | - | the 1500-byte `xortbl` of `NewSimpleXORBlockCrypt(pass)`, read back by encrypting 1500 zero bytes; the generator checks it equals `PBKDF2-HMAC-SHA1(pass, "sH3CIVoF#rWLtJo6", 32, 1500)` |
| `select/method=<m>` for `m` in `aes aes-128 aes-128-gcm aes-192 salsa20 blowfish twofish cast5 3des tea xtea xor sm4 none null bogus` and `""` (`select/method=`) | `method`, `pass` (pass 0, 32 bytes), `effective` (name returned), `nil` (result is nil: only `null`), `key_len` (bytes of `pass` given to the effective constructor, 0 for `null`), `nonce` (only `aes-128-gcm`), `log` (only when `SelectBlockCrypt` logged, flags off, no newline) | a fixed 64-byte buffer | whole-buffer `Encrypt(in)`; for `aes-128-gcm` `nonce ‖ Seal(nonce, in)`; absent for `null` |
| `select_short/method=<m>` | same, with `pass` = the first 16 bytes of pass 0: exercises the fallback (`3des` fails, logs, and becomes AES-128 over the 16-byte pass) | same | same |
| `cfb/<method>/pass_id=<i>/len=<n>` for `method` in `aes aes-128 aes-192 salsa20 blowfish twofish cast5 3des tea xtea sm4 xor none` and `n` in `20 21 23 24 25 31 32 33 63 64 65 127 128 129 1349 1350 1370 1500` | `method`, `pass_id`, `pass`, `key_len` | whole packet of `n` bytes: fixed 16-byte nonce ‖ 4 zero bytes (crc placeholder) ‖ PCG payload (the same for every method and pass) | `Encrypt(in)` in place, with the cipher built by `SelectBlockCrypt(method, pass)`. `none` is the identity. |
| `aead/pass_id=<i>/len=<n>` for `n` in `0 1 24 1314` | `method` `aes-128-gcm`, `pass_id`, `pass`, `key_len` 16, `nonce` (12 bytes) | the plaintext (absent when empty) | `nonce ‖ Seal(nonce, in)` (no additional data; 16-byte tag), the sess.go packet layout |

The generator refuses to write the file unless, for every cfb and select case, an out-of-place
`Encrypt` gives the same bytes and `Decrypt(out) == in` (in place and out of place); for AEAD cases
`Open` must restore `in`; and each select result is reproduced by rebuilding the effective method
from `pass[:key_len]` via `SelectBlockCrypt` (this confirms the effective method; since
`SelectBlockCrypt` re-slices the key for fixed-size methods, `key_len` itself comes from the
copied `cryptMethods` table). There are no salsa20 inputs shorter than 8 bytes: kcp-go v5.6.66
panics on them (the Rust guard is DECISIONS V01, covered by a unit test instead).

### Benchmarks (02.6, 04.2, 04.7, 07.2)

`bench_test.go` holds three Go benchmark sets, none of them part of vector generation (same
`GOMODCACHE`/`GOFLAGS`/`GOTOOLCHAIN` as above):

- `BenchmarkCrypt/<encrypt|decrypt>/<method>/<len>`, the Go side of `crates/kcp/benches/crypt.rs`:
  every method except `null`, on 1350- and 1500-byte packets, in place and keyed through
  `SelectBlockCrypt` like kcptun. Run `go test -run '^$' -bench Crypt`; methodology and results in
  `docs/benchmarks/crypto.md`.
- `BenchmarkRS/<encode|reconstruct_data>/…`, the Go side of `crates/kcp/benches/rs.rs`: pinned
  klauspost/reedsolomon v1.13.0 at kcptun's (10, 3) shape over 1370-byte shards. Run
  `go test -run '^$' -bench RS`; results in `docs/benchmarks/fec.md`.
- `BenchmarkQPP/<encrypt|decrypt>/<len>`, `…/encrypt/chunked=7`, `…/new/<pads>`, `…/create_prng`,
  the Go side of `crates/qpp/benches/qpp.rs`: the shape of qpp's own `BenchmarkQPP` (64 pads, one
  call per iteration) at the sizes kcptun sees, plus the 7-byte chunking that never lines up with
  the 8-byte pad switch and the two setup costs. Run `go test -run '^$' -bench QPP`; numbers in
  the 07.2 commit message (no `docs/benchmarks/` file, per plan README §4).

`internal/kcpcopy/fec_bench_test.go` is the Go side of `crates/kcp/benches/fec.rs`
(`BenchmarkFEC/<encode|decode>/…`): the copied `fecEncoder`/`fecDecoder` with a fixed clock, one
packet per iteration, with and without one loss per group. Run
`go test ./internal/kcpcopy -run '^$' -bench FEC`; results in `docs/benchmarks/fec.md`.

## Area `kcp` (03.1, 03.5)

Produced by `kcp.go` and `kcptrace.go`. kcp-go does not export its segment codec, `flush()` or
the `KCP` fields, so the generator uses `internal/kcpcopy`: a **verbatim copy** of the KCP core of
kcp-go v5.6.66 (`kcp.go`, `ringbuffer.go`, `bufferpool.go`, `snmp.go`, `kcp_trace_off.go`, still
`package kcp`; import it as `kcpcopy`). Each copied file starts with a provenance header; below
its `// ---- verbatim below ----` marker it is byte-identical to the pinned file, except for **one
line** of `kcp.go`:

```diff
-func currentMs() uint32 { return uint32(time.Since(refTime) / time.Millisecond) }
+func currentMs() uint32 { return Clock() }
```

`TestVerbatimCopy` enforces this (skipped when `reference/` is not fetched); do not edit the
copies, re-copy instead. `internal/kcpcopy/export.go` is not copied: it declares `mtuLimit` (from
`sess.go`), the injectable `Clock` (default: the original expression), and exported wrappers
(`Encode`, `DecodeHeader`, `Itimediff`, `Ibound`, `KCP.Flush`, `KCP.SetStream`, `KCP.ConnState`,
`KCP.StateWords`, `KCP.StateDigest`). The copy has its own `DefaultSnmp`. The `real_ack` group
checks the copy against the library itself. Segment `params` (`segParams`) are the header fields
in wire order: `conv cmd frg wnd ts sn una len`.

| Group (name) | `params` | `in` | `out` |
|---|---|---|---|
| `constants` | every exported `IKCP_*` constant of `kcp.go` (incl. `PacketType`, `FlushType`, log masks) and `RINGBUFFER_MIN`/`RINGBUFFER_EXP`, name → value | - | - |
| `segment/<label>` for `zero max distinct_bytes push_mss_default push_mss_production push_msg_frg ack wask wins`, and `segment/random/<i>` (i < 8, every field random, len 0..64) | `segParams` (`len` = payload length) | the payload (absent when empty) | the 24-byte header written by `segment.encode`. The generator checks that `OutSegs` grew by exactly one and that decoding `out ‖ in` gives the params back. |
| `real_ack/<label>` for `in_order ts_wrap out_of_order two_in_order reordered_pair` | `conv`, `push` (the input segments), `acks` (the output segments), `outputs` (the size of each output callback call), `input_ret` | a packet of PUSH segments (frg 0, wnd 32, una 0) | what a fresh `kcp.NewKCP(conv, …)` outputs from `Input(in, IKCP_PACKET_REGULAR, true)`: ACK segments, decoded and re-encoded with the copy to prove they match |
| `itimediff/<i>`, `itimediff/random/<i>` (i < 16) | `later`, `earlier`, `want` = `_itimediff(later, earlier)` | - | - |
| `ibound/<i>` | `lower`, `middle`, `upper`, `want` = `_ibound_(lower, middle, upper)` | - | - |
| `snmp/zero`, `snmp/distinct` (field i = i+1), `snmp/large` (field i = MaxUint64 − i) | own shape (`snmpCase`): `fields` (struct field names in declaration order), `values`, `header` (`Header()`), `to_slice` (`ToSlice()`), `format` (`fmt.Sprintf("%+v", s.Copy())`) | - | - |

### Group `trace/<config>` (03.5): golden KCP API traces

`kcptrace.go` runs two endpoints `a` and `b` of the copied KCP over a deterministic lossy link and
records every API call of each endpoint with its exact results. The Rust port replays each
endpoint alone, call by call (`crates/kcp/src/kcp/trace_tests.rs`), and must reproduce every
result byte for byte. The driver mirrors `UDPSession` (`sess.go`): writes are split into
mss-sized `Send`s when `WaitSnd() < snd_wnd` and flushed at once, the update timer calls
`flush(IKCP_FLUSH_FULL)` and re-arms after the returned interval (or `Update` + `Check` when
`use_update`), every delivered packet is `Input(data, type, ackNoDelay)`, followed by the reader
(`PeekSize`, `Recv`) and the writer. The link (one PCG, `newRNG("kcp", (1<<20) + i)` for config
`i`) loses, delays, jitters, reorders, duplicates, truncates and FEC-marks packets; malformed
packets are injected where `garbage` is set.

The virtual clock reads `uint32(t0 + now)`; with `clock_step > 0` every `currentMs()` read also
advances it, so the number and position of clock reads are part of the trace.

A case has `name`, `params` (the `traceConfig`: `conv`, `t0`, `clock_step`, `use_update`,
`ping_pong`, `garbage`, `to_dead`, `limit_ms`, per-side `a`/`b` settings and per-direction
`a_to_b`/`b_to_a` link settings), `result` (end time, delivered bytes, packet and drop counts,
whether `a` ended dead), and per endpoint `a` and `b`:

| Key | Meaning |
|---|---|
| `payload_stream` | `Send` payloads are drawn in call order with `randBytes` from `newRNG("kcp", payload_stream)`; a `Send` of `n` bytes draws `n` bytes (none for `n = 0`) |
| `snmp` | increments of `InSegs OutSegs RepeatSegs LostSegs FastRetransSegs EarlyRetransSegs RetransSegs` caused by this endpoint |
| `gauges` | `RingBufferSndQueue`, `RingBufferRcvQueue`, `RingBufferSndBuffer` stored by this endpoint's last `flush()` (any path) |
| `final` | `KCP.StateWords()` at the end, in the order of `kcpcopy.StateWordNames` (`mtu mss state snd_una snd_nxt rcv_nxt ssthresh rx_rttvar rx_srtt rx_rto rx_minrto snd_wnd rcv_wnd rmt_wnd cwnd probe interval ts_flush nodelay updated ts_probe probe_wait dead_link incr fastresend nocwnd stream`, then the lengths of `snd_queue rcv_queue snd_buf rcv_buf acklist`) |
| `ops` | one string per API call, in call order |

An op is space-separated: the call name, then `key=value` tokens. Every op has `t=` (the clock
value when the call starts), `rd=` (the number of clock reads during the call) and `st=` (the
16-hex-digit `KCP.StateDigest()` after the call: FNV-1a 64 over the little-endian `StateWords`,
then per `snd_queue` segment `frg len`, per `snd_buf` segment `sn frg ts wnd una rto xmit
resendts fastack acked len`, per `rcv_queue` segment `sn frg len`, per `rcv_buf` segment in heap
array order `sn frg len`, per ACK list entry `sn ts`). `ret=` is the return value (absent for
calls without one), and each `o=<hex>` token is one output callback call during the call, in
order (`o=` alone is an empty packet).

| Op | Call | Extra tokens |
|---|---|---|
| `setmtu a=<mtu>` | `SetMtu(mtu)` | |
| `nodelay a=<n>,<i>,<r>,<c>` | `NoDelay(n, i, r, c)` | |
| `wndsize a=<s>,<r>` | `WndSize(s, r)` | |
| `stream a=<v>` | `kcp.stream = v` (as `SetStreamMode`) | |
| `send n=<len>` | `Send(next len payload bytes)` | |
| `input src=<op>.<out> [cut=<n>] pt=<t> and=<b>` | `Input(peer.ops[op].o[out][:n], PacketType(t), b == 1)` | |
| `input hex=<bytes> pt=<t> and=<b>` | `Input(bytes, …)` (crafted packet) | |
| `flush ft=<t>` | `flush(FlushType(t))` | |
| `update` / `check` | `Update()` / `Check()` | |
| `recv n=<len>` | `Recv(make([]byte, len))` | `h=` first 8 bytes of the SHA-256 of the received bytes (when `ret > 0`) |
| `peek` / `waitsnd` | `PeekSize()` / `WaitSnd()` | |

The configs cover kcptun's normal/fast/fast2/fast3 no-delay settings, windows 8 to 1024, MTUs
200/400/500/1322/1400, `ackNoDelay`, congestion control on (`nc = 0`), message mode with
fragments and the `Send` -1/-2 and `Recv` -2 cases, `Update`/`Check` with the clock crossing
`2^32`, a clock that advances on every read, zero-window probing, a dead link, FEC-typed,
truncated and malformed inputs, and Go's `TestLossyConn1`/`TestLossyConn4` echo at the ARQ
level. The generator checks that every non-dead trace delivered exactly the bytes sent.

## Area `autotune` (04.3)

Produced by `autotune.go` with `internal/kcpcopy/autotune.go`, a **verbatim copy** of kcp-go
v5.6.66 `autotune.go` (`autoTune` is unexported; `TestVerbatimCopy` checks the copy, with no
changed lines). `export.go` adds `AutoTune` (alias), `Pop` (head++, count--, as
`TestAutoTunePop` does), `Count` and `Sorted` (a copy of `sortCache[:count]`). Every case feeds
its samples to a fresh `autoTune`, pops `pops` times, then calls `FindPeriod(true)` and
`FindPeriod(false)`. The generator checks that both calls leave the same order in `sortCache`.

Case fields (own struct `autotuneCase`): `name`; `samples` (hex, 5 bytes per `Sample` call in
order: seq as u32 little-endian, then the bit as 0/1); `pops` (omitted when 0); `count` (samples in
the ring before `FindPeriod`); `find_true`, `find_false`; `sorted` (`sortCache[:count]` after
`FindPeriod`, same 5-byte layout; omitted when `count < 3`, where `FindPeriod` returns -1 without
sorting). The recorded order is what `sort.Slice` (Go's unstable pdqsort) produces with the
`_itimediff(a.seq, b.seq) < 0` comparison, so the groups include inputs where that order depends on
the algorithm: equal seqids and seqid sets that make the comparison cyclic.

Groups `<group>/<i>` (`i < 8`, samples from `newRNG("autotune", group_index<<16 + i)`), in file
order:

| Group | Samples |
|---|---|
| `periodic` | an FEC stream of random `(ds, ps)` (`ds` 1..16, `ps` 1..8): consecutive seqids wrapping at `paws`, bit = `seq % (ds+ps) < ds`, starting near 0, at random, or just before the `paws` wrap; 3..702 samples |
| `reorder` | `periodic`, with samples swapped with a neighbour up to 8 positions later |
| `loss` | `periodic`, each sample dropped with probability 1/25 |
| `dup` | `periodic`, with duplicated samples (same seqid and bit) inserted nearby |
| `dup_flip` | `periodic`, with inserted samples that repeat a seqid with the opposite bit (ties whose order changes the result) |
| `random` | uniformly random seqids and bits (the comparison is cyclic) |
| `narrow` | seqids from a range of 1, 2, 3, 8, 32 or 128 values (many ties), random bits |
| `descending` | `periodic`, reversed (pdqsort's decreasing hint) |
| `nearly_sorted` | `periodic` of 50+ samples with up to 6 distant swaps (partial insertion sort) |
| `sawtooth` | seqid patterns `base + i % m`, or organ pipes, bit = `seq % 3 != 0` (pattern breaking) |
| `wide` | `periodic` with up to 4 seqids moved about 2^31 away |
| `killer` | 100..258 distinct seqids in an order produced by McIlroy's killer adversary against `sort.Slice` itself (`sortKiller`), bit = `seq % 4 != 0`: forces pdqsort's heapsort fallback |
| `pop` | `periodic`, then up to `min(n, 258)` pops |

The Rust test (`crates/kcp/src/autotune/tests.rs`, `vectors_autotune`) also checks that these
cases reach every rare path of its `sort.Slice` port (heapsort, pattern breaking, decreasing
hint, equal partitioning, partial insertion sort).

## Area `rs` (04.1)

Produced by `rs.go` with klauspost/reedsolomon v1.13.0 exactly as kcp-go calls it:
`reedsolomon.New(ds, ps)` with default options (for `ds+ps <= 256` the `buildMatrix` code:
`vandermonde(total, ds) x inverse(top ds x ds)` over GF(2^8), polynomial 0x11D). Only the exported
API is used. `(ds, ps)` configs, in order: `(1,1) (2,1) (3,2) (4,4) (10,3) (20,5) (30,10) (70,30)
(128,128) (200,56)`; shard lengths `1 17 64 1370 1500`.

**Byte fields, full or hashed.** A byte string of at most 4096 bytes is stored in full as hex under
its key (`parity_rows`, `parity`, `out`); a longer one is stored as a `Blob` (length, SHA-256,
first/last 16 bytes) under `<key>_blob` instead. An empty byte string is omitted (`omitempty`).
This keeps `rs.json` at about 380 KB. With the current configs the hashed fields are: `parity`
of every config from `(4,4)` up at shard lengths 1370 and 1500, plus `(128,128)` at 64;
`parity_rows` of `(128,128)` and `(200,56)`; and `out` of the reconstruct cases that recover more
than 4096 bytes (31 of 200, all at 1370/1500 bytes or `(128,128)` at 64). Everything else is in
full.

| Group (name) | Fields | Meaning |
|---|---|---|
| `galois` | `exp`, `log`, `inv` (hex, 256 bytes each), `mul_table` (Blob of 65536 bytes), `mul_row_2` (hex) | `exp[i] = 2^i` (so `exp[255] = 1`), `log[x]` with `log[0] = 0`, `inv = Inv(x)` (`Inv(0) = 0`), `mul_table[a*256+b] = a*b` read with `LowLevel.GalMulSlice` (also checked against `GalMulSliceXor`). `TestRsGaloisMatchesLiteralTables` checks `exp`/`log`/`inv` equal the `expTable`/`logTable`/`invTable` literals of the pinned `galois.go` (skipped without `reference/`). |
| `matrix/ds=D,ps=P` | `ds`, `ps`, `parity_rows` | rows `ds..ds+ps` of the encoding matrix, row-major (`ps*ds` bytes), read back through `Encode` with data shard `j` = unit vector `e_j` |
| `encode/ds=D,ps=P/len=N` | `ds`, `ps`, `len`, `stream`, `data_sha256`, `parity` | data shard `i` is bytes `[i*len, (i+1)*len)` of `randBytes(newRNG("rs", stream), ds*len)` (`stream = 1<<16 + config_index<<12 + len`); `parity` is the concatenation of the `ps` parity shards from `Encode` (the generator also runs `Verify`) |
| `reconstruct/ds=D,ps=P/len=N/<pattern>` | `ds`, `ps`, `len`, `stream`, `missing`, `recovered`, `out` | the encode case's full shard set with the `missing` shard indices set to `nil`, then `ReconstructData`; `recovered` lists the data shards it filled in (the missing ones below `ds`), `out` is their concatenation. The generator checks the recovered shards equal the originals, missing parity shards stay `nil` and present shards are untouched. |
| `error/<label>` | `op` (`new`, `encode`, `reconstruct_data`), `ds`, `ps`, `shard_lens` (0 = `nil`), `err` (`""` = success), `impl` (`new` only: `%T` of the Encoder) | New/Encode/ReconstructData on invalid or borderline input; `new_257` and `new_1_256` show that above 256 shards `New` returns a Leopard GF(2^16) codec (`*reedsolomon.leopardFF16`), not `ErrMaxShardNum` |

The four erasure patterns per config (drawn once per config from `newRNG("rs", 1 + config_index)`
and used for every shard length; at most `ps` shards missing): `first_data` (shard 0 plus `ps-1`
random others, data or parity), `all_parity` (every parity shard: `ReconstructData` has nothing to
do), `data_max` (`min(ds, ps)` random data shards), `mixed` (`k` in `[1, ps]` random shards with at
least one data shard and, for `k >= 2`, at least one parity shard).

## Area `fec` (04.6)

Produced by `fec.go` with `internal/kcpcopy/fec.go`, a **verbatim copy** of kcp-go v5.6.66
`fec.go` (`fecEncoder`/`fecDecoder` are unexported) and the pinned klauspost/reedsolomon v1.13.0.
The only change, enforced by `TestVerbatimCopy`, is the encoder's clock read:

```diff
-	now := time.Now().UnixMilli()
+	now := FecClock(time.Now)
```

`FecClock` (in `export.go`, default `now().UnixMilli()`) is replaced by scripted times. The copy
keeps `tsLatestPacket = 0`, so with times near 1758000000000 the first comparison always sees a
huge gap (the `ds == 1` first-group quirk). `export.go` adds `FecEncoder`/`FecDecoder`
(aliases), `NewFECEncoder`, `NewFECDecoder`, `Encode`, `EncodeOOB`, `Next`, `SetNext`, `Paws`,
`Decode`, `Shards` (current `(ds, ps)`) and `ShardSets`. Every encoder uses rto 500
(`maxFECEncodeLatency`). The decoder always gets the packet from the FEC header on (the crypto
header room `[0, offset)` removed, as `sess.go` does). The file is about 560 KB.

Cases, in order (own case structs; all names are unique):

**`encoder/<config>`** for `ds=10,ps=3,off=20` (60 calls), `ds=3,ps=2,off=12` (51 calls plus 3
`encodeOOB` calls), `ds=1,ps=1,off=0` (50 calls) and `ds=4,ps=2,off=8,wrap` (24 calls, starting
three groups before `paws`). Fields: `ds`, `ps`, `offset`, `rto`, `next` (initial seqid set with
`SetNext`, omitted when 0), `paws`, `payload_stream`, `packets`. The input of call `i` is the next
`packets[i].len` bytes of `randBytes(newRNG("fec", payload_stream), sum of all len)` (the crypto
header room and FEC header bytes are random too, so the test sees exactly what the encoder
writes). Per call: `len`, `now` (the `FecClock` value; absent for OOB calls), `oob` (true for
`encodeOOB`), `out` (the whole packet after the call, hex) and `parity` (the parity shards
returned, each `maxSize` bytes including the zeroed room before `offset`; absent when none).
Lengths are KCP-sized (ACK-only, MTU-sized up to exactly 1500, or random; one packet of only
`offset + 8` bytes in the first three configs). Clock deltas are 0..300 ms, with scripted gaps: 499 and 500 ms and
larger gaps before a group's last packet (parity emitted / skipped), long gaps inside a group
(no effect), and negative deltas (a clock going backwards: `now - tsLatestPacket < rto`, parity
emitted). The generator checks which groups skip their parity, that no parity appears mid-group,
that `encodeOOB` does not change `next`, and verifies every complete group with
`reedsolomon.Verify`.

**`decoder/<config>/<pattern>`**: the wire stream of encoder case `stream` (per call: the data or
OOB packet, then its parity shards; the decoder input is `packet[offset:]`) fed to a fresh
`newFECDecoder(ds, ps)` in the order given by `feed`: space-separated tokens, `i` = stream packet
`i`, `i:n` = its first `n` bytes (a truncated copy, `n >= 6`), `cK` = `crafted[K]` (hex). OOB
packets are never fed (the session does not pass them to the decoder). Patterns (random choices
from `newRNG("fec", 3<<16 + 64*config + pattern)`):

| Pattern | Feed |
|---|---|
| `clean` | every packet in order |
| `drop1` | one random data packet lost per group |
| `drop_ps` | `ps` random packets (data or parity) lost per group |
| `drop_ps_data` | `ps` random data packets lost per group |
| `drop_ps1` | `ps + 1` random packets lost per group (unrecoverable; not for `ds == 1`) |
| `parity_lost` | every parity packet lost |
| `dup` | `drop1`, plus copies of packets a few positions later and some much later (after their group was decoded, so they are stored again) |
| `reorder` | one random packet lost per group, local swaps, and 3 packets delayed by about 5 groups (past the discard horizon) |
| `mixed` | random loss (1/8), duplicates and swaps |
| `mistyped` | `clean` with a data packet of the third group and a parity packet of the fifth replaced by short packets of the same seqid with the parity (resp. type 0) flag: `FindPeriod` finds the current `(ds, ps)` and decoding goes on; then the first data packet of the last group is repeated with the parity flag, whose duplicate seqid makes `FindPeriod` fail, so the decoder stays out of sync and drops the rest |
| `garbage` | `drop1` with truncated copies (some replacing the packet), crafted packets at random positions (OOB, seqid `== paws`, seqid `0xFFFFFFFF`, size field too large / too small), and at the end a new group of `ds` header-only packets whose reconstruction fails (`FECErrs`); not for `ds == 1` |

Results: `recovered` (one string per recovered shard, in order: `call len sha256`, `call` being
the 0-based index of the `feed` token), `tunes` (`call ds ps` whenever `Shards()` changed after a
call; absent when never), `counters` (the copy's `DefaultSnmp` FEC fields after the case,
`Reset()` before it: counters `fec_parity_shards`, `fec_full_shard_set`, `fec_recovered`,
`fec_errs`, gauges `fec_shard_set`, `fec_shard_min`), `final_ds`, `final_ps` and `shard_sets`
(`len(shardSet)`). For all patterns but `garbage` the generator checks that every recovered
shard is a data shard of the stream, zero-padded, and that the decoder never retunes.

**`autotune/<name>`**: the stream comes from `phases` instead of an encoder case: each phase is a
fresh `newFECEncoder(ds, ps, 0)` with `SetNext(next)`, encoding one packet per entry of `lens`
(space-separated) at `start + i*step`, with bytes from `randBytes(newRNG("fec", payload_stream),
sum of lens)`; the stream is the concatenation of all phases' output. `stream_sha256` is the
SHA-256 over every packet as `u16 LE length || bytes`, so a consumer that rebuilds the stream
with its own encoder can check it. The decoder is `newFECDecoder(ds, ps)`; the other fields are
those of the decoder cases. Cases: `switch_continue` ((10,3) for 60 packets, then (5,2) for 230
with seqids continuing from the next multiple of 7), `switch_restart` (the (5,2) sender restarts
at seqid 0), `mismatch_start` (decoder (5,2), sender (10,3)), `switch_back` ((10,3) -> (5,2) ->
(10,3)), each with one data packet lost per group except while the decoder has to find the new
period, and `switch_mixed` (random loss, duplicates and swaps throughout). `FindPeriod` only
succeeds on a gap-free run of seqids at the start of its sorted 258-sample ring, so a switch is
detected only once enough packets of the new sender arrived without loss; `switch_mixed` shows
the decoder staying out of sync meanwhile.

`fec_test.go` also recomputes the SHA-1 stream digests hard-coded in the Rust test
`fec::tests::stream_digest_matches_go_copy` from the copy.

## Area `smux` (06.1)

Produced by `smux.go` with xtaci/smux v1.5.55. `frame.go` (`rawHeader`, `newFrame`, `updHeader`)
and the session constants are unexported, so no frame is built by the generator: frames are
**captured from real sessions** driven through the exported API. The capture conn deliberately
does not implement `WriteBuffers`, so `sendLoop` takes the `copy(buf[headerSize:], ...)` branch
and every `Write` call carries exactly one complete frame (header + payload). Each captured frame
is checked against the expected version, command, stream id and length before it is recorded, so
a vector can never describe something the library did not write.

| Group (name) | Fields | Meaning |
|---|---|---|
| `errors` | `params`: `ErrInvalidProtocol`, `ErrConsumed`, `ErrGoAway`, `ErrTimeout` (+ `.Timeout`, `.Temporary`), `ErrWouldBlock`, `io.EOF`, `io.ErrClosedPipe` | the exact error texts of `session.go`, which the Rust `Error` enum must reproduce (porting guide §4) |
| `config/default` | `config`, `err` | `smux.DefaultConfig()` field by field (durations in nanoseconds), and that it verifies |
| `config/verify/<label>` | `config`, `err` | one `smux.VerifyConfig` call per branch, `err` = `""` when accepted. Notable: a **negative** `KeepAliveInterval` is accepted (`keepalive()` then panics in `time.NewTicker`), and `max stream buffer cannot be larger than 2147483647` is unreachable because the receive-buffer check fires first (`stream_buffer=maxint32+1` shows which error actually comes out) |
| `frame/v<V>/<cmd>/...` | `ver`, `cmd`, `sid`, `len`, `out` or `out_blob`, plus `payload_stream` (PSH) and `consumed`/`window` (UPD) | the wire bytes of one frame. `syn`/`fin` come from `OpenStream`/`Close` on a client session (client ids start at 1 and add 2 before use, so `sid` is 3), `psh` from `Write`, `nop` from a session with a 20 ms keepalive interval. `frame/v2/upd/*` and `frame/v2/fin/sid=4294967293` come from a **server** session that is fed a `SYN` and one 4096-byte `PSH` for a stream id near the `uint32` wrap: the first read answers with `UPD(consumed=1, window=MaxStreamBuffer)` (initial read), and the read that pushes `incr` to `MaxStreamBuffer/2` with `UPD(consumed=2049, ...)`. Fed frames are inputs only, never vectors |
| `flow/v2/initial_peer_window` | `ver`, `max_frame_size`, `written`, `lens`, `total` | a v2 writer handed 327675 bytes whose peer never reads: it emits `4 x 65535 + 4` bytes and then blocks, which pins the unexported `initialPeerWindow = 262144` |

PSH payloads are `randBytes(newRNG("smux", 1<<16 + len), len)`, recorded as `payload_stream`. A
frame longer than 4096 bytes is stored as a `Blob` under `out_blob` instead of `out` (the 65535-byte
PSH), and the Rust test regenerates its payload from `payload_stream`.

## Area `snappy` (07.1)

Produced by `snappy.go` with golang/snappy v1.0.0. kcptun's `CompStream.Write` is one
`snappy.Writer.Write` plus one `Flush` per call, so `snappyFrame` repeats exactly those two calls
per write against the pinned library: the generator may not import kcptun (no `replace`
directives), and nothing about the framing is reimplemented: the bytes come from the library.
Every `write/*` case is also read back with `snappy.NewReader` before it becomes a vector, and
every `error/*` case must really fail, so no vector can describe something the library does not
do.

| Group (name) | Fields | Meaning |
|---|---|---|
| `write/<kind>/len=<n>`, `write/sequence/<kind>` | `kind`, `stream`, `writes`, `len`, `in` or `in_blob`, `out` or `out_blob` | one scripted sequence of `CompStream.Write` calls (`writes` holds the length of each) and the framed bytes it puts on the connection. `write/empty` is a single empty write, which produces **no bytes at all**, not even the stream identifier, which Go's buffered writer only emits with the first chunk. 8200 bytes is one smux frame (8192 payload plus the 8-byte header) and 70000 spans two 64 KiB chunks |
| `read/<what>` | `in`, `out`, `err` (`""`) | a framed stream the reader accepts: both data chunk types, empty bodies, skippable chunks (0x80, 0xfd), padding (0xfe), a repeated stream identifier, and a block whose length header is a **padded, non-canonical varint** of five and six bytes (`binary.Uvarint` reads up to ten, so Go accepts them, a decoder that insists on the shortest encoding would not) |
| `error/<what>` | `in`, `out`, `err` | a framed stream the reader rejects, with the bytes it delivered first and Go's error text (`snappy: corrupt input` or `snappy: unsupported input`). Covers the identifier-first rule, a reserved unskippable chunk type, a chunk longer than the reader's buffer, bodies that are too short or too long, flipped checksums, truncation and four malformed blocks |

Payloads are built from `kind`: `text` cycles `"the quick brown fox jumps over the lazy dog. "`,
`random` is `randBytes(newRNG("snappy", stream), len)` (one stream per payload length, recorded as
`stream`) and `zeros` is a run of `0x00`. The Rust test rebuilds the payload from those fields and
checks it against `in`/`in_blob` before comparing the framed output, so a divergence in the
payload cannot be mistaken for a divergence in the framing. Byte strings longer than 4096 bytes
are stored as a `Blob`.

## Area `qpp` (07.2)

Produced by `qpp.go` with xtaci/qpp v1.1.25. `seedToChunks`, the pad tables and the PRNG state
are unexported, so the cases come from `internal/qppcopy`, a verbatim copy of `qpp.go` and
`prng.go` with an export file beside it (the same arrangement as `internal/kcpcopy`).
`internal/qppcopy/copy_test.go` checks the copied files against the pinned source and the
copy's behaviour against the linked `github.com/xtaci/qpp`: same minimum sizes, and the same
ciphertext for four seeds, five pad counts and six chunkings, so a vector cannot describe
anything the real library does not do. Every `pads/*` case is checked to be a permutation with
`rpads` its inverse, and every `stream/*` case is decrypted again, before it becomes a vector.

| Group (name) | Fields | Meaning |
|---|---|---|
| `minimum/qubits=<n>` | `qubits`, `seed_len`, `minimum_pads` | `QPPMinimumSeedLength(n)` and `QPPMinimumPads(n)` for 1..15 qubits, the range Go's own `TestQPPMinimumSeedLength` prints. Only 8 qubits is used in practice: 211 bytes and 7 pads |
| `chunks/<seed>` | `seed` or `seed_stream`, `seed_len`, `expanded`, `chunks`, `out` | `seedToChunks(seed, 8)`: seven 32-byte chunks, concatenated in `out`. `expanded` marks a seed shorter than 32 bytes, which is PBKDF2-expanded first, after which `seedIdx` reads the same 32 bytes for every chunk, so all seven come out identical. The 300-byte seed is the case where `seedIdx` wraps mid-chunk |
| `pads/num_pads=<n>` | `seed`, `num_pads`, `pad0`, `pads`, `rpads` | the permutation matrices for 1, 7, 61 and 101 pads, as `Blob`s, with the first one in full. The pad id goes into the HMAC message in binary (`QPP_%b`), so the counts span several id widths |
| `prng/<create\|fast>/<seed>` | `ctor`, `seed` or `seed_stream`, `seed_len`, `xoshiro`, `seed64`, `count`, `outputs` | the generator `CreatePRNG`/`FastPRNG` produces, and its next 16 outputs |
| `stream/<chunking>` | `seed`, `num_pads`, `chunk`, `chunk_stream`, `plain_stream`, `plain`, `out`, `rand_after` | 1 MiB encrypted with 61 pads in pieces of `chunk` bytes (0: one call, -1: random 1..4096 from `newRNG("qpp", chunk_stream)`), plus the generator's state afterwards. The transform is position-based, so all four chunkings give the same ciphertext, which is the point of the group |

Seeds are either a fixed string (`seed`, as hex) or `randBytes(newRNG("qpp", seed_stream),
seed_len)`; the 1 MiB plaintext is `randBytes(newRNG("qpp", plain_stream), 1<<20)`. Byte strings
longer than 4096 bytes are stored as a `Blob`.

## File format

```json
{
  "generator": "govectors",
  "go": "go1.27.1",
  "modules": {
    "github.com/xtaci/kcp-go/v5": "v5.6.66",
    "...": "..."
  },
  "area": "crypt",
  "cases": [
    { "name": "aes/len=21", "params": { "...": "..." }, "in": "hex", "out": "hex" }
  ]
}
```

| Key | Meaning |
|---|---|
| `generator` | Always `govectors`. |
| `go` | Go toolchain that produced the file (`runtime.Version()`). |
| `modules` | Every module linked into the generator, path → version, from `debug.ReadBuildInfo`. |
| `area` | The area name, equal to the file's base name. |
| `cases` | Array of cases, never `null` (`[]` while an area is a stub). |

A case is normally a `Case` (`vecio.go`):

| Key | Meaning |
|---|---|
| `name` | Required, unique within the file; `/`-separated, e.g. `aes/len=21`. Tests report failures by it. |
| `params` | Optional object with the inputs that are not bytes (key, sizes, flags). |
| `in`, `out` | Optional byte strings as lower-case hex. |

Areas may use their own case struct when one input/output pair is not enough; it must still have a
unique `name` (implement `CaseName()` so the generator checks it). Large byte strings (QPP pads,
long streams) are stored as a `Blob`: `{"len", "sha256", "head", "tail"}` with the SHA-256 of all
bytes and hex of the first and last 16 bytes. Keep each file under 1 MB.

## Area `cli` (08.1)

Command-line parsing and help rendering, as urfave/cli v1.22.17 does it on top of Go's `flag`
package (`cli.go`). Every case is one `cli.App.Run` with a recorded environment and `os.Args`.

The first case, `app`, carries the flag table all the other cases are parsed against (a
representative subset of kcptun's client table: strings with and without a default, aliases
written with and without a space, an `EnvVar` flag, ints, bools, hidden flags and a one-letter
name) and, because its argv is `-h`, the rendered help. The Rust side builds its `App` from that
definition, so the two tables cannot drift. `HelpName` is fixed to `PROGRAM` (urfave would use
`filepath.Base(os.Args[0])`, i.e. the generator binary).

| Key | Meaning |
|---|---|
| `app` | Only in case `app`: `name`, `help_name`, `usage`, `version` and the `flags` table (`name`, `kind`, `value`, `usage`, `env`, `hidden`) |
| `env` | Environment variables set around `App.Run` |
| `args` | `os.Args`, including `argv[0]` |
| `stdout` | What `App.Writer` received: help, version, `Incorrect Usage. <err>` + help, `Cannot use two forms ...` + help |
| `stderr` | What `cli.ErrWriter` received (`ExitCoder` errors, e.g. an unknown help topic) |
| `err` | `App.Run`'s error text |
| `exit` | The code passed to `cli.OsExiter`, when it was called |
| `action` | Whether the app action ran |
| `values` | Flag name (aliases included) → `Context.String/Int/Bool` |
| `set` | Names for which `Context.IsSet` is true, in table order |
| `rest` | `Context.Args()` |

Case groups: `syntax/*` (`-`/`--`, `=` or space, bad syntax, case sensitivity), `int/*` (base-0
decimal, octal, hex, binary, underscores, signs, range and parse errors, `%q` quoting of the
offending value), `bool/*` (`strconv.ParseBool` forms, bare `-flag`, the "`-nocomp false`
stops parsing" trap), `stop/*` (first non-flag, lone `-`, `--`), `error/*` (unknown flags,
missing values), `alias/*` (including `Cannot use two forms of the same flag`), `hidden/*`,
`env/*` (default, override, empty value), `help/*`, `version/*`, `empty/*`.

### Encoding rules (determinism)

- Two-space indent, no HTML escaping, a trailing newline. Struct fields keep their declared order;
  map keys are sorted (`encoding/json`).
- No timestamps, host names or paths. Time values that matter are fixed or injected.
- The only randomness is `newRNG(area, stream)`: a `math/rand/v2` PCG seeded with the FNV-1a-64
  hash of `govectors/<area>` and `stream`. Bytes come from `randBytes` (little-endian `Uint64`s).
  Use a separate stream per independent group of cases so that adding one case does not change
  the bytes of the others. `TestNewRNGIsPinned` pins the sequence.
- Re-running produces byte-identical files; `go test` (`TestGenerateDeterministic`) and
  `tools/gen-vectors.sh --check` verify it. The `go` field changes with the toolchain, so the
  check expects the Go version recorded in the files.

## Area `multiport` (08.4)

The two address parsers kcptun runs before it opens a socket (`multiport.go`), each over its own
address table:

- `std.ParseMultiPort` (`internal/std/multiport.go`, a verbatim copy of kcptun's
  `std/multiport.go`, regexp and error texts included) for `-remoteaddr` / `-listen`;
- Go's `net.SplitHostPort`, whose *failure* is how `client/main.go:319` and `server/main.go:449`
  decide that `-l` / `-t` names a unix socket rather than a TCP address.

| Key | Meaning |
|---|---|
| `func` | `ParseMultiPort` or `SplitHostPort` |
| `addr` | The address that was passed in |
| `ok` | Whether the call succeeded |
| `host`, `minport`, `maxport` | The `*MultiPort` fields (`ParseMultiPort`, on success) |
| `host`, `port` | The two results (`SplitHostPort`, on success) |
| `err` | The error text, as `log.Println` would print it |

Case groups: `parse/<addr>` and `splithostport/<addr>`. The addresses pin the quirks down:
the greedy unanchored `(.*)\:([0-9]{1,5})-?([0-9]{1,5})?` (`host:80:90` → host `host:80`,
`junk a:1-2` → host `junk a`, trailing junk ignored), the five-digit cap (`host:123456` → 12345
and 6), the range check, and every branch of `SplitHostPort`, brackets and all.

## Area `timefmt` (08.4)

`time.Time.Format` with Go's reference layouts (`timefmt.go`), which kcptun applies to the
user-supplied `-snmplog` file name (`std/snmp.go:56`).

| Key | Meaning |
|---|---|
| `layout` | The reference layout |
| `unix`, `nanos` | The instant |
| `zone`, `offset` | The zone's abbreviation (`""` for an unnamed zone) and its offset east of UTC in seconds |
| `out` | What `Format` returned |

Case names are `<instant>/<zone>/<layout>`. Six instants (`t0`..`t5`: afternoon, Go's own
reference time, midnight, noon on a leap day, the last second of a year, year 6) meet four fixed
zones (`utc`, `mst` = -07:00, `noname` = +05:30 without an abbreviation, `lmt` = +01:03:01).
All layouts are rendered at `t0` in `utc` and `mst`; the zone-dependent ones also in `noname` and
`lmt`, and the calendar-dependent ones at the other instants in `mst`. The layouts cover every
token of `nextStdChunk`, the `time` package's layout constants, kcptun-shaped file names and the
scanner's quirks (`Month` and `Janx` are literals, `_2006` is an underscore plus a year, `.0001`
is `.00` plus a zero-padded month, `snmp-pm.log` becomes `snmp-am.log`).

## Area `errno` (10.6)

Go's `syscall` error table (DECISIONS **D30**), read by `errno.go` straight out of the Go
distribution's own generated files (`$GOROOT/src/syscall/zerrors_<goos>_<goarch>.go`,
`var errors = [...]string{}`), not out of a pinned module, which is why this is the one area
whose input is the toolchain rather than `vendor/`. `tools/gen-vectors.sh` exports `GOROOT`
for it, because `go build -trimpath` strips the compiled-in one.

Go never calls `strerror(3)`: it renders every `syscall.Errno` from that table and falls back to
`"errno " + itoa(n)` for an index the table leaves empty. Borrowing the C library's message
instead is only right by coincidence: a static musl build's `strerror` spells `EADDRINUSE`
`Address in use` where glibc's spells it `Address already in use`, and Go's own table entry is
the lower-case `address already in use`, so `kcptun_kcp::goerrno` carries the table and
`tools/gen-errno-table.py` reshapes this file into `crates/kcp/src/goerrno/table.rs`.

One case per GOOS/GOARCH, named `<goos>/<goarch>`, for the platforms of DECISIONS D22:
`linux/{amd64,386,arm64,arm}`, `darwin/{amd64,arm64}` and `freebsd/amd64`.

| Key | Meaning |
|---|---|
| `goos`, `goarch` | The platform |
| `source` | The file in the Go distribution the table was read from |
| `errors` | Go's `errors` array: index == errno, `""` where Go's own table is empty |
| `probes` | `syscall.Errno(errno).Error()` at the ends of the table and past them, including the numeric fallback |

The generator refuses to write the file unless the table it parsed for the **host** platform
reproduces the linked Go runtime's own `syscall.Errno(n).Error()` for every `n` up to 64 past
the end of the table: the parser is checked against the real thing on the one platform where
that is possible, and every other target comes out of the same generated files by the same
parser. The Rust side is checked by `kcptun_kcp::goerrno::tests::vectors_errno_tables`, which
compares *every* platform's table, not only the host's.
