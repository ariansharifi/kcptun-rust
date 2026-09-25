# gointerop

Small Go programs that each expose **one** kcptun layer, so every Rust layer can be tested
against real Go code before the full client/server binaries exist (plan step 01.3). They link
the **exact** library versions of the Go reference (`reference/kcptun/go.mod`): kcp-go v5.6.66,
smux v1.5.55, qpp v1.1.25, snappy v1.0.0, x/crypto v0.47.0 and their pinned indirect
dependencies. Each program checks this at startup (`internal/peer.CheckPinned`) and exits with
status 3 if a pinned module is linked at another version or replaced.

| Program | Layer | Modes |
|---|---|---|
| `kcpecho` | raw kcp-go `UDPSession` (FEC + crypt, no smux) | `server`, `client` |
| `smuxecho` | smux over plain TCP | `server`, `client` |
| `snappycheck` | snappy framing as used by kcptun's `CompStream` | `decode`, `encode` |
| `qppcheck` | Quantum Permutation Pads as used by kcptun's `QPPPort` | `encrypt`, `decrypt`, `pads` |

## Building

`tools/fetch-reference.sh` builds every `cmd/<name>` into
`reference/bin/<name>_<os>_<arch>` for darwin/arm64, linux/arm64 and linux/amd64 (step 5 of the
script). By hand:

```sh
cd tools/gointerop
export GOMODCACHE="$PWD/../../reference/gomod" GOFLAGS=-modcacherw GOTOOLCHAIN=local
go vet ./... && go test ./...
go build -o bin/ ./cmd/...        # bin/ is gitignored
```

## Code copied from kcptun

`internal/std` holds **verbatim** copies of kcptun `std/crypt.go` (`SelectBlockCrypt`),
`std/smuxcfg.go` (`BuildSmuxConfig`) and `std/comp.go` (`CompStream`), MIT, from
kcptun v0.0.0-20260208051026-39935d5307f0. Only a provenance comment is prepended; the license
header and `package std` are unchanged, and `TestVerbatimCopies` fails if a copy drifts from
`reference/kcptun/std/`. `internal/std/key.go` adds kcptun's key derivation
(`pbkdf2.Key(key, "kcp-go", 4096, 32, sha1.New)`, from client/server `main.go`), so crypt names
and keys behave exactly like kcptun, including the fallback to `aes` for unknown names.

## The deterministic stream

The echo clients send `internal/peer.Stream`: Go `math/rand/v2` `rand.NewPCG(seed, 0)`, eight
little-endian bytes per `Uint64`, truncated to the length. This is the same stream as the Rust
testkit's `PrngStream` (`crates/testkit/src/servers.rs`), so Rust tests can compute the expected
SHA-256 with `PrngStream::sha256_hex(seed, len)`. `TestStreamMatchesTestkitPinnedHash` pins the
hash that `crates/testkit/src/rng.rs` pins too.

## Output conventions

- Servers print `listening on: <addr>` on stdout once bound (the Rust `testkit::proc` waits for
  this line) and log to stderr. Use port 0 or a port >= 20000 in tests.
- Clients and the check modes print **one JSON line** on stdout.
- Exit status: 0 success; 1 verification, timeout, decode or I/O error; 2 bad usage (unknown
  mode or flag, invalid value); 3 pinned-version mismatch.

## kcpecho

```sh
kcpecho server -listen 127.0.0.1:20000 -crypt aes -key secret -ds 10 -ps 3
kcpecho client -remote 127.0.0.1:20000 -crypt aes -key secret -ds 10 -ps 3 -bytes 5242880 -seed 9
```

KCP flags (both modes, kcptun's names and defaults): `-crypt aes`, `-key "it's a secrect"`,
`-ds 10`, `-ps 3`, `-mtu 1350`, `-sndwnd`/`-rcvwnd` (client 128/512, server 1024/1024, as in
kcptun), `-nodelay 0 -interval 30 -resend 2 -nc 1` (kcptun's default `fast` mode),
`-acknodelay false`, `-stream true`, `-writedelay false`, `-dscp 0`, `-sockbuf 4194304`,
`-ratelimit 0`. kcptun hard-codes stream mode on and write delay off; `-stream` and
`-writedelay` exist to test the other settings.

Options are applied in kcptun's order. Client (`client/main.go:createConn`): SetStreamMode,
SetWriteDelay, SetNoDelay, SetWindowSize, SetMtu, SetACKNoDelay, SetRateLimit, SetDSCP,
SetReadBuffer, SetWriteBuffer. Server (`server/main.go:serveListener`): SetDSCP, SetReadBuffer,
SetWriteBuffer on the listener, then per session SetStreamMode, SetWriteDelay, SetNoDelay,
SetMtu, SetWindowSize, SetACKNoDelay, SetRateLimit.

- `server`: `-listen` (default `127.0.0.1:0`), `-idle 60`. Echoes every session: each `Read` is
  written back with one `Write`. KCP has no close handshake, so a session is closed after
  `-idle` seconds without data (0 disables).
- `client`: `-remote`, `-bytes 1048576`, `-seed 1`, `-chunk 32768` (bytes per `Write`),
  `-timeout 60` (seconds, overall deadline, 0 none). Sends the stream, reads the echo
  concurrently and verifies it byte by byte:

  ```json
  {"ok":true,"bytes":5242880,"received":5242880,"duration_ms":90,"sha256":"c5e7…","expected_sha256":"c5e7…",
   "crypt":"aes","mismatch_offset":-1,"snmp":{"BytesSent":5242880,"BytesReceived":5242880,…,"OOBPackets":0}}
  ```

  `sha256` hashes the received echo; `crypt` is the effective cipher after kcptun's fallback;
  `snmp` is `kcp.DefaultSnmp` with Go's field names; `error` is present on failure (Go's text,
  e.g. `read: timeout`).

## smuxecho

```sh
smuxecho server -listen 127.0.0.1:20001 -ver 1
smuxecho client -remote 127.0.0.1:20001 -ver 1 -streams 8 -bytes 3000000 -seed 5
```

smux flags (kcptun's defaults): `-ver 2`, `-smuxbuf 4194304`, `-streambuf 2097152`,
`-framesize 8192`, `-keepalive 10` (seconds). The config comes from kcptun's
`BuildSmuxConfig`, so invalid values fail with smux's `VerifyConfig` text (exit 2).

- `server`: `-listen`. Runs `smux.Server` per TCP connection and echoes each stream with
  kcptun's half-close order (`std.Pipe`): copy until the peer's FIN, `CloseWrite`, `Close`.
- `client`: `-remote`, `-streams 4`, `-bytes 1048576` (per stream), `-seed 1` (stream *i* uses
  `seed + i`), `-chunk 32768`, `-timeout 60`, `-early-closewrite false`. Opens the streams
  concurrently on one session, sends, `CloseWrite`s, reads the echo up to EOF and verifies it:

  ```json
  {"ok":true,"ver":1,"streams":8,"bytes_per_stream":3000000,"total_bytes":24000000,"duration_ms":26,
   "results":[{"index":0,"id":3,"seed":5,"received":3000000,"sha256":"c4c0…","ok":true},…]}
  ```

**Known smux bug (pinned v1.5.55, still present upstream).** When a stream has called
`CloseWrite` and the peer's FIN then arrives, `tryHalfCloseCleanup` closes the stream and
`streamClosed` → `recycleTokens` **discards received data that has not been read yet**; the
reader gets EOF early. kcptun's `std.Pipe` half-closes in exactly this order, so a real
kcptun tunnel can truncate the response of a client that half-closes (`shutdown(SHUT_WR)`)
before the response has been read. To stay reliable the client therefore calls `CloseWrite`
only after the whole echo has arrived. `-early-closewrite` calls it right after sending (the
`std.Pipe` order) and reproduces the truncation with both `-ver 1` and `-ver 2`.

## snappycheck

```sh
snappycheck encode -chunk 8200 < plain > framed      # CompStream.Write (Write + Flush) per chunk
snappycheck decode -o plain.out < framed             # {"ok":true,"len":N,"sha256":"…"}
```

- `encode`: `-chunk 8200` (comma list, cycled). Each chunk is read in full (only the last may be
  shorter) and passed to kcptun's `CompStream.Write`, which calls `snappy.Writer.Write` then
  `Flush`, so the framed output is byte-for-byte what kcptun would send for writes of those
  sizes. Empty input gives empty output.
- `decode`: `-o FILE` optionally saves the decoded bytes. On error it prints
  `{"ok":false,"len":<decoded so far>,"sha256":"…","error":"snappy: corrupt input"}` and exits 1.

## qppcheck

```sh
qppcheck encrypt -key 'qpp-seed-0123456789abcdef' -pads 61 -chunk 1,7,4096 < plain > cipher
qppcheck decrypt -key 'qpp-seed-0123456789abcdef' -pads 61 -chunk 5,9999   < cipher > plain
qppcheck pads    -key 'qpp-seed-0123456789abcdef' -pads 61
```

Like kcptun, the pad is `qpp.NewQPP([]byte(key), uint16(pads))` with the **raw** key as seed
and each direction uses one `qpp.CreatePRNG([]byte(key))`. `encrypt`/`decrypt` apply
`EncryptWithPRNG`/`DecryptWithPRNG` per chunk (`-chunk 4096`, comma list, cycled) with the same
PRNG, as `QPPPort` does per `Write`/`Read`; the output does not depend on the chunking. Defaults:
`-key "it's a secrect"`, `-pads 61` (kcptun's `QPPCount`); `-pads` must be 1..65535. `pads`
prints the SHA-256 and first 32 bytes of the encryption pads and of the reverse pads (read from
qpp's unexported fields with reflect):

```json
{"pads":61,"len":15616,"pads_sha256":"8a59…","rpads_sha256":"3382…","pads_head":"7811…","rpads_head":"1c51…"}
```
