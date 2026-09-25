# Wire Format & Algorithm Reference

Extracted from the pinned Go reference (kcptun `39935d5`, kcp-go v5.6.66, smux v1.5.55, qpp v1.1.25,
tcpraw v1.2.32, golang/snappy v1.0.0, klauspost/reedsolomon v1.13.0). Integers are **little-endian**
unless stated otherwise. When this document and the Go source disagree, **the Go source wins**: fix this
document in the same commit.

---

## 0. Parameters that must match on both ends

`-key`, `-crypt`, `-nocomp`, `-smuxver`, `-QPP`, `-QPPCount`.
FEC `-datashard/-parityshard` do *not* need to match: the receiver auto-tunes (§4.5). MTU, windows and
modes are local.

Defaults:

| flag | client | server |
|---|---|---|
| listen / localaddr | `:12948` | `:29900` |
| remoteaddr / target | `vps:29900` | `127.0.0.1:12948` |
| key | `it's a secrect` (sic) | same |
| crypt / mode | `aes` / `fast` | same |
| mtu | 1350 | 1350 |
| sndwnd / rcvwnd | **128 / 512** | **1024 / 1024** |
| datashard / parityshard | 10 / 3 | 10 / 3 |
| smuxver / smuxbuf / streambuf / framesize | 2 / 4194304 / 2097152 / 8192 | same |
| sockbuf / keepalive | 4194304 / 10 s | same |
| closewait | **0** | **30** |
| conn / autoexpire / scavengettl | 1 / 0 / 600 | - |
| QPPCount / snmpperiod | 61 / 60 | same |
| hidden: nodelay / interval / resend / nc | 0 / 50 / 0 / 0 | same |

Mode presets (applied **after** JSON parsing; any other mode name keeps the manual values):
`normal {0,40,2,1}`, `fast {0,30,2,1}`, `fast2 {1,20,2,1}`, `fast3 {1,10,2,1}` as
`{nodelay, interval, resend, nc}`.

---

## 1. Key derivation and crypt selection (`kcptun/std/crypt.go`, `kcp-go/crypt.go`)

```
pass = PBKDF2-HMAC-SHA1(password = UTF-8 bytes of -key, salt = "kcp-go", iter = 4096, dkLen = 32)
```

| `-crypt` | Cipher | Key material | Block | Header on wire |
|---|---|---|---|---|
| `aes` (default) and **any unknown name** | AES-256 | `pass[0:32]` | 16 | nonce 16 + crc 4 |
| `aes-128` | AES-128 | `pass[0:16]` | 16 | nonce 16 + crc 4 |
| `aes-192` | AES-192 | `pass[0:24]` | 16 | nonce 16 + crc 4 |
| `aes-128-gcm` | AES-128-GCM (AEAD) | `pass[0:16]` | - | nonce 12, plus 16-byte tag at the end |
| `salsa20` | Salsa20/20, nonce = packet bytes `[0:8]` | `pass` (32) | stream | nonce 16 + crc 4 |
| `blowfish` | Blowfish | `pass` (32 bytes) | 8 | nonce 16 + crc 4 |
| `twofish` | Twofish-256 | `pass` (32) | 16 | nonce 16 + crc 4 |
| `cast5` | CAST5 | `pass[0:16]` | 8 | nonce 16 + crc 4 |
| `3des` | 3DES-EDE3 (k1‖k2‖k3) | `pass[0:24]` | 8 | nonce 16 + crc 4 |
| `tea` | TEA, **16 rounds** (`tea.NewCipherWithRounds(key,16)`), big-endian | `pass[0:16]` | 8 | nonce 16 + crc 4 |
| `xtea` | XTEA (x/crypto default, 64 rounds), big-endian | `pass[0:16]` | 8 | nonce 16 + crc 4 |
| `sm4` | SM4 | `pass[0:16]` | 16 | nonce 16 + crc 4 |
| `xor` | XOR with pad `PBKDF2-HMAC-SHA1(pass, "sH3CIVoF#rWLtJo6", 32, 1500)` over `min(len,1500)` bytes | - | - | nonce 16 + crc 4 |
| `none` | identity (no encryption) | - | - | nonce 16 + crc 4 (plaintext) |
| `null` | **no crypto layer at all** | - | - | **none** |

- If a constructor errors, Go logs `crypt: failed to create %s cipher: %v, falling back to aes` and uses
  AES-256 with the full `pass`.
- The startup log line `encryption: <value>` prints the **configured** string (for example `bogus`),
  not the effective one.
- QPP (§9) uses the **raw `-key` bytes**, not `pass`.

### 1.1 CFB variant (all 8- and 16-byte block ciphers)

```
IV (fixed) = [167,115,79,156,18,172,27,1,164,21,242,193,252,120,230,107]   (first 8 bytes for 8-byte ciphers)
encrypt(buf):  t = E(IV[0:bs]); for each full block B_i: C_i = B_i ⊕ t; t = E(C_i)
               trailing partial block (len % bs bytes): C = B ⊕ t[0:rem]
decrypt(buf):  t = E(IV[0:bs]); for each full block: n = E(C_i); B_i = C_i ⊕ t; t = n
               trailing partial: B = C ⊕ t[0:rem]
```

This is standard full-block CFB with a constant IV. The **whole packet is encrypted, including the random
nonce**, so the nonce acts as a random first block. Decryption keystreams are independent per block (they
depend only on ciphertext), so they can be computed with multi-block parallel AES. Encryption is
inherently serial.

---

## 2. Packet layout on UDP (`kcp-go/sess.go` postProcess / packetInput)

### 2.1 CFB-family, salsa20, xor, none
```
 0            16        20           28 (if FEC)
 ┌────────────┬─────────┬────────────┬──────────────────────────┐
 │ nonce (16) │ crc32(4)│ FEC hdr (8)│ KCP segments ...         │   ← then the whole buffer is encrypted
 └────────────┴─────────┴────────────┴──────────────────────────┘
```
- nonce: 16 random bytes per packet (Go: AES-based RNG).
- crc32: **CRC-32/IEEE** (`crc32.ChecksumIEEE`) over bytes `[20:]`, stored LE at `[16:20]`, computed
  **before** encryption.
- Receive: `len < 20` → drop. Decrypt the whole buffer, check `crc32(data[20:]) == LE32(data[16:20])`.
  On mismatch increment `InCsumErrors` and drop. The payload is `data[20:]`.

### 2.2 AEAD (`aes-128-gcm`)
```
 ┌───────────┬──────────────────────────────────────────┐
 │ nonce (12)│ AES-GCM ciphertext of [FEC hdr + KCP] + tag(16) │   (no AAD, no crc)
 └───────────┴──────────────────────────────────────────┘
```
Receive: `len < 12+16` → drop. Open failure → `InCsumErrors++`.

### 2.3 null
Raw `[FEC hdr +] KCP` bytes.

### 2.4 Minimum sizes and MTU arithmetic
- After decrypt: `len < min(24, 8+4) = 12` → drop (`KCPInErrors++` in a session; silent in the listener).
- `headerSize = (null: 0 | AEAD: 12 | others: 20) + (8 if FEC enabled)`.
- `kcp.mtu = min(1500, -mtu) − headerSize − (16 if AEAD)`, and `mss = kcp.mtu − 24`.
  - default (mtu 1350, aes, FEC 10/3): kcp.mtu = 1322, mss = 1298
  - production (mtu 1390, xor, no FEC): kcp.mtu = 1370, mss = 1346
  - aes-128-gcm with FEC: 1350 − 20 − 16 = 1314
- `mtuLimit = 1500`: all receive buffers are 1500 bytes and pool buffers are 1500 bytes.

---

## 3. KCP segment (`kcp-go/kcp.go`)

Header is 24 bytes (`IKCP_OVERHEAD`). Several segments can be packed into one packet (≤ kcp.mtu).

| off | size | field | notes |
|---:|---:|---|---|
| 0 | 4 | conv | random u32 chosen by the client per session (crypto/rand) |
| 4 | 1 | cmd | 81 PUSH, 82 ACK, 83 WASK (window probe), 84 WINS (window tell) |
| 5 | 1 | frg | always 0 (kcptun uses stream mode) |
| 6 | 2 | wnd | receiver free window = `rcv_wnd − len(rcv_queue)` (0 if negative) |
| 8 | 4 | ts | sender ms timestamp (monotonic since process start, u32 wrap), echoed in ACKs |
| 12 | 4 | sn | sequence number (`IKCP_SN_OFFSET = 12`) |
| 16 | 4 | una | receiver's `rcv_nxt` (cumulative ack) |
| 20 | 4 | len | data length |
| 24 | len | data | |

Input rules worth remembering:
- A `conv` mismatch rejects the whole packet (−1).
- An unknown cmd returns −3.
- `rmt_wnd` is updated only from regular (non-FEC-recovered) packets.
- RTT is updated only from regular packets, using the latest ACK's ts.

Constants: `RTO_NDL 30, RTO_MIN 100, RTO_DEF 200, RTO_MAX 60000, WND_SND 32, WND_RCV 32, MTU_DEF 1400,
ACK_FAST 3, INTERVAL 100, DEADLINK 20, THRESH_INIT 2, THRESH_MIN 2, PROBE_INIT 500, PROBE_LIMIT 120000`.
`NoDelay` clamps interval to [10, 5000]. `SetMtu` rejects `mtu < 50` (v5.6.66; later versions use
`<= 24`).

---

## 4. FEC (`kcp-go/fec.go`, `autotune.go`)

Enabled on the sender iff `datashard > 0 && parityshard > 0`. Receivers always understand FEC packets:
if a receiver has no decoder, it lazily creates a (1,1) decoder and auto-tunes.

### 4.1 Header
```
data   : seqid u32 | type u16 = 0x00F1 | size u16 = 2 + len(KCP bytes) | KCP bytes
parity : seqid u32 | type u16 = 0x00F2 | parity bytes (len = max data "size-region" length in the group)
oob    : seqid u32 = 0xFFFFFFFF | type u16 = 0x00F3 | size u16 | conv u32 | payload   (not FEC-protected)
```
- Demux: read the u16 at offset 4 of the decrypted payload. 0xF1/0xF2/0xF3 are FEC types; anything else
  is plain KCP. KCP bytes 4–5 are `cmd, frg` with cmd ∈ 81–84, so they cannot collide.
- An RS **shard** is the bytes from the `size` field to the end (`fecPacket.data() = pkt[6:]`),
  zero-padded to the group's max length.

### 4.2 Sequencing
- `shardSize = ds + ps`, `paws = (0xFFFFFFFF / shardSize) * shardSize`.
- `seqid` starts at 0 per session and increments for every data and every parity packet, `% paws`.
- `group = seqid / shardSize`, `pos = seqid % shardSize` (`pos < ds` means data, otherwise parity).
- **Parity generation** happens when `ds` data packets are collected. It is **skipped** (seqid still
  advances by `ps`) when `now − tsLatestPacket ≥ 500 ms` (`maxFECEncodeLatency`), where `tsLatestPacket`
  is the time of the *previous* `encode` call.

### 4.3 Reed-Solomon
GF(2^8) with primitive polynomial **0x11D**. klauspost `New(ds, ps)` with ≤ 256 shards uses
**`buildMatrix`**: `vandermonde(total, ds) × inverse(top ds×ds)` (systematic). Parity = `M[ds..] · data`.
`ReconstructData` recovers only missing *data* shards.

### 4.4 Decoder behaviour
- Drop packets with `seqid ≥ paws`. Dedup per group.
- Recover when a group has ≥ ds shards. Go pops **all** shards currently in that group's heap.
- Recovered shard `r`: `sz = LE16(r[0:2])`. If `2 ≤ sz ≤ len(r)`, feed `r[2:sz]` to KCP as an **FEC
  packet** (no `rmt_wnd`/RTT update, no RepeatSegs counting).
- Groups older than 3 groups behind the newest are discarded (`maxShardSets = 3`).

### 4.5 Auto-tune
Each decoded packet samples `(isData, seqid)` into a 258-entry ring. When a packet's type contradicts its
position under the current (ds, ps), the decoder finds the data/parity pulse periods. If both are > 0 and
their sum < 256 it resets to (autoDS, autoPS), dropping all groups. `shouldTune` is always cleared after
an attempt that found both periods.

---

## 5. Session demux on the server (`kcp-go/sess.go` Listener.packetInput)

- Sessions are keyed by the **remote address string**.
- conv/sn extraction:
  - FEC data with len ≥ 8+24: from the KCP header after the FEC header.
  - Parity: no conv; routed to the existing session only.
  - OOB: conv right after the FEC header.
  - Plain KCP: conv at offset 0, sn at offset 12.
- Existing session with a different conv: if `sn == 0` the old session is closed and a new one created,
  otherwise the packet is dropped.
- New session only if `len(accept backlog) < 128`. It is created, fed this packet, registered, then
  queued for accept.

---

## 6. Snappy framed stream (`kcptun/std/comp.go` over golang/snappy; unless `-nocomp`)

Wraps the KCP byte stream **below** smux. Every `Write` (one smux frame) is written and flushed
immediately, which produces exactly one chunk per frame for frames ≤ 64 KiB.

```
stream id chunk (once, first): FF 06 00 00 73 4E 61 50 70 59        ("sNaPpY")
chunk: type u8 | length u24 LE | body
  0x00 compressed   : masked_crc32c(uncompressed) u32 LE | snappy block
  0x01 uncompressed : masked_crc32c(data) u32 LE | data      (≤ 65536 bytes)
  0x80–0xFD         : skippable padding
  0x02–0x7F         : reserved unskippable → error
masked_crc = ((c >> 15) | (c << 17)) + 0xA282EAD8   (u32 wrapping), c = CRC-32C (Castagnoli)
```
- The writer uses a compressed chunk only if `len(compressed) < len − len/8`.
- The reader **requires the stream id chunk first** (otherwise ErrCorrupt).

---

## 7. smux (`xtaci/smux` v1.5.55)

```
header (8 bytes): ver u8 | cmd u8 | length u16 LE | sid u32 LE      then `length` payload bytes
cmd: 0 SYN, 1 FIN, 2 PSH, 3 NOP, 4 UPD (v2 only; payload = consumed u32 LE | window u32 LE)
```
- `ver` must equal the local `-smuxver`, otherwise `ErrInvalidProtocol` and the session is dead. Newer
  smux also rejects non-zero length on SYN/FIN/NOP and UPD length ≠ 8 (adopt: V01).
- **Stream IDs:** the client starts at 1 and adds 2 *before* use, so it opens **3, 5, 7, …**. The server
  counter starts at 0 (kcptun servers never open streams). Overflow → `ErrGoAway`.
- NOP keepalive: every `-keepalive` seconds, sid 0. The session is closed if **no frame at all** arrived
  during a `KeepAliveTimeout` (30 s, fixed) window *and* the token bucket > 0.
- FIN = end of that side's data (half-close via `CloseWrite`, or full `Close`). A full close also removes
  the stream, so later PSH frames for that sid are discarded.
- **v2 flow control:**
  - The reader sends `UPD(consumed = total bytes read, window = MaxStreamBuffer)` when bytes read since
    the last UPD ≥ `MaxStreamBuffer/2`, or on the **first** read.
  - The writer may have `inflight = numWritten − peerConsumed` ≤ `peerWindow` (initial **262144**) and
    blocks otherwise.
  - `inflight < 0` → `ErrConsumed`.
- The session-wide receive token bucket (`MaxReceiveBuffer = -smuxbuf`) is local only (never on the wire).
  recvLoop stops reading when it reaches ≤ 0.
- **Write ordering (shaper):** there is one heap per sid, and the sids are served **round-robin**. NOP
  uses sid 0, so it is just another RR member with no global priority.
  - Within one sid's heap: `class` first (CTRL = SYN and UPD; DATA = PSH and FIN), then request `seq`
    (wrapping compare).
  - FIN is DATA class so it stays ordered after that stream's data.
- Config limits:
  - `MaxFrameSize` ∈ (0, 65535]
  - `MaxReceiveBuffer` ∈ (0, 2^31−1]
  - `0 < MaxStreamBuffer ≤ MaxReceiveBuffer`
  - `KeepAliveTimeout ≥ KeepAliveInterval`: a `-keepalive` > 30 makes `VerifyConfig` fail, and the client
    then loops on "re-connecting".

---

## 8. Proxy semantics (`kcptun/std/copy.go`, client/server `handleClient`)

- `Pipe(a, b, closeWait)`: two directions. When one direction's source hits EOF or an error, sleep
  `closeWait` seconds, then `CloseWrite()` the destination if supported (TCP, smux stream), else `Close()`
  it. After both directions finish, close both ends.
  - Go's QPP wrapper has no `CloseWrite`, so with QPP the smux side is fully closed. See DECISIONS V04.
- The server dials the target with a **10 s** timeout. The target is TCP if `net.SplitHostPort(target)`
  succeeds, otherwise a unix socket path. The client's local address uses the same rule.
- Client session selection:
  - `rr` (u16) increments per accepted connection, and `idx = rr % conn`.
  - The session slot is (re)created synchronously with `waitConn` (retry every 1 s) if it is nil, closed,
    or past `autoexpire`.
  - Expired sessions go to the scavenger (every 5 s), which closes them `scavengettl` seconds after
    expiry.
- Each client session dial picks a random port in `[min,max]` of `-r host:min-max`, using
  `uint64 from crypto/rand % (max-min+1)`.

---

## 9. QPP: Quantum Permutation Pad (`xtaci/qpp` v1.1.25, **GPL-3.0**)

Applied **per smux stream** to the stream payload bytes (after smux on send, before smux on receive). Seed
= raw `-key` bytes. `numPads = -QPPCount`. Each stream gets fresh `wprng = CreatePRNG(seed)` and
`rprng = CreatePRNG(seed)`.

### 9.1 Pad generation (`NewQPP(seed, numPads)`)
```
if len(seed) < 32: seed = PBKDF2-HMAC-SHA1(seed, "___QUANTUM_PERMUTATION_PAD_SEED_DERIVE___", 128, 32)
byteLen   = QPPMinimumSeedLength(8) = ceil(bitlen(256!)/8) = 211
chunks    = ceil(211/32) = 7 chunks of 32 bytes; chunk i takes 32 bytes cyclically from seed (continuing index),
            then chunk i = PBKDF2-HMAC-SHA1(chunk i, "___QUANTUM_PERMUTATION_PAD_SEED_DERIVE___", 1024, 32)
blocks[j] = AES-256 with key PBKDF2-HMAC-SHA1(chunk j, "___QUANTUM_PERMUTATION_PAD_SHUFFLE_SALT___", 128, 32)
for pad i in 0..numPads:
    pad = [0,1,...,255]
    sum = HMAC-SHA256(key = chunks[i % 7], msg = "QPP_" + binary(i))   # Go fmt "%b": 0→"QPP_0", 5→"QPP_101"
    for k = 255 down to 1:
        for each block j in 0..7: AES-encrypt sum[0:16] and sum[16:32] in place (ECB, 2 blocks)
        idx = (sum as 256-bit BIG-endian unsigned) mod (k+1)
        swap(pad[k], pad[idx])
    rpad = inverse permutation of pad
```

### 9.2 PRNG (`CreatePRNG(seed)`)
```
s   = HMAC-SHA256(key = seed, msg = "PERMUTATION_MATRIX_SELECTOR")
x   = PBKDF2-HMAC-SHA1(s, "___QUANTUM_PERMUTATION_PAD_PRNG_SALT___", 128, 32)
state[0..4] = LE u64 of x[0:8], x[8:16], x[16:24], x[24:32]
seed64 = xoshiro256**(state)   (first output; state advanced once);  count = 0
xoshiro256**: result = rotl(s1*5, 7)*9; t = s1<<17; s2^=s0; s3^=s1; s1^=s2; s0^=s3; s2^=t; s3=rotl(s3,45)
```

### 9.3 Byte transform (position-based: independent of how writes/reads are chunked)
```
r = seed64 at stream start; every 8 bytes of stream position: r = next xoshiro256** output
k = (r as u16) % numPads            # pad index, re-selected whenever r changes
encrypt byte at position p:  c = pads[k][ b ^ (byte)(r >> 8*(p mod 8)) ]
decrypt:                     b = rpads[k][c] ^ (byte)(r >> 8*(p mod 8))
```

Validation warnings (non-fatal):
- key length < 211 bytes
- `QPPCount < 7`
- `gcd(QPPCount, 8) ≠ 1` ("choose a prime number")

`QPPCount ≤ 0` is fatal.

---

## 10. tcpraw fake TCP (`xtaci/tcpraw` v1.2.32, Linux only)

- **Client:**
  - Opens a raw `ip:tcp` socket connected to the server IP.
  - Makes a **real** TCP connection (kernel handshake), then sets **TTL/hop-limit = 1** on the real
    socket.
  - Adds iptables OUTPUT rule `-m ttl --ttl-eq 1 -p tcp -s <laddr> --sport <lport> -d <rip> --dport
    <rport> -j DROP`, and the ip6tables equivalent with `-m hl --hl-eq 1`.
- **Server:**
  - Raw `ip:tcp` sockets on each interface address (or the given IP), plus a real TCP listener.
  - Accepted connections get TTL = 1.
  - Rule `-m ttl --ttl-eq 1 -p tcp --sport <port> -j DROP` (v6: `-m hl --hl-eq 1`).
- Data packets are crafted TCP segments with flags **PSH|ACK**, window 65535 and urgent 0:
  - seq = last ack seen from the peer, then += payload length
  - ack = tracked from the peer's seq + len (+1 for SYN/FIN)
  - Checksum uses the IPv4/IPv6 pseudo-header.
  - **Go v1.2.32 option bytes (quirk):**
    `01 01 08 0C <TSval u32 BE> <TSecr u32 BE> 00 00` plus 2 padding bytes (`00 00`), so the header is
    36 bytes (data offset 9). The timestamp option has **length 12** because gopacket serialises the
    10-byte `OptionData`. TSval is Unix time in ms (u32 BE).
  - Go parses an incoming TSval only when the option data is 10 bytes, which effectively means only from
    Go-tcpraw peers.
  - Upstream tcpraw after the pin (`cbf9635`) emits a standard length-10 option (32-byte header) with an
    uptime-style TSval. The Rust port adopts that fix (DECISIONS V10). Both forms interoperate because
    receivers locate the payload via the data offset.
- Payloads of PSH packets on known flows are delivered as datagrams. Packets without PSH, or on orphan
  flows (no real conn), are not delivered. Flows expire after 1 min (5 s for orphans).
- On SIGINT/SIGTERM, `IPTablesReset()` closes all conns, which deletes the rules.
- The IPv4 raw socket read in Go strips the IP header, so the parser starts at the TCP header.
