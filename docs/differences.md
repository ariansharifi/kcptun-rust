# Differences from Go kcptun

**The wire protocol is unchanged.** Every difference here is in local behaviour — what gets
refused at startup, what an error looks like, what a peer is allowed to do. A Go client talks to a
Rust server and the other way round, in every combination this project tests.

Behaviour was ported as it stands, quirks included, so the list is short and every entry is
deliberate. Each has an id (`V01`–`V23`) that
[`docs/DECISIONS.md`](DECISIONS.md) records in full, with the Go source it came from and the
evidence for changing it. `tools/check-docs.py` fails if this page and that register ever
disagree about which deviations exist.

The short version, for readers who only want the ones that could bite:
[README → Differences from Go](differences.md).

## The ones most likely to affect you

* **Configurations that Go accepts and then dies on are refused at startup**, with exit status 1 and
  a message naming the flag: FEC with more than 256 total shards (**V07**), and `-QPPCount` or
  `-conn` values that overflow Go's internal `uint16` cast (**V15**, **V19**). In each case Go
  either panics on the first packet or silently runs in a state its own validation did not intend.
  A negative `-keepalive` (**V12**) is likewise reported — with smux's own error, when the session
  is built — instead of panicking. No configuration that *works* under Go is refused, with one
  exception: a `-QPPCount` above 65535 that does **not** truncate to zero (`65537` and friends)
  truncates in Go to a single pad, with no warning of any kind, and runs — insecurely. That is
  refused here too (**V15**).
* **A usage error exits with status 2, not 0** (**V06**), so supervisors and deployment scripts can
  tell a typo from a clean exit.
* **Half-closed connections get complete responses** (**V11**, **V04**). A client that calls
  `shutdown(SHUT_WR)` and then reads the answer — HTTP/1.0-shaped traffic, many RPC clients — can
  receive a **truncated** answer through Go kcptun, because Go's smux discards received-but-unread
  data when the peer's FIN arrives. That is fixed here, invisibly to the wire, and it shows up in
  the interop matrix: a Rust client is held to a byte-complete response against either server, while
  the `go→go` control truncates.
* **Fatal errors print one line, not a Go stack trace** (**V20**). The first line — what a human or
  a log scraper actually reads — is byte-identical to Go's.
* **`--pprof` in a default build logs one extra line** saying the profiler is not compiled in
  (**V21**). Build with `--features pprof` for Go's behaviour.
* **A peer may answer from a different address** (**V23**), which Go drops. Multi-homed and anycast
  servers, direct-return load balancers and multi-WAN clients all send from one address and answer
  from another; under Go's rule the tunnel simply stalls. Only what we *accept* widens — the address
  we *send* to never moves, so a spoofed source cannot redirect a session. With `-crypt null` there
  is no integrity check to fall back on, so prefer a real cipher (any of them checks a CRC32; AES
  checks an AEAD tag). `-strictsource` puts Go's rule back, and the flag only helps when **both**
  ends run this port: a Go server opens a fresh session for a new address regardless.

## Full list

| ID | Area | Go | kcptun-rust |
|---|---|---|---|
| **V01** | Upstream bug fixes published after the pin | Pinned kcp-go v5.6.66 and smux v1.5.55, bugs included | Adopts the fixes up to kcp-go v5.6.72 and smux v1.5.57 that do not touch the wire format: salsa20 short-packet guard, empty-packet guards, ring-buffer `Discard` wrap fix, no panic out of the rate limiter, smux rejecting malformed frame lengths |
| **V02** | `-ratelimit` with an oversized batch | Asking the limiter for more than its burst returns an error: v5.6.66 **panics**, later versions send unpaced | The limiter allows debt, so pacing still holds and nothing crashes |
| **V03** | `-dscp` over IPv6 | Writes the raw DSCP into the IPv6 traffic class, so the marking is shifted and DSCP's low bits show up as **ECN** | `TCLASS = dscp << 2`, matching the IPv4 path |
| **V04** | `-QPP` with a half-close | The QPP stream has no `CloseWrite`, so kcptun closes the whole stream and the reverse direction is lost | Forwards the half-close (an smux FIN); the response completes |
| **V05** | Session close | The final flush races the shutdown signal, so the last packets are sent about half the time | The final flush is always queued and the sender drains before exiting |
| **V06** | Command-line usage error | Prints `Incorrect Usage` plus the help, exits **0** | Same text, exits **2** |
| **V07** | `-datashard` + `-parityshard` above 256 | The sender silently switches to a different erasure code that **no kcptun receiver can decode**; receivers reject the parameters outright, so the tunnel is broken without a word | Refused at startup, naming both flags |
| **V08** | `file:line` prefix in unstamped builds | Go source file and line | Rust source file and line. Unavoidable; the rest of the format is identical |
| **V09** | Unix-socket `-l`/`-t` on Windows | Supported on Windows 10+ | Unix platforms only. Windows is not a supported platform here at all (D22) |
| **V10** | `-tcp` TCP timestamp option | v1.2.32 emits a malformed timestamp option | Emits the standard option, as upstream tcpraw does now. Interoperates with both, because payloads are located by the data offset |
| **V11** | Half-close with unread data | The peer's FIN discards data that has arrived but not yet been read, cutting the answer short | Buffered data stays readable: the reader drains it, then sees EOF |
| **V12** | Negative `-keepalive` | Passes validation, then **panics** when the first session opens | The session is refused with smux's own message, `keep-alive interval must be positive` |
| **V13** | Session send-queue depth | — | **Superseded by V18** |
| **V14** | `MST` inside a `-snmplog` file name | Renders the local zone's abbreviation, so `-snmplog snmp-MST.log` writes `snmp-CEST.log` | Renders Go's own numeric fallback, `snmp-+0200.log`. A limitation, not an improvement; only a file *name* is affected, and only when it contains that token |
| **V15** | `-QPPCount` above 65535 | Truncated to 16 bits: `65536` becomes 0 and panics on the first byte of traffic, `65537` becomes one pad with **no warning at all** | Refused at startup, naming the value it would truncate to |
| **V16** | Write pattern for an uncompressed chunk | Two writes on the inner connection, header then body | One write. The byte stream is identical |
| **V17** | QPP short writes | Returns the inner connection's short count for a buffer it already encrypted in place, so the caller retries ciphertext | Keeps the unwritten ciphertext queued instead. Required rather than preferred: re-encrypting a tail would desynchronise the peer. Wire bytes identical |
| **V18** | Send queue full | The KCP output callback **drops** the packet; the segment is already marked as sent, so every drop costs a retransmission timeout — and one flush of the production window is four times the queue's depth | Backpressure: the flush stops before the queue fills, having mutated nothing, and the rest goes out on the next flush. Nothing KCP emits is dropped locally, and worst-case burst memory is quartered |
| **V19** | `-conn` at a multiple of 65536 | Passes validation, prints the whole startup block, then **divides by zero** on the first accepted connection | Refused at startup, naming the flag. Every other value behaves exactly as in Go |
| **V20** | Fatal errors | The message, then a Go stack trace | The message line only, byte-identical to Go's first line |
| **V21** | `--pprof` without the `pprof` feature | Always ships the profiler and logs nothing extra | The flag is accepted and one line records that the profiler is not in this build. With `--features pprof` the output is byte-identical to Go's |
| **V22** | `-tcp` (fake-TCP) **client** | kcp-go filters inbound packets by Go type as well as by address, and a fake-TCP connection reports its peers as `*net.TCPAddr` while the session's remote is a `*net.UDPAddr` — so every inbound packet is counted as an error and dropped, and the Go `-tcp` client receives nothing. A Go `-tcp` *server* is unaffected | One address type, so the same filter compares addresses only and `-tcp` works in both directions |
| **V23** | Where a peer may answer from | Both ends require every datagram to come from the address they send to: the client counts anything else as `InErrs` and drops it, and the server keys sessions by address, so a second source address opens a **second session** and the tunnel stalls | A peer may answer from, or send from, an address other than the one we send to. What we accept widens; where we send never moves. On by default; `-strictsource` restores Go's rule. Only helps Rust↔Rust — a Go server still opens a fresh session for a new address |

Two further limitations are not deviations from Go's behaviour but are worth knowing: `-tcp` is not
wired up yet (see [Status](status.md)), and on Windows signals and Unix-socket endpoints are
unavailable.
