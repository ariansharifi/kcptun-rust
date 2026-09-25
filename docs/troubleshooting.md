# Troubleshooting

What the common failures look like, and what they mean. Every message quoted here was produced by
the binaries in this repository; where the behaviour is inherited from Go kcptun, that is said so
you know whether switching implementations would change anything.

Useful first moves:

* `kill -USR1 <pid>` dumps the SNMP counters to the log of either binary. Most of the diagnoses
  below are a counter.
* Run without `-quiet` so `stream opened` / `stream closed` lines are visible.
* An unstamped build (`-v` prints `SELFBUILD`) prefixes every log line with `file:line`, as an
  unstamped Go build does. The file names are Rust ones
  ([V08](differences.md#full-list)).

## The tunnel comes up but no data flows

Both processes log normally, a client application connects, and nothing comes back.

**Check the settings that must be identical on both sides**: `-key`, `-crypt`, `-nocomp`,
`-smuxver`, `-QPP`, `-QPPCount`. None of them is negotiated.

| Symptom | Cause |
|---|---|
| Server's `InCsumErrors` climbs with every packet, no `remote address:` line | `-key` or `-crypt` differ. The server cannot authenticate the packets, so no session is ever created. |
| Server logs `remote address:` and `smux version:`, then `invalid protocol` | The smux layer received something it cannot parse: `-smuxver` differs, or `-nocomp` / `-QPP` / `-QPPCount` differ, so the stream bytes are garbage to the receiver. |
| Client logs `stream opened` but the server logs nothing | The packets are not arriving at all: UDP firewall, NAT, wrong port, or a `-l`/`-r` port-range mismatch. |

`InCsumErrors` on a key mismatch is not a corrupted link: it is the CRC over a packet that was
decrypted with the wrong key.

## The client repeats `re-connecting: …`

```
re-connecting: dial(): malformed address:badaddr
```

The client could not create a KCP session and will retry forever. What follows `re-connecting:` is
the underlying error, with Go's own wording. Common ones:

| Text | Meaning |
|---|---|
| `dial(): malformed address:…` | `-r` is not `host:port` or `host:min-max`. |
| `dial(): lookup …: no such host` | DNS failure for the remote host. |
| `dial(): tcpraw.Dial(): dial ip:tcp <remote ip>: socket: operation not permitted` (Linux) | `-tcp` needs `CAP_NET_RAW` for its raw socket (and `iptables`, i.e. `CAP_NET_ADMIN`, to suppress the kernel's own segments). Run the client as root or give the binary `setcap cap_net_raw,cap_net_admin+ep`. Identical in Go. |
| `dial(): tcpraw.Dial(): os not supported` (not Linux) | Go's fake TCP is Linux-only and this port says the same thing everywhere else. See [Status](status.md). |
| `-tcp` tunnel carries nothing, and the **Go** client's `SIGUSR1` dump shows `InErrs` climbing with `InPkts:0` | Not fixable from this side: kcp-go's read loop demands a `*net.UDPAddr` and tcpraw hands it a `*net.TCPAddr`, so a Go `-tcp` client drops every inbound packet, against a Go server too ([V22](differences.md#full-list)). Use this port's client for `-tcp`. |
| A `-A OUTPUT … -m ttl --ttl-eq 1 … -j DROP` rule is left behind | The process was `SIGKILL`ed (or the machine lost power): no process can catch that signal, so nothing removed the rule. Go behaves identically. Remove it with the `-D` form of the same rule, e.g. `iptables -D OUTPUT -s <local> -d <remote> -p tcp -m ttl --ttl-eq 1 -m tcp --sport <port> --dport <port> -j DROP` (`--sport <port>` alone for a server's rule); `iptables -S OUTPUT` lists them. Every other exit path, `SIGINT`, `SIGTERM`, a normal close, removes them. |
| `BuildSmuxConfig(): keep-alive interval must be positive` | `-keepalive` is negative. Go would instead pass validation and panic when the session opens ([V12](differences.md#full-list)). |
| `BuildSmuxConfig(): keep-alive timeout must be larger than keep-alive interval` | `-keepalive` is greater than 30. smux's keep-alive *timeout* is fixed at 30 s and kcptun never changes it, so no session can be built and the client retries forever. Identical in Go. |

## The process exits immediately

| Exit status | Meaning |
|---|---|
| `2` | Usage error. `Incorrect Usage. flag provided but not defined: -nosuchflag`, followed by the help text. Go prints the same text and exits **0** ([V06](differences.md#full-list)). |
| `1` | A fatal error: the message is the last log line. |

Fatal errors you may hit, all reported before any traffic:

```
datashard 255 + parityshard 2 exceeds 256: cannot create Encoder with more than 256 data+parity shards
conn 65536 does not fit in uint16: kcptun would truncate it to 0
QPPCount 65536 does not fit in uint16: kcptun would truncate it to 0
QPP: not available in this build
listen udp :29900: bind: address already in use
```

The first three are configurations Go accepts and then breaks on: a silently undecodable erasure
code, or a division by zero at the first connection ([V07](differences.md#full-list),
[V19](differences.md#full-list), [V15](differences.md#full-list)). Fix the value; no configuration that
works under Go is refused here, with one exception: a `-QPPCount` above 65535 that does not truncate
to zero (`65537` and friends) becomes a single pad in Go, with no warning at all, and runs,
insecurely. It is refused here ([V15](differences.md#full-list)).

`QPP: not available in this build` means the binary was built with `--no-default-features`, without
the GPL-3.0 QPP crate. Rebuild with default features, or drop `-QPP`.

Unlike Go, a fatal error prints **one line and no stack trace**
([V20](differences.md#full-list)). The line itself is byte-identical to Go's first line.

## The binary will not start at all on Linux: `GLIBC_2.x not found`, or `No such file or directory`

```
./kcptun-client: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.17' not found
bash: ./kcptun-client: No such file or directory      # the file *is* there
```

Both mean the same thing: you are running the **glibc** archive,
`kcptun-rust-linux-<arch>-gnu-<version>.tar.gz`, which is dynamically linked against glibc 2.17 or
newer, and this host's glibc is older, or it has no glibc at all (Alpine and other musl
distributions: there the dynamic loader named in the executable is missing, which the kernel
reports as the misleading `No such file or directory`).

Take the default archive instead: `kcptun-rust-linux-<arch>-<version>.tar.gz` is statically linked
against musl and has no runtime dependency of any kind. It is also the smaller resident set at a
typical tunnel workload. The only thing you give up is the one reason to take the `-gnu-` archive:
a static build cannot hand a traffic burst's memory back and holds its high-water mark until it
restarts ([README](benchmarks/REPORT.md#memory)).

## `SetReadBuffer` / `SetWriteBuffer` errors at startup

```
SetWriteBuffer: set udp [::]:29900: setsockopt: invalid argument
```

`-sockbuf` was rejected by the kernel, usually a negative or absurd value. Note that the kernel
also silently *caps* acceptable values at `net.core.rmem_max` / `wmem_max`, so a large `-sockbuf`
can be accepted and then not take effect; raise those sysctls too (see
[the tuning guide](tuning.md#before-you-tune)).

## Packets are being dropped locally

Rising `InErrs` in the SNMP dump, or throughput far below the link's capacity with no loss on the
path itself, usually means the receiver cannot drain the socket in time:

1. raise `-sockbuf` and the matching `net.core.*` sysctls;
2. on a slow CPU, turn FEC off (`-datashard 0 -parityshard 0`) and use a cheap cipher;
3. if the *sender* is bursting, use `-ratelimit` to pace it.

Rising `RetransSegs` with a flat `FECRecovered` means real loss that parity is not covering: raise
`-parityshard`, or make retransmission more aggressive with `-mode fast3`.

## A connection hangs for about 30 seconds when it finishes

The server's `-closewait` default is **30 seconds**: the delay before it tears a connection down,
and it applies once per direction, so a request/response round trip against the defaults can take a
minute to close. This is Go's default and Go's behaviour. Set `-closewait 0` if your workload
half-closes and you want teardown to be immediate.

## After the server restarts, existing clients take about a minute to recover

That is expected, and identical in Go. The client only notices that its session is dead when
smux's keepalive times out; the timeout is 30 seconds and a session that carried traffic survives
one tick and dies on the next, so recovery takes roughly 30–65 seconds, after which the next
accepted connection dials a fresh session. `-keepalive` does **not** change this: it only sets the
interval between NOP pings. The detection window is smux's `KeepAliveTimeout`, which
`smux.DefaultConfig()` fixes at 30 seconds and which kcptun does not expose, and setting
`-keepalive` above 30 does not lengthen it either, it just makes every session fail to build (see
the `re-connecting:` table above).

A client is *not* logging `re-connecting:` during this; that loop only runs when dialling fails,
and dialling UDP does not fail.

## Responses are truncated

If the truncation happens with a **Go client** (against either server), it is Go's
half-close data loss: Go's smux discards data that arrived but has not been read once the peer's FIN
completes the half-close. It is reproducible with Go on both ends, and it is fixed in this port's
client ([V11](differences.md#full-list), [V04](differences.md#full-list) with `-QPP`). The interop
matrix records exactly this: a Rust client is held to a complete response, a Go client is not.

If the truncation happens with a **Rust client**, that is a bug: please report it with the flags
and, if possible, a packet capture.

## A flag seems to be ignored, or takes a strange value

* **Integers are parsed base-0, as in Go.** `-mtu 01350` is *octal* and yields 744. Drop the
  leading zero.
* **A JSON file given with `-c` overrides the command line**, not the other way round, and a
  `-mode` preset then overrides `nodelay` / `interval` / `resend` / `nc` from both.
* **Unknown JSON keys are ignored silently**, exactly as Go's `encoding/json` ignores them, so a
  misspelled key does nothing and says nothing. Compare against
  [`dist/local.json.example`](../dist/local.json.example) and
  [`dist/server.json.example`](../dist/server.json.example), which are parsed by the test suite.
* The startup block in the log prints every effective value. Read it back before hunting further.

## `--pprof` does nothing

```
pprof: not available in this build
```

The profiling endpoint is behind an optional cargo feature. Rebuild with
`cargo build --release --features pprof` (Unix only). The flag is always accepted, so a Go command
line keeps working either way ([V21](differences.md#full-list)).

## Signals

* `SIGUSR1`: dump the SNMP counters to the log.
* `SIGTERM` / `SIGINT`: the process restores the default disposition and re-raises the signal, as
  Go's does, so a supervisor sees a signal death rather than `exit 0`.

## Reporting a problem

Include: both command lines, `-v` output from both binaries, the log from both sides (without
`-quiet`), a `SIGUSR1` SNMP dump from both, and whether the peer was a Go or a Rust binary. If the
same configuration works with Go on both ends, say so: that is the most useful fact in the report.
