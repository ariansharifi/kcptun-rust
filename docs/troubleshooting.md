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

## Connections are left behind: FIN-WAIT-2, CLOSE-WAIT, or descriptors with no connection

v0.2.1 of both binaries leaked finished connections, and so does Go kcptun 2026-02: once the far
end dropped a stream, the connection's TCP socket was never read or closed again. In production
that grew to thousands of sockets and to one server holding 827 MB of its host's 829 MB of TCP
memory. **v0.2.2 fixes it** ([V24](differences.md#full-list)). The Go releases before 2026, which
close both ends when either direction finishes, do not have it.

**How to check**, on the host of the process you suspect (`<pid>` is its process id; `ss -p`
needs root to name another user's process):

```sh
ss -tnp state fin-wait-2 | grep 'pid=<pid>,'  # the leak's signature: a full Recv-Q nobody reads
ss -tnp state close-wait | grep 'pid=<pid>,'  # some are normal, see below
ls -l /proc/<pid>/fd | grep -c socket:        # the sockets the process holds ...
ss -tanp | grep -c 'pid=<pid>,'               # ... and the TCP ones the kernel still lists
grep '^TCP:' /proc/net/sockstat               # host-wide: alloc far above inuse is sockets
                                              # closed but still held
cat /proc/sys/net/ipv4/tcp_mem                # sockstat's "mem" against the third value (pages)
```

A process holds a few sockets more than `ss -t` lists (its UDP sockets, for one). Thousands more
are closed connections whose descriptor was never closed: no state table lists them any more, but
their unread data is still charged to the host's TCP memory. Past the third value of `tcp_mem` the
kernel starts refusing buffer memory to every TCP socket on the host, not only to kcptun's, and may
log `TCP: out of memory -- consider tuning tcp_mem`.

**What v0.2.2 changed.** Both binaries now:

* close both ends of a connection `-closewait` seconds after its first direction finishes, and
  never leave a socket half-closed and unread;
* while one direction waits for its destination, check both ends once a second: a socket that was
  reset, or that TCP keepalive gave up on, ends the connection, and so does a connection whose far
  end has finished, or whose stream holds up its whole session, while its application or target
  takes nothing for 30 s (`-closewait` if longer; since v0.2.3 counted from when that started, and
  never applied to a reader waiting on the tunnel);
* turn TCP keepalive on for the client's accepted connections and the server's target
  connections, as Go does (15 s idle, 15 s interval, 9 probes, [D36](DECISIONS.md)), so a peer
  that vanishes without a FIN or an RST is noticed after about 150 s;
* let go of a dead session's socket and queues, and of a closed session's streams, at once
  ([D35](DECISIONS.md)).

A connection now ends at most `-closewait` seconds after one of its directions finishes, or after
the stall limit when its application or target stopped reading after the far end had finished. Some CLOSE-WAIT sockets are
normal: a target that has closed waits there for the server's `-closewait` (30 s by default) before
kcptun closes its end, and an application that sent its data and closed waits there while the tail
of that data goes through the tunnel. With a Go peer, the Go side keeps its own leak; only this
port's end is freed.

**What it logs**, without `-quiet`, as `pipe: <error> in: <a> out: <b>`:

| Error | Meaning |
|---|---|
| `i/o timeout` | The stall rule ended the connection: the far end had finished, or the connection's stream was holding up its whole session, and the application or target took nothing for the stall limit. That reader loses what it had not read, and its socket is reset. |
| `connection reset by peer` | The application or the target reset its connection. Since v0.2.2 that is noticed even while the other direction is waiting for the tunnel, and the connection ends. `connection timed out` is the same for a peer that TCP keepalive gave up on. |

**Why an application may now see `ECONNRESET`.** When kcptun ends a connection while it still holds
data on its way to an application (the grace ran out while an answer was arriving, the stall rule
ended a connection whose application had stopped reading, or the session died before the far end
finished), it resets that application's socket instead of closing it. The application reads
`connection reset by peer` instead of a clean end of file, so a download cut short cannot pass for a
complete one. On the server the same holds for the target, for an upload.

**Applications that half-close.** v0.2.2 does not pass a half-close through the tunnel. When an
application calls `shutdown(SHUT_WR)` (`nc -N`, HTTP/1.0-shaped clients, some RPC clients) and then
waits for its answer, the client closes the whole connection `-closewait` seconds later, at once
with the default of 0, and the target sees the end of the request only when the server closes its
connection, after the client has closed its own. Give the **client** a `-closewait` as long as the
answer can take. It helps only within that grace: an answer still on its way when the grace runs
out is cut (with a reset if kcptun was holding part of it, otherwise as an early end of file), and
it cannot help a target that waits for the end of the request before answering. It also applies to
every other connection the client carries, each of which then sees its end of file that much later.

## A connection hangs for about 30 seconds when it finishes

The server's `-closewait` default is **30 seconds**: the time between the first direction of a
connection finishing and both ends being closed. When the target closes, the client application
gets the target's data at once but its end of file only 30 s later, at teardown; when the client
application closes, the target sees the end 30 s later. The default is Go's, and so is the
behaviour. Up to v0.2.1 the wait applied once per direction, so a round trip could take a minute to
close; since v0.2.2 it applies once per connection ([V24](differences.md#full-list)).

Set the server's `-closewait 0` for an immediate teardown. Data already handed to the tunnel is
still delivered; what is lost is anything the client application sends after the target has
closed, which matters only to a target that half-closes and keeps reading.

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
completes the half-close, and with `-QPP` Go closes the whole stream instead
([V11](differences.md#full-list), [V04](differences.md#full-list)). It is reproducible with Go on
both ends, and the interop matrix records it.

If it happens with a **Rust client**, first check whether it is one of the cuts v0.2.2 makes on
purpose ([V24](differences.md#full-list)): the application half-closed and the answer took longer
than the client's `-closewait`, or the application stopped reading for 30 s after the far end had
finished. See
[Connections are left behind](#connections-are-left-behind-fin-wait-2-close-wait-or-descriptors-with-no-connection)
for both. Anything else is a bug: please report it with the flags and, if possible, a packet
capture.

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
