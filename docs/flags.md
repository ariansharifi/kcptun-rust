# Flags

Both binaries take Go kcptun's flags, so a command line written for the Go binaries works here.

Both binaries take Go kcptun's flags with Go's parsing rules: `-flag value` and `--flag=value` are
equivalent, `-nocomp` is a boolean flag, integers are parsed base-0 (so `01350` is octal), `--`
terminates the flags, and a JSON file given with `-c` overrides the command line.

The table is generated from the binaries' own `-h` output by
[`tools/check-docs.py`](../tools/check-docs.py), which also fails if this file and the binaries ever
disagree. "n/a" means the flag does not exist on that side; "-" means it takes no value.

<!-- BEGIN generated: flags (tools/check-docs.py) -->
| Flag | Client default | Server default | Meaning |
|---|---|---|---|
| `--localaddr value, -l value` | `":12948"` | n/a | local listen address |
| `--remoteaddr value, -r value` | `"vps:29900"` | n/a | kcp server address, eg: "IP:29900" a for single port, "IP:minport-maxport" for port range |
| `--listen value, -l value` | n/a | `":29900"` | kcp server listen address, eg: "IP:29900" for a single port, "IP:minport-maxport" for port range |
| `--target value, -t value` | n/a | `"127.0.0.1:12948"` | target server address, or path/to/unix_socket |
| `--key value` | `"it's a secrect"` | `"it's a secrect"` | pre-shared secret between client and server. Also read from `$KCPTUN_KEY`. |
| `--crypt value` | `"aes"` | `"aes"` | aes, aes-128, aes-128-gcm, aes-192, salsa20, blowfish, twofish, cast5, 3des, tea, xtea, xor, sm4, none, null |
| `--mode value` | `"fast"` | `"fast"` | profiles: fast3, fast2, fast, normal, manual |
| `--QPP` | - | - | enable Quantum Permutation Pads(QPP) |
| `--QPPCount value` | `61` | `61` | the prime number of pads to use for QPP: The more pads you use, the more secure the encryption. Each pad requires 256 bytes. |
| `--conn value` | `1` | n/a | set num of UDP connections to server |
| `--autoexpire value` | `0` | n/a | set auto expiration time(in seconds) for a single UDP connection, 0 to disable |
| `--scavengettl value` | `600` | n/a | set how long an expired connection can live (in seconds) |
| `--mtu value` | `1350` | `1350` | set maximum transmission unit for UDP packets |
| `--ratelimit value` | `0` | `0` | set maximum outgoing speed (in bytes per second) for a single KCP connection, 0 to disable. Also known as packet pacing |
| `--sndwnd value` | `128` | `1024` | set send window size(num of packets) |
| `--rcvwnd value` | `512` | `1024` | set receive window size(num of packets) |
| `--datashard value, --ds value` | `10` | `10` | set reed-solomon erasure coding - datashard |
| `--parityshard value, --ps value` | `3` | `3` | set reed-solomon erasure coding - parityshard |
| `--dscp value` | `0` | `0` | set DSCP(6bit) |
| `--nocomp` | - | - | disable compression |
| `--sockbuf value` | `4194304` | `4194304` | per-socket buffer in bytes |
| `--smuxver value` | `2` | `2` | specify smux version, available 1,2 |
| `--smuxbuf value` | `4194304` | `4194304` | the overall de-mux buffer in bytes |
| `--framesize value` | `8192` | `8192` | smux max frame size |
| `--streambuf value` | `2097152` | `2097152` | per stream receive buffer in bytes, smux v2+ |
| `--keepalive value` | `10` | `10` | seconds between heartbeats |
| `--closewait value` | `0` | `30` | the seconds to wait before tearing down a connection |
| `--snmplog value` | - | - | collect snmp to file, aware of timeformat in golang, like: ./snmp-20060102.log |
| `--snmpperiod value` | `60` | `60` | snmp collect period, in seconds |
| `--log value` | - | - | specify a log file to output, default goes to stderr |
| `--quiet` | - | - | to suppress the 'stream open/close' messages |
| `--tcp` | - | - | to emulate a TCP connection(linux) |
| `-c value` | - | - | config from json file, which will override the command from shell |
| `--pprof` | - | - | start profiling server on :6060 |
| `--help, -h` | - | - | show help |
| `--version, -v` | - | - | print the version |
<!-- END generated: flags -->

`-mode manual` unlocks `-nodelay`, `-interval`, `-resend` and `-nc`, and `-acknodelay` is accepted in
any mode: all five are hidden from `-h` exactly as in Go, and all five are printed in the startup
block.

`-tcp` needs `CAP_NET_RAW` and `iptables` and works on Linux only, exactly as in Go; it is
implemented but not yet verified in the lab, see [Status](status.md).

Two environment variables matter and have no flag:

| Variable | Effect |
|---|---|
| `KCPTUN_KEY` | The pre-shared secret, exactly as in Go. |
| `GOMAXPROCS` | Number of worker threads, read with Go's own rules (a decimal `int32` greater than zero; anything else is ignored). Unset means one per available CPU. In a container with a *fractional* CPU limit this lands lower than Go's count, which rounds the cgroup limit up and never goes below 2: set `GOMAXPROCS` explicitly there if it matters. |

`GOGC` does nothing: there is no garbage collector. The [tuning guide](tuning.md#memory)
explains what bounds memory instead.

See also: [tuning](tuning.md) for what to set and why · [differences from Go](differences.md) ·
[example configurations](../dist/README.md).
