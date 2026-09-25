# Status

**Released and in use, but young.** Tagged releases exist, the container image is published to
[`ariyansharifi/kcptun-rust`](https://hub.docker.com/r/ariyansharifi/kcptun-rust), and CI runs on
every push. Nothing is on crates.io. Read the unfinished list below before adopting it for anything
you cannot afford to have break.

What is finished and tested:

| Area | State |
|---|---|
| KCP ARQ, FEC / Reed-Solomon, all 15 `-crypt` modes, smux v1 and v2, snappy, QPP | Ported and verified against golden vectors generated from the Go code |
| `kcptun-client` / `kcptun-server` | Complete: flags, JSON config, presets, logging, SNMP, signals, port ranges, Unix-socket targets |
| Go ↔ Rust interop | 128/128 runs green on macOS/arm64 and on Linux/aarch64 ([matrix](interop-matrix.md)) |
| Startup-log and CLI behaviour | Differential-tested against the Go binaries across 50 command lines, with a closed allow-list of known differences |
| Packaging | Cross-build script, Dockerfile, systemd units, sysctl drop-ins, example configurations |

What is **not** finished:

* **`-tcp` (fake TCP) is wired up but not yet verified.** The transport and both binaries' `-tcp`
  paths are complete: the client dials through it, the server adds a fake-TCP listener next to its
  UDP one, and the `filter/OUTPUT` rules are removed on every exit path but `SIGKILL` (which no
  process can catch; Go leaves the rules behind there too, and after a panic as well), but the
  privileged Linux tests (raw sockets, `iptables`, Go interop in `-tcp` mode) have not been run
  yet, so treat it as unverified.
  Off Linux nothing changes: Go's fake TCP is Linux-only and this port reports its `os not
  supported` in the same places. If you depend on `-tcp` in production, stay on Go for now.
* **Failure-mode testing.** The network-impairment matrix, the WAN runs and a six-hour soak are
  done ([lab results](lab-results/)); the deliberate failure-mode suite: peer restarts,
  half-open paths, clock jumps: is not.
* **The performance programme is partial, and knowing which parts is the point.** The measurements
  are real and end to end, but three of seven metric families, two of four configurations and 16 of
  28 impairment cells were never run, and idle CPU cost, startup time and the QPP scenario have no
  harness at all. [`docs/benchmarks/REPORT.md`](benchmarks/REPORT.md) says exactly what was
  measured, on what, and what was not.
* **Windows is not supported and not built.** This is a Linux project; macOS works and is the
  development host. Windows is not in the release archives, not in CI and not maintained.
