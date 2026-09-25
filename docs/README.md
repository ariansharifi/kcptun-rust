# Documentation

| Document | What it covers |
|---|---|
| [tuning.md](tuning.md) | Throughput, latency, head-of-line blocking, FEC, pacing, choosing a cipher, memory, slow devices, SNMP, profiling |
| [troubleshooting.md](troubleshooting.md) | What the common failures look like, and what each message means |
| [interop-matrix.md](interop-matrix.md) | Go ↔ Rust interop results per platform: the cases, the binaries, the workloads, and how to regenerate them |
| [benchmarks/REPORT.md](benchmarks/REPORT.md) | **The performance report.** Go vs Rust end to end, under impairment, over a real path and over six hours of churn — the short answer, then every caveat and every unmeasured row |
| [benchmarks/crypto.md](benchmarks/crypto.md) | Packet encryption and decryption for the 14 `-crypt` modes that have a cipher (`null` installs none), Rust vs Go, on two machines |
| [benchmarks/fec.md](benchmarks/fec.md) | FEC and Reed-Solomon per-packet and per-group costs, Rust vs Go |
| [benchmarks/kcp.md](benchmarks/kcp.md) | The KCP ARQ core: `flush`, ACK input, send/flush round trips |
| [benchmarks/session.md](benchmarks/session.md) | The KCP session layer end to end over loopback: throughput and CPU per GB, Rust vs Go |
| [benchmarks/smux.md](benchmarks/smux.md) | The smux multiplexer over TCP: throughput cross-matrix and memory per idle stream |
| [benchmarks/memory.md](benchmarks/memory.md) | Memory: idle RSS, peak under load, per idle session and per idle stream, and what is given back afterwards |
| [benchmarks/micro.md](benchmarks/micro.md) | The micro-benchmark index: one headline per layer, and what each page is *not* evidence for |
| [benchmarks/2026-09-24-lab-arm64-netns-clean.md](benchmarks/2026-09-24-lab-arm64-netns-clean.md) | Go vs Rust end to end on a real tunnel, **aarch64, 2 vCPU** — the Step 12.1 baseline on the deployment architecture |
| [benchmarks/2026-09-24-lab-x86-1-netns-clean-s1-sockbuf.md](benchmarks/2026-09-24-lab-x86-1-netns-clean-s1-sockbuf.md) | **The current S1 grid on x86_64, 1 vCPU** — re-taken in 12.1b on a host that can honour `-sockbuf`; supersedes the `s1` half of the page below |
| [benchmarks/2026-09-24-lab-x86-1-netns-clean.md](benchmarks/2026-09-24-lab-x86-1-netns-clean.md) | The same grid on **x86_64, 1 vCPU** — the Step 12.1 baseline on a box with no headroom. Its **`s1` half is withdrawn** (taken at a stock socket-buffer ceiling, docs/DECISIONS.md D32); its `s2` half stands |
| [benchmarks/2026-09-24-lab-x86-1-netns-clean-s2-control.md](benchmarks/2026-09-24-lab-x86-1-netns-clean-s2-control.md) | The one-cell control that checked the `s2` half rather than assuming it |
| [lab-results/](lab-results/README.md) | Lab sessions: the netem impairment matrix, the WAN matrix over the real RTT ladder, the six-hour soak and the allocator comparison |
| [porting-guide.md](porting-guide.md) | How the port is written: source of truth, fidelity rules, provenance comments, error and integer semantics, safety, test conventions |
| [DECISIONS.md](DECISIONS.md) | The register: every architecture decision (D-xx) and every intentional behaviour deviation from Go (V-xx), with its evidence |
| [WIRE-FORMAT.md](WIRE-FORMAT.md) | The byte-level protocol reference, extracted from the Go source |

Elsewhere in the repository:

* [../README.md](../README.md) — what this is, compatibility, quickstart, flags, differences from
  Go, performance, licence.
* [../CHANGELOG.md](../CHANGELOG.md) — what has changed.
* [../dist/README.md](../dist/README.md) — service files, sysctl, example configurations, the
  container image.
* [../tools/lab/README.md](../tools/lab/README.md) — the lab harness: the hosts, the binding safety
  rules and how a campaign is run.

Benchmark reports state their machines, their method and their date; read those before quoting a
number. None of them is a claim about hardware they were not measured on.
