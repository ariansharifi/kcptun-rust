//! Loopback echo throughput and CPU baseline of the KCP session layer (plan step 05.9).
//!
//! `#[ignore]` like the rest of the interop suite: it needs the Go `kcpecho` binary of
//! `tools/fetch-reference.sh`, it takes a few minutes, and its numbers only mean something on an
//! otherwise idle machine.
//!
//! ```sh
//! cargo test -p kcptun-interop-tests --release --test kcp_echo_bench -- --ignored --nocapture
//! ```
//!
//! It measures the two profiles of [`echo_bench::profiles`] at the two message sizes of
//! [`echo_bench::MESSAGE_SIZES`] and the two payloads of [`echo_bench::DEFAULT_PAYLOADS`],
//! alternating Rust and Go run by run so that both see the same background load, and prints
//! every run, a median table and the spread behind those medians. Configuration (all optional):
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `KCPTUN_BENCH_BYTES` | `8388608,33554432` | comma-separated payloads echoed per run |
//! | `KCPTUN_BENCH_REPEAT` | 3 | runs per (implementation, profile, payload, size) |
//!
//! More than one payload is measured because the production profile used to have a degradation
//! band: a tx-channel overrun that cost a retransmission timeout per dropped packet, worst at
//! 8 MiB and, on lab-arm64's 2 vCPU aarch64, still 0.70-0.77x Go at 32 MiB after 05.10 had
//! widened the channel. Backpressure in `Kcp::flush` (12.2a, Deviation V18) removed it: 32 MiB
//! now runs at 1.02-1.38x Go there and 2.63-2.83x on macOS. Both payloads stay in the sweep as
//! the regression test for that band, and [`DEFAULT_PAYLOADS`] has both hosts' tables. The
//! default profile never stalled. Wall time is reported as a median *with its min and max*
//! because on a loaded machine the run-to-run spread is of the same order as the
//! Rust-versus-Go difference; CPU per GB is the stable metric, and it compares the two
//! implementations within one host only.
//!
//! The full Go-versus-Rust write-up is Step 12's job (docs/porting-guide.md §10, review and
//! verification policy); this is the informative baseline for it.

use std::path::PathBuf;
use std::time::Duration;

use kcptun_interop_tests::echo_bench::{
    DEFAULT_PAYLOADS, DEFAULT_REPEATS, MESSAGE_SIZES, Measurement, comparison_table, measure_go,
    measure_rust, profiles, size_label, spread_table,
};
use kcptun_interop_tests::go_bin;

/// Payloads per run, overridable with a comma-separated `KCPTUN_BENCH_BYTES`.
fn payloads() -> Vec<u64> {
    let Some(raw) = env_var("KCPTUN_BENCH_BYTES") else {
        return DEFAULT_PAYLOADS.to_vec();
    };
    let list: Vec<u64> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse()
                .unwrap_or_else(|e| panic!("KCPTUN_BENCH_BYTES={raw:?}: {s:?}: {e}"))
        })
        .collect();
    assert!(
        !list.is_empty(),
        "KCPTUN_BENCH_BYTES={raw:?} names no payload",
    );
    list
}

/// Runs per combination, overridable with `KCPTUN_BENCH_REPEAT`.
fn repeats() -> usize {
    match env_var("KCPTUN_BENCH_REPEAT") {
        None => DEFAULT_REPEATS,
        Some(raw) => raw
            .trim()
            .parse::<u64>()
            .unwrap_or_else(|e| panic!("KCPTUN_BENCH_REPEAT={raw:?}: {e}"))
            .max(1) as usize,
    }
}

fn env_var(name: &str) -> Option<String> {
    let raw = std::env::var(name).ok()?;
    if raw.trim().is_empty() {
        return None;
    }
    Some(raw)
}

fn kcpecho_bin() -> PathBuf {
    go_bin("kcpecho").unwrap_or_else(|e| panic!("{e}"))
}

#[test]
#[ignore = "benchmark: needs the Go kcpecho binary and an idle machine"]
fn interop_kcp_echo_throughput_and_cpu_baseline() {
    let bin = kcpecho_bin();
    let (payloads, repeats) = (payloads(), repeats());
    // One runtime for every Rust run: the sessions spawn their own tasks, and the CPU reading
    // covers the whole process, so nothing else may run on it.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    println!(
        "\nkcp echo baseline: payload(s) {}, {repeats} run(s) per combination, \
         {} profile(s) x {} message size(s), rust and go alternating\n",
        payloads
            .iter()
            .map(|b| size_label(*b))
            .collect::<Vec<_>>()
            .join(", "),
        profiles().len(),
        MESSAGE_SIZES.len(),
    );

    let mut measurements: Vec<Measurement> = Vec::new();
    for round in 1..=repeats {
        for profile in profiles() {
            for bytes in &payloads {
                for chunk in MESSAGE_SIZES {
                    let rust = rt
                        .block_on(measure_rust(&profile, chunk, *bytes))
                        .unwrap_or_else(|e| panic!("round {round}: {e}"));
                    println!("  {rust}");
                    let go = measure_go(&bin, &profile, chunk, *bytes)
                        .unwrap_or_else(|e| panic!("round {round}: {e}"));
                    println!("  {go}");
                    measurements.push(rust);
                    measurements.push(go);
                    // A short pause keeps a finished run's sockets and tasks out of the next one.
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
    }

    println!("\n{}", comparison_table(&measurements));
    println!("{}", spread_table(&measurements));
    println!(
        "profiles: {}",
        profiles()
            .iter()
            .map(|p| format!("{} = {}", p.name, p.case.label()))
            .collect::<Vec<_>>()
            .join("; ")
    );
    println!(
        "payload counted once per direction; the link carries it once each way per run. \
         Wall time is noisy run to run: read the min-max columns before the medians; \
         CPU per GB is the stable metric.\n"
    );

    let expected = repeats * profiles().len() * payloads.len() * MESSAGE_SIZES.len() * 2;
    assert_eq!(
        measurements.len(),
        expected,
        "every run must have produced a measurement"
    );
    assert!(
        measurements.iter().all(|m| m.mib_per_sec() > 0.0),
        "a run with no measurable duration means the harness, not the port, is being measured",
    );
}
