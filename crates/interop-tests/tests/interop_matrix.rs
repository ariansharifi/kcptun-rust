//! The Go↔Rust interop matrix (plan step 09.4).
//!
//! | Test | Runs |
//! |---|---|
//! | `interop_matrix_smoke` | the default case in all four pairings, small workload — checks the harness in about ten seconds |
//! | `interop_matrix_full` | every case of [`all_cases`] in all four pairings, the plan's workload, and writes the report |
//!
//! Both are `#[ignore]`, like the rest of this crate: they need the Go reference binaries **and**
//! our own release build.
//!
//! ```sh
//! cargo build --release -p kcptun-client -p kcptun-server
//! tools/fetch-reference.sh --skip-latest --skip-tests
//! cargo test -p kcptun-interop-tests --test interop_matrix -- --ignored --nocapture interop_matrix_full
//! ```
//!
//! The trailing test name matters: libtest runs tests in parallel, so without it
//! `interop_matrix_smoke` runs *alongside* the full matrix and each measures the other.
//!
//! | Environment variable | Effect |
//! |---|---|
//! | `KCPTUN_INTEROP_MATRIX_FILTER` | run only the cases whose id contains this (e.g. `pair/07`, `crypt/sm4`) |
//! | `KCPTUN_INTEROP_MATRIX_OUT` | write the Markdown report to this path — honoured only by a complete `interop_matrix_full` run at the `full` workload, so a filtered or smoke run cannot overwrite the committed document |
//! | `KCPTUN_INTEROP_MATRIX_WORKLOAD` | `full` (default) or `smoke` — the lighter one is for lab-arm64, which has 2 shared vCPUs |
//! | `KCPTUN_GO_BIN_DIR` / `KCPTUN_RS_BIN_DIR` | where to find the binaries |
//!
//! The whole matrix runs **one tunnel at a time**: the workload is heavy enough that two
//! concurrent cases would measure the laptop rather than the protocol, and serialising also keeps
//! the macOS file-descriptor race that `kcptun_testkit::proc` documents closed. Every process is
//! a `Proc` and is killed and reaped when its `Tunnel` is dropped, including on the panic and
//! timeout paths, so a failing matrix leaves nothing behind.

use std::time::Instant;

use kcptun_interop_tests::interop_matrix::{
    CaseResult, FULL, InteropCase, PAIRINGS, SMOKE, Workload, all_cases, case_table, crypt_cases,
    report, result_table, run_case, select,
};

/// Environment variable naming the cases to run (substring of the case id).
const FILTER_ENV: &str = "KCPTUN_INTEROP_MATRIX_FILTER";
/// Environment variable naming where to write the Markdown report.
const OUT_ENV: &str = "KCPTUN_INTEROP_MATRIX_OUT";
/// Environment variable selecting the workload: `full` (the default) or `smoke`.
const WORKLOAD_ENV: &str = "KCPTUN_INTEROP_MATRIX_WORKLOAD";

/// The workload `interop_matrix_full` runs.
///
/// It is [`FULL`] unless `KCPTUN_INTEROP_MATRIX_WORKLOAD=smoke`, which trades traffic for time:
/// the matrix also runs on lab-arm64, a **2-vCPU box shared with live tunnels**, where 128 runs of
/// 40 MB plus 100 streams each would saturate it for far longer than `tools/lab/README.md` allows. The
/// case list, the pairings and every check are identical either way — only the byte counts move.
fn workload_from_env() -> &'static Workload {
    match std::env::var(WORKLOAD_ENV).unwrap_or_default().trim() {
        "" | "full" => &FULL,
        "smoke" => &SMOKE,
        other => panic!("{WORKLOAD_ENV}={other:?}: expected `full` or `smoke`"),
    }
}

/// Runs `cases` in every pairing, printing a line per run, and returns every outcome.
///
/// A failing run does **not** stop the matrix: the point of the exercise is the whole table, and
/// one broken combination should not hide the other 140. Every failure is printed in full (with
/// the case's exact configuration) as it happens, and again at the end.
async fn run_all(cases: &[InteropCase], workload: &Workload) -> Vec<CaseResult> {
    let mut results = Vec::with_capacity(cases.len() * PAIRINGS.len());
    let started = Instant::now();
    for (n, case) in cases.iter().enumerate() {
        for pairing in PAIRINGS {
            let outcome = run_case(case, pairing, workload).await;
            match &outcome {
                Ok(r) => println!(
                    "[{:3}/{}] {:<24} {pairing}  {:>6.1}s  {}",
                    n + 1,
                    cases.len(),
                    case.id,
                    r.elapsed.as_secs_f64(),
                    r.detail()
                ),
                Err(e) => println!(
                    "[{:3}/{}] {:<24} {pairing}  FAILED\n{e}",
                    n + 1,
                    cases.len(),
                    case.id
                ),
            }
            results.push(CaseResult {
                case_id: case.id.clone(),
                pairing,
                outcome,
            });
        }
    }
    println!(
        "{} runs in {:.1}s",
        results.len(),
        started.elapsed().as_secs_f64()
    );
    results
}

/// Prints the report, writes it to `KCPTUN_INTEROP_MATRIX_OUT` if that is set *and* `complete`
/// says this run is one the document may be regenerated from, and panics unless every run passed.
///
/// `report` replaces this platform's whole section, so a partial run must not be allowed to
/// write: `KCPTUN_INTEROP_MATRIX_FILTER=pair/07` would otherwise cut a 32-row section down to
/// one, and the smoke test would replace it with four rows of a lighter workload.
fn finish(results: &[CaseResult], workload: &Workload, complete: bool) {
    let out = std::env::var_os(OUT_ENV).filter(|v| !v.is_empty());
    let out = match (out, complete) {
        (Some(path), true) => Some(path),
        (Some(_), false) => {
            println!(
                "{OUT_ENV} ignored: only a complete `interop_matrix_full` run at the `full` \
                 workload may rewrite the report (this run is filtered or lighter)"
            );
            None
        }
        (None, _) => None,
    };
    // `report` keeps the other platforms' sections of an existing document, so a macOS run does
    // not throw away the lab-arm64 run recorded next to it (and vice versa).
    let existing = out
        .as_ref()
        .and_then(|path| std::fs::read_to_string(path).ok());
    let body = report(existing.as_deref(), results, workload);
    if let Some(path) = &out {
        std::fs::write(path, &body)
            .unwrap_or_else(|e| panic!("writing {}: {e}", std::path::Path::new(path).display()));
        println!("report written to {}", std::path::Path::new(path).display());
    }
    println!("\n{body}");

    let failed: Vec<&CaseResult> = results.iter().filter(|r| !r.passed()).collect();
    assert!(
        !results.is_empty(),
        "no cases ran; is {FILTER_ENV} too narrow?"
    );
    if failed.is_empty() {
        return;
    }
    let controls = failed.iter().filter(|r| r.pairing.is_control()).count();
    let mut msg = format!(
        "{} of {} interop runs failed ({controls} of them controls).\n",
        failed.len(),
        results.len()
    );
    if controls > 0 {
        msg.push_str(
            "A control (go->go, rs->rs) failing means THIS HARNESS is wrong, not the port: \
             go->go runs no Rust at all. Fix the harness before touching crates/client or \
             crates/server.\n",
        );
    }
    for f in failed {
        if let Err(e) = &f.outcome {
            msg.push_str(&format!("\n{e}\n"));
        }
    }
    panic!("{msg}");
}

/// The cases this run covers, after `KCPTUN_INTEROP_MATRIX_FILTER`.
fn filtered(cases: Vec<InteropCase>) -> Vec<InteropCase> {
    let filter = std::env::var(FILTER_ENV).unwrap_or_default();
    let cases = select(cases, filter.trim());
    assert!(
        !cases.is_empty(),
        "{FILTER_ENV}={filter:?} matches no case; the full list is:\n{}",
        case_table()
    );
    cases
}

/// A quick check of the harness itself: kcptun's defaults, all four pairings, a small workload.
///
/// Run this first when the full matrix misbehaves — if `go->go` is red here, nothing in
/// `crates/` is implicated.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the Go reference binaries and `cargo build --release -p kcptun-client -p kcptun-server`"]
async fn interop_matrix_smoke() {
    let cases = vec![crypt_cases().remove(0)];
    let results = run_all(&cases, &SMOKE).await;
    assert_eq!(results.len(), PAIRINGS.len());
    // Never writes the report: one case at the smoke workload is not what the document records.
    finish(&results, &SMOKE, false);
}

/// The plan's matrix: 15 crypt modes at the defaults, the pairwise expansion of every other
/// dimension, and the fixed production profile — each in all four pairings, with 20 MB each way,
/// 100 concurrent streams and the half-close probe.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "the full matrix: needs both implementations' binaries and takes several minutes"]
async fn interop_matrix_full() {
    let all = all_cases();
    let cases = filtered(all.clone());
    // Only an unfiltered run at the full workload may rewrite `docs/interop-matrix.md`.
    let complete = cases.len() == all.len() && *workload_from_env() == FULL;
    println!(
        "{} cases x {} pairings\n{}",
        cases.len(),
        PAIRINGS.len(),
        case_table()
    );
    let workload = workload_from_env();
    let results = run_all(&cases, workload).await;
    finish(&results, workload, complete);
}

/// The case list is a committed artefact (`docs/interop-matrix.md`), so it must be printable and
/// stable without running anything. This test needs no binaries and is therefore not ignored.
#[test]
fn interop_matrix_case_list_is_printable() {
    let table = case_table();
    print!("{table}");
    assert_eq!(table.lines().count(), all_cases().len() + 2);
    assert_eq!(case_table(), table, "the case list is deterministic");
    // The empty report still renders, so a run that dies before its first case still says so.
    let empty = result_table(&[]);
    assert_eq!(empty.lines().count(), 2, "header and separator only");
}
