//! Runs `tools/bench/bench_test.py` as part of the cargo gate (`tool_*`, docs/porting-guide.md §8).
//!
//! Same reasoning as [`lab_py`](./lab_py.rs): `tools/bench/bench.py` decides which benchmark runs
//! happen and then turns their files into the page a performance claim is quoted from, and it is
//! python, so `cargo test` would never see it. Its suite substitutes written-by-hand run
//! directories for a lab host and touches nothing over ssh.
//!
//! It is skipped, not failed, where there is no `python3`: the gate must stay runnable on a
//! machine that has a Rust toolchain and nothing else.

use std::path::Path;
use std::process::Command;

#[test]
fn tool_bench_py_test_suite_passes() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("tools/pingpong lives two levels below the repository root")
        .to_path_buf();
    let suite = repo.join("tools/bench/bench_test.py");
    assert!(suite.is_file(), "missing {}", suite.display());

    let output = match Command::new("python3").arg(&suite).output() {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping: no python3 on PATH");
            return;
        }
        Err(err) => panic!("could not run python3 {}: {err}", suite.display()),
    };
    assert!(
        output.status.success(),
        "python3 {} failed ({})\n--- stdout ---\n{}\n--- stderr ---\n{}",
        suite.display(),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
