//! Runs the lab's python suites as part of the cargo gate (`tool_*`, docs/porting-guide.md §8).
//!
//! `lab.py`, `failure.py` and `deploy.sh` decide what a six-hour soak runs, on which host and
//! for which architecture, and they are python and bash, so `cargo test` never saw them. That
//! gap has already cost something real: `lab_test.py` kept asserting `closewait 0` for the soak
//! after DECISIONS D28 changed the scenario to the production default, and nothing noticed,
//! because nothing ran the file. This test closes the loop: the python suites are now part of
//! the gate, and their fake-ssh `Runner` means they still touch no host.
//!
//! They are skipped, not failed, where there is no `python3`: the gate must stay runnable on a
//! machine that has a Rust toolchain and nothing else.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The repository root, two levels above `tools/pingpong`.
fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("tools/pingpong lives two levels below the repository root")
        .to_path_buf()
}

/// Runs one `unittest` suite, or returns without failing when there is no `python3`.
fn run_suite(relative: &str) {
    let suite = repo().join(relative);
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

#[test]
fn tool_lab_py_test_suite_passes() {
    run_suite("tools/lab/lab_test.py");
}

/// Step 11.5's driver: the only thing in the lab that kills a running tunnel on purpose, and the
/// one whose answers ("recovery took 57 s") are arithmetic over a CSV rather than a number
/// somebody read off a screen.
#[test]
fn tool_failure_py_test_suite_passes() {
    run_suite("tools/lab/failure_test.py");
}
