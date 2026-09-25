//! Tests for [`super`]: Go's `syscall.Errno` error table (DECISIONS D30).

use std::io;

use kcptun_testkit::vectors;
use serde::Deserialize;

use super::{
    HEAD, TAIL, errno_error, errno_text, go_error_text, has_table, platform_error_text, table,
    table_len,
};

/// One case of `testdata/vectors/errno.json`: one GOOS/GOARCH pair's table.
#[derive(Debug, Deserialize)]
struct ErrnoCase {
    name: String,
    goos: String,
    goarch: String,
    errors: Vec<String>,
    probes: Vec<Probe>,
}

/// One `syscall.Errno(errno).Error()` the generator recorded.
#[derive(Debug, Deserialize)]
struct Probe {
    errno: i32,
    text: String,
}

fn cases() -> Vec<ErrnoCase> {
    let file = vectors!("errno");
    assert!(!file.is_empty(), "the errno area has no cases");
    file.cases.iter().map(|c| c.to::<ErrnoCase>()).collect()
}

/// Every table in `table.rs` is Go's, for every platform — not only the host's. The tables of
/// the targets this host cannot run are the reason this check does not use `cfg!`: a wrong
/// Linux entry has to fail the macOS gate too, which is exactly how the musl defect of 10.5
/// escaped in the first place.
#[test]
fn vectors_errno_tables() {
    let cases = cases();
    let ours = table::all();
    assert_eq!(
        ours.len(),
        cases.len(),
        "table::all() covers {:?}, the vector file has {:?}",
        ours.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
        cases.iter().map(|c| c.name.as_str()).collect::<Vec<_>>()
    );
    for (case, (name, got)) in cases.iter().zip(ours.iter()) {
        assert_eq!(case.name, *name, "table::all() is out of order");
        assert_eq!(
            case.name,
            format!("{}/{}", case.goos, case.goarch),
            "case name does not match its goos/goarch"
        );
        assert_eq!(
            got.len(),
            case.errors.len(),
            "{name}: table has {} entries, Go has {}",
            got.len(),
            case.errors.len()
        );
        for (errno, (mine, theirs)) in got.iter().zip(case.errors.iter()).enumerate() {
            assert_eq!(mine, theirs, "{name}: errno {errno}");
        }
    }
}

/// The vector file pins the one entry the musl defect was about, on the platform it was found
/// on, so that a regenerated table that quietly lost it fails here with the reason attached.
#[test]
fn eaddrinuse_is_gos_wording_on_every_platform() {
    for case in cases() {
        // Linux EADDRINUSE is 98, BSD's (macOS, FreeBSD) is 48.
        let errno = if case.goos == "linux" { 98 } else { 48 };
        assert_eq!(
            case.errors[errno], "address already in use",
            "{}: errno {errno}",
            case.name
        );
    }
}

/// `errno_error` is Go's `(Errno).Error()`, numeric fallback included, for every platform's
/// probe list — replayed against the host's own table, so the host's case is the live one and
/// the others only confirm the fallback shape.
#[test]
fn vectors_errno_error_matches_go() {
    let host = host_case().expect("this host's platform is in the vector file");
    for probe in &host.probes {
        assert_eq!(
            errno_error(probe.errno).as_deref(),
            Some(probe.text.as_str()),
            "errno {}",
            probe.errno
        );
    }
    // Every entry of the host's table, not only the probed ones.
    for (errno, want) in host.errors.iter().enumerate() {
        let errno = i32::try_from(errno).expect("table index fits in i32");
        if want.is_empty() {
            assert_eq!(errno_text(errno), None, "errno {errno} should be a hole");
            assert_eq!(
                errno_error(errno).as_deref(),
                Some(&*format!("errno {errno}"))
            );
        } else {
            assert_eq!(errno_text(errno), Some(want.as_str()), "errno {errno}");
            assert_eq!(errno_error(errno).as_deref(), Some(want.as_str()));
        }
    }
}

/// The host's own case, or `None` on a platform whose table is not carried.
fn host_case() -> Option<ErrnoCase> {
    let goos = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "freebsd") {
        "freebsd"
    } else {
        return None;
    };
    let goarch = if cfg!(target_arch = "x86_64") {
        "amd64"
    } else if cfg!(target_arch = "x86") {
        "386"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "arm") {
        "arm"
    } else {
        return None;
    };
    let name = format!("{goos}/{goarch}");
    cases().into_iter().find(|c| c.name == name)
}

/// The `cfg` selection picks the host's own table out of `table.rs`: `HEAD` and `TAIL` together
/// are exactly the vector's, entry for entry. Without this, a target could compile with an
/// empty table and silently keep the libc text.
#[test]
fn the_selected_table_is_this_targets() {
    match host_case() {
        Some(case) => {
            assert!(has_table(), "{}: no table selected", case.name);
            assert_eq!(table_len(), case.errors.len(), "{}", case.name);
            let joined: Vec<&str> = HEAD.iter().chain(TAIL.iter()).copied().collect();
            assert_eq!(joined, case.errors, "{}", case.name);
        }
        None => {
            // A platform D22 does not list: the libc text, as before (module docs).
            assert!(!has_table());
            assert_eq!(table_len(), 0);
            assert_eq!(errno_error(1), None);
        }
    }
}

/// A failed `bind(2)` reads the way Go reads it — the assertion that fails on a static musl
/// build without D30's table, and the reason this sub-step exists.
#[test]
fn a_syscall_error_is_spelled_from_gos_table() {
    if !has_table() {
        return;
    }
    let eaddrinuse = if cfg!(target_os = "linux") { 98 } else { 48 };
    assert_eq!(
        go_error_text(&io::Error::from_raw_os_error(eaddrinuse)),
        "address already in use"
    );

    let einval = 22;
    assert_eq!(
        go_error_text(&io::Error::from_raw_os_error(einval)),
        "invalid argument"
    );
    // EPERM: what a `--tcp` client without CAP_NET_RAW gets from socket(AF_INET, SOCK_RAW, …).
    assert_eq!(
        go_error_text(&io::Error::from_raw_os_error(1)),
        "operation not permitted"
    );
    // EACCES, ECONNREFUSED and ENOENT round out what the binaries actually report.
    let (eacces, econnrefused, enoent) = (13, if cfg!(target_os = "linux") { 111 } else { 61 }, 2);
    assert_eq!(
        go_error_text(&io::Error::from_raw_os_error(eacces)),
        "permission denied"
    );
    assert_eq!(
        go_error_text(&io::Error::from_raw_os_error(econnrefused)),
        "connection refused"
    );
    assert_eq!(
        go_error_text(&io::Error::from_raw_os_error(enoent)),
        "no such file or directory"
    );
}

/// An errno Go's table does not name takes **Go's** numeric fallback, not the C library's
/// `Unknown error N`.
#[test]
fn an_unnamed_errno_takes_gos_numeric_fallback() {
    if !has_table() {
        return;
    }
    let past_end = i32::try_from(table_len()).expect("table length fits in i32");
    assert_eq!(
        go_error_text(&io::Error::from_raw_os_error(past_end)),
        format!("errno {past_end}")
    );
    assert_eq!(
        go_error_text(&io::Error::from_raw_os_error(4095)),
        "errno 4095"
    );
    // Go's array is sparse; index 0 is empty on every platform, so errno 0 is numeric too.
    assert_eq!(go_error_text(&io::Error::from_raw_os_error(0)), "errno 0");
    assert_eq!(errno_text(0), None);
    // A negative errno never indexes the array (Go: `0 <= int(e)`).
    assert_eq!(errno_text(-1), None);
    assert_eq!(errno_error(-1).as_deref(), Some("errno -1"));
}

/// Go's own tables keep an acronym capitalised, which the pre-D30 "lower-case the first letter"
/// rule corrupted. macOS is where this is visible: `EBADRPC` is `RPC struct is bad` in Go's
/// darwin table and `rPC struct is bad` through the old rule.
#[test]
fn an_acronym_keeps_its_case() {
    let darwin = cases()
        .into_iter()
        .find(|c| c.name == "darwin/arm64")
        .expect("darwin/arm64 case");
    assert_eq!(darwin.errors[72], "RPC struct is bad");
    assert_eq!(
        platform_error_text(&io::Error::other("RPC struct is bad")),
        "rPC struct is bad"
    );
    #[cfg(target_os = "macos")]
    assert_eq!(
        go_error_text(&io::Error::from_raw_os_error(72)),
        "RPC struct is bad"
    );
}

/// An error with no errno is not a `syscall.Errno` and keeps the pre-D30 rendering: Go has no
/// table entry to spell it from either.
#[test]
fn an_error_without_an_errno_keeps_the_platform_rendering() {
    assert_eq!(
        go_error_text(&io::Error::new(
            io::ErrorKind::InvalidInput,
            "Nothing to do"
        )),
        "nothing to do"
    );
    assert_eq!(
        go_error_text(&io::Error::from(io::ErrorKind::ConnectionRefused)),
        "connection refused"
    );
    assert_eq!(go_error_text(&io::Error::other("")), "");
    // The ` (os error N)` suffix only ever comes from an OS error, which the table now answers;
    // the stripper stays for the targets that carry no table.
    assert_eq!(
        platform_error_text(&io::Error::other("Address in use (os error 98)")),
        "address in use"
    );
    // A text that merely looks similar but is not closed is left alone.
    assert_eq!(
        platform_error_text(&io::Error::other("Broken (os error 98")),
        "broken (os error 98"
    );
}
