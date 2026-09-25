//! Tests of the open-file limit (D34).
//!
//! The pure decision ([`nofile_target`]) is tested exhaustively; the syscall half is tested
//! once, for the property that actually matters in production: after the call the soft limit is
//! not below what it was, and on a host whose hard limit is higher it has reached it.

use super::*;

/// Go's `lim.Cur != lim.Max` guard: nothing to do when the soft limit is already the hard one.
// Go: syscall/rlimit.go:init()
#[test]
fn an_already_raised_limit_is_left_alone() {
    assert_eq!(nofile_target(1024, 1024, None), None);
    assert_eq!(nofile_target(1_048_576, 1_048_576, None), None);
    // Even with a macOS cap in play, an equal pair is Go's early exit.
    assert_eq!(nofile_target(10_240, 10_240, Some(10_240)), None);
}

/// The production case, and the one that caused the incident: Docker's soft 1024 against a hard
/// limit three orders of magnitude higher.
#[test]
fn the_docker_default_is_raised_to_the_hard_limit() {
    assert_eq!(nofile_target(1024, 1_048_576, None), Some(1_048_576));
}

/// macOS's hard limit is `RLIM_INFINITY`, which `setrlimit` refuses; Go clamps to
/// `kern.maxfilesperproc`, and the clamp is a ceiling only: a hard limit below it is taken as
/// it stands.
// Go: syscall/rlimit_darwin.go:adjustFileLimit()
#[test]
fn the_darwin_cap_is_a_ceiling_and_not_a_floor() {
    assert_eq!(nofile_target(256, u64::MAX, Some(10_240)), Some(10_240));
    // A hard limit under the cap is not raised *to* the cap.
    assert_eq!(nofile_target(256, 4096, Some(10_240)), Some(4096));
    // Nor is a soft limit already above it lowered to it. Go cannot reach this case; this port
    // refuses to be the one that lowers a limit.
    assert_eq!(nofile_target(65_536, u64::MAX, Some(10_240)), None);
    assert_eq!(nofile_target(10_240, u64::MAX, Some(10_240)), None);
}

/// The syscall half, over the real process: raising is idempotent and never lowers. Whatever the
/// host's limits are, a second call must report the first one's result as already done.
#[test]
#[cfg(unix)]
fn raising_is_idempotent_and_never_lowers() {
    let before = soft_limit().expect("getrlimit must work on a Unix host");

    let first = raise_nofile();
    let after = soft_limit().expect("getrlimit");
    assert!(
        after >= before,
        "the soft limit must never go down: {before} -> {after}"
    );
    match first {
        Nofile::Raised { from, to } => {
            assert_eq!(from, before);
            assert_eq!(to, after);
            assert!(to > from);
        }
        Nofile::AlreadyRaised { limit } => assert_eq!(limit, before),
        // A sandbox may forbid `setrlimit`; that is Go's silent path too, not a failure.
        Nofile::Unchanged => return,
    }

    // Idempotent: the limit has reached the ceiling, so the second call has nothing to do.
    assert_eq!(raise_nofile(), Nofile::AlreadyRaised { limit: after });
    assert_eq!(soft_limit().expect("getrlimit"), after);
}

#[cfg(unix)]
fn soft_limit() -> Option<u64> {
    // SAFETY: as in `raise_nofile` - an all-zero `rlimit` is a valid value.
    let mut lim: libc::rlimit = unsafe { mem::zeroed() };
    // SAFETY: as in `raise_nofile`.
    (unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut lim) } == 0)
        .then_some(lim.rlim_cur as u64)
}
