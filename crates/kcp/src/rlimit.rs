//! The open-file limit, which **the Go runtime raises by itself**, so Go kcptun gets it for
//! free and this port has to ask.
//!
//! Go source: `syscall/rlimit.go`, an `init()` that runs before `main`,
//!
//! ```go
//! func init() {
//!     var lim Rlimit
//!     if err := Getrlimit(RLIMIT_NOFILE, &lim); err == nil && lim.Cur != lim.Max {
//!         origRlimitNofile.Store(&lim)
//!         nlim := lim
//!         nlim.Cur = nlim.Max
//!         adjustFileLimit(&nlim)
//!         setrlimit(RLIMIT_NOFILE, &nlim)
//!     }
//! }
//! ```
//!
//! **D34, and it was a production incident before it was a decision.** A container started with
//! the common Docker `nofile` default (soft 1024, hard 1048576) gives a Go kcptun 1048576
//! descriptors and gave this port 1024, because nothing here asked. A busy server reaches that
//! ceiling: `-closewait` (30 s on the server, Go's default too) holds every finished connection
//! for thirty seconds, so a few tens of connections per second is a steady state of hundreds of
//! descriptors, and past the ceiling `accept` fails with `EMFILE` and the tunnel flaps. Nothing
//! about the port's own behaviour differed from Go's, only the limit it ran under.
//!
//! This is a *restoration* of Go's behaviour, not a deviation from it, so it has no V-number and
//! no flag: Go does it unconditionally and silently, and so does this. Errors are swallowed the
//! same way, so a process that may not raise its own limit still starts with whatever it was
//! given.

#[cfg(unix)]
use std::mem;

/// What [`raise_nofile`] did. Go's initialiser returns nothing and nothing here acts on this
/// value either: it exists so the behaviour can be tested and, if a caller ever wants it,
/// reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nofile {
    /// The soft limit already equalled the hard limit. Go's `lim.Cur != lim.Max` guard skips the
    /// `setrlimit` in this case too.
    AlreadyRaised { limit: u64 },
    /// The soft limit was raised from `from` to `to`.
    Raised { from: u64, to: u64 },
    /// `getrlimit` or `setrlimit` failed, or this is not a Unix platform. Go ignores the error
    /// and carries on; so does this.
    Unchanged,
}

/// Raises the open-file soft limit to the hard limit, as the Go runtime does before `main`.
///
/// Call it before anything opens a descriptor: the binaries call it first thing in `main`,
/// ahead of building the tokio runtime, which opens several of its own.
// Go: syscall/rlimit.go:init()
pub fn raise_nofile() -> Nofile {
    #[cfg(unix)]
    {
        // SAFETY: `libc::rlimit` is a plain struct of two integers, for which an
        // all-zero bit pattern is a valid value; `getrlimit` overwrites it anyway.
        let mut lim: libc::rlimit = unsafe { mem::zeroed() };
        // SAFETY: `getrlimit` writes one `struct rlimit` through the pointer, which points at a
        // live local of exactly that type.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut lim) } != 0 {
            return Nofile::Unchanged;
        }
        let (cur, max) = (lim.rlim_cur as u64, lim.rlim_max as u64);
        let Some(target) = nofile_target(cur, max, max_files_per_proc()) else {
            return Nofile::AlreadyRaised { limit: cur };
        };
        lim.rlim_cur = target as libc::rlim_t;
        // SAFETY: as above; `setrlimit` only reads the struct.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const lim) } != 0 {
            return Nofile::Unchanged;
        }
        Nofile::Raised {
            from: cur,
            to: target,
        }
    }
    #[cfg(not(unix))]
    Nofile::Unchanged
}

/// The soft limit to ask for, or `None` when Go's `lim.Cur != lim.Max` guard skips the call.
///
/// `max_per_proc` is macOS's `kern.maxfilesperproc` and `None` elsewhere. Go applies it only as
/// a ceiling, never a floor, so a hard limit already below it is left alone.
fn nofile_target(cur: u64, max: u64, max_per_proc: Option<u64>) -> Option<u64> {
    if cur == max {
        return None;
    }
    let target = match max_per_proc {
        Some(cap) if max > cap => cap,
        _ => max,
    };
    // The clamp can land on, or below, where we already are. Asking for that is a wasted syscall
    // at best and a *lowering* at worst, so it is skipped. Go cannot reach this case: it clamps
    // only a hard limit of `RLIM_INFINITY`, which is above every soft limit there is.
    (target > cur).then_some(target)
}

/// macOS's `kern.maxfilesperproc`, the ceiling Go clamps to because the hard limit there is
/// usually `RLIM_INFINITY` and `setrlimit` refuses it; `None` on every other platform, and
/// whenever the sysctl cannot be read.
// Go: syscall/rlimit_darwin.go:adjustFileLimit()
fn max_files_per_proc() -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        let mut value: libc::c_int = 0;
        let mut len = mem::size_of::<libc::c_int>();
        // SAFETY: the name is a NUL-terminated literal, and the out pointer and its length
        // describe the same live `c_int`. A `newp` of null means "read, do not write".
        let rc = unsafe {
            libc::sysctlbyname(
                c"kern.maxfilesperproc".as_ptr(),
                (&raw mut value).cast::<libc::c_void>(),
                &raw mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        (rc == 0 && value > 0).then_some(value as u64)
    }
    #[cfg(not(target_os = "macos"))]
    None
}

#[cfg(test)]
#[path = "rlimit/tests.rs"]
mod tests;
