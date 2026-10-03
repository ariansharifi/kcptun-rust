//! How much of what a process wrote into a stream socket its peer has not consumed yet.
//!
//! The proxy pipe (`kcptun_std::pipe`, DECISIONS D35) needs this to tell a reader that is slow
//! from one that has stopped. A write into a TCP socket completes only when the kernel has room
//! for it, and `EPOLLOUT` is raised again only once about a third of the send buffer has drained
//! (`sk_stream_is_writeable`), so with a 4 MiB send buffer a reader at 30 KiB/s lets a write
//! complete about once every 40 seconds. The kernel's own count of unacknowledged and unsent
//! bytes moves with every window the reader reopens, which is fine enough to see it alive.
//!
//! Go kcptun has nothing like this; nothing on the wire depends on it.
//!
//! | Platform | Call | What it counts |
//! |---|---|---|
//! | Linux | `ioctl(SIOCOUTQ)` (`TIOCOUTQ` in `libc`) | TCP: `write_seq - snd_una`, unacked plus unsent (plus 1 for a queued FIN). Unix stream: bytes the reader has not consumed, in skb truesize |
//! | macOS | `getsockopt(SO_NWRITE)` | TCP: unacked plus unsent. Unix stream: always 0, since the data lives in the reader's queue |
//! | FreeBSD | `ioctl(FIONWRITE)` | unsent and unacked bytes in the send buffer |
//!
//! Elsewhere the answer is "unknown", and the pipe falls back to what it sees of its own writes.

use std::io;
#[cfg(unix)]
use std::os::fd::BorrowedFd;

/// The number of bytes queued in a connected stream socket's send buffer that the peer has not
/// consumed: for TCP, data not yet acknowledged; for a unix stream socket, data its reader has
/// not read (on Linux; macOS always reports 0 there).
///
/// `Ok(None)` means the platform has no way to ask.
#[cfg(unix)]
pub fn send_queue_len(fd: BorrowedFd<'_>) -> io::Result<Option<usize>> {
    imp::send_queue_len(fd)
}

/// Off unix there is nothing to ask.
#[cfg(not(unix))]
pub fn send_queue_len<T>(_fd: T) -> io::Result<Option<usize>> {
    Ok(None)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use std::io;
    use std::os::fd::{AsRawFd, BorrowedFd};

    pub(super) fn send_queue_len(fd: BorrowedFd<'_>) -> io::Result<Option<usize>> {
        let mut n: libc::c_int = 0;
        // SAFETY: `TIOCOUTQ` (the kernel's `SIOCOUTQ`) writes exactly one `int` through the
        // pointer, which points at a live local of that type; the descriptor is borrowed for the
        // duration of the call, so it cannot be closed under it.
        let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCOUTQ, &raw mut n) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(usize::try_from(n).unwrap_or(0)))
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod imp {
    use std::io;
    use std::mem;
    use std::os::fd::{AsRawFd, BorrowedFd};

    pub(super) fn send_queue_len(fd: BorrowedFd<'_>) -> io::Result<Option<usize>> {
        let mut n: libc::c_int = 0;
        let mut len = mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `SO_NWRITE` writes one `int`; the value pointer and the length describe the
        // same live local, and the descriptor is borrowed for the duration of the call.
        let rc = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NWRITE,
                (&raw mut n).cast::<libc::c_void>(),
                &raw mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(usize::try_from(n).unwrap_or(0)))
    }
}

#[cfg(target_os = "freebsd")]
mod imp {
    use std::io;
    use std::os::fd::{AsRawFd, BorrowedFd};

    pub(super) fn send_queue_len(fd: BorrowedFd<'_>) -> io::Result<Option<usize>> {
        let mut n: libc::c_int = 0;
        // SAFETY: `FIONWRITE` writes exactly one `int` through the pointer, which points at a
        // live local of that type; the descriptor is borrowed for the duration of the call.
        let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::FIONWRITE, &raw mut n) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(usize::try_from(n).unwrap_or(0)))
    }
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd"
    ))
))]
mod imp {
    use std::io;
    use std::os::fd::BorrowedFd;

    pub(super) fn send_queue_len(_fd: BorrowedFd<'_>) -> io::Result<Option<usize>> {
        Ok(None)
    }
}

#[cfg(test)]
#[path = "sockinfo/tests.rs"]
mod tests;
