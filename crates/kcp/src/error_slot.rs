//! A write-once socket error with a wake-up, the equivalent of kcp-go's
//! `socketWriteError` + `chSocketWriteError` pair.
//!
//! A session records the first error its socket reports in each direction and wakes everybody
//! blocked on that direction:
//!
//! ```go
//! // sess.go
//! func (s *UDPSession) notifyWriteError(err error) {
//!     s.socketWriteErrorOnce.Do(func() {
//!         s.socketWriteError.Store(err)
//!         close(s.chSocketWriteError)      // a closed channel stays readable forever
//!     })
//! }
//! ```
//!
//! [`ErrorSlot`] is that `sync.Once` + `atomic.Value` + closed channel in one: the first
//! [`set`](ErrorSlot::set) wins, later ones are ignored, and [`wait`](ErrorSlot::wait) resolves
//! immediately once the slot is filled, before or after the fact, so no wake-up can be lost.
//!
//! The tx task (05.2) fills the write slot; the read loop and the listener (05.3, 05.6, 05.7)
//! fill the read slot the same way.
#![forbid(unsafe_code)]

use std::fmt;
use std::io;
use std::sync::{Arc, OnceLock};

use tokio::sync::Notify;

/// A socket error recorded once, with a notification for whoever is waiting on it.
#[derive(Default)]
pub struct ErrorSlot {
    err: OnceLock<Arc<io::Error>>,
    notify: Notify,
}

impl ErrorSlot {
    /// An empty slot.
    pub fn new() -> ErrorSlot {
        ErrorSlot::default()
    }

    /// Records `err` and wakes every waiter, unless an error was already recorded (Go's
    /// `socketWriteErrorOnce`). Returns whether this call was the one that filled the slot.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).notifyWriteError() / notifyReadError()
    pub fn set(&self, err: io::Error) -> bool {
        if self.err.set(Arc::new(err)).is_err() {
            return false;
        }
        // Go closes the channel, which releases current and future waiters; `wait` re-checks
        // the slot, so waiters that arrive later never block.
        self.notify.notify_waiters();
        true
    }

    /// The recorded error, if any.
    pub fn get(&self) -> Option<&Arc<io::Error>> {
        self.err.get()
    }

    /// Whether an error has been recorded.
    pub fn is_set(&self) -> bool {
        self.err.get().is_some()
    }

    /// A fresh [`io::Error`] with the recorded kind and message, for returning to a caller.
    ///
    /// Go hands out the same error value over and over; [`io::Error`] is not `Clone`, so the
    /// kind and the message are copied instead and the original is kept as the source.
    pub fn io_error(&self) -> Option<io::Error> {
        self.err
            .get()
            .map(|err| io::Error::new(err.kind(), ErrorRef(Arc::clone(err))))
    }

    /// Resolves as soon as an error is recorded (immediately, if one already is).
    // Go: `case <-s.chSocketWriteError:` on a channel that is closed by notifyWriteError.
    pub async fn wait(&self) {
        loop {
            // Register before re-checking, so a `set` racing with this loop cannot be missed
            // (docs/porting-guide.md §6).
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_set() {
                return;
            }
            notified.await;
        }
    }
}

impl fmt::Debug for ErrorSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErrorSlot").field("err", &self.err).finish()
    }
}

/// Wrapper that lets a recorded error be the `source` of the copies handed out by
/// [`ErrorSlot::io_error`].
#[derive(Debug)]
struct ErrorRef(Arc<io::Error>);

impl fmt::Display for ErrorRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&*self.0, f)
    }
}

impl std::error::Error for ErrorRef {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn first_error_wins() {
        let slot = ErrorSlot::new();
        assert!(!slot.is_set());
        assert!(slot.get().is_none());
        assert!(slot.io_error().is_none());

        assert!(slot.set(io::Error::new(io::ErrorKind::BrokenPipe, "first")));
        assert!(!slot.set(io::Error::other("second")));

        let err = slot.io_error().expect("error recorded");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(err.to_string(), "first");
        assert_eq!(slot.get().expect("set").to_string(), "first");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wait_resolves_before_and_after_the_error() {
        let slot = Arc::new(ErrorSlot::new());

        // A waiter that is already parked must be woken.
        let waiter = {
            let slot = Arc::clone(&slot);
            tokio::spawn(async move {
                slot.wait().await;
                slot.io_error().expect("error").to_string()
            })
        };
        tokio::task::yield_now().await;
        slot.set(io::Error::other("socket gone"));
        let msg = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("no deadlock")
            .expect("task");
        assert_eq!(msg, "socket gone");

        // A waiter that arrives afterwards must not block.
        tokio::time::timeout(Duration::from_secs(5), slot.wait())
            .await
            .expect("already set");
    }
}
