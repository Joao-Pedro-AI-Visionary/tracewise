//! Cooperative cancellation of the native analyses.
//!
//! The server runs every analysis on a blocking thread. When the MCP request is cancelled the
//! awaiting future is dropped, but a blocking thread cannot be killed: the analysis has to notice.
//! The server installs a [`CancelToken`] for the thread with [`scope`]; long loops in this crate
//! call [`cancelled`] (or [`checkpoint`]) every so often and stop early.
//!
//! A thread-local keeps the analysis functions free of an extra parameter. Code that runs on a
//! helper thread (the requirement decoder) is short and bounded by its own pre-scan, so it does
//! not look at the token.

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::error::{NativeError, NativeResult};

#[derive(Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    /// A guard that cancels the token when dropped (when the awaiting request future is dropped).
    pub fn cancel_on_drop(&self) -> CancelOnDrop {
        CancelOnDrop { token: self.clone(), armed: true }
    }
}

pub struct CancelOnDrop {
    token: CancelToken,
    armed: bool,
}

impl CancelOnDrop {
    /// The analysis finished normally; dropping the guard no longer cancels anything.
    pub fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.token.cancel();
        }
    }
}

thread_local! {
    static CURRENT: RefCell<Option<CancelToken>> = const { RefCell::new(None) };
}

/// Run `work` with `token` installed for this thread.
pub fn scope<T>(token: CancelToken, work: impl FnOnce() -> T) -> T {
    let previous = CURRENT.with(|current| current.replace(Some(token)));
    let result = work();
    CURRENT.with(|current| *current.borrow_mut() = previous);
    result
}

/// Whether the request running on this thread has been cancelled.
pub fn cancelled() -> bool {
    CURRENT.with(|current| current.borrow().as_ref().is_some_and(CancelToken::is_cancelled))
}

/// `Err` when cancelled, for code that returns [`NativeResult`].
pub fn checkpoint(operation: &str) -> NativeResult<()> {
    if cancelled() {
        Err(NativeError::Cancelled { operation: operation.to_string() })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_token_is_visible_only_inside_its_scope() {
        let token = CancelToken::new();
        assert!(!cancelled());
        scope(token.clone(), || {
            assert!(!cancelled());
            token.cancel();
            assert!(cancelled());
            assert!(checkpoint("op").is_err());
        });
        assert!(!cancelled());
    }

    #[test]
    fn dropping_the_guard_cancels_unless_it_was_disarmed() {
        let token = CancelToken::new();
        drop(token.cancel_on_drop());
        assert!(token.is_cancelled());
        let finished = CancelToken::new();
        finished.cancel_on_drop().disarm();
        assert!(!finished.is_cancelled());
    }
}
