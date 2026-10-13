//! Cooperative cancellation for blocking analysis work (REA `JavaScriptAnalysisControl.ts`).
//!
//! The MCP layer runs the analysis on a blocking thread; dropping the request future flips this
//! flag (through [`CancelGuard`]) and the analysis stops at its next checkpoint.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::error::JsError;

#[derive(Clone, Debug, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// `assertJavaScriptAnalysisActive`.
    pub fn check(&self) -> Result<(), JsError> {
        if self.is_cancelled() {
            Err(JsError::Io(super::error::CANCELLED_MESSAGE.into()))
        } else {
            Ok(())
        }
    }
}

/// Cancels the flag when dropped, so a dropped request future stops its blocking work.
pub struct CancelGuard(Option<Cancel>);

impl CancelGuard {
    pub fn new(cancel: Cancel) -> Self {
        CancelGuard(Some(cancel))
    }

    /// The work finished normally: dropping the guard no longer cancels it.
    pub fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        if let Some(cancel) = &self.0 {
            cancel.cancel();
        }
    }
}

/// Number of visited syntax nodes between two cancellation checks (REA checks every 1024 nodes).
pub const NODE_CHECK_INTERVAL: u32 = 1024;

/// Unwind payload used by [`checkpoint`] to leave a long per-file pass once the call is cancelled;
/// [`catch_cancellation`] turns it back into a value. Raised with `resume_unwind`, so no panic
/// message is printed and no panic hook runs.
struct CancelUnwind;

thread_local! {
    static ACTIVE: std::cell::RefCell<Option<Cancel>> = const { std::cell::RefCell::new(None) };
    static VISITED: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Per-node cancellation checkpoint for the traversals inside one file's analysis. Cheap: a counter
/// bump, and every [`NODE_CHECK_INTERVAL`] nodes one atomic load. Does nothing outside
/// [`catch_cancellation`].
#[inline]
pub fn checkpoint() {
    let due = VISITED.with(|visited| {
        let next = visited.get().wrapping_add(1);
        visited.set(next);
        next % NODE_CHECK_INTERVAL == 0
    });
    if due && ACTIVE.with(|active| active.borrow().as_ref().is_some_and(Cancel::is_cancelled)) {
        std::panic::resume_unwind(Box::new(CancelUnwind));
    }
}

/// The work was abandoned mid-way because the call was cancelled.
#[derive(Debug, Clone, Copy)]
pub struct Cancelled;

/// Runs `work` with `cancel` armed for [`checkpoint`] on this thread. `Err(Cancelled)` means the work was
/// abandoned mid-way because the call was cancelled; any other panic keeps unwinding.
pub fn catch_cancellation<T>(cancel: &Cancel, work: impl FnOnce() -> T) -> Result<T, Cancelled> {
    ACTIVE.with(|active| *active.borrow_mut() = Some(cancel.clone()));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work));
    ACTIVE.with(|active| *active.borrow_mut() = None);
    match outcome {
        Ok(value) => Ok(value),
        Err(payload) if payload.is::<CancelUnwind>() => Err(Cancelled),
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

/// Wraps `work` so that, when it runs on another thread (the analysis passes use scoped threads with
/// a large stack), it checks the cancellation armed on the spawning thread.
pub fn inherit<R>(work: impl FnOnce() -> R) -> impl FnOnce() -> R {
    let active = ACTIVE.with(|active| active.borrow().clone());
    move || {
        ACTIVE.with(|slot| *slot.borrow_mut() = active);
        work()
    }
}
