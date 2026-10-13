//! Cancellation for blocking provider work (Apktool, JADX, JEB).
//!
//! MCP drops the tool future when a request is cancelled, but blocking work
//! running on `spawn_blocking` keeps going. A [`CancelToken`] reaches that work:
//! the async side owns a [`CancelOnDrop`] guard, the blocking side polls
//! [`CancelToken::is_cancelled`] and registers every child it starts as a
//! process group. Cancelling kills those groups at once (`killpg(SIGKILL)`), so
//! a launcher that did not `exec` its JVM leaves nothing behind, and the
//! blocking side then unwinds, joins its readers and removes its temp
//! directory.

use std::io;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Inner {
    cancelled: AtomicBool,
    groups: Mutex<Vec<i32>>,
}

/// Shared flag plus the process groups to kill when it is set.
#[derive(Clone, Default)]
pub struct CancelToken(Arc<Inner>);

/// Kill a whole process group; ignores groups that no longer exist.
pub fn kill_group(pgid: i32) {
    if pgid > 1 {
        // SAFETY: killpg has no memory-safety preconditions.
        unsafe {
            libc::killpg(pgid, libc::SIGKILL);
        }
    }
}

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::SeqCst)
    }

    /// Set the flag and kill every registered process group.
    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::SeqCst);
        let groups = self.0.groups.lock().unwrap_or_else(|e| e.into_inner());
        for pgid in groups.iter() {
            kill_group(*pgid);
        }
    }

    /// Track a live child group; kills it immediately when already cancelled.
    pub fn register(&self, pgid: i32) {
        let mut groups = self.0.groups.lock().unwrap_or_else(|e| e.into_inner());
        groups.push(pgid);
        if self.is_cancelled() {
            kill_group(pgid);
        }
    }

    /// Forget a group once its leader has been reaped (the id may be reused).
    pub fn unregister(&self, pgid: i32) {
        let mut groups = self.0.groups.lock().unwrap_or_else(|e| e.into_inner());
        groups.retain(|g| *g != pgid);
    }

    /// A guard that cancels this token when dropped.
    pub fn guard(&self) -> CancelOnDrop {
        CancelOnDrop(Some(self.clone()))
    }
}

/// Held by the async caller; dropping it before [`CancelOnDrop::disarm`] (the
/// MCP request was cancelled) cancels the work.
pub struct CancelOnDrop(Option<CancelToken>);

impl CancelOnDrop {
    /// The work finished normally; nothing to cancel any more.
    pub fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if let Some(token) = self.0.take() {
            token.cancel();
        }
    }
}

/// A child that leads its own process group and is killed with it.
pub struct GroupChild {
    pub child: Child,
    pgid: i32,
    token: CancelToken,
    reaped: bool,
}

impl GroupChild {
    /// Spawn `command` as the leader of a new process group tracked by `token`.
    pub fn spawn(command: &mut Command, token: &CancelToken) -> io::Result<GroupChild> {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
        let child = command.spawn()?;
        let pgid = child.id() as i32;
        token.register(pgid);
        Ok(GroupChild { child, pgid, token: token.clone(), reaped: false })
    }

    /// Like [`GroupChild::spawn`], for a child that outlives the call that started
    /// it (the retained JADX engine). Each call registers the group itself while
    /// it uses the child.
    pub fn spawn_untracked(command: &mut Command) -> io::Result<GroupChild> {
        GroupChild::spawn(command, &CancelToken::new())
    }

    pub fn pgid(&self) -> i32 {
        self.pgid
    }

    /// Non-blocking status check. When the leader has exited it is first peeked
    /// at (`WNOWAIT`), so the group id is still ours while stragglers are killed;
    /// only then is it reaped and the group forgotten.
    pub fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        if self.reaped {
            return Ok(None);
        }
        // SAFETY: an all-zero siginfo_t is a valid value for waitid to fill in.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` is a valid out-pointer and the pid is our own child.
        let result = unsafe {
            libc::waitid(libc::P_PID, self.child.id() as libc::id_t, &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT)
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: waitid filled the structure; si_pid is 0 while the child runs.
        if unsafe { info.si_pid() } == 0 {
            return Ok(None);
        }
        kill_group(self.pgid);
        let status = self.child.wait()?;
        self.mark_reaped();
        Ok(Some(status))
    }

    /// Kill the whole group, then reap the leader.
    pub fn kill_and_wait(&mut self) -> io::Result<std::process::ExitStatus> {
        if !self.reaped {
            // The leader is not reaped yet, so the group id cannot be reused.
            kill_group(self.pgid);
        }
        let status = self.child.wait()?;
        self.mark_reaped();
        Ok(status)
    }

    fn mark_reaped(&mut self) {
        if !self.reaped {
            self.reaped = true;
            self.token.unregister(self.pgid);
        }
    }
}

impl Drop for GroupChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.kill_and_wait();
        }
    }
}
