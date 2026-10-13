//! Process hygiene shared by the engine clients: child hardening, safe group kill and the
//! OS randomness source.

use std::process::Stdio;

/// Make a spawned engine die with this server where the OS can express it.
///
/// Linux: `PR_SET_PDEATHSIG` between fork and exec, so a killed server never leaves a JVM or
/// proxy behind. Elsewhere (macOS, where Hopper really runs) the kernel has no equivalent, so
/// the caller relies on the process-group kill, `Drop`, the server's shutdown hook and
/// [`spawn_watchdog`].
pub fn harden_child(command: &mut tokio::process::Command) {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: the closure only calls the async-signal-safe prctl(2) between fork and exec.
        unsafe {
            command.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = command;
    }
}

/// Same hardening for a command built by `process_wrap` (it only exposes the tokio command).
pub fn harden_proxy(command: &mut tokio::process::Command) {
    harden_child(command);
}

/// SIGKILL a whole process group. A pid that is not strictly greater than 1 is refused:
/// `kill(-0, ...)` would signal the caller's own group and `kill(-1, ...)` every process.
pub fn kill_group(pid: i32) -> bool {
    if pid <= 1 {
        return false;
    }
    // SAFETY: plain signal delivery to a group id this process created (leader pid == pgid).
    unsafe { libc::kill(-pid, libc::SIGKILL) == 0 }
}

/// Shell body of the non-Linux watchdog: wait for the server to disappear, then kill the group.
pub fn watchdog_script(server_pid: u32, group_pid: i32) -> String {
    format!(
        "while kill -0 {server_pid} 2>/dev/null; do sleep 1; done; kill -9 -{group_pid} 2>/dev/null; exit 0"
    )
}

/// Start a detached watchdog that kills `group_pid`'s group once this server process is gone.
///
/// Only needed where there is no parent-death signal; a no-op on Linux. The watchdog is its
/// own process group, holds no engine data and ends as soon as the group is dead.
pub fn spawn_watchdog(group_pid: i32) {
    if cfg!(target_os = "linux") || group_pid <= 1 {
        return;
    }
    start_watchdog(group_pid);
}

/// Unconditional watchdog start (the Linux unit test drives it directly).
pub fn start_watchdog(group_pid: i32) -> Option<std::process::Child> {
    use std::os::unix::process::CommandExt;
    let mut command = std::process::Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(watchdog_script(std::process::id(), group_pid))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    command.spawn().ok()
}

/// Cryptographically secure random bytes from the OS. A failure aborts the process: a
/// predictable token or runtime directory name must never be used.
pub fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    if let Err(error) = getrandom::fill(&mut bytes) {
        eprintln!("fatal: the operating system random source failed: {error}");
        std::process::abort();
    }
    bytes
}

pub fn random_hex(length: usize) -> String {
    hex::encode(random_bytes(length))
}

pub fn random_uuid() -> String {
    let mut b = random_bytes(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(&b);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_to_signal_unsafe_group_ids() {
        assert!(!kill_group(0));
        assert!(!kill_group(1));
        assert!(!kill_group(-5));
    }

    #[test]
    fn random_values_have_the_requested_shape_and_differ() {
        assert_eq!(random_bytes(32).len(), 32);
        assert_ne!(random_hex(16), random_hex(16));
        let uuid = random_uuid();
        assert_eq!(uuid.len(), 36);
        assert_eq!(&uuid[14..15], "4");
    }

    #[test]
    fn watchdog_kills_the_group_when_the_watched_process_is_gone() {
        use std::os::unix::process::CommandExt;
        // A "victim" group and a watched process that exits right away.
        let mut victim = std::process::Command::new("/bin/sleep")
            .arg("60")
            .process_group(0)
            .spawn()
            .unwrap();
        let group = victim.id() as i32;
        let mut watched = std::process::Command::new("/bin/sleep").arg("0").spawn().unwrap();
        let _ = watched.wait();
        let script = watchdog_script(watched.id(), group);
        let mut dog = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .process_group(0)
            .spawn()
            .unwrap();
        let _ = dog.wait();
        let status = victim.wait().unwrap();
        assert!(!status.success(), "victim must have been killed, got {status:?}");
    }
}
