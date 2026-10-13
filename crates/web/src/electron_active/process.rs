//! Ownership of one Electron run: private runtime directory, process group,
//! stderr endpoint discovery and cleanup that cannot be skipped.
//!
//! REA launches through Playwright and verifies cleanup with an environment
//! run token (`ProcessOwnership.ts`). Chromium rewrites the argv/environ area
//! of its helper processes (`setproctitle`), so on Linux the token is unreadable
//! for every helper and REA reports `cleanup_incomplete` for a perfectly clean
//! run. Tracewise proves ownership structurally instead: the leader is started
//! in a fresh process group, so the group id equals the leader pid and cannot be
//! recycled while any member is alive. Processes that left the group (setsid)
//! are signaled only when their environment still carries the run token; the
//! rest is reported as unverified and left untouched, as REA does.
//!
//! Guarantees:
//! - dropping [`OwnedElectron`] (MCP cancellation drops the future) kills the
//!   group, sweeps token-owned strays and removes the private directory;
//! - an `atexit` hook does the same for every live run when the server exits
//!   through `process::exit` (signal handler) or `main` returns;
//! - the leader gets `PR_SET_PDEATHSIG=SIGKILL`, so a SIGKILLed server does not
//!   leave a window-owning process behind.

use std::collections::{HashMap, VecDeque};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;
use tokio::process::{Child, ChildStderr, Command};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Environment variable that marks every process of one run (REA name).
pub const RUN_TOKEN_ENV: &str = "REA_PROCESS_RUN_ID";
/// Prefix of the private per-run directory below the runtime root.
pub const RUN_DIR_PREFIX: &str = "tracewise-electron-";

const HOOK: &str = include_str!("../../hooks/electron-active-hook.cjs");
const HOOK_BOUNDARIES: &str = include_str!("../../hooks/electron-active-hook-boundaries.cjs");
const STDERR_TAIL_BYTES: usize = 8 * 1024;
const STDERR_LINE_LIMIT: usize = 64 * 1024;
const SAFE_ENVIRONMENT: [&str; 6] = ["HOME", "LANG", "PATH", "USER", "DISPLAY", "WAYLAND_DISPLAY"];

// ------------------------------------------------------------------ registry

struct Live {
    key: u64,
    pgid: i32,
    run_id: String,
    dir: PathBuf,
}

static LIVE: Mutex<Vec<Live>> = Mutex::new(Vec::new());
static NEXT_KEY: AtomicU64 = AtomicU64::new(1);
static AT_EXIT: Once = Once::new();

fn live() -> std::sync::MutexGuard<'static, Vec<Live>> {
    LIVE.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

extern "C" fn at_exit() {
    shutdown_all_blocking();
}

/// Kill every Electron run this process still owns and remove its directory.
/// Registered with `atexit`; also callable from an explicit shutdown path.
pub fn shutdown_all_blocking() {
    let entries = std::mem::take(&mut *live());
    for entry in entries {
        terminate_blocking(entry.pgid, &entry.run_id, &entry.dir);
    }
}

/// Number of runs currently registered (diagnostics and tests).
pub fn live_runs() -> usize {
    live().len()
}

fn register(pgid: i32, run_id: &str, dir: &Path) -> u64 {
    AT_EXIT.call_once(|| {
        // SAFETY: `at_exit` is a plain `extern "C" fn()` that only touches statics.
        unsafe {
            libc::atexit(at_exit);
        }
    });
    let key = NEXT_KEY.fetch_add(1, Ordering::Relaxed);
    live().push(Live {
        key,
        pgid,
        run_id: run_id.to_string(),
        dir: dir.to_path_buf(),
    });
    key
}

fn deregister(key: u64) {
    live().retain(|entry| entry.key != key);
}

// --------------------------------------------------------------- /proc access

/// One row of the process table (`/proc/<pid>/stat`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcEntry {
    pub pid: i32,
    pub ppid: i32,
    pub pgid: i32,
    pub state: char,
    /// Start time in clock ticks since boot (0 when unknown): with the pid it survives pid reuse.
    pub start: u64,
}

impl ProcEntry {
    fn is_live(&self) -> bool {
        !matches!(self.state, 'Z' | 'X')
    }
}

fn parse_stat(text: &str, pid: i32) -> Option<ProcEntry> {
    // `pid (comm) state ppid pgrp ...`; comm may contain spaces and parentheses.
    let close = text.rfind(')')?;
    let fields: Vec<&str> = text.get(close + 1..)?.split_whitespace().collect();
    let state = fields.first()?.chars().next()?;
    let ppid = fields.get(1)?.parse().ok()?;
    let pgid = fields.get(2)?.parse().ok()?;
    let start = fields.get(19).and_then(|field| field.parse().ok()).unwrap_or(0);
    Some(ProcEntry { pid, ppid, pgid, state, start })
}

pub fn list_processes() -> Vec<ProcEntry> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let pid: i32 = entry.file_name().to_str()?.parse().ok()?;
            let text = std::fs::read_to_string(entry.path().join("stat")).ok()?;
            parse_stat(&text, pid)
        })
        .collect()
}

/// Live descendants of `root` (by parent links) at this instant.
pub fn descendants_of(root: i32) -> Vec<ProcEntry> {
    let table = list_processes();
    let mut found: Vec<ProcEntry> = Vec::new();
    let mut frontier = vec![root];
    while let Some(parent) = frontier.pop() {
        for entry in table.iter().filter(|e| e.ppid == parent && e.is_live()) {
            if !found.iter().any(|known| known.pid == entry.pid) {
                found.push(entry.clone());
                frontier.push(entry.pid);
            }
        }
    }
    found
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenState {
    Match,
    Absent,
    Unreadable(String),
}

pub fn read_token(pid: i32, run_id: &str) -> TokenState {
    let wanted = format!("{RUN_TOKEN_ENV}={run_id}");
    match std::fs::read(format!("/proc/{pid}/environ")) {
        Ok(bytes) => {
            if bytes.split(|b| *b == 0).any(|item| item == wanted.as_bytes()) {
                TokenState::Match
            } else {
                TokenState::Absent
            }
        }
        Err(error) => TokenState::Unreadable(error.to_string()),
    }
}

fn group_members(pgid: i32) -> Vec<ProcEntry> {
    list_processes()
        .into_iter()
        .filter(|entry| entry.pgid == pgid && entry.is_live())
        .collect()
}

fn signal_group(pgid: i32, signal: i32) {
    if pgid > 1 {
        // SAFETY: plain syscall; `pgid` is the pid of a leader this module created.
        unsafe {
            libc::killpg(pgid, signal);
        }
    }
}

fn signal_pid(pid: i32, signal: i32) {
    if pid > 1 {
        // SAFETY: plain syscall.
        unsafe {
            libc::kill(pid, signal);
        }
    }
}

/// Synchronous, bounded teardown shared by `Drop` and the `atexit` hook.
fn terminate_blocking(pgid: i32, run_id: &str, dir: &Path) {
    signal_group(pgid, libc::SIGKILL);
    for entry in list_processes() {
        if entry.is_live() && entry.pgid != pgid && read_token(entry.pid, run_id) == TokenState::Match {
            signal_pid(entry.pid, libc::SIGKILL);
        }
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline && !group_members(pgid).is_empty() {
        std::thread::sleep(Duration::from_millis(10));
    }
    for _ in 0..5 {
        if std::fs::remove_dir_all(dir).is_ok() || !dir.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

// --------------------------------------------------------------------- launch

/// What to launch.
pub struct SpawnSpec<'a> {
    pub executable: &'a Path,
    pub application: &'a str,
    pub root: &'a str,
    pub args: &'a [String],
    pub environment: &'a HashMap<String, String>,
    /// Parent of the per-run directory (defaults to the system temp dir).
    pub runtime_root: &'a Path,
}

#[derive(Debug, Clone, Default)]
struct Observed {
    node: Option<String>,
    browser: Option<String>,
    no_display: bool,
}

/// Inspector and DevTools WebSocket endpoints printed on stderr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    pub node: String,
    pub browser: String,
}

#[derive(Debug)]
pub enum StartupFailure {
    Spawn(std::io::Error),
    Exited(String),
    NoDisplay,
    Timeout,
}

/// Result of [`OwnedElectron::terminate`].
#[derive(Debug, Clone, Default)]
pub struct CleanupOutcome {
    pub cleaned: bool,
    pub reason: Option<String>,
    /// Escaped processes whose ownership could not be proven: `(pid, diagnostic)`.
    pub unverified: Vec<(i32, String)>,
}

/// One owned Electron application. Dropping it kills everything it started.
pub struct OwnedElectron {
    run_id: String,
    dir: PathBuf,
    leader_pid: i32,
    pgid: i32,
    child: Option<Child>,
    observed: watch::Receiver<Observed>,
    pump: Option<JoinHandle<()>>,
    tail: Arc<Mutex<VecDeque<u8>>>,
    registry_key: Option<u64>,
    /// Descendants seen while the application was still running (they may reparent later).
    lineage: Vec<ProcEntry>,
    cleaned: bool,
}

pub fn new_run_id() -> String {
    let mut bytes = [0u8; 16];
    let filled = std::fs::File::open("/dev/urandom")
        .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut bytes))
        .is_ok();
    if !filled {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        bytes.copy_from_slice(&(nanos ^ ((std::process::id() as u128) << 96)).to_le_bytes());
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

impl OwnedElectron {
    /// Create the private directory, write the hook and start Electron in its
    /// own process group. Nothing is left behind when this returns an error.
    pub fn spawn(spec: &SpawnSpec<'_>, run_id: &str) -> Result<Self, StartupFailure> {
        let dir = spec.runtime_root.join(format!("{RUN_DIR_PREFIX}{run_id}"));
        let (_, rx) = watch::channel(Observed::default());
        // The guard exists before anything is created, so `Drop` removes partial state.
        let mut owned = Self {
            run_id: run_id.to_string(),
            dir: dir.clone(),
            leader_pid: 0,
            pgid: 0,
            child: None,
            observed: rx,
            pump: None,
            tail: Arc::new(Mutex::new(VecDeque::new())),
            registry_key: None,
            lineage: Vec::new(),
            cleaned: false,
        };
        sweep_stale_runs(spec.runtime_root);
        let prepared = prepare_directory(&dir).map_err(StartupFailure::Spawn)?;
        let mut command = Command::new(spec.executable);
        command.arg("--inspect=0").arg("--remote-debugging-port=0");
        // SAFETY: plain syscall.
        let running_as_root = unsafe { libc::geteuid() } == 0;
        if running_as_root && !spec.args.iter().any(|arg| arg == "--no-sandbox") {
            command.arg("--no-sandbox");
        }
        command
            .arg(format!("--user-data-dir={}", prepared.profile.display()))
            .arg("-r")
            .arg(&prepared.hook)
            .arg(spec.application)
            .args(spec.args)
            .current_dir(spec.root)
            .env_clear()
            .env(RUN_TOKEN_ENV, run_id)
            .env("TMPDIR", &prepared.tmp)
            .env("TMP", &prepared.tmp)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        for name in SAFE_ENVIRONMENT {
            if let Some(value) = spec.environment.get(name) {
                command.env(name, value);
            }
        }
        // SAFETY: the closure only calls the async-signal-safe `prctl` between fork and exec.
        unsafe {
            command.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0, 0, 0);
                Ok(())
            });
        }
        let mut child = command.spawn().map_err(StartupFailure::Spawn)?;
        let Some(pid) = child.id().map(|id| id as i32) else {
            return Err(StartupFailure::Exited("Electron exited before its pid was read".to_string()));
        };
        owned.leader_pid = pid;
        owned.pgid = pid;
        owned.registry_key = Some(register(pid, run_id, &dir));
        let stderr = child.stderr.take();
        owned.child = Some(child);
        let (tx, rx) = watch::channel(Observed::default());
        owned.observed = rx;
        if let Some(stderr) = stderr {
            owned.pump = Some(tokio::spawn(pump_stderr(stderr, tx, owned.tail.clone())));
        }
        Ok(owned)
    }

    /// Remember the live descendants now. Call before asking the application to quit: once a
    /// helper loses its parent it is reparented and can no longer be found by ancestry.
    pub fn sample_lineage(&mut self) {
        for entry in descendants_of(self.leader_pid) {
            if !self.lineage.iter().any(|known| known.pid == entry.pid) {
                self.lineage.push(entry);
            }
        }
    }

    pub fn leader_pid(&self) -> i32 {
        self.leader_pid
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Last bytes Electron wrote to stderr (diagnostics only).
    pub fn stderr_tail(&self) -> String {
        let tail = self.tail.lock().unwrap_or_else(|p| p.into_inner());
        let bytes: Vec<u8> = tail.iter().copied().collect();
        String::from_utf8_lossy(&bytes).trim().to_string()
    }

    /// REA `waitForLine`: the Node inspector and DevTools endpoints.
    pub async fn wait_endpoints(&mut self, deadline: Instant) -> Result<Endpoints, StartupFailure> {
        loop {
            let observed = self.observed.borrow().clone();
            if let (Some(node), Some(browser)) = (&observed.node, &observed.browser) {
                return Ok(Endpoints {
                    node: node.clone(),
                    browser: browser.clone(),
                });
            }
            if observed.no_display && observed.browser.is_none() {
                return Err(StartupFailure::NoDisplay);
            }
            if let Some(child) = self.child.as_mut() {
                if let Ok(Some(status)) = child.try_wait() {
                    return Err(StartupFailure::Exited(format!("Electron exited during startup ({status})")));
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(StartupFailure::Timeout);
            }
            let step = (deadline - now).min(Duration::from_millis(50));
            tokio::select! {
                _ = self.observed.changed() => {}
                _ = tokio::time::sleep(step) => {}
            }
        }
    }

    /// Ask nothing of the application: wait for the leader to leave by itself
    /// (the caller already requested `app.quit()`), then make sure nothing owned
    /// survives and the private directory is gone.
    pub async fn terminate(&mut self, graceful: Duration) -> CleanupOutcome {
        self.sample_lineage();
        let lineage = self.lineage.clone();
        if let Some(child) = self.child.as_mut() {
            let _ = tokio::time::timeout(graceful, child.wait()).await;
        }
        if !group_members(self.pgid).is_empty() {
            signal_group(self.pgid, libc::SIGTERM);
            wait_group_empty(self.pgid, Duration::from_millis(1500)).await;
        }
        if !group_members(self.pgid).is_empty() {
            signal_group(self.pgid, libc::SIGKILL);
            wait_group_empty(self.pgid, Duration::from_secs(5)).await;
        }
        if let Some(child) = self.child.as_mut() {
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
        }
        let mut unverified: Vec<(i32, String)> = Vec::new();
        let mut owned_strays: Vec<i32> = Vec::new();
        for entry in lineage.iter().filter(|entry| entry.pgid != self.pgid) {
            // Gone, or the pid now belongs to a different process: not ours to look at.
            if !is_live_pid(entry.pid) || (entry.start != 0 && proc_start_time(entry.pid) != Some(entry.start)) {
                continue;
            }
            match read_token(entry.pid, &self.run_id) {
                TokenState::Match => {
                    signal_pid(entry.pid, libc::SIGKILL);
                    owned_strays.push(entry.pid);
                }
                TokenState::Absent => unverified.push((
                    entry.pid,
                    "the run token is absent from its environment, so it cannot be tied to this run".to_string(),
                )),
                TokenState::Unreadable(reason) => {
                    unverified.push((entry.pid, format!("its environment is unreadable ({reason})")))
                }
            }
        }
        for entry in list_processes() {
            if entry.is_live()
                && entry.pgid != self.pgid
                && !lineage.iter().any(|known| known.pid == entry.pid)
                && read_token(entry.pid, &self.run_id) == TokenState::Match
            {
                signal_pid(entry.pid, libc::SIGKILL);
                owned_strays.push(entry.pid);
            }
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline
            && (!group_members(self.pgid).is_empty() || owned_strays.iter().any(|pid| is_live_pid(*pid)))
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut reason: Option<String> = None;
        if !group_members(self.pgid).is_empty() {
            reason = Some(format!("process group {} still has live members after SIGKILL", self.pgid));
        } else if let Some(pid) = owned_strays.iter().find(|pid| is_live_pid(**pid)) {
            reason = Some(format!("token-owned process {pid} survived SIGKILL"));
        }
        if let Some(pump) = self.pump.take() {
            pump.abort();
        }
        if reason.is_none() {
            let mut removed = false;
            for _ in 0..10 {
                if std::fs::remove_dir_all(&self.dir).is_ok() || !self.dir.exists() {
                    removed = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            if !removed {
                reason = Some(format!("private run directory {} could not be removed", self.dir.display()));
            }
        }
        if reason.is_none() {
            self.cleaned = true;
            if let Some(key) = self.registry_key.take() {
                deregister(key);
            }
        }
        CleanupOutcome {
            cleaned: reason.is_none(),
            reason,
            unverified,
        }
    }
}

impl Drop for OwnedElectron {
    fn drop(&mut self) {
        if self.cleaned {
            return;
        }
        if let Some(pump) = self.pump.take() {
            pump.abort();
        }
        if self.pgid > 0 {
            terminate_blocking(self.pgid, &self.run_id, &self.dir);
        } else {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
        if let Some(key) = self.registry_key.take() {
            deregister(key);
        }
    }
}

fn is_live_pid(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|text| parse_stat(&text, pid))
        .is_some_and(|entry| entry.is_live())
}

async fn wait_group_empty(pgid: i32, limit: Duration) {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline && !group_members(pgid).is_empty() {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

const OWNER_FILE: &str = "owner";

/// Clock-tick start time of `pid` (`/proc/<pid>/stat`, field 22): with the pid it
/// identifies a process even after the pid is reused.
fn proc_start_time(pid: i32) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = text.rfind(')')?;
    text.get(close + 1..)?.split_whitespace().nth(19)?.parse().ok()
}

fn owner_is_alive(content: &str) -> bool {
    let mut fields = content.split_whitespace();
    let (Some(Ok(pid)), Some(Ok(start))) = (
        fields.next().map(str::parse::<i32>),
        fields.next().map(str::parse::<u64>),
    ) else {
        return true; // unreadable owner record: not ours to remove
    };
    proc_start_time(pid) == Some(start)
}

/// Remove run directories whose owning server died without cleaning up (SIGKILL,
/// OOM, power loss): kill what still runs from them and delete them. A directory
/// is identified by its owner record (pid + start time) and processes by the
/// directory path every Chromium helper carries in `--user-data-dir=`, so nothing
/// unrelated can be hit through pid reuse.
pub fn sweep_stale_runs(root: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(root) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with(RUN_DIR_PREFIX) {
            continue;
        }
        let dir = entry.path();
        let Ok(owner) = std::fs::read_to_string(dir.join(OWNER_FILE)) else {
            continue;
        };
        if owner_is_alive(&owner) {
            continue;
        }
        let needle = dir.to_string_lossy().to_string();
        if let Ok(procs) = std::fs::read_dir("/proc") {
            for proc in procs.flatten() {
                let Some(pid) = proc.file_name().to_str().and_then(|n| n.parse::<i32>().ok()) else {
                    continue;
                };
                let Ok(cmdline) = std::fs::read(proc.path().join("cmdline")) else {
                    continue;
                };
                if String::from_utf8_lossy(&cmdline).contains(&needle) {
                    signal_pid(pid, libc::SIGKILL);
                }
            }
        }
        for _ in 0..10 {
            if std::fs::remove_dir_all(&dir).is_ok() || !dir.exists() {
                removed += 1;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    removed
}

struct Prepared {
    hook: PathBuf,
    profile: PathBuf,
    tmp: PathBuf,
}

fn prepare_directory(dir: &Path) -> std::io::Result<Prepared> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(dir)?;
    let hooks = dir.join("hook");
    let profile = dir.join("profile");
    let tmp = dir.join("tmp");
    for sub in [&hooks, &profile, &tmp] {
        builder.create(sub)?;
    }
    std::fs::write(hooks.join("electron-active-hook.cjs"), HOOK)?;
    std::fs::write(hooks.join("electron-active-hook-boundaries.cjs"), HOOK_BOUNDARIES)?;
    let me = std::process::id() as i32;
    std::fs::write(dir.join(OWNER_FILE), format!("{me} {}\n", proc_start_time(me).unwrap_or(0)))?;
    Ok(Prepared {
        hook: hooks.join("electron-active-hook.cjs"),
        profile,
        tmp,
    })
}

/// Read Electron's stderr without ever blocking it, keeping a bounded tail and
/// the two endpoint lines REA waits for.
async fn pump_stderr(mut stderr: ChildStderr, tx: watch::Sender<Observed>, tail: Arc<Mutex<VecDeque<u8>>>) {
    let mut chunk = [0u8; 4096];
    let mut line: Vec<u8> = Vec::new();
    let mut overflow = false;
    let mut state = Observed::default();
    loop {
        let read = match stderr.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
        };
        {
            let mut tail = tail.lock().unwrap_or_else(|p| p.into_inner());
            tail.extend(&chunk[..read]);
            while tail.len() > STDERR_TAIL_BYTES {
                tail.pop_front();
            }
        }
        let mut changed = false;
        for byte in &chunk[..read] {
            if *byte == b'\n' {
                if !overflow {
                    changed |= observe_line(&String::from_utf8_lossy(&line), &mut state);
                }
                line.clear();
                overflow = false;
            } else if line.len() < STDERR_LINE_LIMIT {
                line.push(*byte);
            } else {
                overflow = true;
            }
        }
        if changed {
            let _ = tx.send(state.clone());
        }
    }
}

fn observe_line(line: &str, state: &mut Observed) -> bool {
    let line = line.trim_end_matches('\r');
    if let Some(url) = line.strip_prefix("Debugger listening on ") {
        if url.starts_with("ws://") && state.node.is_none() {
            state.node = Some(url.to_string());
            return true;
        }
    }
    if let Some(url) = line.strip_prefix("DevTools listening on ") {
        if url.starts_with("ws://") && state.browser.is_none() {
            state.browser = Some(url.to_string());
            return true;
        }
    }
    if line.contains("Unable to open X display") && !state.no_display {
        state.no_display = true;
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_parser_handles_spaces_and_parentheses_in_comm() {
        let entry = parse_stat("4242 (my (odd) app) S 17 4242 4242 0 -1 4194560", 4242).unwrap();
        assert_eq!(entry, ProcEntry { pid: 4242, ppid: 17, pgid: 4242, state: 'S', start: 0 });
        // Field 22 of the real layout is the start time.
        let full = "4242 (electron) S 17 4242 4242 0 -1 4194560 100 0 0 0 5 6 0 0 20 0 8 0 987654 1 2";
        assert_eq!(parse_stat(full, 4242).unwrap().start, 987654);
        assert!(parse_stat("4242 (x) Z 1 4242", 4242).is_some_and(|e| !e.is_live()));
        assert!(parse_stat("garbage", 1).is_none());
    }

    #[test]
    fn endpoint_lines_follow_the_rea_patterns() {
        let mut state = Observed::default();
        assert!(!observe_line("[1:2] ERROR something", &mut state));
        assert!(observe_line("Debugger listening on ws://127.0.0.1:9229/abc", &mut state));
        assert!(observe_line("DevTools listening on ws://127.0.0.1:1234/devtools/browser/x\r", &mut state));
        assert_eq!(state.node.as_deref(), Some("ws://127.0.0.1:9229/abc"));
        assert_eq!(state.browser.as_deref(), Some("ws://127.0.0.1:1234/devtools/browser/x"));
        assert!(!observe_line("Debugger listening on http://x", &mut Observed::default()));
        let mut display = Observed::default();
        assert!(observe_line("Error: Unable to open X display", &mut display));
        assert!(display.no_display);
    }

    fn script(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("fake-electron.sh");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn scratch(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tw-proc-{label}-{}-{}", std::process::id(), new_run_id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn alive(pid: i32) -> bool {
        is_live_pid(pid)
    }

    /// Digits only, unique per call: used as the fractional part of `sleep` durations so the
    /// sleepers of one test can be told apart in `/proc`.
    fn numeric_tag() -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        format!("{}{nanos}", std::process::id())
    }

    /// The pids of every `sleep <marker>` process (the marker makes them unique to one test).
    fn sleepers(marker: &str) -> Vec<i32> {
        let mut found = Vec::new();
        for entry in std::fs::read_dir("/proc").unwrap().flatten() {
            let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<i32>().ok()) else { continue };
            let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else { continue };
            let text = String::from_utf8_lossy(&cmdline).replace('\0', " ");
            if text.starts_with("sleep ") && text.contains(marker) && alive(pid) {
                found.push(pid);
            }
        }
        found
    }

    /// Owned group members die; an escaped helper that still carries the run token is killed; one that
    /// lost the token is reported as unverified and left alone (REA's rule: never signal what is not proven).
    #[tokio::test]
    async fn terminate_kills_the_group_and_token_owned_strays_but_never_an_unproven_process() {
        let root = scratch("terminate");
        let tag = numeric_tag();
        let tag = tag.as_str();
        let launcher = script(
            &root,
            &format!(
                "sleep 1000.{tag} &\n\
                 setsid sleep 1001.{tag} &\n\
                 env -u {RUN_TOKEN_ENV} setsid sleep 1002.{tag} &\n\
                 echo 'Debugger listening on ws://127.0.0.1:9/x' >&2\n\
                 echo 'DevTools listening on ws://127.0.0.1:9/devtools/browser/y' >&2\n\
                 exec sleep 1003.{tag}"
            ),
        );
        let environment = HashMap::new();
        let run_id = new_run_id();
        let spec = SpawnSpec {
            executable: &launcher,
            application: "/nonexistent/app.js",
            root: "/",
            args: &[],
            environment: &environment,
            runtime_root: &root,
        };
        let mut app = OwnedElectron::spawn(&spec, &run_id).expect("spawn");
        let endpoints = app.wait_endpoints(Instant::now() + Duration::from_secs(10)).await.expect("endpoints");
        assert_eq!(endpoints.node, "ws://127.0.0.1:9/x");
        assert!(wait_for(|| sleepers(tag).len() == 4), "the four sleepers started: {:?}", sleepers(tag));
        let all = sleepers(tag);
        let unproven = all
            .iter()
            .copied()
            .find(|pid| std::fs::read_to_string(format!("/proc/{pid}/cmdline")).unwrap_or_default().contains("1002"))
            .expect("the token-less sleeper");
        assert_eq!(read_token(unproven, &run_id), TokenState::Absent);
        app.sample_lineage();
        let dir = app.dir().to_path_buf();
        let outcome = app.terminate(Duration::from_millis(100)).await;
        assert!(outcome.cleaned, "{outcome:?}");
        assert!(!dir.exists(), "the private directory is removed");
        let left = sleepers(tag);
        assert_eq!(left, vec![unproven], "only the process that cannot be tied to the run survives");
        assert_eq!(outcome.unverified.len(), 1, "{outcome:?}");
        assert_eq!(outcome.unverified[0].0, unproven);
        assert!(outcome.unverified[0].1.contains("run token is absent"), "{outcome:?}");
        signal_pid(unproven, libc::SIGKILL);
        assert!(wait_for(|| sleepers(tag).is_empty()));
        let _ = std::fs::remove_dir_all(&root);
    }

    fn wait_for(mut condition: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if condition() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        condition()
    }

    #[tokio::test]
    async fn dropping_the_guard_kills_everything_and_removes_the_directory() {
        let root = scratch("drop");
        let tag = numeric_tag();
        let launcher = script(
            &root,
            &format!("setsid sleep 2001.{tag} &\nsleep 2000.{tag} &\nexec sleep 2002.{tag}"),
        );
        let environment = HashMap::new();
        let run_id = new_run_id();
        let spec = SpawnSpec {
            executable: &launcher,
            application: "/nonexistent/app.js",
            root: "/",
            args: &[],
            environment: &environment,
            runtime_root: &root,
        };
        let app = OwnedElectron::spawn(&spec, &run_id).expect("spawn");
        let dir = app.dir().to_path_buf();
        assert!(wait_for(|| sleepers(&tag).len() == 3), "{:?}", sleepers(&tag));
        assert!(dir.exists() && live_runs() >= 1);
        drop(app);
        assert!(!dir.exists(), "Drop removes the directory synchronously");
        assert!(wait_for(|| sleepers(&tag).is_empty()), "group members and the token-owned stray are gone: {:?}", sleepers(&tag));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn run_ids_are_uuid_shaped_and_unique() {
        let a = new_run_id();
        let b = new_run_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(a.as_bytes()[14], b'4');
    }
}
