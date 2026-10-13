//! Bounded, owned execution of one firmware tool command (port of
//! `runFirmwareCommand` in REA `FirmwareCommand.ts` plus the owned-process
//! supervision of `ProviderProcess.ts` and `ProcessOwnership.ts` on Linux).
//!
//! The tool runs behind util-linux `prlimit` in its own session/process group
//! with a run token in its environment (`REA_PROCESS_RUN_ID`). When the run
//! ends, every process still in that group is verified to carry the token
//! before the group is killed, so a reused PID is never signalled.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::Notify;

use crate::error::ToolError;
use crate::firmware::files::{inventory, ReportError};
use crate::firmware::release::{ADDRESS_SPACE_BYTES, DIAGNOSTIC_BYTES, REPORT_BYTES, TIMEOUT_MS};
use crate::firmware::FwFailure;

const KILL_GRACE: Duration = Duration::from_millis(1_000);
const POLL: Duration = Duration::from_millis(100);

/// Staging budgets polled while the tool runs.
#[derive(Debug, Clone)]
pub struct OutputBudget {
    pub root: String,
    pub bytes: u64,
    pub entries: u64,
}

pub struct RunContext<'a> {
    pub engine: &'a str,
    pub operation: &'a str,
    pub command: &'a str,
    pub limiter: &'a str,
    pub args: Vec<String>,
    pub cwd: &'a str,
    pub host_environment: &'a HashMap<String, String>,
    pub output_budget: Option<OutputBudget>,
    pub accept_reported_extraction_failure: bool,
    pub deadline: Instant,
}

#[derive(Debug, Clone)]
pub struct Captured {
    pub text: String,
    pub bytes: usize,
    pub observed_bytes: usize,
}

impl Captured {
    fn to_json(&self) -> Value {
        json!({ "text": self.text, "bytes": self.bytes, "observedBytes": self.observed_bytes })
    }
}

#[derive(Debug, Clone)]
pub struct RunResult {
    pub stdout: Captured,
    pub stderr: Captured,
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
    pub command: String,
    pub args: Vec<String>,
    pub resource_limiter: String,
}

impl RunResult {
    /// The `execution` record kept in `raw_result`.
    pub fn to_json(&self) -> Value {
        json!({
            "stdout": self.stdout.to_json(),
            "stderr": self.stderr.to_json(),
            "exit_code": self.exit_code,
            "signal": self.signal,
            "command": self.command,
            "args": self.args,
            "resource_limiter": self.resource_limiter,
        })
    }
}

#[derive(Default)]
struct Shared {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_observed: usize,
    stderr_observed: usize,
    truncated: bool,
    readers_closed: u8,
    exit: Option<(Option<i32>, Option<i32>)>,
}

fn signal_name(signal: i32) -> String {
    match signal {
        libc::SIGHUP => "SIGHUP",
        libc::SIGINT => "SIGINT",
        libc::SIGQUIT => "SIGQUIT",
        libc::SIGILL => "SIGILL",
        libc::SIGABRT => "SIGABRT",
        libc::SIGBUS => "SIGBUS",
        libc::SIGFPE => "SIGFPE",
        libc::SIGKILL => "SIGKILL",
        libc::SIGUSR1 => "SIGUSR1",
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGUSR2 => "SIGUSR2",
        libc::SIGPIPE => "SIGPIPE",
        libc::SIGALRM => "SIGALRM",
        libc::SIGTERM => "SIGTERM",
        libc::SIGXCPU => "SIGXCPU",
        libc::SIGXFSZ => "SIGXFSZ",
        other => return format!("SIG{other}"),
    }
    .to_string()
}

/// A random RFC 4122 version-4 identifier.
pub fn random_uuid() -> String {
    let mut bytes = [0u8; 16];
    if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
        let _ = std::io::Read::read_exact(&mut file, &mut bytes);
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let h = hex::encode(bytes);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

#[derive(Debug, PartialEq, Eq)]
enum Cleanup {
    Cleaned,
    Failed(String),
}

/// `(pid, process group, state)` of every process in `/proc`.
fn process_table() -> Result<Vec<(i32, i32, char)>, String> {
    let mut table = Vec::new();
    let listing = std::fs::read_dir("/proc").map_err(|e| e.to_string())?;
    for entry in listing.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<i32>().ok()) else { continue };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else { continue };
        let Some(close) = stat.rfind(')') else { continue };
        let mut fields = stat[close + 1..].split_whitespace();
        let state = fields.next().and_then(|s| s.chars().next()).unwrap_or('?');
        let _ppid = fields.next();
        let Some(pgrp) = fields.next().and_then(|s| s.parse::<i32>().ok()) else { continue };
        table.push((pid, pgrp, state));
    }
    Ok(table)
}

fn run_token(pid: i32) -> Result<Option<String>, String> {
    let environ = std::fs::read(format!("/proc/{pid}/environ")).map_err(|e| e.to_string())?;
    for item in environ.split(|b| *b == 0) {
        if let Some(rest) = item.strip_prefix(b"REA_PROCESS_RUN_ID=") {
            return Ok(Some(String::from_utf8_lossy(rest).into_owned()));
        }
    }
    Ok(None)
}

/// Token-validate the owned process group before signalling any member.
fn cleanup_owned_group(run_id: &str, pgid: i32) -> Cleanup {
    // A group member that is exiting (or has just exec'd) briefly exposes an empty
    // or unreadable environment, so a failed ownership proof is re-observed a few
    // times; only a member that stays unprovable is a real ownership failure.
    let mut outcome = cleanup_owned_group_once(run_id, pgid);
    for _ in 0..8 {
        match &outcome {
            Cleanup::Failed(reason) if reason.contains("unowned or PID-reused") || reason.contains("could not be read") => {
                std::thread::sleep(Duration::from_millis(25));
                outcome = cleanup_owned_group_once(run_id, pgid);
            }
            _ => break,
        }
    }
    outcome
}

fn cleanup_owned_group_once(run_id: &str, pgid: i32) -> Cleanup {
    let table = match process_table() {
        Ok(table) => table,
        Err(reason) => return Cleanup::Failed(format!("process table could not be inspected: {reason}")),
    };
    let members: Vec<i32> = table.iter().filter(|(_, g, state)| *g == pgid && *state != 'Z').map(|(p, _, _)| *p).collect();
    if members.is_empty() {
        return Cleanup::Cleaned;
    }
    for pid in &members {
        match run_token(*pid) {
            Ok(Some(token)) if token == run_id => {}
            Ok(_) => return Cleanup::Failed("process tree contains an unowned or PID-reused process".to_string()),
            Err(_) => {
                return Cleanup::Failed(format!(
                    "process ownership token could not be read for 1 live process(es): environment_unavailable=1; live candidates {pid}=environment_unavailable"
                ))
            }
        }
    }
    // SAFETY: signalling a process group whose members were token-validated above.
    let result = unsafe { libc::killpg(pgid, libc::SIGKILL) };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Cleanup::Failed(format!("owned process group signal failed: {error}"));
        }
    }
    Cleanup::Cleaned
}

/// Kills the owned process group if the run is abandoned (the MCP request was
/// cancelled and the future dropped). Ownership is token-validated first, so a
/// reused PID is never signalled; a normal run disarms it after `stop_owned`.
struct GroupGuard {
    run_id: String,
    pgid: i32,
    armed: bool,
}

impl Drop for GroupGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = cleanup_owned_group(&self.run_id, self.pgid);
        }
    }
}

async fn wait_exit(shared: &Arc<Mutex<Shared>>, notify: &Notify, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        if shared.lock().expect("shared").exit.is_some() {
            return true;
        }
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        let _ = tokio::time::timeout(deadline - now, notify.notified()).await;
    }
}

fn spawn_diagnostic(error: &std::io::Error, program: &str) -> FwFailure {
    FwFailure::Other(format!("spawn {program} {}", crate::exec::spawn_error_code(error)))
}

fn feed(shared: &Arc<Mutex<Shared>>, notify: &Arc<Notify>, stdout: bool, chunk: &[u8]) {
    let mut state = shared.lock().expect("shared");
    if stdout {
        state.stdout_observed += chunk.len();
    } else {
        state.stderr_observed += chunk.len();
    }
    let used = state.stdout.len() + state.stderr.len();
    let remaining = DIAGNOSTIC_BYTES.saturating_sub(used);
    let retained = chunk.len().min(remaining);
    if retained < chunk.len() {
        state.truncated = true;
    }
    if stdout {
        state.stdout.extend_from_slice(&chunk[..retained]);
    } else {
        state.stderr.extend_from_slice(&chunk[..retained]);
    }
    drop(state);
    notify.notify_waiters();
}

/// Run `limiter ... command args` and verify cleanup. See the module docs.
pub async fn run_command(ctx: RunContext<'_>) -> Result<RunResult, FwFailure> {
    let run_id = format!("rea-firmware-{}", random_uuid());
    let fsize = ctx.output_budget.as_ref().map(|b| b.bytes).unwrap_or(REPORT_BYTES as u64);
    let mut limiter_args = vec![
        format!("--as={ADDRESS_SPACE_BYTES}"),
        format!("--fsize={fsize}"),
        "--core=0".to_string(),
        "--cpu=120".to_string(),
        "--".to_string(),
        ctx.command.to_string(),
    ];
    limiter_args.extend(ctx.args.iter().cloned());
    let mut command = Command::new(ctx.limiter);
    command
        .args(&limiter_args)
        .current_dir(ctx.cwd)
        .env_clear()
        .envs(ctx.host_environment)
        .env("TMPDIR", ctx.cwd)
        .env("OMP_NUM_THREADS", "1")
        .env("OPENBLAS_NUM_THREADS", "1")
        .env("RAYON_NUM_THREADS", "1")
        .env("NO_COLOR", "1")
        .env("REA_PROCESS_RUN_ID", &run_id)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: setsid is async-signal-safe; it makes the tool its own group leader.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|e| spawn_diagnostic(&e, ctx.limiter))?;
    let pid = child.id().ok_or_else(|| FwFailure::Other("Provider launcher has no process ID".to_string()))? as i32;
    let mut group_guard = GroupGuard { run_id: run_id.clone(), pgid: pid, armed: true };
    let shared = Arc::new(Mutex::new(Shared::default()));
    let notify = Arc::new(Notify::new());
    let stdout_pipe = child.stdout.take().expect("piped stdout");
    let stderr_pipe = child.stderr.take().expect("piped stderr");
    tokio::spawn(pump(stdout_pipe, shared.clone(), notify.clone(), true));
    tokio::spawn(pump(stderr_pipe, shared.clone(), notify.clone(), false));
    {
        let shared = shared.clone();
        let notify = notify.clone();
        tokio::spawn(async move {
            let status = child.wait().await;
            let observed = match status {
                Ok(status) => {
                    use std::os::unix::process::ExitStatusExt;
                    (status.code(), status.signal())
                }
                Err(_) => (None, None),
            };
            shared.lock().expect("shared").exit = Some(observed);
            notify.notify_waiters();
        });
    }

    let mut failure: Option<FwFailure> = None;
    loop {
        {
            let state = shared.lock().expect("shared");
            if state.readers_closed >= 2 && state.exit.is_some() {
                break;
            }
        }
        let _ = tokio::time::timeout(POLL, notify.notified()).await;
        {
            let state = shared.lock().expect("shared");
            if state.readers_closed >= 2 && state.exit.is_some() {
                break;
            }
        }
        if let Some(error) = check_diagnostics(&shared, ctx.operation) {
            failure = Some(error);
            break;
        }
        if Instant::now() >= ctx.deadline {
            failure = Some(FwFailure::Typed(ToolError::Timeout {
                operation: ctx.operation.to_string(),
                timeout_ms: TIMEOUT_MS,
            }));
            break;
        }
        if let Some(budget) = ctx.output_budget.clone() {
            let outcome = tokio::task::spawn_blocking(move || inventory(&budget.root, budget.bytes, budget.entries))
                .await
                .map_err(|e| FwFailure::Other(e.to_string()));
            match outcome {
                Ok(Ok(_)) => {}
                Ok(Err(ReportError::Output(reason))) => {
                    failure = Some(FwFailure::Typed(ToolError::Output { operation: ctx.operation.to_string(), reason }));
                    break;
                }
                Ok(Err(ReportError::Other(message))) => {
                    failure = Some(FwFailure::Other(message));
                    break;
                }
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
        }
    }
    if failure.is_none() {
        failure = check_diagnostics(&shared, ctx.operation);
    }

    // stop(): token-verified group cleanup, then wait for the launcher to exit.
    let stopped = stop_owned(&run_id, pid, &shared, &notify).await;
    group_guard.armed = false;
    let (stdout, stderr, exit) = {
        let state = shared.lock().expect("shared");
        (
            Captured {
                text: String::from_utf8_lossy(&state.stdout).into_owned(),
                bytes: state.stdout.len(),
                observed_bytes: state.stdout_observed,
            },
            Captured {
                text: String::from_utf8_lossy(&state.stderr).into_owned(),
                bytes: state.stderr.len(),
                observed_bytes: state.stderr_observed,
            },
            state.exit,
        )
    };
    let (exit_code, signal) = match exit {
        Some((code, signal)) => (code, signal.map(signal_name)),
        None => (None, None),
    };
    if let Err(reason) = stopped {
        return Err(FwFailure::Typed(ToolError::Cleanup {
            provider_id: ctx.engine.to_string(),
            operation: "close_binary".to_string(),
            resources: vec![run_id, ctx.cwd.to_string()],
            diagnostics: json!({
                "reason": reason,
                "leader_pid": pid,
                "process_group_id": pid,
                "exit_code": exit_code,
                "signal": signal,
                "stdout": stdout.text,
                "stderr": stderr.text,
                "stdout_bytes": stdout.bytes,
                "stderr_bytes": stderr.bytes,
                "previous_error": failure.as_ref().map(failure_message),
            }),
            partial: None,
        }));
    }
    if let Some(error) = failure {
        return Err(error);
    }
    let accepted = exit_code == Some(0) || (ctx.accept_reported_extraction_failure && exit_code == Some(1));
    if !accepted {
        return Err(FwFailure::Typed(ToolError::Adapter {
            provider_id: ctx.engine.to_string(),
            operation: ctx.operation.to_string(),
            diagnostics: Some(json!({
                "reason": "Tool failed; inspect exit status and stderr for format, dependency, sandbox or resource-limit failures",
                "exit_code": exit_code,
                "signal": signal,
                "stdout": stdout.text,
                "stderr": stderr.text,
                "stdout_bytes": stdout.bytes,
                "stderr_bytes": stderr.bytes,
            })),
        }));
    }
    Ok(RunResult {
        stdout,
        stderr,
        exit_code,
        signal,
        command: ctx.command.to_string(),
        args: ctx.args,
        resource_limiter: ctx.limiter.to_string(),
    })
}

async fn pump<R: tokio::io::AsyncRead + Unpin>(
    mut pipe: R,
    shared: Arc<Mutex<Shared>>,
    notify: Arc<Notify>,
    is_stdout: bool,
) {
    let mut buffer = vec![0u8; 32 * 1024];
    loop {
        match pipe.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(n) => feed(&shared, &notify, is_stdout, &buffer[..n]),
        }
    }
    shared.lock().expect("shared").readers_closed += 1;
    notify.notify_waiters();
}

fn failure_message(failure: &FwFailure) -> String {
    match failure {
        FwFailure::Typed(error) => error.message(),
        FwFailure::Other(message) => message.clone(),
        FwFailure::Protocol => "Tool report violated the pinned producer protocol".to_string(),
    }
}

fn check_diagnostics(shared: &Arc<Mutex<Shared>>, operation: &str) -> Option<FwFailure> {
    let state = shared.lock().expect("shared");
    if !state.truncated {
        return None;
    }
    Some(FwFailure::Typed(ToolError::OutputWithCapture {
        operation: operation.to_string(),
        reason: format!("Tool diagnostics exceeded the {DIAGNOSTIC_BYTES}-byte capture budget"),
        captured: json!({
            "stdout": String::from_utf8_lossy(&state.stdout),
            "stderr": String::from_utf8_lossy(&state.stderr),
            "truncated": true,
        }),
    }))
}

async fn stop_owned(
    run_id: &str,
    pgid: i32,
    shared: &Arc<Mutex<Shared>>,
    notify: &Notify,
) -> Result<(), String> {
    let cleanup = |run_id: String| async move {
        tokio::task::spawn_blocking(move || cleanup_owned_group(&run_id, pgid))
            .await
            .unwrap_or_else(|e| Cleanup::Failed(e.to_string()))
    };
    if let Cleanup::Failed(reason) = cleanup(run_id.to_string()).await {
        return Err(reason);
    }
    if wait_exit(shared, notify, KILL_GRACE).await {
        return Ok(());
    }
    if let Cleanup::Failed(reason) = cleanup(run_id.to_string()).await {
        return Err(reason);
    }
    if wait_exit(shared, notify, KILL_GRACE).await {
        return Ok(());
    }
    Err("verified process-group cleanup did not stop the launcher".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A limiter stand-in: drops its prlimit options and runs the command.
    fn limiter(dir: &std::path::Path) -> String {
        let path = dir.join("limiter.sh");
        std::fs::write(&path, "#!/bin/sh\nwhile [ \"$1\" != \"--\" ]; do shift; done\nshift\nexec \"$@\"\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn context<'a>(
        dir: &'a str,
        limiter: &'a str,
        script: &str,
        env: &'a HashMap<String, String>,
        deadline: Instant,
    ) -> RunContext<'a> {
        RunContext {
            engine: "binwalk",
            operation: "inspect_firmware_regions",
            command: "/bin/sh",
            limiter,
            args: vec!["-c".to_string(), script.to_string()],
            cwd: dir,
            host_environment: env,
            output_budget: None,
            accept_reported_extraction_failure: false,
            deadline,
        }
    }

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("tw-runner-{name}-{}", random_uuid()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn captures_output_and_exit() {
        let dir = temp("capture");
        let limiter = limiter(&dir);
        let env = HashMap::new();
        let dir_text = dir.to_string_lossy().into_owned();
        let ok = run_command(context(&dir_text, &limiter, "echo out; echo err >&2", &env, Instant::now() + Duration::from_secs(20)))
            .await
            .unwrap_or_else(|_| panic!("run failed"));
        assert_eq!(ok.exit_code, Some(0));
        assert_eq!(ok.stdout.text, "out\n");
        assert_eq!(ok.stderr.text, "err\n");
        assert_eq!(ok.stdout.observed_bytes, 4);
        let failed = run_command(context(&dir_text, &limiter, "exit 7", &env, Instant::now() + Duration::from_secs(20))).await;
        assert!(matches!(failed, Err(FwFailure::Typed(ToolError::Adapter { .. }))));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn deadline_stops_the_owned_group() {
        let dir = temp("deadline");
        let limiter = limiter(&dir);
        let env = HashMap::new();
        let dir_text = dir.to_string_lossy().into_owned();
        let started = Instant::now();
        let outcome = run_command(context(&dir_text, &limiter, "sleep 30", &env, Instant::now() + Duration::from_millis(400))).await;
        assert!(matches!(outcome, Err(FwFailure::Typed(ToolError::Timeout { .. }))));
        assert!(started.elapsed() < Duration::from_secs(10), "the group was not stopped promptly");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn stray_descendants_are_killed_after_a_clean_exit() {
        let dir = temp("stray");
        let limiter = limiter(&dir);
        let env = HashMap::new();
        let dir_text = dir.to_string_lossy().into_owned();
        let marker = format!("tw-stray-{}", random_uuid());
        let script = format!("sh -c 'sleep 31; true # {marker}' >/dev/null 2>&1 & echo started");
        let outcome = run_command(context(&dir_text, &limiter, &script, &env, Instant::now() + Duration::from_secs(20))).await;
        assert!(outcome.is_ok());
        // The marker is part of the stray shell's command line, so a survivor is visible.
        let alive = std::process::Command::new("pgrep").arg("-f").arg(&marker).output().unwrap();
        assert!(String::from_utf8_lossy(&alive.stdout).trim().is_empty(), "stray process survived");
        let _ = std::fs::remove_dir_all(dir);
    }
}
