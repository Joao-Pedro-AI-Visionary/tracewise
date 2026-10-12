//! Port of REA `process/capture/ProcessHarness.ts` and
//! `ProcessCaptureLifecycle.ts` (Linux).
//!
//! The target runs under a PTY opened with `portable-pty`. It cannot go
//! through `proc-supervisor`: that crate wraps `tokio::process::Command` with
//! piped stdio, while a PTY capture needs the slave side as stdio plus
//! `setsid` + `TIOCSCTTY` in the child, which `portable-pty` performs. Exit
//! status is read with `waitpid` so killed targets report the signal number
//! the way node-pty does (`code` 0 / `signal` N), and ownership is enforced
//! the REA way: every target carries `REA_PROCESS_RUN_ID`, and cleanup only
//! signals process groups whose members prove that token.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use serde_json::{json, Map, Value};

use super::filesystem::{classify_effects, files_value, snapshot_roots, FilesystemSnapshot};
use super::normalization::{bucket, normalize_samples, normalize_text, ProcessSample};
use super::ownership::{
    captured_process_group_ids, cleanup_owned_processes, observe_settlement, Sampler, RUN_ID_VARIABLE,
};
use super::renderer::{TerminalRenderer, TerminalRetention};
use super::scenario::{
    comparison_contract, digest_commitment, resolve_runtime_paths, scenario_commitment, ProcessScenario,
    ScenarioEvent,
};
use crate::error::JsError;

/// Version of the REA contract this port reproduces (`PRODUCT_IDENTITY.packageVersion`).
pub const REA_VERSION: &str = "6.3.0";
pub const PROVIDER_VERSION: &str = "3";
const SAMPLE_INTERVAL: Duration = Duration::from_millis(50);
const DESTROY_SOCKET_TIMEOUT: Duration = Duration::from_millis(200);

/// Node `process.arch` naming used by REA manifests and environments.
pub fn node_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "ia32",
        "powerpc64" => "ppc64",
        other => other,
    }
}

pub fn node_platform() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    }
}

/// A capture failure surfaced as an `isError` tool result.
#[derive(Debug)]
pub struct CaptureFailure {
    pub message: String,
    pub cleanup_incomplete: bool,
}

fn failure(message: impl Into<String>) -> CaptureFailure {
    CaptureFailure { message: message.into(), cleanup_incomplete: false }
}

impl From<JsError> for CaptureFailure {
    fn from(error: JsError) -> Self {
        let message = match error {
            JsError::Io(m) | JsError::InvalidInput(m) | JsError::Domain(m) | JsError::Format(m) | JsError::Path(m)
            | JsError::Integrity(m) => m,
        };
        failure(message)
    }
}

/// Monotonic observation-order ledger.
#[derive(Default)]
struct Journal(Vec<Value>);

impl Journal {
    fn record(&mut self, collection: &str, index: usize) {
        let order = self.0.len();
        self.0.push(json!({ "capture_order": order, "collection": collection, "index": index }));
    }
}

struct ExecutableIdentity {
    dev: u64,
    ino: u64,
    mode: u32,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

fn identity(meta: &std::fs::Metadata) -> ExecutableIdentity {
    ExecutableIdentity {
        dev: meta.dev(),
        ino: meta.ino(),
        mode: meta.mode(),
        size: meta.size(),
        mtime: (meta.mtime(), meta.mtime_nsec()),
        ctime: (meta.ctime(), meta.ctime_nsec()),
    }
}

fn same_identity(a: &ExecutableIdentity, b: &ExecutableIdentity) -> bool {
    a.dev == b.dev && a.ino == b.ino && a.mode == b.mode && a.size == b.size && a.mtime == b.mtime && a.ctime == b.ctime
}

struct SelectedExecutable {
    sha256: Option<String>,
    identity: Option<ExecutableIdentity>,
    reason: Option<String>,
}

/// Sample the selected file without launching it; retain file identity.
fn observe_selected_executable(path: &str) -> SelectedExecutable {
    use std::os::unix::fs::OpenOptionsExt;
    use sha2::{Digest, Sha256};
    let fail = |error: std::io::Error| SelectedExecutable {
        sha256: None,
        identity: None,
        reason: Some(format!("Executable file observation failed: {error}")),
    };
    let mut file = match std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(path) {
        Ok(f) => f,
        Err(e) => return fail(e),
    };
    let opened = match file.metadata() {
        Ok(m) => m,
        Err(e) => return fail(e),
    };
    if !opened.is_file() {
        return SelectedExecutable { sha256: None, identity: None, reason: Some("Selected executable is not a regular file.".into()) };
    }
    let opened_identity = identity(&opened);
    match std::fs::metadata(path) {
        Ok(m) if same_identity(&opened_identity, &identity(&m)) => {}
        Ok(_) => {
            return SelectedExecutable {
                sha256: None,
                identity: None,
                reason: Some("Selected executable path changed while it was being opened.".into()),
            }
        }
        Err(e) => return fail(e),
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buffer[..n]),
            Err(e) => return fail(e),
        }
    }
    match file.metadata() {
        Ok(m) if same_identity(&opened_identity, &identity(&m)) => SelectedExecutable {
            sha256: Some(hex::encode(hasher.finalize())),
            identity: Some(opened_identity),
            reason: None,
        },
        Ok(_) => SelectedExecutable {
            sha256: None,
            identity: None,
            reason: Some("Selected executable changed while its contents were sampled.".into()),
        },
        Err(e) => fail(e),
    }
}

struct LaunchedExecutable {
    selected_sha256: Option<String>,
    sha256: Option<String>,
    state: &'static str,
    reason: Option<String>,
}

/// Compare the selected file metadata with the path immediately after spawn.
fn observe_launched_executable(path: &str, selected: &SelectedExecutable) -> LaunchedExecutable {
    let (Some(selected_identity), Some(sha)) = (&selected.identity, &selected.sha256) else {
        return LaunchedExecutable {
            selected_sha256: selected.sha256.clone(),
            sha256: None,
            state: "unknown",
            reason: Some(selected.reason.clone().unwrap_or_else(|| "Selected executable identity is unavailable.".into())),
        };
    };
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() && same_identity(selected_identity, &identity(&meta)) => LaunchedExecutable {
            selected_sha256: Some(sha.clone()),
            sha256: Some(sha.clone()),
            state: "path_metadata_unchanged",
            reason: None,
        },
        Ok(_) => LaunchedExecutable {
            selected_sha256: Some(sha.clone()),
            sha256: None,
            state: "unknown",
            reason: Some("Executable path metadata changed between sampling and spawn.".into()),
        },
        Err(error) => LaunchedExecutable {
            selected_sha256: Some(sha.clone()),
            sha256: None,
            state: "unknown",
            reason: Some(format!("Executable file observation failed: {error}")),
        },
    }
}

fn iso_now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn random_uuid() -> String {
    let mut bytes = [0u8; 16];
    if std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes)).is_err() {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
        bytes.copy_from_slice(&(nanos ^ ((std::process::id() as u128) << 64)).to_le_bytes());
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

/// Node `StringDecoder('utf8')`: hold incomplete trailing sequences and
/// replace invalid bytes with U+FFFD.
fn decode_utf8(pending: &mut Vec<u8>, chunk: &[u8]) -> String {
    pending.extend_from_slice(chunk);
    let mut out = String::new();
    let mut rest: &[u8] = pending;
    loop {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                out.push_str(s);
                rest = &[];
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                out.push_str(std::str::from_utf8(&rest[..valid]).unwrap_or_default());
                match error.error_len() {
                    None => {
                        rest = &rest[valid..];
                        break;
                    }
                    Some(len) => {
                        out.push('\u{FFFD}');
                        rest = &rest[valid + len..];
                    }
                }
            }
        }
    }
    *pending = rest.to_vec();
    out
}

fn wait_status(pid: libc::pid_t) -> Option<(i64, i64)> {
    let mut status: libc::c_int = 0;
    // SAFETY: `status` is a valid out-pointer; WNOHANG never blocks.
    let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if rc == pid {
        let code = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) as i64 } else { 0 };
        let signal = if libc::WIFSIGNALED(status) { libc::WTERMSIG(status) as i64 } else { 0 };
        Some((code, signal))
    } else if rc < 0 {
        // Already reaped elsewhere: report an unknown normal exit.
        Some((0, 0))
    } else {
        None
    }
}

enum PtyMessage {
    Data(Vec<u8>),
    Closed,
}

enum RenderOp {
    Write(String, u64),
    Resize(u16, u16, u64),
}

fn signal_number(name: &str) -> libc::c_int {
    match name {
        "SIGINT" => libc::SIGINT,
        "SIGTERM" => libc::SIGTERM,
        _ => libc::SIGKILL,
    }
}

fn host_environment() -> Vec<(String, String)> {
    std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .collect()
}

/// Build the child environment: host plus overrides, node-pty `TERM`/`PWD`, run token.
fn child_environment(scenario: &ProcessScenario, host: &[(String, String)], run_id: &str) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = Vec::new();
    let mut set = |key: &str, value: &str| {
        if let Some(entry) = env.iter_mut().find(|(k, _)| k == key) {
            entry.1 = value.to_string();
        } else {
            env.push((key.to_string(), value.to_string()));
        }
    };
    for (k, v) in host.iter().chain(scenario.environment.iter()) {
        set(k, v);
    }
    // node-pty assigns `env.PWD = cwd` and `env.TERM = name` ("xterm-256color").
    set("TERM", "xterm-256color");
    set(RUN_ID_VARIABLE, run_id);
    set("PWD", &scenario.working_directory);
    env
}

struct Exit {
    code: i64,
    signal: i64,
    reason: &'static str,
}

fn retention_unknowns(details: &Value) -> Vec<(&'static str, String)> {
    let mut unknowns = Vec::new();
    let omitted = |r: &Value| r["observed_frames"].as_u64() > r["retained_frames"].as_u64();
    if omitted(&details["raw_terminal"]) {
        unknowns.push(("terminal", "Raw PTY chunks exceeded output_bytes and were omitted; rendered states also lack those inputs. See truncation_details.raw_terminal.".to_string()));
    }
    if omitted(&details["rendered_terminal"]) {
        unknowns.push(("terminal", "Cumulative rendered state and visible-line bytes exceeded output_bytes; whole rendered frames were omitted. Raw PTY coverage is reported separately. See truncation_details.rendered_terminal.".to_string()));
    }
    for (name, key) in [("before", "filesystem_before"), ("after_settlement", "filesystem_after")] {
        let coverage = &details[key];
        if coverage["enumeration_truncated"].as_bool() == Some(true) {
            let reasons: Vec<&str> = coverage["enumeration_reasons"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
            unknowns.push(("filesystem", format!("Filesystem {name} path enumeration was incomplete: {}. See truncation_details.", reasons.join(", "))));
        }
        let omissions = coverage["hash_omissions"].as_array().map_or(0, Vec::len);
        if omissions > 0 {
            unknowns.push(("filesystem", format!("Filesystem {name} omitted {omissions} whole-file digests; per-path reasons and remaining file_bytes budget are in truncation_details.")));
        }
    }
    if details["process"]["sampling_partial"].as_bool() == Some(true) {
        unknowns.push(("process", "Process sampling stopped with incomplete observations; sample_limit is reported in truncation_details.process.".to_string()));
    }
    unknowns
}

/// Execute one validated scenario and return the verified capture result.
#[allow(clippy::too_many_lines)]
pub fn run_capture(input: &ProcessScenario) -> Result<Value, CaptureFailure> {
    let host_env = host_environment();
    let scenario = resolve_runtime_paths(input, &host_env)?;
    let before = snapshot_roots(&scenario)?;
    let run_id = random_uuid();
    let temporary = tempfile::Builder::new()
        .prefix("rea-process-")
        .tempdir()
        .map_err(|e| failure(format!("temporary root could not be created: {e}")))?;
    let temporary_root = temporary.path().to_string_lossy().into_owned();
    let mut journal = Journal::default();
    journal.record("filesystem_checkpoints", 0);

    let selected = observe_selected_executable(&scenario.executable);
    let started_at = iso_now();
    let started = Instant::now();
    let elapsed = |at: Instant| at.duration_since(started).as_millis() as u64;
    let bucket_ms = scenario.normalization.time_bucket_ms;

    let pty = native_pty_system();
    let pair = pty
        .openpty(PtySize { rows: scenario.terminal.rows, cols: scenario.terminal.columns, pixel_width: 0, pixel_height: 0 })
        .map_err(|e| failure(format!("PTY could not be opened: {e}")))?;
    let mut command = CommandBuilder::new(&scenario.executable);
    command.args(&scenario.arguments);
    command.cwd(&scenario.working_directory);
    command.env_clear();
    for (k, v) in child_environment(&scenario, &host_env, &run_id) {
        command.env(k, v);
    }
    let child = pair
        .slave
        .spawn_command(command)
        .map_err(|e| failure(format!("process could not be spawned: {e}")))?;
    drop(pair.slave);
    let Some(root_pid) = child.process_id() else {
        return Err(failure("spawned PTY process has no pid"));
    };
    let root_pid = root_pid as u64;
    let launched = observe_launched_executable(&scenario.executable, &selected);
    let mut reader = pair.master.try_clone_reader().map_err(|e| failure(format!("PTY reader unavailable: {e}")))?;
    let mut writer = pair.master.take_writer().map_err(|e| failure(format!("PTY writer unavailable: {e}")))?;
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => {
                    let _ = sender.send(PtyMessage::Closed);
                    break;
                }
                Ok(n) => {
                    if sender.send(PtyMessage::Data(buffer[..n].to_vec())).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let normalize_pid = root_pid as i64;
    let normalize = |value: &str| normalize_text(value, &scenario, &temporary_root, normalize_pid);
    let mut renderer = TerminalRenderer::new(
        scenario.terminal.columns,
        scenario.terminal.rows,
        scenario.terminal.scrollback,
        scenario.limits.output_bytes,
    );
    let mut frames: Vec<Value> = Vec::new();
    let mut raw = TerminalRetention { budget_bytes: scenario.limits.output_bytes, ..TerminalRetention::default() };
    let mut pending_bytes = Vec::new();
    let mut interactions: Vec<Value> = Vec::new();
    let mut dispatched = vec![false; scenario.events.len()];
    let mut samples: Vec<ProcessSample> = Vec::new();
    let mut sampler = Sampler::new(root_pid, &run_id, scenario.limits.processes);
    let mut last_sample: Option<Instant> = None;
    let mut last_output = started;
    let mut reason: &'static str = "exited";
    let mut killed = false;
    let mut exit_status: Option<(i64, i64, Instant)> = None;
    let mut closed = false;
    // Renders queued in an earlier loop turn (xterm parses writes asynchronously).
    let mut deferred: VecDeque<RenderOp> = VecDeque::new();
    let mut queued: VecDeque<RenderOp> = VecDeque::new();

    let flush = |ops: &mut VecDeque<RenderOp>, renderer: &mut TerminalRenderer, journal: &mut Journal| {
        while let Some(op) = ops.pop_front() {
            let retained = match op {
                RenderOp::Write(data, at) => renderer.write(&data, at, &normalize),
                RenderOp::Resize(c, r, at) => renderer.resize(c, r, at, &normalize),
            };
            if let Some(sequence) = retained {
                journal.record("rendered_frames", sequence);
            }
        }
    };

    let exit = loop {
        let mut messages = Vec::new();
        match receiver.recv_timeout(Duration::from_millis(5)) {
            Ok(m) => {
                messages.push(m);
                while let Ok(m) = receiver.try_recv() {
                    messages.push(m);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => closed = true,
        }
        for message in messages {
            match message {
                PtyMessage::Closed => closed = true,
                PtyMessage::Data(bytes) => {
                    let data = decode_utf8(&mut pending_bytes, &bytes);
                    if data.is_empty() {
                        continue;
                    }
                    let now = Instant::now();
                    last_output = now;
                    let size = data.len() as u64;
                    raw.observed_bytes += size;
                    raw.observed_frames += 1;
                    if raw.retained_bytes + size > scenario.limits.output_bytes {
                        continue;
                    }
                    raw.retained_bytes += size;
                    raw.retained_frames += 1;
                    let at_ms = bucket(elapsed(now), bucket_ms);
                    let normalized = normalize(&data);
                    let sequence = frames.len();
                    let mut frame = Map::new();
                    frame.insert("sequence".into(), json!(sequence));
                    frame.insert("at_ms".into(), json!(at_ms));
                    frame.insert("data".into(), json!(normalized));
                    if normalized != data {
                        frame.insert("raw_data".into(), json!(data));
                    }
                    frames.push(Value::Object(frame));
                    queued.push_back(RenderOp::Write(data, at_ms));
                    journal.record("frames", sequence);
                }
            }
        }
        let now = Instant::now();
        if exit_status.is_none() {
            if closed {
                // The PTY reached EOF: the target is exiting; observe it now.
                let deadline = Instant::now() + Duration::from_millis(100);
                while exit_status.is_none() && Instant::now() < deadline {
                    exit_status = wait_status(root_pid as libc::pid_t).map(|(c, s)| (c, s, Instant::now()));
                    if exit_status.is_none() {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            } else {
                exit_status = wait_status(root_pid as libc::pid_t).map(|(c, s)| (c, s, now));
            }
        }
        if exit_status.is_none() {
            // Scheduled interactions.
            for (index, event) in scenario.events.iter().enumerate() {
                if dispatched[index] || elapsed(now) < event.at_ms() {
                    continue;
                }
                dispatched[index] = true;
                let dispatched_at = elapsed(Instant::now());
                let outcome_ok = match event {
                    ScenarioEvent::Input { data, .. } => writer.write_all(data.as_bytes()).and_then(|()| writer.flush()).is_ok(),
                    ScenarioEvent::Resize { columns, rows, .. } => {
                        let ok = pair
                            .master
                            .resize(PtySize { rows: *rows, cols: *columns, pixel_width: 0, pixel_height: 0 })
                            .is_ok();
                        queued.push_back(RenderOp::Resize(*columns, *rows, bucket(dispatched_at, bucket_ms)));
                        ok
                    }
                    // SAFETY: plain syscall with integer arguments.
                    ScenarioEvent::Signal { signal, .. } => unsafe { libc::kill(root_pid as libc::pid_t, signal_number(signal)) == 0 },
                };
                let data = match event {
                    ScenarioEvent::Input { data, sensitive: true, .. } => format!("<redacted-input:{}-bytes>", data.len()),
                    ScenarioEvent::Input { data, .. } => normalize_text(data, &scenario, "<no-temporary-root>", -1),
                    other => other.descriptor(),
                };
                let sequence = interactions.len();
                interactions.push(json!({
                    "sequence": sequence,
                    "scheduled_at_ms": event.at_ms(),
                    "dispatched_at_ms": dispatched_at,
                    "type": event.type_name(),
                    "data": data,
                    "outcome": if outcome_ok { "dispatched" } else { "failed" },
                }));
                journal.record("interaction_events", sequence);
            }
            // Deadlines (REA checks every 20 ms; the first trigger kills).
            if !killed {
                if elapsed(now) >= scenario.timeout_ms {
                    reason = "timeout";
                } else if now.duration_since(last_output).as_millis() as u64 >= scenario.idle_timeout_ms {
                    reason = "idle_timeout";
                }
                if reason != "exited" {
                    killed = true;
                    // SAFETY: plain syscall with integer arguments.
                    unsafe { libc::kill(root_pid as libc::pid_t, libc::SIGKILL) };
                }
            }
        }
        if last_sample.is_none_or(|t| now.duration_since(t) >= SAMPLE_INTERVAL) {
            last_sample = Some(now);
            for sample in sampler.sample(elapsed(now), samples.len()) {
                journal.record("process_samples", samples.len());
                samples.push(sample);
            }
        }
        if let Some((code, signal, at)) = exit_status {
            if closed || now.duration_since(at) >= DESTROY_SOCKET_TIMEOUT {
                journal.record("lifecycle", 0);
                let exited_at = elapsed(Instant::now());
                for (index, event) in scenario.events.iter().enumerate() {
                    if dispatched[index] {
                        continue;
                    }
                    let sequence = interactions.len();
                    interactions.push(json!({
                        "sequence": sequence,
                        "scheduled_at_ms": event.at_ms(),
                        "dispatched_at_ms": exited_at,
                        "type": event.type_name(),
                        "data": event.descriptor(),
                        "outcome": "target_exited",
                    }));
                    journal.record("interaction_events", sequence);
                }
                break Exit { code, signal, reason };
            }
        }
        flush(&mut deferred, &mut renderer, &mut journal);
        deferred.append(&mut queued);
    };
    deferred.append(&mut queued);
    flush(&mut deferred, &mut renderer, &mut journal);

    let group_ids = captured_process_group_ids(root_pid, &samples);
    let (settlement_state, settlement_elapsed) = observe_settlement(&run_id, &group_ids, scenario.settle_ms, &mut || {
        let now = Instant::now();
        if last_sample.is_none_or(|t| now.duration_since(t) >= SAMPLE_INTERVAL) {
            last_sample = Some(now);
            for sample in sampler.sample(elapsed(now), samples.len()) {
                journal.record("process_samples", samples.len());
                samples.push(sample);
            }
        }
    });
    journal.record("lifecycle", 1);

    let after = snapshot_roots(&scenario)?;
    journal.record("filesystem_checkpoints", 1);
    let after_at = elapsed(Instant::now());
    let completed_at = iso_now();

    // Cleanup before the capture becomes immutable.
    let sampled_groups: Vec<u64> = captured_process_group_ids(root_pid, &samples).into_iter().filter(|g| *g != root_pid).collect();
    let cleanup = cleanup_owned_processes(&run_id, root_pid, &sampled_groups);
    drop(writer);
    drop(pair.master);
    drop(child);
    let removed = temporary.close();
    if let Err(reason) = cleanup {
        return Err(CaptureFailure { message: format!("owned_process_group: {reason}"), cleanup_incomplete: true });
    }
    if let Err(error) = removed {
        return Err(CaptureFailure { message: format!("temporary_root: {error}"), cleanup_incomplete: true });
    }

    let commitment = scenario_commitment(&scenario, launched.selected_sha256.as_deref());
    let contract = comparison_contract(&scenario);
    let normalization = scenario.normalization.to_value();
    let manifest = json!({
        "rea_version": REA_VERSION,
        "provider_version": PROVIDER_VERSION,
        "platform": node_platform(),
        "architecture": node_architecture(),
        "pty_backend": "node-pty",
        "started_at": started_at,
        "completed_at": completed_at,
        "full_scenario_sha256": digest_commitment(&commitment)?,
        "comparison_contract_sha256": digest_commitment(&contract)?,
        "scenario": commitment,
        "comparison_contract": contract,
        "selected_executable_sha256": launched.selected_sha256,
        "executable_sha256": launched.sha256,
        "executable_identity": { "state": launched.state, "reason": launched.reason },
        "normalization_sha256": digest_commitment(&normalization)?,
    });
    let manifest = reorder(&manifest, &[
        "rea_version", "provider_version", "platform", "architecture", "pty_backend", "started_at", "completed_at",
        "scenario", "comparison_contract", "full_scenario_sha256", "comparison_contract_sha256",
        "selected_executable_sha256", "executable_sha256", "executable_identity", "normalization_sha256",
    ]);

    let effects = classify_effects(&before, &after);
    let process_coverage = json!({
        "sample_limit": scenario.limits.processes,
        "sampling_partial": sampler.partial,
        "retained_samples": samples.len(),
        "sample_limit_reached": sampler.limit_reached,
        "sampling_failures": sampler.failures,
        "first_sampling_failure": sampler.first_failure,
        "coverage": "sampled",
    });
    let truncation_details = json!({
        "raw_terminal": raw.to_value(),
        "rendered_terminal": renderer.retention().to_value(),
        "filesystem_before": before.coverage.to_value(),
        "filesystem_after": after.coverage.to_value(),
        "process": process_coverage,
    });
    let truncated = raw.omitted()
        || renderer.retention().omitted()
        || before.coverage.truncated()
        || after.coverage.truncated()
        || sampler.partial;
    let coverage_unknowns = retention_unknowns(&truncation_details);
    let (limitations, residual_unknowns) = capture_limitations(&scenario, &effects, &coverage_unknowns, sampler.partial);
    let exit_value = json!({
        "code": if exit.reason == "exited" && exit.code >= 0 { json!(exit.code) } else { Value::Null },
        "signal": exit.signal,
        "reason": exit.reason,
    });
    let settlement = json!({
        "state": settlement_state,
        "elapsed_ms": settlement_elapsed,
        "cleanup_outcome": if settlement_state == "quiesced" { "not_required" } else { "cleaned" },
    });
    let normalized_samples: Vec<Value> = normalize_samples(&samples, &scenario, root_pid)
        .into_iter()
        .map(|s| json!({
            "at_ms": s.at_ms,
            "pid": s.pid,
            "parent_pid": s.parent_pid,
            "command": s.command,
            "process_group_id": s.process_group_id,
            "session_id": s.session_id,
        }))
        .collect();
    let checkpoints = json!([
        checkpoint("before", 0, &before, Vec::new()),
        checkpoint("after_settlement", after_at, &after, effects.clone()),
    ]);
    Ok(json!({
        "manifest": manifest,
        "normalization": normalization,
        "frames": frames,
        "rendered_frames": renderer.frames(),
        "interaction_events": interactions,
        "exit": exit_value,
        "settlement": settlement,
        "process_samples": normalized_samples,
        "filesystem_checkpoints": checkpoints,
        "event_journal": journal.0,
        "files_before": files_value(&before.files),
        "files_after": files_value(&after.files),
        "filesystem_effects": effects,
        "truncated": truncated,
        "truncation_details": truncation_details,
        "limitations": limitations,
        "residual_unknowns": residual_unknowns,
        "cleanup": { "owned_process_group": "verified", "temporary_root": "removed" },
    }))
}

fn reorder(value: &Value, keys: &[&str]) -> Value {
    let mut map = Map::new();
    for key in keys {
        if let Some(v) = value.get(*key) {
            map.insert((*key).to_string(), v.clone());
        }
    }
    Value::Object(map)
}

fn checkpoint(name: &str, at_ms: u64, snapshot: &FilesystemSnapshot, effects: Vec<Value>) -> Value {
    json!({
        "name": name,
        "at_ms": at_ms,
        "files": files_value(&snapshot.files),
        "effects": effects,
        "truncated": snapshot.truncated,
    })
}

const SENSITIVE_INPUT_UNKNOWN: &str = "Sensitive scripted input values are redacted from process capture Evidence.";
const FILESYSTEM_OBSERVATION_UNKNOWN: &str =
    "No filesystem observation paths were selected; filesystem effects remain unknown.";

/// `buildCaptureResult` limitations and residual unknowns.
fn capture_limitations(
    scenario: &ProcessScenario,
    effects: &[Value],
    coverage_unknowns: &[(&'static str, String)],
    sampling_partial: bool,
) -> (Vec<String>, Vec<Value>) {
    let has_paths = !scenario.filesystem_observation_paths.is_empty();
    let mut filesystem_unknowns: Vec<String> = Vec::new();
    for effect in effects {
        if effect["status"] == "unknown" {
            if let Some(reason) = effect["reason"].as_str() {
                if !filesystem_unknowns.iter().any(|r| r == reason) {
                    filesystem_unknowns.push(reason.to_string());
                }
            }
        }
    }
    let sensitive = scenario.has_sensitive_input();
    let mut limitations = vec![
        "The executable digest is a prelaunch file sample; matching path metadata immediately after spawn does not prove an atomic operating-system image binding.".to_string(),
        "Process trees are sampled and may omit short-lived descendants.".to_string(),
    ];
    if sampling_partial {
        limitations.push("Process-tree sampling ended with an incomplete observation.".into());
    }
    limitations.push("Filesystem observations are before/after snapshots, not syscall traces.".into());
    limitations.push("Inherited host environment variables are not recorded and may affect results.".into());
    if !has_paths {
        limitations.push(FILESYSTEM_OBSERVATION_UNKNOWN.into());
    }
    limitations.extend(filesystem_unknowns.iter().cloned());
    limitations.extend(coverage_unknowns.iter().map(|(_, r)| r.clone()));
    if sensitive {
        limitations.push(SENSITIVE_INPUT_UNKNOWN.into());
    }
    let mut unknowns = vec![
        json!({"scope": "process", "reason": "Process trees are sampled and may omit short-lived descendants."}),
        json!({"scope": "process", "reason": "The executable digest is a prelaunch file sample; operating-system image binding is not atomically observed."}),
        json!({"scope": "environment", "reason": "Inherited host environment variables are not recorded."}),
        json!({"scope": "network", "reason": "Network activity is not observed by this capture."}),
    ];
    if !has_paths {
        unknowns.push(json!({"scope": "filesystem", "reason": FILESYSTEM_OBSERVATION_UNKNOWN}));
    }
    unknowns.extend(filesystem_unknowns.iter().map(|r| json!({"scope": "filesystem", "reason": r})));
    if sensitive {
        unknowns.push(json!({"scope": "interaction", "reason": SENSITIVE_INPUT_UNKNOWN}));
    }
    unknowns.extend(
        coverage_unknowns.iter().filter(|(scope, _)| *scope != "terminal").map(|(scope, r)| json!({"scope": scope, "reason": r})),
    );
    (limitations, unknowns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoder_holds_partial_sequences() {
        let mut pending = Vec::new();
        assert_eq!(decode_utf8(&mut pending, &[b'a', 0xc3]), "a");
        assert_eq!(decode_utf8(&mut pending, &[0xa9]), "é");
        assert_eq!(decode_utf8(&mut pending, &[0xff, b'b']), "\u{FFFD}b");
    }
}
