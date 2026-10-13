//! Firmware inspection and extraction (`inspect_firmware_regions`,
//! `extract_firmware`): bring-your-own Binwalk 3.1.x and Unblob 26.6.x on Linux
//! (port of REA `FirmwareProvider.ts` and its collaborators).
//!
//! Flow: resolve the caller-supplied tool and `prlimit`, copy the firmware (or
//! the selected byte range) into a private runtime root, check the tool's
//! `--version` banner, run it once under `prlimit` in its own process group,
//! read and normalize its report, and for extraction publish the verified
//! regular files into the caller's absent output directory.

pub mod collate;
pub mod command;
pub mod files;
pub mod publish;
pub mod release;
pub mod reports;
pub mod runner;

use std::collections::HashMap;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use crate::error::ToolError;
use crate::firmware::command::{resolve_command, tool_unavailable};
use crate::firmware::files::{inventory, read_report, snapshot, ReportError};
use crate::firmware::release::{admit_version, Admission, Engine, TIMEOUT_MS};
use crate::firmware::runner::{random_uuid, run_command, OutputBudget, RunContext, RunResult};
use crate::fsutil::node_io_error;
use crate::input::{int, optional, prop, string, validate_props, with_default, Kind, Prop, StrTest};

pub const INSPECT_FIRMWARE_REGIONS: &str = "inspect_firmware_regions";
pub const EXTRACT_FIRMWARE: &str = "extract_firmware";
pub const FIRMWARE_TOOLS: [&str; 2] = [INSPECT_FIRMWARE_REGIONS, EXTRACT_FIRMWARE];

/// Any failure inside the provider before it is typed for the caller.
#[derive(Debug, Clone)]
pub enum FwFailure {
    /// A typed analysis error (`AnalysisError` in REA).
    Typed(ToolError),
    /// An untyped `Error`; its message becomes `diagnostics.reason`.
    Other(String),
    /// A zod parse failure of a tool report.
    Protocol,
}

impl From<ToolError> for FwFailure {
    fn from(error: ToolError) -> Self {
        FwFailure::Typed(error)
    }
}

const LIMITATIONS: [&str; 4] = [
    "Signature matches and reported sizes do not establish partition validity, encryption or runtime mappings. Binwalk may infer unknown lengths before emitting its report.",
    "Only Linux is supported by this integration. One worker, inherited per-process address-space/file-size/CPU limits and a deadline constrain execution; staging byte and entry budgets are polled and may transiently overshoot. Limits are not aggregate process-memory or filesystem quotas.",
    "Unblob's default sandbox and skip rules remain enabled. Missing external extractors, unknown chunks, encrypted chunks and depth limits yield partial coverage. Extracted code is never executed; only regular files are published, without executable permission bits.",
    "The actual launcher executable is hashed. Interpreter, shared libraries and installed Python package dependencies are not independently attested; source revision remains unknown for caller-supplied builds.",
];

/// What the MCP layer needs to compose the Evidence.
#[derive(Debug, Clone)]
pub struct FirmwareExecution {
    pub result: Value,
    pub raw_result: Value,
    pub limitations: Vec<String>,
    pub subject_path: String,
    pub subject_sha256: String,
    pub provider_id: &'static str,
    pub provider_name: &'static str,
    pub provider_version: String,
    pub location_start: u64,
    pub location_end: u64,
}

fn absolute_path(text: &str) -> bool {
    text.starts_with('/')
}

fn no_nul(text: &str) -> bool {
    !text.contains('\0')
}

fn path_kind(refine_message: &'static str) -> Kind {
    string(
        Some(1),
        None,
        vec![(no_nul as StrTest, "Local filesystem paths cannot contain NUL"), (absolute_path as StrTest, refine_message)],
    )
}

const PATH_MESSAGE: &str = "path must be an absolute local filesystem path (for example /tmp/firmware.bin or C:\\firmware\\firmware.bin)";

fn schema_for(tool: &str) -> Option<Vec<Prop>> {
    Some(match tool {
        INSPECT_FIRMWARE_REGIONS => vec![prop("path", path_kind(PATH_MESSAGE))],
        EXTRACT_FIRMWARE => vec![
            prop("path", path_kind(PATH_MESSAGE)),
            prop("output_directory", path_kind("output_directory must be an absolute local filesystem path")),
            optional(
                "range",
                Kind::Object(vec![
                    prop("offset", Kind::Int { min: Some(0), exclusive_min: false, max: Some(9_007_199_254_740_991), safe: false }),
                    prop("length", Kind::Int { min: Some(0), exclusive_min: true, max: Some(9_007_199_254_740_991), safe: false }),
                ]),
            ),
            with_default("max_depth", int(Some(1), Some(10)), json!(3)),
            with_default("max_output_bytes", int(Some(1), Some(512 * 1024 * 1024)), json!(256 * 1024 * 1024)),
            with_default("max_output_files", int(Some(1), Some(100_000)), json!(10_000)),
        ],
        _ => return None,
    })
}

/// Validate `arguments` for one firmware tool.
pub fn validate(tool: &str, arguments: &Value) -> Result<Map<String, Value>, String> {
    let props = schema_for(tool).ok_or_else(|| format!("Unknown tool: '{tool}'"))?;
    validate_props(tool, &props, arguments)
}

// ---------------------------------------------------------------- runtime --

/// Serialize requests like REA's queued provider: one firmware run at a time.
static QUEUE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn tmpdir(env: &HashMap<String, String>) -> String {
    let pick = |key: &str| env.get(key).filter(|v| !v.is_empty()).cloned();
    let dir = pick("TMPDIR").or_else(|| pick("TMP")).or_else(|| pick("TEMP")).unwrap_or_else(|| "/tmp".to_string());
    if dir.len() > 1 && dir.ends_with('/') {
        dir.trim_end_matches('/').to_string()
    } else {
        dir
    }
}

/// `mkdtemp(join(tmpdir, "rea-firmware-"))` with mode 0700.
fn create_private_root(env: &HashMap<String, String>) -> Result<String, String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let base = tmpdir(env);
    for _ in 0..64 {
        let uuid = random_uuid();
        let entropy: Vec<u8> = hex::decode(uuid.replace('-', "")).unwrap_or_default();
        let suffix: String = (0..6).map(|i| ALPHABET[(entropy[i] as usize) % ALPHABET.len()] as char).collect();
        let path = format!("{base}/rea-firmware-{suffix}");
        match std::fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| node_io_error(&e, "chmod", &path))?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(node_io_error(&error, "mkdtemp", &format!("{base}/rea-firmware-XXXXXX"))),
        }
    }
    Err("Could not allocate a private runtime directory".to_string())
}

async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(work).await.expect("blocking task")
}

fn engine_for(operation: &str) -> Engine {
    if operation == INSPECT_FIRMWARE_REGIONS {
        Engine::Binwalk
    } else {
        Engine::Unblob
    }
}

/// Run one validated request. `environment` is the process environment.
pub async fn execute(
    operation: &str,
    input: &Map<String, Value>,
    environment: &HashMap<String, String>,
) -> Result<FirmwareExecution, ToolError> {
    let _turn = QUEUE.lock().await;
    let engine = engine_for(operation);
    let deadline = Instant::now() + Duration::from_millis(TIMEOUT_MS);
    // Declared after `_turn`, so on cancellation it drops first: the private
    // root is gone before the next request may start.
    let mut root = RootGuard::default();
    let outcome = run_request(operation, input, environment, engine, deadline, &mut root.path).await;
    let outcome = outcome.map_err(|cause| map_failure(cause, operation, engine, deadline));
    finish_workspace(&mut root.path, outcome, operation, engine, input).await
}

/// Owns the private runtime root until `finish_workspace` has dealt with it.
/// If the request is cancelled (future dropped) the root is removed here; the
/// owned process group was already killed by the runner's guard, which drops
/// first.
#[derive(Default)]
struct RootGuard {
    path: Option<String>,
}

impl Drop for RootGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

fn map_failure(cause: FwFailure, operation: &str, engine: Engine, deadline: Instant) -> ToolError {
    match cause {
        FwFailure::Typed(error @ (ToolError::Cleanup { .. } | ToolError::CleanupWrapped { .. })) => error,
        _ if Instant::now() >= deadline => ToolError::Timeout { operation: operation.to_string(), timeout_ms: TIMEOUT_MS },
        FwFailure::Typed(error) => error,
        FwFailure::Protocol => ToolError::Output {
            operation: operation.to_string(),
            reason: "Tool report violated the pinned producer protocol".to_string(),
        },
        FwFailure::Other(message) => ToolError::Adapter {
            provider_id: engine.id().to_string(),
            operation: operation.to_string(),
            diagnostics: Some(json!({ "reason": message })),
        },
    }
}

/// `finishFirmwareWorkspace`: close the private root, keeping a completed
/// extraction visible beside a cleanup failure.
async fn finish_workspace(
    root_slot: &mut Option<String>,
    outcome: Result<FirmwareExecution, ToolError>,
    operation: &str,
    engine: Engine,
    input: &Map<String, Value>,
) -> Result<FirmwareExecution, ToolError> {
    if let Err(error) = &outcome {
        if let ToolError::Cleanup { resources, .. } | ToolError::CleanupWrapped { resources, .. } = error {
            // The root is retained on purpose (a process could not be proven
            // stopped), so the cancellation guard must not remove it.
            let retained = root_slot.take();
            match &retained {
                None => return outcome,
                Some(path) if resources.contains(path) => return outcome,
                Some(path) => {
                    let mut all = resources.clone();
                    all.push(path.clone());
                    let diagnostics = match error {
                        ToolError::Cleanup { diagnostics, .. } => diagnostics.clone(),
                        other => json!({ "reason": other.message() }),
                    };
                    return Err(ToolError::Cleanup {
                        provider_id: engine.id().to_string(),
                        operation: operation.to_string(),
                        resources: all,
                        diagnostics,
                        partial: None,
                    });
                }
            }
        }
    }
    let Some(path) = root_slot.clone() else { return outcome };
    let removal = {
        let target = path.clone();
        blocking(move || std::fs::remove_dir_all(&target).map_err(|e| e.to_string())).await
    };
    // Settled either way: removed, or reported below as a cleanup failure.
    *root_slot = None;
    match removal {
        Ok(()) => outcome,
        Err(reason) => {
            let mut resources = vec![path.clone()];
            if outcome.is_ok() && operation == EXTRACT_FIRMWARE {
                resources.push(input.get("output_directory").and_then(Value::as_str).unwrap_or_default().to_string());
            }
            let partial = outcome.as_ref().ok().map(completed_observation);
            let cleanup = ToolError::Cleanup {
                provider_id: engine.id().to_string(),
                operation: operation.to_string(),
                resources,
                diagnostics: json!({ "reason": reason }),
                partial,
            };
            match outcome {
                Ok(_) => Err(cleanup),
                Err(primary) => Err(ToolError::with_cleanup_failure(primary, cleanup, operation)),
            }
        }
    }
}

fn completed_observation(execution: &FirmwareExecution) -> Value {
    json!({
        "kind": "firmware",
        "result": execution.result,
        "provenance": {
            "raw_result": execution.raw_result,
            "provider": {
                "id": execution.provider_id,
                "name": execution.provider_name,
                "version": execution.provider_version,
            },
            "subject": {
                "path": execution.subject_path,
                "sha256": execution.subject_sha256,
                "format": "file",
            },
            "locations": [{ "kind": "file-offset-range", "start": execution.location_start, "end": execution.location_end }],
            "limitations": limitations_for(execution),
        },
    })
}

fn limitations_for(execution: &FirmwareExecution) -> Vec<String> {
    execution.limitations.clone()
}

async fn run_request(
    operation: &str,
    input: &Map<String, Value>,
    environment: &HashMap<String, String>,
    engine: Engine,
    deadline: Instant,
    root_slot: &mut Option<String>,
) -> Result<FirmwareExecution, FwFailure> {
    let lookup = {
        let environment = environment.clone();
        move |key: &str| environment.get(key).cloned()
    };
    let command = {
        let operation = operation.to_string();
        blocking(move || resolve_command(&lookup, engine, &operation)).await?
    };
    let root = {
        let environment = environment.clone();
        blocking(move || create_private_root(&environment)).await.map_err(FwFailure::Other)?
    };
    *root_slot = Some(root.clone());
    let path = input.get("path").and_then(Value::as_str).unwrap_or_default().to_string();
    let range = input.get("range").and_then(|r| {
        Some((r.get("offset")?.as_u64()?, r.get("length")?.as_u64()?))
    });
    let range = if operation == EXTRACT_FIRMWARE { range } else { None };
    let target = {
        let (operation, root) = (operation.to_string(), root.clone());
        blocking(move || snapshot(&operation, &path, range, &root)).await?
    };
    let run = |args: Vec<String>, budget: Option<OutputBudget>| {
        let command = &command;
        let root = &root;
        async move {
            run_command(RunContext {
                engine: engine.id(),
                operation,
                command: &command.command,
                limiter: &command.limiter,
                args,
                cwd: root,
                host_environment: environment,
                accept_reported_extraction_failure: budget.is_some(),
                output_budget: budget,
                deadline,
            })
            .await
        }
    };
    let version_run = run(vec!["--version".to_string()], None).await?;
    let version = crate::parse::js_trim(&version_run.stdout.text).to_string();
    if version_run.stdout.bytes > 1024 {
        return Err(tool_unavailable(
            engine.id(),
            operation,
            format!(
                "Tool version banner is {} bytes; expected a short {} version line.",
                version_run.stdout.bytes,
                engine.id()
            ),
        )
        .into());
    }
    let admitted = match admit_version(engine, &version) {
        Admission::Unsupported { message } | Admission::Unresolved { message } => {
            return Err(tool_unavailable(engine.id(), operation, message).into())
        }
        Admission::Verified { version } => (version, None),
        Admission::Compatible { version, limitation } => (version, Some(limitation)),
    };
    let engine_json = json!({
        "name": engine.id(),
        "version": admitted.0,
        "executable_path": command.command,
        "executable_sha256": command.sha256,
        "source_revision": Value::Null,
        "worker_count": 1,
    });
    let report_path = format!("{root}/report.json");
    let (result, raw) = if operation == INSPECT_FIRMWARE_REGIONS {
        let process_run = run(
            vec![
                "--quiet".into(),
                "--search-all".into(),
                "--threads".into(),
                "1".into(),
                "--log".into(),
                report_path.clone(),
                target.input_path.clone(),
            ],
            None,
        )
        .await?;
        let report = read_command_report(&report_path, engine, operation, &process_run).await?;
        let regions = reports::normalize_binwalk(&report, &target.input_path, target.size)?;
        let result = json!({
            "engine": engine_json,
            "input_size": target.size,
            "regions": regions,
            "coverage": "signature_scan",
        });
        let raw = json!({
            "report": report,
            "execution": process_run.to_json(),
            "version_execution": version_run.to_json(),
        });
        (result, raw)
    } else {
        let output_directory = input.get("output_directory").and_then(Value::as_str).unwrap_or_default().to_string();
        let max_depth = input.get("max_depth").and_then(Value::as_u64).unwrap_or(3);
        let max_bytes = input.get("max_output_bytes").and_then(Value::as_u64).unwrap_or(256 * 1024 * 1024);
        let max_files = input.get("max_output_files").and_then(Value::as_u64).unwrap_or(10_000);
        let output_root = format!("{root}/extracted");
        let process_run = run(
            vec![
                "--process-num".into(),
                "1".into(),
                "--depth".into(),
                max_depth.to_string(),
                "--randomness-depth".into(),
                "0".into(),
                "--report".into(),
                report_path.clone(),
                "--log".into(),
                format!("{root}/unblob.log"),
                "--extract-dir".into(),
                output_root.clone(),
                target.input_path.clone(),
            ],
            Some(OutputBudget { root: output_root.clone(), bytes: max_bytes, entries: max_files }),
        )
        .await?;
        let report = read_command_report(&report_path, engine, operation, &process_run).await?;
        let normalized = reports::normalize_unblob(
            &report,
            &reports::UnblobContext {
                input_path: &target.input_path,
                output_root: &output_root,
                sha256: &target.selection.sha256,
                length: target.selection.length,
                offset: target.selection.offset,
                max_depth,
            },
        )?;
        if process_run.exit_code == Some(1) && normalized.diagnostics.is_empty() {
            return Err(FwFailure::Typed(ToolError::Output {
                operation: operation.to_string(),
                reason: "Unblob failed without a reported extraction diagnostic".to_string(),
            }));
        }
        let entries = {
            let output_root = output_root.clone();
            blocking(move || inventory(&output_root, max_bytes, max_files)).await.map_err(report_failure(operation))?
        };
        let selection = (target.selection.offset, target.selection.length, target.selection.sha256.clone());
        let engine_clone = engine_json.clone();
        let result = blocking(move || {
            publish::publish_extraction(
                &output_directory,
                &entries,
                &normalized,
                (selection.0, selection.1, &selection.2),
                &engine_clone,
            )
        })
        .await?;
        let raw = json!({
            "report": report,
            "execution": process_run.to_json(),
            "version_execution": version_run.to_json(),
        });
        (result, raw)
    };
    let mut limitations: Vec<String> = LIMITATIONS.iter().map(|s| s.to_string()).collect();
    if let Some(extra) = admitted.1 {
        limitations.push(extra);
    }
    Ok(FirmwareExecution {
        result,
        raw_result: raw,
        limitations,
        subject_path: target.subject_path.clone(),
        subject_sha256: target.sha256.clone(),
        provider_id: engine.id(),
        provider_name: engine.label(),
        provider_version: admitted.0,
        location_start: target.selection.offset,
        location_end: target.selection.offset + target.selection.length,
    })
}

fn report_failure(operation: &str) -> impl Fn(ReportError) -> FwFailure + '_ {
    move |error| match error {
        ReportError::Output(reason) => {
            FwFailure::Typed(ToolError::Output { operation: operation.to_string(), reason })
        }
        ReportError::Other(message) => FwFailure::Other(message),
    }
}

/// `readFirmwareCommandReport`: keep tool diagnostics when the report is unusable.
async fn read_command_report(
    path: &str,
    engine: Engine,
    operation: &str,
    execution: &RunResult,
) -> Result<Value, FwFailure> {
    let owned = path.to_string();
    let outcome = blocking(move || read_report(&owned)).await;
    let cause = match outcome {
        Ok(report) => return Ok(report),
        Err(cause) => cause,
    };
    if execution.exit_code == Some(1) {
        let report_failure = match &cause {
            ReportError::Output(reason) => reason.clone(),
            ReportError::Other(message) => message.clone(),
        };
        return Err(FwFailure::Typed(ToolError::Adapter {
            provider_id: engine.id().to_string(),
            operation: operation.to_string(),
            diagnostics: Some(json!({
                "reason": "Tool exited 1 without a usable analysis report; inspect stderr for startup, sandbox or dependency failures",
                "report_failure": report_failure,
                "exit_code": 1,
                "signal": execution.signal,
                "stdout": execution.stdout.text,
                "stderr": execution.stderr.text,
                "stdout_bytes": execution.stdout.bytes,
                "stderr_bytes": execution.stderr.bytes,
            })),
        }));
    }
    let diagnostics = format!(
        "stdout ({} bytes): {}; stderr ({} bytes): {}",
        execution.stdout.bytes, execution.stdout.text, execution.stderr.bytes, execution.stderr.text
    );
    let reason = match cause {
        ReportError::Output(reason) => format!("{reason}; {diagnostics}"),
        ReportError::Other(_) => {
            format!("Tool did not produce the expected complete report: {path}; {diagnostics}")
        }
    };
    Err(FwFailure::Typed(ToolError::Output { operation: operation.to_string(), reason }))
}
