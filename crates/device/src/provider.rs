//! The adb provider: device inspection and acquisition over a caller-selected
//! adb binary (port of REA `AdbProvider.ts`).
//!
//! Every operation composes fixed adb argument vectors; caller values occupy
//! positional arguments, shell-quoted where adb forwards them to the device
//! shell. The provider never starts an emulator, installs platform tools or
//! drives the device UI.

use std::os::unix::fs::MetadataExt;
use std::sync::{Mutex, OnceLock};

use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::config::{inspect_adb_client, resolve_adb_binary, AdbBinarySelection, ConfigurationFailure};
use crate::error::ToolError;
use crate::exec::{exec_file_binary, exec_file_output, BinaryRun, ExecFailure, ExecSuccess, FailureCode};
use crate::fsutil::{basename, hash_stable_file, join, resolve};
use crate::parse::*;

pub const ADB_PROVIDER_ID: &str = "adb";
pub const ADB_PROVIDER_NAME: &str = "Android Debug Bridge";

#[derive(Clone, Copy)]
struct Limits {
    timeout_ms: u64,
    max_output_bytes: usize,
}

const fn limits(timeout_ms: u64, max_output_bytes: usize) -> Limits {
    Limits { timeout_ms, max_output_bytes }
}

const DEVICES: Limits = limits(20_000, 1024 * 1024);
const SHELL: Limits = limits(30_000, 0); // output cap supplied per call
const GETPROP_MAX: usize = 2 * 1024 * 1024;
const PACKAGE_LIST: Limits = limits(60_000, 8 * 1024 * 1024);
const PM_PATH: Limits = limits(30_000, 64 * 1024);
const PULL: Limits = limits(600_000, 1024 * 1024);
const LOGCAT: Limits = limits(60_000, 4 * 1024 * 1024);
const DUMPSYS_PACKAGE: Limits = limits(60_000, 8 * 1024 * 1024);
const DUMPSYS_WINDOW_MAX: usize = 8 * 1024 * 1024;
const LISTING: Limits = limits(30_000, 4 * 1024 * 1024);
const SETTINGS: Limits = limits(20_000, 1024 * 1024);
const SCREEN: Limits = limits(60_000, 32 * 1024 * 1024);
const BUGREPORT: Limits = limits(600_000, 1024 * 1024);
const UNPARSED_LINES_REPORTED: usize = 10;

/// Successful provider execution (`AnalysisExecution`).
#[derive(Debug, Clone)]
pub struct Execution {
    pub result: Value,
    pub limitations: Vec<String>,
    /// `adb version` build string, the Evidence provider version.
    pub provider_version: Option<String>,
}

/// A failed execution: a typed analysis error, or the plain message of a
/// configuration failure that REA lets escape the provider unwrapped.
#[derive(Debug, Clone)]
pub enum ExecuteFailure {
    Analysis(ToolError),
    Plain(String),
}

impl From<ToolError> for ExecuteFailure {
    fn from(error: ToolError) -> Self {
        ExecuteFailure::Analysis(error)
    }
}

/// adb joins shell operands into a remote POSIX command; quote at that boundary.
fn quote_shell_operand(value: &str) -> String {
    static SAFE: OnceLock<Regex> = OnceLock::new();
    let safe = SAFE.get_or_init(|| Regex::new(r"^[A-Za-z0-9_./:=@+,-]+$").expect("pattern"));
    if safe.is_match(value) {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn adb_arguments(serial: Option<&str>, arguments: &[&str]) -> Vec<String> {
    let operands: Vec<String> = if arguments.first() == Some(&"shell") {
        std::iter::once("shell".to_string())
            .chain(arguments[1..].iter().map(|a| quote_shell_operand(a)))
            .collect()
    } else {
        arguments.iter().map(|a| a.to_string()).collect()
    };
    match serial {
        Some(serial) => [vec!["-s".to_string(), serial.to_string()], operands].concat(),
        None => operands,
    }
}

fn str_of<'a>(input: &'a Map<String, Value>, key: &str) -> &'a str {
    input.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn failure_exit_text(code: &FailureCode) -> String {
    match code {
        FailureCode::Exit(code) => code.to_string(),
        FailureCode::Name(name) => name.clone(),
        FailureCode::None => "null".to_string(),
    }
}

fn classify_failure(operation: &str, target: &str, limits: Limits, failure: ExecFailure) -> ToolError {
    static UNAUTHORIZED: OnceLock<Regex> = OnceLock::new();
    static NOT_FOUND: OnceLock<Regex> = OnceLock::new();
    static MISSING: OnceLock<Regex> = OnceLock::new();
    let unauthorized = UNAUTHORIZED.get_or_init(|| Regex::new(r"(?i)unauthorized").expect("pattern"));
    let not_found = NOT_FOUND.get_or_init(|| {
        Regex::new(r"(?i)device[^\n]*not found|device offline|still authorizing|more than one device").expect("pattern")
    });
    let missing = MISSING.get_or_init(|| {
        Regex::new(r"(?i)No such file or directory|Permission denied|read: Permission denied").expect("pattern")
    });
    if failure.output_truncated {
        return ToolError::ResourceConstraint {
            operation: operation.to_string(),
            resource: "memory",
            reason: format!("adb output exceeded the {}-byte capture budget", limits.max_output_bytes),
            reported_limits: json!({ "max_output_bytes": limits.max_output_bytes }),
        };
    }
    let excerpt = slice_utf16(js_trim(&failure.stderr), 512);
    if unauthorized.is_match(&excerpt) || not_found.is_match(&excerpt) || missing.is_match(&excerpt) {
        return ToolError::UnsupportedTarget {
            operation: operation.to_string(),
            path: target.to_string(),
            reason: excerpt,
        };
    }
    if failure.killed {
        return ToolError::Timeout { operation: operation.to_string(), timeout_ms: limits.timeout_ms };
    }
    ToolError::protocol(if excerpt.is_empty() {
        format!("adb exited with code {} for {operation}", failure_exit_text(&failure.code))
    } else {
        excerpt
    })
}

/// Run one bounded adb invocation and keep its exact failure shape (`runAdb`).
async fn run_adb(
    operation: &str,
    target: &str,
    binary: &str,
    arguments: Vec<String>,
    limits: Limits,
) -> Result<ExecSuccess, ToolError> {
    exec_file_output(binary, &arguments, limits.timeout_ms, limits.max_output_bytes)
        .await
        .map_err(|failure| classify_failure(operation, target, limits, failure))
}

fn reported(unparsed: &[String], partial: bool) -> (Vec<String>, &'static str) {
    (
        unparsed.iter().take(UNPARSED_LINES_REPORTED).cloned().collect(),
        if partial || !unparsed.is_empty() { "partial" } else { "complete" },
    )
}

fn unparsed_overflow(unparsed: &[String]) -> Vec<String> {
    if unparsed.len() > UNPARSED_LINES_REPORTED {
        vec![format!(
            "unparsed_lines reports the first {UNPARSED_LINES_REPORTED} of {} unrecognized lines",
            unparsed.len()
        )]
    } else {
        Vec::new()
    }
}

fn node_error_text(error: &std::io::Error, syscall: &str, path: &str) -> String {
    let (code, text) = match error.raw_os_error() {
        Some(1) => ("EPERM", "operation not permitted"),
        Some(2) => ("ENOENT", "no such file or directory"),
        Some(13) => ("EACCES", "permission denied"),
        Some(17) => ("EEXIST", "file already exists"),
        Some(20) => ("ENOTDIR", "not a directory"),
        Some(21) => ("EISDIR", "illegal operation on a directory"),
        Some(30) => ("EROFS", "read-only file system"),
        Some(39) => ("ENOTEMPTY", "directory not empty"),
        _ => return error.to_string(),
    };
    format!("{code}: {text}, {syscall} '{path}'")
}

async fn path_exists(path: &str) -> bool {
    tokio::fs::symlink_metadata(path).await.is_ok()
}

/// Materialize the caller's output directory (`prepareOutputDirectory`).
async fn prepare_output_directory(operation: &str, directory: &str) -> Result<String, ToolError> {
    let root = resolve(directory);
    let failure = || ToolError::Output {
        operation: operation.to_string(),
        reason: format!("The output directory is not writable or could not be created: {root}"),
    };
    tokio::fs::create_dir_all(&root).await.map_err(|_| failure())?;
    let writable = {
        let path = std::ffi::CString::new(root.clone()).map_err(|_| failure())?;
        // SAFETY: `path` is a valid NUL-terminated string for the call duration.
        unsafe { libc::access(path.as_ptr(), libc::W_OK) == 0 }
    };
    if !writable {
        return Err(failure());
    }
    Ok(root)
}

async fn refuse_existing_target(operation: &str, path: &str) -> Result<(), ToolError> {
    if path_exists(path).await {
        return Err(ToolError::Output {
            operation: operation.to_string(),
            reason: format!("The output file already exists: {path}"),
        });
    }
    Ok(())
}

async fn hash_file(path: &str) -> Result<(String, u64), String> {
    let owned = path.to_string();
    tokio::task::spawn_blocking(move || hash_stable_file(&owned))
        .await
        .map_err(|error| error.to_string())?
}

// ---------------------------------------------------------------- cleanup --

#[derive(Clone)]
struct PendingCleanup {
    path: String,
    identity: Option<(u64, u64, u32)>,
    primary: ToolError,
}

/// Registers a package directory left behind by a cancelled `pull_adb_package`
/// (the future was dropped) so the next call removes it; a normal return
/// disarms it.
struct PackageDirGuard {
    path: String,
    identity: Option<(u64, u64, u32)>,
    operation: String,
    armed: bool,
}

impl Drop for PackageDirGuard {
    fn drop(&mut self) {
        if self.armed {
            if let Ok(mut pending) = pending_cleanups().lock() {
                pending.push(PendingCleanup {
                    path: self.path.clone(),
                    identity: self.identity,
                    primary: ToolError::Cancelled { operation: self.operation.clone() },
                });
            }
        }
    }
}

fn pending_cleanups() -> &'static Mutex<Vec<PendingCleanup>> {
    static PENDING: OnceLock<Mutex<Vec<PendingCleanup>>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(Vec::new()))
}

fn remove_owned_package_directory(path: &str, identity: Option<(u64, u64, u32)>) -> Result<(), String> {
    let Some((dev, ino, mode)) = identity else {
        return Err(format!(
            "Cannot verify the created package directory identity; refusing to remove {path}"
        ));
    };
    let current = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(node_error_text(&error, "lstat", path)),
    };
    if !current.is_dir() || current.file_type().is_symlink() || current.dev() != dev || current.ino() != ino
        || current.mode() != mode
    {
        return Err(format!(
            "The created package directory was replaced or changed; refusing to remove {path}"
        ));
    }
    std::fs::remove_dir_all(path).map_err(|error| node_error_text(&error, "rmdir", path))
}

fn cleanup_error(path: &str, reason: String, operation: &str) -> ToolError {
    ToolError::Cleanup {
        provider_id: ADB_PROVIDER_ID.to_string(),
        operation: operation.to_string(),
        resources: vec![path.to_string()],
        diagnostics: json!({ "reason": reason }),
        partial: None,
    }
}

/// Retry removal of package directories retained after a failed rollback.
fn retry_package_directory_cleanup() -> Result<(), ToolError> {
    let owners: Vec<PendingCleanup> = pending_cleanups().lock().expect("cleanup registry").clone();
    let mut failures: Vec<ToolError> = Vec::new();
    for owner in owners {
        match remove_owned_package_directory(&owner.path, owner.identity) {
            Ok(()) => pending_cleanups()
                .lock()
                .expect("cleanup registry")
                .retain(|candidate| candidate.path != owner.path),
            Err(reason) => failures.push(ToolError::with_cleanup_failure(
                owner.primary.clone(),
                cleanup_error(&owner.path, reason, "pull_adb_package"),
                "pull_adb_package",
            )),
        }
    }
    match failures.len() {
        0 => Ok(()),
        1 => Err(failures.remove(0)),
        _ => {
            let remaining: Vec<String> = pending_cleanups()
                .lock()
                .expect("cleanup registry")
                .iter()
                .map(|owner| owner.path.clone())
                .collect();
            Err(ToolError::Cleanup {
                provider_id: ADB_PROVIDER_ID.to_string(),
                operation: "pull_adb_package".to_string(),
                resources: remaining,
                diagnostics: json!({
                    "reason": "Failed package output directories remain after cleanup retry",
                    "failures": failures
                        .iter()
                        .map(|failure| json!({
                            "message": failure.message(),
                            "resources": failure_resources(failure),
                        }))
                        .collect::<Vec<_>>(),
                }),
                partial: None,
            })
        }
    }
}

/// Server shutdown (transport closed, SIGTERM, SIGINT): finish the removals that cancelled
/// `pull_adb_package` calls left registered, instead of leaving them to a next adb call that
/// will never come. Returns the paths that could not be removed (they stay registered).
/// Blocking: call it from a blocking thread.
pub fn shutdown() -> Vec<String> {
    match retry_package_directory_cleanup() {
        Ok(()) => Vec::new(),
        Err(_) => pending_cleanups()
            .lock()
            .map(|pending| pending.iter().map(|owner| owner.path.clone()).collect())
            .unwrap_or_default(),
    }
}

fn failure_resources(error: &ToolError) -> Vec<String> {
    match error {
        ToolError::Cleanup { resources, .. } | ToolError::CleanupWrapped { resources, .. } => resources.clone(),
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------- execute --

/// Run one validated request. `configured` is the `REA_ADB_PATH` value.
pub async fn execute(
    operation: &str,
    input: &Map<String, Value>,
    configured: Option<String>,
) -> Result<Execution, ExecuteFailure> {
    let has_pending = !pending_cleanups().lock().expect("cleanup registry").is_empty();
    if has_pending {
        tokio::task::spawn_blocking(retry_package_directory_cleanup)
            .await
            .map_err(|error| ToolError::protocol(error.to_string()))??;
    }
    let selection = match resolve_adb_binary(configured) {
        Ok(selection) => selection,
        Err(failure) => return Err(ExecuteFailure::Plain(failure.message().to_string())),
    };
    let identity = match inspect_adb_client(&selection).await {
        Ok(identity) => identity,
        Err(failure) => {
            return Err(ToolError::CapabilityUnavailable {
                provider_id: ADB_PROVIDER_ID.to_string(),
                operation: operation.to_string(),
                reason: capability_reason(&failure),
                user_message: None,
            }
            .into())
        }
    };
    let client = json!({
        "binary_path": selection.binary,
        "path_source": selection.path_source,
        "version": identity.version,
        "installed_path": identity.installed_path,
    });
    let ctx = Ctx { operation, selection, client, provider_version: identity.version };
    ctx.dispatch(input).await.map_err(ExecuteFailure::from)
}

fn capability_reason(failure: &ConfigurationFailure) -> String {
    failure.capability_reason()
}

struct Ctx<'a> {
    operation: &'a str,
    selection: AdbBinarySelection,
    client: Value,
    provider_version: Option<String>,
}

type Outcome = Result<Execution, ToolError>;

impl Ctx<'_> {
    fn binary(&self) -> &str {
        &self.selection.binary
    }

    fn done(&self, mut result: Map<String, Value>, limitations: Vec<String>) -> Outcome {
        let mut with_client = Map::new();
        with_client.insert("client".into(), self.client.clone());
        with_client.append(&mut result);
        Ok(Execution {
            result: Value::Object(with_client),
            limitations,
            provider_version: self.provider_version.clone(),
        })
    }

    fn base(&self, serial: &str) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("serial".into(), json!(serial));
        map
    }

    async fn adb(&self, target: &str, arguments: Vec<String>, limits: Limits) -> Result<ExecSuccess, ToolError> {
        run_adb(self.operation, target, self.binary(), arguments, limits).await
    }

    async fn shell(&self, serial: &str, arguments: &[&str], limits: Limits) -> Result<ExecSuccess, ToolError> {
        let mut full = vec!["shell"];
        full.extend_from_slice(arguments);
        self.adb(serial, adb_arguments(Some(serial), &full), limits).await
    }

    fn unsupported(&self, path: &str, reason: impl Into<String>) -> ToolError {
        ToolError::UnsupportedTarget {
            operation: self.operation.to_string(),
            path: path.to_string(),
            reason: reason.into(),
        }
    }

    fn input_error(&self) -> ToolError {
        ToolError::Input { operation: self.operation.to_string(), issues: Vec::new() }
    }

    async fn dispatch(&self, input: &Map<String, Value>) -> Outcome {
        let serial = str_of(input, "serial");
        match self.operation {
            "inspect_adb_client" => {
                let mut result = Map::new();
                result.insert("contacted_adb_server".into(), json!(false));
                self.done(result, vec![])
            }
            "list_adb_devices" => self.list_devices().await,
            "inspect_adb_device" => self.inspect_device(serial).await,
            "list_adb_packages" => self.list_packages(serial, str_of(input, "scope")).await,
            "pull_adb_package" => self.pull_package(input).await,
            "read_adb_logcat" => self.read_logcat(serial, input).await,
            "inspect_adb_package" => self.inspect_package(serial, str_of(input, "package")).await,
            "pull_adb_file" => self.pull_file(input).await,
            "push_adb_file" => self.push_file(input).await,
            "capture_adb_screen" => self.capture_screen(input).await,
            "collect_adb_bugreport" => self.collect_bugreport(input).await,
            "list_adb_processes" => self.list_processes(serial).await,
            "list_adb_directory" => self.list_directory(serial, str_of(input, "device_path")).await,
            "list_adb_features" => self.list_features(serial).await,
            "list_adb_services" => self.list_services(serial).await,
            "inspect_adb_display" => self.inspect_display(serial).await,
            "inspect_adb_window" => self.inspect_window(serial).await,
            "read_adb_setting" => self.read_setting(serial, input).await,
            "resolve_adb_packages" => self.resolve_packages(serial, str_of(input, "query")).await,
            "install_adb_package" => self.install_package(input).await,
            "uninstall_adb_package" => self.uninstall_package(serial, str_of(input, "package")).await,
            "start_adb_app" => self.start_app(serial, str_of(input, "package")).await,
            "start_adb_activity" => self.start_activity(input).await,
            "stop_adb_app" => self.stop_app(serial, str_of(input, "package")).await,
            other => Err(ToolError::protocol(format!("unsupported adb operation: {other}"))),
        }
    }

    async fn list_devices(&self) -> Outcome {
        let ran = self
            .adb(
                "adb-devices",
                adb_arguments(None, &["devices", "-l"]),
                DEVICES,
            )
            .await?;
        let parsed = parse_adb_devices_output(&ran.stdout);
        if let Some(first) = parsed.unparsed_lines.first() {
            return Err(ToolError::protocol(format!(
                "adb devices reported an unrecognized line: {first}"
            )));
        }
        let mut result = Map::new();
        result.insert("devices".into(), Value::Array(parsed.devices));
        result.insert("may_have_started_adb_server".into(), json!(parsed.daemon_started));
        self.done(
            result,
            vec![
                "Device kind is inferred from the emulator serial prefix and USB transport metadata, not from device attestation"
                    .to_string(),
                "Kind stays unknown for TCP transports unless the serial is an emulator port".to_string(),
            ],
        )
    }

    async fn inspect_device(&self, serial: &str) -> Outcome {
        let ran = self
            .adb(
                serial,
                adb_arguments(Some(serial), &["shell", "getprop"]),
                limits(SHELL.timeout_ms, GETPROP_MAX),
            )
            .await?;
        let (properties, emulator) = parse_getprop_output(&ran.stdout);
        let mut result = self.base(serial);
        result.insert("property_count".into(), json!(properties.len()));
        result.insert("properties".into(), Value::Array(properties));
        result.insert("emulator_observed".into(), json!(emulator));
        self.done(
            result,
            vec![
                "Properties are a fixed whitelist of build identity facts, not the full getprop dump".to_string(),
                "emulator_observed is null when the build does not report ro.kernel.qemu".to_string(),
            ],
        )
    }

    async fn list_packages(&self, serial: &str, scope: &str) -> Outcome {
        let flag = match scope {
            "third_party" => Some("-3"),
            "system" => Some("-s"),
            _ => None,
        };
        let mut arguments = vec!["pm", "list", "packages", "-f"];
        arguments.extend(flag);
        let ran = self.shell(serial, &arguments, PACKAGE_LIST).await?;
        let (packages, unparsed) = parse_package_list_output(&ran.stdout);
        let (lines, coverage) = reported(&unparsed, false);
        let mut result = self.base(serial);
        result.insert("scope".into(), json!(scope));
        result.insert("packages".into(), Value::Array(packages));
        result.insert("unparsed_lines".into(), json!(lines));
        result.insert("coverage".into(), json!(coverage));
        let mut limitations =
            vec!["base_apk_device_path is a device filesystem path, not a host-local path".to_string()];
        limitations.extend(unparsed_overflow(&unparsed));
        self.done(result, limitations)
    }

    async fn read_logcat(&self, serial: &str, input: &Map<String, Value>) -> Outcome {
        let count = input.get("count").and_then(Value::as_i64).unwrap_or(500);
        let buffer = str_of(input, "buffer");
        let pid = input.get("pid").and_then(Value::as_i64);
        let count_text = count.to_string();
        let pid_text = pid.map(|p| p.to_string());
        let mut arguments = vec!["logcat", "-d", "-b", buffer, "-t", count_text.as_str()];
        if let Some(pid_text) = &pid_text {
            arguments.push("--pid");
            arguments.push(pid_text);
        }
        let ran = self.shell(serial, &arguments, LOGCAT).await?;
        let mut lines: Vec<String> = split_lines(&ran.stdout).into_iter().map(str::to_string).collect();
        if lines.last().map(String::as_str) == Some("") {
            lines.pop();
        }
        let keep = count.max(0) as usize;
        let bounded: Vec<String> = lines[lines.len().saturating_sub(keep)..].to_vec();
        let coverage = if bounded.len() != lines.len() || bounded.len() as i64 == count {
            "partial"
        } else {
            "complete"
        };
        let mut result = self.base(serial);
        result.insert("count".into(), json!(count));
        result.insert("buffer".into(), json!(buffer));
        result.insert("pid".into(), json!(pid));
        result.insert("lines".into(), json!(bounded));
        result.insert("total_bytes".into(), json!(ran.stdout.encode_utf16().count()));
        result.insert("coverage".into(), json!(coverage));
        self.done(
            result,
            vec![
                "Reads a bounded dump (logcat -d); the newest lines are kept when the count cap trims".to_string(),
                "coverage is partial when the requested count or capture budget truncated the dump".to_string(),
            ],
        )
    }

    async fn inspect_package(&self, serial: &str, package: &str) -> Outcome {
        let ran = self.shell(serial, &["dumpsys", "package", package], DUMPSYS_PACKAGE).await?;
        static MISSING: OnceLock<Regex> = OnceLock::new();
        let missing = MISSING.get_or_init(|| Regex::new(r"Unable to find package:").expect("pattern"));
        if missing.is_match(&ran.stdout) || js_trim(&ran.stdout).is_empty() {
            return Err(self.unsupported(
                serial,
                format!("Package Manager did not report details for {package}; it may not be installed for user 0"),
            ));
        }
        let details = parse_dumpsys_package_output(&ran.stdout);
        let coverage = if details.version_code.is_none() && details.version_name.is_none() {
            "partial"
        } else {
            "complete"
        };
        let mut result = self.base(serial);
        result.insert("package_name".into(), json!(package));
        result.insert("version_name".into(), json!(details.version_name));
        result.insert("version_code".into(), json!(details.version_code));
        result.insert("first_install_time".into(), json!(details.first_install_time));
        result.insert("last_update_time".into(), json!(details.last_update_time));
        result.insert("installer_package_name".into(), json!(details.installer_package_name));
        result.insert("user_id".into(), json!(details.user_id));
        result.insert("pkg_flags".into(), json!(details.pkg_flags));
        result.insert("requested_permissions_count".into(), json!(details.requested_permissions));
        result.insert("coverage".into(), json!(coverage));
        self.done(
            result,
            vec![
                "Fields are a fixed projection of dumpsys package output; version-dependent sections are ignored rather than guessed"
                    .to_string(),
                "requested_permissions_count counts the listed requested permissions section only".to_string(),
            ],
        )
    }

    async fn list_processes(&self, serial: &str) -> Outcome {
        let ran = self.shell(serial, &["ps", "-A"], LISTING).await?;
        let (columns, processes, unparsed) = parse_process_list_output(&ran.stdout);
        let (lines, coverage) = reported(&unparsed, false);
        let mut result = self.base(serial);
        result.insert("columns".into(), json!(columns));
        result.insert("processes".into(), Value::Array(processes));
        result.insert("unparsed_lines".into(), json!(lines));
        result.insert("coverage".into(), json!(coverage));
        self.done(result, unparsed_overflow(&unparsed))
    }

    async fn list_directory(&self, serial: &str, device_path: &str) -> Outcome {
        let ran = self.shell(serial, &["ls", "-la", device_path], LISTING).await?;
        let (entries, unparsed) = parse_ls_output(&ran.stdout);
        let (lines, coverage) = reported(&unparsed, false);
        let mut result = self.base(serial);
        result.insert("device_path".into(), json!(device_path));
        result.insert("entries".into(), Value::Array(entries));
        result.insert("unparsed_lines".into(), json!(lines));
        result.insert("coverage".into(), json!(coverage));
        let mut limitations = vec!["Entry kinds derive from the permission string's type character".to_string()];
        limitations.extend(unparsed_overflow(&unparsed));
        self.done(result, limitations)
    }

    async fn list_features(&self, serial: &str) -> Outcome {
        let ran = self.shell(serial, &["pm", "list", "features"], LISTING).await?;
        let (features, unparsed) = parse_feature_list_output(&ran.stdout);
        let (lines, coverage) = reported(&unparsed, false);
        let mut result = self.base(serial);
        result.insert("features".into(), Value::Array(features));
        result.insert("unparsed_lines".into(), json!(lines));
        result.insert("coverage".into(), json!(coverage));
        self.done(result, unparsed_overflow(&unparsed))
    }

    async fn list_services(&self, serial: &str) -> Outcome {
        let ran = self.shell(serial, &["service", "list"], LISTING).await?;
        let (services, unparsed) = parse_service_list_output(&ran.stdout);
        let (lines, coverage) = reported(&unparsed, false);
        let mut result = self.base(serial);
        result.insert("services".into(), Value::Array(services));
        result.insert("unparsed_lines".into(), json!(lines));
        result.insert("coverage".into(), json!(coverage));
        self.done(result, unparsed_overflow(&unparsed))
    }

    async fn inspect_display(&self, serial: &str) -> Outcome {
        let size = self.shell(serial, &["wm", "size"], SETTINGS).await?;
        let density = self.shell(serial, &["wm", "density"], SETTINGS).await?;
        let (physical, override_size) = parse_wm_size_output(&size.stdout);
        let Some(physical) = physical else {
            return Err(ToolError::protocol(
                "wm size did not report a physical size; the build may use an unsupported format",
            ));
        };
        let (physical_density, override_density) = parse_wm_density_output(&density.stdout);
        let mut result = self.base(serial);
        result.insert("physical_size".into(), physical);
        result.insert("override_size".into(), json!(override_size));
        result.insert("physical_density".into(), json!(physical_density));
        result.insert("override_density".into(), json!(override_density));
        self.done(
            result,
            vec!["Override values are present only when a build has overridden the physical values".to_string()],
        )
    }

    async fn inspect_window(&self, serial: &str) -> Outcome {
        let limits = limits(SHELL.timeout_ms, DUMPSYS_WINDOW_MAX);
        let ran = self.shell(serial, &["dumpsys", "window", "windows"], limits).await?;
        let (window, app) = parse_window_focus_output(&ran.stdout);
        let observed: Vec<&String> = window.iter().chain(app.iter()).collect();
        let mut result = self.base(serial);
        result.insert("focused_window".into(), json!(window));
        result.insert("focused_app".into(), json!(app));
        result.insert("observed_lines".into(), json!(observed));
        self.done(
            result,
            vec![
                "Focus values are the window manager's declarations at read time; no interaction occurred".to_string(),
            ],
        )
    }

    async fn read_setting(&self, serial: &str, input: &Map<String, Value>) -> Outcome {
        let namespace = str_of(input, "namespace");
        let key = str_of(input, "key");
        let ran = self.shell(serial, &["settings", "get", namespace, key], SETTINGS).await?;
        let (value, device_null) = parse_settings_get_output(&ran.stdout);
        let mut result = self.base(serial);
        result.insert("namespace".into(), json!(namespace));
        result.insert("key".into(), json!(key));
        result.insert("value".into(), json!(value));
        result.insert("device_reported_null".into(), json!(device_null));
        self.done(
            result,
            vec![
                "Android prints the literal string null for absent keys; that is reported as a device-side null observation"
                    .to_string(),
            ],
        )
    }

    async fn resolve_packages(&self, serial: &str, query: &str) -> Outcome {
        let ran = self.shell(serial, &["pm", "list", "packages", "-f"], PACKAGE_LIST).await?;
        let (packages, unparsed) = parse_package_list_output(&ran.stdout);
        let needle = query.to_lowercase();
        let matches: Vec<Value> = packages
            .into_iter()
            .filter(|entry| entry["package_name"].as_str().unwrap_or_default().to_lowercase().contains(&needle))
            .collect();
        let exact = matches.len() == 1
            && matches[0]["package_name"].as_str().unwrap_or_default().to_lowercase() == needle;
        let mut result = self.base(serial);
        result.insert("query".into(), json!(query));
        result.insert("matches".into(), Value::Array(matches));
        result.insert("exact_match".into(), json!(exact));
        result.insert("coverage".into(), json!(if unparsed.is_empty() { "complete" } else { "partial" }));
        let mut limitations = vec![
            "Matching is a case-insensitive substring over package names; application display labels are not part of pm output"
                .to_string(),
        ];
        limitations.extend(unparsed_overflow(&unparsed));
        self.done(result, limitations)
    }

    // -------------------------------------------------------- acquisition --

    async fn pull_package(&self, input: &Map<String, Value>) -> Outcome {
        let operation = self.operation;
        let serial = str_of(input, "serial");
        let package = str_of(input, "package");
        let paths = self
            .adb(
                serial,
                adb_arguments(Some(serial), &["shell", "pm", "path", package]),
                PM_PATH,
            )
            .await?;
        let (entries, unparsed) = parse_pm_path_output(&paths.stdout);
        if entries.is_empty() && unparsed.is_empty() {
            return Err(self.unsupported(
                serial,
                format!("Package Manager reported no APK paths for {package}; it may not be installed for user 0"),
            ));
        }
        if let Some(first) = unparsed.first() {
            return Err(ToolError::protocol(format!("pm path reported an unrecognized line: {first}")));
        }
        let directory = prepare_output_directory(operation, str_of(input, "output_directory")).await?;
        let package_directory = join(&directory, package);
        let mut identity: Option<(u64, u64, u32)> = None;
        let mut created = false;
        let creation: Result<(), String> = async {
            if path_exists(&package_directory).await {
                return Err(format!("The package output directory already exists: {package_directory}"));
            }
            tokio::fs::create_dir(&package_directory)
                .await
                .map_err(|error| node_error_text(&error, "mkdir", &package_directory))?;
            created = true;
            let metadata = tokio::fs::symlink_metadata(&package_directory)
                .await
                .map_err(|error| node_error_text(&error, "lstat", &package_directory))?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(format!(
                    "The created package output is not a regular directory: {package_directory}"
                ));
            }
            identity = Some((metadata.dev(), metadata.ino(), metadata.mode()));
            Ok(())
        }
        .await;
        if let Err(message) = creation {
            let primary = ToolError::Output { operation: operation.to_string(), reason: message };
            if !created {
                return Err(primary);
            }
            pending_cleanups().lock().expect("cleanup registry").push(PendingCleanup {
                path: package_directory.clone(),
                identity,
                primary: primary.clone(),
            });
            let cleanup = cleanup_error(
                &package_directory,
                "Could not establish an owned package directory identity".to_string(),
                operation,
            );
            return Err(ToolError::with_cleanup_failure(primary, cleanup, operation));
        }
        let mut cancel_guard = PackageDirGuard {
            path: package_directory.clone(),
            identity,
            operation: operation.to_string(),
            armed: true,
        };
        let mut artifacts: Vec<Value> = Vec::new();
        let mut failures: Vec<Value> = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        for entry in &entries {
            if seen.contains(&entry.file_name) {
                failures.push(json!({
                    "device_path": entry.device_path,
                    "stage": "pull",
                    "message": format!(
                        "Duplicate file name {} in the APK set; refusing to overwrite",
                        entry.file_name
                    ),
                }));
                continue;
            }
            seen.push(entry.file_name.clone());
            let local_path = join(&package_directory, &entry.file_name);
            let pulled = self
                .adb(
                    serial,
                    adb_arguments(Some(serial), &["pull", &entry.device_path, &local_path]),
                    PULL,
                )
                .await;
            if let Err(error) = pulled {
                failures.push(json!({
                    "device_path": entry.device_path,
                    "stage": "pull",
                    "message": error.message(),
                }));
                continue;
            }
            match hash_file(&local_path).await {
                Ok((sha256, bytes)) => artifacts.push(json!({
                    "device_path": entry.device_path,
                    "file_name": entry.file_name,
                    "local_path": local_path,
                    "bytes": bytes,
                    "sha256": sha256,
                    "role": entry.role,
                    "role_basis": "file_name",
                })),
                Err(_) => failures.push(json!({
                    "device_path": entry.device_path,
                    "stage": "digest",
                    "message": format!("The pulled file could not be read back after pulling: {local_path}"),
                })),
            }
        }
        // Past the pulls: the outcome (kept output or its own rollback) is decided below.
        cancel_guard.armed = false;
        if artifacts.is_empty() && !failures.is_empty() {
            let first = failures[0]["message"].as_str().unwrap_or_default().to_string();
            let primary = ToolError::protocol(format!("Every APK pull failed for {package} on {serial}: {first}"));
            let removal = {
                let path = package_directory.clone();
                tokio::task::spawn_blocking(move || remove_owned_package_directory(&path, identity))
                    .await
                    .unwrap_or_else(|error| Err(error.to_string()))
            };
            return match removal {
                Ok(()) => Err(primary),
                Err(reason) => {
                    pending_cleanups().lock().expect("cleanup registry").push(PendingCleanup {
                        path: package_directory.clone(),
                        identity,
                        primary: primary.clone(),
                    });
                    let cleanup = cleanup_error(&package_directory, reason, operation);
                    Err(ToolError::with_cleanup_failure(primary, cleanup, operation))
                }
            };
        }
        let mut result = self.base(serial);
        result.insert("package_name".into(), json!(package));
        result.insert("output_directory".into(), json!(directory));
        result.insert("coverage".into(), json!(if failures.is_empty() { "complete" } else { "partial" }));
        result.insert("artifacts".into(), Value::Array(artifacts));
        result.insert("failures".into(), Value::Array(failures));
        self.done(
            result,
            vec![
                "APK role names derive from the pulled file names (base.apk, split_*.apk)".to_string(),
                "Pulled artifacts are host-local copies; the device retains the originals".to_string(),
            ],
        )
    }

    async fn pull_file(&self, input: &Map<String, Value>) -> Outcome {
        let operation = self.operation;
        let serial = str_of(input, "serial");
        let device_path = str_of(input, "device_path");
        let directory = prepare_output_directory(operation, str_of(input, "output_directory")).await?;
        let mut file_name = basename(device_path);
        if file_name.is_empty() {
            file_name = "pulled".to_string();
        }
        let local_path = join(&directory, &file_name);
        refuse_existing_target(operation, &local_path).await?;
        self.adb(
            serial,
            adb_arguments(Some(serial), &["pull", device_path, &local_path]),
            PULL,
        )
        .await?;
        match hash_file(&local_path).await {
            Ok((sha256, bytes)) => {
                let mut result = self.base(serial);
                result.insert("device_path".into(), json!(device_path));
                result.insert("local_path".into(), json!(local_path));
                result.insert("bytes".into(), json!(bytes));
                result.insert("sha256".into(), json!(sha256));
                self.done(
                    result,
                    vec!["The pulled file is a host-local copy; the device retains the original".to_string()],
                )
            }
            Err(_) => Err(ToolError::Output {
                operation: operation.to_string(),
                reason: format!("The pulled file could not be read back after pulling: {local_path}"),
            }),
        }
    }

    async fn push_file(&self, input: &Map<String, Value>) -> Outcome {
        let operation = self.operation;
        let serial = str_of(input, "serial");
        let device_path = str_of(input, "device_path");
        let overwrite = input.get("overwrite").and_then(Value::as_bool).unwrap_or(false);
        let local_path = resolve(str_of(input, "local_path"));
        let is_file = tokio::fs::metadata(&local_path).await.map(|m| m.is_file()).unwrap_or(false);
        if !is_file {
            return Err(self.input_error());
        }
        let (sha256, bytes) = hash_file(&local_path).await.map_err(ToolError::protocol)?;
        let exists_probe = self
            .adb(
                device_path,
                adb_arguments(Some(serial), &["shell", "test", "-e", device_path]),
                limits(SETTINGS.timeout_ms, 1024),
            )
            .await;
        let device_exists = match exists_probe {
            Ok(_) => true,
            Err(ToolError::Protocol { .. }) => false,
            Err(
                error @ (ToolError::Timeout { .. }
                | ToolError::Cancelled { .. }
                | ToolError::ResourceConstraint { .. }),
            ) => return Err(error),
            // authorization/refusal states surface on push instead
            Err(_) => true,
        };
        if device_exists && !overwrite {
            return Err(ToolError::Output {
                operation: operation.to_string(),
                reason: format!("The device path already exists and overwrite was not requested: {device_path}"),
            });
        }
        self.adb(
            device_path,
            adb_arguments(Some(serial), &["push", &local_path, device_path]),
            PULL,
        )
        .await?;
        let device_digest = self
            .adb(
                device_path,
                adb_arguments(Some(serial), &["shell", "sha256sum", device_path]),
                limits(SHELL.timeout_ms, 1024),
            )
            .await;
        let mut result = self.base(serial);
        result.insert("local_path".into(), json!(local_path));
        result.insert("device_path".into(), json!(device_path));
        result.insert("bytes".into(), json!(bytes));
        result.insert("sha256".into(), json!(sha256));
        match device_digest {
            Ok(output) => {
                static DIGEST: OnceLock<Regex> = OnceLock::new();
                let pattern = DIGEST.get_or_init(|| Regex::new(r"^([a-f0-9]{64})\s").expect("pattern"));
                let matched = pattern.captures(&output.stdout).map(|c| c[1].to_string());
                if let Some(device_sha) = &matched {
                    if *device_sha != sha256 {
                        return Err(ToolError::ArtifactChanged {
                            operation: operation.to_string(),
                            path: device_path.to_string(),
                            reason: format!(
                                "The device-reported digest does not match the pushed local file: {local_path}"
                            ),
                        });
                    }
                }
                result.insert("device_sha256".into(), json!(matched));
                result.insert("overwritten".into(), json!(device_exists));
                result.insert("device_digest_source".into(), json!("device_sha256sum"));
                self.done(
                    result,
                    vec![
                        "Push writes the caller's file to the device; this is the only device-mutating ADB tool"
                            .to_string(),
                    ],
                )
            }
            Err(_) => {
                result.insert("device_sha256".into(), Value::Null);
                result.insert("overwritten".into(), json!(device_exists));
                result.insert("device_digest_source".into(), json!("unavailable"));
                self.done(
                    result,
                    vec![
                        "The device did not answer sha256sum, so the transfer is not device-side verified".to_string(),
                        "Push writes the caller's file to the device; this is the only device-mutating ADB tool"
                            .to_string(),
                    ],
                )
            }
        }
    }

    async fn install_package(&self, input: &Map<String, Value>) -> Outcome {
        let operation = self.operation;
        let serial = str_of(input, "serial");
        let replace = input.get("replace").and_then(Value::as_bool).unwrap_or(false);
        let apk_path = resolve(str_of(input, "apk_path"));
        let is_file = tokio::fs::metadata(&apk_path).await.map(|m| m.is_file()).unwrap_or(false);
        if !is_file {
            return Err(self.input_error());
        }
        let (sha256, bytes) = hash_file(&apk_path).await.map_err(ToolError::protocol)?;
        let mut arguments = vec!["install"];
        if replace {
            arguments.push("-r");
        }
        arguments.push(&apk_path);
        let installed = self.adb(serial, adb_arguments(Some(serial), &arguments), PULL).await?;
        let (success, reason) = parse_package_change_output(&installed.stdout);
        if !success {
            return Err(self.unsupported(
                serial,
                reason.unwrap_or_else(|| "the device refused the installation".to_string()),
            ));
        }
        let mut result = self.base(serial);
        result.insert("apk_path".into(), json!(apk_path));
        result.insert("bytes".into(), json!(bytes));
        result.insert("sha256".into(), json!(sha256));
        result.insert("replaced".into(), json!(replace));
        let _ = operation;
        self.done(
            result,
            vec!["Install changes device state; the installed APK's digest is the host file's digest".to_string()],
        )
    }

    async fn uninstall_package(&self, serial: &str, package: &str) -> Outcome {
        let uninstalled = self
            .adb(
                serial,
                adb_arguments(Some(serial), &["uninstall", package]),
                limits(PACKAGE_LIST.timeout_ms, PULL.max_output_bytes),
            )
            .await?;
        let (success, reason) = parse_package_change_output(&uninstalled.stdout);
        if !success {
            return Err(self.unsupported(
                serial,
                reason.unwrap_or_else(|| "the device refused the removal".to_string()),
            ));
        }
        let mut result = self.base(serial);
        result.insert("package_name".into(), json!(package));
        self.done(
            result,
            vec![
                "Uninstall removes the package and its data for user 0; keeping data (-k) is not exposed".to_string(),
            ],
        )
    }

    async fn start_app(&self, serial: &str, package: &str) -> Outcome {
        let resolved = self
            .adb(
                serial,
                adb_arguments(
                    Some(serial),
                    &[
                        "shell",
                        "cmd",
                        "package",
                        "resolve-activity",
                        "--brief",
                        "-c",
                        "android.intent.category.LAUNCHER",
                        package,
                    ],
                ),
                limits(SHELL.timeout_ms, PM_PATH.max_output_bytes),
            )
            .await?;
        let Some(component) = parse_resolve_activity_output(&resolved.stdout) else {
            return Err(self.unsupported(serial, format!("No launcher activity is declared for {package}")));
        };
        let mut fields = self.base(serial);
        fields.insert("package_name".into(), json!(package));
        fields.insert("component".into(), json!(component));
        self.run_am_start(serial, vec!["-n".to_string(), component], fields).await
    }

    async fn start_activity(&self, input: &Map<String, Value>) -> Outcome {
        let serial = str_of(input, "serial");
        let extras = input.get("extras").and_then(Value::as_array).cloned().unwrap_or_default();
        static BOOLEAN: OnceLock<Regex> = OnceLock::new();
        static INTEGER: OnceLock<Regex> = OnceLock::new();
        static FLOAT: OnceLock<Regex> = OnceLock::new();
        let boolean = BOOLEAN.get_or_init(|| Regex::new(r"^(true|false)$").expect("pattern"));
        let integer = INTEGER.get_or_init(|| Regex::new(r"^-?[0-9]+$").expect("pattern"));
        let float = FLOAT.get_or_init(|| Regex::new(r"^-?[0-9]+(\.[0-9]+)?$").expect("pattern"));
        for extra in &extras {
            let key = extra["key"].as_str().unwrap_or_default();
            let kind = extra["type"].as_str().unwrap_or_default();
            let value = extra["value"].as_str().unwrap_or_default();
            let bad = match kind {
                "boolean" => !boolean.is_match(value),
                "int" | "long" => !integer.is_match(value),
                "float" => !float.is_match(value),
                _ => false,
            };
            if bad {
                // The REA error carries only a cause; the projection has no issue details.
                let _ = key;
                return Err(self.input_error());
            }
        }
        let mut arguments = vec!["-a".to_string(), str_of(input, "action").to_string()];
        if let Some(data_uri) = input.get("data_uri").and_then(Value::as_str) {
            arguments.push("-d".into());
            arguments.push(data_uri.to_string());
        }
        if let Some(component) = input.get("component").and_then(Value::as_str) {
            arguments.push("-n".into());
            arguments.push(component.to_string());
        }
        for extra in &extras {
            let flag = match extra["type"].as_str().unwrap_or_default() {
                "string" => "--es",
                "boolean" => "--ez",
                "int" => "--ei",
                "long" => "--el",
                _ => "--ef",
            };
            arguments.push(flag.into());
            arguments.push(extra["key"].as_str().unwrap_or_default().to_string());
            arguments.push(extra["value"].as_str().unwrap_or_default().to_string());
        }
        let mut fields = self.base(serial);
        fields.insert("action".into(), json!(str_of(input, "action")));
        fields.insert("data_uri".into(), json!(input.get("data_uri").and_then(Value::as_str)));
        fields.insert("component".into(), json!(input.get("component").and_then(Value::as_str)));
        fields.insert("extras".into(), Value::Array(extras));
        self.run_am_start(serial, arguments, fields).await
    }

    async fn run_am_start(&self, serial: &str, arguments: Vec<String>, mut fields: Map<String, Value>) -> Outcome {
        let mut full = vec!["shell", "am", "start", "-W"];
        full.extend(arguments.iter().map(String::as_str));
        let started = self
            .adb(
                serial,
                adb_arguments(Some(serial), &full),
                limits(SHELL.timeout_ms, PM_PATH.max_output_bytes),
            )
            .await?;
        let verdict = parse_am_start_output(&started.stdout);
        if !verdict.started {
            return Err(self.unsupported(
                serial,
                verdict.reason.unwrap_or_else(|| "am start refused the intent".to_string()),
            ));
        }
        fields.insert("started_activity".into(), json!(verdict.started_activity));
        self.done(
            fields,
            vec![
                "Starting an activity changes device state; am start -W waits for launch completion but no lifecycle observation is captured"
                    .to_string(),
            ],
        )
    }

    async fn stop_app(&self, serial: &str, package: &str) -> Outcome {
        self.adb(
            serial,
            adb_arguments(Some(serial), &["shell", "am", "force-stop", package]),
            limits(SHELL.timeout_ms, PM_PATH.max_output_bytes),
        )
        .await?;
        let mut result = self.base(serial);
        result.insert("package_name".into(), json!(package));
        self.done(
            result,
            vec![
                "Force-stop succeeds even for packages with no running process; it reports completion, not prior state"
                    .to_string(),
            ],
        )
    }

    async fn capture_screen(&self, input: &Map<String, Value>) -> Outcome {
        let operation = self.operation;
        let serial = str_of(input, "serial");
        let directory = prepare_output_directory(operation, str_of(input, "output_directory")).await?;
        let local_path = join(&directory, "screen.png");
        refuse_existing_target(operation, &local_path).await?;
        let captured = exec_file_binary(
            self.binary(),
            &adb_arguments(Some(serial), &["exec-out", "screencap", "-p"]),
            SCREEN.timeout_ms,
            SCREEN.max_output_bytes,
        )
        .await;
        let bytes = match captured {
            BinaryRun::Output(bytes) => bytes,
            BinaryRun::Timeout => {
                return Err(ToolError::Timeout { operation: operation.to_string(), timeout_ms: SCREEN.timeout_ms })
            }
            BinaryRun::Failed(message) => {
                return Err(ToolError::protocol(format!("adb failed for {operation}: {message}")))
            }
        };
        let Some((width, height)) = parse_png_dimensions(&bytes) else {
            return Err(ToolError::protocol(
                "screencap did not return a PNG payload; the device may not expose a display",
            ));
        };
        let write = {
            let path = local_path.clone();
            let payload = bytes.clone();
            tokio::task::spawn_blocking(move || {
                use std::io::Write;
                let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
                file.write_all(&payload)
            })
            .await
        };
        if !matches!(write, Ok(Ok(()))) {
            return Err(ToolError::Output {
                operation: operation.to_string(),
                reason: format!("The screen output could not be created exclusively: {local_path}"),
            });
        }
        let sha256 = hex::encode(Sha256::digest(&bytes));
        let mut result = self.base(serial);
        result.insert("local_path".into(), json!(local_path));
        result.insert("bytes".into(), json!(bytes.len()));
        result.insert("sha256".into(), json!(sha256));
        result.insert("width".into(), json!(width));
        result.insert("height".into(), json!(height));
        self.done(
            result,
            vec!["The capture is one frame at read time; no recording or interaction occurred".to_string()],
        )
    }

    async fn collect_bugreport(&self, input: &Map<String, Value>) -> Outcome {
        let operation = self.operation;
        let serial = str_of(input, "serial");
        let directory = prepare_output_directory(operation, str_of(input, "output_directory")).await?;
        let collected = self
            .adb(serial, adb_arguments(Some(serial), &["bugreport", &directory]), BUGREPORT)
            .await?;
        let Some(reported_path) = parse_bugreport_copied_path(&collected.stdout) else {
            return Err(ToolError::protocol(
                "adb bugreport did not report an archive path; the build may use an unsupported format",
            ));
        };
        match hash_file(&reported_path).await {
            Ok((sha256, bytes)) => {
                let mut result = self.base(serial);
                result.insert("local_path".into(), json!(reported_path));
                result.insert("bytes".into(), json!(bytes));
                result.insert("sha256".into(), json!(sha256));
                result.insert("adb_reported_path".into(), json!(reported_path));
                self.done(
                    result,
                    vec![
                        "The archive is device-generated: dumpstate, dumpsys, and logcat content is the device's own report"
                            .to_string(),
                    ],
                )
            }
            Err(_) => Err(ToolError::Output {
                operation: operation.to_string(),
                reason: format!("The reported bugreport archive could not be read back: {reported_path}"),
            }),
        }
    }
}
