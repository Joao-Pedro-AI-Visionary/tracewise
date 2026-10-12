//! Port of REA `domain/process/processScenario.ts` and
//! `process/capture/ProcessScenarioRuntimeValidation.ts`: boundary parsing
//! with deterministic defaults, canonical commitments, and runtime path
//! resolution.

use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use serde_json::{json, Map, Value};
use tracewise_domain::canonical::canonical_sha256;

use crate::error::JsError;

/// Maximum xterm backing cells for one visible-plus-scrollback buffer.
pub const PROCESS_TERMINAL_CELL_BUDGET: u64 = 1_000_000;
const RESERVED_RUN_ID: &str = "REA_PROCESS_RUN_ID";
const MAX_SAFE: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq)]
pub enum ScenarioEvent {
    Input { at_ms: u64, data: String, sensitive: bool },
    Resize { at_ms: u64, columns: u16, rows: u16 },
    Signal { at_ms: u64, signal: String },
}

impl ScenarioEvent {
    pub fn at_ms(&self) -> u64 {
        match self {
            Self::Input { at_ms, .. } | Self::Resize { at_ms, .. } | Self::Signal { at_ms, .. } => *at_ms,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Input { .. } => "input",
            Self::Resize { .. } => "resize",
            Self::Signal { .. } => "signal",
        }
    }

    /// `data` recorded for a non-dispatched or dispatched interaction (non-input).
    pub fn descriptor(&self) -> String {
        match self {
            Self::Input { .. } => "<not-dispatched>".into(),
            Self::Resize { columns, rows, .. } => format!("{columns}x{rows}"),
            Self::Signal { signal, .. } => signal.clone(),
        }
    }

    fn committed(&self, include_sensitive_length: bool) -> Value {
        match self {
            Self::Input { at_ms, data, sensitive } => {
                let data = if *sensitive {
                    if include_sensitive_length {
                        format!("<redacted-input:{}-bytes>", data.len())
                    } else {
                        "<redacted-input>".to_string()
                    }
                } else {
                    data.clone()
                };
                json!({ "at_ms": at_ms, "type": "input", "data": data, "sensitive": sensitive })
            }
            Self::Resize { at_ms, columns, rows } => {
                json!({ "at_ms": at_ms, "type": "resize", "columns": columns, "rows": rows })
            }
            Self::Signal { at_ms, signal } => json!({ "at_ms": at_ms, "type": "signal", "signal": signal }),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Pattern {
    pub pattern: String,
    pub replacement: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Normalization {
    pub paths: bool,
    pub pids: bool,
    pub ports: bool,
    pub time_bucket_ms: u64,
    pub patterns: Vec<Pattern>,
}

impl Normalization {
    pub fn to_value(&self) -> Value {
        json!({
            "paths": self.paths,
            "pids": self.pids,
            "ports": self.ports,
            "time_bucket_ms": self.time_bucket_ms,
            "patterns": self.patterns.iter().map(|p| json!({"pattern": p.pattern, "replacement": p.replacement})).collect::<Vec<_>>(),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Limits {
    pub output_bytes: u64,
    pub files: u64,
    pub file_bytes: u64,
    pub processes: u64,
    pub filesystem_depth: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Terminal {
    pub columns: u16,
    pub rows: u16,
    pub scrollback: u64,
}

/// Parsed instructions and resource bounds for one process experiment.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessScenario {
    pub executable: String,
    pub arguments: Vec<String>,
    pub working_directory: String,
    /// Insertion-ordered caller overrides.
    pub environment: Vec<(String, String)>,
    pub filesystem_observation_paths: Vec<String>,
    pub terminal: Terminal,
    pub events: Vec<ScenarioEvent>,
    pub timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub settle_ms: u64,
    pub limits: Limits,
    pub normalization: Normalization,
}

impl ProcessScenario {
    pub fn environment_value(&self) -> Value {
        let mut map = Map::new();
        for (key, value) in &self.environment {
            map.insert(key.clone(), Value::String(value.clone()));
        }
        Value::Object(map)
    }

    fn terminal_value(&self) -> Value {
        json!({ "columns": self.terminal.columns, "rows": self.terminal.rows, "scrollback": self.terminal.scrollback })
    }

    fn limits_value(&self) -> Value {
        json!({
            "output_bytes": self.limits.output_bytes,
            "files": self.limits.files,
            "file_bytes": self.limits.file_bytes,
            "processes": self.limits.processes,
            "filesystem_depth": self.limits.filesystem_depth,
        })
    }

    fn events_value(&self, include_sensitive_length: bool) -> Value {
        Value::Array(self.events.iter().map(|e| e.committed(include_sensitive_length)).collect())
    }

    pub fn has_sensitive_input(&self) -> bool {
        self.events.iter().any(|e| matches!(e, ScenarioEvent::Input { sensitive: true, .. }))
    }
}

/// Caller-selected scenario projection committed by process-capture Evidence.
pub fn scenario_commitment(scenario: &ProcessScenario, executable_sha256: Option<&str>) -> Value {
    json!({
        "executable": scenario.executable,
        "arguments": scenario.arguments,
        "working_directory": scenario.working_directory,
        "environment": scenario.environment_value(),
        "filesystem_observation_paths": scenario.filesystem_observation_paths,
        "terminal": scenario.terminal_value(),
        "events": scenario.events_value(true),
        "timeout_ms": scenario.timeout_ms,
        "idle_timeout_ms": scenario.idle_timeout_ms,
        "settle_ms": scenario.settle_ms,
        "limits": scenario.limits_value(),
        "normalization": scenario.normalization.to_value(),
        "executable_sha256": executable_sha256,
    })
}

/// Observation settings shared by capture and reconstruction.
pub fn comparison_contract(scenario: &ProcessScenario) -> Value {
    let mut map = Map::new();
    map.insert("working_directory".into(), json!(scenario.working_directory));
    map.insert("environment".into(), scenario.environment_value());
    map.insert("ambient_environment".into(), json!("unknown"));
    map.insert("filesystem_observation_paths".into(), json!(scenario.filesystem_observation_paths));
    map.insert("terminal".into(), scenario.terminal_value());
    map.insert("events".into(), scenario.events_value(false));
    map.insert("timeout_ms".into(), json!(scenario.timeout_ms));
    map.insert("idle_timeout_ms".into(), json!(scenario.idle_timeout_ms));
    map.insert("settle_ms".into(), json!(scenario.settle_ms));
    map.insert("limits".into(), scenario.limits_value());
    map.insert("normalization".into(), scenario.normalization.to_value());
    if scenario.normalization.ports {
        map.insert("port_normalization_version".into(), json!("contextual-endpoints-v2"));
    }
    if !scenario.normalization.patterns.is_empty() {
        map.insert("pattern_normalization_version".into(), json!("literal-replacements-v1"));
    }
    map.insert("rendered_line_format".into(), json!("trailing-spaces-trimmed-v1"));
    Value::Object(map)
}

/// Canonical (RFC 8785) SHA-256 commitment.
pub fn digest_commitment(value: &Value) -> Result<String, JsError> {
    canonical_sha256(value).map_err(|e| JsError::InvalidInput(format!("Process capture commitment is not canonical JSON: {e}")))
}

// ---------------------------------------------------------------------------
// Boundary parsing (zod `processScenarioSchema` equivalent)
// ---------------------------------------------------------------------------

struct Issues(Vec<String>);

impl Issues {
    fn push(&mut self, path: &str, message: impl Into<String>) {
        let message = message.into();
        if path.is_empty() {
            self.0.push(message);
        } else {
            self.0.push(format!("{path}: {message}"));
        }
    }
}

fn strict_keys(value: &Map<String, Value>, allowed: &[&str], path: &str, issues: &mut Issues) {
    for key in value.keys() {
        if !allowed.contains(&key.as_str()) {
            issues.push(path, format!("Unrecognized key: \"{key}\""));
        }
    }
}

fn os_string(value: &Value, path: &str, issues: &mut Issues) -> Option<String> {
    match value.as_str() {
        Some(s) if s.contains('\0') => {
            issues.push(path, "Values passed to operating-system APIs cannot contain NUL");
            None
        }
        Some(s) => Some(s.to_string()),
        None => {
            issues.push(path, "Invalid input: expected string");
            None
        }
    }
}

fn integer(value: Option<&Value>, default: u64, min: u64, max: u64, path: &str, issues: &mut Issues) -> u64 {
    let Some(value) = value else { return default };
    match value.as_u64() {
        Some(n) if n >= min && n <= max => n,
        Some(_) => {
            issues.push(path, format!("Invalid input: expected integer in {min}..={max}"));
            default
        }
        None => {
            if value.as_f64().is_some_and(|f| f.fract() == 0.0 && f >= min as f64 && f <= max as f64) {
                return value.as_f64().unwrap_or_default() as u64;
            }
            issues.push(path, format!("Invalid input: expected integer in {min}..={max}"));
            default
        }
    }
}

fn boolean(value: Option<&Value>, default: bool, path: &str, issues: &mut Issues) -> bool {
    match value {
        None => default,
        Some(Value::Bool(b)) => *b,
        Some(_) => {
            issues.push(path, "Invalid input: expected boolean");
            default
        }
    }
}

fn object<'a>(value: Option<&'a Value>, path: &str, issues: &mut Issues) -> Option<&'a Map<String, Value>> {
    match value {
        None => None,
        Some(Value::Object(map)) => Some(map),
        Some(_) => {
            issues.push(path, "Invalid input: expected object");
            None
        }
    }
}

fn array<'a>(value: Option<&'a Value>, path: &str, issues: &mut Issues) -> &'a [Value] {
    match value {
        None => &[],
        Some(Value::Array(items)) => items,
        Some(_) => {
            issues.push(path, "Invalid input: expected array");
            &[]
        }
    }
}

fn fits_cell_budget(columns: u64, rows: u64, scrollback: u64) -> bool {
    rows.saturating_add(scrollback) <= PROCESS_TERMINAL_CELL_BUDGET / columns.max(1)
}

fn valid_environment_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Environment names must not be empty".into());
    }
    if name == RESERVED_RUN_ID {
        return Err(format!("{RESERVED_RUN_ID} is reserved by the process adapter"));
    }
    if name.contains('=') || name.contains('\0') {
        return Err("Environment names cannot contain '=' or NUL".into());
    }
    Ok(())
}

/// Parse untrusted process scenario input and apply safe default budgets.
pub fn parse_process_scenario(input: &Value) -> Result<ProcessScenario, JsError> {
    let mut issues = Issues(Vec::new());
    let Some(root) = input.as_object() else {
        return Err(validation_error(&["Invalid input: expected object".into()]));
    };
    strict_keys(
        root,
        &[
            "executable", "arguments", "working_directory", "environment", "filesystem_observation_paths",
            "terminal", "events", "timeout_ms", "idle_timeout_ms", "settle_ms", "limits", "normalization",
        ],
        "",
        &mut issues,
    );
    let executable = match root.get("executable") {
        None => {
            issues.push("executable", "Invalid input: expected string, received undefined");
            String::new()
        }
        Some(v) => {
            let s = os_string(v, "executable", &mut issues).unwrap_or_default();
            if v.is_string() && s.is_empty() {
                issues.push("executable", "Too small: expected string to have >=1 characters");
            }
            s
        }
    };
    let arguments = array(root.get("arguments"), "arguments", &mut issues)
        .iter()
        .enumerate()
        .filter_map(|(i, v)| os_string(v, &format!("arguments.{i}"), &mut issues))
        .collect();
    let working_directory = match root.get("working_directory") {
        None => ".".to_string(),
        Some(v) => os_string(v, "working_directory", &mut issues).unwrap_or_default(),
    };
    let mut environment = Vec::new();
    if let Some(env) = object(root.get("environment"), "environment", &mut issues) {
        for (key, value) in env {
            if let Err(message) = valid_environment_name(key) {
                issues.push(&format!("environment.{key}"), message);
                continue;
            }
            if let Some(v) = os_string(value, &format!("environment.{key}"), &mut issues) {
                environment.push((key.clone(), v));
            }
        }
    }
    let mut filesystem_observation_paths = Vec::new();
    for (i, v) in array(root.get("filesystem_observation_paths"), "filesystem_observation_paths", &mut issues)
        .iter()
        .enumerate()
    {
        let path = format!("filesystem_observation_paths.{i}");
        if let Some(s) = os_string(v, &path, &mut issues) {
            if s.is_empty() {
                issues.push(&path, "Too small: expected string to have >=1 characters");
            }
            filesystem_observation_paths.push(s);
        }
    }
    let terminal = match object(root.get("terminal"), "terminal", &mut issues) {
        None => Terminal { columns: 80, rows: 24, scrollback: 1000 },
        Some(t) => {
            strict_keys(t, &["columns", "rows", "scrollback"], "terminal", &mut issues);
            Terminal {
                columns: integer(t.get("columns"), 80, 1, 65_535, "terminal.columns", &mut issues) as u16,
                rows: integer(t.get("rows"), 24, 1, 65_535, "terminal.rows", &mut issues) as u16,
                scrollback: integer(t.get("scrollback"), 1000, 0, MAX_SAFE, "terminal.scrollback", &mut issues),
            }
        }
    };
    let mut events = Vec::new();
    for (i, v) in array(root.get("events"), "events", &mut issues).iter().enumerate() {
        let path = format!("events.{i}");
        let Some(ev) = v.as_object() else {
            issues.push(&path, "Invalid input: expected object");
            continue;
        };
        let at_ms = match ev.get("at_ms") {
            None => {
                issues.push(&format!("{path}.at_ms"), "Invalid input: expected number, received undefined");
                0
            }
            some => integer(some, 0, 0, MAX_SAFE, &format!("{path}.at_ms"), &mut issues),
        };
        match ev.get("type").and_then(Value::as_str) {
            Some("input") => {
                strict_keys(ev, &["at_ms", "type", "data", "sensitive"], &path, &mut issues);
                let data = match ev.get("data").and_then(Value::as_str) {
                    Some(s) => s.to_string(),
                    None => {
                        issues.push(&format!("{path}.data"), "Invalid input: expected string");
                        String::new()
                    }
                };
                let sensitive = boolean(ev.get("sensitive"), false, &format!("{path}.sensitive"), &mut issues);
                events.push(ScenarioEvent::Input { at_ms, data, sensitive });
            }
            Some("resize") => {
                strict_keys(ev, &["at_ms", "type", "columns", "rows"], &path, &mut issues);
                for key in ["columns", "rows"] {
                    if ev.get(key).is_none() {
                        issues.push(&format!("{path}.{key}"), "Invalid input: expected number, received undefined");
                    }
                }
                let columns = integer(ev.get("columns"), 1, 1, 65_535, &format!("{path}.columns"), &mut issues) as u16;
                let rows = integer(ev.get("rows"), 1, 1, 65_535, &format!("{path}.rows"), &mut issues) as u16;
                events.push(ScenarioEvent::Resize { at_ms, columns, rows });
            }
            Some("signal") => {
                strict_keys(ev, &["at_ms", "type", "signal"], &path, &mut issues);
                match ev.get("signal").and_then(Value::as_str) {
                    Some(s @ ("SIGINT" | "SIGTERM" | "SIGKILL")) => {
                        events.push(ScenarioEvent::Signal { at_ms, signal: s.to_string() })
                    }
                    _ => issues.push(
                        &format!("{path}.signal"),
                        "Invalid option: expected one of \"SIGINT\"|\"SIGTERM\"|\"SIGKILL\"",
                    ),
                }
            }
            _ => issues.push(&format!("{path}.type"), "Invalid input"),
        }
    }
    let timeout_ms = integer(root.get("timeout_ms"), 30_000, 1, MAX_SAFE, "timeout_ms", &mut issues);
    let idle_timeout_ms = integer(root.get("idle_timeout_ms"), 30_000, 1, MAX_SAFE, "idle_timeout_ms", &mut issues);
    let settle_ms = integer(root.get("settle_ms"), 100, 0, MAX_SAFE, "settle_ms", &mut issues);
    let limits = match object(root.get("limits"), "limits", &mut issues) {
        None => Limits { output_bytes: 1_000_000, files: 10_000, file_bytes: 10_000_000, processes: 1_000, filesystem_depth: 16 },
        Some(l) => {
            strict_keys(l, &["output_bytes", "files", "file_bytes", "processes", "filesystem_depth"], "limits", &mut issues);
            Limits {
                output_bytes: integer(l.get("output_bytes"), 1_000_000, 1, MAX_SAFE, "limits.output_bytes", &mut issues),
                files: integer(l.get("files"), 10_000, 1, MAX_SAFE, "limits.files", &mut issues),
                file_bytes: integer(l.get("file_bytes"), 10_000_000, 1, MAX_SAFE, "limits.file_bytes", &mut issues),
                processes: integer(l.get("processes"), 1_000, 1, MAX_SAFE, "limits.processes", &mut issues),
                filesystem_depth: integer(l.get("filesystem_depth"), 16, 0, MAX_SAFE, "limits.filesystem_depth", &mut issues),
            }
        }
    };
    let normalization = match object(root.get("normalization"), "normalization", &mut issues) {
        None => Normalization { paths: false, pids: true, ports: true, time_bucket_ms: 10, patterns: Vec::new() },
        Some(n) => {
            strict_keys(n, &["paths", "pids", "ports", "time_bucket_ms", "patterns"], "normalization", &mut issues);
            let mut patterns = Vec::new();
            for (i, p) in array(n.get("patterns"), "normalization.patterns", &mut issues).iter().enumerate() {
                let path = format!("normalization.patterns.{i}");
                match p.as_object() {
                    Some(obj) => {
                        strict_keys(obj, &["pattern", "replacement"], &path, &mut issues);
                        match (obj.get("pattern").and_then(Value::as_str), obj.get("replacement").and_then(Value::as_str)) {
                            (Some(pattern), Some(replacement)) => patterns.push(Pattern {
                                pattern: pattern.to_string(),
                                replacement: replacement.to_string(),
                            }),
                            _ => issues.push(&path, "Invalid input: expected pattern and replacement strings"),
                        }
                    }
                    None => issues.push(&path, "Invalid input: expected object"),
                }
            }
            Normalization {
                paths: boolean(n.get("paths"), false, "normalization.paths", &mut issues),
                pids: boolean(n.get("pids"), true, "normalization.pids", &mut issues),
                ports: boolean(n.get("ports"), true, "normalization.ports", &mut issues),
                time_bucket_ms: integer(n.get("time_bucket_ms"), 10, 1, MAX_SAFE, "normalization.time_bucket_ms", &mut issues),
                patterns,
            }
        }
    };
    // superRefine
    if !fits_cell_budget(terminal.columns as u64, terminal.rows as u64, terminal.scrollback) {
        issues.push(
            "terminal",
            format!("terminal columns × (rows + scrollback) must not exceed {PROCESS_TERMINAL_CELL_BUDGET} renderer cells"),
        );
    }
    for index in 1..events.len() {
        if events[index].at_ms() < events[index - 1].at_ms() {
            issues.push(&format!("events.{index}"), "events must be ordered by at_ms");
        }
    }
    for (index, event) in events.iter().enumerate() {
        if let ScenarioEvent::Resize { at_ms, columns, rows } = event {
            if !fits_cell_budget(*columns as u64, *rows as u64, terminal.scrollback) {
                issues.push(
                    &format!("events.{index}"),
                    format!("resize event at {at_ms} ms exceeds the {PROCESS_TERMINAL_CELL_BUDGET}-cell renderer budget with the selected scrollback"),
                );
            }
        }
        if event.at_ms() > timeout_ms {
            issues.push("events", "event occurs after the scenario timeout");
        }
    }
    if !issues.0.is_empty() {
        return Err(validation_error(&issues.0));
    }
    Ok(ProcessScenario {
        executable,
        arguments,
        working_directory,
        environment,
        filesystem_observation_paths,
        terminal,
        events,
        timeout_ms,
        idle_timeout_ms,
        settle_ms,
        limits,
        normalization,
    })
}

fn validation_error(issues: &[String]) -> JsError {
    JsError::InvalidInput(format!(
        "Input validation error: Invalid arguments for tool capture_process_scenario: {}",
        issues.join("; ")
    ))
}

// ---------------------------------------------------------------------------
// Runtime path resolution
// ---------------------------------------------------------------------------

/// Node `path.resolve(base, path)`: lexical, no symlink resolution.
pub fn resolve_lexical(base: &Path, path: &str) -> PathBuf {
    let joined = if Path::new(path).is_absolute() { PathBuf::from(path) } else { base.join(path) };
    let mut out = PathBuf::from("/");
    for component in joined.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => out.push(part),
        }
    }
    out
}

fn os_failure(error: &std::io::Error) -> String {
    match error.raw_os_error() {
        Some(code) => format!(" ({})", errno_name(code)),
        None => String::new(),
    }
}

pub(crate) fn errno_name(code: i32) -> &'static str {
    match code {
        libc::ENOENT => "ENOENT",
        libc::EACCES => "EACCES",
        libc::ENOTDIR => "ENOTDIR",
        libc::EPERM => "EPERM",
        libc::ELOOP => "ELOOP",
        libc::EISDIR => "EISDIR",
        libc::ESTALE => "ESTALE",
        libc::ENAMETOOLONG => "ENAMETOOLONG",
        libc::EIO => "EIO",
        _ => "EUNKNOWN",
    }
}

fn is_executable(path: &Path) -> Result<bool, std::io::Error> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: `c` is a valid NUL-terminated path for the duration of the call.
    let rc = unsafe { libc::access(c.as_ptr(), libc::X_OK) };
    if rc == 0 {
        Ok(true)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Resolve a selected executable through the caller's effective PATH.
pub fn resolve_executable(command: &str, working_directory: &Path, search_path: &str) -> Result<String, JsError> {
    let candidates: Vec<PathBuf> = if Path::new(command).is_absolute() || command.contains('/') || command.contains('\\') {
        vec![resolve_lexical(working_directory, command)]
    } else {
        search_path
            .split(':')
            .map(|dir| {
                let dir = if dir.is_empty() { working_directory.to_path_buf() } else { resolve_lexical(working_directory, dir) };
                dir.join(command)
            })
            .collect()
    };
    let mut failures = Vec::new();
    for candidate in candidates {
        match is_executable(&candidate).and_then(|_| std::fs::metadata(&candidate)) {
            Ok(meta) if meta.is_file() => return Ok(candidate.to_string_lossy().into_owned()),
            Ok(_) => failures.push(format!("{} (not a regular file)", candidate.display())),
            Err(error) => {
                let code = error.raw_os_error();
                if code != Some(libc::ENOENT) && code != Some(libc::ENOTDIR) {
                    failures.push(format!("{}{}", candidate.display(), os_failure(&error)));
                }
            }
        }
    }
    Err(JsError::Io(if failures.is_empty() {
        format!("executable could not be resolved: {command}")
    } else {
        format!("executable could not be resolved: {command}; checked {}", failures.join("; "))
    }))
}

/// Resolve caller-selected executable and observation paths for this execution.
pub fn resolve_runtime_paths(
    scenario: &ProcessScenario,
    host_environment: &[(String, String)],
) -> Result<ProcessScenario, JsError> {
    let cwd = std::env::current_dir().map_err(|e| JsError::Io(e.to_string()))?;
    let selected = resolve_lexical(&cwd, &scenario.working_directory);
    let working_directory = std::fs::canonicalize(&selected).map_err(|e| {
        JsError::Io(format!("working directory could not be resolved: {}{}", selected.display(), os_failure(&e)))
    })?;
    let meta = std::fs::metadata(&working_directory).map_err(|e| {
        JsError::Io(format!("working directory could not be inspected: {}{}", working_directory.display(), os_failure(&e)))
    })?;
    if !meta.is_dir() {
        return Err(JsError::Io(format!("working directory is not a directory: {}", working_directory.display())));
    }
    let lookup = |env: &[(String, String)]| env.iter().find(|(k, _)| k == "PATH").map(|(_, v)| v.clone());
    let search_path = lookup(&scenario.environment).or_else(|| lookup(host_environment)).unwrap_or_default();
    let executable = resolve_executable(&scenario.executable, &working_directory, &search_path)?;
    let filesystem_observation_paths = scenario
        .filesystem_observation_paths
        .iter()
        .map(|p| resolve_lexical(&working_directory, p).to_string_lossy().into_owned())
        .collect();
    Ok(ProcessScenario {
        executable,
        working_directory: working_directory.to_string_lossy().into_owned(),
        filesystem_observation_paths,
        ..scenario.clone()
    })
}

/// Executable bit check used by tests.
#[allow(dead_code)]
pub(crate) fn mode_is_executable(meta: &std::fs::Metadata) -> bool {
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_rea_contract() {
        let scenario = parse_process_scenario(&json!({"executable": "/bin/true"})).unwrap();
        assert_eq!(scenario.working_directory, ".");
        assert_eq!(scenario.terminal, Terminal { columns: 80, rows: 24, scrollback: 1000 });
        assert_eq!(scenario.settle_ms, 100);
        assert!(!scenario.normalization.paths && scenario.normalization.pids && scenario.normalization.ports);
    }

    #[test]
    fn rejects_reserved_environment_and_late_events() {
        assert!(parse_process_scenario(&json!({"executable": "x", "environment": {"REA_PROCESS_RUN_ID": "1"}})).is_err());
        assert!(parse_process_scenario(&json!({"executable": "x", "timeout_ms": 10, "events": [{"at_ms": 11, "type": "signal", "signal": "SIGINT"}]})).is_err());
        assert!(parse_process_scenario(&json!({"executable": "x", "terminal": {"columns": 1000, "rows": 24, "scrollback": 1000}})).is_err());
    }

    #[test]
    fn lexical_resolution() {
        assert_eq!(resolve_lexical(Path::new("/a/b"), "../c/./d/"), PathBuf::from("/a/c/d"));
        assert_eq!(resolve_lexical(Path::new("/a"), "/x/../y"), PathBuf::from("/y"));
    }
}
