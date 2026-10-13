//! `capture_electron_scenario` (port of REA
//! domain/javascript/electronActiveObservation.ts input schema,
//! application/javascript/ElectronActiveObservationService.ts,
//! application/javascript/ElectronActiveEvidence.ts and
//! browser/PlaywrightElectronActiveProjection.ts).
//!
//! Ported faithfully:
//! - strict input validation (absolute NUL-free paths, `args`, the five action
//!   kinds with their defaults, absolute deep-link URLs);
//! - path canonicalization (`realpath` of executable, application and root;
//!   root defaults to the application's directory). Unresolvable paths fail
//!   with REA's `invalid_request` issue on `application_path`;
//! - the hook-snapshot projection (`project_electron_active_capture`: coverage,
//!   retention, IPC/timeline split and limitations) and the Evidence envelope
//!   (`create_electron_active_evidence`, including `scenario_sha256`).
//!
//! The active provider itself (REA's `PlaywrightElectronActiveProvider`: launch
//! with the injected `scripts/electron-active-hook.cjs` main-process hook, drive
//! windows, read the hook snapshot, verify owned-process cleanup) lives in
//! [`crate::electron_active`]; it controls Electron over CDP instead of
//! Playwright. Without an operator-configured Electron
//! (`TRACEWISE_ELECTRON_EXECUTABLE`) the tool returns the failure REA returns
//! when its active provider is not configured:
//! `AnalysisCapabilityUnavailableError("rea-playwright-electron-active",
//! "capture_electron_scenario", "active Electron observation provider is not configured")`.
//! The projection and evidence functions below are shared by both paths.

use std::path::Path;

use serde_json::{json, Map, Value};
use tracewise_domain::canonical::canonical_sha256;
use tracewise_domain::evidence::{
    create_evidence, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation,
    EvidenceProvider, ExecutionEnvironment, IsolationLevel,
};

use crate::electron_active::{self, ElectronActiveConfig, ElectronCaptureError};
use crate::error::WebError;

pub const OPERATION: &str = "capture_electron_scenario";
pub const PLAYWRIGHT_ELECTRON_ACTIVE_PROVIDER_ID: &str = "rea-playwright-electron-active";
pub const PLAYWRIGHT_ELECTRON_ACTIVE_PROVIDER_NAME: &str = "REA Playwright active Electron observation provider";
pub const PLAYWRIGHT_ELECTRON_ACTIVE_PROVIDER_VERSION: &str = "1";
pub const PROVIDER_NOT_CONFIGURED: &str = "active Electron observation provider is not configured";
pub const CANONICAL_PATH_MESSAGE: &str = "Electron executable, application, and root must resolve to existing paths";
const ABSOLUTE_PATH_MESSAGE: &str = "Electron executable, application, and root paths must be absolute local filesystem paths (for example /Applications/Electron.app/Contents/MacOS/Electron)";
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// Schema-level input violation (zod-style issue path and message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioInputIssue {
    pub path: Vec<String>,
    pub message: String,
}

impl std::fmt::Display for ScenarioInputIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.path.is_empty() {
            write!(f, "{}", self.message)
        } else {
            write!(f, "{}: {}", self.path.join("."), self.message)
        }
    }
}

fn issue(path: &[&str], message: impl Into<String>) -> ScenarioInputIssue {
    ScenarioInputIssue {
        path: path.iter().map(|p| p.to_string()).collect(),
        message: message.into(),
    }
}

/// Validate the strict input object and apply REA defaults. Returns the parsed
/// scenario as JSON (same shape REA hashes into `scenario_sha256`).
pub fn parse_capture_electron_scenario_input(args: &Value) -> Result<Map<String, Value>, Vec<ScenarioInputIssue>> {
    let Some(object) = args.as_object() else {
        return Err(vec![issue(&[], "Invalid input: expected object")]);
    };
    let mut issues = Vec::new();
    let unknown: Vec<&String> = object
        .keys()
        .filter(|key| !["executable_path", "application_path", "application_root", "args", "actions"].contains(&key.as_str()))
        .collect();
    if !unknown.is_empty() {
        let names: Vec<String> = unknown.iter().map(|key| format!("\"{key}\"")).collect();
        let noun = if unknown.len() == 1 { "key" } else { "keys" };
        issues.push(issue(&[], format!("Unrecognized {noun}: {}", names.join(", "))));
    }
    let mut parsed = Map::new();
    for (key, required) in [("executable_path", true), ("application_path", true), ("application_root", false)] {
        match object.get(key) {
            None if !required => {}
            None => issues.push(issue(&[key], "Invalid input: expected string, received undefined")),
            Some(Value::String(path)) => match path_issue(path) {
                Some(message) => issues.push(issue(&[key], message)),
                None => {
                    parsed.insert(key.to_string(), Value::String(path.clone()));
                }
            },
            Some(other) => issues.push(issue(&[key], format!("Invalid input: expected string, received {}", type_name(other)))),
        }
    }
    match object.get("args") {
        None => {
            parsed.insert("args".to_string(), json!([]));
        }
        Some(Value::Array(items)) => {
            for (index, item) in items.iter().enumerate() {
                let at = index.to_string();
                match item {
                    Value::String(text) if text.contains('\0') => {
                        issues.push(issue(&["args", &at], "Electron arguments must not contain NUL"))
                    }
                    Value::String(_) => {}
                    other => issues.push(issue(
                        &["args", &at],
                        format!("Invalid input: expected string, received {}", type_name(other)),
                    )),
                }
            }
            parsed.insert("args".to_string(), Value::Array(items.clone()));
        }
        Some(other) => issues.push(issue(&["args"], format!("Invalid input: expected array, received {}", type_name(other)))),
    }
    match object.get("actions") {
        None => {
            parsed.insert("actions".to_string(), json!([]));
        }
        Some(Value::Array(items)) => {
            let mut actions = Vec::new();
            for (index, item) in items.iter().enumerate() {
                match parse_action(item, &index.to_string()) {
                    Ok(action) => actions.push(action),
                    Err(mut found) => issues.append(&mut found),
                }
            }
            parsed.insert("actions".to_string(), Value::Array(actions));
        }
        Some(other) => issues.push(issue(&["actions"], format!("Invalid input: expected array, received {}", type_name(other)))),
    }
    if issues.is_empty() {
        // REA key order: schema order with defaults applied.
        let mut ordered = Map::new();
        for key in ["executable_path", "application_path", "application_root", "args", "actions"] {
            if let Some(value) = parsed.remove(key) {
                ordered.insert(key.to_string(), value);
            }
        }
        Ok(ordered)
    } else {
        Err(issues)
    }
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn path_issue(path: &str) -> Option<&'static str> {
    if path.is_empty() {
        return Some("Too small: expected string to have >=1 characters");
    }
    if path.contains('\0') {
        return Some("Local filesystem paths cannot contain NUL");
    }
    if !Path::new(path).is_absolute() {
        return Some(ABSOLUTE_PATH_MESSAGE);
    }
    None
}

fn parse_action(item: &Value, index: &str) -> Result<Value, Vec<ScenarioInputIssue>> {
    let Some(object) = item.as_object() else {
        return Err(vec![issue(&["actions", index], "Invalid input")]);
    };
    let kind = object.get("kind").and_then(Value::as_str).unwrap_or("");
    let allowed: &[&str] = match kind {
        "click" => &["step_id", "kind", "selector", "window_index"],
        "wait" => &["step_id", "kind", "duration_ms", "window_index"],
        "renderer-reload" | "renderer-crash" => &["step_id", "kind", "window_index"],
        "deep-link" => &["step_id", "kind", "delivery", "url"],
        _ => {
            return Err(vec![issue(
                &["actions", index, "kind"],
                "Invalid input: expected \"click\" | \"wait\" | \"renderer-reload\" | \"renderer-crash\" | \"deep-link\"",
            )])
        }
    };
    let mut issues = Vec::new();
    let unknown: Vec<String> = object
        .keys()
        .filter(|key| !allowed.contains(&key.as_str()))
        .map(|key| format!("\"{key}\""))
        .collect();
    if !unknown.is_empty() {
        let noun = if unknown.len() == 1 { "key" } else { "keys" };
        issues.push(issue(&["actions", index], format!("Unrecognized {noun}: {}", unknown.join(", "))));
    }
    let non_empty = |key: &str, issues: &mut Vec<ScenarioInputIssue>| match object.get(key) {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(Value::String(_)) => {
            issues.push(issue(&["actions", index, key], "Too small: expected string to have >=1 characters"));
            None
        }
        _ => {
            issues.push(issue(&["actions", index, key], "Invalid input: expected string"));
            None
        }
    };
    let window_index = |default: Option<i64>, issues: &mut Vec<ScenarioInputIssue>| match object.get("window_index") {
        None => default.map(Value::from),
        Some(value) => match non_negative_integer(value) {
            Some(n) => Some(Value::from(n)),
            None => {
                issues.push(issue(&["actions", index, "window_index"], "Invalid input: expected int >=0"));
                None
            }
        },
    };
    let step_id = non_empty("step_id", &mut issues);
    let mut action = Map::new();
    action.insert("step_id".to_string(), json!(step_id));
    action.insert("kind".to_string(), json!(kind));
    match kind {
        "click" => {
            let selector = non_empty("selector", &mut issues);
            action.insert("selector".to_string(), json!(selector));
            action.insert("window_index".to_string(), window_index(Some(0), &mut issues).unwrap_or(Value::Null));
        }
        "wait" => {
            match object.get("duration_ms").and_then(non_negative_integer) {
                Some(n) => {
                    action.insert("duration_ms".to_string(), json!(n));
                }
                None => issues.push(issue(&["actions", index, "duration_ms"], "Invalid input: expected int >=0")),
            }
            if let Some(window) = window_index(None, &mut issues) {
                action.insert("window_index".to_string(), window);
            }
        }
        "renderer-reload" | "renderer-crash" => {
            action.insert("window_index".to_string(), window_index(Some(0), &mut issues).unwrap_or(Value::Null));
        }
        _ => {
            match object.get("delivery").and_then(Value::as_str) {
                Some(delivery @ ("open-url" | "second-instance")) => {
                    action.insert("delivery".to_string(), json!(delivery));
                }
                _ => issues.push(issue(
                    &["actions", index, "delivery"],
                    "Invalid option: expected one of \"open-url\"|\"second-instance\"",
                )),
            }
            if let Some(url) = non_empty("url", &mut issues) {
                if url::Url::parse(&url).is_err() {
                    issues.push(issue(&["actions", index, "url"], "deep-link url must be an absolute URL"));
                }
                action.insert("url".to_string(), json!(url));
            }
        }
    }
    if issues.is_empty() {
        Ok(Value::Object(action))
    } else {
        Err(issues)
    }
}

fn non_negative_integer(value: &Value) -> Option<i64> {
    let n = value.as_i64().or_else(|| value.as_f64().filter(|n| n.fract() == 0.0).map(|n| n as i64))?;
    (0..=MAX_SAFE_INTEGER).contains(&n).then_some(n)
}

/// REA `canonicalizeInput`: realpath every path; the root defaults to the
/// application's parent directory.
pub fn canonicalize_scenario(input: &Map<String, Value>) -> Result<Map<String, Value>, WebError> {
    let invalid = || WebError::Input {
        operation: OPERATION.to_string(),
        path: vec!["application_path".to_string()],
        reason: "invalid_format".to_string(),
        message: CANONICAL_PATH_MESSAGE.to_string(),
    };
    let real = |key: &str| -> Result<String, WebError> {
        let path = input.get(key).and_then(Value::as_str).ok_or_else(invalid)?;
        let canonical = std::fs::canonicalize(path).map_err(|_| invalid())?;
        canonical.to_str().map(str::to_string).ok_or_else(invalid)
    };
    let executable = real("executable_path")?;
    let application = real("application_path")?;
    let root = if input.contains_key("application_root") {
        real("application_root")?
    } else {
        Path::new(&application)
            .parent()
            .and_then(Path::to_str)
            .unwrap_or("/")
            .to_string()
    };
    let mut canonical = input.clone();
    canonical.insert("executable_path".to_string(), Value::String(executable));
    canonical.insert("application_path".to_string(), Value::String(application));
    canonical.insert("application_root".to_string(), Value::String(root));
    Ok(canonical)
}

/// Run one scenario: validate paths, then use the configured active provider
/// (`TRACEWISE_ELECTRON_EXECUTABLE`) or report that none is configured.
pub async fn capture_electron_scenario(input: &Map<String, Value>) -> Result<Evidence, ElectronCaptureError> {
    let environment: std::collections::HashMap<String, String> = std::env::vars().collect();
    capture_electron_scenario_with(input, ElectronActiveConfig::from_env().as_ref(), &environment).await
}

/// [`capture_electron_scenario`] with an explicit configuration and environment
/// (the environment is what the launched Electron may inherit).
pub async fn capture_electron_scenario_with(
    input: &Map<String, Value>,
    config: Option<&ElectronActiveConfig>,
    environment: &std::collections::HashMap<String, String>,
) -> Result<Evidence, ElectronCaptureError> {
    let canonical = canonicalize_scenario(input)?;
    match config {
        None => Err(electron_active::provider_not_configured().into()),
        Some(config) => electron_active::capture(&canonical, config, environment).await,
    }
}

const OBSERVABLE_EVENT_FAMILIES: &[&str] = &[
    "app-lifecycle",
    "window-lifecycle",
    "web-contents-lifecycle",
    "navigation",
    "shell-attempt",
    "process-lifecycle",
    "permission",
    "popup-attempt",
    "download",
    "protocol",
    "preload",
    "preload-configuration",
    "renderer-ipc",
    "native-addon",
    "updater",
    "error",
    "ipc",
];

const IPC_EVENT_KINDS: &[&str] = &[
    "main-handler-invocation",
    "main-event-invocation",
    "utility-process-fork",
    "utility-process-message",
    "ipc-main-to-renderer",
    "ipc-utility-to-main",
    "ipc-renderer-send",
    "ipc-renderer-invoke",
    "ipc-renderer-post-message",
];

fn event_family(kind: &str, process_type: Option<&str>) -> String {
    if kind == "preload" && matches!(process_type, Some("main" | "browser")) {
        return "preload-configuration".to_string();
    }
    if kind.starts_with("ipc-renderer") {
        return if process_type == Some("renderer") { "renderer-ipc" } else { "ipc" }.to_string();
    }
    if IPC_EVENT_KINDS.contains(&kind) {
        "ipc".to_string()
    } else {
        kind.to_string()
    }
}

fn events(snapshot: &Value) -> &[Value] {
    snapshot["events"].as_array().map(Vec::as_slice).unwrap_or(&[])
}

fn named_counts<'v>(snapshot: &'v Value, field: &str, name: &str) -> Vec<&'v str> {
    snapshot[field]
        .as_array()
        .map(|items| items.iter().filter_map(|item| item[name].as_str()).collect())
        .unwrap_or_default()
}

fn coverage(snapshot: &Value) -> Value {
    let mut observed: std::collections::BTreeSet<String> = events(snapshot)
        .iter()
        .map(|event| event_family(event["kind"].as_str().unwrap_or(""), event["process_type"].as_str()))
        .collect();
    observed.extend(named_counts(snapshot, "dropped_event_families", "family").into_iter().map(str::to_string));
    let mut unavailable: std::collections::BTreeSet<String> = OBSERVABLE_EVENT_FAMILIES
        .iter()
        .filter(|family| !observed.contains(**family))
        .map(|family| family.to_string())
        .collect();
    let mut roles = std::collections::BTreeSet::new();
    for event in events(snapshot) {
        let kind = event["kind"].as_str().unwrap_or("");
        let process_type = event["process_type"].as_str();
        if let Some(process_type) = process_type {
            roles.insert(process_type.to_string());
        }
        if kind == "window-lifecycle" {
            roles.insert("window".to_string());
        }
        if kind == "web-contents-lifecycle" || kind == "navigation" {
            roles.insert("web_contents".to_string());
        }
        if kind == "preload" && process_type == Some("preload") {
            roles.insert("preload".to_string());
        }
        if kind.starts_with("ipc-renderer") && process_type == Some("renderer") {
            roles.insert("renderer".to_string());
        }
    }
    roles.extend(named_counts(snapshot, "dropped_event_roles", "role").into_iter().map(str::to_string));
    if !roles.contains("preload") {
        unavailable.insert("preload".to_string());
    }
    if !roles.contains("renderer") {
        unavailable.insert("renderer-ipc".to_string());
    }
    json!({
        "status": if snapshot["hook_error"] == true { "hook_conflict" } else { "partial_attach" },
        "observed_event_families": observed,
        "unavailable_event_families": unavailable,
        "observed_roles": roles,
        "pre_capture_activity": "unavailable",
    })
}

/// State read from one owned Electron application (REA `readApplicationState`).
#[derive(Debug, Clone, PartialEq)]
pub struct ElectronCaptureState {
    pub windows: Vec<Value>,
    pub metrics: Vec<Value>,
    pub electron_version: String,
    pub hook_snapshot: Value,
}

/// Project one hook snapshot into the public result (REA `projectElectronActiveCapture`).
/// Note: JavaScript's `localeCompare`-free `.sort()` on ASCII strings equals the byte order used here.
pub fn project_electron_active_capture(
    executable: &str,
    application: &str,
    actions: Vec<Value>,
    state: &ElectronCaptureState,
) -> Value {
    let snapshot = &state.hook_snapshot;
    let ipc_events: Vec<&Value> = events(snapshot)
        .iter()
        .filter(|event| IPC_EVENT_KINDS.contains(&event["kind"].as_str().unwrap_or("")))
        .collect();
    let mut limitations = vec![
        "IPC payloads are represented by value shapes; payload values are never retained.".to_string(),
        "IPC direction and sender/receiver identifiers are observed only where Electron exposes them at the hooked boundary.".to_string(),
        "The runtime timeline records lifecycle, navigation, shell, permission, popup, download, protocol, preload, native-addon, process, and IPC events; activity before hook installation is unavailable.".to_string(),
        "The preload and renderer process contexts are not instrumented by the main-process -r hook; preload configuration and contextBridge API-shape events are main-boundary observations, not proof of renderer-side execution.".to_string(),
    ];
    if !events(snapshot).iter().any(|event| event["kind"] == "preload") {
        limitations.push("Preload configuration was not exposed by the observed Electron window metadata. Preload paths and execution remain unavailable.".to_string());
    }
    limitations.push("Process metrics are an Electron API snapshot and do not prove hostile-local-user isolation.".to_string());
    let count = |field: &str| snapshot[field].as_i64().unwrap_or(0);
    if count("dropped") > 0 {
        limitations.push(format!(
            "The active hook retained {} of {} observed events within a {}-byte retained-data budget; {} events were dropped ({} IPC, {} runtime).",
            count("retained"),
            count("observed"),
            count("retention_budget_bytes"),
            count("dropped"),
            count("dropped_ipc"),
            count("dropped_runtime"),
        ));
    }
    limitations.push("External shell opens, external navigation, permission grants, downloads, popup windows, updater relaunches, and OS integration are blocked and recorded by the active hook; other application filesystem and network behavior is not sandboxed by this provider.".to_string());
    if snapshot["hook_error"] == true {
        limitations.push("The active IPC hook could not be installed.".to_string());
    }
    json!({
        "application": {
            "executable_path": executable,
            "application_path": application,
            "electron_version": state.electron_version,
            "process_ownership": "provider-owned",
            "cleanup": "terminated-owned-process",
        },
        "actions": actions,
        "windows": state.windows,
        "processes": { "items": state.metrics },
        "ipc": {
            "events": ipc_events,
            "observed": count("observed_ipc"),
            "dropped": count("dropped_ipc"),
        },
        "timeline": {
            "events": events(snapshot),
            "observed": count("observed"),
            "dropped": count("dropped"),
        },
        "retention": {
            "budget_bytes": count("retention_budget_bytes"),
            "estimated_retained_bytes": count("estimated_retained_bytes"),
            "event_serialized_byte_upper_bound": count("event_serialized_byte_upper_bound"),
            "retained": count("retained"),
            "dropped": count("dropped"),
            "dropped_event_families": snapshot["dropped_event_families"],
            "dropped_event_roles": snapshot["dropped_event_roles"],
            "observed_ipc": count("observed_ipc"),
            "dropped_ipc": count("dropped_ipc"),
            "observed_runtime": count("observed_runtime"),
            "dropped_runtime": count("dropped_runtime"),
        },
        "coverage": coverage(snapshot),
        "limitations": limitations,
    })
}

/// Commit the selected experiment and its result (REA `createElectronActiveEvidence`).
pub fn create_electron_active_evidence(canonical_input: &Map<String, Value>, result: Value) -> Result<Evidence, WebError> {
    let scenario = Value::Object(canonical_input.clone());
    let mut parameters = canonical_input.clone();
    parameters.insert("scenario_sha256".to_string(), Value::String(canonical_sha256(&scenario)?));
    let mut limitations = vec!["Artifact identity is unavailable for this observation.".to_string()];
    if let Some(items) = result["limitations"].as_array() {
        limitations.extend(items.iter().filter_map(|item| item.as_str().map(str::to_string)));
    }
    limitations.push("Application host platform and architecture were not observed.".to_string());
    let environment = ExecutionEnvironment {
        id: format!("{}@unknown", result["application"]["electron_version"].as_str().unwrap_or_default()),
        platform: "unknown".to_string(),
        architecture: "unknown".to_string(),
        isolation: IsolationLevel::None,
    };
    create_evidence(
        None,
        EvidenceProvider {
            id: PLAYWRIGHT_ELECTRON_ACTIVE_PROVIDER_ID.to_string(),
            name: PLAYWRIGHT_ELECTRON_ACTIVE_PROVIDER_NAME.to_string(),
            version: Some(PLAYWRIGHT_ELECTRON_ACTIVE_PROVIDER_VERSION.to_string()),
        },
        EvidenceObservation {
            predicate_type: Some("rea.electron-active-scenario".to_string()),
            operation: OPERATION.to_string(),
            parameters: Value::Object(parameters),
            normalized_result: result,
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Observed),
            authority: Some(EvidenceAuthority::ControlledReplay),
            environment: Some(environment),
            limitations: Some(limitations),
            locations: Some(vec![]),
            evidence_links: Some(vec![]),
        },
    )
    .map_err(WebError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(events: Value, dropped: i64, families: Value, roles: Value) -> Value {
        json!({
            "events": events,
            "retention_budget_bytes": 16 * 1024 * 1024,
            "estimated_retained_bytes": 1024,
            "event_serialized_byte_upper_bound": 512,
            "retained": 1,
            "dropped": dropped,
            "dropped_ipc": 0,
            "dropped_runtime": dropped,
            "dropped_event_families": families,
            "dropped_event_roles": roles,
            "observed": 1 + dropped,
            "observed_ipc": 1,
            "observed_runtime": dropped,
            "hook_error": false,
        })
    }

    fn event(kind: &str, process_type: &str) -> Value {
        json!({
            "sequence": 1, "correlation_id": "capture:123:1", "kind": kind, "event": null,
            "phase": "observed", "channel": "readiness:echo", "direction": "renderer-to-main",
            "sender": null, "receiver": "main", "frame": null, "target": null,
            "argument_shapes": [], "result_shape": null, "process_type": process_type,
            "source": "electron-active-hook", "capture_method": "api-wrapper",
            "artifact_path": null, "artifact_sha256": null, "error": false,
        })
    }

    /// REA PlaywrightElectronActiveProjection.test.ts, first case.
    #[test]
    fn projects_retention_and_dropped_families() {
        let state = ElectronCaptureState {
            windows: vec![],
            metrics: vec![],
            electron_version: "test-electron".to_string(),
            hook_snapshot: snapshot(
                json!([event("main-handler-invocation", "main")]),
                1,
                json!([{ "family": "renderer-ipc", "count": 1 }]),
                json!([{ "role": "renderer", "count": 1 }]),
            ),
        };
        let result = project_electron_active_capture("/opt/electron", "/opt/app/main.js", vec![], &state);
        assert_eq!(result["retention"]["dropped_event_families"], json!([{ "family": "renderer-ipc", "count": 1 }]));
        assert_eq!(result["ipc"]["observed"], 1);
        assert_eq!(result["ipc"]["dropped"], 0);
        assert_eq!(result["ipc"]["events"].as_array().unwrap().len(), 1);
        assert_eq!(result["timeline"]["observed"], 2);
        assert_eq!(result["timeline"]["dropped"], 1);
        let coverage = &result["coverage"];
        assert!(coverage["observed_event_families"].as_array().unwrap().contains(&json!("renderer-ipc")));
        assert!(!coverage["unavailable_event_families"].as_array().unwrap().contains(&json!("renderer-ipc")));
        assert!(coverage["observed_roles"].as_array().unwrap().contains(&json!("renderer")));
        assert!(coverage["unavailable_event_families"].as_array().unwrap().contains(&json!("preload")));
        assert_eq!(coverage["status"], "partial_attach");
        assert!(result["limitations"].as_array().unwrap().iter().any(|l| l
            .as_str()
            .unwrap()
            .starts_with("The active hook retained 1 of 2 observed events within a 16777216-byte")));
    }

    /// REA PlaywrightElectronActiveProjection.test.ts, second case.
    #[test]
    fn main_only_capture_keeps_renderer_ipc_unavailable() {
        let state = ElectronCaptureState {
            windows: vec![],
            metrics: vec![],
            electron_version: "test-electron".to_string(),
            hook_snapshot: snapshot(json!([event("app-lifecycle", "main")]), 0, json!([]), json!([])),
        };
        let result = project_electron_active_capture("/opt/electron", "/opt/app/main.js", vec![], &state);
        assert!(!result["coverage"]["observed_roles"].as_array().unwrap().contains(&json!("renderer")));
        assert!(result["coverage"]["unavailable_event_families"]
            .as_array()
            .unwrap()
            .contains(&json!("renderer-ipc")));
        assert_eq!(result["ipc"]["events"], json!([]));
    }

    #[test]
    fn input_defaults_and_issues_follow_rea() {
        let parsed = parse_capture_electron_scenario_input(&json!({
            "executable_path": "/bin/true",
            "application_path": "/tmp",
            "actions": [
                { "step_id": "a", "kind": "click", "selector": "#x" },
                { "step_id": "b", "kind": "wait", "duration_ms": 5 },
            ],
        }))
        .unwrap();
        assert_eq!(parsed["args"], json!([]));
        assert_eq!(parsed["actions"][0]["window_index"], 0);
        assert!(parsed["actions"][1].get("window_index").is_none());
        let issues = parse_capture_electron_scenario_input(&json!({
            "executable_path": "electron",
            "application_path": "app",
        }))
        .unwrap_err();
        assert_eq!(
            issues.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
            format!("executable_path: {ABSOLUTE_PATH_MESSAGE}, application_path: {ABSOLUTE_PATH_MESSAGE}")
        );
        let issues = parse_capture_electron_scenario_input(&json!({
            "executable_path": "/bin/true", "application_path": "/tmp",
            "actions": [{ "step_id": "s", "kind": "deep-link", "delivery": "open-url", "url": "notaurl" }],
        }))
        .unwrap_err();
        assert_eq!(issues[0].to_string(), "actions.0.url: deep-link url must be an absolute URL");
    }
}
