//! Shared plumbing for the managed/android track: REA error envelopes,
//! argument validation messages and per-session selection state.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use rmcp::model::{CallToolResult, Content};
use serde_json::{json, Value};
use tracewise_domain::ledger::EvidenceLedger;

use crate::session::BinarySession;

/// REA's structured error text (`{"error": {...}}`), flagged as a tool error.
pub fn rea_error(
    code: &str,
    category: &str,
    message: &str,
    retryable: bool,
    remediation: &str,
    details: Value,
) -> CallToolResult {
    let body = json!({
        "error": {
            "code": code,
            "category": category,
            "message": message,
            "retryable": retryable,
            "remediation": { "action": remediation },
            "details": details,
        }
    });
    CallToolResult::error(vec![Content::text(body.to_string())])
}

/// `AnalysisInputError` for a missing required argument.
pub fn missing_argument(operation: &str, path: &str, message: &str) -> CallToolResult {
    rea_error(
        "invalid_request",
        "invalid_input",
        "Analysis input is invalid. Check the arguments and try again.",
        true,
        "Correct the listed arguments and retry.",
        json!({
            "operation": operation,
            "issues": [{ "path": [path], "reason": "missing_argument", "message": message }],
        }),
    )
}

/// `target_unavailable` for a path that cannot be opened.
pub fn target_unavailable(path: &str, reason: &str, constraint: Option<&str>) -> CallToolResult {
    if constraint == Some("directory_requires_file") {
        return rea_error(
            "target_unavailable",
            "unavailable",
            "open_binary accepts files and macOS app bundles. This target is a directory; JavaScript/Electron application directories can be analyzed directly with analyze_javascript_application or `rea analyze <directory>`.",
            false,
            "For a JavaScript/Electron application directory, call analyze_javascript_application with input_path or run `rea analyze <directory>`. For binary analysis, select its executable file.",
            json!({ "path": path, "reason": reason, "constraint": "directory_requires_file" }),
        );
    }
    let message = format!(
        "Cannot open artifact: {reason}. Check that the path exists, is readable, and points to a supported file."
    );
    rea_error(
        "target_unavailable",
        "unavailable",
        &message,
        false,
        &message,
        json!({ "path": path, "reason": reason }),
    )
}

/// `AnalysisCapabilityUnavailableError`.
pub fn capability_unavailable(provider_id: &str, operation: &str, reason: &str) -> CallToolResult {
    rea_error(
        "capability_unavailable",
        "unsupported_provider",
        "This analysis is unavailable for the current target. Choose another analysis or target.",
        false,
        "This analysis is unavailable for the current target. Choose another analysis or target.",
        json!({ "provider_id": provider_id, "operation": operation, "reason": reason }),
    )
}

/// `ProviderAdapterError` rendering for an unexpected provider failure.
pub fn execution_failure(provider_id: &str, operation: &str) -> CallToolResult {
    rea_error(
        "execution_failure",
        "execution_failure",
        "Analysis could not complete. Retry once; if it continues, run `rea doctor`.",
        false,
        "Analysis could not complete. Retry once; if it continues, run `rea doctor`.",
        json!({ "provider_id": provider_id, "operation": operation }),
    )
}

/// SDK-level input validation text (zod) for a tool call.
pub fn input_validation_error(tool: &str, issues: &[String]) -> CallToolResult {
    CallToolResult::error(vec![Content::text(format!(
        "Input validation error: Invalid arguments for tool {tool}: {}",
        issues.join(", ")
    ))])
}

/// Validate an object whose only allowed key is an optional absolute `path`.
/// Returns the path when present.
pub fn validate_path_only(args: &Value) -> Result<Option<String>, Vec<String>> {
    let mut issues = Vec::new();
    let Some(object) = args.as_object() else {
        return Err(vec!["Invalid input: expected object, received ".to_string() + js_type_name(args)]);
    };
    for key in object.keys() {
        if key != "path" {
            issues.push(format!("Unrecognized key: \"{key}\""));
        }
    }
    let mut path = None;
    if let Some(value) = object.get("path") {
        match value {
            Value::String(text) => {
                if text.is_empty() {
                    issues.push("path: Too small: expected string to have >=1 characters".to_string());
                }
                if text.contains('\0') {
                    issues.push("path: Local filesystem paths cannot contain NUL".to_string());
                }
                if !is_absolute_path(text) {
                    issues.push(
                        "path: path must be an absolute local filesystem path (for example /tmp/Example.dll or C:\\Example.dll)"
                            .to_string(),
                    );
                }
                path = Some(text.clone());
            }
            other => issues.push(format!("path: Invalid input: expected string, received {}", js_type_name(other))),
        }
    }
    if issues.is_empty() {
        Ok(path)
    } else {
        Err(issues)
    }
}

pub fn js_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// `path.isAbsolute` on POSIX plus Windows drive/UNC forms.
pub fn is_absolute_path(path: &str) -> bool {
    if path.starts_with('/') {
        return true;
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/') {
        return true;
    }
    path.starts_with("\\\\")
}

type Entries = HashMap<(usize, String), (Weak<Mutex<EvidenceLedger>>, String)>;

fn registry() -> &'static Mutex<Entries> {
    static REGISTRY: OnceLock<Mutex<Entries>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn session_key(session: &BinarySession) -> usize {
    Arc::as_ptr(&session.ledger) as *const () as usize
}

/// Per-session memory (REA keeps these as closure state in the server).
pub fn selected(session: &BinarySession, slot: &str) -> Option<String> {
    let key = (session_key(session), slot.to_string());
    let map = registry().lock().unwrap();
    let (weak, value) = map.get(&key)?;
    let live = weak.upgrade()?;
    if Arc::ptr_eq(&live, &session.ledger) {
        Some(value.clone())
    } else {
        None
    }
}

pub fn select(session: &BinarySession, slot: &str, value: String) {
    let key = (session_key(session), slot.to_string());
    registry().lock().unwrap().insert(key, (Arc::downgrade(&session.ledger), value));
}

