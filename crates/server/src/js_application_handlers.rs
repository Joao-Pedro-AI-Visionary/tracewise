//! `analyze_javascript_application`: the parse-heavy analysis runs on a blocking thread and stops
//! at its next checkpoint when the request is cancelled (the dispatcher drops this future), and
//! failures are REA error envelopes instead of free-form messages.

use rmcp::model::{CallToolResult, Content};
use rmcp::ErrorData as McpError;
use serde_json::{json, Value};
use tracewise_js::jsgraph::control::{Cancel, CancelGuard};
use tracewise_js::jsgraph::error::{AnalysisFailure, ArtifactFailure};
use tracewise_native::error::{ArtifactReason, InputIssue, NativeError};

use crate::handlers::remember_evidence;
use crate::session::BinarySession;

const OPERATION: &str = "analyze_javascript_application";

/// Validation text of REA's zod schema (`Input validation error: ...`).
fn validation_error(detail: String) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::error(vec![Content::text(format!(
        "Input validation error: Invalid arguments for tool {OPERATION}: {detail}"
    ))]))
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

/// Parsed request (`analyzeJavaScriptApplicationInputSchema`).
struct Request {
    input_path: String,
    format: String,
    integrity_policy: String,
}

fn parse_request(args: &Value) -> Result<Request, String> {
    let Some(object) = args.as_object() else {
        return Err(format!("Invalid input: expected object, received {}", type_name(args)));
    };
    let input_path = match object.get("input_path") {
        None => return Err("input_path: Invalid input: expected string, received undefined".into()),
        Some(Value::String(text)) if text.is_empty() => {
            return Err("input_path: Too small: expected string to have >=1 characters".into())
        }
        Some(Value::String(text)) => text.clone(),
        Some(other) => {
            return Err(format!("input_path: Invalid input: expected string, received {}", type_name(other)))
        }
    };
    let format = match object.get("format") {
        None => "auto".to_string(),
        Some(Value::String(text)) if matches!(text.as_str(), "auto" | "asar" | "directory") => text.clone(),
        Some(_) => return Err("format: Invalid option: expected one of \"auto\"|\"asar\"|\"directory\"".into()),
    };
    let integrity_policy = match object.get("integrity_policy") {
        None => "fail".to_string(),
        Some(Value::String(text)) if matches!(text.as_str(), "fail" | "record-and-continue") => text.clone(),
        Some(_) => {
            return Err("integrity_policy: Invalid option: expected one of \"fail\"|\"record-and-continue\"".into())
        }
    };
    for key in object.keys() {
        if !matches!(key.as_str(), "input_path" | "format" | "integrity_policy" | "_meta") {
            return Err(format!("Unrecognized key: \"{key}\""));
        }
    }
    Ok(Request { input_path, format, integrity_policy })
}

fn failure_envelope(failure: AnalysisFailure) -> NativeError {
    match failure {
        AnalysisFailure::Input { path, message, expected } => NativeError::Input {
            operation: OPERATION.into(),
            issues: vec![InputIssue {
                path: vec![json!(path)],
                reason: "invalid_value".into(),
                message: Some(message),
                expected: expected.map(|items| json!(items)),
            }],
        },
        AnalysisFailure::UnsupportedTarget { path, reason, remediation } => NativeError::UnsupportedTarget {
            operation: OPERATION.into(),
            path,
            reason,
            remediation: Some(remediation),
        },
        AnalysisFailure::AccessDenied { path, system_code } => NativeError::AccessDenied {
            operation: OPERATION.into(),
            path,
            system_code,
        },
        AnalysisFailure::Artifact { reason } => NativeError::Artifact {
            operation: OPERATION.into(),
            reason: match reason {
                ArtifactFailure::Cancelled => ArtifactReason::Cancelled,
                ArtifactFailure::Format => ArtifactReason::Format,
                ArtifactFailure::Integrity => ArtifactReason::Integrity,
                ArtifactFailure::Limit => ArtifactReason::Limit,
                ArtifactFailure::Path => ArtifactReason::Path,
                ArtifactFailure::Unavailable => ArtifactReason::Unavailable,
                ArtifactFailure::Io => ArtifactReason::Io,
            },
            detail: None,
        },
        AnalysisFailure::Unsupported { what } => NativeError::Capability {
            provider_id: "rea-javascript-application".into(),
            operation: OPERATION.into(),
            reason: format!("This port does not reproduce {what}."),
            user_message: true,
        },
        AnalysisFailure::Other(error) => NativeError::Output {
            operation: OPERATION.into(),
            reason: error.to_string(),
        },
    }
}

pub async fn handle_analyze_javascript_application(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let request = match parse_request(args) {
        Ok(request) => request,
        Err(detail) => return validation_error(detail),
    };
    let cancel = Cancel::new();
    // Dropping this future (request cancelled) flips the flag; the blocking work then stops at
    // its next checkpoint and releases its resources.
    let guard = CancelGuard::new(cancel.clone());
    let outcome = tokio::task::spawn_blocking(move || {
        tracewise_js::analyze_javascript_application_cancellable(
            &request.input_path,
            &request.format,
            &request.integrity_policy,
            &cancel,
        )
    })
    .await
    .map_err(|error| McpError::internal_error(format!("application analysis task failed: {error}"), None))?;
    guard.disarm();
    match outcome {
        Ok(evidence) => remember_evidence(session, evidence),
        Err(failure) => Ok(CallToolResult::error(vec![Content::text(
            failure_envelope(failure).to_body().to_string(),
        )])),
    }
}
