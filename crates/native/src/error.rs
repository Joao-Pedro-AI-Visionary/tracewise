//! Typed failures of the native static tools and their REA error projection.
//!
//! REA projects every expected failure into
//! `{ error: { code, category, message, retryable, remediation, details } }`
//! (`domain/analysisErrorProjection.ts`, `analysisErrorPresentation.ts`).
//! The variants below cover the failures the 14 native tools can raise.

use serde_json::{json, Map, Value};

/// One caller-input issue (`AnalysisInputError.issues`).
#[derive(Debug, Clone, PartialEq)]
pub struct InputIssue {
    pub path: Vec<Value>,
    pub reason: String,
    pub message: Option<String>,
    pub expected: Option<Value>,
}

impl InputIssue {
    pub fn invalid(path: Vec<Value>, message: impl Into<String>) -> Self {
        Self {
            path,
            reason: "invalid_value".to_string(),
            message: Some(message.into()),
            expected: None,
        }
    }
}

/// `ArtifactOperationError.reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactReason {
    Cancelled,
    Format,
    Integrity,
    Limit,
    Path,
    Unavailable,
    Io,
}

impl ArtifactReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::Format => "format",
            Self::Integrity => "integrity",
            Self::Limit => "limit",
            Self::Path => "path",
            Self::Unavailable => "unavailable",
            Self::Io => "io",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum NativeError {
    /// `AnalysisInputError` with issues.
    Input {
        operation: String,
        issues: Vec<InputIssue>,
    },
    /// `AnalysisUnsupportedTargetError`.
    UnsupportedTarget {
        operation: String,
        path: String,
        reason: String,
        remediation: Option<String>,
    },
    /// `ArtifactOperationError` without artifact details.
    Artifact {
        operation: String,
        reason: ArtifactReason,
        detail: Option<String>,
    },
    /// `AnalysisOutputError`: the input could not be decoded.
    Output { operation: String, reason: String },
    /// `AnalysisCapabilityUnavailableError`.
    Capability {
        provider_id: String,
        operation: String,
        reason: String,
        /// The reason is also the caller-facing message (`userMessage`).
        user_message: bool,
    },
    /// `BinaryTargetError` raised while resolving the active target.
    Target { path: String, reason: String },
    /// `NoBinaryOpenError`.
    NoBinaryOpen,
    /// `AnalysisResourceConstraintError`.
    Resource {
        operation: String,
        resource: String,
        reason: String,
        reported_limits: Value,
    },
    /// `AnalysisAccessDeniedError`.
    AccessDenied {
        operation: String,
        path: String,
        system_code: String,
    },
    /// `AnalysisArtifactChangedError`.
    ArtifactChanged {
        operation: String,
        path: String,
        reason: String,
    },
    /// `AnalysisTimeoutError`.
    Timeout { operation: String, timeout_ms: u64 },
    /// The request was cancelled while the analysis ran (`AnalysisCancelledError`).
    Cancelled { operation: String },
    /// Any error carrying the captured diagnostics of an owned worker.
    Captured { inner: Box<NativeError>, output: Value },
}

pub type NativeResult<T> = Result<T, NativeError>;

const UNSUPPORTED_TARGET_ACTION: &str = "Select a target supported by this operation or choose an operation supporting the reported target format.";

impl NativeError {
    pub fn artifact(operation: &str, reason: ArtifactReason, detail: impl Into<String>) -> Self {
        Self::Artifact {
            operation: operation.to_string(),
            reason,
            detail: Some(detail.into()),
        }
    }

    pub fn artifact_bare(operation: &str, reason: ArtifactReason) -> Self {
        Self::Artifact {
            operation: operation.to_string(),
            reason,
            detail: None,
        }
    }

    pub fn unsupported(operation: &str, path: &str, reason: impl Into<String>) -> Self {
        Self::UnsupportedTarget {
            operation: operation.to_string(),
            path: path.to_string(),
            reason: reason.into(),
            remediation: None,
        }
    }

    pub fn input(operation: &str, path: Vec<Value>, message: impl Into<String>) -> Self {
        Self::Input {
            operation: operation.to_string(),
            issues: vec![InputIssue::invalid(path, message)],
        }
    }

    pub fn output(operation: &str, reason: impl Into<String>) -> Self {
        Self::Output {
            operation: operation.to_string(),
            reason: reason.into(),
        }
    }

    /// REA error body (`{ "error": { ... } }`).
    pub fn to_body(&self) -> Value {
        let (code, category, message, retryable, action, details) = self.projection();
        let mut error = Map::new();
        error.insert("code".into(), json!(code));
        error.insert("category".into(), json!(category));
        error.insert("message".into(), json!(message));
        error.insert("retryable".into(), json!(retryable));
        error.insert("remediation".into(), json!({ "action": action }));
        let mut details = details;
        if let Self::Captured { output, .. } = self {
            let mut merged = match details.take() {
                Some(Value::Object(map)) => map,
                _ => Map::new(),
            };
            merged.insert("captured_output".into(), output.clone());
            details = Some(Value::Object(merged));
        }
        if let Some(details) = details {
            error.insert("details".into(), details);
        }
        json!({ "error": Value::Object(error) })
    }

    #[allow(clippy::type_complexity)]
    fn projection(&self) -> (&'static str, &'static str, String, bool, String, Option<Value>) {
        match self {
            Self::Captured { inner, .. } => inner.projection(),
            Self::ArtifactChanged {
                operation,
                path,
                reason,
            } => (
                "artifact_changed",
                "integrity_mismatch",
                "The selected artifact changed during acquisition; no stable snapshot was decoded.".to_string(),
                true,
                "Wait until the selected file is stable. For an active binary session, reopen the target with open_binary before retrying so REA acquires its current identity; for a CLI command or target-free tool, rerun the operation.".to_string(),
                Some(json!({
                    "operation": operation,
                    "path": path,
                    "reason": reason,
                    "boundary": "stable-artifact-read",
                })),
            ),
            Self::Timeout {
                operation,
                timeout_ms,
            } => {
                let message = "Analysis took too long. Try a smaller request, then run `rea doctor` if it continues.".to_string();
                (
                    "provider_timeout",
                    "timeout",
                    message.clone(),
                    true,
                    message,
                    Some(json!({"operation": operation, "timeout_ms": timeout_ms})),
                )
            }
            Self::Input { operation, issues } => {
                let details = if issues.is_empty() {
                    None
                } else {
                    Some(json!({
                        "operation": operation,
                        "issues": issues.iter().map(|issue| {
                            let mut item = Map::new();
                            item.insert("path".into(), Value::Array(issue.path.clone()));
                            item.insert("reason".into(), json!(issue.reason));
                            if let Some(message) = &issue.message {
                                item.insert("message".into(), json!(message));
                            }
                            if let Some(expected) = &issue.expected {
                                item.insert("expected".into(), expected.clone());
                            }
                            Value::Object(item)
                        }).collect::<Vec<_>>(),
                    }))
                };
                (
                    "invalid_request",
                    "invalid_input",
                    "Analysis input is invalid. Check the arguments and try again.".to_string(),
                    true,
                    "Correct the listed arguments and retry.".to_string(),
                    details,
                )
            }
            Self::UnsupportedTarget {
                operation,
                path,
                reason,
                remediation,
            } => (
                "unsupported_target",
                "unsupported_target",
                format!("Unsupported target for {operation} at {path}: {reason}"),
                false,
                remediation
                    .clone()
                    .unwrap_or_else(|| UNSUPPORTED_TARGET_ACTION.to_string()),
                Some(json!({ "operation": operation, "path": path, "reason": reason })),
            ),
            Self::Artifact {
                operation,
                reason,
                detail,
            } => {
                let (code, category) = match reason {
                    ArtifactReason::Limit => ("truncated", "truncated"),
                    ArtifactReason::Cancelled => ("cancelled", "cancelled"),
                    ArtifactReason::Integrity => ("artifact_operation_failed", "integrity_mismatch"),
                    ArtifactReason::Unavailable => ("artifact_operation_failed", "unavailable"),
                    _ => ("artifact_operation_failed", "execution_failure"),
                };
                let message = artifact_message(*reason, detail.as_deref());
                let mut details = Map::new();
                details.insert("operation".into(), json!(operation));
                details.insert("reason".into(), json!(reason.as_str()));
                if *reason == ArtifactReason::Limit {
                    details.insert("truncated".into(), json!(true));
                }
                if let Some(detail) = detail {
                    details.insert("detail".into(), json!(detail));
                }
                (
                    code,
                    category,
                    message.clone(),
                    code == "cancelled",
                    message,
                    Some(Value::Object(details)),
                )
            }
            Self::Output { operation, reason } => {
                let message = "Analysis returned an unreadable result. Retry once; if it continues, run `rea doctor`.".to_string();
                (
                    "unreadable_output",
                    "execution_failure",
                    message.clone(),
                    false,
                    message,
                    Some(json!({ "operation": operation, "reason": reason })),
                )
            }
            Self::Capability {
                provider_id,
                operation,
                reason,
                user_message,
            } => {
                let message = if *user_message {
                    reason.clone()
                } else {
                    "This analysis is unavailable for the current target. Choose another analysis or target.".to_string()
                };
                (
                    "capability_unavailable",
                    "unsupported_provider",
                    message.clone(),
                    false,
                    message,
                    Some(json!({ "provider_id": provider_id, "operation": operation, "reason": reason })),
                )
            }
            Self::Resource {
                operation,
                resource,
                reason,
                reported_limits,
            } => {
                let action = match resource.as_str() {
                    "transport" => "Export retained session evidence through export_evidence_bundle to a caller-selected path, or use complete CLI JSON output. Tools that accept retained-evidence references can inspect compatible records. The connection remains usable.",
                    "cpu" => "Review the reported worker CPU limits and observed signal. Retry with sufficient CPU time or a smaller artifact; REA retains tighter inherited limits.",
                    "file-size" => "Review the reported worker file-size limits and write failure. Retry with a sufficient file-size allowance for the evidence reply; REA retains tighter inherited limits.",
                    _ => "Review the reported worker memory limits and available host memory. Retry with sufficient memory or a smaller artifact; REA retains tighter inherited limits.",
                };
                (
                    "resource_constraint",
                    "resource_constraint",
                    reason.clone(),
                    false,
                    action.to_string(),
                    Some(json!({
                        "operation": operation,
                        "resource": resource,
                        "reason": reason,
                        "reported_limits": reported_limits,
                    })),
                )
            }
            Self::AccessDenied {
                operation,
                path,
                system_code,
            } => (
                "access_denied",
                "unavailable",
                "Host filesystem permissions denied read access to the selected path.".to_string(),
                false,
                "Check the current process's read access to the selected path. Retry with a readable local file.".to_string(),
                Some(json!({
                    "operation": operation,
                    "path": path,
                    "system_code": system_code,
                    "boundary": "filesystem-read",
                })),
            ),
            Self::Cancelled { operation } => (
                "cancelled",
                "cancelled",
                "The operation was cancelled before it finished.".to_string(),
                true,
                "Start the operation again when ready.".to_string(),
                Some(json!({ "operation": operation })),
            ),
            Self::NoBinaryOpen => {
                let message = "No app is open. Ask the user which app to investigate, then call open_binary with its local path.".to_string();
                (
                    "target_unavailable",
                    "unavailable",
                    message.clone(),
                    false,
                    message,
                    None,
                )
            }
            Self::Target { path, reason } => (
                "target_unavailable",
                "unavailable",
                format!("{reason}. Check that the path exists, is readable, and points to a supported file."),
                false,
                format!("{reason}. Check that the path exists, is readable, and points to a supported file."),
                Some(json!({ "path": path, "reason": reason })),
            ),
        }
    }
}

fn artifact_message(reason: ArtifactReason, _detail: Option<&str>) -> String {
    match reason {
        ArtifactReason::Cancelled => "Artifact operation was cancelled. Start it again when ready.",
        ArtifactReason::Limit => "Artifact is too large to process safely. Narrow the requested path or use a smaller artifact.",
        ArtifactReason::Path => "Artifact contains a conflicting internal path. Inspect the reported path before retrying.",
        ArtifactReason::Unavailable => "Artifact processing is unavailable for the current target or host. Check artifact support and required tools.",
        ArtifactReason::Format | ArtifactReason::Integrity => "Artifact is invalid or has changed. Get a fresh copy and try again.",
        ArtifactReason::Io => "Artifact could not be read or written. Check file access and try again.",
    }
    .to_string()
}

impl std::fmt::Display for NativeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_body())
    }
}

impl std::error::Error for NativeError {}

impl From<std::io::Error> for NativeError {
    fn from(error: std::io::Error) -> Self {
        NativeError::Artifact {
            operation: "native".to_string(),
            reason: ArtifactReason::Io,
            detail: Some(error.to_string()),
        }
    }
}
