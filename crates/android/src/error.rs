//! REA's analysis error model, reduced to what the Android, Apktool and JEB
//! providers raise, with the secret-safe projection REA returns to callers
//! (`projectAnalysisError`).

use serde_json::{json, Map, Value};

#[derive(Debug, Clone)]
pub struct InputIssue {
    pub path: Vec<String>,
    pub reason: &'static str,
    pub message: String,
}

/// An expected failure of one analysis operation.
#[derive(Debug, Clone)]
pub enum Failure {
    /// `AnalysisInputError`.
    Input { operation: String, issues: Vec<InputIssue> },
    /// `AnalysisCapabilityUnavailableError`.
    CapabilityUnavailable {
        provider_id: String,
        operation: String,
        reason: String,
        user_message: Option<String>,
        captured_output: Option<Value>,
    },
    /// `AnalysisOutputError`.
    Output { operation: String, reason: String },
    /// `AnalysisProtocolError`.
    Protocol { message: String },
    /// `ProviderAdapterError`.
    Adapter { provider_id: String, operation: String, diagnostics: Option<Value> },
    /// `AnalysisTimeoutError`.
    Timeout { operation: String, timeout_ms: u64, captured_output: Option<Value> },
    /// `AnalysisCancelledError`.
    Cancelled { operation: String },
    /// `AnalysisUnsupportedTargetError`.
    UnsupportedTarget { operation: String, path: String, reason: String, captured_output: Option<Value> },
    /// `AnalysisResourceConstraintError`.
    ResourceConstraint { operation: String, resource: String, reason: String, limits: Value, captured_output: Option<Value> },
}

/// A failure plus the provider facts collected before it (`partialObservation`).
#[derive(Debug, Clone)]
pub struct Error {
    pub failure: Failure,
    pub partial_observation: Option<Value>,
}

impl From<Failure> for Error {
    fn from(failure: Failure) -> Self {
        Error { failure, partial_observation: None }
    }
}

pub type Outcome<T> = Result<T, Error>;

impl Failure {
    pub fn input(operation: &str, field: &str, message: impl Into<String>) -> Failure {
        Failure::Input {
            operation: operation.to_string(),
            issues: vec![InputIssue { path: vec![field.to_string()], reason: "invalid_value", message: message.into() }],
        }
    }

    pub fn output(operation: &str, reason: impl Into<String>) -> Failure {
        Failure::Output { operation: operation.to_string(), reason: reason.into() }
    }

    pub fn capability(provider: &str, operation: &str, reason: impl Into<String>) -> Failure {
        Failure::CapabilityUnavailable {
            provider_id: provider.to_string(),
            operation: operation.to_string(),
            reason: reason.into(),
            user_message: None,
            captured_output: None,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Failure::Input { .. } => "invalid_request",
            Failure::CapabilityUnavailable { .. } => "capability_unavailable",
            Failure::Output { .. } | Failure::Protocol { .. } => "unreadable_output",
            Failure::Adapter { .. } => "execution_failure",
            Failure::Timeout { .. } => "provider_timeout",
            Failure::Cancelled { .. } => "cancelled",
            Failure::UnsupportedTarget { .. } => "unsupported_target",
            Failure::ResourceConstraint { .. } => "resource_constraint",
        }
    }

    fn category(&self) -> &'static str {
        match self {
            Failure::Input { .. } => "invalid_input",
            Failure::CapabilityUnavailable { .. } => "unsupported_provider",
            Failure::Output { .. } | Failure::Protocol { .. } | Failure::Adapter { .. } => "execution_failure",
            Failure::Timeout { .. } => "timeout",
            Failure::Cancelled { .. } => "cancelled",
            Failure::UnsupportedTarget { .. } => "unsupported_target",
            Failure::ResourceConstraint { .. } => "resource_constraint",
        }
    }

    fn retryable(&self) -> bool {
        matches!(self.code(), "invalid_request" | "provider_timeout" | "cancelled" | "artifact_changed" | "revision_conflict" | "provider_unavailable")
    }

    fn message(&self) -> String {
        match self {
            Failure::Input { .. } => "Analysis input is invalid. Check the arguments and try again.".to_string(),
            Failure::CapabilityUnavailable { user_message, .. } => user_message
                .clone()
                .unwrap_or_else(|| "This analysis is unavailable for the current target. Choose another analysis or target.".to_string()),
            Failure::Output { .. } | Failure::Protocol { .. } => {
                "Analysis returned an unreadable result. Retry once; if it continues, run `rea doctor`.".to_string()
            }
            Failure::Adapter { .. } => "Analysis could not complete. Retry once; if it continues, run `rea doctor`.".to_string(),
            Failure::Timeout { .. } => {
                "Analysis took too long. Try a smaller request, then run `rea doctor` if it continues.".to_string()
            }
            Failure::Cancelled { .. } => "Analysis was cancelled. Start it again when ready.".to_string(),
            Failure::UnsupportedTarget { operation, path, reason, .. } => {
                format!("Unsupported target for {operation} at {path}: {reason}")
            }
            Failure::ResourceConstraint { reason, .. } => reason.clone(),
        }
    }

    fn remediation(&self) -> String {
        match self {
            Failure::Input { .. } => "Correct the listed arguments and retry.".to_string(),
            Failure::UnsupportedTarget { .. } => {
                "Select a target supported by this operation or choose an operation supporting the reported target format."
                    .to_string()
            }
            Failure::ResourceConstraint { resource, .. } => match resource.as_str() {
                "transport" => "Export retained session evidence through export_evidence_bundle to a caller-selected path, or use complete CLI JSON output. Tools that accept retained-evidence references can inspect compatible records. The connection remains usable.".to_string(),
                "cpu" => "Review the reported worker CPU limits and observed signal. Retry with sufficient CPU time or a smaller artifact; REA retains tighter inherited limits.".to_string(),
                "file-size" => "Review the reported worker file-size limits and write failure. Retry with a sufficient file-size allowance for the evidence reply; REA retains tighter inherited limits.".to_string(),
                _ => "Review the reported worker memory limits and available host memory. Retry with sufficient memory or a smaller artifact; REA retains tighter inherited limits.".to_string(),
            },
            other => other.message(),
        }
    }

    fn details(&self) -> Option<Map<String, Value>> {
        let mut map = Map::new();
        match self {
            Failure::Input { operation, issues } if !issues.is_empty() => {
                map.insert("operation".into(), json!(operation));
                map.insert(
                    "issues".into(),
                    Value::Array(
                        issues
                            .iter()
                            .map(|i| json!({ "path": i.path, "reason": i.reason, "message": i.message }))
                            .collect(),
                    ),
                );
            }
            Failure::Output { operation, reason } => {
                map.insert("operation".into(), json!(operation));
                map.insert("reason".into(), json!(reason));
            }
            Failure::CapabilityUnavailable { provider_id, operation, reason, .. } => {
                map.insert("provider_id".into(), json!(provider_id));
                map.insert("operation".into(), json!(operation));
                map.insert("reason".into(), json!(reason));
            }
            Failure::Adapter { provider_id, operation, diagnostics } => {
                map.insert("provider_id".into(), json!(provider_id));
                map.insert("operation".into(), json!(operation));
                if let Some(diagnostics) = diagnostics {
                    map.insert("diagnostics".into(), diagnostics.clone());
                }
            }
            Failure::Timeout { operation, timeout_ms, .. } => {
                map.insert("operation".into(), json!(operation));
                map.insert("timeout_ms".into(), json!(timeout_ms));
            }
            Failure::Cancelled { operation } => {
                map.insert("operation".into(), json!(operation));
                map.insert("cleanup".into(), json!("complete"));
            }
            Failure::UnsupportedTarget { operation, path, reason, .. } => {
                map.insert("operation".into(), json!(operation));
                map.insert("path".into(), json!(path));
                map.insert("reason".into(), json!(reason));
            }
            Failure::ResourceConstraint { operation, resource, reason, limits, .. } => {
                map.insert("operation".into(), json!(operation));
                map.insert("resource".into(), json!(resource));
                map.insert("reason".into(), json!(reason));
                map.insert("reported_limits".into(), limits.clone());
            }
            _ => {}
        }
        let captured = match self {
            Failure::CapabilityUnavailable { captured_output, .. }
            | Failure::Timeout { captured_output, .. }
            | Failure::UnsupportedTarget { captured_output, .. }
            | Failure::ResourceConstraint { captured_output, .. } => captured_output.clone(),
            _ => None,
        };
        if let Some(captured) = captured {
            map.insert("captured_output".into(), captured);
        }
        if map.is_empty() {
            None
        } else {
            Some(map)
        }
    }
}

impl Error {
    /// The `{ "error": ... }` document REA serializes into a tool error result.
    pub fn to_envelope(&self) -> Value {
        let mut details = self.failure.details().unwrap_or_default();
        if let Some(partial) = &self.partial_observation {
            details.insert("partial_observation".into(), partial.clone());
        }
        let mut error = Map::new();
        error.insert("code".into(), json!(self.failure.code()));
        error.insert("category".into(), json!(self.failure.category()));
        error.insert("message".into(), json!(self.failure.message()));
        error.insert("retryable".into(), json!(self.failure.retryable()));
        error.insert("remediation".into(), json!({ "action": self.failure.remediation() }));
        if !details.is_empty() {
            error.insert("details".into(), Value::Object(details));
        }
        json!({ "error": Value::Object(error) })
    }
}
