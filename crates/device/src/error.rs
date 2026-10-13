//! Typed analysis failures used by the adb provider and their REA projection.
//!
//! Port of the subset of REA's `analysisErrorCore.ts`, `providerAdapterError.ts`,
//! `analysisErrorProjection.ts` and `analysisErrorPresentation.ts` that the adb
//! provider can raise. The projected body is what REA returns as the text of an
//! `isError` tool result: `{ "error": { code, category, message, retryable,
//! remediation: { action }, details? } }`.

use serde_json::{json, Map, Value};

/// One rejected caller argument (`AnalysisInputIssue`).
#[derive(Debug, Clone)]
pub struct InputIssue {
    pub path: Vec<Value>,
    pub reason: &'static str,
    pub message: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ToolError {
    /// `AnalysisCancelledError`.
    Cancelled { operation: String },
    /// `AnalysisTimeoutError`.
    Timeout { operation: String, timeout_ms: u64 },
    /// `AnalysisProtocolError` (message is never exposed to the caller).
    Protocol { message: String },
    /// `AnalysisInputError` (without issues the projection carries no details).
    Input { operation: String, issues: Vec<InputIssue> },
    /// `AnalysisOutputError`.
    Output { operation: String, reason: String },
    /// `AnalysisOutputError` carrying retained command output (`capturedOutput`).
    OutputWithCapture { operation: String, reason: String, captured: Value },
    /// `AnalysisUnsupportedTargetError`.
    UnsupportedTarget { operation: String, path: String, reason: String },
    /// `AnalysisResourceConstraintError` (resource is always `memory` here).
    ResourceConstraint {
        operation: String,
        resource: &'static str,
        reason: String,
        reported_limits: Value,
    },
    /// `AnalysisCapabilityUnavailableError`; `user_message` replaces the generic text.
    CapabilityUnavailable {
        provider_id: String,
        operation: String,
        reason: String,
        user_message: Option<String>,
    },
    /// `NoBinaryOpenError`: the tool needs an active target.
    NoBinaryOpen,
    /// An error already projected elsewhere (for example by a sibling tool); kept verbatim.
    Projected { error: Value },
    /// `ProviderAdapterError` without cleanup uncertainty.
    Adapter { provider_id: String, operation: String, diagnostics: Option<Value> },
    /// `AnalysisArtifactChangedError`.
    ArtifactChanged { operation: String, path: String, reason: String },
    /// `ProviderCleanupError`: provider resources could not be proven closed.
    Cleanup {
        provider_id: String,
        operation: String,
        resources: Vec<String>,
        diagnostics: Value,
        /// Completed observation retained beside the cleanup failure.
        partial: Option<Value>,
    },
    /// `ProviderAdapterError` produced by `analysisErrorWithCleanupFailure`.
    CleanupWrapped {
        provider_id: String,
        operation: String,
        user_message: String,
        cleanup_reason: String,
        resources: Vec<String>,
        diagnostics: Value,
    },
}

/// `NoBinaryOpenError` message.
pub const NO_BINARY_OPEN: &str =
    "No app is open. Ask the user which app to investigate, then call open_binary with its local path.";

impl ToolError {
    pub fn protocol(message: impl Into<String>) -> Self {
        ToolError::Protocol { message: message.into() }
    }

    /// `Error.message` of the equivalent REA class.
    pub fn message(&self) -> String {
        match self {
            ToolError::Cancelled { operation } => format!("Analysis operation was cancelled: {operation}"),
            ToolError::Timeout { operation, timeout_ms } => {
                format!("Analysis operation timed out after {timeout_ms}ms: {operation}")
            }
            ToolError::Protocol { message } => message.clone(),
            ToolError::Input { operation, .. } => format!("Invalid analysis input for {operation}"),
            ToolError::Output { operation, reason } | ToolError::OutputWithCapture { operation, reason, .. } => {
                format!("Invalid analysis output for {operation}: {reason}")
            }
            ToolError::UnsupportedTarget { operation, path, reason } => {
                format!("Unsupported target for {operation} at {path}: {reason}")
            }
            ToolError::ResourceConstraint { operation, reason, .. } => {
                format!("Resource constraint during {operation}: {reason}")
            }
            ToolError::CapabilityUnavailable { provider_id, operation, reason, .. } => {
                format!("Provider {provider_id} cannot execute {operation}: {reason}")
            }
            ToolError::NoBinaryOpen => NO_BINARY_OPEN.to_string(),
            ToolError::Projected { error } => error["message"].as_str().unwrap_or_default().to_string(),
            ToolError::Adapter { provider_id, operation, .. } => {
                format!("Provider {provider_id} adapter failed during {operation}")
            }
            ToolError::ArtifactChanged { reason, .. } => {
                format!("Selected artifact changed during acquisition: {reason}")
            }
            ToolError::Cleanup { provider_id, operation, .. }
            | ToolError::CleanupWrapped { provider_id, operation, .. } => {
                format!("Provider {provider_id} adapter failed during {operation}")
            }
        }
    }

    fn cleanup_incomplete(&self) -> bool {
        matches!(self, ToolError::Cleanup { .. } | ToolError::CleanupWrapped { .. })
    }

    fn cleanup_resources(&self) -> Vec<String> {
        match self {
            ToolError::Cleanup { resources, .. } | ToolError::CleanupWrapped { resources, .. } => {
                resources.clone()
            }
            _ => Vec::new(),
        }
    }

    fn underlying_code(&self) -> &'static str {
        match self {
            ToolError::Protocol { .. } | ToolError::Output { .. } | ToolError::OutputWithCapture { .. } => "unreadable_output",
            ToolError::Input { .. } => "invalid_request",
            ToolError::ArtifactChanged { .. } => "artifact_changed",
            ToolError::CapabilityUnavailable { .. } => "capability_unavailable",
            ToolError::NoBinaryOpen => "target_unavailable",
            ToolError::UnsupportedTarget { .. } => "unsupported_target",
            ToolError::Cancelled { .. } => "cancelled",
            ToolError::Timeout { .. } => "provider_timeout",
            ToolError::ResourceConstraint { .. } => "resource_constraint",
            ToolError::Cleanup { .. }
            | ToolError::CleanupWrapped { .. }
            | ToolError::Adapter { .. }
            | ToolError::Projected { .. } => "execution_failure",
        }
    }

    fn category(&self) -> &'static str {
        match self {
            ToolError::Input { .. } => "invalid_input",
            ToolError::ArtifactChanged { .. } => "integrity_mismatch",
            ToolError::CapabilityUnavailable { .. } => "unsupported_provider",
            ToolError::NoBinaryOpen => "unavailable",
            ToolError::UnsupportedTarget { .. } => "unsupported_target",
            ToolError::Cancelled { .. } => "cancelled",
            ToolError::Timeout { .. } => "timeout",
            ToolError::ResourceConstraint { .. } => "resource_constraint",
            ToolError::Protocol { .. }
            | ToolError::Output { .. }
            | ToolError::OutputWithCapture { .. }
            | ToolError::Cleanup { .. }
            | ToolError::CleanupWrapped { .. }
            | ToolError::Adapter { .. }
            | ToolError::Projected { .. } => "execution_failure",
        }
    }

    /// `analysisErrorUserMessage`.
    fn user_message(&self) -> String {
        match self {
            ToolError::UnsupportedTarget { .. } => self.message(),
            ToolError::ResourceConstraint { reason, .. } => reason.clone(),
            ToolError::ArtifactChanged { .. } => {
                "The selected artifact changed during acquisition; no stable snapshot was decoded.".to_string()
            }
            ToolError::Input { .. } => "Analysis input is invalid. Check the arguments and try again.".to_string(),
            ToolError::Protocol { .. } | ToolError::Output { .. } | ToolError::OutputWithCapture { .. } => {
                "Analysis returned an unreadable result. Retry once; if it continues, run `rea doctor`.".to_string()
            }
            ToolError::CapabilityUnavailable { user_message, .. } => user_message.clone().unwrap_or_else(|| {
                "This analysis is unavailable for the current target. Choose another analysis or target.".to_string()
            }),
            ToolError::NoBinaryOpen => NO_BINARY_OPEN.to_string(),
            ToolError::Adapter { .. } | ToolError::Projected { .. } => {
                "Analysis could not complete. Retry once; if it continues, run `rea doctor`.".to_string()
            }
            ToolError::Cancelled { .. } => "Analysis was cancelled. Start it again when ready.".to_string(),
            ToolError::Timeout { .. } => {
                "Analysis took too long. Try a smaller request, then run `rea doctor` if it continues.".to_string()
            }
            ToolError::Cleanup { .. } => {
                "Provider cleanup could not be fully confirmed. Review the reported local resources before opening another target."
                    .to_string()
            }
            ToolError::CleanupWrapped { user_message, .. } => user_message.clone(),
        }
    }

    /// `analysisErrorRemediationAction`.
    fn remediation_action(&self) -> String {
        match self {
            ToolError::UnsupportedTarget { .. } => {
                "Select a target supported by this operation or choose an operation supporting the reported target format."
                    .to_string()
            }
            ToolError::ResourceConstraint { .. } => {
                "Review the reported worker memory limits and available host memory. Retry with sufficient memory or a smaller artifact; REA retains tighter inherited limits."
                    .to_string()
            }
            ToolError::ArtifactChanged { .. } => {
                "Wait until the selected file is stable. For an active binary session, reopen the target with open_binary before retrying so REA acquires its current identity; for a CLI command or target-free tool, rerun the operation."
                    .to_string()
            }
            ToolError::Input { .. } => "Correct the listed arguments and retry.".to_string(),
            other => other.user_message(),
        }
    }

    /// `errorDetails` of the primary error (before cleanup merging).
    fn primary_details(&self) -> Option<Map<String, Value>> {
        let mut map = Map::new();
        match self {
            ToolError::UnsupportedTarget { operation, path, reason } => {
                map.insert("operation".into(), json!(operation));
                map.insert("path".into(), json!(path));
                map.insert("reason".into(), json!(reason));
            }
            ToolError::ResourceConstraint { operation, resource, reason, reported_limits } => {
                map.insert("operation".into(), json!(operation));
                map.insert("resource".into(), json!(resource));
                map.insert("reason".into(), json!(reason));
                map.insert("reported_limits".into(), reported_limits.clone());
            }
            ToolError::ArtifactChanged { operation, path, reason } => {
                map.insert("operation".into(), json!(operation));
                map.insert("path".into(), json!(path));
                map.insert("reason".into(), json!(reason));
                map.insert("boundary".into(), json!("stable-artifact-read"));
            }
            ToolError::Output { operation, reason } | ToolError::OutputWithCapture { operation, reason, .. } => {
                map.insert("operation".into(), json!(operation));
                map.insert("reason".into(), json!(reason));
            }
            ToolError::Input { operation, issues } if !issues.is_empty() => {
                map.insert("operation".into(), json!(operation));
                let list: Vec<Value> = issues
                    .iter()
                    .map(|issue| {
                        let mut item = Map::new();
                        item.insert("path".into(), Value::Array(issue.path.clone()));
                        item.insert("reason".into(), json!(issue.reason));
                        if let Some(message) = &issue.message {
                            item.insert("message".into(), json!(message));
                        }
                        Value::Object(item)
                    })
                    .collect();
                map.insert("issues".into(), Value::Array(list));
            }
            ToolError::CapabilityUnavailable { provider_id, operation, reason, .. } => {
                map.insert("provider_id".into(), json!(provider_id));
                map.insert("operation".into(), json!(operation));
                map.insert("reason".into(), json!(reason));
            }
            ToolError::Adapter { provider_id, operation, diagnostics } => {
                map.insert("provider_id".into(), json!(provider_id));
                map.insert("operation".into(), json!(operation));
                if let Some(diagnostics) = diagnostics {
                    map.insert("diagnostics".into(), diagnostics.clone());
                }
            }
            ToolError::Cancelled { operation } => {
                map.insert("operation".into(), json!(operation));
                map.insert("cleanup".into(), json!("complete"));
            }
            ToolError::Timeout { operation, timeout_ms } => {
                map.insert("operation".into(), json!(operation));
                map.insert("timeout_ms".into(), json!(timeout_ms));
            }
            ToolError::Cleanup { provider_id, operation, resources, diagnostics, .. } => {
                map.insert("provider_id".into(), json!(provider_id));
                map.insert("operation".into(), json!(operation));
                map.insert("cleanup".into(), json!("incomplete"));
                map.insert("resources".into(), json!(resources));
                map.insert("diagnostics".into(), diagnostics.clone());
            }
            ToolError::CleanupWrapped { provider_id, operation, resources, diagnostics, .. } => {
                map.insert("provider_id".into(), json!(provider_id));
                map.insert("operation".into(), json!(operation));
                map.insert("cleanup".into(), json!("incomplete"));
                map.insert("resources".into(), json!(resources));
                map.insert("diagnostics".into(), diagnostics.clone());
            }
            ToolError::Input { .. } | ToolError::Protocol { .. } | ToolError::NoBinaryOpen | ToolError::Projected { .. } => return None,
        }
        Some(map)
    }

    /// `projectAnalysisError(error).message`: the caller-facing text.
    pub fn user_message_text(&self) -> String {
        match self {
            ToolError::Projected { error } => error["message"].as_str().unwrap_or_default().to_string(),
            other => other.project()["message"].as_str().unwrap_or_default().to_string(),
        }
    }

    /// `projectAnalysisError`.
    pub fn project(&self) -> Value {
        if let ToolError::Projected { error } = self {
            return error.clone();
        }
        let underlying = self.underlying_code();
        let code = if self.cleanup_incomplete() { "cleanup_incomplete" } else { underlying };
        let mut details = self.primary_details().unwrap_or_default();
        if self.cleanup_incomplete() {
            details.insert("cleanup".into(), json!("incomplete"));
            details.insert("resources".into(), json!(self.cleanup_resources()));
            if let ToolError::CleanupWrapped { cleanup_reason, .. } = self {
                details.insert("cleanup_reason".into(), json!(cleanup_reason));
            }
            let execution_failure = details
                .get("execution_failure")
                .cloned()
                .unwrap_or_else(|| json!(underlying));
            details.insert("execution_failure".into(), execution_failure);
        }
        let retryable = matches!(
            code,
            "artifact_changed"
                | "invalid_request"
                | "provider_timeout"
                | "cancelled"
                | "revision_conflict"
                | "provider_unavailable"
        );
        let mut body = Map::new();
        body.insert("code".into(), json!(code));
        body.insert("category".into(), json!(self.category()));
        body.insert("message".into(), json!(self.user_message()));
        body.insert("retryable".into(), json!(retryable));
        body.insert("remediation".into(), json!({ "action": self.remediation_action() }));
        if let ToolError::OutputWithCapture { captured, .. } = self {
            details.insert("captured_output".into(), captured.clone());
        }
        if let ToolError::Cleanup { partial: Some(partial), .. } = self {
            details.insert("partial_observation".into(), partial.clone());
        }
        if !details.is_empty() {
            body.insert("details".into(), Value::Object(details));
        }
        Value::Object(body)
    }

    /// The text body REA puts in an `isError` tool result.
    pub fn error_body(&self) -> Value {
        json!({ "error": self.project() })
    }

    /// `analysisErrorWithCleanupFailure(primary, cleanup, operation)`.
    pub fn with_cleanup_failure(primary: ToolError, cleanup: ToolError, operation: &str) -> ToolError {
        let projected_cleanup = cleanup.project();
        let provider_id = match &cleanup {
            ToolError::Cleanup { provider_id, .. } | ToolError::CleanupWrapped { provider_id, .. } => {
                provider_id.clone()
            }
            _ => "rea".to_string(),
        };
        let mut resources = primary.cleanup_resources();
        for resource in cleanup.cleanup_resources() {
            if !resources.contains(&resource) {
                resources.push(resource);
            }
        }
        let reason = projected_cleanup["message"].as_str().unwrap_or_default().to_string();
        ToolError::CleanupWrapped {
            provider_id,
            operation: operation.to_string(),
            user_message: primary.project()["message"].as_str().unwrap_or_default().to_string(),
            cleanup_reason: reason,
            resources,
            diagnostics: json!({
                "primary_error": primary.project(),
                "cleanup_error": projected_cleanup,
            }),
        }
    }
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for ToolError {}
