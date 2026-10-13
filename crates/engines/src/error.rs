//! Analysis errors and their secret-safe projection.
//!
//! Port of the error classes REA raises at the provider boundary
//! (`domain/analysisError*.ts`, `hopperErrors.ts`, `providerSelectionError.ts`) and of
//! `projectAnalysisError`, which turns them into the caller-visible `{ "error": ... }` body.

use serde_json::{json, Map, Value};

/// Secret-safe correction metadata for one rejected caller argument.
#[derive(Debug, Clone, PartialEq)]
pub struct InputIssue {
    pub path: Vec<Value>,
    pub reason: &'static str,
    pub message: Option<String>,
    pub expected: Option<Value>,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
}

impl InputIssue {
    pub fn invalid_value(path: Vec<Value>, message: impl Into<String>) -> Self {
        Self {
            path,
            reason: "invalid_value",
            message: Some(message.into()),
            expected: None,
            minimum: None,
            maximum: None,
        }
    }
}

/// One rejection retained while selecting a deep provider.
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderRejection {
    pub provider_id: String,
    pub code: String,
    pub reason: String,
    pub diagnostics: Value,
}

/// Hopper stage of a failure (`ProviderFailureStage`).
pub type FailureStage = &'static str;

#[derive(Debug, Clone, PartialEq)]
pub enum AnalysisError {
    NoBinaryOpen,
    Input {
        operation: String,
        issues: Vec<InputIssue>,
    },
    Output {
        operation: String,
        reason: String,
    },
    /// `AnalysisProtocolError`: a provider answered outside its protocol (the message is
    /// diagnostic only; callers see the generic unreadable-result projection).
    Protocol {
        message: String,
    },
    CapabilityUnavailable {
        provider_id: String,
        operation: String,
        reason: String,
        user_message: Option<String>,
    },
    Cancelled {
        operation: String,
    },
    Timeout {
        operation: String,
        timeout_ms: u64,
    },
    ResourceConstraint {
        operation: String,
        resource: String,
        reason: String,
        reported_limits: Option<Value>,
        remediation: Option<String>,
    },
    AccessDenied {
        operation: String,
        path: String,
        system_code: String,
    },
    ArtifactChanged {
        operation: String,
        path: String,
        reason: String,
    },
    UnsupportedTarget {
        operation: String,
        path: String,
        reason: String,
        remediation: Option<String>,
    },
    ProviderAdapter {
        provider_id: String,
        operation: String,
        diagnostics: Option<Value>,
        cleanup_incomplete: bool,
        cleanup_resources: Vec<String>,
    },
    ProviderSelection {
        operation: String,
        reason: String,
        requested_provider_id: String,
        candidate_ids: Vec<String>,
        rejections: Vec<ProviderRejection>,
    },
    Configuration {
        settings: Vec<(String, String)>,
    },
    BinaryTarget {
        path: String,
        reason: String,
        constraint: Option<String>,
        system_code: Option<String>,
    },
    HopperTimeout {
        timeout_ms: u64,
        operation: Option<String>,
        request_id: Option<u64>,
        provider_state: &'static str,
        stage: FailureStage,
        launcher: Option<Value>,
    },
    HopperCancelled,
    HopperProtocol {
        message: String,
    },
    HopperRemote {
        code: i64,
        safe_message: String,
        diagnostic_type: String,
        operation: Option<String>,
        request_id: Option<u64>,
    },
    HopperProcess {
        exit_code: Option<i64>,
        diagnostic: Option<Value>,
        operation: Option<String>,
        request_id: Option<u64>,
        provider_state: &'static str,
        stage: FailureStage,
        launcher: Option<Value>,
        failure_code: Option<String>,
        user_message: Option<String>,
    },
    HopperStart {
        user_message: Option<String>,
        owner_run_id: Option<String>,
        launcher: Option<Value>,
    },
    /// A failure that keeps the completed part of its observation as caller evidence.
    Partial {
        inner: Box<AnalysisError>,
        partial_observation: Value,
    },
}

impl std::fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.user_message())
    }
}

impl std::error::Error for AnalysisError {}

pub type AnalysisResult<T> = Result<T, AnalysisError>;

impl AnalysisError {
    pub fn input(operation: &str, path: Vec<Value>, message: impl Into<String>) -> Self {
        Self::Input {
            operation: operation.to_string(),
            issues: vec![InputIssue::invalid_value(path, message)],
        }
    }

    pub fn output(operation: &str, reason: impl Into<String>) -> Self {
        Self::Output {
            operation: operation.to_string(),
            reason: reason.into(),
        }
    }

    pub fn adapter(provider_id: &str, operation: &str) -> Self {
        Self::ProviderAdapter {
            provider_id: provider_id.to_string(),
            operation: operation.to_string(),
            diagnostics: None,
            cleanup_incomplete: false,
            cleanup_resources: Vec::new(),
        }
    }

    pub fn adapter_with(provider_id: &str, operation: &str, diagnostics: Value) -> Self {
        Self::ProviderAdapter {
            provider_id: provider_id.to_string(),
            operation: operation.to_string(),
            diagnostics: Some(diagnostics),
            cleanup_incomplete: false,
            cleanup_resources: Vec::new(),
        }
    }

    pub fn capability_unavailable(provider_id: &str, operation: &str, reason: &str) -> Self {
        Self::CapabilityUnavailable {
            provider_id: provider_id.to_string(),
            operation: operation.to_string(),
            reason: reason.to_string(),
            user_message: None,
        }
    }

    pub fn cancelled(operation: &str) -> Self {
        Self::Cancelled {
            operation: operation.to_string(),
        }
    }

    /// Stable `_tag` of the underlying REA class.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Partial { inner, .. } => inner.tag(),
            Self::NoBinaryOpen => "NoBinaryOpenError",
            Self::Input { .. } => "AnalysisInputError",
            Self::Output { .. } => "AnalysisOutputError",
            Self::Protocol { .. } => "AnalysisProtocolError",
            Self::CapabilityUnavailable { .. } => "AnalysisCapabilityUnavailableError",
            Self::Cancelled { .. } => "AnalysisCancelledError",
            Self::Timeout { .. } => "AnalysisTimeoutError",
            Self::ResourceConstraint { .. } => "AnalysisResourceConstraintError",
            Self::AccessDenied { .. } => "AnalysisAccessDeniedError",
            Self::ArtifactChanged { .. } => "AnalysisArtifactChangedError",
            Self::UnsupportedTarget { .. } => "AnalysisUnsupportedTargetError",
            Self::ProviderAdapter { .. } => "ProviderAdapterError",
            Self::ProviderSelection { .. } => "ProviderSelectionError",
            Self::Configuration { .. } => "ConfigurationError",
            Self::BinaryTarget { .. } => "BinaryTargetError",
            Self::HopperTimeout { .. } => "HopperTimeoutError",
            Self::HopperCancelled => "HopperCancelledError",
            Self::HopperProtocol { .. } => "HopperProtocolError",
            Self::HopperRemote { .. } => "HopperRemoteError",
            Self::HopperProcess { .. } => "HopperProcessError",
            Self::HopperStart { .. } => "HopperStartError",
        }
    }

    pub fn is_cancelled(&self) -> bool {
        match self {
            Self::Partial { inner, .. } => inner.is_cancelled(),
            other => matches!(other, Self::Cancelled { .. } | Self::HopperCancelled),
        }
    }

    fn cleanup_incomplete(&self) -> bool {
        match self {
            Self::Partial { inner, .. } => inner.cleanup_incomplete(),
            other => matches!(
                other,
                Self::ProviderAdapter {
                    cleanup_incomplete: true,
                    ..
                }
            ),
        }
    }

    fn underlying_code(&self) -> &'static str {
        match self {
            Self::Partial { inner, .. } => inner.underlying_code(),
            Self::HopperRemote {
                diagnostic_type, ..
            } if diagnostic_type == "invalid_request" => "invalid_request",
            Self::ProviderSelection { reason, .. } => {
                if reason == "provider_unavailable" {
                    "provider_unavailable"
                } else {
                    "capability_unavailable"
                }
            }
            Self::BinaryTarget { system_code, .. } => {
                if system_code.is_none() {
                    "target_unavailable"
                } else {
                    "access_denied"
                }
            }
            Self::Output { .. } | Self::Protocol { .. } | Self::HopperProtocol { .. } => "unreadable_output",
            Self::Input { .. } => "invalid_request",
            Self::AccessDenied { .. } => "access_denied",
            Self::ArtifactChanged { .. } => "artifact_changed",
            Self::CapabilityUnavailable { .. } => "capability_unavailable",
            Self::UnsupportedTarget { .. } => "unsupported_target",
            Self::Cancelled { .. } | Self::HopperCancelled => "cancelled",
            Self::Timeout { .. } | Self::HopperTimeout { .. } => "provider_timeout",
            Self::ResourceConstraint { .. } => "resource_constraint",
            Self::HopperProcess { .. } | Self::HopperStart { .. } => "provider_unavailable",
            Self::Configuration { .. } => "configuration_invalid",
            Self::NoBinaryOpen => "target_unavailable",
            Self::ProviderAdapter { .. } | Self::HopperRemote { .. } => "execution_failure",
        }
    }

    fn code(&self) -> &'static str {
        if self.cleanup_incomplete() {
            "cleanup_incomplete"
        } else {
            self.underlying_code()
        }
    }

    fn category(&self) -> &'static str {
        match self {
            Self::Partial { inner, .. } => inner.category(),
            Self::ProviderSelection { reason, .. } if reason == "provider_unavailable" => {
                "unavailable"
            }
            Self::HopperRemote {
                diagnostic_type, ..
            } if diagnostic_type == "invalid_request" => "invalid_input",
            Self::HopperRemote {
                diagnostic_type, ..
            } if diagnostic_type == "authorization" => "unavailable",
            Self::HopperProcess { .. } | Self::HopperStart { .. } => "unavailable",
            Self::Input { .. } => "invalid_input",
            Self::AccessDenied { .. } => "unavailable",
            Self::ArtifactChanged { .. } => "integrity_mismatch",
            Self::CapabilityUnavailable { .. } => "unsupported_provider",
            Self::UnsupportedTarget { .. } => "unsupported_target",
            Self::ProviderSelection { .. } => "unsupported_provider",
            Self::Cancelled { .. } | Self::HopperCancelled => "cancelled",
            Self::Timeout { .. } | Self::HopperTimeout { .. } => "timeout",
            Self::ResourceConstraint { .. } => "resource_constraint",
            Self::NoBinaryOpen | Self::BinaryTarget { .. } => "unavailable",
            _ => "execution_failure",
        }
    }

    /// `analysisErrorUserMessage`.
    pub fn user_message(&self) -> String {
        match self {
            Self::Partial { inner, .. } => inner.user_message(),
            Self::UnsupportedTarget {
                operation,
                path,
                reason,
                ..
            } => format!("Unsupported target for {operation} at {path}: {reason}"),
            Self::ResourceConstraint { reason, .. } => reason.clone(),
            Self::AccessDenied { .. } => {
                "Host filesystem permissions denied read access to the selected path.".to_string()
            }
            Self::ArtifactChanged { .. } => "The selected artifact changed during acquisition; no stable snapshot was decoded.".to_string(),
            Self::Input { .. } => {
                "Analysis input is invalid. Check the arguments and try again.".to_string()
            }
            Self::HopperTimeout {
                operation,
                provider_state,
                ..
            } => match operation {
                None => "REA timed out waiting for Hopper bridge readiness. Hopper may be waiting for a loader or license dialog; inspect its window and the captured launcher outcome before retrying.".to_string(),
                Some(request) => {
                    if *provider_state == "busy" {
                        format!("Hopper timed out during {request} while the provider remained busy. Check binary_session.analysis_activity, wait for the active request to finish, then retry.")
                    } else {
                        format!("Hopper timed out during {request} before it started. Check binary_session for provider health, then retry.")
                    }
                }
            },
            Self::HopperProcess { .. } => self.hopper_process_message(),
            Self::HopperStart { user_message, .. } => user_message.clone().unwrap_or_else(|| {
                "Hopper could not start. Check the launcher and target details, then retry opening the target.".to_string()
            }),
            Self::HopperRemote {
                code,
                safe_message,
                diagnostic_type,
                operation,
                ..
            } => format!(
                "Hopper {} failed ({}, {}): {}",
                operation.as_deref().unwrap_or("analysis"),
                code,
                diagnostic_type,
                safe_message
            ),
            Self::CapabilityUnavailable {
                user_message: Some(message),
                ..
            } => message.clone(),
            Self::ProviderSelection {
                reason,
                candidate_ids,
                ..
            } => match reason.as_str() {
                "ambiguous" => "Multiple analysis providers support this target. Choose one with provider_id, --provider, or REA_ANALYSIS_PROVIDER.".to_string(),
                "unknown_provider" => format!(
                    "The requested analysis provider is unknown. Choose one of: {}.",
                    if candidate_ids.is_empty() {
                        "no configured providers".to_string()
                    } else {
                        candidate_ids.join(", ")
                    }
                ),
                "provider_unavailable" => "The selected analysis provider is unavailable. Review the reported local diagnostics or run `rea doctor`, then retry.".to_string(),
                "target_unsupported" => "The selected analysis provider does not support this target. Choose another provider or open a supported extracted binary.".to_string(),
                _ => "The analysis provider selection or open options are invalid. Correct them and try again.".to_string(),
            },
            Self::Output { .. } | Self::Protocol { .. } | Self::HopperProtocol { .. } => {
                "Analysis returned an unreadable result. Retry once; if it continues, run `rea doctor`.".to_string()
            }
            Self::CapabilityUnavailable { .. } => {
                "This analysis is unavailable for the current target. Choose another analysis or target.".to_string()
            }
            Self::Cancelled { .. } | Self::HopperCancelled => {
                "Analysis was cancelled. Start it again when ready.".to_string()
            }
            Self::Timeout { .. } => {
                "Analysis took too long. Try a smaller request, then run `rea doctor` if it continues.".to_string()
            }
            Self::ProviderAdapter { .. } => {
                "Analysis could not complete. Retry once; if it continues, run `rea doctor`.".to_string()
            }
            Self::Configuration { settings } => {
                if settings.is_empty() {
                    "REA configuration is invalid. Run `rea doctor` and fix the reported setting.".to_string()
                } else {
                    let parts: Vec<String> = settings
                        .iter()
                        .map(|(setting, constraint)| {
                            if constraint.contains(setting.as_str()) {
                                constraint.trim_end_matches('.').to_string()
                            } else {
                                format!("{setting}: {constraint}")
                            }
                        })
                        .collect();
                    format!("REA configuration is invalid: {}.", parts.join("; "))
                }
            }
            Self::NoBinaryOpen => "No app is open. Ask the user which app to investigate, then call open_binary with its local path.".to_string(),
            Self::BinaryTarget {
                constraint, reason, ..
            } => {
                if constraint.as_deref() == Some("directory_requires_file") {
                    "open_binary accepts files and macOS app bundles. This target is a directory; JavaScript/Electron application directories can be analyzed directly with analyze_javascript_application or `rea analyze <directory>`.".to_string()
                } else {
                    format!("Cannot open artifact: {reason}. Check that the path exists, is readable, and points to a supported file.")
                }
            }
        }
    }

    fn hopper_process_message(&self) -> String {
        let Self::HopperProcess {
            exit_code,
            operation,
            request_id,
            provider_state,
            stage,
            failure_code,
            user_message,
            ..
        } = self
        else {
            return String::new();
        };
        let where_ = operation.clone().unwrap_or_else(|| stage.to_string());
        let request = request_id
            .map(|id| format!(" Request id {id}."))
            .unwrap_or_default();
        let startup = user_message
            .as_ref()
            .map(|m| format!(" {m}"))
            .unwrap_or_default();
        const RESTART: &str = "Restart the owned provider by calling close_binary, then open the target again and retry.";
        match *provider_state {
            "exited" => {
                let exit = match exit_code {
                    None => "no exit code was observed".to_string(),
                    Some(code) => format!("exit code {code}"),
                };
                let recovery = if failure_code.is_none() && *stage != "launch" {
                    format!(" {RESTART}")
                } else {
                    String::new()
                };
                format!("Hopper exited during {where_} ({exit}).{startup}{recovery}{request}")
            }
            "unreachable" => format!(
                "Hopper became unreachable during {where_}; its process exit was not observed. {RESTART}{startup}{request}"
            ),
            _ => format!(
                "Hopper failed during {where_} and REA could not determine whether the provider is busy, exited, or unreachable.{startup} Read binary_session.provider_operation_health for this request before retrying or restarting.{request}"
            ),
        }
    }

    /// `analysisErrorRemediationAction`.
    pub fn remediation_action(&self) -> String {
        match self {
            Self::Partial { inner, .. } => inner.remediation_action(),
            Self::UnsupportedTarget { remediation, .. } => remediation.clone().unwrap_or_else(|| "Select a target supported by this operation or choose an operation supporting the reported target format.".to_string()),
            Self::ResourceConstraint {
                resource,
                remediation,
                ..
            } => remediation.clone().unwrap_or_else(|| match resource.as_str() {
                "transport" => "Export retained session evidence through export_evidence_bundle to a caller-selected path, or use complete CLI JSON output. Tools that accept retained-evidence references can inspect compatible records. The connection remains usable.".to_string(),
                "cpu" => "Review the reported worker CPU limits and observed signal. Retry with sufficient CPU time or a smaller artifact; REA retains tighter inherited limits.".to_string(),
                "file-size" => "Review the reported worker file-size limits and write failure. Retry with a sufficient file-size allowance for the evidence reply; REA retains tighter inherited limits.".to_string(),
                _ => "Review the reported worker memory limits and available host memory. Retry with sufficient memory or a smaller artifact; REA retains tighter inherited limits.".to_string(),
            }),
            Self::HopperTimeout {
                operation,
                provider_state,
                ..
            } => match operation {
                None => "Inspect Hopper for a loader or license dialog and review details.launcher. Correct the loader configuration or complete Hopper setup, then open the target again.".to_string(),
                Some(_) => {
                    if *provider_state == "busy" {
                        "Check binary_session.analysis_activity, wait for the active Hopper request to finish, then retry.".to_string()
                    } else {
                        "Check binary_session for Hopper health, then retry the operation.".to_string()
                    }
                }
            },
            Self::HopperProcess {
                failure_code,
                user_message,
                stage,
                provider_state,
                ..
            } => {
                if failure_code.is_some() && user_message.is_some() {
                    return user_message.clone().unwrap_or_default();
                }
                if *stage == "launch" {
                    return "Review the captured launcher diagnostics and Hopper setup, then retry opening the target.".to_string();
                }
                if provider_retry_action(provider_state, false) == "restart_provider" {
                    return "Restart the owned provider by calling close_binary, then open the target again and retry.".to_string();
                }
                "Read binary_session.provider_operation_health for this request before retrying or restarting the owned provider.".to_string()
            }
            Self::HopperStart { owner_run_id, .. } => match owner_run_id {
                None => "Check the Hopper launcher and target details, then retry opening the target.".to_string(),
                Some(id) => format!("Use the active REA session {id} or close it before opening this target again."),
            },
            Self::HopperRemote {
                diagnostic_type, ..
            } => {
                if diagnostic_type == "invalid_request" {
                    "Correct the reported address, document, or arguments and retry.".to_string()
                } else {
                    "Review the Hopper diagnostic details; correct the request or retry if the failure was transient.".to_string()
                }
            }
            Self::BinaryTarget {
                constraint,
                system_code,
                ..
            } => {
                if constraint.as_deref() == Some("directory_requires_file") {
                    "For a JavaScript/Electron application directory, call analyze_javascript_application with input_path or run `rea analyze <directory>`. For binary analysis, select its executable file.".to_string()
                } else if system_code.is_some() {
                    "Check the current process's read access to the selected path. Retry with a readable local file.".to_string()
                } else {
                    self.user_message()
                }
            }
            Self::AccessDenied { .. } => "Check the current process's read access to the selected path. Retry with a readable local file.".to_string(),
            Self::ArtifactChanged { .. } => "Wait until the selected file is stable. For an active binary session, reopen the target with open_binary before retrying so REA acquires its current identity; for a CLI command or target-free tool, rerun the operation.".to_string(),
            Self::Configuration { settings } if !settings.is_empty() => {
                let mut names: Vec<&str> = Vec::new();
                for (setting, _) in settings {
                    if !names.contains(&setting.as_str()) {
                        names.push(setting);
                    }
                }
                format!("Correct {} in the environment that starts REA (your shell or the MCP client's registration), then rerun.", names.join(", "))
            }
            Self::Input { .. } => "Correct the listed arguments and retry.".to_string(),
            _ => self.user_message(),
        }
    }

    fn details(&self) -> Option<Map<String, Value>> {
        if let Self::Partial { inner, partial_observation } = self {
            let mut details = inner.details().unwrap_or_default();
            details.insert("partial_observation".into(), partial_observation.clone());
            return Some(details);
        }
        let mut details = Map::new();
        match self {
            Self::UnsupportedTarget {
                operation,
                path,
                reason,
                ..
            } => {
                details.insert("operation".into(), json!(operation));
                details.insert("path".into(), json!(path));
                details.insert("reason".into(), json!(reason));
            }
            Self::ResourceConstraint {
                operation,
                resource,
                reason,
                reported_limits,
                ..
            } => {
                details.insert("operation".into(), json!(operation));
                details.insert("resource".into(), json!(resource));
                details.insert("reason".into(), json!(reason));
                details.insert(
                    "reported_limits".into(),
                    reported_limits.clone().unwrap_or(Value::Null),
                );
            }
            Self::ArtifactChanged {
                operation,
                path,
                reason,
            } => {
                details.insert("operation".into(), json!(operation));
                details.insert("path".into(), json!(path));
                details.insert("reason".into(), json!(reason));
                details.insert("boundary".into(), json!("stable-artifact-read"));
            }
            Self::AccessDenied {
                operation,
                path,
                system_code,
            } => {
                details.insert("operation".into(), json!(operation));
                details.insert("path".into(), json!(path));
                details.insert("system_code".into(), json!(system_code));
                details.insert("boundary".into(), json!("filesystem-read"));
            }
            Self::Output { operation, reason } => {
                details.insert("operation".into(), json!(operation));
                details.insert("reason".into(), json!(reason));
            }
            Self::Input { operation, issues } if !issues.is_empty() => {
                details.insert("operation".into(), json!(operation));
                let list: Vec<Value> = issues
                    .iter()
                    .map(|issue| {
                        let mut o = Map::new();
                        o.insert("path".into(), Value::Array(issue.path.clone()));
                        o.insert("reason".into(), json!(issue.reason));
                        if let Some(m) = &issue.message {
                            o.insert("message".into(), json!(m));
                        }
                        if let Some(e) = &issue.expected {
                            o.insert("expected".into(), e.clone());
                        }
                        if let Some(m) = issue.minimum {
                            o.insert("minimum".into(), number(m));
                        }
                        if let Some(m) = issue.maximum {
                            o.insert("maximum".into(), number(m));
                        }
                        Value::Object(o)
                    })
                    .collect();
                details.insert("issues".into(), Value::Array(list));
            }
            Self::CapabilityUnavailable {
                provider_id,
                operation,
                reason,
                ..
            } => {
                details.insert("provider_id".into(), json!(provider_id));
                details.insert("operation".into(), json!(operation));
                details.insert("reason".into(), json!(reason));
            }
            Self::ProviderSelection {
                operation,
                reason,
                requested_provider_id,
                candidate_ids,
                rejections,
            } => {
                details.insert("operation".into(), json!(operation));
                details.insert("selection_reason".into(), json!(reason));
                details.insert(
                    "requested_provider_id".into(),
                    json!(requested_provider_id),
                );
                details.insert("candidate_ids".into(), json!(candidate_ids));
                let list: Vec<Value> = rejections
                    .iter()
                    .map(|r| {
                        json!({
                            "provider_id": r.provider_id,
                            "code": r.code,
                            "reason": r.reason,
                            "diagnostics": r.diagnostics,
                        })
                    })
                    .collect();
                details.insert("rejections".into(), Value::Array(list));
            }
            Self::ProviderAdapter {
                provider_id,
                operation,
                diagnostics,
                cleanup_incomplete,
                cleanup_resources,
            } => {
                details.insert("provider_id".into(), json!(provider_id));
                details.insert("operation".into(), json!(operation));
                if *cleanup_incomplete {
                    details.insert("cleanup".into(), json!("incomplete"));
                    details.insert("resources".into(), json!(cleanup_resources));
                }
                if let Some(d) = diagnostics {
                    details.insert("diagnostics".into(), d.clone());
                }
            }
            Self::HopperRemote {
                code,
                diagnostic_type,
                operation,
                request_id,
                ..
            } => {
                details.insert("stage".into(), json!("analysis"));
                details.insert("provider_code".into(), json!(code));
                details.insert("diagnostic_type".into(), json!(diagnostic_type));
                if let Some(op) = operation {
                    details.insert("operation".into(), json!(op));
                }
                if let Some(id) = request_id {
                    details.insert("request_id".into(), json!(id));
                }
            }
            Self::HopperProcess {
                exit_code,
                diagnostic,
                operation,
                request_id,
                provider_state,
                stage,
                launcher,
                failure_code,
                ..
            } => {
                details.insert("exit_code".into(), json!(exit_code));
                details.insert("stage".into(), json!(stage));
                details.insert("provider_state".into(), json!(provider_state));
                details.insert(
                    "retry_action".into(),
                    json!(provider_retry_action(
                        provider_state,
                        failure_code.is_some() || *stage == "launch"
                    )),
                );
                if let Some(code) = failure_code {
                    details.insert("failure_code".into(), json!(code));
                }
                if let Some(op) = operation {
                    details.insert("operation".into(), json!(op));
                }
                if let Some(id) = request_id {
                    details.insert("request_id".into(), json!(id));
                }
                if let Some(d) = diagnostic {
                    details.insert("diagnostics".into(), d.clone());
                }
                if let Some(l) = launcher {
                    details.insert("launcher".into(), l.clone());
                }
            }
            Self::HopperStart {
                owner_run_id,
                launcher,
                ..
            } => {
                details.insert("stage".into(), json!("launch"));
                details.insert("provider_state".into(), json!("unknown"));
                details.insert(
                    "retry_action".into(),
                    json!(if owner_run_id.is_none() {
                        "retry"
                    } else {
                        "unknown"
                    }),
                );
                if let Some(id) = owner_run_id {
                    details.insert("owner_run_id".into(), json!(id));
                }
                if let Some(l) = launcher {
                    details.insert("launcher".into(), l.clone());
                }
            }
            Self::Cancelled { operation } => {
                details.insert("operation".into(), json!(operation));
                details.insert("cleanup".into(), json!("complete"));
            }
            Self::HopperCancelled => {
                details.insert("operation".into(), json!("hopper"));
                details.insert("cleanup".into(), json!("complete"));
            }
            Self::Timeout {
                operation,
                timeout_ms,
            } => {
                details.insert("operation".into(), json!(operation));
                details.insert("timeout_ms".into(), json!(timeout_ms));
            }
            Self::HopperTimeout {
                timeout_ms,
                operation,
                request_id,
                provider_state,
                stage,
                launcher,
            } => {
                details.insert(
                    "stage".into(),
                    json!(if operation.is_none() { "startup" } else { stage }),
                );
                details.insert("timeout_ms".into(), json!(timeout_ms));
                if let Some(l) = launcher {
                    details.insert("launcher".into(), l.clone());
                }
                details.insert("provider_state".into(), json!(provider_state));
                details.insert(
                    "retry_action".into(),
                    json!(if *provider_state == "busy" {
                        "wait"
                    } else {
                        "retry"
                    }),
                );
                if let Some(op) = operation {
                    details.insert("operation".into(), json!(op));
                }
                if let Some(id) = request_id {
                    details.insert("request_id".into(), json!(id));
                }
            }
            Self::Configuration { settings } if !settings.is_empty() => {
                let list: Vec<Value> = settings
                    .iter()
                    .map(|(setting, constraint)| json!({"setting": setting, "constraint": constraint}))
                    .collect();
                details.insert("settings".into(), Value::Array(list));
            }
            Self::BinaryTarget {
                path,
                reason,
                constraint,
                system_code,
            } => {
                details.insert("path".into(), json!(path));
                details.insert("reason".into(), json!(reason));
                if let Some(c) = constraint {
                    details.insert("constraint".into(), json!(c));
                }
                if let Some(s) = system_code {
                    details.insert("system_code".into(), json!(s));
                    details.insert("boundary".into(), json!("filesystem-read"));
                }
            }
            _ => {}
        }
        if self.cleanup_incomplete() {
            details.insert("execution_failure".into(), json!("execution_failure"));
        }
        if details.is_empty() {
            None
        } else {
            Some(details)
        }
    }

    /// `projectAnalysisError`.
    pub fn project(&self) -> Value {
        let code = self.code();
        let mut out = Map::new();
        out.insert("code".into(), json!(code));
        out.insert("category".into(), json!(self.category()));
        out.insert("message".into(), json!(self.user_message()));
        out.insert(
            "retryable".into(),
            json!(matches!(
                code,
                "artifact_changed"
                    | "invalid_request"
                    | "provider_timeout"
                    | "cancelled"
                    | "revision_conflict"
                    | "provider_unavailable"
            )),
        );
        out.insert(
            "remediation".into(),
            json!({ "action": self.remediation_action() }),
        );
        if let Some(details) = self.details() {
            out.insert("details".into(), Value::Object(details));
        }
        Value::Object(out)
    }

    /// Body of an `isError` tool result.
    pub fn error_body(&self) -> Value {
        json!({ "error": self.project() })
    }
}

fn number(value: f64) -> Value {
    if value.fract() == 0.0 && value.abs() < 9.0e15 {
        json!(value as i64)
    } else {
        json!(value)
    }
}

/// `providerRetryAction` for the states a Hopper failure can establish.
pub fn provider_retry_action(state: &str, startup_failure: bool) -> &'static str {
    if startup_failure && state == "exited" {
        return "retry";
    }
    match state {
        "busy" => "wait",
        "exited" | "unreachable" => "restart_provider",
        "not_started" => "retry",
        _ => "unknown",
    }
}

impl AnalysisError {
    /// The `Error.message` REA's class carries (used where workflows embed the raw message).
    pub fn message(&self) -> String {
        match self {
            Self::Partial { inner, .. } => inner.message(),
            Self::NoBinaryOpen => "No app is open. Ask the user which app to investigate, then call open_binary with its local path.".to_string(),
            Self::Input { operation, .. } => format!("Invalid analysis input for {operation}"),
            Self::Output { operation, reason } => format!("Invalid analysis output for {operation}: {reason}"),
            Self::CapabilityUnavailable { provider_id, operation, reason, .. } => {
                format!("Provider {provider_id} cannot execute {operation}: {reason}")
            }
            Self::Cancelled { operation } => format!("Analysis operation was cancelled: {operation}"),
            Self::Timeout { operation, timeout_ms } => {
                format!("Analysis operation timed out after {timeout_ms}ms: {operation}")
            }
            Self::ResourceConstraint { operation, reason, .. } => format!("Resource constraint during {operation}: {reason}"),
            Self::AccessDenied { operation, path, system_code } => {
                format!("Host filesystem read access denied ({system_code}) for {path} during {operation}")
            }
            Self::ArtifactChanged { reason, .. } => format!("Selected artifact changed during acquisition: {reason}"),
            Self::UnsupportedTarget { operation, path, reason, .. } => {
                format!("Unsupported target for {operation} at {path}: {reason}")
            }
            Self::ProviderAdapter { provider_id, operation, .. } => {
                format!("Provider {provider_id} adapter failed during {operation}")
            }
            Self::ProviderSelection { reason, requested_provider_id, candidate_ids, .. } => format!(
                "Analysis provider selection failed ({reason}) for {requested_provider_id}; candidates: {}",
                if candidate_ids.is_empty() { "none".to_string() } else { candidate_ids.join(", ") }
            ),
            Self::Configuration { .. } => "Invalid REA environment configuration".to_string(),
            Self::BinaryTarget { reason, .. } => format!("Cannot open artifact: {reason}"),
            Self::HopperTimeout { timeout_ms, operation, .. } => format!(
                "Hopper {} timed out after {timeout_ms}ms",
                operation.as_deref().unwrap_or("startup")
            ),
            Self::HopperCancelled => "Hopper operation was cancelled".to_string(),
            Self::Protocol { message } | Self::HopperProtocol { message } => message.clone(),
            Self::HopperRemote { code, safe_message, .. } => format!("Hopper request failed ({code}): {safe_message}"),
            Self::HopperProcess { exit_code, .. } => match exit_code {
                Some(code) => format!("Hopper bridge stopped unexpectedly with code {code}"),
                None => "Hopper bridge stopped unexpectedly with code null".to_string(),
            },
            Self::HopperStart { .. } => "Hopper application bridge could not be started".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projects_a_capability_error_like_rea() {
        let error = AnalysisError::capability_unavailable("ghidra", "current_document", "operation is not declared by this provider");
        assert_eq!(
            error.error_body(),
            json!({
                "error": {
                    "code": "capability_unavailable",
                    "category": "unsupported_provider",
                    "message": "This analysis is unavailable for the current target. Choose another analysis or target.",
                    "retryable": false,
                    "remediation": { "action": "This analysis is unavailable for the current target. Choose another analysis or target." },
                    "details": {
                        "provider_id": "ghidra",
                        "operation": "current_document",
                        "reason": "operation is not declared by this provider",
                    },
                }
            })
        );
    }

    #[test]
    fn no_binary_open_is_a_target_unavailable_error() {
        let projection = AnalysisError::NoBinaryOpen.project();
        assert_eq!(projection["code"], "target_unavailable");
        assert_eq!(projection["category"], "unavailable");
        assert_eq!(projection["retryable"], false);
        assert!(projection.get("details").is_none());
    }

    #[test]
    fn partial_observations_ride_in_the_details() {
        let error = AnalysisError::Partial {
            inner: Box::new(AnalysisError::capability_unavailable("hopper", "address_to_file_offset", "no")),
            partial_observation: json!({ "address": "0x1" }),
        };
        assert_eq!(error.project()["details"]["partial_observation"], json!({ "address": "0x1" }));
        assert_eq!(error.tag(), "AnalysisCapabilityUnavailableError");
    }
}
