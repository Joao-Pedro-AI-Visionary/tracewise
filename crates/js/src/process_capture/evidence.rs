//! Port of REA `application/process/ProcessEvidence.ts` and
//! `server/registerProcessComparisonTool.ts` (Evidence envelopes).

use std::path::Path;

use serde_json::{json, Value};
use tracewise_domain::evidence::{
    create_evidence, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation, EvidenceProvider,
    ExecutionEnvironment, IsolationLevel,
};

use super::capture::{run_capture, CaptureFailure};
use super::compare::{compare_process_captures, CompareOptions};
use super::scenario::parse_process_scenario;
use super::trace::parse_trace_specification;
use super::validation::collect_capture_issues;
use crate::error::JsError;

const MISSING_SUBJECT: &str = "Artifact identity is unavailable for this observation.";

/// Canonical provider identity for controlled process capture Evidence.
pub(crate) fn process_provider() -> EvidenceProvider {
    EvidenceProvider { id: "rea-process".to_string(), name: "REA process capture".to_string(), version: Some("3".to_string()) }
}

/// Outcome of `capture_process_scenario`.
#[derive(Debug)]
pub enum CaptureError {
    /// Boundary validation failure (protocol-level invalid params).
    Invalid(String),
    /// Execution or cleanup failure (an `isError` tool result).
    Failed(CaptureFailure),
}

impl CaptureError {
    /// REA error envelope for failed captures.
    pub fn body(&self) -> Value {
        match self {
            Self::Invalid(message) => json!({ "error": { "code": "invalid_input", "message": message } }),
            Self::Failed(failure) => {
                let mut details = json!({ "execution_failure": failure.message });
                if failure.cleanup_incomplete {
                    details["cleanup_incomplete"] = json!(true);
                }
                json!({
                    "error": {
                        "code": "process_capture_failed",
                        "category": "execution_failure",
                        "message": failure.message,
                        "retryable": false,
                        "remediation": { "action": failure.message },
                        "details": details,
                    }
                })
            }
        }
    }
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(m) => f.write_str(m),
            Self::Failed(failure) => f.write_str(&failure.message),
        }
    }
}

/// Run one caller-selected command under a PTY and return capture Evidence.
pub fn capture_process_scenario(args: &Value) -> Result<Evidence, CaptureError> {
    if std::env::consts::OS == "windows" {
        return Err(CaptureError::Failed(CaptureFailure {
            message: "Windows PTY process capture is unavailable because this adapter does not yet verify descendant cleanup. Use Linux (including WSL for Linux commands) or macOS. Reinstalling the PTY backend does not enable native Windows capture.".into(),
            cleanup_incomplete: false,
        }));
    }
    let scenario = parse_process_scenario(args).map_err(|e| CaptureError::Invalid(e.to_string()))?;
    let capture = run_capture(&scenario).map_err(CaptureError::Failed)?;
    let issues = collect_capture_issues(&capture);
    if !issues.is_empty() {
        return Err(CaptureError::Failed(CaptureFailure {
            message: format!("process capture validation failed: Invalid process capture: {}", issues.join("; ")),
            cleanup_incomplete: false,
        }));
    }
    let platform = capture["manifest"]["platform"].as_str().unwrap_or_default().to_string();
    let architecture = capture["manifest"]["architecture"].as_str().unwrap_or_default().to_string();
    let executable_name = Path::new(&scenario.executable)
        .file_name()
        .map_or_else(|| scenario.executable.clone(), |n| n.to_string_lossy().into_owned());
    let parameters = json!({
        "executable_name": executable_name,
        "argument_count": scenario.arguments.len(),
        "event_count": scenario.events.len(),
        "filesystem_observation_path_count": scenario.filesystem_observation_paths.len(),
        "normalization": scenario.normalization.to_value(),
    });
    let mut limitations = vec![MISSING_SUBJECT.to_string()];
    limitations.extend(capture["limitations"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_string)));
    create_evidence(
        None,
        process_provider(),
        EvidenceObservation {
            predicate_type: Some("rea.process-capture".to_string()),
            operation: "capture_process_scenario".to_string(),
            parameters,
            normalized_result: capture,
            raw_result: None,
            confidence: Some(EvidenceConfidence::Observed),
            authority: Some(EvidenceAuthority::ControlledReplay),
            environment: Some(ExecutionEnvironment {
                id: format!("{platform}-{architecture}"),
                platform,
                architecture,
                isolation: IsolationLevel::Process,
            }),
            limitations: Some(limitations),
            locations: None,
            evidence_links: None,
            analysis_profile: None,
        },
    )
    .map_err(|e| CaptureError::Failed(CaptureFailure { message: e.to_string(), cleanup_incomplete: false }))
}

/// Parse one side and name the failed constraint.
fn parse_capture_side<'a>(side: &str, evidence: &'a Evidence) -> Result<&'a Value, JsError> {
    evidence.verify().map_err(|e| {
        JsError::Integrity(format!(
            "The {side} Evidence failed validation ({e}). Supply unmodified capture Evidence from capture_process_scenario."
        ))
    })?;
    if evidence.operation != "capture_process_scenario" || evidence.predicate_type != "rea.process-capture" {
        return Err(JsError::InvalidInput(format!(
            "{side}: Expected process capture Evidence (operation capture_process_scenario, predicate rea.process-capture); the {side} Evidence has operation {} and predicate {}.",
            evidence.operation, evidence.predicate_type
        )));
    }
    let issues = collect_capture_issues(&evidence.normalized_result);
    if !issues.is_empty() {
        return Err(JsError::Integrity(format!(
            "The {side} Evidence has an invalid process capture result (Invalid process capture: {}). Recreate the capture with capture_process_scenario.",
            issues.join("; ")
        )));
    }
    Ok(&evidence.normalized_result)
}

/// `compare_process_captures`: derived comparison Evidence.
pub fn compare_process_captures_tool(left: &Evidence, right: &Evidence, args: &Value) -> Result<Evidence, JsError> {
    let left_capture = parse_capture_side("left", left)?;
    let right_capture = parse_capture_side("right", right)?;
    let trace_spec = match args.get("trace_spec") {
        None => None,
        Some(value) => Some(parse_trace_specification(value)?),
    };
    let max_capture_age_ms = match args.get("max_capture_age_ms") {
        None => None,
        Some(v) => Some(v.as_u64().ok_or_else(|| JsError::InvalidInput("max_capture_age_ms: expected a nonnegative integer".into()))?),
    };
    let options = CompareOptions { max_capture_age_ms, trace_spec, now_ms: None };
    let comparison = compare_process_captures(left_capture, right_capture, &options)?;
    let mut parameters = json!({
        "left_evidence_id": left.evidence_id,
        "right_evidence_id": right.evidence_id,
        "left_normalization": left_capture["normalization"],
        "right_normalization": right_capture["normalization"],
    });
    if let Some(spec) = &options.trace_spec {
        parameters["trace_spec"] = spec.raw.clone();
    }
    let mut limitations = vec![MISSING_SUBJECT.to_string()];
    limitations.extend(comparison["limitations"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_string)));
    let mut locations = left.locations.clone();
    locations.extend(right.locations.iter().cloned());
    Ok(create_evidence(
        None,
        process_provider(),
        EvidenceObservation {
            predicate_type: Some("rea.process-comparison".to_string()),
            operation: "compare_process_captures".to_string(),
            parameters,
            normalized_result: comparison,
            raw_result: None,
            confidence: Some(EvidenceConfidence::Derived),
            authority: Some(EvidenceAuthority::AnalystInference),
            environment: None,
            limitations: Some(limitations),
            locations: Some(locations),
            evidence_links: Some(vec![left.evidence_id.clone(), right.evidence_id.clone()]),
            analysis_profile: None,
        },
    )?)
}
