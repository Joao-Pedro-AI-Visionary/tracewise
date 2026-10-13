//! Provider-neutral managed-code workflows over authenticated Evidence
//! (REA `src/application/managed` and `src/domain/managed`).
//!
//! Every workflow is a pure function from Evidence JSON to its result object.
//! Callers validate request shape and the nested inspection schemas first; a
//! violated invariant that remains here is reported as [`WorkflowError::Input`],
//! mirroring REA's `TypeError`/`ZodError` handling.

use serde_json::Value;
use tracewise_domain::canonical::canonical_sha256;
use tracewise_domain::evidence::Evidence;

pub mod compare;
pub mod reconstruction;
pub mod verify;

/// REA distinguishes input faults (`TypeError`, `ZodError`) from protocol faults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowError {
    Input(String),
    Protocol(String),
}

impl std::fmt::Display for WorkflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkflowError::Input(message) | WorkflowError::Protocol(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for WorkflowError {}

pub type WR<T> = Result<T, WorkflowError>;

pub(crate) fn input_error(message: impl Into<String>) -> WorkflowError {
    WorkflowError::Input(message.into())
}

/// SHA-256 of the RFC 8785 canonical form (REA `sha256(canonicalize(value))`).
pub fn sha256_canonical(value: &Value) -> WR<String> {
    canonical_sha256(value).map_err(|error| WorkflowError::Protocol(error.to_string()))
}

/// `parseEvidence`: strict shape plus semantic-identifier authentication.
pub fn parse_evidence(raw: &Value) -> WR<Evidence> {
    let evidence: Evidence = serde_json::from_value(raw.clone())
        .map_err(|error| input_error(format!("Evidence is not a valid record: {error}")))?;
    evidence.verify().map_err(|error| match error {
        tracewise_domain::error::EvidenceError::TamperedId { .. } => input_error(
            "A nested value failed validation at evidence_id: Evidence semantic identifier does not match its record",
        ),
        other => input_error(other.to_string()),
    })?;
    Ok(evidence)
}

/// `parseManagedInspectionEvidence`: authenticate and bind an inspection result to its subject.
pub fn parse_managed_inspection_evidence(raw: &Value, operation: &str) -> WR<(Evidence, Value)> {
    let evidence = parse_evidence(raw)?;
    if evidence.operation != operation {
        return Err(input_error(format!("Evidence operation is not {operation}")));
    }
    let result = evidence.normalized_result.clone();
    let artifact_sha = result["artifact"]["sha256"].as_str().unwrap_or_default().to_string();
    if let Some(subject) = &evidence.subject {
        if subject.digest.sha256 != artifact_sha {
            return Err(input_error(format!(
                "Managed Evidence {operation} ({}) subject SHA-256 {} does not match normalized artifact SHA-256 {artifact_sha}",
                evidence.evidence_id, subject.digest.sha256
            )));
        }
    }
    if let Some(scope) = result.get("identity_scope").filter(|v| !v.is_null()) {
        let required = scope["requires_artifact_sha256"].as_str().unwrap_or_default();
        if required != artifact_sha {
            return Err(input_error(format!(
                "Managed Evidence {operation} ({}) token scope SHA-256 {required} does not match normalized artifact SHA-256 {artifact_sha}",
                evidence.evidence_id
            )));
        }
        if let (Some(required_mvid), Some(module_mvid)) =
            (scope["requires_mvid"].as_str(), result["module"]["mvid"].as_str())
        {
            if required_mvid.to_lowercase() != module_mvid.to_lowercase() {
                return Err(input_error(format!(
                    "Managed Evidence {operation} ({}) token scope MVID {required_mvid} does not match module MVID {module_mvid}",
                    evidence.evidence_id
                )));
            }
        }
    }
    Ok((evidence, result))
}

/// `managedTokenScopesMatch`: tokens join only under one known, equal MVID.
pub fn token_scopes_match(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.to_lowercase() == right.to_lowercase(),
        _ => false,
    }
}
