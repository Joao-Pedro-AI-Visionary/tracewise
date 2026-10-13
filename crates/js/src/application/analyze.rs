//! `analyze_javascript_application` evidence construction.

use serde_json::Value;
use tracewise_domain::evidence::{
    create_evidence, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceLocation,
    EvidenceObservation, EvidenceProvider, EvidenceSubject,
};

use crate::error::JsError;
use crate::jsgraph::control::Cancel;
use crate::jsgraph::error::AnalysisFailure;

use super::reconstruct::reconstruct_javascript_application;

pub fn analyze_javascript_application(
    input_path: &str,
    format: &str,
    integrity_policy: &str,
) -> Result<Evidence, JsError> {
    analyze_javascript_application_cancellable(input_path, format, integrity_policy, &Cancel::new())
        .map_err(JsError::from)
}

/// Like [`analyze_javascript_application`], stopping at the next checkpoint once `cancel` is set.
pub fn analyze_javascript_application_cancellable(
    input_path: &str,
    format: &str,
    integrity_policy: &str,
    cancel: &Cancel,
) -> Result<Evidence, AnalysisFailure> {
    let result = reconstruct_javascript_application(input_path, format, integrity_policy, cancel)?;
    let subject = subject_for(&result)?;
    let limitations = string_array(result.get("limitations"))?;
    create_evidence(
        Some(subject),
        EvidenceProvider {
            id: "rea-javascript-application".to_string(),
            name: "REA JavaScript application analyzer".to_string(),
            version: Some("1".to_string()),
        },
        EvidenceObservation {
            predicate_type: Some("rea.javascript-application-analysis".to_string()),
            operation: "analyze_javascript_application".to_string(),
            parameters: serde_json::json!({
                "format": format,
                "integrity_policy": integrity_policy,
            }),
            normalized_result: result,
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Derived),
            authority: Some(EvidenceAuthority::ShippedArtifact),
            environment: None,
            limitations: Some(limitations),
            locations: Some(vec![EvidenceLocation::ArtifactPath {
                path: "artifact-root".to_string(),
            }]),
            evidence_links: None,
        },
    )
    .map_err(|error| AnalysisFailure::from(JsError::from(error)))
}

fn subject_for(result: &Value) -> Result<EvidenceSubject, JsError> {
    let root = result
        .get("root_artifact_sha256")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsError::InvalidInput("root_artifact_sha256 missing".into()))?;
    let format = result
        .get("format")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsError::InvalidInput("format missing".into()))?;
    let input_path = result
        .get("input_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsError::InvalidInput("input_path missing".into()))?;
    let name = std::path::Path::new(input_path)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| input_path.to_string());
    Ok(EvidenceSubject {
        name,
        digest: tracewise_domain::evidence::DigestSha256 {
            sha256: root.to_string(),
        },
        format: format.to_string(),
        architecture: None,
        local_path: input_path.to_string(),
    })
}

fn string_array(value: Option<&Value>) -> Result<Vec<String>, JsError> {
    Ok(match value.and_then(|v| v.as_array()) {
        None => Vec::new(),
        Some(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
    })
}
