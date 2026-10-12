//! Evidence envelopes for JavaScript application workflow tools.

use serde_json::Value;
use tracewise_domain::evidence::{
    create_evidence, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation,
    EvidenceProvider,
};

use crate::error::JsError;

const MISSING_SUBJECT: &str = "Artifact identity is unavailable for this observation.";

pub fn workflow_evidence(
    operation: &str,
    predicate_type: &str,
    parameters: Value,
    normalized_result: Value,
    result_limitations: Vec<String>,
    evidence_links: Vec<String>,
) -> Result<Evidence, JsError> {
    let mut limitations = vec![MISSING_SUBJECT.to_string()];
    limitations.extend(result_limitations);
    create_evidence(
        None,
        EvidenceProvider {
            id: "rea-javascript-application-workflows".to_string(),
            name: "REA JavaScript application workflows".to_string(),
            version: Some("1".to_string()),
        },
        EvidenceObservation {
            predicate_type: Some(predicate_type.to_string()),
            operation: operation.to_string(),
            parameters,
            normalized_result,
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Inferred),
            authority: Some(EvidenceAuthority::AnalystInference),
            environment: None,
            limitations: Some(limitations),
            locations: None,
            evidence_links: Some(evidence_links),
        },
    )
    .map_err(JsError::from)
}
