use crate::comparison::compare_artifacts;
use crate::error::JsError;
use crate::extraction::extract_artifact;
use crate::inspection::create_artifact_inspection;
use crate::inventory::scan_artifact_inventory;
use crate::types::{artifact_comparison_provider, artifact_graph_provider};
use std::path::Path;
use tracewise_domain::evidence::{
    create_evidence, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation,
    EvidenceSubject,
};

pub fn inspect_artifact(path: &str, integrity_policy: &str) -> Result<Vec<Evidence>, JsError> {
    let _ = integrity_policy;
    let p = Path::new(path);
    let inventory = scan_artifact_inventory(p)?;
    let subject = subject_for(path, &inventory.manifest);
    let inventory_ev = create_evidence(
        Some(subject.clone()),
        artifact_graph_provider(),
        EvidenceObservation {
            predicate_type: None,
            operation: "inventory_artifact".to_string(),
            parameters: serde_json::json!({ "integrity_policy": integrity_policy }),
            normalized_result: serde_json::to_value(&inventory)?,
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Observed),
            authority: Some(EvidenceAuthority::ShippedArtifact),
            environment: None,
            limitations: Some(inventory.limitations.clone()),
            locations: None,
            evidence_links: None,
        },
    )?;
    let inspection = create_artifact_inspection(&inventory_ev)?;
    let inspection_limits = inspection["limitations"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let inspect_ev = create_evidence(
        Some(subject),
        artifact_graph_provider(),
        EvidenceObservation {
            predicate_type: None,
            operation: "inspect_artifact".to_string(),
            parameters: serde_json::json!({ "integrity_policy": integrity_policy }),
            normalized_result: inspection,
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Observed),
            authority: Some(EvidenceAuthority::ShippedArtifact),
            environment: None,
            limitations: Some(inspection_limits),
            locations: None,
            evidence_links: Some(vec![inventory_ev.evidence_id.clone()]),
        },
    )?;
    Ok(vec![inventory_ev, inspect_ev])
}

pub fn extract_artifact_tool(path: &str, integrity_policy: &str) -> Result<Evidence, JsError> {
    let result = extract_artifact(Path::new(path), integrity_policy)?;
    let subject = subject_for(path, &result.manifest);
    create_evidence(
        Some(subject),
        artifact_graph_provider(),
        EvidenceObservation {
            predicate_type: None,
            operation: "extract_artifact".to_string(),
            parameters: serde_json::json!({ "integrity_policy": integrity_policy }),
            normalized_result: serde_json::to_value(&result)?,
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Observed),
            authority: Some(EvidenceAuthority::ShippedArtifact),
            environment: None,
            limitations: Some(result.limitations.clone()),
            locations: None,
            evidence_links: None,
        },
    )
    .map_err(JsError::from)
}

pub fn compare_artifacts_tool(left: &Evidence, right: &Evidence) -> Result<Evidence, JsError> {
    let comparison = compare_artifacts(left, right)?;
    let limitations = comparison["limitations"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    create_evidence(
        None,
        artifact_comparison_provider(),
        EvidenceObservation {
            predicate_type: Some("rea.artifact-comparison".to_string()),
            operation: "compare_artifacts".to_string(),
            parameters: serde_json::json!({
                "left_evidence_ids": [left.evidence_id.clone()],
                "right_evidence_ids": [right.evidence_id.clone()],
            }),
            normalized_result: comparison,
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Derived),
            authority: Some(EvidenceAuthority::AnalystInference),
            environment: None,
            limitations: Some(limitations),
            locations: None,
            evidence_links: Some(vec![left.evidence_id.clone(), right.evidence_id.clone()]),
        },
    )
    .map_err(JsError::from)
}

fn subject_for(path: &str, manifest: &crate::types::ArtifactGraphManifest) -> EvidenceSubject {
    let name = Path::new(path)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string());
    EvidenceSubject {
        name,
        digest: tracewise_domain::evidence::DigestSha256 {
            sha256: manifest.root_sha256.clone(),
        },
        format: manifest.root_format.clone(),
        architecture: None,
        local_path: path.to_string(),
    }
}
