use crate::digest::digest_canonical_value;
use crate::types::{ArtifactEdge, ArtifactNode, ArtifactOccurrence, IntegrityContradiction};
use tracewise_domain::error::DomainError;

pub fn logical_path_nfc(value: &str) -> String {
    value.to_string()
}

pub fn artifact_id_for_content(sha256: &str) -> Result<String, DomainError> {
    let h = digest_canonical_value(&serde_json::json!({ "sha256": sha256 }))?;
    Ok(format!("art_{h}"))
}

pub fn occurrence_id_for_location(
    root_artifact_id: &str,
    logical_path: &str,
    entry_kind: &str,
) -> Result<String, DomainError> {
    let h = if logical_path == "." {
        digest_canonical_value(&serde_json::json!({ "root": root_artifact_id }))?
    } else {
        digest_canonical_value(&serde_json::json!({
            "root_artifact_id": root_artifact_id,
            "logical_path": logical_path,
            "entry_kind": entry_kind,
        }))?
    };
    Ok(format!("occ_{h}"))
}

pub fn artifact_graph_digest(
    nodes: &[ArtifactNode],
    occurrences: &[ArtifactOccurrence],
    edges: &[ArtifactEdge],
    contradictions: &[IntegrityContradiction],
) -> Result<String, DomainError> {
    digest_canonical_value(&serde_json::json!({
        "nodes": nodes,
        "occurrences": occurrences,
        "edges": edges,
        "integrity_contradictions": contradictions,
    }))
}

pub fn artifact_manifest_id(root_artifact_id: &str, graph_sha256: &str) -> Result<String, DomainError> {
    let h = digest_canonical_value(&serde_json::json!({
        "root_artifact_id": root_artifact_id,
        "graph_sha256": graph_sha256,
    }))?;
    Ok(format!("agm_{h}"))
}

pub fn artifact_contradiction_id(
    root_artifact_id: &str,
    logical_path: &str,
    declared_sha256: &str,
    observed_sha256: &str,
) -> Result<String, DomainError> {
    let h = digest_canonical_value(&serde_json::json!({
        "root_artifact_id": root_artifact_id,
        "logical_path": logical_path,
        "declared_sha256": declared_sha256,
        "observed_sha256": observed_sha256,
    }))?;
    Ok(format!("ic_{h}"))
}

pub fn artifact_edge_id(
    parent_artifact_id: &str,
    relation: &str,
    occurrence_id: &str,
    child_artifact_id: &str,
    logical_path: &str,
) -> Result<String, DomainError> {
    let h = digest_canonical_value(&serde_json::json!({
        "parent_artifact_id": parent_artifact_id,
        "child_artifact_id": child_artifact_id,
        "relation": relation,
        "occurrence_id": occurrence_id,
        "logical_path": logical_path,
    }))?;
    Ok(format!("edge_{h}"))
}

pub fn preliminary_occurrence_id(path: &str, kind: &str) -> Result<String, DomainError> {
    let h = digest_canonical_value(&serde_json::json!({ "path": path, "kind": kind }))?;
    Ok(format!("occ_{h}"))
}
