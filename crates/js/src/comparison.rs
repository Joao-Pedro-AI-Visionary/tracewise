use crate::types::{ArtifactInventoryResult, ZIP_NON_ENTRY_TAIL_LIMITATION};
use crate::unicode::compare_unicode_code_points;
use serde_json::{json, Map, Value};
use tracewise_domain::canonical::canonical_json;
use tracewise_domain::evidence::Evidence;
use tracewise_domain::error::DomainError;

pub fn compare_artifacts(left: &Evidence, right: &Evidence) -> Result<Value, DomainError> {
    let left_inv = parse_inventory(left)?;
    let right_inv = parse_inventory(right)?;
    let left_covered = !has_coverage_limitation(&left_inv.limitations);
    let right_covered = !has_coverage_limitation(&right_inv.limitations);
    let mut limitations: Vec<String> = left_inv
        .limitations
        .iter()
        .map(|s| format!("Left: {}", s))
        .chain(right_inv.limitations.iter().map(|s| format!("Right: {}", s)))
        .collect();
    let evidence_links = vec![left.evidence_id.clone(), right.evidence_id.clone()];
    let mut changes = compare_occurrences(
        &left_inv,
        &right_inv,
        &evidence_links,
        left_covered && right_covered,
    );
    if let Some(root) = root_hash_change(&left_inv, &right_inv, &changes, &evidence_links) {
        changes.push(root);
    }
    let summary = summarize(&left_inv, &changes, left_covered && right_covered);
    let status = if changes.iter().any(|c| c["classification"] == "contradiction") {
        "contradiction"
    } else if !left_covered || !right_covered {
        "unknown"
    } else if changes.iter().any(|c| c["classification"] == "unknown") {
        "unknown"
    } else if changes.is_empty() {
        "unchanged"
    } else {
        "changed"
    };
    limitations.sort_by(|a, b| compare_unicode_code_points(a, b));
    limitations.dedup();
    Ok(json!({
        "status": status,
        "left_manifest_id": left_inv.manifest.manifest_id,
        "right_manifest_id": right_inv.manifest.manifest_id,
        "summary": summary,
        "changes": changes,
        "limitations": limitations,
    }))
}

fn parse_inventory(evidence: &Evidence) -> Result<ArtifactInventoryResult, DomainError> {
    if evidence.operation == "inventory_artifact" {
        return serde_json::from_value(evidence.normalized_result.clone())
            .map_err(|e| DomainError::Canonicalization(e.to_string()));
    }
    if evidence.operation == "inspect_artifact" {
        let nested = evidence.normalized_result["substeps"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|s| s.get("evidence"))
            .ok_or_else(|| DomainError::Canonicalization("missing inventory substep".to_string()))?;
        let inv_ev: Evidence = serde_json::from_value(nested.clone())
            .map_err(|e| DomainError::Canonicalization(e.to_string()))?;
        return serde_json::from_value(inv_ev.normalized_result.clone())
            .map_err(|e| DomainError::Canonicalization(e.to_string()));
    }
    Err(DomainError::Canonicalization(
        "Artifact comparison requires inspect_artifact Evidence".to_string(),
    ))
}

fn has_coverage_limitation(limitations: &[String]) -> bool {
    limitations.iter().any(|l| {
        l != ZIP_NON_ENTRY_TAIL_LIMITATION && !l.contains("integrity contradiction(s) were recorded")
    })
}

fn change_base(
    path: &str,
    left_occ: Option<&crate::types::ArtifactOccurrence>,
    right_occ: Option<&crate::types::ArtifactOccurrence>,
    evidence_links: &[String],
) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("logical_path".to_string(), Value::String(path.to_string()));
    m.insert(
        "left_occurrence_id".to_string(),
        left_occ
            .map(|o| Value::String(o.occurrence_id.clone()))
            .unwrap_or(Value::Null),
    );
    m.insert(
        "right_occurrence_id".to_string(),
        right_occ
            .map(|o| Value::String(o.occurrence_id.clone()))
            .unwrap_or(Value::Null),
    );
    m.insert(
        "left_artifact_id".to_string(),
        left_occ
            .and_then(|o| o.artifact_id.clone())
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    m.insert(
        "right_artifact_id".to_string(),
        right_occ
            .and_then(|o| o.artifact_id.clone())
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    m.insert(
        "evidence_links".to_string(),
        Value::Array(evidence_links.iter().cloned().map(Value::String).collect()),
    );
    m
}

fn compare_occurrences(
    left: &ArtifactInventoryResult,
    right: &ArtifactInventoryResult,
    evidence_links: &[String],
    complete: bool,
) -> Vec<Value> {
    let left_by: std::collections::HashMap<_, _> = left
        .occurrences
        .iter()
        .map(|o| (o.logical_path.clone(), o))
        .collect();
    let right_by: std::collections::HashMap<_, _> = right
        .occurrences
        .iter()
        .map(|o| (o.logical_path.clone(), o))
        .collect();
    let left_nodes: std::collections::HashMap<_, _> = left
        .nodes
        .iter()
        .map(|n| (n.artifact_id.clone(), n.clone()))
        .collect();
    let right_nodes: std::collections::HashMap<_, _> = right
        .nodes
        .iter()
        .map(|n| (n.artifact_id.clone(), n.clone()))
        .collect();
    let mut paths: Vec<String> = left_by
        .keys()
        .chain(right_by.keys())
        .cloned()
        .collect();
    paths.sort_by(|a, b| compare_unicode_code_points(a, b));
    paths.dedup();
    let mut out = Vec::new();
    for path in paths {
        if let Some(change) = classify_path(
            &path,
            left_by.get(&path).copied(),
            right_by.get(&path).copied(),
            &left_nodes,
            &right_nodes,
            complete,
            evidence_links,
        ) {
            out.push(change);
        }
    }
    out
}

fn classify_path(
    path: &str,
    left_occ: Option<&crate::types::ArtifactOccurrence>,
    right_occ: Option<&crate::types::ArtifactOccurrence>,
    left_nodes: &std::collections::HashMap<String, crate::types::ArtifactNode>,
    right_nodes: &std::collections::HashMap<String, crate::types::ArtifactNode>,
    complete: bool,
    evidence_links: &[String],
) -> Option<Value> {
    let mut obj = change_base(path, left_occ, right_occ, evidence_links);
    if left_occ.is_none() {
        obj.insert(
            "classification".to_string(),
            Value::String(if complete { "added" } else { "unknown" }.to_string()),
        );
        obj.insert(
            "dimensions".to_string(),
            Value::Array(vec![Value::String(
                if complete { "content" } else { "availability" }.to_string(),
            )]),
        );
        return Some(Value::Object(obj));
    }
    if right_occ.is_none() {
        obj.insert(
            "classification".to_string(),
            Value::String(if complete { "removed" } else { "unknown" }.to_string()),
        );
        obj.insert(
            "dimensions".to_string(),
            Value::Array(vec![Value::String(
                if complete { "content" } else { "availability" }.to_string(),
            )]),
        );
        return Some(Value::Object(obj));
    }
    let lo = left_occ.unwrap();
    let ro = right_occ.unwrap();
    if lo.hash_status == "mismatched" || ro.hash_status == "mismatched" {
        obj.insert("classification".to_string(), Value::String("contradiction".to_string()));
        obj.insert(
            "dimensions".to_string(),
            Value::Array(vec![Value::String("integrity".to_string())]),
        );
        return Some(Value::Object(obj));
    }
    let ln = lo.artifact_id.as_ref().and_then(|id| left_nodes.get(id));
    let rn = ro.artifact_id.as_ref().and_then(|id| right_nodes.get(id));
    if lo.hash_status != "verified"
        || ro.hash_status != "verified"
        || ln.is_none()
        || rn.is_none()
    {
        obj.insert("classification".to_string(), Value::String("unknown".to_string()));
        obj.insert(
            "dimensions".to_string(),
            Value::Array(vec![Value::String("availability".to_string())]),
        );
        return Some(Value::Object(obj));
    }
    let ln = ln.unwrap();
    let rn = rn.unwrap();
    let mut dimensions = Vec::new();
    if ln.sha256 != rn.sha256 {
        dimensions.push("content");
    }
    if lo.artifact_kind != ro.artifact_kind {
        dimensions.push("kind");
    }
    if ln.format != rn.format || lo.artifact_format != ro.artifact_format {
        dimensions.push("format");
    }
    if ln.size != rn.size {
        dimensions.push("size");
    }
    if lo.executable != ro.executable {
        dimensions.push("executable");
    }
    if metadata_changed(lo, ro, ln, rn) {
        dimensions.push("metadata");
    }
    if dimensions.is_empty() {
        return None;
    }
    obj.insert("classification".to_string(), Value::String("changed".to_string()));
    obj.insert(
        "dimensions".to_string(),
        Value::Array(
            dimensions
                .into_iter()
                .map(|d| Value::String(d.to_string()))
                .collect(),
        ),
    );
    Some(Value::Object(obj))
}

fn metadata_changed(
    lo: &crate::types::ArtifactOccurrence,
    ro: &crate::types::ArtifactOccurrence,
    ln: &crate::types::ArtifactNode,
    rn: &crate::types::ArtifactNode,
) -> bool {
    ln.media_type != rn.media_type
        || ln.architecture != rn.architecture
        || ln.content_state != rn.content_state
        || lo.entry_kind != ro.entry_kind
        || lo.encrypted != ro.encrypted
        || canonical_json(&ln.limitations).ok() != canonical_json(&rn.limitations).ok()
        || canonical_json(&lo.limitations).ok() != canonical_json(&ro.limitations).ok()
}

fn summarize(
    left: &ArtifactInventoryResult,
    changes: &[Value],
    covered: bool,
) -> Value {
    let mut added = 0;
    let mut removed = 0;
    let mut changed = 0;
    let mut unknown = 0;
    let mut contradiction = 0;
    for c in changes {
        match c["classification"].as_str() {
            Some("added") => added += 1,
            Some("removed") => removed += 1,
            Some("changed") => changed += 1,
            Some("unknown") => unknown += 1,
            Some("contradiction") => contradiction += 1,
            _ => {}
        }
    }
    let unchanged = if covered {
        (left.occurrences.len() as i64 - removed - changed - contradiction - unknown).max(0)
    } else {
        0
    };
    json!({
        "unchanged": unchanged,
        "added": added,
        "removed": removed,
        "changed": changed,
        "unknown": unknown,
        "contradiction": contradiction,
    })
}

fn root_hash_change(
    left: &ArtifactInventoryResult,
    right: &ArtifactInventoryResult,
    changes: &[Value],
    evidence_links: &[String],
) -> Option<Value> {
    if left.manifest.root_sha256 == right.manifest.root_sha256 {
        return None;
    }
    if changes.iter().any(|c| {
        c["logical_path"] == "."
            && c["dimensions"]
                .as_array()
                .map(|d| d.iter().any(|x| x == "content"))
                .unwrap_or(false)
    }) {
        return None;
    }
    let left_root = left.occurrences.iter().find(|o| o.logical_path == ".");
    let right_root = right.occurrences.iter().find(|o| o.logical_path == ".");
    Some(json!({
        "classification": "changed",
        "logical_path": ".",
        "dimensions": ["content"],
        "left_occurrence_id": left_root.map(|o| o.occurrence_id.clone()),
        "right_occurrence_id": right_root.map(|o| o.occurrence_id.clone()),
        "left_artifact_id": left_root.and_then(|o| o.artifact_id.clone()),
        "right_artifact_id": right_root.and_then(|o| o.artifact_id.clone()),
        "evidence_links": evidence_links,
    }))
}
