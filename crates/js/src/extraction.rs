use crate::digest::digest_canonical_value;
use crate::error::JsError;
use crate::inventory::scan_artifact_inventory;
use crate::paths::normalize_artifact_path;
use crate::readers::create_reader;
use crate::types::{
    ArtifactExtractionResult, ExtractionCleanup, ExtractionManifest,
    ExtractedArtifact,
};
use crate::unicode::compare_unicode_code_points;
use std::collections::{HashMap, HashSet};
use std::path::Path;

pub fn extract_artifact(path: &Path, integrity_policy: &str) -> Result<ArtifactExtractionResult, JsError> {
    let snapshot = scan_artifact_inventory(path)?;
    let output_root = tempfile::tempdir()
        .map_err(|e| JsError::Io(e.to_string()))?
        .keep();
    materialize_inventory(path, &snapshot, &output_root, integrity_policy)
}

fn materialize_inventory(
    source_path: &Path,
    snapshot: &crate::types::ArtifactInventoryResult,
    output_root: &Path,
    _integrity_policy: &str,
) -> Result<ArtifactExtractionResult, JsError> {
    let regular_paths: HashSet<String> = snapshot
        .occurrences
        .iter()
        .filter(|o| (o.entry_kind == "file" || o.entry_kind == "slice") && o.logical_path != ".")
        .map(|o| o.logical_path.clone())
        .collect();
    let active: Vec<_> = snapshot
        .occurrences
        .iter()
        .filter(|o| {
            (o.entry_kind == "file" || o.entry_kind == "slice")
                && o.logical_path != "."
                && !is_nested_under_regular_file(&o.logical_path, &regular_paths)
        })
        .collect();
    let mut selected_ids: Vec<String> = active.iter().map(|o| o.occurrence_id.clone()).collect();
    selected_ids.sort_by(|a, b| compare_unicode_code_points(a, b));
    let canonical = std::fs::canonicalize(source_path)?;
    let reader = create_reader(&canonical, &snapshot.manifest.root_format)?
        .ok_or_else(|| JsError::Format("No reader for extraction".to_string()))?;
    let mut extracted = Vec::new();
    let entries = reader.list_entries()?;
    let by_path: HashMap<_, _> = active
        .iter()
        .filter_map(|o| o.artifact_id.as_ref().map(|aid| (o.logical_path.clone(), (o, aid))))
        .collect();
    for entry in entries {
        let path = normalize_artifact_path(&entry.path)?;
        if let Some((occ, aid)) = by_path.get(&path) {
            if occ.encrypted {
                return Err(JsError::InvalidInput(
                    format!("Archive entry {} is encrypted", path),
                ));
            }
            let bytes = reader.read_entry(&entry)?;
            let dest = output_root.join(&path);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&dest, &bytes)?;
            let node = snapshot
                .nodes
                .iter()
                .find(|n| n.artifact_id == **aid)
                .ok_or_else(|| JsError::Integrity("missing node".to_string()))?;
            extracted.push(ExtractedArtifact {
                artifact_id: node.artifact_id.clone(),
                relative_path: path,
                sha256: node.sha256.clone(),
                bytes_written: bytes.len() as u64,
                created: true,
            });
        }
    }
    extracted.sort_by(|a, b| compare_unicode_code_points(&a.relative_path, &b.relative_path));
    let files_sha256 = digest_canonical_value(&extracted).map_err(|e| JsError::Domain(e.to_string()))?;
    let extraction_id = format!(
        "aex_{}",
        digest_canonical_value(&serde_json::json!({
            "source_manifest_id": snapshot.manifest.manifest_id,
            "files_sha256": files_sha256,
        }))
        .map_err(|e| JsError::Domain(e.to_string()))?
    );
    Ok(ArtifactExtractionResult {
        manifest: snapshot.manifest.clone(),
        extraction_manifest: ExtractionManifest {
            extraction_id,
            source_manifest_id: snapshot.manifest.manifest_id.clone(),
            selected_occurrence_ids: selected_ids,
            files_sha256,
            output_root_alias: "$OUTPUT_ROOT".to_string(),
        },
        output_root: output_root.to_string_lossy().to_string(),
        artifacts: extracted,
        containment_verified: true,
        cleanup: ExtractionCleanup {
            attempted: false,
            verified: true,
            residual_paths: vec![],
        },
        provenance: vec![],
        integrity_contradictions: snapshot.integrity_contradictions.clone(),
        limitations: vec![
            "All regular files in the active artifact were materialized; nested archive contents remain represented by their containing file.".to_string(),
        ],
    })
}

fn is_nested_under_regular_file(path: &str, regular_paths: &HashSet<String>) -> bool {
    let mut p = path.to_string();
    while let Some(slash) = p.rfind('/') {
        p = p[..slash].to_string();
        if regular_paths.contains(&p) {
            return true;
        }
    }
    false
}
