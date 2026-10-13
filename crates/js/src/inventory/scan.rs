use crate::classify::{classify_root_format, read_classification_prefix};
use crate::error::JsError;
use crate::hash::{hash_bytes, hash_file, HashResult};
use crate::identity::{
    artifact_contradiction_id, artifact_graph_digest, artifact_manifest_id,
};
use crate::inventory::graph::{
    create_artifact_edges, create_artifact_node, create_occurrence, create_root_node,
    digest_entry_classification, materialize_directory_nodes, note_unread_container_suffix,
    rekey_occurrences, resolve_occurrence_parents, root_occurrence_for, MutableOccurrence,
};
use crate::paths::normalize_artifact_path;
use crate::readers::{create_reader, inventory_limitations, ArtifactEntry, ArtifactReader};
use crate::types::{
    ArtifactGraphManifest, ArtifactInventoryResult, ArtifactNode, IntegrityContradiction,
};
use crate::unicode::compare_unicode_code_points;
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tracewise_domain::error::DomainError;

#[derive(Debug, Clone)]
pub struct PendingContradiction {
    pub logical_path: String,
    pub declared_sha256: String,
    pub observed_sha256: String,
    pub entry_kind: String,
    pub unpacked: bool,
}

pub fn scan_artifact_inventory(path: &Path) -> Result<ArtifactInventoryResult, JsError> {
    scan_artifact_inventory_with_policy(path, "fail")
}

/// Inventory with REA's `integrity_policy` (`fail` or `record-and-continue`).
pub fn scan_artifact_inventory_with_policy(
    path: &Path,
    integrity_policy: &str,
) -> Result<ArtifactInventoryResult, JsError> {
    let canonical = std::fs::canonicalize(path)?;
    let meta = std::fs::metadata(&canonical)?;
    let is_directory = meta.is_dir();
    let root_format = if is_directory {
        "directory".to_string()
    } else {
        let prefix = read_classification_prefix(&canonical)?;
        classify_root_format(
            canonical.to_string_lossy().as_ref(),
            &prefix,
            false,
        )
    };
    let root_digest: Option<HashResult> = if is_directory {
        None
    } else {
        Some(hash_file(&canonical)?)
    };
    let reader = create_reader(&canonical, &root_format)?;
    let has_reader = reader.is_some();
    let (mut nodes, mut occurrences, pending) = if let Some(reader) = reader {
        scan_reader(reader.as_ref(), integrity_policy)?
    } else {
        (HashMap::new(), Vec::new(), Vec::new())
    };
    materialize_directory_nodes(&mut occurrences, &mut nodes)?;
    let root_node = create_root_node(root_digest.as_ref(), &occurrences)?;
    nodes.insert(root_node.artifact_id.clone(), root_node.clone());
    rekey_occurrences(&root_node.artifact_id, &mut occurrences)?;
    let root_occ = root_occurrence_for(
        &root_node,
        meta.len(),
        meta.permissions().mode() & 0o111 != 0,
        &root_format,
        canonical.to_string_lossy().as_ref(),
    )?;
    for occ in &mut occurrences {
        if occ.parent_occurrence_id.is_none() && occ.logical_path != "." {
            occ.parent_occurrence_id = Some(root_occ.occurrence_id.clone());
        }
    }
    occurrences.insert(0, root_occ);
    let integrity_contradictions =
        build_contradictions(&pending, &occurrences, &root_node)?;
    let edges = create_artifact_edges(&root_node.artifact_id, &occurrences)?;
    let ordered_nodes = sort_nodes(nodes);
    let ordered_occurrences = sort_occurrences(occurrences);
    let ordered_edges = sort_edges(edges);
    let graph_sha256 = artifact_graph_digest(
        &ordered_nodes,
        &ordered_occurrences,
        &ordered_edges,
        &integrity_contradictions,
    )?;
    let manifest = ArtifactGraphManifest {
        manifest_id: artifact_manifest_id(&root_node.artifact_id, &graph_sha256)?,
        root_artifact_id: root_node.artifact_id.clone(),
        root_sha256: root_node.sha256.clone(),
        root_format: root_format.clone(),
        graph_sha256,
        node_count: ordered_nodes.len() as u64,
        occurrence_count: ordered_occurrences.len() as u64,
        edge_count: ordered_edges.len() as u64,
    };
    let mut limitations = inventory_limitations(&root_format, has_reader);
    if !integrity_contradictions.is_empty() {
        limitations.push(format!(
            "{} integrity contradiction(s) were recorded; mismatched content is observed-untrusted.",
            integrity_contradictions.len()
        ));
    }
    Ok(ArtifactInventoryResult {
        manifest,
        nodes: ordered_nodes,
        occurrences: ordered_occurrences,
        edges: ordered_edges,
        provenance: vec![],
        integrity_contradictions,
        limitations,
    })
}

/// Nodes by artifact id, occurrences in reader order, and the contradictions still to be resolved.
type ScannedArtifact = (HashMap<String, ArtifactNode>, Vec<MutableOccurrence>, Vec<PendingContradiction>);

fn scan_reader(
    reader: &dyn ArtifactReader,
    integrity_policy: &str,
) -> Result<ScannedArtifact, JsError> {
    let mut nodes = HashMap::new();
    let mut occurrences = Vec::new();
    let mut pending = Vec::new();
    let entries = reader.list_entries()?;
    for entry in entries {
        let logical_path = normalize_artifact_path(&entry.path)?;
        let mut occurrence = create_occurrence(&entry, &logical_path, None)?;
        if (entry.kind == "file" || entry.kind == "slice") && !entry.encrypted {
            match digest_entry(reader, &entry, &logical_path, integrity_policy, &mut pending) {
                Ok(Some((node, kind, format, mismatched))) => {
                    nodes.insert(node.artifact_id.clone(), node.clone());
                    occurrence.artifact_id = Some(node.artifact_id.clone());
                    occurrence.artifact_kind = kind;
                    occurrence.artifact_format = format;
                    occurrence.hash_status = if mismatched {
                        "mismatched".to_string()
                    } else {
                        "verified".to_string()
                    };
                    if mismatched {
                        occurrence
                            .limitations
                            .push("Declared integrity metadata contradicts observed bytes.".to_string());
                    }
                }
                Ok(None) => note_unread_container_suffix(&mut occurrence),
                Err(e) => {
                    if entry.unpacked && e.to_string().contains("io") {
                        occurrence.hash_status = "unavailable".to_string();
                        occurrence.limitations.push(
                            "ASAR unpacked companion bytes were unavailable; no content hash or child artifact was produced.".to_string(),
                        );
                    } else {
                        return Err(e);
                    }
                }
            }
        } else {
            note_unread_container_suffix(&mut occurrence);
        }
        occurrences.push(occurrence);
    }
    resolve_occurrence_parents(&mut occurrences);
    Ok((nodes, occurrences, pending))
}

fn digest_entry(
    reader: &dyn ArtifactReader,
    entry: &ArtifactEntry,
    logical_path: &str,
    integrity_policy: &str,
    pending: &mut Vec<PendingContradiction>,
) -> Result<Option<(ArtifactNode, String, String, bool)>, JsError> {
    let bytes = reader.read_entry(entry)?;
    let hash = hash_bytes(&bytes);
    let mismatched = entry
        .declared_sha256
        .as_ref()
        .map(|d| d != &hash.sha256)
        .unwrap_or(false);
    if mismatched {
        if integrity_policy == "fail" {
            return Err(JsError::Integrity(format!(
                "Artifact integrity metadata disagrees with content: {}",
                logical_path
            )));
        }
        pending.push(PendingContradiction {
            logical_path: logical_path.to_string(),
            declared_sha256: entry.declared_sha256.clone().unwrap_or_default(),
            observed_sha256: hash.sha256.clone(),
            entry_kind: entry.kind.clone(),
            unpacked: entry.unpacked,
        });
    }
    let (node_format, kind, format) = digest_entry_classification(logical_path, &hash);
    let node = create_artifact_node(&hash.sha256, hash.bytes, &node_format, "embedded")?;
    Ok(Some((node, kind, format, mismatched)))
}

fn build_contradictions(
    pending: &[PendingContradiction],
    occurrences: &[MutableOccurrence],
    root_node: &ArtifactNode,
) -> Result<Vec<IntegrityContradiction>, DomainError> {
    let by_path: HashMap<_, _> = occurrences
        .iter()
        .map(|o| (o.logical_path.clone(), o))
        .collect();
    let by_id: HashMap<_, _> = occurrences
        .iter()
        .map(|o| (o.occurrence_id.clone(), o))
        .collect();
    let mut out = Vec::new();
    for c in pending {
        let occ = by_path
            .get(&c.logical_path)
            .ok_or_else(|| DomainError::Canonicalization("missing occurrence".to_string()))?;
        let parent_artifact_id = if let Some(pid) = &occ.parent_occurrence_id {
            by_id
                .get(pid)
                .and_then(|p| p.artifact_id.clone())
                .unwrap_or_else(|| root_node.artifact_id.clone())
        } else {
            root_node.artifact_id.clone()
        };
        out.push(IntegrityContradiction {
            contradiction_id: artifact_contradiction_id(
                &root_node.artifact_id,
                &c.logical_path,
                &c.declared_sha256,
                &c.observed_sha256,
            )?,
            occurrence_id: occ.occurrence_id.clone(),
            parent_artifact_id,
            logical_path: c.logical_path.clone(),
            declared_sha256: c.declared_sha256.clone(),
            observed_sha256: c.observed_sha256.clone(),
            entry_kind: c.entry_kind.clone(),
            unpacked: c.unpacked,
            trust: "observed-untrusted".to_string(),
            provenance: "container-integrity-metadata-versus-observed-bytes".to_string(),
            limitations: vec![
                "Observed bytes contradict declared integrity metadata and cannot support equivalence."
                    .to_string(),
            ],
        });
    }
    Ok(out)
}

fn sort_nodes(nodes: HashMap<String, ArtifactNode>) -> Vec<ArtifactNode> {
    let mut v: Vec<_> = nodes.into_values().collect();
    v.sort_by(|a, b| compare_unicode_code_points(&a.artifact_id, &b.artifact_id));
    v
}

fn sort_occurrences(mut occurrences: Vec<MutableOccurrence>) -> Vec<crate::types::ArtifactOccurrence> {
    occurrences.sort_by(|a, b| compare_unicode_code_points(&a.logical_path, &b.logical_path));
    occurrences
        .into_iter()
        .map(|o| crate::types::ArtifactOccurrence {
            occurrence_id: o.occurrence_id,
            artifact_id: o.artifact_id,
            parent_occurrence_id: o.parent_occurrence_id,
            logical_path: o.logical_path,
            entry_kind: o.entry_kind,
            artifact_kind: o.artifact_kind,
            artifact_format: o.artifact_format,
            declared_size: o.declared_size,
            compressed_size: o.compressed_size,
            executable: o.executable,
            encrypted: o.encrypted,
            hash_status: o.hash_status,
            source_location: o.source_location,
            limitations: o.limitations,
        })
        .collect()
}

fn sort_edges(edges: Vec<crate::types::ArtifactEdge>) -> Vec<crate::types::ArtifactEdge> {
    let mut edges = edges;
    edges.sort_by(|a, b| compare_unicode_code_points(&a.edge_id, &b.edge_id));
    for (i, edge) in edges.iter_mut().enumerate() {
        edge.ordinal = i as u64;
    }
    edges
}

#[cfg(test)]
mod inventory_oracle_test {
    use super::*;
    use std::path::Path;
    #[test]
    fn app_fixture_inventory_matches_oracle() {
        let inv = scan_artifact_inventory(Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/js/app"))).unwrap();
        assert_eq!(
            inv.manifest.manifest_id,
            "agm_f284bb10399be287041cef6720f3b62a856cf56e48b79bf0e0a6294de0c381c2"
        );
        let graph_sha = crate::identity::artifact_graph_digest(
            &inv.nodes,
            &inv.occurrences,
            &inv.edges,
            &inv.integrity_contradictions,
        )
        .unwrap();
        assert_eq!(
            graph_sha,
            "1a9169342f95469852289bf8a81c88c25bed775dd521523fdae79e6ba66e5534"
        );
    }
}
