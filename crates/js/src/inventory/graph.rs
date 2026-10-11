use crate::classify::{
    classify_artifact_bytes, classify_artifact_content, classify_artifact_path,
    zip_package_format_for_path,
};
use crate::digest::digest_canonical_value;
use crate::hash::HashResult;
use crate::identity::{
    artifact_edge_id, artifact_id_for_content, occurrence_id_for_location, preliminary_occurrence_id,
};
use crate::readers::ArtifactEntry;
use crate::types::ArtifactNode;
use crate::unicode::compare_unicode_code_points;
use std::collections::HashMap;
use tracewise_domain::error::DomainError;

#[derive(Debug, Clone)]
pub struct MutableOccurrence {
    pub occurrence_id: String,
    pub artifact_id: Option<String>,
    pub parent_occurrence_id: Option<String>,
    pub logical_path: String,
    pub entry_kind: String,
    pub artifact_kind: String,
    pub artifact_format: String,
    pub declared_size: Option<u64>,
    pub compressed_size: Option<u64>,
    pub executable: bool,
    pub encrypted: bool,
    pub hash_status: String,
    pub source_location: Option<crate::types::SourceLocation>,
    pub limitations: Vec<String>,
}

fn container_suffix_family(path: &str) -> Option<&'static str> {
    let lower = path.to_lowercase();
    if lower.ends_with(".asar") {
        return Some("asar");
    }
    zip_package_format_for_path(&lower)
}

pub fn create_occurrence(
    entry: &ArtifactEntry,
    path: &str,
    parent: Option<String>,
) -> Result<MutableOccurrence, DomainError> {
    let (artifact_kind, artifact_format) = if entry.kind == "directory" {
        let kind = if path.to_lowercase().ends_with(".framework") {
            "framework"
        } else {
            "container"
        };
        (kind.to_string(), "directory".to_string())
    } else if container_suffix_family(path).is_none() {
        let (k, f) = classify_artifact_path(path);
        (k, f)
    } else {
        ("unknown".to_string(), "unknown".to_string())
    };
    Ok(MutableOccurrence {
        occurrence_id: preliminary_occurrence_id(path, &entry.kind)?,
        artifact_id: None,
        parent_occurrence_id: parent,
        logical_path: path.to_string(),
        entry_kind: entry.kind.clone(),
        artifact_kind,
        artifact_format,
        declared_size: entry.declared_size,
        compressed_size: entry.compressed_size,
        executable: entry.executable,
        encrypted: entry.encrypted,
        hash_status: if entry.encrypted {
            "unavailable".to_string()
        } else {
            "not-hashed".to_string()
        },
        source_location: None,
        limitations: entry.limitations.clone(),
    })
}

pub fn note_unread_container_suffix(occurrence: &mut MutableOccurrence) {
    if occurrence.entry_kind == "directory" {
        return;
    }
    if let Some(family) = container_suffix_family(&occurrence.logical_path) {
        occurrence.limitations.push(format!(
            "The path suffix suggests {}, but these bytes were not read, so the container family is unknown.",
            family.to_uppercase()
        ));
    }
}

pub fn create_artifact_node(
    sha256: &str,
    size: u64,
    format: &str,
    content_state: &str,
) -> Result<ArtifactNode, DomainError> {
    Ok(ArtifactNode {
        artifact_id: artifact_id_for_content(sha256)?,
        format: format.to_string(),
        sha256: sha256.to_string(),
        size,
        media_type: None,
        architecture: None,
        content_state: content_state.to_string(),
        limitations: vec![],
    })
}

pub fn create_root_node(
    digest: Option<&HashResult>,
    occurrences: &[MutableOccurrence],
) -> Result<ArtifactNode, DomainError> {
    let sha256 = if let Some(d) = digest {
        d.sha256.clone()
    } else {
        let children: Vec<_> = occurrences
            .iter()
            .map(|o| {
                serde_json::json!({
                    "logical_path": o.logical_path,
                    "artifact_id": o.artifact_id,
                })
            })
            .collect();
        let mut sorted = children;
        sorted.sort_by(|a, b| {
            compare_unicode_code_points(
                a["logical_path"].as_str().unwrap_or(""),
                b["logical_path"].as_str().unwrap_or(""),
            )
        });
        digest_canonical_value(
            &serde_json::json!({ "kind": "directory-root", "children": sorted }),
        )?
    };
    let format = if digest.is_none() {
        "directory".to_string()
    } else {
        classify_artifact_bytes(&digest.unwrap().prefix, digest.unwrap().bytes)
    };
    create_artifact_node(&sha256, digest.map(|d| d.bytes).unwrap_or(0), &format, "materialized")
}

pub fn root_occurrence_for(
    node: &ArtifactNode,
    size: u64,
    executable: bool,
    format: &str,
    path: &str,
) -> Result<MutableOccurrence, DomainError> {
    let entry_kind = if format == "directory" {
        "directory"
    } else {
        "file"
    };
    let artifact_kind = if format == "directory"
        || matches!(
            format,
            "zip" | "ipa" | "apk" | "msix" | "appx" | "asar" | "dmg" | "pkg"
        )
    {
        "container".to_string()
    } else {
        classify_artifact_path(path).0
    };
    Ok(MutableOccurrence {
        occurrence_id: occurrence_id_for_location(&node.artifact_id, ".", entry_kind)?,
        artifact_id: Some(node.artifact_id.clone()),
        parent_occurrence_id: None,
        logical_path: ".".to_string(),
        entry_kind: entry_kind.to_string(),
        artifact_kind,
        artifact_format: format.to_string(),
        declared_size: Some(size),
        compressed_size: None,
        executable,
        encrypted: false,
        hash_status: "verified".to_string(),
        source_location: None,
        limitations: vec![],
    })
}

pub fn materialize_directory_nodes(
    occurrences: &mut [MutableOccurrence],
    nodes: &mut HashMap<String, ArtifactNode>,
) -> Result<(), DomainError> {
    let mut directories: Vec<(usize, usize)> = occurrences
        .iter()
        .enumerate()
        .filter(|(_, o)| o.entry_kind == "directory")
        .map(|(i, o)| (i, o.logical_path.matches('/').count()))
        .collect();
    directories.sort_by(|a, b| b.1.cmp(&a.1));
    let directories: Vec<usize> = directories.into_iter().map(|(i, _)| i).collect();
    let mut children_by_parent: HashMap<String, Vec<(String, Option<String>, String)>> =
        HashMap::new();
    for occ in occurrences.iter() {
        if let Some(parent_id) = &occ.parent_occurrence_id {
            children_by_parent
                .entry(parent_id.clone())
                .or_default()
                .push((
                    occ.logical_path.clone(),
                    occ.artifact_id.clone(),
                    occ.entry_kind.clone(),
                ));
        }
    }
    for idx in directories {
        let directory = &occurrences[idx];
        let children = children_by_parent
            .get(&directory.occurrence_id)
            .cloned()
            .unwrap_or_default();
        let mut child_specs: Vec<_> = children
            .iter()
            .map(|(path, aid, kind)| {
                let name = path
                    .strip_prefix(&format!("{}/", directory.logical_path))
                    .unwrap_or(path)
                    .to_string();
                serde_json::json!({
                    "name": name,
                    "artifact_id": aid,
                    "entry_kind": kind,
                })
            })
            .collect();
        child_specs.sort_by(|a, b| {
            compare_unicode_code_points(
                a["name"].as_str().unwrap_or(""),
                b["name"].as_str().unwrap_or(""),
            )
        });
        let sha256 = digest_canonical_value(
            &serde_json::json!({ "kind": "directory", "children": child_specs }),
        )?;
        let node = create_artifact_node(&sha256, 0, "directory", "virtual")?;
        nodes.insert(node.artifact_id.clone(), node.clone());
        occurrences[idx].artifact_id = Some(node.artifact_id.clone());
        occurrences[idx].hash_status = "verified".to_string();
    }
    Ok(())
}

pub fn rekey_occurrences(root_artifact_id: &str, occurrences: &mut [MutableOccurrence]) -> Result<(), DomainError> {
    let mut replacements = HashMap::new();
    for occ in occurrences.iter() {
        let new_id = occurrence_id_for_location(
            root_artifact_id,
            &occ.logical_path,
            &occ.entry_kind,
        )?;
        replacements.insert(occ.occurrence_id.clone(), new_id);
    }
    for occ in occurrences.iter_mut() {
        occ.occurrence_id = replacements
            .get(&occ.occurrence_id)
            .cloned()
            .unwrap_or(occ.occurrence_id.clone());
        if let Some(parent) = &occ.parent_occurrence_id {
            occ.parent_occurrence_id = replacements.get(parent).cloned();
        }
    }
    Ok(())
}

pub fn resolve_occurrence_parents(occurrences: &mut [MutableOccurrence]) {
    let snapshot: Vec<(String, String, String, String)> = occurrences
        .iter()
        .map(|o| {
            (
                o.logical_path.clone(),
                o.occurrence_id.clone(),
                o.entry_kind.clone(),
                o.artifact_format.clone(),
            )
        })
        .collect();
    for occ in occurrences.iter_mut() {
        let path = &occ.logical_path;
        let mut parent: Option<String> = None;
        if let Some(slash) = path.rfind('/') {
            let parent_path = &path[..slash];
            for (lp, oid, ek, af) in &snapshot {
                if lp == parent_path && (ek == "directory" || af == "asar") {
                    parent = Some(oid.clone());
                    break;
                }
            }
        }
        occ.parent_occurrence_id = parent;
    }
}

pub fn create_artifact_edges(
    root_artifact_id: &str,
    occurrences: &[MutableOccurrence],
) -> Result<Vec<crate::types::ArtifactEdge>, DomainError> {
    let by_id: HashMap<_, _> = occurrences
        .iter()
        .map(|o| (o.occurrence_id.clone(), o))
        .collect();
    let by_path: HashMap<_, _> = occurrences
        .iter()
        .map(|o| (o.logical_path.clone(), o))
        .collect();
    let mut edges = Vec::new();
    for occ in occurrences {
        if occ.parent_occurrence_id.is_none() || occ.artifact_id.is_none() {
            continue;
        }
        let relation = if occ.entry_kind == "slice" {
            "slice-of"
        } else if occ.logical_path.to_lowercase().ends_with(".map") {
            "maps-source"
        } else if occ.logical_path.to_lowercase().contains(".framework/") {
            "embeds"
        } else {
            "contains"
        };
        let parent_artifact_id = if occ.logical_path.to_lowercase().ends_with(".map") {
            let base = occ.logical_path.trim_end_matches(".map");
            by_path
                .get(base)
                .and_then(|o| o.artifact_id.clone())
                .unwrap_or_else(|| root_artifact_id.to_string())
        } else {
            by_id
                .get(occ.parent_occurrence_id.as_ref().unwrap())
                .and_then(|p| p.artifact_id.clone())
                .unwrap_or_else(|| root_artifact_id.to_string())
        };
        let edge_id = artifact_edge_id(
            &parent_artifact_id,
            relation,
            &occ.occurrence_id,
            occ.artifact_id.as_ref().unwrap(),
            &occ.logical_path,
        )?;
        edges.push(crate::types::ArtifactEdge {
            edge_id,
            ordinal: edges.len() as u64,
            parent_artifact_id,
            relation: relation.to_string(),
            occurrence_id: occ.occurrence_id.clone(),
            producer: None,
        });
    }
    Ok(edges)
}

pub fn digest_entry_classification(
    path: &str,
    hash: &HashResult,
) -> (String, String, String) {
    let node_format = classify_artifact_bytes(&hash.prefix, hash.bytes);
    let (kind, format) = classify_artifact_content(path, &hash.prefix, hash.bytes);
    (node_format, kind, format)
}
