//! Candidate index for historical source files against application-graph nodes.

use std::collections::{HashMap, HashSet};

use serde_json::{json, Value};

use crate::error::JsError;
use crate::source_bundle_paths::{
    add_path, is_digest, path_suffixes, posix_basename, posix_extname, required_str, string_array,
    unique_paths, CurrentPath,
};
use crate::unicode::{compare_unicode_code_points, unique_sorted};

const RELEVANT_KINDS: &[&str] = &["javascript-asset", "javascript-module", "source-module"];
const PATH_PROPERTIES: &[&str] = &[
    "path",
    "source",
    "original_source",
    "module_path",
    "resolved_path",
    "declared_path",
];

pub(crate) struct Projection {
    pub(crate) node_id: String,
    node_kind: String,
    digests: HashSet<String>,
    paths: Vec<CurrentPath>,
}

pub(crate) struct Index {
    nodes: HashMap<String, Projection>,
    by_digest: HashMap<String, HashSet<String>>,
    by_path_suffix: HashMap<String, HashSet<String>>,
    by_basename: HashMap<String, HashSet<String>>,
}

pub(crate) struct SourceFile {
    pub(crate) path: String,
    pub(crate) sha256: Option<String>,
    pub(crate) language: Option<String>,
    pub(crate) limitations: Vec<String>,
}

pub(crate) fn candidate_has_digest(index: &Index, node_id: &str) -> bool {
    index.nodes.get(node_id).is_some_and(|node| !node.digests.is_empty())
}

pub(crate) fn historical_sources(reference: &Value) -> Result<Vec<SourceFile>, JsError> {
    let entries = reference
        .get("entries")
        .and_then(|v| v.as_array())
        .ok_or_else(|| JsError::InvalidInput("reference.entries must be an array".into()))?;
    let mut sources = Vec::new();
    for entry in entries {
        if entry.get("kind").and_then(|v| v.as_str()) != Some("file") {
            continue;
        }
        let classes = string_array(entry.get("classifications").unwrap_or(&json!([])), "classifications")?;
        if !classes.iter().any(|c| c == "source") {
            continue;
        }
        let sha = match entry.get("sha256") {
            Some(Value::String(value)) if is_digest(value) => Some(value.clone()),
            Some(Value::Null) | None => None,
            Some(Value::String(_)) => None,
            _ => {
                return Err(JsError::InvalidInput(
                    "source sha256 must be a digest or null".into(),
                ))
            }
        };
        let language = match entry.get("language") {
            Some(Value::String(value)) => Some(value.clone()),
            Some(Value::Null) | None => None,
            _ => return Err(JsError::InvalidInput("source language must be a string or null".into())),
        };
        sources.push(SourceFile {
            path: required_str(entry, "path")?,
            sha256: sha,
            language,
            limitations: string_array(entry.get("limitations").unwrap_or(&json!([])), "limitations")?,
        });
    }
    sources.sort_by(|left, right| compare_unicode_code_points(&left.path, &right.path));
    Ok(sources)
}

pub(crate) fn source_bearing_nodes(graph: &Value) -> Result<Vec<Projection>, JsError> {
    let nodes = graph
        .get("nodes")
        .and_then(|v| v.as_array())
        .ok_or_else(|| JsError::InvalidInput("application graph nodes must be an array".into()))?;
    let mut projections = Vec::new();
    for node in nodes {
        let kind = required_str(node, "kind")?;
        if !RELEVANT_KINDS.contains(&kind.as_str()) {
            continue;
        }
        projections.push(project_node(node, &kind)?);
    }
    projections.sort_by(|left, right| compare_unicode_code_points(&left.node_id, &right.node_id));
    Ok(projections)
}

fn project_node(node: &Value, kind: &str) -> Result<Projection, JsError> {
    let identity = node.get("identity").cloned().unwrap_or(json!({}));
    let strategy = identity.get("strategy").and_then(|v| v.as_str()).unwrap_or("");
    let mut digests = HashSet::new();
    let mut paths = Vec::new();
    if strategy == "content-digest" {
        if let Some(sha) = identity.get("sha256").and_then(|v| v.as_str()) {
            if is_digest(sha) {
                digests.insert(sha.to_string());
            }
        }
    }
    if strategy == "source-map-original" {
        if let Some(sha) = identity.get("source_sha256").and_then(|v| v.as_str()) {
            if is_digest(sha) {
                digests.insert(sha.to_string());
            }
        }
    }
    if strategy == "canonical-path" {
        if let Some(path) = identity.get("path").and_then(|v| v.as_str()) {
            add_path(&mut paths, "canonical-path", path);
        }
    }
    let observations = node.get("observations").and_then(|v| v.as_array());
    if let Some(observations) = observations {
        for observation in observations {
            if strategy == "source-map-original" {
                let resolution = observation.pointer("/source_map_reference/resolution");
                if let Some(resolution) = resolution {
                    let res_kind = resolution.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                    if res_kind != "unresolved" {
                        if let Some(path) = resolution.get("path").and_then(|v| v.as_str()) {
                            paths.push(CurrentPath {
                                kind: "source-map-original",
                                value: path.to_string(),
                                allow_suffix: res_kind == "suffix",
                            });
                        }
                    }
                }
            } else {
                if let Some(props) = observation.get("properties") {
                    if let Some(sha) = props.get("source_sha256").and_then(|v| v.as_str()) {
                        if is_digest(sha) {
                            digests.insert(sha.to_string());
                        }
                    }
                    for key in PATH_PROPERTIES {
                        if let Some(path) = props.get(*key).and_then(|v| v.as_str()) {
                            add_path(&mut paths, "observation-path", path);
                        }
                    }
                }
            }
        }
    }
    Ok(Projection {
        node_id: required_str(node, "node_id")?,
        node_kind: kind.to_string(),
        digests,
        paths: unique_paths(paths),
    })
}

pub(crate) fn build_index(nodes: &[Projection]) -> Index {
    let mut by_digest: HashMap<String, HashSet<String>> = HashMap::new();
    let mut by_path_suffix: HashMap<String, HashSet<String>> = HashMap::new();
    let mut by_basename: HashMap<String, HashSet<String>> = HashMap::new();
    for node in nodes {
        for digest in &node.digests {
            by_digest.entry(digest.clone()).or_default().insert(node.node_id.clone());
        }
        for path in &node.paths {
            let keys = if path.allow_suffix {
                path_suffixes(&path.value)
            } else {
                vec![path.value.clone()]
            };
            for key in keys {
                by_path_suffix.entry(key).or_default().insert(node.node_id.clone());
            }
            by_basename
                .entry(posix_basename(&path.value).to_string())
                .or_default()
                .insert(node.node_id.clone());
        }
    }
    Index {
        nodes: nodes
            .iter()
            .map(|node| (node.node_id.clone(), clone_projection(node)))
            .collect(),
        by_digest,
        by_path_suffix,
        by_basename,
    }
}

fn clone_projection(node: &Projection) -> Projection {
    Projection {
        node_id: node.node_id.clone(),
        node_kind: node.node_kind.clone(),
        digests: node.digests.clone(),
        paths: node
            .paths
            .iter()
            .map(|path| CurrentPath {
                kind: path.kind,
                value: path.value.clone(),
                allow_suffix: path.allow_suffix,
            })
            .collect(),
    }
}

pub(crate) fn candidate_ids_for(source: &SourceFile, index: &Index) -> Vec<String> {
    let mut groups: Vec<Option<&HashSet<String>>> = Vec::new();
    groups.push(source.sha256.as_ref().and_then(|sha| index.by_digest.get(sha)));
    groups.push(index.by_path_suffix.get(&source.path));
    groups.push(index.by_basename.get(posix_basename(&source.path)));
    let mut seen = HashSet::new();
    let mut output = Vec::new();
    for group in groups.into_iter().flatten() {
        let mut ids: Vec<String> = group.iter().cloned().collect();
        ids.sort_by(|a, b| compare_unicode_code_points(a, b));
        for node_id in ids {
            if seen.insert(node_id.clone()) {
                output.push(node_id);
            }
        }
    }
    output
}

pub(crate) fn score_candidate(source: &SourceFile, node_id: &str, index: &Index) -> Result<Option<Value>, JsError> {
    let Some(projection) = index.nodes.get(node_id) else {
        return Ok(None);
    };
    let signals = candidate_signals(source, projection);
    let score: i64 = signals.iter().filter_map(|s| s.get("weight").and_then(|v| v.as_i64())).sum();
    if score < 20 {
        return Ok(None);
    }
    let confidence = candidate_confidence(&signals);
    Ok(Some(json!({
        "current_node_id": projection.node_id,
        "current_node_kind": projection.node_kind,
        "score": score,
        "confidence": confidence,
        "signals": signals,
    })))
}

fn candidate_signals(source: &SourceFile, current: &Projection) -> Vec<Value> {
    let mut signals = Vec::new();
    if let Some(sha) = &source.sha256 {
        if current.digests.contains(sha) {
            signals.push(signal("exact-source-digest", 100, sha, &[sha.clone()]));
        }
    }
    let source_map_paths = matching_paths(
        &source.path,
        current.paths.iter().filter(|path| path.kind == "source-map-original"),
    );
    if !source_map_paths.is_empty() {
        signals.push(signal("source-map-original-path", 70, &source.path, &source_map_paths));
    }
    let other: Vec<&CurrentPath> = current
        .paths
        .iter()
        .filter(|path| path.kind != "source-map-original")
        .collect();
    let exact: Vec<String> = other
        .iter()
        .filter(|path| path.value == source.path)
        .map(|path| path.value.clone())
        .collect();
    if !exact.is_empty() {
        signals.push(signal("current-path-exact", 60, &source.path, &exact));
    }
    let suffixes: Vec<String> = other
        .iter()
        .filter(|path| path.allow_suffix && path.value != source.path && path.value.ends_with(&format!("/{}", source.path)))
        .map(|path| path.value.clone())
        .collect();
    if !suffixes.is_empty() {
        signals.push(signal("current-path-suffix", 40, &source.path, &suffixes));
    }
    let base = posix_basename(&source.path).to_string();
    let basename_paths: Vec<String> = current
        .paths
        .iter()
        .filter(|path| posix_basename(&path.value) == base)
        .map(|path| path.value.clone())
        .collect();
    if !basename_paths.is_empty() {
        signals.push(signal("basename-match", 20, &base, &basename_paths));
    }
    let extension = posix_extname(&source.path);
    let extension_paths: Vec<String> = current
        .paths
        .iter()
        .filter(|path| !extension.is_empty() && posix_extname(&path.value) == extension)
        .map(|path| path.value.clone())
        .collect();
    if !extension.is_empty() && !extension_paths.is_empty() {
        signals.push(signal("language-extension", 5, &extension, &extension_paths));
    }
    signals
}

fn signal(kind: &str, weight: i64, source_value: &str, current_values: &[String]) -> Value {
    let current_values = unique_sorted(current_values);
    json!({
        "kind": kind,
        "weight": weight,
        "source_value": source_value,
        "current_values": current_values,
    })
}

fn candidate_confidence(signals: &[Value]) -> &'static str {
    let kinds: HashSet<&str> = signals.iter().filter_map(|s| s.get("kind").and_then(|v| v.as_str())).collect();
    if kinds.contains("exact-source-digest") {
        "exact"
    } else if kinds.contains("source-map-original-path") || kinds.contains("current-path-exact") {
        "high"
    } else if kinds.contains("current-path-suffix") {
        "medium"
    } else {
        "low"
    }
}

fn matching_paths<'a>(source_path: &str, paths: impl Iterator<Item = &'a CurrentPath>) -> Vec<String> {
    paths
        .filter(|path| path.value == source_path || (path.allow_suffix && path.value.ends_with(&format!("/{source_path}"))))
        .map(|path| path.value.clone())
        .collect()
}

