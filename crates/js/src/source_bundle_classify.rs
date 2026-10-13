//! Classification of one historical source against scored bundle candidates.

use std::collections::{HashMap, HashSet};

use serde_json::{json, Map, Value};
use tracewise_domain::canonical::canonical_sha256;

use crate::error::JsError;
use crate::source_bundle_index::SourceFile;
use crate::source_bundle_paths::string_array;
use crate::unicode::unique_sorted;

const STATIC_LIMIT: &str = "Static digest and location signals do not establish runtime behavior, semantic equivalence, or absence of dynamically generated modules.";

pub(crate) struct Classified {
    pub(crate) status: String,
    pub(crate) confidence: String,
    pub(crate) node_ids: Vec<String>,
    pub(crate) limitations: Vec<String>,
}

pub(crate) fn classify(
    candidates: &[Value],
    absence_complete: bool,
    digest_comparable: impl Fn(&str) -> bool,
) -> Classified {
    let exact: Vec<&Value> = candidates
        .iter()
        .filter(|candidate| has_signal(candidate, "exact-source-digest"))
        .collect();
    if exact.len() == 1 {
        return Classified {
            status: "unchanged".into(),
            confidence: "exact".into(),
            node_ids: node_id_of(exact[0]).into_iter().collect(),
            limitations: vec!["Exact byte identity does not establish equivalent load context or runtime behavior.".into()],
        };
    }
    if exact.len() > 1 {
        return Classified {
            status: "duplicated".into(),
            confidence: "exact".into(),
            node_ids: exact.iter().filter_map(|c| node_id_of(c)).collect(),
            limitations: vec!["The same historical source digest occurs in multiple current graph nodes.".into()],
        };
    }
    let path_candidates: Vec<&Value> = candidates
        .iter()
        .filter(|candidate| {
            ["source-map-original-path", "current-path-exact", "current-path-suffix"]
                .iter()
                .any(|kind| has_signal(candidate, kind))
        })
        .collect();
    let top_score = path_candidates.first().and_then(|c| c.get("score")).and_then(|v| v.as_i64());
    let top: Vec<&Value> = match top_score {
        Some(score) => path_candidates
            .into_iter()
            .filter(|c| c.get("score").and_then(|v| v.as_i64()) == Some(score))
            .collect(),
        None => Vec::new(),
    };
    if top.len() == 1 {
        let node_id = node_id_of(top[0]).unwrap_or_default();
        if digest_comparable(&node_id) {
            let confidence = if top[0].get("confidence").and_then(|v| v.as_str()) == Some("high") {
                "high"
            } else {
                "medium"
            };
            return Classified {
                status: "modified".into(),
                confidence: confidence.into(),
                node_ids: vec![node_id],
                limitations: vec!["Location evidence links the source to the current node, but their source digests differ.".into()],
            };
        }
        return Classified {
            status: "unknown".into(),
            confidence: "unknown".into(),
            node_ids: if node_id.is_empty() { Vec::new() } else { vec![node_id] },
            limitations: vec!["Location evidence links the source to the current node, but comparable source digests are unavailable.".into()],
        };
    }
    if top.len() > 1 {
        return Classified {
            status: "split".into(),
            confidence: "medium".into(),
            node_ids: top.iter().filter_map(|c| node_id_of(c)).collect(),
            limitations: vec!["Multiple equally scored current nodes retain the historical source path; this is a static split inference, not runtime proof.".into()],
        };
    }
    if !candidates.is_empty() {
        return Classified {
            status: "unknown".into(),
            confidence: "unknown".into(),
            node_ids: Vec::new(),
            limitations: vec!["Only weak basename or extension signals were available; no mapping was forced.".into()],
        };
    }
    if absence_complete {
        Classified {
            status: "removed".into(),
            confidence: "high".into(),
            node_ids: Vec::new(),
            limitations: vec!["No retained current node matched exact digest or path signals within complete static inventories.".into()],
        }
    } else {
        Classified {
            status: "unknown".into(),
            confidence: "unknown".into(),
            node_ids: Vec::new(),
            limitations: vec!["No candidate was observed, but incomplete input or graph coverage prevents a removal claim.".into()],
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn item_value(
    reference_root: &str,
    graph_id: &str,
    source: &SourceFile,
    status: &str,
    confidence: &str,
    node_ids: &[String],
    candidates: &[Value],
    limitations: &[String],
) -> Result<Value, JsError> {
    let semantic = json!({
        "source_path": source.path,
        "source_sha256": source.sha256,
        "source_language": source.language,
        "status": status,
        "confidence": confidence,
        "current_node_ids": node_ids,
        "candidates": candidates,
        "limitations": limitations,
    });
    let mapping_id = mapping_id(reference_root, graph_id, &semantic)?;
    Ok(json!({
        "mapping_id": mapping_id,
        "source_path": source.path,
        "source_sha256": source.sha256,
        "source_language": source.language,
        "status": status,
        "confidence": confidence,
        "current_node_ids": node_ids,
        "candidates": candidates,
        "limitations": limitations,
    }))
}

pub(crate) fn mark_merged(reference_root: &str, graph_id: &str, items: Vec<Value>) -> Result<Vec<Value>, JsError> {
    let mut by_node: HashMap<String, Vec<String>> = HashMap::new();
    for item in &items {
        if item.get("status").and_then(|v| v.as_str()) != Some("unchanged") {
            continue;
        }
        let ids = item.get("current_node_ids").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        if ids.len() != 1 {
            continue;
        }
        let Some(node_id) = ids[0].as_str() else { continue };
        let path = item.get("source_path").and_then(|v| v.as_str()).unwrap_or("").to_string();
        by_node.entry(node_id.to_string()).or_default().push(path);
    }
    let merged: HashSet<String> = by_node
        .into_values()
        .filter(|group| group.len() > 1)
        .flatten()
        .collect();
    let mut out = Vec::new();
    for mut item in items {
        let path = item.get("source_path").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if !merged.contains(&path) {
            out.push(item);
            continue;
        }
        let mut limitations = string_array(item.get("limitations").unwrap_or(&Value::Null), "limitations")?;
        limitations.push(
            "Multiple historical source paths have exact digest identity with the same current graph node.".into(),
        );
        let limitations = unique_sorted(&limitations);
        if let Some(obj) = item.as_object_mut() {
            obj.insert("status".into(), json!("merged"));
            obj.insert("confidence".into(), json!("exact"));
            obj.insert(
                "limitations".into(),
                Value::Array(limitations.iter().cloned().map(Value::String).collect()),
            );
            obj.remove("mapping_id");
        }
        let mapping_id = mapping_id(reference_root, graph_id, &item)?;
        let mut ordered = Map::new();
        ordered.insert("mapping_id".into(), Value::String(mapping_id));
        if let Some(obj) = item.as_object() {
            for (key, value) in obj {
                if key != "mapping_id" {
                    ordered.insert(key.clone(), value.clone());
                }
            }
        }
        out.push(Value::Object(ordered));
    }
    Ok(out)
}

fn mapping_id(reference_root: &str, graph_id: &str, semantic: &Value) -> Result<String, JsError> {
    let mut body = Map::new();
    body.insert("reference_root_sha256".into(), json!(reference_root));
    body.insert("application_graph_id".into(), json!(graph_id));
    if let Some(obj) = semantic.as_object() {
        for (key, value) in obj {
            if key != "mapping_id" {
                body.insert(key.clone(), value.clone());
            }
        }
    }
    Ok(format!("stbc_item_{}", canonical_sha256(&Value::Object(body))?))
}

pub(crate) fn summary_of(items: &[Value]) -> Value {
    let count = |status: &str| {
        items
            .iter()
            .filter(|item| item.get("status").and_then(|v| v.as_str()) == Some(status))
            .count() as i64
    };
    json!({
        "unchanged": count("unchanged"),
        "modified": count("modified"),
        "removed": count("removed"),
        "split": count("split"),
        "merged": count("merged"),
        "duplicated": count("duplicated"),
        "unknown": count("unknown"),
    })
}

pub(crate) fn comparison_limitations(
    reference: &Value,
    graph: &Value,
    inventory_state: &str,
    coverage_status: &str,
) -> Result<Vec<String>, JsError> {
    let mut limits = vec![STATIC_LIMIT.to_string()];
    limits.extend(string_array(
        reference.get("limitations").unwrap_or(&json!([])),
        "reference.limitations",
    )?);
    limits.extend(string_array(
        graph.get("limitations").unwrap_or(&json!([])),
        "graph.limitations",
    )?);
    if inventory_state != "complete" {
        limits.push(format!(
            "Historical source inventory is {inventory_state}; unmatched files remain unknown."
        ));
    }
    if coverage_status != "complete" {
        limits.push(format!(
            "Application graph coverage is {coverage_status}; unmatched files remain unknown."
        ));
    }
    Ok(unique_sorted(&limits))
}

fn has_signal(candidate: &Value, kind: &str) -> bool {
    candidate
        .get("signals")
        .and_then(|v| v.as_array())
        .is_some_and(|signals| signals.iter().any(|s| s.get("kind").and_then(|v| v.as_str()) == Some(kind)))
}

fn node_id_of(candidate: &Value) -> Option<String> {
    candidate
        .get("current_node_id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}
