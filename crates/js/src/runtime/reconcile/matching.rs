//! Static runtime candidates and conservative runtime matching (port of REA
//! javascriptRuntimeStaticCandidates.ts and javascriptRuntimeReconciliationMatching.ts).

use std::collections::{HashMap, HashSet};

use serde_json::{json, Value};

use crate::application::graph_seal::create_edge;
use crate::digest::digest_canonical_value;
use crate::error::JsError;
use crate::unicode::{compare_unicode_code_points, unique_sorted};

use super::entities::RuntimeEntity;
use super::input::{RuntimeCapture, RuntimeLoc, RuntimeMapping, StaticLayer};
use super::paths::{path_below_root, path_below_url_prefix, path_within_prefix, relative_logical_path, safe_artifact_path};

/// One statically reconstructed entity that can receive runtime matches.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub layer: usize,
    pub layer_id: String,
    pub node_id: String,
    pub category: &'static str,
    pub paths: Vec<String>,
    /// `(sha256, basis)` pairs.
    pub digests: Vec<(String, &'static str)>,
}

impl Candidate {
    fn key(&self) -> String {
        format!("{}:{}", self.layer_id, self.node_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedPath {
    pub path: String,
    pub basis: &'static str,
}

/// Index statically reconstructed entities that can receive runtime matches.
pub fn collect_static_candidates(layers: &[StaticLayer]) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    for (index, layer) in layers.iter().enumerate() {
        let paths = index_static_paths(&layer.graph);
        for node in layer.graph["nodes"].as_array().into_iter().flatten() {
            let Some(category) = candidate_category(node) else {
                continue;
            };
            let node_id = node["node_id"].as_str().unwrap_or_default().to_string();
            candidates.push(Candidate {
                layer: index,
                layer_id: layer.layer_id.clone(),
                paths: paths.get(&node_id).cloned().unwrap_or_default(),
                node_id,
                category,
                digests: candidate_digests(node),
            });
        }
    }
    candidates.sort_by(|left, right| {
        compare_unicode_code_points(&left.layer_id, &right.layer_id)
            .then_with(|| compare_unicode_code_points(&left.node_id, &right.node_id))
    });
    candidates
}

fn candidate_category(node: &Value) -> Option<&'static str> {
    match node["kind"].as_str()? {
        "electron-renderer" => Some("renderer"),
        "javascript-asset" => Some("javascript"),
        "javascript-module" if !is_static_source_module(node) => Some("javascript"),
        "worker" => Some("worker"),
        "service-worker" => Some("service-worker"),
        _ => None,
    }
}

fn is_static_source_module(node: &Value) -> bool {
    node["observations"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|observation| observation["properties"]["semantic_role"] == "source-module")
}

/// Graph paths per node, including the paths of `maps_to` targets.
pub fn index_static_paths(graph: &Value) -> HashMap<String, Vec<String>> {
    let nodes: HashMap<&str, &Value> = graph["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|node| (node["node_id"].as_str().unwrap_or_default(), node))
        .collect();
    let mut related: HashMap<&str, Vec<&Value>> = HashMap::new();
    for edge in graph["edges"].as_array().into_iter().flatten() {
        if edge["relation"] != "maps_to" {
            continue;
        }
        if let Some(target) = edge["target_node_id"].as_str().and_then(|id| nodes.get(id)) {
            related
                .entry(edge["source_node_id"].as_str().unwrap_or_default())
                .or_default()
                .push(target);
        }
    }
    graph["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|node| {
            let id = node["node_id"].as_str().unwrap_or_default();
            let mut paths = node_paths(node);
            for target in related.get(id).into_iter().flatten() {
                paths.extend(node_paths(target));
            }
            (id.to_string(), unique_sorted(&paths))
        })
        .collect()
}

fn node_paths(node: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    if node["identity"]["strategy"] == "canonical-path" {
        if let Some(path) = node["identity"]["path"].as_str() {
            paths.push(path.to_string());
        }
    }
    for observation in node["observations"].as_array().into_iter().flatten() {
        for property in ["path", "resolved_path", "declared_path"] {
            if let Some(path) = observation["properties"][property].as_str() {
                paths.push(path.to_string());
            }
        }
        let location = &observation["evidence"]["location"];
        if location["available"] == true && location["value"]["kind"] == "artifact-path" {
            if let Some(path) = location["value"]["path"].as_str() {
                paths.push(path.to_string());
            }
        }
    }
    paths
        .iter()
        .filter_map(|path| relative_logical_path(path))
        .filter(|path| path != "artifact-root")
        .collect()
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn candidate_digests(node: &Value) -> Vec<(String, &'static str)> {
    let mut values: Vec<(String, &'static str)> = Vec::new();
    if node["kind"] == "javascript-asset" && node["identity"]["strategy"] == "content-digest" {
        if let Some(sha) = node["identity"]["sha256"].as_str() {
            values.push((sha.to_string(), "content-sha256"));
        }
    }
    if node["kind"] == "javascript-module" {
        for observation in node["observations"].as_array().into_iter().flatten() {
            if let Some(sha) = observation["properties"]["source_sha256"].as_str().filter(|s| is_sha256(s)) {
                values.push((sha.to_string(), "module-source-sha256"));
            }
        }
    }
    let mut seen = HashSet::new();
    values.retain(|(sha, basis)| seen.insert(format!("{basis}:{sha}")));
    values
}

/// Translate one already-authorized runtime location into artifact paths.
pub fn mapped_runtime_paths(layer: &StaticLayer, location: &RuntimeLoc) -> Vec<MappedPath> {
    let mut paths = Vec::new();
    if let (RuntimeLoc::File(file), "directory") = (location, layer.format.as_str()) {
        if let Some(path) = path_below_root(&layer.input_path, file) {
            paths.push(MappedPath { path, basis: "artifact-path" });
        }
    }
    for mapping in &layer.runtime_mappings {
        let suffix = match (mapping, location) {
            (RuntimeMapping::FileRoot { root, .. }, RuntimeLoc::File(file)) => path_below_root(root, file),
            (RuntimeMapping::UrlPrefix { prefix, .. }, RuntimeLoc::Url(url)) => path_below_url_prefix(prefix, url),
            _ => None,
        };
        let Some(path) = suffix.and_then(|suffix| safe_artifact_path(mapping.artifact_prefix(), &suffix)) else {
            continue;
        };
        paths.push(MappedPath {
            path,
            basis: match mapping {
                RuntimeMapping::FileRoot { .. } => "operator-file-mapping",
                RuntimeMapping::UrlPrefix { .. } => "operator-url-mapping",
            },
        });
    }
    let mut seen = HashSet::new();
    paths.retain(|mapped| seen.insert(format!("{}:{}", mapped.basis, mapped.path)));
    paths.sort_by(|left, right| {
        compare_unicode_code_points(&left.path, &right.path).then_with(|| compare_unicode_code_points(left.basis, right.basis))
    });
    paths
}

/// Artifact prefixes exercised by a bounded runtime set.
pub fn active_artifact_prefixes(layer: &StaticLayer, entities: &[RuntimeEntity]) -> Vec<String> {
    let mut prefixes: Vec<String> = Vec::new();
    if layer.format == "directory"
        && entities.iter().any(|entity| {
            matches!(&entity.location, RuntimeLoc::File(file) if path_below_root(&layer.input_path, file).is_some())
        })
    {
        prefixes.push(String::new());
    }
    for mapping in &layer.runtime_mappings {
        let exercised = entities.iter().any(|entity| match (mapping, &entity.location) {
            (RuntimeMapping::FileRoot { root, .. }, RuntimeLoc::File(file)) => path_below_root(root, file).is_some(),
            (RuntimeMapping::UrlPrefix { prefix, .. }, RuntimeLoc::Url(url)) => {
                path_below_url_prefix(prefix, url).is_some()
            }
            _ => false,
        });
        if exercised {
            prefixes.push(mapping.artifact_prefix().to_string());
        }
    }
    unique_sorted(&prefixes)
}

/// Whether any of a node's paths falls under an exercised prefix.
pub fn node_within_runtime_scope(paths: &[String], prefixes: &[String]) -> bool {
    paths.iter().any(|path| prefixes.iter().any(|prefix| path_within_prefix(path, prefix)))
}

pub struct MatchingProjection {
    pub items: Vec<Value>,
    pub edges: Vec<Value>,
    pub omitted_items: u64,
}

struct CandidateIndex<'a> {
    by_category_digest: HashMap<String, Vec<&'a Candidate>>,
    by_layer_category_path: HashMap<String, Vec<&'a Candidate>>,
}

struct Located<'a> {
    candidate: &'a Candidate,
    mapping: MappedPath,
}

/// Match runtime entities conservatively and emit only inferred observed_as edges.
pub fn reconcile_runtime_entities(
    entities: &[RuntimeEntity],
    captures: &[RuntimeCapture],
    candidates: &[Candidate],
    layers: &[StaticLayer],
) -> Result<MatchingProjection, JsError> {
    let mut index = CandidateIndex {
        by_category_digest: HashMap::new(),
        by_layer_category_path: HashMap::new(),
    };
    for candidate in candidates {
        for (sha, _) in &candidate.digests {
            index
                .by_category_digest
                .entry(format!("{}\0{sha}", candidate.category))
                .or_default()
                .push(candidate);
        }
        for path in &candidate.paths {
            index
                .by_layer_category_path
                .entry(format!("{}\0{}\0{path}", candidate.layer_id, candidate.category))
                .or_default()
                .push(candidate);
        }
    }
    let mut evaluated = Vec::new();
    for entity in entities {
        evaluated.push(reconcile_entity(entity, &captures[entity.capture], &index, layers)?);
    }
    evaluated.sort_by(|left, right| {
        compare_unicode_code_points(
            left.0["reconciliation_id"].as_str().unwrap_or_default(),
            right.0["reconciliation_id"].as_str().unwrap_or_default(),
        )
    });
    let mut items = Vec::new();
    let mut edges = Vec::new();
    for (item, edge) in evaluated {
        items.push(item);
        edges.extend(edge);
    }
    Ok(MatchingProjection {
        items,
        edges,
        omitted_items: 0,
    })
}

struct Outcome<'a> {
    status: &'static str,
    basis: &'static str,
    confidence: &'static str,
    reason: &'static str,
    candidates: Vec<&'a Candidate>,
}

fn reconcile_entity(
    entity: &RuntimeEntity,
    capture: &RuntimeCapture,
    index: &CandidateIndex<'_>,
    layers: &[StaticLayer],
) -> Result<(Value, Option<Value>), JsError> {
    if matches!(entity.location, RuntimeLoc::Unresolved(_)) {
        return unresolved(entity, capture, Outcome {
            status: "unknown",
            basis: "none",
            confidence: "unknown",
            reason: "runtime-location-unresolved",
            candidates: vec![],
        });
    }
    let locations = candidates_with_location(entity, index, layers);
    if let Some(source) = &entity.source_sha256 {
        let content: Vec<&Candidate> = index
            .by_category_digest
            .get(&format!("{}\0{source}", entity.static_kind))
            .cloned()
            .unwrap_or_default();
        let located: HashSet<String> = locations.iter().map(|l| l.candidate.key()).collect();
        let combined: Vec<&Candidate> = content.iter().copied().filter(|c| located.contains(&c.key())).collect();
        if combined.len() == 1 {
            return matched(entity, capture, combined[0], &layers[combined[0].layer], "content-and-location", "high", "content-and-location-match");
        }
        if content.len() == 1 {
            let candidate = content[0];
            let basis = candidate
                .digests
                .iter()
                .find(|(sha, _)| sha == source)
                .map(|(_, basis)| *basis)
                .unwrap_or("content-sha256");
            return matched(entity, capture, candidate, &layers[candidate.layer], basis, "high", "unique-content-match");
        }
        if content.len() > 1 {
            return unresolved(entity, capture, Outcome {
                status: "ambiguous",
                basis: "none",
                confidence: "unknown",
                reason: "ambiguous-static-candidates",
                candidates: content,
            });
        }
        if !locations.is_empty() {
            return unresolved(entity, capture, Outcome {
                status: "unmatched",
                basis: strongest_location_basis(&locations),
                confidence: "high",
                reason: "captured-content-disagrees-with-static-location",
                candidates: locations.iter().map(|l| l.candidate).collect(),
            });
        }
        return unresolved(entity, capture, Outcome {
            status: "unmatched",
            basis: "none",
            confidence: "high",
            reason: "no-static-content-match",
            candidates: vec![],
        });
    }
    if locations.len() == 1 {
        let located = &locations[0];
        return matched(
            entity,
            capture,
            located.candidate,
            &layers[located.candidate.layer],
            located.mapping.basis,
            "medium",
            "unique-location-match",
        );
    }
    if locations.len() > 1 {
        return unresolved(entity, capture, Outcome {
            status: "ambiguous",
            basis: strongest_location_basis(&locations),
            confidence: "unknown",
            reason: "ambiguous-static-candidates",
            candidates: locations.iter().map(|l| l.candidate).collect(),
        });
    }
    let mapped = layers.iter().any(|layer| !mapped_runtime_paths(layer, &entity.location).is_empty());
    unresolved(entity, capture, Outcome {
        status: if mapped { "unmatched" } else { "unknown" },
        basis: "none",
        confidence: "unknown",
        reason: if mapped { "no-static-content-match" } else { "no-authorized-location-mapping" },
        candidates: vec![],
    })
}

fn candidates_with_location<'a>(
    entity: &RuntimeEntity,
    index: &CandidateIndex<'a>,
    layers: &[StaticLayer],
) -> Vec<Located<'a>> {
    let mut located: Vec<Located<'a>> = Vec::new();
    let mut seen = HashSet::new();
    for layer in layers {
        for mapping in mapped_runtime_paths(layer, &entity.location) {
            let key = format!("{}\0{}\0{}", layer.layer_id, entity.static_kind, mapping.path);
            for candidate in index.by_layer_category_path.get(&key).into_iter().flatten() {
                if seen.insert(candidate.key()) {
                    located.push(Located {
                        candidate,
                        mapping: mapping.clone(),
                    });
                }
            }
        }
    }
    located.sort_by(|left, right| compare_unicode_code_points(&left.candidate.key(), &right.candidate.key()));
    located
}

fn strongest_location_basis(values: &[Located<'_>]) -> &'static str {
    let has = |basis: &str| values.iter().any(|l| l.mapping.basis == basis);
    if has("artifact-path") {
        "artifact-path"
    } else if has("operator-file-mapping") {
        "operator-file-mapping"
    } else {
        "operator-url-mapping"
    }
}

fn create_item(
    entity: &RuntimeEntity,
    capture: &RuntimeCapture,
    matched: Option<(&str, &str)>,
    outcome: &Outcome<'_>,
) -> Result<Value, JsError> {
    let mut seen = HashSet::new();
    let mut references = Vec::new();
    for candidate in &outcome.candidates {
        if seen.insert(candidate.key()) {
            references.push(json!({ "static_layer_id": candidate.layer_id, "static_node_id": candidate.node_id }));
        }
    }
    let (layer_id, node_id) = match matched {
        Some((layer, node)) => (json!(layer), json!(node)),
        None => (Value::Null, Value::Null),
    };
    let mut semantic = json!({
        "entity_kind": entity.kind.as_str(),
        "runtime_evidence_id": capture.evidence.evidence_id,
        "runtime_node_id": entity.node_id(),
        "static_layer_id": layer_id,
        "static_node_id": node_id,
        "status": outcome.status,
        "basis": outcome.basis,
        "confidence": outcome.confidence,
        "reason": outcome.reason,
        "candidate_static_count": references.len(),
        "candidate_static_nodes": references,
    });
    let id = format!("jrr_item_{}", digest_canonical_value(&semantic)?);
    semantic["reconciliation_id"] = json!(id);
    Ok(semantic)
}

fn unresolved(entity: &RuntimeEntity, capture: &RuntimeCapture, outcome: Outcome<'_>) -> Result<(Value, Option<Value>), JsError> {
    Ok((create_item(entity, capture, None, &outcome)?, None))
}

fn matched(
    entity: &RuntimeEntity,
    capture: &RuntimeCapture,
    candidate: &Candidate,
    layer: &StaticLayer,
    basis: &'static str,
    confidence: &'static str,
    reason: &'static str,
) -> Result<(Value, Option<Value>), JsError> {
    let outcome = Outcome {
        status: "matched",
        basis,
        confidence,
        reason,
        candidates: vec![candidate],
    };
    let item = create_item(entity, capture, Some((&candidate.layer_id, &candidate.node_id)), &outcome)?;
    let artifact = match &entity.source_sha256 {
        Some(sha) => json!({ "available": true, "artifact_id": format!("art_{sha}"), "sha256": sha }),
        None => json!({
            "available": false,
            "reason": "not-observed",
            "detail": "Runtime source bytes were not captured for this mapping.",
        }),
    };
    let complete = layer.coverage_complete() && capture.scripts_complete_within_scope;
    let coverage = if complete {
        json!({ "status": "complete", "truncated": false, "omitted_count": 0, "limits": [] })
    } else {
        json!({ "status": "partial", "truncated": false, "omitted_count": null, "limits": [] })
    };
    let byte_identity = matches!(basis, "content-sha256" | "module-source-sha256" | "content-and-location");
    let mut evidence_ids = vec![layer.evidence.evidence_id.clone(), capture.evidence.evidence_id.clone()];
    evidence_ids.sort();
    let edge = create_edge(&json!({
        "source_node_id": candidate.node_id,
        "target_node_id": entity.node_id(),
        "relation": "observed_as",
        "properties": {
            "reconciliation_id": item["reconciliation_id"],
            "basis": basis,
            "static_layer_id": candidate.layer_id,
        },
        "evidence": {
            "authority": "cross-layer-reconciliation",
            "state": "inferred",
            "confidence": if confidence == "medium" { "medium" } else { "high" },
            "artifact": artifact,
            "location": entity.node["observations"][0]["evidence"]["location"],
            "extractor": {
                "name": "rea-javascript-runtime-reconciliation",
                "version": "1",
                "operation": "reconcile_javascript_runtime",
                "executable_sha256": null,
            },
            "coverage": coverage,
            "limitations": [
                if byte_identity {
                    "Equal content digests establish byte identity, not execution causality."
                } else {
                    "Location correspondence is inferred from an artifact root or caller-declared mapping."
                },
                "Passive script parsing or target presence does not prove feature execution.",
            ],
            "evidence_ids": evidence_ids,
        },
    }))?;
    Ok((item, Some(edge)))
}
