//! Static load states, the combined application graph, and the reconciliation
//! result (port of REA javascriptRuntimeLoadState.ts,
//! javascriptRuntimeReconciliationGraph.ts and
//! javascriptRuntimeReconciliationResult.ts).

use std::collections::{HashMap, HashSet};

use serde_json::{json, Value};

use crate::application::graph_seal::{recreate_node, seal_application_graph};
use crate::digest::digest_canonical_value;
use crate::error::JsError;
use crate::unicode::unique_sorted;

use super::entities::{EntityKind, RuntimeProjection};
use super::input::{RuntimeCapture, RuntimeLoc, StaticLayer};
use super::matching::{active_artifact_prefixes, index_static_paths, mapped_runtime_paths, node_within_runtime_scope, MatchingProjection};

fn str_of<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or_default()
}

/// Classify static code presence without claiming bundled module execution.
pub fn classify_static_load_states(
    layers: &[StaticLayer],
    captures: &[RuntimeCapture],
    runtime: &RuntimeProjection,
    matches: &[Value],
    reconciliation_complete: bool,
) -> Vec<Value> {
    let mut states = Vec::new();
    for layer in layers {
        let mut direct: Vec<(String, Vec<String>)> = Vec::new();
        for item in matches {
            if item["status"] == "matched" && item["static_layer_id"] == layer.layer_id.as_str() {
                let node = str_of(item, "static_node_id").to_string();
                let runtime_node = str_of(item, "runtime_node_id").to_string();
                match direct.iter_mut().find(|(id, _)| *id == node) {
                    Some((_, values)) => values.push(runtime_node),
                    None => direct.push((node, vec![runtime_node])),
                }
            }
        }
        let resident = resident_nodes(layer, &direct);
        let prefixes = active_artifact_prefixes(layer, &runtime.entities);
        let paths = index_static_paths(&layer.graph);
        let scoped: Vec<_> = runtime
            .entities
            .iter()
            .filter(|entity| !mapped_runtime_paths(layer, &entity.location).is_empty())
            .collect();
        let layer_complete = reconciliation_complete
            && layer.coverage_complete()
            && !scoped.is_empty()
            && scoped.iter().all(|entity| captures[entity.capture].scripts_complete_within_scope);
        for node in layer.graph["nodes"].as_array().into_iter().flatten() {
            let kind = str_of(node, "kind");
            if !matches!(kind, "javascript-asset" | "javascript-chunk" | "javascript-module") {
                continue;
            }
            let node_id = str_of(node, "node_id");
            let runtime_ids = direct
                .iter()
                .find(|(id, _)| id == node_id)
                .map(|(_, values)| unique_sorted(values))
                .unwrap_or_default();
            let within = node_within_runtime_scope(paths.get(node_id).map(Vec::as_slice).unwrap_or(&[]), &prefixes);
            let (status, reason) = if !runtime_ids.is_empty() {
                ("loaded", "runtime-script-correspondence")
            } else if resident.contains(node_id) {
                ("resident-in-loaded-asset", "containing-asset-was-loaded")
            } else if layer_complete && within {
                ("not-observed-in-capture", "not-observed-in-bounded-capture")
            } else if !within {
                ("unknown", "layer-outside-runtime-scope")
            } else {
                ("unknown", "static-or-runtime-coverage-incomplete")
            };
            states.push(json!({
                "static_layer_id": layer.layer_id,
                "static_node_id": node_id,
                "kind": kind,
                "status": status,
                "runtime_node_ids": runtime_ids,
                "reason": reason,
            }));
        }
    }
    states
}

fn resident_nodes(layer: &StaticLayer, direct: &[(String, Vec<String>)]) -> HashSet<String> {
    let kinds: HashMap<&str, &str> = layer.graph["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|node| (str_of(node, "node_id"), str_of(node, "kind")))
        .collect();
    let mut children: HashMap<&str, Vec<&str>> = HashMap::new();
    for edge in layer.graph["edges"].as_array().into_iter().flatten() {
        if edge["relation"] == "contains" {
            children.entry(str_of(edge, "source_node_id")).or_default().push(str_of(edge, "target_node_id"));
        }
    }
    let mut pending: Vec<&str> = direct
        .iter()
        .map(|(id, _)| id.as_str())
        .filter(|id| kinds.get(id) == Some(&"javascript-asset"))
        .collect();
    let mut resident = HashSet::new();
    let mut index = 0;
    while index < pending.len() {
        let current = pending[index];
        index += 1;
        for child in children.get(current).into_iter().flatten() {
            if resident.insert(child.to_string()) {
                pending.push(child);
            }
        }
    }
    resident
}

/// Merge source graphs, runtime nodes, and inferred mappings into one valid JAG.
pub fn build_reconciled_graph(
    layers: &[StaticLayer],
    captures: &[RuntimeCapture],
    runtime: &RuntimeProjection,
    reconciliation_edges: &[Value],
    omitted_reconciliation_items: u64,
) -> Result<(Value, u64), JsError> {
    let mut all_nodes: Vec<Value> = Vec::new();
    for layer in layers {
        all_nodes.extend(layer.graph["nodes"].as_array().into_iter().flatten().cloned());
    }
    all_nodes.extend(runtime.nodes.iter().cloned());
    let nodes = merge_nodes(&all_nodes)?;

    let mut edges: Vec<Value> = Vec::new();
    let mut edge_ids = HashSet::new();
    for layer in layers {
        for edge in layer.graph["edges"].as_array().into_iter().flatten() {
            if edge_ids.insert(str_of(edge, "edge_id").to_string()) {
                edges.push(edge.clone());
            }
        }
    }
    for edge in runtime.edges.iter().chain(reconciliation_edges) {
        if edge_ids.insert(str_of(edge, "edge_id").to_string()) {
            edges.push(edge.clone());
        }
    }
    let node_ids: HashSet<&str> = nodes.iter().map(|node| str_of(node, "node_id")).collect();
    edges.retain(|edge| node_ids.contains(str_of(edge, "source_node_id")) && node_ids.contains(str_of(edge, "target_node_id")));

    let mut roots: Vec<String> = runtime.target_nodes.iter().map(|(_, node)| str_of(node, "node_id").to_string()).collect();
    for application in [true, false] {
        for layer in layers.iter().filter(|layer| (layer.role == "application") == application) {
            roots.extend(layer.graph["root_node_ids"].as_array().into_iter().flatten().filter_map(|id| id.as_str().map(str::to_string)));
        }
    }

    let omitted_graph_items = 0u64;
    let projection_omissions = runtime.omitted_entities + omitted_reconciliation_items + omitted_graph_items;
    let capture_truncated = captures.iter().any(|capture| capture.inspection.has_condition("truncated"));
    let capture_unknown_omissions = captures.iter().any(|capture| capture.inspection.has_unavailable_sections());
    let input_truncated = layers.iter().any(StaticLayer::coverage_truncated) || capture_truncated;
    let input_complete = layers.iter().all(StaticLayer::coverage_complete)
        && captures.iter().all(|capture| capture.inspection.complete_within_window());
    let output_truncated = projection_omissions > 0;
    let source_omissions: u64 = layers.iter().map(|layer| layer.graph["coverage"]["omitted_count"].as_u64().unwrap_or(0)).sum();
    let omissions_known = !capture_truncated
        && !capture_unknown_omissions
        && layers.iter().all(|layer| !layer.graph["coverage"]["omitted_count"].is_null());
    let known = if omissions_known { json!(projection_omissions + source_omissions) } else { Value::Null };
    let input_status = if input_truncated {
        "truncated"
    } else if input_complete {
        "complete"
    } else {
        "partial"
    };
    let coverage = if input_status == "complete" && !output_truncated {
        json!({ "status": "complete", "truncated": false, "omitted_count": 0, "limits": [] })
    } else if input_status == "truncated" || output_truncated {
        let mut limits = Vec::new();
        if input_status == "truncated" {
            limits.push(json!({
                "name": "runtime-reconciliation-input-coverage",
                "value": layers.len() + captures.len(),
                "unit": "items",
            }));
        }
        if output_truncated {
            limits.push(json!({ "name": "runtime-reconciliation-output-limits", "value": nodes.len(), "unit": "items" }));
        }
        json!({ "status": "partial", "truncated": true, "omitted_count": known, "limits": limits })
    } else {
        json!({ "status": "partial", "truncated": false, "omitted_count": known, "limits": [] })
    };

    let mut limitations: Vec<String> = Vec::new();
    for layer in layers {
        limitations.extend(layer.graph["limitations"].as_array().into_iter().flatten().filter_map(|l| l.as_str().map(str::to_string)));
    }
    limitations.extend(
        [
            "Runtime presence is bounded to passive capture windows and does not prove feature execution.",
            "Cross-layer observed_as edges are inferences; digest equality proves byte identity only.",
            "Source-map relationships retain their original static authority and are not promoted into runtime matches.",
        ]
        .map(str::to_string),
    );
    if input_status == "truncated" {
        limitations.push("One or more source graphs or passive captures were incomplete or truncated.".to_string());
    }
    if output_truncated {
        limitations.push("The reconciled graph omitted entities or classifications during projection.".to_string());
    }
    let graph = seal_application_graph(&json!({
        "schema": "JavaScriptApplicationGraph",
        "root_node_ids": roots,
        "nodes": nodes,
        "edges": edges,
        "coverage": coverage,
        "limitations": limitations,
    }))?;
    Ok((graph, omitted_graph_items))
}

fn merge_nodes(nodes: &[Value]) -> Result<Vec<Value>, JsError> {
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<&Value>> = HashMap::new();
    for node in nodes {
        let id = str_of(node, "node_id").to_string();
        if !groups.contains_key(&id) {
            order.push(id.clone());
        }
        groups.entry(id).or_default().push(node);
    }
    let mut merged = Vec::new();
    for id in order {
        let group = &groups[&id];
        let first = group[0];
        if group.iter().any(|node| node["kind"] != first["kind"] || node["identity"] != first["identity"]) {
            return Err(JsError::Integrity("Colliding JAG node identifiers disagree".into()));
        }
        if group.len() == 1 {
            merged.push(first.clone());
            continue;
        }
        let mut seen = HashSet::new();
        let observations: Vec<Value> = group
            .iter()
            .flat_map(|node| node["observations"].as_array().cloned().unwrap_or_default())
            .filter(|observation| seen.insert(str_of(observation, "observation_id").to_string()))
            .collect();
        merged.push(recreate_node(&json!({
            "kind": first["kind"],
            "identity": first["identity"],
            "observations": observations,
        }))?);
    }
    Ok(merged)
}

/// Build the deterministic caller-visible reconciliation result.
pub fn create_reconciliation_result(
    layers: &[StaticLayer],
    captures: &[RuntimeCapture],
    runtime: &RuntimeProjection,
    matching: &MatchingProjection,
    load_states: Vec<Value>,
    graph: Value,
    omitted_graph_items: u64,
) -> Result<Value, JsError> {
    let input_truncated = layers.iter().any(StaticLayer::coverage_truncated)
        || captures.iter().any(|capture| capture.inspection.has_condition("truncated"));
    let input_partial = layers.iter().any(|layer| !layer.coverage_complete())
        || captures.iter().any(|capture| !capture.inspection.complete_within_window());
    let omitted_static_load_states = 0u64;
    let output_truncated = runtime.omitted_entities > 0
        || matching.omitted_items > 0
        || omitted_static_load_states > 0
        || omitted_graph_items > 0;
    let input_status = if input_truncated {
        "truncated"
    } else if input_partial {
        "partial"
    } else {
        "complete"
    };

    let static_layers: Vec<Value> = layers
        .iter()
        .map(|layer| {
            json!({
                "layer_id": layer.layer_id,
                "role": layer.role,
                "evidence_id": layer.evidence.evidence_id,
                "graph_id": layer.graph["graph_id"],
                "root_artifact_sha256": layer.root_artifact_sha256,
                "input_path": layer.input_path,
                "format": layer.format,
                "runtime_mappings": layer.runtime_mappings.iter().map(|m| m.to_json()).collect::<Vec<_>>(),
            })
        })
        .collect();
    let mut runtime_captures = Vec::new();
    for capture in captures {
        let target_node = runtime
            .target_nodes
            .iter()
            .find(|(id, _)| *id == capture.evidence.evidence_id)
            .map(|(_, node)| node)
            .ok_or_else(|| JsError::Integrity("Runtime projection omitted a required target node".into()))?;
        let target_location = match &capture.inspection.target.location {
            RuntimeLoc::Unresolved(location) => location.clone(),
            other => json!(other.value()),
        };
        runtime_captures.push(json!({
            "evidence_id": capture.evidence.evidence_id,
            "capture_sha256": capture.capture_sha256,
            "kind": capture.kind,
            "target_node_id": target_node["node_id"],
            "target_key": capture.inspection.target.target_id,
            "target_location": target_location,
            "frames": capture.inspection.frames.len(),
            "scripts": capture.inspection.scripts.len(),
            "workers": capture.inspection.workers.len(),
            "scripts_complete_within_scope": capture.scripts_complete_within_scope,
        }));
    }
    let count_entities = |kind: EntityKind| runtime.entities.iter().filter(|e| e.kind == kind).count();
    let count_status = |items: &[Value], status: &str| items.iter().filter(|item| item["status"] == status).count();
    let summary = json!({
        "runtime_targets": count_entities(EntityKind::Target),
        "runtime_frames": count_entities(EntityKind::Frame),
        "runtime_scripts": count_entities(EntityKind::Script),
        "runtime_workers": count_entities(EntityKind::Worker),
        "matched": count_status(&matching.items, "matched"),
        "ambiguous": count_status(&matching.items, "ambiguous"),
        "unmatched": count_status(&matching.items, "unmatched"),
        "unknown": count_status(&matching.items, "unknown"),
        "static_loaded": count_status(&load_states, "loaded"),
        "static_resident": count_status(&load_states, "resident-in-loaded-asset"),
        "static_not_observed": count_status(&load_states, "not-observed-in-capture"),
        "static_unknown": count_status(&load_states, "unknown"),
    });
    let runtime_script_declarations: usize = captures
        .iter()
        .filter(|capture| capture.kind == "browser")
        .map(|capture| {
            capture
                .inspection
                .scripts
                .iter()
                .filter(|script| script.source_map_url.as_ref().is_some_and(|url| !url.is_null()))
                .count()
        })
        .sum();
    let truncated = output_truncated || input_status == "truncated";
    let coverage = json!({
        "status": if truncated { "truncated" } else if input_status == "partial" { "partial" } else { "complete-within-inputs" },
        "truncated": truncated,
        "omitted_runtime_entities": runtime.omitted_entities,
        "omitted_reconciliation_items": matching.omitted_items,
        "omitted_static_load_states": omitted_static_load_states,
        "omitted_graph_items": omitted_graph_items,
    });
    let mut links: Vec<String> = layers.iter().map(|layer| layer.evidence.evidence_id.clone()).collect();
    links.extend(captures.iter().map(|capture| capture.evidence.evidence_id.clone()));
    let mut limitations: Vec<String> = [
        "Only caller-supplied, semantically verified Evidence records were reconciled.",
        "Digest equality establishes byte identity but not code reachability, module initialization, or feature execution.",
        "A static module resident in an observed bundle is not reported as executed.",
        "Not-observed means absent from the bounded captures in scope, never globally unloaded.",
        "Caller-declared file and URL mappings are inference inputs and do not expand CDP origin or filesystem-root authority.",
        "Source-map authority remains separate from passive runtime authority.",
    ]
    .map(str::to_string)
    .to_vec();
    if input_status != "complete" {
        limitations.push("One or more static graphs or passive captures were incomplete.".to_string());
    }
    if output_truncated {
        limitations.push("Runtime reconciliation omitted entities or classifications during projection.".to_string());
    }
    let mut semantic = json!({
        "static_layers": static_layers,
        "runtime_captures": runtime_captures,
        "graph": graph,
        "summary": summary,
        "reconciliations": matching.items,
        "static_load_states": load_states,
        "source_map_authority": {
            "used_for_primary_matching": false,
            "static_layer_count": layers.len(),
            "runtime_script_declarations": runtime_script_declarations,
            "limitation": "Source-map declarations and original-source content retain separate static authority and are not used as primary runtime byte matches.",
        },
        "coverage": coverage,
        "evidence_links": unique_sorted(&links),
        "limitations": unique_sorted(&limitations),
    });
    let id = format!("jrr_{}", digest_canonical_value(&semantic)?);
    semantic["reconciliation_id"] = json!(id);
    Ok(semantic)
}
