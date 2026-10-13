//! `compare_application_versions` — tiered identity comparison of two application graphs.

use std::collections::{HashMap, HashSet};

use serde_json::{json, Value};
use tracewise_domain::canonical::canonical_json;
use tracewise_domain::evidence::Evidence;

use crate::error::JsError;
use crate::unicode::{compare_unicode_code_points, unique_sorted};

use super::feature_trace::application_graph;
use super::graph_seal::{canonical_text, create_edge, digest_prefixed, recreate_node, seal_application_graph};
use super::workflow::workflow_evidence;

const AMBIGUOUS_MATCH_LIMITATION: &str =
    "Multiple nodes share the same permitted match key; no cross-version pair was selected.";
const INCOMPLETE_GRAPH_LIMITATION: &str =
    "The opposite graph is incomplete, so an unmatched node cannot be classified as added or removed.";

pub fn compare_application_versions(
    left: &Evidence,
    right: &Evidence,
    left_native: &[Evidence],
    right_native: &[Evidence],
) -> Result<Evidence, JsError> {
    if left.evidence_id == right.evidence_id {
        return Err(JsError::InvalidInput(
            "Application version Evidence must be distinct".into(),
        ));
    }
    require_unique(left_native, "left_native_observations")?;
    require_unique(right_native, "right_native_observations")?;
    let left_graph = application_graph(left)?;
    let right_graph = application_graph(right)?;
    let left_nodes = left_graph["nodes"].as_array().cloned().unwrap_or_default();
    let right_nodes = right_graph["nodes"].as_array().cloned().unwrap_or_default();
    let matching = match_versions(&left_nodes, &right_nodes);
    let items = classify_items(&matching, left, right, left_graph, right_graph, left_native, right_native)?;
    let change_graph = build_change_graph(left_graph, right_graph, &left.evidence_id, &right.evidence_id, &items)?;
    let evidence_links = unique_sorted(
        &items
            .iter()
            .flat_map(|item| string_list(&item["evidence_links"]))
            .collect::<Vec<_>>(),
    );
    let coverage = comparison_coverage(left_graph, right_graph);
    let mut semantic = json!({
        "left": {
            "evidence_id": left.evidence_id,
            "graph_id": left_graph["graph_id"],
            "root_artifact_sha256": left.normalized_result["root_artifact_sha256"],
        },
        "right": {
            "evidence_id": right.evidence_id,
            "graph_id": right_graph["graph_id"],
            "root_artifact_sha256": right.normalized_result["root_artifact_sha256"],
        },
        "summary": summary(&items),
        "matching": matching_summary(&items),
        "items": items,
        "graph": change_graph,
        "coverage": coverage,
        "evidence_links": evidence_links,
        "limitations": comparison_limitations(left_graph, right_graph),
    });
    let comparison_id = digest_prefixed("javc_", &semantic)?;
    semantic
        .as_object_mut()
        .expect("object")
        .insert("comparison_id".into(), json!(comparison_id));
    let limitations = string_list(semantic.get("limitations").unwrap_or(&Value::Null));
    let links = string_list(semantic.get("evidence_links").unwrap_or(&Value::Null));
    workflow_evidence(
        "compare_application_versions",
        "rea.application-version-comparison",
        json!({
            "left_evidence_id": left.evidence_id,
            "right_evidence_id": right.evidence_id,
            "left_native_evidence_ids": left_native.iter().map(|item| item.evidence_id.clone()).collect::<Vec<_>>(),
            "right_native_evidence_ids": right_native.iter().map(|item| item.evidence_id.clone()).collect::<Vec<_>>(),
        }),
        semantic,
        limitations,
        links,
    )
}

struct Pair {
    left: Value,
    right: Value,
    basis: &'static str,
    confidence: &'static str,
}

struct Matching {
    pairs: Vec<Pair>,
    unmatched_left: Vec<Value>,
    unmatched_right: Vec<Value>,
    candidates_for_left: HashMap<String, Vec<String>>,
    candidates_for_right: HashMap<String, Vec<String>>,
}

/// Basis, confidence and key extractor of one matching tier.
type TierSpec = (&'static str, &'static str, fn(&Value) -> Option<String>);

fn match_versions(left_nodes: &[Value], right_nodes: &[Value]) -> Matching {
    let mut left: HashMap<String, Value> = left_nodes
        .iter()
        .map(|node| (node["node_id"].as_str().unwrap_or("").to_string(), node.clone()))
        .collect();
    let mut right: HashMap<String, Value> = right_nodes
        .iter()
        .map(|node| (node["node_id"].as_str().unwrap_or("").to_string(), node.clone()))
        .collect();
    let mut left_candidates: HashMap<String, HashSet<String>> = HashMap::new();
    let mut right_candidates: HashMap<String, HashSet<String>> = HashMap::new();
    let mut pairs = Vec::new();
    let tiers: &[TierSpec] = &[
        ("exact-content-digest", "exact", content_digest_key),
        ("exact-module-source-digest", "exact", module_source_digest_key),
        ("exact-node-identity", "exact", node_identity_key),
        ("source-map-identity", "high", source_map_key),
        ("structural-fingerprint", "medium", structural_fingerprint_key),
        ("semantic-key", "medium", semantic_key),
    ];
    for (basis, confidence, key_for) in tiers {
        apply_tier(&mut left, &mut right, &mut pairs, &mut left_candidates, &mut right_candidates, basis, confidence, *key_for);
    }
    let unmatched_left = sorted_nodes(left.into_values());
    let unmatched_right = sorted_nodes(right.into_values());
    let left_ids: HashSet<String> = unmatched_left.iter().map(|node| node["node_id"].as_str().unwrap_or("").to_string()).collect();
    let right_ids: HashSet<String> = unmatched_right.iter().map(|node| node["node_id"].as_str().unwrap_or("").to_string()).collect();
    pairs.sort_by(|left, right| {
        compare_unicode_code_points(
            &format!("{}\0{}", left.left["node_id"].as_str().unwrap_or(""), left.right["node_id"].as_str().unwrap_or("")),
            &format!("{}\0{}", right.left["node_id"].as_str().unwrap_or(""), right.right["node_id"].as_str().unwrap_or("")),
        )
    });
    Matching {
        pairs,
        unmatched_left,
        unmatched_right,
        candidates_for_left: filtered_candidates(&left_candidates, &right_ids),
        candidates_for_right: filtered_candidates(&right_candidates, &left_ids),
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_tier(
    left: &mut HashMap<String, Value>,
    right: &mut HashMap<String, Value>,
    pairs: &mut Vec<Pair>,
    left_candidates: &mut HashMap<String, HashSet<String>>,
    right_candidates: &mut HashMap<String, HashSet<String>>,
    basis: &'static str,
    confidence: &'static str,
    key_for: fn(&Value) -> Option<String>,
) {
    let left_by_key = nodes_by_key(left.values(), key_for);
    let right_by_key = nodes_by_key(right.values(), key_for);
    let mut keys: Vec<String> = left_by_key.keys().cloned().collect();
    keys.sort_by(|left, right| compare_unicode_code_points(left, right));
    let mut remove_left = Vec::new();
    let mut remove_right = Vec::new();
    for key in keys {
        let left_group = left_by_key.get(&key).cloned().unwrap_or_default();
        let right_group = right_by_key.get(&key).cloned().unwrap_or_default();
        if right_group.is_empty() {
            continue;
        }
        record_candidates(&left_group, &right_group, left_candidates, right_candidates);
        if left_group.len() != 1 || right_group.len() != 1 {
            continue;
        }
        let left_node = &left_group[0];
        let right_node = &right_group[0];
        pairs.push(Pair {
            left: left_node.clone(),
            right: right_node.clone(),
            basis,
            confidence,
        });
        remove_left.push(left_node["node_id"].as_str().unwrap_or("").to_string());
        remove_right.push(right_node["node_id"].as_str().unwrap_or("").to_string());
    }
    for id in remove_left {
        left.remove(&id);
    }
    for id in remove_right {
        right.remove(&id);
    }
}

fn nodes_by_key<'a>(nodes: impl Iterator<Item = &'a Value>, key_for: fn(&Value) -> Option<String>) -> HashMap<String, Vec<Value>> {
    let mut output: HashMap<String, Vec<Value>> = HashMap::new();
    for node in nodes {
        if let Some(key) = key_for(node) {
            output.entry(key).or_default().push(node.clone());
        }
    }
    output
}

fn record_candidates(
    left: &[Value],
    right: &[Value],
    left_candidates: &mut HashMap<String, HashSet<String>>,
    right_candidates: &mut HashMap<String, HashSet<String>>,
) {
    for left_node in left {
        let id = left_node["node_id"].as_str().unwrap_or("");
        let entry = left_candidates.entry(id.to_string()).or_default();
        for right_node in right {
            entry.insert(right_node["node_id"].as_str().unwrap_or("").to_string());
        }
    }
    for right_node in right {
        let id = right_node["node_id"].as_str().unwrap_or("");
        let entry = right_candidates.entry(id.to_string()).or_default();
        for left_node in left {
            entry.insert(left_node["node_id"].as_str().unwrap_or("").to_string());
        }
    }
}

fn filtered_candidates(candidates: &HashMap<String, HashSet<String>>, retained: &HashSet<String>) -> HashMap<String, Vec<String>> {
    let mut output = HashMap::new();
    for (node_id, values) in candidates {
        let mut filtered: Vec<String> = values.iter().filter(|value| retained.contains(*value)).cloned().collect();
        filtered.sort_by(|left, right| compare_unicode_code_points(left, right));
        if !filtered.is_empty() {
            output.insert(node_id.clone(), filtered);
        }
    }
    output
}

fn content_digest_key(node: &Value) -> Option<String> {
    (node["identity"]["strategy"].as_str() == Some("content-digest")).then(|| {
        format!("content\0{}\0{}", node["kind"].as_str().unwrap_or(""), node["identity"]["sha256"].as_str().unwrap_or(""))
    })
}

fn module_source_digest_key(node: &Value) -> Option<String> {
    if node["kind"].as_str() != Some("javascript-module") {
        return None;
    }
    unique_string_property(node, "source_sha256")
        .map(|value| format!("module-source\0{}\0{value}", node["kind"].as_str().unwrap_or("")))
}

fn node_identity_key(node: &Value) -> Option<String> {
    Some(format!("node\0{}\0{}", node["kind"].as_str().unwrap_or(""), node["node_id"].as_str().unwrap_or("")))
}

fn source_map_key(node: &Value) -> Option<String> {
    if node["kind"].as_str() == Some("source-module") && node["identity"]["strategy"].as_str() == Some("source-map-original") {
        let encoded = canonical_json(&json!([node["identity"]["source_root"], node["identity"]["original_source"]])).ok()?;
        Some(format!("source-map\0{encoded}"))
    } else {
        None
    }
}

fn structural_fingerprint_key(node: &Value) -> Option<String> {
    if node["kind"].as_str() != Some("javascript-module") {
        return None;
    }
    let digest = unique_string_property(node, "structural_fingerprint_sha256")?;
    let algorithm = unique_string_property(node, "structural_fingerprint_algorithm")?;
    Some(format!("structural\0{}\0{algorithm}\0{digest}", node["kind"].as_str().unwrap_or("")))
}

fn semantic_key(node: &Value) -> Option<String> {
    let kind = node["kind"].as_str().unwrap_or("");
    if matches!(kind, "javascript-module" | "javascript-chunk" | "runtime-script-instance" | "unknown") {
        return None;
    }
    let properties = node["observations"].as_array().and_then(|items| items.first()).map(|item| item["properties"].clone()).unwrap_or_else(|| json!({}));
    let value = semantic_value(node, &properties)?;
    Some(format!("semantic\0{kind}\0{value}"))
}

fn semantic_value(node: &Value, properties: &Value) -> Option<String> {
    let kind = node["kind"].as_str().unwrap_or("");
    match kind {
        "endpoint" => {
            let endpoint_kind = non_empty_string(&properties["endpoint_kind"])?;
            let value = exact_string(&properties["value"])?;
            Some(format!("{endpoint_kind}\0{value}"))
        }
        "storage" => joined([&properties["storage_kind"], properties.get("name").filter(|value| !value.is_null()).unwrap_or(&properties["mechanism"])]),
        "ipc-channel" => {
            if properties["resolution"].as_str() == Some("dynamic") {
                None
            } else {
                exact_string(&properties["channel"]).or_else(|| first_label(node))
            }
        }
        "context-bridge-api" => first_label(node)
            .or_else(|| exact_string(&properties["api_key"]))
            .or_else(|| non_empty_string(&properties["api_name"])),
        "native-export" => joined_optional(
            [
                properties.get("specifier").cloned(),
                Some(json!(composite_key(&[
                    json!(string_list_sorted(&properties["requested_members"])),
                    bool_or_null(&properties["namespace_access"]),
                    bool_or_null(&properties["dynamic_member_access"]),
                ]))),
            ],
        )
        .or_else(|| first_label(node)),
        "electron-main" | "electron-preload" | "electron-renderer" | "electron-utility" => {
            joined([&properties["declared_path"], &properties["resolved_path"]])
        }
        "package" => non_empty_string(&properties["name"]),
        _ => canonical_path(node).or_else(|| non_empty_string(&properties["path"])),
    }
}

fn joined(values: [&Value; 2]) -> Option<String> {
    let strings = values.map(non_empty_string);
    if strings.iter().any(Option::is_none) {
        None
    } else {
        Some(composite_key(&strings.into_iter().flatten().map(|value| json!(value)).collect::<Vec<_>>()))
    }
}

fn joined_optional(values: [Option<Value>; 2]) -> Option<String> {
    let mut strings = Vec::new();
    for value in values {
        strings.push(non_empty_string(value.as_ref()?)?);
    }
    Some(composite_key(&strings.into_iter().map(|value| json!(value)).collect::<Vec<_>>()))
}

fn composite_key(parts: &[Value]) -> String {
    serde_json::to_string(parts).unwrap_or_else(|_| "[]".to_string())
}

fn canonical_path(node: &Value) -> Option<String> {
    (node["identity"]["strategy"].as_str() == Some("canonical-path"))
        .then(|| node["identity"]["path"].as_str().unwrap_or("").to_string())
        .filter(|path| !path.is_empty())
}

fn first_label(node: &Value) -> Option<String> {
    node["observations"].as_array().and_then(|observations| {
        observations.iter().find_map(|observation| observation["label"].as_str().map(str::to_string))
    })
}

fn unique_string_property(node: &Value, name: &str) -> Option<String> {
    let mut values = HashSet::new();
    if let Some(observations) = node["observations"].as_array() {
        for observation in observations {
            if let Some(value) = observation["properties"][name].as_str() {
                values.insert(value.to_string());
            }
        }
    }
    (values.len() == 1).then(|| values.into_iter().next()).flatten()
}

fn non_empty_string(value: &Value) -> Option<String> {
    value.as_str().filter(|text| !text.is_empty()).map(str::to_string)
}

fn exact_string(value: &Value) -> Option<String> {
    value.as_str().map(str::to_string)
}

fn bool_or_null(value: &Value) -> Value {
    if value.is_boolean() {
        value.clone()
    } else {
        Value::Null
    }
}

fn string_list_sorted(value: &Value) -> Vec<String> {
    let mut values = string_list(value);
    values.sort_by(|left, right| compare_unicode_code_points(left, right));
    values
}

fn sorted_nodes(nodes: impl Iterator<Item = Value>) -> Vec<Value> {
    let mut nodes: Vec<Value> = nodes.collect();
    nodes.sort_by(|left, right| {
        compare_unicode_code_points(left["node_id"].as_str().unwrap_or(""), right["node_id"].as_str().unwrap_or(""))
    });
    nodes
}

fn classify_items(
    matching: &Matching,
    left_evidence: &Evidence,
    right_evidence: &Evidence,
    left_graph: &Value,
    right_graph: &Value,
    left_native: &[Evidence],
    right_native: &[Evidence],
) -> Result<Vec<Value>, JsError> {
    let pair_by_left: HashMap<String, String> = matching
        .pairs
        .iter()
        .map(|pair| {
            let left_id = pair.left["node_id"].as_str().unwrap_or("");
            let right_id = pair.right["node_id"].as_str().unwrap_or("");
            (left_id.to_string(), format!("pair:{left_id}:{right_id}"))
        })
        .collect();
    let pair_by_right: HashMap<String, String> = matching
        .pairs
        .iter()
        .map(|pair| {
            let left_id = pair.left["node_id"].as_str().unwrap_or("");
            let right_id = pair.right["node_id"].as_str().unwrap_or("");
            (right_id.to_string(), format!("pair:{left_id}:{right_id}"))
        })
        .collect();
    let left_native_by_digest = index_native(left_native);
    let right_native_by_digest = index_native(right_native);
    let left_relationships = index_relationships(left_graph);
    let right_relationships = index_relationships(right_graph);
    let mut items = Vec::new();
    for pair in &matching.pairs {
        items.push(matched_item(
            pair,
            left_evidence,
            right_evidence,
            left_graph,
            right_graph,
            &pair_by_left,
            &pair_by_right,
            &left_relationships,
            &right_relationships,
            &left_native_by_digest,
            &right_native_by_digest,
        )?);
    }
    for node in &matching.unmatched_left {
        let id = node["node_id"].as_str().unwrap_or("");
        let candidates = matching.candidates_for_left.get(id).cloned().unwrap_or_default();
        items.push(left_only_item(node, &candidates, left_evidence, right_evidence, right_graph, &left_native_by_digest)?);
    }
    for node in &matching.unmatched_right {
        let id = node["node_id"].as_str().unwrap_or("");
        let candidates = matching.candidates_for_right.get(id).cloned().unwrap_or_default();
        items.push(right_only_item(node, &candidates, left_evidence, right_evidence, left_graph, &right_native_by_digest)?);
    }
    items.sort_by(|left, right| compare_unicode_code_points(left["item_id"].as_str().unwrap_or(""), right["item_id"].as_str().unwrap_or("")));
    Ok(items)
}

#[allow(clippy::too_many_arguments)]
fn matched_item(
    pair: &Pair,
    left_evidence: &Evidence,
    right_evidence: &Evidence,
    left_graph: &Value,
    right_graph: &Value,
    pair_by_left: &HashMap<String, String>,
    pair_by_right: &HashMap<String, String>,
    left_relationships: &RelationshipIndex,
    right_relationships: &RelationshipIndex,
    left_native: &HashMap<String, Vec<String>>,
    right_native: &HashMap<String, Vec<String>>,
) -> Result<Value, JsError> {
    let mut dimensions = changed_dimensions(pair, pair_by_left, pair_by_right, left_relationships, right_relationships)?;
    let complete = absence_claimable(&left_graph["coverage"]) && absence_claimable(&right_graph["coverage"]);
    let observed_change = dimensions.iter().any(|dimension| matches!(dimension.as_str(), "content" | "location" | "properties"));
    let status = if observed_change || (complete && !dimensions.is_empty()) {
        "changed"
    } else if complete {
        "unchanged"
    } else {
        "unknown"
    };
    if status == "unknown" && !dimensions.iter().any(|dimension| dimension == "coverage") {
        dimensions.push("coverage".to_string());
    }
    item_with_id(&json!({
        "status": status,
        "node_kind": pair.left["kind"],
        "left_node_id": pair.left["node_id"],
        "right_node_id": pair.right["node_id"],
        "match": matched_match(pair),
        "dimensions": dimensions,
        "evidence_links": item_links(Some(&pair.left), Some(&pair.right), left_evidence, right_evidence, left_native, right_native),
        "limitations": pair_limitations(pair, status),
    }))
}

fn matched_match(pair: &Pair) -> Value {
    json!({
        "status": "matched",
        "basis": pair.basis,
        "confidence": pair.confidence,
        "candidate_left_node_ids": [],
        "candidate_right_node_ids": [],
    })
}

fn left_only_item(
    node: &Value,
    candidates: &[String],
    left_evidence: &Evidence,
    right_evidence: &Evidence,
    right_graph: &Value,
    left_native: &HashMap<String, Vec<String>>,
) -> Result<Value, JsError> {
    let links = item_links(Some(node), None, left_evidence, right_evidence, left_native, &HashMap::new());
    if let Some(first) = candidates.first() {
        let _ = first;
        return item_with_id(&json!({
            "status": "unknown",
            "node_kind": node["kind"],
            "left_node_id": node["node_id"],
            "right_node_id": Value::Null,
            "match": {
                "status": "ambiguous",
                "basis": "none",
                "confidence": "unknown",
                "candidate_left_node_ids": [],
                "candidate_right_node_ids": candidates,
            },
            "dimensions": ["availability"],
            "evidence_links": links,
            "limitations": [AMBIGUOUS_MATCH_LIMITATION],
        }));
    }
    let absence = absence_claimable(&right_graph["coverage"]);
    item_with_id(&json!({
        "status": if absence { "removed" } else { "unknown" },
        "node_kind": node["kind"],
        "left_node_id": node["node_id"],
        "right_node_id": Value::Null,
        "match": unmatched_match(),
        "dimensions": if absence { vec!["availability"] } else { vec!["availability", "coverage"] },
        "evidence_links": links,
        "limitations": if absence { Vec::<String>::new() } else { vec![INCOMPLETE_GRAPH_LIMITATION.to_string()] },
    }))
}

fn right_only_item(
    node: &Value,
    candidates: &[String],
    left_evidence: &Evidence,
    right_evidence: &Evidence,
    left_graph: &Value,
    right_native: &HashMap<String, Vec<String>>,
) -> Result<Value, JsError> {
    let links = item_links(None, Some(node), left_evidence, right_evidence, &HashMap::new(), right_native);
    if !candidates.is_empty() {
        return item_with_id(&json!({
            "status": "unknown",
            "node_kind": node["kind"],
            "left_node_id": Value::Null,
            "right_node_id": node["node_id"],
            "match": {
                "status": "ambiguous",
                "basis": "none",
                "confidence": "unknown",
                "candidate_left_node_ids": candidates,
                "candidate_right_node_ids": [],
            },
            "dimensions": ["availability"],
            "evidence_links": links,
            "limitations": [AMBIGUOUS_MATCH_LIMITATION],
        }));
    }
    let absence = absence_claimable(&left_graph["coverage"]);
    item_with_id(&json!({
        "status": if absence { "added" } else { "unknown" },
        "node_kind": node["kind"],
        "left_node_id": Value::Null,
        "right_node_id": node["node_id"],
        "match": unmatched_match(),
        "dimensions": if absence { vec!["availability"] } else { vec!["availability", "coverage"] },
        "evidence_links": links,
        "limitations": if absence { Vec::<String>::new() } else { vec![INCOMPLETE_GRAPH_LIMITATION.to_string()] },
    }))
}

fn unmatched_match() -> Value {
    json!({
        "status": "unmatched",
        "basis": "none",
        "confidence": "unknown",
        "candidate_left_node_ids": [],
        "candidate_right_node_ids": [],
    })
}

fn pair_limitations(pair: &Pair, status: &str) -> Vec<String> {
    let mut limitations = Vec::new();
    if pair.basis == "structural-fingerprint" {
        limitations.push("Structural fingerprint equality is rename-resistant inference; it is not byte identity or proof of semantic equivalence.".to_string());
    }
    if pair.basis == "source-map-identity" {
        limitations.push("Source-map original names identify a candidate source lineage; changed or unavailable source content remains explicit.".to_string());
    }
    if pair.basis == "semantic-key" {
        limitations.push("Semantic-key pairing is a deterministic inference and is never promoted to exact identity.".to_string());
    }
    if status == "unknown" {
        limitations.push("Incomplete graph coverage prevents a complete node-level conclusion.".to_string());
    }
    limitations
}

fn changed_dimensions(
    pair: &Pair,
    pair_by_left: &HashMap<String, String>,
    pair_by_right: &HashMap<String, String>,
    left_relationships: &RelationshipIndex,
    right_relationships: &RelationshipIndex,
) -> Result<Vec<String>, JsError> {
    let mut dimensions = Vec::new();
    let left_content = content_identity(&pair.left);
    let right_content = content_identity(&pair.right);
    if left_content.is_some() && right_content.is_some() && left_content != right_content {
        dimensions.push("content".to_string());
    }
    if canonical_text(&locations(&pair.left))? != canonical_text(&locations(&pair.right))? {
        dimensions.push("location".to_string());
    }
    if canonical_text(&properties_view(&pair.left))? != canonical_text(&properties_view(&pair.right))? {
        dimensions.push("properties".to_string());
    }
    if relationship_signature(&pair.left, pair_by_left, left_relationships)?
        != relationship_signature(&pair.right, pair_by_right, right_relationships)?
    {
        dimensions.push("relationships".to_string());
    }
    Ok(dimensions)
}

fn content_identity(node: &Value) -> Option<String> {
    if node["identity"]["strategy"].as_str() == Some("content-digest") {
        return Some(format!("content:{}", node["identity"]["sha256"].as_str().unwrap_or("")));
    }
    if node["kind"].as_str() == Some("javascript-module") {
        return unique_string_property(node, "source_sha256");
    }
    if node["kind"].as_str() == Some("source-module") && node["identity"]["strategy"].as_str() == Some("source-map-original") {
        return node["identity"]["source_sha256"].as_str().map(str::to_string);
    }
    None
}

fn locations(node: &Value) -> Value {
    let mut values = Vec::new();
    if let Some(observations) = node["observations"].as_array() {
        for observation in observations {
            let location = &observation["evidence"]["location"];
            if location["available"].as_bool() == Some(true) {
                values.push(location["value"].clone());
            } else {
                values.push(location.clone());
            }
        }
    }
    values.sort_by(|left, right| {
        compare_unicode_code_points(
            &canonical_text(left).unwrap_or_default(),
            &canonical_text(right).unwrap_or_default(),
        )
    });
    Value::Array(values)
}

fn properties_view(node: &Value) -> Value {
    let mut values = Vec::new();
    if let Some(observations) = node["observations"].as_array() {
        for observation in observations {
            values.push(json!({
                "label": observation["label"],
                "properties": observation["properties"],
                "source_map_reference": observation["source_map_reference"],
            }));
        }
    }
    values.sort_by(|left, right| {
        compare_unicode_code_points(
            &canonical_text(left).unwrap_or_default(),
            &canonical_text(right).unwrap_or_default(),
        )
    });
    Value::Array(values)
}

struct IndexedRelationship {
    direction: &'static str,
    relation: String,
    neighbor_id: String,
}

struct RelationshipIndex {
    node_by_id: HashMap<String, Value>,
    adjacency: HashMap<String, Vec<IndexedRelationship>>,
}

fn index_relationships(graph: &Value) -> RelationshipIndex {
    let mut node_by_id = HashMap::new();
    if let Some(nodes) = graph["nodes"].as_array() {
        for node in nodes {
            node_by_id.insert(node["node_id"].as_str().unwrap_or("").to_string(), node.clone());
        }
    }
    let mut adjacency: HashMap<String, Vec<IndexedRelationship>> = HashMap::new();
    if let Some(edges) = graph["edges"].as_array() {
        for edge in edges {
            let source = edge["source_node_id"].as_str().unwrap_or("").to_string();
            let target = edge["target_node_id"].as_str().unwrap_or("").to_string();
            let relation = edge["relation"].as_str().unwrap_or("").to_string();
            adjacency.entry(source.clone()).or_default().push(IndexedRelationship {
                direction: "out",
                relation: relation.clone(),
                neighbor_id: target.clone(),
            });
            if target != source {
                adjacency.entry(target).or_default().push(IndexedRelationship {
                    direction: "in",
                    relation,
                    neighbor_id: source,
                });
            }
        }
    }
    RelationshipIndex { node_by_id, adjacency }
}

fn relationship_signature(
    node: &Value,
    paired: &HashMap<String, String>,
    index: &RelationshipIndex,
) -> Result<String, JsError> {
    let id = node["node_id"].as_str().unwrap_or("");
    let mut signatures = Vec::new();
    for relationship in index.adjacency.get(id).into_iter().flatten() {
        let mapped = paired.get(&relationship.neighbor_id).cloned();
        let kind = index
            .node_by_id
            .get(&relationship.neighbor_id)
            .and_then(|neighbor| neighbor["kind"].as_str())
            .unwrap_or("unknown");
        let neighbor = mapped.unwrap_or_else(|| format!("unmatched:{kind}"));
        signatures.push(format!("{}\0{}\0{neighbor}", relationship.direction, relationship.relation));
    }
    signatures.sort_by(|left, right| compare_unicode_code_points(left, right));
    canonical_text(&json!(signatures))
}

fn item_links(
    left: Option<&Value>,
    right: Option<&Value>,
    left_evidence: &Evidence,
    right_evidence: &Evidence,
    left_native: &HashMap<String, Vec<String>>,
    right_native: &HashMap<String, Vec<String>>,
) -> Vec<String> {
    let mut links = vec![left_evidence.evidence_id.clone(), right_evidence.evidence_id.clone()];
    if let Some(node) = left {
        links.extend(native_links(node, left_native));
    }
    if let Some(node) = right {
        links.extend(native_links(node, right_native));
    }
    unique_sorted(&links)
}

fn native_links(node: &Value, evidence_by_digest: &HashMap<String, Vec<String>>) -> Vec<String> {
    let Some(identity) = content_identity(node) else {
        return Vec::new();
    };
    let digest = identity.trim_start_matches("content:");
    evidence_by_digest.get(digest).cloned().unwrap_or_default()
}

fn index_native(evidence: &[Evidence]) -> HashMap<String, Vec<String>> {
    let mut output: HashMap<String, Vec<String>> = HashMap::new();
    for item in evidence {
        if let Some(subject) = &item.subject {
            output.entry(subject.digest.sha256.clone()).or_default().push(item.evidence_id.clone());
        }
    }
    output
}

fn item_with_id(semantic: &Value) -> Result<Value, JsError> {
    let mut item = semantic.clone();
    let item_id = digest_prefixed("javc_item_", semantic)?;
    item.as_object_mut().expect("object").insert("item_id".into(), json!(item_id));
    Ok(item)
}

fn absence_claimable(coverage: &Value) -> bool {
    let omitted_ok = match coverage.get("omitted_count") {
        None | Some(Value::Null) => true,
        Some(value) => value.as_u64() == Some(0),
    };
    coverage["status"].as_str() == Some("complete")
        && coverage["truncated"].as_bool() != Some(true)
        && omitted_ok
}

fn summary(items: &[Value]) -> Value {
    json!({
        "unchanged": count_item(items, "unchanged"),
        "added": count_item(items, "added"),
        "removed": count_item(items, "removed"),
        "changed": count_item(items, "changed"),
        "unknown": count_item(items, "unknown"),
    })
}

fn matching_summary(items: &[Value]) -> Value {
    json!({
        "exact_node_identity": count_basis(items, "exact-node-identity"),
        "exact_content_digest": count_basis(items, "exact-content-digest"),
        "exact_module_source_digest": count_basis(items, "exact-module-source-digest"),
        "source_map_identity": count_basis(items, "source-map-identity"),
        "structural_fingerprint": count_basis(items, "structural-fingerprint"),
        "semantic_key": count_basis(items, "semantic-key"),
        "ambiguous": items.iter().filter(|item| item["match"]["status"].as_str() == Some("ambiguous")).count(),
        "unmatched": items.iter().filter(|item| item["match"]["status"].as_str() == Some("unmatched")).count(),
    })
}

fn count_item(items: &[Value], status: &str) -> usize {
    items.iter().filter(|item| item["status"].as_str() == Some(status)).count()
}

fn count_basis(items: &[Value], basis: &str) -> usize {
    items.iter().filter(|item| item["match"]["basis"].as_str() == Some(basis)).count()
}

fn comparison_coverage(left_graph: &Value, right_graph: &Value) -> Value {
    let complete = left_graph["coverage"]["status"].as_str() == Some("complete")
        && right_graph["coverage"]["status"].as_str() == Some("complete");
    let truncated = left_graph["coverage"]["truncated"].as_bool() == Some(true)
        || right_graph["coverage"]["truncated"].as_bool() == Some(true);
    let status = if complete {
        "complete-within-inputs"
    } else if truncated {
        "truncated"
    } else {
        "partial"
    };
    json!({
        "left_graph_status": left_graph["coverage"]["status"],
        "right_graph_status": right_graph["coverage"]["status"],
        "left_graph_omitted_count": left_graph["coverage"]["omitted_count"],
        "right_graph_omitted_count": right_graph["coverage"]["omitted_count"],
        "status": status,
    })
}

fn comparison_limitations(left_graph: &Value, right_graph: &Value) -> Vec<String> {
    let mut limitations = vec![
        "Application comparison never uses bundler module ordinals as persistent identity and performs no fuzzy pairing.".to_string(),
        "Exact digest equality proves byte identity only; source-map, structural-fingerprint, and semantic-key matches retain inferred confidence.".to_string(),
        "Minified names and chunk locations are not assumed stable across versions.".to_string(),
        "The comparison reads retained graphs and Evidence only; it does not execute either application.".to_string(),
        "Native Evidence is linked only by exact subject digest; provider snapshot reuse remains target/provider/profile exact.".to_string(),
    ];
    if left_graph["coverage"]["status"].as_str() != Some("complete")
        || right_graph["coverage"]["status"].as_str() != Some("complete")
    {
        limitations.push("At least one source graph is incomplete; unmatched entities on the opposite side remain unknown rather than added or removed.".to_string());
    }
    unique_sorted(&limitations)
}

fn build_change_graph(
    left_graph: &Value,
    right_graph: &Value,
    left_evidence_id: &str,
    right_evidence_id: &str,
    items: &[Value],
) -> Result<Value, JsError> {
    let mut required = HashSet::new();
    for id in string_list(&left_graph["root_node_ids"]) {
        required.insert(id);
    }
    for id in string_list(&right_graph["root_node_ids"]) {
        required.insert(id);
    }
    for item in items {
        if let Some(id) = item["left_node_id"].as_str() {
            required.insert(id.to_string());
        }
        if let Some(id) = item["right_node_id"].as_str() {
            required.insert(id.to_string());
        }
    }
    let mut grouped: HashMap<String, Vec<Value>> = HashMap::new();
    for node in left_graph["nodes"].as_array().into_iter().flatten().chain(right_graph["nodes"].as_array().into_iter().flatten()) {
        let id = node["node_id"].as_str().unwrap_or("").to_string();
        if required.contains(&id) {
            grouped.entry(id).or_default().push(node.clone());
        }
    }
    let mut preferred = unique_sorted(&{
        let mut roots = string_list(&right_graph["root_node_ids"]);
        roots.extend(string_list(&left_graph["root_node_ids"]));
        roots
    });
    preferred.retain(|id| grouped.contains_key(id));
    let mut ordered = preferred.clone();
    for item in items {
        if let Some(id) = item["right_node_id"].as_str() {
            ordered.push(id.to_string());
        }
        if let Some(id) = item["left_node_id"].as_str() {
            ordered.push(id.to_string());
        }
    }
    let ordered = unique_sorted(&ordered);
    let retained: HashSet<String> = ordered.iter().cloned().collect();
    let mut merged = Vec::new();
    for id in &ordered {
        if let Some(group) = grouped.get(id) {
            merged.push(merge_group(group)?);
        }
    }
    merged.sort_by(|left, right| compare_unicode_code_points(left["node_id"].as_str().unwrap_or(""), right["node_id"].as_str().unwrap_or("")));
    let mut edges = unique_edges(
        &left_graph["edges"]
            .as_array()
            .into_iter()
            .flatten()
            .chain(right_graph["edges"].as_array().into_iter().flatten())
            .filter(|edge| {
                retained.contains(edge["source_node_id"].as_str().unwrap_or(""))
                    && retained.contains(edge["target_node_id"].as_str().unwrap_or(""))
            })
            .cloned()
            .collect::<Vec<_>>(),
    );
    let left_by_id = node_map(left_graph);
    let right_by_id = node_map(right_graph);
    for item in items {
        if let Some(edge) = changed_from_edge(item, left_evidence_id, right_evidence_id, left_graph, right_graph, &retained, &left_by_id, &right_by_id)? {
            edges.push(edge);
        }
    }
    let edges = unique_edges(&edges);
    let roots = if preferred.iter().any(|id| retained.contains(id)) {
        preferred.into_iter().filter(|id| retained.contains(id)).collect::<Vec<_>>()
    } else if let Some(fallback) = merged.first().and_then(|node| node["node_id"].as_str()) {
        vec![fallback.to_string()]
    } else {
        Vec::new()
    };
    let mut limitations = Vec::new();
    for value in string_list(&left_graph["limitations"]) {
        limitations.push(format!("Left: {value}"));
    }
    for value in string_list(&right_graph["limitations"]) {
        limitations.push(format!("Right: {value}"));
    }
    limitations.push("changed_from edges are cross-version inferences and never promote structural or semantic matches to exact identity.".to_string());
    limitations.push("The change graph contains compared entities and their retained relationships; it is not an executable application.".to_string());
    seal_application_graph(&json!({
        "schema": "JavaScriptApplicationGraph",
        "root_node_ids": roots,
        "nodes": merged,
        "edges": edges,
        "coverage": change_graph_coverage(left_graph, right_graph),
        "limitations": unique_sorted(&limitations),
    }))
}

fn merge_group(group: &[Value]) -> Result<Value, JsError> {
    let first = group.first().ok_or_else(|| JsError::InvalidInput("empty change-graph node group".into()))?;
    let mut by_id: HashMap<String, Value> = HashMap::new();
    let mut order = Vec::new();
    for node in group {
        if let Some(observations) = node["observations"].as_array() {
            for observation in observations {
                let id = observation["observation_id"].as_str().unwrap_or("").to_string();
                if !by_id.contains_key(&id) {
                    order.push(id.clone());
                }
                by_id.insert(id, observation.clone());
            }
        }
    }
    order.sort_by(|left, right| compare_unicode_code_points(left, right));
    let observations: Vec<Value> = order.iter().filter_map(|id| by_id.get(id).cloned()).collect();
    let mut node = first.clone();
    node["observations"] = json!(observations);
    recreate_node(&node)
}

#[allow(clippy::too_many_arguments)]
fn changed_from_edge(
    item: &Value,
    left_evidence_id: &str,
    right_evidence_id: &str,
    left_graph: &Value,
    right_graph: &Value,
    retained: &HashSet<String>,
    left_by_id: &HashMap<String, Value>,
    right_by_id: &HashMap<String, Value>,
) -> Result<Option<Value>, JsError> {
    let left = item["left_node_id"].as_str();
    let right = item["right_node_id"].as_str();
    if item["match"]["status"].as_str() != Some("matched")
        || item["status"].as_str() == Some("unchanged")
        || left.is_none()
        || right.is_none()
        || left == right
        || !retained.contains(left.unwrap_or(""))
        || !retained.contains(right.unwrap_or(""))
    {
        return Ok(None);
    }
    let left_id = left.unwrap();
    let right_id = right.unwrap();
    let evidence = comparison_evidence(item, left_evidence_id, right_evidence_id, left_graph, right_graph, left_by_id.get(left_id), right_by_id.get(right_id));
    Ok(Some(create_edge(&json!({
        "source_node_id": right_id,
        "target_node_id": left_id,
        "relation": "changed_from",
        "properties": {
            "comparison_item_id": item["item_id"],
            "status": item["status"],
            "match_basis": item["match"]["basis"],
            "match_confidence": item["match"]["confidence"],
            "dimensions": item["dimensions"],
        },
        "evidence": evidence,
    }))?))
}

fn comparison_evidence(
    item: &Value,
    left_evidence_id: &str,
    right_evidence_id: &str,
    left_graph: &Value,
    right_graph: &Value,
    left: Option<&Value>,
    right: Option<&Value>,
) -> Value {
    let source = right
        .and_then(|node| node["observations"].as_array().and_then(|items| items.first()))
        .or_else(|| left.and_then(|node| node["observations"].as_array().and_then(|items| items.first())))
        .map(|observation| observation["evidence"].clone());
    let complete = left_graph["coverage"]["status"].as_str() == Some("complete")
        && right_graph["coverage"]["status"].as_str() == Some("complete");
    let mut limitations = vec!["Cross-version pairing is inferred from the stated match basis; changed_from does not prove runtime reachability.".to_string()];
    limitations.extend(string_list(&item["limitations"]));
    let coverage = if complete {
        json!({ "status": "complete", "truncated": false, "omitted_count": 0, "limits": [] })
    } else {
        json!({
            "status": "partial",
            "truncated": left_graph["coverage"]["truncated"].as_bool() == Some(true) || right_graph["coverage"]["truncated"].as_bool() == Some(true),
            "omitted_count": combine_omitted(left_graph["coverage"].get("omitted_count"), right_graph["coverage"].get("omitted_count")),
            "limits": source_coverage_limits(left_graph, right_graph),
        })
    };
    let mut evidence = source.unwrap_or_else(|| {
        json!({
            "artifact": { "available": false, "reason": "unresolved", "detail": "Compared node has no artifact-backed observation." },
            "location": { "available": false, "reason": "unresolved", "detail": "Compared node has no actionable source location." },
        })
    });
    if let Some(obj) = evidence.as_object_mut() {
        obj.insert("authority".into(), json!("cross-version-comparison"));
        obj.insert("state".into(), json!("inferred"));
        obj.insert(
            "confidence".into(),
            json!(if item["match"]["confidence"].as_str() == Some("medium") { "medium" } else { "high" }),
        );
        obj.insert(
            "extractor".into(),
            json!({
                "name": "rea-application-version-comparison",
                "version": "1",
                "operation": "compare_application_versions",
                "executable_sha256": Value::Null,
            }),
        );
        obj.insert("coverage".into(), coverage);
        obj.insert("limitations".into(), json!(limitations));
        obj.insert("evidence_ids".into(), json!([left_evidence_id, right_evidence_id]));
        if !obj.contains_key("artifact") {
            obj.insert("artifact".into(), json!({ "available": false, "reason": "unresolved", "detail": "Compared node has no artifact-backed observation." }));
        }
        if !obj.contains_key("location") {
            obj.insert("location".into(), json!({ "available": false, "reason": "unresolved", "detail": "Compared node has no actionable source location." }));
        }
    }
    evidence
}

fn change_graph_coverage(left_graph: &Value, right_graph: &Value) -> Value {
    if left_graph["coverage"]["status"].as_str() == Some("complete") && right_graph["coverage"]["status"].as_str() == Some("complete") {
        json!({ "status": "complete", "truncated": false, "omitted_count": 0, "limits": [] })
    } else {
        json!({
            "status": "partial",
            "truncated": left_graph["coverage"]["truncated"].as_bool() == Some(true) || right_graph["coverage"]["truncated"].as_bool() == Some(true),
            "omitted_count": combine_omitted(left_graph["coverage"].get("omitted_count"), right_graph["coverage"].get("omitted_count")),
            "limits": source_coverage_limits(left_graph, right_graph),
        })
    }
}

fn source_coverage_limits(left_graph: &Value, right_graph: &Value) -> Vec<Value> {
    let mut keyed: HashMap<String, Value> = HashMap::new();
    let mut order = Vec::new();
    for limit in left_graph["coverage"]["limits"].as_array().into_iter().flatten().chain(right_graph["coverage"]["limits"].as_array().into_iter().flatten()) {
        let key = format!("{}\0{}\0{}", limit["name"].as_str().unwrap_or(""), limit["value"], limit["unit"].as_str().unwrap_or(""));
        if !keyed.contains_key(&key) {
            order.push(key.clone());
        }
        keyed.insert(key, limit.clone());
    }
    let mut limits: Vec<Value> = order.iter().filter_map(|key| keyed.get(key).cloned()).collect();
    limits.sort_by(|left, right| compare_unicode_code_points(left["name"].as_str().unwrap_or(""), right["name"].as_str().unwrap_or("")));
    limits
}

fn combine_omitted(left: Option<&Value>, right: Option<&Value>) -> Value {
    match (left.and_then(|value| value.as_i64()), right.and_then(|value| value.as_i64())) {
        (Some(left), Some(right)) => json!(left + right),
        _ => Value::Null,
    }
}

fn unique_edges(edges: &[Value]) -> Vec<Value> {
    let mut by_id: HashMap<String, Value> = HashMap::new();
    let mut order = Vec::new();
    for edge in edges {
        let id = edge["edge_id"].as_str().unwrap_or("").to_string();
        if !by_id.contains_key(&id) {
            order.push(id.clone());
        }
        by_id.insert(id, edge.clone());
    }
    let mut edges: Vec<Value> = order.iter().filter_map(|id| by_id.get(id).cloned()).collect();
    edges.sort_by(|left, right| compare_unicode_code_points(left["edge_id"].as_str().unwrap_or(""), right["edge_id"].as_str().unwrap_or("")));
    edges
}

fn node_map(graph: &Value) -> HashMap<String, Value> {
    graph["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|node| (node["node_id"].as_str().unwrap_or("").to_string(), node.clone()))
        .collect()
}

fn require_unique(evidence: &[Evidence], label: &str) -> Result<(), JsError> {
    let mut seen = HashSet::new();
    for item in evidence {
        if !seen.insert(item.evidence_id.clone()) {
            return Err(JsError::InvalidInput(format!("Native observations must be unique on {label}")));
        }
    }
    Ok(())
}

fn string_list(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| items.iter().filter_map(|item| item.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}
