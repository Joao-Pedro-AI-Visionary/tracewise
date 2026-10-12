//! `trace_application_feature` — literal seed walk over a JavaScript application graph.

use std::collections::{HashMap, HashSet};

use serde_json::{json, Value};
use tracewise_domain::evidence::Evidence;
use unicode_normalization::UnicodeNormalization;

use crate::error::JsError;
use crate::unicode::{compare_unicode_code_points, unique_sorted};

use super::graph_seal::{digest_prefixed, required_str, seal_application_graph};
use super::workflow::workflow_evidence;

const NO_MATCH_LIMITATION: &str = "No graph entity matched the literal seed; this is not evidence that the feature is absent.";
const TRACE_EDGE_LIMITATION: &str = "Trace edges retain their source authority; graph connectivity does not prove runtime execution or reachability.";
const TRACE_RELATIONSHIP_LIMITATION: &str = "A trace reports graph relationships, not proof that code executed or that a feature is reachable in every state.";
const AUTHORITY_LIMITATION: &str = "Static, native, passive-runtime, inferred, and unknown facts retain their original authority in the returned graph.";
const HANDOFF_LIMITATION: &str = "Native handoffs never open a binary or invoke a provider automatically; snapshot reuse remains provider/profile/target exact.";
const INCOMPLETE_SOURCE_LIMITATION: &str =
    "The source application graph is incomplete; unmatched seeds and frontiers remain unknown.";

pub fn trace_application_feature(
    application: &Evidence,
    native_observations: &[Evidence],
    seed: &Value,
    direction: Option<&str>,
) -> Result<Evidence, JsError> {
    let graph = application_graph(application)?;
    let seed = normalize_seed(seed)?;
    let direction = normalize_direction(direction)?;
    require_unique_ids(native_observations)?;
    let source_graph_id = required_str(graph, "graph_id")?.to_string();
    let nodes = graph
        .get("nodes")
        .and_then(|v| v.as_array())
        .ok_or_else(|| JsError::InvalidInput("graph nodes missing".into()))?;
    let seed_matches = find_seeds(nodes, &seed);
    let result = if seed_matches.is_empty() {
        no_match(
            &application.evidence_id,
            &source_graph_id,
            &seed,
            &direction,
            graph,
        )?
    } else {
        matched_trace(
            application,
            native_observations,
            graph,
            &source_graph_id,
            &seed,
            &direction,
            &seed_matches,
        )?
    };
    let limitations = string_list(result.get("limitations").unwrap_or(&Value::Null));
    let links = string_list(result.get("evidence_links").unwrap_or(&Value::Null));
    workflow_evidence(
        "trace_application_feature",
        "rea.application-feature-trace",
        json!({
            "application_evidence_id": application.evidence_id,
            "native_evidence_ids": native_observations.iter().map(|item| item.evidence_id.clone()).collect::<Vec<_>>(),
            "seed": seed,
            "direction": direction,
        }),
        result,
        limitations,
        links,
    )
}

fn matched_trace(
    application: &Evidence,
    native_observations: &[Evidence],
    graph: &Value,
    source_graph_id: &str,
    seed: &Value,
    direction: &str,
    seed_matches: &[Value],
) -> Result<Value, JsError> {
    let seed_ids: Vec<String> = seed_matches
        .iter()
        .filter_map(|item| item.get("node_id").and_then(|v| v.as_str()).map(str::to_string))
        .collect();
    let traversal = traverse(graph, &seed_ids, direction)?;
    let traced = trace_graph(graph, seed_matches, &traversal)?;
    let paths = terminal_paths(&traversal, &seed_ids)?;
    let handoffs = native_handoffs(&traversal.nodes, &traversal.edges, native_observations);
    let mut link_ids = vec![application.evidence_id.clone()];
    for handoff in &handoffs {
        link_ids.extend(string_list(handoff.get("evidence_ids").unwrap_or(&Value::Null)));
    }
    let evidence_links = unique_sorted(&link_ids);
    let facts = fact_summary(&traversal.nodes, &traversal.edges);
    let mut semantic = json!({
        "source_evidence_id": application.evidence_id,
        "source_graph_id": source_graph_id,
        "seed": seed,
        "direction": direction,
        "seed_matches": seed_matches,
        "graph": traced,
        "paths": paths,
        "native_handoffs": handoffs,
        "summary": {
            "matched_seeds": seed_matches.len(),
            "traced_nodes": traversal.nodes.len(),
            "traced_edges": traversal.edges.len(),
            "terminal_paths": paths.len(),
            "native_handoffs": handoffs.len(),
            "observed_facts": facts.0,
            "inferred_facts": facts.1,
            "unknown_facts": facts.2,
            "unavailable_facts": facts.3,
        },
        "coverage": {
            "status": trace_coverage_status(graph),
            "source_graph_status": graph["coverage"]["status"].as_str().unwrap_or("unknown"),
            "total_seed_matches": seed_matches.len(),
        },
        "evidence_links": evidence_links,
        "limitations": trace_limitations(graph),
    });
    let trace_id = digest_prefixed("jatr_", &semantic)?;
    semantic
        .as_object_mut()
        .expect("object")
        .insert("trace_id".into(), json!(trace_id));
    Ok(semantic)
}

fn no_match(
    source_evidence_id: &str,
    source_graph_id: &str,
    seed: &Value,
    direction: &str,
    graph: &Value,
) -> Result<Value, JsError> {
    let mut limitations = vec![NO_MATCH_LIMITATION.to_string()];
    limitations.extend(source_coverage_limitations(graph));
    let mut semantic = json!({
        "source_evidence_id": source_evidence_id,
        "source_graph_id": source_graph_id,
        "seed": seed,
        "direction": direction,
        "seed_matches": [],
        "graph": Value::Null,
        "paths": [],
        "native_handoffs": [],
        "summary": {
            "matched_seeds": 0,
            "traced_nodes": 0,
            "traced_edges": 0,
            "terminal_paths": 0,
            "native_handoffs": 0,
            "observed_facts": 0,
            "inferred_facts": 0,
            "unknown_facts": 0,
            "unavailable_facts": 0,
        },
        "coverage": {
            "status": "no-match",
            "source_graph_status": graph["coverage"]["status"].as_str().unwrap_or("unknown"),
            "total_seed_matches": 0,
        },
        "evidence_links": [source_evidence_id],
        "limitations": unique_sorted(&limitations),
    });
    let trace_id = digest_prefixed("jatr_", &semantic)?;
    semantic
        .as_object_mut()
        .expect("object")
        .insert("trace_id".into(), json!(trace_id));
    Ok(semantic)
}

struct Traversal {
    nodes: Vec<Value>,
    edges: Vec<Value>,
    predecessors: HashMap<String, (String, String)>,
}

fn traverse(graph: &Value, seed_ids: &[String], direction: &str) -> Result<Traversal, JsError> {
    let nodes = graph["nodes"].as_array().cloned().unwrap_or_default();
    let edges = graph["edges"].as_array().cloned().unwrap_or_default();
    let node_ids: HashSet<String> = nodes
        .iter()
        .filter_map(|node| node.get("node_id").and_then(|v| v.as_str()).map(str::to_string))
        .collect();
    let adjacency = build_adjacency(&edges, direction);
    let mut visited: HashSet<String> = seed_ids.iter().cloned().collect();
    let mut retained: HashMap<String, Value> = HashMap::new();
    let mut predecessors = HashMap::new();
    let mut queue = seed_ids.to_vec();
    let mut offset = 0;
    while offset < queue.len() {
        let current = queue[offset].clone();
        offset += 1;
        for entry in adjacency.get(&current).cloned().unwrap_or_default() {
            let edge_id = required_str(&entry.edge, "edge_id")?.to_string();
            retained.insert(edge_id, entry.edge);
            if visited.contains(&entry.next) || !node_ids.contains(&entry.next) {
                continue;
            }
            visited.insert(entry.next.clone());
            predecessors.insert(entry.next.clone(), (current.clone(), entry.edge_id));
            queue.push(entry.next);
        }
    }
    let mut kept_nodes: Vec<Value> = nodes
        .into_iter()
        .filter(|node| {
            node.get("node_id")
                .and_then(|v| v.as_str())
                .is_some_and(|id| visited.contains(id))
        })
        .collect();
    kept_nodes.sort_by(|left, right| {
        compare_unicode_code_points(
            left["node_id"].as_str().unwrap_or(""),
            right["node_id"].as_str().unwrap_or(""),
        )
    });
    let mut kept_edges: Vec<Value> = retained.into_values().collect();
    kept_edges.sort_by(|left, right| {
        compare_unicode_code_points(
            left["edge_id"].as_str().unwrap_or(""),
            right["edge_id"].as_str().unwrap_or(""),
        )
    });
    Ok(Traversal {
        nodes: kept_nodes,
        edges: kept_edges,
        predecessors,
    })
}

#[derive(Clone)]
struct Adj {
    edge: Value,
    edge_id: String,
    next: String,
}

fn build_adjacency(edges: &[Value], direction: &str) -> HashMap<String, Vec<Adj>> {
    let mut adjacency: HashMap<String, Vec<Adj>> = HashMap::new();
    for edge in edges {
        let source = edge["source_node_id"].as_str().unwrap_or("").to_string();
        let target = edge["target_node_id"].as_str().unwrap_or("").to_string();
        let edge_id = edge["edge_id"].as_str().unwrap_or("").to_string();
        if direction != "incoming" {
            adjacency.entry(source.clone()).or_default().push(Adj {
                edge: edge.clone(),
                edge_id: edge_id.clone(),
                next: target.clone(),
            });
        }
        if direction != "outgoing" {
            adjacency.entry(target).or_default().push(Adj {
                edge: edge.clone(),
                edge_id,
                next: source,
            });
        }
    }
    for entries in adjacency.values_mut() {
        entries.sort_by(|left, right| {
            compare_unicode_code_points(
                &format!("{}\0{}", left.edge_id, left.next),
                &format!("{}\0{}", right.edge_id, right.next),
            )
        });
    }
    adjacency
}

fn trace_graph(graph: &Value, seeds: &[Value], traversal: &Traversal) -> Result<Value, JsError> {
    let roots = unique_sorted(
        &seeds
            .iter()
            .filter_map(|seed| seed.get("node_id").and_then(|v| v.as_str()).map(str::to_string))
            .collect::<Vec<_>>(),
    );
    let mut limitations = string_list(graph.get("limitations").unwrap_or(&Value::Null));
    limitations.push(TRACE_EDGE_LIMITATION.to_string());
    let coverage = if graph["coverage"]["status"].as_str() == Some("complete") {
        json!({ "status": "complete", "truncated": false, "omitted_count": 0, "limits": [] })
    } else {
        graph["coverage"].clone()
    };
    seal_application_graph(&json!({
        "schema": "JavaScriptApplicationGraph",
        "root_node_ids": roots,
        "nodes": traversal.nodes,
        "edges": traversal.edges,
        "coverage": coverage,
        "limitations": unique_sorted(&limitations),
    }))
}

fn terminal_paths(traversal: &Traversal, seed_ids: &[String]) -> Result<Vec<Value>, JsError> {
    let seed_ids: HashSet<&str> = seed_ids.iter().map(String::as_str).collect();
    let edge_by_id: HashMap<String, Value> = traversal
        .edges
        .iter()
        .filter_map(|edge| {
            edge.get("edge_id")
                .and_then(|v| v.as_str())
                .map(|id| (id.to_string(), edge.clone()))
        })
        .collect();
    let mut paths = Vec::new();
    for node in &traversal.nodes {
        let node_id = node["node_id"].as_str().unwrap_or("");
        let terminal = matches!(
            node["kind"].as_str().unwrap_or(""),
            "endpoint" | "storage" | "native-addon" | "native-export" | "unknown"
        );
        if !terminal {
            continue;
        }
        if seed_ids.contains(node_id) && traversal.nodes.len() != 1 {
            continue;
        }
        if let Some(path) = path_to(node, &traversal.predecessors, &edge_by_id)? {
            paths.push(path);
        }
    }
    paths.sort_by(|left, right| {
        compare_unicode_code_points(
            left["path_id"].as_str().unwrap_or(""),
            right["path_id"].as_str().unwrap_or(""),
        )
    });
    Ok(paths)
}

fn path_to(
    node: &Value,
    predecessors: &HashMap<String, (String, String)>,
    edge_by_id: &HashMap<String, Value>,
) -> Result<Option<Value>, JsError> {
    let end = node["node_id"].as_str().unwrap_or("").to_string();
    let mut node_ids = vec![end.clone()];
    let mut edge_ids = Vec::new();
    let mut current = end.clone();
    while let Some((previous, edge_id)) = predecessors.get(&current) {
        node_ids.push(previous.clone());
        edge_ids.push(edge_id.clone());
        current = previous.clone();
    }
    node_ids.reverse();
    edge_ids.reverse();
    let mut edges = Vec::new();
    for edge_id in &edge_ids {
        let Some(edge) = edge_by_id.get(edge_id) else {
            return Ok(None);
        };
        edges.push(edge);
    }
    let authorities = unique_sorted(
        &edges
            .iter()
            .filter_map(|edge| edge["evidence"]["authority"].as_str().map(str::to_string))
            .collect::<Vec<_>>(),
    );
    let contains_inference = edges
        .iter()
        .any(|edge| edge["evidence"]["state"].as_str() == Some("inferred"));
    let mut semantic = json!({
        "start_node_id": node_ids.first().cloned().unwrap_or(end.clone()),
        "end_node_id": end,
        "end_kind": node["kind"].as_str().unwrap_or(""),
        "node_ids": node_ids,
        "edge_ids": edge_ids,
        "authorities": authorities,
        "contains_inference": contains_inference,
    });
    let path_id = digest_prefixed("jatp_", &semantic)?;
    semantic
        .as_object_mut()
        .expect("object")
        .insert("path_id".into(), json!(path_id));
    Ok(Some(semantic))
}

fn fact_summary(nodes: &[Value], edges: &[Value]) -> (usize, usize, usize, usize) {
    let mut states = Vec::new();
    for node in nodes {
        if let Some(observations) = node["observations"].as_array() {
            for observation in observations {
                if let Some(state) = observation["evidence"]["state"].as_str() {
                    states.push(state.to_string());
                }
            }
        }
    }
    for edge in edges {
        if let Some(state) = edge["evidence"]["state"].as_str() {
            states.push(state.to_string());
        }
    }
    (
        states.iter().filter(|state| state.as_str() == "observed").count(),
        states.iter().filter(|state| state.as_str() == "inferred").count(),
        states.iter().filter(|state| state.as_str() == "unknown").count(),
        states.iter().filter(|state| state.as_str() == "unavailable").count(),
    )
}

fn trace_coverage_status(graph: &Value) -> &'static str {
    if graph["coverage"]["status"].as_str() == Some("complete") {
        "complete-within-source"
    } else {
        "partial"
    }
}

fn trace_limitations(graph: &Value) -> Vec<String> {
    let mut limitations = vec![
        TRACE_RELATIONSHIP_LIMITATION.to_string(),
        AUTHORITY_LIMITATION.to_string(),
        HANDOFF_LIMITATION.to_string(),
    ];
    limitations.extend(source_coverage_limitations(graph));
    unique_sorted(&limitations)
}

fn source_coverage_limitations(graph: &Value) -> Vec<String> {
    if graph["coverage"]["status"].as_str() == Some("complete") {
        Vec::new()
    } else {
        vec![INCOMPLETE_SOURCE_LIMITATION.to_string()]
    }
}

fn native_handoffs(nodes: &[Value], edges: &[Value], native: &[Evidence]) -> Vec<Value> {
    let mut handoffs = Vec::new();
    for node in nodes {
        if node["kind"].as_str() != Some("native-addon") {
            continue;
        }
        let Some(digest) = artifact_digest(node) else {
            continue;
        };
        let linked: Vec<&Evidence> = native
            .iter()
            .filter(|item| {
                item.subject
                    .as_ref()
                    .is_some_and(|subject| subject.digest.sha256 == digest)
            })
            .collect();
        let export_nodes = native_export_nodes(node, edges, nodes);
        let mut evidence_ids: Vec<String> = linked.iter().map(|item| item.evidence_id.clone()).collect();
        evidence_ids.sort_by(|left, right| compare_unicode_code_points(left, right));
        handoffs.push(json!({
            "native_node_id": node["node_id"],
            "artifact_sha256": digest,
            "artifact_path": artifact_path(node),
            "export_node_ids": export_nodes.iter().map(|item| item["node_id"].clone()).collect::<Vec<_>>(),
            "requested_exports": requested_exports(&export_nodes),
            "status": if linked.is_empty() { "requires-provider-analysis" } else { "evidence-linked" },
            "providers": unique_providers(&linked),
            "evidence_ids": evidence_ids,
            "recommended_tools": ["open_binary", "binary_overview", "search_procedures", "analyze_function", "xrefs"],
        }));
    }
    handoffs.sort_by(|left, right| {
        compare_unicode_code_points(
            left["native_node_id"].as_str().unwrap_or(""),
            right["native_node_id"].as_str().unwrap_or(""),
        )
    });
    handoffs
}

fn artifact_digest(node: &Value) -> Option<String> {
    if node["identity"]["strategy"].as_str() == Some("content-digest") {
        return node["identity"]["sha256"].as_str().map(str::to_string);
    }
    node["observations"].as_array().and_then(|observations| {
        observations.iter().find_map(|observation| {
            let artifact = &observation["evidence"]["artifact"];
            if artifact["available"].as_bool() == Some(true) {
                artifact["sha256"].as_str().map(str::to_string)
            } else {
                None
            }
        })
    })
}

fn artifact_path(node: &Value) -> Value {
    let Some(observations) = node["observations"].as_array() else {
        return Value::Null;
    };
    for observation in observations {
        let location = &observation["evidence"]["location"];
        if location["available"].as_bool() == Some(true)
            && location["value"]["kind"].as_str() == Some("artifact-path")
        {
            return location["value"]["path"].clone();
        }
    }
    Value::Null
}

fn native_export_nodes<'a>(addon: &Value, edges: &'a [Value], nodes: &'a [Value]) -> Vec<&'a Value> {
    let addon_id = addon["node_id"].as_str().unwrap_or("");
    let mut ids = Vec::new();
    for edge in edges {
        let relation = edge["relation"].as_str().unwrap_or("");
        if edge["source_node_id"].as_str() == Some(addon_id) && matches!(relation, "contains" | "exposes")
        {
            if let Some(id) = edge["target_node_id"].as_str() {
                ids.push(id.to_string());
            }
        }
        if edge["target_node_id"].as_str() == Some(addon_id) && matches!(relation, "imports" | "loads")
        {
            if let Some(id) = edge["source_node_id"].as_str() {
                ids.push(id.to_string());
            }
        }
    }
    ids.sort();
    ids.dedup();
    let mut exports: Vec<&Value> = ids
        .iter()
        .filter_map(|id| {
            nodes.iter().find(|node| {
                node["node_id"].as_str() == Some(id.as_str()) && node["kind"].as_str() == Some("native-export")
            })
        })
        .collect();
    exports.sort_by(|left, right| {
        compare_unicode_code_points(
            left["node_id"].as_str().unwrap_or(""),
            right["node_id"].as_str().unwrap_or(""),
        )
    });
    exports
}

fn requested_exports(nodes: &[&Value]) -> Vec<String> {
    let mut values = Vec::new();
    for node in nodes {
        let Some(observations) = node["observations"].as_array() else {
            continue;
        };
        for observation in observations {
            let properties = &observation["properties"];
            let label = observation["label"].as_str();
            if label.is_some() && !properties["requested_members"].is_array() {
                if let Some(label) = label {
                    values.push(label.to_string());
                }
            }
            values.extend(string_list(&properties["requested_members"]));
            values.extend(string_list(&properties["members"]));
        }
    }
    unique_sorted(&values)
}

fn unique_providers(evidence: &[&Evidence]) -> Vec<Value> {
    let mut providers = Vec::new();
    let mut seen = HashSet::new();
    for item in evidence {
        let version = item.provider.version.clone().unwrap_or_default();
        let key = format!("{}\0{}\0{}", item.provider.id, item.provider.name, version);
        if seen.insert(key) {
            providers.push(json!({
                "id": item.provider.id,
                "name": item.provider.name,
                "version": item.provider.version,
            }));
        }
    }
    providers.sort_by(|left, right| {
        let key = |value: &Value| {
            format!(
                "{}\0{}\0{}",
                value["id"].as_str().unwrap_or(""),
                value["name"].as_str().unwrap_or(""),
                value["version"].as_str().unwrap_or("")
            )
        };
        compare_unicode_code_points(&key(left), &key(right))
    });
    providers
}

fn find_seeds(nodes: &[Value], seed: &Value) -> Vec<Value> {
    let mut matches = Vec::new();
    for node in nodes {
        if let Some(found) = seed_match(node, seed) {
            matches.push(found);
        }
    }
    matches.sort_by(|left, right| {
        let key = |value: &Value| {
            format!(
                "{}\0{}\0{}",
                value["node_id"].as_str().unwrap_or(""),
                value["basis"].as_str().unwrap_or(""),
                value["field"].as_str().unwrap_or("")
            )
        };
        compare_unicode_code_points(&key(left), &key(right))
    });
    matches
}

fn seed_match(node: &Value, seed: &Value) -> Option<Value> {
    let kind = seed["kind"].as_str()?;
    let value = seed["value"].as_str()?;
    if kind == "node-id" {
        return (node["node_id"].as_str() == Some(value)).then(|| {
            json!({
                "node_id": node["node_id"],
                "kind": node["kind"],
                "basis": "node-id",
                "field": "node_id",
            })
        });
    }
    if !kind_matches(node, kind) {
        return None;
    }
    let mode = match_mode(seed);
    let case_sensitive = seed["case_sensitive"].as_bool().unwrap_or(false);
    let query = normalized_text(value, case_sensitive);
    let found = candidate_fields(node, kind)
        .into_iter()
        .find(|candidate| {
            let text = normalized_text(&candidate.value, case_sensitive);
            if mode == "exact" {
                text == query
            } else {
                text.contains(&query)
            }
        })?;
    Some(json!({
        "node_id": node["node_id"],
        "kind": node["kind"],
        "basis": found.basis,
        "field": found.field,
    }))
}

struct Candidate {
    basis: &'static str,
    field: String,
    selection_path: String,
    value: String,
}

fn kind_matches(node: &Value, kind: &str) -> bool {
    let node_kind = node["kind"].as_str().unwrap_or("");
    match kind {
        "string" => true,
        "route" => {
            node_kind == "endpoint"
                && node["observations"].as_array().is_some_and(|observations| {
                    observations
                        .iter()
                        .any(|observation| observation["properties"]["endpoint_kind"].as_str() == Some("route"))
                })
        }
        "api" => node_kind == "context-bridge-api",
        "channel" => node_kind == "ipc-channel",
        "module" => matches!(node_kind, "javascript-asset" | "javascript-module" | "source-module"),
        "native-export" => node_kind == "native-export",
        _ => false,
    }
}

fn candidate_fields(node: &Value, seed_kind: &str) -> Vec<Candidate> {
    let mut fields = identity_fields(node);
    if let Some(observations) = node["observations"].as_array() {
        for (index, observation) in observations.iter().enumerate() {
            if let Some(label) = observation["label"].as_str() {
                fields.push(Candidate {
                    basis: "label",
                    field: format!("observations[{index}].label"),
                    selection_path: format!("observations[{index}].label"),
                    value: label.to_string(),
                });
            }
            let resolution = &observation["source_map_reference"]["resolution"];
            if observation["source_map_reference"].is_object()
                && resolution["kind"].as_str().is_some_and(|kind| kind != "unresolved")
            {
                if let Some(path) = resolution["path"].as_str() {
                    fields.push(Candidate {
                        basis: "property",
                        field: format!("observations[{index}].source_map_reference.resolution.path"),
                        selection_path: format!("observations[{index}].source_map_reference.resolution.path"),
                        value: path.to_string(),
                    });
                }
            }
            fields.extend(property_fields(
                &observation["properties"],
                &format!("observations[{index}].properties"),
            ));
        }
    }
    if seed_kind == "string" {
        return fields;
    }
    let names = relevant_fields(seed_kind);
    fields
        .into_iter()
        .filter(|candidate| {
            names.iter().any(|name| {
                let path = if member_suffix(name) {
                    candidate.selection_path.as_str()
                } else {
                    candidate.field.as_str()
                };
                path == "identity" || path.ends_with(name)
            })
        })
        .collect()
}

fn member_suffix(name: &str) -> bool {
    matches!(name, ".members" | ".methods" | ".exports" | ".requested_members")
}

fn relevant_fields(kind: &str) -> &'static [&'static str] {
    match kind {
        "route" => &[".label", ".value", ".path"],
        "api" => &[".label", ".api_name", ".api_key", ".key", ".methods", ".members"],
        "channel" => &[".label", ".channel", ".key"],
        "module" => &[
            ".label",
            ".module_key",
            ".path",
            ".source",
            ".original_source",
            ".source_root",
            ".exports",
        ],
        "native-export" => &[".label", ".key", ".requested_members", ".members"],
        _ => &[],
    }
}

fn identity_fields(node: &Value) -> Vec<Candidate> {
    let identity = &node["identity"];
    let strategy = identity["strategy"].as_str().unwrap_or("");
    match strategy {
        "content-digest" => vec![candidate("identity", "identity", identity["sha256"].as_str().unwrap_or(""))],
        "source-map-original" => {
            let mut fields = vec![candidate(
                "identity",
                "identity.original_source",
                identity["original_source"].as_str().unwrap_or(""),
            )];
            if let Some(root) = identity["source_root"].as_str() {
                fields.push(candidate("identity", "identity.source_root", root));
            }
            fields
        }
        "canonical-path" => vec![candidate("identity", "identity.path", identity["path"].as_str().unwrap_or(""))],
        "artifact-local-key" => vec![candidate("identity", "identity.key", identity["key"].as_str().unwrap_or(""))],
        "runtime-instance" => vec![candidate(
            "identity",
            "identity.runtime_key",
            identity["runtime_key"].as_str().unwrap_or(""),
        )],
        _ => Vec::new(),
    }
}

fn candidate(basis: &'static str, field: &str, value: &str) -> Candidate {
    Candidate {
        basis,
        field: field.to_string(),
        selection_path: field.to_string(),
        value: value.to_string(),
    }
}

fn property_fields(value: &Value, prefix: &str) -> Vec<Candidate> {
    let mut output = Vec::new();
    let mut pending = vec![(value.clone(), prefix.to_string(), prefix.to_string())];
    while let Some((current, path, selection_path)) = pending.pop() {
        if let Some(text) = current.as_str() {
            output.push(Candidate {
                basis: "property",
                field: path,
                selection_path,
                value: text.to_string(),
            });
            continue;
        }
        if let Some(items) = current.as_array() {
            for (index, item) in items.iter().enumerate().rev() {
                pending.push((item.clone(), format!("{path}[{index}]"), selection_path.clone()));
            }
            continue;
        }
        if let Some(object) = current.as_object() {
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort_by(|left, right| compare_unicode_code_points(left, right));
            for key in keys.into_iter().rev() {
                pending.push((
                    object.get(key).cloned().unwrap_or(Value::Null),
                    format!("{path}.{key}"),
                    format!("{selection_path}.{key}"),
                ));
            }
        }
    }
    output
}

fn match_mode(seed: &Value) -> &'static str {
    match seed["match"].as_str() {
        Some("exact") => "exact",
        Some("contains") => "contains",
        _ => {
            if seed["kind"].as_str() == Some("string") {
                "contains"
            } else {
                "exact"
            }
        }
    }
}

fn normalized_text(value: &str, case_sensitive: bool) -> String {
    let composed: String = value.nfkc().collect();
    if case_sensitive {
        composed
    } else {
        composed.chars().flat_map(char::to_lowercase).collect()
    }
}

fn normalize_seed(seed: &Value) -> Result<Value, JsError> {
    let kind = required_str(seed, "kind")?;
    let value = seed
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsError::InvalidInput("seed.value missing".into()))?;
    let literal = matches!(kind, "route" | "string" | "api" | "channel" | "module" | "native-export");
    if kind != "node-id" && !literal {
        return Err(JsError::InvalidInput(format!("unsupported seed kind {kind}")));
    }
    if value.is_empty() && !(literal && seed["match"].as_str() == Some("exact")) {
        return Err(JsError::InvalidInput(
            "empty feature seeds require an explicit exact match".into(),
        ));
    }
    if !value.is_empty() && seed.get("match").is_some() && !seed["match"].is_null() && seed["match"].as_str().is_none()
    {
        return Err(JsError::InvalidInput("seed.match is invalid".into()));
    }
    let mut normalized = seed.clone();
    if let Some(obj) = normalized.as_object_mut() {
        obj.entry("match".to_string()).or_insert(Value::Null);
        obj.entry("case_sensitive".to_string())
            .or_insert(json!(false));
    }
    Ok(normalized)
}

fn normalize_direction(direction: Option<&str>) -> Result<String, JsError> {
    match direction {
        None => Ok("both".to_string()),
        Some("outgoing" | "incoming" | "both") => Ok(direction.unwrap().to_string()),
        Some(other) => Err(JsError::InvalidInput(format!("unsupported direction {other}"))),
    }
}

fn require_unique_ids(evidence: &[Evidence]) -> Result<(), JsError> {
    let mut seen = HashSet::new();
    for item in evidence {
        if !seen.insert(item.evidence_id.clone()) {
            return Err(JsError::InvalidInput(
                "Native observations must be unique".into(),
            ));
        }
    }
    Ok(())
}

pub fn application_graph(evidence: &Evidence) -> Result<&Value, JsError> {
    if evidence.operation != "analyze_javascript_application" {
        return Err(JsError::InvalidInput(
            "application evidence must come from analyze_javascript_application".into(),
        ));
    }
    if evidence.predicate_type != "rea.javascript-application-analysis" {
        return Err(JsError::InvalidInput(
            "application evidence predicate does not match".into(),
        ));
    }
    evidence
        .normalized_result
        .get("graph")
        .ok_or_else(|| JsError::InvalidInput("application graph missing".into()))
}

fn string_list(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}
