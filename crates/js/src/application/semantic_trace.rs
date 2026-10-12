//! `trace_javascript_semantics` — static semantic graph traversal (REA query port).

use std::collections::{HashMap, HashSet, VecDeque};

use serde_json::{json, Value};
use tracewise_domain::evidence::{
    create_evidence, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation,
    EvidenceProvider,
};

use crate::error::JsError;
use crate::unicode::{compare_unicode_code_points, unique_sorted};

use super::graph_ids::jsrq_id;
use super::semantic_graph::semantic_graph_from_result;

const MISSING_SUBJECT: &str = "Artifact identity is unavailable for this observation.";

const OWNERSHIP_RELATIONS: &[&str] = &[
    "acquires",
    "aggregates",
    "awaits",
    "chains",
    "connects-stdio",
    "creates-promise",
    "detaches-task",
    "owns",
    "releases",
    "returns-task",
    "spawns",
];

pub fn trace_javascript_semantics(
    application: &Evidence,
    query: &Value,
) -> Result<Evidence, JsError> {
    validate_application_evidence(application)?;
    let semantic = semantic_graph_from_result(&application.normalized_result)?;
    let graph_id = required_str(semantic, "graph_id")?;
    let query_id = jsrq_id(graph_id, query)?;
    let seeds = resolve_seeds(semantic, query)?;
    let traversal = traverse(semantic, query, &seeds)?;
    let (nodes, relations) = retained_subgraph(semantic, &traversal);
    let unknowns = relevant_unknowns(semantic, &traversal.node_ids, query);
    let candidate_relations = relevant_candidate_relations(semantic, &traversal.node_ids, query);
    let expected_match_node_ids = expected_match_node_ids(&nodes, &relations, query);
    let retained_context_ids = retained_context_ids(&nodes, &relations, &unknowns);
    let evidence_contexts = filter_evidence_contexts(semantic, &retained_context_ids);
    let assessment = assess_query(
        semantic,
        seeds.len(),
        expected_match_node_ids.len(),
        query.get("expected").map(|v| !v.is_null()).unwrap_or(false),
        unknowns.len(),
        candidate_relations,
    );
    let result_limitations = assessment.limitations.clone();
    let mut envelope_limitations = vec![MISSING_SUBJECT.to_string()];
    envelope_limitations.extend(result_limitations.clone());
    let normalized = json!({
        "query_id": query_id,
        "source_graph_id": graph_id,
        "seed": query.get("seed").cloned().unwrap_or(Value::Null),
        "direction": query.get("direction").cloned().unwrap_or(Value::Null),
        "status": assessment.status,
        "seed_node_ids": seeds,
        "evidence_contexts": evidence_contexts,
        "nodes": nodes,
        "relations": relations,
        "unknowns": unknowns,
        "expected_match_node_ids": expected_match_node_ids,
        "summary": {
            "total_seed_matches": seeds.len(),
            "traversed_nodes": traversal.node_ids.len(),
            "traversed_relations": traversal.relation_ids.len(),
            "traversed_functions": traversal.function_ids.len(),
            "traversed_modules": traversal.modules.len(),
            "relevant_unknowns": unknowns.len(),
        },
        "coverage": assessment.coverage,
        "limitations": result_limitations,
        "source_evidence_id": application.evidence_id,
        "evidence_links": [application.evidence_id.clone()],
    });
    create_evidence(
        None,
        EvidenceProvider {
            id: "rea-javascript-application-workflows".to_string(),
            name: "REA JavaScript application workflows".to_string(),
            version: Some("1".to_string()),
        },
        EvidenceObservation {
            predicate_type: Some("rea.javascript-semantic-trace".to_string()),
            operation: "trace_javascript_semantics".to_string(),
            parameters: json!({
                "application_evidence_id": application.evidence_id,
                "query": query,
            }),
            normalized_result: normalized,
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Inferred),
            authority: Some(EvidenceAuthority::AnalystInference),
            environment: None,
            limitations: Some(envelope_limitations),
            locations: None,
            evidence_links: Some(vec![application.evidence_id.clone()]),
        },
    )
    .map_err(JsError::from)
}

struct Traversal {
    node_ids: HashSet<String>,
    relation_ids: HashSet<String>,
    function_ids: HashSet<String>,
    modules: HashSet<String>,
}

struct Assessment {
    status: String,
    coverage: Value,
    limitations: Vec<String>,
}

fn validate_application_evidence(application: &Evidence) -> Result<(), JsError> {
    if application.operation != "analyze_javascript_application" {
        return Err(JsError::InvalidInput(
            "trace_javascript_semantics requires analyze_javascript_application evidence".into(),
        ));
    }
    if application.predicate_type != "rea.javascript-application-analysis" {
        return Err(JsError::InvalidInput(
            "application evidence predicate does not match".into(),
        ));
    }
    if application.provider.id != "rea-javascript-application" {
        return Err(JsError::InvalidInput("application provider mismatch".into()));
    }
    Ok(())
}

fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str, JsError> {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsError::InvalidInput(format!("{key} missing")))
}

fn resolve_seeds(graph: &Value, query: &Value) -> Result<Vec<String>, JsError> {
    let seed = query
        .get("seed")
        .ok_or_else(|| JsError::InvalidInput("query.seed missing".into()))?;
    let kind = required_str(seed, "kind")?;
    let nodes = graph
        .get("nodes")
        .and_then(|v| v.as_array())
        .ok_or_else(|| JsError::InvalidInput("semantic nodes missing".into()))?;
    let mut ids = Vec::new();
    for node in nodes {
        let node_id = required_str(node, "node_id")?;
        let matches = match kind {
            "semantic-node" => seed.get("node_id").and_then(|v| v.as_str()) == Some(node_id),
            "application-node" => {
                seed.get("node_id").and_then(|v| v.as_str())
                    == node
                        .get("application_node_ids")
                        .and_then(|v| v.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|v| v.as_str())
            }
            "function" => {
                let fp = seed.get("fingerprint_sha256").and_then(|v| v.as_str());
                node.get("kind").and_then(|v| v.as_str()) == Some("function")
                    && graph
                        .get("fingerprints")
                        .and_then(|v| v.as_array())
                        .map(|fps| {
                            fps.iter().any(|entry| {
                                entry.get("function_node_id").and_then(|v| v.as_str()) == Some(node_id)
                                    && entry.get("fingerprint_sha256").and_then(|v| v.as_str()) == fp
                            })
                        })
                        .unwrap_or(false)
            }
            _ => false,
        };
        if matches {
            ids.push(node_id.to_string());
        }
    }
    ids.sort_by(|a, b| compare_unicode_code_points(a, b));
    Ok(ids)
}

fn traverse(graph: &Value, query: &Value, seeds: &[String]) -> Result<Traversal, JsError> {
    let direction = required_str(query, "direction")?;
    let include_ambiguous = query
        .get("include_ambiguous_dynamic_edges")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let allowed = query.get("allowed_relations").and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect::<HashSet<_>>()
    });
    let nodes: HashMap<String, Value> = graph
        .get("nodes")
        .and_then(|v| v.as_array())
        .ok_or_else(|| JsError::InvalidInput("semantic nodes missing".into()))?
        .iter()
        .filter_map(|n| {
            n.get("node_id")
                .and_then(|v| v.as_str())
                .map(|id| (id.to_string(), n.clone()))
        })
        .collect();
    let adjacency = build_adjacency(
        graph
            .get("relations")
            .and_then(|v| v.as_array())
            .ok_or_else(|| JsError::InvalidInput("relations missing".into()))?,
        direction,
        include_ambiguous,
        allowed.as_ref(),
    );
    let mut node_ids: HashSet<String> = seeds.iter().cloned().collect();
    let mut relation_ids = HashSet::new();
    let mut function_ids = HashSet::new();
    let mut modules = HashSet::new();
    for id in &node_ids {
        retain_owners(nodes.get(id), &mut function_ids, &mut modules);
    }
    let mut queue: VecDeque<String> = node_ids.iter().cloned().collect();
    while let Some(current) = queue.pop_front() {
        for entry in adjacency.get(&current).map(|v| v.as_slice()).unwrap_or(&[]) {
            relation_ids.insert(entry.relation_id.clone());
            if node_ids.contains(&entry.next_node_id) {
                continue;
            }
            if nodes.contains_key(&entry.next_node_id) {
                node_ids.insert(entry.next_node_id.clone());
                retain_owners(nodes.get(&entry.next_node_id), &mut function_ids, &mut modules);
                queue.push_back(entry.next_node_id.clone());
            }
        }
    }
    Ok(Traversal {
        node_ids,
        relation_ids,
        function_ids,
        modules,
    })
}

struct AdjEntry {
    next_node_id: String,
    relation_id: String,
}

fn build_adjacency(
    relations: &[Value],
    direction: &str,
    include_ambiguous: bool,
    allowed: Option<&HashSet<String>>,
) -> HashMap<String, Vec<AdjEntry>> {
    let mut adjacency: HashMap<String, Vec<AdjEntry>> = HashMap::new();
    for relation in relations {
        let rel_kind = relation.get("relation").and_then(|v| v.as_str()).unwrap_or("");
        if let Some(set) = allowed {
            if !set.contains(rel_kind) {
                continue;
            }
        }
        if relation.get("resolution").and_then(|v| v.as_str()) == Some("candidate")
            && !include_ambiguous
        {
            continue;
        }
        let source = relation
            .get("source_node_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let target = relation
            .get("target_node_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let relation_id = relation
            .get("relation_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        add_directed(&mut adjacency, relation, direction, source, target, relation_id.clone());
    }
    adjacency
}

fn add_directed(
    adjacency: &mut HashMap<String, Vec<AdjEntry>>,
    relation: &Value,
    direction: &str,
    source: &str,
    target: &str,
    relation_id: String,
) {
    let rel = relation.get("relation").and_then(|v| v.as_str()).unwrap_or("");
    match direction {
        "callers" => {
            if rel == "calls" {
                push_entry(adjacency, target, source, relation_id);
            }
        }
        "ownership" => {
            if OWNERSHIP_RELATIONS.contains(&rel) {
                push_entry(adjacency, source, target, relation_id.clone());
                push_entry(adjacency, target, source, relation_id);
            }
        }
        "backward-provenance" => push_entry(adjacency, target, source, relation_id),
        _ => push_entry(adjacency, source, target, relation_id),
    }
}

fn push_entry(
    adjacency: &mut HashMap<String, Vec<AdjEntry>>,
    from: &str,
    to: &str,
    relation_id: String,
) {
    adjacency
        .entry(from.to_string())
        .or_default()
        .push(AdjEntry {
            next_node_id: to.to_string(),
            relation_id,
        });
}

fn retain_owners(node: Option<&Value>, functions: &mut HashSet<String>, modules: &mut HashSet<String>) {
    if let Some(node) = node {
        let function_id = if node.get("kind").and_then(|v| v.as_str()) == Some("function") {
            node.get("node_id").and_then(|v| v.as_str())
        } else {
            node.get("function_node_id").and_then(|v| v.as_str())
        };
        if let Some(id) = function_id {
            functions.insert(id.to_string());
        }
        if let Some(path) = node
            .get("identity")
            .and_then(|v| v.get("module_path"))
            .and_then(|v| v.as_str())
        {
            modules.insert(path.to_string());
        }
    }
}

fn retained_subgraph(graph: &Value, traversal: &Traversal) -> (Vec<Value>, Vec<Value>) {
    let nodes = graph
        .get("nodes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|n| {
                    n.get("node_id")
                        .and_then(|v| v.as_str())
                        .map(|id| traversal.node_ids.contains(id))
                        .unwrap_or(false)
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let relations = graph
        .get("relations")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|r| {
                    r.get("relation_id")
                        .and_then(|v| v.as_str())
                        .map(|id| traversal.relation_ids.contains(id))
                        .unwrap_or(false)
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    (nodes, relations)
}

fn relevant_unknowns(graph: &Value, node_ids: &HashSet<String>, query: &Value) -> Vec<Value> {
    let allowed = query.get("allowed_relations").and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect::<HashSet<_>>()
    });
    graph
        .get("unknowns")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|unknown| {
                    let nid = unknown.get("node_id").and_then(|v| v.as_str());
                    let node_relevant = nid.map(|id| node_ids.contains(id)).unwrap_or(true);
                    if !node_relevant {
                        return false;
                    }
                    match &allowed {
                        None => true,
                        Some(set) => unknown
                            .get("relation_kinds")
                            .and_then(|v| v.as_array())
                            .map(|kinds| {
                                kinds
                                    .iter()
                                    .filter_map(|v| v.as_str())
                                    .any(|k| set.contains(k))
                            })
                            .unwrap_or(false),
                    }
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

fn relevant_candidate_relations(
    graph: &Value,
    node_ids: &HashSet<String>,
    query: &Value,
) -> usize {
    let direction = query.get("direction").and_then(|v| v.as_str()).unwrap_or("");
    let allowed = query.get("allowed_relations").and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect::<HashSet<_>>()
    });
    let relations = graph.get("relations").and_then(|v| v.as_array());
    let mut count = 0;
    for relation in relations.into_iter().flatten() {
        if relation.get("resolution").and_then(|v| v.as_str()) != Some("candidate") {
            continue;
        }
        let rel = relation.get("relation").and_then(|v| v.as_str()).unwrap_or("");
        if let Some(set) = &allowed {
            if !set.contains(rel) {
                continue;
            }
        }
        let source = relation.get("source_node_id").and_then(|v| v.as_str()).unwrap_or("");
        let target = relation.get("target_node_id").and_then(|v| v.as_str()).unwrap_or("");
        let source_rel = node_ids.contains(source);
        let target_rel = node_ids.contains(target);
        let relevant = (direction == "callers" && rel == "calls" && target_rel)
            || (direction == "ownership" && OWNERSHIP_RELATIONS.contains(&rel) && (source_rel || target_rel))
            || (direction == "backward-provenance" && target_rel)
            || (direction == "forward-influence" && source_rel);
        if relevant {
            count += 1;
        }
    }
    count
}

fn expected_match_node_ids(nodes: &[Value], relations: &[Value], query: &Value) -> Vec<String> {
    let expected = query.get("expected");
    if expected.is_none() || expected.map(|v| v.is_null()).unwrap_or(true) {
        return Vec::<String>::new();
    }
    let classes: HashSet<String> = expected
        .and_then(|v| v.get("classes"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let role = expected.and_then(|v| v.get("role")).and_then(|v| v.as_str()).unwrap_or("source");
    let connected: HashSet<String> = relations
        .iter()
        .filter_map(|relation| {
            if role == "source" {
                relation.get("target_node_id").and_then(|v| v.as_str())
            } else {
                relation.get("source_node_id").and_then(|v| v.as_str())
            }
        })
        .map(String::from)
        .collect();
    nodes
        .iter()
        .filter(|node| {
            node.get("kind")
                .and_then(|v| v.as_str())
                .map(|k| classes.contains(k))
                .unwrap_or(false)
                && node
                    .get("node_id")
                    .and_then(|v| v.as_str())
                    .map(|id| !connected.contains(id))
                    .unwrap_or(false)
        })
        .filter_map(|node| node.get("node_id").and_then(|v| v.as_str()).map(String::from))
        .collect()
}

fn retained_context_ids(nodes: &[Value], relations: &[Value], unknowns: &[Value]) -> HashSet<String> {
    let mut ids = HashSet::new();
    for value in nodes
        .iter()
        .chain(relations.iter())
        .chain(unknowns.iter())
    {
        if let Some(id) = value
            .get("evidence")
            .and_then(|e| e.get("context_id"))
            .and_then(|v| v.as_str())
        {
            ids.insert(id.to_string());
        }
    }
    ids
}

fn filter_evidence_contexts(graph: &Value, retained: &HashSet<String>) -> Vec<Value> {
    graph
        .get("evidence_contexts")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|ctx| {
                    ctx.get("context_id")
                        .and_then(|v| v.as_str())
                        .map(|id| retained.contains(id))
                        .unwrap_or(false)
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

fn assess_query(
    graph: &Value,
    total_seeds: usize,
    expected_matches: usize,
    has_expectation: bool,
    unknowns: usize,
    candidate_relations: usize,
) -> Assessment {
    let graph_coverage = graph.get("coverage").cloned().unwrap_or(json!({}));
    let graph_status = graph_coverage
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("complete");
    let truncated = graph_coverage
        .get("truncated")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let coverage_status = if graph_status == "unavailable" {
        "unavailable"
    } else if unknowns > 0
        || candidate_relations > 0
        || graph_status != "complete"
        || truncated
    {
        "partial"
    } else {
        "complete"
    };
    let status = if graph_status == "unavailable" {
        "unsupported".to_string()
    } else if candidate_relations > 0 {
        "ambiguous".to_string()
    } else if total_seeds == 0 || (has_expectation && expected_matches == 0) {
        if unknowns > 0 || graph_status != "complete" || truncated {
            "partial".to_string()
        } else {
            "no-match".to_string()
        }
    } else if total_seeds > 1 {
        "ambiguous".to_string()
    } else {
        "found".to_string()
    };
    let graph_limitations: Vec<String> = graph
        .get("limitations")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let mut limitations = unique_sorted(&[
        "Semantic graph reachability is a static inference and does not prove runtime execution."
            .to_string(),
    ]);
    limitations.extend(graph_limitations);
    if unknowns > 0 {
        limitations.push(
            "Relevant dynamic, unsupported, incomplete, or ambiguous semantics remain unknown."
                .to_string(),
        );
    }
    if candidate_relations > 0 {
        limitations.push(
            "Candidate relations remain ambiguous and do not establish a resolved semantic path."
                .to_string(),
        );
    }
    limitations = unique_sorted(&limitations);
    Assessment {
        status,
        coverage: json!({ "status": coverage_status }),
        limitations,
    }
}
