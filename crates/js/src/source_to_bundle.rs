//! Historical-source to shipped-bundle comparison.
//!
//! Signal weights and classifications follow REA `sourceToBundleComparison.ts`.
//! The envelope limitation about missing artifact identity is added only on the
//! Evidence record, matching `createEvidence` when the subject is absent.

use std::collections::HashSet;

use serde_json::{json, Map, Value};
use tracewise_domain::canonical::canonical_sha256;
use tracewise_domain::evidence::{
    create_evidence, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation,
    EvidenceProvider,
};

use crate::error::JsError;
use crate::source_bundle_classify::{
    classify, comparison_limitations, item_value, mark_merged, summary_of,
};
use crate::source_bundle_index::{
    build_index, candidate_has_digest, candidate_ids_for, historical_sources, score_candidate,
    source_bearing_nodes,
};
use crate::source_bundle_paths::{required_str, string_array};
use crate::unicode::{compare_unicode_code_points, unique_sorted};

const WEIGHTS: &[(&str, i64)] = &[
    ("exact-source-digest", 100),
    ("source-map-original-path", 70),
    ("current-path-exact", 60),
    ("current-path-suffix", 40),
    ("basename-match", 20),
    ("language-extension", 5),
];
const MISSING_SUBJECT: &str = "Artifact identity is unavailable for this observation.";

pub fn compare_source_to_bundle_tool(
    reference: &Value,
    application: &Evidence,
) -> Result<Evidence, JsError> {
    let (root_sha, graph) = application_graph(application)?;
    let result = compare_mappings(reference, application.evidence_id.as_str(), &root_sha, graph)?;
    let result_limitations = string_array(result.get("limitations").unwrap_or(&Value::Null), "limitations")?;
    let mut envelope_limitations = vec![MISSING_SUBJECT.to_string()];
    envelope_limitations.extend(result_limitations);
    let evidence_links = vec![application.evidence_id.clone()];
    create_evidence(
        None,
        EvidenceProvider {
            id: "rea-javascript-application-workflows".to_string(),
            name: "REA JavaScript application workflows".to_string(),
            version: Some("1".to_string()),
        },
        EvidenceObservation {
            predicate_type: Some("rea.source-to-bundle-comparison".to_string()),
            operation: "compare_source_to_bundle".to_string(),
            parameters: json!({
                "reference_root_sha256": reference
                    .get("root_sha256")
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
                "application_evidence_id": application.evidence_id,
            }),
            normalized_result: result,
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Inferred),
            authority: Some(EvidenceAuthority::AnalystInference),
            environment: None,
            limitations: Some(envelope_limitations),
            locations: None,
            evidence_links: Some(evidence_links),
        },
    )
    .map_err(JsError::from)
}

fn application_graph(evidence: &Evidence) -> Result<(String, &Value), JsError> {
    if evidence.operation != "analyze_javascript_application" {
        return Err(JsError::InvalidInput(
            "compare_source_to_bundle requires analyze_javascript_application evidence".into(),
        ));
    }
    if evidence.predicate_type != "rea.javascript-application-analysis" {
        return Err(JsError::InvalidInput(
            "JavaScript application evidence predicate does not match its result".into(),
        ));
    }
    if evidence.provider.id != "rea-javascript-application"
        || evidence.provider.name != "REA JavaScript application analyzer"
        || evidence.provider.version.as_deref() != Some("1")
    {
        return Err(JsError::InvalidInput(
            "JavaScript application evidence provider does not match".into(),
        ));
    }
    if evidence.authority != EvidenceAuthority::ShippedArtifact
        || evidence.confidence != EvidenceConfidence::Derived
    {
        return Err(JsError::InvalidInput(
            "JavaScript application evidence must use shipped-artifact authority and derived confidence".into(),
        ));
    }
    let nr = &evidence.normalized_result;
    let root = required_str(nr, "root_artifact_sha256")?;
    let format = required_str(nr, "format")?;
    let input_path = required_str(nr, "input_path")?;
    let subject = evidence.subject.as_ref().ok_or_else(|| {
        JsError::InvalidInput("JavaScript application evidence is missing its subject".into())
    })?;
    if subject.digest.sha256 != root || subject.format != format || subject.local_path != input_path {
        return Err(JsError::InvalidInput(
            "JavaScript application evidence subject does not match the analyzed artifact".into(),
        ));
    }
    let graph = nr
        .get("graph")
        .ok_or_else(|| JsError::InvalidInput("application graph is missing".into()))?;
    Ok((root, graph))
}

fn compare_mappings(
    reference: &Value,
    evidence_id: &str,
    root_sha: &str,
    graph: &Value,
) -> Result<Value, JsError> {
    let graph_id = required_str(graph, "graph_id")?;
    let inventory_state = required_str(reference, "inventory_state")?;
    let reference_root = required_str(reference, "root_sha256")?;
    let sources = historical_sources(reference)?;
    let nodes = source_bearing_nodes(graph)?;
    let index = build_index(&nodes);
    let absence = inventory_state == "complete" && absence_claimable(graph.get("coverage"))?;
    let coverage_status = graph
        .get("coverage")
        .and_then(|c| c.get("status"))
        .and_then(|s| s.as_str())
        .unwrap_or("unknown");
    let mut evaluations = 0i64;
    let mut items = Vec::new();
    for source in &sources {
        let candidate_ids = candidate_ids_for(source, &index);
        evaluations += candidate_ids.len() as i64;
        let mut scored = Vec::new();
        for node_id in &candidate_ids {
            if let Some(candidate) = score_candidate(source, node_id, &index)? {
                scored.push(candidate);
            }
        }
        scored.sort_by(|left, right| {
            right
                .get("score")
                .and_then(|v| v.as_i64())
                .unwrap_or(0)
                .cmp(&left.get("score").and_then(|v| v.as_i64()).unwrap_or(0))
                .then_with(|| {
                    compare_unicode_code_points(
                        left.get("current_node_id").and_then(|v| v.as_str()).unwrap_or(""),
                        right.get("current_node_id").and_then(|v| v.as_str()).unwrap_or(""),
                    )
                })
        });
        let classification = classify(&scored, absence, |node_id| {
            source.sha256.is_some() && candidate_has_digest(&index, node_id)
        });
        let limitations = unique_sorted(
            &source
                .limitations
                .iter()
                .cloned()
                .chain(classification.limitations)
                .collect::<Vec<_>>(),
        );
        items.push(item_value(
            &reference_root,
            &graph_id,
            source,
            &classification.status,
            &classification.confidence,
            &classification.node_ids,
            &scored,
            &limitations,
        )?);
    }
    let items = mark_merged(&reference_root, &graph_id, items)?;
    let mapped: HashSet<&str> = items
        .iter()
        .filter_map(|item| item.get("current_node_ids").and_then(|v| v.as_array()))
        .flatten()
        .filter_map(|v| v.as_str())
        .collect();
    let unmapped: Vec<Value> = nodes
        .iter()
        .filter(|node| !mapped.contains(node.node_id.as_str()))
        .map(|node| Value::String(node.node_id.clone()))
        .collect();
    let summary = summary_of(&items);
    let limitations = comparison_limitations(reference, graph, &inventory_state, coverage_status)?;
    let mut semantic = Map::new();
    semantic.insert(
        "reference".into(),
        json!({"root_sha256": reference_root, "inventory_state": inventory_state}),
    );
    semantic.insert(
        "application".into(),
        json!({
            "evidence_id": evidence_id,
            "graph_id": graph_id,
            "root_artifact_sha256": root_sha,
        }),
    );
    semantic.insert(
        "scoring".into(),
        json!({
            "algorithm": "rea-source-to-bundle-signals",
            "minimum_candidate_score": 20,
            "weights": WEIGHTS.iter().map(|(signal, weight)| json!({"signal": signal, "weight": weight})).collect::<Vec<_>>(),
        }),
    );
    semantic.insert("summary".into(), summary);
    semantic.insert("items".into(), Value::Array(items));
    semantic.insert("unmapped_current_node_ids".into(), Value::Array(unmapped));
    semantic.insert(
        "coverage".into(),
        json!({
            "status": if inventory_state == "complete" && coverage_status == "complete" {
                "complete-within-inputs"
            } else {
                "partial"
            },
            "reference_inventory_state": inventory_state,
            "application_graph_status": coverage_status,
            "retained_source_files": sources.len() as i64,
            "retained_application_nodes": nodes.len() as i64,
            "candidate_evaluations": evaluations,
        }),
    );
    semantic.insert(
        "evidence_links".into(),
        json!([evidence_id]),
    );
    semantic.insert(
        "limitations".into(),
        Value::Array(limitations.into_iter().map(Value::String).collect()),
    );
    let semantic_value = Value::Object(semantic);
    let comparison_id = format!("stbc_{}", canonical_sha256(&semantic_value)?);
    let mut ordered = Map::new();
    ordered.insert("comparison_id".into(), Value::String(comparison_id));
    if let Value::Object(rest) = semantic_value {
        for (key, value) in rest {
            ordered.insert(key, value);
        }
    }
    Ok(Value::Object(ordered))
}

fn absence_claimable(coverage: Option<&Value>) -> Result<bool, JsError> {
    let Some(coverage) = coverage else {
        return Ok(false);
    };
    let status = coverage.get("status").and_then(|v| v.as_str()).unwrap_or("");
    if status != "complete" {
        return Ok(false);
    }
    if coverage.get("truncated").and_then(|v| v.as_bool()) == Some(true) {
        return Ok(false);
    }
    match coverage.get("omitted_count") {
        None => Ok(true),
        Some(Value::Null) => Ok(false),
        Some(value) => Ok(value.as_i64() == Some(0)),
    }
}

