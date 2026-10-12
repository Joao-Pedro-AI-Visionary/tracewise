//! Semantic identifiers for JavaScript application graphs (REA graph factory).

use serde_json::{json, Map, Value};
use tracewise_domain::canonical::{canonical_json, canonical_sha256};

use crate::error::JsError;
use crate::unicode::{compare_unicode_code_points, unique_sorted};

pub fn digest_prefixed(prefix: &str, value: &Value) -> Result<String, JsError> {
    Ok(format!("{prefix}{}", canonical_sha256(value)?))
}

pub fn canonical_text(value: &Value) -> Result<String, JsError> {
    canonical_json(value).map_err(JsError::from)
}

pub fn seal_application_graph(graph: &Value) -> Result<Value, JsError> {
    let mut nodes = array(graph, "nodes")?;
    nodes.sort_by(|left, right| compare_unicode_code_points(node_id(left), node_id(right)));
    let mut edges = array(graph, "edges")?;
    edges.sort_by(|left, right| compare_unicode_code_points(edge_id(left), edge_id(right)));
    let root_node_ids = unique_sorted(&string_array(graph, "root_node_ids")?);
    if root_node_ids.is_empty() {
        return Err(JsError::InvalidInput(
            "application graph requires a root node".into(),
        ));
    }
    let limitations = unique_sorted(&string_array(graph, "limitations")?);
    let coverage = normalize_coverage(graph.get("coverage").unwrap_or(&Value::Null))?;
    let schema = graph
        .get("schema")
        .and_then(|v| v.as_str())
        .unwrap_or("JavaScriptApplicationGraph");
    let mut content = json!({
        "schema": schema,
        "root_node_ids": root_node_ids,
        "nodes": nodes,
        "edges": edges,
        "coverage": coverage,
        "limitations": limitations,
    });
    let graph_id = digest_prefixed("jag_", &content)?;
    content
        .as_object_mut()
        .expect("object")
        .insert("graph_id".into(), json!(graph_id));
    Ok(content)
}

pub fn recreate_node(node: &Value) -> Result<Value, JsError> {
    let kind = required_str(node, "kind")?;
    let identity = normalize_identity(node.get("identity").cloned().unwrap_or(Value::Null))?;
    let node_id = digest_prefixed("jag_node_", &json!({ "kind": kind, "identity": identity }))?;
    let mut observations = Vec::new();
    for observation in array(node, "observations")? {
        observations.push(recreate_observation(&node_id, &observation)?);
    }
    observations.sort_by(|left, right| {
        compare_unicode_code_points(required_str(left, "observation_id").unwrap_or(""), required_str(right, "observation_id").unwrap_or(""))
    });
    Ok(json!({
        "node_id": node_id,
        "kind": kind,
        "identity": identity,
        "observations": observations,
    }))
}

pub fn create_edge(input: &Value) -> Result<Value, JsError> {
    let mut semantic = Map::new();
    for key in ["source_node_id", "target_node_id", "relation", "properties"] {
        semantic.insert(
            key.into(),
            input.get(key).cloned().unwrap_or(Value::Null),
        );
    }
    semantic.insert(
        "evidence".into(),
        normalize_graph_evidence(input.get("evidence").unwrap_or(&Value::Null))?,
    );
    semantic.insert(
        "identifier_strategy".into(),
        json!({
            "strategy": "semantic-content-sha256",
            "stability": "relationship-exact",
        }),
    );
    let edge_id = digest_prefixed("jag_edge_", &Value::Object(semantic.clone()))?;
    semantic.insert("edge_id".into(), json!(edge_id));
    Ok(Value::Object(semantic))
}

fn recreate_observation(node_id: &str, observation: &Value) -> Result<Value, JsError> {
    let mut semantic = Map::new();
    semantic.insert("node_id".into(), json!(node_id));
    for key in ["label", "source_map_reference", "properties"] {
        if let Some(value) = observation.get(key) {
            semantic.insert(key.into(), value.clone());
        }
    }
    semantic.insert(
        "evidence".into(),
        normalize_graph_evidence(observation.get("evidence").unwrap_or(&Value::Null))?,
    );
    semantic.insert(
        "identifier_strategy".into(),
        json!({
            "strategy": "semantic-content-sha256",
            "stability": "observation-exact",
        }),
    );
    let observation_id = digest_prefixed("jag_observation_", &Value::Object(semantic.clone()))?;
    semantic.remove("node_id");
    semantic.insert("observation_id".into(), json!(observation_id));
    Ok(Value::Object(semantic))
}

pub fn normalize_graph_evidence(evidence: &Value) -> Result<Value, JsError> {
    let mut evidence = evidence.clone();
    let Some(obj) = evidence.as_object_mut() else {
        return Ok(evidence);
    };
    if let Some(coverage) = obj.get("coverage").cloned() {
        obj.insert("coverage".into(), normalize_coverage(&coverage)?);
    }
    if let Some(limitations) = obj.get("limitations") {
        let values = string_list(limitations);
        obj.insert("limitations".into(), json!(unique_sorted(&values)));
    }
    if let Some(links) = obj.get("evidence_ids") {
        let values = string_list(links);
        obj.insert("evidence_ids".into(), json!(unique_sorted(&values)));
    }
    Ok(evidence)
}

fn normalize_identity(identity: Value) -> Result<Value, JsError> {
    let mut identity = identity;
    if identity.get("strategy").and_then(|v| v.as_str()) == Some("structural-fingerprint") {
        if let Some(basis) = identity.get("basis") {
            let sorted = unique_sorted(&string_list(basis));
            if let Some(obj) = identity.as_object_mut() {
                obj.insert("basis".into(), json!(sorted));
            }
        }
    }
    Ok(identity)
}

fn normalize_coverage(coverage: &Value) -> Result<Value, JsError> {
    let mut coverage = coverage.clone();
    let limits = coverage
        .get("limits")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if let Some(obj) = coverage.as_object_mut() {
        obj.insert("limits".into(), json!(normalize_limits(&limits)?));
    }
    Ok(coverage)
}

fn normalize_limits(limits: &[Value]) -> Result<Vec<Value>, JsError> {
    let mut keyed = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for limit in limits {
        let key = canonical_text(limit)?;
        if seen.insert(key.clone()) {
            keyed.push((key, limit.clone()));
        }
    }
    keyed.sort_by(|left, right| compare_unicode_code_points(&left.0, &right.0));
    Ok(keyed.into_iter().map(|(_, value)| value).collect())
}

fn array(value: &Value, key: &str) -> Result<Vec<Value>, JsError> {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .cloned()
        .ok_or_else(|| JsError::InvalidInput(format!("{key} missing")))
}

fn string_array(value: &Value, key: &str) -> Result<Vec<String>, JsError> {
    Ok(string_list(value.get(key).unwrap_or(&Value::Null)))
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

fn node_id(node: &Value) -> &str {
    node.get("node_id").and_then(|v| v.as_str()).unwrap_or("")
}

fn edge_id(edge: &Value) -> &str {
    edge.get("edge_id").and_then(|v| v.as_str()).unwrap_or("")
}

pub fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str, JsError> {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsError::InvalidInput(format!("{key} missing")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_graph() -> Value {
        let body: Value = serde_json::from_str(include_str!(
            "../../../../fixtures/js/app_analysis_normalized_body.json"
        ))
        .expect("body");
        body["graph"].clone()
    }

    #[test]
    fn resealing_fixture_graph_keeps_identifiers() {
        let graph = fixture_graph();
        let sealed = seal_application_graph(&graph).expect("seal");
        assert_eq!(sealed["graph_id"], graph["graph_id"]);
        let nodes = graph["nodes"].as_array().expect("nodes");
        for node in nodes {
            let recreated = recreate_node(node).expect("node");
            assert_eq!(&recreated, node);
        }
        let edges = graph["edges"].as_array().expect("edges");
        for edge in edges {
            let recreated = create_edge(edge).expect("edge");
            assert_eq!(&recreated["edge_id"], &edge["edge_id"]);
        }
    }
}
