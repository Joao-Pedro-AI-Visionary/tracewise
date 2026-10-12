//! Stable graph identifiers (REA `javascriptApplicationGraph.ts` / semantic graph).

use serde_json::Value;

use crate::digest::digest_canonical_value;
use crate::error::JsError;

#[allow(dead_code)]
pub fn jag_node_id(kind: &str, identity: &Value) -> Result<String, JsError> {
    let semantic = serde_json::json!({ "kind": kind, "identity": identity });
    Ok(format!(
        "jag_node_{}",
        digest_canonical_value(&semantic)?
    ))
}

pub fn jsrq_id(graph_id: &str, query: &Value) -> Result<String, JsError> {
    let mut body = query.as_object().cloned().unwrap_or_default();
    body.insert(
        "source_graph_id".to_string(),
        Value::String(graph_id.to_string()),
    );
    if let Some(allowed) = body.get("allowed_relations") {
        if let Some(arr) = allowed.as_array() {
            let sorted = crate::unicode::unique_sorted(
                &arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>(),
            );
            body.insert("allowed_relations".to_string(), serde_json::json!(sorted));
        }
    }
    if let Some(expected) = body.get("expected") {
        if !expected.is_null() {
            if let Some(obj) = expected.as_object() {
                let mut copy = obj.clone();
                if let Some(classes) = copy.get("classes").and_then(|v| v.as_array()) {
                    let sorted = crate::unicode::unique_sorted(
                        &classes
                            .iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect::<Vec<_>>(),
                    );
                    copy.insert("classes".to_string(), serde_json::json!(sorted));
                }
                body.insert("expected".to_string(), Value::Object(copy));
            }
        }
    }
    Ok(format!("jsrq_{}", digest_canonical_value(&Value::Object(body))?))
}
