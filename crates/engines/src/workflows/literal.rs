//! Literal feature tracing through provider xrefs (port of `EnhancedLiteralTracing.ts`).

use std::collections::HashSet;

use serde_json::{json, Value};

use crate::error::AnalysisError;

use super::Env;

/// Trace matching strings and procedures through provider xrefs.
pub async fn trace_feature(env: &Env<'_>, input: &Value) -> Result<Value, AnalysisError> {
    let query = input.get("query").and_then(Value::as_str).unwrap_or_default();
    let case_sensitive = input.get("case_sensitive").and_then(Value::as_bool).unwrap_or(false);
    let mut matches: Vec<(String, String, String)> = Vec::new();
    let mut matched: HashSet<(String, String)> = HashSet::new();
    for (tool, kind) in [("search_strings", "string"), ("search_procedures", "procedure")] {
        let result = env
            .call(
                tool,
                json!({ "pattern": query, "mode": "literal", "case_sensitive": case_sensitive }),
            )
            .await?;
        let invalid = || AnalysisError::output(tool, "provider returned an invalid search result");
        let items = result.as_array().ok_or_else(invalid)?;
        let mut parsed = Vec::new();
        for item in items {
            let object = item.as_object().ok_or_else(invalid)?;
            let address = object.get("address").and_then(Value::as_str).ok_or_else(invalid)?;
            let value = object.get("value").and_then(Value::as_str).ok_or_else(invalid)?;
            parsed.push((address.to_string(), value.to_string()));
        }
        for (address, value) in parsed {
            if matched.insert((kind.to_string(), address.clone())) {
                matches.push((kind.to_string(), address, value));
            }
        }
    }
    let mut references: Vec<Value> = Vec::new();
    for (_, address, _) in &matches {
        let xrefs = env.call("xrefs", json!({ "address": address })).await?;
        let sources = xrefs
            .as_array()
            .ok_or_else(|| AnalysisError::output("xrefs", "provider returned a non-array result"))?;
        for source in sources {
            let Some(source) = source.as_str() else {
                return Err(AnalysisError::output("xrefs", "provider returned a non-address value"));
            };
            let resolved = env
                .call("resolve_containing_procedure", json!({ "address": source }))
                .await?;
            references.push(json!({
                "target_address": address,
                "source_address": source,
                "containing_procedure": resolved,
            }));
        }
    }
    Ok(json!({
        "query": query,
        "search_mode": "literal",
        "matches": matches.iter().map(|(kind, address, value)| json!({ "type": kind, "address": address, "value": value })).collect::<Vec<_>>(),
        "references": references,
        "truncated": false,
        "residual_unknowns": [],
    }))
}
