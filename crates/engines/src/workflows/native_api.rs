//! Native API boundary inspection (port of `NativeApiInspection.ts`).

use serde_json::{json, Value};

use crate::error::AnalysisError;

use super::Env;

fn unavailable_boundary() -> Value {
    json!({
        "available": false,
        "reason": "The selected provider did not expose a structured native API boundary model.",
        "residual_unknowns": [
            "What are the function's return and parameter boundary types?",
            "Does this function dispatch through a jump table with recoverable data addresses?",
        ],
    })
}

/// Project one analyzed-function dossier into inspectable native API substeps.
pub async fn inspect(env: &Env<'_>, input: &Value) -> Result<Value, AnalysisError> {
    let procedure = input.get("procedure").and_then(Value::as_str).unwrap_or_default();
    let dossier = env.call("analyze_function", json!({ "procedure": procedure })).await?;
    if !dossier.is_object() {
        return Err(AnalysisError::output("analyze_function", "provider output did not match the dossier contract"));
    }
    Ok(project(&dossier))
}

pub fn project(dossier: &Value) -> Value {
    let boundary = match dossier.get("native_api") {
        Some(b) if !b.is_null() => b.clone(),
        _ => unavailable_boundary(),
    };
    let available = boundary["available"] == json!(true);
    let unsupported_branches: Vec<&str> = if available {
        vec![]
    } else {
        vec!["structured-boundary-types", "jump-table-data-mapping"]
    };
    let residual: Vec<String> = if available {
        available_residual_unknowns(&boundary)
    } else {
        boundary["residual_unknowns"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    };
    let observation_reason = boundary["reason"].as_str().unwrap_or("").to_string();
    json!({
        "procedure": {
            "address": dossier["procedure"]["address"],
            "name": dossier["procedure"]["name"],
        },
        "boundary": boundary,
        "substeps": [
            {
                "operation": "analyze_function",
                "status": "completed",
                "observations": [
                    "provider function dossier",
                    "provider pseudocode classification",
                    "provider control-flow observations",
                ],
            },
            {
                "operation": "project_native_api_boundary",
                "status": if available { "completed" } else { "unsupported" },
                "observations": if available {
                    json!([
                        "return and parameter boundary types",
                        "confidence and inference evidence",
                        "jump-table dispatch, data, and target addresses",
                    ])
                } else {
                    json!([observation_reason])
                },
            },
            {
                "operation": "preserve_residual_unknowns",
                "status": "completed",
                "observations": if residual.is_empty() {
                    json!(["no additional structured-boundary unknowns"])
                } else {
                    json!(residual)
                },
            },
        ],
        "unsupported_branches": unsupported_branches,
        "residual_unknowns": residual,
    })
}

fn available_residual_unknowns(boundary: &Value) -> Vec<String> {
    let mut unknowns: Vec<String> = Vec::new();
    let mut push = |text: String| {
        if !unknowns.contains(&text) {
            unknowns.push(text);
        }
    };
    let empty = Vec::new();
    for table in boundary["jump_tables"].as_array().unwrap_or(&empty) {
        let dispatch = table["dispatch_address"].as_str().unwrap_or_default();
        let list = |key: &str| table[key].as_array().cloned().unwrap_or_default();
        if list("default_targets").is_empty() {
            push(format!(
                "Which default or out-of-range path, if any, belongs to the dispatch at {dispatch}?"
            ));
        }
        if list("mappings").is_empty() {
            push(format!("Which case values and targets belong to the dispatch at {dispatch}?"));
        }
        if list("data_sources").is_empty() {
            push(format!(
                "What backing data address produced the jump table dispatched at {dispatch}?"
            ));
        }
        if list("data_sources")
            .iter()
            .any(|s| s["entry_count"].is_null() || s["entry_size_bytes"].is_null())
        {
            push(format!(
                "What are the exact entry size and count for candidate jump-table data dispatched at {dispatch}?"
            ));
        }
        if list("mappings").iter().any(|m| m["case_value"].is_null()) {
            push(format!(
                "Which source-level case values correspond to every target dispatched at {dispatch}?"
            ));
        }
    }
    let mut values = vec![boundary["return_type"].clone()];
    values.extend(boundary["parameters"].as_array().cloned().unwrap_or_default());
    for value in values {
        if value["confidence"] == json!("low") {
            push(format!(
                "Can the inferred {} type {} be confirmed with imported metadata or an ABI probe?",
                value["role"].as_str().unwrap_or_default(),
                value["data_type"].as_str().unwrap_or_default()
            ));
        }
    }
    unknowns
}
