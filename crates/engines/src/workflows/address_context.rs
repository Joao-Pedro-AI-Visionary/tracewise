//! Address and navigation context (port of `AnalysisContextQueries.ts`).

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::error::AnalysisError;
use crate::provider::AnalysisExecution;

use super::Env;

fn parameters(document: Option<&str>, address: Option<&str>) -> Value {
    let mut out = Map::new();
    if let Some(document) = document {
        out.insert("document".into(), json!(document));
    }
    if let Some(address) = address {
        out.insert("address".into(), json!(address));
    }
    Value::Object(out)
}

/// Compose the provider's volatile selection state into one coherent query.
pub async fn navigation(env: &Env<'_>, input: &Value) -> Result<Value, AnalysisError> {
    let document: Value = match input.get("document").and_then(Value::as_str) {
        Some(document) => json!(document),
        None => env.execute("current_document", json!({})).await?.result,
    };
    let document_args = match document.as_str() {
        Some(name) => parameters(Some(name), None),
        None => json!({}),
    };
    let address = env.execute("current_address", document_args).await?;
    let Some(address_text) = address.result.as_str().map(str::to_string) else {
        return Ok(json!({ "document": document, "address": address.result, "procedure": Value::Null }));
    };
    let procedure = env
        .execute(
            "resolve_containing_procedure",
            parameters(document.as_str(), Some(&address_text)),
        )
        .await;
    match procedure {
        Err(error) => {
            if !is_missing_current_procedure(&error) {
                return Err(error);
            }
            Ok(json!({ "document": document, "address": address_text, "procedure": Value::Null }))
        }
        Ok(procedure) => Ok(json!({
            "document": document,
            "address": address_text,
            "procedure": containing_procedure_name(&procedure.result),
        })),
    }
}

/// Inspect bounded provider-neutral facets at one explicit reproducible address.
pub async fn inspect(env: &Env<'_>, input: &Value) -> Result<Value, AnalysisError> {
    let address = input.get("address").and_then(Value::as_str).unwrap_or_default();
    let document = env
        .resolve_document(input.get("document").and_then(Value::as_str))
        .await?;
    let args = parameters(Some(&document), Some(address));
    let operations = ["address_name", "resolve_containing_procedure", "comment", "inline_comment", "list_bookmarks"];
    let mut results: Vec<Result<AnalysisExecution, AnalysisError>> = Vec::new();
    for operation in operations {
        let params = if operation == "list_bookmarks" {
            parameters(Some(&document), None)
        } else {
            args.clone()
        };
        results.push(env.execute(operation, params).await);
    }
    for result in &results {
        if let Err(error) = result {
            if matches!(
                error,
                AnalysisError::Cancelled { .. } | AnalysisError::Timeout { .. } | AnalysisError::NoBinaryOpen
            ) {
                return Err(error.clone());
            }
        }
    }
    let name = facet(&results[0], operations[0]);
    let procedure = facet(&results[1], operations[1]);
    let comment = facet(&results[2], operations[2]);
    let inline_comment = facet(&results[3], operations[3]);
    let bookmarks = facet(&results[4], operations[4]);
    let bookmarks = if bookmarks["state"] == json!("available") {
        matching_bookmarks(&bookmarks["value"], &resolved_address(&results[1], address))
    } else {
        bookmarks
    };
    Ok(json!({
        "address": address,
        "document": document,
        "name": name,
        "procedure": procedure,
        "comment": comment,
        "inline_comment": inline_comment,
        "bookmarks": bookmarks,
    }))
}

fn facet(result: &Result<AnalysisExecution, AnalysisError>, operation: &str) -> Value {
    match result {
        Ok(execution) => json!({ "state": "available", "value": execution.result }),
        Err(error) => json!({
            "state": "unavailable",
            "reason": error.message(),
            "remediation": format!("Call {operation} directly to inspect provider availability and diagnostics."),
        }),
    }
}

fn is_missing_current_procedure(error: &AnalysisError) -> bool {
    Regex::new(r"(?i)(?:no procedure exists|not in a procedure)")
        .map(|re| re.is_match(&error.message()))
        .unwrap_or(false)
}

fn containing_procedure_name(value: &Value) -> Value {
    if value.get("found") != Some(&json!(true)) {
        return Value::Null;
    }
    match value.get("procedure").and_then(Value::as_object) {
        Some(procedure) => match procedure.get("name") {
            Some(Value::String(name)) => json!(name),
            _ => Value::Null,
        },
        None => Value::Null,
    }
}

fn resolved_address(result: &Result<AnalysisExecution, AnalysisError>, fallback: &str) -> String {
    match result {
        Ok(execution) => execution
            .result
            .get("query_address")
            .and_then(Value::as_str)
            .unwrap_or(fallback)
            .to_string(),
        Err(_) => fallback.to_string(),
    }
}

fn matching_bookmarks(value: &Value, address: &str) -> Value {
    let malformed = |reason: &str| {
        json!({
            "state": "unavailable",
            "reason": reason,
            "remediation": "Retry list_bookmarks directly and report the provider output shape if it remains malformed.",
        })
    };
    let Some(items) = value.as_array() else {
        return malformed("list_bookmarks returned malformed output; expected an array.");
    };
    let mut kept = Vec::new();
    for item in items {
        let ok = item
            .as_object()
            .map(|o| {
                o.len() == 2
                    && o.get("address").map(Value::is_string).unwrap_or(false)
                    && matches!(o.get("name"), Some(Value::String(_) | Value::Null))
            })
            .unwrap_or(false);
        if !ok {
            return malformed(
                "list_bookmarks returned malformed entries; expected an address string and a string or null name.",
            );
        }
        if item["address"] == json!(address) {
            kept.push(item.clone());
        }
    }
    json!({ "state": "available", "value": kept })
}
