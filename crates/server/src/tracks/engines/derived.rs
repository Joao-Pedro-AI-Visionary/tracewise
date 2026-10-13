//! Evidence-derived investigation tools of the engines track: `compare_functions` and
//! `build_call_path`. They compute from complete Evidence records (supplied inline in the
//! arguments) and need no live provider; the computation lives in
//! `tracewise_engines::derived`.

use std::collections::BTreeSet;

use rmcp::model::{CallToolResult, Content};
use rmcp::ErrorData as McpError;
use serde_json::{json, Value};
use tracewise_engines::derived::call_path::{build_call_path, parse_call_path_address, unknown_input as call_path_unknown};
use tracewise_engines::derived::function_comparison::{compare_functions, unknown_input as comparison_unknown};
use tracewise_engines::derived::{
    derived_evidence, evidence_closure, parse_evidence, record_derived_evidence, validate_tool_input, zod_error_text,
    DerivedError, CALL_PATH_PROVIDER, FUNCTION_COMPARISON_PROVIDER,
};

use crate::session::BinarySession;

fn text_error(message: String) -> CallToolResult {
    CallToolResult::error(vec![Content::text(message)])
}

fn failure(operation: &str, error: &DerivedError) -> Result<CallToolResult, McpError> {
    Ok(text_error(error.body(operation).to_string()))
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item.as_str().map(str::to_string))
        .collect()
}

pub fn handle_compare_functions(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    const TOOL: &str = "compare_functions";
    let parameters = match validate_tool_input(TOOL, args) {
        Ok(parameters) => parameters,
        Err(message) => return Ok(text_error(message)),
    };
    let (left_input, right_input) = (&parameters["left"], &parameters["right"]);
    let mut sources = Vec::new();
    for input in [left_input, right_input] {
        match parse_evidence(input) {
            Ok(evidence) => sources.push(evidence),
            Err(issue) => return failure(TOOL, &DerivedError::Integrity(zod_error_text(&[issue]))),
        }
    }
    if sources
        .iter()
        .any(|evidence| evidence.operation != "analyze_function" || evidence.predicate_type != "rea.analysis")
    {
        return failure(TOOL, &DerivedError::Integrity("Expected analyze_function Evidence".into()));
    }
    let (left_id, right_id) = (sources[0].evidence_id.clone(), sources[1].evidence_id.clone());
    let comparison = match compare_functions(left_input, right_input) {
        Ok(comparison) => comparison,
        Err(error) => return failure(TOOL, &error),
    };
    let mut ledger = session.ledger.lock().unwrap();
    for source in &sources {
        if let Err(error) = ledger.record(source.clone()) {
            return failure(TOOL, &DerivedError::Integrity(error.to_string()));
        }
    }
    let status = comparison["status"].as_str().unwrap_or("unknown").to_string();
    let evidence = match derived_evidence(
        FUNCTION_COMPARISON_PROVIDER,
        "rea.function-comparison",
        TOOL,
        json!({ "left_evidence_id": left_id, "right_evidence_id": right_id }),
        comparison.clone(),
        &strings(&comparison["limitations"]),
        vec![left_id.clone(), right_id.clone()],
    ) {
        Ok(evidence) => evidence,
        Err(error) => return failure(TOOL, &error),
    };
    let unknown = comparison_unknown(&status, &[left_id], &[right_id], &evidence.evidence_id);
    if let Err(error) = record_derived_evidence(&mut ledger, &evidence, unknown.as_ref()) {
        return failure(TOOL, &error);
    }
    let value = serde_json::to_value(&evidence).map_err(|e| McpError::internal_error(e.to_string(), None))?;
    Ok(CallToolResult::structured(value))
}

pub fn handle_build_call_path(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    const TOOL: &str = "build_call_path";
    let parameters = match validate_tool_input(TOOL, args) {
        Ok(parameters) => parameters,
        Err(message) => return Ok(text_error(message)),
    };
    let functions: Vec<Value> = parameters["functions"].as_array().cloned().unwrap_or_default();
    let normalized = |key: &str| parse_call_path_address(parameters[key]["address"].as_str().unwrap_or(""));
    let (start, goal) = match (normalized("start"), normalized("goal")) {
        (Ok(start), Ok(goal)) => (start, goal),
        (Err(error), _) | (_, Err(error)) => return failure(TOOL, &error),
    };
    let seeds: Vec<String> = functions
        .iter()
        .filter_map(|function| function["evidence_id"].as_str().map(str::to_string))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut ledger = session.ledger.lock().unwrap();
    let links = match evidence_closure(&ledger, &seeds) {
        Ok(links) => links,
        Err(error) => return failure(TOOL, &error),
    };
    let result = match build_call_path(&functions, &start, &goal) {
        Ok(result) => result,
        Err(error) => return failure(TOOL, &error),
    };
    let evidence = match derived_evidence(
        CALL_PATH_PROVIDER,
        "rea.call-path",
        TOOL,
        json!({ "start": start, "goal": goal }),
        result.clone(),
        &strings(&result["limitations"]),
        links,
    ) {
        Ok(evidence) => evidence,
        Err(error) => return failure(TOOL, &error),
    };
    let unknown = (result["status"] == "unknown").then(|| call_path_unknown(&evidence.evidence_id));
    if let Err(error) = record_derived_evidence(&mut ledger, &evidence, unknown.as_ref()) {
        return failure(TOOL, &error);
    }
    let value = serde_json::to_value(&evidence).map_err(|e| McpError::internal_error(e.to_string(), None))?;
    Ok(CallToolResult::structured(value))
}
