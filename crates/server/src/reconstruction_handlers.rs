//! MCP handlers for the reconstruction and investigation workflows.
//!
//! Mirrors REA `server/registerInvestigationTools.ts` (Evidence closure over the
//! session ledger, workflow unknowns for unresolved results) and
//! `server/registerApplicationTools/{obligationLedger,coverage}.ts`.

use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use rmcp::model::CallToolResult;
use rmcp::ErrorData as McpError;
use serde_json::Value;
use tracewise_domain::ledger::EvidenceLedger;
use tracewise_js::reconstruction::WorkflowOutcome;
use tracewise_js::JsError;

use crate::handlers::remember_evidence;
use crate::session::BinarySession;

fn js_error(error: JsError) -> McpError {
    McpError::invalid_params(error.to_string(), None)
}

/// Inline Evidence stays inline (REA does not record investigation inputs);
/// `retained-evidence` references resolve from the session ledger.
fn resolve(session: &BinarySession, value: &Value) -> Result<Value, McpError> {
    if value.get("kind").and_then(Value::as_str) != Some("retained-evidence") {
        return Ok(value.clone());
    }
    let evidence_id = value
        .get("evidence_id")
        .and_then(Value::as_str)
        .ok_or_else(|| McpError::invalid_params("retained evidence requires evidence_id", None))?;
    let evidence = session
        .ledger
        .lock()
        .unwrap()
        .get(evidence_id)
        .cloned()
        .ok_or_else(|| {
            McpError::invalid_params(format!("Evidence retained in this session is missing: {evidence_id}"), None)
        })?;
    serde_json::to_value(evidence).map_err(|error| McpError::internal_error(error.to_string(), None))
}

fn resolve_list(session: &BinarySession, args: &Value, key: &str) -> Result<Vec<Value>, McpError> {
    match args.get(key) {
        Some(Value::Array(items)) => items.iter().map(|item| resolve(session, item)).collect(),
        _ => Err(McpError::invalid_params(format!("{key} must be an array"), None)),
    }
}

/// `evidenceClosure`: every seed and transitive link must be retained in the session.
fn evidence_closure(ledger: &EvidenceLedger, seeds: &[String]) -> Result<Vec<String>, JsError> {
    let mut visited = BTreeSet::new();
    let mut pending: Vec<String> = seeds.to_vec();
    while let Some(id) = pending.pop() {
        if visited.contains(&id) {
            continue;
        }
        let evidence = ledger
            .get(&id)
            .ok_or_else(|| JsError::Integrity("Investigation input has a dangling Evidence link".into()))?;
        pending.extend(evidence.evidence_links.iter().cloned());
        visited.insert(id);
    }
    let mut ids: Vec<String> = visited.into_iter().collect();
    ids.sort();
    Ok(ids)
}

fn record_outcome(session: &BinarySession, outcome: WorkflowOutcome) -> Result<CallToolResult, McpError> {
    if let Some(unknown) = outcome.unknown {
        let mut ledger = session.ledger.lock().unwrap();
        if ledger.record_unknown(&unknown, outcome.evidence.clone()).is_ok() {
            drop(ledger);
            let value = serde_json::to_value(&outcome.evidence)
                .map_err(|error| McpError::internal_error(error.to_string(), None))?;
            return Ok(CallToolResult::structured(value));
        }
    }
    remember_evidence(session, outcome.evidence)
}

pub fn handle_build_reconstruction_obligation_ledger(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let (evidence, sources) = tracewise_js::build_reconstruction_obligation_ledger(args).map_err(js_error)?;
    {
        let mut ledger = session.ledger.lock().unwrap();
        for source in sources {
            if !ledger.has(&source.evidence_id) {
                ledger
                    .record(source)
                    .map_err(|error| McpError::internal_error(error.to_string(), None))?;
            }
        }
    }
    remember_evidence(session, evidence)
}

pub fn handle_evaluate_reconstruction_coverage(
    _session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default();
    let result = tracewise_js::evaluate_reconstruction_coverage(args, now).map_err(js_error)?;
    Ok(CallToolResult::structured(result))
}

pub fn handle_verify_reconstruction(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    if args.as_object().is_none_or(|o| o.keys().any(|k| k != "specification")) {
        return Err(McpError::invalid_params("verify_reconstruction accepts only specification", None));
    }
    let specification = args
        .get("specification")
        .ok_or_else(|| McpError::invalid_params("verify_reconstruction requires specification", None))?;
    let bundle = session.ledger.lock().unwrap().export();
    let ledger = session.ledger.lock().unwrap().clone();
    let closure = |seeds: &[String]| evidence_closure(&ledger, seeds);
    let outcome = tracewise_js::verify_reconstruction(specification, &bundle, &closure).map_err(js_error)?;
    record_outcome(session, outcome)
}

pub fn handle_find_changed_behavior(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    if args.as_object().is_none_or(|o| o.keys().any(|k| k != "comparisons")) {
        return Err(McpError::invalid_params("find_changed_behavior accepts only comparisons", None));
    }
    let comparisons = resolve_list(session, args, "comparisons")?;
    let ledger = session.ledger.lock().unwrap().clone();
    let closure = |seeds: &[String]| evidence_closure(&ledger, seeds);
    let outcome = tracewise_js::find_changed_behavior(&comparisons, &closure).map_err(js_error)?;
    record_outcome(session, outcome)
}

pub fn handle_correlate_static_and_runtime(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let mut resolved = args.clone();
    for key in ["static_comparisons", "runtime_comparisons"] {
        if args.get(key).is_some() {
            resolved[key] = Value::Array(resolve_list(session, args, key)?);
        }
    }
    let ledger = session.ledger.lock().unwrap().clone();
    let closure = |seeds: &[String]| evidence_closure(&ledger, seeds);
    let outcome = tracewise_js::correlate_static_and_runtime(&resolved, &closure).map_err(js_error)?;
    record_outcome(session, outcome)
}
