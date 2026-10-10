use std::path::Path;

use rmcp::model::{CallToolRequestParam, CallToolResult};
use rmcp::ErrorData as McpError;
use serde_json::{json, Value};
use tracewise_domain::bundle::parse_evidence_bundle;
use tracewise_domain::comparison::{compare_bundles, RecordPair};
use tracewise_domain::evidence::{
    create_evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation,
};
use tracewise_domain::unknown::{RecordUnknownInput, UpdateUnknownInput};

use crate::session::BinarySession;

pub async fn dispatch_tool(
    session: &BinarySession,
    request: CallToolRequestParam,
) -> Result<CallToolResult, McpError> {
    let name = request.name.as_ref();
    let args_map = request.arguments.unwrap_or_default();
    let args = Value::Object(args_map);

    match name {
        "open_binary" => handle_open_binary(session, &args),
        "close_binary" => handle_close_binary(session, &args),
        "binary_session" => handle_binary_session(session, &args),
        "inspect_analysis_view" => handle_inspect_analysis_view(session, &args),
        "record_unknown" => handle_record_unknown(session, &args),
        "update_unknown" => handle_update_unknown(session, &args),
        "list_unknowns" => handle_list_unknowns(session, &args),
        "verify_unknown_resolution" => handle_verify_unknown_resolution(session, &args),
        "export_evidence_bundle" => handle_export_evidence_bundle(session, &args),
        "import_evidence_bundle" => handle_import_evidence_bundle(session, &args),
        "get_evidence_bundle" => handle_get_evidence_bundle(session, &args),
        "compare_bundles" => handle_compare_bundles(session, &args),
        _ => Err(McpError::invalid_request(
            format!("Unknown tool: '{name}'"),
            None,
        )),
    }
}

fn handle_open_binary(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| McpError::invalid_params("open_binary requires 'path' string parameter", None))?;

    let format_hint = args.get("format").and_then(|v| v.as_str()).map(|s| s.to_string());
    let provider_id = args.get("provider_id").and_then(|v| v.as_str()).map(|s| s.to_string());

    let result = session
        .open(path, format_hint, provider_id)
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

    Ok(CallToolResult::structured(json!({ "result": result })))
}

fn handle_close_binary(session: &BinarySession, _args: &Value) -> Result<CallToolResult, McpError> {
    session
        .close()
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

    Ok(CallToolResult::structured(json!({ "result": null })))
}

fn handle_binary_session(session: &BinarySession, _args: &Value) -> Result<CallToolResult, McpError> {
    let status = session.status();
    Ok(CallToolResult::structured(json!({ "result": status })))
}

fn handle_inspect_analysis_view(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let ev = session
        .inspect_analysis_view(args)
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

    let val = serde_json::to_value(&ev)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

    Ok(CallToolResult::structured(val))
}

fn handle_record_unknown(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    let input: RecordUnknownInput = serde_json::from_value(args.clone())
        .map_err(|e| McpError::invalid_params(format!("Invalid record_unknown input: {e}"), None))?;

    let target = session.active_target.lock().unwrap().clone();
    let mutation_ev = create_evidence(
        target,
        session.provider.clone(),
        EvidenceObservation {
            predicate_type: Some("rea.residual-unknown-mutation".to_string()),
            operation: "record_unknown".to_string(),
            parameters: args.clone(),
            normalized_result: json!({ "action": "record_unknown", "domain": input.domain }),
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Observed),
            authority: Some(EvidenceAuthority::AnalystInference),
            environment: None,
            limitations: None,
            locations: None,
            evidence_links: None,
        },
    )
    .map_err(|e| McpError::internal_error(e.to_string(), None))?;

    let mut ledger = session.ledger.lock().unwrap();
    let unknown = ledger
        .record_unknown(&input, mutation_ev)
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

    Ok(CallToolResult::structured(json!({ "result": unknown })))
}

fn handle_update_unknown(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    let input: UpdateUnknownInput = serde_json::from_value(args.clone())
        .map_err(|e| McpError::invalid_params(format!("Invalid update_unknown input: {e}"), None))?;

    let target = session.active_target.lock().unwrap().clone();
    let mutation_ev = create_evidence(
        target,
        session.provider.clone(),
        EvidenceObservation {
            predicate_type: Some("rea.residual-unknown-mutation".to_string()),
            operation: "update_unknown".to_string(),
            parameters: args.clone(),
            normalized_result: json!({ "action": "update_unknown", "unknown_id": input.unknown_id }),
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Observed),
            authority: Some(EvidenceAuthority::AnalystInference),
            environment: None,
            limitations: None,
            locations: None,
            evidence_links: None,
        },
    )
    .map_err(|e| McpError::internal_error(e.to_string(), None))?;

    let mut ledger = session.ledger.lock().unwrap();
    let updated = ledger
        .update_unknown(&input, mutation_ev)
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

    Ok(CallToolResult::structured(json!({ "result": updated })))
}

fn handle_list_unknowns(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    let status = args
        .get("status")
        .and_then(|v| serde_json::from_value(v.clone()).ok());
    let severity = args
        .get("severity")
        .and_then(|v| serde_json::from_value(v.clone()).ok());
    let domain = args.get("domain").and_then(|v| v.as_str());

    let ledger = session.ledger.lock().unwrap();
    let items = ledger.list_unknowns(status, severity, domain);
    let total = items.len();

    Ok(CallToolResult::structured(json!({
        "result": {
            "items": items,
            "total": total
        }
    })))
}

fn handle_verify_unknown_resolution(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let unknown_id = args
        .get("unknown_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| McpError::invalid_params("verify_unknown_resolution requires 'unknown_id'", None))?;

    let ledger = session.ledger.lock().unwrap();
    let res = ledger
        .verify_unknown_resolution(unknown_id)
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

    Ok(CallToolResult::structured(json!({
        "result": {
            "valid": res.valid,
            "truthVerified": res.truth_verified,
            "unknown": res.unknown
        }
    })))
}

fn handle_export_evidence_bundle(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| McpError::invalid_params("export_evidence_bundle requires 'path'", None))?;

    let overwrite = args.get("overwrite").and_then(|v| v.as_bool()).unwrap_or(false);
    if !overwrite && Path::new(path).exists() {
        return Err(McpError::invalid_params(
            format!("File '{path}' already exists and overwrite is false"),
            None,
        ));
    }

    let bundle = session.ledger.lock().unwrap().export();
    let serialized = tracewise_domain::canonical_json(&bundle)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

    std::fs::write(path, serialized.as_bytes())
        .map_err(|e| McpError::internal_error(format!("Failed to write bundle file: {e}"), None))?;

    Ok(CallToolResult::structured(json!({
        "result": {
            "path": path,
            "bytes": serialized.len(),
            "records": bundle.records.len(),
            "unknowns": bundle.unknowns.len()
        }
    })))
}

fn handle_import_evidence_bundle(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| McpError::invalid_params("import_evidence_bundle requires 'path'", None))?;

    let content = std::fs::read_to_string(path)
        .map_err(|e| McpError::invalid_params(format!("Failed to read bundle file: {e}"), None))?;

    let bundle = parse_evidence_bundle(&content)
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

    let delta = session
        .ledger
        .lock()
        .unwrap()
        .import(&bundle)
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

    let total = session.ledger.lock().unwrap().export().records.len();

    Ok(CallToolResult::structured(json!({
        "result": {
            "imported": delta,
            "unknowns_added": delta.unknowns_added,
            "total": total
        }
    })))
}

fn handle_get_evidence_bundle(
    session: &BinarySession,
    _args: &Value,
) -> Result<CallToolResult, McpError> {
    let bundle = session.ledger.lock().unwrap().export();
    Ok(CallToolResult::structured(json!({ "result": bundle })))
}

fn handle_compare_bundles(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let left_path = args
        .get("left_bundle_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| McpError::invalid_params("compare_bundles requires 'left_bundle_path'", None))?;

    let right_path = args
        .get("right_bundle_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| McpError::invalid_params("compare_bundles requires 'right_bundle_path'", None))?;

    let pairs: Vec<RecordPair> = args
        .get("record_pairs")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let left_content = std::fs::read_to_string(left_path)
        .map_err(|e| McpError::invalid_params(format!("Failed to read left bundle: {e}"), None))?;
    let right_content = std::fs::read_to_string(right_path)
        .map_err(|e| McpError::invalid_params(format!("Failed to read right bundle: {e}"), None))?;

    let left = parse_evidence_bundle(&left_content)
        .map_err(|e| McpError::invalid_params(format!("Invalid left bundle: {e}"), None))?;
    let right = parse_evidence_bundle(&right_content)
        .map_err(|e| McpError::invalid_params(format!("Invalid right bundle: {e}"), None))?;

    let comparison = compare_bundles(&left, &right, &pairs)
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

    let ev = create_evidence(
        None,
        session.provider.clone(),
        EvidenceObservation {
            predicate_type: Some("rea.bundle-comparison".to_string()),
            operation: "compare_bundles".to_string(),
            parameters: json!({
                "left_bundle_sha256": comparison.left_bundle_sha256,
                "right_bundle_sha256": comparison.right_bundle_sha256,
                "record_pairs": pairs,
            }),
            normalized_result: serde_json::to_value(&comparison)
                .map_err(|e| McpError::internal_error(e.to_string(), None))?,
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Derived),
            authority: Some(EvidenceAuthority::AnalystInference),
            environment: None,
            limitations: Some(comparison.limitations.clone()),
            locations: None,
            evidence_links: None,
        },
    )
    .map_err(|e| McpError::internal_error(e.to_string(), None))?;

    let _ = session.ledger.lock().unwrap().record(ev.clone());

    let val = serde_json::to_value(&ev)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

    Ok(CallToolResult::structured(val))
}
