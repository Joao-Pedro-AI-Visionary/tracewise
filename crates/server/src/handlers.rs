use std::path::Path;

use rmcp::model::{CallToolRequestParam, CallToolResult, ErrorCode, ProgressNotificationParam};
use rmcp::service::RequestContext;
use rmcp::ErrorData as McpError;
use rmcp::RoleServer;
use serde_json::{json, Value};
use tracewise_domain::bundle::parse_evidence_bundle;
use tracewise_domain::comparison::{compare_bundles, RecordPair};
use tracewise_domain::evidence::{
    create_evidence, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation,
};
use tracewise_domain::unknown::{RecordUnknownInput, UpdateUnknownInput};

use crate::session::BinarySession;

pub async fn dispatch_tool(
    session: &BinarySession,
    request: CallToolRequestParam,
    context: Option<&RequestContext<RoleServer>>,
) -> Result<CallToolResult, McpError> {
    let name = request.name.to_string();
    let args_map = request.arguments.unwrap_or_default();
    let args = Value::Object(args_map);

    if let Some(ctx) = context {
        if ctx.ct.is_cancelled() {
            return Err(McpError::new(
                ErrorCode(-32800),
                "Request cancelled",
                None,
            ));
        }

        let ct = ctx.ct.clone();
        let peer = ctx.peer.clone();
        let progress_token = ctx.meta.get_progress_token().or_else(|| {
            args.get("_meta")
                .and_then(|m| m.get("progressToken"))
                .and_then(|t| serde_json::from_value(t.clone()).ok())
        });

        tokio::select! {
            _ = ct.cancelled() => {
                Err(McpError::new(
                    ErrorCode(-32800),
                    "Request cancelled",
                    None,
                ))
            }
            res = execute_tool(session, &name, &args, Some((&peer, progress_token.as_ref()))) => {
                res
            }
        }
    } else {
        execute_tool(session, &name, &args, None).await
    }
}

pub async fn call_tool_local(
    session: &BinarySession,
    request: CallToolRequestParam,
) -> Result<CallToolResult, McpError> {
    dispatch_tool(session, request, None).await
}

async fn execute_tool(
    session: &BinarySession,
    name: &str,
    args: &Value,
    progress: Option<(&rmcp::service::Peer<RoleServer>, Option<&rmcp::model::ProgressToken>)>,
) -> Result<CallToolResult, McpError> {
    if let Ok(delay_str) = std::env::var("TRACEWISE_TEST_DELAY_MS") {
        if let Ok(ms) = delay_str.parse::<u64>() {
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        }
    }

    if let Some((peer, Some(token))) = progress {
        let start_msg = progress_message(name, true);
        let _ = peer.notify_progress(ProgressNotificationParam {
            progress_token: (*token).clone(),
            progress: 0.0,
            total: Some(1.0),
            message: Some(start_msg),
        }).await;
    }

    let result = match name {
        "open_binary" => handle_open_binary(session, args),
        "close_binary" => handle_close_binary(session, args),
        "binary_session" => handle_binary_session(session, args),
        "inspect_analysis_view" => handle_inspect_analysis_view(session, args),
        "record_unknown" => handle_record_unknown(session, args),
        "update_unknown" => handle_update_unknown(session, args),
        "list_unknowns" => handle_list_unknowns(session, args),
        "verify_unknown_resolution" => handle_verify_unknown_resolution(session, args),
        "export_evidence_bundle" => handle_export_evidence_bundle(session, args),
        "import_evidence_bundle" => handle_import_evidence_bundle(session, args),
        "get_evidence_bundle" => handle_get_evidence_bundle(session, args),
        "compare_bundles" => handle_compare_bundles(session, args),
        "inspect_web_network_capture" => handle_inspect_web_network_capture(session, args),
        "export_web_scripts" => handle_export_web_scripts(session, args),
        "trace_web_module_imports" => handle_trace_web_module_imports(session, args),
        "trace_web_source_location" => handle_trace_web_source_location(session, args),
        "compare_web_captures" => handle_compare_web_captures(session, args),
        "compare_web_screenshots" => handle_compare_web_screenshots(session, args),
        "list_browser_targets" => handle_list_browser_targets(session, args).await,
        "capture_web_screenshot" => handle_capture_web_screenshot(session, args).await,
        "inspect_web_page" => handle_inspect_web_page(session, args).await,
        "observe_web_session" => handle_observe_web_session(session, args).await,
        "analyze_web_bundle" => handle_analyze_web_bundle(session, args).await,
        "observe_web_execution" => handle_observe_web_execution(session, args).await,
        "inspect_web_event_listeners" => handle_inspect_web_event_listeners(session, args).await,
        "discover_webmcp_tools" => handle_discover_webmcp_tools(session, args).await,
        "capture_browser_scenario" => handle_capture_browser_scenario(session, args).await,
        "infer_api_spec" => handle_infer_api_spec(session, args),
        "generate_api_client" => handle_generate_api_client(session, args),
        "inspect_artifact" => handle_inspect_artifact(session, args),
        "extract_artifact" => handle_extract_artifact(session, args),
        "compare_artifacts" => handle_compare_artifacts(session, args),
        "recover_javascript_sources" => handle_recover_javascript_sources(session, args),
        "compare_source_to_bundle" => handle_compare_source_to_bundle(session, args),
        "analyze_javascript_application" => handle_analyze_javascript_application(session, args),
        "trace_javascript_semantics" => handle_trace_javascript_semantics(session, args),
        "trace_application_feature" => handle_trace_application_feature(session, args),
        "compare_application_versions" => handle_compare_application_versions(session, args),
        "compare_javascript_export_shapes" => handle_compare_javascript_export_shapes(session, args),
        "list_javascript_runtime_targets" => handle_list_javascript_runtime_targets(session, args).await,
        "observe_javascript_runtime" => handle_observe_javascript_runtime(session, args).await,
        "reconcile_javascript_runtime" => handle_reconcile_javascript_runtime(session, args),
        "list_electron_targets" => crate::electron_handlers::handle_list_electron_targets(session, args).await,
        "inspect_electron_page" => crate::electron_handlers::handle_inspect_electron_page(session, args).await,
        "capture_electron_scenario" => crate::electron_handlers::handle_capture_electron_scenario(session, args).await,
        "capture_process_scenario" => crate::process_handlers::handle_capture_process_scenario(session, args).await,
        "compare_process_captures" => crate::process_handlers::handle_compare_process_captures(session, args),
        "build_reconstruction_obligation_ledger" => {
            crate::reconstruction_handlers::handle_build_reconstruction_obligation_ledger(session, args)
        }
        "evaluate_reconstruction_coverage" => {
            crate::reconstruction_handlers::handle_evaluate_reconstruction_coverage(session, args)
        }
        "verify_reconstruction" => crate::reconstruction_handlers::handle_verify_reconstruction(session, args),
        "find_changed_behavior" => crate::reconstruction_handlers::handle_find_changed_behavior(session, args),
        "correlate_static_and_runtime" => {
            crate::reconstruction_handlers::handle_correlate_static_and_runtime(session, args)
        }
        _ => Err(McpError::invalid_request(
            format!("Unknown tool: '{name}'"),
            None,
        )),
    };

    if result.is_ok() {
        if let Some((peer, Some(token))) = progress {
            let end_msg = progress_message(name, false);
            let _ = peer.notify_progress(ProgressNotificationParam {
                progress_token: (*token).clone(),
                progress: 1.0,
                total: Some(1.0),
                message: Some(end_msg),
            }).await;
        }
    }

    result
}

fn progress_message(tool_name: &str, start: bool) -> String {
    match (tool_name, start) {
        ("open_binary", true) => "Hashing and inspecting target binary...".to_string(),
        ("open_binary", false) => "Target binary inspected and opened".to_string(),
        ("export_evidence_bundle", true) => "Exporting evidence bundle...".to_string(),
        ("export_evidence_bundle", false) => "Evidence bundle exported".to_string(),
        ("import_evidence_bundle", true) => "Importing and validating evidence bundle...".to_string(),
        ("import_evidence_bundle", false) => "Evidence bundle imported".to_string(),
        ("compare_bundles", true) => "Comparing evidence bundles...".to_string(),
        ("compare_bundles", false) => "Evidence bundles compared".to_string(),
        ("export_web_scripts", true) => "Exporting web scripts from capture...".to_string(),
        ("export_web_scripts", false) => "Web scripts exported".to_string(),
        ("trace_web_module_imports", true) => "Tracing web module imports...".to_string(),
        ("trace_web_module_imports", false) => "Web module imports traced".to_string(),
        ("trace_web_source_location", true) => "Tracing web source location...".to_string(),
        ("trace_web_source_location", false) => "Web source location traced".to_string(),
        ("compare_web_captures", true) => "Comparing web captures...".to_string(),
        ("compare_web_captures", false) => "Web captures compared".to_string(),
        ("compare_web_screenshots", true) => "Comparing web screenshots...".to_string(),
        ("compare_web_screenshots", false) => "Web screenshots compared".to_string(),
        ("list_browser_targets", true) => "Discovering browser targets...".to_string(),
        ("list_browser_targets", false) => "Browser targets listed".to_string(),
        ("capture_web_screenshot", true) => "Capturing web screenshot...".to_string(),
        ("capture_web_screenshot", false) => "Screenshot capture complete".to_string(),
        ("inspect_web_page", true) => "Inspecting web page...".to_string(),
        ("inspect_web_page", false) => "Web page inspected".to_string(),
        ("observe_web_session", true) => "Observing web session...".to_string(),
        ("observe_web_session", false) => "Web session observed".to_string(),
        ("analyze_web_bundle", true) => "Analyzing web bundle...".to_string(),
        ("analyze_web_bundle", false) => "Web bundle analyzed".to_string(),
        ("observe_web_execution", true) => "Observing web execution...".to_string(),
        ("observe_web_execution", false) => "Web execution observed".to_string(),
        ("inspect_web_event_listeners", true) => "Inspecting web event listeners...".to_string(),
        ("inspect_web_event_listeners", false) => "Web event listeners inspected".to_string(),
        ("discover_webmcp_tools", true) => "Discovering WebMCP tools...".to_string(),
        ("discover_webmcp_tools", false) => "WebMCP tools discovered".to_string(),
        ("capture_browser_scenario", true) => "Capturing browser scenario...".to_string(),
        ("capture_browser_scenario", false) => "Browser scenario captured".to_string(),
        ("list_javascript_runtime_targets", true) => "Discovering V8 Inspector targets...".to_string(),
        ("list_javascript_runtime_targets", false) => "V8 Inspector targets listed".to_string(),
        ("observe_javascript_runtime", true) => "Observing JavaScript runtime...".to_string(),
        ("observe_javascript_runtime", false) => "JavaScript runtime observed".to_string(),
        ("reconcile_javascript_runtime", true) => "Reconciling static and runtime evidence...".to_string(),
        ("reconcile_javascript_runtime", false) => "JavaScript runtime reconciled".to_string(),
        ("infer_api_spec", true) => "Inferring OpenAPI spec from redacted capture...".to_string(),
        ("infer_api_spec", false) => "OpenAPI spec inferred".to_string(),
        ("generate_api_client", true) => "Generating typed API clients...".to_string(),
        ("generate_api_client", false) => "API clients generated".to_string(),
        (name, true) => format!("Starting operation: {name}"),
        (name, false) => format!("Completed operation: {name}"),
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
            "imported": delta.records_added,
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

fn handle_inspect_web_network_capture(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let input: tracewise_web::har::InspectWebNetworkCaptureInput = serde_json::from_value(args.clone())
        .map_err(|e| McpError::invalid_params(format!("Invalid inspect_web_network_capture input: {e}"), None))?;

    let ev = match input.format.as_str() {
        "har" => tracewise_web::har::inspect_har_capture(input)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?,
        "mitmproxy" => tracewise_web::mitmproxy::inspect_mitmproxy_capture(input)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?,
        _ => return Err(McpError::invalid_params(
            format!("Unsupported format: '{}'. Supported formats are 'har' and 'mitmproxy'.", input.format),
            None,
        )),
    };

    let _ = session.ledger.lock().unwrap().record(ev.clone());

    let val = serde_json::to_value(&ev)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

    Ok(CallToolResult::structured(val))
}

fn handle_export_web_scripts(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let input: tracewise_web::scripts_export::ExportWebScriptsInput = serde_json::from_value(args.clone())
        .map_err(|e| McpError::invalid_params(format!("Invalid export_web_scripts input: {e}"), None))?;

    let ev = tracewise_web::scripts_export::export_web_scripts(input)
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

    let _ = session.ledger.lock().unwrap().record(ev.clone());

    let val = serde_json::to_value(&ev)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

    Ok(CallToolResult::structured(val))
}

fn handle_trace_web_module_imports(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let input: tracewise_web::module_trace::TraceWebModuleImportsInput = serde_json::from_value(args.clone())
        .map_err(|e| McpError::invalid_params(format!("Invalid trace_web_module_imports input: {e}"), None))?;

    let ev = tracewise_web::module_trace::trace_web_module_imports(input)
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

    let _ = session.ledger.lock().unwrap().record(ev.clone());

    let val = serde_json::to_value(&ev)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

    Ok(CallToolResult::structured(val))
}

fn handle_trace_web_source_location(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let input: tracewise_web::source_location::TraceWebSourceLocationInput = serde_json::from_value(args.clone())
        .map_err(|e| McpError::invalid_params(format!("Invalid trace_web_source_location input: {e}"), None))?;

    let ev = tracewise_web::source_location::trace_web_source_location(input)
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

    let _ = session.ledger.lock().unwrap().record(ev.clone());

    let val = serde_json::to_value(&ev)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

    Ok(CallToolResult::structured(val))
}

fn handle_compare_web_captures(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    if args.get("before_scenario").is_some() || args.get("after_scenario").is_some() {
        let ev = tracewise_web::scenario_diff::compare_browser_scenarios(args)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        let _ = session.ledger.lock().unwrap().record(ev.clone());
        let val = serde_json::to_value(&ev).map_err(|e| McpError::internal_error(e.to_string(), None))?;
        return Ok(CallToolResult::structured(val));
    }

    let input: tracewise_web::capture_diff::CompareWebCapturesInput = serde_json::from_value(args.clone())
        .map_err(|e| McpError::invalid_params(format!("Invalid compare_web_captures input: {e}"), None))?;

    let ev = tracewise_web::capture_diff::compare_web_captures(input)
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

    let _ = session.ledger.lock().unwrap().record(ev.clone());

    let val = serde_json::to_value(&ev)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

    Ok(CallToolResult::structured(val))
}

fn handle_compare_web_screenshots(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let input: tracewise_web::screenshot_diff::CompareWebScreenshotsInput = serde_json::from_value(args.clone())
        .map_err(|e| McpError::invalid_params(format!("Invalid compare_web_screenshots input: {e}"), None))?;

    let ev = tracewise_web::screenshot_diff::compare_web_screenshots(input)
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

    let _ = session.ledger.lock().unwrap().record(ev.clone());

    let val = serde_json::to_value(&ev)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

    Ok(CallToolResult::structured(val))
}


/// Browser observation failures are tool results (`isError`), not protocol errors.
pub(crate) fn browser_tool_result(
    session: &BinarySession,
    outcome: Result<tracewise_domain::evidence::Evidence, tracewise_web::error::WebError>,
) -> Result<CallToolResult, McpError> {
    let ev = match outcome {
        Ok(ev) => ev,
        Err(e) => {
            return match tracewise_web::browser_observation::browser_error_body(&e) {
                Some(body) => Ok(CallToolResult::error(vec![rmcp::model::Content::text(
                    body.to_string(),
                )])),
                None => Err(McpError::invalid_params(e.to_string(), None)),
            }
        }
    };

    let _ = session.ledger.lock().unwrap().record(ev.clone());

    let val = serde_json::to_value(&ev)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

    Ok(CallToolResult::structured(val))
}

async fn handle_list_browser_targets(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let input = tracewise_web::browser_targets::parse_list_browser_targets_input(args)
        .map_err(|e| McpError::invalid_params(format!("Invalid list_browser_targets input: {e}"), None))?;

    browser_tool_result(
        session,
        tracewise_web::browser_targets::list_browser_targets(&input).await,
    )
}

async fn handle_capture_web_screenshot(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let input = tracewise_web::web_screenshot::parse_capture_web_screenshot_input(args)
        .map_err(|e| McpError::invalid_params(format!("Invalid capture_web_screenshot input: {e}"), None))?;

    browser_tool_result(
        session,
        tracewise_web::web_screenshot::capture_web_screenshot(&input).await,
    )
}

async fn handle_inspect_web_page(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let input = tracewise_web::page_inspection::parse_inspect_web_page_input(args)
        .map_err(|e| McpError::invalid_params(format!("Invalid inspect_web_page input: {e}"), None))?;

    browser_tool_result(
        session,
        tracewise_web::page_inspection::inspect_web_page(&input).await,
    )
}

async fn handle_observe_web_session(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let input = tracewise_web::session_observation::parse_observe_web_session_input(args)
        .map_err(|e| McpError::invalid_params(format!("Invalid observe_web_session input: {e}"), None))?;

    browser_tool_result(
        session,
        tracewise_web::session_observation::observe_web_session(&input).await,
    )
}

async fn handle_analyze_web_bundle(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let input = tracewise_web::bundle_analysis::parse_analyze_web_bundle_input(args)
        .map_err(|e| McpError::invalid_params(format!("Invalid analyze_web_bundle input: {e}"), None))?;

    browser_tool_result(
        session,
        tracewise_web::bundle_analysis::analyze_web_bundle(&input).await,
    )
}

async fn handle_observe_web_execution(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let input = tracewise_web::web_execution::parse_observe_web_execution_input(args)
        .map_err(|e| McpError::invalid_params(format!("Invalid observe_web_execution input: {e}"), None))?;

    browser_tool_result(
        session,
        tracewise_web::web_execution::observe_web_execution(&input).await,
    )
}

async fn handle_inspect_web_event_listeners(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let input = tracewise_web::web_listeners::parse_inspect_web_event_listeners_input(args).map_err(|e| {
        McpError::invalid_params(format!("Invalid inspect_web_event_listeners input: {e}"), None)
    })?;

    browser_tool_result(
        session,
        tracewise_web::web_listeners::inspect_web_event_listeners(&input).await,
    )
}

async fn handle_discover_webmcp_tools(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let input = tracewise_web::webmcp_discovery::parse_discover_webmcp_tools_input(args)
        .map_err(|e| McpError::invalid_params(format!("Invalid discover_webmcp_tools input: {e}"), None))?;

    browser_tool_result(
        session,
        tracewise_web::webmcp_discovery::discover_webmcp_tools(&input).await,
    )
}

async fn handle_capture_browser_scenario(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let input = tracewise_web::browser_scenario::parse_capture_browser_scenario_input(args)
        .map_err(|e| McpError::invalid_params(format!("Invalid capture_browser_scenario input: {e}"), None))?;

    browser_tool_result(
        session,
        tracewise_web::browser_scenario_run::capture_browser_scenario(&input).await,
    )
}

fn handle_infer_api_spec(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    let input: tracewise_web::api_spec::InferApiSpecInput = serde_json::from_value(args.clone())
        .map_err(|e| McpError::invalid_params(format!("Invalid infer_api_spec input: {e}"), None))?;

    if input.evidence_ids.is_some() && input.capture_path.is_some() {
        return Err(McpError::invalid_params(
            "infer_api_spec accepts evidence_ids or capture_path, not both",
            None,
        ));
    }

    let (fresh_sources, inferred) = if let Some(path) = input.capture_path.clone() {
        let source = tracewise_web::api_spec::inspect_capture_for_spec(&path)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        let inferred = tracewise_web::api_spec::infer_from_captures(
            &input,
            std::slice::from_ref(&source),
        )
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        (vec![source], inferred)
    } else {
        let ids = input.evidence_ids.clone().ok_or_else(|| {
            McpError::invalid_params(
                "infer_api_spec requires evidence_ids or capture_path",
                None,
            )
        })?;
        if ids.is_empty() {
            return Err(McpError::invalid_params(
                "infer_api_spec requires at least one evidence_id",
                None,
            ));
        }
        let ledger = session.ledger.lock().unwrap();
        let mut sources = Vec::with_capacity(ids.len());
        for id in &ids {
            let ev = ledger.get(id).cloned().ok_or_else(|| {
                McpError::invalid_params(
                    format!("Evidence '{id}' is not in the session ledger"),
                    None,
                )
            })?;
            sources.push(ev);
        }
        drop(ledger);
        let inferred = tracewise_web::api_spec::infer_from_captures(&input, &sources)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        (Vec::new(), inferred)
    };

    let mut ledger = session.ledger.lock().unwrap();
    for source in fresh_sources {
        if !ledger.has(&source.evidence_id) {
            ledger
                .record(source)
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        }
    }
    if !ledger.has(&inferred.evidence.evidence_id) {
        ledger
            .record(inferred.evidence.clone())
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    }
    for unknown in &inferred.unknowns {
        match ledger.record_unknown(unknown, inferred.evidence.clone()) {
            Ok(_) => {}
            Err(tracewise_domain::DomainError::Unknown(
                tracewise_domain::UnknownError::AlreadyExists(_),
            )) => {}
            Err(e) => return Err(McpError::internal_error(e.to_string(), None)),
        }
    }

    let val = serde_json::to_value(&inferred.evidence)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    Ok(CallToolResult::structured(val))
}

fn handle_inspect_artifact(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    let path = session
        .active_target
        .lock()
        .unwrap()
        .as_ref()
        .map(|s| s.local_path.clone())
        .ok_or_else(|| McpError::invalid_params("inspect_artifact requires an active binary target (open_binary first)", None))?;
    let integrity_policy = args
        .get("integrity_policy")
        .and_then(|v| v.as_str())
        .unwrap_or("fail");
    let evidences = tracewise_js::inspect_artifact(&path, integrity_policy)
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
    let mut ledger = session.ledger.lock().unwrap();
    for ev in &evidences {
        ledger
            .record(ev.clone())
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    }
    let inspect_ev = evidences
        .last()
        .ok_or_else(|| McpError::internal_error("inspect_artifact produced no evidence", None))?;
    let val = serde_json::to_value(inspect_ev)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    Ok(CallToolResult::structured(val))
}

fn handle_extract_artifact(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    let path = session
        .active_target
        .lock()
        .unwrap()
        .as_ref()
        .map(|s| s.local_path.clone())
        .ok_or_else(|| McpError::invalid_params("extract_artifact requires an active binary target (open_binary first)", None))?;
    let integrity_policy = args
        .get("integrity_policy")
        .and_then(|v| v.as_str())
        .unwrap_or("fail");
    let ev = tracewise_js::extract_artifact_tool(&path, integrity_policy)
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
    let _ = session.ledger.lock().unwrap().record(ev.clone());
    let val = serde_json::to_value(&ev)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    Ok(CallToolResult::structured(val))
}

fn handle_compare_artifacts(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    let left: tracewise_domain::evidence::Evidence = serde_json::from_value(
        args.get("left")
            .cloned()
            .ok_or_else(|| McpError::invalid_params("compare_artifacts requires 'left'", None))?,
    )
    .map_err(|e| McpError::invalid_params(format!("Invalid left evidence: {e}"), None))?;
    let right: tracewise_domain::evidence::Evidence = serde_json::from_value(
        args.get("right")
            .cloned()
            .ok_or_else(|| McpError::invalid_params("compare_artifacts requires 'right'", None))?,
    )
    .map_err(|e| McpError::invalid_params(format!("Invalid right evidence: {e}"), None))?;
    let mut ledger = session.ledger.lock().unwrap();
    for source in [&left, &right] {
        if !ledger.has(&source.evidence_id) {
            ledger
                .record(source.clone())
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        }
    }
    let ev = tracewise_js::compare_artifacts_tool(&left, &right)
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
    ledger
        .record(ev.clone())
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let val = serde_json::to_value(&ev)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    Ok(CallToolResult::structured(val))
}

fn handle_recover_javascript_sources(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let path = args.get("path").and_then(|v| v.as_str()).ok_or_else(|| {
        McpError::invalid_params("recover_javascript_sources requires 'path'", None)
    })?;
    let output_directory = args
        .get("output_directory")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            McpError::invalid_params("recover_javascript_sources requires 'output_directory'", None)
        })?;
    let extraction_mode = args
        .get("extraction_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("structural");
    let rewrite_level = args
        .get("rewrite_level")
        .and_then(|v| v.as_str())
        .unwrap_or("standard");
    let evidence = tracewise_js::recover_javascript_sources(
        path,
        output_directory,
        extraction_mode,
        rewrite_level,
    )
    .map_err(|error| McpError::invalid_params(error.to_string(), None))?;
    session
        .ledger
        .lock()
        .unwrap()
        .record(evidence.clone())
        .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    let val = serde_json::to_value(&evidence)
        .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    Ok(CallToolResult::structured(val))
}

fn handle_compare_source_to_bundle(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let reference = args.get("reference").cloned().ok_or_else(|| {
        McpError::invalid_params("compare_source_to_bundle requires 'reference'", None)
    })?;
    let application_value = args.get("application").cloned().ok_or_else(|| {
        McpError::invalid_params("compare_source_to_bundle requires 'application'", None)
    })?;
    let application = if application_value.get("kind").and_then(|v| v.as_str()) == Some("retained-evidence")
    {
        let evidence_id = application_value
            .get("evidence_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpError::invalid_params("retained evidence requires evidence_id", None))?;
        session
            .ledger
            .lock()
            .unwrap()
            .get(evidence_id)
            .cloned()
            .ok_or_else(|| {
                McpError::invalid_params(
                    format!("Evidence retained in this session is missing: {evidence_id}"),
                    None,
                )
            })?
    } else {
        serde_json::from_value(application_value).map_err(|error| {
            McpError::invalid_params(format!("Invalid application evidence: {error}"), None)
        })?
    };
    let mut ledger = session.ledger.lock().unwrap();
    if !ledger.has(&application.evidence_id) {
        ledger
            .record(application.clone())
            .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    }
    let evidence = tracewise_js::compare_source_to_bundle_tool(&reference, &application)
        .map_err(|error| McpError::invalid_params(error.to_string(), None))?;
    ledger
        .record(evidence.clone())
        .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    let val = serde_json::to_value(&evidence)
        .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    Ok(CallToolResult::structured(val))
}

fn handle_analyze_javascript_application(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let input_path = args
        .get("input_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            McpError::invalid_params(
                "analyze_javascript_application requires 'input_path'",
                None,
            )
        })?;
    let format = args
        .get("format")
        .and_then(|v| v.as_str())
        .unwrap_or("directory");
    let integrity_policy = args
        .get("integrity_policy")
        .and_then(|v| v.as_str())
        .unwrap_or("fail");
    let evidence = tracewise_js::analyze_javascript_application(
        input_path,
        format,
        integrity_policy,
    )
    .map_err(|error| McpError::invalid_params(error.to_string(), None))?;
    session
        .ledger
        .lock()
        .unwrap()
        .record(evidence.clone())
        .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    let val = serde_json::to_value(&evidence)
        .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    Ok(CallToolResult::structured(val))
}

fn handle_trace_javascript_semantics(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let application_value = args.get("application").cloned().ok_or_else(|| {
        McpError::invalid_params("trace_javascript_semantics requires 'application'", None)
    })?;
    let query = args.get("query").cloned().ok_or_else(|| {
        McpError::invalid_params("trace_javascript_semantics requires 'query'", None)
    })?;
    let application = if application_value.get("kind").and_then(|v| v.as_str()) == Some("retained-evidence")
    {
        let evidence_id = application_value
            .get("evidence_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpError::invalid_params("retained evidence requires evidence_id", None))?;
        session
            .ledger
            .lock()
            .unwrap()
            .get(evidence_id)
            .cloned()
            .ok_or_else(|| {
                McpError::invalid_params(
                    format!("Evidence retained in this session is missing: {evidence_id}"),
                    None,
                )
            })?
    } else {
        serde_json::from_value(application_value).map_err(|error| {
            McpError::invalid_params(format!("Invalid application evidence: {error}"), None)
        })?
    };
    let mut ledger = session.ledger.lock().unwrap();
    if !ledger.has(&application.evidence_id) {
        ledger
            .record(application.clone())
            .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    }
    let evidence = tracewise_js::trace_javascript_semantics(&application, &query)
        .map_err(|error| McpError::invalid_params(error.to_string(), None))?;
    ledger
        .record(evidence.clone())
        .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    let val = serde_json::to_value(&evidence)
        .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    Ok(CallToolResult::structured(val))
}

pub(crate) fn resolve_evidence_input(
    session: &BinarySession,
    value: &Value,
    label: &str,
) -> Result<Evidence, McpError> {
    let evidence = if value.get("kind").and_then(|v| v.as_str()) == Some("retained-evidence") {
        let evidence_id = value.get("evidence_id").and_then(|v| v.as_str()).ok_or_else(|| {
            McpError::invalid_params("retained evidence requires evidence_id", None)
        })?;
        session
            .ledger
            .lock()
            .unwrap()
            .get(evidence_id)
            .cloned()
            .ok_or_else(|| {
                McpError::invalid_params(
                    format!("Evidence retained in this session is missing: {evidence_id}"),
                    None,
                )
            })?
    } else {
        serde_json::from_value(value.clone()).map_err(|error| {
            McpError::invalid_params(format!("Invalid {label} evidence: {error}"), None)
        })?
    };
    let mut ledger = session.ledger.lock().unwrap();
    if !ledger.has(&evidence.evidence_id) {
        ledger
            .record(evidence.clone())
            .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    }
    Ok(evidence)
}

pub(crate) fn remember_evidence(session: &BinarySession, evidence: Evidence) -> Result<CallToolResult, McpError> {
    session
        .ledger
        .lock()
        .unwrap()
        .record(evidence.clone())
        .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    let val = serde_json::to_value(&evidence)
        .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    Ok(CallToolResult::structured(val))
}

fn evidence_list(value: Option<&Value>, label: &str) -> Result<Vec<Value>, McpError> {
    match value {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => Ok(items.clone()),
        Some(_) => Err(McpError::invalid_params(format!("{label} must be an array"), None)),
    }
}

fn handle_trace_application_feature(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let application_value = args.get("application").cloned().ok_or_else(|| {
        McpError::invalid_params("trace_application_feature requires 'application'", None)
    })?;
    let seed = args.get("seed").cloned().ok_or_else(|| {
        McpError::invalid_params("trace_application_feature requires 'seed'", None)
    })?;
    let application = resolve_evidence_input(session, &application_value, "application")?;
    let mut native = Vec::new();
    for item in evidence_list(args.get("native_observations"), "native_observations")? {
        native.push(resolve_evidence_input(session, &item, "native_observations")?);
    }
    let direction = args.get("direction").and_then(|v| v.as_str());
    let evidence = tracewise_js::trace_application_feature(&application, &native, &seed, direction)
        .map_err(|error| McpError::invalid_params(error.to_string(), None))?;
    remember_evidence(session, evidence)
}

fn handle_compare_application_versions(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let left_value = args.get("left").cloned().ok_or_else(|| {
        McpError::invalid_params("compare_application_versions requires 'left'", None)
    })?;
    let right_value = args.get("right").cloned().ok_or_else(|| {
        McpError::invalid_params("compare_application_versions requires 'right'", None)
    })?;
    let left = resolve_evidence_input(session, &left_value, "left")?;
    let right = resolve_evidence_input(session, &right_value, "right")?;
    let mut left_native = Vec::new();
    for item in evidence_list(args.get("left_native_observations"), "left_native_observations")? {
        left_native.push(resolve_evidence_input(session, &item, "left_native_observations")?);
    }
    let mut right_native = Vec::new();
    for item in evidence_list(args.get("right_native_observations"), "right_native_observations")? {
        right_native.push(resolve_evidence_input(session, &item, "right_native_observations")?);
    }
    let evidence = tracewise_js::compare_application_versions(&left, &right, &left_native, &right_native)
        .map_err(|error| McpError::invalid_params(error.to_string(), None))?;
    remember_evidence(session, evidence)
}

fn handle_compare_javascript_export_shapes(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let text = |key: &str| {
        args.get(key).and_then(|v| v.as_str()).map(str::to_string).ok_or_else(|| {
            McpError::invalid_params(format!("compare_javascript_export_shapes requires '{key}'"), None)
        })
    };
    let left_module_path = text("left_module_path")?;
    let left_export_name = text("left_export_name")?;
    let right_module_path = text("right_module_path")?;
    let right_export_name = text("right_export_name")?;
    let left_value = args.get("left").cloned().ok_or_else(|| {
        McpError::invalid_params("compare_javascript_export_shapes requires 'left'", None)
    })?;
    let right_value = args.get("right").cloned().ok_or_else(|| {
        McpError::invalid_params("compare_javascript_export_shapes requires 'right'", None)
    })?;
    let left = resolve_evidence_input(session, &left_value, "left")?;
    let right = resolve_evidence_input(session, &right_value, "right")?;
    let evidence = tracewise_js::compare_javascript_export_shapes(
        &left,
        &right,
        &left_module_path,
        &left_export_name,
        &right_module_path,
        &right_export_name,
    )
    .map_err(|error| McpError::invalid_params(error.to_string(), None))?;
    remember_evidence(session, evidence)
}

fn handle_generate_api_client(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    let input: tracewise_web::api_client::GenerateApiClientInput = serde_json::from_value(args.clone())
        .map_err(|e| McpError::invalid_params(format!("Invalid generate_api_client input: {e}"), None))?;
    let generated = tracewise_web::api_client::generate_api_client(&input)
        .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

    let mut ledger = session.ledger.lock().unwrap();
    if let Some(source) = generated.replay_source {
        if !ledger.has(&source.evidence_id) {
            ledger
                .record(source)
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        }
    }
    if !ledger.has(&generated.evidence.evidence_id) {
        ledger
            .record(generated.evidence.clone())
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    }
    let val = serde_json::to_value(&generated.evidence)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    Ok(CallToolResult::structured(val))
}

async fn handle_list_javascript_runtime_targets(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let input = tracewise_js::runtime::inspector::parse_list_runtime_targets_input(args).map_err(|e| {
        McpError::invalid_params(format!("Invalid list_javascript_runtime_targets input: {e}"), None)
    })?;
    browser_tool_result(
        session,
        tracewise_js::runtime::inspector::list_javascript_runtime_targets(&input).await,
    )
}

async fn handle_observe_javascript_runtime(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let input = tracewise_js::runtime::inspector::parse_observe_runtime_input(args).map_err(|e| {
        McpError::invalid_params(format!("Invalid observe_javascript_runtime input: {e}"), None)
    })?;
    browser_tool_result(
        session,
        tracewise_js::runtime::inspector::observe_javascript_runtime(&input).await,
    )
}

fn handle_reconcile_javascript_runtime(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let evidence = tracewise_js::reconcile_javascript_runtime(args)
        .map_err(|error| McpError::invalid_params(error.to_string(), None))?;
    remember_evidence(session, evidence)
}
