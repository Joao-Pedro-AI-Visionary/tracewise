//! Apktool and JEB tools (REA `registerApktoolTools`, `registerJebTools`):
//! `inspect_apktool_client`, `decode_android_resources`, `inspect_jeb_client`,
//! `open_jeb_project`, `list_jeb_units`, `decompile_jeb_item`.
//!
//! Both engines are bring-your-own. Without a launcher or a running client the
//! tools answer a structured `capability_unavailable`; nothing is installed.

#![allow(clippy::result_large_err)]

use rmcp::model::CallToolResult;
use rmcp::ErrorData as McpError;
use serde_json::{json, Value};
use tracewise_android::cancel::CancelToken;
use tracewise_android::config::process_env;
use tracewise_android::{apktool, jeb};
use tracewise_domain::evidence::{
    create_evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation, EvidenceProvider,
};

use super::android::error_result;
use super::support::input_validation_error;
use super::workflows::schema_issues;
use crate::handlers::remember_evidence;
use crate::session::BinarySession;

const NO_IDENTITY: &str = "Artifact identity is unavailable for this observation.";

fn provider_of(value: &Value) -> EvidenceProvider {
    EvidenceProvider {
        id: value["id"].as_str().unwrap_or_default().to_string(),
        name: value["name"].as_str().unwrap_or_default().to_string(),
        version: value["version"].as_str().map(str::to_string),
    }
}

#[allow(clippy::too_many_arguments)]
fn record(
    session: &BinarySession,
    operation: &str,
    parameters: Value,
    result: Value,
    provider: &Value,
    raw_result: Option<Value>,
    limitations: Vec<String>,
    confidence: EvidenceConfidence,
) -> Result<CallToolResult, McpError> {
    let mut all = vec![NO_IDENTITY.to_string()];
    all.extend(limitations);
    let evidence = create_evidence(
        None,
        provider_of(provider),
        EvidenceObservation {
            predicate_type: Some("rea.analysis".to_string()),
            operation: operation.to_string(),
            parameters,
            normalized_result: result,
            raw_result,
            analysis_profile: None,
            confidence: Some(confidence),
            authority: Some(EvidenceAuthority::ShippedArtifact),
            environment: None,
            limitations: Some(all),
            locations: Some(Vec::new()),
            evidence_links: Some(Vec::new()),
        },
    )
    .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    remember_evidence(session, evidence)
}

// ---------------------------------------------------------------------------
// Apktool
// ---------------------------------------------------------------------------

pub async fn handle_apktool(session: &BinarySession, tool: &str, args: &Value) -> Result<CallToolResult, McpError> {
    let issues = schema_issues(tool, args);
    if !issues.is_empty() {
        return Ok(input_validation_error(tool, &issues));
    }
    let env = process_env();
    // An invalid launcher setting is a startup configuration error in REA: the
    // tool call itself fails with the bare setting message.
    if let Err(config) = apktool::resolve_command(&env) {
        return Ok(CallToolResult::error(vec![rmcp::model::Content::text(config.message)]));
    }
    let tool_name = tool.to_string();
    let input = args.clone();
    let worker_env = env.clone();
    // Dropping this future (MCP cancellation) kills the launcher's process group
    // and lets the blocking side remove its workspace.
    let cancel = CancelToken::new();
    let guard = cancel.guard();
    let worker_cancel = cancel.clone();
    let outcome = tokio::task::spawn_blocking(move || match tool_name.as_str() {
        "inspect_apktool_client" => apktool::execute_client(&worker_env, &worker_cancel),
        _ => {
            let include_strings = input.get("include_strings").and_then(Value::as_bool).unwrap_or(true);
            let locale = input.get("locale").and_then(Value::as_str);
            apktool::execute_decode(&worker_env, input["path"].as_str().unwrap_or_default(), include_strings, locale, &worker_cancel)
        }
    })
    .await
    .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    guard.disarm();
    let execution = match outcome {
        Ok(execution) => execution,
        Err(error) => return Ok(error_result(&error)),
    };
    let mut parameters = args.as_object().cloned().unwrap_or_default();
    if tool == "decode_android_resources" && !parameters.contains_key("include_strings") {
        parameters.insert("include_strings".to_string(), json!(true));
    }
    record(
        session,
        tool,
        Value::Object(parameters),
        execution.result,
        &execution.provider,
        None,
        execution.limitations,
        EvidenceConfidence::Observed,
    )
}

// ---------------------------------------------------------------------------
// JEB
// ---------------------------------------------------------------------------

pub async fn handle_jeb(session: &BinarySession, tool: &str, args: &Value) -> Result<CallToolResult, McpError> {
    let issues = schema_issues(tool, args);
    if !issues.is_empty() {
        return Ok(input_validation_error(tool, &issues));
    }
    let Some(request) = jeb::Request::from_args(tool, args) else {
        return Ok(input_validation_error(tool, &["Invalid input".to_string()]));
    };
    let env = process_env();
    let worker_request = request.clone();
    let cancel = CancelToken::new();
    let guard = cancel.guard();
    let worker_cancel = cancel.clone();
    let outcome = tokio::task::spawn_blocking(move || jeb::execute(&worker_request, &env, &worker_cancel))
        .await
        .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    guard.disarm();
    let outcome = match outcome {
        Ok(outcome) => outcome,
        // An unusable endpoint makes REA's provider construction throw.
        Err(_rejected) => return Err(McpError::internal_error("Internal server error", None)),
    };
    let execution = match outcome {
        Ok(execution) => execution,
        Err(error) => return Ok(error_result(&error)),
    };
    record(
        session,
        tool,
        request.parameters(),
        execution.result,
        &execution.provider,
        Some(execution.raw_result),
        execution.limitations,
        if tool == "decompile_jeb_item" { EvidenceConfidence::Derived } else { EvidenceConfidence::Observed },
    )
}
