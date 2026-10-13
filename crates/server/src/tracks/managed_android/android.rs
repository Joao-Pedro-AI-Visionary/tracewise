//! Static Android tools: the five JADX-backed inspections and the
//! execution-free application projection (REA `registerAndroidTools`,
//! `AndroidAnalysisService`, `projectAndroidApplicationEvidence`).

#![allow(clippy::result_large_err)]

use rmcp::model::{CallToolResult, Content};
use rmcp::ErrorData as McpError;
use serde_json::{json, Value};
use tracewise_android::analysis::Request;
use tracewise_android::cancel::CancelToken;
use tracewise_android::config::process_env;
use tracewise_android::error::Error as AndroidError;
use tracewise_android::jadx::{self, Target, LIMITATIONS};
use tracewise_domain::evidence::{
    create_evidence, DigestSha256, EvidenceAuthority, EvidenceConfidence, EvidenceLocation, EvidenceObservation,
    EvidenceProvider, EvidenceSubject,
};
use tracewise_managed::target::resolve_target_bounded;

use super::support::{input_validation_error, target_unavailable};
use super::workflows::schema_issues;
use crate::handlers::remember_evidence;
use crate::session::BinarySession;

pub fn jadx_provider() -> EvidenceProvider {
    EvidenceProvider { id: "jadx".to_string(), name: "JADX headless".to_string(), version: Some("0.7.1".to_string()) }
}

pub fn error_result(error: &AndroidError) -> CallToolResult {
    CallToolResult::error(vec![Content::text(error.to_envelope().to_string())])
}

pub async fn handle_jadx(session: &BinarySession, tool: &str, args: &Value) -> Result<CallToolResult, McpError> {
    let issues = schema_issues(tool, args);
    if !issues.is_empty() {
        return Ok(input_validation_error(tool, &issues));
    }
    let Some(request) = Request::from_args(tool, args) else {
        return Ok(input_validation_error(tool, &["Invalid input".to_string()]));
    };
    let path = args["path"].as_str().unwrap_or_default().to_string();
    // Hashing streams the whole file; only a 16 MiB head is kept for format detection.
    let resolve_path = path.clone();
    let resolved = match tokio::task::spawn_blocking(move || resolve_target_bounded(&resolve_path, 16 * 1024 * 1024))
        .await
        .map_err(|error| McpError::internal_error(error.to_string(), None))?
    {
        Ok(resolved) => resolved,
        Err(error) => return Ok(target_unavailable(&error.path, &error.reason, error.constraint)),
    };
    let target = Target {
        selected_path: path.clone(),
        path: resolved.path.clone(),
        sha256: resolved.sha256.clone(),
        format: resolved.format.clone(),
    };
    drop(resolved);
    let operation = tool.to_string();
    let worker_request = request.clone();
    let worker_target = target.clone();
    // Dropping this future (MCP cancellation) kills the engine's process group; the
    // blocking side then retires the session and removes its private directory.
    let cancel = CancelToken::new();
    let guard = cancel.guard();
    let worker_cancel = cancel.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        jadx::execute(&worker_target, &worker_request, &process_env(), &worker_cancel)
    })
    .await
    .map_err(|error| McpError::internal_error(format!("{operation}: {error}"), None))?;
    guard.disarm();
    let execution = match outcome {
        Ok(execution) => execution,
        Err(error) => return Ok(error_result(&error)),
    };
    let name = std::path::Path::new(&target.path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| target.path.clone());
    let subject = EvidenceSubject {
        name,
        digest: DigestSha256 { sha256: target.sha256.clone() },
        format: "apk".to_string(),
        architecture: None,
        local_path: target.path.clone(),
    };
    let locations: Vec<EvidenceLocation> = execution
        .locations
        .iter()
        .filter_map(|l| l["path"].as_str().map(|p| EvidenceLocation::ArtifactPath { path: p.to_string() }))
        .collect();
    debug_assert_eq!(execution.limitations.len(), LIMITATIONS.len());
    let evidence = create_evidence(
        Some(subject),
        jadx_provider(),
        EvidenceObservation {
            predicate_type: Some("rea.analysis".to_string()),
            operation: tool.to_string(),
            parameters: args.clone(),
            normalized_result: execution.result,
            raw_result: Some(execution.raw_result),
            analysis_profile: None,
            confidence: Some(if tool == "inspect_android_method" { EvidenceConfidence::Derived } else { EvidenceConfidence::Observed }),
            authority: Some(EvidenceAuthority::ShippedArtifact),
            environment: None,
            limitations: Some(execution.limitations),
            locations: Some(locations),
            evidence_links: Some(Vec::new()),
        },
    )
    .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    remember_evidence(session, evidence)
}

fn workflow_input(messages: &[String]) -> CallToolResult {
    let error = AndroidError::from(tracewise_android::error::Failure::Input {
        operation: "project_android_application_graph".to_string(),
        issues: messages
            .iter()
            .map(|message| tracewise_android::error::InputIssue { path: vec![], reason: "invalid_value", message: message.clone() })
            .collect(),
    });
    error_result(&error)
}

pub fn handle_graph(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    let tool = "project_android_application_graph";
    let issues = schema_issues(tool, args);
    if !issues.is_empty() {
        return Ok(input_validation_error(tool, &issues));
    }
    let records: Vec<Value> = args["inventory_evidence"].as_array().cloned().unwrap_or_default();
    let (result, source_ids, subject) = match tracewise_android::appgraph::project_android_application(&records) {
        Ok(projection) => projection,
        Err(tracewise_android::appgraph::ProjectionError::Input(messages)) => return Ok(workflow_input(&messages)),
        Err(tracewise_android::appgraph::ProjectionError::Protocol(_)) => {
            return Ok(super::support::rea_error(
                "unreadable_output",
                "execution_failure",
                "Analysis returned an unreadable result. Retry once; if it continues, run `rea doctor`.",
                false,
                "Analysis returned an unreadable result. Retry once; if it continues, run `rea doctor`.",
                json!({}),
            ))
        }
    };
    let subject = subject.map(|s| EvidenceSubject {
        name: s["local_path"]
            .as_str()
            .and_then(|p| p.rsplit('/').next())
            .filter(|n| !n.is_empty())
            .unwrap_or("artifact")
            .to_string(),
        digest: DigestSha256 { sha256: result["root_sha256"].as_str().unwrap_or_default().to_string() },
        format: "apk".to_string(),
        architecture: None,
        local_path: s["local_path"].as_str().unwrap_or_default().to_string(),
    });
    let mut limitations: Vec<String> = Vec::new();
    if subject.is_none() {
        limitations.push("Artifact identity is unavailable for this observation.".to_string());
    }
    limitations.extend(result["limitations"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_string)));
    let evidence = create_evidence(
        subject,
        EvidenceProvider {
            id: "rea-android-application".to_string(),
            name: "REA Android application workflows".to_string(),
            version: Some("1".to_string()),
        },
        EvidenceObservation {
            predicate_type: Some("rea.android-application-graph".to_string()),
            operation: tool.to_string(),
            parameters: json!({ "inventory_evidence_ids": source_ids }),
            normalized_result: result,
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Inferred),
            authority: Some(EvidenceAuthority::AnalystInference),
            environment: None,
            limitations: Some(limitations),
            locations: None,
            evidence_links: Some(source_ids),
        },
    )
    .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    remember_evidence(session, evidence)
}
