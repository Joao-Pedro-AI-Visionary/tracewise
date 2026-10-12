//! Electron tool handlers (port of REA server/registerElectronTools.ts).
//!
//! Error mapping follows the other CDP tools: malformed arguments are MCP
//! protocol errors (`invalid_params`); CDP observation failures go through
//! `browser_tool_result` and become `isError` results. The two non-browser
//! failures of `capture_electron_scenario` (unresolvable paths and the missing
//! active provider) are `isError` results with REA's projected error body.

use rmcp::model::{CallToolResult, Content};
use rmcp::ErrorData as McpError;
use serde_json::{json, Value};
use tracewise_web::error::WebError;

use crate::handlers::browser_tool_result;
use crate::session::BinarySession;

pub async fn handle_list_electron_targets(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let endpoint = tracewise_web::electron_targets::parse_list_electron_targets_input(args).map_err(|e| {
        McpError::invalid_params(format!("Invalid list_electron_targets input: {e}"), None)
    })?;
    browser_tool_result(session, tracewise_js::list_electron_targets_tool(&endpoint).await)
}

pub async fn handle_inspect_electron_page(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let input = tracewise_web::electron_inspection::parse_inspect_electron_page_input(args).map_err(|e| {
        McpError::invalid_params(format!("Invalid inspect_electron_page input: {e}"), None)
    })?;
    browser_tool_result(session, tracewise_js::inspect_electron_page_tool(&input).await)
}

pub async fn handle_capture_electron_scenario(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let input = tracewise_web::electron_scenario::parse_capture_electron_scenario_input(args).map_err(|issues| {
        let text: Vec<String> = issues.iter().map(ToString::to_string).collect();
        McpError::invalid_params(
            format!("Invalid capture_electron_scenario input: {}", text.join(", ")),
            None,
        )
    })?;
    match tracewise_js::capture_electron_scenario_tool(&input).await {
        Err(error @ (WebError::Input { .. } | WebError::CapabilityUnavailable { .. })) => {
            Ok(CallToolResult::error(vec![Content::text(scenario_error_body(&error).to_string())]))
        }
        outcome => browser_tool_result(session, outcome),
    }
}

/// REA `projectAnalysisError` body for `AnalysisInputError` and
/// `AnalysisCapabilityUnavailableError`.
fn scenario_error_body(error: &WebError) -> Value {
    match error {
        WebError::Input {
            operation,
            path,
            reason,
            message,
        } => json!({
            "error": {
                "code": "invalid_request",
                "category": "invalid_input",
                "message": "Analysis input is invalid. Check the arguments and try again.",
                "retryable": true,
                "remediation": { "action": "Correct the listed arguments and retry." },
                "details": {
                    "operation": operation,
                    "issues": [{ "path": path, "reason": reason, "message": message }],
                },
            }
        }),
        WebError::CapabilityUnavailable {
            capability,
            operation,
            reason,
            user_message,
        } => json!({
            "error": {
                "code": "capability_unavailable",
                "category": "unsupported_provider",
                "message": user_message,
                "retryable": false,
                "remediation": { "action": user_message },
                "details": {
                    "provider_id": capability,
                    "operation": operation,
                    "reason": reason,
                },
            }
        }),
        other => json!({ "error": { "message": other.to_string() } }),
    }
}
