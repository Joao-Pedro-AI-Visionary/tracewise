//! `capture_process_scenario` and `compare_process_captures` (REA
//! `registerSessionTools.ts` / `registerProcessComparisonTool.ts`).
//!
//! Capture and comparison failures are tool results (`isError`) carrying the
//! REA error envelope; only malformed capture arguments are protocol errors,
//! matching the rest of this server.

use rmcp::model::{CallToolResult, Content};
use rmcp::ErrorData as McpError;
use serde_json::{json, Value};
use tracewise_js::process_capture::CaptureError;
use tracewise_js::JsError;

use crate::handlers::{remember_evidence, resolve_evidence_input};
use crate::session::BinarySession;

fn error_result(body: Value) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::error(vec![Content::text(body.to_string())]))
}

pub async fn handle_capture_process_scenario(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let owned = args.clone();
    // The capture blocks on PTY reads, sampling and settlement; keep it off the async workers.
    let outcome = tokio::task::spawn_blocking(move || tracewise_js::capture_process_scenario(&owned))
        .await
        .map_err(|e| McpError::internal_error(format!("process capture task failed: {e}"), None))?;
    match outcome {
        Ok(evidence) => remember_evidence(session, evidence),
        Err(CaptureError::Invalid(message)) => Err(McpError::invalid_params(message, None)),
        Err(error @ CaptureError::Failed(_)) => error_result(error.body()),
    }
}

/// REA envelope for comparison failures.
fn compare_error_body(error: &JsError) -> Value {
    match error {
        JsError::Integrity(message) => json!({
            "error": {
                "code": "evidence_integrity_mismatch",
                "category": "integrity_mismatch",
                "message": message,
                "retryable": false,
                "remediation": { "action": message },
                "details": { "reason": message },
            }
        }),
        other => {
            let text = match other {
                JsError::InvalidInput(m) => m.clone(),
                e => e.to_string(),
            };
            let (path, message) = match text.split_once(": ") {
                Some((p, m)) if !p.contains(' ') => (p.to_string(), m.to_string()),
                _ => (String::new(), text.clone()),
            };
            json!({
                "error": {
                    "code": "invalid_request",
                    "category": "invalid_input",
                    "message": "Analysis input is invalid. Check the arguments and try again.",
                    "retryable": true,
                    "remediation": { "action": "Correct the listed arguments and retry." },
                    "details": {
                        "operation": "compare_process_captures",
                        "issues": [{ "path": [path], "reason": "invalid_value", "message": message }],
                    },
                }
            })
        }
    }
}

pub fn handle_compare_process_captures(
    session: &BinarySession,
    args: &Value,
) -> Result<CallToolResult, McpError> {
    let left_value = args
        .get("left")
        .ok_or_else(|| McpError::invalid_params("compare_process_captures requires left", None))?;
    let right_value = args
        .get("right")
        .ok_or_else(|| McpError::invalid_params("compare_process_captures requires right", None))?;
    let left = resolve_evidence_input(session, left_value, "left")?;
    let right = resolve_evidence_input(session, right_value, "right")?;
    match tracewise_js::compare_process_captures_tool(&left, &right, args) {
        Ok(evidence) => remember_evidence(session, evidence),
        Err(error) => error_result(compare_error_body(&error)),
    }
}
