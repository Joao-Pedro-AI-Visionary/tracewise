//! Dispatch for the native runtime tools (6).
//!
//! Each arm still answers with the pending-port error. Replace an arm with the
//! real handler when the tool is implemented.

use rmcp::model::CallToolResult;
use rmcp::ErrorData as McpError;
use serde_json::Value;

use super::pending;
use crate::session::BinarySession;

pub async fn dispatch(
    _session: &BinarySession,
    name: &str,
    _args: &Value,
) -> Option<Result<CallToolResult, McpError>> {
    Some(match name {
        "trace_native_ui_action" |
        "observe_native_ui" |
        "capture_native_ui_scenario" |
        "observe_native_calls" |
        "inspect_firmware_regions" |
        "extract_firmware" => pending(name),
        _ => return None,
    })
}
