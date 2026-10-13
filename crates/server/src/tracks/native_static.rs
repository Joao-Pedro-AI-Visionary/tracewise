//! Dispatch for the native static tools (14).
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
        "inspect_macho" |
        "inspect_signature" |
        "inspect_plist" |
        "list_architectures" |
        "demangle_swift" |
        "decode_interface_builder" |
        "inspect_keyed_archive" |
        "inspect_asset_catalog" |
        "trace_dylib_resolution" |
        "inspect_binary_layout" |
        "inspect_pe_resources" |
        "inspect_evm_interface" |
        "inspect_recorded_crash" |
        "project_apple_application_graph" => pending(name),
        _ => return None,
    })
}
