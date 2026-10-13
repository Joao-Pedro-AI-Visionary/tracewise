//! Dispatch for the managed android tools (19).
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
        "inspect_managed_artifact" |
        "inspect_managed_members" |
        "inspect_managed_native_boundaries" |
        "compare_managed_members" |
        "verify_managed_native_boundaries" |
        "import_managed_reconstruction" |
        "project_managed_application_graph" |
        "inspect_android_package" |
        "search_android_classes" |
        "inspect_android_class" |
        "inspect_android_method" |
        "trace_android_references" |
        "inspect_jeb_client" |
        "open_jeb_project" |
        "list_jeb_units" |
        "decompile_jeb_item" |
        "inspect_apktool_client" |
        "decode_android_resources" |
        "project_android_application_graph" => pending(name),
        _ => return None,
    })
}
