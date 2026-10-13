//! Dispatch for the engines tools (57).
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
        "inspect_native_load_image" |
        "inspect_native_data_type" |
        "inspect_native_instruction" |
        "resolve_native_call_targets" |
        "address_name" |
        "comment" |
        "inline_comment" |
        "list_documents" |
        "list_names" |
        "list_procedures" |
        "list_segments" |
        "list_strings" |
        "next_address" |
        "prev_address" |
        "procedure_address" |
        "procedure_assembly" |
        "procedure_callees" |
        "procedure_callers" |
        "procedure_info" |
        "read_function_instructions" |
        "read_bytes" |
        "address_to_file_offset" |
        "procedure_references" |
        "procedure_pseudo_code" |
        "resolve_containing_procedure" |
        "search_procedures" |
        "search_strings" |
        "xrefs" |
        "trace_native_values" |
        "inspect_native_dispatch_metadata" |
        "get_objc_classes" |
        "get_objc_protocols" |
        "batch_decompile" |
        "get_call_graph" |
        "analyze_swift_types" |
        "find_xrefs_to_name" |
        "binary_overview" |
        "analyze_function" |
        "inspect_native_api" |
        "trace_feature" |
        "trace_call_path" |
        "compare_functions" |
        "build_call_path" |
        "inspect_address_context" |
        "annotate_native_function" |
        "current_address" |
        "current_procedure" |
        "current_document" |
        "goto_address" |
        "list_bookmarks" |
        "set_address_name" |
        "set_addresses_names" |
        "set_bookmark" |
        "set_comment" |
        "set_inline_comment" |
        "unset_bookmark" |
        "get_navigation_context" => pending(name),
        _ => return None,
    })
}
