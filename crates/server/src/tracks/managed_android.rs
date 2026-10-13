//! Dispatch for the managed android tools (19).
//!
//! Arms that still answer with the pending-port error are replaced by the real
//! handler as each tool lands.

use rmcp::model::CallToolResult;
use rmcp::ErrorData as McpError;
use serde_json::Value;

use crate::session::BinarySession;

mod android;
mod managed;
mod providers;
pub(crate) mod support;
mod workflows;

pub async fn dispatch(
    session: &BinarySession,
    name: &str,
    args: &Value,
) -> Option<Result<CallToolResult, McpError>> {
    Some(match name {
        "inspect_managed_artifact" | "inspect_managed_members" | "inspect_managed_native_boundaries" => {
            managed::handle(session, name, args).await
        }
        "compare_managed_members" | "verify_managed_native_boundaries" | "import_managed_reconstruction" | "project_managed_application_graph" => {
            workflows::handle(session, name, args)
        }
        "inspect_android_package"
        | "search_android_classes"
        | "inspect_android_class"
        | "inspect_android_method"
        | "trace_android_references" => android::handle_jadx(session, name, args).await,
        "project_android_application_graph" => android::handle_graph(session, args),
        "inspect_jeb_client" | "open_jeb_project" | "list_jeb_units" | "decompile_jeb_item" => {
            providers::handle_jeb(session, name, args).await
        }
        "inspect_apktool_client" | "decode_android_resources" => providers::handle_apktool(session, name, args).await,
        _ => return None,
    })
}
