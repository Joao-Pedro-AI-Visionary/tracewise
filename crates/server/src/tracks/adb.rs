//! Dispatch for the adb tools (24).
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
        "inspect_adb_client" |
        "list_adb_devices" |
        "inspect_adb_device" |
        "list_adb_packages" |
        "pull_adb_package" |
        "read_adb_logcat" |
        "inspect_adb_package" |
        "pull_adb_file" |
        "push_adb_file" |
        "capture_adb_screen" |
        "list_adb_processes" |
        "list_adb_directory" |
        "list_adb_features" |
        "list_adb_services" |
        "inspect_adb_display" |
        "inspect_adb_window" |
        "read_adb_setting" |
        "collect_adb_bugreport" |
        "resolve_adb_packages" |
        "install_adb_package" |
        "uninstall_adb_package" |
        "start_adb_app" |
        "start_adb_activity" |
        "stop_adb_app" => pending(name),
        _ => return None,
    })
}
