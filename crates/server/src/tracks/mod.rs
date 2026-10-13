//! Phase 3-6 tool families, one module per track.

pub mod managed_android;
pub mod adb;
pub mod native_static;
pub mod engines;
pub mod native_runtime;

use rmcp::model::CallToolResult;
use rmcp::ErrorData as McpError;
use serde_json::Value;

use crate::session::BinarySession;

/// Release everything the tracks hold outside a tool call. Called when the MCP transport closes
/// and on SIGTERM/SIGINT; nothing may outlive the server:
/// - engines: live Ghidra/Hopper/IDA processes and their runtime directories;
/// - Android: the retained JADX session (JVM and its `rea-android-*` directory) and the JEB
///   provider state;
/// - adb: package directories left behind by cancelled `pull_adb_package` calls.
pub async fn shutdown() {
    // Independent releases run side by side: engines may take seconds to confirm their exit.
    let blocking = tokio::task::spawn_blocking(|| {
        tracewise_android::jadx::shutdown();
        tracewise_android::jeb::shutdown();
        let left = tracewise_device::provider::shutdown();
        if !left.is_empty() {
            eprintln!("tracewise: could not remove {} pending adb package directories: {}", left.len(), left.join(", "));
        }
    });
    engines::shutdown().await;
    let _ = blocking.await;
}

pub async fn dispatch(
    session: &BinarySession,
    name: &str,
    args: &Value,
) -> Option<Result<CallToolResult, McpError>> {
    if let Some(result) = managed_android::dispatch(session, name, args).await {
        return Some(result);
    }
    if let Some(result) = adb::dispatch(session, name, args).await {
        return Some(result);
    }
    if let Some(result) = native_static::dispatch(session, name, args).await {
        return Some(result);
    }
    if let Some(result) = engines::dispatch(session, name, args).await {
        return Some(result);
    }
    if let Some(result) = native_runtime::dispatch(session, name, args).await {
        return Some(result);
    }
    None
}
