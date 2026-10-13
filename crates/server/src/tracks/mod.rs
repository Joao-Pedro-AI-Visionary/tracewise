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

/// Marker returned by tools whose port has not landed yet.
pub const PENDING_PORT: &str = "pending port";

pub(crate) fn pending(name: &str) -> Result<CallToolResult, McpError> {
    Err(McpError::invalid_request(format!("{PENDING_PORT}: {name}"), None))
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
