//! Dispatch for the native static tools (14).
//!
//! The parsing and analysis live in the `tracewise-native` crate; the handlers
//! in the submodules only validate input, resolve the active target, call the
//! crate and record Evidence.
//!
//! Every analysis reads files and decodes untrusted formats, so it runs on the blocking pool
//! behind a semaphore instead of on the async worker. When the request future is dropped
//! (MCP cancellation) a [`CancelToken`] is set, and the long loops of the crate stop early; the
//! semaphore permit travels with the blocking task, so a cancelled analysis keeps its slot until
//! it has really stopped.
#![allow(clippy::result_large_err, clippy::too_many_arguments)]

use std::sync::OnceLock;

use rmcp::model::CallToolResult;
use rmcp::ErrorData as McpError;
use serde_json::Value;
use tokio::sync::Semaphore;
use tracewise_native::cancel::{self, CancelToken};

use crate::session::BinarySession;

mod apple_graph;
mod artifact_tools;
mod binary_tools;
mod common;
mod macho_handlers;
mod validate;

/// Analyses that may decode untrusted input at the same time.
const MAX_CONCURRENT_ANALYSES: usize = 4;

fn permits() -> &'static std::sync::Arc<Semaphore> {
    static PERMITS: OnceLock<std::sync::Arc<Semaphore>> = OnceLock::new();
    PERMITS.get_or_init(|| std::sync::Arc::new(Semaphore::new(MAX_CONCURRENT_ANALYSES)))
}

const TOOLS: [&str; 14] = [
    "trace_dylib_resolution",
    "inspect_keyed_archive",
    "decode_interface_builder",
    "inspect_pe_resources",
    "inspect_evm_interface",
    "project_apple_application_graph",
    "inspect_binary_layout",
    "inspect_recorded_crash",
    "list_architectures",
    "inspect_macho",
    "inspect_plist",
    "demangle_swift",
    "inspect_signature",
    "inspect_asset_catalog",
];

/// The synchronous body of one tool call.
fn run(session: &BinarySession, name: &str, args: &Value) -> Result<CallToolResult, McpError> {
    match name {
        "trace_dylib_resolution" => artifact_tools::trace_dylib_resolution(session, args),
        "inspect_keyed_archive" => artifact_tools::inspect_keyed_archive(session, args),
        "decode_interface_builder" => artifact_tools::decode_interface_builder(session, args),
        "inspect_pe_resources" => binary_tools::inspect_pe_resources(session, args),
        "inspect_evm_interface" => binary_tools::inspect_evm_interface(session, args),
        "project_apple_application_graph" => apple_graph::project_apple_application_graph(session, args),
        "inspect_binary_layout" => binary_tools::inspect_binary_layout(session, args),
        "inspect_recorded_crash" => binary_tools::inspect_recorded_crash(session, args),
        "list_architectures" => macho_handlers::list_architectures(session, args),
        "inspect_macho" => macho_handlers::inspect_macho(session, args),
        "inspect_plist" => macho_handlers::inspect_plist(session, args),
        "demangle_swift" => macho_handlers::demangle_swift(session, args),
        "inspect_signature" => macho_handlers::inspect_signature(session, args),
        "inspect_asset_catalog" => artifact_tools::inspect_asset_catalog(session, args),
        other => Err(McpError::invalid_request(format!("unknown native tool: {other}"), None)),
    }
}

pub async fn dispatch(
    session: &BinarySession,
    name: &str,
    args: &Value,
) -> Option<Result<CallToolResult, McpError>> {
    if !TOOLS.contains(&name) {
        return None;
    }
    let permit = match permits().clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => return Some(Err(McpError::internal_error("the native analysis pool is closed", None))),
    };
    let token = CancelToken::new();
    // Dropped with this future when the request is cancelled.
    let guard = token.cancel_on_drop();
    let (session, name, args) = (session.clone(), name.to_string(), args.clone());
    let worker_token = token.clone();
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        cancel::scope(worker_token, || run(&session, &name, &args))
    });
    let outcome = match task.await {
        Ok(result) => result,
        Err(join_error) => Err(McpError::internal_error(format!("native analysis failed: {join_error}"), None)),
    };
    guard.disarm();
    Some(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    async fn wait_for_all_slots() {
        for _ in 0..200 {
            if permits().available_permits() == MAX_CONCURRENT_ANALYSES {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("analysis slots were not released");
    }

    #[tokio::test]
    async fn a_dropped_request_releases_its_slot_and_the_next_call_is_served() {
        let session = BinarySession::new();
        // A request that is abandoned right away (what MCP cancellation does to the future).
        let abandoned = tokio::time::timeout(
            Duration::from_millis(1),
            dispatch(&session, "demangle_swift", &json!({"symbols": ["$s4Test3fooyyF"]})),
        )
        .await;
        drop(abandoned);
        wait_for_all_slots().await;
        // The pool still works, and an unknown tool is not claimed by this track.
        let served = dispatch(&session, "demangle_swift", &json!({"symbols": ["x"]})).await;
        assert!(served.is_some());
        assert!(dispatch(&session, "not_a_native_tool", &json!({})).await.is_none());
        wait_for_all_slots().await;
    }

    #[tokio::test]
    async fn more_requests_than_slots_all_complete() {
        let session = BinarySession::new();
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let session = session.clone();
                tokio::spawn(async move {
                    dispatch(&session, "demangle_swift", &json!({"symbols": ["$s4Test3fooyyF"]})).await.is_some()
                })
            })
            .collect();
        for handle in handles {
            assert!(handle.await.unwrap());
        }
        wait_for_all_slots().await;
    }
}
