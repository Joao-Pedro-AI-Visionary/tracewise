//! Phase 0 and Phase 1 tools must reach a real handler.
//! Phase 2 tools not yet ported are registered and return `not yet implemented: <tool>`.
//!
//! Empty input may fail validation. It must not report that the tool is unknown.
//! Phase 0 and Phase 1 must not report that the implementation is still missing.

use rmcp::model::CallToolRequestParam;
use serde_json::json;
use tracewise_contracts::{
    all_tool_names, phase0_tool_names, phase1_tool_names, phase2_tool_names,
    tracewise_tool_names,
};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

/// Phase 2 tools implemented in Rust (still listed under phase2 in contracts).
const PHASE2_IMPLEMENTED: &[&str] = &[
    "inspect_artifact",
    "extract_artifact",
    "compare_artifacts",
    "recover_javascript_sources",
    "compare_source_to_bundle",
    "analyze_javascript_application",
    "trace_javascript_semantics",
    "trace_application_feature",
    "compare_application_versions",
    "compare_javascript_export_shapes",
    "list_javascript_runtime_targets",
    "observe_javascript_runtime",
    "reconcile_javascript_runtime",
];

#[tokio::test]
async fn every_rea_tool_dispatches_to_an_implementation() {
    let names = all_tool_names();
    assert_eq!(names.len(), 50, "REA exposes 50 tools");
    let pending: Vec<&str> = phase2_tool_names()
        .iter()
        .copied()
        .filter(|name| !PHASE2_IMPLEMENTED.contains(name))
        .collect();
    assert_eq!(pending.len(), 10);
    let mut implemented: Vec<&str> = Vec::new();
    implemented.extend_from_slice(phase0_tool_names());
    implemented.extend_from_slice(phase1_tool_names());
    implemented.extend_from_slice(PHASE2_IMPLEMENTED);
    assert_eq!(implemented.len(), 40, "27 phase0/1 + 13 phase2 tools");
    let session = BinarySession::new();
    for name in implemented {
        let result = call_tool_local(
            &session,
            CallToolRequestParam {
                name: (*name).to_string().into(),
                arguments: Some(json!({}).as_object().unwrap().clone()),
            },
        )
        .await;
        let message = match &result {
            Ok(output) => output
                .content
                .iter()
                .map(|item| format!("{item:?}"))
                .collect::<Vec<_>>()
                .join("\n"),
            Err(error) => error.to_string(),
        };
        let folded = message.to_ascii_lowercase();
        assert!(
            !folded.contains("not yet implemented"),
            "{name} is still a stub: {message}"
        );
        assert!(
            !folded.contains("unknown tool"),
            "{name} did not dispatch to an implementation: {message}"
        );
    }

    for name in pending {
        let result = call_tool_local(
            &session,
            CallToolRequestParam {
                name: (*name).to_string().into(),
                arguments: Some(json!({}).as_object().unwrap().clone()),
            },
        )
        .await;
        let Err(error) = result else {
            panic!("{name} should return an MCP error");
        };
        let expected = format!("not yet implemented: {name}");
        assert_eq!(
            error.message.as_ref(),
            expected.as_str(),
            "{name} stub error was: {error}"
        );
    }

    for name in tracewise_tool_names() {
        let result = call_tool_local(
            &session,
            CallToolRequestParam {
                name: (*name).to_string().into(),
                arguments: Some(json!({}).as_object().unwrap().clone()),
            },
        )
        .await;
        let message = match &result {
            Ok(output) => output
                .content
                .iter()
                .map(|item| format!("{item:?}"))
                .collect::<Vec<_>>()
                .join("\n"),
            Err(error) => error.to_string(),
        };
        let folded = message.to_ascii_lowercase();
        assert!(
            !folded.contains("unknown tool"),
            "{name} did not dispatch to an implementation: {message}"
        );
    }
}
