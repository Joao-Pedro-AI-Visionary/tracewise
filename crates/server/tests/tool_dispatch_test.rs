//! Every registered REA tool must reach a real handler.
//!
//! Empty input may fail validation. It must not report that the tool is unknown
//! or that its implementation is still missing.

use rmcp::model::CallToolRequestParam;
use serde_json::json;
use tracewise_contracts::all_tool_names;
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

#[tokio::test]
async fn every_rea_tool_dispatches_to_an_implementation() {
    let names = all_tool_names();
    assert_eq!(names.len(), 27, "REA exposes 27 tools");
    let session = BinarySession::new();
    for name in names {
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
}
