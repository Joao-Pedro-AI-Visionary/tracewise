//! Every REA tool (50) and every tracewise tool (2) must reach a real handler.
//!
//! Empty input may fail validation. It must not report that the tool is unknown
//! or that the implementation is still missing.

use rmcp::model::CallToolRequestParam;
use serde_json::json;
use tracewise_contracts::{
    all_tool_names, phase0_tool_names, phase1_tool_names, phase2_tool_names,
    tracewise_tool_names,
};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

#[tokio::test]
async fn every_tool_dispatches_to_an_implementation() {
    let rea = all_tool_names();
    assert_eq!(rea.len(), 50, "REA exposes 50 tools");
    assert_eq!(phase0_tool_names().len() + phase1_tool_names().len(), 27);
    assert_eq!(phase2_tool_names().len(), 23);
    assert_eq!(tracewise_tool_names().len(), 2);

    let mut names = rea;
    names.extend_from_slice(tracewise_tool_names());
    let session = BinarySession::new();
    for name in names {
        let result = call_tool_local(
            &session,
            CallToolRequestParam {
                name: name.to_string().into(),
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

#[test]
fn server_sources_have_no_stub_marker() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                assert!(
                    !text.to_ascii_lowercase().contains("not yet implemented"),
                    "{} still contains a stub marker",
                    path.display()
                );
            }
        }
    }
}
