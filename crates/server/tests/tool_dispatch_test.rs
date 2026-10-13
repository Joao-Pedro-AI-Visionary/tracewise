//! Every tool the server lists (170 REA tools and 2 tracewise tools) must reach a real handler.
//!
//! Empty input may fail validation. It must not report that the tool is unknown, that the
//! implementation is still missing, or that its port has not landed yet.

use rmcp::model::CallToolRequestParam;
use serde_json::json;
use tracewise_contracts::{
    all_tool_names, later_phase_tool_names, listed_tool_names, phase0_tool_names, phase1_tool_names,
    phase2_tool_names, tracewise_tool_names,
};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

/// Texts a tool must never answer with (compared case-insensitively): the stub marker of the early
/// phases and the marker of a track whose port had not landed.
const FORBIDDEN_MARKERS: [&str; 2] = ["not yet implemented", "pending port"];

#[tokio::test]
async fn every_tool_dispatches_to_an_implementation() {
    let names = listed_tool_names();
    assert_eq!(all_tool_names().len(), 50, "REA phases 0-2 expose 50 tools");
    assert_eq!(phase0_tool_names().len() + phase1_tool_names().len(), 27);
    assert_eq!(phase2_tool_names().len(), 23);
    assert_eq!(later_phase_tool_names().len(), 120, "REA phases 3-6 expose 120 tools");
    assert_eq!(tracewise_tool_names().len(), 2);
    assert_eq!(names.len(), 172, "tools/list advertises 170 REA tools and 2 tracewise tools");
    let mut unique = names.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), names.len(), "a tool name is listed twice");

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
        for marker in FORBIDDEN_MARKERS {
            assert!(!folded.contains(marker), "{name} answered with the marker {marker:?}: {message}");
        }
        assert!(
            !folded.contains("unknown tool"),
            "{name} did not dispatch to an implementation: {message}"
        );
    }
}

/// The marker check above only sees what a tool answers to empty input. The sources of every
/// crate must not carry the markers at all (a `pending` helper nothing calls would hide here).
#[test]
fn sources_have_no_stub_marker() {
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut stack: Vec<std::path::PathBuf> = std::fs::read_dir(&crates)
        .unwrap()
        .map(|entry| entry.unwrap().path().join("src"))
        .filter(|src| src.is_dir())
        .collect();
    assert!(stack.len() >= 8, "the workspace crates were not found under {}", crates.display());
    let mut scanned = 0;
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                scanned += 1;
                let text = std::fs::read_to_string(&path).unwrap().to_ascii_lowercase();
                for marker in FORBIDDEN_MARKERS {
                    assert!(!text.contains(marker), "{} still contains the marker {marker:?}", path.display());
                }
            }
        }
    }
    assert!(scanned > 100, "only {scanned} source files were scanned");
}
