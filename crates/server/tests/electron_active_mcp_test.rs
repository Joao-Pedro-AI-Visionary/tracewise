//! `capture_electron_scenario` through the MCP dispatcher (`call_tool_local`), configured the way
//! an operator configures the server: `TRACEWISE_ELECTRON_EXECUTABLE`, `TRACEWISE_ELECTRON_RUNTIME_DIR`
//! and the display in the process environment.
//!
//! Covered here (the provider itself is covered by `electron_active_test.rs`):
//! - the tool result is `structuredContent` that validates against the catalog `outputSchema`
//!   and the Evidence lands in the session ledger;
//! - the requested executable must be the configured one (`capability_unavailable` body);
//! - a request cancelled the way `handlers.rs` cancels it (`tokio::select!` dropping the future)
//!   leaves no Electron and no directory.
//!
//! The environment is set once, before any tool call, because the process environment is global;
//! the "no Electron configured" error with the variable unset is asserted by
//! `electron_tools_test.rs`, which never sets it.

mod electron_support;

use std::time::Duration;

use electron_support::*;
use rmcp::model::{CallToolRequestParam, CallToolResult};
use serde_json::{json, Value};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;



async fn call(session: &BinarySession, arguments: Value) -> CallToolResult {
    call_tool_local(
        session,
        CallToolRequestParam {
            name: "capture_electron_scenario".into(),
            arguments: Some(arguments.as_object().unwrap().clone()),
        },
    )
    .await
    .unwrap_or_else(|e| panic!("capture_electron_scenario: {e}"))
}

fn arguments(configured: &Configured, actions: Value) -> Value {
    let app = readiness_app();
    json!({
        "executable_path": configured.electron,
        "application_path": app.join("main.js"),
        "application_root": app,
        "args": base_args(),
        "actions": actions,
    })
}

#[tokio::test]
async fn the_tool_returns_validated_evidence_and_records_it() {
    let _serial = SERIAL.lock().await;
    let Some(configured) = configured() else { return };
    let session = BinarySession::new();
    let result = call(
        &session,
        arguments(
            configured,
            json!([
                { "step_id": "ipc", "kind": "click", "selector": "#run" },
                { "step_id": "settle", "kind": "wait", "duration_ms": 200 },
            ]),
        ),
    )
    .await;
    assert_ne!(result.is_error, Some(true), "{:?}", result.content);
    let structured = result.structured_content.expect("structuredContent");
    validate_schema(&structured);
    assert_eq!(structured["operation"], "capture_electron_scenario");
    assert_eq!(structured["parameters"]["actions"][0]["window_index"], 0, "REA default is applied");
    assert_eq!(structured["normalized_result"]["application"]["electron_version"], "44.7.0");
    assert!(structured["normalized_result"]["ipc"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["channel"] == "readiness:echo"));
    let evidence_id = structured["evidence_id"].as_str().expect("evidence_id");
    assert!(session.ledger.lock().unwrap().has(evidence_id), "the Evidence is in the session ledger");
    assert!(run_directories(&configured.runtime).is_empty(), "{:?}", run_directories(&configured.runtime));
}

#[tokio::test]
async fn another_executable_is_not_launched() {
    let _serial = SERIAL.lock().await; // the runtime directory is shared with the tests that launch Electron
    let Some(configured) = configured() else { return };
    let session = BinarySession::new();
    let mut request = arguments(configured, json!([]));
    request["executable_path"] = json!("/bin/sh");
    let result = call(&session, request).await;
    assert_eq!(result.is_error, Some(true));
    let text = result.content[0].as_text().expect("text content").text.clone();
    let body: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["error"]["code"], "capability_unavailable");
    assert_eq!(body["error"]["category"], "unsupported_provider");
    assert_eq!(body["error"]["details"]["provider_id"], "rea-playwright-electron-active");
    assert!(body["error"]["details"]["reason"]
        .as_str()
        .unwrap()
        .contains("not an Electron executable configured"));
    assert!(run_directories(&configured.runtime).is_empty());
}

#[tokio::test]
async fn cancelling_the_request_kills_electron_and_removes_the_profile() {
    let _serial = SERIAL.lock().await;
    let Some(configured) = configured() else { return };
    let session = BinarySession::new();
    let request = arguments(
        configured,
        json!([{ "step_id": "never", "kind": "click", "selector": "#does-not-exist" }]),
    );
    let needle = configured.runtime.to_string_lossy().to_string();
    // `dispatch_tool` cancels with `tokio::select! { _ = ct.cancelled() => .., res = execute_tool(..) => res }`:
    // the tool's future is dropped. The same shape, with the cancellation arriving once Electron is up.
    let cancelled = async {
        // Never block: the tool's future shares this thread and must keep running to start Electron.
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        while processes_with_cmdline(&needle).len() < 4 {
            assert!(std::time::Instant::now() < deadline, "Electron never started");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::sleep(Duration::from_secs(8)).await;
    };
    tokio::select! {
        _ = call(&session, request) => panic!("a click on a missing element never completes"),
        _ = cancelled => {}
    }
    assert!(run_directories(&configured.runtime).is_empty(), "{:?}", run_directories(&configured.runtime));
    assert!(wait_until(Duration::from_secs(3), || processes_with_cmdline(&needle).is_empty()), "{:?}", processes_with_cmdline(&needle));
    assert!(session.ledger.lock().unwrap().export().records.is_empty(), "a cancelled request records nothing");
}
