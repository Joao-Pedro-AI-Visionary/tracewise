//! `open_binary` on app bundles and directories against the ORIGINAL REA (Linux).
//!
//! `fixtures/integration/open_binary_oracle.json` holds REA's answer (`isError` plus the complete
//! result, success or error body) for each target of `open_binary_cases.json`, recorded by
//! `fixtures/integration/gen_open_binary_oracle.py` from the same fixtures
//! (`fixtures/native_static`). The checkout path is stored as `$ROOT` and replaced by this
//! checkout's path; nothing else is normalized or ignored, so the comparison covers the resolved
//! program file (path, format, kind, sha256, architecture), the ZIP package suffixes, and the
//! `target_unavailable` bodies for a directory that is not an app, an app whose layout cannot be
//! resolved, and the rest.
//!
//! One known divergence, pinned here instead of hidden: REA's MCP route refuses a directory that
//! is not an app (`directory_requires_file`), while tracewise still opens it as a directory target,
//! because the Phase 2 artifact scenarios (`artifact_tools_test::inspect_directory_matches_oracle`)
//! inventory directories through the session. Those cases carry `"tracewise": "directory-target"`.
//!
//! Beyond the answer, the session must behave the way REA's does after the call: the target is the
//! bundle's program file, the artifact tools still inventory the bundle, a failed open leaves the
//! previous target alone, and closing or opening something else forgets the bundle.

use std::path::{Path, PathBuf};

use rmcp::model::{CallToolRequestParam, CallToolResult};
use serde_json::{json, Value};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("repo root")
}

fn fixtures() -> PathBuf {
    root().join("fixtures/native_static")
}

async fn call(session: &BinarySession, tool: &str, arguments: Value) -> CallToolResult {
    call_tool_local(
        session,
        CallToolRequestParam { name: tool.to_string().into(), arguments: Some(arguments.as_object().cloned().unwrap_or_default()) },
    )
    .await
    .unwrap_or_else(|e| panic!("{tool}: protocol error {e:?}"))
}

/// What the client sees, in the shape the oracle file stores: `isError` plus the structured
/// result or the error text.
fn answer(result: &CallToolResult) -> Value {
    if result.is_error == Some(true) {
        let text = result.content.iter().find_map(|c| c.as_text().map(|t| t.text.clone())).expect("error text");
        json!({ "isError": true, "text": serde_json::from_str::<Value>(&text).unwrap_or(Value::String(text)) })
    } else {
        json!({ "isError": false, "structuredContent": result.structured_content.clone().expect("structuredContent") })
    }
}

fn expected(entry: &Value) -> Value {
    let result = &entry["result"];
    if result["isError"] == json!(true) {
        let text = result["content"][0]["text"].as_str().expect("error text");
        json!({ "isError": true, "text": serde_json::from_str::<Value>(text).unwrap_or(Value::String(text.to_string())) })
    } else {
        json!({ "isError": false, "structuredContent": result["structuredContent"] })
    }
}

#[tokio::test]
async fn open_binary_matches_rea_on_bundles_and_directories() {
    let cases: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(root().join("fixtures/integration/open_binary_cases.json")).unwrap()).unwrap();
    let oracle: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(root().join("fixtures/integration/open_binary_oracle.json")).unwrap()).unwrap();
    assert_eq!(cases.len(), oracle.len(), "one oracle answer per case");
    let (root_text, fixtures_text) = (root().to_string_lossy().into_owned(), fixtures().to_string_lossy().into_owned());
    let mut failures = Vec::new();
    let (mut opened, mut refused, mut diverging) = (0, 0, 0);
    for (case, entry) in cases.iter().zip(&oracle) {
        let id = case["id"].as_str().unwrap();
        assert_eq!(entry["id"], case["id"]);
        let path = case["path"].as_str().unwrap().replace("$FIX", &fixtures_text);
        let session = BinarySession::new();
        let got = answer(&call(&session, "open_binary", json!({ "path": path })).await);
        let want: Value = serde_json::from_str(&expected(entry).to_string().replace("$ROOT", &root_text)).unwrap();
        if case["tracewise"] == "directory-target" {
            // The divergence: REA refuses with `directory_requires_file`, tracewise opens the directory.
            if want["text"]["error"]["details"]["constraint"] != "directory_requires_file" {
                failures.push(format!("{id}: REA no longer refuses this directory: {want}"));
            }
            let result = &got["structuredContent"]["result"];
            if got["isError"] != false || result["format"] != "directory" || result["path"] != json!(path) {
                failures.push(format!("{id}: tracewise should open the directory as a directory target: {got}"));
            }
            diverging += 1;
            continue;
        }
        if got != want {
            failures.push(format!("{id}:\n  rea:       {want}\n  tracewise: {got}"));
        }
        if want["isError"] == json!(true) {
            refused += 1;
        } else {
            opened += 1;
        }
    }
    assert!(failures.is_empty(), "{} of {} targets differ:\n{}", failures.len(), cases.len(), failures.join("\n"));
    assert_eq!((opened, refused, diverging), (13, 1, 3), "the oracle answers a different mix than the test expects");
}

fn session_path(status: &Value) -> Option<String> {
    status["result"]["path"].as_str().map(str::to_string)
}

#[tokio::test]
async fn the_session_holds_the_program_file_and_remembers_the_bundle() {
    let session = BinarySession::new();
    let bundle = fixtures().join("apple/Mac.app");
    let program = bundle.join("Contents/MacOS/Mac");
    let opened = call(&session, "open_binary", json!({ "path": bundle.to_string_lossy() })).await;
    assert_ne!(opened.is_error, Some(true));

    // binary_session reports the program file, as REA does.
    let status = call(&session, "binary_session", json!({})).await;
    let status = status.structured_content.unwrap();
    assert_eq!(session_path(&status).as_deref(), program.to_str());
    assert_eq!(status["result"]["format"], "mach-o");

    // The artifact tools still work on the bundle, not on the lone executable.
    let inspected = call(&session, "inspect_artifact", json!({})).await.structured_content.unwrap();
    assert_eq!(inspected["subject"]["local_path"], json!(bundle.to_string_lossy()));
    assert_eq!(inspected["subject"]["format"], "directory");

    // A failed open does not disturb the target in place.
    let refused = call(&session, "open_binary", json!({ "path": fixtures().join("apple/Upper.app").to_string_lossy() })).await;
    assert_eq!(refused.is_error, Some(true));
    let status = call(&session, "binary_session", json!({})).await.structured_content.unwrap();
    assert_eq!(session_path(&status).as_deref(), program.to_str());
    let again = call(&session, "inspect_artifact", json!({})).await.structured_content.unwrap();
    assert_eq!(again["subject"]["local_path"], json!(bundle.to_string_lossy()), "the bundle is still remembered");

    // Opening a plain file forgets the bundle.
    let ipa = fixtures().join("apple/Fixture.ipa");
    call(&session, "open_binary", json!({ "path": ipa.to_string_lossy() })).await;
    let inspected = call(&session, "inspect_artifact", json!({})).await.structured_content.unwrap();
    assert_eq!(inspected["subject"]["local_path"], json!(ipa.to_string_lossy()));
    assert!(session.source_bundle.lock().unwrap().is_none());

    // Closing forgets it too.
    call(&session, "open_binary", json!({ "path": bundle.to_string_lossy() })).await;
    assert!(session.source_bundle.lock().unwrap().is_some());
    call(&session, "close_binary", json!({})).await;
    assert!(session.source_bundle.lock().unwrap().is_none());
}
