//! "Clone this feature", end to end, with a real Electron: capture the feature running, check a
//! reimplementation against the evidence, and see the reconstruction ledger take the runtime
//! observation as the original's authority.
//!
//! The application is `fixtures/electron/invoice_app` (window, preload, `invoice:export` IPC
//! handler). The reimplementation is `invoice_clone/invoice-core.js` (integer cents, same output) and
//! the wrong one is `invoice_regression/invoice-core.js` (total rounded to one decimal).
//!
//! 1. `capture_electron_scenario` launches the real Electron 44.7.0, clicks `#export` and observes
//!    the `invoice:export` handler: channel, direction, argument and result shapes, never the values.
//! 2. `capture_process_scenario` runs the original feature and both reimplementations under a PTY,
//!    `compare_process_captures` compares them.
//! 3. `verify_reconstruction`: the clone passes its claim, the regression fails it.
//! 4. `build_reconstruction_obligation_ledger`: a reviewed `electron/ipc` obligation bound to the
//!    clone. The active Electron capture is accepted as the original's `runtime` authority
//!    (`missing-original-case` / `static-only` disappear); without it they come back.
//!
//! Scope note: `analyze_javascript_application` and `trace_application_feature` are native and
//! can analyze this Electron app (`jsgraph_mcp_parity_test` traces `invoice_app` against the REA).
//! This test does not call them: the feature is followed through the runtime observation (step 1),
//! which is what the ledger consumes.
//!
//! Skips (printing why) without Electron or Xvfb, or without `node`; fails instead when
//! `TRACEWISE_REQUIRE_ORACLE=1`.

mod electron_support;

use electron_support::*;
use rmcp::model::CallToolRequestParam;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

async fn call(session: &BinarySession, name: &str, args: Value) -> Value {
    let result = call_tool_local(
        session,
        CallToolRequestParam {
            name: name.to_string().into(),
            arguments: Some(args.as_object().unwrap().clone()),
        },
    )
    .await
    .unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_ne!(result.is_error, Some(true), "{name}: {:?}", result.content);
    let structured = result.structured_content.expect("structuredContent");
    let tools = tracewise_contracts::all_tools_value();
    let tool = tools["tools"].as_array().unwrap().iter().find(|t| t["name"] == name).expect("tool in the catalog");
    jsonschema::validator_for(&tool["outputSchema"])
        .expect("schema")
        .validate(&structured)
        .unwrap_or_else(|error| panic!("{name} schema: {error}"));
    structured
}

fn node_is_available() -> bool {
    let found = std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .any(|dir| dir.join("node").is_file());
    if !found {
        skip_or_fail("node is not on PATH");
    }
    found
}

fn sha256_of(path: &std::path::Path) -> String {
    let bytes = std::fs::read(path).unwrap();
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn reviewed_obligation(capture_id: &str) -> Value {
    json!({
        "obligation_id": "reviewed.invoice-export",
        "obligation_version": 1,
        "title": "Export the invoice (invoice:export)",
        "application_layer": "electron",
        "family": "ipc",
        "target": { "artifact_sha256": null, "application_node_id": null, "semantic_node_id": null, "location": "invoice:export" },
        "required": true,
        "required_case_kinds": ["positive"],
        "required_original_authority": "runtime",
        "required_fixture_authority": "unit",
        "required_verifier_authority": "integration",
        "requires_parser_type": false,
        "dependency_obligation_ids": [],
        "residual_unknown_ids": [],
        "unavailable_authority": [],
        "required_next_evidence": [],
        "disposition": "active",
        "review_evidence_ids": [capture_id],
    })
}

fn manifest(owner: &std::path::Path, cases: Value) -> Value {
    json!({
        "bindings": [{
            "obligation_id": "reviewed.invoice-export",
            "owner": { "module_path": "invoice_clone/invoice-core.js", "symbol": "renderInvoice", "owner_sha256": sha256_of(owner) },
            "parser_type": null,
            "original_cases": cases,
            "fixtures": [],
            "verifier": null,
        }],
        "contradictions": [],
    })
}

fn codes(obligation: &Value) -> Vec<String> {
    obligation["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["code"].as_str().unwrap().to_string())
        .collect()
}

fn reviewed_of(ledger: &Value) -> Value {
    ledger["normalized_result"]["obligations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["obligation_id"] == "reviewed.invoice-export")
        .cloned()
        .expect("the reviewed obligation is in the ledger")
}

#[tokio::test]
async fn clone_this_feature_with_a_real_electron() {
    let _serial = SERIAL.lock().await;
    if !node_is_available() {
        return;
    }
    let Some(configured) = configured() else { return };
    let session = BinarySession::new();
    let fixtures = repo_root().join("fixtures/electron");
    let app = fixtures.join("invoice_app");

    // 1. The feature, running.
    let capture = call(
        &session,
        "capture_electron_scenario",
        json!({
            "executable_path": configured.electron,
            "application_path": app.join("main.js"),
            "application_root": app,
            "args": base_args(),
            "actions": [
                { "step_id": "export", "kind": "click", "selector": "#export" },
                { "step_id": "settle", "kind": "wait", "duration_ms": 300 },
            ],
        }),
    )
    .await;
    let capture_id = capture["evidence_id"].as_str().unwrap().to_string();
    let result = &capture["normalized_result"];
    assert!(result["actions"].as_array().unwrap().iter().all(|a| a["status"] == "completed"), "{}", result["actions"]);
    let export = result["ipc"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .position(|e| e["kind"] == "main-handler-invocation" && e["channel"] == "invoice:export")
        .unwrap_or_else(|| panic!("the invoice:export handler was not observed: {}", result["ipc"]));
    let event = &result["ipc"]["events"][export];
    assert_eq!(event["direction"], "renderer-to-main");
    assert_eq!(event["argument_shapes"], json!(["object"]), "payload values are never retained");
    assert_eq!(event["result_shape"], "object");
    assert!(
        !capture.to_string().contains("9.75"),
        "the exported total is a value, not a shape: it must not be in the Evidence"
    );
    assert!(run_directories(&configured.runtime).is_empty(), "the run directory (and the PDF the app wrote there) is gone");

    // 2. The original feature and its reimplementations, as processes.
    let mut runs = Vec::new();
    for dir in ["invoice_app", "invoice_clone", "invoice_regression"] {
        runs.push(
            call(
                &session,
                "capture_process_scenario",
                json!({
                    "executable": "node",
                    "arguments": [format!("{dir}/invoice-core.js")],
                    "working_directory": fixtures,
                    "normalization": { "time_bucket_ms": 1000 },
                }),
            )
            .await,
        );
    }
    let same = call(&session, "compare_process_captures", json!({ "left": runs[0], "right": runs[1] })).await;
    let different = call(&session, "compare_process_captures", json!({ "left": runs[0], "right": runs[2] })).await;
    assert_eq!(same["normalized_result"]["terminal"], "unchanged");
    assert_eq!(different["normalized_result"]["terminal"], "changed");
    assert_eq!(different["normalized_result"]["first_divergence"]["left"]["data"], "invoice total: 9.75\r\n");
    assert_eq!(different["normalized_result"]["first_divergence"]["right"]["data"], "invoice total: 9.8\r\n");

    // 3. Verification against the evidence.
    let claim = |comparison: &Value| {
        json!({ "specification": { "name": "Invoice feature reconstruction", "claims": [{
            "claim_id": "invoice.output", "title": "Invoice total output", "kind": "behavioral",
            "dimension": "terminal", "comparison_evidence_id": comparison["evidence_id"],
        }]}})
    };
    let verified = call(&session, "verify_reconstruction", claim(&same)).await;
    assert_eq!(verified["normalized_result"]["status"], "pass", "{}", verified["normalized_result"]);
    let rejected = call(&session, "verify_reconstruction", claim(&different)).await;
    assert_eq!(rejected["normalized_result"]["status"], "fail", "{}", rejected["normalized_result"]);

    // 4. The ledger takes the real Electron observation as the original's runtime authority.
    let bundle = call(&session, "get_evidence_bundle", json!({})).await["result"].clone();
    let owner = fixtures.join("invoice_clone/invoice-core.js");
    let observed = json!([{ "kind": "positive", "evidence_id": capture_id, "location": format!("/normalized_result/ipc/events/{export}") }]);
    let with_capture = call(
        &session,
        "build_reconstruction_obligation_ledger",
        json!({
            "evidence_bundle": bundle,
            "reviewed_obligations": [reviewed_obligation(&capture_id)],
            "manifest": manifest(&owner, observed),
        }),
    )
    .await;
    let obligation = reviewed_of(&with_capture);
    let found = codes(&obligation);
    assert_eq!(obligation["status"], "implemented", "bound to the clone: {found:?}");
    for gone in ["missing-original-case", "weak-original-case-authority", "static-only", "missing-owner"] {
        assert!(!found.contains(&gone.to_string()), "{gone} must not remain once the Electron capture is the original case: {found:?}");
    }
    // What is still open is exactly the proof side, which no tool in the catalog can produce.
    assert!(found.contains(&"missing-verifier".to_string()) && found.contains(&"missing-case".to_string()), "{found:?}");

    let without_capture = call(
        &session,
        "build_reconstruction_obligation_ledger",
        json!({
            "evidence_bundle": bundle,
            "reviewed_obligations": [reviewed_obligation(&capture_id)],
            "manifest": manifest(&owner, json!([])),
        }),
    )
    .await;
    let found = codes(&reviewed_of(&without_capture));
    assert!(found.contains(&"missing-original-case".to_string()), "no original case without the capture: {found:?}");
}
