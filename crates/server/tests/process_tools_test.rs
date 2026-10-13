//! `capture_process_scenario` and `compare_process_captures` against the
//! ORIGINAL REA oracle (`fixtures/rea_oracle.py`).
//!
//! Comparison is deterministic: the tests feed the oracle's own capture
//! Evidence (`oracle_capture_process_scenario.json`,
//! `process_capture_world_oracle.json`) with the same arguments the oracle
//! received and require the whole `structuredContent` to be equal — no field
//! ignored — for a plain comparison, a `finite_traces` spec and a
//! `partial_order` spec (`process_trace_specs.json`).
//!
//! The live capture runs `/bin/sh -c 'printf hello'` in `/workspace/tracewise`,
//! the scenario the oracle captured. Ignored fields, all time-dependent:
//! - `evidence_id` (hashes every field below)
//! - `normalized_result.manifest.started_at` / `completed_at` (wall clock)
//! - `normalized_result.frames[].at_ms` and `rendered_frames[].at_ms`
//!   (bucketed launch-to-output latency; node needs ~10 ms more than Rust)
//! - `normalized_result.settlement.elapsed_ms` (settlement polling time)
//! - `normalized_result.filesystem_checkpoints[1].at_ms` (time of the final snapshot)
//! - `manifest.executable_sha256`, `manifest.selected_executable_sha256`,
//!   `manifest.scenario.executable_sha256` and `manifest.full_scenario_sha256`:
//!   they digest the host `/bin/sh`, which differs between hosts. Ours must
//!   equal the real `/bin/sh` digest; the oracle's is the oracle host's.
//!
//! Everything else — scenario/contract/normalization commitments and their
//! SHA-256s, exit, rendered lines and serialized xterm
//! state, event journal order, truncation accounting, limitations and
//! residual unknowns — must match the oracle exactly.

use rmcp::model::{CallToolRequestParam, CallToolResult};
use serde_json::{json, Value};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

const FIXTURES: &str = "/workspace/tracewise/fixtures/js";

fn validate_schema(tool_name: &str, structured: &Value) {
    let tools = tracewise_contracts::phase2_tools_value();
    let tool = tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == tool_name)
        .expect("tool in phase2");
    let validator = jsonschema::validator_for(&tool["outputSchema"]).expect("schema");
    validator
        .validate(structured)
        .unwrap_or_else(|error| panic!("{tool_name} schema: {error}"));
}

fn fixture(name: &str) -> Value {
    let text = std::fs::read_to_string(format!("{FIXTURES}/{name}.json")).expect("fixture");
    serde_json::from_str(&text).expect("fixture json")
}

fn oracle(name: &str) -> Value {
    fixture(name)["structuredContent"].clone()
}

async fn call_raw(session: &BinarySession, name: &str, args: Value) -> CallToolResult {
    call_tool_local(
        session,
        CallToolRequestParam { name: name.to_string().into(), arguments: Some(args.as_object().unwrap().clone()) },
    )
    .await
    .unwrap_or_else(|error| panic!("{name}: {error}"))
}

async fn call(session: &BinarySession, name: &str, args: Value) -> Value {
    let result = call_raw(session, name, args).await;
    assert_ne!(result.is_error, Some(true), "{name}: {:?}", result.content);
    let structured = result.structured_content.expect("structuredContent");
    validate_schema(name, &structured);
    structured
}

fn error_body(result: &CallToolResult) -> Value {
    assert_eq!(result.is_error, Some(true), "expected isError: {:?}", result.structured_content);
    let text = result.content[0].as_text().expect("text content").text.clone();
    serde_json::from_str(&text).expect("error envelope json")
}

fn strip_time_fields(evidence: &mut Value) {
    evidence["evidence_id"] = Value::Null;
    let result = &mut evidence["normalized_result"];
    result["manifest"]["started_at"] = Value::Null;
    result["manifest"]["completed_at"] = Value::Null;
    for key in ["frames", "rendered_frames"] {
        for frame in result[key].as_array_mut().unwrap() {
            frame["at_ms"] = Value::Null;
        }
    }
    result["settlement"]["elapsed_ms"] = Value::Null;
    result["filesystem_checkpoints"][1]["at_ms"] = Value::Null;
}

fn hello_args() -> Value {
    json!({
        "executable": "/bin/sh",
        "arguments": ["-c", "printf hello"],
        "working_directory": "/workspace/tracewise",
    })
}

#[tokio::test]
async fn capture_matches_rea_oracle_except_time_fields() {
    let session = BinarySession::new();
    let mut ours = call(&session, "capture_process_scenario", hello_args()).await;
    let mut expected = oracle("oracle_capture_process_scenario");
    validate_schema("capture_process_scenario", &expected);
    strip_time_fields(&mut ours);
    strip_time_fields(&mut expected);
    let host_sh = {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(std::fs::canonicalize("/bin/sh").unwrap()).unwrap();
        Value::String(hex::encode(Sha256::digest(bytes)))
    };
    let manifest = &ours["normalized_result"]["manifest"];
    assert_eq!(manifest["executable_sha256"], host_sh);
    assert_eq!(manifest["selected_executable_sha256"], host_sh);
    assert_eq!(manifest["scenario"]["executable_sha256"], host_sh);
    for evidence in [&mut ours, &mut expected] {
        let manifest = &mut evidence["normalized_result"]["manifest"];
        manifest["executable_sha256"] = Value::Null;
        manifest["selected_executable_sha256"] = Value::Null;
        manifest["scenario"]["executable_sha256"] = Value::Null;
        manifest["full_scenario_sha256"] = Value::Null;
    }
    assert_eq!(ours, expected);
}

#[tokio::test]
async fn compare_matches_rea_oracle_exactly() {
    let session = BinarySession::new();
    let left = oracle("oracle_capture_process_scenario");
    let right = oracle("process_capture_world_oracle");
    let specs = fixture("process_trace_specs");
    for (args, expected) in [
        (json!({"left": left, "right": right}), "oracle_compare_process_captures"),
        (json!({"left": left, "right": right, "trace_spec": specs["finite"]}), "process_compare_finite_trace_oracle"),
        (json!({"left": left, "right": right, "trace_spec": specs["partial"]}), "process_compare_partial_trace_oracle"),
    ] {
        let ours = call(&session, "compare_process_captures", args).await;
        assert_eq!(ours, oracle(expected), "{expected}");
    }
}

#[tokio::test]
async fn live_captures_compare_and_reject_bad_inputs() {
    let session = BinarySession::new();
    let first = call(&session, "capture_process_scenario", hello_args()).await;
    let world = call(
        &session,
        "capture_process_scenario",
        json!({
            "executable": "/bin/sh",
            "arguments": ["-c", "printf world; exit 3"],
            "working_directory": "/workspace/tracewise",
        }),
    )
    .await;
    assert_eq!(world["normalized_result"]["exit"], json!({"code": 3, "signal": 0, "reason": "exited"}));
    let comparison = call(&session, "compare_process_captures", json!({"left": first, "right": world})).await;
    let result = &comparison["normalized_result"];
    assert_eq!(result["status"], "changed");
    assert_eq!(result["terminal"], "changed");
    assert_eq!(result["exit"], "changed");
    assert_eq!(result["first_divergence"]["dimension"], "terminal");
    assert_eq!(comparison["evidence_links"], json!([first["evidence_id"], world["evidence_id"]]));

    // Tampered Evidence is an integrity failure, as in REA.
    let mut tampered = first.clone();
    tampered["normalized_result"]["frames"][0]["data"] = json!("x");
    let body = error_body(&call_raw(&session, "compare_process_captures", json!({"left": tampered, "right": world})).await);
    assert_eq!(body["error"]["code"], "evidence_integrity_mismatch");

    // A different comparison contract (terminal shape) is rejected by name.
    let wide = call(
        &session,
        "capture_process_scenario",
        json!({"executable": "/bin/true", "working_directory": "/workspace/tracewise", "terminal": {"columns": 100, "rows": 24, "scrollback": 1000}}),
    )
    .await;
    let body = error_body(&call_raw(&session, "compare_process_captures", json!({"left": first, "right": wide})).await);
    assert_eq!(body["error"]["code"], "invalid_request");
    let message = body["error"]["details"]["issues"][0]["message"].as_str().unwrap();
    assert!(message.contains("these scenario fields differ: terminal."), "{message}");

    // Same failure text as the oracle for an unresolvable command.
    let body = error_body(&call_raw(&session, "capture_process_scenario", json!({"executable": "nonexistent-xyz"})).await);
    assert_eq!(body["error"]["code"], "process_capture_failed");
    assert_eq!(body["error"]["message"], "executable could not be resolved: nonexistent-xyz");
}

#[tokio::test]
async fn scripted_events_timeout_and_filesystem_effects() {
    let root = tempfile_root();
    std::fs::write(root.join("keep.txt"), "base\n").unwrap();
    let session = BinarySession::new();
    let capture = call(
        &session,
        "capture_process_scenario",
        json!({
            "executable": "sh",
            "arguments": ["-c", "read x; echo \"got $x\"; echo new > new.txt; sleep 5"],
            "working_directory": root.to_string_lossy(),
            "filesystem_observation_paths": ["."],
            "events": [{"at_ms": 50, "type": "input", "data": "secret\r", "sensitive": true}],
            "timeout_ms": 700,
            "terminal": {"columns": 40, "rows": 5, "scrollback": 10},
        }),
    )
    .await;
    let result = &capture["normalized_result"];
    assert_eq!(result["exit"], json!({"code": null, "signal": 9, "reason": "timeout"}));
    assert_eq!(result["interaction_events"][0]["data"], "<redacted-input:7-bytes>");
    assert_eq!(result["manifest"]["comparison_contract"]["events"][0]["data"], "<redacted-input>");
    let serialized = serde_json::to_string(&capture).unwrap();
    assert!(!serialized.contains("secret\\r\"") && serialized.contains("got secret"));
    let effects: Vec<(String, String)> = result["filesystem_effects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["path"].as_str().unwrap().to_string(), e["status"].as_str().unwrap().to_string()))
        .collect();
    assert!(effects.contains(&("root_0:keep.txt".into(), "unchanged".into())), "{effects:?}");
    assert!(effects.contains(&("root_0:new.txt".into(), "created".into())), "{effects:?}");
    assert!(result["residual_unknowns"].as_array().unwrap().iter().any(|u| u["scope"] == "interaction"));
    let samples = result["process_samples"].as_array().unwrap();
    assert!(samples.iter().any(|s| s["command"] == "sleep 5"), "{samples:?}");
    let _ = std::fs::remove_dir_all(&root);
}

fn tempfile_root() -> std::path::PathBuf {
    let root = std::path::PathBuf::from(format!(
        "/workspace/tracewise/target/process-tools-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}
