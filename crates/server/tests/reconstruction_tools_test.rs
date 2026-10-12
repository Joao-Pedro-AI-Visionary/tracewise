//! Reconstruction ledger, coverage, verification, and investigation workflows
//! against ground truth from the ORIGINAL REA MCP server.
//!
//! Every oracle fixture comes from `fixtures/js/reconstruction_oracle_chain.py`,
//! which chains real REA tools (inspect_artifact, compare_artifacts,
//! capture_process_scenario, compare_process_captures,
//! analyze_javascript_application, export_evidence_bundle) in one REA session
//! and then calls the tool under test. The REA session bundle exported right
//! before each call is imported here, so both sides see the same records and
//! residual unknowns.
//!
//! Ignored fields: none. Outputs carry no paths or timestamps of their own
//! (subjects are null). `evaluate_reconstruction_coverage` depends on the wall
//! clock only through verifier `max_age_ms`; the fixture uses ten-year windows
//! anchored in 2026, so the comparison is exact until 2036.

use rmcp::model::{CallToolRequestParam, CallToolResult};
use rmcp::ErrorData as McpError;
use serde_json::{json, Value};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

const FIXTURES: &str = "/workspace/tracewise/fixtures/js";

fn fixture(name: &str) -> Value {
    let path = format!("{FIXTURES}/{name}");
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}")))
        .expect("fixture json")
}

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

async fn raw_call(session: &BinarySession, name: &str, args: Value) -> Result<CallToolResult, McpError> {
    call_tool_local(
        session,
        CallToolRequestParam { name: name.to_string().into(), arguments: args.as_object().cloned() },
    )
    .await
}

async fn call(session: &BinarySession, name: &str, args: Value) -> Value {
    let result = raw_call(session, name, args).await.unwrap_or_else(|error| panic!("{name}: {error}"));
    assert!(result.is_error != Some(true), "{name} isError");
    result.structured_content.expect("structuredContent")
}

async fn session_with(bundle: &str) -> BinarySession {
    let session = BinarySession::new();
    call(&session, "import_evidence_bundle", json!({ "path": format!("{FIXTURES}/{bundle}") })).await;
    session
}

fn assert_matches(tool: &str, actual: &Value, oracle: &Value) {
    validate_schema(tool, actual);
    let expected = &oracle["structuredContent"];
    assert!(expected.is_object(), "oracle for {tool} has no structuredContent");
    if actual != expected {
        panic!(
            "{tool} differs from REA oracle\nactual: {}\nexpected: {}",
            serde_json::to_string_pretty(actual).unwrap(),
            serde_json::to_string_pretty(expected).unwrap()
        );
    }
}

#[tokio::test]
async fn verify_reconstruction_approves_rebuilt_artifact() {
    let session = session_with("reconstruction_verify_pass_bundle.json").await;
    let actual = call(&session, "verify_reconstruction", fixture("reconstruction_verify_pass_input.json")).await;
    assert_eq!(actual["normalized_result"]["status"], "pass");
    assert_matches("verify_reconstruction", &actual, &fixture("oracle_verify_reconstruction.json"));
}

#[tokio::test]
async fn verify_reconstruction_rejects_regression() {
    let session = session_with("reconstruction_investigation_bundle.json").await;
    let actual = call(&session, "verify_reconstruction", fixture("reconstruction_verify_fail_input.json")).await;
    assert_eq!(actual["normalized_result"]["status"], "fail");
    assert_matches("verify_reconstruction", &actual, &fixture("oracle_verify_reconstruction_fail.json"));
}

#[tokio::test]
async fn find_changed_behavior_matches_oracle() {
    let comparisons = fixture("reconstruction_investigation_comparisons.json");
    let oracle = fixture("oracle_find_changed_behavior.json");
    let session = session_with("reconstruction_investigation_bundle.json").await;
    let inline = call(
        &session,
        "find_changed_behavior",
        json!({ "comparisons": [comparisons["artifact_changed"], comparisons["process_regression"]] }),
    )
    .await;
    assert_matches("find_changed_behavior", &inline, &oracle);

    // Retained-evidence references resolve from the session ledger to the same result.
    let session = session_with("reconstruction_investigation_bundle.json").await;
    let reference = |key: &str| json!({ "kind": "retained-evidence", "evidence_id": comparisons[key]["evidence_id"] });
    let retained = call(
        &session,
        "find_changed_behavior",
        json!({ "comparisons": [reference("artifact_changed"), reference("process_regression")] }),
    )
    .await;
    assert_matches("find_changed_behavior", &retained, &oracle);
}

#[tokio::test]
async fn find_changed_behavior_rejects_dangling_links_like_rea() {
    let oracle = fixture("oracle_find_changed_behavior_dangling.json");
    assert_eq!(oracle["isError"], true);
    assert!(oracle["content"][0]["text"].as_str().unwrap().contains("dangling Evidence link"));
    let session = BinarySession::new();
    let result = raw_call(
        &session,
        "find_changed_behavior",
        json!({ "comparisons": [fixture("investigation_function_comparison.json")] }),
    )
    .await;
    let message = match result {
        Err(error) => error.message.to_string(),
        Ok(result) => panic!("expected an error, got {result:?}"),
    };
    assert!(message.contains("dangling Evidence link"), "{message}");
}

#[tokio::test]
async fn correlate_static_and_runtime_matches_oracle() {
    let session = session_with("reconstruction_investigation_bundle.json").await;
    let actual = call(&session, "correlate_static_and_runtime", fixture("reconstruction_correlate_input.json")).await;
    assert_matches(
        "correlate_static_and_runtime",
        &actual,
        &fixture("oracle_correlate_static_and_runtime.json"),
    );
}

#[tokio::test]
async fn evaluate_reconstruction_coverage_matches_oracle() {
    let session = BinarySession::new();
    let coverage = fixture("reconstruction_coverage_input.json");
    let oracle = fixture("oracle_evaluate_reconstruction_coverage.json");
    for case in oracle["cases"].as_array().unwrap() {
        let actual = call(
            &session,
            "evaluate_reconstruction_coverage",
            json!({ "coverage": coverage, "boundary_id": case["boundary_id"] }),
        )
        .await;
        assert_matches("evaluate_reconstruction_coverage", &actual, &case["result"]);
    }
}

#[tokio::test]
async fn build_reconstruction_obligation_ledger_matches_oracle() {
    let session = BinarySession::new();
    let input = fixture("reconstruction_ledger_input.json");
    let actual = call(
        &session,
        "build_reconstruction_obligation_ledger",
        json!({
            "evidence_bundle": fixture("reconstruction_ledger_bundle.json"),
            "reviewed_obligations": input["reviewed_obligations"],
            "manifest": input["manifest"],
        }),
    )
    .await;
    assert_matches(
        "build_reconstruction_obligation_ledger",
        &actual,
        &fixture("oracle_build_reconstruction_obligation_ledger.json"),
    );
}

#[tokio::test]
async fn build_reconstruction_obligation_ledger_empty_bundle_matches_oracle() {
    let session = BinarySession::new();
    let actual = call(
        &session,
        "build_reconstruction_obligation_ledger",
        json!({
            "evidence_bundle": { "artifacts": [], "providers": [], "environments": [], "scenarios": [],
                                 "captures": [], "unknowns": [], "records": [] },
            "reviewed_obligations": [],
            "manifest": { "bindings": [], "contradictions": [] },
        }),
    )
    .await;
    assert_matches(
        "build_reconstruction_obligation_ledger",
        &actual,
        &fixture("oracle_build_reconstruction_obligation_ledger_empty.json"),
    );
}
