//! Application feature trace, version comparison, and export-shape comparison.
//!
//! Oracle inputs are the Evidence objects produced by this port's
//! `analyze_javascript_application` on `fixtures/js/app` and `fixtures/js/app-v2`.
//! The original REA tools consume those same objects. Comparison results have a
//! null subject and no timestamps. No path or time field is ignored.

use rmcp::model::CallToolRequestParam;
use serde_json::{json, Value};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

fn validate_schema(tool_name: &str, structured: &Value) {
    let tools_val = tracewise_contracts::phase2_tools_value();
    let tool_def = tools_val["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == tool_name)
        .expect("tool in phase2");
    let validator = jsonschema::validator_for(&tool_def["outputSchema"]).expect("schema");
    validator
        .validate(structured)
        .unwrap_or_else(|error| panic!("{tool_name} schema: {error}"));
}

async fn call(session: &BinarySession, name: &str, args: Value) -> Value {
    let result = call_tool_local(
        session,
        CallToolRequestParam {
            name: name.to_string().into(),
            arguments: args.as_object().cloned(),
        },
    )
    .await;
    let result = result.unwrap_or_else(|error| panic!("{name}: {error}"));
    assert!(result.is_error.is_none() || result.is_error == Some(false), "{name} isError");
    result.structured_content.expect("structuredContent")
}

async fn analyze(session: &BinarySession, path: &str) -> Value {
    call(
        session,
        "analyze_javascript_application",
        json!({
            "input_path": path,
            "format": "directory",
            "integrity_policy": "fail",
        }),
    )
    .await
}

fn assert_oracle(tool_name: &str, structured: &Value) {
    let path = format!("/workspace/tracewise/fixtures/js/oracle_{tool_name}.json");
    let oracle: Value = serde_json::from_str(
        &std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {path}: {error}")),
    )
    .expect("oracle json");
    assert_eq!(structured, &oracle["structuredContent"]);
}

#[tokio::test]
async fn trace_application_feature_matches_oracle() {
    let session = BinarySession::new();
    let application = analyze(&session, "/workspace/tracewise/fixtures/js/app").await;
    let structured = call(
        &session,
        "trace_application_feature",
        json!({
            "application": application,
            "seed": { "kind": "string", "value": "total" },
            "direction": "both",
        }),
    )
    .await;
    validate_schema("trace_application_feature", &structured);
    assert_oracle("trace_application_feature", &structured);
}

#[tokio::test]
async fn compare_application_versions_matches_oracle() {
    let session = BinarySession::new();
    let left = analyze(&session, "/workspace/tracewise/fixtures/js/app").await;
    let right = analyze(&session, "/workspace/tracewise/fixtures/js/app-v2").await;
    let structured = call(
        &session,
        "compare_application_versions",
        json!({
            "left": left,
            "right": right,
        }),
    )
    .await;
    validate_schema("compare_application_versions", &structured);
    assert_oracle("compare_application_versions", &structured);
}

#[tokio::test]
async fn compare_javascript_export_shapes_matches_oracle() {
    let session = BinarySession::new();
    let left = analyze(&session, "/workspace/tracewise/fixtures/js/app").await;
    let right = analyze(&session, "/workspace/tracewise/fixtures/js/app-v2").await;
    let structured = call(
        &session,
        "compare_javascript_export_shapes",
        json!({
            "left": left,
            "right": right,
            "left_module_path": "src/math.js",
            "left_export_name": "add",
            "right_module_path": "src/math.js",
            "right_export_name": "add",
        }),
    )
    .await;
    validate_schema("compare_javascript_export_shapes", &structured);
    assert_oracle("compare_javascript_export_shapes", &structured);
}
