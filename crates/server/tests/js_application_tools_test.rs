//! JavaScript application analysis and semantic trace oracle parity.
//!
//! Ignored volatile fields when comparing to REA oracles:
//! - `evidence_id` (content-addressed per observation envelope)
//! - `subject.local_path` (host-specific absolute path; analysis only)
//! - `normalized_result.input_path` (same reason; analysis only)
//!
//! `trace_javascript_semantics` has a null subject, so the path fields above
//! are absent. No timestamp is part of the trace. The embedded
//! `parameters.application_evidence_id` and `evidence_links` are compared.

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

fn strip_volatile(mut value: Value) -> Value {
    if let Some(obj) = value.as_object_mut() {
        obj.remove("evidence_id");
        if let Some(subject) = obj.get_mut("subject") {
            if let Some(s) = subject.as_object_mut() {
                s.insert("local_path".to_string(), json!(""));
            }
        }
        if let Some(nr) = obj.get_mut("normalized_result") {
            if let Some(n) = nr.as_object_mut() {
                n.insert("input_path".to_string(), json!(""));
            }
        }
    }
    value
}

#[tokio::test]
async fn analyze_javascript_application_matches_oracle() {
    let session = BinarySession::new();
    let result = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "analyze_javascript_application".into(),
            arguments: Some(
                json!({
                    "input_path": "/workspace/tracewise/fixtures/js/app",
                    "format": "directory",
                    "integrity_policy": "fail",
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("analyze");
    assert!(result.is_error.is_none() || result.is_error == Some(false));
    let structured = result.structured_content.expect("structuredContent");
    validate_schema("analyze_javascript_application", &structured);
    let oracle: Value = serde_json::from_str(
        &std::fs::read_to_string(
            "/workspace/tracewise/fixtures/js/oracle_analyze_javascript_application.json",
        )
        .expect("oracle"),
    )
    .expect("oracle json");
    assert_eq!(
        strip_volatile(structured),
        strip_volatile(oracle["structuredContent"].clone())
    );
}

#[tokio::test]
async fn trace_javascript_semantics_matches_oracle() {
    let session = BinarySession::new();
    let analyze = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "analyze_javascript_application".into(),
            arguments: Some(
                json!({
                    "input_path": "/workspace/tracewise/fixtures/js/app",
                    "format": "directory",
                    "integrity_policy": "fail",
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("analyze");
    let application = analyze.structured_content.expect("application");
    let oracle: Value = serde_json::from_str(
        &std::fs::read_to_string(
            "/workspace/tracewise/fixtures/js/oracle_trace_javascript_semantics.json",
        )
        .expect("oracle"),
    )
    .expect("oracle json");
    let query = oracle["structuredContent"]["parameters"]["query"].clone();
    let result = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "trace_javascript_semantics".into(),
            arguments: Some(
                json!({
                    "application": application,
                    "query": query,
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("trace");
    assert!(result.is_error.is_none() || result.is_error == Some(false));
    let structured = result.structured_content.expect("structuredContent");
    validate_schema("trace_javascript_semantics", &structured);
    assert_eq!(
        strip_volatile(structured),
        strip_volatile(oracle["structuredContent"].clone())
    );
}
