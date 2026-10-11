//! Source-map recovery and historical-source comparison.
//!
//! `compare_source_to_bundle` is compared in full to
//! `fixtures/js/oracle_compare_source_to_bundle.json`. No fields are ignored:
//! the application evidence and historical graph are fixed inputs, and the
//! comparison id is a canonical digest of that result.
//!
//! `recover_javascript_sources` is not compared to the original REA oracle.
//! The original tool requires a caller-supplied Wakaru binary
//! (`REA_WAKARU_COMMAND`), which is not installed; its engine path, executable
//! digest and extraction ranges are host-dependent. This implementation copies
//! `sourcesContent` from `fixtures/js/bundle-app/dist/app.js.map`. The test
//! checks those recovered bytes and validates `structuredContent` against the
//! tool outputSchema. Output directory paths are absolute and temporary.

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

#[tokio::test]
async fn recover_javascript_sources_matches_source_map_contents() {
    let output = std::env::temp_dir().join(format!(
        "tracewise-recover-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&output);
    let session = BinarySession::new();
    let result = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "recover_javascript_sources".into(),
            arguments: Some(
                json!({
                    "path": "/workspace/tracewise/fixtures/js/bundle-app/dist/app.js",
                    "output_directory": output.display().to_string(),
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("recover");
    assert!(result.is_error.is_none() || result.is_error == Some(false));
    let structured = result.structured_content.expect("structuredContent");
    validate_schema("recover_javascript_sources", &structured);
    assert_eq!(structured["operation"], "recover_javascript_sources");
    assert_eq!(structured["normalized_result"]["status"], "complete");
    assert_eq!(structured["normalized_result"]["runtime_equivalence"], "unknown");
    assert_eq!(structured["normalized_result"]["total"], 2);
    assert_eq!(structured["normalized_result"]["failed"], 0);
    let greet = std::fs::read_to_string(output.join("modules/src/greet.js")).expect("greet");
    let math = std::fs::read_to_string(output.join("modules/src/math.js")).expect("math");
    let map: Value = serde_json::from_str(
        &std::fs::read_to_string("/workspace/tracewise/fixtures/js/bundle-app/dist/app.js.map")
            .expect("map"),
    )
    .expect("map json");
    assert_eq!(greet, map["sourcesContent"][0].as_str().unwrap());
    assert_eq!(math, map["sourcesContent"][1].as_str().unwrap());
    let _ = std::fs::remove_dir_all(&output);
}

#[tokio::test]
async fn compare_source_to_bundle_matches_oracle() {
    let reference: Value = serde_json::from_str(
        &std::fs::read_to_string("/workspace/tracewise/fixtures/js/historical_source_graph.json")
            .expect("reference"),
    )
    .expect("reference json");
    let application: Value = serde_json::from_str(
        &std::fs::read_to_string(
            "/workspace/tracewise/fixtures/js/bundle_app_application_evidence.json",
        )
        .expect("application"),
    )
    .expect("application json");
    let session = BinarySession::new();
    let result = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "compare_source_to_bundle".into(),
            arguments: Some(
                json!({
                    "reference": reference,
                    "application": application,
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("compare");
    assert!(result.is_error.is_none() || result.is_error == Some(false));
    let structured = result.structured_content.expect("structuredContent");
    validate_schema("compare_source_to_bundle", &structured);
    let oracle: Value = serde_json::from_str(
        &std::fs::read_to_string(
            "/workspace/tracewise/fixtures/js/oracle_compare_source_to_bundle.json",
        )
        .expect("oracle"),
    )
    .expect("oracle json");
    assert_eq!(structured, oracle["structuredContent"]);
}
