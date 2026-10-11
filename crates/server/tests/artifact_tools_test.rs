//! Artifact graph tools (zip, asar, directory) vs REA oracle fixtures.
//!
//! Ignored fields when comparing `structuredContent` to oracle:
//! - `evidence_id` (session-local)
//! - `subject.local_path` and nested inventory `subject.local_path`
//! - nested `evidence_id` inside inspect substeps
//! - `extract_artifact` `normalized_result.output_root` and extraction manifest paths tied to temp dirs

use rmcp::model::CallToolRequestParam;
use serde_json::{json, Value};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

fn strip_volatile(value: &mut Value) {
    if let Some(obj) = value.as_object_mut() {
        obj.remove("evidence_id");
        if let Some(subject) = obj.get_mut("subject") {
            strip_local_path(subject);
        }
        if let Some(nr) = obj.get_mut("normalized_result") {
            if let Some(root) = nr.get_mut("output_root") {
                *root = json!("$OUTPUT_ROOT");
            }
            if let Some(em) = nr.get_mut("extraction_manifest").and_then(|v| v.as_object_mut()) {
                em.remove("extraction_id");
            }
            if let Some(substeps) = nr.get_mut("substeps").and_then(|s| s.as_array_mut()) {
                for step in substeps {
                    if let Some(ev) = step.get_mut("evidence") {
                        if let Some(o) = ev.as_object_mut() {
                            o.remove("evidence_id");
                            if let Some(subj) = o.get_mut("subject") {
                                strip_local_path(subj);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn strip_local_path(subject: &mut Value) {
    if let Some(s) = subject.as_object_mut() {
        s.remove("local_path");
    }
}

fn assert_matches_oracle(actual: &Value, oracle_path: &str, tool_name: &str) {
    let oracle_raw = std::fs::read_to_string(oracle_path).expect("read oracle");
    let oracle: Value = serde_json::from_str(&oracle_raw).expect("parse oracle");
    let mut expected = oracle["structuredContent"].clone();
    let mut got = actual.clone();
    strip_volatile(&mut expected);
    strip_volatile(&mut got);
    assert_eq!(got, expected, "mismatch for {tool_name} vs {oracle_path}");
}

fn validate_schema(tool_name: &str, structured: &Value) {
    let tools_val = tracewise_contracts::phase2_tools_value();
    let tool_def = tools_val["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == tool_name)
        .expect("tool in phase2");
    let validator = jsonschema::validator_for(&tool_def["outputSchema"]).expect("schema");
    validator
        .validate(structured)
        .unwrap_or_else(|e| panic!("{tool_name} schema: {e}"));
}

async fn open_and_inspect(fixture_path: &str) -> Value {
    let session = BinarySession::new();
    call_tool_local(
        &session,
        CallToolRequestParam {
            name: "open_binary".into(),
            arguments: Some(json!({ "path": fixture_path }).as_object().unwrap().clone()),
        },
    )
    .await
    .expect("open_binary");
    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "inspect_artifact".into(),
            arguments: Some(json!({ "integrity_policy": "fail" }).as_object().unwrap().clone()),
        },
    )
    .await
    .expect("inspect_artifact");
    res.structured_content
        .clone()
        .expect("structuredContent")
}

#[tokio::test]
async fn inspect_zip_matches_oracle() {
    let structured = open_and_inspect("/workspace/tracewise/fixtures/js/app-a.zip").await;
    validate_schema("inspect_artifact", &structured);
    assert_matches_oracle(
        &structured,
        "/workspace/tracewise/fixtures/js/raw_inspect_zip.json",
        "inspect_artifact",
    );
}

#[tokio::test]
async fn inspect_asar_matches_oracle() {
    let structured = open_and_inspect("/workspace/tracewise/fixtures/js/app-a.asar").await;
    validate_schema("inspect_artifact", &structured);
    assert_matches_oracle(
        &structured,
        "/workspace/tracewise/fixtures/js/raw_inspect_asar.json",
        "inspect_artifact",
    );
}

#[tokio::test]
async fn inspect_directory_matches_oracle() {
    let structured = open_and_inspect("/workspace/tracewise/fixtures/js/app-dir").await;
    validate_schema("inspect_artifact", &structured);
    assert_matches_oracle(
        &structured,
        "/workspace/tracewise/fixtures/js/raw_inspect_dir.json",
        "inspect_artifact",
    );
}

#[tokio::test]
async fn extract_zip_matches_oracle() {
    let session = BinarySession::new();
    let path = "/workspace/tracewise/fixtures/js/app-a.zip";
    call_tool_local(
        &session,
        CallToolRequestParam {
            name: "open_binary".into(),
            arguments: Some(json!({ "path": path }).as_object().unwrap().clone()),
        },
    )
    .await
    .expect("open");
    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "extract_artifact".into(),
            arguments: Some(json!({ "integrity_policy": "fail" }).as_object().unwrap().clone()),
        },
    )
    .await
    .expect("extract");
    let structured = res.structured_content.expect("structured");
    validate_schema("extract_artifact", &structured);
    assert_matches_oracle(
        &structured,
        "/workspace/tracewise/fixtures/js/raw_extract_zip.json",
        "extract_artifact",
    );
}

#[tokio::test]
async fn compare_zip_a_vs_b() {
    let left = open_and_inspect("/workspace/tracewise/fixtures/js/app-a.zip").await;
    let right = open_and_inspect("/workspace/tracewise/fixtures/js/app-b.zip").await;
    let left_inv = left["normalized_result"]["substeps"][0]["evidence"].clone();
    let right_inv = right["normalized_result"]["substeps"][0]["evidence"].clone();
    let session = BinarySession::new();
    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "compare_artifacts".into(),
            arguments: Some(
                json!({ "left": left_inv, "right": right_inv })
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        },
    )
    .await
    .expect("compare");
    let structured = res.structured_content.expect("structured");
    validate_schema("compare_artifacts", &structured);
    assert_eq!(structured["normalized_result"]["status"], "changed");
    assert!(structured["normalized_result"]["changes"]
        .as_array()
        .map(|a| !a.is_empty())
        .unwrap_or(false));
}
