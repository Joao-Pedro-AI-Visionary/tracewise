use base64::prelude::*;
use rmcp::model::CallToolRequestParam;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

#[tokio::test]
async fn test_compare_web_captures() {
    let session = BinarySession::new();
    let before_str =
        std::fs::read_to_string("/workspace/tracewise/fixtures/web/capture_before.json")
            .expect("read capture_before.json");
    let after_str =
        std::fs::read_to_string("/workspace/tracewise/fixtures/web/capture_after.json")
            .expect("read capture_after.json");

    let before_val: Value = serde_json::from_str(&before_str).expect("parse capture_before.json");
    let after_val: Value = serde_json::from_str(&after_str).expect("parse capture_after.json");

    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "compare_web_captures".into(),
            arguments: Some(
                json!({
                    "before": {
                        "inspection": before_val,
                    },
                    "after": {
                        "inspection": after_val,
                    },
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("compare_web_captures call failed");

    let structured = res
        .structured_content
        .as_ref()
        .expect("structured_content must not be None");

    // 1. Output schema validation against phase1_tools_value()
    let tools_val = tracewise_contracts::phase1_tools_value();
    let tools_arr = tools_val["tools"].as_array().expect("tools array");
    let tool_def = tools_arr
        .iter()
        .find(|t| t["name"] == "compare_web_captures")
        .expect("compare_web_captures tool definition");
    let schema = &tool_def["outputSchema"];
    let validator = jsonschema::validator_for(schema)
        .unwrap_or_else(|e| panic!("Failed to compile outputSchema: {e}"));

    if let Err(first_err) = validator.validate(structured) {
        let all_errors: Vec<String> = validator
            .iter_errors(structured)
            .map(|e| format!("path: {}, error: {}", e.instance_path(), e))
            .collect();
        panic!(
            "structuredContent failed schema validation:\nFirst error: {}\nAll errors:\n{}\n",
            first_err,
            all_errors.join("\n")
        );
    }

    // 2. Oracle comparison
    let oracle_str = std::fs::read_to_string(
        "/workspace/tracewise/fixtures/web/oracle_compare_web_captures.json",
    )
    .expect("Failed to read oracle json");
    let oracle: Value = serde_json::from_str(&oracle_str).expect("Failed to parse oracle json");
    let oracle_structured = &oracle["structuredContent"];

    // Ignored fields documentation:
    // None. All fields in structuredContent (including evidence_id, provider, parameters,
    // normalized_result, limitations, locations, and evidence_links) match the oracle exactly.
    assert_eq!(structured, oracle_structured);
}

#[tokio::test]
async fn test_compare_web_screenshots() {
    let session = BinarySession::new();
    let bytes_a = std::fs::read("/workspace/tracewise/fixtures/web/shot_a.png")
        .expect("read shot_a.png");
    let bytes_b = std::fs::read("/workspace/tracewise/fixtures/web/shot_b.png")
        .expect("read shot_b.png");

    let sha_a = hex::encode(Sha256::digest(&bytes_a));
    let sha_b = hex::encode(Sha256::digest(&bytes_b));

    let art_a = json!({
        "sha256": sha_a,
        "bytes": bytes_a.len(),
        "media_type": "image/png",
        "data_base64": BASE64_STANDARD.encode(&bytes_a),
    });
    let art_b = json!({
        "sha256": sha_b,
        "bytes": bytes_b.len(),
        "media_type": "image/png",
        "data_base64": BASE64_STANDARD.encode(&bytes_b),
    });

    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "compare_web_screenshots".into(),
            arguments: Some(
                json!({
                    "before": art_a,
                    "after": art_b,
                    "channel_threshold": 0,
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("compare_web_screenshots call failed");

    let structured = res
        .structured_content
        .as_ref()
        .expect("structured_content must not be None");

    // 1. Output schema validation against phase1_tools_value()
    let tools_val = tracewise_contracts::phase1_tools_value();
    let tools_arr = tools_val["tools"].as_array().expect("tools array");
    let tool_def = tools_arr
        .iter()
        .find(|t| t["name"] == "compare_web_screenshots")
        .expect("compare_web_screenshots tool definition");
    let schema = &tool_def["outputSchema"];
    let validator = jsonschema::validator_for(schema)
        .unwrap_or_else(|e| panic!("Failed to compile outputSchema: {e}"));

    if let Err(first_err) = validator.validate(structured) {
        let all_errors: Vec<String> = validator
            .iter_errors(structured)
            .map(|e| format!("path: {}, error: {}", e.instance_path(), e))
            .collect();
        panic!(
            "structuredContent failed schema validation:\nFirst error: {}\nAll errors:\n{}\n",
            first_err,
            all_errors.join("\n")
        );
    }

    // 2. Oracle comparison
    let oracle_str = std::fs::read_to_string(
        "/workspace/tracewise/fixtures/web/oracle_compare_web_screenshots.json",
    )
    .expect("Failed to read oracle json");
    let oracle: Value = serde_json::from_str(&oracle_str).expect("Failed to parse oracle json");
    let oracle_structured = &oracle["structuredContent"];

    // Ignored fields documentation:
    // None. All fields in structuredContent (including evidence_id, provider, parameters,
    // normalized_result, limitations, locations, and evidence_links) match the oracle exactly.
    assert_eq!(structured, oracle_structured);
}
