use rmcp::model::CallToolRequestParam;
use serde_json::{json, Value};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

#[tokio::test]
async fn test_inspect_web_network_capture_demo_har() {
    let session = BinarySession::new();
    let demo_path = "/workspace/tracewise/fixtures/web/demo.har";

    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "inspect_web_network_capture".into(),
            arguments: Some(
                json!({
                    "capture_path": demo_path,
                    "format": "har"
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("inspect_web_network_capture failed");

    // Assert no "SECRET-" substring in output
    let output_str = serde_json::to_string(&res).expect("Failed to serialize CallToolResult");
    assert!(
        !output_str.contains("SECRET-"),
        "Output must not contain 'SECRET-'"
    );

    let structured = res
        .structured_content
        .as_ref()
        .expect("structured_content must not be None");

    // Validate against tool outputSchema with jsonschema
    let tools_val = tracewise_contracts::phase1_tools_value();
    let tools_arr = tools_val["tools"].as_array().expect("tools array");
    let tool_def = tools_arr
        .iter()
        .find(|t| t["name"] == "inspect_web_network_capture")
        .expect("inspect_web_network_capture tool definition");
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

    // Compare against oracle (all fields match identically without environmental differences)
    let oracle_str = std::fs::read_to_string(
        "/workspace/tracewise/fixtures/web/oracle_inspect_web_network_capture_demo.json",
    )
    .expect("Failed to read oracle json");
    let oracle: Value = serde_json::from_str(&oracle_str).expect("Failed to parse oracle json");
    let oracle_structured = &oracle["structuredContent"];

    assert_eq!(structured, oracle_structured);

    // Verify evidence was persisted in binary session ledger with credentials redacted
    let evidence_id = structured["evidence_id"].as_str().expect("evidence_id");
    let ledger = session.ledger.lock().unwrap();
    let persisted = ledger.get(evidence_id).expect("persisted evidence in ledger");
    let persisted_str = serde_json::to_string(persisted).expect("serialize persisted evidence");
    assert!(
        !persisted_str.contains("SECRET-"),
        "Persisted evidence must not contain 'SECRET-'"
    );
}

#[tokio::test]
async fn test_inspect_web_network_capture_demo_mitm() {
    // Native mitmproxy decoding needs REA_MITMDUMP_COMMAND pointing at a
    // caller-supplied mitmdump 12.2.3 (e.g. `pip install mitmproxy==12.2.3`).
    if std::env::var("REA_MITMDUMP_COMMAND").is_err() {
        eprintln!("skipping: REA_MITMDUMP_COMMAND is not set (needs mitmdump 12.2.3)");
        return;
    }

    let session = BinarySession::new();
    let demo_path = "/workspace/tracewise/fixtures/web/demo.mitm";

    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "inspect_web_network_capture".into(),
            arguments: Some(
                json!({
                    "capture_path": demo_path,
                    "format": "mitmproxy"
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("inspect_web_network_capture failed for mitmproxy");

    // Assert no "SECRET-" substring in output
    let output_str = serde_json::to_string(&res).expect("Failed to serialize CallToolResult");
    assert!(
        !output_str.contains("SECRET-"),
        "Output must not contain 'SECRET-'"
    );

    let structured = res
        .structured_content
        .as_ref()
        .expect("structured_content must not be None");

    // Validate against tool outputSchema with jsonschema
    let tools_val = tracewise_contracts::phase1_tools_value();
    let tools_arr = tools_val["tools"].as_array().expect("tools array");
    let tool_def = tools_arr
        .iter()
        .find(|t| t["name"] == "inspect_web_network_capture")
        .expect("inspect_web_network_capture tool definition");
    let schema = &tool_def["outputSchema"];
    let validator = jsonschema::validator_for(schema)
        .unwrap_or_else(|e| panic!("Failed to compile outputSchema: {e}"));

    if let Err(first_err) = validator.validate(structured) {
        let all_errors: Vec<String> = validator
            .iter_errors(structured)
            .map(|e| format!("path: {}, error: {}", e.instance_path(), e))
            .collect();
        panic!(
            "mitmproxy structuredContent failed schema validation:\nFirst error: {}\nAll errors:\n{}\n",
            first_err,
            all_errors.join("\n")
        );
    }

    // Compare against oracle (all fields match identically without environmental differences)
    let oracle_str = std::fs::read_to_string(
        "/workspace/tracewise/fixtures/web/oracle_inspect_web_network_capture_demo_mitm.json",
    )
    .expect("Failed to read oracle json");
    let oracle: Value = serde_json::from_str(&oracle_str).expect("Failed to parse oracle json");
    let oracle_structured = &oracle["structuredContent"];

    assert_eq!(structured, oracle_structured);

    // Verify evidence was persisted in binary session ledger with credentials redacted
    let evidence_id = structured["evidence_id"].as_str().expect("evidence_id");
    let ledger = session.ledger.lock().unwrap();
    let persisted = ledger.get(evidence_id).expect("persisted evidence in ledger");
    let persisted_str = serde_json::to_string(persisted).expect("serialize persisted evidence");
    assert!(
        !persisted_str.contains("SECRET-"),
        "Persisted evidence must not contain 'SECRET-'"
    );
}

#[tokio::test]
async fn test_inspect_web_network_capture_demo_har_sensitive_values() {
    let session = BinarySession::new();
    let demo_path = "/workspace/tracewise/fixtures/web/demo.har";

    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "inspect_web_network_capture".into(),
            arguments: Some(
                json!({
                    "capture_path": demo_path,
                    "format": "har",
                    "sensitive_values": ["todos"]
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("inspect_web_network_capture with sensitive_values failed");

    let output_str = serde_json::to_string(&res).expect("Failed to serialize CallToolResult");
    assert!(
        !output_str.contains("SECRET-"),
        "Output must not contain 'SECRET-'"
    );

    let structured = res
        .structured_content
        .as_ref()
        .expect("structured_content must not be None");

    let oracle_str = std::fs::read_to_string(
        "/workspace/tracewise/fixtures/web/oracle_inspect_web_network_capture_demo_sensitive.json",
    )
    .expect("Failed to read oracle json");
    let oracle: Value = serde_json::from_str(&oracle_str).expect("Failed to parse oracle json");
    let oracle_structured = &oracle["structuredContent"];

    assert_eq!(structured, oracle_structured);
}
