use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

#[tokio::test]
async fn test_mcp_stdio_lifecycle() {
    // Locate the built binary
    let bin_path = env!("CARGO_BIN_EXE_tracewise");

    let mut child = Command::new(bin_path)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to spawn tracewise mcp");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut reader = BufReader::new(stdout).lines();

    // 1. Send initialize request
    let init_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        }
    });
    stdin
        .write_all(format!("{}\n", init_req).as_bytes())
        .await
        .expect("Failed to write initialize request");
    stdin.flush().await.expect("Failed to flush stdin");

    let line = reader
        .next_line()
        .await
        .expect("Failed to read line")
        .expect("EOF reading initialize response");
    let init_resp: serde_json::Value =
        serde_json::from_str(&line).expect("Failed to parse initialize response");
    assert_eq!(init_resp["id"], 1);
    assert_eq!(init_resp["result"]["serverInfo"]["name"], "tracewise");

    // 2. Send notifications/initialized
    let initialized_notif = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    stdin
        .write_all(format!("{}\n", initialized_notif).as_bytes())
        .await
        .expect("Failed to write initialized notification");
    stdin.flush().await.expect("Failed to flush stdin");

    // 3. Send tools/list request
    let tools_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    stdin
        .write_all(format!("{}\n", tools_req).as_bytes())
        .await
        .expect("Failed to write tools/list request");
    stdin.flush().await.expect("Failed to flush stdin");

    let line = reader
        .next_line()
        .await
        .expect("Failed to read line")
        .expect("EOF reading tools/list response");
    let tools_resp: serde_json::Value =
        serde_json::from_str(&line).expect("Failed to parse tools/list response");
    assert_eq!(tools_resp["id"], 2);

    let tools = tools_resp["result"]["tools"]
        .as_array()
        .expect("Expected tools array");
    assert_eq!(tools.len(), 12, "Expected exactly 12 tools");

    let expected_names = [
        "inspect_analysis_view",
        "open_binary",
        "close_binary",
        "binary_session",
        "export_evidence_bundle",
        "import_evidence_bundle",
        "get_evidence_bundle",
        "compare_bundles",
        "list_unknowns",
        "record_unknown",
        "update_unknown",
        "verify_unknown_resolution",
    ];

    let actual_names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().expect("Tool name must be string"))
        .collect();

    assert_eq!(actual_names, expected_names);

    // 4. Send tools/call for binary_session
    let call_session_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "binary_session",
            "arguments": {}
        }
    });
    stdin
        .write_all(format!("{}\n", call_session_req).as_bytes())
        .await
        .expect("Failed to write tools/call request");
    stdin.flush().await.expect("Failed to flush stdin");

    let line = reader
        .next_line()
        .await
        .expect("Failed to read line")
        .expect("EOF reading binary_session response");
    let call_resp: serde_json::Value =
        serde_json::from_str(&line).expect("Failed to parse binary_session response");
    assert_eq!(call_resp["id"], 3);
    assert!(
        call_resp["result"]["structuredContent"]["result"]["server_identity"]["name"]
            == "tracewise"
    );

    // 5. Send tools/call for record_unknown
    let call_unknown_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "record_unknown",
            "arguments": {
                "question": "What does the decoder do?",
                "severity": "medium",
                "domain": "decoding",
                "required_authority": null,
                "required_confidence": "observed",
                "required_environment": null,
                "recommended_probes": [],
                "relationships": []
            }
        }
    });
    stdin
        .write_all(format!("{}\n", call_unknown_req).as_bytes())
        .await
        .expect("Failed to write record_unknown tools/call");
    stdin.flush().await.expect("Failed to flush stdin");

    let line = reader
        .next_line()
        .await
        .expect("Failed to read line")
        .expect("EOF reading record_unknown response");
    let unknown_resp: serde_json::Value =
        serde_json::from_str(&line).expect("Failed to parse record_unknown response");
    assert_eq!(unknown_resp["id"], 4);
    let unknown_id = unknown_resp["result"]["structuredContent"]["result"]["unknown_id"]
        .as_str()
        .expect("Expected unknown_id");
    assert!(
        unknown_id.starts_with("unk_"),
        "unknown_id should start with unk_: {unknown_id}"
    );

    // Clean up
    drop(stdin);
    let _ = child.kill().await;
}
