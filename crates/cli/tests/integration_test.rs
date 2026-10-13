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
    assert_eq!(
        tools.len(),
        172,
        "Expected 170 REA tools plus infer_api_spec and generate_api_client"
    );

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
        "trace_web_module_imports",
        "trace_web_source_location",
        "observe_web_execution",
        "inspect_web_event_listeners",
        "inspect_web_network_capture",
        "export_web_scripts",
        "list_browser_targets",
        "inspect_web_page",
        "analyze_web_bundle",
        "observe_web_session",
        "discover_webmcp_tools",
        "compare_web_captures",
        "capture_web_screenshot",
        "compare_web_screenshots",
        "capture_browser_scenario",
        "inspect_artifact",
        "extract_artifact",
        "recover_javascript_sources",
        "list_electron_targets",
        "inspect_electron_page",
        "analyze_javascript_application",
        "reconcile_javascript_runtime",
        "capture_electron_scenario",
        "list_javascript_runtime_targets",
        "observe_javascript_runtime",
        "trace_application_feature",
        "trace_javascript_semantics",
        "compare_application_versions",
        "compare_source_to_bundle",
        "compare_javascript_export_shapes",
        "build_reconstruction_obligation_ledger",
        "evaluate_reconstruction_coverage",
        "capture_process_scenario",
        "compare_process_captures",
        "compare_artifacts",
        "find_changed_behavior",
        "correlate_static_and_runtime",
        "verify_reconstruction",
        "infer_api_spec",
        "generate_api_client",
    ];

    let actual_names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().expect("Tool name must be string"))
        .collect();

    // Phases 3-6 sit between the 50 ported REA tools and the tracewise tools.
    let ported: Vec<&str> = actual_names[..50]
        .iter()
        .chain(actual_names[170..].iter())
        .copied()
        .collect();
    assert_eq!(ported, expected_names);

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
        call_resp["result"]["structuredContent"]["result"]["server_identity"]["server"]["name"]
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

#[tokio::test]
async fn test_mcp_cancellation() {
    let bin_path = env!("CARGO_BIN_EXE_tracewise");

    let mut child = Command::new(bin_path)
        .arg("mcp")
        .env("TRACEWISE_TEST_DELAY_MS", "3000")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to spawn tracewise mcp");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut reader = BufReader::new(stdout).lines();

    // 1. Initialize
    let init_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "1.0.0" }
        }
    });
    stdin
        .write_all(format!("{}\n", init_req).as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let init_line = reader.next_line().await.unwrap().unwrap();
    let init_resp: serde_json::Value = serde_json::from_str(&init_line).unwrap();
    assert_eq!(init_resp["id"], 1);

    // 2. Initialized notification
    let init_notif = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    stdin
        .write_all(format!("{}\n", init_notif).as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    // 3. Send tools/call that will sleep for 3000ms
    let start_time = std::time::Instant::now();
    let call_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {
            "name": "binary_session",
            "arguments": {}
        }
    });
    stdin
        .write_all(format!("{}\n", call_req).as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    // Wait 100ms so the request enters execute_tool and starts sleeping
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // 4. Send cancellation notification
    let cancel_notif = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {
            "requestId": 42,
            "reason": "Test client requested cancellation"
        }
    });
    stdin
        .write_all(format!("{}\n", cancel_notif).as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    // 5. Read response for id 42
    let line = tokio::time::timeout(std::time::Duration::from_secs(2), reader.next_line())
        .await
        .expect("Timeout waiting for cancellation response")
        .expect("Failed to read line")
        .expect("EOF reading response");

    let elapsed = start_time.elapsed();
    assert!(
        elapsed < std::time::Duration::from_millis(2500),
        "Request took {:?}, expected to be cancelled early before 3000ms",
        elapsed
    );

    let resp: serde_json::Value = serde_json::from_str(&line).expect("Failed to parse JSON");
    assert_eq!(resp["id"], 42);
    assert!(
        resp.get("error").is_some(),
        "Expected error response upon cancellation, got: {:?}",
        resp
    );
    assert_eq!(resp["error"]["code"], -32800);

    drop(stdin);
    let _ = child.kill().await;
}

#[tokio::test]
async fn test_mcp_progress() {
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

    // 1. Initialize
    let init_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "1.0.0" }
        }
    });
    stdin
        .write_all(format!("{}\n", init_req).as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    let init_line = reader.next_line().await.unwrap().unwrap();
    let init_resp: serde_json::Value = serde_json::from_str(&init_line).unwrap();
    assert_eq!(init_resp["id"], 1);

    // 2. Initialized notification
    let init_notif = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    stdin
        .write_all(format!("{}\n", init_notif).as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    // Create temp file for open_binary
    let temp_path = std::env::temp_dir().join(format!("test_prog_{}.bin", std::process::id()));
    let dummy_elf = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    std::fs::write(&temp_path, dummy_elf).unwrap();

    // 3. Send tools/call with progressToken
    let progress_token = "token-test-xyz";
    let call_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {
            "name": "open_binary",
            "arguments": {
                "path": temp_path.to_str().unwrap()
            },
            "_meta": {
                "progressToken": progress_token
            }
        }
    });
    stdin
        .write_all(format!("{}\n", call_req).as_bytes())
        .await
        .unwrap();
    stdin.flush().await.unwrap();

    // Read messages until we get the response for id 10
    let mut progress_notifs = Vec::new();
    let mut final_resp = None;

    while let Ok(Ok(Some(line))) =
        tokio::time::timeout(std::time::Duration::from_secs(5), reader.next_line()).await
    {
        let msg: serde_json::Value = serde_json::from_str(&line).unwrap();
        if msg.get("id") == Some(&serde_json::json!(10)) {
            final_resp = Some(msg);
            break;
        } else if msg.get("method") == Some(&serde_json::json!("notifications/progress")) {
            progress_notifs.push(msg);
        }
    }

    assert!(final_resp.is_some(), "Did not receive response for tool call");
    assert!(
        !progress_notifs.is_empty(),
        "Expected at least one progress notification"
    );

    // Verify progress tokens match
    for notif in &progress_notifs {
        assert_eq!(notif["params"]["progressToken"], progress_token);
    }

    // Verify start (0.0) and end (1.0)
    let progress_values: Vec<f64> = progress_notifs
        .iter()
        .map(|n| n["params"]["progress"].as_f64().unwrap())
        .collect();
    assert!(
        progress_values.contains(&0.0),
        "Expected 0.0 progress notification"
    );
    assert!(
        progress_values.contains(&1.0),
        "Expected 1.0 progress notification"
    );

    let _ = std::fs::remove_file(&temp_path);
    drop(stdin);
    let _ = child.kill().await;
}

#[tokio::test]
async fn test_infer_api_spec_cli() {
    let bin_path = env!("CARGO_BIN_EXE_tracewise");
    let output = std::env::temp_dir().join(format!("tracewise-cli-spec-{}.json", std::process::id()));
    let status = Command::new(bin_path)
        .arg("infer-api-spec")
        .arg("/workspace/tracewise/fixtures/web/demo.har")
        .arg("-o")
        .arg(&output)
        .status()
        .await
        .expect("spawn infer-api-spec");
    assert!(status.success(), "infer-api-spec exited {status}");
    let text = std::fs::read_to_string(&output).expect("read spec");
    assert!(!text.contains("SECRET-"));
    let spec: serde_json::Value = serde_json::from_str(&text).expect("parse spec");
    assert!(spec["paths"].get("/api/todos/{id}").is_some());
    assert_eq!(spec["openapi"], "3.1.0");
    let _ = std::fs::remove_file(&output);
}

#[tokio::test]
async fn test_generate_api_client_cli() {
    let bin_path = env!("CARGO_BIN_EXE_tracewise");
    let root = std::env::temp_dir().join(format!("tracewise-cli-client-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("cli outdir");
    let spec = root.join("spec.json");
    let infer = Command::new(bin_path)
        .arg("infer-api-spec")
        .arg("/workspace/tracewise/fixtures/web/demo.har")
        .arg("-o")
        .arg(&spec)
        .status()
        .await
        .expect("spawn infer-api-spec");
    assert!(infer.success(), "infer-api-spec exited {infer}");
    let outdir = root.join("sdk");
    let status = Command::new(bin_path)
        .arg("generate-api-client")
        .arg(&spec)
        .arg("--lang")
        .arg("ts,py")
        .arg("-o")
        .arg(&outdir)
        .arg("--replay")
        .arg("/workspace/tracewise/fixtures/web/demo.har")
        .status()
        .await
        .expect("spawn generate-api-client");
    assert!(status.success(), "generate-api-client exited {status}");
    let client = std::fs::read_to_string(outdir.join("python/inferred_api/client.py")).expect("python client");
    assert!(client.contains("def get_api_todos_by_id"));
    let ts = std::fs::read_to_string(outdir.join("typescript/src/client.ts")).expect("ts client");
    assert!(ts.contains("getApiTodosById"));
    assert!(!client.contains("SECRET-"));
    assert!(!ts.contains("SECRET-"));
    let _ = std::fs::remove_dir_all(&root);
}
