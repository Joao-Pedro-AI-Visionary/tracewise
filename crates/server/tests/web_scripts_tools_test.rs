use rmcp::model::CallToolRequestParam;
use serde_json::{json, Value};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

#[tokio::test]
async fn test_export_web_scripts() {
    let session = BinarySession::new();
    let capture_path = "/workspace/tracewise/fixtures/web/scripts.har";
    let temp_dir = std::env::temp_dir().join(format!("tracewise_export_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);

    let output_dir_str = temp_dir.to_str().unwrap().to_string();

    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "export_web_scripts".into(),
            arguments: Some(
                json!({
                    "capture_path": capture_path,
                    "output_directory": &output_dir_str,
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("export_web_scripts call failed");

    let structured = res
        .structured_content
        .as_ref()
        .expect("structured_content must not be None");

    // 1. Output schema validation against phase1_tools_value()
    let tools_val = tracewise_contracts::phase1_tools_value();
    let tools_arr = tools_val["tools"].as_array().expect("tools array");
    let tool_def = tools_arr
        .iter()
        .find(|t| t["name"] == "export_web_scripts")
        .expect("export_web_scripts tool definition");
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
        "/workspace/tracewise/fixtures/web/oracle_export_web_scripts.json",
    )
    .expect("Failed to read oracle json");
    let oracle: Value = serde_json::from_str(&oracle_str).expect("Failed to parse oracle json");
    let oracle_structured = &oracle["structuredContent"];

    // Compare non-path-dependent fields:
    // Path/time-dependent fields ignored and why:
    // - evidence_id: SHA-256 digest over the entire observation envelope, which embeds the host-dependent output_directory path.
    // - parameters.output_directory: caller-selected temporary filesystem directory path.
    // - normalized_result.output_directory: destination output path.
    // - normalized_result.analysis_input.input_path: filesystem path to exported files directory.
    // - normalized_result.manifest.path: filesystem path to manifest.json.
    // - normalized_result.manifest.sha256: digest of manifest.json whose content contains output_directory path.
    // - normalized_result.manifest.bytes: byte length of manifest.json (varies with output_directory path length).
    // - locations: contains filesystem path to manifest.json.

    assert_eq!(structured["provider"], oracle_structured["provider"]);
    assert_eq!(structured["predicate_type"], oracle_structured["predicate_type"]);
    assert_eq!(structured["operation"], oracle_structured["operation"]);
    assert_eq!(structured["confidence"], oracle_structured["confidence"]);
    assert_eq!(structured["authority"], oracle_structured["authority"]);
    assert_eq!(structured["limitations"], oracle_structured["limitations"]);

    // Subject
    assert_eq!(structured["subject"]["name"], oracle_structured["subject"]["name"]);
    assert_eq!(structured["subject"]["digest"], oracle_structured["subject"]["digest"]);
    assert_eq!(structured["subject"]["format"], oracle_structured["subject"]["format"]);
    assert_eq!(structured["subject"]["local_path"], oracle_structured["subject"]["local_path"]);

    // Normalized result
    let norm = &structured["normalized_result"];
    let oracle_norm = &oracle_structured["normalized_result"];

    assert_eq!(norm["capture_path"], oracle_norm["capture_path"]);
    assert_eq!(norm["capture_sha256"], oracle_norm["capture_sha256"]);
    assert_eq!(norm["capture_kind"], oracle_norm["capture_kind"]);
    assert_eq!(norm["source_evidence_id"], oracle_norm["source_evidence_id"]);
    assert_eq!(norm["capture_completeness"], oracle_norm["capture_completeness"]);
    assert_eq!(norm["scripts"], oracle_norm["scripts"]);
    assert_eq!(norm["limitations"], oracle_norm["limitations"]);

    // Verify files were actually created in output directory
    assert!(temp_dir.join("manifest.json").exists());
    assert!(temp_dir.join("files").exists());

    // Verify ledger record
    let evidence_id = structured["evidence_id"].as_str().expect("evidence_id");
    let ledger = session.ledger.lock().unwrap();
    assert!(ledger.get(evidence_id).is_some());

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_trace_web_module_imports() {
    if std::env::var("REA_BROWSER_EXECUTABLE").is_err() {
        std::env::set_var("REA_BROWSER_EXECUTABLE", "/usr/bin/google-chrome");
    }

    let session = BinarySession::new();
    let capture_path = "/workspace/tracewise/fixtures/web/scripts.har";
    let temp_dir = std::env::temp_dir().join(format!("tracewise_module_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    let output_dir_str = temp_dir.to_str().unwrap().to_string();

    // Export scripts first to get manifest
    let export_res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "export_web_scripts".into(),
            arguments: Some(
                json!({
                    "capture_path": capture_path,
                    "output_directory": &output_dir_str,
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("export_web_scripts call failed");

    let manifest_path = export_res
        .structured_content
        .as_ref()
        .unwrap()["normalized_result"]["manifest"]["path"]
        .as_str()
        .unwrap()
        .to_string();

    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "trace_web_module_imports".into(),
            arguments: Some(
                json!({
                    "manifest_path": &manifest_path,
                    "script_index": 0,
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("trace_web_module_imports call failed");

    let structured = res
        .structured_content
        .as_ref()
        .expect("structured_content must not be None");

    // 1. Output schema validation against phase1_tools_value()
    let tools_val = tracewise_contracts::phase1_tools_value();
    let tools_arr = tools_val["tools"].as_array().expect("tools array");
    let tool_def = tools_arr
        .iter()
        .find(|t| t["name"] == "trace_web_module_imports")
        .expect("trace_web_module_imports tool definition");
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
        "/workspace/tracewise/fixtures/web/oracle_trace_web_module_imports.json",
    )
    .expect("Failed to read oracle json");
    let oracle: Value = serde_json::from_str(&oracle_str).expect("Failed to parse oracle json");
    let oracle_structured = &oracle["structuredContent"];

    // Compare non-path-dependent fields:
    // Path/time-dependent fields ignored and why:
    // - evidence_id: SHA-256 digest over the entire observation envelope, embedding host-dependent manifest and source paths.
    // - subject.local_path: filesystem path to exported script.
    // - parameters.manifest_path: caller-supplied manifest filesystem path.
    // - normalized_result.manifest.path: filesystem path to manifest.json.
    // - normalized_result.manifest.sha256: digest of manifest.json which embeds the temp output_directory path.
    // - normalized_result.manifest.bytes: byte length of manifest.json.
    // - normalized_result.manifest.reported_output_directory: temp output_directory path.
    // - normalized_result.source.path: filesystem path to exported script.
    // - locations: contains filesystem paths to manifest.json and source file.

    assert_eq!(structured["provider"], oracle_structured["provider"]);
    assert_eq!(structured["predicate_type"], oracle_structured["predicate_type"]);
    assert_eq!(structured["operation"], oracle_structured["operation"]);
    assert_eq!(structured["confidence"], oracle_structured["confidence"]);
    assert_eq!(structured["authority"], oracle_structured["authority"]);
    assert_eq!(structured["limitations"], oracle_structured["limitations"]);
    assert_eq!(structured["parameters"]["script_index"], oracle_structured["parameters"]["script_index"]);

    // Subject
    assert_eq!(structured["subject"]["name"], oracle_structured["subject"]["name"]);
    assert_eq!(structured["subject"]["digest"], oracle_structured["subject"]["digest"]);
    assert_eq!(structured["subject"]["format"], oracle_structured["subject"]["format"]);

    // Normalized result
    let norm = &structured["normalized_result"];
    let oracle_norm = &oracle_structured["normalized_result"];

    assert_eq!(norm["importer"], oracle_norm["importer"]);
    assert_eq!(norm["import_map"], oracle_norm["import_map"]);
    assert_eq!(norm["parser"], oracle_norm["parser"]);
    assert_eq!(norm["engine"], oracle_norm["engine"]);
    assert_eq!(norm["imports"], oracle_norm["imports"]);
    assert_eq!(norm["diagnostics"], oracle_norm["diagnostics"]);
    assert_eq!(norm["limitations"], oracle_norm["limitations"]);

    // Source script comparison
    assert_eq!(norm["source"]["sha256"], oracle_norm["source"]["sha256"]);
    assert_eq!(norm["source"]["bytes"], oracle_norm["source"]["bytes"]);
    assert_eq!(norm["source"]["script_index"], oracle_norm["source"]["script_index"]);
    assert_eq!(norm["source"]["script"], oracle_norm["source"]["script"]);

    // Manifest metadata comparison
    assert_eq!(norm["manifest"]["capture_path"], oracle_norm["manifest"]["capture_path"]);
    assert_eq!(norm["manifest"]["capture_sha256"], oracle_norm["manifest"]["capture_sha256"]);
    assert_eq!(norm["manifest"]["capture_kind"], oracle_norm["manifest"]["capture_kind"]);
    assert_eq!(norm["manifest"]["capture_completeness"], oracle_norm["manifest"]["capture_completeness"]);

    // Raw result comparison
    let raw = &structured["raw_result"];
    let oracle_raw = &oracle_structured["raw_result"];
    assert_eq!(raw["native_report"], oracle_raw["native_report"]);
    assert_eq!(raw["requests"], oracle_raw["requests"]);
    assert_eq!(raw["diagnostics"], oracle_raw["diagnostics"]);
    assert_eq!(raw["engine"], oracle_raw["engine"]);
    assert_eq!(raw["executable_path"], oracle_raw["executable_path"]);

    // Verify ledger record
    let evidence_id = structured["evidence_id"].as_str().expect("evidence_id");
    let ledger = session.ledger.lock().unwrap();
    assert!(ledger.get(evidence_id).is_some());

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_trace_web_source_location() {
    let session = BinarySession::new();
    let capture_path = "/workspace/tracewise/fixtures/web/scripts.har";
    let source_map_path = "/workspace/tracewise/fixtures/web/main.js.map";
    let temp_dir = std::env::temp_dir().join(format!("tracewise_srcloc_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    let output_dir_str = temp_dir.to_str().unwrap().to_string();

    // Export scripts first to get manifest
    let export_res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "export_web_scripts".into(),
            arguments: Some(
                json!({
                    "capture_path": capture_path,
                    "output_directory": &output_dir_str,
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("export_web_scripts call failed");

    let manifest_path = export_res
        .structured_content
        .as_ref()
        .unwrap()["normalized_result"]["manifest"]["path"]
        .as_str()
        .unwrap()
        .to_string();

    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "trace_web_source_location".into(),
            arguments: Some(
                json!({
                    "manifest_path": &manifest_path,
                    "script_index": 0,
                    "source_map": {
                        "path": source_map_path,
                        "url": "http://127.0.0.1:8000/app/main.js.map"
                    },
                    "generated_position": {
                        "line": 1,
                        "column": 0
                    }
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("trace_web_source_location call failed");

    let structured = res
        .structured_content
        .as_ref()
        .expect("structured_content must not be None");

    // 1. Output schema validation against phase1_tools_value()
    let tools_val = tracewise_contracts::phase1_tools_value();
    let tools_arr = tools_val["tools"].as_array().expect("tools array");
    let tool_def = tools_arr
        .iter()
        .find(|t| t["name"] == "trace_web_source_location")
        .expect("trace_web_source_location tool definition");
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
        "/workspace/tracewise/fixtures/web/oracle_trace_web_source_location.json",
    )
    .expect("Failed to read oracle json");
    let oracle: Value = serde_json::from_str(&oracle_str).expect("Failed to parse oracle json");
    let oracle_structured = &oracle["structuredContent"];

    // Compare non-path-dependent fields:
    // Path/time-dependent fields ignored and why:
    // - evidence_id: SHA-256 digest over the entire observation envelope, embedding host-dependent manifest and source paths.
    // - subject.local_path: filesystem path to exported script.
    // - parameters.manifest_path: caller-supplied manifest filesystem path.
    // - normalized_result.manifest.path: filesystem path to manifest.json.
    // - normalized_result.manifest.sha256: digest of manifest.json which embeds the temp output_directory path.
    // - normalized_result.manifest.bytes: byte length of manifest.json.
    // - normalized_result.manifest.reported_output_directory: temp output_directory path.
    // - normalized_result.source.path: filesystem path to exported script.
    // - locations: contains filesystem paths to manifest.json, source file, and source_map.

    assert_eq!(structured["provider"], oracle_structured["provider"]);
    assert_eq!(structured["predicate_type"], oracle_structured["predicate_type"]);
    assert_eq!(structured["operation"], oracle_structured["operation"]);
    assert_eq!(structured["confidence"], oracle_structured["confidence"]);
    assert_eq!(structured["authority"], oracle_structured["authority"]);
    assert_eq!(structured["limitations"], oracle_structured["limitations"]);
    assert_eq!(structured["parameters"]["script_index"], oracle_structured["parameters"]["script_index"]);
    assert_eq!(structured["parameters"]["source_map"], oracle_structured["parameters"]["source_map"]);
    assert_eq!(structured["parameters"]["generated_position"], oracle_structured["parameters"]["generated_position"]);

    // Subject
    assert_eq!(structured["subject"]["name"], oracle_structured["subject"]["name"]);
    assert_eq!(structured["subject"]["digest"], oracle_structured["subject"]["digest"]);
    assert_eq!(structured["subject"]["format"], oracle_structured["subject"]["format"]);

    // Raw result
    assert_eq!(structured["raw_result"], oracle_structured["raw_result"]);

    // Normalized result
    let norm = &structured["normalized_result"];
    let oracle_norm = &oracle_structured["normalized_result"];

    assert_eq!(norm["source_map_sha256"], oracle_norm["source_map_sha256"]);
    assert_eq!(norm["url_context"], oracle_norm["url_context"]);
    assert_eq!(norm["engine"], oracle_norm["engine"]);
    assert_eq!(norm["runtime"], oracle_norm["runtime"]);
    assert_eq!(norm["format"], oracle_norm["format"]);
    assert_eq!(norm["reported_file"], oracle_norm["reported_file"]);
    assert_eq!(norm["lookup"], oracle_norm["lookup"]);
    assert_eq!(norm["matches"], oracle_norm["matches"]);
    assert_eq!(norm["diagnostics"], oracle_norm["diagnostics"]);
    assert_eq!(norm["source_map"], oracle_norm["source_map"]);
    assert_eq!(norm["generated_offset"], oracle_norm["generated_offset"]);
    assert_eq!(norm["source_authenticity"], oracle_norm["source_authenticity"]);
    assert_eq!(norm["execution"], oracle_norm["execution"]);
    assert_eq!(norm["limitations"], oracle_norm["limitations"]);

    // Source script comparison
    assert_eq!(norm["source"]["sha256"], oracle_norm["source"]["sha256"]);
    assert_eq!(norm["source"]["bytes"], oracle_norm["source"]["bytes"]);
    assert_eq!(norm["source"]["script_index"], oracle_norm["source"]["script_index"]);
    assert_eq!(norm["source"]["script"], oracle_norm["source"]["script"]);

    // Manifest metadata comparison
    assert_eq!(norm["manifest"]["capture_path"], oracle_norm["manifest"]["capture_path"]);
    assert_eq!(norm["manifest"]["capture_sha256"], oracle_norm["manifest"]["capture_sha256"]);
    assert_eq!(norm["manifest"]["capture_kind"], oracle_norm["manifest"]["capture_kind"]);
    assert_eq!(norm["manifest"]["capture_completeness"], oracle_norm["manifest"]["capture_completeness"]);

    // Verify ledger record
    let evidence_id = structured["evidence_id"].as_str().expect("evidence_id");
    let ledger = session.ledger.lock().unwrap();
    assert!(ledger.get(evidence_id).is_some());

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);
}
