use std::path::Path;

use rmcp::model::CallToolRequestParam;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
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

    // 2. Oracle comparison.
    // Ignored field (only this one):
    // - evidence_id: semantic digest of the whole observation envelope. It covers
    //   parameters.output_directory and normalized_result.manifest.sha256, both of
    //   which embed the caller-chosen directory. Path strings are rewritten to the
    //   oracle directory before comparison. Exported file sha256/bytes are checked
    //   on the bytes after that same prefix rewrite (script bodies do not contain
    //   the directory; manifest.json does).
    let oracle_str = std::fs::read_to_string(
        "/workspace/tracewise/fixtures/web/oracle_export_web_scripts.json",
    )
    .expect("Failed to read oracle json");
    let oracle: Value = serde_json::from_str(&oracle_str).expect("Failed to parse oracle json");
    let oracle_structured = &oracle["structuredContent"];
    let oracle_dir = oracle_structured["parameters"]["output_directory"]
        .as_str()
        .expect("oracle output_directory");

    let manifest_sha =
        assert_exported_files_match_oracle(&temp_dir, &output_dir_str, structured, oracle_structured);

    let mut actual = structured.clone();
    rewrite_output_prefix(&mut actual, &output_dir_str, oracle_dir);
    // The tool reports the digest of the file it wrote (host path included).
    // The oracle digest is of the same document with the oracle directory prefix.
    actual["normalized_result"]["manifest"]["sha256"] = json!(manifest_sha.sha256);
    actual["normalized_result"]["manifest"]["bytes"] = json!(manifest_sha.bytes);
    actual.as_object_mut().expect("object").remove("evidence_id");

    let mut expected = oracle_structured.clone();
    expected.as_object_mut().expect("object").remove("evidence_id");
    assert_eq!(actual, expected);

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
    // engine.version is the host Chrome version (the oracle host ran Chrome 154),
    // so it must equal the Chrome installed here; the engine id must match the oracle.
    assert_eq!(norm["engine"]["id"], oracle_norm["engine"]["id"]);
    let host_chrome = std::process::Command::new("google-chrome")
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|text| text.split_whitespace().last().map(str::to_string));
    match host_chrome {
        Some(version) => assert_eq!(norm["engine"]["version"], Value::String(version)),
        None => assert_eq!(norm["engine"], oracle_norm["engine"]),
    }
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
    assert_eq!(raw["engine"], norm["engine"], "raw and normalized engine must agree");
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

struct FileDigest {
    sha256: String,
    bytes: usize,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Replace the caller-chosen output directory. Exported script bytes are
/// independent of that directory; manifest.json embeds it as a path prefix.
fn normalize_export_prefix(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
    let from_bytes = from.as_bytes();
    let to_bytes = to.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(from_bytes) {
            out.extend_from_slice(to_bytes);
            index += from_bytes.len();
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    out
}

fn rewrite_output_prefix(value: &mut Value, from: &str, to: &str) {
    match value {
        Value::String(text) => {
            if text.contains(from) {
                *text = text.replace(from, to);
            }
        }
        Value::Array(items) => {
            for item in items {
                rewrite_output_prefix(item, from, to);
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                rewrite_output_prefix(item, from, to);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn list_export_files(root: &Path) -> Vec<String> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap_or_else(|err| panic!("read_dir {}: {err}", dir.display()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|err| panic!("read_dir entry: {err}"));
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let relative = path
                    .strip_prefix(root)
                    .expect("export file stays under the output directory")
                    .to_string_lossy()
                    .replace('\\', "/");
                files.push(relative);
            }
        }
    }
    files.sort();
    files
}

fn assert_exported_files_match_oracle(
    output_dir: &Path,
    actual_prefix: &str,
    structured: &Value,
    oracle_structured: &Value,
) -> FileDigest {
    let oracle_norm = &oracle_structured["normalized_result"];
    let oracle_dir = oracle_norm["output_directory"]
        .as_str()
        .expect("oracle output_directory");
    assert_ne!(
        actual_prefix, oracle_dir,
        "normalization must rewrite a distinct output directory"
    );

    let manifest_raw = std::fs::read(output_dir.join("manifest.json")).expect("read manifest.json");
    let reported = &structured["normalized_result"]["manifest"];
    assert_eq!(
        reported["sha256"].as_str().expect("reported manifest sha256"),
        sha256_hex(&manifest_raw),
        "reported manifest sha256 must be the digest of the written file"
    );
    assert_eq!(
        reported["bytes"].as_u64().expect("reported manifest bytes") as usize,
        manifest_raw.len(),
        "reported manifest size must be the written file"
    );
    let manifest_norm = normalize_export_prefix(&manifest_raw, actual_prefix, oracle_dir);
    let manifest = FileDigest {
        sha256: sha256_hex(&manifest_norm),
        bytes: manifest_norm.len(),
    };
    let oracle_manifest = &oracle_norm["manifest"];
    assert_eq!(
        manifest.bytes,
        oracle_manifest["bytes"].as_u64().expect("oracle manifest bytes") as usize,
        "manifest.json size after rewriting {actual_prefix} -> {oracle_dir}\n{}",
        String::from_utf8_lossy(&manifest_norm)
    );
    assert_eq!(
        manifest.sha256,
        oracle_manifest["sha256"].as_str().expect("oracle manifest sha256"),
        "manifest.json sha256 after rewriting {actual_prefix} -> {oracle_dir}\n{}",
        String::from_utf8_lossy(&manifest_norm)
    );

    let mut expected_files = vec!["manifest.json".to_string()];
    let scripts = oracle_norm["scripts"].as_array().expect("oracle scripts");
    for script in scripts {
        let content = &script["content"];
        if content["state"] != "exported" {
            continue;
        }
        let relative = content["relative_path"]
            .as_str()
            .expect("exported script relative_path");
        let raw = std::fs::read(output_dir.join("files").join(relative))
            .unwrap_or_else(|err| panic!("read exported script {relative}: {err}"));
        let normalized = normalize_export_prefix(&raw, actual_prefix, oracle_dir);
        assert_eq!(
            normalized.len(),
            content["bytes"].as_u64().expect("script bytes") as usize,
            "{relative} size"
        );
        assert_eq!(
            sha256_hex(&normalized),
            content["sha256"].as_str().expect("script sha256"),
            "{relative} sha256"
        );
        expected_files.push(format!("files/{relative}"));
    }
    expected_files.sort();
    assert_eq!(
        list_export_files(output_dir),
        expected_files,
        "export tree must be exactly the manifest and the oracle scripts"
    );
    manifest
}
