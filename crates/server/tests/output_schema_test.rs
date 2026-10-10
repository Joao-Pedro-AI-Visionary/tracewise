use std::collections::{HashMap, HashSet};
use rmcp::model::CallToolRequestParam;
use rmcp::model::CallToolResult;
use serde_json::json;
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

fn validate_tool_output(
    validators: &HashMap<String, jsonschema::Validator>,
    tool_name: &str,
    result: &CallToolResult,
    validated_set: &mut HashSet<String>,
) {
    let validator = validators
        .get(tool_name)
        .unwrap_or_else(|| panic!("No validator found for tool '{tool_name}'"));
    let structured = result
        .structured_content
        .as_ref()
        .unwrap_or_else(|| panic!("Tool '{tool_name}' returned None for structuredContent"));

    if let Err(first_err) = validator.validate(structured) {
        let all_errors: Vec<String> = validator
            .iter_errors(structured)
            .map(|e| format!("path: {}, error: {}", e.instance_path(), e))
            .collect();
        panic!(
            "Tool '{tool_name}' structuredContent failed schema validation:\nFirst error: {}\nAll errors:\n{}\nPayload:\n{}",
            first_err,
            all_errors.join("\n"),
            serde_json::to_string_pretty(structured).unwrap()
        );
    }

    validated_set.insert(tool_name.to_string());
}

#[tokio::test]
async fn test_all_12_tools_output_schema_validation() {
    let tools_val = tracewise_contracts::phase0_tools_value();
    let tools_arr = tools_val["tools"]
        .as_array()
        .expect("phase0_tools must have 'tools' array");

    let mut validators = HashMap::new();
    for t in tools_arr {
        let name = t["name"].as_str().unwrap().to_string();
        let schema = &t["outputSchema"];
        let validator = jsonschema::validator_for(schema)
            .unwrap_or_else(|e| panic!("Failed to compile schema for '{name}': {e}"));
        validators.insert(name, validator);
    }
    assert_eq!(validators.len(), 12, "Must have compiled schemas for 12 tools");

    let mut validated_set = HashSet::new();
    let session = BinarySession::new();

    // 1. binary_session (closed session state)
    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "binary_session".into(),
            arguments: Some(json!({}).as_object().unwrap().clone()),
        },
    )
    .await
    .expect("binary_session failed");
    validate_tool_output(&validators, "binary_session", &res, &mut validated_set);

    // Prepare temp ELF binary
    let temp_dir = std::env::temp_dir();
    let elf_path = temp_dir.join(format!("test_target_{}.elf", std::process::id()));
    let mut elf_bytes = vec![0u8; 64];
    elf_bytes[0..4].copy_from_slice(b"\x7fELF");
    elf_bytes[4] = 2; // 64-bit
    elf_bytes[5] = 1; // little endian
    elf_bytes[6] = 1; // version
    elf_bytes[18] = 62; // x86_64
    elf_bytes[19] = 0;
    std::fs::write(&elf_path, &elf_bytes).expect("Failed to write temp ELF");

    // 2. open_binary
    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "open_binary".into(),
            arguments: Some(
                json!({
                    "path": elf_path.to_str().unwrap()
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("open_binary failed");
    validate_tool_output(&validators, "open_binary", &res, &mut validated_set);

    // binary_session (open session state)
    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "binary_session".into(),
            arguments: Some(json!({}).as_object().unwrap().clone()),
        },
    )
    .await
    .expect("binary_session failed");
    validate_tool_output(&validators, "binary_session", &res, &mut validated_set);

    // 3. inspect_analysis_view
    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "inspect_analysis_view".into(),
            arguments: Some(
                json!({
                    "source": {
                        "kind": "retained-evidence",
                        "evidence_id": "ev_0000000000000000000000000000000000000000000000000000000000000000"
                    },
                    "view": { "kind": "summary" }
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("inspect_analysis_view failed");
    validate_tool_output(&validators, "inspect_analysis_view", &res, &mut validated_set);

    // 4. record_unknown
    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "record_unknown".into(),
            arguments: Some(
                json!({
                    "question": "Does main function allocate a stack frame?",
                    "severity": "medium",
                    "domain": "stack_analysis",
                    "required_authority": null,
                    "required_confidence": "observed",
                    "required_environment": null,
                    "recommended_probes": [],
                    "relationships": []
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("record_unknown failed");
    validate_tool_output(&validators, "record_unknown", &res, &mut validated_set);

    let unk_val = res.structured_content.unwrap();
    let unknown_id = unk_val["result"]["unknown_id"]
        .as_str()
        .expect("unknown_id must be string")
        .to_string();

    // 5. update_unknown
    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "update_unknown".into(),
            arguments: Some(
                json!({
                    "unknown_id": unknown_id,
                    "expected_revision": 1,
                    "status": "investigating",
                    "severity": "high",
                    "supporting_evidence_ids": [],
                    "contradicting_evidence_ids": [],
                    "required_authority": null,
                    "required_confidence": "observed",
                    "required_environment": null,
                    "recommended_probes": [],
                    "relationships": [],
                    "resolution": null
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("update_unknown failed");
    validate_tool_output(&validators, "update_unknown", &res, &mut validated_set);

    // 6. verify_unknown_resolution
    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "verify_unknown_resolution".into(),
            arguments: Some(
                json!({
                    "unknown_id": unknown_id
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("verify_unknown_resolution failed");
    validate_tool_output(&validators, "verify_unknown_resolution", &res, &mut validated_set);

    // 7. list_unknowns
    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "list_unknowns".into(),
            arguments: Some(json!({}).as_object().unwrap().clone()),
        },
    )
    .await
    .expect("list_unknowns failed");
    validate_tool_output(&validators, "list_unknowns", &res, &mut validated_set);

    // 8. export_evidence_bundle
    let bundle1_path = temp_dir.join(format!("test_bundle1_{}.json", std::process::id()));
    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "export_evidence_bundle".into(),
            arguments: Some(
                json!({
                    "path": bundle1_path.to_str().unwrap(),
                    "overwrite": true
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("export_evidence_bundle failed");
    validate_tool_output(&validators, "export_evidence_bundle", &res, &mut validated_set);

    // Export second bundle for compare_bundles
    let bundle2_path = temp_dir.join(format!("test_bundle2_{}.json", std::process::id()));
    let res_b2 = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "export_evidence_bundle".into(),
            arguments: Some(
                json!({
                    "path": bundle2_path.to_str().unwrap(),
                    "overwrite": true
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("export_evidence_bundle 2 failed");
    validate_tool_output(&validators, "export_evidence_bundle", &res_b2, &mut validated_set);

    // 9. compare_bundles
    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "compare_bundles".into(),
            arguments: Some(
                json!({
                    "left_bundle_path": bundle1_path.to_str().unwrap(),
                    "right_bundle_path": bundle2_path.to_str().unwrap(),
                    "record_pairs": []
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("compare_bundles failed");
    validate_tool_output(&validators, "compare_bundles", &res, &mut validated_set);

    // 10. import_evidence_bundle
    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "import_evidence_bundle".into(),
            arguments: Some(
                json!({
                    "path": bundle1_path.to_str().unwrap()
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("import_evidence_bundle failed");
    validate_tool_output(&validators, "import_evidence_bundle", &res, &mut validated_set);

    // 11. get_evidence_bundle
    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "get_evidence_bundle".into(),
            arguments: Some(json!({}).as_object().unwrap().clone()),
        },
    )
    .await
    .expect("get_evidence_bundle failed");
    validate_tool_output(&validators, "get_evidence_bundle", &res, &mut validated_set);

    // 12. close_binary
    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "close_binary".into(),
            arguments: Some(json!({}).as_object().unwrap().clone()),
        },
    )
    .await
    .expect("close_binary failed");
    validate_tool_output(&validators, "close_binary", &res, &mut validated_set);

    // Verify all 12 tools were validated
    let expected_names: HashSet<String> = tracewise_contracts::phase0_tool_names()
        .iter()
        .map(|s| s.to_string())
        .collect();

    assert_eq!(
        validated_set, expected_names,
        "Every one of the 12 Phase 0 tools must have its structuredContent validated"
    );

    // Cleanup temp files
    let _ = std::fs::remove_file(&elf_path);
    let _ = std::fs::remove_file(&bundle1_path);
    let _ = std::fs::remove_file(&bundle2_path);
}
