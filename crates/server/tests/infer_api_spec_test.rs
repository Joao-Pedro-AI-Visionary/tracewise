use std::path::Path;

use rmcp::model::CallToolRequestParam;
use serde_json::{json, Value};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

const DEMO_HAR: &str = "/workspace/tracewise/fixtures/web/demo.har";
const SNAPSHOT: &str = "/workspace/tracewise/fixtures/web/infer_api_spec_demo.openapi.json";

fn validate_output_schema(structured: &Value) {
    let tools_val = tracewise_contracts::tracewise_tools_value();
    let tool = tools_val["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .find(|tool| tool["name"] == "infer_api_spec")
        .expect("infer_api_spec schema");
    let validator = jsonschema::validator_for(&tool["outputSchema"])
        .unwrap_or_else(|err| panic!("outputSchema failed to compile: {err}"));
    if let Err(first) = validator.validate(structured) {
        let errors: Vec<String> = validator
            .iter_errors(structured)
            .map(|err| format!("path: {}, error: {err}", err.instance_path()))
            .collect();
        panic!(
            "structuredContent failed outputSchema validation:\n{first}\n{}",
            errors.join("\n")
        );
    }
}

fn confidence_values(value: &Value, found: &mut std::collections::BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            if let Some(confidence) = map.get("x-tracewise-confidence").and_then(|v| v.as_str()) {
                found.insert(confidence.to_string());
            }
            for child in map.values() {
                confidence_values(child, found);
            }
        }
        Value::Array(items) => {
            for child in items {
                confidence_values(child, found);
            }
        }
        _ => {}
    }
}

#[tokio::test]
async fn test_infer_api_spec_demo_har() {
    let session = BinarySession::new();
    let output_path = std::env::temp_dir().join(format!(
        "tracewise-infer-api-spec-{}.json",
        std::process::id()
    ));

    let res = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "infer_api_spec".into(),
            arguments: Some(
                json!({
                    "capture_path": DEMO_HAR,
                    "output_path": output_path,
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        },
    )
    .await
    .expect("infer_api_spec failed");

    let output_str = serde_json::to_string(&res).expect("serialize result");
    assert!(!output_str.contains("SECRET-"), "tool output leaked a credential");

    let structured = res
        .structured_content
        .as_ref()
        .expect("structured content");
    validate_output_schema(structured);
    assert_eq!(structured["predicate_type"], "tracewise.api-spec");
    assert_eq!(structured["confidence"], "inferred");
    assert_eq!(structured["operation"], "infer_api_spec");

    let openapi = &structured["normalized_result"];
    assert_eq!(openapi["openapi"], "3.1.0");
    let paths = openapi["paths"].as_object().expect("paths");
    assert!(
        paths.contains_key("/api/todos/{id}"),
        "numeric ids must template to one path: {paths:?}"
    );
    assert!(!paths.contains_key("/api/todos/1"));
    assert!(!paths.contains_key("/api/todos/99"));
    let spec_text = serde_json::to_string(openapi).unwrap();
    assert!(!spec_text.contains("/api/todos/1"));
    assert!(!spec_text.contains("/api/todos/99"));
    assert!(!spec_text.contains("SECRET-"));

    for (path, item) in paths {
        for method in ["get", "post", "put", "patch", "delete", "head", "options", "trace"] {
            let Some(operation) = item.get(method) else {
                continue;
            };
            let evidence = operation["x-tracewise-evidence"]
                .as_array()
                .unwrap_or_else(|| panic!("{method} {path} missing x-tracewise-evidence"));
            assert!(!evidence.is_empty(), "{method} {path} has empty evidence");
            let confidence = operation["x-tracewise-confidence"]
                .as_str()
                .unwrap_or_else(|| panic!("{method} {path} missing confidence"));
            assert!(
                confidence == "observed" || confidence == "inferred",
                "{method} {path} confidence {confidence}"
            );
        }
    }

    let todo = &openapi["paths"]["/api/todos/{id}"]["get"];
    assert_eq!(todo["x-tracewise-confidence"], "inferred");
    let id_param = todo["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|param| param["name"] == "id" && param["in"] == "path")
        .expect("path param id");
    assert_eq!(id_param["required"], true);
    assert_eq!(id_param["x-tracewise-confidence"], "inferred");
    assert_eq!(id_param["schema"]["type"], "integer");
    let ordinals: Vec<u64> = id_param["x-tracewise-evidence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["ordinal"].as_u64().unwrap())
        .collect();
    assert!(ordinals.contains(&2) && ordinals.contains(&4), "{ordinals:?}");

    let title = &todo["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["title"];
    assert_eq!(title["type"], "string");
    assert_eq!(title["x-tracewise-confidence"], "observed");
    assert!(!title["x-tracewise-evidence"].as_array().unwrap().is_empty());

    assert_eq!(
        openapi["paths"]["/api/me"]["get"]["x-tracewise-confidence"],
        "observed"
    );
    let limit = openapi["paths"]["/api/todos"]["get"]["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|param| param["name"] == "limit")
        .expect("limit query param");
    assert_eq!(limit["in"], "query");
    assert_eq!(limit["schema"]["type"], "integer");
    assert_eq!(
        openapi["components"]["securitySchemes"]["authorization"]["scheme"],
        "unknown"
    );

    let mut confidences = std::collections::BTreeSet::new();
    confidence_values(openapi, &mut confidences);
    assert!(confidences.contains("observed"), "{confidences:?}");
    assert!(confidences.contains("inferred"), "{confidences:?}");
    assert!(confidences.iter().all(|c| c == "observed" || c == "inferred"));

    let written = std::fs::read_to_string(&output_path).expect("output file");
    assert!(!written.contains("SECRET-"));
    let written_value: Value = serde_json::from_str(&written).unwrap();
    assert_eq!(&written_value, openapi);
    let _ = std::fs::remove_file(&output_path);

    let unknowns = session
        .ledger
        .lock()
        .unwrap()
        .list_unknowns(None, None, Some("tracewise.api-spec"));
    assert!(!unknowns.is_empty(), "residual unknowns must be recorded");
    assert!(
        unknowns.iter().any(|unknown| unknown.question.contains("Authorization")),
        "auth scheme must be an unknown: {unknowns:?}"
    );
    let unknown_text = serde_json::to_string(&unknowns).unwrap();
    assert!(!unknown_text.contains("SECRET-"));
    let questions: Vec<&str> = openapi["x-tracewise-unknowns"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(questions.len(), unknowns.len());

    let pretty = serde_json::to_string_pretty(openapi).unwrap() + "\n";
    if !Path::new(SNAPSHOT).exists() {
        std::fs::write(SNAPSHOT, &pretty).unwrap();
    }
    let expected: Value = serde_json::from_str(
        &std::fs::read_to_string(SNAPSHOT).expect("openapi snapshot"),
    )
    .unwrap();
    assert_eq!(openapi, &expected, "OpenAPI snapshot drifted");

    let source_id = structured["evidence_links"][0]
        .as_str()
        .expect("source evidence")
        .to_string();
    let replay = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "infer_api_spec".into(),
            arguments: Some(
                json!({ "evidence_ids": [source_id] })
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        },
    )
    .await
    .expect("infer from evidence_ids");
    let replay_text = serde_json::to_string(&replay).unwrap();
    assert!(!replay_text.contains("SECRET-"));
    let replay_doc = &replay.structured_content.as_ref().unwrap()["normalized_result"];
    assert_eq!(replay_doc, openapi);
}
