//! Managed workflow tools (`compare_managed_members`,
//! `verify_managed_native_boundaries`, `import_managed_reconstruction`,
//! `project_managed_application_graph`): parity with the REA oracle.
//!
//! Oracle: REA @0fa0b04 run through an MCP stdio session (`fixtures/rea_oracle.py`
//! protocol). `fixtures/managed/workflow_scenarios.json` lists the requests with
//! symbolic inputs (`$ev` = a stored inspection Evidence from
//! `oracle_inspect.json`, `$native` = crafted `inspect_macho`/`analyze_function`
//! Evidence from `workflow_inputs_native.json`, `$mutate` = the same record with
//! a field changed and the identifier left stale). `oracle_workflows.json` holds
//! REA's answers. Each scenario ran in a fresh REA session followed by
//! `list_unknowns`; the `sequences` share one session to cover the residual
//! unknown registry (a repeated unknown is a revision conflict).
//!
//! The inputs are self-contained Evidence, so nothing depends on the checkout
//! path and the comparison is exact: every field of `structuredContent`
//! including `evidence_id`, the unknown records, and the error envelopes.
//! Ignored fields: none. Differences that are known and not asserted: the text of
//! SDK-level schema errors for structurally invalid requests (zod wording vs
//! JSON-Schema wording) is only checked for the cases listed in the scenarios.

mod managed_android_support;

use std::path::PathBuf;

use rmcp::model::CallToolRequestParam;
use serde_json::{json, Value};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/managed").canonicalize().expect("fixtures/managed")
}

fn load(name: &str) -> Value {
    let text = managed_android_support::read_fixture_text(&fixture_dir().join(name));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: {e}"))
}

struct Inputs {
    inspect: Value,
    native: Value,
}

fn resolve(inputs: &Inputs, value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            if let Some(reference) = map.get("$ev").and_then(Value::as_str) {
                let (file, tool) = reference.split_once('/').expect("file/tool");
                return inputs.inspect[file][tool]["structuredContent"].clone();
            }
            if let Some(name) = map.get("$native").and_then(Value::as_str) {
                return inputs.native[name].clone();
            }
            if let Some(base) = map.get("$mutate") {
                let mut base = resolve(inputs, base);
                for (key, value) in map["set"].as_object().unwrap() {
                    base[key] = value.clone();
                }
                return base;
            }
            Value::Object(map.iter().map(|(k, v)| (k.clone(), resolve(inputs, v))).collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(|i| resolve(inputs, i)).collect()),
        other => other.clone(),
    }
}

fn schema_for(tool: &str) -> jsonschema::Validator {
    let catalog: Value = serde_json::from_str(tracewise_contracts::PHASE3_TOOLS_JSON).unwrap();
    let definition = catalog["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == tool)
        .unwrap_or_else(|| panic!("{tool} is not in the phase 3 catalog"));
    jsonschema::validator_for(&definition["outputSchema"]).unwrap_or_else(|e| panic!("{tool}: output schema: {e}"))
}

async fn call(session: &BinarySession, tool: &str, args: &Value) -> Value {
    let result = call_tool_local(
        session,
        CallToolRequestParam { name: tool.to_string().into(), arguments: Some(args.as_object().cloned().unwrap_or_default()) },
    )
    .await
    .unwrap_or_else(|error| panic!("{tool}: {error}"));
    if result.is_error == Some(true) {
        let text = result.content[0].as_text().map(|t| t.text.clone()).unwrap_or_default();
        return json!({ "error": text });
    }
    json!({ "structuredContent": result.structured_content.expect("structuredContent") })
}

fn same_result(label: &str, actual: &Value, expected: &Value) {
    match (actual.get("error"), expected.get("error")) {
        (Some(got), Some(want)) => {
            let (got, want) = (got.as_str().unwrap(), want.as_str().unwrap());
            match (serde_json::from_str::<Value>(got), serde_json::from_str::<Value>(want)) {
                (Ok(g), Ok(w)) => assert_eq!(g, w, "{label}: error envelope"),
                _ => assert_eq!(got, want, "{label}: error text"),
            }
        }
        (None, None) => assert_eq!(actual["structuredContent"], expected["structuredContent"], "{label}"),
        (got, want) => panic!("{label}: expected {want:?}, got {got:?}"),
    }
}

#[tokio::test]
async fn managed_workflows_match_rea_oracle() {
    let inputs = Inputs { inspect: load("oracle_inspect.json"), native: load("workflow_inputs_native.json") };
    let scenarios = load("workflow_scenarios.json");
    let oracle = load("oracle_workflows.json");
    let specs = scenarios["scenarios"].as_array().unwrap();
    let answers = oracle["scenarios"].as_array().unwrap();
    assert_eq!(specs.len(), answers.len());
    assert_eq!(specs.len(), 95, "workflow scenarios");
    let mut with_unknowns = 0;
    for (spec, answer) in specs.iter().zip(answers) {
        assert_eq!(spec["name"], answer["name"]);
        let label = spec["name"].as_str().unwrap();
        let tool = spec["tool"].as_str().unwrap();
        let session = BinarySession::new();
        let actual = call(&session, tool, &resolve(&inputs, &spec["args"])).await;
        same_result(label, &actual, &answer["result"]);
        if let Some(structured) = actual.get("structuredContent") {
            schema_for(tool).validate(structured).unwrap_or_else(|e| panic!("{label}: output schema: {e}"));
        }
        let unknowns = call(&session, "list_unknowns", &json!({})).await;
        same_result(&format!("{label} [unknowns]"), &unknowns, &answer["unknowns"]);
        if answer["unknowns"]["structuredContent"]["result"]["total"].as_u64().unwrap_or(0) > 0 {
            with_unknowns += 1;
        }
    }
    assert_eq!(with_unknowns, 22, "scenarios that recorded residual unknowns");
}

#[tokio::test]
async fn managed_workflow_sessions_match_rea_oracle() {
    let inputs = Inputs { inspect: load("oracle_inspect.json"), native: load("workflow_inputs_native.json") };
    let scenarios = load("workflow_scenarios.json");
    let oracle = load("oracle_workflows.json");
    let sequences = scenarios["sequences"].as_array().unwrap();
    let answers = oracle["sequences"].as_array().unwrap();
    assert_eq!(sequences.len(), answers.len());
    assert_eq!(sequences.len(), 3, "workflow sequences");
    for (sequence, answer) in sequences.iter().zip(answers) {
        let session = BinarySession::new();
        let steps = sequence["steps"].as_array().unwrap();
        let results = answer["results"].as_array().unwrap();
        assert_eq!(steps.len(), results.len(), "{}: oracle answers", sequence["name"]);
        for (index, (step, expected)) in steps.iter().zip(results).enumerate() {
            let tool = step["tool"].as_str().unwrap();
            let mut args = resolve(&inputs, &step["args"]);
            if tool == "export_evidence_bundle" {
                let path = std::env::temp_dir().join(format!("tracewise-managed-bundle-{}.json", std::process::id()));
                args = json!({ "path": path.to_string_lossy(), "overwrite": true });
                let actual = call(&session, tool, &args).await;
                assert!(actual.get("error").is_none(), "{}: bundle export", sequence["name"]);
                let _ = std::fs::remove_file(path);
                continue;
            }
            let actual = call(&session, tool, &args).await;
            same_result(&format!("{} step {index} {tool}", sequence["name"]), &actual, expected);
        }
    }
}
