//! Passive V8 Inspector tools and static/runtime reconciliation.
//!
//! `reconcile_javascript_runtime` is deterministic: the test feeds the exact
//! Evidence the REA oracle received (`oracle_analyze_javascript_application.json`
//! and `oracle_observe_javascript_runtime.json`) and compares the whole
//! `structuredContent` with `oracle_reconcile_javascript_runtime.json`. No field
//! is ignored.
//!
//! The live tests launch `node --inspect=127.0.0.1:0 --import
//! fixtures/js/app/src/main.js fixtures/js/runtime/keepalive.cjs` (the command
//! the oracle observed) and skip when the Node binary is missing. Ignored
//! fields against the REA oracle, all process-dependent:
//! - `evidence_id` (hashes every field below)
//! - `parameters.inspector_endpoint` (random Inspector port)
//! - `parameters.target_id` and `normalized_result.target(s).target_id`
//!   (Node assigns a random UUID per process)
//! - `normalized_result.execution_contexts[].name` (contains the process id)
//! - `normalized_result.capture.metadata_bytes_retained` (counts the length
//!   of that context name, so it varies with the pid's digit count)

use std::path::PathBuf;
use std::time::{Duration, Instant};

use proc_supervisor::{ProcessSupervisor, SupervisedChild};
use rmcp::model::CallToolRequestParam;
use serde_json::{json, Value};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

const NODE: &str = "/tmp/node-v22.20.0-linux-x64/bin/node";
const FIXTURES: &str = "/workspace/tracewise/fixtures/js";

fn validate_schema(tool_name: &str, structured: &Value) {
    let tools = tracewise_contracts::phase2_tools_value();
    let tool = tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == tool_name)
        .expect("tool in phase2");
    let validator = jsonschema::validator_for(&tool["outputSchema"]).expect("schema");
    validator
        .validate(structured)
        .unwrap_or_else(|error| panic!("{tool_name} schema: {error}"));
}

fn oracle(name: &str) -> Value {
    let text = std::fs::read_to_string(format!("{FIXTURES}/oracle_{name}.json")).expect("oracle");
    let value: Value = serde_json::from_str(&text).expect("oracle json");
    value["structuredContent"].clone()
}

async fn call(session: &BinarySession, name: &str, args: Value) -> Value {
    let result = call_tool_local(
        session,
        CallToolRequestParam {
            name: name.to_string().into(),
            arguments: Some(args.as_object().unwrap().clone()),
        },
    )
    .await
    .unwrap_or_else(|error| panic!("{name}: {error}"));
    assert_ne!(result.is_error, Some(true), "{name}: {:?}", result.content);
    let structured = result.structured_content.expect("structuredContent");
    validate_schema(name, &structured);
    structured
}

fn reconcile_args(observation: Value) -> Value {
    json!({
        "static_layers": [{
            "analysis": oracle("analyze_javascript_application"),
            "runtime_mappings": [{
                "kind": "file-root",
                "root": "/workspace/tracewise/fixtures/js/runtime",
                "artifact_prefix": "runtime",
            }],
        }],
        "runtime_observations": [observation],
    })
}

#[tokio::test]
async fn reconcile_javascript_runtime_matches_oracle() {
    let session = BinarySession::new();
    let structured = call(
        &session,
        "reconcile_javascript_runtime",
        reconcile_args(oracle("observe_javascript_runtime")),
    )
    .await;
    assert_eq!(structured, oracle("reconcile_javascript_runtime"));
}

#[tokio::test]
async fn reconcile_rejects_tampered_and_duplicate_evidence() {
    let session = BinarySession::new();
    let mut tampered = oracle("observe_javascript_runtime");
    tampered["normalized_result"]["target"]["attached"] = json!(true);
    let error = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "reconcile_javascript_runtime".into(),
            arguments: Some(reconcile_args(tampered).as_object().unwrap().clone()),
        },
    )
    .await
    .expect_err("tampered Evidence must be rejected");
    assert!(error.message.contains("not authentic"), "{error}");

    let mut duplicate = reconcile_args(oracle("observe_javascript_runtime"));
    let observation = duplicate["runtime_observations"][0].clone();
    duplicate["runtime_observations"] = json!([observation.clone(), observation]);
    let error = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "reconcile_javascript_runtime".into(),
            arguments: Some(duplicate.as_object().unwrap().clone()),
        },
    )
    .await
    .expect_err("duplicate runtime Evidence must be rejected");
    assert!(error.message.contains("must be unique"), "{error}");
}

/// A Node process with its Inspector on a kernel-assigned loopback port.
struct NodeInspector {
    endpoint: String,
    child: Option<SupervisedChild>,
    stderr_path: PathBuf,
}

impl NodeInspector {
    fn launch() -> Option<Self> {
        if !std::path::Path::new(NODE).exists() {
            eprintln!("skipping: {NODE} is missing");
            return None;
        }
        let stderr_path = std::env::temp_dir().join(format!(
            "tracewise-node-inspect-{}-{:?}.log",
            std::process::id(),
            std::thread::current().id()
        ));
        // `exec` keeps the supervised process group at a single Node process;
        // the shell only redirects stderr, where Node prints the chosen port.
        let script = format!(
            "exec {NODE} --inspect=127.0.0.1:0 --import {FIXTURES}/app/src/main.js {FIXTURES}/runtime/keepalive.cjs 2>'{}'",
            stderr_path.display()
        );
        let mut supervisor = ProcessSupervisor::new("/bin/sh");
        supervisor.null_stdio();
        supervisor.args(["-c", script.as_str()]);
        let child = supervisor.spawn().expect("spawn node");
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let log = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            if let Some(port) = listening_port(&log) {
                return Some(Self {
                    endpoint: format!("http://127.0.0.1:{port}"),
                    child: Some(child),
                    stderr_path,
                });
            }
            assert!(Instant::now() < deadline, "node did not report its Inspector port: {log}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn listening_port(log: &str) -> Option<u16> {
    let rest = &log[log.find("ws://127.0.0.1:")? + "ws://127.0.0.1:".len()..];
    rest[..rest.find('/')?].parse().ok()
}

impl Drop for NodeInspector {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill_group();
        }
        let _ = std::fs::remove_file(&self.stderr_path);
    }
}

fn strip_process_fields(mut value: Value) -> Value {
    value.as_object_mut().unwrap().remove("evidence_id");
    let parameters = value["parameters"].as_object_mut().unwrap();
    parameters.remove("inspector_endpoint");
    parameters.remove("target_id");
    let result = value["normalized_result"].as_object_mut().unwrap();
    if let Some(targets) = result.get_mut("targets").and_then(Value::as_array_mut) {
        for target in targets {
            target.as_object_mut().unwrap().remove("target_id");
        }
    }
    if let Some(target) = result.get_mut("target").and_then(Value::as_object_mut) {
        target.remove("target_id");
    }
    if let Some(contexts) = result.get_mut("execution_contexts").and_then(Value::as_array_mut) {
        for context in contexts {
            context.as_object_mut().unwrap().remove("name");
        }
    }
    if let Some(capture) = result.get_mut("capture").and_then(Value::as_object_mut) {
        capture.remove("metadata_bytes_retained");
    }
    value
}

#[tokio::test]
async fn runtime_inspector_tools_match_oracle() {
    let Some(node) = NodeInspector::launch() else {
        return;
    };
    let session = BinarySession::new();

    let listed = call(
        &session,
        "list_javascript_runtime_targets",
        json!({ "inspector_endpoint": node.endpoint }),
    )
    .await;
    assert_eq!(listed["parameters"]["inspector_endpoint"], json!(node.endpoint));
    let targets = listed["normalized_result"]["targets"].as_array().expect("targets");
    assert_eq!(targets.len(), 1);
    let target_id = targets[0]["target_id"].as_str().expect("target id").to_string();
    assert_eq!(
        strip_process_fields(listed.clone()),
        strip_process_fields(oracle("list_javascript_runtime_targets"))
    );

    let observed = call(
        &session,
        "observe_javascript_runtime",
        json!({
            "inspector_endpoint": node.endpoint,
            "target_id": target_id,
            "runtime_kind": "node",
        }),
    )
    .await;
    assert_eq!(observed["normalized_result"]["target"]["target_id"], json!(target_id));
    let name = observed["normalized_result"]["execution_contexts"][0]["name"]
        .as_str()
        .expect("context name");
    assert!(name.starts_with(NODE), "{name}");
    assert_eq!(
        strip_process_fields(observed.clone()),
        strip_process_fields(oracle("observe_javascript_runtime"))
    );

    // The live capture reconciles exactly like the oracle's recorded one.
    let reconciled = call(&session, "reconcile_javascript_runtime", reconcile_args(observed)).await;
    let expected = oracle("reconcile_javascript_runtime");
    for key in ["summary", "static_load_states", "coverage", "limitations"] {
        if key == "static_load_states" {
            let project = |value: &Value| -> Vec<Value> {
                value.as_array().unwrap().iter().map(|state| json!([state["static_node_id"], state["status"], state["reason"]])).collect()
            };
            assert_eq!(
                project(&reconciled["normalized_result"][key]),
                project(&expected["normalized_result"][key])
            );
        } else {
            assert_eq!(reconciled["normalized_result"][key], expected["normalized_result"][key], "{key}");
        }
    }
}

#[tokio::test]
async fn observe_rejects_unknown_target_as_tool_error() {
    let Some(node) = NodeInspector::launch() else {
        return;
    };
    let session = BinarySession::new();
    let result = call_tool_local(
        &session,
        CallToolRequestParam {
            name: "observe_javascript_runtime".into(),
            arguments: Some(
                json!({ "inspector_endpoint": node.endpoint, "target_id": "missing" })
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        },
    )
    .await
    .expect("tool result");
    assert_eq!(result.is_error, Some(true));
    let text = format!("{:?}", result.content);
    assert!(text.contains("target_not_found"), "{text}");
}
