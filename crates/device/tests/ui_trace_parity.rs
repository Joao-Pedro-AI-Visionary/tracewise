//! `trace_native_ui_action` against REA's own compiled workflow.
//!
//! The real tool needs a Mach-O target, Interface Builder archives and a
//! Ghidra/Hopper engine, none of which exist on this Linux host. REA tests the
//! workflow with an in-memory `AnalysisOperationPort`; this test does the same
//! in both implementations: every scenario scripts the answers of
//! `decode_interface_builder`, `inspect_native_dispatch_metadata`, `list_names`,
//! `procedure_address`, `procedure_references` and `procedure_callees`, then
//! runs
//! - REA's compiled `EnhancedTools.execute("trace_native_ui_action", ...)`
//!   (`fixtures/native_trace/oracle_trace.mjs`), and
//! - `tracewise_device::ui_trace::trace_native_ui_action`,
//!
//! and compares, with nothing ignored, the returned trace (or the projected
//! error) and the ordered list of port calls with their parameters. The 13
//! scenarios of REA's own `EnhancedNativeInvestigation.test.ts` are replayed
//! first, followed by scenarios for the typed-reference reader, the dispatch
//! join (resolved, ambiguous, category, unresolved), bounds and error handling.
//!
//! [Não verificável] here: the end-to-end tool against a real binary, because
//! the engines that answer these operations (Ghidra/Hopper/IDA) and the macOS
//! `ibtool` decoding are outside this environment. What is proven is the
//! workflow logic, byte for byte, over the operation contract.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

use serde_json::{json, Value};
use tracewise_device::native;
use tracewise_device::ui_trace::{trace_native_ui_action, AnalysisPort, PortExecution, TraceInput};
use tracewise_device::ToolError;

const NODE: &str = "/tmp/node-v22.20.0-linux-x64/bin/node";
const T: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn evidence() -> Value {
    json!([{
        "kind": "interface_builder_resource",
        "description": "Fixture UI archive",
        "location": { "address": null, "file_offset": null },
        "artifact_path": null,
        "artifact_sha256": null,
    }])
}

fn node(id: &str, kind: &str, name: &str, attributes: Value) -> Value {
    json!({ "id": id, "kind": kind, "name": name, "location": null, "attributes": attributes, "evidence": evidence() })
}

fn edge(id: &str, from: &str, to: &str, relation: &str) -> Value {
    json!({
        "id": id, "from": from, "to": to, "relation": relation, "resolution": "observed",
        "evidence": evidence(), "limitations": [],
    })
}

fn base_graph() -> Value {
    json!({
        "target_sha256": T,
        "provider": { "id": "fixture", "version": "1", "tool_version": "fixture" },
        "nodes": [
            node("button", "control", "Build", json!({"class_name": "UIButton", "interface_builder_object_id": "button"})),
            node("action", "action", "buildTapped:", json!({"selector": "buildTapped:"})),
            node("controller", "view_controller", "BuildViewController", json!({"class_name": "BuildViewController"})),
            node("selector", "objc_selector", "buildTapped:", json!({})),
        ],
        "edges": [
            edge("button-action", "button", "action", "target_action"),
            edge("action-selector", "action", "selector", "target_action"),
            edge("action-controller", "action", "controller", "target_action"),
        ],
        "coverage": [],
        "truncated": false,
    })
}

fn document() -> Value {
    json!({
        "relative_path": "Base.lproj/Main.nib",
        "archive_sha256": "b".repeat(64),
        "document_kind": "nib",
        "object_count": 4,
        "connection_count": 3,
        "hierarchy_complete": true,
    })
}

fn ib_result(graph: Value) -> Value {
    json!({ "target_sha256": T, "documents": [document()], "graph": graph, "limitations": [] })
}

fn subject(sha: &str) -> Value {
    json!({ "sha256": sha, "path": "/fixture.app", "format": "mach-o", "architecture": "arm64" })
}

fn capability(reason: &str) -> Value {
    json!({ "error": { "kind": "capability", "reason": reason } })
}

fn ok_with(result: Value, sha: &str) -> Value {
    json!({ "ok": result, "subject": subject(sha) })
}

fn matched(procedure: &str, rule: Value) -> Value {
    let mut rule = rule;
    rule["match"] = json!({ "procedure": procedure });
    rule
}

fn defaults() -> serde_json::Map<String, Value> {
    let mut map = serde_json::Map::new();
    map.insert("procedure_address".into(), json!([capability("Seed not available")]));
    map.insert("procedure_references".into(), json!([capability("No typed reference reader in fixture")]));
    map.insert("inspect_native_dispatch_metadata".into(), json!([capability("No binary metadata reader in fixture")]));
    map.insert("decode_interface_builder".into(), json!([ok_with(ib_result(base_graph()), T)]));
    map.insert(
        "list_names".into(),
        json!([ok_with(json!([{ "address": "0x1000", "name": "-[BuildViewController buildTapped:]" }]), T)]),
    );
    map.insert(
        "procedure_callees".into(),
        json!([matched("0x1000", ok_with(json!(["0x2000"]), T)), ok_with(json!([]), T)]),
    );
    map
}

struct Scenario {
    name: &'static str,
    input: Value,
    overrides: Vec<(&'static str, Value)>,
}

fn scenario(name: &'static str, input: Value, overrides: Vec<(&'static str, Value)>) -> Scenario {
    Scenario { name, input, overrides }
}

fn to_json(scenarios: &[Scenario]) -> Value {
    Value::Array(
        scenarios
            .iter()
            .map(|s| {
                let mut responses = defaults();
                for (operation, rules) in &s.overrides {
                    responses.insert((*operation).to_string(), rules.clone());
                }
                json!({ "name": s.name, "input": s.input, "responses": responses })
            })
            .collect(),
    )
}

fn metadata_result(implementations: Value) -> Value {
    json!({
        "target_sha256": T,
        "provider": { "id": "fixture", "name": "Fixture", "version": "1" },
        "analysis_profile_digest": null,
        "result": {
            "objc_classes": [], "objc_protocols": [], "objc_categories": [], "swift_decls": [], "objc_ivars": [],
            "objc_protocol_records": [], "objc_dispatch_implementations": implementations,
            "swift_conformances": [], "swift_dispatch_slots": [], "swift_symbols": [], "relative_pointers": [],
            "coverage": [], "db_save_result": null,
        },
    })
}

fn implementation(class_name: &str, selector: &str, address: Option<&str>, status: &str) -> Value {
    json!({
        "class_name": class_name,
        "selector": selector,
        "method_type": "instance",
        "implementation_address": address,
        "location": { "address": address, "file_offset": 64 },
        "decode": { "status": status, "reason": null },
        "evidence": [{
            "kind": "binary_metadata",
            "description": format!("Encoded method {class_name} {selector}"),
            "location": { "address": address, "file_offset": 64 },
            "artifact_path": "Fixture.app/Contents/MacOS/Fixture",
            "artifact_sha256": "c".repeat(64),
        }],
    })
}

fn typed_reference(source: &str, target: &str, target_procedure: Option<&str>, call: bool, indirect: bool, computed: bool) -> Value {
    json!({
        "source_address": source,
        "target_address": target,
        "source_procedure": null,
        "target_procedure": target_procedure.map(|a| json!({ "address": a })),
        "kind": {
            "available": true, "provenance": "fixture", "type": "UNCONDITIONAL_CALL", "flow": true, "call": call,
            "jump": false, "data": false, "read": false, "write": false, "indirect": indirect, "computed": computed,
            "conditional": false, "terminal": false, "primary": true, "operand_index": 0, "external": false,
        },
    })
}

fn typed_references(kinds_available: bool, references: Vec<Value>, unresolved: Vec<Value>) -> Value {
    json!({ "reference_kinds_available": kinds_available, "references": references, "unresolved_calls": unresolved })
}

fn deep_graph() -> Value {
    let mut graph = base_graph();
    graph["nodes"].as_array_mut().unwrap().extend([
        node("view", "view", "Container", json!({})),
        node("nested-view", "view", "Nested container", json!({})),
    ]);
    graph["edges"].as_array_mut().unwrap().extend([
        edge("controller-view", "controller", "view", "contains"),
        edge("view-nested-view", "view", "nested-view", "contains"),
    ]);
    graph
}

fn scenarios() -> Vec<Scenario> {
    let names_5000: Vec<Value> = (0..5000)
        .map(|index| json!({ "address": format!("0x{:x}", index + 1), "name": format!("unrelated_symbol_{index}") }))
        .chain([json!({ "address": "0x2000", "name": "-[BuildViewController buildTapped:]" })])
        .collect();
    let mut duplicate = base_graph();
    let mut second = duplicate["nodes"][1].clone();
    second["id"] = json!("second-action");
    duplicate["nodes"].as_array_mut().unwrap().push(second);
    let mut bounded = base_graph();
    bounded["coverage"] = json!([{ "facet": "objects:Main.nib", "status": "partial", "reason": "object_limit_reached", "examined": 2, "omitted": 1 }]);
    bounded["truncated"] = json!(true);
    let two_actions = {
        let mut graph = base_graph();
        graph["nodes"].as_array_mut().unwrap().push(node("action2", "action", "other:", json!({"selector": "other:"})));
        graph["edges"].as_array_mut().unwrap().push(edge("button-action2", "button", "action2", "target_action"));
        graph
    };
    let seed = |address: &str, sha: &str| json!([ok_with(json!(address), sha)]);
    let build = json!({ "action": "buildTapped:" });
    vec![
        // --- REA's EnhancedNativeInvestigation.test.ts, replayed ---
        scenario("native seed without UI connection", json!({"action": "0x1000"}), vec![("procedure_address", seed("0x1000", T))]),
        scenario("evidence path from active app", build.clone(), vec![]),
        scenario("handler traversal depth with deeper UI branch", json!({"action": "buildTapped:", "max_depth": 3}),
            vec![("decode_interface_builder", json!([ok_with(ib_result(deep_graph()), T)]))]),
        scenario("control object id", json!({"action": "button"}), vec![]),
        scenario("different target identities", build.clone(), vec![("list_names", json!([ok_with(json!([]), &"c".repeat(64))]))]),
        scenario("ambiguous selector", build.clone(),
            vec![("decode_interface_builder", json!([ok_with(json!({"target_sha256": T, "documents": [], "graph": duplicate, "limitations": []}), T)]))]),
        scenario("decoder truncation kept when action absent", json!({"action": "missing-selector"}),
            vec![("decode_interface_builder", json!([ok_with(ib_result(bounded), T)]))]),
        scenario("cancellation during callee expansion", build.clone(),
            vec![("procedure_callees", json!([{ "error": { "kind": "cancelled" } }]))]),
        scenario("callees left by the edge limit", json!({"action": "buildTapped:", "max_depth": 4, "max_edges": 5}),
            vec![("procedure_callees", json!([matched("0x1000", ok_with(json!(["0x2000", "0x2001", "0x2002"]), T)), ok_with(json!([]), T)]))]),
        scenario("unresolved dispatch evidence", build.clone(), vec![("list_names", json!([ok_with(json!([]), T)]))]),
        scenario("cancellation while decoding archives", build.clone(),
            vec![("decode_interface_builder", json!([{ "error": { "kind": "cancelled" } }]))]),
        scenario("handler after the former inventory limit", build.clone(), vec![("list_names", json!([ok_with(Value::Array(names_5000), T)]))]),
        scenario("edges removed with nodes", json!({"action": "missing-selector", "max_nodes": 1}), vec![]),
        // --- typed reference reader ---
        scenario("typed direct and indirect references", build.clone(), vec![
            ("procedure_references", json!([
                matched("0x1000", ok_with(typed_references(true, vec![
                    typed_reference("0x1004", "0x3000", Some("0x3000"), true, false, false),
                    typed_reference("0x1008", "0x3100", None, true, true, false),
                    typed_reference("0x100c", "0x3200", None, true, false, true),
                    typed_reference("0x1010", "0x3300", None, false, false, false),
                ], vec![json!({"address": "0x1014", "reason": "register call"})]), T)),
                ok_with(typed_references(true, vec![], vec![]), T),
            ])),
        ]),
        scenario("ambiguous call site", build.clone(), vec![
            ("procedure_references", json!([
                matched("0x1000", ok_with(typed_references(true, vec![
                    typed_reference("0x1004", "0x3000", None, true, false, false),
                    typed_reference("0x1004", "0x3100", None, true, false, false),
                ], vec![]), T)),
                ok_with(typed_references(true, vec![], vec![]), T),
            ])),
        ]),
        scenario("untyped references fall back to callees", build.clone(), vec![
            ("procedure_references", json!([ok_with(typed_references(false, vec![], vec![]), T)])),
        ]),
        scenario("references with unavailable kinds fall back", build.clone(), vec![
            ("procedure_references", json!([ok_with(typed_references(false, vec![json!({
                "source_address": "0x1004", "target_address": "0x3000", "source_procedure": null, "target_procedure": null,
                "kind": { "available": false, "reason": "no kinds" },
            })], vec![]), T)])),
        ]),
        scenario("invalid typed references", build.clone(), vec![
            ("procedure_references", json!([ok_with(json!({"references": 5}), T)])),
        ]),
        scenario("references fail without capability error", build.clone(), vec![
            ("procedure_references", json!([{ "error": { "kind": "output", "reason": "boom" } }])),
        ]),
        scenario("references unlimited by edge bound", json!({"action": "buildTapped:", "max_edges": 4}), vec![
            ("procedure_references", json!([
                matched("0x1000", ok_with(typed_references(true, vec![
                    typed_reference("0x1004", "0x3000", None, true, false, false),
                    typed_reference("0x1008", "0x3100", None, true, false, false),
                ], vec![json!({"address": "0x1014", "reason": "register call"}), json!({"address": "0x1018", "reason": "vtable"})]), T)),
                ok_with(typed_references(true, vec![], vec![]), T),
            ])),
        ]),
        scenario("node bound during expansion", json!({"action": "buildTapped:", "max_nodes": 6}), vec![
            ("procedure_callees", json!([matched("0x1000", ok_with(json!(["0x2000", "0x2001", "0x2002"]), T)), ok_with(json!([]), T)])),
        ]),
        scenario("callees invalid", build.clone(), vec![("procedure_callees", json!([ok_with(json!({"callees": [1]}), T)]))]),
        scenario("callees wrapped", build.clone(), vec![("procedure_callees", json!([ok_with(json!({"callees": ["0x2000", "0x2100"]}), T)]))]),
        scenario("callees failure becomes unknown edge", build.clone(), vec![
            ("procedure_callees", json!([matched("0x1000", json!({ "error": { "kind": "timeout" } })), ok_with(json!([]), T)])),
        ]),
        scenario("callees unsupported target", build.clone(), vec![
            ("procedure_callees", json!([matched("0x1000", json!({ "error": { "kind": "unsupported", "reason": "no such procedure" } })), ok_with(json!([]), T)])),
        ]),
        scenario("max depth zero", json!({"action": "buildTapped:", "max_depth": 0}), vec![]),
        // --- binary metadata and the dispatch join ---
        scenario("binary metadata resolves handler", build.clone(), vec![
            ("inspect_native_dispatch_metadata", json!([ok_with(metadata_result(json!([implementation("BuildViewController", "buildTapped:", Some("0x1000"), "decoded")])), T)])),
        ]),
        scenario("binary metadata partial decode is inferred", build.clone(), vec![
            ("inspect_native_dispatch_metadata", json!([ok_with(metadata_result(json!([implementation("BuildViewController", "buildTapped:", Some("0x1000"), "partial")])), T)])),
        ]),
        scenario("category suffix is ignored", build.clone(), vec![
            ("inspect_native_dispatch_metadata", json!([ok_with(metadata_result(json!([implementation("BuildViewController(Extras)", "buildTapped:", Some("0x1000"), "decoded")])), T)])),
        ]),
        scenario("ambiguous implementations", build.clone(), vec![
            ("inspect_native_dispatch_metadata", json!([ok_with(metadata_result(json!([
                implementation("BuildViewController(One)", "buildTapped:", Some("0x1000"), "decoded"),
                implementation("BuildViewController(Two)", "buildTapped:", Some("0x1100"), "decoded"),
            ])), T)])),
        ]),
        scenario("implementation without address", build.clone(), vec![
            ("inspect_native_dispatch_metadata", json!([ok_with(metadata_result(json!([implementation("BuildViewController", "buildTapped:", None, "partial")])), T)])),
        ]),
        scenario("other class implements the selector", build.clone(), vec![
            ("inspect_native_dispatch_metadata", json!([ok_with(metadata_result(json!([implementation("Other", "buildTapped:", Some("0x1000"), "decoded")])), T)])),
        ]),
        scenario("metadata without target identity", build.clone(), vec![
            ("inspect_native_dispatch_metadata", json!([ok_with({
                let mut meta = metadata_result(json!([]));
                meta["target_sha256"] = Value::Null;
                meta
            }, T)])),
        ]),
        scenario("metadata reader fails with another error", build.clone(), vec![
            ("inspect_native_dispatch_metadata", json!([{ "error": { "kind": "protocol" } }])),
        ]),
        scenario("name inventory reader fails", build.clone(), vec![("list_names", json!([{ "error": { "kind": "output", "operation": "list_names", "reason": "inventory" } }]))]),
        scenario("name inventory shapes", build.clone(), vec![("list_names", json!([ok_with(json!([{"address": "0x10", "value": "+[Factory make]"}, {"address": "0x20", "name": "-[BuildViewController buildTapped:]"}]), T)]))]),
        scenario("name inventory invalid", build.clone(), vec![("list_names", json!([ok_with(json!([{"address": "0x10"}]), T)]))]),
        // --- decoder outcomes and query resolution ---
        scenario("decoder unavailable, native symbol seed", json!({"action": "buildTapped:"}), vec![
            ("decode_interface_builder", json!([capability("ibtool unavailable")])),
            ("procedure_address", seed("0x1000", T)),
        ]),
        scenario("decoder unavailable, unknown query", json!({"action": "nothing"}), vec![
            ("decode_interface_builder", json!([capability("ibtool unavailable")])),
        ]),
        scenario("decoder returns an invalid graph", build.clone(), vec![
            ("decode_interface_builder", json!([ok_with(json!({"target_sha256": T, "documents": [], "graph": {"nodes": 1}, "limitations": []}), T)])),
        ]),
        scenario("decoder reports a different target", build.clone(), vec![
            ("decode_interface_builder", json!([ok_with(json!({"target_sha256": "d".repeat(64), "documents": [], "graph": base_graph(), "limitations": []}), T)])),
        ]),
        scenario("native seed with another subject", json!({"action": "0x1000"}), vec![("procedure_address", seed("0x1000", &"e".repeat(64)))]),
        scenario("native seed not a string", json!({"action": "0x1000"}), vec![("procedure_address", json!([ok_with(json!(7), T)]))]),
        scenario("native seed cancelled", json!({"action": "0x1000"}), vec![("procedure_address", json!([{ "error": { "kind": "cancelled" } }]))]),
        scenario("object with several actions", json!({"action": "button"}), vec![
            ("decode_interface_builder", json!([ok_with(ib_result(two_actions), T)])),
        ]),
        scenario("archives with partial decode coverage", build, vec![
            ("decode_interface_builder", json!([ok_with(ib_result({
                let mut graph = base_graph();
                graph["coverage"] = json!([{ "facet": "archive_decode", "status": "partial", "reason": "ibtool_failed_for_some", "examined": 9, "omitted": 2 }]);
                graph
            }), T)])),
        ]),
    ]
}

// ------------------------------------------------------------ scripted port ----

struct Scripted {
    responses: serde_json::Map<String, Value>,
    calls: Mutex<Vec<Value>>,
}

fn to_error(spec: &Value, operation: &str) -> ToolError {
    let text = |key: &str, default: &str| spec[key].as_str().unwrap_or(default).to_string();
    match spec["kind"].as_str().unwrap_or_default() {
        "capability" => ToolError::CapabilityUnavailable {
            provider_id: text("provider", "fixture"),
            operation: text("operation", operation),
            reason: text("reason", "unavailable"),
            user_message: None,
        },
        "cancelled" => ToolError::Cancelled { operation: text("operation", operation) },
        "output" => ToolError::Output { operation: text("operation", operation), reason: text("reason", "bad output") },
        "protocol" => ToolError::protocol(text("message", "protocol")),
        "unsupported" => ToolError::UnsupportedTarget {
            operation: text("operation", operation),
            path: text("path", "/x"),
            reason: text("reason", "unsupported"),
        },
        "timeout" => ToolError::Timeout { operation: text("operation", operation), timeout_ms: spec["timeout_ms"].as_u64().unwrap_or(1000) },
        other => panic!("unknown error kind {other}"),
    }
}

impl AnalysisPort for Scripted {
    fn execute(&self, operation: &str, parameters: Value) -> impl std::future::Future<Output = Result<PortExecution, ToolError>> + Send {
        self.calls.lock().unwrap().push(json!({ "operation": operation, "parameters": parameters }));
        let rule = self
            .responses
            .get(operation)
            .and_then(Value::as_array)
            .and_then(|rules| {
                rules.iter().find(|rule| {
                    rule.get("match")
                        .and_then(Value::as_object)
                        .map(|m| m.iter().all(|(k, v)| parameters.get(k) == Some(v)))
                        .unwrap_or(true)
                })
            })
            .cloned()
            .unwrap_or_else(|| panic!("Unexpected provider operation: {operation} {parameters}"));
        let outcome = if let Some(spec) = rule.get("error") {
            Err(to_error(spec, operation))
        } else {
            Ok(PortExecution {
                result: rule["ok"].clone(),
                provider: rule.get("provider").cloned().unwrap_or_else(|| json!({"id": "fixture", "name": "Fixture", "version": "1"})),
                subject_sha256: rule.get("subject").and_then(|s| s["sha256"].as_str()).map(str::to_string),
                analysis_profile_digest: None,
            })
        };
        std::future::ready(outcome)
    }
}

fn run_oracle(scenarios: &Value) -> Vec<Value> {
    let work = concat!(env!("CARGO_TARGET_TMPDIR"), "/trace-parity");
    fs::create_dir_all(work).unwrap();
    let input = format!("{work}/scenarios.json");
    let output = format!("{work}/oracle.json");
    fs::write(&input, scenarios.to_string()).unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/native_trace/oracle_trace.mjs");
    let status = Command::new(NODE).arg(script).arg(&input).arg(&output).status().expect("node");
    assert!(status.success(), "oracle script failed");
    serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap()
}

#[tokio::test]
async fn trace_native_ui_action_matches_rea_workflow() {
    let mut missing = tracewise_device::testing::missing_paths(&[NODE, "/workspace/rea-map/src/dist/application/EnhancedTools.js"]);
    missing.dedup();
    if !tracewise_device::testing::require_or_skip("ui_trace_parity", &missing) {
        return;
    }
    let list = scenarios();
    let document = to_json(&list);
    let oracle = run_oracle(&document);
    assert_eq!(oracle.len(), list.len());
    let mut failures = Vec::new();
    let mut ok_count = 0;
    let mut error_count = 0;
    for (scenario, expected) in document.as_array().unwrap().iter().zip(&oracle) {
        let name = scenario["name"].as_str().unwrap();
        assert!(expected.get("thrown").is_none(), "[{name}] the oracle threw: {}", expected["thrown"]);
        let validated = native::validate("trace_native_ui_action", &scenario["input"]).expect("valid input");
        let port = Scripted { responses: scenario["responses"].as_object().unwrap().clone(), calls: Mutex::new(Vec::new()) };
        let result = trace_native_ui_action(&port, &TraceInput::from_validated(&validated)).await;
        let calls = Value::Array(port.calls.lock().unwrap().clone());
        let actual = match &result {
            Ok(value) => json!({ "ok": true, "value": value }),
            Err(error) => json!({ "ok": false, "error": error.project() }),
        };
        if expected["ok"] == true {
            ok_count += 1;
        } else {
            error_count += 1;
        }
        let expected_outcome = if expected["ok"] == true { json!({"ok": true, "value": expected["value"]}) } else { json!({"ok": false, "error": expected["error"]}) };
        if actual != expected_outcome {
            failures.push(format!(
                "[{name}] outcome differs\n oracle: {}\n rust:   {}",
                serde_json::to_string(&expected_outcome).unwrap(),
                serde_json::to_string(&actual).unwrap()
            ));
        }
        if calls != expected["calls"] {
            failures.push(format!(
                "[{name}] port calls differ\n oracle: {}\n rust:   {}",
                serde_json::to_string(&expected["calls"]).unwrap(),
                serde_json::to_string(&calls).unwrap()
            ));
        }
    }
    assert!(failures.is_empty(), "{} of {} scenarios differ:\n\n{}", failures.len(), list.len(), failures.join("\n\n"));
    assert!(ok_count > 10 && error_count > 5, "the scenario set must exercise both outcomes ({ok_count} ok, {error_count} errors)");
    eprintln!("trace_native_ui_action: {} scenarios identical to REA ({ok_count} traces, {error_count} errors)", list.len());
}
