//! Static Android tools against the REA oracle with the Appium ApiDemos APK.
//!
//! Oracle: REA @0fa0b04 running the real engine (jadx-headless-mcp 0.7.1,
//! SHA-256 6e5eacf5...) on Temurin 21.0.5+11 over the public Appium ApiDemos
//! v6.0.18 APK (SHA-256 a9eecf37...). `fixtures/android/android_scenarios.json`
//! lists the requests (with the environment REA ran under) and
//! `fixtures/android/oracle_android.json` holds REA's answers. Every scenario ran
//! in its own REA process, so the first call of a scenario loads the APK and the
//! later ones reuse the engine; the Rust side retires its retained session
//! before each scenario to reproduce that.
//!
//! External dependencies (installed pinned under /workspace/tools, never
//! downloaded by the test): the JAR, the JDK and the APK. When one is missing the
//! test prints why and returns without asserting; here they are installed.
//!
//! Compared in full: `structuredContent` (subject, provider, parameters,
//! `normalized_result`, `raw_result`, limitations, locations, confidence) and the
//! error envelopes including `partial_observation`. Normalized before comparing:
//! the random private workspace name (`/tmp/rea-android-XXXXXX/`), the engine's
//! `load_duration_ms`, the checkout path of the managed fixtures, and the working
//! directory used to resolve a relative APK path. Ignored: `evidence_id`, which
//! hashes the workspace name through `raw_result`; it is checked for
//! self-consistency instead.

mod managed_android_support;

use std::path::PathBuf;

use managed_android_support::{ensure_derived_android_fixtures, require_or_skip};

use regex::Regex;
use rmcp::model::CallToolRequestParam;
use serde_json::{json, Value};
use tracewise_domain::evidence::Evidence;
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

const APK: &str = "/workspace/tools/fixtures-android/ApiDemos-debug.apk";
const JAR: &str = "/workspace/tools/jadx-headless-mcp-0.7.1/jadx-headless-mcp-0.7.1-all.jar";
const JDK: &str = "/workspace/tools/temurin-21.0.5+11/bin/java";
const ORACLE_MANAGED_DIR: &str = "/workspace/wt/managed_android/fixtures/managed";
const ORACLE_CWD: &str = "/workspace/rea-map/src";
const ENV_KEYS: [&str; 4] = ["REA_JADX_MCP_JAR", "JAVA_HOME", "REA_JADX_HEAP_MIB", "REA_JADX_ACTIVE_PROCESSOR_COUNT"];

fn fixtures(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures").join(name).canonicalize().expect(name)
}

fn load(path: PathBuf) -> Value {
    serde_json::from_str(&managed_android_support::read_fixture_text(&path)).expect("json")
}

fn normalizer() -> impl Fn(&str) -> String {
    let workspace = Regex::new(r"/tmp/rea-android-[A-Za-z0-9]{6}/").unwrap();
    let load_ms = Regex::new(r#"\\?"load_duration_ms\\?":\d+"#).unwrap();
    let managed = fixtures("managed").to_string_lossy().into_owned();
    let cwd = std::env::current_dir().unwrap().to_string_lossy().into_owned();
    move |text: &str| {
        let text = workspace.replace_all(text, "<root>/");
        let text = load_ms.replace_all(&text, "\"load_duration_ms\":0");
        text.replace(ORACLE_MANAGED_DIR, &managed).replace(ORACLE_CWD, &cwd)
    }
}

fn normalize_value(value: &Value, text: &dyn Fn(&str) -> String) -> Value {
    match value {
        // The bridge builds replies with Java , whose iteration order changes
        // from one JVM run to the next; compare embedded JSON documents by content.
        Value::String(s) if s.starts_with('{') || s.starts_with('[') => match serde_json::from_str::<Value>(&text(s)) {
            Ok(parsed) => Value::String(tracewise_domain::canonical::canonical_json(&parsed).unwrap_or_else(|_| text(s))),
            Err(_) => Value::String(text(s)),
        },
        Value::String(s) => Value::String(text(s)),
        Value::Array(items) => Value::Array(items.iter().map(|v| normalize_value(v, text)).collect()),
        Value::Object(map) => Value::Object(map.iter().map(|(k, v)| (k.clone(), normalize_value(v, text))).collect()),
        other => other.clone(),
    }
}

/// First differing JSON path, with short renderings of both sides.
fn first_difference(path: &str, got: &Value, want: &Value) -> Option<String> {
    let short = |v: &Value| {
        let text = v.to_string();
        if text.len() > 300 { format!("{}...<{} bytes>", &text[..300], text.len()) } else { text }
    };
    match (got, want) {
        (Value::Object(a), Value::Object(b)) => {
            for key in a.keys().chain(b.keys()) {
                let next = format!("{path}/{key}");
                match (a.get(key), b.get(key)) {
                    (Some(x), Some(y)) => {
                        if let Some(found) = first_difference(&next, x, y) {
                            return Some(found);
                        }
                    }
                    (x, y) => return Some(format!("{next}: got {:?}, want {:?}", x.map(short), y.map(short))),
                }
            }
            None
        }
        (Value::Array(a), Value::Array(b)) => {
            if a.len() != b.len() {
                return Some(format!("{path}: got {} items, want {}", a.len(), b.len()));
            }
            a.iter().zip(b).enumerate().find_map(|(i, (x, y))| first_difference(&format!("{path}/{i}"), x, y))
        }
        _ if got == want => None,
        _ => Some(format!("{path}: got {}, want {}", short(got), short(want))),
    }
}

fn prerequisites_missing() -> Option<String> {
    for path in [APK, JAR, JDK] {
        if !std::path::Path::new(path).exists() {
            return Some(format!("{path} is not installed"));
        }
    }
    None
}

fn apply_env(env: &Value) {
    for key in ENV_KEYS {
        std::env::remove_var(key);
    }
    for (key, value) in env.as_object().unwrap() {
        std::env::set_var(key, value.as_str().unwrap());
    }
}

async fn call(tool: &str, args: &Value, session: &BinarySession) -> Value {
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

fn schema_for(tool: &str) -> jsonschema::Validator {
    let catalog: Value = serde_json::from_str(tracewise_contracts::PHASE3_TOOLS_JSON).unwrap();
    let definition = catalog["tools"].as_array().unwrap().iter().find(|t| t["name"] == tool).expect("tool");
    jsonschema::validator_for(&definition["outputSchema"]).expect("schema")
}

fn strip_id(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.remove("evidence_id");
    }
    value
}

#[tokio::test]
async fn android_tools_match_rea_oracle_on_apidemos() {
    if let Some(reason) = prerequisites_missing() {
        require_or_skip(&format!("android oracle test: {reason}"));
        return;
    }
    ensure_derived_android_fixtures(APK);
    let scenarios = load(fixtures("android").join("android_scenarios.json"));
    let oracle = load(fixtures("android").join("oracle_android.json"));
    let text = normalizer();
    let mut compared = 0;
    let mut successes = 0;
    assert_eq!(scenarios.as_array().unwrap().len(), oracle.as_array().unwrap().len(), "android oracle scenarios");
    for (scenario, answers) in scenarios.as_array().unwrap().iter().zip(oracle.as_array().unwrap()) {
        let name = scenario["name"].as_str().unwrap();
        assert_eq!(answers["name"], scenario["name"]);
        apply_env(&scenario["env"]);
        tracewise_android::jadx::retire_retained();
        let session = BinarySession::new();
        let calls = scenario["calls"].as_array().unwrap();
        let results = answers["results"].as_array().unwrap();
        assert_eq!(calls.len(), results.len());
        for (index, (call_spec, expected)) in calls.iter().zip(results).enumerate() {
            let tool = call_spec[0].as_str().unwrap();
            let args = normalize_value(&call_spec[1], &text);
            let label = format!("{name}[{index}] {tool} {}", args.to_string().chars().take(120).collect::<String>());
            let actual = call(tool, &args, &session).await;
            match (actual.get("error"), expected.get("error")) {
                (Some(got), Some(want)) => {
                    let (got, want) = (got.as_str().unwrap(), want.as_str().unwrap());
                    match (serde_json::from_str::<Value>(got), serde_json::from_str::<Value>(want)) {
                        (Ok(g), Ok(w)) => {
                            if let Some(diff) = first_difference("", &normalize_value(&g, &text), &normalize_value(&w, &text)) {
                                panic!("{label}: error envelope differs at {diff}");
                            }
                        }
                        _ => assert_eq!(text(got), text(want), "{label}: error text"),
                    }
                }
                (None, None) => {
                    let structured = actual["structuredContent"].clone();
                    schema_for(tool).validate(&structured).unwrap_or_else(|e| panic!("{label}: output schema: {e}"));
                    let evidence: Evidence = serde_json::from_value(structured.clone()).expect("evidence");
                    evidence.verify().unwrap_or_else(|e| panic!("{label}: evidence id: {e}"));
                    let got = normalize_value(&strip_id(structured), &text);
                    let want = normalize_value(&strip_id(expected["structuredContent"].clone()), &text);
                    if let Some(diff) = first_difference("", &got, &want) {
                        panic!("{label}: differs at {diff}");
                    }
                    successes += 1;
                }
                (got, want) => panic!("{label}: expected {want:?}, got {got:?}"),
            }
            compared += 1;
        }
    }
    tracewise_android::jadx::retire_retained();
    assert_eq!(compared, 59, "compared calls");
    assert_eq!(successes, 19, "successful observations compared");
}

fn resolve_graph_input(inputs: &Value, value: &Value) -> Value {
    match value {
        Value::Object(map) => match map.get("$g").and_then(Value::as_str) {
            Some(name) => inputs[name].clone(),
            None => Value::Object(map.iter().map(|(k, v)| (k.clone(), resolve_graph_input(inputs, v))).collect()),
        },
        Value::Array(items) => Value::Array(items.iter().map(|v| resolve_graph_input(inputs, v)).collect()),
        other => other.clone(),
    }
}

/// `project_android_application_graph` is pure, so it is checked without the engine.
/// Inputs are REA `inspect_artifact` Evidence for the ApiDemos APK (stored in
/// `fixtures/android/graph_inputs.json`) plus synthetic inventories built with REA's own
/// identity functions; the comparison is exact, including `evidence_id`.
#[tokio::test]
async fn android_application_graph_matches_rea_oracle() {
    let inputs = load(fixtures("android").join("graph_inputs.json"));
    let scenarios = load(fixtures("android").join("graph_scenarios.json"));
    let oracle = load(fixtures("android").join("oracle_android_graph.json"));
    let validator = schema_for("project_android_application_graph");
    let mut successes = 0;
    assert_eq!(scenarios.as_array().unwrap().len(), oracle.as_array().unwrap().len(), "graph oracle scenarios");
    assert_eq!(scenarios.as_array().unwrap().len(), 16, "graph scenarios");
    for (scenario, answer) in scenarios.as_array().unwrap().iter().zip(oracle.as_array().unwrap()) {
        let label = scenario["name"].as_str().unwrap();
        assert_eq!(scenario["name"], answer["name"]);
        let session = BinarySession::new();
        let args = resolve_graph_input(&inputs, &scenario["args"]);
        let actual = call("project_android_application_graph", &args, &session).await;
        let expected = &answer["result"];
        match (actual.get("error"), expected.get("error")) {
            (Some(got), Some(want)) => {
                let (got, want) = (got.as_str().unwrap(), want.as_str().unwrap());
                match (serde_json::from_str::<Value>(got), serde_json::from_str::<Value>(want)) {
                    (Ok(g), Ok(w)) => {
                        if let Some(diff) = first_difference("", &g, &w) {
                            panic!("{label}: error envelope differs at {diff}");
                        }
                    }
                    _ => assert_eq!(got, want, "{label}: error text"),
                }
            }
            (None, None) => {
                validator.validate(&actual["structuredContent"]).unwrap_or_else(|e| panic!("{label}: output schema: {e}"));
                if let Some(diff) = first_difference("", &actual["structuredContent"], &expected["structuredContent"]) {
                    panic!("{label}: differs at {diff}");
                }
                successes += 1;
            }
            (got, want) => panic!("{label}: expected {want:?}, got {got:?}"),
        }
    }
    assert_eq!(successes, 8, "successful projections compared");
}
