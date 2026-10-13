//! Apktool and JEB tools against the REA oracle.
//!
//! Oracle: REA @0fa0b04 over stdio, one process per scenario.
//!
//! * Apktool: the real launcher (Apktool 2.9.3 on Temurin 21.0.5+11, installed
//!   under /workspace/tools) decoding the Appium ApiDemos APK, plus three shell
//!   launchers in `fixtures/android/fake-apktool-*.sh` that fail or emit
//!   oversized output.
//! * JEB: JEB is commercial and never installed. `fixtures/android/fake-jeb.mjs`
//!   is a dependency-free MCP-over-HTTP test double with 24 behaviours (normal,
//!   SSE, GUI client, refusals, malformed envelopes, ...). Scenarios without a
//!   reachable engine cover the "capability unavailable" behaviour that is the
//!   minimum parity when JEB is absent.
//!
//! Compared in full: `structuredContent` and the error envelopes. Normalized:
//! the private workspace name, the fake endpoint's ephemeral port, the checkout
//! path of the fixtures. Skipped on purpose: "version blank" (REA reports the
//! host's coreutils version string, which is machine specific).
//!
//! Needs `node` for the JEB double and the pinned tools under /workspace/tools
//! for Apktool; a missing prerequisite prints why and skips that part.

mod managed_android_support;

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use managed_android_support::{ensure_derived_android_fixtures, require_or_skip};
use regex::Regex;
use rmcp::model::CallToolRequestParam;
use serde_json::{json, Value};
use tracewise_domain::evidence::Evidence;
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

const ORACLE_ANDROID_DIR: &str = "/workspace/wt/managed_android/fixtures/android";
const REAL_APKTOOL: &str = "/workspace/tools/apktool-2.9.3/apktool";
const JDK_BIN: &str = "/workspace/tools/temurin-21.0.5+11/bin";
const APK: &str = "/workspace/tools/fixtures-android/ApiDemos-debug.apk";

fn fixtures(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures").join(name).canonicalize().expect(name)
}

fn load(path: PathBuf) -> Value {
    serde_json::from_str(&managed_android_support::read_fixture_text(&path)).expect("json")
}

fn normalizer() -> impl Fn(&str) -> String {
    let apktool_workspace = Regex::new(r"/tmp/rea-apktool-[A-Za-z0-9]{6}").unwrap();
    let port = Regex::new(r"127\.0\.0\.1:\d+").unwrap();
    // `/bin/true --version` prints the host's coreutils release.
    let coreutils = Regex::new(r"\(GNU coreutils\) [0-9][0-9.]*").unwrap();
    let android = fixtures("android").to_string_lossy().into_owned();
    move |text: &str| {
        let text = apktool_workspace.replace_all(text, "<workspace>");
        let text = port.replace_all(&text, "127.0.0.1:PORT");
        let text = coreutils.replace_all(&text, "(GNU coreutils) X");
        text.replace(ORACLE_ANDROID_DIR, &android)
    }
}

fn normalize_value(value: &Value, text: &dyn Fn(&str) -> String) -> Value {
    match value {
        Value::String(s) => Value::String(text(s)),
        Value::Array(items) => Value::Array(items.iter().map(|v| normalize_value(v, text)).collect()),
        Value::Object(map) => Value::Object(map.iter().map(|(k, v)| (k.clone(), normalize_value(v, text))).collect()),
        other => other.clone(),
    }
}

fn first_difference(path: &str, got: &Value, want: &Value) -> Option<String> {
    let short = |v: &Value| {
        let text = v.to_string();
        if text.len() > 400 { format!("{}...<{} bytes>", &text[..400], text.len()) } else { text }
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

/// Both tests change process environment variables; run them one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

enum Answer {
    Result(Value),
    Error(String),
    Rpc(String),
}

async fn call(tool: &str, args: &Value, session: &BinarySession) -> Answer {
    let outcome = call_tool_local(
        session,
        CallToolRequestParam { name: tool.to_string().into(), arguments: Some(args.as_object().cloned().unwrap_or_default()) },
    )
    .await;
    match outcome {
        Err(error) => Answer::Rpc(error.message.to_string()),
        Ok(result) if result.is_error == Some(true) => {
            Answer::Error(result.content[0].as_text().map(|t| t.text.clone()).unwrap_or_default())
        }
        Ok(result) => Answer::Result(result.structured_content.expect("structuredContent")),
    }
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

/// Compare one answer with the oracle entry; returns whether it was a success.
fn check(label: &str, tool: &str, answer: Answer, expected: &Value, text: &dyn Fn(&str) -> String) -> bool {
    if let Some(unexpected) = expected.get("unexpected") {
        // REA failed while building the provider: a JSON-RPC error, not a tool result.
        match answer {
            Answer::Rpc(message) => {
                assert_eq!(message, unexpected["error"]["message"].as_str().unwrap(), "{label}: rpc error message");
                assert_eq!(unexpected["error"]["code"], -32603, "{label}");
            }
            _ => panic!("{label}: expected a JSON-RPC internal error"),
        }
        return false;
    }
    match (answer, expected.get("error"), expected.get("structuredContent")) {
        (Answer::Error(got), Some(want), _) => {
            let want = text(want.as_str().unwrap());
            let got = text(&got);
            match (serde_json::from_str::<Value>(&got), serde_json::from_str::<Value>(&want)) {
                (Ok(g), Ok(w)) => {
                    if let Some(diff) = first_difference("", &g, &w) {
                        panic!("{label}: error envelope differs at {diff}");
                    }
                }
                _ => assert_eq!(got, want, "{label}: error text"),
            }
            false
        }
        (Answer::Result(got), None, Some(want)) => {
            let schema = schema_for(tool);
            assert!(schema.is_valid(&got), "{label}: output violates the catalog schema");
            let evidence: Evidence = serde_json::from_value(got.clone()).expect("evidence");
            evidence.verify().unwrap_or_else(|e| panic!("{label}: evidence id: {e}"));
            let got = normalize_value(&strip_id(got), text);
            let want = normalize_value(&strip_id(want.clone()), text);
            if let Some(diff) = first_difference("", &got, &want) {
                panic!("{label}: differs at {diff}");
            }
            true
        }
        (Answer::Error(got), None, _) => panic!("{label}: unexpected error {got}"),
        (Answer::Result(got), Some(want), _) => panic!("{label}: expected error {want}, got {got}"),
        (Answer::Rpc(message), _, _) => panic!("{label}: unexpected JSON-RPC error {message}"),
        _ => panic!("{label}: malformed oracle entry"),
    }
}

fn set_env(env: &Value, managed: &[&str]) {
    for key in managed {
        std::env::remove_var(key);
    }
    for (key, value) in env.as_object().unwrap() {
        std::env::set_var(key, value.as_str().unwrap());
    }
}

fn node_binary() -> Option<String> {
    let candidates = ["node", "/workspace/tools/node-v22.23.3-linux-x64/bin/node", "/tmp/node-v22.20.0-linux-x64/bin/node"];
    candidates
        .iter()
        .find(|c| Command::new(c).arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false))
        .map(|c| c.to_string())
}

/// Kills the test double even when an assertion unwinds.
struct Fake(Child);

impl Drop for Fake {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_fake(node: &str, mode: &str) -> (Fake, String) {
    let mut child = Command::new(node)
        .arg(fixtures("android").join("fake-jeb.mjs"))
        .arg(mode)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn fake JEB");
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).expect("endpoint line");
    (Fake(child), line.trim().to_string())
}

#[tokio::test]
async fn apktool_tools_match_rea_oracle() {
    let _serial = SERIAL.lock().await;
    for path in [REAL_APKTOOL, APK, JDK_BIN] {
        if !std::path::Path::new(path).exists() {
            require_or_skip(&format!("{path} is not installed"));
            return;
        }
    }
    ensure_derived_android_fixtures(APK);
    let scenarios = load(fixtures("android").join("apktool_scenarios.json"));
    let oracle = load(fixtures("android").join("oracle_apktool.json"));
    let text = normalizer();
    let android = fixtures("android").to_string_lossy().into_owned();
    let (mut compared, mut successes) = (0, 0);
    assert_eq!(scenarios.as_array().unwrap().len(), oracle.as_array().unwrap().len(), "apktool oracle scenarios");
    for (scenario, answers) in scenarios.as_array().unwrap().iter().zip(oracle.as_array().unwrap()) {
        let name = scenario["name"].as_str().unwrap();
        assert_eq!(name, answers["name"]);
        assert_eq!(scenario["calls"].as_array().unwrap().len(), answers["results"].as_array().unwrap().len(), "{name}: oracle answers");
        let rewrite = |value: &str| value.replace(ORACLE_ANDROID_DIR, &android);
        let env: Value = Value::Object(
            scenario["env"].as_object().unwrap().iter().map(|(k, v)| (k.clone(), json!(rewrite(v.as_str().unwrap())))).collect(),
        );
        set_env(&env, &["REA_APKTOOL_COMMAND"]);
        let saved_path = std::env::var("PATH").unwrap_or_default();
        if env.get("PATH").is_some() {
            // The scenario PATH is only meaningful for its own entries; keep the host's tail.
            std::env::set_var("PATH", format!("{JDK_BIN}:{saved_path}"));
            if scenario["env"]["PATH"].as_str().is_some_and(|p| !p.starts_with(JDK_BIN)) {
                std::env::set_var("PATH", &saved_path);
            }
        }
        let session = BinarySession::new();
        for (index, (call_spec, expected)) in
            scenario["calls"].as_array().unwrap().iter().zip(answers["results"].as_array().unwrap()).enumerate()
        {
            let tool = call_spec[0].as_str().unwrap();
            let args: Value = serde_json::from_str(&rewrite(&call_spec[1].to_string())).unwrap();
            let label = format!("{name}[{index}] {tool} {args}");
            let answer = call(tool, &args, &session).await;
            if check(&label, tool, answer, expected, &text) {
                successes += 1;
            }
            compared += 1;
        }
        std::env::set_var("PATH", saved_path);
    }
    assert_eq!(compared, 41, "compared calls");
    assert_eq!(successes, 19, "successful observations compared");
}

#[tokio::test]
async fn jeb_tools_match_rea_oracle_with_test_double() {
    let _serial = SERIAL.lock().await;
    let Some(node) = node_binary() else {
        require_or_skip("node is not available for the JEB test double");
        return;
    };
    let scenarios = load(fixtures("android").join("jeb_scenarios.json"));
    let oracle = load(fixtures("android").join("oracle_jeb.json"));
    let text = normalizer();
    let (mut compared, mut successes) = (0, 0);
    assert_eq!(scenarios.as_array().unwrap().len(), 39, "JEB scenarios");
    assert_eq!(scenarios.as_array().unwrap().len(), oracle.as_array().unwrap().len(), "JEB oracle scenarios");
    for (scenario, answers) in scenarios.as_array().unwrap().iter().zip(oracle.as_array().unwrap()) {
        let name = scenario["name"].as_str().unwrap();
        assert_eq!(name, answers["name"]);
        assert_eq!(scenario["calls"].as_array().unwrap().len(), answers["results"].as_array().unwrap().len(), "{name}: oracle answers");
        let own_endpoint = scenario["env"].get("REA_JEB_MCP_URL").is_some() || name == "default endpoint (nothing listening)";
        let mut fake = None;
        let mut env = scenario["env"].clone();
        if !own_endpoint {
            let (child, url) = start_fake(&node, scenario["mode"].as_str().unwrap());
            env["REA_JEB_MCP_URL"] = json!(url);
            fake = Some(child);
        }
        set_env(&env, &["REA_JEB_MCP_URL"]);
        tracewise_android::jeb::reset();
        let session = BinarySession::new();
        for (index, (call_spec, expected)) in
            scenario["calls"].as_array().unwrap().iter().zip(answers["results"].as_array().unwrap()).enumerate()
        {
            let tool = call_spec[0].as_str().unwrap();
            let args = &call_spec[1];
            let label = format!("{name}[{index}] {tool} {args}");
            let answer = call(tool, args, &session).await;
            if check(&label, tool, answer, expected, &text) {
                successes += 1;
            }
            compared += 1;
        }
        drop(fake);
    }
    std::env::remove_var("REA_JEB_MCP_URL");
    tracewise_android::jeb::reset();
    assert_eq!(compared, 136, "compared calls");
    assert_eq!(successes, 39, "successful observations compared");
}

/// The engine reply is read with a ceiling (16 MiB): a 20 MiB answer is refused as
/// an unreadable result instead of being buffered. REA has no such cap, so this is a
/// hardening of the port and has no oracle entry.
#[tokio::test]
async fn jeb_response_over_the_cap_is_refused() {
    let _serial = SERIAL.lock().await;
    let Some(node) = node_binary() else {
        require_or_skip("node is not available for the JEB test double");
        return;
    };
    let (_fake, url) = start_fake(&node, "huge-call");
    std::env::set_var("REA_JEB_MCP_URL", &url);
    tracewise_android::jeb::reset();
    let session = BinarySession::new();
    let answer = call("inspect_jeb_client", &json!({}), &session).await;
    std::env::remove_var("REA_JEB_MCP_URL");
    tracewise_android::jeb::reset();
    match answer {
        Answer::Error(text) => {
            let envelope: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(envelope["error"]["code"], "unreadable_output", "{text}");
        }
        _ => panic!("expected an unreadable_output error"),
    }
}

/// Server shutdown drops the retained JEB provider (connection and Mcp-Session-Id), through the
/// same `tracks::shutdown()` that the MCP transport closing and SIGTERM/SIGINT run.
#[tokio::test]
async fn shutdown_releases_the_retained_jeb_provider() {
    let _serial = SERIAL.lock().await;
    let Some(node) = node_binary() else {
        require_or_skip("node is not available for the JEB test double");
        return;
    };
    let (_fake, url) = start_fake(&node, "normal");
    std::env::set_var("REA_JEB_MCP_URL", &url);
    tracewise_android::jeb::reset();
    assert!(!tracewise_android::jeb::has_provider(), "the test starts without a provider");
    let session = BinarySession::new();
    match call("inspect_jeb_client", &json!({}), &session).await {
        Answer::Result(_) => {}
        _ => panic!("inspect_jeb_client must succeed against the test double"),
    }
    assert!(tracewise_android::jeb::has_provider(), "a successful call keeps the provider for the next one");
    tracewise_server::tracks::shutdown().await;
    assert!(!tracewise_android::jeb::has_provider(), "shutdown must drop the retained provider");
    std::env::remove_var("REA_JEB_MCP_URL");
}
