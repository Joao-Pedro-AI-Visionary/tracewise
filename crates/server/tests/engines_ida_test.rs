//! IDA provider (phase 5b) against the REA oracle, with a fake upstream ida-pro-mcp server.
//!
//! Oracle goldens (all produced by the ORIGINAL REA talking to `fixtures/engines/ida/fake_ida_mcp.mjs`,
//! with `fixtures/engines/ida/run_oracle.sh` or, for the variants, `generate_variants.py`):
//!
//! | golden                               | calls                                    | REA mode / fake profile |
//! |--------------------------------------|------------------------------------------|-------------------------|
//! | `oracle_ida_attached_direct.json`    | `calls_ida_direct.json`                  | attached / legacy       |
//! | `oracle_ida_attached_workflows.json` | `calls_ida_workflows.json`               | attached / legacy       |
//! | `oracle_ida_attached_catalog.json`   | `calls_ida_catalog.json` (other tools)   | attached / legacy       |
//! | `oracle_ida_headless_direct.json`    | `calls_ida_direct.json`                  | headless / modern       |
//! | `oracle_ida_headless_workflows.json` | `calls_ida_workflows.json`               | headless / modern       |
//! | `oracle_ida_headless_catalog.json`   | `calls_ida_catalog.json`                 | headless / modern       |
//! | `oracle_ida_faults.json`             | `variants_faults.json` (19 upstream faults) | both                 |
//! | `oracle_ida_registration.json`       | `variants_registration.json` (8 bad ones)   | none                 |
//! | `oracle_ida_http.json`               | `variants_http.json` (local HTTP + headers) | both                 |
//!
//! Nothing is mocked in the Rust server: the engine session spawns the real `node` fake (stdio) or
//! connects to it (HTTP), exactly as it would for an upstream ida-pro-mcp.
//!
//! Everything the oracle recorded is compared field by field (`structuredContent`, or the
//! error body) and each success is validated against the tool's `outputSchema`. Ignored:
//! * `subject.local_path` (harness; the target is a copy in a fixed private directory, so
//!   no other path needs normalizing and `evidence_id` stays comparable in attached mode);
//! * headless mode only: REA allocates a random private workspace (`rea-ida-XXXXXX`) and
//!   a random worker session id (`rea-<uuid>`). Those values appear in the raw upstream
//!   observations, so they are rewritten to `$WORKSPACE` / `$SESSION` on both sides and
//!   `evidence_id` (a digest over them) is not compared; its shape is still checked;
//! * `registration_errors_match_the_oracle` compares the selection error's code, category,
//!   message, remediation, operation and IDA's own rejection, not the candidate list: REA
//!   also lists Hopper, which tracewise does not register yet.
//!
//! Beyond parity the tests audit the fake's call log: IDA only reads, attached mode never
//! touches the database lifecycle, headless mode opens one private copy, scopes every
//! request to it, closes it with `save: false` and leaves no process or directory behind.
//!
//! Known divergence (outside this provider): REA starts the engine while opening the target
//! (`open_binary` fails when the registration is bad); the Rust server starts it lazily, so
//! `registration_errors_match_the_oracle` compares the error of the first analysis call.

mod engines_common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use engines_common::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracewise_server::session::BinarySession;

/// A private call log (`FAKE_IDA_LOG`) and pid file (`FAKE_IDA_PID_FILE`) of one session.
struct Probe {
    log: PathBuf,
    pid: PathBuf,
}

impl Probe {
    fn new(label: &str) -> Self {
        let base = std::env::temp_dir().join(format!("tracewise-ida-{label}-{}", std::process::id()));
        let probe = Self {
            log: base.with_extension("log"),
            pid: base.with_extension("pid"),
        };
        let _ = std::fs::remove_file(&probe.log);
        let _ = std::fs::remove_file(&probe.pid);
        probe
    }

    fn arm(&self, env: &mut std::collections::BTreeMap<String, String>) {
        env.insert("FAKE_IDA_LOG".into(), self.log.to_string_lossy().to_string());
        env.insert("FAKE_IDA_PID_FILE".into(), self.pid.to_string_lossy().to_string());
    }

    fn calls(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).expect("log line"))
            .collect()
    }

    fn pid(&self) -> Option<u32> {
        std::fs::read_to_string(&self.pid).ok().and_then(|text| text.trim().parse().ok())
    }

    /// `close_binary` releases the engine in the background; wait until the proxy is gone.
    async fn wait_for_proxy_exit(&self) {
        let pid = self.pid().expect("the fake server recorded its pid");
        let deadline = Instant::now() + Duration::from_secs(20);
        while Path::new(&format!("/proc/{pid}")).exists() {
            assert!(Instant::now() < deadline, "the fake IDA proxy (pid {pid}) outlived close_binary");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.log);
        let _ = std::fs::remove_file(&self.pid);
    }
}

fn target_path() -> PathBuf {
    PathBuf::from(IDA_PARITY_DIR).join("sample_elf")
}

fn digest(path: &Path) -> Vec<u8> {
    Sha256::digest(std::fs::read(path).expect("read target")).to_vec()
}

fn names(calls: &[Value]) -> Vec<String> {
    calls.iter().map(|c| c["tool"].as_str().unwrap().to_string()).collect()
}

const LEGACY_READ_TOOLS: [&str; 10] = [
    "get_metadata",
    "list_functions",
    "list_strings",
    "get_function_by_name",
    "get_function_by_address",
    "decompile_function",
    "disassemble_function",
    "get_callers",
    "get_callees",
    "get_xrefs_to",
];

const MODERN_READ_TOOLS: [&str; 8] = [
    "server_health",
    "list_funcs",
    "lookup_funcs",
    "find_regex",
    "decompile",
    "disasm",
    "callees",
    "xrefs_to",
];

async fn attached_session(label: &str) -> Option<(BinarySession, Probe)> {
    let mut env = ida_environment("legacy")?;
    let probe = Probe::new(label);
    probe.arm(&mut env);
    Some((session_with(env).await, probe))
}

async fn finish_attached(session: BinarySession, probe: &Probe) {
    let closed = call(&session, "close_binary", &json!({})).await;
    assert!(closed.is_ok());
    probe.wait_for_proxy_exit().await;
    let calls = probe.calls();
    assert!(!calls.is_empty(), "the fake server was never called");
    for tool in names(&calls) {
        assert!(
            LEGACY_READ_TOOLS.contains(&tool.as_str()),
            "attached mode called {tool}, which is not a read of the user's open database"
        );
    }
}

async fn replay_and_report(session: &BinarySession, golden: &[Value]) {
    let root = repo_root().to_string_lossy().to_string();
    let failures = replay(session, golden, &root, false).await;
    assert!(
        failures.is_empty(),
        "{} of {} calls differ from the oracle:\n{}",
        failures.len(),
        golden.len(),
        failures.join("\n")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn attached_direct_operations_match_the_oracle() {
    let Some((session, probe)) = attached_session("attached-direct").await else { return };
    let before = digest(&target_path());
    let golden = load_golden("ida/oracle_ida_attached_direct.json");
    replay_and_report(&session, &golden).await;
    finish_attached(session, &probe).await;
    assert_eq!(before, digest(&target_path()), "target bytes must stay unchanged");
}

#[tokio::test(flavor = "multi_thread")]
async fn attached_workflows_match_the_oracle() {
    let Some((session, probe)) = attached_session("attached-workflows").await else { return };
    let golden = load_golden("ida/oracle_ida_attached_workflows.json");
    replay_and_report(&session, &golden).await;
    finish_attached(session, &probe).await;
}

// ------------------------------------------------------------------------------ headless

/// Rewrite the values REA and tracewise each allocate at random.
fn scrub_ephemeral(value: &mut Value) {
    match value {
        Value::String(text) => *text = scrub_text(text),
        Value::Array(items) => items.iter_mut().for_each(scrub_ephemeral),
        Value::Object(map) => {
            map.remove("evidence_id");
            map.values_mut().for_each(scrub_ephemeral);
        }
        _ => {}
    }
}

fn scrub_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        if let Some(tail) = rest.strip_prefix("rea-ida-") {
            let length = tail.bytes().take_while(|b| b.is_ascii_alphanumeric()).count();
            out.push_str("$WORKSPACE");
            rest = &tail[length..];
        } else if let Some(tail) = rest.strip_prefix("rea-") {
            let candidate: String = tail.chars().take(36).collect();
            let shaped = candidate.len() == 36
                && candidate.char_indices().all(|(i, c)| match i {
                    8 | 13 | 18 | 23 => c == '-',
                    _ => c.is_ascii_hexdigit(),
                });
            if shaped {
                out.push_str("$SESSION");
                rest = &tail[36..];
            } else {
                out.push_str("rea-");
                rest = tail;
            }
        } else {
            let c = rest.chars().next().unwrap();
            out.push(c);
            rest = &rest[c.len_utf8()..];
        }
    }
    out
}

async fn replay_ephemeral(session: &BinarySession, golden: &[Value]) -> Vec<String> {
    let root = repo_root().to_string_lossy().to_string();
    let mut failures = Vec::new();
    for (index, entry) in golden.iter().enumerate() {
        let name = entry["name"].as_str().unwrap();
        let actual = call(session, name, &entry["arguments"]).await;
        let actual_value = rust_result_value(&actual);
        let mut want = comparable(&entry["result"], &root);
        let mut got = comparable(&actual_value, &root);
        if let Some(id) = got["structured"]["evidence_id"].as_str() {
            let shaped = id.len() == 67 && id.starts_with("ev_") && id[3..].bytes().all(|b| b.is_ascii_hexdigit());
            if !shaped {
                failures.push(format!("#{index} {name}: malformed evidence_id {id}"));
            }
        }
        scrub_ephemeral(&mut want);
        scrub_ephemeral(&mut got);
        if want != got {
            failures.push(format!(
                "#{index} {name} {} differs\n  oracle: {}\n  rust:   {}",
                entry["arguments"],
                &want.to_string()[..want.to_string().len().min(1500)],
                &got.to_string()[..got.to_string().len().min(1500)]
            ));
        } else if actual_value["isError"] == json!(false) && name != "open_binary" {
            if let Err(error) = output_schema_validator(name).validate(&actual_value["structuredContent"]) {
                failures.push(format!("#{index} {name} outputSchema: {error}"));
            }
        }
    }
    failures
}

fn workspaces_in_temp() -> Vec<String> {
    std::fs::read_dir(std::env::temp_dir())
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|e| e.file_name().to_str().map(str::to_string))
                .filter(|name| name.starts_with("rea-ida-"))
                .collect()
        })
        .unwrap_or_default()
}

/// Replay a headless golden and audit the lifecycle the fake logged.
async fn headless_run(label: &str, golden_name: &str) {
    let Some(mut env) = ida_environment("modern") else { return };
    let probe = Probe::new(label);
    probe.arm(&mut env);
    let before_target = digest(&target_path());
    let workspaces_before = workspaces_in_temp();
    let session = session_with(env).await;
    let golden = load_golden(golden_name);
    let failures = replay_ephemeral(&session, &golden).await;
    let closed = call(&session, "close_binary", &json!({})).await;
    assert!(closed.is_ok());
    probe.wait_for_proxy_exit().await;
    assert!(
        failures.is_empty(),
        "{} of {} calls differ from the oracle:\n{}",
        failures.len(),
        golden.len(),
        failures.join("\n")
    );

    let calls = probe.calls();
    let tools = names(&calls);
    // One private worker: opened first, closed last without saving, and nothing else
    // touches the lifecycle.
    assert_eq!(tools.iter().filter(|t| *t == "idb_open").count(), 1, "{tools:?}");
    assert_eq!(tools.iter().filter(|t| *t == "idb_close").count(), 1, "{tools:?}");
    assert_eq!(tools.first().map(String::as_str), Some("idb_open"));
    let close_position = tools.iter().position(|t| t == "idb_close").unwrap();
    assert!(
        tools[close_position + 1..].iter().all(|t| t == "idb_list"),
        "only the release verification may follow idb_close: {tools:?}"
    );
    for tool in &tools {
        assert!(
            matches!(tool.as_str(), "idb_open" | "idb_list" | "idb_close") || MODERN_READ_TOOLS.contains(&tool.as_str()),
            "headless mode called {tool}, which is not a read of its private worker"
        );
    }
    let open = &calls[0]["arguments"];
    assert_eq!(open["mode"], "force_headless");
    let input = open["input_path"].as_str().unwrap();
    let session_id = open["preferred_session_id"].as_str().unwrap();
    assert_ne!(Path::new(input), target_path(), "the user's file must never be opened directly");
    assert!(input.contains("/rea-ida-"), "the worker opens a private copy: {input}");
    assert!(session_id.starts_with("rea-"));
    for call in &calls {
        let tool = call["tool"].as_str().unwrap();
        if !matches!(tool, "idb_open" | "idb_list") {
            assert_eq!(call["arguments"]["database"], session_id, "{tool} must be scoped to the private worker");
        }
        if tool == "idb_close" {
            assert_eq!(call["arguments"]["save"], json!(false), "the worker must be closed without saving");
        }
    }
    // Cleanup: no private directory is left and the user's file is untouched.
    assert!(
        !Path::new(input).parent().unwrap().exists(),
        "the private workspace must be removed after close"
    );
    for leftover in workspaces_in_temp() {
        assert!(
            workspaces_before.contains(&leftover) || !input.contains(&leftover),
            "workspace {leftover} survived close"
        );
    }
    assert_eq!(before_target, digest(&target_path()), "target bytes must stay unchanged");
}

#[tokio::test(flavor = "multi_thread")]
async fn headless_direct_operations_match_the_oracle() {
    headless_run("headless-direct", "ida/oracle_ida_headless_direct.json").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn headless_workflows_match_the_oracle() {
    headless_run("headless-workflows", "ida/oracle_ida_headless_workflows.json").await;
}

// ------------------------------------------------------------------------------ variants

fn load_json(name: &str) -> Value {
    serde_json::from_str(&read_fixture_text(name)).expect("fixture is JSON")
}

fn variant_environment(variant: &Value) -> Option<std::collections::BTreeMap<String, String>> {
    ida_variant_environment(
        variant["profile"].as_str().unwrap(),
        variant["files"].as_object().unwrap_or(&serde_json::Map::new()),
        variant["env"].as_object().unwrap_or(&serde_json::Map::new()),
    )
}

/// Upstream faults (malformed or truncated answers, tool errors) in both tool families,
/// including the exact zod wording REA reports as the `reason` of the output error.
#[tokio::test(flavor = "multi_thread")]
async fn upstream_faults_match_the_oracle() {
    let variants = load_json("ida/variants_faults.json");
    let golden = load_json("ida/oracle_ida_faults.json");
    let root = repo_root().to_string_lossy().to_string();
    let mut failures = Vec::new();
    for variant in variants.as_array().unwrap() {
        let name = variant["name"].as_str().unwrap();
        let Some(env) = variant_environment(variant) else { return };
        let expected = golden[name].as_array().unwrap_or_else(|| panic!("no golden for {name}"));
        let session = session_with(env).await;
        let found = if variant["profile"] == "modern" {
            replay_ephemeral(&session, expected).await
        } else {
            replay(&session, expected, &root, false).await
        };
        failures.extend(found.into_iter().map(|f| format!("[{name}] {f}")));
        assert!(call(&session, "close_binary", &json!({})).await.is_ok());
    }
    assert!(failures.is_empty(), "{} divergences from the oracle:\n{}", failures.len(), failures.join("\n"));
}

/// A rejected or missing registration makes IDA unavailable; compare what the caller is told
/// about IDA. REA stops at `open_binary`'s sibling call because it lists three candidates
/// (Hopper is not registered in tracewise yet), so only IDA's own rejection and the
/// selection summary are compared.
#[tokio::test(flavor = "multi_thread")]
async fn registration_errors_match_the_oracle() {
    let variants = load_json("ida/variants_registration.json");
    let golden = load_json("ida/oracle_ida_registration.json");
    let mut failures = Vec::new();
    for variant in variants.as_array().unwrap() {
        let name = variant["name"].as_str().unwrap();
        let Some(env) = variant_environment(variant) else { return };
        let session = session_with(env).await;
        let opened = call(&session, "open_binary", &variant["calls"][0]["arguments"]).await;
        assert!(opened.is_ok() && opened.as_ref().unwrap().is_error != Some(true), "[{name}] open_binary");
        let actual = call(&session, "list_procedures", &variant["calls"][1]["arguments"]).await;
        let want: Value = serde_json::from_str(golden[name][1]["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        let got: Value = serde_json::from_str(&result_text(actual.as_ref().unwrap())).unwrap();
        let summary = |body: &Value| {
            let error = &body["error"];
            let details = &error["details"];
            let ida: Vec<Value> = details["rejections"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|r| r["provider_id"] == "ida")
                .cloned()
                .collect();
            json!({
                "code": error["code"], "category": error["category"], "message": error["message"],
                "retryable": error["retryable"], "remediation": error["remediation"],
                "operation": details["operation"], "selection_reason": details["selection_reason"],
                "requested_provider_id": details["requested_provider_id"], "ida": ida,
            })
        };
        if summary(&want) != summary(&got) {
            failures.push(format!("[{name}]\n  oracle: {}\n  rust:   {}", summary(&want), summary(&got)));
        }
        let candidates: Vec<&str> = got["error"]["details"]["candidate_ids"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(candidates.contains(&"ida"), "[{name}] IDA must be a listed candidate: {candidates:?}");
        let _ = call(&session, "close_binary", &json!({})).await;
    }
    assert!(failures.is_empty(), "{} divergences from the oracle:\n{}", failures.len(), failures.join("\n"));
}

// ------------------------------------------------------------------------------ HTTP

/// The fake served over HTTP on the port a variant's registration names; killed on drop.
struct HttpFake {
    child: std::process::Child,
}

impl HttpFake {
    fn start(profile: &str, port: u64, log: &Path) -> Self {
        use std::io::BufRead;
        let script = PathBuf::from(IDA_PARITY_DIR).join("fake_ida_mcp.mjs");
        let mut child = std::process::Command::new("node")
            .arg(script)
            .args(["--profile", profile, "--http", &port.to_string()])
            .env("FAKE_IDA_LOG", log)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("start the fake HTTP server");
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
        assert_eq!(line.trim(), format!("listening {port}"), "the fake HTTP server could not bind port {port}");
        Self { child }
    }
}

impl Drop for HttpFake {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Local streamable-HTTP registrations (with headers) in both modes, against the oracle.
#[tokio::test(flavor = "multi_thread")]
async fn http_registrations_match_the_oracle() {
    let variants = load_json("ida/variants_http.json");
    let golden = load_json("ida/oracle_ida_http.json");
    let root = repo_root().to_string_lossy().to_string();
    let mut failures = Vec::new();
    for variant in variants.as_array().unwrap() {
        let name = variant["name"].as_str().unwrap();
        let headless = variant["server"]["profile"] == "modern";
        let Some(env) = variant_environment(variant) else { return };
        let probe = Probe::new(name);
        let server = HttpFake::start(
            variant["server"]["profile"].as_str().unwrap(),
            variant["server"]["port"].as_u64().unwrap(),
            &probe.log,
        );
        let expected = golden[name].as_array().unwrap_or_else(|| panic!("no golden for {name}"));
        let session = session_with(env).await;
        let found = if headless {
            replay_ephemeral(&session, expected).await
        } else {
            replay(&session, expected, &root, false).await
        };
        failures.extend(found.into_iter().map(|f| format!("[{name}] {f}")));
        assert!(call(&session, "close_binary", &json!({})).await.is_ok());
        if headless {
            // The release runs in the background; wait for its verification listing.
            let deadline = Instant::now() + Duration::from_secs(15);
            while !(names(&probe.calls()).iter().any(|t| t == "idb_close") && names(&probe.calls()).last().map(String::as_str) == Some("idb_list")) {
                assert!(Instant::now() < deadline, "[{name}] the worker was not released: {:?}", names(&probe.calls()));
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let calls = probe.calls();
            let close = calls.iter().find(|c| c["tool"] == "idb_close").unwrap();
            assert_eq!(close["arguments"]["save"], json!(false));
        }
        let calls = probe.calls();
        assert!(!calls.is_empty());
        for call in &calls {
            assert_eq!(call["fixture_key"], "fixture-key-value", "[{name}] the registration's headers must reach the endpoint");
        }
        drop(server);
    }
    assert!(failures.is_empty(), "{} divergences from the oracle:\n{}", failures.len(), failures.join("\n"));
}

// ------------------------------------------------------------------------------ catalog

/// One call of every other engines tool (everything IDA does not declare answers
/// `capability_unavailable`, and the workflows that need only IDA's operations still run).
async fn catalog_run(profile: &str, golden_name: &str) {
    let Some(mut env) = ida_environment(profile) else { return };
    let probe = Probe::new(&format!("catalog-{profile}"));
    probe.arm(&mut env);
    let session = session_with(env).await;
    let golden = load_golden(golden_name);
    let root = repo_root().to_string_lossy().to_string();
    let failures = if profile == "modern" {
        replay_ephemeral(&session, &golden).await
    } else {
        replay(&session, &golden, &root, false).await
    };
    assert!(call(&session, "close_binary", &json!({})).await.is_ok());
    // The engine only starts when a call reaches it; when it did, it must be gone after close.
    if probe.pid().is_some() {
        probe.wait_for_proxy_exit().await;
    }
    assert!(
        failures.is_empty(),
        "{} of {} calls differ from the oracle:\n{}",
        failures.len(),
        golden.len(),
        failures.join("\n")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn attached_catalog_matches_the_oracle() {
    catalog_run("legacy", "ida/oracle_ida_attached_catalog.json").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn headless_catalog_matches_the_oracle() {
    catalog_run("modern", "ida/oracle_ida_headless_catalog.json").await;
}
