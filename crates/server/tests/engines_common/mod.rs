//! Shared harness for the engines parity tests.
//!
//! A golden file holds the REA oracle's answers to an ordered call list that shares one
//! session (`fixtures/engines/oracle_session.py`). The Rust server replays the same calls
//! against the same engine and every result must match.
//!
//! Ignored when comparing: `subject.local_path` and any occurrence of the fixture root
//! path (the oracle ran from the worktree that generated the golden, the test may run
//! from another checkout). `evidence_id` is compared: it is a digest of the complete
//! observation and does not depend on the file location.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use rmcp::model::{CallToolRequestParam, CallToolResult, RawContent};
use serde_json::{json, Value};
use tracewise_engines::config::EngineConfig;
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;
use tracewise_server::tracks::engines::configure;

/// Absolute path where the goldens were generated; replaced by `$ROOT` before comparing.
pub const GOLDEN_ROOT: &str = "/workspace/wt/engines";

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("repo root")
}

pub fn fixture(path: &str) -> PathBuf {
    repo_root().join("fixtures").join("engines").join(path)
}

pub fn ghidra_environment() -> Option<BTreeMap<String, String>> {
    let install = std::env::var("TRACEWISE_GHIDRA_INSTALL_DIR").unwrap_or_else(|_| "/workspace/tools/ghidra-12.1.4".to_string());
    let java = std::env::var("TRACEWISE_JAVA_HOME").unwrap_or_else(|_| "/workspace/tools/temurin-21.0.5+11".to_string());
    if !PathBuf::from(&install).join("support/analyzeHeadless").exists() || !PathBuf::from(&java).join("bin/java").exists() {
        return skip_or_fail(&format!("Ghidra ({install}) or JDK ({java}) is not installed; install them under /workspace/tools to run this parity test"));
    }
    let mut env: BTreeMap<String, String> = std::env::vars().collect();
    env.insert("GHIDRA_INSTALL_DIR".into(), install);
    env.insert("JAVA_HOME".into(), java);
    env.insert("GHIDRA_HEADLESS_MAXMEM".into(), "1G".into());
    env.remove("REA_ANALYSIS_PROVIDER");
    env.remove("HOPPER_LAUNCHER_PATH");
    env.remove("REA_IDA_MCP_CONFIG");
    Some(env)
}

pub fn hopper_environment() -> Option<BTreeMap<String, String>> {
    let launcher = fixture("hopper/fake_hopper");
    if !launcher.exists() {
        return skip_or_fail(&format!("the fake Hopper launcher {} is missing", launcher.display()));
    }
    if !PathBuf::from("/usr/bin/python3").exists() {
        return skip_or_fail("python3 is required by the fake Hopper runtime");
    }
    let mut env: BTreeMap<String, String> = std::env::vars().collect();
    for key in ["GHIDRA_INSTALL_DIR", "REA_ANALYSIS_PROVIDER", "REA_IDA_MCP_CONFIG", "HOPPER_LOADER_ARGS_JSON", "HOPPER_TARGET_PATH"] {
        env.remove(key);
    }
    env.insert("HOPPER_LAUNCHER_PATH".into(), launcher.to_string_lossy().to_string());
    Some(env)
}

pub async fn call(session: &BinarySession, name: &str, arguments: &Value) -> Result<CallToolResult, rmcp::ErrorData> {
    call_tool_local(
        session,
        CallToolRequestParam {
            name: name.to_string().into(),
            arguments: arguments.as_object().cloned(),
        },
    )
    .await
}

pub fn result_text(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|c| match &c.raw {
            RawContent::Text(t) => Some(t.text.clone()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("")
}

fn normalize(value: &mut Value, root: &str) {
    match value {
        Value::String(s) => {
            if s.contains(root) {
                *s = s.replace(root, "$ROOT");
            }
            if s.contains(GOLDEN_ROOT) {
                *s = s.replace(GOLDEN_ROOT, "$ROOT");
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|v| normalize(v, root)),
        Value::Object(map) => {
            if let Some(Value::Object(subject)) = map.get_mut("subject") {
                subject.remove("local_path");
            }
            map.values_mut().for_each(|v| normalize(v, root));
        }
        _ => {}
    }
}

/// Drop content digests (`evidence_id`) that embed a checkout path when comparing across checkouts.
fn strip_path_bound_ids(value: &mut Value, root: &str) {
    let bound = {
        let mut copy = value.clone();
        if let Some(subject) = copy.pointer_mut("/structured/subject").and_then(Value::as_object_mut) {
            subject.remove("local_path");
        }
        let text = copy.to_string();
        text.contains(GOLDEN_ROOT) || text.contains(root)
    };
    if bound && root != GOLDEN_ROOT {
        fn strip(value: &mut Value) {
            match value {
                Value::Object(map) => {
                    map.remove("evidence_id");
                    map.values_mut().for_each(strip);
                }
                Value::Array(items) => items.iter_mut().for_each(strip),
                _ => {}
            }
        }
        strip(value);
    }
}

/// What a result looks like once ignored fields are removed.
pub fn comparable(result: &Value, root: &str) -> Value {
    let mut out = if result.get("isError") == Some(&json!(true)) {
        let text = result["content"][0]["text"].as_str().unwrap_or("").to_string();
        let parsed = serde_json::from_str::<Value>(&text).unwrap_or(Value::String(text));
        json!({ "isError": true, "body": parsed })
    } else {
        json!({ "isError": false, "structured": result.get("structuredContent").cloned().unwrap_or(Value::Null) })
    };
    strip_path_bound_ids(&mut out, root);
    normalize(&mut out, root);
    out
}

pub fn rust_result_value(result: &Result<CallToolResult, rmcp::ErrorData>) -> Value {
    match result {
        Ok(r) => {
            if r.is_error == Some(true) {
                json!({ "isError": true, "content": [{ "type": "text", "text": result_text(r) }] })
            } else {
                json!({ "isError": false, "structuredContent": r.structured_content.clone().unwrap_or(Value::Null) })
            }
        }
        Err(e) => json!({ "isError": true, "content": [{ "type": "text", "text": format!("PROTOCOL ERROR: {}", e.message) }] }),
    }
}

/// Text of a recorded oracle file. Goldens are stored gzip-compressed (`<name>.gz`); a plain
/// `<name>` is still accepted so a freshly generated oracle can be used before it is compressed.
pub fn read_fixture_text(name: &str) -> String {
    use std::io::Read;
    let plain = fixture(name);
    let packed = fixture(&format!("{name}.gz"));
    if packed.exists() {
        let file = std::fs::File::open(&packed).unwrap_or_else(|e| panic!("open {}: {e}", packed.display()));
        let mut text = String::new();
        flate2::read::GzDecoder::new(file)
            .read_to_string(&mut text)
            .unwrap_or_else(|e| panic!("decompress {}: {e}", packed.display()));
        return text;
    }
    std::fs::read_to_string(&plain).unwrap_or_else(|e| panic!("read {}: {e}", plain.display()))
}

pub fn load_golden(name: &str) -> Vec<Value> {
    serde_json::from_str(&read_fixture_text(name)).expect("golden is a JSON array")
}

pub async fn session_with(env: BTreeMap<String, String>) -> BinarySession {
    let session = BinarySession::new();
    configure(&session, EngineConfig::from_environment(env)).await;
    session
}

pub fn output_schema_validator(tool: &str) -> jsonschema::Validator {
    let schema = tracewise_engines::contract_input::output_schema(tool).unwrap_or_else(|| panic!("no outputSchema for {tool}"));
    jsonschema::validator_for(schema).unwrap_or_else(|e| panic!("outputSchema of {tool}: {e}"))
}

/// Replay the golden call list and return every mismatch (empty when all agree).
pub async fn replay(session: &BinarySession, golden: &[Value], root: &str, skip_open: bool) -> Vec<String> {
    let mut failures = Vec::new();
    for (index, entry) in golden.iter().enumerate() {
        let name = entry["name"].as_str().unwrap();
        let mut arguments = entry["arguments"].clone();
        if let Some(path) = arguments.get("path").and_then(Value::as_str) {
            arguments["path"] = json!(path.replace(GOLDEN_ROOT, root));
        }
        let actual = call(session, name, &arguments).await;
        if name == "open_binary" && skip_open {
            if actual.is_err() || actual.as_ref().unwrap().is_error == Some(true) {
                failures.push(format!("#{index} open_binary failed: {actual:?}"));
            }
            continue;
        }
        let actual_value = rust_result_value(&actual);
        let want = comparable(&entry["result"], root);
        let got = comparable(&actual_value, root);
        if want != got {
            if let Ok(dir) = std::env::var("TRACEWISE_DIFF_DIR") {
                let _ = std::fs::write(format!("{dir}/{index}_{name}_oracle.json"), serde_json::to_string_pretty(&want).unwrap_or_default());
                let _ = std::fs::write(format!("{dir}/{index}_{name}_rust.json"), serde_json::to_string_pretty(&got).unwrap_or_default());
            }
            failures.push(format!(
                "#{index} {name} {} differs\n  oracle: {}\n  rust:   {}",
                serde_json::to_string(&entry["arguments"]).unwrap_or_default(),
                truncate(&want.to_string(), 1500),
                truncate(&got.to_string(), 1500)
            ));
        } else if actual_value["isError"] == json!(false) && name != "open_binary" {
            let structured = &actual_value["structuredContent"];
            let validator = output_schema_validator(name);
            if let Err(error) = validator.validate(structured) {
                failures.push(format!("#{index} {name} outputSchema: {error}"));
            }
        }
    }
    failures
}

fn truncate(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        text.to_string()
    } else {
        format!("{}...({} bytes)", &text[..limit], text.len())
    }
}

// ---------------------------------------------------------------------------------------
// IDA (phase 5b): the fake upstream MCP server.
//
// The oracle and the Rust server must see byte-identical registrations, copies of the
// target and artifact paths, because REA commits a digest of the registration to the
// analysis profile and records the artifact path as an Evidence location. Both therefore
// run against one fixed private directory (`IDA_PARITY_DIR`), which
// `fixtures/engines/ida/run_oracle.sh` fills in the same way as `ida_environment`.
// ---------------------------------------------------------------------------------------

/// Fixed private directory holding the target copy, the fake server and the registrations.
pub const IDA_PARITY_DIR: &str = "/tmp/tracewise-ida-parity";

/// Whether a missing external dependency must fail instead of skipping.
pub fn oracle_required() -> bool {
    std::env::var("TRACEWISE_REQUIRE_ORACLE").map(|v| v == "1").unwrap_or(false)
}

fn skip_or_fail(reason: &str) -> Option<BTreeMap<String, String>> {
    if oracle_required() {
        panic!("TRACEWISE_REQUIRE_ORACLE=1 but {reason}");
    }
    eprintln!("SKIP: {reason}");
    None
}

fn find_on_path(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(program))
            .find(|candidate| candidate.is_file())
    })
}

/// Write `bytes` to `path` atomically (a concurrent reader never sees a torn file).
fn write_atomic(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write;
    if std::fs::read(path).map(|existing| existing == bytes).unwrap_or(false) {
        return;
    }
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let temporary = path.with_extension(format!("tmp{}-{unique}", std::process::id()));
    let mut file = std::fs::File::create(&temporary).expect("create temporary fixture file");
    file.write_all(bytes).expect("write fixture file");
    drop(file);
    std::fs::rename(&temporary, path).expect("publish fixture file");
}

/// Prepare `IDA_PARITY_DIR` (target copy, fake server, registration of one profile) and
/// return the environment under which IDA is the only configured engine.
/// `profile` is `legacy` (attached mode) or `modern` (headless mode).
pub fn ida_environment(profile: &str) -> Option<BTreeMap<String, String>> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    // Tests of one binary prepare the shared directory one at a time.
    static SETUP: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _setup = SETUP.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if find_on_path("node").is_none() {
        return skip_or_fail("`node` is not on PATH; it runs the fake IDA MCP server");
    }
    let dir = PathBuf::from(IDA_PARITY_DIR);
    match std::fs::symlink_metadata(&dir) {
        Ok(meta) => {
            let mine = std::fs::metadata("/proc/self").map(|m| m.uid()).ok();
            assert!(
                meta.is_dir() && !meta.file_type().is_symlink() && Some(meta.uid()) == mine,
                "{IDA_PARITY_DIR} must be a real directory owned by the current user"
            );
        }
        Err(_) => {
            if let Err(error) = std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                assert!(dir.is_dir(), "cannot create {IDA_PARITY_DIR}: {error}");
            }
        }
    }
    write_atomic(
        &dir.join("sample_elf"),
        &std::fs::read(fixture("sample_elf")).expect("read sample_elf"),
    );
    let script = dir.join("fake_ida_mcp.mjs");
    write_atomic(&script, &std::fs::read(fixture("ida/fake_ida_mcp.mjs")).expect("read the fake IDA server"));
    let mode = if profile == "modern" { "headless" } else { "attached" };
    let registration = dir.join(format!("{profile}.json"));
    write_atomic(
        &registration,
        format!(
            "{{\"command\":\"node\",\"args\":[\"{}\",\"--profile\",\"{profile}\"],\"mode\":\"{mode}\"}}\n",
            script.display()
        )
        .as_bytes(),
    );
    let mut env: BTreeMap<String, String> = std::env::vars().collect();
    for key in [
        "GHIDRA_INSTALL_DIR",
        "JAVA_HOME",
        "REA_ANALYSIS_PROVIDER",
        "HOPPER_LAUNCHER_PATH",
        "HOPPER_LOADER_ARGS_JSON",
        "HOPPER_TARGET_PATH",
        "FAKE_IDA_LOG",
        "FAKE_IDA_PID_FILE",
        "FAKE_IDA_STALL_TOOL",
    ] {
        env.remove(key);
    }
    env.insert("REA_IDA_MCP_CONFIG".into(), registration.to_string_lossy().to_string());
    Some(env)
}

/// Like [`ida_environment`] for the oracle's variants (`fixtures/engines/ida/variants_*.json`):
/// `profile` is `legacy`, `modern`, `none` (no registration at all) or `file:NAME` (one of
/// `files`, written first); `extra` holds the `FAKE_IDA_*` switches of the variant.
pub fn ida_variant_environment(
    profile: &str,
    files: &serde_json::Map<String, Value>,
    extra: &serde_json::Map<String, Value>,
) -> Option<BTreeMap<String, String>> {
    let base = if profile == "modern" { "modern" } else { "legacy" };
    let mut env = ida_environment(base)?;
    let dir = PathBuf::from(IDA_PARITY_DIR);
    for (name, text) in files {
        write_atomic(&dir.join(name), text.as_str().expect("registration text").as_bytes());
    }
    if profile == "none" {
        env.remove("REA_IDA_MCP_CONFIG");
    } else if let Some(name) = profile.strip_prefix("file:") {
        env.insert("REA_IDA_MCP_CONFIG".into(), dir.join(name).to_string_lossy().to_string());
    }
    for (key, value) in extra {
        env.insert(key.clone(), value.as_str().expect("environment text").to_string());
    }
    Some(env)
}
