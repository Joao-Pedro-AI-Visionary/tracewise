//! Shared harness of the native_static oracle tests.
//!
//! Scenarios live in `fixtures/native_static/scenarios.json`; the oracle
//! results in `fixtures/native_static/oracle/<id>.json` were produced by
//! `fixtures/native_static/gen_oracle.py` against the original REA server with
//! the fixtures at `/workspace/wt/native_static/...`.
//!
//! Normalization applied to both sides (so no field is silently ignored):
//! - the checkout prefix (`/workspace/wt/native_static` in the oracle files, the
//!   actual workspace root here) becomes `$ROOT`, because paths enter Evidence;
//! - the top-level `evidence_id` is dropped (it hashes the absolute path);
//! - `$FIX` in scenario arguments is the fixtures directory;
//! - the remediation of "not an NSKeyedArchiver archive" errors: REA on Linux
//!   says `inspect_plist` needs a macOS host; tracewise implements
//!   `inspect_plist` natively, so the expectation uses REA's macOS wording;
//! - per-suite `ignore` paths (documented by each test).

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use rmcp::model::{CallToolRequestParam, CallToolResult};
use serde_json::{json, Value};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

pub const ORACLE_ROOT: &str = "/workspace/wt/native_static";
const LINUX_PLIST_REMEDIATION: &str = "Select an NSKeyedArchiver archive; inspect_keyed_archive decodes only those. inspect_plist, which reads ordinary property lists, requires a macOS host.";
const MACOS_PLIST_REMEDIATION: &str = "Inspect an ordinary property list with inspect_plist; inspect_keyed_archive decodes NSKeyedArchiver archives only.";

pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

/// Directories the scenarios need EMPTY. Git does not version empty directories, so a clean
/// checkout lacks them; they are created here, once per test process, instead of being committed.
const EMPTY_FIXTURE_DIRECTORIES: [&str; 3] = ["apple/Empty.app", "evm/dir.hex", "bundles/Rich.app/Contents/Plugins"];

pub fn fixtures() -> PathBuf {
    static PREPARED: std::sync::Once = std::sync::Once::new();
    let root = workspace_root().join("fixtures/native_static");
    PREPARED.call_once(|| {
        for relative in EMPTY_FIXTURE_DIRECTORIES {
            std::fs::create_dir_all(root.join(relative)).expect("create an empty fixture directory");
        }
    });
    root
}

pub fn output_schema(tool: &str) -> Option<Value> {
    // The tools under test live in phase 4; the tools that feed them (`open_binary`,
    // `inspect_artifact`) in the earlier catalogs.
    for file in ["phase4", "phase0", "phase1", "phase2", "phase3"] {
        let path = workspace_root().join(format!("crates/contracts/{file}_tools.json"));
        let catalog: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        if let Some(found) = catalog["tools"].as_array().unwrap().iter().find(|t| t["name"] == tool) {
            return Some(found["outputSchema"].clone());
        }
    }
    None
}

fn remove_path(value: &mut Value, path: &[&str]) {
    if let Some((last, parents)) = path.split_last() {
        let mut current = value;
        for key in parents {
            match current.get_mut(*key) {
                Some(next) => current = next,
                None => return,
            }
        }
        if let Some(object) = current.as_object_mut() {
            object.remove(*last);
        }
    }
}

fn drop_limitations(value: &mut Value, prefixes: &[&str]) {
    match value {
        Value::Object(map) => {
            if let Some(Value::Array(items)) = map.get_mut("limitations") {
                items.retain(|item| {
                    !item
                        .as_str()
                        .map(|text| prefixes.iter().any(|prefix| text.starts_with(prefix)))
                        .unwrap_or(false)
                });
            }
            for child in map.values_mut() {
                drop_limitations(child, prefixes);
            }
        }
        Value::Array(items) => {
            for child in items {
                drop_limitations(child, prefixes);
            }
        }
        _ => {}
    }
}

pub fn normalize(value: &Value, root: &str, ignore: &[&[&str]], drop_prefixes: &[&str]) -> Value {
    let text = value.to_string().replace(root, "$ROOT");
    let mut parsed: Value = serde_json::from_str(&text).unwrap();
    if let Some(object) = parsed.as_object_mut() {
        object.remove("evidence_id");
    }
    if let Some(structured) = parsed.get_mut("structured") {
        if let Some(object) = structured.as_object_mut() {
            object.remove("evidence_id");
        }
    }
    for path in ignore {
        remove_path(&mut parsed, path);
    }
    if !drop_prefixes.is_empty() {
        drop_limitations(&mut parsed, drop_prefixes);
    }
    parsed
}

/// The comparable payload of a result: structured content, or the parsed error text.
pub fn payload(result: &CallToolResult) -> Value {
    if result.is_error == Some(true) {
        let text = result
            .content
            .iter()
            .find_map(|c| c.as_text().map(|t| t.text.clone()))
            .expect("error text");
        return match serde_json::from_str::<Value>(&text) {
            Ok(value) => json!({"isError": true, "error": value}),
            Err(_) => json!({"isError": true, "text": text}),
        };
    }
    json!({"isError": false, "structured": result.structured_content.clone().expect("structuredContent")})
}

pub fn oracle_payload(entry: &Value) -> Value {
    if entry["isError"] == json!(true) {
        let text = entry["content"][0]["text"].as_str().expect("error text");
        let text = text.replace(LINUX_PLIST_REMEDIATION, MACOS_PLIST_REMEDIATION);
        return match serde_json::from_str::<Value>(&text) {
            Ok(value) => json!({"isError": true, "error": value}),
            Err(_) => json!({"isError": true, "text": text}),
        };
    }
    json!({"isError": false, "structured": entry["structuredContent"].clone()})
}

pub async fn call(session: &BinarySession, name: &str, arguments: &Value) -> Result<CallToolResult, rmcp::ErrorData> {
    call_tool_local(
        session,
        CallToolRequestParam {
            name: name.to_string().into(),
            arguments: Some(arguments.as_object().cloned().unwrap_or_default()),
        },
    )
    .await
}

fn substitute(value: &Value, fixtures: &str) -> Value {
    match value {
        Value::String(text) => Value::String(text.replace("$FIX", fixtures)),
        Value::Array(items) => Value::Array(items.iter().map(|v| substitute(v, fixtures)).collect()),
        Value::Object(map) => Value::Object(map.iter().map(|(k, v)| (k.clone(), substitute(v, fixtures))).collect()),
        other => other.clone(),
    }
}

fn resolve_results(value: &Value, results: &[Option<Value>]) -> Value {
    match value {
        Value::Object(map) if map.contains_key("$result") => {
            let index = map["$result"].as_u64().unwrap() as usize;
            let mut base = results[index].clone().expect("structured content of an earlier call");
            if map.get("inner") == Some(&json!(true)) {
                base = base["normalized_result"]["substeps"][0]["evidence"].clone();
            }
            let object = base.as_object_mut().expect("evidence object");
            if let Some(Value::Array(drop)) = map.get("drop") {
                for key in drop {
                    object.remove(key.as_str().unwrap());
                }
            }
            if let Some(Value::Object(set)) = map.get("set") {
                for (key, item) in set {
                    object.insert(key.clone(), item.clone());
                }
            }
            base
        }
        Value::Object(map) => Value::Object(map.iter().map(|(k, v)| (k.clone(), resolve_results(v, results))).collect()),
        Value::Array(items) => Value::Array(items.iter().map(|v| resolve_results(v, results)).collect()),
        other => other.clone(),
    }
}

/// Evidence ids hash the record, including the paths in it, so Evidence captured at `ORACLE_ROOT`
/// cannot simply have its paths edited: the tool would reject it as tampered. Rewrite the paths and
/// recompute every id (inner Evidence first, references to the old ids follow), which is exactly what
/// the tool being tested would have been given had the oracle run in this checkout.
fn retarget_evidence(arguments: &Value, actual_root: &str) -> (Value, Vec<(String, String)>) {
    let mut text = arguments.to_string().replace(ORACLE_ROOT, actual_root);
    let mut all_renames: Vec<(String, String)> = Vec::new();
    for _ in 0..8 {
        let value: Value = serde_json::from_str(&text).unwrap();
        let mut renamed: Vec<(String, String)> = Vec::new();
        collect_new_ids(&value, &mut renamed);
        if renamed.is_empty() {
            break;
        }
        for (old, new) in renamed {
            text = text.replace(&old, &new);
            all_renames.push((old, new));
        }
    }
    (serde_json::from_str(&text).unwrap(), all_renames)
}

fn collect_new_ids(value: &Value, renamed: &mut Vec<(String, String)>) {
    match value {
        Value::Object(map) => {
            if map.contains_key("evidence_id") && map.contains_key("predicate_type") {
                if let Ok(evidence) = serde_json::from_value::<tracewise_domain::evidence::Evidence>(value.clone()) {
                    if let Ok(id) = evidence.compute_id() {
                        if id != evidence.evidence_id {
                            renamed.push((evidence.evidence_id.clone(), id));
                        }
                    }
                }
            }
            // `inspection_id` hashes the whole inspection, the inventory Evidence (paths included)
            // among it: the same treatment as an Evidence id.
            if let Some(Value::String(old)) = map.get("inspection_id") {
                if old.starts_with("ai_") && map.contains_key("substeps") {
                    let mut semantic = map.clone();
                    semantic.remove("inspection_id");
                    if let Ok(digest) = tracewise_domain::canonical_sha256(&Value::Object(semantic)) {
                        let id = format!("ai_{digest}");
                        if &id != old {
                            renamed.push((old.clone(), id));
                        }
                    }
                }
            }
            for item in map.values() {
                collect_new_ids(item, renamed);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect_new_ids(item, renamed)),
        _ => {}
    }
}

/// Run every scenario whose id starts with `prefix` and compare with its oracle file.
pub async fn run_scenarios(prefix: &str, ignore: &[&[&str]]) -> usize {
    run_scenarios_with(prefix, ignore, &[]).await
}

/// Like `run_scenarios`, additionally dropping limitation sentences with the given prefixes.
pub async fn run_scenarios_with(prefix: &str, ignore: &[&[&str]], drop_prefixes: &[&str]) -> usize {
    run_scenarios_impl(prefix, ignore, drop_prefixes, false).await
}

/// Replay EVERY call of the scenarios with tracewise's own tools, ignoring `only`: the tools that
/// produce the input of the tool under test run here too, and each of their answers is compared
/// with the oracle's. Evidence ids are compared as well (see `retarget_evidence`: the oracle's
/// Evidence is rewritten to this checkout's paths and its ids recomputed, which is exactly what an
/// identical tool would have produced here).
pub async fn run_scenarios_full(prefix: &str, ignore: &[&[&str]]) -> usize {
    run_scenarios_impl(prefix, ignore, &[], true).await
}

async fn run_scenarios_impl(prefix: &str, ignore: &[&[&str]], drop_prefixes: &[&str], full: bool) -> usize {
    let scenarios: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(fixtures().join("scenarios.json")).unwrap()).unwrap();
    let actual_root = workspace_root().to_string_lossy().into_owned();
    let fixtures_dir = fixtures().to_string_lossy().into_owned();
    let mut compared = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for scenario in scenarios.iter().filter(|s| s["id"].as_str().unwrap().starts_with(prefix)) {
        let id = scenario["id"].as_str().unwrap();
        let oracle: Vec<Value> =
            serde_json::from_str(&std::fs::read_to_string(fixtures().join("oracle").join(format!("{id}.json"))).unwrap())
                .unwrap();
        let session = BinarySession::new();
        if let Some(open) = scenario["open"].as_str() {
            let path = fixtures().join(open);
            call(&session, "open_binary", &json!({"path": path.to_string_lossy()}))
                .await
                .unwrap_or_else(|e| panic!("{id}: open_binary: {e:?}"));
        }
        // `only`: replay just that tool; earlier calls feed it with the ORACLE's results, so the
        // comparison isolates the tool under test from the tools that produced its input.
        let only = if full { None } else { scenario["only"].as_str() };
        let mut results: Vec<Option<Value>> = Vec::new();
        // Evidence ids of the retargeted input (oracle id -> id in this checkout).
        let mut renames: Vec<(String, String)> = Vec::new();
        for (index, request) in scenario["calls"].as_array().unwrap().iter().enumerate() {
            let name = request["name"].as_str().unwrap();
            if let Some(only) = only {
                if name != only {
                    // Evidence recorded by the oracle names the checkout it ran in; point it at this one
                    // before the scenario's own edits (tampering) are applied on top.
                    let recorded = oracle[index].get("structuredContent").cloned();
                    results.push(match recorded {
                        Some(value) if actual_root != ORACLE_ROOT => {
                            let (value, renamed) = retarget_evidence(&value, &actual_root);
                            renames.extend(renamed);
                            Some(value)
                        }
                        other => other,
                    });
                    continue;
                }
            }
            let arguments = resolve_results(&substitute(&request["arguments"], &fixtures_dir), &results);

            let result = call(&session, name, &arguments)
                .await
                .unwrap_or_else(|e| panic!("{id}: {name} returned a protocol error: {e:?}"));
            results.push(result.structured_content.clone());
            if result.is_error != Some(true) {
                let structured = result.structured_content.clone().expect("structuredContent");
                match output_schema(name) {
                    Some(schema) => {
                        let validator = jsonschema::validator_for(&schema).expect("schema");
                        if let Err(error) = validator.validate(&structured) {
                            failures.push(format!("{id}: {name} violates outputSchema: {error}"));
                        }
                    }
                    // A tool without a contract schema must not pass unchecked.
                    None => failures.push(format!("{id}: {name} has no outputSchema in the catalog")),
                }
            }
            // The ids the tool copies from its input follow the retargeting. The projection id is a hash
            // over them and over paths, so it cannot be derived here and is compared only when this
            // checkout is the one the oracle ran in.
            let mut expected_payload = oracle_payload(&oracle[index]);
            // Paths in the expected payload: `ORACLE_ROOT`, unless the whole payload was rewritten.
            let mut expected_root = ORACLE_ROOT;
            if full && actual_root != ORACLE_ROOT {
                // Ids the earlier calls renamed, first, so that Evidence nested in this payload is
                // already in this checkout's terms when its own id is recomputed.
                let mut text = expected_payload.to_string();
                for (old, new) in &renames {
                    text = text.replace(old.as_str(), new.as_str());
                }
                expected_payload = serde_json::from_str(&text).unwrap();
                if let Some(structured) = expected_payload.get("structured").cloned() {
                    let (retargeted, renamed) = retarget_evidence(&structured, &actual_root);
                    expected_payload["structured"] = retargeted;
                    renames.extend(renamed);
                }
                expected_payload = serde_json::from_str(&expected_payload.to_string().replace(ORACLE_ROOT, &actual_root)).unwrap();
                expected_root = &actual_root;
            } else if !renames.is_empty() {
                let mut text = expected_payload.to_string();
                for (old, new) in &renames {
                    text = text.replace(old.as_str(), new.as_str());
                }
                expected_payload = serde_json::from_str(&text).unwrap();
            }
            if full {
                // Every Evidence this call returns must carry the id the oracle's would have here.
                let got_id = result.structured_content.as_ref().and_then(|v| v.get("evidence_id")).cloned();
                let want_id = expected_payload.get("structured").and_then(|v| v.get("evidence_id")).cloned();
                // A projection's own id hashes `projection_id`, which is not derivable here (above).
                let projection = actual_root != ORACLE_ROOT
                    && expected_payload["structured"]["normalized_result"].get("projection_id").is_some();
                if got_id != want_id && !projection {
                    failures.push(format!("{id}: {name} evidence_id {got_id:?}, the oracle's would be {want_id:?}"));
                }
            }
            let mut ignore_here: Vec<&[&str]> = ignore.to_vec();
            if actual_root != ORACLE_ROOT {
                ignore_here.push(&["structured", "normalized_result", "projection_id"]);
            }
            let ignore_here: &[&[&str]] = &ignore_here;
            let expected = normalize(&expected_payload, expected_root, ignore_here, drop_prefixes);
            let got = normalize(&payload(&result), &actual_root, ignore_here, drop_prefixes);
            if expected != got {
                let dir = std::env::temp_dir().join("native_static_diff");
                let _ = std::fs::create_dir_all(&dir);
                let _ = std::fs::write(
                    dir.join(format!("{id}.{index}.{name}.expected.json")),
                    serde_json::to_string_pretty(&expected).unwrap(),
                );
                let _ = std::fs::write(
                    dir.join(format!("{id}.{index}.{name}.actual.json")),
                    serde_json::to_string_pretty(&got).unwrap(),
                );
                failures.push(format!("{id}: {name} differs from the oracle (see {})", dir.display()));
            }
            compared += 1;
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    compared
}
