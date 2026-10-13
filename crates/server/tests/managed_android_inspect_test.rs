//! Managed PE/CLI inspectors: parity with the REA oracle.
//!
//! Oracle: REA @0fa0b04 (`inspect_managed_artifact`, `inspect_managed_members`,
//! `inspect_managed_native_boundaries`) run through `fixtures/rea_oracle.py` on
//! every file in `fixtures/managed/` (synthetic images from REA's own
//! `ManagedPe.fixture.ts` via `fixtures/managed/gen.mjs`, plus three real NuGet
//! assemblies, see `fixtures/managed/PROVENANCE.txt`). The captured results are
//! in `fixtures/managed/oracle_inspect.json`; they were produced with the
//! fixtures at `/workspace/wt/managed_android/fixtures/managed`, so that prefix
//! is rewritten to the checkout this test runs in.
//!
//! Compared in full: every `structuredContent` field, including `subject`,
//! `parameters`, `locations`, `limitations`, and the error envelopes (code,
//! category, message, remediation, details).
//! Ignored: `evidence_id`, because it hashes the absolute path. It is checked
//! for self-consistency (`Evidence::verify`) and, when the checkout sits at the
//! oracle prefix, compared exactly.

mod managed_android_support;

use std::path::PathBuf;

use rmcp::model::CallToolRequestParam;
use serde_json::Value;
use tracewise_domain::evidence::Evidence;
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

const ORACLE_PREFIX: &str = "/workspace/wt/managed_android/fixtures/managed";

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/managed").canonicalize().expect("fixtures/managed")
}

fn schema_for(tool: &str) -> jsonschema::Validator {
    let catalog: Value = serde_json::from_str(tracewise_contracts::PHASE3_TOOLS_JSON).unwrap();
    let definition = catalog["tools"].as_array().unwrap().iter().find(|t| t["name"] == tool).expect("tool in phase3");
    jsonschema::validator_for(&definition["outputSchema"]).expect("schema")
}

fn rewrite(text: &str, dir: &str) -> String {
    text.replace(ORACLE_PREFIX, dir)
}

async fn call(session: &BinarySession, tool: &str, args: Value) -> rmcp::model::CallToolResult {
    call_tool_local(
        session,
        CallToolRequestParam { name: tool.to_string().into(), arguments: Some(args.as_object().unwrap().clone()) },
    )
    .await
    .unwrap_or_else(|error| panic!("{tool}: {error}"))
}

fn strip_id(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.remove("evidence_id");
    }
    value
}

#[tokio::test]
async fn managed_inspectors_match_rea_oracle_on_every_fixture() {
    let dir = fixture_dir();
    let dir_text = dir.to_string_lossy().into_owned();
    let raw = managed_android_support::read_fixture_text(&dir.join("oracle_inspect.json"));
    let oracle: Value = serde_json::from_str(&rewrite(&raw, &dir_text)).expect("oracle json");
    let files = oracle.as_object().unwrap();
    let on_disk = std::fs::read_dir(&dir).unwrap().flatten().filter(|e| e.path().extension().is_some_and(|x| x == "dll")).count();
    assert_eq!(files.len(), on_disk, "the oracle covers every .dll fixture");
    assert_eq!(files.len(), 66, "managed fixtures");
    let mut checked = 0;
    for (name, tools) in files {
        for (tool, expected) in tools.as_object().unwrap() {
            let session = BinarySession::new();
            let path = format!("{dir_text}/{name}.dll");
            let result = call(&session, tool, serde_json::json!({ "path": path })).await;
            if let Some(error_text) = expected.get("error") {
                assert_eq!(result.is_error, Some(true), "{name} {tool} should be an error");
                let actual = result.content[0].as_text().map(|t| t.text.clone()).unwrap_or_default();
                let expected_value: Value = serde_json::from_str(error_text.as_str().unwrap()).unwrap();
                let actual_value: Value = serde_json::from_str(&actual).unwrap();
                assert_eq!(actual_value, expected_value, "{name} {tool} error envelope");
                checked += 1;
                continue;
            }
            assert_ne!(result.is_error, Some(true), "{name} {tool}: {:?}", result.content);
            let actual = result.structured_content.clone().expect("structuredContent");
            schema_for(tool)
                .validate(&actual)
                .unwrap_or_else(|error| panic!("{name} {tool} schema: {error}"));
            let evidence: Evidence = serde_json::from_value(actual.clone()).expect("evidence shape");
            evidence.verify().unwrap_or_else(|error| panic!("{name} {tool} evidence id: {error}"));
            let want = &expected["structuredContent"];
            if dir_text == ORACLE_PREFIX {
                assert_eq!(actual["evidence_id"], want["evidence_id"], "{name} {tool} evidence_id");
            }
            assert_eq!(strip_id(actual), strip_id(want.clone()), "{name} {tool}");
            checked += 1;
        }
    }
    assert_eq!(checked, 66 * 3, "oracle results checked (3 inspectors per fixture)");
}

/// Session behaviour: path selection and reuse, target classification and input
/// validation, replayed against `oracle_sequences.json` (each sequence ran in one
/// REA MCP session).
#[tokio::test]
async fn managed_inspector_sessions_match_rea_oracle() {
    let dir = fixture_dir();
    let dir_text = dir.to_string_lossy().into_owned();
    let raw = managed_android_support::read_fixture_text(&dir.join("oracle_sequences.json"));
    let raw = raw.replace("$DIR", ORACLE_PREFIX);
    let oracle: Value = serde_json::from_str(&rewrite(&raw, &dir_text)).expect("oracle json");
    let mut checked = 0;
    assert_eq!(oracle.as_object().unwrap().len(), 2, "oracle sequences");
    for (sequence, body) in oracle.as_object().unwrap() {
        let session = BinarySession::new();
        let steps = body["steps"].as_array().unwrap();
        let results = body["results"].as_array().unwrap();
        assert_eq!(steps.len(), results.len(), "{sequence}: oracle answers");
        for (index, (step, expected)) in steps.iter().zip(results).enumerate() {
            let tool = step["tool"].as_str().unwrap();
            let args = step["args"].clone();
            let result = call(&session, tool, args).await;
            let label = format!("{sequence}[{index}] {tool}");
            if let Some(error_text) = expected.get("error") {
                assert_eq!(result.is_error, Some(true), "{label} should be an error");
                let actual = result.content[0].as_text().map(|t| t.text.clone()).unwrap_or_default();
                let expected_text = error_text.as_str().unwrap();
                match (serde_json::from_str::<Value>(expected_text), serde_json::from_str::<Value>(&actual)) {
                    (Ok(want), Ok(got)) => assert_eq!(got, want, "{label} error envelope"),
                    _ => assert_eq!(actual, expected_text, "{label} error text"),
                }
            } else {
                assert_ne!(result.is_error, Some(true), "{label}: {:?}", result.content);
                let actual = result.structured_content.clone().expect("structuredContent");
                schema_for(tool).validate(&actual).unwrap_or_else(|error| panic!("{label} schema: {error}"));
                assert_eq!(strip_id(actual), strip_id(expected["structuredContent"].clone()), "{label}");
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 19);
}

/// Special targets: a character device, a FIFO and a sparse 200 MiB PE. REA refuses
/// the first two as "not a regular file" without reading them and reports the
/// third as a `resource_constraint` (snapshot budget 128 MiB). The port must give
/// the same envelopes, quickly, without hanging on the device or the FIFO.
#[tokio::test]
async fn special_targets_match_rea_oracle_without_unbounded_reads() {
    use std::os::unix::fs::FileTypeExt;
    let oracle: Value = serde_json::from_str(&std::fs::read_to_string(fixture_dir().join("oracle_special_targets.json")).unwrap()).unwrap();
    let dir = std::env::temp_dir().join(format!("tracewise-special-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let fifo = dir.join("fifo");
    assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    assert!(std::fs::metadata(&fifo).unwrap().file_type().is_fifo());
    let big = dir.join("big.dll");
    std::fs::copy(fixture_dir().join("basic.dll"), &big).unwrap();
    std::fs::OpenOptions::new().write(true).open(&big).unwrap().set_len(200 * 1024 * 1024).unwrap();
    let dir_text = dir.to_string_lossy().into_owned();
    let session = BinarySession::new();
    for entry in oracle.as_array().unwrap() {
        let tool = entry["tool"].as_str().unwrap();
        let path = entry["path"].as_str().unwrap().replace("$DIR", &dir_text);
        let started = std::time::Instant::now();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            call_tool_local(
                &session,
                CallToolRequestParam {
                    name: tool.to_string().into(),
                    arguments: Some(serde_json::json!({ "path": path }).as_object().cloned().unwrap()),
                },
            ),
        )
        .await
        .unwrap_or_else(|_| panic!("{tool} {path}: did not return within 20 s"))
        .unwrap();
        assert_eq!(result.is_error, Some(true), "{tool} {path}");
        let got = result.content[0].as_text().unwrap().text.clone();
        let want = entry["error"].as_str().unwrap().replace("$DIR", &dir_text);
        let got: Value = serde_json::from_str(&got).unwrap();
        let want: Value = serde_json::from_str(&want).unwrap();
        assert_eq!(got, want, "{tool} {path}");
        if path == "/dev/zero" || path.ends_with("/fifo") || path == "/dev/null" {
            assert!(started.elapsed() < std::time::Duration::from_secs(2), "{tool} {path}: took {:?}", started.elapsed());
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
