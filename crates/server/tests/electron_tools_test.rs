//! Electron tools: `list_electron_targets`, `inspect_electron_page`,
//! `capture_electron_scenario`.
//!
//! Ground truth comes from the ORIGINAL REA server (`fixtures/rea_oracle.py`)
//! run against headless Google Chrome serving `fixtures/web/electron_app`
//! over `file://`. Electron is not installed; Chrome is a CDP stand-in for the
//! passive tools because they only speak standard CDP (`/json/*`, `Page.*`,
//! `Runtime.enable`, `Debugger.*`, `DOMSnapshot.captureSnapshot`,
//! `Target.getTargets`). Fixtures:
//! - `fixtures/js/oracle_list_electron_targets.json`,
//!   `oracle_inspect_electron_page.json` (observation_ms 200),
//!   `oracle_inspect_electron_page_sources.json` (include_script_sources)
//! - `oracle_inspect_electron_page_target_not_found.json`,
//!   `oracle_inspect_electron_page_target_not_allowed.json` (about:blank page),
//!   `oracle_list_electron_targets_unreachable.json` (port 1),
//!   `oracle_capture_electron_scenario.json` (nonexistent paths)
//! - `fixtures/web/electron_cdp_recorded.json`: raw CDP responses/events
//!   recorded from the same Chrome session the oracle observed.
//!
//! Deterministic tests (no browser):
//! - the recorded CDP responses projected by the Rust code equal the oracle's
//!   `frames`, `resources`, `dom`, `scripts`, `workers` and `completeness`;
//! - the Evidence envelope rebuilt from the oracle's `parameters` and
//!   `normalized_result` equals the oracle `structuredContent` byte-for-byte
//!   (same `evidence_id`), for both passive tools. No field is ignored.
//! - `capture_electron_scenario` with unresolvable paths returns REA's exact
//!   `isError` body. No field is ignored.
//!
//! Live tests launch `/usr/bin/google-chrome --headless=new` (skipped when
//! absent). Fields ignored against the oracle, all process/time dependent:
//! - `evidence_id` (hashes every field below)
//! - `parameters.cdp_endpoint` (random port) and `parameters.target_id`
//! - `normalized_result.browser` and `environment.id` (Chrome build string)
//! - target ids: `targets[].target_id`, `target.target_id`
//! - `capture_window.started_at` / `ended_at`
//! - frame ids: `frames[].frame_id`, `frames[].parent_frame_id`,
//!   `scripts.items[].frame_id`, and `scripts.items[].script_key` (it hashes
//!   the frame id); script items are then compared ordered by `file_path`
//! - `list_electron_targets.excluded.non_page` (Chrome's own background
//!   pages/popups come and go).
//!
//! Browser failure bodies follow the shared tracewise convention
//! (`browser_error_body`: code, message, details). REA's `category`,
//! `retryable` and `remediation` are not compared for them.
//!
//! Active scenarios: REA's only active provider, `PlaywrightElectronActiveProvider`,
//! is ported over CDP (`tracewise_web::electron_active`) and tested against a real
//! Electron in `electron_active_*_test.rs`. This file covers the case where no
//! Electron is configured (`TRACEWISE_ELECTRON_EXECUTABLE` unset): REA's
//! provider-not-configured error (`capability_unavailable`). The projection +
//! evidence port is also validated against `outputSchema` from a recorded hook
//! snapshot here.

use std::collections::HashSet;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use proc_supervisor::{ProcessSupervisor, SupervisedChild};
use rmcp::model::{CallToolRequestParam, CallToolResult};
use serde_json::{json, Value};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;
use tracewise_web::cdp_completeness::CdpCaptureCompleteness;
use tracewise_web::cdp_connection::CdpEvent;
use tracewise_web::electron_inspection as inspection;

const CHROME: &str = "/usr/bin/google-chrome";
const ROOT: &str = "/workspace/tracewise/fixtures";
const APP_INDEX: &str = "/workspace/tracewise/fixtures/web/electron_app/index.html";

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

fn read_json(path: &str) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).expect("json")
}

fn oracle(name: &str) -> Value {
    read_json(&format!("{ROOT}/js/oracle_{name}.json"))
}

fn oracle_error(name: &str) -> Value {
    let raw = oracle(name);
    assert_eq!(raw["isError"], true, "{name} is an error oracle");
    serde_json::from_str(raw["content"][0]["text"].as_str().unwrap()).unwrap()
}

async fn call(session: &BinarySession, name: &str, args: Value) -> Result<CallToolResult, rmcp::ErrorData> {
    call_tool_local(
        session,
        CallToolRequestParam {
            name: name.to_string().into(),
            arguments: Some(args.as_object().unwrap().clone()),
        },
    )
    .await
}

async fn call_ok(session: &BinarySession, name: &str, args: Value) -> Value {
    let result = call(session, name, args).await.unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_ne!(result.is_error, Some(true), "{name}: {:?}", result.content);
    let structured = result.structured_content.expect("structuredContent");
    validate_schema(name, &structured);
    structured
}

async fn call_is_error(session: &BinarySession, name: &str, args: Value) -> Value {
    let result = call(session, name, args).await.unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(result.is_error, Some(true), "{name} should be isError");
    let text = result.content[0].as_text().expect("text content").text.clone();
    serde_json::from_str(&text).expect("error body json")
}

/// Compare only the fields tracewise's shared browser error body carries.
fn assert_browser_error(actual: &Value, expected: &Value) {
    for key in ["code", "message", "details"] {
        assert_eq!(actual["error"][key], expected["error"][key], "error.{key}");
    }
}

// ---------------------------------------------------------------- recorded

fn recorded_state() -> (Value, inspection::ElectronEventState) {
    let recorded = read_json(&format!("{ROOT}/web/electron_cdp_recorded.json"));
    let mut state = inspection::ElectronEventState::default();
    for event in recorded["events"].as_array().unwrap() {
        state.ingest(
            &CdpEvent {
                method: event["method"].as_str().unwrap().to_string(),
                params: event["params"].clone(),
                session_id: None,
            },
            None,
        );
    }
    (recorded, state)
}

#[test]
fn recorded_cdp_responses_project_to_oracle_inspection() {
    let expected = &oracle("inspect_electron_page")["structuredContent"]["normalized_result"];
    let (recorded, mut state) = recorded_state();
    let frames = inspection::capture_frames(recorded["frame_tree"].as_object().unwrap(), &mut state.completeness)
        .expect("frames");
    assert_eq!(Value::from(frames.clone()), expected["frames"]);
    let frame_ids: HashSet<String> = frames
        .iter()
        .map(|frame| frame["frame_id"].as_str().unwrap().to_string())
        .collect();
    let resources =
        inspection::capture_resources(recorded["resource_tree"].as_object().unwrap(), &mut state.completeness)
            .expect("resources");
    assert_eq!(Value::from(resources), expected["resources"]);
    let dom = inspection::capture_dom(recorded["dom_snapshot"].as_object().unwrap(), &mut state.completeness);
    assert_eq!(dom, expected["dom"]);
    let selected = inspection::select_scripts(&mut state, &frame_ids).expect("scripts");
    let sources = vec![inspection::not_selected_source(); selected.len()];
    let scripts = inspection::assemble_scripts(selected, sources, false, &mut state.completeness);
    assert_eq!(scripts, expected["scripts"]);
    let page_target = expected["target"]["target_id"].as_str().unwrap();
    let workers = inspection::project_workers(
        &recorded["targets"]["targetInfos"],
        page_target,
        &frame_ids,
        &mut state.completeness,
    );
    assert_eq!(Value::from(workers), expected["workers"]);
    assert_eq!(state.completeness.snapshot(), expected["completeness"]);
}

#[test]
fn recorded_worker_targets_are_scoped_to_the_page() {
    // Synthetic Target.getTargets entries: Chrome refuses file:// workers, so
    // the recording holds only an out-of-scope extension service worker.
    let mut completeness = CdpCaptureCompleteness::new(&[]);
    let frame_ids: HashSet<String> = ["F".to_string()].into();
    let worker_url = format!("file://{}", APP_INDEX.replace("index.html", "app.js"));
    let workers = inspection::project_workers(
        &json!([
            { "targetId": "W2", "type": "worker", "url": worker_url, "attached": true, "parentFrameId": "F" },
            { "targetId": "W1", "type": "shared_worker", "url": worker_url, "openerId": "PAGE" },
            { "targetId": "W3", "type": "worker", "url": worker_url, "openerId": "OTHER" },
            { "targetId": "W4", "type": "worker", "url": "https://example.com/w.js", "openerId": "PAGE" },
            { "targetId": "", "type": "worker", "url": worker_url, "openerId": "PAGE" },
            { "targetId": "P", "type": "page", "url": worker_url },
        ]),
        "PAGE",
        &frame_ids,
        &mut completeness,
    );
    let ids: Vec<&str> = workers.iter().map(|w| w["target_id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["W1", "W2"]);
    assert_eq!(workers[1]["attached"], true);
    assert_eq!(workers[1]["opener_target_id"], Value::Null);
    assert_eq!(workers[0]["parent_frame_id"], Value::Null);
    let snapshot = completeness.snapshot();
    assert_eq!(
        snapshot["excluded"],
        json!([
            { "section": "workers", "reason": "invalid_protocol_value", "count": 1 },
            { "section": "workers", "reason": "out_of_target_scope", "count": 2 },
        ])
    );
}

#[test]
fn evidence_envelopes_match_oracle_exactly() {
    for (name, operation) in [
        ("list_electron_targets", "list_electron_targets"),
        ("inspect_electron_page", "inspect_electron_page"),
        ("inspect_electron_page_sources", "inspect_electron_page"),
    ] {
        let expected = oracle(name)["structuredContent"].clone();
        validate_schema(operation, &expected);
        let evidence = tracewise_web::electron_targets::create_electron_evidence(
            operation,
            expected["parameters"].clone(),
            expected["normalized_result"].clone(),
        )
        .expect("evidence");
        assert_eq!(serde_json::to_value(&evidence).unwrap(), expected, "{name}");
    }
}

#[test]
fn capture_projection_validates_against_output_schema() {
    use tracewise_web::electron_scenario::{
        canonicalize_scenario, create_electron_active_evidence, parse_capture_electron_scenario_input,
        project_electron_active_capture, ElectronCaptureState,
    };
    let input = parse_capture_electron_scenario_input(&json!({
        "executable_path": "/bin/sh",
        "application_path": APP_INDEX,
        "actions": [{ "step_id": "export", "kind": "click", "selector": "#export" }],
    }))
    .unwrap();
    let canonical = canonicalize_scenario(&input).unwrap();
    assert_eq!(canonical["application_root"], "/workspace/tracewise/fixtures/web/electron_app");
    let event = json!({
        "sequence": 1, "correlation_id": null, "kind": "ipc-renderer-invoke", "event": null,
        "phase": "observed", "channel": "export:pdf", "direction": "renderer-to-main",
        "sender": "webContents:1", "receiver": "main", "frame": null, "target": null,
        "argument_shapes": ["object"], "result_shape": "string", "process_type": "renderer",
        "source": "electron-active-hook", "capture_method": "api-wrapper",
        "artifact_path": null, "artifact_sha256": null, "error": false,
    });
    let state = ElectronCaptureState {
        windows: vec![json!({
            "window_id": "window:1", "web_contents_id": "webContents:1", "url": format!("file://{APP_INDEX}"),
            "title": "Tracewise Electron Fixture", "visible": true, "destroyed": false,
        })],
        metrics: vec![json!({ "pid": 42, "type": "Browser", "name": null, "service_name": null })],
        electron_version: "37.2.0".to_string(),
        hook_snapshot: json!({
            "events": [event], "retention_budget_bytes": 16777216, "estimated_retained_bytes": 400,
            "event_serialized_byte_upper_bound": 400, "retained": 1, "dropped": 0, "dropped_ipc": 0,
            "dropped_runtime": 0, "dropped_event_families": [], "dropped_event_roles": [],
            "observed": 1, "observed_ipc": 1, "observed_runtime": 0, "hook_error": false,
        }),
    };
    let actions = vec![json!({
        "step_id": "export", "kind": "click", "window_index": 0, "target": "window:0",
        "status": "completed", "elapsed_ms": 12, "error": null,
    })];
    let result = project_electron_active_capture(
        canonical["executable_path"].as_str().unwrap(),
        canonical["application_path"].as_str().unwrap(),
        actions,
        &state,
    );
    let evidence = create_electron_active_evidence(&canonical, result).unwrap();
    let structured = serde_json::to_value(&evidence).unwrap();
    validate_schema("capture_electron_scenario", &structured);
    assert_eq!(structured["provider"]["id"], "rea-playwright-electron-active");
    assert_eq!(structured["environment"]["id"], "37.2.0@unknown");
    assert_eq!(structured["normalized_result"]["coverage"]["observed_roles"], json!(["renderer"]));
    assert!(structured["parameters"]["scenario_sha256"].as_str().unwrap().len() == 64);
}

// ---------------------------------------------------------------- no browser

#[tokio::test]
async fn capture_electron_scenario_errors_match_rea() {
    let session = BinarySession::new();
    // Unresolvable paths: exact REA isError body.
    let body = call_is_error(
        &session,
        "capture_electron_scenario",
        json!({ "executable_path": "/nonexistent/electron", "application_path": "/nonexistent/app/main.js" }),
    )
    .await;
    assert_eq!(body, oracle_error("capture_electron_scenario"));

    // Existing paths: REA's provider-not-configured failure.
    let body = call_is_error(
        &session,
        "capture_electron_scenario",
        json!({ "executable_path": "/bin/sh", "application_path": APP_INDEX }),
    )
    .await;
    assert_eq!(
        body,
        json!({ "error": {
            "code": "capability_unavailable",
            "category": "unsupported_provider",
            "message": "This analysis is unavailable for the current target. Choose another analysis or target.",
            "retryable": false,
            "remediation": { "action": "This analysis is unavailable for the current target. Choose another analysis or target." },
            "details": {
                "provider_id": "rea-playwright-electron-active",
                "operation": "capture_electron_scenario",
                "reason": "active Electron observation provider is not configured",
            },
        }})
    );

    // Schema violations are protocol errors carrying REA's zod issue text.
    for (args, issue) in [
        (json!({ "executable_path": "electron", "application_path": "app" }),
         "executable_path: Electron executable, application, and root paths must be absolute local filesystem paths (for example /Applications/Electron.app/Contents/MacOS/Electron), application_path: Electron executable, application, and root paths must be absolute local filesystem paths (for example /Applications/Electron.app/Contents/MacOS/Electron)"),
        (json!({ "executable_path": "/bin/sh", "application_path": APP_INDEX, "extra": 1 }), "Unrecognized key: \"extra\""),
        (json!({ "executable_path": "/bin/sh", "application_path": APP_INDEX, "args": ["a\u{0}b"] }),
         "args.0: Electron arguments must not contain NUL"),
        (json!({ "executable_path": "/bin/sh", "application_path": APP_INDEX,
                 "actions": [{ "step_id": "s", "kind": "deep-link", "delivery": "open-url", "url": "notaurl" }] }),
         "actions.0.url: deep-link url must be an absolute URL"),
    ] {
        let error = call(&session, "capture_electron_scenario", args).await.expect_err("protocol error");
        assert!(error.message.contains(issue), "{} !~ {issue}", error.message);
    }
}

#[tokio::test]
async fn unreachable_endpoint_and_invalid_input() {
    let session = BinarySession::new();
    let body = call_is_error(&session, "list_electron_targets", json!({ "cdp_endpoint": "http://127.0.0.1:1" })).await;
    assert_browser_error(&body, &oracle_error("list_electron_targets_unreachable"));
    for (tool, args) in [
        ("list_electron_targets", json!({})),
        ("list_electron_targets", json!({ "cdp_endpoint": "http://example.com:9222" })),
        ("inspect_electron_page", json!({ "cdp_endpoint": "http://127.0.0.1:9222" })),
        ("inspect_electron_page", json!({ "cdp_endpoint": "http://127.0.0.1:9222", "target_id": "  " })),
        ("inspect_electron_page", json!({ "cdp_endpoint": "http://127.0.0.1:9222", "target_id": "x", "observation_ms": -1 })),
        ("inspect_electron_page", json!({ "cdp_endpoint": "http://127.0.0.1:9222", "target_id": "x", "extra": 1 })),
    ] {
        assert!(call(&session, tool, args.clone()).await.is_err(), "{tool} {args}");
    }
}

// ---------------------------------------------------------------- live

fn strip(value: &mut Value, path: &[&str]) {
    match path {
        [] => {}
        [last] => {
            if let Some(object) = value.as_object_mut() {
                object.remove(*last);
            }
        }
        ["*", rest @ ..] => {
            if let Some(items) = value.as_array_mut() {
                for item in items {
                    strip(item, rest);
                }
            }
        }
        [head, rest @ ..] => {
            if let Some(next) = value.get_mut(*head) {
                strip(next, rest);
            }
        }
    }
}

fn normalize_inspection(mut value: Value) -> Value {
    for path in [
        &["evidence_id"][..],
        &["parameters", "cdp_endpoint"],
        &["parameters", "target_id"],
        &["environment", "id"],
        &["normalized_result", "browser"],
        &["normalized_result", "target", "target_id"],
        &["normalized_result", "capture_window", "started_at"],
        &["normalized_result", "capture_window", "ended_at"],
        &["normalized_result", "frames", "*", "frame_id"],
        &["normalized_result", "frames", "*", "parent_frame_id"],
        &["normalized_result", "scripts", "items", "*", "frame_id"],
        &["normalized_result", "scripts", "items", "*", "script_key"],
    ] {
        strip(&mut value, path);
    }
    if let Some(items) = value["normalized_result"]["scripts"]["items"].as_array_mut() {
        items.sort_by(|a, b| a["file_path"].as_str().cmp(&b["file_path"].as_str()));
    }
    value
}

#[tokio::test]
async fn live_chrome_stand_in_matches_oracle() {
    if !std::path::Path::new(CHROME).exists() {
        eprintln!("skipping: {CHROME} not installed");
        return;
    }
    let chrome = ChromeDebug::launch(&format!("file://{APP_INDEX}"));
    let session = BinarySession::new();
    let endpoint = chrome.endpoint.clone();
    let list = wait_for_list(&session, &endpoint).await;

    let mut expected = oracle("list_electron_targets")["structuredContent"].clone();
    let mut actual = list.clone();
    for value in [&mut expected, &mut actual] {
        for path in [
            &["evidence_id"][..],
            &["parameters", "cdp_endpoint"],
            &["normalized_result", "browser"],
            &["normalized_result", "targets", "*", "target_id"],
            &["normalized_result", "excluded", "non_page"],
        ] {
            strip(value, path);
        }
    }
    assert_eq!(actual, expected, "list_electron_targets");
    let target_id = list["normalized_result"]["targets"][0]["target_id"].as_str().unwrap().to_string();

    let inspected = call_ok(
        &session,
        "inspect_electron_page",
        json!({ "cdp_endpoint": endpoint, "target_id": target_id, "observation_ms": 200 }),
    )
    .await;
    assert_eq!(
        inspected["normalized_result"]["frames"][1]["parent_frame_id"],
        inspected["normalized_result"]["frames"][0]["frame_id"]
    );
    assert_eq!(
        normalize_inspection(inspected),
        normalize_inspection(oracle("inspect_electron_page")["structuredContent"].clone()),
        "inspect_electron_page"
    );

    let with_sources = call_ok(
        &session,
        "inspect_electron_page",
        json!({ "cdp_endpoint": endpoint, "target_id": target_id, "observation_ms": 0, "include_script_sources": true }),
    )
    .await;
    assert_eq!(
        normalize_inspection(with_sources),
        normalize_inspection(oracle("inspect_electron_page_sources")["structuredContent"].clone()),
        "inspect_electron_page include_script_sources"
    );

    let body = call_is_error(
        &session,
        "inspect_electron_page",
        json!({ "cdp_endpoint": endpoint, "target_id": "missing-target" }),
    )
    .await;
    assert_browser_error(&body, &oracle_error("inspect_electron_page_target_not_found"));

    // A non-file page (about:blank) is listed as unsupported and refused.
    let discovery = tracewise_web::cdp_endpoint::discover_cdp_endpoint(&endpoint, "list_electron_targets")
        .await
        .expect("discovery");
    let mut browser =
        tracewise_web::cdp_connection::CdpConnection::connect(discovery.web_socket.url(), "list_electron_targets")
            .await
            .expect("browser socket");
    let created = browser
        .send("Target.createTarget", json!({ "url": "about:blank" }), None)
        .await
        .expect("Target.createTarget");
    browser.close().await;
    let blank_id = created["targetId"].as_str().expect("targetId").to_string();
    let relisted = call_ok(&session, "list_electron_targets", json!({ "cdp_endpoint": endpoint })).await;
    assert_eq!(relisted["normalized_result"]["excluded"]["unsupported_url"], 1);
    assert_eq!(relisted["normalized_result"]["targets"].as_array().unwrap().len(), 1);
    let body = call_is_error(
        &session,
        "inspect_electron_page",
        json!({ "cdp_endpoint": endpoint, "target_id": blank_id }),
    )
    .await;
    assert_browser_error(&body, &oracle_error("inspect_electron_page_target_not_allowed"));
}

async fn wait_for_list(session: &BinarySession, endpoint: &str) -> Value {
    for _ in 0..60 {
        if let Ok(result) = call(session, "list_electron_targets", json!({ "cdp_endpoint": endpoint })).await {
            if result.is_error != Some(true) {
                let structured = result.structured_content.expect("structuredContent");
                validate_schema("list_electron_targets", &structured);
                // Wait for the load to commit: the title comes from the parsed document.
                let ready = structured["normalized_result"]["targets"].as_array().is_some_and(|t| {
                    t.len() == 1 && t[0]["title"] == "Tracewise Electron Fixture"
                });
                if ready {
                    // Let the iframe and scripts finish loading.
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    return structured;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let last = call(session, "list_electron_targets", json!({ "cdp_endpoint": endpoint })).await;
    panic!("chrome never exposed the fixture page at {endpoint}: {last:?}");
}

struct ChromeDebug {
    endpoint: String,
    child: Option<SupervisedChild>,
    user_data_dir: PathBuf,
}

impl ChromeDebug {
    fn launch(url: &str) -> Self {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let user_data_dir =
            std::env::temp_dir().join(format!("tracewise-electron-{port}-{}", std::process::id()));
        std::fs::create_dir_all(&user_data_dir).expect("user-data-dir");
        let mut supervisor = ProcessSupervisor::new(CHROME);
        supervisor.null_stdio();
        for arg in [
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--remote-debugging-address=127.0.0.1",
            "--remote-allow-origins=*",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-extensions",
        ] {
            supervisor.arg(arg);
        }
        supervisor.arg(format!("--user-data-dir={}", user_data_dir.display()));
        supervisor.arg(format!("--remote-debugging-port={port}"));
        // Headless Chrome accepts a single start URL.
        supervisor.arg(url);
        let child = supervisor.spawn().expect("spawn google-chrome");
        Self {
            endpoint: format!("http://127.0.0.1:{port}"),
            child: Some(child),
            user_data_dir,
        }
    }
}

impl Drop for ChromeDebug {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill_group();
        }
        // Chrome's zygote may leave the process group; kill by user-data-dir.
        let needle = self.user_data_dir.display().to_string();
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let pid = entry.file_name().to_string_lossy().to_string();
                if pid.parse::<u32>().is_err() {
                    continue;
                }
                if let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) {
                    if String::from_utf8_lossy(&cmdline).contains(&needle) {
                        let _ = Command::new("kill").args(["-KILL", &pid]).status();
                    }
                }
            }
        }
        let _ = std::fs::remove_dir_all(&self.user_data_dir);
    }
}

