//! Active `capture_electron_scenario` against a real Electron 44.7.0.
//!
//! Ground truth is the ORIGINAL REA server run (`fixtures/electron/gen_oracle.sh`)
//! with the same Electron, the same fixture application
//! (`fixtures/electron/readiness_app`, REA's own readiness app) and the same six
//! actions as REA's `verify:electron` lane. Both run on a private Xvfb display
//! with `--no-sandbox --disable-gpu`.
//!
//! What the oracle can and cannot give here: REA's Playwright provider finishes the
//! scenario and then cannot verify cleanup on Linux. Chromium rewrites the
//! argv/environ area of its helper processes, so `/proc/<pid>/environ` has no
//! `REA_PROCESS_RUN_ID` and REA reports `cleanup_incomplete`, keeping the whole
//! capture in `details.partial_observation` (and leaving Electron running, which the
//! generator kills). The golden is that capture. The parity test therefore compares
//! the Rust result with the golden's `partial_observation.capture`, and the
//! `cleanup_incomplete` body shape with the golden's error body.
//!
//! Compared exactly: `application` (except `cleanup`), `actions` (except `elapsed_ms`),
//! `windows`, `processes.items` (as a multiset of type/name/service, pids dropped),
//! `ipc.events` (all fields except `sequence`/`correlation_id`, which embed the pid),
//! `coverage`, `limitations`, `retention` counters that do not depend on timing, and the
//! multiset of the deterministic timeline events listed in `STABLE_EVENTS`.
//!
//! Ignored, with the reason:
//! - `application.cleanup`: REA says `unverified` (see above); Rust verifies by
//!   process group and says `terminated-owned-process`.
//! - `actions[].elapsed_ms`, `sequence`, `correlation_id`, process pids: time/process.
//! - every other timeline event (focus, blur, move, mouse, paint, ready-to-show,
//!   listener bookkeeping, the spellcheck dictionary download that a fresh
//!   private profile triggers, ...): window-manager/paint/timing dependent. Three runs of the oracle
//!   and three of Rust agreed on all but four of those signatures; `ready-to-show` only
//!   appears under Playwright (it enables Page/Emulation domains), the spellcheck
//!   events only under the private profile.
//! - `retention.estimated_retained_bytes`, `event_serialized_byte_upper_bound`,
//!   `retained`, `observed_runtime`: functions of the ignored events.
//!
//! The Electron path is taken from `TRACEWISE_TEST_ELECTRON`
//! (default `/workspace/tools/electron-44.7.0/electron`). Without Electron or Xvfb
//! the tests skip with a printed reason, or fail when `TRACEWISE_REQUIRE_ORACLE=1`.

mod electron_support;

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::time::Duration;

use electron_support::*;
use serde_json::{json, Value};
use tracewise_domain::canonical::canonical_sha256;
use tracewise_web::browser_observation::browser_error_body;
use tracewise_web::electron_active::{CleanupIncomplete, ElectronActiveConfig, ElectronCaptureError};
use tracewise_web::electron_scenario::{
    canonicalize_scenario, capture_electron_scenario_with, parse_capture_electron_scenario_input,
};


/// Timeline events whose presence and count follow from the fixture application's
/// own code, not from window manager, paint or process timing.
const STABLE_EVENTS: &[(&str, &str, &str)] = &[
    ("app-lifecycle", "will-finish-launching", "observed"),
    ("app-lifecycle", "ready", "observed"),
    ("app-lifecycle", "session-created", "observed"),
    ("app-lifecycle", "web-contents-created", "observed"),
    ("app-lifecycle", "browser-window-created", "observed"),
    ("window-lifecycle", "created", "completed"),
    ("preload", "configured", "completed"),
    ("navigation", "loadFile", "attempted"),
    ("navigation", "loadFile", "completed"),
    ("navigation", "loadURL", "attempted"),
    ("navigation", "loadURL", "completed"),
    ("shell-attempt", "openExternal", "blocked"),
    ("process-lifecycle", "utility-process-fork", "attempted"),
    ("process-lifecycle", "utility-process-fork", "completed"),
    ("process-lifecycle", "child.spawn", "attempted"),
    ("process-lifecycle", "child.spawn", "completed"),
    ("process-lifecycle", "child.spawn", "observed"),
    ("protocol", "open-url", "observed"),
    ("protocol", "second-instance", "observed"),
    ("main-handler-invocation", "", "observed"),
    ("ipc-main-to-renderer", "", "observed"),
];

// ------------------------------------------------------------------ helpers

/// The oracle's raw MCP result and the capture it kept in `partial_observation`.
fn oracle() -> (Value, Value) {
    let raw = read_json(&repo_root().join("fixtures/electron/oracle_capture_electron_scenario.json"));
    assert_eq!(raw["isError"], true, "the oracle ends in cleanup_incomplete on Linux");
    let body: Value = serde_json::from_str(raw["content"][0]["text"].as_str().unwrap()).unwrap();
    let capture = body["error"]["details"]["partial_observation"]["capture"].clone();
    (body, capture)
}

/// Replace the checkout and Electron paths by the golden's placeholders.
fn placeholders(mut value: Value, electron: &std::path::Path) -> Value {
    let text = serde_json::to_string(&value)
        .unwrap()
        .replace(readiness_app().to_str().unwrap(), "{APP}")
        .replace(electron.to_str().unwrap(), "{ELECTRON}");
    value = serde_json::from_str(&text).unwrap();
    value
}

fn event_text(event: &Value, key: &str) -> String {
    match &event[key] {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Every field of an event that does not embed a pid or a clock.
fn event_signature(event: &Value) -> String {
    let mut target = event_text(event, "target");
    if target.starts_with("child:pid:") {
        target = "child:pid:*".to_string();
    }
    // Which of the two identical windows is "window 0" is a race inside REA itself (the order
    // of Playwright's `windows()` is the order DevTools announced the pages; three oracle runs
    // gave both answers), so the window that sent the click is not compared.
    let from_click = event_text(event, "kind") == "main-handler-invocation";
    let hide = |value: String| if from_click { "*".to_string() } else { value };
    [
        event_text(event, "kind"),
        event_text(event, "event"),
        event_text(event, "phase"),
        event_text(event, "channel"),
        event_text(event, "direction"),
        hide(event_text(event, "sender")),
        event_text(event, "receiver"),
        hide(event_text(event, "frame")),
        target,
        event["argument_shapes"].to_string(),
        event_text(event, "result_shape"),
        event_text(event, "process_type"),
        event_text(event, "source"),
        event_text(event, "capture_method"),
        event_text(event, "error"),
    ]
    .join("|")
}

fn stable_timeline(capture: &Value) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for event in capture["timeline"]["events"].as_array().unwrap() {
        let key = (
            event_text(event, "kind"),
            event_text(event, "event"),
            event_text(event, "phase"),
        );
        if STABLE_EVENTS.iter().any(|(k, e, p)| (*k, *e, *p) == (&key.0[..], &key.1[..], &key.2[..])) {
            *counts.entry(event_signature(event)).or_insert(0) += 1;
        }
    }
    counts
}

fn without_keys(value: &Value, keys: &[&str]) -> Value {
    let mut copy = value.clone();
    if let Some(object) = copy.as_object_mut() {
        for key in keys {
            object.remove(*key);
        }
    }
    copy
}

fn process_multiset(capture: &Value) -> Vec<String> {
    let mut rows: Vec<String> = capture["processes"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| format!("{}|{}|{}", p["type"], p["name"], p["service_name"]))
        .collect();
    rows.sort();
    rows
}

// -------------------------------------------------------------------- tests

#[tokio::test]
async fn readiness_scenario_matches_the_rea_oracle() {
    let _serial = SERIAL.lock().await;
    let Some(setup) = Setup::new("parity") else { return };
    let scenario = setup.scenario(readiness_actions());
    let canonical = canonicalize_scenario(&scenario).unwrap();
    let evidence = capture_electron_scenario_with(&scenario, Some(&setup.config()), &setup.environment())
        .await
        .unwrap_or_else(|e| panic!("capture failed: {e:?}"));
    let structured = serde_json::to_value(&evidence).unwrap();
    validate_schema(&structured);
    setup.assert_clean();

    // Evidence envelope (REA createElectronActiveEvidence).
    assert_eq!(structured["provider"]["id"], "rea-playwright-electron-active");
    assert_eq!(structured["provider"]["name"], "REA Playwright active Electron observation provider");
    assert_eq!(structured["predicate_type"], "rea.electron-active-scenario");
    assert_eq!(structured["operation"], "capture_electron_scenario");
    assert_eq!(structured["confidence"], "observed");
    assert_eq!(structured["authority"], "controlled-replay");
    assert_eq!(structured["environment"]["id"], "44.7.0@unknown");
    assert_eq!(structured["environment"]["isolation"], "none");
    let hash = canonical_sha256(&Value::Object(canonical.clone())).unwrap();
    assert_eq!(structured["parameters"]["scenario_sha256"], hash);
    assert_eq!(structured["parameters"]["args"], json!(base_args()));
    let limitations = structured["limitations"].as_array().unwrap();
    assert_eq!(limitations.first().unwrap(), "Artifact identity is unavailable for this observation.");
    assert_eq!(limitations.last().unwrap(), "Application host platform and architecture were not observed.");

    // REA's own `verify:electron` criteria (scripts/verify-real-electron.mjs).
    let result = &structured["normalized_result"];
    let events = result["timeline"]["events"].as_array().unwrap();
    let has = |kind: &str, event: &str, phase: Option<&str>| {
        events.iter().any(|e| {
            e["kind"] == kind && e["event"] == event && phase.map(|p| e["phase"] == p).unwrap_or(true)
        })
    };
    assert_eq!(result["coverage"]["status"], "partial_attach");
    assert!(result["actions"].as_array().unwrap().iter().all(|a| a["status"] == "completed"));
    assert!(result["windows"].as_array().unwrap().len() >= 2);
    assert!(result["ipc"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["kind"] == "main-handler-invocation" && e["channel"] == "readiness:echo"));
    assert!(has("window-lifecycle", "created", Some("completed")));
    assert!(has("process-lifecycle", "utility-process-fork", None));
    assert!(has("shell-attempt", "openExternal", Some("blocked")));
    assert!(has("preload", "configured", Some("completed")));
    assert!(has("protocol", "open-url", None) && has("protocol", "second-instance", None));
    assert!(has("process-lifecycle", "child.spawn", None));

    // Parity with the REA capture.
    let (_, golden) = oracle();
    let rust = placeholders(result.clone(), &setup.electron);
    assert_eq!(
        without_keys(&rust["application"], &["cleanup"]),
        without_keys(&golden["application"], &["cleanup"])
    );
    assert_eq!(rust["application"]["cleanup"], "terminated-owned-process");
    assert_eq!(golden["application"]["cleanup"], "unverified");
    let strip_elapsed = |actions: &Value| -> Vec<Value> {
        actions.as_array().unwrap().iter().map(|a| without_keys(a, &["elapsed_ms"])).collect()
    };
    assert_eq!(strip_elapsed(&rust["actions"]), strip_elapsed(&golden["actions"]));
    assert_eq!(rust["windows"], golden["windows"]);
    assert_eq!(process_multiset(&rust), process_multiset(&golden));
    let ipc = |capture: &Value| -> Vec<String> {
        let mut rows: Vec<String> = capture["ipc"]["events"].as_array().unwrap().iter().map(event_signature).collect();
        rows.sort();
        rows
    };
    assert_eq!(ipc(&rust), ipc(&golden));
    assert_eq!(rust["ipc"]["observed"], golden["ipc"]["observed"]);
    assert_eq!(rust["ipc"]["dropped"], golden["ipc"]["dropped"]);
    assert_eq!(rust["coverage"], golden["coverage"]);
    assert_eq!(rust["limitations"], golden["limitations"]);
    for key in [
        "budget_bytes",
        "dropped",
        "dropped_event_families",
        "dropped_event_roles",
        "observed_ipc",
        "dropped_ipc",
        "dropped_runtime",
    ] {
        assert_eq!(rust["retention"][key], golden["retention"][key], "retention.{key}");
    }
    assert_eq!(rust["timeline"]["dropped"], golden["timeline"]["dropped"]);
    assert_eq!(stable_timeline(&rust), stable_timeline(&golden));
    assert!(!stable_timeline(&golden).is_empty());
}

#[tokio::test]
async fn cleanup_incomplete_body_matches_the_rea_error() {
    let (body, capture) = oracle();
    let details = &body["error"]["details"];
    let info = CleanupIncomplete {
        cleanup_reason: details["cleanup_reason"].as_str().unwrap().to_string(),
        resources: details["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap().to_string())
            .collect(),
        capture_failure: None,
        partial_observation: Some(json!({ "kind": "electron-active-observation", "capture": capture })),
    };
    assert_eq!(info.body(), body);
    // A failed capture adds REA's "Capture also failed" sentence and keeps no observation.
    let failed = CleanupIncomplete {
        cleanup_reason: "x".into(),
        resources: vec![],
        capture_failure: Some("boom".into()),
        partial_observation: None,
    };
    let message = failed.body()["error"]["message"].as_str().unwrap().to_string();
    assert_eq!(
        message,
        "Electron cleanup could not be verified: x. Capture also failed: boom. Inspect the reported process resources before launching another capture."
    );
    assert!(failed.body()["error"]["details"].get("partial_observation").is_none());
}

#[tokio::test]
async fn failed_actions_are_recorded_and_stop_the_scenario() {
    let _serial = SERIAL.lock().await;
    let Some(setup) = Setup::new("actions") else { return };
    // `button, output` is two elements: Playwright's locators are strict and fail the same way.
    let scenario = setup.scenario(json!([
        { "step_id": "ambiguous", "kind": "click", "selector": "button, output" },
        { "step_id": "never-runs", "kind": "wait", "duration_ms": 1 },
    ]));
    let evidence = capture_electron_scenario_with(&scenario, Some(&setup.config()), &setup.environment())
        .await
        .unwrap_or_else(|e| panic!("capture failed: {e:?}"));
    let structured = serde_json::to_value(&evidence).unwrap();
    validate_schema(&structured);
    let actions = structured["normalized_result"]["actions"].as_array().unwrap().clone();
    assert_eq!(actions.len(), 1, "the scenario stops at the first failure: {actions:?}");
    assert_eq!(actions[0]["status"], "failed");
    assert_eq!(actions[0]["target"], "window:0");
    assert!(
        actions[0]["error"].as_str().unwrap().contains("strict mode violation"),
        "{}",
        actions[0]["error"]
    );
    setup.assert_clean();

    // Playwright-only selector engines are reported, not silently reinterpreted.
    let scenario = setup.scenario(json!([{ "step_id": "text", "kind": "click", "selector": "text=Run" }]));
    let evidence = capture_electron_scenario_with(&scenario, Some(&setup.config()), &setup.environment())
        .await
        .unwrap_or_else(|e| panic!("capture failed: {e:?}"));
    let actions = serde_json::to_value(&evidence).unwrap()["normalized_result"]["actions"].clone();
    assert_eq!(actions[0]["status"], "failed");
    assert!(actions[0]["error"].as_str().unwrap().contains("only CSS selectors are supported"));
    setup.assert_clean();
}

#[tokio::test]
async fn a_click_waits_for_its_target_and_lands_once_it_appears() {
    let _serial = SERIAL.lock().await;
    let Some(setup) = Setup::new("late-click") else { return };
    // The element does not exist when the click starts: the renderer adds it later.
    let app = ScratchDir::new("late-app");
    std::fs::write(
        app.0.join("main.js"),
        r#"const { app, BrowserWindow, ipcMain } = require("electron");
app.whenReady().then(() => {
  const window = new BrowserWindow({ show: true, webPreferences: { contextIsolation: false, nodeIntegration: true } });
  window.loadURL("data:text/html," + encodeURIComponent(`<body><script>
    const { ipcRenderer } = require("electron");
    setTimeout(() => {
      const button = document.createElement("button");
      button.id = "late";
      button.textContent = "late";
      button.onclick = () => ipcRenderer.invoke("late:clicked", "ok");
      document.body.append(button);
    }, 700);
  </script></body>`));
  ipcMain.handle("late:clicked", () => "done");
});
"#,
    )
    .unwrap();
    let scenario = parse_capture_electron_scenario_input(&json!({
        "executable_path": setup.electron,
        "application_path": app.0.join("main.js"),
        "args": base_args(),
        "actions": [{ "step_id": "late", "kind": "click", "selector": "#late" }],
    }))
    .unwrap();
    let evidence = capture_electron_scenario_with(&scenario, Some(&setup.config()), &setup.environment())
        .await
        .unwrap_or_else(|e| panic!("capture failed: {e:?}"));
    let result = serde_json::to_value(&evidence).unwrap()["normalized_result"].clone();
    assert_eq!(result["actions"][0]["status"], "completed", "{}", result["actions"][0]);
    assert!(
        result["ipc"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["channel"] == "late:clicked"),
        "the click reached the application: {}",
        result["ipc"]
    );
    setup.assert_clean();
}

#[tokio::test]
async fn an_executable_that_is_not_configured_is_refused_without_launching() {
    let Some(electron) = electron_executable() else { return };
    let scratch = ScratchDir::new("refuse");
    // The configured Electron is `/bin/true`; the request names the real one.
    let config = ElectronActiveConfig::from_values("/bin/true", scratch.0.to_str()).unwrap();
    let app = readiness_app();
    let scenario = parse_capture_electron_scenario_input(&json!({
        "executable_path": electron,
        "application_path": app.join("main.js"),
    }))
    .unwrap();
    let error = capture_electron_scenario_with(&scenario, Some(&config), &HashMap::new())
        .await
        .expect_err("refused");
    let ElectronCaptureError::Web(tracewise_web::error::WebError::CapabilityUnavailable { capability, reason, .. }) = error
    else {
        panic!("expected capability_unavailable, got {error:?}");
    };
    assert_eq!(capability, "rea-playwright-electron-active");
    assert!(reason.contains("not an Electron executable configured for active observation"), "{reason}");
    assert!(run_directories(&scratch.0).is_empty(), "no directory is created for a refused request");

    // Without any configuration it is exactly REA's provider-not-configured error.
    let error = capture_electron_scenario_with(&scenario, None, &HashMap::new()).await.expect_err("unconfigured");
    let ElectronCaptureError::Web(tracewise_web::error::WebError::CapabilityUnavailable { reason, .. }) = error else {
        panic!("expected capability_unavailable");
    };
    assert_eq!(reason, "active Electron observation provider is not configured");

    // Configuration parsing: `:`-separated list, unresolvable entries dropped, none left = unconfigured.
    assert!(ElectronActiveConfig::from_values("", None).is_none());
    assert!(ElectronActiveConfig::from_values("/nonexistent/electron", None).is_none());
    let both = ElectronActiveConfig::from_values(&format!("/nonexistent/x:{}:/bin/true", electron.display()), None).unwrap();
    assert_eq!(both.executables.len(), 2);
}

/// A shell script standing in for Electron: records how it was launched, then exits.
fn recording_launcher(dir: &std::path::Path, log: &std::path::Path) -> PathBuf {
    let path = dir.join("fake-electron.sh");
    std::fs::write(
        &path,
        format!(
            r#"#!/bin/sh
{{
  echo "PWD=$(pwd)"
  hook=""
  next=0
  for a in "$@"; do
    echo "ARG=$a"
    if [ "$next" = 1 ]; then hook="$a"; next=0; fi
    if [ "$a" = "-r" ]; then next=1; fi
  done
  env | sort | sed 's/^/ENV=/'
  if [ -n "$hook" ]; then echo "HOOK_EXISTS=$(test -f "$hook" && echo yes)"; cp "$hook" "{log}.hook"; cp "$(dirname "$hook")/electron-active-hook-boundaries.cjs" "{log}.boundaries"; fi
  echo "OWNER=$(cat "$(dirname "$(dirname "$hook")")/owner")"
}} > "{log}"
exit 3
"#,
            log = log.display()
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[tokio::test]
async fn launch_is_the_rea_command_line_with_a_restricted_environment() {
    let scratch = ScratchDir::new("launch");
    let log = scratch.0.join("launch.log");
    let launcher = recording_launcher(&scratch.0, &log);
    let app_dir = scratch.0.join("app");
    std::fs::create_dir(&app_dir).unwrap();
    std::fs::write(app_dir.join("main.js"), "module.exports = {};\n").unwrap();
    let root = scratch.0.join("root");
    std::fs::create_dir(&root).unwrap();
    let runtime = scratch.0.join("runtime");
    std::fs::create_dir(&runtime).unwrap();
    let config = ElectronActiveConfig::from_values(launcher.to_str().unwrap(), runtime.to_str()).unwrap();
    let scenario = parse_capture_electron_scenario_input(&json!({
        "executable_path": launcher,
        "application_path": app_dir.join("main.js"),
        "application_root": root,
        "args": ["--token", "super-secret", "--flag=a b"],
    }))
    .unwrap();
    let mut environment: HashMap<String, String> = HashMap::new();
    for (name, value) in [
        ("HOME", "/srv/selected-home"),
        ("LANG", "selected-language"),
        ("PATH", "/usr/bin:/bin"),
        ("USER", "someone"),
        ("DISPLAY", ":42"),
        ("WAYLAND_DISPLAY", "wayland-9"),
        ("TMPDIR", "/ambient/tmp"),
        ("AWS_SECRET_ACCESS_KEY", "must-not-leak"),
        ("REA_PRIVATE_VALUE", "not-a-launch-setting"),
    ] {
        environment.insert(name.to_string(), value.to_string());
    }
    let error = capture_electron_scenario_with(&scenario, Some(&config), &environment)
        .await
        .expect_err("the fake launcher exits");
    // The launcher exited (status 3) before publishing endpoints: REA's launch failure, with no leftovers.
    let ElectronCaptureError::Web(error) = error else { panic!("unexpected {error:?}") };
    let body = browser_error_body(&error).expect("browser body");
    assert_eq!(body["error"]["code"], "provider_unavailable");
    assert!(body["error"]["message"].as_str().unwrap().contains("Electron exited during startup"), "{body}");
    assert!(run_directories(&runtime).is_empty(), "{:?}", run_directories(&runtime));

    let text = std::fs::read_to_string(&log).expect("launcher log");
    let args: Vec<&str> = text.lines().filter_map(|l| l.strip_prefix("ARG=")).collect();
    let root_real = std::fs::canonicalize(&root).unwrap();
    let app_real = std::fs::canonicalize(app_dir.join("main.js")).unwrap();
    assert_eq!(args[0], "--inspect=0");
    assert_eq!(args[1], "--remote-debugging-port=0");
    assert!(args[2].starts_with("--user-data-dir="), "{args:?}");
    assert!(args[2].contains("tracewise-electron-"), "profile lives in the private run directory: {args:?}");
    assert_eq!(args[3], "-r");
    assert!(args[4].ends_with("/hook/electron-active-hook.cjs"), "{args:?}");
    assert_eq!(&args[5..], [app_real.to_str().unwrap(), "--token", "super-secret", "--flag=a b"]);
    assert!(text.contains(&format!("PWD={}", root_real.display())), "{text}");
    assert!(text.contains("HOOK_EXISTS=yes"));

    // Environment: REA's allow-list plus the run token; TMPDIR/TMP point into the private directory.
    let env: BTreeMap<&str, &str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("ENV="))
        .filter_map(|l| l.split_once('='))
        .collect();
    for (name, value) in [
        ("HOME", "/srv/selected-home"),
        ("LANG", "selected-language"),
        ("PATH", "/usr/bin:/bin"),
        ("USER", "someone"),
        ("DISPLAY", ":42"),
        ("WAYLAND_DISPLAY", "wayland-9"),
    ] {
        assert_eq!(env.get(name), Some(&value), "{name}");
    }
    assert!(!env.contains_key("AWS_SECRET_ACCESS_KEY") && !env.contains_key("REA_PRIVATE_VALUE"), "{env:?}");
    assert!(env["TMPDIR"].contains("tracewise-electron-") && env["TMPDIR"].ends_with("/tmp"));
    assert_eq!(env["TMP"], env["TMPDIR"]);
    assert_eq!(env["REA_PROCESS_RUN_ID"].len(), 36);
    let allowed = [
        "HOME", "LANG", "PATH", "USER", "DISPLAY", "WAYLAND_DISPLAY", "TMPDIR", "TMP", "REA_PROCESS_RUN_ID", "PWD", "SHLVL", "_", "OLDPWD",
    ];
    let extra: Vec<&&str> = env.keys().filter(|k| !allowed.contains(*k)).collect();
    assert!(extra.is_empty(), "unexpected environment names: {extra:?}");

    // The owner record lets a later run recognise an abandoned directory.
    let owner = text.lines().find_map(|l| l.strip_prefix("OWNER=")).unwrap();
    assert!(owner.starts_with(&std::process::id().to_string()), "{owner}");

    // The hook is REA's, unchanged apart from the attribution header.
    let rea = PathBuf::from("/workspace/rea-map/src/scripts");
    for (copy, original) in [("hook", "electron-active-hook.cjs"), ("boundaries", "electron-active-hook-boundaries.cjs")] {
        let shipped = std::fs::read_to_string(format!("{}.{copy}", log.display())).unwrap();
        assert!(shipped.starts_with("// Derived from morluto/rea (MIT), Copyright (c) 2026 morluto"));
        let body: String = shipped.lines().skip(3).collect::<Vec<_>>().join("\n");
        match std::fs::read_to_string(rea.join(original)) {
            Ok(source) => assert_eq!(body.trim_end(), source.trim_end(), "{original} differs from REA"),
            Err(_) => skip_or_fail(&format!("REA checkout not found, cannot diff {original}")),
        }
    }
}

#[tokio::test]
async fn startup_failures_and_timeouts_leave_nothing_behind() {
    let scratch = ScratchDir::new("startup");
    let runtime = scratch.0.join("runtime");
    std::fs::create_dir(&runtime).unwrap();
    let app = scratch.0.join("main.js");
    std::fs::write(&app, "module.exports = {};\n").unwrap();

    // A launcher that never prints the endpoints: the startup deadline fires and the group is killed.
    let silent = scratch.0.join("silent.sh");
    std::fs::write(&silent, "#!/bin/sh\nsleep 60 &\nsleep 60\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&silent, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut config = ElectronActiveConfig::from_values(silent.to_str().unwrap(), runtime.to_str()).unwrap();
    config.startup_timeout = Duration::from_millis(800);
    let scenario = parse_capture_electron_scenario_input(&json!({
        "executable_path": silent,
        "application_path": app,
    }))
    .unwrap();
    let started = std::time::Instant::now();
    let error = capture_electron_scenario_with(&scenario, Some(&config), &HashMap::new())
        .await
        .expect_err("timeout");
    assert!(started.elapsed() < Duration::from_secs(15), "{:?}", started.elapsed());
    let ElectronCaptureError::Web(error) = error else { panic!("unexpected {error:?}") };
    let body = browser_error_body(&error).unwrap();
    assert_eq!(body["error"]["code"], "provider_timeout", "{body}");
    assert!(body["error"]["message"].as_str().unwrap().contains("did not publish its debugging endpoints"));
    assert!(run_directories(&runtime).is_empty());
    assert!(
        wait_until(Duration::from_secs(5), || processes_with_cmdline("silent.sh").is_empty()
            && processes_with_cmdline("sleep 60").iter().all(|pid| !is_child_of_test_runtime(*pid))),
        "the launcher and its children are gone"
    );
}

/// `sleep 60` started by another test binary or the user is not ours; only report those whose
/// environment carries a run token.
fn is_child_of_test_runtime(pid: i32) -> bool {
    std::fs::read(format!("/proc/{pid}/environ"))
        .map(|bytes| String::from_utf8_lossy(&bytes).contains("REA_PROCESS_RUN_ID="))
        .unwrap_or(false)
}

#[tokio::test]
async fn abandoned_run_directories_are_swept_by_the_next_run() {
    let scratch = ScratchDir::new("sweep");
    let runtime = scratch.0.join("runtime");
    std::fs::create_dir(&runtime).unwrap();
    // A run directory whose owner died, with a process that still carries the directory in its command line.
    let stale = runtime.join("tracewise-electron-00000000-0000-4000-8000-000000000000");
    std::fs::create_dir_all(stale.join("profile")).unwrap();
    let mut dead = std::process::Command::new("true").spawn().unwrap();
    let dead_pid = dead.id();
    dead.wait().unwrap();
    std::fs::write(stale.join("owner"), format!("{dead_pid} 1\n")).unwrap();
    let mut straggler = std::process::Command::new("sh")
        .args(["-c", "sleep 30 & wait", stale.join("profile").to_str().unwrap()])
        .spawn()
        .unwrap();
    // A live owner's directory must survive.
    let live = runtime.join("tracewise-electron-11111111-1111-4111-8111-111111111111");
    std::fs::create_dir_all(&live).unwrap();
    let me = std::process::id();
    let start = std::fs::read_to_string(format!("/proc/{me}/stat"))
        .unwrap()
        .rsplit(')')
        .next()
        .unwrap()
        .split_whitespace()
        .nth(19)
        .unwrap()
        .to_string();
    std::fs::write(live.join("owner"), format!("{me} {start}\n")).unwrap();
    // Not ours at all: no owner record, different prefix.
    std::fs::create_dir(runtime.join("tracewise-electron-no-record")).unwrap();
    std::fs::create_dir(runtime.join("unrelated")).unwrap();

    let removed = tracewise_web::electron_active::process::sweep_stale_runs(&runtime);
    assert_eq!(removed, 1);
    assert!(!stale.exists(), "abandoned directory removed");
    assert!(live.exists() && runtime.join("tracewise-electron-no-record").exists() && runtime.join("unrelated").exists());
    assert!(
        wait_until(Duration::from_secs(5), || straggler.try_wait().map(|s| s.is_some()).unwrap_or(false)),
        "the process that carried the abandoned directory was killed"
    );
    let _ = straggler.kill();
}
