//! Controlled browser scenario driver (port of REA browser/PlaywrightBrowserScenarioProvider.ts,
//! PlaywrightScenarioSession.ts and domain/browserScenarioCapture.ts).
//!
//! Launch mode owns a Chrome process through `proc-supervisor`. Secret values stay
//! in memory for the action that needs them and are redacted from every retained artifact.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use base64::Engine;
use proc_supervisor::{ProcessSupervisor, SupervisedChild};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracewise_domain::evidence::Evidence;
use url::Url;

use crate::browser_observation::{browser_error, BrowserFailureReason, CHROME_WEBMCP_LAUNCH_ARGS};
use crate::browser_scenario::{
    create_scenario_evidence, BrowserScenario, ScenarioAction, ScenarioCapture, ScenarioMode,
};
use crate::browser_scenario_actions::{evaluate, locator_state, navigate, perform_page_action};
use crate::browser_scenario_secrets::ScenarioSecrets;
use crate::cdp_connection::{close_cdp_target_session, open_cdp_target_session, CdpTargetSession};
use crate::cdp_documents::main_frame_url;
use crate::cdp_endpoint::discover_cdp_endpoint;
use crate::error::WebError;
use crate::web_screenshot::web_screenshot_artifact;

const OPERATION: &str = "capture_browser_scenario";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const SNAPSHOTS: [&str; 6] = ["screenshot", "dom", "accessibility", "url", "history", "storage"];

struct OwnedChrome {
    child: SupervisedChild,
    user_data_dir: PathBuf,
}

impl Drop for OwnedChrome {
    fn drop(&mut self) {
        let _ = self.child.kill_group();
        kill_chrome_using(&self.user_data_dir);
        let _ = std::fs::remove_dir_all(&self.user_data_dir);
    }
}

pub async fn capture_browser_scenario(scenario: &BrowserScenario) -> Result<Evidence, WebError> {
    let started = Instant::now();
    let secrets = ScenarioSecrets::resolve(
        &scenario
            .secrets
            .iter()
            .map(|secret| (secret.secret_id.clone(), secret.environment_variable.clone()))
            .collect::<Vec<_>>(),
    )?;
    let (session, owned, product_version) = open_session(scenario).await?;
    let mut session = session;
    let owned_process = owned.is_some();
    let outcome = run_steps(scenario, &mut session, &secrets, started, &product_version.1).await;
    close_cdp_target_session(session, &["Network", "Runtime", "Page"]).await;
    drop(owned);
    let capture = outcome?;
    create_scenario_evidence(scenario, capture, &product_version.0, &product_version.1, owned_process)
}

async fn open_session(
    scenario: &BrowserScenario,
) -> Result<(CdpTargetSession, Option<OwnedChrome>, (String, String)), WebError> {
    match &scenario.mode {
        ScenarioMode::Launch { executable_path, headless } => {
            let owned = launch_chrome(executable_path, *headless, &scenario.environment).await?;
            let discovery = discover_cdp_endpoint(&owned.0, OPERATION).await?;
            let target = discovery
                .targets
                .iter()
                .find(|target| target.target_type == "page")
                .ok_or_else(|| browser_error(OPERATION, BrowserFailureReason::TargetNotFound, None))?;
            let session = open_cdp_target_session(&discovery, target, OPERATION).await?;
            let version = version_from_product(&discovery.version.product);
            Ok((session, Some(owned.1), ("Chromium".to_string(), version)))
        }
        ScenarioMode::Connect { cdp_endpoint, target_id } => {
            let discovery = discover_cdp_endpoint(cdp_endpoint, OPERATION).await?;
            let target = discovery.targets.iter().find(|target| target.id == *target_id).ok_or_else(|| {
                browser_error(
                    OPERATION,
                    BrowserFailureReason::TargetNotFound,
                    Some(format!("Target {target_id} was not found at the selected endpoint.")),
                )
            })?;
            let session = open_cdp_target_session(&discovery, target, OPERATION).await?;
            let version = version_from_product(&discovery.version.product);
            Ok((session, None, ("Chromium".to_string(), version)))
        }
    }
}

async fn launch_chrome(
    executable: &str,
    headless: bool,
    environment: &crate::browser_scenario::ScenarioEnvironment,
) -> Result<(String, OwnedChrome), WebError> {
    if !Path::new(executable).is_file() {
        return Err(browser_error(
            OPERATION,
            BrowserFailureReason::EndpointUnreachable,
            Some(format!("Browser executable was not found at {executable}.")),
        ));
    }
    let port = free_port()?;
    let user_data_dir = std::env::temp_dir().join(format!("tracewise-scenario-{port}-{}", std::process::id()));
    std::fs::create_dir_all(&user_data_dir)?;
    let dir = user_data_dir.display().to_string();
    let mut supervisor = ProcessSupervisor::new(executable);
    supervisor.null_stdio();
    supervisor.env("TZ", &environment.timezone);
    if headless {
        supervisor.arg("--headless=new");
    }
    for arg in [
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
    if environment.service_workers == "block" {
        supervisor.arg("--disable-features=ServiceWorker");
    }
    for arg in CHROME_WEBMCP_LAUNCH_ARGS {
        supervisor.arg(*arg);
    }
    supervisor.arg(format!("--lang={}", environment.locale));
    supervisor.arg(format!("--window-size={},{}", environment.width, environment.height));
    supervisor.arg(format!("--user-data-dir={dir}"));
    supervisor.arg(format!("--remote-debugging-port={port}"));
    supervisor.arg("about:blank");
    let child = supervisor.spawn().map_err(|error| {
        browser_error(
            OPERATION,
            BrowserFailureReason::EndpointUnreachable,
            Some(format!("Browser process did not start: {error}")),
        )
    })?;
    let endpoint = format!("http://127.0.0.1:{port}");
    let owned = OwnedChrome { child, user_data_dir };
    if let Err(error) = wait_for_endpoint(&endpoint).await {
        drop(owned);
        return Err(error);
    }
    Ok((endpoint, owned))
}

async fn wait_for_endpoint(endpoint: &str) -> Result<(), WebError> {
    let mut last = String::from("not attempted");
    for _ in 0..50 {
        match discover_cdp_endpoint(endpoint, OPERATION).await {
            Ok(_) => return Ok(()),
            Err(error) => {
                last = error.to_string();
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
    Err(browser_error(
        OPERATION,
        BrowserFailureReason::Timeout,
        Some(format!("Browser debugging endpoint was not published: {last}")),
    ))
}

async fn run_steps(
    scenario: &BrowserScenario,
    session: &mut CdpTargetSession,
    secrets: &ScenarioSecrets,
    started: Instant,
    version: &str,
) -> Result<Value, WebError> {
    let sid = session.session_id.clone();
    session.connection.send("Page.enable", json!({}), sid.as_deref()).await?;
    session.connection.send("Runtime.enable", json!({}), sid.as_deref()).await?;
    let _ = session
        .connection
        .send(
            "Emulation.setDeviceMetricsOverride",
            json!({
                "width": scenario.environment.width,
                "height": scenario.environment.height,
                "deviceScaleFactor": scenario.environment.device_scale_factor,
                "mobile": false,
            }),
            sid.as_deref(),
        )
        .await;
    install_storage(session, scenario, secrets).await?;
    let before_start = current_url(session).await?;
    navigate(session, &secrets.url(&scenario.start), "load", DEFAULT_TIMEOUT)
        .await
        .map_err(|error| action_error(secrets, &error))?;
    let mut steps = Vec::new();
    steps.push(
        make_step(
            session,
            secrets,
            scenario,
            0,
            "scenario_start",
            "goto_start",
            "completed",
            None,
            started.elapsed(),
            &before_start,
            1,
            0,
        )
        .await?,
    );
    let mut failed = false;
    for (offset, action) in scenario.actions.iter().enumerate() {
        let step_index = offset + 1;
        let before = current_url(session).await?;
        let action_started = Instant::now();
        let (status, error) = if failed {
            ("cancelled", Some("not executed after an earlier action failure".to_string()))
        } else {
            match perform(session, action, secrets).await {
                Ok(()) => ("completed", None),
                Err(error) => {
                    failed = true;
                    ("failed", Some(secrets.redact(&error)))
                }
            }
        };
        steps.push(
            make_step(
                session,
                secrets,
                scenario,
                step_index,
                action.step_id(),
                action.name(),
                status,
                error,
                action_started.elapsed(),
                &before,
                1,
                0,
            )
            .await?,
        );
    }
    Ok(capture_document(scenario, &steps, started.elapsed(), owned_mode(scenario), version))
}

fn owned_mode(scenario: &BrowserScenario) -> (&'static str, &'static str, &'static str) {
    match scenario.mode {
        ScenarioMode::Launch { .. } => ("launch", "provider-owned", "terminated-owned-process"),
        ScenarioMode::Connect { .. } => ("connect", "external", "disconnected-external"),
    }
}

async fn perform(session: &mut CdpTargetSession, action: &ScenarioAction, secrets: &ScenarioSecrets) -> Result<(), String> {
    let timeout = action.timeout_ms().map(|ms| Duration::from_millis(ms as u64)).unwrap_or(DEFAULT_TIMEOUT);
    match action {
        ScenarioAction::Goto { destination, wait_until, .. } => {
            navigate(session, &secrets.url(destination), wait_until, timeout).await
        }
        ScenarioAction::WaitTimeout { duration_ms, .. } => {
            session
                .connection
                .collect_for(Duration::from_millis(*duration_ms as u64))
                .await
                .map_err(|error| error.to_string())
        }
        ScenarioAction::WaitFor { locator, state, .. } => {
            let deadline = tokio::time::Instant::now() + timeout;
            loop {
                let observed = locator_state(session, locator).await?;
                let count = observed.get("count").and_then(Value::as_u64).unwrap_or(0);
                let attached = observed.get("attached").and_then(Value::as_bool).unwrap_or(false);
                let visible = observed.get("visible").and_then(Value::as_bool).unwrap_or(false);
                let ready = match state.as_str() {
                    "attached" => count == 1 && attached,
                    "detached" => count == 0,
                    "visible" => count == 1 && visible,
                    "hidden" => count == 0 || (count == 1 && !visible),
                    _ => false,
                };
                if ready {
                    return Ok(());
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(format!("timed out waiting for locator to be {state}"));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        other => {
            tokio::time::timeout(timeout, perform_page_action(session, other, secrets))
                .await
                .map_err(|_| "action timed out".to_string())?
        }
    }
}

async fn make_step(
    session: &mut CdpTargetSession,
    secrets: &ScenarioSecrets,
    scenario: &BrowserScenario,
    step_index: usize,
    step_id: &str,
    action: &str,
    status: &str,
    error: Option<String>,
    elapsed: Duration,
    before_url: &str,
    event_start: i64,
    event_end: i64,
) -> Result<Value, WebError> {
    let after_url = current_url(session).await?;
    let requested = requested_snapshots(&scenario.capture, step_index, scenario.actions.len());
    let artifacts = if status == "cancelled" {
        unavailable_artifacts(&requested, "scenario request cancelled")
    } else {
        capture_artifacts(session, secrets, &requested).await
    };
    let completeness = step_completeness(&artifacts, status);
    let error_value = match (&status, error) {
        (&"completed", _) => Value::Null,
        (_, Some(error)) => Value::String(error),
        (_, None) => Value::String("browser action failed".to_string()),
    };
    Ok(json!({
        "step_index": step_index,
        "step_id": step_id,
        "action": action,
        "elapsed_ms": elapsed.as_millis() as u64,
        "before_url": secrets.sanitize_url(before_url).to_json(),
        "after_url": secrets.sanitize_url(&after_url).to_json(),
        "event_sequence_start": event_start,
        "event_sequence_end": event_end,
        "artifacts": artifacts,
        "completeness": completeness,
        "status": status,
        "error": error_value,
    }))
}

fn requested_snapshots(capture: &ScenarioCapture, step_index: usize, action_count: usize) -> BTreeSet<String> {
    let mut requested: BTreeSet<String> = capture.after_each_step.iter().cloned().collect();
    if step_index == action_count {
        requested.extend(capture.at_end.iter().cloned());
    }
    requested
}

fn unavailable_artifacts(requested: &BTreeSet<String>, reason: &str) -> Value {
    let mut artifacts = serde_json::Map::new();
    for kind in SNAPSHOTS {
        artifacts.insert(
            kind.to_string(),
            if requested.contains(kind) {
                json!({ "state": "missing", "reason": reason })
            } else {
                json!({ "state": "not_requested" })
            },
        );
    }
    Value::Object(artifacts)
}

async fn capture_artifacts(session: &mut CdpTargetSession, secrets: &ScenarioSecrets, requested: &BTreeSet<String>) -> Value {
    let mut artifacts = serde_json::Map::new();
    for kind in SNAPSHOTS {
        let value = if !requested.contains(kind) {
            json!({ "state": "not_requested" })
        } else {
            match capture_kind(session, secrets, kind).await {
                Ok(value) => json!({ "state": "captured", "value": value }),
                Err(reason) => json!({ "state": "missing", "reason": secrets.redact(&reason) }),
            }
        };
        artifacts.insert(kind.to_string(), value);
    }
    Value::Object(artifacts)
}

async fn capture_kind(session: &mut CdpTargetSession, secrets: &ScenarioSecrets, kind: &str) -> Result<Value, String> {
    match kind {
        "url" => {
            let url = current_url(session).await.map_err(|error| error.to_string())?;
            Ok(secrets.sanitize_url(&url).to_json())
        }
        "dom" => {
            let html = evaluate(session, "document.documentElement ? document.documentElement.outerHTML : \"\"")
                .await?
                .as_str()
                .unwrap_or("")
                .to_string();
            Ok(text_artifact(&secrets.redact(&html)))
        }
        "screenshot" => {
            let sid = session.session_id.clone();
            let shot = session
                .connection
                .send("Page.captureScreenshot", json!({ "format": "png" }), sid.as_deref())
                .await
                .map_err(|error| error.to_string())?;
            let encoded = shot.get("data").and_then(Value::as_str).ok_or("screenshot was not returned")?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| "screenshot was not valid base64".to_string())?;
            Ok(web_screenshot_artifact(&secrets.redact_bytes(&bytes)))
        }
        "accessibility" => {
            let sid = session.session_id.clone();
            let tree = session
                .connection
                .send("Accessibility.getFullAXTree", json!({}), sid.as_deref())
                .await
                .map_err(|error| error.to_string())?;
            Ok(text_artifact(&secrets.redact(&serde_json::to_string(&tree).unwrap_or_default())))
        }
        "history" => capture_history(session, secrets).await,
        "storage" => capture_storage(session, secrets).await,
        _ => Err("snapshot was not requested".to_string()),
    }
}

async fn capture_history(session: &mut CdpTargetSession, secrets: &ScenarioSecrets) -> Result<Value, String> {
    let sid = session.session_id.clone();
    let history = session
        .connection
        .send("Page.getNavigationHistory", json!({}), sid.as_deref())
        .await
        .map_err(|error| error.to_string())?;
    let entries = history.get("entries").and_then(Value::as_array).cloned().unwrap_or_default();
    let current = current_url(session).await.map_err(|error| error.to_string())?;
    Ok(json!({
        "length": entries.len(),
        "current_url": secrets.sanitize_url(&current).to_json(),
        "navigation_entries": entries.iter().map(|entry| {
            let url = entry.get("url").and_then(Value::as_str).unwrap_or("");
            let transition = entry.get("transitionType").and_then(Value::as_str).unwrap_or("");
            json!({
                "type": history_type(transition),
                "name": secrets.sanitize_url(url).to_json(),
            })
        }).collect::<Vec<_>>(),
    }))
}

fn history_type(transition: &str) -> &'static str {
    match transition {
        "reload" => "reload",
        "forward_back" | "back_forward" => "back_forward",
        "prerender" => "prerender",
        "" => "unknown",
        _ => "navigate",
    }
}

async fn capture_storage(session: &mut CdpTargetSession, secrets: &ScenarioSecrets) -> Result<Value, String> {
    let sid = session.session_id.clone();
    let _ = session.connection.send("Network.enable", json!({}), sid.as_deref()).await;
    let cookies = session
        .connection
        .send("Network.getCookies", json!({}), sid.as_deref())
        .await
        .map_err(|error| error.to_string())?;
    let cookie_items = cookies
        .get("cookies")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let local_items = storage_entries(session, "localStorage").await?;
    let session_items = storage_entries(session, "sessionStorage").await?;
    Ok(json!({
        "cookies": cookie_items.iter().map(|cookie| cookie_fingerprint(cookie, secrets)).collect::<Vec<_>>(),
        "local_storage": local_items.iter().map(|entry| entry_fingerprint(entry, secrets)).collect::<Vec<_>>(),
        "session_storage": session_items.iter().map(|entry| entry_fingerprint(entry, secrets)).collect::<Vec<_>>(),
    }))
}

fn cookie_fingerprint(cookie: &Value, secrets: &ScenarioSecrets) -> Value {
    let value = cookie.get("value").and_then(Value::as_str).unwrap_or("");
    let mut fingerprint = secrets.fingerprint(value);
    let same_site = cookie.get("sameSite").and_then(Value::as_str).unwrap_or("Lax");
    let same_site = if matches!(same_site, "Strict" | "Lax" | "None") { same_site } else { "Lax" };
    if let Some(object) = fingerprint.as_object_mut() {
        object.insert("name".to_string(), json!(cookie.get("name").and_then(Value::as_str).unwrap_or("")));
        object.insert("domain".to_string(), json!(cookie.get("domain").and_then(Value::as_str).unwrap_or("")));
        object.insert("path".to_string(), json!(cookie.get("path").and_then(Value::as_str).unwrap_or("/")));
        object.insert("secure".to_string(), json!(cookie.get("secure").and_then(Value::as_bool).unwrap_or(false)));
        object.insert("http_only".to_string(), json!(cookie.get("httpOnly").and_then(Value::as_bool).unwrap_or(false)));
        object.insert("same_site".to_string(), json!(same_site));
    }
    fingerprint
}

fn entry_fingerprint(entry: &Value, secrets: &ScenarioSecrets) -> Value {
    let value = entry.get("value").and_then(Value::as_str).unwrap_or("");
    let mut fingerprint = secrets.fingerprint(value);
    if let Some(object) = fingerprint.as_object_mut() {
        object.insert("name".to_string(), json!(entry.get("name").and_then(Value::as_str).unwrap_or("")));
    }
    fingerprint
}

async fn storage_entries(session: &mut CdpTargetSession, store: &str) -> Result<Vec<Value>, String> {
    let expression = format!(
        "(function(){{ var store = {store}; var items = []; for (var i = 0; i < store.length; i += 1) {{ var name = store.key(i); items.push({{ name: name, value: store.getItem(name) }}); }} return items; }})()"
    );
    match evaluate(session, &expression).await? {
        Value::Array(items) => Ok(items),
        _ => Ok(Vec::new()),
    }
}

async fn install_storage(session: &mut CdpTargetSession, scenario: &BrowserScenario, secrets: &ScenarioSecrets) -> Result<(), WebError> {
    let sid = session.session_id.clone();
    if !scenario.storage.cookies.is_empty() {
        let _ = session.connection.send("Network.enable", json!({}), sid.as_deref()).await;
    }
    for cookie in &scenario.storage.cookies {
        let value = secrets.resolve_value(&cookie.value);
        let url = secrets.url(&cookie.destination);
        session
            .connection
            .send(
                "Network.setCookie",
                json!({
                    "name": cookie.name,
                    "value": value,
                    "url": url,
                    "httpOnly": cookie.http_only,
                    "secure": cookie.secure,
                    "sameSite": cookie.same_site,
                }),
                sid.as_deref(),
            )
            .await
            .map_err(|error| action_error(secrets, &error.to_string()))?;
    }
    for (kind, origins) in [("local", &scenario.storage.local_storage), ("session", &scenario.storage.session_storage)] {
        for origin in origins {
            let entries: Vec<Value> = origin
                .entries
                .iter()
                .map(|(name, value)| json!({ "name": name, "value": secrets.resolve_value(value) }))
                .collect();
            let plan = json!({ "kind": kind, "origin": origin.origin, "entries": entries });
            let source = format!(
                "(function(plan){{ if (location.origin !== plan.origin) return; var store = plan.kind === \"local\" ? localStorage : sessionStorage; plan.entries.forEach(function(entry){{ store.setItem(entry.name, entry.value); }}); }})({plan})"
            );
            session
                .connection
                .send("Page.addScriptToEvaluateOnNewDocument", json!({ "source": source }), sid.as_deref())
                .await
                .map_err(|error| action_error(secrets, &error.to_string()))?;
        }
    }
    Ok(())
}

async fn current_url(session: &mut CdpTargetSession) -> Result<String, WebError> {
    let sid = session.session_id.clone();
    if let Ok(tree) = session.connection.send("Page.getFrameTree", json!({}), sid.as_deref()).await {
        if let Some(url) = main_frame_url(&tree) {
            return Ok(url);
        }
    }
    evaluate(session, "location.href")
        .await
        .map(|value| value.as_str().unwrap_or("about:blank").to_string())
        .map_err(|error| browser_error(OPERATION, BrowserFailureReason::ProtocolError, Some(error)))
}

fn capture_document(
    scenario: &BrowserScenario,
    steps: &[Value],
    elapsed: Duration,
    browser: (&str, &str, &str),
    version: &str,
) -> Value {
    let (mode, ownership, cleanup) = browser;
    let gaps = event_gaps(&scenario.capture);
    let mut missing = steps
        .iter()
        .flat_map(|step| {
            step.get("completeness")
                .and_then(|item| item.get("missing_sections"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|item| item.as_str().map(str::to_string))
        })
        .collect::<Vec<_>>();
    let mut truncated = steps
        .iter()
        .flat_map(|step| {
            step.get("completeness")
                .and_then(|item| item.get("truncated_sections"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|item| item.as_str().map(str::to_string))
        })
        .collect::<Vec<_>>();
    if mode == "connect" || !gaps.is_empty() {
        missing.push("events".to_string());
    }
    missing.sort();
    missing.dedup();
    truncated.sort();
    truncated.dedup();
    let start_origin = Url::parse(&scenario.start.url)
        .ok()
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|| scenario.start.url.clone());
    let mut secret_references: Vec<String> = scenario.secrets.iter().map(|secret| secret.secret_id.clone()).collect();
    secret_references.sort();
    let mut limitations = vec![
        "Event sequence records provider receipt order; simultaneous browser causality is not inferred.".to_string(),
        "Network content is retained only when selected; response bytes are browser-decoded, not compressed wire bytes.".to_string(),
        "Request bytes are limited to what the browser exposes; not_exposed does not establish body absence or multipart file coverage.".to_string(),
        "Network content reads settle within 5 seconds each and never wait for unfinished responses or refetch them.".to_string(),
        "Scenario events do not expose request initiator stacks; receipt order does not prove causality.".to_string(),
        "Storage values are hashed only after declared-secret redaction.".to_string(),
    ];
    if mode == "connect" {
        limitations.push(
            "CDP attachment cannot recover pre-attach events or guarantee launch-time context options.".to_string(),
        );
    }
    limitations.extend(gaps);
    json!({
        "browser": {
            "mode": mode,
            "process_ownership": ownership,
            "cleanup": cleanup,
            "product": "Chromium",
            "version": version,
        },
        "scenario": {
            "start_origin": start_origin,
            "action_count": scenario.actions.len(),
            "secret_references": secret_references,
            "network_content": {
                "request_body": scenario.capture.request_body,
                "response_body": scenario.capture.response_body,
                "header_values": scenario.capture.header_values,
            },
        },
        "duration_ms": elapsed.as_millis() as u64,
        "steps": steps,
        "events": { "retained": 0, "dropped": 0, "items": [] },
        "completeness": classify_completeness(&missing, &truncated),
        "limitations": limitations,
    })
}

fn event_gaps(capture: &ScenarioCapture) -> Vec<String> {
    if capture.events.is_empty() {
        return Vec::new();
    }
    vec!["Selected event families are not retained by this CDP scenario capture.".to_string()]
}

fn classify_completeness(missing: &[String], truncated: &[String]) -> Value {
    if !truncated.is_empty() {
        json!({
            "status": "truncated",
            "equality_eligible": false,
            "missing_sections": missing,
            "truncated_sections": truncated,
        })
    } else if !missing.is_empty() {
        json!({
            "status": "incomplete",
            "equality_eligible": false,
            "missing_sections": missing,
            "truncated_sections": [],
        })
    } else {
        json!({
            "status": "complete",
            "equality_eligible": true,
            "missing_sections": [],
            "truncated_sections": [],
        })
    }
}

fn step_completeness(artifacts: &Value, status: &str) -> Value {
    let mut missing = Vec::new();
    let mut truncated = Vec::new();
    for kind in SNAPSHOTS {
        match artifacts.get(kind).and_then(|item| item.get("state")).and_then(Value::as_str) {
            Some("missing") => missing.push(kind.to_string()),
            Some("truncated") => truncated.push(kind.to_string()),
            _ => {}
        }
    }
    if status != "completed" {
        missing.push("action".to_string());
    }
    missing.sort();
    truncated.sort();
    classify_completeness(&missing, &truncated)
}

fn text_artifact(text: &str) -> Value {
    json!({
        "sha256": hex::encode(Sha256::digest(text.as_bytes())),
        "bytes": text.len(),
        "text": text,
    })
}

fn version_from_product(product: &str) -> String {
    product
        .rsplit_once('/')
        .map(|(_, version)| version)
        .filter(|version| !version.is_empty())
        .unwrap_or(product)
        .to_string()
}

fn action_error(secrets: &ScenarioSecrets, message: &str) -> WebError {
    browser_error(
        OPERATION,
        BrowserFailureReason::ProtocolError,
        Some(secrets.redact(message)),
    )
}

fn free_port() -> Result<u16, WebError> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn kill_chrome_using(user_data_dir: &Path) {
    let needle = user_data_dir.display().to_string();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return;
    };
    for entry in entries.flatten() {
        let pid = entry.file_name();
        let pid = pid.to_string_lossy();
        if pid.parse::<u32>().is_err() {
            continue;
        }
        let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        if String::from_utf8_lossy(&cmdline).contains(&needle) {
            let _ = std::process::Command::new("kill").args(["-KILL", pid.as_ref()]).status();
        }
    }
}
