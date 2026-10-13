//! CDP control of one owned Electron application.
//!
//! REA reaches Electron through Playwright's `_electron.launch`, which opens two
//! WebSockets: the Node inspector (`Debugger listening on ws://`) to evaluate in
//! the main process and the Chromium DevTools endpoint (`DevTools listening on
//! ws://`) for windows. This module speaks the same two protocols directly:
//! - `application.evaluate(fn)`   -> `Runtime.evaluate` on the Node inspector with
//!   `includeCommandLineAPI` (Playwright's own way to reach `require('electron')`);
//! - `application.windows()`      -> page targets of the DevTools endpoint, in the
//!   order they were created (Playwright orders pages by attachment; here by `webContents` id);
//! - `locator(css).click()`       -> actionability polling in the page followed by
//!   `Input.dispatchMouseEvent`;
//! - `page.reload()`              -> `Page.reload` + `Page.loadEventFired`.
//!
//! Limits against Playwright: only CSS selectors (`text=`, `role=`, `>>`, ... are
//! reported as an action failure) and no cross-iframe hit testing.

use std::collections::HashMap;
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::cdp_connection::{CdpConnection, CdpEvent};
use crate::electron_scenario::ElectronCaptureState;
use crate::error::WebError;

use super::process::Endpoints;

pub const OPERATION: &str = "capture_electron_scenario";

const WINDOW_POLL: Duration = Duration::from_millis(25);
/// Quiet time after the last page announcement before a window index is resolved.
const PAGE_SETTLE: Duration = Duration::from_millis(300);

/// Message REA gives a `BrowserObservationError` (an action's `error` text).
pub fn observation_message(reason: &str) -> String {
    format!("Browser observation {OPERATION} failed: {reason}")
}

pub fn describe(error: &WebError) -> String {
    match error {
        WebError::BrowserObservation { reason, .. } => observation_message(reason),
        WebError::CdpCommandRejected { message, .. } => message.clone(),
        other => other.to_string(),
    }
}

const HOOK_SNAPSHOT_FALLBACK: &str = r#"{
  events: [], retention_budget_bytes: 0, estimated_retained_bytes: 0,
  event_serialized_byte_upper_bound: 0, retained: 0, dropped: 0, dropped_ipc: 0,
  dropped_runtime: 0, dropped_event_families: [], dropped_event_roles: [],
  observed: 0, observed_ipc: 0, observed_runtime: 0, hook_error: true
}"#;

/// One main-process read of windows, process metrics, version and hook snapshot
/// (REA `readApplicationState`, evaluated at a single capture boundary).
fn state_expression() -> String {
    format!(
        r#"(() => {{
  const {{ app, BrowserWindow }} = require("electron");
  const windows = BrowserWindow.getAllWindows().map((window) => ({{
    window_id: `window:${{String(window.id)}}`,
    web_contents_id: `webContents:${{String(window.webContents.id)}}`,
    url: window.webContents.getURL(),
    title: window.webContents.getTitle(),
    visible: window.isDestroyed() ? null : window.isVisible(),
    destroyed: window.isDestroyed(),
  }}));
  const metrics = app.getAppMetrics().map((metric) => ({{
    pid: metric.pid,
    type: metric.type,
    name: metric.name ?? null,
    service_name: metric.serviceName ?? null,
  }}));
  const candidate = Reflect.get(globalThis, "__reaElectronActiveSnapshot");
  const hook = typeof candidate === "function" ? candidate() : {HOOK_SNAPSHOT_FALLBACK};
  return {{ windows, metrics, version: process.versions.electron, hook }};
}})()"#
    )
}

fn crash_expression(index: i64) -> String {
    format!(
        r#"(({{ BrowserWindow }}, index) => {{
  const candidate = BrowserWindow.getAllWindows()[index];
  if (candidate === undefined || candidate.isDestroyed()) return false;
  candidate.webContents.forcefullyCrashRenderer();
  return true;
}})(require("electron"), {index})"#
    )
}

fn deep_link_expression(delivery: &str, url: &str) -> String {
    let payload = json!({ "delivery": delivery, "url": url });
    format!(
        r#"(({{ app }}, payload) => {{
  if (payload.delivery === "open-url")
    return app.emit("open-url", {{ preventDefault: () => undefined }}, payload.url);
  return app.emit("second-instance", {{}}, [payload.url], "", {{}});
}})(require("electron"), {payload})"#
    )
}

/// Actionability probe for `locator(selector).click()`: attached, unique, visible,
/// enabled, scrolled into view and not covered. Returns the click point and the
/// box so Rust can require two identical samples (stability).
const CLICK_PROBE: &str = r#"((rawSelector) => {
  const selector = rawSelector.startsWith("css=") ? rawSelector.slice(4) : rawSelector;
  let found;
  try { found = document.querySelectorAll(selector); }
  catch (cause) {
    return { status: "error", message: `Unsupported selector "${rawSelector}": only CSS selectors are supported (${String(cause && cause.message || cause)})` };
  }
  if (found.length === 0) return { status: "wait", reason: "element not found" };
  if (found.length > 1)
    return { status: "error", message: `strict mode violation: locator('${rawSelector}') resolved to ${found.length} elements` };
  const element = found[0];
  if (typeof element.scrollIntoViewIfNeeded === "function") element.scrollIntoViewIfNeeded(true);
  const style = getComputedStyle(element);
  const rect = element.getBoundingClientRect();
  if (rect.width === 0 || rect.height === 0 || style.visibility !== "visible")
    return { status: "wait", reason: "element is not visible" };
  if (element.matches(":disabled") || element.getAttribute("aria-disabled") === "true")
    return { status: "wait", reason: "element is not enabled" };
  const left = Math.max(rect.left, 0), top = Math.max(rect.top, 0);
  const right = Math.min(rect.right, window.innerWidth), bottom = Math.min(rect.bottom, window.innerHeight);
  if (right <= left || bottom <= top) return { status: "wait", reason: "element is outside the viewport" };
  const x = (left + right) / 2, y = (top + bottom) / 2;
  const hit = document.elementFromPoint(x, y);
  if (!(hit === element || element.contains(hit)))
    return { status: "wait", reason: "element does not receive pointer events" };
  return { status: "ready", x, y, box: [rect.left, rect.top, rect.width, rect.height] };
})"#;

/// Connected control channels for one Electron application.
pub struct Driver {
    node: CdpConnection,
    browser: CdpConnection,
    pages: Vec<String>,
    pages_changed: bool,
    last_page_arrival: Option<std::time::Instant>,
    web_contents: HashMap<String, i64>,
    sessions: HashMap<String, String>,
    page_events: Vec<CdpEvent>,
}

impl Driver {
    pub async fn connect(endpoints: &Endpoints) -> Result<Self, WebError> {
        require_loopback(&endpoints.node)?;
        require_loopback(&endpoints.browser)?;
        let node = CdpConnection::connect(&endpoints.node, OPERATION).await?;
        let mut browser = match CdpConnection::connect(&endpoints.browser, OPERATION).await {
            Ok(browser) => browser,
            Err(error) => {
                let mut node = node;
                node.close().await;
                return Err(error);
            }
        };
        if let Err(error) = browser
            .send("Target.setDiscoverTargets", json!({ "discover": true }), None)
            .await
        {
            let mut node = node;
            node.close().await;
            browser.close().await;
            return Err(error);
        }
        let mut driver = Self {
            node,
            browser,
            pages: Vec::new(),
            pages_changed: false,
            last_page_arrival: None,
            web_contents: HashMap::new(),
            sessions: HashMap::new(),
            page_events: Vec::new(),
        };
        driver.absorb();
        Ok(driver)
    }

    /// Drop both sockets (never the application).
    pub async fn close(&mut self) {
        self.node.close().await;
        self.browser.close().await;
    }

    fn absorb(&mut self) {
        for event in self.browser.take_events() {
            match event.method.as_str() {
                "Target.targetCreated" => {
                    let info = &event.params["targetInfo"];
                    if info["type"] == "page" {
                        if let Some(id) = info["targetId"].as_str() {
                            if !self.pages.iter().any(|known| known == id) {
                                self.pages.push(id.to_string());
                                self.pages_changed = true;
                                self.last_page_arrival = Some(std::time::Instant::now());
                            }
                        }
                    }
                }
                "Target.targetDestroyed" => {
                    if let Some(id) = event.params["targetId"].as_str() {
                        self.pages.retain(|known| known != id);
                        self.web_contents.remove(id);
                        self.sessions.remove(id);
                    }
                }
                _ => self.page_events.push(event),
            }
        }
        // Page events of sessions that no longer exist are not needed.
        if self.page_events.len() > 4096 {
            self.page_events.drain(..2048);
        }
    }

    async fn pump(&mut self, window: Duration) -> Result<(), WebError> {
        self.browser.collect_for(window).await?;
        // Idle Node-inspector traffic (console output, scripts) is not used.
        let _ = self.node.take_events();
        self.absorb();
        Ok(())
    }

    /// Give every page its `webContents` id (Playwright's own `browserWindow(page)`
    /// mapping, `webContents.fromDevToolsTargetId`) and order the pages by it.
    ///
    /// `Target.setDiscoverTargets` reports targets that already exist in an
    /// arbitrary order, so the order of arrival is not "window 0, window 1".
    /// `webContents` ids grow with creation, which is the order Playwright's
    /// `application.windows()` yields for windows created after attachment.
    async fn order_pages(&mut self) {
        if !self.pages_changed {
            return;
        }
        self.pages_changed = false;
        let unresolved: Vec<String> = self
            .pages
            .iter()
            .filter(|id| !self.web_contents.contains_key(*id))
            .cloned()
            .collect();
        for target_id in unresolved {
            let expression = format!(
                r#"(() => {{
  const {{ webContents }} = require("electron");
  const contents = typeof webContents.fromDevToolsTargetId === "function"
    ? webContents.fromDevToolsTargetId({}) : undefined;
  return contents === undefined || contents === null ? null : contents.id;
}})()"#,
                Value::String(target_id.clone())
            );
            let resolved = self.main_eval(&expression).await.ok().and_then(|v| v.as_i64());
            match resolved {
                Some(id) => {
                    self.web_contents.insert(target_id, id);
                }
                None => self.pages_changed = true, // not mapped yet; ask again later
            }
        }
        let known = &self.web_contents;
        self.pages.sort_by_key(|id| known.get(id).copied().unwrap_or(i64::MAX));
    }

    /// Wait (without a deadline, like REA) until window `index` exists.
    pub async fn wait_for_window(&mut self, index: usize) -> Result<String, String> {
        loop {
            self.pump(Duration::from_millis(1)).await.map_err(|e| describe(&e))?;
            // Pages announced in the same burst arrive in arbitrary order: wait for the burst to end.
            let settled = self.last_page_arrival.is_none_or(|at| at.elapsed() >= PAGE_SETTLE);
            if self.pages.len() > index && settled {
                self.order_pages().await;
                if let Some(id) = self.pages.get(index) {
                    return Ok(id.clone());
                }
            }
            tokio::time::sleep(WINDOW_POLL).await;
        }
    }

    pub async fn wait_for_first_window(&mut self) -> Result<(), String> {
        self.wait_for_window(0).await.map(|_| ())
    }

    /// `application.evaluate`: run an expression in the Electron main process.
    pub async fn main_eval(&mut self, expression: &str) -> Result<Value, String> {
        let result = self
            .node
            .send(
                "Runtime.evaluate",
                json!({
                    "expression": expression,
                    "returnByValue": true,
                    "awaitPromise": true,
                    "includeCommandLineAPI": true,
                }),
                None,
            )
            .await
            .map_err(|e| describe(&e))?;
        evaluation_value(&result)
    }

    async fn session(&mut self, target_id: &str) -> Result<String, String> {
        if let Some(session) = self.sessions.get(target_id) {
            return Ok(session.clone());
        }
        let attached = self
            .browser
            .send(
                "Target.attachToTarget",
                json!({ "targetId": target_id, "flatten": true }),
                None,
            )
            .await
            .map_err(|e| describe(&e))?;
        let session = attached
            .get("sessionId")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| observation_message("protocol_error"))?
            .to_string();
        self.sessions.insert(target_id.to_string(), session.clone());
        Ok(session)
    }

    async fn page_eval(&mut self, session: &str, expression: &str) -> Result<Value, String> {
        let result = self
            .browser
            .send(
                "Runtime.evaluate",
                json!({ "expression": expression, "returnByValue": true }),
                Some(session),
            )
            .await
            .map_err(|e| describe(&e))?;
        evaluation_value(&result)
    }

    /// `locator(selector).click({ timeout: 0 })`: polls until the click lands.
    pub async fn click(&mut self, target_id: &str, selector: &str) -> Result<(), String> {
        let session = self.session(target_id).await?;
        let probe = format!("{CLICK_PROBE}({})", Value::String(selector.to_string()));
        let mut previous: Option<Value> = None;
        let mut attempt = 0usize;
        loop {
            let state = self.page_eval(&session, &probe).await?;
            match state["status"].as_str() {
                Some("error") => {
                    return Err(state["message"].as_str().unwrap_or("click failed").to_string());
                }
                Some("ready") => {
                    // Stable: the same box on two consecutive samples.
                    if previous.as_ref() == Some(&state["box"]) {
                        let (x, y) = (state["x"].as_f64().unwrap_or(0.0), state["y"].as_f64().unwrap_or(0.0));
                        return self.mouse_click(&session, x, y).await;
                    }
                    previous = Some(state["box"].clone());
                }
                _ => previous = None,
            }
            // Playwright's retry schedule: 0, 20, 100, 100, 500, 500, ...
            let wait = match attempt {
                0 => 20,
                1 | 2 => 100,
                _ => 500,
            };
            attempt += 1;
            let wait = if previous.is_some() { 30 } else { wait };
            tokio::time::sleep(Duration::from_millis(wait)).await;
            self.pump(Duration::from_millis(1)).await.map_err(|e| describe(&e))?;
        }
    }

    async fn mouse_click(&mut self, session: &str, x: f64, y: f64) -> Result<(), String> {
        for (kind, buttons, clicks) in [("mouseMoved", 0, 0), ("mousePressed", 1, 1), ("mouseReleased", 0, 1)] {
            let mut params = json!({ "type": kind, "x": x, "y": y, "buttons": buttons });
            if kind != "mouseMoved" {
                params["button"] = json!("left");
                params["clickCount"] = json!(clicks);
            }
            self.browser
                .send("Input.dispatchMouseEvent", params, Some(session))
                .await
                .map_err(|e| describe(&e))?;
        }
        // Playwright's click returns after its post-action bookkeeping, long enough for the
        // renderer to run the handler and its IPC to reach the main process. One round trip
        // through the page and one through the main process give the same ordering here, so
        // an IPC caused by the click is recorded before the next action starts.
        let _ = self.page_eval(session, "0").await;
        let _ = self.main_eval("0").await;
        Ok(())
    }

    /// `page.reload({ timeout: 0 })`: resolves on the `load` event.
    pub async fn reload(&mut self, target_id: &str) -> Result<(), String> {
        let session = self.session(target_id).await?;
        self.browser
            .send("Page.enable", json!({}), Some(&session))
            .await
            .map_err(|e| describe(&e))?;
        self.page_events.retain(|event| event.session_id.as_deref() != Some(session.as_str()));
        self.browser
            .send("Page.reload", json!({}), Some(&session))
            .await
            .map_err(|e| describe(&e))?;
        loop {
            self.absorb();
            if self.page_events.iter().any(|event| {
                event.method == "Page.loadEventFired" && event.session_id.as_deref() == Some(session.as_str())
            }) {
                return Ok(());
            }
            self.pump(Duration::from_millis(25)).await.map_err(|e| describe(&e))?;
        }
    }

    /// Force a renderer crash (REA evaluates the same main-process snippet).
    pub async fn crash_renderer(&mut self, window_index: i64) -> Result<bool, String> {
        let value = self.main_eval(&crash_expression(window_index)).await?;
        Ok(value == Value::Bool(true))
    }

    /// Synthetic deep-link delivery through `app.emit`.
    pub async fn deep_link(&mut self, delivery: &str, url: &str) -> Result<(), String> {
        self.main_eval(&deep_link_expression(delivery, url)).await.map(|_| ())
    }

    /// REA `readApplicationState`.
    pub async fn read_state(&mut self) -> Result<ElectronCaptureState, String> {
        let value = self.main_eval(&state_expression()).await?;
        parse_state(&value)
    }

    /// Ask the application to quit; the connection may drop before the reply.
    pub async fn quit(&mut self) {
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            self.main_eval(r#"require("electron").app.quit()"#),
        )
        .await;
    }
}

fn require_loopback(url: &str) -> Result<(), WebError> {
    let parsed = url::Url::parse(url).ok();
    let loopback = parsed.as_ref().is_some_and(|u| {
        matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]" | "::1")) && u.scheme() == "ws"
    });
    if loopback {
        Ok(())
    } else {
        Err(crate::browser_observation::browser_error(
            OPERATION,
            crate::browser_observation::BrowserFailureReason::InvalidEndpointResponse,
            None,
        ))
    }
}

fn evaluation_value(result: &Map<String, Value>) -> Result<Value, String> {
    if let Some(details) = result.get("exceptionDetails") {
        let text = details["exception"]["description"]
            .as_str()
            .or_else(|| details["exception"]["value"].as_str())
            .or_else(|| details["text"].as_str())
            .unwrap_or("evaluation failed");
        return Err(text.lines().next().unwrap_or(text).to_string());
    }
    Ok(result
        .get("result")
        .and_then(|r| r.get("value"))
        .cloned()
        .unwrap_or(Value::Null))
}

// ------------------------------------------------------------ state validation

fn is_int(value: &Value, min: i64) -> bool {
    value.as_i64().is_some_and(|n| n >= min) || value.as_f64().is_some_and(|n| n.fract() == 0.0 && n >= min as f64)
}

fn exact_keys(object: &Map<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

fn string_or_null(value: &Value) -> bool {
    value.is_string() || value.is_null()
}

const EVENT_KEYS: [&str; 17] = [
    "sequence",
    "correlation_id",
    "kind",
    "event",
    "phase",
    "channel",
    "direction",
    "sender",
    "receiver",
    "frame",
    "target",
    "argument_shapes",
    "result_shape",
    "process_type",
    "source",
    "capture_method",
    "artifact_path",
];
const EVENT_KINDS: [&str; 23] = [
    "main-handler-invocation",
    "main-event-invocation",
    "utility-process-fork",
    "utility-process-message",
    "ipc-main-to-renderer",
    "ipc-utility-to-main",
    "ipc-renderer-send",
    "ipc-renderer-invoke",
    "ipc-renderer-post-message",
    "app-lifecycle",
    "window-lifecycle",
    "web-contents-lifecycle",
    "navigation",
    "shell-attempt",
    "process-lifecycle",
    "permission",
    "popup-attempt",
    "download",
    "protocol",
    "preload",
    "native-addon",
    "updater",
    "error",
];

fn valid_event(event: &Value) -> bool {
    let Some(object) = event.as_object() else {
        return false;
    };
    // The 17 keys above plus `artifact_sha256` and `error`.
    if object.len() != EVENT_KEYS.len() + 2
        || !EVENT_KEYS.iter().all(|key| object.contains_key(*key))
        || !object.contains_key("artifact_sha256")
        || !object.contains_key("error")
    {
        return false;
    }
    is_int(&object["sequence"], 1)
        && string_or_null(&object["correlation_id"])
        && object["kind"].as_str().is_some_and(|k| EVENT_KINDS.contains(&k))
        && string_or_null(&object["event"])
        && object["phase"]
            .as_str()
            .is_some_and(|p| ["attempted", "completed", "blocked", "failed", "observed"].contains(&p))
        && ["channel", "sender", "receiver", "frame", "target", "result_shape", "process_type", "artifact_path"]
            .iter()
            .all(|key| string_or_null(&object[*key]))
        && (object["direction"].is_null()
            || object["direction"].as_str().is_some_and(|d| {
                ["renderer-to-main", "main-to-renderer", "main-to-utility", "utility-to-main"].contains(&d)
            }))
        && object["argument_shapes"]
            .as_array()
            .is_some_and(|items| items.iter().all(Value::is_string))
        && object["source"].is_string()
        && object["capture_method"]
            .as_str()
            .is_some_and(|m| ["api-wrapper", "event-emitter", "process-hook"].contains(&m))
        && (object["artifact_sha256"].is_null()
            || object["artifact_sha256"]
                .as_str()
                .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))))
        && object["error"].is_boolean()
}

fn valid_counts(items: &Value, name: &str) -> bool {
    items.as_array().is_some_and(|items| {
        items.iter().all(|item| {
            item.as_object().is_some_and(|o| {
                exact_keys(o, &[name, "count"]) && o[name].as_str().is_some_and(|s| !s.is_empty()) && is_int(&o["count"], 1)
            })
        })
    })
}

/// zod `hookSnapshotSchema` + `windowMetadataSchema` + `metricSchema`.
pub fn parse_state(value: &Value) -> Result<ElectronCaptureState, String> {
    let invalid = |what: &str| format!("Electron returned an invalid {what}");
    let object = value.as_object().ok_or_else(|| invalid("application state"))?;
    let windows = object["windows"].as_array().ok_or_else(|| invalid("window list"))?;
    for window in windows {
        let ok = window.as_object().is_some_and(|w| {
            exact_keys(w, &["window_id", "web_contents_id", "url", "title", "visible", "destroyed"])
                && ["window_id", "web_contents_id", "url", "title"].iter().all(|k| w[*k].is_string())
                && (w["visible"].is_boolean() || w["visible"].is_null())
                && w["destroyed"].is_boolean()
        });
        if !ok {
            return Err(invalid("window description"));
        }
    }
    let metrics = object["metrics"].as_array().ok_or_else(|| invalid("process metrics list"))?;
    for metric in metrics {
        let ok = metric.as_object().is_some_and(|m| {
            exact_keys(m, &["pid", "type", "name", "service_name"])
                && is_int(&m["pid"], 1)
                && m["type"].as_str().is_some_and(|t| !t.is_empty())
                && string_or_null(&m["name"])
                && string_or_null(&m["service_name"])
        });
        if !ok {
            return Err(invalid("process metric"));
        }
    }
    let version = object["version"]
        .as_str()
        .ok_or_else(|| invalid("Electron version"))?
        .to_string();
    let hook = object["hook"].as_object().ok_or_else(|| invalid("hook snapshot"))?;
    let counters = [
        "retention_budget_bytes",
        "estimated_retained_bytes",
        "event_serialized_byte_upper_bound",
        "retained",
        "dropped",
        "dropped_ipc",
        "dropped_runtime",
        "observed",
        "observed_ipc",
        "observed_runtime",
    ];
    let hook_ok = exact_keys(
        hook,
        &[
            "events",
            "retention_budget_bytes",
            "estimated_retained_bytes",
            "event_serialized_byte_upper_bound",
            "retained",
            "dropped",
            "dropped_ipc",
            "dropped_runtime",
            "dropped_event_families",
            "dropped_event_roles",
            "observed",
            "observed_ipc",
            "observed_runtime",
            "hook_error",
        ],
    ) && hook["events"].as_array().is_some_and(|events| events.iter().all(valid_event))
        && counters.iter().all(|key| is_int(&hook[*key], 0))
        && valid_counts(&hook["dropped_event_families"], "family")
        && valid_counts(&hook["dropped_event_roles"], "role")
        && hook["hook_error"].is_boolean();
    if !hook_ok {
        return Err(invalid("hook snapshot"));
    }
    Ok(ElectronCaptureState {
        windows: windows.clone(),
        metrics: metrics.clone(),
        electron_version: version,
        hook_snapshot: Value::Object(hook.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> Value {
        json!({
            "events": [], "retention_budget_bytes": 0, "estimated_retained_bytes": 0,
            "event_serialized_byte_upper_bound": 0, "retained": 0, "dropped": 0, "dropped_ipc": 0,
            "dropped_runtime": 0, "dropped_event_families": [], "dropped_event_roles": [],
            "observed": 0, "observed_ipc": 0, "observed_runtime": 0, "hook_error": true,
        })
    }

    #[test]
    fn state_validation_is_strict_like_the_zod_schemas() {
        let ok = json!({ "windows": [], "metrics": [], "version": "44.7.0", "hook": snapshot() });
        assert_eq!(parse_state(&ok).unwrap().electron_version, "44.7.0");
        let mut extra = snapshot();
        extra["extra"] = json!(1);
        assert!(parse_state(&json!({ "windows": [], "metrics": [], "version": "1", "hook": extra })).is_err());
        let bad_metric = json!({ "windows": [], "metrics": [{ "pid": 0, "type": "Tab", "name": null, "service_name": null }], "version": "1", "hook": snapshot() });
        assert!(parse_state(&bad_metric).is_err());
        let bad_window = json!({ "windows": [{ "window_id": "w" }], "metrics": [], "version": "1", "hook": snapshot() });
        assert!(parse_state(&bad_window).is_err());
    }

    #[test]
    fn the_hook_fallback_literal_is_the_missing_hook_snapshot_of_rea() {
        let expression = state_expression();
        assert!(expression.contains("hook_error: true"));
        assert!(expression.contains("__reaElectronActiveSnapshot"));
    }

    #[test]
    fn probe_and_snippets_embed_values_as_json() {
        assert!(deep_link_expression("open-url", "app://x\"y").contains(r#""url":"app://x\"y""#));
        assert!(crash_expression(3).ends_with(r#"(require("electron"), 3)"#));
    }
}
