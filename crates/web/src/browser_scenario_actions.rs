//! Declarative scenario actions over the existing CDP session
//! (port of REA browser/PlaywrightScenarioActions.ts). No caller-supplied code runs.

use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::browser_scenario::{Locator, ScenarioAction, ScenarioValue};
use crate::browser_scenario_secrets::ScenarioSecrets;
use crate::cdp_connection::CdpTargetSession;

const ACTION_SCRIPT: &str = r#"(function(spec){
  function visible(el){
    if (!el || !el.isConnected) return false;
    var style = getComputedStyle(el);
    if (style.visibility === "hidden" || style.display === "none") return false;
    return el.getClientRects().length > 0;
  }
  function implicitRole(el){
    var explicit = el.getAttribute("role");
    if (explicit) return explicit;
    var tag = el.tagName;
    if (tag === "BUTTON") return "button";
    if (tag === "A" && el.hasAttribute("href")) return "link";
    if (tag === "TEXTAREA") return "textbox";
    if (tag === "SELECT") return "combobox";
    if (tag === "OPTION") return "option";
    if (tag === "INPUT") {
      var type = (el.getAttribute("type") || "text").toLowerCase();
      if (type === "checkbox") return "checkbox";
      if (type === "radio") return "radio";
      if (type === "button" || type === "submit" || type === "reset") return "button";
      if (type === "range") return "slider";
      if (type !== "hidden") return "textbox";
    }
    return "";
  }
  function accessibleName(el){
    return (el.getAttribute("aria-label") || el.innerText || el.getAttribute("placeholder") || "").replace(/\s+/g, " ").trim();
  }
  function find(locator){
    if (locator.kind === "css") return Array.prototype.slice.call(document.querySelectorAll(locator.selector));
    if (locator.kind === "test_id") {
      return Array.prototype.slice.call(document.querySelectorAll("[data-testid]")).filter(function(node){
        return node.getAttribute("data-testid") === locator.value;
      });
    }
    return Array.prototype.slice.call(document.querySelectorAll("*")).filter(function(node){
      return implicitRole(node) === locator.role && accessibleName(node) === locator.name;
    });
  }
  if (spec.op === "query") {
    var queried = find(spec.locator);
    return { count: queried.length, attached: queried.length > 0, visible: visible(queried[0]) };
  }
  var nodes = find(spec.locator);
  if (nodes.length !== 1) return { ok: false, error: "locator matched " + nodes.length + " elements" };
  var el = nodes[0];
  if (spec.op === "click") {
    var button = spec.button === "right" ? 2 : spec.button === "middle" ? 1 : 0;
    for (var i = 0; i < spec.click_count; i += 1) {
      if (button === 0) el.click();
      else el.dispatchEvent(new MouseEvent("click", { button: button, bubbles: true, cancelable: true }));
    }
    return { ok: true };
  }
  if (spec.op === "fill") {
    el.focus();
    el.value = spec.value;
    el.setAttribute("value", spec.value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    return { ok: true };
  }
  if (spec.op === "press") {
    el.focus();
    el.dispatchEvent(new KeyboardEvent("keydown", { key: spec.key, bubbles: true }));
    el.dispatchEvent(new KeyboardEvent("keyup", { key: spec.key, bubbles: true }));
    return { ok: true };
  }
  if (spec.op === "select") {
    var matched = false;
    Array.prototype.forEach.call(el.options || [], function(option){
      if (option.value === spec.value || option.label === spec.value) matched = true;
    });
    if (!matched) return { ok: false, error: "option was not found" };
    el.value = spec.value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    return { ok: true };
  }
  if (spec.op === "check") {
    if (el.type !== "checkbox" && el.type !== "radio" && el.getAttribute("role") !== "checkbox" && el.getAttribute("role") !== "switch") {
      return { ok: false, error: "locator is not a checkable control" };
    }
    el.checked = spec.checked;
    if (spec.checked) el.setAttribute("checked", "");
    else el.removeAttribute("checked");
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    return { ok: true };
  }
  return { ok: false, error: "unsupported action" };
})"#;

pub async fn perform_page_action(
    session: &mut CdpTargetSession,
    action: &ScenarioAction,
    secrets: &ScenarioSecrets,
) -> Result<(), String> {
    let spec = match action {
        ScenarioAction::Click { locator, button, click_count, .. } => json!({
            "op": "click",
            "locator": locator.to_json(),
            "button": button,
            "click_count": click_count,
        }),
        ScenarioAction::Fill { locator, value, .. } => json!({
            "op": "fill",
            "locator": locator.to_json(),
            "value": secrets.resolve_value(value),
        }),
        ScenarioAction::Press { locator, key, .. } => json!({
            "op": "press",
            "locator": locator.to_json(),
            "key": key,
        }),
        ScenarioAction::Select { locator, value, .. } => json!({
            "op": "select",
            "locator": locator.to_json(),
            "value": secrets.resolve_value(value),
        }),
        ScenarioAction::Check { locator, checked, .. } => json!({
            "op": "check",
            "locator": locator.to_json(),
            "checked": checked,
        }),
        _ => return Ok(()),
    };
    let value = evaluate(session, &format!("{ACTION_SCRIPT}({spec})")).await?;
    if value.get("ok").and_then(Value::as_bool) == Some(true) {
        return Ok(());
    }
    Err(value.get("error").and_then(Value::as_str).unwrap_or("browser action failed").to_string())
}

pub async fn locator_state(session: &mut CdpTargetSession, locator: &Locator) -> Result<Value, String> {
    let spec = json!({ "op": "query", "locator": locator.to_json() });
    evaluate(session, &format!("{ACTION_SCRIPT}({spec})")).await
}

pub async fn evaluate(session: &mut CdpTargetSession, expression: &str) -> Result<Value, String> {
    let sid = session.session_id.clone();
    let result = session
        .connection
        .send(
            "Runtime.evaluate",
            json!({
                "expression": expression,
                "returnByValue": true,
                "awaitPromise": false,
            }),
            sid.as_deref(),
        )
        .await
        .map_err(|error| error.to_string())?;
    if let Some(details) = result.get("exceptionDetails") {
        let text = details
            .get("exception")
            .and_then(|exception| exception.get("description"))
            .and_then(Value::as_str)
            .or_else(|| details.get("text").and_then(Value::as_str))
            .unwrap_or("page evaluation failed");
        return Err(text.to_string());
    }
    Ok(result
        .get("result")
        .and_then(|remote| remote.get("value"))
        .cloned()
        .unwrap_or(Value::Null))
}

pub async fn navigate(session: &mut CdpTargetSession, url: &str, wait_until: &str, timeout: Duration) -> Result<(), String> {
    let sid = session.session_id.clone();
    let navigated = tokio::time::timeout(
        timeout,
        session.connection.send("Page.navigate", json!({ "url": url }), sid.as_deref()),
    )
    .await
    .map_err(|_| "navigation timed out".to_string())?
    .map_err(|error| error.to_string())?;
    if let Some(error_text) = navigated.get("errorText").and_then(Value::as_str) {
        return Err(error_text.to_string());
    }
    if wait_until == "commit" {
        return Ok(());
    }
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err("navigation timed out".to_string());
        }
        let state = evaluate(session, "document.readyState").await?;
        let ready = state.as_str().unwrap_or("");
        let done = if wait_until == "domcontentloaded" {
            ready == "interactive" || ready == "complete"
        } else {
            ready == "complete"
        };
        if done {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub fn action_locator(action: &ScenarioAction) -> Option<&Locator> {
    match action {
        ScenarioAction::Click { locator, .. }
        | ScenarioAction::Fill { locator, .. }
        | ScenarioAction::Press { locator, .. }
        | ScenarioAction::Select { locator, .. }
        | ScenarioAction::Check { locator, .. }
        | ScenarioAction::WaitFor { locator, .. } => Some(locator),
        _ => None,
    }
}

pub fn action_fill_value(action: &ScenarioAction) -> Option<&ScenarioValue> {
    match action {
        ScenarioAction::Fill { value, .. } | ScenarioAction::Select { value, .. } => Some(value),
        _ => None,
    }
}

pub fn object_map(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}
