//! `inspect_web_event_listeners` (port of REA browser/execution/CdpEventListeners.ts).
//!
//! Reads native listener descriptors on the first main-document CSS match.
//! It does not evaluate JavaScript, dispatch an event, or invoke a handler.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use tracewise_domain::evidence::Evidence;

use crate::browser_observation::{browser_error, create_browser_evidence, BrowserFailureReason, BrowserScope};
use crate::cdp_values::{cdp_str, record, safe_integer};
use crate::error::WebError;
use crate::runtime_cdp::{input_error, iso_now, parse_scope, require_target_id, RuntimeAttach};

const OPERATION: &str = "inspect_web_event_listeners";

pub struct InspectWebEventListenersInput {
    pub scope: BrowserScope,
    pub target_id: String,
    pub selector: String,
}

pub fn parse_inspect_web_event_listeners_input(args: &Value) -> Result<InspectWebEventListenersInput, WebError> {
    let (scope, object) = parse_scope(OPERATION, args, &["target_id", "selector"])?;
    let target_id = require_target_id(OPERATION, &object)?;
    let selector = object
        .get("selector")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| input_error(OPERATION, "selector", "selector must be a non-empty string"))?
        .to_string();
    Ok(InspectWebEventListenersInput {
        scope,
        target_id,
        selector,
    })
}

pub async fn inspect_web_event_listeners(input: &InspectWebEventListenersInput) -> Result<Evidence, WebError> {
    let mut attach = RuntimeAttach::open(OPERATION, &input.scope, &input.target_id).await?;
    let group = object_group();
    let outcome = capture(&mut attach, input, &group).await;
    attach.close(Some(&group)).await;
    let result = outcome?;
    if result["target"]["target_id"].as_str() != Some(input.target_id.as_str())
        || result["selected_node"]["selector"].as_str() != Some(input.selector.as_str())
    {
        return Err(browser_error(
            OPERATION,
            BrowserFailureReason::ProtocolError,
            Some("Provider changed the selected target or node selector.".to_string()),
        ));
    }
    create_browser_evidence(OPERATION, "rea.inspect-web-event-listeners", parameters(input), result)
}

async fn capture(attach: &mut RuntimeAttach, input: &InspectWebEventListenersInput, group: &str) -> Result<Value, WebError> {
    for domain in ["Page", "Runtime", "Debugger", "DOM"] {
        attach.enable(domain).await?;
    }
    attach.assert_document().await?;
    let document = attach.command("DOM.getDocument", json!({ "depth": 0 })).await?;
    let root_id = document
        .get("root")
        .and_then(record)
        .and_then(|root| root.get("nodeId"))
        .and_then(positive)
        .ok_or_else(|| browser_error(OPERATION, BrowserFailureReason::ProtocolError, None))?;
    let selected = query_selector(attach, root_id, &input.selector).await?;
    let node_id = selected
        .get("nodeId")
        .and_then(nonneg)
        .ok_or_else(|| browser_error(OPERATION, BrowserFailureReason::ProtocolError, None))?;

    let mut backend_node_id = None;
    let mut listeners = Vec::new();
    if node_id != 0 {
        let described = attach.command("DOM.describeNode", json!({ "nodeId": node_id })).await?;
        backend_node_id = described
            .get("node")
            .and_then(record)
            .and_then(|node| node.get("backendNodeId"))
            .and_then(positive);
        if backend_node_id.is_none() {
            return Err(browser_error(OPERATION, BrowserFailureReason::ProtocolError, None));
        }
        let resolved = attach
            .command(
                "DOM.resolveNode",
                json!({ "nodeId": node_id, "objectGroup": group }),
            )
            .await?;
        let object_id = resolved
            .get("object")
            .and_then(record)
            .and_then(|object| object.get("objectId"))
            .and_then(cdp_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| browser_error(OPERATION, BrowserFailureReason::ProtocolError, None))?;
        let described_listeners = attach
            .command(
                "DOMDebugger.getEventListeners",
                json!({ "objectId": object_id, "depth": 0, "pierce": false }),
            )
            .await?;
        listeners = described_listeners
            .get("listeners")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| browser_error(OPERATION, BrowserFailureReason::ProtocolError, None))?;
    }

    let mut script_ids = Vec::new();
    let mut projected = Vec::new();
    for listener in &listeners {
        let Some(listener) = listener.as_object() else {
            return Err(browser_error(OPERATION, BrowserFailureReason::ProtocolError, None));
        };
        let event_type = listener
            .get("type")
            .and_then(cdp_str)
            .ok_or_else(|| browser_error(OPERATION, BrowserFailureReason::ProtocolError, None))?;
        let use_capture = listener
            .get("useCapture")
            .and_then(Value::as_bool)
            .ok_or_else(|| browser_error(OPERATION, BrowserFailureReason::ProtocolError, None))?;
        let passive = listener
            .get("passive")
            .and_then(Value::as_bool)
            .ok_or_else(|| browser_error(OPERATION, BrowserFailureReason::ProtocolError, None))?;
        let once = listener
            .get("once")
            .and_then(Value::as_bool)
            .ok_or_else(|| browser_error(OPERATION, BrowserFailureReason::ProtocolError, None))?;
        let script_id = listener.get("scriptId").and_then(cdp_str).unwrap_or("");
        let line = listener
            .get("lineNumber")
            .and_then(nonneg)
            .ok_or_else(|| browser_error(OPERATION, BrowserFailureReason::ProtocolError, None))?;
        let column = listener
            .get("columnNumber")
            .and_then(nonneg)
            .ok_or_else(|| browser_error(OPERATION, BrowserFailureReason::ProtocolError, None))?;
        if !script_id.is_empty() {
            script_ids.push(script_id.to_string());
        }
        let url = attach.sources.reported_script_url(script_id);
        projected.push(json!({
            "type": event_type,
            "use_capture": use_capture,
            "passive": passive,
            "once": once,
            "location": attach.sources.location(script_id, url.as_deref(), line, Some(column), None),
            "execution": "unknown",
        }));
    }
    let sources = read_listener_sources(attach, &script_ids).await?;
    attach.assert_document().await?;
    attach.sources.check()?;
    Ok(json!({
        "browser": attach.document.browser,
        "target": attach.target_json(),
        "inspected_at": iso_now(),
        "selected_node": {
            "selector": input.selector,
            "match": if node_id == 0 { "not_found" } else { "found" },
            "backend_node_id": backend_node_id,
        },
        "listeners": projected,
        "sources": sources,
        "cleanup": "confirmed",
        "limitations": LISTENER_LIMITATIONS,
    }))
}

async fn query_selector(attach: &mut RuntimeAttach, node_id: i64, selector: &str) -> Result<serde_json::Map<String, Value>, WebError> {
    match attach.command("DOM.querySelector", json!({ "nodeId": node_id, "selector": selector })).await {
        Ok(result) => Ok(result),
        Err(WebError::CdpCommandRejected { code, message, .. })
            if code == -32000 && message == "DOM Error while querying" =>
        {
            Err(input_error(
                OPERATION,
                "selector",
                format!(
                    "Chromium rejected the CSS selector syntax for target {}: {selector}. {message}",
                    attach.document.target_id
                ),
            ))
        }
        Err(error) => Err(error),
    }
}

async fn read_listener_sources(attach: &mut RuntimeAttach, script_ids: &[String]) -> Result<Vec<Value>, WebError> {
    attach.sources.read(&mut attach.session, script_ids).await
}

fn nonneg(value: &Value) -> Option<i64> {
    safe_integer(value).filter(|number| *number >= 0)
}

fn positive(value: &Value) -> Option<i64> {
    nonneg(value).filter(|number| *number >= 1)
}

fn object_group() -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    format!("rea-listeners-{}-{nanos}", std::process::id())
}

fn parameters(input: &InspectWebEventListenersInput) -> Value {
    json!({
        "cdp_endpoint": input.scope.cdp_endpoint,
        "allowed_origins": input.scope.allowed_origins,
        "target_id": input.target_id,
        "selector": input.selector,
    })
}

const LISTENER_LIMITATIONS: [&str; 5] = [
    "Inspects listeners registered directly on the first native CSS match in the selected main document. Delegated ancestor listeners, descendants, closed shadow roots and framework registries are not enumerated.",
    "Native CDP listener descriptors report callback locations; registration time, dispatch history and UI causality remain unknown. REA does not dispatch an event, evaluate JavaScript or invoke a handler.",
    "Source identity uses this session's script ID and proven main-frame default-world metadata. Isolated or unknown worlds cannot establish website callback/source joins. A URL or sourceURL declaration never establishes identity or execution.",
    "Source text is retained inline with its independently computed UTF-8 digest; the producer hash is preserved separately. Missing source ownership or collected scripts remain explicit.",
    "REA releases its remote object group, disables enabled domains and detaches its transport; the externally owned page remains open.",
];
