//! `discover_webmcp_tools` (port of REA domain/webMcpDiscovery.ts and
//! browser/CdpWebMcpDiscovery.ts).
//!
//! Discovery listens for `WebMCP.toolsAdded` / `toolsRemoved` only.
//! `WebMCP.invokeTool` is never called, and page-declared metadata stays untrusted.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tracewise_domain::canonical_sha256;
use tracewise_domain::evidence::Evidence;

use crate::browser_observation::{
    allowed_sanitized_url, browser_error, create_browser_evidence, parse_browser_scope, sanitize_browser_url,
    trimmed_string_field, BrowserFailureReason, BrowserScope,
};
use crate::cdp_completeness::CdpCaptureCompleteness;
use crate::cdp_connection::{close_cdp_target_session, open_cdp_target_session, CdpEvent, CdpTargetSession};
use crate::cdp_documents::{capture_frames, main_frame_url};
use crate::cdp_endpoint::{discover_cdp_endpoint, CdpEndpointDiscovery, CdpEndpointTarget};
use crate::cdp_values::{cdp_str, finite_f64, record};
use crate::error::WebError;
use crate::runtime_cdp::optional_i64;

const OPERATION: &str = "discover_webmcp_tools";
const MAX_SAFE_INT: i64 = 9_007_199_254_740_991;
const EXTRAS: &[&str] = &["target_id", "observation_ms"];

#[derive(Debug, Clone)]
pub struct DiscoverWebMcpToolsInput {
    pub scope: BrowserScope,
    pub target_id: String,
    pub observation_ms: i64,
}

pub fn parse_discover_webmcp_tools_input(args: &Value) -> Result<DiscoverWebMcpToolsInput, WebError> {
    let (scope, object) = parse_browser_scope(OPERATION, args, EXTRAS)?;
    let target_id = trimmed_string_field(OPERATION, &object, "target_id")?;
    let observation_ms = optional_i64(OPERATION, &object, "observation_ms", 0, MAX_SAFE_INT)?.unwrap_or(100);
    Ok(DiscoverWebMcpToolsInput {
        scope,
        target_id,
        observation_ms,
    })
}

pub async fn discover_webmcp_tools(input: &DiscoverWebMcpToolsInput) -> Result<Evidence, WebError> {
    let discovery = discover_cdp_endpoint(&input.scope.cdp_endpoint, OPERATION).await?;
    let target = authorize_target(&discovery, input)?;
    let origins = scoped_origins(input, target)?;
    let mut session = open_cdp_target_session(&discovery, target, OPERATION).await?;
    let captured = discover_in_session(&mut session, &discovery, target, input, &origins).await;
    close_cdp_target_session(session, &["WebMCP", "Page"]).await;
    let result = captured?;
    create_browser_evidence(OPERATION, "rea.webmcp-discovery", parameters(input, &origins, &result), result)
}

fn authorize_target<'a>(
    discovery: &'a CdpEndpointDiscovery,
    input: &DiscoverWebMcpToolsInput,
) -> Result<&'a CdpEndpointTarget, WebError> {
    let target = discovery.targets.iter().find(|candidate| candidate.id == input.target_id).ok_or_else(|| {
        browser_error(
            OPERATION,
            BrowserFailureReason::TargetNotFound,
            Some(format!("Target {} was not found at the selected endpoint.", input.target_id)),
        )
    })?;
    if target.target_type != "page" {
        return Err(not_allowed(&input.target_id));
    }
    let origin = sanitize_browser_url(&target.url).origin;
    let allowed = &input.scope.allowed_origins;
    match origin {
        Some(origin) if allowed.is_empty() || allowed.contains(&origin) => Ok(target),
        _ => Err(not_allowed(&input.target_id)),
    }
}

fn scoped_origins(input: &DiscoverWebMcpToolsInput, target: &CdpEndpointTarget) -> Result<Vec<String>, WebError> {
    if !input.scope.allowed_origins.is_empty() {
        return Ok(input.scope.allowed_origins.clone());
    }
    sanitize_browser_url(&target.url)
        .origin
        .map(|origin| vec![origin])
        .ok_or_else(|| not_allowed(&input.target_id))
}

fn not_allowed(target_id: &str) -> WebError {
    browser_error(
        OPERATION,
        BrowserFailureReason::TargetNotAllowed,
        Some(format!(
            "Target {target_id} must be an HTTP(S) page in the selected origin scope."
        )),
    )
}

fn parameters(input: &DiscoverWebMcpToolsInput, origins: &[String], result: &Value) -> Value {
    let allowed = if input.scope.allowed_origins.is_empty() {
        result
            .get("target")
            .and_then(|target| target.get("origin"))
            .and_then(Value::as_str)
            .filter(|origin| !origin.is_empty())
            .map(|origin| vec![origin.to_string()])
            .unwrap_or_default()
    } else {
        origins.to_vec()
    };
    json!({
        "cdp_endpoint": input.scope.cdp_endpoint,
        "allowed_origins": allowed,
        "target_id": input.target_id,
        "observation_ms": input.observation_ms,
    })
}

struct FrameScope {
    url: String,
    origin: String,
    parent_frame_id: Option<String>,
    loader_id: Option<String>,
}

struct DiscoveryState {
    origins: Vec<String>,
    frames: HashMap<String, FrameScope>,
    tools: BTreeMap<String, Value>,
    completeness: CdpCaptureCompleteness,
    transient: HashSet<String>,
    resolved_transient: HashSet<String>,
}

async fn discover_in_session(
    session: &mut CdpTargetSession,
    discovery: &CdpEndpointDiscovery,
    target: &CdpEndpointTarget,
    input: &DiscoverWebMcpToolsInput,
    origins: &[String],
) -> Result<Value, WebError> {
    let mut limitations = vec![
        "Page-declared tool metadata is untrusted and is never registered or invoked by REA.".to_string(),
        "Discovery uses only WebMCP.enable and toolsAdded/toolsRemoved; WebMCP.invokeTool is never called.".to_string(),
    ];
    let sid = session.session_id.clone();
    send(session, "Page.enable", json!({})).await?;
    let frame_tree = send(session, "Page.getFrameTree", json!({})).await?;
    let initial_url = main_frame_url(&frame_tree);
    if allowed_sanitized_url(initial_url.as_deref(), origins).is_none() {
        return Err(browser_error(OPERATION, BrowserFailureReason::TargetNotAllowed, None));
    }
    let mut state = DiscoveryState {
        origins: origins.to_vec(),
        frames: HashMap::new(),
        tools: BTreeMap::new(),
        completeness: CdpCaptureCompleteness::new(&[]),
        transient: HashSet::new(),
        resolved_transient: HashSet::new(),
    };
    seed_frames(&frame_tree, &mut state);
    let available = match send(session, "WebMCP.enable", json!({})).await {
        Ok(_) => true,
        Err(WebError::CdpCommandRejected { code: -32601, .. }) => {
            limitations.push("WebMCP.enable was unavailable from this browser target.".to_string());
            false
        }
        Err(error) => return Err(error),
    };
    // CDP may replay toolsAdded immediately after the enable response.
    ingest_queued(session, sid.as_deref(), &mut state);
    if !available {
        state.completeness.unavailable("webmcp_tools");
    } else if input.observation_ms > 0 {
        session
            .connection
            .collect_for(Duration::from_millis(input.observation_ms as u64))
            .await?;
    }
    ingest_queued(session, sid.as_deref(), &mut state);
    let final_tree = send(session, "Page.getFrameTree", json!({})).await?;
    ingest_queued(session, sid.as_deref(), &mut state);
    let final_url = main_frame_url(&final_tree);
    if allowed_sanitized_url(final_url.as_deref(), origins).is_none() {
        return Err(browser_error(OPERATION, BrowserFailureReason::TargetNotAllowed, None));
    }
    if final_url != initial_url {
        return Err(browser_error(OPERATION, BrowserFailureReason::TargetChanged, None));
    }
    if !state.transient.is_empty() {
        state.completeness.attach_limited("webmcp_tools");
    }
    Ok(build_result(discovery, target, &frame_tree, origins, &state, &limitations, available))
}

async fn send(session: &mut CdpTargetSession, method: &str, params: Value) -> Result<Map<String, Value>, WebError> {
    let sid = session.session_id.clone();
    if method == "Page.enable" {
        session.connection.send(method, params, sid.as_deref()).await?;
        return Ok(Map::new());
    }
    session.connection.send(method, params, sid.as_deref()).await
}

fn seed_frames(frame_tree: &Map<String, Value>, state: &mut DiscoveryState) {
    for item in capture_frames(frame_tree, &state.origins, Some(&mut state.completeness)) {
        let Some(frame_id) = item.get("frame_id").and_then(Value::as_str) else {
            continue;
        };
        state.frames.insert(
            frame_id.to_string(),
            FrameScope {
                url: item.get("url").and_then(Value::as_str).unwrap_or_default().to_string(),
                origin: item.get("origin").and_then(Value::as_str).unwrap_or_default().to_string(),
                parent_frame_id: item.get("parent_frame_id").and_then(Value::as_str).map(str::to_string),
                loader_id: None,
            },
        );
    }
    let Some(root) = frame_tree.get("frameTree").and_then(record) else {
        return;
    };
    let mut pending = vec![root];
    while let Some(tree) = pending.pop() {
        match tree.get("childFrames") {
            Some(Value::Array(children)) => {
                for child in children.iter().rev() {
                    match child.as_object() {
                        Some(child) => pending.push(child),
                        None => state.completeness.exclude("webmcp_tools", "invalid_protocol_value", Some(1)),
                    }
                }
            }
            Some(_) => state.completeness.exclude("webmcp_tools", "invalid_protocol_value", Some(1)),
            None => {}
        }
        let Some(frame) = tree.get("frame").and_then(record) else {
            continue;
        };
        let Some(frame_id) = frame.get("id").and_then(cdp_str) else {
            continue;
        };
        if let Some(prior) = state.frames.get_mut(frame_id) {
            prior.loader_id = frame.get("loaderId").and_then(cdp_str).map(str::to_string);
        }
    }
}

fn ingest_queued(session: &mut CdpTargetSession, session_id: Option<&str>, state: &mut DiscoveryState) {
    for event in session.connection.take_events() {
        if event.session_id.as_deref() != session_id {
            continue;
        }
        if !ingest_frame_event(&event, state) {
            ingest_webmcp_event(&event, state);
        }
    }
}

fn ingest_frame_event(event: &CdpEvent, state: &mut DiscoveryState) -> bool {
    let Some(params) = event.params.as_object() else {
        return false;
    };
    match event.method.as_str() {
        "Page.frameDetached" => {
            detach_frame(params, state);
            true
        }
        "Page.frameNavigated" => {
            update_frame(params.get("frame").and_then(record), state, true);
            true
        }
        "Page.navigatedWithinDocument" => {
            update_frame(Some(params), state, false);
            true
        }
        _ => false,
    }
}

fn detach_frame(params: &Map<String, Value>, state: &mut DiscoveryState) {
    let Some(frame_id) = params.get("frameId").and_then(cdp_str) else {
        state.completeness.exclude("webmcp_tools", "invalid_protocol_value", Some(1));
        return;
    };
    remove_frame(frame_id, state);
    state.transient.remove(frame_id);
    state.resolved_transient.remove(frame_id);
}

fn update_frame(frame: Option<&Map<String, Value>>, state: &mut DiscoveryState, document_committed: bool) {
    let Some(frame) = frame else {
        state.completeness.exclude("webmcp_tools", "invalid_protocol_value", Some(1));
        return;
    };
    let frame_id = frame.get("id").and_then(cdp_str).or_else(|| frame.get("frameId").and_then(cdp_str));
    let Some(frame_id) = frame_id else {
        state.completeness.exclude("webmcp_tools", "invalid_protocol_value", Some(1));
        return;
    };
    let raw_url = frame.get("url").and_then(cdp_str);
    if is_transient_url(raw_url) {
        if document_committed {
            remove_frame_tools(frame_id, state);
            state.transient.insert(frame_id.to_string());
            state.resolved_transient.remove(frame_id);
        }
        return;
    }
    let Some(sanitized) = allowed_sanitized_url(raw_url, &state.origins) else {
        remove_frame_tools(frame_id, state);
        state.frames.remove(frame_id);
        state.completeness.exclude("webmcp_tools", "out_of_target_scope", Some(1));
        return;
    };
    let Some(origin) = sanitized.origin else {
        remove_frame_tools(frame_id, state);
        state.frames.remove(frame_id);
        state.completeness.exclude("webmcp_tools", "out_of_target_scope", Some(1));
        return;
    };
    let previous = state.frames.get(frame_id);
    let loader_id = frame.get("loaderId").and_then(cdp_str).map(str::to_string);
    if document_committed
        && previous.is_some_and(|prior| {
            prior.url != sanitized.url
                || (loader_id.is_some() && prior.loader_id.is_some() && prior.loader_id != loader_id)
        })
    {
        remove_frame_tools(frame_id, state);
    }
    if document_committed && state.transient.contains(frame_id) {
        state.resolved_transient.insert(frame_id.to_string());
    }
    let parent = parent_frame_id(frame, state.frames.get(frame_id));
    state.frames.insert(
        frame_id.to_string(),
        FrameScope {
            url: sanitized.url,
            origin,
            parent_frame_id: parent,
            loader_id,
        },
    );
}

fn parent_frame_id(frame: &Map<String, Value>, previous: Option<&FrameScope>) -> Option<String> {
    if let Some(id) = frame.get("parentId").and_then(cdp_str) {
        return (!id.is_empty()).then(|| id.to_string());
    }
    previous.and_then(|prior| prior.parent_frame_id.clone())
}

fn is_transient_url(url: Option<&str>) -> bool {
    matches!(url, Some("") | Some("about:blank") | Some("about:srcdoc"))
}

fn remove_frame_tools(frame_id: &str, state: &mut DiscoveryState) {
    state.tools.retain(|_, tool| tool.get("frame_id").and_then(Value::as_str) != Some(frame_id));
}

fn remove_frame(frame_id: &str, state: &mut DiscoveryState) {
    let mut pending = vec![frame_id.to_string()];
    let mut removed = HashSet::new();
    while let Some(current) = pending.pop() {
        if !removed.insert(current.clone()) {
            continue;
        }
        let children: Vec<String> = state
            .frames
            .iter()
            .filter(|(_, frame)| frame.parent_frame_id.as_deref() == Some(current.as_str()))
            .map(|(id, _)| id.clone())
            .collect();
        pending.extend(children);
        state.frames.remove(&current);
    }
    state.tools.retain(|_, tool| {
        tool.get("frame_id")
            .and_then(Value::as_str)
            .is_none_or(|id| !removed.contains(id))
    });
}

fn ingest_webmcp_event(event: &CdpEvent, state: &mut DiscoveryState) {
    if event.method != "WebMCP.toolsAdded" && event.method != "WebMCP.toolsRemoved" {
        return;
    }
    let Some(params) = event.params.as_object() else {
        state.completeness.exclude("webmcp_tools", "invalid_protocol_value", Some(1));
        return;
    };
    let declared = event_tools(params.get("tools"), state);
    if event.method == "WebMCP.toolsRemoved" {
        for tool in declared {
            let name = tool.get("name").and_then(cdp_str);
            let frame_id = tool.get("frameId").and_then(cdp_str);
            let (Some(name), Some(frame_id)) = (name, frame_id) else {
                state.completeness.exclude("webmcp_tools", "invalid_protocol_value", Some(1));
                continue;
            };
            state.tools.retain(|_, existing| {
                !(existing.get("name").and_then(Value::as_str) == Some(name)
                    && existing.get("frame_id").and_then(Value::as_str) == Some(frame_id))
            });
        }
        return;
    }
    for tool in declared {
        if let Some(frame_id) = tool.get("frameId").and_then(cdp_str) {
            if state.transient.contains(frame_id) {
                if !state.resolved_transient.contains(frame_id) {
                    continue;
                }
                state.transient.remove(frame_id);
                state.resolved_transient.remove(frame_id);
            }
        }
        if let Some(normalized) = normalize_tool(&tool, &state.origins, &state.frames, &mut state.completeness) {
            let key = normalized.get("tool_key").and_then(Value::as_str).unwrap_or_default().to_string();
            state.tools.insert(key, normalized);
        }
    }
}

fn event_tools(value: Option<&Value>, state: &mut DiscoveryState) -> Vec<Map<String, Value>> {
    let Some(items) = value.and_then(Value::as_array) else {
        state.completeness.exclude("webmcp_tools", "invalid_protocol_value", Some(1));
        return Vec::new();
    };
    let mut records = Vec::new();
    for item in items {
        match item.as_object() {
            Some(record) => records.push(record.clone()),
            None => state.completeness.exclude("webmcp_tools", "invalid_protocol_value", Some(1)),
        }
    }
    records
}

fn normalize_tool(
    value: &Map<String, Value>,
    origins: &[String],
    frames: &HashMap<String, FrameScope>,
    completeness: &mut CdpCaptureCompleteness,
) -> Option<Value> {
    let frame_id = value.get("frameId").and_then(cdp_str);
    let name = value.get("name").and_then(cdp_str);
    let (Some(frame_id), Some(name)) = (frame_id, name) else {
        completeness.exclude("webmcp_tools", "invalid_protocol_value", Some(1));
        return None;
    };
    let Some(frame) = frames.get(frame_id) else {
        completeness.exclude("webmcp_tools", "out_of_target_scope", Some(1));
        return None;
    };
    if frame.origin.is_empty() {
        completeness.exclude("webmcp_tools", "out_of_target_scope", Some(1));
        return None;
    }
    let schema_raw = value.get("inputSchema");
    let (input_schema, input_schema_sha256) = match schema_raw {
        Some(schema) => match canonical_sha256(schema) {
            Ok(digest) => (schema.clone(), Value::String(digest)),
            Err(_) => {
                completeness.exclude("webmcp_tools", "invalid_protocol_value", Some(1));
                (Value::Null, Value::Null)
            }
        },
        None => {
            completeness.exclude("webmcp_tools", "invalid_protocol_value", Some(1));
            (Value::Null, Value::Null)
        }
    };
    let annotations = value.get("annotations").and_then(record);
    Some(json!({
        "tool_key": tool_key(&frame.url, frame_id, name),
        "name": name,
        "description": value.get("description").and_then(cdp_str).unwrap_or(""),
        "frame_id": frame_id,
        "frame_url": frame.url,
        "owner_origin": frame.origin,
        "declaration_kind": if value.get("backendNodeId").and_then(finite_f64).is_some() { "declarative" } else { "imperative" },
        "input_schema": input_schema,
        "input_schema_sha256": input_schema_sha256,
        "annotations": {
            "read_only": bool_or_null(annotations.and_then(|item| item.get("readOnly"))),
            "untrusted_content": bool_or_null(annotations.and_then(|item| item.get("untrustedContent"))),
            "autosubmit": bool_or_null(annotations.and_then(|item| item.get("autosubmit"))),
        },
        "registration_source": registration_source(value.get("stackTrace").and_then(record), origins),
        "trust": "page-declared-untrusted",
    }))
}

fn registration_source(stack: Option<&Map<String, Value>>, origins: &[String]) -> Value {
    let frame = stack
        .and_then(|stack| stack.get("callFrames"))
        .and_then(Value::as_array)
        .and_then(|frames| frames.first())
        .and_then(record);
    let Some(frame) = frame else {
        return Value::Null;
    };
    let Some(url) = allowed_sanitized_url(frame.get("url").and_then(cdp_str), origins) else {
        return Value::Null;
    };
    json!({
        "url": url.url,
        "line": integer_or_null(frame.get("lineNumber")),
        "column": integer_or_null(frame.get("columnNumber")),
    })
}

fn bool_or_null(value: Option<&Value>) -> Value {
    match value {
        Some(Value::Bool(flag)) => Value::Bool(*flag),
        _ => Value::Null,
    }
}

fn integer_or_null(value: Option<&Value>) -> Value {
    match value.and_then(finite_f64) {
        Some(number) => Value::from(number.trunc().max(0.0) as i64),
        None => Value::Null,
    }
}

fn tool_key(frame_url: &str, frame_id: &str, name: &str) -> String {
    let composite = serde_json::to_string(&vec![frame_url, frame_id, name]).unwrap_or_default();
    format!("webmcp_{}", hex::encode(Sha256::digest(composite.as_bytes())))
}

fn build_result(
    discovery: &CdpEndpointDiscovery,
    target: &CdpEndpointTarget,
    frame_tree: &Map<String, Value>,
    origins: &[String],
    state: &DiscoveryState,
    limitations: &[String],
    available: bool,
) -> Value {
    let target_url = main_frame_url(frame_tree).unwrap_or_else(|| target.url.clone());
    let sanitized = allowed_sanitized_url(Some(&target_url), origins);
    let mut items: Vec<Value> = state.tools.values().cloned().collect();
    items.sort_by(|left, right| {
        left.get("tool_key")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .cmp(right.get("tool_key").and_then(Value::as_str).unwrap_or_default())
    });
    json!({
        "browser": discovery.version.to_json(),
        "target": {
            "target_id": target.id,
            "url": sanitized.as_ref().map(|url| url.url.as_str()).unwrap_or("[unsupported-url]"),
            "origin": sanitized.and_then(|url| url.origin).unwrap_or_default(),
        },
        "status": if available { "available" } else { "unavailable" },
        "tools": {
            "total": items.len() as i64 + state.completeness.dropped_total(),
            "items": items,
        },
        "completeness": state.completeness.snapshot(),
        "limitations": limitations,
    })
}
