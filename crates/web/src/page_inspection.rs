//! `inspect_web_page` (port of REA browser/CdpPageCapture.ts and CdpBrowserProvider.inspectPage).
//!
//! The page is not navigated and JavaScript is not evaluated. Network capture
//! keeps an allowlisted metadata projection and drops Cookie / Authorization.

use std::collections::BTreeSet;
use std::time::Duration;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tracewise_domain::canonical::canonical_sha256;
use tracewise_domain::evidence::Evidence;

use crate::browser_observation::{
    browser_error, create_browser_evidence, parse_browser_scope, sanitize_browser_url,
    trimmed_string_field, BrowserFailureReason, BrowserScope,
};
use crate::cdp_connection::{close_cdp_target_session, open_cdp_target_session, CdpEvent, CdpTargetSession};
use crate::cdp_documents::{
    capture_accessibility, capture_dom, capture_frames, capture_resources, frame_document_key, main_frame_id,
    main_frame_url,
};
use crate::cdp_endpoint::{discover_cdp_endpoint, CdpEndpointDiscovery, CdpEndpointTarget};
use crate::cdp_page_events::{CapturedScript, PageEvents};
use crate::cdp_values::{allowed_url, cdp_str, finite_f64, record, records};
use crate::error::WebError;
use crate::web_inventory::{reconcile_captured_script, stable_resource_key, stable_script_key};

const OPERATION: &str = "inspect_web_page";
const CLEANUP_DOMAINS: [&str; 4] = ["Network", "Debugger", "Runtime", "Page"];
const MAX_SAFE_INT: i64 = 9_007_199_254_740_991;
const EXTRAS: &[&str] = &[
    "target_id",
    "observation_ms",
    "include_accessibility_text",
    "include_console_text",
    "include_json_body_shapes",
    "include_websocket_shapes",
    "include_storage_keys",
    "include_storage_fingerprints",
    "include_script_sources",
];

#[derive(Debug, Clone)]
pub struct InspectWebPageInput {
    pub scope: BrowserScope,
    pub target_id: String,
    pub observation_ms: i64,
    pub include_accessibility_text: bool,
    pub include_console_text: bool,
    pub include_json_body_shapes: bool,
    pub include_websocket_shapes: bool,
    pub include_storage_keys: bool,
    pub include_storage_fingerprints: bool,
    pub include_script_sources: bool,
}

pub fn parse_inspect_web_page_input(args: &Value) -> Result<InspectWebPageInput, WebError> {
    let (scope, object) = parse_browser_scope(OPERATION, args, EXTRAS)?;
    let target_id = trimmed_string_field(OPERATION, &object, "target_id")?;
    let observation_ms = optional_i64(&object, "observation_ms", 0, MAX_SAFE_INT)?.unwrap_or(500);
    let include_accessibility_text = optional_bool(&object, "include_accessibility_text")?.unwrap_or(false);
    let include_console_text = optional_bool(&object, "include_console_text")?.unwrap_or(false);
    let include_json_body_shapes = optional_bool(&object, "include_json_body_shapes")?.unwrap_or(false);
    let include_websocket_shapes = optional_bool(&object, "include_websocket_shapes")?.unwrap_or(false);
    let include_storage_keys = optional_bool(&object, "include_storage_keys")?.unwrap_or(false);
    let include_storage_fingerprints = optional_bool(&object, "include_storage_fingerprints")?.unwrap_or(false);
    let include_script_sources = optional_bool(&object, "include_script_sources")?.unwrap_or(false);
    if include_storage_fingerprints && !include_storage_keys {
        return Err(input_error(
            "include_storage_fingerprints",
            "Storage fingerprints require storage key capture",
        ));
    }
    Ok(InspectWebPageInput {
        scope,
        target_id,
        observation_ms,
        include_accessibility_text,
        include_console_text,
        include_json_body_shapes,
        include_websocket_shapes,
        include_storage_keys,
        include_storage_fingerprints,
        include_script_sources,
    })
}

pub async fn inspect_web_page(input: &InspectWebPageInput) -> Result<Evidence, WebError> {
    let discovery = discover_cdp_endpoint(&input.scope.cdp_endpoint, OPERATION).await?;
    let (target, origins) = authorize_target(&discovery, input)?;
    let mut session = open_cdp_target_session(&discovery, target, OPERATION).await?;
    let captured = capture_page(&mut session, &discovery, target, input, &origins).await;
    close_cdp_target_session(session, &CLEANUP_DOMAINS).await;
    let result = captured?;
    create_browser_evidence(OPERATION, "rea.web-page-inspection", parameters(input, &origins), result)
}

async fn capture_page(
    session: &mut CdpTargetSession,
    discovery: &CdpEndpointDiscovery,
    target: &CdpEndpointTarget,
    input: &InspectWebPageInput,
    origins: &[String],
) -> Result<Value, WebError> {
    let started_at = iso_now();
    let mut limitations = vec![
        "Observation starts when REA attaches; prior network and console activity is unavailable.".to_string(),
        "Raw network headers, bodies, cookies, storage values, console objects, and WebSocket payloads are never retained; explicitly requested primitive console text is retained verbatim, while payload captures retain value-free shapes.".to_string(),
        "Source maps are reported only as declarative URLs and are not fetched.".to_string(),
        "URL-less scripts and console events without an allowed source URL are excluded because their origin cannot be proven.".to_string(),
    ];
    let mut events = PageEvents::new(
        origins.to_vec(),
        input.include_console_text,
        input.include_json_body_shapes,
        input.include_websocket_shapes,
    );
    send(session, &mut events, "Page.enable", json!({})).await?;
    let initial = send(session, &mut events, "Page.getFrameTree", json!({})).await?;
    let initial_url = main_frame_url(&initial).unwrap_or_default();
    if allowed_url(Some(initial_url.as_str()), origins).is_none() {
        return Err(fail(BrowserFailureReason::TargetNotAllowed));
    }
    let frame_id = main_frame_id(&initial).ok_or_else(|| fail(BrowserFailureReason::ProtocolError))?;
    // Drop anything observed before the main frame was authorized.
    let _ = session.connection.take_events();
    events.begin_authorized_frame(&frame_id, frame_document_key(&initial));
    send(session, &mut events, "Runtime.enable", json!({})).await?;
    send(session, &mut events, "Debugger.enable", json!({})).await?;
    send(session, &mut events, "Network.enable", json!({})).await?;
    observe_window(session, &mut events, input.observation_ms).await?;
    if events.origin_violation {
        return Err(fail(BrowserFailureReason::TargetNotAllowed));
    }
    let frame_result = send(session, &mut events, "Page.getFrameTree", json!({})).await?;
    let attached_url = main_frame_url(&frame_result).unwrap_or_default();
    let frames = capture_frames(&frame_result, origins, Some(&mut events.completeness));
    if frames.is_empty() {
        return Err(fail(BrowserFailureReason::TargetNotAllowed));
    }
    let resource_result = send(session, &mut events, "Page.getResourceTree", json!({})).await?;
    let raw_resources = capture_resources(&resource_result, origins, &mut events.completeness);
    let mut resources = Vec::new();
    for resource in &raw_resources {
        let mut public = resource.public.clone();
        if let Some(object) = public.as_object_mut() {
            object.insert("resource_key".to_string(), Value::String(stable_resource_key(&resource.public)?));
        }
        resources.push(public);
    }
    resources.sort_by(|left, right| {
        left["resource_key"]
            .as_str()
            .unwrap_or("")
            .cmp(right["resource_key"].as_str().unwrap_or(""))
    });
    let dom_result = send(
        session,
        &mut events,
        "DOMSnapshot.captureSnapshot",
        json!({ "computedStyles": [], "includePaintOrder": false, "includeDOMRects": false }),
    )
    .await?;
    let dom = capture_dom(&dom_result, origins, &mut events.completeness);
    let accessibility = accessibility_for_frames(session, &mut events, input, &frames, &mut limitations).await?;
    let frame_ids: BTreeSet<String> = frames
        .iter()
        .filter_map(|frame| frame["frame_id"].as_str().map(str::to_string))
        .collect();
    let scripts = script_inventory(session, &mut events, input, &raw_resources, &resources, &frame_ids).await?;
    if !input.include_script_sources {
        events
            .completeness
            .exclude("script_sources", "not_approved", Some(events.scripts.len() as i64));
    }
    let workers = capture_workers(session, &mut events, target, origins, &frame_ids, &mut limitations).await?;
    let storage = capture_storage(session, &mut events, input, &attached_url, &mut limitations).await?;
    if !input.include_storage_keys {
        events.completeness.exclude("storage_keys", "not_approved", None);
    }
    let completed = send(session, &mut events, "Page.getFrameTree", json!({})).await?;
    let completed_url = main_frame_url(&completed).unwrap_or_default();
    if events.origin_violation {
        return Err(fail(BrowserFailureReason::TargetNotAllowed));
    }
    if events.navigation_during_capture || completed_url != attached_url {
        return Err(fail(BrowserFailureReason::TargetChanged));
    }
    let mut agent_hints = events.agent_hints.clone();
    agent_hints.extend(dom.agent_hints);
    dedup_hints(&mut agent_hints);
    Ok(json!({
        "browser": discovery.version.to_json(),
        "target": {
            "target_id": target.id,
            "type": target.target_type,
            "title": target.title,
            "url": allowed_url(Some(attached_url.as_str()), origins).map(|url| url.url).unwrap_or_else(|| "[unsupported-url]".to_string()),
            "origin": allowed_url(Some(attached_url.as_str()), origins).and_then(|url| url.origin).unwrap_or_default(),
            "attached": target.attached,
        },
        "capture_window": {
            "started_at": started_at,
            "ended_at": iso_now(),
            "observation_ms": input.observation_ms,
        },
        "completeness": events.completeness.snapshot(),
        "frames": frames,
        "dom": { "total_nodes": dom.total, "nodes": dom.nodes },
        "accessibility": {
            "total_nodes": accessibility.total,
            "text_capture": accessibility.text_capture,
            "nodes": accessibility.nodes,
        },
        "scripts": scripts,
        "resources": resources,
        "network": {
            "requests": events.network_requests(),
            "websocket_events": events.websockets,
            "coverage_started_at": started_at.clone(),
            "prior_activity_available": false,
        },
        "console": {
            "events": events.console,
            "coverage_started_at": started_at,
            "prior_activity_available": false,
        },
        "workers": workers,
        "metadata": {
            "responses": events.response_metadata,
            "dom_urls": dom.urls,
            "agent_hints": agent_hints,
            "excluded_dom_urls": dom.excluded_urls,
            "headers_allowlisted": true,
        },
        "storage": storage,
        "limitations": limitations,
    }))
}

async fn accessibility_for_frames(
    session: &mut CdpTargetSession,
    events: &mut PageEvents,
    input: &InspectWebPageInput,
    frames: &[Value],
    limitations: &mut Vec<String>,
) -> Result<crate::cdp_documents::AxCapture, WebError> {
    let _ = send(session, events, "Accessibility.enable", json!({})).await;
    let mut results = Vec::new();
    let mut unavailable = false;
    for frame in frames {
        let Some(frame_id) = frame["frame_id"].as_str() else {
            continue;
        };
        match optional_send(session, events, "Accessibility.getFullAXTree", json!({ "frameId": frame_id }), limitations).await? {
            Some(result) => results.push(Value::Object(result)),
            None => unavailable = true,
        }
    }
    if unavailable {
        events.completeness.unavailable("accessibility");
    }
    let capture = capture_accessibility(&results, input.include_accessibility_text, results.is_empty() && unavailable);
    if !input.include_accessibility_text {
        events.completeness.exclude(
            "accessibility",
            "not_approved",
            Some(capture.text_capture["excluded_fields"].as_i64().unwrap_or(0)),
        );
    }
    if capture.tree_incomplete {
        events.completeness.truncate("accessibility");
    }
    Ok(capture)
}

async fn script_inventory(
    session: &mut CdpTargetSession,
    events: &mut PageEvents,
    input: &InspectWebPageInput,
    raw_resources: &[crate::cdp_documents::CapturedResource],
    resources: &[Value],
    frame_ids: &BTreeSet<String>,
) -> Result<Value, WebError> {
    let scripts = events.scripts_in_order();
    let total = scripts.len() as i64;
    let raw_pairs: Vec<(String, Value)> = raw_resources
        .iter()
        .map(|resource| (resource.raw_url.clone(), resource.public.clone()))
        .collect();
    let mut drafts = Vec::new();
    for script in scripts {
        let source = if input.include_script_sources {
            script_source(session, events, &script).await?
        } else {
            json!({ "included": false, "reason": "source capture was not selected" })
        };
        let frame_id = script
            .frame_id
            .as_ref()
            .filter(|frame| frame_ids.contains(*frame))
            .cloned();
        let item = json!({
            "frame_id": frame_id,
            "url": script.url,
            "origin": script.origin,
            "cdp_hash": script.hash,
            "length": script.length,
            "is_module": script.is_module,
            "language": script.language,
            "source_map_url": script.source_map_url,
            "resource_reconciliation": reconcile_captured_script(&script.raw_url, &script.url, &raw_pairs, resources)?,
            "source": source,
        });
        drafts.push(item);
    }
    drafts.sort_by(|left, right| {
        let left_key = stable_script_key(left).unwrap_or_default();
        let right_key = stable_script_key(right).unwrap_or_default();
        left_key.cmp(&right_key).then_with(|| source_digest(left).cmp(&source_digest(right))).then_with(|| {
            left["frame_id"].as_str().unwrap_or("").cmp(right["frame_id"].as_str().unwrap_or(""))
        })
    });
    let mut totals = std::collections::BTreeMap::<String, usize>::new();
    let bases: Vec<String> = drafts.iter().map(|item| stable_script_key(item).unwrap_or_default()).collect();
    for base in &bases {
        *totals.entry(base.clone()).or_default() += 1;
    }
    let mut seen = std::collections::BTreeMap::<String, usize>::new();
    let mut items = Vec::new();
    for (item, base) in drafts.into_iter().zip(bases) {
        let occurrence = seen.entry(base.clone()).or_default();
        *occurrence += 1;
        let script_key = if totals.get(&base).copied().unwrap_or(1) == 1 {
            base
        } else {
            format!("{base}_{occurrence}")
        };
        let mut object = item.as_object().cloned().unwrap_or_default();
        object.insert("script_key".to_string(), Value::String(script_key));
        items.push(Value::Object(object));
    }
    Ok(json!({ "total": total, "items": items }))
}

async fn script_source(
    session: &mut CdpTargetSession,
    events: &mut PageEvents,
    script: &CapturedScript,
) -> Result<Value, WebError> {
    let result = send(
        session,
        events,
        "Debugger.getScriptSource",
        json!({ "scriptId": script.script_id }),
    )
    .await?;
    let Some(text) = result.get("scriptSource").and_then(Value::as_str) else {
        return Err(fail(BrowserFailureReason::ProtocolError));
    };
    Ok(json!({ "included": true, "artifact": text_artifact(text) }))
}

fn text_artifact(text: &str) -> Value {
    json!({
        "sha256": hex::encode(Sha256::digest(text.as_bytes())),
        "bytes": text.len() as i64,
        "media_type": "text/javascript",
        "charset": "utf-8",
        "text": text,
    })
}

fn source_digest(item: &Value) -> String {
    let source = &item["source"];
    if source["included"] == true {
        source["artifact"]["sha256"].as_str().unwrap_or("").to_string()
    } else {
        source["reason"].as_str().unwrap_or("").to_string()
    }
}

async fn capture_workers(
    session: &mut CdpTargetSession,
    events: &mut PageEvents,
    target: &CdpEndpointTarget,
    origins: &[String],
    frame_ids: &BTreeSet<String>,
    limitations: &mut Vec<String>,
) -> Result<Vec<Value>, WebError> {
    let result = optional_send(session, events, "Target.getTargets", json!({}), limitations).await?;
    let Some(result) = result else {
        events.completeness.unavailable("workers");
        return Ok(Vec::new());
    };
    let mut items = Vec::new();
    for info in records(result.get("targetInfos").unwrap_or(&Value::Null)) {
        let kind = info.get("type").and_then(cdp_str).unwrap_or("");
        if !kind.contains("worker") {
            continue;
        }
        let opener = info.get("openerId").and_then(cdp_str);
        let parent = info.get("parentFrameId").and_then(cdp_str);
        let related = opener == Some(target.id.as_str()) || parent.is_some_and(|frame| frame_ids.contains(frame));
        if !related {
            events.completeness.exclude("workers", "out_of_target_scope", Some(1));
            continue;
        }
        let raw_url = info.get("url").and_then(cdp_str);
        let Some(url) = allowed_url(raw_url, origins) else {
            let reason = match raw_url {
                None | Some("") => "unattributed_origin",
                Some(url) if crate::cdp_values::is_http_url(url) => "disallowed_origin",
                Some(_) => "unsupported_url",
            };
            events.completeness.exclude("workers", reason, Some(1));
            continue;
        };
        items.push(json!({
            "target_id": info.get("targetId").and_then(cdp_str).unwrap_or(""),
            "type": kind,
            "url": url.url,
            "origin": url.origin,
            "attached": info.get("attached").and_then(Value::as_bool).unwrap_or(false),
            "opener_target_id": opener,
            "parent_frame_id": parent,
        }));
    }
    let _ = session;
    Ok(items)
}

async fn capture_storage(
    session: &mut CdpTargetSession,
    events: &mut PageEvents,
    input: &InspectWebPageInput,
    page_url: &str,
    limitations: &mut Vec<String>,
) -> Result<Value, WebError> {
    let origin = sanitize_browser_url(page_url).origin.unwrap_or_default();
    let quota = optional_send(
        session,
        events,
        "Storage.getUsageAndQuota",
        json!({ "origin": origin }),
        limitations,
    )
    .await?;
    let usage_bytes = quota.as_ref().and_then(|item| item.get("usage")).and_then(finite_f64).map(crate::cdp_values::json_number);
    let quota_bytes = quota.as_ref().and_then(|item| item.get("quota")).and_then(finite_f64).map(crate::cdp_values::json_number);
    let (local_keys, local_items) = if input.include_storage_keys {
        storage_items(session, events, &origin, true, limitations).await?
    } else {
        (Vec::new(), Vec::new())
    };
    let (session_keys, session_items) = if input.include_storage_keys {
        storage_items(session, events, &origin, false, limitations).await?
    } else {
        (Vec::new(), Vec::new())
    };
    let mut fingerprints = Vec::new();
    let mut fingerprints_complete = false;
    if input.include_storage_fingerprints {
        limitations.push(
            "Cookie fingerprints cover cookies applicable to the current main-frame URL, not every path on its origin.".to_string(),
        );
        fingerprints.extend(fingerprint_items("local_storage", &local_items)?);
        fingerprints.extend(fingerprint_items("session_storage", &session_items)?);
        fingerprints.extend(cookie_fingerprints(session, events, page_url, limitations).await?);
        fingerprints.sort_by(|left, right| {
            format!("{}:{}", left["scope"].as_str().unwrap_or(""), left["identity_sha256"].as_str().unwrap_or(""))
                .cmp(&format!("{}:{}", right["scope"].as_str().unwrap_or(""), right["identity_sha256"].as_str().unwrap_or("")))
        });
        fingerprints_complete = fingerprints.iter().all(|item| item["complete"] == true);
    }
    Ok(json!({
        "origin": origin,
        "usage_bytes": usage_bytes.unwrap_or(Value::Null),
        "quota_bytes": quota_bytes.unwrap_or(Value::Null),
        "local_storage_keys": local_keys,
        "session_storage_keys": session_keys,
        "indexed_db_names": [],
        "cache_names": [],
        "content_fingerprints": fingerprints,
        "fingerprint_algorithm": "sha256",
        "fingerprints_complete": fingerprints_complete,
        "values_redacted": true,
    }))
}

async fn storage_items(
    session: &mut CdpTargetSession,
    events: &mut PageEvents,
    origin: &str,
    is_local: bool,
    limitations: &mut Vec<String>,
) -> Result<(Vec<String>, Vec<(String, String)>), WebError> {
    let _ = optional_send(session, events, "DOMStorage.enable", json!({}), limitations).await?;
    let raw = optional_send(
        session,
        events,
        "DOMStorage.getDOMStorageItems",
        json!({ "storageId": { "securityOrigin": origin, "isLocalStorage": is_local } }),
        limitations,
    )
    .await?;
    let Some(entries) = raw.as_ref().and_then(|item| item.get("entries")).and_then(Value::as_array) else {
        return Ok((Vec::new(), Vec::new()));
    };
    let mut keys = Vec::new();
    let mut items = Vec::new();
    for entry in entries {
        let Some(pair) = entry.as_array() else {
            continue;
        };
        let (Some(key), Some(value)) = (pair.first().and_then(Value::as_str), pair.get(1).and_then(Value::as_str)) else {
            continue;
        };
        keys.push(key.to_string());
        items.push((key.to_string(), value.to_string()));
    }
    Ok((keys, items))
}

async fn cookie_fingerprints(
    session: &mut CdpTargetSession,
    events: &mut PageEvents,
    page_url: &str,
    limitations: &mut Vec<String>,
) -> Result<Vec<Value>, WebError> {
    let raw = optional_send(
        session,
        events,
        "Network.getCookies",
        json!({ "urls": [page_url] }),
        limitations,
    )
    .await?;
    let Some(cookies) = raw.as_ref().and_then(|item| item.get("cookies")).and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut items = Vec::new();
    for cookie in cookies.iter().filter_map(record) {
        let (Some(name), Some(value), Some(domain), Some(path)) = (
            cookie.get("name").and_then(cdp_str),
            cookie.get("value").and_then(cdp_str),
            cookie.get("domain").and_then(cdp_str),
            cookie.get("path").and_then(cdp_str),
        ) else {
            continue;
        };
        let identity = json!({
            "domain": domain,
            "name": name,
            "partition_key": cookie.get("partitionKey").cloned().unwrap_or(Value::Null),
            "path": path,
        });
        items.push(json!({
            "scope": "cookie",
            "identity_sha256": canonical_sha256(&identity)?,
            "value_sha256": canonical_sha256(&Value::String(value.to_string()))?,
            "complete": true,
        }));
    }
    Ok(items)
}

fn fingerprint_items(scope: &str, items: &[(String, String)]) -> Result<Vec<Value>, WebError> {
    items
        .iter()
        .map(|(key, value)| {
            Ok(json!({
                "scope": scope,
                "identity_sha256": canonical_sha256(&Value::String(key.clone()))?,
                "value_sha256": canonical_sha256(&Value::String(value.clone()))?,
                "complete": true,
            }))
        })
        .collect()
}

async fn observe_window(session: &mut CdpTargetSession, events: &mut PageEvents, observation_ms: i64) -> Result<(), WebError> {
    let mut remaining = Duration::from_millis(observation_ms.max(0) as u64);
    while !remaining.is_zero() {
        let slice = remaining.min(Duration::from_millis(200));
        session.connection.collect_for(slice).await?;
        ingest(session, events);
        remaining = remaining.saturating_sub(slice);
        if events.origin_violation {
            break;
        }
    }
    Ok(())
}

async fn send(
    session: &mut CdpTargetSession,
    events: &mut PageEvents,
    method: &str,
    params: Value,
) -> Result<Map<String, Value>, WebError> {
    let result = session
        .connection
        .send(method, params, session.session_id.as_deref())
        .await;
    ingest(session, events);
    result
}

async fn optional_send(
    session: &mut CdpTargetSession,
    events: &mut PageEvents,
    method: &str,
    params: Value,
    limitations: &mut Vec<String>,
) -> Result<Option<Map<String, Value>>, WebError> {
    let session_id = if method == "Target.getTargets" {
        None
    } else {
        session.session_id.as_deref()
    };
    let result = session.connection.send(method, params, session_id).await;
    ingest(session, events);
    match result {
        Ok(value) => Ok(Some(value)),
        Err(WebError::CdpCommandRejected { code: -32601, .. }) => {
            limitations.push(format!("{method} was unavailable from this browser target."));
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn ingest(session: &mut CdpTargetSession, events: &mut PageEvents) {
    let session_id = session.session_id.clone();
    for event in session.connection.take_events() {
        if event_in_session(&event, session_id.as_deref()) {
            events.ingest(event);
        }
    }
}

fn event_in_session(event: &CdpEvent, session_id: Option<&str>) -> bool {
    event.session_id.as_deref() == session_id
}

fn authorize_target<'a>(
    discovery: &'a CdpEndpointDiscovery,
    input: &InspectWebPageInput,
) -> Result<(&'a CdpEndpointTarget, Vec<String>), WebError> {
    let target = discovery.targets.iter().find(|candidate| candidate.id == input.target_id).ok_or_else(|| {
        browser_error(
            OPERATION,
            BrowserFailureReason::TargetNotFound,
            Some(format!("Target {} was not found at the selected endpoint.", input.target_id)),
        )
    })?;
    let origin = sanitize_browser_url(&target.url).origin;
    let allowed = &input.scope.allowed_origins;
    match origin {
        Some(origin) if target.target_type == "page" && (allowed.is_empty() || allowed.contains(&origin)) => {
            let scope = if allowed.is_empty() { vec![origin] } else { allowed.clone() };
            Ok((target, scope))
        }
        _ => Err(browser_error(
            OPERATION,
            BrowserFailureReason::TargetNotAllowed,
            Some(format!(
                "Target {} must be an HTTP(S) page in the selected origin scope.",
                input.target_id
            )),
        )),
    }
}

fn parameters(input: &InspectWebPageInput, origins: &[String]) -> Value {
    json!({
        "cdp_endpoint": input.scope.cdp_endpoint,
        "allowed_origins": origins,
        "target_id": input.target_id,
        "observation_ms": input.observation_ms,
        "include_accessibility_text": input.include_accessibility_text,
        "include_console_text": input.include_console_text,
        "include_json_body_shapes": input.include_json_body_shapes,
        "include_websocket_shapes": input.include_websocket_shapes,
        "include_storage_keys": input.include_storage_keys,
        "include_storage_fingerprints": input.include_storage_fingerprints,
        "include_script_sources": input.include_script_sources,
    })
}

fn dedup_hints(hints: &mut Vec<Value>) {
    let mut seen = BTreeSet::new();
    hints.retain(|hint| {
        let key = format!(
            "{}\0{}\0{}",
            hint["mechanism"].as_str().unwrap_or(""),
            hint["declaration"].as_str().unwrap_or(""),
            hint["url"].as_str().unwrap_or("")
        );
        seen.insert(key)
    });
}

pub(crate) fn iso_now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn fail(reason: BrowserFailureReason) -> WebError {
    browser_error(OPERATION, reason, None)
}

fn input_error(path: &str, message: &str) -> WebError {
    WebError::Input {
        operation: OPERATION.to_string(),
        path: vec![path.to_string()],
        reason: "invalid_value".to_string(),
        message: message.to_string(),
    }
}

fn optional_bool(object: &Map<String, Value>, key: &str) -> Result<Option<bool>, WebError> {
    match object.get(key) {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(input_error(key, &format!("{key} must be a boolean"))),
    }
}

fn optional_i64(object: &Map<String, Value>, key: &str, min: i64, max: i64) -> Result<Option<i64>, WebError> {
    match object.get(key) {
        None => Ok(None),
        Some(value) => {
            let Some(number) = value.as_i64().or_else(|| value.as_u64().and_then(|n| i64::try_from(n).ok())) else {
                return Err(input_error(key, &format!("{key} must be an integer")));
            };
            if number < min || number > max {
                return Err(input_error(key, &format!("{key} is outside the accepted range")));
            }
            Ok(Some(number))
        }
    }
}
