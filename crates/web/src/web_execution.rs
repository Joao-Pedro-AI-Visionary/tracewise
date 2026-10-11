//! `observe_web_execution` (port of REA browser/execution/CdpExecutionCapture.ts).
//!
//! One finite window of precise coverage and request initiators. The page stays
//! externally owned: counters reset and optimized code is disabled only until
//! `Profiler.stopPreciseCoverage` confirms cleanup.

use std::time::Duration;

use serde_json::{json, Map, Value};
use tracewise_domain::evidence::Evidence;

use crate::browser_observation::{browser_error, create_browser_evidence, BrowserFailureReason, BrowserScope};
use crate::cdp_connection::CdpEvent;
use crate::cdp_values::{cdp_str, record, safe_integer};
use crate::error::WebError;
use crate::runtime_cdp::{collect_for, iso_now, optional_i64, parse_scope, require_target_id, RuntimeAttach};

const OPERATION: &str = "observe_web_execution";
const MAX_OBSERVATION_MS: i64 = 2_147_483_647;

pub struct ObserveWebExecutionInput {
    pub scope: BrowserScope,
    pub target_id: String,
    pub observation_ms: i64,
}

pub fn parse_observe_web_execution_input(args: &Value) -> Result<ObserveWebExecutionInput, WebError> {
    let (scope, object) = parse_scope(OPERATION, args, &["target_id", "observation_ms"])?;
    let target_id = require_target_id(OPERATION, &object)?;
    let observation_ms = optional_i64(OPERATION, &object, "observation_ms", 1, MAX_OBSERVATION_MS)?.unwrap_or(10_000);
    Ok(ObserveWebExecutionInput {
        scope,
        target_id,
        observation_ms,
    })
}

struct RawSite {
    script_id: String,
    url: Option<String>,
    line_number: i64,
    column_number: Option<i64>,
    function_name: Option<String>,
}

struct LiveRequest {
    request_id: String,
    url: String,
    method: String,
    timestamp_seconds: f64,
    initiator_type: String,
    reported_initiator: Value,
    callsites: Vec<RawSite>,
    async_parent_ids: Vec<Value>,
}

pub async fn observe_web_execution(input: &ObserveWebExecutionInput) -> Result<Evidence, WebError> {
    let mut attach = RuntimeAttach::open(OPERATION, &input.scope, &input.target_id).await?;
    let outcome = capture(&mut attach, input).await;
    attach.close(None).await;
    let result = outcome?;
    create_browser_evidence(OPERATION, "rea.observe-web-execution", parameters(input), result)
}

async fn capture(attach: &mut RuntimeAttach, input: &ObserveWebExecutionInput) -> Result<Value, WebError> {
    for domain in ["Page", "Runtime", "Debugger", "Network", "Profiler"] {
        attach.enable(domain).await?;
    }
    attach.assert_document().await?;
    attach.precise_coverage_active = true;
    let started = attach
        .command(
            "Profiler.startPreciseCoverage",
            json!({ "callCount": true, "detailed": true, "allowTriggeredUpdates": false }),
        )
        .await?;
    let started_seconds = started
        .get("timestamp")
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite() && *value >= 0.0)
        .ok_or_else(|| browser_error(OPERATION, BrowserFailureReason::ProtocolError, None))?;

    let mut requests = Vec::new();
    let mut excluded_requests = 0_i64;
    let mut request_bytes = 0_usize;
    let mut request_failure: Option<String> = None;
    let armed_at = iso_now();
    let (end_reason, ended_at) = wait_window(
        attach,
        input.observation_ms,
        &mut requests,
        &mut excluded_requests,
        &mut request_bytes,
        &mut request_failure,
    )
    .await?;
    if let Some(message) = request_failure {
        return Err(browser_error(OPERATION, BrowserFailureReason::PayloadLimit, Some(message)));
    }

    let mut sample = None;
    if end_reason == "window_elapsed" {
        attach.assert_document().await?;
        let raw = attach.command("Profiler.takePreciseCoverage", json!({})).await?;
        sample = Some(raw);
    }
    attach.sources.metadata_open = false;
    attach.sources.check()?;
    let _ = attach.command("Profiler.stopPreciseCoverage", json!({})).await?;
    attach.precise_coverage_active = false;

    let mut ids = attach.sources.main_script_ids();
    for request in &requests {
        for site in &request.callsites {
            if !site.script_id.is_empty() {
                ids.push(site.script_id.clone());
            }
        }
    }
    let sources = attach.sources.read(&mut attach.session, &ids).await?;
    if end_reason == "window_elapsed" {
        attach.assert_document().await?;
    }
    let main_scripts = attach.sources.main_script_ids();
    let (coverage, sampled_seconds, reported_ids) = match sample {
        Some(raw) => normalize_coverage(attach, &raw)?,
        None => (
            json!({
                "state": "unavailable",
                "reason": format!("The observation ended with {end_reason}; no complete final precise-coverage sample was retained."),
                "offset_units": "utf16-code-units",
                "end_offset": "exclusive",
                "scripts": [],
                "excluded_scripts": 0,
            }),
            None,
            Vec::new(),
        ),
    };
    let not_reported: Vec<String> = main_scripts
        .iter()
        .filter(|id| !reported_ids.iter().any(|reported| reported == *id))
        .cloned()
        .collect();
    let request_items = project_requests(attach, &requests);

    Ok(json!({
        "browser": attach.document.browser,
        "target": attach.target_json(),
        "window": {
            "armed_at": armed_at,
            "ended_at": ended_at,
            "requested_ms": input.observation_ms,
            "end_reason": end_reason,
            "producer_started_seconds": started_seconds,
            "producer_sampled_seconds": sampled_seconds,
        },
        "coverage": coverage,
        "requests": request_items,
        "excluded_requests": excluded_requests,
        "script_inventory": {
            "main_document_scripts": main_scripts.len() as i64,
            "not_reported_script_ids": not_reported,
            "coverage_absence": "unknown",
        },
        "sources": sources,
        "instrumentation": {
            "resets_execution_counters": true,
            "disables_optimized_execution": true,
            "takes_one_resetting_sample": sampled_seconds.is_some(),
            "executes_selected_code": false,
            "cleanup": "confirmed",
            "page_ownership": "external",
        },
        "limitations": EXECUTION_LIMITATIONS,
    }))
}

async fn wait_window(
    attach: &mut RuntimeAttach,
    observation_ms: i64,
    requests: &mut Vec<LiveRequest>,
    excluded_requests: &mut i64,
    request_bytes: &mut usize,
    request_failure: &mut Option<String>,
) -> Result<(&'static str, String), WebError> {
    let mut remaining = Duration::from_millis(observation_ms as u64);
    let slice = Duration::from_millis(50);
    let mut end_reason: Option<&'static str> = None;
    while !remaining.is_zero() && end_reason.is_none() {
        let step = remaining.min(slice);
        match collect_for(attach, step).await {
            Ok(()) => {}
            Err(error) if is_disconnected(&error) => {
                end_reason = Some("target_terminated");
                break;
            }
            Err(error) => return Err(error),
        }
        remaining = remaining.saturating_sub(step);
        for event in attach.drain_events() {
            if end_reason.is_none() {
                ingest_request(
                    attach,
                    &event,
                    requests,
                    excluded_requests,
                    request_bytes,
                    request_failure,
                );
            }
            if end_reason.is_none() {
                if let Some(reason) = terminal_reason(&event, &attach.document.frame_id) {
                    end_reason = Some(reason);
                }
            }
        }
        attach.sources.check()?;
    }
    Ok((end_reason.unwrap_or("window_elapsed"), iso_now()))
}

fn is_disconnected(error: &WebError) -> bool {
    matches!(
        error,
        WebError::BrowserObservation { reason, .. } if reason == "disconnected"
    )
}

fn terminal_reason(event: &CdpEvent, frame_id: &str) -> Option<&'static str> {
    match event.method.as_str() {
        "Target.detachedFromTarget" | "Inspector.targetCrashed" => Some("target_terminated"),
        "Runtime.executionContextsCleared" => Some("document_changed"),
        "Page.frameNavigated" => {
            let main = event
                .params
                .get("frame")
                .and_then(record)
                .is_some_and(|frame| !frame.contains_key("parentId"));
            main.then_some("document_changed")
        }
        "Page.frameDetached" => {
            (event.params.get("frameId").and_then(cdp_str) == Some(frame_id)).then_some("document_changed")
        }
        _ => None,
    }
}

fn ingest_request(
    attach: &RuntimeAttach,
    event: &CdpEvent,
    requests: &mut Vec<LiveRequest>,
    excluded_requests: &mut i64,
    request_bytes: &mut usize,
    request_failure: &mut Option<String>,
) {
    if event.method != "Network.requestWillBeSent" || request_failure.is_some() {
        return;
    }
    let params = &event.params;
    let Some(request_id) = params.get("requestId").and_then(cdp_str).filter(|id| !id.is_empty()) else {
        *request_failure = Some("Malformed network request id.".to_string());
        return;
    };
    let Some(request) = params.get("request").and_then(record) else {
        *request_failure = Some("Malformed network request.".to_string());
        return;
    };
    let Some(raw_url) = request.get("url").and_then(cdp_str) else {
        *request_failure = Some("Malformed network request URL.".to_string());
        return;
    };
    let Some(method) = request.get("method").and_then(cdp_str) else {
        *request_failure = Some("Malformed network request method.".to_string());
        return;
    };
    let Some(timestamp) = params.get("timestamp").and_then(Value::as_f64).filter(|n| n.is_finite() && *n >= 0.0) else {
        *request_failure = Some("Malformed network request timestamp.".to_string());
        return;
    };
    let Some(initiator) = params.get("initiator").and_then(record) else {
        *request_failure = Some("Malformed network request initiator.".to_string());
        return;
    };
    let Some(initiator_type) = initiator.get("type").and_then(cdp_str) else {
        *request_failure = Some("Malformed network request initiator type.".to_string());
        return;
    };
    let sanitized = crate::browser_observation::sanitize_browser_url(raw_url);
    let frame_id = params.get("frameId").and_then(cdp_str);
    if frame_id != Some(attach.document.frame_id.as_str())
        || sanitized.origin.as_ref().is_none_or(|origin| !attach.allowed_origins.iter().any(|allowed| allowed == origin))
    {
        *excluded_requests += 1;
        return;
    }
    *request_bytes += params.to_string().len();
    if *request_bytes > 8 * 1024 * 1024 {
        *request_failure = Some("Request initiator evidence exceeds its complete 8 MiB event budget.".to_string());
        return;
    }
    let mut callsites = Vec::new();
    let mut parents = Vec::new();
    if let Some(stack) = initiator.get("stack") {
        walk_stack(stack, &mut callsites, &mut parents, 0);
    }
    if let (Some(url), Some(line)) = (
        initiator.get("url").and_then(cdp_str),
        initiator.get("lineNumber").and_then(nonneg),
    ) {
        callsites.push(RawSite {
            script_id: String::new(),
            url: Some(crate::browser_observation::sanitize_browser_url(url).url),
            line_number: line,
            column_number: initiator.get("columnNumber").and_then(nonneg),
            function_name: None,
        });
    }
    let mut reported = Value::Object(initiator.clone());
    sanitize_initiator(&mut reported, attach);
    requests.push(LiveRequest {
        request_id: request_id.to_string(),
        url: sanitized.url,
        method: method.to_string(),
        timestamp_seconds: timestamp,
        initiator_type: initiator_type.to_string(),
        reported_initiator: reported,
        callsites,
        async_parent_ids: parents,
    });
}

fn walk_stack(stack: &Value, callsites: &mut Vec<RawSite>, parents: &mut Vec<Value>, depth: u32) {
    if depth > 32 {
        return;
    }
    let Some(obj) = stack.as_object() else {
        return;
    };
    if let Some(frames) = obj.get("callFrames").and_then(Value::as_array) {
        for frame in frames {
            let Some(frame) = frame.as_object() else {
                continue;
            };
            callsites.push(RawSite {
                script_id: frame.get("scriptId").and_then(cdp_str).unwrap_or("").to_string(),
                url: frame.get("url").and_then(cdp_str).map(str::to_string),
                line_number: frame.get("lineNumber").and_then(nonneg).unwrap_or(0),
                column_number: frame.get("columnNumber").and_then(nonneg),
                function_name: frame.get("functionName").and_then(cdp_str).map(str::to_string),
            });
        }
    }
    if let Some(parent_id) = obj.get("parentId").and_then(record) {
        if let Some(id) = parent_id.get("id").and_then(cdp_str) {
            parents.push(json!({
                "id": id,
                "debugger_id": parent_id.get("debuggerId").and_then(cdp_str),
            }));
        }
    }
    if let Some(parent) = obj.get("parent") {
        walk_stack(parent, callsites, parents, depth + 1);
    }
}

fn sanitize_initiator(value: &mut Value, attach: &RuntimeAttach) {
    let Some(obj) = value.as_object_mut() else {
        return;
    };
    if let Some(url) = obj.get("url").and_then(cdp_str).map(str::to_string) {
        obj.insert(
            "url".to_string(),
            Value::String(crate::browser_observation::sanitize_browser_url(&url).url),
        );
    }
    if obj.contains_key("stack") {
        let mut stack = obj.get("stack").cloned().unwrap_or(Value::Null);
        sanitize_stack(&mut stack, attach, 0);
        obj.insert("stack".to_string(), stack);
    }
}

fn sanitize_stack(stack: &mut Value, attach: &RuntimeAttach, depth: u32) {
    if depth > 32 || !stack.is_object() {
        return;
    }
    if let Some(frames) = stack.get_mut("callFrames").and_then(Value::as_array_mut) {
        for frame in frames.iter_mut() {
            let Some(map) = frame.as_object_mut() else {
                continue;
            };
            let script_id = map.get("scriptId").and_then(cdp_str).unwrap_or("").to_string();
            if let Some(url) = map.get("url").and_then(cdp_str).map(str::to_string) {
                map.insert("url".to_string(), Value::String(attach.sources.source_url(&script_id, &url)));
            }
        }
    }
    let parent = stack.get("parent").cloned();
    if let Some(mut parent) = parent {
        sanitize_stack(&mut parent, attach, depth + 1);
        if let Some(obj) = stack.as_object_mut() {
            obj.insert("parent".to_string(), parent);
        }
    }
}

fn project_requests(attach: &RuntimeAttach, requests: &[LiveRequest]) -> Vec<Value> {
    requests
        .iter()
        .map(|request| {
            let callsites: Vec<Value> = request
                .callsites
                .iter()
                .map(|site| {
                    attach.sources.location(
                        &site.script_id,
                        site.url.as_deref(),
                        site.line_number,
                        site.column_number,
                        site.function_name.as_deref(),
                    )
                })
                .collect();
            json!({
                "request_id": request.request_id,
                "url": request.url,
                "method": request.method,
                "timestamp_seconds": request.timestamp_seconds,
                "initiator_type": request.initiator_type,
                "reported_initiator": request.reported_initiator,
                "callsites": callsites,
                "async_parent_ids": request.async_parent_ids,
                "causal_attribution": "unknown",
            })
        })
        .collect()
}

fn normalize_coverage(
    attach: &RuntimeAttach,
    raw: &Map<String, Value>,
) -> Result<(Value, Option<f64>, Vec<String>), WebError> {
    let timestamp = raw
        .get("timestamp")
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite() && *value >= 0.0)
        .ok_or_else(|| browser_error(OPERATION, BrowserFailureReason::ProtocolError, None))?;
    let entries = raw
        .get("result")
        .and_then(Value::as_array)
        .ok_or_else(|| browser_error(OPERATION, BrowserFailureReason::ProtocolError, None))?;
    let mut scripts = Vec::new();
    let mut excluded = 0_i64;
    let mut reported_ids = Vec::new();
    for entry in entries {
        let Some(entry) = entry.as_object() else {
            return Err(browser_error(OPERATION, BrowserFailureReason::ProtocolError, None));
        };
        let Some(script_id) = entry.get("scriptId").and_then(cdp_str).filter(|id| !id.is_empty()) else {
            return Err(browser_error(OPERATION, BrowserFailureReason::ProtocolError, None));
        };
        reported_ids.push(script_id.to_string());
        if !attach.sources.belongs_to_document(script_id) {
            excluded += 1;
            continue;
        }
        let url = entry.get("url").and_then(cdp_str).unwrap_or("");
        let functions = entry
            .get("functions")
            .and_then(Value::as_array)
            .ok_or_else(|| browser_error(OPERATION, BrowserFailureReason::ProtocolError, None))?;
        let mut projected = Vec::new();
        for function in functions {
            let Some(function) = function.as_object() else {
                return Err(browser_error(OPERATION, BrowserFailureReason::ProtocolError, None));
            };
            let name = function.get("functionName").and_then(cdp_str).unwrap_or("");
            let is_block = function
                .get("isBlockCoverage")
                .and_then(Value::as_bool)
                .ok_or_else(|| browser_error(OPERATION, BrowserFailureReason::ProtocolError, None))?;
            let ranges = function
                .get("ranges")
                .and_then(Value::as_array)
                .ok_or_else(|| browser_error(OPERATION, BrowserFailureReason::ProtocolError, None))?;
            let mut projected_ranges = Vec::new();
            let utf16 = attach.sources.captured_utf16(script_id);
            for range in ranges {
                let Some(range) = range.as_object() else {
                    return Err(browser_error(OPERATION, BrowserFailureReason::ProtocolError, None));
                };
                let start = range
                    .get("startOffset")
                    .and_then(nonneg)
                    .ok_or_else(|| browser_error(OPERATION, BrowserFailureReason::ProtocolError, None))?;
                let end = range
                    .get("endOffset")
                    .and_then(nonneg)
                    .ok_or_else(|| browser_error(OPERATION, BrowserFailureReason::ProtocolError, None))?;
                let count = range
                    .get("count")
                    .and_then(nonneg)
                    .ok_or_else(|| browser_error(OPERATION, BrowserFailureReason::ProtocolError, None))?;
                if end < start || utf16.is_some_and(|units| end > units) {
                    return Err(browser_error(
                        OPERATION,
                        BrowserFailureReason::ProtocolError,
                        Some(format!("Script {script_id} coverage range {start}:{end} is outside retained source bounds.")),
                    ));
                }
                projected_ranges.push(json!({
                    "start_offset": start,
                    "end_offset": end,
                    "count": count,
                    "source_bounds": if utf16.is_some() { "verified" } else { "unknown" },
                }));
            }
            projected.push(json!({
                "name": name,
                "is_block_coverage": is_block,
                "ranges": projected_ranges,
            }));
        }
        scripts.push(json!({
            "script_id": script_id,
            "reported_url": attach.sources.source_url(script_id, url),
            "functions": projected,
        }));
    }
    Ok((
        json!({
            "state": "captured",
            "reason": null,
            "offset_units": "utf16-code-units",
            "end_offset": "exclusive",
            "scripts": scripts,
            "excluded_scripts": excluded,
        }),
        Some(timestamp),
        reported_ids,
    ))
}

fn nonneg(value: &Value) -> Option<i64> {
    safe_integer(value).filter(|number| *number >= 0)
}

fn parameters(input: &ObserveWebExecutionInput) -> Value {
    json!({
        "cdp_endpoint": input.scope.cdp_endpoint,
        "allowed_origins": input.scope.allowed_origins,
        "target_id": input.target_id,
        "observation_ms": input.observation_ms,
    })
}

const EXECUTION_LIMITATIONS: [&str; 11] = [
    "Website source ownership requires the selected main frame and a proven default execution world. Isolated, worker and unknown worlds are excluded from coverage/source joins; referenced producer context metadata is retained.",
    "Precise coverage resets counters, retains execution records and prevents optimized execution until stopped. Timing and JIT behavior are affected.",
    "Only the selected main document's proven frame/context scripts are attributed. Child frames, workers, service workers, WebAssembly and scripts without ownership metadata remain outside this operation.",
    "V8 reports nested function/block ranges and counts, not a chronological trace. Counts must not be summed across overlapping ranges; zero counts concern this instrumented window only.",
    "Previously parsed scripts may be absent from a precise sample. Their source inventory is retained, but missing coverage never means zero execution or an unexecuted function.",
    "A detailed-coverage request does not guarantee block granularity for already compiled functions. When is_block_coverage is false, branch execution is unknown; REA preserves the function-only producer ranges.",
    "The local armed/end clock and backend coverage timestamps are distinct clocks. Counters start when the backend accepts instrumentation, before the armed receipt, and end at the resetting sample after the requested window. Counts may include execution during those command intervals; requests are restricted to the locally armed window.",
    "Source metadata is collected through the final resetting sample, then frozen for source joins. Known identities remain checked during asynchronous source completion; newly parsed scripts after that cutoff are outside this evidence.",
    "Request callsites are producer-reported initiators associated by session script ID; they do not establish UI causality. Unresolved asynchronous parent IDs are retained without fetching their stacks.",
    "Producer hashes and UTF-8 digests of retained text are distinct identities. Inline script locations use reported resource offsets; anonymous/eval/sourceURL names are declarations.",
    "Metadata has an 8 MiB script budget and 8 MiB request budget; complete retained sources have a 32 MiB budget. Resource failures return no partial success. The externally owned browser's CPU and memory are not controlled by REA.",
];
