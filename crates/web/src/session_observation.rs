//! `observe_web_session` (port of REA browser/CdpObservationSession.ts).
//!
//! Records navigation metadata only. Headers, bodies, cookies, and payloads
//! are not part of this tool's timeline.

use std::time::Duration;

use serde_json::{json, Map, Value};
use tracewise_domain::evidence::Evidence;

use crate::browser_observation::{
    browser_error, create_browser_evidence, parse_browser_scope, sanitize_browser_url,
    trimmed_string_field, BrowserFailureReason, BrowserScope,
};
use crate::cdp_completeness::CdpCaptureCompleteness;
use crate::cdp_connection::{close_cdp_target_session, open_cdp_target_session, CdpEvent, CdpTargetSession};
use crate::cdp_documents::{main_frame_id, main_frame_url};
use crate::cdp_endpoint::{discover_cdp_endpoint, CdpEndpointDiscovery, CdpEndpointTarget};
use crate::cdp_values::{allowed_url, cdp_str, finite_f64, is_http_url, record};
use crate::error::WebError;

const OPERATION: &str = "observe_web_session";
const CLEANUP_DOMAINS: [&str; 4] = ["Network", "Debugger", "Runtime", "Page"];
const MAX_SAFE_INT: i64 = 9_007_199_254_740_991;

#[derive(Debug, Clone)]
pub struct ObserveWebSessionInput {
    pub scope: BrowserScope,
    pub target_id: String,
    pub observation_ms: i64,
}

pub fn parse_observe_web_session_input(args: &Value) -> Result<ObserveWebSessionInput, WebError> {
    let (scope, object) = parse_browser_scope(OPERATION, args, &["target_id", "observation_ms"])?;
    let target_id = trimmed_string_field(OPERATION, &object, "target_id")?;
    let observation_ms = match object.get("observation_ms") {
        None => 10_000,
        Some(value) => {
            let Some(number) = value.as_i64().or_else(|| value.as_u64().and_then(|n| i64::try_from(n).ok())) else {
                return Err(input_error("observation_ms", "observation_ms must be an integer"));
            };
            if !(1..=MAX_SAFE_INT).contains(&number) {
                return Err(input_error("observation_ms", "observation_ms is outside the accepted range"));
            }
            number
        }
    };
    Ok(ObserveWebSessionInput {
        scope,
        target_id,
        observation_ms,
    })
}

pub async fn observe_web_session(input: &ObserveWebSessionInput) -> Result<Evidence, WebError> {
    let discovery = discover_cdp_endpoint(&input.scope.cdp_endpoint, OPERATION).await?;
    let (target, origins) = authorize_target(&discovery, input)?;
    let mut session = open_cdp_target_session(&discovery, target, OPERATION).await?;
    let observed = observe(&mut session, &discovery, target, input, &origins).await;
    close_cdp_target_session(session, &CLEANUP_DOMAINS).await;
    let result = observed?;
    create_browser_evidence(
        OPERATION,
        "rea.web-observation-session",
        json!({
            "cdp_endpoint": input.scope.cdp_endpoint,
            "allowed_origins": origins,
            "target_id": input.target_id,
            "observation_ms": input.observation_ms,
        }),
        result,
    )
}

async fn observe(
    session: &mut CdpTargetSession,
    discovery: &CdpEndpointDiscovery,
    target: &CdpEndpointTarget,
    input: &ObserveWebSessionInput,
    origins: &[String],
) -> Result<Value, WebError> {
    let initial = session
        .connection
        .send("Page.getFrameTree", json!({}), session.session_id.as_deref())
        .await?;
    let initial_url = main_frame_url(&initial).unwrap_or_default();
    if allowed_url(Some(initial_url.as_str()), origins).is_none() {
        return Err(browser_error(OPERATION, BrowserFailureReason::TargetNotAllowed, None));
    }
    let main_frame = main_frame_id(&initial).ok_or_else(|| browser_error(OPERATION, BrowserFailureReason::ProtocolError, None))?;
    let mut capture = TimelineCapture::new(origins.to_vec(), main_frame, initial_url.clone());
    let session_id = session.session_id.clone();
    session
        .connection
        .send("Page.enable", json!({}), session_id.as_deref())
        .await?;
    ingest(session, &mut capture);
    session
        .connection
        .send("Network.enable", json!({}), session_id.as_deref())
        .await?;
    ingest(session, &mut capture);
    session
        .connection
        .send("Page.setLifecycleEventsEnabled", json!({ "enabled": true }), session_id.as_deref())
        .await?;
    ingest(session, &mut capture);
    let armed_at = iso_now();
    let mut end_reason = wait_for_window(session, &mut capture, input.observation_ms).await?;
    if end_reason == "window_elapsed" {
        end_reason = capture_final_url(session, &mut capture, origins).await?.to_string();
    }
    let initial_public = allowed_url(Some(initial_url.as_str()), origins)
        .map(|url| url.url)
        .unwrap_or_default();
    Ok(json!({
        "browser": discovery.version.to_json(),
        "target": {
            "target_id": target.id,
            "initial_url": initial_public,
            "final_url": capture.final_url,
        },
        "window": {
            "armed_at": armed_at,
            "ended_at": iso_now(),
            "requested_ms": input.observation_ms,
            "end_reason": end_reason,
        },
        "timeline": capture.timeline,
        "completeness": capture.completeness.snapshot(),
        "limitations": [
            "The timeline begins after REA attaches; earlier navigation and network activity is unavailable.",
            "Only navigation metadata is retained; headers, bodies, cookies, console values, and payloads are not captured by this tool.",
            "An out-of-policy destination ends collection immediately and is recorded without its URL.",
        ],
    }))
}

struct TimelineCapture {
    timeline: Vec<Value>,
    completeness: CdpCaptureCompleteness,
    final_url: Option<String>,
    sequence: i64,
    pending_reload: bool,
    end_reason: Option<String>,
    allowed_origins: Vec<String>,
    main_frame_id: String,
}

impl TimelineCapture {
    fn new(allowed_origins: Vec<String>, main_frame_id: String, initial_url: String) -> Self {
        let final_url = allowed_url(Some(initial_url.as_str()), &allowed_origins).map(|url| url.url);
        Self {
            timeline: Vec::new(),
            completeness: CdpCaptureCompleteness::new(&["timeline"]),
            final_url,
            sequence: 0,
            pending_reload: false,
            end_reason: None,
            allowed_origins,
            main_frame_id,
        }
    }

    fn ingest(&mut self, event: CdpEvent) {
        if self.end_reason.is_some() {
            return;
        }
        let Some(params) = event.params.as_object().cloned() else {
            return;
        };
        match event.method.as_str() {
            "Page.frameRequestedNavigation" => self.navigation_requested(&params),
            "Page.frameNavigated" => self.navigation_committed(&params),
            "Page.navigatedWithinDocument" => self.same_document(&params),
            "Network.requestWillBeSent" => self.redirect(&params),
            "Network.loadingFailed" => self.loading_failed(&params),
            "Page.lifecycleEvent" => self.lifecycle(&params),
            "Inspector.targetCrashed" | "Target.detachedFromTarget" => self.target_terminated(),
            _ => {}
        }
    }

    fn target_terminated(&mut self) {
        if self.end_reason.is_some() {
            return;
        }
        self.add("target_terminated", &Map::new(), None, None, Some("target_terminated"));
        self.end_reason = Some("target_terminated".to_string());
    }

    fn navigation_requested(&mut self, params: &Map<String, Value>) {
        if params.get("frameId").and_then(cdp_str) != Some(self.main_frame_id.as_str()) {
            return;
        }
        let reason = safe_detail(params.get("reason"));
        self.pending_reload = reason.as_deref() == Some("reload");
        self.add(
            "navigation_requested",
            params,
            params.get("url").and_then(cdp_str),
            None,
            reason.as_deref(),
        );
    }

    fn navigation_committed(&mut self, params: &Map<String, Value>) {
        let Some(frame) = params.get("frame").and_then(record) else {
            return;
        };
        if frame.get("id").and_then(cdp_str) != Some(self.main_frame_id.as_str()) {
            return;
        }
        let raw_url = frame.get("url").and_then(cdp_str);
        let kind = if self.pending_reload { "same_origin_reload" } else { "navigation_committed" };
        self.pending_reload = false;
        let mut enriched = params.clone();
        if let Some(id) = frame.get("id") {
            enriched.insert("frameId".to_string(), id.clone());
        }
        if let Some(loader) = frame.get("loaderId") {
            enriched.insert("loaderId".to_string(), loader.clone());
        }
        self.add(kind, &enriched, raw_url, None, safe_detail(frame.get("transitionType")).as_deref());
        self.apply_destination(raw_url);
    }

    fn same_document(&mut self, params: &Map<String, Value>) {
        if params.get("frameId").and_then(cdp_str) != Some(self.main_frame_id.as_str()) {
            return;
        }
        let raw_url = params.get("url").and_then(cdp_str);
        self.add("same_document_navigation", params, raw_url, None, None);
        self.apply_destination(raw_url);
    }

    fn redirect(&mut self, params: &Map<String, Value>) {
        let resource_type = params.get("type").and_then(cdp_str);
        if resource_type.is_some_and(|kind| kind != "Document") {
            return;
        }
        if params.get("frameId").and_then(cdp_str) != Some(self.main_frame_id.as_str())
            || params.get("redirectResponse").and_then(record).is_none()
        {
            return;
        }
        let raw_url = params.get("request").and_then(record).and_then(|request| request.get("url")).and_then(cdp_str);
        self.add(
            "redirect",
            params,
            raw_url,
            params.get("requestId").and_then(cdp_str),
            None,
        );
        if scoped(raw_url, &self.allowed_origins).0 != "approved" {
            self.completeness.exclude("timeline", "out_of_target_scope", Some(1));
            self.end_reason = Some("target_left_scope".to_string());
        }
    }

    fn loading_failed(&mut self, params: &Map<String, Value>) {
        if let Some(frame) = params.get("frameId").and_then(cdp_str) {
            if frame != self.main_frame_id {
                return;
            }
        }
        self.add(
            "load_failed",
            params,
            None,
            params.get("requestId").and_then(cdp_str),
            safe_network_error(params.get("errorText")).as_deref(),
        );
    }

    fn lifecycle(&mut self, params: &Map<String, Value>) {
        if params.get("frameId").and_then(cdp_str) != Some(self.main_frame_id.as_str()) {
            return;
        }
        self.add("lifecycle", params, None, None, safe_detail(params.get("name")).as_deref());
    }

    fn apply_destination(&mut self, raw_url: Option<&str>) {
        let (scope, url) = scoped(raw_url, &self.allowed_origins);
        if scope == "approved" {
            self.final_url = url;
        } else {
            self.final_url = None;
            self.completeness.exclude("timeline", "out_of_target_scope", Some(1));
            self.end_reason = Some("target_left_scope".to_string());
        }
    }

    fn add(
        &mut self,
        kind: &str,
        params: &Map<String, Value>,
        raw_url: Option<&str>,
        request_id: Option<&str>,
        detail: Option<&str>,
    ) {
        let (scope, url) = match raw_url {
            Some(raw) => {
                let (scope, url) = scoped(Some(raw), &self.allowed_origins);
                (Some(scope), url)
            }
            None => (None, None),
        };
        self.sequence += 1;
        let timestamp = finite_f64(params.get("timestamp").unwrap_or(&Value::Null)).unwrap_or(0.0).max(0.0);
        self.timeline.push(json!({
            "sequence": self.sequence,
            "type": kind,
            "timestamp": timestamp,
            "frame_id": params.get("frameId").and_then(cdp_str),
            "loader_id": params.get("loaderId").and_then(cdp_str),
            "request_id": request_id,
            "url": url,
            "destination_scope": scope,
            "detail": detail,
        }));
    }
}

async fn wait_for_window(
    session: &mut CdpTargetSession,
    capture: &mut TimelineCapture,
    observation_ms: i64,
) -> Result<String, WebError> {
    let mut remaining = Duration::from_millis(observation_ms.max(1) as u64);
    while !remaining.is_zero() {
        if capture.end_reason.is_some() {
            break;
        }
        let slice = remaining.min(Duration::from_millis(200));
        if let Err(error) = session.connection.collect_for(slice).await {
            if is_disconnected(&error) {
                capture.target_terminated();
                break;
            }
            return Err(error);
        }
        ingest(session, capture);
        remaining = remaining.saturating_sub(slice);
    }
    Ok(capture
        .end_reason
        .clone()
        .unwrap_or_else(|| "window_elapsed".to_string()))
}

async fn capture_final_url(
    session: &mut CdpTargetSession,
    capture: &mut TimelineCapture,
    origins: &[String],
) -> Result<&'static str, WebError> {
    let result = session
        .connection
        .send("Page.getFrameTree", json!({}), session.session_id.as_deref())
        .await?;
    ingest(session, capture);
    let url = main_frame_url(&result);
    if url.as_deref().is_some_and(|value| allowed_url(Some(value), origins).is_some()) {
        if let Some(url) = url.as_deref() {
            let destination = allowed_url(Some(url), origins).map(|item| item.url);
            capture.final_url = destination;
        }
        return Ok("window_elapsed");
    }
    capture.final_url = None;
    capture.completeness.exclude(
        "timeline",
        if url.is_none() { "invalid_protocol_value" } else { "out_of_target_scope" },
        Some(1),
    );
    Ok("target_left_scope")
}

fn ingest(session: &mut CdpTargetSession, capture: &mut TimelineCapture) {
    let session_id = session.session_id.clone();
    for event in session.connection.take_events() {
        if event_matches(&event, session_id.as_deref()) {
            capture.ingest(event);
        }
    }
}

fn event_matches(event: &CdpEvent, session_id: Option<&str>) -> bool {
    if event.method == "Target.detachedFromTarget" {
        return session_id.is_some()
            && event.params.get("sessionId").and_then(Value::as_str) == session_id;
    }
    event.session_id.as_deref() == session_id
}

fn scoped(value: Option<&str>, allowed_origins: &[String]) -> (&'static str, Option<String>) {
    if let Some(allowed) = allowed_url(value, allowed_origins) {
        return ("approved", Some(allowed.url));
    }
    if value.is_some_and(is_http_url) {
        ("outside_policy", None)
    } else {
        ("unsupported", None)
    }
}

fn safe_detail(value: Option<&Value>) -> Option<String> {
    let detail = value.and_then(cdp_str)?.to_ascii_lowercase();
    if !detail.is_empty()
        && detail.len() <= 100
        && detail.chars().all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '.' | ':' | '-'))
    {
        Some(detail)
    } else {
        None
    }
}

fn safe_network_error(value: Option<&Value>) -> Option<String> {
    let error = value.and_then(cdp_str)?;
    if error.starts_with("net::ERR_") && error.len() <= "net::ERR_".len() + 100 && error[9..].chars().all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
    {
        Some(error.to_string())
    } else {
        None
    }
}

fn is_disconnected(error: &WebError) -> bool {
    matches!(
        error,
        WebError::BrowserObservation { reason, .. } if reason == "disconnected"
    )
}

fn authorize_target<'a>(
    discovery: &'a CdpEndpointDiscovery,
    input: &ObserveWebSessionInput,
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

fn input_error(path: &str, message: &str) -> WebError {
    WebError::Input {
        operation: OPERATION.to_string(),
        path: vec![path.to_string()],
        reason: "invalid_value".to_string(),
        message: message.to_string(),
    }
}

fn iso_now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}
