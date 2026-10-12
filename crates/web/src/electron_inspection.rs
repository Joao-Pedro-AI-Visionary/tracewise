//! Passive `inspect_electron_page` (port of REA browser/CdpElectronProvider.ts
//! `inspectPage`, browser/CdpElectronInspection.ts, CdpElectronScripts.ts,
//! CdpElectronScriptEvents.ts and CdpElectronWorkers.ts).
//!
//! Sequence (identical to REA): authorize the target (`page` type with an
//! authorized local file URL), `Page.enable` + `Page.getFrameTree` (initial
//! frames), `Runtime.enable` + `Debugger.enable`, wait `observation_ms`, then
//! `Page.getResourceTree`, `DOMSnapshot.captureSnapshot`, optional
//! `Debugger.getScriptSource` per script, `Target.getTargets` (workers, never
//! attached), and a final `Page.getFrameTree` that rejects a navigated page
//! (`target_changed`). Renderer JavaScript is never evaluated.
//!
//! Differences from REA, none visible in the result shape:
//! - CDP events are drained from the shared sequential connection after each
//!   command and after the observation window instead of by a live listener.
//! - Progress notifications are emitted by the server dispatcher, not here.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::Duration;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tracewise_domain::canonical::canonical_sha256;
use tracewise_domain::evidence::Evidence;

use crate::browser_observation::{browser_error, parse_cdp_endpoint, BrowserFailureReason};
use crate::cdp_completeness::CdpCaptureCompleteness;
use crate::cdp_connection::{close_cdp_target_session, open_cdp_target_session, CdpEvent, CdpTargetSession};
use crate::cdp_endpoint::{discover_cdp_endpoint, CdpEndpointDiscovery, CdpEndpointTarget};
use crate::electron_file_scope::authorized_electron_file;
use crate::electron_targets::create_electron_evidence;
use crate::error::WebError;
use crate::page_inspection::iso_now;

const OPERATION: &str = "inspect_electron_page";
const CLEANUP: [&str; 3] = ["Debugger", "Runtime", "Page"];
const DEFAULT_OBSERVATION_MS: i64 = 100;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
/// REA's user message for browser failures without a reason-specific text.
pub const GENERIC_FAILURE_MESSAGE: &str = "Analysis could not complete. Run `rea doctor`, then try again.";

/// Validated `inspect_electron_page` request (REA `inspectElectronPageInputSchema`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectElectronPageInput {
    pub cdp_endpoint: String,
    pub target_id: String,
    pub observation_ms: i64,
    pub include_script_sources: bool,
}

fn input_error(path: &str, message: impl Into<String>) -> WebError {
    WebError::Input {
        operation: OPERATION.to_string(),
        path: if path.is_empty() { vec![] } else { vec![path.to_string()] },
        reason: "invalid_value".to_string(),
        message: message.into(),
    }
}

/// Parse the strict input object, applying REA defaults.
pub fn parse_inspect_electron_page_input(args: &Value) -> Result<InspectElectronPageInput, WebError> {
    let object = args.as_object().ok_or_else(|| input_error("", "Expected an object"))?;
    for key in object.keys() {
        if !["cdp_endpoint", "target_id", "observation_ms", "include_script_sources"].contains(&key.as_str()) {
            return Err(input_error(key, format!("Unrecognized key: \"{key}\"")));
        }
    }
    let endpoint = match object.get("cdp_endpoint") {
        Some(Value::String(s)) if !s.is_empty() => s,
        _ => return Err(input_error("cdp_endpoint", "cdp_endpoint must be a non-empty string")),
    };
    let cdp_endpoint = parse_cdp_endpoint(endpoint).ok_or_else(|| {
        input_error(
            "cdp_endpoint",
            "CDP endpoint must be an explicit-port HTTP URL on 127.0.0.1 or ::1",
        )
    })?;
    let target_id = match object.get("target_id") {
        Some(Value::String(s)) if !s.trim().is_empty() => s.trim().to_string(),
        Some(Value::String(_)) => {
            return Err(input_error("target_id", "Too small: expected string to have >=1 characters"))
        }
        _ => return Err(input_error("target_id", "target_id must be a string")),
    };
    let observation_ms = match object.get("observation_ms") {
        None => DEFAULT_OBSERVATION_MS,
        Some(value) => match value.as_i64().or_else(|| value.as_f64().filter(|n| n.fract() == 0.0).map(|n| n as i64)) {
            Some(n) if n < 0 => {
                return Err(input_error("observation_ms", "Too small: expected number to be >=0"))
            }
            Some(n) if n <= MAX_SAFE_INTEGER => n,
            _ => return Err(input_error("observation_ms", "observation_ms must be a non-negative integer")),
        },
    };
    let include_script_sources = match object.get("include_script_sources") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => {
            return Err(input_error("include_script_sources", "include_script_sources must be a boolean"))
        }
    };
    Ok(InspectElectronPageInput {
        cdp_endpoint,
        target_id,
        observation_ms,
        include_script_sources,
    })
}

fn fail(reason: BrowserFailureReason) -> WebError {
    let detail = match reason {
        BrowserFailureReason::TargetNotAllowed
        | BrowserFailureReason::TargetChanged
        | BrowserFailureReason::ProtocolError
        | BrowserFailureReason::InvalidEndpointResponse
        | BrowserFailureReason::PayloadLimit => Some(GENERIC_FAILURE_MESSAGE.to_string()),
        _ => None,
    };
    browser_error(OPERATION, reason, detail)
}

/// Replace the shared client's fallback text with REA's generic message.
fn rea_message(error: WebError) -> WebError {
    match error {
        WebError::BrowserObservation {
            operation,
            reason,
            code,
            user_message,
        } if user_message.starts_with("Browser observation ") => WebError::BrowserObservation {
            operation,
            reason,
            code,
            user_message: GENERIC_FAILURE_MESSAGE.to_string(),
        },
        other => other,
    }
}

/// Inspect one local file page and wrap the result in Evidence.
pub async fn inspect_electron_page(input: &InspectElectronPageInput) -> Result<Evidence, WebError> {
    let result = inspect_electron_page_result(input).await.map_err(rea_message)?;
    create_electron_evidence(
        OPERATION,
        json!({
            "cdp_endpoint": input.cdp_endpoint,
            "target_id": input.target_id,
            "observation_ms": input.observation_ms,
            "include_script_sources": input.include_script_sources,
        }),
        result,
    )
}

/// Inspect one local file page (provider result before the Evidence envelope).
pub async fn inspect_electron_page_result(input: &InspectElectronPageInput) -> Result<Value, WebError> {
    let discovery = discover_cdp_endpoint(&input.cdp_endpoint, OPERATION).await?;
    let target = authorize_target(&discovery.targets, &input.target_id)?.clone();
    let mut session = open_cdp_target_session(&discovery, &target, OPERATION).await?;
    let mut inspection = Inspection::new(input, &discovery, &target);
    let result = inspection.run(&mut session).await;
    close_cdp_target_session(session, &CLEANUP).await;
    result
}

/// Select the requested target; only `page` targets with authorized file URLs pass.
pub fn authorize_target<'a>(
    targets: &'a [CdpEndpointTarget],
    target_id: &str,
) -> Result<&'a CdpEndpointTarget, WebError> {
    let target = targets
        .iter()
        .find(|target| target.id == target_id)
        .ok_or_else(|| fail(BrowserFailureReason::TargetNotFound))?;
    if target.target_type != "page" || authorized_electron_file(&target.url).is_none() {
        return Err(fail(BrowserFailureReason::TargetNotAllowed));
    }
    Ok(target)
}

/// Script metadata retained from one `Debugger.scriptParsed` event.
#[derive(Debug, Clone, PartialEq)]
pub struct ElectronScriptDraft {
    pub script_id: String,
    pub raw_url: String,
    pub hash: Option<String>,
    pub length: Option<i64>,
    pub is_module: Option<bool>,
    pub language: Option<String>,
    pub execution_context_key: Option<String>,
}

/// Passive event state (REA `ElectronInspectionState`).
pub struct ElectronEventState {
    pub completeness: CdpCaptureCompleteness,
    pub scripts: Vec<ElectronScriptDraft>,
    pub execution_context_frames: HashMap<String, String>,
    pub main_frame_id: Option<String>,
    pub navigation_during_capture: bool,
}

impl Default for ElectronEventState {
    fn default() -> Self {
        Self {
            completeness: CdpCaptureCompleteness::new(&[]),
            scripts: Vec::new(),
            execution_context_frames: HashMap::new(),
            main_frame_id: None,
            navigation_during_capture: false,
        }
    }
}

impl ElectronEventState {
    /// Ingest one event for the inspected session (REA listener body).
    pub fn ingest(&mut self, event: &CdpEvent, session_id: Option<&str>) {
        if event.session_id.as_deref() != session_id {
            return;
        }
        self.ingest_script_event(event);
        if let Some(main) = &self.main_frame_id {
            if navigated_frame_id(event).as_deref() == Some(main.as_str()) {
                self.navigation_during_capture = true;
            }
        }
    }

    fn ingest_script_event(&mut self, event: &CdpEvent) {
        let params = &event.params;
        match event.method.as_str() {
            "Runtime.executionContextsCleared" => self.execution_context_frames.clear(),
            "Runtime.executionContextDestroyed" => {
                if let Some(key) = execution_context_key(params.get("executionContextId")) {
                    self.execution_context_frames.remove(&key);
                }
            }
            "Runtime.executionContextCreated" => {
                let context = params.get("context");
                let key = execution_context_key(context.and_then(|c| c.get("id")));
                let frame_id = context
                    .and_then(|c| c.get("auxData"))
                    .and_then(|aux| aux.get("frameId"))
                    .and_then(Value::as_str);
                if let (Some(key), Some(frame_id)) = (key, frame_id) {
                    self.execution_context_frames.insert(key, frame_id.to_string());
                }
            }
            "Debugger.scriptParsed" => {
                let Some(script_id) = params.get("scriptId").and_then(Value::as_str) else {
                    self.completeness.exclude("scripts", "invalid_protocol_value", Some(1));
                    return;
                };
                let raw_url = match params.get("url").and_then(Value::as_str) {
                    Some(url) if !url.is_empty() => url,
                    _ => {
                        self.completeness.exclude("scripts", "unattributed_origin", Some(1));
                        return;
                    }
                };
                let length = params
                    .get("length")
                    .and_then(safe_number)
                    .filter(|n| n.fract() == 0.0 && *n >= 0.0 && *n <= MAX_SAFE_INTEGER as f64)
                    .map(|n| n as i64);
                self.scripts.push(ElectronScriptDraft {
                    script_id: script_id.to_string(),
                    raw_url: raw_url.to_string(),
                    hash: params.get("hash").and_then(Value::as_str).map(str::to_string),
                    length,
                    is_module: params.get("isModule").and_then(Value::as_bool),
                    language: params.get("scriptLanguage").and_then(Value::as_str).map(str::to_string),
                    execution_context_key: execution_context_key(params.get("executionContextId")),
                });
            }
            _ => {}
        }
    }
}

fn safe_number(value: &Value) -> Option<f64> {
    value.as_f64().filter(|n| n.is_finite())
}

fn execution_context_key(value: Option<&Value>) -> Option<String> {
    let number = value.and_then(safe_number)?;
    (number.fract() == 0.0 && number.abs() <= MAX_SAFE_INTEGER as f64).then(|| (number as i64).to_string())
}

fn navigated_frame_id(event: &CdpEvent) -> Option<String> {
    match event.method.as_str() {
        "Page.frameNavigated" => event.params.get("frame")?.get("id")?.as_str().map(str::to_string),
        "Page.navigatedWithinDocument" => event.params.get("frameId")?.as_str().map(str::to_string),
        _ => None,
    }
}

struct Inspection<'a> {
    input: &'a InspectElectronPageInput,
    discovery: &'a CdpEndpointDiscovery,
    target: &'a CdpEndpointTarget,
    state: ElectronEventState,
    limitations: Vec<String>,
}

impl<'a> Inspection<'a> {
    fn new(
        input: &'a InspectElectronPageInput,
        discovery: &'a CdpEndpointDiscovery,
        target: &'a CdpEndpointTarget,
    ) -> Self {
        Self {
            input,
            discovery,
            target,
            state: ElectronEventState::default(),
            limitations: vec![
                "Local file paths exposed by the selected CDP target are retained in the observation.".to_string(),
                "REA does not evaluate renderer JavaScript, invoke Electron APIs, navigate, click, or close the page.".to_string(),
                "Select include_script_sources to retain script contents.".to_string(),
            ],
        }
    }

    async fn send(
        &mut self,
        session: &mut CdpTargetSession,
        method: &str,
        params: Value,
        session_id: Option<&str>,
    ) -> Result<Map<String, Value>, WebError> {
        let result = session.connection.send(method, params, session_id).await;
        self.drain(session);
        result
    }

    fn drain(&mut self, session: &mut CdpTargetSession) {
        let session_id = session.session_id.clone();
        for event in session.connection.take_events() {
            self.state.ingest(&event, session_id.as_deref());
        }
    }

    async fn run(&mut self, session: &mut CdpTargetSession) -> Result<Value, WebError> {
        let started_at = iso_now();
        let sid = session.session_id.clone();
        let sid = sid.as_deref();
        // authorizeInitialFrames
        self.send(session, "Page.enable", json!({}), sid).await?;
        let tree = self.send(session, "Page.getFrameTree", json!({}), sid).await?;
        let frames = capture_frames(&tree, &mut self.state.completeness)?;
        let Some(main) = frames.first().cloned() else {
            return Err(fail(BrowserFailureReason::TargetNotAllowed));
        };
        self.state.main_frame_id = main["frame_id"].as_str().map(str::to_string);
        // enableElectronCapture
        self.send(session, "Runtime.enable", json!({}), sid).await?;
        self.send(session, "Debugger.enable", json!({}), sid).await?;
        let window = Duration::from_millis(u64::try_from(self.input.observation_ms).unwrap_or(0));
        session.connection.collect_for(window).await?;
        self.drain(session);
        // captureElectronContent
        let frame_ids: HashSet<String> = frames
            .iter()
            .filter_map(|frame| frame["frame_id"].as_str().map(str::to_string))
            .collect();
        let resource_tree = self.send(session, "Page.getResourceTree", json!({}), sid).await?;
        let resources = capture_resources(&resource_tree, &mut self.state.completeness)?;
        let snapshot = self
            .send(
                session,
                "DOMSnapshot.captureSnapshot",
                json!({ "computedStyles": [], "includePaintOrder": false, "includeDOMRects": false }),
                sid,
            )
            .await?;
        let dom = capture_dom(&snapshot, &mut self.state.completeness);
        let scripts = self.capture_scripts(session, &frame_ids).await?;
        let workers = self.capture_workers(session, &frame_ids).await?;
        // assertStableMainFrame
        let after = self.send(session, "Page.getFrameTree", json!({}), sid).await?;
        let Some(after_path) = main_file_path(&after) else {
            return Err(fail(BrowserFailureReason::TargetNotAllowed));
        };
        if self.state.navigation_during_capture || Some(after_path.as_str()) != main["file_path"].as_str() {
            return Err(fail(BrowserFailureReason::TargetChanged));
        }
        Ok(json!({
            "browser": self.discovery.version.to_json(),
            "target": {
                "target_id": self.target.id,
                "type": self.target.target_type,
                "title": self.target.title,
                "file_path": main["file_path"],
                "attached": self.target.attached,
            },
            "capture_window": {
                "started_at": started_at,
                "ended_at": iso_now(),
                "observation_ms": self.input.observation_ms,
            },
            "completeness": self.state.completeness.snapshot(),
            "frames": frames,
            "dom": dom,
            "scripts": scripts,
            "resources": resources,
            "workers": workers,
            "limitations": self.limitations,
        }))
    }

    async fn capture_scripts(
        &mut self,
        session: &mut CdpTargetSession,
        frame_ids: &HashSet<String>,
    ) -> Result<Value, WebError> {
        let sid = session.session_id.clone();
        let selected = select_scripts(&mut self.state, frame_ids)?;
        let mut sources = Vec::with_capacity(selected.len());
        for script in &selected {
            let source = if self.input.include_script_sources {
                let result = self
                    .send(
                        session,
                        "Debugger.getScriptSource",
                        json!({ "scriptId": script.script_id }),
                        sid.as_deref(),
                    )
                    .await?;
                included_source(&result)?
            } else {
                not_selected_source()
            };
            sources.push(source);
        }
        Ok(assemble_scripts(
            selected,
            sources,
            self.input.include_script_sources,
            &mut self.state.completeness,
        ))
    }

    async fn capture_workers(
        &mut self,
        session: &mut CdpTargetSession,
        frame_ids: &HashSet<String>,
    ) -> Result<Vec<Value>, WebError> {
        let result = match self.send(session, "Target.getTargets", json!({}), None).await {
            Ok(result) => result,
            Err(WebError::CdpCommandRejected { code: -32601, .. }) => {
                self.limitations
                    .push("Target.getTargets was unavailable from this browser target.".to_string());
                self.state.completeness.unavailable("workers");
                return Ok(Vec::new());
            }
            Err(error) => return Err(error),
        };
        Ok(project_workers(
            result.get("targetInfos").unwrap_or(&Value::Null),
            &self.target.id,
            frame_ids,
            &mut self.state.completeness,
        ))
    }
}

/// One authorized, deduplicated script (REA `captureElectronScripts` identity).
#[derive(Debug, Clone, PartialEq)]
pub struct SelectedScript {
    pub script_id: String,
    pub script_key: String,
    pub identity: Value,
}

/// Authorize and deduplicate retained script drafts, in arrival order.
pub fn select_scripts(
    state: &mut ElectronEventState,
    frame_ids: &HashSet<String>,
) -> Result<Vec<SelectedScript>, WebError> {
    let mut selected = Vec::new();
    let mut seen = HashSet::new();
    for script in state.scripts.clone() {
        let Some(path) = authorized_electron_file(&script.raw_url) else {
            state.completeness.exclude("scripts", "out_of_target_scope", Some(1));
            continue;
        };
        let mapped = script
            .execution_context_key
            .as_ref()
            .and_then(|key| state.execution_context_frames.get(key))
            .filter(|frame| frame_ids.contains(*frame))
            .cloned();
        let identity = json!({
            "frame_id": mapped,
            "file_path": path,
            "cdp_hash": script.hash,
            "length": script.length,
            "is_module": script.is_module,
            "language": script.language,
        });
        let script_key = format!("electron_script_{}", canonical_sha256(&identity)?);
        if !seen.insert(script_key.clone()) {
            continue;
        }
        selected.push(SelectedScript {
            script_id: script.script_id,
            script_key,
            identity,
        });
    }
    Ok(selected)
}

/// Source object for an unapproved script.
pub fn not_selected_source() -> Value {
    json!({ "included": false, "reason": "source capture was not selected" })
}

/// Source object from one `Debugger.getScriptSource` result.
pub fn included_source(result: &Map<String, Value>) -> Result<Value, WebError> {
    let Some(text) = result.get("scriptSource").and_then(Value::as_str) else {
        return Err(browser_error(
            OPERATION,
            BrowserFailureReason::ProtocolError,
            Some("Debugger.getScriptSource returned malformed source text: scriptSource must be a string.".to_string()),
        ));
    };
    Ok(json!({ "included": true, "artifact": web_text_artifact(text, "text/javascript") }))
}

/// Public `scripts` section; records unapproved sources in completeness.
pub fn assemble_scripts(
    selected: Vec<SelectedScript>,
    sources: Vec<Value>,
    include_script_sources: bool,
    completeness: &mut CdpCaptureCompleteness,
) -> Value {
    let total = selected.len() as i64;
    let mut items: Vec<Value> = selected
        .into_iter()
        .zip(sources)
        .map(|(script, source)| {
            let mut item = json!({ "script_key": script.script_key });
            for (key, value) in script.identity.as_object().into_iter().flatten() {
                item[key] = value.clone();
            }
            item["source"] = source;
            item
        })
        .collect();
    if !include_script_sources {
        completeness.exclude("script_sources", "not_approved", Some(total));
    }
    items.sort_by(|left, right| key_of(left, "script_key").cmp(key_of(right, "script_key")));
    json!({ "total": total, "items": items })
}

fn key_of<'v>(value: &'v Value, key: &str) -> &'v str {
    value[key].as_str().unwrap_or_default()
}

/// REA `createWebTextArtifact`.
pub fn web_text_artifact(text: &str, media_type: &str) -> Value {
    json!({
        "sha256": hex::encode(Sha256::digest(text.as_bytes())),
        "bytes": text.len(),
        "media_type": media_type,
        "charset": "utf-8",
        "text": text,
    })
}

/// Depth-first frame walk; malformed `childFrames` entries call `on_malformed`.
fn walk_frame_trees(root: &Map<String, Value>, mut on_malformed: impl FnMut()) -> Vec<&Map<String, Value>> {
    let mut pending = vec![root];
    let mut ordered = Vec::new();
    while let Some(tree) = pending.pop() {
        let children: Vec<&Map<String, Value>> = match tree.get("childFrames") {
            None => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|child| {
                    let parsed = child.as_object();
                    if parsed.is_none() {
                        on_malformed();
                    }
                    parsed
                })
                .collect(),
            Some(_) => {
                on_malformed();
                Vec::new()
            }
        };
        for child in children.into_iter().rev() {
            pending.push(child);
        }
        ordered.push(tree);
    }
    ordered
}

/// Authorized frames from one `Page.getFrameTree` result (REA `captureFrames`).
pub fn capture_frames(
    result: &Map<String, Value>,
    completeness: &mut CdpCaptureCompleteness,
) -> Result<Vec<Value>, WebError> {
    let Some(root) = result.get("frameTree").and_then(Value::as_object) else {
        return Err(fail(BrowserFailureReason::ProtocolError));
    };
    let mut malformed = 0;
    let trees = walk_frame_trees(root, || malformed += 1);
    for _ in 0..malformed {
        completeness.exclude("frames", "invalid_protocol_value", Some(1));
    }
    let mut frames = Vec::new();
    for tree in trees {
        let frame = tree.get("frame").and_then(Value::as_object);
        let frame_id = frame.and_then(|f| f.get("id")).and_then(Value::as_str);
        let url = frame.and_then(|f| f.get("url")).and_then(Value::as_str).unwrap_or("");
        let (Some(frame_id), Some(path)) = (frame_id, authorized_electron_file(url)) else {
            completeness.exclude("frames", "out_of_target_scope", Some(1));
            continue;
        };
        frames.push(json!({
            "frame_id": frame_id,
            "parent_frame_id": frame.and_then(|f| f.get("parentId")).and_then(Value::as_str),
            "file_path": path,
        }));
    }
    Ok(frames)
}

/// Authorized, deduplicated resources from `Page.getResourceTree` (REA `captureResources`).
pub fn capture_resources(
    result: &Map<String, Value>,
    completeness: &mut CdpCaptureCompleteness,
) -> Result<Vec<Value>, WebError> {
    let Some(root) = result.get("frameTree").and_then(Value::as_object) else {
        return Err(fail(BrowserFailureReason::ProtocolError));
    };
    let mut pending = std::collections::VecDeque::from([root]);
    let mut resources = Vec::new();
    let mut seen = BTreeSet::new();
    while let Some(tree) = pending.pop_front() {
        for resource in records(tree.get("resources")) {
            let url = resource.get("url").and_then(Value::as_str).unwrap_or("");
            let Some(path) = authorized_electron_file(url) else {
                completeness.exclude("resources", "out_of_target_scope", Some(1));
                continue;
            };
            let content_size = resource
                .get("contentSize")
                .and_then(safe_number)
                .map(|n| crate::cdp_values::json_number(n.max(0.0)))
                .unwrap_or(Value::Null);
            let item = json!({
                "file_path": path,
                "type": resource.get("type").and_then(Value::as_str).unwrap_or("Other"),
                "mime_type": resource.get("mimeType").and_then(Value::as_str).unwrap_or(""),
                "content_size": content_size,
            });
            let resource_key = format!("electron_resource_{}", canonical_sha256(&item)?);
            if !seen.insert(resource_key.clone()) {
                continue;
            }
            let mut public = json!({ "resource_key": resource_key });
            for (key, value) in item.as_object().into_iter().flatten() {
                public[key] = value.clone();
            }
            resources.push(public);
        }
        pending.extend(records(tree.get("childFrames")));
    }
    resources.sort_by(|left, right| key_of(left, "resource_key").cmp(key_of(right, "resource_key")));
    Ok(resources)
}

fn records(value: Option<&Value>) -> Vec<&Map<String, Value>> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_object).collect())
        .unwrap_or_default()
}

fn array(value: Option<&Value>) -> &[Value] {
    value.and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

fn integer(value: Option<&Value>, fallback: i64) -> i64 {
    value.and_then(safe_number).map(|n| n.trunc() as i64).unwrap_or(fallback)
}

fn string_at<'s>(strings: &'s [String], value: Option<&Value>) -> &'s str {
    let index = integer(value, -1);
    usize::try_from(index)
        .ok()
        .and_then(|index| strings.get(index))
        .map(String::as_str)
        .unwrap_or("")
}

/// Structural DOM projection of authorized documents (REA `captureDom`).
pub fn capture_dom(result: &Map<String, Value>, completeness: &mut CdpCaptureCompleteness) -> Value {
    let strings: Vec<String> = array(result.get("strings"))
        .iter()
        .map(|value| value.as_str().unwrap_or("").to_string())
        .collect();
    let mut nodes: Vec<Value> = Vec::new();
    let mut total = 0usize;
    for document in records(result.get("documents")) {
        let document_url = string_at(&strings, document.get("documentURL"));
        if authorized_electron_file(document_url).is_none() {
            completeness.exclude("dom", "out_of_target_scope", Some(1));
            continue;
        }
        let node_data = document.get("nodes");
        let field = |name: &str| array(node_data.and_then(|data| data.get(name)));
        let (node_types, node_names, node_values, parents, attributes) = (
            field("nodeType"),
            field("nodeName"),
            field("nodeValue"),
            field("parentIndex"),
            field("attributes"),
        );
        let base_index = nodes.len() as i64;
        total += node_types.len();
        for index in 0..node_types.len() {
            let parent = integer(parents.get(index), -1);
            let attribute_names: Vec<&str> = array(attributes.get(index))
                .iter()
                .step_by(2)
                .map(|value| string_at(&strings, Some(value)))
                .collect();
            nodes.push(json!({
                "index": nodes.len(),
                "parent_index": if parent < 0 { -1 } else { base_index + parent },
                "node_type": integer(node_types.get(index), 0),
                "node_name": string_at(&strings, node_names.get(index)),
                "node_value_length": string_at(&strings, node_values.get(index)).len(),
                "attribute_names": attribute_names,
            }));
        }
    }
    json!({ "total_nodes": total, "nodes": nodes })
}

fn main_file_path(result: &Map<String, Value>) -> Option<String> {
    let url = result
        .get("frameTree")
        .and_then(|tree| tree.get("frame"))
        .and_then(|frame| frame.get("url"))
        .and_then(Value::as_str)
        .unwrap_or("");
    authorized_electron_file(url)
}

fn bounded_target_field(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
}

/// Local worker targets owned by the inspected page (REA `captureElectronWorkers`).
pub fn project_workers(
    target_infos: &Value,
    page_target_id: &str,
    frame_ids: &HashSet<String>,
    completeness: &mut CdpCaptureCompleteness,
) -> Vec<Value> {
    let mut workers = Vec::new();
    for target in records(Some(target_infos)) {
        let kind = target.get("type").and_then(Value::as_str).unwrap_or("");
        if !kind.contains("worker") {
            continue;
        }
        let opener = bounded_target_field(target.get("openerId"));
        let parent_frame = bounded_target_field(target.get("parentFrameId"));
        let owned = opener.as_deref() == Some(page_target_id)
            || parent_frame.as_ref().is_some_and(|frame| frame_ids.contains(frame));
        if !owned {
            completeness.exclude("workers", "out_of_target_scope", Some(1));
            continue;
        }
        let url = target.get("url").and_then(Value::as_str).unwrap_or("");
        let Some(path) = authorized_electron_file(url) else {
            completeness.exclude("workers", "out_of_target_scope", Some(1));
            continue;
        };
        let Some(target_id) = bounded_target_field(target.get("targetId")) else {
            completeness.exclude("workers", "invalid_protocol_value", Some(1));
            continue;
        };
        workers.push(json!({
            "target_id": target_id,
            "type": kind,
            "file_path": path,
            "attached": target.get("attached") == Some(&Value::Bool(true)),
            "opener_target_id": opener,
            "parent_frame_id": parent_frame,
        }));
    }
    workers.sort_by(|left, right| key_of(left, "target_id").cmp(key_of(right, "target_id")));
    workers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_defaults_and_rejections_follow_rea() {
        let parsed = parse_inspect_electron_page_input(&json!({
            "cdp_endpoint": "http://127.0.0.1:9222",
            "target_id": "  T  ",
        }))
        .unwrap();
        assert_eq!(parsed.target_id, "T");
        assert_eq!(parsed.observation_ms, 100);
        assert!(!parsed.include_script_sources);
        for bad in [
            json!({ "cdp_endpoint": "http://127.0.0.1:9222" }),
            json!({ "cdp_endpoint": "http://127.0.0.1:9222", "target_id": "  " }),
            json!({ "cdp_endpoint": "http://127.0.0.1:9222", "target_id": "x", "observation_ms": -1 }),
            json!({ "cdp_endpoint": "http://127.0.0.1:9222", "target_id": "x", "observation_ms": 1.5 }),
            json!({ "cdp_endpoint": "http://127.0.0.1:9222", "target_id": "x", "include_script_sources": "yes" }),
            json!({ "cdp_endpoint": "http://127.0.0.1:9222", "target_id": "x", "extra": 1 }),
            json!({ "cdp_endpoint": "http://localhost:9222", "target_id": "x" }),
        ] {
            assert!(parse_inspect_electron_page_input(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn script_events_track_contexts_and_navigation() {
        let mut state = ElectronEventState {
            main_frame_id: Some("F".to_string()),
            ..ElectronEventState::default()
        };
        let event = |method: &str, params: Value| CdpEvent {
            method: method.to_string(),
            params,
            session_id: None,
        };
        state.ingest(
            &event("Runtime.executionContextCreated", json!({ "context": { "id": 3, "auxData": { "frameId": "F" } } })),
            None,
        );
        state.ingest(
            &event(
                "Debugger.scriptParsed",
                json!({ "scriptId": "1", "url": "file:///a.js", "hash": "h", "length": 4, "isModule": false, "scriptLanguage": "JavaScript", "executionContextId": 3 }),
            ),
            None,
        );
        state.ingest(&event("Debugger.scriptParsed", json!({ "scriptId": "2", "url": "" })), None);
        state.ingest(&event("Debugger.scriptParsed", json!({ "url": "file:///b.js" })), None);
        // Other sessions are ignored.
        state.ingest(
            &CdpEvent {
                session_id: Some("other".to_string()),
                ..event("Page.frameNavigated", json!({ "frame": { "id": "F" } }))
            },
            None,
        );
        assert!(!state.navigation_during_capture);
        assert_eq!(state.scripts.len(), 1);
        assert_eq!(state.scripts[0].execution_context_key.as_deref(), Some("3"));
        assert_eq!(state.execution_context_frames.get("3").map(String::as_str), Some("F"));
        state.ingest(&event("Page.navigatedWithinDocument", json!({ "frameId": "F" })), None);
        assert!(state.navigation_during_capture);
        let snapshot = state.completeness.snapshot();
        assert_eq!(snapshot["unavailable_sections"], json!(["scripts"]));
        assert_eq!(snapshot["policy_filtered_sections"], json!(["scripts"]));
    }
}
