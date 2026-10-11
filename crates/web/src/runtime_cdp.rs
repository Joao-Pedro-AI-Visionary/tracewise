//! Shared live-page CDP session for execution and listener tools
//! (port of REA browser/execution/CdpRuntimeSession.ts and CdpRuntimeSources.ts).
//!
//! Source ownership is the selected main frame's default world, joined by
//! session script id. A URL never substitutes for that id.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::browser_observation::{
    browser_error, parse_browser_scope, sanitize_browser_url, trimmed_string_field, BrowserFailureReason,
    BrowserScope,
};
use crate::cdp_connection::{close_cdp_target_session, open_cdp_target_session, CdpEvent, CdpTargetSession};
use crate::cdp_documents::{main_frame_id, main_frame_url};
use crate::cdp_endpoint::{discover_cdp_endpoint, CdpEndpointDiscovery, CdpEndpointTarget};
use crate::cdp_values::{cdp_str, record, safe_integer};
use crate::error::WebError;

const RETAINED_EVENT_BYTES: usize = 8 * 1024 * 1024;
const SOURCE_BYTES: usize = 32 * 1024 * 1024;

pub fn iso_now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

pub fn input_error(operation: &str, path: &str, message: impl Into<String>) -> WebError {
    WebError::Input {
        operation: operation.to_string(),
        path: vec![path.to_string()],
        reason: "invalid_value".to_string(),
        message: message.into(),
    }
}

pub fn optional_bool(operation: &str, object: &Map<String, Value>, key: &str) -> Result<Option<bool>, WebError> {
    match object.get(key) {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(input_error(operation, key, format!("{key} must be a boolean"))),
    }
}

pub fn optional_i64(
    operation: &str,
    object: &Map<String, Value>,
    key: &str,
    min: i64,
    max: i64,
) -> Result<Option<i64>, WebError> {
    match object.get(key) {
        None => Ok(None),
        Some(value) => {
            let Some(number) = value.as_i64().or_else(|| value.as_u64().and_then(|n| i64::try_from(n).ok())) else {
                return Err(input_error(operation, key, format!("{key} must be an integer")));
            };
            if number < min || number > max {
                return Err(input_error(operation, key, format!("{key} is outside the accepted range")));
            }
            Ok(Some(number))
        }
    }
}

pub fn parse_scope(
    operation: &str,
    args: &Value,
    extra: &[&str],
) -> Result<(BrowserScope, Map<String, Value>), WebError> {
    parse_browser_scope(operation, args, extra)
}

#[derive(Debug, Clone)]
struct ScriptMeta {
    url: String,
    execution_context_id: i64,
    start_line: i64,
    start_column: i64,
    hash: Option<String>,
    source_map_url: Option<String>,
    has_source_url: Option<bool>,
    language: Option<String>,
    aux: Option<Value>,
    raw: Value,
}

#[derive(Debug, Clone)]
struct ContextMeta {
    raw: Value,
    aux: Option<Value>,
}

pub struct RuntimeSources {
    scripts: BTreeMap<String, ScriptMeta>,
    contexts: BTreeMap<i64, ContextMeta>,
    changed_scripts: BTreeSet<String>,
    changed_contexts: BTreeSet<i64>,
    retained: Vec<Value>,
    retained_ids: BTreeSet<String>,
    failure: Option<String>,
    retained_bytes: usize,
    source_bytes: usize,
    /// When false, newly parsed scripts stay outside this evidence.
    pub metadata_open: bool,
    frame_id: String,
    operation: String,
}

impl RuntimeSources {
    fn new(frame_id: String, operation: &str) -> Self {
        Self {
            scripts: BTreeMap::new(),
            contexts: BTreeMap::new(),
            changed_scripts: BTreeSet::new(),
            changed_contexts: BTreeSet::new(),
            retained: Vec::new(),
            retained_ids: BTreeSet::new(),
            failure: None,
            retained_bytes: 0,
            source_bytes: 0,
            metadata_open: true,
            frame_id,
            operation: operation.to_string(),
        }
    }

    pub fn check(&self) -> Result<(), WebError> {
        match &self.failure {
            Some(message) => Err(browser_error(
                &self.operation,
                BrowserFailureReason::PayloadLimit,
                Some(message.clone()),
            )),
            None => Ok(()),
        }
    }

    fn fail(&mut self, message: &str) -> WebError {
        self.failure = Some(message.to_string());
        browser_error(
            &self.operation,
            BrowserFailureReason::PayloadLimit,
            Some(message.to_string()),
        )
    }

    pub fn ingest(&mut self, event: &CdpEvent) {
        if self.failure.is_some() {
            return;
        }
        match event.method.as_str() {
            "Runtime.executionContextCreated" => self.ingest_context(event),
            "Debugger.scriptParsed" => self.ingest_script(event),
            _ => {}
        }
    }

    fn note_bytes(&mut self, params: &Value) -> bool {
        self.retained_bytes += params.to_string().len();
        if self.retained_bytes > RETAINED_EVENT_BYTES {
            self.failure = Some(
                "Context/script metadata exceeds the complete 8 MiB event budget.".to_string(),
            );
            false
        } else {
            true
        }
    }

    fn ingest_context(&mut self, event: &CdpEvent) {
        let Some(context) = event.params.get("context").and_then(Value::as_object) else {
            self.failure = Some("Malformed execution context.".to_string());
            return;
        };
        let Some(id) = context.get("id").and_then(nonneg) else {
            self.failure = Some("Malformed execution context id.".to_string());
            return;
        };
        if !self.metadata_open && !self.contexts.contains_key(&id) {
            return;
        }
        if !self.note_bytes(&event.params) {
            return;
        }
        let raw = Value::Object(context.clone());
        if let Some(previous) = self.contexts.get(&id) {
            if previous.raw != raw {
                self.changed_contexts.insert(id);
            }
        }
        if self.metadata_open {
            let aux = context.get("auxData").filter(|value| value.is_object()).cloned();
            self.contexts.insert(id, ContextMeta { raw, aux });
        }
    }

    fn ingest_script(&mut self, event: &CdpEvent) {
        let params = &event.params;
        let Some(script_id) = params.get("scriptId").and_then(cdp_str).filter(|id| !id.is_empty()) else {
            self.failure = Some("Malformed script id.".to_string());
            return;
        };
        if !self.metadata_open && !self.scripts.contains_key(script_id) {
            return;
        }
        let Some(url) = params.get("url").and_then(cdp_str) else {
            self.failure = Some("Malformed script url.".to_string());
            return;
        };
        let Some(execution_context_id) = params.get("executionContextId").and_then(nonneg) else {
            self.failure = Some("Malformed script execution context.".to_string());
            return;
        };
        let (Some(start_line), Some(start_column)) = (
            params.get("startLine").and_then(nonneg),
            params.get("startColumn").and_then(nonneg),
        ) else {
            self.failure = Some("Malformed script resource start.".to_string());
            return;
        };
        if !self.note_bytes(params) {
            return;
        }
        let script_id = script_id.to_string();
        let raw = params.clone();
        if let Some(previous) = self.scripts.get(&script_id) {
            if previous.raw != raw {
                self.changed_scripts.insert(script_id.clone());
            }
        }
        if self.metadata_open {
            self.scripts.insert(
                script_id,
                ScriptMeta {
                    url: url.to_string(),
                    execution_context_id,
                    start_line,
                    start_column,
                    hash: params.get("hash").and_then(cdp_str).map(str::to_string),
                    source_map_url: params.get("sourceMapURL").and_then(cdp_str).map(str::to_string),
                    has_source_url: params.get("hasSourceURL").and_then(Value::as_bool),
                    language: params.get("scriptLanguage").and_then(cdp_str).map(str::to_string),
                    aux: params
                        .get("executionContextAuxData")
                        .filter(|value| value.is_object())
                        .cloned(),
                    raw,
                },
            );
        }
    }

    /// Only a proven default world of the selected main frame owns website source.
    pub fn belongs_to_document(&self, script_id: &str) -> bool {
        let Some(script) = self.scripts.get(script_id) else {
            return false;
        };
        if self.changed_scripts.contains(script_id) || self.changed_contexts.contains(&script.execution_context_id) {
            return false;
        }
        let context_aux = self.contexts.get(&script.execution_context_id).and_then(|ctx| ctx.aux.as_ref());
        let worlds = [script.aux.as_ref(), context_aux];
        if worlds.iter().flatten().any(|world| world_rejects(world)) || !worlds.iter().flatten().any(|world| world_proves(world))
        {
            return false;
        }
        let reported = script.aux.as_ref().and_then(|aux| aux.get("frameId")).and_then(cdp_str);
        let context_frame = context_aux.and_then(|aux| aux.get("frameId")).and_then(cdp_str);
        (reported.is_none() || context_frame.is_none() || reported == context_frame)
            && reported.or(context_frame) == Some(self.frame_id.as_str())
    }

    pub fn reported_script_url(&self, script_id: &str) -> Option<String> {
        self.scripts.get(script_id).map(|script| script.url.clone())
    }

    pub fn source_url(&self, script_id: &str, url: &str) -> String {
        if !self.changed_scripts.contains(script_id) {
            if let Some(script) = self.scripts.get(script_id) {
                if script.has_source_url == Some(false) {
                    return sanitize_browser_url(url).url;
                }
            }
        }
        url.to_string()
    }

    pub fn location(
        &self,
        script_id: &str,
        url: Option<&str>,
        line_number: i64,
        column_number: Option<i64>,
        function_name: Option<&str>,
    ) -> Value {
        let url = url.map(|value| self.source_url(script_id, value));
        json!({
            "script_id": script_id,
            "url": url,
            "line_number": line_number,
            "column_number": column_number,
            "function_name": function_name,
            "source_association": if self.belongs_to_document(script_id) { "script_id" } else { "unknown" },
        })
    }

    pub fn main_script_ids(&self) -> Vec<String> {
        self.scripts
            .keys()
            .filter(|id| self.belongs_to_document(id))
            .cloned()
            .collect()
    }

    pub async fn read(&mut self, session: &mut CdpTargetSession, script_ids: &[String]) -> Result<Vec<Value>, WebError> {
        self.check()?;
        for script_id in script_ids {
            if script_id.is_empty() || self.retained_ids.contains(script_id) {
                continue;
            }
            let item = self.read_one(session, script_id).await?;
            self.retained_ids.insert(script_id.clone());
            self.retained.push(item);
            self.check()?;
        }
        Ok(self.retained.clone())
    }

    async fn read_one(&mut self, session: &mut CdpTargetSession, script_id: &str) -> Result<Value, WebError> {
        let owned = self.belongs_to_document(script_id);
        let script = self.scripts.get(script_id).cloned();
        let context = script
            .as_ref()
            .and_then(|meta| self.contexts.get(&meta.execution_context_id))
            .map(|ctx| ctx.raw.clone());
        let changed = self.changed_scripts.contains(script_id);
        let mut source = json!({
            "state": "excluded",
            "reason": if changed {
                "The script changed identity during observation; source attribution is unknown."
            } else {
                "Selected main-document default-world ownership was not established."
            },
        });
        if owned {
            if script.as_ref().and_then(|meta| meta.language.as_deref()) == Some("WebAssembly") {
                source = json!({
                    "state": "excluded",
                    "reason": "WebAssembly bytecode is outside this JavaScript source operation.",
                });
            } else {
                source = self.capture_text(session, script_id).await?;
            }
        }
        let url = script.as_ref().map(|meta| self.source_url(script_id, &meta.url)).unwrap_or_default();
        let mut item = json!({
            "script_id": script_id,
            "url": url,
            "execution_context_id": script.as_ref().map(|meta| json!(meta.execution_context_id)).unwrap_or(Value::Null),
            "reported_execution_context": context.unwrap_or(Value::Null),
            "reported_script_context_aux_data": script.as_ref().and_then(|meta| meta.aux.clone()).unwrap_or(Value::Null),
            "frame_id": if owned { Value::String(self.frame_id.clone()) } else { Value::Null },
            "producer_hash": script.as_ref().and_then(|meta| meta.hash.clone()).map(Value::String).unwrap_or(Value::Null),
            "source_map_url": script.as_ref().and_then(|meta| meta.source_map_url.clone()).map(Value::String).unwrap_or(Value::Null),
            "has_source_url": script.as_ref().and_then(|meta| meta.has_source_url).map(Value::Bool).unwrap_or(Value::Null),
            "language": script.as_ref().and_then(|meta| meta.language.clone()).map(Value::String).unwrap_or(Value::Null),
            "resource_start": script.as_ref().map(|meta| json!({
                "line_number": meta.start_line,
                "column_number": meta.start_column,
            })).unwrap_or(Value::Null),
            "source": source,
        });
        if item["frame_id"].is_string() && !self.belongs_to_document(script_id) {
            item["frame_id"] = Value::Null;
            item["source"] = json!({
                "state": "excluded",
                "reason": "The script or context changed identity during source collection; attribution is unknown.",
            });
        }
        Ok(item)
    }

    async fn capture_text(&mut self, session: &mut CdpTargetSession, script_id: &str) -> Result<Value, WebError> {
        let result = session
            .connection
            .send("Debugger.getScriptSource", json!({ "scriptId": script_id }), session.session_id.as_deref())
            .await;
        let events = session.connection.take_events();
        for event in &events {
            if event_in_session(event, session.session_id.as_deref()) {
                self.ingest(event);
            }
        }
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                return Ok(json!({
                    "state": "unavailable",
                    "reason": error.to_string(),
                }));
            }
        };
        let Some(text) = result.get("scriptSource").and_then(Value::as_str) else {
            return Err(self.fail("Debugger.getScriptSource returned malformed source text."));
        };
        let bytes = text.len();
        self.source_bytes += bytes;
        if self.source_bytes > SOURCE_BYTES {
            return Err(self.fail(
                "Complete runtime source evidence exceeds its 32 MiB budget; no partial evidence is returned.",
            ));
        }
        Ok(json!({
            "state": "captured",
            "text": text,
            "sha256": hex::encode(Sha256::digest(text.as_bytes())),
            "utf8_bytes": bytes as i64,
            "utf16_units": text.encode_utf16().count() as i64,
        }))
    }

    pub fn captured_utf16(&self, script_id: &str) -> Option<i64> {
        self.retained.iter().find_map(|item| {
            if item["script_id"].as_str() != Some(script_id) {
                return None;
            }
            (item["source"]["state"].as_str() == Some("captured"))
                .then(|| item["source"]["utf16_units"].as_i64())
                .flatten()
        })
    }
}

fn world_rejects(world: &Value) -> bool {
    if world.get("isDefault") == Some(&Value::Bool(false)) {
        return true;
    }
    world
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind != "default")
}

fn world_proves(world: &Value) -> bool {
    world.get("isDefault") == Some(&Value::Bool(true)) || world.get("type").and_then(Value::as_str) == Some("default")
}

fn nonneg(value: &Value) -> Option<i64> {
    safe_integer(value).filter(|number| *number >= 0)
}

pub struct RuntimeDocument {
    pub target_id: String,
    pub origin: String,
    pub initial_url: String,
    pub frame_id: String,
    pub loader_id: Option<String>,
    pub browser: Value,
}

pub struct RuntimeAttach {
    pub session: CdpTargetSession,
    pub sources: RuntimeSources,
    pub document: RuntimeDocument,
    pub allowed_origins: Vec<String>,
    pub operation: String,
    enabled: Vec<&'static str>,
    pub precise_coverage_active: bool,
}

impl RuntimeAttach {
    pub async fn open(
        operation: &str,
        scope: &BrowserScope,
        target_id: &str,
    ) -> Result<Self, WebError> {
        let discovery = discover_cdp_endpoint(&scope.cdp_endpoint, operation).await?;
        let (target, allowed_origins) = authorize(&discovery, operation, target_id, &scope.allowed_origins)?;
        let mut session = open_cdp_target_session(&discovery, target, operation).await?;
        let document = match read_document(&mut session, &discovery, target, &allowed_origins, operation).await {
            Ok(document) => document,
            Err(error) => {
                session.connection.close().await;
                return Err(error);
            }
        };
        let _ = session.connection.take_events();
        Ok(Self {
            sources: RuntimeSources::new(document.frame_id.clone(), operation),
            session,
            document,
            allowed_origins,
            operation: operation.to_string(),
            enabled: vec!["Page"],
            precise_coverage_active: false,
        })
    }

    pub async fn enable(&mut self, domain: &'static str) -> Result<(), WebError> {
        if !self.enabled.contains(&domain) {
            self.enabled.push(domain);
        }
        self.command(&format!("{domain}.enable"), json!({})).await?;
        Ok(())
    }

    pub async fn command(&mut self, method: &str, params: Value) -> Result<Map<String, Value>, WebError> {
        let result = self
            .session
            .connection
            .send(method, params, self.session.session_id.as_deref())
            .await?;
        self.drain_into_sources();
        self.sources.check()?;
        Ok(result)
    }

    pub fn drain_events(&mut self) -> Vec<CdpEvent> {
        let events = self.session.connection.take_events();
        let mut matched = Vec::new();
        for event in events {
            if event_in_session(&event, self.session.session_id.as_deref()) {
                self.sources.ingest(&event);
                matched.push(event);
            }
        }
        matched
    }

    fn drain_into_sources(&mut self) {
        let _ = self.drain_events();
    }

    pub async fn assert_document(&mut self) -> Result<(), WebError> {
        let tree = self.command("Page.getFrameTree", json!({})).await?;
        let frame = tree
            .get("frameTree")
            .and_then(record)
            .and_then(|node| node.get("frame"))
            .and_then(record)
            .ok_or_else(|| browser_error(&self.operation, BrowserFailureReason::ProtocolError, None))?;
        let url = frame.get("url").and_then(cdp_str).unwrap_or("");
        let sanitized = sanitize_browser_url(url);
        let loader = frame.get("loaderId").and_then(cdp_str);
        let frame_id = frame.get("id").and_then(cdp_str).unwrap_or("");
        if frame_id != self.document.frame_id
            || loader != self.document.loader_id.as_deref()
            || (self.document.loader_id.is_none() && sanitized.url != self.document.initial_url)
        {
            return Err(browser_error(
                &self.operation,
                BrowserFailureReason::TargetChanged,
                Some(format!(
                    "Selected target {} changed document during {}.",
                    self.document.target_id, self.operation
                )),
            ));
        }
        match sanitized.origin {
            Some(origin) if self.allowed_origins.iter().any(|allowed| allowed == &origin) => Ok(()),
            _ => Err(browser_error(
                &self.operation,
                BrowserFailureReason::TargetNotAllowed,
                Some(format!(
                    "Selected target {} moved to an unselected origin during {}.",
                    self.document.target_id, self.operation
                )),
            )),
        }
    }

    pub async fn close(mut self, object_group: Option<&str>) {
        if self.precise_coverage_active {
            let _ = self
                .session
                .connection
                .send("Profiler.stopPreciseCoverage", json!({}), self.session.session_id.as_deref())
                .await;
            self.precise_coverage_active = false;
        }
        if let Some(group) = object_group {
            let _ = self
                .session
                .connection
                .send(
                    "Runtime.releaseObjectGroup",
                    json!({ "objectGroup": group }),
                    self.session.session_id.as_deref(),
                )
                .await;
        }
        close_cdp_target_session(self.session, &self.enabled).await;
    }

    pub fn target_json(&self) -> Value {
        json!({
            "target_id": self.document.target_id,
            "origin": self.document.origin,
            "initial_url": self.document.initial_url,
            "frame_id": self.document.frame_id,
            "loader_id": self.document.loader_id,
        })
    }
}

fn event_in_session(event: &CdpEvent, session_id: Option<&str>) -> bool {
    event.session_id.as_deref() == session_id
}

fn authorize<'a>(
    discovery: &'a CdpEndpointDiscovery,
    operation: &str,
    target_id: &str,
    allowed: &[String],
) -> Result<(&'a CdpEndpointTarget, Vec<String>), WebError> {
    let target = discovery.targets.iter().find(|candidate| candidate.id == target_id).ok_or_else(|| {
        browser_error(
            operation,
            BrowserFailureReason::TargetNotFound,
            Some(format!("Target {target_id} was not found at the selected endpoint.")),
        )
    })?;
    let origin = sanitize_browser_url(&target.url).origin;
    match origin {
        Some(origin) if target.target_type == "page" && (allowed.is_empty() || allowed.contains(&origin)) => {
            let scope = if allowed.is_empty() { vec![origin] } else { allowed.to_vec() };
            Ok((target, scope))
        }
        _ => Err(browser_error(
            operation,
            BrowserFailureReason::TargetNotAllowed,
            Some(format!("Target {target_id} must be an HTTP(S) page in the selected origin scope.")),
        )),
    }
}

async fn read_document(
    session: &mut CdpTargetSession,
    discovery: &CdpEndpointDiscovery,
    target: &CdpEndpointTarget,
    allowed_origins: &[String],
    operation: &str,
) -> Result<RuntimeDocument, WebError> {
    session
        .connection
        .send("Page.enable", json!({}), session.session_id.as_deref())
        .await?;
    let tree = session
        .connection
        .send("Page.getFrameTree", json!({}), session.session_id.as_deref())
        .await?;
    let url = main_frame_url(&tree).unwrap_or_default();
    let sanitized = sanitize_browser_url(&url);
    let Some(origin) = sanitized.origin.filter(|origin| allowed_origins.iter().any(|allowed| allowed == origin)) else {
        return Err(browser_error(operation, BrowserFailureReason::TargetNotAllowed, None));
    };
    let frame_id = main_frame_id(&tree).ok_or_else(|| browser_error(operation, BrowserFailureReason::ProtocolError, None))?;
    let loader_id = tree
        .get("frameTree")
        .and_then(record)
        .and_then(|node| node.get("frame"))
        .and_then(record)
        .and_then(|frame| frame.get("loaderId"))
        .and_then(cdp_str)
        .map(str::to_string);
    Ok(RuntimeDocument {
        target_id: target.id.clone(),
        origin,
        initial_url: sanitized.url,
        frame_id,
        loader_id,
        browser: discovery.version.to_json(),
    })
}

pub fn require_target_id(operation: &str, object: &Map<String, Value>) -> Result<String, WebError> {
    trimmed_string_field(operation, object, "target_id")
}

pub async fn collect_for(attach: &mut RuntimeAttach, duration: Duration) -> Result<(), WebError> {
    attach.session.connection.collect_for(duration).await
}
