//! Passive Node/Electron V8 Inspector provider (port of REA
//! inspector/V8InspectorProvider.ts, V8InspectorEndpoint.ts,
//! V8InspectorCaptureProjection.ts and
//! application/javascript/JavaScriptRuntimeObservation{Service,Evidence}.ts).
//!
//! Attach-only: the provider sends `Runtime.enable` and `Debugger.enable`
//! and nothing else. It never evaluates, pauses, resumes, or reads source.

use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tracewise_domain::evidence::{
    create_evidence, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation,
    EvidenceProvider, ExecutionEnvironment, IsolationLevel,
};
use tracewise_web::browser_observation::{browser_error, parse_cdp_endpoint, BrowserFailureReason};
use tracewise_web::cdp_connection::{CdpConnection, CdpEvent};
use tracewise_web::error::WebError;
use url::Url;

use super::location::{authorize_runtime_location, authorize_runtime_target_location, LocationDecision};

pub const V8_INSPECTOR_PROVIDER_ID: &str = "rea-v8-inspector";
pub const V8_INSPECTOR_PROVIDER_NAME: &str = "REA passive Node/Electron V8 Inspector provider";
pub const V8_INSPECTOR_PROVIDER_VERSION: &str = "1";

const LIST_OPERATION: &str = "list_javascript_runtime_targets";
const OBSERVE_OPERATION: &str = "observe_javascript_runtime";
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);
const MISSING_SUBJECT: &str = "Artifact identity is unavailable for this observation.";

/// Aggregate retained metadata budget, including an estimate of JS object overhead.
pub const INSPECTOR_MAX_RETAINED_METADATA_BYTES: i64 = 8 * 1024 * 1024;
const RETAINED_OBJECT_OVERHEAD_BYTES: i64 = 512;

pub const RUNTIME_KINDS: &[&str] = &["node", "electron-main", "electron-preload", "electron-renderer"];

/// Validated `list_javascript_runtime_targets` input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRuntimeTargetsInput {
    pub inspector_endpoint: String,
}

/// Validated `observe_javascript_runtime` input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserveRuntimeInput {
    pub inspector_endpoint: String,
    pub target_id: String,
    pub runtime_kind: Option<String>,
    pub observation_ms: u64,
}

fn input_error(operation: &str, path: &[&str], message: impl Into<String>) -> WebError {
    WebError::Input {
        operation: operation.to_string(),
        path: path.iter().map(|p| p.to_string()).collect(),
        reason: "invalid_value".to_string(),
        message: message.into(),
    }
}

fn strict_object<'a>(operation: &str, args: &'a Value, keys: &[&str]) -> Result<&'a Map<String, Value>, WebError> {
    let object = args.as_object().ok_or_else(|| input_error(operation, &[], "Expected an object"))?;
    if let Some(key) = object.keys().find(|key| !keys.contains(&key.as_str())) {
        return Err(input_error(operation, &[key.as_str()], format!("Unrecognized key: \"{key}\"")));
    }
    Ok(object)
}

fn endpoint_field(operation: &str, object: &Map<String, Value>) -> Result<String, WebError> {
    let raw = match object.get("inspector_endpoint") {
        Some(Value::String(s)) if !s.is_empty() => s,
        _ => return Err(input_error(operation, &["inspector_endpoint"], "inspector_endpoint must be a non-empty string")),
    };
    parse_cdp_endpoint(raw).ok_or_else(|| {
        input_error(
            operation,
            &["inspector_endpoint"],
            "CDP endpoint must be an explicit-port HTTP URL on 127.0.0.1 or ::1",
        )
    })
}

pub fn parse_list_runtime_targets_input(args: &Value) -> Result<ListRuntimeTargetsInput, WebError> {
    let object = strict_object(LIST_OPERATION, args, &["inspector_endpoint"])?;
    Ok(ListRuntimeTargetsInput {
        inspector_endpoint: endpoint_field(LIST_OPERATION, object)?,
    })
}

pub fn parse_observe_runtime_input(args: &Value) -> Result<ObserveRuntimeInput, WebError> {
    let object = strict_object(
        OBSERVE_OPERATION,
        args,
        &["inspector_endpoint", "target_id", "runtime_kind", "observation_ms"],
    )?;
    let inspector_endpoint = endpoint_field(OBSERVE_OPERATION, object)?;
    let target_id = match object.get("target_id") {
        Some(Value::String(s)) if !s.trim().is_empty() => s.trim().to_string(),
        _ => return Err(input_error(OBSERVE_OPERATION, &["target_id"], "target_id must be a non-empty string")),
    };
    let runtime_kind = match object.get("runtime_kind") {
        None => None,
        Some(Value::String(s)) if RUNTIME_KINDS.contains(&s.as_str()) => Some(s.clone()),
        Some(_) => {
            return Err(input_error(
                OBSERVE_OPERATION,
                &["runtime_kind"],
                "runtime_kind must be node, electron-main, electron-preload, or electron-renderer",
            ))
        }
    };
    let observation_ms = match object.get("observation_ms") {
        None => 100,
        Some(value) => safe_non_negative_integer(value).ok_or_else(|| {
            input_error(OBSERVE_OPERATION, &["observation_ms"], "observation_ms must be a non-negative integer")
        })?,
    };
    Ok(ObserveRuntimeInput {
        inspector_endpoint,
        target_id,
        runtime_kind,
        observation_ms,
    })
}

fn safe_non_negative_integer(value: &Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        return (n <= 9_007_199_254_740_991).then_some(n);
    }
    let f = value.as_f64()?;
    (f >= 0.0 && f.fract() == 0.0 && f <= 9_007_199_254_740_991.0).then_some(f as u64)
}

/// One target reported by `/json/list` with a validated debugger socket.
#[derive(Debug, Clone)]
struct InspectorTarget {
    id: String,
    target_type: String,
    url: String,
    attached: bool,
    web_socket_url: String,
}

#[derive(Debug, Clone)]
struct InspectorDiscovery {
    runtime: Value,
    product: String,
    protocol_version: String,
    targets: Vec<InspectorTarget>,
}

/// Discover Node/Electron Inspector targets from one loopback endpoint.
async fn discover_v8_inspector(endpoint: &str, operation: &str) -> Result<InspectorDiscovery, WebError> {
    let base = Url::parse(endpoint).map_err(|_| browser_error(operation, BrowserFailureReason::EndpointUnreachable, None))?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(DISCOVERY_TIMEOUT)
        .build()
        .map_err(|_| browser_error(operation, BrowserFailureReason::EndpointUnreachable, None))?;
    let (version_input, targets_input) = tokio::join!(
        read_inspector_json(&client, &base, "/json/version", operation),
        read_inspector_json(&client, &base, "/json/list", operation),
    );
    let (version_input, targets_input) = (version_input?, targets_input?);
    let invalid = || browser_error(operation, BrowserFailureReason::InvalidEndpointResponse, None);
    let version = version_input.as_object().ok_or_else(invalid)?;
    let product = non_empty(version.get("Browser")).ok_or_else(invalid)?;
    let protocol_version = non_empty(version.get("Protocol-Version")).ok_or_else(invalid)?;
    let v8_version = match version.get("V8-Version") {
        None => Value::Null,
        Some(Value::String(s)) => json!(s),
        Some(_) => return Err(invalid()),
    };
    let mut targets = Vec::new();
    for raw in targets_input.as_array().ok_or_else(invalid)? {
        let object = raw.as_object().ok_or_else(invalid)?;
        let id = non_empty(object.get("id")).ok_or_else(invalid)?;
        let target_type = non_empty(object.get("type")).ok_or_else(invalid)?;
        let url = object.get("url").and_then(Value::as_str).ok_or_else(invalid)?.to_string();
        let attached = match object.get("attached") {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(invalid()),
        };
        let reported = non_empty(object.get("webSocketDebuggerUrl")).ok_or_else(invalid)?;
        let web_socket_url = validated_inspector_web_socket(endpoint, &id, &reported).ok_or_else(invalid)?;
        targets.push(InspectorTarget {
            id,
            target_type,
            url,
            attached,
            web_socket_url,
        });
    }
    Ok(InspectorDiscovery {
        runtime: json!({
            "product": product,
            "protocol_version": protocol_version,
            "v8_version": v8_version,
        }),
        product,
        protocol_version,
        targets,
    })
}

fn non_empty(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
}

async fn read_inspector_json(client: &reqwest::Client, base: &Url, path: &str, operation: &str) -> Result<Value, WebError> {
    let url = base
        .join(path)
        .map_err(|_| browser_error(operation, BrowserFailureReason::EndpointUnreachable, None))?;
    let response = client
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|error| {
            let reason = if error.is_timeout() {
                BrowserFailureReason::Timeout
            } else {
                BrowserFailureReason::EndpointUnreachable
            };
            browser_error(operation, reason, None)
        })?;
    if response.status().as_u16() != 200 {
        return Err(browser_error(operation, BrowserFailureReason::InvalidEndpointResponse, None));
    }
    let body = response
        .bytes()
        .await
        .map_err(|_| browser_error(operation, BrowserFailureReason::EndpointUnreachable, None))?;
    serde_json::from_slice(&body).map_err(|_| browser_error(operation, BrowserFailureReason::InvalidEndpointResponse, None))
}

/// Accept only same-port, credential-free `ws:` sockets for this exact target
/// and pin their host to the trusted endpoint host.
fn validated_inspector_web_socket(endpoint: &str, target_id: &str, reported: &str) -> Option<String> {
    let mut socket = Url::parse(reported).ok()?;
    let trusted = Url::parse(endpoint).ok()?;
    let allowed = [
        format!("/{target_id}"),
        format!("/devtools/node/{target_id}"),
        format!("/devtools/page/{target_id}"),
    ];
    if socket.scheme() != "ws"
        || socket.port() != trusted.port()
        || !socket.username().is_empty()
        || socket.password().is_some()
        || !socket.query().unwrap_or("").is_empty()
        || !socket.fragment().unwrap_or("").is_empty()
        || !allowed.iter().any(|path| path == socket.path())
    {
        return None;
    }
    socket.set_host(trusted.host_str()).ok()?;
    socket.set_query(None);
    socket.set_fragment(None);
    Some(socket.to_string())
}

/// Stable safety and protocol limitations shared by target-list Evidence.
fn inspector_target_limitations() -> Vec<String> {
    [
        "REA attaches to an already-running exact target and never launches, resumes, evaluates, pauses, or mutates it.",
        "Only Runtime.enable and Debugger.enable are sent; source text, object values, EventEmitter activity, and Electron IPC are not inspected.",
        "The selected endpoint and target ID authorize observation; discovery file locations can remain unresolved and do not prove filesystem identity.",
        "Node discovery reports a best-effort pathname rather than an encoded file URL; lossy Windows paths and ambiguous underscores are preserved without guessing a file path.",
        "Every target exposed by the selected Inspector endpoint is eligible for observation; target IDs and locations are not authenticated as operating-system process identity.",
        "No runtime graph depth is traversed because passive Inspector events do not establish require/import caller edges.",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn project_target(target: &InspectorTarget, location: &Value) -> Value {
    json!({
        "target_id": target.id,
        "protocol_type": target.target_type,
        "attached": target.attached,
        "location": location,
    })
}

/// List every eligible target exposed by the selected loopback Inspector.
pub async fn list_javascript_runtime_targets(input: &ListRuntimeTargetsInput) -> Result<Evidence, WebError> {
    let discovery = discover_v8_inspector(&input.inspector_endpoint, LIST_OPERATION).await?;
    let mut allowed: Vec<(InspectorTarget, Value)> = Vec::new();
    let mut unsupported_location = 0u64;
    for target in &discovery.targets {
        match authorize_runtime_target_location(&target.url, &target.target_type, &discovery.product) {
            LocationDecision::Allowed(location) if location["kind"] != "builtin" => {
                allowed.push((target.clone(), location));
            }
            _ => unsupported_location += 1,
        }
    }
    allowed.sort_by(|left, right| left.0.id.cmp(&right.0.id));
    let result = json!({
        "runtime": discovery.runtime,
        "targets": allowed.iter().map(|(target, location)| project_target(target, location)).collect::<Vec<_>>(),
        "excluded": { "unsupported_location": unsupported_location, "unconnectable": 0 },
        "limitations": inspector_target_limitations(),
    });
    runtime_evidence(
        LIST_OPERATION,
        json!({ "inspector_endpoint": input.inspector_endpoint }),
        result,
        &discovery,
    )
}

struct ScriptDraft {
    raw_url: String,
    execution_context_key: Option<String>,
    cdp_hash: Option<String>,
    length: Option<u64>,
    is_module: Option<bool>,
}

struct ContextDraft {
    context_key: String,
    state: &'static str,
    name: Option<String>,
    origin: Option<String>,
}

#[derive(Default)]
struct CaptureState {
    scripts: Vec<ScriptDraft>,
    /// Insertion-ordered contexts keyed by context key.
    contexts: Vec<ContextDraft>,
    events_observed: u64,
    events_retained: u64,
    events_dropped: u64,
    metadata_bytes: i64,
    scripts_observed: u64,
    invalid_scripts: u64,
    truncated: bool,
    truncation_reasons: BTreeSet<String>,
}

impl CaptureState {
    fn ingest(&mut self, event: &CdpEvent) {
        let method = event.method.as_str();
        if !matches!(
            method,
            "Debugger.scriptParsed"
                | "Debugger.scriptFailedToParse"
                | "Runtime.executionContextCreated"
                | "Runtime.executionContextDestroyed"
                | "Runtime.executionContextsCleared"
        ) {
            return;
        }
        self.events_observed += 1;
        match method {
            "Debugger.scriptParsed" => self.ingest_script(&event.params),
            "Debugger.scriptFailedToParse" => {
                self.invalid_scripts += 1;
                self.retain_event(0);
            }
            _ => self.ingest_context(method, &event.params),
        }
    }

    fn ingest_script(&mut self, params: &Value) {
        self.scripts_observed += 1;
        let value = params.as_object();
        let Some(raw_url) = value.and_then(|v| v.get("url")).and_then(Value::as_str) else {
            self.invalid_scripts += 1;
            self.retain_event(0);
            return;
        };
        let length = value
            .and_then(|v| v.get("length"))
            .and_then(safe_integer)
            .and_then(|n| u64::try_from(n).ok());
        let draft = ScriptDraft {
            raw_url: raw_url.to_string(),
            execution_context_key: context_key(value.and_then(|v| v.get("executionContextId"))),
            cdp_hash: value.and_then(|v| v.get("hash")).and_then(Value::as_str).map(str::to_string),
            length,
            is_module: value.and_then(|v| v.get("isModule")).and_then(Value::as_bool),
        };
        let bytes = script_bytes(&draft);
        if !self.retain_event(bytes) {
            return;
        }
        self.scripts.push(draft);
    }

    fn ingest_context(&mut self, method: &str, params: &Value) {
        if method == "Runtime.executionContextsCleared" {
            // Context state is not part of the retained-bytes estimate, so
            // clearing changes no budget; REA still routes it through the budget.
            if self.replace_retained_metadata(0) {
                for context in &mut self.contexts {
                    context.state = "cleared";
                }
                self.retain_event(0);
            }
            return;
        }
        let created = method == "Runtime.executionContextCreated";
        let runtime_context = if created { params.get("context") } else { Some(params) };
        let runtime_context = runtime_context.and_then(Value::as_object);
        let key = context_key(runtime_context.and_then(|context| {
            context.get(if created { "id" } else { "executionContextId" })
        }));
        let Some(key) = key else {
            self.retain_event(0);
            return;
        };
        let previous = self.contexts.iter().position(|context| context.context_key == key);
        let text = |field: &str| runtime_context.and_then(|c| c.get(field)).and_then(Value::as_str).map(str::to_string);
        let (name, origin) = if created {
            (text("name"), text("origin"))
        } else {
            previous
                .map(|index| (self.contexts[index].name.clone(), self.contexts[index].origin.clone()))
                .unwrap_or((None, None))
        };
        let draft = ContextDraft {
            state: if created { "created" } else { "destroyed" },
            name,
            origin,
            context_key: key,
        };
        let bytes = context_bytes(&draft.context_key, &draft.name, &draft.origin)
            - previous
                .map(|index| {
                    let p = &self.contexts[index];
                    context_bytes(&p.context_key, &p.name, &p.origin)
                })
                .unwrap_or(0);
        if !self.retain_event(bytes) {
            return;
        }
        match previous {
            Some(index) => self.contexts[index] = draft,
            None => self.contexts.push(draft),
        }
    }

    fn retain_event(&mut self, bytes: i64) -> bool {
        if !self.replace_retained_metadata(bytes) {
            return false;
        }
        self.events_retained += 1;
        true
    }

    fn replace_retained_metadata(&mut self, delta: i64) -> bool {
        if self.metadata_bytes + delta > INSPECTOR_MAX_RETAINED_METADATA_BYTES {
            self.events_dropped += 1;
            self.truncated = true;
            self.truncation_reasons.insert("retained_metadata_budget_exceeded".to_string());
            return false;
        }
        self.metadata_bytes += delta;
        true
    }
}

/// JS string storage estimate: UTF-16 code units at two bytes each.
fn utf16_bytes(text: Option<&str>) -> i64 {
    text.map_or(0, |t| t.encode_utf16().count() as i64 * 2)
}

fn script_bytes(draft: &ScriptDraft) -> i64 {
    RETAINED_OBJECT_OVERHEAD_BYTES
        + utf16_bytes(Some(&draft.raw_url)) * 2
        + utf16_bytes(draft.execution_context_key.as_deref())
        + utf16_bytes(draft.cdp_hash.as_deref())
}

fn context_bytes(key: &str, name: &Option<String>, origin: &Option<String>) -> i64 {
    RETAINED_OBJECT_OVERHEAD_BYTES + utf16_bytes(Some(key)) + utf16_bytes(name.as_deref()) + utf16_bytes(origin.as_deref())
}

/// A finite JS number that is a safe integer.
fn safe_integer(value: &Value) -> Option<i64> {
    if let Some(n) = value.as_i64() {
        return (n.unsigned_abs() <= 9_007_199_254_740_991).then_some(n);
    }
    let f = value.as_f64()?;
    (f.is_finite() && f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0).then_some(f as i64)
}

fn context_key(value: Option<&Value>) -> Option<String> {
    value.and_then(safe_integer).map(|n| n.to_string())
}

fn script_from_draft(draft: &ScriptDraft, location: &Value) -> Value {
    // REA hashes JSON.stringify of this insertion-ordered object.
    let stable = json!({
        "location": location,
        "execution_context_key": draft.execution_context_key,
        "cdp_hash": draft.cdp_hash,
        "length": draft.length,
        "is_module": draft.is_module,
    });
    let digest = hex::encode(Sha256::digest(stable.to_string().as_bytes()));
    json!({
        "script_key": format!("v8_script_{digest}"),
        "location": location,
        "execution_context_key": draft.execution_context_key,
        "cdp_hash": draft.cdp_hash,
        "length": draft.length,
        "is_module": draft.is_module,
        "status": "observed-loaded",
    })
}

/// Canonically authorize, deduplicate, and sort one bounded raw capture.
fn finalize_capture(input: &ObserveRuntimeInput, runtime: &Value, target: &InspectorTarget, target_location: &Value, state: &CaptureState) -> Value {
    let mut groups: Vec<(&str, Vec<&ScriptDraft>)> = Vec::new();
    let mut group_index: HashMap<&str, usize> = HashMap::new();
    for draft in &state.scripts {
        match group_index.get(draft.raw_url.as_str()) {
            Some(index) => groups[*index].1.push(draft),
            None => {
                group_index.insert(&draft.raw_url, groups.len());
                groups.push((&draft.raw_url, vec![draft]));
            }
        }
    }
    let mut unsupported_location = 0u64;
    let mut scripts: Vec<Value> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (raw_url, drafts) in groups {
        let decision = authorize_runtime_location(raw_url);
        for draft in drafts {
            match &decision {
                LocationDecision::Denied => unsupported_location += 1,
                LocationDecision::Allowed(location) => {
                    let script = script_from_draft(draft, location);
                    if seen.insert(script["script_key"].as_str().unwrap_or_default().to_string()) {
                        scripts.push(script);
                    }
                }
            }
        }
    }
    scripts.sort_by(|left, right| left["script_key"].as_str().cmp(&right["script_key"].as_str()));
    let mut contexts: Vec<Value> = state
        .contexts
        .iter()
        .map(|context| {
            json!({
                "context_key": context.context_key,
                "state": context.state,
                "name": context.name,
                "origin": context.origin,
            })
        })
        .collect();
    contexts.sort_by(|left, right| left["context_key"].as_str().cmp(&right["context_key"].as_str()));
    let mut unknowns = Vec::new();
    if target_location["kind"] == "unresolved" {
        unknowns.push("The discovery-reported file location cannot be verified; loaded script locations are resolved independently from Debugger.scriptParsed.".to_string());
    }
    unknowns.extend(
        [
            "Scripts collected before attachment may have been garbage-collected and therefore omitted.",
            "A bounded observation window cannot establish that an unobserved script or behavior never occurs.",
            "The declared Node/Electron process role is not authenticated by the Inspector protocol.",
        ]
        .iter()
        .map(|s| s.to_string()),
    );
    json!({
        "runtime": runtime,
        "target": {
            "target_id": target.id,
            "protocol_type": target.target_type,
            "attached": target.attached,
            "location": target_location,
            "runtime_kind": input.runtime_kind.as_deref().unwrap_or("unknown"),
            "runtime_kind_authority": if input.runtime_kind.is_some() { "caller-declared-unverified" } else { "not-declared" },
        },
        "capture": {
            "observation_ms": input.observation_ms,
            "events_observed": state.events_observed,
            "events_retained": state.events_retained,
            "events_dropped": state.events_dropped,
            "metadata_bytes_retained": state.metadata_bytes,
            "truncated": state.truncated,
            "truncation_reasons": state.truncation_reasons.iter().collect::<Vec<_>>(),
        },
        "scripts": {
            "items": scripts,
            "observed_total": state.scripts_observed,
            "excluded": {
                "unsupported_location": unsupported_location,
                "invalid_protocol_value": state.invalid_scripts,
            },
        },
        "execution_contexts": contexts,
        "directly_observed": [
            "Debugger.scriptParsed established script presence within the bounded capture window.",
            "Runtime execution-context lifecycle events established context creation, destruction, or clearing.",
        ],
        "unavailable_without_instrumentation": [
            "require/import caller-to-callee edges",
            "EventEmitter emissions and listener invocation",
            "Electron IPC messages and handlers",
            "script unload events",
        ],
        "unknowns": unknowns,
        "limitations": inspector_target_limitations(),
    })
}

/// Attach passively to one Inspector target and capture script/context metadata.
pub async fn observe_javascript_runtime(input: &ObserveRuntimeInput) -> Result<Evidence, WebError> {
    let discovery = discover_v8_inspector(&input.inspector_endpoint, OBSERVE_OPERATION).await?;
    let not_allowed = || browser_error(OBSERVE_OPERATION, BrowserFailureReason::TargetNotAllowed, None);
    let target = discovery
        .targets
        .iter()
        .find(|target| target.id == input.target_id)
        .ok_or_else(|| browser_error(OBSERVE_OPERATION, BrowserFailureReason::TargetNotFound, None))?;
    let location = match authorize_runtime_target_location(&target.url, &target.target_type, &discovery.product) {
        LocationDecision::Allowed(location) if !target.attached && location["kind"] != "builtin" => location,
        _ => return Err(not_allowed()),
    };
    if let Some(kind) = input.runtime_kind.as_deref() {
        let accepted = if kind == "electron-preload" || kind == "electron-renderer" {
            target.target_type == "page"
        } else {
            target.target_type == "node"
        };
        if !accepted {
            return Err(not_allowed());
        }
    }
    let mut connection = CdpConnection::connect(&target.web_socket_url, OBSERVE_OPERATION).await?;
    let captured = capture_events(&mut connection, input.observation_ms).await;
    connection.close().await;
    let events = captured?;
    let mut state = CaptureState::default();
    for event in &events {
        state.ingest(event);
    }
    let result = finalize_capture(input, &discovery.runtime, target, &location, &state);
    let mut parameters = json!({
        "inspector_endpoint": input.inspector_endpoint,
        "target_id": input.target_id,
    });
    if let Some(kind) = &input.runtime_kind {
        parameters["runtime_kind"] = json!(kind);
    }
    parameters["observation_ms"] = json!(input.observation_ms);
    runtime_evidence(OBSERVE_OPERATION, parameters, result, &discovery)
}

async fn capture_events(connection: &mut CdpConnection, observation_ms: u64) -> Result<Vec<CdpEvent>, WebError> {
    connection.send("Runtime.enable", json!({}), None).await?;
    connection.send("Debugger.enable", json!({}), None).await?;
    connection.collect_for(Duration::from_millis(observation_ms)).await?;
    Ok(connection.take_events())
}

fn runtime_evidence(operation: &str, parameters: Value, result: Value, discovery: &InspectorDiscovery) -> Result<Evidence, WebError> {
    let mut limitations = vec![MISSING_SUBJECT.to_string()];
    limitations.extend(
        result["limitations"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|item| item.as_str().map(str::to_string)),
    );
    limitations.push("Runtime host platform and architecture were not observed.".to_string());
    let predicate = if operation == LIST_OPERATION {
        "rea.javascript-runtime-target-list"
    } else {
        "rea.javascript-runtime-observation"
    };
    create_evidence(
        None,
        EvidenceProvider {
            id: V8_INSPECTOR_PROVIDER_ID.to_string(),
            name: V8_INSPECTOR_PROVIDER_NAME.to_string(),
            version: Some(V8_INSPECTOR_PROVIDER_VERSION.to_string()),
        },
        EvidenceObservation {
            predicate_type: Some(predicate.to_string()),
            operation: operation.to_string(),
            parameters,
            normalized_result: result,
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Observed),
            authority: Some(EvidenceAuthority::ExternalService),
            environment: Some(ExecutionEnvironment {
                id: format!("{}@{}", discovery.product, discovery.protocol_version),
                platform: "unknown".to_string(),
                architecture: "unknown".to_string(),
                isolation: IsolationLevel::None,
            }),
            limitations: Some(limitations),
            locations: Some(vec![]),
            evidence_links: Some(vec![]),
        },
    )
    .map_err(WebError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_socket_is_pinned_to_exact_target_and_trusted_host() {
        assert_eq!(
            validated_inspector_web_socket("http://127.0.0.1:9229", "abc", "ws://localhost:9229/abc").as_deref(),
            Some("ws://127.0.0.1:9229/abc")
        );
        for bad in [
            "ws://127.0.0.1:9230/abc",
            "wss://127.0.0.1:9229/abc",
            "ws://u:p@127.0.0.1:9229/abc",
            "ws://127.0.0.1:9229/abc?x=1",
            "ws://127.0.0.1:9229/other",
        ] {
            assert_eq!(validated_inspector_web_socket("http://127.0.0.1:9229", "abc", bad), None, "{bad}");
        }
    }

    #[test]
    fn observe_input_defaults_and_rejections() {
        let parsed = parse_observe_runtime_input(&json!({
            "inspector_endpoint": "http://127.0.0.1:9229/",
            "target_id": "  T1 ",
        }))
        .expect("input");
        assert_eq!(parsed.inspector_endpoint, "http://127.0.0.1:9229");
        assert_eq!(parsed.target_id, "T1");
        assert_eq!(parsed.observation_ms, 100);
        assert!(parse_observe_runtime_input(&json!({
            "inspector_endpoint": "http://localhost:9229",
            "target_id": "T1",
        }))
        .is_err());
        assert!(parse_observe_runtime_input(&json!({
            "inspector_endpoint": "http://127.0.0.1:9229",
            "target_id": "T1",
            "runtime_kind": "browser",
        }))
        .is_err());
    }

    #[test]
    fn metadata_budget_drops_and_marks_truncation() {
        let mut state = CaptureState {
            metadata_bytes: INSPECTOR_MAX_RETAINED_METADATA_BYTES - 10,
            ..CaptureState::default()
        };
        state.ingest(&CdpEvent {
            method: "Debugger.scriptParsed".into(),
            params: json!({ "url": "node:fs", "executionContextId": 1 }),
            session_id: None,
        });
        assert_eq!(state.events_dropped, 1);
        assert!(state.truncated);
        assert!(state.scripts.is_empty());
        assert_eq!(state.scripts_observed, 1);
    }
}
