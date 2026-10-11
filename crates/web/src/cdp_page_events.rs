//! Passive CDP event normalization for `inspect_web_page`
//! (port of REA browser/CdpCaptureEvents.ts and CdpCaptureEventHandlers.ts).
//!
//! Request and response headers are reduced to an allowlist. `Cookie`,
//! `Set-Cookie`, and `Authorization` are removed before that allowlist is read,
//! so credential values never enter captured network data.

use std::collections::{HashMap, HashSet};

use serde_json::{json, Map, Value};

use crate::cdp_completeness::CdpCaptureCompleteness;
use crate::cdp_connection::CdpEvent;
use crate::cdp_values::{
    allowed_url, cdp_str, exclusion_reason_for_url, finite_f64, header_get, header_map, integer_or_null,
    is_http_url, json_number, record, records, safe_integer,
};

const SCRIPT_LIMIT: usize = 50_000;
const SCRIPT_METADATA_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct CapturedScript {
    pub script_id: String,
    pub raw_url: String,
    pub url: String,
    pub origin: String,
    pub hash: Option<String>,
    pub length: Option<i64>,
    pub is_module: Option<bool>,
    pub language: Option<String>,
    pub source_map_url: Option<String>,
    pub frame_id: Option<String>,
}

pub struct PageEvents {
    pub scripts: HashMap<String, CapturedScript>,
    script_order: Vec<String>,
    pub network: HashMap<String, Value>,
    network_order: Vec<String>,
    timestamps: HashMap<String, f64>,
    malformed_redirects: HashSet<String>,
    allowed_websockets: HashSet<String>,
    execution_frames: HashMap<String, String>,
    pub console: Vec<Value>,
    pub websockets: Vec<Value>,
    pub response_metadata: Vec<Value>,
    pub agent_hints: Vec<Value>,
    pub completeness: CdpCaptureCompleteness,
    pub origin_violation: bool,
    pub navigation_during_capture: bool,
    main_frame_id: Option<String>,
    committed_document: Option<String>,
    include_console_text: bool,
    include_json_body_shapes: bool,
    include_websocket_shapes: bool,
    allowed_origins: Vec<String>,
}

impl PageEvents {
    pub fn new(allowed_origins: Vec<String>, include_console_text: bool, include_json: bool, include_ws: bool) -> Self {
        Self {
            scripts: HashMap::new(),
            script_order: Vec::new(),
            network: HashMap::new(),
            network_order: Vec::new(),
            timestamps: HashMap::new(),
            malformed_redirects: HashSet::new(),
            allowed_websockets: HashSet::new(),
            execution_frames: HashMap::new(),
            console: Vec::new(),
            websockets: Vec::new(),
            response_metadata: Vec::new(),
            agent_hints: Vec::new(),
            completeness: CdpCaptureCompleteness::new(&[
                "network_requests",
                "console_events",
                "websocket_connections",
                "websocket_frames",
                "metadata",
            ]),
            origin_violation: false,
            navigation_during_capture: false,
            main_frame_id: None,
            committed_document: None,
            include_console_text,
            include_json_body_shapes: include_json,
            include_websocket_shapes: include_ws,
            allowed_origins,
        }
    }

    /// The authorized main frame is the document already reported by `getFrameTree`.
    pub fn begin_authorized_frame(&mut self, frame_id: &str, document_key: Option<String>) {
        self.main_frame_id = Some(frame_id.to_string());
        self.origin_violation = false;
        self.navigation_during_capture = false;
        self.committed_document = document_key;
        self.scripts.clear();
        self.script_order.clear();
        self.network.clear();
        self.network_order.clear();
        self.timestamps.clear();
        self.malformed_redirects.clear();
        self.allowed_websockets.clear();
        self.execution_frames.clear();
        self.console.clear();
        self.websockets.clear();
        self.response_metadata.clear();
        self.agent_hints.clear();
        self.completeness.reset();
        if !self.include_console_text {
            self.completeness.exclude("console_text", "not_approved", None);
        }
        if !self.include_json_body_shapes {
            self.completeness.exclude("json_body_shapes", "not_approved", None);
        }
        if !self.include_websocket_shapes {
            self.completeness.exclude("websocket_shapes", "not_approved", None);
        }
    }

    pub fn note_final_frame(&mut self, frame_id: &str) {
        self.main_frame_id = Some(frame_id.to_string());
        self.committed_document = None;
    }

    pub fn ingest(&mut self, event: CdpEvent) {
        let Some(params) = event.params.as_object().cloned() else {
            return;
        };
        match event.method.as_str() {
            "Runtime.executionContextCreated" => self.context_created(&params),
            "Runtime.executionContextDestroyed" => self.context_destroyed(&params),
            "Runtime.executionContextsCleared" => self.execution_frames.clear(),
            "Debugger.scriptParsed" => self.script_parsed(&params),
            "Network.requestWillBeSent" => self.request_will_be_sent(&params),
            "Network.responseReceived" => self.response_received(&params),
            "Network.loadingFinished" => self.loading_finished(&params),
            "Runtime.consoleAPICalled" => self.console_called(&params),
            "Page.frameNavigated" => self.frame_navigated(&params),
            "Network.webSocketCreated" => self.websocket_created(&params),
            "Network.webSocketFrameSent" => self.websocket_frame(&params, "sent"),
            "Network.webSocketFrameReceived" => self.websocket_frame(&params, "received"),
            _ => {}
        }
    }

    pub fn network_requests(&self) -> Vec<Value> {
        self.network_order
            .iter()
            .filter_map(|id| self.network.get(id).cloned())
            .collect()
    }

    pub fn scripts_in_order(&self) -> Vec<CapturedScript> {
        self.script_order
            .iter()
            .filter_map(|id| self.scripts.get(id).cloned())
            .collect()
    }

    fn context_created(&mut self, params: &Map<String, Value>) {
        let Some(context) = params.get("context").and_then(record) else {
            return;
        };
        let Some(key) = context.get("id").and_then(crate::cdp_values::execution_context_key) else {
            return;
        };
        let Some(frame_id) = context
            .get("auxData")
            .and_then(record)
            .and_then(|aux| aux.get("frameId"))
            .and_then(cdp_str)
        else {
            return;
        };
        self.execution_frames.insert(key, frame_id.to_string());
    }

    fn context_destroyed(&mut self, params: &Map<String, Value>) {
        if let Some(key) = params.get("executionContextId").and_then(crate::cdp_values::execution_context_key) {
            self.execution_frames.remove(&key);
        }
    }

    fn script_parsed(&mut self, params: &Map<String, Value>) {
        let Some(script_id) = params.get("scriptId").and_then(cdp_str) else {
            self.completeness.exclude("scripts", "invalid_protocol_value", Some(1));
            return;
        };
        let raw_url = params.get("url").and_then(cdp_str).unwrap_or("");
        let Some(sanitized) = allowed_url(Some(raw_url).filter(|url| !url.is_empty()), &self.allowed_origins) else {
            self.completeness
                .exclude("scripts", exclusion_reason_for_url(if raw_url.is_empty() { None } else { Some(raw_url) }), Some(1));
            return;
        };
        let Some(origin) = sanitized.origin else {
            self.completeness.exclude("scripts", "unattributed_origin", Some(1));
            return;
        };
        if self.scripts.len() >= SCRIPT_LIMIT {
            self.completeness.exclude("scripts", "resource_budget_exhausted", Some(1));
            return;
        }
        let context_key = params.get("executionContextId").and_then(crate::cdp_values::execution_context_key);
        let frame_id = context_key.as_ref().and_then(|key| self.execution_frames.get(key).cloned());
        let source_map = params
            .get("sourceMapURL")
            .and_then(cdp_str)
            .filter(|url| !url.is_empty())
            .and_then(|declared| resolve_source_map(declared, raw_url, &self.allowed_origins));
        let script = CapturedScript {
            script_id: script_id.to_string(),
            raw_url: raw_url.to_string(),
            url: sanitized.url,
            origin,
            hash: params.get("hash").and_then(cdp_str).map(str::to_string),
            length: params.get("length").and_then(safe_integer).filter(|length| *length >= 0),
            is_module: params.get("isModule").and_then(Value::as_bool),
            language: params.get("scriptLanguage").and_then(cdp_str).map(str::to_string),
            source_map_url: source_map,
            frame_id,
        };
        let retained = script_metadata_bytes(&script);
        if retained > SCRIPT_METADATA_BYTES {
            self.completeness.exclude("scripts", "resource_budget_exhausted", Some(1));
            return;
        }
        if !self.script_order.iter().any(|id| id == script_id) {
            self.script_order.push(script_id.to_string());
        }
        self.scripts.insert(script_id.to_string(), script);
    }

    fn request_will_be_sent(&mut self, params: &Map<String, Value>) {
        let Some(request_id) = params.get("requestId").and_then(cdp_str) else {
            self.completeness.exclude("network_requests", "invalid_protocol_value", Some(1));
            return;
        };
        if self.malformed_redirects.contains(request_id) {
            return;
        }
        let Some(request) = params.get("request").and_then(record) else {
            self.completeness.exclude("network_requests", "invalid_protocol_value", Some(1));
            self.remove_request(request_id);
            return;
        };
        let raw_url = request.get("url").and_then(cdp_str);
        let Some(sanitized) = allowed_url(raw_url, &self.allowed_origins) else {
            self.completeness
                .exclude("network_requests", exclusion_reason_for_url(raw_url), Some(1));
            self.remove_request(request_id);
            return;
        };
        let mut redirects = self
            .network
            .get(request_id)
            .and_then(|current| current.get("redirects"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if let Some(redirect) = params.get("redirectResponse").and_then(record) {
            let raw_response = redirect.get("url").and_then(cdp_str);
            let Some(response_url) = allowed_url(raw_response, &self.allowed_origins) else {
                self.completeness.exclude(
                    "network_requests",
                    if raw_response.is_none_or(str::is_empty) {
                        "invalid_protocol_value"
                    } else {
                        exclusion_reason_for_url(raw_response)
                    },
                    Some(1),
                );
                self.remove_request(request_id);
                return;
            };
            if let Some(previous) = self.network.get(request_id) {
                redirects.push(json!({
                    "url": previous["url"].as_str().unwrap_or(""),
                    "response_url": response_url.url,
                    "method": previous["method"].as_str().unwrap_or("GET"),
                    "resource_type": previous.get("resource_type").cloned().unwrap_or(Value::Null),
                    "status": redirect.get("status").and_then(finite_f64).map(json_number).unwrap_or(Value::Null),
                    "mime_type": redirect.get("mimeType").and_then(cdp_str),
                    "encoded_data_length": redirect.get("encodedDataLength").and_then(finite_f64).map(|n| json_number(n.max(0.0))).unwrap_or(Value::Null),
                    "request_timestamp": self.timestamps.get(request_id).copied().map(json_number).unwrap_or(Value::Null),
                    "redirect_event_timestamp": params.get("timestamp").and_then(finite_f64).map(json_number).unwrap_or(Value::Null),
                }));
            } else {
                self.completeness.attach_limited("network_requests");
            }
        }
        let initiator = params.get("initiator").and_then(record);
        let frame = initiator.and_then(initiator_location);
        let raw_initiator = frame.and_then(|frame| frame.get("url")).and_then(cdp_str);
        let initiator_url = allowed_url(raw_initiator, &self.allowed_origins);
        if raw_initiator.is_some() && initiator_url.is_none() {
            self.completeness
                .exclude("network_initiators", exclusion_reason_for_url(raw_initiator), Some(1));
        }
        // Headers, including Cookie and Authorization, are intentionally unread.
        let _redacted_headers = request.get("headers").map(header_map);
        let entry = json!({
            "request_id": request_id,
            "url": sanitized.url,
            "origin": sanitized.origin.unwrap_or_default(),
            "method": request.get("method").and_then(cdp_str).unwrap_or("GET"),
            "resource_type": params.get("type").and_then(cdp_str),
            "status": Value::Null,
            "mime_type": Value::Null,
            "encoded_data_length": Value::Null,
            "redirects": redirects,
            "initiator": {
                "type": initiator.and_then(|item| item.get("type")).and_then(cdp_str).unwrap_or("other"),
                "url": initiator_url.map(|url| url.url),
                "line": frame.map(|item| integer_or_null(item.get("lineNumber").unwrap_or(&Value::Null))).unwrap_or(Value::Null),
                "column": frame.map(|item| integer_or_null(item.get("columnNumber").unwrap_or(&Value::Null))).unwrap_or(Value::Null),
            },
            "body_shapes": body_shapes_not_approved(self.include_json_body_shapes),
        });
        if !self.network_order.iter().any(|id| id == request_id) {
            self.network_order.push(request_id.to_string());
        }
        self.network.insert(request_id.to_string(), entry);
        if let Some(timestamp) = params.get("timestamp").and_then(finite_f64) {
            self.timestamps.insert(request_id.to_string(), timestamp);
        } else {
            self.timestamps.remove(request_id);
        }
    }

    fn response_received(&mut self, params: &Map<String, Value>) {
        let Some(request_id) = params.get("requestId").and_then(cdp_str) else {
            self.completeness.exclude("network_requests", "invalid_protocol_value", Some(1));
            return;
        };
        if self.malformed_redirects.contains(request_id) {
            return;
        }
        let Some(current) = self.network.get(request_id).cloned() else {
            return;
        };
        let Some(response) = params.get("response").and_then(record) else {
            self.completeness.exclude("network_requests", "invalid_protocol_value", Some(1));
            self.remove_request(request_id);
            return;
        };
        let raw_url = response.get("url").and_then(cdp_str);
        let Some(sanitized) = allowed_url(raw_url, &self.allowed_origins) else {
            self.completeness
                .exclude("network_requests", exclusion_reason_for_url(raw_url), Some(1));
            self.remove_request(request_id);
            return;
        };
        let mut updated = current;
        if let Some(object) = updated.as_object_mut() {
            object.insert(
                "status".to_string(),
                response.get("status").and_then(finite_f64).map(json_number).unwrap_or(Value::Null),
            );
            object.insert(
                "mime_type".to_string(),
                response.get("mimeType").and_then(cdp_str).map(|text| Value::String(text.to_string())).unwrap_or(Value::Null),
            );
        }
        self.network.insert(request_id.to_string(), updated);
        let metadata = safe_response_metadata(request_id, &sanitized.url, response, &self.allowed_origins);
        self.response_metadata.push(metadata.0);
        self.agent_hints.extend(metadata.1);
    }

    fn loading_finished(&mut self, params: &Map<String, Value>) {
        let Some(request_id) = params.get("requestId").and_then(cdp_str) else {
            return;
        };
        let Some(mut current) = self.network.get(request_id).cloned() else {
            return;
        };
        let length = params.get("encodedDataLength").and_then(finite_f64).unwrap_or(0.0).max(0.0);
        if let Some(object) = current.as_object_mut() {
            object.insert("encoded_data_length".to_string(), json_number(length));
        }
        self.network.insert(request_id.to_string(), current);
    }

    fn console_called(&mut self, params: &Map<String, Value>) {
        let Some(frame) = params
            .get("stackTrace")
            .and_then(record)
            .and_then(|stack| stack.get("callFrames"))
            .and_then(Value::as_array)
            .and_then(|frames| frames.first())
            .and_then(record)
        else {
            self.completeness.exclude("console_events", "unattributed_origin", Some(1));
            return;
        };
        let raw_url = frame.get("url").and_then(cdp_str);
        let Some(source) = allowed_url(raw_url, &self.allowed_origins) else {
            self.completeness
                .exclude("console_events", exclusion_reason_for_url(raw_url), Some(1));
            return;
        };
        let arguments = records(params.get("args").unwrap_or(&Value::Null));
        let argument_types: Vec<&str> = arguments
            .iter()
            .map(|argument| argument.get("type").and_then(cdp_str).unwrap_or("unknown"))
            .collect();
        self.console.push(json!({
            "type": params.get("type").and_then(cdp_str).unwrap_or("unknown"),
            "timestamp": params.get("timestamp").and_then(finite_f64).unwrap_or(0.0),
            "argument_types": argument_types,
            "url": source.url,
            "line": integer_or_null(frame.get("lineNumber").unwrap_or(&Value::Null)),
            "column": integer_or_null(frame.get("columnNumber").unwrap_or(&Value::Null)),
            "text_capture": if self.include_console_text {
                console_text(&arguments)
            } else {
                json!({ "status": "not_approved", "values": [], "retained_bytes": 0 })
            },
        }));
    }

    fn frame_navigated(&mut self, params: &Map<String, Value>) {
        let Some(main_frame) = self.main_frame_id.clone() else {
            return;
        };
        let Some(frame) = params.get("frame").and_then(record) else {
            return;
        };
        if frame.get("id").and_then(cdp_str) != Some(main_frame.as_str()) {
            return;
        }
        let raw_url = frame.get("url").and_then(cdp_str).unwrap_or("");
        let loader = frame.get("loaderId").and_then(cdp_str).unwrap_or("");
        let document = format!("{loader}\0{raw_url}");
        if self.committed_document.as_deref() == Some(document.as_str()) {
            return;
        }
        self.committed_document = Some(document);
        self.navigation_during_capture = true;
        if is_http_url(raw_url) && allowed_url(Some(raw_url), &self.allowed_origins).is_none() {
            self.origin_violation = true;
        }
    }

    fn websocket_created(&mut self, params: &Map<String, Value>) {
        let Some(request_id) = params.get("requestId").and_then(cdp_str) else {
            self.completeness.exclude("websocket_connections", "invalid_protocol_value", Some(1));
            return;
        };
        let Some(raw_url) = params.get("url").and_then(cdp_str) else {
            self.completeness.exclude("websocket_connections", "invalid_protocol_value", Some(1));
            return;
        };
        let Ok(mut parsed) = url::Url::parse(raw_url) else {
            self.completeness.exclude("websocket_connections", "unsupported_url", Some(1));
            return;
        };
        match parsed.scheme() {
            "ws" => parsed.set_scheme("http").ok(),
            "wss" => parsed.set_scheme("https").ok(),
            _ => {
                self.completeness.exclude("websocket_connections", "unsupported_url", Some(1));
                return;
            }
        };
        let origin = parsed.origin().ascii_serialization();
        if !self.allowed_origins.iter().any(|allowed| allowed == &origin) {
            self.completeness.exclude("websocket_connections", "disallowed_origin", Some(1));
            return;
        }
        self.allowed_websockets.insert(request_id.to_string());
    }

    fn websocket_frame(&mut self, params: &Map<String, Value>, direction: &str) {
        let Some(request_id) = params.get("requestId").and_then(cdp_str) else {
            return;
        };
        if !self.network.contains_key(request_id) && !self.allowed_websockets.contains(request_id) {
            return;
        }
        let response = params.get("response").and_then(record);
        let payload = response.and_then(|item| item.get("payloadData")).and_then(cdp_str).unwrap_or("");
        let opcode = response
            .and_then(|item| item.get("opcode"))
            .and_then(finite_f64)
            .unwrap_or(0.0)
            .trunc()
            .max(0.0) as i64;
        self.websockets.push(json!({
            "request_id": request_id,
            "direction": direction,
            "opcode": opcode,
            "payload_bytes": payload.len() as i64,
            "payload_shape": if self.include_websocket_shapes {
                json!({ "format": if opcode == 1 { "text" } else { "binary" }, "json_shape": Value::Null })
            } else {
                Value::Null
            },
        }));
    }

    fn remove_request(&mut self, request_id: &str) {
        self.network.remove(request_id);
        self.network_order.retain(|id| id != request_id);
        self.timestamps.remove(request_id);
    }
}

fn body_shapes_not_approved(include: bool) -> Value {
    json!({
        "status": if include { "unavailable" } else { "not_approved" },
        "request": Value::Null,
        "response": Value::Null,
    })
}

fn resolve_source_map(declared: &str, script_url: &str, allowed_origins: &[String]) -> Option<String> {
    let base = url::Url::parse(script_url).ok()?;
    let resolved = base.join(declared).ok()?;
    allowed_url(Some(resolved.as_str()), allowed_origins).map(|url| url.url)
}

fn script_metadata_bytes(script: &CapturedScript) -> usize {
    script.script_id.len()
        + script.raw_url.len()
        + script.url.len()
        + script.origin.len()
        + script.hash.as_ref().map_or(0, String::len)
        + script.language.as_ref().map_or(0, String::len)
        + script.frame_id.as_ref().map_or(0, String::len)
        + script.source_map_url.as_ref().map_or(0, String::len)
}

fn initiator_location(initiator: &Map<String, Value>) -> Option<&Map<String, Value>> {
    let mut stack = initiator.get("stack").and_then(record);
    for _ in 0..32 {
        let Some(current) = stack else {
            break;
        };
        if let Some(frame) = current
            .get("callFrames")
            .and_then(Value::as_array)
            .and_then(|frames| frames.first())
            .and_then(record)
        {
            return Some(frame);
        }
        stack = current.get("parent").and_then(record);
    }
    initiator.get("url").and_then(cdp_str).is_some().then_some(initiator)
}

fn console_text(arguments: &[&Map<String, Value>]) -> Value {
    let mut values = Vec::new();
    let mut retained = 0_i64;
    for (index, argument) in arguments.iter().enumerate() {
        let Some(kind) = argument.get("type").and_then(cdp_str) else {
            continue;
        };
        if !matches!(kind, "string" | "number" | "boolean" | "undefined") {
            continue;
        }
        let Some(text) = argument.get("value").map(|value| match value {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        }) else {
            continue;
        };
        retained += text.len() as i64;
        values.push(json!({
            "argument_index": index as i64,
            "type": kind,
            "text": text,
        }));
    }
    json!({ "status": "included", "values": values, "retained_bytes": retained })
}

/// Allowlisted response metadata. Credential headers are already gone.
pub fn safe_response_metadata(
    request_id: &str,
    url: &str,
    response: &Map<String, Value>,
    allowed_origins: &[String],
) -> (Value, Vec<Value>) {
    let headers = response.get("headers").map(header_map).unwrap_or_default();
    let mut agent_hints = Vec::new();
    for name in ["x-model-context", "x-webmcp", "mcp-server"] {
        if headers.contains_key(name) {
            agent_hints.push(json!({
                "mechanism": "response_header",
                "declaration": name,
                "url": Value::Null,
                "trust": "page-declared-untrusted",
            }));
        }
    }
    if let Ok(parsed) = url::Url::parse(url) {
        if matches!(
            parsed.path(),
            "/.well-known/ai-plugin.json" | "/.well-known/mcp" | "/.well-known/model-context"
        ) {
            agent_hints.push(json!({
                "mechanism": "well_known_resource",
                "declaration": parsed.path(),
                "url": url,
                "trust": "page-declared-untrusted",
            }));
        }
    }
    let _ = allowed_origins;
    let response_value = json!({
        "request_id": request_id,
        "url": url,
        "mime_type": response.get("mimeType").and_then(cdp_str).map(|text| text.trim().to_ascii_lowercase()),
        "content_length": nonnegative_header(header_get(&headers, "content-length")),
        "content_encoding": bounded_header(header_get(&headers, "content-encoding")),
        "csp": empty_csp(),
        "links": [],
        "policies": {
            "coop": policy_token(header_get(&headers, "cross-origin-opener-policy")),
            "coep": policy_token(header_get(&headers, "cross-origin-embedder-policy")),
            "corp": policy_token(header_get(&headers, "cross-origin-resource-policy")),
            "referrer_policy": referrer_policy(header_get(&headers, "referrer-policy")),
            "x_content_type_options": policy_token(header_get(&headers, "x-content-type-options")),
            "permissions_policy_features": [],
        },
    });
    (response_value, agent_hints)
}

fn empty_csp() -> Value {
    json!({ "directives": [], "nonce_count": 0, "hash_count": 0 })
}

fn bounded_header(value: Option<&str>) -> Value {
    value
        .map(|text| Value::String(text.trim().to_ascii_lowercase()))
        .unwrap_or(Value::Null)
}

fn nonnegative_header(value: Option<&str>) -> Value {
    let Some(value) = value else {
        return Value::Null;
    };
    let Ok(number) = value.trim().parse::<f64>() else {
        return Value::Null;
    };
    if !number.is_finite() {
        return Value::Null;
    }
    json!(number.trunc().max(0.0) as i64)
}

fn policy_token(value: Option<&str>) -> Value {
    let Some(token) = value.map(|text| text.trim().to_ascii_lowercase()) else {
        return Value::Null;
    };
    if token.is_empty() {
        return Value::Null;
    }
    let mut chars = token.chars();
    let Some(first) = chars.next() else {
        return Value::Null;
    };
    if !first.is_ascii_lowercase()
        || !chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '.' | '-'))
    {
        return Value::Null;
    }
    Value::String(token)
}

fn referrer_policy(value: Option<&str>) -> Value {
    const POLICIES: &[&str] = &[
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    ];
    let mut selected = None;
    for raw in value.unwrap_or("").split(',') {
        let token = raw.trim().to_ascii_lowercase();
        if token.is_empty() {
            continue;
        }
        if !token.chars().all(|ch| ch.is_ascii_lowercase() || ch == '-') {
            return Value::Null;
        }
        if POLICIES.contains(&token.as_str()) {
            selected = Some(token);
        }
    }
    selected.map(Value::String).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn credential_headers_never_reach_response_metadata() {
        let response = json!({
            "url": "http://127.0.0.1:9/api",
            "mimeType": "application/json",
            "status": 200,
            "headers": {
                "Content-Type": "application/json",
                "Content-Length": "12",
                "Set-Cookie": "sid=tracewise-secret-cookie",
                "Authorization": "Bearer tracewise-secret-token",
                "Cookie": "sid=tracewise-secret-cookie"
            }
        });
        let (metadata, _) = safe_response_metadata(
            "1",
            "http://127.0.0.1:9/api",
            response.as_object().unwrap(),
            &["http://127.0.0.1:9".to_string()],
        );
        let encoded = metadata.to_string();
        assert!(!encoded.contains("tracewise-secret-cookie"));
        assert!(!encoded.contains("tracewise-secret-token"));
        assert!(!encoded.to_ascii_lowercase().contains("set-cookie"));
        assert!(!encoded.to_ascii_lowercase().contains("authorization"));
        assert_eq!(metadata["content_length"], 12);
        assert_eq!(metadata["mime_type"], "application/json");
    }
}
