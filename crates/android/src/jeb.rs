//! JEB through a caller-run MCP client (REA `JebMcpEndpoint.ts`,
//! `JebMcpConnection.ts`, `JebProvider.ts`).
//!
//! JEB is commercial and is never installed, launched or opened by this code.
//! The provider speaks MCP over streamable HTTP to a loopback endpoint a user
//! already runs (`REA_JEB_MCP_URL`, default `http://127.0.0.1:8425/mcp`). With
//! nothing listening, every operation answers `capability_unavailable`.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};
use url::Url;

use crate::cancel::CancelToken;
use crate::config::Env;
use crate::error::{Error, Failure, Outcome};

pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:8425/mcp";
pub const ENV_URL: &str = "REA_JEB_MCP_URL";

const PROTOCOL_VERSION: &str = "2025-06-18";
const CALL_TIMEOUT: Duration = Duration::from_secs(300);

/// `parseJebMcpEndpoint`: only scheme, host and port select the engine.
pub fn parse_endpoint(value: Option<&str>) -> Result<Url, String> {
    let raw = match value {
        Some(text) if !text.is_empty() => text,
        _ => DEFAULT_ENDPOINT,
    };
    let url = Url::parse(raw).map_err(|_| "Expected an absolute http(s) URL".to_string())?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err("Only http and https JEB MCP endpoints are supported".to_string());
    }
    let host = url.host_str().unwrap_or_default();
    if host != "127.0.0.1" && host != "[::1]" {
        return Err("JEB MCP endpoint must use a literal loopback host (127.0.0.1 or ::1)".to_string());
    }
    if !url.username().is_empty() || url.password().is_some_and(|p| !p.is_empty()) {
        return Err("Embedding credentials in the JEB MCP endpoint is not supported; configure authentication with the engine".to_string());
    }
    if url.query().is_some_and(|q| !q.is_empty()) || url.fragment().is_some_and(|f| !f.is_empty()) || raw.contains('?') || raw.contains('#') {
        return Err("JEB MCP endpoint query strings and fragments are not supported".to_string());
    }
    Ok(url)
}

/// One observation from the engine, ready to become Evidence.
pub struct Execution {
    pub result: Value,
    /// Provider identity (`id`, `name`, `version`) as of this observation.
    pub provider: Value,
    pub raw_result: Value,
    pub limitations: Vec<String>,
}

/// A request the provider accepts, after input defaults are applied.
#[derive(Debug, Clone)]
pub enum Request {
    Client,
    Open { path: String },
    Units { filter: Option<String>, parent_unit_path: Option<String>, index: u64, count: u64 },
    Decompile { unit_path: Option<String>, item_address: String, item_kind: String },
}

impl Request {
    pub fn operation(&self) -> &'static str {
        match self {
            Request::Client => "inspect_jeb_client",
            Request::Open { .. } => "open_jeb_project",
            Request::Units { .. } => "list_jeb_units",
            Request::Decompile { .. } => "decompile_jeb_item",
        }
    }

    /// Parse validated arguments (the schema check happens before this).
    pub fn from_args(tool: &str, args: &Value) -> Option<Request> {
        let text = |key: &str| args.get(key).and_then(Value::as_str).map(str::to_string);
        Some(match tool {
            "inspect_jeb_client" => Request::Client,
            "open_jeb_project" => Request::Open { path: text("path")? },
            "list_jeb_units" => Request::Units {
                filter: text("filter"),
                parent_unit_path: text("parent_unit_path"),
                index: args.get("index").and_then(Value::as_u64).unwrap_or(0),
                count: args.get("count").and_then(Value::as_u64).unwrap_or(100),
            },
            "decompile_jeb_item" => Request::Decompile {
                unit_path: text("unit_path"),
                item_address: text("item_address")?,
                item_kind: text("item_kind")?,
            },
            _ => return None,
        })
    }

    /// Parameters as REA records them: the validated input with defaults.
    pub fn parameters(&self) -> Value {
        match self {
            Request::Client => json!({}),
            Request::Open { path } => json!({ "path": path }),
            Request::Units { filter, parent_unit_path, index, count } => {
                let mut map = Map::new();
                if let Some(filter) = filter {
                    map.insert("filter".into(), json!(filter));
                }
                if let Some(parent) = parent_unit_path {
                    map.insert("parent_unit_path".into(), json!(parent));
                }
                map.insert("index".into(), json!(index));
                map.insert("count".into(), json!(count));
                Value::Object(map)
            }
            Request::Decompile { unit_path, item_address, item_kind } => {
                let mut map = Map::new();
                if let Some(unit) = unit_path {
                    map.insert("unit_path".into(), json!(unit));
                }
                map.insert("item_address".into(), json!(item_address));
                map.insert("item_kind".into(), json!(item_kind));
                Value::Object(map)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MCP over streamable HTTP
// ---------------------------------------------------------------------------

/// Hard cap on one HTTP response (headers and body) from the engine.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 64 * 1024;
/// How often a waiting request looks at its cancellation token.
const IO_POLL: Duration = Duration::from_millis(50);

struct Connection {
    endpoint: Url,
    session_id: Option<String>,
    next_id: u64,
    connected: bool,
}

/// A transport or protocol failure with the text REA's MCP SDK would carry.
enum TransportError {
    Failed(String),
    Cancelled,
    TooLarge,
}

fn fetch_failed() -> TransportError {
    TransportError::Failed("fetch failed".to_string())
}

struct HttpResponse {
    status: u16,
    content_type: String,
    session_id: Option<String>,
    body: Vec<u8>,
}

/// Decode `Transfer-Encoding: chunked`; `None` when the framing is malformed.
fn dechunk(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = raw;
    loop {
        let line_end = rest.windows(2).position(|w| w == b"\r\n")?;
        let size_text = std::str::from_utf8(&rest[..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        if rest.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

/// One `POST` over a fresh plain-HTTP connection (`Connection: close`), read in
/// short slices so that a cancelled call stops waiting, with every buffer capped.
fn http_post(
    endpoint: &Url,
    session_id: Option<&str>,
    body: &str,
    cancel: &CancelToken,
    deadline: Instant,
) -> Result<HttpResponse, TransportError> {
    use std::io::{ErrorKind, Read, Write};
    use std::net::TcpStream;
    // The engine speaks to loopback only; TLS is not available here.
    if endpoint.scheme() != "http" {
        return Err(fetch_failed());
    }
    let addresses = endpoint.socket_addrs(|| Some(80)).map_err(|_| fetch_failed())?;
    let address = addresses.first().ok_or_else(fetch_failed)?;
    if cancel.is_cancelled() {
        return Err(TransportError::Cancelled);
    }
    let mut stream = TcpStream::connect_timeout(address, Duration::from_secs(5)).map_err(|_| fetch_failed())?;
    let _ = stream.set_nodelay(true);
    stream.set_write_timeout(Some(Duration::from_secs(10))).map_err(|_| fetch_failed())?;
    stream.set_read_timeout(Some(IO_POLL)).map_err(|_| fetch_failed())?;
    let mut target = endpoint.path().to_string();
    if let Some(query) = endpoint.query() {
        target.push('?');
        target.push_str(query);
    }
    let host = match endpoint.port() {
        Some(port) => format!("{}:{port}", endpoint.host_str().unwrap_or_default()),
        None => endpoint.host_str().unwrap_or_default().to_string(),
    };
    let mut request = format!(
        "POST {target} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(session) = session_id {
        request.push_str(&format!("Mcp-Session-Id: {session}\r\nMcp-Protocol-Version: {PROTOCOL_VERSION}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream.write_all(request.as_bytes()).map_err(|_| fetch_failed())?;
    let mut raw: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if cancel.is_cancelled() {
            return Err(TransportError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(fetch_failed());
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                if raw.len() + read > MAX_RESPONSE_BYTES + MAX_HEADER_BYTES {
                    return Err(TransportError::TooLarge);
                }
                raw.extend_from_slice(&chunk[..read]);
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => continue,
            Err(_) => return Err(fetch_failed()),
        }
    }
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(fetch_failed)?;
    if split > MAX_HEADER_BYTES {
        return Err(TransportError::TooLarge);
    }
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(fetch_failed)?;
    let (mut content_type, mut session, mut chunked, mut length) = (String::new(), None, false, None);
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-type" => content_type = value.to_string(),
            "mcp-session-id" => session = Some(value.to_string()),
            "transfer-encoding" => chunked = value.to_ascii_lowercase().contains("chunked"),
            "content-length" => length = value.parse::<usize>().ok(),
            _ => {}
        }
    }
    let payload = &raw[split + 4..];
    let body = if chunked {
        dechunk(payload).ok_or_else(fetch_failed)?
    } else if let Some(length) = length {
        if length > MAX_RESPONSE_BYTES {
            return Err(TransportError::TooLarge);
        }
        payload[..length.min(payload.len())].to_vec()
    } else {
        payload.to_vec()
    };
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(TransportError::TooLarge);
    }
    Ok(HttpResponse { status, content_type, session_id: session, body })
}

impl Connection {
    fn new(endpoint: Url) -> Self {
        Connection { endpoint, session_id: None, next_id: 0, connected: false }
    }

    fn post(&mut self, body: &Value, expect_response: bool, cancel: &CancelToken) -> Result<Option<Value>, TransportError> {
        let deadline = Instant::now() + CALL_TIMEOUT;
        let response = http_post(&self.endpoint, self.session_id.as_deref(), &body.to_string(), cancel, deadline)?;
        if let Some(session) = &response.session_id {
            self.session_id = Some(session.clone());
        }
        // fetch(..., {redirect: "error"}) rejects instead of following.
        if (300..400).contains(&response.status) {
            return Err(fetch_failed());
        }
        let text = String::from_utf8_lossy(&response.body).into_owned();
        if !(200..300).contains(&response.status) {
            return Err(TransportError::Failed(format!("Error POSTing to endpoint: {text}")));
        }
        if !expect_response {
            return Ok(None);
        }
        let id = body.get("id").cloned();
        if response.content_type.starts_with("text/event-stream") {
            for event in text.split("\n\n") {
                let data: Vec<&str> = event.lines().filter_map(|l| l.strip_prefix("data:")).map(|l| l.trim_start()).collect();
                if data.is_empty() {
                    continue;
                }
                if let Ok(message) = serde_json::from_str::<Value>(&data.join("\n")) {
                    if message.get("id") == id.as_ref() && (message.get("result").is_some() || message.get("error").is_some()) {
                        return Ok(Some(message));
                    }
                }
            }
            return Err(TransportError::Failed("Streamable HTTP response ended without a result".to_string()));
        }
        if !response.content_type.starts_with("application/json") {
            return Err(TransportError::Failed(format!("Unexpected content type: {}", response.content_type)));
        }
        serde_json::from_str::<Value>(&text)
            .map(Some)
            .map_err(|e| TransportError::Failed(format!("Unexpected response: {e}")))
    }

    fn request(&mut self, method: &str, params: Value, cancel: &CancelToken) -> Result<Value, TransportError> {
        self.next_id += 1;
        let body = json!({ "jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params });
        let message = self.post(&body, true, cancel)?.ok_or_else(|| TransportError::Failed("empty response".to_string()))?;
        if let Some(error) = message.get("error") {
            let text = error.get("message").and_then(Value::as_str).unwrap_or_default();
            return Err(TransportError::Failed(text.to_string()));
        }
        Ok(message.get("result").cloned().unwrap_or(Value::Null))
    }

    fn connect(&mut self, cancel: &CancelToken) -> Result<(), TransportError> {
        if self.connected {
            return Ok(());
        }
        let outcome = (|| {
            self.request(
                "initialize",
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": { "name": "rea-jeb", "version": "0.0.0" },
                }),
                cancel,
            )?;
            self.post(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }), false, cancel)?;
            self.request("tools/list", json!({}), cancel)?;
            Ok(())
        })();
        match outcome {
            Ok(()) => {
                self.connected = true;
                Ok(())
            }
            Err(error) => {
                self.session_id = None;
                Err(error)
            }
        }
    }

    fn call(&mut self, name: &str, args: Value, cancel: &CancelToken) -> Result<Value, CallError> {
        let transport = |error: TransportError| match error {
            TransportError::Failed(reason) => CallError::Transport(reason),
            TransportError::Cancelled => CallError::Cancelled,
            TransportError::TooLarge => CallError::Protocol(format!(
                "JEB MCP response exceeds {MAX_RESPONSE_BYTES} bytes; no complete result is available"
            )),
        };
        self.connect(cancel).map_err(transport)?;
        let result = self.request("tools/call", json!({ "name": name, "arguments": args }), cancel).map_err(transport)?;
        decode_tool_result(&result)
    }
}

enum CallError {
    /// Connection or JSON-RPC failure: the engine is not usable.
    Transport(String),
    /// `AnalysisProtocolError` or a zod failure: the answer is unreadable.
    Protocol(String),
    /// The caller cancelled while the request was in flight.
    Cancelled,
}

/// `decodeJebToolResult`.
fn decode_tool_result(input: &Value) -> Result<Value, CallError> {
    let malformed = || CallError::Protocol("JEB omitted or malformed required observation fields".to_string());
    let object = input.as_object().ok_or_else(malformed)?;
    if let Some(flag) = object.get("isError") {
        if !flag.is_boolean() {
            return Err(malformed());
        }
    }
    let structured = match object.get("structuredContent") {
        None | Some(Value::Null) if !object.contains_key("structuredContent") => None,
        Some(Value::Object(map)) => Some(map.clone()),
        _ => return Err(malformed()),
    };
    let mut blocks: Vec<String> = Vec::new();
    match object.get("content") {
        None => {}
        Some(Value::Array(items)) => {
            for item in items {
                let block = item.as_object().ok_or_else(malformed)?;
                let kind = block.get("type").and_then(Value::as_str).ok_or_else(malformed)?;
                match block.get("text") {
                    None => {}
                    Some(Value::String(text)) => {
                        if kind == "text" {
                            blocks.push(text.clone());
                        }
                    }
                    Some(_) => return Err(malformed()),
                }
            }
        }
        Some(_) => return Err(malformed()),
    }
    if let Some(map) = structured {
        return Ok(Value::Object(map));
    }
    if blocks.len() != 1 {
        return Err(CallError::Protocol(
            "JEB MCP omitted a single structured or text result; unsupported content cannot establish an empty observation.".to_string(),
        ));
    }
    match serde_json::from_str::<Value>(&blocks[0]) {
        Ok(value) => Ok(value),
        Err(_) => {
            if object.get("isError") == Some(&Value::Bool(true)) {
                return Err(CallError::Protocol(format!("JEB MCP tool failed: {}", blocks[0])));
            }
            Ok(Value::String(blocks[0].clone()))
        }
    }
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

struct Provider {
    endpoint: Url,
    connection: Connection,
    version: Option<String>,
    gui_client: Option<bool>,
    /// Token of the call currently using this provider.
    cancel: CancelToken,
}

static STATE: Mutex<Option<Provider>> = Mutex::new(None);

/// Drop the retained connection and engine identity (tests; a fresh process).
pub fn reset() {
    *STATE.lock().unwrap() = None;
}

/// Server shutdown: drop the retained connection. The provider owns no process or directory here
/// (JEB is an external client reached over HTTP) and REA's transport `close()` only aborts the
/// local request state, so what is released is the Mcp-Session-Id and the cached engine identity.
///
/// A call in flight holds the state; it is given a short grace period (the process is going away
/// either way, and there is nothing outside this memory to leak).
pub fn shutdown() {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match STATE.try_lock() {
            Ok(mut state) => {
                *state = None;
                return;
            }
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                *poisoned.into_inner() = None;
                return;
            }
            Err(std::sync::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(std::sync::TryLockError::WouldBlock) => return,
        }
    }
}

/// Whether a provider (connection and session id) is currently retained.
pub fn has_provider() -> bool {
    STATE.lock().unwrap_or_else(|e| e.into_inner()).is_some()
}

fn user_message() -> String {
    format!("Start a JEB client serving MCP (default {DEFAULT_ENDPOINT}) or set REA_JEB_MCP_URL to the running endpoint.")
}

fn protocol(message: &str) -> Error {
    Failure::Protocol { message: message.to_string() }.into()
}

fn unavailable(operation: &str, reason: String) -> Error {
    Failure::CapabilityUnavailable {
        provider_id: "jeb".to_string(),
        operation: operation.to_string(),
        reason,
        user_message: Some(user_message()),
        captured_output: None,
    }
    .into()
}

fn call_failure(operation: &str, error: CallError) -> Error {
    match error {
        CallError::Transport(reason) => unavailable(operation, reason),
        CallError::Protocol(message) => protocol(&message),
        CallError::Cancelled => Failure::Cancelled { operation: operation.to_string() }.into(),
    }
}

fn zod_failure() -> Error {
    protocol("JEB omitted or malformed required observation fields")
}

/// `#requireSuccess`: unwrap a `{success: true}` envelope or classify the refusal.
fn require_success(endpoint: &Url, payload: &Value, operation: &str) -> Outcome<()> {
    let Some(object) = payload.as_object() else {
        return Err(protocol("JEB MCP returned a non-object envelope; no observation can be established"));
    };
    match object.get("success") {
        Some(Value::Bool(false)) => Err(Failure::UnsupportedTarget {
            operation: operation.to_string(),
            path: endpoint.to_string(),
            reason: refusal_reason(payload),
            captured_output: None,
        }
        .into()),
        Some(Value::Bool(true)) => Ok(()),
        _ => Err(protocol("JEB MCP omitted its success field; no observation can be established")),
    }
}

/// `refusalReason`: the engine's own words, else a generic sentence.
fn refusal_reason(payload: &Value) -> String {
    const FALLBACK: &str = "The engine refused the request";
    let object = payload.as_object().unwrap();
    let optional_string = |value: Option<&Value>| match value {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(()),
    };
    let message = optional_string(object.get("message"));
    let error = match object.get("error") {
        None => Ok((None, None)),
        Some(Value::Object(map)) => match (optional_string(map.get("code")), optional_string(map.get("message")), optional_string(map.get("recovery_tool"))) {
            (Ok(code), Ok(message), Ok(_)) => Ok((code, message)),
            _ => Err(()),
        },
        Some(_) => Err(()),
    };
    // A malformed failure envelope falls back to the generic sentence.
    let (Ok(message), Ok((code, error_message))) = (message, error) else {
        return FALLBACK.to_string();
    };
    match error_message.or(message).or(code) {
        Some(reason) if !reason.is_empty() => reason,
        _ => FALLBACK.to_string(),
    }
}

struct ClientInformation {
    version: Option<String>,
    gui_client: Option<bool>,
    startup_ts: Option<u64>,
    message: Option<String>,
}

fn parse_client_information(payload: &Value) -> Result<ClientInformation, ()> {
    let object = payload.as_object().ok_or(())?;
    let version = match object.get("version") {
        None => None,
        Some(Value::String(text)) => Some(text.clone()),
        Some(_) => return Err(()),
    };
    let gui_client = match object.get("gui_client") {
        None => None,
        Some(Value::Bool(flag)) => Some(*flag),
        Some(_) => return Err(()),
    };
    let startup_ts = match object.get("startup_ts") {
        None => None,
        Some(Value::Number(n)) => Some(n.as_u64().ok_or(())?),
        Some(_) => return Err(()),
    };
    let message = match object.get("message") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(text.clone()),
        Some(_) => return Err(()),
    };
    Ok(ClientInformation { version, gui_client, startup_ts, message })
}

fn parse_units(value: Option<&Value>, required: bool) -> Result<Vec<Value>, ()> {
    let Some(value) = value else {
        return if required { Err(()) } else { Ok(vec![]) };
    };
    let items = value.as_array().ok_or(())?;
    items
        .iter()
        .map(|item| {
            let object = item.as_object().ok_or(())?;
            let path = object.get("unit_path").and_then(Value::as_str).ok_or(())?;
            let kind = object.get("unit_type").and_then(Value::as_str).ok_or(())?;
            Ok(json!({ "unit_path": path, "unit_type": kind }))
        })
        .collect()
}

impl Provider {
    fn identity(&self) -> Value {
        json!({ "id": "jeb", "name": "JEB", "version": self.version })
    }

    fn refresh_client_information(&mut self, operation: &str) -> Outcome<(Value, ClientInformation)> {
        let payload = self.connection.call("get_client_information", json!({}), &self.cancel).map_err(|e| call_failure(operation, e))?;
        require_success(&self.endpoint, &payload, "inspect_jeb_client")?;
        let information = parse_client_information(&payload).map_err(|_| zod_failure())?;
        self.version = information.version.clone();
        self.gui_client = information.gui_client;
        Ok((payload, information))
    }

    /// `#engine`: ensure the engine identity is known, then describe it.
    fn engine(&mut self, operation: &str) -> Outcome<Value> {
        if self.version.is_none() {
            self.refresh_client_information(operation)?;
        }
        Ok(json!({
            "name": "jeb",
            "version": self.version,
            "endpoint": self.endpoint.to_string(),
            "gui_client": self.gui_client,
        }))
    }

    fn execute(&mut self, request: &Request) -> Outcome<Execution> {
        let operation = request.operation();
        match request {
            Request::Client => {
                let (payload, information) = self.refresh_client_information(operation)?;
                let result = json!({
                    "engine": {
                        "name": "jeb",
                        "version": information.version,
                        "endpoint": self.endpoint.to_string(),
                        "gui_client": information.gui_client,
                    },
                    "startup_ts": information.startup_ts,
                    "message": information.message,
                });
                Ok(Execution {
                    result,
                    provider: self.identity(),
                    raw_result: payload,
                    limitations: if information.version.is_none() {
                        vec!["The engine did not report its version.".to_string()]
                    } else {
                        vec![]
                    },
                })
            }
            Request::Open { path } => {
                let payload = self
                    .connection
                    .call("open_project", json!({ "file_path": path }), &self.cancel)
                    .map_err(|e| call_failure(operation, e))?;
                require_success(&self.endpoint, &payload, operation)?;
                let object = payload.as_object().unwrap();
                let nullable_string = |key: &str| match object.get(key) {
                    None | Some(Value::Null) => Ok(Value::Null),
                    Some(Value::String(text)) => Ok(json!(text)),
                    Some(_) => Err(()),
                };
                let name = nullable_string("name").map_err(|_| zod_failure())?;
                let created = nullable_string("creation_datetime").map_err(|_| zod_failure())?;
                let input_files = match object.get("input_files") {
                    None => vec![],
                    Some(Value::Array(items)) => items
                        .iter()
                        .map(|item| {
                            let entry = item.as_object().ok_or(())?;
                            let file_name = entry.get("file_name").and_then(Value::as_str).ok_or(())?;
                            let size = entry.get("file_size").and_then(Value::as_u64).ok_or(())?;
                            let hash = entry.get("contents_sha256_hash").and_then(Value::as_str).ok_or(())?;
                            Ok(json!({ "file_name": file_name, "file_size": size, "contents_sha256_hash": hash }))
                        })
                        .collect::<Result<Vec<Value>, ()>>()
                        .map_err(|_| zod_failure())?,
                    Some(_) => return Err(zod_failure()),
                };
                let units = parse_units(object.get("units"), false).map_err(|_| zod_failure())?;
                let engine = self.engine(operation)?;
                Ok(Execution {
                    result: json!({
                        "engine": engine,
                        "project_name": name,
                        "creation_datetime": created,
                        "input_files": input_files,
                        "units": units,
                    }),
                    provider: self.identity(),
                    raw_result: payload,
                    limitations: vec![
                        "JEB resolves and analyzes the artifact on the engine host; REA did not open the target itself.".to_string(),
                    ],
                })
            }
            Request::Units { filter, parent_unit_path, index, count } => {
                let mut args = Map::new();
                args.insert("count".into(), json!(count));
                args.insert("index".into(), json!(index));
                if let Some(filter) = filter {
                    args.insert("filter".into(), json!(filter));
                }
                if let Some(parent) = parent_unit_path {
                    args.insert("parent_unit_path".into(), json!(parent));
                }
                let payload = self
                    .connection
                    .call("list_units", Value::Object(args), &self.cancel)
                    .map_err(|e| call_failure(operation, e))?;
                require_success(&self.endpoint, &payload, operation)?;
                let units = parse_units(payload.get("units"), true).map_err(|_| zod_failure())?;
                let engine = self.engine(operation)?;
                let coverage = if (units.len() as u64) < *count { "complete" } else { "partial" };
                Ok(Execution {
                    result: json!({
                        "engine": engine,
                        "filter": filter,
                        "parent_unit_path": parent_unit_path,
                        "index": index,
                        "count": count,
                        "units": units,
                        "coverage": coverage,
                    }),
                    provider: self.identity(),
                    raw_result: payload,
                    limitations: vec![
                        "The engine caps unit pages at 100; a full page means more units may exist.".to_string(),
                    ],
                })
            }
            Request::Decompile { unit_path, item_address, item_kind } => {
                let mut args = Map::new();
                args.insert("item_address".into(), json!(item_address));
                args.insert("item_kind".into(), json!(item_kind));
                if let Some(unit) = unit_path {
                    args.insert("unit_path".into(), json!(unit));
                }
                let payload = self
                    .connection
                    .call("decompile_code_item", Value::Object(args), &self.cancel)
                    .map_err(|e| call_failure(operation, e))?;
                require_success(&self.endpoint, &payload, operation)?;
                let text = payload.get("text").and_then(Value::as_str).ok_or_else(zod_failure)?.to_string();
                let engine = self.engine(operation)?;
                Ok(Execution {
                    result: json!({
                        "engine": engine,
                        "unit_path": unit_path,
                        "item_address": item_address,
                        "item_kind": item_kind,
                        "text": text,
                    }),
                    provider: self.identity(),
                    raw_result: payload,
                    limitations: if unit_path.is_none() {
                        vec![
                            "The engine selected the project's first code unit implicitly; the effective unit identity is unknown."
                                .to_string(),
                        ]
                    } else {
                        vec![]
                    },
                })
            }
        }
    }
}

/// Why a configured endpoint cannot be used (REA fails when it builds the provider).
pub struct EndpointRejected(pub String);

/// Run one JEB request against the endpoint named by the environment.
pub fn execute(request: &Request, env: &Env, cancel: &CancelToken) -> Result<Outcome<Execution>, EndpointRejected> {
    let endpoint = parse_endpoint(env.get(ENV_URL).map(String::as_str)).map_err(EndpointRejected)?;
    // Calls are serialized; a call that is cancelled while it waits never starts.
    let mut guard = loop {
        if cancel.is_cancelled() {
            return Ok(Err(Failure::Cancelled { operation: request.operation().to_string() }.into()));
        }
        match STATE.try_lock() {
            Ok(guard) => break guard,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => break poisoned.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    if guard.as_ref().is_none_or(|p| p.endpoint != endpoint) {
        *guard = Some(Provider {
            endpoint: endpoint.clone(),
            connection: Connection::new(endpoint),
            version: None,
            gui_client: None,
            cancel: cancel.clone(),
        });
    }
    let provider = guard.as_mut().unwrap();
    provider.cancel = cancel.clone();
    Ok(provider.execute(request))
}
