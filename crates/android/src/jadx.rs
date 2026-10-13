//! JADX provider: one serialized, immutable APK session per process (REA
//! `JadxProvider.ts`, `JadxSession.ts`, `JadxMcpTransport.ts`,
//! `AndroidTargetSnapshot.ts`).
//!
//! The engine is the unmodified jadx-headless-mcp JAR driven through REA's
//! Java metadata bridge, compiled by the caller's JDK in source-file mode. The
//! bridge speaks newline-delimited JSON-RPC (MCP) on stdio.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::analysis::{analyze_request, Request, Tools};
use crate::cancel::{CancelToken, GroupChild};
use crate::config::{self, Env, JadxConfiguration, BRIDGE_NAME, BRIDGE_VERSION, JADX_REVISION, JADX_SHA256, JADX_VERSION};
use crate::error::{Error, Failure, Outcome};

const OPERATION_TIMEOUT: Duration = Duration::from_secs(120);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const IDLE_RETIREMENT: Duration = Duration::from_secs(60);
const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
const MAX_OPERATION_BYTES: usize = 32 * 1024 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 1024 * 1024;
/// How often a waiting call looks at its cancellation token.
const CANCEL_POLL: Duration = Duration::from_millis(50);

/// REA's metadata bridge, embedded so its digest is part of every observation.
pub const BRIDGE_SOURCE: &[u8] = include_bytes!("../bridge/ReaJadxBridge.java");

pub const LIMITATIONS: [&str; 4] = [
    "Static decompiler observations do not establish runtime behavior; the APK is never executed.",
    "Method signatures use provider display types; exact DEX descriptors and instruction offsets are unavailable. Overload indices are local to this engine and artifact.",
    "Class inventories use parsed metadata before code generation, including synthetic members that may be omitted from decompiled source. Source positions remain unknown.",
    "Manifest summary fields are extracted by the upstream engine; decoded XML is retained for verification. APK signatures, split APKs, native libraries and Android runtime capture are not verified by this provider.",
];

/// The admitted APK (`BinaryTarget`).
#[derive(Debug, Clone)]
pub struct Target {
    pub selected_path: String,
    pub path: String,
    pub sha256: String,
    pub format: String,
}

#[derive(Debug, Clone)]
pub struct Execution {
    pub result: Value,
    pub raw_result: Value,
    pub limitations: Vec<String>,
    pub locations: Vec<Value>,
}

pub fn sha256_file(path: &str) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn bridge_sha256() -> String {
    hex::encode(Sha256::digest(BRIDGE_SOURCE))
}

// ---------------------------------------------------------------------------
// Process and JSON-RPC transport
// ---------------------------------------------------------------------------

enum Line {
    Text(String),
    Oversize(String),
    Eof,
}

enum RpcError {
    Remote { code: i64, message: String },
    Closed,
    Timeout,
    Cancelled,
    Transport(String),
}

struct Session {
    child: GroupChild,
    stdin: Option<ChildStdin>,
    lines: Receiver<Line>,
    stderr: Arc<Mutex<Vec<u8>>>,
    operation_bytes: Arc<AtomicUsize>,
    next_id: u64,
    connected: bool,
    loaded: Option<Value>,
    server: Option<Value>,
    failure: Option<String>,
}

impl Session {
    fn spawn(
        config: &JadxConfiguration,
        env: &Env,
        root: &std::path::Path,
        engine: &str,
        bridge: &str,
    ) -> std::io::Result<Session> {
        let run_id = format!("{:016x}", rand_u64());
        let mut command = Command::new(&config.java);
        command
            .args(&config.jvm_arguments)
            .arg("--class-path")
            .arg(engine)
            .arg(bridge)
            .current_dir(root)
            .env_clear()
            .envs(env)
            .env("REA_PROCESS_RUN_ID", &run_id)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Its own process group: the JVM and anything it starts die together.
        let mut child = GroupChild::spawn_untracked(&mut command)?;
        let stdin = child.child.stdin.take();
        let stdout = child.child.stdout.take().expect("stdout");
        let stderr_pipe = child.child.stderr.take().expect("stderr");
        let (sender, lines) = channel::<Line>();
        let operation_bytes = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&operation_bytes);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut buffer = Vec::new();
                // Never buffer more than one frame plus a byte, whatever the engine prints.
                match reader.by_ref().take(MAX_FRAME_BYTES as u64 + 1).read_until(b'\n', &mut buffer) {
                    Ok(0) | Err(_) => {
                        let _ = sender.send(Line::Eof);
                        break;
                    }
                    Ok(read) => {
                        let total = counter.fetch_add(read, Ordering::SeqCst) + read;
                        if total > MAX_OPERATION_BYTES {
                            let _ = sender.send(Line::Oversize(format!(
                                "JADX operation output exceeds {MAX_OPERATION_BYTES} bytes; no complete result is available"
                            )));
                            break;
                        }
                        if buffer.len() > MAX_FRAME_BYTES {
                            let _ = sender.send(Line::Oversize(format!("JADX MCP frame exceeds {MAX_FRAME_BYTES} bytes")));
                            break;
                        }
                        while matches!(buffer.last(), Some(b'\n') | Some(b'\r')) {
                            buffer.pop();
                        }
                        let _ = sender.send(Line::Text(String::from_utf8_lossy(&buffer).into_owned()));
                    }
                }
            }
        });
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let stderr_sink = Arc::clone(&stderr);
        let counter = Arc::clone(&operation_bytes);
        std::thread::spawn(move || {
            let mut pipe = stderr_pipe;
            let mut chunk = [0u8; 8192];
            while let Ok(read) = pipe.read(&mut chunk) {
                if read == 0 {
                    break;
                }
                counter.fetch_add(read, Ordering::SeqCst);
                let mut sink = stderr_sink.lock().unwrap();
                if sink.len() < MAX_DIAGNOSTIC_BYTES {
                    let take = read.min(MAX_DIAGNOSTIC_BYTES - sink.len());
                    sink.extend_from_slice(&chunk[..take]);
                }
            }
        });
        Ok(Session {
            child,
            stdin,
            lines,
            stderr,
            operation_bytes,
            next_id: 0,
            connected: false,
            loaded: None,
            server: None,
            failure: None,
        })
    }

    fn diagnostics(&self) -> String {
        String::from_utf8_lossy(&self.stderr.lock().unwrap()).into_owned()
    }

    fn send(&mut self, message: &Value) -> Result<(), RpcError> {
        let stdin = self.stdin.as_mut().ok_or(RpcError::Closed)?;
        let mut line = serde_json::to_vec(message).map_err(|e| RpcError::Transport(e.to_string()))?;
        line.push(b'\n');
        stdin.write_all(&line).and_then(|_| stdin.flush()).map_err(|_| RpcError::Closed)
    }

    fn request(
        &mut self,
        method: &str,
        params: Value,
        deadline: Instant,
        per_call: Duration,
        cancel: &CancelToken,
    ) -> Result<Value, RpcError> {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }))?;
        let limit = deadline.min(Instant::now() + per_call);
        loop {
            if cancel.is_cancelled() {
                return Err(RpcError::Cancelled);
            }
            let remaining = limit.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(RpcError::Timeout);
            }
            match self.lines.recv_timeout(remaining.min(CANCEL_POLL)) {
                Ok(Line::Text(text)) => {
                    let Ok(message) = serde_json::from_str::<Value>(&text) else { continue };
                    if message.get("id") != Some(&json!(id)) || message.get("method").is_some() {
                        continue;
                    }
                    if let Some(error) = message.get("error") {
                        return Err(RpcError::Remote {
                            code: error.get("code").and_then(Value::as_i64).unwrap_or(-32603),
                            message: error.get("message").and_then(Value::as_str).unwrap_or_default().to_string(),
                        });
                    }
                    return Ok(message.get("result").cloned().unwrap_or(Value::Null));
                }
                Ok(Line::Oversize(reason)) => {
                    self.failure.get_or_insert(reason.clone());
                    return Err(RpcError::Transport(reason));
                }
                Ok(Line::Eof) | Err(RecvTimeoutError::Disconnected) => return Err(RpcError::Closed),
                Err(RecvTimeoutError::Timeout) => continue,
            }
        }
    }

    fn connect(&mut self, deadline: Instant, cancel: &CancelToken) -> Result<(), RpcError> {
        let initialized = self.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "rea-android-adapter", "version": "1" },
            }),
            deadline,
            CONNECT_TIMEOUT,
            cancel,
        )?;
        let info = initialized.get("serverInfo").cloned().unwrap_or(Value::Null);
        let mut server = Map::new();
        for key in ["name", "version"] {
            if let Some(text) = info.get(key).and_then(Value::as_str) {
                server.insert(key.to_string(), json!(text));
            }
        }
        self.server = Some(Value::Object(server));
        self.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))?;
        self.connected = true;
        Ok(())
    }

    fn shutdown(&mut self) {
        self.stdin.take();
        let _ = self.child.kill_and_wait();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn rand_u64() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
    hasher.finish()
}

// ---------------------------------------------------------------------------
// One observation
// ---------------------------------------------------------------------------

struct Context<'a> {
    request: &'a Request,
    target: &'a Target,
    snapshot: &'a str,
    jar_hash: &'a str,
    bridge_hash: &'a str,
    java: &'a str,
    deadline: Instant,
    cancel: &'a CancelToken,
}

struct Observed {
    calls: Vec<Value>,
    engine_version: Option<String>,
}

struct SessionTools<'a> {
    session: &'a mut Session,
    observed: &'a mut Observed,
    ctx: &'a Context<'a>,
}

impl SessionTools<'_> {
    fn call(&mut self, name: &str, input: Value) -> Result<String, Failure> {
        let operation = self.ctx.request.operation();
        let response = self
            .session
            .request("tools/call", json!({ "name": name, "arguments": input }), self.ctx.deadline, OPERATION_TIMEOUT, self.ctx.cancel)
            .map_err(|e| rpc_failure(self.session, operation, e))?;
        self.observed.calls.push(json!({ "operation": name, "input": input, "response": response }));
        // parseJadxEnvelope: exactly one text block.
        let blocks = response.get("content").and_then(Value::as_array);
        let single = blocks.filter(|b| b.len() == 1).and_then(|b| {
            let block = &b[0];
            (block.get("type") == Some(&json!("text"))).then(|| block.get("text").and_then(Value::as_str)).flatten()
        });
        let is_error_valid = response.get("isError").map(Value::is_boolean).unwrap_or(true);
        let Some(text) = single.filter(|_| is_error_valid) else {
            return Err(Failure::output(operation, "JADX returned an unsupported MCP content envelope"));
        };
        if response.get("isError") == Some(&json!(true)) {
            if text.starts_with('{') {
                if let Ok(parsed) = serde_json::from_str::<Value>(text) {
                    if parsed.get("kind") == Some(&json!("invalid-input")) {
                        let field = parsed.get("field").and_then(Value::as_str);
                        let message = parsed.get("message").and_then(Value::as_str).filter(|m| !m.is_empty());
                        if let (Some(field), Some(message)) = (field, message) {
                            if ["class_name", "method_name", "overload_index"].contains(&field) {
                                return Err(Failure::input(operation, field, message));
                            }
                        }
                    }
                } else {
                    return Err(Failure::output(operation, "JADX returned malformed JSON text"));
                }
            }
            return Err(Failure::Adapter {
                provider_id: "jadx".to_string(),
                operation: operation.to_string(),
                diagnostics: Some(json!({
                    "upstream_operation": name,
                    "reason": text,
                    "target_path": self.ctx.target.path,
                    "target_sha256": self.ctx.target.sha256,
                })),
            });
        }
        Ok(text.to_string())
    }
}

impl Tools for SessionTools<'_> {
    fn json(&mut self, name: &str, input: Value) -> Result<Value, Failure> {
        let text = self.call(name, input)?;
        serde_json::from_str(&text).map_err(|_| Failure::output(self.ctx.request.operation(), "JADX returned malformed JSON text"))
    }

    fn text(&mut self, name: &str, input: Value) -> Result<String, Failure> {
        self.call(name, input)
    }
}

fn rpc_failure(session: &Session, operation: &str, error: RpcError) -> Failure {
    if let Some(reason) = &session.failure {
        return Failure::output(operation, reason.clone());
    }
    match error {
        RpcError::Cancelled => Failure::Cancelled { operation: operation.to_string() },
        RpcError::Timeout => Failure::Timeout { operation: operation.to_string(), timeout_ms: OPERATION_TIMEOUT.as_millis() as u64, captured_output: None },
        RpcError::Remote { code, message } => Failure::Adapter {
            provider_id: "jadx".to_string(),
            operation: operation.to_string(),
            diagnostics: Some(json!({ "reason": format!("MCP error {code}: {message}"), "stderr": session.diagnostics() })),
        },
        RpcError::Closed => Failure::Adapter {
            provider_id: "jadx".to_string(),
            operation: operation.to_string(),
            diagnostics: Some(json!({ "reason": "MCP error -32000: Connection closed", "stderr": session.diagnostics() })),
        },
        RpcError::Transport(reason) => Failure::Adapter {
            provider_id: "jadx".to_string(),
            operation: operation.to_string(),
            diagnostics: Some(json!({ "reason": reason, "stderr": session.diagnostics() })),
        },
    }
}

fn parse_runtime(value: &Value) -> Option<(String, u64)> {
    let version = value.get("engine_reported_version")?.as_str().filter(|v| !v.is_empty())?.to_string();
    let heap = value.get("max_heap_bytes")?.as_u64().filter(|v| *v > 0 && *v < (1u64 << 53))?;
    value.get("available_processors")?.as_u64().filter(|v| *v > 0)?;
    value.get("java_version")?.as_str().filter(|v| !v.is_empty())?;
    (value.get("metadata_scope")? == "parsed_members").then_some(())?;
    Some((version, heap))
}

fn parse_loaded(value: &Value) -> Option<Value> {
    (value.get("state")? == "LOADED").then_some(())?;
    (value.get("threads")? == &json!(1)).then_some(())?;
    (value.get("resources")? == "full").then_some(())?;
    Some(json!({
        "state": "LOADED",
        "apk_path": value.get("apk_path")?.as_str()?,
        "class_count": value.get("class_count")?.as_u64()?,
        "resource_count": value.get("resource_count")?.as_u64()?,
        "threads": 1,
        "resources": "full",
    }))
}

fn partial_observation(ctx: &Context, session: &Session, observed: &Observed) -> Value {
    json!({
        "provider_id": "jadx",
        "operation": ctx.request.operation(),
        "target": {
            "selected_path": ctx.target.selected_path,
            "path": ctx.target.path,
            "sha256": ctx.target.sha256,
            "format": "apk",
        },
        "provider_facts": {
            "jar_sha256": ctx.jar_hash,
            "bridge_sha256": ctx.bridge_hash,
            "bridge_name": BRIDGE_NAME,
            "bridge_version": BRIDGE_VERSION,
            "server_name": session.server.as_ref().and_then(|s| s.get("name")).cloned().unwrap_or(Value::Null),
            "server_version": session.server.as_ref().and_then(|s| s.get("version")).cloned().unwrap_or(Value::Null),
            "engine_version": observed.engine_version,
        },
        "calls": observed.calls,
    })
}

fn execute_on_session(session: &mut Session, ctx: &Context) -> Outcome<Execution> {
    let operation = ctx.request.operation();
    let mut observed = Observed { calls: Vec::new(), engine_version: None };
    session.operation_bytes.store(0, Ordering::SeqCst);
    let result = (|| -> Result<Execution, Failure> {
        if !session.connected {
            session.connect(ctx.deadline, ctx.cancel).map_err(|e| rpc_failure(session, operation, e))?;
        }
        let server = session.server.clone().unwrap_or(Value::Null);
        if server.get("name") != Some(&json!(BRIDGE_NAME)) || server.get("version") != Some(&json!(BRIDGE_VERSION)) {
            return Err(Failure::capability(
                "jadx",
                operation,
                format!(
                    "Expected {BRIDGE_NAME} {BRIDGE_VERSION}; server reported {} {}.",
                    server.get("name").and_then(Value::as_str).unwrap_or("unknown"),
                    server.get("version").and_then(Value::as_str).unwrap_or("unknown")
                ),
            ));
        }
        let mut tools = SessionTools { session, observed: &mut observed, ctx };
        let status = tools.json("rea_jvm_status", json!({}))?;
        let Some((engine_version, heap_bytes)) = parse_runtime(&status) else {
            return Err(Failure::output(operation, "JADX response violated the pinned upstream protocol"));
        };
        tools.observed.engine_version = Some(engine_version.clone());
        if engine_version != JADX_VERSION {
            return Err(Failure::capability("jadx", operation, format!("Expected engine {JADX_VERSION}; JAR reported {engine_version}.")));
        }
        let loaded = match tools.session.loaded.clone() {
            Some(loaded) => loaded,
            None => {
                let raw = tools.json("load_apk", json!({ "path": ctx.snapshot, "threads": 1, "resources": "full" }))?;
                parse_loaded(&raw).ok_or_else(|| Failure::output(operation, "JADX response violated the pinned upstream protocol"))?
            }
        };
        if loaded["apk_path"] != ctx.snapshot {
            return Err(Failure::output(operation, "JADX loaded a different APK path than the admitted snapshot"));
        }
        tools.session.loaded = Some(loaded.clone());
        let heap_mib = heap_bytes / (1024 * 1024);
        let engine = json!({
            "name": "jadx-headless-mcp",
            "version": engine_version,
            "artifact_sha256": ctx.jar_hash,
            "source_revision": if ctx.jar_hash == JADX_SHA256 { json!(JADX_REVISION) } else { Value::Null },
            "worker_count": 1,
            "heap_limit_mib": if heap_mib == 0 { Value::Null } else { json!(heap_mib) },
        });
        let result = analyze_request(&mut tools, ctx.request, &loaded, &engine)?;
        Ok(Execution {
            result,
            raw_result: json!({
                "server": server,
                "bridge_sha256": ctx.bridge_hash,
                "jar_sha256": ctx.jar_hash,
                "loaded": loaded,
                "calls": observed.calls,
            }),
            limitations: LIMITATIONS.iter().map(|s| s.to_string()).collect(),
            locations: if operation == "inspect_android_package" {
                vec![json!({ "kind": "artifact-path", "path": "AndroidManifest.xml" })]
            } else {
                vec![]
            },
        })
    })();
    match result {
        Ok(execution) => Ok(execution),
        Err(failure @ Failure::Cancelled { .. }) => Err(Error::from(failure)),
        Err(failure) => {
            let failure = if !session.connected {
                // Java could not start the bridge.
                let stderr = session.diagnostics();
                let reason = format!(
                    "Java could not start REA's Android bridge using {}: {}.{} Select a full JDK including jdk.compiler via JAVA_HOME, or a working java on PATH; verify it with java --list-modules. A JRE cannot compile REA's source bridge. If the JDK works, verify the REA bridge and configured JADX JAR installation.",
                    ctx.java,
                    startup_cause(&failure),
                    if stderr.is_empty() { String::new() } else { format!(" Java diagnostics: {stderr}") }
                );
                Failure::CapabilityUnavailable {
                    provider_id: "jadx".to_string(),
                    operation: operation.to_string(),
                    reason: reason.clone(),
                    user_message: Some(reason),
                    captured_output: Some(json!({ "stdout": "", "stderr": stderr, "truncated": false })),
                }
            } else {
                failure
            };
            Err(Error { failure, partial_observation: Some(partial_observation(ctx, session, &observed)) })
        }
    }
}

fn startup_cause(failure: &Failure) -> String {
    match failure {
        Failure::Adapter { diagnostics: Some(d), .. } => d.get("reason").and_then(Value::as_str).unwrap_or("Connection closed").to_string(),
        Failure::Timeout { .. } => "Request timed out".to_string(),
        _ => "Connection closed".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Retained session
// ---------------------------------------------------------------------------

struct Retained {
    key: String,
    // Fields drop in declaration order: the session (which kills the JVM and its
    // group) must go before the directory the JVM runs in.
    session: Session,
    root: tempfile::TempDir,
    snapshot: String,
    jar_hash: String,
    bridge_hash: String,
    generation: u64,
}

impl Drop for Retained {
    fn drop(&mut self) {
        // Forget the group before the session (a field, dropped after this) kills it, so that
        // `shutdown` can never signal a group id that has been released.
        let _ = LIVE_PGID.compare_exchange(self.session.child.pgid(), 0, Ordering::SeqCst, Ordering::SeqCst);
    }
}

/// Process group of the retained engine (0: none). Readable without the state lock, which a call
/// in flight holds for its whole duration.
static LIVE_PGID: AtomicI32 = AtomicI32::new(0);

struct State {
    retained: Option<Retained>,
    generation: u64,
    /// When the retained session goes idle-away, and which generation that is for.
    idle_deadline: Option<(Instant, u64)>,
}

fn state() -> &'static (Mutex<State>, Condvar) {
    static STATE: OnceLock<(Mutex<State>, Condvar)> = OnceLock::new();
    STATE.get_or_init(|| (Mutex::new(State { retained: None, generation: 0, idle_deadline: None }), Condvar::new()))
}

/// The one thread that retires an idle session (instead of one sleeper per call).
fn ensure_idle_watcher() {
    static START: std::sync::Once = std::sync::Once::new();
    START.call_once(|| {
        let _ = std::thread::Builder::new().name("jadx-idle".to_string()).spawn(|| {
            let (lock, wake) = state();
            let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                match guard.idle_deadline {
                    None => guard = wake.wait(guard).unwrap_or_else(|e| e.into_inner()),
                    Some((deadline, generation)) => {
                        let now = Instant::now();
                        if now >= deadline {
                            guard.idle_deadline = None;
                            if guard.retained.as_ref().is_some_and(|r| r.generation == generation) {
                                guard.retained = None;
                            }
                        } else {
                            guard = wake.wait_timeout(guard, deadline - now).unwrap_or_else(|e| e.into_inner()).0;
                        }
                    }
                }
            }
        });
    });
}

/// Retire the retained engine session (shutdown, tests, configuration change).
pub fn retire_retained() {
    let mut guard = state().0.lock().unwrap_or_else(|e| e.into_inner());
    guard.retained = None;
    guard.idle_deadline = None;
}

/// Release the engine for good: the server is going away (transport closed, SIGTERM, SIGINT).
///
/// The JVM's process group is killed first, so a call that is still running (it holds the state
/// lock until it returns) fails at once instead of making the shutdown wait for its timeout; then
/// the retained session and its private `rea-android-*` directory are dropped. Blocking: call it
/// from a blocking thread.
pub fn shutdown() {
    let pgid = LIVE_PGID.load(Ordering::SeqCst);
    if pgid > 0 {
        // SAFETY: plain signal delivery to the process group this module spawned and still owns
        // (`Retained::drop` clears LIVE_PGID before the group is released).
        unsafe {
            libc::killpg(pgid, libc::SIGKILL);
        }
    }
    retire_retained();
}

/// Whether an engine session (JVM) is currently retained.
pub fn has_retained() -> bool {
    state().0.lock().unwrap_or_else(|e| e.into_inner()).retained.is_some()
}

fn copy_snapshot(source: &str, destination: &std::path::Path, expected: &str, cancel: &CancelToken) -> Result<String, std::io::Error> {
    let mut input = std::fs::File::open(source)?;
    let mut output = std::fs::OpenOptions::new().write(true).create_new(true).open(destination)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        if cancel.is_cancelled() {
            return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "cancelled"));
        }
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        output.write_all(&buffer[..read])?;
    }
    output.flush()?;
    let digest = hex::encode(hasher.finalize());
    if digest != expected {
        return Err(std::io::Error::other(format!("Android snapshot digest mismatch for {source}")));
    }
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o400))?;
    Ok(digest)
}

fn changed_target(operation: &str, path: &str) -> Failure {
    Failure::input(operation, "path", format!("APK bytes changed after admission at {path}; retry against a stable file."))
}

/// Analyze one admitted APK.
pub fn execute(target: &Target, request: &Request, env: &Env, cancel: &CancelToken) -> Outcome<Execution> {
    let (lock, wake) = state();
    let operation = request.operation();
    // Calls are serialized; a call that is cancelled while it waits never starts.
    let mut guard = loop {
        if cancel.is_cancelled() {
            return Err(Failure::Cancelled { operation: operation.to_string() }.into());
        }
        match lock.try_lock() {
            Ok(guard) => break guard,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => break poisoned.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(10)),
        }
    };
    let deadline = Instant::now() + OPERATION_TIMEOUT;
    let outcome = execute_locked(&mut guard, target, request, env, deadline, cancel);
    match &outcome {
        Ok(_) => {
            guard.generation += 1;
            let generation = guard.generation;
            if let Some(retained) = guard.retained.as_mut() {
                retained.generation = generation;
            }
            guard.idle_deadline = Some((Instant::now() + IDLE_RETIREMENT, generation));
            ensure_idle_watcher();
            wake.notify_all();
        }
        Err(_) => {
            guard.retained = None;
            guard.idle_deadline = None;
        }
    }
    outcome
}

fn execute_locked(
    guard: &mut State,
    target: &Target,
    request: &Request,
    env: &Env,
    deadline: Instant,
    cancel: &CancelToken,
) -> Outcome<Execution> {
    let operation = request.operation();
    if target.format != "apk" {
        return Err(Failure::capability("jadx", operation, format!("Target {} is {}; provide one standalone APK.", target.path, target.format)).into());
    }
    let configuration = config::read_inputs(env).map_err(|e| Error::from(e.into_failure(operation)))?;
    let jar_hash = sha256_file(&configuration.jar).map_err(|_| {
        Error::from(Failure::capability(
            "jadx",
            operation,
            format!("Selected JADX input bytes changed during admission at {}; retry with a stable installation.", configuration.jar),
        ))
    })?;
    let bridge_hash = bridge_sha256();
    let target_hash = sha256_file(&target.path).map_err(|_| Error::from(changed_target(operation, &target.path)))?;
    if target_hash != target.sha256 {
        return Err(changed_target(operation, &target.path).into());
    }
    let option = |name: &str| env.get(name).cloned();
    let key = json!({
        "path": target.path,
        "sha256": target.sha256,
        "jar": configuration.jar,
        "jarHash": jar_hash,
        "bridgeHash": bridge_hash,
        "java": configuration.java,
        "arguments": configuration.jvm_arguments,
        "options": [option("JAVA_TOOL_OPTIONS"), option("_JAVA_OPTIONS"), option("JDK_JAVA_OPTIONS"), option("PATH"), option("JAVA_HOME")],
    })
    .to_string();
    if guard.retained.as_ref().is_some_and(|r| r.key != key) {
        guard.retained = None;
    }
    if guard.retained.is_none() {
        config::validate_contents(&configuration, env).map_err(|e| Error::from(e.into_failure(operation)))?;
        let root = tempfile::Builder::new()
            .prefix("rea-android-")
            .rand_bytes(6)
            .tempdir()
            .map_err(|e| adapter_error(operation, e.to_string()))?;
        let engine_path = root.path().join("engine.jar");
        let engine_hash = copy_snapshot(&configuration.jar, &engine_path, &jar_hash, cancel).map_err(|e| {
            if e.kind() == std::io::ErrorKind::Interrupted {
                return Error::from(Failure::Cancelled { operation: operation.to_string() });
            }
            Error::from(Failure::capability(
                "jadx",
                operation,
                format!("REA_JADX_MCP_JAR bytes changed during admission at {}; retry with a stable engine file.", configuration.jar),
            ))
        })?;
        let snapshot_path = root.path().join("target.apk");
        copy_snapshot(&target.path, &snapshot_path, &target.sha256, cancel).map_err(|e| {
            if e.kind() == std::io::ErrorKind::Interrupted {
                return Error::from(Failure::Cancelled { operation: operation.to_string() });
            }
            Error::from(changed_target(operation, &target.path))
        })?;
        let bridge_path = root.path().join("ReaJadxBridge.java");
        std::fs::write(&bridge_path, BRIDGE_SOURCE).map_err(|e| adapter_error(operation, e.to_string()))?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&bridge_path, std::fs::Permissions::from_mode(0o400));
        }
        let session = Session::spawn(
            &configuration,
            env,
            root.path(),
            &engine_path.to_string_lossy(),
            &bridge_path.to_string_lossy(),
        )
        .map_err(|e| {
            Error::from(Failure::capability(
                "jadx",
                operation,
                format!("Java could not start REA's Android bridge using {}: {e}.", configuration.java),
            ))
        })?;
        LIVE_PGID.store(session.child.pgid(), Ordering::SeqCst);
        guard.retained = Some(Retained {
            key,
            root,
            session,
            snapshot: snapshot_path.to_string_lossy().into_owned(),
            jar_hash: engine_hash,
            bridge_hash,
            generation: 0,
        });
    }
    let retained = guard.retained.as_mut().expect("retained session");
    let ctx = Context {
        request,
        target,
        snapshot: &retained.snapshot.clone(),
        jar_hash: &retained.jar_hash.clone(),
        bridge_hash: &retained.bridge_hash.clone(),
        java: &configuration.java,
        deadline,
        cancel,
    };
    // While this call runs, cancelling it kills the engine's whole process group.
    let pgid = retained.session.child.pgid();
    cancel.register(pgid);
    let outcome = execute_on_session(&mut retained.session, &ctx);
    cancel.unregister(pgid);
    let _ = &retained.root;
    outcome
}

fn adapter_error(operation: &str, reason: String) -> Error {
    Error::from(Failure::Adapter {
        provider_id: "jadx".to_string(),
        operation: operation.to_string(),
        diagnostics: Some(json!({ "reason": reason, "stderr": "" })),
    })
}
