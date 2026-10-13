//! One authenticated NDJSON-over-Unix-socket Hopper bridge session (port of
//! `HopperClient.ts`, `HopperRequestQueue.ts`, `BridgeLauncher.ts` native mode and the
//! shutdown protocol of `HopperCleanup.ts`).
//!
//! The Hopper process (or any launcher honoring Hopper's `--analysis -Y <script>
//! --executable <path>` contract) runs REA's packaged bridge script, which serves a
//! single token-authenticated connection on a private socket. Requests are serialized
//! on the wire: a caller that gives up (cancellation or deadline) leaves the active
//! request to finish and its reply is discarded.

use std::collections::BTreeMap;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::error::AnalysisError;
use crate::provider::tokio_util_lite::CancelToken;

const BRIDGE: &str = include_str!("../../bridge/hopper_bridge.py");
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const DIAGNOSTIC_BYTES: usize = 64 * 1024;
const NO_EXIT: i64 = i64::MIN;
const MAX_LINE_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct HopperClientOptions {
    pub launcher_path: String,
    pub environment: BTreeMap<String, String>,
    pub target_path: String,
    pub target_kind: String,
    pub loader_args: Vec<String>,
    pub startup_timeout_ms: u64,
}

struct Request {
    id: u64,
    method: String,
    params: Value,
    transmitted: Arc<AtomicBool>,
    reply: oneshot::Sender<Result<Value, AnalysisError>>,
}

#[derive(Default)]
struct Streams {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_total: u64,
    stderr_total: u64,
}

type SharedStreams = Arc<StdMutex<Streams>>;

struct Live {
    pid: i32,
    exited: Arc<AtomicBool>,
    exit_code: Arc<AtomicI64>,
    dead: Arc<AtomicBool>,
    runtime_root: PathBuf,
    token: String,
    next_id: AtomicU64,
    streams: SharedStreams,
    sender: StdMutex<Option<mpsc::UnboundedSender<Request>>>,
    info: StdMutex<Value>,
}

impl Live {
    fn kill_group(&self) {
        if !self.exited.load(Ordering::SeqCst) {
            crate::process::kill_group(self.pid);
        }
    }

    fn launcher_outcome(&self) -> Value {
        let streams = self.streams.lock().unwrap();
        let redact = |bytes: &[u8]| String::from_utf8_lossy(bytes).replace(&self.token, "[redacted transport credential]");
        let code = self.exit_code.load(Ordering::SeqCst);
        json!({
            "exit_code": if code == NO_EXIT { Value::Null } else { json!(code) },
            "signal": Value::Null,
            "stdout": { "text": redact(&streams.stdout), "bytes": streams.stdout_total, "retained_bytes": streams.stdout.len() },
            "stderr": { "text": redact(&streams.stderr), "bytes": streams.stderr_total, "retained_bytes": streams.stderr.len() },
            "output_closed": true,
            "diagnostic_truncated": streams.stdout_total as usize > streams.stdout.len() || streams.stderr_total as usize > streams.stderr.len(),
        })
    }
}

struct RootGuard {
    path: PathBuf,
    armed: bool,
}

impl Drop for RootGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        self.kill_group();
        let _ = std::fs::remove_dir_all(&self.runtime_root);
    }
}

pub struct HopperClient {
    options: HopperClientOptions,
    state: Mutex<Option<Arc<Live>>>,
}

/// Failure phase of an operation, as shown in provider diagnostics.
fn operation_stage(method: &str) -> &'static str {
    if method == "health" {
        "connection"
    } else if method == "procedure_pseudo_code" {
        "decompilation"
    } else {
        "analysis"
    }
}

impl HopperClient {
    pub fn new(options: HopperClientOptions) -> Self {
        Self {
            options,
            state: Mutex::new(None),
        }
    }

    /// Launch the bridge once and complete its authenticated health handshake.
    pub async fn start(&self, cancel: &CancelToken) -> Result<Value, AnalysisError> {
        let mut state = self.state.lock().await;
        let live = self.ensure_live(&mut state, cancel).await?;
        let info = live.info.lock().unwrap().clone();
        Ok(info)
    }

    /// Invoke one declared bridge operation.
    pub async fn call_tool(
        &self,
        name: &str,
        arguments: &Value,
        cancel: &CancelToken,
        timeout: Option<Duration>,
    ) -> Result<Value, AnalysisError> {
        let live = {
            let mut state = self.state.lock().await;
            self.ensure_live(&mut state, cancel).await?
        };
        let result = Self::request(&live, name, arguments, timeout, Some(cancel)).await;
        match result {
            Err(AnalysisError::HopperRemote {
                diagnostic_type,
                safe_message,
                ..
            }) if diagnostic_type == "capability_unavailable" => {
                Err(AnalysisError::capability_unavailable("hopper", name, &safe_message))
            }
            other => other,
        }
    }

    /// Stop the bridge: document shutdown, transport release, owned process group, runtime files.
    pub async fn close(&self, retain_document: bool) -> Result<(), AnalysisError> {
        let taken = self.state.lock().await.take();
        let Some(live) = taken else {
            return Ok(());
        };
        let mut confirmed = false;
        if !live.dead.load(Ordering::SeqCst) && !live.exited.load(Ordering::SeqCst) {
            let method = if retain_document { "shutdown" } else { "shutdown_document" };
            let shutdown = Self::request(&live, method, &json!({}), Some(SHUTDOWN_TIMEOUT), None).await;
            confirmed = shutdown.as_ref().map(shutdown_acknowledged).unwrap_or(false);
            if !confirmed {
                tracing::warn!("Hopper document shutdown was not confirmed");
            }
        }
        // Release the transport so the bridge connection ends.
        live.sender.lock().unwrap().take();
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline && !live.exited.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        live.kill_group();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !live.exited.load(Ordering::SeqCst) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let root = live.runtime_root.clone();
        let _ = tokio::task::spawn_blocking(move || std::fs::remove_dir_all(root)).await;
        if confirmed || live.dead.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(AnalysisError::ProviderAdapter {
                provider_id: "hopper".to_string(),
                operation: "close_binary".to_string(),
                diagnostics: Some(json!({
                    "issues": [{ "resource": "hopper-document", "reason": "authenticated shutdown acknowledgement was not observed" }]
                })),
                cleanup_incomplete: true,
                cleanup_resources: vec!["hopper-document".to_string()],
            })
        }
    }

    async fn ensure_live(
        &self,
        state: &mut Option<Arc<Live>>,
        cancel: &CancelToken,
    ) -> Result<Arc<Live>, AnalysisError> {
        if let Some(live) = state.as_ref() {
            if !live.dead.load(Ordering::SeqCst) {
                return Ok(live.clone());
            }
            // A failed bridge is not restarted behind the caller's back: report its state.
            let dead = live.clone();
            return Err(Self::process_error(&dead, None, None, "unreachable"));
        }
        let live = self.start_session(cancel).await?;
        *state = Some(live.clone());
        Ok(live)
    }

    fn process_error(live: &Live, method: Option<&str>, id: Option<u64>, state: &'static str) -> AnalysisError {
        let code = live.exit_code.load(Ordering::SeqCst);
        let exit_code = if code == NO_EXIT { None } else { Some(code) };
        AnalysisError::HopperProcess {
            exit_code,
            diagnostic: None,
            operation: method.map(str::to_string),
            request_id: id,
            provider_state: if exit_code.is_some() { "exited" } else { state },
            stage: method.map(operation_stage).unwrap_or("connection"),
            launcher: None,
            failure_code: None,
            user_message: None,
        }
    }

    async fn start_session(&self, cancel: &CancelToken) -> Result<Arc<Live>, AnalysisError> {
        if cancel.is_cancelled() {
            return Err(AnalysisError::HopperCancelled);
        }
        let deadline = Instant::now() + Duration::from_millis(self.options.startup_timeout_ms);
        let root = make_private_dir(&session_root(), "rea-").map_err(|e| AnalysisError::HopperStart {
            user_message: Some(format!("Hopper private runtime allocation failed: {e}")),
            owner_run_id: None,
            launcher: None,
        })?;
        // Removes the directory if this future is dropped (cancelled) before `Live` takes ownership.
        let mut guard = RootGuard { path: root.clone(), armed: true };
        match self.launch_in(&root, deadline, cancel).await {
            Ok(live) => {
                guard.armed = false;
                Ok(live)
            }
            Err((error, live)) => {
                if let Some(live) = live {
                    live.kill_group();
                    let wait = Instant::now() + Duration::from_secs(5);
                    while !live.exited.load(Ordering::SeqCst) && Instant::now() < wait {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
                drop(guard);
                Err(error)
            }
        }
    }

    async fn launch_in(
        &self,
        root: &Path,
        deadline: Instant,
        cancel: &CancelToken,
    ) -> Result<Arc<Live>, (AnalysisError, Option<Arc<Live>>)> {
        let start_error = |message: String| {
            (
                AnalysisError::HopperStart {
                    user_message: Some(message),
                    owner_run_id: None,
                    launcher: None,
                },
                None,
            )
        };
        let socket_path = root.join("bridge.sock");
        let token = random_hex(32);
        let run_id = random_uuid();
        let bridge_path = root.join("hopper_bridge.py");
        write_private(&bridge_path, BRIDGE.as_bytes()).map_err(|e| start_error(format!("Hopper bridge staging failed: {e}")))?;
        let bootstrap_path = root.join("bootstrap.py");
        let quote = |s: &str| serde_json::to_string(s).unwrap_or_default();
        let bootstrap = [
            format!("REA_SOCKET = {}", quote(&socket_path.to_string_lossy())),
            format!("REA_TOKEN = {}", quote(&token)),
            format!("REA_RUN_ID = {}", quote(&run_id)),
            format!("REA_TARGET_PATH = {}", quote(&self.options.target_path)),
            "REA_OWNS_PROCESS_LIFETIME = False".to_string(),
            format!(
                "exec(compile(open({0}, 'rb').read(), {0}, 'exec'))",
                quote(&bridge_path.to_string_lossy())
            ),
            String::new(),
        ]
        .join("\n");
        write_private(&bootstrap_path, bootstrap.as_bytes())
            .map_err(|e| start_error(format!("Hopper bootstrap write failed: {e}")))?;

        let action = if self.options.target_kind == "database" { "--database" } else { "--executable" };
        let mut arguments: Vec<String> = self.options.loader_args.clone();
        arguments.extend([
            "--analysis".to_string(),
            "-Y".to_string(),
            bootstrap_path.to_string_lossy().to_string(),
            action.to_string(),
            self.options.target_path.clone(),
        ]);
        if cancel.is_cancelled() {
            return Err((AnalysisError::HopperCancelled, None));
        }
        let mut command = Command::new(&self.options.launcher_path);
        command
            .args(&arguments)
            .env_clear()
            .envs(&self.options.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(false);
        command.process_group(0);
        crate::process::harden_child(&mut command);
        let mut child = command.spawn().map_err(|e| start_error(format!("Hopper launcher could not start: {e}")))?;
        let pid = child.id().unwrap_or(0) as i32;
        crate::process::spawn_watchdog(pid);
        let exited = Arc::new(AtomicBool::new(false));
        let exit_code = Arc::new(AtomicI64::new(NO_EXIT));
        let streams: SharedStreams = Arc::new(StdMutex::new(Streams::default()));
        spawn_drain(child.stdout.take(), streams.clone(), true);
        spawn_drain(child.stderr.take(), streams.clone(), false);
        {
            let exited = exited.clone();
            let exit_code = exit_code.clone();
            tokio::spawn(async move {
                if let Ok(status) = child.wait().await {
                    if let Some(code) = status.code() {
                        exit_code.store(code as i64, Ordering::SeqCst);
                    }
                }
                exited.store(true, Ordering::SeqCst);
            });
        }
        let dead = Arc::new(AtomicBool::new(false));
        let live = Arc::new(Live {
            pid,
            exited: exited.clone(),
            exit_code: exit_code.clone(),
            dead: dead.clone(),
            runtime_root: root.to_path_buf(),
            token: token.clone(),
            next_id: AtomicU64::new(1),
            streams,
            sender: StdMutex::new(None),
            info: StdMutex::new(Value::Null),
        });
        // Connect.
        let stream = loop {
            if cancel.is_cancelled() {
                return Err((AnalysisError::HopperCancelled, Some(live)));
            }
            if exited.load(Ordering::SeqCst) {
                let outcome = live.launcher_outcome();
                return Err((
                    AnalysisError::HopperStart {
                        user_message: Some("Hopper's launcher helper failed before bridge readiness. Review details.launcher and complete Hopper setup before retrying.".to_string()),
                        owner_run_id: None,
                        launcher: Some(outcome),
                    },
                    Some(live),
                ));
            }
            if Instant::now() >= deadline {
                let outcome = live.launcher_outcome();
                return Err((
                    AnalysisError::HopperTimeout {
                        timeout_ms: self.options.startup_timeout_ms,
                        operation: None,
                        request_id: None,
                        provider_state: "not_started",
                        stage: "launch",
                        launcher: Some(outcome),
                    },
                    Some(live),
                ));
            }
            if socket_path.exists() {
                if let Ok(stream) = UnixStream::connect(&socket_path).await {
                    break stream;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let (read, write) = stream.into_split();
        let (tx, rx) = mpsc::unbounded_channel::<Request>();
        *live.sender.lock().unwrap() = Some(tx);
        tokio::spawn(connection_actor(
            rx,
            BufReader::new(read),
            write,
            token.clone(),
            live.clone(),
        ));
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err((
                AnalysisError::HopperTimeout {
                    timeout_ms: self.options.startup_timeout_ms,
                    operation: None,
                    request_id: None,
                    provider_state: "not_started",
                    stage: "launch",
                    launcher: None,
                },
                Some(live),
            ));
        }
        let health = Self::request(&live, "health", &json!({}), Some(remaining), Some(cancel)).await;
        let health = match health {
            Ok(value) => value,
            Err(error) => return Err((error, Some(live))),
        };
        let valid = health.get("name") == Some(&json!("REA Hopper bridge"))
            && health.get("version").map(Value::is_string).unwrap_or(false)
            && health.get("run_id") == Some(&json!(run_id));
        if !valid {
            return Err((
                AnalysisError::HopperProtocol {
                    message: "Hopper bridge health result is invalid".to_string(),
                },
                Some(live),
            ));
        }
        *live.info.lock().unwrap() = json!({ "name": health["name"], "version": health["version"] });
        Ok(live)
    }

    async fn request(
        live: &Arc<Live>,
        method: &str,
        params: &Value,
        timeout: Option<Duration>,
        cancel: Option<&CancelToken>,
    ) -> Result<Value, AnalysisError> {
        let id = live.next_id.fetch_add(1, Ordering::SeqCst);
        let sender = live.sender.lock().unwrap().clone();
        let Some(sender) = sender.filter(|_| !live.dead.load(Ordering::SeqCst)) else {
            return Err(Self::process_error(live, Some(method), Some(id), "unreachable"));
        };
        if cancel.map(CancelToken::is_cancelled).unwrap_or(false) {
            return Err(AnalysisError::HopperCancelled);
        }
        if timeout == Some(Duration::ZERO) {
            return Err(AnalysisError::HopperTimeout {
                timeout_ms: 0,
                operation: Some(method.to_string()),
                request_id: Some(id),
                provider_state: "not_started",
                stage: operation_stage(method),
                launcher: None,
            });
        }
        let (reply, receive) = oneshot::channel();
        let transmitted = Arc::new(AtomicBool::new(false));
        sender
            .send(Request {
                id,
                method: method.to_string(),
                params: params.clone(),
                transmitted: transmitted.clone(),
                reply,
            })
            .map_err(|_| Self::process_error(live, Some(method), Some(id), "unreachable"))?;
        let cancelled = async {
            match cancel {
                Some(token) => token.cancelled().await,
                None => std::future::pending::<()>().await,
            }
        };
        let timed = async {
            match timeout {
                Some(t) => tokio::time::sleep(t).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            outcome = receive => match outcome {
                Ok(result) => result,
                Err(_) => Err(Self::process_error(live, Some(method), Some(id), "unreachable")),
            },
            _ = cancelled => Err(AnalysisError::HopperCancelled),
            _ = timed => Err(AnalysisError::HopperTimeout {
                timeout_ms: timeout.map(|t| t.as_millis() as u64).unwrap_or(0),
                operation: Some(method.to_string()),
                request_id: Some(id),
                provider_state: if transmitted.load(Ordering::SeqCst) { "busy" } else { "not_started" },
                stage: operation_stage(method),
                launcher: None,
            }),
        }
    }
}

fn shutdown_acknowledged(value: &Value) -> bool {
    if value.get("shutdown") != Some(&json!(true)) {
        return false;
    }
    (value.get("analysis_stopped") == Some(&json!(true)) && value.get("document_closed") == Some(&json!(true)))
        || (value.get("document_closed") == Some(&json!(false)) && value.get("document_retained") == Some(&json!(true)))
}

/// Owns the socket: writes one request, then reads until its response.
async fn connection_actor(
    mut requests: mpsc::UnboundedReceiver<Request>,
    mut reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    mut writer: tokio::net::unix::OwnedWriteHalf,
    token: String,
    live: Arc<Live>,
) {
    /// Fail the active request and everything queued behind it with `error(method, id)`.
    fn fail_all(
        active: Request,
        requests: &mut mpsc::UnboundedReceiver<Request>,
        error: &dyn Fn(&str, u64) -> AnalysisError,
    ) {
        let _ = active.reply.send(Err(error(&active.method, active.id)));
        requests.close();
        while let Ok(pending) = requests.try_recv() {
            let _ = pending.reply.send(Err(error(&pending.method, pending.id)));
        }
    }
    let unreachable = |method: &str, id: u64| process_failure(&live, Some(method), Some(id));
    while let Some(request) = requests.recv().await {
        if request.reply.is_closed() {
            continue;
        }
        let line = format!(
            "{}\n",
            json!({ "id": request.id, "token": token, "method": request.method, "params": request.params })
        );
        request.transmitted.store(true, Ordering::SeqCst);
        if writer.write_all(line.as_bytes()).await.is_err() {
            live.dead.store(true, Ordering::SeqCst);
            fail_all(request, &mut requests, &unreachable);
            return;
        }
        loop {
            let mut buffer = Vec::new();
            match read_line(&mut reader, &mut buffer).await {
                Err(message) => {
                    live.dead.store(true, Ordering::SeqCst);
                    let protocol = |_: &str, _: u64| AnalysisError::HopperProtocol { message: message.clone() };
                    fail_all(request, &mut requests, &protocol);
                    return;
                }
                Ok(0) => {
                    live.dead.store(true, Ordering::SeqCst);
                    // Let the launcher exit status settle so the failure names it.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    fail_all(request, &mut requests, &unreachable);
                    return;
                }
                Ok(_) => {}
            }
            let text = String::from_utf8_lossy(&buffer).to_string();
            let trimmed = text.trim();
            if trimmed.is_empty() {
                continue;
            }
            let abort = |message: String, request: Request, requests: &mut mpsc::UnboundedReceiver<Request>| {
                live.dead.store(true, Ordering::SeqCst);
                let protocol = |_: &str, _: u64| AnalysisError::HopperProtocol { message: message.clone() };
                fail_all(request, requests, &protocol);
            };
            match parse_message(trimmed) {
                Err(message) => {
                    abort(message, request, &mut requests);
                    return;
                }
                Ok(Message::Event { id }) => {
                    if id >= live.next_id.load(Ordering::SeqCst) {
                        abort("Hopper returned an unknown response id".to_string(), request, &mut requests);
                        return;
                    }
                }
                Ok(Message::Response { id, result }) => {
                    if id == request.id {
                        let outcome = result.map_err(|remote| remote.with_context(&request.method, request.id));
                        let _ = request.reply.send(outcome);
                        break;
                    }
                    if id >= live.next_id.load(Ordering::SeqCst) {
                        abort("Hopper returned an unknown response id".to_string(), request, &mut requests);
                        return;
                    }
                    // A stale reply to an abandoned request: ignore.
                }
            }
        }
    }
}

fn process_failure(live: &Live, method: Option<&str>, id: Option<u64>) -> AnalysisError {
    HopperClient::process_error(live, method, id, "unreachable")
}

struct Remote {
    code: i64,
    message: String,
    diagnostic_type: String,
}

impl Remote {
    fn with_context(self, method: &str, id: u64) -> AnalysisError {
        AnalysisError::HopperRemote {
            code: self.code,
            safe_message: self.message,
            diagnostic_type: self.diagnostic_type,
            operation: Some(method.to_string()),
            request_id: Some(id),
        }
    }
}

enum Message {
    Response { id: u64, result: Result<Value, Remote> },
    Event { id: u64 },
}

fn parse_message(line: &str) -> Result<Message, String> {
    let value: Value = serde_json::from_str(line).map_err(|_| "Hopper returned malformed JSON".to_string())?;
    let outside = || "Hopper returned a message outside the bridge contract".to_string();
    let object = value.as_object().ok_or_else(outside)?;
    let id = object.get("id").and_then(Value::as_u64).ok_or_else(outside)?;
    if object.len() != 2 {
        return Err(outside());
    }
    if let Some(result) = object.get("result") {
        return Ok(Message::Response {
            id,
            result: Ok(result.clone()),
        });
    }
    if let Some(error) = object.get("error") {
        let error = error.as_object().ok_or_else(outside)?;
        let code = error.get("code").and_then(Value::as_i64).ok_or_else(outside)?;
        let message = error.get("message").and_then(Value::as_str).ok_or_else(outside)?;
        let kind = error.get("type").and_then(Value::as_str).unwrap_or("remote");
        if !["remote", "authorization", "invalid_request", "capability_unavailable", "bridge_exception"].contains(&kind) {
            return Err(outside());
        }
        return Ok(Message::Response {
            id,
            result: Err(Remote {
                code,
                message: message.to_string(),
                diagnostic_type: kind.to_string(),
            }),
        });
    }
    if let Some(event) = object.get("event") {
        let kind = event.get("type").and_then(Value::as_str);
        if kind == Some("progress") || kind == Some("diagnostic") {
            return Ok(Message::Event { id });
        }
    }
    Err(outside())
}

async fn read_line(
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    buffer: &mut Vec<u8>,
) -> Result<usize, String> {
    let mut total = 0usize;
    loop {
        let chunk = reader
            .fill_buf()
            .await
            .map_err(|e| format!("Hopper socket failed: {e}"))?;
        if chunk.is_empty() {
            return Ok(total);
        }
        match chunk.iter().position(|b| *b == b'\n') {
            Some(position) => {
                buffer.extend_from_slice(&chunk[..position]);
                total += position + 1;
                reader.consume(position + 1);
                return Ok(total);
            }
            None => {
                let length = chunk.len();
                buffer.extend_from_slice(chunk);
                total += length;
                reader.consume(length);
                if buffer.len() > MAX_LINE_BYTES {
                    return Err("Hopper response exceeds the transport limit".to_string());
                }
            }
        }
    }
}

fn spawn_drain<R>(stream: Option<R>, streams: SharedStreams, stdout: bool)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let Some(mut stream) = stream else { return };
    tokio::spawn(async move {
        let mut chunk = vec![0u8; 8192];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut guard = streams.lock().unwrap();
                    let inner = &mut *guard;
                    let (buffer, total) = if stdout {
                        (&mut inner.stdout, &mut inner.stdout_total)
                    } else {
                        (&mut inner.stderr, &mut inner.stderr_total)
                    };
                    *total += n as u64;
                    buffer.extend_from_slice(&chunk[..n]);
                    if buffer.len() > DIAGNOSTIC_BYTES {
                        let excess = buffer.len() - DIAGNOSTIC_BYTES;
                        buffer.drain(..excess);
                    }
                }
            }
        }
    });
}

/// Session root: `/tmp` on macOS (socket path limits), the temp dir elsewhere.
fn session_root() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/tmp")
    } else {
        std::env::temp_dir()
    }
}

use crate::process::{random_hex, random_uuid};

fn make_private_dir(parent: &Path, prefix: &str) -> std::io::Result<PathBuf> {
    for _ in 0..16 {
        let path = parent.join(format!("{prefix}{}", random_hex(6)));
        match std::fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("could not allocate a private runtime directory"))
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}
