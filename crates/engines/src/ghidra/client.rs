//! One isolated, authenticated headless Ghidra session (port of `GhidraClient.ts`,
//! `GhidraLauncher.ts`, `GhidraJavaLaunch.ts` and the bridge wire protocol, POSIX only).
//!
//! Ghidra imports an immutable private copy of the target into an ephemeral project,
//! runs REA's packaged bridge script and serves newline-delimited JSON over a private
//! Unix socket guarded by a per-session token. The project, the socket and the target
//! copy live in a 0700 runtime directory removed on close.

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::Command;
use tokio::sync::Mutex;

use crate::provider::tokio_util_lite::CancelToken;

use super::capabilities::session_capabilities;
use super::install::{ghidra_java_environment, GhidraInstallation};

const BRIDGE: &str = include_str!("../../bridge/ghidra/ReaGhidraBridge.java");
const EXTENSIONS: &str = include_str!("../../bridge/ghidra/ReaGhidraExtensions.java");
const NO_RETURN_FIX: &str = include_str!("../../bridge/ghidra/ReaGhidraNoReturnFix.java");

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: usize = 256 * 1024 * 1024;
const DIAGNOSTIC_BYTES: usize = 64 * 1024;

/// Failure phase for one private Ghidra headless session.
#[derive(Debug, Clone)]
pub struct SessionError {
    pub kind: &'static str,
    pub message: String,
    pub remote_code: Option<String>,
    pub timeout_ms: Option<u64>,
    pub diagnostics: Value,
}

impl SessionError {
    fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            remote_code: None,
            timeout_ms: None,
            diagnostics: json!({}),
        }
    }

    fn with_diagnostics(mut self, diagnostics: Value) -> Self {
        let mut merged = self.diagnostics.as_object().cloned().unwrap_or_default();
        if let Some(extra) = diagnostics.as_object() {
            for (k, v) in extra {
                merged.insert(k.clone(), v.clone());
            }
        }
        merged.insert("failure_kind".into(), json!(self.kind));
        merged.insert("failure_message".into(), json!(self.message));
        if let Some(code) = &self.remote_code {
            merged.insert("remote_code".into(), json!(code));
            merged.insert("remote_message".into(), json!(self.message));
        }
        self.diagnostics = Value::Object(merged);
        self
    }
}

#[derive(Debug, Clone)]
pub struct GhidraClientOptions {
    pub installation: GhidraInstallation,
    pub environment: BTreeMap<String, String>,
    pub target_path: String,
    pub target_sha256: String,
    pub provider_version: String,
    pub profile_digest: String,
    pub startup_timeout_ms: u64,
}

struct Connection {
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: tokio::net::unix::OwnedWriteHalf,
}

/// Process and private files of one started session.
struct Live {
    pid: i32,
    exited: Arc<AtomicBool>,
    dead: AtomicBool,
    runtime_root: PathBuf,
    socket_root: Option<PathBuf>,
    token: String,
    next_id: AtomicU64,
    snapshot_path: PathBuf,
    streams: SharedStreams,
    connection: Mutex<Option<Connection>>,
    info: StdMutex<Value>,
}

#[derive(Default)]
struct Streams {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_total: u64,
    stderr_total: u64,
}

/// Removes the session directories unless ownership moved to `Live`.
struct DirsGuard {
    runtime: PathBuf,
    socket: Option<PathBuf>,
    armed: bool,
}

impl Drop for DirsGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_dir_all(&self.runtime);
            if let Some(root) = &self.socket {
                let _ = std::fs::remove_dir_all(root);
            }
        }
    }
}

impl Live {
    fn kill_group(&self) {
        if !self.exited.load(Ordering::SeqCst) {
            crate::process::kill_group(self.pid);
        }
        self.dead.store(true, Ordering::SeqCst);
    }

    fn diagnostics(&self, options: &GhidraClientOptions) -> Value {
        let snapshot = self.streams.lock().unwrap();
        let redact = |bytes: &[u8]| -> String {
            String::from_utf8_lossy(bytes).replace(&self.token, "[REDACTED]")
        };
        json!({
            "target_path": options.target_path,
            "target_sha256": options.target_sha256,
            "transport": "unix-socket",
            "provider_version": options.provider_version,
            "profile_digest": options.profile_digest,
            "runtime_root": self.runtime_root.to_string_lossy(),
            "process_id": self.pid,
            "stdout": { "text": redact(&snapshot.stdout), "bytes": snapshot.stdout_total, "retained_bytes": snapshot.stdout.len() },
            "stderr": { "text": redact(&snapshot.stderr), "bytes": snapshot.stderr_total, "retained_bytes": snapshot.stderr.len() },
        })
    }
}

/// Kills the session process group when a request future is dropped mid-flight.
struct InFlight {
    live: Arc<Live>,
    armed: bool,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if self.armed {
            self.live.kill_group();
        }
    }
}

pub struct GhidraClient {
    options: GhidraClientOptions,
    state: Mutex<Option<Arc<Live>>>,
}

impl GhidraClient {
    pub fn new(options: GhidraClientOptions) -> Self {
        Self {
            options,
            state: Mutex::new(None),
        }
    }

    pub fn options(&self) -> &GhidraClientOptions {
        &self.options
    }

    /// Launch Ghidra once and require its exact post-analysis handshake.
    pub async fn start(&self, cancel: &CancelToken) -> Result<Value, SessionError> {
        let mut state = self.state.lock().await;
        let live = self.ensure_live(&mut state, cancel).await?;
        let info = live.info.lock().unwrap().clone();
        Ok(info)
    }

    /// Execute one admitted operation through the serial per-Program queue.
    pub async fn call_tool(
        &self,
        operation: &str,
        parameters: &Value,
        cancel: &CancelToken,
    ) -> Result<Value, SessionError> {
        let mut state = self.state.lock().await;
        if cancel.is_cancelled() {
            return Err(SessionError::new("cancelled", "Ghidra request was cancelled"));
        }
        let live = self.ensure_live(&mut state, cancel).await?;
        let mut guard = InFlight {
            live: live.clone(),
            armed: true,
        };
        let outcome = self
            .request(&live, operation, parameters, None, Some(cancel))
            .await;
        guard.armed = false;
        match outcome {
            Err(error) if error.kind == "cancelled" => {
                // Cancelling an active request terminates the ephemeral database.
                live.kill_group();
                let taken = state.take();
                drop(state);
                if let Some(taken) = taken {
                    self.cleanup(&taken).await;
                }
                Err(error)
            }
            Err(error) if error.kind == "process" || error.kind == "protocol" => {
                live.kill_group();
                let taken = state.take();
                drop(state);
                if let Some(taken) = taken {
                    self.cleanup(&taken).await;
                }
                Err(error)
            }
            other => other,
        }
    }

    /// Read the private immutable source copy used for independent verification.
    pub async fn read_target_snapshot(&self) -> Result<Vec<u8>, SessionError> {
        let state = self.state.lock().await;
        let Some(live) = state.as_ref() else {
            return Err(SessionError::new(
                "protocol",
                "Ghidra target snapshot is unavailable before startup or after close",
            ));
        };
        std::fs::read(&live.snapshot_path).map_err(|e| {
            SessionError::new(
                "protocol",
                format!("Ghidra target snapshot could not be read for load-image verification: {e}"),
            )
        })
    }

    /// Stop the owned process group and remove all project/runtime artifacts.
    pub async fn close(&self) -> Result<(), SessionError> {
        let taken = self.state.lock().await.take();
        let Some(live) = taken else {
            return Ok(());
        };
        if !live.dead.load(Ordering::SeqCst) && !live.exited.load(Ordering::SeqCst) {
            let shutdown = self
                .request(&live, "shutdown", &json!({}), Some(SHUTDOWN_TIMEOUT), None)
                .await;
            let acknowledged = shutdown
                .as_ref()
                .map(|v| v["shutdown"] == json!(true) && v["project_ephemeral"] == json!(true))
                .unwrap_or(false);
            if !acknowledged {
                tracing::warn!("Ghidra bridge shutdown was not confirmed");
            }
            // Give the JVM a moment to exit by itself before stopping the group.
            let deadline = Instant::now() + Duration::from_millis(500);
            while Instant::now() < deadline && !live.exited.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        self.cleanup(&live).await;
        Ok(())
    }

    async fn cleanup(&self, live: &Arc<Live>) {
        live.kill_group();
        // The reaper observes the exit; wait briefly so the files are quiescent.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !live.exited.load(Ordering::SeqCst) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        *live.connection.lock().await = None;
        let root = live.runtime_root.clone();
        let socket_root = live.socket_root.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let _ = std::fs::remove_dir_all(&root);
            if let Some(socket_root) = socket_root {
                let _ = std::fs::remove_dir_all(socket_root);
            }
        })
        .await;
    }

    async fn ensure_live(
        &self,
        state: &mut Option<Arc<Live>>,
        cancel: &CancelToken,
    ) -> Result<Arc<Live>, SessionError> {
        if let Some(live) = state.as_ref() {
            if !live.dead.load(Ordering::SeqCst) && !live.exited.load(Ordering::SeqCst) {
                return Ok(live.clone());
            }
            let stale = state.take().unwrap();
            self.cleanup(&stale).await;
        }
        match self.start_session(cancel).await {
            Ok(live) => {
                *state = Some(live.clone());
                Ok(live)
            }
            Err(error) => Err(error),
        }
    }

    async fn start_session(&self, cancel: &CancelToken) -> Result<Arc<Live>, SessionError> {
        if cancel.is_cancelled() {
            return Err(SessionError::new("cancelled", "Ghidra startup was cancelled"));
        }
        let deadline = Instant::now() + Duration::from_millis(self.options.startup_timeout_ms);
        let installation = &self.options.installation;
        let analyze_headless = installation
            .analyze_headless_path
            .clone()
            .ok_or_else(|| SessionError::new("start", "Ghidra installation is incomplete"))?;
        let java_home = installation
            .java_home
            .clone()
            .ok_or_else(|| SessionError::new("start", "POSIX Ghidra requires its inspected JDK home"))?;

        let runtime_root = make_private_dir(&session_root(), "rea-ghidra-")
            .map_err(|e| SessionError::new("start", format!("Ghidra runtime root creation failed: {e}")))?;
        // Owns the runtime directories from this point on, so a cancelled (dropped) startup future
        // cannot leave a target copy, a project or the session descriptor behind.
        let mut dirs = DirsGuard { runtime: runtime_root.clone(), socket: None, armed: true };
        let outcome = self
            .start_in(&runtime_root, &mut dirs.socket, &analyze_headless, &java_home, deadline, cancel)
            .await;
        match outcome {
            Ok(live) => {
                dirs.armed = false; // `Live` owns the directories now (see its Drop)
                Ok(live)
            }
            Err((error, live)) => {
                if let Some(live) = live {
                    live.kill_group();
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while !live.exited.load(Ordering::SeqCst) && Instant::now() < deadline {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
                drop(dirs);
                Err(error)
            }
        }
    }

    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    async fn start_in(
        &self,
        runtime_root: &Path,
        socket_root: &mut Option<PathBuf>,
        analyze_headless: &str,
        java_home: &str,
        deadline: Instant,
        cancel: &CancelToken,
    ) -> Result<Arc<Live>, (SessionError, Option<Arc<Live>>)> {
        let fail = |e: SessionError| (e, None);
        let mut sub = BTreeMap::new();
        for name in ["project", "home", "tmp", "cache", "config", "data", "bridge"] {
            let path = runtime_root.join(name);
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&path)
                .map_err(|e| fail(SessionError::new("start", format!("Ghidra runtime directory creation failed: {e}"))))?;
            sub.insert(name, path);
        }
        // sockaddr_un holds 108 bytes including the terminating NUL.
        let mut endpoint = runtime_root.join("bridge.sock");
        if endpoint.as_os_str().len() > 107 {
            let root = make_private_dir(Path::new("/tmp"), "rea-ghidra-socket-")
                .map_err(|e| fail(SessionError::new("start", format!("Ghidra private endpoint allocation failed: {e}"))))?;
            endpoint = root.join("s");
            *socket_root = Some(root);
        }
        let snapshot_path = create_snapshot(&self.options.target_path, runtime_root, &self.options.target_sha256)
            .map_err(|e| fail(SessionError::new("start", format!("Ghidra target snapshot failed admission: {e}"))))?;
        // Packaged scripts, written next to the private project.
        let bridge_dir = &sub["bridge"];
        for (name, content) in [
            ("ReaGhidraBridge.java", BRIDGE),
            ("ReaGhidraExtensions.java", EXTENSIONS),
            ("ReaGhidraNoReturnFix.java", NO_RETURN_FIX),
        ] {
            write_private(&bridge_dir.join(name), content.as_bytes())
                .map_err(|e| fail(SessionError::new("start", format!("Ghidra bridge staging failed: {e}"))))?;
        }
        let token = random_hex(32);
        let run_id = random_uuid();
        let descriptor_path = runtime_root.join("session.json");
        write_private(
            &descriptor_path,
            format!(
                "{}\n",
                json!({
                    "transport": "unix-socket",
                    "endpoint_path": endpoint.to_string_lossy(),
                    "token": token,
                    "run_id": run_id,
                    "target_sha256": self.options.target_sha256,
                    "provider_version": self.options.provider_version,
                    "profile_digest": self.options.profile_digest,
                })
            )
            .as_bytes(),
        )
        .map_err(|e| fail(SessionError::new("start", format!("Ghidra descriptor write failed: {e}"))))?;
        if cancel.is_cancelled() {
            return Err(fail(SessionError::new("cancelled", "Ghidra startup was cancelled")));
        }

        let ghidra_log = runtime_root.join("ghidra.log");
        let script_log = runtime_root.join("script.log");
        let mut headless_arguments: Vec<String> = vec![
            sub["project"].to_string_lossy().to_string(),
            "rea-project".to_string(),
            "-import".to_string(),
            snapshot_path.to_string_lossy().to_string(),
            "-readOnly".to_string(),
            "-deleteProject".to_string(),
            "-log".to_string(),
            ghidra_log.to_string_lossy().to_string(),
            "-scriptlog".to_string(),
            script_log.to_string_lossy().to_string(),
            "-scriptPath".to_string(),
            bridge_dir.to_string_lossy().to_string(),
            "-postScript".to_string(),
            bridge_dir.join("ReaGhidraNoReturnFix.java").to_string_lossy().to_string(),
            "-postScript".to_string(),
            bridge_dir.join("ReaGhidraBridge.java").to_string_lossy().to_string(),
            descriptor_path.to_string_lossy().to_string(),
        ];

        // Environment: inspected JDK first, then the per-session private home.
        let mut environment = ghidra_java_environment(Some(java_home), &self.options.environment);
        let home_root = sub["home"].to_string_lossy().to_string();
        let temp_root = sub["tmp"].to_string_lossy().to_string();
        let isolated = [
            format!("-Duser.home={home_root}"),
            format!("-Djava.io.tmpdir={temp_root}"),
        ];
        environment.insert("JDK_JAVA_OPTIONS".into(), String::new());
        environment.insert("GHIDRA_HEADLESS_JAVA_OPTIONS".into(), String::new());
        environment.insert("HOME".into(), home_root.clone());
        environment.insert("TMPDIR".into(), temp_root.clone());
        environment.insert("XDG_CACHE_HOME".into(), sub["cache"].to_string_lossy().to_string());
        environment.insert("XDG_CONFIG_HOME".into(), sub["config"].to_string_lossy().to_string());
        environment.insert("XDG_DATA_HOME".into(), sub["data"].to_string_lossy().to_string());

        let java = Path::new(java_home).join("bin").join("java");
        let support_root = Path::new(analyze_headless)
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| fail(SessionError::new("start", "Ghidra support directory is unavailable")))?;
        let install_root = support_root
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| fail(SessionError::new("start", "Ghidra install directory is unavailable")))?;
        let support_args = |flag: &str| -> Vec<String> {
            let mut a = isolated.to_vec();
            a.extend([
                "-cp".to_string(),
                support_root.join("LaunchSupport.jar").to_string_lossy().to_string(),
                "LaunchSupport".to_string(),
                install_root.to_string_lossy().to_string(),
                flag.to_string(),
            ]);
            a
        };
        let envvars = run_support(&java, &support_args("-envvars"), &environment).await.map_err(fail)?;
        for line in envvars.lines() {
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(fail(SessionError::new(
                    "start",
                    format!("Invalid Ghidra LaunchSupport environment entry: {line}"),
                )));
            };
            if key.is_empty()
                || !key.chars().next().map(|c| c.is_ascii_alphabetic() || c == '_').unwrap_or(false)
                || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                return Err(fail(SessionError::new(
                    "start",
                    format!("Invalid Ghidra LaunchSupport environment entry: {line}"),
                )));
            }
            if environment.get(key).map(|v| v.is_empty()).unwrap_or(true) {
                environment.insert(key.to_string(), value.to_string());
            }
        }
        let vmargs_text = run_support(&java, &support_args("-vmargs"), &environment).await.map_err(fail)?;
        let vm_arguments: Vec<String> = vmargs_text
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        if vm_arguments.iter().any(|a| !a.starts_with('-') || a.contains('\0')) {
            return Err(fail(SessionError::new("start", "Invalid Ghidra LaunchSupport JVM argument")));
        }
        let max_memory = environment
            .get("GHIDRA_HEADLESS_MAXMEM")
            .filter(|v| !v.is_empty())
            .or_else(|| environment.get("GHIDRA_MAXMEM").filter(|v| !v.is_empty()))
            .cloned()
            .unwrap_or_else(|| "2G".to_string());
        let mut arguments = vm_arguments;
        arguments.extend([
            format!("-Xmx{max_memory}"),
            "-XX:ParallelGCThreads=2".to_string(),
            "-XX:CICompilerCount=2".to_string(),
            "-Djava.awt.headless=true".to_string(),
        ]);
        arguments.extend(isolated.iter().cloned());
        arguments.extend([
            "-showversion".to_string(),
            "-cp".to_string(),
            install_root
                .join("Ghidra/Framework/Utility/lib/Utility.jar")
                .to_string_lossy()
                .to_string(),
            "ghidra.Ghidra".to_string(),
            "ghidra.app.util.headless.AnalyzeHeadless".to_string(),
        ]);
        arguments.append(&mut headless_arguments);

        let mut command = Command::new(&java);
        command
            .args(&arguments)
            .env_clear()
            .envs(&environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(false);
        command.process_group(0);
        crate::process::harden_child(&mut command);
        let mut child = command
            .spawn()
            .map_err(|e| fail(SessionError::new("start", format!("Ghidra headless launch failed: {e}"))))?;
        let pid = child.id().unwrap_or(0) as i32;
        crate::process::spawn_watchdog(pid);
        let exited = Arc::new(AtomicBool::new(false));
        let streams: SharedStreams = Arc::new(StdMutex::new(Streams::default()));
        spawn_drain(child.stdout.take(), streams.clone(), true);
        spawn_drain(child.stderr.take(), streams.clone(), false);
        {
            let exited = exited.clone();
            tokio::spawn(async move {
                let _ = child.wait().await;
                exited.store(true, Ordering::SeqCst);
            });
        }
        let live = Arc::new(Live {
            pid,
            exited: exited.clone(),
            dead: AtomicBool::new(false),
            runtime_root: runtime_root.to_path_buf(),
            socket_root: socket_root.clone(),
            token: token.clone(),
            next_id: AtomicU64::new(1),
            snapshot_path,
            streams,
            connection: Mutex::new(None),
            info: StdMutex::new(Value::Null),
        });
        let connect = async {
            loop {
                if cancel.is_cancelled() {
                    return Err(SessionError::new("cancelled", "Ghidra startup was cancelled"));
                }
                if exited.load(Ordering::SeqCst) {
                    return Err(SessionError::new("process", "Ghidra exited before bridge startup"));
                }
                if Instant::now() >= deadline {
                    return Err(SessionError {
                        timeout_ms: Some(self.options.startup_timeout_ms),
                        ..SessionError::new("timeout", "Ghidra startup deadline elapsed")
                    });
                }
                if endpoint.exists() {
                    if let Ok(stream) = UnixStream::connect(&endpoint).await {
                        let (read, write) = stream.into_split();
                        return Ok(Connection {
                            reader: BufReader::new(read),
                            writer: write,
                        });
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        match connect.await {
            Ok(connection) => {
                *live.connection.lock().await = Some(connection);
            }
            Err(error) => {
                let diagnostics = live.diagnostics(&self.options);
                return Err((error.with_diagnostics(diagnostics), Some(live)));
            }
        }
        let handshake = self
            .request(&live, "ping", &json!({}), Some(remaining(deadline)), Some(cancel))
            .await;
        let info = match handshake {
            Ok(value) => value,
            Err(error) => {
                let diagnostics = live.diagnostics(&self.options);
                return Err((error.with_diagnostics(diagnostics), Some(live)));
            }
        };
        let verified = self.parse_session_info(&info, &run_id).and_then(|()| {
            if info["analysis_timed_out"] == json!(true) {
                Err(SessionError::new(
                    "analysis_timeout",
                    "Ghidra auto-analysis reached its per-file deadline",
                ))
            } else {
                Ok(())
            }
        });
        if let Err(error) = verified {
            let diagnostics = live.diagnostics(&self.options);
            return Err((error.with_diagnostics(diagnostics), Some(live)));
        }
        *live.info.lock().unwrap() = info;
        Ok(live)
    }

    fn parse_session_info(&self, info: &Value, run_id: &str) -> Result<(), SessionError> {
        let invalid = || SessionError::new("protocol", "Ghidra bridge handshake is invalid");
        let object = info.as_object().ok_or_else(invalid)?;
        let string_at = |value: &Value, key: &str| value.get(key).and_then(Value::as_str).map(str::to_string);
        if object.get("name").and_then(Value::as_str) != Some("REA Ghidra bridge") {
            return Err(invalid());
        }
        let capabilities: Vec<String> = object
            .get("capabilities")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .ok_or_else(invalid)?;
        let expected = session_capabilities();
        let mut sorted = capabilities.clone();
        sorted.sort();
        sorted.dedup();
        let mut expected_sorted: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
        expected_sorted.sort();
        let provider = info.get("provider").ok_or_else(invalid)?;
        let target = info.get("target").ok_or_else(invalid)?;
        let complete = object.get("analysis_complete").and_then(Value::as_bool).ok_or_else(invalid)?;
        let timed_out = object.get("analysis_timed_out").and_then(Value::as_bool).ok_or_else(invalid)?;
        let ok = string_at(info, "run_id").as_deref() == Some(run_id)
            && object.get("read_only").and_then(Value::as_bool) == Some(false)
            && capabilities.len() == expected.len()
            && sorted == expected_sorted
            && provider.get("id").and_then(Value::as_str) == Some("ghidra")
            && string_at(provider, "version").as_deref() == Some(self.options.provider_version.as_str())
            && string_at(info, "profile_digest").as_deref() == Some(self.options.profile_digest.as_str())
            && string_at(target, "sha256").as_deref() == Some(self.options.target_sha256.as_str())
            && complete != timed_out;
        if ok {
            Ok(())
        } else {
            Err(SessionError::new("protocol", "Ghidra bridge handshake is invalid")
                .with_diagnostics(json!({ "failure_cause": { "message": "Ghidra bridge handshake identity is invalid" } })))
        }
    }

    /// Write one authenticated request and return its correlated reply.
    async fn request(
        &self,
        live: &Arc<Live>,
        method: &str,
        params: &Value,
        timeout: Option<Duration>,
        cancel: Option<&CancelToken>,
    ) -> Result<Value, SessionError> {
        let mut guard = live.connection.lock().await;
        let Some(connection) = guard.as_mut() else {
            return Err(SessionError::new("process", "Ghidra bridge is unavailable"));
        };
        if cancel.map(CancelToken::is_cancelled).unwrap_or(false) {
            return Err(SessionError::new("cancelled", "Ghidra request was cancelled"));
        }
        let id = live.next_id.fetch_add(1, Ordering::SeqCst);
        let line = format!(
            "{}\n",
            json!({ "id": id, "token": live.token, "method": method, "params": params })
        );
        let exchange = async {
            connection
                .writer
                .write_all(line.as_bytes())
                .await
                .map_err(|e| SessionError::new("process", format!("Ghidra bridge write failed: {e}")))?;
            loop {
                let mut buffer = Vec::new();
                let read = read_line_limited(&mut connection.reader, &mut buffer).await?;
                if read == 0 {
                    return Err(SessionError::new("process", "Ghidra bridge socket closed"));
                }
                let text = String::from_utf8_lossy(&buffer);
                let trimmed = text.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let response: Value = serde_json::from_str(trimmed)
                    .map_err(|_| SessionError::new("protocol", "Ghidra bridge response is not valid JSON"))?;
                let Some(object) = response.as_object() else {
                    return Err(SessionError::new("protocol", "Ghidra bridge response has an invalid shape"));
                };
                let response_id = object.get("id").and_then(Value::as_u64);
                let ok = object.get("ok").and_then(Value::as_bool);
                let shape_ok = match (response_id, ok) {
                    (Some(_), Some(true)) => object.contains_key("result") && object.len() == 3,
                    (Some(_), Some(false)) => object.contains_key("error") && object.len() == 3,
                    _ => false,
                };
                if !shape_ok {
                    return Err(SessionError::new("protocol", "Ghidra bridge response has an invalid shape"));
                }
                let response_id = response_id.unwrap();
                if response_id != id {
                    if response_id >= id {
                        return Err(SessionError::new("protocol", "Ghidra returned an unknown response id"));
                    }
                    continue;
                }
                if ok == Some(true) {
                    return Ok(object["result"].clone());
                }
                let error = &object["error"];
                let code = error.get("code").and_then(Value::as_str).unwrap_or("").to_string();
                let message = error.get("message").and_then(Value::as_str).unwrap_or("").to_string();
                if code.is_empty() || message.is_empty() {
                    return Err(SessionError::new("protocol", "Ghidra bridge response has an invalid shape"));
                }
                let mut failure = SessionError::new("remote", message);
                failure.remote_code = Some(code);
                return Err(failure);
            }
        };
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
            result = exchange => result,
            _ = cancelled => Err(SessionError::new("cancelled", "Ghidra request was cancelled")),
            _ = timed => Err(SessionError {
                timeout_ms: timeout.map(|t| t.as_millis() as u64),
                ..SessionError::new("timeout", "Ghidra bridge request timed out")
            }),
        }
    }

    /// Latest bounded local diagnostics for a failed call.
    pub async fn diagnostics(&self) -> Value {
        let state = self.state.lock().await;
        match state.as_ref() {
            Some(live) => live.diagnostics(&self.options),
            None => json!({
                "target_path": self.options.target_path,
                "target_sha256": self.options.target_sha256,
                "transport": "unix-socket",
                "provider_version": self.options.provider_version,
                "profile_digest": self.options.profile_digest,
            }),
        }
    }
}

type SharedStreams = Arc<StdMutex<Streams>>;

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1))
}

async fn read_line_limited(
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    buffer: &mut Vec<u8>,
) -> Result<usize, SessionError> {
    let mut total = 0usize;
    loop {
        let chunk = reader
            .fill_buf()
            .await
            .map_err(|e| SessionError::new("process", format!("Ghidra bridge socket failed: {e}")))?;
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
                if buffer.len() > MAX_RESPONSE_BYTES {
                    return Err(SessionError::new("protocol", "Ghidra bridge response exceeds the transport limit"));
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
                    let streams_ref = &mut *guard;
                    let (buffer, total) = if stdout {
                        (&mut streams_ref.stdout, &mut streams_ref.stdout_total)
                    } else {
                        (&mut streams_ref.stderr, &mut streams_ref.stderr_total)
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

async fn run_support(
    java: &Path,
    arguments: &[String],
    environment: &BTreeMap<String, String>,
) -> Result<String, SessionError> {
    let mut command = Command::new(java);
    command
        .args(arguments)
        .env_clear()
        .envs(environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(60), command.output())
        .await
        .map_err(|_| SessionError::new("start", "Ghidra LaunchSupport timed out"))?
        .map_err(|e| SessionError::new("start", format!("Ghidra LaunchSupport failed: {e}")))?;
    if !output.status.success() {
        return Err(SessionError::new("start", "Ghidra LaunchSupport failed"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Session roots may not contain a dot-prefixed path element: Ghidra rejects them.
fn session_root() -> PathBuf {
    let base = std::env::temp_dir();
    let has_dot = |p: &Path| {
        p.components()
            .any(|c| c.as_os_str().to_string_lossy().starts_with('.') && c.as_os_str() != "." && c.as_os_str() != "..")
    };
    if !has_dot(&base) {
        return base;
    }
    let fallback = PathBuf::from("/tmp");
    if !has_dot(&fallback) {
        return fallback;
    }
    let mut current = base.clone();
    while has_dot(&current) {
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => return base,
        }
    }
    current
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

/// Copy one target and require its bytes to match the parsed target identity.
fn create_snapshot(source: &str, runtime_root: &Path, expected_sha256: &str) -> Result<PathBuf, String> {
    if expected_sha256.len() != 64 || !expected_sha256.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
        return Err("Ghidra target SHA-256 commitment is invalid".to_string());
    }
    let extension = Path::new(source)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .filter(|e| e.len() <= 13 && e[1..].chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| ".bin".to_string());
    let destination = runtime_root.join(format!("target-{}{extension}", &expected_sha256[..12]));
    let mut input = std::fs::File::open(source).map_err(|e| format!("The selected Ghidra source could not be opened ({e})"))?;
    if !input.metadata().map(|m| m.is_file()).unwrap_or(false) {
        return Err("The selected Ghidra source is no longer a regular file".to_string());
    }
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&destination)
        .map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    use std::io::Write;
    loop {
        let n = input.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        output.write_all(&buffer[..n]).map_err(|e| e.to_string())?;
    }
    let observed = hex::encode(hasher.finalize());
    if observed != expected_sha256 {
        let _ = std::fs::remove_file(&destination);
        return Err(format!(
            "Ghidra target snapshot digest mismatch: expected {expected_sha256}, observed {observed}"
        ));
    }
    Ok(destination)
}

impl Drop for Live {
    fn drop(&mut self) {
        // Last reference gone (session closed or process shutting down): never leave the JVM behind.
        self.kill_group();
        let _ = std::fs::remove_dir_all(&self.runtime_root);
        if let Some(root) = &self.socket_root {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}
