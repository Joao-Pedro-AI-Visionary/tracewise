//! Active `capture_electron_scenario` provider (port of REA
//! browser/PlaywrightElectronActiveProvider.ts and PlaywrightElectronActiveActions.ts).
//!
//! REA launches the application through Playwright's `_electron.launch` with the
//! injected `scripts/electron-active-hook.cjs`. Tracewise keeps that hook as the
//! in-process bridge (same file, MIT attribution in its header) and replaces
//! Playwright with direct CDP control: see [`driver`] for the protocol mapping and
//! [`process`] for ownership and cleanup.
//!
//! Selection. REA constructs the provider unconditionally and launches whatever
//! `executable_path` the request names. Tracewise only runs an executable the
//! operator configured: `TRACEWISE_ELECTRON_EXECUTABLE` holds one or more
//! absolute paths separated by `:`. Without it the tool returns REA's
//! "active Electron observation provider is not configured" error; a request for
//! another executable returns the same error with its own reason.
//!
//! Divergences from REA, all deliberate:
//! - the Electron profile and `TMPDIR` live in a private 0700 directory that is
//!   removed with the process group (REA leaves `~/.config/Electron` and
//!   `/tmp` residue behind);
//! - ownership is proven by the process group created at launch, not by the
//!   environment token, which Chromium hides from `/proc/<pid>/environ`;
//! - a graceful `app.quit()` that does not finish within five seconds is followed
//!   by SIGTERM/SIGKILL of the group and the run still succeeds if the group is
//!   verified empty (REA turns that into `cleanup_failed`);
//! - selectors are CSS only.

pub mod driver;
pub mod process;

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};
use tracewise_domain::evidence::Evidence;

use crate::browser_observation::{browser_error, BrowserFailureReason};
use crate::electron_scenario::{
    create_electron_active_evidence, project_electron_active_capture, ElectronCaptureState,
    OPERATION, PLAYWRIGHT_ELECTRON_ACTIVE_PROVIDER_ID,
};
use crate::error::WebError;
use driver::Driver;
use process::{new_run_id, CleanupOutcome, OwnedElectron, SpawnSpec, StartupFailure};

pub const EXECUTABLES_ENV: &str = "TRACEWISE_ELECTRON_EXECUTABLE";
pub const RUNTIME_ROOT_ENV: &str = "TRACEWISE_ELECTRON_RUNTIME_DIR";
/// REA `STARTUP_TIMEOUT_MS`.
pub const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
const GRACEFUL_EXIT: Duration = Duration::from_secs(5);
const STDERR_IN_ERROR: usize = 2000;

/// Operator configuration of the active provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectronActiveConfig {
    /// Canonical paths of the Electron executables a request may launch.
    pub executables: Vec<PathBuf>,
    /// Parent of the private per-run directories.
    pub runtime_root: PathBuf,
    /// Time Electron has to publish its endpoints (REA: 60 seconds).
    pub startup_timeout: Duration,
}

impl ElectronActiveConfig {
    /// `None` when no Electron is configured.
    pub fn from_env() -> Option<Self> {
        let executables = std::env::var(EXECUTABLES_ENV).ok()?;
        Self::from_values(&executables, std::env::var(RUNTIME_ROOT_ENV).ok().as_deref())
    }

    pub fn from_values(executables: &str, runtime_root: Option<&str>) -> Option<Self> {
        let executables: Vec<PathBuf> = executables
            .split(':')
            .filter(|path| !path.is_empty())
            .filter_map(|path| std::fs::canonicalize(path).ok())
            .collect();
        if executables.is_empty() {
            return None;
        }
        Some(Self {
            executables,
            runtime_root: runtime_root
                .filter(|root| !root.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir),
            startup_timeout: STARTUP_TIMEOUT,
        })
    }
}

/// Failure of the active tool: a plain browser-style failure, or the REA
/// `cleanup_incomplete` error that keeps what was collected.
#[derive(Debug)]
pub enum ElectronCaptureError {
    Web(WebError),
    CleanupIncomplete(Box<CleanupIncomplete>),
}

#[derive(Debug)]
pub struct CleanupIncomplete {
    pub cleanup_reason: String,
    pub resources: Vec<String>,
    /// Message of the capture failure that preceded the cleanup problem.
    pub capture_failure: Option<String>,
    pub partial_observation: Option<Value>,
}

impl From<WebError> for ElectronCaptureError {
    fn from(error: WebError) -> Self {
        Self::Web(error)
    }
}

impl std::fmt::Display for ElectronCaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Web(error) => write!(f, "{error}"),
            Self::CleanupIncomplete(info) => write!(f, "Electron cleanup could not be verified: {}", info.cleanup_reason),
        }
    }
}

impl std::error::Error for ElectronCaptureError {}

impl CleanupIncomplete {
    /// REA `projectAnalysisError` body for a `BrowserObservationError(cleanup_failed)`.
    pub fn body(&self) -> Value {
        let retained = if self.partial_observation.is_some() {
            " Collected observations are retained in partial_observation."
        } else {
            ""
        };
        let also = self
            .capture_failure
            .as_ref()
            .map(|message| format!(" Capture also failed: {message}."))
            .unwrap_or_default();
        let message = format!(
            "Electron cleanup could not be verified: {}.{retained}{also} Inspect the reported process resources before launching another capture.",
            self.cleanup_reason
        );
        let mut details = json!({
            "operation": OPERATION,
            "reason": "cleanup_failed",
            "cleanup": "incomplete",
            "resources": self.resources,
            "cleanup_reason": self.cleanup_reason,
            "execution_failure": "unreadable_output",
        });
        if let Some(partial) = &self.partial_observation {
            details["partial_observation"] = partial.clone();
        }
        json!({
            "error": {
                "code": "cleanup_incomplete",
                "category": "execution_failure",
                "message": message,
                "retryable": false,
                "remediation": { "action": message },
                "details": details,
            }
        })
    }
}

fn not_configured(reason: &str) -> WebError {
    WebError::CapabilityUnavailable {
        capability: PLAYWRIGHT_ELECTRON_ACTIVE_PROVIDER_ID.to_string(),
        operation: OPERATION.to_string(),
        reason: reason.to_string(),
        user_message: "This analysis is unavailable for the current target. Choose another analysis or target.".to_string(),
    }
}

/// REA's error when no active provider exists.
pub fn provider_not_configured() -> WebError {
    not_configured(crate::electron_scenario::PROVIDER_NOT_CONFIGURED)
}

fn startup_error(failure: StartupFailure, stderr: &str, timeout: Duration) -> WebError {
    let tail: String = stderr.chars().rev().take(STDERR_IN_ERROR).collect::<Vec<_>>().into_iter().rev().collect();
    let diagnostics = if tail.is_empty() {
        String::new()
    } else {
        format!(" Electron stderr (tail): {tail}")
    };
    match failure {
        StartupFailure::Spawn(error) => browser_error(
            OPERATION,
            BrowserFailureReason::EndpointUnreachable,
            Some(format!("Electron could not be started: {error}.")),
        ),
        StartupFailure::Exited(message) => browser_error(
            OPERATION,
            BrowserFailureReason::EndpointUnreachable,
            Some(format!("{message}.{diagnostics}")),
        ),
        StartupFailure::NoDisplay => browser_error(
            OPERATION,
            BrowserFailureReason::EndpointUnreachable,
            Some("Unable to open X display. Most likely there is no X server available; start one (for example Xvfb) and pass its DISPLAY.".to_string()),
        ),
        StartupFailure::Timeout => browser_error(
            OPERATION,
            BrowserFailureReason::Timeout,
            Some(format!(
                "Electron did not publish its debugging endpoints within {} seconds.{diagnostics}",
                timeout.as_secs_f64()
            )),
        ),
    }
}

/// Run one scenario against a provider-owned Electron application.
pub async fn capture(
    canonical: &Map<String, Value>,
    config: &ElectronActiveConfig,
    environment: &HashMap<String, String>,
) -> Result<Evidence, ElectronCaptureError> {
    let text = |key: &str| canonical.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
    let (executable, application, root) = (text("executable_path"), text("application_path"), text("application_root"));
    if !config.executables.iter().any(|allowed| allowed.as_os_str() == executable.as_str()) {
        return Err(not_configured(&format!(
            "executable_path is not an Electron executable configured for active observation ({EXECUTABLES_ENV})"
        ))
        .into());
    }
    let args: Vec<String> = canonical
        .get("args")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(|item| item.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let run_id = new_run_id();
    let deadline = Instant::now() + config.startup_timeout;
    let executable_path = PathBuf::from(&executable);
    let spec = SpawnSpec {
        executable: &executable_path,
        application: &application,
        root: &root,
        args: &args,
        environment,
        runtime_root: &config.runtime_root,
    };
    // `app` owns the process group and the private directory from here on: any
    // return path, error or dropped future, ends up in `OwnedElectron::drop`.
    let mut app = OwnedElectron::spawn(&spec, &run_id).map_err(|failure| startup_error(failure, "", config.startup_timeout))?;
    let mut driver: Option<Driver> = None;
    let outcome = drive(&mut app, canonical, deadline, config.startup_timeout, &mut driver).await;
    // Helpers lose their parent once the application quits: remember who they are first.
    app.sample_lineage();
    if let Some(driver) = driver.as_mut() {
        driver.quit().await;
        driver.close().await;
    }
    let cleanup = app.terminate(GRACEFUL_EXIT).await;
    conclude(canonical, &run_id, app.leader_pid(), outcome, cleanup)
}

fn conclude(
    canonical: &Map<String, Value>,
    run_id: &str,
    pgid: i32,
    outcome: Result<Value, WebError>,
    cleanup: CleanupOutcome,
) -> Result<Evidence, ElectronCaptureError> {
    if !cleanup.cleaned {
        let reason = cleanup.reason.clone().unwrap_or_else(|| "cleanup was not verified".to_string());
        let (capture_failure, partial_observation) = match outcome {
            Ok(mut capture) => {
                capture["application"]["cleanup"] = json!("unverified");
                (None, Some(json!({ "kind": "electron-active-observation", "capture": capture })))
            }
            Err(error) => (Some(failure_message(&error)), None),
        };
        return Err(ElectronCaptureError::CleanupIncomplete(Box::new(CleanupIncomplete {
            cleanup_reason: reason,
            resources: vec![
                "owned_process_group".to_string(),
                format!("run:{run_id}"),
                format!("process-group:{pgid}"),
            ],
            capture_failure,
            partial_observation,
        })));
    }
    let mut capture = outcome?;
    if let Some(limitations) = capture["limitations"].as_array_mut() {
        for (pid, diagnostic) in &cleanup.unverified {
            limitations.push(json!(format!(
                "Ownership of unrelated process {pid} could not be verified; it was left untouched: {diagnostic}"
            )));
        }
    }
    Ok(create_electron_active_evidence(canonical, capture)?)
}

fn failure_message(error: &WebError) -> String {
    match error {
        WebError::BrowserObservation { user_message, .. } => user_message.clone(),
        other => other.to_string(),
    }
}

/// Everything between "process started" and "result projected".
async fn drive(
    app: &mut OwnedElectron,
    canonical: &Map<String, Value>,
    deadline: Instant,
    timeout: Duration,
    slot: &mut Option<Driver>,
) -> Result<Value, WebError> {
    let endpoints = app
        .wait_endpoints(deadline)
        .await
        .map_err(|failure| startup_error(failure, &app.stderr_tail(), timeout))?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    let connected = tokio::time::timeout(remaining, Driver::connect(&endpoints)).await;
    let driver = match connected {
        Ok(result) => slot.insert(result?),
        Err(_) => return Err(startup_error(StartupFailure::Timeout, &app.stderr_tail(), timeout)),
    };
    let actions = run_actions(driver, canonical).await;
    let state = driver.read_state().await.map_err(|message| {
        browser_error(
            OPERATION,
            BrowserFailureReason::ProtocolError,
            Some(format!("Electron state could not be read after the scenario: {message}")),
        )
    })?;
    Ok(project(canonical, actions, &state))
}

fn project(canonical: &Map<String, Value>, actions: Vec<Value>, state: &ElectronCaptureState) -> Value {
    let text = |key: &str| canonical.get(key).and_then(Value::as_str).unwrap_or_default();
    project_electron_active_capture(text("executable_path"), text("application_path"), actions, state)
}

/// REA `runElectronActions`: sequential, stops at the first failure.
async fn run_actions(driver: &mut Driver, canonical: &Map<String, Value>) -> Vec<Value> {
    let mut results = Vec::new();
    let actions = canonical.get("actions").and_then(Value::as_array).cloned().unwrap_or_default();
    for action in actions {
        let started = Instant::now();
        let kind = action["kind"].as_str().unwrap_or_default().to_string();
        let window_index: Option<i64> = match kind.as_str() {
            "click" | "renderer-reload" | "renderer-crash" => action["window_index"].as_i64(),
            "wait" => action["window_index"].as_i64(),
            _ => None,
        };
        let mut selected: Option<String> = None;
        let outcome = run_action(driver, &action, &kind, window_index, &mut selected).await;
        let elapsed = started.elapsed().as_millis() as u64;
        let failed = outcome.is_err();
        results.push(json!({
            "step_id": action["step_id"],
            "kind": kind,
            "window_index": window_index,
            "target": selected.as_ref().and(window_index).map(|index| format!("window:{index}")),
            "elapsed_ms": elapsed,
            "status": if failed { "failed" } else { "completed" },
            "error": outcome.err().map(|message| if message.is_empty() { "Electron action failed".to_string() } else { message }),
        }));
        if failed {
            break;
        }
    }
    results
}

async fn run_action(
    driver: &mut Driver,
    action: &Value,
    kind: &str,
    window_index: Option<i64>,
    selected: &mut Option<String>,
) -> Result<(), String> {
    if let Some(index) = window_index {
        *selected = Some(driver.wait_for_window(index.max(0) as usize).await?);
    }
    match kind {
        "click" => {
            let target = selected.clone().ok_or_else(|| driver::observation_message("window_not_found"))?;
            driver.click(&target, action["selector"].as_str().unwrap_or_default()).await
        }
        "wait" => {
            if selected.is_none() {
                driver.wait_for_first_window().await?;
            }
            tokio::time::sleep(Duration::from_millis(action["duration_ms"].as_u64().unwrap_or(0))).await;
            Ok(())
        }
        "renderer-reload" => {
            let target = selected.clone().ok_or_else(|| driver::observation_message("window_not_found"))?;
            driver.reload(&target).await
        }
        "renderer-crash" => {
            if driver.crash_renderer(window_index.unwrap_or(0)).await? {
                Ok(())
            } else {
                Err(driver::observation_message("window_not_found"))
            }
        }
        _ => {
            driver
                .deep_link(
                    action["delivery"].as_str().unwrap_or_default(),
                    action["url"].as_str().unwrap_or_default(),
                )
                .await
        }
    }
}
