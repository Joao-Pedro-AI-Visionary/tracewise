//! Serial read-only IDA session whose lifecycle authority excludes an attached GUI
//! (port of `IdaSessionClient.ts`).
//!
//! Attached mode never opens, saves or closes anything: it only checks that the user's open
//! database is the selected target. Headless mode opens a verified private copy as a worker
//! database, scopes every request to it, and at the end releases only that worker with
//! `save: false` before deleting only its own private directory.
//!
//! Work runs in detached tasks, as REA's promise chain does: if the caller goes away, the
//! in-flight request is drained, calls stay serialized and a close waits for them.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::sync::{watch, Mutex};
use tracewise_domain::evidence::{AnalysisProfile, EvidenceLocation};

use crate::error::{AnalysisError, InputIssue};
use crate::provider::tokio_util_lite::CancelToken;
use crate::provider::{AnalysisClient, AnalysisExecution, ExecContext};
use crate::target::BinaryTarget;

use super::capabilities::{ida_limitations, is_ida_operation, provider_identity};
use super::config::{IdaMode, IdaRegistration};
use super::connection::{IdaConnection, IdaFault};
use super::input::parse_ida_input;
use super::protocol::{self as p, parse_value as parse};
use super::runner::{Protocol, Runner};
use super::workspace::{file_digest, same_host_path, IdaWorkspace};

const LEGACY_TOOLS: [&str; 10] = [
    "get_metadata",
    "list_functions",
    "list_strings",
    "get_function_by_name",
    "get_function_by_address",
    "decompile_function",
    "disassemble_function",
    "get_callers",
    "get_callees",
    "get_xrefs_to",
];
const MODERN_TOOLS: [&str; 11] = [
    "idb_open",
    "idb_list",
    "idb_close",
    "server_health",
    "list_funcs",
    "lookup_funcs",
    "find_regex",
    "decompile",
    "disasm",
    "callees",
    "xrefs_to",
];

fn fault_message(fault: &IdaFault) -> String {
    match fault {
        IdaFault::Protocol(m) | IdaFault::Malformed(m) | IdaFault::Other(m) => m.clone(),
        IdaFault::Analysis(error) => error.message(),
    }
}

/// Session progress that must survive a caller walking away mid-request.
#[derive(Default)]
struct State {
    /// Startup runs once; a failed startup is never retried implicitly.
    startup: Option<Result<(), IdaFault>>,
    workspace: Option<IdaWorkspace>,
    database: Option<String>,
    database_close_acknowledged: bool,
    open_attempted: bool,
    open_completed: bool,
    initial_identity: Option<Value>,
    metadata: Value,
    lifecycle: Vec<Value>,
}

type CloseOutcome = Result<(), AnalysisError>;
type CloseSlot = StdMutex<Option<watch::Sender<Option<CloseOutcome>>>>;

struct Inner {
    registration: IdaRegistration,
    target: BinaryTarget,
    connection: Arc<dyn IdaConnection>,
    profile: Option<AnalysisProfile>,
    closing: AtomicBool,
    closed: AtomicBool,
    /// The serial tail: held for the whole of one request.
    state: Mutex<State>,
    close_slot: CloseSlot,
}

pub struct IdaSessionClient {
    inner: Arc<Inner>,
}

impl IdaSessionClient {
    pub fn new(
        registration: IdaRegistration,
        target: BinaryTarget,
        connection: Arc<dyn IdaConnection>,
        profile: Option<AnalysisProfile>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                registration,
                target,
                connection,
                profile,
                closing: AtomicBool::new(false),
                closed: AtomicBool::new(false),
                state: Mutex::new(State {
                    metadata: Value::Null,
                    ..State::default()
                }),
                close_slot: StdMutex::new(None),
            }),
        }
    }
}

impl Drop for IdaSessionClient {
    fn drop(&mut self) {
        if self.inner.closed.load(Ordering::SeqCst) {
            return;
        }
        // Release the worker and the private directory through the upstream lifecycle when a
        // runtime is still around; otherwise `Inner::drop` removes the directory and the
        // connection's process-group guard stops the proxy.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let inner = self.inner.clone();
            handle.spawn(async move {
                let _ = inner.close_shared().await;
            });
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        if let Ok(mut state) = self.state.try_lock() {
            if let Some(workspace) = state.workspace.take() {
                let _ = workspace.remove();
            }
        }
    }
}

#[async_trait]
impl AnalysisClient for IdaSessionClient {
    async fn execute(
        &self,
        operation: &str,
        parameters: &Value,
        ctx: &ExecContext,
    ) -> Result<AnalysisExecution, AnalysisError> {
        let inner = self.inner.clone();
        let operation = operation.to_string();
        let parameters = parameters.clone();
        let cancel = ctx.cancel.clone();
        let task = tokio::spawn(async move { inner.run(operation, parameters, cancel).await });
        match task.await {
            Ok(result) => result,
            Err(error) => Err(AnalysisError::adapter_with(
                "ida",
                "execute",
                json!({ "reason": format!("The IDA request task failed: {error}") }),
            )),
        }
    }

    async fn close(&self, _retain_document: bool) -> Result<(), AnalysisError> {
        self.inner.close_shared().await
    }
}

impl Inner {
    fn mode(&self) -> IdaMode {
        self.registration.mode
    }

    async fn run(
        self: &Arc<Self>,
        operation: String,
        parameters: Value,
        cancel: CancelToken,
    ) -> Result<AnalysisExecution, AnalysisError> {
        let mut state = self.state.lock().await;
        if self.closed.load(Ordering::SeqCst) || self.closing.load(Ordering::SeqCst) {
            return Err(AnalysisError::Protocol {
                message: "IDA session is closing or closed; reopen the target.".to_string(),
            });
        }
        if cancel.is_cancelled() {
            return Err(AnalysisError::cancelled(&operation));
        }
        if operation != "health" && !is_ida_operation(&operation) {
            return Err(AnalysisError::capability_unavailable(
                "ida",
                &operation,
                "This integration admits read-only analysis operations only.",
            ));
        }
        if operation == "procedure_callers" && self.mode() == IdaMode::Headless {
            return Err(AnalysisError::capability_unavailable(
                "ida",
                &operation,
                "The modern upstream profile does not prove direct callers.",
            ));
        }
        let parameters = if operation == "health" {
            parameters
        } else {
            parse_ida_input(&operation, &parameters)?
        };
        if let Some(document) = parameters.get("document") {
            let admitted =
                matches!(document, Value::String(text) if same_host_path(text, &self.target.path));
            if !admitted {
                return Err(AnalysisError::Input {
                    operation: operation.clone(),
                    issues: vec![InputIssue {
                        path: vec![json!("document")],
                        reason: "invalid_value",
                        message: Some(
                            "IDA document must be the REA-bound target; omit document or use its admitted path."
                                .to_string(),
                        ),
                        expected: Some(json!(self.target.path)),
                        minimum: None,
                        maximum: None,
                    }],
                });
            }
        }
        match self
            .observe_and_run(&mut state, &operation, &parameters, &cancel)
            .await
        {
            Ok(execution) => Ok(execution),
            Err(fault) => Err(self.failure(&operation, fault, &cancel)),
        }
    }

    async fn observe_and_run(
        &self,
        state: &mut State,
        operation: &str,
        parameters: &Value,
        cancel: &CancelToken,
    ) -> Result<AnalysisExecution, IdaFault> {
        let cancelled = || IdaFault::analysis(AnalysisError::cancelled(operation));
        self.start(state).await?;
        let before = self.observe(state).await?;
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        if operation == "health" {
            return Ok(self.health(state, before));
        }
        let protocol = match self.mode() {
            IdaMode::Attached => Protocol::Legacy,
            IdaMode::Headless => Protocol::Modern,
        };
        let database = state.database.clone();
        let mut runner = Runner::new(&*self.connection, protocol, database, cancel);
        let result = runner.run(operation, parameters).await?;
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        let after = self.observe(state).await?;
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        let mut limitations = ida_limitations();
        limitations.extend(runner.limitations.iter().cloned());
        let mut locations = vec![EvidenceLocation::ArtifactPath {
            path: self.target.path.clone(),
        }];
        locations.append(&mut runner.locations);
        Ok(AnalysisExecution {
            result,
            raw_result: Some(json!({
                "upstream": self.connection.server_info(),
                "metadata_before": before,
                "metadata_after": after,
                "observations": runner.raw,
            })),
            provider: provider_identity(),
            analysis_profile: self.profile.clone(),
            limitations,
            locations,
        })
    }

    fn health(&self, state: &State, metadata: Value) -> AnalysisExecution {
        AnalysisExecution {
            result: json!({
                "ready": true,
                "mode": self.mode().as_str(),
                "database": state.database,
                "upstream": self.connection.server_info(),
                "metadata": metadata,
                "lifecycle": state.lifecycle,
            }),
            raw_result: None,
            provider: provider_identity(),
            analysis_profile: self.profile.clone(),
            limitations: ida_limitations(),
            locations: Vec::new(),
        }
    }

    fn failure(&self, operation: &str, fault: IdaFault, cancel: &CancelToken) -> AnalysisError {
        if cancel.is_cancelled() {
            return AnalysisError::cancelled(operation);
        }
        match fault {
            IdaFault::Analysis(error) => *error,
            IdaFault::Protocol(message) => AnalysisError::Protocol { message },
            IdaFault::Malformed(issues) => AnalysisError::output(
                operation,
                format!("IDA MCP returned malformed or unsupported producer data: {issues}"),
            ),
            IdaFault::Other(reason) => AnalysisError::adapter_with(
                "ida",
                operation,
                json!({
                    "reason": reason,
                    "recovery": "Check the configured upstream MCP registration and selected target; see docs/ida-provider.md.",
                }),
            ),
        }
    }

    async fn start(&self, state: &mut State) -> Result<(), IdaFault> {
        if let Some(outcome) = &state.startup {
            return outcome.clone();
        }
        let outcome = self.initialize(state).await;
        state.startup = Some(outcome.clone());
        outcome
    }

    async fn initialize(&self, state: &mut State) -> Result<(), IdaFault> {
        let tools = self.connection.connect().await?;
        let expected: &[&str] = match self.mode() {
            IdaMode::Attached => &LEGACY_TOOLS,
            IdaMode::Headless => &MODERN_TOOLS,
        };
        let missing: Vec<&str> = expected
            .iter()
            .copied()
            .filter(|name| !tools.iter().any(|tool| tool == name))
            .collect();
        if !missing.is_empty() {
            return Err(IdaFault::protocol(format!(
                "IDA MCP {} compatibility profile is missing tools: {}. Attached mode requires the legacy 1.4 profile; headless mode requires the database supervisor profile. See docs/ida-provider.md.",
                self.mode().as_str(),
                missing.join(", ")
            )));
        }
        if self.mode() == IdaMode::Headless {
            let workspace =
                IdaWorkspace::allocate(&self.target, self.registration.workspace_root.as_deref())
                    .map_err(|e| {
                    IdaFault::Other(format!("Cannot allocate the private IDA workspace: {e}"))
                })?;
            let (input_path, session_id) =
                (workspace.input_path.clone(), workspace.session_id.clone());
            // The session owns the workspace's cleanup before any input is prepared.
            state.workspace = Some(workspace);
            state
                .workspace
                .as_ref()
                .expect("workspace retained")
                .copy_input()?;
            state.open_attempted = true;
            let raw = self
                .connection
                .call(
                    "idb_open",
                    &json!({
                        "input_path": input_path,
                        "mode": "force_headless",
                        "run_auto_analysis": true,
                        "build_caches": true,
                        "init_hexrays": true,
                        "preferred_session_id": session_id,
                    }),
                )
                .await?;
            state.open_completed = true;
            state.lifecycle.push(raw.clone());
            let opened = parse(&raw, p::open_database)?;
            if !same_host_path(&opened.input_path, &input_path) {
                return Err(IdaFault::protocol(
                    "IDA opened a different input than the private admitted target copy.",
                ));
            }
            if opened.session_id != session_id {
                return Err(IdaFault::protocol(
                    "IDA returned an adopted or unexpected session instead of the requested private worker.",
                ));
            }
            let listing = self.connection.call("idb_list", &json!({})).await?;
            let inventory = parse(&listing, p::database_list)?;
            state.lifecycle.push(listing);
            let entry = inventory
                .iter()
                .find(|entry| entry.session_id == opened.session_id);
            let owned_worker = matches!(
                entry,
                Some(entry) if entry.owned && entry.worker && entry.is_active
                    && same_host_path(&entry.input_path, &input_path)
            );
            if !owned_worker {
                return Err(IdaFault::protocol(
                    "IDA did not return an active owned headless worker for the private input copy.",
                ));
            }
            state.database = Some(opened.session_id);
        }
        Ok(())
    }

    /// Verify, before and after each request, that the upstream still serves the selected
    /// target; returns the raw metadata for the evidence.
    async fn observe(&self, state: &mut State) -> Result<Value, IdaFault> {
        let identity: Value;
        if self.mode() == IdaMode::Attached {
            let raw = self.connection.call("get_metadata", &json!({})).await?;
            let metadata = parse(&raw, p::legacy_metadata)?;
            if !metadata.sha256.eq_ignore_ascii_case(&self.target.sha256) {
                return Err(IdaFault::protocol(format!(
                    "The attached IDA input SHA-256 does not match the selected target {}; open that target in IDA or use headless mode.",
                    self.target.path
                )));
            }
            identity = json!([
                metadata.path,
                metadata.sha256.to_ascii_lowercase(),
                metadata.base
            ]);
            state.metadata = raw;
        } else {
            let (Some(database), Some(workspace)) =
                (state.database.clone(), state.workspace.as_ref())
            else {
                return Err(IdaFault::protocol(
                    "IDA headless session has no database binding.",
                ));
            };
            let raw = self
                .connection
                .call("server_health", &json!({ "database": database }))
                .await?;
            let health = parse(&raw, p::modern_health)?;
            let input = workspace.input_path.clone();
            let digest = tokio::task::spawn_blocking({
                let input = input.clone();
                move || file_digest(std::path::Path::new(&input))
            })
            .await
            .ok()
            .and_then(Result::ok);
            if !same_host_path(&health.input_path, &input)
                || digest.as_deref() != Some(self.target.sha256.as_str())
            {
                return Err(IdaFault::protocol(
                    "IDA headless input identity changed after target admission.",
                ));
            }
            if health.auto_analysis_ready != Some(true) {
                return Err(IdaFault::protocol(
                    "IDA auto-analysis is incomplete or readiness is unknown; retry after analysis completes.",
                ));
            }
            identity = json!([
                database,
                health.input_path,
                health.idb_path,
                health.imagebase
            ]);
            state.metadata = raw;
        }
        if let Some(initial) = &state.initial_identity {
            if *initial != identity {
                return Err(IdaFault::protocol(
                    "The attached IDA target or image base changed during the REA session; reopen the target.",
                ));
            }
        }
        state.initial_identity = Some(identity);
        Ok(state.metadata.clone())
    }

    /// Concurrent callers share one in-flight close, which also survives a caller that
    /// stops waiting.
    async fn close_shared(self: &Arc<Self>) -> CloseOutcome {
        let mut receiver = {
            let mut slot = self.close_slot.lock().unwrap();
            match slot.as_ref() {
                Some(sender) => sender.subscribe(),
                None => {
                    let (sender, receiver) = watch::channel(None);
                    *slot = Some(sender.clone());
                    let inner = self.clone();
                    tokio::spawn(async move {
                        let outcome = inner.close_once().await;
                        *inner.close_slot.lock().unwrap() = None;
                        let _ = sender.send(Some(outcome));
                    });
                    receiver
                }
            }
        };
        loop {
            if let Some(outcome) = receiver.borrow().clone() {
                return outcome;
            }
            if receiver.changed().await.is_err() {
                return Err(AnalysisError::adapter_with(
                    "ida",
                    "close",
                    json!({ "reason": "The IDA close task ended without a result." }),
                ));
            }
        }
    }

    async fn close_once(&self) -> Result<(), AnalysisError> {
        self.closing.store(true, Ordering::SeqCst);
        let mut state = self.state.lock().await;
        if self.closed.load(Ordering::SeqCst) {
            return Ok(());
        }
        match self.release(&mut state).await {
            Ok(()) => {
                self.closed.store(true, Ordering::SeqCst);
                Ok(())
            }
            Err(fault) => {
                let path = state
                    .workspace
                    .as_ref()
                    .map(|w| w.directory().to_string_lossy().to_string())
                    .unwrap_or_else(|| "IDA MCP connection".to_string());
                Err(AnalysisError::ProviderAdapter {
                    provider_id: "ida".to_string(),
                    operation: "close".to_string(),
                    diagnostics: Some(json!({
                        "reason": "IDA cleanup could not be verified; the remaining connection or private workspace is retained for retry.",
                        "failure_reason": fault_message(&fault),
                        "workspace": path,
                    })),
                    cleanup_incomplete: true,
                    cleanup_resources: vec![path],
                })
            }
        }
    }

    async fn release(&self, state: &mut State) -> Result<(), IdaFault> {
        let workspace_ids = state
            .workspace
            .as_ref()
            .map(|workspace| (workspace.input_path.clone(), workspace.session_id.clone()));
        if let (Some((input_path, session_id)), true) = (workspace_ids, state.open_attempted) {
            if state.database.is_none() {
                let listing = self.connection.call("idb_list", &json!({})).await?;
                let inventory = parse(&listing, p::database_list)?;
                state.database = inventory
                    .iter()
                    .find(|entry| {
                        entry.owned
                            && entry.worker
                            && entry.session_id == session_id
                            && same_host_path(&entry.input_path, &input_path)
                    })
                    .map(|entry| entry.session_id.clone());
                if state.database.is_none()
                    && inventory
                        .iter()
                        .any(|entry| same_host_path(&entry.input_path, &input_path))
                {
                    return Err(IdaFault::protocol(
                        "An unowned worker still uses the private workspace; it was retained.",
                    ));
                }
            }
            if let Some(database) = state.database.clone() {
                if !state.database_close_acknowledged {
                    let raw = self
                        .connection
                        .call("idb_close", &json!({ "database": database, "save": false }))
                        .await?;
                    let closed = parse(&raw, p::close_database)?;
                    if closed.session_id != database
                        || closed.saved == Some(true)
                        || !closed.owned
                        || !closed.worker
                    {
                        return Err(IdaFault::protocol(
                            "IDA database close did not confirm the requested owned, unsaved session release.",
                        ));
                    }
                    state.database_close_acknowledged = true;
                }
                let listing = self.connection.call("idb_list", &json!({})).await?;
                let inventory = parse(&listing, p::database_list)?;
                if inventory.iter().any(|entry| {
                    entry.session_id == database || same_host_path(&entry.input_path, &input_path)
                }) {
                    return Err(IdaFault::protocol(
                        "IDA worker remains registered after close.",
                    ));
                }
                state.database = None;
            }
            if !state.open_completed {
                return Err(IdaFault::protocol(
                    "IDA database open did not return a completed response. Worker inventory cannot prove that the request has stopped; the private workspace was retained.",
                ));
            }
            state.open_attempted = false;
        }
        self.connection.close().await?;
        if let Some(workspace) = &state.workspace {
            workspace.remove().map_err(|e| {
                IdaFault::Other(format!("Cannot remove the private IDA workspace: {e}"))
            })?;
        }
        Ok(())
    }
}
