//! Dispatch for the engines tools (57): Ghidra (phase 5) and the Hopper/IDA surface
//! (phase 5b) behind one provider abstraction in `tracewise-engines`.
//!
//! Every tool needs a target opened with `open_binary`. The session's engine state is
//! created lazily from the REA environment variables and owns the live provider client;
//! `close_binary` and target switches release it (see [`note_open`] and [`note_close`]).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, Weak};
use std::time::Duration;

use rmcp::model::{CallToolResult, Content};
use rmcp::ErrorData as McpError;
use serde_json::{json, Value};
use tracewise_domain::evidence::{
    create_analysis_profile, create_evidence, AnalysisProfile, CommittedProviderIdentity, EvidenceAuthority,
    EvidenceConfidence, EvidenceLocation, EvidenceObservation, EvidenceProvider,
};
use tracewise_domain::ledger::EvidenceLedger;
use tracewise_domain::unknown::RecordUnknownInput;
use tracewise_engines::config::EngineConfig;
use tracewise_engines::contract_input::parse_contract_input;
use tracewise_engines::error::AnalysisError;
use async_trait::async_trait;
use tracewise_domain::evidence::Evidence;
use tracewise_engines::provider::{AnalysisExecution, ExecContext};
use tracewise_engines::session::{ActiveRoute, EngineSession, OperationPort, Recorder};
use tracewise_engines::target::BinaryTarget;
use tracewise_engines::workflows;

use crate::session::BinarySession;

pub mod derived;

/// Every tool this track owns, for the dispatch gate.
const TOOLS: [&str; 57] = [
    "inspect_native_load_image",
    "inspect_native_data_type",
    "inspect_native_instruction",
    "resolve_native_call_targets",
    "address_name",
    "comment",
    "inline_comment",
    "list_documents",
    "list_names",
    "list_procedures",
    "list_segments",
    "list_strings",
    "next_address",
    "prev_address",
    "procedure_address",
    "procedure_assembly",
    "procedure_callees",
    "procedure_callers",
    "procedure_info",
    "read_function_instructions",
    "read_bytes",
    "address_to_file_offset",
    "procedure_references",
    "procedure_pseudo_code",
    "resolve_containing_procedure",
    "search_procedures",
    "search_strings",
    "xrefs",
    "trace_native_values",
    "inspect_native_dispatch_metadata",
    "get_objc_classes",
    "get_objc_protocols",
    "batch_decompile",
    "get_call_graph",
    "analyze_swift_types",
    "find_xrefs_to_name",
    "binary_overview",
    "analyze_function",
    "inspect_native_api",
    "trace_feature",
    "trace_call_path",
    "compare_functions",
    "build_call_path",
    "inspect_address_context",
    "annotate_native_function",
    "current_address",
    "current_procedure",
    "current_document",
    "goto_address",
    "list_bookmarks",
    "set_address_name",
    "set_addresses_names",
    "set_bookmark",
    "set_comment",
    "set_inline_comment",
    "unset_bookmark",
    "get_navigation_context",
];

/// Engine state of one binary session.
pub struct EngineState {
    engine: StdMutex<Option<Arc<EngineSession>>>,
    config: StdMutex<Option<EngineConfig>>,
    requested_provider: StdMutex<Option<String>>,
    /// Bumped whenever the session's target changes (open or close). A call that captured an
    /// older value must not bind a route for the target it read.
    epoch: AtomicU64,
}

impl EngineState {
    fn new() -> Self {
        Self {
            engine: StdMutex::new(None),
            config: StdMutex::new(None),
            requested_provider: StdMutex::new(None),
            epoch: AtomicU64::new(0),
        }
    }

    fn engine(&self) -> Arc<EngineSession> {
        let mut guard = self.engine.lock().unwrap();
        if let Some(engine) = guard.as_ref() {
            return engine.clone();
        }
        let config = self
            .config
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(EngineConfig::from_process_environment);
        let engine = Arc::new(EngineSession::new(config.build_registry()));
        *guard = Some(engine.clone());
        engine
    }

    /// Detach the live provider route and stop it in the background.
    fn release_in_background(&self) {
        let engine = self.engine.lock().unwrap().clone();
        let Some(route) = engine.and_then(|e| e.detach()) else {
            return;
        };
        let release = async move {
            let _ = route.close().await;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                // Tracked so that shutdown can wait for releases still in flight.
                let mut pending = pending_releases().lock().unwrap();
                pending.retain(|task| !task.is_finished());
                pending.push(handle.spawn(release));
            }
            Err(_) => {
                if let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    runtime.block_on(release);
                }
            }
        }
    }
}

fn pending_releases() -> &'static StdMutex<Vec<tokio::task::JoinHandle<()>>> {
    static PENDING: OnceLock<StdMutex<Vec<tokio::task::JoinHandle<()>>>> = OnceLock::new();
    PENDING.get_or_init(|| StdMutex::new(Vec::new()))
}

type StateEntry = (Weak<StdMutex<EvidenceLedger>>, Arc<EngineState>);

fn states() -> &'static StdMutex<Vec<StateEntry>> {
    static STATES: OnceLock<StdMutex<Vec<StateEntry>>> = OnceLock::new();
    STATES.get_or_init(|| StdMutex::new(Vec::new()))
}

/// The engine state belonging to this session (identified by its ledger allocation).
pub fn state_for(session: &BinarySession) -> Arc<EngineState> {
    let mut states = states().lock().unwrap();
    states.retain(|(weak, _)| weak.strong_count() > 0);
    for (weak, state) in states.iter() {
        if std::ptr::eq(weak.as_ptr(), Arc::as_ptr(&session.ledger)) {
            return state.clone();
        }
    }
    let state = Arc::new(EngineState::new());
    states.push((Arc::downgrade(&session.ledger), state.clone()));
    state
}

/// Replace the engine configuration of a session (tests and embedders). Any live
/// provider client is released first.
pub async fn configure(session: &BinarySession, config: EngineConfig) {
    let state = state_for(session);
    let previous = state.engine.lock().unwrap().take();
    if let Some(previous) = previous {
        let _ = previous.release().await;
    }
    *state.config.lock().unwrap() = Some(config);
}

/// `open_binary` hook: remember the requested provider selector for this session.
pub fn note_open(session: &BinarySession, provider_id: Option<&str>) {
    let state = state_for(session);
    state.epoch.fetch_add(1, Ordering::SeqCst);
    state.release_in_background();
    *state.requested_provider.lock().unwrap() = provider_id.map(str::to_string);
}

/// `close_binary` hook: release the live provider client without blocking the caller.
pub fn note_close(session: &BinarySession) {
    let state = state_for(session);
    state.epoch.fetch_add(1, Ordering::SeqCst);
    state.release_in_background();
    *state.requested_provider.lock().unwrap() = None;
}

/// Release every live engine of every session and wait for releases already in flight, so that
/// no engine process or runtime directory outlives the server (transport closed, SIGTERM, SIGINT).
pub async fn shutdown() {
    const LIMIT: Duration = Duration::from_secs(15);
    let tasks: Vec<_> = std::mem::take(&mut *pending_releases().lock().unwrap());
    for task in tasks {
        let _ = tokio::time::timeout(LIMIT, task).await;
    }
    let entries: Vec<StateEntry> = std::mem::take(&mut *states().lock().unwrap());
    for (_, state) in entries {
        let engine = state.engine.lock().unwrap().take();
        if let Some(engine) = engine {
            let _ = tokio::time::timeout(LIMIT, engine.release()).await;
        }
    }
}

pub async fn dispatch(
    session: &BinarySession,
    name: &str,
    args: &Value,
) -> Option<Result<CallToolResult, McpError>> {
    if !TOOLS.contains(&name) {
        return None;
    }
    match name {
        "compare_functions" => return Some(derived::handle_compare_functions(session, args)),
        "build_call_path" => return Some(derived::handle_build_call_path(session, args)),
        _ => {}
    }
    Some(handle(session, name, args).await)
}

fn error_result(error: &AnalysisError) -> CallToolResult {
    CallToolResult::error(vec![Content::text(error.error_body().to_string())])
}

fn text_error(message: String) -> CallToolResult {
    CallToolResult::error(vec![Content::text(message)])
}

async fn handle(session: &BinarySession, name: &str, args: &Value) -> Result<CallToolResult, McpError> {
    let parameters = match parse_contract_input(name, args) {
        Ok(parameters) => parameters,
        Err(message) => return Ok(text_error(message)),
    };
    let state = state_for(session);
    let epoch = state.epoch.load(Ordering::SeqCst);
    let Some(subject) = session.active_target.lock().unwrap().clone() else {
        return Ok(error_result(&AnalysisError::NoBinaryOpen));
    };
    let target = BinaryTarget::from_session(
        &subject.local_path,
        &subject.format,
        subject.architecture.as_deref(),
        &subject.digest.sha256,
    );
    let engine = state.engine();
    let requested = state.requested_provider.lock().unwrap().clone();
    let ctx = ExecContext::default();
    let route = match engine
        .route_for(&target, requested.as_deref(), &|| state.epoch.load(Ordering::SeqCst) == epoch)
        .await {
        Ok(route) => route,
        Err(error) => return Ok(error_result(&error)),
    };
    let recorder = |operation: &str, parameters: &Value, execution: &AnalysisExecution| {
        if let Ok(evidence) = execution_evidence(session, operation, parameters, execution) {
            let _ = session.ledger.lock().unwrap().record(evidence);
        }
    };
    if workflows::is_workflow(name) {
        let port = LedgerPort {
            route: route.as_ref(),
            recorder: &recorder,
        };
        let env = workflows::Env {
            port: &port,
            ctx: &ctx,
            subject: Some(subject),
        };
        let outcome = match workflows::run(name, &parameters, &env).await {
            Ok(outcome) => outcome,
            Err(error) => return Ok(error_result(&error)),
        };
        if matches!(name, "inspect_address_context" | "get_navigation_context") {
            return Ok(CallToolResult::structured(json!({ "result": outcome.result })));
        }
        return workflow_evidence_result(session, name, &parameters, route.profile(), outcome);
    }
    let execution = match route.execute_with(name, &parameters, &ctx, Some(&recorder)).await {
        Ok(execution) => execution,
        Err(error) => return Ok(error_result(&error)),
    };
    evidence_result(session, name, &parameters, execution)
}

/// Provider identity of deterministic composed workflows.
fn workflow_provider() -> CommittedProviderIdentity {
    CommittedProviderIdentity {
        id: "rea-workflow".to_string(),
        name: "REA composed investigation workflow".to_string(),
        version: "1".to_string(),
    }
}

/// `createWorkflowEvidence`: derived Evidence committed to the upstream analysis profile.
fn workflow_evidence_result(
    session: &BinarySession,
    name: &str,
    parameters: &Value,
    upstream: Option<&AnalysisProfile>,
    outcome: workflows::Outcome,
) -> Result<CallToolResult, McpError> {
    let internal = |e: String| McpError::internal_error(e, None);
    let identity = workflow_provider();
    let analysis_profile = match upstream {
        None => None,
        Some(upstream) => {
            let mut profile_parameters = serde_json::Map::new();
            profile_parameters.insert(
                "upstream_analysis_profile".to_string(),
                serde_json::to_value(upstream).map_err(|e| internal(e.to_string()))?,
            );
            if name == "binary_overview" || name == "batch_decompile" {
                profile_parameters.insert("workflow_revision".to_string(), json!(2));
            }
            let profile = create_analysis_profile(identity.clone(), Value::Object(profile_parameters))
                .map_err(|e| internal(e.to_string()))?;
            Some(serde_json::to_value(profile).map_err(|e| internal(e.to_string()))?)
        }
    };
    let subject = session.active_target.lock().unwrap().clone();
    let result = outcome.result;
    let evidence = create_evidence(
        subject,
        EvidenceProvider {
            id: identity.id,
            name: identity.name,
            version: Some(identity.version),
        },
        EvidenceObservation {
            predicate_type: None,
            operation: name.to_string(),
            parameters: parameters.clone(),
            normalized_result: result.clone(),
            raw_result: None,
            analysis_profile,
            confidence: Some(EvidenceConfidence::Derived),
            authority: Some(EvidenceAuthority::ShippedArtifact),
            environment: None,
            limitations: Some(vec!["Derived by an REA composed workflow.".to_string()]),
            locations: Some(outcome.locations),
            evidence_links: None,
        },
    )
    .map_err(|e| internal(e.to_string()))?;
    session
        .ledger
        .lock()
        .unwrap()
        .record(evidence.clone())
        .map_err(|e| internal(e.to_string()))?;
    record_workflow_unknowns(session, name, &result, &evidence.evidence_id)?;
    let value = serde_json::to_value(&evidence).map_err(|e| internal(e.to_string()))?;
    Ok(CallToolResult::structured(value))
}

/// `recordWorkflowUnknowns`: retain residual workflow questions as residual unknowns.
fn record_workflow_unknowns(
    session: &BinarySession,
    name: &str,
    result: &Value,
    evidence_id: &str,
) -> Result<(), McpError> {
    if !matches!(name, "trace_feature" | "trace_call_path" | "inspect_native_api") {
        return Ok(());
    }
    let Some(questions) = result.get("residual_unknowns").and_then(Value::as_array) else {
        return Ok(());
    };
    for question in questions {
        let Some(question) = question.as_str() else { continue };
        let domain = if name == "inspect_native_api" { "native-api" } else { "control-flow" };
        let rationale = if name == "inspect_native_api" {
            "Confirm the unsupported boundary with a capable provider or ABI probe."
        } else {
            "Continue with a focused query or another available provider."
        };
        let arguments = json!({
            "question": question,
            "severity": "medium",
            "domain": domain,
            "supporting_evidence_ids": [evidence_id],
            "contradicting_evidence_ids": [],
            "required_authority": "shipped-artifact",
            "required_confidence": "observed",
            "required_environment": Value::Null,
            "recommended_probes": [{ "operation": name, "rationale": rationale }],
            "relationships": [],
        });
        let input: RecordUnknownInput = serde_json::from_value(arguments.clone())
            .map_err(|e| McpError::internal_error(format!("workflow unknown: {e}"), None))?;
        let target = session.active_target.lock().unwrap().clone();
        let mutation = create_evidence(
            target,
            session.provider.clone(),
            EvidenceObservation {
                predicate_type: Some("rea.residual-unknown-mutation".to_string()),
                operation: "record_unknown".to_string(),
                parameters: arguments,
                normalized_result: json!({ "action": "record_unknown", "domain": domain }),
                raw_result: None,
                analysis_profile: None,
                confidence: Some(EvidenceConfidence::Observed),
                authority: Some(EvidenceAuthority::AnalystInference),
                environment: None,
                limitations: None,
                locations: None,
                evidence_links: None,
            },
        )
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let recorded = session.ledger.lock().unwrap().record_unknown(&input, mutation);
        if let Err(error) = recorded {
            if !matches!(
                error,
                tracewise_domain::error::DomainError::Unknown(tracewise_domain::error::UnknownError::AlreadyExists(_))
            ) {
                return Err(McpError::internal_error(error.to_string(), None));
            }
        }
    }
    Ok(())
}

/// Provider executions that REA retains as session Evidence (and replays from its snapshot cache).
struct LedgerPort<'a> {
    route: &'a ActiveRoute,
    recorder: &'a dyn Recorder,
}

#[async_trait]
impl OperationPort for LedgerPort<'_> {
    async fn execute(
        &self,
        operation: &str,
        parameters: &Value,
        ctx: &ExecContext,
    ) -> Result<AnalysisExecution, AnalysisError> {
        self.route.execute_with(operation, parameters, ctx, Some(self.recorder)).await
    }
}

/// The Evidence record of one provider execution.
fn execution_evidence(
    session: &BinarySession,
    operation: &str,
    parameters: &Value,
    execution: &AnalysisExecution,
) -> Result<Evidence, McpError> {
    let subject = session.active_target.lock().unwrap().clone();
    let analysis_profile = match &execution.analysis_profile {
        Some(profile) => Some(
            serde_json::to_value(profile).map_err(|e| McpError::internal_error(e.to_string(), None))?,
        ),
        None => None,
    };
    let locations: Vec<EvidenceLocation> = execution.locations.clone();
    create_evidence(
        subject,
        EvidenceProvider {
            id: execution.provider.id.clone(),
            name: execution.provider.name.clone(),
            version: execution.provider.version.clone(),
        },
        EvidenceObservation {
            predicate_type: None,
            operation: operation.to_string(),
            parameters: parameters.clone(),
            normalized_result: execution.result.clone(),
            raw_result: execution.raw_result.clone(),
            analysis_profile,
            confidence: Some(EvidenceConfidence::Observed),
            authority: Some(EvidenceAuthority::ShippedArtifact),
            environment: None,
            limitations: Some(execution.limitations.clone()),
            locations: Some(locations),
            evidence_links: None,
        },
    )
    .map_err(|e| McpError::internal_error(e.to_string(), None))
}

/// Record the execution as Evidence in the session ledger and deliver it.
pub fn evidence_result(
    session: &BinarySession,
    operation: &str,
    parameters: &Value,
    execution: AnalysisExecution,
) -> Result<CallToolResult, McpError> {
    let evidence = execution_evidence(session, operation, parameters, &execution)?;
    session
        .ledger
        .lock()
        .unwrap()
        .record(evidence.clone())
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let value = serde_json::to_value(&evidence).map_err(|e| McpError::internal_error(e.to_string(), None))?;
    Ok(CallToolResult::structured(value))
}
