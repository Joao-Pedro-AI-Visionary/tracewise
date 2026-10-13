//! Deep-provider selection and the engine side of a binary session (port of
//! `AnalysisProviderRegistry.ts`, `SessionProviderRouter.ts` and
//! `BinarySessionExecution.ts`, reduced to the providers this crate owns).

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::Mutex as StdMutex;
use tokio::sync::Mutex;
use tracewise_domain::evidence::AnalysisProfile;

use crate::error::{AnalysisError, ProviderRejection};
use crate::provider::{
    AnalysisClient, AnalysisExecution, AnalysisProvider, CachePolicy, Capability, ExecContext,
    ProviderAvailability, ProviderIdentity, TargetSupport,
};
use crate::target::BinaryTarget;

/// Application capability that runs one analysis operation against the active target.
#[async_trait]
pub trait OperationPort: Send + Sync {
    async fn execute(
        &self,
        operation: &str,
        parameters: &Value,
        ctx: &ExecContext,
    ) -> Result<AnalysisExecution, AnalysisError>;
}

/// Deterministic discovery truth for one configured deep provider.
#[derive(Clone)]
pub struct CandidateStatus {
    pub provider: ProviderIdentity,
    pub availability: ProviderAvailability,
    pub target_support: Option<TargetSupport>,
    pub selected: bool,
    pub capabilities: Vec<Capability>,
}

impl CandidateStatus {
    pub fn to_json(&self) -> Value {
        let support = match &self.target_support {
            Some(s) => json!({
                "status": if s.supported { "supported" } else { "unsupported" },
                "code": s.code,
                "reason": s.reason,
                "diagnostics": s.diagnostics,
            }),
            None => json!({
                "status": "unknown",
                "code": Value::Null,
                "reason": "No target is open.",
                "diagnostics": {},
            }),
        };
        json!({
            "provider": self.provider.to_json(),
            "availability": self.availability.to_json(),
            "target_support": support,
            "selected": self.selected,
            "capabilities": self.capabilities.iter().map(Capability::to_json).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone)]
pub struct Binding {
    pub provider: Arc<dyn AnalysisProvider>,
    pub identity: ProviderIdentity,
    pub selection_source: &'static str,
    pub profile: AnalysisProfile,
}

#[derive(Clone)]
pub struct Selection {
    pub requested_provider_id: String,
    pub binding: Option<Binding>,
    pub candidates: Vec<CandidateStatus>,
}

/// Configured deep providers, in canonical id order.
pub struct Registry {
    providers: Vec<Arc<dyn AnalysisProvider>>,
    default_selector: String,
}

impl Registry {
    pub fn new(mut providers: Vec<Arc<dyn AnalysisProvider>>, default_selector: &str) -> Self {
        providers.sort_by(|a, b| a.identity().id.cmp(&b.identity().id));
        Self {
            providers,
            default_selector: default_selector.to_string(),
        }
    }

    pub fn providers(&self) -> &[Arc<dyn AnalysisProvider>] {
        &self.providers
    }

    pub fn declared_operations(&self) -> Vec<String> {
        let mut ops: Vec<String> = self
            .providers
            .iter()
            .flat_map(|p| p.capabilities().into_iter().map(|c| c.operation))
            .collect();
        ops.sort();
        ops.dedup();
        ops
    }

    fn status(provider: &Arc<dyn AnalysisProvider>, target: Option<&BinaryTarget>) -> CandidateStatus {
        CandidateStatus {
            provider: provider.identity(),
            availability: provider.inspect_availability(),
            target_support: target.map(|t| provider.inspect_target_support(t)),
            selected: false,
            capabilities: provider.capabilities(),
        }
    }

    pub fn candidates(&self, target: Option<&BinaryTarget>) -> Vec<CandidateStatus> {
        self.providers.iter().map(|p| Self::status(p, target)).collect()
    }

    fn selection_error(
        &self,
        reason: &str,
        requested: &str,
        candidates: &[CandidateStatus],
        operation: &str,
    ) -> AnalysisError {
        let mut rejections = Vec::new();
        for candidate in candidates {
            if !candidate.availability.available {
                rejections.push(ProviderRejection {
                    provider_id: candidate.provider.id.clone(),
                    code: candidate.availability.code.clone().unwrap_or_default(),
                    reason: candidate.availability.reason.clone().unwrap_or_default(),
                    diagnostics: candidate.availability.diagnostics.clone(),
                });
            }
            if let Some(support) = &candidate.target_support {
                if !support.supported {
                    rejections.push(ProviderRejection {
                        provider_id: candidate.provider.id.clone(),
                        code: support.code.clone().unwrap_or_default(),
                        reason: support.reason.clone().unwrap_or_default(),
                        diagnostics: support.diagnostics.clone(),
                    });
                }
            }
        }
        AnalysisError::ProviderSelection {
            operation: operation.to_string(),
            reason: reason.to_string(),
            requested_provider_id: requested.to_string(),
            candidate_ids: candidates.iter().map(|c| c.provider.id.clone()).collect(),
            rejections,
        }
    }

    /// Select one whole deep-operation family for a parsed target.
    pub async fn select(
        &self,
        target: &BinaryTarget,
        requested: Option<&str>,
    ) -> Result<Selection, AnalysisError> {
        let selector = requested.unwrap_or(&self.default_selector).to_string();
        let mut baseline = self.candidates(Some(target));
        // A configured default that no provider can serve leaves the target unbound.
        if requested.is_none()
            && selector != "auto"
            && !baseline.is_empty()
            && baseline
                .iter()
                .all(|c| c.target_support.as_ref().map(|s| !s.supported).unwrap_or(false))
        {
            return Ok(Selection {
                requested_provider_id: selector,
                binding: None,
                candidates: baseline,
            });
        }
        if selector != "auto" {
            let Some(provider) = self.providers.iter().find(|p| p.identity().id == selector).cloned() else {
                return Err(self.selection_error("unknown_provider", &selector, &baseline, "open_binary"));
            };
            let index = baseline.iter().position(|c| c.provider.id == selector).unwrap();
            if !baseline[index].target_support.as_ref().map(|s| s.supported).unwrap_or(false) {
                return Err(self.selection_error("target_unsupported", &selector, &baseline, "open_binary"));
            }
            if !baseline[index].availability.available {
                return Err(self.selection_error("provider_unavailable", &selector, &baseline, "open_binary"));
            }
            let profile = provider.resolve_analysis_profile(target).await?;
            let Some(profile) = profile else {
                return Err(self.selection_error("provider_unavailable", &selector, &baseline, "open_binary"));
            };
            let source = if requested.is_none() { "environment" } else { "request" };
            return Ok(Self::bound(&selector, source, provider, profile, &mut baseline));
        }
        let mut usable: Vec<(Arc<dyn AnalysisProvider>, AnalysisProfile)> = Vec::new();
        for provider in &self.providers {
            let status = baseline
                .iter()
                .find(|c| c.provider.id == provider.identity().id)
                .unwrap();
            let supported = status.target_support.as_ref().map(|s| s.supported).unwrap_or(false);
            if status.availability.available && supported {
                if let Some(profile) = provider.resolve_analysis_profile(target).await? {
                    usable.push((provider.clone(), profile));
                }
            }
        }
        if usable.is_empty() {
            return Ok(Selection {
                requested_provider_id: "auto".to_string(),
                binding: None,
                candidates: baseline,
            });
        }
        if usable.len() > 1 {
            return Err(self.selection_error("ambiguous", "auto", &baseline, "open_binary"));
        }
        let (provider, profile) = usable.remove(0);
        Ok(Self::bound("auto", "auto-single-candidate", provider, profile, &mut baseline))
    }

    fn bound(
        requested: &str,
        source: &'static str,
        provider: Arc<dyn AnalysisProvider>,
        profile: AnalysisProfile,
        statuses: &mut [CandidateStatus],
    ) -> Selection {
        let identity = ProviderIdentity {
            id: profile.provider.id.clone(),
            name: profile.provider.name.clone(),
            version: Some(profile.provider.version.clone()),
        };
        for status in statuses.iter_mut() {
            if status.provider.id == identity.id {
                status.provider = identity.clone();
                status.selected = true;
            }
        }
        Selection {
            requested_provider_id: requested.to_string(),
            binding: Some(Binding {
                provider,
                identity,
                selection_source: source,
                profile,
            }),
            candidates: statuses.to_vec(),
        }
    }

    /// Explain why a deep operation is unavailable on an unbound target.
    pub fn unbound_operation_error(&self, operation: &str, selection: &Selection) -> Option<AnalysisError> {
        if selection.binding.is_some() || !self.declared_operations().iter().any(|o| o == operation) {
            return None;
        }
        let all_unsupported = !selection.candidates.is_empty()
            && selection
                .candidates
                .iter()
                .all(|c| c.target_support.as_ref().map(|s| !s.supported).unwrap_or(false));
        let reason = if all_unsupported {
            "target_unsupported"
        } else {
            "provider_unavailable"
        };
        Some(self.selection_error(reason, &selection.requested_provider_id, &selection.candidates, operation))
    }
}

/// One target-bound provider route with its live client.
pub struct ActiveRoute {
    pub target: BinaryTarget,
    pub requested_provider: Option<String>,
    pub selection: Selection,
    capabilities: HashMap<String, Capability>,
    client: Option<Arc<dyn AnalysisClient>>,
    registry: Arc<Registry>,
    cache: StdMutex<SnapshotCache>,
}

/// Immutable provider reads replayed within one session (port of `AnalysisSnapshotCache`).
#[derive(Default)]
struct SnapshotCache {
    entries: HashMap<String, AnalysisExecution>,
    invalidated: bool,
}

/// Callback invoked for every successful, cache-eligible provider execution that was not replayed.
pub trait Recorder: Fn(&str, &Value, &AnalysisExecution) + Send + Sync {}
impl<T: Fn(&str, &Value, &AnalysisExecution) + Send + Sync> Recorder for T {}

const STATEFUL_OPERATIONS: [&str; 6] = [
    "health",
    "current_address",
    "current_procedure",
    "current_document",
    "goto_address",
    "list_documents",
];

const CURSOR_DEFAULT_OPERATIONS: [&str; 6] = ["address_name", "comment", "inline_comment", "next_address", "prev_address", "xrefs"];

/// Operations of REA's official contracts: scoped to a document, so cacheable only with one.
const DOCUMENT_SCOPED_OPERATIONS: [&str; 36] = [
    "annotate_native_function",
    "inspect_native_load_image",
    "inspect_native_data_type",
    "inspect_native_instruction",
    "resolve_native_call_targets",
    "address_name",
    "comment",
    "current_address",
    "current_procedure",
    "goto_address",
    "inline_comment",
    "list_bookmarks",
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
    "procedure_references",
    "procedure_pseudo_code",
    "resolve_containing_procedure",
    "search_procedures",
    "search_strings",
    "set_address_name",
    "set_addresses_names",
    "set_bookmark",
    "set_comment",
    "set_inline_comment",
    "unset_bookmark",
    "xrefs",
];

/// Whether an operation is immutable and independent of provider UI state.
fn is_snapshot_cacheable(operation: &str, capability: &Capability, parameters: &Value) -> bool {
    let has = |key: &str| parameters.get(key).map(Value::is_string).unwrap_or(false);
    !STATEFUL_OPERATIONS.contains(&operation)
        && (!DOCUMENT_SCOPED_OPERATIONS.contains(&operation) || has("document"))
        && (!CURSOR_DEFAULT_OPERATIONS.contains(&operation) || has("address"))
        && !capability.effects.mutates_artifact
        && capability.cache_policy != CachePolicy::Live
        && (capability.cache_policy == CachePolicy::Snapshot || !capability.effects.may_write_filesystem)
        && !capability.effects.changes_permissions
}

impl ActiveRoute {
    pub fn profile(&self) -> Option<&AnalysisProfile> {
        self.selection.binding.as_ref().map(|b| &b.profile)
    }

    pub fn binding(&self) -> Option<&Binding> {
        self.selection.binding.as_ref()
    }

    pub fn capability(&self, operation: &str) -> Option<&Capability> {
        self.capabilities.get(operation)
    }

    pub fn provider_id(&self) -> String {
        self.selection
            .binding
            .as_ref()
            .map(|b| b.identity.id.clone())
            .unwrap_or_else(|| "composite:none".to_string())
    }

    /// Resolve capability and run one operation, committing the selected profile.
    pub async fn execute(
        &self,
        operation: &str,
        parameters: &Value,
        ctx: &ExecContext,
    ) -> Result<AnalysisExecution, AnalysisError> {
        self.execute_with(operation, parameters, ctx, None).await
    }

    /// Like [`execute`](Self::execute), reporting fresh cache-eligible executions to `recorder`.
    pub async fn execute_with(
        &self,
        operation: &str,
        parameters: &Value,
        ctx: &ExecContext,
        recorder: Option<&dyn Recorder>,
    ) -> Result<AnalysisExecution, AnalysisError> {
        let capability = self.capabilities.get(operation);
        if capability.map(|c| !c.available).unwrap_or(true) {
            if let Some(error) = self.registry.unbound_operation_error(operation, &self.selection) {
                return Err(error);
            }
            return Err(AnalysisError::CapabilityUnavailable {
                provider_id: self.provider_id(),
                operation: operation.to_string(),
                reason: capability
                    .and_then(|c| c.reason.clone())
                    .unwrap_or_else(|| "operation is not declared by this provider".to_string()),
                user_message: None,
            });
        }
        let capability = capability.unwrap();
        let profile = self.profile().filter(|p| capability.provider.id == p.provider.id);
        let cache_key = if profile.is_some() && is_snapshot_cacheable(operation, capability, parameters) {
            tracewise_domain::canonical::canonical_json(&json!({ "operation": operation, "parameters": parameters })).ok()
        } else {
            None
        };
        if let Some(key) = &cache_key {
            let cache = self.cache.lock().unwrap();
            if !cache.invalidated {
                if let Some(hit) = cache.entries.get(key) {
                    let mut replay = hit.clone();
                    replay.limitations.push(
                        "Loaded from a local REA analysis snapshot; this call did not re-run the provider.".to_string(),
                    );
                    replay.analysis_profile = profile.cloned();
                    return Ok(replay);
                }
            }
        }
        let Some(client) = &self.client else {
            return Err(AnalysisError::capability_unavailable(
                &self.provider_id(),
                operation,
                "operation is not declared by this provider",
            ));
        };
        let mut execution = client.execute(operation, parameters, ctx).await?;
        if let Some(profile) = profile {
            let provider = &execution.provider;
            if provider.id != profile.provider.id
                || provider.name != profile.provider.name
                || provider.version.as_deref() != Some(profile.provider.version.as_str())
            {
                return Err(AnalysisError::adapter(
                    &profile.provider.id,
                    &format!("{operation}:profile"),
                ));
            }
            execution.analysis_profile = Some(profile.clone());
        }
        if let Some(key) = cache_key {
            {
                let mut cache = self.cache.lock().unwrap();
                if !cache.invalidated {
                    cache.entries.insert(key, execution.clone());
                }
            }
            if let Some(recorder) = recorder {
                recorder(operation, parameters, &execution);
            }
        } else if capability.effects.mutates_artifact {
            let mut cache = self.cache.lock().unwrap();
            cache.entries.clear();
            cache.invalidated = true;
        }
        Ok(execution)
    }

    pub async fn close(&self) -> Result<(), AnalysisError> {
        match &self.client {
            Some(client) => client.close(false).await,
            None => Ok(()),
        }
    }
}

#[async_trait]
impl OperationPort for ActiveRoute {
    async fn execute(
        &self,
        operation: &str,
        parameters: &Value,
        ctx: &ExecContext,
    ) -> Result<AnalysisExecution, AnalysisError> {
        ActiveRoute::execute(self, operation, parameters, ctx).await
    }
}

/// Engine state owned by one binary session.
pub struct EngineSession {
    registry: Arc<Registry>,
    active: StdMutex<Option<Arc<ActiveRoute>>>,
    gate: Mutex<()>,
}

impl EngineSession {
    pub fn new(registry: Registry) -> Self {
        Self {
            registry: Arc::new(registry),
            active: StdMutex::new(None),
            gate: Mutex::new(()),
        }
    }

    pub fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }

    /// Bind the active target (reusing the live route when nothing changed).
    pub async fn route_for(
        &self,
        target: &BinaryTarget,
        requested_provider: Option<&str>,
        still_current: &(dyn Fn() -> bool + Send + Sync),
    ) -> Result<Arc<ActiveRoute>, AnalysisError> {
        let _gate = self.gate.lock().await;
        // The caller read its target before waiting for the gate; if the session moved on in the
        // meantime, binding now would resurrect the previous target's route.
        if !still_current() {
            return Err(AnalysisError::NoBinaryOpen);
        }
        let existing = self.active.lock().unwrap().clone();
        if let Some(route) = existing {
            if route.target == *target && route.requested_provider.as_deref() == requested_provider {
                return Ok(route);
            }
            if let Some(stale) = self.detach() {
                let _ = stale.close().await;
            }
        }
        let selection = self.registry.select(target, requested_provider).await?;
        let mut capabilities = HashMap::new();
        let mut client = None;
        if let Some(binding) = &selection.binding {
            for capability in binding.provider.capabilities() {
                capabilities.insert(capability.operation.clone(), capability);
            }
            client = Some(binding.provider.create_client(target, Some(binding.profile.clone())));
        }
        let route = Arc::new(ActiveRoute {
            target: target.clone(),
            requested_provider: requested_provider.map(str::to_string),
            selection,
            capabilities,
            client,
            registry: self.registry.clone(),
            cache: StdMutex::new(SnapshotCache::default()),
        });
        *self.active.lock().unwrap() = Some(route.clone());
        Ok(route)
    }

    /// Release the live provider client (close_binary or a target switch).
    /// Detach the live route without waiting for its provider to stop.
    pub fn detach(&self) -> Option<Arc<ActiveRoute>> {
        self.active.lock().unwrap().take()
    }

    pub async fn release(&self) -> Result<(), AnalysisError> {
        let taken = self.detach();
        match taken {
            Some(route) => route.close().await,
            None => Ok(()),
        }
    }

    pub fn active_route(&self) -> Option<Arc<ActiveRoute>> {
        self.active.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod stale_route_tests {
    use super::*;

    #[tokio::test]
    async fn a_call_for_a_superseded_target_cannot_bind_a_route() {
        let session = EngineSession::new(Registry::new(Vec::new(), "auto"));
        let target = BinaryTarget::from_session("/nowhere/old_target", "elf", Some("x86_64"), &"a".repeat(64));
        let result = session.route_for(&target, None, &|| false).await;
        assert!(matches!(result, Err(AnalysisError::NoBinaryOpen)));
        assert!(session.active_route().is_none(), "no route may be left behind for the old target");
    }
}
