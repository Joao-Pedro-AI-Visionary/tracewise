//! Provider-neutral analysis contracts (port of `application/AnalysisProvider.ts`).
//!
//! One abstraction serves Ghidra (phase 5), Hopper and IDA (phase 5b): a provider
//! declares capabilities, decides availability and target support, resolves a
//! deterministic analysis profile and creates one client bound to one target.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio_util_lite::CancelToken;
use tracewise_domain::evidence::{AnalysisProfile, EvidenceLocation};

use crate::error::AnalysisError;
use crate::target::BinaryTarget;

/// Minimal cancellation token (avoids a dependency on tokio-util).
pub mod tokio_util_lite {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio::sync::Notify;

    #[derive(Clone, Default)]
    pub struct CancelToken {
        inner: Arc<Inner>,
    }

    #[derive(Default)]
    struct Inner {
        cancelled: AtomicBool,
        notify: Notify,
    }

    impl CancelToken {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn cancel(&self) {
            self.inner.cancelled.store(true, Ordering::SeqCst);
            self.inner.notify.notify_waiters();
        }

        pub fn is_cancelled(&self) -> bool {
            self.inner.cancelled.load(Ordering::SeqCst)
        }

        pub async fn cancelled(&self) {
            loop {
                let notified = self.inner.notify.notified();
                if self.is_cancelled() {
                    return;
                }
                notified.await;
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIdentity {
    pub id: String,
    pub name: String,
    pub version: Option<String>,
}

impl ProviderIdentity {
    pub fn new(id: &str, name: &str, version: Option<&str>) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            version: version.map(str::to_string),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({ "id": self.id, "name": self.name, "version": self.version })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Effects {
    pub mutates_artifact: bool,
    pub launches_process: bool,
    pub may_show_ui: bool,
    pub may_access_network: bool,
    pub may_write_filesystem: bool,
    pub changes_permissions: bool,
    pub requires_root: bool,
}

impl Effects {
    pub fn to_json(&self) -> Value {
        json!({
            "mutates_artifact": self.mutates_artifact,
            "launches_process": self.launches_process,
            "may_show_ui": self.may_show_ui,
            "may_access_network": self.may_access_network,
            "may_write_filesystem": self.may_write_filesystem,
            "changes_permissions": self.changes_permissions,
            "requires_root": self.requires_root,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePolicy {
    Snapshot,
    Live,
    Unspecified,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Capability {
    pub provider: ProviderIdentity,
    pub operation: String,
    pub available: bool,
    pub reason: Option<String>,
    pub availability_code: Option<String>,
    pub cache_policy: CachePolicy,
    pub effects: Effects,
    pub limitations: Vec<String>,
}

impl Capability {
    pub fn to_json(&self) -> Value {
        json!({
            "operation": self.operation,
            "available": self.available,
            "reason": self.reason,
            "availability_code": self.availability_code,
            "effects": self.effects.to_json(),
            "limitations": self.limitations,
        })
    }
}

/// Atomic successful provider observation with exact producing provenance.
#[derive(Debug, Clone)]
pub struct AnalysisExecution {
    pub result: Value,
    pub raw_result: Option<Value>,
    pub provider: ProviderIdentity,
    pub analysis_profile: Option<AnalysisProfile>,
    pub limitations: Vec<String>,
    pub locations: Vec<EvidenceLocation>,
}

impl AnalysisExecution {
    pub fn new(result: Value, provider: ProviderIdentity) -> Self {
        Self {
            result,
            raw_result: None,
            provider,
            analysis_profile: None,
            limitations: Vec::new(),
            locations: Vec::new(),
        }
    }
}

/// Bounded host observation made without starting an analysis process.
#[derive(Debug, Clone)]
pub struct ProviderAvailability {
    pub available: bool,
    pub code: Option<String>,
    pub reason: Option<String>,
    pub diagnostics: Value,
}

impl ProviderAvailability {
    pub fn to_json(&self) -> Value {
        json!({
            "status": if self.available { "available" } else { "unavailable" },
            "code": self.code,
            "reason": self.reason,
            "diagnostics": self.diagnostics,
        })
    }
}

#[derive(Debug, Clone)]
pub struct TargetSupport {
    pub supported: bool,
    pub code: Option<String>,
    pub reason: Option<String>,
    pub diagnostics: Value,
}

impl TargetSupport {
    pub fn supported(diagnostics: Value) -> Self {
        Self {
            supported: true,
            code: None,
            reason: None,
            diagnostics,
        }
    }

    pub fn unsupported(code: &str, reason: &str, diagnostics: Value) -> Self {
        Self {
            supported: false,
            code: Some(code.to_string()),
            reason: Some(reason.to_string()),
            diagnostics,
        }
    }
}

/// Execution context handed to a client call.
#[derive(Clone, Default)]
pub struct ExecContext {
    pub cancel: CancelToken,
}

/// Provider session bound to exactly one parsed artifact.
#[async_trait]
pub trait AnalysisClient: Send + Sync {
    async fn execute(
        &self,
        operation: &str,
        parameters: &Value,
        ctx: &ExecContext,
    ) -> Result<AnalysisExecution, AnalysisError>;

    /// Close owned resources. `retain_document` keeps a GUI document open.
    async fn close(&self, retain_document: bool) -> Result<(), AnalysisError>;
}

/// Factory and capability declaration for an analysis implementation.
#[async_trait]
pub trait AnalysisProvider: Send + Sync {
    fn identity(&self) -> ProviderIdentity;
    fn capabilities(&self) -> Vec<Capability>;
    fn inspect_availability(&self) -> ProviderAvailability;
    fn inspect_target_support(&self, target: &BinaryTarget) -> TargetSupport;
    /// Resolve the version-bound, deterministic profile before any process starts.
    async fn resolve_analysis_profile(
        &self,
        target: &BinaryTarget,
    ) -> Result<Option<AnalysisProfile>, AnalysisError>;
    fn create_client(
        &self,
        target: &BinaryTarget,
        profile: Option<AnalysisProfile>,
    ) -> Arc<dyn AnalysisClient>;
}

/// Shared effect presets.
pub fn read_effects_launching() -> Effects {
    Effects {
        mutates_artifact: false,
        launches_process: true,
        may_show_ui: false,
        may_access_network: false,
        may_write_filesystem: true,
        changes_permissions: false,
        requires_root: false,
    }
}
