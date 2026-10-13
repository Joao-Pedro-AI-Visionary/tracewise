//! Ghidra candidate backed by an isolated ephemeral headless import
//! (port of `GhidraProvider.ts` and `GhidraProviderClient.ts`).

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use serde_json::{json, Value};
use tracewise_domain::evidence::AnalysisProfile;

use crate::error::AnalysisError;
use crate::provider::{
    AnalysisClient, AnalysisExecution, AnalysisProvider, Capability, ExecContext, ProviderAvailability,
    ProviderIdentity, TargetSupport,
};
use crate::target::BinaryTarget;

use super::capabilities::{
    capabilities, health_limitations, is_ghidra_operation, limitations_for, provider_identity,
};
use super::client::{GhidraClient, GhidraClientOptions, SessionError};
use super::install::{inspect_installation, unverified_build_limitation, GhidraInstallation};
use super::{profile, values};

const SUPPORTED_ARCHITECTURES: [&str; 4] = ["x86", "x86_64", "arm", "arm64"];

/// Environment and settings that locate a bring-your-own Ghidra.
#[derive(Debug, Clone)]
pub struct GhidraConfig {
    pub install_dir: Option<String>,
    pub java_home: Option<String>,
    pub startup_timeout_ms: u64,
    pub environment: BTreeMap<String, String>,
}

impl GhidraConfig {
    pub fn from_environment(environment: &BTreeMap<String, String>) -> Self {
        Self {
            install_dir: environment.get("GHIDRA_INSTALL_DIR").filter(|v| !v.is_empty()).cloned(),
            java_home: environment.get("JAVA_HOME").filter(|v| !v.is_empty()).cloned(),
            startup_timeout_ms: environment
                .get("REA_GHIDRA_STARTUP_TIMEOUT_MS")
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|v| *v >= 1)
                .unwrap_or(330_000),
            environment: environment.clone(),
        }
    }
}

pub struct GhidraProvider {
    config: GhidraConfig,
    installation: OnceLock<GhidraInstallation>,
}

impl GhidraProvider {
    pub fn new(config: GhidraConfig) -> Self {
        Self {
            config,
            installation: OnceLock::new(),
        }
    }

    pub fn installation(&self) -> &GhidraInstallation {
        self.installation.get_or_init(|| {
            inspect_installation(
                &self.config.environment,
                self.config.install_dir.as_deref(),
                self.config.java_home.as_deref(),
            )
        })
    }
}

#[async_trait]
impl AnalysisProvider for GhidraProvider {
    fn identity(&self) -> ProviderIdentity {
        provider_identity()
    }

    fn capabilities(&self) -> Vec<Capability> {
        capabilities(&provider_identity())
    }

    fn inspect_availability(&self) -> ProviderAvailability {
        let installation = self.installation();
        match &installation.rejection {
            None => ProviderAvailability {
                available: true,
                code: None,
                reason: None,
                diagnostics: installation.diagnostics(),
            },
            Some((code, reason)) => ProviderAvailability {
                available: false,
                code: Some((*code).to_string()),
                reason: Some(reason.clone()),
                diagnostics: installation.diagnostics(),
            },
        }
    }

    fn inspect_target_support(&self, target: &BinaryTarget) -> TargetSupport {
        let diagnostics = json!({
            "host_platform": "linux",
            "target_kind": target.kind,
            "target_format": target.format,
            "architecture": target.architecture,
            "available_architectures": if target.kind == "executable" { json!(target.available_architectures) } else { Value::Null },
            "executable_role": target.executable_role,
            "managed": target.managed,
        });
        if target.kind != "executable" {
            return TargetSupport::unsupported(
                "target_kind_unsupported",
                &format!("Ghidra v1 imports executable targets, not {} targets.", target.kind),
                diagnostics,
            );
        }
        if target.architecture.as_deref() == Some("mips") {
            return TargetSupport::unsupported(
                "architecture_unsupported",
                "MIPS analysis requires an inspected ELF ABI declaration that tracewise does not parse yet; a family name alone does not select an ISA or ABI.",
                diagnostics,
            );
        }
        if target.format == "dos-mz" || target.format == "dos-com" {
            return TargetSupport::unsupported(
                "target_format_unsupported",
                "DOS real-mode imports need the independent load-image verification that tracewise does not port yet.",
                diagnostics,
            );
        }
        if target.format == "mach-o" && target.available_architectures.len() > 1 {
            return TargetSupport::unsupported(
                "architecture_unsupported",
                "Ghidra v1 cannot enforce the selected architecture when importing a universal Mach-O; analyze a thinned Mach-O slice instead.",
                diagnostics,
            );
        }
        match &target.architecture {
            Some(arch) if SUPPORTED_ARCHITECTURES.contains(&arch.as_str()) => TargetSupport::supported(diagnostics),
            _ => TargetSupport::unsupported(
                "architecture_unsupported",
                "Ghidra v1 requires a supported x86, x86_64, arm, arm64, or MIPS target profile.",
                diagnostics,
            ),
        }
    }

    async fn resolve_analysis_profile(
        &self,
        target: &BinaryTarget,
    ) -> Result<Option<AnalysisProfile>, AnalysisError> {
        profile::resolve(target, self.installation())
    }

    fn create_client(&self, target: &BinaryTarget, profile: Option<AnalysisProfile>) -> Arc<dyn AnalysisClient> {
        let installation = self.installation().clone();
        if target.kind != "executable" {
            return Arc::new(UnavailableClient(AnalysisError::capability_unavailable(
                "ghidra",
                "health",
                &format!("Ghidra cannot import {} targets through this adapter.", target.kind),
            )));
        }
        if !installation.available {
            return Arc::new(UnavailableClient(AnalysisError::adapter_with(
                "ghidra",
                "health",
                installation.diagnostics(),
            )));
        }
        let Some(profile) = profile.filter(|p| p.provider.id == "ghidra") else {
            return Arc::new(UnavailableClient(AnalysisError::adapter("ghidra", "health")));
        };
        let client = GhidraClient::new(GhidraClientOptions {
            installation: installation.clone(),
            environment: self.config.environment.clone(),
            target_path: target.path.clone(),
            target_sha256: target.sha256.clone(),
            provider_version: profile.provider.version.clone(),
            profile_digest: profile.digest.clone(),
            startup_timeout_ms: self.config.startup_timeout_ms,
        });
        let release_limitation = unverified_build_limitation(&profile.provider.version);
        Arc::new(GhidraProviderClient {
            client,
            profile,
            target: target.clone(),
            startup_timeout_ms: self.config.startup_timeout_ms,
            session_limitations: release_limitation.into_iter().collect(),
        })
    }
}

struct UnavailableClient(AnalysisError);

#[async_trait]
impl AnalysisClient for UnavailableClient {
    async fn execute(&self, _: &str, _: &Value, _: &ExecContext) -> Result<AnalysisExecution, AnalysisError> {
        Err(self.0.clone())
    }

    async fn close(&self, _: bool) -> Result<(), AnalysisError> {
        Ok(())
    }
}

pub struct GhidraProviderClient {
    client: GhidraClient,
    profile: AnalysisProfile,
    target: BinaryTarget,
    startup_timeout_ms: u64,
    session_limitations: Vec<String>,
}

impl GhidraProviderClient {
    fn committed_identity(&self) -> ProviderIdentity {
        ProviderIdentity {
            id: self.profile.provider.id.clone(),
            name: self.profile.provider.name.clone(),
            version: Some(self.profile.provider.version.clone()),
        }
    }

    async fn project(&self, operation: &str, failure: SessionError) -> AnalysisError {
        project_session_error(operation, failure, self.startup_timeout_ms)
    }

    /// Non-DOS targets have no independent load-image verification (DOS targets are not admitted).
    fn attest_load_image(&self, measured: &Value) -> Value {
        json!({
            "status": "unsupported",
            "reason": "Independent load-image verification currently supports DOS MZ and explicit DOS COM targets only.",
            "observations": measured,
            "limitations": [
                "Other formats expose measured mappings and source identities; no format-specific verification was performed.",
            ],
        })
    }
}

#[async_trait]
impl AnalysisClient for GhidraProviderClient {
    async fn execute(
        &self,
        operation: &str,
        parameters: &Value,
        ctx: &ExecContext,
    ) -> Result<AnalysisExecution, AnalysisError> {
        if operation != "health" && !is_ghidra_operation(operation) {
            return Err(AnalysisError::capability_unavailable(
                "ghidra",
                operation,
                "The Ghidra adapter does not declare this operation.",
            ));
        }
        if operation == "health" {
            let info = self
                .client
                .start(&ctx.cancel)
                .await
                .map_err(|e| project_session_error(operation, e, self.startup_timeout_ms))?;
            let mut limitations = health_limitations();
            limitations.extend(self.session_limitations.clone());
            return Ok(AnalysisExecution {
                result: info,
                raw_result: None,
                provider: self.committed_identity(),
                analysis_profile: Some(self.profile.clone()),
                limitations,
                locations: Vec::new(),
            });
        }
        let input = values::parse_input(operation, parameters)?;
        let called = match self.client.call_tool(operation, &input, &ctx.cancel).await {
            Ok(value) => value,
            Err(failure) => return Err(self.project(operation, failure).await),
        };
        values::check_result(operation, &called)?;
        let normalized = if operation == "inspect_native_load_image" {
            self.attest_load_image(&called)
        } else {
            called.clone()
        };
        let mut limitations = limitations_for(operation);
        limitations.extend(self.session_limitations.clone());
        let _ = &self.target;
        Ok(AnalysisExecution {
            result: normalized,
            raw_result: Some(called),
            provider: self.committed_identity(),
            analysis_profile: Some(self.profile.clone()),
            limitations,
            locations: Vec::new(),
        })
    }

    async fn close(&self, _retain_document: bool) -> Result<(), AnalysisError> {
        self.client.close().await.map_err(|e| {
            AnalysisError::ProviderAdapter {
                provider_id: "ghidra".to_string(),
                operation: "close_binary".to_string(),
                diagnostics: Some(e.diagnostics.clone()),
                cleanup_incomplete: true,
                cleanup_resources: vec!["ghidra-process".to_string()],
            }
        })
    }
}

/// `projectPrimarySessionError`.
pub fn project_session_error(operation: &str, failure: SessionError, startup_timeout_ms: u64) -> AnalysisError {
    let remote = failure.remote_code.as_deref();
    if operation == "annotate_native_function" && failure.kind == "remote" && remote == Some("invalid_function_name") {
        return AnalysisError::input(operation, vec![json!("name")], failure.message);
    }
    if failure.kind == "cancelled" {
        return AnalysisError::cancelled(operation);
    }
    if failure.kind == "timeout" || failure.kind == "analysis_timeout" {
        return AnalysisError::Timeout {
            operation: operation.to_string(),
            timeout_ms: failure.timeout_ms.unwrap_or(startup_timeout_ms),
        };
    }
    if failure.kind == "remote" && remote == Some("decompile_cancelled") {
        return AnalysisError::cancelled(operation);
    }
    if failure.kind == "remote" && remote == Some("regex_stack_exhausted") {
        return AnalysisError::ResourceConstraint {
            operation: operation.to_string(),
            resource: "memory".to_string(),
            reason: failure.message,
            reported_limits: None,
            remediation: Some("Retry this search in literal mode or simplify the regex. The active analysis session and annotations remain available.".to_string()),
        };
    }
    if failure.kind == "remote" && matches!(remote, Some("invalid_request" | "not_found" | "ambiguous")) {
        return AnalysisError::input(operation, vec![], failure.message);
    }
    if failure.kind == "remote" && remote == Some("method_unavailable") {
        return AnalysisError::capability_unavailable("ghidra", operation, &failure.message);
    }
    AnalysisError::adapter_with("ghidra", operation, failure.diagnostics)
}
