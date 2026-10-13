//! Bring-your-own IDA MCP candidate (port of `IdaProvider.ts`). Discovery performs no
//! provider startup: availability and the profile come from the registration alone.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use serde_json::{json, Value};
use tracewise_domain::evidence::{
    create_analysis_profile, AnalysisProfile, CommittedProviderIdentity,
};

use crate::error::AnalysisError;
use crate::provider::{
    AnalysisClient, AnalysisExecution, AnalysisProvider, Capability, ExecContext,
    ProviderAvailability, ProviderIdentity, TargetSupport,
};
use crate::target::BinaryTarget;

use super::capabilities::{capabilities, provider_identity};
use super::client::IdaSessionClient;
use super::config::{
    configuration_error, read_registration, IdaConfig, IdaMode, IdaRegistration, NOT_CONFIGURED,
};
use super::connection::{default_connection, IdaConnection};

/// Builds the MCP connection of one session (an injection seam for tests).
pub type ConnectionFactory = Arc<
    dyn Fn(&IdaRegistration, &BTreeMap<String, String>) -> Arc<dyn IdaConnection> + Send + Sync,
>;

pub struct IdaProvider {
    config: IdaConfig,
    registration: OnceLock<Result<IdaRegistration, String>>,
    factory: ConnectionFactory,
}

impl IdaProvider {
    pub fn new(config: IdaConfig) -> Self {
        Self::with_connection_factory(config, Arc::new(default_connection))
    }

    pub fn with_connection_factory(config: IdaConfig, factory: ConnectionFactory) -> Self {
        Self {
            config,
            registration: OnceLock::new(),
            factory,
        }
    }

    /// The validated registration, or the constraint text that rejected it.
    fn configuration(&self) -> &Result<IdaRegistration, String> {
        self.registration
            .get_or_init(|| match &self.config.config_path {
                None => Err(NOT_CONFIGURED.to_string()),
                Some(path) if !Path::new(path).is_absolute() => {
                    Err("REA_IDA_MCP_CONFIG must be absolute".to_string())
                }
                Some(path) => read_registration(path),
            })
    }
}

#[async_trait]
impl AnalysisProvider for IdaProvider {
    fn identity(&self) -> ProviderIdentity {
        provider_identity()
    }

    fn capabilities(&self) -> Vec<Capability> {
        match self.configuration() {
            Ok(registration) => capabilities(registration.mode, registration.is_stdio()),
            Err(_) => capabilities(IdaMode::Attached, false),
        }
    }

    fn inspect_availability(&self) -> ProviderAvailability {
        match self.configuration() {
            Ok(registration) => ProviderAvailability {
                available: true,
                code: None,
                reason: None,
                diagnostics: json!({
                    "configured": true,
                    "mode": registration.mode.as_str(),
                    "transport": if registration.is_stdio() { "stdio" } else { "http" },
                    "live_connection_probed": false,
                }),
            },
            Err(constraint) => ProviderAvailability {
                available: false,
                code: Some(
                    if self.config.config_path.is_none() {
                        "not_configured"
                    } else {
                        "open_options_invalid"
                    }
                    .to_string(),
                ),
                reason: Some(constraint.clone()),
                diagnostics: json!({ "configured": false, "live_connection_probed": false }),
            },
        }
    }

    fn inspect_target_support(&self, target: &BinaryTarget) -> TargetSupport {
        let diagnostics = json!({ "target_kind": target.kind, "target_format": target.format });
        if target.kind == "executable" && target.architecture.as_deref() == Some("mips") {
            return TargetSupport::unsupported(
                "architecture_unsupported",
                "REA's IDA adapter has no verified MIPS lane. Select a supported Ghidra profile instead.",
                diagnostics,
            );
        }
        if target.kind == "executable" {
            TargetSupport::supported(diagnostics)
        } else {
            TargetSupport::unsupported(
                "target_kind_unsupported",
                "IDA MCP integration admits executable inputs, not analysis databases. Select the original input binary.",
                diagnostics,
            )
        }
    }

    async fn resolve_analysis_profile(
        &self,
        _target: &BinaryTarget,
    ) -> Result<Option<AnalysisProfile>, AnalysisError> {
        let registration = match self.configuration() {
            Ok(registration) => registration,
            Err(constraint) => return Err(configuration_error(constraint)),
        };
        let parameters = json!({
            "version_scope": "rea-ida-adapter",
            "engine_version": Value::Null,
            "upstream_distribution_version": Value::Null,
            "mode": registration.mode.as_str(),
            "compatibility_profile": match registration.mode {
                IdaMode::Attached => "legacy-1.4",
                IdaMode::Headless => "database-supervisor",
            },
            "database_revision": Value::Null,
            "cache_policy": "live",
            "registration_digest": registration.digest(),
        });
        let identity = provider_identity();
        create_analysis_profile(
            CommittedProviderIdentity {
                id: identity.id,
                name: identity.name,
                version: identity.version.unwrap_or_default(),
            },
            parameters,
        )
        .map(Some)
        .map_err(|e| {
            AnalysisError::adapter_with(
                "ida",
                "resolve_analysis_profile",
                json!({ "reason": e.to_string() }),
            )
        })
    }

    fn create_client(
        &self,
        target: &BinaryTarget,
        profile: Option<AnalysisProfile>,
    ) -> Arc<dyn AnalysisClient> {
        match self.configuration() {
            Err(constraint) => Arc::new(MisconfiguredClient(configuration_error(constraint))),
            Ok(registration) => {
                let connection = (self.factory)(registration, &self.config.environment);
                Arc::new(IdaSessionClient::new(
                    registration.clone(),
                    target.clone(),
                    connection,
                    profile.filter(|p| p.provider.id == "ida"),
                ))
            }
        }
    }
}

/// A rejected registration surfaces its configuration error on every request.
struct MisconfiguredClient(AnalysisError);

#[async_trait]
impl AnalysisClient for MisconfiguredClient {
    async fn execute(
        &self,
        _: &str,
        _: &Value,
        _: &ExecContext,
    ) -> Result<AnalysisExecution, AnalysisError> {
        Err(self.0.clone())
    }

    async fn close(&self, _: bool) -> Result<(), AnalysisError> {
        Ok(())
    }
}
