//! Engine configuration read from the REA environment variables.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::ghidra::{GhidraConfig, GhidraProvider};
use crate::hopper::{HopperConfig, HopperProvider};
use crate::ida::{IdaConfig, IdaProvider};
use crate::provider::AnalysisProvider;
use crate::session::Registry;

/// Settings that locate the configured engines.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// `REA_ANALYSIS_PROVIDER`: `auto` or one provider id.
    pub analysis_provider: String,
    pub environment: BTreeMap<String, String>,
    pub ghidra: GhidraConfig,
    pub hopper: HopperConfig,
    pub ida: IdaConfig,
}

impl EngineConfig {
    pub fn from_environment(environment: BTreeMap<String, String>) -> Self {
        let analysis_provider = environment
            .get("REA_ANALYSIS_PROVIDER")
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| "auto".to_string());
        let ghidra = GhidraConfig::from_environment(&environment);
        let hopper = HopperConfig::from_environment(&environment);
        let ida = IdaConfig::from_environment(&environment);
        Self {
            analysis_provider,
            environment,
            ghidra,
            hopper,
            ida,
        }
    }

    pub fn from_process_environment() -> Self {
        Self::from_environment(std::env::vars().collect())
    }

    pub fn build_registry(&self) -> Registry {
        let providers: Vec<Arc<dyn AnalysisProvider>> = vec![
            Arc::new(GhidraProvider::new(self.ghidra.clone())),
            Arc::new(HopperProvider::new(self.hopper.clone())),
            Arc::new(IdaProvider::new(self.ida.clone())),
        ];
        Registry::new(providers, &self.analysis_provider)
    }
}
