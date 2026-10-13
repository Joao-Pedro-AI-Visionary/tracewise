//! Version-bound, deterministic analysis profile (port of `GhidraAnalysisProfile.ts`).

use serde_json::{json, Map, Value};
use tracewise_domain::evidence::{create_analysis_profile, AnalysisProfile, CommittedProviderIdentity};

use crate::error::AnalysisError;
use crate::target::BinaryTarget;

use super::install::GhidraInstallation;

pub fn resolve(
    target: &BinaryTarget,
    installation: &GhidraInstallation,
) -> Result<Option<AnalysisProfile>, AnalysisError> {
    if target.kind != "executable" {
        return Ok(None);
    }
    let Some(version) = installation.provider_version.clone().filter(|_| installation.available) else {
        return Err(AnalysisError::adapter("ghidra", "resolve_analysis_profile"));
    };
    let mut available: Vec<String> = target.available_architectures.clone();
    available.sort();
    let mut parameters = Map::new();
    parameters.insert("target_kind".into(), json!(target.kind));
    parameters.insert("target_format".into(), json!(target.format));
    if target.format == "pe" {
        parameters.insert("executable_role".into(), json!(target.executable_role));
        parameters.insert("managed".into(), json!(target.managed));
    }
    parameters.insert("architecture".into(), json!(target.architecture));
    parameters.insert("available_architectures".into(), json!(available));
    for (key, value) in [
        ("import_mode", "ephemeral-source-immutable"),
        ("annotation_policy", "atomic-function-entry-metadata-v1"),
        ("load_image_observations", "source-mappings-entry-context-v2"),
        ("function_body_evidence", "complete-inclusive-ranges-v1"),
        ("function_references", "complete-body-and-entry-reference-manager-v2"),
        ("location_resolution", "explicit-address-exact-entry-symbol-first-v3"),
        ("instruction_flow_evidence", "decoded-return-pcode-v1"),
        ("process_launch", "inspected-jvm-launch-support-v1"),
        ("jump_table_evidence", "typed-case-default-blocks-v1"),
    ] {
        parameters.insert(key.into(), json!(value));
    }
    parameters.insert("decompiler_jump_loads".into(), json!(true));
    parameters.insert("loader".into(), json!("auto-from-header"));
    parameters.insert("language_id".into(), json!("auto-from-header"));
    parameters.insert("compiler_spec_id".into(), json!("auto-default"));
    parameters.insert("analyzer_preset".into(), json!("ghidra-default"));
    let provider = CommittedProviderIdentity {
        id: "ghidra".to_string(),
        name: "Ghidra".to_string(),
        version,
    };
    create_analysis_profile(provider, Value::Object(parameters))
        .map(Some)
        .map_err(|e| AnalysisError::adapter_with("ghidra", "resolve_analysis_profile", json!({ "reason": e.to_string() })))
}
