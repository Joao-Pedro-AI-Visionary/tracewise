//! Dispatch for the adb tools (24): `inspect_adb_client`, `list_adb_devices`,
//! `inspect_adb_device`, `list_adb_packages`, `pull_adb_package`,
//! `read_adb_logcat`, `inspect_adb_package`, `pull_adb_file`, `push_adb_file`,
//! `capture_adb_screen`, `list_adb_processes`, `list_adb_directory`,
//! `list_adb_features`, `list_adb_services`, `inspect_adb_display`,
//! `inspect_adb_window`, `read_adb_setting`, `collect_adb_bugreport`,
//! `resolve_adb_packages`, `install_adb_package`, `uninstall_adb_package`,
//! `start_adb_app`, `start_adb_activity` and `stop_adb_app`.
//!
//! The work lives in the `tracewise-device` crate. This module is the MCP
//! boundary of REA's `registerAdbTools.ts` / `AdbDeviceAnalysisService.ts`:
//! admit the arguments, run the provider against the adb binary selected by
//! `REA_ADB_PATH`, and wrap the result in Evidence. Failures are `isError`
//! tool results carrying REA's projected error body.

use rmcp::model::{CallToolResult, Content};
use rmcp::ErrorData as McpError;
use serde_json::Value;
use tracewise_device::config::ADB_BINARY_ENV;
use tracewise_device::{ExecuteFailure, ADB_PROVIDER_ID, ADB_PROVIDER_NAME, ADB_TOOLS};
use tracewise_domain::evidence::{
    create_evidence, EvidenceConfidence, EvidenceObservation, EvidenceProvider,
};

use crate::handlers::remember_evidence;
use crate::session::BinarySession;

/// REA `createEvidence` prepends this when the observation has no subject.
const MISSING_SUBJECT: &str = "Artifact identity is unavailable for this observation.";

fn error_text(text: String) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::error(vec![Content::text(text)]))
}

pub async fn dispatch(
    session: &BinarySession,
    name: &str,
    args: &Value,
) -> Option<Result<CallToolResult, McpError>> {
    if !ADB_TOOLS.contains(&name) {
        return None;
    }
    Some(handle(session, name, args).await)
}

async fn handle(session: &BinarySession, name: &str, args: &Value) -> Result<CallToolResult, McpError> {
    let input = match tracewise_device::input::validate(name, args) {
        Ok(input) => input,
        Err(text) => return error_text(text),
    };
    let configured = std::env::var(ADB_BINARY_ENV).ok();
    let execution = match tracewise_device::execute(name, &input, configured).await {
        Ok(execution) => execution,
        Err(ExecuteFailure::Analysis(error)) => return error_text(error.error_body().to_string()),
        Err(ExecuteFailure::Plain(message)) => return error_text(message),
    };
    let mut limitations = vec![MISSING_SUBJECT.to_string()];
    limitations.extend(execution.limitations);
    let evidence = create_evidence(
        None,
        EvidenceProvider {
            id: ADB_PROVIDER_ID.to_string(),
            name: ADB_PROVIDER_NAME.to_string(),
            version: execution.provider_version,
        },
        EvidenceObservation {
            predicate_type: None,
            operation: name.to_string(),
            parameters: Value::Object(input),
            normalized_result: execution.result,
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Observed),
            authority: None,
            environment: None,
            limitations: Some(limitations),
            locations: Some(Vec::new()),
            evidence_links: Some(Vec::new()),
        },
    )
    .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    remember_evidence(session, evidence)
}
