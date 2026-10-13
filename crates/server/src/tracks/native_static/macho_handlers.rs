//! Handlers of the Mach-O tools that REA backs with Apple command-line utilities:
//! `list_architectures`, `inspect_macho`, `inspect_signature`, `inspect_plist`, `demangle_swift`.
//! Here they run on the file bytes inside the process, on any host.

use rmcp::model::CallToolResult;
use rmcp::ErrorData as McpError;
use serde_json::{json, Value};
use tracewise_domain::evidence::{EvidenceLocation, EvidenceProvider};
use tracewise_native::macho_tools::{FileLocation, NativeObservation};
use tracewise_native::NativeError;

use super::common::{active_target, error_result, error_text_result, evidence_result, ActiveTarget};
use super::validate::{validate, Field};
use crate::session::BinarySession;

pub const NATIVE_MACOS_PROVIDER_ID: &str = "native-macos";

/// `NATIVE_MACOS_PROVIDER_IDENTITY` of REA.
pub fn native_macos_provider() -> EvidenceProvider {
    EvidenceProvider {
        id: NATIVE_MACOS_PROVIDER_ID.to_string(),
        name: "macOS native inspection utilities".to_string(),
        version: None,
    }
}

pub fn locations_of(items: &[FileLocation]) -> Vec<EvidenceLocation> {
    items
        .iter()
        .map(|item| match item {
            FileLocation::Offset(offset) => EvidenceLocation::FileOffset { offset: *offset },
            FileLocation::Range(start, end) => EvidenceLocation::FileOffsetRange { start: *start, end: *end },
        })
        .collect()
}

/// Record a native observation under the active target's subject.
pub fn observation_result(
    session: &BinarySession,
    target: &ActiveTarget,
    operation: &str,
    parameters: Value,
    observation: NativeObservation,
) -> Result<CallToolResult, McpError> {
    evidence_result(
        session,
        Some(target.subject.clone()),
        native_macos_provider(),
        operation,
        parameters,
        observation.result,
        observation.limitations,
        locations_of(&observation.locations),
    )
}

/// The common preamble: strict empty input, an open target.
pub fn require_target(
    session: &BinarySession,
    tool: &str,
    args: &Value,
    fields: &[Field],
) -> Result<ActiveTarget, CallToolResult> {
    if let Err(message) = validate(tool, args, fields) {
        return Err(error_text_result(message));
    }
    active_target(session).map_err(|error| error_result(&error))
}

fn not_macho(operation: &str) -> CallToolResult {
    error_result(&NativeError::Capability {
        provider_id: NATIVE_MACOS_PROVIDER_ID.to_string(),
        operation: operation.to_string(),
        reason: "Active artifact is not Mach-O.".to_string(),
        user_message: false,
    })
}

pub fn list_architectures(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    const TOOL: &str = "list_architectures";
    let target = match require_target(session, TOOL, args, &[]) {
        Ok(target) => target,
        Err(result) => return Ok(result),
    };
    if target.format() != "mach-o" {
        return Ok(not_macho(TOOL));
    }
    match tracewise_native::macho_tools::list_architectures(std::path::Path::new(target.path()), "$ARTIFACT") {
        Ok(observation) => observation_result(session, &target, TOOL, json!({}), observation),
        Err(error) => Ok(error_result(&error)),
    }
}

pub fn inspect_macho(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    const TOOL: &str = "inspect_macho";
    let target = match require_target(session, TOOL, args, &[]) {
        Ok(target) => target,
        Err(result) => return Ok(result),
    };
    if target.format() != "mach-o" {
        return Ok(not_macho(TOOL));
    }
    let architecture = target.subject.architecture.clone();
    match tracewise_native::macho_tools::inspect_macho(
        std::path::Path::new(target.path()),
        architecture.as_deref(),
        "$ARTIFACT",
    ) {
        Ok(observation) => observation_result(session, &target, TOOL, json!({}), observation),
        Err(error) => Ok(error_result(&error)),
    }
}


pub fn demangle_swift(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    use super::validate::Kind;
    const TOOL: &str = "demangle_swift";
    let target = match require_target(
        session,
        TOOL,
        args,
        &[Field { name: "symbols", kind: Kind::SwiftSymbols, required: true }],
    ) {
        Ok(target) => target,
        Err(result) => return Ok(result),
    };
    let symbols: Vec<String> = args["symbols"]
        .as_array()
        .map(|items| items.iter().filter_map(|item| item.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let result = tracewise_native::demangle::demangle_symbols(&symbols, "$ARTIFACT");
    observation_result(
        session,
        &target,
        TOOL,
        json!({ "symbols": symbols }),
        NativeObservation { result, limitations: Vec::new(), locations: Vec::new() },
    )
}

pub fn inspect_plist(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    use super::validate::Kind;
    use tracewise_native::plist_tool::{inspect_plist as run, PlistRequest};
    const TOOL: &str = "inspect_plist";
    let target = match require_target(
        session,
        TOOL,
        args,
        &[Field { name: "path", kind: Kind::LocalPath, required: false }],
    ) {
        Ok(target) => target,
        Err(result) => return Ok(result),
    };
    let requested = args.get("path").and_then(Value::as_str);
    let source = target.bundle.clone().unwrap_or_else(|| std::path::PathBuf::from(target.path()));
    let request = PlistRequest {
        requested,
        source_path: &source,
        target_path: std::path::Path::new(target.path()),
        bundle_info_plist: target.bundle_info_plist.as_deref(),
    };
    match run(&request) {
        Ok(observation) => evidence_result(
            session,
            Some(target.subject.clone()),
            native_macos_provider(),
            TOOL,
            match requested {
                Some(path) => json!({ "path": path }),
                None => json!({}),
            },
            observation.result,
            observation.limitations,
            vec![EvidenceLocation::ArtifactPath { path: observation.source_path }],
        ),
        Err(error) => Ok(error_result(&error)),
    }
}

pub fn inspect_signature(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    const TOOL: &str = "inspect_signature";
    let target = match require_target(session, TOOL, args, &[]) {
        Ok(target) => target,
        Err(result) => return Ok(result),
    };
    if target.format() != "mach-o" {
        return Ok(not_macho(TOOL));
    }
    let architecture = target.subject.architecture.clone();
    match tracewise_native::codesig::inspect_signature(
        std::path::Path::new(target.path()),
        &target.subject.digest.sha256,
        architecture.as_deref(),
        "$ARTIFACT",
    ) {
        Ok(observation) => observation_result(
            session,
            &target,
            TOOL,
            json!({}),
            NativeObservation { result: observation.result, limitations: observation.limitations, locations: Vec::new() },
        ),
        Err(error) => Ok(error_result(&error)),
    }
}
