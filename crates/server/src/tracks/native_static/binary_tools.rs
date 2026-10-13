//! Path-based native tools that need no active target: `inspect_pe_resources`,
//! `inspect_evm_interface`, `inspect_binary_layout`, `inspect_recorded_crash`.

use std::path::Path;

use rmcp::model::CallToolResult;
use rmcp::ErrorData as McpError;
use serde_json::{json, Value};
use tracewise_domain::evidence::{
    create_evidence, DigestSha256, EvidenceAuthority, EvidenceConfidence, EvidenceLocation, EvidenceObservation,
    EvidenceProvider, EvidenceSubject,
};
use tracewise_native::evm::{
    inspect_evm_interface as run_evm, EvmRequest, EVMOLE_PROVIDER_ID, EVMOLE_PROVIDER_NAME, EVMOLE_PROVIDER_VERSION,
};
use tracewise_native::pe_resources::{inspect_pe_resources as run_pe, PeRequest};
use tracewise_native::NativeError;

use super::common::{error_result, error_text_result, strings_of};
use super::validate::{validate, Field, Kind};
use crate::handlers::remember_evidence;
use crate::session::BinarySession;

fn require_absolute(operation: &str, path: &str) -> Result<(), NativeError> {
    if Path::new(path).is_absolute() {
        return Ok(());
    }
    Err(NativeError::Input {
        operation: operation.to_string(),
        issues: vec![tracewise_native::InputIssue {
            path: vec![json!("path")],
            reason: "invalid_format".to_string(),
            message: Some("Expected an absolute filesystem path on this host.".to_string()),
            expected: None,
        }],
    })
}

fn subject_for(path: &str, format: &str, sha256: &str) -> EvidenceSubject {
    EvidenceSubject {
        name: path
            .rsplit('/')
            .next()
            .filter(|segment| !segment.is_empty())
            .unwrap_or("artifact")
            .to_string(),
        digest: DigestSha256 {
            sha256: sha256.to_string(),
        },
        format: format.to_string(),
        architecture: None,
        local_path: path.to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn record(
    session: &BinarySession,
    subject: EvidenceSubject,
    provider: EvidenceProvider,
    operation: &str,
    parameters: Value,
    normalized_result: Value,
    raw_result: Option<Value>,
    confidence: EvidenceConfidence,
    limitations: Vec<String>,
    locations: Vec<EvidenceLocation>,
) -> Result<CallToolResult, McpError> {
    let evidence = create_evidence(
        Some(subject),
        provider,
        EvidenceObservation {
            predicate_type: Some("rea.analysis".to_string()),
            operation: operation.to_string(),
            parameters,
            normalized_result,
            raw_result,
            analysis_profile: None,
            confidence: Some(confidence),
            authority: Some(EvidenceAuthority::ShippedArtifact),
            environment: None,
            limitations: Some(limitations),
            locations: Some(locations),
            evidence_links: None,
        },
    )
    .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    remember_evidence(session, evidence)
}

pub fn inspect_pe_resources(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    const TOOL: &str = "inspect_pe_resources";
    let fields = [
        Field {
            name: "path",
            kind: Kind::Str { min: 1 },
            required: true,
        },
        Field {
            name: "max_file_bytes",
            kind: Kind::Int {
                min: 64,
                max: 536_870_912,
            },
            required: false,
        },
        Field {
            name: "max_entries",
            kind: Kind::Int { min: 1, max: 65_536 },
            required: false,
        },
    ];
    if let Err(text) = validate(TOOL, args, &fields) {
        return Ok(error_text_result(text));
    }
    let path = args["path"].as_str().unwrap_or("");
    if let Err(error) = require_absolute(TOOL, path) {
        return Ok(error_result(&error));
    }
    let max_file_bytes = args.get("max_file_bytes").and_then(Value::as_i64).unwrap_or(67_108_864);
    let max_entries = args.get("max_entries").and_then(Value::as_i64).unwrap_or(4096);
    let (report, sha256) = match run_pe(&PeRequest {
        path,
        max_file_bytes: max_file_bytes as u64,
        max_entries,
    }) {
        Ok(result) => result,
        Err(error) => return Ok(error_result(&error)),
    };
    let limitations = strings_of(&report, "limitations");
    record(
        session,
        subject_for(path, "pe", &sha256),
        EvidenceProvider {
            id: "rea-pe-resources".to_string(),
            name: "REA PE resource parser".to_string(),
            version: Some("1".to_string()),
        },
        TOOL,
        json!({"path": path, "max_file_bytes": max_file_bytes, "max_entries": max_entries}),
        report,
        None,
        EvidenceConfidence::Observed,
        limitations,
        vec![EvidenceLocation::ArtifactPath { path: path.to_string() }],
    )
}

pub fn inspect_evm_interface(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    const TOOL: &str = "inspect_evm_interface";
    let fields = [
        Field {
            name: "path",
            kind: Kind::Str { min: 1 },
            required: true,
        },
        Field {
            name: "encoding",
            kind: Kind::Enum(&["raw", "hex"]),
            required: true,
        },
    ];
    if let Err(text) = validate(TOOL, args, &fields) {
        return Ok(error_text_result(text));
    }
    let path = args["path"].as_str().unwrap_or("");
    let encoding = args["encoding"].as_str().unwrap_or("hex");
    if let Err(error) = require_absolute(TOOL, path) {
        return Ok(error_result(&error));
    }
    let outcome = match run_evm(&EvmRequest { path, encoding }) {
        Ok(outcome) => outcome,
        Err(error) => return Ok(error_result(&error)),
    };
    record(
        session,
        subject_for(path, "file", &outcome.carrier_sha256),
        EvidenceProvider {
            id: EVMOLE_PROVIDER_ID.to_string(),
            name: EVMOLE_PROVIDER_NAME.to_string(),
            version: Some(EVMOLE_PROVIDER_VERSION.to_string()),
        },
        TOOL,
        json!({"path": path, "encoding": encoding}),
        outcome.report,
        Some(outcome.raw),
        EvidenceConfidence::Inferred,
        outcome.limitations,
        vec![EvidenceLocation::ArtifactPath { path: path.to_string() }],
    )
}

fn captured(error: NativeError, stderr: &str) -> NativeError {
    NativeError::Captured {
        inner: Box::new(error),
        output: json!({"stdout": "", "stderr": stderr, "truncated": false}),
    }
}

/// Map an artifact read failure of a pwntools-style adapter (`pwntoolsDecoderFailure`).
fn read_failure(operation: &str, path: &str, error: NativeError, noun: &str) -> NativeError {
    use tracewise_native::ArtifactReason;
    match error {
        NativeError::Artifact { reason, detail, .. } => {
            let message = detail.unwrap_or_default();
            match reason {
                ArtifactReason::Integrity => NativeError::ArtifactChanged {
                    operation: operation.to_string(),
                    path: path.to_string(),
                    reason: message,
                },
                ArtifactReason::Limit | ArtifactReason::Path | ArtifactReason::Format => NativeError::Input {
                    operation: operation.to_string(),
                    issues: vec![tracewise_native::InputIssue {
                        path: vec![json!("path")],
                        reason: if reason == ArtifactReason::Limit { "out_of_range" } else { "invalid_format" }.to_string(),
                        message: Some(message),
                        expected: None,
                    }],
                },
                _ if message.starts_with("ENOENT") || message.starts_with("ENOTDIR") => {
                    let code = message.split(':').next().unwrap_or("ENOENT").to_string();
                    NativeError::input(
                        operation,
                        vec![json!("path")],
                        format!("Selected {noun} could not be read ({code}): {path}."),
                    )
                }
                _ => NativeError::Artifact {
                    operation: operation.to_string(),
                    reason,
                    detail: Some(message),
                },
            }
        }
        other => other,
    }
}

pub fn inspect_binary_layout(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    use tracewise_native::elf_layout::{inspect_elf, layout_summary_view};
    use tracewise_native::pe_resources::read_stable_artifact;
    const TOOL: &str = "inspect_binary_layout";
    const INPUT_BYTES: u64 = 32 * 1024 * 1024;
    let fields = [
        Field {
            name: "path",
            kind: Kind::Str { min: 1 },
            required: true,
        },
        Field {
            name: "detail",
            kind: Kind::Enum(&["complete", "summary"]),
            required: false,
        },
    ];
    if let Err(text) = validate(TOOL, args, &fields) {
        return Ok(error_text_result(text));
    }
    let path = args["path"].as_str().unwrap_or("");
    let summary = args.get("detail").and_then(Value::as_str) == Some("summary");
    if let Err(error) = require_absolute(TOOL, path) {
        return Ok(error_result(&error));
    }
    let (bytes, sha256) = match read_stable_artifact(Path::new(path), INPUT_BYTES, TOOL) {
        Ok(read) => read,
        Err(error) => return Ok(error_result(&read_failure(TOOL, path, error, "object"))),
    };
    let layout = match inspect_elf(&bytes) {
        Ok(layout) => layout,
        Err(failure) => {
            let error = match failure.reason {
                "unsupported-target" => NativeError::UnsupportedTarget {
                    operation: TOOL.to_string(),
                    path: path.to_string(),
                    reason: failure.message.clone(),
                    remediation: None,
                },
                _ => NativeError::Input {
                    operation: TOOL.to_string(),
                    issues: vec![tracewise_native::InputIssue {
                        path: vec![json!("path")],
                        reason: "invalid_format".to_string(),
                        message: Some(failure.message.clone()),
                        expected: None,
                    }],
                },
            };
            return Ok(error_result(&captured(error, &failure.stderr)));
        }
    };
    let mut report = layout.payload;
    if let Some(object) = report.as_object_mut() {
        object.insert(
            "artifact".into(),
            json!({"path": path, "sha256": sha256, "bytes": bytes.len()}),
        );
        object.insert(
            "diagnostics".into(),
            json!({"stdout": "", "stderr": layout.stderr, "truncated": false}),
        );
    }
    let limitations = strings_of(&report, "limitations");
    let subject = EvidenceSubject {
        name: path
            .rsplit('/')
            .next()
            .filter(|segment| !segment.is_empty())
            .unwrap_or("artifact")
            .to_string(),
        digest: DigestSha256 { sha256: sha256.clone() },
        format: "elf".to_string(),
        architecture: Some("x86_64".to_string()),
        local_path: path.to_string(),
    };
    let provider = EvidenceProvider {
        id: "tracewise-elf-layout".to_string(),
        name: "Tracewise native ELF layout adapter".to_string(),
        version: Some("1;pwntools@4.15.0-semantics".to_string()),
    };
    let evidence = create_evidence(
        Some(subject.clone()),
        provider,
        EvidenceObservation {
            predicate_type: Some("rea.analysis".to_string()),
            operation: TOOL.to_string(),
            parameters: json!({"path": path}),
            normalized_result: report.clone(),
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Observed),
            authority: Some(EvidenceAuthority::ShippedArtifact),
            environment: None,
            limitations: Some(limitations.clone()),
            locations: Some(vec![EvidenceLocation::ArtifactPath { path: path.to_string() }]),
            evidence_links: None,
        },
    )
    .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    if !summary {
        return remember_evidence(session, evidence);
    }
    // detail=summary: retain the complete Evidence and deliver its summary view.
    session
        .ledger
        .lock()
        .unwrap()
        .record(evidence.clone())
        .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    let mut view = layout_summary_view(&evidence.evidence_id, &limitations, &report);
    let digest = tracewise_domain::canonical_sha256(&view)
        .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    if let Some(object) = view.as_object_mut() {
        object.insert("view_digest".into(), json!(digest));
    }
    let view_limitations = strings_of(&view, "limitations");
    let view_evidence = create_evidence(
        Some(subject),
        EvidenceProvider {
            id: "rea-analysis-view".to_string(),
            name: "REA analysis view projection".to_string(),
            version: Some("1".to_string()),
        },
        EvidenceObservation {
            predicate_type: Some("rea.analysis-view".to_string()),
            operation: "inspect_analysis_view".to_string(),
            parameters: json!({"parent_evidence_id": evidence.evidence_id, "view": {"kind": "summary"}}),
            normalized_result: view,
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Derived),
            authority: Some(evidence.authority),
            environment: None,
            limitations: Some(view_limitations),
            locations: Some(vec![EvidenceLocation::ArtifactPath { path: path.to_string() }]),
            evidence_links: Some(vec![evidence.evidence_id.clone()]),
        },
    )
    .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    remember_evidence(session, view_evidence)
}

/// Node-shaped `fs.access` failure text (`ENOENT: no such file or directory, access '<path>'`).
fn access_failure(path: &str, mode: i32) -> Option<String> {
    use std::ffi::CString;
    let c_path = CString::new(path).ok()?;
    // SAFETY: `c_path` is a valid NUL-terminated string for the duration of the call.
    let result = unsafe { libc::access(c_path.as_ptr(), mode) };
    if result == 0 {
        return None;
    }
    let (code, text) = match std::io::Error::last_os_error().raw_os_error() {
        Some(2) => ("ENOENT", "no such file or directory"),
        Some(13) => ("EACCES", "permission denied"),
        Some(20) => ("ENOTDIR", "not a directory"),
        Some(1) => ("EPERM", "operation not permitted"),
        _ => ("EIO", "i/o error"),
    };
    Some(format!("{code}: {text}, access '{path}'"))
}

/// The `inspectPwndbgCore` configuration probe. The native port does not drive GDB, so a
/// configured debugger is reported as unsupported instead of being run.
fn debugger_context_unavailable(diagnostics: &Value) -> NativeError {
    let unavailable = |reason: String| NativeError::Captured {
        inner: Box::new(NativeError::Capability {
            provider_id: "pwndbg-core".to_string(),
            operation: "inspect_recorded_crash".to_string(),
            reason,
            user_message: true,
        }),
        output: diagnostics.clone(),
    };
    let probes: [(&str, String, &str); 3] = [
        (
            "REA_PWNDBG_GDB",
            std::env::var("REA_PWNDBG_GDB").unwrap_or_else(|_| "/usr/bin/gdb".to_string()),
            "file",
        ),
        (
            "REA_PWNDBG_GDBINIT",
            std::env::var("REA_PWNDBG_GDBINIT").unwrap_or_default(),
            "file",
        ),
        (
            "REA_PWNDBG_VENV_PATH",
            std::env::var("REA_PWNDBG_VENV_PATH").unwrap_or_default(),
            "directory",
        ),
    ];
    for (key, path, kind) in probes {
        let cause: Option<String> = if !Path::new(&path).is_absolute() {
            Some("Expected an absolute caller-supplied path.".to_string())
        } else if let Some(message) = access_failure(&path, if key == "REA_PWNDBG_GDB" { libc::X_OK } else { libc::R_OK }) {
            Some(message)
        } else {
            match std::fs::metadata(&path) {
                Ok(meta) if (kind == "file" && meta.is_file()) || (kind == "directory" && meta.is_dir()) => None,
                Ok(_) => Some(format!("Expected a {kind}.")),
                Err(error) => Some(error.to_string()),
            }
        };
        if let Some(cause) = cause {
            return unavailable(format!(
                "{key} is unavailable at {path}: {cause}. Configure the requested core-only context, or omit include_debugger_context for basic recorded evidence."
            ));
        }
    }
    unavailable(
        "Core-only GDB/pwndbg mapping candidates are not provided by the native Rust port. Omit include_debugger_context for the complete recorded evidence."
            .to_string(),
    )
}

pub fn inspect_recorded_crash(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    use tracewise_native::core_dump::inspect_core;
    use tracewise_native::pe_resources::read_stable_artifact;
    const TOOL: &str = "inspect_recorded_crash";
    const INPUT_BYTES: u64 = 32 * 1024 * 1024;
    let fields = [
        Field {
            name: "path",
            kind: Kind::Str { min: 1 },
            required: true,
        },
        Field {
            name: "include_debugger_context",
            kind: Kind::Bool,
            required: false,
        },
    ];
    if let Err(text) = validate(TOOL, args, &fields) {
        return Ok(error_text_result(text));
    }
    let path = args["path"].as_str().unwrap_or("");
    let include_debugger = args
        .get("include_debugger_context")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if let Err(error) = require_absolute(TOOL, path) {
        return Ok(error_result(&error));
    }
    let (bytes, sha256) = match read_stable_artifact(Path::new(path), INPUT_BYTES, TOOL) {
        Ok(read) => read,
        Err(error) => return Ok(error_result(&read_failure(TOOL, path, error, "object"))),
    };
    let report = match inspect_core(&bytes) {
        Ok(report) => report,
        Err(failure) => {
            let error = if failure.reason == "unsupported-target" {
                NativeError::UnsupportedTarget {
                    operation: TOOL.to_string(),
                    path: path.to_string(),
                    reason: failure.message.clone(),
                    remediation: None,
                }
            } else {
                NativeError::Input {
                    operation: TOOL.to_string(),
                    issues: vec![tracewise_native::InputIssue {
                        path: vec![json!("path")],
                        reason: "invalid_format".to_string(),
                        message: Some(failure.message.clone()),
                        expected: None,
                    }],
                }
            };
            return Ok(error_result(&captured(error, "")));
        }
    };
    let diagnostics = json!({"stdout": "", "stderr": "", "truncated": false});
    if include_debugger {
        return Ok(error_result(&debugger_context_unavailable(&diagnostics)));
    }
    let mut value = report.payload;
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "artifact".into(),
            json!({"path": path, "sha256": sha256, "bytes": bytes.len()}),
        );
        object.insert("debugger".into(), json!({"status": "not-requested"}));
        object.insert("decoder_diagnostics".into(), diagnostics.clone());
        object.insert("diagnostics".into(), diagnostics);
    }
    let limitations = strings_of(&value, "limitations");
    let subject = EvidenceSubject {
        name: path
            .rsplit('/')
            .next()
            .filter(|segment| !segment.is_empty())
            .unwrap_or("artifact")
            .to_string(),
        digest: DigestSha256 { sha256 },
        format: "elf".to_string(),
        architecture: Some("x86_64".to_string()),
        local_path: path.to_string(),
    };
    record(
        session,
        subject,
        EvidenceProvider {
            id: "tracewise-elf-core".to_string(),
            name: "Tracewise native ELF core adapter".to_string(),
            version: Some("1;pwntools@4.15.0-semantics".to_string()),
        },
        TOOL,
        json!({"path": path, "include_debugger_context": include_debugger}),
        value,
        None,
        EvidenceConfidence::Observed,
        limitations,
        vec![EvidenceLocation::ArtifactPath { path: path.to_string() }],
    )
}
