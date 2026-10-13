//! Shared plumbing for the native static tools: active target resolution,
//! Evidence construction and REA-shaped error results.

use std::path::{Path, PathBuf};

use rmcp::model::{CallToolResult, Content};
use rmcp::ErrorData as McpError;
use serde_json::Value;
use tracewise_domain::evidence::{
    create_evidence, EvidenceAuthority, EvidenceConfidence, EvidenceLocation, EvidenceObservation,
    EvidenceProvider, EvidenceSubject,
};
use tracewise_native::NativeError;

use crate::format::mach_o_architecture;
use crate::handlers::remember_evidence;
use crate::session::BinarySession;

/// `ARTIFACT_GRAPH_PROVIDER` of REA (`application/InvestigationProviders.ts`).
pub fn artifact_graph_provider() -> EvidenceProvider {
    EvidenceProvider {
        id: "rea-artifact-graph".to_string(),
        name: "REA safe artifact graph provider".to_string(),
        version: Some("1".to_string()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Executable,
    Artifact,
}

/// The active target as REA's `BinaryTarget` describes it.
#[derive(Debug, Clone)]
pub struct ActiveTarget {
    pub subject: EvidenceSubject,
    pub kind: TargetKind,
    /// Canonical app bundle directory when the target was opened from a bundle.
    pub bundle: Option<PathBuf>,
    /// Whether the target carries a bundle `Info.plist` (opened from an app directory).
    pub bundle_info_plist: Option<PathBuf>,
}

impl ActiveTarget {
    pub fn path(&self) -> &str {
        &self.subject.local_path
    }

    pub fn format(&self) -> &str {
        &self.subject.format
    }
}

/// Text payload result flagged as an error (REA delivers errors as text content).
pub fn error_text_result(text: String) -> CallToolResult {
    CallToolResult::error(vec![Content::text(text)])
}

pub fn error_result(error: &NativeError) -> CallToolResult {
    error_text_result(error.to_body().to_string())
}

fn head_of(path: &Path, length: usize) -> Vec<u8> {
    use std::io::Read;
    let Ok(mut file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let mut buffer = vec![0u8; length];
    let mut filled = 0usize;
    while filled < length {
        match file.read(&mut buffer[filled..]) {
            Ok(0) | Err(_) => break,
            Ok(count) => filled += count,
        }
    }
    buffer.truncate(filled);
    buffer
}

fn looks_like_plist(head: &[u8]) -> bool {
    if head.starts_with(b"bplist") {
        return true;
    }
    let text = String::from_utf8_lossy(head);
    let trimmed = text.trim_start_matches('\u{feff}').trim_start();
    trimmed.starts_with("<?xml") || trimmed.starts_with("<plist") || trimmed.starts_with("<!DOCTYPE plist")
}

/// Resolve the session's active target the way REA's `BinaryTarget` would describe it.
pub fn active_target(session: &BinarySession) -> Result<ActiveTarget, NativeError> {
    let subject = session
        .active_target
        .lock()
        .unwrap()
        .clone()
        .ok_or(NativeError::NoBinaryOpen)?;
    let path = PathBuf::from(&subject.local_path);
    // An app bundle was resolved by `open_binary`: the subject already is its program file.
    if let Some(source) = session.source_bundle.lock().unwrap().clone() {
        return Ok(ActiveTarget {
            subject,
            kind: TargetKind::Executable,
            bundle: Some(source.bundle),
            bundle_info_plist: Some(source.info_plist),
        });
    }
    let mut subject = subject;
    let head = head_of(&path, 64);
    let kind = if tracewise_native::macho_dyld::has_macho_magic(&head) {
        subject.format = "mach-o".to_string();
        subject.architecture = mach_o_architecture(&path);
        TargetKind::Executable
    } else if looks_like_plist(&head) {
        subject.format = "plist".to_string();
        subject.architecture = None;
        TargetKind::Artifact
    } else {
        match subject.format.as_str() {
            "elf" | "pe" | "dos-mz" | "dos-com" | "hopper" => TargetKind::Executable,
            _ => TargetKind::Artifact,
        }
    };
    Ok(ActiveTarget {
        subject,
        kind,
        bundle: None,
        bundle_info_plist: None,
    })
}

pub fn artifact_path_locations(paths: impl IntoIterator<Item = String>) -> Vec<EvidenceLocation> {
    paths
        .into_iter()
        .map(|path| EvidenceLocation::ArtifactPath { path })
        .collect()
}

/// Record a native observation in the session ledger and return it as structured content.
pub fn evidence_result(
    session: &BinarySession,
    subject: Option<EvidenceSubject>,
    provider: EvidenceProvider,
    operation: &str,
    parameters: Value,
    normalized_result: Value,
    limitations: Vec<String>,
    locations: Vec<EvidenceLocation>,
) -> Result<CallToolResult, McpError> {
    let evidence = create_evidence(
        subject,
        provider,
        EvidenceObservation {
            predicate_type: Some("rea.analysis".to_string()),
            operation: operation.to_string(),
            parameters,
            normalized_result,
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Observed),
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

pub fn strings_of(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}
