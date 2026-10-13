//! `inspect_managed_artifact`, `inspect_managed_members` and
//! `inspect_managed_native_boundaries` (REA `registerManagedTools`).

use rmcp::model::CallToolResult;
use rmcp::ErrorData as McpError;
use serde_json::{json, Value};
use tracewise_domain::evidence::{
    create_evidence, EvidenceAuthority, EvidenceConfidence, EvidenceLocation, EvidenceObservation, EvidenceProvider,
    EvidenceSubject,
};
use tracewise_managed::target::resolve_target_bounded;
use tracewise_managed::ManagedTarget;

use super::support::{
    capability_unavailable, execution_failure, rea_error, input_validation_error, missing_argument, select, selected,
    target_unavailable, validate_path_only,
};
use crate::handlers::remember_evidence;
use crate::session::BinarySession;

pub const PROVIDER_ID: &str = "rea-dotnet-static";
const SELECTED_SLOT: &str = "managed.selected_path";

pub fn provider() -> EvidenceProvider {
    EvidenceProvider {
        id: PROVIDER_ID.to_string(),
        name: "REA managed static analysis provider".to_string(),
        version: Some("1".to_string()),
    }
}

/// REA refuses snapshots above 128 MiB (the provider keeps the PE in memory).
const MAX_SNAPSHOT_BYTES: u64 = tracewise_managed::target::DEFAULT_RETAIN_LIMIT;

/// `resource_constraint` REA answers when the PE exceeds its snapshot budget.
fn snapshot_over_budget(tool: &str) -> CallToolResult {
    const REASON: &str = "Managed static inspection requires an eagerly retained PE snapshot within its input byte budget.";
    rea_error(
        "resource_constraint",
        "resource_constraint",
        REASON,
        false,
        "Review the reported worker memory limits and available host memory. Retry with sufficient memory or a smaller artifact; REA retains tighter inherited limits.",
        json!({
            "operation": tool,
            "resource": "memory",
            "reason": REASON,
            "reported_limits": { "max_snapshot_bytes": MAX_SNAPSHOT_BYTES },
        }),
    )
}

fn locations(tool: &str, result: &Value) -> Vec<EvidenceLocation> {
    let offset = |value: &Value| value.as_u64().map(|offset| EvidenceLocation::FileOffset { offset });
    match tool {
        "inspect_managed_artifact" => {
            let cli = &result["pe"]["cli"];
            if cli.is_null() {
                return vec![EvidenceLocation::FileOffset { offset: 0 }];
            }
            let start = cli["header_offset"].as_u64().unwrap_or(0);
            let size = cli["header_size"].as_u64().unwrap_or(0);
            let mut out = vec![EvidenceLocation::FileOffsetRange { start, end: start + size }];
            for key in ["module", "assembly"] {
                if let Some(location) = offset(&result[key]["row_offset"]) {
                    out.push(location);
                }
            }
            out
        }
        "inspect_managed_members" => {
            let mut out = vec![offset(&result["module"]["row_offset"]).unwrap_or(EvidenceLocation::FileOffset { offset: 0 })];
            if let Some(methods) = result["methods"].as_array() {
                for method in methods {
                    if let Some(location) = offset(&method["body"]["file_offset"]) {
                        out.push(location);
                    }
                }
            }
            out
        }
        _ => {
            let mut out = vec![offset(&result["module"]["row_offset"]).unwrap_or(EvidenceLocation::FileOffset { offset: 0 })];
            if let Some(imports) = result["pinvoke_imports"].as_array() {
                for import in imports {
                    if let Some(location) = offset(&import["row_offset"]) {
                        out.push(location);
                    }
                }
            }
            out
        }
    }
}

/// What the blocking half of a managed inspection produced.
enum Inspected {
    Unreadable(tracewise_managed::target::ResolveError),
    NotPe(String),
    OverBudget,
    Failed,
    Done { path: String, sha256: String, architecture: Option<String>, result: Value },
}

pub async fn handle(session: &BinarySession, tool: &str, args: &Value) -> Result<CallToolResult, McpError> {
    let requested = match validate_path_only(args) {
        Ok(path) => path,
        Err(issues) => return Ok(input_validation_error(tool, &issues)),
    };
    let path = requested.clone().or_else(|| selected(session, SELECTED_SLOT)).or_else(|| {
        session
            .active_target
            .lock()
            .unwrap()
            .as_ref()
            .filter(|target| target.format == "pe")
            .map(|target| target.local_path.clone())
    });
    let Some(path) = path else {
        return Ok(missing_argument(
            tool,
            "path",
            "Provide a managed PE/CLI path or first select one with inspect_managed_artifact.",
        ));
    };
    // File reads and the PE parse run off the async runtime.
    let operation = tool.to_string();
    let worker_path = path.clone();
    let inspected = tokio::task::spawn_blocking(move || {
        let resolved = match resolve_target_bounded(&worker_path, MAX_SNAPSHOT_BYTES) {
            Ok(resolved) => resolved,
            Err(error) => return Inspected::Unreadable(error),
        };
        if resolved.format != "pe" {
            return Inspected::NotPe(resolved.format);
        }
        if resolved.size > MAX_SNAPSHOT_BYTES {
            return Inspected::OverBudget;
        }
        let target = ManagedTarget { path: resolved.path.clone(), sha256: resolved.sha256.clone() };
        let inspected = match operation.as_str() {
            "inspect_managed_artifact" => tracewise_managed::inspect_managed_artifact_bytes(&resolved.bytes, &target),
            "inspect_managed_members" => tracewise_managed::inspect_managed_members_bytes(&resolved.bytes, &target),
            _ => tracewise_managed::inspect_managed_native_boundaries_bytes(&resolved.bytes, &target),
        };
        match inspected {
            Ok(result) => Inspected::Done { path: resolved.path, sha256: resolved.sha256, architecture: resolved.architecture, result },
            Err(_) => Inspected::Failed,
        }
    })
    .await
    .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    let (resolved_path, resolved_sha256, resolved_architecture, result) = match inspected {
        Inspected::Unreadable(error) => return Ok(target_unavailable(&error.path, &error.reason, error.constraint)),
        Inspected::NotPe(format) => {
            return Ok(capability_unavailable(
                PROVIDER_ID,
                tool,
                &format!("Managed static triage requires a PE target; observed {format}."),
            ))
        }
        Inspected::OverBudget => return Ok(snapshot_over_budget(tool)),
        Inspected::Failed => return Ok(execution_failure(PROVIDER_ID, tool)),
        Inspected::Done { path, sha256, architecture, result } => (path, sha256, architecture, result),
    };
    if let Some(requested) = requested {
        select(session, SELECTED_SLOT, requested);
    }
    let name = std::path::Path::new(&resolved_path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| resolved_path.clone());
    let subject = EvidenceSubject {
        name,
        digest: tracewise_domain::evidence::DigestSha256 { sha256: resolved_sha256 },
        format: "pe".to_string(),
        architecture: resolved_architecture,
        local_path: resolved_path,
    };
    let limitations: Vec<String> = result["limitations"]
        .as_array()
        .map(|items| items.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let parameters = match requested_param(args) {
        Some(value) => value,
        None => json!({}),
    };
    let evidence = create_evidence(
        Some(subject),
        provider(),
        EvidenceObservation {
            predicate_type: Some("rea.analysis".to_string()),
            operation: tool.to_string(),
            parameters,
            normalized_result: result.clone(),
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Observed),
            authority: Some(EvidenceAuthority::ShippedArtifact),
            environment: None,
            limitations: Some(limitations),
            locations: Some(locations(tool, &result)),
            evidence_links: Some(Vec::new()),
        },
    )
    .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    remember_evidence(session, evidence)
}

fn requested_param(args: &Value) -> Option<Value> {
    args.get("path").map(|path| json!({ "path": path }))
}
