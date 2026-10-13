//! The four managed-code workflow tools (REA `registerManagedWorkflowTools`):
//! `compare_managed_members`, `verify_managed_native_boundaries`,
//! `import_managed_reconstruction` and `project_managed_application_graph`.

#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::sync::OnceLock;

use rmcp::model::CallToolResult;
use rmcp::ErrorData as McpError;
use serde_json::{json, Value};
use tracewise_domain::evidence::{
    create_evidence, DigestSha256, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation, EvidenceProvider,
    EvidenceSubject,
};
use tracewise_domain::unknown::RecordUnknownInput;
use tracewise_managed::workflows::{self, WorkflowError};

use super::support::{input_validation_error, js_type_name, rea_error};
use crate::session::BinarySession;

const NO_SUBJECT_LIMITATION: &str = "Artifact identity is unavailable for this observation.";

pub fn workflow_provider() -> EvidenceProvider {
    EvidenceProvider {
        id: "rea-dotnet-workflows".to_string(),
        name: "REA managed-code workflows".to_string(),
        version: Some("1".to_string()),
    }
}

fn registry_provider() -> EvidenceProvider {
    EvidenceProvider {
        id: "rea-unknown-registry".to_string(),
        name: "REA residual unknown registry".to_string(),
        version: Some("1".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Request validation (the MCP SDK's zod pass)
// ---------------------------------------------------------------------------

fn validators() -> &'static HashMap<String, jsonschema::Validator> {
    static VALIDATORS: OnceLock<HashMap<String, jsonschema::Validator>> = OnceLock::new();
    VALIDATORS.get_or_init(|| {
        let catalog: Value = serde_json::from_str(tracewise_contracts::PHASE3_TOOLS_JSON).expect("phase 3 catalog");
        let mut map = HashMap::new();
        for tool in catalog["tools"].as_array().into_iter().flatten() {
            let name = tool["name"].as_str().unwrap_or_default().to_string();
            let validator = jsonschema::validator_for(&tool["inputSchema"])
                .unwrap_or_else(|error| panic!("input schema of {name} does not compile: {error}"));
            map.insert(name, validator);
        }
        map
    })
}

/// The JSON type the catalog declares for one top-level property.
fn declared_type(tool: &str, property: &str) -> Option<String> {
    static SCHEMAS: OnceLock<HashMap<String, Value>> = OnceLock::new();
    let schemas = SCHEMAS.get_or_init(|| {
        let catalog: Value = serde_json::from_str(tracewise_contracts::PHASE3_TOOLS_JSON).expect("phase 3 catalog");
        catalog["tools"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|t| (t["name"].as_str().unwrap_or_default().to_string(), t["inputSchema"].clone()))
            .collect()
    });
    let schema = schemas.get(tool)?;
    let mut node = schema["properties"].get(property)?.clone();
    for _ in 0..8 {
        if let Some(reference) = node.get("$ref").and_then(Value::as_str) {
            node = schema.pointer(reference.trim_start_matches('#'))?.clone();
        } else {
            break;
        }
    }
    let kind = node.get("type")?.as_str()?;
    Some(if kind == "integer" { "int".to_string() } else { kind.to_string() })
}

fn dotted(path: &str) -> String {
    path.trim_start_matches('/').replace('/', ".")
}

fn expected_type_for(property: &str) -> &'static str {
    match property {
        "native_observations" | "methods" | "notes" => "array",
        "path" | "name" | "family" | "text" | "kind" | "language" | "token" | "class_name" | "method_name" | "query" => "string",
        _ => "object",
    }
}

/// Schema violations rendered like zod's issue list.
pub fn schema_issues(tool: &str, args: &Value) -> Vec<String> {
    // A tool of this track without a compiled input schema is a bug in the catalog wiring.
    let validator = validators().get(tool).unwrap_or_else(|| panic!("no input validator for tool {tool}"));
    let mut issues = Vec::new();
    for error in validator.iter_errors(args) {
        let path = dotted(&error.instance_path().to_string());
        let prefix = |message: String| if path.is_empty() { message } else { format!("{path}: {message}") };
        use jsonschema::error::ValidationErrorKind as Kind;
        match error.kind() {
            Kind::AdditionalProperties { unexpected } => {
                for key in unexpected {
                    issues.push(prefix(format!("Unrecognized key: \"{key}\"")));
                }
            }
            Kind::Required { property } => {
                let name = property.as_str().unwrap_or_default().to_string();
                let full = if path.is_empty() { name.clone() } else { format!("{path}.{name}") };
                let expected = if path.is_empty() {
                    declared_type(tool, &name).unwrap_or_else(|| expected_type_for(&name).to_string())
                } else {
                    expected_type_for(&name).to_string()
                };
                issues.push(format!("{full}: Invalid input: expected {expected}, received undefined"));
            }
            Kind::MinProperties { .. } => issues.push(prefix("Invalid input".to_string())),
            Kind::MinItems { limit } => issues.push(prefix(format!("Too small: expected array to have >={limit} items"))),
            Kind::MinLength { limit } => issues.push(prefix(format!("Too small: expected string to have >={limit} characters"))),
            Kind::Minimum { limit } => issues.push(prefix(format!("Too small: expected number to be >={limit}"))),
            Kind::Maximum { limit } => issues.push(prefix(format!("Too big: expected number to be <={limit}"))),
            Kind::MaxLength { limit } => issues.push(prefix(format!("Too big: expected string to have <={limit} characters"))),
            Kind::Enum { options } => {
                let rendered: Vec<String> = options.as_array().into_iter().flatten().map(|o| o.to_string()).collect();
                issues.push(prefix(format!("Invalid option: expected one of {}", rendered.join("|"))));
            }
            Kind::Pattern { .. } if tool == "decode_android_resources" => {
                issues.push(prefix("Locale must look like de, pt-BR, pt-rBR, or b+zh+Hans+CN".to_string()))
            }
            Kind::Type { .. } => issues.push(prefix(format!(
                "Invalid input: expected {}, received {}",
                match error.to_string().split(" is not of type ").nth(1).unwrap_or("value").trim_matches('"') {
                    "integer" => "int".to_string(),
                    other => other.to_string(),
                },
                js_type_name(error.instance())
            ))),
            _ => issues.push(prefix(error.to_string())),
        }
    }
    issues
}

// ---------------------------------------------------------------------------
// Evidence resolution (REA `registerManagedWorkflowTools/evidence.ts`)
// ---------------------------------------------------------------------------

fn integrity_error(reason: &str) -> CallToolResult {
    rea_error(
        "evidence_integrity_mismatch",
        "integrity_mismatch",
        "Evidence is invalid or has changed. Recreate or re-import it, then try again.",
        false,
        "Evidence is invalid or has changed. Recreate or re-import it, then try again.",
        json!({ "reason": reason }),
    )
}

fn input_error_result(operation: &str, message: &str) -> CallToolResult {
    rea_error(
        "invalid_request",
        "invalid_input",
        "Analysis input is invalid. Check the arguments and try again.",
        true,
        "Correct the listed arguments and retry.",
        json!({
            "operation": operation,
            "issues": [{ "path": [], "reason": "invalid_value", "message": message }],
        }),
    )
}

fn workflow_failure(operation: &str, error: WorkflowError) -> CallToolResult {
    match error {
        WorkflowError::Input(message) => input_error_result(operation, &message),
        WorkflowError::Protocol(_) => rea_error(
            "protocol_error",
            "execution_failure",
            "Analysis could not complete. Retry once; if it continues, run `rea doctor`.",
            false,
            "Analysis could not complete. Retry once; if it continues, run `rea doctor`.",
            json!({ "operation": operation }),
        ),
    }
}

/// `parseExpectedEvidence` for one record.
fn resolve_evidence(raw: &Value, expected: &[&str]) -> Result<Evidence, CallToolResult> {
    let evidence: Evidence = serde_json::from_value(raw.clone()).map_err(|error| integrity_error(&error.to_string()))?;
    if let Err(error) = evidence.verify() {
        let reason = match error {
            tracewise_domain::error::EvidenceError::TamperedId { .. } => serde_json::to_string_pretty(&json!([{
                "code": "custom",
                "path": ["evidence_id"],
                "message": "Evidence semantic identifier does not match its record",
            }]))
            .unwrap_or_default(),
            other => other.to_string(),
        };
        return Err(integrity_error(&reason));
    }
    if !expected.contains(&evidence.operation.as_str()) || evidence.predicate_type != "rea.analysis" {
        return Err(integrity_error(&format!(
            "Expected {} Evidence, received {}",
            expected.join(" or "),
            evidence.operation
        )));
    }
    Ok(evidence)
}

// ---------------------------------------------------------------------------
// Result recording
// ---------------------------------------------------------------------------

fn record_sources(session: &BinarySession, sources: &[Evidence]) {
    let mut ledger = session.ledger.lock().unwrap();
    for source in sources {
        let _ = ledger.record(source.clone());
    }
}

fn finish(session: &BinarySession, evidence: Evidence, unknown: Option<Value>) -> Result<CallToolResult, McpError> {
    if let Some(unknown) = unknown {
        let input: RecordUnknownInput = serde_json::from_value(unknown.clone())
            .map_err(|error| McpError::internal_error(error.to_string(), None))?;
        let mut links: Vec<String> = Vec::new();
        for id in input.supporting_evidence_ids.iter().chain(input.contradicting_evidence_ids.iter()) {
            if !links.contains(id) {
                links.push(id.clone());
            }
        }
        let mutation = create_evidence(
            None,
            registry_provider(),
            EvidenceObservation {
                predicate_type: Some("rea.residual-unknown-mutation".to_string()),
                operation: "record_unknown".to_string(),
                parameters: json!({ "domain": input.domain, "severity": unknown["severity"] }),
                normalized_result: json!({
                    "action": "record",
                    "question": input.question,
                    "required_authority": unknown["required_authority"],
                    "required_confidence": unknown["required_confidence"],
                }),
                raw_result: None,
                analysis_profile: None,
                confidence: Some(EvidenceConfidence::Derived),
                authority: Some(EvidenceAuthority::AnalystInference),
                environment: None,
                limitations: Some(vec![
                    NO_SUBJECT_LIMITATION.to_string(),
                    "Registry mutation evidence records analyst intent, not proof of the answer.".to_string(),
                ]),
                locations: None,
                evidence_links: Some(links),
            },
        )
        .map_err(|error| McpError::internal_error(error.to_string(), None))?;
        let mut ledger = session.ledger.lock().unwrap();
        match ledger.record_unknown(&input, mutation) {
            Ok(_) => {}
            Err(error) => {
                let text = error.to_string();
                if text.contains("already exists") {
                    return Ok(rea_error(
                        "revision_conflict",
                        "execution_failure",
                        "Evidence state changed before the update completed. Refresh the current state and try again.",
                        true,
                        "Evidence state changed before the update completed. Refresh the current state and try again.",
                        json!({ "reason": "already-exists" }),
                    ));
                }
                return Err(McpError::internal_error(text, None));
            }
        }
        ledger.record(evidence.clone()).map_err(|error| McpError::internal_error(error.to_string(), None))?;
    } else {
        session
            .ledger
            .lock()
            .unwrap()
            .record(evidence.clone())
            .map_err(|error| McpError::internal_error(error.to_string(), None))?;
    }
    let value = serde_json::to_value(&evidence).map_err(|error| McpError::internal_error(error.to_string(), None))?;
    Ok(CallToolResult::structured(value))
}

fn strings(value: &Value) -> Vec<String> {
    value.as_array().map(|items| items.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default()
}

#[allow(clippy::too_many_arguments)]
fn derived_evidence(
    subject: Option<EvidenceSubject>,
    predicate: &str,
    operation: &str,
    parameters: Value,
    result: &Value,
    locations: Vec<tracewise_domain::evidence::EvidenceLocation>,
) -> Result<Evidence, McpError> {
    let mut limitations = Vec::new();
    if subject.is_none() {
        limitations.push(NO_SUBJECT_LIMITATION.to_string());
    }
    limitations.extend(strings(&result["limitations"]));
    create_evidence(
        subject,
        workflow_provider(),
        EvidenceObservation {
            predicate_type: Some(predicate.to_string()),
            operation: operation.to_string(),
            parameters,
            normalized_result: result.clone(),
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Inferred),
            authority: Some(EvidenceAuthority::AnalystInference),
            environment: None,
            limitations: Some(limitations),
            locations: Some(locations),
            evidence_links: Some(strings(&result["evidence_links"])),
        },
    )
    .map_err(|error| McpError::internal_error(error.to_string(), None))
}

fn subject_from_path(path: &str, sha256: &str, architecture: Option<String>) -> EvidenceSubject {
    let name = path.rsplit('/').next().filter(|n| !n.is_empty()).unwrap_or("artifact").to_string();
    EvidenceSubject {
        name,
        digest: DigestSha256 { sha256: sha256.to_string() },
        format: "pe".to_string(),
        architecture,
        local_path: path.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

pub fn handle(session: &BinarySession, tool: &str, args: &Value) -> Result<CallToolResult, McpError> {
    let mut issues = schema_issues(tool, args);
    if issues.is_empty() {
        issues = refinement_issues(tool, args);
    }
    if !issues.is_empty() {
        return Ok(input_validation_error(tool, &issues));
    }
    match tool {
        "compare_managed_members" => compare(session, args),
        "verify_managed_native_boundaries" => verify(session, args),
        "import_managed_reconstruction" => import(session, args),
        _ => graph(session, args),
    }
}

/// Cross-field `superRefine` checks of the request schemas.
fn refinement_issues(tool: &str, args: &Value) -> Vec<String> {
    let id = |value: &Value| value["evidence_id"].as_str().unwrap_or_default().to_string();
    match tool {
        "compare_managed_members" if id(&args["left"]) == id(&args["right"]) => {
            vec!["right: Managed member Evidence must be distinct".to_string()]
        }
        "verify_managed_native_boundaries" => {
            let managed = id(&args["managed_boundaries"]);
            let mut issues = Vec::new();
            let mut seen: Vec<String> = Vec::new();
            for (index, native) in args["native_observations"].as_array().into_iter().flatten().enumerate() {
                let native_id = id(native);
                if native_id == managed {
                    issues.push(format!(
                        "native_observations.{index}: Native observation Evidence must be distinct from managed boundary Evidence"
                    ));
                    issues.push(format!("native_observations.{index}: Native observation Evidence IDs must be unique"));
                } else if seen.contains(&native_id) {
                    issues.push(format!("native_observations.{index}: Native observation Evidence IDs must be unique"));
                }
                seen.push(native_id);
            }
            issues
        }
        "project_managed_application_graph"
            if args.get("managed_artifact").is_none()
                && args.get("managed_members").is_none()
                && args.get("managed_native_boundaries").is_none() =>
        {
            vec!["Invalid input".to_string()]
        }
        _ => vec![],
    }
}

fn compare(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    let operation = "compare_managed_members";
    let left = match resolve_evidence(&args["left"], &["inspect_managed_members"]) {
        Ok(evidence) => evidence,
        Err(error) => return Ok(error),
    };
    let right = match resolve_evidence(&args["right"], &["inspect_managed_members"]) {
        Ok(evidence) => evidence,
        Err(error) => return Ok(error),
    };
    if let Some(error) = nested_schema_error(operation, "inspect_managed_members", &[&left, &right]) {
        return Ok(error);
    }
    let result = match workflows::compare::compare_evidence(&args["left"], &args["right"]) {
        Ok(result) => result,
        Err(error) => return Ok(workflow_failure(operation, error)),
    };
    let evidence = derived_evidence(
        None,
        "rea.managed-member-comparison",
        operation,
        json!({ "left_evidence_id": left.evidence_id, "right_evidence_id": right.evidence_id }),
        &result,
        vec![],
    )?;
    record_sources(session, &[left, right]);
    let unknown = (result["summary"]["unknown"].as_u64().unwrap_or(0) > 0).then(|| {
        json!({
            "question": "Which managed members remain unmatched or ambiguous across these versions?",
            "severity": "medium",
            "domain": "managed-member-comparison",
            "supporting_evidence_ids": [evidence.evidence_id],
            "contradicting_evidence_ids": [],
            "required_authority": "shipped-artifact",
            "required_confidence": "observed",
            "required_environment": null,
            "recommended_probes": [{
                "operation": "inspect_managed_members",
                "rationale": "Review the inspection Evidence coverage and limit diagnostics; this operation has no page override, so unresolved members must remain unknown.",
            }],
            "relationships": [],
        })
    });
    finish(session, evidence, unknown)
}

fn verify(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    let operation = "verify_managed_native_boundaries";
    let managed = match resolve_evidence(&args["managed_boundaries"], &["inspect_managed_native_boundaries"]) {
        Ok(evidence) => evidence,
        Err(error) => return Ok(error),
    };
    let mut natives = Vec::new();
    for raw in args["native_observations"].as_array().into_iter().flatten() {
        match resolve_evidence(raw, &["inspect_macho", "analyze_function"]) {
            Ok(evidence) => natives.push(evidence),
            Err(error) => return Ok(error),
        }
    }
    if let Some(error) = nested_schema_error(operation, "inspect_managed_native_boundaries", &[&managed]) {
        return Ok(error);
    }
    let native_values: Vec<Value> = args["native_observations"].as_array().cloned().unwrap_or_default();
    let result = match workflows::verify::verify_managed_native_boundaries(&args["managed_boundaries"], &native_values) {
        Ok(result) => result,
        Err(error) => return Ok(workflow_failure(operation, error)),
    };
    let native_ids: Vec<String> = natives.iter().map(|n| n.evidence_id.clone()).collect();
    let evidence = derived_evidence(
        None,
        "rea.managed-native-verification",
        operation,
        json!({ "managed_boundaries_evidence_id": managed.evidence_id, "native_evidence_ids": native_ids }),
        &result,
        vec![],
    )?;
    let mut sources = vec![managed];
    sources.extend(natives);
    record_sources(session, &sources);
    let summary = &result["summary"];
    let unresolved = summary["unresolved"].as_u64().unwrap_or(0) > 0
        || summary["contradicted"].as_u64().unwrap_or(0) > 0
        || summary["native_body_unresolved"].as_u64().unwrap_or(0) > 0;
    let unknown = unresolved.then(|| {
        json!({
            "question": "Which managed/native boundaries remain unresolved or contradicted by the supplied native Evidence?",
            "severity": "medium",
            "domain": "managed-native-verification",
            "supporting_evidence_ids": [evidence.evidence_id],
            "contradicting_evidence_ids": [],
            "required_authority": "shipped-artifact",
            "required_confidence": "observed",
            "required_environment": null,
            "recommended_probes": [
                {
                    "operation": "inspect_managed_native_boundaries",
                    "rationale": "Review the inspection Evidence coverage and limit diagnostics; this operation has no page override, so unresolved declarations must remain unknown.",
                },
                {
                    "operation": "analyze_function",
                    "rationale": "Analyze the provider-resolved native function candidate for the declared export.",
                },
            ],
            "relationships": [],
        })
    });
    finish(session, evidence, unknown)
}

fn import(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    let operation = "import_managed_reconstruction";
    let static_members = match resolve_evidence(&args["static_members"], &["inspect_managed_members"]) {
        Ok(evidence) => evidence,
        Err(error) => return Ok(error),
    };
    if let Some(error) = nested_schema_error(operation, "inspect_managed_members", &[&static_members]) {
        return Ok(error);
    }
    let result = match workflows::reconstruction::import_managed_reconstruction(args) {
        Ok(result) => result,
        Err(error) => return Ok(workflow_failure(operation, error)),
    };
    let normalized = workflows::reconstruction::normalize_input(args);
    let locks: Vec<Value> = normalized["methods"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|m| {
            json!({
                "token": m["token"],
                "signature_sha256": m["signature_sha256"],
                "normalized_il_sha256": m["normalized_il_sha256"],
            })
        })
        .collect();
    let observation = &result["static_observation"];
    let subject = subject_from_path(
        observation["artifact_path"].as_str().unwrap_or_default(),
        observation["artifact_sha256"].as_str().unwrap_or_default(),
        None,
    );
    let evidence = derived_evidence(
        Some(subject),
        "rea.managed-reconstruction-import",
        operation,
        json!({
            "static_members_evidence_id": static_members.evidence_id,
            "decompiler": result["decompiler"],
            "method_locks": locks,
            "notes": normalized["notes"],
        }),
        &result,
        vec![tracewise_domain::evidence::EvidenceLocation::ArtifactPath {
            path: observation["artifact_path"].as_str().unwrap_or_default().to_string(),
        }],
    )?;
    record_sources(session, &[static_members]);
    finish(session, evidence, None)
}

fn graph(session: &BinarySession, args: &Value) -> Result<CallToolResult, McpError> {
    let operation = "project_managed_application_graph";
    let mut resolved: Vec<Evidence> = Vec::new();
    let get = |key: &str, op: &str| -> Result<Option<Evidence>, CallToolResult> {
        match args.get(key) {
            None => Ok(None),
            Some(raw) => resolve_evidence(raw, &[op]).map(Some),
        }
    };
    let artifact = match get("managed_artifact", "inspect_managed_artifact") {
        Ok(v) => v,
        Err(e) => return Ok(e),
    };
    let members = match get("managed_members", "inspect_managed_members") {
        Ok(v) => v,
        Err(e) => return Ok(e),
    };
    let boundaries = match get("managed_native_boundaries", "inspect_managed_native_boundaries") {
        Ok(v) => v,
        Err(e) => return Ok(e),
    };
    for (evidence, op) in [
        (&artifact, "inspect_managed_artifact"),
        (&members, "inspect_managed_members"),
        (&boundaries, "inspect_managed_native_boundaries"),
    ] {
        if let Some(evidence) = evidence {
            if let Some(error) = nested_schema_error(operation, op, &[evidence]) {
                return Ok(error);
            }
            resolved.push(evidence.clone());
        }
    }
    let result = match tracewise_managed::graph::project_managed_application_graph(
        args.get("managed_artifact"),
        args.get("managed_members"),
        args.get("managed_native_boundaries"),
    ) {
        Ok(result) => result,
        Err(error) => return Ok(workflow_failure(operation, error)),
    };
    let subject = [&artifact, &members, &boundaries]
        .into_iter()
        .flatten()
        .find_map(|e| e.subject.clone())
        .filter(|s| s.format == "pe")
        .map(|s| subject_from_path(&s.local_path, &s.digest.sha256, s.architecture.clone()));
    let id_of = |e: &Option<Evidence>| e.as_ref().map(|e| e.evidence_id.clone());
    let evidence = derived_evidence(
        subject,
        "rea.managed-application-graph",
        operation,
        json!({
            "managed_artifact_evidence_id": id_of(&artifact),
            "managed_members_evidence_id": id_of(&members),
            "managed_native_boundaries_evidence_id": id_of(&boundaries),
        }),
        &result,
        vec![],
    )?;
    record_sources(session, &resolved);
    finish(session, evidence, None)
}

// ---------------------------------------------------------------------------
// Nested result schemas (REA parses `normalized_result` with the inspection schemas)
// ---------------------------------------------------------------------------

fn result_validators() -> &'static HashMap<String, jsonschema::Validator> {
    static VALIDATORS: OnceLock<HashMap<String, jsonschema::Validator>> = OnceLock::new();
    VALIDATORS.get_or_init(|| {
        let catalog: Value = serde_json::from_str(tracewise_contracts::PHASE3_TOOLS_JSON).expect("phase 3 catalog");
        let mut map = HashMap::new();
        for tool in catalog["tools"].as_array().into_iter().flatten() {
            let name = tool["name"].as_str().unwrap_or_default();
            if !matches!(name, "inspect_managed_artifact" | "inspect_managed_members" | "inspect_managed_native_boundaries") {
                continue;
            }
            let output = &tool["outputSchema"];
            let Some(reference) = output["properties"]["normalized_result"]["$ref"].as_str() else { continue };
            let schema = json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$ref": reference,
                "$defs": output["$defs"],
            });
            let validator = jsonschema::validator_for(&schema)
                .unwrap_or_else(|error| panic!("result schema of {name} does not compile: {error}"));
            map.insert(name.to_string(), validator);
        }
        map
    })
}

/// A `normalized_result` that fails its inspection schema is a workflow input error.
fn nested_schema_error(operation: &str, inspection: &str, evidence: &[&Evidence]) -> Option<CallToolResult> {
    let validator = result_validators()
        .get(inspection)
        .unwrap_or_else(|| panic!("no result validator for {inspection}"));
    for record in evidence {
        if let Some(error) = validator.iter_errors(&record.normalized_result).next() {
            let path = dotted(&error.instance_path().to_string());
            let location = if path.is_empty() { "its root".to_string() } else { path };
            return Some(input_error_result(
                operation,
                &format!("A nested value failed validation at {location}: {error}"),
            ));
        }
    }
    None
}
