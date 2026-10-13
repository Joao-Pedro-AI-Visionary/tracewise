//! Evidence-derived investigation tools: `compare_functions` and `build_call_path`.
//!
//! Both compute from complete `analyze_function` Evidence records (inline arguments) and
//! publish a derived Evidence record (`confidence` derived, `authority` analyst-inference)
//! that links to its sources. Neither needs a live provider. The glue in the server crate
//! calls into this module; everything here is pure over the session ledger.

pub mod call_path;
mod diff;
mod dossier;
pub mod function_comparison;
mod input;
mod util;

use serde_json::{json, Value};
use tracewise_domain::error::DomainError;
use tracewise_domain::evidence::{
    create_evidence, AnalysisProfile, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation,
    EvidenceProvider,
};
use tracewise_domain::ledger::EvidenceLedger;
use tracewise_domain::unknown::{create_residual_unknown, RecordUnknownInput};

pub use dossier::{describe_issues, validate_dossier, Issue};
pub use input::validate_tool_input;

use util::canonical;

/// Limitation REA prepends to every Evidence record that has no artifact subject.
pub const MISSING_SUBJECT: &str = "Artifact identity is unavailable for this observation.";

/// Provider identity of `compare_functions` Evidence.
pub const FUNCTION_COMPARISON_PROVIDER: (&str, &str, &str) =
    ("rea-function-comparison", "REA function comparison", "1");
/// Provider identity of `build_call_path` Evidence.
pub const CALL_PATH_PROVIDER: (&str, &str, &str) = ("rea-call-path", "REA call path reconstruction", "1");
const UNKNOWN_REGISTRY_PROVIDER: (&str, &str, &str) = ("rea-unknown-registry", "REA residual unknown registry", "1");

/// Why a derived tool failed, projected the way REA projects the matching error class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivedError {
    /// `EvidenceIntegrityError`: invalid, tampered or dangling Evidence.
    Integrity(String),
    /// `AnalysisInputError` raised by the computation (a `TypeError` or `ZodError` cause).
    Input(String),
    /// `UnknownRegistryError("already-exists")`.
    UnknownAlreadyExists,
    /// Any other registry rejection.
    UnknownRegistry(String),
}

impl DerivedError {
    /// Body of the `isError` tool result.
    pub fn body(&self, operation: &str) -> Value {
        match self {
            Self::Integrity(reason) => {
                let message = "Evidence is invalid or has changed. Recreate or re-import it, then try again.";
                json!({ "error": {
                    "code": "evidence_integrity_mismatch",
                    "category": "integrity_mismatch",
                    "message": message,
                    "retryable": false,
                    "remediation": { "action": message },
                    "details": { "reason": reason },
                } })
            }
            Self::Input(message) => {
                crate::error::AnalysisError::input(operation, Vec::new(), message.clone()).error_body()
            }
            Self::UnknownAlreadyExists => registry_body("already-exists"),
            Self::UnknownRegistry(reason) => registry_body(reason),
        }
    }
}

fn registry_body(reason: &str) -> Value {
    let message = "Evidence state changed before the update completed. Refresh the current state and try again.";
    json!({ "error": {
        "code": "revision_conflict",
        "category": "execution_failure",
        "message": message,
        "retryable": true,
        "remediation": { "action": message },
        "details": { "reason": reason },
    } })
}

impl From<DomainError> for DerivedError {
    fn from(error: DomainError) -> Self {
        Self::Integrity(error.to_string())
    }
}

/// Text of a zod error for these issues (`ZodError.message`).
pub fn zod_error_text(issues: &[Issue]) -> String {
    let issues: Vec<Value> = issues
        .iter()
        .map(|issue| json!({ "code": "custom", "path": issue.path, "message": issue.message }))
        .collect();
    serde_json::to_string_pretty(&issues).expect("issues serialize")
}

/// Schema refinements of an Evidence record that JSON Schema cannot express: the analysis
/// profile must commit to its own parameters and to the Evidence provider. Paths are
/// relative to the record. A failing profile digest masks the provider check, as in zod.
pub fn evidence_refinement_issues(record: &Value) -> Vec<Issue> {
    let Some(profile_value) = record.get("analysis_profile").filter(|value| !value.is_null()) else {
        return Vec::new();
    };
    let Ok(profile) = serde_json::from_value::<AnalysisProfile>(profile_value.clone()) else {
        return Vec::new();
    };
    if profile.verify().is_err() {
        return vec![Issue {
            path: vec!["analysis_profile".into(), "digest".into()],
            message: "Analysis profile digest does not match its parameters".into(),
        }];
    }
    let provider = &record["provider"];
    let same = provider["id"].as_str() == Some(profile.provider.id.as_str())
        && provider["name"].as_str() == Some(profile.provider.name.as_str())
        && provider["version"].as_str() == Some(profile.provider.version.as_str());
    if same {
        Vec::new()
    } else {
        vec![Issue {
            path: vec!["analysis_profile".into(), "provider".into()],
            message: "Analysis profile provider does not match Evidence provider".into(),
        }]
    }
}

/// `parseEvidence` for an inline record: structure, then the semantic identifier.
pub fn parse_evidence(input: &Value) -> Result<Evidence, Issue> {
    let evidence: Evidence = serde_json::from_value(input.clone()).map_err(|error| Issue {
        path: Vec::new(),
        message: error.to_string(),
    })?;
    if let Some(issue) = evidence_refinement_issues(input).into_iter().next() {
        return Err(issue);
    }
    let computed = evidence.compute_id().map_err(|error| Issue {
        path: Vec::new(),
        message: error.to_string(),
    })?;
    if computed != evidence.evidence_id {
        return Err(Issue {
            path: vec!["evidence_id".into()],
            message: "Evidence semantic identifier does not match its record".into(),
        });
    }
    Ok(evidence)
}

/// Build the derived Evidence record (no subject, so REA's missing-subject limitation leads).
pub fn derived_evidence(
    provider: (&str, &str, &str),
    predicate_type: &str,
    operation: &str,
    parameters: Value,
    result: Value,
    limitations: &[String],
    links: Vec<String>,
) -> Result<Evidence, DerivedError> {
    let mut all = vec![MISSING_SUBJECT.to_string()];
    all.extend(limitations.iter().cloned());
    Ok(create_evidence(
        None,
        EvidenceProvider {
            id: provider.0.into(),
            name: provider.1.into(),
            version: Some(provider.2.into()),
        },
        EvidenceObservation {
            predicate_type: Some(predicate_type.into()),
            operation: operation.into(),
            parameters,
            normalized_result: result,
            raw_result: None,
            analysis_profile: None,
            confidence: Some(EvidenceConfidence::Derived),
            authority: Some(EvidenceAuthority::AnalystInference),
            environment: None,
            limitations: Some(all),
            locations: Some(Vec::new()),
            evidence_links: Some(links),
        },
    )?)
}

/// `unknownMutationEvidence(undefined, input)`.
fn unknown_mutation_evidence(input: &Value) -> Result<Evidence, DerivedError> {
    let links: Vec<String> = {
        let mut links: Vec<String> = Vec::new();
        for key in ["supporting_evidence_ids", "contradicting_evidence_ids"] {
            for id in input[key].as_array().into_iter().flatten().filter_map(Value::as_str) {
                if !links.iter().any(|existing| existing == id) {
                    links.push(id.to_string());
                }
            }
        }
        links
    };
    derived_evidence(
        UNKNOWN_REGISTRY_PROVIDER,
        "rea.residual-unknown-mutation",
        "record_unknown",
        json!({ "domain": input["domain"], "severity": input["severity"] }),
        json!({
            "action": "record",
            "question": input["question"],
            "required_authority": input["required_authority"],
            "required_confidence": input["required_confidence"],
        }),
        &["Registry mutation evidence records analyst intent, not proof of the answer.".to_string()],
        links,
    )
}

/// `recordDerivedEvidence`: commit the Evidence and, when given, its residual Unknown
/// atomically (the ledger lock is held by the caller).
pub fn record_derived_evidence(
    ledger: &mut EvidenceLedger,
    evidence: &Evidence,
    unknown: Option<&Value>,
) -> Result<(), DerivedError> {
    let Some(unknown) = unknown else {
        ledger.record(evidence.clone()).map_err(|e| DerivedError::Integrity(e.to_string()))?;
        return Ok(());
    };
    let input: RecordUnknownInput = serde_json::from_value(unknown.clone())
        .map_err(|error| DerivedError::UnknownRegistry(format!("invalid-transition: {error}")))?;
    let mutation = unknown_mutation_evidence(unknown)?;
    let created = create_residual_unknown(&input, &mutation.evidence_id, None)
        .map_err(|error| DerivedError::UnknownRegistry(format!("invalid-transition: {error}")))?;
    let existing = ledger
        .list_unknowns(None, None, None)
        .into_iter()
        .find(|head| head.unknown_id == created.unknown_id);
    if let Some(existing) = existing {
        if existing.revision != 1 || existing.revision_digest != created.revision_digest {
            return Err(DerivedError::UnknownAlreadyExists);
        }
        ledger.record(evidence.clone()).map_err(|e| DerivedError::Integrity(e.to_string()))?;
        return Ok(());
    }
    ledger.record(evidence.clone()).map_err(|e| DerivedError::Integrity(e.to_string()))?;
    ledger
        .record_unknown(&input, mutation)
        .map_err(|error| DerivedError::UnknownRegistry(error.to_string()))?;
    Ok(())
}

/// `evidenceClosure`: every seed and each transitive link must be retained in the session.
pub fn evidence_closure(ledger: &EvidenceLedger, seeds: &[String]) -> Result<Vec<String>, DerivedError> {
    let mut visited = std::collections::BTreeSet::new();
    let mut pending: Vec<String> = seeds.to_vec();
    while let Some(id) = pending.pop() {
        if visited.contains(&id) {
            continue;
        }
        let Some(record) = ledger.get(&id) else {
            return Err(DerivedError::Integrity("Investigation input has a dangling Evidence link".into()));
        };
        pending.extend(record.evidence_links.iter().cloned());
        visited.insert(id);
    }
    Ok(visited.into_iter().collect())
}

/// Canonical JSON of the record's provider, for identity comparisons.
pub(crate) fn provider_key(evidence: &Evidence) -> String {
    canonical(&serde_json::to_value(&evidence.provider).expect("provider serializes"))
}
