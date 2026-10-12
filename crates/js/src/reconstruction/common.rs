//! Shared helpers for the reconstruction and investigation workflows.
//!
//! Ports of REA `canonicalOrdering`, `unicodeCodePointOrder`,
//! `comparisonSourceEvidence`, and the comparison-result accessors that
//! `changedBehavior`, `staticRuntimeCorrelation`, and `reconstructionVerification`
//! share.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use serde_json::Value;
use tracewise_domain::canonical::{canonical_json, canonical_sha256};
use tracewise_domain::evidence::{
    create_evidence, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation,
    EvidenceProvider,
};
use tracewise_domain::unknown::{Probe, RecordUnknownInput, UnknownSeverity};

use crate::error::JsError;
pub use crate::unicode::compare_unicode_code_points;

pub const MISSING_SUBJECT: &str = "Artifact identity is unavailable for this observation.";

/// Session-side Evidence closure used by investigation workflows.
pub type ClosureFn<'a> = dyn Fn(&[String]) -> Result<Vec<String>, JsError> + 'a;

/// Derived Evidence plus the residual unknown REA records when the result is unresolved.
pub struct WorkflowOutcome {
    pub evidence: Evidence,
    pub unknown: Option<RecordUnknownInput>,
}

pub fn invalid(message: impl Into<String>) -> JsError {
    JsError::InvalidInput(message.into())
}

/// `uniqueSorted`: deduplicate and sort by Unicode code point.
pub fn unique_sorted<I: IntoIterator<Item = String>>(values: I) -> Vec<String> {
    let mut out: Vec<String> = values.into_iter().collect();
    out.sort_by(|a, b| compare_unicode_code_points(a, b));
    out.dedup();
    out
}

/// `compositeKey`: JSON tuple of the components.
pub fn composite_key(parts: &[&str]) -> String {
    serde_json::to_string(parts).unwrap_or_default()
}

/// RFC 8785 SHA-256 of a JSON value.
pub fn digest(value: &Value) -> Result<String, JsError> {
    canonical_sha256(value).map_err(JsError::from)
}

pub fn canonical(value: &Value) -> Result<String, JsError> {
    canonical_json(value).map_err(JsError::from)
}

/// ICU root collation weight for ASCII, as used by V8 `String.prototype.localeCompare`.
///
/// Punctuation and symbols are non-ignorable and sort before digits, which sort
/// before letters; letters compare case-insensitively at the primary level.
fn primary_weight(ch: char) -> (u32, u32) {
    const ORDER: &str = " _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$0123456789abcdefghijklmnopqrstuvwxyz";
    if ch.is_ascii() {
        let lower = ch.to_ascii_lowercase();
        if let Some(index) = ORDER.find(lower) {
            return (0, index as u32);
        }
        return (0, 0);
    }
    (1, ch as u32)
}

/// Approximation of JS `a.localeCompare(b)` (ICU root, default strength) for the
/// identifier-like strings REA sorts with it.
pub fn locale_compare(left: &str, right: &str) -> Ordering {
    let lw: Vec<(u32, u32)> = left.chars().map(primary_weight).collect();
    let rw: Vec<(u32, u32)> = right.chars().map(primary_weight).collect();
    match lw.cmp(&rw) {
        Ordering::Equal => {}
        other => return other,
    }
    // Tertiary level: lowercase sorts before uppercase.
    for (l, r) in left.chars().zip(right.chars()) {
        if l != r {
            let lu = l.is_ascii_uppercase();
            let ru = r.is_ascii_uppercase();
            if lu != ru {
                return if lu { Ordering::Greater } else { Ordering::Less };
            }
            return l.cmp(&r);
        }
    }
    Ordering::Equal
}

/// `[...new Set(values)].sort()` (UTF-16 order; identical to code points for these ids).
pub fn default_sorted_unique<I: IntoIterator<Item = String>>(values: I) -> Vec<String> {
    let set: BTreeSet<String> = values.into_iter().collect();
    let mut out: Vec<String> = set.into_iter().collect();
    out.sort_by(|a, b| compare_unicode_code_points(a, b));
    out
}

/// `parseEvidence`: schema-shaped Evidence whose identifier matches its content.
pub fn parse_evidence(value: &Value) -> Result<Evidence, JsError> {
    let evidence: Evidence = serde_json::from_value(value.clone())
        .map_err(|error| invalid(format!("Invalid Evidence: {error}")))?;
    evidence
        .verify()
        .map_err(|error| JsError::Integrity(error.to_string()))?;
    Ok(evidence)
}

pub fn authority_str(authority: EvidenceAuthority) -> &'static str {
    match authority {
        EvidenceAuthority::ShippedArtifact => "shipped-artifact",
        EvidenceAuthority::ControlledReplay => "controlled-replay",
        EvidenceAuthority::HistoricalReference => "historical-reference",
        EvidenceAuthority::ExternalService => "external-service",
        EvidenceAuthority::AnalystInference => "analyst-inference",
    }
}

pub fn provider_is(evidence: &Evidence, id: &str, name: &str, version: &str) -> bool {
    evidence.provider.id == id
        && evidence.provider.name == name
        && evidence.provider.version.as_deref() == Some(version)
}

/// `isProcessEvidenceProvider`: current and legacy names of the v3 process provider.
pub fn is_process_provider(evidence: &Evidence) -> bool {
    evidence.provider.id == "rea-process"
        && evidence.provider.version.as_deref() == Some("3")
        && (evidence.provider.name == "REA process capture"
            || evidence.provider.name == "REA deterministic process harness")
}

pub fn is_evidence_id(value: &str) -> bool {
    is_prefixed_digest(value, "ev")
}

pub fn is_prefixed_digest(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('_'))
        .is_some_and(is_digest)
}

pub fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `comparisonSourceEvidenceSides`.
pub fn comparison_sides(evidence: &Evidence) -> Result<(Vec<String>, Vec<String>), JsError> {
    let parameters = evidence
        .parameters
        .as_object()
        .ok_or_else(|| invalid("Comparison Evidence parameters must be an object"))?;
    let single = |key: &str| -> Result<Option<String>, JsError> {
        match parameters.get(key) {
            None => Ok(None),
            Some(Value::String(id)) if is_evidence_id(id) => Ok(Some(id.clone())),
            Some(_) => Err(invalid(format!("Comparison Evidence {key} is invalid"))),
        }
    };
    let multiple = |key: &str| -> Result<Option<Vec<String>>, JsError> {
        match parameters.get(key) {
            None => Ok(None),
            Some(Value::Array(items)) if !items.is_empty() => items
                .iter()
                .map(|item| match item.as_str() {
                    Some(id) if is_evidence_id(id) => Ok(id.to_string()),
                    _ => Err(invalid(format!("Comparison Evidence {key} is invalid"))),
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Some),
            Some(_) => Err(invalid(format!("Comparison Evidence {key} is invalid"))),
        }
    };
    let left_single = single("left_evidence_id")?;
    let right_single = single("right_evidence_id")?;
    let left_multi = multiple("left_evidence_ids")?;
    let right_multi = multiple("right_evidence_ids")?;
    if left_single.is_none() != right_single.is_none() || left_multi.is_none() != right_multi.is_none() {
        return Err(invalid("Comparison Evidence source representation omitted one side"));
    }
    let side = |single: Option<String>, multi: Option<Vec<String>>| -> Result<Vec<String>, JsError> {
        if let (Some(one), Some(many)) = (&single, &multi) {
            if many.len() != 1 || &many[0] != one {
                return Err(invalid("Comparison Evidence source representations disagree"));
            }
        }
        let selected = match single {
            Some(one) => vec![one],
            None => multi.unwrap_or_default(),
        };
        if selected.is_empty() {
            return Err(invalid("Comparison Evidence omitted its source parameters"));
        }
        let unique: BTreeSet<&String> = selected.iter().collect();
        if unique.len() != selected.len() {
            return Err(invalid("Comparison Evidence repeats a source within one side"));
        }
        Ok(selected)
    };
    Ok((side(left_single, left_multi)?, side(right_single, right_multi)?))
}

/// `comparisonSourceEvidenceIds`.
pub fn comparison_source_ids(evidence: &Evidence) -> Result<Vec<String>, JsError> {
    let (left, right) = comparison_sides(evidence)?;
    Ok(unique_sorted(left.into_iter().chain(right)))
}

pub const COMPARISON_STATUSES: [&str; 7] = [
    "unchanged", "added", "removed", "changed", "truncated", "unknown", "contradiction",
];
pub const PROCESS_DIMENSIONS: [&str; 5] = ["terminal", "interaction", "exit", "filesystem", "process"];
pub const FUNCTION_DIMENSIONS: [&str; 8] = [
    "identity", "pseudocode", "assembly", "comments", "calls", "references", "strings_names", "cfg",
];

fn string_array(value: Option<&Value>, label: &str) -> Result<Vec<String>, JsError> {
    value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(format!("{label} must be an array of strings")))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or_else(|| invalid(format!("{label} must be an array of strings")))
        })
        .collect()
}

fn evidence_id_array(value: Option<&Value>, label: &str, min: usize) -> Result<Vec<String>, JsError> {
    let ids = string_array(value, label)?;
    if ids.len() < min || ids.iter().any(|id| !is_evidence_id(id)) {
        return Err(invalid(format!("{label} must cite at least {min} Evidence identifiers")));
    }
    Ok(ids)
}

fn status_in(value: Option<&Value>, allowed: &[&str], label: &str) -> Result<String, JsError> {
    match value.and_then(Value::as_str) {
        Some(status) if allowed.contains(&status) => Ok(status.to_string()),
        _ => Err(invalid(format!("{label} is not a valid comparison status"))),
    }
}

/// Parsed `processCaptureComparisonSchema` fields used by the workflows.
pub struct ProcessComparison {
    pub status: String,
    pub dimensions: Vec<(String, String)>,
    pub limitations: Vec<String>,
}

impl ProcessComparison {
    pub fn dimension(&self, name: &str) -> &str {
        self.dimensions
            .iter()
            .find(|(dimension, _)| dimension == name)
            .map(|(_, status)| status.as_str())
            .unwrap_or("unknown")
    }
}

/// `deriveProcessComparisonStatus`.
pub fn derive_process_status(statuses: &[&str]) -> &'static str {
    if statuses.contains(&"truncated") {
        return "truncated";
    }
    if statuses.iter().any(|s| ["changed", "added", "removed"].contains(s)) {
        return "changed";
    }
    if statuses.contains(&"unknown") {
        "unknown"
    } else {
        "unchanged"
    }
}

pub fn parse_process_comparison(result: &Value) -> Result<ProcessComparison, JsError> {
    let status = status_in(result.get("status"), &COMPARISON_STATUSES, "Process comparison status")?;
    let mut dimensions = Vec::new();
    for dimension in PROCESS_DIMENSIONS {
        dimensions.push((
            dimension.to_string(),
            status_in(result.get(dimension), &COMPARISON_STATUSES, "Process comparison dimension")?,
        ));
    }
    let divergence = result
        .get("first_divergence")
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str);
    if !matches!(divergence, Some("none" | "unknown" | "found")) {
        return Err(invalid("Process comparison first_divergence is invalid"));
    }
    let limitations = string_array(result.get("limitations"), "Process comparison limitations")?;
    let statuses: Vec<&str> = dimensions.iter().map(|(_, s)| s.as_str()).collect();
    if status != derive_process_status(&statuses) {
        return Err(invalid("Process comparison status contradicts its dimensions"));
    }
    Ok(ProcessComparison { status, dimensions, limitations })
}

pub struct FunctionDimension {
    pub dimension: String,
    pub status: String,
    pub conclusion_kind: String,
    pub evidence_links: Vec<String>,
    pub limitations: Vec<String>,
}

pub struct FunctionComparison {
    pub status: String,
    pub dimensions: Vec<FunctionDimension>,
}

/// `functionComparisonResultSchema` (fields the workflows consume plus the discriminated union).
pub fn parse_function_comparison(result: &Value) -> Result<FunctionComparison, JsError> {
    let status = status_in(result.get("status"), &["unchanged", "changed", "unknown"], "Function comparison status")?;
    let items = result
        .get("dimensions")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("Function comparison dimensions are missing"))?;
    if items.len() != 8 {
        return Err(invalid("Function comparison must report exactly 8 dimensions"));
    }
    if !result.get("changes").is_some_and(Value::is_array) || !result.get("function_match").is_some_and(Value::is_object) {
        return Err(invalid("Function comparison result is malformed"));
    }
    let mut dimensions = Vec::new();
    for item in items {
        let dimension = status_in(item.get("dimension"), &FUNCTION_DIMENSIONS, "Function dimension")?;
        let status = status_in(item.get("status"), &["unchanged", "changed", "unknown"], "Function dimension status")?;
        let conclusion_kind = item
            .get("conclusion_kind")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let consistent = match status.as_str() {
            "unchanged" => conclusion_kind == "derived_relationship",
            "changed" => conclusion_kind == "derived_relationship" || conclusion_kind == "contradiction",
            _ => conclusion_kind == "unresolved_branch",
        };
        if !consistent {
            return Err(invalid("Function dimension conclusion disagrees with its status"));
        }
        dimensions.push(FunctionDimension {
            dimension,
            status,
            conclusion_kind,
            evidence_links: evidence_id_array(item.get("evidence_links"), "Function dimension evidence_links", 2)?,
            limitations: string_array(item.get("limitations"), "Function dimension limitations")?,
        });
    }
    string_array(result.get("limitations"), "Function comparison limitations")?;
    Ok(FunctionComparison { status, dimensions })
}

pub struct ArtifactChange {
    pub classification: String,
    pub logical_path: String,
    pub evidence_links: Vec<String>,
}

pub struct ArtifactComparison {
    pub status: String,
    pub changes: Vec<ArtifactChange>,
    pub limitations: Vec<String>,
}

/// `artifactComparisonResultSchema` (fields the workflows consume).
pub fn parse_artifact_comparison(result: &Value) -> Result<ArtifactComparison, JsError> {
    let status = status_in(result.get("status"), &COMPARISON_STATUSES, "Artifact comparison status")?;
    for key in ["left_manifest_id", "right_manifest_id"] {
        if !result.get(key).and_then(Value::as_str).is_some_and(|id| is_prefixed_digest(id, "agm")) {
            return Err(invalid(format!("Artifact comparison {key} is invalid")));
        }
    }
    let items = result
        .get("changes")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("Artifact comparison changes are missing"))?;
    let mut changes = Vec::new();
    for item in items {
        let classification = status_in(
            item.get("classification"),
            &["added", "removed", "changed", "unknown", "contradiction"],
            "Artifact change classification",
        )?;
        let logical_path = item
            .get("logical_path")
            .and_then(Value::as_str)
            .filter(|path| !path.is_empty())
            .ok_or_else(|| invalid("Artifact change logical_path is invalid"))?
            .to_string();
        changes.push(ArtifactChange {
            classification,
            logical_path,
            evidence_links: evidence_id_array(item.get("evidence_links"), "Artifact change evidence_links", 2)?,
        });
    }
    let limitations = string_array(result.get("limitations"), "Artifact comparison limitations")?;
    Ok(ArtifactComparison { status, changes, limitations })
}

/// Derived Evidence for investigation workflows (`createEvidence(undefined, provider, ...)`).
#[allow(clippy::too_many_arguments)]
pub fn derived_evidence(
    provider: (&str, &str),
    predicate_type: &str,
    operation: &str,
    parameters: Value,
    result: Value,
    confidence: EvidenceConfidence,
    result_limitations: Vec<String>,
    links: Vec<String>,
) -> Result<Evidence, JsError> {
    let mut limitations = vec![MISSING_SUBJECT.to_string()];
    limitations.extend(result_limitations);
    create_evidence(
        None,
        EvidenceProvider {
            id: provider.0.to_string(),
            name: provider.1.to_string(),
            version: Some("1".to_string()),
        },
        EvidenceObservation {
            predicate_type: Some(predicate_type.to_string()),
            operation: operation.to_string(),
            parameters,
            normalized_result: result,
            raw_result: None,
            analysis_profile: None,
            confidence: Some(confidence),
            authority: Some(EvidenceAuthority::AnalystInference),
            environment: None,
            limitations: Some(limitations),
            locations: None,
            evidence_links: Some(links),
        },
    )
    .map_err(JsError::from)
}

/// `recordWorkflowEvidence` unknown registration for unresolved results.
pub fn workflow_unknown(
    evidence: &Evidence,
    question: &str,
    domain: &str,
    required_authority: Option<EvidenceAuthority>,
    required_confidence: EvidenceConfidence,
    probes: Vec<(String, String)>,
) -> RecordUnknownInput {
    RecordUnknownInput {
        question: question.to_string(),
        severity: UnknownSeverity::High,
        domain: domain.to_string(),
        supporting_evidence_ids: vec![evidence.evidence_id.clone()],
        contradicting_evidence_ids: vec![],
        required_authority,
        required_confidence,
        required_environment: None,
        recommended_probes: probes
            .into_iter()
            .map(|(operation, rationale)| Probe { operation, rationale })
            .collect(),
        relationships: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_compare_matches_icu_root_for_ascii() {
        let mut values = vec!["a-b", "ab", "a_b", "a b", "a:b", "a1", "aB", "Ab"];
        values.sort_by(|a, b| locale_compare(a, b));
        assert_eq!(values, vec!["a b", "a_b", "a-b", "a:b", "a1", "ab", "aB", "Ab"]);
        assert_eq!(locale_compare("x-ab", "xa-b"), Ordering::Less);
    }
}
