//! Port of REA `domain/reconstructionVerification.ts`,
//! `reconstructionVerificationSchemas.ts`, and `reconstructionUnknowns.ts`.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};
use tracewise_domain::bundle::EvidenceBundle;
use tracewise_domain::evidence::{Evidence, EvidenceAuthority, EvidenceConfidence};
use tracewise_domain::unknown::{RelationshipType, ResidualUnknown, UnknownStatus};

use super::common::*;
use crate::error::JsError;

struct Claim {
    claim_id: String,
    title: String,
    kind: String,
    dimension: String,
    comparison_evidence_id: String,
}

/// `IDENTIFIER_PATTERN`: `^[A-Za-z][A-Za-z0-9._-]*$`.
fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

fn parse_specification(value: &Value) -> Result<(String, Vec<Claim>), JsError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("specification must be an object"))?;
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid("specification.name must be non-empty"))?;
    let items = match object.get("claims").and_then(Value::as_array) {
        Some(items) if !items.is_empty() => items,
        _ => return Err(invalid("specification.claims must be a non-empty array")),
    };
    let mut claims = Vec::new();
    for item in items {
        let text = |key: &str| item.get(key).and_then(Value::as_str);
        let claim_id = text("claim_id")
            .filter(|id| is_identifier(id))
            .ok_or_else(|| invalid("claim_id must be an identifier"))?;
        let title = text("title")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid("claim title must be non-empty"))?;
        let comparison = text("comparison_evidence_id")
            .filter(|id| is_evidence_id(id))
            .ok_or_else(|| invalid("comparison_evidence_id must be an Evidence identifier"))?;
        let kind = text("kind").unwrap_or_default();
        let dimension = text("dimension").unwrap_or_default();
        let allowed: Vec<&str> = match kind {
            "behavioral" => std::iter::once("overall").chain(PROCESS_DIMENSIONS).collect(),
            "structural-function" => std::iter::once("overall").chain(FUNCTION_DIMENSIONS).collect(),
            "structural-artifact" => vec!["overall"],
            _ => return Err(invalid("claim kind is invalid")),
        };
        if !allowed.contains(&dimension) {
            return Err(invalid("claim dimension is invalid for its kind"));
        }
        claims.push(Claim {
            claim_id: claim_id.to_string(),
            title,
            kind: kind.to_string(),
            dimension: dimension.to_string(),
            comparison_evidence_id: comparison.to_string(),
        });
    }
    let ids: BTreeSet<&str> = claims.iter().map(|c| c.claim_id.as_str()).collect();
    if ids.len() != claims.len() {
        return Err(invalid("Claim IDs must be unique"));
    }
    let selectors: BTreeSet<String> = claims
        .iter()
        .map(|c| format!("{}:{}:{}", c.kind, c.comparison_evidence_id, c.dimension))
        .collect();
    if selectors.len() != claims.len() {
        return Err(invalid("Claim comparison selectors must be unique"));
    }
    Ok((name, claims))
}

fn claim_value(claim: &Claim) -> Value {
    json!({
        "claim_id": claim.claim_id,
        "title": claim.title,
        "comparison_evidence_id": claim.comparison_evidence_id,
        "kind": claim.kind,
        "dimension": claim.dimension,
    })
}

/// `reconstructionUnknownHeads`.
fn unknown_heads(revisions: &[ResidualUnknown]) -> BTreeMap<String, ResidualUnknown> {
    let mut heads: BTreeMap<String, ResidualUnknown> = BTreeMap::new();
    for item in revisions {
        let replace = heads
            .get(&item.unknown_id)
            .is_none_or(|current| current.revision < item.revision);
        if replace {
            heads.insert(item.unknown_id.clone(), item.clone());
        }
    }
    heads
}

/// `reconstructionClaimUnknowns`.
fn claim_unknowns<'a>(
    heads: &'a BTreeMap<String, ResidualUnknown>,
    comparison_id: &str,
    source_ids: &[String],
) -> Vec<&'a ResidualUnknown> {
    let evidence_ids: BTreeSet<&str> = std::iter::once(comparison_id)
        .chain(source_ids.iter().map(String::as_str))
        .collect();
    let mut relevant: BTreeSet<String> = heads
        .values()
        .filter(|item| {
            item.status != UnknownStatus::Resolved
                && item
                    .supporting_evidence_ids
                    .iter()
                    .chain(&item.contradicting_evidence_ids)
                    .any(|id| evidence_ids.contains(id.as_str()))
        })
        .map(|item| item.unknown_id.clone())
        .collect();
    let mut pending: Vec<String> = relevant.iter().cloned().collect();
    while let Some(current_id) = pending.pop() {
        let Some(current) = heads.get(&current_id) else { continue };
        for relationship in &current.relationships {
            if relationship.rel_type == RelationshipType::RelatedTo {
                continue;
            }
            let Some(dependency) = heads.get(&relationship.unknown_id) else { continue };
            if dependency.status == UnknownStatus::Resolved || relevant.contains(&dependency.unknown_id) {
                continue;
            }
            relevant.insert(dependency.unknown_id.clone());
            pending.push(dependency.unknown_id.clone());
        }
    }
    let mut out: Vec<&ResidualUnknown> = relevant.iter().filter_map(|id| heads.get(id)).collect();
    out.sort_by(|a, b| compare_unicode_code_points(&a.unknown_id, &b.unknown_id));
    out
}

fn validate_comparison_identity(claim: &Claim, evidence: &Evidence) -> Result<(), JsError> {
    evidence
        .verify()
        .map_err(|error| JsError::Integrity(error.to_string()))?;
    let (operation, predicate, id, name) = match claim.kind.as_str() {
        "behavioral" => ("compare_process_captures", "rea.process-comparison", "", ""),
        "structural-function" => (
            "compare_functions",
            "rea.function-comparison",
            "rea-function-comparison",
            "REA function comparison",
        ),
        _ => (
            "compare_artifacts",
            "rea.artifact-comparison",
            "rea-artifact-comparison",
            "REA artifact comparison",
        ),
    };
    let provider_ok = if claim.kind == "behavioral" {
        is_process_provider(evidence)
    } else {
        provider_is(evidence, id, name, "1")
    };
    if evidence.operation != operation
        || evidence.predicate_type != predicate
        || !provider_ok
        || evidence.confidence != EvidenceConfidence::Derived
        || evidence.authority != EvidenceAuthority::AnalystInference
        || evidence.subject.is_some()
    {
        return Err(invalid("Comparison Evidence identity or authority disagrees"));
    }
    Ok(())
}

fn validate_source_kinds(claim: &Claim, sources: &[&Evidence]) -> Result<(), JsError> {
    let (operation, predicate) = match claim.kind.as_str() {
        "behavioral" => ("capture_process_scenario", "rea.process-capture"),
        "structural-function" => ("analyze_function", "rea.analysis"),
        _ => ("inventory_artifact", "rea.analysis"),
    };
    if sources
        .iter()
        .any(|s| s.operation != operation || s.predicate_type != predicate)
    {
        return Err(invalid("Comparison source Evidence has an unexpected observation type"));
    }
    for source in sources {
        let result = &source.normalized_result;
        let shaped = match claim.kind.as_str() {
            "behavioral" => {
                result.get("manifest").is_some_and(Value::is_object)
                    && result.get("exit").is_some_and(Value::is_object)
                    && result.get("settlement").is_some_and(Value::is_object)
            }
            _ => result.is_object(),
        };
        if !shaped {
            return Err(invalid("Comparison source Evidence result is malformed"));
        }
    }
    Ok(())
}

fn observed_status(claim: &Claim, evidence: &Evidence) -> Result<String, JsError> {
    match claim.kind.as_str() {
        "behavioral" => {
            let result = parse_process_comparison(&evidence.normalized_result)?;
            Ok(if claim.dimension == "overall" {
                result.status.clone()
            } else {
                result.dimension(&claim.dimension).to_string()
            })
        }
        "structural-function" => {
            let result = parse_function_comparison(&evidence.normalized_result)?;
            if claim.dimension == "overall" {
                return Ok(result.status);
            }
            let dimension = result
                .dimensions
                .iter()
                .find(|d| d.dimension == claim.dimension)
                .ok_or_else(|| invalid("Function comparison dimension missing"))?;
            if dimension.evidence_links.iter().any(|id| !evidence.evidence_links.contains(id)) {
                return Err(invalid("Function dimension cites Evidence outside comparison closure"));
            }
            Ok(dimension.status.clone())
        }
        _ => {
            let result = parse_artifact_comparison(&evidence.normalized_result)?;
            if result
                .changes
                .iter()
                .any(|c| c.evidence_links.iter().any(|id| !evidence.evidence_links.contains(id)))
            {
                return Err(invalid("Artifact change cites Evidence outside comparison closure"));
            }
            Ok(result.status)
        }
    }
}

fn authority_limitations(claim: &Claim, sources: &[&Evidence], left: &[String], right: &[String]) -> Vec<String> {
    let behavioral = claim.kind == "behavioral";
    let required = if behavioral {
        EvidenceAuthority::ControlledReplay
    } else {
        EvidenceAuthority::ShippedArtifact
    };
    let mut limitations = Vec::new();
    if left.iter().any(|id| right.contains(id)) {
        limitations.push("A source observation appears on both comparison sides; independent original and reconstruction observations are unavailable.".to_string());
    }
    if sources.iter().any(|source| {
        source.authority != required
            || if claim.kind == "structural-function" {
                source.confidence == EvidenceConfidence::Inferred
            } else {
                source.confidence != EvidenceConfidence::Observed
            }
    }) {
        limitations.push(format!(
            "Source Evidence lacks qualifying {} authority.",
            authority_str(required)
        ));
    }
    if !behavioral && sources.iter().any(|s| s.subject.is_none()) {
        limitations.push("Structural source artifact identity is unavailable.".to_string());
    }
    if behavioral {
        let find = |id: Option<&String>| id.and_then(|id| sources.iter().find(|s| &s.evidence_id == id));
        let left_env = find(left.first()).map(|s| s.environment.clone());
        let right_env = find(right.first()).map(|s| s.environment.clone());
        let incompatible = matches!(left_env, Some(None))
            || matches!(right_env, Some(None))
            || serde_json::to_string(&left_env).ok() != serde_json::to_string(&right_env).ok();
        if incompatible {
            limitations.push("Controlled replay environments are unavailable or incompatible.".to_string());
        }
    }
    limitations
}

fn evaluate_claim(
    claim: &Claim,
    records: &BTreeMap<&str, &Evidence>,
    heads: &BTreeMap<String, ResidualUnknown>,
) -> Result<Value, JsError> {
    let comparison = records
        .get(claim.comparison_evidence_id.as_str())
        .ok_or_else(|| invalid(format!("Missing comparison Evidence {}", claim.comparison_evidence_id)))?;
    validate_comparison_identity(claim, comparison)?;
    let (left, right) = comparison_sides(comparison)?;
    let all_sources = unique_sorted(left.iter().chain(&right).cloned());
    if unique_sorted(comparison.evidence_links.iter().cloned()) != all_sources {
        return Err(invalid("Comparison Evidence closure disagrees with its parameters"));
    }
    let sources: Vec<&Evidence> = all_sources
        .iter()
        .map(|id| {
            records
                .get(id.as_str())
                .copied()
                .ok_or_else(|| invalid(format!("Missing source Evidence {id}")))
        })
        .collect::<Result<_, _>>()?;
    validate_source_kinds(claim, &sources)?;
    let observed = observed_status(claim, comparison)?;
    let limitations = authority_limitations(claim, &sources, &left, &right);
    let unknowns = claim_unknowns(heads, &comparison.evidence_id, &all_sources);
    let status = if !limitations.is_empty() {
        "unknown"
    } else if ["changed", "added", "removed", "contradiction"].contains(&observed.as_str()) {
        "fail"
    } else if observed == "unknown" || observed == "truncated" || !unknowns.is_empty() {
        "unknown"
    } else {
        "pass"
    };
    let all_limitations = unique_sorted(
        comparison
            .limitations
            .iter()
            .cloned()
            .chain(limitations)
            .chain(unknowns.iter().map(|u| format!("Residual unknown: {}", u.question))),
    );
    Ok(json!({
        "claim_id": claim.claim_id,
        "kind": claim.kind,
        "dimension": claim.dimension,
        "status": status,
        "observed_status": observed,
        "comparison_evidence_id": comparison.evidence_id,
        "left_evidence_ids": left,
        "right_evidence_ids": right,
        "evidence_links": unique_sorted(std::iter::once(comparison.evidence_id.clone()).chain(all_sources)),
        "unknown_ids": unknowns.iter().map(|u| u.unknown_id.clone()).collect::<Vec<_>>(),
        "limitations": all_limitations,
    }))
}

fn default_probe(kind: &str) -> (&'static str, &'static str) {
    match kind {
        "behavioral" => (
            "capture_process_scenario",
            "Repeat both scenarios under one controlled environment.",
        ),
        "structural-function" => (
            "analyze_function",
            "Capture complete function dossiers under equal limits.",
        ),
        _ => (
            "inspect_artifact",
            "Capture complete artifact inventories under equal limits.",
        ),
    }
}

type ProbeEntry = (String, String, Vec<String>, Vec<String>);

/// `reconstructionProbes`.
fn probes(results: &[Value], heads: &BTreeMap<String, ResidualUnknown>) -> Vec<Value> {
    let mut output: BTreeMap<String, ProbeEntry> = BTreeMap::new();
    for result in results.iter().filter(|r| r["status"] == "unknown") {
        let unknown_ids: Vec<String> = result["unknown_ids"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|id| id.as_str().map(str::to_string))
            .collect();
        let mut candidates: Vec<(String, String)> = unknown_ids
            .iter()
            .filter_map(|id| heads.get(id))
            .flat_map(|u| u.recommended_probes.iter().map(|p| (p.operation.clone(), p.rationale.clone())))
            .collect();
        if candidates.is_empty() {
            let (operation, rationale) = default_probe(result["kind"].as_str().unwrap_or_default());
            candidates.push((operation.to_string(), rationale.to_string()));
        }
        let claim_id = result["claim_id"].as_str().unwrap_or_default().to_string();
        for (operation, rationale) in candidates {
            let key = composite_key(&[&operation, &rationale]);
            let entry = output
                .entry(key)
                .or_insert_with(|| (operation.clone(), rationale.clone(), vec![], vec![]));
            entry.2 = unique_sorted(entry.2.iter().cloned().chain(std::iter::once(claim_id.clone())));
            entry.3 = unique_sorted(entry.3.iter().cloned().chain(unknown_ids.iter().cloned()));
        }
    }
    let mut sorted: Vec<(String, ProbeEntry)> = output.into_iter().collect();
    sorted.sort_by(|a, b| compare_unicode_code_points(&a.0, &b.0));
    sorted
        .into_iter()
        .map(|(_, (operation, rationale, claim_ids, unknown_ids))| {
            json!({
                "operation": operation,
                "rationale": rationale,
                "claim_ids": claim_ids,
                "unknown_ids": unknown_ids,
            })
        })
        .collect()
}

/// `verifyReconstruction` against the session-owned Evidence bundle.
pub fn verification_result(specification: &Value, bundle: &EvidenceBundle) -> Result<Value, JsError> {
    let (name, claims) = parse_specification(specification)?;
    let records: BTreeMap<&str, &Evidence> = bundle.records.iter().map(|e| (e.evidence_id.as_str(), e)).collect();
    let heads = unknown_heads(&bundle.unknowns);
    let mut results: Vec<Value> = claims
        .iter()
        .map(|claim| evaluate_claim(claim, &records, &heads))
        .collect::<Result<_, _>>()?;
    results.sort_by(|a, b| {
        compare_unicode_code_points(
            a["claim_id"].as_str().unwrap_or_default(),
            b["claim_id"].as_str().unwrap_or_default(),
        )
    });
    let count = |status: &str| results.iter().filter(|r| r["status"] == status).count();
    let failed = count("fail");
    let unresolved = count("unknown");
    let recommended = probes(&results, &heads);
    let links = unique_sorted(results.iter().flat_map(|r| {
        r["evidence_links"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|id| id.as_str().map(str::to_string))
    }));
    let mut sorted_claims: Vec<&Claim> = claims.iter().collect();
    sorted_claims.sort_by(|a, b| compare_unicode_code_points(&a.claim_id, &b.claim_id));
    let specification_sha256 = digest(&json!({
        "name": name,
        "claims": sorted_claims.iter().map(|c| claim_value(c)).collect::<Vec<_>>(),
    }))?;
    let behavioral = results.iter().filter(|r| r["kind"] == "behavioral").count();
    Ok(json!({
        "status": if failed > 0 { "fail" } else if unresolved > 0 { "unknown" } else { "pass" },
        "specification_sha256": specification_sha256,
        "summary": {
            "total": results.len(),
            "passed": count("pass"),
            "failed": failed,
            "unknown": unresolved,
            "behavioral": behavioral,
            "structural": results.len() - behavioral,
        },
        "claims": { "items": results },
        "recommended_probes": recommended,
        "evidence_links": links,
        "limitations": [
            "Pass means every declared claim passed; it does not establish global implementation equivalence."
        ],
    }))
}

/// Full `verify_reconstruction` workflow over the session bundle.
pub fn verify_reconstruction(
    specification: &Value,
    bundle: &EvidenceBundle,
    closure: &ClosureFn<'_>,
) -> Result<WorkflowOutcome, JsError> {
    let result = verification_result(specification, bundle)?;
    let result_links: Vec<String> = serde_json::from_value(result["evidence_links"].clone())?;
    let links = closure(&result_links)?;
    let status = result["status"].as_str().unwrap_or("unknown").to_string();
    let limitations: Vec<String> = serde_json::from_value(result["limitations"].clone())?;
    let probes: Vec<(String, String)> = result["recommended_probes"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|p| {
            (
                p["operation"].as_str().unwrap_or_default().to_string(),
                p["rationale"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let claim_ids: Vec<Value> = specification["claims"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|c| c["claim_id"].clone())
        .collect();
    let evidence = derived_evidence(
        ("rea-reconstruction-verifier", "REA reconstruction verifier"),
        "rea.reconstruction-verification",
        "verify_reconstruction",
        json!({
            "specification_sha256": result["specification_sha256"],
            "claim_ids": claim_ids,
        }),
        result,
        EvidenceConfidence::Derived,
        limitations,
        links,
    )?;
    let unknown = (status == "unknown").then(|| {
        workflow_unknown(
            &evidence,
            "Does the reconstruction satisfy every declared claim?",
            "reconstruction-verification",
            None,
            EvidenceConfidence::Derived,
            probes,
        )
    });
    Ok(WorkflowOutcome { evidence, unknown })
}
