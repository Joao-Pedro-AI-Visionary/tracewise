//! Port of REA `domain/changedBehavior.ts` plus the `find_changed_behavior`
//! registration in `server/registerInvestigationTools.ts`.

use std::collections::BTreeSet;

use serde_json::{json, Value};
use tracewise_domain::evidence::{Evidence, EvidenceAuthority, EvidenceConfidence};

use super::common::*;
use crate::error::JsError;

struct Finding {
    scope: &'static str,
    dimension: String,
    classification: &'static str,
    status: String,
    source: String,
    links: Vec<String>,
    limitations: Vec<String>,
}

impl Finding {
    fn to_value(&self) -> Value {
        json!({
            "scope": self.scope,
            "dimension": self.dimension,
            "classification": self.classification,
            "status": self.status,
            "source_comparison_id": self.source,
            "evidence_links": self.links,
            "limitations": self.limitations,
        })
    }
}

fn make_finding(
    evidence: &Evidence,
    dimension: String,
    scope: &'static str,
    status: &str,
    classification: &'static str,
    limitations: &[String],
    links: Option<&[String]>,
) -> Finding {
    let cited = links.unwrap_or(&evidence.evidence_links);
    Finding {
        scope,
        dimension,
        classification,
        status: status.to_string(),
        source: evidence.evidence_id.clone(),
        links: unique_sorted(std::iter::once(evidence.evidence_id.clone()).chain(cited.iter().cloned())),
        limitations: unique_sorted(limitations.iter().cloned()),
    }
}

fn is_change(status: &str) -> bool {
    matches!(status, "added" | "removed" | "changed")
}

/// Input Evidence for a comparison (inline evidence already resolved by the server).
pub fn parse_comparison(value: &Value) -> Result<Evidence, JsError> {
    let evidence = parse_evidence(value)?;
    let (predicate, process) = match evidence.operation.as_str() {
        "compare_process_captures" => ("rea.process-comparison", true),
        "compare_artifacts" => ("rea.artifact-comparison", false),
        "compare_functions" => ("rea.function-comparison", false),
        _ => {
            return Err(invalid(
                "Changed-behavior analysis requires process, artifact, or function comparison Evidence",
            ))
        }
    };
    let provider_ok = if process {
        is_process_provider(&evidence)
    } else if evidence.operation == "compare_artifacts" {
        provider_is(&evidence, "rea-artifact-comparison", "REA artifact comparison", "1")
    } else {
        provider_is(&evidence, "rea-function-comparison", "REA function comparison", "1")
    };
    if evidence.predicate_type != predicate
        || !provider_ok
        || evidence.confidence != EvidenceConfidence::Derived
        || evidence.authority != EvidenceAuthority::AnalystInference
        || evidence.subject.is_some()
    {
        return Err(invalid("Comparison Evidence operation, predicate, and provider disagree"));
    }
    if !comparison_source_ids(&evidence)?
        .iter()
        .all(|id| evidence.evidence_links.contains(id))
    {
        return Err(invalid("Comparison Evidence must cite both selected source observations"));
    }
    let top: BTreeSet<&String> = evidence.evidence_links.iter().collect();
    match evidence.operation.as_str() {
        "compare_process_captures" => {
            parse_process_comparison(&evidence.normalized_result)?;
        }
        "compare_functions" => {
            let result = parse_function_comparison(&evidence.normalized_result)?;
            if result.dimensions.iter().flat_map(|d| &d.evidence_links).any(|id| !top.contains(id)) {
                return Err(invalid("Comparison finding cites Evidence outside its top-level closure"));
            }
        }
        _ => {
            let result = parse_artifact_comparison(&evidence.normalized_result)?;
            if result.changes.iter().flat_map(|c| &c.evidence_links).any(|id| !top.contains(id)) {
                return Err(invalid("Comparison finding cites Evidence outside its top-level closure"));
            }
        }
    }
    Ok(evidence)
}

fn findings_for(evidence: &Evidence) -> Result<Vec<Finding>, JsError> {
    match evidence.operation.as_str() {
        "compare_process_captures" => {
            let result = parse_process_comparison(&evidence.normalized_result)?;
            let scopes = [
                ("terminal", "runtime"),
                ("interaction", "runtime"),
                ("exit", "runtime"),
                ("filesystem", "resource"),
                ("process", "runtime"),
            ];
            Ok(scopes
                .iter()
                .filter_map(|(dimension, scope)| {
                    let status = result.dimension(dimension);
                    (status != "unchanged").then(|| {
                        make_finding(
                            evidence,
                            dimension.to_string(),
                            scope,
                            status,
                            if is_change(status) { "observed_change" } else { "unresolved_branch" },
                            &result.limitations,
                            None,
                        )
                    })
                })
                .collect())
        }
        "compare_functions" => {
            let result = parse_function_comparison(&evidence.normalized_result)?;
            Ok(result
                .dimensions
                .iter()
                .filter(|d| d.status != "unchanged")
                .map(|d| {
                    let classification = if d.status == "unknown" {
                        "unresolved_branch"
                    } else if d.conclusion_kind == "contradiction" {
                        "contradiction"
                    } else {
                        "derived_relationship"
                    };
                    make_finding(
                        evidence,
                        d.dimension.clone(),
                        "static_candidate",
                        &d.status,
                        classification,
                        &d.limitations,
                        Some(&d.evidence_links),
                    )
                })
                .collect())
        }
        _ => {
            let result = parse_artifact_comparison(&evidence.normalized_result)?;
            let mut changes: Vec<Finding> = result
                .changes
                .iter()
                .map(|change| {
                    let classification = match change.classification.as_str() {
                        "contradiction" => "contradiction",
                        "unknown" => "unresolved_branch",
                        _ => "derived_relationship",
                    };
                    make_finding(
                        evidence,
                        format!("artifact:{}", change.logical_path),
                        "static_candidate",
                        &change.classification,
                        classification,
                        &result.limitations,
                        Some(&change.evidence_links),
                    )
                })
                .collect();
            if (result.status == "unknown" || result.status == "truncated")
                && !changes.iter().any(|f| f.classification == "unresolved_branch")
            {
                changes.push(make_finding(
                    evidence,
                    "artifact:coverage".to_string(),
                    "static_candidate",
                    &result.status,
                    "unresolved_branch",
                    &result.limitations,
                    None,
                ));
            }
            Ok(changes)
        }
    }
}

/// `findChangedBehavior`: the deterministic aggregate result.
pub fn changed_behavior_result(comparisons: &[Evidence]) -> Result<Value, JsError> {
    if comparisons.is_empty() {
        return Err(invalid("find_changed_behavior requires at least one comparison"));
    }
    let ids: BTreeSet<&String> = comparisons.iter().map(|e| &e.evidence_id).collect();
    if ids.len() != comparisons.len() {
        return Err(invalid("Changed-behavior analysis rejects duplicate comparison Evidence"));
    }
    let mut findings = Vec::new();
    for evidence in comparisons {
        findings.extend(findings_for(evidence)?);
    }
    findings.sort_by(|left, right| {
        compare_unicode_code_points(
            &composite_key(&[left.scope, &left.dimension, &left.source]),
            &composite_key(&[right.scope, &right.dimension, &right.source]),
        )
    });
    let mut runtime = Vec::new();
    for evidence in comparisons.iter().filter(|e| e.operation == "compare_process_captures") {
        runtime.push(parse_process_comparison(&evidence.normalized_result)?.status);
    }
    let behavior_status = if runtime.is_empty() {
        "unknown"
    } else if runtime.iter().any(|s| s == "truncated") {
        "truncated"
    } else if runtime.iter().any(|s| s == "unknown") {
        "unknown"
    } else if runtime.iter().any(|s| is_change(s)) {
        "observed_changed"
    } else {
        "observed_unchanged"
    };
    let links = unique_sorted(
        comparisons
            .iter()
            .flat_map(|e| std::iter::once(e.evidence_id.clone()).chain(e.evidence_links.iter().cloned())),
    );
    let mut limitations: Vec<String> = comparisons.iter().flat_map(|e| e.limitations.iter().cloned()).collect();
    if comparisons.iter().any(|e| e.operation != "compare_process_captures") {
        limitations.push("Static differences are behavior candidates, not runtime observations.".into());
    }
    if runtime.is_empty() {
        limitations.push("No process comparison Evidence was supplied.".into());
    }
    if links.len() < 2 {
        return Err(invalid("Changed-behavior result must cite at least two Evidence records"));
    }
    let count = |c: &str| findings.iter().filter(|f| f.classification == c).count();
    Ok(json!({
        "behavior_status": behavior_status,
        "summary": {
            "observed_changes": count("observed_change"),
            "static_candidates": count("derived_relationship"),
            "contradictions": count("contradiction"),
            "unresolved": count("unresolved_branch"),
        },
        "findings": { "items": findings.iter().map(Finding::to_value).collect::<Vec<_>>() },
        "evidence_links": links,
        "limitations": unique_sorted(limitations),
    }))
}

/// Full `find_changed_behavior` workflow over resolved comparison Evidence.
pub fn find_changed_behavior(comparison_values: &[Value], closure: &ClosureFn<'_>) -> Result<WorkflowOutcome, JsError> {
    if comparison_values.is_empty() {
        return Err(invalid("find_changed_behavior requires at least one comparison"));
    }
    let raw: Vec<Evidence> = comparison_values.iter().map(parse_evidence).collect::<Result<_, _>>()?;
    let seeds = unique_sorted(
        raw.iter()
            .flat_map(|e| std::iter::once(e.evidence_id.clone()).chain(e.evidence_links.iter().cloned())),
    );
    let links = closure(&seeds)?;
    let comparisons: Vec<Evidence> = comparison_values.iter().map(parse_comparison).collect::<Result<_, _>>()?;
    let result = changed_behavior_result(&comparisons)?;
    let status = result["behavior_status"].as_str().unwrap_or("unknown").to_string();
    let limitations: Vec<String> = serde_json::from_value(result["limitations"].clone())?;
    let evidence = derived_evidence(
        ("rea-changed-behavior", "REA changed behavior investigation"),
        "rea.changed-behavior",
        "find_changed_behavior",
        json!({ "comparison_evidence_ids": comparisons.iter().map(|e| e.evidence_id.clone()).collect::<Vec<_>>() }),
        result,
        EvidenceConfidence::Derived,
        limitations,
        links,
    )?;
    let unknown = (status == "unknown" || status == "truncated").then(|| {
        workflow_unknown(
            &evidence,
            "Did both versions behave the same under a complete controlled replay?",
            "changed-behavior",
            Some(EvidenceAuthority::ControlledReplay),
            EvidenceConfidence::Observed,
            vec![(
                "capture_process_scenario".into(),
                "Capture both versions under the same bounded scenario and environment.".into(),
            )],
        )
    });
    Ok(WorkflowOutcome { evidence, unknown })
}
