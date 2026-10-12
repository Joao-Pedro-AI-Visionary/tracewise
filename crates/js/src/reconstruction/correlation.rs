//! Port of REA `domain/staticRuntimeCorrelation.ts` plus the
//! `correlate_static_and_runtime` registration.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};
use tracewise_domain::evidence::{Evidence, EvidenceAuthority, EvidenceConfidence};

use super::common::*;
use crate::error::JsError;

const EXPECTED_PATTERNS: [&str; 4] = ["cochanged", "static_only", "runtime_only", "both_unchanged"];

struct Mapping {
    static_id: String,
    selector: Value,
    runtime_id: String,
    dimension: String,
    side_alignment: String,
    statement: String,
    expected: String,
}

fn strict_object<'a>(value: &'a Value, keys: &[&str], label: &str) -> Result<&'a Map<String, Value>, JsError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{label} must be an object")))?;
    if let Some(extra) = object.keys().find(|key| !keys.contains(&key.as_str())) {
        return Err(invalid(format!("{label} has unexpected property {extra}")));
    }
    for key in keys {
        if !object.contains_key(*key) {
            return Err(invalid(format!("{label} requires {key}")));
        }
    }
    Ok(object)
}

fn evidence_id_field(object: &Map<String, Value>, key: &str, label: &str) -> Result<String, JsError> {
    match object.get(key).and_then(Value::as_str) {
        Some(id) if is_evidence_id(id) => Ok(id.to_string()),
        _ => Err(invalid(format!("{label}.{key} must be an Evidence identifier"))),
    }
}

fn enum_field(object: &Map<String, Value>, key: &str, allowed: &[&str], label: &str) -> Result<String, JsError> {
    match object.get(key).and_then(Value::as_str) {
        Some(value) if allowed.contains(&value) => Ok(value.to_string()),
        _ => Err(invalid(format!("{label}.{key} is invalid"))),
    }
}

fn parse_mapping(value: &Value) -> Result<Mapping, JsError> {
    let mapping = strict_object(value, &["static", "runtime", "side_alignment", "hypothesis"], "mapping")?;
    let static_side = strict_object(&mapping["static"], &["comparison_evidence_id", "selector"], "mapping.static")?;
    let static_id = evidence_id_field(static_side, "comparison_evidence_id", "mapping.static")?;
    let selector_value = &static_side["selector"];
    let selector = match selector_value.get("kind").and_then(Value::as_str) {
        Some("artifact") => {
            let object = strict_object(selector_value, &["kind", "logical_path"], "selector")?;
            match object.get("logical_path").and_then(Value::as_str) {
                Some(path) if !path.is_empty() => json!({ "kind": "artifact", "logical_path": path }),
                _ => return Err(invalid("selector.logical_path must be a non-empty string")),
            }
        }
        Some("function") => {
            let object = strict_object(selector_value, &["kind", "dimension"], "selector")?;
            json!({ "kind": "function", "dimension": enum_field(object, "dimension", &FUNCTION_DIMENSIONS, "selector")? })
        }
        _ => return Err(invalid("selector.kind must be artifact or function")),
    };
    let runtime = strict_object(&mapping["runtime"], &["comparison_evidence_id", "dimension"], "mapping.runtime")?;
    let runtime_id = evidence_id_field(runtime, "comparison_evidence_id", "mapping.runtime")?;
    let dimension = enum_field(runtime, "dimension", &PROCESS_DIMENSIONS, "mapping.runtime")?;
    let side_alignment = enum_field(mapping, "side_alignment", &["left_to_left", "left_to_right"], "mapping")?;
    let hypothesis = strict_object(&mapping["hypothesis"], &["statement", "expected_pattern"], "mapping.hypothesis")?;
    let statement = hypothesis
        .get("statement")
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid("mapping.hypothesis.statement must be non-empty"))?;
    let expected = enum_field(hypothesis, "expected_pattern", &EXPECTED_PATTERNS, "mapping.hypothesis")?;
    Ok(Mapping { static_id, selector, runtime_id, dimension, side_alignment, statement, expected })
}

fn assert_comparison_identity(evidence: &Evidence) -> Result<(), JsError> {
    let ok = match evidence.operation.as_str() {
        "compare_artifacts" => {
            evidence.predicate_type == "rea.artifact-comparison"
                && provider_is(evidence, "rea-artifact-comparison", "REA artifact comparison", "1")
        }
        "compare_functions" => {
            evidence.predicate_type == "rea.function-comparison"
                && provider_is(evidence, "rea-function-comparison", "REA function comparison", "1")
        }
        "compare_process_captures" => {
            evidence.predicate_type == "rea.process-comparison" && is_process_provider(evidence)
        }
        _ => false,
    };
    if !ok
        || evidence.confidence != EvidenceConfidence::Derived
        || evidence.authority != EvidenceAuthority::AnalystInference
        || evidence.subject.is_some()
    {
        return Err(invalid(
            "Comparison Evidence operation, predicate, provider, or citations disagree",
        ));
    }
    let expected = comparison_source_ids(evidence)?;
    let actual = unique_sorted(evidence.evidence_links.iter().cloned());
    if expected != actual {
        return Err(invalid("Comparison Evidence closure disagrees with its source parameters"));
    }
    Ok(())
}

fn assert_nested(evidence: &Evidence, nested: &[&String]) -> Result<(), JsError> {
    let closure: BTreeSet<&String> = evidence.evidence_links.iter().collect();
    if nested.iter().any(|id| !closure.contains(id)) {
        return Err(invalid("Comparison finding cites Evidence outside its top-level closure"));
    }
    Ok(())
}

fn parse_static(value: &Value) -> Result<Evidence, JsError> {
    let evidence = parse_evidence(value)?;
    if evidence.operation != "compare_artifacts" && evidence.operation != "compare_functions" {
        return Err(invalid(
            "Static/runtime correlation requires artifact or function comparison Evidence",
        ));
    }
    assert_comparison_identity(&evidence)?;
    if evidence.operation == "compare_artifacts" {
        let result = parse_artifact_comparison(&evidence.normalized_result)?;
        let nested: Vec<&String> = result.changes.iter().flat_map(|c| &c.evidence_links).collect();
        assert_nested(&evidence, &nested)?;
    } else {
        let result = parse_function_comparison(&evidence.normalized_result)?;
        let nested: Vec<&String> = result.dimensions.iter().flat_map(|d| &d.evidence_links).collect();
        assert_nested(&evidence, &nested)?;
    }
    Ok(evidence)
}

fn parse_runtime(value: &Value) -> Result<Evidence, JsError> {
    let evidence = parse_evidence(value)?;
    if evidence.operation != "compare_process_captures" {
        return Err(invalid("Static/runtime correlation requires process comparison Evidence"));
    }
    assert_comparison_identity(&evidence)?;
    parse_process_comparison(&evidence.normalized_result)?;
    Ok(evidence)
}

fn select_static(evidence: &Evidence, selector: &Value) -> Result<(String, &'static str), JsError> {
    if selector["kind"] == "function" {
        if evidence.operation != "compare_functions" {
            return Err(invalid("Function selector requires function comparison Evidence"));
        }
        let result = parse_function_comparison(&evidence.normalized_result)?;
        let matches: Vec<_> = result
            .dimensions
            .iter()
            .filter(|d| Some(d.dimension.as_str()) == selector["dimension"].as_str())
            .collect();
        if matches.len() != 1 {
            return Err(invalid("Function selector must resolve exactly once"));
        }
        let kind = match matches[0].conclusion_kind.as_str() {
            "contradiction" => "contradiction",
            "unresolved_branch" => "unresolved_branch",
            _ => "derived_relationship",
        };
        return Ok((matches[0].status.clone(), kind));
    }
    if evidence.operation != "compare_artifacts" {
        return Err(invalid("Artifact selector requires artifact comparison Evidence"));
    }
    let result = parse_artifact_comparison(&evidence.normalized_result)?;
    let matches: Vec<_> = result
        .changes
        .iter()
        .filter(|c| Some(c.logical_path.as_str()) == selector["logical_path"].as_str())
        .collect();
    if matches.len() != 1 {
        return Err(invalid("Artifact selector must resolve exactly one reported delta"));
    }
    let status = matches[0].classification.clone();
    let kind = match status.as_str() {
        "contradiction" => "contradiction",
        "unknown" => "unresolved_branch",
        _ => "derived_relationship",
    };
    Ok((status, kind))
}

fn observed_pattern(static_status: &str, runtime_status: &str) -> &'static str {
    if static_status == "truncated" || runtime_status == "truncated" {
        return "truncated";
    }
    if static_status == "unknown" || runtime_status == "unknown" {
        return "unknown";
    }
    match (static_status != "unchanged", runtime_status != "unchanged") {
        (true, true) => "cochanged",
        (true, false) => "static_only",
        (false, true) => "runtime_only",
        (false, false) => "both_unchanged",
    }
}

fn correlate(
    mapping: &Mapping,
    statics: &BTreeMap<String, Evidence>,
    runtimes: &BTreeMap<String, Evidence>,
) -> Result<Value, JsError> {
    let static_evidence = statics
        .get(&mapping.static_id)
        .ok_or_else(|| invalid("Mapping references absent static comparison Evidence"))?;
    let runtime_evidence = runtimes
        .get(&mapping.runtime_id)
        .ok_or_else(|| invalid("Mapping references absent runtime comparison Evidence"))?;
    let (static_status, conclusion_kind) = select_static(static_evidence, &mapping.selector)?;
    let process = parse_process_comparison(&runtime_evidence.normalized_result)?;
    let runtime_status = process.dimension(&mapping.dimension).to_string();
    let pattern = observed_pattern(&static_status, &runtime_status);
    let classification = if pattern == "unknown" || pattern == "truncated" {
        "unresolved_branch"
    } else if pattern == mapping.expected {
        "hypothesis"
    } else {
        "contradiction"
    };
    let static_projection = json!({
        "comparison_evidence_id": mapping.static_id,
        "selector": mapping.selector,
    });
    let runtime_projection = json!({
        "comparison_evidence_id": mapping.runtime_id,
        "dimension": mapping.dimension,
    });
    let hypothesis = json!({ "statement": mapping.statement, "expected_pattern": mapping.expected });
    let projection = json!({
        "static": static_projection,
        "runtime": runtime_projection,
        "side_alignment": mapping.side_alignment,
        "hypothesis": hypothesis,
    });
    let mut limitations: Vec<String> = static_evidence
        .limitations
        .iter()
        .chain(&runtime_evidence.limitations)
        .chain(&process.limitations)
        .cloned()
        .collect();
    limitations.push("This correlation tests an explicit hypothesis and does not establish causality.".into());
    limitations.push(
        "Side alignment is caller-declared and was not independently validated against source subjects or environments."
            .into(),
    );
    Ok(json!({
        "correlation_id": format!("cor_{}", digest(&projection)?),
        "static": {
            "comparison_evidence_id": mapping.static_id,
            "selector": mapping.selector,
            "status": static_status,
            "conclusion_kind": conclusion_kind,
        },
        "runtime": {
            "comparison_evidence_id": mapping.runtime_id,
            "dimension": mapping.dimension,
            "status": runtime_status,
        },
        "side_alignment": mapping.side_alignment,
        "hypothesis": hypothesis,
        "observed_pattern": pattern,
        "classification": classification,
        "evidence_links": unique_sorted(
            std::iter::once(static_evidence.evidence_id.clone())
                .chain(static_evidence.evidence_links.iter().cloned())
                .chain(std::iter::once(runtime_evidence.evidence_id.clone()))
                .chain(runtime_evidence.evidence_links.iter().cloned()),
        ),
        "limitations": unique_sorted(limitations),
    }))
}

fn array<'a>(args: &'a Value, key: &str) -> Result<&'a Vec<Value>, JsError> {
    match args.get(key).and_then(Value::as_array) {
        Some(items) if !items.is_empty() => Ok(items),
        _ => Err(invalid(format!("correlate_static_and_runtime requires a non-empty {key}"))),
    }
}

/// `correlateStaticAndRuntime` over inline (already resolved) inputs.
pub fn correlation_result(args: &Value) -> Result<Value, JsError> {
    strict_object(args, &["static_comparisons", "runtime_comparisons", "mappings"], "input")?;
    let mappings: Vec<Mapping> = array(args, "mappings")?.iter().map(parse_mapping).collect::<Result<_, _>>()?;
    let statics: Vec<Evidence> = array(args, "static_comparisons")?.iter().map(parse_static).collect::<Result<_, _>>()?;
    let runtimes: Vec<Evidence> = array(args, "runtime_comparisons")?.iter().map(parse_runtime).collect::<Result<_, _>>()?;
    let by_id = |items: Vec<Evidence>, label: &str| -> Result<BTreeMap<String, Evidence>, JsError> {
        let count = items.len();
        let map: BTreeMap<String, Evidence> = items.into_iter().map(|e| (e.evidence_id.clone(), e)).collect();
        if map.len() != count {
            return Err(invalid(format!("Static/runtime correlation rejects duplicate {label}")));
        }
        Ok(map)
    };
    let statics = by_id(statics, "static comparison Evidence")?;
    let runtimes = by_id(runtimes, "runtime comparison Evidence")?;
    let mut correlations: Vec<Value> = mappings
        .iter()
        .map(|mapping| correlate(mapping, &statics, &runtimes))
        .collect::<Result<_, _>>()?;
    correlations.sort_by(|a, b| {
        compare_unicode_code_points(
            a["correlation_id"].as_str().unwrap_or_default(),
            b["correlation_id"].as_str().unwrap_or_default(),
        )
    });
    let ids: BTreeSet<&str> = correlations.iter().filter_map(|c| c["correlation_id"].as_str()).collect();
    if ids.len() != correlations.len() {
        return Err(invalid("Static/runtime correlation rejects duplicate mappings"));
    }
    let links = unique_sorted(correlations.iter().flat_map(|c| {
        c["evidence_links"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|id| id.as_str().map(str::to_string))
    }));
    let count = |class: &str| correlations.iter().filter(|c| c["classification"] == class).count();
    let unresolved = count("unresolved_branch");
    let contradictions = count("contradiction");
    let status = if correlations.iter().any(|c| c["observed_pattern"] == "truncated") {
        "truncated"
    } else if unresolved > 0 {
        "unknown"
    } else if contradictions > 0 {
        "contradicted"
    } else {
        "correlated"
    };
    Ok(json!({
        "status": status,
        "summary": {
            "hypotheses": correlations.len() - contradictions - unresolved,
            "contradictions": contradictions,
            "unresolved": unresolved,
        },
        "correlations": { "items": correlations },
        "evidence_links": links,
        "limitations": [
            "Mappings are caller-declared hypotheses; consistency does not establish causality.",
            "Only explicit mappings were evaluated; similar unmapped observations were not correlated.",
        ],
    }))
}

/// Full `correlate_static_and_runtime` workflow (inputs already resolved to inline Evidence).
pub fn correlate_static_and_runtime(args: &Value, closure: &ClosureFn<'_>) -> Result<WorkflowOutcome, JsError> {
    let mut seeds = Vec::new();
    for key in ["static_comparisons", "runtime_comparisons"] {
        for value in array(args, key)? {
            let evidence = parse_evidence(value)?;
            seeds.push(evidence.evidence_id.clone());
            seeds.extend(evidence.evidence_links.iter().cloned());
        }
    }
    let links = closure(&unique_sorted(seeds))?;
    let result = correlation_result(args)?;
    let status = result["status"].as_str().unwrap_or("unknown").to_string();
    let limitations: Vec<String> = serde_json::from_value(result["limitations"].clone())?;
    let evidence = derived_evidence(
        ("rea-static-runtime-correlation", "REA static/runtime correlation"),
        "rea.static-runtime-correlation",
        "correlate_static_and_runtime",
        json!({ "mapping_count": array(args, "mappings")?.len() }),
        result,
        EvidenceConfidence::Inferred,
        limitations,
        links,
    )?;
    let unknown = (status == "unknown" || status == "truncated").then(|| {
        workflow_unknown(
            &evidence,
            "Does runtime behavior match the available static analysis?",
            "static-runtime-correlation",
            None,
            EvidenceConfidence::Derived,
            vec![(
                "capture_process_scenario".into(),
                "Repeat runtime observations and complete the mapped static comparison Evidence.".into(),
            )],
        )
    });
    Ok(WorkflowOutcome { evidence, unknown })
}
