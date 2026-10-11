//! Step-aligned browser scenario comparison (port of REA domain/browserScenarioDiff.ts).
//!
//! This is the scenario branch of `compare_web_captures`. Missing or truncated
//! evidence stays unknown; it is never treated as equality.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};
use tracewise_domain::canonical_sha256;
use tracewise_domain::evidence::{
    create_evidence, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation, EvidenceProvider,
};

use crate::error::WebError;
use crate::runtime_cdp::input_error;

const OPERATION: &str = "compare_web_captures";
const ARTIFACTS: [&str; 8] = [
    "action_state",
    "screenshot",
    "dom",
    "accessibility",
    "url",
    "history",
    "storage",
    "events",
];
const BUILT_IN_RULES: [&str; 5] = [
    "ignore_step_elapsed_ms",
    "ignore_event_sequence",
    "ignore_event_step_index",
    "compare_screenshot_content_digest",
    "compare_normalized_text_content",
];
const EVENT_SECTIONS: [&str; 5] = ["events", "frames", "workers", "popups", "websockets"];

pub fn compare_browser_scenarios(args: &Value) -> Result<Evidence, WebError> {
    let object = args.as_object().ok_or_else(|| input_error(OPERATION, "", "Expected an object"))?;
    for key in object.keys() {
        if key != "before_scenario" && key != "after_scenario" && key != "normalization" {
            return Err(input_error(OPERATION, key, format!("Unrecognized key: \"{key}\"")));
        }
    }
    let before = required_capture(object.get("before_scenario"), "before_scenario")?;
    let after = required_capture(object.get("after_scenario"), "after_scenario")?;
    let rules = parse_rules(object.get("normalization"))?;
    let commitment = json!({ "built_in_rules": BUILT_IN_RULES, "rules": rules });
    let normalization_sha256 = canonical_sha256(&commitment)?;
    let normalization = json!({
        "built_in_rules": BUILT_IN_RULES,
        "rules": rules,
        "sha256": normalization_sha256,
    });
    let diff = compare(before, after, &rules);
    let mut result = diff;
    result.insert("normalization".to_string(), normalization.clone());
    let limitations = result
        .get("limitations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut envelope = vec!["Artifact identity is unavailable for this observation.".to_string()];
    envelope.extend(limitations.iter().filter_map(|item| item.as_str().map(str::to_string)));
    let parameters = json!({
        "comparison_kind": "browser_scenario",
        "before_browser": before.get("browser").cloned().unwrap_or(Value::Null),
        "after_browser": after.get("browser").cloned().unwrap_or(Value::Null),
        "before_start_origin": before.get("scenario").and_then(|item| item.get("start_origin")).cloned().unwrap_or(Value::Null),
        "after_start_origin": after.get("scenario").and_then(|item| item.get("start_origin")).cloned().unwrap_or(Value::Null),
        "normalization_sha256": normalization_sha256,
    });
    let provider = EvidenceProvider {
        id: "rea-cdp-browser".to_string(),
        name: "REA Chrome DevTools Protocol observation provider".to_string(),
        version: Some("2".to_string()),
    };
    let observation = EvidenceObservation {
        predicate_type: Some("rea.web-capture-diff".to_string()),
        operation: OPERATION.to_string(),
        parameters,
        normalized_result: Value::Object(result),
        raw_result: None,
        analysis_profile: None,
        confidence: Some(EvidenceConfidence::Observed),
        authority: Some(EvidenceAuthority::ExternalService),
        environment: None,
        limitations: Some(envelope),
        locations: Some(vec![]),
        evidence_links: Some(vec![]),
    };
    create_evidence(None, provider, observation).map_err(WebError::from)
}

fn compare(before: &Value, after: &Value, rules: &[Value]) -> Map<String, Value> {
    let before_steps = steps_of(before);
    let after_steps = steps_of(after);
    let before_duplicates = duplicates(&before_steps);
    let after_duplicates = duplicates(&after_steps);
    let before_unique = unique_steps(&before_steps, &before_duplicates);
    let after_unique = unique_steps(&after_steps, &after_duplicates);
    let before_only: Vec<String> = before_unique.keys().filter(|id| !after_unique.contains_key(*id)).cloned().collect();
    let after_only: Vec<String> = after_unique.keys().filter(|id| !before_unique.contains_key(*id)).cloned().collect();
    let mut before_only = before_only;
    let mut after_only = after_only;
    before_only.sort();
    after_only.sort();
    let mut failures = Vec::new();
    for step_id in before_duplicates.iter() {
        failures.push(failure("duplicate_before_step_id", Some(step_id), &format!("before capture contains duplicate step_id {step_id}.")));
    }
    for step_id in after_duplicates.iter() {
        failures.push(failure("duplicate_after_step_id", Some(step_id), &format!("after capture contains duplicate step_id {step_id}.")));
    }
    for step_id in &after_only {
        failures.push(failure("missing_before_step", Some(step_id), &format!("Step {step_id} is missing from the before capture.")));
    }
    for step_id in &before_only {
        failures.push(failure("missing_after_step", Some(step_id), &format!("Step {step_id} is missing from the after capture.")));
    }
    if !contexts_match(before, after) {
        failures.push(failure(
            "capture_context_mismatch",
            None,
            "Browser product/version or scenario origin scope differs between captures.",
        ));
    }
    let mut ordered = Vec::new();
    let mut seen = BTreeSet::new();
    for step in &before_steps {
        let Some(step_id) = step.get("step_id").and_then(Value::as_str) else {
            continue;
        };
        if seen.insert(step_id.to_string()) && before_unique.contains_key(step_id) && after_unique.contains_key(step_id) {
            ordered.push(step_id.to_string());
        }
    }
    let network_reason = network_reason(before, after);
    let mut compared_steps = Vec::new();
    let mut total_diffs = 0;
    for step_id in &ordered {
        let before_step = &before_unique[step_id];
        let after_step = &after_unique[step_id];
        if before_step.get("action") != after_step.get("action") {
            let before_action = before_step.get("action").and_then(Value::as_str).unwrap_or("");
            let after_action = after_step.get("action").and_then(Value::as_str).unwrap_or("");
            failures.push(failure(
                "action_mismatch",
                Some(step_id),
                &format!("Aligned step action changed from {before_action} to {after_action}."),
            ));
        }
        let (status, diffs) = compare_step(before, before_step, after, after_step, rules, network_reason);
        total_diffs += diffs.len();
        compared_steps.push(json!({
            "step_id": step_id,
            "before_step_index": before_step.get("step_index").cloned().unwrap_or(Value::from(0)),
            "after_step_index": after_step.get("step_index").cloned().unwrap_or(Value::from(0)),
            "before_action": before_step.get("action").cloned().unwrap_or(Value::String(String::new())),
            "after_action": after_step.get("action").cloned().unwrap_or(Value::String(String::new())),
            "status": status,
            "artifact_diffs": diffs,
        }));
    }
    let alignment_status = if failures.is_empty() {
        "aligned"
    } else if compared_steps.is_empty() {
        "failed"
    } else {
        "partial"
    };
    let equality = before.get("completeness").and_then(|item| item.get("equality_eligible")).and_then(Value::as_bool) == Some(true)
        && after.get("completeness").and_then(|item| item.get("equality_eligible")).and_then(Value::as_bool) == Some(true)
        && alignment_status == "aligned";
    let overall = if compared_steps.iter().any(|step| step.get("status").and_then(Value::as_str) == Some("changed")) {
        "changed"
    } else if compared_steps.iter().any(|step| step.get("status").and_then(Value::as_str) == Some("unknown")) || !equality {
        "unknown"
    } else {
        "unchanged"
    };
    json!({
        "comparison_kind": "browser_scenario",
        "overall_status": overall,
        "alignment": {
            "status": alignment_status,
            "aligned_steps": compared_steps.len(),
            "before_only": before_only,
            "after_only": after_only,
            "failures": failures,
        },
        "steps": compared_steps,
        "artifact_diffs": { "total": total_diffs },
        "limitations": [
            "Steps align only by exact, unique step_id; missing, duplicate, or action-mismatched steps are reported and prevent an unchanged claim.",
            "Only declared literal normalization rules are applied, in canonical rule_id order, to already-redacted durable capture fields.",
            "Elapsed time and event sequence/index values are excluded as volatile; screenshot bytes are compared by content digest.",
            "A changed status proves an observed normalized difference. Missing or truncated evidence, incompatible capture context, or alignment failure prevents an unchanged claim.",
        ],
    })
    .as_object()
    .cloned()
    .unwrap_or_default()
}

fn compare_step(
    before_capture: &Value,
    before_step: &Value,
    after_capture: &Value,
    after_step: &Value,
    rules: &[Value],
    network_reason: Option<&str>,
) -> (String, Vec<Value>) {
    let mut statuses = Vec::new();
    let mut diffs = Vec::new();
    for artifact in ARTIFACTS {
        let (before_state, before_value) = artifact_side(artifact, before_capture, before_step);
        let (after_state, after_value) = artifact_side(artifact, after_capture, after_step);
        if before_state == "not_requested" && after_state == "not_requested" {
            statuses.push("not_compared");
            continue;
        }
        let before_sha = digest_if_captured(artifact, &before_state, before_value.as_ref(), rules);
        let after_sha = digest_if_captured(artifact, &after_state, after_value.as_ref(), rules);
        let incomparable = artifact == "events" && network_reason.is_some();
        if before_state != "captured" || after_state != "captured" || incomparable {
            let reason = if incomparable {
                network_reason.unwrap_or("Network content selections differ.").to_string()
            } else {
                format!("Artifact coverage is not comparable ({before_state} before, {after_state} after).")
            };
            statuses.push("unknown");
            diffs.push(diff(artifact, "unknown", &before_state, &after_state, before_sha, after_sha, Some(reason)));
            continue;
        }
        if before_sha == after_sha {
            statuses.push("unchanged");
        } else {
            statuses.push("changed");
            diffs.push(diff(artifact, "changed", &before_state, &after_state, before_sha, after_sha, None));
        }
    }
    let status = if statuses.contains(&"changed") {
        "changed"
    } else if statuses.contains(&"unknown") {
        "unknown"
    } else {
        "unchanged"
    };
    (status.to_string(), diffs)
}

fn artifact_side<'a>(artifact: &str, capture: &'a Value, step: &'a Value) -> (String, Option<Value>) {
    if artifact == "action_state" {
        let value = json!({
            "action": step.get("action").cloned().unwrap_or(Value::Null),
            "status": step.get("status").cloned().unwrap_or(Value::Null),
            "before_url": step.get("before_url").cloned().unwrap_or(Value::Null),
            "after_url": step.get("after_url").cloned().unwrap_or(Value::Null),
            "error": step.get("error").cloned().unwrap_or(Value::Null),
        });
        return (evidence_state("action", "captured", step), Some(value));
    }
    if artifact == "events" {
        return (event_state(capture, step), Some(events_for(capture, step)));
    }
    let state = step
        .get("artifacts")
        .and_then(|artifacts| artifacts.get(artifact))
        .and_then(|item| item.get("state"))
        .and_then(Value::as_str)
        .unwrap_or("missing");
    let value = step
        .get("artifacts")
        .and_then(|artifacts| artifacts.get(artifact))
        .and_then(|item| item.get("value"))
        .cloned();
    let projected = if artifact == "screenshot" {
        value.map(|shot| {
            json!({
                "sha256": shot.get("sha256").cloned().unwrap_or(Value::Null),
                "bytes": shot.get("bytes").cloned().unwrap_or(Value::Null),
                "media_type": shot.get("media_type").cloned().unwrap_or(Value::Null),
            })
        })
    } else if matches!(artifact, "dom" | "accessibility") {
        value.and_then(|item| item.get("text").cloned())
    } else {
        value
    };
    (evidence_state(artifact, state, step), projected)
}

fn evidence_state(section: &str, state: &str, step: &Value) -> String {
    if state != "captured" {
        return state.to_string();
    }
    if section_listed(step.get("completeness"), "truncated_sections", section) {
        return "truncated".to_string();
    }
    if section_listed(step.get("completeness"), "missing_sections", section) {
        return "missing".to_string();
    }
    "captured".to_string()
}

fn event_state(capture: &Value, step: &Value) -> String {
    let listed = |collection: &str| {
        EVENT_SECTIONS.iter().any(|section| {
            section_listed(capture.get("completeness"), collection, section)
                || section_listed(step.get("completeness"), collection, section)
        })
    };
    let dropped = capture.get("events").and_then(|events| events.get("dropped")).and_then(Value::as_i64).unwrap_or(0);
    if dropped > 0 || listed("truncated_sections") {
        "truncated".to_string()
    } else if listed("missing_sections") {
        "missing".to_string()
    } else {
        "captured".to_string()
    }
}

fn section_listed(completeness: Option<&Value>, collection: &str, section: &str) -> bool {
    completeness
        .and_then(|item| item.get(collection))
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(section)))
}

fn events_for(capture: &Value, step: &Value) -> Value {
    let step_index = step.get("step_index").and_then(Value::as_i64);
    let items = capture
        .get("events")
        .and_then(|events| events.get("items"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let sources: BTreeMap<i64, i64> = items
        .iter()
        .filter_map(|event| {
            Some((
                event.get("sequence").and_then(Value::as_i64)?,
                event.get("step_index").and_then(Value::as_i64)?,
            ))
        })
        .collect();
    let projected: Vec<Value> = items
        .iter()
        .filter_map(|event| {
            let mut projected = event.as_object()?.clone();
            projected.remove("sequence");
            projected.remove("step_index");
            if event.get("kind").and_then(Value::as_str) == Some("network-content") {
                let source = projected.remove("source_event_sequence").and_then(|value| value.as_i64());
                return (source.and_then(|sequence| sources.get(&sequence).copied()) == step_index)
                    .then_some(Value::Object(projected));
            }
            (event.get("step_index").and_then(Value::as_i64) == step_index).then_some(Value::Object(projected))
        })
        .collect();
    Value::Array(projected)
}

fn digest_if_captured(artifact: &str, state: &str, value: Option<&Value>, rules: &[Value]) -> Value {
    if state != "captured" {
        return Value::Null;
    }
    let Some(value) = value else {
        return Value::Null;
    };
    let normalized = normalize(value, artifact, rules);
    canonical_sha256(&normalized).map(Value::String).unwrap_or(Value::Null)
}

fn normalize(value: &Value, artifact: &str, rules: &[Value]) -> Value {
    if artifact == "screenshot" {
        return value.clone();
    }
    match value {
        Value::String(text) => Value::String(rules.iter().fold(text.clone(), |current, rule| {
            let applies = rule
                .get("artifacts")
                .and_then(Value::as_array)
                .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(artifact)));
            if !applies {
                return current;
            }
            let Some(pattern) = rule.get("match").and_then(Value::as_str) else {
                return current;
            };
            let replacement = rule.get("replacement").and_then(Value::as_str).unwrap_or("");
            current.replace(pattern, replacement)
        })),
        Value::Array(items) => Value::Array(items.iter().map(|item| normalize(item, artifact, rules)).collect()),
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, item)| (key.clone(), normalize(item, artifact, rules)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn network_reason<'a>(before: &'a Value, after: &'a Value) -> Option<&'a str> {
    let left = before.get("scenario").and_then(|item| item.get("network_content"));
    let right = after.get("scenario").and_then(|item| item.get("network_content"));
    let differs = ["request_body", "response_body", "header_values"]
        .iter()
        .any(|key| left.and_then(|item| item.get(*key)) != right.and_then(|item| item.get(*key)));
    differs.then_some(
        "Network content selections differ; capture both sides with matching content selection before comparing network evidence.",
    )
}

fn contexts_match(before: &Value, after: &Value) -> bool {
    before.get("browser").and_then(|item| item.get("product")) == after.get("browser").and_then(|item| item.get("product"))
        && before.get("browser").and_then(|item| item.get("version")) == after.get("browser").and_then(|item| item.get("version"))
        && before.get("scenario").and_then(|item| item.get("start_origin"))
            == after.get("scenario").and_then(|item| item.get("start_origin"))
}

fn steps_of(capture: &Value) -> Vec<Value> {
    capture.get("steps").and_then(Value::as_array).cloned().unwrap_or_default()
}

fn duplicates(steps: &[Value]) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut duplicates = BTreeSet::new();
    for step in steps {
        let Some(step_id) = step.get("step_id").and_then(Value::as_str) else {
            continue;
        };
        if !seen.insert(step_id.to_string()) {
            duplicates.insert(step_id.to_string());
        }
    }
    duplicates
}

fn unique_steps(steps: &[Value], duplicates: &BTreeSet<String>) -> BTreeMap<String, Value> {
    steps
        .iter()
        .filter_map(|step| {
            let step_id = step.get("step_id").and_then(Value::as_str)?;
            (!duplicates.contains(step_id)).then(|| (step_id.to_string(), step.clone()))
        })
        .collect()
}

fn failure(code: &str, step_id: Option<&str>, reason: &str) -> Value {
    json!({
        "code": code,
        "step_id": step_id,
        "reason": reason,
    })
}

fn diff(
    artifact: &str,
    status: &str,
    before_state: &str,
    after_state: &str,
    before_sha256: Value,
    after_sha256: Value,
    reason: Option<String>,
) -> Value {
    json!({
        "artifact": artifact,
        "status": status,
        "before_state": before_state,
        "after_state": after_state,
        "before_sha256": before_sha256,
        "after_sha256": after_sha256,
        "reason": reason,
    })
}

fn required_capture<'a>(value: Option<&'a Value>, path: &str) -> Result<&'a Value, WebError> {
    let capture = value.ok_or_else(|| input_error(OPERATION, path, format!("{path} is required")))?;
    let object = capture.as_object().ok_or_else(|| input_error(OPERATION, path, format!("{path} must be an object")))?;
    for key in ["browser", "scenario", "steps", "events", "completeness"] {
        if !object.contains_key(key) {
            return Err(input_error(OPERATION, &format!("{path}.{key}"), format!("{key} is required")));
        }
    }
    Ok(capture)
}

fn parse_rules(value: Option<&Value>) -> Result<Vec<Value>, WebError> {
    let rules = match value {
        None => Vec::new(),
        Some(value) => {
            let object = value.as_object().ok_or_else(|| input_error(OPERATION, "normalization", "Expected an object"))?;
            for key in object.keys() {
                if key != "rules" {
                    return Err(input_error(OPERATION, "normalization", format!("Unrecognized key: \"{key}\"")));
                }
            }
            object.get("rules").and_then(Value::as_array).cloned().unwrap_or_default()
        }
    };
    let mut parsed = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, rule) in rules.iter().enumerate() {
        let object = rule.as_object().ok_or_else(|| {
            input_error(OPERATION, &format!("normalization.rules.{index}"), "Expected an object")
        })?;
        let rule_id = object.get("rule_id").and_then(Value::as_str).unwrap_or("").trim().to_string();
        if rule_id.is_empty() || !seen.insert(rule_id.clone()) {
            return Err(input_error(
                OPERATION,
                &format!("normalization.rules.{index}.rule_id"),
                "Normalization rule IDs must be unique",
            ));
        }
        let artifacts = object.get("artifacts").and_then(Value::as_array).cloned().unwrap_or_default();
        if artifacts.is_empty() {
            return Err(input_error(OPERATION, &format!("normalization.rules.{index}.artifacts"), "artifacts are required"));
        }
        let mut kinds = Vec::new();
        for artifact in artifacts {
            let Some(kind) = artifact.as_str() else {
                return Err(input_error(OPERATION, "normalization", "Unsupported artifact kind"));
            };
            if !matches!(
                kind,
                "action_state" | "dom" | "accessibility" | "url" | "history" | "storage" | "events"
            ) {
                return Err(input_error(OPERATION, "normalization", "Unsupported artifact kind"));
            }
            kinds.push(kind.to_string());
        }
        if kinds.len() != kinds.iter().collect::<BTreeSet<_>>().len() {
            return Err(input_error(
                OPERATION,
                &format!("normalization.rules.{index}.artifacts"),
                "Normalization rule artifact kinds must be unique",
            ));
        }
        kinds.sort();
        let pattern = object.get("match").and_then(Value::as_str).unwrap_or("");
        if pattern.is_empty() {
            return Err(input_error(OPERATION, &format!("normalization.rules.{index}.match"), "match must be a non-empty string"));
        }
        let replacement = match object.get("replacement") {
            Some(Value::String(value)) => value.clone(),
            _ => return Err(input_error(OPERATION, "normalization", "replacement must be a string")),
        };
        parsed.push(json!({
            "rule_id": rule_id,
            "artifacts": kinds,
            "match": pattern,
            "replacement": replacement,
        }));
    }
    parsed.sort_by(|left, right| {
        left.get("rule_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .cmp(right.get("rule_id").and_then(Value::as_str).unwrap_or_default())
    });
    Ok(parsed)
}
