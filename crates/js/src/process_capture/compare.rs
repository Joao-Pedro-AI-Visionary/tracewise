//! Port of REA `domain/process/processComparison.ts`.

use serde_json::{json, Map, Value};
use tracewise_domain::canonical::canonical_json;

use super::trace::{compare_traces, trace_outcomes_differ, TraceSpecification};
use crate::error::JsError;

pub const DIMENSIONS: [&str; 5] = ["terminal", "interaction", "exit", "filesystem", "process"];

fn arr(value: &Value) -> Vec<Value> {
    value.as_array().cloned().unwrap_or_default()
}

pub(crate) fn same_json(left: &Value, right: &Value) -> bool {
    match (canonical_json(left), canonical_json(right)) {
        (Ok(l), Ok(r)) => l == r,
        _ => false,
    }
}

/// Derive the overall comparison status from every process dimension.
pub fn derive_status(dimensions: &[&str]) -> &'static str {
    if dimensions.contains(&"truncated") {
        "truncated"
    } else if dimensions.iter().any(|s| matches!(*s, "changed" | "added" | "removed")) {
        "changed"
    } else if dimensions.contains(&"unknown") {
        "unknown"
    } else {
        "unchanged"
    }
}

/// Project normalized PTY facts without the audit-only `raw_data`.
pub(crate) fn comparable_terminal_frame(frame: &Value) -> Value {
    json!({ "sequence": frame["sequence"], "at_ms": frame["at_ms"], "data": frame["data"] })
}

fn terminal_observations(capture: &Value) -> Vec<Value> {
    let mut items: Vec<(u64, u8, u64, Value)> = Vec::new();
    for frame in arr(&capture["frames"]) {
        let mut object = Map::new();
        object.insert("kind".into(), json!("raw"));
        if let Value::Object(fields) = comparable_terminal_frame(&frame) {
            object.extend(fields);
        }
        items.push((frame["at_ms"].as_u64().unwrap_or(0), 0, frame["sequence"].as_u64().unwrap_or(0), Value::Object(object)));
    }
    for frame in arr(&capture["rendered_frames"]) {
        let mut object = Map::new();
        object.insert("kind".into(), json!("rendered"));
        if let Value::Object(fields) = &frame {
            object.extend(fields.clone());
        }
        items.push((frame["at_ms"].as_u64().unwrap_or(0), 1, frame["sequence"].as_u64().unwrap_or(0), Value::Object(object)));
    }
    // Stable sort, like Array.prototype.sort.
    items.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(if a.1 == b.1 { a.2.cmp(&b.2) } else { std::cmp::Ordering::Equal }));
    items.into_iter().map(|(_, _, _, v)| v).collect()
}

fn exit_observation(capture: &Value) -> Value {
    let mut object = capture["exit"].as_object().cloned().unwrap_or_default();
    object.insert("settlement".into(), capture["settlement"].clone());
    Value::Object(object)
}

/// Canonical observations for one process-comparison dimension.
pub fn dimension_observations(capture: &Value, dimension: &str) -> Vec<Value> {
    match dimension {
        "terminal" => terminal_observations(capture),
        "interaction" => arr(&capture["interaction_events"]),
        "exit" => vec![exit_observation(capture)],
        "filesystem" => arr(&capture["filesystem_checkpoints"]),
        "process" => arr(&capture["process_samples"]),
        _ => Vec::new(),
    }
}

fn classify_collection(left: &[Value], right: &[Value]) -> &'static str {
    if same_json(&json!(left), &json!(right)) {
        "unchanged"
    } else if left.is_empty() {
        "added"
    } else if right.is_empty() {
        "removed"
    } else {
        "changed"
    }
}

fn has_unknown(capture: &Value, scope: &str) -> bool {
    capture["residual_unknowns"].as_array().is_some_and(|items| items.iter().any(|u| u["scope"] == scope))
}

/// Whether producer accounting reports a gap in the selected observation source.
pub fn source_truncated(capture: &Value, source: &str) -> bool {
    let details = &capture["truncation_details"];
    let omitted = |r: &Value| r["observed_frames"].as_u64().unwrap_or(0) > r["retained_frames"].as_u64().unwrap_or(0);
    let fs = |c: &Value| c["enumeration_truncated"] == true || c["hash_omissions"].as_array().is_some_and(|a| !a.is_empty());
    match source {
        "terminal_raw" => omitted(&details["raw_terminal"]),
        "terminal_rendered" => omitted(&details["raw_terminal"]) || omitted(&details["rendered_terminal"]),
        "filesystem" => fs(&details["filesystem_before"]) || fs(&details["filesystem_after"]),
        "process" => details["process"]["sampling_partial"] == true,
        _ => false,
    }
}

type Dimensions = [(&'static str, &'static str); 5];

fn compare_dimensions(left: &Value, right: &Value, same_normalization: bool) -> Dimensions {
    let classify = |scope: &str, source: &str, l: Vec<Value>, r: Vec<Value>| -> &'static str {
        if !same_normalization
            || has_unknown(left, scope)
            || has_unknown(right, scope)
            || source_truncated(left, source)
            || source_truncated(right, source)
        {
            "unknown"
        } else {
            classify_collection(&l, &r)
        }
    };
    let exit = if has_unknown(left, "exit") || has_unknown(right, "exit") {
        "unknown"
    } else if same_json(
        &json!({"exit": left["exit"], "settlement": left["settlement"]}),
        &json!({"exit": right["exit"], "settlement": right["settlement"]}),
    ) {
        "unchanged"
    } else {
        "changed"
    };
    [
        ("terminal", classify("terminal", "terminal_rendered", terminal_observations(left), terminal_observations(right))),
        ("interaction", classify("interaction", "interaction", arr(&left["interaction_events"]), arr(&right["interaction_events"]))),
        ("exit", exit),
        ("filesystem", classify("filesystem", "filesystem", arr(&left["filesystem_checkpoints"]), arr(&right["filesystem_checkpoints"]))),
        ("process", classify("process", "process", arr(&left["process_samples"]), arr(&right["process_samples"]))),
    ]
}

fn event_time(value: &Value) -> Option<u64> {
    value.get("at_ms").and_then(Value::as_u64)
}

fn first_collection_divergence(dimension: &str, left: &[Value], right: &[Value]) -> Option<Value> {
    for index in 0..left.len().max(right.len()) {
        let l = left.get(index).cloned().unwrap_or(Value::Null);
        let r = right.get(index).cloned().unwrap_or(Value::Null);
        if same_json(&l, &r) {
            continue;
        }
        return Some(json!({
            "status": "found",
            "dimension": dimension,
            "index": index,
            "left_at_ms": event_time(&l),
            "right_at_ms": event_time(&r),
            "left": l,
            "right": r,
        }));
    }
    None
}

fn choose_first_divergence(candidates: Vec<Option<Value>>) -> Value {
    let key = |c: &Value| {
        c["left_at_ms"].as_u64().unwrap_or(u64::MAX).min(c["right_at_ms"].as_u64().unwrap_or(u64::MAX))
    };
    candidates.into_iter().flatten().min_by_key(key).unwrap_or_else(|| json!({ "status": "none" }))
}

/// Name top-level contract fields whose canonical values differ.
fn differing_contract_fields(left: &Value, right: &Value) -> Vec<String> {
    let empty = Map::new();
    let l = left.as_object().unwrap_or(&empty);
    let r = right.as_object().unwrap_or(&empty);
    let mut fields: Vec<String> = l
        .keys()
        .chain(r.keys())
        .filter(|f| match (l.get(*f), r.get(*f)) {
            (Some(a), Some(b)) => !same_json(a, b),
            _ => true,
        })
        .cloned()
        .collect();
    fields.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    fields.dedup();
    fields
}

fn parse_iso_ms(value: &Value) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(value.as_str()?).ok().map(|d| d.timestamp_millis())
}

fn assert_comparable(left: &Value, right: &Value, max_capture_age_ms: Option<u64>, now_ms: i64) -> Result<(), JsError> {
    let lm = &left["manifest"];
    let rm = &right["manifest"];
    if lm["comparison_contract_sha256"] != rm["comparison_contract_sha256"] {
        let fields = differing_contract_fields(&lm["comparison_contract"], &rm["comparison_contract"]);
        return Err(JsError::InvalidInput(format!(
            "right: Process captures have incompatible comparison contracts{}. Capture both scenarios with the same values for these fields, then compare them.",
            if fields.is_empty() { String::new() } else { format!("; these scenario fields differ: {}", fields.join(", ")) }
        )));
    }
    let Some(max) = max_capture_age_ms else { return Ok(()) };
    let stale: Vec<String> = [("left", lm), ("right", rm)]
        .into_iter()
        .filter_map(|(side, manifest)| {
            let age = now_ms - parse_iso_ms(&manifest["completed_at"])?;
            (age > max as i64).then(|| format!("{side} completed at {} ({age} ms ago)", manifest["completed_at"].as_str().unwrap_or_default()))
        })
        .collect();
    if !stale.is_empty() {
        return Err(JsError::InvalidInput(format!(
            "max_capture_age_ms: Process capture exceeds max_capture_age_ms {max}: {}. Recapture the stale scenario or raise max_capture_age_ms.",
            stale.join("; ")
        )));
    }
    Ok(())
}

fn dimensions_for_sources(sources: &[String]) -> Vec<&'static str> {
    let mut out = Vec::new();
    for source in sources {
        let d = if source.starts_with("terminal_") {
            "terminal"
        } else {
            match source.as_str() {
                "interaction" => "interaction",
                "lifecycle" => "exit",
                "filesystem" => "filesystem",
                "process" => "process",
                _ => continue,
            }
        };
        if !out.contains(&d) {
            out.push(d);
        }
    }
    out
}

fn trace_covers_dimension(dimension: &str, sources: &[String], left: &Value, right: &Value) -> bool {
    let has = |s: &str| sources.iter().any(|x| x == s);
    let any = |key: &str| arr(&left[key]).len() + arr(&right[key]).len() > 0;
    match dimension {
        "terminal" => (!any("frames") || has("terminal_raw")) && (!any("rendered_frames") || has("terminal_rendered")),
        "interaction" => has("interaction"),
        "exit" => has("lifecycle"),
        "process" => has("process"),
        _ => false,
    }
}

fn apply_trace_verdict(dimensions: Dimensions, spec: &TraceSpecification, trace: &Value, left: &Value, right: &Value) -> Dimensions {
    let differ = trace_outcomes_differ(trace);
    let verdict = trace["verdict"].as_str().unwrap_or("unknown");
    let trace_status = if verdict == "unknown" {
        "unknown"
    } else if verdict == "equivalent" || !differ {
        "unchanged"
    } else {
        "changed"
    };
    let sources: Vec<String> = spec.sources();
    let covered = dimensions_for_sources(&sources);
    dimensions.map(|(dimension, exact)| {
        let status = if !covered.contains(&dimension) || verdict == "nonconforming" {
            exact
        } else if verdict == "different" {
            if differ { "changed" } else { exact }
        } else if verdict == "unknown" && matches!(exact, "changed" | "added" | "removed") {
            exact
        } else if trace_covers_dimension(dimension, &sources, left, right) {
            trace_status
        } else {
            exact
        };
        (dimension, status)
    })
}

/// Options for one comparison.
#[derive(Default)]
pub struct CompareOptions {
    pub max_capture_age_ms: Option<u64>,
    pub trace_spec: Option<TraceSpecification>,
    pub now_ms: Option<i64>,
}

/// Compare two process capture observations without treating absence as proof.
pub fn compare_process_captures(left: &Value, right: &Value, options: &CompareOptions) -> Result<Value, JsError> {
    let now_ms = options.now_ms.unwrap_or_else(|| chrono::Utc::now().timestamp_millis());
    assert_comparable(left, right, options.max_capture_age_ms, now_ms)?;
    let same_normalization = same_json(&left["normalization"], &right["normalization"]);
    let exact = compare_dimensions(left, right, same_normalization);
    let trace = options.trace_spec.as_ref().map(|spec| compare_traces(left, right, spec));
    let dimensions = match (&trace, &options.trace_spec) {
        (Some(trace), Some(spec)) => apply_trace_verdict(exact, spec, trace, left, right),
        _ => exact,
    };
    let status_of = |name: &str| dimensions.iter().find(|(d, _)| *d == name).map_or("unknown", |(_, s)| *s);
    let trace_equivalent = trace.as_ref().is_some_and(|t| t["verdict"] == "equivalent");
    let candidates: Vec<Option<Value>> = DIMENSIONS
        .iter()
        .map(|dimension| {
            if status_of(dimension) == "unknown" {
                return None;
            }
            let candidate = first_collection_divergence(
                dimension,
                &dimension_observations(left, dimension),
                &dimension_observations(right, dimension),
            )?;
            if trace_equivalent && status_of(dimension) == "unchanged" {
                None
            } else {
                Some(candidate)
            }
        })
        .collect();
    let observed_first = choose_first_divergence(candidates);
    let statuses: Vec<&str> = DIMENSIONS.iter().map(|d| status_of(d)).collect();
    let status = derive_status(&statuses);
    let residuals = |c: &Value| c["residual_unknowns"].as_array().is_some_and(|a| !a.is_empty());
    let first_divergence = if left["truncated"] == true || right["truncated"] == true {
        json!({"status": "unknown", "reason": "Incomplete observations prevent locating the first divergence; unaffected dimensions retain their comparisons."})
    } else if trace_equivalent && status == "unchanged" {
        json!({"status": "none"})
    } else if observed_first["status"] == "found" {
        observed_first
    } else if !same_normalization || residuals(left) || residuals(right) {
        json!({"status": "unknown", "reason": "Residual unknowns prevent proving that no divergence occurred."})
    } else {
        observed_first
    };
    let mut limitations: Vec<Value> = Vec::new();
    limitations.extend(arr(&left["limitations"]));
    limitations.extend(arr(&right["limitations"]));
    for capture in [left, right] {
        limitations.extend(arr(&capture["residual_unknowns"]).iter().map(|u| u["reason"].clone()));
    }
    if !same_normalization {
        limitations.push(json!("Capture normalization rules differ."));
    }
    let mut result = Map::new();
    result.insert("status".into(), json!(status));
    for (dimension, s) in dimensions {
        result.insert(dimension.into(), json!(s));
    }
    result.insert("first_divergence".into(), first_divergence);
    if let Some(trace) = trace {
        result.insert("trace".into(), trace);
    }
    result.insert("limitations".into(), Value::Array(limitations));
    Ok(Value::Object(result))
}
