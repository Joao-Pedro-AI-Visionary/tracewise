//! `compare_functions`: deterministic, dimension-classified comparison of two complete
//! `analyze_function` Evidence records (no fuzzy matching).
//!
//! Port of REA's `functionComparison*.ts`. The eight dimensions are identity, pseudocode,
//! assembly, comments, calls, references, strings/names and an address-normalized CFG. A
//! dimension that cannot be compared safely is `unknown`, never silently `unchanged`.

use std::collections::BTreeSet;
use std::time::Duration;

use regex::Regex;
use serde_json::{json, Map, Value};

use super::diff::diff_lines;
use super::dossier::{parse_function_evidence, FunctionSnapshot};
use super::util::{canonical, digest, sorted_by_canonical, utf16_cmp};
use super::{provider_key, DerivedError};

const DIFF_TIMEOUT: Duration = Duration::from_millis(100);
const DIFF_MAX_EDIT_LENGTH: usize = 10_000;

/// `isAutoName`: address-derived procedure names are not stable identities.
fn is_auto_name(name: &str) -> bool {
    use std::sync::OnceLock;
    static AUTO: OnceLock<Regex> = OnceLock::new();
    AUTO.get_or_init(|| Regex::new(r"(?i)^(?:sub_[0-9a-f]+|fcn\.[0-9a-f]+|FUN_[0-9a-f]+)$").expect("valid pattern"))
        .is_match(name)
}

/// `/^0x[0-9a-f]+$/iu` followed by `BigInt`.
fn parse_address(value: &str) -> Option<u128> {
    let digits = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X"))?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u128::from_str_radix(digits, 16).ok()
}

fn relative_address(value: &str, base: &str) -> Option<String> {
    let parsed = parse_address(value)?;
    let parsed_base = parse_address(base)?;
    if parsed < parsed_base {
        None
    } else {
        Some((parsed - parsed_base).to_string())
    }
}

fn name_of(procedure: &Value) -> Value {
    if procedure.is_null() {
        Value::Null
    } else {
        procedure["name"].clone()
    }
}

struct Context<'a> {
    links: &'a [String],
    providers_differ: bool,
}

fn base_dimension(
    dimension: &str,
    left_count: Option<usize>,
    right_count: Option<usize>,
    context: &Context,
    limitations: &[String],
) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("dimension".into(), json!(dimension));
    map.insert("left_count".into(), left_count.map_or(Value::Null, |n| json!(n)));
    map.insert("right_count".into(), right_count.map_or(Value::Null, |n| json!(n)));
    map.insert("evidence_links".into(), json!(context.links));
    map.insert("limitations".into(), json!(limitations));
    map
}

fn unresolved(
    dimension: &str,
    left_count: Option<usize>,
    right_count: Option<usize>,
    context: &Context,
    limitations: &[String],
) -> Value {
    let mut map = base_dimension(dimension, left_count, right_count, context, limitations);
    map.insert("status".into(), json!("unknown"));
    map.insert("left_digest".into(), Value::Null);
    map.insert("right_digest".into(), Value::Null);
    map.insert("text_delta".into(), Value::Null);
    map.insert("conclusion_kind".into(), json!("unresolved_branch"));
    Value::Object(map)
}

#[allow(clippy::too_many_arguments)]
fn resolved(
    dimension: &str,
    changed: bool,
    left: &Value,
    right: &Value,
    left_count: Option<usize>,
    right_count: Option<usize>,
    text_delta: Value,
    context: &Context,
    limitations: &[String],
) -> Value {
    let mut map = base_dimension(dimension, left_count, right_count, context, limitations);
    map.insert("left_digest".into(), json!(digest(left)));
    map.insert("right_digest".into(), json!(digest(right)));
    map.insert("text_delta".into(), text_delta);
    if changed {
        map.insert("status".into(), json!("changed"));
        map.insert(
            "conclusion_kind".into(),
            json!(if context.providers_differ { "contradiction" } else { "derived_relationship" }),
        );
    } else {
        map.insert("status".into(), json!("unchanged"));
        map.insert("conclusion_kind".into(), json!("derived_relationship"));
    }
    Value::Object(map)
}

fn compare_values(dimension: &str, left: &Value, right: &Value, context: &Context) -> Value {
    let changed = canonical(left) != canonical(right);
    resolved(
        dimension,
        changed,
        left,
        right,
        left.as_array().map(Vec::len),
        right.as_array().map(Vec::len),
        Value::Null,
        context,
        &[],
    )
}

fn compare_text(dimension: &str, left: &str, right: &str, context: &Context) -> Value {
    let limitations: Vec<String> = if dimension == "assembly" {
        vec!["Assembly is opaque provider text; relocation normalization is unavailable.".into()]
    } else {
        Vec::new()
    };
    let left_count = left.chars().count();
    let right_count = right.chars().count();
    if context.providers_differ {
        let mut notes = limitations;
        notes.push("Exact text comparison requires one provider identity.".into());
        return unresolved(dimension, Some(left_count), Some(right_count), context, &notes);
    }
    let Some(changes) = diff_lines(left, right, DIFF_TIMEOUT, DIFF_MAX_EDIT_LENGTH) else {
        return unresolved(
            dimension,
            Some(left_count),
            Some(right_count),
            context,
            &["Bounded line diff exceeded its time or edit-distance limit.".to_string()],
        );
    };
    let (mut added, mut removed, mut hunks) = (0usize, 0usize, 0usize);
    for change in &changes {
        if change.added {
            added += change.count;
        }
        if change.removed {
            removed += change.count;
        }
        if change.added || change.removed {
            hunks += 1;
        }
    }
    resolved(
        dimension,
        hunks != 0,
        &json!(left),
        &json!(right),
        Some(left_count),
        Some(right_count),
        json!({ "added_lines": added, "removed_lines": removed, "hunks": hunks }),
        context,
        &limitations,
    )
}

fn identity_projection(snapshot: &FunctionSnapshot) -> Value {
    let procedure = &snapshot.dossier["procedure"];
    let mut locals: Vec<String> = procedure["locals"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|local| local["description"].as_str().map(str::to_string))
        .collect();
    locals.sort_by(|a, b| utf16_cmp(a, b));
    json!({ "name": procedure["name"], "signature": procedure["signature"], "locals": locals })
}

fn compare_identity(left: &FunctionSnapshot, right: &FunctionSnapshot, context: &Context) -> Value {
    if is_auto_name(left.name()) || is_auto_name(right.name()) {
        return unresolved(
            "identity",
            None,
            None,
            context,
            &["Address-derived function names are not stable cross-version identity.".to_string()],
        );
    }
    compare_values("identity", &identity_projection(left), &identity_projection(right), context)
}

fn comment_projection(snapshot: &FunctionSnapshot) -> Option<Value> {
    let base = snapshot.address();
    let mut values = Vec::new();
    for comment in snapshot.field("comments") {
        let offset = relative_address(comment["address"].as_str().unwrap_or(""), base)?;
        values.push(json!({ "offset": offset, "kind": comment["kind"], "text": comment["text"] }));
    }
    Some(Value::Array(sorted_by_canonical(values)))
}

fn compare_comments(left: &FunctionSnapshot, right: &FunctionSnapshot, context: &Context) -> Value {
    match (comment_projection(left), comment_projection(right)) {
        (Some(left_values), Some(right_values)) => compare_values("comments", &left_values, &right_values, context),
        _ => unresolved(
            "comments",
            Some(left.field("comments").len()),
            Some(right.field("comments").len()),
            context,
            &["Comment locations could not be normalized relative to the function.".to_string()],
        ),
    }
}

fn string_and_name_projection(snapshot: &FunctionSnapshot) -> Option<Value> {
    let base = snapshot.address();
    let mut values = Vec::new();
    for (kind, key) in [("string", "referenced_strings"), ("name", "referenced_names")] {
        for item in snapshot.field(key) {
            let offset = relative_address(item["source_address"].as_str().unwrap_or(""), base)?;
            values.push(json!({ "kind": kind, "source_offset": offset, "value": item["value"] }));
        }
    }
    Some(Value::Array(sorted_by_canonical(values)))
}

fn compare_strings_and_names(left: &FunctionSnapshot, right: &FunctionSnapshot, context: &Context) -> Value {
    match (string_and_name_projection(left), string_and_name_projection(right)) {
        (Some(left_values), Some(right_values)) => {
            compare_values("strings_names", &left_values, &right_values, context)
        }
        _ => unresolved(
            "strings_names",
            None,
            None,
            context,
            &["Reference source locations could not be normalized to function offsets.".to_string()],
        ),
    }
}

fn reference_projection(snapshot: &FunctionSnapshot) -> Value {
    let mut edges = Vec::new();
    for (direction, key) in [("in", "incoming_references"), ("out", "outgoing_references")] {
        for edge in snapshot.field(key) {
            edges.push(json!({
                "direction": direction,
                "source": name_of(&edge["source_procedure"]),
                "target": name_of(&edge["target_procedure"]),
            }));
        }
    }
    Value::Array(sorted_by_canonical(edges))
}

fn reference_kind_projection(snapshot: &FunctionSnapshot) -> Option<Value> {
    const FLAGS: [&str; 11] = [
        "flow",
        "call",
        "jump",
        "data",
        "read",
        "write",
        "indirect",
        "computed",
        "conditional",
        "terminal",
        "primary",
    ];
    let mut edges: Vec<(&str, &Value)> = Vec::new();
    for (direction, key) in [("in", "incoming_references"), ("out", "outgoing_references")] {
        for edge in snapshot.field(key) {
            edges.push((direction, edge));
        }
    }
    if edges.iter().any(|(_, edge)| edge["kind"]["available"] != Value::Bool(true)) {
        return None;
    }
    let values = edges
        .into_iter()
        .map(|(direction, edge)| {
            let kind = &edge["kind"];
            let mut map = Map::new();
            map.insert("direction".into(), json!(direction));
            map.insert("source".into(), name_of(&edge["source_procedure"]));
            map.insert("target".into(), name_of(&edge["target_procedure"]));
            map.insert("type".into(), kind["type"].clone());
            for flag in FLAGS {
                map.insert(flag.into(), kind[flag].clone());
            }
            map.insert("operand_index".into(), kind["operand_index"].clone());
            map.insert("external".into(), kind["external"].clone());
            Value::Object(map)
        })
        .collect();
    Some(Value::Array(sorted_by_canonical(values)))
}

fn compare_references(left: &FunctionSnapshot, right: &FunctionSnapshot, context: &Context) -> Value {
    let left_projection = reference_projection(left);
    let right_projection = reference_projection(right);
    let both_empty = left_projection.as_array().is_some_and(Vec::is_empty)
        && right_projection.as_array().is_some_and(Vec::is_empty);
    if both_empty {
        return compare_values("references", &left_projection, &right_projection, context);
    }
    if canonical(&left_projection) != canonical(&right_projection) {
        return resolved(
            "references",
            true,
            &left_projection,
            &right_projection,
            left_projection.as_array().map(Vec::len),
            right_projection.as_array().map(Vec::len),
            Value::Null,
            context,
            &["Reference endpoints differ independently of provider reference-kind metadata.".to_string()],
        );
    }
    match (reference_kind_projection(left), reference_kind_projection(right)) {
        (Some(left_kinds), Some(right_kinds)) => compare_values("references", &left_kinds, &right_kinds, context),
        _ => unresolved(
            "references",
            left_projection.as_array().map(Vec::len),
            right_projection.as_array().map(Vec::len),
            context,
            &["At least one provider did not expose reference kinds, so equal endpoints do not prove equal edge semantics."
                .to_string()],
        ),
    }
}

/// `callProjection` plus the auto-name guard: callers/callees are matched by name.
fn compare_calls(left: &FunctionSnapshot, right: &FunctionSnapshot, context: &Context) -> Value {
    let projection = |snapshot: &FunctionSnapshot| -> Vec<Value> {
        let mut calls = Vec::new();
        for caller in snapshot.field("callers") {
            calls.push(json!({ "direction": "in", "name": caller["name"] }));
        }
        for callee in snapshot.field("callees") {
            calls.push(json!({ "direction": "out", "name": callee["name"] }));
        }
        calls
    };
    let left_values = projection(left);
    let right_values = projection(right);
    if left_values
        .iter()
        .chain(right_values.iter())
        .any(|call| is_auto_name(call["name"].as_str().unwrap_or("")))
    {
        return unresolved(
            "calls",
            Some(left_values.len()),
            Some(right_values.len()),
            context,
            &["Address-derived callee or caller names cannot be matched safely.".to_string()],
        );
    }
    compare_values(
        "calls",
        &Value::Array(sorted_by_canonical(left_values)),
        &Value::Array(sorted_by_canonical(right_values)),
        context,
    )
}

/// `normalizeCfg`: block addresses become local indices; `None` when not normalizable.
fn normalize_cfg(blocks: &[Value]) -> Option<Value> {
    struct Block<'a> {
        block: &'a Value,
        start: u128,
        end: u128,
    }
    let mut parsed = Vec::new();
    for block in blocks {
        let start = parse_address(block["start"].as_str().unwrap_or(""))?;
        let end = parse_address(block["end"].as_str().unwrap_or(""))?;
        if end <= start {
            return None;
        }
        parsed.push(Block { block, start, end });
    }
    parsed.sort_by_key(|block| block.start);
    let starts: BTreeSet<u128> = parsed.iter().map(|block| block.start).collect();
    if starts.len() != parsed.len() {
        return None;
    }
    let mut graph = Vec::new();
    for entry in &parsed {
        let mut successors: Vec<usize> = Vec::new();
        for address in entry.block["successors"].as_array().into_iter().flatten() {
            let target = parse_address(address.as_str().unwrap_or(""))?;
            successors.push(parsed.iter().position(|block| block.start == target)?);
        }
        successors.sort_unstable();
        graph.push(json!({ "size": (entry.end - entry.start).to_string(), "successors": successors }));
    }
    Some(Value::Array(graph))
}

fn compare_cfg(left: &FunctionSnapshot, right: &FunctionSnapshot, context: &Context) -> Value {
    let left_blocks = left.field("basic_blocks");
    let right_blocks = right.field("basic_blocks");
    match (normalize_cfg(left_blocks), normalize_cfg(right_blocks)) {
        (Some(left_graph), Some(right_graph)) => compare_values("cfg", &left_graph, &right_graph, context),
        _ => unresolved(
            "cfg",
            Some(left_blocks.len()),
            Some(right_blocks.len()),
            context,
            &["CFG addresses could not be normalized to local block indices.".to_string()],
        ),
    }
}

fn function_match(left: &FunctionSnapshot, right: &FunctionSnapshot) -> Value {
    let status = if !is_auto_name(left.name()) && left.name() == right.name() {
        return json!({
            "status": "matched",
            "method": "symbol",
            "left_name": left.name(),
            "right_name": right.name(),
        });
    } else if left.name() == right.name() {
        "ambiguous"
    } else {
        "mismatched"
    };
    json!({ "status": status, "method": "explicit", "left_name": left.name(), "right_name": right.name() })
}

fn status_of(dimension: &Value) -> &str {
    dimension["status"].as_str().unwrap_or("")
}

fn overall_status(dimensions: &[Value], match_status: &str) -> &'static str {
    if match_status == "ambiguous" || dimensions.iter().any(|d| status_of(d) == "unknown") {
        return "unknown";
    }
    if match_status == "mismatched" {
        return "changed";
    }
    if dimensions.iter().any(|d| status_of(d) == "changed") {
        "changed"
    } else {
        "unchanged"
    }
}

/// Compare two complete function Evidence records. The result is the Evidence payload.
pub fn compare_functions(left_input: &Value, right_input: &Value) -> Result<Value, DerivedError> {
    let left = parse_function_evidence(left_input)?;
    let right = parse_function_evidence(right_input)?;
    let links = vec![left.evidence.evidence_id.clone(), right.evidence.evidence_id.clone()];
    let providers_differ = provider_key(&left.evidence) != provider_key(&right.evidence);
    let context = Context {
        links: &links,
        providers_differ,
    };
    let dimensions = vec![
        compare_identity(&left, &right, &context),
        compare_text(
            "pseudocode",
            left.dossier["pseudocode"].as_str().unwrap_or(""),
            right.dossier["pseudocode"].as_str().unwrap_or(""),
            &context,
        ),
        compare_text("assembly", &joined_assembly(&left), &joined_assembly(&right), &context),
        compare_comments(&left, &right, &context),
        compare_calls(&left, &right, &context),
        compare_references(&left, &right, &context),
        compare_strings_and_names(&left, &right, &context),
        compare_cfg(&left, &right, &context),
    ];
    let matched = function_match(&left, &right);
    let changes: Vec<Value> = dimensions.iter().filter(|d| status_of(d) != "unchanged").cloned().collect();
    let count = |status: &str| dimensions.iter().filter(|d| status_of(d) == status).count();
    let mut limitations: BTreeSet<String> = BTreeSet::new();
    limitations.extend(left.limitations.iter().map(|item| format!("Left: {item}")));
    limitations.extend(right.limitations.iter().map(|item| format!("Right: {item}")));
    if providers_differ {
        limitations.insert("Provider-specific pseudocode and assembly representations were not equated.".into());
    }
    Ok(json!({
        "status": overall_status(&dimensions, matched["status"].as_str().unwrap_or("")),
        "function_match": matched,
        "left_subject_sha256": left.subject.digest.sha256,
        "right_subject_sha256": right.subject.digest.sha256,
        "summary": { "unchanged": count("unchanged"), "changed": count("changed"), "unknown": count("unknown") },
        "dimensions": dimensions,
        "changes": changes,
        "limitations": limitations.into_iter().collect::<Vec<_>>(),
    }))
}

fn joined_assembly(snapshot: &FunctionSnapshot) -> String {
    snapshot
        .field("assembly")
        .iter()
        .map(|line| line.as_str().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `functionUnknownInput`: the residual Unknown REA registers for a non-`unchanged` result.
pub fn unknown_input(status: &str, left_ids: &[String], right_ids: &[String], comparison_id: &str) -> Option<Value> {
    if status == "unchanged" {
        return None;
    }
    let mut supporting: Vec<String> = Vec::new();
    for id in left_ids.iter().chain(right_ids.iter()) {
        if !supporting.contains(id) {
            supporting.push(id.clone());
        }
    }
    let contradicting: Vec<String> = right_ids.iter().filter(|id| !left_ids.contains(id)).cloned().collect();
    let contradictory = status == "changed";
    Some(json!({
        "question": format!("Function comparison is {status} (comparison {comparison_id})"),
        "severity": if status == "changed" { "medium" } else { "high" },
        "domain": "function-comparison",
        "supporting_evidence_ids": if contradictory { left_ids.to_vec() } else { supporting },
        "contradicting_evidence_ids": if contradictory { contradicting } else { Vec::new() },
        "required_authority": "shipped-artifact",
        "required_confidence": "observed",
        "required_environment": null,
        "recommended_probes": [{
            "operation": "analyze_function",
            "rationale": "Capture complete dossiers for both functions under the same target context.",
        }],
        "relationships": [],
    }))
}

