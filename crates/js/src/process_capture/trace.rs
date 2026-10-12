//! Port of REA `domain/process/processTraceSpecification.ts`,
//! `processTraceEvaluation.ts`, `processTraceComparison.ts` and the journal
//! projection in `processObservation.ts`.

use std::collections::{HashMap, HashSet};

use serde_json::{json, Map, Value};
use tracewise_domain::canonical::canonical_json;

use super::compare::{comparable_terminal_frame, source_truncated};
use crate::error::JsError;

const SOURCES: [&str; 6] = ["terminal_raw", "terminal_rendered", "interaction", "lifecycle", "process", "filesystem"];
const IGNORABLE: [&str; 5] = ["sequence", "at_ms", "scheduled_at_ms", "dispatched_at_ms", "elapsed_ms"];

#[derive(Debug, Clone)]
pub struct EventDeclaration {
    pub id: String,
    pub source: String,
    pub exact: Value,
    pub ignore_fields: Vec<String>,
    pub min: u64,
    pub max: u64,
}

#[derive(Debug, Clone)]
pub enum Token {
    Event(String),
    Unordered(Vec<String>),
}

#[derive(Debug, Clone)]
pub enum Language {
    PartialOrder {
        happens_before: Vec<(String, String)>,
        not_before: Vec<(String, String)>,
        unordered_groups: Vec<Vec<String>>,
        prefix: Vec<String>,
        suffix: Vec<String>,
    },
    FiniteTraces(Vec<(String, Vec<Token>)>),
}

#[derive(Debug, Clone)]
pub struct TraceSpecification {
    pub events: Vec<EventDeclaration>,
    pub language: Language,
    /// The caller's JSON, echoed into Evidence parameters.
    pub raw: Value,
}

impl TraceSpecification {
    pub fn sources(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for e in &self.events {
            if !out.contains(&e.source) {
                out.push(e.source.clone());
            }
        }
        out
    }
}

fn canonical(value: &Value) -> String {
    canonical_json(value).unwrap_or_default()
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Remove only explicitly declared top-level volatile fields before matching.
fn comparable_payload(value: &Value, ignored: &[String]) -> Value {
    match value {
        Value::Object(map) if !ignored.is_empty() => {
            Value::Object(map.iter().filter(|(k, _)| !ignored.contains(k)).map(|(k, v)| (k.clone(), v.clone())).collect())
        }
        other => other.clone(),
    }
}

fn pair_key(a: &str, b: &str) -> (String, String) {
    if a <= b {
        (a.to_string(), b.to_string())
    } else {
        (b.to_string(), a.to_string())
    }
}

fn ids(value: &Value, path: &str, issues: &mut Vec<String>) -> Vec<String> {
    match value {
        Value::Null => Vec::new(),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .filter_map(|(i, v)| match v.as_str() {
                Some(s) if is_identifier(s) => Some(s.to_string()),
                _ => {
                    issues.push(format!("{path}.{i}: invalid identifier"));
                    None
                }
            })
            .collect(),
        _ => {
            issues.push(format!("{path}: expected array"));
            Vec::new()
        }
    }
}

fn strict(map: &Map<String, Value>, allowed: &[&str], path: &str, issues: &mut Vec<String>) {
    for key in map.keys() {
        if !allowed.contains(&key.as_str()) {
            issues.push(format!("{path}: Unrecognized key: \"{key}\""));
        }
    }
}

/// The zod-parsed specification REA echoes: schema key order with defaults
/// (`cardinality: {kind: required}`, empty partial-order lists) applied.
fn with_defaults(value: &Value) -> Value {
    let reorder = |source: &Value, keys: &[&str], defaults: &[(&str, Value)]| -> Value {
        let mut map = Map::new();
        for key in keys {
            if let Some(v) = source.get(*key) {
                map.insert((*key).to_string(), v.clone());
            } else if let Some((_, d)) = defaults.iter().find(|(k, _)| k == key) {
                map.insert((*key).to_string(), d.clone());
            }
        }
        Value::Object(map)
    };
    let events: Vec<Value> = value["events"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|e| reorder(e, &["id", "source", "exact", "ignore_fields", "cardinality"], &[("cardinality", json!({"kind": "required"}))]))
        .collect();
    let language = &value["language"];
    let language = if language["kind"] == "partial_order" {
        reorder(
            language,
            &["kind", "happens_before", "not_before", "unordered_groups", "prefix", "suffix"],
            &[("happens_before", json!([])), ("not_before", json!([])), ("unordered_groups", json!([])), ("prefix", json!([])), ("suffix", json!([]))],
        )
    } else {
        reorder(language, &["kind", "variants"], &[])
    };
    json!({ "events": events, "language": language })
}

/// Parse and validate a trace specification (`processTraceSpecificationSchema`).
#[allow(clippy::too_many_lines)]
pub fn parse_trace_specification(value: &Value) -> Result<TraceSpecification, JsError> {
    let mut issues: Vec<String> = Vec::new();
    let Some(root) = value.as_object() else {
        return Err(JsError::InvalidInput("trace_spec: expected object".into()));
    };
    strict(root, &["events", "language"], "trace_spec", &mut issues);
    let mut events = Vec::new();
    match root.get("events").and_then(Value::as_array) {
        Some(items) if !items.is_empty() => {
            for (i, item) in items.iter().enumerate() {
                let path = format!("trace_spec.events.{i}");
                let Some(e) = item.as_object() else {
                    issues.push(format!("{path}: expected object"));
                    continue;
                };
                strict(e, &["id", "source", "exact", "ignore_fields", "cardinality"], &path, &mut issues);
                let id = e.get("id").and_then(Value::as_str).filter(|s| is_identifier(s)).unwrap_or_else(|| {
                    issues.push(format!("{path}.id: invalid identifier"));
                    ""
                });
                let source = e.get("source").and_then(Value::as_str).filter(|s| SOURCES.contains(s)).unwrap_or_else(|| {
                    issues.push(format!("{path}.source: invalid source"));
                    ""
                });
                let Some(exact) = e.get("exact") else {
                    issues.push(format!("{path}.exact: required"));
                    continue;
                };
                let mut ignore_fields: Vec<String> = Vec::new();
                if let Some(fields) = e.get("ignore_fields") {
                    for f in fields.as_array().into_iter().flatten() {
                        match f.as_str() {
                            Some(s) if IGNORABLE.contains(&s) => ignore_fields.push(s.to_string()),
                            _ => issues.push(format!("{path}.ignore_fields: invalid field")),
                        }
                    }
                    let unique: HashSet<&String> = ignore_fields.iter().collect();
                    if unique.len() != ignore_fields.len() {
                        issues.push(format!("{path}.ignore_fields: ignored event fields must be unique"));
                    }
                }
                let (min, max) = match e.get("cardinality") {
                    None => (1, 1),
                    Some(c) => match c["kind"].as_str() {
                        Some("required") => (1, 1),
                        Some("optional") => (0, 1),
                        Some("exact") => {
                            let n = c["count"].as_u64().unwrap_or_else(|| {
                                issues.push(format!("{path}.cardinality.count: expected integer"));
                                0
                            });
                            (n, n)
                        }
                        Some("range") => {
                            let (a, b) = (c["min"].as_u64().unwrap_or(0), c["max"].as_u64().unwrap_or(0));
                            if a > b {
                                issues.push(format!("{path}.cardinality.min: cardinality min must not exceed max"));
                            }
                            (a, b)
                        }
                        _ => {
                            issues.push(format!("{path}.cardinality: invalid cardinality"));
                            (1, 1)
                        }
                    },
                };
                events.push(EventDeclaration { id: id.into(), source: source.into(), exact: exact.clone(), ignore_fields, min, max });
            }
        }
        _ => issues.push("trace_spec.events: expected a nonempty array".into()),
    }
    let language_value = root.get("language").cloned().unwrap_or(Value::Null);
    let language = match language_value["kind"].as_str() {
        Some("partial_order") => {
            let Some(l) = language_value.as_object() else { unreachable!() };
            strict(l, &["kind", "happens_before", "not_before", "unordered_groups", "prefix", "suffix"], "trace_spec.language", &mut issues);
            let pairs = |key: &str, a: &str, b: &str, issues: &mut Vec<String>| -> Vec<(String, String)> {
                l.get(key)
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|p| match (p[a].as_str(), p[b].as_str()) {
                        (Some(x), Some(y)) if is_identifier(x) && is_identifier(y) => Some((x.to_string(), y.to_string())),
                        _ => {
                            issues.push(format!("trace_spec.language.{key}: invalid pair"));
                            None
                        }
                    })
                    .collect()
            };
            let happens_before = pairs("happens_before", "before", "after", &mut issues);
            let not_before = pairs("not_before", "event", "anchor", &mut issues);
            let mut unordered_groups = Vec::new();
            for (i, g) in l.get("unordered_groups").and_then(Value::as_array).into_iter().flatten().enumerate() {
                let group = ids(&g["events"], &format!("trace_spec.language.unordered_groups.{i}.events"), &mut issues);
                if group.len() < 2 {
                    issues.push(format!("trace_spec.language.unordered_groups.{i}.events: expected at least 2 events"));
                }
                unordered_groups.push(group);
            }
            let prefix = ids(l.get("prefix").unwrap_or(&Value::Null), "trace_spec.language.prefix", &mut issues);
            let suffix = ids(l.get("suffix").unwrap_or(&Value::Null), "trace_spec.language.suffix", &mut issues);
            Language::PartialOrder { happens_before, not_before, unordered_groups, prefix, suffix }
        }
        Some("finite_traces") => {
            let mut variants = Vec::new();
            match language_value["variants"].as_array() {
                Some(items) if !items.is_empty() => {
                    for (i, v) in items.iter().enumerate() {
                        let id = v["id"].as_str().filter(|s| is_identifier(s)).unwrap_or_else(|| {
                            issues.push(format!("trace_spec.language.variants.{i}.id: invalid identifier"));
                            ""
                        });
                        let mut tokens = Vec::new();
                        for t in v["trace"].as_array().into_iter().flatten() {
                            match t {
                                Value::String(s) if is_identifier(s) => tokens.push(Token::Event(s.clone())),
                                Value::Object(o) if o.len() == 1 && o.contains_key("unordered") => {
                                    let group = ids(&o["unordered"], &format!("trace_spec.language.variants.{i}.trace"), &mut issues);
                                    if group.len() < 2 {
                                        issues.push(format!("trace_spec.language.variants.{i}.trace: unordered tokens need at least 2 events"));
                                    }
                                    tokens.push(Token::Unordered(group));
                                }
                                _ => issues.push(format!("trace_spec.language.variants.{i}.trace: invalid token")),
                            }
                        }
                        variants.push((id.to_string(), tokens));
                    }
                }
                _ => issues.push("trace_spec.language.variants: expected a nonempty array".into()),
            }
            Language::FiniteTraces(variants)
        }
        _ => {
            issues.push("trace_spec.language.kind: expected partial_order or finite_traces".into());
            Language::FiniteTraces(Vec::new())
        }
    };
    let spec = TraceSpecification { events, language, raw: with_defaults(value) };
    validate(&spec, &mut issues);
    if issues.is_empty() {
        Ok(spec)
    } else {
        Err(JsError::InvalidInput(format!("Invalid trace_spec: {}", issues.join("; "))))
    }
}

#[allow(clippy::too_many_lines)]
fn validate(spec: &TraceSpecification, issues: &mut Vec<String>) {
    let mut seen = HashSet::new();
    let mut predicates = HashSet::new();
    let mut ignored_by_source: HashMap<&str, String> = HashMap::new();
    for (index, event) in spec.events.iter().enumerate() {
        if !seen.insert(event.id.clone()) {
            issues.push(format!("events.{index}.id: event ids must be unique"));
        }
        let mut ignored = event.ignore_fields.clone();
        ignored.sort();
        if !ignored.is_empty() && !event.exact.is_object() {
            issues.push(format!("events.{index}.ignore_fields: ignored schedule fields require an exact object payload"));
        }
        let key = canonical(&json!(ignored));
        if let Some(prior) = ignored_by_source.get(event.source.as_str()) {
            if *prior != key {
                issues.push(format!("events.{index}.ignore_fields: events from one source must use the same ignored schedule fields"));
            }
        }
        ignored_by_source.insert(&event.source, key);
        if ignored.iter().any(|f| event.exact.get(f).is_some()) {
            issues.push(format!("events.{index}.exact: exact payload must omit every ignored schedule field"));
        }
        let predicate = format!("{}\0{}", event.source, canonical(&comparable_payload(&event.exact, &ignored)));
        if !predicates.insert(predicate) {
            issues.push(format!("events.{index}: exact event predicates must not overlap"));
        }
    }
    let known: HashSet<&str> = spec.events.iter().map(|e| e.id.as_str()).collect();
    let mut reference = |id: &str, path: String| {
        if !known.contains(id) {
            issues.push(format!("{path}: unknown event id: {id}"));
        }
    };
    match &spec.language {
        Language::PartialOrder { happens_before, not_before, unordered_groups, prefix, suffix } => {
            let ids: Vec<&str> = spec.events.iter().map(|e| e.id.as_str()).collect();
            let mut adjacency: HashMap<&str, Vec<&str>> = ids.iter().map(|id| (*id, Vec::new())).collect();
            let mut local: Vec<String> = Vec::new();
            for (i, (b, a)) in happens_before.iter().enumerate() {
                reference(b, format!("language.happens_before.{i}.before"));
                reference(a, format!("language.happens_before.{i}.after"));
                if b == a {
                    local.push(format!("language.happens_before.{i}: happens-before edges must reference distinct events"));
                }
                if let Some(next) = adjacency.get_mut(b.as_str()) {
                    next.push(a.as_str());
                }
            }
            // cycle detection
            fn visit<'a>(n: &'a str, adj: &HashMap<&'a str, Vec<&'a str>>, active: &mut HashSet<&'a str>, done: &mut HashSet<&'a str>) -> bool {
                if active.contains(n) {
                    return true;
                }
                if done.contains(n) {
                    return false;
                }
                active.insert(n);
                let cyclic = adj.get(n).into_iter().flatten().any(|m| visit(m, adj, active, done));
                active.remove(n);
                done.insert(n);
                cyclic
            }
            let (mut active, mut done) = (HashSet::new(), HashSet::new());
            if ids.iter().any(|id| visit(id, &adjacency, &mut active, &mut done)) {
                local.push("language: happens-before graph must be acyclic".into());
            }
            let reachable: HashMap<&str, HashSet<&str>> = ids
                .iter()
                .map(|origin| {
                    let mut seen = HashSet::new();
                    let mut pending: Vec<&str> = adjacency.get(origin).cloned().unwrap_or_default();
                    while let Some(c) = pending.pop() {
                        if seen.insert(c) {
                            pending.extend(adjacency.get(c).cloned().unwrap_or_default());
                        }
                    }
                    (*origin, seen)
                })
                .collect();
            let ordered = |l: &str, r: &str| reachable.get(l).is_some_and(|s| s.contains(r)) || reachable.get(r).is_some_and(|s| s.contains(l));
            let mut nb_pairs = HashSet::new();
            for (i, (event, anchor)) in not_before.iter().enumerate() {
                reference(event, format!("language.not_before.{i}.event"));
                reference(anchor, format!("language.not_before.{i}.anchor"));
                if event == anchor {
                    local.push(format!("language.not_before.{i}: not-before constraints must reference distinct events"));
                }
                if !nb_pairs.insert(pair_key(event, anchor)) {
                    local.push(format!("language.not_before.{i}: not-before event pairs must be declared once"));
                }
                if reachable.get(event.as_str()).is_some_and(|s| s.contains(anchor.as_str())) {
                    local.push(format!("language.not_before.{i}: not-before constraint conflicts with happens-before order"));
                }
            }
            let mut unordered_pairs = HashSet::new();
            for (gi, group) in unordered_groups.iter().enumerate() {
                if group.iter().collect::<HashSet<_>>().len() != group.len() {
                    local.push(format!("language.unordered_groups.{gi}.events: unordered groups must not repeat event ids"));
                }
                for (ei, id) in group.iter().enumerate() {
                    reference(id, format!("language.unordered_groups.{gi}.events.{ei}"));
                }
                for (li, l) in group.iter().enumerate() {
                    for r in &group[li + 1..] {
                        let key = pair_key(l, r);
                        if !unordered_pairs.insert(key.clone()) {
                            local.push(format!("language.unordered_groups.{gi}: unordered event pairs must be declared once"));
                        }
                        if ordered(l, r) || nb_pairs.contains(&key) {
                            local.push(format!("language.unordered_groups.{gi}: ordered events cannot also be declared unordered"));
                        }
                    }
                }
            }
            for (li, l) in ids.iter().enumerate() {
                for r in &ids[li + 1..] {
                    let key = pair_key(l, r);
                    if !ordered(l, r) && !nb_pairs.contains(&key) && !unordered_pairs.contains(&key) {
                        local.push(format!("language: event pair {l}/{r} must be explicitly ordered or unordered"));
                    }
                }
            }
            for (kind, values) in [("prefix", prefix), ("suffix", suffix)] {
                for (i, id) in values.iter().enumerate() {
                    reference(id, format!("language.{kind}.{i}"));
                }
            }
            issues.extend(local);
        }
        Language::FiniteTraces(variants) => {
            let mut local = Vec::new();
            let mut variant_ids = HashSet::new();
            let mut traces = HashSet::new();
            for (vi, (id, trace)) in variants.iter().enumerate() {
                if !variant_ids.insert(id.clone()) {
                    local.push(format!("language.variants.{vi}.id: finite trace variant ids must be unique"));
                }
                let trace_json = json!(trace
                    .iter()
                    .map(|t| match t {
                        Token::Event(s) => json!(s),
                        Token::Unordered(g) => json!({ "unordered": g }),
                    })
                    .collect::<Vec<_>>());
                if !traces.insert(canonical(&trace_json)) {
                    local.push(format!("language.variants.{vi}.trace: finite trace variants must not duplicate a trace"));
                }
                let mut counts: HashMap<&str, u64> = HashMap::new();
                for (ti, token) in trace.iter().enumerate() {
                    let values: Vec<&String> = match token {
                        Token::Event(s) => vec![s],
                        Token::Unordered(g) => g.iter().collect(),
                    };
                    for v in values {
                        reference(v, format!("language.variants.{vi}.trace.{ti}"));
                        *counts.entry(v.as_str()).or_default() += 1;
                    }
                }
                for event in &spec.events {
                    let count = counts.get(event.id.as_str()).copied().unwrap_or(0);
                    if count < event.min || count > event.max {
                        local.push(format!("language.variants.{vi}.trace: variant {id} violates {} cardinality", event.id));
                    }
                }
            }
            issues.extend(local);
        }
    }
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

fn project(capture: &Value, location: &Value) -> Option<(&'static str, Value)> {
    let index = location["index"].as_u64()? as usize;
    let collection = location["collection"].as_str()?;
    let (source, value) = match collection {
        "frames" => ("terminal_raw", capture["frames"].get(index).map(comparable_terminal_frame)),
        "rendered_frames" => ("terminal_rendered", capture["rendered_frames"].get(index).cloned()),
        "interaction_events" => ("interaction", capture["interaction_events"].get(index).cloned()),
        "lifecycle" => {
            let (event, base) = match index {
                0 => ("exit", &capture["exit"]),
                1 => ("settlement", &capture["settlement"]),
                _ => return None,
            };
            let mut map = Map::new();
            map.insert("event".into(), json!(event));
            if let Value::Object(fields) = base {
                map.extend(fields.clone());
            }
            ("lifecycle", Some(Value::Object(map)))
        }
        "process_samples" => ("process", capture["process_samples"].get(index).cloned()),
        "filesystem_checkpoints" => ("filesystem", capture["filesystem_checkpoints"].get(index).cloned()),
        _ => return None,
    };
    Some((source, value?))
}

fn location_value(location: &Value) -> Value {
    json!({
        "collection": location["collection"],
        "index": location["index"],
        "capture_order": location["capture_order"],
    })
}

struct Side {
    result: Value,
    diagnostic: Option<Value>,
}

fn side(status: &str, variant: Option<&str>, satisfied: Vec<String>, raw: &[Value]) -> Value {
    json!({ "satisfied_constraints": satisfied, "raw_trace": raw, "status": status, "matched_variant": variant })
}

fn failure(kind: &str, message: String, event_ids: Vec<String>, locations: Vec<Value>, raw: &[Value]) -> Side {
    Side {
        result: side("fail", None, Vec::new(), raw),
        diagnostic: Some(json!({ "kind": kind, "message": message, "event_ids": event_ids, "locations": locations })),
    }
}

fn evaluate_side(capture: &Value, spec: &TraceSpecification) -> Side {
    let sources = spec.sources();
    let scopes: HashSet<&str> = sources
        .iter()
        .map(|s| {
            if s.starts_with("terminal_") {
                "terminal"
            } else {
                match s.as_str() {
                    "lifecycle" => "exit",
                    "filesystem" => "filesystem",
                    "process" => "process",
                    _ => "interaction",
                }
            }
        })
        .collect();
    let incomplete = sources.iter().any(|s| source_truncated(capture, s))
        || capture["residual_unknowns"].as_array().into_iter().flatten().any(|u| u["scope"].as_str().is_some_and(|s| scopes.contains(s)));
    let journal = capture["event_journal"].as_array().cloned().unwrap_or_default();
    if journal.is_empty() {
        return Side {
            result: side("unknown", None, Vec::new(), &[]),
            diagnostic: Some(json!({ "kind": "journal", "message": "Capture has no cross-source event journal.", "event_ids": [], "locations": [] })),
        };
    }
    // Match records.
    let mut ignored_by_source: HashMap<&str, &Vec<String>> = HashMap::new();
    let mut events_by_key: HashMap<String, &EventDeclaration> = HashMap::new();
    for event in &spec.events {
        ignored_by_source.insert(&event.source, &event.ignore_fields);
        events_by_key.insert(format!("{}\0{}", event.source, canonical(&comparable_payload(&event.exact, &event.ignore_fields))), event);
    }
    let mut raw: Vec<Value> = Vec::new();
    let mut locations_by_id: HashMap<String, Vec<Value>> = HashMap::new();
    let mut predicate_failure: Option<Side> = None;
    for location in &journal {
        let Some((source, payload)) = project(capture, location) else { continue };
        if !sources.iter().any(|s| s == source) {
            continue;
        }
        let empty = Vec::new();
        let ignored = ignored_by_source.get(source).copied().unwrap_or(&empty);
        let key = format!("{source}\0{}", canonical(&comparable_payload(&payload, ignored)));
        let location = location_value(location);
        match events_by_key.get(&key) {
            None => {
                predicate_failure = Some(failure(
                    "predicate",
                    "Observed event does not match any declared exact predicate.".into(),
                    Vec::new(),
                    vec![location],
                    &raw,
                ));
                break;
            }
            Some(event) => {
                raw.push(json!({ "event_id": event.id, "location": location }));
                locations_by_id.entry(event.id.clone()).or_default().push(location);
            }
        }
    }
    if incomplete {
        let raw_trace = predicate_failure.as_ref().map_or(raw.clone(), |f| f.result["raw_trace"].as_array().cloned().unwrap_or_default());
        return Side { result: side("unknown", None, Vec::new(), &raw_trace), diagnostic: None };
    }
    if let Some(f) = predicate_failure {
        return f;
    }
    for event in &spec.events {
        let locations = locations_by_id.get(&event.id).cloned().unwrap_or_default();
        let n = locations.len() as u64;
        if n < event.min || n > event.max {
            return failure(
                "cardinality",
                format!("{} observed {n} times; expected {}..{}.", event.id, event.min, event.max),
                vec![event.id.clone()],
                locations,
                &raw,
            );
        }
    }
    let ids: Vec<String> = raw.iter().map(|r| r["event_id"].as_str().unwrap_or_default().to_string()).collect();
    let order = |l: &Value| l["capture_order"].as_u64().unwrap_or(0);
    match &spec.language {
        Language::PartialOrder { happens_before, not_before, unordered_groups, prefix, suffix } => {
            let mut satisfied = Vec::new();
            for (b, a) in happens_before {
                let before = locations_by_id.get(b).cloned().unwrap_or_default();
                let after = locations_by_id.get(a).cloned().unwrap_or_default();
                match (before.last(), after.first()) {
                    (None, Some(first)) => {
                        return failure("edge", format!("{b} is required when {a} occurs."), vec![b.clone(), a.clone()], vec![first.clone()], &raw)
                    }
                    (Some(last), Some(first)) if order(last) >= order(first) => {
                        return failure("edge", format!("{b} must happen before {a}."), vec![b.clone(), a.clone()], vec![last.clone(), first.clone()], &raw)
                    }
                    _ => satisfied.push(format!("happens_before:{b}:{a}")),
                }
            }
            for (event, anchor) in not_before {
                let events = locations_by_id.get(event).cloned().unwrap_or_default();
                let anchors = locations_by_id.get(anchor).cloned().unwrap_or_default();
                match (events.first(), anchors.first()) {
                    (Some(first), None) => {
                        return failure("edge", format!("{anchor} is required when {event} occurs."), vec![event.clone(), anchor.clone()], vec![first.clone()], &raw)
                    }
                    (Some(first), Some(anchor_first)) if order(first) < order(anchor_first) => {
                        return failure(
                            "edge",
                            format!("{event} must not occur before {anchor}."),
                            vec![event.clone(), anchor.clone()],
                            vec![first.clone(), anchor_first.clone()],
                            &raw,
                        )
                    }
                    _ => satisfied.push(format!("not_before:{event}:{anchor}")),
                }
            }
            for (kind, expected) in [("prefix", prefix), ("suffix", suffix)] {
                let actual: &[String] = if kind == "prefix" {
                    &ids[..expected.len().min(ids.len())]
                } else if expected.is_empty() {
                    &[]
                } else {
                    &ids[ids.len().saturating_sub(expected.len())..]
                };
                if actual != expected.as_slice() {
                    let slice: &[Value] = if kind == "prefix" {
                        &raw[..expected.len().min(raw.len())]
                    } else if expected.is_empty() {
                        // JavaScript `slice(-0)` returns the whole trace.
                        &raw[..]
                    } else {
                        &raw[raw.len().saturating_sub(expected.len())..]
                    };
                    return failure(
                        kind,
                        format!("Observed trace does not satisfy the declared {kind}."),
                        expected.clone(),
                        slice.iter().map(|r| r["location"].clone()).collect(),
                        &raw,
                    );
                }
            }
            satisfied.extend(unordered_groups.iter().map(|g| format!("unordered:{}", g.join(":"))));
            if !prefix.is_empty() {
                satisfied.push(format!("prefix:{}", prefix.join(":")));
            }
            if !suffix.is_empty() {
                satisfied.push(format!("suffix:{}", suffix.join(":")));
            }
            Side { result: side("pass", None, satisfied, &raw), diagnostic: None }
        }
        Language::FiniteTraces(variants) => {
            for (variant, trace) in variants {
                let mut offset = 0;
                let mut accepted = true;
                for token in trace {
                    match token {
                        Token::Event(id) => {
                            if ids.get(offset) != Some(id) {
                                accepted = false;
                            }
                            offset += 1;
                        }
                        Token::Unordered(group) => {
                            let mut actual: Vec<&String> = ids.iter().skip(offset).take(group.len()).collect();
                            actual.sort();
                            let mut expected: Vec<&String> = group.iter().collect();
                            expected.sort();
                            if actual != expected {
                                accepted = false;
                            }
                            offset += group.len();
                        }
                    }
                }
                if accepted && offset == ids.len() {
                    return Side { result: side("pass", Some(variant), vec![format!("variant:{variant}")], &raw), diagnostic: None };
                }
            }
            failure(
                "trace",
                "Observed events do not match any finite trace variant.".into(),
                ids.clone(),
                raw.iter().map(|r| r["location"].clone()).collect(),
                &raw,
            )
        }
    }
}

/// Compare two captures against an explicit finite trace language.
pub fn compare_traces(left: &Value, right: &Value, spec: &TraceSpecification) -> Value {
    let l = evaluate_side(left, spec);
    let r = evaluate_side(right, spec);
    let with_side = |d: &Value, side: &str| {
        let mut map = Map::new();
        map.insert("kind".into(), d["kind"].clone());
        map.insert("side".into(), json!(side));
        map.insert("message".into(), d["message"].clone());
        map.insert("event_ids".into(), d["event_ids"].clone());
        map.insert("locations".into(), d["locations"].clone());
        Value::Object(map)
    };
    let diagnostic = match (&l.diagnostic, &r.diagnostic) {
        (Some(d), _) => with_side(d, "left"),
        (None, Some(d)) => with_side(d, "right"),
        (None, None) => Value::Null,
    };
    let (ls, rs) = (l.result["status"].as_str().unwrap_or(""), r.result["status"].as_str().unwrap_or(""));
    let verdict = if ls == "unknown" || rs == "unknown" {
        "unknown"
    } else if ls == "pass" && rs == "pass" {
        "equivalent"
    } else if outcomes_differ(&l.result, &r.result) {
        "different"
    } else {
        "nonconforming"
    };
    json!({ "verdict": verdict, "left": l.result, "right": r.result, "diagnostic": diagnostic })
}

fn trace_ids(side: &Value) -> Vec<Value> {
    side["raw_trace"].as_array().into_iter().flatten().map(|r| r["event_id"].clone()).collect()
}

fn outcomes_differ(left: &Value, right: &Value) -> bool {
    left["status"] != right["status"] || trace_ids(left) != trace_ids(right)
}

/// Whether trace conformance or raw declared order differs across captures.
pub fn trace_outcomes_differ(comparison: &Value) -> bool {
    outcomes_differ(&comparison["left"], &comparison["right"])
}
