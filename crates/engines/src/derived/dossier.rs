//! Strict function-dossier validation (`functionDossierSchema`) and the parsed snapshot used
//! by the comparison and call-path tools.
//!
//! The validator reports issues in the order, with the paths and with the messages of the
//! zod schema it ports, because REA surfaces the first issue (and the count of the rest) to
//! callers. `native_api` and `native_value_flow` are only checked to be an object or null:
//! their nested schemas (native API boundaries, value flows) belong to other tools.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};
use tracewise_domain::evidence::{Evidence, EvidenceSubject};

use super::util::sorted_unique;
use super::{parse_evidence, DerivedError};

/// One validation issue: a path (strings and indexes) and a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub path: Vec<String>,
    pub message: String,
}

/// `describeValidationFailure` for a list of issues.
pub fn describe_issues(issues: &[Issue]) -> String {
    let (first, rest) = issues.split_first().expect("at least one issue");
    let location = if first.path.is_empty() {
        "the document root".to_string()
    } else {
        first.path.join(".")
    };
    let more = if rest.is_empty() {
        String::new()
    } else {
        format!(" ({} more issues)", rest.len())
    };
    format!("at {location}: {}{more}", first.message)
}

pub(super) fn js_type(value: Option<&Value>) -> &'static str {
    match value {
        None => "undefined",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    }
}

pub(super) struct Check {
    pub(super) issues: Vec<Issue>,
    /// Issues zod treats as aborting (type, enum, key and discriminator failures); value
    /// checks such as lengths and patterns still let refinements run.
    pub(super) aborts: usize,
}

impl Check {
    pub(super) fn push(&mut self, path: &[String], message: impl Into<String>) {
        self.issues.push(Issue {
            path: path.to_vec(),
            message: message.into(),
        });
    }

    pub(super) fn push_abort(&mut self, path: &[String], message: impl Into<String>) {
        self.aborts += 1;
        self.push(path, message);
    }

    pub(super) fn type_error(&mut self, path: &[String], expected: &str, value: Option<&Value>) {
        self.push_abort(
            path,
            format!("Invalid input: expected {expected}, received {}", js_type(value)),
        );
    }

    pub(super) fn string(&mut self, path: &[String], value: Option<&Value>, min_length: usize) {
        match value {
            Some(Value::String(text)) => {
                if text.chars().count() < min_length {
                    self.push(
                        path,
                        format!("Too small: expected string to have >={min_length} characters"),
                    );
                }
            }
            other => self.type_error(path, "string", other),
        }
    }

    fn nullable_string(&mut self, path: &[String], value: Option<&Value>) {
        if !matches!(value, Some(Value::Null)) {
            self.string(path, value, 0);
        }
    }

    pub(super) fn boolean(&mut self, path: &[String], value: Option<&Value>) {
        if !matches!(value, Some(Value::Bool(_))) {
            self.type_error(path, "boolean", value);
        }
    }

    fn integer(&mut self, path: &[String], value: Option<&Value>, min: Option<i64>, max: Option<i64>) {
        match value {
            Some(Value::Number(number)) => {
                let float = number.as_f64().unwrap_or(0.0);
                if float.fract() != 0.0 {
                    self.push_abort(path, "Invalid input: expected int, received number");
                    return;
                }
                if let Some(min) = min {
                    if float < min as f64 {
                        self.push(path, format!("Too small: expected number to be >={min}"));
                        return;
                    }
                }
                if let Some(max) = max {
                    if float > max as f64 {
                        self.push(path, format!("Too big: expected number to be <={max}"));
                    }
                }
            }
            other => self.type_error(path, "number", other),
        }
    }

    fn nullable_integer(&mut self, path: &[String], value: Option<&Value>, min: Option<i64>, max: Option<i64>) {
        if !matches!(value, Some(Value::Null)) {
            self.integer(path, value, min, max);
        }
    }

    fn enumeration(&mut self, path: &[String], value: Option<&Value>, options: &[&str]) {
        match value {
            Some(Value::String(text)) if options.contains(&text.as_str()) => {}
            Some(Value::String(_)) | Some(_) | None => {
                if matches!(value, Some(Value::String(_))) {
                    let list: Vec<String> = options.iter().map(|o| format!("\"{o}\"")).collect();
                    self.push_abort(path, format!("Invalid option: expected one of {}", list.join("|")));
                } else {
                    self.type_error(path, "string", value);
                }
            }
        }
    }

    pub(super) fn array<'a>(&mut self, path: &[String], value: Option<&'a Value>) -> Option<&'a Vec<Value>> {
        match value {
            Some(Value::Array(items)) => Some(items),
            other => {
                self.type_error(path, "array", other);
                None
            }
        }
    }

    pub(super) fn object<'a>(&mut self, path: &[String], value: Option<&'a Value>) -> Option<&'a Map<String, Value>> {
        match value {
            Some(Value::Object(map)) => Some(map),
            other => {
                self.type_error(path, "object", other);
                None
            }
        }
    }

    pub(super) fn strict_keys(&mut self, path: &[String], map: &Map<String, Value>, known: &[&str]) {
        let unknown: Vec<&String> = map.keys().filter(|key| !known.contains(&key.as_str())).collect();
        match unknown.len() {
            0 => {}
            1 => self.push_abort(path, format!("Unrecognized key: \"{}\"", unknown[0])),
            _ => {
                let list: Vec<String> = unknown.iter().map(|key| format!("\"{key}\"")).collect();
                self.push_abort(path, format!("Unrecognized keys: {}", list.join(", ")));
            }
        }
    }
}

pub(super) fn child(path: &[String], key: impl ToString) -> Vec<String> {
    let mut next = path.to_vec();
    next.push(key.to_string());
    next
}

const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// `addressCoordinate`: the address space and numeric offset, `None` when malformed.
fn address_coordinate(value: &str) -> Option<(String, u128)> {
    let (space, offset) = match value.rfind(":0x") {
        Some(separator) => (value[..separator].to_string(), &value[separator + 1..]),
        None => ("default".to_string(), value),
    };
    let digits = offset.strip_prefix("0x")?;
    if digits.is_empty() || !digits.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    u128::from_str_radix(digits, 16).ok().map(|offset| (space, offset))
}

fn body_refinement(body: &Map<String, Value>) -> Option<&'static str> {
    let ranges = body.get("ranges").and_then(Value::as_array)?;
    let mut total: u128 = 0;
    let mut bounds: BTreeMap<String, (u128, u128)> = BTreeMap::new();
    let mut closed: BTreeSet<String> = BTreeSet::new();
    let mut previous_space: Option<String> = None;
    for range in ranges {
        let start = address_coordinate(range.get("start").and_then(Value::as_str).unwrap_or(""));
        let end = address_coordinate(range.get("end").and_then(Value::as_str).unwrap_or(""));
        let (Some(start), Some(end)) = (start, end) else {
            return Some("Function body range has invalid inclusive endpoints");
        };
        if start.0 != end.0 || end.1 < start.1 {
            return Some("Function body range has invalid inclusive endpoints");
        }
        if let Some(previous) = &previous_space {
            if *previous != start.0 {
                closed.insert(previous.clone());
            }
        }
        let previous = bounds.get(&start.0).copied();
        if closed.contains(&start.0) || previous.is_some_and(|(_, last_end)| start.1 <= last_end + 1) {
            return Some("Function body ranges must be ordered, disjoint and maximal within each address space");
        }
        bounds.insert(start.0.clone(), (previous.map_or(start.1, |(first, _)| first), end.1));
        previous_space = Some(start.0);
        total += end.1 - start.1 + 1;
    }
    let span: Option<u128> = if bounds.is_empty() {
        Some(0)
    } else if bounds.len() == 1 {
        bounds.values().next().map(|(first, last)| last - first + 1)
    } else {
        None
    };
    let reported_span = match body.get("span_bytes") {
        Some(Value::Null) => None,
        Some(value) => value.as_u64().map(u128::from),
        None => None,
    };
    let reported_total = body.get("total_bytes").and_then(Value::as_u64).map(u128::from);
    let non_contiguous = body.get("non_contiguous").and_then(Value::as_bool);
    if Some(total) != reported_total || span != reported_span || non_contiguous != Some(ranges.len() > 1) {
        return Some("Function body counts, enclosing span or contiguity disagree with inclusive ranges");
    }
    None
}

fn body_entry_agrees(body: &Map<String, Value>, address: &str) -> bool {
    if body.get("available") != Some(&Value::Bool(true)) {
        return true;
    }
    let Some(entry) = address_coordinate(address) else {
        return false;
    };
    let contains = body
        .get("ranges")
        .and_then(Value::as_array)
        .map(|ranges| {
            ranges.iter().any(|range| {
                let start = address_coordinate(range.get("start").and_then(Value::as_str).unwrap_or(""));
                let end = address_coordinate(range.get("end").and_then(Value::as_str).unwrap_or(""));
                match (start, end) {
                    (Some(start), Some(end)) => start.0 == entry.0 && entry.1 >= start.1 && entry.1 <= end.1,
                    _ => false,
                }
            })
        })
        .unwrap_or(false);
    Some(contains) == body.get("contains_entry").and_then(Value::as_bool)
}

fn unavailable_fact(check: &mut Check, path: &[String], map: &Map<String, Value>) {
    check.strict_keys(path, map, &["available", "reason"]);
    check.string(&child(path, "reason"), map.get("reason"), 0);
}

fn function_body(check: &mut Check, path: &[String], value: Option<&Value>) {
    let Some(map) = check.object(path, value) else { return };
    let before = check.aborts;
    match map.get("available") {
        Some(Value::Bool(false)) => unavailable_fact(check, path, map),
        Some(Value::Bool(true)) => {
            let known = [
                "available",
                "provenance",
                "ranges",
                "total_bytes",
                "span_bytes",
                "non_contiguous",
                "contains_entry",
            ];
            check.string(&child(path, "provenance"), map.get("provenance"), 1);
            let ranges_path = child(path, "ranges");
            if let Some(ranges) = check.array(&ranges_path, map.get("ranges")) {
                for (index, range) in ranges.iter().enumerate() {
                    let range_path = child(&ranges_path, index);
                    if let Some(range) = check.object(&range_path, Some(range)) {
                        check.string(&child(&range_path, "start"), range.get("start"), 0);
                        check.string(&child(&range_path, "end"), range.get("end"), 0);
                        check.strict_keys(&range_path, range, &["start", "end"]);
                    }
                }
            }
            check.integer(&child(path, "total_bytes"), map.get("total_bytes"), Some(0), Some(MAX_SAFE_INTEGER));
            check.nullable_integer(&child(path, "span_bytes"), map.get("span_bytes"), Some(0), Some(MAX_SAFE_INTEGER));
            check.boolean(&child(path, "non_contiguous"), map.get("non_contiguous"));
            check.boolean(&child(path, "contains_entry"), map.get("contains_entry"));
            check.strict_keys(path, map, &known);
            if check.aborts == before {
                if let Some(message) = body_refinement(map) {
                    check.push(path, message);
                }
            }
        }
        _ => check.push_abort(&child(path, "available"), "Invalid discriminator value. Expected 'false' | 'true'"),
    }
}

fn classification(check: &mut Check, path: &[String], value: Option<&Value>) {
    if matches!(value, Some(Value::Null)) {
        return;
    }
    let Some(map) = check.object(path, value) else { return };
    check.boolean(&child(path, "external"), map.get("external"));
    check.boolean(&child(path, "thunk"), map.get("thunk"));
    check.nullable_string(&child(path, "thunk_target"), map.get("thunk_target"));
    check.string(&child(path, "provenance"), map.get("provenance"), 1);
    check.strict_keys(path, map, &["external", "thunk", "thunk_target", "provenance"]);
}

/// `procedureIdentitySchema`; `extended` adds the dossier's `signature` and `locals`.
fn procedure_identity(check: &mut Check, path: &[String], value: Option<&Value>, extended: bool) {
    let Some(map) = check.object(path, value) else { return };
    let before = check.aborts;
    check.string(&child(path, "address"), map.get("address"), 0);
    check.string(&child(path, "name"), map.get("name"), 0);
    classification(check, &child(path, "classification"), map.get("classification"));
    function_body(check, &child(path, "body"), map.get("body"));
    let mut known = vec!["address", "name", "classification", "body"];
    if extended {
        check.nullable_string(&child(path, "signature"), map.get("signature"));
        let locals_path = child(path, "locals");
        if let Some(locals) = check.array(&locals_path, map.get("locals")) {
            for (index, local) in locals.iter().enumerate() {
                let local_path = child(&locals_path, index);
                let Some(local) = check.object(&local_path, Some(local)) else { continue };
                check.string(&child(&local_path, "description"), local.get("description"), 0);
                check.string(&child(&local_path, "provenance"), local.get("provenance"), 1);
                if let Some(name) = local.get("name") {
                    check.nullable_string(&child(&local_path, "name"), Some(name));
                }
                if let Some(displacement) = local.get("stack_displacement") {
                    let displacement_path = child(&local_path, "stack_displacement");
                    if !displacement.is_null() {
                        match displacement.as_str() {
                            Some(text) => {
                                let digits = text.strip_prefix('-').unwrap_or(text);
                                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                                    check.push(&displacement_path, "Invalid string: must match pattern /^-?\\d+$/u");
                                }
                            }
                            None => check.type_error(&displacement_path, "string", Some(displacement)),
                        }
                    }
                }
                check.strict_keys(&local_path, local, &["description", "provenance", "name", "stack_displacement"]);
            }
        }
        known.extend(["signature", "locals"]);
    }
    check.strict_keys(path, map, &known);
    if check.aborts == before {
        let agrees = match (map.get("body"), map.get("address")) {
            (Some(Value::Object(body)), Some(Value::String(address))) => body_entry_agrees(body, address),
            _ => true,
        };
        if !agrees {
            check.push(path, "Function body entry membership disagrees with procedure identity");
        }
    }
}

fn nullable_identity(check: &mut Check, path: &[String], value: Option<&Value>) {
    if !matches!(value, Some(Value::Null)) {
        procedure_identity(check, path, value, false);
    }
}

fn reference_kind(check: &mut Check, path: &[String], value: Option<&Value>) {
    let Some(map) = check.object(path, value) else { return };
    match map.get("available") {
        Some(Value::Bool(false)) => unavailable_fact(check, path, map),
        Some(Value::Bool(true)) => {
            check.string(&child(path, "provenance"), map.get("provenance"), 1);
            check.string(&child(path, "type"), map.get("type"), 0);
            for key in [
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
            ] {
                check.boolean(&child(path, key), map.get(key));
            }
            check.integer(&child(path, "operand_index"), map.get("operand_index"), None, None);
            check.boolean(&child(path, "external"), map.get("external"));
            check.strict_keys(
                path,
                map,
                &[
                    "available",
                    "provenance",
                    "type",
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
                    "operand_index",
                    "external",
                ],
            );
        }
        _ => check.push_abort(&child(path, "available"), "Invalid discriminator value. Expected 'false' | 'true'"),
    }
}

fn reference_edges(check: &mut Check, path: &[String], value: Option<&Value>) {
    let Some(edges) = check.array(path, value) else { return };
    for (index, edge) in edges.iter().enumerate() {
        let edge_path = child(path, index);
        let Some(map) = check.object(&edge_path, Some(edge)) else { continue };
        check.string(&child(&edge_path, "source_address"), map.get("source_address"), 0);
        check.string(&child(&edge_path, "target_address"), map.get("target_address"), 0);
        nullable_identity(check, &child(&edge_path, "source_procedure"), map.get("source_procedure"));
        nullable_identity(check, &child(&edge_path, "target_procedure"), map.get("target_procedure"));
        reference_kind(check, &child(&edge_path, "kind"), map.get("kind"));
        if let Some(call) = map.get("call") {
            let call_path = child(&edge_path, "call");
            if let Some(call) = check.object(&call_path, Some(call)) {
                check.enumeration(
                    &child(&call_path, "classification"),
                    call.get("classification"),
                    &["none", "unknown", "direct", "objective_c"],
                );
                check.integer(&child(&call_path, "provider_type"), call.get("provider_type"), None, None);
                check.string(&child(&call_path, "provenance"), call.get("provenance"), 1);
                check.strict_keys(&call_path, call, &["classification", "provider_type", "provenance"]);
            }
        }
        check.strict_keys(
            &edge_path,
            map,
            &["source_address", "target_address", "source_procedure", "target_procedure", "kind", "call"],
        );
    }
}

fn strict_records(
    check: &mut Check,
    path: &[String],
    value: Option<&Value>,
    keys: &[&str],
    each: impl Fn(&mut Check, &[String], &Map<String, Value>),
) {
    let Some(items) = check.array(path, value) else { return };
    for (index, item) in items.iter().enumerate() {
        let item_path = child(path, index);
        if let Some(map) = check.object(&item_path, Some(item)) {
            each(check, &item_path, map);
            check.strict_keys(&item_path, map, keys);
        }
    }
}

fn identities(check: &mut Check, path: &[String], value: Option<&Value>) {
    let Some(items) = check.array(path, value) else { return };
    for (index, item) in items.iter().enumerate() {
        procedure_identity(check, &child(path, index), Some(item), false);
    }
}

fn loose_object_or_null(check: &mut Check, path: &[String], value: Option<&Value>) {
    if !matches!(value, Some(Value::Null)) {
        check.object(path, value);
    }
}

fn referenced_strings(check: &mut Check, path: &[String], value: Option<&Value>) {
    let Some(items) = check.array(path, value) else { return };
    for (index, item) in items.iter().enumerate() {
        let item_path = child(path, index);
        let Some(map) = check.object(&item_path, Some(item)) else { continue };
        check.string(&child(&item_path, "address"), map.get("address"), 0);
        check.string(&child(&item_path, "value"), map.get("value"), 0);
        if let Some(provider_value) = map.get("provider_value") {
            check.string(&child(&item_path, "provider_value"), Some(provider_value), 0);
        }
        if let Some(decoding) = map.get("decoding") {
            let decoding_path = child(&item_path, "decoding");
            if let Some(decoding) = check.object(&decoding_path, Some(decoding)) {
                if decoding.get("available") != Some(&Value::Bool(false)) {
                    check.push_abort(&child(&decoding_path, "available"), "Invalid input: expected false");
                }
                unavailable_fact(check, &decoding_path, decoding);
            }
        }
        if let Some(string) = map.get("string") {
            let string_path = child(&item_path, "string");
            if let Some(string) = check.object(&string_path, Some(string)) {
                check.string(&child(&string_path, "encoding"), string.get("encoding"), 1);
                if let Some(status) = string.get("encoding_status") {
                    check.enumeration(&child(&string_path, "encoding_status"), Some(status), &["observed", "inferred"]);
                }
                check.enumeration(
                    &child(&string_path, "termination"),
                    string.get("termination"),
                    &["missing", "present_or_not_required"],
                );
                check.integer(&child(&string_path, "byte_length"), string.get("byte_length"), Some(0), None);
            }
        }
        check.string(&child(&item_path, "source_address"), map.get("source_address"), 0);
    }
}

/// Validate a dossier, returning every issue in zod order.
pub fn validate_dossier(value: &Value) -> Vec<Issue> {
    let mut check = Check {
        issues: Vec::new(),
        aborts: 0,
    };
    let path: Vec<String> = Vec::new();
    let Some(map) = check.object(&path, Some(value)) else {
        return check.issues;
    };
    procedure_identity(&mut check, &child(&path, "procedure"), map.get("procedure"), true);
    check.string(&child(&path, "pseudocode"), map.get("pseudocode"), 0);
    let assembly_path = child(&path, "assembly");
    if let Some(items) = check.array(&assembly_path, map.get("assembly")) {
        for (index, item) in items.iter().enumerate() {
            check.string(&child(&assembly_path, index), Some(item), 0);
        }
    }
    strict_records(
        &mut check,
        &child(&path, "comments"),
        map.get("comments"),
        &["address", "kind", "text"],
        |check, path, map| {
            check.string(&child(path, "address"), map.get("address"), 0);
            check.enumeration(&child(path, "kind"), map.get("kind"), &["comment", "inline"]);
            check.string(&child(path, "text"), map.get("text"), 0);
        },
    );
    identities(&mut check, &child(&path, "callers"), map.get("callers"));
    identities(&mut check, &child(&path, "callees"), map.get("callees"));
    reference_edges(&mut check, &child(&path, "incoming_references"), map.get("incoming_references"));
    reference_edges(&mut check, &child(&path, "outgoing_references"), map.get("outgoing_references"));
    if let Some(unresolved) = map.get("unresolved_calls") {
        strict_records(
            &mut check,
            &child(&path, "unresolved_calls"),
            Some(unresolved),
            &["address", "reason"],
            |check, path, map| {
                check.string(&child(path, "address"), map.get("address"), 0);
                check.string(&child(path, "reason"), map.get("reason"), 0);
            },
        );
    }
    referenced_strings(&mut check, &child(&path, "referenced_strings"), map.get("referenced_strings"));
    strict_records(
        &mut check,
        &child(&path, "referenced_names"),
        map.get("referenced_names"),
        &["address", "value", "source_address"],
        |check, path, map| {
            for key in ["address", "value", "source_address"] {
                check.string(&child(path, key), map.get(key), 0);
            }
        },
    );
    strict_records(
        &mut check,
        &child(&path, "basic_blocks"),
        map.get("basic_blocks"),
        &["start", "end", "successors"],
        |check, path, map| {
            check.string(&child(path, "start"), map.get("start"), 0);
            check.string(&child(path, "end"), map.get("end"), 0);
            let successors_path = child(path, "successors");
            if let Some(items) = check.array(&successors_path, map.get("successors")) {
                for (index, item) in items.iter().enumerate() {
                    check.string(&child(&successors_path, index), Some(item), 0);
                }
            }
        },
    );
    loose_object_or_null(&mut check, &child(&path, "native_api"), map.get("native_api"));
    loose_object_or_null(&mut check, &child(&path, "native_value_flow"), map.get("native_value_flow"));
    let limitations_path = child(&path, "limitations");
    if let Some(items) = check.array(&limitations_path, map.get("limitations")) {
        for (index, item) in items.iter().enumerate() {
            check.string(&child(&limitations_path, index), Some(item), 0);
        }
    }
    check.strict_keys(
        &path,
        map,
        &[
            "procedure",
            "pseudocode",
            "assembly",
            "comments",
            "callers",
            "callees",
            "incoming_references",
            "outgoing_references",
            "unresolved_calls",
            "referenced_strings",
            "referenced_names",
            "basic_blocks",
            "native_api",
            "native_value_flow",
            "limitations",
        ],
    );
    check.issues
}

/// Complete function observation parsed from one `analyze_function` Evidence record.
pub struct FunctionSnapshot {
    pub evidence: Evidence,
    pub subject: EvidenceSubject,
    pub dossier: Value,
    pub limitations: Vec<String>,
}

impl FunctionSnapshot {
    fn procedure(&self) -> &Value {
        &self.dossier["procedure"]
    }

    pub fn name(&self) -> &str {
        self.procedure()["name"].as_str().unwrap_or("")
    }

    pub fn address(&self) -> &str {
        self.procedure()["address"].as_str().unwrap_or("")
    }

    pub fn field(&self, key: &str) -> &[Value] {
        self.dossier[key].as_array().map(Vec::as_slice).unwrap_or(&[])
    }
}

/// `parseFunctionEvidence`: authenticate the record, then require a complete dossier.
pub fn parse_function_evidence(input: &Value) -> Result<FunctionSnapshot, DerivedError> {
    let evidence = parse_evidence(input).map_err(|issue| DerivedError::Input(describe_issues(&[issue])))?;
    if evidence.operation != "analyze_function" {
        return Err(DerivedError::Input("Function comparison requires analyze_function Evidence".into()));
    }
    let Some(subject) = evidence.subject.clone() else {
        return Err(DerivedError::Input("Function comparison requires artifact-bound Evidence".into()));
    };
    let issues = validate_dossier(&evidence.normalized_result);
    if !issues.is_empty() {
        return Err(DerivedError::Input(describe_issues(&issues)));
    }
    let mut limitations: Vec<String> = evidence.limitations.clone();
    limitations.extend(
        evidence.normalized_result["limitations"]
            .as_array()
            .map(|items| items.iter().filter_map(|item| item.as_str().map(str::to_string)))
            .into_iter()
            .flatten(),
    );
    let limitations = sorted_unique(limitations);
    let dossier = evidence.normalized_result.clone();
    Ok(FunctionSnapshot {
        evidence,
        subject,
        dossier,
        limitations,
    })
}

