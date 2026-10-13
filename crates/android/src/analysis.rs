//! Normalization of the JADX bridge replies into REA's Android observations
//! (REA `JadxAnalysis.ts` and `JadxProtocol.ts`).

use std::collections::HashMap;

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::config::JADX_VERSION;
use crate::error::Failure;

/// A parsed Android request.
#[derive(Debug, Clone)]
pub enum Request {
    Package,
    Search { query: String },
    Class { class_name: String },
    Method { class_name: String, method_name: String, overload_index: Option<u64> },
    References { class_name: String, method_name: Option<String> },
}

impl Request {
    pub fn operation(&self) -> &'static str {
        match self {
            Request::Package => "inspect_android_package",
            Request::Search { .. } => "search_android_classes",
            Request::Class { .. } => "inspect_android_class",
            Request::Method { .. } => "inspect_android_method",
            Request::References { .. } => "trace_android_references",
        }
    }

    /// Build a request from validated tool arguments.
    pub fn from_args(operation: &str, args: &Value) -> Option<Request> {
        let text = |key: &str| args.get(key).and_then(Value::as_str).map(str::to_string);
        Some(match operation {
            "inspect_android_package" => Request::Package,
            "search_android_classes" => Request::Search { query: text("query")? },
            "inspect_android_class" => Request::Class { class_name: text("class_name")? },
            "inspect_android_method" => Request::Method {
                class_name: text("class_name")?,
                method_name: text("method_name")?,
                overload_index: args.get("overload_index").and_then(Value::as_u64),
            },
            "trace_android_references" => {
                Request::References { class_name: text("class_name")?, method_name: text("method_name") }
            }
            _ => return None,
        })
    }
}

/// The calls the analysis layer makes against the bridge.
pub trait Tools {
    fn json(&mut self, name: &str, input: Value) -> Result<Value, Failure>;
    fn text(&mut self, name: &str, input: Value) -> Result<String, Failure>;
}

fn protocol_violation(operation: &str) -> Failure {
    Failure::output(operation, "JADX response violated the pinned upstream protocol")
}

fn str_of<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn count_of(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn bool_of(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn strings_of(value: &Value, key: &str) -> Option<Vec<String>> {
    value.get(key)?.as_array()?.iter().map(|v| v.as_str().map(str::to_string)).collect()
}

/// `normalizeJadxText`: upstream byte truncation is reported, not hidden.
pub fn normalize_text(text: &str) -> Value {
    let marker = Regex::new(r"\n\n\.\.\. \[truncated: exceeds (\d+) bytes, total (\d+) bytes\]$").expect("regex");
    let captures = marker.captures(text);
    let total = captures.as_ref().and_then(|c| c[2].parse::<u64>().ok()).filter(|t| *t < (1u64 << 53));
    json!({
        "status": if captures.is_none() { "complete" } else { "partial" },
        "text": text,
        "reported_total_bytes": total,
    })
}

struct ClassSummary {
    full_name: String,
    methods: Vec<MethodSummary>,
    fields: Vec<(String, String)>,
    inner_classes: Vec<String>,
}

struct MethodSummary {
    name: String,
    signature: String,
    is_constructor: bool,
}

fn parse_class(raw: &Value) -> Option<ClassSummary> {
    let methods = raw
        .get("methods")?
        .as_array()?
        .iter()
        .map(|m| {
            m.get("def_pos")?.as_i64()?;
            Some(MethodSummary {
                name: str_of(m, "name")?.to_string(),
                signature: str_of(m, "signature")?.to_string(),
                is_constructor: bool_of(m, "is_constructor")?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    let fields = raw
        .get("fields")?
        .as_array()?
        .iter()
        .map(|f| {
            f.get("def_pos")?.as_i64()?;
            Some((str_of(f, "name")?.to_string(), str_of(f, "type")?.to_string()))
        })
        .collect::<Option<Vec<_>>>()?;
    let inner = strings_of(raw, "inner_classes")?;
    str_of(raw, "name")?;
    count_of(raw, "method_count")?;
    count_of(raw, "field_count")?;
    count_of(raw, "inner_class_count")?;
    Some(ClassSummary { full_name: str_of(raw, "full_name")?.to_string(), methods, fields, inner_classes: inner })
}

fn methods_of(summary: &ClassSummary) -> Vec<Value> {
    let mut seen: HashMap<&str, u64> = HashMap::new();
    summary
        .methods
        .iter()
        .map(|method| {
            let index = seen.get(method.name.as_str()).copied().unwrap_or(0);
            seen.insert(method.name.as_str(), index + 1);
            json!({
                "name": method.name,
                "reported_signature": method.signature,
                "overload_index": index,
                "is_constructor": method.is_constructor,
                "dex_descriptor": null,
            })
        })
        .collect()
}

fn class_summary(tools: &mut dyn Tools, operation: &str, class_name: &str) -> Result<ClassSummary, Failure> {
    let raw = tools.json("get_class_summary", json!({ "class_name": class_name }))?;
    if let Some(error) = raw.as_object().and_then(|o| o.get("error")).and_then(Value::as_str) {
        return Err(Failure::output(operation, format!("JADX class summary failed: {error}")));
    }
    let Some(value) = parse_class(&raw) else {
        return Err(Failure::output(
            operation,
            "JADX class summary failed or was malformed; negative counts are not an empty class",
        ));
    };
    if value.full_name != class_name {
        return Err(Failure::input(
            operation,
            "class_name",
            format!(
                "Exact class {class_name} resolved to {}; use the fully qualified class name from search_android_classes.",
                value.full_name
            ),
        ));
    }
    let (method_count, field_count, inner_count) = (
        count_of(&raw, "method_count").unwrap_or(0),
        count_of(&raw, "field_count").unwrap_or(0),
        count_of(&raw, "inner_class_count").unwrap_or(0),
    );
    if method_count != value.methods.len() as u64
        || field_count != value.fields.len() as u64
        || inner_count != value.inner_classes.len() as u64
    {
        return Err(Failure::output(operation, "JADX class member counts do not match the returned inventory"));
    }
    Ok(value)
}

fn inspect_package(tools: &mut dyn Tools, operation: &str, loaded: &Value, engine: &Value) -> Result<Value, Failure> {
    let app = tools.json("get_app_info", json!({}))?;
    let valid = ["package", "version_name", "version_code", "min_sdk", "target_sdk"].iter().all(|k| str_of(&app, k).is_some())
        && strings_of(&app, "permissions").is_some();
    if !valid {
        return Err(protocol_violation(operation));
    }
    let manifest = normalize_text(&tools.text("get_android_manifest", json!({}))?);
    let nullable = |key: &str| -> Value {
        match str_of(&app, key) {
            Some(text) if !text.is_empty() => json!(text),
            _ => Value::Null,
        }
    };
    Ok(json!({
        "engine": engine,
        "package_name": nullable("package"),
        "version_name": nullable("version_name"),
        "version_code": nullable("version_code"),
        "min_sdk": nullable("min_sdk"),
        "target_sdk": nullable("target_sdk"),
        "permissions": app["permissions"],
        "manifest": manifest,
        "class_count": loaded["class_count"],
        "resource_count": loaded["resource_count"],
        "signature_verification": "not_performed",
    }))
}

fn search_classes(tools: &mut dyn Tools, operation: &str, query: &str, loaded: &Value, engine: &Value) -> Result<Value, Failure> {
    let mut classes: Vec<String> = Vec::new();
    let page_size: u64 = 4096;
    let mut total: Option<u64> = None;
    loop {
        let page = tools.json("list_classes", json!({ "offset": classes.len(), "limit": page_size }))?;
        let (Some(page_total), Some(offset), Some(limit), Some(items)) =
            (count_of(&page, "total"), count_of(&page, "offset"), count_of(&page, "limit"), strings_of(&page, "items"))
        else {
            return Err(protocol_violation(operation));
        };
        if total.is_some_and(|t| t != page_total) || offset != classes.len() as u64 || limit != page_size || items.len() as u64 > page_size {
            return Err(Failure::output(operation, "JADX class pagination changed identity or counts"));
        }
        total = Some(page_total);
        let empty = items.is_empty();
        classes.extend(items);
        if classes.len() as u64 > page_total || (empty && (classes.len() as u64) < page_total) {
            return Err(Failure::output(operation, "JADX class pagination is incomplete"));
        }
        if classes.len() as u64 >= page_total {
            break;
        }
    }
    let total = total.unwrap_or(0);
    let mut unique = classes.clone();
    unique.sort();
    unique.dedup();
    if unique.len() != classes.len() || Some(total) != count_of(loaded, "class_count") {
        return Err(Failure::output(operation, "JADX class inventory is duplicated or differs from the loaded class count"));
    }
    Ok(json!({
        "engine": engine,
        "query": query,
        "total_classes": total,
        "matches": classes.iter().filter(|name| name.contains(query)).collect::<Vec<_>>(),
        "coverage": "complete",
    }))
}

fn matching_methods(summary: &ClassSummary, operation: &str, method_name: Option<&str>) -> Result<Vec<Value>, Failure> {
    let candidates: Vec<Value> =
        methods_of(summary).into_iter().filter(|m| method_name.is_some_and(|n| m["name"] == n)).collect();
    if let Some(name) = method_name {
        if candidates.is_empty() {
            return Err(Failure::input(
                operation,
                "method_name",
                format!("Method {}.{name} was not found; inspect_android_class lists available methods.", summary.full_name),
            ));
        }
    }
    Ok(candidates)
}

fn inspect_method(
    tools: &mut dyn Tools,
    operation: &str,
    class_name: &str,
    method_name: &str,
    overload_index: Option<u64>,
    summary: &ClassSummary,
    engine: &Value,
) -> Result<Value, Failure> {
    let _ = class_name;
    let candidates = matching_methods(summary, operation, Some(method_name))?;
    if candidates.len() > 1 && overload_index.is_none() {
        let listing = candidates
            .iter()
            .map(|m| format!("{}: {}", m["overload_index"], m["reported_signature"].as_str().unwrap_or_default()))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(Failure::input(operation, "overload_index", format!("Select one of {} overloads: {listing}", candidates.len())));
    }
    let index = overload_index.unwrap_or(0);
    let Some(selected) = candidates.get(index as usize).cloned() else {
        return Err(Failure::input(
            operation,
            "overload_index",
            format!("Index {index} is outside the {} matching overloads.", candidates.len()),
        ));
    };
    let body = tools.json(
        "get_method_body",
        json!({
            "class_name": summary.full_name,
            "method_name": method_name,
            "overload_index": index,
            "smali_fallback": true,
        }),
    )?;
    let (Some(body_class), Some(body_method), Some(_full), Some(body_index), Some(body_count), Some(mode), Some(fell_back), Some(markers), Some(text)) = (
        str_of(&body, "class_name"),
        str_of(&body, "method_name"),
        str_of(&body, "full_name"),
        count_of(&body, "overload_index"),
        count_of(&body, "overload_count"),
        str_of(&body, "mode").filter(|m| *m == "java" || *m == "smali"),
        bool_of(&body, "fell_back"),
        strings_of(&body, "markers"),
        str_of(&body, "body"),
    ) else {
        return Err(protocol_violation(operation));
    };
    if body_class != summary.full_name || body_method != method_name || body_index != index || body_count != candidates.len() as u64 {
        return Err(Failure::output(operation, "JADX returned a different method or overload inventory"));
    }
    if text.starts_with("// ERROR:") {
        return Err(Failure::output(operation, format!("JADX did not produce method source: {text}")));
    }
    if mode == "smali" && candidates.len() > 1 {
        return Err(Failure::capability(
            "jadx",
            operation,
            format!(
                "JADX {JADX_VERSION} smali fallback joins all same-name overloads for {}.{method_name}; it cannot establish source for only overload {index}.",
                summary.full_name
            ),
        ));
    }
    Ok(json!({
        "engine": engine,
        "class_name": summary.full_name,
        "method": selected,
        "overload_count": candidates.len(),
        "representation": mode,
        "body_status": if text.is_empty() || text == "// method exists but has no decompiled body (native/abstract)" { "not_available" } else { "available" },
        "fell_back": fell_back,
        "markers": markers,
        "source": normalize_text(text),
    }))
}

fn trace_references(
    tools: &mut dyn Tools,
    operation: &str,
    method_name: Option<&str>,
    summary: &ClassSummary,
    engine: &Value,
) -> Result<Value, Failure> {
    let candidates = matching_methods(summary, operation, method_name)?;
    if candidates.len() > 1 {
        return Err(Failure::capability(
            "jadx",
            operation,
            format!(
                "References require a unique method name; {}.{} has {} overloads. No unambiguous reference result is available.",
                summary.full_name,
                method_name.unwrap_or("undefined"),
                candidates.len()
            ),
        ));
    }
    let expected_target = match method_name {
        None => summary.full_name.clone(),
        Some(name) => format!("{}.{name}", summary.full_name),
    };
    let mut input = Map::new();
    input.insert("class_name".into(), json!(summary.full_name));
    if let Some(name) = method_name {
        input.insert("method_name".into(), json!(name));
    }
    input.insert("limit".into(), json!(2_147_483_647u64));
    input.insert("resolve_line".into(), json!(false));
    let xrefs = tools.json(
        if method_name.is_none() { "get_xrefs_to_class" } else { "get_xrefs_to_method" },
        Value::Object(input),
    )?;
    let items = xrefs.get("items").and_then(Value::as_array);
    let valid = str_of(&xrefs, "target").is_some()
        && count_of(&xrefs, "total").is_some()
        && count_of(&xrefs, "count").is_some()
        && xrefs.get("resolve_line") == Some(&json!(false))
        && items.is_some_and(|items| {
            items.iter().all(|i| {
                ["kind", "name", "full_name", "containing_class", "top_class"].iter().all(|k| str_of(i, k).is_some())
                    && i.get("def_pos").and_then(Value::as_i64).is_some()
            })
        });
    if !valid {
        return Err(protocol_violation(operation));
    }
    let items = items.cloned().unwrap_or_default();
    let total = count_of(&xrefs, "total").unwrap_or(0);
    if str_of(&xrefs, "target") != Some(expected_target.as_str()) || total != count_of(&xrefs, "count").unwrap_or(0) || total != items.len() as u64 {
        return Err(Failure::output(operation, "JADX references are incomplete or refer to another target"));
    }
    Ok(json!({
        "engine": engine,
        "class_name": summary.full_name,
        "method_name": method_name,
        "total": total,
        "references": items.iter().map(|r| json!({
            "kind": r["kind"],
            "name": r["name"],
            "reported_full_name": r["full_name"],
            "containing_class": r["containing_class"],
            "top_class": r["top_class"],
            "source_line": null,
            "dex_offset": null,
        })).collect::<Vec<_>>(),
        "coverage": "complete",
    }))
}

/// Normalize only the selected analyst outcome and reject ambiguous engine selectors.
pub fn analyze_request(tools: &mut dyn Tools, request: &Request, loaded: &Value, engine: &Value) -> Result<Value, Failure> {
    let operation = request.operation();
    match request {
        Request::Package => inspect_package(tools, operation, loaded, engine),
        Request::Search { query } => search_classes(tools, operation, query, loaded, engine),
        Request::Class { class_name } => {
            let summary = class_summary(tools, operation, class_name)?;
            Ok(json!({
                "engine": engine,
                "class_name": summary.full_name,
                "methods": methods_of(&summary),
                "fields": summary.fields.iter().map(|(name, ty)| json!({ "name": name, "reported_type": ty })).collect::<Vec<_>>(),
                "inner_classes": summary.inner_classes,
            }))
        }
        Request::Method { class_name, method_name, overload_index } => {
            let summary = class_summary(tools, operation, class_name)?;
            inspect_method(tools, operation, class_name, method_name, *overload_index, &summary, engine)
        }
        Request::References { class_name, method_name } => {
            let summary = class_summary(tools, operation, class_name)?;
            trace_references(tools, operation, method_name.as_deref(), &summary, engine)
        }
    }
}
