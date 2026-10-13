//! Composed investigation workflows over a provider port (port of `EnhancedTools.ts`
//! and the helpers it drives). Every workflow calls only provider operations, so it works
//! with whichever engine the session is bound to.

pub mod address_context;
pub mod call_path;
pub mod dispatch_metadata;
pub mod literal;
pub mod native_api;
pub mod native_value;
pub mod symbols;

use std::collections::{BTreeMap, HashSet};

use serde_json::{json, Map, Value};
use tracewise_domain::evidence::{EvidenceLocation, EvidenceSubject};

use crate::error::AnalysisError;
use crate::provider::{AnalysisExecution, ExecContext};
use crate::session::OperationPort;

use symbols::Addressed;

/// Tools implemented as workflows.
pub const WORKFLOW_TOOLS: [&str; 14] = [
    "trace_native_values",
    "inspect_native_dispatch_metadata",
    "get_objc_classes",
    "get_objc_protocols",
    "batch_decompile",
    "get_call_graph",
    "analyze_swift_types",
    "find_xrefs_to_name",
    "binary_overview",
    "inspect_native_api",
    "trace_feature",
    "trace_call_path",
    "inspect_address_context",
    "get_navigation_context",
];

pub fn is_workflow(name: &str) -> bool {
    WORKFLOW_TOOLS.contains(&name)
}

/// Successful workflow output.
pub struct Outcome {
    pub result: Value,
    pub locations: Vec<EvidenceLocation>,
}

impl Outcome {
    fn of(result: Value) -> Self {
        Self {
            result,
            locations: Vec::new(),
        }
    }
}

/// What a workflow runs against.
pub struct Env<'a> {
    pub port: &'a dyn OperationPort,
    pub ctx: &'a ExecContext,
    /// Evidence subject of the active target (used for nested Evidence identities).
    pub subject: Option<EvidenceSubject>,
}

impl Env<'_> {
    pub async fn execute(&self, operation: &str, parameters: Value) -> Result<AnalysisExecution, AnalysisError> {
        if self.ctx.cancel.is_cancelled() {
            return Err(AnalysisError::cancelled(operation));
        }
        let execution = self.port.execute(operation, &parameters, self.ctx).await;
        if self.ctx.cancel.is_cancelled() {
            return Err(AnalysisError::cancelled(operation));
        }
        execution
    }

    /// Run an operation and keep only its result.
    pub async fn call(&self, operation: &str, parameters: Value) -> Result<Value, AnalysisError> {
        self.execute(operation, parameters).await.map(|e| e.result)
    }

    /// `resolveProcedureAddress`.
    pub async fn resolve_procedure_address(&self, procedure: &str) -> Result<String, AnalysisError> {
        let result = self.call("procedure_address", json!({ "procedure": procedure })).await?;
        match result.as_str() {
            Some(address) if !address.is_empty() => Ok(address.to_string()),
            _ => Err(AnalysisError::output(
                "procedure_address",
                "provider returned no canonical procedure address",
            )),
        }
    }

    /// `resolveAnalysisDocument`.
    pub async fn resolve_document(&self, document: Option<&str>) -> Result<String, AnalysisError> {
        if let Some(document) = document {
            return Ok(document.to_string());
        }
        if self.ctx.cancel.is_cancelled() {
            return Err(AnalysisError::cancelled("current_document"));
        }
        match self.execute("current_document", json!({})).await {
            Ok(current) => match current.result.as_str() {
                Some(name) if !name.is_empty() => Ok(name.to_string()),
                _ => Err(AnalysisError::output(
                    "current_document",
                    "expected a nonempty document identity string",
                )),
            },
            Err(AnalysisError::CapabilityUnavailable { .. }) => {
                let listed = self.execute("list_documents", json!({})).await?;
                let documents = parse_documents(&listed.result).map_err(|_| {
                    AnalysisError::output(
                        "list_documents",
                        "expected one document identity when resolving a headless provider",
                    )
                })?;
                if documents.len() != 1 {
                    return Err(AnalysisError::output(
                        "list_documents",
                        format!(
                            "expected exactly one document identity for a provider without current-document selection, received {}",
                            documents.len()
                        ),
                    ));
                }
                let name = documents[0].clone();
                if name.is_empty() {
                    return Err(AnalysisError::output("list_documents", "provider returned no document identity"));
                }
                Ok(name)
            }
            Err(other) => Err(other),
        }
    }
}

// ---- hopperValues parsing helpers -------------------------------------------------------

fn hopper_protocol(expected: &str) -> AnalysisError {
    AnalysisError::HopperProtocol {
        message: format!("Hopper returned an invalid {expected}"),
    }
}

/// A direct value or the object wrapping it under `property`.
pub fn unwrap_property<'a>(value: &'a Value, property: &str) -> &'a Value {
    match value.as_object() {
        Some(object) if object.contains_key(property) => &object[property],
        _ => value,
    }
}

pub fn parse_documents(value: &Value) -> Result<Vec<String>, AnalysisError> {
    unwrap_property(value, "documents")
        .as_array()
        .and_then(|a| a.iter().map(|v| v.as_str().map(str::to_string)).collect::<Option<Vec<_>>>())
        .ok_or_else(|| hopper_protocol("document list"))
}

pub fn parse_related_addresses(value: &Value, relation: &str) -> Result<Vec<String>, AnalysisError> {
    unwrap_property(value, relation)
        .as_array()
        .and_then(|a| a.iter().map(|v| v.as_str().map(str::to_string)).collect::<Option<Vec<_>>>())
        .ok_or_else(|| hopper_protocol(&format!("{relation} list")))
}

pub fn parse_list_count(value: &Value, property: &str) -> Result<usize, AnalysisError> {
    match unwrap_property(value, property) {
        Value::Array(items) => Ok(items.len()),
        Value::Object(map) => Ok(map.len()),
        _ => Err(hopper_protocol(&format!("{property} list"))),
    }
}

pub struct SegmentSummary {
    pub name: String,
    pub start: String,
    pub end: String,
}

pub fn parse_segments(value: &Value) -> Result<Vec<SegmentSummary>, AnalysisError> {
    let invalid = || hopper_protocol("segment list");
    let items = unwrap_property(value, "segments").as_array().ok_or_else(invalid)?;
    let mut out = Vec::new();
    for item in items {
        let object = item.as_object().ok_or_else(invalid)?;
        let string = |key: &str| object.get(key).and_then(Value::as_str).map(str::to_string);
        let nullable_bool = |key: &str| matches!(object.get(key), Some(Value::Bool(_) | Value::Null));
        if !(nullable_bool("readable") && nullable_bool("writable") && nullable_bool("executable")) {
            return Err(invalid());
        }
        out.push(SegmentSummary {
            name: string("name").ok_or_else(invalid)?,
            start: string("start").ok_or_else(invalid)?,
            end: string("end").ok_or_else(invalid)?,
        });
    }
    Ok(out)
}

fn coordinate(value: &str) -> Option<(String, u128)> {
    let (space, offset) = match value.rfind(":0x") {
        Some(index) => (value[..index].to_string(), &value[index + 1..]),
        None => ("default".to_string(), value),
    };
    let hex = offset.strip_prefix("0x")?;
    if hex.is_empty() || !hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
        return None;
    }
    Some((space, u128::from_str_radix(hex, 16).ok()?))
}

/// Bounded byte distance between canonical addresses in one space.
pub fn address_distance(start: &str, end: &str) -> u64 {
    let (Some(left), Some(right)) = (coordinate(start), coordinate(end)) else {
        return 0;
    };
    if left.0 != right.0 || right.1 <= left.1 {
        return 0;
    }
    let distance = right.1 - left.1;
    distance.min(9_007_199_254_740_991u128) as u64
}

/// `allAddressed` for `list_names` / `list_procedures`.
async fn all_addressed(env: &Env<'_>, tool: &str) -> Result<Vec<Addressed>, AnalysisError> {
    let result = env.call(tool, json!({})).await?;
    let invalid = || AnalysisError::output(tool, "provider returned an invalid inventory");
    let items = result.as_array().ok_or_else(invalid)?;
    let mut out = Vec::new();
    for item in items {
        let object = item.as_object().ok_or_else(invalid)?;
        let address = object.get("address").and_then(Value::as_str).ok_or_else(invalid)?;
        let value = object.get("value").and_then(Value::as_str).ok_or_else(invalid)?;
        out.push(Addressed {
            address: address.to_string(),
            name: value.to_string(),
        });
    }
    Ok(out)
}

/// Dispatch one workflow by name.
pub async fn run(name: &str, input: &Value, env: &Env<'_>) -> Result<Outcome, AnalysisError> {
    match name {
        "binary_overview" => binary_overview(env).await.map(Outcome::of),
        "get_call_graph" => call_graph(env, input).await.map(Outcome::of),
        "find_xrefs_to_name" => find_xrefs(env, input).await.map(Outcome::of),
        "batch_decompile" => batch_decompile(env, input).await,
        "get_objc_classes" => {
            let pattern = input.get("pattern").and_then(Value::as_str).unwrap_or("");
            let names = all_addressed(env, "list_names").await?;
            Ok(Outcome::of(symbols::discover_objc_classes(&names, pattern)))
        }
        "get_objc_protocols" => {
            let names = all_addressed(env, "list_names").await?;
            Ok(Outcome::of(symbols::discover_objc_protocols(&names)))
        }
        "analyze_swift_types" => analyze_swift_types(env, input).await.map(Outcome::of),
        "inspect_native_dispatch_metadata" => {
            let max = input.get("max_records").and_then(Value::as_u64).unwrap_or(5000) as usize;
            dispatch_metadata::inspect(env, max).await.map(Outcome::of)
        }
        "trace_native_values" => native_value::trace(env, input).await.map(Outcome::of),
        "inspect_native_api" => native_api::inspect(env, input).await.map(Outcome::of),
        "trace_feature" => literal::trace_feature(env, input).await.map(Outcome::of),
        "trace_call_path" => call_path::trace(env, input).await.map(Outcome::of),
        "inspect_address_context" => address_context::inspect(env, input).await.map(Outcome::of),
        "get_navigation_context" => address_context::navigation(env, input).await.map(Outcome::of),
        other => Err(AnalysisError::capability_unavailable(
            "rea-workflow",
            other,
            "operation is not declared by this provider",
        )),
    }
}

async fn binary_overview(env: &Env<'_>) -> Result<Value, AnalysisError> {
    let document = env.resolve_document(None).await?;
    let segments = env.call("list_segments", json!({})).await;
    let procedures = env.call("list_procedures", json!({})).await;
    let strings = env.call("list_strings", json!({})).await;
    let segments = segments?;
    let procedures = procedures?;
    let strings = strings?;
    let segments = parse_segments(&segments)?;
    let procedure_count = parse_list_count(&procedures, "procedures")?;
    let string_count = parse_list_count(&strings, "strings")?;
    Ok(json!({
        "document": document,
        "segments": segments.iter().map(|s| json!({
            "name": s.name,
            "start": s.start,
            "end": s.end,
            "length": address_distance(&s.start, &s.end),
        })).collect::<Vec<_>>(),
        "segment_count": segments.len(),
        "procedure_count": procedure_count,
        "string_count": string_count,
    }))
}

async fn call_graph(env: &Env<'_>, input: &Value) -> Result<Value, AnalysisError> {
    let address = input.get("address").and_then(Value::as_str).unwrap_or_default();
    let forward = input.get("direction").and_then(Value::as_str).unwrap_or("forward") == "forward";
    let (relation, tool) = if forward {
        ("callees", "procedure_callees")
    } else {
        ("callers", "procedure_callers")
    };
    let resolved = env.resolve_procedure_address(address).await?;
    let mut discovered: HashSet<String> = HashSet::from([resolved.clone()]);
    let mut queue: Vec<(String, usize)> = vec![(resolved, 0)];
    let mut index = 0;
    let mut graph: Map<String, Value> = Map::new();
    while index < queue.len() {
        let (current, depth) = queue[index].clone();
        index += 1;
        let level = graph
            .entry(depth.to_string())
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .unwrap();
        match env.call(tool, json!({ "procedure": current })).await {
            Err(error) => {
                level.push(json!({ "address": current, "status": "error", "error": error.project() }));
            }
            Ok(result) => match parse_related_addresses(&result, relation) {
                Err(error) => {
                    level.push(json!({ "address": current, "status": "error", "error": error.project() }));
                }
                Ok(related) => {
                    level.push(json!({ "address": current, "status": "ok", "calls": related }));
                    for address in related {
                        if discovered.insert(address.clone()) {
                            queue.push((address, depth + 1));
                        }
                    }
                }
            },
        }
    }
    Ok(Value::Object(graph))
}

async fn find_xrefs(env: &Env<'_>, input: &Value) -> Result<Value, AnalysisError> {
    let name = input.get("name").and_then(Value::as_str).unwrap_or_default();
    let names = all_addressed(env, "list_names").await?;
    let Some(resolved) = names.iter().find(|e| e.name == name) else {
        return Ok(json!({ "status": "unresolved", "name": name, "reason": "name_not_found" }));
    };
    let xrefs = env.call("xrefs", json!({ "address": resolved.address })).await?;
    let valid = xrefs
        .as_array()
        .map(|a| a.iter().all(Value::is_string))
        .unwrap_or(false);
    if !valid {
        return Err(AnalysisError::output("xrefs", "provider returned an invalid address list"));
    }
    Ok(json!({ "status": "resolved", "name": name, "address": resolved.address, "xrefs": xrefs }))
}

async fn batch_decompile(env: &Env<'_>, input: &Value) -> Result<Outcome, AnalysisError> {
    let addresses: Vec<String> = input
        .get("addresses")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    // REA runs every address concurrently over the provider's serial wire, which fixes the
    // order in which request ids are issued; joining the futures reproduces it.
    let items: Vec<Value> = futures_util::future::join_all(addresses.iter().map(|address| batch_item(env, address))).await;
    let succeeded = items.iter().filter(|i| i["status"] == "ok").count();
    let mut locations: Vec<EvidenceLocation> = Vec::new();
    let mut seen = HashSet::new();
    for item in &items {
        let procedure = &item["procedure"];
        if procedure["status"] == "resolved" {
            if let Some(address) = procedure["address"].as_str() {
                if seen.insert(address.to_string()) {
                    locations.push(EvidenceLocation::Address {
                        address: address.to_string(),
                    });
                }
            }
        }
    }
    Ok(Outcome {
        result: json!({
            "items": items,
            "total": items.len(),
            "succeeded": succeeded,
            "failed": items.len() - succeeded,
        }),
        locations,
    })
}

async fn batch_item(env: &Env<'_>, address: &str) -> Value {
    {
        let resolved = env.resolve_procedure_address(address).await;
        let procedure = match &resolved {
            Ok(resolved) => batch_procedure_identity(env, resolved).await,
            Err(error) => json!({ "status": "unknown", "error": error.project() }),
        };
        let target = resolved.as_ref().map(String::as_str).unwrap_or(address);
        let item = match env.call("procedure_pseudo_code", json!({ "procedure": target })).await {
            Err(error) => json!({ "address": address, "procedure": procedure, "status": "error", "error": error.project() }),
            Ok(result) => match result.as_str() {
                Some(code) if !code.is_empty() => json!({
                    "address": address, "procedure": procedure, "status": "ok", "pseudocode": code,
                }),
                _ => json!({
                    "address": address,
                    "procedure": procedure,
                    "status": "error",
                    "error": AnalysisError::output("procedure_pseudo_code", "provider returned empty pseudocode").project(),
                }),
            },
        };
        item
    }
}

async fn batch_procedure_identity(env: &Env<'_>, address: &str) -> Value {
    let observed = env.call("address_name", json!({ "address": address })).await;
    match observed {
        Ok(value) if value.is_string() || value.is_null() => {
            json!({ "status": "resolved", "address": address, "name": value })
        }
        Ok(_) => json!({
            "status": "resolved",
            "address": address,
            "name": Value::Null,
            "name_error": AnalysisError::output("address_name", "provider returned an invalid entry label").project(),
        }),
        Err(error) => json!({
            "status": "resolved",
            "address": address,
            "name": Value::Null,
            "name_error": error.project(),
        }),
    }
}

async fn analyze_swift_types(env: &Env<'_>, input: &Value) -> Result<Value, AnalysisError> {
    let procedures = all_addressed(env, "list_procedures").await?;
    let symbols_result = all_addressed(env, "list_names").await;
    if let Err(error) = &symbols_result {
        if !matches!(error, AnalysisError::CapabilityUnavailable { .. }) {
            return Err(error.clone());
        }
    }
    let category = input.get("category").and_then(Value::as_str);
    let pattern = input.get("pattern").and_then(Value::as_str);
    let symbols: Vec<Addressed> = symbols_result.as_ref().cloned().unwrap_or_default();
    let mut result = symbols::categorize_swift_types(&procedures, category, pattern, &symbols);
    if let Err(error) = symbols_result {
        let object = result.as_object_mut().unwrap();
        object.insert("symbol_inventory_error".into(), error.project());
        let limitations = object.get_mut("limitations").and_then(Value::as_array_mut).unwrap();
        limitations.push(json!(
            "The provider's symbol inventory is unavailable; demangled procedures could not be joined to their Swift aliases."
        ));
    }
    Ok(result)
}

/// Sorting used by deterministic frontier reports.
pub fn sorted_unique(values: &[String]) -> Vec<String> {
    let set: BTreeMap<&String, ()> = values.iter().map(|v| (v, ())).collect();
    set.into_keys().cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_distance_is_bounded_and_space_aware() {
        assert_eq!(address_distance("0x400000", "0x400318"), 792);
        assert_eq!(address_distance("0x10", "0x10"), 0);
        assert_eq!(address_distance("0x20", "0x10"), 0);
        assert_eq!(address_distance(".text:0x0", ".data:0x10"), 0);
        assert_eq!(address_distance(".text:0x0", ".text:0x2d"), 45);
        assert_eq!(address_distance("not-an-address", "0x10"), 0);
    }

    #[test]
    fn hopper_value_parsers_accept_wrapped_and_direct_lists() {
        let wrapped = json!({ "callees": ["0x1", "0x2"] });
        assert_eq!(parse_related_addresses(&wrapped, "callees").unwrap(), vec!["0x1", "0x2"]);
        assert_eq!(parse_related_addresses(&json!(["0x3"]), "callees").unwrap(), vec!["0x3"]);
        assert!(parse_related_addresses(&json!([1]), "callees").is_err());
        assert_eq!(parse_list_count(&json!({ "0x1": "a", "0x2": "b" }), "procedures").unwrap(), 2);
        assert_eq!(parse_list_count(&json!([1, 2, 3]), "strings").unwrap(), 3);
        assert!(parse_list_count(&json!("x"), "strings").is_err());
        let segments = json!([{ "name": "a", "start": "0x1", "end": "0x2", "readable": null, "writable": true, "executable": false }]);
        assert_eq!(parse_segments(&segments).unwrap().len(), 1);
        assert!(parse_segments(&json!([{ "name": "a", "start": "0x1", "end": "0x2" }])).is_err());
    }
}
