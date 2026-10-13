//! `trace_native_ui_action`: follow one compiled UI action, interface object,
//! native symbol or exact function address through authored connections, encoded
//! or symbolized Objective-C handlers and bounded static call references.
//!
//! Port of REA `NativeUiActionTrace.ts`, `NativeCallRoutes.ts`,
//! `NativeDispatchMetadataInspection.ts`, `nativeInvestigationGraph.ts` and the
//! name-inventory decoder of `objcSwiftMetadata.ts`. The workflow is generic
//! over an [`AnalysisPort`] (REA's `AnalysisOperationPort`): in the server it
//! forwards to the sibling tools (`decode_interface_builder`, the Ghidra/Hopper
//! operations); in tests it is a scripted fake, so the same scenario can be run
//! through REA's compiled workflow and this port and compared field by field.

use std::collections::{HashMap, HashSet};
use std::future::Future;

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::error::ToolError;

/// One executed analysis operation (REA `AnalysisExecution`).
#[derive(Debug, Clone)]
pub struct PortExecution {
    pub result: Value,
    /// `{ id, name, version }` of the provider that answered.
    pub provider: Value,
    pub subject_sha256: Option<String>,
    pub analysis_profile_digest: Option<String>,
}

/// REA's `AnalysisOperationPort`.
pub trait AnalysisPort {
    fn execute(&self, operation: &str, parameters: Value) -> impl Future<Output = Result<PortExecution, ToolError>> + Send;
}

// ----------------------------------------------------------------- helpers --

/// JavaScript `Map`: insertion order, `set` on an existing key keeps its place.
#[derive(Default, Clone)]
struct OrderedMap {
    items: Vec<(String, Value)>,
    index: HashMap<String, usize>,
}

impl OrderedMap {
    fn from(values: impl IntoIterator<Item = (String, Value)>) -> Self {
        let mut map = OrderedMap::default();
        for (key, value) in values {
            map.set(key, value);
        }
        map
    }
    fn set(&mut self, key: String, value: Value) {
        match self.index.get(&key) {
            Some(position) => self.items[*position].1 = value,
            None => {
                self.index.insert(key.clone(), self.items.len());
                self.items.push((key, value));
            }
        }
    }
    fn has(&self, key: &str) -> bool {
        self.index.contains_key(key)
    }
    fn len(&self) -> usize {
        self.items.len()
    }
    fn values(&self) -> impl Iterator<Item = &Value> {
        self.items.iter().map(|(_, v)| v)
    }
}

fn s<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn output_error(operation: &str, reason: &str) -> ToolError {
    ToolError::Output { operation: operation.to_string(), reason: reason.to_string() }
}

fn is_cancelled(error: &ToolError) -> bool {
    match error {
        ToolError::Cancelled { .. } => true,
        ToolError::Projected { error } => error["code"] == "cancelled",
        _ => false,
    }
}

fn is_capability_unavailable(error: &ToolError) -> bool {
    match error {
        ToolError::CapabilityUnavailable { .. } => true,
        ToolError::Projected { error } => error["code"] == "capability_unavailable",
        _ => false,
    }
}

fn is_hex64(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ---------------------------------------------------------------- schemas ----

const NODE_KINDS: [&str; 27] = [
    "storyboard",
    "scene",
    "view_controller",
    "view",
    "control",
    "constraint",
    "layout_guide",
    "resource",
    "placeholder",
    "external_object",
    "outlet",
    "action",
    "segue",
    "objc_class",
    "objc_selector",
    "swift_declaration",
    "swift_requirement",
    "dispatch_table",
    "dispatch_slot",
    "thunk",
    "function",
    "state_value",
    "global_value",
    "field",
    "branch_condition",
    "sink",
    "unknown",
];

const RELATIONS: [&str; 15] = [
    "contains",
    "outlet_to",
    "target_action",
    "segue_to",
    "objc_dispatch",
    "swift_witness_dispatch",
    "swift_vtable_dispatch",
    "thunk_to",
    "direct_call",
    "indirect_call",
    "provider_call",
    "reads",
    "writes",
    "flows_to",
    "controls",
];

const EVIDENCE_KINDS: [&str; 5] = ["binary_metadata", "interface_builder_resource", "symbol", "reference", "decompiler"];

fn only_keys(map: &Map<String, Value>, allowed: &[&str]) -> bool {
    map.keys().all(|key| allowed.contains(&key.as_str()))
}

fn non_negative_int(value: &Value) -> bool {
    value.as_f64().filter(|_| value.is_number()).map(|n| n.fract() == 0.0 && n >= 0.0).unwrap_or(false)
}

/// `nativeMetadataLocationSchema` (strict, both keys required).
fn parse_location(value: &Value) -> Option<Value> {
    let map = value.as_object()?;
    if !only_keys(map, &["address", "file_offset"]) {
        return None;
    }
    let address = map.get("address")?;
    let offset = map.get("file_offset")?;
    if !(address.is_null() || address.is_string()) || !(offset.is_null() || non_negative_int(offset)) {
        return None;
    }
    Some(json!({ "address": address, "file_offset": offset }))
}

/// `nativeMetadataEvidenceSchema` (strict; `artifact_*` default to null).
fn parse_evidence(value: &Value) -> Option<Value> {
    let map = value.as_object()?;
    if !only_keys(map, &["kind", "description", "location", "artifact_path", "artifact_sha256"]) {
        return None;
    }
    let kind = map.get("kind")?.as_str().filter(|k| EVIDENCE_KINDS.contains(k))?;
    let description = map.get("description")?.as_str().filter(|d| !d.is_empty())?;
    let location = parse_location(map.get("location")?)?;
    let artifact_path = match map.get("artifact_path") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(path)) if !path.is_empty() => json!(path),
        _ => return None,
    };
    let artifact_sha256 = match map.get("artifact_sha256") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(sha)) if is_hex64(sha) => json!(sha),
        _ => return None,
    };
    Some(json!({
        "kind": kind,
        "description": description,
        "location": location,
        "artifact_path": artifact_path,
        "artifact_sha256": artifact_sha256,
    }))
}

fn parse_evidence_list(value: &Value, min: usize) -> Option<Vec<Value>> {
    let list = value.as_array()?;
    if list.len() < min {
        return None;
    }
    list.iter().map(parse_evidence).collect()
}

/// `nativeInvestigationNodeSchema`.
fn parse_node(value: &Value) -> Option<Value> {
    let map = value.as_object()?;
    if !only_keys(map, &["id", "kind", "name", "location", "attributes", "evidence"]) {
        return None;
    }
    let id = map.get("id")?.as_str().filter(|v| !v.is_empty())?;
    let kind = map.get("kind")?.as_str().filter(|k| NODE_KINDS.contains(k))?;
    let name = map.get("name")?.as_str().filter(|v| !v.is_empty())?;
    let location = match map.get("location")? {
        Value::Null => Value::Null,
        other => parse_location(other)?,
    };
    let attributes = map.get("attributes")?.as_object()?;
    let evidence = parse_evidence_list(map.get("evidence")?, 0)?;
    Some(json!({
        "id": id, "kind": kind, "name": name, "location": location,
        "attributes": attributes, "evidence": evidence,
    }))
}

/// `nativeInvestigationEdgeSchema`.
fn parse_edge(value: &Value) -> Option<Value> {
    let map = value.as_object()?;
    let id = map.get("id")?.as_str().filter(|v| !v.is_empty())?;
    let from = map.get("from")?.as_str().filter(|v| !v.is_empty())?;
    let relation = map.get("relation")?.as_str().filter(|r| RELATIONS.contains(r))?;
    let limitations = map.get("limitations")?.as_array()?;
    if !limitations.iter().all(Value::is_string) {
        return None;
    }
    let resolution = map.get("resolution")?.as_str()?;
    if resolution == "unresolved" {
        if !only_keys(map, &["id", "from", "to", "relation", "resolution", "reason", "evidence", "limitations"]) {
            return None;
        }
        if !map.get("to")?.is_null() {
            return None;
        }
        let reason = map.get("reason")?.as_str().filter(|v| !v.is_empty())?;
        let evidence = parse_evidence_list(map.get("evidence")?, 0)?;
        return Some(json!({
            "id": id, "from": from, "to": Value::Null, "relation": relation, "resolution": "unresolved",
            "reason": reason, "evidence": evidence, "limitations": limitations,
        }));
    }
    if !["observed", "inferred", "resolved", "ambiguous"].contains(&resolution) {
        return None;
    }
    if !only_keys(map, &["id", "from", "to", "relation", "resolution", "evidence", "limitations"]) {
        return None;
    }
    let to = map.get("to")?.as_str().filter(|v| !v.is_empty())?;
    let evidence = parse_evidence_list(map.get("evidence")?, 1)?;
    Some(json!({
        "id": id, "from": from, "to": to, "relation": relation, "resolution": resolution,
        "evidence": evidence, "limitations": limitations,
    }))
}

/// `nativeInvestigationCoverageSchema`.
fn parse_coverage(value: &Value) -> Option<Value> {
    let map = value.as_object()?;
    if !only_keys(map, &["facet", "status", "reason", "examined", "omitted"]) {
        return None;
    }
    let facet = map.get("facet")?.as_str().filter(|v| !v.is_empty())?;
    let status = map.get("status")?.as_str().filter(|v| ["complete", "partial", "unsupported", "not_requested"].contains(v))?;
    let reason = map.get("reason")?;
    if !(reason.is_null() || reason.is_string()) || !non_negative_int(map.get("examined")?) || !non_negative_int(map.get("omitted")?) {
        return None;
    }
    Some(json!({ "facet": facet, "status": status, "reason": reason, "examined": map["examined"], "omitted": map["omitted"] }))
}

#[derive(Clone)]
struct Graph {
    target_sha256: String,
    provider: Value,
    nodes: Vec<Value>,
    edges: Vec<Value>,
    coverage: Vec<Value>,
    truncated: bool,
}

/// `nativeInvestigationGraphSchema`.
fn parse_graph(value: &Value) -> Option<Graph> {
    let map = value.as_object()?;
    if !only_keys(map, &["target_sha256", "provider", "nodes", "edges", "coverage", "truncated"]) {
        return None;
    }
    let target_sha256 = map.get("target_sha256")?.as_str().filter(|v| is_hex64(v))?.to_string();
    let provider = map.get("provider")?.as_object()?;
    if !only_keys(provider, &["id", "version", "tool_version"]) {
        return None;
    }
    let id = provider.get("id")?.as_str().filter(|v| !v.is_empty())?;
    let version = provider.get("version")?;
    let tool_version = provider.get("tool_version")?.as_str().filter(|v| !v.is_empty())?;
    if !(version.is_null() || version.is_string()) {
        return None;
    }
    Some(Graph {
        target_sha256,
        provider: json!({ "id": id, "version": version, "tool_version": tool_version }),
        nodes: map.get("nodes")?.as_array()?.iter().map(parse_node).collect::<Option<_>>()?,
        edges: map.get("edges")?.as_array()?.iter().map(parse_edge).collect::<Option<_>>()?,
        coverage: map.get("coverage")?.as_array()?.iter().map(parse_coverage).collect::<Option<_>>()?,
        truncated: map.get("truncated")?.as_bool()?,
    })
}

/// `interfaceBuilderAnalysisSchema` (documents are checked for shape and count).
fn parse_interface_builder(value: &Value) -> Option<(Graph, usize)> {
    let map = value.as_object()?;
    if !only_keys(map, &["target_sha256", "documents", "graph", "limitations"]) {
        return None;
    }
    if !is_hex64(map.get("target_sha256")?.as_str()?) {
        return None;
    }
    let documents = map.get("documents")?.as_array()?;
    if documents.len() > 64 {
        return None;
    }
    for document in documents {
        let d = document.as_object()?;
        if !only_keys(d, &["relative_path", "archive_sha256", "document_kind", "object_count", "connection_count", "hierarchy_complete"]) {
            return None;
        }
        d.get("relative_path")?.as_str().filter(|v| !v.is_empty())?;
        if !is_hex64(d.get("archive_sha256")?.as_str()?) {
            return None;
        }
        d.get("document_kind")?.as_str().filter(|v| ["nib", "storyboard_scene"].contains(v))?;
        if !non_negative_int(d.get("object_count")?) || !non_negative_int(d.get("connection_count")?) {
            return None;
        }
        d.get("hierarchy_complete")?.as_bool()?;
    }
    if !map.get("limitations")?.as_array()?.iter().all(Value::is_string) {
        return None;
    }
    let graph = parse_graph(map.get("graph")?)?;
    Some((graph, documents.len()))
}

// -------------------------------------------------------- dispatch metadata ---

#[derive(Clone)]
struct Implementation {
    class_name: String,
    selector: String,
    method_type: String,
    implementation_address: Option<String>,
    file_offset: Value,
    decode_status: String,
    evidence: Vec<Value>,
}

struct Metadata {
    target_sha256: Option<String>,
    provider: Value,
    implementations: Vec<Implementation>,
}

/// `nativeDispatchMetadataResultSchema` as far as the trace consumes it.
fn parse_metadata(value: &Value) -> Option<Metadata> {
    let map = value.as_object()?;
    if !only_keys(map, &["target_sha256", "provider", "analysis_profile_digest", "result"]) {
        return None;
    }
    let target = map.get("target_sha256")?;
    let target_sha256 = match target {
        Value::Null => None,
        Value::String(sha) if is_hex64(sha) => Some(sha.clone()),
        _ => return None,
    };
    let provider = map.get("provider")?.as_object()?;
    if !only_keys(provider, &["id", "name", "version"]) {
        return None;
    }
    provider.get("id")?.as_str().filter(|v| !v.is_empty())?;
    provider.get("name")?.as_str().filter(|v| !v.is_empty())?;
    if !(provider.get("version")?.is_null() || provider.get("version")?.is_string()) {
        return None;
    }
    let digest = map.get("analysis_profile_digest")?;
    if !(digest.is_null() || digest.as_str().map(|d| !d.is_empty()).unwrap_or(false)) {
        return None;
    }
    let result = map.get("result")?.as_object()?;
    let mut implementations = Vec::new();
    for item in result.get("objc_dispatch_implementations").and_then(Value::as_array).cloned().unwrap_or_default() {
        let i = item.as_object()?;
        let evidence = parse_evidence_list(i.get("evidence")?, 1)?;
        let location = parse_location(i.get("location")?)?;
        let decode = i.get("decode")?.as_object()?;
        let status = decode.get("status")?.as_str().filter(|v| ["decoded", "partial", "unsupported", "invalid"].contains(v))?;
        if !(decode.get("reason")?.is_null() || decode.get("reason")?.is_string()) {
            return None;
        }
        let address = i.get("implementation_address")?;
        implementations.push(Implementation {
            class_name: i.get("class_name")?.as_str().filter(|v| !v.is_empty())?.to_string(),
            selector: i.get("selector")?.as_str().filter(|v| !v.is_empty())?.to_string(),
            method_type: i.get("method_type")?.as_str().filter(|v| ["instance", "class"].contains(v))?.to_string(),
            implementation_address: match address {
                Value::Null => None,
                Value::String(a) => Some(a.clone()),
                _ => return None,
            },
            file_offset: location["file_offset"].clone(),
            decode_status: status.to_string(),
            evidence,
        });
    }
    Some(Metadata {
        target_sha256,
        provider: map["provider"].clone(),
        implementations,
    })
}

fn method_symbol_pattern() -> &'static Regex {
    static PATTERN: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"^([+-])\[([^\s\]]+)\s+([^\]]+)\]$").expect("method pattern"))
}

/// `inspectNativeDispatchMetadata`: decode only what a provider's name
/// inventory exposes. Returns the `objc_dispatch_implementations` subset the
/// trace consumes together with the full normalized metadata result.
fn inspect_names(names: &[(String, String)], max_records: usize) -> Vec<Implementation> {
    let examined = &names[..names.len().min(max_records)];
    let mut implementations: Vec<((String, String, String), Implementation)> = Vec::new();
    for (address, name) in examined {
        if let Some(c) = method_symbol_pattern().captures(name) {
            let (class_name, selector) = (c[2].to_string(), c[3].to_string());
            let method_type = if &c[1] == "+" { "class" } else { "instance" };
            let key = (class_name.clone(), selector.clone(), method_type.to_string());
            let implementation = Implementation {
                class_name,
                selector,
                method_type: method_type.to_string(),
                implementation_address: Some(address.clone()),
                file_offset: Value::Null,
                decode_status: "partial".to_string(),
                evidence: vec![json!({
                    "kind": "symbol",
                    "description": format!("Provider symbol {name}"),
                    "location": { "address": address, "file_offset": Value::Null },
                    "artifact_path": Value::Null,
                    "artifact_sha256": Value::Null,
                })],
            };
            match implementations.iter().position(|(k, _)| *k == key) {
                Some(position) => implementations[position].1 = implementation,
                None => implementations.push((key, implementation)),
            }
        }
    }
    let mut decoded: Vec<Implementation> = implementations.into_iter().map(|(_, i)| i).collect();
    decoded.sort_by(|a, b| {
        let key = |i: &Implementation| serde_json::to_string(&[&i.class_name, &i.selector]).unwrap_or_default();
        crate::firmware::collate::code_point_order(&key(a), &key(b))
    });
    decoded
}

/// `inspectNativeDispatch`: prefer validated binary metadata, otherwise the
/// bound provider's symbol-only coverage.
async fn inspect_native_dispatch<P: AnalysisPort + Sync>(port: &P, max_records: u64) -> Result<Metadata, ToolError> {
    let binary = port.execute("inspect_native_dispatch_metadata", json!({ "max_records": max_records })).await;
    match binary {
        Ok(execution) => {
            return parse_metadata(&execution.result)
                .ok_or_else(|| output_error("inspect_native_dispatch_metadata", "provider returned invalid dispatch metadata"))
        }
        Err(error) if !is_capability_unavailable(&error) => return Err(error),
        Err(_) => {}
    }
    let execution = port.execute("list_names", json!({})).await?;
    let names = execution
        .result
        .as_array()
        .and_then(|list| {
            list.iter()
                .map(|entry| {
                    let map = entry.as_object()?;
                    let address = map.get("address")?.as_str()?.to_string();
                    let value = match (map.get("value"), map.get("name"), map.len()) {
                        (Some(Value::String(v)), None, 2) => v.clone(),
                        (None, Some(Value::String(n)), 2) => n.clone(),
                        _ => return None,
                    };
                    Some((address, value))
                })
                .collect::<Option<Vec<_>>>()
        })
        .ok_or_else(|| output_error("list_names", "provider returned an invalid inventory"))?;
    let provider = execution.provider.clone();
    Ok(Metadata {
        target_sha256: execution.subject_sha256.clone(),
        provider,
        implementations: inspect_names(&names, max_records as usize),
    })
}

// ------------------------------------------------------------ graph logic ----

fn node_id(node: &Value) -> &str {
    s(node, "id").unwrap_or_default()
}

fn edge_to(edge: &Value) -> Option<&str> {
    edge.get("to").and_then(Value::as_str)
}

/// `traceNativeInvestigationGraph` (forward, the only direction this tool uses).
fn trace_graph(graph: &Graph, start_id: &str, max_depth: u64, max_nodes: u64, max_edges: u64) -> Value {
    let Some(start) = graph.nodes.iter().find(|n| node_id(n) == start_id) else {
        return json!({
            "target_sha256": graph.target_sha256, "provider": graph.provider, "start": start_id,
            "direction": "forward", "nodes": [], "edges": [], "unresolved": [], "reached_depth": 0,
            "truncated": false, "reason": "start_node_missing", "coverage": graph.coverage,
            "limitations": ["The requested start node is absent from the supplied graph."],
        });
    };
    let node_by_id: HashMap<&str, &Value> = graph.nodes.iter().map(|n| (node_id(n), n)).collect();
    let start_id = node_id(start).to_string();
    let mut visited: Vec<String> = vec![start_id.clone()];
    let mut visited_set: HashSet<String> = HashSet::from([start_id.clone()]);
    let mut selected = OrderedMap::default();
    let mut unresolved = OrderedMap::default();
    let mut queue: std::collections::VecDeque<(String, u64)> = std::collections::VecDeque::from([(start_id.clone(), 0)]);
    let mut reached_depth: u64 = 0;
    let mut truncated = false;
    let mut reason: Option<&'static str> = None;
    let mut adjacency: HashMap<&str, Vec<&Value>> = HashMap::new();
    for edge in &graph.edges {
        if let Some(from) = s(edge, "from") {
            adjacency.entry(from).or_default().push(edge);
        }
    }
    while let Some((current, depth)) = queue.pop_front() {
        reached_depth = reached_depth.max(depth);
        let adjacent = adjacency.get(current.as_str()).cloned().unwrap_or_default();
        for edge in adjacent {
            if (selected.len() + unresolved.len()) as u64 >= max_edges {
                truncated = true;
                reason = Some("max_edges_reached");
                break;
            }
            let id = s(edge, "id").unwrap_or_default().to_string();
            if s(edge, "resolution") == Some("unresolved") {
                unresolved.set(id, edge.clone());
                continue;
            }
            let next = edge_to(edge).unwrap_or_default().to_string();
            let already_visited = visited_set.contains(&next);
            if !already_visited && depth >= max_depth {
                truncated = true;
                reason = reason.or(Some("max_depth_reached"));
                continue;
            }
            selected.set(id, edge.clone());
            if already_visited {
                continue;
            }
            if visited.len() as u64 >= max_nodes {
                truncated = true;
                reason = Some("max_nodes_reached");
                break;
            }
            if !node_by_id.contains_key(next.as_str()) {
                truncated = true;
                reason = reason.or(Some("edge_target_missing_from_graph"));
                continue;
            }
            visited.push(next.clone());
            visited_set.insert(next.clone());
            queue.push_back((next, depth + 1));
        }
        if matches!(reason, Some("max_edges_reached") | Some("max_nodes_reached")) {
            break;
        }
    }
    json!({
        "target_sha256": graph.target_sha256,
        "provider": graph.provider,
        "start": start_id,
        "direction": "forward",
        "nodes": visited.iter().filter_map(|id| node_by_id.get(id.as_str()).map(|n| (*n).clone())).collect::<Vec<_>>(),
        "edges": selected.values().cloned().collect::<Vec<_>>(),
        "unresolved": unresolved.values().cloned().collect::<Vec<_>>(),
        "reached_depth": reached_depth,
        "truncated": truncated,
        "reason": reason,
        "coverage": graph.coverage,
        "limitations": [
            "Static analysis does not prove that an authored UI action is reachable or executed at runtime.",
            "Provider call graphs may omit unresolved indirect dispatch.",
        ],
    })
}

/// `joinInterfaceBuilderDispatch`: join authored UI actions to exact
/// Objective-C method symbols when known.
fn join_dispatch(graph: Graph, implementations: &[Implementation]) -> Graph {
    let mut nodes = OrderedMap::from(graph.nodes.iter().map(|n| (node_id(n).to_string(), n.clone())));
    let mut edges: Vec<Value> = graph.edges.clone();
    let mut existing: HashSet<String> = edges.iter().map(|e| s(e, "id").unwrap_or_default().to_string()).collect();
    let mut selector_nodes_by_action: HashMap<String, String> = HashMap::new();
    for edge in &edges {
        if s(edge, "resolution") == Some("observed") && s(edge, "relation") == Some("target_action") {
            let target_kind = edge_to(edge).and_then(|to| nodes.index.get(to)).map(|i| nodes.items[*i].1["kind"].clone());
            if target_kind == Some(json!("objc_selector")) {
                selector_nodes_by_action.insert(s(edge, "from").unwrap_or_default().to_string(), edge_to(edge).unwrap_or_default().to_string());
            }
        }
    }
    let category_suffix = Regex::new(r"\([^)]*\)$").expect("category suffix");
    let mut examined: u64 = 0;
    let mut resolved: u64 = 0;
    let mut inferred_without_owner: u64 = 0;
    let action_nodes: Vec<Value> = nodes.values().filter(|n| s(n, "kind") == Some("action")).cloned().collect();
    for action in action_nodes {
        let selector = match action["attributes"].get("selector").and_then(Value::as_str) {
            Some(selector) if !selector.is_empty() => selector.to_string(),
            _ => continue,
        };
        let action_id = node_id(&action).to_string();
        let Some(selector_node_id) = selector_nodes_by_action.get(&action_id).cloned() else { continue };
        let destination = edges.iter().find(|edge| {
            s(edge, "resolution") == Some("observed")
                && s(edge, "relation") == Some("target_action")
                && s(edge, "from") == Some(action_id.as_str())
                && edge_to(edge)
                    .and_then(|to| nodes.index.get(to))
                    .map(|i| ["view_controller", "placeholder", "external_object"].contains(&s(&nodes.items[*i].1, "kind").unwrap_or_default()))
                    .unwrap_or(false)
        });
        let Some(destination) = destination else { continue };
        let owner = edge_to(destination).and_then(|to| nodes.index.get(to)).map(|i| nodes.items[*i].1.clone());
        examined += 1;
        let declared_class = owner.as_ref().and_then(|o| o["attributes"].get("class_name")).and_then(Value::as_str);
        let class_name: Option<String> = match (declared_class, owner.as_ref().and_then(|o| s(o, "kind"))) {
            (Some(name), Some("view_controller")) if !name.is_empty() => Some(name.to_string()),
            _ => None,
        };
        let candidates: Vec<&Implementation> = implementations
            .iter()
            .filter(|c| {
                c.method_type == "instance"
                    && c.selector == selector
                    && class_name
                        .as_ref()
                        .map(|name| category_suffix.replace(&c.class_name, "") == name.as_str())
                        .unwrap_or(true)
            })
            .collect();
        let implementation = if candidates.len() == 1 { Some(candidates[0]) } else { None };
        let owner_key = class_name.clone().or_else(|| owner.as_ref().map(|o| node_id(o).to_string())).unwrap_or_else(|| "unknown".to_string());
        let edge_id = format!("dispatch:{selector_node_id}:{owner_key}:{selector}");
        if existing.contains(&edge_id) {
            continue;
        }
        existing.insert(edge_id.clone());
        let action_evidence: Vec<Value> = action["evidence"].as_array().cloned().unwrap_or_default();
        let Some(implementation) = implementation.filter(|i| i.implementation_address.is_some()) else {
            let mut evidence = action_evidence.clone();
            evidence.extend(candidates.iter().flat_map(|c| c.evidence.clone()));
            edges.push(json!({
                "id": edge_id,
                "from": selector_node_id,
                "to": Value::Null,
                "relation": "objc_dispatch",
                "resolution": "unresolved",
                "reason": if candidates.len() > 1 {
                    "selector_has_multiple_candidate_implementations"
                } else {
                    "implementation_not_resolved_from_binary_metadata_or_provider_symbols"
                },
                "evidence": evidence,
                "limitations": ["A missing or ambiguous symbol match does not prove that the runtime implementation is absent."],
            }));
            continue;
        };
        let address = implementation.implementation_address.clone().unwrap_or_default();
        let function_id = format!("native:function:{address}");
        if !nodes.has(&function_id) {
            nodes.set(
                function_id.clone(),
                json!({
                    "id": function_id,
                    "kind": "function",
                    "name": format!("{} {}", implementation.class_name, selector),
                    "location": { "address": address, "file_offset": implementation.file_offset },
                    "attributes": {
                        "class_name": implementation.class_name,
                        "selector": selector,
                        "method_type": implementation.method_type,
                    },
                    "evidence": implementation.evidence,
                }),
            );
        }
        let mut evidence = action_evidence;
        evidence.extend(implementation.evidence.clone());
        edges.push(json!({
            "id": edge_id,
            "from": selector_node_id,
            "to": function_id,
            "relation": "objc_dispatch",
            "resolution": if class_name.is_some() && implementation.decode_status == "decoded" { "resolved" } else { "inferred" },
            "evidence": evidence,
            "limitations": if class_name.is_none() {
                ["The selector uniquely matches a encoded or symbolized method, but the Interface Builder receiver is an unresolved placeholder; runtime dispatch was not observed."]
            } else {
                ["The Interface Builder target and encoded or symbolized method agree on class and selector; runtime dispatch and dynamically supplied targets were not observed."]
            },
        }));
        resolved += 1;
        if class_name.is_none() {
            inferred_without_owner += 1;
        }
    }
    let complete = examined == resolved && inferred_without_owner == 0;
    let mut coverage = graph.coverage.clone();
    coverage.push(json!({
        "facet": "ui_to_objc_dispatch",
        "status": if complete { "complete" } else { "partial" },
        "reason": if complete {
            Value::Null
        } else if inferred_without_owner > 0 {
            json!("some_action_receivers_remain_placeholders")
        } else {
            json!("some_action_implementations_not_resolved")
        },
        "examined": examined,
        "omitted": examined - resolved + inferred_without_owner,
    }));
    Graph {
        target_sha256: graph.target_sha256,
        provider: json!({ "id": "rea-native-investigation", "version": Value::Null, "tool_version": "rea-native-investigation/1" }),
        nodes: nodes.values().cloned().collect(),
        edges,
        coverage,
        truncated: graph.truncated,
    }
}

struct Resolved {
    node_id: Option<String>,
    candidates: Vec<Value>,
    reason: Option<&'static str>,
}

/// `resolveUiAction`.
fn resolve_ui_action(graph: &Graph, query: &str) -> Resolved {
    if let Some(exact) = graph.nodes.iter().find(|n| node_id(n) == query) {
        if s(exact, "kind") == Some("action") {
            return Resolved { node_id: Some(node_id(exact).to_string()), candidates: vec![], reason: None };
        }
    }
    let actions: Vec<&Value> = graph
        .nodes
        .iter()
        .filter(|n| {
            s(n, "kind") == Some("action")
                && (s(n, "name") == Some(query) || n["attributes"].get("selector").and_then(Value::as_str) == Some(query))
        })
        .collect();
    if actions.len() == 1 {
        return Resolved { node_id: Some(node_id(actions[0]).to_string()), candidates: vec![], reason: None };
    }
    if actions.len() > 1 {
        return Resolved {
            node_id: None,
            candidates: actions.into_iter().cloned().collect(),
            reason: Some("action_selector_matches_multiple_ui_connections"),
        };
    }
    let object_ids: Vec<&str> = graph
        .nodes
        .iter()
        .filter(|n| {
            ["control", "view", "view_controller", "scene"].contains(&s(n, "kind").unwrap_or_default())
                && (node_id(n) == query || n["attributes"].get("interface_builder_object_id").and_then(Value::as_str) == Some(query))
        })
        .map(node_id)
        .collect();
    let mut action_ids: Vec<String> = Vec::new();
    for edge in &graph.edges {
        let matches = s(edge, "resolution") == Some("observed")
            && s(edge, "relation") == Some("target_action")
            && object_ids.iter().any(|id| s(edge, "from") == Some(*id))
            && graph.nodes.iter().any(|n| Some(node_id(n)) == edge_to(edge) && s(n, "kind") == Some("action"));
        if matches {
            let to = edge_to(edge).unwrap_or_default().to_string();
            if !action_ids.contains(&to) {
                action_ids.push(to);
            }
        }
    }
    if action_ids.len() == 1 {
        return Resolved { node_id: Some(action_ids[0].clone()), candidates: vec![], reason: None };
    }
    if action_ids.len() > 1 {
        return Resolved {
            node_id: None,
            candidates: graph.nodes.iter().filter(|n| action_ids.iter().any(|id| id == node_id(n))).cloned().collect(),
            reason: Some("interface_object_has_multiple_action_connections"),
        };
    }
    Resolved { node_id: None, candidates: vec![], reason: Some("ui_action_or_object_not_found") }
}

/// `boundUiGraph`: (graph, truncated, omitted).
fn bound_ui_graph(graph: Graph, max_nodes: u64, max_edges: u64) -> (Graph, bool, u64) {
    let keep = (max_nodes as usize).min(graph.nodes.len());
    let nodes: Vec<Value> = graph.nodes[..keep].to_vec();
    let ids: HashSet<&str> = nodes.iter().map(node_id).collect();
    let eligible: Vec<Value> = graph
        .edges
        .iter()
        .filter(|e| ids.contains(s(e, "from").unwrap_or_default()) && edge_to(e).map(|to| ids.contains(to)).unwrap_or(true))
        .cloned()
        .collect();
    let edges: Vec<Value> = eligible.into_iter().take(max_edges as usize).collect();
    let omitted = (graph.nodes.len() - nodes.len() + graph.edges.len() - edges.len()) as u64;
    let truncated = omitted > 0;
    (
        Graph { nodes, edges, truncated: graph.truncated || truncated, ..graph },
        truncated,
        omitted,
    )
}

// -------------------------------------------------------------- call routes ---

struct Routes {
    provider: Value,
    routes: Vec<Route>,
    unknowns: Vec<(String, String)>,
}

struct Route {
    address: String,
    site: String,
    relation: &'static str,
    resolution: &'static str,
}

fn unwrap_property<'a>(value: &'a Value, property: &str) -> &'a Value {
    match value.as_object() {
        Some(map) if map.contains_key(property) => &map[property],
        _ => value,
    }
}

const AVAILABLE_KIND_KEYS: [&str; 16] = [
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
];

/// `referencesSchema` of `NativeCallRoutes.ts`.
struct TypedReferences {
    kinds_available: bool,
    references: Vec<TypedReference>,
    unresolved: Vec<(String, String)>,
}

/// One entry of `references`; `flags` is `(call, computed, indirect)` when the kind is available.
struct TypedReference {
    source: String,
    target: String,
    target_procedure: Option<String>,
    flags: Option<(bool, bool, bool)>,
}

fn parse_references(value: &Value) -> Option<TypedReferences> {
    let map = value.as_object()?;
    let kinds_available = map.get("reference_kinds_available")?.as_bool()?;
    let mut references = Vec::new();
    for reference in map.get("references")?.as_array()? {
        let r = reference.as_object()?;
        let source = r.get("source_address")?.as_str()?.to_string();
        let target = r.get("target_address")?.as_str()?.to_string();
        let target_procedure = match r.get("target_procedure")? {
            Value::Null => None,
            other => Some(other.as_object()?.get("address")?.as_str()?.to_string()),
        };
        let kind = r.get("kind")?.as_object()?;
        let flags = match kind.get("available")?.as_bool()? {
            false => {
                if !only_keys(kind, &["available", "reason"]) || !kind.get("reason")?.is_string() {
                    return None;
                }
                None
            }
            true => {
                if kind.len() != AVAILABLE_KIND_KEYS.len() || !only_keys(kind, &AVAILABLE_KIND_KEYS) {
                    return None;
                }
                if !kind.get("provenance")?.as_str().map(|p| !p.is_empty()).unwrap_or(false) || !kind.get("type")?.is_string() {
                    return None;
                }
                for key in ["flow", "call", "jump", "data", "read", "write", "indirect", "computed", "conditional", "terminal", "primary", "external"] {
                    kind.get(key)?.as_bool()?;
                }
                let operand = kind.get("operand_index")?.as_f64()?;
                if operand.fract() != 0.0 {
                    return None;
                }
                Some((kind["call"].as_bool()?, kind["computed"].as_bool()?, kind["indirect"].as_bool()?))
            }
        };
        references.push(TypedReference { source, target, target_procedure, flags });
    }
    let mut unresolved = Vec::new();
    for item in map.get("unresolved_calls")?.as_array()? {
        let u = item.as_object()?;
        if !only_keys(u, &["address", "reason"]) {
            return None;
        }
        unresolved.push((u.get("address")?.as_str()?.to_string(), u.get("reason")?.as_str()?.to_string()));
    }
    Some(TypedReferences { kinds_available, references, unresolved })
}

/// `readNativeCallRoutes`: typed static call references, falling back to
/// untyped provider callees.
async fn read_call_routes<P: AnalysisPort + Sync>(port: &P, procedure: &str) -> Result<Routes, ToolError> {
    match port.execute("procedure_references", json!({ "procedure": procedure, "direction": "outgoing" })).await {
        Ok(execution) => {
            let parsed = parse_references(&execution.result)
                .ok_or_else(|| output_error("procedure_references", "Invalid typed call references"))?;
            let all_available = !parsed.references.is_empty() && parsed.references.iter().all(|r| r.flags.is_some());
            if parsed.kinds_available || all_available {
                let calls: Vec<&TypedReference> =
                    parsed.references.iter().filter(|r| r.flags.map(|(call, _, _)| call).unwrap_or(false)).collect();
                let mut targets_by_site: HashMap<&str, HashSet<&str>> = HashMap::new();
                for call in &calls {
                    targets_by_site.entry(call.source.as_str()).or_default().insert(call.target.as_str());
                }
                let routes = calls
                    .iter()
                    .map(|call| {
                        let (_, computed, indirect) = call.flags.unwrap_or((false, false, false));
                        let dynamic = computed || indirect;
                        Route {
                            address: call.target_procedure.clone().unwrap_or_else(|| call.target.clone()),
                            site: call.source.clone(),
                            relation: if dynamic { "indirect_call" } else { "direct_call" },
                            resolution: if targets_by_site.get(call.source.as_str()).map(|t| t.len()).unwrap_or(0) > 1 {
                                "ambiguous"
                            } else if dynamic {
                                "resolved"
                            } else {
                                "observed"
                            },
                        }
                    })
                    .collect();
                return Ok(Routes { provider: execution.provider, routes, unknowns: parsed.unresolved });
            }
        }
        Err(error) if !is_capability_unavailable(&error) => return Err(error),
        Err(_) => {}
    }
    let callees = port.execute("procedure_callees", json!({ "procedure": procedure })).await?;
    let list = unwrap_property(&callees.result, "callees");
    let addresses: Vec<String> = list
        .as_array()
        .and_then(|items| items.iter().map(|v| v.as_str().map(str::to_string)).collect())
        .ok_or_else(|| ToolError::protocol("Hopper returned an invalid callees list"))?;
    Ok(Routes {
        provider: callees.provider,
        routes: addresses
            .into_iter()
            .map(|address| Route { address, site: procedure.to_string(), relation: "provider_call", resolution: "inferred" })
            .collect(),
        unknowns: Vec::new(),
    })
}

// ------------------------------------------------------------------ workflow --

struct Expansion {
    nodes: Vec<Value>,
    edges: Vec<Value>,
    examined: u64,
    omitted: u64,
    truncated: bool,
}

fn graph_node_depths(start: &str, nodes: &[Value], edges: &[Value]) -> HashMap<String, u64> {
    let known: HashSet<&str> = nodes.iter().map(node_id).collect();
    let mut depths: HashMap<String, u64> = HashMap::from([(start.to_string(), 0)]);
    let mut queue: Vec<String> = vec![start.to_string()];
    let mut index = 0;
    while index < queue.len() {
        let current = queue[index].clone();
        index += 1;
        let depth = depths.get(&current).copied().unwrap_or(0);
        for edge in edges {
            let Some(to) = edge_to(edge) else { continue };
            if s(edge, "resolution") == Some("unresolved")
                || s(edge, "from") != Some(current.as_str())
                || !known.contains(to)
                || depths.contains_key(to)
            {
                continue;
            }
            depths.insert(to.to_string(), depth + 1);
            queue.push(to.to_string());
        }
    }
    depths
}

struct QueueEntry {
    node: Value,
    address: String,
    depth: u64,
}

async fn add_direct_callees<P: AnalysisPort + Sync>(
    port: &P,
    initial: &Value,
    max_depth: u64,
    max_nodes: u64,
    max_edges: u64,
    target_sha256: &str,
) -> Result<Expansion, ToolError> {
    let initial_nodes: Vec<Value> = initial["nodes"].as_array().cloned().unwrap_or_default();
    let initial_edges: Vec<Value> = initial["edges"].as_array().cloned().unwrap_or_default();
    let initial_unresolved: Vec<Value> = initial["unresolved"].as_array().cloned().unwrap_or_default();
    let mut nodes = OrderedMap::from(initial_nodes.iter().map(|n| (node_id(n).to_string(), n.clone())));
    let mut edges = OrderedMap::from(
        initial_edges.iter().chain(initial_unresolved.iter()).map(|e| (s(e, "id").unwrap_or_default().to_string(), e.clone())),
    );
    let mut address_names: HashMap<String, String> = HashMap::new();
    let start = initial["start"].as_str().unwrap_or_default();
    let reached = initial["reached_depth"].as_u64().unwrap_or(0);
    let depth_by_node = graph_node_depths(start, &initial_nodes, &initial_edges);
    for node in nodes.values() {
        if s(node, "kind") == Some("function") {
            // `node.location?.address !== null`: a missing location counts as undefined.
            match node.get("location") {
                Some(Value::Object(location)) => {
                    if let Some(Value::String(address)) = location.get("address") {
                        address_names.insert(address.clone(), s(node, "name").unwrap_or_default().to_string());
                    }
                }
                _ => {
                    address_names.insert(String::new(), s(node, "name").unwrap_or_default().to_string());
                }
            }
        }
    }
    let mut queue: Vec<QueueEntry> = initial_nodes
        .iter()
        .filter_map(|node| {
            let address = node["location"].get("address").and_then(Value::as_str)?;
            (s(node, "kind") == Some("function")).then(|| QueueEntry {
                node: node.clone(),
                address: address.to_string(),
                depth: depth_by_node.get(node_id(node)).copied().unwrap_or(reached),
            })
        })
        .collect();
    let mut visited: HashSet<String> = HashSet::new();
    let mut index = 0;
    let mut examined: u64 = 0;
    let mut omitted: u64 = 0;
    let mut truncated = false;
    while index < queue.len() {
        let current_index = index;
        index += 1;
        let (current_node, current_address, current_depth) = {
            let c = &queue[current_index];
            (c.node.clone(), c.address.clone(), c.depth)
        };
        if visited.contains(&current_address) {
            continue;
        }
        visited.insert(current_address.clone());
        if current_depth >= max_depth {
            truncated = true;
            omitted += 1;
            continue;
        }
        if nodes.len() as u64 >= max_nodes {
            truncated = true;
            omitted += (queue.len() - index + 1) as u64;
            break;
        }
        let execution = read_call_routes(port, &current_address).await;
        examined += 1;
        let routes = match execution {
            Ok(routes) => routes,
            Err(error) => {
                if is_cancelled(&error) {
                    return Err(error);
                }
                let id = format!("unknown-callees:{current_address}");
                edges.set(
                    id.clone(),
                    json!({
                        "id": id,
                        "from": node_id(&current_node),
                        "to": Value::Null,
                        "relation": "direct_call",
                        "resolution": "unresolved",
                        "reason": error.user_message_text(),
                        "evidence": [],
                        "limitations": ["The provider could not enumerate resolved direct callees."],
                    }),
                );
                continue;
            }
        };
        for (unknown_address, unknown_reason) in &routes.unknowns {
            if edges.len() as u64 >= max_edges {
                truncated = true;
                omitted += 1;
                break;
            }
            let id = format!("unknown-dispatch:{current_address}:{unknown_address}");
            edges.set(
                id.clone(),
                json!({
                    "id": id,
                    "from": node_id(&current_node),
                    "to": Value::Null,
                    "relation": "indirect_call",
                    "resolution": "unresolved",
                    "reason": unknown_reason,
                    "evidence": [{
                        "kind": "reference",
                        "description": unknown_reason,
                        "location": { "address": unknown_address, "file_offset": Value::Null },
                        "artifact_path": Value::Null,
                        "artifact_sha256": target_sha256,
                    }],
                    "limitations": [],
                }),
            );
        }
        let provider_id = routes.provider["id"].as_str().unwrap_or_default().to_string();
        let provider_name = routes.provider["name"].as_str().unwrap_or_default().to_string();
        let total = routes.routes.len();
        for (route_index, route) in routes.routes.iter().enumerate() {
            let address = &route.address;
            if edges.len() as u64 >= max_edges {
                truncated = true;
                omitted += (total - route_index) as u64;
                break;
            }
            let target_id = format!("native:function:{address}");
            let evidence = json!([{
                "kind": "reference",
                "description": format!("{provider_name} reported {} from {current_address} to {address}", route.relation),
                "location": { "address": route.site, "file_offset": Value::Null },
                "artifact_path": Value::Null,
                "artifact_sha256": target_sha256,
            }]);
            if !nodes.has(&target_id) {
                if nodes.len() as u64 >= max_nodes {
                    truncated = true;
                    omitted += 1;
                    let id = format!("unknown-node-bound:{current_address}:{address}");
                    edges.set(
                        id.clone(),
                        json!({
                            "id": id,
                            "from": node_id(&current_node),
                            "to": Value::Null,
                            "relation": "direct_call",
                            "resolution": "unresolved",
                            "reason": "native_trace_node_bound_reached",
                            "evidence": evidence,
                            "limitations": [],
                        }),
                    );
                    continue;
                }
                let name = address_names.get(address).cloned().unwrap_or_else(|| address.clone());
                let node = json!({
                    "id": target_id,
                    "kind": "function",
                    "name": name,
                    "location": { "address": address, "file_offset": Value::Null },
                    "attributes": { "resolved_by": provider_id },
                    "evidence": evidence,
                });
                nodes.set(target_id.clone(), node.clone());
                queue.push(QueueEntry { node, address: address.clone(), depth: current_depth + 1 });
            }
            let edge_id = format!("call:{current_address}:{}:{address}", route.site);
            edges.set(
                edge_id.clone(),
                json!({
                    "id": edge_id,
                    "from": node_id(&current_node),
                    "to": target_id,
                    "relation": route.relation,
                    "resolution": route.resolution,
                    "evidence": evidence,
                    "limitations": ["A resolved static call edge does not establish runtime reachability."],
                }),
            );
        }
    }
    Ok(Expansion {
        nodes: nodes.values().cloned().collect(),
        edges: edges.values().cloned().collect(),
        examined,
        omitted,
        truncated,
    })
}

fn empty_graph(target_sha256: &str, provider: &Value) -> Graph {
    Graph {
        target_sha256: target_sha256.to_string(),
        provider: json!({
            "id": provider["id"],
            "version": provider["version"],
            "tool_version": "rea-native-ui-trace/1",
        }),
        nodes: vec![],
        edges: vec![],
        coverage: vec![],
        truncated: false,
    }
}

/// Input of `trace_native_ui_action` after admission.
pub struct TraceInput {
    pub action: String,
    pub max_depth: u64,
    pub max_nodes: u64,
    pub max_edges: u64,
}

impl TraceInput {
    pub fn from_validated(input: &Map<String, Value>) -> TraceInput {
        TraceInput {
            action: input.get("action").and_then(Value::as_str).unwrap_or_default().to_string(),
            max_depth: input.get("max_depth").and_then(Value::as_u64).unwrap_or(8),
            max_nodes: input.get("max_nodes").and_then(Value::as_u64).unwrap_or(250),
            max_edges: input.get("max_edges").and_then(Value::as_u64).unwrap_or(500),
        }
    }
}

/// `traceNativeUiAction`: the UI-to-code trace of the active app.
pub async fn trace_native_ui_action<P: AnalysisPort + Sync>(port: &P, input: &TraceInput) -> Result<Value, ToolError> {
    let (ui_execution, metadata_execution) = tokio::join!(
        port.execute(
            "decode_interface_builder",
            json!({ "max_documents": 64, "max_objects": input.max_nodes, "max_connections": input.max_edges }),
        ),
        inspect_native_dispatch(port, 20_000),
    );
    if let Err(error) = &ui_execution {
        if is_cancelled(error) {
            return Err(error.clone());
        }
    }
    let metadata = metadata_execution?;
    let Some(target_sha256) = metadata.target_sha256.clone() else {
        return Err(output_error("inspect_native_dispatch_metadata", "Dispatch metadata lacks target identity"));
    };

    let mut graph = empty_graph(&target_sha256, &metadata.provider);
    let mut coverage: Vec<Value> = Vec::new();
    match &ui_execution {
        Ok(execution) => {
            let Some((decoded_graph, document_count)) = parse_interface_builder(&execution.result) else {
                return Err(output_error("decode_interface_builder", "artifact provider returned an invalid interface graph"));
            };
            if execution.result["target_sha256"].as_str() != Some(target_sha256.as_str()) {
                return Err(output_error(
                    "decode_interface_builder",
                    "UI and native provider results refer to different target SHA-256 values",
                ));
            }
            graph = join_dispatch(decoded_graph.clone(), &metadata.implementations);
            let archive_decode = decoded_graph.coverage.iter().find(|facet| s(facet, "facet") == Some("archive_decode"));
            let documents_found = document_count > 0;
            let archive_status = archive_decode.and_then(|f| s(f, "status")).unwrap_or_default();
            coverage.push(json!({
                "facet": "interface_builder_archives",
                "status": if ["partial", "complete", "unsupported"].contains(&archive_status) {
                    archive_status
                } else if documents_found {
                    "complete"
                } else {
                    "unsupported"
                },
                "reason": match archive_decode.and_then(|f| f.get("reason")) {
                    Some(Value::String(reason)) => json!(reason),
                    _ => if documents_found { Value::Null } else { json!("no_compiled_interface_builder_archives_found") },
                },
                "examined": archive_decode.and_then(|f| f.get("examined").cloned()).unwrap_or_else(|| json!(document_count)),
                "omitted": archive_decode.and_then(|f| f.get("omitted").cloned()).unwrap_or_else(|| json!(0)),
            }));
            let (bounded, truncated, omitted) = bound_ui_graph(graph, input.max_nodes, input.max_edges);
            graph = bounded;
            if truncated {
                coverage.push(json!({
                    "facet": "interface_builder_graph",
                    "status": "partial",
                    "reason": "native_trace_output_bounds_reached",
                    "examined": decoded_graph.nodes.len() + decoded_graph.edges.len(),
                    "omitted": omitted,
                }));
            }
        }
        Err(error) => coverage.push(json!({
            "facet": "interface_builder_archives",
            "status": "unsupported",
            "reason": error.user_message_text(),
            "examined": 0,
            "omitted": 0,
        })),
    }

    let mut selected = resolve_ui_action(&graph, &input.action);
    if selected.node_id.is_none() && selected.candidates.is_empty() {
        match port.execute("procedure_address", json!({ "procedure": input.action })).await {
            Err(error) if is_cancelled(&error) => return Err(error),
            Err(_) => {}
            Ok(native) => {
                let address = native.result.as_str();
                let Some(address) = address.filter(|_| native.subject_sha256.as_deref() == Some(target_sha256.as_str())) else {
                    return Err(output_error(
                        "procedure_address",
                        "Native seed lacks a validated address or matching target identity",
                    ));
                };
                let id = format!("native:function:{address}");
                graph.nodes.push(json!({
                    "id": id,
                    "kind": "function",
                    "name": input.action,
                    "location": { "address": address, "file_offset": Value::Null },
                    "attributes": { "resolved_by": native.provider["id"] },
                    "evidence": [{
                        "kind": "reference",
                        "description": format!("Provider resolved the explicit native seed {}", input.action),
                        "location": { "address": address, "file_offset": Value::Null },
                        "artifact_path": Value::Null,
                        "artifact_sha256": target_sha256,
                    }],
                }));
                selected = Resolved { node_id: Some(id), candidates: vec![], reason: None };
            }
        }
    }
    let Some(start) = selected.node_id.clone() else {
        coverage.extend(graph.coverage.iter().cloned());
        return Ok(json!({
            "target_sha256": graph.target_sha256,
            "provider": graph.provider,
            "start": input.action,
            "direction": "forward",
            "nodes": selected.candidates,
            "edges": [],
            "unresolved": [],
            "reached_depth": 0,
            "truncated": graph.truncated,
            "reason": selected.reason,
            "coverage": coverage,
            "limitations": [
                "The query did not identify one unique authored UI action or native function; no handler path was inferred.",
            ],
        }));
    };

    let initial = trace_graph(&graph, &start, input.max_depth, input.max_nodes, input.max_edges);
    let expanded = add_direct_callees(port, &initial, input.max_depth, input.max_nodes, input.max_edges, &target_sha256).await?;
    coverage.push(json!({
        "facet": "static_native_calls",
        "status": "partial",
        "reason": "typed_direct_and_indirect_references_do_not_cover_all_runtime_dispatch; untyped_provider_callees_remain_inferred",
        "examined": expanded.examined,
        "omitted": expanded.omitted,
    }));
    coverage.push(json!({
        "facet": "cross_function_value_flow",
        "status": "unsupported",
        "reason": "call edges identify control-flow candidates but do not recover argument, return, or shared-memory value relationships",
        "examined": 0,
        "omitted": 0,
    }));
    let mut all_coverage = graph.coverage.clone();
    all_coverage.extend(coverage);
    let final_graph = Graph {
        nodes: expanded.nodes.clone(),
        edges: expanded.edges.clone(),
        coverage: all_coverage,
        truncated: graph.truncated || expanded.truncated,
        ..graph.clone()
    };
    let mut trace = trace_graph(&final_graph, &start, input.max_depth, input.max_nodes, input.max_edges);
    let trace_truncated = trace["truncated"].as_bool().unwrap_or(false);
    let trace_reason = trace["reason"].clone();
    trace["truncated"] = json!(trace_truncated || expanded.truncated || graph.truncated);
    trace["reason"] = if expanded.truncated && trace_reason.is_null() {
        json!("native_call_traversal_bound_reached")
    } else if graph.truncated && trace_reason.is_null() {
        json!("native_trace_output_bound_reached")
    } else {
        trace_reason
    };
    Ok(trace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordered_map_keeps_first_position() {
        let mut map = OrderedMap::default();
        map.set("a".into(), json!(1));
        map.set("b".into(), json!(2));
        map.set("a".into(), json!(3));
        let values: Vec<Value> = map.values().cloned().collect();
        assert_eq!(values, vec![json!(3), json!(2)]);
    }

    #[test]
    fn symbol_inventory_decodes_objc_methods() {
        let names = vec![
            ("0x1000".to_string(), "-[BuildViewController buildTapped:]".to_string()),
            ("0x1100".to_string(), "+[Factory make]".to_string()),
            ("0x1200".to_string(), "unrelated".to_string()),
        ];
        let found = inspect_names(&names, 10);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].class_name, "BuildViewController");
        assert_eq!(found[1].method_type, "class");
    }
}
