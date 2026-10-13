//! Port of `javascriptSemanticDataEffects.ts`: configuration, request and boundary candidates.

use std::collections::{HashMap, HashSet};

use crate::jsgraph::ast::{Kind, NodeId, N};
use crate::jsgraph::ast_values::{static_property_key, static_property_name, unwrap_expression};
use crate::jsgraph::ir::{
    Primitive, RequestField, SemanticBoundaryOperation, SemanticCallable, SemanticConfigurationOperation,
    SemanticRequestOperation,
};
use crate::jsgraph::util::compare_code_points;

use super::data_effect_helpers::{
    ancestors_nearest_first, assigned_semantic_result_bindings, builtin_data_effect_method,
    data_effect_argument_binding_id, data_effect_literal_string, data_effect_member_callee, data_effect_member_object,
    data_effect_primitive, is_semantic_process_object, outer_data_effect_binding, projected_result_facts,
    traverse_data_effects,
};
use super::provenance::semantic_builtin_namespace_path;
use super::state::{resolve_semantic_binding_state, semantic_resolution_blocked, SemanticAnalysisState};

/// `DataEffectAnalysis`.
#[derive(Clone, Debug, Default)]
pub struct DataEffectAnalysis {
    pub configuration_operations: Vec<SemanticConfigurationOperation>,
    pub request_operations: Vec<SemanticRequestOperation>,
    pub boundary_operations: Vec<SemanticBoundaryOperation>,
}

struct ConfigurationCandidate<'a> {
    node: N<'a>,
    operation: SemanticConfigurationOperation,
}

struct RequestCandidate {
    operation: SemanticRequestOperation,
}

/// Recover configuration, request, and boundary candidates from inert syntax
/// (`collectJavaScriptSemanticDataEffects`).
pub fn collect_semantic_data_effects<'a>(
    root: N<'a>,
    state: &SemanticAnalysisState<'a>,
    callables: &[SemanticCallable],
) -> DataEffectAnalysis {
    let callable_ids: HashSet<String> = callables.iter().map(|callable| callable.callable_id.clone()).collect();
    let configuration = collect_configurations(root, state, &callable_ids);
    let requests = collect_requests(root, state, &callable_ids);
    let mut configuration_operations: Vec<SemanticConfigurationOperation> =
        configuration.iter().map(|candidate| candidate.operation.clone()).collect();
    configuration_operations.extend(collect_defaults(root, state, &callable_ids, &configuration));
    let mut request_operations: Vec<SemanticRequestOperation> =
        requests.iter().map(|candidate| candidate.operation.clone()).collect();
    request_operations.extend(collect_response_consumers(root, state, &callable_ids, &requests));
    DataEffectAnalysis {
        configuration_operations,
        request_operations,
        boundary_operations: collect_boundaries(root, state, &callable_ids),
    }
}

struct ConfigurationDetails {
    kind: &'static str,
    key: Option<String>,
    resolution: &'static str,
}

fn collect_configurations<'a>(
    root: N<'a>,
    state: &SemanticAnalysisState<'a>,
    callable_ids: &HashSet<String>,
) -> Vec<ConfigurationCandidate<'a>> {
    let mut output = Vec::new();
    traverse_data_effects(root, callable_ids, |node, parent, owner| {
        let Some(details) = configuration_details(node, parent, state) else { return };
        let operation = SemanticConfigurationOperation {
            config_id: format!("config:{}:{}:{}", details.kind, node.start(), node.end()),
            kind: details.kind.into(),
            location: node.loc(),
            owner_callable_id: owner.map(String::from),
            result_binding_id: outer_data_effect_binding(node, state),
            key: details.key,
            source_config_id: None,
            value: Primitive::Null,
            resolution: details.resolution.into(),
        };
        output.push(ConfigurationCandidate { node, operation });
    });
    output
}

fn configuration_details<'a>(
    node: N<'a>,
    parent: Option<N<'a>>,
    state: &SemanticAnalysisState<'a>,
) -> Option<ConfigurationDetails> {
    if node.is_member() && data_effect_member_object(parent) != Some(node) {
        if let Some(process_member) = process_configuration_member(node, state) {
            return Some(process_member);
        }
    }
    if !node.is_call() {
        return None;
    }
    let file_method = builtin_data_effect_method(node.f("callee")?, state, &["fs", "node:fs"]);
    if matches!(file_method.as_deref(), Some("readFile") | Some("readFileSync")) {
        let first = node.list("arguments").first().copied().flatten();
        let key = data_effect_literal_string(first);
        let resolution = if key.is_none() { "partial" } else { "complete" };
        return Some(ConfigurationDetails { kind: "file", key, resolution });
    }
    None
}

fn process_configuration_member<'a>(
    node: N<'a>,
    state: &SemanticAnalysisState<'a>,
) -> Option<ConfigurationDetails> {
    let object = node.f("object")?;
    if !object.is_member() {
        return None;
    }
    if !is_semantic_process_object(object.f("object")?, state) {
        return None;
    }
    let family = static_property_name(object.f("property")?, object.flag("computed"));
    if family != "env" && family != "argv" {
        return None;
    }
    // `process.env[""]` names an exact (empty) key; only a dynamic key is unknown.
    let key = static_property_key(node.f("property")?, node.flag("computed"));
    if family == "argv" && key.as_deref().is_some_and(|key| !is_array_index_key(key)) {
        return None;
    }
    Some(ConfigurationDetails {
        kind: if family == "env" { "environment" } else { "argv" },
        resolution: if key.is_none() { "partial" } else { "complete" },
        key,
    })
}

fn is_array_index_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return false;
    }
    if bytes.len() > 1 && bytes[0] == b'0' {
        return false;
    }
    // `Number.isSafeInteger(index) && index < 2 ** 32 - 1` without float rounding.
    key.parse::<u64>().is_ok_and(|index| index < 4_294_967_295)
}

fn collect_defaults<'a>(
    root: N<'a>,
    state: &SemanticAnalysisState<'a>,
    callable_ids: &HashSet<String>,
    configurations: &[ConfigurationCandidate<'a>],
) -> Vec<SemanticConfigurationOperation> {
    let mut output = Vec::new();
    let by_node: HashMap<NodeId, usize> = configurations
        .iter()
        .enumerate()
        .map(|(index, candidate)| (candidate.node.id, index))
        .collect();
    traverse_data_effects(root, callable_ids, |node, _parent, owner| {
        if !node.is(Kind::LogicalExpression) || !matches!(node.str("operator"), Some("??") | Some("||")) {
            return;
        }
        let Some(left) = node.f("left") else { return };
        let source = unwrap_expression(left).0;
        let Some(&index) = by_node.get(&source.id) else { return };
        let candidate = &configurations[index];
        let Some(right) = node.f("right") else { return };
        let value = data_effect_primitive(right);
        output.push(SemanticConfigurationOperation {
            config_id: format!("config:default:{}:{}", node.start(), node.end()),
            kind: "default".into(),
            location: right.loc(),
            owner_callable_id: owner.map(String::from),
            result_binding_id: outer_data_effect_binding(node, state),
            key: candidate.operation.key.clone(),
            source_config_id: Some(candidate.operation.config_id.clone()),
            resolution: if value.is_none() { "partial" } else { "complete" }.into(),
            value: value.unwrap_or(Primitive::Null),
        });
    });
    output
}

fn collect_requests<'a>(
    root: N<'a>,
    state: &SemanticAnalysisState<'a>,
    callable_ids: &HashSet<String>,
) -> Vec<RequestCandidate> {
    let mut output = Vec::new();
    traverse_data_effects(root, callable_ids, |node, _parent, owner| {
        if !node.is_call() && !node.is(Kind::NewExpression) {
            return;
        }
        let Some(method) = request_method(node, state) else { return };
        let endpoint = request_endpoint(node);
        let projected = assigned_semantic_result_bindings(node, ancestors_nearest_first(node), state);
        output.push(RequestCandidate {
            operation: SemanticRequestOperation {
                request_id: format!("request:{}:{}", node.start(), node.end()),
                kind: "request".into(),
                method: method.into(),
                location: node.loc(),
                owner_callable_id: owner.map(String::from),
                result_binding_id: outer_data_effect_binding(node, state),
                projected_result_bindings: projected_result_facts(&projected),
                linked_request_ids: Vec::new(),
                resolution: if endpoint.is_none() { "partial" } else { "complete" }.into(),
                endpoint,
                fields: request_fields(node, method, state),
            },
        });
    });
    output
}

fn collect_response_consumers<'a>(
    root: N<'a>,
    state: &SemanticAnalysisState<'a>,
    callable_ids: &HashSet<String>,
    requests: &[RequestCandidate],
) -> Vec<SemanticRequestOperation> {
    let mut requests_by_binding: HashMap<&str, Vec<usize>> = HashMap::new();
    for (index, request) in requests.iter().enumerate() {
        let ids = request
            .operation
            .result_binding_id
            .iter()
            .map(String::as_str)
            .chain(request.operation.projected_result_bindings.iter().map(|binding| binding.binding_id.as_str()));
        for id in ids {
            requests_by_binding.entry(id).or_default().push(index);
        }
    }
    let mut output = Vec::new();
    traverse_data_effects(root, callable_ids, |node, _parent, owner| {
        if !node.is_call() {
            return;
        }
        let Some(member) = data_effect_member_callee(node) else { return };
        let Some(object) = member.f("object").filter(|object| object.is_identifier()) else { return };
        let method = static_property_name(member.f("property").unwrap_or(member), member.flag("computed"));
        if method != "json" && method != "text" && method != "arrayBuffer" {
            return;
        }
        let binding = resolve_semantic_binding_state(state, object, object.name().unwrap_or(""));
        let binding_id = binding.map(|ix| state.bindings[ix].binding_id.as_str());
        let linked: Vec<usize> = match binding_id {
            None => Vec::new(),
            Some(id) => requests_by_binding.get(id).cloned().unwrap_or_default(),
        };
        if linked.is_empty() {
            return;
        }
        let projected = assigned_semantic_result_bindings(node, ancestors_nearest_first(node), state);
        let mut linked_ids: Vec<String> =
            linked.iter().map(|&index| requests[index].operation.request_id.clone()).collect();
        linked_ids.sort_by(|left, right| compare_code_points(left, right));
        output.push(SemanticRequestOperation {
            request_id: format!("response:{}:{}", node.start(), node.end()),
            kind: "response-consumer".into(),
            method,
            location: node.loc(),
            owner_callable_id: owner.map(String::from),
            result_binding_id: outer_data_effect_binding(node, state),
            projected_result_bindings: projected_result_facts(&projected),
            linked_request_ids: linked_ids,
            endpoint: None,
            fields: Vec::new(),
            resolution: if linked.len() == 1
                && !requests[linked[0]]
                    .operation
                    .projected_result_bindings
                    .iter()
                    .any(|projected| Some(projected.binding_id.as_str()) == binding_id)
            {
                "complete"
            } else {
                "partial"
            }
            .into(),
        });
    });
    output
}

fn collect_boundaries<'a>(
    root: N<'a>,
    state: &SemanticAnalysisState<'a>,
    callable_ids: &HashSet<String>,
) -> Vec<SemanticBoundaryOperation> {
    let mut output = Vec::new();
    traverse_data_effects(root, callable_ids, |node, _parent, owner| {
        if !node.is_call() {
            return;
        }
        let Some((kind, method, resolution)) = boundary_details(node, state) else { return };
        output.push(SemanticBoundaryOperation {
            boundary_id: format!("boundary:{kind}:{}:{}", node.start(), node.end()),
            kind: kind.into(),
            method,
            location: node.loc(),
            owner_callable_id: owner.map(String::from),
            source_binding_id: data_effect_argument_binding_id(node.list("arguments").first().copied().flatten(), state),
            result_binding_id: outer_data_effect_binding(node, state),
            resolution: resolution.into(),
        });
    });
    output
}

/// `(kind, method, resolution)` of a parse/coerce/validate boundary call.
fn boundary_details<'a>(
    node: N<'a>,
    state: &SemanticAnalysisState<'a>,
) -> Option<(&'static str, String, &'static str)> {
    let callee = node.f("callee")?;
    if callee.is_identifier() {
        let name = callee.name().unwrap_or("");
        let unbound = resolve_semantic_binding_state(state, callee, name).is_none()
            && !semantic_resolution_blocked(state, callee, name);
        if unbound && ["String", "Number", "Boolean", "parseInt", "parseFloat"].contains(&name) {
            return Some(("coerce", name.to_string(), "complete"));
        }
    }
    let member = data_effect_member_callee(node)?;
    let method = static_property_name(member.f("property")?, member.flag("computed"));
    if method == "parse" {
        if let Some(object) = member.f("object") {
            if object.is_identifier()
                && object.name() == Some("JSON")
                && resolve_semantic_binding_state(state, object, "JSON").is_none()
                && !semantic_resolution_blocked(state, object, "JSON")
            {
                return Some(("parse", "JSON.parse".to_string(), "complete"));
            }
        }
    }
    if method == "parse" || method == "safeParse" {
        return Some(("parse", method, "partial"));
    }
    if method == "validate" || method == "assert" || method == "is" {
        return Some(("validate", method, "partial"));
    }
    None
}

fn request_method<'a>(node: N<'a>, state: &SemanticAnalysisState<'a>) -> Option<&'static str> {
    let callee = node.f("callee")?;
    if callee.is_identifier() {
        let name = callee.name().unwrap_or("");
        let unbound = resolve_semantic_binding_state(state, callee, name).is_none()
            && !semantic_resolution_blocked(state, callee, name);
        let is_new = node.is(Kind::NewExpression);
        if !is_new && unbound && name == "fetch" {
            return Some("fetch");
        }
        if is_new && unbound && name == "WebSocket" {
            return Some("WebSocket");
        }
    }
    let member = data_effect_member_callee(node)?;
    let object = member.f("object").filter(|object| object.is_identifier())?;
    let method = static_property_name(member.f("property")?, member.flag("computed"));
    let method = match method.as_str() {
        "request" => "request",
        "get" => "get",
        _ => return None,
    };
    let binding = resolve_semantic_binding_state(state, object, object.name().unwrap_or(""))?;
    state.bindings[binding]
        .direct_origins
        .iter()
        .any(|origin| {
            ["http", "https", "node:http", "node:https"].contains(&origin.specifier.as_str())
                && semantic_builtin_namespace_path(&origin.imported_path)
        })
        .then_some(method)
}

fn request_fields<'a>(node: N<'a>, method: &str, state: &SemanticAnalysisState<'a>) -> Vec<RequestField> {
    let arguments = node.list("arguments");
    let argument = |index: usize| arguments.get(index).copied().flatten();
    let candidate = if method == "fetch" || method == "WebSocket" {
        argument(1)
    } else if argument(0).is_some_and(|first| first.is(Kind::ObjectExpression)) {
        argument(0)
    } else {
        argument(1)
    };
    let Some(candidate) = candidate.filter(|candidate| candidate.is(Kind::ObjectExpression)) else {
        return Vec::new();
    };
    candidate
        .nodes("properties")
        .into_iter()
        .filter(|property| property.is(Kind::ObjectProperty))
        .filter_map(|property| {
            // `{[key]: 1}` sends no knowable field name; reporting `key` would invent a request
            // field that may not exist.
            let name = static_property_key(property.f("key")?, property.flag("computed"))?;
            let source_binding_id = property.f("value").and_then(|value| {
                if value.is_identifier() {
                    resolve_semantic_binding_state(state, value, value.name().unwrap_or(""))
                        .map(|ix| state.bindings[ix].binding_id.clone())
                } else {
                    None
                }
            });
            Some(RequestField { name, source_binding_id })
        })
        .collect()
}

fn request_endpoint(node: N<'_>) -> Option<String> {
    let first = node.list("arguments").first().copied().flatten();
    if first.is_some_and(|first| first.is(Kind::ObjectExpression)) {
        None
    } else {
        data_effect_literal_string(first)
    }
}
