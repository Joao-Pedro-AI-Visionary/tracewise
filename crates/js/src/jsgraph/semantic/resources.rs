//! Port of `javascriptSemanticResources.ts`: built-in filesystem/network acquisition and local
//! release handles.

use std::collections::{HashMap, HashSet};

use crate::jsgraph::ast::N;
use crate::jsgraph::ast_values::static_property_name;
use crate::jsgraph::ir::{SemanticCallable, SemanticResourceOperation};

use super::data_effect_helpers::{
    data_effect_member_callee, outer_data_effect_binding, traverse_data_effects,
};
use super::provenance::semantic_builtin_namespace_path;
use super::state::{resolve_semantic_binding_state, BindingIx, SemanticAnalysisState};

const ACQUIRE_METHODS: [&str; 6] =
    ["open", "openSync", "createReadStream", "createWriteStream", "connect", "createConnection"];
const RELEASE_METHODS: [&str; 3] = ["close", "destroy", "end"];

struct ResourceCandidate<'a> {
    node: N<'a>,
    method: &'static str,
    owner_callable_id: Option<String>,
    result_binding_id: Option<String>,
}

/// Recover built-in filesystem/network acquisition and local release handles
/// (`collectJavaScriptSemanticResources`).
pub fn collect_semantic_resources<'a>(
    root: N<'a>,
    state: &SemanticAnalysisState<'a>,
    callables: &[SemanticCallable],
) -> Vec<SemanticResourceOperation> {
    let callable_ids: HashSet<String> = callables.iter().map(|callable| callable.callable_id.clone()).collect();
    let acquisitions = collect_acquisitions(root, state, &callable_ids);
    let mut output: Vec<SemanticResourceOperation> = acquisitions.iter().map(immutable_acquisition).collect();
    output.extend(collect_releases(root, state, &callable_ids, &acquisitions));
    output
}

fn collect_acquisitions<'a>(
    root: N<'a>,
    state: &SemanticAnalysisState<'a>,
    callable_ids: &HashSet<String>,
) -> Vec<ResourceCandidate<'a>> {
    let mut output = Vec::new();
    traverse_data_effects(root, callable_ids, |node, _parent, owner| {
        if !node.is_call() {
            return;
        }
        let Some(callee) = node.f("callee") else { return };
        let Some(method) = acquisition_method(callee, state) else { return };
        output.push(ResourceCandidate {
            node,
            method,
            owner_callable_id: owner.map(String::from),
            result_binding_id: outer_data_effect_binding(node, state),
        });
    });
    output
}

fn collect_releases<'a>(
    root: N<'a>,
    state: &SemanticAnalysisState<'a>,
    callable_ids: &HashSet<String>,
    acquisitions: &[ResourceCandidate<'a>],
) -> Vec<SemanticResourceOperation> {
    let mut by_binding: HashMap<&str, Vec<usize>> = HashMap::new();
    for (index, acquisition) in acquisitions.iter().enumerate() {
        if let Some(binding) = &acquisition.result_binding_id {
            by_binding.entry(binding.as_str()).or_default().push(index);
        }
    }
    let mut output = Vec::new();
    traverse_data_effects(root, callable_ids, |node, _parent, owner| {
        if !node.is_call() {
            return;
        }
        let Some(member) = data_effect_member_callee(node) else { return };
        let Some(object) = member.f("object").filter(|object| object.is_identifier()) else { return };
        let Some(property) = member.f("property") else { return };
        let name = static_property_name(property, member.flag("computed"));
        let Some(method) = RELEASE_METHODS.iter().copied().find(|candidate| *candidate == name) else { return };
        let binding = resolve_semantic_binding_state(state, object, object.name().unwrap_or(""));
        let binding_id = binding.map(|ix| state.bindings[ix].binding_id.as_str());
        let linked: &[usize] = binding_id.and_then(|id| by_binding.get(id)).map_or(&[], Vec::as_slice);
        if linked.is_empty() {
            return;
        }
        let mut linked_ids: Vec<String> = linked.iter().map(|&index| resource_candidate_id(&acquisitions[index])).collect();
        linked_ids.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
        output.push(SemanticResourceOperation {
            resource_id: format!("resource:release:{}:{}", node.start(), node.end()),
            kind: "release".into(),
            method: method.into(),
            location: node.loc(),
            owner_callable_id: owner.map(String::from),
            result_binding_id: binding_id.map(String::from),
            linked_resource_ids: linked_ids,
            resolution: if linked.len() == 1 { "complete" } else { "partial" }.into(),
        });
    });
    output
}

fn immutable_acquisition(candidate: &ResourceCandidate<'_>) -> SemanticResourceOperation {
    SemanticResourceOperation {
        resource_id: resource_candidate_id(candidate),
        kind: "acquire".into(),
        method: candidate.method.into(),
        location: candidate.node.loc(),
        owner_callable_id: candidate.owner_callable_id.clone(),
        result_binding_id: candidate.result_binding_id.clone(),
        linked_resource_ids: Vec::new(),
        resolution: "complete".into(),
    }
}

fn acquisition_method<'a>(callee: N<'a>, state: &SemanticAnalysisState<'a>) -> Option<&'static str> {
    if callee.is_identifier() {
        let binding = resolve_semantic_binding_state(state, callee, callee.name().unwrap_or(""));
        return method_from_binding(state, binding);
    }
    if !callee.is_member() {
        return None;
    }
    let name = static_property_name(callee.f("property")?, callee.flag("computed"));
    let method = ACQUIRE_METHODS.iter().copied().find(|candidate| *candidate == name)?;
    let object = callee.f("object").filter(|object| object.is_identifier())?;
    let binding = resolve_semantic_binding_state(state, object, object.name().unwrap_or(""));
    resource_namespace(state, binding).then_some(method)
}

fn method_from_binding(state: &SemanticAnalysisState<'_>, binding: Option<BindingIx>) -> Option<&'static str> {
    for origin in &state.bindings[binding?].direct_origins {
        if !resource_module(&origin.specifier) {
            continue;
        }
        let last = origin.imported_path.last();
        if let Some(method) = ACQUIRE_METHODS.iter().copied().find(|candidate| Some(*candidate) == last.map(String::as_str)) {
            return Some(method);
        }
    }
    None
}

fn resource_namespace(state: &SemanticAnalysisState<'_>, binding: Option<BindingIx>) -> bool {
    binding.is_some_and(|binding| {
        state.bindings[binding]
            .direct_origins
            .iter()
            .any(|origin| resource_module(&origin.specifier) && semantic_builtin_namespace_path(&origin.imported_path))
    })
}

fn resource_module(specifier: &str) -> bool {
    ["fs", "fs/promises", "net", "node:fs", "node:fs/promises", "node:net", "node:tls", "tls"].contains(&specifier)
}

fn resource_candidate_id(candidate: &ResourceCandidate<'_>) -> String {
    format!("resource:acquire:{}:{}", candidate.node.start(), candidate.node.end())
}
