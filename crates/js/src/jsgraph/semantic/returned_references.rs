//! Port of `javascriptSemanticReturnedReferences.ts`: conservative result-reference resolution.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use crate::jsgraph::ast::{Alias, Kind, NodeId, N};
use crate::jsgraph::ast_values::{static_property_key, unwrap_expression};

use super::ast_util::static_key_path;
use super::call_resolution::{callable_by_id, resolve_local_callables, CallableById, LocalCallableResolution};
use super::callable_results::semantic_callable_result_expressions;
use super::property_paths::{semantic_array_index, PathKey, PropertyPath};
use super::state::{resolve_semantic_binding_state, BindingIx, SemanticAnalysisState};

/// A reference potentially handed to a caller or generator consumer.
#[derive(Clone, Debug)]
pub struct SemanticReturnedReference<'a> {
    pub node: N<'a>,
    pub projection: PropertyPath,
}

#[derive(Clone)]
struct Candidate<'a> {
    node: N<'a>,
    path: Vec<PathKey>,
    bindings: Vec<BindingIx>,
}

struct ObjectTargetUnknown<'a> {
    node: N<'a>,
    previous: Option<Rc<ObjectTargetUnknown<'a>>>,
}

struct ObjectTargetIndex<'a> {
    property_by_name: HashMap<String, N<'a>>,
    trailing_unknowns_by_property: HashMap<NodeId, Rc<ObjectTargetUnknown<'a>>>,
}

/// `createSemanticReturnedReferences(state)`: the memoizing resolver returned by REA as a closure.
pub struct SemanticReturnedReferences<'a> {
    callable_by_id: CallableById,
    binding_cache: HashMap<BindingIx, LocalCallableResolution>,
    results: HashMap<NodeId, Rc<Vec<SemanticReturnedReference<'a>>>>,
    object_targets: HashMap<NodeId, Rc<ObjectTargetIndex<'a>>>,
}

/// `createSemanticReturnedReferences`.
pub fn create_semantic_returned_references<'a>(state: &SemanticAnalysisState<'a>) -> SemanticReturnedReferences<'a> {
    SemanticReturnedReferences {
        callable_by_id: callable_by_id(&state.callables),
        binding_cache: HashMap::new(),
        results: HashMap::new(),
        object_targets: HashMap::new(),
    }
}

impl<'a> SemanticReturnedReferences<'a> {
    /// Resolve local result references of `callee` conservatively, without claiming call
    /// execution.
    pub fn get(&mut self, state: &SemanticAnalysisState<'a>, callee: N<'a>) -> Rc<Vec<SemanticReturnedReference<'a>>> {
        if let Some(existing) = self.results.get(&callee.id) {
            return existing.clone();
        }
        let mut functions: Vec<N<'a>> = Vec::new();
        let mut function_set: HashSet<NodeId> = HashSet::new();
        let mut add_function = |node: N<'a>, functions: &mut Vec<N<'a>>| {
            if function_set.insert(node.id) {
                functions.push(node);
            }
        };
        let resolution = resolve_local_callables(
            callee,
            state,
            &self.callable_by_id,
            &HashSet::new(),
            &mut self.binding_cache,
        );
        for id in &resolution.callable_ids {
            if let Some(&node) = state.callable_nodes_by_id.get(id) {
                add_function(node, &mut functions);
            }
        }
        let mut pending: Vec<Candidate<'a>> = vec![Candidate { node: callee, path: Vec::new(), bindings: Vec::new() }];
        let mut cursor = 0;
        while cursor < pending.len() {
            let item = pending[cursor].clone();
            cursor += 1;
            let node = unwrap_expression(item.node).0;
            match node.kind() {
                Kind::Identifier => {
                    let name = node.name().unwrap_or("");
                    let Some(binding_ix) = resolve_semantic_binding_state(state, node, name) else { continue };
                    if item.bindings.contains(&binding_ix) {
                        continue;
                    }
                    let mut bindings = item.bindings.clone();
                    bindings.push(binding_ix);
                    let binding = &state.bindings[binding_ix];
                    for (init_node, projection) in binding
                        .initializers
                        .iter()
                        .map(|i| (i.node, &i.projection))
                        .chain(binding.reference_initializers.iter().map(|i| (i.node, &i.projection)))
                    {
                        let mut path = projection.clone();
                        path.extend(item.path.iter().cloned());
                        pending.push(Candidate { node: init_node, path, bindings: bindings.clone() });
                    }
                }
                Kind::MemberExpression | Kind::OptionalMemberExpression => {
                    let mut path: Vec<PathKey> = Vec::new();
                    let mut receiver = node;
                    while receiver.is_member() {
                        path.push(
                            receiver
                                .f("property")
                                .map(|property| static_key_path(property, receiver.flag("computed")))
                                .unwrap_or(PathKey::Null),
                        );
                        match receiver.f("object") {
                            Some(object) => receiver = unwrap_expression(object).0,
                            None => break,
                        }
                    }
                    path.reverse();
                    path.extend(item.path.iter().cloned());
                    pending.push(Candidate { node: receiver, path, bindings: item.bindings.clone() });
                }
                Kind::ConditionalExpression | Kind::LogicalExpression => {
                    let conditional = node.is(Kind::ConditionalExpression);
                    for key in [if conditional { "consequent" } else { "left" }, if conditional { "alternate" } else { "right" }] {
                        if let Some(branch) = node.f(key) {
                            pending.push(Candidate { node: branch, ..item.clone() });
                        }
                    }
                }
                Kind::SequenceExpression => {
                    if let Some(last) = node.nodes("expressions").last() {
                        pending.push(Candidate { node: *last, ..item.clone() });
                    }
                }
                _ if node.is_function() && item.path.is_empty() => add_function(node, &mut functions),
                Kind::ObjectExpression => self.select_object_targets(node, &item, &mut pending),
                Kind::ArrayExpression => {
                    let key = item.path.first();
                    let path: Vec<PathKey> = item.path.iter().skip(1).cloned().collect();
                    let index = match key {
                        None | Some(PathKey::Null) => None,
                        Some(key) => semantic_array_index(key),
                    };
                    let mut uncertain_offset = false;
                    for (offset, element) in node.list("elements").into_iter().enumerate() {
                        let Some(element) = element else { continue };
                        if element.is(Kind::SpreadElement) {
                            uncertain_offset = true;
                            if let Some(argument) = element.f("argument") {
                                let mut spread_path = vec![PathKey::Null];
                                spread_path.extend(path.iter().cloned());
                                pending.push(Candidate { node: argument, path: spread_path, ..item.clone() });
                            }
                        } else if index.is_none() || uncertain_offset || index == Some(offset as u64) {
                            pending.push(Candidate { node: element, path: path.clone(), ..item.clone() });
                        }
                    }
                }
                Kind::NewExpression => {
                    if let Some(callee) = node.f("callee") {
                        pending.push(Candidate { node: callee, ..item.clone() });
                    }
                }
                _ if node.has_alias(Alias::Class) => {
                    let key = item.path.first();
                    let path: Vec<PathKey> = item.path.iter().skip(1).cloned().collect();
                    let body = node.f("body").map(|b| b.nodes("body")).unwrap_or_default();
                    for member in body {
                        let key_matches = |member: N<'a>| -> bool {
                            match key {
                                None => false,
                                Some(PathKey::Null) => true,
                                Some(key) => {
                                    member
                                        .f("key")
                                        .and_then(|k| static_property_key(k, member.flag("computed")))
                                        .as_deref()
                                        == Some(key.js_string().as_str())
                                }
                            }
                        };
                        if member.is(Kind::ClassMethod) {
                            if (item.path.is_empty() && member.str("kind") == Some("constructor")) || key_matches(member) {
                                pending.push(Candidate { node: member, path: path.clone(), ..item.clone() });
                            }
                        } else if member.is(Kind::ClassProperty) && key_matches(member) {
                            if let Some(value) = member.f("value") {
                                pending.push(Candidate { node: value, path: path.clone(), ..item.clone() });
                            }
                        }
                    }
                    if let Some(super_class) = node.f("superClass") {
                        pending.push(Candidate { node: super_class, ..item.clone() });
                    }
                }
                _ => {}
            }
        }
        let mut output: Vec<SemanticReturnedReference<'a>> = Vec::new();
        for node in functions {
            let callables: Vec<N<'a>> = if node.has_alias(Alias::Class) {
                node.f("body")
                    .map(|body| body.nodes("body"))
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|member| member.is(Kind::ClassMethod) && member.str("kind") == Some("constructor"))
                    .collect()
            } else {
                vec![node]
            };
            for callable in callables {
                for expression in semantic_callable_result_expressions(callable) {
                    if let Some(result) = expression.node {
                        output.push(SemanticReturnedReference {
                            node: result,
                            projection: if expression.delegated { vec![PathKey::Null] } else { Vec::new() },
                        });
                    }
                }
            }
        }
        let output = Rc::new(output);
        self.results.insert(callee.id, output.clone());
        output
    }

    fn select_object_targets(&mut self, node: N<'a>, item: &Candidate<'a>, pending: &mut Vec<Candidate<'a>>) {
        let key = item.path.first();
        let path: Vec<PathKey> = item.path.iter().skip(1).cloned().collect();
        if let Some(key) = key {
            if !matches!(key, PathKey::Null) {
                let index = self.object_target_index(node);
                if let Some(&property) = index.property_by_name.get(&key.js_string()) {
                    let mut unknowns: Vec<Rc<ObjectTargetUnknown<'a>>> = Vec::new();
                    let mut cursor = index.trailing_unknowns_by_property.get(&property.id).cloned();
                    while let Some(unknown) = cursor {
                        cursor = unknown.previous.clone();
                        unknowns.push(unknown);
                    }
                    for unknown in unknowns.iter().rev() {
                        let target = unknown.node;
                        if target.is(Kind::SpreadElement) {
                            if let Some(argument) = target.f("argument") {
                                pending.push(Candidate { node: argument, ..item.clone() });
                            }
                        } else {
                            let value = if target.is(Kind::ObjectProperty) { target.f("value") } else { Some(target) };
                            if let Some(value) = value {
                                pending.push(Candidate { node: value, path: path.clone(), ..item.clone() });
                            }
                        }
                    }
                    let value = if property.is(Kind::ObjectProperty) { property.f("value") } else { Some(property) };
                    if let Some(value) = value {
                        pending.push(Candidate { node: value, path: path.clone(), ..item.clone() });
                    }
                    return;
                }
            }
        }
        let selected_key: Option<String> = match key {
            None | Some(PathKey::Null) => None,
            Some(key) => Some(key.js_string()),
        };
        let mut replaced = false;
        let mut properties = node.nodes("properties");
        properties.reverse();
        for property in properties {
            if replaced {
                break;
            }
            if property.is(Kind::SpreadElement) {
                if let Some(argument) = property.f("argument") {
                    pending.push(Candidate { node: argument, ..item.clone() });
                }
                continue;
            }
            let name = property.f("key").and_then(|k| static_property_key(k, property.flag("computed")));
            if let (Some(selected), Some(name)) = (&selected_key, &name) {
                if name != selected {
                    continue;
                }
            }
            if property.is(Kind::ObjectProperty) {
                if let Some(value) = property.f("value") {
                    pending.push(Candidate { node: value, path: path.clone(), ..item.clone() });
                }
            } else {
                pending.push(Candidate { node: property, path: path.clone(), ..item.clone() });
            }
            if let (Some(selected), Some(name)) = (&selected_key, &name) {
                if name == selected {
                    replaced = true;
                }
            }
        }
    }

    fn object_target_index(&mut self, node: N<'a>) -> Rc<ObjectTargetIndex<'a>> {
        if let Some(existing) = self.object_targets.get(&node.id) {
            return existing.clone();
        }
        let mut property_by_name: HashMap<String, N<'a>> = HashMap::new();
        let mut trailing_unknowns_by_property: HashMap<NodeId, Rc<ObjectTargetUnknown<'a>>> = HashMap::new();
        let mut trailing_unknown: Option<Rc<ObjectTargetUnknown<'a>>> = None;
        let mut properties = node.nodes("properties");
        properties.reverse();
        for property in properties {
            if property.is(Kind::SpreadElement) {
                trailing_unknown = Some(Rc::new(ObjectTargetUnknown { node: property, previous: trailing_unknown.take() }));
                continue;
            }
            let name = property.f("key").and_then(|k| static_property_key(k, property.flag("computed")));
            let Some(name) = name else {
                trailing_unknown = Some(Rc::new(ObjectTargetUnknown { node: property, previous: trailing_unknown.take() }));
                continue;
            };
            if property_by_name.contains_key(&name) {
                continue;
            }
            property_by_name.insert(name, property);
            if let Some(unknown) = &trailing_unknown {
                trailing_unknowns_by_property.insert(property.id, unknown.clone());
            }
        }
        let created = Rc::new(ObjectTargetIndex { property_by_name, trailing_unknowns_by_property });
        self.object_targets.insert(node.id, created.clone());
        created
    }
}
