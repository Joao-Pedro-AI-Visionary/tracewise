//! Port of `javascriptSemanticCallResolution.ts`: local call-target resolution.

use std::collections::{HashMap, HashSet};

use crate::jsgraph::ast::{Kind, N};
use crate::jsgraph::ast_values::unwrap_expression;
use crate::jsgraph::ir::{SemanticCallable, SourceRange};

use super::projection::semantic_callable_id_for_node;
use super::state::{resolve_semantic_binding_state, BindingIx, SemanticAnalysisState};

/// Resolution of one call target within the currently analyzed source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalCallableResolution {
    pub callable_ids: Vec<String>,
    pub complete: bool,
    pub reason: String,
}

/// `callableById` as an index map: callable id to its position in the callables slice.
pub type CallableById = HashMap<String, usize>;

/// Build the `callableById` lookup (later duplicates win, as `new Map(...)`).
pub fn callable_by_id(callables: &[SemanticCallable]) -> CallableById {
    callables.iter().enumerate().map(|(index, callable)| (callable.callable_id.clone(), index)).collect()
}

/// Resolve local callable candidates without following dynamic properties
/// (`resolveLocalCallables`). `seen_bindings` is the set of bindings already on the path and
/// `binding_cache` the shared memo of complete binding resolutions.
pub fn resolve_local_callables<'a>(
    node: N<'a>,
    state: &SemanticAnalysisState<'a>,
    callable_by_id: &CallableById,
    seen_bindings: &HashSet<BindingIx>,
    binding_cache: &mut HashMap<BindingIx, LocalCallableResolution>,
) -> LocalCallableResolution {
    resolve_callables(node, state, callable_by_id, seen_bindings, binding_cache)
}

fn resolve_callables<'a>(
    node: N<'a>,
    state: &SemanticAnalysisState<'a>,
    callable_by_id: &CallableById,
    seen: &HashSet<BindingIx>,
    cache: &mut HashMap<BindingIx, LocalCallableResolution>,
) -> LocalCallableResolution {
    // `unwrapJavaScriptExpression` strips all transparent layers iteratively, so a single
    // recursion step suffices (no per-layer stack growth).
    let unwrapped = unwrap_expression(node).0;
    if unwrapped != node {
        return resolve_callables(unwrapped, state, callable_by_id, seen, cache);
    }
    if let Some(direct) = semantic_callable_id_for_node(node) {
        if callable_by_id.contains_key(&direct) {
            return LocalCallableResolution {
                callable_ids: vec![direct],
                complete: true,
                reason: "Direct local callable.".into(),
            };
        }
    }
    if node.is_identifier() {
        return resolve_identifier(node, state, callable_by_id, seen, cache);
    }
    if node.is(Kind::ConditionalExpression) || node.is(Kind::LogicalExpression) {
        let conditional = node.is(Kind::ConditionalExpression);
        return resolve_alternatives(
            node.f(if conditional { "consequent" } else { "left" }),
            node.f(if conditional { "alternate" } else { "right" }),
            state,
            callable_by_id,
            seen,
            cache,
        );
    }
    LocalCallableResolution {
        callable_ids: Vec::new(),
        complete: false,
        reason: format!("Unsupported {} call target.", node.kind().as_str()),
    }
}

fn resolve_identifier<'a>(
    node: N<'a>,
    state: &SemanticAnalysisState<'a>,
    callable_by_id: &CallableById,
    seen: &HashSet<BindingIx>,
    cache: &mut HashMap<BindingIx, LocalCallableResolution>,
) -> LocalCallableResolution {
    let name = node.name().unwrap_or("");
    match resolve_semantic_binding_state(state, node, name) {
        None => LocalCallableResolution {
            callable_ids: Vec::new(),
            complete: false,
            reason: format!("Unresolved call target {name}."),
        },
        Some(binding) => resolve_binding_callables(binding, state, callable_by_id, seen, cache),
    }
}

fn resolve_alternatives<'a>(
    left: Option<N<'a>>,
    right: Option<N<'a>>,
    state: &SemanticAnalysisState<'a>,
    callable_by_id: &CallableById,
    seen: &HashSet<BindingIx>,
    cache: &mut HashMap<BindingIx, LocalCallableResolution>,
) -> LocalCallableResolution {
    let mut candidates = Vec::new();
    for candidate in [left, right] {
        candidates.push(match candidate {
            Some(candidate) => resolve_callables(candidate, state, callable_by_id, seen, cache),
            None => LocalCallableResolution {
                callable_ids: Vec::new(),
                complete: false,
                reason: "Unsupported undefined call target.".into(),
            },
        });
    }
    LocalCallableResolution {
        callable_ids: unique_callable_ids(candidates.iter().flat_map(|c| c.callable_ids.iter().cloned())),
        complete: candidates.iter().all(|c| c.complete),
        reason: "Conditional or logical call target has multiple candidates.".into(),
    }
}

fn resolve_binding_callables<'a>(
    binding_ix: BindingIx,
    state: &SemanticAnalysisState<'a>,
    callable_by_id: &CallableById,
    seen: &HashSet<BindingIx>,
    cache: &mut HashMap<BindingIx, LocalCallableResolution>,
) -> LocalCallableResolution {
    if let Some(cached) = cache.get(&binding_ix) {
        return cached.clone();
    }
    let binding = &state.bindings[binding_ix];
    if seen.contains(&binding_ix) {
        return LocalCallableResolution {
            callable_ids: Vec::new(),
            complete: false,
            reason: format!("Call target alias cycle at {}.", binding.name),
        };
    }
    if binding.initializers.is_empty() {
        return missing_binding_initializer(binding.kind, &binding.name);
    }
    let mut candidate_seen = seen.clone();
    candidate_seen.insert(binding_ix);
    let mut candidates = Vec::new();
    for initializer in &binding.initializers {
        candidates.push(if initializer.projection.is_empty() {
            resolve_callables(initializer.node, state, callable_by_id, &candidate_seen, cache)
        } else {
            LocalCallableResolution {
                callable_ids: Vec::new(),
                complete: false,
                reason: format!("Projected call target {} is unresolved.", binding.name),
            }
        });
    }
    let callable_ids = unique_callable_ids(candidates.iter().flat_map(|c| c.callable_ids.iter().cloned()));
    let complete = candidates.iter().all(|c| c.complete);
    let resolution = LocalCallableResolution {
        reason: if callable_ids.len() == 1 && complete {
            "Unique local callable target.".into()
        } else {
            format!("Call target {} has ambiguous or unsupported assignments.", binding.name)
        },
        callable_ids,
        complete,
    };
    if resolution.complete {
        cache.insert(binding_ix, resolution.clone());
    }
    resolution
}

fn missing_binding_initializer(kind: &str, name: &str) -> LocalCallableResolution {
    LocalCallableResolution {
        callable_ids: Vec::new(),
        complete: false,
        reason: if kind == "import" {
            format!("Call target {name} is imported from outside this source.")
        } else {
            format!("Call target {name} has no local initializer.")
        },
    }
}

/// Find all bindings introduced by one positional parameter pattern.
pub fn parameter_bindings<'a>(
    callable: &SemanticCallable,
    index: usize,
    state: &SemanticAnalysisState<'a>,
) -> Vec<BindingIx> {
    let Some(body_scope_id) = &callable.body_scope_id else { return Vec::new() };
    let Some(scope) = state.scope_by_id(body_scope_id) else { return Vec::new() };
    let mut found: Vec<BindingIx> = state.scopes[scope]
        .bindings
        .values()
        .copied()
        .filter(|&binding_ix| {
            let binding = &state.bindings[binding_ix];
            binding.kind == "parameter"
                && binding.definitions.iter().any(|definition| {
                    definition.kind == "parameter"
                        && parameter_accepts_argument(callable, &definition.location, index, state)
                })
        })
        .collect();
    found.sort_by(|left, right| state.bindings[*left].binding_id.cmp(&state.bindings[*right].binding_id));
    found
}

fn parameter_accepts_argument<'a>(
    callable: &SemanticCallable,
    location: &SourceRange,
    argument_index: usize,
    state: &SemanticAnalysisState<'a>,
) -> bool {
    let Some(node) = state.callable_nodes_by_id.get(&callable.callable_id) else { return false };
    if !node.is_function() {
        return false;
    }
    let params = node.nodes("params");
    let parameter_index = params.iter().position(|parameter| range_contains(&parameter.loc(), location));
    if parameter_index == Some(argument_index) {
        return true;
    }
    match parameter_index {
        Some(position) => position < argument_index && params[position].is(Kind::RestElement),
        None => false,
    }
}

fn range_contains(outer: &SourceRange, inner: &SourceRange) -> bool {
    (outer.start.line < inner.start.line
        || (outer.start.line == inner.start.line && outer.start.column <= inner.start.column))
        && (outer.end.line > inner.end.line
            || (outer.end.line == inner.end.line && outer.end.column >= inner.end.column))
}

fn unique_callable_ids(values: impl Iterator<Item = String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut unique: Vec<String> = values.filter(|value| seen.insert(value.clone())).collect();
    unique.sort();
    unique
}
