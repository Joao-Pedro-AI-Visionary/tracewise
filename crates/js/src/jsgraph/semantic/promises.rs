//! Port of `javascriptSemanticPromises.ts`: explicit Promise construction, chaining, aggregation
//! and ownership.

use std::collections::{HashMap, HashSet};

use crate::jsgraph::ast::{Kind, NodeId, N};
use crate::jsgraph::ast_values::{static_property_name, unwrap_expression};
use crate::jsgraph::ir::{SemanticCallable, SemanticPromiseOperation, SourceRange};
use crate::jsgraph::util::compare_code_points;

use super::data_effect_helpers::{
    assigned_semantic_result_bindings, data_effect_member_callee, scalar_assigned_result_binding,
    traverse_data_effects,
};
use super::projection::semantic_callable_id_for_node;
use super::state::{is_unshadowed_global, resolve_semantic_binding_state, SemanticAnalysisState};

struct PromiseCandidate<'a> {
    node: N<'a>,
    kind: &'static str,
    method: &'static str,
    promise_id: String,
    owner_callable_id: Option<String>,
}

struct PromiseResolution {
    promise_ids: Vec<String>,
    /// `complete`, `partial`, `unresolved`.
    status: &'static str,
}

struct PromiseOwnership {
    ownership: &'static str,
    owner_binding_id: Option<String>,
    return_site_id: Option<String>,
}

enum OwnershipStep {
    Found(PromiseOwnership),
    Boundary,
    Continue,
}

/// `createReturnSiteLookup`: return-site ids by callable and exact location (first wins).
struct ReturnSiteLookup<'c> {
    callables: &'c [SemanticCallable],
    callable_index: Option<HashMap<&'c str, usize>>,
    sites: HashMap<usize, HashMap<SourceRange, String>>,
}

impl<'c> ReturnSiteLookup<'c> {
    fn new(callables: &'c [SemanticCallable]) -> Self {
        ReturnSiteLookup { callables, callable_index: None, sites: HashMap::new() }
    }

    fn get(&mut self, callable_id: Option<&str>, location: &SourceRange) -> Option<String> {
        let callable_id = callable_id?;
        let callables = self.callables;
        let index = self.callable_index.get_or_insert_with(|| {
            let mut map = HashMap::new();
            for (position, callable) in callables.iter().enumerate() {
                map.entry(callable.callable_id.as_str()).or_insert(position);
            }
            map
        });
        let position = *index.get(callable_id)?;
        let sites = self.sites.entry(position).or_insert_with(|| {
            let mut map = HashMap::new();
            for site in &callables[position].return_sites {
                map.entry(site.location).or_insert_with(|| site.return_site_id.clone());
            }
            map
        });
        sites.get(location).cloned()
    }
}

/// Recover explicit Promise construction, chaining, aggregation, and ownership
/// (`collectJavaScriptSemanticPromises`).
pub fn collect_semantic_promises<'a>(
    root: N<'a>,
    state: &SemanticAnalysisState<'a>,
    callables: &[SemanticCallable],
) -> Vec<SemanticPromiseOperation> {
    let candidates = collect_candidates(root, state, callables);
    let mut return_sites = ReturnSiteLookup::new(callables);
    let candidate_by_node: HashMap<NodeId, usize> =
        candidates.iter().enumerate().map(|(index, candidate)| (candidate.node.id, index)).collect();
    candidates
        .iter()
        .map(|candidate| {
            let ownership = promise_ownership(candidate, &candidates, &candidate_by_node, state, &mut return_sites);
            let sources = promise_sources(candidate, &candidates, &candidate_by_node, state);
            let mut seen = HashSet::new();
            let mut source_ids: Vec<String> =
                sources.promise_ids.into_iter().filter(|id| seen.insert(id.clone())).collect();
            source_ids.sort_by(|left, right| compare_code_points(left, right));
            SemanticPromiseOperation {
                promise_id: candidate.promise_id.clone(),
                kind: candidate.kind.into(),
                method: candidate.method.into(),
                location: candidate.node.loc(),
                owner_callable_id: candidate.owner_callable_id.clone(),
                ownership: ownership.ownership.into(),
                owner_binding_id: ownership.owner_binding_id,
                return_site_id: ownership.return_site_id,
                source_promise_ids: source_ids,
                source_resolution: sources.status.into(),
            }
        })
        .collect()
}

fn collect_candidates<'a>(
    root: N<'a>,
    state: &SemanticAnalysisState<'a>,
    callables: &[SemanticCallable],
) -> Vec<PromiseCandidate<'a>> {
    let mut output = Vec::new();
    let admitted: HashSet<String> = callables.iter().map(|callable| callable.callable_id.clone()).collect();
    traverse_data_effects(root, &admitted, |node, _parent, owner| {
        if let Some((kind, method)) = promise_candidate_details(node, state) {
            output.push(PromiseCandidate {
                node,
                kind,
                method,
                promise_id: format!("promise:{kind}:{}:{}", node.start(), node.end()),
                owner_callable_id: owner.map(String::from),
            });
        }
    });
    output
}

fn promise_candidate_details<'a>(
    node: N<'a>,
    state: &SemanticAnalysisState<'a>,
) -> Option<(&'static str, &'static str)> {
    if node.is(Kind::NewExpression) {
        let callee = node.f("callee")?;
        if callee.is_identifier() && callee.name() == Some("Promise") && is_unshadowed_global(callee, state, "Promise") {
            return Some(("constructor", "new"));
        }
    }
    if node.is_call() {
        let member = data_effect_member_callee(node)?;
        let method = static_property_name(member.f("property")?, member.flag("computed"));
        let object = member.f("object");
        if let Some(object) = object {
            if object.is_identifier() && object.name() == Some("Promise") && is_unshadowed_global(object, state, "Promise") {
                match method.as_str() {
                    "all" => return Some(("aggregate", "all")),
                    "allSettled" => return Some(("aggregate", "allSettled")),
                    "resolve" => return Some(("static", "resolve")),
                    "reject" => return Some(("static", "reject")),
                    _ => {}
                }
            }
        }
        match method.as_str() {
            "then" => return Some(("chain", "then")),
            "catch" => return Some(("chain", "catch")),
            "finally" => return Some(("chain", "finally")),
            _ => {}
        }
    }
    if node.is(Kind::AwaitExpression) && !node.f("argument").is_some_and(|argument| is_promise_producer(argument, state)) {
        return Some(("awaited-expression", "await"));
    }
    None
}

fn is_promise_producer<'a>(node: N<'a>, state: &SemanticAnalysisState<'a>) -> bool {
    promise_candidate_details(unwrap_expression(node).0, state).is_some()
}

fn empty_ownership(ownership: &'static str) -> PromiseOwnership {
    PromiseOwnership { ownership, owner_binding_id: None, return_site_id: None }
}

fn promise_ownership<'a>(
    candidate: &PromiseCandidate<'a>,
    candidates: &[PromiseCandidate<'a>],
    candidate_by_node: &HashMap<NodeId, usize>,
    state: &SemanticAnalysisState<'a>,
    return_sites: &mut ReturnSiteLookup<'_>,
) -> PromiseOwnership {
    if candidate.kind == "awaited-expression" {
        return empty_ownership("awaited");
    }
    let mut ancestor = candidate.node.parent();
    while let Some(current) = ancestor {
        match ownership_at_ancestor(current, candidate, candidates, candidate_by_node, state, return_sites) {
            OwnershipStep::Boundary => break,
            OwnershipStep::Found(ownership) => return ownership,
            OwnershipStep::Continue => {}
        }
        ancestor = current.parent();
    }
    empty_ownership("unknown")
}

fn ownership_at_ancestor<'a>(
    ancestor: N<'a>,
    candidate: &PromiseCandidate<'a>,
    candidates: &[PromiseCandidate<'a>],
    candidate_by_node: &HashMap<NodeId, usize>,
    state: &SemanticAnalysisState<'a>,
    return_sites: &mut ReturnSiteLookup<'_>,
) -> OwnershipStep {
    if ancestor.is(Kind::AwaitExpression) {
        return if ancestor.f("argument").is_some_and(|argument| unwrap_expression(argument).0 == candidate.node) {
            OwnershipStep::Found(empty_ownership("awaited"))
        } else {
            OwnershipStep::Boundary
        };
    }
    let outer = candidate_by_node.get(&ancestor.id).map(|&index| &candidates[index]);
    if let Some(outer) = outer {
        if outer.owner_callable_id == candidate.owner_callable_id && outer_consumes_candidate(outer, candidate) {
            return OwnershipStep::Found(empty_ownership(if outer.kind == "chain" { "chained" } else { "aggregated" }));
        }
    }
    if outer.is_none() && (ancestor.is_call() || ancestor.is(Kind::NewExpression)) {
        return OwnershipStep::Boundary;
    }
    if let Some(assigned) = assigned_promise_binding(ancestor, candidate.node, state) {
        return OwnershipStep::Found(PromiseOwnership {
            ownership: "assigned",
            owner_binding_id: assigned,
            return_site_id: None,
        });
    }
    if ancestor.is(Kind::ReturnStatement) {
        let matches = ancestor
            .f("argument")
            .is_some_and(|argument| unwrap_expression(argument).0 == candidate.node);
        if !matches {
            return OwnershipStep::Boundary;
        }
        return OwnershipStep::Found(returned_promise_ownership(
            candidate.owner_callable_id.as_deref(),
            &ancestor.loc(),
            return_sites,
        ));
    }
    if ancestor.is(Kind::ExpressionStatement) {
        return if ancestor.f("expression").is_some_and(|expression| unwrap_expression(expression).0 == candidate.node) {
            OwnershipStep::Found(empty_ownership("detached"))
        } else {
            OwnershipStep::Boundary
        };
    }
    let Some(callable_id) = semantic_callable_id_for_node(ancestor) else { return OwnershipStep::Continue };
    if candidate.owner_callable_id.as_deref() != Some(callable_id.as_str()) {
        return OwnershipStep::Continue;
    }
    if ancestor.is(Kind::ArrowFunctionExpression) {
        if let Some(body) = ancestor.f("body") {
            if unwrap_expression(body).0 == candidate.node {
                return OwnershipStep::Found(returned_promise_ownership(
                    candidate.owner_callable_id.as_deref(),
                    &body.loc(),
                    return_sites,
                ));
            }
        }
    }
    OwnershipStep::Boundary
}

/// `assignedPromiseBinding`: `None` is `undefined`; `Some(None)` is `null`.
fn assigned_promise_binding<'a>(
    ancestor: N<'a>,
    candidate: N<'a>,
    state: &SemanticAnalysisState<'a>,
) -> Option<Option<String>> {
    let declarator = ancestor.is(Kind::VariableDeclarator);
    if !declarator && !ancestor.is(Kind::AssignmentExpression) {
        return None;
    }
    let source = if declarator { ancestor.f("init") } else { ancestor.f("right") }?;
    if unwrap_expression(source).0 != candidate {
        return None;
    }
    Some(scalar_assigned_result_binding(&assigned_semantic_result_bindings(
        source,
        std::iter::once(ancestor),
        state,
    )))
}

fn returned_promise_ownership(
    callable_id: Option<&str>,
    location: &SourceRange,
    return_sites: &mut ReturnSiteLookup<'_>,
) -> PromiseOwnership {
    PromiseOwnership {
        ownership: "returned",
        owner_binding_id: None,
        return_site_id: return_sites.get(callable_id, location),
    }
}

fn outer_consumes_candidate<'a>(outer: &PromiseCandidate<'a>, candidate: &PromiseCandidate<'a>) -> bool {
    if outer.kind == "chain" && outer.node.is_call() {
        return data_effect_member_callee(outer.node)
            .and_then(|member| member.f("object"))
            .is_some_and(|object| unwrap_expression(object).0 == candidate.node);
    }
    if outer.kind == "aggregate" && outer.node.is_call() {
        let input = outer.node.list("arguments").into_iter().next().flatten();
        return input.is_some_and(|input| {
            input.is(Kind::ArrayExpression)
                && input.list("elements").into_iter().any(|element| {
                    element.is_some_and(|element| {
                        !element.is(Kind::SpreadElement) && unwrap_expression(element).0 == candidate.node
                    })
                })
        });
    }
    false
}

fn promise_sources<'a>(
    candidate: &PromiseCandidate<'a>,
    candidates: &[PromiseCandidate<'a>],
    candidate_by_node: &HashMap<NodeId, usize>,
    state: &SemanticAnalysisState<'a>,
) -> PromiseResolution {
    let seen = HashSet::new();
    match candidate.kind {
        "chain" => {
            let member = if candidate.node.is_call() { data_effect_member_callee(candidate.node) } else { None };
            match member.and_then(|member| member.f("object")) {
                None => unresolved_promise(),
                Some(object) => resolve_promise_expression(object, candidate, candidates, candidate_by_node, state, &seen),
            }
        }
        "aggregate" => aggregate_sources(candidate, candidates, candidate_by_node, state),
        "awaited-expression" => match candidate.node.f("argument") {
            Some(argument) if candidate.node.is(Kind::AwaitExpression) => {
                resolve_promise_expression(argument, candidate, candidates, candidate_by_node, state, &seen)
            }
            _ => unresolved_promise(),
        },
        _ => PromiseResolution { promise_ids: Vec::new(), status: "complete" },
    }
}

fn aggregate_sources<'a>(
    candidate: &PromiseCandidate<'a>,
    candidates: &[PromiseCandidate<'a>],
    candidate_by_node: &HashMap<NodeId, usize>,
    state: &SemanticAnalysisState<'a>,
) -> PromiseResolution {
    if !candidate.node.is_call() {
        return unresolved_promise();
    }
    let Some(input) = candidate.node.list("arguments").into_iter().next().flatten() else {
        return unresolved_promise();
    };
    if !input.is(Kind::ArrayExpression) {
        return unresolved_promise();
    }
    let seen = HashSet::new();
    let resolutions: Vec<PromiseResolution> = input
        .list("elements")
        .into_iter()
        .map(|element| match element {
            None => complete_promise(),
            Some(element) if element.is(Kind::SpreadElement) => unresolved_promise(),
            Some(element) if is_obviously_non_promise(element) => complete_promise(),
            Some(element) => resolve_promise_expression(element, candidate, candidates, candidate_by_node, state, &seen),
        })
        .collect();
    combine_promise_resolutions(resolutions)
}

fn resolve_promise_expression<'a>(
    raw: N<'a>,
    current: &PromiseCandidate<'a>,
    candidates: &[PromiseCandidate<'a>],
    candidate_by_node: &HashMap<NodeId, usize>,
    state: &SemanticAnalysisState<'a>,
    seen_bindings: &HashSet<String>,
) -> PromiseResolution {
    let node = unwrap_expression(raw).0;
    if let Some(&index) = candidate_by_node.get(&node.id) {
        let direct = &candidates[index];
        if direct.promise_id != current.promise_id {
            return PromiseResolution { promise_ids: vec![direct.promise_id.clone()], status: "complete" };
        }
    }
    if !node.is_identifier() {
        return unresolved_promise();
    }
    let Some(binding) = resolve_semantic_binding_state(state, node, node.name().unwrap_or("")) else {
        return unresolved_promise();
    };
    let binding = &state.bindings[binding];
    if binding.mutable || binding.initializers.len() != 1 || seen_bindings.contains(&binding.binding_id) {
        return unresolved_promise();
    }
    let initializer = &binding.initializers[0];
    if !initializer.projection.is_empty() {
        return unresolved_promise();
    }
    let mut nested = seen_bindings.clone();
    nested.insert(binding.binding_id.clone());
    resolve_promise_expression(initializer.node, current, candidates, candidate_by_node, state, &nested)
}

fn combine_promise_resolutions(resolutions: Vec<PromiseResolution>) -> PromiseResolution {
    let any_unresolved = resolutions.iter().any(|resolution| resolution.status == "unresolved");
    let any_complete = resolutions.iter().any(|resolution| resolution.status == "complete");
    let any_partial = resolutions.iter().any(|resolution| resolution.status == "partial");
    let status = if any_unresolved {
        if any_complete {
            "partial"
        } else {
            "unresolved"
        }
    } else if any_partial {
        "partial"
    } else {
        "complete"
    };
    PromiseResolution { promise_ids: resolutions.into_iter().flat_map(|r| r.promise_ids).collect(), status }
}

fn complete_promise() -> PromiseResolution {
    PromiseResolution { promise_ids: Vec::new(), status: "complete" }
}

fn unresolved_promise() -> PromiseResolution {
    PromiseResolution { promise_ids: Vec::new(), status: "unresolved" }
}

fn is_obviously_non_promise(node: N<'_>) -> bool {
    use crate::jsgraph::ast::Alias;
    node.has_alias(Alias::Literal)
        || node.is(Kind::ObjectExpression)
        || node.has_alias(Alias::Function)
        || node.is(Kind::ClassExpression)
}
