//! Port of `javascriptSemanticReturns.ts`: direct return sites and module-link callable
//! resolution. (`flattenSemanticReturnValue`, the export-shape projection helper, belongs to the
//! graph layer.)

use std::collections::HashSet;

use crate::jsgraph::ast::N;
use crate::jsgraph::ast_values::unwrap_expression;
use crate::jsgraph::ir::{SemanticCallable, SemanticModuleLink, SemanticReturnSite, SourceRange};

use super::callable_results::{semantic_callable_result_expressions, CallableResultKind};
use super::coverage::semantic_return_coverage;
use super::projection::semantic_callable_id_for_node;
use super::state::{resolve_semantic_binding_state, BindingIx, SemanticAnalysisState};
use super::value_types::unknown;
use super::values::evaluate_semantic_expression;

/// Evaluate direct returns while excluding every nested callable.
pub fn collect_semantic_returns(state: &SemanticAnalysisState<'_>, parser_partial: bool) -> Vec<SemanticCallable> {
    state
        .callables
        .iter()
        .map(|callable| {
            let Some(&node) = state.callable_nodes_by_id.get(&callable.callable_id) else {
                return SemanticCallable {
                    return_coverage: crate::jsgraph::ir::ReturnCoverage {
                        status: "partial".into(),
                        retained_count: 0,
                        omitted_count: None,
                    },
                    ..callable.clone()
                };
            };
            let mut sites: Vec<SemanticReturnSite> = Vec::new();
            for expression in semantic_callable_result_expressions(node) {
                if expression.kind != CallableResultKind::Return {
                    continue;
                }
                let location = expression.site.loc();
                sites.push(SemanticReturnSite {
                    return_site_id: semantic_return_site_id(&callable.callable_id, &location),
                    location,
                    identity_reference_location: expression
                        .node
                        .filter(|n| n.is_identifier())
                        .map(|n| n.loc()),
                    value: match expression.node {
                        None => unknown("Return has no value."),
                        Some(result) => evaluate_semantic_expression(state, result, None),
                    },
                });
            }
            SemanticCallable {
                return_coverage: semantic_return_coverage(sites.len() as u64, parser_partial),
                return_sites: sites,
                ..callable.clone()
            }
        })
        .collect()
}

fn semantic_return_site_id(callable_id: &str, location: &SourceRange) -> String {
    format!(
        "{callable_id}:return:{}:{}:{}:{}",
        location.start.line, location.start.column, location.end.line, location.end.column
    )
}

/// Link exports to callables only when lexical resolution is unique and exact.
pub fn resolve_semantic_module_callables(
    state: &SemanticAnalysisState<'_>,
    callables: &[SemanticCallable],
) -> Vec<SemanticModuleLink> {
    let callable_ids: HashSet<&str> = callables.iter().map(|c| c.callable_id.as_str()).collect();
    state
        .module_links
        .iter()
        .enumerate()
        .map(|(index, link)| {
            // Named exports follow their lexical binding, including every assignment. A
            // declaration's ID or a callable's display name cannot prove that link.
            if link.local_name.is_none() {
                return if link.callable_id.as_deref().is_some_and(|id| callable_ids.contains(id)) {
                    link.clone()
                } else {
                    SemanticModuleLink { callable_id: None, ..link.clone() }
                };
            }
            let resolved = match state.module_link_bindings.get(&index) {
                None => Vec::new(),
                Some(&binding) => callable_ids_for_binding(binding, state, &callable_ids, &[]),
            };
            SemanticModuleLink {
                callable_id: if resolved.len() == 1 { Some(resolved[0].clone()) } else { None },
                ..link.clone()
            }
        })
        .collect()
}

fn callable_ids_for_binding(
    binding_ix: BindingIx,
    state: &SemanticAnalysisState<'_>,
    admitted: &HashSet<&str>,
    seen: &[BindingIx],
) -> Vec<String> {
    let binding = &state.bindings[binding_ix];
    // A single initializer does not prove an assignment executes or replace the unknown incoming
    // value of a parameter/catch binding.
    if seen.contains(&binding_ix)
        || binding.initializers.len() != 1
        || binding
            .definitions
            .iter()
            .any(|definition| matches!(definition.kind.as_str(), "assignment" | "parameter" | "catch"))
    {
        return Vec::new();
    }
    let initializer = &binding.initializers[0];
    if !initializer.projection.is_empty() || state.conditional_initializers.contains(&initializer.node.id) {
        return Vec::new();
    }
    let mut next_seen = seen.to_vec();
    next_seen.push(binding_ix);
    callable_ids_for_node(initializer.node, state, admitted, &next_seen)
}

fn callable_ids_for_node<'a>(
    node: N<'a>,
    state: &SemanticAnalysisState<'a>,
    admitted: &HashSet<&str>,
    seen: &[BindingIx],
) -> Vec<String> {
    let unwrapped = unwrap_expression(node).0;
    if unwrapped != node {
        return callable_ids_for_node(unwrapped, state, admitted, seen);
    }
    if let Some(direct) = semantic_callable_id_for_node(node) {
        if admitted.contains(direct.as_str()) {
            return vec![direct];
        }
    }
    if node.is_identifier() {
        let name = node.name().unwrap_or("");
        return match resolve_semantic_binding_state(state, node, name) {
            None => Vec::new(),
            Some(binding) => callable_ids_for_binding(binding, state, admitted, seen),
        };
    }
    Vec::new()
}
