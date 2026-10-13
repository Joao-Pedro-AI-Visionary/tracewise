//! Port of `javascriptSemanticCalls.ts`: local call, argument/return/result flow, closure capture
//! and unsupported-frontier facts.

use std::collections::{HashMap, HashSet};

use crate::jsgraph::ast::{Kind, N};
use crate::jsgraph::ast_values::static_property_key;
use crate::jsgraph::ir::{
    SemanticArgumentFlow, SemanticCallArgument, SemanticCallResultFlow, SemanticCallReturnFlow, SemanticCallSite,
    SemanticCallable, SemanticClosureCapture, SemanticFrontier,
};

use super::call_resolution::{
    callable_by_id, parameter_bindings, resolve_local_callables, CallableById, LocalCallableResolution,
};
use super::data_effect_helpers::{ancestors_nearest_first, assigned_semantic_result_bindings};
use super::projection::{semantic_callable_id_for_node, semantic_reference_role};
use super::state::{is_unshadowed_global, resolve_semantic_binding_state, BindingIx, SemanticAnalysisState};
use super::traversal::{traverse_javascript_ast, AstVisitor};

/// `JavaScriptSemanticCallAnalysis`: local call, flow, capture, and unsupported-frontier facts.
#[derive(Clone, Debug, Default)]
pub struct CallAnalysis {
    pub call_sites: Vec<SemanticCallSite>,
    pub argument_flows: Vec<SemanticArgumentFlow>,
    pub call_return_flows: Vec<SemanticCallReturnFlow>,
    pub call_result_flows: Vec<SemanticCallResultFlow>,
    pub closure_captures: Vec<SemanticClosureCapture>,
    pub frontiers: Vec<SemanticFrontier>,
}

struct CallCollector<'c, 'a> {
    state: &'c SemanticAnalysisState<'a>,
    callables: &'c [SemanticCallable],
    by_id: CallableById,
    output: CallAnalysis,
    binding_resolution_cache: HashMap<BindingIx, LocalCallableResolution>,
    parameter_binding_cache: HashMap<(usize, usize), Vec<BindingIx>>,
    /// Indices into `callables` of the enclosing callables, innermost last.
    callable_stack: Vec<(usize, Option<usize>)>,
}

/// Recover direct-call and lexical-capture candidates from inert syntax
/// (`collectJavaScriptSemanticCalls`).
pub fn collect_semantic_calls<'a>(
    root: N<'a>,
    state: &SemanticAnalysisState<'a>,
    callables: &[SemanticCallable],
) -> CallAnalysis {
    let mut collector = CallCollector {
        state,
        callables,
        by_id: callable_by_id(callables),
        output: CallAnalysis::default(),
        binding_resolution_cache: HashMap::new(),
        parameter_binding_cache: HashMap::new(),
        callable_stack: Vec::new(),
    };
    traverse_javascript_ast(root, &mut collector);
    collector.output
}

impl<'a> AstVisitor<'a> for CallCollector<'_, 'a> {
    fn enter(&mut self, node: N<'a>, parent: Option<N<'a>>) {
        if let Some(id) = semantic_callable_id_for_node(node) {
            if let Some(&index) = self.by_id.get(&id) {
                let nearest = if self.callables[index].kind != "class" {
                    Some(index)
                } else {
                    self.callable_stack.last().and_then(|&(_, nearest)| nearest)
                };
                self.callable_stack.push((index, nearest));
            }
        }
        let owner = self.enclosing_function();
        self.collect_capture(node, parent, owner);
        self.collect_dynamic_property(node, owner);
        self.collect_dynamic_scope(node, owner);
        if node.is_call() || node.is(Kind::NewExpression) {
            self.collect_call_site(node, owner);
        }
    }

    fn exit(&mut self, node: N<'a>, _parent: Option<N<'a>>) {
        if let Some(id) = semantic_callable_id_for_node(node) {
            if let Some(&(top, _)) = self.callable_stack.last() {
                if self.callables[top].callable_id == id {
                    self.callable_stack.pop();
                }
            }
        }
    }
}

impl<'a> CallCollector<'_, 'a> {
    /// `stack.findLast(({ kind }) => kind !== "class")`.
    fn enclosing_function(&self) -> Option<usize> {
        self.callable_stack.last().and_then(|&(_, nearest)| nearest)
    }

    fn collect_call_site(&mut self, node: N<'a>, owner: Option<usize>) {
        let Some(callee) = node.f("callee") else { return };
        let resolution = resolve_local_callables(
            callee,
            self.state,
            &self.by_id,
            &HashSet::new(),
            &mut self.binding_resolution_cache,
        );
        let call_site_id = semantic_call_site_id(node);
        let arguments = retained_arguments(node);
        let exact = resolution.callable_ids.len() == 1 && resolution.complete;
        let site = SemanticCallSite {
            call_site_id,
            kind: if node.is(Kind::NewExpression) { "construct" } else { "call" }.into(),
            caller_callable_id: owner.map(|index| self.callables[index].callable_id.clone()),
            location: node.loc(),
            callee_location: callee.loc(),
            resolution: if exact {
                "exact"
            } else if !resolution.callable_ids.is_empty() {
                "ambiguous"
            } else {
                "unresolved"
            }
            .into(),
            callee_callable_ids: resolution.callable_ids.clone(),
            arguments,
        };
        self.collect_call_result_flow(&site, node);
        if site.resolution != "exact" {
            self.output.frontiers.push(SemanticFrontier {
                kind: "dynamic-call".into(),
                callable_id: owner.map(|index| self.callables[index].callable_id.clone()),
                location: callee.loc(),
                reason: resolution.reason.clone(),
            });
        }
        self.collect_argument_flows(&site, node);
        if site.kind == "call" {
            self.collect_return_flows(&site);
        }
        self.output.call_sites.push(site);
    }

    fn collect_call_result_flow(&mut self, site: &SemanticCallSite, node: N<'a>) {
        let assigned = assigned_semantic_result_bindings(node, ancestors_nearest_first(node), self.state);
        for assigned in assigned.iter().filter(|assigned| assigned.projection_path.is_empty()) {
            let Some(binding) = self.state.binding_by_id(&assigned.binding_id) else { continue };
            let identifier_range = assigned.identifier.loc();
            let Some(definition) =
                self.state.bindings[binding].definitions.iter().find(|definition| definition.location == identifier_range)
            else {
                continue;
            };
            self.output.call_result_flows.push(SemanticCallResultFlow {
                call_site_id: site.call_site_id.clone(),
                binding_id: self.state.bindings[binding].binding_id.clone(),
                definition_location: definition.location,
            });
        }
    }

    fn collect_argument_flows(&mut self, site: &SemanticCallSite, node: N<'a>) {
        let retained: HashSet<u64> = site.arguments.iter().map(|argument| argument.index).collect();
        let mut position_is_exact = true;
        for (index, argument) in node.list("arguments").into_iter().enumerate() {
            let Some(argument) = argument else { continue };
            if argument.is(Kind::SpreadElement) {
                position_is_exact = false;
                continue;
            }
            if !position_is_exact || !retained.contains(&(index as u64)) || !argument.is_expression() {
                continue;
            }
            for callable_id in &site.callee_callable_ids {
                let Some(&callable_index) = self.by_id.get(callable_id) else { continue };
                let parameters = self.cached_parameter_bindings(callable_index, index);
                for parameter in parameters {
                    let binding = &self.state.bindings[parameter];
                    let Some(definition) = binding.definitions.iter().find(|definition| definition.kind == "parameter")
                    else {
                        continue;
                    };
                    self.output.argument_flows.push(SemanticArgumentFlow {
                        call_site_id: site.call_site_id.clone(),
                        argument_index: index as u64,
                        argument_location: argument.loc(),
                        callable_id: callable_id.clone(),
                        parameter_binding_id: binding.binding_id.clone(),
                        parameter_location: definition.location,
                    });
                }
            }
        }
    }

    fn cached_parameter_bindings(&mut self, callable_index: usize, index: usize) -> Vec<BindingIx> {
        let key = (callable_index, index);
        if let Some(cached) = self.parameter_binding_cache.get(&key) {
            return cached.clone();
        }
        let bindings = parameter_bindings(&self.callables[callable_index], index, self.state);
        self.parameter_binding_cache.insert(key, bindings.clone());
        bindings
    }

    fn collect_return_flows(&mut self, site: &SemanticCallSite) {
        for callable_id in &site.callee_callable_ids {
            let Some(&callable_index) = self.by_id.get(callable_id) else { continue };
            for return_site in &self.callables[callable_index].return_sites {
                self.output.call_return_flows.push(SemanticCallReturnFlow {
                    call_site_id: site.call_site_id.clone(),
                    callable_id: callable_id.clone(),
                    return_site_id: return_site.return_site_id.clone(),
                    return_location: return_site.location,
                });
            }
        }
    }

    fn collect_capture(&mut self, node: N<'a>, parent: Option<N<'a>>, owner: Option<usize>) {
        let (Some(parent), Some(owner)) = (parent, owner) else { return };
        if !node.is_identifier() {
            return;
        }
        let owner = &self.callables[owner];
        let Some(body_scope_id) = &owner.body_scope_id else { return };
        if semantic_reference_role(node, parent).is_none() {
            return;
        }
        let Some(binding) = resolve_semantic_binding_state(self.state, node, node.name().unwrap_or("")) else {
            return;
        };
        if self.binding_is_within_callable(binding, body_scope_id) {
            return;
        }
        self.output.closure_captures.push(SemanticClosureCapture {
            callable_id: owner.callable_id.clone(),
            binding_id: self.state.bindings[binding].binding_id.clone(),
            reference_location: node.loc(),
        });
    }

    fn collect_dynamic_property(&mut self, node: N<'a>, owner: Option<usize>) {
        let callable_id = owner.map(|index| self.callables[index].callable_id.clone());
        if node.is_member() {
            let Some(property) = node.f("property") else { return };
            if static_property_key(property, node.flag("computed")).is_none() {
                self.output.frontiers.push(SemanticFrontier {
                    kind: "dynamic-property".into(),
                    callable_id,
                    location: property.loc(),
                    reason: "Computed member property is not a static string or number.".into(),
                });
            }
        } else if (node.is(Kind::ObjectProperty) || node.is(Kind::ObjectMethod)) && node.flag("computed") {
            let Some(key) = node.f("key") else { return };
            if static_property_key(key, true).is_none() {
                self.output.frontiers.push(SemanticFrontier {
                    kind: "dynamic-property".into(),
                    callable_id,
                    location: key.loc(),
                    reason: "Computed object property is not a static string or number.".into(),
                });
            }
        }
    }

    /// `with (o) { ... }` and `eval("...")` decide at runtime which bindings exist, so every name
    /// inside them is unresolvable statically.
    fn collect_dynamic_scope(&mut self, node: N<'a>, owner: Option<usize>) {
        let reason = if node.is(Kind::WithStatement) {
            "`with` introduces a runtime binding environment; names inside are not statically resolvable."
        } else if node.is(Kind::CallExpression)
            && node.f("callee").is_some_and(|callee| is_unshadowed_global(callee, self.state, "eval"))
        {
            "`eval` can declare bindings at runtime; names inside the evaluated source are not statically resolvable."
        } else {
            return;
        };
        self.output.frontiers.push(SemanticFrontier {
            kind: "dynamic-scope".into(),
            callable_id: owner.map(|index| self.callables[index].callable_id.clone()),
            location: node.loc(),
            reason: reason.into(),
        });
    }

    fn binding_is_within_callable(&self, binding: BindingIx, body_scope_id: &str) -> bool {
        let mut scope = self.state.scope_by_id(&self.state.bindings[binding].scope_id);
        while let Some(ix) = scope {
            let current = &self.state.scopes[ix];
            if current.scope_id == body_scope_id {
                return true;
            }
            scope = current.parent_scope_id.as_ref().and_then(|id| self.state.scope_by_id(id));
        }
        false
    }
}

/// Keep argument positions with a node; Babel recovery can leave null slots.
fn retained_arguments(node: N<'_>) -> Vec<SemanticCallArgument> {
    node.list("arguments")
        .into_iter()
        .enumerate()
        .filter_map(|(index, argument)| {
            let argument = argument?;
            Some(SemanticCallArgument {
                index: index as u64,
                location: argument.loc(),
                spread: argument.is(Kind::SpreadElement),
            })
        })
        .collect()
}

fn semantic_call_site_id(node: N<'_>) -> String {
    format!(
        "call:{}:{}:{}",
        if node.is(Kind::NewExpression) { "construct" } else { "call" },
        node.start(),
        node.end()
    )
}
