//! Port of `javascriptSemanticDataEffectHelpers.ts`: result-binding projection, built-in method
//! resolution and the shared callable-aware traversal used by the derived collectors.

use std::collections::HashSet;

use crate::jsgraph::ast::{Kind, N};
use crate::jsgraph::ast_values::{read_exact_literal, static_property_key, static_property_name, unwrap_expression};
use crate::jsgraph::ir::{Primitive, ProjectedResultBinding, ProjectionKey};

use super::projection::semantic_callable_id_for_node;
use super::provenance::semantic_builtin_namespace_path;
use super::state::{resolve_semantic_binding_state, semantic_resolution_blocked, SemanticAnalysisState};
use super::traversal::{traverse_javascript_ast, AstVisitor};

/// `SemanticProjectedBinding`: one identifier written by the nearest variable/assignment owner.
#[derive(Clone, Debug)]
pub struct ProjectedBinding<'a> {
    pub binding_id: String,
    pub identifier: N<'a>,
    pub projection_path: Vec<Option<ProjectionKey>>,
    /// `complete` or `partial`.
    pub resolution: &'static str,
}

/// Proper ancestors of `node`, nearest first (REA's `ancestors` stack read from the end).
pub fn ancestors_nearest_first<'a>(node: N<'a>) -> impl Iterator<Item = N<'a>> {
    std::iter::successors(node.parent(), |ancestor| ancestor.parent())
}

/// Resolve bindings written by the nearest variable or assignment owner
/// (`assignedSemanticResultBindings`). `ancestors` run nearest first.
pub fn assigned_semantic_result_bindings<'a>(
    node: N<'a>,
    ancestors: impl Iterator<Item = N<'a>>,
    state: &SemanticAnalysisState<'a>,
) -> Vec<ProjectedBinding<'a>> {
    for owner in ancestors {
        let mut pattern: Option<N<'a>> = None;
        let mut source: Option<N<'a>> = None;
        if owner.is(Kind::VariableDeclarator) {
            pattern = owner.f("id");
            source = owner.f("init");
        } else if owner.is(Kind::AssignmentExpression) {
            pattern = owner.f("left");
            source = owner.f("right");
        }
        if let (Some(pattern), Some(source)) = (pattern, source) {
            if assigned_source_is(node, source) {
                return projected_pattern_bindings(pattern, state);
            }
        }
        if semantic_callable_id_for_node(owner).is_some() {
            return Vec::new();
        }
    }
    Vec::new()
}

fn assigned_source_is(node: N<'_>, source: N<'_>) -> bool {
    let mut value = source;
    loop {
        if value.is(Kind::AwaitExpression) {
            match value.f("argument") {
                Some(argument) => value = argument,
                None => break,
            }
        } else {
            let unwrapped = unwrap_expression(value).0;
            if unwrapped == value {
                break;
            }
            value = unwrapped;
        }
    }
    value == node
}

fn projected_pattern_bindings<'a>(pattern: N<'a>, state: &SemanticAnalysisState<'a>) -> Vec<ProjectedBinding<'a>> {
    let mut output = Vec::new();
    visit_pattern(pattern, &[], false, state, &mut output);
    output
}

fn visit_pattern<'a>(
    current: N<'a>,
    path: &[Option<ProjectionKey>],
    partial: bool,
    state: &SemanticAnalysisState<'a>,
    output: &mut Vec<ProjectedBinding<'a>>,
) {
    match current.kind() {
        Kind::Identifier => {
            let name = current.name().unwrap_or("");
            if let Some(binding) = resolve_semantic_binding_state(state, current, name) {
                output.push(ProjectedBinding {
                    binding_id: state.bindings[binding].binding_id.clone(),
                    identifier: current,
                    projection_path: path.to_vec(),
                    resolution: if partial { "partial" } else { "complete" },
                });
            }
        }
        Kind::AssignmentPattern => {
            if let Some(left) = current.f("left") {
                visit_pattern(left, path, true, state, output);
            }
        }
        Kind::RestElement => {
            if let Some(argument) = current.f("argument") {
                let mut next = path.to_vec();
                next.push(None);
                visit_pattern(argument, &next, true, state, output);
            }
        }
        Kind::ObjectPattern => {
            for property in current.nodes("properties") {
                if property.is(Kind::RestElement) {
                    if let Some(argument) = property.f("argument") {
                        let mut next = path.to_vec();
                        next.push(None);
                        visit_pattern(argument, &next, true, state, output);
                    }
                } else if let Some(value) = property.f("value") {
                    let key = property
                        .f("key")
                        .and_then(|key| static_property_key(key, property.flag("computed")));
                    let mut next = path.to_vec();
                    let dynamic = key.is_none();
                    next.push(key.map(ProjectionKey::Name));
                    visit_pattern(value, &next, partial || dynamic, state, output);
                }
            }
        }
        Kind::ArrayPattern => {
            for (index, element) in current.list("elements").into_iter().enumerate() {
                if let Some(element) = element {
                    let mut next = path.to_vec();
                    next.push(Some(ProjectionKey::Index(index as u64)));
                    visit_pattern(element, &next, partial, state, output);
                }
            }
        }
        _ => {}
    }
}

/// `semanticProjectedBindingFacts`: drop the identifier from each fact.
pub fn projected_binding_facts(bindings: &[&ProjectedBinding<'_>]) -> Vec<ProjectedResultBinding> {
    bindings
        .iter()
        .map(|binding| ProjectedResultBinding {
            binding_id: binding.binding_id.clone(),
            projection_path: binding.projection_path.clone(),
            resolution: binding.resolution.to_string(),
        })
        .collect()
}

/// The facts of every projected (non-empty path) binding, as the collectors retain them.
pub fn projected_result_facts(bindings: &[ProjectedBinding<'_>]) -> Vec<ProjectedResultBinding> {
    let projected: Vec<&ProjectedBinding<'_>> =
        bindings.iter().filter(|binding| !binding.projection_path.is_empty()).collect();
    projected_binding_facts(&projected)
}

/// Return a scalar owner only for an unprojected identifier result (`scalarAssignedResultBinding`).
pub fn scalar_assigned_result_binding(bindings: &[ProjectedBinding<'_>]) -> Option<String> {
    if bindings.len() == 1 && bindings[0].projection_path.is_empty() {
        Some(bindings[0].binding_id.clone())
    } else {
        None
    }
}

/// Resolve a direct or namespace-imported built-in method (`builtinDataEffectMethod`).
pub fn builtin_data_effect_method<'a>(
    callee: N<'a>,
    state: &SemanticAnalysisState<'a>,
    specifiers: &[&str],
) -> Option<String> {
    if callee.is_identifier() {
        let binding = resolve_semantic_binding_state(state, callee, callee.name().unwrap_or(""));
        return module_method(state, binding, specifiers);
    }
    if !callee.is_member() {
        return None;
    }
    let object = callee.f("object")?;
    if !object.is_identifier() {
        return None;
    }
    let binding = resolve_semantic_binding_state(state, object, object.name().unwrap_or(""));
    let namespace = binding.is_some_and(|binding| {
        state.bindings[binding].direct_origins.iter().any(|origin| {
            specifiers.contains(&origin.specifier.as_str()) && semantic_builtin_namespace_path(&origin.imported_path)
        })
    });
    if namespace {
        Some(static_property_name(callee.f("property")?, callee.flag("computed")))
    } else {
        None
    }
}

fn module_method(
    state: &SemanticAnalysisState<'_>,
    binding: Option<usize>,
    specifiers: &[&str],
) -> Option<String> {
    let binding = binding?;
    for origin in &state.bindings[binding].direct_origins {
        if !specifiers.contains(&origin.specifier.as_str()) {
            continue;
        }
        return origin.imported_path.last().cloned();
    }
    None
}

/// Recognize global or `node:process` aliases without accepting shadowing (`isSemanticProcessObject`).
pub fn is_semantic_process_object<'a>(node: N<'a>, state: &SemanticAnalysisState<'a>) -> bool {
    if !node.is_identifier() {
        return false;
    }
    let name = node.name().unwrap_or("");
    match resolve_semantic_binding_state(state, node, name) {
        None => name == "process" && !semantic_resolution_blocked(state, node, name),
        Some(binding) => state.bindings[binding]
            .direct_origins
            .iter()
            .any(|origin| origin.specifier == "process" || origin.specifier == "node:process"),
    }
}

/// Resolve the nearest direct variable/assignment owner before a callable (`outerDataEffectBinding`).
pub fn outer_data_effect_binding<'a>(node: N<'a>, state: &SemanticAnalysisState<'a>) -> Option<String> {
    scalar_assigned_result_binding(&assigned_semantic_result_bindings(node, ancestors_nearest_first(node), state))
}

/// Exact callable stack shared by the collectors: push on entering an admitted callable, pop on
/// leaving it (`callableStack` handling in every `traverse*` of the TS collectors).
pub struct CallableStack<'s> {
    admitted: Option<&'s HashSet<String>>,
    stack: Vec<String>,
}

impl<'s> CallableStack<'s> {
    /// A stack admitting only `admitted` callable ids (`None` admits every callable node).
    pub fn new(admitted: Option<&'s HashSet<String>>) -> Self {
        CallableStack { admitted, stack: Vec::new() }
    }

    pub fn enter(&mut self, node: N<'_>) {
        if let Some(id) = semantic_callable_id_for_node(node) {
            if self.admitted.is_none_or(|set| set.contains(&id)) {
                self.stack.push(id);
            }
        }
    }

    pub fn exit(&mut self, node: N<'_>) {
        if let Some(id) = semantic_callable_id_for_node(node) {
            if self.stack.last() == Some(&id) {
                self.stack.pop();
            }
        }
    }

    pub fn top(&self) -> Option<&str> {
        self.stack.last().map(String::as_str)
    }

    pub fn top_owned(&self) -> Option<String> {
        self.stack.last().cloned()
    }
}

struct DataEffectVisitor<'s, F> {
    callables: CallableStack<'s>,
    visit: F,
}

impl<'a, 's, F: FnMut(N<'a>, Option<N<'a>>, Option<&str>)> AstVisitor<'a> for DataEffectVisitor<'s, F> {
    fn enter(&mut self, node: N<'a>, parent: Option<N<'a>>) {
        self.callables.enter(node);
        (self.visit)(node, parent, self.callables.top());
    }

    fn exit(&mut self, node: N<'a>, _parent: Option<N<'a>>) {
        self.callables.exit(node);
    }
}

/// Traverse with an exact callable stack (`traverseDataEffects`). `visit` receives the node, its
/// parent and the id of the innermost admitted callable.
pub fn traverse_data_effects<'a>(
    root: N<'a>,
    callable_ids: &HashSet<String>,
    visit: impl FnMut(N<'a>, Option<N<'a>>, Option<&str>),
) {
    let mut visitor = DataEffectVisitor { callables: CallableStack::new(Some(callable_ids)), visit };
    traverse_javascript_ast(root, &mut visitor);
}

/// Resolve one direct identifier argument to a lexical binding (`dataEffectArgumentBindingId`).
pub fn data_effect_argument_binding_id<'a>(node: Option<N<'a>>, state: &SemanticAnalysisState<'a>) -> Option<String> {
    let node = node?;
    if !node.is_identifier() {
        return None;
    }
    resolve_semantic_binding_state(state, node, node.name().unwrap_or(""))
        .map(|binding| state.bindings[binding].binding_id.clone())
}

/// Read one JSON primitive default without evaluating code (`dataEffectPrimitive`).
pub fn data_effect_primitive(node: N<'_>) -> Option<Primitive> {
    match node.kind() {
        Kind::StringLiteral => Some(Primitive::Str(node.str("value").unwrap_or("").to_string())),
        Kind::NumericLiteral => Some(Primitive::Num(crate::jsgraph::ir::JsNumber(node.num("value").unwrap_or(f64::NAN)))),
        Kind::BooleanLiteral => Some(Primitive::Bool(node.flag("value"))),
        _ => None,
    }
}

/// Read one static string or expression-free template (`dataEffectLiteralString`).
pub fn data_effect_literal_string(node: Option<N<'_>>) -> Option<String> {
    let node = node?;
    if let Some(Primitive::Str(text)) = read_exact_literal(node) {
        return Some(text);
    }
    if node.is(Kind::TemplateLiteral) && node.list_len("expressions") == 0 {
        return node.nodes("quasis").first().and_then(|quasi| quasi.str("raw")).map(String::from);
    }
    None
}

/// Read a member callee from call or construction syntax (`dataEffectMemberCallee`).
pub fn data_effect_member_callee<'a>(node: N<'a>) -> Option<N<'a>> {
    node.f("callee").filter(|callee| callee.is_member())
}

/// Read a parent member's object when present (`dataEffectMemberObject`).
pub fn data_effect_member_object<'a>(node: Option<N<'a>>) -> Option<N<'a>> {
    node.filter(|node| node.is_member()).and_then(|node| node.f("object"))
}
