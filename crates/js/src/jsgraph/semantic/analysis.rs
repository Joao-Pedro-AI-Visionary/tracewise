//! Port of `javascriptSemanticAnalysis.ts`: lexical definitions (`collectDefinitions`,
//! `bindPattern`, scopes), the full semantic analysis, and the open-receiver / Electron-binding
//! classifiers.

use std::collections::HashMap;

use crate::jsgraph::ast::{Alias, Ast, Kind, NodeId, N};
use crate::jsgraph::ast_values::{object_pattern_keys, property_name, static_property_key};
use crate::jsgraph::ir::{ModuleOrigin, SemanticDefinition, SemanticIr, SemanticReference};
use crate::jsgraph::static_types::OpenReceiverFact;

use super::ast_util::static_key_path;
use super::coverage::semantic_coverage;
use super::derived::collect_derived;
use super::member_mutations::collect_semantic_member_mutations;
use super::projection::{
    collect_semantic_callable, collect_semantic_module_link, collect_semantic_references,
    immutable_semantic_bindings, immutable_semantic_scopes,
};
use super::property_paths::PathKey;
use super::require_origin::semantic_require_origin;
use super::resource_limits::semantic_resource_limits_in;
use super::returns::{collect_semantic_returns, resolve_semantic_module_callables};
use super::state::{
    current_semantic_scope, resolve_semantic_binding_from_scope, resolve_semantic_binding_state,
    semantic_resolution_blocked, semantic_scope_id, semantic_variable_scope, BindingIx, BindingState, CopyKind,
    ReferenceInitializer, ScopeIx, ScopeState, SemanticAnalysisState, SemanticInitializer, SourceRef,
};
use super::traversal::{traverse_javascript_ast, read_ancestors, AstVisitor, EnterFn};

/// Run `work` on a thread with a large stack: REA recurses on a few unbounded shapes (alias
/// chains, deep patterns) where JavaScript would throw a `RangeError`; the port instead has room.
pub(crate) fn with_large_stack<R: Send>(work: impl FnOnce() -> R + Send) -> R {
    std::thread::scope(|scope| {
        let handle = std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn_scoped(scope, crate::jsgraph::control::inherit(work))
            .expect("spawn semantic analysis thread");
        match handle.join() {
            Ok(value) => value,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    })
}

/// Recover lexical bindings, aliases, constants, and module links from a parsed program
/// (`analyzeParsedJavaScriptSemantics`).
pub fn analyze_semantics(ast: &Ast) -> SemanticIr {
    with_large_stack(|| analyze_semantics_inner(ast))
}

/// Recover lexical references, optionally for one name, without evaluating values or provenance
/// (`analyzeParsedJavaScriptReferences`).
pub fn analyze_references(ast: &Ast, name: Option<&str>) -> Vec<SemanticReference> {
    with_large_stack(|| {
        let mut state = SemanticAnalysisState::new(ast);
        collect_definitions(&mut state);
        collect_semantic_references(&state, name)
    })
}

fn analyze_semantics_inner(ast: &Ast) -> SemanticIr {
    let mut state = SemanticAnalysisState::new(ast);
    collect_definitions(&mut state);
    collect_semantic_member_mutations(&mut state);
    {
        let mut visitor = EnterFn(|node, _parent| collect_semantic_module_link(node, &mut state));
        traverse_javascript_ast(ast.root(), &mut visitor);
    }
    let references = collect_semantic_references(&state, None);
    let parser_partial = ast.error_count > 0;
    let bindings = immutable_semantic_bindings(&state);
    let callables = collect_semantic_returns(&state, parser_partial);
    let module_links = resolve_semantic_module_callables(&state, &callables);
    let derived = collect_derived(ast, &state, &callables, parser_partial);
    let limits = semantic_resource_limits_in(
        bindings
            .iter()
            .map(|binding| &binding.value)
            .chain(callables.iter().flat_map(|callable| callable.return_sites.iter().map(|site| &site.value))),
    );
    let mut limitations: Vec<String> = Vec::new();
    if parser_partial {
        limitations.push("The parser recovered from syntax errors; affected bindings are partial.".into());
    }
    limitations.extend([
        "Values and aliases were recovered from inert syntax only; no JavaScript was executed.".to_string(),
        "Return sites include only direct callable returns; nested callable returns remain separate.".to_string(),
        "Local call, argument, return, and closure relations are static candidates and do not prove runtime invocation.".to_string(),
        "Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.".to_string(),
        "Cross-function mutation and dynamic property resolution remain unknown.".to_string(),
    ]);
    SemanticIr {
        schema: "JavaScriptSemanticIR".into(),
        scopes: immutable_semantic_scopes(&state),
        bindings,
        callables,
        references,
        module_links,
        call_sites: derived.call_sites,
        argument_flows: derived.argument_flows,
        call_return_flows: derived.call_return_flows,
        call_result_flows: derived.call_result_flows,
        closure_captures: derived.closure_captures,
        promise_operations: derived.promise_operations,
        event_operations: derived.event_operations,
        timer_operations: derived.timer_operations,
        child_process_spawns: derived.child_process_spawns,
        child_process_interactions: derived.child_process_interactions,
        configuration_operations: derived.configuration_operations,
        request_operations: derived.request_operations,
        boundary_operations: derived.boundary_operations,
        resource_operations: derived.resource_operations,
        object_operations: derived.object_operations,
        function_fingerprints: derived.function_fingerprints,
        frontiers: derived.frontiers,
        coverage: semantic_coverage(parser_partial, limits),
        limitations,
    }
}

// ---------------------------------------------------------------------------------------------
// Definitions
// ---------------------------------------------------------------------------------------------

/// Inputs of `bindPattern`.
#[derive(Clone)]
struct BindPatternInput<'a> {
    pattern: N<'a>,
    initializer: Option<N<'a>>,
    scope: ScopeIx,
    mutable: bool,
    kind: &'static str,
    projection: Vec<PathKey>,
    reference_only: bool,
    copy_kind: Option<CopyKind>,
    copy_projection_offset: Option<usize>,
    copy_excluded_keys: Option<Vec<String>>,
    copy_start_index: Option<u64>,
    fallback_sources: Option<Vec<SourceRef<'a>>>,
    required_sources: Option<Vec<SourceRef<'a>>>,
}

impl<'a> BindPatternInput<'a> {
    fn new(pattern: N<'a>, initializer: Option<N<'a>>, scope: ScopeIx, mutable: bool) -> Self {
        BindPatternInput {
            pattern,
            initializer,
            scope,
            mutable,
            kind: "variable",
            projection: Vec::new(),
            reference_only: false,
            copy_kind: None,
            copy_projection_offset: None,
            copy_excluded_keys: None,
            copy_start_index: None,
            fallback_sources: None,
            required_sources: None,
        }
    }
}

struct AddBindingInput<'a> {
    scope: ScopeIx,
    name: String,
    kind: &'static str,
    mutable: bool,
    definition_node: N<'a>,
    initializer: Option<N<'a>>,
    direct_origin: Option<ModuleOrigin>,
    projection: Vec<PathKey>,
}

struct DefinitionsVisitor<'s, 'a> {
    state: &'s mut SemanticAnalysisState<'a>,
    stack: Vec<ScopeIx>,
    opened: HashMap<NodeId, u32>,
    assignments: Vec<(N<'a>, ScopeIx)>,
    function_bodies: Vec<(N<'a>, ScopeIx)>,
}

/// `collectDefinitionsSteps`.
fn collect_definitions<'a>(state: &mut SemanticAnalysisState<'a>) {
    let program = state.ast.root();
    let root_scope: ScopeIx = 0;
    let mut visitor = DefinitionsVisitor {
        state,
        stack: vec![root_scope],
        opened: HashMap::new(),
        assignments: Vec::new(),
        function_bodies: Vec::new(),
    };
    traverse_javascript_ast(program, &mut visitor);
    let DefinitionsVisitor { state, assignments, function_bodies, .. } = visitor;
    // All declarations must exist before resolving writes, including hoisted functions and local
    // declarations that shadow an outer binding.
    for (node, scope) in assignments {
        bind_assignment(node, scope, state);
    }
    for (function, scope) in function_bodies {
        let Some(body) = function.f("body") else { continue };
        for parameter in function.nodes("params") {
            let target = if parameter.is(Kind::TSParameterProperty) {
                parameter.f("parameter").unwrap_or(parameter)
            } else {
                parameter
            };
            for identifier in assigned_pattern_identifiers(target) {
                copy_parameter_to_body(identifier, body, scope, state);
            }
        }
    }
}

impl<'s, 'a> AstVisitor<'a> for DefinitionsVisitor<'s, 'a> {
    fn enter(&mut self, node: N<'a>, parent: Option<N<'a>>) {
        let mut parent_scope = current_semantic_scope(&self.stack);
        if let Some(parent_node) = parent {
            if (parent_node.is(Kind::ObjectMethod) || parent_node.is(Kind::ClassMethod))
                && parent_node.flag("computed")
                && parent_node.f("key") == Some(node)
            {
                if let Some(key_scope) = self.state.scopes[parent_scope].parent {
                    // A computed method key is evaluated before entering the method's parameter
                    // and body environments.
                    self.stack.push(key_scope);
                    self.opened.insert(node.id, 1);
                    parent_scope = key_scope;
                }
            }
            if parent_node.is(Kind::WithStatement) && parent_node.f("body") == Some(node) {
                let dynamic_scope = ScopeState {
                    scope_id: format!("{}:with", semantic_scope_id("block", parent_node)),
                    parent_scope_id: Some(self.state.scopes[parent_scope].scope_id.clone()),
                    parent: Some(parent_scope),
                    kind: "block",
                    location: parent_node.loc(),
                    bindings_complete: false,
                    bindings: HashMap::new(),
                };
                let ix = self.state.push_scope(dynamic_scope);
                self.stack.push(ix);
                self.opened.insert(node.id, 1);
                parent_scope = ix;
            }
        }
        bind_outer_declaration(node, parent_scope, self.state);
        let nested = nested_scope(node, parent, parent_scope, self.state);
        if let Some(nested) = nested {
            self.stack.push(nested);
            *self.opened.entry(node.id).or_insert(0) += 1;
            if node.is(Kind::BlockStatement) {
                if let Some(function) = parent.filter(|p| p.is_function()) {
                    self.function_bodies.push((function, nested));
                }
            }
        }
        let scope = current_semantic_scope(&self.stack);
        // Other nodes inherit the nearest boundary through their AST parents. Avoid a second
        // full-tree index for the same lexical relationship.
        if parent.is_none() || self.opened.contains_key(&node.id) {
            self.state.set_scope_for_node(node, scope);
        }
        collect_semantic_callable(self.state, node, parent, parent_scope, nested);
        bind_inner_declaration(node, parent, scope, self.state);
        if node.is(Kind::VariableDeclarator) {
            if let (Some(init), Some(parent_node)) = (node.f("init"), parent) {
                if parent_node.is(Kind::VariableDeclaration)
                    && parent_node.str("kind") == Some("var")
                    && has_conditional_initializer(&read_ancestors(node))
                {
                    self.state.conditional_initializers.insert(init.id);
                }
            }
        }
        if matches!(
            node.kind(),
            Kind::AssignmentExpression | Kind::UpdateExpression | Kind::ForOfStatement | Kind::ForInStatement
        ) {
            self.assignments.push((node, scope));
        }
    }

    fn exit(&mut self, node: N<'a>, _parent: Option<N<'a>>) {
        let count = self.opened.get(&node.id).copied().unwrap_or(0);
        for _ in 0..count {
            self.stack.pop();
        }
    }
}

fn copy_parameter_to_body<'a>(
    identifier: N<'a>,
    body: N<'a>,
    scope: ScopeIx,
    state: &mut SemanticAnalysisState<'a>,
) {
    let name = identifier.name().unwrap_or("");
    let Some(&binding_ix) = state.scopes[scope].bindings.get(name) else { return };
    {
        let binding = &state.bindings[binding_ix];
        if binding.kind != "variable" || binding.definitions.iter().any(|definition| definition.kind == "function") {
            return;
        }
    }
    // A separate body var environment starts with the parameter's value. The real parameter
    // identifier retains its scope and source location; entryBody records when the copy occurs
    // without inventing an expression in the AST.
    state.bindings[binding_ix].initializers.insert(
        0,
        SemanticInitializer { node: identifier, projection: Vec::new(), entry_body: Some(body) },
    );
    let mut index = state.bindings[binding_ix].initializers.len();
    while index > 0 {
        index -= 1;
        let (candidate, is_self_copy_shape) = {
            let initializer = &state.bindings[binding_ix].initializers[index];
            (
                initializer.node,
                initializer.entry_body.is_none() && initializer.projection.is_empty() && initializer.node.is_identifier(),
            )
        };
        if is_self_copy_shape
            && resolve_semantic_binding_state(state, candidate, candidate.name().unwrap_or("")) == Some(binding_ix)
        {
            // Direct self-initialization preserves the prior value, including any actual
            // overwrite before it. Keep the source definition/reference facts.
            state.bindings[binding_ix].initializers.remove(index);
        }
    }
}

fn has_conditional_initializer(ancestors: &[N<'_>]) -> bool {
    // A hoisted var can remain undefined when control flow skips its initializer. Conditions
    // outside the owning callable/static block do not govern its body.
    for node in ancestors.iter().rev() {
        if node.is_function() || node.is(Kind::Program) || node.is(Kind::StaticBlock) {
            return false;
        }
        if node.is(Kind::IfStatement)
            || node.has_alias(Alias::Loop)
            || node.is(Kind::SwitchCase)
            || node.is(Kind::TryStatement)
        {
            return true;
        }
    }
    false
}

fn bind_outer_declaration<'a>(node: N<'a>, scope: ScopeIx, state: &mut SemanticAnalysisState<'a>) {
    let kind = match node.kind() {
        Kind::FunctionDeclaration => "function",
        Kind::ClassDeclaration => "class",
        _ => return,
    };
    let Some(id) = node.f("id").filter(|id| id.is_identifier()) else { return };
    add_binding(
        state,
        AddBindingInput {
            scope,
            name: id.name().unwrap_or("").to_string(),
            kind,
            mutable: false,
            definition_node: id,
            initializer: Some(node),
            direct_origin: None,
            projection: Vec::new(),
        },
    );
}

fn bind_inner_declaration<'a>(
    node: N<'a>,
    parent: Option<N<'a>>,
    scope: ScopeIx,
    state: &mut SemanticAnalysisState<'a>,
) {
    match node.kind() {
        Kind::ImportDeclaration => bind_imports(node, scope, state),
        Kind::VariableDeclarator => {
            let Some(id) = node.f("id") else { return };
            let variable_scope = semantic_variable_scope(state, scope, parent);
            let mutable = match parent {
                Some(p) if p.is(Kind::VariableDeclaration) => p.str("kind") != Some("const"),
                _ => true,
            };
            bind_pattern(BindPatternInput::new(id, node.f("init"), variable_scope, mutable), state);
        }
        Kind::ClassExpression => {
            if let Some(id) = node.f("id").filter(|id| id.is_identifier()) {
                add_binding(
                    state,
                    AddBindingInput {
                        scope,
                        name: id.name().unwrap_or("").to_string(),
                        kind: "class",
                        mutable: false,
                        definition_node: id,
                        initializer: Some(node),
                        direct_origin: None,
                        projection: Vec::new(),
                    },
                );
            }
        }
        _ if node.is_function() => bind_function_locals(node, scope, state),
        Kind::CatchClause => {
            if let Some(param) = node.f("param") {
                let mut input = BindPatternInput::new(param, None, scope, true);
                input.kind = "catch";
                bind_pattern(input, state);
            }
        }
        _ => {}
    }
}

fn bind_assignment<'a>(node: N<'a>, scope: ScopeIx, state: &mut SemanticAnalysisState<'a>) {
    match node.kind() {
        Kind::AssignmentExpression => {
            let (Some(left), Some(right)) = (node.f("left"), node.f("right")) else { return };
            if left.is_identifier() {
                let operator = node.str("operator");
                let initializer = if matches!(operator, Some("=" | "||=" | "??=")) { right } else { node };
                add_assignment(left, initializer, scope, state);
            } else {
                for identifier in assigned_pattern_identifiers(left) {
                    add_assignment(identifier, node, scope, state);
                }
            }
        }
        Kind::UpdateExpression => {
            if let Some(argument) = node.f("argument").filter(|a| a.is_identifier()) {
                add_assignment(argument, node, scope, state);
            }
        }
        Kind::ForOfStatement | Kind::ForInStatement => {
            let Some(left) = node.f("left") else { return };
            let patterns: Vec<N<'a>> = if left.is(Kind::VariableDeclaration) {
                left.nodes("declarations").into_iter().filter_map(|d| d.f("id")).collect()
            } else {
                vec![left]
            };
            for pattern in patterns {
                for identifier in assigned_pattern_identifiers(pattern) {
                    add_assignment(identifier, node, scope, state);
                }
                if node.is(Kind::ForOfStatement) {
                    // Keep the loop value unknown, but preserve references yielded into each
                    // bound slot so writes/escapes can reach their iterable origins.
                    let mut input = BindPatternInput::new(pattern, Some(node), scope, true);
                    input.reference_only = true;
                    bind_pattern(input, state);
                }
            }
        }
        _ => {}
    }
}

/// `assignedPatternIdentifiers`: the identifiers a pattern assigns (stack order of the TS).
fn assigned_pattern_identifiers<'a>(pattern: N<'a>) -> Vec<N<'a>> {
    let mut identifiers = Vec::new();
    let mut pending = vec![pattern];
    while let Some(node) = pending.pop() {
        match node.kind() {
            Kind::Identifier => identifiers.push(node),
            Kind::RestElement => pending.extend(node.f("argument")),
            Kind::AssignmentPattern => pending.extend(node.f("left")),
            Kind::ArrayPattern => pending.extend(node.list("elements").into_iter().flatten()),
            Kind::ObjectPattern => {
                for property in node.nodes("properties") {
                    if property.is(Kind::RestElement) {
                        pending.extend(property.f("argument"));
                    } else {
                        pending.extend(property.f("value"));
                    }
                }
            }
            _ => {}
        }
    }
    identifiers
}

fn nested_scope<'a>(
    node: N<'a>,
    parent: Option<N<'a>>,
    parent_scope: ScopeIx,
    state: &mut SemanticAnalysisState<'a>,
) -> Option<ScopeIx> {
    let switch_owner = match parent {
        Some(p) if node.is(Kind::SwitchCase) && p.is(Kind::SwitchStatement) => Some(p),
        _ => None,
    };
    if let Some(owner) = switch_owner {
        if let Some(existing) = state.scope_by_id(&semantic_scope_id("block", owner)) {
            return Some(existing);
        }
    }
    let kind = scope_kind(node, parent)?;
    let name_scope = function_name_scope(node, parent_scope, state);
    let owner_node = switch_owner.unwrap_or(node);
    let parent_ix = name_scope.unwrap_or(parent_scope);
    let scope = ScopeState {
        scope_id: semantic_scope_id(kind, owner_node),
        parent_scope_id: Some(state.scopes[parent_ix].scope_id.clone()),
        parent: Some(parent_ix),
        kind,
        location: owner_node.loc(),
        bindings_complete: true,
        bindings: HashMap::new(),
    };
    Some(state.push_scope(scope))
}

fn function_name_scope<'a>(
    node: N<'a>,
    parent_scope: ScopeIx,
    state: &mut SemanticAnalysisState<'a>,
) -> Option<ScopeIx> {
    if !node.is(Kind::FunctionExpression) {
        return None;
    }
    let id = node.f("id").filter(|id| id.is_identifier())?;
    // A named expression has a private name environment outside its parameters and body.
    // Parameters and local declarations may shadow that name.
    let scope = ScopeState {
        scope_id: format!("{}:function-name", semantic_scope_id("block", node)),
        parent_scope_id: Some(state.scopes[parent_scope].scope_id.clone()),
        parent: Some(parent_scope),
        kind: "block",
        location: node.loc(),
        bindings_complete: true,
        bindings: HashMap::new(),
    };
    let ix = state.push_scope(scope);
    add_binding(
        state,
        AddBindingInput {
            scope: ix,
            name: id.name().unwrap_or("").to_string(),
            kind: "function",
            mutable: false,
            definition_node: id,
            initializer: Some(node),
            direct_origin: None,
            projection: Vec::new(),
        },
    );
    Some(ix)
}

fn scope_kind(node: N<'_>, parent: Option<N<'_>>) -> Option<&'static str> {
    if node.is_function() {
        return Some("function");
    }
    if node.has_alias(Alias::Class) {
        return Some("class");
    }
    if node.is(Kind::CatchClause) {
        return Some("catch");
    }
    if matches!(node.kind(), Kind::ForStatement | Kind::ForOfStatement | Kind::ForInStatement) {
        return Some("block");
    }
    // A switch body is one lexical scope shared by all its cases, so `let` in two cases must
    // resolve to one binding rather than collide or leak.
    if node.is(Kind::SwitchCase) {
        return Some("block");
    }
    // Each `static {}` block is its own lexical scope; otherwise a `let` in two static blocks
    // would collide in the enclosing class scope.
    if node.is(Kind::StaticBlock) {
        return Some("static-block");
    }
    if node.is(Kind::BlockStatement) {
        if let Some(function) = parent.filter(|p| p.is_function() && p.f("body") == Some(node)) {
            // Parameter expressions cannot see declarations in the function body. Retain the
            // outer function scope for parameters and callable ownership; body declarations
            // belong to a separate variable environment.
            return if function_parameters_have_expressions(function) { Some("function") } else { None };
        }
        return Some("block");
    }
    None
}

fn function_parameters_have_expressions(node: N<'_>) -> bool {
    let mut pending: Vec<N<'_>> = node.nodes("params");
    while let Some(parameter) = pending.pop() {
        match parameter.kind() {
            Kind::AssignmentPattern => return true,
            Kind::TSParameterProperty => pending.extend(parameter.f("parameter")),
            Kind::RestElement => pending.extend(parameter.f("argument")),
            Kind::ArrayPattern => pending.extend(parameter.list("elements").into_iter().flatten()),
            Kind::ObjectPattern => {
                for property in parameter.nodes("properties") {
                    if property.is(Kind::RestElement) {
                        pending.extend(property.f("argument"));
                    } else {
                        if property.flag("computed") {
                            return true;
                        }
                        pending.extend(property.f("value"));
                    }
                }
            }
            _ => {}
        }
    }
    false
}

fn bind_imports<'a>(node: N<'a>, scope: ScopeIx, state: &mut SemanticAnalysisState<'a>) {
    let specifier_text = node.f("source").and_then(|s| s.str("value")).unwrap_or("").to_string();
    for specifier in node.nodes("specifiers") {
        let imported_path: Vec<String> = match specifier.kind() {
            Kind::ImportDefaultSpecifier => vec!["default".into()],
            Kind::ImportNamespaceSpecifier => Vec::new(),
            _ => {
                let name = specifier.f("imported").map(property_name).unwrap_or_default();
                vec![if name.is_empty() { "[dynamic]".to_string() } else { name }]
            }
        };
        let Some(local) = specifier.f("local") else { continue };
        add_binding(
            state,
            AddBindingInput {
                scope,
                name: local.name().unwrap_or("").to_string(),
                kind: "import",
                mutable: false,
                definition_node: local,
                initializer: None,
                direct_origin: Some(ModuleOrigin { specifier: specifier_text.clone(), imported_path }),
                projection: Vec::new(),
            },
        );
    }
}

fn bind_function_locals<'a>(node: N<'a>, scope: ScopeIx, state: &mut SemanticAnalysisState<'a>) {
    for parameter in node.nodes("params") {
        let pattern = if parameter.is(Kind::TSParameterProperty) {
            parameter.f("parameter").unwrap_or(parameter)
        } else {
            parameter
        };
        let mut input = BindPatternInput::new(pattern, None, scope, true);
        input.kind = "parameter";
        bind_pattern(input, state);
    }
}

fn bind_pattern<'a>(input: BindPatternInput<'a>, state: &mut SemanticAnalysisState<'a>) {
    let pattern = input.pattern;
    match pattern.kind() {
        Kind::TSParameterProperty => {
            if let Some(parameter) = pattern.f("parameter") {
                bind_pattern(BindPatternInput { pattern: parameter, ..input }, state);
            }
        }
        Kind::Identifier => {
            let name = pattern.name().unwrap_or("");
            if input.reference_only {
                let binding = resolve_semantic_binding_from_scope(state, input.scope, name);
                if let (Some(binding), Some(initializer)) = (binding, input.initializer) {
                    state.bindings[binding].reference_initializers.push(ReferenceInitializer {
                        node: initializer,
                        projection: input.projection,
                        copy_kind: input.copy_kind,
                        copy_projection_offset: input.copy_projection_offset,
                        copy_excluded_keys: input.copy_excluded_keys,
                        copy_start_index: input.copy_start_index,
                        fallback_sources: input.fallback_sources,
                        required_sources: input.required_sources,
                    });
                }
                return;
            }
            add_binding(
                state,
                AddBindingInput {
                    scope: input.scope,
                    name: name.to_string(),
                    kind: input.kind,
                    mutable: input.mutable,
                    definition_node: pattern,
                    initializer: input.initializer,
                    direct_origin: None,
                    projection: input.projection,
                },
            );
        }
        Kind::AssignmentPattern => {
            let (Some(left), Some(right)) = (pattern.f("left"), pattern.f("right")) else { return };
            let projection = input.projection.clone();
            let mut required = input.required_sources.clone().unwrap_or_default();
            if let Some(initializer) = input.initializer {
                required.push(SourceRef { node: initializer, projection: projection.clone() });
            }
            bind_pattern(
                BindPatternInput {
                    pattern: left,
                    initializer: if input.kind == "parameter" || input.kind == "catch" {
                        input.initializer
                    } else {
                        input.initializer.or(Some(right))
                    },
                    required_sources: Some(required),
                    ..input.clone()
                },
                state,
            );
            let mut fallback = input.fallback_sources.clone().unwrap_or_default();
            if let Some(initializer) = input.initializer {
                fallback.push(SourceRef { node: initializer, projection });
            }
            bind_pattern(
                BindPatternInput {
                    pattern: left,
                    initializer: Some(right),
                    scope: input.scope,
                    mutable: input.mutable,
                    kind: input.kind,
                    projection: Vec::new(),
                    reference_only: true,
                    copy_kind: None,
                    copy_projection_offset: None,
                    copy_excluded_keys: None,
                    copy_start_index: None,
                    fallback_sources: Some(fallback),
                    required_sources: input.required_sources.clone(),
                },
                state,
            );
        }
        Kind::RestElement => {
            if let Some(argument) = pattern.f("argument") {
                bind_pattern(
                    BindPatternInput { pattern: argument, initializer: None, mutable: true, ..input },
                    state,
                );
            }
        }
        Kind::ObjectPattern => {
            for property in pattern.nodes("properties") {
                if property.is(Kind::RestElement) {
                    let Some(argument) = property.f("argument") else { continue };
                    bind_pattern(
                        BindPatternInput {
                            pattern: argument,
                            initializer: None,
                            mutable: true,
                            projection: Vec::new(),
                            ..input.clone()
                        },
                        state,
                    );
                    let mut projection = input.projection.clone();
                    projection.push(PathKey::Null);
                    bind_pattern(
                        BindPatternInput {
                            pattern: argument,
                            projection,
                            reference_only: true,
                            copy_kind: Some(CopyKind::ObjectRest),
                            copy_projection_offset: Some(input.projection.len()),
                            copy_excluded_keys: Some(object_pattern_keys(pattern)),
                            ..input.clone()
                        },
                        state,
                    );
                } else {
                    let key = property
                        .f("key")
                        .map(|key| static_key_path(key, property.flag("computed")))
                        .unwrap_or(PathKey::Null);
                    let Some(value) = property.f("value") else { continue };
                    let mut projection = input.projection.clone();
                    projection.push(key);
                    bind_pattern(BindPatternInput { pattern: value, projection, ..input.clone() }, state);
                }
            }
        }
        Kind::ArrayPattern => {
            for (index, element) in pattern.list("elements").into_iter().enumerate() {
                let Some(element) = element else { continue };
                let mut projection = input.projection.clone();
                projection.push(PathKey::Index(index as u64));
                bind_pattern(BindPatternInput { pattern: element, projection, ..input.clone() }, state);
                if element.is(Kind::RestElement) {
                    if let Some(argument) = element.f("argument") {
                        let mut rest_projection = input.projection.clone();
                        rest_projection.push(PathKey::Null);
                        bind_pattern(
                            BindPatternInput {
                                pattern: argument,
                                projection: rest_projection,
                                reference_only: true,
                                copy_kind: Some(CopyKind::ArrayRest),
                                copy_projection_offset: Some(input.projection.len()),
                                copy_start_index: Some(index as u64),
                                ..input.clone()
                            },
                            state,
                        );
                    }
                }
            }
        }
        _ => {}
    }
}

fn add_binding<'a>(state: &mut SemanticAnalysisState<'a>, input: AddBindingInput<'a>) {
    let AddBindingInput { scope, name, kind, mutable, definition_node, initializer, direct_origin, projection } = input;
    let binding_ix = match state.scopes[scope].bindings.get(&name).copied() {
        Some(existing) => existing,
        None => {
            if !state.scopes[scope].bindings_complete {
                return;
            }
            let binding_id = format!("{}:binding:{}", state.scopes[scope].scope_id, encode_uri_component(&name));
            let ix = state.bindings.len();
            state.bindings.push(BindingState {
                binding_id: binding_id.clone(),
                scope_id: state.scopes[scope].scope_id.clone(),
                name: name.clone(),
                kind,
                mutable,
                mutated_paths: Vec::new(),
                escaped_paths: Vec::new(),
                definitions: Vec::new(),
                initializers: Vec::new(),
                reference_initializers: Vec::new(),
                direct_origins: Vec::new(),
            });
            state.scopes[scope].bindings.insert(name, ix);
            state.bindings_by_id.insert(binding_id, ix);
            ix
        }
    };
    let binding = &mut state.bindings[binding_ix];
    binding.mutable = binding.mutable || mutable;
    binding.definitions.push(SemanticDefinition { kind: kind.to_string(), location: definition_node.loc() });
    if let Some(initializer) = initializer {
        binding.initializers.push(SemanticInitializer { node: initializer, projection, entry_body: None });
    }
    if let Some(origin) = direct_origin {
        binding.direct_origins.push(origin);
    }
}

/// JS `encodeURIComponent`.
pub(crate) fn encode_uri_component(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

fn add_assignment<'a>(
    identifier: N<'a>,
    initializer: N<'a>,
    scope: ScopeIx,
    state: &mut SemanticAnalysisState<'a>,
) {
    let Some(binding_ix) = resolve_semantic_binding_from_scope(state, scope, identifier.name().unwrap_or("")) else {
        return;
    };
    let binding = &mut state.bindings[binding_ix];
    binding.mutable = true;
    binding.definitions.push(SemanticDefinition { kind: "assignment".into(), location: identifier.loc() });
    binding.initializers.push(SemanticInitializer { node: initializer, projection: Vec::new(), entry_body: None });
}

// ---------------------------------------------------------------------------------------------
// Classifiers
// ---------------------------------------------------------------------------------------------

/// Resolve only the lexical receiver identity needed to distinguish browser `window.open` from
/// XHR and global storage `.open` calls (`classifyParsedJavaScriptOpenReceivers`). Keys are the
/// call expression start offsets. This deliberately builds definitions without running semantic
/// value or provenance analysis.
pub fn classify_open_receivers(ast: &Ast) -> HashMap<u32, OpenReceiverFact> {
    with_large_stack(|| {
        let mut state = SemanticAnalysisState::new(ast);
        collect_definitions(&mut state);
        let mut facts: HashMap<u32, OpenReceiverFact> = HashMap::new();
        let mut visitor = EnterFn(|node, _parent| {
            classify_open_call(&state, node, &mut facts);
        });
        traverse_javascript_ast(ast.root(), &mut visitor);
        facts
    })
}

fn classify_open_call<'a>(
    state: &SemanticAnalysisState<'a>,
    node: N<'a>,
    facts: &mut HashMap<u32, OpenReceiverFact>,
) {
    if !node.is_call() {
        return;
    }
    let Some(callee) = node.f("callee").filter(|c| c.is_member()) else { return };
    let Some(property) = callee.f("property") else { return };
    if static_property_key(property, callee.flag("computed")).as_deref() != Some("open") {
        return;
    }
    let Some(object) = callee.f("object").filter(|o| o.is_identifier()) else { return };
    let receiver = object.name().unwrap_or("");
    let start = node.start();
    let Some(binding_ix) = resolve_semantic_binding_state(state, node, receiver) else {
        if semantic_resolution_blocked(state, node, receiver) {
            return;
        }
        if let Some(fact) = open_global_fact(receiver) {
            facts.insert(start, fact);
        }
        return;
    };
    // A lexically bound receiver overrides ambient browser globals. Mark an otherwise unresolved
    // local as local so name-based window.open heuristics do not hide its XHR-like overloads.
    facts.insert(start, OpenReceiverFact::Local);
    if receiver == "indexedDB" || receiver == "caches" {
        facts.insert(
            start,
            if receiver == "indexedDB" { OpenReceiverFact::LocalIndexedDb } else { OpenReceiverFact::LocalCacheStorage },
        );
        return;
    }
    let binding = &state.bindings[binding_ix];
    if binding.mutable || binding.initializers.len() != 1 {
        return;
    }
    let initializer = binding.initializers[0].node;
    if !initializer.is_identifier() {
        return;
    }
    let initializer_name = initializer.name().unwrap_or("");
    if let Some(initializer_binding_ix) = resolve_semantic_binding_state(state, initializer, initializer_name) {
        if initializer_name == "indexedDB" || initializer_name == "caches" {
            let local_fact = if initializer_name == "indexedDB" {
                OpenReceiverFact::LocalIndexedDb
            } else {
                OpenReceiverFact::LocalCacheStorage
            };
            facts.insert(start, local_fact);
            let initializer_binding = &state.bindings[initializer_binding_ix];
            if initializer_binding.mutable || initializer_binding.initializers.len() != 1 {
                return;
            }
            let nested = initializer_binding.initializers[0].node;
            if nested.is_identifier() {
                if let Some(nested_fact) = resolve_global_alias_fact(state, initializer, nested.name().unwrap_or("")) {
                    facts.insert(start, nested_fact);
                }
            }
        } else if initializer_name == "window" {
            facts.insert(start, OpenReceiverFact::Local);
        }
        return;
    }
    if let Some(alias_fact) = resolve_global_alias_fact(state, initializer, initializer_name) {
        facts.insert(start, alias_fact);
    }
}

fn open_global_fact(name: &str) -> Option<OpenReceiverFact> {
    match name {
        "window" | "self" | "globalThis" | "top" | "parent" | "opener" | "frames" | "document" => {
            Some(OpenReceiverFact::Window)
        }
        "indexedDB" => Some(OpenReceiverFact::IndexedDb),
        "caches" => Some(OpenReceiverFact::CacheStorage),
        _ => None,
    }
}

fn resolve_global_alias_fact(
    state: &SemanticAnalysisState<'_>,
    node: N<'_>,
    name: &str,
) -> Option<OpenReceiverFact> {
    if resolve_semantic_binding_state(state, node, name).is_some() || semantic_resolution_blocked(state, node, name) {
        return None;
    }
    open_global_fact(name)
}

/// Electron export paths for call and construction roots bound to Electron under another name,
/// such as esbuild's `import { ipcMain as ipcMain2 }`
/// (`classifyParsedJavaScriptElectronBindings`). Keys are root identifier offsets; roots spelled
/// as their export are omitted.
pub fn classify_electron_bindings(ast: &Ast) -> HashMap<u32, String> {
    with_large_stack(|| {
        let mut state = SemanticAnalysisState::new(ast);
        collect_definitions(&mut state);
        let mut facts: HashMap<u32, String> = HashMap::new();
        let mut exports_by_binding: HashMap<BindingIx, Option<String>> = HashMap::new();
        let mut visitor = EnterFn(|node: N<'_>, _parent: Option<N<'_>>| {
            if !node.is_call() && !node.is(Kind::NewExpression) {
                return;
            }
            let Some(root) = node.f("callee").and_then(callee_root) else { return };
            let name = root.name().unwrap_or("");
            let Some(binding_ix) = resolve_semantic_binding_state(&state, root, name) else { return };
            let exported = exports_by_binding
                .entry(binding_ix)
                .or_insert_with(|| electron_export(binding_ix, &state))
                .clone();
            if let Some(exported) = exported {
                if exported != name {
                    facts.insert(root.start(), exported);
                }
            }
        });
        traverse_javascript_ast(ast.root(), &mut visitor);
        facts
    })
}

fn callee_root<'a>(mut node: N<'a>) -> Option<N<'a>> {
    while node.is_member() {
        node = node.f("object")?;
    }
    node.is_identifier().then_some(node)
}

/// `/^electron(?:\/(?:common|main|renderer|utility))?$/u`.
fn is_electron_module(specifier: &str) -> bool {
    match specifier.strip_prefix("electron") {
        Some("") => true,
        Some(rest) => matches!(rest, "/common" | "/main" | "/renderer" | "/utility"),
        None => false,
    }
}

// Read import and require origins directly; general value evaluation is unnecessary here and
// costly across large vendor bundles.
fn electron_export(binding_ix: BindingIx, state: &SemanticAnalysisState<'_>) -> Option<String> {
    let origin = binding_origin(binding_ix, state)?;
    (is_electron_module(&origin.specifier) && !origin.imported_path.is_empty())
        .then(|| origin.imported_path.join("."))
}

fn binding_origin(binding_ix: BindingIx, state: &SemanticAnalysisState<'_>) -> Option<ModuleOrigin> {
    let binding = &state.bindings[binding_ix];
    if !binding.direct_origins.is_empty() {
        return if binding.direct_origins.len() == 1 { Some(binding.direct_origins[0].clone()) } else { None };
    }
    let initializer = binding.initializers.first()?;
    // A var/let declaration permits writes without proving one occurred. Require one
    // unconditional initializer and no actual binding writes.
    if binding.initializers.len() != 1
        || binding.definitions.iter().any(|definition| definition.kind == "assignment")
        || state.conditional_initializers.contains(&initializer.node.id)
    {
        return None;
    }
    let origin = semantic_require_origin(Some(initializer.node), state)?;
    let projection: Option<Vec<String>> = initializer
        .projection
        .iter()
        .map(|key| match key {
            PathKey::Name(name) => Some(name.clone()),
            _ => None,
        })
        .collect();
    let projection = projection?;
    let mut imported_path = origin.imported_path;
    imported_path.extend(projection);
    Some(ModuleOrigin { specifier: origin.specifier, imported_path })
}

