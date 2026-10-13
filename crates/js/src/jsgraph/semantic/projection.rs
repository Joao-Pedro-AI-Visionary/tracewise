//! Port of `javascriptSemanticProjection.ts`: callables, module links, references and the
//! immutable scope/binding projections.

use std::collections::HashSet;

use crate::jsgraph::ast::{Alias, Kind, N};
use crate::jsgraph::ast_values::{property_name, static_property_key};
use crate::jsgraph::ir::{
    ReturnCoverage, SemanticBinding, SemanticCallable, SemanticModuleLink, SemanticReference, SemanticScope,
};

use super::ast_util::is_identifier_named;
use super::require_origin::semantic_require_origin;
use super::state::{
    is_unshadowed_global, resolve_semantic_binding_state, semantic_resolution_blocked, ScopeIx,
    SemanticAnalysisState,
};
use super::traversal::{read_ancestors, traverse_javascript_ast, AstVisitor};
use super::values::{evaluate_semantic_binding, evaluate_semantic_provenance};

/// Retain callable identity without polluting lexical bindings (`collectSemanticCallable`).
pub fn collect_semantic_callable<'a>(
    state: &mut SemanticAnalysisState<'a>,
    node: N<'a>,
    parent: Option<N<'a>>,
    container_scope: ScopeIx,
    body_scope: Option<ScopeIx>,
) {
    let Some(kind) = callable_kind(node) else { return };
    let callable_id = semantic_callable_id_for_node(node).unwrap_or_else(|| "callable:unknown:-1:-1".into());
    let container_scope_id = state.scopes[container_scope].scope_id.clone();
    let body_scope_id = match body_scope {
        Some(scope) if state.scopes[scope].bindings_complete => Some(state.scopes[scope].scope_id.clone()),
        _ => None,
    };
    state.callables.push(SemanticCallable {
        callable_id: callable_id.clone(),
        kind: kind.into(),
        name: callable_name(node, parent),
        container_scope_id,
        body_scope_id,
        location: node.loc(),
        return_sites: Vec::new(),
        return_coverage: ReturnCoverage { status: "partial".into(), retained_count: 0, omitted_count: None },
    });
    state.callable_nodes_by_id.insert(callable_id, node);
}

/// Collect one static import/export relationship for later composition.
pub fn collect_semantic_module_link<'a>(node: N<'a>, state: &mut SemanticAnalysisState<'a>) {
    match node.kind() {
        Kind::ImportDeclaration => collect_imports(node, state),
        Kind::ExportAllDeclaration => add_module_link(
            state,
            SemanticModuleLink {
                kind: "re-export".into(),
                specifier: node.f("source").and_then(|source| source.str("value")).map(String::from),
                imported_name: Some("*".into()),
                local_name: None,
                exported_name: Some("*".into()),
                callable_id: None,
                location: node.loc(),
            },
            node,
        ),
        Kind::ExportNamedDeclaration => collect_named_exports(node, state),
        Kind::ExportDefaultDeclaration => {
            let declaration = node.f("declaration");
            add_module_link(
                state,
                SemanticModuleLink {
                    kind: "export".into(),
                    specifier: None,
                    imported_name: None,
                    local_name: declaration.and_then(default_declaration_name),
                    exported_name: Some("default".into()),
                    callable_id: declaration.and_then(semantic_callable_id_for_node),
                    location: node.loc(),
                },
                node,
            );
        }
        Kind::VariableDeclarator => collect_require_link(node, state),
        Kind::AssignmentExpression => collect_commonjs_export(node, state),
        _ => {}
    }
}

/// Collect lexical references after definitions exist, optionally for one name
/// (`collectSemanticReferences`).
pub fn collect_semantic_references<'a>(
    state: &SemanticAnalysisState<'a>,
    name: Option<&str>,
) -> Vec<SemanticReference> {
    struct Collector<'s, 'a, 'n> {
        state: &'s SemanticAnalysisState<'a>,
        name: Option<&'n str>,
        output: Vec<SemanticReference>,
        seen: HashSet<(u32, &'static str, &'a str)>,
        patterns: Vec<N<'a>>,
    }
    impl<'s, 'a, 'n> AstVisitor<'a> for Collector<'s, 'a, 'n> {
        fn enter(&mut self, node: N<'a>, parent: Option<N<'a>>) {
            if is_pattern_node(node) {
                self.patterns.push(node);
            }
            let Some(parent) = parent else { return };
            if !node.is_identifier() {
                return;
            }
            let node_name = node.name().unwrap_or("");
            if self.name.is_some_and(|wanted| wanted != node_name) {
                return;
            }
            if is_non_reference_key(node, parent)
                && !self.patterns.iter().any(|pattern| binds_identifier(*pattern, parent, node))
            {
                return;
            }
            let role = semantic_identifier_role_with_patterns(node, parent, &self.patterns);
            let Some(role) = role else { return };
            // A compound assignment or update reads before it writes; emit both so reference
            // consumers see the read they actually execute.
            let roles: &[&'static str] = if role == "write" && semantic_reads_before_write(node, parent) {
                &["read", "write"]
            } else if role == "write" {
                &["write"]
            } else if role == "read" {
                &["read"]
            } else {
                &["export"]
            };
            for resolved_role in roles {
                if !self.seen.insert((node.start(), resolved_role, node_name)) {
                    continue;
                }
                let binding = resolve_semantic_binding_state(self.state, node, node_name);
                let blocked = binding.is_none() && semantic_resolution_blocked(self.state, node, node_name);
                self.output.push(SemanticReference {
                    name: node_name.to_string(),
                    role: (*resolved_role).to_string(),
                    location: node.loc(),
                    binding_id: binding.map(|ix| self.state.bindings[ix].binding_id.clone()),
                    resolution: if binding.is_some() {
                        "resolved"
                    } else if blocked {
                        "unknown"
                    } else {
                        "unbound"
                    }
                    .to_string(),
                });
            }
        }

        fn exit(&mut self, node: N<'a>, _parent: Option<N<'a>>) {
            if is_pattern_node(node) {
                self.patterns.pop();
            }
        }
    }
    let mut collector =
        Collector { state, name, output: Vec::new(), seen: HashSet::new(), patterns: Vec::new() };
    traverse_javascript_ast(state.ast.root(), &mut collector);
    collector.output
}

/// Freeze collected scopes into deterministic IR order.
pub fn immutable_semantic_scopes(state: &SemanticAnalysisState<'_>) -> Vec<SemanticScope> {
    state
        .scopes
        .iter()
        .map(|scope| {
            let mut binding_ids: Vec<String> =
                scope.bindings.values().map(|ix| state.bindings[*ix].binding_id.clone()).collect();
            binding_ids.sort();
            SemanticScope {
                scope_id: scope.scope_id.clone(),
                parent_scope_id: scope.parent_scope_id.clone(),
                kind: scope.kind.to_string(),
                location: scope.location,
                bindings_complete: scope.bindings_complete,
                binding_ids,
            }
        })
        .collect()
}

/// Evaluate and freeze bindings into deterministic IR order.
pub fn immutable_semantic_bindings(state: &SemanticAnalysisState<'_>) -> Vec<SemanticBinding> {
    let mut bindings: Vec<SemanticBinding> = (0..state.bindings.len())
        .map(|ix| {
            let binding = &state.bindings[ix];
            SemanticBinding {
                binding_id: binding.binding_id.clone(),
                scope_id: binding.scope_id.clone(),
                name: binding.name.clone(),
                kind: binding.kind.to_string(),
                mutable: binding.mutable,
                definitions: binding.definitions.clone(),
                value: evaluate_semantic_binding(state, ix),
                provenance: evaluate_semantic_provenance(state, ix),
            }
        })
        .collect();
    bindings.sort_by(|left, right| left.binding_id.cmp(&right.binding_id));
    bindings
}

fn callable_kind(node: N<'_>) -> Option<&'static str> {
    if matches!(node.kind(), Kind::ClassMethod | Kind::ClassPrivateMethod | Kind::ObjectMethod) {
        return Some("method");
    }
    if node.is_function() {
        return Some("function");
    }
    if node.has_alias(Alias::Class) {
        return Some("class");
    }
    None
}

fn callable_name(node: N<'_>, parent: Option<N<'_>>) -> Option<String> {
    if matches!(
        node.kind(),
        Kind::FunctionDeclaration | Kind::FunctionExpression | Kind::ClassDeclaration | Kind::ClassExpression
    ) {
        if let Some(id) = node.f("id").filter(|id| id.is_identifier()) {
            return id.name().map(String::from);
        }
    }
    if matches!(node.kind(), Kind::ClassMethod | Kind::ClassPrivateMethod | Kind::ObjectMethod) {
        let key = node.f("key");
        if let Some(key) = key.filter(|key| key.is(Kind::PrivateName)) {
            return Some(format!("#{}", key.f("id").and_then(|id| id.name()).unwrap_or("")));
        }
        // `{[key]() {}}` names nothing statically; reading `key` off the key node would report
        // the variable name as the method name. `{[""]() {}}` names the exact empty key, which is
        // retained rather than replaced.
        return Some(
            key.and_then(|key| static_property_key(key, node.flag("computed")))
                .unwrap_or_else(|| format!("[computed@{}]", node.start())),
        );
    }
    if let Some(parent) = parent {
        if parent.is(Kind::VariableDeclarator) {
            if let Some(id) = parent.f("id").filter(|id| id.is_identifier()) {
                return id.name().map(String::from);
            }
        }
    }
    None
}

fn collect_imports<'a>(node: N<'a>, state: &mut SemanticAnalysisState<'a>) {
    let specifier_text: Option<String> = node.f("source").and_then(|source| source.str("value")).map(String::from);
    let specifiers = node.nodes("specifiers");
    if specifiers.is_empty() {
        add_module_link(
            state,
            SemanticModuleLink {
                kind: "import".into(),
                specifier: specifier_text.clone(),
                imported_name: None,
                local_name: None,
                exported_name: None,
                callable_id: None,
                location: node.loc(),
            },
            node,
        );
    }
    for specifier in specifiers {
        let imported_name = match specifier.kind() {
            Kind::ImportDefaultSpecifier => "default".to_string(),
            Kind::ImportNamespaceSpecifier => "*".to_string(),
            _ => specifier.f("imported").map(property_name).unwrap_or_default(),
        };
        add_module_link(
            state,
            SemanticModuleLink {
                kind: "import".into(),
                specifier: specifier_text.clone(),
                imported_name: Some(imported_name),
                local_name: specifier.f("local").and_then(|local| local.name()).map(String::from),
                exported_name: None,
                callable_id: None,
                location: specifier.loc(),
            },
            node,
        );
    }
}

fn collect_named_exports<'a>(node: N<'a>, state: &mut SemanticAnalysisState<'a>) {
    if let Some(declaration) = node.f("declaration") {
        for local_name in declaration_names(declaration) {
            let callable_id = declaration_callable_id(declaration, &local_name);
            add_module_link(
                state,
                SemanticModuleLink {
                    kind: "export".into(),
                    specifier: None,
                    imported_name: None,
                    local_name: Some(local_name.clone()),
                    exported_name: Some(local_name),
                    callable_id,
                    location: declaration.loc(),
                },
                node,
            );
        }
    }
    let source = node.f("source");
    for specifier in node.nodes("specifiers") {
        if !specifier.is(Kind::ExportSpecifier) {
            continue;
        }
        let local = specifier.f("local").map(property_name).unwrap_or_default();
        add_module_link(
            state,
            SemanticModuleLink {
                kind: if source.is_none() { "export" } else { "re-export" }.into(),
                specifier: source.and_then(|s| s.str("value")).map(String::from),
                imported_name: Some(local.clone()),
                local_name: if source.is_none() { Some(local) } else { None },
                exported_name: Some(specifier.f("exported").map(property_name).unwrap_or_default()),
                callable_id: None,
                location: specifier.loc(),
            },
            node,
        );
    }
}

fn collect_require_link<'a>(node: N<'a>, state: &mut SemanticAnalysisState<'a>) {
    let Some(origin) = semantic_require_origin(node.f("init"), state) else { return };
    let Some(id) = node.f("id") else { return };
    for (imported_name, local_name) in require_pattern_bindings(id, &origin.imported_path) {
        add_module_link(
            state,
            SemanticModuleLink {
                kind: "require".into(),
                specifier: Some(origin.specifier.clone()),
                imported_name: Some(imported_name),
                local_name: Some(local_name),
                exported_name: None,
                callable_id: None,
                location: node.loc(),
            },
            node,
        );
    }
}

/// `(importedName, localName)` pairs introduced by a require destructuring pattern.
fn require_pattern_bindings(pattern: N<'_>, path: &[String]) -> Vec<(String, String)> {
    match pattern.kind() {
        Kind::TSParameterProperty => pattern
            .f("parameter")
            .map(|parameter| require_pattern_bindings(parameter, path))
            .unwrap_or_default(),
        Kind::Identifier => vec![(
            path.last().cloned().unwrap_or_else(|| "*".into()),
            pattern.name().unwrap_or("").to_string(),
        )],
        Kind::AssignmentPattern => {
            pattern.f("left").map(|left| require_pattern_bindings(left, path)).unwrap_or_default()
        }
        Kind::ObjectPattern => {
            let mut out = Vec::new();
            for property in pattern.nodes("properties") {
                if property.is(Kind::RestElement) {
                    continue;
                }
                let Some(name) = property.f("key").and_then(|key| static_property_key(key, property.flag("computed")))
                else {
                    continue;
                };
                let mut next = path.to_vec();
                next.push(name);
                if let Some(value) = property.f("value") {
                    out.extend(require_pattern_bindings(value, &next));
                }
            }
            out
        }
        Kind::ArrayPattern => {
            let mut out = Vec::new();
            for (index, element) in pattern.list("elements").into_iter().enumerate() {
                let Some(element) = element else { continue };
                let mut next = path.to_vec();
                next.push(index.to_string());
                out.extend(require_pattern_bindings(element, &next));
            }
            out
        }
        _ => Vec::new(),
    }
}

fn collect_commonjs_export<'a>(node: N<'a>, state: &mut SemanticAnalysisState<'a>) {
    let Some(left) = node.f("left") else { return };
    let Some(exported_name) = commonjs_export_name(left, state) else { return };
    let right = node.f("right");
    let origin = semantic_require_origin(right, state);
    add_module_link(
        state,
        SemanticModuleLink {
            kind: "commonjs-export".into(),
            specifier: origin.as_ref().map(|o| o.specifier.clone()),
            imported_name: origin.as_ref().and_then(|o| o.imported_path.last().cloned()),
            local_name: right.filter(|r| r.is_identifier()).and_then(|r| r.name()).map(String::from),
            exported_name: Some(exported_name),
            callable_id: right.and_then(semantic_callable_id_for_node),
            location: node.loc(),
        },
        node,
    );
}

fn add_module_link<'a>(
    state: &mut SemanticAnalysisState<'a>,
    link: SemanticModuleLink,
    reference_node: N<'a>,
) {
    let local_name = link.local_name.clone();
    state.module_links.push(link);
    if let Some(local_name) = local_name {
        if let Some(binding) = resolve_semantic_binding_state(state, reference_node, &local_name) {
            let index = state.module_links.len() - 1;
            state.module_link_bindings.insert(index, binding);
        }
    }
}

/// Deterministic callable identity shared by collection and return recovery.
pub fn semantic_callable_id_for_node(node: N<'_>) -> Option<String> {
    callable_kind(node).map(|kind| format!("callable:{kind}:{}:{}", node.start(), node.end()))
}

fn declaration_callable_id(declaration: N<'_>, local_name: &str) -> Option<String> {
    if matches!(declaration.kind(), Kind::FunctionDeclaration | Kind::ClassDeclaration)
        && declaration.f("id").and_then(|id| id.name()) == Some(local_name)
    {
        return semantic_callable_id_for_node(declaration);
    }
    if !declaration.is(Kind::VariableDeclaration) {
        return None;
    }
    let declarator = declaration
        .nodes("declarations")
        .into_iter()
        .find(|declarator| is_identifier_named(declarator.f("id"), local_name))?;
    declarator.f("init").and_then(semantic_callable_id_for_node)
}

/// True when writing `node` also reads it first: a compound assignment (`+=`, `||=`, ...) or an
/// update (`++`/`--`). A plain `=` writes only.
pub fn semantic_reads_before_write(node: N<'_>, parent: N<'_>) -> bool {
    (parent.is(Kind::AssignmentExpression)
        && parent.f("left") == Some(node)
        && parent.str("operator") != Some("="))
        || (parent.is(Kind::UpdateExpression) && parent.f("argument") == Some(node))
}

/// Role of one identifier occurrence, given the node's ancestry. See the TS commentary: a binding
/// inside a destructuring pattern has an ObjectProperty/ArrayPattern as its direct parent, so the
/// ancestry decides between a declaration and an assignment target.
pub fn semantic_identifier_role(node: N<'_>, parent: N<'_>) -> Option<&'static str> {
    let ancestors = read_ancestors(node);
    let patterns: Vec<N<'_>> = ancestors.into_iter().filter(|a| is_pattern_node(*a)).collect();
    semantic_identifier_role_with_patterns(node, parent, &patterns)
}

/// [`semantic_identifier_role`] with the pattern-node ancestors (outermost first) already known.
fn semantic_identifier_role_with_patterns<'a>(
    node: N<'a>,
    parent: N<'a>,
    patterns: &[N<'a>],
) -> Option<&'static str> {
    if let Some(pattern_ancestor) = enclosing_pattern_ancestor(node, parent, patterns) {
        if is_pattern_owner_declaration(pattern_ancestor) {
            return None;
        }
        return Some("write");
    }
    semantic_reference_role(node, parent)
}

/// The nearest ancestor that owns this identifier as a *bound* pattern slot, or `None` when the
/// identifier is not being bound.
fn enclosing_pattern_ancestor<'a>(node: N<'a>, parent: N<'a>, patterns: &[N<'a>]) -> Option<N<'a>> {
    for &ancestor in patterns.iter().rev() {
        if !binds_identifier(ancestor, parent, node) {
            continue;
        }
        // Found the binding slot; now find what owns the pattern.
        let mut owner = ancestor.parent();
        while let Some(candidate) = owner {
            if matches!(
                candidate.kind(),
                Kind::AssignmentExpression | Kind::ForInStatement | Kind::ForOfStatement
            ) {
                return Some(candidate);
            }
            if is_pattern_owner_declaration(candidate) {
                return Some(candidate);
            }
            owner = candidate.parent();
        }
        return None;
    }
    None
}

/// True when `parent` places `node` in the bound slot of `pattern`.
fn binds_identifier(pattern: N<'_>, parent: N<'_>, node: N<'_>) -> bool {
    // The identifier sits directly in the pattern: `[b]`, `({b})`, `{b = 1}`.
    if parent == pattern {
        return pattern_contains(pattern, node);
    }
    match pattern.kind() {
        Kind::ObjectPattern => {
            parent.is(Kind::ObjectProperty)
                && (parent.f("value") == Some(node)
                    || (parent.flag("shorthand") && parent.f("key") == Some(node)))
        }
        Kind::ArrayPattern => pattern.list("elements").into_iter().any(|element| element == Some(parent)),
        Kind::AssignmentPattern => pattern.f("left") == Some(parent),
        Kind::RestElement => pattern.f("argument") == Some(parent),
        _ => false,
    }
}

fn is_pattern_node(node: N<'_>) -> bool {
    matches!(
        node.kind(),
        Kind::ObjectPattern | Kind::ArrayPattern | Kind::AssignmentPattern | Kind::RestElement
    )
}

fn is_pattern_owner_declaration(node: N<'_>) -> bool {
    (node.is(Kind::VariableDeclarator) && node.f("id").is_some_and(|id| id.has_alias(Alias::Pattern)))
        || (node.is_function()
            && node.nodes("params").into_iter().any(|parameter| parameter.has_alias(Alias::Pattern)))
        || (node.is(Kind::CatchClause) && node.f("param").is_some_and(|param| param.has_alias(Alias::Pattern)))
}

/// Classify one identifier occurrence consistently with semantic references.
pub fn semantic_reference_role(node: N<'_>, parent: N<'_>) -> Option<&'static str> {
    if is_declaration_identifier(node, parent) || is_non_reference_key(node, parent) {
        return None;
    }
    if (parent.is(Kind::AssignmentExpression) && parent.f("left") == Some(node))
        || parent.is(Kind::UpdateExpression)
        || ((parent.is(Kind::ForInStatement) || parent.is(Kind::ForOfStatement)) && parent.f("left") == Some(node))
    {
        return Some("write");
    }
    if parent.is(Kind::ExportSpecifier) && parent.f("local") == Some(node) {
        return Some("export");
    }
    Some("read")
}

fn is_declaration_identifier(node: N<'_>, parent: N<'_>) -> bool {
    (parent.is(Kind::VariableDeclarator) && parent.f("id").is_some_and(|id| pattern_contains(id, node)))
        || (matches!(parent.kind(), Kind::FunctionDeclaration | Kind::FunctionExpression)
            && parent.f("id") == Some(node))
        || (parent.is_function()
            && parent.nodes("params").into_iter().any(|value| pattern_contains(value, node)))
        || (matches!(parent.kind(), Kind::ClassDeclaration | Kind::ClassExpression)
            && parent.f("id") == Some(node))
        || (parent.is(Kind::ImportSpecifier)
            && (parent.f("local") == Some(node) || parent.f("imported") == Some(node)))
        || (parent.is(Kind::ImportDefaultSpecifier) && parent.f("local") == Some(node))
        || (parent.is(Kind::ImportNamespaceSpecifier) && parent.f("local") == Some(node))
        || (parent.is(Kind::CatchClause) && parent.f("param") == Some(node))
}

fn is_non_reference_key(node: N<'_>, parent: N<'_>) -> bool {
    (parent.is_member() && parent.f("property") == Some(node) && !parent.flag("computed"))
        || ((parent.is(Kind::ObjectProperty) || parent.is(Kind::ObjectMethod))
            && parent.f("key") == Some(node)
            && !parent.flag("computed")
            && !(parent.is(Kind::ObjectProperty) && parent.flag("shorthand")))
        || (parent.is(Kind::ExportSpecifier) && parent.f("exported") == Some(node))
        || parent.is(Kind::LabeledStatement)
        || parent.is(Kind::BreakStatement)
        || parent.is(Kind::ContinueStatement)
}

fn pattern_names(pattern: N<'_>) -> Vec<String> {
    match pattern.kind() {
        Kind::TSParameterProperty => pattern.f("parameter").map(pattern_names).unwrap_or_default(),
        Kind::Identifier => vec![pattern.name().unwrap_or("").to_string()],
        Kind::AssignmentPattern => pattern.f("left").map(pattern_names).unwrap_or_default(),
        Kind::RestElement => pattern.f("argument").map(pattern_names).unwrap_or_default(),
        Kind::ObjectPattern => pattern
            .nodes("properties")
            .into_iter()
            .flat_map(|property| {
                let target =
                    if property.is(Kind::RestElement) { property.f("argument") } else { property.f("value") };
                target.map(pattern_names).unwrap_or_default()
            })
            .collect(),
        Kind::ArrayPattern => pattern
            .list("elements")
            .into_iter()
            .flat_map(|element| element.map(pattern_names).unwrap_or_default())
            .collect(),
        _ => Vec::new(),
    }
}

/// `patternContains(pattern, target)`.
fn pattern_contains(pattern: N<'_>, target: N<'_>) -> bool {
    let mut pending = vec![pattern];
    while let Some(current) = pending.pop() {
        if current == target {
            return true;
        }
        match current.kind() {
            Kind::AssignmentPattern => pending.extend(current.f("left")),
            Kind::RestElement => pending.extend(current.f("argument")),
            Kind::ObjectPattern => {
                for property in current.nodes("properties") {
                    if property.is(Kind::RestElement) {
                        pending.extend(property.f("argument"));
                    } else {
                        pending.extend(property.f("value"));
                    }
                }
            }
            Kind::ArrayPattern => pending.extend(current.list("elements").into_iter().flatten()),
            _ => {}
        }
    }
    false
}

fn declaration_names(declaration: N<'_>) -> Vec<String> {
    if declaration.is(Kind::VariableDeclaration) {
        return declaration
            .nodes("declarations")
            .into_iter()
            .flat_map(|declarator| declarator.f("id").map(pattern_names).unwrap_or_default())
            .collect();
    }
    if matches!(declaration.kind(), Kind::FunctionDeclaration | Kind::ClassDeclaration) {
        if let Some(id) = declaration.f("id").filter(|id| id.is_identifier()) {
            return vec![id.name().unwrap_or("").to_string()];
        }
    }
    Vec::new()
}

fn default_declaration_name(declaration: N<'_>) -> Option<String> {
    if matches!(declaration.kind(), Kind::FunctionDeclaration | Kind::ClassDeclaration) {
        if let Some(id) = declaration.f("id").filter(|id| id.is_identifier()) {
            return id.name().map(String::from);
        }
    }
    None
}

fn commonjs_export_name(node: N<'_>, state: &SemanticAnalysisState<'_>) -> Option<String> {
    if is_unshadowed_global(node, state, "exports") {
        return Some("default".into());
    }
    if !node.is_member() {
        return None;
    }
    let computed = node.flag("computed");
    let key = node.f("property").and_then(|property| static_property_key(property, computed));
    let object = node.f("object")?;
    // `exports[key]`/`module.exports[key]` assign an export whose name is not knowable. Report
    // the wildcard rather than the variable name, and never collapse it into `default`, which
    // would claim a real default export.
    if is_unshadowed_global(object, state, "exports") {
        return Some(match key {
            None => "*".into(),
            Some(key) if key.is_empty() => "*".into(),
            Some(key) => key,
        });
    }
    if object.is(Kind::MemberExpression) {
        let inner_object = object.f("object");
        let inner_key = object
            .f("property")
            .and_then(|property| static_property_key(property, object.flag("computed")));
        if inner_object.is_some_and(|inner| is_unshadowed_global(inner, state, "module"))
            && inner_key.as_deref() == Some("exports")
        {
            return Some(match key {
                None => "*".into(),
                Some(key) if key.is_empty() => "default".into(),
                Some(key) => key,
            });
        }
    }
    if is_unshadowed_global(object, state, "module") && key.as_deref() == Some("exports") {
        return Some("default".into());
    }
    None
}
