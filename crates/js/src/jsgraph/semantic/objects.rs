//! Port of `javascriptSemanticObjects.ts`: bounded static property reads, writes, spreads and
//! destructuring.

use std::collections::HashSet;

use crate::jsgraph::ast::{Kind, N};
use crate::jsgraph::ast_values::{static_property_key, unwrap_expression};
use crate::jsgraph::ir::{SemanticCallable, SemanticObjectOperation};

use super::data_effect_helpers::traverse_data_effects;
use super::projection::semantic_reads_before_write;
use super::state::{resolve_semantic_binding_state, SemanticAnalysisState};

/// Recover bounded static property reads, writes, spreads, and destructuring
/// (`collectJavaScriptSemanticObjects`).
pub fn collect_semantic_objects<'a>(
    root: N<'a>,
    state: &SemanticAnalysisState<'a>,
    callables: &[SemanticCallable],
) -> Vec<SemanticObjectOperation> {
    let mut output = Vec::new();
    let callable_ids: HashSet<String> = callables.iter().map(|callable| callable.callable_id.clone()).collect();
    traverse_data_effects(root, &callable_ids, |node, parent, owner| {
        let owner = owner.map(String::from);
        if node.is_member() {
            collect_member(node, parent, owner, state, &mut output);
        } else if node.is(Kind::SpreadElement) && parent.is_some_and(|parent| parent.is(Kind::ObjectExpression)) {
            let identity = expression_object_identity(node.f("argument"), state);
            add_object_operation(
                AddObjectOperation {
                    node,
                    kind: "spread",
                    owner_callable_id: owner,
                    object_binding_id: identity.binding_id,
                    target_binding_id: None,
                    property_path: identity.path,
                },
                &mut output,
            );
        } else if node.is(Kind::VariableDeclarator)
            && node
                .f("id")
                .is_some_and(|id| id.is(Kind::ObjectPattern) || id.is(Kind::ArrayPattern))
        {
            collect_destructuring(node, owner, state, &mut output);
        }
    });
    output
}

fn collect_member<'a>(
    node: N<'a>,
    parent: Option<N<'a>>,
    owner_callable_id: Option<String>,
    state: &SemanticAnalysisState<'a>,
    output: &mut Vec<SemanticObjectOperation>,
) {
    // A chain is one property access; retaining every prefix duplicates work and would make full
    // paths quadratic in deeply nested producer expressions.
    if parent.is_some_and(|parent| parent.is_member() && parent.f("object") == Some(node)) {
        return;
    }
    let identity = expression_object_identity(Some(node), state);
    let write = parent.is_some_and(|parent| {
        (parent.is(Kind::AssignmentExpression) && parent.f("left") == Some(node))
            || (parent.is(Kind::UpdateExpression) && parent.f("argument") == Some(node))
    });
    let reads_before_write = write && parent.is_some_and(|parent| semantic_reads_before_write(node, parent));
    if reads_before_write {
        add_object_operation(
            AddObjectOperation {
                node,
                kind: "read",
                owner_callable_id: owner_callable_id.clone(),
                object_binding_id: identity.binding_id.clone(),
                target_binding_id: None,
                property_path: identity.path.clone(),
            },
            output,
        );
    }
    add_object_operation(
        AddObjectOperation {
            node,
            kind: if write { "write" } else { "read" },
            owner_callable_id,
            object_binding_id: identity.binding_id,
            target_binding_id: None,
            property_path: identity.path,
        },
        output,
    );
}

fn collect_destructuring<'a>(
    node: N<'a>,
    owner_callable_id: Option<String>,
    state: &SemanticAnalysisState<'a>,
    output: &mut Vec<SemanticObjectOperation>,
) {
    let source = expression_object_identity(node.f("init"), state);
    if let Some(id) = node.f("id") {
        visit_destructuring(id, &[], &source, &owner_callable_id, state, output);
    }
}

fn visit_destructuring<'a>(
    pattern: N<'a>,
    path: &[String],
    source: &ObjectIdentity,
    owner_callable_id: &Option<String>,
    state: &SemanticAnalysisState<'a>,
    output: &mut Vec<SemanticObjectOperation>,
) {
    if pattern.is(Kind::ObjectPattern) {
        for property in pattern.nodes("properties") {
            if !property.is(Kind::ObjectProperty) {
                continue;
            }
            let Some(key) = property.f("key") else { continue };
            if let Some(name) = static_property_key(key, property.flag("computed")) {
                if let Some(value) = property.f("value") {
                    let mut next = path.to_vec();
                    next.push(name);
                    visit_destructuring(value, &next, source, owner_callable_id, state, output);
                }
            }
        }
        return;
    }
    if pattern.is(Kind::ArrayPattern) {
        for (index, element) in pattern.list("elements").into_iter().enumerate() {
            if let Some(element) = element {
                if !element.is(Kind::RestElement) {
                    let mut next = path.to_vec();
                    next.push(index.to_string());
                    visit_destructuring(element, &next, source, owner_callable_id, state, output);
                }
            }
        }
        return;
    }
    let Some(target) = binding_identifier(pattern) else { return };
    let target_binding_id = resolve_semantic_binding_state(state, target, target.name().unwrap_or(""))
        .map(|ix| state.bindings[ix].binding_id.clone());
    add_object_operation(
        AddObjectOperation {
            node: pattern,
            kind: "destructure",
            owner_callable_id: owner_callable_id.clone(),
            object_binding_id: source.binding_id.clone(),
            target_binding_id,
            property_path: source.path.as_ref().map(|base| base.iter().cloned().chain(path.iter().cloned()).collect()),
        },
        output,
    );
}

struct AddObjectOperation<'a> {
    node: N<'a>,
    kind: &'static str,
    owner_callable_id: Option<String>,
    object_binding_id: Option<String>,
    target_binding_id: Option<String>,
    property_path: Option<Vec<String>>,
}

fn add_object_operation(input: AddObjectOperation<'_>, output: &mut Vec<SemanticObjectOperation>) {
    let partial = input.object_binding_id.is_none()
        || input.property_path.is_none()
        || (input.kind == "destructure" && input.target_binding_id.is_none());
    output.push(SemanticObjectOperation {
        object_operation_id: format!("object:{}:{}:{}", input.kind, input.node.start(), input.node.end()),
        kind: input.kind.into(),
        location: input.node.loc(),
        owner_callable_id: input.owner_callable_id,
        object_binding_id: input.object_binding_id,
        target_binding_id: input.target_binding_id,
        property_path: input.property_path,
        resolution: if partial { "partial" } else { "complete" }.into(),
    });
}

struct ObjectIdentity {
    binding_id: Option<String>,
    path: Option<Vec<String>>,
}

fn expression_object_identity<'a>(node: Option<N<'a>>, state: &SemanticAnalysisState<'a>) -> ObjectIdentity {
    let mut path: Vec<String> = Vec::new();
    let mut current = node;
    let mut static_path = true;
    while let Some(candidate) = current {
        let unwrapped = unwrap_expression(candidate).0;
        current = Some(unwrapped);
        if unwrapped.is_member() {
            let name = unwrapped.f("property").and_then(|property| static_property_key(property, unwrapped.flag("computed")));
            match name {
                None => static_path = false,
                Some(name) => path.push(name),
            }
            current = unwrapped.f("object");
        } else {
            break;
        }
    }
    let binding_id = current.filter(|node| node.is_identifier()).and_then(|identifier| {
        resolve_semantic_binding_state(state, identifier, identifier.name().unwrap_or(""))
            .map(|ix| state.bindings[ix].binding_id.clone())
    });
    ObjectIdentity {
        binding_id,
        path: static_path.then(|| {
            path.reverse();
            path
        }),
    }
}

fn binding_identifier<'a>(node: N<'a>) -> Option<N<'a>> {
    if node.is_identifier() {
        return Some(node);
    }
    if node.is(Kind::AssignmentPattern) {
        return node.f("left").filter(|left| left.is_identifier());
    }
    None
}
