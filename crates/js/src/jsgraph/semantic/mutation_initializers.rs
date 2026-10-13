//! Port of `javascriptSemanticMutationInitializers.ts`: statement-order reasoning that decides
//! which initializers a mutation or capture can observe.

use crate::jsgraph::ast::{Kind, NodeId, N};
use crate::jsgraph::ast_values::{static_property_key, unwrap_expression};

use super::state::BindingState;

/// Where a statement sits in its `body` list. `body` is the owning Program/BlockStatement id
/// (the identity of its `body` array).
#[derive(Clone, Copy, Debug)]
pub struct StatementPosition {
    body: NodeId,
    index: isize,
    declarator_index: isize,
}

fn statement_position(statement: N<'_>, declarator: Option<N<'_>>) -> Option<StatementPosition> {
    let parent = statement.parent()?;
    if !parent.is(Kind::Program) && !parent.is(Kind::BlockStatement) {
        return None;
    }
    let index = parent.nodes("body").iter().position(|candidate| *candidate == statement)?;
    let declarator_index = match declarator {
        Some(declarator) if statement.is(Kind::VariableDeclaration) => statement
            .nodes("declarations")
            .iter()
            .position(|candidate| *candidate == declarator)
            .map_or(-1, |position| position as isize),
        _ => -1,
    };
    Some(StatementPosition { body: parent.id, index: index as isize, declarator_index })
}

fn position_precedes(left: StatementPosition, right: StatementPosition) -> bool {
    left.body == right.body
        && (left.index < right.index
            || (left.index == right.index
                && left.declarator_index >= 0
                && left.declarator_index < right.declarator_index))
}

fn direct_initializer_position(node: N<'_>) -> Option<StatementPosition> {
    let parent = node.parent()?;
    if parent.is(Kind::VariableDeclarator) && parent.f("init") == Some(node) {
        let declaration = parent.parent()?;
        return if declaration.is(Kind::VariableDeclaration) {
            statement_position(declaration, Some(parent))
        } else {
            None
        };
    }
    if parent.is(Kind::AssignmentExpression)
        && parent.str("operator") == Some("=")
        && parent.f("right") == Some(node)
        && parent.f("left").is_some_and(|left| left.is_identifier())
    {
        let statement = parent.parent()?;
        return if statement.is(Kind::ExpressionStatement) && statement.f("expression") == Some(parent) {
            statement_position(statement, None)
        } else {
            None
        };
    }
    None
}

fn direct_mutation_position(node: N<'_>) -> Option<StatementPosition> {
    if node.is(Kind::ForOfStatement) {
        return statement_position(node, None);
    }
    if node.is(Kind::VariableDeclarator) {
        let declaration = node.parent()?;
        return if declaration.is(Kind::VariableDeclaration) {
            statement_position(declaration, Some(node))
        } else {
            None
        };
    }
    if node.is(Kind::SpreadElement) {
        let array = node.parent()?;
        return if array.is(Kind::ArrayExpression) { semantic_capture_position(array) } else { None };
    }
    let delete_unary = node.is(Kind::UnaryExpression) && node.str("operator") == Some("delete");
    if !node.is(Kind::AssignmentExpression)
        && !node.is(Kind::UpdateExpression)
        && !delete_unary
        && !node.is(Kind::CallExpression)
        && !node.is(Kind::OptionalCallExpression)
        && !node.is(Kind::NewExpression)
        && !node.is(Kind::TaggedTemplateExpression)
    {
        return None;
    }
    let mut current = node;
    loop {
        let parent = current.parent()?;
        if parent.is_function()
            || (parent.is(Kind::LogicalExpression) && parent.f("right") == Some(current))
            || (parent.is(Kind::ConditionalExpression) && parent.f("test") != Some(current))
        {
            return None;
        }
        if parent.has_alias(crate::jsgraph::ast::Alias::Statement) {
            return statement_position(parent, None);
        }
        if parent.is(Kind::VariableDeclarator) {
            let declaration = parent.parent()?;
            return if declaration.is(Kind::VariableDeclaration) {
                statement_position(declaration, Some(parent))
            } else {
                None
            };
        }
        current = parent;
    }
}

fn reference_initializer_position(node: N<'_>) -> Option<StatementPosition> {
    // Defaults live inside the declaration pattern rather than its initializer.
    let mut current = node;
    loop {
        if let Some(direct) = direct_initializer_position(current) {
            return Some(direct);
        }
        let parent = current.parent()?;
        if parent.has_alias(crate::jsgraph::ast::Alias::Statement) || parent.is_function() {
            return None;
        }
        if parent.is(Kind::VariableDeclarator) {
            let declaration = parent.parent()?;
            return if declaration.is(Kind::VariableDeclaration) {
                statement_position(declaration, Some(parent))
            } else {
                None
            };
        }
        current = parent;
    }
}

/// Indices into `binding.initializers` and `binding.reference_initializers` that a mutation can
/// observe. When the position cannot be proven the whole binding is returned.
pub struct MutationInitializerSelection {
    pub initializers: Vec<usize>,
    pub reference_initializers: Vec<usize>,
}

/// Resolve origins at their use or capture, never at a later transitive effect.
pub fn semantic_mutation_initializers(
    binding: &BindingState<'_>,
    mutation: N<'_>,
) -> MutationInitializerSelection {
    let everything = || MutationInitializerSelection {
        initializers: (0..binding.initializers.len()).collect(),
        reference_initializers: (0..binding.reference_initializers.len()).collect(),
    };
    let Some(mutation_position) =
        direct_mutation_position(mutation).or_else(|| reference_initializer_position(mutation))
    else {
        return everything();
    };
    // (is a plain initializer, index, position)
    let mut origins: Vec<(bool, usize, StatementPosition)> = Vec::new();
    for (index, initializer) in binding.initializers.iter().enumerate() {
        let position = match initializer.entry_body {
            None => direct_initializer_position(initializer.node),
            Some(entry) => {
                Some(StatementPosition { body: entry.id, index: -1, declarator_index: -1 })
            }
        };
        let Some(position) = position else { return everything() };
        origins.push((true, index, position));
    }
    for (index, initializer) in binding.reference_initializers.iter().enumerate() {
        let Some(position) = reference_initializer_position(initializer.node) else {
            return everything();
        };
        origins.push((false, index, position));
    }
    if origins.iter().any(|(_, _, position)| !position_precedes(*position, mutation_position)) {
        return everything();
    }
    let mut latest: Option<StatementPosition> = None;
    for (_, _, position) in &origins {
        if latest.is_none_or(|current| position_precedes(current, *position)) {
            latest = Some(*position);
        }
    }
    let retained = |is_plain: bool| -> Vec<usize> {
        origins
            .iter()
            .filter(|(plain, _, position)| {
                *plain == is_plain
                    && latest.is_some_and(|l| position.index == l.index && position.declarator_index == l.declarator_index)
            })
            .map(|(_, index, _)| *index)
            .collect()
    };
    MutationInitializerSelection { initializers: retained(true), reference_initializers: retained(false) }
}

/// Locate a capture only in an unconditional declaration or literal initializer.
pub fn semantic_capture_position(node: N<'_>) -> Option<StatementPosition> {
    let mut current = node;
    loop {
        if let Some(direct) = direct_initializer_position(current) {
            return Some(direct);
        }
        let parent = current.parent()?;
        let static_property_value = parent.is(Kind::ObjectProperty)
            && parent.f("value") == Some(current)
            && parent
                .f("key")
                .and_then(|key| static_property_key(key, parent.flag("computed")))
                .is_some();
        if static_property_value || parent.is(Kind::ObjectExpression) || parent.is(Kind::ArrayExpression) {
            current = parent;
        } else {
            return None;
        }
    }
}

/// Intermediate values must themselves have been initialized before capture.
pub fn semantic_binding_precedes_capture(binding: &BindingState<'_>, capture: N<'_>) -> bool {
    if binding.initializers.len() != 1 {
        return false;
    }
    let initializer = &binding.initializers[0];
    let source_position = direct_initializer_position(initializer.node);
    let capture_position = semantic_capture_position(capture);
    match (source_position, capture_position) {
        (Some(source), Some(capture)) => position_precedes(source, capture),
        _ => false,
    }
}

/// Ignore later escapes only while reading earlier references in one activation.
pub fn semantic_escape_follows_capture(
    binding: &BindingState<'_>,
    capture: N<'_>,
    escape: Option<N<'_>>,
) -> bool {
    let Some(escape) = escape else { return false };
    let Some(initializer) = binding.initializers.first() else { return false };
    if !semantic_binding_precedes_capture(binding, capture) {
        return false;
    }
    // A literal allocates here. Aliases are evaluated at the same capture point, so an
    // outer/persistent origin still receives all of its own escape effects.
    let origin = unwrap_expression(initializer.node).0;
    if !origin.is(Kind::ObjectExpression)
        && !origin.is(Kind::ArrayExpression)
        && !origin.is(Kind::Identifier)
        && !origin.is(Kind::MemberExpression)
        && !origin.is(Kind::OptionalMemberExpression)
    {
        return false;
    }
    match (semantic_capture_position(capture), direct_mutation_position(escape)) {
        (Some(capture_position), Some(escape_position)) => position_precedes(capture_position, escape_position),
        _ => false,
    }
}
