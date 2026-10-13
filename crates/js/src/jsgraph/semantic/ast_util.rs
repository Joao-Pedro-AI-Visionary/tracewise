//! Small AST helpers shared by the semantic modules (`stringValue`, `t.isIdentifier(node,
//! {name})`, key conversions).

use crate::jsgraph::ast::N;
use crate::jsgraph::ast_values::{read_exact_literal, static_property_key, unwrap_expression};
use crate::jsgraph::ir::Primitive;

use super::property_paths::PathKey;

/// `stringValue(node)`: an exact string literal value.
pub fn string_value(node: Option<N<'_>>) -> Option<String> {
    match read_exact_literal(node?) {
        Some(Primitive::Str(text)) => Some(text),
        _ => None,
    }
}

/// `t.isIdentifier(node, { name })` for an optional node.
pub fn is_identifier_named(node: Option<N<'_>>, name: &str) -> bool {
    node.is_some_and(|n| n.is_identifier() && n.name() == Some(name))
}

/// `semanticStaticPropertyKey(property, computed)` as a path key (`null` when dynamic).
pub fn static_key_path(property: N<'_>, computed: bool) -> PathKey {
    match static_property_key(property, computed) {
        Some(name) => PathKey::Name(name),
        None => PathKey::Null,
    }
}

/// `unwrapJavaScriptExpression(node).node`.
pub fn unwrapped<'a>(node: N<'a>) -> N<'a> {
    unwrap_expression(node).0
}

/// `(start, end)` of an optional node, for identity keys (`node?.start`, `node?.end`).
pub fn span_of(node: Option<N<'_>>) -> Option<(u32, u32)> {
    node.map(|n| (n.start(), n.end()))
}
