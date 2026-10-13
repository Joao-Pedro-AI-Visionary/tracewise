//! Port of `electronStaticAnalysisValues.ts`.

use super::super::ast::{Kind, N};
use super::super::ast_values::{read_exact_literal, static_property_name};
use super::super::ir::{JsNumber, Primitive};
use super::super::static_types::ElectronStaticValue;
use super::helpers::{callee_name, js_trim, sorted_set};
use super::state::Ctx;

/// `electronCalleeName`: name a callee, spelling a root renamed from Electron as its export.
pub fn electron_callee_name(callee: N<'_>, ctx: &Ctx<'_>) -> String {
    let name = callee_name(callee);
    let mut root = callee;
    while root.is_member() {
        match root.f("object") {
            Some(object) => root = object,
            None => return name,
        }
    }
    if !root.is_identifier() {
        return name;
    }
    match ctx.electron_bindings.get(&root.start()) {
        None => name,
        Some(exported) => {
            let root_name = root.name().unwrap_or("");
            // `name.slice(root.name.length)`: the dotted name starts with the root identifier.
            let rest = name.strip_prefix(root_name).unwrap_or("");
            format!("{exported}{rest}")
        }
    }
}

/// `electronStaticValue`: preserve one literal value or the exact inert expression.
pub fn electron_static_value(node: Option<N<'_>>) -> ElectronStaticValue {
    match literal_value(node) {
        Some(value) => ElectronStaticValue { status: "literal".into(), value, expression: None },
        None => ElectronStaticValue {
            status: "dynamic".into(),
            value: Primitive::Null,
            expression: Some(bounded_expression(node)),
        },
    }
}

/// `boundedExpression`: an actionable expression without evaluating it.
pub fn bounded_expression(node: Option<N<'_>>) -> String {
    let Some(node) = node else { return "[missing-expression]".into() };
    let expression = js_trim(node.text());
    if expression.is_empty() {
        format!("[{}]", node.kind().as_str())
    } else {
        expression.to_string()
    }
}

/// Result of [`object_property`].
pub enum ObjectProperty<'a> {
    Missing,
    Dynamic,
    Explicit(N<'a>),
}

/// `objectProperty`: the effective explicit property, preserving unresolved overrides.
pub fn object_property<'a>(object: Option<N<'a>>, name: &str) -> ObjectProperty<'a> {
    let Some(object) = object else { return ObjectProperty::Missing };
    if !object.is(Kind::ObjectExpression) {
        return ObjectProperty::Dynamic;
    }
    for property in object.nodes("properties").into_iter().rev() {
        if property.is(Kind::SpreadElement) {
            return ObjectProperty::Dynamic;
        }
        let Some(key_node) = property.f("key") else { return ObjectProperty::Dynamic };
        let key = static_property_name(key_node, property.flag("computed"));
        if key.is_empty() && !key_node.is_string_literal() {
            return ObjectProperty::Dynamic;
        }
        if key != name {
            continue;
        }
        return if property.is(Kind::ObjectProperty) {
            ObjectProperty::Explicit(property)
        } else {
            ObjectProperty::Dynamic
        };
    }
    ObjectProperty::Missing
}

/// `handlerKind`.
pub fn handler_kind(node: N<'_>) -> &'static str {
    if matches!(
        node.kind(),
        Kind::ArrowFunctionExpression | Kind::FunctionExpression | Kind::FunctionDeclaration
    ) {
        "inline-function"
    } else if node.is_identifier() {
        "identifier"
    } else if node.is_member() {
        "member-expression"
    } else {
        "dynamic-expression"
    }
}

/// Result of [`collect_context_bridge_members`].
pub struct ContextBridgeMembers {
    pub status: &'static str,
    pub members: Vec<String>,
    pub unknown: u64,
}

/// `collectContextBridgeMembers`: statically visible dotted keys of one literal API object.
pub fn collect_context_bridge_members(node: Option<N<'_>>) -> ContextBridgeMembers {
    let Some(node) = node else {
        return ContextBridgeMembers { status: "missing", members: Vec::new(), unknown: 0 };
    };
    if !node.is(Kind::ObjectExpression) {
        return ContextBridgeMembers { status: "dynamic", members: Vec::new(), unknown: 1 };
    }
    let mut members: Vec<String> = Vec::new();
    let mut unknown = 0u64;
    collect_members_at(node, "", 0, &mut members, &mut unknown);
    ContextBridgeMembers { status: "object-literal", members: sorted_set(members), unknown }
}

fn collect_members_at(
    object: N<'_>,
    prefix: &str,
    depth: u32,
    members: &mut Vec<String>,
    unknown: &mut u64,
) {
    if depth >= 8 {
        *unknown += 1;
        return;
    }
    for property in object.nodes("properties") {
        if property.is(Kind::SpreadElement) {
            *unknown += 1;
            continue;
        }
        let name = property
            .f("key")
            .map(|key| static_property_name(key, property.flag("computed")))
            .unwrap_or_default();
        if name.is_empty() || property.flag("computed") {
            *unknown += 1;
            continue;
        }
        let path = if prefix.is_empty() { name } else { format!("{prefix}.{name}") };
        members.push(path.clone());
        if property.is(Kind::ObjectProperty) {
            if let Some(value) = property.f("value") {
                if value.is(Kind::ObjectExpression) {
                    collect_members_at(value, &path, depth + 1, members, unknown);
                }
            }
        }
    }
}

/// `literalValue`: an exact literal, or a negated finite non-zero numeric literal.
fn literal_value(node: Option<N<'_>>) -> Option<Primitive> {
    let node = node?;
    if let Some(literal) = read_exact_literal(node) {
        return Some(literal);
    }
    if node.is(Kind::UnaryExpression) && node.str("operator") == Some("-") {
        let argument = node.f("argument")?;
        if argument.is_numeric_literal() {
            let value = -argument.num("value").unwrap_or(f64::NAN);
            // `Number.isFinite(value) && !Object.is(value, -0)`
            if value.is_finite() && !(value == 0.0 && value.is_sign_negative()) {
                return Some(Primitive::Num(JsNumber(value)));
            }
        }
    }
    None
}
