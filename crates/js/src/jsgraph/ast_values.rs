//! Port of REA `javascriptAstValues.ts`: syntax-level literal and property-name reads.

use super::ast::{Alias, Kind, N};
use super::ir::{JsNumber, Primitive};
use super::util::js_number_to_string;

/// Remove wrappers that affect TypeScript or Flow checking but not runtime expression identity.
/// Returns the inner node and how many wrappers were removed.
pub fn unwrap_expression(node: N<'_>) -> (N<'_>, u32) {
    let mut current = node;
    let mut depth = 0;
    loop {
        let wrapper = matches!(
            current.kind(),
            Kind::ParenthesizedExpression
                | Kind::TSAsExpression
                | Kind::TSTypeAssertion
                | Kind::TSNonNullExpression
                | Kind::TSSatisfiesExpression
                | Kind::TSInstantiationExpression
                | Kind::TypeCastExpression
        );
        if !wrapper {
            return (current, depth);
        }
        match current.f("expression") {
            Some(inner) => current = inner,
            None => return (current, depth),
        }
        depth += 1;
    }
}

/// Read one syntax-level primitive only when its value is exact.
pub fn read_exact_literal(node: N<'_>) -> Option<Primitive> {
    let node = unwrap_expression(node).0;
    match node.kind() {
        Kind::StringLiteral => Some(Primitive::Str(node.str("value").unwrap_or("").to_string())),
        Kind::NumericLiteral => {
            let value = node.num("value").unwrap_or(f64::NAN);
            value.is_finite().then_some(Primitive::Num(JsNumber(value)))
        }
        Kind::BooleanLiteral => Some(Primitive::Bool(node.flag("value"))),
        Kind::NullLiteral => Some(Primitive::Null),
        Kind::TemplateLiteral => {
            let quasis = node.nodes("quasis");
            if node.list_len("expressions") == 0 && quasis.len() == 1 {
                quasis[0].str("cooked").map(|c| Primitive::Str(c.to_string()))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// `propertyName`: identifier or string/numeric literal name, `""` otherwise.
pub fn property_name(node: N<'_>) -> String {
    match node.kind() {
        Kind::Identifier => node.str("name").unwrap_or("").to_string(),
        Kind::StringLiteral => node.str("value").unwrap_or("").to_string(),
        Kind::NumericLiteral => js_number_to_string(node.num("value").unwrap_or(f64::NAN)),
        _ => String::new(),
    }
}

/// `semanticStaticPropertyKey`: exact key or `None`.
pub fn static_property_key(property: N<'_>, computed: bool) -> Option<String> {
    let property = unwrap_expression(property).0;
    match property.kind() {
        Kind::StringLiteral => Some(property.str("value").unwrap_or("").to_string()),
        Kind::NumericLiteral => Some(js_number_to_string(property.num("value").unwrap_or(f64::NAN))),
        Kind::Identifier if !computed => Some(property.str("name").unwrap_or("").to_string()),
        _ => None,
    }
}

/// `semanticStaticPropertyName`: exact key or `""`.
pub fn static_property_name(property: N<'_>, computed: bool) -> String {
    static_property_key(property, computed).unwrap_or_default()
}

/// `semanticObjectPatternKeys`: exact consumed keys of an `ObjectPattern`.
pub fn object_pattern_keys(pattern: N<'_>) -> Vec<String> {
    pattern
        .nodes("properties")
        .into_iter()
        .filter(|p| !p.is(Kind::RestElement))
        .filter_map(|p| {
            let key = p.f("key")?;
            static_property_key(key, p.flag("computed"))
        })
        .collect()
}

/// `javascriptDisplayText`: a graph label for a legal empty string.
pub fn display_text(value: &str) -> String {
    if value.is_empty() {
        "\"\"".to_string()
    } else {
        value.to_string()
    }
}

/// True when `node` is a Babel `Function` (declaration, expression, arrow, method).
pub fn is_function(node: N<'_>) -> bool {
    node.has_alias(Alias::Function)
}
