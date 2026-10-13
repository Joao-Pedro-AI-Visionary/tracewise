//! Port of `javascriptSemanticPrimitives.ts` plus the JavaScript primitive coercions the value
//! evaluator relies on (`String(x)`, `Number(x)`, truthiness).

use std::collections::HashSet;

use crate::jsgraph::ir::{JsNumber, Primitive, ResourceLimit, SemanticValue};
use crate::jsgraph::util::js_number_to_string;

use super::resource_limits::{
    exceeds_semantic_primitive_string_byte_budget, semantic_resource_limit_unknown,
    SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT,
};
use super::value_types::{literal, unknown};

/// A number primitive.
pub fn num(value: f64) -> Primitive {
    Primitive::Num(JsNumber(value))
}

/// JS `String(value)`.
pub fn primitive_to_js_string(value: &Primitive) -> String {
    match value {
        Primitive::Null => "null".into(),
        Primitive::Bool(true) => "true".into(),
        Primitive::Bool(false) => "false".into(),
        Primitive::Num(JsNumber(number)) => js_number_to_string(*number),
        Primitive::Str(text) => text.clone(),
    }
}

/// JS `Number(value)`.
pub fn primitive_to_js_number(value: &Primitive) -> f64 {
    match value {
        Primitive::Null => 0.0,
        Primitive::Bool(true) => 1.0,
        Primitive::Bool(false) => 0.0,
        Primitive::Num(JsNumber(number)) => *number,
        Primitive::Str(text) => js_string_to_number(text),
    }
}

/// JS truthiness (`!!value`).
pub fn primitive_truthy(value: &Primitive) -> bool {
    match value {
        Primitive::Null => false,
        Primitive::Bool(flag) => *flag,
        Primitive::Num(JsNumber(number)) => *number != 0.0 && !number.is_nan(),
        Primitive::Str(text) => !text.is_empty(),
    }
}

fn is_js_whitespace(ch: char) -> bool {
    matches!(
        ch,
        '\u{9}' | '\u{a}' | '\u{b}' | '\u{c}' | '\u{d}' | ' ' | '\u{a0}' | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

/// ECMAScript `StringToNumber`.
pub fn js_string_to_number(text: &str) -> f64 {
    let trimmed = text.trim_matches(is_js_whitespace);
    if trimmed.is_empty() {
        return 0.0;
    }
    let bytes = trimmed.as_bytes();
    if bytes.len() > 2 && bytes[0] == b'0' {
        let radix = match bytes[1] {
            b'x' | b'X' => 16,
            b'o' | b'O' => 8,
            b'b' | b'B' => 2,
            _ => 0,
        };
        if radix != 0 {
            let mut value = 0f64;
            for &byte in &bytes[2..] {
                let Some(digit) = (byte as char).to_digit(radix) else {
                    return f64::NAN;
                };
                value = value * f64::from(radix) + f64::from(digit);
            }
            return value;
        }
    }
    let (sign, rest) = match bytes[0] {
        b'+' => (1.0, &trimmed[1..]),
        b'-' => (-1.0, &trimmed[1..]),
        _ => (1.0, trimmed),
    };
    if rest == "Infinity" {
        return sign * f64::INFINITY;
    }
    if !is_decimal_literal(rest) {
        return f64::NAN;
    }
    match rest.parse::<f64>() {
        Ok(value) => sign * value,
        Err(_) => f64::NAN,
    }
}

/// `StrUnsignedDecimalLiteral` without `Infinity`.
fn is_decimal_literal(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    let digits = |from: usize| bytes[from..].iter().take_while(|b| b.is_ascii_digit()).count();
    let integer = digits(index);
    index += integer;
    let mut fraction = 0;
    if index < bytes.len() && bytes[index] == b'.' {
        index += 1;
        fraction = digits(index);
        index += fraction;
    }
    if integer == 0 && fraction == 0 {
        return false;
    }
    if index < bytes.len() && (bytes[index] == b'e' || bytes[index] == b'E') {
        index += 1;
        if index < bytes.len() && (bytes[index] == b'+' || bytes[index] == b'-') {
            index += 1;
        }
        let exponent = digits(index);
        if exponent == 0 {
            return false;
        }
        index += exponent;
    }
    index == bytes.len()
}

/// `JSON.stringify` of a string.
pub fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("json string")
}

/// `semanticPrimitiveKey`: canonically distinguish primitive values across type boundaries.
pub fn semantic_primitive_key(value: &Primitive) -> String {
    match value {
        Primitive::Null => "null:null".into(),
        Primitive::Bool(flag) => format!("boolean:{flag}"),
        Primitive::Num(JsNumber(number)) => format!("number:{}", js_number_to_string(*number)),
        Primitive::Str(text) => format!("string:{}", json_string(text)),
    }
}

/// Normalize one bounded collection of possible primitive values.
pub fn semantic_primitive_set(values: &[Primitive]) -> SemanticValue {
    let mut seen: HashSet<String> = HashSet::new();
    let mut unique_values: Vec<(String, &Primitive)> = Vec::new();
    for value in values {
        if let Primitive::Num(JsNumber(number)) = value {
            if !number.is_finite() {
                return unknown("Nonfinite numbers are outside the JSON primitive lattice.");
            }
            if *number == 0.0 && number.is_sign_negative() {
                return unknown("Negative zero cannot be preserved by JSON primitive evidence.");
            }
        }
        let key = semantic_primitive_key(value);
        if seen.insert(key.clone()) {
            unique_values.push((key, value));
        }
        if unique_values.len() > SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT {
            return semantic_resource_limit_unknown(ResourceLimit::PrimitiveCandidates);
        }
    }
    if exceeds_semantic_primitive_string_byte_budget(unique_values.iter().filter_map(
        |(_, value)| match value {
            Primitive::Str(text) => Some(text.as_str()),
            _ => None,
        },
    )) {
        return semantic_resource_limit_unknown(ResourceLimit::PrimitiveBytes);
    }
    unique_values.sort_by(|left, right| left.0.cmp(&right.0));
    if unique_values.len() == 1 {
        return literal(unique_values[0].1.clone());
    }
    SemanticValue::Union { values: unique_values.into_iter().map(|(_, value)| value.clone()).collect() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_to_number_matches_ecmascript() {
        assert_eq!(js_string_to_number(""), 0.0);
        assert_eq!(js_string_to_number("  12  "), 12.0);
        assert_eq!(js_string_to_number("0x1F"), 31.0);
        assert!(js_string_to_number("1_0").is_nan());
        assert_eq!(js_string_to_number("-.5e1"), -5.0);
        assert!(js_string_to_number("e5").is_nan());
        assert_eq!(js_string_to_number("-Infinity"), f64::NEG_INFINITY);
        assert!(js_string_to_number("-0x1").is_nan());
        assert!(js_string_to_number("1e").is_nan());
        assert_eq!(js_string_to_number("5."), 5.0);
    }
}
