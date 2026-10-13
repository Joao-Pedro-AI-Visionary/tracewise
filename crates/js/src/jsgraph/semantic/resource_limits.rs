//! Port of `javascriptSemanticResourceLimits.ts`.

use std::collections::HashSet;

use crate::jsgraph::ir::{Primitive, ResourceLimit, SemanticValue};

use super::primitives::primitive_to_js_string;

/// Maximum distinct alternatives retained in one normalized primitive value.
pub const SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT: usize = 256;
/// Maximum active expression nesting during inert semantic evaluation.
pub const SEMANTIC_EXPRESSION_DEPTH_LIMIT: u32 = 256;
/// Bound normalized strings and transient keys independently of transport limits.
pub const SEMANTIC_PRIMITIVE_JSON_BYTES_LIMIT: usize = 1_048_576;

/// The kebab-case JSON spelling of a resource limit.
pub fn resource_limit_name(limit: ResourceLimit) -> &'static str {
    match limit {
        ResourceLimit::PrimitiveCandidates => "primitive-candidates",
        ResourceLimit::PrimitiveBytes => "primitive-bytes",
        ResourceLimit::ExpressionDepth => "expression-depth",
    }
}

/// `RESOURCE_LIMIT_REASON[resourceLimit]`.
pub fn semantic_resource_limit_reason(limit: ResourceLimit) -> &'static str {
    match limit {
        ResourceLimit::PrimitiveCandidates => {
            "Primitive candidate budget exceeded (maximum 256 alternatives)."
        }
        ResourceLimit::PrimitiveBytes => {
            "Primitive string-byte budget exceeded (maximum 1048576 estimated JSON bytes)."
        }
        ResourceLimit::ExpressionDepth => {
            "Semantic expression depth budget exceeded (maximum 256 nested expressions)."
        }
    }
}

/// UTF-16 code-unit length (`string.length`).
pub fn utf16_len(value: &str) -> usize {
    if value.is_ascii() {
        value.len()
    } else {
        value.encode_utf16().count()
    }
}

/// Worst-case JSON escaping size from a UTF-16 length.
fn json_string_bytes_from_length(code_units: usize) -> usize {
    code_units * 6 + 2
}

/// Bound string payload before JSON key serialization or candidate creation.
pub fn exceeds_semantic_primitive_string_byte_budget<'s>(
    strings: impl IntoIterator<Item = &'s str>,
) -> bool {
    let mut total = 0usize;
    for value in strings {
        total += json_string_bytes_from_length(utf16_len(value));
        if total > SEMANTIC_PRIMITIVE_JSON_BYTES_LIMIT {
            return true;
        }
    }
    false
}

/// Bound all outputs of a primitive addition before concatenating any.
pub fn exceeds_semantic_primitive_addition_byte_budget(left: &[Primitive], right: &[Primitive]) -> bool {
    let mut total = 0usize;
    for left_value in left {
        for right_value in right {
            if !matches!(left_value, Primitive::Str(_)) && !matches!(right_value, Primitive::Str(_)) {
                continue;
            }
            let length = utf16_len(&primitive_to_js_string(left_value))
                + utf16_len(&primitive_to_js_string(right_value));
            total += json_string_bytes_from_length(length);
            if total > SEMANTIC_PRIMITIVE_JSON_BYTES_LIMIT {
                return true;
            }
        }
    }
    false
}

/// Bound template interpolation outputs before creating concatenated strings.
pub fn exceeds_semantic_template_byte_budget(prefixes: &[String], suffixes: &[String]) -> bool {
    let mut total = 0usize;
    for prefix in prefixes {
        let prefix_length = utf16_len(prefix);
        for suffix in suffixes {
            total += json_string_bytes_from_length(prefix_length + utf16_len(suffix));
            if total > SEMANTIC_PRIMITIVE_JSON_BYTES_LIMIT {
                return true;
            }
        }
    }
    false
}

/// Make an explicit unknown value tagged with the semantic resource bound.
pub fn semantic_resource_limit_unknown(limit: ResourceLimit) -> SemanticValue {
    SemanticValue::Unknown {
        reason: semantic_resource_limit_reason(limit).to_string(),
        resource_limit: Some(limit),
    }
}

/// Collect resource-limit classifications from nested semantic values (sorted as the JS default
/// `Array.prototype.sort`, which orders these ASCII names by code unit).
pub fn semantic_resource_limits_in<'v>(
    values: impl IntoIterator<Item = &'v SemanticValue>,
) -> Vec<ResourceLimit> {
    let mut found: HashSet<ResourceLimit> = HashSet::new();
    let mut pending: Vec<&SemanticValue> = values.into_iter().collect();
    while let Some(value) = pending.pop() {
        match value {
            SemanticValue::Unknown { resource_limit: Some(limit), .. } => {
                found.insert(*limit);
            }
            SemanticValue::Object { properties, .. } => {
                pending.extend(properties.iter().map(|property| &property.value));
            }
            SemanticValue::Array { items, .. } => {
                pending.extend(items.iter().map(|item| &item.value));
            }
            _ => {}
        }
    }
    let mut sorted: Vec<ResourceLimit> = found.into_iter().collect();
    sorted.sort_by_key(|limit| resource_limit_name(*limit));
    sorted
}
