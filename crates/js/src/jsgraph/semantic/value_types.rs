//! Helpers over the value lattice of `javascriptSemanticValueTypes.ts` (the types themselves
//! live in `jsgraph::ir`).

use crate::jsgraph::ir::{Primitive, ResourceLimit, SemanticValue};

/// `{ status: "unknown", reason }`.
pub fn unknown(reason: impl Into<String>) -> SemanticValue {
    SemanticValue::Unknown { reason: reason.into(), resource_limit: None }
}

/// `{ status: "ambiguous", reason }`.
pub fn ambiguous(reason: impl Into<String>) -> SemanticValue {
    SemanticValue::Ambiguous { reason: reason.into(), resource_limit: None }
}

/// `{ status: "cycle", reason }`.
pub fn cycle(reason: impl Into<String>) -> SemanticValue {
    SemanticValue::Cycle { reason: reason.into(), resource_limit: None }
}

/// `{ status: "literal", value }`.
pub fn literal(value: Primitive) -> SemanticValue {
    SemanticValue::Literal { value }
}

/// `value.status === "literal" || value.status === "union"`.
pub fn is_primitive(value: &SemanticValue) -> bool {
    matches!(value, SemanticValue::Literal { .. } | SemanticValue::Union { .. })
}

/// `value.status === "unknown" && value.resourceLimit !== undefined`.
pub fn is_resource_limit(value: &SemanticValue) -> bool {
    matches!(value, SemanticValue::Unknown { resource_limit: Some(_), .. })
}

/// The `resourceLimit` of an unknown value.
pub fn resource_limit_of(value: &SemanticValue) -> Option<ResourceLimit> {
    match value {
        SemanticValue::Unknown { resource_limit, .. } => *resource_limit,
        _ => None,
    }
}

/// `"reason" in value`.
pub fn reason_of(value: &SemanticValue) -> Option<&str> {
    match value {
        SemanticValue::Unknown { reason, .. }
        | SemanticValue::Ambiguous { reason, .. }
        | SemanticValue::Cycle { reason, .. } => Some(reason),
        _ => None,
    }
}

/// The JS `status` string.
pub fn status_of(value: &SemanticValue) -> &'static str {
    match value {
        SemanticValue::Literal { .. } => "literal",
        SemanticValue::Union { .. } => "union",
        SemanticValue::Object { .. } => "object",
        SemanticValue::Array { .. } => "array",
        SemanticValue::Unknown { .. } => "unknown",
        SemanticValue::Ambiguous { .. } => "ambiguous",
        SemanticValue::Cycle { .. } => "cycle",
    }
}

/// `{ ...value, reason }` for a value that carries a reason.
pub fn with_reason(value: &SemanticValue, reason: String) -> SemanticValue {
    match value {
        SemanticValue::Unknown { resource_limit, .. } => {
            SemanticValue::Unknown { reason, resource_limit: *resource_limit }
        }
        SemanticValue::Ambiguous { resource_limit, .. } => {
            SemanticValue::Ambiguous { reason, resource_limit: *resource_limit }
        }
        SemanticValue::Cycle { resource_limit, .. } => {
            SemanticValue::Cycle { reason, resource_limit: *resource_limit }
        }
        other => other.clone(),
    }
}

/// Primitive candidates retained in one lattice value (`semanticPrimitiveCandidates`).
pub fn primitive_candidates(value: &SemanticValue) -> Option<Vec<Primitive>> {
    match value {
        SemanticValue::Literal { value } => Some(vec![value.clone()]),
        SemanticValue::Union { values } => Some(values.clone()),
        _ => None,
    }
}
