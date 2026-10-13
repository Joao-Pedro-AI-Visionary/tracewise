//! Port of `javascriptSemanticCoverage.ts`.

use crate::jsgraph::ir::{ResourceLimit, ReturnCoverage, SemanticCoverage};

use super::resource_limits::{
    SEMANTIC_EXPRESSION_DEPTH_LIMIT, SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT, SEMANTIC_PRIMITIVE_JSON_BYTES_LIMIT,
};

/// Classify whole-file semantic coverage from parsing and value bounds.
pub fn semantic_coverage(parser_partial: bool, resource_limits: Vec<ResourceLimit>) -> SemanticCoverage {
    if !resource_limits.is_empty() {
        SemanticCoverage {
            status: "partial".into(),
            omitted_count: None,
            resource_limits: Some(resource_limits),
        }
    } else {
        SemanticCoverage {
            status: if parser_partial { "partial" } else { "complete" }.into(),
            omitted_count: Some(0),
            resource_limits: None,
        }
    }
}

/// Read typed resource-limit classifications from any coverage state.
pub fn semantic_coverage_resource_limits(coverage: &SemanticCoverage) -> Vec<ResourceLimit> {
    coverage.resource_limits.clone().unwrap_or_default()
}

/// One caller-visible application coverage limit (`ApplicationCoverage["limits"][number]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticResourceBound {
    pub name: String,
    pub value: u64,
    pub unit: &'static str,
}

/// Map semantic evaluator bounds to their caller-visible application coverage.
pub fn semantic_resource_limit_coverage(resource_limits: &[ResourceLimit]) -> Vec<SemanticResourceBound> {
    resource_limits
        .iter()
        .map(|limit| {
            let (value, unit) = match limit {
                ResourceLimit::PrimitiveCandidates => (SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT as u64, "items"),
                ResourceLimit::PrimitiveBytes => (SEMANTIC_PRIMITIVE_JSON_BYTES_LIMIT as u64, "bytes"),
                ResourceLimit::ExpressionDepth => (u64::from(SEMANTIC_EXPRESSION_DEPTH_LIMIT), "depth"),
            };
            SemanticResourceBound {
                name: format!(
                    "javascript_semantic_{}",
                    super::resource_limits::resource_limit_name(*limit).replace('-', "_")
                ),
                value,
                unit,
            }
        })
        .collect()
}

/// Classify one callable's direct-return coverage.
pub fn semantic_return_coverage(retained_count: u64, parser_partial: bool) -> ReturnCoverage {
    ReturnCoverage {
        status: if parser_partial { "partial" } else { "complete" }.into(),
        retained_count,
        omitted_count: Some(0),
    }
}
