//! Semantic graph slice of a JavaScript application analysis result.

use serde_json::Value;

use crate::error::JsError;

/// Return the sealed semantic graph embedded in a normalized application result.
pub fn semantic_graph_from_result(result: &Value) -> Result<&Value, JsError> {
    result
        .get("semantic_graph")
        .ok_or_else(|| JsError::InvalidInput("semantic graph is missing".into()))
}
