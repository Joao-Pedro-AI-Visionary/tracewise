//! Application reconstruction: delegates to the native `jsgraph` pipeline.

use serde_json::Value;

use crate::jsgraph::error::AnalysisFailure;
use crate::jsgraph::control::Cancel;

pub fn reconstruct_javascript_application(
    input_path: &str,
    format: &str,
    integrity_policy: &str,
    cancel: &Cancel,
) -> Result<Value, AnalysisFailure> {
    crate::jsgraph::pipeline::reconstruct_javascript_application(input_path, format, integrity_policy, cancel)
}
