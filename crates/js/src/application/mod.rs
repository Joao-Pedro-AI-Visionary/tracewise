mod analyze;
mod export_shapes;
mod feature_trace;
mod graph_ids;
pub(crate) mod graph_seal;
mod reconstruct;
mod semantic_graph;
mod semantic_trace;
mod version_compare;
mod workflow;

pub use analyze::{analyze_javascript_application, analyze_javascript_application_cancellable};
pub use export_shapes::compare_javascript_export_shapes;
pub use feature_trace::trace_application_feature;
pub use semantic_trace::trace_javascript_semantics;
pub use version_compare::compare_application_versions;
