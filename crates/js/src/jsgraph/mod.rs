//! Real JavaScript application graph construction (port of the REA `src/application/javascript`
//! pipeline). See `docs/progress/jsgraph.md` for the exact coverage.

pub mod app_graph;
pub mod ast;
pub mod ast_values;
pub mod control;
pub mod error;
pub mod ir;
pub mod pipeline;
pub mod semantic;
pub mod semantic_graph;
pub mod static_analysis;
pub mod static_types;
pub mod util;
