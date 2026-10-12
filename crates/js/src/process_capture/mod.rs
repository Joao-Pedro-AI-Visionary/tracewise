//! Process scenario capture and comparison (port of REA `process/capture`,
//! `domain/process` and the two MCP tool registrations).

mod capture;
mod compare;
mod evidence;
mod filesystem;
mod normalization;
mod ownership;
mod renderer;
mod scenario;
mod trace;
mod validation;

pub use compare::{compare_process_captures, CompareOptions};
pub use evidence::{capture_process_scenario, compare_process_captures_tool, CaptureError};
pub use trace::{parse_trace_specification, TraceSpecification};
pub use validation::collect_capture_issues;
