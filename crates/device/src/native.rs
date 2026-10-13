//! Native runtime tools (macOS): argument admission and the host gate.
//!
//! Covers `observe_native_ui`, `capture_native_ui_scenario`,
//! `observe_native_calls` and the admission of `trace_native_ui_action`. The
//! macOS paths of the first three drive Accessibility (Swift helpers) and LLDB;
//! they exist only on macOS. On every other host REA answers with the provider
//! set's `unsupported_host` capability, which this module reproduces exactly.

use serde_json::{json, Map, Value};

use crate::error::ToolError;
use crate::input::{
    int, optional, positive_int, prop, string, validate_props, with_default, Kind, Prop, StrTest,
};

pub const OBSERVE_NATIVE_UI: &str = "observe_native_ui";
pub const CAPTURE_NATIVE_UI_SCENARIO: &str = "capture_native_ui_scenario";
pub const OBSERVE_NATIVE_CALLS: &str = "observe_native_calls";
pub const TRACE_NATIVE_UI_ACTION: &str = "trace_native_ui_action";

/// Tools whose real implementation needs a macOS host.
pub const HOST_GATED_TOOLS: [&str; 3] = [OBSERVE_NATIVE_UI, CAPTURE_NATIVE_UI_SCENARIO, OBSERVE_NATIVE_CALLS];

/// Reason REA's native-macos provider reports on every other host.
pub const UNSUPPORTED_HOST_REASON: &str = "Native macOS utilities require macOS.";

/// Auxiliary provider set REA routes every open target through, sorted. A deep
/// engine bound to the target would add its id to this composite.
pub const AUXILIARY_PROVIDER_IDS: [&str; 3] = ["native-macos", "rea-artifact-graph", "rea-dotnet-static"];

/// `composite:<ids>` identity of the session route.
pub fn composite_provider_id(extra: &[&str]) -> String {
    let mut ids: Vec<&str> = AUXILIARY_PROVIDER_IDS.iter().copied().chain(extra.iter().copied()).collect();
    ids.sort_unstable();
    format!("composite:{}", ids.join("+"))
}

fn no_nul(text: &str) -> bool {
    !text.contains('\0')
}

fn objc_bare(text: &str) -> bool {
    // /^[^\s\x5b\x5d]+$/u
    !text.is_empty() && !text.chars().any(|c| crate::input::is_js_whitespace(c) || c == '[' || c == ']')
}

fn env_name(text: &str) -> bool {
    // /^[^=\x00]+$/u
    !text.is_empty() && !text.contains('=') && !text.contains('\0')
}

fn native_string(min: Option<usize>) -> Kind {
    string(min, None, vec![(no_nul as StrTest, "Native launch and breakpoint strings cannot contain NUL")])
}

fn objc_name() -> Kind {
    string(
        Some(1),
        None,
        vec![
            (no_nul as StrTest, "Native launch and breakpoint strings cannot contain NUL"),
            (objc_bare as StrTest, "Use the bare name without spaces or brackets"),
        ],
    )
}

fn scope() -> Vec<Prop> {
    vec![
        prop("pid", positive_int()),
        prop("window_id", positive_int()),
        with_default("screenshot", Kind::Bool, json!(true)),
        with_default("accessibility", Kind::Bool, json!(true)),
        with_default(
            "max_nodes",
            Kind::Int { min: Some(0), exclusive_min: true, max: None, safe: true },
            json!(500),
        ),
    ]
}

fn path_array() -> Kind {
    Kind::Array { item: Box::new(int(Some(0), None)), min: None, max: Some(32) }
}

fn schema_for(tool: &str) -> Option<Vec<Prop>> {
    Some(match tool {
        OBSERVE_NATIVE_UI => scope(),
        CAPTURE_NATIVE_UI_SCENARIO => {
            let mut props = scope();
            props.push(prop(
                "steps",
                Kind::Array {
                    item: Box::new(Kind::Union {
                        tag: "kind",
                        variants: vec![
                            ("click", vec![prop("path", path_array())]),
                            (
                                "scroll",
                                vec![
                                    prop("path", path_array()),
                                    prop("direction", Kind::Enum(&["increment", "decrement"])),
                                ],
                            ),
                            ("key-entry", vec![prop("path", path_array()), prop("text", string(None, None, vec![]))]),
                            ("wait", vec![prop("milliseconds", int(Some(0), Some(180_000)))]),
                        ],
                    }),
                    min: Some(1),
                    max: None,
                },
            ));
            props
        }
        OBSERVE_NATIVE_CALLS => vec![
            prop(
                "breakpoints",
                Kind::Array {
                    item: Box::new(Kind::Union {
                        tag: "kind",
                        variants: vec![
                            (
                                "function",
                                vec![prop("name", native_string(Some(1))), optional("module", native_string(Some(1)))],
                            ),
                            (
                                "objc-method",
                                vec![
                                    prop("selector", objc_name()),
                                    optional("class_name", objc_name()),
                                    with_default("method_type", Kind::Enum(&["instance", "class", "any"]), json!("any")),
                                ],
                            ),
                        ],
                    }),
                    min: Some(1),
                    max: None,
                },
            ),
            with_default(
                "arguments",
                Kind::Array { item: Box::new(native_string(None)), min: None, max: None },
                json!([]),
            ),
            with_default(
                "environment",
                Kind::Record {
                    key: Box::new(string(Some(1), None, vec![(env_name as StrTest, "Environment names cannot contain '=' or NUL")])),
                    value: Box::new(string(None, None, vec![(no_nul as StrTest, "Environment values cannot contain NUL")])),
                },
                json!({}),
            ),
            optional(
                "working_directory",
                string(Some(1), None, vec![(no_nul as StrTest, "Local filesystem paths cannot contain NUL")]),
            ),
            with_default("duration_ms", int(Some(100), Some(600_000)), json!(10_000)),
            with_default("max_events", int(Some(1), Some(100_000)), json!(1_000)),
            with_default("argument_registers", int(Some(0), Some(8)), json!(4)),
            with_default("backtrace_frames", int(Some(0), Some(64)), json!(0)),
        ],
        TRACE_NATIVE_UI_ACTION => vec![
            prop("action", string(Some(1), None, vec![])),
            with_default("max_depth", int(Some(0), Some(32)), json!(8)),
            with_default("max_nodes", int(Some(1), Some(2_000)), json!(250)),
            with_default("max_edges", int(Some(1), Some(5_000)), json!(500)),
        ],
        _ => return None,
    })
}

/// Validate `arguments` for one of the native runtime tools.
pub fn validate(tool: &str, arguments: &Value) -> Result<Map<String, Value>, String> {
    let props = schema_for(tool).ok_or_else(|| format!("Unknown tool: '{tool}'"))?;
    validate_props(tool, &props, arguments)
}

/// The capability error REA raises when the route's provider set does not
/// support `operation` on this host (`unsupported_host`).
pub fn host_unsupported(operation: &str, provider_id: &str) -> ToolError {
    ToolError::CapabilityUnavailable {
        provider_id: provider_id.to_string(),
        operation: operation.to_string(),
        reason: UNSUPPORTED_HOST_REASON.to_string(),
        user_message: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composite_id_is_sorted() {
        assert_eq!(
            composite_provider_id(&[]),
            "composite:native-macos+rea-artifact-graph+rea-dotnet-static"
        );
        assert_eq!(
            composite_provider_id(&["ghidra"]),
            "composite:ghidra+native-macos+rea-artifact-graph+rea-dotnet-static"
        );
    }

    #[test]
    fn scenario_defaults() {
        let ok = validate(
            CAPTURE_NATIVE_UI_SCENARIO,
            &json!({"pid": 1, "window_id": 2, "steps": [{"kind": "wait", "milliseconds": 5}]}),
        )
        .unwrap();
        assert_eq!(ok["max_nodes"], 500);
        assert_eq!(ok["steps"][0]["kind"], "wait");
    }
}
