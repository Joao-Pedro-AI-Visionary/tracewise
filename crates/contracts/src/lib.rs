use rmcp::model::Tool;
use serde::Deserialize;

pub const PHASE0_TOOLS_JSON: &str = include_str!("../phase0_tools.json");
pub const PHASE1_TOOLS_JSON: &str = include_str!("../phase1_tools.json");
pub const TRACEWISE_TOOLS_JSON: &str = include_str!("../tracewise_tools.json");

#[derive(Debug, Deserialize)]
struct ToolsContainer {
    tools: Vec<Tool>,
}

/// Returns the raw JSON string of Phase 0 tools.
pub fn phase0_tools_json() -> &'static str {
    PHASE0_TOOLS_JSON
}

/// Returns the raw JSON string of Phase 1 tools.
pub fn phase1_tools_json() -> &'static str {
    PHASE1_TOOLS_JSON
}

/// Returns the parsed serde_json::Value of phase0_tools.json.
pub fn phase0_tools_value() -> serde_json::Value {
    serde_json::from_str(PHASE0_TOOLS_JSON).expect("phase0_tools.json must be valid JSON")
}

/// Returns the parsed serde_json::Value of phase1_tools.json.
pub fn phase1_tools_value() -> serde_json::Value {
    serde_json::from_str(PHASE1_TOOLS_JSON).expect("phase1_tools.json must be valid JSON")
}

/// Returns the parsed serde_json::Value of tracewise-owned tools.
pub fn tracewise_tools_value() -> serde_json::Value {
    serde_json::from_str(TRACEWISE_TOOLS_JSON).expect("tracewise_tools.json must be valid JSON")
}

/// Returns the 12 Phase 0 tools as rmcp::model::Tool instances with verbatim schemas.
pub fn phase0_tools() -> Vec<Tool> {
    let container: ToolsContainer = serde_json::from_str(PHASE0_TOOLS_JSON)
        .expect("phase0_tools.json must deserialize to rmcp Tool definitions");
    container.tools
}

/// Returns the 15 Phase 1 tools as rmcp::model::Tool instances with verbatim schemas.
pub fn phase1_tools() -> Vec<Tool> {
    let container: ToolsContainer = serde_json::from_str(PHASE1_TOOLS_JSON)
        .expect("phase1_tools.json must deserialize to rmcp Tool definitions");
    container.tools
}

/// Returns tracewise-owned tools that are not part of the REA catalog.
pub fn tracewise_tools() -> Vec<Tool> {
    let container: ToolsContainer = serde_json::from_str(TRACEWISE_TOOLS_JSON)
        .expect("tracewise_tools.json must deserialize to rmcp Tool definitions");
    container.tools
}

/// Returns all 27 tools (Phase 0 + Phase 1) as rmcp::model::Tool instances.
pub fn all_tools() -> Vec<Tool> {
    let mut tools = phase0_tools();
    tools.extend(phase1_tools());
    tools
}

/// Returns the combined parsed serde_json::Value for all 27 tools.
pub fn all_tools_value() -> serde_json::Value {
    let t0 = phase0_tools_value();
    let t1 = phase1_tools_value();
    let mut arr = t0["tools"].as_array().cloned().unwrap_or_default();
    if let Some(arr1) = t1["tools"].as_array() {
        arr.extend(arr1.iter().cloned());
    }
    serde_json::json!({ "tools": arr })
}

/// Returns the 27 REA tools plus tracewise-owned tools (29 with infer_api_spec and generate_api_client).
pub fn listed_tools() -> Vec<Tool> {
    let mut tools = all_tools();
    tools.extend(tracewise_tools());
    tools
}

/// Returns the JSON catalog served by tools/list.
/// The first 27 entries stay byte-identical to the REA tools.
pub fn listed_tools_value() -> serde_json::Value {
    let mut listed = all_tools_value();
    let extra = tracewise_tools_value();
    if let Some(arr) = listed
        .get_mut("tools")
        .and_then(|value| value.as_array_mut())
    {
        if let Some(extra_arr) = extra.get("tools").and_then(|value| value.as_array()) {
            arr.extend(extra_arr.iter().cloned());
        }
    }
    listed
}

/// Returns the static list of the 12 Phase 0 tool names in canonical order.
pub fn phase0_tool_names() -> &'static [&'static str] {
    &[
        "inspect_analysis_view",
        "open_binary",
        "close_binary",
        "binary_session",
        "export_evidence_bundle",
        "import_evidence_bundle",
        "get_evidence_bundle",
        "compare_bundles",
        "list_unknowns",
        "record_unknown",
        "update_unknown",
        "verify_unknown_resolution",
    ]
}

/// Returns the static list of the 15 Phase 1 tool names in canonical order.
pub fn phase1_tool_names() -> &'static [&'static str] {
    &[
        "trace_web_module_imports",
        "trace_web_source_location",
        "observe_web_execution",
        "inspect_web_event_listeners",
        "inspect_web_network_capture",
        "export_web_scripts",
        "list_browser_targets",
        "inspect_web_page",
        "analyze_web_bundle",
        "observe_web_session",
        "discover_webmcp_tools",
        "compare_web_captures",
        "capture_web_screenshot",
        "compare_web_screenshots",
        "capture_browser_scenario",
    ]
}

/// Returns the list of all 27 REA tool names in canonical order.
pub fn all_tool_names() -> Vec<&'static str> {
    let mut names = phase0_tool_names().to_vec();
    names.extend_from_slice(phase1_tool_names());
    names
}

/// Tracewise-owned tool names appended after the 27 REA tools.
pub fn tracewise_tool_names() -> &'static [&'static str] {
    &["infer_api_spec", "generate_api_client"]
}

/// Names returned by tools/list: 27 REA tools, then tracewise-owned tools.
pub fn listed_tool_names() -> Vec<&'static str> {
    let mut names = all_tool_names();
    names.extend_from_slice(tracewise_tool_names());
    names
}
