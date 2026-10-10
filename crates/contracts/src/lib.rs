use rmcp::model::Tool;
use serde::Deserialize;

pub const PHASE0_TOOLS_JSON: &str = include_str!("../phase0_tools.json");

#[derive(Debug, Deserialize)]
struct Phase0ToolsContainer {
    tools: Vec<Tool>,
}

/// Returns the raw JSON string of Phase 0 tools.
pub fn phase0_tools_json() -> &'static str {
    PHASE0_TOOLS_JSON
}

/// Returns the parsed serde_json::Value of phase0_tools.json.
pub fn phase0_tools_value() -> serde_json::Value {
    serde_json::from_str(PHASE0_TOOLS_JSON).expect("phase0_tools.json must be valid JSON")
}

/// Returns the 12 Phase 0 tools as rmcp::model::Tool instances with verbatim schemas.
pub fn phase0_tools() -> Vec<Tool> {
    let container: Phase0ToolsContainer = serde_json::from_str(PHASE0_TOOLS_JSON)
        .expect("phase0_tools.json must deserialize to rmcp Tool definitions");
    container.tools
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
