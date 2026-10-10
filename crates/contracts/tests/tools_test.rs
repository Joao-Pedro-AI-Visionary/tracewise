use std::path::{Path, PathBuf};

use serde_json::Value;
use tracewise_contracts::{phase0_tool_names, phase0_tools, phase0_tools_value};

fn fixture_path(name: &str) -> String {
    format!(
        "{}/../../fixtures/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    )
}

#[test]
fn test_tools_equal_fixtures() {
    let fixture_raw = std::fs::read_to_string(fixture_path("phase0_tools.json"))
        .expect("Failed to read fixtures/phase0_tools.json");
    let fixture_val: Value =
        serde_json::from_str(&fixture_raw).expect("Failed to parse fixtures/phase0_tools.json");

    let contracts_val = phase0_tools_value();
    assert_eq!(
        contracts_val, fixture_val,
        "phase0_tools in contracts does not match fixtures/phase0_tools.json"
    );

    let tools = phase0_tools();
    assert_eq!(tools.len(), 12);

    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(names, phase0_tool_names());
}

#[test]
fn test_tools_equal_head_tools_if_exists() {
    let override_path = std::env::var("REA_TOOLS_JSON").ok().map(PathBuf::from);
    let default_path = PathBuf::from("/workspace/rea-map/tmp/head/tools.json");
    let head_path: &Path = override_path.as_deref().unwrap_or(&default_path);

    if !head_path.exists() {
        println!(
            "Skipping test: {} does not exist (set REA_TOOLS_JSON to override)",
            head_path.display()
        );
        return;
    }

    let head_raw = std::fs::read_to_string(head_path).expect("Failed to read head tools.json");
    let head_val: Value =
        serde_json::from_str(&head_raw).expect("Failed to parse head tools.json");

    let head_tools = head_val
        .get("tools")
        .and_then(|v| v.as_array())
        .expect("Expected tools array in head tools.json");

    let contracts_val = phase0_tools_value();
    let contract_tools = contracts_val
        .get("tools")
        .and_then(|v| v.as_array())
        .expect("Expected tools array in contracts tools");

    let head_map: std::collections::HashMap<&str, &Value> = head_tools
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(|n| (n, t)))
        .collect();

    for contract_tool in contract_tools {
        let name = contract_tool
            .get("name")
            .and_then(|n| n.as_str())
            .expect("Tool must have name");

        let head_tool = head_map
            .get(name)
            .unwrap_or_else(|| panic!("Tool '{name}' not found in head tools.json"));

        assert_eq!(
            contract_tool, *head_tool,
            "Tool '{name}' in contracts does not match head tools.json"
        );
    }
}
