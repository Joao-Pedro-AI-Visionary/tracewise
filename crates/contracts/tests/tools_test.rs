use std::path::{Path, PathBuf};

use serde_json::Value;
use tracewise_contracts::{
    all_tool_names, all_tools, all_tools_value, listed_tool_names, listed_tools, listed_tools_value,
    phase0_tool_names, phase0_tools, phase0_tools_value, phase1_tool_names, phase1_tools,
    phase1_tools_value,
};

fn fixture_path(name: &str) -> String {
    format!(
        "{}/../../fixtures/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    )
}

#[test]
fn test_tools_equal_fixtures() {
    let fixture0_raw = std::fs::read_to_string(fixture_path("phase0_tools.json"))
        .expect("Failed to read fixtures/phase0_tools.json");
    let fixture0_val: Value =
        serde_json::from_str(&fixture0_raw).expect("Failed to parse fixtures/phase0_tools.json");

    let contracts0_val = phase0_tools_value();
    assert_eq!(
        contracts0_val, fixture0_val,
        "phase0_tools in contracts does not match fixtures/phase0_tools.json"
    );

    let tools0 = phase0_tools();
    assert_eq!(tools0.len(), 12);

    let names0: Vec<&str> = tools0.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(names0, phase0_tool_names());

    let fixture1_raw = std::fs::read_to_string(fixture_path("phase1_tools.json"))
        .expect("Failed to read fixtures/phase1_tools.json");
    let fixture1_val: Value =
        serde_json::from_str(&fixture1_raw).expect("Failed to parse fixtures/phase1_tools.json");

    let contracts1_val = phase1_tools_value();
    assert_eq!(
        contracts1_val, fixture1_val,
        "phase1_tools in contracts does not match fixtures/phase1_tools.json"
    );

    let tools1 = phase1_tools();
    assert_eq!(tools1.len(), 15);

    let names1: Vec<&str> = tools1.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(names1, phase1_tool_names());

    let all = all_tools();
    assert_eq!(all.len(), 27);
    let all_names: Vec<&str> = all.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(all_names, all_tool_names());

    let listed = listed_tools();
    assert_eq!(listed.len(), 29);
    let listed_names: Vec<&str> = listed.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(listed_names, listed_tool_names());
    assert_eq!(listed_names[27], "infer_api_spec");
    assert_eq!(listed_names[28], "generate_api_client");

    let listed_val = listed_tools_value();
    let listed_arr = listed_val["tools"].as_array().expect("listed tools");
    let rea_arr = all_tools_value()["tools"]
        .as_array()
        .expect("rea tools")
        .clone();
    assert_eq!(listed_arr.len(), 29);
    assert_eq!(&listed_arr[..27], rea_arr.as_slice());
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

    let contracts_val = all_tools_value();
    let contract_tools = contracts_val
        .get("tools")
        .and_then(|v| v.as_array())
        .expect("Expected tools array in contracts tools");

    assert_eq!(
        contract_tools.len(),
        27,
        "Expected 27 tools across Phase 0 and Phase 1"
    );

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
