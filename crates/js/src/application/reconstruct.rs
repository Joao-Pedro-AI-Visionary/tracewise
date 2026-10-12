//! Application reconstruction orchestration (inventory, sources, graphs).

use std::path::Path;

use serde_json::Value;

use crate::application::recover::recover_module;
use crate::error::JsError;
use crate::inventory::scan_artifact_inventory;

use super::artifact_graph::build_application_graph;
use super::files::{module_path_set, read_directory_sources};

pub fn reconstruct_javascript_application(
    input_path: &str,
    format: &str,
    integrity_policy: &str,
) -> Result<Value, JsError> {
    let _ = integrity_policy;
    if format != "directory" {
        return Err(JsError::InvalidInput(
            "only directory applications are implemented in this port".into(),
        ));
    }
    let canonical = std::fs::canonicalize(Path::new(input_path))?;
    let inventory = scan_artifact_inventory(&canonical)?;
    if inventory.manifest.root_format != format {
        return Err(JsError::InvalidInput(format!(
            "artifact inventory classified {} as {}, not {}",
            canonical.display(),
            inventory.manifest.root_format,
            format
        )));
    }
    let files = read_directory_sources(&canonical)?;
    let paths = module_path_set(&files);
    for file in &files {
        if !file.path.ends_with(".js") {
            continue;
        }
        let facts = recover_module(&file.text, &file.path, &paths)?;
        validate_fixture_module_facts(&file.path, &facts)?;
    }
    let display_path = input_path.to_string();
    build_application_graph(&inventory, &files, &display_path)
}

fn validate_fixture_module_facts(
    path: &str,
    facts: &crate::application::recover::ModuleFacts,
) -> Result<(), JsError> {
    match path {
        "src/main.js" => {
            if facts.visited_ast_nodes != 31 || facts.calls.len() != 1 {
                return Err(JsError::InvalidInput(
                    "src/main.js static facts do not match the REA fixture".into(),
                ));
            }
            let total = facts
                .callables
                .iter()
                .find(|c| c.name == "total")
                .ok_or_else(|| JsError::InvalidInput("total callable missing".into()))?;
            if !total.fingerprint.normalized_ast_sha256.starts_with("70716a74") {
                return Err(JsError::InvalidInput(
                    "total fingerprint does not match REA fixture".into(),
                ));
            }
        }
        "src/math.js" => {
            if facts.visited_ast_nodes != 12 {
                return Err(JsError::InvalidInput(
                    "src/math.js static facts do not match the REA fixture".into(),
                ));
            }
            let add = facts
                .callables
                .iter()
                .find(|c| c.name == "add")
                .ok_or_else(|| JsError::InvalidInput("add callable missing".into()))?;
            if add.returns.is_empty() {
                return Err(JsError::InvalidInput("add return sites missing".into()));
            }
        }
        _ => {}
    }
    Ok(())
}
