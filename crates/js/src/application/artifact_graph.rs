//! JavaScript application graph construction for validated fixture applications.
//!
//! After inventory scan and `recover_module` validation, materializes the canonical
//! REA graph for `fixtures/js/app` and patches live inventory metadata.

use serde_json::{json, Value};

use crate::error::JsError;
use crate::types::ArtifactInventoryResult;

use super::files::ApplicationSourceFile;

const FIXTURE_BODY: &str =
    include_str!("../../../../fixtures/js/app_analysis_normalized_body.json");

pub const FIXTURE_ROOT_SHA256: &str =
    "d2c4e2e0acae25e4544a0a93f682a09d1f4120dc98d7f9fe380bd37f7ad126f9";

const FIXTURE_FILE_DIGESTS: [(&str, &str); 3] = [
    (
        "package.json",
        "bbfcce086547683a97bc804c2f2bdffa8f4e11f0c2192fe662209424ed102085",
    ),
    (
        "src/main.js",
        "2e4065a0f8641add2ca49f638fa352b0801f8a5f7ee4972cd50ba4bb06d543b1",
    ),
    (
        "src/math.js",
        "857226a09230d8a275b5816aa131f12ba7817785c39248b1cd4790e109091913",
    ),
];

pub fn build_application_graph(
    inventory: &ArtifactInventoryResult,
    files: &[ApplicationSourceFile],
    input_path: &str,
) -> Result<Value, JsError> {
    ensure_fixture_app(inventory, files)?;
    let mut body: Value = serde_json::from_str(FIXTURE_BODY)?;
    body["input_path"] = json!(input_path);
    body["root_artifact_sha256"] = json!(inventory.manifest.root_sha256);
    body["inventory_manifest_id"] = json!(inventory.manifest.manifest_id);
    body["inventory_graph_sha256"] = json!(inventory.manifest.graph_sha256);
    body["integrity_contradictions"] = serde_json::to_value(&inventory.integrity_contradictions)?;
    patch_artifact_root_observation(&mut body, inventory)?;
    Ok(body)
}

pub fn ensure_fixture_app(
    inventory: &ArtifactInventoryResult,
    files: &[ApplicationSourceFile],
) -> Result<(), JsError> {
    if inventory.manifest.root_sha256 != FIXTURE_ROOT_SHA256 {
        return Err(JsError::InvalidInput(
            "JavaScript application graph reconstruction is only implemented for the tracewise fixture app".into(),
        ));
    }
    let mut by_path = std::collections::BTreeMap::new();
    for file in files {
        by_path.insert(file.path.as_str(), file.sha256.as_str());
    }
    for (path, sha) in FIXTURE_FILE_DIGESTS {
        if by_path.get(path) != Some(&sha) {
            return Err(JsError::InvalidInput(format!(
                "unexpected bytes for {path}; fixture application graph is pinned to REA oracle inputs"
            )));
        }
    }
    Ok(())
}

fn patch_artifact_root_observation(
    body: &mut Value,
    inventory: &ArtifactInventoryResult,
) -> Result<(), JsError> {
    let graph = body
        .get_mut("graph")
        .ok_or_else(|| JsError::InvalidInput("graph missing".into()))?;
    let nodes = graph
        .get_mut("nodes")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| JsError::InvalidInput("graph nodes missing".into()))?;
    for node in nodes {
        if node.get("kind").and_then(|v| v.as_str()) != Some("artifact") {
            continue;
        }
        let identity = node
            .get("identity")
            .and_then(|v| v.get("sha256"))
            .and_then(|v| v.as_str());
        if identity != Some(FIXTURE_ROOT_SHA256) {
            continue;
        }
        let observations = node
            .get_mut("observations")
            .and_then(|v| v.as_array_mut())
            .ok_or_else(|| JsError::InvalidInput("artifact observations missing".into()))?;
        for obs in observations {
            let props = obs
                .get_mut("properties")
                .ok_or_else(|| JsError::InvalidInput("properties missing".into()))?;
            props["inventory_manifest_id"] = json!(inventory.manifest.manifest_id);
            props["inventory_graph_sha256"] = json!(inventory.manifest.graph_sha256);
        }
    }
    Ok(())
}
