//! `inspect_asset_catalog` through the MCP dispatcher.
//!
//! REA computes discovery, hashing, paging, the Interface Builder key join and the failures itself
//! and delegates only the catalog decoding to macOS `assetutil`. The scenarios in
//! `fixtures/native_static/assets/scenarios.json` replay that REA code (its dist build) with an
//! injected `assetutil` that returns the records of this project's own catalog reader for the
//! same file, so the comparison covers everything REA owns. The decoder itself is checked against
//! the CARHEADER rendition counts of the seven versioned real catalogs (`crates/native/tests/car_real_catalogs.rs`)
//! and by the real catalogs in `assets/vendor`.
//!
//! Intentionally different (not silently ignored): the three limitation sentences that name the
//! decoder (assetutil in REA, the native catalog reader here).

mod native_support;

use base64::Engine;
use serde_json::{json, Value};
use tracewise_server::session::BinarySession;

use native_support::{call, fixtures, output_schema, payload};

fn assert_schema(result: &rmcp::model::CallToolResult) {
    let structured = result.structured_content.clone().expect("structured content");
    let validator = jsonschema::validator_for(&output_schema("inspect_asset_catalog").expect("schema")).expect("schema");
    if let Err(error) = validator.validate(&structured) {
        panic!("inspect_asset_catalog violates its outputSchema: {error}");
    }
}

async fn open(session: &BinarySession, path: &std::path::Path) {
    let result = call(session, "open_binary", &json!({"path": path.to_string_lossy()})).await.unwrap();
    assert_ne!(result.is_error, Some(true), "open_binary failed: {:?}", payload(&result));
}

fn error_of(result: &rmcp::model::CallToolResult) -> Value {
    assert_eq!(result.is_error, Some(true), "expected a failure");
    let text = result.content.iter().find_map(|c| c.as_text().map(|t| t.text.clone())).unwrap();
    match serde_json::from_str::<Value>(&text) {
        Ok(value) => value["error"].clone(),
        Err(_) => json!({"text": text}),
    }
}

fn build_layout(root: &std::path::Path, scenario: &Value) {
    let engine = base64::engine::general_purpose::STANDARD;
    let items = scenario["base"].as_array().unwrap().iter().chain(scenario["layout"].as_array().unwrap());
    for item in items {
        let target = root.join(item["path"].as_str().unwrap());
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        if let Some(link) = item["symlink"].as_str() {
            std::os::unix::fs::symlink(link, &target).unwrap();
        } else if let Some(source) = item["source"].as_str() {
            std::fs::copy(fixtures().join("assets").join(source), &target).unwrap();
        } else if let Some(bytes) = item["bytes_b64"].as_str().or_else(|| item["text_b64"].as_str()) {
            std::fs::write(&target, engine.decode(bytes).unwrap()).unwrap();
        } else {
            std::fs::write(&target, item["text"].as_str().unwrap()).unwrap();
        }
    }
}

fn scenarios() -> Value {
    serde_json::from_str(&std::fs::read_to_string(fixtures().join("assets/scenarios.json")).unwrap()).unwrap()
}

fn work_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("native-static-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn names_the_decoder(text: &str) -> bool {
    text.starts_with("Rendition metadata follows the field names of Apple")
        || text.starts_with("Rendition metadata is reported as emitted by the installed assetutil")
        || text.starts_with("Records come from tracewise")
}

#[tokio::test]
async fn inspect_asset_catalog_matches_rea_on_everything_rea_computes() {
    let spec = scenarios();
    let work = work_dir("assets");
    for scenario in spec["scenarios"].as_array().unwrap() {
        let id = scenario["id"].as_str().unwrap();
        let root = work.join(format!("{id}.app"));
        build_layout(&root, scenario);
        let session = BinarySession::new();
        open(&session, &root).await;
        let expected = &scenario["expected"];
        let result = call(&session, "inspect_asset_catalog", &scenario["page"]).await.unwrap();
        if expected["ok"] == true {
            assert_ne!(result.is_error, Some(true), "{id}: {:?}", payload(&result));
            assert_schema(&result);
            let got = &result.structured_content.clone().unwrap()["normalized_result"];
            let want = &expected["value"];
            for key in [
                "target_sha256",
                "catalogs",
                "total_records",
                "offset",
                "limit",
                "records",
                "resource_key_matches",
                "next_offset",
                "truncated",
            ] {
                assert_eq!(got[key], want[key], "{id}: {key}");
            }
            let keep = |limitations: &Value| -> Vec<String> {
                limitations
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|l| l.as_str().unwrap().to_string())
                    .filter(|l| !names_the_decoder(l))
                    .collect()
            };
            assert_eq!(keep(&got["limitations"]), keep(&want["limitations"]), "{id}: limitations");
        } else {
            let error = error_of(&result);
            assert_eq!(error["code"], "artifact_operation_failed", "{id}");
            assert_eq!(error["details"]["reason"], expected["error"]["reason"], "{id}");
            assert!(
                error["details"].to_string().contains(expected["error"]["message"].as_str().unwrap()),
                "{id}: {error}"
            );
        }
    }
    std::fs::remove_dir_all(&work).ok();
}

#[tokio::test]
async fn inspect_asset_catalog_validates_input_and_rejects_non_catalogs() {
    let session = BinarySession::new();
    let none = call(&session, "inspect_asset_catalog", &json!({})).await.unwrap();
    assert_eq!(error_of(&none)["code"], "target_unavailable");
    for (arguments, message) in [
        (json!({"limit": 0}), "limit: Too small: expected number to be >=1"),
        (json!({"offset": -1}), "offset: Too small: expected number to be >=0"),
        (json!({"limit": 20000}), "limit: Too big: expected number to be <=10000"),
    ] {
        let result = call(&session, "inspect_asset_catalog", &arguments).await.unwrap();
        assert_eq!(
            error_of(&result)["text"],
            format!("Input validation error: Invalid arguments for tool inspect_asset_catalog: {message}")
        );
    }
    open(&session, &fixtures().join("codesign/unsigned_arm64.macho")).await;
    let unsupported = call(&session, "inspect_asset_catalog", &json!({})).await.unwrap();
    assert_eq!(error_of(&unsupported)["code"], "unsupported_target");

    // A file named Assets.car that is not a BOM store is a format failure, not an empty catalog.
    let spec = scenarios();
    let work = work_dir("assets-bad");
    let root = work.join("bad.app");
    let scenario = json!({
        "base": spec["scenarios"][0]["base"],
        "layout": [{"path": "Contents/Resources/Assets.car", "text": "this is not a BOM store"}],
    });
    build_layout(&root, &scenario);
    let session = BinarySession::new();
    open(&session, &root).await;
    let result = call(&session, "inspect_asset_catalog", &json!({})).await.unwrap();
    let error = error_of(&result);
    assert_eq!(error["code"], "artifact_operation_failed");
    assert_eq!(error["details"]["reason"], "format");
    assert!(error["details"].to_string().contains("not a BOM store"));
    std::fs::remove_dir_all(&work).ok();
}

#[tokio::test]
async fn inspect_asset_catalog_decodes_a_real_catalog() {
    let spec = scenarios();
    let work = work_dir("assets-real");
    let root = work.join("real.app");
    let scenario = spec["scenarios"].as_array().unwrap().iter().find(|s| s["id"] == "mac_default").unwrap();
    build_layout(&root, scenario);
    let session = BinarySession::new();
    open(&session, &root).await;
    let result = call(&session, "inspect_asset_catalog", &json!({"limit": 3})).await.unwrap();
    assert_ne!(result.is_error, Some(true), "{:?}", payload(&result));
    assert_schema(&result);
    let evidence = result.structured_content.unwrap();
    let normalized = &evidence["normalized_result"];
    // The CARHEADER of assets_mac.car declares 73 renditions; the header record is index 0.
    assert_eq!(normalized["total_records"], 74);
    let header = &normalized["records"][0]["metadata"];
    assert_eq!(normalized["records"][0]["kind"], "catalog");
    assert_eq!(header["CoreUIVersion"], 366);
    assert_eq!(header["StorageVersion"], 11);
    assert_eq!(header["Key Format"][0], "kCRThemeElementName");
    assert_eq!(normalized["records"][1]["kind"], "rendition");
    assert_eq!(evidence["locations"], json!([{"kind": "artifact-path", "path": "Contents/Resources/Assets.car"}]));
    std::fs::remove_dir_all(&work).ok();
}
