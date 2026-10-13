//! Parity of the path-based native tools with the REA oracle:
//! `inspect_pe_resources`, `inspect_evm_interface` (and, once added,
//! `inspect_binary_layout`, `inspect_recorded_crash`).
//!
//! Ignored fields (beyond the shared normalization in `native_support`):
//! - `inspect_evm_interface`: `limitations` (evidence and result). REA lists the
//!   resource limits of its owned worker process; tracewise analyses in-process
//!   and states that instead. The shared sentences are asserted separately.

mod native_support;

use native_support::{call, run_scenarios};
use serde_json::{json, Value};
use tracewise_server::session::BinarySession;

#[tokio::test]
async fn inspect_pe_resources_matches_oracle() {
    assert!(run_scenarios("pe_", &[]).await >= 28);
}

#[tokio::test]
async fn inspect_evm_interface_matches_oracle() {
    let compared = run_scenarios(
        "evm_",
        &[&["structured", "limitations"], &["structured", "normalized_result", "limitations"]],
    )
    .await;
    assert!(compared >= 25);
}

#[tokio::test]
async fn evm_limitations_keep_the_shared_caveats() {
    let session = BinarySession::new();
    let path = native_support::fixtures().join("evm/doc.hex");
    let result = call(
        &session,
        "inspect_evm_interface",
        &json!({"path": path.to_string_lossy(), "encoding": "hex"}),
    )
    .await
    .unwrap();
    let limitations = result.structured_content.unwrap()["limitations"].to_string();
    for sentence in [
        "Recovered selectors, argument strings and mutability are upstream inferences",
        "Bytecode kind, hardfork and deployed-contract authenticity are unknown",
        "Original carrier and decoded bytecode SHA-256 are distinct identities",
    ] {
        assert!(limitations.contains(sentence), "missing: {sentence}");
    }
}

// ---------------------------------------------------------------------------
// inspect_binary_layout
//
// Ignored fields (documented, not silent):
// - `provider`: tracewise reports its own adapter identity, REA reports the pwntools adapter;
//   the parent Evidence id (and so every id derived from it in `detail: summary`) differs with it.
// - `normalized_result.diagnostics`: REA's stderr carries host-specific pwntools/Unicorn
//   warnings (its 3 GiB address-space limit makes the PLT emulation fail); compared against the
//   unconstrained bridge reference below instead.
// - `normalized_result.linkage.plt`: same reason.
// - the limitation "Effective owned Python resource soft limits ..." (REA's Python sandbox).
// ---------------------------------------------------------------------------

const LAYOUT_IGNORE: &[&[&str]] = &[
    &["structured", "provider"],
    &["structured", "normalized_result", "diagnostics"],
    &["structured", "normalized_result", "linkage", "plt"],
    &["structured", "parameters", "parent_evidence_id"],
    &["structured", "evidence_links"],
    &["structured", "normalized_result", "parent_evidence_id"],
    &["structured", "normalized_result", "parent_digest"],
    &["structured", "normalized_result", "view_digest"],
    &["error", "error", "details", "captured_output", "stderr"],
];

/// REA's Python sandbox sentence and the Rust port's execution-model sentence.
const LAYOUT_DROPPED_LIMITATIONS: &[&str] = &[
    "Effective owned Python resource soft limits",
    "The layout was decoded in-process by the Rust port",
];

#[tokio::test]
async fn inspect_binary_layout_matches_oracle() {
    let compared = native_support::run_scenarios_with(
        "layout_",
        LAYOUT_IGNORE,
        LAYOUT_DROPPED_LIMITATIONS,
    )
    .await;
    assert!(compared >= 55);
}

/// The unconstrained pwntools bridge (REA's own `layout_impl.py` without its 3 GiB limit)
/// is the reference for the PLT map, the stderr warnings and the failure messages.
#[tokio::test]
async fn inspect_binary_layout_matches_bridge_reference() {
    use std::path::Path;
    let reference_dir = native_support::fixtures().join("bridge_reference");
    let mut checked = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&reference_dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().trim_end_matches(".json").to_string();
        let reference: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(entry.path()).unwrap()).unwrap();
        let candidates = [
            native_support::fixtures().join("elf").join(&name),
            native_support::fixtures().join("elf/variants").join(&name),
        ];
        let path = candidates.iter().find(|p| Path::new(p).is_file()).expect("fixture for reference");
        let session = BinarySession::new();
        let result = call(
            &session,
            "inspect_binary_layout",
            &json!({"path": path.to_string_lossy()}),
        )
        .await
        .unwrap();
        if reference["ok"] == json!(true) {
            let evidence = result.structured_content.clone().unwrap_or_else(|| panic!("{name}: expected success"));
            let report = &evidence["normalized_result"];
            let mut expected = reference["value"].clone();
            let mut got = report.clone();
            for value in [&mut expected, &mut got] {
                if let Some(object) = value.as_object_mut() {
                    object.remove("artifact");
                    object.remove("diagnostics");
                }
                if let Some(Value::Array(items)) = value.get_mut("limitations") {
                    items.retain(|item| {
                        let text = item.as_str().unwrap_or("");
                        !LAYOUT_DROPPED_LIMITATIONS.iter().any(|prefix| text.starts_with(prefix))
                    });
                }
            }
            if expected != got {
                let dir = std::env::temp_dir().join("native_static_diff");
                let _ = std::fs::create_dir_all(&dir);
                let _ = std::fs::write(dir.join(format!("bridge_{name}.expected.json")), serde_json::to_string_pretty(&expected).unwrap());
                let _ = std::fs::write(dir.join(format!("bridge_{name}.actual.json")), serde_json::to_string_pretty(&got).unwrap());
                failures.push(format!("{name}: payload differs from the bridge reference"));
            }
            let stderr = report["diagnostics"]["stderr"].as_str().unwrap_or("");
            // The bridge also logs unexpected `Could not populate ...` warnings for damaged inputs.
            if reference["stderr"].as_str().unwrap_or("") != stderr {
                failures.push(format!("{name}: stderr {:?} != reference {:?}", stderr, reference["stderr"]));
            }
        } else {
            assert_eq!(result.is_error, Some(true), "{name}: expected a failure");
            let text = result.content.iter().find_map(|c| c.as_text().map(|t| t.text.clone())).unwrap();
            let message = reference["message"].as_str().unwrap_or("");
            if !text.contains(&serde_json::to_string(message).unwrap().trim_matches('"').to_string()) {
                failures.push(format!("{name}: failure message does not carry {message:?}: {text}"));
            }
            let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            let stderr = body["error"]["details"]["captured_output"]["stderr"].as_str().unwrap_or("");
            if reference["stderr"].as_str().unwrap_or("") != stderr {
                failures.push(format!("{name}: failure stderr {:?} != reference {:?}", stderr, reference["stderr"]));
            }
        }
        checked += 1;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(checked >= 40);
}

// ---------------------------------------------------------------------------
// inspect_recorded_crash
//
// Ignored fields: `provider` (tracewise reports its own adapter identity). The debugger scenario
// (`include_debugger_context`) compares the capability error REA raises when GDB/pwndbg is not
// configured; a configured pwndbg is reported as unsupported by the native port (not run).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn inspect_recorded_crash_matches_oracle() {
    let compared = native_support::run_scenarios_with(
        "crash_",
        &[&["structured", "provider"]],
        &[
            "Effective owned Python resource soft limits",
            "The core was decoded in-process by the Rust port",
        ],
    )
    .await;
    assert!(compared >= 40);
}
