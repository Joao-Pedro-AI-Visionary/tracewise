//! Provider selection errors with no engine configured: the unbound route answers every engine
//! tool with REA's `provider_unavailable` body and its per-candidate rejection diagnostics.
//!
//! Oracle: `fixtures/engines/oracle_selection.json`, produced with `GHIDRA_INSTALL_DIR`,
//! `JAVA_HOME`, `HOPPER_LAUNCHER_PATH` and `REA_IDA_MCP_CONFIG` unset on a host without Java on
//! PATH and without Hopper at its default launcher path (the diagnostics name both). REA rejects
//! an explicit `provider_id` inside `open_binary`; tracewise's phase-0 `open_binary` accepts it
//! and the same selection error is returned by the first engine tool that needs the provider,
//! which is what this test compares.

mod engines_common;

use std::collections::BTreeMap;

use engines_common::*;
use serde_json::{json, Value};

fn host_matches_golden() -> bool {
    let java_on_path = std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .any(|dir| std::path::Path::new(dir).join("java").exists());
    !java_on_path && !std::path::Path::new("/opt/hopper/bin/Hopper").exists()
}

fn bare_environment() -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = std::env::vars().collect();
    for key in ["GHIDRA_INSTALL_DIR", "JAVA_HOME", "HOPPER_LAUNCHER_PATH", "HOPPER_LOADER_ARGS_JSON", "REA_IDA_MCP_CONFIG", "REA_ANALYSIS_PROVIDER"] {
        env.remove(key);
    }
    env
}

#[tokio::test(flavor = "multi_thread")]
async fn unconfigured_engines_answer_with_the_selection_error_of_rea() {
    if !host_matches_golden() {
        if oracle_required() {
            panic!("TRACEWISE_REQUIRE_ORACLE=1 but this host has Java on PATH or Hopper installed, which the golden diagnostics exclude");
        }
        eprintln!("SKIP: this host has Java on PATH or Hopper installed, which the golden diagnostics exclude");
        return;
    }
    let root = repo_root();
    let root = root.to_string_lossy().to_string();
    let golden = load_golden("oracle_selection.json");
    let session = session_with(bare_environment()).await;
    // Entries 0..=3: open, then three engine tools against the unbound route.
    let failures = replay(&session, &golden[..4], &root, true).await;
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    // Entries 4..: explicit provider_id; REA fails inside open_binary.
    let target = fixture("sample_elf");
    for (index, entry) in golden.iter().enumerate().skip(4) {
        let provider = entry["arguments"]["provider_id"].clone();
        let fresh = session_with(bare_environment()).await;
        let opened = call(&fresh, "open_binary", &json!({ "path": target.to_string_lossy(), "provider_id": provider })).await;
        assert!(opened.is_ok());
        let actual = call(&fresh, "list_procedures", &json!({})).await;
        let mut got = comparable(&rust_result_value(&actual), &root);
        let want = comparable(&entry["result"], &root);
        // The failing operation is open_binary in REA and the first engine tool here.
        if let Some(details) = got.pointer_mut("/body/error/details").and_then(Value::as_object_mut) {
            details.insert("operation".into(), json!("open_binary"));
        }
        assert_eq!(got, want, "entry #{index} (provider_id {provider})");
    }
}
