//! Ghidra-backed workflows (phase 5) against the REA oracle with the real engine.
//!
//! Oracle: `fixtures/engines/oracle_ghidra_workflows.json`, produced by
//! `fixtures/engines/oracle_session.py fixtures/engines/calls_ghidra_workflows.json` with
//! `GHIDRA_INSTALL_DIR` (Ghidra 12.1.4) and `JAVA_HOME` (Temurin 21) set. Ignored fields:
//! see `engines_common`.

mod engines_common;

use engines_common::*;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn ghidra_workflows_match_the_oracle() {
    let Some(env) = ghidra_environment() else { return };
    let root = repo_root();
    let root = root.to_string_lossy().to_string();
    let session = session_with(env).await;
    let golden = load_golden("oracle_ghidra_workflows.json");
    let failures = replay(&session, &golden, &root, true).await;
    let closed = call(&session, "close_binary", &json!({})).await;
    assert!(closed.is_ok());
    assert!(
        failures.is_empty(),
        "{} of {} calls differ from the oracle:\n{}",
        failures.len(),
        golden.len(),
        failures.join("\n")
    );
}
