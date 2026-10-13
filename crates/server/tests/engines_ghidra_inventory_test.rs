//! Ghidra against REA's own conformance fixture (`inventory.c`, built -O2 -g): jump tables,
//! flow controls, indirect calls, DWARF types, interior pointers and a regex that exhausts
//! Java's stack, all compared with the REA oracle on the real engine.
//!
//! Oracle: `fixtures/engines/oracle_ghidra_inventory.json`, produced from
//! `fixtures/engines/calls_ghidra_inventory.json` with Ghidra 12.1.4 and Temurin 21.

mod engines_common;

use engines_common::*;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn ghidra_inventory_fixture_matches_the_oracle() {
    let Some(env) = ghidra_environment() else { return };
    let root = repo_root();
    let root = root.to_string_lossy().to_string();
    let session = session_with(env).await;
    let golden = load_golden("oracle_ghidra_inventory.json");
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
