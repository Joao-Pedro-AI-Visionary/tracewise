//! Hopper operations and the 5b navigation/annotation tools against the REA oracle.
//!
//! Hopper is a commercial GUI, so both sides run against a fake: `fixtures/engines/hopper/`
//! holds a launcher (`fake_hopper`, a shell script with a deterministic digest) that starts
//! `fake_hopper_launcher.py`, a stand-in for Hopper's embedded Python API backed by
//! `sample_model.json` (derived from `sample_elf`). The real, unmodified `hopper_bridge.py`
//! runs inside it and the real Rust client talks to that bridge over its Unix socket.
//!
//! Oracles (REA's original MCP server, `fixtures/engines/oracle_session.py`, with
//! `HOPPER_LAUNCHER_PATH` pointing at the fake and `force_darwin.mjs` preloaded so only the Hopper
//! provider constructor sees "darwin" and REA takes its direct launch path):
//! - `oracle_hopper.json`: the normal run (90 calls);
//! - `oracle_hopper_dropwrites.json`: the same fake with `FAKE_HOPPER_DROP_WRITES=1`, whose
//!   mutating calls report success without persisting, so the bridge's mandatory read-back fails.
//!
//! Ignored fields: see `engines_common`.

mod engines_common;

use engines_common::*;
use serde_json::json;
use sha2::{Digest, Sha256};

async fn run_against(golden_file: &str, drop_writes: bool) {
    let Some(mut env) = hopper_environment() else { return };
    env.remove("FAKE_HOPPER_DROP_WRITES");
    if drop_writes {
        env.insert("FAKE_HOPPER_DROP_WRITES".into(), "1".into());
    }
    let root = repo_root();
    let root = root.to_string_lossy().to_string();
    let target = fixture("sample_elf");
    let before = Sha256::digest(std::fs::read(&target).unwrap());
    let session = session_with(env).await;
    let golden = load_golden(golden_file);
    let failures = replay(&session, &golden, &root, true).await;
    let closed = call(&session, "close_binary", &json!({})).await;
    assert!(closed.is_ok());
    let after = Sha256::digest(std::fs::read(&target).unwrap());
    assert_eq!(before, after, "the analyzed binary must stay byte-identical");
    assert!(
        failures.is_empty(),
        "{} of {} calls differ from the oracle:\n{}",
        failures.len(),
        golden.len(),
        failures.join("\n")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn hopper_operations_match_the_oracle() {
    run_against("oracle_hopper.json", false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hopper_failed_readback_matches_the_oracle() {
    run_against("oracle_hopper_dropwrites.json", true).await;
}
