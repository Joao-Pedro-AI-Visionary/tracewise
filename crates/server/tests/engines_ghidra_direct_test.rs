//! Ghidra direct operations (phase 5) against the REA oracle with the real engine.
//!
//! Oracle: `fixtures/engines/oracle_ghidra_direct.json`, produced by
//! `fixtures/engines/oracle_session.py fixtures/engines/calls_ghidra_direct.json` with
//! `GHIDRA_INSTALL_DIR` (Ghidra 12.1.4) and `JAVA_HOME` (Temurin 21) set. The Rust server
//! reads the same variables. Ignored fields: see `engines_common`.
//!
//! The test also proves the criteria of the port plan: the Ghidra project is ephemeral
//! (the runtime directory disappears on close) and the target bytes are unchanged.

mod engines_common;

use engines_common::*;
use serde_json::json;
use sha2::{Digest, Sha256};

/// Runtime directories and processes that still hold a private copy of the target.
fn leftovers(sha256: &str) -> Vec<String> {
    let marker = format!("target-{}", &sha256[..12]);
    let mut found = Vec::new();
    if let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with("rea-ghidra-") {
                let has_copy = std::fs::read_dir(entry.path())
                    .map(|files| files.flatten().any(|f| f.file_name().to_string_lossy().starts_with(&marker)))
                    .unwrap_or(false);
                if has_copy {
                    found.push(format!("directory {}", entry.path().display()));
                }
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let cmdline = std::fs::read(entry.path().join("cmdline")).unwrap_or_default();
            if String::from_utf8_lossy(&cmdline).contains(&marker) {
                found.push(format!("process {}", entry.file_name().to_string_lossy()));
            }
        }
    }
    found
}

#[tokio::test(flavor = "multi_thread")]
async fn ghidra_direct_operations_match_the_oracle() {
    let Some(env) = ghidra_environment() else { return };
    let root = repo_root();
    let root = root.to_string_lossy().to_string();
    let target = fixture("sample_elf");
    let before = Sha256::digest(std::fs::read(&target).unwrap());
    let session = session_with(env).await;
    let golden = load_golden("oracle_ghidra_direct.json");
    let failures = replay(&session, &golden, &root, true).await;
    let closed = call(&session, "close_binary", &json!({})).await;
    assert!(closed.is_ok());
    let after = Sha256::digest(std::fs::read(&target).unwrap());
    assert_eq!(before, after, "target bytes must stay unchanged");
    // The ephemeral project, the private target copy and the JVM disappear with close_binary.
    let sha256 = hex::encode(before);
    let mut remaining = leftovers(&sha256);
    for _ in 0..50 {
        if remaining.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        remaining = leftovers(&sha256);
    }
    assert!(remaining.is_empty(), "close_binary left Ghidra state behind: {remaining:?}");
    assert!(
        failures.is_empty(),
        "{} of {} calls differ from the oracle:\n{}",
        failures.len(),
        golden.len(),
        failures.join("\n")
    );
}
