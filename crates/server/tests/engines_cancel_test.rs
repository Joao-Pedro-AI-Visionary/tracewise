//! Cancelling an engine call mid-startup must not leak the provider process or its runtime
//! directory, and the next call must start a clean session (an MCP cancellation drops the
//! in-flight tool future).

mod engines_common;

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use engines_common::*;
use serde_json::json;

/// Runtime directory names (`rea-ghidra-*`) named by the command line of a live Ghidra process
/// that works on the sample target. Other test runs on a shared machine have their own.
fn ghidra_process_runtimes() -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let cmdline = std::fs::read(entry.path().join("cmdline")).unwrap_or_default();
            let text = String::from_utf8_lossy(&cmdline).replace('\0', " ");
            if !text.contains("target-61ec63014") {
                continue;
            }
            for word in text.split(|c: char| c == '/' || c.is_whitespace()) {
                if word.starts_with("rea-ghidra-") {
                    found.insert(word.to_string());
                }
            }
        }
    }
    found
}

/// `rea-ghidra-*` runtime directories in the temp directory.
fn runtime_dirs() -> BTreeSet<String> {
    std::fs::read_dir(std::env::temp_dir())
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .filter(|name| name.starts_with("rea-ghidra-"))
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread")]
async fn dropping_a_call_during_startup_stops_ghidra_and_the_next_call_recovers() {
    let Some(env) = ghidra_environment() else { return };
    let session = session_with(env).await;
    let target = fixture("sample_elf");
    let opened = call(&session, "open_binary", &json!({ "path": target.to_string_lossy() })).await;
    assert!(opened.is_ok());

    let dirs_before = runtime_dirs();
    let processes_before = ghidra_process_runtimes();

    // Abandon the call only once the headless process really exists, not after a fixed delay.
    let started = async {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let appeared: BTreeSet<String> = ghidra_process_runtimes().difference(&processes_before).cloned().collect();
            if !appeared.is_empty() {
                let dirs: BTreeSet<String> = runtime_dirs().difference(&dirs_before).cloned().collect();
                assert!(!dirs.is_empty(), "a started session must own a runtime directory");
                return appeared;
            }
            assert!(Instant::now() < deadline, "Ghidra never started");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    let arguments = json!({});
    let launched = tokio::select! {
        appeared = started => appeared,
        _ = call(&session, "list_procedures", &arguments) => panic!("the call finished before the abandon point"),
    };
    assert!(!launched.is_empty());

    // The in-flight call future has now been dropped by the select above.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let leftover_processes: BTreeSet<String> =
            ghidra_process_runtimes().difference(&processes_before).cloned().collect();
        let leftover_dirs: BTreeSet<String> = runtime_dirs().difference(&dirs_before).cloned().collect();
        if leftover_processes.is_empty() && leftover_dirs.is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "cancelled startup left processes {leftover_processes:?} or directories {leftover_dirs:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // A fresh call re-imports the artifact and succeeds.
    let result = call(&session, "list_documents", &json!({})).await.expect("tool result");
    assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
    let closed = call(&session, "close_binary", &json!({})).await;
    assert!(closed.is_ok());
}
