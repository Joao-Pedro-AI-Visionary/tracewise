//! `tracewise mcp` must not leave the JADX JVM or its `rea-android-*` directory behind when the
//! MCP client goes away without any explicit release: stdin closed, SIGTERM, and SIGTERM while a
//! call is still running.
//!
//! The server is the real binary, started with the real JADX engine (jadx-headless-mcp 0.7.1 on
//! Temurin 21) over the Appium ApiDemos APK, the same installation `managed_android_android_test`
//! uses. Each test gives the server a private `TMPDIR`, so the directories it owns are exactly the
//! `rea-android-*` entries there (nothing is attributed by diffing a shared `/tmp`), and looks for
//! live processes whose command line mentions one of them (the JVM runs from that directory).

mod mcp_client;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use mcp_client::Client;
use serde_json::json;

const APK: &str = "/workspace/tools/fixtures-android/ApiDemos-debug.apk";
const JAR: &str = "/workspace/tools/jadx-headless-mcp-0.7.1/jadx-headless-mcp-0.7.1-all.jar";
const JAVA_HOME: &str = "/workspace/tools/temurin-21.0.5+11";

/// Each test runs a JVM and attributes processes by directory: one at a time.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn require_oracle() -> bool {
    std::env::var("TRACEWISE_REQUIRE_ORACLE").map(|v| v == "1").unwrap_or(false)
}

fn prerequisites() -> bool {
    let java = format!("{JAVA_HOME}/bin/java");
    let missing: Vec<&str> = [APK, JAR, java.as_str()].into_iter().filter(|path| !Path::new(path).exists()).collect();
    if missing.is_empty() {
        return true;
    }
    if require_oracle() {
        panic!("TRACEWISE_REQUIRE_ORACLE=1 but {missing:?} is not installed");
    }
    eprintln!("SKIP: {missing:?} is not installed");
    false
}

/// A private temp directory for one server, removed at the end of the test.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Scratch {
        let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("android-shutdown-{}-{label}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Scratch(path)
    }

    fn runtime_dirs(&self) -> BTreeSet<String> {
        std::fs::read_dir(&self.0)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .filter(|name| name.starts_with("rea-android-"))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Live processes (pid, command line) that mention one of the server's runtime directories.
    fn processes_using(&self, dirs: &BTreeSet<String>) -> Vec<(u32, String)> {
        let mut found = Vec::new();
        let Ok(entries) = std::fs::read_dir("/proc") else { return found };
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else { continue };
            let cmdline = std::fs::read(entry.path().join("cmdline")).unwrap_or_default();
            let text = String::from_utf8_lossy(&cmdline).replace('\0', " ");
            let zombie = std::fs::read_to_string(entry.path().join("stat")).map(|s| s.contains(") Z ")).unwrap_or(false);
            if !zombie && dirs.iter().any(|dir| text.contains(&format!("{}/{dir}", self.0.display()))) {
                found.push((pid, text));
            }
        }
        found
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn start(scratch: &Scratch) -> Client {
    Client::start(&[
        ("TMPDIR", &scratch.0.to_string_lossy()),
        ("REA_JADX_MCP_JAR", JAR),
        ("JAVA_HOME", JAVA_HOME),
        ("REA_JADX_HEAP_MIB", "768"),
    ])
}

fn inspect_args() -> serde_json::Value {
    json!({ "path": APK })
}

/// Wait until the server owns a runtime directory with a live JVM in it.
fn wait_for_live_engine(scratch: &Scratch) -> BTreeSet<String> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let owned = scratch.runtime_dirs();
        if !owned.is_empty() && !scratch.processes_using(&owned).is_empty() {
            return owned;
        }
        assert!(Instant::now() < deadline, "the JADX engine never started");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Open a real JADX session, and return the directories and JVMs it owns.
fn start_with_live_engine(scratch: &Scratch) -> (Client, BTreeSet<String>) {
    let mut client = start(scratch);
    // The bridge is compiled by the JDK on the first call and the server gives the JVM 30 s to
    // answer; on a machine busy with builds that can expire. That is a failure to start the
    // engine, not the behaviour under test, so the call is retried (the failed attempt retires its
    // own session).
    let mut result = client.tool("inspect_android_package", inspect_args());
    for _ in 0..2 {
        if result["isError"] != json!(true) || !result.to_string().contains("Request timed out") {
            break;
        }
        result = client.tool("inspect_android_package", inspect_args());
    }
    assert_ne!(result["isError"], json!(true), "{result}");
    let owned = scratch.runtime_dirs();
    assert!(!owned.is_empty(), "a live JADX session must own a runtime directory");
    let processes = scratch.processes_using(&owned);
    assert!(processes.iter().any(|(_, cmdline)| cmdline.contains("java")), "the runtime must be in use by the JVM: {processes:?}");
    (client, owned)
}

fn assert_clean(scratch: &Scratch, owned: &BTreeSet<String>) {
    // Everything the server owned is gone the moment it exits: nothing is left to the idle
    // watcher thread or to the OS to clean up later.
    let dirs = scratch.runtime_dirs();
    let leftover_dirs: Vec<&String> = owned.iter().filter(|dir| dirs.contains(*dir)).collect();
    assert!(leftover_dirs.is_empty(), "runtime directories left behind: {leftover_dirs:?}");
    let leftover_processes = scratch.processes_using(owned);
    assert!(leftover_processes.is_empty(), "JADX processes left behind: {leftover_processes:?}");
}

#[test]
fn closing_stdin_releases_the_jadx_session() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    if !prerequisites() {
        return;
    }
    let scratch = Scratch::new("stdin");
    let (mut client, owned) = start_with_live_engine(&scratch);
    let since = Instant::now();
    drop(client.stdin.take());
    let (status, _) = client.wait_exit(since, Duration::from_secs(40));
    assert_eq!(status.code(), Some(0), "exit status {status:?}");
    assert_clean(&scratch, &owned);
}

#[test]
fn sigterm_releases_the_jadx_session() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    if !prerequisites() {
        return;
    }
    let scratch = Scratch::new("sigterm");
    let (mut client, owned) = start_with_live_engine(&scratch);
    let since = Instant::now();
    client.signal("TERM");
    let (status, _) = client.wait_exit(since, Duration::from_secs(40));
    assert_eq!(status.code(), Some(143), "exit status {status:?}");
    assert_clean(&scratch, &owned);
}

/// SIGTERM while the first call is still loading the APK: the call holds the session until it
/// returns, so the shutdown has to take the JVM down itself instead of waiting for the call.
#[test]
fn sigterm_during_a_running_call_releases_the_jadx_session_promptly() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    if !prerequisites() {
        return;
    }
    let scratch = Scratch::new("inflight");
    let mut client = start(&scratch);
    let _call = client.send_request("tools/call", json!({ "name": "inspect_android_package", "arguments": inspect_args() }));
    let owned = wait_for_live_engine(&scratch);
    let since = Instant::now();
    client.signal("TERM");
    let (status, took) = client.wait_exit(since, Duration::from_secs(40));
    assert_eq!(status.code(), Some(143), "exit status {status:?}");
    // The call was still being served (the JVM had only just started): had the shutdown waited
    // for it, it would have taken as long as the rest of that call (about 4 s here; with the
    // process-group kill it takes some tens of milliseconds).
    assert!(took < Duration::from_secs(2), "the shutdown waited {took:?} for a running call");
    assert_clean(&scratch, &owned);
}
