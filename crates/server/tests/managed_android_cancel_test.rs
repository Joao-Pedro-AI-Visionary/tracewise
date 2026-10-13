//! Cancellation: when MCP drops a tool future (`tokio::select!` in
//! `handlers.rs`), the child processes and private temp directories of the
//! Apktool, JADX and JEB tools must not outlive it.
//!
//! * Apktool: `fixtures/android/fake-apktool-slow.sh` is a wrapper that does not
//!   `exec` (it runs `sleep 300` as a child and another in the background), the
//!   case in which killing only the launcher would leave orphans. The future is
//!   dropped in the middle of the decode; no process of the launcher's group may
//!   remain and its `/tmp/rea-apktool-*` workspace must be gone.
//! * JADX: the real engine (pinned JDK + jadx-headless-mcp, see
//!   `managed_android_android_test.rs`). Dropped while the JVM is running; the
//!   JVM must die, the `/tmp/rea-android-*` directory must be removed and no
//!   session may stay retained.
//! * JEB: `fake-jeb.mjs hang-call` never answers a tool call. After the drop the
//!   provider must be free again within seconds (the call does not sit on its
//!   300 s timeout).

mod managed_android_support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use managed_android_support::require_or_skip;
use rmcp::model::CallToolRequestParam;
use serde_json::{json, Value};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

const APK: &str = "/workspace/tools/fixtures-android/ApiDemos-debug.apk";
const JAR: &str = "/workspace/tools/jadx-headless-mcp-0.7.1/jadx-headless-mcp-0.7.1-all.jar";
const JDK_HOME: &str = "/workspace/tools/temurin-21.0.5+11";

/// Tests here change process environment variables; run them one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn fixtures(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures").join(name).canonicalize().expect(name)
}

fn request(tool: &str, args: Value) -> CallToolRequestParam {
    CallToolRequestParam { name: tool.to_string().into(), arguments: Some(args.as_object().cloned().unwrap_or_default()) }
}

/// `(pid, state, pgrp)` of every process, from /proc.
fn processes() -> Vec<(i32, char, i32)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<i32>().ok()) else { continue };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else { continue };
        let Some(after) = stat.rsplit_once(')').map(|(_, rest)| rest.trim_start().to_string()) else { continue };
        let fields: Vec<&str> = after.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        if let (Some(state), Ok(pgrp)) = (fields[0].chars().next(), fields[2].parse::<i32>()) {
            out.push((pid, state, pgrp));
        }
    }
    out
}

/// Live (non-zombie) members of a process group.
fn group_members(pgid: i32) -> Vec<i32> {
    processes().into_iter().filter(|(_, state, pgrp)| *pgrp == pgid && *state != 'Z').map(|(pid, _, _)| pid).collect()
}

/// Live processes whose command line mentions `needle`.
fn processes_mentioning(needle: &str) -> Vec<i32> {
    let mut found = Vec::new();
    for (pid, state, _) in processes() {
        if state == 'Z' {
            continue;
        }
        if let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) {
            if String::from_utf8_lossy(&cmdline).replace('\0', " ").contains(needle) {
                found.push(pid);
            }
        }
    }
    found
}

fn tmp_dirs(prefix: &str) -> BTreeSet<String> {
    std::fs::read_dir("/tmp")
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .filter(|n| n.starts_with(prefix))
        .collect()
}

async fn wait_for<T>(what: &str, limit: Duration, mut probe: impl FnMut() -> Option<T>) -> T {
    let started = Instant::now();
    loop {
        if let Some(value) = probe() {
            return value;
        }
        assert!(started.elapsed() < limit, "timed out after {limit:?} waiting for {what}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn dropping_an_apktool_decode_kills_the_launcher_group_and_removes_the_workspace() {
    let _serial = SERIAL.lock().await;
    let launcher = fixtures("android").join("fake-apktool-slow.sh");
    let pidfile = std::env::temp_dir().join(format!("tracewise-slow-{}.pids", std::process::id()));
    let _ = std::fs::remove_file(&pidfile);
    std::env::set_var("REA_APKTOOL_COMMAND", &launcher);
    std::env::set_var("SLOW_PIDFILE", &pidfile);
    let before = tmp_dirs("rea-apktool-");
    let session = BinarySession::new();
    let input = fixtures("android").join("fake-apktool-slow.sh");
    let call = call_tool_local(&session, request("decode_android_resources", json!({ "path": input })));
    // Cancel as soon as the wrapper is running its slow decode.
    let mut call = Box::pin(call);
    let wrapper: i32 = {
        tokio::select! {
            _ = &mut call => panic!("the slow decode finished by itself"),
            pid = wait_for("the slow launcher to start", Duration::from_secs(30), || {
                let text = std::fs::read_to_string(&pidfile).ok()?;
                let mut lines = text.lines();
                let wrapper: i32 = lines.next()?.trim().parse().ok()?;
                lines.next()?.trim().parse::<i32>().ok()?;
                Some(wrapper)
            }) => pid,
        }
    };
    assert!(group_members(wrapper).len() >= 3, "wrapper, background sleep and foreground sleep: {:?}", group_members(wrapper));
    assert!(tmp_dirs("rea-apktool-").difference(&before).count() >= 1, "decode workspace exists while running");
    drop(call); // the MCP request was cancelled
    wait_for("the launcher's whole process group to die", Duration::from_secs(10), || group_members(wrapper).is_empty().then_some(())).await;
    wait_for("the decode workspace to be removed", Duration::from_secs(10), || {
        tmp_dirs("rea-apktool-").difference(&before).next().is_none().then_some(())
    })
    .await;
    std::env::remove_var("REA_APKTOOL_COMMAND");
    std::env::remove_var("SLOW_PIDFILE");
    let _ = std::fs::remove_file(&pidfile);
}

#[tokio::test]
async fn dropping_a_jadx_inspection_kills_the_jvm_and_removes_its_directory() {
    let _serial = SERIAL.lock().await;
    for path in [APK, JAR, JDK_HOME] {
        if !Path::new(path).exists() {
            require_or_skip(&format!("{path} is not installed"));
            return;
        }
    }
    tracewise_android::jadx::retire_retained();
    std::env::set_var("REA_JADX_MCP_JAR", JAR);
    std::env::set_var("JAVA_HOME", JDK_HOME);
    let before = tmp_dirs("rea-android-");
    let session = BinarySession::new();
    let mut call = Box::pin(call_tool_local(&session, request("inspect_android_package", json!({ "path": APK }))));
    let directory = {
        tokio::select! {
            _ = &mut call => panic!("the inspection finished before it could be cancelled"),
            dir = wait_for("the engine's private directory", Duration::from_secs(30), || {
                let created = tmp_dirs("rea-android-");
                let new = created.difference(&before).next()?.clone();
                // The JVM is running once its command line names the directory.
                (!processes_mentioning(&new).is_empty()).then_some(new)
            }) => dir,
        }
    };
    let jvm = processes_mentioning(&directory);
    assert!(!jvm.is_empty(), "the JVM is running before the drop");
    drop(call);
    wait_for("the JVM to exit", Duration::from_secs(15), || processes_mentioning(&directory).is_empty().then_some(())).await;
    wait_for("the private directory to be removed", Duration::from_secs(15), || {
        (!Path::new("/tmp").join(&directory).exists()).then_some(())
    })
    .await;
    wait_for("the session to be released", Duration::from_secs(15), || (!tracewise_android::jadx::has_retained()).then_some(())).await;
    std::env::remove_var("REA_JADX_MCP_JAR");
    std::env::remove_var("JAVA_HOME");
}

#[tokio::test]
async fn dropping_a_jeb_call_frees_the_provider_promptly() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    let _serial = SERIAL.lock().await;
    let node = ["node", "/workspace/tools/node-v22.23.3-linux-x64/bin/node", "/tmp/node-v22.20.0-linux-x64/bin/node"]
        .into_iter()
        .find(|c| Command::new(c).arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success()));
    let Some(node) = node else {
        require_or_skip("node is not available for the JEB test double");
        return;
    };
    struct Fake(std::process::Child);
    impl Drop for Fake {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let spawn = |mode: &str| {
        let mut child = Command::new(node)
            .arg(fixtures("android").join("fake-jeb.mjs"))
            .arg(mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
        (Fake(child), line.trim().to_string())
    };
    let (_hanging, hanging_url) = spawn("hang-call");
    let (_normal, normal_url) = spawn("normal");
    tracewise_android::jeb::reset();
    std::env::set_var("REA_JEB_MCP_URL", &hanging_url);
    let session = BinarySession::new();
    // Give the call time to reach the engine, then cancel it.
    let outcome = tokio::time::timeout(Duration::from_millis(800), call_tool_local(&session, request("inspect_jeb_client", json!({})))).await;
    assert!(outcome.is_err(), "the hanging engine never answers");
    // The provider is serialized: if the cancelled call still held it for its 300 s
    // timeout, this would not finish.
    std::env::set_var("REA_JEB_MCP_URL", &normal_url);
    let started = Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(10), call_tool_local(&session, request("inspect_jeb_client", json!({}))))
        .await
        .expect("the provider was still busy after the cancelled call")
        .unwrap();
    assert_eq!(result.is_error, Some(false), "{result:?}");
    assert!(started.elapsed() < Duration::from_secs(5), "took {:?}", started.elapsed());
    std::env::remove_var("REA_JEB_MCP_URL");
    tracewise_android::jeb::reset();
}
