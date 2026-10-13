//! `tracewise mcp` must not leave engine processes or runtime directories behind when the MCP
//! client goes away without `close_binary`: stdin closed, SIGTERM and SIGINT.
//!
//! The server is the real binary, started with the real Ghidra (the same installation the
//! engines parity tests use). The test opens the sample ELF, runs a Ghidra tool so that the JVM,
//! its project, the target copy and the session descriptor exist, then ends the server in one
//! of the three ways and checks the process table and the temp directory.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// The tests attribute runtime directories by diffing the temp directory, and each runs a 1 GB JVM:
/// run them one at a time.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("repo root")
}

fn require_oracle() -> bool {
    std::env::var("TRACEWISE_REQUIRE_ORACLE").map(|v| v == "1").unwrap_or(false)
}

fn ghidra_paths() -> Option<(String, String)> {
    let install = std::env::var("TRACEWISE_GHIDRA_INSTALL_DIR").unwrap_or_else(|_| "/workspace/tools/ghidra-12.1.4".into());
    let java = std::env::var("TRACEWISE_JAVA_HOME").unwrap_or_else(|_| "/workspace/tools/temurin-21.0.5+11".into());
    if PathBuf::from(&install).join("support/analyzeHeadless").exists() && PathBuf::from(&java).join("bin/java").exists() {
        return Some((install, java));
    }
    if require_oracle() {
        panic!("TRACEWISE_REQUIRE_ORACLE=1 but Ghidra ({install}) or the JDK ({java}) is not installed");
    }
    eprintln!("SKIP: Ghidra ({install}) or JDK ({java}) is not installed");
    None
}

/// Runtime directory names (`rea-ghidra-*`) in the temp directory.
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

/// Runtime directory names mentioned by the command line of any live process.
fn process_runtimes() -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let cmdline = std::fs::read(entry.path().join("cmdline")).unwrap_or_default();
            let text = String::from_utf8_lossy(&cmdline).replace('\0', " ");
            for word in text.split(|c: char| c == '/' || c.is_whitespace()) {
                if word.starts_with("rea-ghidra-") {
                    found.insert(word.to_string());
                }
            }
        }
    }
    found
}

struct Client {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: std::sync::mpsc::Receiver<String>,
    next_id: u64,
}

impl Client {
    fn start(install: &str, java: &str) -> Client {
        let mut child = Command::new(env!("CARGO_BIN_EXE_tracewise"))
            .arg("mcp")
            .env("GHIDRA_INSTALL_DIR", install)
            .env("JAVA_HOME", java)
            .env("GHIDRA_HEADLESS_MAXMEM", "1G")
            .env_remove("REA_ANALYSIS_PROVIDER")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn tracewise mcp");
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (sender, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let mut client = Client { child, stdin, lines, next_id: 0 };
        client.request(
            "initialize",
            json!({ "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "shutdown-test", "version": "1" } }),
        );
        client.notify("notifications/initialized");
        client
    }

    fn send(&mut self, message: Value) {
        let stdin = self.stdin.as_mut().expect("stdin open");
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
    }

    fn notify(&mut self, method: &str) {
        self.send(json!({ "jsonrpc": "2.0", "method": method }));
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = self.lines.recv_timeout(left).expect("response before the deadline");
            let value: Value = serde_json::from_str(&line).unwrap();
            if value.get("id") == Some(&json!(id)) {
                return value;
            }
        }
    }

    fn tool(&mut self, name: &str, arguments: Value) -> Value {
        let response = self.request("tools/call", json!({ "name": name, "arguments": arguments }));
        assert!(response.get("error").is_none(), "{response}");
        response["result"].clone()
    }
}

/// Open the sample, make the engine start, and return the runtime directories it owns.
fn start_with_live_engine(install: &str, java: &str) -> (Client, BTreeSet<String>) {
    let before = runtime_dirs();
    let mut client = Client::start(install, java);
    let target = repo_root().join("fixtures/engines/sample_elf");
    let opened = client.tool("open_binary", json!({ "path": target.to_string_lossy() }));
    assert_ne!(opened["isError"], json!(true), "{opened}");
    let listed = client.tool("list_documents", json!({}));
    assert_ne!(listed["isError"], json!(true), "{listed}");
    let owned: BTreeSet<String> = runtime_dirs().difference(&before).cloned().collect();
    assert!(!owned.is_empty(), "a live Ghidra session must own a runtime directory");
    assert!(
        owned.iter().all(|dir| process_runtimes().contains(dir)),
        "the owned runtime must be in use by a live process: {owned:?}"
    );
    (client, owned)
}

fn assert_clean_after(mut client: Client, owned: &BTreeSet<String>, expected_exit: Option<i32>) {
    let deadline = Instant::now() + Duration::from_secs(40);
    let status = loop {
        if let Some(status) = client.child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "tracewise mcp did not exit");
        std::thread::sleep(Duration::from_millis(50));
    };
    if let Some(code) = expected_exit {
        assert_eq!(status.code(), Some(code), "exit status {status:?}");
    }
    // Everything the server owned is gone the moment it exits: nothing is left to a background
    // task or to the OS to clean up later.
    let dirs = runtime_dirs();
    let leftover_dirs: Vec<&String> = owned.iter().filter(|dir| dirs.contains(*dir)).collect();
    assert!(leftover_dirs.is_empty(), "runtime directories left behind: {leftover_dirs:?}");
    let runtimes = process_runtimes();
    let leftover_processes: Vec<&String> = owned.iter().filter(|dir| runtimes.contains(*dir)).collect();
    assert!(leftover_processes.is_empty(), "engine processes left behind: {leftover_processes:?}");
}

#[test]
fn closing_stdin_without_close_binary_releases_the_engine() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some((install, java)) = ghidra_paths() else { return };
    let (mut client, owned) = start_with_live_engine(&install, &java);
    drop(client.stdin.take());
    assert_clean_after(client, &owned, Some(0));
}

fn terminate_with(signal: &str, expected_exit: i32) {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some((install, java)) = ghidra_paths() else { return };
    let (client, owned) = start_with_live_engine(&install, &java);
    let status = Command::new("kill").arg(format!("-{signal}")).arg(client.child.id().to_string()).status().unwrap();
    assert!(status.success());
    assert_clean_after(client, &owned, Some(expected_exit));
}

#[test]
fn sigterm_releases_the_engine() {
    terminate_with("TERM", 143);
}

#[test]
fn sigint_releases_the_engine() {
    terminate_with("INT", 130);
}

/// The IDA proxy is a child MCP server: it must die with the session even when the client never
/// closes the binary (it used to depend on `KillOnDrop` alone, which a process exit never runs).
fn ida_proxy_is_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
        && std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map(|stat| !stat.contains(") Z "))
            .unwrap_or(false)
}

fn ida_shutdown(how: &str) {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    if Command::new("node").arg("--version").stdout(Stdio::null()).status().map(|s| !s.success()).unwrap_or(true) {
        if require_oracle() {
            panic!("TRACEWISE_REQUIRE_ORACLE=1 but `node` is not on PATH; it runs the fake IDA MCP server");
        }
        eprintln!("SKIP: `node` is not on PATH");
        return;
    }
    let work = std::env::temp_dir().join(format!("tracewise-ida-shutdown-{}-{how}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    let fixtures = repo_root().join("fixtures/engines");
    let script = work.join("fake_ida_mcp.mjs");
    std::fs::copy(fixtures.join("ida/fake_ida_mcp.mjs"), &script).unwrap();
    let target = work.join("sample_elf");
    std::fs::copy(fixtures.join("sample_elf"), &target).unwrap();
    let registration = work.join("legacy.json");
    std::fs::write(
        &registration,
        format!("{{\"command\":\"node\",\"args\":[\"{}\",\"--profile\",\"legacy\"],\"mode\":\"attached\"}}\n", script.display()),
    )
    .unwrap();
    let pid_file = work.join("proxy.pid");

    let mut child = Command::new(env!("CARGO_BIN_EXE_tracewise"))
        .arg("mcp")
        .env_remove("GHIDRA_INSTALL_DIR")
        .env_remove("JAVA_HOME")
        .env_remove("REA_ANALYSIS_PROVIDER")
        .env("REA_IDA_MCP_CONFIG", &registration)
        .env("FAKE_IDA_PID_FILE", &pid_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn tracewise mcp");
    let stdin = child.stdin.take();
    let stdout = child.stdout.take().unwrap();
    let (sender, lines) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let mut client = Client { child, stdin, lines, next_id: 0 };
    client.request(
        "initialize",
        json!({ "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "shutdown-test", "version": "1" } }),
    );
    client.notify("notifications/initialized");
    let opened = client.tool("open_binary", json!({ "path": target.to_string_lossy() }));
    assert_ne!(opened["isError"], json!(true), "{opened}");
    let listed = client.tool("list_procedures", json!({}));
    assert_ne!(listed["isError"], json!(true), "{listed}");
    let pid: u32 = std::fs::read_to_string(&pid_file).expect("the proxy recorded its pid").trim().parse().unwrap();
    assert!(ida_proxy_is_alive(pid), "the proxy must be running while the session is live");

    match how {
        "stdin" => drop(client.stdin.take()),
        signal => {
            let status = Command::new("kill").arg(format!("-{signal}")).arg(client.child.id().to_string()).status().unwrap();
            assert!(status.success());
        }
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while client.child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "tracewise mcp did not exit");
        std::thread::sleep(Duration::from_millis(50));
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while ida_proxy_is_alive(pid) {
        assert!(Instant::now() < deadline, "the IDA proxy {pid} outlived the server");
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn closing_stdin_stops_the_ida_proxy() {
    ida_shutdown("stdin");
}

#[test]
fn sigterm_stops_the_ida_proxy() {
    ida_shutdown("TERM");
}
