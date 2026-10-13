//! The IDA provider over the real stdio transport, against the fake upstream server in
//! `fixtures/engines/ida` (needs `node` on PATH; with `TRACEWISE_REQUIRE_ORACLE=1` a missing
//! `node` fails instead of skipping). These tests prove what the in-process fake cannot:
//! the selected environment reaches the proxy and nothing ambient does, requests time out,
//! and no proxy or grandchild survives a close, a failure or a dropped client.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::error::AnalysisError;
use crate::provider::{AnalysisClient, ExecContext};
use crate::target::BinaryTarget;

use super::config::{parse_registration, IdaRegistration};
use super::connection::{IdaConnection, IdaFault, McpConnection};
use super::IdaSessionClient;

const SAMPLE_SHA256: &str = "61ec630145d9a6b8ddb77a33a5d31b3a75589df9e02eb68c749044e1c4a5a83e";

fn node() -> Option<PathBuf> {
    let found = std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join("node"))
            .find(|candidate| candidate.is_file())
    });
    if found.is_none() {
        if std::env::var("TRACEWISE_REQUIRE_ORACLE")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            panic!("TRACEWISE_REQUIRE_ORACLE=1 but `node` is not on PATH; it runs the fake IDA MCP server");
        }
        eprintln!("SKIP: `node` is not on PATH; it runs the fake IDA MCP server");
    }
    found
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/engines")
}

fn fake_script() -> PathBuf {
    fixtures()
        .join("ida/fake_ida_mcp.mjs")
        .canonicalize()
        .expect("fake IDA server")
}

fn alive(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        // The state follows the parenthesized command name; a zombie is already dead.
        Ok(stat) => stat
            .rsplit(')')
            .next()
            .map(|rest| !rest.trim_start().starts_with('Z'))
            .unwrap_or(false),
        Err(_) => false,
    }
}

async fn wait_gone(pid: u32, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while alive(pid) {
        assert!(
            Instant::now() < deadline,
            "{what} (pid {pid}) is still running"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn read_pid(path: &Path) -> u32 {
    std::fs::read_to_string(path)
        .expect("pid file")
        .trim()
        .parse()
        .expect("pid")
}

struct Rig {
    dir: tempfile::TempDir,
    node: PathBuf,
    environment: BTreeMap<String, String>,
}

impl Rig {
    fn new() -> Option<Self> {
        let node = node()?;
        let dir = tempfile::tempdir().unwrap();
        let mut environment: BTreeMap<String, String> = BTreeMap::new();
        if let Ok(path) = std::env::var("PATH") {
            environment.insert("PATH".into(), path);
        }
        Some(Self {
            dir,
            node,
            environment,
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn registration(&self, profile: &str, mode: &str, extra: Value) -> IdaRegistration {
        let mut value = json!({
            "command": self.node,
            "args": [fake_script(), "--profile", profile],
            "mode": mode,
            "timeoutMs": 20000,
        });
        for (key, v) in extra.as_object().cloned().unwrap_or_default() {
            value[key] = v;
        }
        parse_registration(&value).expect("valid registration")
    }

    fn target(&self) -> BinaryTarget {
        let path = self.path("sample_elf");
        std::fs::copy(fixtures().join("sample_elf"), &path).unwrap();
        BinaryTarget {
            path: path.to_string_lossy().to_string(),
            kind: "executable".to_string(),
            format: "elf".to_string(),
            architecture: Some("x86_64".to_string()),
            available_architectures: vec!["x86_64".to_string()],
            sha256: SAMPLE_SHA256.to_string(),
            executable_role: None,
            managed: None,
            mips_elf: None,
        }
    }

    fn log_calls(&self) -> Vec<Value> {
        std::fs::read_to_string(self.path("calls.log"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn observe(&mut self) {
        self.environment.insert(
            "FAKE_IDA_LOG".into(),
            self.path("calls.log").to_string_lossy().to_string(),
        );
        self.environment.insert(
            "FAKE_IDA_PID_FILE".into(),
            self.path("proxy.pid").to_string_lossy().to_string(),
        );
    }
}

async fn run(
    client: &dyn AnalysisClient,
    operation: &str,
    parameters: Value,
) -> Result<crate::provider::AnalysisExecution, AnalysisError> {
    client
        .execute(operation, &parameters, &ExecContext::default())
        .await
}

#[tokio::test(flavor = "multi_thread")]
async fn attached_session_reads_through_the_stdio_transport_and_leaves_no_process() {
    let Some(mut rig) = Rig::new() else { return };
    rig.observe();
    let target = rig.target();
    let registration = rig.registration("legacy", "attached", json!({}));
    let connection = Arc::new(McpConnection::new(
        registration.clone(),
        rig.environment.clone(),
    ));
    let client = IdaSessionClient::new(registration, target, connection, None);
    let listed = run(&client, "list_procedures", json!({})).await.unwrap();
    assert_eq!(listed.result.as_array().unwrap().len(), 14);
    let dossier = run(
        &client,
        "analyze_function",
        json!({ "procedure": "engine_branch" }),
    )
    .await
    .unwrap();
    assert_eq!(dossier.result["callees"].as_array().unwrap().len(), 1);
    assert_eq!(
        dossier.raw_result.as_ref().unwrap()["upstream"],
        json!({ "name": "ida-pro-mcp-fixture", "version": "1.0.0-fixture" })
    );
    let proxy = read_pid(&rig.path("proxy.pid"));
    assert!(alive(proxy));
    assert!(client.close(false).await.is_ok());
    wait_gone(proxy, "the IDA proxy").await;
    let tools: Vec<String> = rig
        .log_calls()
        .iter()
        .map(|c| c["tool"].as_str().unwrap().to_string())
        .collect();
    assert!(!tools.is_empty());
    assert!(
        tools.iter().all(|t| !t.starts_with("idb_")
            && !matches!(
                t.as_str(),
                "rename_function" | "set_comment" | "declare_c_type"
            )),
        "attached mode must only read: {tools:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn headless_session_opens_one_private_worker_and_releases_it_without_saving() {
    let Some(mut rig) = Rig::new() else { return };
    rig.observe();
    let workspace_root = rig.path("workspaces");
    std::fs::create_dir(&workspace_root).unwrap();
    let target = rig.target();
    let registration = rig.registration(
        "modern",
        "headless",
        json!({ "workspaceRoot": workspace_root }),
    );
    let connection = Arc::new(McpConnection::new(
        registration.clone(),
        rig.environment.clone(),
    ));
    let client = IdaSessionClient::new(registration, target.clone(), connection, None);
    let result = run(
        &client,
        "procedure_pseudo_code",
        json!({ "procedure": "engine_branch" }),
    )
    .await
    .unwrap();
    assert!(result
        .result
        .as_str()
        .unwrap()
        .starts_with("int __fastcall engine_branch(int a1)"));
    assert_eq!(
        std::fs::read_dir(&workspace_root).unwrap().count(),
        1,
        "one private workspace while the worker is open"
    );
    let proxy = read_pid(&rig.path("proxy.pid"));
    assert!(client.close(false).await.is_ok());
    wait_gone(proxy, "the IDA proxy").await;
    assert_eq!(
        std::fs::read_dir(&workspace_root).unwrap().count(),
        0,
        "the private workspace is removed"
    );
    let calls = rig.log_calls();
    let tools: Vec<&str> = calls.iter().map(|c| c["tool"].as_str().unwrap()).collect();
    assert_eq!(tools.iter().filter(|t| **t == "idb_open").count(), 1);
    let close = calls
        .iter()
        .find(|c| c["tool"] == "idb_close")
        .expect("the worker is closed");
    assert_eq!(close["arguments"]["save"], json!(false));
    assert_ne!(
        calls[0]["arguments"]["input_path"],
        json!(target.path),
        "the user's file is never opened"
    );
    assert!(!tools.contains(&"idb_save"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_timeout_is_reported_and_close_still_reaps_the_proxy() {
    let Some(mut rig) = Rig::new() else { return };
    rig.observe();
    rig.environment
        .insert("FAKE_IDA_STALL_TOOL".into(), "get_metadata".into());
    let target = rig.target();
    let registration = rig.registration("legacy", "attached", json!({ "timeoutMs": 400 }));
    let connection = Arc::new(McpConnection::new(
        registration.clone(),
        rig.environment.clone(),
    ));
    let client = IdaSessionClient::new(registration, target, connection, None);
    let started = Instant::now();
    let error = run(&client, "list_procedures", json!({}))
        .await
        .unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(10));
    match error {
        AnalysisError::ProviderAdapter {
            provider_id,
            diagnostics,
            ..
        } => {
            assert_eq!(provider_id, "ida");
            assert_eq!(diagnostics.unwrap()["reason"], "Request timed out");
        }
        other => panic!("unexpected {other:?}"),
    }
    let proxy = read_pid(&rig.path("proxy.pid"));
    assert!(client.close(false).await.is_ok());
    wait_gone(proxy, "the stalled IDA proxy").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn dropping_a_connection_kills_the_proxy_and_its_descendants() {
    let Some(mut rig) = Rig::new() else { return };
    // A proxy that leaves a grandchild behind, as a real supervisor would with its workers.
    let script = rig.path("proxy.mjs");
    std::fs::write(
        &script,
        r#"
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
const child = spawn('sleep', ['300'], { stdio: 'ignore' });
writeFileSync(process.env.PROXY_PIDS, JSON.stringify({ proxy: process.pid, child: child.pid }));
createInterface({ input: process.stdin }).on('line', (line) => {
  const request = JSON.parse(line);
  if (request.id === undefined) return;
  const result = request.method === 'initialize'
    ? { protocolVersion: request.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: 'leaky', version: '1' } }
    : { tools: [{ name: 'get_metadata', inputSchema: { type: 'object' } }] };
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, result }) + '\n');
});
"#,
    )
    .unwrap();
    rig.environment.insert(
        "PROXY_PIDS".into(),
        rig.path("pids.json").to_string_lossy().to_string(),
    );
    let registration =
        parse_registration(&json!({ "command": rig.node, "args": [script], "timeoutMs": 20000 }))
            .unwrap();
    let connection = McpConnection::new(registration, rig.environment.clone());
    let tools = connection.connect().await.unwrap();
    assert_eq!(tools, vec!["get_metadata".to_string()]);
    let pids: Value =
        serde_json::from_str(&std::fs::read_to_string(rig.path("pids.json")).unwrap()).unwrap();
    let (proxy, child) = (
        pids["proxy"].as_u64().unwrap() as u32,
        pids["child"].as_u64().unwrap() as u32,
    );
    assert!(alive(proxy) && alive(child));
    drop(connection);
    wait_gone(proxy, "the proxy").await;
    wait_gone(child, "the proxy's grandchild").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn dropping_a_headless_client_releases_the_worker_and_the_workspace() {
    let Some(mut rig) = Rig::new() else { return };
    rig.observe();
    let workspace_root = rig.path("workspaces");
    std::fs::create_dir(&workspace_root).unwrap();
    let target = rig.target();
    let registration = rig.registration(
        "modern",
        "headless",
        json!({ "workspaceRoot": workspace_root }),
    );
    let connection = Arc::new(McpConnection::new(
        registration.clone(),
        rig.environment.clone(),
    ));
    let client = IdaSessionClient::new(registration, target, connection, None);
    assert!(run(&client, "list_procedures", json!({})).await.is_ok());
    let proxy = read_pid(&rig.path("proxy.pid"));
    drop(client);
    wait_gone(proxy, "the IDA proxy").await;
    assert_eq!(std::fs::read_dir(&workspace_root).unwrap().count(), 0);
    let tools: Vec<String> = rig
        .log_calls()
        .iter()
        .map(|c| c["tool"].as_str().unwrap().to_string())
        .collect();
    assert!(
        tools.contains(&"idb_close".to_string()),
        "the worker is released through the upstream lifecycle: {tools:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_proxy_sees_the_selected_environment_and_nothing_ambient() {
    let Some(mut rig) = Rig::new() else { return };
    let script = rig.path("environment.mjs");
    std::fs::write(
        &script,
        r#"
import { createInterface } from 'node:readline';
createInterface({ input: process.stdin }).on('line', (line) => {
  const request = JSON.parse(line);
  if (request.id === undefined) return;
  const result = request.method === 'initialize'
    ? { protocolVersion: request.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: 'environment-producer', version: '1' } }
    : request.method === 'tools/list'
      ? { tools: [{ name: 'environment', inputSchema: { type: 'object' } }] }
      : { content: [], structuredContent: {
          selected: process.env.REA_SELECTED_CONTEXT ?? null,
          registration: process.env.REA_REGISTRATION_CONTEXT ?? null,
          ambient: process.env.REA_AMBIENT_CONTEXT ?? null,
          workers: process.env.IDA_MCP_MAX_WORKERS ?? null,
          home: process.env.HOME ?? null,
        } };
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, result }) + '\n');
});
"#,
    )
    .unwrap();
    std::env::set_var("REA_AMBIENT_CONTEXT", "ambient-only");
    rig.environment
        .insert("REA_SELECTED_CONTEXT".into(), "selected".into());
    rig.environment
        .insert("HOME".into(), "/selected-home".into());
    let registration = parse_registration(&json!({
        "command": rig.node,
        "args": [script],
        "env": { "REA_REGISTRATION_CONTEXT": "registration" },
        "timeoutMs": 20000,
    }))
    .unwrap();
    for (selected, expect_home) in [
        (rig.environment.clone(), json!("/selected-home")),
        (BTreeMap::new(), json!("")),
    ] {
        let connection = McpConnection::new(registration.clone(), selected.clone());
        assert_eq!(
            connection.connect().await.unwrap(),
            vec!["environment".to_string()]
        );
        let observed = connection.call("environment", &json!({})).await.unwrap();
        assert_eq!(observed["registration"], "registration");
        assert_eq!(
            observed["ambient"],
            Value::Null,
            "ambient variables must not reach the proxy"
        );
        assert_eq!(observed["workers"], "1");
        assert_eq!(
            observed["selected"],
            json!(selected.get("REA_SELECTED_CONTEXT"))
        );
        assert_eq!(observed["home"], expect_home);
        connection.close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unlaunchable_proxy_is_a_provider_failure_not_a_hang() {
    let Some(rig) = Rig::new() else { return };
    let registration =
        parse_registration(&json!({ "command": rig.path("does-not-exist"), "timeoutMs": 2000 }))
            .unwrap();
    let connection = McpConnection::new(registration, rig.environment.clone());
    match connection.connect().await {
        Err(IdaFault::Other(message)) => assert!(
            message.contains("Cannot start the IDA MCP proxy"),
            "{message}"
        ),
        other => panic!("unexpected {other:?}"),
    }
    assert!(connection.close().await.is_ok());
}

// ---------------------------------------------------------------- streamable HTTP

/// The fake served over HTTP on an ephemeral port; killed when dropped.
struct HttpFake {
    child: std::process::Child,
    port: u16,
}

impl HttpFake {
    fn start(rig: &Rig, profile: &str, log: &Path) -> Self {
        use std::io::BufRead;
        let mut child = std::process::Command::new(&rig.node)
            .arg(fake_script())
            .args(["--profile", profile, "--http", "0"])
            .env("FAKE_IDA_LOG", log)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("start the fake HTTP server");
        let mut line = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let port = line
            .trim()
            .strip_prefix("listening ")
            .expect("listening line")
            .parse()
            .unwrap();
        Self { child, port }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }
}

impl Drop for HttpFake {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn http_client(
    rig: &Rig,
    fake: &HttpFake,
    path: &str,
    mode: &str,
) -> (IdaSessionClient, BinaryTarget) {
    let registration = parse_registration(&json!({
        "url": fake.url(path),
        "mode": mode,
        "headers": { "X-Fixture-Key": "fixture-key-value" },
        "timeoutMs": 20000,
    }))
    .unwrap();
    let target = rig.target();
    let connection = Arc::new(McpConnection::new(
        registration.clone(),
        rig.environment.clone(),
    ));
    (
        IdaSessionClient::new(registration, target.clone(), connection, None),
        target,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn an_http_registration_reads_through_the_endpoint_and_forwards_its_headers() {
    let Some(rig) = Rig::new() else { return };
    let log = rig.path("http.log");
    let fake = HttpFake::start(&rig, "legacy", &log);
    let (client, _) = http_client(&rig, &fake, "/mcp", "attached");
    let listed = run(&client, "list_procedures", json!({})).await.unwrap();
    assert_eq!(listed.result.as_array().unwrap().len(), 14);
    assert_eq!(
        listed.raw_result.as_ref().unwrap()["upstream"],
        json!({ "name": "ida-pro-mcp-fixture", "version": "1.0.0-fixture" })
    );
    assert!(client.close(false).await.is_ok());
    let calls: Vec<Value> = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(!calls.is_empty());
    assert!(
        calls
            .iter()
            .all(|c| c["fixture_key"] == "fixture-key-value"),
        "every request carries the registration's headers: {calls:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_headless_http_session_releases_its_worker_without_saving() {
    let Some(rig) = Rig::new() else { return };
    let log = rig.path("http.log");
    let fake = HttpFake::start(&rig, "modern", &log);
    let (client, target) = http_client(&rig, &fake, "/mcp", "headless");
    assert!(run(
        &client,
        "procedure_address",
        json!({ "procedure": "engine_leaf" })
    )
    .await
    .is_ok());
    assert!(client.close(false).await.is_ok());
    let calls: Vec<Value> = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(calls.iter().filter(|c| c["tool"] == "idb_open").count(), 1);
    let close = calls
        .iter()
        .find(|c| c["tool"] == "idb_close")
        .expect("the worker is closed");
    assert_eq!(close["arguments"]["save"], json!(false));
    assert_ne!(calls[0]["arguments"]["input_path"], json!(target.path));
}

#[tokio::test(flavor = "multi_thread")]
async fn redirects_are_refused_rather_than_followed() {
    let Some(rig) = Rig::new() else { return };
    let log = rig.path("http.log");
    let fake = HttpFake::start(&rig, "legacy", &log);
    let (client, _) = http_client(&rig, &fake, "/redirect", "attached");
    let error = run(&client, "list_procedures", json!({}))
        .await
        .unwrap_err();
    assert!(
        matches!(error, AnalysisError::ProviderAdapter { .. }),
        "{error:?}"
    );
    assert!(
        std::fs::read_to_string(&log).unwrap_or_default().is_empty(),
        "nothing may reach the redirect target"
    );
    assert!(client.close(false).await.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn https_and_unreachable_http_endpoints_fail_as_provider_errors() {
    let Some(rig) = Rig::new() else { return };
    let https = parse_registration(&json!({ "url": "https://localhost:9/mcp" })).unwrap();
    match McpConnection::new(https, rig.environment.clone())
        .connect()
        .await
    {
        Err(IdaFault::Other(message)) => assert!(message.contains("Only plain http"), "{message}"),
        other => panic!("unexpected {other:?}"),
    }
    let closed_port =
        parse_registration(&json!({ "url": "http://127.0.0.1:9/mcp", "timeoutMs": 5000 })).unwrap();
    let started = Instant::now();
    assert!(matches!(
        McpConnection::new(closed_port, rig.environment.clone())
            .connect()
            .await,
        Err(IdaFault::Other(_))
    ));
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_registration_headers_are_a_provider_error_that_does_not_echo_the_value() {
    let Some(rig) = Rig::new() else { return };
    let registration = parse_registration(&json!({
        "url": "http://127.0.0.1:9/mcp",
        "headers": { "Authorization": "bad\nsecret-value" },
    }))
    .unwrap();
    match McpConnection::new(registration, rig.environment.clone())
        .connect()
        .await
    {
        Err(IdaFault::Other(message)) => {
            assert!(message.contains("not a valid HTTP header"), "{message}");
            assert!(!message.contains("secret-value"));
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn dropping_a_client_outside_a_runtime_still_stops_the_proxy_and_removes_the_workspace() {
    let Some(mut rig) = Rig::new() else { return };
    rig.observe();
    let workspace_root = rig.path("workspaces");
    std::fs::create_dir(&workspace_root).unwrap();
    let target = rig.target();
    let registration = rig.registration(
        "modern",
        "headless",
        json!({ "workspaceRoot": workspace_root }),
    );
    let connection = Arc::new(McpConnection::new(
        registration.clone(),
        rig.environment.clone(),
    ));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let client = IdaSessionClient::new(registration, target, connection, None);
    runtime.block_on(async {
        assert!(run(&client, "list_procedures", json!({})).await.is_ok());
    });
    let proxy = read_pid(&rig.path("proxy.pid"));
    assert!(alive(proxy));
    assert_eq!(std::fs::read_dir(&workspace_root).unwrap().count(), 1);
    // This thread is not inside the runtime, so no graceful release can be scheduled: the
    // synchronous guards must still stop the proxy and delete the private directory.
    drop(client);
    let deadline = Instant::now() + Duration::from_secs(20);
    while alive(proxy) {
        assert!(
            Instant::now() < deadline,
            "the IDA proxy (pid {proxy}) survived the drop"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(std::fs::read_dir(&workspace_root).unwrap().count(), 0);
    drop(runtime);
}
