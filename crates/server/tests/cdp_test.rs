//! Live Chrome CDP coverage for browser observation tools.
//!
//! Skips when `/usr/bin/google-chrome` is absent. The browser is started on a
//! free loopback port and killed with its process group when the test ends.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use proc_supervisor::{ProcessSupervisor, SupervisedChild};
use sha2::{Digest, Sha256};
use rmcp::model::{CallToolRequestParam, CallToolResult, RawContent};
use serde_json::{json, Value};
use tracewise_server::handlers::call_tool_local;
use tracewise_server::session::BinarySession;

const CHROME: &str = "/usr/bin/google-chrome";

#[tokio::test]
async fn live_cdp_lists_targets_and_captures_screenshot() {
    if !std::path::Path::new(CHROME).is_file() {
        eprintln!("skipping live CDP test: {CHROME} is missing");
        return;
    }

    let page = HtmlServer::start();
    let origin = format!("http://127.0.0.1:{}", page.port);
    let page_url = format!("{origin}/");
    let chrome = ChromeDebug::launch();

    navigate_page(&chrome.endpoint, &page_url).await;

    let session = BinarySession::new();
    let listed = call_ok(
        &session,
        "list_browser_targets",
        json!({
            "cdp_endpoint": chrome.endpoint,
            "allowed_origins": [origin],
        }),
    )
    .await;
    let listed_body = structured_of("list_browser_targets", &listed);
    assert_output_schema("list_browser_targets", listed_body);
    let targets = listed_body["normalized_result"]["targets"]
        .as_array()
        .expect("targets array");
    let matched: Vec<&Value> = targets
        .iter()
        .filter(|target| target["origin"] == origin)
        .collect();
    assert_eq!(
        matched.len(),
        1,
        "expected the local page inside allowed_origins, got {targets:?}"
    );
    let target_url = matched[0]["url"].as_str().unwrap_or_default();
    assert!(
        target_url.starts_with(&origin),
        "listed url {target_url} should stay on {origin}"
    );
    assert_eq!(matched[0]["type"], "page");
    let target_id = matched[0]["target_id"]
        .as_str()
        .expect("target_id")
        .to_string();

    let blocked = call_ok(
        &session,
        "list_browser_targets",
        json!({
            "cdp_endpoint": chrome.endpoint,
            "allowed_origins": ["https://blocked.example"],
        }),
    )
    .await;
    let blocked_body = structured_of("list_browser_targets", &blocked);
    assert_output_schema("list_browser_targets", blocked_body);
    let blocked_targets = blocked_body["normalized_result"]["targets"]
        .as_array()
        .expect("blocked targets");
    assert!(
        blocked_targets.iter().all(|target| target["origin"] != origin),
        "allowed_origins must exclude {origin}: {blocked_targets:?}"
    );
    let disallowed = blocked_body["normalized_result"]["excluded"]["disallowed_origin"]
        .as_u64()
        .expect("disallowed_origin count");
    assert!(
        disallowed >= 1,
        "the local page should count as disallowed_origin, got {disallowed}"
    );

    let shot = call_ok(
        &session,
        "capture_web_screenshot",
        json!({
            "cdp_endpoint": chrome.endpoint,
            "allowed_origins": [origin],
            "target_id": target_id,
        }),
    )
    .await;
    let shot_body = structured_of("capture_web_screenshot", &shot);
    assert_output_schema("capture_web_screenshot", shot_body);
    let normalized = &shot_body["normalized_result"];
    assert_eq!(normalized["target"]["origin"], origin);
    assert_eq!(normalized["target"]["target_id"], target_id);
    assert_eq!(normalized["artifact"]["media_type"], "image/png");
    assert!(png_artifact(&normalized["artifact"]), "artifact must be a PNG");
    assert!(normalized["viewport"]["width"].as_u64().unwrap_or(0) >= 1);
    assert!(normalized["viewport"]["height"].as_u64().unwrap_or(0) >= 1);

    let denied = call_ok(
        &session,
        "capture_web_screenshot",
        json!({
            "cdp_endpoint": chrome.endpoint,
            "allowed_origins": ["https://blocked.example"],
            "target_id": target_id,
        }),
    )
    .await;
    assert_eq!(denied.is_error, Some(true), "{}", content_text(&denied));
    let denied_text = content_text(&denied);
    assert!(
        denied_text.contains("target_not_allowed"),
        "disallowed origin must be rejected, got {denied_text}"
    );
}

const SCENARIO_SECRET: &str = "tracewise-scenario-secret-value";

#[tokio::test]
async fn live_cdp_discovers_webmcp_and_captures_scenario() {
    if !std::path::Path::new(CHROME).is_file() {
        eprintln!("skipping live CDP test: {CHROME} is missing");
        return;
    }
    std::env::set_var("TRACEWISE_SCENARIO_SECRET", SCENARIO_SECRET);

    let page = HtmlServer::start_webmcp();
    let origin = format!("http://127.0.0.1:{}", page.port);
    let page_url = format!("{origin}/");
    let chrome = ChromeDebug::launch();
    navigate_page(&chrome.endpoint, &page_url).await;

    let session = BinarySession::new();
    let target_id = page_target_id(&session, &chrome.endpoint, &origin).await;
    let discovered = call_ok(
        &session,
        "discover_webmcp_tools",
        json!({
            "cdp_endpoint": chrome.endpoint,
            "allowed_origins": [origin],
            "target_id": target_id,
            "observation_ms": 500,
        }),
    )
    .await;
    let discovered_body = structured_of("discover_webmcp_tools", &discovered);
    assert_output_schema("discover_webmcp_tools", discovered_body);
    let webmcp = &discovered_body["normalized_result"];
    assert_eq!(webmcp["target"]["origin"], origin);
    assert_eq!(webmcp["target"]["target_id"], target_id);
    let limitations = webmcp["limitations"].as_array().expect("webmcp limitations");
    assert!(limitations.iter().any(|item| {
        item.as_str()
            .unwrap_or("")
            .contains("WebMCP.invokeTool is never called")
    }));
    if webmcp["status"] == "available" {
        let names: Vec<&str> = webmcp["tools"]["items"]
            .as_array()
            .expect("tools")
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        assert!(
            names.iter().any(|name| *name == "tracewise_echo"),
            "expected navigator.modelContext tool, got {names:?}\n{webmcp}"
        );
    }

    let captured = call_ok(
        &session,
        "capture_browser_scenario",
        json!({
            "browser": {
                "mode": "launch",
                "executable_path": CHROME,
                "headless": true
            },
            "start_url": { "url": page_url },
            "actions": [
                {
                    "step_id": "type_token",
                    "action": "fill",
                    "locator": { "kind": "test_id", "value": "secret" },
                    "value": { "source": "secret", "secret_id": "token" }
                },
                {
                    "step_id": "press_go",
                    "action": "click",
                    "locator": { "kind": "test_id", "value": "go" }
                }
            ],
            "secrets": [
                { "secret_id": "token", "environment_variable": "TRACEWISE_SCENARIO_SECRET" }
            ],
            "capture": { "at_end": ["url", "dom"] }
        }),
    )
    .await;
    let captured_body = structured_of("capture_browser_scenario", &captured);
    assert_output_schema("capture_browser_scenario", captured_body);
    let scenario = &captured_body["normalized_result"];
    assert_eq!(scenario["browser"]["mode"], "launch");
    assert_eq!(scenario["browser"]["process_ownership"], "provider-owned");
    assert_eq!(scenario["browser"]["cleanup"], "terminated-owned-process");
    assert_eq!(scenario["scenario"]["start_origin"], origin);
    assert_eq!(scenario["scenario"]["action_count"], 2);
    assert_eq!(scenario["steps"].as_array().expect("steps").len(), 3);
    for step in scenario["steps"].as_array().expect("steps") {
        assert_eq!(step["status"], "completed", "step failed: {step}");
    }
    let encoded = captured_body.to_string();
    assert!(
        !encoded.contains(SCENARIO_SECRET),
        "scenario secret was persisted in the tool result"
    );
    assert!(encoded.contains("[REDACTED:token]"), "filled secret should be redacted in the DOM snapshot");
}

const SECRET_TOKEN: &str = "tracewise-secret-token";
const SECRET_COOKIE: &str = "tracewise-secret-cookie";

#[tokio::test]
async fn live_cdp_inspects_page_and_observes_session() {
    if !std::path::Path::new(CHROME).is_file() {
        eprintln!("skipping live CDP test: {CHROME} is missing");
        return;
    }

    let page = HtmlServer::start_scripted();
    let origin = format!("http://127.0.0.1:{}", page.port);
    let page_url = format!("{origin}/");
    let chrome = ChromeDebug::launch();
    navigate_page(&chrome.endpoint, &page_url).await;

    let session = BinarySession::new();
    let inspected = call_ok(
        &session,
        "inspect_web_page",
        json!({
            "cdp_endpoint": chrome.endpoint,
            "allowed_origins": [origin],
            "target_id": page_target_id(&session, &chrome.endpoint, &origin).await,
            "observation_ms": 1500,
        }),
    )
    .await;
    let inspected_body = structured_of("inspect_web_page", &inspected);
    assert_output_schema("inspect_web_page", inspected_body);
    let normalized = &inspected_body["normalized_result"];
    let script_urls: Vec<&str> = normalized["scripts"]["items"]
        .as_array()
        .expect("scripts")
        .iter()
        .filter_map(|script| script["url"].as_str())
        .collect();
    assert!(
        script_urls.iter().any(|url| url.ends_with("/app.js")),
        "expected /app.js in scripts, got {script_urls:?}"
    );
    let request_urls: Vec<&str> = normalized["network"]["requests"]
        .as_array()
        .expect("requests")
        .iter()
        .filter_map(|request| request["url"].as_str())
        .collect();
    assert!(
        request_urls.iter().any(|url| url.contains("/api")),
        "expected fetch /api in network, got {request_urls:?}\n{normalized}"
    );
    let encoded = normalized.to_string();
    assert!(
        !encoded.contains(SECRET_TOKEN),
        "Authorization value leaked into inspect_web_page output"
    );
    assert!(
        !encoded.contains(SECRET_COOKIE),
        "cookie value leaked into inspect_web_page output"
    );
    assert_eq!(normalized["network"]["prior_activity_available"], false);
    assert_eq!(normalized["metadata"]["headers_allowlisted"], true);
    assert_eq!(normalized["storage"]["values_redacted"], true);

    let observed = call_ok(
        &session,
        "observe_web_session",
        json!({
            "cdp_endpoint": chrome.endpoint,
            "allowed_origins": [origin],
            "target_id": page_target_id(&session, &chrome.endpoint, &origin).await,
            "observation_ms": 400,
        }),
    )
    .await;
    let observed_body = structured_of("observe_web_session", &observed);
    assert_output_schema("observe_web_session", observed_body);
    let session_result = &observed_body["normalized_result"];
    assert_eq!(session_result["window"]["end_reason"], "window_elapsed");
    assert_eq!(session_result["window"]["requested_ms"], 400);
    let initial_url = session_result["target"]["initial_url"].as_str().unwrap_or("");
    assert!(
        initial_url.starts_with(&origin),
        "initial_url {initial_url} should stay on {origin}"
    );
    assert!(
        !session_result.to_string().contains(SECRET_TOKEN),
        "session timeline retained the Authorization secret"
    );
    assert!(
        !session_result.to_string().contains(SECRET_COOKIE),
        "session timeline retained the cookie secret"
    );
}

#[tokio::test]
async fn live_cdp_analyzes_bundle_observes_execution_and_inspects_listeners() {
    if !std::path::Path::new(CHROME).is_file() {
        eprintln!("skipping live CDP test: {CHROME} is missing");
        return;
    }

    let page = HtmlServer::start_listeners();
    let origin = format!("http://127.0.0.1:{}", page.port);
    let page_url = format!("{origin}/");
    let chrome = ChromeDebug::launch();
    navigate_page(&chrome.endpoint, &page_url).await;

    let session = BinarySession::new();
    let target_id = page_target_id(&session, &chrome.endpoint, &origin).await;
    let listeners = call_ok(
        &session,
        "inspect_web_event_listeners",
        json!({
            "cdp_endpoint": chrome.endpoint,
            "allowed_origins": [origin],
            "target_id": target_id,
            "selector": "#go",
        }),
    )
    .await;
    let listeners_body = structured_of("inspect_web_event_listeners", &listeners);
    assert_output_schema("inspect_web_event_listeners", listeners_body);
    let listener_result = &listeners_body["normalized_result"];
    assert_eq!(listener_result["selected_node"]["match"], "found");
    assert_eq!(listener_result["selected_node"]["selector"], "#go");
    assert_eq!(listener_result["cleanup"], "confirmed");
    let click_listeners: Vec<&Value> = listener_result["listeners"]
        .as_array()
        .expect("listeners")
        .iter()
        .filter(|listener| listener["type"] == "click")
        .collect();
    assert!(
        !click_listeners.is_empty(),
        "expected a click listener on #go, got {}",
        listener_result["listeners"]
    );
    assert_eq!(click_listeners[0]["execution"], "unknown");
    assert!(listener_result["sources"].as_array().is_some_and(|items| !items.is_empty()));

    let execution = call_ok(
        &session,
        "observe_web_execution",
        json!({
            "cdp_endpoint": chrome.endpoint,
            "allowed_origins": [origin],
            "target_id": target_id,
            "observation_ms": 500,
        }),
    )
    .await;
    let execution_body = structured_of("observe_web_execution", &execution);
    assert_output_schema("observe_web_execution", execution_body);
    let execution_result = &execution_body["normalized_result"];
    assert_eq!(execution_result["window"]["end_reason"], "window_elapsed");
    assert_eq!(execution_result["window"]["requested_ms"], 500);
    assert_eq!(execution_result["instrumentation"]["executes_selected_code"], false);
    assert_eq!(execution_result["instrumentation"]["cleanup"], "confirmed");
    assert_eq!(execution_result["coverage"]["offset_units"], "utf16-code-units");
    let request_urls: Vec<&str> = execution_result["requests"]
        .as_array()
        .expect("requests")
        .iter()
        .filter_map(|request| request["url"].as_str())
        .collect();
    assert!(
        request_urls.iter().any(|url| url.contains("/api")),
        "expected an armed-window fetch /api, got {request_urls:?}"
    );

    let analyzed = call_ok(
        &session,
        "analyze_web_bundle",
        json!({
            "cdp_endpoint": chrome.endpoint,
            "allowed_origins": [origin],
            "target_id": target_id,
            "observation_ms": 200,
            "include_script_sources": true,
            "fetch_source_maps": false,
        }),
    )
    .await;
    let analyzed_body = structured_of("analyze_web_bundle", &analyzed);
    assert_output_schema("analyze_web_bundle", analyzed_body);
    let bundle = &analyzed_body["normalized_result"];
    assert!(bundle["capture"]["scripts_analyzed"].as_i64().unwrap_or(0) >= 1);
    assert_eq!(bundle["observations"]["source_maps"]["status"], "not_requested");
    let endpoints = bundle["observations"]["endpoints"].as_array().expect("endpoints");
    assert!(
        endpoints.iter().any(|item| item["value"].as_str().unwrap_or("").contains("/api")),
        "expected fetch('/api') in bundle endpoints, got {endpoints:?}"
    );
}

async fn page_target_id(session: &BinarySession, endpoint: &str, origin: &str) -> String {
    let listed = call_ok(
        session,
        "list_browser_targets",
        json!({
            "cdp_endpoint": endpoint,
            "allowed_origins": [origin],
        }),
    )
    .await;
    let body = structured_of("list_browser_targets", &listed);
    body["normalized_result"]["targets"]
        .as_array()
        .expect("targets")
        .iter()
        .find(|target| target["origin"] == origin)
        .and_then(|target| target["target_id"].as_str())
        .expect("scripted page target")
        .to_string()
}

fn structured_of<'a>(tool: &str, result: &'a CallToolResult) -> &'a Value {
    assert_ne!(
        result.is_error,
        Some(true),
        "{tool} failed: {}",
        content_text(result)
    );
    result
        .structured_content
        .as_ref()
        .unwrap_or_else(|| panic!("{tool} returned no structuredContent"))
}

fn assert_output_schema(tool_name: &str, structured: &Value) {
    let tools_val = tracewise_contracts::phase1_tools_value();
    let tools_arr = tools_val["tools"].as_array().expect("tools array");
    let tool_def = tools_arr
        .iter()
        .find(|tool| tool["name"] == tool_name)
        .unwrap_or_else(|| panic!("{tool_name} tool definition"));
    let schema = &tool_def["outputSchema"];
    let validator = jsonschema::validator_for(schema)
        .unwrap_or_else(|err| panic!("Failed to compile {tool_name} outputSchema: {err}"));
    if let Err(first_err) = validator.validate(structured) {
        let all_errors: Vec<String> = validator
            .iter_errors(structured)
            .map(|err| format!("path: {}, error: {}", err.instance_path(), err))
            .collect();
        panic!(
            "{tool_name} structuredContent failed schema validation:\nFirst error: {first_err}\nAll errors:\n{}\nBody: {structured}",
            all_errors.join("\n")
        );
    }
}

fn png_artifact(artifact: &Value) -> bool {
    let Some(encoded) = artifact["data_base64"].as_str() else {
        return false;
    };
    let Ok(bytes) = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        encoded,
    ) else {
        return false;
    };
    let sha = artifact["sha256"].as_str().unwrap_or_default();
    let digest = hex::encode(Sha256::digest(&bytes));
    bytes.len() >= 24
        && bytes.len() == artifact["bytes"].as_u64().unwrap_or(0) as usize
        && sha == digest
        && bytes[..8] == [137, 80, 78, 71, 13, 10, 26, 10]
}

fn content_text(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .map(|item| match &item.raw {
            RawContent::Text(text) => text.text.clone(),
            other => format!("{other:?}"),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

async fn call_ok(session: &BinarySession, name: &str, args: Value) -> CallToolResult {
    call_tool_local(
        session,
        CallToolRequestParam {
            name: name.to_owned().into(),
            arguments: Some(
                args.as_object()
                    .unwrap_or_else(|| panic!("{name} arguments must be an object"))
                    .clone(),
            ),
        },
    )
    .await
    .unwrap_or_else(|err| panic!("{name} returned a protocol error: {err}"))
}

async fn navigate_page(endpoint: &str, page_url: &str) {
    let discovery = wait_for_discovery(endpoint).await;
    let target = discovery
        .targets
        .iter()
        .find(|target| target.target_type == "page")
        .unwrap_or_else(|| panic!("chrome exposed no page target at {endpoint}"));
    let mut session = tracewise_web::cdp_connection::open_cdp_target_session(
        &discovery,
        target,
        "capture_web_screenshot",
    )
    .await
    .unwrap_or_else(|err| panic!("attach to {} failed: {err}", target.id));
    let session_id = session.session_id.clone();
    let sid = session_id.as_deref();
    session
        .connection
        .send("Page.enable", json!({}), sid)
        .await
        .unwrap_or_else(|err| panic!("Page.enable failed: {err}"));
    let navigated = session
        .connection
        .send("Page.navigate", json!({ "url": page_url }), sid)
        .await
        .unwrap_or_else(|err| panic!("Page.navigate failed: {err}"));
    if let Some(error_text) = navigated.get("errorText").and_then(Value::as_str) {
        panic!("Page.navigate reported {error_text}");
    }

    let mut last_url = target.url.clone();
    for _ in 0..40 {
        let tree = session
            .connection
            .send("Page.getFrameTree", json!({}), sid)
            .await
            .unwrap_or_else(|err| panic!("Page.getFrameTree failed: {err}"));
        last_url = tree
            .get("frameTree")
            .and_then(|node| node.get("frame"))
            .and_then(|frame| frame.get("url"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let committed = last_url.starts_with(page_url)
            || last_url.trim_end_matches('/') == page_url.trim_end_matches('/');
        if committed {
            tracewise_web::cdp_connection::close_cdp_target_session(session, &["Page"]).await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tracewise_web::cdp_connection::close_cdp_target_session(session, &["Page"]).await;
    panic!("navigation to {page_url} did not commit; last url was {last_url}");
}

async fn wait_for_discovery(endpoint: &str) -> tracewise_web::cdp_endpoint::CdpEndpointDiscovery {
    let mut last_error = String::from("not attempted");
    for _ in 0..50 {
        match tracewise_web::cdp_endpoint::discover_cdp_endpoint(endpoint, "list_browser_targets")
            .await
        {
            Ok(discovery) => return discovery,
            Err(err) => {
                last_error = err.to_string();
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
    panic!("CDP endpoint {endpoint} was not ready: {last_error}");
}

#[derive(Clone, Copy)]
enum PageMode {
    Plain,
    Scripted,
    Listeners,
    WebMcp,
}

struct HtmlServer {
    port: u16,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl HtmlServer {
    fn start() -> Self {
        Self::start_mode(PageMode::Plain)
    }

    fn start_scripted() -> Self {
        Self::start_mode(PageMode::Scripted)
    }

    fn start_listeners() -> Self {
        Self::start_mode(PageMode::Listeners)
    }

    fn start_webmcp() -> Self {
        Self::start_mode(PageMode::WebMcp)
    }

    fn start_mode(mode: PageMode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local html server");
        let port = listener.local_addr().expect("html port").port();
        listener
            .set_nonblocking(true)
            .expect("html listener nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => write_html(stream, mode),
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            port,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for HtmlServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn write_html(mut stream: TcpStream, mode: PageMode) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
    let mut buf = [0_u8; 2048];
    let n = stream.read(&mut buf).unwrap_or(0);
    let request = String::from_utf8_lossy(&buf[..n]);
    let path = request.split_whitespace().nth(1).unwrap_or("/");
    let path = path.split('?').next().unwrap_or("/");
    let (content_type, extra, body): (&str, String, Vec<u8>) = match (mode, path) {
        (PageMode::Scripted, "/app.js") => (
            "text/javascript; charset=utf-8",
            String::new(),
            format!(
                "setInterval(function(){{fetch('/api',{{headers:{{Authorization:'Bearer {SECRET_TOKEN}'}}}}).catch(function(){{}});}},100);\n"
            )
            .into_bytes(),
        ),
        (PageMode::Scripted, "/api") => (
            "application/json",
            format!("Set-Cookie: sid={SECRET_COOKIE}; Path=/\r\n"),
            b"{\"ok\":true}".to_vec(),
        ),
        (PageMode::Scripted, _) => (
            "text/html; charset=utf-8",
            String::new(),
            b"<!DOCTYPE html><html><head><title>tracewise</title><script src=\"/app.js\"></script></head><body><h1>tracewise-cdp</h1></body></html>".to_vec(),
        ),
        (PageMode::Listeners, "/app.js") => (
            "text/javascript; charset=utf-8",
            String::new(),
            b"function arm(){var el=document.getElementById('go');if(el){el.addEventListener('click',function onGo(){});}}if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',arm);}else{arm();}setInterval(function(){fetch('/api').catch(function(){});},100);\n".to_vec(),
        ),
        (PageMode::Listeners, "/api") => (
            "application/json",
            String::new(),
            b"{\"ok\":true}".to_vec(),
        ),
        (PageMode::Listeners, _) => (
            "text/html; charset=utf-8",
            String::new(),
            b"<!DOCTYPE html><html><head><title>tracewise</title><script src=\"/app.js\"></script></head><body><button id=\"go\">go</button><h1>tracewise-cdp</h1></body></html>".to_vec(),
        ),
        (PageMode::WebMcp, _) => (
            "text/html; charset=utf-8",
            String::new(),
            b"<!DOCTYPE html><html><head><title>tracewise</title></head><body><form toolname=\"tracewise_echo\" tooldescription=\"Echo a short string\" toolinputschema='{\"type\":\"object\",\"properties\":{\"text\":{\"type\":\"string\"}},\"required\":[\"text\"]}'></form><script>(function(){var tool={name:'tracewise_echo',description:'Echo a short string',inputSchema:{type:'object',properties:{text:{type:'string'}},required:['text']},execute:function(args){return Promise.resolve(String(args&&args.text||''));}};var ctx=navigator.modelContext;if(ctx&&typeof ctx.registerTool==='function')ctx.registerTool(tool);else if(ctx&&typeof ctx.provideContext==='function')ctx.provideContext({tools:[tool]});else if(ctx&&typeof ctx.registerTools==='function')ctx.registerTools([tool]);})();</script><input id=\"secret\" data-testid=\"secret\"><button id=\"go\" data-testid=\"go\">go</button><h1>tracewise-webmcp</h1></body></html>".to_vec(),
        ),
        (PageMode::Plain, _) => (
            "text/html; charset=utf-8",
            String::new(),
            b"<!DOCTYPE html><html><head><title>tracewise</title></head><body><h1>tracewise-cdp</h1></body></html>".to_vec(),
        ),
    };
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(&body);
}

struct ChromeDebug {
    endpoint: String,
    child: Option<SupervisedChild>,
    user_data_dir: PathBuf,
}

impl ChromeDebug {
    fn launch() -> Self {
        let port = free_port();
        let user_data_dir =
            std::env::temp_dir().join(format!("tracewise-cdp-{port}-{}", std::process::id()));
        std::fs::create_dir_all(&user_data_dir).expect("create chrome user-data-dir");
        let dir = user_data_dir.display().to_string();
        let args = [
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--remote-debugging-address=127.0.0.1",
            "--remote-allow-origins=*",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-extensions",
            "--window-size=800,600",
        ];
        let mut supervisor = ProcessSupervisor::new(CHROME);
        supervisor.null_stdio();
        for arg in args {
            supervisor.arg(arg);
        }
        for arg in tracewise_web::browser_observation::CHROME_WEBMCP_LAUNCH_ARGS {
            supervisor.arg(*arg);
        }
        // A separate `--user-data-dir <path>` is parsed as a second headless
        // target. Chrome only accepts the switch when the path is attached.
        supervisor.arg(format!("--user-data-dir={dir}"));
        supervisor.arg(format!("--remote-debugging-port={port}"));
        supervisor.arg("about:blank");
        let child = supervisor.spawn().expect("spawn google-chrome");
        Self {
            endpoint: format!("http://127.0.0.1:{port}"),
            child: Some(child),
            user_data_dir,
        }
    }
}

impl Drop for ChromeDebug {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill_group();
        }
        kill_chrome_using(&self.user_data_dir);
        let _ = std::fs::remove_dir_all(&self.user_data_dir);
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve port")
        .local_addr()
        .expect("reserved port")
        .port()
}

/// Chrome's zygote may leave the supervised process group. Kill anything whose
/// command line still names this test's user-data-dir.
fn kill_chrome_using(user_data_dir: &std::path::Path) {
    let needle = user_data_dir.display().to_string();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return;
    };
    for entry in entries.flatten() {
        let pid = entry.file_name();
        let pid = pid.to_string_lossy();
        if pid.parse::<u32>().is_err() {
            continue;
        }
        let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        if String::from_utf8_lossy(&cmdline).contains(&needle) {
            let _ = Command::new("kill").args(["-KILL", pid.as_ref()]).status();
        }
    }
}
