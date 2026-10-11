//! `analyze_web_bundle` (port of REA domain/webBundleAnalysis.ts,
//! webBundleAnalyzer.ts and the browser tool in registerBrowserTools.ts).
//!
//! The page capture is the existing passive inspection with script source
//! retained. Findings come from a literal scan of that source: imports,
//! route registrations, network callees, vendor markers and WebMCP declarations.
//! Captured JavaScript is not executed.

use std::collections::BTreeSet;
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracewise_domain::evidence::Evidence;

use crate::browser_observation::{create_browser_evidence, sanitize_browser_url, BrowserScope};
use crate::error::WebError;
use crate::page_inspection::{inspect_web_page, InspectWebPageInput};
use crate::runtime_cdp::{input_error, optional_bool, optional_i64, parse_scope, require_target_id};

const OPERATION: &str = "analyze_web_bundle";
const MAX_SAFE_INT: i64 = 9_007_199_254_740_991;
const MAPPING_LIMIT: usize = 4_000;

static IMPORT_FROM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)(?:^|[^\w$])import\s+(?:[^'"\n]+?\s+from\s+)?['"]([^'"]+)['"]"#).expect("import regex")
});
static DYNAMIC_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"import\s*\(\s*['"]([^'"]+)['"]"#).expect("dynamic import regex"));
static REQUIRE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?:^|[^\w$])require\s*\(\s*['"]([^'"]+)['"]"#).expect("require regex"));
static IMPORT_SCRIPTS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?:^|[^\w$])importScripts\s*\(\s*['"]([^'"]+)['"]"#).expect("importScripts regex"));
static FETCH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?:^|[^\w$])([\w$.]*fetch)\s*\(\s*['"]([^'"]+)['"]"#).expect("fetch regex"));
static WEBSOCKET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"new\s+WebSocket\s*\(\s*['"]([^'"]+)['"]"#).expect("websocket regex"));
static XHR_OPEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"([\w$.]*open)\s*\(\s*['"][A-Za-z]+['"]\s*,\s*['"]([^'"]+)['"]"#).expect("xhr regex")
});
static ROUTE_CALL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?:^|[^\w$])((?:[\w$]+\.)*(?:route|addRoute|useRoutes|createBrowserRouter|createHashRouter))\s*\(\s*['"]([^'"]*)['"]"#,
    )
    .expect("route regex")
});
static ROUTE_PROP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?:^|[^\w$])(path|route)\s*:\s*['"]([^'"]+)['"]"#).expect("route property regex"));
static WEBMCP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"modelContext\.registerTool\s*\(\s*\{([^}]*)\}"#).expect("webmcp regex")
});

pub struct AnalyzeWebBundleInput {
    pub scope: BrowserScope,
    pub target_id: String,
    pub observation_ms: i64,
    pub include_accessibility_text: bool,
    pub include_console_text: bool,
    pub include_json_body_shapes: bool,
    pub include_websocket_shapes: bool,
    pub include_storage_keys: bool,
    pub include_storage_fingerprints: bool,
    pub fetch_source_maps: bool,
}

pub fn parse_analyze_web_bundle_input(args: &Value) -> Result<AnalyzeWebBundleInput, WebError> {
    let (scope, object) = parse_scope(
        OPERATION,
        args,
        &[
            "target_id",
            "observation_ms",
            "include_accessibility_text",
            "include_console_text",
            "include_json_body_shapes",
            "include_websocket_shapes",
            "include_storage_keys",
            "include_storage_fingerprints",
            "include_script_sources",
            "fetch_source_maps",
        ],
    )?;
    let target_id = require_target_id(OPERATION, &object)?;
    if let Some(false) = optional_bool(OPERATION, &object, "include_script_sources")? {
        return Err(input_error(
            OPERATION,
            "include_script_sources",
            "include_script_sources must be true",
        ));
    }
    let include_storage_keys = optional_bool(OPERATION, &object, "include_storage_keys")?.unwrap_or(false);
    let include_storage_fingerprints = optional_bool(OPERATION, &object, "include_storage_fingerprints")?.unwrap_or(false);
    if include_storage_fingerprints && !include_storage_keys {
        return Err(input_error(
            OPERATION,
            "include_storage_fingerprints",
            "Storage fingerprints require storage key capture",
        ));
    }
    Ok(AnalyzeWebBundleInput {
        scope,
        target_id,
        observation_ms: optional_i64(OPERATION, &object, "observation_ms", 0, MAX_SAFE_INT)?.unwrap_or(500),
        include_accessibility_text: optional_bool(OPERATION, &object, "include_accessibility_text")?.unwrap_or(false),
        include_console_text: optional_bool(OPERATION, &object, "include_console_text")?.unwrap_or(false),
        include_json_body_shapes: optional_bool(OPERATION, &object, "include_json_body_shapes")?.unwrap_or(false),
        include_websocket_shapes: optional_bool(OPERATION, &object, "include_websocket_shapes")?.unwrap_or(false),
        include_storage_keys,
        include_storage_fingerprints,
        fetch_source_maps: optional_bool(OPERATION, &object, "fetch_source_maps")?.unwrap_or(false),
    })
}

pub async fn analyze_web_bundle(input: &AnalyzeWebBundleInput) -> Result<Evidence, WebError> {
    let inspection = inspect_web_page(&InspectWebPageInput {
        scope: input.scope.clone(),
        target_id: input.target_id.clone(),
        observation_ms: input.observation_ms,
        include_accessibility_text: input.include_accessibility_text,
        include_console_text: input.include_console_text,
        include_json_body_shapes: input.include_json_body_shapes,
        include_websocket_shapes: input.include_websocket_shapes,
        include_storage_keys: input.include_storage_keys,
        include_storage_fingerprints: input.include_storage_fingerprints,
        include_script_sources: true,
    })
    .await?;
    let page = &inspection.normalized_result;
    let source_maps = if input.fetch_source_maps {
        fetch_source_maps(page, &input.scope.allowed_origins).await
    } else {
        json!({
            "status": "not_requested",
            "requested": 0,
            "processed": 0,
            "items": [],
        })
    };
    let analysis = analyze_captured_bundle(page, source_maps);
    create_browser_evidence(OPERATION, "rea.web-bundle-analysis", parameters(input), analysis)
}

fn parameters(input: &AnalyzeWebBundleInput) -> Value {
    json!({
        "cdp_endpoint": input.scope.cdp_endpoint,
        "allowed_origins": input.scope.allowed_origins,
        "target_id": input.target_id,
        "observation_ms": input.observation_ms,
        "include_accessibility_text": input.include_accessibility_text,
        "include_console_text": input.include_console_text,
        "include_json_body_shapes": input.include_json_body_shapes,
        "include_websocket_shapes": input.include_websocket_shapes,
        "include_storage_keys": input.include_storage_keys,
        "include_storage_fingerprints": input.include_storage_fingerprints,
        "include_script_sources": true,
        "fetch_source_maps": input.fetch_source_maps,
    })
}

struct Finding {
    value: String,
    mechanism: String,
    line: Option<i64>,
    column: Option<i64>,
}

struct Edge {
    kind: &'static str,
    specifier: String,
    resolved_url: Option<String>,
    line: Option<i64>,
    column: Option<i64>,
}

fn analyze_captured_bundle(inspection: &Value, source_maps: Value) -> Value {
    let items = inspection["scripts"]["items"].as_array().cloned().unwrap_or_default();
    let mut included = Vec::new();
    let mut unavailable = Vec::new();
    for item in &items {
        if item["source"]["included"] == true {
            included.push(item.clone());
        } else if let Some(key) = item["script_key"].as_str() {
            unavailable.push(key.to_string());
        }
    }
    let mut scan = Scan::default();
    let mut visited = 0_i64;
    let mut parsed = 0_i64;
    let mut failures = 0_i64;
    for script in &included {
        let text = script["source"]["artifact"]["text"].as_str().unwrap_or("");
        if text.is_empty() && script["source"]["artifact"]["text"].as_str().is_none() {
            failures += 1;
            continue;
        }
        parsed += 1;
        visited += text.chars().filter(|ch| "{}();,".contains(*ch)).count() as i64;
        detect_vendors(script, text, &mut scan.inferences, &mut scan.seen);
        scan_script(script, text, &mut scan);
    }
    let omitted_scripts = budget_omission(inspection, "scripts");
    let omitted_maps = if source_maps["status"] == "not_requested" {
        None
    } else {
        budget_omission(inspection, "source_maps")
    };
    let source_map_incomplete = matches!(source_maps["status"].as_str(), Some("partial" | "unavailable"));
    let partial = failures > 0 || !unavailable.is_empty() || source_map_incomplete || omitted_scripts.is_some() || omitted_maps.is_some();
    json!({
        "capture": {
            "target_url": inspection["target"]["url"].as_str().unwrap_or(""),
            "scripts_observed": inspection["scripts"]["total"].as_i64().unwrap_or(items.len() as i64),
            "scripts_analyzed": included.len() as i64,
            "source_artifacts": included.iter().map(source_artifact).collect::<Vec<_>>(),
        },
        "observations": {
            "chunks": {
                "nodes": included.iter().map(chunk_node).collect::<Vec<_>>(),
                "edges": scan.edges.iter().map(|(key, edge)| edge_json(key, edge)).collect::<Vec<_>>(),
            },
            "routes": scan.routes.iter().map(|(key, finding)| finding_json(key, finding)).collect::<Vec<_>>(),
            "endpoints": scan.endpoints.iter().map(|(key, finding)| finding_json(key, finding)).collect::<Vec<_>>(),
            "webmcp_declarations": scan.webmcp,
            "source_maps": source_maps.clone(),
        },
        "inferences": scan.inferences,
        "unknowns": unknowns(&included, &unavailable, failures, &source_maps, omitted_scripts, omitted_maps),
        "completeness": {
            "status": if partial { "partial" } else { "complete" },
            "parsed_scripts": parsed,
            "parse_failures": failures,
            "visited_ast_nodes": visited,
        },
        "limitations": [
            "Static bundle findings are observations or bounded inferences; REA does not execute captured JavaScript.",
            "String-built routes and endpoints, encrypted configuration, and server-side behavior may remain unknown.",
            "Page-declared WebMCP metadata is untrusted and is never registered or invoked as an REA tool.",
        ],
    })
}

fn source_artifact(script: &Value) -> Value {
    let artifact = &script["source"]["artifact"];
    json!({
        "sha256": artifact["sha256"],
        "bytes": artifact["bytes"],
        "media_type": artifact["media_type"],
        "charset": "utf-8",
        "text_available": true,
    })
}

fn chunk_node(script: &Value) -> Value {
    json!({
        "script_key": script["script_key"],
        "url": script["url"],
        "artifact_sha256": script["source"]["artifact"]["sha256"],
        "bytes": script["source"]["artifact"]["bytes"],
    })
}

fn edge_json(script_key: &str, edge: &Edge) -> Value {
    json!({
        "from_script_key": script_key,
        "kind": edge.kind,
        "specifier": edge.specifier,
        "resolved_url": edge.resolved_url,
        "location": location(script_key, edge.line, edge.column),
    })
}

fn finding_json(script_key: &str, finding: &Finding) -> Value {
    json!({
        "value": finding.value,
        "mechanism": finding.mechanism,
        "location": location(script_key, finding.line, finding.column),
    })
}

fn location(script_key: &str, line: Option<i64>, column: Option<i64>) -> Value {
    json!({ "script_key": script_key, "line": line, "column": column })
}

#[derive(Default)]
struct Scan {
    edges: Vec<(String, Edge)>,
    routes: Vec<(String, Finding)>,
    endpoints: Vec<(String, Finding)>,
    webmcp: Vec<Value>,
    inferences: Vec<Value>,
    seen: BTreeSet<String>,
}

fn scan_script(script: &Value, text: &str, scan: &mut Scan) {
    let script_key = script["script_key"].as_str().unwrap_or("");
    let script_url = script["url"].as_str().unwrap_or("");
    for (kind, regex) in [
        ("static_import", &*IMPORT_FROM),
        ("dynamic_import", &*DYNAMIC_IMPORT),
        ("require", &*REQUIRE),
        ("worker_import", &*IMPORT_SCRIPTS),
    ] {
        for found in regex.captures_iter(text) {
            let Some(specifier) = found.get(1).map(|m| m.as_str().to_string()) else {
                continue;
            };
            let (line, column) = line_column(text, found.get(0).map(|m| m.start()).unwrap_or(0));
            let key = format!("edge\0{script_key}\0{kind}\0{specifier}");
            if !scan.seen.insert(key) {
                continue;
            }
            let resolved = if kind == "worker_import" || url_like(&specifier) {
                resolve_specifier(&specifier, script_url)
            } else {
                None
            };
            scan.edges.push((
                script_key.to_string(),
                Edge {
                    kind,
                    specifier,
                    resolved_url: resolved,
                    line: Some(line),
                    column: Some(column),
                },
            ));
        }
    }
    for found in FETCH.captures_iter(text) {
        push_endpoint(script, &mut scan.endpoints, &mut scan.seen, found.get(1), found.get(2), found.get(0));
    }
    for found in XHR_OPEN.captures_iter(text) {
        push_endpoint(script, &mut scan.endpoints, &mut scan.seen, found.get(1), found.get(2), found.get(0));
    }
    for found in WEBSOCKET.captures_iter(text) {
        let name = "WebSocket";
        push_named_endpoint(script, &mut scan.endpoints, &mut scan.seen, name, found.get(1), found.get(0));
    }
    for found in ROUTE_CALL.captures_iter(text) {
        let Some(name) = found.get(1).map(|m| m.as_str()) else {
            continue;
        };
        if let Some(value) = found.get(2) {
            push_finding(script, &mut scan.routes, &mut scan.seen, &format!("call:{name}"), value.as_str(), value.start(), text);
        }
        let value = if name.ends_with("useRoutes") || name.ends_with("createBrowserRouter") {
            "React Router-compatible route API"
        } else {
            "Generic route registration API"
        };
        let key = format!("route-framework\0{script_key}\0{value}");
        if scan.seen.insert(key) {
            let (line, column) = line_column(text, found.get(0).map(|m| m.start()).unwrap_or(0));
            scan.inferences.push(json!({
                "kind": "route_framework",
                "value": value,
                "confidence": "medium",
                "basis": [{
                    "script_key": script_key,
                    "artifact_sha256": script["source"]["artifact"]["sha256"],
                    "line": line,
                    "column": column,
                    "detector": format!("call:{name}"),
                }],
            }));
        }
    }
    for found in ROUTE_PROP.captures_iter(text) {
        let Some(name) = found.get(1).map(|m| m.as_str()) else {
            continue;
        };
        if let Some(value) = found.get(2) {
            push_finding(script, &mut scan.routes, &mut scan.seen, &format!("property:{name}"), value.as_str(), value.start(), text);
        }
    }
    for found in WEBMCP.captures_iter(text) {
        let body = found.get(1).map(|m| m.as_str()).unwrap_or("");
        let name = object_string(body, "name");
        let description = object_string(body, "description");
        let props = schema_properties(body);
        let key = format!("webmcp\0{script_key}\0{}\0{}", name.as_deref().unwrap_or(""), props.join("\u{1}"));
        if !scan.seen.insert(key) {
            continue;
        }
        let (line, column) = line_column(text, found.get(0).map(|m| m.start()).unwrap_or(0));
        scan.webmcp.push(json!({
            "name": name,
            "description": description,
            "schema_property_names": props,
            "trust": "page-declared-untrusted",
            "location": location(script_key, Some(line), Some(column)),
        }));
    }
}

fn push_endpoint(
    script: &Value,
    endpoints: &mut Vec<(String, Finding)>,
    seen: &mut BTreeSet<String>,
    name: Option<regex::Match<'_>>,
    value: Option<regex::Match<'_>>,
    whole: Option<regex::Match<'_>>,
) {
    let (Some(name), Some(value)) = (name, value) else {
        return;
    };
    push_named_endpoint(script, endpoints, seen, name.as_str(), Some(value), whole);
}

fn push_named_endpoint(
    script: &Value,
    endpoints: &mut Vec<(String, Finding)>,
    seen: &mut BTreeSet<String>,
    name: &str,
    value: Option<regex::Match<'_>>,
    whole: Option<regex::Match<'_>>,
) {
    let Some(value) = value else {
        return;
    };
    push_finding(
        script,
        endpoints,
        seen,
        &format!("call:{name}"),
        value.as_str(),
        whole.map(|m| m.start()).unwrap_or(0),
        "",
    );
}

fn push_finding(
    script: &Value,
    collection: &mut Vec<(String, Finding)>,
    seen: &mut BTreeSet<String>,
    mechanism: &str,
    raw_value: &str,
    start: usize,
    text_for_line: &str,
) {
    let script_key = script["script_key"].as_str().unwrap_or("");
    let value = sanitize_browser_url(raw_value).url;
    let key = format!("finding\0{mechanism}\0{script_key}\0{value}");
    if !seen.insert(key) {
        return;
    }
    let (line, column) = if text_for_line.is_empty() {
        (None, None)
    } else {
        let (line, column) = line_column(text_for_line, start);
        (Some(line), Some(column))
    };
    collection.push((
        script_key.to_string(),
        Finding {
            value,
            mechanism: mechanism.to_string(),
            line,
            column,
        },
    ));
}

fn detect_vendors(script: &Value, text: &str, inferences: &mut Vec<Value>, seen: &mut BTreeSet<String>) {
    const DETECTORS: &[(&str, &str, &str, &str, &[&str])] = &[
        ("webpack", "webpack-runtime", "high", "bundle_runtime", &["__webpack_require__"]),
        ("Vite", "vite-runtime", "medium", "bundle_runtime", &["__vite__", "import.meta.hot"]),
        ("React", "react-runtime", "medium", "vendor_fingerprint", &["__REACT_DEVTOOLS_GLOBAL_HOOK__", "React.createElement"]),
        ("Vue", "vue-runtime", "medium", "vendor_fingerprint", &["__VUE__", "createApp("]),
        ("Next.js", "next-runtime", "high", "vendor_fingerprint", &["__NEXT_DATA__", "/_next/"]),
        ("Angular", "angular-runtime", "high", "vendor_fingerprint", &["ɵɵdefineComponent"]),
        ("Svelte", "svelte-runtime", "medium", "vendor_fingerprint", &["svelte/internal"]),
    ];
    let script_key = script["script_key"].as_str().unwrap_or("");
    for (value, detector, confidence, kind, patterns) in DETECTORS {
        if !patterns.iter().any(|pattern| text.contains(pattern)) {
            continue;
        }
        let key = format!("vendor\0{script_key}\0{value}");
        if !seen.insert(key) {
            continue;
        }
        inferences.push(json!({
            "kind": kind,
            "value": value,
            "confidence": confidence,
            "basis": [{
                "script_key": script_key,
                "artifact_sha256": script["source"]["artifact"]["sha256"],
                "line": null,
                "column": null,
                "detector": detector,
            }],
        }));
    }
}

fn object_string(body: &str, name: &str) -> Option<String> {
    let pattern = format!(r#"{name}\s*:\s*['"]([^'"]*)['"]"#);
    Regex::new(&pattern).ok()?.captures(body)?.get(1).map(|m| m.as_str().to_string())
}

fn schema_properties(body: &str) -> Vec<String> {
    let Some(props) = body.split("properties").nth(1) else {
        return Vec::new();
    };
    let mut names = BTreeSet::new();
    if let Ok(regex) = Regex::new(r#"['"]([A-Za-z_][\w-]*)['"]\s*:"#) {
        for found in regex.captures_iter(props) {
            if let Some(name) = found.get(1) {
                names.insert(name.as_str().to_string());
            }
        }
    }
    names.into_iter().collect()
}

fn url_like(specifier: &str) -> bool {
    specifier.starts_with('/')
        || specifier.starts_with("./")
        || specifier.starts_with("../")
        || specifier.split(':').next().is_some_and(|scheme| {
            !scheme.is_empty()
                && scheme.chars().next().is_some_and(|ch| ch.is_ascii_alphabetic())
                && scheme.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '+' || ch == '.' || ch == '-')
                && specifier.contains(':')
        })
}

fn resolve_specifier(specifier: &str, base: &str) -> Option<String> {
    let base = url::Url::parse(base).ok()?;
    let resolved = url::Url::options().base_url(Some(&base)).parse(specifier).ok()?;
    if resolved.scheme() != "http" && resolved.scheme() != "https" {
        return None;
    }
    Some(sanitize_browser_url(resolved.as_str()).url)
}

fn line_column(text: &str, start: usize) -> (i64, i64) {
    let bounded = start.min(text.len());
    let prefix = &text[..bounded];
    let line = prefix.chars().filter(|ch| *ch == '\n').count() as i64 + 1;
    let column = prefix.rsplit('\n').next().unwrap_or("").encode_utf16().count() as i64;
    (line, column)
}

fn budget_omission(inspection: &Value, section: &str) -> Option<Option<i64>> {
    let excluded = inspection["completeness"]["excluded"].as_array()?;
    let matches: Vec<&Value> = excluded
        .iter()
        .filter(|item| item["section"].as_str() == Some(section) && item["reason"].as_str() == Some("resource_budget_exhausted"))
        .collect();
    if matches.is_empty() {
        return None;
    }
    if matches.iter().any(|item| item["count"].is_null()) {
        return Some(None);
    }
    Some(Some(matches.iter().filter_map(|item| item["count"].as_i64()).sum()))
}

fn unknowns(
    included: &[Value],
    unavailable: &[String],
    failures: i64,
    source_maps: &Value,
    omitted_scripts: Option<Option<i64>>,
    omitted_maps: Option<Option<i64>>,
) -> Vec<Value> {
    let mut items = Vec::new();
    if let Some(count) = omitted_scripts {
        items.push(json!({
            "dimension": "script_inventory",
            "reason": budget_reason("script records", count),
            "affected_script_keys": [],
        }));
    }
    if !unavailable.is_empty() {
        items.push(json!({
            "dimension": "script_source",
            "reason": "Source artifact was not captured",
            "affected_script_keys": unavailable,
        }));
    }
    if failures > 0 {
        items.push(json!({
            "dimension": "javascript_ast",
            "reason": "One or more source artifacts could not be parsed",
            "affected_script_keys": included.iter().filter_map(|script| script["script_key"].as_str()).collect::<Vec<_>>(),
        }));
    }
    if let Some(count) = omitted_maps {
        items.push(json!({
            "dimension": "source_maps",
            "reason": budget_reason("source-map declarations", count),
            "affected_script_keys": [],
        }));
    }
    let status = source_maps["status"].as_str().unwrap_or("");
    if status != "not_requested" && status != "included" {
        let mut keys: Vec<&str> = source_maps["items"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter(|item| item["status"].as_str() != Some("included"))
                    .filter_map(|item| item["script_key"].as_str())
                    .collect()
            })
            .unwrap_or_default();
        keys.sort_unstable();
        items.push(json!({
            "dimension": "source_maps",
            "reason": source_maps["limitation"].as_str().unwrap_or("One or more requested source maps were unavailable or incomplete"),
            "affected_script_keys": keys,
        }));
    }
    items
}

fn budget_reason(label: &str, count: Option<i64>) -> String {
    match count {
        None => format!("Capture omitted an unknown number of {label} because its resource budget was exhausted."),
        Some(count) => format!("Capture omitted {count} {label} because its resource budget was exhausted."),
    }
}

async fn fetch_source_maps(inspection: &Value, allowed_origins: &[String]) -> Value {
    let mut requests = Vec::new();
    if let Some(items) = inspection["scripts"]["items"].as_array() {
        for item in items {
            if let Some(url) = item["source_map_url"].as_str() {
                if let Some(key) = item["script_key"].as_str() {
                    requests.push((key.to_string(), url.to_string()));
                }
            }
        }
    }
    if requests.is_empty() {
        return json!({
            "status": "unavailable",
            "requested": 0,
            "processed": 0,
            "items": [],
        });
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .build();
    let mut items = Vec::new();
    for (script_key, declared) in &requests {
        items.push(fetch_one(client.as_ref().ok(), script_key, declared, allowed_origins).await);
    }
    let retained = items
        .iter()
        .filter(|item| matches!(item["status"].as_str(), Some("included" | "partial")))
        .count();
    let status = if items.is_empty() || retained == 0 {
        "unavailable"
    } else if retained == items.len() && items.iter().all(|item| item["status"] == "included") {
        "included"
    } else {
        "partial"
    };
    json!({
        "status": status,
        "requested": requests.len() as i64,
        "processed": items.len() as i64,
        "items": items,
    })
}

async fn fetch_one(client: Option<&reqwest::Client>, script_key: &str, declared: &str, allowed_origins: &[String]) -> Value {
    let Some(client) = client else {
        return failed_map(script_key, declared, "fetch_failed", "Source-map fetch client could not be created.");
    };
    if crate::cdp_values::allowed_url(Some(declared), allowed_origins).is_none() {
        return failed_map(script_key, declared, "policy_filtered", "Source-map URL is outside the selected origin scope.");
    }
    let response = match client.get(declared).send().await {
        Ok(response) => response,
        Err(error) => return failed_map(script_key, declared, "fetch_failed", &error.to_string()),
    };
    if !response.status().is_success() {
        return failed_map(
            script_key,
            declared,
            "fetch_failed",
            &format!("Source-map fetch returned HTTP {}.", response.status()),
        );
    }
    let bytes = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(error) => return failed_map(script_key, declared, "fetch_failed", &error.to_string()),
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return failed_map(script_key, declared, "invalid", "Source-map response is not valid UTF-8.");
    };
    match sourcemap::SourceMap::from_slice(text.as_bytes()) {
        Ok(map) => parsed_map(script_key, declared, text, &map),
        Err(error) => failed_map(script_key, declared, "invalid", &error.to_string()),
    }
}

fn parsed_map(script_key: &str, declared: &str, text: &str, map: &sourcemap::SourceMap) -> Value {
    let mut mappings = Vec::new();
    let mut truncated = false;
    for token in map.tokens() {
        if mappings.len() >= MAPPING_LIMIT {
            truncated = true;
            break;
        }
        let Some(source) = token.get_source() else {
            continue;
        };
        mappings.push(json!({
            "generated_line": token.get_dst_line() as i64 + 1,
            "generated_column": token.get_dst_col() as i64,
            "source": source,
            "original_line": token.get_src_line() as i64 + 1,
            "original_column": token.get_src_col() as i64,
            "name": token.get_name(),
        }));
    }
    let mut originals = Vec::new();
    let mut module_edges = Vec::new();
    for index in 0..map.get_source_count() {
        let Some(source) = map.get_source(index) else {
            continue;
        };
        let contents = map.get_source_contents(index);
        if let Some(contents) = contents {
            module_edges.extend(module_edges_in(source, contents));
        }
        originals.push(json!({
            "source": source,
            "artifact": contents.map(text_artifact),
        }));
    }
    json!({
        "script_key": script_key,
        "declared_url": declared,
        "artifact": text_artifact(text),
        "original_sources": originals,
        "original_module_edges": module_edges,
        "mappings": mappings,
        "status": if truncated { "partial" } else { "included" },
        "limitation": if truncated { Value::String(format!("Mappings were limited to {MAPPING_LIMIT} entries.")) } else { Value::Null },
    })
}

fn module_edges_in(source: &str, text: &str) -> Vec<Value> {
    let mut edges = Vec::new();
    for (kind, regex) in [("static_import", &*IMPORT_FROM), ("dynamic_import", &*DYNAMIC_IMPORT), ("require", &*REQUIRE)] {
        for found in regex.captures_iter(text) {
            let Some(specifier) = found.get(1).map(|m| m.as_str()) else {
                continue;
            };
            edges.push(json!({
                "from_source": source,
                "kind": kind,
                "specifier": specifier,
                "resolved_source": None::<String>,
            }));
        }
    }
    edges
}

fn text_artifact(text: &str) -> Value {
    json!({
        "sha256": hex::encode(Sha256::digest(text.as_bytes())),
        "bytes": text.len() as i64,
        "media_type": "application/json",
        "charset": "utf-8",
        "text": text,
    })
}

fn failed_map(script_key: &str, declared: &str, status: &str, limitation: &str) -> Value {
    json!({
        "script_key": script_key,
        "declared_url": declared,
        "status": status,
        "artifact": null,
        "original_sources": [],
        "original_module_edges": [],
        "mappings": [],
        "limitation": limitation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_fetch_and_import_are_bundle_findings() {
        let inspection = json!({
            "target": { "url": "https://app.example/index.html" },
            "scripts": {
                "total": 1,
                "items": [{
                    "script_key": "app.js",
                    "url": "https://app.example/app.js",
                    "source": {
                        "included": true,
                        "artifact": {
                            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "bytes": 42,
                            "media_type": "text/javascript",
                            "charset": "utf-8",
                            "text": "import './chunk.js';\nfetch('/api');\n__webpack_require__(1);\n",
                        }
                    }
                }]
            },
            "completeness": { "excluded": [] }
        });
        let analysis = analyze_captured_bundle(
            &inspection,
            json!({"status": "not_requested", "requested": 0, "processed": 0, "items": []}),
        );
        assert_eq!(analysis["capture"]["scripts_analyzed"], 1);
        assert_eq!(analysis["completeness"]["status"], "complete");
        let edges = analysis["observations"]["chunks"]["edges"].as_array().unwrap();
        assert!(edges.iter().any(|edge| edge["specifier"] == "./chunk.js" && edge["kind"] == "static_import"));
        let endpoints = analysis["observations"]["endpoints"].as_array().unwrap();
        assert!(endpoints.iter().any(|item| item["value"] == "/api" && item["mechanism"] == "call:fetch"));
        assert!(analysis["inferences"].as_array().unwrap().iter().any(|item| item["value"] == "webpack"));
    }
}
