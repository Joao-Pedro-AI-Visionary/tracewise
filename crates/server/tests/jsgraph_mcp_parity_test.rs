//! Live parity with the ORIGINAL REA MCP server for the tools that consume the JavaScript
//! application graph, on real applications (no recorded answers).
//!
//! Oracle: `node <REA_SRC>/scripts/rea.mjs mcp` (default `/workspace/rea-map/src`), driven over
//! stdio JSON-RPC for every call. The port needs the oracle (`TRACEWISE_REQUIRE_ORACLE=1` turns a
//! missing one into a failure instead of a skip).
//!
//! Applications: `fixtures/js/app`, `fixtures/js/app-v2`, `fixtures/electron/invoice_app`,
//! `fixtures/electron/readiness_app`, `fixtures/js/reconstruction_app`, the REA-derived trees in
//! `fixtures/jsgraph/rea/`, `fixtures/jsgraph/own/mixed-formats`, `fixtures/jsgraph/own/dts-app`
//! (declaration files) and the two pinned npm packages in `fixtures/jsgraph/npm/`.
//!
//! Compared, for each tool, the WHOLE MCP result (`structuredContent` and the text `content`
//! item) with only these fields normalized on both sides:
//! - `evidence_id` of the analysis result and every `evidence_links` / `application_evidence_id`
//!   entry that carries one: the id is content-addressed over the host path of the input, which
//!   differs between the checkout the oracle and this port analyze (it is a function of
//!   `subject.local_path`; each side is compared against ids it produced itself, see `canon`),
//! - `subject.local_path`, `normalized_result.input_path`, `parameters.input_path`: host paths.
//!
//! Nothing else is ignored: graph ids, node ids, edge ids, ordering, limitations, coverage and
//! summaries must match exactly.

mod jsgraph_support;

use jsgraph_support::{ours, oracle_available, rea_normalized, repo_root, Counter, Rea};
use serde_json::{json, Value};
use std::path::PathBuf;
use tracewise_server::session::BinarySession;

fn apps() -> Vec<(&'static str, PathBuf)> {
    let f = repo_root().join("fixtures");
    vec![
        ("app", f.join("js/app")),
        ("app-v2", f.join("js/app-v2")),
        ("invoice_app", f.join("electron/invoice_app")),
        ("readiness_app", f.join("electron/readiness_app")),
        ("reconstruction_app", f.join("js/reconstruction_app")),
        ("bundle-app", f.join("js/bundle-app")),
        ("app-a-asar", f.join("js/app-a.asar")),
        ("rea-electron-boundary", f.join("jsgraph/rea/electron-boundary")),
        ("rea-ts-dialect", f.join("jsgraph/rea/ts-dialect")),
        ("rea-bom", f.join("jsgraph/rea/bom")),
        ("own-mixed-formats", f.join("jsgraph/own/mixed-formats")),
        ("npm-ms", f.join("jsgraph/npm/ms-2.1.3")),
        ("npm-escape-html", f.join("jsgraph/npm/escape-html-1.0.3")),
        ("own-dts-app", f.join("jsgraph/own/dts-app")),
    ]
}

/// Strings worth seeding a trace with: labels and identities of the application nodes.
fn seeds_for(application: &Value) -> Vec<Value> {
    let nodes = application["structuredContent"]["normalized_result"]["graph"]["nodes"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut seen = std::collections::BTreeSet::new();
    let mut seeds = Vec::new();
    for node in &nodes {
        let kind = node["kind"].as_str().unwrap_or("");
        let label = node["label"].as_str().unwrap_or("");
        let want = matches!(
            kind,
            "ipc-channel" | "endpoint" | "module" | "web-source-module" | "electron-renderer" | "native-addon"
                | "storage-key" | "artifact" | "asar-entry"
        );
        if !want || label.is_empty() || !seen.insert((kind.to_string(), label.to_string())) {
            continue;
        }
        let seed_kind = match kind {
            "ipc-channel" => "channel",
            "endpoint" => "route",
            "module" | "web-source-module" => "module",
            _ => "string",
        };
        seeds.push(json!({"kind": seed_kind, "value": label}));
        if seeds.len() >= 6 {
            break;
        }
    }
    if let Some(first) = nodes.first() {
        seeds.push(json!({"kind":"node-id","value":first["node_id"]}));
    }
    seeds.push(json!({"kind":"string","value":"definitely-not-present-in-any-app"}));
    seeds
}

/// Semantic trace queries drawn from the application's own semantic graph: every seed kind, every
/// direction, with and without ambiguous edges and an expected source/sink class.
fn semantic_queries(application: &Value) -> Vec<Value> {
    let result = &application["structuredContent"]["normalized_result"];
    let nodes = result["semantic_graph"]["nodes"].as_array().cloned().unwrap_or_default();
    let mut seeds: Vec<Value> = Vec::new();
    let mut kinds_seen = std::collections::BTreeSet::new();
    for node in &nodes {
        let kind = node["kind"].as_str().unwrap_or("");
        if kinds_seen.insert(kind.to_string()) && seeds.len() < 8 {
            let id = jsrg_id(node);
            seeds.push(json!({"kind":"semantic-node","node_id": id}));
        }
    }
    if let Some(fp) = result["semantic_graph"]["fingerprints"].get(0) {
        seeds.push(json!({"kind":"function","fingerprint_sha256": fp["fingerprint_sha256"]}));
    }
    if let Some(node) = result["graph"]["nodes"].get(0) {
        seeds.push(json!({"kind":"application-node","node_id": node["node_id"]}));
    }
    for node in &nodes {
        if let Some(label) = node["label"].as_str() {
            if !label.is_empty() && node["kind"] == "expression" && label.len() < 40 {
                seeds.push(json!({"kind":"literal","value": label}));
                seeds.push(json!({"kind":"property","name": label}));
                seeds.push(json!({"kind":"endpoint","value": label}));
                seeds.push(json!({"kind":"event","name": label}));
                seeds.push(json!({"kind":"boundary-field","field": label}));
                break;
            }
        }
    }
    let mut queries = Vec::new();
    for seed in seeds {
        for direction in ["backward-provenance", "forward-influence", "callers", "ownership"] {
            queries.push(json!({"seed": seed, "direction": direction, "include_ambiguous_dynamic_edges": false, "expected": null}));
        }
    }
    if let Some(first) = queries.first().cloned() {
        let mut ambiguous = first;
        ambiguous["include_ambiguous_dynamic_edges"] = json!(true);
        ambiguous["expected"] = json!({"role":"sink","classes":["expression","call-site"]});
        queries.push(ambiguous);
    }
    queries
}

fn jsrg_id(node: &Value) -> Value {
    // Semantic node ids are derived by the graph; they are stored as `node_id` on the node.
    node["node_id"].clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn analyze_and_consumers_match_rea_on_real_applications() {
    if !oracle_available() {
        return;
    }
    let mut rea = Rea::start();
    let session = BinarySession::new();
    let mut counter = Counter { compared: 0, failures: Vec::new() };
    let mut analyses: Vec<(String, Value, Value)> = Vec::new();

    for (name, path) in apps() {
        let format = if path.extension().is_some_and(|e| e == "asar") { "asar" } else { "directory" };
        let input = json!({"input_path": path.to_string_lossy(), "format": format, "integrity_policy":"fail"});
        let rea_result = rea.call("analyze_javascript_application", input.clone());
        let port_result = ours(&session, "analyze_javascript_application", input).await;
        analyses.push((name.to_string(), rea_normalized(rea_result.clone()), port_result.clone()));
        counter.check(&format!("analyze[{name}]"), rea_result.clone(), port_result.clone());

        let rea_app = rea_normalized(rea_result);
        let application = rea_app["structuredContent"].clone();
        if application.is_null() {
            continue;
        }
        for seed in seeds_for(&rea_app) {
            for direction in ["both", "outgoing", "incoming"] {
                let args = json!({"application": application, "seed": seed, "direction": direction});
                let want = rea.call("trace_application_feature", args.clone());
                let got = ours(&session, "trace_application_feature", args).await;
                counter.check(&format!("trace_application_feature[{name}, {seed}, {direction}]"), want, got);
            }
        }
        for query in semantic_queries(&rea_app) {
            let args = json!({"application": application, "query": query});
            let want = rea.call("trace_javascript_semantics", args.clone());
            let got = ours(&session, "trace_javascript_semantics", args).await;
            counter.check(&format!("trace_javascript_semantics[{name}, {query}]"), want, got);
        }
    }

    // Version comparison and export shapes across every pair that shares a name prefix.
    let by_name = |n: &str| analyses.iter().find(|(name, _, _)| name == n).map(|(_, rea, _)| rea.clone());
    for (left, right) in [("app", "app-v2"), ("app-v2", "app"), ("invoice_app", "readiness_app"), ("npm-ms", "npm-escape-html")] {
        let (Some(l), Some(r)) = (by_name(left), by_name(right)) else { continue };
        let args = json!({"left": l["structuredContent"], "right": r["structuredContent"]});
        let want = rea.call("compare_application_versions", args.clone());
        let got = ours(&session, "compare_application_versions", args).await;
        counter.check(&format!("compare_application_versions[{left}, {right}]"), want, got);
    }
    // Source-to-bundle comparison of the historical reference against every analyzed application.
    let reference: Value = serde_json::from_str(
        &std::fs::read_to_string(repo_root().join("fixtures/js/historical_source_graph.json")).expect("reference"),
    )
    .expect("reference json");
    for (name, rea_app, _) in &analyses {
        if rea_app["structuredContent"].is_null() {
            continue;
        }
        let args = json!({"reference": reference, "application": rea_app["structuredContent"]});
        let want = rea.call("compare_source_to_bundle", args.clone());
        let got = ours(&session, "compare_source_to_bundle", args).await;
        counter.check(&format!("compare_source_to_bundle[{name}]"), want, got);
    }
    let (Some(l), Some(r)) = (by_name("app"), by_name("app-v2")) else { panic!("missing analyses") };
    let args = json!({
        "left": l["structuredContent"], "right": r["structuredContent"],
        "left_module_path":"src/math.js","left_export_name":"add",
        "right_module_path":"src/math.js","right_export_name":"add",
    });
    let want = rea.call("compare_javascript_export_shapes", args.clone());
    let got = ours(&session, "compare_javascript_export_shapes", args).await;
    counter.check("compare_javascript_export_shapes[app, app-v2]", want, got);

    eprintln!("compared {} MCP results", counter.compared);
    for failure in &counter.failures {
        eprintln!("DIFF {failure}");
    }
    assert!(
        counter.failures.is_empty(),
        "{} of {} MCP results differ from REA",
        counter.failures.len(),
        counter.compared
    );
}
