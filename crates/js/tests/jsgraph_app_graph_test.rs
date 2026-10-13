//! The application graph, Electron summary, statistics and metadata built from real files must
//! equal what the original REA returns for the same application directory.
//!
//! The per-file layers (static analysis, semantic IR) come from the REA oracle here
//! (`OracleAnalyzer`), so this test isolates the application-graph port; the layers have their
//! own parity tests. Compared exactly: everything in `normalized_result` except `input_path`
//! (machine path); that includes the semantic relation graph.

mod support;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::Value;
use support::{collect_with_node_modules, diff, oracle_available, rea_mcp_call, stream_oracle, Report};
use tracewise_js::jsgraph::app_graph::analysis::{FileAnalyzer, JsFileResult, ParsedFile};
use tracewise_js::jsgraph::app_graph::model::ArtifactFile;
use tracewise_js::jsgraph::app_graph::reconstruct::reconstruct_application;
use tracewise_js::jsgraph::semantic_graph::SemanticGraphProjection;
use tracewise_js::jsgraph::control::Cancel;
use tracewise_js::jsgraph::ir::SemanticIr;
use tracewise_js::jsgraph::static_types::StaticAnalysis;
use tracewise_js::jsgraph::error::AnalysisFailure;

struct OracleAnalyzer {
    root: PathBuf,
    lines: HashMap<PathBuf, Value>,
}

impl FileAnalyzer for OracleAnalyzer {
    fn analyze_javascript(&self, file: &ArtifactFile, _source: &str) -> Result<JsFileResult, AnalysisFailure> {
        let line = self
            .lines
            .get(&self.root.join(&file.path))
            .unwrap_or_else(|| panic!("no oracle layer line for {}", file.path));
        if line["ok"] != Value::Bool(true) {
            return Ok(JsFileResult { parsed: None });
        }
        let static_analysis: StaticAnalysis = serde_json::from_value(line["static"].clone()).expect("static");
        let ir = if static_analysis.parse_status == "failed" {
            None
        } else {
            Some(serde_json::from_value::<SemanticIr>(line["ir"].clone()).expect("ir"))
        };
        Ok(JsFileResult { parsed: Some(ParsedFile { static_analysis, ir }) })
    }

    fn source_map_reference(&self, source_name: &str, _root: Option<&str>, map_path: &str) -> Value {
        panic!("source maps need the static layer port ({source_name} in {map_path})")
    }
}

fn analyzer_for(root: &Path) -> OracleAnalyzer {
    let mut files = Vec::new();
    collect_with_node_modules(root, &mut files);
    let mut lines = HashMap::new();
    stream_oracle("layers.mjs", &files, |line| {
        lines.insert(PathBuf::from(line["path"].as_str().unwrap()), line);
    });
    OracleAnalyzer { root: root.to_path_buf(), lines }
}

fn check_application(root: &Path, report: &mut Report) {
    let analyzer = analyzer_for(root);
    let mine = reconstruct_application(
        root.to_str().unwrap(),
        "auto",
        "fail",
        &analyzer,
        Box::new(SemanticGraphProjection::new()),
        &Cancel::new(),
    )
    .unwrap_or_else(|error| panic!("{}: {error}", root.display()));
    let expected = rea_mcp_call(
        "analyze_javascript_application",
        serde_json::json!({ "input_path": root.to_str().unwrap() }),
    );
    let result = &expected["structuredContent"]["normalized_result"];
    assert!(result.is_object(), "{}: oracle failed: {expected}", root.display());
    let mut want = result.clone();
    let mut got = mine;
    for value in [&mut want, &mut got] {
        let object = value.as_object_mut().unwrap();
        object.remove("input_path");
    }
    eprintln!(
        "{}: {} nodes, {} edges; semantic {} nodes, {} relations, {} unknowns, {} fingerprints",
        root.display(),
        got["graph"]["nodes"].as_array().map_or(0, Vec::len),
        got["graph"]["edges"].as_array().map_or(0, Vec::len),
        got["semantic_graph"]["nodes"].as_array().map_or(0, Vec::len),
        got["semantic_graph"]["relations"].as_array().map_or(0, Vec::len),
        got["semantic_graph"]["unknowns"].as_array().map_or(0, Vec::len),
        got["semantic_graph"]["fingerprints"].as_array().map_or(0, Vec::len)
    );
    report.record(&root.display().to_string(), &diff(&want, &got, 12));
}

fn roots() -> Vec<PathBuf> {
    let fixtures = support::repo_root().join("fixtures");
    [
        "js/app",
        "js/app-v2",
        "electron/invoice_app",
        "electron/readiness_app",
        "js/reconstruction_app",
        "jsgraph/rea/electron-boundary",
        "jsgraph/rea/ts-dialect",
        "jsgraph/rea/bom",
        "jsgraph/own/mixed-formats",
        "jsgraph/npm/ms-2.1.3",
        "jsgraph/npm/escape-html-1.0.3",
        "jsgraph/own/dts-app",
    ]
    .iter()
    .map(|p| fixtures.join(p))
    .collect()
}

#[test]
fn application_graph_matches_rea_for_fixture_applications() {
    if !oracle_available() {
        return;
    }
    let mut report = Report::default();
    for root in roots() {
        check_application(&root, &mut report);
    }
    report.finish("application graph");
}
