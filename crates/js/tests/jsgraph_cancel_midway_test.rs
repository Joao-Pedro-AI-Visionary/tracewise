//! Cancelling while the per-file analysis is in progress stops it at the next file boundary.
//!
//! Deterministic (no sleeps, no timing): the analyzer wrapper flips the cancellation flag from inside
//! the Nth file's analysis, so the cancel always arrives with the loop provably mid-way, and the
//! number of analyzed files shows exactly where it stopped.

use std::cell::Cell;
use std::path::PathBuf;

use serde_json::Value;
use tracewise_js::jsgraph::app_graph::analysis::{FileAnalyzer, JsFileResult};
use tracewise_js::jsgraph::app_graph::model::ArtifactFile;
use tracewise_js::jsgraph::app_graph::reconstruct::reconstruct_application;
use tracewise_js::jsgraph::control::Cancel;
use tracewise_js::jsgraph::error::AnalysisFailure;
use tracewise_js::jsgraph::pipeline::NativeAnalyzer;
use tracewise_js::jsgraph::semantic_graph::SemanticGraphProjection;

const FILES: usize = 40;

struct Counting<'a> {
    inner: NativeAnalyzer,
    analyzed: Cell<usize>,
    cancel_at: Option<usize>,
    cancel: &'a Cancel,
}

impl FileAnalyzer for Counting<'_> {
    fn analyze_javascript(&self, file: &ArtifactFile, source: &str) -> Result<JsFileResult, AnalysisFailure> {
        let result = self.inner.analyze_javascript(file, source);
        self.analyzed.set(self.analyzed.get() + 1);
        if Some(self.analyzed.get()) == self.cancel_at {
            self.cancel.cancel();
        }
        result
    }

    fn source_map_reference(&self, source_name: &str, source_root: Option<&str>, map_path: &str) -> Value {
        self.inner.source_map_reference(source_name, source_root, map_path)
    }
}

fn app() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("jsgraph-cancel-midway-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("package.json"), r#"{"name":"midway","main":"index.js"}"#).unwrap();
    let mut index = String::new();
    for n in 0..FILES {
        std::fs::write(
            dir.join(format!("src/m{n}.js")),
            format!("exports.f = (a, b) => [a + b + {n}, {{ k: {n} }}].map((x) => x && x.k);\n"),
        )
        .unwrap();
        index.push_str(&format!("require('./src/m{n}.js');\n"));
    }
    std::fs::write(dir.join("index.js"), index).unwrap();
    dir
}

fn run(dir: &std::path::Path, cancel_at: Option<usize>) -> (Result<Value, AnalysisFailure>, usize) {
    let cancel = Cancel::new();
    let analyzer = Counting { inner: NativeAnalyzer, analyzed: Cell::new(0), cancel_at, cancel: &cancel };
    let result = reconstruct_application(
        dir.to_str().unwrap(),
        "directory",
        "fail",
        &analyzer,
        Box::new(SemanticGraphProjection::new()),
        &cancel,
    );
    (result, analyzer.analyzed.get())
}

#[test]
fn cancel_during_the_file_loop_stops_at_the_next_file() {
    let dir = app();

    let (full, total) = run(&dir, None);
    assert!(full.is_ok(), "the uncancelled run completes");
    assert_eq!(total, FILES + 1, "every JavaScript file is analyzed when nothing cancels");

    let at = 7;
    let (cancelled, analyzed) = run(&dir, Some(at));
    let error = cancelled.expect_err("a cancelled run returns an error");
    assert!(
        error.to_string().contains("Cancelled"),
        "the failure is the cancellation: {error}"
    );
    assert_eq!(analyzed, at, "no file is analyzed after the cancel arrived mid-loop");
    assert!(analyzed < total);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Cancels just before delegating, so the flag is already set when the file's own passes start.
struct CancelsInsideFile<'a> {
    inner: NativeAnalyzer,
    cancel: &'a Cancel,
    returned: Cell<bool>,
}

impl FileAnalyzer for CancelsInsideFile<'_> {
    fn analyze_javascript(&self, file: &ArtifactFile, source: &str) -> Result<JsFileResult, AnalysisFailure> {
        self.cancel.cancel();
        let result = self.inner.analyze_javascript(file, source);
        self.returned.set(true);
        result
    }

    fn source_map_reference(&self, source_name: &str, source_root: Option<&str>, map_path: &str) -> Value {
        self.inner.source_map_reference(source_name, source_root, map_path)
    }
}

#[test]
fn cancel_inside_a_single_large_file_abandons_that_file() {
    let dir = std::env::temp_dir().join(format!("jsgraph-cancel-inside-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("package.json"), r#"{"name":"inside","main":"big.js"}"#).unwrap();
    let mut source = String::new();
    for n in 0..4_000 {
        source.push_str(&format!("function f{n}(a, b) {{ return [a + b + {n}, {{ k: {n} }}].map((x) => x && x.k); }}\n"));
    }
    std::fs::write(dir.join("big.js"), source).unwrap();

    let cancel = Cancel::new();
    let analyzer = CancelsInsideFile { inner: NativeAnalyzer, cancel: &cancel, returned: Cell::new(false) };
    let result = reconstruct_application(
        dir.to_str().unwrap(),
        "directory",
        "fail",
        &analyzer,
        Box::new(SemanticGraphProjection::new()),
        &cancel,
    );
    let error = result.expect_err("a cancelled run returns an error");
    assert!(error.to_string().contains("Cancelled"), "the failure is the cancellation: {error}");
    assert!(
        !analyzer.returned.get(),
        "the file's analysis must be abandoned at a node checkpoint, not run to completion"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
