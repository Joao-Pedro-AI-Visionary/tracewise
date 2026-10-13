//! Live parity with the ORIGINAL REA MCP server for the artifact inventory that feeds the
//! JavaScript application graph, on source-map layouts.
//!
//! REA parents a `.map` edge under the bundle it maps (the sibling path minus `.map`) and falls
//! back to the directory that contains the map when no such bundle was observed. Applications:
//! the REA-derived `fixtures/jsgraph/rea/versions/version-{1,2}` trees (their maps live in
//! `renderer/`, their bundles under `renderer/chunks/`) and generated minimal trees for each
//! shape of the pairing rule. The whole MCP result is compared (`structuredContent` and the text
//! item), with only host paths and the ids derived from them normalized (see `jsgraph_support`).
//!
//! The oracle is `node <REA_SRC>/scripts/rea.mjs mcp`; `TRACEWISE_REQUIRE_ORACLE=1` turns a
//! missing one into a failure.

mod jsgraph_support;

use jsgraph_support::{ours, oracle_available, rea_normalized, repo_root, Counter, Rea};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use tracewise_server::session::BinarySession;

/// A scratch application tree removed on drop.
struct Tree(PathBuf);

impl Tree {
    fn new(name: &str, files: &[(&str, &str)]) -> Self {
        let root = std::env::temp_dir().join(format!("tracewise-inv-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (path, text) in files {
            let target = root.join(path);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::write(target, text).unwrap();
        }
        Tree(root)
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const MAP: &str = r#"{"version":3,"file":"a.js","sources":["a.ts"],"sourcesContent":["export const a = 1;"],"names":[],"mappings":"AAAA"}"#;
const BUNDLE: &str = "export const a = 1;\n//# sourceMappingURL=a.js.map\n";

fn trees() -> Vec<Tree> {
    vec![
        // The reported case: the map sits in a subdirectory, its bundle at the root.
        Tree::new("map-in-subdir", &[("a.js", BUNDLE), ("sub/a.js.map", MAP)]),
        // Control: bundle and map side by side.
        Tree::new("map-beside-bundle", &[("dist/app.js", BUNDLE), ("dist/app.js.map", MAP)]),
        // A map at the root with no bundle at all falls back to the root.
        Tree::new("orphan-root-map", &[("lonely.js.map", MAP), ("main.js", "module.exports = 1;\n")]),
        // A map inside a directory whose bundle is missing falls back to that directory.
        Tree::new("orphan-nested-map", &[("main.js", "module.exports = 1;\n"), ("sub/deep/b.js.map", MAP)]),
        // `.map` is cut once, not repeatedly: `a.js.map.map` maps `a.js.map`.
        Tree::new("map-of-map", &[("a.js", BUNDLE), ("a.js.map", MAP), ("a.js.map.map", MAP)]),
        // The suffix test is case-insensitive and the cut is exactly four characters.
        Tree::new("upper-case-map", &[("UP.JS", BUNDLE), ("UP.JS.MAP", MAP)]),
    ]
}

fn versions() -> Vec<(String, PathBuf)> {
    let base = repo_root().join("fixtures/jsgraph/rea/versions");
    vec![("version-1".into(), base.join("version-1")), ("version-2".into(), base.join("version-2"))]
}

fn analysis_input(path: &Path) -> Value {
    json!({"input_path": path.to_string_lossy(), "format": "directory", "integrity_policy": "fail"})
}

#[tokio::test(flavor = "multi_thread")]
async fn source_map_pairing_matches_rea() {
    if !oracle_available() {
        return;
    }
    let mut rea = Rea::start();
    let session = BinarySession::new();
    let mut counter = Counter { compared: 0, failures: Vec::new() };

    let trees = trees();
    let mut inputs: Vec<(String, PathBuf)> = trees
        .iter()
        .map(|tree| (tree.0.file_name().unwrap().to_string_lossy().into_owned(), tree.0.clone()))
        .collect();
    inputs.extend(versions());
    let mut analyses = Vec::new();

    for (name, path) in &inputs {
        let args = analysis_input(path);
        let want = rea.call("analyze_javascript_application", args.clone());
        let got = ours(&session, "analyze_javascript_application", args).await;
        assert!(want["isError"] != json!(true), "[{name}]: the oracle itself failed: {want}");
        analyses.push((name.clone(), rea_normalized(want.clone())));
        counter.check(&format!("analyze_javascript_application[{name}]"), want, got);
    }

    // The two versions exist to be compared: the comparison embeds both graphs and their ids.
    let find = |name: &str| analyses.iter().find(|(n, _)| n == name).map(|(_, a)| a.clone()).expect("analysis");
    let (left, right) = (find("version-1"), find("version-2"));
    let args = json!({"left": left["structuredContent"], "right": right["structuredContent"]});
    let want = rea.call("compare_application_versions", args.clone());
    let got = ours(&session, "compare_application_versions", args).await;
    counter.check("compare_application_versions[version-1, version-2]", want, got);

    eprintln!("compared {} MCP results over {} applications", counter.compared, inputs.len());
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
