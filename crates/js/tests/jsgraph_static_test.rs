//! The Rust AST-only static analysis must equal REA's `analyzeParsedJavaScriptStaticSource`
//! exactly (same keys, same order inside arrays, same values) on every corpus file.
//!
//! Oracle: `fixtures/jsgraph/oracle/static_layer.mjs` (the compiled REA, live). The two maps the
//! semantic layer feeds into the static layer (`openReceivers`, `electronBindings`) are taken from
//! the oracle line, so this test does not depend on the semantic port.
//!
//! Corpus: the shared one (`support::corpus`) plus the inline scenarios in `snippets/` (derived from
//! the REA unit tests of this layer and combinatorial sweeps). Snippets named `astgap_*` hold
//! inputs where Babel *recovers* from a syntax error that `jsgraph::ast::parse_babel` rejects or
//! does not count (AST track); for those the static findings must still be identical and only the
//! parser-derived fields may differ (see `snippets/gaps.rs`).

mod support;

use std::collections::HashMap;

use serde_json::Value;
use support::{corpus, diff, oracle_available, stream_oracle, Report};
use tracewise_js::jsgraph::ast::{parse_babel, ParseOptions};
use tracewise_js::jsgraph::static_analysis::analyze_static_source;
use tracewise_js::jsgraph::static_types::{OpenReceiverFact, StaticAnalysis};

mod snippets;

/// The fields derived from the parser's recovered-error count.
const PARSER_DERIVED: &[&str] = &["$.parse_status", "$.parse_error_count", "$.limitations"];

fn maps(line: &Value) -> (HashMap<u32, OpenReceiverFact>, HashMap<u32, String>) {
    let mut open_receivers = HashMap::new();
    for entry in line["openReceivers"].as_array().into_iter().flatten() {
        let offset = entry[0].as_u64().expect("offset") as u32;
        let fact: OpenReceiverFact = serde_json::from_value(entry[1].clone()).expect("fact");
        open_receivers.insert(offset, fact);
    }
    let mut electron_bindings = HashMap::new();
    for entry in line["electronBindings"].as_array().into_iter().flatten() {
        electron_bindings.insert(
            entry[0].as_u64().expect("offset") as u32,
            entry[1].as_str().expect("export").to_string(),
        );
    }
    (open_receivers, electron_bindings)
}

fn is_parser_derived(difference: &str) -> bool {
    PARSER_DERIVED.iter().any(|field| difference.starts_with(field))
}

fn run() {
    let owned = snippets::all();
    let borrowed: Vec<(&str, &str)> = owned.iter().map(|(n, s)| (n.as_str(), s.as_str())).collect();
    if let Ok(dir) = std::env::var("TRACEWISE_SNIPPET_DUMP") {
        // Debug aid: write the inline snippets out so they can be fed to other tools.
        std::fs::create_dir_all(&dir).expect("dump dir");
        for (name, text) in &borrowed {
            std::fs::write(std::path::Path::new(&dir).join(name), text).expect("dump snippet");
        }
    }
    let corpus = corpus(&borrowed);
    eprintln!("corpus: {} files", corpus.files.len());
    let mut report = Report::default();
    let mut known_gaps = 0usize;
    let mut lines_seen = 0usize;
    let mut not_parsed = 0usize;
    let mut last_path = String::new();
    let mut totals: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    stream_oracle("static_layer.mjs", &corpus.files, |line| {
        let path = line["path"].as_str().unwrap().to_string();
        lines_seen += 1;
        last_path = path.clone();
        if line["ok"] != Value::Bool(true) {
            not_parsed += 1;
            return;
        }
        let gap = path.rsplit('/').next().is_some_and(|name| name.starts_with(snippets::gaps::PREFIX));
        let source = std::fs::read_to_string(&path).expect("read corpus file");
        let (open_receivers, electron_bindings) = maps(&line);
        let mine = match parse_babel(&source, &ParseOptions { path: Some(&path) }) {
            Ok(ast) => analyze_static_source(&source, &ast, &open_receivers, &electron_bindings),
            Err(error) if gap => {
                known_gaps += 1;
                eprintln!("known AST-layer gap (Babel recovers, Rust parse fails): {path}: {error:?}");
                return;
            }
            Err(error) => {
                report.record(&path, &[format!("Rust parse failed where Babel parsed: {error:?}")]);
                return;
            }
        };
        let mine: Value = serde_json::to_value::<StaticAnalysis>(mine).expect("serialize");
        // Coverage evidence: how many findings of each kind the oracle reported in total.
        for key in ["references", "endpoints", "storage", "bundler_registrations", "role_paths", "source_map_urls", "vendors"] {
            *totals.entry(key.into()).or_default() += line["static"][key].as_array().map_or(0, Vec::len);
        }
        for key in ["browser_windows", "context_bridge_apis", "ipc", "sender_validations", "utility_processes", "native_addon_bindings"] {
            *totals.entry(format!("electron.{key}")).or_default() += line["static"]["electron"][key].as_array().map_or(0, Vec::len);
        }
        let mut differences = diff(&line["static"], &mine, 8);
        if gap {
            let before = differences.len();
            differences.retain(|difference| !is_parser_derived(difference));
            if before != differences.len() {
                known_gaps += 1;
                eprintln!("known AST-layer gap (parser-derived fields differ): {path}");
            }
        }
        report.record(&path, &differences);
    });
    assert_eq!(lines_seen, corpus.files.len(), "every corpus file must be answered by the oracle");
    eprintln!("oracle lines: {lines_seen} ({not_parsed} unparsed by Babel), last: {last_path}");
    eprintln!("known AST-layer gaps in this run: {known_gaps}");
    eprintln!("oracle findings compared: {totals:?}");
    report.finish("static analysis");
}

#[test]
fn static_analysis_matches_rea() {
    if !oracle_available() {
        return;
    }
    // `parse_babel` (AST track) recurses over expression nesting, so deep inputs (a 12,000-member
    // chain) need more than a test thread's 2 MiB. The static analysis brings its own stack.
    std::thread::Builder::new()
        .name("static-parity".into())
        .stack_size(1 << 30)
        .spawn(run)
        .expect("spawn")
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
