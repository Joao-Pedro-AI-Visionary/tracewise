//! The Rust layer types (`jsgraph::static_types`, `jsgraph::ir`) must round-trip REA's JSON for
//! the static analysis and the semantic IR exactly: deserialize the oracle output, serialize it
//! again, and compare with the original.

mod support;

use serde_json::Value;
use support::{corpus, diff, oracle_available, stream_oracle, Report};
use tracewise_js::jsgraph::ir::SemanticIr;
use tracewise_js::jsgraph::static_types::StaticAnalysis;

#[test]
fn layer_types_round_trip_rea_json() {
    if !oracle_available() {
        return;
    }
    let corpus = corpus(&[
        ("a.js", "const fs = require('node:fs'); module.exports = { read: (p) => fs.readFileSync(p, 'utf8') };\n"),
        ("b.ts", "export async function f(x: number): Promise<number> { return await Promise.resolve(x + 1); }\n"),
    ]);
    let mut report = Report::default();
    stream_oracle("layers.mjs", &corpus.files, |line| {
        let path = line["path"].as_str().unwrap().to_string();
        if line["ok"] != Value::Bool(true) {
            return;
        }
        let mut diffs = Vec::new();
        let static_value = &line["static"];
        match serde_json::from_value::<StaticAnalysis>(static_value.clone()) {
            Ok(parsed) => diffs.extend(
                diff(static_value, &serde_json::to_value(&parsed).unwrap(), 5)
                    .into_iter()
                    .map(|d| format!("static {d}")),
            ),
            Err(error) => diffs.push(format!("static does not deserialize: {error}")),
        }
        let ir_value = &line["ir"];
        match serde_json::from_value::<SemanticIr>(ir_value.clone()) {
            Ok(parsed) => diffs.extend(
                diff(ir_value, &serde_json::to_value(&parsed).unwrap(), 5)
                    .into_iter()
                    .map(|d| format!("ir {d}")),
            ),
            Err(error) => diffs.push(format!("ir does not deserialize: {error}")),
        }
        report.record(&path, &diffs);
    });
    report.finish("layer types");
}
