//! Parity of the derived semantic collectors (`jsgraph::semantic::derived`) with REA: for every
//! corpus file the 17 derived keys of the Rust `analyze_semantics` output must equal the oracle's
//! semantic IR **exactly** (same ids, array order, resolutions, limitations).
//!
//! Corpus: see `tests/support/mod.rs` (`TRACEWISE_JSGRAPH_STRIDE`, `TRACEWISE_JSGRAPH_CORPUS`)
//! plus inline snippets and `fixtures/jsgraph/semantic/snippets.json` (sources lifted from REA's own
//! unit tests, evaluated by the oracle).
//!
//! `TRACEWISE_DERIVED_KEYS=callSites,frontiers` restricts the comparison to a subset of the keys
//! (development aid; unset compares all 17).

mod support;
#[path = "support/derived_scenarios.rs"]
mod derived_scenarios;

use serde_json::Value;
use support::{corpus, diff, oracle_available, repo_root, stream_oracle, Report};
use tracewise_js::jsgraph::ast::{parse_babel, ParseOptions};
use tracewise_js::jsgraph::semantic::analyze_semantics;

const DERIVED_FIELDS: &[&str] = &[
    "argumentFlows",
    "callResultFlows",
    "callReturnFlows",
    "callSites",
    "boundaryOperations",
    "childProcessInteractions",
    "childProcessSpawns",
    "closureCaptures",
    "configurationOperations",
    "eventOperations",
    "frontiers",
    "functionFingerprints",
    "objectOperations",
    "promiseOperations",
    "requestOperations",
    "resourceOperations",
    "timerOperations",
];

fn selected_fields() -> Vec<&'static str> {
    match std::env::var("TRACEWISE_DERIVED_KEYS") {
        Ok(list) if !list.trim().is_empty() => {
            let wanted: Vec<String> = list.split(',').map(|s| s.trim().to_string()).collect();
            DERIVED_FIELDS.iter().copied().filter(|f| wanted.iter().any(|w| w == f)).collect()
        }
        _ => DERIVED_FIELDS.to_vec(),
    }
}

fn pick(ir: &Value, fields: &[&str]) -> Value {
    let mut out = serde_json::Map::new();
    for field in fields {
        out.insert((*field).to_string(), ir.get(*field).cloned().unwrap_or(Value::Null));
    }
    Value::Object(out)
}

/// Inline scenarios; the oracle provides the expected output for each.
fn snippets() -> Vec<(&'static str, &'static str)> {
    vec![
        ("der_calls.js", "function f(a, b) { return a + b; } const g = f; const r = g(1, 2); const { x, y: [z] } = f(1, 2); new f(3); f(...[1, 2], 3); (cond ? f : g)(1); eval('x'); with (o) { p; } o[k](); obj[dyn] = 1; ({ [dyn2]: 1 }); function outer() { const c = 1; return () => c + r; }\n"),
        ("der_promises.js", "async function a() { const p = new Promise((res, rej) => res(1)); await p; Promise.resolve(2).then(x => x).catch(e => e).finally(() => 1); const all = Promise.all([p, Promise.reject(1)]); Promise.allSettled([p]); return p; } async function b() { return await a(); } const d = a(); a().then(() => {}); const e = Promise.race([a()]);\n"),
        ("der_async.js", "import { EventEmitter } from 'node:events'; const em = new EventEmitter(); function h() {} em.on('x', h); em.once('y', () => 1); em.off('x', h); em.emit('x', 1); em.addListener('z', h); em.removeAllListeners('x'); const t = setTimeout(h, 100); clearTimeout(t); const i = setInterval(() => 1, 5); clearInterval(i); setImmediate(h); document.addEventListener('click', h); window.removeEventListener('click', h);\n"),
        ("der_child.js", "const cp = require('node:child_process'); const { spawn, exec } = require('child_process'); const p = spawn('ls', ['-l'], { env: process.env, stdio: 'inherit' }); p.on('exit', () => 1); p.kill('SIGTERM'); const q = cp.execSync('echo hi'); cp.fork('./w.js'); const [a, b] = [1, 2]; exec('ls', (e, out) => out); p.stdout.on('data', d => d); const { stdout } = cp.spawnSync('ls');\n"),
        ("der_data.js", "const port = process.env.PORT || 3000; const { HOME, USER = 'x' } = process.env; const argv = process.argv.slice(2); const fs = require('fs'); const cfg = JSON.parse(fs.readFileSync('config.json', 'utf8')); fetch('https://api.example.com/x', { method: 'POST', body: JSON.stringify({ a: port }) }).then(r => r.json()); const n = Number(port); const s = String(n); z.parse(cfg); const u = new URL('http://a/b'); const ws = new WebSocket('wss://x/y'); const xhr = new XMLHttpRequest(); xhr.open('GET', '/api'); xhr.send(); axios.get('/u', { params: { q: 1 } });\n"),
        ("der_resources.js", "const fs = require('fs'); const fd = fs.openSync('a', 'r'); fs.closeSync(fd); const s = fs.createReadStream('a'); s.close(); s.destroy(); const w = fs.createWriteStream('b'); w.end(); const srv = require('http').createServer(); srv.listen(80); srv.close(); const db = new Database(); db.close(); fs.promises.open('x').then(h => h.close());\n"),
        ("der_objects.js", "const o = { a: 1, b: { c: 2 } }; const { a, b: { c }, ...rest } = o; const copy = { ...o, d: 4 }; o.a = 5; o.b.c = 6; const v = o.b.c; const k = o['a']; const arr = [1, 2]; const [h, ...t] = arr; Object.assign(o, copy); function f({ p, q = 1 }, [r]) { return p + q + r; } o[dyn] = 1; delete o.a; this.x = 1;\n"),
        ("der_fingerprint.ts", "export async function load(id: string): Promise<number> { const r = await fetch('/x/' + id); if (!r.ok) { throw new Error('bad'); } for (const k of [1, 2]) { setTimeout(() => k, 10); } try { return (await r.json()).n; } catch (e) { return 0; } finally { console.log('done'); } } class K { m() { return 1; } static s = 1; } const arrow = () => ({ a: 1 }); function* gen() { yield 1; }\n"),
    ]
}

fn scenario_fixtures() -> Vec<(String, String)> {
    let path = repo_root().join("fixtures/jsgraph/semantic/snippets.json");
    let text = std::fs::read_to_string(&path).expect("fixtures/jsgraph/semantic/snippets.json");
    let entries: Vec<Value> = serde_json::from_str(&text).expect("snippets.json");
    entries
        .iter()
        .map(|entry| (entry["name"].as_str().unwrap().to_string(), entry["source"].as_str().unwrap().to_string()))
        .collect()
}

/// `await (x)` at the top level of a non-ESM file is a call of the identifier `await` in Babel;
/// the Rust AST layer cannot reproduce that (known AST-layer gap, see `jsgraph_semantic_test.rs`).
fn ambiguous_top_level_await(source: &str) -> bool {
    source.trim_start().starts_with("await (") && !source.contains("import ") && !source.contains("export ")
}

#[test]
fn semantic_derived_matches_rea() {
    if !oracle_available() {
        return;
    }
    let fields = selected_fields();
    let fixtures = scenario_fixtures();
    let mut all: Vec<(&str, &str)> = snippets();
    all.extend_from_slice(derived_scenarios::SCENARIOS);
    all.extend(fixtures.iter().map(|(name, text)| (name.as_str(), text.as_str())));
    let corpus = corpus(&all);
    let mut report = Report::default();
    let mut checked = 0usize;
    let mut skipped_ast = 0usize;
    let mut oracle_lines = 0usize;
    // Entries the oracle reports per key: a key that is empty everywhere would make the comparison vacuous.
    let mut entries: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    let mut oracle_not_ok = 0usize;
    let answered = stream_oracle("layers.mjs", &corpus.files, |line| {
        oracle_lines += 1;
        let path = line["path"].as_str().unwrap().to_string();
        if line["ok"] != Value::Bool(true) {
            oracle_not_ok += 1;
            return;
        }
        let text = std::fs::read_to_string(&path).expect("read source");
        if ambiguous_top_level_await(&text) {
            skipped_ast += 1;
            return;
        }
        let expected_partial = line["ir"]["limitations"][0]
            .as_str()
            .is_some_and(|limitation| limitation.starts_with("The parser recovered from syntax errors"));
        let mut ast = match parse_babel(&text, &ParseOptions { path: Some(&path) }) {
            Ok(ast) => ast,
            Err(error) => {
                if expected_partial {
                    skipped_ast += 1;
                } else {
                    report.record(&path, &[format!("Rust parse failed where Babel succeeded: {error:?}")]);
                }
                return;
            }
        };
        if expected_partial && ast.error_count == 0 {
            ast.error_count = 1;
        }
        let expected = pick(&line["ir"], &fields);
        let actual_ir = serde_json::to_value(analyze_semantics(&ast)).expect("serialize ir");
        let actual = pick(&actual_ir, &fields);
        let diffs: Vec<String> = diff(&expected, &actual, 6).into_iter().map(|d| format!("ir {d}")).collect();
        for field in &fields {
            *entries.entry(*field).or_default() += expected[*field].as_array().map_or(0, Vec::len);
        }
        checked += 1;
        report.record(&path, &diffs);
    });
    assert!(checked > 0, "oracle produced no analyzable file");
    eprintln!(
        "derived parity: corpus {} files, oracle lines {oracle_lines} ({oracle_not_ok} unparseable for REA), {checked} compared, \
         {skipped_ast} skipped for AST-layer gaps, keys {fields:?}",
        corpus.files.len()
    );
    eprintln!("expected entries per derived key: {entries:?}");
    for field in &fields {
        assert!(entries.get(field).copied().unwrap_or(0) > 0, "no corpus file exercises {field}: the comparison would be vacuous");
    }
    assert_eq!(oracle_lines, corpus.files.len(), "every corpus file must be answered by the oracle");
    assert_eq!(answered, corpus.files.len());
    report.finish("semantic derived");
}
