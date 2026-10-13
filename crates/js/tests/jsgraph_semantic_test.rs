//! Parity of the semantic core (`jsgraph::semantic`) with REA: for every corpus file the Rust
//! `analyze_semantics` output must equal REA's semantic IR **exactly** for the fields this layer
//! owns, and the open-receiver / Electron-binding classifier maps must equal the oracle's.
//!
//! The derived collectors (calls, promises, async effects, child processes, data effects,
//! resources, objects, fingerprints) are ported separately; their 17 output fields are listed in
//! [`DERIVED_FIELDS`] and excluded from both sides until they land. Empty that list to compare the
//! full IR.
//!
//! Corpus: see `tests/support/mod.rs` (`TRACEWISE_JSGRAPH_STRIDE`, `TRACEWISE_JSGRAPH_CORPUS`).
//! Extra scenario fixtures live in `fixtures/jsgraph/semantic/` (sources lifted from REA's own
//! unit tests, which the oracle then evaluates).

mod support;

use std::collections::BTreeMap;

use serde_json::Value;
use support::{corpus, diff, oracle_available, repo_root, stream_oracle, Report};
use tracewise_js::jsgraph::ast::{parse_babel, ParseOptions};
use tracewise_js::jsgraph::semantic::{analyze_references, analyze_semantics, classify_electron_bindings, classify_open_receivers};

/// Semantic IR fields produced by the derived collectors (`javascriptSemanticDerivedAnalysis.ts`).
/// They are removed from both sides of the comparison until the derived layer is ported.
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

fn strip_derived(ir: &mut Value) {
    if let Value::Object(map) = ir {
        for field in DERIVED_FIELDS {
            map.remove(*field);
        }
    }
}

/// Inline scenarios; the oracle provides the expected output for each.
fn snippets() -> Vec<(&'static str, &'static str)> {
    vec![
        ("sem_basic.js", "const a = 1; let b = a + 2; var c = `x${b}`; function f(x, y = 2) { return x + y; } export { f };\n"),
        ("sem_require.js", "const { readFile: rf, ...rest } = require('node:fs'); const os = require('os'); module.exports = { rf, os, rest };\n"),
        ("sem_esm.mjs", "import fs, { readFile as rf } from 'node:fs'; import * as ns from 'path'; import './side'; export * from 'a'; export { x as y } from 'b'; export default function g() {}\n"),
        ("sem_destructure.js", "const o = { a: { b: 1 }, c: [1, 2, 3] }; const { a: { b }, c: [first, ...tail] } = o; let z; [z = 5] = []; for (const [k, v] of Object.entries(o)) { console.log(k, v); }\n"),
        ("sem_mutation.js", "const cfg = { mode: 'a', nested: { x: 1 } }; cfg.mode = 'b'; function touch(o) { o.nested.x = 2; } touch(cfg); const copy = { ...cfg }; copy.mode = 'c'; const arr = [1, 2]; arr.push(3); const [h, ...t] = arr; t.push(1);\n"),
        ("sem_open.js", "const w = window; w.open('x'); const x = new XMLHttpRequest(); x.open('GET', '/a'); const idb = indexedDB; idb.open('db'); function f(window) { window.open('y'); } self.open('z'); caches.open('c'); let m = caches; m.open('d');\n"),
        ("sem_electron.js", "const { ipcMain: ipcMain2, app } = require('electron'); const e = require('electron/main'); ipcMain2.on('x', () => {}); new e.BrowserWindow({}); app.quit();\n"),
        ("sem_electron_esm.mjs", "import { ipcMain as ipcMain2, BrowserWindow as BW } from 'electron'; import * as el from 'electron/renderer'; ipcMain2.handle('a', () => 1); new BW({}); el.ipcRenderer.send('b');\n"),
        ("sem_classes.js", "class A { #p = 1; static s = 2; constructor(a) { this.a = a; } get v() { return this.#p; } m() { return () => this.a; } static { let t = 1; } } const B = class extends A { [`k${1}`]() {} }; const o = { m() { return 1; }, get g() { return 2; }, ['c' + 'd']: 3, __proto__: null };\n"),
        ("sem_flow.js", "function f(a, b) { if (a) { return b ? 1 : 2; } return a || 'x'; } function* g() { yield 1; yield* h(); } async function h() { return await 1; } const arrow = (x) => x; const cond = c ? f : arrow; try { f(); } catch ({ message }) { message; }\n"),
        ("sem_templates.ts", "const k: string = 'a'; const t = `${k}-${1 + 2}-${true}`; const n = -0; const u = +'12'; const big = 'x'.repeat(3); enum E { A = 1 } abstract class C { constructor(private x: number, public y = 2) {} } export const v = (k as string) + (1 satisfies number);\n"),
        ("sem_switch.js", "switch (x) { case 1: let a = 1; break; case 2: let b = a; } label: for (var i = 0; i < 3; i++) { if (i) continue label; } do { var d = 1; } while (0); var v = 1; v += 2; v++; let l = 1; { let l = 2; } l = l || 3;\n"),
        // `with` is a recoverable strict-mode error for Babel (parser-partial); see AstLayerGaps.
        ("sem_with.js", "var o = { a: 1 }; with (o) { var q = a; function inner() { return q; } } var after = q; function g() { with (o) { return b; } }\n"),
        ("sem_computed_keys.js", "const k = 'm'; const o = { [k]() { return k; }, get [k + '2']() { return 1; } }; class C { [k](a = k) { return a; } static [`s${k}`] = 1; } function f(a = () => b, b = 2) { var a; return a(); }\n"),
        ("sem_named_fn.js", "const f = function g(g2) { return g; }; const h = function h() { return h; }; var r = (function fact(n) { return n ? n * fact(n - 1) : 1; })(5); function same(same) { return same; }\n"),
        ("sem_params.ts", "function a(x, { y, z = 3 } = {}, [p, q] = [1, 2], ...rest) { var x; let w = x; return [x, y, z, p, q, rest, w]; } const arrow = (m = 1, n = m) => { var m; return n; }; class K { constructor(public a = 1, private readonly b = a) { this.a = b; } }\n"),
        ("sem_iteration.js", "const src = [{ v: 1 }, { v: 2 }]; for (const item of src) { item.v = 3; } const [a, ...others] = src; others[0].v = 4; const { ...copy } = src[0]; copy.v = 5; function* gen() { yield* src; } for (const x of gen()) { x.v = 6; } call(...src); [...src].forEach((e) => { e.v = 7; });\n"),
        ("sem_escape.js", "const shared = { mode: 'a', inner: { n: 1 } }; function mutate(o) { o.mode = 'b'; } mutate(shared); other(shared.inner); const holder = { shared }; holder.shared.inner.n = 2; const copy = Object.assign({}, shared); const fns = { f() { return shared; } }; fns.f().mode = 'c'; new Thing(shared); tag`${shared}`; shared.method();\n"),
        ("sem_prototype.js", "const base = [1, 2]; Array.prototype.push = function () {}; const list = ['a']; for (const v of list) { v; } globalThis.Array.prototype[Symbol.iterator] = null; const [z] = ['q'];\n"),
        ("sem_commonjs.js", "exports.a = 1; module.exports.b = function () {}; module.exports = { c: require('x').y.z }; exports[dyn] = 3; module.exports[''] = 4; exports[''] = 5; const m = require('m'); const { n: { o } } = require('n'); const [p0] = require('p');\n"),
        ("sem_aliases.js", "var a = 1; var b = a; var c = b; a = c; let u; u = 'x'; u += 'y'; const t = cond ? 'a' : 'b'; const v = cond && 'c'; const w = !0; const neg = -1; const add = 'a' + 1 + 2n; const num = 1 + 2; const str = '1' + 2; const tpl = `${t}${v}`; const obj = { t, v, ...rest }; const arr = [t, , v, ...rest, 5];\n"),
    ]
}

/// Generated stress inputs for the resource limits and deep nesting.
fn generated_snippets() -> Vec<(String, String)> {
    let mut out = Vec::new();
    // primitive-candidates: 20 alternatives multiplied three times.
    let alts: Vec<String> = (0..20).map(|i| format!("c{i} ? '{i}' : ")).collect();
    let union20 = format!("{}'z'", alts.concat());
    out.push((
        "stress_candidates.js".to_string(),
        format!("const a = {union20}; const b = {union20}; const c = `${{a}}${{b}}`; const d = a + b; const e = `${{c}}${{d}}`;\n"),
    ));
    // primitive-bytes: a doubling string.
    let mut doubling = String::from("let s = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';\n");
    for index in 0..14 {
        doubling.push_str(&format!("const d{index} = {} + {};\n", if index == 0 { "s".to_string() } else { format!("d{}", index - 1) }, if index == 0 { "s".to_string() } else { format!("d{}", index - 1) }));
    }
    out.push(("stress_bytes.js".to_string(), doubling));
    // expression-depth: nested conditionals, nested members, long alias chains.
    let mut nested = String::from("const leaf = 1;\n");
    for index in 0..300 {
        nested.push_str(&format!("const n{index} = c ? {} : 0;\n", if index == 0 { "leaf".to_string() } else { format!("n{}", index - 1) }));
    }
    out.push(("stress_depth_chain.js".to_string(), nested));
    let deep_expr = format!("const x = {}1{};\n", "(".repeat(300), " as any)".repeat(300));
    out.push(("stress_depth_wrappers.ts".to_string(), deep_expr));
    let mut objects = String::from("const o0 = { v: 1 };\n");
    for index in 1..35 {
        objects.push_str(&format!("const o{index} = {{ v: o{} }};\n", index - 1));
    }
    objects.push_str("export const last = o34.v.v.v;\n");
    out.push(("stress_depth_objects.js".to_string(), objects));
    let deep_add = format!("const y = {}1;\n", "1 + ".repeat(2000));
    out.push(("stress_long_addition.js".to_string(), deep_add));
    let deep_ternary = format!("const z = {}1{};\n", "c ? 1 : (".repeat(150), ")".repeat(150));
    out.push(("stress_depth_ternary.js".to_string(), deep_ternary));
    let aliases: String = (0..400).map(|i| format!("var a{} = a{};\n", i + 1, i)).collect::<String>() + "var a0 = 'v';\nfn(a400);\n";
    out.push(("stress_alias_chain.js".to_string(), aliases));
    let many_writes: String = (0..300).map(|i| format!("o.k{i} = {i};\n")).collect::<String>() + "var o = { k0: 'a' }; use(o);\n";
    out.push(("stress_many_writes.js".to_string(), many_writes));
    let spreads: String = (0..60).map(|i| format!("const s{} = {{ ...s{}, p{i}: {i} }};\n", i + 1, i)).collect::<String>() + "const s0 = { a: 1 }; s60.a = 2; use(s0);\n";
    out.push(("stress_spreads.js".to_string(), spreads));
    out.extend(rea_test_generators());
    out
}

/// The programs REA's own unit tests build with `Array.from` / `repeat` (bounded member path
/// propagation, wide escaped receivers, near-budget unions, deep member chains, ...).
fn rea_test_generators() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut add = |name: &str, source: String| out.push((name.to_string(), source));
    let wrap = |body: &str| format!("export function result() {{ {body} }}\n");

    // reference_lifetimes.test.ts
    let branches = (0..16).map(|i| format!("if (flag === {i}) node = node.m{i};")).collect::<Vec<_>>().join(" else ");
    add(
        "gen_cyclic_member_paths.js",
        format!("export function result(seed) {{ let node=seed; while(node) {{ {branches} use(node.state); }} return seed.keep; }}\n"),
    );
    add(
        "gen_scalar_member_loop.js",
        wrap(&format!("const source={{child:1,keep:{{value:3}}}}; let node=source.child; while(node) {{ {branches} use(node.state); }} return source.keep.value;")),
    );
    let alias_chain = (0..9)
        .map(|i| format!("const alias{} = {{ left: alias{i}, right: alias{i} }};", i + 1))
        .collect::<Vec<_>>()
        .join("\n");
    let pattern = format!("{}[copy]{}", "{ [key]: ".repeat(9), " }".repeat(9));
    add(
        "gen_dynamic_destructuring.js",
        wrap(&format!("const alias0 = [1]; {alias_chain} const {pattern} = alias9; return alias0[0];")),
    );
    let copies = (0..20)
        .map(|i| format!("const alias{} = flag ? {{...alias{i}, a{i}:{{}}}} : {{...alias{i}, b{i}:{{}}}};", i + 1))
        .collect::<Vec<_>>()
        .join("\n");
    add(
        "gen_conditional_copies.js",
        wrap(&format!("const alias0 = {{ value: {{ token: 1 }} }}; {copies} consume(alias20); return alias0.value.token;")),
    );

    // member_mutations.test.ts
    let aliases = (0..24)
        .map(|i| format!("let alias{} = alias{i}; alias{} = alias{i};", i + 1, i + 1))
        .collect::<Vec<_>>()
        .join("\n");
    add("gen_repeated_alias_branches.js", wrap(&format!("let alias0 = {{ value: 1 }}; {aliases} mutate(alias24); return alias0.value;")));
    let writes = (0..2000).map(|i| format!("source.p{i} = {i};")).collect::<Vec<_>>().join(" ");
    add("gen_many_property_writes.js", wrap(&format!("const source = {{ token: \"TOKEN\" }}; {writes} return [source.token, source.p1999];")));
    let methods = (0..2000).map(|i| format!("m{i}() {{ return shared; }}")).collect::<Vec<_>>().join(",");
    let method_writes = (0..2000).map(|i| format!("box.m{i}().p{i} = {i};")).collect::<Vec<_>>().join(" ");
    add(
        "gen_wide_receiver.js",
        wrap(&format!("const shared = {{ token: \"TOKEN\" }}; const box = {{ {methods} }}; {method_writes} return shared.token;")),
    );

    // member_depth.test.ts
    let chain = ".next".repeat(12_000);
    add(
        "gen_member_chain_12000.js",
        format!("const value = require(\"./addon.node\"){chain}.last; const ordinary = root.next.last;\n"),
    );
    let ordinary = ".next".repeat(64);
    add(
        "gen_member_chain_reexport.js",
        format!("module.exports.result = require(\"./dependency.js\"){ordinary}.last;\nconst dynamic = require(\"./other.js\"){ordinary}[key].last;\n"),
    );
    add(
        "gen_deep_mutation.js",
        format!("const root = {{ untouched: \"retained\" }};\nroot{ordinary}.last = 1;\nconst value = root.untouched;\n"),
    );

    // unions.test.ts
    let term = "(choice ? \"a\" : \"b\")";
    let product = vec![term; 20].join(" + ");
    add("gen_candidate_budget.js", format!("const answer = {product};\n"));
    let part = "x".repeat(32_768);
    add("gen_large_string.js", format!("const left = \"{part}\"; const right = \"{part}\"; const answer = left + right;\n"));
    let (left, right) = ("l".repeat(85), "r".repeat(85));
    let cartesian = (0..7)
        .map(|_| format!("(\"{left}\" + (choice ? \"{left}\" : \"{right}\"))"))
        .collect::<Vec<_>>()
        .join(" + ");
    add("gen_near_budget_union.js", format!("const answer = {cartesian};\n"));

    // scope_depth.test.ts and rejection.test.ts
    for depth in [160usize, 600] {
        add(
            &format!("gen_scope_depth_{depth}.js"),
            format!("const a=1; module.exports.value={}a{};\n", "a+(".repeat(depth), ")".repeat(depth)),
        );
    }
    let names = (0..280).map(|i| format!("key{i}: {i}")).collect::<Vec<_>>().join(", ");
    add(
        "gen_wide_object.js",
        format!("const first = require(\"first\"); const second = require(\"second\"); first; second; const object = {{ {names} }};\n"),
    );
    add(
        "gen_nested_object_40.js",
        format!("const nested = {}\"value\"{};\n", "{ next: ".repeat(40), " }".repeat(40)),
    );
    out
}

/// Snippets lifted from REA's own unit tests by `scripts/gen_jsgraph_semantic_snippets.mjs`.
fn scenario_fixtures() -> Vec<(String, String)> {
    let path = repo_root().join("fixtures/jsgraph/semantic/snippets.json");
    let text = std::fs::read_to_string(&path).expect("fixtures/jsgraph/semantic/snippets.json");
    let entries: Vec<Value> = serde_json::from_str(&text).expect("snippets.json");
    entries
        .iter()
        .map(|entry| (entry["name"].as_str().unwrap().to_string(), entry["source"].as_str().unwrap().to_string()))
        .collect()
}

/// Counters for the differences that belong to the AST layer (`jsgraph/ast`), not to the semantic
/// core, so they stay visible instead of being silently skipped.
#[derive(Default, Debug)]
struct AstLayerGaps {
    /// Babel recovered from syntax errors (`file.errors.length > 0`) but the Rust AST reports none:
    /// the analysis is re-run with the parser-partial flag the oracle shows.
    recovered_errors_not_counted: usize,
    /// Babel's error recovery produced a tree where oxc has none (argument holes, missing
    /// initializers, missing semicolons, ...): there is no Rust AST to analyze.
    unparseable_after_recovery: usize,
    /// `await (...)` at the top level of an ambiguous file is a call of an identifier in Babel.
    ambiguous_top_level_await: usize,
}

/// Upper bound for [`AstLayerGaps::unparseable_after_recovery`] on the default corpus; a rise
/// means the AST layer regressed.
const UNPARSEABLE_AFTER_RECOVERY_LIMIT: usize = 24;

/// Sources whose Babel tree cannot be reproduced by the Rust AST: `await (x)` is a call of the
/// identifier `await` when the file has no ESM syntax.
fn ambiguous_top_level_await(source: &str) -> bool {
    source.trim_start().starts_with("await (") && !source.contains("import ") && !source.contains("export ")
}

#[test]
fn semantic_core_matches_rea() {
    // Deep generated inputs recurse in the AST converter: run on a thread with a large stack.
    std::thread::Builder::new()
        .stack_size(512 * 1024 * 1024)
        .spawn(semantic_core_matches_rea_inner)
        .expect("spawn")
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

fn semantic_core_matches_rea_inner() {
    if !oracle_available() {
        return;
    }
    let fixtures = scenario_fixtures();
    let generated = generated_snippets();
    let mut all: Vec<(&str, &str)> = snippets();
    all.extend(generated.iter().map(|(name, text)| (name.as_str(), text.as_str())));
    all.extend(fixtures.iter().map(|(name, text)| (name.as_str(), text.as_str())));
    let mut corpus = corpus(&all);
    // Explicit files of any size (the corpus collector skips files over 2 MB), for large bundles.
    if let Ok(extra) = std::env::var("TRACEWISE_JSGRAPH_FILES") {
        corpus.files.extend(extra.split(',').filter(|f| !f.is_empty()).map(std::path::PathBuf::from));
    }
    let default_corpus = std::env::var("TRACEWISE_JSGRAPH_CORPUS").is_err()
        && std::env::var("TRACEWISE_JSGRAPH_STRIDE").is_err()
        && std::env::var("TRACEWISE_JSGRAPH_FILES").is_err();
    let mut report = Report::default();
    let mut gaps = AstLayerGaps::default();
    let mut classifier_checked = 0usize;
    let mut oracle_rejected = 0usize;
    let mut limit_counts: BTreeMap<String, usize> = BTreeMap::new();
    stream_oracle("semantic.mjs", &corpus.files, |line| {
        let path = line["path"].as_str().unwrap().to_string();
        if line["ok"] != Value::Bool(true) {
            oracle_rejected += 1;
            eprintln!("REA cannot parse {path}");
            return;
        }
        for limit in line["ir"]["coverage"]["resourceLimits"].as_array().into_iter().flatten() {
            *limit_counts.entry(limit.as_str().unwrap_or("?").to_string()).or_default() += 1;
        }
        let text = std::fs::read_to_string(&path).expect("read source");
        if ambiguous_top_level_await(&text) {
            gaps.ambiguous_top_level_await += 1;
            return;
        }
        let expected_partial = line["ir"]["limitations"][0]
            .as_str()
            .is_some_and(|limitation| limitation.starts_with("The parser recovered from syntax errors"));
        let mut ast = match parse_babel(&text, &ParseOptions { path: Some(&path) }) {
            Ok(ast) => ast,
            Err(error) => {
                if expected_partial {
                    gaps.unparseable_after_recovery += 1;
                } else {
                    report.record(&path, &[format!("Rust parse failed where Babel succeeded: {error:?}")]);
                }
                return;
            }
        };
        if expected_partial && ast.error_count == 0 {
            gaps.recovered_errors_not_counted += 1;
            ast.error_count = 1;
        }
        let mut diffs: Vec<String> = Vec::new();

        let mut expected_ir = line["ir"].clone();
        strip_derived(&mut expected_ir);
        let mut actual_ir = serde_json::to_value(analyze_semantics(&ast)).expect("serialize ir");
        strip_derived(&mut actual_ir);
        diffs.extend(diff(&expected_ir, &actual_ir, 6).into_iter().map(|d| format!("ir {d}")));

        let open: BTreeMap<u32, String> = classify_open_receivers(&ast)
            .into_iter()
            .map(|(offset, fact)| (offset, serde_json::to_value(fact).unwrap().as_str().unwrap().to_string()))
            .collect();
        let expected_open: BTreeMap<u32, String> = line["openReceivers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| (pair[0].as_u64().unwrap() as u32, pair[1].as_str().unwrap().to_string()))
            .collect();
        if open != expected_open {
            diffs.push(format!("openReceivers: expected {expected_open:?} actual {open:?}"));
        }
        let electron: BTreeMap<u32, String> = classify_electron_bindings(&ast).into_iter().collect();
        let expected_electron: BTreeMap<u32, String> = line["electronBindings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| (pair[0].as_u64().unwrap() as u32, pair[1].as_str().unwrap().to_string()))
            .collect();
        if electron != expected_electron {
            diffs.push(format!("electronBindings: expected {expected_electron:?} actual {electron:?}"));
        }
        // `analyzeParsedJavaScriptReferences(file, name)` is the unfiltered reference list
        // restricted to that name.
        if let Some(name) = expected_ir["references"][0]["name"].as_str() {
            let expected_named: Vec<Value> = expected_ir["references"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|reference| reference["name"].as_str() == Some(name))
                .cloned()
                .collect();
            let actual_named = serde_json::to_value(analyze_references(&ast, Some(name))).expect("serialize references");
            diffs.extend(
                diff(&Value::Array(expected_named), &actual_named, 3).into_iter().map(|d| format!("references({name}) {d}")),
            );
        }
        classifier_checked += 1;
        if classifier_checked.is_multiple_of(1000) {
            eprintln!("progress: {classifier_checked} files, now at {path}");
        }
        report.record(&path, &diffs);
    });
    assert!(classifier_checked > 0, "oracle produced no analyzable file");
    eprintln!("analyzed {classifier_checked} files ({oracle_rejected} unparseable for REA itself); resource limits seen: {limit_counts:?}");
    eprintln!("AST-layer gaps (kept visible, not skipped silently): {gaps:?}");
    assert!(
        !default_corpus || gaps.unparseable_after_recovery <= UNPARSEABLE_AFTER_RECOVERY_LIMIT,
        "Rust AST fails on more Babel-recoverable sources than before: {gaps:?}"
    );
    report.finish("semantic core");
}
