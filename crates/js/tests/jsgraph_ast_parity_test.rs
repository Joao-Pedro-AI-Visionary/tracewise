//! The Babel-shaped tree built from oxc must equal what REA's `@babel/parser` (8.0.4, REA plugin
//! set) produces, node for node.
//!
//! Oracle: `fixtures/jsgraph/oracle/babel_ast.mjs` runs REA's own `parseJavaScriptSource` from
//! the compiled REA checkout (`REA_SRC`, default `/workspace/rea-map/src`) on every file.
//!
//! Compared per node: `type`, `start`, `end` (UTF-16 offsets) and every field Babel reports.
//! Ignored on both sides: `loc`/`range`/`extra`/comment attachments (REA reads none of them;
//! raw text lives in `x_*` fields here). A field Babel omits or reports as its default
//! (`null`, `false`, `[]`, `"value"` import kinds) may be absent here, and vice versa.
//!
//! Corpus: inline syntax snippets, every JS/TS file under `fixtures/` (that includes the real
//! `.d.ts`/`.d.mts`/`.d.cts` files in `fixtures/jsgraph/dts/` and `npm/commander-14.0.3/typings/`
//! and the ambient-context cases in `fixtures/jsgraph/own/ambient-cases/`) and under the REA test
//! fixtures. Set `TRACEWISE_AST_CORPUS=dir1,dir2` to sweep more (for example the REA sources or
//! every `.d.ts` of `node_modules`). `TRACEWISE_AST_SHOW=all` lists every differing file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use tracewise_js::jsgraph::ast::{ast_to_json, parse_babel, ConvertError, ParseOptions};

fn rea_src() -> PathBuf {
    PathBuf::from(std::env::var("REA_SRC").unwrap_or_else(|_| "/workspace/rea-map/src".into()))
}

fn require_oracle() -> bool {
    let src = rea_src();
    if src.join("dist/domain/javascript/javascriptSourceParser.js").exists() {
        return true;
    }
    if std::env::var("TRACEWISE_REQUIRE_ORACLE").as_deref() == Ok("1") {
        panic!("REA checkout not found at {} (set REA_SRC)", src.display());
    }
    eprintln!("skipping: REA checkout not found at {}", src.display());
    false
}

fn is_source(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" | "mts" | "cts")
    )
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(|e| e.path());
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        if name == "node_modules" || name == "target" || name == ".git" {
            continue;
        }
        if path.is_dir() {
            collect(&path, out);
        } else if is_source(&path) {
            if let Ok(meta) = path.metadata() {
                if meta.len() < 3_000_000 {
                    out.push(path);
                }
            }
        }
    }
}

fn is_default(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(false) => true,
        Value::Array(items) => items.is_empty(),
        Value::String(text) => text == "value",
        _ => false,
    }
}

const IGNORED: &[&str] = &[
    "type", "start", "end", "loc", "range", "extra", "leadingComments", "trailingComments",
    "innerComments", "comments", "tokens", "errors",
];

fn compare(path: &str, babel: &Value, mine: &Value, diffs: &mut Vec<String>) {
    if diffs.len() > 4000 {
        return;
    }
    match (babel, mine) {
        (Value::Object(b), Value::Object(m)) => {
            if b.get("type") != m.get("type") {
                diffs.push(format!("{path}: type {:?} vs {:?}", b.get("type"), m.get("type")));
                return;
            }
            let ty = b.get("type").and_then(|t| t.as_str()).unwrap_or("?");
            for key in ["start", "end"] {
                if b.get(key) != m.get(key) {
                    diffs.push(format!("{path}: {ty}.{key} {:?} vs {:?}", b.get(key), m.get(key)));
                }
            }
            for (key, value) in b {
                if IGNORED.contains(&key.as_str()) {
                    continue;
                }
                match m.get(key) {
                    Some(other) => compare(&format!("{path}.{key}"), value, other, diffs),
                    None if is_default(value) => {}
                    None => diffs.push(format!("{path}: {ty}.{key} missing (babel {})", brief(value))),
                }
            }
            for (key, value) in m {
                if IGNORED.contains(&key.as_str()) || key.starts_with("x_") || b.contains_key(key) {
                    continue;
                }
                if !is_default(value) {
                    diffs.push(format!("{path}: {ty}.{key} extra (mine {})", brief(value)));
                }
            }
        }
        (Value::Array(b), Value::Array(m)) => {
            if b.len() != m.len() {
                diffs.push(format!("{path}: array length {} vs {}", b.len(), m.len()));
                return;
            }
            for (index, (left, right)) in b.iter().zip(m).enumerate() {
                compare(&format!("{path}[{index}]"), left, right, diffs);
            }
        }
        (left, right) => {
            if left != right && !(is_default(left) && is_default(right)) {
                diffs.push(format!("{path}: {} vs {}", brief(left), brief(right)));
            }
        }
    }
}

fn brief(value: &Value) -> String {
    let text = value.to_string();
    if text.len() > 90 {
        format!("{}...", &text[..90])
    } else {
        text
    }
}

/// Files where the two parsers legitimately disagree about recovering from a broken tail.
/// `bundle092.js` ends in a lone `\`: Babel records a recoverable error, oxc a fatal one.
/// Babel's own `index.d.ts` uses a construct Babel itself rejects.
const KNOWN_PARSER_DISAGREEMENTS: &[&str] = &["Heavy.app/Scripts", "@babel/parser/lib/index.d.ts"];

fn known_disagreement(path: &str) -> bool {
    KNOWN_PARSER_DISAGREEMENTS.iter().any(|part| path.contains(part))
}

const SNIPPETS: &[(&str, &str)] = &[
    ("basic.js", "const a = 1; let b = 'x'; var c = `t${a}u${b}`;\nfunction f(x, y = 2, ...z) { return x + y; }\n"),
    ("arrow.js", "const f = async (a, {b, c: [d]}, ...rest) => a?.b?.[c]?.(d);\nconst g = x => ({x});\nconst h = () => { 'use strict'; };\n"),
    ("esm.mjs", "import d, {a as b, c} from './m.js';\nimport * as ns from 'n';\nimport './side';\nexport {b as e, c};\nexport * from 'x';\nexport * as y from 'y';\nexport default function () {}\nexport const k = 1;\n"),
    ("cjs.js", "#!/usr/bin/env node\n'use strict';\nconst { a, b: { c = 1 } } = require('x');\nmodule.exports = { a, f() {}, get g() { return 1; }, [h]: 2, ...i };\nexports.z = function* () { yield 1; yield* other(); };\n"),
    ("class.js", "class A extends B { #p = 1; static s = 2; static { init(); } constructor(x) { super(x); } get v() { return this.#p; } set v(x) {} static async *m() {} #priv() {} ['computed']() {} }\nconst C = class {};\n"),
    ("control.js", "label: for (let i = 0; i < 3; i++) { if (i) continue label; else break; }\nfor (const k in o) {}\nfor (const [a, b] of arr) {}\nfor await (const x of y) {}\nwhile (x) { do { y(); } while (z); }\nswitch (v) { case 1: a(); break; default: b(); }\ntry { t(); } catch ({message}) { m(); } finally { f(); }\ntry { t(); } catch { m(); }\nwith (o) { p; }\nthrow new Error('x');\n"),
    ("exprs.js", "a = b ? c : d; a ||= 1; a ??= 2; a **= 3; x = a ?? b; y = (1, 2); z = !a && -b || +c; ++i; j--; typeof t; void 0; delete o.p; new Foo; new Foo(1)(2); `a${b}`; tag`x${1}y`; /re+/gi.test(s); 10n; 0x1F; 1_000; .5; 'a\\n';\nimport.meta.url; import('x');\n(a?.b).c; a?.b.c; a?.b(); a.b?.(); a?.[0]?.c.d(1);\n"),
    ("destructure.js", "[a, , b = 2, ...c] = d;\n({ a, b: [c], d = 1, ...e } = f);\nfor ([a, b] of c) {}\nconst [x, [y]] = z;\nfunction g({ a, b } = {}, [c] = []) {}\n"),
    ("jsx.jsx", "const e = <div className=\"a\" {...p} onClick={() => 1}>text {x} <b>bold</b> <></> </div>;\nconst f = <Foo.Bar a:b=\"1\" />;\nconst g = <A>{}</A>;\n"),
    ("types.ts", "interface I<T> extends J { a: string; b?: number; readonly c: T[]; d(x: number): void; [k: string]: any; new (x): I; (y): z }\ntype U = A | B & C | 'lit' | 1 | -1 | `t${string}` | typeof x | keyof T | T[K] | [a: string, b?: number, ...c: boolean[]] | { [K in keyof T]?: T[K] } | (new () => X) | ((a: number) => void) | unique symbol;\nenum E { A, B = 2, 'C' = 3 }\ndeclare const dc: number;\nnamespace N.M { export const z = 1; }\ndeclare module 'm' { export function f(): void; }\nabstract class AC<T> implements I, J<T> { private x: number = 1; protected abstract y(): void; constructor(public a: string, readonly b?: number) { } static #s?: number; declare z: string; }\nfunction over(a: number): void;\nfunction over(a: any) {}\nconst v = <T,>(x: T) => x as unknown as T satisfies T;\nlet nn = a!.b!;\nlet cast = <number>y;\nexport type { U };\nimport type { T1 } from 'x';\nimport tt = require('x');\nexport = foo;\nexport as namespace NS;\nfunction f(this: Window, x?: number, ...rest: string[]): x is number {}\nfunction assertIt(v: unknown): asserts v is string {}\nlet cond: A extends B ? infer C : never;\nlet imp: import('x').Y<Z>;\nlet tup: readonly [x: number];\n"),
    ("decorators.ts", "@dec class D { @prop x = 1; @method() m(@param p) {} }\n"),
    ("script.js", "var a = 1; function f() { return arguments; } eval('x'); a.b.c();\n"),
    ("unicode.js", "const s = '😀é'; /* é */ const t = `😀${s}`; // trailing é\nfoo('日本語');\n"),
    ("crlf.js", "a();\r\nb();\r\n/* x\r\n y */ c();\r"),
];

#[test]
fn babel_shaped_tree_matches_babel() {
    if !require_oracle() {
        return;
    }
    let work = tempfile::tempdir().expect("tempdir");
    let mut files: Vec<PathBuf> = Vec::new();
    for (name, text) in SNIPPETS {
        let path = work.path().join(name);
        std::fs::write(&path, text).expect("write snippet");
        files.push(path);
    }
    let error_cases = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/jsgraph/syntax_errors.txt"),
    )
    .expect("syntax error cases");
    for (index, case) in error_cases.lines().filter(|line| !line.is_empty()).enumerate() {
        for ext in ["js", "ts"] {
            let path = work.path().join(format!("err{index}.{ext}"));
            std::fs::write(&path, case).expect("write error case");
            files.push(path);
        }
    }
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    collect(&repo, &mut files);
    collect(&rea_src().join("tests/fixtures"), &mut files);
    if let Ok(extra) = std::env::var("TRACEWISE_AST_CORPUS") {
        for dir in extra.split(',').filter(|d| !d.is_empty()) {
            collect(Path::new(dir), &mut files);
        }
    }
    let list = work.path().join("files.txt");
    std::fs::write(
        &list,
        files.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join("\n"),
    )
    .unwrap();
    let output = Command::new("node")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/jsgraph/oracle/babel_ast.mjs"))
        .arg(&list)
        .env("REA_SRC", rea_src())
        .output()
        .expect("run node");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(text.lines().count(), files.len(), "the oracle must answer exactly one line per corpus file");

    let mut failures: BTreeMap<String, usize> = BTreeMap::new();
    let mut shown = 0usize;
    // `TRACEWISE_AST_SHOW=all` lists every differing file instead of the first 12.
    let shown_limit = if std::env::var("TRACEWISE_AST_SHOW").as_deref() == Ok("all") { usize::MAX } else { 12 };
    let mut checked = 0usize;
    let mut recovered_honestly = 0usize;
    for line in text.lines() {
        let babel: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(error) => panic!(
                "unreadable oracle line ({error}): {}",
                &line[..line.char_indices().nth(120).map_or(line.len(), |(i, _)| i)]
            ),
        };
        let path = babel["path"].as_str().unwrap();
        let source = std::fs::read_to_string(path).unwrap();
        let mine = parse_babel(&source, &ParseOptions { path: Some(path) });
        let babel_ok = babel["ok"].as_bool().unwrap();
        match (babel_ok, mine) {
            (true, Ok(ast)) => {
                checked += 1;
                let mut diffs = Vec::new();
                compare("$", &babel["program"], &ast_to_json(&ast), &mut diffs);
                // Babel recovered from errors, we produced a clean tree: a silent wrong answer.
                if babel["errors"].as_u64().unwrap() as usize != ast.error_count {
                    diffs.push(format!(
                        "babel-error-count: babel {} vs ours {}",
                        babel["errors"], ast.error_count
                    ));
                    eprintln!("    source: {:?}", &source[..source.len().min(100)]);
                }
                if !diffs.is_empty() {
                    for diff in &diffs {
                        // Aggregate by shape ("Type.field: ...") without the node path.
                        let key = diff.split(": ").skip(1).collect::<Vec<_>>().join(": ");
                        let key: String = key.chars().take(80).collect();
                        *failures.entry(key).or_default() += 1;
                    }
                    if shown < shown_limit {
                        shown += 1;
                        eprintln!("--- {path}: {} differences, first:", diffs.len());
                        for diff in diffs.iter().take(6) {
                            eprintln!("    {diff}");
                        }
                    }
                }
            }
            (true, Err(_)) if known_disagreement(path) => {}
            // Babel recovered from syntax errors; this port reports that honestly instead of
            // returning a tree with a different error count.
            (true, Err(ConvertError::Unsupported(_))) if babel["errors"].as_u64().unwrap() > 0 => {
                recovered_honestly += 1;
            }
            (true, Err(error)) => {
                *failures.entry(format!("unconverted: {error:?}")).or_default() += 1;
                eprintln!("--- {path}: not converted: {error:?}");
            }
            (false, Ok(_)) if known_disagreement(path) => {}
            (false, Ok(_)) => {
                eprintln!("--- {path}: babel failed, oxc parsed");
                *failures.entry("babel failed, oxc parsed".into()).or_default() += 1;
            }
            (false, Err(_)) => {}
        }
    }
    eprintln!("checked {checked} files, {recovered_honestly} Babel-recovered files reported as unsupported");
    if !failures.is_empty() {
        let mut ranked: Vec<_> = failures.iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(a.1));
        for (key, count) in ranked.iter().take(60) {
            eprintln!("{count:6}  {key}");
        }
        panic!("{} difference shapes", failures.len());
    }
}
