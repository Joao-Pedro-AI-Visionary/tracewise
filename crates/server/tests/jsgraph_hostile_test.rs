//! Hostile and degenerate application inputs: the port must answer exactly as the original REA
//! does (same graph, or the same error envelope) for each of them, live.
//!
//! Compared: the whole MCP result of `analyze_javascript_application` with only host paths and
//! the ids derived from them normalized (see `jsgraph_support::canon`).
//!
//! Cases (each built in a private temp directory removed on drop):
//! - symlinks to a file and to a directory outside the application root,
//! - 2 500 small modules,
//! - import cycles (a -> b -> a, self import),
//! - an 8 MiB module, a module with invalid UTF-8, a UTF-8 BOM, an empty file,
//! - nesting deeper than the parser can hold (REA fails the parse, so must the port), including
//!   a quote inside a regex literal that would hide the nesting from a lexical scanner,
//! - deep-but-legal nesting that both parse, and member chains of 12 000 and 50 000 links (REA's
//!   Babel parses them iteratively, so both analyze them),
//! - brackets inside regex literals, which are not nesting (1 600 lines of `/\(/.test(s)`, and one
//!   regex literal holding 5 000 `\(`),
//! - sloppy-mode JavaScript (`'\033[31m'`, `0644`, `with`, `let a; let a;`), which Babel parses
//!   with recoverable errors: the file is `partial`, the application still has its graph,
//! - an empty directory, no JavaScript at all, a file given instead of a directory,
//! - paths that are not valid arguments.
//!
//! Known, documented departures (not asserted here): Babel's stack-dependent nesting limit differs
//! per construct (about 350 nested arrays, 500 calls, 800 blocks, 3 700 prefix operators, 6 500
//! binary operators in a chain) from the port's fixed parser guard, which is looser for all of
//! them; chains deeper than `MAX_AST_DEPTH` (200 000) are refused where REA analyzes them. Inputs
//! between the two limits are therefore not compared. See `docs/progress/jsgraph.md`.

mod jsgraph_support;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use jsgraph_support::{oracle_available, Counter, Rea};
use serde_json::json;
use tracewise_server::session::BinarySession;

struct Temp(PathBuf);

impl Temp {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("jsgraph-hostile-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Temp(dir)
    }

    fn write(&self, relative: &str, content: impl AsRef<[u8]>) -> &Self {
        let path = self.0.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
        self
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn compare(rea: &mut Rea, session: &BinarySession, counter: &mut Counter, label: &str, input_path: &Path) {
    let args = json!({"input_path": input_path.to_string_lossy(), "format":"directory"});
    let want = rea.call("analyze_javascript_application", args.clone());
    let got = jsgraph_support::ours(session, "analyze_javascript_application", args).await;
    counter.check(label, want, got);
}

#[tokio::test(flavor = "multi_thread")]
async fn hostile_inputs_match_rea() {
    if !oracle_available() {
        return;
    }
    let mut rea = Rea::start();
    let session = BinarySession::new();
    let mut counter = Counter { compared: 0, failures: Vec::new() };

    // Symlinks pointing outside the application root.
    let outside = Temp::new("outside");
    outside.write("secret.js", "module.exports = 'outside';\n");
    outside.write("dir/inner.js", "exports.inner = 1;\n");
    let linked = Temp::new("symlinks");
    linked.write("package.json", r#"{"name":"linked","main":"main.js"}"#);
    linked.write("main.js", "const s = require('./leak.js'); const d = require('./leakdir/inner.js');\n");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(outside.0.join("secret.js"), linked.0.join("leak.js")).unwrap();
        std::os::unix::fs::symlink(outside.0.join("dir"), linked.0.join("leakdir")).unwrap();
        std::os::unix::fs::symlink("main.js", linked.0.join("alias.js")).unwrap();
        std::os::unix::fs::symlink("../nowhere", linked.0.join("dangling.js")).unwrap();
    }
    compare(&mut rea, &session, &mut counter, "symlinks-outside-root", &linked.0).await;

    // Thousands of files.
    let many = Temp::new("many");
    many.write("package.json", r#"{"name":"many","main":"index.js"}"#);
    let mut index = String::new();
    for n in 0..2_500 {
        many.write(&format!("src/m{n}.js"), format!("exports.v{n} = {n};\n"));
        let _ = writeln!(index, "require('./src/m{n}.js');");
    }
    many.write("index.js", index);
    compare(&mut rea, &session, &mut counter, "2500-files", &many.0).await;

    // Import cycles and self imports, ESM and CommonJS.
    let cycle = Temp::new("cycle");
    cycle.write("package.json", r#"{"name":"cycle","main":"a.js"}"#);
    cycle.write("a.js", "const b = require('./b.js'); exports.a = () => b.b();\nrequire('./a.js');\n");
    cycle.write("b.js", "const a = require('./a.js'); exports.b = () => a.a();\n");
    cycle.write("x.mjs", "import { y } from './y.mjs'; export const x = () => y();\nimport './x.mjs';\n");
    cycle.write("y.mjs", "import { x } from './x.mjs'; export const y = () => x();\nexport * from './x.mjs';\n");
    compare(&mut rea, &session, &mut counter, "import-cycles", &cycle.0).await;

    // One large module.
    let huge = Temp::new("huge");
    huge.write("package.json", r#"{"name":"huge","main":"big.js"}"#);
    let mut big = String::with_capacity(9 << 20);
    let mut n = 0u32;
    while big.len() < 8 << 20 {
        let _ = writeln!(big, "function f{n}(a, b) {{ return a + b + {n}; }}");
        n += 1;
    }
    huge.write("big.js", big);
    compare(&mut rea, &session, &mut counter, "8MiB-module", &huge.0).await;

    // Encoding edge cases.
    let enc = Temp::new("encoding");
    enc.write("package.json", r#"{"name":"enc","main":"bom.js"}"#);
    enc.write("bom.js", [&[0xef, 0xbb, 0xbf][..], b"exports.bom = 1;\n"].concat());
    enc.write("bad.js", [&b"exports.bad = '"[..], &[0xff, 0xfe][..], &b"';\n"[..]].concat());
    enc.write("empty.js", "");
    enc.write("data.json", [&[0xef, 0xbb, 0xbf][..], b"{\"a\":1}"].concat());
    enc.write("bad.json", "{ not json");
    compare(&mut rea, &session, &mut counter, "encodings", &enc.0).await;

    // Nesting: far beyond any parser stack (both fail), and a legal depth both parse.
    for (label, source) in [
        ("array-nesting-20000", format!("x = {}{};\n", "[".repeat(20_000), "]".repeat(20_000))),
        ("call-nesting-20000", format!("x = {}{};\n", "f(".repeat(20_000), ")".repeat(20_000))),
        ("block-nesting-5000", format!("{}{}\n", "{".repeat(5_000), "}".repeat(5_000))),
        ("array-nesting-100", format!("x = {}{};\n", "[".repeat(100), "]".repeat(100))),
        ("member-chain-5000", format!("x = a{};\n", ".b".repeat(5_000))),
        ("member-chain-12000", format!("x = a{};\n", ".b".repeat(12_000))),
        ("member-chain-50000", format!("x = a{};\n", ".b".repeat(50_000))),
        // A quote inside a regex literal swallows everything up to the next quote for a lexical
        // scanner; the nesting that follows must still be seen (and fail the parse, as in REA).
        (
            "regex-quote-then-brackets-1M",
            format!("var r = /'/;\nx = {}{};\n", "[".repeat(1_000_000), "]".repeat(1_000_000)),
        ),
        (
            "regex-after-paren-then-parens",
            format!("if (a) /'/.test(b);\nx = {}{} + 'q';\n", "(".repeat(300_000), ")".repeat(300_000)),
        ),
        ("prefix-operators-1M", format!("x = {}a;\n", "!".repeat(1_000_000))),
        ("if-chain-300000", format!("{};\n", "if (a) ".repeat(300_000))),
        // Brackets inside regex literals are not nesting.
        (
            "regex-paren-lines-1600",
            format!("var n = 0, s = 'x';\n{}", "if (/\\(/.test(s)) n++;\n".repeat(1_600)),
        ),
        ("regex-paren-literal-5000", format!("var re = /{}/;\n", "\\(".repeat(5_000))),
        // Sloppy-mode JavaScript: valid, but Babel's strict module attempt records errors.
        ("sloppy-octal-escape", "var s = '\\033[31m'; console.log(s + '\\033[0m');\n".to_string()),
        ("sloppy-legacy-octal", "var mode = 0644; chmod(mode);\n".to_string()),
        ("sloppy-with", "with (a) { b = c; }\n".to_string()),
        ("sloppy-redeclared-let", "let a = 1; let a = 2;\n".to_string()),
    ] {
        let dir = Temp::new(label);
        dir.write("package.json", r#"{"name":"deep","main":"deep.js"}"#);
        dir.write("deep.js", source);
        compare(&mut rea, &session, &mut counter, label, &dir.0).await;
    }

    // Degenerate roots.
    let empty = Temp::new("empty-dir");
    compare(&mut rea, &session, &mut counter, "empty-directory", &empty.0).await;
    let no_js = Temp::new("no-js");
    no_js.write("readme.txt", "hello");
    no_js.write("package.json", r#"{"name":"nojs"}"#);
    compare(&mut rea, &session, &mut counter, "no-javascript", &no_js.0).await;
    compare(&mut rea, &session, &mut counter, "file-not-directory", &no_js.0.join("readme.txt")).await;
    compare(&mut rea, &session, &mut counter, "missing-path", &no_js.0.join("does-not-exist")).await;

    eprintln!("compared {} hostile-input results", counter.compared);
    for failure in &counter.failures {
        eprintln!("DIFF {failure}");
    }
    assert!(counter.failures.is_empty(), "{} hostile-input results differ from REA", counter.failures.len());
}
