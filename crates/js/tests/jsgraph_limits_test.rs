//! Stack safety and structured refusals of the native pipeline on hostile syntax.
//!
//! No input may abort the process: a file that cannot be parsed within the nesting guard is a
//! parse failure (as in REA, where Babel overflows its stack), a tree that parses but is too deep
//! to analyze is a structured refusal, and sloppy-mode JavaScript is a partial parse of that file.
//!
//! (Parity with REA on the same inputs is in `crates/server/tests/jsgraph_hostile_test.rs`.)

use std::path::PathBuf;

use serde_json::Value;
use tracewise_js::jsgraph::control::Cancel;
use tracewise_js::jsgraph::pipeline::{reconstruct_javascript_application, MAX_AST_DEPTH};

struct Temp(PathBuf);

impl Temp {
    fn with_module(label: &str, source: &str) -> Self {
        Self::with_file(label, "deep.js", source)
    }

    fn with_file(label: &str, file: &str, source: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("jsgraph-limits-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("package.json"), format!(r#"{{"name":"deep","main":"{file}"}}"#)).unwrap();
        std::fs::write(dir.join(file), source).unwrap();
        Temp(dir)
    }

    fn analyze(&self) -> Result<Value, String> {
        reconstruct_javascript_application(self.0.to_str().unwrap(), "directory", "fail", &Cancel::new())
            .map_err(|error| error.to_string())
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Every `key` string value found anywhere in `value`, in document order.
fn strings_under(value: &Value, key: &str, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (name, inner) in map {
                if name == key {
                    if let Some(text) = inner.as_str() {
                        out.push(text.to_string());
                    }
                }
                strings_under(inner, key, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| strings_under(item, key, out)),
        _ => {}
    }
}

fn parse_failures(result: &Value) -> u64 {
    result["statistics"]["parse_failures"].as_u64().expect("parse_failures")
}

#[test]
fn bracket_nesting_far_beyond_a_parser_stack_is_a_parse_failure_not_a_crash() {
    for source in [
        format!("x = {}{};\n", "[".repeat(200_000), "]".repeat(200_000)),
        format!("{}{}\n", "{".repeat(100_000), "}".repeat(100_000)),
        format!("{}{}\n", "{".repeat(5_000), "}".repeat(5_000)),
        format!("x = {}{};\n", "f(".repeat(100_000), ")".repeat(100_000)),
    ] {
        let app = Temp::with_module("brackets", &source);
        let result = app.analyze().expect("analysis completes");
        assert_eq!(parse_failures(&result), 1);
    }
}

/// The nesting guard sits inside the parser, so it does not depend on reading the source the way
/// a lexical estimate does: a regex literal holding a quote (which a naive scanner takes for the
/// start of a string, hiding every bracket after it) must not let a deep file through.
#[test]
fn a_regex_literal_cannot_hide_nesting_from_the_guard() {
    let hidden = format!("var r = /'/;\nx = {}{};\n", "[".repeat(1_000_000), "]".repeat(1_000_000));
    let app = Temp::with_module("regex-trap", &hidden);
    let result = app.analyze().expect("analysis completes");
    assert_eq!(parse_failures(&result), 1);

    // `if (x) /'/` is a regex after a `)`: the other classic trap for lexical scanners.
    let after_paren = format!("if (a) /'/.test(b);\nx = {}{} + 'q';\n", "(".repeat(300_000), ")".repeat(300_000));
    let app = Temp::with_module("regex-after-paren", &after_paren);
    let result = app.analyze().expect("analysis completes");
    assert_eq!(parse_failures(&result), 1);
}

/// Unmatched brackets inside regex literals, strings and comments are not nesting.
#[test]
fn brackets_inside_regex_literals_are_not_nesting() {
    let many_lines = "var n = 0, s = 'x';\n".to_string() + &"if (/\\(/.test(s)) n++;\n".repeat(1_600);
    let one_literal = format!("var re = /{}/;\n", "\\(".repeat(5_000));
    for (label, source) in [("regex-lines", many_lines), ("regex-literal", one_literal)] {
        let app = Temp::with_module(label, &source);
        let result = app.analyze().expect("analysis completes");
        assert_eq!(parse_failures(&result), 0, "{label}");
    }
}

/// Every construct that recurses in a parser, repeated far past any limit: each must come back as
/// a parse failure (REA's Babel overflows its stack on all of them) and never abort the process.
#[test]
fn every_recursive_construct_is_a_parse_failure_when_hostile() {
    let n = 400_000;
    let repeat = |unit: &str| unit.repeat(n);
    let cases: Vec<(&str, &str, String)> = vec![
        ("array", "js", format!("x = {}{};", repeat("["), repeat("]"))),
        ("paren", "js", format!("x = {}1{};", repeat("("), repeat(")"))),
        ("call", "js", format!("x = {}{};", repeat("f("), repeat(")"))),
        ("block", "js", format!("{}{}", repeat("{"), repeat("}"))),
        ("object", "js", format!("x = {}1{};", repeat("{a:"), repeat("}"))),
        ("prefix-bang", "js", format!("x = {}a;", repeat("!"))),
        ("prefix-increment", "js", format!("x = {}a;", repeat("++"))),
        ("typeof", "js", format!("x = {}a;", repeat("typeof "))),
        ("await", "js", format!("async function f() {{ {}a }}", repeat("await "))),
        ("yield", "js", format!("function* f() {{ {}a }}", repeat("yield "))),
        ("new", "js", format!("x = {}a;", repeat("new "))),
        ("conditional", "js", format!("x = {}c;", repeat("a?b:"))),
        ("assignment", "js", format!("{}c;", repeat("a="))),
        ("exponent", "js", format!("x = {}a;", repeat("a**"))),
        ("arrow", "js", format!("x = {}c;", repeat("a=>"))),
        ("template", "js", format!("x = {}1{};", repeat("`${"), repeat("}`"))),
        ("spread", "js", format!("x = {}a{};", repeat("[..."), repeat("]"))),
        ("import-call", "js", format!("x = {}1{};", repeat("import("), repeat(")"))),
        ("if", "js", format!("{};", repeat("if(a)"))),
        ("else-if", "js", format!("{};", repeat("if(a);else "))),
        ("for", "js", format!("{}x;", repeat("for(;;)"))),
        ("while", "js", format!("{}x;", repeat("while(a)"))),
        ("do-while", "js", format!("{}x;{}", repeat("do "), repeat("while(0)"))),
        ("with", "js", format!("{}x;", repeat("with(a)"))),
        ("label", "js", format!("{}x;", repeat("a:"))),
        ("switch", "js", format!("{}{}", repeat("switch(a){case 1:"), repeat("}"))),
        ("try", "js", format!("{}{}", repeat("try{"), repeat("}finally{}"))),
        ("function", "js", format!("{}{}", repeat("function f(){"), repeat("}"))),
        ("class-extends", "js", format!("x = {}{{}};", repeat("class extends "))),
        ("class-body", "js", format!("{}{}", repeat("class A{ m(){"), repeat("}}"))),
        ("array-pattern", "js", format!("var {}a{};", repeat("["), repeat("]"))),
        ("object-pattern", "js", format!("var {}a{};", repeat("{a:"), repeat("}"))),
        ("decorator", "ts", format!("@({}a{}) class A {{}}", repeat("("), repeat(")"))),
        ("jsx", "js", format!("x = {}{};", repeat("<a>"), repeat("</a>"))),
        ("ts-generic-type", "ts", format!("type T = {}number{};", repeat("Array<"), repeat(">"))),
        ("ts-paren-type", "ts", format!("type T = {}number{};", repeat("("), repeat(")"))),
        ("ts-keyof", "ts", format!("type T = {}number;", repeat("keyof "))),
        ("ts-conditional-type", "ts", format!("type T = {}number;", repeat("A extends B ? C : "))),
        ("ts-function-type", "ts", format!("type T = {}number;", repeat("() => "))),
        ("ts-object-type", "ts", format!("type T = {}number{};", repeat("{a:"), repeat("}"))),
        ("ts-angle-assertion", "ts", format!("x = {}a;", repeat("<T>"))),
        ("ts-nested-generic-calls", "ts", format!("x = {}1{};", repeat("f<A<"), repeat(">>()"))),
        ("ts-typed-arrows", "ts", format!("x = {}a{};", repeat("((a: T): T => ("), repeat("))"))),
        ("ts-type-parameters", "ts", format!("function f{}number{}(){{}}", repeat("<T extends "), repeat(">"))),
    ];
    for (label, extension, source) in cases {
        let app = Temp::with_file(label, &format!("deep.{extension}"), &source);
        let result = app.analyze().unwrap_or_else(|error| panic!("{label}: {error}"));
        assert_eq!(parse_failures(&result), 1, "{label}");
    }
}

/// Wide but shallow inputs are not nesting.
#[test]
fn flat_repetition_is_analyzed() {
    let source = format!("x = [{}];\nf({});\ny = (a{});\n", "1,".repeat(300_000), "2,".repeat(300_000), ",b".repeat(20_000));
    let app = Temp::with_module("flat", &source);
    let result = app.analyze().expect("analysis completes");
    assert_eq!(parse_failures(&result), 0);
}

/// `a.b.b.b...` parses iteratively, but its tree is as deep as the chain is long: the conversion
/// moves to heap-allocated stack segments, so depth costs memory, not native stack.
#[test]
fn very_long_chains_are_analyzed_without_overflowing_the_stack() {
    for (label, source) in [
        ("member", format!("x = a{};\n", ".b".repeat(50_000))),
        // (A call chain's text is quadratic in the output, so it is kept shorter.)
        ("call", format!("x = f{};\n", "()".repeat(3_000))),
        ("binary", format!("x = 1{};\n", "+1".repeat(50_000))),
        ("tagged-template", format!("x = a{};\n", "`t`".repeat(30_000))),
    ] {
        let app = Temp::with_module(label, &source);
        let result = app.analyze().unwrap_or_else(|error| panic!("{label}: {error}"));
        assert_eq!(parse_failures(&result), 0, "{label}");
    }
    let app = Temp::with_file("ts-chain", "deep.ts", &format!("x = a{}; y = b{};\n", " as T".repeat(3_000), "!".repeat(30_000)));
    let result = app.analyze().expect("analysis completes");
    assert_eq!(parse_failures(&result), 0);
}

#[test]
fn trees_deeper_than_the_supported_limit_are_refused_with_a_structured_error() {
    for source in [
        format!("x = a{};\n", ".b".repeat(MAX_AST_DEPTH + 10)),
        format!("x = 1{};\n", "+1".repeat(MAX_AST_DEPTH + 10)),
    ] {
        let app = Temp::with_module("too-deep", &source);
        let error = app.analyze().expect_err("refused");
        assert!(error.contains("nested deeper than"), "{error}");
    }
}

#[test]
fn legal_deep_nesting_still_parses() {
    let app = Temp::with_module("legal", &format!("x = {}{};\n", "[".repeat(100), "]".repeat(100)));
    let result = app.analyze().expect("analysis completes");
    assert_eq!(parse_failures(&result), 0);
}

/// Sloppy-mode JavaScript is valid; Babel (strict module attempt, `errorRecovery`) reports it as
/// recoverable errors, so REA returns the graph with `parse_status: "partial"` for that file
/// instead of failing. The application as a whole must not fail either.
#[test]
fn sloppy_mode_javascript_is_a_partial_parse_of_the_file() {
    // (Babel's exact error count for each is checked by `jsgraph_ast_parity_test`.)
    let cases: [(&str, &str, bool); 6] = [
        ("octal-escape", "var s = '\\033[31m'; console.log(s);\n", true),
        ("legacy-octal", "var mode = 0644;\n", true),
        ("with", "with (a) { b; }\n", true),
        ("redeclared-let", "let a; let a;\n", true),
        ("several-kinds", "var a = 0644; with (b) { c; } let d; let d;\n", true),
        ("clean", "var ok = 1;\n", false),
    ];
    for (label, source, recovered) in cases {
        let app = Temp::with_module(label, source);
        let result = app.analyze().unwrap_or_else(|error| panic!("{label}: {error}"));
        assert_eq!(parse_failures(&result), 0, "{label}");
        let mut statuses = Vec::new();
        strings_under(&result, "parse_status", &mut statuses);
        let expected = if recovered { "partial" } else { "complete" };
        assert!(statuses.iter().any(|status| status == expected), "{label}: {statuses:?}");
        let note = "The parser recovered from syntax errors";
        assert_eq!(result.to_string().contains(note), recovered, "{label}");
    }
}
