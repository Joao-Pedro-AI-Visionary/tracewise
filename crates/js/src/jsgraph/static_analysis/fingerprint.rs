//! Port of `javascriptAstFingerprint.ts`: rename-resistant syntax fingerprints and static
//! CommonJS/bundler export names.

use std::collections::HashSet;

use sha2::{Digest, Sha256};

use super::super::ast::{walk, Ast, Kind, N};
use super::super::ast_values::property_name;
use super::super::util::{compare_code_points, js_number_to_string};
use super::helpers::string_value;

/// Static CommonJS export names (`StaticExports`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticExports {
    pub values: Vec<String>,
}

/// `fingerprintJavaScriptAst`: a rename-resistant syntax fingerprint without code execution.
pub fn fingerprint_javascript_ast(node: N<'_>) -> String {
    fingerprint(node, false)
}

/// `fingerprintJavaScriptAst(file)` for the Babel `File` node above the tree root: the same walk
/// preceded by the `File` node's own token.
pub fn fingerprint_javascript_file(ast: &Ast) -> String {
    fingerprint(ast.root(), true)
}

fn fingerprint(node: N<'_>, under_file: bool) -> String {
    // sha256 over `JSON.stringify(tokens)`, streamed so no token array is materialized.
    let mut hasher = Sha256::new();
    hasher.update(b"[");
    let mut first = true;
    let mut push = |hasher: &mut Sha256, token: &str| {
        if !first {
            hasher.update(b",");
        }
        first = false;
        hasher.update(serde_json::to_string(token).expect("json string").as_bytes());
    };
    if under_file {
        push(&mut hasher, "node:File");
    }
    walk(
        node,
        |current, _| {
            semantic_tokens(current, &mut |token| push(&mut hasher, token));
            true
        },
        |_, _| {},
    );
    hasher.update(b"]");
    hex::encode(hasher.finalize())
}

/// `collectJavaScriptExports`: statically declared CommonJS/bundler export names of a factory.
pub fn collect_javascript_exports(node: N<'_>) -> StaticExports {
    let mut exports: HashSet<String> = HashSet::new();
    walk(
        node,
        |current, _| {
            if current.is(Kind::AssignmentExpression) {
                if let (Some(left), Some(right)) = (current.f("left"), current.f("right")) {
                    collect_assignment_exports(left, right, &mut exports);
                }
            }
            if current.is(Kind::CallExpression) {
                collect_call_exports(current, &mut exports);
            }
            true
        },
        |_, _| {},
    );
    let mut values: Vec<String> = exports.into_iter().collect();
    values.sort_by(|a, b| compare_code_points(a, b));
    StaticExports { values }
}

fn semantic_tokens(node: N<'_>, emit: &mut dyn FnMut(&str)) {
    emit(&format!("node:{}", node.kind().as_str()));
    match node.kind() {
        Kind::StringLiteral => emit(&format!("string:{}", node.str("value").unwrap_or(""))),
        Kind::NumericLiteral => emit(&format!(
            "number:{}",
            js_number_to_string(node.num("value").unwrap_or(f64::NAN))
        )),
        Kind::BooleanLiteral => emit(&format!("boolean:{}", node.flag("value"))),
        Kind::RegExpLiteral => emit(&format!(
            "regexp:{}/{}",
            node.str("pattern").unwrap_or(""),
            node.str("flags").unwrap_or("")
        )),
        Kind::BinaryExpression
        | Kind::LogicalExpression
        | Kind::UnaryExpression
        | Kind::UpdateExpression => emit(&format!("operator:{}", node.str("operator").unwrap_or(""))),
        _ => {}
    }
    if node.is_member() {
        if let Some(property) = node.f("property") {
            let name = property_name(property);
            if !name.is_empty() {
                emit(&format!("property:{name}"));
            }
        }
    }
    if (node.is(Kind::ObjectProperty) || node.is(Kind::ObjectMethod)) && !node.flag("computed") {
        if let Some(key) = node.f("key") {
            let name = property_name(key);
            if !name.is_empty() {
                emit(&format!("key:{name}"));
            }
        }
    }
}

fn collect_assignment_exports(left: N<'_>, right: N<'_>, output: &mut HashSet<String>) {
    let path = member_path(Some(left));
    if path == "exports" || path == "module.exports" {
        if right.is(Kind::ObjectExpression) {
            collect_object_keys(right, output);
        } else {
            output.insert("default".into());
        }
        return;
    }
    if let Some(rest) = path.strip_prefix("exports.") {
        output.insert(rest.to_string());
    }
    if let Some(rest) = path.strip_prefix("module.exports.") {
        output.insert(rest.to_string());
    }
}

fn collect_call_exports(call: N<'_>, output: &mut HashSet<String>) {
    let callee = member_path(call.f("callee"));
    let args = call.nodes("arguments");
    if callee == "Object.defineProperty" {
        let target = member_path(args.first().copied());
        let name = string_value(args.get(1).copied());
        if target == "exports" || target == "module.exports" {
            if let Some(name) = name.filter(|name| !name.is_empty()) {
                output.insert(name);
            }
        }
    }
    if !callee.ends_with(".d") {
        return;
    }
    let target = member_path(args.first().copied());
    if (target == "exports" || target == "module.exports")
        && args.get(1).is_some_and(|declarations| declarations.is(Kind::ObjectExpression))
    {
        collect_object_keys(args[1], output);
    }
}

fn collect_object_keys(object: N<'_>, output: &mut HashSet<String>) {
    for property in object.nodes("properties") {
        if !property.is(Kind::ObjectProperty) && !property.is(Kind::ObjectMethod) {
            continue;
        }
        let Some(key) = property.f("key") else { continue };
        let name = property_name(key);
        if !name.is_empty() {
            output.insert(name);
        }
    }
}

/// `memberPath`: dotted member path rooted at an identifier or `this`.
pub fn member_path(node: Option<N<'_>>) -> String {
    let mut properties: Vec<String> = Vec::new();
    let mut current = node;
    while let Some(candidate) = current.filter(|candidate| candidate.is_member()) {
        properties.push(candidate.f("property").map(property_name).unwrap_or_default());
        current = candidate.f("object");
    }
    let root = match current {
        Some(node) if node.is_identifier() => node.name().unwrap_or("").to_string(),
        Some(node) if node.is(Kind::ThisExpression) => "this".to_string(),
        _ => String::new(),
    };
    if properties.is_empty() {
        return root;
    }
    properties.reverse();
    let mut path: Vec<String> = if root.is_empty() { Vec::new() } else { vec![root] };
    for property in properties {
        if path.is_empty() && property.is_empty() {
            continue;
        }
        path.push(property);
    }
    path.join(".")
}
