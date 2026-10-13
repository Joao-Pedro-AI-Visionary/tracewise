//! Port of `javascriptSemanticFingerprints.ts`: bounded rename- and formatting-resistant
//! components per callable.

use std::collections::{HashMap, HashSet};

use crate::jsgraph::ast::{Alias, Kind, Val, N};
use crate::jsgraph::ir::{
    FingerprintComponents, SemanticCallSite, SemanticCallable, SemanticChildProcessInteraction,
    SemanticChildProcessSpawn, SemanticClosureCapture, SemanticEventOperation, SemanticFunctionFingerprint,
    SemanticPromiseOperation, SemanticRequestOperation, SemanticResourceOperation, SemanticTimerOperation,
};
use crate::jsgraph::util::{compare_code_points, js_number_to_string, sha256_text};

use super::primitives::json_string;
use super::projection::semantic_callable_id_for_node;
use super::state::SemanticAnalysisState;
use super::traversal::{traverse_javascript_ast, AstVisitor};

/// `SemanticFingerprintCollectionInput`.
pub struct FingerprintInput<'c, 'a> {
    pub state: &'c SemanticAnalysisState<'a>,
    pub callables: &'c [SemanticCallable],
    pub call_sites: &'c [SemanticCallSite],
    pub closure_captures: &'c [SemanticClosureCapture],
    pub promises: &'c [SemanticPromiseOperation],
    pub events: &'c [SemanticEventOperation],
    pub timers: &'c [SemanticTimerOperation],
    pub child_process_spawns: &'c [SemanticChildProcessSpawn],
    pub child_process_interactions: &'c [SemanticChildProcessInteraction],
    pub request_operations: &'c [SemanticRequestOperation],
    pub resource_operations: &'c [SemanticResourceOperation],
    pub parser_partial: bool,
}

/// Build bounded rename- and formatting-resistant components per callable
/// (`collectJavaScriptSemanticFingerprintsSteps`).
pub fn collect_semantic_fingerprints(input: &FingerprintInput<'_, '_>) -> Vec<SemanticFunctionFingerprint> {
    let call_sites_by_caller = group_by_owner(input.call_sites, |site| site.caller_callable_id.as_deref());
    let mut capture_count_by_callable: HashMap<&str, usize> = HashMap::new();
    for capture in input.closure_captures {
        *capture_count_by_callable.entry(capture.callable_id.as_str()).or_default() += 1;
    }
    let promise_effects = group_by_owner(input.promises, |value| value.owner_callable_id.as_deref());
    let event_effects = group_by_owner(input.events, |value| value.owner_callable_id.as_deref());
    let timer_effects = group_by_owner(input.timers, |value| value.owner_callable_id.as_deref());
    let mut child_process_effects: HashMap<&str, usize> = HashMap::new();
    for owner in input.child_process_spawns.iter().filter_map(|value| value.owner_callable_id.as_deref()) {
        *child_process_effects.entry(owner).or_default() += 1;
    }
    for owner in input.child_process_interactions.iter().filter_map(|value| value.owner_callable_id.as_deref()) {
        *child_process_effects.entry(owner).or_default() += 1;
    }
    let network_effects = group_by_owner(input.request_operations, |value| value.owner_callable_id.as_deref());
    let resource_effects = group_by_owner(input.resource_operations, |value| value.owner_callable_id.as_deref());
    let mut targets: HashMap<String, usize> = HashMap::new();
    for callable in input.callables {
        if callable.kind != "class" && input.state.callable_nodes_by_id.contains_key(&callable.callable_id) {
            let next = targets.len();
            targets.entry(callable.callable_id.clone()).or_insert(next);
        }
    }
    let syntaxes = fingerprint_syntaxes(input.state.ast.root(), &targets);
    let mut fingerprints = Vec::new();
    for callable in input.callables {
        if callable.kind == "class" {
            continue;
        }
        let Some(&node) = input.state.callable_nodes_by_id.get(&callable.callable_id) else { continue };
        let syntax = &syntaxes[targets[&callable.callable_id]];
        let id = callable.callable_id.as_str();
        let promises = promise_effects.get(id).map_or(&[][..], Vec::as_slice);
        let mut effects: Vec<String> = Vec::new();
        if node.is_function() && node.flag("async") {
            effects.push("async".into());
        }
        if child_process_effects.get(id).is_some_and(|count| *count > 0) {
            effects.push("child-process".into());
        }
        if has_values(&event_effects, id) {
            effects.push("event".into());
        }
        if has_values(&network_effects, id) {
            effects.push("network".into());
        }
        if !promises.is_empty() {
            effects.push("promise".into());
        }
        if has_values(&resource_effects, id) {
            effects.push("resource".into());
        }
        if has_values(&timer_effects, id) {
            effects.push("timer".into());
        }
        let mut literals: Vec<Tok> = Vec::new();
        let mut seen = HashSet::new();
        for literal in &syntax.literals {
            if seen.insert(literal) {
                literals.push(literal.clone());
            }
        }
        literals.sort_by(Tok::compare_code_points);
        let mut limitations = vec!["The fingerprint is a static candidate and does not prove behavioral equivalence.".to_string()];
        if input.parser_partial {
            limitations.push("Incomplete semantic recovery makes this fingerprint partial.".to_string());
        }
        fingerprints.push(SemanticFunctionFingerprint {
            callable_id: callable.callable_id.clone(),
            status: if input.parser_partial || callable.return_coverage.status != "complete" {
                "partial"
            } else {
                "complete"
            }
            .into(),
            components: FingerprintComponents {
                parameter_arity: if node.is_function() { node.list_len("params") as u64 } else { 0 },
                normalized_ast_sha256: digest(&syntax.normalized_tokens),
                control_flow_sha256: digest(&syntax.control_flow_tokens),
                relation_shape_sha256: digest(&texts(relation_shape(
                    callable,
                    call_sites_by_caller.get(id).map_or(&[][..], Vec::as_slice),
                    capture_count_by_callable.get(id).copied().unwrap_or(0),
                    promises,
                ))),
                literal_set_sha256: digest(&literals),
                effects,
            },
            limitations,
        });
    }
    fingerprints
}

fn has_values<T>(map: &HashMap<&str, Vec<&T>>, id: &str) -> bool {
    map.get(id).is_some_and(|values| !values.is_empty())
}

fn group_by_owner<'v, T>(values: &'v [T], owner: impl Fn(&'v T) -> Option<&'v str>) -> HashMap<&'v str, Vec<&'v T>> {
    let mut grouped: HashMap<&str, Vec<&T>> = HashMap::new();
    for value in values {
        if let Some(owner) = owner(value) {
            grouped.entry(owner).or_default().push(value);
        }
    }
    grouped
}

struct FingerprintSyntax {
    normalized_tokens: Vec<Tok>,
    control_flow_tokens: Vec<Tok>,
    literals: Vec<Tok>,
}

/// One traversal of the program that attributes every node to its innermost enclosing-or-self
/// callable. REA walks each callable's subtree separately and keeps the nodes whose innermost
/// callable is the target, so the token lists (and their order) are identical; doing it once avoids
/// walking nested callables once per ancestor.
struct SyntaxVisitor<'t> {
    /// Callable id to the index of its `FingerprintSyntax` in `syntaxes` (fingerprint targets only).
    targets: &'t HashMap<String, usize>,
    /// `(callable id, target index)` of every callable node on the path, innermost last.
    callable_stack: Vec<(String, Option<usize>)>,
    syntaxes: Vec<FingerprintSyntax>,
}

impl<'a> AstVisitor<'a> for SyntaxVisitor<'_> {
    fn enter(&mut self, node: N<'a>, parent: Option<N<'a>>) {
        if let Some(id) = semantic_callable_id_for_node(node) {
            let target = self.targets.get(&id).copied();
            self.callable_stack.push((id, target));
        }
        let Some(&(_, Some(target))) = self.callable_stack.last() else { return };
        // The callable node itself is the traversal root in REA, so it never has a parent there.
        let parent = if semantic_callable_id_for_node(node).is_some() { None } else { parent };
        let syntax = &mut self.syntaxes[target];
        syntax.normalized_tokens.push(normalized_node_token(node, parent));
        if let Some(control) = control_flow_token(node) {
            syntax.control_flow_tokens.push(Tok::Text(control));
        }
        if let Some(literal) = semantic_literal(node) {
            syntax.literals.push(literal);
        }
    }

    fn exit(&mut self, node: N<'a>, _parent: Option<N<'a>>) {
        if let Some(id) = semantic_callable_id_for_node(node) {
            if self.callable_stack.last().is_some_and(|(top, _)| *top == id) {
                self.callable_stack.pop();
            }
        }
    }
}

/// Token lists of every target callable, in `targets` order of index.
fn fingerprint_syntaxes(root: N<'_>, targets: &HashMap<String, usize>) -> Vec<FingerprintSyntax> {
    let mut visitor = SyntaxVisitor {
        targets,
        callable_stack: Vec::new(),
        syntaxes: (0..targets.len())
            .map(|_| FingerprintSyntax {
                normalized_tokens: Vec::new(),
                control_flow_tokens: Vec::new(),
                literals: Vec::new(),
            })
            .collect(),
    };
    traverse_javascript_ast(root, &mut visitor);
    visitor.syntaxes
}

fn normalized_node_token(node: N<'_>, parent: Option<N<'_>>) -> Tok {
    if node.is_identifier() {
        return Tok::Text(if property_identity(node, parent) {
            format!("property:{}", node.name().unwrap_or(""))
        } else {
            "identifier".into()
        });
    }
    if node.is_string_literal() {
        return if property_identity(node, parent) {
            js_text("property:", node.str("value").unwrap_or(""), node.str("x_raw"))
        } else {
            Tok::Text("string-literal".into())
        };
    }
    let mut token = node.kind().as_str().to_string();
    for key in ["operator", "kind", "computed", "optional", "async", "generator"] {
        if let Some(attribute) = primitive_attribute(node, key) {
            token.push(':');
            token.push_str(&attribute);
        }
    }
    Tok::Text(token)
}

/// `primitiveAttribute`: `key=value` for a string, number, or boolean own property.
fn primitive_attribute(node: N<'_>, key: &str) -> Option<String> {
    if key == "computed" && babel_omits_computed(node) {
        return None;
    }
    match node.field(key)? {
        Val::Str(value) => Some(format!("{key}={value}")),
        Val::Num(value) => Some(format!("{key}={}", js_number_to_string(*value))),
        Val::Bool(value) => Some(format!("{key}={value}")),
        _ => None,
    }
}

/// Babel only sets `computed` on a private class member when the member name was first parsed as an
/// ordinary property name: `get #x`, `set #x` and `async #x` parse the contextual keyword first,
/// while `#x(){}`, `*#x(){}` and every `ClassPrivateProperty` never go through that path. The arena
/// AST normalizes the flag to `false`, so the fingerprint restores Babel's own presence rule
/// (`Reflect.get(node, "computed")` is `undefined` there).
fn babel_omits_computed(node: N<'_>) -> bool {
    match node.kind() {
        Kind::ClassPrivateProperty => true,
        Kind::ClassPrivateMethod => !(matches!(node.str("kind"), Some("get") | Some("set")) || node.flag("async")),
        _ => false,
    }
}

fn property_identity(node: N<'_>, parent: Option<N<'_>>) -> bool {
    let Some(parent) = parent else { return false };
    if parent.is_member() && parent.f("property") == Some(node) {
        return !parent.flag("computed") || node.is_string_literal();
    }
    if matches!(parent.kind(), Kind::ObjectProperty | Kind::ObjectMethod | Kind::ClassMethod | Kind::ClassProperty)
        && parent.f("key") == Some(node)
    {
        return !parent.flag("computed") || node.is_string_literal();
    }
    false
}

fn control_flow_token(node: N<'_>) -> Option<String> {
    let flow = matches!(
        node.kind(),
        Kind::IfStatement
            | Kind::ConditionalExpression
            | Kind::SwitchStatement
            | Kind::SwitchCase
            | Kind::TryStatement
            | Kind::CatchClause
            | Kind::ReturnStatement
            | Kind::ThrowStatement
            | Kind::AwaitExpression
            | Kind::YieldExpression
            | Kind::LogicalExpression
    ) || node.has_alias(Alias::Loop);
    if !flow {
        return None;
    }
    Some(match primitive_attribute(node, "operator") {
        None => node.kind().as_str().to_string(),
        Some(operator) => format!("{}:{operator}", node.kind().as_str()),
    })
}

fn semantic_literal(node: N<'_>) -> Option<Tok> {
    let text = |value: String| Some(Tok::Text(value));
    match node.kind() {
        Kind::StringLiteral => Some(js_text("string:", node.str("value").unwrap_or(""), node.str("x_raw"))),
        Kind::NumericLiteral => text(format!("number:{}", js_number_to_string(node.num("value").unwrap_or(f64::NAN)))),
        Kind::BooleanLiteral => text(format!("boolean:{}", node.flag("value"))),
        Kind::NullLiteral => text("null".into()),
        Kind::BigIntLiteral => text(format!("bigint:{}", node.str("value").unwrap_or(""))),
        Kind::RegExpLiteral => text(format!(
            "regexp:{}/{}",
            node.str("pattern").unwrap_or(""),
            node.str("flags").unwrap_or("")
        )),
        Kind::TemplateElement => match node.str("cooked") {
            Some(cooked) => Some(js_text("template:", cooked, node.str("raw"))),
            None => text(format!("template:{}", node.str("raw").unwrap_or(""))),
        },
        _ => None,
    }
}

fn relation_shape(
    callable: &SemanticCallable,
    call_sites: &[&SemanticCallSite],
    capture_count: usize,
    promises: &[&SemanticPromiseOperation],
) -> Vec<String> {
    let mut shape = vec![format!("returns:{}:{}", callable.return_sites.len(), callable.return_coverage.status)];
    shape.extend(call_sites.iter().map(|site| {
        format!(
            "call:{}:{}:{}:{}",
            site.kind,
            site.resolution,
            site.arguments.len(),
            site.callee_callable_ids.len()
        )
    }));
    shape.push(format!("captures:{capture_count}"));
    shape.extend(promises.iter().map(|promise| {
        format!("promise:{}:{}:{}:{}", promise.kind, promise.method, promise.ownership, promise.source_resolution)
    }));
    shape
}

fn texts(values: Vec<String>) -> Vec<Tok> {
    values.into_iter().map(Tok::Text).collect()
}

/// `sha256(JSON.stringify(strings))`.
fn digest(values: &[Tok]) -> String {
    let items: Vec<String> = values.iter().map(Tok::json).collect();
    sha256_text(&format!("[{}]", items.join(",")))
}

/// One fingerprint token. A JavaScript string may hold lone surrogates, which a Rust `String`
/// cannot; such tokens keep their code units (`Units`) so `JSON.stringify` (which escapes lone
/// surrogates as `\udXXX`) and `compareUnicodeCodePoints` stay exact.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Tok {
    Text(String),
    Units(Vec<u32>),
}

impl Tok {
    fn json(&self) -> String {
        match self {
            Tok::Text(text) => json_string(text),
            Tok::Units(units) => {
                let mut out = String::from("\"");
                for &unit in units {
                    match unit {
                        0x22 => out.push_str("\\\""),
                        0x5c => out.push_str("\\\\"),
                        0x08 => out.push_str("\\b"),
                        0x0c => out.push_str("\\f"),
                        0x0a => out.push_str("\\n"),
                        0x0d => out.push_str("\\r"),
                        0x09 => out.push_str("\\t"),
                        0..=0x1f | 0xd800..=0xdfff => out.push_str(&format!("\\u{unit:04x}")),
                        _ => out.push(char::from_u32(unit).unwrap_or('\u{fffd}')),
                    }
                }
                out.push('"');
                out
            }
        }
    }

    fn code_points(&self) -> Vec<u32> {
        match self {
            Tok::Text(text) => text.chars().map(u32::from).collect(),
            Tok::Units(units) => units.clone(),
        }
    }

    /// `compareUnicodeCodePoints`.
    fn compare_code_points(left: &Tok, right: &Tok) -> std::cmp::Ordering {
        match (left, right) {
            (Tok::Text(left), Tok::Text(right)) => compare_code_points(left, right),
            _ => left.code_points().cmp(&right.code_points()),
        }
    }
}

/// `prefix + value` as a JavaScript string. oxc encodes a lone surrogate in a string value as
/// U+FFFD followed by its code unit in four hex digits (and a real U+FFFD as `fffd`); the arena AST
/// keeps that encoding without oxc's `lone_surrogates` flag, so the decode is attempted only when
/// the raw source has an escape and every U+FFFD in the value is followed by a valid code.
fn js_text(prefix: &str, value: &str, raw: Option<&str>) -> Tok {
    if value.contains('\u{fffd}') && raw.is_none_or(|raw| raw.contains('\\')) {
        if let Some(mut units) = decode_lone_surrogates(value) {
            let mut all: Vec<u32> = prefix.chars().map(u32::from).collect();
            all.append(&mut units);
            return Tok::Units(all);
        }
    }
    Tok::Text(format!("{prefix}{value}"))
}

fn decode_lone_surrogates(value: &str) -> Option<Vec<u32>> {
    let mut units = Vec::new();
    let mut chars = value.chars();
    let mut any_surrogate = false;
    while let Some(ch) = chars.next() {
        if ch != '\u{fffd}' {
            units.push(u32::from(ch));
            continue;
        }
        let hex: String = chars.by_ref().take(4).collect();
        if hex.len() != 4 {
            return None;
        }
        let code = u32::from_str_radix(&hex, 16).ok()?;
        match code {
            0xfffd => units.push(0xfffd),
            0xd800..=0xdfff => {
                any_surrogate = true;
                units.push(code);
            }
            _ => return None,
        }
    }
    any_surrogate.then_some(units)
}
