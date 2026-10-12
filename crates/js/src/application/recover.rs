//! Static IR for the syntax the fixture application uses.
//!
//! Scope ids, definition order, reference order, and fingerprint tokens follow
//! REA's Babel walk. oxc semantic symbol spans choose the binding a reference
//! resolves to.

#![allow(dead_code)]

use std::collections::{BTreeSet, HashSet};

use sha2::{Digest, Sha256};

use super::babel::{count_nodes, parse_module, BNode};
use crate::error::JsError;

#[derive(Clone, Debug)]
pub struct SourceRange {
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

#[derive(Clone, Debug)]
pub struct BindingFact {
    pub binding_id: String,
    pub name: String,
    pub kind: String,
    pub anchor: (u32, u32),
    pub scope_index: usize,
    pub definitions: Vec<DefinitionFact>,
    pub initializers: Vec<InitKind>,
    pub value_status: String,
    pub value_reason: String,
}

#[derive(Clone, Debug)]
pub struct DefinitionFact {
    pub kind: String,
    pub start: u32,
    pub end: u32,
    pub range: SourceRange,
}

#[derive(Clone, Debug)]
pub enum InitKind {
    Number(f64),
    Function,
    ForOf,
    Call,
    Other(String),
}

#[derive(Clone, Debug)]
pub struct ReferenceFact {
    pub index: usize,
    pub name: String,
    pub role: String,
    pub range: SourceRange,
    pub binding_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CallableFact {
    pub callable_id: String,
    pub name: String,
    pub start: u32,
    pub end: u32,
    pub range: SourceRange,
    pub scope_index: usize,
    pub arity: u32,
    pub returns: Vec<ReturnFact>,
    pub fingerprint: FingerprintFact,
}

#[derive(Clone, Debug)]
pub struct ReturnFact {
    pub return_id: String,
    pub range: SourceRange,
    pub identity: Option<SourceRange>,
    pub value_status: String,
    pub value_reason: String,
}

#[derive(Clone, Debug)]
pub struct CallFact {
    pub call_id: String,
    pub range: SourceRange,
    pub callee_range: SourceRange,
    pub caller_callable_id: Option<String>,
    pub callee_name: String,
    pub resolution: String,
    pub arguments: Vec<SourceRange>,
    pub result_binding_id: Option<String>,
    pub frontier_reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CaptureFact {
    pub binding_id: String,
    pub callable_id: String,
    pub range: SourceRange,
}

#[derive(Clone, Debug)]
pub struct ImportFact {
    pub specifier: String,
    pub imported_name: String,
    pub local_name: String,
    pub local_range: SourceRange,
    pub declaration_range: SourceRange,
    pub resolved_path: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ExportFact {
    pub local_name: String,
    pub exported_name: String,
    pub callable_id: String,
    pub range: SourceRange,
    pub value_status: String,
    pub value_reason: String,
    pub return_range: Option<SourceRange>,
}

#[derive(Clone, Debug)]
pub struct FingerprintFact {
    pub normalized_ast_sha256: String,
    pub control_flow_sha256: String,
    pub relation_shape_sha256: String,
    pub literal_set_sha256: String,
    pub parameter_arity: u32,
}

#[derive(Clone, Debug)]
pub struct ModuleFacts {
    pub visited_ast_nodes: usize,
    pub module_format: &'static str,
    pub file_range: SourceRange,
    pub imports: Vec<ImportFact>,
    pub exports: Vec<ExportFact>,
    pub bindings: Vec<BindingFact>,
    pub references: Vec<ReferenceFact>,
    pub callables: Vec<CallableFact>,
    pub calls: Vec<CallFact>,
    pub captures: Vec<CaptureFact>,
}

struct Scope {
    id: String,
    parent: Option<usize>,
}

struct PendingAssign {
    name: String,
    start: u32,
    end: u32,
    init: InitKind,
    scope: usize,
}

struct RawCallable {
    callable_id: String,
    name: String,
    start: u32,
    end: u32,
    range: SourceRange,
    scope_index: usize,
    arity: u32,
    node: BNode,
    returns: Vec<ReturnFact>,
}

pub fn recover_module(
    source: &str,
    path: &str,
    files: &BTreeSet<String>,
) -> Result<ModuleFacts, JsError> {
    let parsed = parse_module(source)?;
    let program_end = parsed.program.end;
    let mut scopes = vec![Scope {
        id: format!("scope:program:0:{program_end}"),
        parent: None,
    }];
    let mut bindings = Vec::new();
    let mut callables = Vec::new();
    let mut pending = Vec::new();
    walk_bindings(
        &parsed.program,
        source,
        0,
        false,
        &mut scopes,
        &mut bindings,
        &mut callables,
        &mut pending,
    );
    apply_assignments(source, &pending, &scopes, &mut bindings);
    evaluate_bindings(&mut bindings);
    let mut references = Vec::new();
    let mut calls = Vec::new();
    let mut captures = Vec::new();
    let mut seen_refs = HashSet::new();
    walk_uses(
        &parsed.program,
        source,
        None,
        0,
        &[],
        &scopes,
        &bindings,
        &mut callables,
        &mut references,
        &mut calls,
        &mut captures,
        &mut seen_refs,
    );
    let exports = export_facts(&parsed.program, &callables);
    let imports = import_facts(source, path, files, &parsed.program);
    let finished = finish_callables(&callables, &calls, &captures);
    Ok(ModuleFacts {
        visited_ast_nodes: count_nodes(&parsed.program) + 1,
        module_format: if imports.is_empty() && exports.is_empty() {
            "script"
        } else {
            "esm"
        },
        file_range: range_of(source, parsed.program.start, parsed.program.end),
        imports,
        exports,
        bindings,
        references,
        callables: finished,
        calls,
        captures,
    })
}

fn walk_bindings(
    node: &BNode,
    source: &str,
    scope: usize,
    function_body: bool,
    scopes: &mut Vec<Scope>,
    bindings: &mut Vec<BindingFact>,
    callables: &mut Vec<RawCallable>,
    pending: &mut Vec<PendingAssign>,
) {
    if node.kind == "FunctionDeclaration" {
        if let Some(name) = node.children.iter().find(|child| child.kind == "Identifier") {
            add_binding(source, bindings, scopes, scope, name, "function", vec![InitKind::Function]);
        }
        let idx = push_scope(scopes, "function", node.start, node.end, Some(scope));
        let mut arity = 0u32;
        for child in &node.children {
            if child.kind == "Identifier" && is_parameter(node, child) {
                add_binding(source, bindings, scopes, idx, child, "parameter", Vec::new());
                arity += 1;
            }
        }
        if let Some(body) = node.children.iter().find(|child| child.kind == "BlockStatement") {
            walk_bindings(body, source, idx, true, scopes, bindings, callables, pending);
        }
        let name = node
            .children
            .iter()
            .find(|child| child.kind == "Identifier")
            .and_then(|child| child.name.clone())
            .unwrap_or_default();
        callables.push(RawCallable {
            callable_id: format!("callable:function:{}:{}", node.start, node.end),
            name,
            start: node.start,
            end: node.end,
            range: range_of(source, node.start, node.end),
            scope_index: idx,
            arity,
            node: node.clone(),
            returns: Vec::new(),
        });
        return;
    }
    if node.kind == "BlockStatement" && !function_body {
        let idx = push_scope(scopes, "block", node.start, node.end, Some(scope));
        for child in &node.children {
            walk_bindings(child, source, idx, false, scopes, bindings, callables, pending);
        }
        return;
    }
    if node.kind == "ForOfStatement" {
        let idx = push_scope(scopes, "block", node.start, node.end, Some(scope));
        for child in &node.children {
            walk_bindings(child, source, idx, false, scopes, bindings, callables, pending);
        }
        if let Some(decl) = node.children.iter().find(|child| child.kind == "VariableDeclaration") {
            for declarator in decl.children.iter().filter(|child| child.kind == "VariableDeclarator") {
                if let Some(id) = declarator.children.iter().find(|child| child.kind == "Identifier") {
                    if let Some(name) = &id.name {
                        pending.push(PendingAssign {
                            name: name.clone(),
                            start: id.start,
                            end: id.end,
                            init: InitKind::ForOf,
                            scope: idx,
                        });
                    }
                }
            }
        }
        return;
    }
    if node.kind == "VariableDeclarator" {
        if let Some(id) = node.children.iter().find(|child| child.kind == "Identifier") {
            let inits = node
                .children
                .iter()
                .find(|child| child.kind != "Identifier")
                .map(|child| vec![init_of(child)])
                .unwrap_or_default();
            add_binding(source, bindings, scopes, scope, id, "variable", inits);
        }
        return;
    }
    if node.kind == "ImportSpecifier" {
        if let Some(local) = node.children.iter().filter(|child| child.kind == "Identifier").nth(1) {
            add_binding(source, bindings, scopes, scope, local, "import", Vec::new());
        }
        return;
    }
    if node.kind == "AssignmentExpression" {
        if let Some(id) = node.children.iter().find(|child| child.kind == "Identifier") {
            if let Some(name) = &id.name {
                let init = node
                    .children
                    .iter()
                    .rev()
                    .find(|child| child.kind != "Identifier")
                    .map(init_of)
                    .unwrap_or(InitKind::Other("AssignmentExpression".into()));
                pending.push(PendingAssign {
                    name: name.clone(),
                    start: id.start,
                    end: id.end,
                    init,
                    scope,
                });
            }
        }
    }
    for child in &node.children {
        walk_bindings(child, source, scope, false, scopes, bindings, callables, pending);
    }
}

fn is_parameter(func: &BNode, child: &BNode) -> bool {
    let mut seen_name = false;
    for item in &func.children {
        if item.kind != "Identifier" {
            break;
        }
        if !seen_name {
            seen_name = true;
            continue;
        }
        if item.start == child.start && item.end == child.end {
            return true;
        }
    }
    false
}

fn add_binding(
    source: &str,
    bindings: &mut Vec<BindingFact>,
    scopes: &[Scope],
    scope: usize,
    id: &BNode,
    kind: &str,
    initializers: Vec<InitKind>,
) {
    let Some(name) = &id.name else { return };
    let binding_id = format!("{}:binding:{name}", scopes[scope].id);
    let definition = DefinitionFact {
        kind: match kind {
            "function" => "function",
            "parameter" => "parameter",
            "import" => "import",
            _ => "variable",
        }
        .to_string(),
        start: id.start,
        end: id.end,
        range: range_of(source, id.start, id.end),
    };
    if let Some(existing) = bindings.iter_mut().find(|binding| binding.binding_id == binding_id) {
        existing.definitions.push(definition);
        existing.initializers.extend(initializers);
        return;
    }
    bindings.push(BindingFact {
        binding_id,
        name: name.clone(),
        kind: kind.to_string(),
        anchor: (id.start, id.end),
        scope_index: scope,
        definitions: vec![definition],
        initializers,
        value_status: String::new(),
        value_reason: String::new(),
    });
}

fn apply_assignments(
    source: &str,
    pending: &[PendingAssign],
    scopes: &[Scope],
    bindings: &mut [BindingFact],
) {
    for assign in pending {
        let Some(binding_id) = resolve_name(assign.scope, &assign.name, scopes, bindings) else {
            continue;
        };
        let Some(binding) = bindings.iter_mut().find(|binding| binding.binding_id == binding_id) else {
            continue;
        };
        binding.definitions.push(DefinitionFact {
            kind: "assignment".into(),
            start: assign.start,
            end: assign.end,
            range: range_of(source, assign.start, assign.end),
        });
        binding.initializers.push(assign.init.clone());
    }
}

fn evaluate_bindings(bindings: &mut [BindingFact]) {
    for binding in bindings {
        let (status, reason) = value_from_initializers(&binding.name, &binding.initializers);
        binding.value_status = status;
        binding.value_reason = reason;
    }
}

fn value_from_initializers(name: &str, initializers: &[InitKind]) -> (String, String) {
    if initializers.is_empty() {
        return (
            "unknown".into(),
            format!("Binding {name} has no constant initializer."),
        );
    }
    if initializers.len() > 1 {
        return (
            "ambiguous".into(),
            format!("Binding {name} has multiple possible assignments."),
        );
    }
    match &initializers[0] {
        InitKind::Number(_) => ("known".into(), String::new()),
        InitKind::Function => (
            "unknown".into(),
            "Unsupported FunctionDeclaration value.".into(),
        ),
        InitKind::ForOf => (
            "unknown".into(),
            "Unsupported ForOfStatement value.".into(),
        ),
        InitKind::Call => ("unknown".into(), "Unsupported CallExpression value.".into()),
        InitKind::Other(kind) => ("unknown".into(), format!("Unsupported {kind} value.")),
    }
}

fn resolve_name(
    scope: usize,
    name: &str,
    scopes: &[Scope],
    bindings: &[BindingFact],
) -> Option<String> {
    let mut current = Some(scope);
    while let Some(index) = current {
        if let Some(binding) = bindings
            .iter()
            .find(|binding| binding.scope_index == index && binding.name == name)
        {
            return Some(binding.binding_id.clone());
        }
        current = scopes[index].parent;
    }
    None
}

fn resolve_symbol(symbol: (u32, u32), bindings: &[BindingFact]) -> Option<String> {
    bindings
        .iter()
        .find(|binding| binding.anchor == symbol)
        .map(|binding| binding.binding_id.clone())
}

fn init_of(node: &BNode) -> InitKind {
    match node.kind {
        "NumericLiteral" => InitKind::Number(node.number.unwrap_or(0.0)),
        "FunctionDeclaration" => InitKind::Function,
        "CallExpression" => InitKind::Call,
        "ForOfStatement" => InitKind::ForOf,
        _ => InitKind::Other(node.kind.to_string()),
    }
}

fn push_scope(
    scopes: &mut Vec<Scope>,
    kind: &str,
    start: u32,
    end: u32,
    parent: Option<usize>,
) -> usize {
    scopes.push(Scope {
        id: format!("scope:{kind}:{start}:{end}"),
        parent,
    });
    scopes.len() - 1
}

#[allow(clippy::too_many_arguments)]
fn walk_uses(
    node: &BNode,
    source: &str,
    parent: Option<&BNode>,
    scope: usize,
    functions: &[usize],
    scopes: &[Scope],
    bindings: &[BindingFact],
    callables: &mut [RawCallable],
    references: &mut Vec<ReferenceFact>,
    calls: &mut Vec<CallFact>,
    captures: &mut Vec<CaptureFact>,
    seen: &mut HashSet<String>,
) {
    if node.kind == "FunctionDeclaration" {
        let idx = scope_index(scopes, "function", node.start, node.end).unwrap_or(scope);
        let callable = callables
            .iter()
            .position(|callable| callable.start == node.start && callable.end == node.end);
        let mut next = functions.to_vec();
        if let Some(callable) = callable {
            next.push(callable);
        }
        if let Some(body) = node.children.iter().find(|child| child.kind == "BlockStatement") {
            walk_uses(
                body, source, Some(node), idx, &next, scopes, bindings, callables, references, calls,
                captures, seen,
            );
        }
        return;
    }
    if node.kind == "BlockStatement" && parent.is_none_or(|parent| parent.kind != "FunctionDeclaration") {
        let idx = scope_index(scopes, "block", node.start, node.end).unwrap_or(scope);
        for child in &node.children {
            walk_uses(
                child, source, Some(node), idx, functions, scopes, bindings, callables, references,
                calls, captures, seen,
            );
        }
        return;
    }
    if node.kind == "ForOfStatement" {
        let idx = scope_index(scopes, "block", node.start, node.end).unwrap_or(scope);
        for child in &node.children {
            walk_uses(
                child, source, Some(node), idx, functions, scopes, bindings, callables, references,
                calls, captures, seen,
            );
        }
        return;
    }
    if node.kind == "Identifier" && !is_declaration(parent) {
        record_reference(
            node, source, parent, scope, functions, scopes, bindings, callables, references, captures,
            seen,
        );
    }
    if node.kind == "CallExpression" {
        record_call(node, source, parent, scope, functions, scopes, bindings, callables, calls);
    }
    if node.kind == "ReturnStatement" {
        record_return(node, source, scope, functions, scopes, bindings, callables);
    }
    for child in &node.children {
        walk_uses(
            child, source, Some(node), scope, functions, scopes, bindings, callables, references,
            calls, captures, seen,
        );
    }
}

fn record_reference(
    node: &BNode,
    source: &str,
    parent: Option<&BNode>,
    scope: usize,
    functions: &[usize],
    scopes: &[Scope],
    bindings: &[BindingFact],
    callables: &[RawCallable],
    references: &mut Vec<ReferenceFact>,
    captures: &mut Vec<CaptureFact>,
    seen: &mut HashSet<String>,
) {
    let Some(name) = &node.name else { return };
    let role = if parent.is_some_and(|parent| {
        parent.kind == "AssignmentExpression"
            && parent
                .children
                .iter()
                .find(|child| child.kind == "Identifier")
                .is_some_and(|left| left.start == node.start && left.end == node.end)
    }) {
        "write"
    } else {
        "read"
    };
    let key = format!("{}:{role}:{name}", node.start);
    if !seen.insert(key) {
        return;
    }
    let binding_id = node
        .symbol
        .and_then(|symbol| resolve_symbol(symbol, bindings))
        .or_else(|| resolve_name(scope, name, scopes, bindings));
    let range = range_of(source, node.start, node.end);
    if let (Some(binding_id), Some(callable)) = (
        &binding_id,
        functions.last().and_then(|index| callables.get(*index)),
    ) {
        let binding = bindings.iter().find(|binding| &binding.binding_id == binding_id);
        if let Some(binding) = binding {
            if !scope_contains(binding.scope_index, callable.scope_index, scopes) {
                if !captures.iter().any(|capture| {
                    capture.binding_id == *binding_id && capture.callable_id == callable.callable_id
                }) {
                    captures.push(CaptureFact {
                        binding_id: binding_id.clone(),
                        callable_id: callable.callable_id.clone(),
                        range: range.clone(),
                    });
                }
            }
        }
    }
    references.push(ReferenceFact {
        index: references.len(),
        name: name.clone(),
        role: role.to_string(),
        range,
        binding_id,
    });
}

fn scope_contains(binding_scope: usize, function_scope: usize, scopes: &[Scope]) -> bool {
    let mut current = Some(binding_scope);
    while let Some(index) = current {
        if index == function_scope {
            return true;
        }
        current = scopes[index].parent;
    }
    false
}

fn record_call(
    node: &BNode,
    source: &str,
    parent: Option<&BNode>,
    scope: usize,
    functions: &[usize],
    scopes: &[Scope],
    bindings: &[BindingFact],
    callables: &[RawCallable],
    calls: &mut Vec<CallFact>,
) {
    let Some(callee) = node.children.iter().find(|child| child.kind == "Identifier") else {
        return;
    };
    let Some(name) = &callee.name else { return };
    let binding_id = callee
        .symbol
        .and_then(|symbol| resolve_symbol(symbol, bindings))
        .or_else(|| resolve_name(scope, name, scopes, bindings));
    let binding = binding_id
        .as_ref()
        .and_then(|id| bindings.iter().find(|binding| &binding.binding_id == id));
    let (resolution, frontier) = match binding.map(|binding| binding.kind.as_str()) {
        Some("import") => (
            "unresolved",
            Some(format!("Call target {name} is imported from outside this source.")),
        ),
        Some("function") => ("exact", None),
        _ => ("unresolved", Some(format!("Call target {name} is unresolved."))),
    };
    let arguments = node
        .children
        .iter()
        .skip(1)
        .map(|arg| range_of(source, arg.start, arg.end))
        .collect();
    let result_binding_id = parent.and_then(|parent| {
        if parent.kind != "AssignmentExpression" {
            return None;
        }
        let left = parent.children.iter().find(|child| child.kind == "Identifier")?;
        left.symbol
            .and_then(|symbol| resolve_symbol(symbol, bindings))
            .or_else(|| left.name.as_ref().and_then(|name| resolve_name(scope, name, scopes, bindings)))
    });
    let caller = functions.last().and_then(|index| callables.get(*index)).map(|c| c.callable_id.clone());
    calls.push(CallFact {
        call_id: format!("call:call:{}:{}", node.start, node.end),
        range: range_of(source, node.start, node.end),
        callee_range: range_of(source, callee.start, callee.end),
        caller_callable_id: caller,
        callee_name: name.clone(),
        resolution: resolution.to_string(),
        arguments,
        result_binding_id,
        frontier_reason: frontier,
    });
}

fn record_return(
    node: &BNode,
    source: &str,
    scope: usize,
    functions: &[usize],
    scopes: &[Scope],
    bindings: &[BindingFact],
    callables: &mut [RawCallable],
) {
    let Some(index) = functions.last().copied() else { return };
    let Some(callable) = callables.get(index) else { return };
    let range = range_of(source, node.start, node.end);
    let argument = node.children.first();
    let (identity, status, reason) = match argument {
        Some(arg) if arg.kind == "Identifier" => {
            let binding_id = arg
                .symbol
                .and_then(|symbol| resolve_symbol(symbol, bindings))
                .or_else(|| arg.name.as_ref().and_then(|name| resolve_name(scope, name, scopes, bindings)));
            let binding = binding_id
                .as_ref()
                .and_then(|id| bindings.iter().find(|binding| &binding.binding_id == id));
            (
                Some(range_of(source, arg.start, arg.end)),
                binding.map(|b| b.value_status.clone()).unwrap_or_else(|| "unknown".into()),
                binding.map(|b| b.value_reason.clone()).unwrap_or_else(|| "Unknown value.".into()),
            )
        }
        Some(arg) if arg.kind == "BinaryExpression" && arg.operator.as_deref() == Some("+") => {
            (None, "unknown".into(), "Non-primitive addition.".into())
        }
        Some(arg) => (None, "unknown".into(), format!("Unsupported {} value.", arg.kind)),
        None => (None, "unknown".into(), "Return has no value.".into()),
    };
    let return_id = format!(
        "{}:return:{}:{}:{}:{}",
        callable.callable_id, range.start_line, range.start_column, range.end_line, range.end_column
    );
    if let Some(callable) = callables.get_mut(index) {
        callable.returns.push(ReturnFact {
            return_id,
            range,
            identity,
            value_status: status,
            value_reason: reason,
        });
    }
}

fn is_declaration(parent: Option<&BNode>) -> bool {
    parent.is_some_and(|parent| {
        matches!(parent.kind, "ImportSpecifier" | "FunctionDeclaration" | "VariableDeclarator")
    })
}

fn scope_index(scopes: &[Scope], kind: &str, start: u32, end: u32) -> Option<usize> {
    let id = format!("scope:{kind}:{start}:{end}");
    scopes.iter().position(|scope| scope.id == id)
}

fn export_facts(program: &BNode, callables: &[RawCallable]) -> Vec<ExportFact> {
    let mut exports = Vec::new();
    fn walk(node: &BNode, callables: &[RawCallable], exports: &mut Vec<ExportFact>) {
        if node.kind == "ExportNamedDeclaration" {
            if let Some(func) = node.children.iter().find(|child| child.kind == "FunctionDeclaration") {
                if let Some(callable) = callables.iter().find(|callable| callable.start == func.start) {
                    let ret = callable.returns.first();
                    exports.push(ExportFact {
                        local_name: callable.name.clone(),
                        exported_name: callable.name.clone(),
                        callable_id: callable.callable_id.clone(),
                        range: callable.range.clone(),
                        value_status: ret.map(|r| r.value_status.clone()).unwrap_or_else(|| "unknown".into()),
                        value_reason: ret.map(|r| r.value_reason.clone()).unwrap_or_default(),
                        return_range: ret.map(|r| r.range.clone()),
                    });
                }
            }
        }
        for child in &node.children {
            walk(child, callables, exports);
        }
    }
    walk(program, callables, &mut exports);
    exports
}

fn import_facts(
    source: &str,
    path: &str,
    files: &BTreeSet<String>,
    program: &BNode,
) -> Vec<ImportFact> {
    let mut imports = Vec::new();
    fn walk(
        node: &BNode,
        source: &str,
        path: &str,
        files: &BTreeSet<String>,
        imports: &mut Vec<ImportFact>,
    ) {
        if node.kind == "ImportDeclaration" {
            let specifier = node
                .children
                .iter()
                .find(|child| child.kind == "StringLiteral")
                .and_then(|child| child.name.clone())
                .unwrap_or_default();
            let resolved = resolve_specifier(path, &specifier, files);
            for spec in node.children.iter().filter(|child| child.kind == "ImportSpecifier") {
                let idents: Vec<&BNode> = spec.children.iter().filter(|child| child.kind == "Identifier").collect();
                if idents.len() >= 2 {
                    imports.push(ImportFact {
                        specifier: specifier.clone(),
                        imported_name: idents[0].name.clone().unwrap_or_default(),
                        local_name: idents[1].name.clone().unwrap_or_default(),
                        local_range: range_of(source, idents[1].start, idents[1].end),
                        declaration_range: range_of(source, node.start, node.end),
                        resolved_path: resolved.clone(),
                    });
                }
            }
        }
        for child in &node.children {
            walk(child, source, path, files, imports);
        }
    }
    walk(program, source, path, files, &mut imports);
    imports
}

fn resolve_specifier(from: &str, specifier: &str, files: &BTreeSet<String>) -> Option<String> {
    if !specifier.starts_with('.') {
        return None;
    }
    let dir = from.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");
    let joined = if dir.is_empty() {
        specifier.trim_start_matches("./").to_string()
    } else {
        format!("{dir}/{specifier}")
    };
    let normalized = normalize_path(&joined);
    files.contains(&normalized).then_some(normalized)
}

fn normalize_path(path: &str) -> String {
    let mut parts = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            parts.pop();
        } else {
            parts.push(part);
        }
    }
    parts.join("/")
}

fn finish_callables(
    callables: &[RawCallable],
    calls: &[CallFact],
    captures: &[CaptureFact],
) -> Vec<CallableFact> {
    callables
        .iter()
        .map(|callable| {
            let mut shapes = vec![format!("returns:{}:complete", callable.returns.len())];
            for call in calls.iter().filter(|call| call.caller_callable_id.as_deref() == Some(callable.callable_id.as_str())) {
                let callees = if call.resolution == "exact" { 1 } else { 0 };
                shapes.push(format!(
                    "call:call:{}:{}:{callees}",
                    call.resolution,
                    call.arguments.len()
                ));
            }
            let capture_count = captures
                .iter()
                .filter(|capture| capture.callable_id == callable.callable_id)
                .count();
            shapes.push(format!("captures:{capture_count}"));
            CallableFact {
                callable_id: callable.callable_id.clone(),
                name: callable.name.clone(),
                start: callable.start,
                end: callable.end,
                range: callable.range.clone(),
                scope_index: callable.scope_index,
                arity: callable.arity,
                returns: callable.returns.clone(),
                fingerprint: FingerprintFact {
                    normalized_ast_sha256: digest_strings(&fingerprint_tokens(&callable.node)),
                    control_flow_sha256: digest_strings(&control_tokens(&callable.node)),
                    relation_shape_sha256: digest_strings(&shapes),
                    literal_set_sha256: digest_strings(&literal_tokens(&callable.node)),
                    parameter_arity: callable.arity,
                },
            }
        })
        .collect()
}

fn fingerprint_tokens(node: &BNode) -> Vec<String> {
    let mut out = Vec::new();
    fn walk(node: &BNode, out: &mut Vec<String>) {
        out.push(normalized_token(node));
        for child in &node.children {
            walk(child, out);
        }
    }
    walk(node, &mut out);
    out
}

fn normalized_token(node: &BNode) -> String {
    if node.kind == "Identifier" {
        return "identifier".into();
    }
    if node.kind == "StringLiteral" {
        return "string-literal".into();
    }
    let mut parts = vec![node.kind.to_string()];
    if let Some(op) = &node.operator {
        parts.push(format!("operator={op}"));
    }
    if let Some(kind) = &node.var_kind {
        parts.push(format!("kind={kind}"));
    }
    if node.kind == "FunctionDeclaration" {
        parts.push(format!("async={}", node.r#async));
        parts.push(format!("generator={}", node.generator));
    }
    parts.join(":")
}

fn control_tokens(node: &BNode) -> Vec<String> {
    let mut out = Vec::new();
    fn walk(node: &BNode, out: &mut Vec<String>) {
        if matches!(
            node.kind,
            "ForOfStatement" | "ForStatement" | "ForInStatement" | "ReturnStatement"
                | "IfStatement" | "WhileStatement" | "DoWhileStatement"
        ) {
            out.push(node.kind.to_string());
        }
        for child in &node.children {
            walk(child, out);
        }
    }
    walk(node, &mut out);
    out
}

fn literal_tokens(node: &BNode) -> Vec<String> {
    let mut out = Vec::new();
    fn walk(node: &BNode, out: &mut Vec<String>) {
        if node.kind == "NumericLiteral" {
            if let Some(value) = node.number {
                out.push(format!("number:{}", format_number(value)));
            }
        }
        for child in &node.children {
            walk(child, out);
        }
    }
    walk(node, &mut out);
    out.sort();
    out.dedup();
    out
}

fn format_number(value: f64) -> String {
    if value.fract() == 0.0 && value.abs() < i64::MAX as f64 {
        format!("{}", value as i64)
    } else {
        format!("{value}")
    }
}

fn digest_strings(values: &[String]) -> String {
    let encoded = serde_json::to_string(values).unwrap_or_else(|_| "[]".into());
    let mut hasher = Sha256::new();
    hasher.update(encoded.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn range_of(source: &str, start: u32, end: u32) -> SourceRange {
    SourceRange {
        start_line: point(source, start).0,
        start_column: point(source, start).1,
        end_line: point(source, end).0,
        end_column: point(source, end).1,
    }
}

fn point(source: &str, offset: u32) -> (u32, u32) {
    let mut line = 1u32;
    let mut column = 0u32;
    for (index, ch) in source.char_indices() {
        if index >= offset as usize {
            break;
        }
        if ch == '\n' {
            line += 1;
            column = 0;
        } else {
            column += 1;
        }
    }
    (line, column)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_fingerprints_match_rea() {
        let main = include_str!("../../../../fixtures/js/app/src/main.js");
        let math = include_str!("../../../../fixtures/js/app/src/math.js");
        let files = BTreeSet::from(["src/main.js".into(), "src/math.js".into()]);
        let main_facts = recover_module(main, "src/main.js", &files).unwrap();
        let math_facts = recover_module(math, "src/math.js", &files).unwrap();
        let total = main_facts.callables.iter().find(|c| c.name == "total").unwrap();
        let add = math_facts.callables.iter().find(|c| c.name == "add").unwrap();
        assert_eq!(
            &total.fingerprint.normalized_ast_sha256[..8],
            "70716a74",
            "ast {}",
            total.fingerprint.normalized_ast_sha256
        );
        assert_eq!(&total.fingerprint.control_flow_sha256[..8], "e487932f");
        assert_eq!(&total.fingerprint.relation_shape_sha256[..8], "48c265d5");
        assert_eq!(&total.fingerprint.literal_set_sha256[..8], "599532fd");
        assert_eq!(main_facts.visited_ast_nodes, 31);
        assert_eq!(math_facts.visited_ast_nodes, 12);
        assert_eq!(main_facts.references.len(), 6);
        assert_eq!(main_facts.calls.len(), 1);
        assert_eq!(main_facts.captures.len(), 1);
        assert_eq!(add.returns.len(), 1);
        assert_eq!(add.returns[0].value_reason, "Non-primitive addition.");
        let _ = add;
    }
}
