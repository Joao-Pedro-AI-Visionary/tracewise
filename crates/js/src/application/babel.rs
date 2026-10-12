//! Babel-shaped tree built from an oxc parse plus oxc semantic bindings.
//!
//! REA's application graph identities use Babel `node.start`/`node.end` and
//! `VISITOR_KEYS` order. oxc spans are UTF-8 byte offsets; they match Babel on
//! the ASCII fixture. Semantic analysis fills `reference_id` so a reference
//! resolves to the symbol span Babel would bind.

use std::collections::BTreeSet;

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, AssignmentTarget, BindingPatternKind, Declaration, ExportNamedDeclaration,
    Expression, ForStatementLeft, Function, ImportDeclaration, ImportDeclarationSpecifier,
    ModuleExportName, Statement, VariableDeclarationKind,
};
use oxc_parser::Parser;
use oxc_semantic::SemanticBuilder;
use oxc_span::SourceType;

use crate::error::JsError;

#[derive(Clone, Debug)]
pub struct BNode {
    pub kind: &'static str,
    pub start: u32,
    pub end: u32,
    pub name: Option<String>,
    pub number: Option<f64>,
    pub operator: Option<String>,
    pub var_kind: Option<String>,
    /// oxc symbol span this identifier reference resolves to.
    pub symbol: Option<(u32, u32)>,
    pub r#async: bool,
    pub generator: bool,
    pub children: Vec<BNode>,
}

#[allow(dead_code)]
pub struct ParsedModule {
    pub program: BNode,
    pub symbols: BTreeSet<(u32, u32)>,
    pub len: u32,
}

pub fn parse_module(source: &str) -> Result<ParsedModule, JsError> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::mjs()).parse();
    if !parsed.errors.is_empty() {
        return Err(JsError::InvalidInput(
            "JavaScript parser rejected the source".into(),
        ));
    }
    let semantic = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(&parsed.program);
    if !semantic.errors.is_empty() {
        return Err(JsError::InvalidInput(
            "JavaScript semantic analysis rejected the source".into(),
        ));
    }
    let scoping = semantic.semantic.scoping();
    let mut symbols = BTreeSet::new();
    for id in scoping.symbol_ids() {
        let span = scoping.symbol_span(id);
        symbols.insert((span.start, span.end));
    }
    let program = program_node(&parsed.program, scoping);
    Ok(ParsedModule {
        program,
        symbols,
        len: source.len() as u32,
    })
}

fn program_node(
    program: &oxc_ast::ast::Program<'_>,
    scoping: &oxc_semantic::Scoping,
) -> BNode {
    let mut children = Vec::new();
    for stmt in &program.body {
        children.push(statement_node(stmt, scoping));
    }
    node("Program", program.span.start, program.span.end, children)
}

fn statement_node(stmt: &Statement<'_>, scoping: &oxc_semantic::Scoping) -> BNode {
    match stmt {
        Statement::ImportDeclaration(decl) => import_node(decl, scoping),
        Statement::ExportNamedDeclaration(decl) => export_named(decl, scoping),
        Statement::FunctionDeclaration(func) => function_node(func, scoping),
        Statement::VariableDeclaration(decl) => variable_node(decl, scoping),
        Statement::ForOfStatement(stmt) => {
            let mut children = Vec::new();
            if let ForStatementLeft::VariableDeclaration(decl) = &stmt.left {
                children.push(variable_node(decl, scoping));
            }
            children.push(expression_node(&stmt.right, scoping));
            children.push(statement_node(&stmt.body, scoping));
            node("ForOfStatement", stmt.span.start, stmt.span.end, children)
        }
        Statement::BlockStatement(block) => {
            let children = block
                .body
                .iter()
                .map(|stmt| statement_node(stmt, scoping))
                .collect();
            node("BlockStatement", block.span.start, block.span.end, children)
        }
        Statement::ExpressionStatement(stmt) => {
            let child = expression_node(&stmt.expression, scoping);
            node(
                "ExpressionStatement",
                stmt.span.start,
                stmt.span.end,
                vec![child],
            )
        }
        Statement::ReturnStatement(stmt) => {
            let children = stmt
                .argument
                .as_ref()
                .map(|expr| vec![expression_node(expr, scoping)])
                .unwrap_or_default();
            node(
                "ReturnStatement",
                stmt.span.start,
                stmt.span.end,
                children,
            )
        }
        _ => node("UnsupportedStatement", 0, 0, Vec::new()),
    }
}

fn import_node(decl: &ImportDeclaration<'_>, scoping: &oxc_semantic::Scoping) -> BNode {
    let mut children = Vec::new();
    if let Some(specifiers) = &decl.specifiers {
        for spec in specifiers {
            if let ImportDeclarationSpecifier::ImportSpecifier(spec) = spec {
                let imported = match &spec.imported {
                    ModuleExportName::IdentifierName(name) => {
                        ident(name.span.start, name.span.end, name.name.as_str(), None)
                    }
                    ModuleExportName::IdentifierReference(name) => ident(
                        name.span.start,
                        name.span.end,
                        name.name.as_str(),
                        symbol_of(name, scoping),
                    ),
                    ModuleExportName::StringLiteral(_) => {
                        ident(spec.span.start, spec.span.end, "", None)
                    }
                };
                let local = ident(
                    spec.local.span.start,
                    spec.local.span.end,
                    spec.local.name.as_str(),
                    None,
                );
                children.push(BNode {
                    kind: "ImportSpecifier",
                    start: spec.span.start,
                    end: spec.span.end,
                    children: vec![imported, local],
                    ..empty()
                });
            }
        }
    }
    children.push(string_literal(
        decl.source.span.start,
        decl.source.span.end,
        decl.source.value.as_str(),
    ));
    node(
        "ImportDeclaration",
        decl.span.start,
        decl.span.end,
        children,
    )
}

fn export_named(decl: &ExportNamedDeclaration<'_>, scoping: &oxc_semantic::Scoping) -> BNode {
    let mut children = Vec::new();
    if let Some(Declaration::FunctionDeclaration(func)) = &decl.declaration {
        children.push(function_node(func, scoping));
    }
    node(
        "ExportNamedDeclaration",
        decl.span.start,
        decl.span.end,
        children,
    )
}

fn function_node(func: &Function<'_>, scoping: &oxc_semantic::Scoping) -> BNode {
    let mut children = Vec::new();
    if let Some(id) = &func.id {
        children.push(ident(id.span.start, id.span.end, id.name.as_str(), None));
    }
    for param in &func.params.items {
        if let BindingPatternKind::BindingIdentifier(id) = &param.pattern.kind {
            children.push(ident(id.span.start, id.span.end, id.name.as_str(), None));
        }
    }
    if let Some(body) = &func.body {
        let body_children = body
            .statements
            .iter()
            .map(|stmt| statement_node(stmt, scoping))
            .collect();
        children.push(node(
            "BlockStatement",
            body.span.start,
            body.span.end,
            body_children,
        ));
    }
    BNode {
        kind: "FunctionDeclaration",
        start: func.span.start,
        end: func.span.end,
        r#async: func.r#async,
        generator: func.generator,
        children,
        ..empty()
    }
}

fn variable_node(
    decl: &oxc_ast::ast::VariableDeclaration<'_>,
    scoping: &oxc_semantic::Scoping,
) -> BNode {
    let var_kind = match decl.kind {
        VariableDeclarationKind::Var => "var",
        VariableDeclarationKind::Let => "let",
        VariableDeclarationKind::Const => "const",
        VariableDeclarationKind::Using | VariableDeclarationKind::AwaitUsing => "using",
    };
    let children = decl
        .declarations
        .iter()
        .map(|declarator| {
            let mut kids = Vec::new();
            if let BindingPatternKind::BindingIdentifier(id) = &declarator.id.kind {
                kids.push(ident(id.span.start, id.span.end, id.name.as_str(), None));
            }
            if let Some(init) = &declarator.init {
                kids.push(expression_node(init, scoping));
            }
            node(
                "VariableDeclarator",
                declarator.span.start,
                declarator.span.end,
                kids,
            )
        })
        .collect();
    BNode {
        kind: "VariableDeclaration",
        start: decl.span.start,
        end: decl.span.end,
        var_kind: Some(var_kind.to_string()),
        children,
        ..empty()
    }
}

fn expression_node(expr: &Expression<'_>, scoping: &oxc_semantic::Scoping) -> BNode {
    match expr {
        Expression::Identifier(id) => {
            ident(id.span.start, id.span.end, id.name.as_str(), symbol_of(id, scoping))
        }
        Expression::NumericLiteral(lit) => BNode {
            kind: "NumericLiteral",
            start: lit.span.start,
            end: lit.span.end,
            number: Some(lit.value),
            ..empty()
        },
        Expression::StringLiteral(lit) => {
            string_literal(lit.span.start, lit.span.end, lit.value.as_str())
        }
        Expression::AssignmentExpression(expr) => {
            let mut children = Vec::new();
            if let AssignmentTarget::AssignmentTargetIdentifier(id) = &expr.left {
                children.push(ident(
                    id.span.start,
                    id.span.end,
                    id.name.as_str(),
                    symbol_of(id, scoping),
                ));
            }
            children.push(expression_node(&expr.right, scoping));
            BNode {
                kind: "AssignmentExpression",
                start: expr.span.start,
                end: expr.span.end,
                operator: Some(expr.operator.as_str().to_string()),
                children,
                ..empty()
            }
        }
        Expression::CallExpression(expr) => {
            let mut children = vec![expression_node(&expr.callee, scoping)];
            for arg in &expr.arguments {
                children.push(argument_node(arg, scoping));
            }
            node(
                "CallExpression",
                expr.span.start,
                expr.span.end,
                children,
            )
        }
        Expression::BinaryExpression(expr) => BNode {
            kind: "BinaryExpression",
            start: expr.span.start,
            end: expr.span.end,
            operator: Some(expr.operator.as_str().to_string()),
            children: vec![
                expression_node(&expr.left, scoping),
                expression_node(&expr.right, scoping),
            ],
            ..empty()
        },
        _ => node("UnsupportedExpression", 0, 0, Vec::new()),
    }
}

fn argument_node(arg: &Argument<'_>, scoping: &oxc_semantic::Scoping) -> BNode {
    match arg {
        Argument::Identifier(id) => {
            ident(id.span.start, id.span.end, id.name.as_str(), symbol_of(id, scoping))
        }
        Argument::NumericLiteral(lit) => BNode {
            kind: "NumericLiteral",
            start: lit.span.start,
            end: lit.span.end,
            number: Some(lit.value),
            ..empty()
        },
        Argument::SpreadElement(spread) => expression_node(&spread.argument, scoping),
        _ => node("UnsupportedArgument", 0, 0, Vec::new()),
    }
}

fn symbol_of(
    id: &oxc_ast::ast::IdentifierReference<'_>,
    scoping: &oxc_semantic::Scoping,
) -> Option<(u32, u32)> {
    let reference_id = id.reference_id.get()?;
    let symbol_id = scoping.get_reference(reference_id).symbol_id()?;
    let span = scoping.symbol_span(symbol_id);
    Some((span.start, span.end))
}

fn ident(start: u32, end: u32, name: &str, symbol: Option<(u32, u32)>) -> BNode {
    BNode {
        kind: "Identifier",
        start,
        end,
        name: Some(name.to_string()),
        symbol,
        ..empty()
    }
}

fn string_literal(start: u32, end: u32, value: &str) -> BNode {
    BNode {
        kind: "StringLiteral",
        start,
        end,
        name: Some(value.to_string()),
        ..empty()
    }
}

fn node(kind: &'static str, start: u32, end: u32, children: Vec<BNode>) -> BNode {
    BNode {
        kind,
        start,
        end,
        children,
        ..empty()
    }
}

fn empty() -> BNode {
    BNode {
        kind: "",
        start: 0,
        end: 0,
        name: None,
        number: None,
        operator: None,
        var_kind: None,
        symbol: None,
        r#async: false,
        generator: false,
        children: Vec::new(),
    }
}

pub fn count_nodes(node: &BNode) -> usize {
    1 + node.children.iter().map(count_nodes).sum::<usize>()
}
