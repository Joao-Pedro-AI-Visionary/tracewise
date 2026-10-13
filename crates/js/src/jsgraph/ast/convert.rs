//! oxc parse tree -> Babel-shaped [`Ast`].
//!
//! Every conversion follows what `@babel/parser` 8 (plugins `decorators-legacy`, `jsx`,
//! `typescript`) produces for the same source. The AST parity test
//! (`crates/js/tests/jsgraph_ast_parity_test.rs`) diffs this output against the real Babel
//! parser. Syntax this converter does not know yields [`ConvertError`], never a made-up node.

use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_parser::{ParseOptions as OxcParseOptions, Parser};
use oxc_span::{GetSpan, SourceType, Span};

use super::{Ast, Comment, Kind, NodeData, NodeId, Source, Val};

/// Options chosen from the source path (REA `parserPluginsForPath`).
#[derive(Clone, Debug, Default)]
pub struct ParseOptions<'a> {
    pub path: Option<&'a str>,
}

/// Why a source could not be turned into a Babel-shaped tree.
#[derive(Debug)]
pub enum ConvertError {
    /// The parser could not recover a program (Babel would throw).
    Unparseable(String),
    /// A syntax node this port does not convert yet.
    Unsupported(String),
    /// The syntax tree is nested deeper than [`super::MAX_AST_DEPTH`]; nothing was converted.
    TooDeep(String),
}

/// `BigInt(raw).toString()` for a literal such as `0x1Fn` or `1_000n`.
pub(super) fn bigint_decimal(raw: &str) -> String {
    let text: String = raw.trim_end_matches('n').chars().filter(|c| *c != '_').collect();
    let (radix, digits) = match text.get(..2) {
        Some("0x") | Some("0X") => (16u32, &text[2..]),
        Some("0o") | Some("0O") => (8, &text[2..]),
        Some("0b") | Some("0B") => (2, &text[2..]),
        _ => (10, &text[..]),
    };
    if radix == 10 {
        let trimmed = digits.trim_start_matches('0');
        return if trimmed.is_empty() { "0".into() } else { trimmed.to_string() };
    }
    // little-endian base 1e9 limbs
    let mut limbs: Vec<u64> = vec![0];
    for ch in digits.chars() {
        let Some(digit) = ch.to_digit(radix) else { return text };
        let mut carry = digit as u64;
        for limb in limbs.iter_mut() {
            let value = *limb * radix as u64 + carry;
            *limb = value % 1_000_000_000;
            carry = value / 1_000_000_000;
        }
        while carry > 0 {
            limbs.push(carry % 1_000_000_000);
            carry /= 1_000_000_000;
        }
    }
    let mut out = format!("{}", limbs.last().copied().unwrap_or(0));
    for limb in limbs.iter().rev().skip(1) {
        out.push_str(&format!("{limb:09}"));
    }
    out
}

fn source_type_for(path: Option<&str>, module: bool) -> SourceType {
    let path = path.unwrap_or("").to_ascii_lowercase();
    let dts = path.ends_with(".d.ts") || path.ends_with(".d.mts") || path.ends_with(".d.cts");
    let ts_like = path.ends_with(".ts") || path.ends_with(".cts") || path.ends_with(".mts");
    let tsx = path.ends_with(".tsx");
    let base = SourceType::default()
        .with_typescript(true)
        .with_module(module)
        .with_script(!module);
    if dts {
        base.with_typescript_definition(true).with_jsx(false)
    } else if tsx || !ts_like {
        base.with_jsx(true)
    } else {
        base.with_jsx(false)
    }
}

/// Parse `text` like REA's `parseJavaScriptSource` (Babel `sourceType: "unambiguous"`).
///
/// Babel parses as a module first; without ESM syntax (`import`/`export`, `import.meta`,
/// top-level `await`) the same tree is returned as a script, and a module parse failure falls
/// back to a script parse.
pub fn parse_babel(text: &str, options: &ParseOptions<'_>) -> Result<Ast, ConvertError> {
    match parse_once(text, options, true) {
        Ok(ast) => Ok(ast),
        // Babel's `unambiguous` retries as a script only when the module parse *throws*.
        // A parse that failed on nesting depth fails the same way as a script: skip the retry.
        Err(ConvertError::Unparseable(module_error)) if module_error != oxc_parser::NESTING_ERROR_MESSAGE => {
            parse_once(text, options, false).map_err(|error| match error {
                ConvertError::Unparseable(_) => ConvertError::Unparseable(module_error),
                other => other,
            })
        }
        Err(other) => Err(other),
    }
}

/// oxc messages for syntax errors Babel reports as recoverable (partial parse, not a throw).
const BABEL_RECOVERABLE: &[&str] = &[
    "Cannot assign to this expression",
    "mentioned twice in regular expression",
    "Spread must be last element",
    "Dynamic imports can only accept",
    "Invalid Character",
    "Expected `;` but found",
    "is a reserved word that cannot be used here",
];

/// oxc checker messages for forms Babel accepts without an error: signatures without an
/// implementation (overloads, ambient members) are never diagnosed by its parser. Strict-mode
/// binding rules do not apply inside ambient code either (definition files and `declare`
/// statements; Babel parses those as sloppy), see `in_ambient_code`.
fn in_ambient_code(error: &oxc_diagnostics::OxcDiagnostic, definition_file: bool, declared: &[(usize, usize)]) -> bool {
    definition_file
        || error.labels.iter().flatten().any(|label| {
            declared.iter().any(|(start, end)| label.offset() >= *start && label.offset() < *end)
        })
}

const BABEL_ACCEPTS: &[&str] = &[
    "Function implementation is missing or not immediately following the declaration.",
    "Constructor implementation is missing.",
    "Getters and setters must have an implementation.",
];

/// Reserved words (`var static`, `var yield`, ...) for which Babel raises exactly one error.
/// `let` and `interface` are left out on purpose: Babel reports two errors for `let let`, and the
/// TypeScript plugin throws on `interface = 1`.
const RESERVED_ONE_ERROR: &[&str] = &["static", "implements", "package", "private", "public", "protected", "yield"];

/// True for the oxc diagnostics that Babel records as exactly one recoverable error with the same
/// syntax tree (checked against the live Babel parse by `jsgraph_ast_parity_test`).
fn babel_counts_one_error(message: &str) -> bool {
    const EXACT: &[&str] = &[
        "'with' statements are not allowed",
        "'0'-prefixed octal literals and octal escape sequences are deprecated",
        "Decimals with leading zeros are not allowed in strict mode",
        "Invalid escape sequence",
        "Bad escape sequence in untagged template literal",
        "Cannot assign to 'eval' in strict mode",
        "Cannot assign to 'arguments' in strict mode",
        "Delete of an unqualified identifier in strict mode.",
        "Illegal break statement",
        "Jump target cannot cross function boundary.",
        "Unexpected new.target expression",
        "Missing initializer in const declaration",
        "Missing initializer in destructuring declaration",
        "Super calls are not permitted outside constructors or in nested functions inside constructors.",
        "'super' can only be referenced in a derived class.",
        "'super' can only be referenced in members of derived classes or object literal expressions.",
        "Illegal 'use strict' directive in function with non-simple parameter list",
        "Invalid function declaration",
        "for-in loop variable declaration may not have an initializer",
        "for-of loop variable declaration may not have an initializer",
        "await expression not allowed in formal parameter",
        "yield expression not allowed in formal parameter",
    ];
    if EXACT.contains(&message) {
        return true;
    }
    let between = |prefix: &str, suffix: &str| {
        message.strip_prefix(prefix).and_then(|rest| rest.strip_suffix(suffix)).is_some()
    };
    if between("Identifier `", "` has already been declared") || between("Label `", "` has already been declared") {
        return true;
    }
    if message.starts_with("Illegal continue statement") {
        return true;
    }
    message
        .strip_prefix("The keyword '")
        .and_then(|rest| rest.strip_suffix("' is reserved"))
        .is_some_and(|word| RESERVED_ONE_ERROR.contains(&word))
}

fn parse_once(text: &str, options: &ParseOptions<'_>, module: bool) -> Result<Ast, ConvertError> {
    let allocator = Allocator::default();
    let mut parsed = Parser::new(&allocator, text, source_type_for(options.path, module))
        .with_options(OxcParseOptions {
            preserve_parens: false,
            allow_return_outside_function: true,
            ..OxcParseOptions::default()
        })
        .parse();
    if parsed.panicked {
        // The parser could not continue: Babel throws too, and REA records a parse failure.
        let message = parsed
            .errors
            .first()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "parser panicked".into());
        // Hostile nesting: Babel overflows its own stack here and REA records a parse failure.
        if parsed.errors.iter().any(|e| e.to_string() == oxc_parser::NESTING_ERROR_MESSAGE) {
            return Err(ConvertError::Unparseable(oxc_parser::NESTING_ERROR_MESSAGE.to_string()));
        }
        // oxc stops at a few syntax errors that Babel (`errorRecovery`) records and keeps going.
        if BABEL_RECOVERABLE.iter().any(|pattern| message.contains(pattern)) {
            return Err(ConvertError::Unsupported(format!(
                "recoverable syntax error: {message}"
            )));
        }
        return Err(ConvertError::Unparseable(message));
    }
    // The semantic pass and the conversion recurse over the tree: refuse a tree too deep for them.
    if super::depth::program_depth_exceeds(&parsed.program, super::MAX_AST_DEPTH) {
        return Err(ConvertError::TooDeep(format!(
            "the syntax tree is nested deeper than {} levels",
            super::MAX_AST_DEPTH
        )));
    }
    // Early errors (redeclarations, strict-mode rules) come from the semantic pass in oxc;
    // Babel reports the same class while parsing.
    let definition_file = parsed.program.source_type.is_typescript_definition();
    let declared = super::convert_scope::declare_spans(&parsed.program);
    // oxc builds no scopes or bindings for definition files (`.d.ts`), while Babel's scope
    // tracker keeps declaring names in ambient mode (export checks, redeclarations). Run the
    // semantic pass as for a regular TypeScript file; the parse above already used ambient
    // rules, so bodiless members and `declare` forms are accepted. Nothing downstream reads
    // `Program::source_type` except its module flag. (`with_typescript_definition(false)` is
    // a no-op in oxc, hence `with_typescript(true)`.)
    // Its checker also rejects ambient forms that are valid there (bodiless functions and
    // constructors); those messages are filtered below.
    if definition_file {
        parsed.program.source_type = parsed.program.source_type.with_typescript(true);
    }
    // The pass runs even when the parse recovered from errors: Babel counts those too.
    let built = Some(
        oxc_semantic::SemanticBuilder::new()
            .with_check_syntax_error(true)
            .build(&parsed.program),
    );
    let early_errors: Vec<_> = built
        .as_ref()
        .map(|b| {
            b.errors
                .iter()
                // Babel accepts repeated constructor overload-like members without an error.
                .filter(|e| !e.to_string().contains("Multiple constructor implementations"))
                .filter(|e| !BABEL_ACCEPTS.iter().any(|m| e.to_string().contains(m)))
                .filter(|e| !(e.to_string().ends_with(" in strict mode") && in_ambient_code(e, definition_file, &declared)))
                .collect()
        })
        .unwrap_or_default();
    // Babel (`errorRecovery`) keeps going after these errors, returns the same tree and counts one
    // error per diagnostic (`file.errors.length`, which REA reports as a partial parse). Only the
    // diagnostics verified to map one-to-one are accepted; any other would risk a different tree
    // or error count, so it is reported as unsupported instead of answered with a wrong status.
    let messages: Vec<String> = parsed
        .errors
        .iter()
        .chain(early_errors.iter().copied())
        .map(|e| e.to_string())
        .collect();
    if let Some(unknown) = messages.iter().find(|message| !babel_counts_one_error(message)) {
        return Err(ConvertError::Unsupported(format!("recoverable syntax error: {unknown}")));
    }
    let recovered_errors = messages.len();
    let source = Source::new(text);
    let mut cx = Cx {
        src: &source,
        nodes: Vec::new(),
        unsupported: None,
        fn_depth: 0,
        saw_esm: false,
        recoverable_errors: 0,
        strict: module,
        scoping: built.as_ref().map(|b| b.semantic.scoping()),
        scope: super::convert_scope::ScopeState::new(definition_file),
    };
    let root = cx.program(&parsed.program);
    if let Some(what) = cx.scope.unparseable.take() {
        return Err(ConvertError::Unparseable(what));
    }
    if let Some(what) = cx.unsupported.take() {
        return Err(ConvertError::Unsupported(what));
    }
    let source_type = if module && cx.saw_esm { "module" } else { "script" };
    cx.set(root, "sourceType", string(source_type));
    let recoverable = cx.recoverable_errors + recovered_errors;
    let nodes = std::mem::take(&mut cx.nodes);
    let comments = parsed
        .program
        .comments
        .iter()
        .map(|comment| {
            let start = source.unit_of_byte(comment.span.start);
            let end = source.unit_of_byte(comment.span.end);
            let block = matches!(comment.kind, CommentKind::Block);
            let (from, to) = if block {
                (start + 2, end.saturating_sub(2).max(start + 2))
            } else {
                (start + 2, end)
            };
            Comment {
                block,
                start,
                end,
                value: source.slice(from, to).to_string(),
            }
        })
        .collect();
    let mut ast = Ast {
        nodes,
        root,
        source,
        comments,
        error_count: recoverable,
    };
    ast.link_parents();
    Ok(ast)
}

type Fields = Vec<(&'static str, Val)>;

/// Stack kept free below every recursive conversion call, and the size of each extra segment.
const STACK_RED_ZONE: usize = 512 * 1024;
const STACK_SEGMENT: usize = 32 * 1024 * 1024;

/// Run one recursive conversion step, moving to a fresh heap-allocated stack segment when the
/// current one is nearly used up. The conversion recurses once per tree level, and a chain such
/// as `a.b.b.b...` (parsed iteratively) is as deep as the file is long.
pub(super) fn grow<R>(step: impl FnOnce() -> R) -> R {
    stacker::maybe_grow(STACK_RED_ZONE, STACK_SEGMENT, step)
}

pub(super) struct Cx<'s> {
    pub(super) src: &'s Source,
    pub(super) nodes: Vec<NodeData>,
    pub(super) unsupported: Option<String>,
    /// Number of enclosing functions (for top-level `await` and `return` checks).
    pub(super) fn_depth: u32,
    /// ESM syntax seen (`import`/`export`, `import.meta`, top-level `await`).
    pub(super) saw_esm: bool,
    /// Errors Babel reports but recovers from (`'return' outside of function`).
    pub(super) recoverable_errors: usize,
    /// Strict-mode parse (the module attempt): Babel rejects duplicate block-level functions.
    pub(super) strict: bool,
    pub(super) scoping: Option<&'s oxc_semantic::Scoping>,
    /// Babel's module/namespace scope rules (export checks, namespace errors).
    pub(super) scope: super::convert_scope::ScopeState,
}

pub(super) fn node(id: NodeId) -> Val {
    Val::Node(id)
}
pub(super) fn opt(id: Option<NodeId>) -> Val {
    id.map_or(Val::Null, Val::Node)
}
pub(super) fn list(ids: Vec<NodeId>) -> Val {
    Val::List(ids.into_iter().map(Some).collect())
}
pub(super) fn string(text: &str) -> Val {
    Val::Str(text.to_string())
}
pub(super) fn flag(value: bool) -> Val {
    Val::Bool(value)
}

impl<'s> Cx<'s> {
    pub(super) fn u(&self, byte: u32) -> u32 {
        self.src.unit_of_byte(byte)
    }

    pub(super) fn span(&self, span: Span) -> (u32, u32) {
        (self.u(span.start), self.u(span.end))
    }

    pub(super) fn mk(&mut self, kind: Kind, start: u32, end: u32, fields: Fields) -> NodeId {
        let id = self.nodes.len() as NodeId;
        self.nodes.push(NodeData {
            kind,
            start,
            end,
            parent: None,
            fields,
        });
        id
    }

    pub(super) fn mks(&mut self, kind: Kind, span: Span, fields: Fields) -> NodeId {
        let (start, end) = self.span(span);
        self.mk(kind, start, end, fields)
    }

    pub(super) fn unsupported(&mut self, what: &str) -> NodeId {
        if self.unsupported.is_none() {
            self.unsupported = Some(what.to_string());
        }
        self.mk(Kind::EmptyStatement, 0, 0, Vec::new())
    }

    pub(super) fn set(&mut self, id: NodeId, key: &'static str, value: Val) {
        let fields = &mut self.nodes[id as usize].fields;
        if let Some(slot) = fields.iter_mut().find(|(name, _)| *name == key) {
            slot.1 = value;
        } else {
            fields.push((key, value));
        }
    }

    pub(super) fn set_end(&mut self, id: NodeId, end: u32) {
        self.nodes[id as usize].end = end;
    }

    pub(super) fn set_start(&mut self, id: NodeId, start: u32) {
        self.nodes[id as usize].start = start;
    }

    pub(super) fn end_of(&self, id: NodeId) -> u32 {
        self.nodes[id as usize].end
    }

    pub(super) fn start_of(&self, id: NodeId) -> u32 {
        self.nodes[id as usize].start
    }

    // ---- program ---------------------------------------------------------------------------

    fn program(&mut self, program: &Program<'_>) -> NodeId {
        self.prescan_imports(program);
        let directives = program
            .directives
            .iter()
            .map(|directive| self.directive(directive))
            .collect();
        let body = program
            .body
            .iter()
            .map(|statement| self.statement(statement))
            .collect();
        let interpreter = match &program.hashbang {
            Some(hashbang) => {
                let id = self.mks(
                    Kind::InterpreterDirective,
                    hashbang.span,
                    vec![("value", string(hashbang.value.as_str()))],
                );
                node(id)
            }
            None => Val::Null,
        };
        let source_type = if program.source_type.is_module() {
            "module"
        } else {
            "script"
        };
        self.mk(
            Kind::Program,
            0,
            self.src.len16(),
            vec![
                ("sourceType", string(source_type)),
                ("interpreter", interpreter),
                ("body", list(body)),
                ("directives", list(directives)),
            ],
        )
    }

    fn directive(&mut self, directive: &oxc_ast::ast::Directive<'_>) -> NodeId {
        let literal = self.mks(
            Kind::DirectiveLiteral,
            directive.expression.span,
            vec![("value", string(directive.directive.as_str()))],
        );
        self.mks(Kind::Directive, directive.span, vec![("value", node(literal))])
    }

    // ---- statements ------------------------------------------------------------------------

    pub(super) fn statement(&mut self, statement: &Statement<'_>) -> NodeId {
        grow(|| self.statement_inner(statement))
    }

    fn statement_inner(&mut self, statement: &Statement<'_>) -> NodeId {
        if let Some(declaration) = statement.as_declaration() {
            return self.declaration(declaration);
        }
        if let Some(module) = statement.as_module_declaration() {
            return self.module_declaration(module);
        }
        match statement {
            Statement::BlockStatement(block) => self.block(block),
            Statement::BreakStatement(stmt) => {
                let label = stmt.label.as_ref().map(|l| self.label(l));
                self.mks(Kind::BreakStatement, stmt.span, vec![("label", opt(label))])
            }
            Statement::ContinueStatement(stmt) => {
                let label = stmt.label.as_ref().map(|l| self.label(l));
                self.mks(Kind::ContinueStatement, stmt.span, vec![("label", opt(label))])
            }
            Statement::DebuggerStatement(stmt) => self.mks(Kind::DebuggerStatement, stmt.span, vec![]),
            Statement::DoWhileStatement(stmt) => {
                let body = self.statement(&stmt.body);
                let test = self.expression(&stmt.test);
                self.mks(
                    Kind::DoWhileStatement,
                    stmt.span,
                    vec![("body", node(body)), ("test", node(test))],
                )
            }
            Statement::EmptyStatement(stmt) => self.mks(Kind::EmptyStatement, stmt.span, vec![]),
            Statement::ExpressionStatement(stmt) => {
                let expression = self.expression(&stmt.expression);
                self.mks(
                    Kind::ExpressionStatement,
                    stmt.span,
                    vec![("expression", node(expression))],
                )
            }
            Statement::ForInStatement(stmt) => {
                let left = self.for_left(&stmt.left);
                let right = self.expression(&stmt.right);
                let body = self.statement(&stmt.body);
                self.mks(
                    Kind::ForInStatement,
                    stmt.span,
                    vec![("left", node(left)), ("right", node(right)), ("body", node(body))],
                )
            }
            Statement::ForOfStatement(stmt) => {
                let left = self.for_left(&stmt.left);
                let right = self.expression(&stmt.right);
                let body = self.statement(&stmt.body);
                self.mks(
                    Kind::ForOfStatement,
                    stmt.span,
                    vec![
                        ("await", flag(stmt.r#await)),
                        ("left", node(left)),
                        ("right", node(right)),
                        ("body", node(body)),
                    ],
                )
            }
            Statement::ForStatement(stmt) => {
                let init = stmt.init.as_ref().map(|init| match init {
                    ForStatementInit::VariableDeclaration(decl) => self.variable_declaration(decl),
                    other => {
                        let expression = other.to_expression();
                        self.expression(expression)
                    }
                });
                let test = stmt.test.as_ref().map(|e| self.expression(e));
                let update = stmt.update.as_ref().map(|e| self.expression(e));
                let body = self.statement(&stmt.body);
                self.mks(
                    Kind::ForStatement,
                    stmt.span,
                    vec![
                        ("init", opt(init)),
                        ("test", opt(test)),
                        ("update", opt(update)),
                        ("body", node(body)),
                    ],
                )
            }
            Statement::IfStatement(stmt) => {
                let test = self.expression(&stmt.test);
                let consequent = self.statement(&stmt.consequent);
                let alternate = stmt.alternate.as_ref().map(|s| self.statement(s));
                self.mks(
                    Kind::IfStatement,
                    stmt.span,
                    vec![
                        ("test", node(test)),
                        ("consequent", node(consequent)),
                        ("alternate", opt(alternate)),
                    ],
                )
            }
            Statement::LabeledStatement(stmt) => {
                let label = self.label(&stmt.label);
                let body = self.statement(&stmt.body);
                self.mks(
                    Kind::LabeledStatement,
                    stmt.span,
                    vec![("label", node(label)), ("body", node(body))],
                )
            }
            Statement::ReturnStatement(stmt) => {
                if self.fn_depth == 0 {
                    self.recoverable_errors += 1;
                }
                let argument = stmt.argument.as_ref().map(|e| self.expression(e));
                self.mks(Kind::ReturnStatement, stmt.span, vec![("argument", opt(argument))])
            }
            Statement::SwitchStatement(stmt) => {
                let discriminant = self.expression(&stmt.discriminant);
                let cases = stmt
                    .cases
                    .iter()
                    .map(|case| {
                        let test = case.test.as_ref().map(|e| self.expression(e));
                        let consequent = case.consequent.iter().map(|s| self.statement(s)).collect();
                        self.mks(
                            Kind::SwitchCase,
                            case.span,
                            vec![("test", opt(test)), ("consequent", list(consequent))],
                        )
                    })
                    .collect();
                self.mks(
                    Kind::SwitchStatement,
                    stmt.span,
                    vec![("discriminant", node(discriminant)), ("cases", list(cases))],
                )
            }
            Statement::ThrowStatement(stmt) => {
                let argument = self.expression(&stmt.argument);
                self.mks(Kind::ThrowStatement, stmt.span, vec![("argument", node(argument))])
            }
            Statement::TryStatement(stmt) => {
                let block = self.block(&stmt.block);
                let handler = stmt.handler.as_ref().map(|clause| {
                    let param = clause
                        .param
                        .as_ref()
                        .map(|param| self.binding_pattern(&param.pattern));
                    let body = self.block(&clause.body);
                    self.mks(
                        Kind::CatchClause,
                        clause.span,
                        vec![("param", opt(param)), ("body", node(body))],
                    )
                });
                let finalizer = stmt.finalizer.as_ref().map(|b| self.block(b));
                self.mks(
                    Kind::TryStatement,
                    stmt.span,
                    vec![
                        ("block", node(block)),
                        ("handler", opt(handler)),
                        ("finalizer", opt(finalizer)),
                    ],
                )
            }
            Statement::WhileStatement(stmt) => {
                let test = self.expression(&stmt.test);
                let body = self.statement(&stmt.body);
                self.mks(
                    Kind::WhileStatement,
                    stmt.span,
                    vec![("test", node(test)), ("body", node(body))],
                )
            }
            Statement::WithStatement(stmt) => {
                let object = self.expression(&stmt.object);
                let body = self.statement(&stmt.body);
                self.mks(
                    Kind::WithStatement,
                    stmt.span,
                    vec![("object", node(object)), ("body", node(body))],
                )
            }
            _ => self.unsupported("statement"),
        }
    }

    fn label(&mut self, label: &LabelIdentifier<'_>) -> NodeId {
        self.ident(label.name.as_str(), label.span)
    }

    pub(super) fn ident(&mut self, name: &str, span: Span) -> NodeId {
        self.mks(Kind::Identifier, span, vec![("name", string(name))])
    }

    fn block(&mut self, block: &BlockStatement<'_>) -> NodeId {
        if self.strict {
            let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
            for statement in &block.body {
                if let Statement::FunctionDeclaration(function) = statement {
                    if let Some(id) = &function.id {
                        if !seen.insert(id.name.as_str()) {
                            self.recoverable_errors += 1;
                        }
                    }
                }
            }
        }
        let body = block.body.iter().map(|s| self.statement(s)).collect();
        self.mks(
            Kind::BlockStatement,
            block.span,
            vec![("directives", list(vec![])), ("body", list(body))],
        )
    }

    fn for_left(&mut self, left: &ForStatementLeft<'_>) -> NodeId {
        match left {
            ForStatementLeft::VariableDeclaration(decl) => self.variable_declaration(decl),
            other => {
                let target = other.to_assignment_target();
                self.assignment_target(target)
            }
        }
    }

    pub(super) fn variable_declaration(&mut self, decl: &VariableDeclaration<'_>) -> NodeId {
        let entered = self.enter_declare(decl.declare);
        for declarator in &decl.declarations {
            self.ambient_declarator(decl.kind, declarator);
        }
        let id = self.variable_declaration_inner(decl);
        self.leave_declare(entered);
        id
    }

    fn variable_declaration_inner(&mut self, decl: &VariableDeclaration<'_>) -> NodeId {
        let declarations = decl
            .declarations
            .iter()
            .map(|d| {
                let id = self.binding_pattern(&d.id);
                let init = d.init.as_ref().map(|e| self.expression(e));
                let mut fields = vec![("id", node(id)), ("init", opt(init))];
                if d.definite {
                    fields.push(("definite", flag(true)));
                }
                self.mks(Kind::VariableDeclarator, d.span, fields)
            })
            .collect();
        let kind = match decl.kind {
            VariableDeclarationKind::Var => "var",
            VariableDeclarationKind::Let => "let",
            VariableDeclarationKind::Const => "const",
            VariableDeclarationKind::Using => "using",
            VariableDeclarationKind::AwaitUsing => "await using",
        };
        let mut fields = vec![("kind", string(kind)), ("declarations", list(declarations))];
        if decl.declare {
            fields.push(("declare", flag(true)));
        }
        self.mks(Kind::VariableDeclaration, decl.span, fields)
    }

    fn declaration(&mut self, declaration: &Declaration<'_>) -> NodeId {
        match declaration {
            Declaration::VariableDeclaration(decl) => self.variable_declaration(decl),
            Declaration::FunctionDeclaration(function) => self.function(function),
            Declaration::ClassDeclaration(class) => self.class(class),
            Declaration::TSTypeAliasDeclaration(decl) => self.ts_type_alias(decl),
            Declaration::TSInterfaceDeclaration(decl) => self.ts_interface(decl),
            Declaration::TSEnumDeclaration(decl) => self.ts_enum(decl),
            Declaration::TSModuleDeclaration(decl) => self.ts_module(decl),
            Declaration::TSImportEqualsDeclaration(decl) => self.ts_import_equals(decl),
        }
    }

    // ---- modules ---------------------------------------------------------------------------

    fn module_declaration(&mut self, decl: &ModuleDeclaration<'_>) -> NodeId {
        self.saw_esm = true;
        match decl {
            ModuleDeclaration::ImportDeclaration(import) => {
                self.note_import(import);
                self.import_declaration(import)
            }
            ModuleDeclaration::ExportAllDeclaration(export) => self.export_all(export),
            ModuleDeclaration::ExportDefaultDeclaration(export) => {
                let declaration = match &export.declaration {
                    ExportDefaultDeclarationKind::FunctionDeclaration(function) => {
                        self.function(function)
                    }
                    ExportDefaultDeclarationKind::ClassDeclaration(class) => self.class(class),
                    ExportDefaultDeclarationKind::TSInterfaceDeclaration(decl) => {
                        self.ts_interface(decl)
                    }
                    other => {
                        let expression = other.to_expression();
                        self.expression(expression)
                    }
                };
                self.mks(
                    Kind::ExportDefaultDeclaration,
                    export.span,
                    vec![("declaration", node(declaration))],
                )
            }
            ModuleDeclaration::ExportNamedDeclaration(export) => self.export_named(export),
            ModuleDeclaration::TSExportAssignment(assign) => {
                self.check_export_assignment(assign);
                let expression = self.expression(&assign.expression);
                self.mks(
                    Kind::TSExportAssignment,
                    assign.span,
                    vec![("expression", node(expression))],
                )
            }
            ModuleDeclaration::TSNamespaceExportDeclaration(decl) => {
                let id = self.ident(decl.id.name.as_str(), decl.id.span);
                self.mks(
                    Kind::TSNamespaceExportDeclaration,
                    decl.span,
                    vec![("id", node(id))],
                )
            }
        }
    }

    fn module_export_name(&mut self, name: &ModuleExportName<'_>) -> NodeId {
        match name {
            ModuleExportName::IdentifierName(id) => self.ident(id.name.as_str(), id.span),
            ModuleExportName::IdentifierReference(id) => self.ident(id.name.as_str(), id.span),
            ModuleExportName::StringLiteral(lit) => self.string_literal(lit),
        }
    }

    fn import_attributes(&mut self, clause: &Option<oxc_allocator::Box<'_, WithClause<'_>>>) -> Val {
        match clause {
            None => list(vec![]),
            Some(clause) => {
                let items = clause
                    .with_entries
                    .iter()
                    .map(|attribute| {
                        let key = match &attribute.key {
                            ImportAttributeKey::Identifier(id) => self.ident(id.name.as_str(), id.span),
                            ImportAttributeKey::StringLiteral(lit) => self.string_literal(lit),
                        };
                        let value = self.string_literal(&attribute.value);
                        self.mks(
                            Kind::ImportAttribute,
                            attribute.span,
                            vec![("key", node(key)), ("value", node(value))],
                        )
                    })
                    .collect();
                list(items)
            }
        }
    }

    fn import_kind(kind: ImportOrExportKind) -> &'static str {
        match kind {
            ImportOrExportKind::Value => "value",
            ImportOrExportKind::Type => "type",
        }
    }

    fn import_declaration(&mut self, import: &ImportDeclaration<'_>) -> NodeId {
        let specifiers = import
            .specifiers
            .as_ref()
            .map(|specifiers| {
                specifiers
                    .iter()
                    .map(|specifier| match specifier {
                        ImportDeclarationSpecifier::ImportSpecifier(spec) => {
                            let imported = self.module_export_name(&spec.imported);
                            let local = self.ident(spec.local.name.as_str(), spec.local.span);
                            self.mks(
                                Kind::ImportSpecifier,
                                spec.span,
                                vec![
                                    ("imported", node(imported)),
                                    ("local", node(local)),
                                    ("importKind", string(Self::import_kind(spec.import_kind))),
                                ],
                            )
                        }
                        ImportDeclarationSpecifier::ImportDefaultSpecifier(spec) => {
                            let local = self.ident(spec.local.name.as_str(), spec.local.span);
                            self.mks(
                                Kind::ImportDefaultSpecifier,
                                spec.span,
                                vec![("local", node(local))],
                            )
                        }
                        ImportDeclarationSpecifier::ImportNamespaceSpecifier(spec) => {
                            let local = self.ident(spec.local.name.as_str(), spec.local.span);
                            self.mks(
                                Kind::ImportNamespaceSpecifier,
                                spec.span,
                                vec![("local", node(local))],
                            )
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        let source = self.string_literal(&import.source);
        let attributes = self.import_attributes(&import.with_clause);
        let phase = match import.phase {
            Some(ImportPhase::Source) => string("source"),
            Some(ImportPhase::Defer) => string("defer"),
            None => Val::Null,
        };
        self.mks(
            Kind::ImportDeclaration,
            import.span,
            vec![
                ("phase", phase),
                ("importKind", string(Self::import_kind(import.import_kind))),
                ("specifiers", list(specifiers)),
                ("source", node(source)),
                ("attributes", attributes),
            ],
        )
    }

    fn export_all(&mut self, export: &ExportAllDeclaration<'_>) -> NodeId {
        let source = self.string_literal(&export.source);
        let attributes = self.import_attributes(&export.with_clause);
        if let Some(exported) = &export.exported {
            // `export * as ns from "m"` is ExportNamedDeclaration + ExportNamespaceSpecifier.
            let exported_id = self.module_export_name(exported);
            let (start, _) = self.span(exported.span());
            let star_start = self.start_of(exported_id);
            let _ = star_start;
            let specifier = self.mk(
                Kind::ExportNamespaceSpecifier,
                self.namespace_specifier_start(export, start),
                self.end_of(exported_id),
                vec![("exported", node(exported_id))],
            );
            return self.mks(
                Kind::ExportNamedDeclaration,
                export.span,
                vec![
                    ("exportKind", string(Self::import_kind(export.export_kind))),
                    ("declaration", Val::Null),
                    ("specifiers", list(vec![specifier])),
                    ("source", node(source)),
                    ("attributes", attributes),
                ],
            );
        }
        self.mks(
            Kind::ExportAllDeclaration,
            export.span,
            vec![
                ("exportKind", string(Self::import_kind(export.export_kind))),
                ("source", node(source)),
                ("attributes", attributes),
            ],
        )
    }

    /// Babel's namespace specifier starts at the `*` token.
    fn namespace_specifier_start(&self, export: &ExportAllDeclaration<'_>, exported_start: u32) -> u32 {
        let from = self.u(export.span.start);
        let text = self.src.slice(from, exported_start);
        match text.find('*') {
            Some(index) => from + text[..index].encode_utf16().count() as u32,
            None => exported_start,
        }
    }

    fn export_named(&mut self, export: &ExportNamedDeclaration<'_>) -> NodeId {
        if export.source.is_none() {
            for spec in &export.specifiers {
                if let (Some(scoping), ModuleExportName::IdentifierReference(local)) =
                    (self.scoping, &spec.local)
                {
                    let declared = self.export_local_defined(
                        local.name.as_str(),
                        scoping.get_root_binding(local.name.as_str()).is_some(),
                    );
                    if !declared {
                        // Babel: "Export 'a' is not defined." (recoverable)
                        self.recoverable_errors += 1;
                    }
                }
            }
        }
        let declaration = export.declaration.as_ref().map(|d| self.declaration(d));
        let specifiers = export
            .specifiers
            .iter()
            .map(|spec| {
                let local = self.module_export_name(&spec.local);
                let exported = self.module_export_name(&spec.exported);
                self.mks(
                    Kind::ExportSpecifier,
                    spec.span,
                    vec![
                        ("local", node(local)),
                        ("exported", node(exported)),
                        ("exportKind", string(Self::import_kind(spec.export_kind))),
                    ],
                )
            })
            .collect();
        let source = export.source.as_ref().map(|s| self.string_literal(s));
        let attributes = self.import_attributes(&export.with_clause);
        self.mks(
            Kind::ExportNamedDeclaration,
            export.span,
            vec![
                ("exportKind", string(Self::import_kind(export.export_kind))),
                ("declaration", opt(declaration)),
                ("specifiers", list(specifiers)),
                ("source", opt(source)),
                ("attributes", attributes),
            ],
        )
    }

    // ---- literals --------------------------------------------------------------------------

    pub(super) fn numeric_literal(&mut self, lit: &NumericLiteral<'_>) -> NodeId {
        let mut fields = vec![("value", Val::Num(lit.value))];
        if let Some(raw) = &lit.raw {
            fields.push(("x_raw", string(raw.as_str())));
        }
        self.mks(Kind::NumericLiteral, lit.span, fields)
    }

    pub(super) fn string_literal(&mut self, lit: &StringLiteral<'_>) -> NodeId {
        let mut fields = vec![("value", string(lit.value.as_str()))];
        if let Some(raw) = &lit.raw {
            fields.push(("x_raw", string(raw.as_str())));
        }
        self.mks(Kind::StringLiteral, lit.span, fields)
    }

    fn template_literal(&mut self, template: &TemplateLiteral<'_>) -> NodeId {
        let quasis = template
            .quasis
            .iter()
            .map(|quasi| self.template_element(quasi))
            .collect();
        let expressions = template.expressions.iter().map(|e| self.expression(e)).collect();
        self.mks(
            Kind::TemplateLiteral,
            template.span,
            vec![("quasis", list(quasis)), ("expressions", list(expressions))],
        )
    }

    pub(super) fn template_element(&mut self, quasi: &TemplateElement<'_>) -> NodeId {
        // Babel's element range covers only the raw text between the delimiters.
        let (start, end) = self.span(quasi.span);
        self.mk(
            Kind::TemplateElement,
            start,
            end,
            vec![
                ("raw", string(quasi.value.raw.as_str())),
                (
                    "cooked",
                    quasi.value.cooked.as_ref().map_or(Val::Null, |c| string(c.as_str())),
                ),
                ("tail", flag(quasi.tail)),
            ],
        )
    }

    // ---- expressions -----------------------------------------------------------------------

    pub(super) fn expression(&mut self, expression: &Expression<'_>) -> NodeId {
        grow(|| self.expression_inner(expression))
    }

    fn expression_inner(&mut self, expression: &Expression<'_>) -> NodeId {
        match expression {
            Expression::BooleanLiteral(lit) => {
                self.mks(Kind::BooleanLiteral, lit.span, vec![("value", flag(lit.value))])
            }
            Expression::NullLiteral(lit) => self.mks(Kind::NullLiteral, lit.span, vec![]),
            Expression::NumericLiteral(lit) => self.numeric_literal(lit),
            Expression::BigIntLiteral(lit) => {
                let raw = lit.raw.as_ref().map(|r| r.as_str()).unwrap_or("");
                self.mks(Kind::BigIntLiteral, lit.span, vec![("value", Val::Str(bigint_decimal(raw)))])
            }
            Expression::RegExpLiteral(lit) => {
                let (pattern, flags) = match lit.raw.as_ref() {
                    Some(raw) => {
                        let raw = raw.as_str();
                        match raw.rfind('/') {
                            Some(index) if index > 0 => (raw[1..index].to_string(), raw[index + 1..].to_string()),
                            _ => (lit.regex.pattern.text.to_string(), lit.regex.flags.to_string()),
                        }
                    }
                    None => (lit.regex.pattern.text.to_string(), lit.regex.flags.to_string()),
                };
                self.mks(
                    Kind::RegExpLiteral,
                    lit.span,
                    vec![("pattern", Val::Str(pattern)), ("flags", Val::Str(flags))],
                )
            }
            Expression::StringLiteral(lit) => self.string_literal(lit),
            Expression::TemplateLiteral(template) => self.template_literal(template),
            Expression::Identifier(id) => self.ident(id.name.as_str(), id.span),
            Expression::MetaProperty(meta) => {
                if meta.meta.name == "import" {
                    self.saw_esm = true;
                }
                let m = self.ident(meta.meta.name.as_str(), meta.meta.span);
                let p = self.ident(meta.property.name.as_str(), meta.property.span);
                self.mks(
                    Kind::MetaProperty,
                    meta.span,
                    vec![("meta", node(m)), ("property", node(p))],
                )
            }
            Expression::Super(sup) => self.mks(Kind::Super, sup.span, vec![]),
            Expression::ArrayExpression(array) => {
                let elements = array
                    .elements
                    .iter()
                    .map(|element| self.array_element(element))
                    .collect();
                self.mks(Kind::ArrayExpression, array.span, vec![("elements", Val::List(elements))])
            }
            Expression::ArrowFunctionExpression(arrow) => self.arrow(arrow),
            Expression::AssignmentExpression(assign) => {
                let left = self.assignment_target(&assign.left);
                let right = self.expression(&assign.right);
                self.mks(
                    Kind::AssignmentExpression,
                    assign.span,
                    vec![
                        ("operator", string(assign.operator.as_str())),
                        ("left", node(left)),
                        ("right", node(right)),
                    ],
                )
            }
            Expression::AwaitExpression(expr) => {
                if self.fn_depth == 0 {
                    self.saw_esm = true;
                }
                let argument = self.expression(&expr.argument);
                self.mks(Kind::AwaitExpression, expr.span, vec![("argument", node(argument))])
            }
            Expression::BinaryExpression(expr) => {
                let left = self.expression(&expr.left);
                let right = self.expression(&expr.right);
                self.mks(
                    Kind::BinaryExpression,
                    expr.span,
                    vec![
                        ("left", node(left)),
                        ("operator", string(expr.operator.as_str())),
                        ("right", node(right)),
                    ],
                )
            }
            Expression::CallExpression(call) => self.call_expression(call),
            Expression::ChainExpression(chain) => self.chain(chain),
            Expression::ClassExpression(class) => self.class(class),
            Expression::ConditionalExpression(expr) => {
                let test = self.expression(&expr.test);
                let consequent = self.expression(&expr.consequent);
                let alternate = self.expression(&expr.alternate);
                self.mks(
                    Kind::ConditionalExpression,
                    expr.span,
                    vec![
                        ("test", node(test)),
                        ("consequent", node(consequent)),
                        ("alternate", node(alternate)),
                    ],
                )
            }
            Expression::FunctionExpression(function) => self.function(function),
            Expression::ImportExpression(import) => {
                let source = self.expression(&import.source);
                let options = import.options.as_ref().map(|e| self.expression(e));
                let phase = match import.phase {
                    Some(ImportPhase::Source) => string("source"),
                    Some(ImportPhase::Defer) => string("defer"),
                    None => Val::Null,
                };
                self.mks(
                    Kind::ImportExpression,
                    import.span,
                    vec![("phase", phase), ("source", node(source)), ("options", opt(options))],
                )
            }
            Expression::LogicalExpression(expr) => {
                let left = self.expression(&expr.left);
                let right = self.expression(&expr.right);
                self.mks(
                    Kind::LogicalExpression,
                    expr.span,
                    vec![
                        ("left", node(left)),
                        ("operator", string(expr.operator.as_str())),
                        ("right", node(right)),
                    ],
                )
            }
            Expression::NewExpression(new) => {
                let callee = self.expression(&new.callee);
                let type_arguments = new.type_arguments.as_ref().map(|t| self.ts_type_args(t));
                let arguments = new.arguments.iter().map(|a| self.argument(a)).collect();
                self.mks(
                    Kind::NewExpression,
                    new.span,
                    vec![
                        ("callee", node(callee)),
                        ("typeArguments", opt(type_arguments)),
                        ("arguments", list(arguments)),
                    ],
                )
            }
            Expression::ObjectExpression(object) => {
                let properties = object
                    .properties
                    .iter()
                    .map(|property| match property {
                        ObjectPropertyKind::ObjectProperty(property) => self.object_property(property),
                        ObjectPropertyKind::SpreadProperty(spread) => {
                            let argument = self.expression(&spread.argument);
                            self.mks(
                                Kind::SpreadElement,
                                spread.span,
                                vec![("argument", node(argument))],
                            )
                        }
                    })
                    .collect();
                self.mks(Kind::ObjectExpression, object.span, vec![("properties", list(properties))])
            }
            Expression::ParenthesizedExpression(paren) => {
                // Not reached with `preserve_parens: false`; unwrap defensively.
                self.expression(&paren.expression)
            }
            Expression::SequenceExpression(seq) => {
                let expressions = seq.expressions.iter().map(|e| self.expression(e)).collect();
                self.mks(
                    Kind::SequenceExpression,
                    seq.span,
                    vec![("expressions", list(expressions))],
                )
            }
            Expression::TaggedTemplateExpression(tagged) => {
                let tag = self.expression(&tagged.tag);
                let type_arguments = tagged.type_arguments.as_ref().map(|t| self.ts_type_args(t));
                let quasi = self.template_literal(&tagged.quasi);
                self.mks(
                    Kind::TaggedTemplateExpression,
                    tagged.span,
                    vec![
                        ("tag", node(tag)),
                        ("typeArguments", opt(type_arguments)),
                        ("quasi", node(quasi)),
                    ],
                )
            }
            Expression::ThisExpression(this) => self.mks(Kind::ThisExpression, this.span, vec![]),
            Expression::UnaryExpression(expr) => {
                let argument = self.expression(&expr.argument);
                self.mks(
                    Kind::UnaryExpression,
                    expr.span,
                    vec![
                        ("operator", string(expr.operator.as_str())),
                        ("prefix", flag(true)),
                        ("argument", node(argument)),
                    ],
                )
            }
            Expression::UpdateExpression(expr) => {
                let argument = self.simple_assignment_target(&expr.argument);
                self.mks(
                    Kind::UpdateExpression,
                    expr.span,
                    vec![
                        ("operator", string(expr.operator.as_str())),
                        ("prefix", flag(expr.prefix)),
                        ("argument", node(argument)),
                    ],
                )
            }
            Expression::YieldExpression(expr) => {
                let argument = expr.argument.as_ref().map(|e| self.expression(e));
                self.mks(
                    Kind::YieldExpression,
                    expr.span,
                    vec![("delegate", flag(expr.delegate)), ("argument", opt(argument))],
                )
            }
            Expression::PrivateInExpression(expr) => {
                let left = self.private_name(&expr.left);
                let right = self.expression(&expr.right);
                self.mks(
                    Kind::BinaryExpression,
                    expr.span,
                    vec![
                        ("left", node(left)),
                        ("operator", string("in")),
                        ("right", node(right)),
                    ],
                )
            }
            Expression::JSXElement(element) => self.jsx_element(element),
            Expression::JSXFragment(fragment) => self.jsx_fragment(fragment),
            Expression::TSAsExpression(expr) => {
                let inner = self.expression(&expr.expression);
                let ty = self.ts_type(&expr.type_annotation);
                self.mks(
                    Kind::TSAsExpression,
                    expr.span,
                    vec![("expression", node(inner)), ("typeAnnotation", node(ty))],
                )
            }
            Expression::TSSatisfiesExpression(expr) => {
                let inner = self.expression(&expr.expression);
                let ty = self.ts_type(&expr.type_annotation);
                self.mks(
                    Kind::TSSatisfiesExpression,
                    expr.span,
                    vec![("expression", node(inner)), ("typeAnnotation", node(ty))],
                )
            }
            Expression::TSTypeAssertion(expr) => {
                let ty = self.ts_type(&expr.type_annotation);
                let inner = self.expression(&expr.expression);
                self.mks(
                    Kind::TSTypeAssertion,
                    expr.span,
                    vec![("typeAnnotation", node(ty)), ("expression", node(inner))],
                )
            }
            Expression::TSNonNullExpression(expr) => {
                let inner = self.expression(&expr.expression);
                self.mks(
                    Kind::TSNonNullExpression,
                    expr.span,
                    vec![("expression", node(inner))],
                )
            }
            Expression::TSInstantiationExpression(expr) => {
                let inner = self.expression(&expr.expression);
                let args = self.ts_type_args(&expr.type_arguments);
                self.mks(
                    Kind::TSInstantiationExpression,
                    expr.span,
                    vec![("expression", node(inner)), ("typeArguments", node(args))],
                )
            }
            Expression::V8IntrinsicExpression(_) => self.unsupported("V8 intrinsic"),
            other => {
                if let Some(member) = other.as_member_expression() {
                    self.member_expression(member)
                } else {
                    self.unsupported("expression")
                }
            }
        }
    }

    fn array_element(&mut self, element: &ArrayExpressionElement<'_>) -> Option<NodeId> {
        match element {
            ArrayExpressionElement::SpreadElement(spread) => {
                let argument = self.expression(&spread.argument);
                Some(self.mks(
                    Kind::SpreadElement,
                    spread.span,
                    vec![("argument", node(argument))],
                ))
            }
            ArrayExpressionElement::Elision(_) => None,
            other => {
                let expression = other.to_expression();
                Some(self.expression(expression))
            }
        }
    }

    pub(super) fn argument(&mut self, argument: &Argument<'_>) -> NodeId {
        match argument {
            Argument::SpreadElement(spread) => {
                let inner = self.expression(&spread.argument);
                self.mks(Kind::SpreadElement, spread.span, vec![("argument", node(inner))])
            }
            other => {
                let expression = other.to_expression();
                self.expression(expression)
            }
        }
    }

    fn private_name(&mut self, name: &PrivateIdentifier<'_>) -> NodeId {
        // Babel's PrivateName range includes the `#`; the inner identifier does not.
        let (start, end) = self.span(name.span);
        let id = self.mk(
            Kind::Identifier,
            start + 1,
            end,
            vec![("name", string(name.name.as_str()))],
        );
        self.mk(Kind::PrivateName, start, end, vec![("id", node(id))])
    }

    pub(super) fn property_key(&mut self, key: &PropertyKey<'_>) -> NodeId {
        match key {
            PropertyKey::StaticIdentifier(id) => self.ident(id.name.as_str(), id.span),
            PropertyKey::PrivateIdentifier(id) => self.private_name(id),
            other => {
                let expression = other.to_expression();
                self.expression(expression)
            }
        }
    }

    fn object_property(&mut self, property: &oxc_ast::ast::ObjectProperty<'_>) -> NodeId {
        let key = self.property_key(&property.key);
        let method_like = property.method || !matches!(property.kind, PropertyKind::Init);
        if method_like {
            if let Expression::FunctionExpression(function) = &property.value {
                let kind = match property.kind {
                    PropertyKind::Get => "get",
                    PropertyKind::Set => "set",
                    PropertyKind::Init => "method",
                };
                let parts = self.function_parts(function);
                let mut fields = vec![
                    ("method", flag(kind == "method")),
                    ("kind", string(kind)),
                    ("key", node(key)),
                    ("computed", flag(property.computed)),
                ];
                fields.extend(parts.into_method_fields());
                return self.mks(Kind::ObjectMethod, property.span, fields);
            }
        }
        let value = self.expression(&property.value);
        self.mks(
            Kind::ObjectProperty,
            property.span,
            vec![
                ("key", node(key)),
                ("value", node(value)),
                ("computed", flag(property.computed)),
                ("shorthand", flag(property.shorthand)),
            ],
        )
    }

    // ---- members, calls, optional chains --------------------------------------------------

    pub(super) fn member_expression(&mut self, member: &MemberExpression<'_>) -> NodeId {
        let object = self.expression(member.object());
        self.member_with(member, object, false)
    }

    /// Build a member node around an already converted object.
    fn member_with(&mut self, member: &MemberExpression<'_>, object: NodeId, optional_kind: bool) -> NodeId {
        let (property, computed, optional, span) = match member {
            MemberExpression::ComputedMemberExpression(m) => {
                let property = self.expression(&m.expression);
                (property, true, m.optional, m.span)
            }
            MemberExpression::StaticMemberExpression(m) => {
                let property = self.ident(m.property.name.as_str(), m.property.span);
                (property, false, m.optional, m.span)
            }
            MemberExpression::PrivateFieldExpression(m) => {
                let property = self.private_name(&m.field);
                (property, false, m.optional, m.span)
            }
        };
        if optional_kind {
            self.mks(
                Kind::OptionalMemberExpression,
                span,
                vec![
                    ("object", node(object)),
                    ("computed", flag(computed)),
                    ("property", node(property)),
                    ("optional", flag(optional)),
                ],
            )
        } else {
            self.mks(
                Kind::MemberExpression,
                span,
                vec![
                    ("object", node(object)),
                    ("computed", flag(computed)),
                    ("property", node(property)),
                ],
            )
        }
    }

    pub(super) fn call_expression(&mut self, call: &CallExpression<'_>) -> NodeId {
        let callee = self.expression(&call.callee);
        self.call_with(call, callee, false)
    }

    fn call_with(&mut self, call: &CallExpression<'_>, callee: NodeId, optional_kind: bool) -> NodeId {
        let type_arguments = call.type_arguments.as_ref().map(|t| self.ts_type_args(t));
        let arguments = call.arguments.iter().map(|a| self.argument(a)).collect();
        if optional_kind {
            self.mks(
                Kind::OptionalCallExpression,
                call.span,
                vec![
                    ("callee", node(callee)),
                    ("arguments", list(arguments)),
                    ("optional", flag(call.optional)),
                    ("typeArguments", opt(type_arguments)),
                ],
            )
        } else {
            self.mks(
                Kind::CallExpression,
                call.span,
                vec![
                    ("callee", node(callee)),
                    ("arguments", list(arguments)),
                    ("typeArguments", opt(type_arguments)),
                ],
            )
        }
    }

    /// oxc `ChainExpression` -> Babel `Optional*` nodes. A spine node is `Optional*` when the
    /// chain below it (inclusive) contains an `?.` link; plain nodes stay below the first `?.`.
    fn chain(&mut self, chain: &ChainExpression<'_>) -> NodeId {
        enum Link<'x, 'a> {
            Member(&'x MemberExpression<'a>),
            Call(&'x CallExpression<'a>),
            NonNull(&'x TSNonNullExpression<'a>),
        }
        fn link_of<'x, 'a>(expression: &'x Expression<'a>) -> Option<Link<'x, 'a>> {
            match expression {
                Expression::CallExpression(call) => Some(Link::Call(call)),
                Expression::TSNonNullExpression(non_null) => Some(Link::NonNull(non_null)),
                other => other.as_member_expression().map(Link::Member),
            }
        }
        let first = match &chain.expression {
            ChainElement::CallExpression(call) => Link::Call(call),
            ChainElement::TSNonNullExpression(non_null) => Link::NonNull(non_null),
            other => Link::Member(other.to_member_expression()),
        };
        let mut links = vec![first];
        let base = loop {
            let inner: &Expression<'_> = match links.last().expect("link") {
                Link::Member(member) => member.object(),
                Link::Call(call) => &call.callee,
                Link::NonNull(non_null) => &non_null.expression,
            };
            match link_of(inner) {
                Some(link) => links.push(link),
                None => break inner,
            }
        };
        let deepest_optional = links.iter().rposition(|link| match link {
            Link::Member(member) => member.optional(),
            Link::Call(call) => call.optional,
            Link::NonNull(_) => false,
        });
        let mut current = self.expression(base);
        for (index, link) in links.iter().enumerate().rev() {
            let optional_kind = deepest_optional.is_some_and(|deepest| index <= deepest);
            current = match link {
                Link::Member(member) => self.member_with(member, current, optional_kind),
                Link::Call(call) => self.call_with(call, current, optional_kind),
                Link::NonNull(non_null) => self.mks(
                    Kind::TSNonNullExpression,
                    non_null.span,
                    vec![("expression", node(current))],
                ),
            };
        }
        current
    }
}
