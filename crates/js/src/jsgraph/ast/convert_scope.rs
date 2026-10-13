//! The slice of Babel's TypeScript scope tracking that decides which parse errors a file reports
//! inside `declare module "x" { .. }`, `namespace N { .. }` and `declare global { .. }` bodies.
//!
//! oxc resolves names with real scopes, Babel with a handful of per-scope tables and a few
//! quirks (verified against `@babel/parser` 8.0.4, see `jsgraph_ast_parity_test`):
//!
//! * `export { x }` is accepted when `x` was declared EARLIER in an enclosing module/namespace
//!   body as a class, enum, namespace, interface, type alias, bodiless function (`declare`
//!   function or overload) or a named/`import =` import. `var`/`let`/`const`, functions with a
//!   body and default/namespace imports do not count there (only at the top level).
//! * `declare global { .. }` opens no scope: its names land in the enclosing scope.
//! * Directly inside a `namespace` (not `declare module "x"`) imports from a module, and every
//!   export that is not `export <declaration>` (or `export { .. }` in an ambient context), are
//!   errors.

use std::collections::{HashMap, HashSet};

use oxc_ast::ast::*;

use super::convert::Cx;
use super::NodeId;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum FrameKind {
    /// `declare module "x" { .. }`.
    Module,
    /// `namespace N { .. }`, `module N { .. }`.
    Namespace,
    /// `declare global { .. }`.
    Global,
}

/// Babel's `names` table entry kinds that can clash across the file scope and `declare global`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Bind {
    /// `var`, function with a body.
    Var,
    /// `let`/`const`, non-`declare` classes, default/namespace imports.
    Lexical,
}

fn clashes(new: Bind, existing: Bind) -> bool {
    new == Bind::Lexical || existing == Bind::Lexical
}

struct Frame {
    names: HashSet<String>,
}

#[derive(Default)]
pub(super) struct ScopeState {
    frames: Vec<Frame>,
    /// Names declared by `declare global` blocks at the top level (they join the top-level scope).
    root_extra: HashSet<String>,
    /// Named imports (`import { a }`, `import a = ..`) and the order Babel sees them in: a name
    /// imported later does not satisfy an earlier `export { a }`.
    imports_seen: HashSet<String>,
    /// Every named import at the top level of the file (known up front).
    top_named_imports: HashSet<String>,
    /// Redeclaration-relevant bindings of `declare global` blocks at the top level.
    global_binds: HashMap<String, Bind>,
    /// The same for the file scope itself, as Babel's scope handler records them.
    top_binds: HashMap<String, Bind>,
    /// Depth of enclosing ambient contexts (`declare` blocks, or the whole file for `.d.ts`).
    ambient: u32,
    /// Babel throws (REA records a parse failure) while oxc accepts the source.
    pub(super) unparseable: Option<String>,
}

impl ScopeState {
    pub(super) fn new(definition_file: bool) -> Self {
        ScopeState { ambient: u32::from(definition_file), ..ScopeState::default() }
    }
}

impl<'s> Cx<'s> {
    /// Convert the statements of a module/namespace/global body, tracking Babel's scope rules.
    pub(super) fn module_block_body(
        &mut self,
        kind: FrameKind,
        declare: bool,
        body: &[Statement<'_>],
    ) -> Vec<NodeId> {
        if kind != FrameKind::Global {
            self.scope.frames.push(Frame { names: HashSet::new() });
        }
        self.scope.ambient += u32::from(declare);
        let mut out = Vec::with_capacity(body.len());
        for statement in body {
            if kind == FrameKind::Namespace {
                self.namespace_statement_errors(statement);
            }
            out.push(self.statement(statement));
            self.register_names(statement, kind == FrameKind::Global && self.scope.frames.is_empty());
        }
        self.scope.ambient -= u32::from(declare);
        if kind != FrameKind::Global {
            self.scope.frames.pop();
        }
        out
    }

    /// Babel's `checkLocalExport` for `export { name }`. `root_bound`: oxc found a file-scope
    /// symbol for `name`.
    pub(super) fn export_local_defined(&self, name: &str, root_bound: bool) -> bool {
        if self.scope.frames.iter().any(|frame| frame.names.contains(name))
            || self.scope.root_extra.contains(name)
            || self.scope.imports_seen.contains(name)
        {
            return true;
        }
        // Babel files named imports separately and never resolves them by a later `import`.
        root_bound && !self.scope.top_named_imports.contains(name)
    }

    /// Collect the file's named imports and file-scope bindings before converting anything.
    pub(super) fn prescan_imports(&mut self, program: &Program<'_>) {
        for statement in &program.body {
            match statement {
                Statement::ImportDeclaration(import) => {
                    for specifier in import.specifiers.iter().flatten() {
                        match specifier {
                            ImportDeclarationSpecifier::ImportSpecifier(s) => {
                                self.scope.top_named_imports.insert(s.local.name.to_string());
                            }
                            other => {
                                self.scope.top_binds.insert(other.local().name.to_string(), Bind::Lexical);
                            }
                        }
                    }
                }
                Statement::TSImportEqualsDeclaration(import) => {
                    self.scope.top_named_imports.insert(import.id.name.to_string());
                }
                Statement::ExportNamedDeclaration(export) => {
                    if let Some(declaration) = &export.declaration {
                        // `export declare class` loses its `declare` in Babel's scope handler.
                        self.prescan_declaration(declaration, true);
                    }
                }
                Statement::ExportDefaultDeclaration(export) => match &export.declaration {
                    ExportDefaultDeclarationKind::ClassDeclaration(c) => {
                        self.scope.top_binds.extend(c.id.iter().map(|i| (i.name.to_string(), Bind::Lexical)));
                    }
                    ExportDefaultDeclarationKind::FunctionDeclaration(f) if f.body.is_some() => {
                        self.scope.top_binds.extend(f.id.iter().map(|i| (i.name.to_string(), Bind::Var)));
                    }
                    _ => {}
                },
                other => {
                    if let Some(declaration) = other.as_declaration() {
                        self.prescan_declaration(declaration, false);
                    }
                }
            }
        }
    }

    fn prescan_declaration(&mut self, declaration: &Declaration<'_>, exported: bool) {
        match declaration {
            // Only a plain `declare class` (not abstract, not exported) is export-only.
            Declaration::ClassDeclaration(c) if exported || !c.declare || c.r#abstract => {
                self.scope.top_binds.extend(c.id.iter().map(|i| (i.name.to_string(), Bind::Lexical)));
            }
            Declaration::FunctionDeclaration(f) if f.body.is_some() => {
                self.scope.top_binds.extend(f.id.iter().map(|i| (i.name.to_string(), Bind::Var)));
            }
            Declaration::VariableDeclaration(v) => {
                let bind = if v.kind == VariableDeclarationKind::Var { Bind::Var } else { Bind::Lexical };
                for declarator in &v.declarations {
                    for id in declarator.id.get_binding_identifiers() {
                        self.scope.top_binds.insert(id.name.to_string(), bind);
                    }
                }
            }
            _ => {}
        }
    }

    pub(super) fn note_import(&mut self, import: &ImportDeclaration<'_>) {
        for specifier in import.specifiers.iter().flatten() {
            if let ImportDeclarationSpecifier::ImportSpecifier(s) = specifier {
                self.scope.imports_seen.insert(s.local.name.to_string());
            }
        }
    }

    pub(super) fn note_import_equals(&mut self, import: &TSImportEqualsDeclaration<'_>) {
        self.scope.imports_seen.insert(import.id.name.to_string());
    }

    /// `declare global` at the top level shares Babel's file scope: a `var` that meets a lexical
    /// binding of the same name (or the reverse) is a redeclaration. oxc keeps the block's
    /// scope apart, so count the clashes here.
    fn global_redeclarations(&mut self, binds: Vec<(String, Bind)>) {
        for (name, bind) in binds {
            let clash = [self.scope.global_binds.get(&name), self.scope.top_binds.get(&name)]
                .into_iter()
                .flatten()
                .any(|existing| clashes(bind, *existing));
            if clash {
                self.recoverable_errors += 1;
            }
            let entry = self.scope.global_binds.entry(name).or_insert(bind);
            if bind == Bind::Lexical {
                *entry = Bind::Lexical;
            }
        }
    }

    /// Errors Babel raises for statements that sit directly inside a `namespace` body.
    fn namespace_statement_errors(&mut self, statement: &Statement<'_>) {
        let error = match statement {
            Statement::ImportDeclaration(_) => true,
            Statement::TSImportEqualsDeclaration(import) => {
                matches!(import.module_reference, TSModuleReference::ExternalModuleReference(_))
            }
            Statement::ExportNamedDeclaration(export) => {
                export.source.is_some() || (export.declaration.is_none() && self.scope.ambient == 0)
            }
            Statement::ExportAllDeclaration(_)
            | Statement::ExportDefaultDeclaration(_)
            | Statement::TSExportAssignment(_)
            | Statement::TSNamespaceExportDeclaration(_) => true,
            _ => false,
        };
        if error {
            self.recoverable_errors += 1;
        }
    }

    /// Record the names `statement` declares, the way Babel's scope handler would see them.
    /// `everything` also records `var`/`let`/`const`/functions (a `declare global` body at the
    /// top level declares them into the file scope).
    fn register_names(&mut self, statement: &Statement<'_>, everything: bool) {
        let mut names: Vec<String> = Vec::new();
        let mut binds: Vec<(String, Bind)> = Vec::new();
        let mut declaration = statement.as_declaration();
        match statement {
            Statement::ExportNamedDeclaration(export) => declaration = export.declaration.as_ref(),
            Statement::ImportDeclaration(import) => {
                for specifier in import.specifiers.iter().flatten() {
                    match specifier {
                        ImportDeclarationSpecifier::ImportSpecifier(s) => {
                            names.push(s.local.name.to_string());
                        }
                        other if everything => {
                            names.push(other.local().name.to_string());
                            binds.push((other.local().name.to_string(), Bind::Lexical));
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        if let Some(declaration) = declaration {
            match declaration {
                Declaration::ClassDeclaration(c) => {
                    names.extend(c.id.iter().map(|i| i.name.to_string()));
                    if !c.declare {
                        binds.extend(c.id.iter().map(|i| (i.name.to_string(), Bind::Lexical)));
                    }
                }
                Declaration::TSEnumDeclaration(e) => names.push(e.id.name.to_string()),
                Declaration::TSInterfaceDeclaration(i) => names.push(i.id.name.to_string()),
                Declaration::TSTypeAliasDeclaration(t) => names.push(t.id.name.to_string()),
                Declaration::TSImportEqualsDeclaration(i) => names.push(i.id.name.to_string()),
                Declaration::TSModuleDeclaration(m) => {
                    if let TSModuleDeclarationName::Identifier(id) = &m.id {
                        names.push(id.name.to_string());
                    }
                }
                Declaration::FunctionDeclaration(f) => {
                    if f.body.is_none() || everything {
                        names.extend(f.id.iter().map(|i| i.name.to_string()));
                    }
                    if f.body.is_some() {
                        binds.extend(f.id.iter().map(|i| (i.name.to_string(), Bind::Var)));
                    }
                }
                Declaration::VariableDeclaration(v) if everything => {
                    let bind = if v.kind == VariableDeclarationKind::Var { Bind::Var } else { Bind::Lexical };
                    for declarator in &v.declarations {
                        for id in declarator.id.get_binding_identifiers() {
                            names.push(id.name.to_string());
                            binds.push((id.name.to_string(), bind));
                        }
                    }
                }
                _ => {}
            }
        }
        if everything {
            self.global_redeclarations(binds);
        }
        let target = match self.scope.frames.last_mut() {
            Some(frame) => &mut frame.names,
            None => &mut self.scope.root_extra,
        };
        target.extend(names);
    }

    /// `export = function f(): T;` parses in oxc (ambient function expression) but Babel throws.
    pub(super) fn check_export_assignment(&mut self, assign: &TSExportAssignment<'_>) {
        if let Expression::FunctionExpression(function) = &assign.expression {
            if function.body.is_none() && self.scope.unparseable.is_none() {
                self.scope.unparseable =
                    Some("function expression without a body in `export =`".into());
            }
        }
    }
}

// ---- ambient contexts (`.d.ts` files and `declare` statements) ------------------------------

fn is_number_literal(expression: &Expression<'_>) -> bool {
    matches!(expression, Expression::NumericLiteral(_) | Expression::BigIntLiteral(_))
}

/// Babel's `isUncomputedMemberExpressionChain` (`a.b.c`).
fn is_member_chain(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::Identifier(_) => true,
        Expression::StaticMemberExpression(member) => is_member_chain(&member.object),
        _ => false,
    }
}

/// Babel's `isValidAmbientConstInitializer` (parenthesized initializers are rejected there; oxc
/// drops the parentheses, so `declare const x = (1)` is the one form this cannot tell apart).
fn valid_ambient_const_initializer(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::StringLiteral(_) | Expression::BooleanLiteral(_) => true,
        Expression::NumericLiteral(_) | Expression::BigIntLiteral(_) => true,
        Expression::UnaryExpression(unary) => {
            unary.operator == UnaryOperator::UnaryNegation && is_number_literal(&unary.argument)
        }
        Expression::TemplateLiteral(template) => template.expressions.is_empty(),
        // `Enum.Member`, `Enum["Member"]`, `` Enum[`Member`] ``
        Expression::StaticMemberExpression(member) => is_member_chain(&member.object),
        Expression::ComputedMemberExpression(member) => {
            let literal_key = match &member.expression {
                Expression::StringLiteral(_) => true,
                Expression::TemplateLiteral(template) => template.expressions.is_empty(),
                _ => false,
            };
            literal_key && is_member_chain(&member.object)
        }
        _ => false,
    }
}

impl<'s> Cx<'s> {
    /// Enter the ambient context a `declare` statement opens; pass the result to `leave_declare`.
    pub(super) fn enter_declare(&mut self, declare: bool) -> u32 {
        let entered = u32::from(declare);
        self.scope.ambient += entered;
        entered
    }

    pub(super) fn leave_declare(&mut self, entered: u32) {
        self.scope.ambient -= entered;
    }

    /// "An implementation cannot be declared in ambient contexts." (function or method body).
    pub(super) fn ambient_implementation(&mut self) {
        if self.scope.ambient > 0 {
            self.recoverable_errors += 1;
        }
    }

    /// Initializer rules for `var`/`let`/`const` declarators in ambient contexts.
    pub(super) fn ambient_declarator(&mut self, kind: VariableDeclarationKind, declarator: &VariableDeclarator<'_>) {
        let Some(init) = &declarator.init else { return };
        if self.scope.ambient == 0 {
            return;
        }
        let annotated = declarator.id.type_annotation.is_some();
        let literal = valid_ambient_const_initializer(init);
        if matches!(kind, VariableDeclarationKind::Var | VariableDeclarationKind::Let) || annotated || !literal {
            self.recoverable_errors += 1;
        }
    }

    /// Class fields may only carry an initializer when `readonly` and without a type annotation.
    pub(super) fn ambient_property(&mut self, property: &PropertyDefinition<'_>) {
        if self.scope.ambient > 0
            && property.value.is_some()
            && !(property.readonly && property.type_annotation.is_none())
        {
            self.recoverable_errors += 1;
        }
    }
}

/// Byte ranges of the top-level `declare` statements of a program (ambient code).
pub(super) fn declare_spans(program: &Program<'_>) -> Vec<(usize, usize)> {
    fn declared(declaration: &Declaration<'_>) -> bool {
        match declaration {
            Declaration::VariableDeclaration(d) => d.declare,
            Declaration::FunctionDeclaration(d) => d.declare,
            Declaration::ClassDeclaration(d) => d.declare,
            Declaration::TSEnumDeclaration(d) => d.declare,
            Declaration::TSModuleDeclaration(d) => d.declare,
            _ => false,
        }
    }
    let mut spans = Vec::new();
    for statement in &program.body {
        let declaration = match statement {
            Statement::ExportNamedDeclaration(export) => export.declaration.as_ref(),
            other => other.as_declaration(),
        };
        if declaration.is_some_and(declared) {
            let span = oxc_span::GetSpan::span(statement);
            spans.push((span.start as usize, span.end as usize));
        }
    }
    spans
}
