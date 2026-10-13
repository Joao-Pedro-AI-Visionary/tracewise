//! Babel-shaped syntax tree.
//!
//! REA parses with `@babel/parser` and walks the tree with `VISITOR_KEYS` order. Node
//! ids, fingerprints and output order depend on that shape, so the port keeps a Babel-shaped
//! tree (node `type`, UTF-16 `start`/`end`, Babel field names) instead of exposing oxc's own AST.
//! [`convert`] fills it from an oxc parse; the analyses are then mechanical ports of the REA
//! code written against `@babel/types`.
//!
//! The tree is an arena: [`Ast::nodes`] holds every node, children are [`NodeId`] indices and
//! [`N`] is a cheap `Copy` cursor (`ast` + `id`) that reads like a Babel node
//! (`call.f("callee")`, `call.list("arguments")`).

pub mod babel_types;
mod convert;
mod depth;
mod convert_decl;
mod convert_jsx;
mod convert_scope;
mod convert_ts;
mod json;
mod source;

use std::collections::HashMap;

pub use babel_types::{Alias, Kind};
pub use convert::{parse_babel, ConvertError, ParseOptions};
pub use json::ast_to_json;
pub use source::{Source, SourcePoint, SourceRange};

/// Deepest oxc syntax tree the semantic pass, the converter and the analyses downstream are sized
/// for. A deeper tree that still parses (a very long `a.b.c...` or `1+1+...` chain) is refused with
/// [`ConvertError::TooDeep`] before anything recurses over it.
pub const MAX_AST_DEPTH: usize = 200_000;

/// Index into [`Ast::nodes`].
pub type NodeId = u32;

/// One Babel field value.
#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    Node(NodeId),
    /// Child list; `None` marks a hole (`[ , a]`, `[a, ,]`).
    List(Vec<Option<NodeId>>),
    Str(String),
    Num(f64),
    Bool(bool),
    Null,
}

#[derive(Clone, Debug)]
pub struct NodeData {
    pub kind: Kind,
    /// UTF-16 code-unit offsets, as `@babel/parser` reports them.
    pub start: u32,
    pub end: u32,
    pub parent: Option<NodeId>,
    pub fields: Vec<(&'static str, Val)>,
}

/// A source comment (`file.comments`).
#[derive(Clone, Debug)]
pub struct Comment {
    pub block: bool,
    pub start: u32,
    pub end: u32,
    /// Comment text without `//` or `/* */`.
    pub value: String,
}

#[derive(Debug)]
pub struct Ast {
    pub nodes: Vec<NodeData>,
    pub root: NodeId,
    pub source: Source,
    pub comments: Vec<Comment>,
    /// Recoverable parser errors (`file.errors.length`).
    pub error_count: usize,
}

/// Cursor over one node: `Copy`, comparable by id.
#[derive(Clone, Copy)]
pub struct N<'a> {
    pub ast: &'a Ast,
    pub id: NodeId,
}

impl PartialEq for N<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && std::ptr::eq(self.ast, other.ast)
    }
}
impl Eq for N<'_> {}
impl std::hash::Hash for N<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}
impl std::fmt::Debug for N<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}#{}[{}..{}]", self.kind().as_str(), self.id, self.start(), self.end())
    }
}

impl Ast {
    pub fn root(&self) -> N<'_> {
        N { ast: self, id: self.root }
    }

    pub fn node(&self, id: NodeId) -> N<'_> {
        N { ast: self, id }
    }

    pub fn data(&self, id: NodeId) -> &NodeData {
        &self.nodes[id as usize]
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// `loc` of a UTF-16 offset range.
    pub fn range(&self, start: u32, end: u32) -> SourceRange {
        self.source.range(start, end)
    }

    /// Fill `parent` for every node reachable from `root` (VISITOR_KEYS order).
    fn link_parents(&mut self) {
        let mut stack = vec![self.root];
        while let Some(id) = stack.pop() {
            let children = child_ids(&self.nodes[id as usize]);
            for child in children {
                self.nodes[child as usize].parent = Some(id);
                stack.push(child);
            }
        }
    }
}

/// Child ids of one node in `VISITOR_KEYS` order.
pub(crate) fn child_ids(data: &NodeData) -> Vec<NodeId> {
    let mut out = Vec::new();
    for key in data.kind.visitor_keys() {
        match data.fields.iter().find(|(name, _)| name == key).map(|(_, v)| v) {
            Some(Val::Node(id)) => out.push(*id),
            Some(Val::List(items)) => out.extend(items.iter().flatten().copied()),
            _ => {}
        }
    }
    out
}

impl<'a> N<'a> {
    pub fn kind(self) -> Kind {
        self.ast.nodes[self.id as usize].kind
    }

    pub fn data(self) -> &'a NodeData {
        &self.ast.nodes[self.id as usize]
    }

    pub fn start(self) -> u32 {
        self.data().start
    }

    pub fn end(self) -> u32 {
        self.data().end
    }

    pub fn loc(self) -> SourceRange {
        self.ast.range(self.start(), self.end())
    }

    pub fn is(self, kind: Kind) -> bool {
        self.kind() == kind
    }

    /// `t.isX` for a Babel alias (`Function`, `Expression`, `Pattern`, ...).
    pub fn has_alias(self, alias: Alias) -> bool {
        self.kind().alias_mask() & alias.bit() != 0
    }

    pub fn parent(self) -> Option<N<'a>> {
        self.data().parent.map(|id| N { ast: self.ast, id })
    }

    pub fn field(self, key: &str) -> Option<&'a Val> {
        self.data().fields.iter().find(|(name, _)| *name == key).map(|(_, v)| v)
    }

    /// Single child node (`None` when absent or null).
    pub fn f(self, key: &str) -> Option<N<'a>> {
        match self.field(key) {
            Some(Val::Node(id)) => Some(N { ast: self.ast, id: *id }),
            _ => None,
        }
    }

    /// Child list with holes preserved.
    pub fn list(self, key: &str) -> Vec<Option<N<'a>>> {
        match self.field(key) {
            Some(Val::List(items)) => items
                .iter()
                .map(|item| item.map(|id| N { ast: self.ast, id }))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Child list without holes.
    pub fn nodes(self, key: &str) -> Vec<N<'a>> {
        match self.field(key) {
            Some(Val::List(items)) => items
                .iter()
                .flatten()
                .map(|id| N { ast: self.ast, id: *id })
                .collect(),
            _ => Vec::new(),
        }
    }

    pub fn list_len(self, key: &str) -> usize {
        match self.field(key) {
            Some(Val::List(items)) => items.len(),
            _ => 0,
        }
    }

    pub fn str(self, key: &str) -> Option<&'a str> {
        match self.field(key) {
            Some(Val::Str(value)) => Some(value.as_str()),
            _ => None,
        }
    }

    pub fn num(self, key: &str) -> Option<f64> {
        match self.field(key) {
            Some(Val::Num(value)) => Some(*value),
            _ => None,
        }
    }

    pub fn flag(self, key: &str) -> bool {
        matches!(self.field(key), Some(Val::Bool(true)))
    }

    /// Children in `VISITOR_KEYS` order (Babel `childNodes`).
    pub fn children(self) -> Vec<N<'a>> {
        child_ids(self.data())
            .into_iter()
            .map(|id| N { ast: self.ast, id })
            .collect()
    }

    /// Source text of this node (`source.slice(start, end)`).
    pub fn text(self) -> &'a str {
        self.ast.source.slice(self.start(), self.end())
    }

    // ---- convenient `t.isX` shorthands used all over the REA analyses --------------------

    pub fn is_identifier(self) -> bool {
        self.is(Kind::Identifier)
    }

    pub fn name(self) -> Option<&'a str> {
        self.str("name")
    }

    pub fn is_function(self) -> bool {
        self.has_alias(Alias::Function)
    }

    pub fn is_expression(self) -> bool {
        self.has_alias(Alias::Expression)
    }

    pub fn is_string_literal(self) -> bool {
        self.is(Kind::StringLiteral)
    }

    pub fn is_numeric_literal(self) -> bool {
        self.is(Kind::NumericLiteral)
    }

    pub fn is_member(self) -> bool {
        matches!(self.kind(), Kind::MemberExpression | Kind::OptionalMemberExpression)
    }

    pub fn is_call(self) -> bool {
        matches!(self.kind(), Kind::CallExpression | Kind::OptionalCallExpression)
    }
}

/// Pre-order walk in Babel `VISITOR_KEYS` order. `enter` returns `false` to skip the subtree.
pub fn walk<'a>(
    root: N<'a>,
    mut enter: impl FnMut(N<'a>, Option<N<'a>>) -> bool,
    mut exit: impl FnMut(N<'a>, Option<N<'a>>),
) {
    struct Frame<'a> {
        node: N<'a>,
        parent: Option<N<'a>>,
        children: Vec<N<'a>>,
        next: usize,
    }
    let mut stack: Vec<Frame<'a>> = Vec::new();
    crate::jsgraph::control::checkpoint();
    let descend = enter(root, None);
    stack.push(Frame {
        node: root,
        parent: None,
        children: if descend { root.children() } else { Vec::new() },
        next: 0,
    });
    while let Some(frame) = stack.last_mut() {
        if let Some(child) = frame.children.get(frame.next).copied() {
            frame.next += 1;
            let parent = frame.node;
            crate::jsgraph::control::checkpoint();
            let descend = enter(child, Some(parent));
            stack.push(Frame {
                node: child,
                parent: Some(parent),
                children: if descend { child.children() } else { Vec::new() },
                next: 0,
            });
        } else {
            let done = stack.pop().expect("frame");
            exit(done.node, done.parent);
        }
    }
}

/// Map from node id to a value; the Rust analogue of a JS `WeakMap<Node, T>`.
pub type NodeMap<T> = HashMap<NodeId, T>;
