//! Port of `javascriptSemanticTraversal.ts`: deterministic AST traversal (no cooperative
//! yielding in the Rust port) and the direct-child expansion.

use crate::jsgraph::ast::N;

/// Callbacks for one deterministic AST traversal (`JavaScriptAstVisitor`).
pub trait AstVisitor<'a> {
    fn enter(&mut self, node: N<'a>, parent: Option<N<'a>>);
    fn exit(&mut self, _node: N<'a>, _parent: Option<N<'a>>) {}
}

struct Frame<'a> {
    node: N<'a>,
    parent: Option<N<'a>>,
    children: Vec<N<'a>>,
    next: usize,
}

/// Visit every Babel AST node in deterministic source-tree order (`traverseJavaScriptAst`).
/// `enter` runs before the node's children are expanded, exactly as in REA.
pub fn traverse_javascript_ast<'a>(root: N<'a>, visitor: &mut impl AstVisitor<'a>) {
    crate::jsgraph::control::checkpoint();
    visitor.enter(root, None);
    let mut pending = vec![Frame { node: root, parent: None, children: root.children(), next: 0 }];
    while let Some(current) = pending.last_mut() {
        if let Some(&child) = current.children.get(current.next) {
            current.next += 1;
            let parent = current.node;
            crate::jsgraph::control::checkpoint();
            visitor.enter(child, Some(parent));
            pending.push(Frame { node: child, parent: Some(parent), children: child.children(), next: 0 });
        } else {
            visitor.exit(current.node, current.parent);
            pending.pop();
        }
    }
}

/// A traversal visitor made of closures (enter only).
pub struct EnterFn<F>(pub F);

impl<'a, F: FnMut(N<'a>, Option<N<'a>>)> AstVisitor<'a> for EnterFn<F> {
    fn enter(&mut self, node: N<'a>, parent: Option<N<'a>>) {
        (self.0)(node, parent)
    }
}

/// `readAncestors()`: outermost-first snapshot ending with the direct parent of `node`.
pub fn read_ancestors<'a>(node: N<'a>) -> Vec<N<'a>> {
    let mut chain = Vec::new();
    let mut current = node.parent();
    while let Some(ancestor) = current {
        chain.push(ancestor);
        current = ancestor.parent();
    }
    chain.reverse();
    chain
}

/// Child Babel nodes in `VISITOR_KEYS` order (`childNodes`).
pub fn child_nodes<'a>(node: N<'a>) -> Vec<N<'a>> {
    node.children()
}
