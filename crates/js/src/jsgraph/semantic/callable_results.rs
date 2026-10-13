//! Port of `javascriptSemanticCallableResults.ts`.

use crate::jsgraph::ast::{Alias, Kind, N};

/// `"return" | "yield"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallableResultKind {
    Return,
    Yield,
}

/// One direct return or yield, excluding every nested callable.
#[derive(Clone, Copy, Debug)]
pub struct SemanticCallableResultExpression<'a> {
    pub node: Option<N<'a>>,
    pub site: N<'a>,
    pub kind: CallableResultKind,
    pub delegated: bool,
}

/// Collect direct result syntax without executing or evaluating a callable.
pub fn semantic_callable_result_expressions<'a>(callable: N<'a>) -> Vec<SemanticCallableResultExpression<'a>> {
    if callable.is(Kind::ArrowFunctionExpression) {
        if let Some(body) = callable.f("body") {
            if !body.is(Kind::BlockStatement) {
                return vec![SemanticCallableResultExpression {
                    node: Some(body),
                    site: body,
                    kind: CallableResultKind::Return,
                    delegated: false,
                }];
            }
        }
    }
    if !callable.is_function() {
        return Vec::new();
    }
    let mut output = Vec::new();
    let Some(body) = callable.f("body") else { return output };
    let mut pending: Vec<N<'a>> = body.children();
    pending.reverse();
    while let Some(node) = pending.pop() {
        if node.is_function() || node.has_alias(Alias::Class) {
            continue;
        }
        if node.is(Kind::ReturnStatement) {
            output.push(SemanticCallableResultExpression {
                node: node.f("argument"),
                site: node,
                kind: CallableResultKind::Return,
                delegated: false,
            });
        }
        if node.is(Kind::YieldExpression) {
            output.push(SemanticCallableResultExpression {
                node: node.f("argument"),
                site: node,
                kind: CallableResultKind::Yield,
                delegated: node.flag("delegate"),
            });
        }
        let mut children = node.children();
        children.reverse();
        pending.extend(children);
    }
    output
}
