//! JSX syntax -> Babel `JSX*` nodes.

use oxc_ast::ast::*;

use super::convert::{flag, list, node, opt, string, Cx};
use super::{Kind, NodeId};

impl<'s> Cx<'s> {
    pub(super) fn jsx_element(&mut self, element: &JSXElement<'_>) -> NodeId {
        let name = self.jsx_element_name(&element.opening_element.name);
        let type_arguments = element
            .opening_element
            .type_arguments
            .as_ref()
            .map(|t| self.ts_type_args(t));
        let attributes = element
            .opening_element
            .attributes
            .iter()
            .map(|attribute| self.jsx_attribute_item(attribute))
            .collect();
        let self_closing = element.closing_element.is_none();
        let opening = self.mks(
            Kind::JSXOpeningElement,
            element.opening_element.span,
            vec![
                ("name", node(name)),
                ("typeArguments", opt(type_arguments)),
                ("attributes", list(attributes)),
                ("selfClosing", flag(self_closing)),
            ],
        );
        let children = element.children.iter().map(|c| self.jsx_child(c)).collect();
        let closing = element.closing_element.as_ref().map(|closing| {
            let name = self.jsx_element_name(&closing.name);
            self.mks(Kind::JSXClosingElement, closing.span, vec![("name", node(name))])
        });
        self.mks(
            Kind::JSXElement,
            element.span,
            vec![
                ("openingElement", node(opening)),
                ("children", list(children)),
                ("closingElement", opt(closing)),
            ],
        )
    }

    pub(super) fn jsx_fragment(&mut self, fragment: &JSXFragment<'_>) -> NodeId {
        let opening = self.mks(Kind::JSXOpeningFragment, fragment.opening_fragment.span, vec![]);
        let children = fragment.children.iter().map(|c| self.jsx_child(c)).collect();
        let closing = self.mks(Kind::JSXClosingFragment, fragment.closing_fragment.span, vec![]);
        self.mks(
            Kind::JSXFragment,
            fragment.span,
            vec![
                ("openingFragment", node(opening)),
                ("children", list(children)),
                ("closingFragment", node(closing)),
            ],
        )
    }

    fn jsx_identifier(&mut self, id: &JSXIdentifier<'_>) -> NodeId {
        self.mks(Kind::JSXIdentifier, id.span, vec![("name", string(id.name.as_str()))])
    }

    fn jsx_element_name(&mut self, name: &JSXElementName<'_>) -> NodeId {
        match name {
            JSXElementName::Identifier(id) => self.jsx_identifier(id),
            JSXElementName::IdentifierReference(id) => self.mks(
                Kind::JSXIdentifier,
                id.span,
                vec![("name", string(id.name.as_str()))],
            ),
            JSXElementName::NamespacedName(ns) => self.jsx_namespaced(ns),
            JSXElementName::MemberExpression(member) => self.jsx_member(member),
            JSXElementName::ThisExpression(this) => self.mks(
                Kind::JSXIdentifier,
                this.span,
                vec![("name", string("this"))],
            ),
        }
    }

    fn jsx_namespaced(&mut self, ns: &JSXNamespacedName<'_>) -> NodeId {
        let namespace = self.jsx_identifier(&ns.namespace);
        let name = self.jsx_identifier(&ns.name);
        self.mks(
            Kind::JSXNamespacedName,
            ns.span,
            vec![("namespace", node(namespace)), ("name", node(name))],
        )
    }

    fn jsx_member(&mut self, member: &JSXMemberExpression<'_>) -> NodeId {
        let object = match &member.object {
            JSXMemberExpressionObject::IdentifierReference(id) => self.mks(
                Kind::JSXIdentifier,
                id.span,
                vec![("name", string(id.name.as_str()))],
            ),
            JSXMemberExpressionObject::MemberExpression(inner) => self.jsx_member(inner),
            JSXMemberExpressionObject::ThisExpression(this) => self.mks(
                Kind::JSXIdentifier,
                this.span,
                vec![("name", string("this"))],
            ),
        };
        let property = self.jsx_identifier(&member.property);
        self.mks(
            Kind::JSXMemberExpression,
            member.span,
            vec![("object", node(object)), ("property", node(property))],
        )
    }

    fn jsx_attribute_item(&mut self, item: &JSXAttributeItem<'_>) -> NodeId {
        match item {
            JSXAttributeItem::Attribute(attribute) => {
                let name = match &attribute.name {
                    JSXAttributeName::Identifier(id) => self.jsx_identifier(id),
                    JSXAttributeName::NamespacedName(ns) => self.jsx_namespaced(ns),
                };
                let value = attribute.value.as_ref().map(|value| match value {
                    JSXAttributeValue::StringLiteral(lit) => self.string_literal(lit),
                    JSXAttributeValue::ExpressionContainer(container) => {
                        self.jsx_expression_container(container)
                    }
                    JSXAttributeValue::Element(element) => self.jsx_element(element),
                    JSXAttributeValue::Fragment(fragment) => self.jsx_fragment(fragment),
                });
                self.mks(
                    Kind::JSXAttribute,
                    attribute.span,
                    vec![("name", node(name)), ("value", opt(value))],
                )
            }
            JSXAttributeItem::SpreadAttribute(spread) => {
                let argument = self.expression(&spread.argument);
                self.mks(
                    Kind::JSXSpreadAttribute,
                    spread.span,
                    vec![("argument", node(argument))],
                )
            }
        }
    }

    fn jsx_expression_container(&mut self, container: &JSXExpressionContainer<'_>) -> NodeId {
        let expression = match &container.expression {
            JSXExpression::EmptyExpression(empty) => {
                // Babel: the empty expression spans the gap between the braces.
                let (start, end) = self.span(container.span);
                let _ = empty;
                self.mk(Kind::JSXEmptyExpression, start + 1, end.saturating_sub(1), vec![])
            }
            other => {
                let expression = other.to_expression();
                self.expression(expression)
            }
        };
        self.mks(
            Kind::JSXExpressionContainer,
            container.span,
            vec![("expression", node(expression))],
        )
    }

    fn jsx_child(&mut self, child: &JSXChild<'_>) -> NodeId {
        match child {
            JSXChild::Text(text) => self.mks(
                Kind::JSXText,
                text.span,
                vec![("value", string(text.value.as_str()))],
            ),
            JSXChild::Element(element) => self.jsx_element(element),
            JSXChild::Fragment(fragment) => self.jsx_fragment(fragment),
            JSXChild::ExpressionContainer(container) => self.jsx_expression_container(container),
            JSXChild::Spread(spread) => {
                let expression = self.expression(&spread.expression);
                self.mks(
                    Kind::JSXSpreadChild,
                    spread.span,
                    vec![("expression", node(expression))],
                )
            }
        }
    }
}
