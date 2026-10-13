//! Patterns, assignment targets, functions and classes.

use oxc_ast::ast::*;
use oxc_span::GetSpan;

use super::convert::{flag, list, node, opt, string, Cx};
use super::{Kind, NodeId, Val};

type Fields = Vec<(&'static str, Val)>;

/// Everything a Babel function-like node takes from an oxc `Function`.
pub(super) struct FunctionParts {
    pub id: Option<NodeId>,
    pub type_parameters: Option<NodeId>,
    pub params: Vec<NodeId>,
    pub return_type: Option<NodeId>,
    pub body: Option<NodeId>,
    pub generator: bool,
    pub is_async: bool,
}

impl FunctionParts {
    pub(super) fn into_method_fields(self) -> Fields {
        let mut fields: Fields = vec![
            ("generator", flag(self.generator)),
            ("async", flag(self.is_async)),
            ("params", list(self.params)),
            ("returnType", opt(self.return_type)),
            ("typeParameters", opt(self.type_parameters)),
        ];
        if let Some(body) = self.body {
            fields.push(("body", node(body)));
        }
        fields
    }
}

fn accessibility(value: Option<TSAccessibility>) -> Option<&'static str> {
    value.map(|a| match a {
        TSAccessibility::Private => "private",
        TSAccessibility::Protected => "protected",
        TSAccessibility::Public => "public",
    })
}

impl<'s> Cx<'s> {
    // ---- binding patterns --------------------------------------------------------------------

    pub(super) fn binding_pattern(&mut self, pattern: &BindingPattern<'_>) -> NodeId {
        super::convert::grow(|| self.binding_pattern_inner(pattern))
    }

    fn binding_pattern_inner(&mut self, pattern: &BindingPattern<'_>) -> NodeId {
        let id = self.binding_pattern_bare(pattern);
        self.annotate(id, pattern.type_annotation.as_deref(), pattern.optional);
        id
    }

    /// Babel extends an identifier or pattern over its `?` and type annotation.
    pub(super) fn annotate(&mut self, id: NodeId, annotation: Option<&TSTypeAnnotation<'_>>, optional: bool) {
        if optional {
            self.set(id, "optional", flag(true));
        }
        if let Some(annotation) = annotation {
            let ty = self.ts_type_annotation(annotation);
            self.set(id, "typeAnnotation", node(ty));
            let end = self.end_of(ty);
            self.set_end(id, end);
        } else if optional {
            let end = self.after_question(self.end_of(id));
            self.set_end(id, end);
        }
    }

    pub(super) fn after_question(&self, end: u32) -> u32 {
        let rest = self.src.slice(end, self.src.len16());
        let mut offset = 0u32;
        for ch in rest.chars() {
            if ch == '?' {
                return end + offset + 1;
            }
            if !ch.is_whitespace() {
                break;
            }
            offset += ch.len_utf16() as u32;
        }
        end
    }

    fn binding_pattern_bare(&mut self, pattern: &BindingPattern<'_>) -> NodeId {
        match &pattern.kind {
            BindingPatternKind::BindingIdentifier(id) => self.ident(id.name.as_str(), id.span),
            BindingPatternKind::ObjectPattern(object) => {
                let mut properties: Vec<NodeId> = object
                    .properties
                    .iter()
                    .map(|property| {
                        let key = self.property_key(&property.key);
                        let value = self.binding_pattern(&property.value);
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
                    })
                    .collect();
                if let Some(rest) = &object.rest {
                    properties.push(self.rest_element(rest));
                }
                self.mks(Kind::ObjectPattern, object.span, vec![("properties", list(properties))])
            }
            BindingPatternKind::ArrayPattern(array) => {
                let mut elements: Vec<Option<NodeId>> = array
                    .elements
                    .iter()
                    .map(|element| element.as_ref().map(|e| self.binding_pattern(e)))
                    .collect();
                if let Some(rest) = &array.rest {
                    elements.push(Some(self.rest_element(rest)));
                }
                self.mks(Kind::ArrayPattern, array.span, vec![("elements", Val::List(elements))])
            }
            BindingPatternKind::AssignmentPattern(assign) => {
                let left = self.binding_pattern(&assign.left);
                let right = self.expression(&assign.right);
                self.mks(
                    Kind::AssignmentPattern,
                    assign.span,
                    vec![("left", node(left)), ("right", node(right))],
                )
            }
        }
    }

    pub(super) fn rest_element(&mut self, rest: &BindingRestElement<'_>) -> NodeId {
        let argument = self.binding_pattern_bare(&rest.argument);
        let id = self.mks(Kind::RestElement, rest.span, vec![("argument", node(argument))]);
        self.annotate(id, rest.argument.type_annotation.as_deref(), rest.argument.optional);
        id
    }

    // ---- assignment targets ------------------------------------------------------------------

    pub(super) fn assignment_target(&mut self, target: &AssignmentTarget<'_>) -> NodeId {
        super::convert::grow(|| self.assignment_target_inner(target))
    }

    fn assignment_target_inner(&mut self, target: &AssignmentTarget<'_>) -> NodeId {
        if let Some(simple) = target.as_simple_assignment_target() {
            return self.simple_assignment_target(simple);
        }
        match target {
            AssignmentTarget::ArrayAssignmentTarget(array) => {
                let mut elements: Vec<Option<NodeId>> = array
                    .elements
                    .iter()
                    .map(|element| element.as_ref().map(|e| self.assignment_target_maybe_default(e)))
                    .collect();
                if let Some(rest) = &array.rest {
                    elements.push(Some(self.assignment_rest(rest)));
                }
                self.mks(Kind::ArrayPattern, array.span, vec![("elements", Val::List(elements))])
            }
            AssignmentTarget::ObjectAssignmentTarget(object) => {
                let mut properties: Vec<NodeId> = object
                    .properties
                    .iter()
                    .map(|property| self.assignment_target_property(property))
                    .collect();
                if let Some(rest) = &object.rest {
                    properties.push(self.assignment_rest(rest));
                }
                self.mks(Kind::ObjectPattern, object.span, vec![("properties", list(properties))])
            }
            _ => self.unsupported("assignment target"),
        }
    }

    fn assignment_rest(&mut self, rest: &AssignmentTargetRest<'_>) -> NodeId {
        let argument = self.assignment_target(&rest.target);
        self.mks(Kind::RestElement, rest.span, vec![("argument", node(argument))])
    }

    pub(super) fn simple_assignment_target(&mut self, target: &SimpleAssignmentTarget<'_>) -> NodeId {
        match target {
            SimpleAssignmentTarget::AssignmentTargetIdentifier(id) => self.ident(id.name.as_str(), id.span),
            SimpleAssignmentTarget::TSAsExpression(expr) => {
                let inner = self.expression(&expr.expression);
                let ty = self.ts_type(&expr.type_annotation);
                self.mks(
                    Kind::TSAsExpression,
                    expr.span,
                    vec![("expression", node(inner)), ("typeAnnotation", node(ty))],
                )
            }
            SimpleAssignmentTarget::TSSatisfiesExpression(expr) => {
                let inner = self.expression(&expr.expression);
                let ty = self.ts_type(&expr.type_annotation);
                self.mks(
                    Kind::TSSatisfiesExpression,
                    expr.span,
                    vec![("expression", node(inner)), ("typeAnnotation", node(ty))],
                )
            }
            SimpleAssignmentTarget::TSNonNullExpression(expr) => {
                let inner = self.expression(&expr.expression);
                self.mks(
                    Kind::TSNonNullExpression,
                    expr.span,
                    vec![("expression", node(inner))],
                )
            }
            SimpleAssignmentTarget::TSTypeAssertion(expr) => {
                let ty = self.ts_type(&expr.type_annotation);
                let inner = self.expression(&expr.expression);
                self.mks(
                    Kind::TSTypeAssertion,
                    expr.span,
                    vec![("typeAnnotation", node(ty)), ("expression", node(inner))],
                )
            }
            other => match other.as_member_expression() {
                Some(member) => self.member_expression(member),
                None => self.unsupported("simple assignment target"),
            },
        }
    }

    fn assignment_target_maybe_default(&mut self, target: &AssignmentTargetMaybeDefault<'_>) -> NodeId {
        match target {
            AssignmentTargetMaybeDefault::AssignmentTargetWithDefault(with_default) => {
                let left = self.assignment_target(&with_default.binding);
                let right = self.expression(&with_default.init);
                self.mks(
                    Kind::AssignmentPattern,
                    with_default.span,
                    vec![("left", node(left)), ("right", node(right))],
                )
            }
            other => self.assignment_target(other.to_assignment_target()),
        }
    }

    fn assignment_target_property(&mut self, property: &AssignmentTargetProperty<'_>) -> NodeId {
        match property {
            AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(prop) => {
                let key = self.ident(prop.binding.name.as_str(), prop.binding.span);
                let target = self.ident(prop.binding.name.as_str(), prop.binding.span);
                let value = match &prop.init {
                    Some(init) => {
                        let right = self.expression(init);
                        let start = self.start_of(target);
                        let end = self.end_of(right);
                        self.mk(
                            Kind::AssignmentPattern,
                            start,
                            end,
                            vec![("left", node(target)), ("right", node(right))],
                        )
                    }
                    None => target,
                };
                self.mks(
                    Kind::ObjectProperty,
                    prop.span,
                    vec![
                        ("key", node(key)),
                        ("value", node(value)),
                        ("computed", flag(false)),
                        ("shorthand", flag(true)),
                    ],
                )
            }
            AssignmentTargetProperty::AssignmentTargetPropertyProperty(prop) => {
                let key = self.property_key(&prop.name);
                let value = self.assignment_target_maybe_default(&prop.binding);
                self.mks(
                    Kind::ObjectProperty,
                    prop.span,
                    vec![
                        ("key", node(key)),
                        ("value", node(value)),
                        ("computed", flag(prop.computed)),
                        ("shorthand", flag(false)),
                    ],
                )
            }
        }
    }

    // ---- functions ---------------------------------------------------------------------------

    pub(super) fn decorators(&mut self, decorators: &[Decorator<'_>]) -> Val {
        let items = decorators
            .iter()
            .map(|decorator| {
                let expression = self.expression(&decorator.expression);
                self.mks(Kind::Decorator, decorator.span, vec![("expression", node(expression))])
            })
            .collect();
        list(items)
    }

    pub(super) fn formal_params(
        &mut self,
        params: &FormalParameters<'_>,
        this_param: Option<&TSThisParameter<'_>>,
    ) -> Vec<NodeId> {
        let mut out = Vec::new();
        if let Some(this_param) = this_param {
            let (start, mut end) = self.span(this_param.this_span);
            let mut fields = vec![("name", string("this"))];
            let annotation = this_param.type_annotation.as_ref().map(|a| self.ts_type_annotation(a));
            if let Some(annotation) = annotation {
                fields.push(("typeAnnotation", node(annotation)));
                end = self.end_of(annotation);
            }
            out.push(self.mk(Kind::Identifier, start, end, fields));
        }
        for param in &params.items {
            let pattern = self.binding_pattern(&param.pattern);
            let has_modifier =
                param.accessibility.is_some() || param.readonly || param.r#override;
            if has_modifier {
                let decorators = self.decorators(&param.decorators);
                let mut fields = vec![("parameter", node(pattern))];
                if let Some(acc) = accessibility(param.accessibility) {
                    fields.push(("accessibility", string(acc)));
                }
                if param.readonly {
                    fields.push(("readonly", flag(true)));
                }
                if param.r#override {
                    fields.push(("override", flag(true)));
                }
                fields.push(("decorators", decorators));
                out.push(self.mks(Kind::TSParameterProperty, param.span, fields));
            } else {
                if !param.decorators.is_empty() {
                    let decorators = self.decorators(&param.decorators);
                    self.set(pattern, "decorators", decorators);
                }
                out.push(pattern);
            }
        }
        if let Some(rest) = &params.rest {
            out.push(self.rest_element(rest));
        }
        out
    }

    pub(super) fn function_body(&mut self, body: &FunctionBody<'_>) -> NodeId {
        let directives = body.directives.iter().map(|d| self.directive_node(d)).collect();
        let statements = body.statements.iter().map(|s| self.statement(s)).collect();
        self.mks(
            Kind::BlockStatement,
            body.span,
            vec![("directives", list(directives)), ("body", list(statements))],
        )
    }

    pub(super) fn directive_node(&mut self, directive: &oxc_ast::ast::Directive<'_>) -> NodeId {
        let literal = self.mks(
            Kind::DirectiveLiteral,
            directive.expression.span,
            vec![("value", string(directive.directive.as_str()))],
        );
        self.mks(Kind::Directive, directive.span, vec![("value", node(literal))])
    }

    pub(super) fn function_parts(&mut self, function: &Function<'_>) -> FunctionParts {
        self.fn_depth += 1;
        let parts = self.function_parts_inner(function);
        self.fn_depth -= 1;
        parts
    }

    fn function_parts_inner(&mut self, function: &Function<'_>) -> FunctionParts {
        let id = function.id.as_ref().map(|id| self.ident(id.name.as_str(), id.span));
        let type_parameters = function.type_parameters.as_ref().map(|t| self.ts_type_params(t));
        let params = self.formal_params(&function.params, function.this_param.as_deref());
        let return_type = function.return_type.as_ref().map(|t| self.ts_type_annotation(t));
        let body = function.body.as_ref().map(|b| self.function_body(b));
        FunctionParts {
            id,
            type_parameters,
            params,
            return_type,
            body,
            generator: function.generator,
            is_async: function.r#async,
        }
    }

    /// `FunctionDeclaration`, `FunctionExpression` or `TSDeclareFunction`.
    pub(super) fn function(&mut self, function: &Function<'_>) -> NodeId {
        let kind = match function.r#type {
            FunctionType::FunctionDeclaration => Kind::FunctionDeclaration,
            FunctionType::FunctionExpression => Kind::FunctionExpression,
            FunctionType::TSDeclareFunction | FunctionType::TSEmptyBodyFunctionExpression => {
                Kind::TSDeclareFunction
            }
        };
        let entered = self.enter_declare(function.declare);
        if function.r#type == FunctionType::FunctionDeclaration && function.body.is_some() {
            self.ambient_implementation();
        }
        let parts = self.function_parts(function);
        let mut fields: Fields = vec![("id", opt(parts.id))];
        if function.declare {
            fields.push(("declare", flag(true)));
        }
        fields.extend(parts.into_method_fields());
        self.leave_declare(entered);
        self.mks(kind, function.span, fields)
    }

    pub(super) fn arrow(&mut self, arrow: &ArrowFunctionExpression<'_>) -> NodeId {
        self.fn_depth += 1;
        let id = self.arrow_inner(arrow);
        self.fn_depth -= 1;
        id
    }

    fn arrow_inner(&mut self, arrow: &ArrowFunctionExpression<'_>) -> NodeId {
        let type_parameters = arrow.type_parameters.as_ref().map(|t| self.ts_type_params(t));
        let params = self.formal_params(&arrow.params, None);
        let return_type = arrow.return_type.as_ref().map(|t| self.ts_type_annotation(t));
        let body = if arrow.expression {
            match arrow.body.statements.first() {
                Some(Statement::ExpressionStatement(stmt)) => self.expression(&stmt.expression),
                _ => self.unsupported("arrow expression body"),
            }
        } else {
            self.function_body(&arrow.body)
        };
        self.mks(
            Kind::ArrowFunctionExpression,
            arrow.span,
            vec![
                ("generator", flag(false)),
                ("async", flag(arrow.r#async)),
                ("params", list(params)),
                ("returnType", opt(return_type)),
                ("typeParameters", opt(type_parameters)),
                ("body", node(body)),
            ],
        )
    }

    // ---- classes -----------------------------------------------------------------------------

    pub(super) fn class(&mut self, class: &Class<'_>) -> NodeId {
        let entered = self.enter_declare(class.declare);
        let id = self.class_inner(class);
        self.leave_declare(entered);
        id
    }

    fn class_inner(&mut self, class: &Class<'_>) -> NodeId {
        let kind = match class.r#type {
            ClassType::ClassDeclaration => Kind::ClassDeclaration,
            ClassType::ClassExpression => Kind::ClassExpression,
        };
        let decorators = self.decorators(&class.decorators);
        let id = class.id.as_ref().map(|id| self.ident(id.name.as_str(), id.span));
        let type_parameters = class.type_parameters.as_ref().map(|t| self.ts_type_params(t));
        let super_class = class.super_class.as_ref().map(|e| self.expression(e));
        let super_type_arguments = class.super_type_arguments.as_ref().map(|t| self.ts_type_args(t));
        let implements = class
            .implements
            .iter()
            .map(|item| {
                let expression = self.ts_type_name_as_member(&item.expression);
                let type_arguments = item.type_arguments.as_ref().map(|t| self.ts_type_args(t));
                self.mks(
                    Kind::TSClassImplements,
                    item.span,
                    vec![("expression", node(expression)), ("typeArguments", opt(type_arguments))],
                )
            })
            .collect();
        let members = class
            .body
            .body
            .iter()
            .filter_map(|element| self.class_element(element))
            .collect();
        let body = self.mks(Kind::ClassBody, class.body.span, vec![("body", list(members))]);
        let mut fields: Fields = vec![
            ("decorators", decorators),
            ("id", opt(id)),
            ("typeParameters", opt(type_parameters)),
            ("superClass", opt(super_class)),
            ("superTypeArguments", opt(super_type_arguments)),
            ("implements", list(implements)),
            ("body", node(body)),
        ];
        if class.r#abstract {
            fields.push(("abstract", flag(true)));
        }
        if class.declare {
            fields.push(("declare", flag(true)));
        }
        self.mks(kind, class.span, fields)
    }

    fn class_element(&mut self, element: &ClassElement<'_>) -> Option<NodeId> {
        Some(match element {
            ClassElement::StaticBlock(block) => {
                let body = block.body.iter().map(|s| self.statement(s)).collect();
                self.mks(Kind::StaticBlock, block.span, vec![("body", list(body))])
            }
            ClassElement::MethodDefinition(method) => self.method_definition(method),
            ClassElement::PropertyDefinition(property) => {
                self.ambient_property(property);
                let private = matches!(property.key, PropertyKey::PrivateIdentifier(_));
                let decorators = self.decorators(&property.decorators);
                let key = self.property_key(&property.key);
                let type_annotation = property.type_annotation.as_ref().map(|t| self.ts_type_annotation(t));
                let value = property.value.as_ref().map(|e| self.expression(e));
                let mut fields: Fields = vec![
                    ("decorators", decorators),
                    ("key", node(key)),
                    ("typeAnnotation", opt(type_annotation)),
                    ("value", opt(value)),
                    ("static", flag(property.r#static)),
                    ("computed", flag(property.computed)),
                ];
                for (name, on) in [
                    ("declare", property.declare),
                    ("override", property.r#override),
                    ("optional", property.optional),
                    ("definite", property.definite),
                    ("readonly", property.readonly),
                    (
                        "abstract",
                        matches!(property.r#type, PropertyDefinitionType::TSAbstractPropertyDefinition),
                    ),
                ] {
                    if on {
                        fields.push((name, flag(true)));
                    }
                }
                if let Some(acc) = accessibility(property.accessibility) {
                    fields.push(("accessibility", string(acc)));
                }
                self.mks(
                    if private { Kind::ClassPrivateProperty } else { Kind::ClassProperty },
                    property.span,
                    fields,
                )
            }
            ClassElement::AccessorProperty(property) => {
                let decorators = self.decorators(&property.decorators);
                let key = self.property_key(&property.key);
                let type_annotation = property.type_annotation.as_ref().map(|t| self.ts_type_annotation(t));
                let value = property.value.as_ref().map(|e| self.expression(e));
                let mut fields: Fields = vec![
                    ("decorators", decorators),
                    ("key", node(key)),
                    ("typeAnnotation", opt(type_annotation)),
                    ("value", opt(value)),
                    ("static", flag(property.r#static)),
                    ("computed", flag(property.computed)),
                ];
                for (name, on) in [("override", property.r#override), ("definite", property.definite)] {
                    if on {
                        fields.push((name, flag(true)));
                    }
                }
                self.mks(Kind::ClassAccessorProperty, property.span, fields)
            }
            ClassElement::TSIndexSignature(signature) => self.ts_index_signature(signature),
        })
    }

    fn method_definition(&mut self, method: &MethodDefinition<'_>) -> NodeId {
        let decorators = self.decorators(&method.decorators);
        let private = matches!(method.key, PropertyKey::PrivateIdentifier(_));
        let key = self.property_key(&method.key);
        let parts = self.function_parts(&method.value);
        let has_body = parts.body.is_some();
        if has_body {
            self.ambient_implementation();
        }
        let kind_text = match method.kind {
            MethodDefinitionKind::Constructor => "constructor",
            MethodDefinitionKind::Method => "method",
            MethodDefinitionKind::Get => "get",
            MethodDefinitionKind::Set => "set",
        };
        let kind = if !has_body {
            Kind::TSDeclareMethod
        } else if private {
            Kind::ClassPrivateMethod
        } else {
            Kind::ClassMethod
        };
        let mut fields: Fields = vec![
            ("decorators", decorators),
            ("key", node(key)),
            ("kind", string(kind_text)),
            ("static", flag(method.r#static)),
            ("computed", flag(method.computed)),
        ];
        for (name, on) in [
            ("override", method.r#override),
            ("optional", method.optional),
            (
                "abstract",
                matches!(method.r#type, MethodDefinitionType::TSAbstractMethodDefinition),
            ),
        ] {
            if on {
                fields.push((name, flag(true)));
            }
        }
        if let Some(acc) = accessibility(method.accessibility) {
            fields.push(("accessibility", string(acc)));
        }
        fields.extend(parts.into_method_fields());
        self.mks(kind, method.span, fields)
    }

    #[allow(dead_code)]
    pub(super) fn span_of<T: GetSpan>(&self, item: &T) -> (u32, u32) {
        self.span(item.span())
    }
}
