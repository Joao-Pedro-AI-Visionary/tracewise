//! TypeScript syntax (types, declarations) -> Babel `TS*` nodes.

use oxc_ast::ast::*;

use super::convert::{flag, list, node, opt, string, Cx};
use super::convert_scope::FrameKind;
use super::{Kind, NodeId, Val};

type Fields = Vec<(&'static str, Val)>;

impl<'s> Cx<'s> {
    pub(super) fn ts_type_annotation(&mut self, annotation: &TSTypeAnnotation<'_>) -> NodeId {
        let ty = self.ts_type(&annotation.type_annotation);
        self.mks(
            Kind::TSTypeAnnotation,
            annotation.span,
            vec![("typeAnnotation", node(ty))],
        )
    }

    pub(super) fn ts_type_args(&mut self, args: &TSTypeParameterInstantiation<'_>) -> NodeId {
        let params = args.params.iter().map(|t| self.ts_type(t)).collect();
        self.mks(
            Kind::TSTypeParameterInstantiation,
            args.span,
            vec![("params", list(params))],
        )
    }

    pub(super) fn ts_type_params(&mut self, params: &TSTypeParameterDeclaration<'_>) -> NodeId {
        let items = params.params.iter().map(|p| self.ts_type_parameter(p)).collect();
        self.mks(
            Kind::TSTypeParameterDeclaration,
            params.span,
            vec![("params", list(items))],
        )
    }

    fn ts_type_parameter(&mut self, param: &TSTypeParameter<'_>) -> NodeId {
        let name = self.ident(param.name.name.as_str(), param.name.span);
        let constraint = param.constraint.as_ref().map(|t| self.ts_type(t));
        let default = param.default.as_ref().map(|t| self.ts_type(t));
        let mut fields: Fields = vec![
            ("name", node(name)),
            ("constraint", opt(constraint)),
            ("default", opt(default)),
        ];
        for (key, on) in [("in", param.r#in), ("out", param.out), ("const", param.r#const)] {
            if on {
                fields.push((key, flag(true)));
            }
        }
        self.mks(Kind::TSTypeParameter, param.span, fields)
    }

    pub(super) fn ts_type_name(&mut self, name: &TSTypeName<'_>) -> NodeId {
        match name {
            TSTypeName::IdentifierReference(id) => self.ident(id.name.as_str(), id.span),
            TSTypeName::QualifiedName(q) => self.ts_qualified_name(q),
        }
    }

    /// `implements a.b.C`: Babel reports the heritage expression as a `MemberExpression` chain
    /// (unlike type references, which use `TSQualifiedName`).
    pub(super) fn ts_type_name_as_member(&mut self, name: &TSTypeName<'_>) -> NodeId {
        match name {
            TSTypeName::IdentifierReference(id) => self.ident(id.name.as_str(), id.span),
            TSTypeName::QualifiedName(q) => {
                let object = self.ts_type_name_as_member(&q.left);
                let property = self.ident(q.right.name.as_str(), q.right.span);
                self.mks(
                    Kind::MemberExpression,
                    q.span,
                    vec![
                        ("object", node(object)),
                        ("computed", flag(false)),
                        ("property", node(property)),
                    ],
                )
            }
        }
    }

    fn ts_qualified_name(&mut self, name: &TSQualifiedName<'_>) -> NodeId {
        let left = self.ts_type_name(&name.left);
        let right = self.ident(name.right.name.as_str(), name.right.span);
        self.mks(
            Kind::TSQualifiedName,
            name.span,
            vec![("left", node(left)), ("right", node(right))],
        )
    }

    pub(super) fn ts_type(&mut self, ty: &TSType<'_>) -> NodeId {
        super::convert::grow(|| self.ts_type_inner(ty))
    }

    fn ts_type_inner(&mut self, ty: &TSType<'_>) -> NodeId {
        macro_rules! keyword {
            ($kind:ident, $node:expr) => {
                self.mks(Kind::$kind, $node.span, vec![])
            };
        }
        match ty {
            TSType::TSAnyKeyword(n) => keyword!(TSAnyKeyword, n),
            TSType::TSBigIntKeyword(n) => keyword!(TSBigIntKeyword, n),
            TSType::TSBooleanKeyword(n) => keyword!(TSBooleanKeyword, n),
            TSType::TSIntrinsicKeyword(n) => keyword!(TSIntrinsicKeyword, n),
            TSType::TSNeverKeyword(n) => keyword!(TSNeverKeyword, n),
            TSType::TSNullKeyword(n) => keyword!(TSNullKeyword, n),
            TSType::TSNumberKeyword(n) => keyword!(TSNumberKeyword, n),
            TSType::TSObjectKeyword(n) => keyword!(TSObjectKeyword, n),
            TSType::TSStringKeyword(n) => keyword!(TSStringKeyword, n),
            TSType::TSSymbolKeyword(n) => keyword!(TSSymbolKeyword, n),
            TSType::TSUndefinedKeyword(n) => keyword!(TSUndefinedKeyword, n),
            TSType::TSUnknownKeyword(n) => keyword!(TSUnknownKeyword, n),
            TSType::TSVoidKeyword(n) => keyword!(TSVoidKeyword, n),
            TSType::TSThisType(n) => keyword!(TSThisType, n),
            TSType::TSArrayType(n) => {
                let element = self.ts_type(&n.element_type);
                self.mks(Kind::TSArrayType, n.span, vec![("elementType", node(element))])
            }
            TSType::TSConditionalType(n) => {
                let check = self.ts_type(&n.check_type);
                let extends = self.ts_type(&n.extends_type);
                let true_type = self.ts_type(&n.true_type);
                let false_type = self.ts_type(&n.false_type);
                let id = self.mks(
                    Kind::TSConditionalType,
                    n.span,
                    vec![
                        ("checkType", node(check)),
                        ("extendsType", node(extends)),
                        ("trueType", node(true_type)),
                        ("falseType", node(false_type)),
                    ],
                );
                // Babel starts a conditional type at its unparenthesized check type.
                self.set_start(id, self.start_of(check));
                id
            }
            TSType::TSConstructorType(n) => {
                let type_parameters = n.type_parameters.as_ref().map(|t| self.ts_type_params(t));
                let params = self.formal_params(&n.params, None);
                let return_type = self.ts_type_annotation(&n.return_type);
                let mut fields: Fields = vec![
                    ("typeParameters", opt(type_parameters)),
                    ("params", list(params)),
                    ("returnType", node(return_type)),
                ];
                if n.r#abstract {
                    fields.push(("abstract", flag(true)));
                }
                self.mks(Kind::TSConstructorType, n.span, fields)
            }
            TSType::TSFunctionType(n) => {
                let type_parameters = n.type_parameters.as_ref().map(|t| self.ts_type_params(t));
                let params = self.formal_params(&n.params, n.this_param.as_deref());
                let return_type = self.ts_type_annotation(&n.return_type);
                self.mks(
                    Kind::TSFunctionType,
                    n.span,
                    vec![
                        ("typeParameters", opt(type_parameters)),
                        ("params", list(params)),
                        ("returnType", node(return_type)),
                    ],
                )
            }
            TSType::TSImportType(n) => self.ts_import_type(n),
            TSType::TSIndexedAccessType(n) => {
                let object = self.ts_type(&n.object_type);
                let index = self.ts_type(&n.index_type);
                self.mks(
                    Kind::TSIndexedAccessType,
                    n.span,
                    vec![("objectType", node(object)), ("indexType", node(index))],
                )
            }
            TSType::TSInferType(n) => {
                let parameter = self.ts_type_parameter(&n.type_parameter);
                self.mks(Kind::TSInferType, n.span, vec![("typeParameter", node(parameter))])
            }
            TSType::TSIntersectionType(n) => {
                let types = n.types.iter().map(|t| self.ts_type(t)).collect();
                self.mks(Kind::TSIntersectionType, n.span, vec![("types", list(types))])
            }
            TSType::TSLiteralType(n) => {
                let literal = match &n.literal {
                    TSLiteral::BooleanLiteral(lit) => {
                        self.mks(Kind::BooleanLiteral, lit.span, vec![("value", flag(lit.value))])
                    }
                    TSLiteral::NumericLiteral(lit) => self.numeric_literal(lit),
                    TSLiteral::BigIntLiteral(lit) => {
                        let raw = lit.raw.as_ref().map(|r| r.as_str()).unwrap_or("");
                        let value = super::convert::bigint_decimal(raw);
                        self.mks(Kind::BigIntLiteral, lit.span, vec![("value", Val::Str(value))])
                    }
                    TSLiteral::StringLiteral(lit) => self.string_literal(lit),
                    TSLiteral::TemplateLiteral(template) => {
                        let quasis = template
                            .quasis
                            .iter()
                            .map(|quasi| self.template_element(quasi))
                            .collect();
                        let expressions =
                            template.expressions.iter().map(|e| self.expression(e)).collect();
                        self.mks(
                            Kind::TemplateLiteral,
                            template.span,
                            vec![("quasis", list(quasis)), ("expressions", list(expressions))],
                        )
                    }
                    TSLiteral::UnaryExpression(unary) => {
                        let argument = self.expression(&unary.argument);
                        self.mks(
                            Kind::UnaryExpression,
                            unary.span,
                            vec![
                                ("operator", string(unary.operator.as_str())),
                                ("prefix", flag(true)),
                                ("argument", node(argument)),
                            ],
                        )
                    }
                };
                self.mks(Kind::TSLiteralType, n.span, vec![("literal", node(literal))])
            }
            TSType::TSMappedType(n) => {
                let key = self.ident(n.type_parameter.name.name.as_str(), n.type_parameter.name.span);
                let constraint = n.type_parameter.constraint.as_ref().map(|t| self.ts_type(t));
                let name_type = n.name_type.as_ref().map(|t| self.ts_type(t));
                let type_annotation = n.type_annotation.as_ref().map(|t| self.ts_type(t));
                let modifier = |m: Option<TSMappedTypeModifierOperator>| match m {
                    None => Val::Null,
                    Some(TSMappedTypeModifierOperator::True) => flag(true),
                    Some(TSMappedTypeModifierOperator::Plus) => string("+"),
                    Some(TSMappedTypeModifierOperator::Minus) => string("-"),
                };
                let mut fields: Fields = vec![
                    ("key", node(key)),
                    ("constraint", opt(constraint)),
                    ("nameType", opt(name_type)),
                    ("typeAnnotation", opt(type_annotation)),
                ];
                if n.readonly.is_some() {
                    fields.push(("readonly", modifier(n.readonly)));
                }
                if n.optional.is_some() {
                    fields.push(("optional", modifier(n.optional)));
                }
                self.mks(Kind::TSMappedType, n.span, fields)
            }
            TSType::TSNamedTupleMember(n) => self.ts_named_tuple_member(n),
            TSType::TSTemplateLiteralType(n) => {
                let quasis = n.quasis.iter().map(|q| self.template_element(q)).collect();
                let types = n.types.iter().map(|t| self.ts_type(t)).collect();
                self.mks(
                    Kind::TSTemplateLiteralType,
                    n.span,
                    vec![("quasis", list(quasis)), ("types", list(types))],
                )
            }
            TSType::TSTupleType(n) => {
                let elements = n
                    .element_types
                    .iter()
                    .map(|element| self.ts_tuple_element(element))
                    .collect();
                self.mks(Kind::TSTupleType, n.span, vec![("elementTypes", list(elements))])
            }
            TSType::TSTypeLiteral(n) => {
                let members = n.members.iter().map(|m| self.ts_signature(m)).collect();
                self.mks(Kind::TSTypeLiteral, n.span, vec![("members", list(members))])
            }
            TSType::TSTypeOperatorType(n) => {
                let ty = self.ts_type(&n.type_annotation);
                let operator = match n.operator {
                    TSTypeOperatorOperator::Keyof => "keyof",
                    TSTypeOperatorOperator::Unique => "unique",
                    TSTypeOperatorOperator::Readonly => "readonly",
                };
                self.mks(
                    Kind::TSTypeOperator,
                    n.span,
                    vec![("operator", string(operator)), ("typeAnnotation", node(ty))],
                )
            }
            TSType::TSTypePredicate(n) => {
                let parameter = match &n.parameter_name {
                    TSTypePredicateName::Identifier(id) => self.ident(id.name.as_str(), id.span),
                    TSTypePredicateName::This(this) => self.mks(Kind::TSThisType, this.span, vec![]),
                };
                let annotation = n.type_annotation.as_ref().map(|a| self.ts_type_annotation(a));
                self.mks(
                    Kind::TSTypePredicate,
                    n.span,
                    vec![
                        ("parameterName", node(parameter)),
                        ("typeAnnotation", opt(annotation)),
                        ("asserts", flag(n.asserts)),
                    ],
                )
            }
            TSType::TSTypeQuery(n) => {
                let name = match &n.expr_name {
                    TSTypeQueryExprName::TSImportType(import) => self.ts_import_type(import),
                    other => {
                        let type_name = other.to_ts_type_name();
                        self.ts_type_name(type_name)
                    }
                };
                let type_arguments = n.type_arguments.as_ref().map(|t| self.ts_type_args(t));
                self.mks(
                    Kind::TSTypeQuery,
                    n.span,
                    vec![("exprName", node(name)), ("typeArguments", opt(type_arguments))],
                )
            }
            TSType::TSTypeReference(n) => {
                let name = self.ts_type_name(&n.type_name);
                let type_arguments = n.type_arguments.as_ref().map(|t| self.ts_type_args(t));
                self.mks(
                    Kind::TSTypeReference,
                    n.span,
                    vec![("typeName", node(name)), ("typeArguments", opt(type_arguments))],
                )
            }
            TSType::TSUnionType(n) => {
                let types = n.types.iter().map(|t| self.ts_type(t)).collect();
                self.mks(Kind::TSUnionType, n.span, vec![("types", list(types))])
            }
            TSType::TSParenthesizedType(n) => self.ts_type(&n.type_annotation),
            TSType::JSDocNullableType(_)
            | TSType::JSDocNonNullableType(_)
            | TSType::JSDocUnknownType(_) => self.unsupported("JSDoc type"),
        }
    }

    fn ts_import_type(&mut self, import: &TSImportType<'_>) -> NodeId {
        let source = match &import.argument {
            TSType::TSLiteralType(literal) => match &literal.literal {
                TSLiteral::StringLiteral(lit) => self.string_literal(lit),
                _ => self.unsupported("import type argument"),
            },
            _ => self.unsupported("import type argument"),
        };
        let options = import.options.as_ref().map(|o| {
            let properties = o
                .properties
                .iter()
                .map(|property| match property {
                    ObjectPropertyKind::ObjectProperty(property) => {
                        let key = self.property_key(&property.key);
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
                    ObjectPropertyKind::SpreadProperty(spread) => {
                        let argument = self.expression(&spread.argument);
                        self.mks(Kind::SpreadElement, spread.span, vec![("argument", node(argument))])
                    }
                })
                .collect();
            self.mks(Kind::ObjectExpression, o.span, vec![("properties", list(properties))])
        });
        let qualifier = import.qualifier.as_ref().map(|q| self.ts_type_name(q));
        let type_arguments = import.type_arguments.as_ref().map(|t| self.ts_type_args(t));
        self.mks(
            Kind::TSImportType,
            import.span,
            vec![
                ("source", node(source)),
                ("options", opt(options)),
                ("qualifier", opt(qualifier)),
                ("typeArguments", opt(type_arguments)),
            ],
        )
    }

    fn ts_named_tuple_member(&mut self, member: &TSNamedTupleMember<'_>) -> NodeId {
        let label = self.ident(member.label.name.as_str(), member.label.span);
        let element = self.ts_tuple_element(&member.element_type);
        self.mks(
            Kind::TSNamedTupleMember,
            member.span,
            vec![
                ("label", node(label)),
                ("elementType", node(element)),
                ("optional", flag(member.optional)),
            ],
        )
    }

    fn ts_tuple_element(&mut self, element: &TSTupleElement<'_>) -> NodeId {
        match element {
            TSTupleElement::TSOptionalType(n) => {
                let ty = self.ts_type(&n.type_annotation);
                self.mks(Kind::TSOptionalType, n.span, vec![("typeAnnotation", node(ty))])
            }
            TSTupleElement::TSRestType(n) => {
                let ty = self.ts_type(&n.type_annotation);
                self.mks(Kind::TSRestType, n.span, vec![("typeAnnotation", node(ty))])
            }
            other => {
                let ty = other.to_ts_type();
                self.ts_type(ty)
            }
        }
    }

    pub(super) fn ts_index_signature(&mut self, signature: &TSIndexSignature<'_>) -> NodeId {
        let parameters = signature
            .parameters
            .iter()
            .map(|parameter| {
                let annotation = self.ts_type_annotation(&parameter.type_annotation);
                let (start, _) = self.span(parameter.span);
                let end = self.end_of(annotation);
                self.mk(
                    Kind::Identifier,
                    start,
                    end,
                    vec![
                        ("name", string(parameter.name.as_str())),
                        ("typeAnnotation", node(annotation)),
                    ],
                )
            })
            .collect();
        let annotation = self.ts_type_annotation(&signature.type_annotation);
        let mut fields: Fields = vec![
            ("parameters", list(parameters)),
            ("typeAnnotation", node(annotation)),
        ];
        if signature.readonly {
            fields.push(("readonly", flag(true)));
        }
        if signature.r#static {
            fields.push(("static", flag(true)));
        }
        self.mks(Kind::TSIndexSignature, signature.span, fields)
    }

    fn ts_signature(&mut self, signature: &TSSignature<'_>) -> NodeId {
        match signature {
            TSSignature::TSIndexSignature(n) => self.ts_index_signature(n),
            TSSignature::TSPropertySignature(n) => {
                let key = self.property_key(&n.key);
                let annotation = n.type_annotation.as_ref().map(|a| self.ts_type_annotation(a));
                let mut fields: Fields = vec![
                    ("key", node(key)),
                    ("typeAnnotation", opt(annotation)),
                    ("computed", flag(n.computed)),
                ];
                if n.optional {
                    fields.push(("optional", flag(true)));
                }
                if n.readonly {
                    fields.push(("readonly", flag(true)));
                }
                self.mks(Kind::TSPropertySignature, n.span, fields)
            }
            TSSignature::TSCallSignatureDeclaration(n) => {
                let type_parameters = n.type_parameters.as_ref().map(|t| self.ts_type_params(t));
                let params = self.formal_params(&n.params, n.this_param.as_deref());
                let return_type = n.return_type.as_ref().map(|t| self.ts_type_annotation(t));
                self.mks(
                    Kind::TSCallSignatureDeclaration,
                    n.span,
                    vec![
                        ("typeParameters", opt(type_parameters)),
                        ("params", list(params)),
                        ("returnType", opt(return_type)),
                    ],
                )
            }
            TSSignature::TSConstructSignatureDeclaration(n) => {
                let type_parameters = n.type_parameters.as_ref().map(|t| self.ts_type_params(t));
                let params = self.formal_params(&n.params, None);
                let return_type = n.return_type.as_ref().map(|t| self.ts_type_annotation(t));
                self.mks(
                    Kind::TSConstructSignatureDeclaration,
                    n.span,
                    vec![
                        ("typeParameters", opt(type_parameters)),
                        ("params", list(params)),
                        ("returnType", opt(return_type)),
                    ],
                )
            }
            TSSignature::TSMethodSignature(n) => {
                let key = self.property_key(&n.key);
                let type_parameters = n.type_parameters.as_ref().map(|t| self.ts_type_params(t));
                let params = self.formal_params(&n.params, n.this_param.as_deref());
                let return_type = n.return_type.as_ref().map(|t| self.ts_type_annotation(t));
                let kind = match n.kind {
                    TSMethodSignatureKind::Method => "method",
                    TSMethodSignatureKind::Get => "get",
                    TSMethodSignatureKind::Set => "set",
                };
                let mut fields: Fields = vec![
                    ("key", node(key)),
                    ("kind", string(kind)),
                    ("computed", flag(n.computed)),
                    ("typeParameters", opt(type_parameters)),
                    ("params", list(params)),
                    ("returnType", opt(return_type)),
                ];
                if n.optional {
                    fields.push(("optional", flag(true)));
                }
                self.mks(Kind::TSMethodSignature, n.span, fields)
            }
        }
    }

    // ---- declarations ------------------------------------------------------------------------

    pub(super) fn ts_type_alias(&mut self, decl: &TSTypeAliasDeclaration<'_>) -> NodeId {
        let id = self.ident(decl.id.name.as_str(), decl.id.span);
        let type_parameters = decl.type_parameters.as_ref().map(|t| self.ts_type_params(t));
        let ty = self.ts_type(&decl.type_annotation);
        let mut fields: Fields = vec![
            ("id", node(id)),
            ("typeParameters", opt(type_parameters)),
            ("typeAnnotation", node(ty)),
        ];
        if decl.declare {
            fields.push(("declare", flag(true)));
        }
        self.mks(Kind::TSTypeAliasDeclaration, decl.span, fields)
    }

    pub(super) fn ts_interface(&mut self, decl: &TSInterfaceDeclaration<'_>) -> NodeId {
        let id = self.ident(decl.id.name.as_str(), decl.id.span);
        let type_parameters = decl.type_parameters.as_ref().map(|t| self.ts_type_params(t));
        let extends = decl
            .extends
            .iter()
            .map(|heritage| {
                let expression = self.expression(&heritage.expression);
                let type_arguments = heritage.type_arguments.as_ref().map(|t| self.ts_type_args(t));
                self.mks(
                    Kind::TSInterfaceHeritage,
                    heritage.span,
                    vec![("expression", node(expression)), ("typeArguments", opt(type_arguments))],
                )
            })
            .collect();
        let members = decl.body.body.iter().map(|m| self.ts_signature(m)).collect();
        let body = self.mks(Kind::TSInterfaceBody, decl.body.span, vec![("body", list(members))]);
        let mut fields: Fields = vec![
            ("id", node(id)),
            ("typeParameters", opt(type_parameters)),
            ("extends", list(extends)),
            ("body", node(body)),
        ];
        if decl.declare {
            fields.push(("declare", flag(true)));
        }
        self.mks(Kind::TSInterfaceDeclaration, decl.span, fields)
    }

    pub(super) fn ts_enum(&mut self, decl: &TSEnumDeclaration<'_>) -> NodeId {
        let id = self.ident(decl.id.name.as_str(), decl.id.span);
        let members = decl
            .body
            .members
            .iter()
            .map(|member| {
                let member_id = match &member.id {
                    TSEnumMemberName::Identifier(id) => self.ident(id.name.as_str(), id.span),
                    TSEnumMemberName::String(lit) | TSEnumMemberName::ComputedString(lit) => {
                        self.string_literal(lit)
                    }
                    TSEnumMemberName::ComputedTemplateString(_) => {
                        self.unsupported("computed enum member name")
                    }
                };
                let initializer = member.initializer.as_ref().map(|e| self.expression(e));
                self.mks(
                    Kind::TSEnumMember,
                    member.span,
                    vec![("id", node(member_id)), ("initializer", opt(initializer))],
                )
            })
            .collect();
        let body = self.mks(Kind::TSEnumBody, decl.body.span, vec![("members", list(members))]);
        let mut fields: Fields = vec![("id", node(id)), ("body", node(body))];
        if decl.r#const {
            fields.push(("const", flag(true)));
        }
        if decl.declare {
            fields.push(("declare", flag(true)));
        }
        self.mks(Kind::TSEnumDeclaration, decl.span, fields)
    }

    pub(super) fn ts_module(&mut self, decl: &TSModuleDeclaration<'_>) -> NodeId {
        // Babel 8 flattens `namespace A.B.C {}` into one declaration with a qualified-name id.
        let mut id = match &decl.id {
            TSModuleDeclarationName::Identifier(id) => self.ident(id.name.as_str(), id.span),
            TSModuleDeclarationName::StringLiteral(lit) => self.string_literal(lit),
        };
        let mut body = decl.body.as_ref();
        while let Some(TSModuleDeclarationBody::TSModuleDeclaration(inner)) = body {
            let right = match &inner.id {
                TSModuleDeclarationName::Identifier(name) => self.ident(name.name.as_str(), name.span),
                TSModuleDeclarationName::StringLiteral(lit) => self.string_literal(lit),
            };
            let start = self.start_of(id);
            let end = self.end_of(right);
            id = self.mk(
                Kind::TSQualifiedName,
                start,
                end,
                vec![("left", node(id)), ("right", node(right))],
            );
            body = inner.body.as_ref();
        }
        let body = body.map(|body| match body {
            TSModuleDeclarationBody::TSModuleDeclaration(_) => unreachable!("flattened above"),
            TSModuleDeclarationBody::TSModuleBlock(block) => {
                let directives = block.directives.iter().map(|d| self.directive_node(d)).collect();
                let frame = match (decl.kind, &decl.id) {
                    (TSModuleDeclarationKind::Global, _) => FrameKind::Global,
                    (_, TSModuleDeclarationName::StringLiteral(_)) => FrameKind::Module,
                    _ => FrameKind::Namespace,
                };
                let statements = self.module_block_body(frame, decl.declare, &block.body);
                self.mks(
                    Kind::TSModuleBlock,
                    block.span,
                    vec![("directives", list(directives)), ("body", list(statements))],
                )
            }
        });
        let kind = match decl.kind {
            TSModuleDeclarationKind::Global => "global",
            TSModuleDeclarationKind::Module => "module",
            TSModuleDeclarationKind::Namespace => "namespace",
        };
        let mut fields: Fields = vec![("id", node(id)), ("kind", string(kind))];
        if let Some(body) = body {
            fields.push(("body", node(body)));
        }
        if decl.declare {
            fields.push(("declare", flag(true)));
        }
        self.mks(Kind::TSModuleDeclaration, decl.span, fields)
    }

    pub(super) fn ts_import_equals(&mut self, decl: &TSImportEqualsDeclaration<'_>) -> NodeId {
        self.note_import_equals(decl);
        let id = self.ident(decl.id.name.as_str(), decl.id.span);
        let reference = match &decl.module_reference {
            TSModuleReference::ExternalModuleReference(external) => {
                let expression = self.string_literal(&external.expression);
                self.mks(
                    Kind::TSExternalModuleReference,
                    external.span,
                    vec![("expression", node(expression))],
                )
            }
            other => {
                let name = other.to_ts_type_name();
                self.ts_type_name(name)
            }
        };
        let import_kind = match decl.import_kind {
            ImportOrExportKind::Value => "value",
            ImportOrExportKind::Type => "type",
        };
        self.mks(
            Kind::TSImportEqualsDeclaration,
            decl.span,
            vec![
                ("id", node(id)),
                ("moduleReference", node(reference)),
                ("importKind", string(import_kind)),
            ],
        )
    }
}
