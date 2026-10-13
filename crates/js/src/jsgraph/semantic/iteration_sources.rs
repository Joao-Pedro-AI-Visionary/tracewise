//! Port of `javascriptSemanticIterationSources.ts`: iterator receivers and property reference
//! stores, described without evaluation.

use std::collections::HashSet;

use crate::jsgraph::ast::{Alias, Kind, N};
use crate::jsgraph::ast_values::object_pattern_keys;

use super::ast_util::static_key_path;
use super::property_paths::{semantic_array_index, PathKey, PropertyPath, Selection};
use super::state::SourceRef;

/// `"iteration" | "reference-store"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IterationSourceKind {
    Iteration,
    ReferenceStore,
}

/// An iterator receiver or property reference store, with default guards.
#[derive(Clone, Debug)]
pub struct SemanticIterationSource<'a> {
    pub kind: IterationSourceKind,
    pub node: N<'a>,
    pub projection: PropertyPath,
    pub mutation: N<'a>,
    pub fallback_sources: Option<Vec<SourceRef<'a>>>,
    pub required_sources: Option<Vec<SourceRef<'a>>>,
}

#[derive(Clone, Debug)]
struct PatternSource<'a> {
    node: N<'a>,
    projection: PropertyPath,
    /// A rest binding is a fresh array whose children retain their source indices.
    rest_start_index: Option<u64>,
}

#[derive(Clone, Default)]
struct SourceGuards<'a> {
    fallback_sources: Option<Vec<SourceRef<'a>>>,
    required_sources: Option<Vec<SourceRef<'a>>>,
}

fn source_ref<'a>(source: &PatternSource<'a>) -> SourceRef<'a> {
    SourceRef { node: source.node, projection: source.projection.clone() }
}

fn add<'a>(
    sources: &mut Vec<SemanticIterationSource<'a>>,
    node: N<'a>,
    projection: PropertyPath,
    mutation: N<'a>,
    guards: &SourceGuards<'a>,
    kind: IterationSourceKind,
) {
    sources.push(SemanticIterationSource {
        kind,
        node,
        projection,
        mutation,
        fallback_sources: guards.fallback_sources.clone(),
        required_sources: guards.required_sources.clone(),
    });
}

fn project<'a>(source: Option<&PatternSource<'a>>, key: PathKey) -> Option<PatternSource<'a>> {
    let source = source?;
    let index = if matches!(key, PathKey::Null) { None } else { semantic_array_index(&key) };
    let mut projection = source.projection.clone();
    projection.push(match (source.rest_start_index, index) {
        (Some(start), Some(index)) => PathKey::Index(start + index),
        _ => key,
    });
    Some(PatternSource { node: source.node, projection, rest_start_index: None })
}

struct PatternCollection<'s, 'a> {
    sources: &'s mut Vec<SemanticIterationSource<'a>>,
    mutation: N<'a>,
}

fn visit<'a>(
    context: &mut PatternCollection<'_, 'a>,
    pattern: N<'a>,
    source: Option<PatternSource<'a>>,
    guards: &SourceGuards<'a>,
) {
    let mutation = context.mutation;
    match pattern.kind() {
        Kind::MemberExpression => {
            // Property stores have no lexical alias binding. Preserve the selected reference's
            // escape rather than claiming later writes cannot reach it.
            if let Some(source) = source {
                let projection = match source.rest_start_index {
                    None => source.projection.clone(),
                    Some(start) => {
                        let mut projection = source.projection.clone();
                        projection.push(PathKey::Select(Selection { excluded_keys: Vec::new(), start_index: Some(start) }));
                        projection
                    }
                };
                add(context.sources, source.node, projection, mutation, guards, IterationSourceKind::ReferenceStore);
            }
        }
        Kind::TSParameterProperty => {
            if let Some(parameter) = pattern.f("parameter") {
                visit(context, parameter, source, guards);
            }
        }
        Kind::AssignmentPattern => {
            let Some(left) = pattern.f("left") else { return };
            let mut required = guards.required_sources.clone().unwrap_or_default();
            if let Some(source) = &source {
                required.push(source_ref(source));
            }
            let required_guards = SourceGuards {
                fallback_sources: guards.fallback_sources.clone(),
                required_sources: Some(required),
            };
            visit(context, left, source.clone(), &required_guards);
            let mut fallback = guards.fallback_sources.clone().unwrap_or_default();
            if let Some(source) = &source {
                fallback.push(source_ref(source));
            }
            let fallback_guards = SourceGuards {
                fallback_sources: Some(fallback),
                required_sources: guards.required_sources.clone(),
            };
            if let Some(right) = pattern.f("right") {
                visit(
                    context,
                    left,
                    Some(PatternSource { node: right, projection: Vec::new(), rest_start_index: None }),
                    &fallback_guards,
                );
            }
        }
        Kind::ObjectPattern => {
            for property in pattern.nodes("properties") {
                if property.is(Kind::RestElement) {
                    // A rest copy owns its scalar slots; only selected child references escape
                    // when that fresh copy is stored through a member target.
                    let rest_source = source.as_ref().map(|source| {
                        let mut excluded: Vec<String> = Vec::new();
                        let mut seen = HashSet::new();
                        for key in object_pattern_keys(pattern) {
                            if seen.insert(key.clone()) {
                                excluded.push(key);
                            }
                        }
                        excluded.sort();
                        let mut projection = source.projection.clone();
                        projection.push(PathKey::Select(Selection { excluded_keys: excluded, start_index: None }));
                        PatternSource { node: source.node, projection, rest_start_index: None }
                    });
                    if let Some(argument) = property.f("argument") {
                        visit(context, argument, rest_source, guards);
                    }
                    continue;
                }
                let key = property
                    .f("key")
                    .map(|key| static_key_path(key, property.flag("computed")))
                    .unwrap_or(PathKey::Null);
                if let Some(value) = property.f("value") {
                    visit(context, value, project(source.as_ref(), key), guards);
                }
            }
        }
        Kind::ArrayPattern => {
            if let Some(source) = &source {
                if source.rest_start_index.is_none() {
                    add(
                        context.sources,
                        source.node,
                        source.projection.clone(),
                        mutation,
                        guards,
                        IterationSourceKind::Iteration,
                    );
                }
            }
            for (index, element) in pattern.list("elements").into_iter().enumerate() {
                let Some(element) = element else { continue };
                if element.is(Kind::RestElement) {
                    let rest_source = source.as_ref().map(|source| PatternSource {
                        node: source.node,
                        projection: source.projection.clone(),
                        rest_start_index: Some(source.rest_start_index.unwrap_or(0) + index as u64),
                    });
                    if let Some(argument) = element.f("argument") {
                        visit(context, argument, rest_source, guards);
                    }
                } else {
                    visit(context, element, project(source.as_ref(), PathKey::Index(index as u64)), guards);
                }
            }
        }
        Kind::RestElement => {
            if let Some(argument) = pattern.f("argument") {
                visit(context, argument, None, guards);
            }
        }
        _ => {}
    }
}

/// Describe iterator receivers and property reference stores without evaluation.
pub fn semantic_iteration_sources<'a>(node: N<'a>, parent: Option<N<'a>>) -> Vec<SemanticIterationSource<'a>> {
    let mut sources: Vec<SemanticIterationSource<'a>> = Vec::new();
    let no_guards = SourceGuards::default();
    {
        let mut context = PatternCollection { sources: &mut sources, mutation: node };
        match node.kind() {
            Kind::VariableDeclarator if node.f("init").is_some() => {
                if let (Some(id), Some(init)) = (node.f("id"), node.f("init")) {
                    visit(
                        &mut context,
                        id,
                        Some(PatternSource { node: init, projection: Vec::new(), rest_start_index: None }),
                        &no_guards,
                    );
                }
            }
            Kind::AssignmentExpression
                if matches!(node.str("operator"), Some("=" | "||=" | "&&=" | "??=")) =>
            {
                if let (Some(left), Some(right)) = (node.f("left"), node.f("right")) {
                    visit(
                        &mut context,
                        left,
                        Some(PatternSource { node: right, projection: Vec::new(), rest_start_index: None }),
                        &no_guards,
                    );
                }
            }
            Kind::ForOfStatement => {
                if let Some(right) = node.f("right") {
                    add(context.sources, right, Vec::new(), node, &no_guards, IterationSourceKind::Iteration);
                    let source = PatternSource { node: right, projection: vec![PathKey::Null], rest_start_index: None };
                    if let Some(left) = node.f("left") {
                        if left.is(Kind::VariableDeclaration) {
                            for declaration in left.nodes("declarations") {
                                if let Some(id) = declaration.f("id") {
                                    visit(&mut context, id, Some(source.clone()), &no_guards);
                                }
                            }
                        } else {
                            visit(&mut context, left, Some(source), &no_guards);
                        }
                    }
                }
            }
            Kind::SpreadElement if parent.is_some_and(|p| p.is(Kind::ArrayExpression)) => {
                if let Some(argument) = node.f("argument") {
                    add(context.sources, argument, Vec::new(), node, &no_guards, IterationSourceKind::Iteration);
                }
            }
            Kind::YieldExpression if node.flag("delegate") && node.f("argument").is_some() => {
                if let Some(argument) = node.f("argument") {
                    add(context.sources, argument, Vec::new(), node, &no_guards, IterationSourceKind::Iteration);
                }
            }
            _ if node.has_alias(Alias::Function) => {
                for parameter in node.nodes("params") {
                    visit(&mut context, parameter, None, &no_guards);
                }
            }
            _ => {}
        }
    }
    sources
}
