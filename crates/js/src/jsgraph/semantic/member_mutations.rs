//! Port of `javascriptSemanticMemberMutations.ts`: preserve uncertainty from property writes
//! and from references exposed to calls.
//!
//! The collector runs one AST traversal that records writes and escapes, then iterates the
//! destructuring-default and iterable origins until their effects are stable. Everything is
//! recorded on [`BindingState::mutated_paths`] / [`BindingState::escaped_paths`].

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use crate::jsgraph::ast::{Kind, NodeId, N};
use crate::jsgraph::ast_values::static_property_key;
use crate::jsgraph::ir::{SemanticValue, SlotPresence};

use super::ast_util::{span_of, static_key_path, unwrapped};
use super::callable_results::semantic_callable_result_expressions;
use super::iteration_sources::{semantic_iteration_sources, IterationSourceKind};
use super::mutation_initializers::semantic_mutation_initializers;
use super::property_paths::{
    semantic_array_index, semantic_array_index_str, semantic_property_path_key_matches, PathKey, PropertyPath,
    Selection, SemanticPropertyPathCoverage,
};
use super::returned_references::{create_semantic_returned_references, SemanticReturnedReferences};
use super::slots::{semantic_container, semantic_slot_at_path, ContainerCoverage};
use super::state::{
    resolve_semantic_binding_state, BindingIx, EscapedPath, ReferenceInitializer, SemanticAnalysisState,
    SemanticInitializer, SourceRef,
};
use super::traversal::{traverse_javascript_ast, AstVisitor};
use super::values::{
    clear_semantic_primitive_binding_values, evaluate_semantic_binding, evaluate_semantic_expression,
};

/// `"write" | "escape"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ValueEffect {
    Write,
    Escape,
}

/// `[bindingId, originAt?.start, originAt?.end]`: one alias lifetime on a traversal path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Lifetime {
    binding: BindingIx,
    origin: Option<(u32, u32)>,
}

/// Persistent set of lifetimes (`ReadonlySet<string>` of the TS).
#[derive(Clone, Default)]
struct LifetimeSet(Option<Rc<LifetimeNode>>);

struct LifetimeNode {
    lifetime: Lifetime,
    next: LifetimeSet,
}

impl LifetimeSet {
    fn has(&self, lifetime: Lifetime) -> bool {
        let mut cursor = &self.0;
        while let Some(node) = cursor {
            if node.lifetime == lifetime {
                return true;
            }
            cursor = &node.next.0;
        }
        false
    }

    fn with(&self, lifetime: Lifetime) -> LifetimeSet {
        LifetimeSet(Some(Rc::new(LifetimeNode { lifetime, next: self.clone() })))
    }

    fn sorted(&self) -> Vec<Lifetime> {
        let mut out = Vec::new();
        let mut cursor = &self.0;
        while let Some(node) = cursor {
            out.push(node.lifetime);
            cursor = &node.next.0;
        }
        out.sort();
        out.dedup();
        out
    }
}

/// A value reached from an expression through a property path.
#[derive(Clone, Debug)]
struct ReferencedValue<'a> {
    node: N<'a>,
    path: PropertyPath,
    iterable_fallback_path: Option<PropertyPath>,
}

/// A deferred iterable or destructuring reference (`IterableReference`).
#[derive(Clone)]
struct IterableReference<'a> {
    node: N<'a>,
    projection: PropertyPath,
    path: PropertyPath,
    fallback_path: PropertyPath,
    bindings: LifetimeSet,
    effect: ValueEffect,
    mutation: Option<N<'a>>,
    origin_at: Option<N<'a>>,
    iteration_only: Option<bool>,
    required_sources: Option<Vec<SourceRef<'a>>>,
    fallback_sources: Option<Vec<SourceRef<'a>>>,
}

struct PendingReference<'a> {
    initializer: ReferenceInitializer<'a>,
    path: PropertyPath,
    bindings: LifetimeSet,
    effect: ValueEffect,
    mutation: Option<N<'a>>,
    origin_at: Option<N<'a>>,
}

#[derive(Clone)]
struct MarkItem<'a> {
    node: N<'a>,
    path: PropertyPath,
    bindings: LifetimeSet,
    origin_at: Option<N<'a>>,
}

type Span = Option<(u32, u32)>;

/// Elements of the selection identity: the first selector is reduced to its `startIndex`.
#[derive(PartialEq, Eq, Hash)]
enum SelectionIdentityKey {
    Plain(PathKey),
    StartOnly(Option<u64>),
}

#[derive(PartialEq, Eq, Hash)]
struct SelectionIdentity {
    binding: BindingIx,
    effect: ValueEffect,
    path: Vec<SelectionIdentityKey>,
    mutation: Span,
    origin: Span,
}

#[derive(PartialEq, Eq, Hash)]
struct PathStateKey {
    binding: BindingIx,
    effect: ValueEffect,
    write_length: Option<usize>,
    mutation: Span,
    origin: Span,
}

#[derive(PartialEq, Eq, Hash)]
struct EffectIdentity {
    binding: BindingIx,
    effect: ValueEffect,
    path: PropertyPath,
    mutation: Span,
    origin: Span,
}

#[derive(PartialEq, Eq, Hash)]
struct IterableKey {
    projection: PropertyPath,
    path: PropertyPath,
    fallback_path: PropertyPath,
    effect: ValueEffect,
    mutation: Span,
    origin_at: Span,
    iteration_only: Option<bool>,
    required: Option<Vec<(u32, u32, PropertyPath)>>,
    fallback: Option<Vec<(u32, u32, PropertyPath)>>,
    bindings: Vec<Lifetime>,
}

fn source_keys(sources: &Option<Vec<SourceRef<'_>>>) -> Option<Vec<(u32, u32, PropertyPath)>> {
    sources.as_ref().map(|sources| {
        sources.iter().map(|source| (source.node.start(), source.node.end(), source.projection.clone())).collect()
    })
}

struct MemberMutationCollector<'s, 'a> {
    state: &'s mut SemanticAnalysisState<'a>,
    normalize_path: ObservableMutationPaths<'a>,
    returned_references: SemanticReturnedReferences<'a>,
    recorded_effects: HashSet<EffectIdentity>,
    selections: HashMap<SelectionIdentity, Vec<String>>,
    covering_paths: HashMap<PathStateKey, SemanticPropertyPathCoverage>,
    array_iteration_unknown: bool,
    pending_references: Vec<PendingReference<'a>>,
    iterable_references: Vec<IterableReference<'a>>,
    iterable_reference_keys: HashMap<NodeId, HashSet<IterableKey>>,
    escaped_leaves: HashMap<(NodeId, PropertyPath), Rc<Vec<ReferencedValue<'a>>>>,
}

/// Preserve uncertainty from property writes and references exposed to calls
/// (`collectSemanticMemberMutations`).
pub fn collect_semantic_member_mutations<'a>(state: &mut SemanticAnalysisState<'a>) {
    let program = state.ast.root();
    let normalize_path = ObservableMutationPaths::new(state);
    let returned_references = create_semantic_returned_references(state);
    let mut collector = MemberMutationCollector {
        state,
        normalize_path,
        returned_references,
        recorded_effects: HashSet::new(),
        selections: HashMap::new(),
        covering_paths: HashMap::new(),
        array_iteration_unknown: false,
        pending_references: Vec::new(),
        iterable_references: Vec::new(),
        iterable_reference_keys: HashMap::new(),
        escaped_leaves: HashMap::new(),
    };
    traverse_javascript_ast(program, &mut collector);
    collector.settle_references();
    // Gathering effects can evaluate a primitive projection before its object escapes. Final
    // values must use the completed mutation state.
    clear_semantic_primitive_binding_values(collector.state);
}

impl<'s, 'a> AstVisitor<'a> for MemberMutationCollector<'s, 'a> {
    fn enter(&mut self, node: N<'a>, parent: Option<N<'a>>) {
        for source in semantic_iteration_sources(node, parent) {
            self.defer_iterable(IterableReference {
                node: source.node,
                projection: source.projection.clone(),
                path: source.projection.clone(),
                fallback_path: source.projection,
                bindings: LifetimeSet::default(),
                effect: ValueEffect::Escape,
                mutation: Some(source.mutation),
                origin_at: Some(source.mutation),
                iteration_only: Some(source.kind == IterationSourceKind::Iteration),
                required_sources: source.required_sources,
                fallback_sources: source.fallback_sources,
            });
        }
        match node.kind() {
            Kind::AssignmentExpression => {
                if let Some(left) = node.f("left") {
                    self.mark_target(left, node);
                }
            }
            Kind::UpdateExpression => {
                if let Some(argument) = node.f("argument") {
                    self.mark_target(argument, node);
                }
            }
            Kind::UnaryExpression if node.str("operator") == Some("delete") => {
                if let Some(argument) = node.f("argument") {
                    self.mark_target(argument, node);
                }
            }
            Kind::ForOfStatement | Kind::ForInStatement => {
                if let Some(left) = node.f("left") {
                    self.mark_target(left, node);
                }
            }
            Kind::CallExpression | Kind::OptionalCallExpression | Kind::NewExpression => {
                if let Some(callee) = node.f("callee") {
                    let references = self.returned_references.get(self.state, callee);
                    for source in references.iter() {
                        self.mark_escaped(source.node, node, source.projection.clone());
                    }
                }
                for argument in node.nodes("arguments") {
                    if argument.is(Kind::SpreadElement) {
                        if let Some(inner) = argument.f("argument") {
                            self.defer_iterable(IterableReference {
                                node: inner,
                                projection: Vec::new(),
                                path: vec![PathKey::Null],
                                fallback_path: Vec::new(),
                                bindings: LifetimeSet::default(),
                                effect: ValueEffect::Escape,
                                mutation: Some(node),
                                origin_at: Some(node),
                                iteration_only: None,
                                required_sources: None,
                                fallback_sources: None,
                            });
                        }
                    } else {
                        self.mark_escaped(argument, node, Vec::new());
                    }
                }
                // Constructing a member does not pass its container as `this`.
                if !node.is(Kind::NewExpression) {
                    if let Some(callee) = node.f("callee") {
                        self.mark_receiver(callee, node);
                    }
                }
            }
            Kind::TaggedTemplateExpression => {
                if let Some(tag) = node.f("tag") {
                    self.mark_receiver(tag, node);
                }
                if let Some(quasi) = node.f("quasi") {
                    for expression in quasi.nodes("expressions") {
                        self.mark_escaped(expression, node, Vec::new());
                    }
                }
            }
            _ => {}
        }
    }
}

impl<'s, 'a> MemberMutationCollector<'s, 'a> {
    fn defer_iterable(&mut self, reference: IterableReference<'a>) {
        let key = IterableKey {
            projection: reference.projection.clone(),
            path: reference.path.clone(),
            fallback_path: reference.fallback_path.clone(),
            effect: reference.effect,
            mutation: span_of(reference.mutation),
            origin_at: span_of(reference.origin_at),
            iteration_only: reference.iteration_only,
            required: source_keys(&reference.required_sources),
            fallback: source_keys(&reference.fallback_sources),
            bindings: reference.bindings.sorted(),
        };
        let keys = self.iterable_reference_keys.entry(reference.node.id).or_default();
        if !keys.insert(key) {
            return;
        }
        self.iterable_references.push(reference);
    }

    fn mark_escaped(&mut self, node: N<'a>, mutation: N<'a>, path: PropertyPath) {
        self.mark_value(node, path, LifetimeSet::default(), ValueEffect::Escape, Some(mutation), None);
    }

    fn mark_receiver(&mut self, callee: N<'a>, mutation: N<'a>) {
        let expression = unwrapped(callee);
        if expression.is_member() {
            if let Some(object) = expression.f("object") {
                self.mark_escaped(object, mutation, Vec::new());
            }
        }
    }

    fn mark_target(&mut self, node: N<'a>, mutation: N<'a>) {
        match node.kind() {
            Kind::MemberExpression | Kind::OptionalMemberExpression => {
                if let (Some(object), Some(property)) = (node.f("object"), node.f("property")) {
                    self.mark_value(
                        object,
                        vec![static_key_path(property, node.flag("computed"))],
                        LifetimeSet::default(),
                        ValueEffect::Write,
                        Some(mutation),
                        None,
                    );
                }
            }
            Kind::RestElement => {
                if let Some(argument) = node.f("argument") {
                    self.mark_target(argument, mutation);
                }
            }
            Kind::AssignmentPattern => {
                if let Some(left) = node.f("left") {
                    self.mark_target(left, mutation);
                }
            }
            Kind::ArrayPattern => {
                for element in node.list("elements").into_iter().flatten() {
                    self.mark_target(element, mutation);
                }
            }
            Kind::ObjectPattern => {
                for property in node.nodes("properties") {
                    let target = if property.is(Kind::RestElement) { property.f("argument") } else { property.f("value") };
                    if let Some(target) = target {
                        self.mark_target(target, mutation);
                    }
                }
            }
            _ => {}
        }
    }

    /// `markValue`: record an effect on every binding reached from `node` through `path`.
    fn mark_value(
        &mut self,
        node: N<'a>,
        path: PropertyPath,
        bindings: LifetimeSet,
        effect: ValueEffect,
        mutation: Option<N<'a>>,
        origin_at: Option<N<'a>>,
    ) {
        let origin_at = origin_at.or(mutation);
        let mut pending: Vec<MarkItem<'a>> = vec![MarkItem { node, path, bindings, origin_at }];
        // Visit shallower alias traversals first so their exact prefixes suppress longer loop
        // paths before those paths enumerate every assignment order.
        let mut cursor = 0;
        while cursor < pending.len() {
            let current = pending[cursor].clone();
            cursor += 1;
            let expression = unwrapped(current.node);
            if expression.is_identifier() {
                let name = expression.name().unwrap_or("");
                let Some(binding_ix) = resolve_semantic_binding_state(self.state, expression, name) else {
                    let first = current.path.first();
                    let second = current.path.get(1);
                    let named = |key: Option<&PathKey>, text: &str| matches!(key, Some(PathKey::Name(n)) if n == text);
                    let null = |key: Option<&PathKey>| matches!(key, Some(PathKey::Null));
                    if (name == "Array" && (named(first, "prototype") || null(first)))
                        || (["globalThis", "global", "window", "self"].contains(&name)
                            && (named(first, "Array") || null(first))
                            && (named(second, "prototype") || null(second)))
                    {
                        self.array_iteration_unknown = true;
                    }
                    continue;
                };
                // An alias restored from a saved reference can revisit the same binding at an
                // earlier capture. Only a repeated lifetime closes a cycle.
                let lifetime = Lifetime { binding: binding_ix, origin: span_of(current.origin_at) };
                if current.bindings.has(lifetime) {
                    continue;
                }
                // Union compatible copied-slot selections at each binding. Carrying every
                // combination of exclusions through branch diamonds is exponential. Preserve
                // paths that can change observed slots or Array prototype effects;
                // canonicalize suffixes that cannot distinguish lattice facts.
                let Some(mut path) = self.normalize_path.call(self.state, binding_ix, &current.path, effect) else {
                    continue;
                };
                let selector_index = path.iter().position(|key| key.is_selection());
                if let Some(index) = selector_index {
                    let PathKey::Select(selector) = path[index].clone() else { unreachable!("selection") };
                    let identity = SelectionIdentity {
                        binding: binding_ix,
                        effect,
                        path: path
                            .iter()
                            .enumerate()
                            .map(|(position, key)| {
                                if position == index {
                                    SelectionIdentityKey::StartOnly(selector.start_index)
                                } else {
                                    SelectionIdentityKey::Plain(key.clone())
                                }
                            })
                            .collect(),
                        mutation: span_of(mutation),
                        origin: span_of(current.origin_at),
                    };
                    let previous = self.selections.get(&identity);
                    let excluded_keys: Vec<String> = match previous {
                        None => selector.excluded_keys.clone(),
                        Some(previous) => {
                            previous.iter().filter(|key| selector.excluded_keys.contains(key)).cloned().collect()
                        }
                    };
                    if previous.is_some_and(|previous| excluded_keys.len() == previous.len()) {
                        continue;
                    }
                    self.selections.insert(identity, excluded_keys.clone());
                    path[index] = PathKey::Select(Selection { excluded_keys, start_index: selector.start_index });
                }
                // Keep an antichain of exact paths. Widening distinct member keys would also
                // invalidate unrelated siblings that never reach this effect.
                let path_state = PathStateKey {
                    binding: binding_ix,
                    effect,
                    // Short writes stop at owned literal slots, whereas longer writes reach shared
                    // children. Only equal-depth writes cover one another.
                    write_length: if effect == ValueEffect::Write { Some(path.len()) } else { None },
                    mutation: span_of(mutation),
                    origin: span_of(current.origin_at),
                };
                let covering = self.covering_paths.entry(path_state).or_default();
                if !covering.retain(&path) {
                    continue;
                }
                let identity = EffectIdentity {
                    binding: binding_ix,
                    effect,
                    path: path.clone(),
                    mutation: span_of(mutation),
                    origin: span_of(current.origin_at),
                };
                if self.recorded_effects.contains(&identity) {
                    continue;
                }
                // A recorded write invalidates the binding to a non-primitive value, so only its
                // first write can target a primitive. Re-evaluating it would replay every earlier
                // write and make repeated writes superlinear.
                let primitive_write = effect == ValueEffect::Write
                    && self.state.bindings[binding_ix].mutated_paths.is_empty()
                    && matches!(
                        evaluate_semantic_binding(self.state, binding_ix),
                        SemanticValue::Literal { .. } | SemanticValue::Union { .. }
                    );
                self.recorded_effects.insert(identity);
                let nested = current.bindings.with(lifetime);
                let (initializers, reference_initializers): (Vec<SemanticInitializer<'a>>, Vec<ReferenceInitializer<'a>>) = {
                    let binding = &self.state.bindings[binding_ix];
                    match current.origin_at {
                        None => (binding.initializers.clone(), binding.reference_initializers.clone()),
                        Some(origin) => {
                            let selected = semantic_mutation_initializers(binding, origin);
                            (
                                selected.initializers.iter().map(|i| binding.initializers[*i].clone()).collect(),
                                selected
                                    .reference_initializers
                                    .iter()
                                    .map(|i| binding.reference_initializers[*i].clone())
                                    .collect(),
                            )
                        }
                    }
                };
                if !primitive_write {
                    let binding = &mut self.state.bindings[binding_ix];
                    if effect == ValueEffect::Escape {
                        binding.escaped_paths.push(EscapedPath { path: path.clone(), node: mutation });
                    } else {
                        binding.mutated_paths.push(path.clone());
                    }
                    clear_semantic_primitive_binding_values(self.state);
                    for initializer in &initializers {
                        let mut initializer_path = initializer.projection.clone();
                        initializer_path.extend(path.iter().cloned());
                        pending.push(MarkItem {
                            node: initializer.node,
                            path: initializer_path,
                            bindings: nested.clone(),
                            origin_at: Some(initializer.node),
                        });
                    }
                }
                for initializer in reference_initializers {
                    let Some(copied_path) = copied_reference_path(&initializer, &path, effect) else { continue };
                    let origin = initializer.node;
                    self.pending_references.push(PendingReference {
                        initializer,
                        path: copied_path,
                        bindings: nested.clone(),
                        effect,
                        mutation,
                        origin_at: Some(origin),
                    });
                }
            } else if expression.is_member() {
                if let (Some(object), Some(property)) = (expression.f("object"), expression.f("property")) {
                    let mut member_path = vec![static_key_path(property, expression.flag("computed"))];
                    member_path.extend(current.path.iter().cloned());
                    pending.push(MarkItem {
                        node: object,
                        path: member_path,
                        bindings: current.bindings.clone(),
                        origin_at: current.origin_at,
                    });
                }
            } else {
                let values: Vec<ReferencedValue<'a>> = if effect == ValueEffect::Escape {
                    self.escaped_reference_leaves(expression, &current.path).as_ref().clone()
                } else {
                    self.expanded_values(expression, &current.path, effect)
                };
                for value in values {
                    if let Some(fallback) = value.iterable_fallback_path.clone() {
                        self.defer_iterable(IterableReference {
                            node: value.node,
                            projection: Vec::new(),
                            path: value.path,
                            fallback_path: fallback,
                            bindings: current.bindings.clone(),
                            effect,
                            mutation,
                            origin_at: current.origin_at,
                            iteration_only: None,
                            required_sources: None,
                            fallback_sources: None,
                        });
                    } else {
                        pending.push(MarkItem {
                            node: value.node,
                            path: value.path,
                            bindings: current.bindings.clone(),
                            origin_at: current.origin_at,
                        });
                    }
                }
            }
        }
    }

    fn expanded_values(&mut self, expression: N<'a>, path: &[PathKey], effect: ValueEffect) -> Vec<ReferencedValue<'a>> {
        let named = |key: Option<&PathKey>, text: &str| matches!(key, Some(PathKey::Name(n)) if n == text);
        if expression.is(Kind::ArrayExpression)
            && ((named(path.first(), "__proto__") && (effect == ValueEffect::Escape || path.len() > 1))
                || (named(path.first(), "constructor") && named(path.get(1), "prototype")))
        {
            self.array_iteration_unknown = true;
        }
        referenced_values(expression, path, effect)
    }

    // Expanding a value below its references depends only on syntax, not on the escape site.
    // Escaping an object reaches every method's results, so re-expanding it at each call through
    // that object made N calls over N methods quadratic. Identifiers that resolve to the same
    // binding and path are processed identically, so one stands for all of them.
    fn escaped_reference_leaves(&mut self, root: N<'a>, root_path: &[PathKey]) -> Rc<Vec<ReferencedValue<'a>>> {
        let root_key = (root.id, root_path.to_vec());
        if let Some(cached) = self.escaped_leaves.get(&root_key) {
            return cached.clone();
        }
        let mut leaves: Vec<ReferencedValue<'a>> = Vec::new();
        let mut leaf_identities: HashSet<(Option<BindingIx>, Option<String>, PropertyPath)> = HashSet::new();
        let mut expanded: HashMap<NodeId, HashSet<PropertyPath>> = HashMap::new();
        let mut pending = self.expanded_values(root, root_path, ValueEffect::Escape);
        let mut cursor = 0;
        while cursor < pending.len() {
            let value = pending[cursor].clone();
            cursor += 1;
            let node = unwrapped(value.node);
            if node.is_identifier() && value.iterable_fallback_path.is_none() {
                let name = node.name().unwrap_or("");
                let binding = resolve_semantic_binding_state(self.state, node, name);
                let identity = (
                    binding,
                    if binding.is_none() { Some(name.to_string()) } else { None },
                    value.path.clone(),
                );
                if !leaf_identities.insert(identity) {
                    continue;
                }
                leaves.push(value);
            } else if value.iterable_fallback_path.is_some() || node.is_identifier() || node.is_member() {
                leaves.push(value);
            } else {
                let paths = expanded.entry(node.id).or_default();
                if !paths.insert(value.path.clone()) {
                    continue;
                }
                for reference in self.expanded_values(node, &value.path, ValueEffect::Escape) {
                    pending.push(reference);
                }
            }
        }
        let leaves = Rc::new(leaves);
        self.escaped_leaves.insert(root_key, leaves.clone());
        leaves
    }

    /// The post-traversal fixpoint over destructuring defaults and iterable origins.
    fn settle_references(&mut self) {
        // A later effect can make a previously defined destructuring source uncertain.
        // Reconsider defaults and iterable origins until their effects are stable.
        while !self.pending_references.is_empty() || !self.iterable_references.is_empty() {
            let effects_before = self.recorded_effects.len();
            let iterables_before = self.iterable_references.len();
            let iteration_before = self.array_iteration_unknown;
            let drained = std::mem::take(&mut self.pending_references);
            for reference in drained {
                let initializer = &reference.initializer;
                if reference_sources_inactive(
                    self.state,
                    initializer.required_sources.as_deref(),
                    initializer.fallback_sources.as_deref(),
                ) {
                    self.pending_references.push(reference);
                } else if reference.initializer.node.is(Kind::ForOfStatement) {
                    let Some(right) = reference.initializer.node.f("right") else { continue };
                    let mut path = vec![PathKey::Null];
                    path.extend(reference.path.iter().cloned());
                    self.defer_iterable(IterableReference {
                        node: right,
                        projection: Vec::new(),
                        path,
                        fallback_path: Vec::new(),
                        bindings: reference.bindings.clone(),
                        effect: reference.effect,
                        mutation: reference.mutation,
                        origin_at: Some(reference.initializer.node),
                        iteration_only: None,
                        required_sources: None,
                        fallback_sources: None,
                    });
                } else if reference.initializer.copy_kind == Some(super::state::CopyKind::ArrayRest)
                    && reference.initializer.copy_projection_offset.is_some()
                {
                    let offset = reference.initializer.copy_projection_offset.unwrap_or(0);
                    let projection: PropertyPath =
                        reference.initializer.projection.iter().take(offset).cloned().collect();
                    self.defer_iterable(IterableReference {
                        node: reference.initializer.node,
                        projection: projection.clone(),
                        path: reference.path.clone(),
                        fallback_path: projection,
                        bindings: reference.bindings.clone(),
                        effect: reference.effect,
                        mutation: reference.mutation,
                        origin_at: reference.origin_at,
                        iteration_only: None,
                        required_sources: None,
                        fallback_sources: None,
                    });
                } else {
                    self.mark_value(
                        reference.initializer.node,
                        reference.path.clone(),
                        reference.bindings.clone(),
                        reference.effect,
                        reference.mutation,
                        reference.origin_at,
                    );
                }
            }
            let snapshot: Vec<IterableReference<'a>> = self.iterable_references.clone();
            for reference in snapshot {
                if reference_sources_inactive(
                    self.state,
                    reference.required_sources.as_deref(),
                    reference.fallback_sources.as_deref(),
                ) {
                    continue;
                }
                if reference.iteration_only == Some(true) {
                    if let Some(expanded) = expanded_iteration_references(self.state, &reference) {
                        for selected in expanded {
                            self.defer_iterable(selected);
                        }
                        continue;
                    }
                }
                let slot = selected_reference_slot(self.state, reference.node, &reference.projection, None);
                // Custom iteration can yield the iterable itself as well as any child. Treat its
                // root as escaped, including writes through yielded references.
                let known_array = !self.array_iteration_unknown
                    && matches!(&slot, Some((_, SemanticValue::Array { items, .. }))
                        if items.iter().all(|item| semantic_array_index_str(&item.name).is_some()));
                if known_array && reference.iteration_only == Some(true) {
                    continue;
                }
                self.mark_value(
                    reference.node,
                    if known_array { reference.path.clone() } else { reference.fallback_path.clone() },
                    reference.bindings.clone(),
                    if known_array { reference.effect } else { ValueEffect::Escape },
                    reference.mutation,
                    reference.origin_at,
                );
            }
            if self.recorded_effects.len() == effects_before
                && self.iterable_references.len() == iterables_before
                && self.array_iteration_unknown == iteration_before
            {
                break;
            }
        }
    }
}

fn reference_sources_inactive(
    state: &SemanticAnalysisState<'_>,
    required: Option<&[SourceRef<'_>]>,
    fallback: Option<&[SourceRef<'_>]>,
) -> bool {
    let required_inactive = required.is_some_and(|sources| {
        sources.iter().any(|source| {
            matches!(
                selected_reference_slot(state, source.node, &source.projection, Some(source.node)),
                Some((SlotPresence::Absent, _))
            )
        })
    });
    if required_inactive {
        return true;
    }
    fallback.is_some_and(|sources| {
        sources.iter().any(|source| {
            // Selection precedes effects through the chosen reference. A later escape cannot make
            // a fallback that was excluded at destructuring reachable.
            matches!(
                selected_reference_slot(state, source.node, &source.projection, Some(source.node)),
                Some((
                    SlotPresence::Present,
                    SemanticValue::Literal { .. }
                        | SemanticValue::Union { .. }
                        | SemanticValue::Object { .. }
                        | SemanticValue::Array { .. }
                ))
            )
        })
    })
}

fn expanded_iteration_references<'a>(
    state: &SemanticAnalysisState<'a>,
    reference: &IterableReference<'a>,
) -> Option<Vec<IterableReference<'a>>> {
    let mutation = reference.mutation?;
    if !mutation.is(Kind::ForOfStatement) {
        return None;
    }
    let iterable = mutation.f("right")?;
    // Expand only the loop's yielded-item selector. Enumerating dynamic property selections would
    // multiply paths through shared object aliases.
    let selects = |node: N<'a>, projection: &PropertyPath| node == iterable && matches!(projection.first(), Some(PathKey::Null));
    let found = selects(reference.node, &reference.projection)
        || reference.required_sources.iter().flatten().any(|source| selects(source.node, &source.projection))
        || reference.fallback_sources.iter().flatten().any(|source| selects(source.node, &source.projection));
    if !found {
        return None;
    }
    let slot = selected_reference_slot(state, iterable, &[], None)?;
    let container = semantic_container(&slot.1)?;
    if container.coverage != ContainerCoverage::Complete {
        return None;
    }
    let select = |node: N<'a>, projection: &PropertyPath, name: &str| -> PropertyPath {
        if selects(node, projection) {
            let mut out = vec![PathKey::Name(name.to_string())];
            out.extend(projection.iter().skip(1).cloned());
            out
        } else {
            projection.clone()
        }
    };
    Some(
        container
            .slots
            .iter()
            .map(|slot| {
                let projection = select(reference.node, &reference.projection, &slot.name);
                IterableReference {
                    projection: projection.clone(),
                    path: projection.clone(),
                    fallback_path: projection,
                    required_sources: reference.required_sources.as_ref().map(|sources| {
                        sources
                            .iter()
                            .map(|source| SourceRef {
                                node: source.node,
                                projection: select(source.node, &source.projection, &slot.name),
                            })
                            .collect()
                    }),
                    fallback_sources: reference.fallback_sources.as_ref().map(|sources| {
                        sources
                            .iter()
                            .map(|source| SourceRef {
                                node: source.node,
                                projection: select(source.node, &source.projection, &slot.name),
                            })
                            .collect()
                    }),
                    ..reference.clone()
                }
            })
            .collect(),
    )
}

/// `referencedValues`: the values an expression forwards below `path`.
fn referenced_values<'a>(node: N<'a>, path: &[PathKey], effect: ValueEffect) -> Vec<ReferencedValue<'a>> {
    let plain = |node: N<'a>, path: &[PathKey]| ReferencedValue { node, path: path.to_vec(), iterable_fallback_path: None };
    if effect == ValueEffect::Escape && node.is_function() {
        return semantic_callable_result_expressions(node)
            .into_iter()
            .filter_map(|result| {
                result.node.map(|node| ReferencedValue {
                    node,
                    path: if result.delegated { vec![PathKey::Null] } else { Vec::new() },
                    iterable_fallback_path: None,
                })
            })
            .collect();
    }
    // An initializer owns its slots; only deeper writes can affect shared children.
    if node.is(Kind::ObjectExpression) || node.is(Kind::ArrayExpression) {
        if effect == ValueEffect::Write && path.len() < 2 {
            return Vec::new();
        }
        return if node.is(Kind::ObjectExpression) {
            object_referenced_values(node, path)
        } else {
            array_referenced_values(node, path)
        };
    }
    match node.kind() {
        Kind::AssignmentExpression => {
            let operator = node.str("operator");
            let mut out = Vec::new();
            if operator == Some("||=") || operator == Some("??=") {
                if let Some(left) = node.f("left") {
                    out.push(plain(left, path));
                }
            }
            if let Some(right) = node.f("right") {
                out.push(plain(right, path));
            }
            out
        }
        Kind::AwaitExpression => node.f("argument").map(|argument| vec![plain(argument, path)]).unwrap_or_default(),
        Kind::SequenceExpression => {
            node.nodes("expressions").last().map(|last| vec![plain(*last, path)]).unwrap_or_default()
        }
        Kind::ConditionalExpression => [node.f("consequent"), node.f("alternate")]
            .into_iter()
            .flatten()
            .map(|branch| plain(branch, path))
            .collect(),
        Kind::LogicalExpression => {
            [node.f("left"), node.f("right")].into_iter().flatten().map(|branch| plain(branch, path)).collect()
        }
        _ => Vec::new(),
    }
}

fn object_referenced_values<'a>(node: N<'a>, path: &[PathKey]) -> Vec<ReferencedValue<'a>> {
    let key = path.first();
    let remaining: PropertyPath = path.iter().skip(1).cloned().collect();
    let mut references: Vec<ReferencedValue<'a>> = Vec::new();
    let mut overwritten: Vec<String> = Vec::new();
    let mut overwritten_set: HashSet<String> = HashSet::new();
    let mut properties = node.nodes("properties");
    properties.reverse();
    for property in properties {
        if property.is(Kind::SpreadElement) {
            let selected_path_key = match key {
                // `key ?? null` is `null`, and `typeof null === "object"`: an untracked key
                // selects every slot except the overwritten ones.
                None | Some(PathKey::Null) => {
                    let mut excluded: Vec<String> = overwritten.clone();
                    excluded.sort();
                    excluded.dedup();
                    PathKey::Select(Selection { excluded_keys: excluded, start_index: None })
                }
                Some(PathKey::Select(selection)) => {
                    let mut excluded: Vec<String> = selection.excluded_keys.clone();
                    excluded.extend(overwritten.iter().cloned());
                    excluded.sort();
                    excluded.dedup();
                    PathKey::Select(Selection { excluded_keys: excluded, start_index: selection.start_index })
                }
                Some(plain) => {
                    if overwritten_set.contains(&plain.js_string()) {
                        continue;
                    }
                    plain.clone()
                }
            };
            if let Some(argument) = property.f("argument") {
                let mut spread_path = vec![selected_path_key];
                spread_path.extend(remaining.iter().cloned());
                references.push(ReferencedValue { node: argument, path: spread_path, iterable_fallback_path: None });
            }
            continue;
        }
        let computed = property.flag("computed");
        let name = property.f("key").and_then(|key| static_property_key(key, computed));
        if name.as_ref().is_some_and(|name| overwritten_set.contains(name)) {
            continue;
        }
        let matches_key = match &name {
            None => true,
            Some(name) => semantic_property_path_key_matches(key.unwrap_or(&PathKey::Null), name),
        };
        if matches_key {
            let target = if property.is(Kind::ObjectProperty) { property.f("value") } else { Some(property) };
            if let Some(target) = target {
                references.push(ReferencedValue { node: target, path: remaining.clone(), iterable_fallback_path: None });
            }
        }
        // A prototype setter does not replace an own property from a spread.
        if let Some(name) = name {
            let setter_or_getter = property.is(Kind::ObjectMethod) && property.str("kind") != Some("method");
            let proto_setter = property.is(Kind::ObjectProperty)
                && !computed
                && !property.flag("shorthand")
                && name == "__proto__";
            if !setter_or_getter && !proto_setter && overwritten_set.insert(name.clone()) {
                overwritten.push(name);
            }
        }
    }
    references
}

fn array_referenced_values<'a>(node: N<'a>, path: &[PathKey]) -> Vec<ReferencedValue<'a>> {
    let selected = path.first().cloned().unwrap_or(PathKey::Null);
    let remaining: PropertyPath = path.iter().skip(1).cloned().collect();
    let object_like = matches!(selected, PathKey::Null | PathKey::Select(_));
    let selected_index = if object_like { None } else { semantic_array_index(&selected) };
    if !object_like && selected_index.is_none() {
        return Vec::new();
    }
    let mut references = Vec::new();
    let mut minimum_index: u64 = 0;
    let mut uncertain_index = false;
    for element in node.list("elements") {
        if let Some(element) = element.filter(|e| e.is(Kind::SpreadElement)) {
            if selected_index.is_none_or(|index| index >= minimum_index) {
                let mut source_key = PathKey::Null;
                if !uncertain_index {
                    if let Some(index) = selected_index {
                        source_key = PathKey::Index(index - minimum_index);
                    } else if let PathKey::Select(selection) = &selected {
                        source_key = PathKey::Select(Selection {
                            excluded_keys: selection
                                .excluded_keys
                                .iter()
                                .filter_map(|name| match semantic_array_index_str(name) {
                                    Some(index) if index >= minimum_index => Some((index - minimum_index).to_string()),
                                    _ => None,
                                })
                                .collect(),
                            start_index: Some(selection.start_index.unwrap_or(0).saturating_sub(minimum_index)),
                        });
                    }
                }
                if let Some(argument) = element.f("argument") {
                    let mut spread_path = vec![source_key];
                    spread_path.extend(remaining.iter().cloned());
                    references.push(ReferencedValue {
                        node: argument,
                        path: spread_path,
                        iterable_fallback_path: Some(Vec::new()),
                    });
                }
            }
            uncertain_index = true;
            continue;
        }
        if let Some(element) = element {
            let selected_here = if uncertain_index {
                selected_index.is_none_or(|index| index >= minimum_index)
            } else {
                semantic_property_path_key_matches(&selected, &minimum_index.to_string())
            };
            if selected_here {
                references.push(ReferencedValue { node: element, path: remaining.clone(), iterable_fallback_path: None });
            }
        }
        minimum_index += 1;
    }
    references
}

fn copied_reference_path(
    initializer: &ReferenceInitializer<'_>,
    path: &[PathKey],
    effect: ValueEffect,
) -> Option<PropertyPath> {
    let Some(offset) = initializer.copy_projection_offset else {
        let mut out = initializer.projection.clone();
        out.extend(path.iter().cloned());
        return Some(out);
    };
    let mut copied_path: PropertyPath = initializer.projection.iter().skip(offset + 1).cloned().collect();
    copied_path.extend(path.iter().cloned());
    if effect == ValueEffect::Write && copied_path.len() < 2 {
        return None;
    }
    let key = copied_path.first().cloned();
    let remaining: PropertyPath = copied_path.iter().skip(1).cloned().collect();
    let key = if initializer.copy_kind == Some(super::state::CopyKind::ArrayRest) {
        let start_index = initializer.copy_start_index.unwrap_or(0);
        match key {
            None | Some(PathKey::Null) => {
                PathKey::Select(Selection { excluded_keys: Vec::new(), start_index: Some(start_index) })
            }
            Some(PathKey::Select(selection)) => PathKey::Select(Selection {
                excluded_keys: selection
                    .excluded_keys
                    .iter()
                    .filter_map(|name| semantic_array_index_str(name).map(|index| (index + start_index).to_string()))
                    .collect(),
                start_index: Some(selection.start_index.unwrap_or(0) + start_index),
            }),
            Some(other) => PathKey::Index(semantic_array_index(&other)? + start_index),
        }
    } else {
        let excluded_keys = initializer.copy_excluded_keys.clone().unwrap_or_default();
        match key {
            None | Some(PathKey::Null) => PathKey::Select(Selection { excluded_keys, start_index: None }),
            Some(PathKey::Select(selection)) => {
                let mut merged = selection.excluded_keys.clone();
                merged.extend(excluded_keys);
                merged.sort();
                merged.dedup();
                PathKey::Select(Selection { excluded_keys: merged, start_index: selection.start_index })
            }
            Some(other) => {
                if excluded_keys.contains(&other.js_string()) {
                    return None;
                }
                other
            }
        }
    };
    let mut out: PropertyPath = initializer.projection.iter().take(offset).cloned().collect();
    out.push(key);
    out.extend(remaining);
    Some(out)
}

/// `selectedReferenceSlot`: the slot a (node, projection) reference selects, if its path is static.
fn selected_reference_slot<'a>(
    state: &SemanticAnalysisState<'a>,
    node: N<'a>,
    projection: &[PathKey],
    capture_point: Option<N<'a>>,
) -> Option<(SlotPresence, SemanticValue)> {
    let mut path: Vec<String> = Vec::with_capacity(projection.len());
    for key in projection {
        if key.is_null_or_selection() {
            return None;
        }
        path.push(key.js_string());
    }
    let value = evaluate_semantic_expression(state, node, capture_point);
    let slot = semantic_slot_at_path(&value, &path);
    Some((slot.presence, slot.value.into_owned()))
}

// ---------------------------------------------------------------------------------------------
// observableMutationPaths
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum MutationObservableOrigin {
    /// An object or array literal.
    Literal(NodeId),
    Ambient,
    Array,
    ArrayPrototype,
    Opaque,
}

#[derive(PartialEq, Eq, Hash, Clone)]
enum ProjectionIdentity {
    Null,
    Name(String),
    Selection(Selection),
}

#[derive(Default)]
struct OrderedIds {
    items: Vec<usize>,
    set: HashSet<usize>,
}

impl OrderedIds {
    fn insert(&mut self, id: usize) -> bool {
        if self.set.insert(id) {
            self.items.push(id);
            true
        } else {
            false
        }
    }
}

#[derive(Default)]
struct OrderedOrigins {
    items: Vec<MutationObservableOrigin>,
    set: HashSet<MutationObservableOrigin>,
}

impl OrderedOrigins {
    fn insert(&mut self, origin: MutationObservableOrigin) -> bool {
        if self.set.insert(origin) {
            self.items.push(origin);
            true
        } else {
            false
        }
    }
}

#[derive(Default)]
struct MutationObserverNode {
    origins: OrderedOrigins,
    sources: OrderedIds,
    dependents: OrderedIds,
    projections: HashMap<ProjectionIdentity, usize>,
    read: Option<(usize, PathKey)>,
}

struct ObservableMutationPaths<'a> {
    nodes: Vec<MutationObserverNode>,
    binding_nodes: HashMap<BindingIx, usize>,
    expressions: HashMap<NodeId, usize>,
    pending_expressions: Vec<(N<'a>, usize)>,
    pending: Vec<usize>,
    queued: HashSet<usize>,
}

impl<'a> ObservableMutationPaths<'a> {
    fn new(state: &SemanticAnalysisState<'a>) -> Self {
        let mut this = ObservableMutationPaths {
            nodes: Vec::new(),
            binding_nodes: HashMap::new(),
            expressions: HashMap::new(),
            pending_expressions: Vec::new(),
            pending: Vec::new(),
            queued: HashSet::new(),
        };
        for ix in 0..state.bindings.len() {
            let node = this.create(None);
            this.binding_nodes.insert(ix, node);
        }
        for ix in 0..state.bindings.len() {
            let observer = this.binding_nodes[&ix];
            let binding = &state.bindings[ix];
            for initializer in &binding.initializers {
                let expression = this.expression_node(initializer.node);
                let projected = this.project(expression, &initializer.projection);
                this.link(projected, observer);
            }
            // Preserve exact paths where copies, defaults or iteration need their
            // reference-specific projections; an opaque origin prevents pruning.
            if !binding.reference_initializers.is_empty() {
                this.nodes[observer].origins.insert(MutationObservableOrigin::Opaque);
            }
            for initializer in &binding.reference_initializers {
                let mut sources: Vec<N<'a>> = vec![initializer.node];
                sources.extend(initializer.required_sources.iter().flatten().map(|s| s.node));
                sources.extend(initializer.fallback_sources.iter().flatten().map(|s| s.node));
                for source in sources {
                    let expression = this.expression_node(source);
                    this.link(expression, observer);
                }
            }
        }
        this.settle(state);
        this
    }

    fn create(&mut self, read: Option<(usize, PathKey)>) -> usize {
        self.nodes.push(MutationObserverNode { read, ..MutationObserverNode::default() });
        self.nodes.len() - 1
    }

    fn schedule(&mut self, node: usize) {
        if self.queued.insert(node) {
            self.pending.push(node);
        }
    }

    fn link(&mut self, source: usize, target: usize) {
        if self.nodes[target].sources.set.contains(&source) {
            return;
        }
        self.nodes[target].sources.insert(source);
        self.nodes[source].dependents.insert(target);
        self.schedule(target);
    }

    fn expression_node(&mut self, node: N<'a>) -> usize {
        let expression = unwrapped(node);
        if let Some(&existing) = self.expressions.get(&expression.id) {
            return existing;
        }
        let observer = self.create(None);
        self.expressions.insert(expression.id, observer);
        self.pending_expressions.push((expression, observer));
        observer
    }

    fn project(&mut self, source: usize, path: &[PathKey]) -> usize {
        let mut observer = source;
        for key in path {
            let identity = match key {
                PathKey::Null => ProjectionIdentity::Null,
                PathKey::Select(selection) => ProjectionIdentity::Selection(selection.clone()),
                other => ProjectionIdentity::Name(other.js_string()),
            };
            let selected = match self.nodes[observer].projections.get(&identity) {
                Some(&selected) => selected,
                None => {
                    let selected = self.create(Some((observer, key.clone())));
                    self.nodes[observer].projections.insert(identity, selected);
                    self.nodes[observer].dependents.insert(selected);
                    self.schedule(selected);
                    selected
                }
            };
            observer = selected;
        }
        observer
    }

    fn settle(&mut self, state: &SemanticAnalysisState<'a>) {
        while !self.pending_expressions.is_empty() || !self.pending.is_empty() {
            while let Some((expression, observer)) = self.pending_expressions.pop() {
                if expression.is(Kind::ObjectExpression) || expression.is(Kind::ArrayExpression) {
                    self.nodes[observer].origins.insert(MutationObservableOrigin::Literal(expression.id));
                } else if expression.is_identifier() {
                    let name = expression.name().unwrap_or("");
                    if let Some(binding) = resolve_semantic_binding_state(state, expression, name) {
                        if let Some(&origin) = self.binding_nodes.get(&binding) {
                            self.link(origin, observer);
                        }
                    } else if name == "Array" {
                        self.nodes[observer].origins.insert(MutationObservableOrigin::Array);
                    } else if ["globalThis", "global", "window", "self"].contains(&name) {
                        self.nodes[observer].origins.insert(MutationObservableOrigin::Ambient);
                    }
                } else if expression.is_member() {
                    if let (Some(object), Some(property)) = (expression.f("object"), expression.f("property")) {
                        let object_node = self.expression_node(object);
                        let key = static_key_path(property, expression.flag("computed"));
                        let projected = self.project(object_node, &[key]);
                        self.link(projected, observer);
                    }
                } else {
                    for reference in referenced_values(expression, &[], ValueEffect::Escape) {
                        let reference_node = self.expression_node(reference.node);
                        let projected = self.project(reference_node, &reference.path);
                        self.link(projected, observer);
                    }
                }
                self.schedule(observer);
            }
            let Some(observer) = self.pending.pop() else { continue };
            self.queued.remove(&observer);
            let mut changed = false;
            let sources: Vec<usize> = self.nodes[observer].sources.items.clone();
            for source in sources {
                let origins: Vec<MutationObservableOrigin> = self.nodes[source].origins.items.clone();
                for origin in origins {
                    if self.nodes[observer].origins.insert(origin) {
                        changed = true;
                    }
                }
            }
            if let Some((source, key)) = self.nodes[observer].read.clone() {
                if key.is_null_or_selection() {
                    // Dynamic keys and copied-slot masks retain their original paths. Enumerating
                    // their exclusion combinations would recreate the growth that the mutation
                    // collector's selection union already prevents.
                    if !self.nodes[source].origins.items.is_empty()
                        && self.nodes[observer].origins.insert(MutationObservableOrigin::Opaque)
                    {
                        changed = true;
                    }
                } else {
                    let origins: Vec<MutationObservableOrigin> = self.nodes[source].origins.items.clone();
                    for origin in origins {
                        match origin {
                            MutationObservableOrigin::ArrayPrototype | MutationObservableOrigin::Opaque => {
                                if self.nodes[observer].origins.insert(origin) {
                                    changed = true;
                                }
                            }
                            MutationObservableOrigin::Ambient => {
                                if semantic_property_path_key_matches(&key, "Array")
                                    && self.nodes[observer].origins.insert(MutationObservableOrigin::Array)
                                {
                                    changed = true;
                                }
                            }
                            MutationObservableOrigin::Array => {
                                if semantic_property_path_key_matches(&key, "prototype")
                                    && self.nodes[observer].origins.insert(MutationObservableOrigin::ArrayPrototype)
                                {
                                    changed = true;
                                }
                            }
                            MutationObservableOrigin::Literal(literal_id) => {
                                let literal = state.ast.node(literal_id);
                                for reference in referenced_values(literal, std::slice::from_ref(&key), ValueEffect::Escape) {
                                    let reference_node = self.expression_node(reference.node);
                                    let projected = self.project(reference_node, &reference.path);
                                    self.link(projected, observer);
                                    if let Some(fallback) = &reference.iterable_fallback_path {
                                        let reference_node = self.expression_node(reference.node);
                                        let projected = self.project(reference_node, fallback);
                                        self.link(projected, observer);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if changed {
                let dependents: Vec<usize> = self.nodes[observer].dependents.items.clone();
                for dependent in dependents {
                    self.schedule(dependent);
                }
            }
        }
    }

    /// The closure returned by `observableMutationPaths`.
    fn call(
        &mut self,
        state: &SemanticAnalysisState<'a>,
        binding: BindingIx,
        path: &[PathKey],
        effect: ValueEffect,
    ) -> Option<PropertyPath> {
        let Some(&root) = self.binding_nodes.get(&binding) else { return Some(path.to_vec()) };
        let mut observer = root;
        if path.iter().any(|key| key.is_selection()) {
            return Some(path.to_vec());
        }
        if effect == ValueEffect::Escape {
            observer = self.project(observer, path);
            self.settle(state);
            return if self.nodes[observer].origins.items.is_empty() { None } else { Some(path.to_vec()) };
        }
        if self.nodes[observer].origins.items.is_empty() {
            return Some(if path.is_empty() { path.to_vec() } else { vec![PathKey::Null] });
        }
        for (offset, key) in path.iter().enumerate() {
            observer = self.project(observer, std::slice::from_ref(key));
            self.settle(state);
            if self.nodes[observer].origins.items.is_empty() && offset + 1 < path.len() {
                let mut out: PropertyPath = path[..=offset].to_vec();
                out.push(PathKey::Null);
                return Some(out);
            }
        }
        Some(path.to_vec())
    }
}
