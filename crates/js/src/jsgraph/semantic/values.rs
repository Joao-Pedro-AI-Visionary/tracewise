//! Port of `javascriptSemanticValues.ts`: the bounded constant-value lattice and module
//! provenance evaluator.
//!
//! Entry points: [`evaluate_semantic_binding`], [`evaluate_semantic_expression`],
//! [`evaluate_semantic_provenance`] and [`clear_semantic_primitive_binding_values`].

use std::rc::Rc;

use crate::jsgraph::ast::{Kind, NodeId, N};
use crate::jsgraph::ast_values::{read_exact_literal, static_property_key, unwrap_expression};
use crate::jsgraph::ir::{
    BindingProvenance, ModuleOrigin, Primitive, ResourceLimit, SemanticProperty, SemanticValue,
    SlotPresence,
};

use super::mutation_initializers::{
    semantic_binding_precedes_capture, semantic_capture_position, semantic_escape_follows_capture,
};
use super::mutation_values::{invalidate_semantic_escaped_path, invalidate_semantic_mutation_paths};
use super::primitives::{
    primitive_to_js_number, primitive_to_js_string, primitive_truthy, semantic_primitive_set, num,
};
use super::property_paths::PathKey;
use super::provenance::{
    semantic_ambiguous_provenance, semantic_local_provenance, semantic_origins_provenance,
    semantic_unresolved_provenance, unique_semantic_origins,
};
use super::require_origin::semantic_require_origin;
use super::resource_limits::{
    exceeds_semantic_primitive_addition_byte_budget, exceeds_semantic_template_byte_budget,
    semantic_resource_limit_reason, semantic_resource_limit_unknown, SEMANTIC_EXPRESSION_DEPTH_LIMIT,
    SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT,
};
use super::slots::semantic_slot_at_path;
use super::state::{resolve_semantic_binding_state, BindingIx, SemanticAnalysisState};
use super::value_types::{
    ambiguous, cycle, is_primitive, is_resource_limit, literal, primitive_candidates, resource_limit_of,
    unknown,
};

/// Persistent set of binding indices on the current evaluation path (`context.bindings`).
#[derive(Clone, Default)]
struct BindingSet(Option<Rc<BindingSetNode>>);

struct BindingSetNode {
    binding: BindingIx,
    next: BindingSet,
}

impl BindingSet {
    fn has(&self, binding: BindingIx) -> bool {
        let mut cursor = &self.0;
        while let Some(node) = cursor {
            if node.binding == binding {
                return true;
            }
            cursor = &node.next.0;
        }
        false
    }

    fn with(&self, binding: BindingIx) -> BindingSet {
        BindingSet(Some(Rc::new(BindingSetNode { binding, next: self.clone() })))
    }
}

/// Which `primitiveBindingValues` map a context reads and writes.
#[derive(Clone, Copy)]
enum CacheSel {
    Global,
    Capture(NodeId),
}

#[derive(Clone)]
struct EvaluationContext<'a> {
    bindings: BindingSet,
    expression_depth: u32,
    capture_point: Option<N<'a>>,
    cache: CacheSel,
}

impl<'a> EvaluationContext<'a> {
    fn root() -> Self {
        EvaluationContext {
            bindings: BindingSet::default(),
            expression_depth: 0,
            capture_point: None,
            cache: CacheSel::Global,
        }
    }
}

fn cache_get(state: &SemanticAnalysisState<'_>, selector: CacheSel, binding: BindingIx) -> Option<SemanticValue> {
    let caches = state.caches.borrow();
    match selector {
        CacheSel::Global => caches.primitive_bindings.get(&binding).cloned(),
        CacheSel::Capture(node) => caches.captured_bindings.get(&node).and_then(|map| map.get(&binding)).cloned(),
    }
}

fn cache_set(state: &SemanticAnalysisState<'_>, selector: CacheSel, binding: BindingIx, value: SemanticValue) {
    let mut caches = state.caches.borrow_mut();
    match selector {
        CacheSel::Global => {
            caches.primitive_bindings.insert(binding, value);
        }
        CacheSel::Capture(node) => {
            caches.captured_bindings.entry(node).or_default().insert(binding, value);
        }
    }
}

/// Discard primitive projections evaluated before mutation collection finished.
pub fn clear_semantic_primitive_binding_values(state: &SemanticAnalysisState<'_>) {
    let mut caches = state.caches.borrow_mut();
    caches.primitive_bindings.clear();
    caches.captured_bindings.clear();
    caches.primitive_expressions.clear();
}

/// Evaluate one binding in the bounded constant-value lattice.
pub fn evaluate_semantic_binding(state: &SemanticAnalysisState<'_>, binding: BindingIx) -> SemanticValue {
    evaluate_binding(state, binding, &EvaluationContext::root())
}

/// Evaluate an inert expression, optionally at an earlier reference capture.
pub fn evaluate_semantic_expression<'a>(
    state: &SemanticAnalysisState<'a>,
    node: N<'a>,
    capture_point: Option<N<'a>>,
) -> SemanticValue {
    let context = EvaluationContext::root();
    let context = match capture_point {
        None => context,
        Some(point) => capture_context_at(state, point, &context).unwrap_or(context),
    };
    evaluate_expression(state, node, &context)
}

/// Follow module provenance through destructuring, members, and aliases.
pub fn evaluate_semantic_provenance(state: &SemanticAnalysisState<'_>, binding: BindingIx) -> BindingProvenance {
    provenance_for_binding(state, binding, &EvaluationContext::root())
}

fn evaluate_binding<'a>(
    state: &SemanticAnalysisState<'a>,
    binding_ix: BindingIx,
    context: &EvaluationContext<'a>,
) -> SemanticValue {
    let binding = &state.bindings[binding_ix];
    if context.bindings.has(binding_ix) {
        return cycle(format!("Alias cycle at {}.", binding.name));
    }
    if let Some(capture_point) = context.capture_point {
        if !semantic_binding_precedes_capture(binding, capture_point) {
            let live = EvaluationContext {
                capture_point: None,
                cache: CacheSel::Global,
                ..context.clone()
            };
            return evaluate_binding(state, binding_ix, &live);
        }
    }
    if let Some(cached) = cache_get(state, context.cache, binding_ix) {
        return cached;
    }
    if binding.initializers.is_empty() {
        return unknown(format!("Binding {} has no constant initializer.", binding.name));
    }
    if binding.initializers.iter().any(|initializer| {
        initializer.node.is(Kind::UpdateExpression)
            || (initializer.node.is(Kind::AssignmentExpression)
                && !matches!(initializer.node.str("operator"), Some("=" | "&&=" | "||=" | "??=")))
    }) {
        return unknown(format!("Binding {} has a compound or update write.", binding.name));
    }
    if binding.initializers.len() > 1 {
        return ambiguous(format!("Binding {} has multiple possible assignments.", binding.name));
    }
    let initializer = &binding.initializers[0];
    let nested = nested_context(context, Some(binding_ix));
    let mut value = project_value(&evaluate_expression(state, initializer.node, &nested), &initializer.projection);
    if !is_primitive(&value) {
        if let Some(capture_context) = primitive_capture_context(state, initializer.node, &nested) {
            let captured = project_value(
                &evaluate_expression(state, initializer.node, &capture_context),
                &initializer.projection,
            );
            if is_primitive(&captured) {
                value = captured;
            }
        }
    }
    let mut projected = invalidate_semantic_mutation_paths(&value, &binding.mutated_paths);
    for escape in &binding.escaped_paths {
        // Escapes only invalidate object references; other lattice values survive.
        if !matches!(projected, SemanticValue::Object { .. } | SemanticValue::Array { .. }) {
            break;
        }
        if let Some(capture_point) = context.capture_point {
            if semantic_escape_follows_capture(binding, capture_point, escape.node) {
                continue;
            }
        }
        projected = invalidate_semantic_escaped_path(&projected, &escape.path);
    }
    // Point-local memoization also bounds failed speculative captures. Only a primitive result is
    // allowed back into ordinary value evaluation.
    if context.capture_point.is_some()
        || matches!(projected, SemanticValue::Literal { .. } | SemanticValue::Union { .. })
        || (is_resource_limit(&projected)
            && matches!(
                resource_limit_of(&projected),
                Some(ResourceLimit::PrimitiveBytes | ResourceLimit::PrimitiveCandidates)
            ))
    {
        cache_set(state, context.cache, binding_ix, projected.clone());
    }
    projected
}

fn evaluate_expression<'a>(
    state: &SemanticAnalysisState<'a>,
    node: N<'a>,
    context: &EvaluationContext<'a>,
) -> SemanticValue {
    if context.expression_depth > SEMANTIC_EXPRESSION_DEPTH_LIMIT {
        return semantic_resource_limit_unknown(ResourceLimit::ExpressionDepth);
    }
    let (unwrapped, depth) = unwrap_expression(node);
    if depth > 0 {
        if context.expression_depth + depth > SEMANTIC_EXPRESSION_DEPTH_LIMIT {
            return semantic_resource_limit_unknown(ResourceLimit::ExpressionDepth);
        }
        let deeper = EvaluationContext {
            expression_depth: context.expression_depth + depth,
            ..context.clone()
        };
        return evaluate_expression(state, unwrapped, &deeper);
    }
    if let Some(value) = read_exact_literal(node) {
        return match value {
            Primitive::Num(_) => semantic_primitive_set(&[value]),
            other => literal(other),
        };
    }
    match node.kind() {
        Kind::Identifier => {
            let name = node.name().unwrap_or("");
            match resolve_semantic_binding_state(state, node, name) {
                None => unknown(format!("Unbound identifier {name}.")),
                Some(binding) => evaluate_binding(state, binding, &nested_context(context, None)),
            }
        }
        Kind::TemplateLiteral => evaluate_template(state, node, context),
        Kind::ConditionalExpression => merge_values(&[
            evaluate_optional(state, node.f("consequent"), context),
            evaluate_optional(state, node.f("alternate"), context),
        ]),
        Kind::LogicalExpression => merge_values(&[
            evaluate_optional(state, node.f("left"), context),
            evaluate_optional(state, node.f("right"), context),
        ]),
        Kind::ObjectExpression => evaluate_object(state, node, context),
        Kind::ArrayExpression => evaluate_array(state, node, context),
        Kind::MemberExpression | Kind::OptionalMemberExpression => evaluate_member(state, node, context),
        Kind::BinaryExpression if node.str("operator") == Some("+") => evaluate_addition(state, node, context),
        Kind::UnaryExpression => evaluate_unary(state, node, context),
        other => unknown(format!("Unsupported {} value.", other.as_str())),
    }
}

fn evaluate_optional<'a>(
    state: &SemanticAnalysisState<'a>,
    node: Option<N<'a>>,
    context: &EvaluationContext<'a>,
) -> SemanticValue {
    match node {
        Some(node) => evaluate_expression(state, node, &nested_context(context, None)),
        None => unknown("Missing expression."),
    }
}

fn evaluate_template<'a>(
    state: &SemanticAnalysisState<'a>,
    node: N<'a>,
    context: &EvaluationContext<'a>,
) -> SemanticValue {
    let quasis = node.nodes("quasis");
    let expressions = node.list("expressions");
    let mut candidates: Vec<String> = vec![String::new()];
    for (index, quasi) in quasis.iter().enumerate() {
        let Some(text) = quasi.str("cooked") else {
            return unknown("Template text has no cooked representation.");
        };
        if exceeds_semantic_template_byte_budget(&candidates, &[text.to_string()]) {
            return semantic_resource_limit_unknown(ResourceLimit::PrimitiveBytes);
        }
        candidates = candidates.iter().map(|prefix| format!("{prefix}{text}")).collect();
        let Some(Some(expression)) = expressions.get(index).copied() else { continue };
        let evaluated = evaluate_expression(state, expression, &nested_context(context, None));
        let Some(values) = primitive_candidates(&evaluated) else {
            if is_resource_limit(&evaluated) {
                return evaluated;
            }
            return unknown("Template expression is not a bounded primitive.");
        };
        if (candidates.len() as f64) > SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT as f64 / values.len() as f64 {
            return semantic_resource_limit_unknown(ResourceLimit::PrimitiveCandidates);
        }
        let suffixes: Vec<String> = values.iter().map(primitive_to_js_string).collect();
        if exceeds_semantic_template_byte_budget(&candidates, &suffixes) {
            return semantic_resource_limit_unknown(ResourceLimit::PrimitiveBytes);
        }
        candidates = candidates
            .iter()
            .flat_map(|prefix| suffixes.iter().map(move |suffix| format!("{prefix}{suffix}")))
            .collect();
    }
    let primitives: Vec<Primitive> = candidates.into_iter().map(Primitive::Str).collect();
    semantic_primitive_set(&primitives)
}

fn evaluate_object<'a>(
    state: &SemanticAnalysisState<'a>,
    node: N<'a>,
    context: &EvaluationContext<'a>,
) -> SemanticValue {
    let mut properties_by_name: Vec<SemanticProperty> = Vec::new();
    let mut index_by_name: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut unknown_properties = false;
    let mut omitted_properties: Option<u64> = Some(0);
    fn invalidate_earlier(properties: &mut [SemanticProperty]) {
        for property in properties.iter_mut() {
            *property = SemanticProperty {
                name: property.name.clone(),
                presence: SlotPresence::Present,
                value: unknown("A later property may overwrite this value."),
            };
        }
    }
    for property in node.nodes("properties") {
        if property.is(Kind::SpreadElement) {
            unknown_properties = true;
            omitted_properties = None;
            invalidate_earlier(&mut properties_by_name);
            continue;
        }
        let computed = property.flag("computed");
        let name = property.f("key").and_then(|key| static_property_key(key, computed));
        let Some(name) = name else {
            unknown_properties = true;
            if let Some(count) = omitted_properties.as_mut() {
                *count += 1;
            }
            invalidate_earlier(&mut properties_by_name);
            continue;
        };
        // This spelling changes the prototype instead of defining an own slot.
        if property.is(Kind::ObjectProperty) && !computed && !property.flag("shorthand") && name == "__proto__" {
            unknown_properties = true;
            if let Some(count) = omitted_properties.as_mut() {
                *count += 1;
            }
            continue;
        }
        let value = if property.is(Kind::ObjectProperty) {
            match property.f("value") {
                Some(value_node) => evaluate_captured_expression(state, value_node, &nested_context(context, None)),
                None => unknown("Missing expression."),
            }
        } else {
            unknown("Object method or accessor value is not a primitive.")
        };
        let entry = SemanticProperty { name: name.clone(), presence: SlotPresence::Present, value };
        match index_by_name.get(&name) {
            Some(&slot) => properties_by_name[slot] = entry,
            None => {
                index_by_name.insert(name, properties_by_name.len());
                properties_by_name.push(entry);
            }
        }
    }
    properties_by_name.sort_by(|left, right| left.name.cmp(&right.name));
    if unknown_properties {
        SemanticValue::Object { properties: properties_by_name, unknown_properties: true, omitted_properties }
    } else {
        SemanticValue::Object {
            properties: properties_by_name,
            unknown_properties: false,
            omitted_properties: Some(0),
        }
    }
}

fn evaluate_array<'a>(
    state: &SemanticAnalysisState<'a>,
    node: N<'a>,
    context: &EvaluationContext<'a>,
) -> SemanticValue {
    let mut items: Vec<SemanticProperty> = Vec::new();
    let mut unknown_items = false;
    let mut omitted_items: Option<u64> = Some(0);
    for element in node.list("elements") {
        match element {
            Some(element) if element.is(Kind::SpreadElement) => {
                unknown_items = true;
                omitted_items = None;
                // Subsequent elements have no fixed index after an unknown-length spread.
                break;
            }
            None => items.push(SemanticProperty {
                name: items.len().to_string(),
                presence: SlotPresence::Absent,
                value: unknown("Array hole has no own value."),
            }),
            Some(element) => {
                let value = evaluate_captured_expression(state, element, &nested_context(context, None));
                items.push(SemanticProperty {
                    name: items.len().to_string(),
                    presence: SlotPresence::Present,
                    value,
                });
            }
        }
    }
    if unknown_items {
        SemanticValue::Array { items, unknown_items: true, omitted_items }
    } else {
        SemanticValue::Array { items, unknown_items: false, omitted_items: Some(0) }
    }
}

fn evaluate_member<'a>(
    state: &SemanticAnalysisState<'a>,
    node: N<'a>,
    context: &EvaluationContext<'a>,
) -> SemanticValue {
    let mut keys: Vec<String> = Vec::new();
    let mut current = node;
    let mut value: Option<SemanticValue> = None;
    while current.is_member() {
        let Some(object) = current.f("object") else {
            value = Some(unknown("Unsupported member base."));
            break;
        };
        let key = current.f("property").and_then(|property| static_property_key(property, current.flag("computed")));
        let Some(key) = key else {
            value = Some(unknown("Dynamic member key."));
            break;
        };
        keys.push(key);
        current = object;
    }
    let mut value = match value {
        Some(value) => value,
        None => evaluate_expression(state, current, &nested_context(context, None)),
    };
    for key in keys.into_iter().rev() {
        value = project_value(&value, &[PathKey::Name(key)]);
    }
    value
}

fn evaluate_addition<'a>(
    state: &SemanticAnalysisState<'a>,
    node: N<'a>,
    context: &EvaluationContext<'a>,
) -> SemanticValue {
    let mut pending: Vec<(N<'a>, Option<SemanticValue>)> = Vec::new();
    let mut current = node;
    loop {
        if current.is(Kind::BinaryExpression) && current.str("operator") == Some("+") {
            pending.push((current, None));
            match current.f("left") {
                Some(left) => {
                    current = left;
                    continue;
                }
                None => return unknown("Missing expression."),
            }
        }
        let mut value = evaluate_expression(state, current, &nested_context(context, None));
        loop {
            match pending.last_mut() {
                None => return value,
                Some((parent_node, left)) => {
                    if left.is_none() {
                        *left = Some(value);
                        match parent_node.f("right") {
                            Some(right) => current = right,
                            None => return unknown("Missing expression."),
                        }
                        break;
                    }
                    let left_value = left.take().expect("left value");
                    value = add_primitive_values(&left_value, &value);
                    pending.pop();
                }
            }
        }
    }
}

fn add_primitive_values(left_value: &SemanticValue, right_value: &SemanticValue) -> SemanticValue {
    let (Some(left), Some(right)) = (primitive_candidates(left_value), primitive_candidates(right_value)) else {
        if is_resource_limit(left_value) {
            return left_value.clone();
        }
        if is_resource_limit(right_value) {
            return right_value.clone();
        }
        return unknown("Non-primitive addition.");
    };
    if (left.len() as f64) > SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT as f64 / right.len() as f64 {
        return semantic_resource_limit_unknown(ResourceLimit::PrimitiveCandidates);
    }
    if exceeds_semantic_primitive_addition_byte_budget(&left, &right) {
        return semantic_resource_limit_unknown(ResourceLimit::PrimitiveBytes);
    }
    let mut values: Vec<Primitive> = Vec::with_capacity(left.len() * right.len());
    for left_primitive in &left {
        for right_primitive in &right {
            if matches!(left_primitive, Primitive::Str(_)) || matches!(right_primitive, Primitive::Str(_)) {
                values.push(Primitive::Str(format!(
                    "{}{}",
                    primitive_to_js_string(left_primitive),
                    primitive_to_js_string(right_primitive)
                )));
            } else {
                values.push(num(primitive_to_js_number(left_primitive) + primitive_to_js_number(right_primitive)));
            }
        }
    }
    semantic_primitive_set(&values)
}

fn evaluate_unary<'a>(
    state: &SemanticAnalysisState<'a>,
    node: N<'a>,
    context: &EvaluationContext<'a>,
) -> SemanticValue {
    let evaluated = evaluate_optional(state, node.f("argument"), context);
    let Some(argument) = primitive_candidates(&evaluated) else {
        if is_resource_limit(&evaluated) {
            return evaluated;
        }
        return unknown("Non-primitive unary operand.");
    };
    let operator = node.str("operator").unwrap_or("");
    match operator {
        "!" => semantic_primitive_set(&argument.iter().map(|v| Primitive::Bool(!primitive_truthy(v))).collect::<Vec<_>>()),
        "+" => semantic_primitive_set(&argument.iter().map(|v| num(primitive_to_js_number(v))).collect::<Vec<_>>()),
        "-" => semantic_primitive_set(&argument.iter().map(|v| num(-primitive_to_js_number(v))).collect::<Vec<_>>()),
        other => unknown(format!("Unsupported unary {other}.")),
    }
}

/// `projectValue`: project a static member path out of a value.
pub fn project_value(value: &SemanticValue, projection: &[PathKey]) -> SemanticValue {
    if projection.iter().any(|key| matches!(key, PathKey::Null)) {
        return unknown("Cannot project a dynamic property.");
    }
    let path: Vec<String> = projection.iter().map(PathKey::js_string).collect();
    let slot = semantic_slot_at_path(value, &path);
    if slot.presence == SlotPresence::Present {
        slot.value.into_owned()
    } else {
        let presence = match slot.presence {
            SlotPresence::Absent => "absent",
            SlotPresence::UnknownCoverage => "unknown-coverage",
            SlotPresence::Present => "present",
        };
        unknown(format!("Own property {} is {presence}.", path.join("/")))
    }
}

fn provenance_for_binding<'a>(
    state: &SemanticAnalysisState<'a>,
    binding_ix: BindingIx,
    context: &EvaluationContext<'a>,
) -> BindingProvenance {
    let binding = &state.bindings[binding_ix];
    if context.bindings.has(binding_ix) {
        return semantic_unresolved_provenance("cycle", format!("Alias cycle at {}.", binding.name));
    }
    if !binding.direct_origins.is_empty() {
        return semantic_origins_provenance(&binding.direct_origins);
    }
    if binding.initializers.is_empty() {
        return semantic_local_provenance();
    }
    if binding.initializers.len() > 1 {
        return semantic_ambiguous_provenance(
            Vec::new(),
            format!("Binding {} has multiple possible assignments.", binding.name),
        );
    }
    let initializer = &binding.initializers[0];
    if initializer.projection.iter().any(|key| matches!(key, PathKey::Null)) {
        return semantic_unresolved_provenance("unknown", "Dynamic provenance projection.");
    }
    let resolved = provenance_for_expression(state, initializer.node, &nested_context(context, Some(binding_ix)));
    if resolved.status != "module" || initializer.projection.is_empty() {
        return resolved;
    }
    let origins: Vec<ModuleOrigin> = resolved
        .origins
        .iter()
        .map(|origin| ModuleOrigin {
            specifier: origin.specifier.clone(),
            imported_path: origin
                .imported_path
                .iter()
                .cloned()
                .chain(initializer.projection.iter().map(PathKey::js_string))
                .collect(),
        })
        .collect();
    semantic_origins_provenance(&origins)
}

fn provenance_for_expression<'a>(
    state: &SemanticAnalysisState<'a>,
    node: N<'a>,
    context: &EvaluationContext<'a>,
) -> BindingProvenance {
    if context.expression_depth > SEMANTIC_EXPRESSION_DEPTH_LIMIT {
        return semantic_unresolved_provenance(
            "unknown",
            semantic_resource_limit_reason(ResourceLimit::ExpressionDepth),
        );
    }
    let (unwrapped, depth) = unwrap_expression(node);
    if depth > 0 {
        if context.expression_depth + depth > SEMANTIC_EXPRESSION_DEPTH_LIMIT {
            return semantic_unresolved_provenance(
                "unknown",
                semantic_resource_limit_reason(ResourceLimit::ExpressionDepth),
            );
        }
        let deeper = EvaluationContext { expression_depth: context.expression_depth + depth, ..context.clone() };
        return provenance_for_expression(state, unwrapped, &deeper);
    }
    if let Some(required) = semantic_require_origin(Some(node), state) {
        return semantic_origins_provenance(&[required]);
    }
    if node.is(Kind::Identifier) {
        let name = node.name().unwrap_or("");
        return match resolve_semantic_binding_state(state, node, name) {
            None => semantic_unresolved_provenance("unknown", format!("Unbound identifier {name}.")),
            Some(binding) => provenance_for_binding(state, binding, &nested_context(context, None)),
        };
    }
    if node.is_member() {
        let mut members: Vec<String> = Vec::new();
        let mut current = node;
        while current.is_member() {
            let Some(object) = current.f("object") else {
                return semantic_unresolved_provenance("unknown", "Unsupported member base.");
            };
            let member = current
                .f("property")
                .and_then(|property| static_property_key(property, current.flag("computed")));
            let Some(member) = member else {
                return semantic_unresolved_provenance("unknown", "Dynamic provenance member.");
            };
            members.push(member);
            current = object;
        }
        let base = provenance_for_expression(state, current, &nested_context(context, None));
        members.reverse();
        if base.status != "module" {
            return base;
        }
        let origins: Vec<ModuleOrigin> = base
            .origins
            .iter()
            .map(|origin| ModuleOrigin {
                specifier: origin.specifier.clone(),
                imported_path: origin.imported_path.iter().cloned().chain(members.iter().cloned()).collect(),
            })
            .collect();
        return semantic_origins_provenance(&origins);
    }
    if node.is(Kind::ConditionalExpression) || node.is(Kind::LogicalExpression) {
        let conditional = node.is(Kind::ConditionalExpression);
        let (Some(left), Some(right)) = (
            node.f(if conditional { "consequent" } else { "left" }),
            node.f(if conditional { "alternate" } else { "right" }),
        ) else {
            return semantic_unresolved_provenance("unknown", "Conditional provenance is unresolved.");
        };
        let candidates = [
            provenance_for_expression(state, left, &nested_context(context, None)),
            provenance_for_expression(state, right, &nested_context(context, None)),
        ];
        let all_origins: Vec<ModuleOrigin> =
            candidates.iter().flat_map(|candidate| candidate.origins.iter().cloned()).collect();
        let origins = unique_semantic_origins(&all_origins);
        let all_module_origins = candidates.iter().all(|candidate| candidate.status == "module");
        if all_module_origins && origins.len() == 1 {
            return semantic_origins_provenance(&origins);
        }
        return if !origins.is_empty() {
            let reason = if all_module_origins {
                "Multiple module origins."
            } else {
                "Conditional provenance includes a non-module alternative."
            };
            semantic_ambiguous_provenance(origins, reason)
        } else {
            semantic_unresolved_provenance("unknown", "Conditional provenance is unresolved.")
        };
    }
    semantic_local_provenance()
}

fn merge_values(values: &[SemanticValue]) -> SemanticValue {
    if let Some(limit) = values.iter().find(|value| is_resource_limit(value)) {
        return limit.clone();
    }
    let primitives: Vec<Primitive> =
        values.iter().flat_map(|value| primitive_candidates(value).unwrap_or_default()).collect();
    if values.iter().all(|value| matches!(value, SemanticValue::Union { .. } | SemanticValue::Literal { .. })) {
        semantic_primitive_set(&primitives)
    } else {
        ambiguous("Branches have incompatible values.")
    }
}

fn nested_context<'a>(context: &EvaluationContext<'a>, binding: Option<BindingIx>) -> EvaluationContext<'a> {
    EvaluationContext {
        bindings: match binding {
            None => context.bindings.clone(),
            Some(ix) => context.bindings.with(ix),
        },
        expression_depth: context.expression_depth + 1,
        capture_point: context.capture_point,
        cache: context.cache,
    }
}

fn primitive_capture_context<'a>(
    state: &SemanticAnalysisState<'a>,
    node: N<'a>,
    context: &EvaluationContext<'a>,
) -> Option<EvaluationContext<'a>> {
    if node.is(Kind::ObjectExpression) || node.is(Kind::ArrayExpression) {
        return None;
    }
    capture_context_at(state, node, context)
}

fn capture_context_at<'a>(
    _state: &SemanticAnalysisState<'a>,
    node: N<'a>,
    context: &EvaluationContext<'a>,
) -> Option<EvaluationContext<'a>> {
    if context.capture_point.is_some() || semantic_capture_position(node).is_none() {
        return None;
    }
    Some(EvaluationContext { capture_point: Some(node), cache: CacheSel::Capture(node.id), ..context.clone() })
}

fn evaluate_captured_expression<'a>(
    state: &SemanticAnalysisState<'a>,
    node: N<'a>,
    context: &EvaluationContext<'a>,
) -> SemanticValue {
    // A literal field captures its primitive at construction, even when its containing object is
    // subsequently read at another capture point.
    if let Some(cached) = state.caches.borrow().primitive_expressions.get(&node.id) {
        return cached.clone();
    }
    let mut value = evaluate_expression(state, node, context);
    if !is_primitive(&value) {
        if let Some(capture_context) = primitive_capture_context(state, node, context) {
            let captured = evaluate_expression(state, node, &capture_context);
            if is_primitive(&captured) {
                value = captured;
            }
        }
    }
    // Never publish values evaluated at somebody else's capture point. Like binding caches, these
    // entries are discarded whenever effects change.
    if context.capture_point.is_none() && is_primitive(&value) {
        state.caches.borrow_mut().primitive_expressions.insert(node.id, value.clone());
    }
    value
}
