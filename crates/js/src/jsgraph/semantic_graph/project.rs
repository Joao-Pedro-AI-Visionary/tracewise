//! Per-file semantic projection passes: definitions, references, values, objects, calls, promises,
//! closures and frontiers (REA `JavaScriptSemanticGraphBuilder.ts`, `...ValueProjection.ts`,
//! `...ObjectProjection.ts`, `...FlowProjection.ts`).

use std::collections::HashMap;

use serde_json::{json, Value};

use crate::error::JsError;
use crate::jsgraph::app_graph::model::ArtifactFile;
use crate::jsgraph::ast::SourceRange;
use crate::jsgraph::ir::{
    JsNumber, Primitive, SemanticBinding, SemanticCallArgument, SemanticIr, SemanticProperty, SemanticValue,
    SlotPresence,
};
use crate::jsgraph::util::{js_number_to_string, sha256_text, source_ranges_equal};
use tracewise_domain::canonical::canonical_sha256;

use super::construction::{NodeInput, NodeRef, ProjectionState, RelationInput, UnknownInput};
use super::evidence::{inferred_semantic_evidence_at, observed_semantic_evidence, unknown_semantic_evidence};
use super::lookup::{
    semantic_container, semantic_property_pointer, semantic_slot_at_path, value_status_text, CallSiteLookup,
    CallableOwnerLookup, NodeRangeLookup,
};

/// File-local graph state needed by every projection pass.
pub struct FileCtx<'a> {
    pub file: &'a ArtifactFile,
    pub ir: &'a SemanticIr,
    pub module_node: NodeRef,
    pub binding_nodes: HashMap<String, NodeRef>,
    pub callable_nodes: HashMap<String, NodeRef>,
    pub call_site_nodes: HashMap<String, NodeRef>,
    pub return_site_nodes: HashMap<String, NodeRef>,
    pub reference_nodes: Vec<NodeRef>,
    pub reference_lookup: NodeRangeLookup,
    pub call_resolutions: HashMap<String, &'static str>,
    pub callable_owner: CallableOwnerLookup,
    pub call_site_lookup: CallSiteLookup,
}

impl FileCtx<'_> {
    pub fn call_site_at(&self, range: &SourceRange) -> Option<NodeRef> {
        self.call_site_lookup.at(range)
    }

    /// `callableNodes.get(owner)?.node_id ?? null`.
    pub fn owner_function_id(&self, owner: Option<&String>) -> Option<String> {
        owner
            .and_then(|id| self.callable_nodes.get(id))
            .map(|node| node.node_id.clone())
    }
}

fn resolution_of(complete: bool) -> &'static str {
    if complete {
        "resolved"
    } else {
        "candidate"
    }
}

// ---- definitions and references --------------------------------------------------------------

pub fn project_definitions_and_references(
    state: &mut ProjectionState,
    ctx: &mut FileCtx<'_>,
) -> Result<(), JsError> {
    let file = ctx.file;
    for binding in &ctx.ir.bindings {
        let Some(binding_node) = ctx.binding_nodes.get(&binding.binding_id).cloned() else {
            continue;
        };
        for (index, definition) in binding.definitions.iter().enumerate() {
            let definition_node = state.retain_node(
                file,
                NodeInput::new(
                    "expression",
                    format!("definition:{}:{index}", binding.binding_id),
                    Some(definition.location),
                    Some(definition.kind.clone()),
                )
                .function(binding_node.function_node_id.clone()),
            )?;
            state.add_relation(RelationInput::new(
                definition_node.as_ref(),
                Some(&binding_node),
                "defines",
                "resolved",
            ))?;
        }
    }
    for (index, reference) in ctx.ir.references.iter().enumerate() {
        let owner = ctx.callable_owner.at(Some(&reference.location));
        let expression = state.retain_node(
            file,
            NodeInput::new(
                "expression",
                format!("reference:{index}:{}:{}", reference.role, reference.name),
                Some(reference.location),
                Some(reference.name.clone()),
            )
            .function(owner.map(|n| n.node_id.clone())),
        )?;
        let binding = reference
            .binding_id
            .as_ref()
            .and_then(|id| ctx.binding_nodes.get(id))
            .cloned();
        if let Some(expression) = &expression {
            ctx.reference_nodes.push(expression.clone());
        }
        let (Some(binding), Some(expression)) = (binding, expression) else {
            continue;
        };
        if reference.role == "read" {
            state.add_relation(
                RelationInput::new(Some(&binding), Some(&expression), "reads", "resolved")
                    .evidence(inferred_semantic_evidence_at(file, &reference.location)),
            )?;
        } else {
            state.add_relation(RelationInput::new(Some(&expression), Some(&binding), "writes", "resolved"))?;
        }
    }
    Ok(())
}

// ---- values ------------------------------------------------------------------------------------

pub fn project_values(state: &mut ProjectionState, ctx: &FileCtx<'_>) -> Result<(), JsError> {
    for binding in &ctx.ir.bindings {
        let Some(binding_node) = ctx.binding_nodes.get(&binding.binding_id).cloned() else {
            continue;
        };
        project_value(state, ctx, binding, &binding.value, &binding_node, &[])?;
    }
    Ok(())
}

/// `JSON.stringify` of a primitive (JavaScript number formatting).
fn encode_primitive(value: &Primitive) -> String {
    match value {
        Primitive::Null => "null".into(),
        Primitive::Bool(true) => "true".into(),
        Primitive::Bool(false) => "false".into(),
        Primitive::Num(number) => js_number_to_string(number.0),
        Primitive::Str(text) => serde_json::to_string(text).unwrap_or_default(),
    }
}

fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

fn add_literal_node(
    state: &mut ProjectionState,
    ctx: &FileCtx<'_>,
    binding: &SemanticBinding,
    value: &Primitive,
    role: &str,
) -> Result<Option<NodeRef>, JsError> {
    let encoded = encode_primitive(value);
    let value_digest = format!(
        "value-sha256:{}",
        canonical_sha256(&serde_json::to_value(value).unwrap_or(Value::Null))?
    );
    let value_key = if utf16_len(&encoded) <= utf16_len(&value_digest) { encoded.clone() } else { value_digest };
    let label = if matches!(value, Primitive::Str(_)) && utf16_len(&encoded) > "string literal".len() {
        "string literal".to_string()
    } else {
        encoded
    };
    state.retain_node(
        ctx.file,
        NodeInput::new(
            "literal",
            format!("literal:{}:{role}:{value_key}", binding.binding_id),
            binding.definitions.first().map(|d| d.location),
            Some(label),
        )
        .function(
            ctx.binding_nodes
                .get(&binding.binding_id)
                .and_then(|n| n.function_node_id.clone()),
        )
        .properties(json!({ "value": value })),
    )
}

/// One canonical slot for a root binding and exact static property path.
pub fn semantic_property_slot(
    state: &mut ProjectionState,
    ctx: &FileCtx<'_>,
    object_binding_id: &str,
    path: &[String],
    fact: &SemanticProperty,
) -> Result<Option<NodeRef>, JsError> {
    let coverage = semantic_container(&fact.value).map(|c| json!({ "status": c.status, "omitted": c.omitted }));
    state.retain_node(
        ctx.file,
        NodeInput::new(
            "property-slot",
            format!(
                "property:{}",
                serde_json::to_string(&json!([object_binding_id, path])).unwrap_or_default()
            ),
            None,
            Some(fact.name.clone()),
        )
        .function(
            ctx.binding_nodes
                .get(object_binding_id)
                .and_then(|n| n.function_node_id.clone()),
        )
        .properties(json!({
            "name": fact.name,
            "property_path": path,
            "property_pointer": semantic_property_pointer(path),
            "object_binding_id": object_binding_id,
            "presence": match fact.presence {
                SlotPresence::Present => "present",
                SlotPresence::Absent => "absent",
                SlotPresence::UnknownCoverage => "unknown-coverage",
            },
            "value_status": value_status_text(&fact.value),
            "value_coverage": coverage,
        })),
    )
}

fn project_value(
    state: &mut ProjectionState,
    ctx: &FileCtx<'_>,
    binding: &SemanticBinding,
    value: &SemanticValue,
    target: &NodeRef,
    path: &[String],
) -> Result<(), JsError> {
    let role = if path.is_empty() {
        "binding".to_string()
    } else {
        format!("property:{}", semantic_property_pointer(path))
    };
    match value {
        SemanticValue::Literal { value: literal } => {
            let node = add_literal_node(state, ctx, binding, literal, &role)?;
            state.add_relation(RelationInput::new(node.as_ref(), Some(target), "defines", "resolved"))?;
        }
        SemanticValue::Union { values } => {
            for primitive in values {
                let node = add_literal_node(state, ctx, binding, primitive, &role)?;
                state.add_relation(RelationInput::new(node.as_ref(), Some(target), "defines", "candidate"))?;
            }
        }
        SemanticValue::Object { .. } | SemanticValue::Array { .. } => {
            let container = semantic_container(value).expect("container");
            for property in container.slots {
                let mut property_path: Vec<String> = path.to_vec();
                property_path.push(property.name.clone());
                let slot = semantic_property_slot(state, ctx, &binding.binding_id, &property_path, property)?;
                if property.presence == SlotPresence::Absent {
                    continue;
                }
                state.add_relation(RelationInput::new(
                    Some(target),
                    slot.as_ref(),
                    "writes-property",
                    if property.presence == SlotPresence::Present { "resolved" } else { "candidate" },
                ))?;
                if property.presence == SlotPresence::Present {
                    if let Some(slot) = &slot {
                        project_value(state, ctx, binding, &property.value, slot, &property_path)?;
                    } else {
                        // `target === null` in REA: nothing is projected below a dropped slot.
                    }
                }
            }
            if container.status == "partial" {
                let kind = if matches!(value, SemanticValue::Object { .. }) { "properties" } else { "items" };
                let omitted = match container.omitted {
                    None => " with an unknown omitted count".to_string(),
                    Some(count) => format!("; {count} omitted"),
                };
                state.add_unknown(UnknownInput {
                    node_id: Some(target.node_id.clone()),
                    family: "object-flow",
                    relation_kinds: vec!["writes-property"],
                    reason: "ambiguous-target",
                    detail: format!("Initializer container has unknown {kind}{omitted}."),
                    candidate_node_ids: vec![target.node_id.clone()],
                    evidence: unknown_semantic_evidence(ctx.file, binding.definitions.first().map(|d| &d.location)),
                })?;
            }
        }
        SemanticValue::Unknown { reason, resource_limit }
        | SemanticValue::Ambiguous { reason, resource_limit }
        | SemanticValue::Cycle { reason, resource_limit } => {
            let location = binding.definitions.first().map(|d| &d.location);
            let mut evidence = observed_semantic_evidence(ctx.file, location);
            let object = evidence.as_object_mut().expect("evidence");
            object.insert("authority".into(), json!("unknown"));
            object.insert("state".into(), json!("unknown"));
            object.insert("confidence".into(), json!("unknown"));
            object.insert("limitations".into(), json!([reason]));
            state.add_unknown(UnknownInput {
                node_id: Some(target.node_id.clone()),
                family: "data-flow",
                relation_kinds: vec!["defines"],
                reason: if resource_limit.is_none() { "unknown-value" } else { "resource-limit" },
                detail: format!("{reason} Unknown value at {role}."),
                candidate_node_ids: vec![target.node_id.clone()],
                evidence,
            })?;
        }
    }
    Ok(())
}

// ---- objects -----------------------------------------------------------------------------------

struct ObjectTarget {
    object_node: Option<NodeRef>,
    slot: Option<NodeRef>,
    presence: SlotPresence,
    receiver_resolved: bool,
}

fn presence_text(presence: SlotPresence) -> &'static str {
    match presence {
        SlotPresence::Present => "present",
        SlotPresence::Absent => "absent",
        SlotPresence::UnknownCoverage => "unknown-coverage",
    }
}

pub fn project_objects(state: &mut ProjectionState, ctx: &FileCtx<'_>) -> Result<(), JsError> {
    let values: HashMap<&str, &SemanticValue> =
        ctx.ir.bindings.iter().map(|b| (b.binding_id.as_str(), &b.value)).collect();
    for operation in &ctx.ir.object_operations {
        let occurrence = add_object_occurrence(state, ctx, operation)?;
        let target = object_target(state, ctx, &values, operation)?;
        let (source, tgt): (Option<NodeRef>, Option<NodeRef>) = match operation.kind.as_str() {
            "read" => (target.slot.clone(), occurrence.clone()),
            "write" => (occurrence.clone(), target.slot.clone()),
            "destructure" => (
                target.slot.clone(),
                operation.target_binding_id.as_ref().and_then(|id| ctx.binding_nodes.get(id)).cloned(),
            ),
            _ => (target.object_node.clone(), occurrence.clone()),
        };
        let relation = object_relation(&operation.kind);
        let resolved = operation.resolution == "complete"
            && if operation.kind == "write" {
                target.receiver_resolved
            } else {
                target.presence == SlotPresence::Present
            };
        state.add_relation(RelationInput::new(
            source.as_ref(),
            tgt.as_ref(),
            relation,
            resolution_of(resolved),
        ))?;
        if !resolved {
            let node = target.slot.as_ref().or(occurrence.as_ref());
            let path_text = match &operation.property_path {
                None => "path is unresolved".to_string(),
                Some(path) => semantic_property_pointer(path),
            };
            state.add_unknown(UnknownInput {
                node_id: node.map(|n| n.node_id.clone()),
                family: "object-flow",
                relation_kinds: vec![relation],
                reason: "ambiguous-target",
                detail: format!(
                    "Static {} property {} has {} presence; its receiver is {}; object identity is {}.",
                    operation.kind,
                    path_text,
                    presence_text(target.presence),
                    if target.receiver_resolved {
                        "a retained container"
                    } else {
                        "unresolved or not a retained container"
                    },
                    operation.resolution
                ),
                candidate_node_ids: Vec::new(),
                evidence: unknown_semantic_evidence(ctx.file, Some(&operation.location)),
            })?;
        }
    }
    Ok(())
}

fn object_relation(kind: &str) -> &'static str {
    match kind {
        "read" => "reads-property",
        "write" => "writes-property",
        "destructure" => "destructures",
        _ => "spreads",
    }
}

fn object_target(
    state: &mut ProjectionState,
    ctx: &FileCtx<'_>,
    values: &HashMap<&str, &SemanticValue>,
    operation: &crate::jsgraph::ir::SemanticObjectOperation,
) -> Result<ObjectTarget, JsError> {
    let binding = operation
        .object_binding_id
        .as_ref()
        .and_then(|id| ctx.binding_nodes.get(id))
        .cloned();
    let value = operation.object_binding_id.as_ref().and_then(|id| values.get(id.as_str()).copied());
    let (Some(binding_id), Some(path), Some(value)) =
        (operation.object_binding_id.as_ref(), operation.property_path.as_ref(), value)
    else {
        return Ok(ObjectTarget {
            object_node: binding,
            slot: None,
            presence: SlotPresence::UnknownCoverage,
            receiver_resolved: false,
        });
    };
    let fact = semantic_slot_at_path(value, path);
    if path.is_empty() {
        return Ok(ObjectTarget {
            object_node: binding,
            slot: None,
            presence: fact.presence,
            receiver_resolved: semantic_container(value).is_some(),
        });
    }
    let slot = semantic_property_slot(state, ctx, binding_id, path, &fact)?;
    let receiver = semantic_slot_at_path(value, &path[..path.len() - 1]);
    Ok(ObjectTarget {
        object_node: slot.clone(),
        slot,
        presence: fact.presence,
        receiver_resolved: receiver.presence == SlotPresence::Present && semantic_container(&receiver.value).is_some(),
    })
}

fn add_object_occurrence(
    state: &mut ProjectionState,
    ctx: &FileCtx<'_>,
    operation: &crate::jsgraph::ir::SemanticObjectOperation,
) -> Result<Option<NodeRef>, JsError> {
    let label = match &operation.property_path {
        None => operation.kind.clone(),
        Some(path) => format!("{}:{}", operation.kind, semantic_property_pointer(path)),
    };
    state.retain_node(
        ctx.file,
        NodeInput::new(
            "expression",
            operation.object_operation_id.clone(),
            Some(operation.location),
            Some(label),
        )
        .function(ctx.owner_function_id(operation.owner_callable_id.as_ref()))
        .properties(json!({
            "operation_kind": operation.kind,
            "property_path": operation.property_path,
        })),
    )
}

// ---- calls -------------------------------------------------------------------------------------

pub fn project_calls(state: &mut ProjectionState, ctx: &FileCtx<'_>) -> Result<(), JsError> {
    let mut argument_nodes: HashMap<String, NodeRef> = HashMap::new();
    for call in &ctx.ir.call_sites {
        let Some(call_node) = ctx.call_site_nodes.get(&call.call_site_id).cloned() else {
            continue;
        };
        for callable_id in &call.callee_callable_ids {
            let callable = ctx.callable_nodes.get(callable_id);
            state.add_relation(RelationInput::new(
                Some(&call_node),
                callable,
                "calls",
                if call.resolution == "exact" { "resolved" } else { "candidate" },
            ))?;
        }
        for argument in &call.arguments {
            let argument_node = create_argument_node(state, ctx, &call_node, &call.call_site_id, argument)?;
            if let Some(node) = &argument_node {
                argument_nodes.insert(format!("{}\u{0}{}", call.call_site_id, argument.index), node.clone());
            }
            let references = ctx.reference_lookup.within(&argument.location);
            for reference in &references {
                let exact = references.len() == 1
                    && source_ranges_equal(reference.source_range.as_ref(), &argument.location);
                state.add_relation(RelationInput::new(
                    Some(reference),
                    argument_node.as_ref(),
                    "aliases",
                    resolution_of(exact),
                ))?;
            }
        }
    }
    for flow in &ctx.ir.argument_flows {
        let argument = argument_nodes.get(&format!("{}\u{0}{}", flow.call_site_id, flow.argument_index));
        let parameter = ctx.binding_nodes.get(&flow.parameter_binding_id);
        let resolution = ctx.call_resolutions.get(&flow.call_site_id).copied().unwrap_or("candidate");
        state.add_relation(RelationInput::new(argument, parameter, "argument-to-parameter", resolution))?;
    }
    for flow in &ctx.ir.call_return_flows {
        let resolution = ctx.call_resolutions.get(&flow.call_site_id).copied().unwrap_or("candidate");
        state.add_relation(RelationInput::new(
            ctx.return_site_nodes.get(&flow.return_site_id),
            ctx.call_site_nodes.get(&flow.call_site_id),
            "returns-to-call",
            resolution,
        ))?;
    }
    for flow in &ctx.ir.call_result_flows {
        let resolution = ctx.call_resolutions.get(&flow.call_site_id).copied().unwrap_or("candidate");
        state.add_relation(RelationInput::new(
            ctx.call_site_nodes.get(&flow.call_site_id),
            ctx.binding_nodes.get(&flow.binding_id),
            "aliases",
            resolution,
        ))?;
    }
    project_return_values(state, ctx)
}

fn create_argument_node(
    state: &mut ProjectionState,
    ctx: &FileCtx<'_>,
    call_node: &NodeRef,
    call_site_id: &str,
    argument: &SemanticCallArgument,
) -> Result<Option<NodeRef>, JsError> {
    let label = if argument.spread {
        "spread argument".to_string()
    } else {
        format!("argument {}", argument.index)
    };
    state.retain_node(
        ctx.file,
        NodeInput::new(
            "expression",
            format!("argument:{call_site_id}:{}", argument.index),
            Some(argument.location),
            Some(label),
        )
        .function(call_node.function_node_id.clone()),
    )
}

/// Link direct return expressions to their retained semantic references.
fn project_return_values(state: &mut ProjectionState, ctx: &FileCtx<'_>) -> Result<(), JsError> {
    for callable in &ctx.ir.callables {
        for site in &callable.return_sites {
            let return_node = ctx.return_site_nodes.get(&site.return_site_id);
            for reference in ctx.reference_lookup.within(&site.location) {
                let resolved = site.identity_reference_location.is_some()
                    && source_ranges_equal(
                        reference.source_range.as_ref(),
                        site.identity_reference_location.as_ref().expect("checked"),
                    );
                state.add_relation(RelationInput::new(
                    Some(&reference),
                    return_node,
                    "aliases",
                    resolution_of(resolved),
                ))?;
            }
        }
    }
    Ok(())
}

// ---- promises, closures, frontiers -------------------------------------------------------------

pub fn project_promises(state: &mut ProjectionState, ctx: &FileCtx<'_>) -> Result<(), JsError> {
    let mut promise_nodes: HashMap<String, NodeRef> = HashMap::new();
    for operation in &ctx.ir.promise_operations {
        let owner = operation.owner_callable_id.as_ref().and_then(|id| ctx.callable_nodes.get(id));
        let label = if operation.kind == "awaited-expression" {
            "awaited expression".to_string()
        } else {
            format!("Promise.{}", operation.method)
        };
        let node = state.retain_node(
            ctx.file,
            NodeInput::new(
                if operation.kind == "awaited-expression" { "task" } else { "promise" },
                operation.promise_id.clone(),
                Some(operation.location),
                Some(label),
            )
            .function(owner.map(|n| n.node_id.clone()))
            .properties(json!({
                "method": operation.method,
                "operation_kind": operation.kind,
                "ownership": operation.ownership,
                "source_resolution": operation.source_resolution,
            })),
        )?;
        if let Some(node) = node {
            promise_nodes.insert(operation.promise_id.clone(), node);
        }
    }
    for operation in &ctx.ir.promise_operations {
        let Some(promise) = promise_nodes.get(&operation.promise_id).cloned() else {
            continue;
        };
        // creation
        if operation.kind != "awaited-expression" {
            let candidate = operation.kind == "chain" || operation.source_resolution != "complete";
            state.add_relation(RelationInput::new(
                ctx.call_site_at(&operation.location).as_ref(),
                Some(&promise),
                "creates-promise",
                if candidate { "candidate" } else { "resolved" },
            ))?;
        }
        // sources
        for source_id in &operation.source_promise_ids {
            let source = promise_nodes.get(source_id);
            let resolution = resolution_of(operation.source_resolution == "complete");
            if operation.kind == "aggregate" {
                state.add_relation(RelationInput::new(Some(&promise), source, "aggregates", resolution))?;
            } else {
                state.add_relation(RelationInput::new(source, Some(&promise), "chains", resolution))?;
            }
        }
        // ownership
        let owner = match &operation.owner_callable_id {
            None => Some(ctx.module_node.clone()),
            Some(id) => ctx.callable_nodes.get(id).cloned(),
        };
        match operation.ownership.as_str() {
            "awaited" => state.add_relation(RelationInput::new(owner.as_ref(), Some(&promise), "awaits", "resolved"))?,
            "assigned" => state.add_relation(RelationInput::new(
                operation.owner_binding_id.as_ref().and_then(|id| ctx.binding_nodes.get(id)),
                Some(&promise),
                "owns",
                "resolved",
            ))?,
            "returned" => state.add_relation(RelationInput::new(
                operation.return_site_id.as_ref().and_then(|id| ctx.return_site_nodes.get(id)),
                Some(&promise),
                "returns-task",
                "resolved",
            ))?,
            "detached" => {
                state.add_relation(RelationInput::new(owner.as_ref(), Some(&promise), "detaches-task", "resolved"))?
            }
            _ => {}
        }
        if operation.source_resolution != "complete"
            && matches!(operation.kind.as_str(), "chain" | "aggregate" | "awaited-expression")
        {
            let relation = if operation.kind == "aggregate" { "aggregates" } else { "chains" };
            let candidates: Vec<String> = operation
                .source_promise_ids
                .iter()
                .filter_map(|id| promise_nodes.get(id).map(|n| n.node_id.clone()))
                .collect();
            state.add_unknown(UnknownInput {
                node_id: Some(promise.node_id.clone()),
                family: "promise-ownership",
                relation_kinds: vec![relation],
                reason: "ambiguous-target",
                detail: format!(
                    "Static {} source resolution was {}.",
                    operation.method, operation.source_resolution
                ),
                candidate_node_ids: candidates,
                evidence: unknown_semantic_evidence(ctx.file, Some(&operation.location)),
            })?;
        }
    }
    Ok(())
}

/// Link each captured binding to the callable at the exact reference site.
pub fn project_closure_captures(state: &mut ProjectionState, ctx: &FileCtx<'_>) -> Result<(), JsError> {
    for capture in &ctx.ir.closure_captures {
        state.add_relation(
            RelationInput::new(
                ctx.binding_nodes.get(&capture.binding_id),
                ctx.callable_nodes.get(&capture.callable_id),
                "captures",
                "resolved",
            )
            .evidence(inferred_semantic_evidence_at(ctx.file, &capture.reference_location)),
        )?;
    }
    Ok(())
}

/// Retain bounded unresolved dynamic-call, dynamic-property and dynamic-scope frontiers.
pub fn project_frontiers(state: &mut ProjectionState, ctx: &FileCtx<'_>) -> Result<(), JsError> {
    for frontier in &ctx.ir.frontiers {
        let (family, relation_kinds): (&'static str, Vec<&'static str>) = match frontier.kind.as_str() {
            "dynamic-call" => ("call-flow", vec!["calls"]),
            "dynamic-scope" => ("data-flow", vec!["reads", "writes"]),
            _ => ("object-flow", vec!["reads-property", "writes-property"]),
        };
        let reason: &'static str = match frontier.kind.as_str() {
            "dynamic-call" => "dynamic-call",
            "dynamic-scope" => "dynamic-scope",
            _ => "dynamic-property",
        };
        let node_id = match &frontier.callable_id {
            None => ctx.module_node.node_id.clone(),
            Some(id) => ctx
                .callable_nodes
                .get(id)
                .map(|n| n.node_id.clone())
                .unwrap_or_else(|| ctx.module_node.node_id.clone()),
        };
        state.add_unknown(UnknownInput {
            node_id: Some(node_id),
            family,
            relation_kinds,
            reason,
            detail: frontier.reason.clone(),
            candidate_node_ids: Vec::new(),
            evidence: unknown_semantic_evidence(ctx.file, Some(&frontier.location)),
        })?;
    }
    Ok(())
}

#[allow(dead_code)]
fn unused(_: JsNumber, _: &str) -> String {
    sha256_text("")
}
