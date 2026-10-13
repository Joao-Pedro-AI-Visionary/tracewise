//! Event, timer, child-process, configuration, request, boundary, resource and fingerprint
//! projection (REA `JavaScriptSemanticGraph{Async,ChildProcess,Data,Resource,Fingerprint}Projection.ts`).

use std::collections::HashMap;

use serde_json::{json, Map, Value};

use crate::error::JsError;
use crate::jsgraph::ir::{
    ProjectedResultBinding, SemanticBoundaryOperation, SemanticChildProcessInteraction,
    SemanticChildProcessSpawn, SemanticConfigurationOperation, SemanticEventOperation,
    SemanticRequestOperation, SemanticResourceOperation, SemanticTimerOperation,
};
use crate::jsgraph::app_graph::findings::compact_string_identity_key;
use crate::jsgraph::ast::SourceRange;

use super::construction::{NodeInput, NodeRef, ProjectionState, RelationInput, UnknownInput};
use super::evidence::{observed_semantic_evidence, unknown_semantic_evidence};
use super::project::FileCtx;

fn resolution_of(complete: bool) -> &'static str {
    if complete {
        "resolved"
    } else {
        "candidate"
    }
}

fn projection_properties(projected: &ProjectedResultBinding) -> Value {
    json!({
        "projection_path": projected.projection_path,
        "projection_resolution": projected.resolution,
    })
}

// ---- events ------------------------------------------------------------------------------------

pub fn project_events(state: &mut ProjectionState, ctx: &FileCtx<'_>) -> Result<(), JsError> {
    let mut event_nodes: HashMap<String, NodeRef> = HashMap::new();
    for operation in &ctx.ir.event_operations {
        let event_key = match &operation.event_name {
            None => operation.event_id.clone(),
            Some(name) => format!("{}\u{0}{}", operation.emitter_key, compact_string_identity_key(name)?),
        };
        let event = match event_nodes.get(&event_key) {
            Some(node) => Some(node.clone()),
            None => add_event_node(state, ctx, operation, &event_key)?,
        };
        let Some(event) = event else {
            continue;
        };
        event_nodes.insert(event_key, event.clone());
        let relation = event_relation(operation);
        let resolution = resolution_of(operation.resolution == "complete");
        if operation.kind == "dispatch" {
            let emitter = event_emitter_node(ctx, operation);
            state.add_relation(RelationInput::new(Some(&emitter), Some(&event), relation, resolution))?;
        } else {
            let listener = add_listener_node(state, ctx, operation)?;
            state.add_relation(RelationInput::new(Some(&event), listener.as_ref(), relation, resolution))?;
        }
        if operation.resolution != "complete" {
            state.add_unknown(UnknownInput {
                node_id: Some(event.node_id.clone()),
                family: "event",
                relation_kinds: vec![relation],
                reason: "ambiguous-target",
                detail: if operation.event_name.is_none() {
                    format!("Dynamic {} event name remains unresolved.", operation.method)
                } else {
                    format!("Static {} emitter identity is partial.", operation.method)
                },
                candidate_node_ids: Vec::new(),
                evidence: unknown_semantic_evidence(ctx.file, Some(&operation.location)),
            })?;
        }
    }
    Ok(())
}

fn add_event_node(
    state: &mut ProjectionState,
    ctx: &FileCtx<'_>,
    operation: &SemanticEventOperation,
    event_key: &str,
) -> Result<Option<NodeRef>, JsError> {
    let label = match &operation.event_name {
        Some(name) if name.encode_utf16().count() > "event".len() => Some("event".to_string()),
        other => other.clone(),
    };
    state.retain_node(
        ctx.file,
        NodeInput::new(
            "event",
            format!("event:{event_key}"),
            if operation.event_name.is_none() { Some(operation.location) } else { None },
            label,
        )
        .properties(json!({
            "emitter_key": operation.emitter_key,
            "event_name": operation.event_name,
        })),
    )
}

fn add_listener_node(
    state: &mut ProjectionState,
    ctx: &FileCtx<'_>,
    operation: &SemanticEventOperation,
) -> Result<Option<NodeRef>, JsError> {
    let label = match &operation.event_name {
        None => operation.method.clone(),
        Some(name) if name.encode_utf16().count() <= "listener".len() => format!("{}:{name}", operation.method),
        Some(_) => format!("{}:listener", operation.method),
    };
    state.retain_node(
        ctx.file,
        NodeInput::new(
            "listener",
            format!("listener:{}", operation.event_id),
            Some(operation.listener_location.unwrap_or(operation.location)),
            Some(label),
        )
        .function(ctx.owner_function_id(operation.owner_callable_id.as_ref()))
        .properties(json!({
            "emitter_key": operation.emitter_key,
            "event_name": operation.event_name,
            "method": operation.method,
        })),
    )
}

fn event_emitter_node(ctx: &FileCtx<'_>, operation: &SemanticEventOperation) -> NodeRef {
    operation
        .emitter_binding_id
        .as_ref()
        .and_then(|id| ctx.binding_nodes.get(id))
        .cloned()
        .unwrap_or_else(|| owner_or_module(ctx, operation.owner_callable_id.as_ref()))
}

fn owner_or_module(ctx: &FileCtx<'_>, callable: Option<&String>) -> NodeRef {
    match callable {
        None => ctx.module_node.clone(),
        Some(id) => ctx.callable_nodes.get(id).cloned().unwrap_or_else(|| ctx.module_node.clone()),
    }
}

fn event_relation(operation: &SemanticEventOperation) -> &'static str {
    match operation.kind.as_str() {
        "register" => "registers-listener",
        "remove" => "removes-listener",
        _ => "dispatches-candidate",
    }
}

// ---- timers ------------------------------------------------------------------------------------

pub fn project_timers(state: &mut ProjectionState, ctx: &FileCtx<'_>) -> Result<(), JsError> {
    let mut timer_nodes: HashMap<String, NodeRef> = HashMap::new();
    for operation in &ctx.ir.timer_operations {
        if operation.kind != "schedule" {
            continue;
        }
        let timer = state.retain_node(
            ctx.file,
            NodeInput::new("timer", operation.timer_id.clone(), Some(operation.location), Some(operation.method.clone()))
                .function(ctx.owner_function_id(operation.owner_callable_id.as_ref()))
                .properties(json!({
                    "delay_milliseconds": operation.delay_milliseconds,
                    "method": operation.method,
                })),
        )?;
        if let Some(timer) = timer {
            timer_nodes.insert(operation.timer_id.clone(), timer);
        }
    }
    for operation in &ctx.ir.timer_operations {
        if operation.kind == "schedule" {
            project_timer_schedule(state, ctx, operation, &timer_nodes)?;
        } else {
            project_timer_cancellation(state, ctx, operation, &timer_nodes)?;
        }
    }
    Ok(())
}

fn project_timer_schedule(
    state: &mut ProjectionState,
    ctx: &FileCtx<'_>,
    operation: &SemanticTimerOperation,
    timer_nodes: &HashMap<String, NodeRef>,
) -> Result<(), JsError> {
    let timer = timer_nodes.get(&operation.timer_id);
    state.add_relation(RelationInput::new(
        ctx.call_site_at(&operation.location).as_ref(),
        timer,
        "schedules-timer",
        "resolved",
    ))?;
    for projected in &operation.projected_result_bindings {
        state.add_relation(
            RelationInput::new(
                timer,
                ctx.binding_nodes.get(&projected.binding_id),
                "destructures",
                resolution_of(projected.resolution == "complete"),
            )
            .properties(projection_properties(projected)),
        )?;
    }
    Ok(())
}

fn project_timer_cancellation(
    state: &mut ProjectionState,
    ctx: &FileCtx<'_>,
    operation: &SemanticTimerOperation,
    timer_nodes: &HashMap<String, NodeRef>,
) -> Result<(), JsError> {
    let call_site = ctx.call_site_at(&operation.location);
    let target = operation.linked_timer_id.as_ref().and_then(|id| timer_nodes.get(id));
    state.add_relation(RelationInput::new(
        call_site.as_ref(),
        target,
        "cancels-timer",
        resolution_of(operation.resolution == "complete"),
    ))?;
    if operation.resolution == "complete" {
        return Ok(());
    }
    state.add_unknown(UnknownInput {
        node_id: call_site.map(|n| n.node_id.clone()),
        family: "timer",
        relation_kinds: vec!["cancels-timer"],
        reason: "ambiguous-target",
        detail: format!(
            "Static {} handle resolution was {}.",
            operation.method, operation.resolution
        ),
        candidate_node_ids: Vec::new(),
        evidence: unknown_semantic_evidence(ctx.file, Some(&operation.location)),
    })
}

// ---- child processes ---------------------------------------------------------------------------

fn child_unknown(
    state: &mut ProjectionState,
    ctx: &FileCtx<'_>,
    node: Option<&NodeRef>,
    location: &SourceRange,
    relation_kinds: Vec<&'static str>,
    detail: String,
    candidates: Vec<String>,
) -> Result<(), JsError> {
    state.add_unknown(UnknownInput {
        node_id: node.map(|n| n.node_id.clone()),
        family: "child-process",
        relation_kinds,
        reason: "ambiguous-target",
        detail,
        candidate_node_ids: candidates,
        evidence: unknown_semantic_evidence(ctx.file, Some(location)),
    })
}

pub fn project_child_processes(state: &mut ProjectionState, ctx: &FileCtx<'_>) -> Result<(), JsError> {
    let mut process_nodes: HashMap<String, NodeRef> = HashMap::new();
    for spawn in &ctx.ir.child_process_spawns {
        let node = state.retain_node(
            ctx.file,
            NodeInput::new(
                "child-process",
                spawn.process_id.clone(),
                Some(spawn.location),
                Some(spawn.command.clone().unwrap_or_else(|| spawn.method.clone())),
            )
            .function(ctx.owner_function_id(spawn.owner_callable_id.as_ref()))
            .properties(json!({
                "argv_count": spawn.argv_count,
                "command": spawn.command,
                "environment_supplied": spawn.environment_supplied,
                "method": spawn.method,
                "stdio_mode": spawn.stdio_mode,
            })),
        )?;
        if let Some(node) = node {
            process_nodes.insert(spawn.process_id.clone(), node);
        }
    }
    for spawn in &ctx.ir.child_process_spawns {
        if let Some(child) = process_nodes.get(&spawn.process_id).cloned() {
            project_spawn(state, ctx, spawn, &child)?;
        }
    }
    for interaction in &ctx.ir.child_process_interactions {
        project_interaction(state, ctx, interaction, &process_nodes)?;
    }
    Ok(())
}

fn project_spawn(
    state: &mut ProjectionState,
    ctx: &FileCtx<'_>,
    spawn: &SemanticChildProcessSpawn,
    child: &NodeRef,
) -> Result<(), JsError> {
    let call_site = ctx.call_site_at(&spawn.location);
    state.add_relation(RelationInput::new(
        call_site.as_ref(),
        Some(child),
        "spawns",
        resolution_of(spawn.resolution == "complete"),
    ))?;
    for projected in &spawn.projected_result_bindings {
        state.add_relation(
            RelationInput::new(
                Some(child),
                ctx.binding_nodes.get(&projected.binding_id),
                "destructures",
                resolution_of(projected.resolution == "complete"),
            )
            .properties(projection_properties(projected)),
        )?;
    }
    if let Some(count) = spawn.argv_count {
        state.add_relation(
            RelationInput::new(call_site.as_ref(), Some(child), "supplies-argv", "resolved")
                .properties(json!({ "argument_count": count })),
        )?;
    }
    if spawn.environment_supplied {
        state.add_relation(RelationInput::new(call_site.as_ref(), Some(child), "supplies-env", "resolved"))?;
    }
    let stdio = state.retain_node(
        ctx.file,
        NodeInput::new(
            "stdio",
            format!("stdio:{}", spawn.process_id),
            Some(spawn.location),
            Some(spawn.stdio_mode.clone()),
        )
        .function(child.function_node_id.clone())
        .properties(json!({ "mode": spawn.stdio_mode })),
    )?;
    state.add_relation(RelationInput::new(
        Some(child),
        stdio.as_ref(),
        "connects-stdio",
        if spawn.stdio_mode == "dynamic" { "candidate" } else { "resolved" },
    ))?;
    if spawn.resolution != "complete" {
        child_unknown(
            state,
            ctx,
            Some(child),
            &spawn.location,
            vec!["spawns"],
            format!("Static {} command remains unresolved.", spawn.method),
            Vec::new(),
        )?;
    }
    Ok(())
}

fn project_interaction(
    state: &mut ProjectionState,
    ctx: &FileCtx<'_>,
    interaction: &SemanticChildProcessInteraction,
    process_nodes: &HashMap<String, NodeRef>,
) -> Result<(), JsError> {
    let children: Vec<NodeRef> = interaction
        .linked_process_ids
        .iter()
        .filter_map(|id| process_nodes.get(id).cloned())
        .collect();
    let owner = ctx.owner_function_id(interaction.owner_callable_id.as_ref());
    let effect = if interaction.kind == "listener" {
        state.retain_node(
            ctx.file,
            NodeInput::new(
                "listener",
                interaction.interaction_id.clone(),
                Some(interaction.listener_location.unwrap_or(interaction.location)),
                interaction.event_name.clone(),
            )
            .function(owner)
            .properties(json!({ "event_name": interaction.event_name, "method": interaction.method })),
        )?
    } else {
        state.retain_node(
            ctx.file,
            NodeInput::new(
                "signal",
                interaction.interaction_id.clone(),
                Some(interaction.location),
                interaction.signal_name.clone(),
            )
            .function(owner)
            .properties(json!({ "signal_name": interaction.signal_name })),
        )?
    };
    let relation: &'static str = if interaction.kind == "signal" {
        "forwards-signal"
    } else if interaction.event_name.as_deref() == Some("exit") {
        "listens-exit"
    } else {
        "listens-error"
    };
    for child in &children {
        let (source, target) = if interaction.kind == "listener" {
            (Some(child), effect.as_ref())
        } else {
            (effect.as_ref(), Some(child))
        };
        state.add_relation(RelationInput::new(
            source,
            target,
            relation,
            resolution_of(interaction.resolution == "complete"),
        ))?;
    }
    if interaction.resolution != "complete" {
        child_unknown(
            state,
            ctx,
            effect.as_ref(),
            &interaction.location,
            vec![relation],
            format!("Static child {} ownership is ambiguous.", interaction.method),
            children.iter().map(|c| c.node_id.clone()).collect(),
        )?;
    }
    Ok(())
}

// ---- configuration, requests, boundaries -------------------------------------------------------

fn binding_or_owner(ctx: &FileCtx<'_>, binding_id: Option<&String>, callable: Option<&String>) -> NodeRef {
    binding_id
        .and_then(|id| ctx.binding_nodes.get(id))
        .cloned()
        .unwrap_or_else(|| owner_or_module(ctx, callable))
}

#[allow(clippy::too_many_arguments)] // mirrors the positional signature of REA `dataUnknown`
fn data_unknown(
    state: &mut ProjectionState,
    ctx: &FileCtx<'_>,
    node: &NodeRef,
    family: &'static str,
    relation_kinds: Vec<&'static str>,
    location: &SourceRange,
    detail: String,
    candidates: Vec<String>,
) -> Result<(), JsError> {
    state.add_unknown(UnknownInput {
        node_id: Some(node.node_id.clone()),
        family,
        relation_kinds,
        reason: "ambiguous-target",
        detail,
        candidate_node_ids: candidates,
        evidence: unknown_semantic_evidence(ctx.file, Some(location)),
    })
}

fn configuration_relation(operation: &SemanticConfigurationOperation) -> &'static str {
    match operation.kind.as_str() {
        "environment" => "reads-environment",
        "argv" => "reads-argv",
        "file" => "reads-config",
        _ => "defaults",
    }
}

pub fn project_configuration(state: &mut ProjectionState, ctx: &FileCtx<'_>) -> Result<(), JsError> {
    let mut config_nodes: HashMap<String, NodeRef> = HashMap::new();
    for operation in &ctx.ir.configuration_operations {
        let node = state.retain_node(
            ctx.file,
            NodeInput::new(
                "config-source",
                operation.config_id.clone(),
                Some(operation.location),
                Some(operation.key.clone().unwrap_or_else(|| operation.kind.clone())),
            )
            .function(ctx.owner_function_id(operation.owner_callable_id.as_ref()))
            .properties(json!({
                "key": operation.key,
                "source_kind": operation.kind,
                "value": operation.value,
            })),
        )?;
        if let Some(node) = node {
            config_nodes.insert(operation.config_id.clone(), node);
        }
    }
    for operation in &ctx.ir.configuration_operations {
        let Some(config) = config_nodes.get(&operation.config_id).cloned() else {
            continue;
        };
        let target = binding_or_owner(ctx, operation.result_binding_id.as_ref(), operation.owner_callable_id.as_ref());
        let resolution = resolution_of(operation.resolution == "complete");
        state.add_relation(RelationInput::new(
            Some(&config),
            Some(&target),
            configuration_relation(operation),
            resolution,
        ))?;
        if operation.kind == "default" {
            if let Some(source_id) = &operation.source_config_id {
                state.add_relation(RelationInput::new(
                    config_nodes.get(source_id),
                    Some(&config),
                    "overrides",
                    resolution,
                ))?;
            }
        }
        if operation.resolution != "complete" {
            let mut kinds = vec![configuration_relation(operation)];
            if operation.kind == "default" {
                kinds.push("overrides");
            }
            data_unknown(
                state,
                ctx,
                &config,
                "configuration",
                kinds,
                &operation.location,
                format!("Static {} configuration identity is partial.", operation.kind),
                Vec::new(),
            )?;
        }
    }
    Ok(())
}

pub fn project_requests(state: &mut ProjectionState, ctx: &FileCtx<'_>) -> Result<(), JsError> {
    let mut request_nodes: HashMap<String, NodeRef> = HashMap::new();
    for operation in &ctx.ir.request_operations {
        let label = match &operation.endpoint {
            Some(endpoint) if endpoint.encode_utf16().count() <= operation.method.encode_utf16().count() => {
                endpoint.clone()
            }
            _ => operation.method.clone(),
        };
        let node = state.retain_node(
            ctx.file,
            NodeInput::new(
                if operation.kind == "request" { "request" } else { "response" },
                operation.request_id.clone(),
                Some(operation.location),
                Some(label),
            )
            .function(ctx.owner_function_id(operation.owner_callable_id.as_ref()))
            .properties(json!({
                "endpoint": operation.endpoint,
                "method": operation.method,
                "operation_kind": operation.kind,
            })),
        )?;
        if let Some(node) = node {
            request_nodes.insert(operation.request_id.clone(), node);
        }
    }
    for operation in &ctx.ir.request_operations {
        let Some(request) = request_nodes.get(&operation.request_id).cloned() else {
            continue;
        };
        if operation.kind == "request" {
            project_request_construction(state, ctx, operation, &request)?;
        } else {
            state.add_relation(
                RelationInput::new(
                    Some(&request),
                    ctx.call_site_at(&operation.location).as_ref(),
                    "consumed-by",
                    resolution_of(operation.resolution == "complete"),
                )
                .properties(json!({ "method": operation.method })),
            )?;
        }
        if operation.resolution != "complete" {
            let kinds = if operation.kind == "request" {
                vec!["constructs-request", "supplies-request-field"]
            } else {
                vec!["consumed-by"]
            };
            let candidates = operation
                .linked_request_ids
                .iter()
                .filter_map(|id| request_nodes.get(id).map(|n| n.node_id.clone()))
                .collect();
            data_unknown(
                state,
                ctx,
                &request,
                "request",
                kinds,
                &operation.location,
                format!("Static {} request resolution was {}.", operation.method, operation.resolution),
                candidates,
            )?;
        }
    }
    Ok(())
}

fn project_request_construction(
    state: &mut ProjectionState,
    ctx: &FileCtx<'_>,
    operation: &SemanticRequestOperation,
    request: &NodeRef,
) -> Result<(), JsError> {
    let call_site = ctx.call_site_at(&operation.location);
    state.add_relation(RelationInput::new(
        call_site.as_ref(),
        Some(request),
        "constructs-request",
        resolution_of(operation.resolution == "complete"),
    ))?;
    for projected in &operation.projected_result_bindings {
        state.add_relation(
            RelationInput::new(
                Some(request),
                ctx.binding_nodes.get(&projected.binding_id),
                "destructures",
                resolution_of(projected.resolution == "complete"),
            )
            .properties(projection_properties(projected)),
        )?;
    }
    for field in &operation.fields {
        let source = match &field.source_binding_id {
            None => call_site.clone(),
            Some(id) => ctx.binding_nodes.get(id).cloned(),
        };
        state.add_relation(
            RelationInput::new(
                source.as_ref(),
                Some(request),
                "supplies-request-field",
                if field.source_binding_id.is_none() { "candidate" } else { "resolved" },
            )
            .properties(json!({ "field": field.name })),
        )?;
    }
    Ok(())
}

pub fn project_boundaries(state: &mut ProjectionState, ctx: &FileCtx<'_>) -> Result<(), JsError> {
    for operation in &ctx.ir.boundary_operations {
        let Some(boundary) = add_boundary_node(state, ctx, operation)? else {
            continue;
        };
        let relation: &'static str = match operation.kind.as_str() {
            "parse" => "parses",
            "coerce" => "coerces",
            _ => "validates",
        };
        let source = binding_or_owner(ctx, operation.source_binding_id.as_ref(), operation.owner_callable_id.as_ref());
        state.add_relation(RelationInput::new(
            Some(&source),
            Some(&boundary),
            relation,
            resolution_of(operation.resolution == "complete"),
        ))?;
        if operation.resolution != "complete" {
            data_unknown(
                state,
                ctx,
                &boundary,
                "boundary",
                vec![relation],
                &operation.location,
                format!("Static {} boundary kind is a candidate.", operation.method),
                Vec::new(),
            )?;
        }
    }
    Ok(())
}

fn add_boundary_node(
    state: &mut ProjectionState,
    ctx: &FileCtx<'_>,
    operation: &SemanticBoundaryOperation,
) -> Result<Option<NodeRef>, JsError> {
    state.retain_node(
        ctx.file,
        NodeInput::new(
            "boundary",
            operation.boundary_id.clone(),
            Some(operation.location),
            Some(operation.method.clone()),
        )
        .function(ctx.owner_function_id(operation.owner_callable_id.as_ref()))
        .properties(json!({ "boundary_kind": operation.kind, "method": operation.method })),
    )
}

// ---- resources ---------------------------------------------------------------------------------

pub fn project_resources(state: &mut ProjectionState, ctx: &FileCtx<'_>) -> Result<(), JsError> {
    let mut resource_nodes: HashMap<String, NodeRef> = HashMap::new();
    for operation in &ctx.ir.resource_operations {
        if operation.kind != "acquire" {
            continue;
        }
        let node = add_resource_node(state, ctx, operation)?;
        if let Some(node) = node {
            resource_nodes.insert(operation.resource_id.clone(), node);
        }
    }
    for operation in &ctx.ir.resource_operations {
        if operation.kind == "acquire" {
            state.add_relation(RelationInput::new(
                ctx.call_site_at(&operation.location).as_ref(),
                resource_nodes.get(&operation.resource_id),
                "acquires",
                "resolved",
            ))?;
        } else {
            project_release(state, ctx, operation, &resource_nodes)?;
        }
    }
    Ok(())
}

fn add_resource_node(
    state: &mut ProjectionState,
    ctx: &FileCtx<'_>,
    operation: &SemanticResourceOperation,
) -> Result<Option<NodeRef>, JsError> {
    state.retain_node(
        ctx.file,
        NodeInput::new(
            "resource",
            operation.resource_id.clone(),
            Some(operation.location),
            Some(operation.method.clone()),
        )
        .function(ctx.owner_function_id(operation.owner_callable_id.as_ref()))
        .properties(json!({ "method": operation.method })),
    )
}

fn project_release(
    state: &mut ProjectionState,
    ctx: &FileCtx<'_>,
    operation: &SemanticResourceOperation,
    resource_nodes: &HashMap<String, NodeRef>,
) -> Result<(), JsError> {
    let call_site = ctx.call_site_at(&operation.location);
    let resources: Vec<NodeRef> = operation
        .linked_resource_ids
        .iter()
        .filter_map(|id| resource_nodes.get(id).cloned())
        .collect();
    for resource in &resources {
        state.add_relation(RelationInput::new(
            call_site.as_ref(),
            Some(resource),
            "releases",
            resolution_of(operation.resolution == "complete"),
        ))?;
    }
    if operation.resolution == "complete" {
        return Ok(());
    }
    state.add_unknown(UnknownInput {
        node_id: call_site.map(|n| n.node_id.clone()),
        family: "resource-lifecycle",
        relation_kinds: vec!["releases"],
        reason: "ambiguous-target",
        detail: format!("Static {} resource ownership is ambiguous.", operation.method),
        candidate_node_ids: resources.iter().map(|r| r.node_id.clone()).collect(),
        evidence: unknown_semantic_evidence(ctx.file, Some(&operation.location)),
    })
}

// ---- fingerprints ------------------------------------------------------------------------------

/// Bind domain fingerprint components to exact semantic function nodes.
pub fn project_function_fingerprints(
    state: &mut ProjectionState,
    ctx: &FileCtx<'_>,
) -> Result<Vec<Value>, JsError> {
    let mut out = Vec::new();
    for fingerprint in &ctx.ir.function_fingerprints {
        let Some(callable) = ctx.callable_nodes.get(&fingerprint.callable_id) else {
            continue;
        };
        out.push(create_fingerprint(state, ctx, callable, fingerprint)?);
    }
    Ok(out)
}

fn create_fingerprint(
    state: &mut ProjectionState,
    ctx: &FileCtx<'_>,
    callable: &NodeRef,
    fingerprint: &crate::jsgraph::ir::SemanticFunctionFingerprint,
) -> Result<Value, JsError> {
    use crate::jsgraph::util::compare_code_points;
    let mut effects: Vec<String> = fingerprint.components.effects.clone();
    effects.sort_by(|a, b| compare_code_points(a, b));
    effects.dedup();
    let mut limitations: Vec<String> = fingerprint.limitations.clone();
    limitations.sort_by(|a, b| compare_code_points(a, b));
    limitations.dedup();
    let evidence = state
        .evidence
        .intern(&observed_semantic_evidence(ctx.file, callable.source_range.as_ref()))?;
    let components = json!({
        "parameter_arity": fingerprint.components.parameter_arity,
        "normalized_ast_sha256": fingerprint.components.normalized_ast_sha256,
        "control_flow_sha256": fingerprint.components.control_flow_sha256,
        "relation_shape_sha256": fingerprint.components.relation_shape_sha256,
        "literal_set_sha256": fingerprint.components.literal_set_sha256,
        "effects": effects,
    });
    let fingerprint_sha256 = super::evidence::digest(&components)?;
    let fingerprint_id = format!(
        "jsrg_fingerprint_{}",
        super::evidence::digest(&json!({
            "function_node_id": callable.node_id,
            "algorithm": "rea.javascript-semantic-function",
            "fingerprint_sha256": fingerprint_sha256,
        }))?
    );
    let mut object = Map::new();
    object.insert("function_node_id".into(), json!(callable.node_id));
    object.insert("algorithm".into(), json!("rea.javascript-semantic-function"));
    object.insert("status".into(), json!(fingerprint.status));
    object.insert("components".into(), components);
    object.insert("limitations".into(), json!(limitations));
    object.insert("evidence".into(), evidence.to_value());
    object.insert("fingerprint_sha256".into(), json!(fingerprint_sha256));
    object.insert("fingerprint_id".into(), json!(fingerprint_id));
    Ok(Value::Object(object))
}
