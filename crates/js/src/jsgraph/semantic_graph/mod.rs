//! Semantic relation graph projection (port of `JavaScriptSemanticGraph*.ts` and
//! `javascriptSemanticGraph*.ts`): turns each file's semantic IR into semantic nodes, relations,
//! unknown frontiers and function fingerprints, then seals them against the application graph.

mod construction;
mod effects;
pub mod evidence;
mod lookup;
mod project;

use std::collections::HashMap;

use serde_json::{json, Value};

use crate::error::JsError;
use crate::jsgraph::app_graph::analysis::SemanticSink;
use crate::jsgraph::app_graph::model::ArtifactFile;
use crate::jsgraph::app_graph::reconstruct::SemanticGraphBuilder;
use crate::jsgraph::ir::SemanticIr;
use crate::jsgraph::util::compare_code_points;

use construction::{
    application_node_ids_by_location, node_location_key, NodeInput, NodeRef, ProjectionState,
};
use evidence::digest;
use lookup::{CallSiteLookup, CallableOwnerLookup, NodeRangeLookup};
use project::FileCtx;
use tracewise_domain::canonical::canonical_json;

/// Resource-safety ceiling on retained semantic nodes (whole tree).
pub const SEMANTIC_GRAPH_NODE_CEILING: usize = 100_000;
/// Per-file share of the semantic node budget.
pub const SEMANTIC_GRAPH_FILE_NODE_CEILING: usize = 20_000;

const RELATION_FAMILIES: [&str; 12] = [
    "boundary",
    "call-flow",
    "child-process",
    "closure",
    "configuration",
    "data-flow",
    "event",
    "object-flow",
    "promise-ownership",
    "request",
    "resource-lifecycle",
    "timer",
];

/// `JAVASCRIPT_SEMANTIC_RELATION_FAMILY`.
fn relation_family(relation: &str) -> &'static str {
    match relation {
        "acquires" | "releases" => "resource-lifecycle",
        "aggregates" | "awaits" | "chains" | "creates-promise" | "detaches-task" | "owns" | "returns-task" => {
            "promise-ownership"
        }
        "aliases" | "defines" | "reads" | "writes" => "data-flow",
        "argument-to-parameter" | "calls" | "returns-to-call" => "call-flow",
        "cancels-timer" | "schedules-timer" => "timer",
        "captures" => "closure",
        "coerces" | "parses" | "validates" => "boundary",
        "connects-stdio" | "forwards-signal" | "listens-error" | "listens-exit" | "spawns" | "supplies-argv"
        | "supplies-env" => "child-process",
        "consumed-by" | "constructs-request" | "supplies-request-field" => "request",
        "defaults" | "overrides" | "reads-argv" | "reads-config" | "reads-environment" => "configuration",
        "destructures" | "reads-property" | "spreads" | "writes-property" => "object-flow",
        "dispatches-candidate" | "registers-listener" | "removes-listener" => "event",
        other => panic!("unknown semantic relation {other}"),
    }
}

const LIMITATIONS: [&str; 11] = [
    "The semantic graph contains static syntax observations and conservative relationship candidates; it does not claim runtime execution.",
    "Local data flow does not claim control-flow-sensitive reaching definitions or arbitrary dynamic property resolution.",
    "Promise ownership covers explicit unshadowed Promise construction, static factories, aggregation, chaining, and await syntax only.",
    "Function fingerprints are static candidates; equal digests can remain ambiguous and do not prove behavioral equivalence.",
    "Event extraction covers EventEmitter-style literal registrations, removals, and dispatch candidates; dynamic names remain unknown.",
    "Timer extraction covers global or node:timers scheduling and exact local-handle cancellation.",
    "Child-process extraction covers asynchronous node:child_process creation, literal argv/env/stdio options, exit/error listeners, and kill signals.",
    "Configuration extraction covers process.env, process.argv, node:fs reads, and direct logical defaults.",
    "Request extraction covers fetch, WebSocket, node:http/node:https construction, direct option fields, and exact local response consumers.",
    "Boundary extraction covers unshadowed JSON/global coercions plus parse and validation method candidates.",
    "Resource extraction covers built-in filesystem/network acquisition and exact local close/destroy/end handles.",
];

/// File-local semantic projection that does not retain consumed source IR.
pub struct SemanticGraphProjection {
    state: ProjectionState,
    fingerprints: Vec<Value>,
    truncated_files: usize,
}

impl SemanticGraphProjection {
    pub fn new() -> Self {
        SemanticGraphProjection {
            state: ProjectionState::new(),
            fingerprints: Vec::new(),
            truncated_files: 0,
        }
    }

    fn project_file_inner(&mut self, file: &ArtifactFile, ir: &SemanticIr) -> Result<Vec<Value>, JsError> {
        let state = &mut self.state;
        let Some(module_node) = state.retain_node(
            file,
            NodeInput::new("module", "module", None, Some(file.path.clone())),
        )?
        else {
            return Ok(Vec::new());
        };
        state.roots.insert(module_node.node_id.clone());
        let mut callable_nodes: HashMap<String, NodeRef> = HashMap::new();
        for callable in &ir.callables {
            let node = state.retain_node(
                file,
                NodeInput::new(
                    "function",
                    format!("callable:{}", callable.callable_id),
                    Some(callable.location),
                    callable.name.clone(),
                )
                .properties(json!({ "name": callable.name })),
            )?;
            if let Some(node) = node {
                callable_nodes.insert(callable.callable_id.clone(), node);
            }
        }
        let callable_owner = CallableOwnerLookup::new(&ir.callables, &callable_nodes);
        let mut binding_nodes: HashMap<String, NodeRef> = HashMap::new();
        for binding in &ir.bindings {
            let location = binding.definitions.first().map(|d| d.location);
            let kind = if binding.kind == "parameter" { "parameter" } else { "binding" };
            let owner = callable_owner.at(location.as_ref());
            let node = state.retain_node(
                file,
                NodeInput::new(
                    kind,
                    format!("binding:{}", binding.binding_id),
                    location,
                    Some(binding.name.clone()),
                )
                .function(owner.map(|n| n.node_id.clone())),
            )?;
            if let Some(node) = node {
                binding_nodes.insert(binding.binding_id.clone(), node);
            }
        }
        let mut return_site_nodes: HashMap<String, NodeRef> = HashMap::new();
        for callable in &ir.callables {
            let Some(owner) = callable_nodes.get(&callable.callable_id) else {
                continue;
            };
            for site in &callable.return_sites {
                let node = state.retain_node(
                    file,
                    NodeInput::new(
                        "return-site",
                        site.return_site_id.clone(),
                        Some(site.location),
                        Some("return".into()),
                    )
                    .function(Some(owner.node_id.clone())),
                )?;
                if let Some(node) = node {
                    return_site_nodes.insert(site.return_site_id.clone(), node);
                }
            }
        }
        let mut call_site_nodes: HashMap<String, NodeRef> = HashMap::new();
        for call in &ir.call_sites {
            let owner = call
                .caller_callable_id
                .as_ref()
                .and_then(|id| callable_nodes.get(id))
                .map(|n| n.node_id.clone());
            let node = state.retain_node(
                file,
                NodeInput::new(
                    "call-site",
                    format!("call:{}", call.call_site_id),
                    Some(call.location),
                    Some(call.kind.clone()),
                )
                .function(owner),
            )?;
            if let Some(node) = node {
                call_site_nodes.insert(call.call_site_id.clone(), node);
            }
        }
        let call_resolutions = ir
            .call_sites
            .iter()
            .map(|call| {
                (
                    call.call_site_id.clone(),
                    if call.resolution == "exact" { "resolved" } else { "candidate" },
                )
            })
            .collect();
        let call_site_lookup = CallSiteLookup::new(&ir.call_sites, &call_site_nodes);
        let mut ctx = FileCtx {
            file,
            ir,
            module_node,
            binding_nodes,
            callable_nodes,
            call_site_nodes,
            return_site_nodes,
            reference_nodes: Vec::new(),
            reference_lookup: NodeRangeLookup::new(&[]),
            call_resolutions,
            callable_owner,
            call_site_lookup,
        };
        project::project_definitions_and_references(state, &mut ctx)?;
        ctx.reference_lookup = NodeRangeLookup::new(&ctx.reference_nodes);
        project::project_values(state, &ctx)?;
        project::project_objects(state, &ctx)?;
        project::project_calls(state, &ctx)?;
        project::project_promises(state, &ctx)?;
        effects::project_events(state, &ctx)?;
        effects::project_timers(state, &ctx)?;
        effects::project_child_processes(state, &ctx)?;
        effects::project_configuration(state, &ctx)?;
        effects::project_requests(state, &ctx)?;
        effects::project_boundaries(state, &ctx)?;
        effects::project_resources(state, &ctx)?;
        project::project_closure_captures(state, &ctx)?;
        project::project_frontiers(state, &ctx)?;
        effects::project_function_fingerprints(state, &ctx)
    }

    fn finish_inner(&mut self, root_artifact_sha256: &str, application_graph: &Value) -> Result<Value, JsError> {
        // Bind retained semantic identities after all application observations exist.
        let application_nodes: Vec<Value> = application_graph["nodes"].as_array().cloned().unwrap_or_default();
        let by_location = application_node_ids_by_location(&application_nodes);
        if self.state.roots.is_empty() {
            self.state.add_fallback_root(root_artifact_sha256)?;
        }
        let mut nodes: Vec<Value> = self
            .state
            .nodes
            .values()
            .map(|node| {
                let ids = by_location.get(&node_location_key(node)).cloned().unwrap_or_default();
                node.to_value(&ids)
            })
            .collect();
        let relations: Vec<Value> = self.state.relations.values().cloned().collect();
        let unknowns: Vec<Value> = self.state.unknowns.values().cloned().collect();
        let mut retained_by_family: HashMap<&str, usize> = HashMap::new();
        for relation in &relations {
            let family = relation_family(relation["relation"].as_str().unwrap_or_default());
            *retained_by_family.entry(family).or_default() += 1;
        }
        let mut unknown_ids_by_family: HashMap<String, Vec<String>> = HashMap::new();
        for unknown in &unknowns {
            unknown_ids_by_family
                .entry(unknown["family"].as_str().unwrap_or_default().to_string())
                .or_default()
                .push(unknown["unknown_id"].as_str().unwrap_or_default().to_string());
        }
        let truncated = self.truncated_files > 0;
        let families: Vec<Value> = RELATION_FAMILIES
            .iter()
            .map(|family| {
                let mut ids = unknown_ids_by_family.remove(*family).unwrap_or_default();
                ids.sort_by(|a, b| compare_code_points(a, b));
                ids.dedup();
                json!({
                    "family": family,
                    "status": "partial",
                    "retained_relations": retained_by_family.get(family).copied().unwrap_or(0),
                    "omitted_relations": if truncated { Value::Null } else { json!(0) },
                    "unknown_ids": ids,
                })
            })
            .collect();
        let sort_by_key = |items: &mut Vec<Value>, key: &str| {
            items.sort_by(|a, b| {
                compare_code_points(a[key].as_str().unwrap_or_default(), b[key].as_str().unwrap_or_default())
            });
        };
        sort_by_key(&mut nodes, "node_id");
        let mut relations = relations;
        sort_by_key(&mut relations, "relation_id");
        let mut fingerprints = std::mem::take(&mut self.fingerprints);
        sort_by_key(&mut fingerprints, "fingerprint_id");
        let mut unknowns = unknowns;
        sort_by_key(&mut unknowns, "unknown_id");
        let mut limits: Vec<Value> = Vec::new();
        if truncated {
            limits.push(json!({
                "name": "semantic_graph_node_ceiling",
                "value": SEMANTIC_GRAPH_NODE_CEILING,
                "unit": "items",
            }));
        }
        let mut limitations: Vec<String> = LIMITATIONS.iter().map(|s| s.to_string()).collect();
        limitations.sort_by(|a, b| compare_code_points(a, b));
        limitations.dedup();
        let mut root_ids: Vec<String> = self.state.roots.iter().cloned().collect();
        root_ids.sort_by(|a, b| compare_code_points(a, b));
        root_ids.dedup();
        let semantic = json!({
            "schema": "JavaScriptSemanticRelationGraph",
            "root_artifact_sha256": root_artifact_sha256,
            "application_graph_id": application_graph["graph_id"],
            "root_node_ids": root_ids,
            "evidence_contexts": self.state.evidence.contexts(),
            "nodes": nodes,
            "relations": relations,
            "fingerprints": fingerprints,
            "unknowns": unknowns,
            "coverage": {
                "status": if truncated { "partial" } else { "unknown" },
                "truncated": truncated,
                "omitted_nodes": if truncated { Value::Null } else { json!(0) },
                "omitted_relations": if truncated { Value::Null } else { json!(0) },
                "limits": limits,
                "families": families,
            },
            "limitations": limitations,
        });
        let graph_id = format!("jsrg_{}", digest(&semantic)?);
        let mut graph = semantic;
        graph
            .as_object_mut()
            .expect("graph object")
            .insert("graph_id".into(), json!(graph_id));
        self.state.clear();
        let _ = canonical_json(&Value::Null);
        Ok(graph)
    }
}

impl Default for SemanticGraphProjection {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticSink for SemanticGraphProjection {
    fn project_file(&mut self, file: &ArtifactFile, ir: &SemanticIr) -> Result<(), JsError> {
        if self.state.nodes.len() >= SEMANTIC_GRAPH_NODE_CEILING {
            self.truncated_files += 1;
            return Ok(());
        }
        let remaining_tree_budget = SEMANTIC_GRAPH_NODE_CEILING - self.state.nodes.len();
        self.state.file_node_budget =
            Some(SEMANTIC_GRAPH_FILE_NODE_CEILING.min(remaining_tree_budget) as i64);
        self.state.file_nodes_dropped = false;
        let fingerprints = self.project_file_inner(file, ir)?;
        self.fingerprints.extend(fingerprints);
        if self.state.file_nodes_dropped {
            self.truncated_files += 1;
        }
        self.state.file_node_budget = None;
        Ok(())
    }
}

impl SemanticGraphBuilder for SemanticGraphProjection {
    fn finish(mut self: Box<Self>, root_artifact_sha256: &str, application_graph: &Value) -> Result<Value, JsError> {
        self.finish_inner(root_artifact_sha256, application_graph)
    }
}
