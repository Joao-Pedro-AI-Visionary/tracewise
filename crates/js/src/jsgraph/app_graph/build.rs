//! Project artifact and AST facts into the JavaScript Application Graph (REA
//! `JavaScriptArtifactGraphBuilder.ts`).

use std::collections::HashMap;

use serde_json::{json, Value};

use crate::application::graph_seal::seal_application_graph;
use crate::error::JsError;
use crate::jsgraph::control::Cancel;
use crate::jsgraph::ir::ResourceLimit;
use crate::types::ArtifactInventoryResult;

use super::bundlers::add_bundler_nodes;
use super::context::{self_reference_omissions, GraphContext};
use super::documents::{add_html_roles, add_source_map_originals};
use super::domain::{complete_coverage, partial_coverage, Accumulator};
use super::electron::{
    add_electron_boundaries, classify_ipc_pairings, collect_ipc_records,
};
use super::findings::add_static_findings;
use super::model::{ArtifactAnalysis, FileSet};
use super::module_relationships::{
    add_module_relationships, add_source_modules, resource_limit_coverage, resource_limit_reason,
    semantic_resource_limits, RelationshipOmissions,
};
use super::path_resolution::Files;
use super::structure::{
    add_artifact_containers, add_artifact_files, add_package_nodes, create_root_node,
};

/// Build the sealed application graph.
pub fn build_application_graph(
    snapshot: &ArtifactInventoryResult,
    file_set: &FileSet,
    analysis: &ArtifactAnalysis,
    cancel: &Cancel,
) -> Result<Value, JsError> {
    let mut acc = Accumulator::new();
    let root = create_root_node(&mut acc, snapshot)?;
    let mut container_nodes = HashMap::new();
    container_nodes.insert(snapshot.manifest.root_sha256.clone(), root.clone());
    let mut ctx = GraphContext {
        acc,
        snapshot,
        file_set,
        analysis,
        root: root.clone(),
        files_by_path: Files::new(file_set.files.iter()),
        file_nodes: HashMap::new(),
        asset_nodes: HashMap::new(),
        source_module_nodes: HashMap::new(),
        chunk_nodes: HashMap::new(),
        module_nodes: HashMap::new(),
        container_nodes,
    };
    add_artifact_containers(&mut ctx)?;
    cancel.check()?;
    add_artifact_files(&mut ctx)?;
    cancel.check()?;
    let package_roots = add_package_nodes(&mut ctx)?;
    add_source_modules(&mut ctx)?;
    cancel.check()?;
    let bundler_limitations = add_bundler_nodes(&mut ctx)?;
    let relationship_omissions = add_module_relationships(&mut ctx)?;
    cancel.check()?;
    let finding_limitations = add_static_findings(&mut ctx)?;
    cancel.check()?;
    add_electron_boundaries(&mut ctx)?;
    add_html_roles(&mut ctx)?;
    add_source_map_originals(&mut ctx)?;
    cancel.check()?;
    let coverage = graph_coverage(&ctx);
    let coverage_status = coverage["status"].as_str().unwrap_or("complete").to_string();
    let root_node_ids: Vec<String> = if package_roots.is_empty() {
        vec![root.node_id.clone()]
    } else {
        package_roots.iter().map(|n| n.node_id.clone()).collect()
    };
    let mut limitations: Vec<String> = Vec::new();
    limitations.extend(bundler_limitations);
    limitations.extend(finding_limitations);
    limitations.extend(graph_limitations(&ctx, &coverage_status, &relationship_omissions));
    let graph = json!({
        "schema": "JavaScriptApplicationGraph",
        "root_node_ids": root_node_ids,
        "nodes": ctx.acc.nodes(),
        "edges": ctx.acc.edges(),
        "coverage": coverage,
        "limitations": limitations,
    });
    seal_application_graph(&graph)
}

fn semantic_limits(ctx: &GraphContext<'_>) -> Vec<ResourceLimit> {
    let mut found: Vec<ResourceLimit> = Vec::new();
    for analyzed in &ctx.analysis.files {
        if let Some(semantic) = &analyzed.semantic {
            for limit in semantic_resource_limits(semantic) {
                if !found.contains(&limit) {
                    found.push(limit);
                }
            }
        }
    }
    found.sort_by_key(|limit| limit.as_str());
    found
}

fn graph_coverage(ctx: &GraphContext<'_>) -> Value {
    let analysis = ctx.analysis;
    let resource_limits = semantic_limits(ctx);
    let source_map_policy_gap = analysis.source_maps.iter().any(|m| m.status == "invalid");
    let malformed = analysis.packages.iter().any(|p| p.status != "included")
        || analysis.json_modules.iter().any(|j| j.status != "included")
        || analysis.source_maps.iter().any(|m| m.status == "invalid");
    let partial_javascript = analysis
        .files
        .iter()
        .any(|a| a.javascript.as_ref().is_some_and(|js| js.parse_status == "partial"));
    let unknown_gap = analysis.parse_failures > 0
        || ctx.file_set.invalid_utf8_files > 0
        || source_map_policy_gap
        || malformed
        || partial_javascript;
    if !resource_limits.is_empty() {
        return partial_coverage(resource_limit_coverage(&resource_limits), None);
    }
    if unknown_gap {
        return partial_coverage(Vec::new(), None);
    }
    if !ctx.snapshot.integrity_contradictions.is_empty() {
        let nested_archive_was_opaque = ctx
            .snapshot
            .integrity_contradictions
            .iter()
            .any(|c| c.logical_path.to_lowercase().ends_with(".asar"));
        return partial_coverage(Vec::new(), if nested_archive_was_opaque { None } else { Some(0) });
    }
    complete_coverage()
}

fn graph_limitations(
    ctx: &GraphContext<'_>,
    coverage: &str,
    omissions: &RelationshipOmissions,
) -> Vec<String> {
    let analysis = ctx.analysis;
    let ipc = collect_ipc_records(analysis);
    let pairings = classify_ipc_pairings(&ipc);
    let electron_findings: usize = analysis
        .files
        .iter()
        .map(|a| {
            a.javascript.as_ref().map_or(0, |js| {
                let e = &js.electron;
                e.browser_windows.len()
                    + e.context_bridge_apis.len()
                    + e.ipc.len()
                    + e.sender_validations.len()
                    + e.utility_processes.len()
                    + e.native_addon_bindings.len()
            })
        })
        .sum();
    let mut out: Vec<String> = analysis.limitations.clone();
    out.extend(ctx.snapshot.integrity_contradictions.iter().map(|c| {
        format!(
            "Artifact integrity metadata contradicts observed bytes at {}; the observed bytes are untrusted.",
            c.logical_path
        )
    }));
    out.extend(self_reference_omissions(
        omissions.self_imports,
        ("import specifier", "import specifiers"),
        "the importing module",
    ));
    out.push("CommonJS and ESM binding relationships were recovered from inert syntax and resolved only within the inventoried artifact container.".into());
    out.push("Webpack/Rspack factories were recovered from AST literals; REA did not invoke push handlers or bundle bootstrap code.".into());
    out.push("Static imports, entrypoints, workers, endpoints, and storage relationships do not prove runtime execution.".into());
    if electron_findings != 0 {
        out.push("Electron relationships are derived from inert syntax; runtime registration, reachability, defaults, and enforcement remain unproven.".into());
    }
    if ipc.iter().any(|r| r.finding.channel.is_none()) {
        out.push("Dynamic IPC channel expressions remain unresolved and are never paired by textual similarity.".into());
    }
    if pairings.iter().any(|s| s.status == "ambiguous") {
        out.push("Some literal IPC channels have multiple compatible main handlers; ambiguous calls are not paired to any handler.".into());
    }
    if analysis
        .files
        .iter()
        .any(|a| a.javascript.as_ref().is_some_and(|js| !js.electron.sender_validations.is_empty()))
    {
        out.push("Sender, frame, URL, and origin checks are observations only; REA does not claim that they enforce a complete authorization policy.".into());
    }
    out.extend(semantic_limits(ctx).into_iter().map(|l| resource_limit_reason(l).to_string()));
    if analysis
        .files
        .iter()
        .any(|a| a.javascript.as_ref().is_some_and(|js| !js.electron.native_addon_bindings.is_empty()))
    {
        out.push("Native member names are requested by JavaScript syntax and are not verified binary exports in this workflow.".into());
    }
    if coverage != "complete" {
        out.push("Graph coverage is incomplete; unavailable facts remain explicit and must not be read as absence.".into());
    }
    out
}
