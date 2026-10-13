//! Root, container, file and package nodes (REA `JavaScriptArtifactGraphStructure.ts`).

use serde_json::json;

use crate::error::JsError;
use crate::jsgraph::static_types::StaticAnalysis;

use super::context::{artifact_file_node_kind, GraphContext, RoleNodeInput};
use super::domain::{
    artifact_local_identity, artifact_observation_evidence, canonical_path_identity,
    complete_coverage, content_digest_identity, static_inference_evidence, Accumulator,
    EvidenceInput, NodeRef, ObservationInput,
};
use super::model::{ArtifactFile, FileKind};
use super::path_resolution::PathContext;
use crate::types::ArtifactInventoryResult;

/// Create the exact root artifact node from the inventory manifest.
pub fn create_root_node(
    acc: &mut Accumulator,
    snapshot: &ArtifactInventoryResult,
) -> Result<NodeRef, JsError> {
    let root = snapshot
        .nodes
        .iter()
        .find(|node| node.artifact_id == snapshot.manifest.root_artifact_id)
        .ok_or_else(|| JsError::InvalidInput("Artifact inventory root is missing".into()))?;
    let coverage = complete_coverage();
    let limitations = vec![
        "artifact-root is a path-independent alias; the application result retains the canonical local input path."
            .to_string(),
    ];
    acc.add_node(
        "artifact",
        content_digest_identity(&root.sha256),
        vec![ObservationInput::new(
            Some("artifact root".into()),
            json!({
                "format": snapshot.manifest.root_format,
                "bytes": root.size,
                "inventory_manifest_id": snapshot.manifest.manifest_id,
                "inventory_graph_sha256": snapshot.manifest.graph_sha256,
                "inventory_artifact_id": root.artifact_id,
            }),
            artifact_observation_evidence(
                &EvidenceInput::new(&root.sha256, "artifact-root", "inventory-root", &coverage)
                    .limitations(&limitations),
            ),
        )],
    )
}

/// Project nested ASAR containers inventoried inside a directory.
pub fn add_artifact_containers(ctx: &mut GraphContext<'_>) -> Result<(), JsError> {
    let coverage = complete_coverage();
    for container in &ctx.file_set.containers {
        let node = ctx.acc.add_node(
            "artifact",
            content_digest_identity(&container.sha256),
            vec![ObservationInput::new(
                Some(container.path.clone()),
                json!({
                    "path": container.path,
                    "format": "asar",
                    "bytes": container.bytes,
                    "inventory_artifact_id": container.inventory_artifact_id,
                }),
                artifact_observation_evidence(&EvidenceInput::new(
                    &container.sha256,
                    &container.path,
                    "inventory-nested-asar",
                    &coverage,
                )),
            )],
        )?;
        ctx.container_nodes.insert(container.sha256.clone(), node.clone());
        let root_sha = ctx.snapshot.manifest.root_sha256.clone();
        ctx.acc.add_edge(
            &ctx.root.node_id.clone(),
            &node.node_id,
            "contains",
            json!({ "path": container.path, "format": "asar" }),
            artifact_observation_evidence(&EvidenceInput::new(
                &root_sha,
                &container.path,
                "inventory-nested-asar",
                &coverage,
            )),
        )?;
    }
    Ok(())
}

/// Project relevant files, ASAR entries, and explicit unavailable parse scopes.
pub fn add_artifact_files(ctx: &mut GraphContext<'_>) -> Result<(), JsError> {
    let analysis = ctx.analysis;
    for analyzed in &analysis.files {
        let file = &analyzed.file;
        let target = create_file_target(ctx, file, analyzed.javascript.as_ref())?;
        ctx.file_nodes.insert(file.path.clone(), target.clone());
        if file.kind == FileKind::Javascript {
            ctx.asset_nodes.insert(file.path.clone(), target.clone());
        }
        let entry = create_asar_entry(ctx, file)?;
        let parent = ctx
            .container_nodes
            .get(&file.container_sha256)
            .cloned()
            .unwrap_or_else(|| ctx.root.clone());
        match entry {
            None => ctx.add_artifact_contains_edge(&parent, &target, file, "inventory-file")?,
            Some(entry) => {
                ctx.add_artifact_contains_edge(&parent, &entry, file, "inventory-entry")?;
                let coverage = complete_coverage();
                ctx.acc.add_edge(
                    &entry.node_id,
                    &target.node_id,
                    "maps_to",
                    json!({ "sha256": file.sha256 }),
                    artifact_observation_evidence(&EvidenceInput::new(
                        &file.container_sha256,
                        &file.path,
                        "map-entry-content",
                        &coverage,
                    )),
                )?;
            }
        }
        if file.kind == FileKind::Javascript
            && analyzed
                .javascript
                .as_ref()
                .is_none_or(|js| js.parse_status == "failed")
        {
            let limitation = match &file.text {
                Some(_) => "JavaScript syntax could not be parsed.".to_string(),
                None => format!(
                    "JavaScript text was unavailable: {}.",
                    file.text_reason.unwrap_or("not-applicable")
                ),
            };
            ctx.add_unavailable_static_parse_scope(file, &target, "parse-javascript", &limitation)?;
        }
        if let Some(package) = analysis.packages.iter().find(|p| p.path == file.path) {
            if package.status != "included" {
                ctx.add_unavailable_static_parse_scope(
                    file,
                    &target,
                    "parse-package-json",
                    package.limitation.as_deref().unwrap_or_default(),
                )?;
            }
        }
        if let Some(json_module) = analysis.json_modules.iter().find(|j| j.path == file.path) {
            if json_module.status != "included" {
                ctx.add_unavailable_static_parse_scope(
                    file,
                    &target,
                    "parse-json-module",
                    json_module.limitation.as_deref().unwrap_or_default(),
                )?;
            }
        }
        if let Some(source_map) = analysis.source_maps.iter().find(|m| m.path == file.path) {
            if source_map.status == "invalid" {
                ctx.add_unavailable_static_parse_scope(
                    file,
                    &target,
                    "parse-local-source-map",
                    source_map.limitation.as_deref().unwrap_or_default(),
                )?;
            }
        }
    }
    Ok(())
}

/// Project package metadata and its declared Electron roles.
pub fn add_package_nodes(ctx: &mut GraphContext<'_>) -> Result<Vec<NodeRef>, JsError> {
    let analysis = ctx.analysis;
    let mut roots: Vec<NodeRef> = Vec::new();
    for package in &analysis.packages {
        let Some(file) = ctx.files_by_path.get(&package.path) else {
            continue;
        };
        let coverage = complete_coverage();
        let limitations: Vec<String> = package.limitation.iter().cloned().collect();
        let node = ctx.acc.add_node(
            "package",
            artifact_local_identity(&file.sha256, "package-json", &file.path),
            vec![ObservationInput::new(
                Some(package.name.clone().unwrap_or_else(|| file.path.clone())),
                json!({
                    "path": file.path,
                    "name": package.name,
                    "version": package.version,
                    "main": package.main,
                    "renderer": package.renderer,
                    "parse_status": package.status,
                }),
                artifact_observation_evidence(
                    &EvidenceInput::new(&file.sha256, &file.path, "parse-package-json", &coverage)
                        .limitations(&limitations),
                ),
            )],
        )?;
        if roots.is_empty() {
            roots.push(node.clone());
            ctx.acc.add_edge(
                &node.node_id,
                &ctx.root.node_id.clone(),
                "contains",
                json!({ "basis": "package-metadata-within-artifact" }),
                static_inference_evidence(&EvidenceInput::new(
                    &file.sha256,
                    &file.path,
                    "associate-package-artifact",
                    &coverage,
                )),
            )?;
        } else {
            let root = ctx.root.clone();
            ctx.add_artifact_contains_edge(&root, &node, file, "inventory-package")?;
        }
        add_package_role(ctx, &node, file, "electron-main", package.main.as_deref())?;
        add_package_role(ctx, &node, file, "electron-renderer", package.renderer.as_deref())?;
    }
    Ok(roots)
}

fn create_file_target(
    ctx: &mut GraphContext<'_>,
    file: &ArtifactFile,
    javascript: Option<&StaticAnalysis>,
) -> Result<NodeRef, JsError> {
    let kind = artifact_file_node_kind(file.kind);
    let json_module = ctx.analysis.json_modules.iter().find(|j| j.path == file.path);
    let coverage = complete_coverage();
    let text_status = match &file.text {
        Some(_) => "included".to_string(),
        None => file.text_reason.unwrap_or("not-applicable").to_string(),
    };
    ctx.acc.add_node(
        kind,
        content_digest_identity(&file.sha256),
        vec![ObservationInput::new(
            Some(file.path.clone()),
            json!({
                "path": file.path,
                "bytes": file.bytes,
                "inventory_artifact_id": file.inventory_artifact_id,
                "unpacked": file.unpacked,
                "file_kind": file.kind.as_str(),
                "text_status": text_status,
                "parse_status": javascript.map(|js| js.parse_status.clone()),
                "json_parse_status": json_module.map(|j| j.status),
                "json_top_level_keys": json_module.map(|j| j.top_level_keys.clone()).unwrap_or_default(),
                "omitted_json_top_level_keys": json_module.and_then(|j| j.omitted_top_level_keys).unwrap_or(0),
                "vendor_markers": javascript.map(|js| js.vendors.clone()).unwrap_or_default(),
            }),
            artifact_observation_evidence(&EvidenceInput::new(
                &file.sha256,
                &file.path,
                "inventory-relevant-file",
                &coverage,
            )),
        )],
    )
}

fn create_asar_entry(ctx: &mut GraphContext<'_>, file: &ArtifactFile) -> Result<Option<NodeRef>, JsError> {
    let is_asar = ctx.snapshot.manifest.root_format == "asar"
        || file.container_sha256 != ctx.snapshot.manifest.root_sha256;
    if !is_asar {
        return Ok(None);
    }
    let coverage = complete_coverage();
    let node = ctx.acc.add_node(
        "asar-entry",
        canonical_path_identity(&file.container_sha256, &file.path),
        vec![ObservationInput::new(
            Some(file.path.clone()),
            json!({
                "entry_sha256": file.sha256,
                "bytes": file.bytes,
                "unpacked": file.unpacked,
                "inventory_artifact_id": file.inventory_artifact_id,
            }),
            artifact_observation_evidence(&EvidenceInput::new(
                &file.container_sha256,
                &file.path,
                "inventory-asar-entry",
                &coverage,
            )),
        )],
    )?;
    Ok(Some(node))
}

fn add_package_role(
    ctx: &mut GraphContext<'_>,
    package_node: &NodeRef,
    package_file: &ArtifactFile,
    kind: &'static str,
    declared: Option<&str>,
) -> Result<(), JsError> {
    let Some(declared) = declared else {
        return Ok(());
    };
    let resolution = ctx.resolve_by_context(declared, &package_file.path, PathContext::PackageEntrypoint);
    let role = ctx.create_electron_role_node(RoleNodeInput {
        kind,
        anchor: package_file,
        resolution: &resolution,
        mechanism: if kind == "electron-main" { "package.json:main" } else { "package.json:renderer" },
        range: None,
        coverage: None,
    })?;
    let coverage = complete_coverage();
    ctx.acc.add_edge(
        &package_node.node_id,
        &role.node_id,
        "loads",
        json!({
            "declared_path": declared,
            "resolution_context": resolution.context.as_str(),
            "resolved_path": resolution.resolved_path,
            "resolution_status": resolution.status.as_str(),
            "limitations": resolution.limitations,
        }),
        static_inference_evidence(
            &EvidenceInput::new(&package_file.sha256, &package_file.path, "discover-package-entrypoint", &coverage)
                .limitations(&resolution.limitations),
        ),
    )?;
    ctx.link_electron_role_to_asset(&role, package_file, &resolution, None, None)
}
