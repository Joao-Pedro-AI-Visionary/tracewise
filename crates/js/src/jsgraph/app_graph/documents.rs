//! HTML renderer roles and source-map originals (REA `JavaScriptArtifactGraphDocuments.ts`).

use std::collections::HashMap;

use serde_json::{json, Value};

use crate::error::JsError;

use super::context::{EdgeInput, GraphContext, RoleNodeInput};
use super::domain::{
    artifact_observation_evidence, complete_coverage, static_inference_evidence, EvidenceInput, ObservationInput,
};
use super::model::HtmlScriptObservation;
use super::path_resolution::{
    resolve_artifact_path_by_context, PathContext, Resolution, ResolveInput, Status,
};

/// Project HTML renderer entrypoints and their local script assets.
pub fn add_html_roles(ctx: &mut GraphContext<'_>) -> Result<(), JsError> {
    let analysis = ctx.analysis;
    let mut order: Vec<&str> = Vec::new();
    let mut by_html: HashMap<&str, Vec<&HtmlScriptObservation>> = HashMap::new();
    for script in &analysis.html_scripts {
        let entry = by_html.entry(script.html_path.as_str()).or_default();
        if entry.is_empty() {
            order.push(script.html_path.as_str());
        }
        entry.push(script);
    }
    for html_path in order {
        let scripts = &by_html[html_path];
        let Some(html) = ctx.files_by_path.get(html_path) else {
            continue;
        };
        let role_resolution = Resolution {
            declared_path: html.path.clone(),
            context: PathContext::HtmlReference,
            resolved_path: Some(html.path.clone()),
            status: Status::Resolved,
            limitations: Vec::new(),
        };
        let role = ctx.create_electron_role_node(RoleNodeInput {
            kind: "electron-renderer",
            anchor: html,
            resolution: &role_resolution,
            mechanism: "html-script-entrypoint",
            range: None,
            coverage: None,
        })?;
        let root = ctx.root.clone();
        ctx.add_artifact_contains_edge(&root, &role, html, "discover-html-renderer")?;
        ctx.link_electron_role_to_asset(&role, html, &role_resolution, None, None)?;
        for script in scripts {
            let mut input = ResolveInput::new(
                &script.script_path,
                &html.path,
                PathContext::HtmlReference,
                &ctx.files_by_path,
            );
            input.html_base_href = script.base_href.as_deref();
            let resolution = resolve_artifact_path_by_context(&input);
            let coverage = complete_coverage();
            let Some(resolved_path) = &resolution.resolved_path else {
                let mut properties = serde_json::Map::new();
                properties.insert("mechanism".into(), json!("html-script-reference"));
                properties.insert("script_path".into(), json!(script.script_path));
                properties.insert("base_href".into(), json!(script.base_href));
                properties.extend(resolution.to_properties());
                ctx.acc.add_node(
                    &role.kind,
                    role.identity.clone(),
                    vec![ObservationInput::new(
                        Some(script.script_path.clone()),
                        Value::Object(properties),
                        static_inference_evidence(
                            &EvidenceInput::new(&html.sha256, &html.path, "resolve-html-script-reference", &coverage)
                                .range(&script.location)
                                .limitations(&resolution.limitations),
                        ),
                    )],
                )?;
                continue;
            };
            let Some(resolved) = ctx.file_nodes.get(resolved_path).cloned() else {
                continue;
            };
            ctx.add_static_inference_edge(
                EdgeInput {
                    source: &role,
                    target: &resolved,
                    file: html,
                    range: &script.location,
                    coverage: &coverage,
                    properties: json!({
                        "script_path": script.script_path,
                        "base_href": script.base_href,
                        "resolution_context": resolution.context.as_str(),
                        "resolved_path": resolved_path,
                        "resolution_status": resolution.status.as_str(),
                        "limitations": resolution.limitations,
                    }),
                },
                "loads",
            )?;
        }
    }
    Ok(())
}

/// Project original source names and optional content digests from approved maps.
pub fn add_source_map_originals(ctx: &mut GraphContext<'_>) -> Result<(), JsError> {
    let analysis = ctx.analysis;
    for source_map in &analysis.source_maps {
        let (Some(map_file), Some(map_node)) = (
            ctx.files_by_path.get(&source_map.path),
            ctx.file_nodes.get(&source_map.path).cloned(),
        ) else {
            continue;
        };
        let coverage = complete_coverage();
        let limitations: Vec<String> = source_map.limitation.iter().cloned().collect();
        for original in &source_map.sources {
            let node = ctx.acc.add_node(
                "source-module",
                json!({
                    "strategy": "source-map-original",
                    "stability": "source-map-exact",
                    "source_map_sha256": map_file.sha256,
                    "original_source": original.source_name,
                    "source_root": original.source_root,
                    "source_sha256": original.content_sha256,
                }),
                vec![ObservationInput {
                    label: Some(original.source_name.clone()),
                    source_map_reference: original.reference.clone(),
                    properties: json!({ "content_available": original.content.is_some() })
                        .as_object()
                        .cloned()
                        .unwrap_or_default(),
                    evidence: artifact_observation_evidence(
                        &EvidenceInput::new(&map_file.sha256, &map_file.path, "parse-local-source-map", &coverage)
                            .limitations(&limitations),
                    ),
                }],
            )?;
            ctx.acc.add_edge(
                &map_node.node_id,
                &node.node_id,
                "contains",
                json!({
                    "original_source": original.source_name,
                    "source_root": original.source_root,
                }),
                artifact_observation_evidence(
                    &EvidenceInput::new(&map_file.sha256, &map_file.path, "parse-local-source-map", &coverage)
                        .limitations(&limitations),
                ),
            )?;
        }
    }
    Ok(())
}
