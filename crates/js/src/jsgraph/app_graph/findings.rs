//! Static findings as graph nodes and edges (REA `JavaScriptArtifactGraphFindings.ts`).

use serde_json::{json, Value};

use crate::error::JsError;
use crate::jsgraph::static_types::{
    RolePath, SourceMapUrl, StaticEndpoint, StaticReference, StaticStorage,
};
use crate::jsgraph::util::sha256_text;
use tracewise_domain::canonical::canonical_sha256;

use super::context::{
    chunk_lookup_key, javascript_analysis_coverage, module_lookup_key, self_reference_omissions,
    EdgeInput, GraphContext, RoleNodeInput,
};
use super::domain::{
    artifact_local_identity, ast_observation_evidence, static_inference_evidence, EvidenceInput, NodeRef,
    ObservationInput,
};
use super::model::{ArtifactFile, FileKind};
use super::path_resolution::{ModuleKind, PathContext};

/// `compactStringIdentityKey`: short exact keys, or their digest in a reserved namespace.
pub fn compact_string_identity_key(value: &str) -> Result<String, JsError> {
    let prefix = "value-sha256:";
    let digest = canonical_sha256(&Value::String(value.to_string()))?;
    let digest_key = format!("{prefix}{digest}");
    if value.encode_utf16().count() <= digest_key.encode_utf16().count() && !value.starts_with(prefix) {
        Ok(value.to_string())
    } else {
        Ok(digest_key)
    }
}

struct Resolved {
    path: String,
    file_kind: FileKind,
    node: NodeRef,
}

/// Project imports, workers, roles, endpoints, storage, and source-map links.
pub fn add_static_findings(ctx: &mut GraphContext<'_>) -> Result<Vec<String>, JsError> {
    let analysis = ctx.analysis;
    let mut self_references = 0u64;
    for analyzed in &analysis.files {
        let file = &analyzed.file;
        let (Some(javascript), Some(asset)) = (analyzed.javascript.as_ref(), ctx.asset_nodes.get(&file.path).cloned())
        else {
            continue;
        };
        let coverage = javascript_analysis_coverage(javascript);
        for value in &javascript.references {
            self_references += add_reference(ctx, file, &asset, value, &coverage)?;
        }
        for value in &javascript.endpoints {
            add_endpoint(ctx, file, &asset, value, &coverage)?;
        }
        for value in &javascript.storage {
            add_storage(ctx, file, &asset, value, &coverage)?;
        }
        for value in &javascript.role_paths {
            add_discovered_role(ctx, file, &asset, value, &coverage)?;
        }
        for value in &javascript.source_map_urls {
            add_source_map_edge(ctx, file, &asset, value, &coverage)?;
        }
    }
    Ok(self_reference_omissions(
        self_references,
        ("static reference", "static references"),
        "the referencing module",
    ))
}

fn finding_source(
    ctx: &GraphContext<'_>,
    file: &ArtifactFile,
    asset: &NodeRef,
    module_key: Option<&str>,
    runtime: Option<&str>,
) -> NodeRef {
    ctx.source_node_for(&file.path, module_key, runtime)
        .unwrap_or_else(|| asset.clone())
}

fn add_reference(
    ctx: &mut GraphContext<'_>,
    file: &ArtifactFile,
    asset: &NodeRef,
    value: &StaticReference,
    coverage: &Value,
) -> Result<u64, JsError> {
    let source = finding_source(ctx, file, asset, value.module_key.as_deref(), value.module_runtime.as_deref());
    let resolved = match &value.specifier {
        None => None,
        Some(_) => resolve_reference(ctx, &file.path, value),
    };
    if value.kind == "worker" || value.kind == "service-worker" {
        let worker = ctx.acc.add_node(
            if value.kind == "worker" { "worker" } else { "service-worker" },
            artifact_local_identity(
                &file.sha256,
                &value.kind,
                value.specifier.as_deref().or(value.expression.as_deref()).unwrap_or_default(),
            ),
            vec![ObservationInput::new(
                value.specifier.clone(),
                json!({
                    "declared_specifier": value.specifier,
                    "expression": value.expression,
                    "resolved_path": resolved.as_ref().map(|r| r.path.clone()),
                }),
                static_inference_evidence(
                    &EvidenceInput::new(&file.sha256, &file.path, "discover-worker", coverage)
                        .range(&value.location),
                ),
            )],
        )?;
        ctx.add_static_inference_edge(
            EdgeInput {
                source: &source,
                target: &worker,
                file,
                range: &value.location,
                coverage,
                properties: json!({ "kind": value.kind }),
            },
            "loads",
        )?;
        if let Some(resolved) = &resolved {
            ctx.add_static_inference_edge(
                EdgeInput {
                    source: &worker,
                    target: &resolved.node,
                    file,
                    range: &value.location,
                    coverage,
                    properties: json!({ "resolved_path": resolved.path }),
                },
                "maps_to",
            )?;
        }
        return Ok(0);
    }
    // A reference that resolves to its own source cannot become an edge.
    if resolved.as_ref().is_some_and(|r| r.node.node_id == source.node_id) {
        return Ok(1);
    }
    let target = match &resolved {
        Some(resolved) => resolved.node.clone(),
        None => unresolved_reference_node(ctx, file, value, coverage)?,
    };
    let relation = if resolved.as_ref().is_some_and(|r| r.file_kind == FileKind::NativeAddon) {
        "loads"
    } else {
        "imports"
    };
    ctx.add_static_inference_edge(
        EdgeInput {
            source: &source,
            target: &target,
            file,
            range: &value.location,
            coverage,
            properties: json!({
                "kind": value.kind,
                "specifier": value.specifier,
                "expression": value.expression,
                "resolved_path": resolved.as_ref().map(|r| r.path.clone()),
            }),
        },
        relation,
    )?;
    Ok(0)
}

fn add_endpoint(
    ctx: &mut GraphContext<'_>,
    file: &ArtifactFile,
    asset: &NodeRef,
    value: &StaticEndpoint,
    coverage: &Value,
) -> Result<(), JsError> {
    let source = finding_source(ctx, file, asset, value.module_key.as_deref(), value.module_runtime.as_deref());
    let key = compact_string_identity_key(&value.value)?;
    let label = format!("{} endpoint", value.kind);
    let shown = if value.value.encode_utf16().count() <= label.encode_utf16().count() {
        value.value.clone()
    } else {
        label
    };
    let node = ctx.acc.add_node(
        "endpoint",
        artifact_local_identity(&file.sha256, &value.kind, &key),
        vec![ObservationInput::new(
            Some(shown),
            json!({
                "endpoint_kind": value.kind,
                "value": value.value,
                "mechanism": value.mechanism,
            }),
            ast_observation_evidence(
                &EvidenceInput::new(&file.sha256, &file.path, "discover-static-endpoint", coverage)
                    .range(&value.location),
            ),
        )],
    )?;
    ctx.add_static_inference_edge(
        EdgeInput {
            source: &source,
            target: &node,
            file,
            range: &value.location,
            coverage,
            properties: json!({ "mechanism": value.mechanism }),
        },
        if value.kind == "route" { "exposes" } else { "calls" },
    )
}

fn add_storage(
    ctx: &mut GraphContext<'_>,
    file: &ArtifactFile,
    asset: &NodeRef,
    value: &StaticStorage,
    coverage: &Value,
) -> Result<(), JsError> {
    let source = finding_source(ctx, file, asset, value.module_key.as_deref(), value.module_runtime.as_deref());
    let node = ctx.acc.add_node(
        "storage",
        artifact_local_identity(
            &file.sha256,
            &value.kind,
            value.name.as_deref().unwrap_or(&value.mechanism),
        ),
        vec![ObservationInput::new(
            Some(value.name.clone().unwrap_or_else(|| value.kind.clone())),
            json!({
                "storage_kind": value.kind,
                "name": value.name,
                "mechanism": value.mechanism,
            }),
            ast_observation_evidence(
                &EvidenceInput::new(&file.sha256, &file.path, "discover-static-storage", coverage)
                    .range(&value.location),
            ),
        )],
    )?;
    ctx.add_static_inference_edge(
        EdgeInput {
            source: &source,
            target: &node,
            file,
            range: &value.location,
            coverage,
            properties: json!({ "mechanism": value.mechanism }),
        },
        "persists_to",
    )
}

fn add_discovered_role(
    ctx: &mut GraphContext<'_>,
    file: &ArtifactFile,
    asset: &NodeRef,
    value: &RolePath,
    coverage: &Value,
) -> Result<(), JsError> {
    let resolution = ctx.resolve_by_context(&value.path, &file.path, PathContext::parse(&value.resolution_context));
    let role = ctx.create_electron_role_node(RoleNodeInput {
        kind: if value.role == "preload" { "electron-preload" } else { "electron-renderer" },
        anchor: file,
        resolution: &resolution,
        mechanism: &value.mechanism,
        range: Some(&value.location),
        coverage: Some(coverage),
    })?;
    let source = finding_source(ctx, file, asset, value.module_key.as_deref(), value.module_runtime.as_deref());
    ctx.add_static_inference_edge(
        EdgeInput {
            source: &source,
            target: &role,
            file,
            range: &value.location,
            coverage,
            properties: json!({ "mechanism": value.mechanism }),
        },
        "loads",
    )?;
    ctx.link_electron_role_to_asset(&role, file, &resolution, Some(&value.location), Some(coverage))
}

fn add_source_map_edge(
    ctx: &mut GraphContext<'_>,
    file: &ArtifactFile,
    asset: &NodeRef,
    value: &SourceMapUrl,
    coverage: &Value,
) -> Result<(), JsError> {
    let declared_url_sha256 = sha256_text(&value.declared_url);
    let resolved_path = ctx
        .resolve_by_context(&value.declared_url, &file.path, PathContext::UrlReference)
        .resolved_path;
    let resolved_file = resolved_path.as_deref().and_then(|p| ctx.files_by_path.get(p));
    let resolved_node = resolved_path.as_deref().and_then(|p| ctx.file_nodes.get(p)).cloned();
    let is_available = resolved_file.is_some_and(|f| f.kind == FileKind::SourceMap) && resolved_node.is_some();
    let identity = match (&resolved_node, is_available) {
        (Some(node), true) => node.identity.clone(),
        _ => artifact_local_identity(&file.sha256, "unresolved-source-map", &declared_url_sha256),
    };
    let limitations: Vec<String> = if is_available {
        Vec::new()
    } else {
        vec!["The declared source map was not present in the inventoried artifact.".into()]
    };
    let target = ctx.acc.add_node(
        "source-map",
        identity,
        vec![ObservationInput::new(
            Some("source map reference".into()),
            json!({
                "declared_url": value.declared_url,
                "declared_url_sha256": declared_url_sha256,
                "resolved_path": resolved_path,
                "available": is_available,
            }),
            static_inference_evidence(
                &EvidenceInput::new(&file.sha256, &file.path, "discover-source-map", coverage)
                    .range(&value.location)
                    .confidence("medium")
                    .limitations(&limitations),
            ),
        )],
    )?;
    ctx.add_static_inference_edge(
        EdgeInput {
            source: asset,
            target: &target,
            file,
            range: &value.location,
            coverage,
            properties: json!({
                "declared_url_sha256": declared_url_sha256,
                "resolved_path": resolved_path,
            }),
        },
        "maps_to",
    )
}

fn resolve_reference(ctx: &GraphContext<'_>, source_path: &str, reference: &StaticReference) -> Option<Resolved> {
    let specifier = reference.specifier.as_deref()?;
    if let Some(chunk) = resolve_bundler_chunk_reference(ctx, source_path, reference) {
        return Some(chunk);
    }
    if let Some(runtime) = &reference.module_runtime {
        if let Some(module) = ctx.module_nodes.get(&module_lookup_key(source_path, runtime, specifier)) {
            let file = ctx.files_by_path.get(source_path)?;
            return Some(Resolved {
                path: format!("{source_path}#module:{specifier}"),
                file_kind: file.kind,
                node: module.clone(),
            });
        }
    }
    // Worker scripts are URLs relative to the script, not module specifiers.
    let path = if reference.kind == "worker" || reference.kind == "service-worker" {
        ctx.resolve_by_context(specifier, source_path, PathContext::UrlReference)
            .resolved_path
    } else {
        let module_kind = match reference.kind.as_str() {
            "require" => Some(ModuleKind::Require),
            "static-import" | "dynamic-import" => Some(ModuleKind::Import),
            _ => None,
        };
        ctx.resolve_artifact_path(specifier, source_path, module_kind)
    }?;
    let file = ctx.files_by_path.get(&path)?;
    let node = ctx.file_nodes.get(&path)?.clone();
    Some(Resolved { path, file_kind: file.kind, node })
}

fn resolve_bundler_chunk_reference(
    ctx: &GraphContext<'_>,
    source_path: &str,
    reference: &StaticReference,
) -> Option<Resolved> {
    let key = reference.specifier.as_deref()?.strip_prefix("chunk:")?;
    let file = ctx.files_by_path.get(source_path)?;
    let analyzed = ctx.analysis.files.iter().find(|a| a.file.path == source_path)?;
    let registrations = analyzed.javascript.as_ref()?.bundler_registrations.iter().filter(|registration| {
        match &reference.module_runtime {
            None => reference.module_key.is_none(),
            Some(runtime) => {
                &registration.runtime == runtime
                    && registration
                        .modules
                        .iter()
                        .any(|m| Some(&m.module_key) == reference.module_key.as_ref())
            }
        }
    });
    let mut unique: Vec<NodeRef> = Vec::new();
    for registration in registrations {
        if let Some(node) = ctx
            .chunk_nodes
            .get(&chunk_lookup_key(source_path, &registration.runtime, key))
        {
            if !unique.iter().any(|existing| existing.node_id == node.node_id) {
                unique.push(node.clone());
            }
        }
    }
    if unique.len() != 1 {
        return None;
    }
    Some(Resolved {
        path: format!("{source_path}#chunk:{key}"),
        file_kind: file.kind,
        node: unique.remove(0),
    })
}

fn unresolved_reference_node(
    ctx: &mut GraphContext<'_>,
    file: &ArtifactFile,
    reference: &StaticReference,
    coverage: &Value,
) -> Result<NodeRef, JsError> {
    ctx.acc.add_node(
        "javascript-module",
        artifact_local_identity(
            &file.sha256,
            "unresolved-reference",
            &format!(
                "{}:{}",
                reference.kind,
                reference.specifier.as_deref().or(reference.expression.as_deref()).unwrap_or_default()
            ),
        ),
        vec![ObservationInput::new(
            reference.specifier.clone(),
            json!({
                "reference_kind": reference.kind,
                "specifier": reference.specifier,
                "expression": reference.expression,
                "resolution": "unresolved",
            }),
            static_inference_evidence(
                &EvidenceInput::new(&file.sha256, &file.path, "resolve-static-reference", coverage)
                    .range(&reference.location)
                    .confidence("low")
                    .limitations(&["The static reference could not be resolved within the inventoried artifact.".to_string()]),
            ),
        )],
    )
}
