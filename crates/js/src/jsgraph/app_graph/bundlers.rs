//! Webpack/Rspack/esbuild registrations as chunk and module nodes (REA
//! `JavaScriptArtifactGraphBundlers.ts`).

use serde_json::{json, Value};

use crate::error::JsError;
use crate::jsgraph::static_types::{BundlerRegistration, StaticAnalysis};
use crate::jsgraph::util::composite_key;

use super::context::{
    chunk_lookup_key, javascript_analysis_coverage, module_lookup_key, self_reference_omissions,
    EdgeInput, GraphContext,
};
use super::domain::{
    artifact_local_identity, ast_observation_evidence, static_inference_evidence, EvidenceInput, NodeRef,
    ObservationInput,
};
use super::model::ArtifactFile;

/// Project Webpack/Rspack AST literals and disclose unrepresentable relationships.
pub fn add_bundler_nodes(ctx: &mut GraphContext<'_>) -> Result<Vec<String>, JsError> {
    let analysis = ctx.analysis;
    let mut self_async_chunks = 0u64;
    for analyzed in &analysis.files {
        let file = &analyzed.file;
        let (Some(javascript), Some(asset)) = (analyzed.javascript.as_ref(), ctx.asset_nodes.get(&file.path).cloned())
        else {
            continue;
        };
        let coverage = javascript_analysis_coverage(javascript);
        let mut records: Vec<(NodeRef, &BundlerRegistration)> = Vec::new();
        for registration in &javascript.bundler_registrations {
            let chunk = create_chunk_node(ctx, file, registration, &coverage, javascript)?;
            ctx.add_ast_contains_edge(EdgeInput {
                source: &asset,
                target: &chunk,
                file,
                range: &registration.location,
                coverage: &coverage,
                properties: json!({ "bundler": registration.bundler }),
            })?;
            for key in &registration.chunk_keys {
                ctx.chunk_nodes
                    .insert(chunk_lookup_key(&file.path, &registration.runtime, key), chunk.clone());
            }
            records.push((chunk.clone(), registration));
            add_module_nodes(ctx, file, registration, &chunk, &coverage, javascript)?;
        }
        for (chunk, registration) in records {
            self_async_chunks += add_runtime_edges(ctx, file, registration, &chunk, &coverage)?;
        }
    }
    Ok(self_reference_omissions(
        self_async_chunks,
        ("bundler async-chunk reference", "bundler async-chunk references"),
        "the requesting chunk",
    ))
}

fn create_chunk_node(
    ctx: &mut GraphContext<'_>,
    file: &ArtifactFile,
    registration: &BundlerRegistration,
    coverage: &Value,
    javascript: &StaticAnalysis,
) -> Result<NodeRef, JsError> {
    let chunk_key = format!("{}:{}", registration.runtime, registration.chunk_keys.join(","));
    ctx.acc.add_node(
        "javascript-chunk",
        artifact_local_identity(
            &file.sha256,
            "bundler-chunk",
            &composite_key(&[json!(registration.runtime), json!(registration.chunk_keys)]),
        ),
        vec![ObservationInput::new(
            Some(chunk_key),
            json!({
                "path": file.path,
                "bundler": registration.bundler,
                "runtime": registration.runtime,
                "chunk_keys": registration.chunk_keys,
                "unknown_chunk_keys": registration.unknown_chunk_keys,
                "runtime_require_name": registration.runtime_require_name,
                "runtime_module_cache_status": registration.runtime_module_cache_status,
                "entry_module_keys": registration.entry_module_keys,
                "unknown_entry_module_keys": registration.unknown_entry_module_keys,
                "async_chunk_keys": registration.async_chunk_keys,
                "unknown_async_chunk_keys": registration.unknown_async_chunk_keys,
                "module_count": registration.modules.len(),
            }),
            ast_observation_evidence(
                &EvidenceInput::new(&file.sha256, &file.path, "extract-bundler-registration", coverage)
                    .range(&registration.location)
                    .limitations(&javascript.limitations),
            ),
        )],
    )
}

fn add_module_nodes(
    ctx: &mut GraphContext<'_>,
    file: &ArtifactFile,
    registration: &BundlerRegistration,
    chunk: &NodeRef,
    coverage: &Value,
    javascript: &StaticAnalysis,
) -> Result<(), JsError> {
    for module in &registration.modules {
        let node = ctx.acc.add_node(
            "javascript-module",
            artifact_local_identity(&file.sha256, &format!("{}:module", registration.runtime), &module.module_key),
            vec![ObservationInput::new(
                Some(module.module_key.clone()),
                json!({
                    "path": file.path,
                    "bundler": registration.bundler,
                    "runtime": registration.runtime,
                    "chunk_keys": registration.chunk_keys,
                    "module_key": module.module_key,
                    "factory_require_name": module.factory_require_name,
                    "runtime_entry": registration.entry_module_keys.contains(&module.module_key),
                    "source_sha256": module.source_sha256,
                    "structural_fingerprint_sha256": module.structural_fingerprint_sha256,
                    "structural_fingerprint_algorithm": module.structural_fingerprint_algorithm,
                    "exports": module.exports,
                }),
                ast_observation_evidence(
                    &EvidenceInput::new(&file.sha256, &file.path, "extract-bundler-module", coverage)
                        .range(&module.location)
                        .limitations(&javascript.limitations),
                ),
            )],
        )?;
        ctx.module_nodes.insert(
            module_lookup_key(&file.path, &registration.runtime, &module.module_key),
            node.clone(),
        );
        ctx.add_ast_contains_edge(EdgeInput {
            source: chunk,
            target: &node,
            file,
            range: &module.location,
            coverage,
            properties: json!({
                "bundler": registration.bundler,
                "runtime": registration.runtime,
                "chunk_keys": registration.chunk_keys,
                "module_key": module.module_key,
            }),
        })?;
    }
    Ok(())
}

fn add_runtime_edges(
    ctx: &mut GraphContext<'_>,
    file: &ArtifactFile,
    registration: &BundlerRegistration,
    chunk: &NodeRef,
    coverage: &Value,
) -> Result<u64, JsError> {
    let mut self_async_chunks = 0u64;
    for module_key in &registration.entry_module_keys {
        let resolved = ctx
            .module_nodes
            .get(&module_lookup_key(&file.path, &registration.runtime, module_key))
            .cloned();
        let target = match &resolved {
            Some(node) => node.clone(),
            None => unresolved_module_node(ctx, file, registration, coverage, module_key)?,
        };
        let confidence = if resolved.is_none() { "low" } else { "high" };
        ctx.acc.add_edge(
            &chunk.node_id,
            &target.node_id,
            "loads",
            json!({
                "kind": "bundler-entry-module",
                "bundler": registration.bundler,
                "runtime": registration.runtime,
                "module_key": module_key,
                "resolution_status": if resolved.is_none() { "not-found" } else { "resolved" },
            }),
            static_inference_evidence(
                &EvidenceInput::new(&file.sha256, &file.path, "resolve-bundler-entry-module", coverage)
                    .range(&registration.location)
                    .confidence(confidence),
            ),
        )?;
    }
    for chunk_key in &registration.async_chunk_keys {
        let lookup = chunk_lookup_key(&file.path, &registration.runtime, chunk_key);
        let resolved = ctx.chunk_nodes.get(&lookup).cloned();
        if resolved.as_ref().is_some_and(|node| node.node_id == chunk.node_id) {
            self_async_chunks += 1;
            continue;
        }
        let target = match &resolved {
            Some(node) => node.clone(),
            None => unresolved_chunk_node(ctx, file, registration, coverage, chunk_key)?,
        };
        let confidence = if resolved.is_none() { "low" } else { "high" };
        ctx.acc.add_edge(
            &chunk.node_id,
            &target.node_id,
            "imports",
            json!({
                "kind": "bundler-async-chunk",
                "bundler": registration.bundler,
                "runtime": registration.runtime,
                "chunk_key": chunk_key,
                "resolution_status": if resolved.is_none() { "not-found" } else { "resolved" },
            }),
            static_inference_evidence(
                &EvidenceInput::new(&file.sha256, &file.path, "resolve-bundler-async-chunk", coverage)
                    .range(&registration.location)
                    .confidence(confidence),
            ),
        )?;
    }
    Ok(self_async_chunks)
}

fn unresolved_module_node(
    ctx: &mut GraphContext<'_>,
    file: &ArtifactFile,
    registration: &BundlerRegistration,
    coverage: &Value,
    module_key: &str,
) -> Result<NodeRef, JsError> {
    ctx.acc.add_node(
        "javascript-module",
        artifact_local_identity(
            &file.sha256,
            &format!("{}:unresolved-entry-module", registration.runtime),
            module_key,
        ),
        vec![ObservationInput::new(
            Some(module_key.to_string()),
            json!({
                "semantic_role": "bundler-module-reference",
                "bundler": registration.bundler,
                "runtime": registration.runtime,
                "module_key": module_key,
                "resolution_status": "not-found",
            }),
            static_inference_evidence(
                &EvidenceInput::new(
                    &file.sha256,
                    &file.path,
                    "retain-unresolved-bundler-entry-module",
                    coverage,
                )
                .range(&registration.location)
                .confidence("low"),
            ),
        )],
    )
}

fn unresolved_chunk_node(
    ctx: &mut GraphContext<'_>,
    file: &ArtifactFile,
    registration: &BundlerRegistration,
    coverage: &Value,
    chunk_key: &str,
) -> Result<NodeRef, JsError> {
    ctx.acc.add_node(
        "javascript-chunk",
        artifact_local_identity(
            &file.sha256,
            &format!("{}:unresolved-async-chunk", registration.runtime),
            chunk_key,
        ),
        vec![ObservationInput::new(
            Some(chunk_key.to_string()),
            json!({
                "semantic_role": "bundler-chunk-reference",
                "bundler": registration.bundler,
                "runtime": registration.runtime,
                "chunk_key": chunk_key,
                "resolution_status": "not-found",
            }),
            static_inference_evidence(
                &EvidenceInput::new(
                    &file.sha256,
                    &file.path,
                    "retain-unresolved-bundler-async-chunk",
                    coverage,
                )
                .range(&registration.location)
                .confidence("low"),
            ),
        )],
    )
}
