//! Mutable graph-construction state and shared edge/node helpers (REA
//! `JavaScriptArtifactGraphContext.ts`).

use std::collections::HashMap;

use serde_json::{json, Value};

use crate::error::JsError;
use crate::jsgraph::ast::SourceRange;
use crate::jsgraph::static_types::StaticAnalysis;
use crate::jsgraph::util::composite_key;
use crate::types::ArtifactInventoryResult;

use super::domain::{
    artifact_local_identity, artifact_observation_evidence, ast_observation_evidence,
    complete_coverage, partial_coverage, static_inference_evidence, unavailable_ast_evidence,
    Accumulator, EvidenceInput, NodeRef, ObservationInput,
};
use super::model::{ArtifactAnalysis, ArtifactFile, FileKind, FileSet};
use super::path_resolution::{
    resolve_artifact_path_by_context, Files, ModuleKind, PathContext, Resolution, ResolveInput,
};

/// Mutable graph-construction state scoped to one reconstruction.
pub struct GraphContext<'a> {
    pub acc: Accumulator,
    pub snapshot: &'a ArtifactInventoryResult,
    pub file_set: &'a FileSet,
    pub analysis: &'a ArtifactAnalysis,
    pub root: NodeRef,
    pub files_by_path: Files<'a>,
    pub file_nodes: HashMap<String, NodeRef>,
    pub asset_nodes: HashMap<String, NodeRef>,
    pub source_module_nodes: HashMap<String, NodeRef>,
    pub chunk_nodes: HashMap<String, NodeRef>,
    pub module_nodes: HashMap<String, NodeRef>,
    pub container_nodes: HashMap<String, NodeRef>,
}

/// Coverage for one bounded JavaScript AST analysis.
pub fn javascript_analysis_coverage(analysis: &StaticAnalysis) -> Value {
    if analysis.parse_status == "complete" {
        complete_coverage()
    } else {
        partial_coverage(Vec::new(), None)
    }
}

/// Select the graph node kind for one inventoried relevant file.
pub fn artifact_file_node_kind(kind: FileKind) -> &'static str {
    match kind {
        FileKind::Javascript => "javascript-asset",
        FileKind::SourceMap => "source-map",
        FileKind::NativeAddon => "native-addon",
        _ => "artifact",
    }
}

/// Deterministic key for one recovered module inside a bundle asset.
pub fn module_lookup_key(path: &str, runtime: &str, module_key: &str) -> String {
    composite_key(&[json!(path), json!(runtime), json!(module_key)])
}

/// Deterministic key for one recovered bundler chunk inside a bundle asset.
pub fn chunk_lookup_key(path: &str, runtime: &str, chunk_key: &str) -> String {
    composite_key(&[json!(path), json!(runtime), json!(chunk_key)])
}

/// Disclose relationships omitted because they resolved to their own source.
pub fn self_reference_omissions(count: u64, noun: (&str, &str), owner: &str) -> Vec<String> {
    if count == 0 {
        return Vec::new();
    }
    let (word, verb) = if count == 1 { (noun.0, "was") } else { (noun.1, "were") };
    vec![format!(
        "{count} {word} resolved back to {owner} itself and {verb} omitted; application graph edges cannot be self-referential."
    )]
}

/// Edge values shared by AST and inference edges.
pub struct EdgeInput<'a> {
    pub source: &'a NodeRef,
    pub target: &'a NodeRef,
    pub file: &'a ArtifactFile,
    pub range: &'a SourceRange,
    pub coverage: &'a Value,
    pub properties: Value,
}

/// Electron role identity and static discovery evidence.
pub struct RoleNodeInput<'a> {
    pub kind: &'static str,
    pub anchor: &'a ArtifactFile,
    pub resolution: &'a Resolution,
    pub mechanism: &'a str,
    pub range: Option<&'a SourceRange>,
    pub coverage: Option<&'a Value>,
}

impl<'a> GraphContext<'a> {
    /// Add a direct artifact-containment edge.
    pub fn add_artifact_contains_edge(
        &mut self,
        source: &NodeRef,
        target: &NodeRef,
        file: &ArtifactFile,
        operation: &str,
    ) -> Result<(), JsError> {
        let sha = if operation == "inventory-entry" { &file.container_sha256 } else { &file.sha256 };
        let coverage = complete_coverage();
        self.acc.add_edge(
            &source.node_id,
            &target.node_id,
            "contains",
            json!({ "path": file.path }),
            artifact_observation_evidence(&EvidenceInput::new(sha, &file.path, operation, &coverage)),
        )
    }

    /// Add an exact AST containment edge.
    pub fn add_ast_contains_edge(&mut self, input: EdgeInput<'_>) -> Result<(), JsError> {
        self.acc.add_edge(
            &input.source.node_id,
            &input.target.node_id,
            "contains",
            input.properties,
            ast_observation_evidence(
                &EvidenceInput::new(&input.file.sha256, &input.file.path, "map-bundler-structure", input.coverage)
                    .range(input.range),
            ),
        )
    }

    /// Add an explicitly inferred static relationship edge.
    pub fn add_static_inference_edge(&mut self, input: EdgeInput<'_>, relation: &str) -> Result<(), JsError> {
        self.acc.add_edge(
            &input.source.node_id,
            &input.target.node_id,
            relation,
            input.properties,
            static_inference_evidence(
                &EvidenceInput::new(&input.file.sha256, &input.file.path, "map-static-relationship", input.coverage)
                    .range(input.range),
            ),
        )
    }

    /// Preserve a static parse or approval gap as an explicit unknown scope.
    pub fn add_unavailable_static_parse_scope(
        &mut self,
        file: &ArtifactFile,
        asset: &NodeRef,
        operation: &str,
        limitation: &str,
    ) -> Result<(), JsError> {
        let coverage = partial_coverage(Vec::new(), None);
        let node = self.acc.add_node(
            "unknown",
            artifact_local_identity(
                &file.sha256,
                "static-parse-scope",
                &format!("{operation}:{}", file.path),
            ),
            vec![ObservationInput::new(
                Some(format!("{} parse scope", file.path)),
                json!({ "path": file.path, "operation": operation, "limitation": limitation }),
                unavailable_ast_evidence(
                    &EvidenceInput::new(&file.sha256, &file.path, operation, &coverage),
                    limitation,
                ),
            )],
        )?;
        let complete = complete_coverage();
        self.acc.add_edge(
            &asset.node_id,
            &node.node_id,
            "contains",
            json!({ "scope": "unavailable-static-analysis" }),
            artifact_observation_evidence(&EvidenceInput::new(
                &file.sha256,
                &file.path,
                "associate-unavailable-parse-scope",
                &complete,
            )),
        )
    }

    /// Create or merge an Electron role inferred from static syntax or metadata.
    pub fn create_electron_role_node(&mut self, input: RoleNodeInput<'_>) -> Result<NodeRef, JsError> {
        let resolution = input.resolution;
        let resolved_or_declared = resolution
            .resolved_path
            .clone()
            .unwrap_or_else(|| resolution.declared_path.clone());
        let default_coverage = complete_coverage();
        let coverage = input.coverage.unwrap_or(&default_coverage);
        let mut evidence_input = EvidenceInput::new(
            &input.anchor.sha256,
            &input.anchor.path,
            "discover-electron-entrypoint",
            coverage,
        )
        .limitations(&resolution.limitations);
        if let Some(range) = input.range {
            evidence_input = evidence_input.range(range);
        }
        self.acc.add_node(
            input.kind,
            artifact_local_identity(
                &input.anchor.sha256,
                "electron-role",
                &format!(
                    "{}:{}:{}",
                    input.kind,
                    resolution.context.as_str(),
                    resolved_or_declared
                ),
            ),
            vec![ObservationInput::new(
                Some(resolved_or_declared.clone()),
                json!({
                    "declared_path": resolution.declared_path,
                    "resolution_context": resolution.context.as_str(),
                    "resolved_path": resolution.resolved_path,
                    "resolution_status": resolution.status.as_str(),
                    "limitations": resolution.limitations,
                    "mechanism": input.mechanism,
                }),
                static_inference_evidence(&evidence_input),
            )],
        )
    }

    /// Resolve an Electron role to an inventoried asset when available.
    pub fn link_electron_role_to_asset(
        &mut self,
        role: &NodeRef,
        anchor: &ArtifactFile,
        resolution: &Resolution,
        range: Option<&SourceRange>,
        coverage: Option<&Value>,
    ) -> Result<(), JsError> {
        let Some(path) = &resolution.resolved_path else {
            return Ok(());
        };
        let asset = self
            .asset_nodes
            .get(path)
            .or_else(|| self.file_nodes.get(path))
            .cloned();
        let Some(asset) = asset else {
            return Ok(());
        };
        let default_coverage = complete_coverage();
        let coverage = coverage.unwrap_or(&default_coverage);
        let mut evidence_input = EvidenceInput::new(
            &anchor.sha256,
            &anchor.path,
            "resolve-electron-entrypoint",
            coverage,
        )
        .limitations(&resolution.limitations);
        if let Some(range) = range {
            evidence_input = evidence_input.range(range);
        }
        let evidence = static_inference_evidence(&evidence_input);
        self.acc.add_edge(
            &role.node_id,
            &asset.node_id,
            "maps_to",
            json!({
                "declared_path": resolution.declared_path,
                "resolution_context": resolution.context.as_str(),
                "resolved_path": path,
                "resolution_status": resolution.status.as_str(),
            }),
            evidence,
        )
    }

    /// Resolve a relative static specifier without escaping the artifact root.
    pub fn resolve_artifact_path(
        &self,
        specifier: &str,
        source_path: &str,
        module_kind: Option<ModuleKind>,
    ) -> Option<String> {
        let mut input = ResolveInput::new(specifier, source_path, PathContext::ModuleSpecifier, &self.files_by_path);
        input.module_kind = module_kind;
        resolve_artifact_path_by_context(&input).resolved_path
    }

    /// Resolve with an explicit context.
    pub fn resolve_by_context(
        &self,
        declared: &str,
        source_path: &str,
        context: PathContext,
    ) -> Resolution {
        let input = ResolveInput::new(declared, source_path, context, &self.files_by_path);
        resolve_artifact_path_by_context(&input)
    }

    /// Locate the recovered module that owns a static finding.
    pub fn source_node_for(
        &self,
        path: &str,
        module_key: Option<&str>,
        runtime: Option<&str>,
    ) -> Option<NodeRef> {
        match module_key {
            None => self.source_module_nodes.get(path).cloned(),
            Some(key) => runtime.and_then(|runtime| {
                self.module_nodes
                    .get(&module_lookup_key(path, runtime, key))
                    .cloned()
            }),
        }
    }
}
