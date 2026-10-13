//! Source-module nodes and CommonJS/ESM relationships across files (REA
//! `JavaScriptModuleRelationships.ts` and `javascriptExportReturnShapeProjection.ts`).

use std::collections::HashSet;

use serde_json::{json, Map, Value};

use crate::error::JsError;
use crate::jsgraph::ir::{
    ModuleOrigin, ResourceLimit, SemanticCallable, SemanticModuleLink, SemanticProperty,
    SemanticValue, SlotPresence,
};
use crate::jsgraph::util::{compare_code_points, composite_key};

use super::context::{EdgeInput, GraphContext};
use super::domain::{
    artifact_local_identity, ast_observation_evidence, complete_coverage, partial_coverage,
    static_inference_evidence, truncated_coverage, EvidenceInput, NodeRef, ObservationInput,
};
use super::model::{ArtifactFile, FileKind, ModuleSemanticIr};
use super::path_resolution::{ModuleKind, PathContext, ResolveInput, Status};
use super::posix::extname;

/// Relationship compositions the application graph cannot represent, for disclosure.
#[derive(Default, Debug)]
pub struct RelationshipOmissions {
    /// Import specifiers that resolved back to the importing module itself.
    pub self_imports: u64,
}

// ---- resource limit presentation (javascriptSemanticCoverage / ResourceLimits) ------------

pub fn resource_limit_reason(limit: ResourceLimit) -> &'static str {
    match limit {
        ResourceLimit::PrimitiveCandidates => {
            "Primitive candidate budget exceeded (maximum 256 alternatives)."
        }
        ResourceLimit::PrimitiveBytes => {
            "Primitive string-byte budget exceeded (maximum 1048576 estimated JSON bytes)."
        }
        ResourceLimit::ExpressionDepth => {
            "Semantic expression depth budget exceeded (maximum 256 nested expressions)."
        }
    }
}

/// `semanticResourceLimitCoverage`: caller-visible application coverage limits.
pub fn resource_limit_coverage(limits: &[ResourceLimit]) -> Vec<Value> {
    limits
        .iter()
        .map(|limit| {
            let (name, value, unit) = match limit {
                ResourceLimit::PrimitiveCandidates => ("javascript_semantic_primitive_candidates", 256, "items"),
                ResourceLimit::PrimitiveBytes => ("javascript_semantic_primitive_bytes", 1_048_576, "bytes"),
                ResourceLimit::ExpressionDepth => ("javascript_semantic_expression_depth", 256, "depth"),
            };
            json!({ "name": name, "value": value, "unit": unit })
        })
        .collect()
}

pub fn semantic_resource_limits(semantic: &ModuleSemanticIr) -> Vec<ResourceLimit> {
    semantic
        .coverage
        .as_ref()
        .and_then(|c| c.resource_limits.clone())
        .unwrap_or_default()
}

/// Graph coverage of one file's semantic recovery (`semanticCoverage` in the REA module).
pub fn semantic_coverage(semantic: &ModuleSemanticIr) -> Value {
    let limits = semantic_resource_limits(semantic);
    let coverage = semantic.coverage.as_ref();
    let complete = coverage.is_some_and(|c| c.status == "complete");
    if complete && limits.is_empty() {
        return complete_coverage();
    }
    partial_coverage(
        resource_limit_coverage(&limits),
        coverage.and_then(|c| c.omitted_count),
    )
}

// ---- source modules ------------------------------------------------------------------------

fn module_format(path: &str, ir: &ModuleSemanticIr) -> &'static str {
    let extension = extname(path).to_lowercase();
    if extension == ".mjs" {
        return "esm";
    }
    if extension == ".cjs" {
        return "commonjs";
    }
    let esm = ir
        .module_links
        .iter()
        .any(|l| matches!(l.kind.as_str(), "import" | "export" | "re-export"));
    let common_js = ir
        .module_links
        .iter()
        .any(|l| matches!(l.kind.as_str(), "require" | "commonjs-export"));
    match (esm, common_js) {
        (true, true) => "mixed",
        (true, false) => "esm",
        (false, true) => "commonjs",
        (false, false) => "unknown",
    }
}

/// Create one path-scoped source-module identity for every analyzed source file.
pub fn add_source_modules(ctx: &mut GraphContext<'_>) -> Result<(), JsError> {
    let analysis = ctx.analysis;
    for analyzed in &analysis.files {
        let file = &analyzed.file;
        let Some(asset) = ctx.asset_nodes.get(&file.path).cloned() else {
            continue;
        };
        let Some(semantic) = &analyzed.semantic else {
            continue;
        };
        let Some(program) = semantic.scopes.iter().find(|s| s.kind == "program") else {
            continue;
        };
        let mut exports: Vec<&str> = semantic
            .module_links
            .iter()
            .filter_map(|link| link.exported_name.as_deref())
            .collect();
        exports.sort_by(|a, b| compare_code_points(a, b));
        let mut retained: Vec<&str> = Vec::new();
        let mut seen: HashSet<&str> = HashSet::new();
        for name in &exports {
            if seen.insert(name) {
                retained.push(name);
            }
        }
        let coverage = semantic_coverage(semantic);
        let import_relationships = semantic
            .module_links
            .iter()
            .filter(|l| l.kind == "import" || l.kind == "require")
            .count();
        let source = ctx.acc.add_node(
            "javascript-module",
            artifact_local_identity(
                &file.sha256,
                "source-module",
                &format!("{}:{}", file.container_sha256, file.path),
            ),
            vec![ObservationInput::new(
                Some(file.path.clone()),
                json!({
                    "semantic_role": "source-module",
                    "path": file.path,
                    "container_sha256": file.container_sha256,
                    "logical_module_key": file.path,
                    "module_format": module_format(&file.path, semantic),
                    "import_relationships": import_relationships,
                    "export_relationships": exports.len(),
                    "export_names": retained,
                    "omitted_export_names": 0,
                }),
                ast_observation_evidence(
                    &EvidenceInput::new(&file.sha256, &file.path, "recover-source-module", &coverage)
                        .range(&program.location)
                        .limitations(&semantic.limitations),
                ),
            )],
        )?;
        ctx.source_module_nodes.insert(file.path.clone(), source.clone());
        ctx.add_ast_contains_edge(EdgeInput {
            source: &asset,
            target: &source,
            file,
            range: &program.location,
            coverage: &coverage,
            properties: json!({ "logical_module_key": file.path }),
        })?;
    }
    Ok(())
}

// ---- relationships -------------------------------------------------------------------------

struct Resolved {
    node: NodeRef,
    path: Option<String>,
    file_kind: Option<FileKind>,
    json_status: Option<&'static str>,
    status: Status,
    limitations: Vec<String>,
}

fn is_export_link(link: &SemanticModuleLink) -> bool {
    matches!(link.kind.as_str(), "export" | "re-export" | "commonjs-export")
}

/// Compose bounded CommonJS and ESM binding relationships across artifact files.
pub fn add_module_relationships(ctx: &mut GraphContext<'_>) -> Result<RelationshipOmissions, JsError> {
    let analysis = ctx.analysis;
    let mut omissions = RelationshipOmissions::default();
    for analyzed in &analysis.files {
        let file = &analyzed.file;
        let (Some(semantic), Some(source)) = (&analyzed.semantic, ctx.source_module_nodes.get(&file.path).cloned())
        else {
            continue;
        };
        for link in &semantic.module_links {
            if is_export_link(link) {
                add_export_relationship(ctx, file, semantic, &source, link, &mut omissions)?;
            } else if let Some(specifier) = &link.specifier {
                let origin = ModuleOrigin {
                    specifier: specifier.clone(),
                    imported_path: link.imported_name.iter().cloned().collect(),
                };
                add_import_relationship(ctx, file, semantic, &source, link, &origin, &mut omissions)?;
            }
        }
    }
    Ok(omissions)
}

fn add_export_relationship(
    ctx: &mut GraphContext<'_>,
    file: &ArtifactFile,
    semantic: &ModuleSemanticIr,
    source: &NodeRef,
    link: &SemanticModuleLink,
    omissions: &mut RelationshipOmissions,
) -> Result<(), JsError> {
    let Some(exported_name) = &link.exported_name else {
        return Ok(());
    };
    let base_coverage = semantic_coverage(semantic);
    let return_shapes = project_export_return_shapes(semantic, link, &file.path, &base_coverage);
    let mut observations = vec![ObservationInput::new(
        Some(format!("{}:{}", file.path, exported_name)),
        json!({
            "semantic_role": "export-binding",
            "module_path": file.path,
            "relationship_kind": link.kind,
            "exported_name": exported_name,
            "local_name": link.local_name,
            "imported_name": link.imported_name,
            "declared_specifier": link.specifier,
        }),
        ast_observation_evidence(
            &EvidenceInput::new(&file.sha256, &file.path, "recover-module-export", &base_coverage)
                .range(&link.location)
                .limitations(&semantic.limitations),
        ),
    )];
    if let Some(shapes) = &return_shapes {
        observations.push(ObservationInput::new(
            Some(format!("{}:{}:return-shapes", file.path, exported_name)),
            Value::Object(shapes.properties.clone()),
            static_inference_evidence(
                &EvidenceInput::new(&file.sha256, &file.path, "recover-export-return-shapes", &shapes.coverage)
                    .range(&shapes.range)
                    .limitations(&shapes.limitations),
            ),
        ));
    }
    let exported = ctx.acc.add_node(
        "javascript-module",
        artifact_local_identity(
            &file.sha256,
            "module-export",
            &composite_key(&[json!(file.container_sha256), json!(file.path), json!(exported_name)]),
        ),
        observations,
    )?;
    let evidence = relationship_evidence(file, semantic, link, "expose-module-export", &[], "high");
    ctx.acc.add_edge(
        &source.node_id,
        &exported.node_id,
        "exposes",
        relationship_properties(link, None, None),
        evidence,
    )?;
    if let Some(origin) = module_origin_for_export(semantic, link) {
        add_import_relationship(ctx, file, semantic, &exported, link, &origin, omissions)?;
    }
    Ok(())
}

fn add_import_relationship(
    ctx: &mut GraphContext<'_>,
    file: &ArtifactFile,
    semantic: &ModuleSemanticIr,
    source: &NodeRef,
    link: &SemanticModuleLink,
    origin: &ModuleOrigin,
    omissions: &mut RelationshipOmissions,
) -> Result<(), JsError> {
    let target = resolve_module_target(ctx, file, semantic, link, &origin.specifier)?;
    // A specifier that resolves back to the importing module itself cannot become an edge:
    // the application graph forbids self-referential edges.
    if target.node.node_id == source.node_id {
        omissions.self_imports += 1;
        return Ok(());
    }
    let confidence = match target.status {
        Status::Resolved => "high",
        Status::External => "medium",
        _ => "low",
    };
    let evidence = relationship_evidence(
        file,
        semantic,
        link,
        "resolve-semantic-module-relationship",
        &target.limitations,
        confidence,
    );
    ctx.acc.add_edge(
        &source.node_id,
        &target.node.node_id,
        "imports",
        relationship_properties(link, Some(&target), Some(origin)),
        evidence,
    )
}

fn resolve_module_target(
    ctx: &mut GraphContext<'_>,
    file: &ArtifactFile,
    semantic: &ModuleSemanticIr,
    link: &SemanticModuleLink,
    specifier: &str,
) -> Result<Resolved, JsError> {
    let mut input = ResolveInput::new(specifier, &file.path, PathContext::ModuleSpecifier, &ctx.files_by_path);
    input.module_kind = Some(if link.kind == "require" || link.kind == "commonjs-export" {
        ModuleKind::Require
    } else {
        ModuleKind::Import
    });
    let resolution = super::path_resolution::resolve_artifact_path_by_context(&input);
    if resolution.status != Status::Resolved {
        let node = unresolved_module_node(ctx, file, semantic, link, specifier, resolution.status)?;
        return Ok(Resolved {
            node,
            path: None,
            file_kind: None,
            json_status: None,
            status: resolution.status,
            limitations: resolution.limitations,
        });
    }
    let path = resolution.resolved_path.clone().unwrap_or_default();
    let target_file = ctx.files_by_path.get(&path);
    let node = ctx
        .source_module_nodes
        .get(&path)
        .or_else(|| ctx.file_nodes.get(&path))
        .cloned();
    let (Some(target_file), Some(node)) = (target_file, node) else {
        return Err(JsError::InvalidInput(format!(
            "Resolved artifact path {path} is absent from its graph context."
        )));
    };
    let json_status = if target_file.kind == FileKind::Json {
        Some(json_status(target_file))
    } else {
        None
    };
    Ok(Resolved {
        node,
        path: Some(path),
        file_kind: Some(target_file.kind),
        json_status,
        status: Status::Resolved,
        limitations: resolution.limitations,
    })
}

fn json_status(file: &ArtifactFile) -> &'static str {
    match &file.text {
        None => "unavailable",
        Some(text) => {
            if serde_json::from_str::<Value>(text).is_ok() {
                "included"
            } else {
                "invalid"
            }
        }
    }
}

fn unresolved_module_node(
    ctx: &mut GraphContext<'_>,
    file: &ArtifactFile,
    semantic: &ModuleSemanticIr,
    link: &SemanticModuleLink,
    specifier: &str,
    status: Status,
) -> Result<NodeRef, JsError> {
    let coverage = semantic_coverage(semantic);
    ctx.acc.add_node(
        "javascript-module",
        artifact_local_identity(
            &file.sha256,
            "unresolved-semantic-module",
            &format!("{}:{specifier}", status.as_str()),
        ),
        vec![ObservationInput::new(
            Some(specifier.to_string()),
            json!({
                "semantic_role": "module-reference",
                "declared_specifier": specifier,
                "resolution_status": status.as_str(),
            }),
            static_inference_evidence(
                &EvidenceInput::new(&file.sha256, &file.path, "retain-unresolved-semantic-module", &coverage)
                    .range(&link.location)
                    .confidence("low")
                    .limitations(&semantic.limitations),
            ),
        )],
    )
}

fn module_origin_for_export(semantic: &ModuleSemanticIr, link: &SemanticModuleLink) -> Option<ModuleOrigin> {
    if let Some(specifier) = &link.specifier {
        return Some(ModuleOrigin {
            specifier: specifier.clone(),
            imported_path: link.imported_name.iter().cloned().collect(),
        });
    }
    let local_name = link.local_name.as_ref()?;
    let program = semantic.scopes.iter().find(|s| s.kind == "program");
    let binding = semantic
        .bindings
        .iter()
        .find(|b| &b.name == local_name && Some(&b.scope_id) == program.map(|p| &p.scope_id))?;
    if binding.provenance.status == "module" && binding.provenance.origins.len() == 1 {
        binding.provenance.origins.first().cloned()
    } else {
        None
    }
}

fn relationship_properties(link: &SemanticModuleLink, target: Option<&Resolved>, origin: Option<&ModuleOrigin>) -> Value {
    let imported_name = origin
        .and_then(|o| o.imported_path.last().cloned())
        .or_else(|| link.imported_name.clone());
    json!({
        "module_link_kind": link.kind,
        "specifier": origin.map(|o| o.specifier.clone()).or_else(|| link.specifier.clone()),
        "imported_name": imported_name,
        "imported_path": origin.map(|o| o.imported_path.clone()).unwrap_or_default(),
        "local_name": link.local_name,
        "exported_name": link.exported_name,
        "resolved_path": target.and_then(|t| t.path.clone()),
        "resolution_status": target.map(|t| t.status.as_str()),
        "target_file_kind": target.and_then(|t| t.file_kind).map(|k| k.as_str()),
        "target_json_status": target.and_then(|t| t.json_status),
    })
}

fn relationship_evidence(
    file: &ArtifactFile,
    semantic: &ModuleSemanticIr,
    link: &SemanticModuleLink,
    operation: &str,
    limitations: &[String],
    confidence: &str,
) -> Value {
    let coverage = semantic_coverage(semantic);
    let mut all: Vec<String> = semantic.limitations.clone();
    all.extend(
        semantic_resource_limits(semantic)
            .into_iter()
            .map(|limit| resource_limit_reason(limit).to_string()),
    );
    all.extend(limitations.iter().cloned());
    static_inference_evidence(
        &EvidenceInput::new(&file.sha256, &file.path, operation, &coverage)
            .range(&link.location)
            .confidence(confidence)
            .limitations(&all),
    )
}

// ---- export return shapes ------------------------------------------------------------------

struct ReturnShapeProjection {
    properties: Map<String, Value>,
    range: crate::jsgraph::ast::SourceRange,
    coverage: Value,
    limitations: Vec<String>,
}

/// Project one exact export/callable link into inert return-shape observations.
fn project_export_return_shapes(
    ir: &ModuleSemanticIr,
    link: &SemanticModuleLink,
    module_path: &str,
    base_coverage: &Value,
) -> Option<ReturnShapeProjection> {
    let callable_id = link.callable_id.as_ref()?;
    let exported_name = link.exported_name.as_ref()?;
    let callable = ir.callables.iter().find(|c| &c.callable_id == callable_id)?;
    let shapes = project_return_sites(callable);
    let projection_omitted: u64 = 0;
    let semantic_omitted = callable.return_coverage.omitted_count;
    let complete = base_coverage["status"] == "complete"
        && callable.return_coverage.status == "complete"
        && projection_omitted == 0;
    let limits: Vec<Value> = base_coverage["limits"].as_array().cloned().unwrap_or_default();
    let omitted = semantic_omitted.map(|n| n + projection_omitted);
    let coverage = if complete {
        base_coverage.clone()
    } else if projection_omitted > 0 {
        truncated_coverage(limits, omitted)
    } else {
        partial_coverage(limits, omitted)
    };
    let mut limitations: Vec<String> = ir.limitations.clone();
    limitations.push("Return shapes are inferred from inert syntax and do not prove runtime behavior.".into());
    if callable.return_sites.is_empty() {
        limitations
            .push("No direct return value was retained; runtime return behavior remains unknown.".into());
    }
    let mut properties = Map::new();
    properties.insert("semantic_role".into(), json!("export-return-shapes"));
    properties.insert("module_path".into(), json!(module_path));
    properties.insert("exported_name".into(), json!(exported_name));
    properties.insert("callable_id".into(), json!(callable.callable_id));
    properties.insert("callable_kind".into(), json!(callable.kind));
    properties.insert("static_return_shapes".into(), Value::Array(shapes.clone()));
    properties.insert(
        "return_shape_coverage".into(),
        json!({
            "status": callable.return_coverage.status,
            "retained_return_sites": shapes.len(),
            "omitted_return_sites": semantic_omitted,
            "omitted_fields": 0,
            "omitted_property_coverage": 0,
            "projection_complete": projection_omitted == 0,
        }),
    );
    Some(ReturnShapeProjection { properties, range: callable.location, coverage, limitations })
}

fn project_return_sites(callable: &SemanticCallable) -> Vec<Value> {
    callable
        .return_sites
        .iter()
        .map(|site| {
            let (fields, property_coverage) = flatten_semantic_return_value(&site.value);
            let status = match &site.value {
                SemanticValue::Literal { .. } => "literal",
                SemanticValue::Union { .. } => "union",
                SemanticValue::Object { .. } => "object",
                SemanticValue::Array { .. } => "array",
                SemanticValue::Unknown { .. } => "unknown",
                SemanticValue::Ambiguous { .. } => "ambiguous",
                SemanticValue::Cycle { .. } => "cycle",
            };
            json!({
                "source_range": site.location,
                "value_status": status,
                "fields": fields,
                "property_coverage": property_coverage,
            })
        })
        .collect()
}

fn pointer_segment(name: &str) -> String {
    format!("/{}", name.replace('~', "~0").replace('/', "~1"))
}

/// Flatten a semantic value to bounded JSON-pointer leaves for graph projection.
pub fn flatten_semantic_return_value(value: &SemanticValue) -> (Vec<Value>, Vec<Value>) {
    let mut fields: Vec<(String, Value)> = Vec::new();
    let mut coverage: Vec<(String, Value)> = Vec::new();
    flatten_value(value, String::new(), &mut fields, &mut coverage, SlotPresence::Present);
    fields.sort_by(|a, b| compare_code_points(&a.0, &b.0));
    coverage.sort_by(|a, b| compare_code_points(&a.0, &b.0));
    (
        fields.into_iter().map(|(_, v)| v).collect(),
        coverage.into_iter().map(|(_, v)| v).collect(),
    )
}

fn presence_text(presence: SlotPresence) -> &'static str {
    match presence {
        SlotPresence::Present => "present",
        SlotPresence::Absent => "absent",
        SlotPresence::UnknownCoverage => "unknown-coverage",
    }
}

fn value_reason(value: &SemanticValue) -> Option<&str> {
    match value {
        SemanticValue::Unknown { reason, .. }
        | SemanticValue::Ambiguous { reason, .. }
        | SemanticValue::Cycle { reason, .. } => Some(reason),
        _ => None,
    }
}

fn flatten_value(
    value: &SemanticValue,
    path: String,
    fields: &mut Vec<(String, Value)>,
    coverage: &mut Vec<(String, Value)>,
    presence: SlotPresence,
) {
    if presence != SlotPresence::Present {
        fields.push((
            path.clone(),
            json!({
                "path": path,
                "presence": presence_text(presence),
                "state": "unknown",
                "value": null,
                "reason": value_reason(value).unwrap_or("Property presence is uncertain."),
            }),
        ));
        return;
    }
    match value {
        SemanticValue::Literal { value: literal } => {
            fields.push((
                path.clone(),
                json!({ "path": path, "presence": "present", "state": "literal", "value": literal, "reason": null }),
            ));
        }
        SemanticValue::Union { values } => {
            fields.push((
                path.clone(),
                json!({ "path": path, "presence": "present", "state": "union", "value": values, "reason": null }),
            ));
        }
        SemanticValue::Unknown { reason, .. }
        | SemanticValue::Ambiguous { reason, .. }
        | SemanticValue::Cycle { reason, .. } => {
            fields.push((
                path.clone(),
                json!({ "path": path, "presence": "present", "state": "unknown", "value": null, "reason": reason }),
            ));
        }
        SemanticValue::Object { properties, unknown_properties, omitted_properties } => {
            push_container(&path, properties, *unknown_properties, *omitted_properties, fields, coverage);
        }
        SemanticValue::Array { items, unknown_items, omitted_items } => {
            push_container(&path, items, *unknown_items, *omitted_items, fields, coverage);
        }
    }
}

fn push_container(
    path: &str,
    slots: &[SemanticProperty],
    unknown: bool,
    omitted: Option<u64>,
    fields: &mut Vec<(String, Value)>,
    coverage: &mut Vec<(String, Value)>,
) {
    coverage.push((
        path.to_string(),
        if unknown {
            json!({ "path": path, "status": "partial", "omitted": omitted })
        } else {
            json!({ "path": path, "status": "complete", "omitted": 0 })
        },
    ));
    for slot in slots {
        flatten_value(
            &slot.value,
            format!("{path}{}", pointer_segment(&slot.name)),
            fields,
            coverage,
            slot.presence,
        );
    }
}
