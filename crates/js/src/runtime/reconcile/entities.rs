//! Capture-scoped runtime nodes and edges (port of REA
//! javascriptRuntimeReconciliationRuntime.ts).

use std::collections::HashMap;

use serde_json::{json, Map, Value};

use crate::application::graph_seal::{create_edge, recreate_node};
use crate::error::JsError;

use super::input::{RuntimeCapture, RuntimeLoc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityKind {
    Target,
    Frame,
    Script,
    Worker,
}

impl EntityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Target => "target",
            Self::Frame => "frame",
            Self::Script => "script",
            Self::Worker => "worker",
        }
    }

    fn section(self) -> &'static str {
        match self {
            Self::Target => "target",
            Self::Frame => "frames",
            Self::Script => "scripts",
            Self::Worker => "workers",
        }
    }
}

/// One runtime entity plus its capture-scoped graph node.
#[derive(Debug, Clone)]
pub struct RuntimeEntity {
    pub kind: EntityKind,
    pub node: Value,
    /// Index into the parsed capture list.
    pub capture: usize,
    pub runtime_key: String,
    pub location: RuntimeLoc,
    pub frame_key: Option<String>,
    pub source_sha256: Option<String>,
    pub static_kind: &'static str,
}

impl RuntimeEntity {
    pub fn node_id(&self) -> &str {
        self.node["node_id"].as_str().unwrap_or_default()
    }
}

pub struct RuntimeProjection {
    pub entities: Vec<RuntimeEntity>,
    pub nodes: Vec<Value>,
    pub edges: Vec<Value>,
    /// Target node per capture evidence id, in capture order.
    pub target_nodes: Vec<(String, Value)>,
    pub omitted_entities: u64,
}

/// Project authorized passive capture metadata into capture-scoped JAG nodes.
pub fn project_runtime_captures(captures: &[RuntimeCapture]) -> Result<RuntimeProjection, JsError> {
    let mut entities = Vec::new();
    for (index, capture) in captures.iter().enumerate() {
        entities.extend(project_capture(index, capture)?);
    }
    let nodes = entities.iter().map(|entity| entity.node.clone()).collect();
    let mut edges = Vec::new();
    for (index, capture) in captures.iter().enumerate() {
        edges.extend(runtime_edges(index, capture, &entities)?);
    }
    let target_nodes = entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Target)
        .map(|entity| (captures[entity.capture].evidence.evidence_id.clone(), entity.node.clone()))
        .collect();
    Ok(RuntimeProjection {
        entities,
        nodes,
        edges,
        target_nodes,
        omitted_entities: 0,
    })
}

struct EntityInput {
    kind: EntityKind,
    node_kind: &'static str,
    runtime_key: String,
    target_key: String,
    frame_key: Option<String>,
    script_key: Option<String>,
    location: RuntimeLoc,
    static_kind: &'static str,
    source_sha256: Option<String>,
    label: String,
    properties: Map<String, Value>,
}

fn project_capture(index: usize, capture: &RuntimeCapture) -> Result<Vec<RuntimeEntity>, JsError> {
    let inspection = &capture.inspection;
    let target = &inspection.target;
    let mut out = Vec::new();

    let mut properties = Map::new();
    properties.insert("runtime_type".into(), json!(target.target_type));
    match &target.location {
        RuntimeLoc::Unresolved(location) => {
            properties.insert("reported_url".into(), location["reported_url"].clone());
            properties.insert("location_kind".into(), json!("unresolved"));
            properties.insert("location_reason".into(), json!("unverifiable-file-location"));
        }
        other => {
            properties.insert("location".into(), json!(other.value()));
        }
    }
    properties.insert("attached".into(), json!(target.attached));
    out.push(runtime_entity(
        index,
        capture,
        EntityInput {
            kind: EntityKind::Target,
            node_kind: "target",
            runtime_key: target.target_id.clone(),
            target_key: target.target_id.clone(),
            frame_key: None,
            script_key: None,
            location: target.location.clone(),
            static_kind: "renderer",
            source_sha256: None,
            label: target.title.clone(),
            properties,
        },
    )?);

    for frame in &inspection.frames {
        let mut properties = Map::new();
        properties.insert("parent_frame_id".into(), frame.parent_frame_id.clone());
        properties.insert("location".into(), json!(frame.location.value()));
        out.push(runtime_entity(
            index,
            capture,
            EntityInput {
                kind: EntityKind::Frame,
                node_kind: "frame",
                runtime_key: frame.frame_id.clone(),
                target_key: target.target_id.clone(),
                frame_key: Some(frame.frame_id.clone()),
                script_key: None,
                location: frame.location.clone(),
                static_kind: "renderer",
                source_sha256: None,
                label: frame.location.value(),
                properties,
            },
        )?);
    }

    for script in &inspection.scripts {
        let mut properties = Map::new();
        match &script.location {
            RuntimeLoc::Unresolved(location) => {
                properties.insert("location_kind".into(), json!("unresolved"));
                properties.insert("reported_url".into(), location["reported_url"].clone());
                properties.insert("location_reason".into(), location["reason"].clone());
            }
            other => {
                properties.insert("location".into(), json!(other.value()));
            }
        }
        properties.insert("cdp_hash".into(), script.cdp_hash.clone());
        properties.insert("length".into(), script.length.clone());
        properties.insert("is_module".into(), script.is_module.clone());
        properties.insert("language".into(), script.language.clone());
        properties.insert("source_sha256".into(), json!(script.source_sha256));
        if let Some(url) = &script.source_map_url {
            properties.insert("source_map_url".into(), url.clone());
        }
        out.push(runtime_entity(
            index,
            capture,
            EntityInput {
                kind: EntityKind::Script,
                node_kind: "runtime-script-instance",
                runtime_key: script.script_key.clone(),
                target_key: target.target_id.clone(),
                frame_key: script.frame_id.clone(),
                script_key: Some(script.script_key.clone()),
                location: script.location.clone(),
                static_kind: "javascript",
                source_sha256: script.source_sha256.clone(),
                label: script.location.value(),
                properties,
            },
        )?);
    }

    for worker in &inspection.workers {
        let service_worker = worker.worker_type.contains("service");
        let mut properties = Map::new();
        properties.insert("runtime_type".into(), json!(worker.worker_type));
        properties.insert("location".into(), json!(worker.location.value()));
        properties.insert("attached".into(), json!(worker.attached));
        properties.insert("opener_target_id".into(), worker.opener_target_id.clone());
        properties.insert("parent_frame_id".into(), json!(worker.parent_frame_id));
        out.push(runtime_entity(
            index,
            capture,
            EntityInput {
                kind: EntityKind::Worker,
                node_kind: if service_worker { "service-worker" } else { "worker" },
                runtime_key: worker.target_id.clone(),
                target_key: worker.target_id.clone(),
                frame_key: worker.parent_frame_id.clone(),
                script_key: None,
                location: worker.location.clone(),
                static_kind: if service_worker { "service-worker" } else { "worker" },
                source_sha256: None,
                label: worker.location.value(),
                properties,
            },
        )?);
    }
    Ok(out)
}

fn extractor(capture: &RuntimeCapture) -> Value {
    let version = capture
        .evidence
        .provider
        .version
        .clone()
        .unwrap_or_else(|| if capture.kind == "browser" { "2".into() } else { "1".into() });
    json!({
        "name": capture.evidence.provider.id,
        "version": version,
        "operation": capture.evidence.operation,
        "executable_sha256": null,
    })
}

fn runtime_entity(index: usize, capture: &RuntimeCapture, input: EntityInput) -> Result<RuntimeEntity, JsError> {
    let section = input.kind.section();
    let artifact = match &input.source_sha256 {
        Some(sha256) => json!({ "available": true, "artifact_id": format!("art_{sha256}"), "sha256": sha256 }),
        None if section == "scripts" => json!({
            "available": false,
            "reason": "not-observed",
            "detail": "Script source bytes were not included in this passive capture.",
        }),
        None => json!({
            "available": false,
            "reason": "not-applicable",
            "detail": "This runtime entity has no standalone artifact bytes.",
        }),
    };
    let mut limitations = vec![json!("The entity was observed only within one bounded passive CDP capture.")];
    if !section_complete(capture, section) {
        limitations.push(json!(format!("The runtime {section} inventory was incomplete within this capture.")));
    }
    let evidence = json!({
        "authority": "passive-cdp-runtime",
        "state": "observed",
        "confidence": "exact",
        "artifact": artifact,
        "location": {
            "available": true,
            "value": {
                "kind": "runtime",
                "capture_sha256": capture.capture_sha256,
                "target_key": input.target_key,
                "frame_key": input.frame_key,
                "script_key": input.script_key,
            },
        },
        "extractor": extractor(capture),
        "coverage": section_coverage(capture, section),
        "limitations": limitations,
        "evidence_ids": [capture.evidence.evidence_id],
    });
    let label = if input.label.is_empty() { Value::Null } else { json!(input.label) };
    let node = recreate_node(&json!({
        "kind": input.node_kind,
        "identity": {
            "strategy": "runtime-instance",
            "stability": "capture-only",
            "capture_sha256": capture.capture_sha256,
            "runtime_key": input.runtime_key,
        },
        "observations": [{
            "label": label,
            "source_map_reference": null,
            "properties": input.properties,
            "evidence": evidence,
        }],
    }))?;
    Ok(RuntimeEntity {
        kind: input.kind,
        node,
        capture: index,
        runtime_key: input.runtime_key,
        location: input.location,
        frame_key: input.frame_key,
        source_sha256: input.source_sha256,
        static_kind: input.static_kind,
    })
}

fn runtime_edges(index: usize, capture: &RuntimeCapture, entities: &[RuntimeEntity]) -> Result<Vec<Value>, JsError> {
    let local: Vec<&RuntimeEntity> = entities.iter().filter(|entity| entity.capture == index).collect();
    let Some(target) = local.iter().find(|entity| entity.kind == EntityKind::Target) else {
        return Ok(vec![]);
    };
    let mut frames: HashMap<&str, &RuntimeEntity> = HashMap::new();
    for entity in local.iter().filter(|entity| entity.kind == EntityKind::Frame) {
        // A later frame with the same key replaces the earlier one (Map semantics).
        frames.insert(entity.runtime_key.as_str(), entity);
    }
    let mut edges = Vec::new();
    for entity in &local {
        if std::ptr::eq(*entity, *target) {
            continue;
        }
        let parent = match (&entity.kind, &entity.frame_key) {
            (EntityKind::Script | EntityKind::Worker, Some(frame_key)) => {
                frames.get(frame_key.as_str()).copied().unwrap_or(target)
            }
            _ => target,
        };
        let section = entity.kind.section();
        edges.push(create_edge(&json!({
            "source_node_id": parent.node_id(),
            "target_node_id": entity.node_id(),
            "relation": if entity.kind == EntityKind::Script { "loads" } else { "contains" },
            "properties": { "basis": "passive-cdp-observation" },
            "evidence": {
                "authority": "passive-cdp-runtime",
                "state": "observed",
                "confidence": "exact",
                "artifact": {
                    "available": false,
                    "reason": "not-applicable",
                    "detail": "The relationship is runtime metadata, not standalone bytes.",
                },
                "location": {
                    "available": true,
                    "value": {
                        "kind": "runtime",
                        "capture_sha256": capture.capture_sha256,
                        "target_key": capture.inspection.target.target_id,
                        "frame_key": entity.frame_key,
                        "script_key": if entity.kind == EntityKind::Script { json!(entity.runtime_key) } else { Value::Null },
                    },
                },
                "extractor": extractor(capture),
                "coverage": section_coverage(capture, section),
                "limitations": ["The relationship was observed only within one bounded passive CDP capture."],
                "evidence_ids": [capture.evidence.evidence_id],
            },
        }))?);
    }
    Ok(edges)
}

fn section_complete(capture: &RuntimeCapture, section: &str) -> bool {
    match section {
        "target" => true,
        "scripts" => capture.scripts_complete_within_scope,
        _ => !capture.inspection.truncated_section(section) && !capture.inspection.unavailable_section(section),
    }
}

fn section_count(capture: &RuntimeCapture, section: &str) -> usize {
    match section {
        "frames" => capture.inspection.frames.len(),
        "scripts" => capture.inspection.scripts.len(),
        "workers" => capture.inspection.workers.len(),
        _ => 1,
    }
}

fn section_coverage(capture: &RuntimeCapture, section: &str) -> Value {
    if section_complete(capture, section) {
        return json!({ "status": "complete", "truncated": false, "omitted_count": 0, "limits": [] });
    }
    let truncated = section != "target" && capture.inspection.truncated_section(section);
    let limits = if truncated {
        vec![json!({
            "name": format!("passive-cdp-{section}-limit"),
            "value": section_count(capture, section),
            "unit": "items",
        })]
    } else {
        vec![]
    };
    json!({ "status": "partial", "truncated": truncated, "omitted_count": null, "limits": limits })
}
