//! Evidence for semantic graph facts and the interning context registry (REA
//! `JavaScriptSemanticGraphEvidence.ts`, `JavaScriptSemanticEvidenceContextRegistry`).

use std::collections::HashMap;

use serde_json::{json, Map, Value};
use tracewise_domain::canonical::{canonical_json, canonical_sha256};

use crate::error::JsError;
use crate::jsgraph::app_graph::model::ArtifactFile;
use crate::jsgraph::ast::SourceRange;
use crate::jsgraph::util::{compare_code_points, sha256_text};

const INFERENCE_LIMITATION: &str =
    "This relationship is a conservative static candidate; it does not prove runtime execution or causal flow.";

fn artifact_reference(sha256: &str) -> Value {
    json!({ "available": true, "artifact_id": format!("art_{sha256}"), "sha256": sha256 })
}

fn extractor() -> Value {
    json!({
        "name": "rea-javascript-semantic-analysis",
        "version": "1",
        "operation": "analyze_javascript_application",
        "executable_sha256": null,
    })
}

fn location_value(file: &ArtifactFile, location: Option<&SourceRange>) -> Value {
    match location {
        None => json!({ "available": true, "value": { "kind": "artifact-path", "path": file.path } }),
        Some(range) => json!({
            "available": true,
            "value": {
                "kind": "source-range",
                "source": file.path,
                "start": { "line": range.start.line, "column": range.start.column },
                "end": { "line": range.end.line, "column": range.end.column },
            }
        }),
    }
}

/// Exact artifact-backed syntax evidence for one semantic graph node.
pub fn observed_semantic_evidence(file: &ArtifactFile, location: Option<&SourceRange>) -> Value {
    json!({
        "authority": "ast-static-analysis",
        "state": "observed",
        "confidence": "exact",
        "artifact": artifact_reference(&file.sha256),
        "location": location_value(file, location),
        "extractor": extractor(),
        "coverage": { "status": "complete", "truncated": false, "omitted_count": 0, "limits": [] },
        "limitations": [],
        "evidence_ids": [],
    })
}

/// Conservative static relationship evidence derived from one syntax node.
pub fn inferred_semantic_evidence(source: &Value) -> Value {
    let mut evidence = source.clone();
    let object = evidence.as_object_mut().expect("evidence object");
    object.insert("authority".into(), json!("static-relationship-inference"));
    object.insert("state".into(), json!("inferred"));
    object.insert("confidence".into(), json!("high"));
    object.insert("limitations".into(), json!([INFERENCE_LIMITATION]));
    evidence
}

/// Static relationship evidence anchored at the syntax that proves the link.
pub fn inferred_semantic_evidence_at(file: &ArtifactFile, location: &SourceRange) -> Value {
    inferred_semantic_evidence(&observed_semantic_evidence(file, Some(location)))
}

/// Explicit absence of semantic syntax for an artifact-level fallback root.
pub fn unavailable_semantic_root_evidence(root_artifact_sha256: &str) -> Value {
    json!({
        "authority": "unknown",
        "state": "unavailable",
        "confidence": "unknown",
        "artifact": artifact_reference(root_artifact_sha256),
        "location": {
            "available": false,
            "reason": "not-observed",
            "detail": "No admitted JavaScript source produced semantic IR.",
        },
        "extractor": extractor(),
        "coverage": { "status": "unavailable", "truncated": false, "omitted_count": null, "limits": [] },
        "limitations": ["This synthetic graph root does not claim a source location."],
        "evidence_ids": [],
    })
}

/// Explicit unknown evidence at one unresolved dynamic syntax location.
pub fn unknown_semantic_evidence(file: &ArtifactFile, location: Option<&SourceRange>) -> Value {
    let mut evidence = observed_semantic_evidence(file, location);
    let object = evidence.as_object_mut().expect("evidence object");
    object.insert("authority".into(), json!("unknown"));
    object.insert("state".into(), json!("unknown"));
    object.insert("confidence".into(), json!("unknown"));
    object.insert(
        "limitations".into(),
        json!(["Dynamic syntax prevents an exact static relationship."]),
    );
    evidence
}

/// Compact provenance on one graph fact: a shared context plus the fact's own location.
#[derive(Clone, Debug)]
pub struct EvidenceRef {
    pub context_id: String,
    pub location: Value,
}

impl EvidenceRef {
    pub fn to_value(&self) -> Value {
        json!({ "context_id": self.context_id, "location": self.location })
    }
}

fn unique_sorted_strings(value: Option<&Value>) -> Vec<Value> {
    let mut items: Vec<String> = value
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    items.sort_by(|a, b| compare_code_points(a, b));
    items.dedup();
    items.into_iter().map(Value::String).collect()
}

/// `normalizeEvidence` of the semantic graph: limits sorted (not deduplicated) by canonical text.
fn normalize_evidence(evidence: &Value) -> Result<Value, JsError> {
    let mut evidence = evidence.clone();
    let object = evidence.as_object_mut().expect("evidence object");
    if let Some(Value::Object(coverage)) = object.get_mut("coverage") {
        let mut keyed: Vec<(String, Value)> = Vec::new();
        if let Some(Value::Array(limits)) = coverage.get("limits") {
            for limit in limits {
                keyed.push((canonical_json(limit)?, limit.clone()));
            }
        }
        keyed.sort_by(|a, b| compare_code_points(&a.0, &b.0));
        coverage.insert("limits".into(), Value::Array(keyed.into_iter().map(|(_, v)| v).collect()));
    }
    let limitations = unique_sorted_strings(object.get("limitations"));
    object.insert("limitations".into(), Value::Array(limitations));
    let evidence_ids = unique_sorted_strings(object.get("evidence_ids"));
    object.insert("evidence_ids".into(), Value::Array(evidence_ids));
    Ok(evidence)
}

/// Graph-scoped owner for canonical provenance shared by semantic facts.
#[derive(Default)]
pub struct EvidenceRegistry {
    contexts: HashMap<String, Value>,
    ids_by_canonical_context: HashMap<String, String>,
}

impl EvidenceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern normalized non-location provenance at fact construction.
    pub fn intern(&mut self, evidence: &Value) -> Result<EvidenceRef, JsError> {
        let normalized = normalize_evidence(evidence)?;
        let mut context = normalized.as_object().cloned().unwrap_or_default();
        let location = context.remove("location").unwrap_or(Value::Null);
        let context = Value::Object(context);
        let canonical = canonical_json(&context)?;
        if let Some(id) = self.ids_by_canonical_context.get(&canonical) {
            return Ok(EvidenceRef { context_id: id.clone(), location });
        }
        let context_id = format!("jsrg_evidence_{}", canonical_sha256(&context)?);
        if self.contexts.contains_key(&context_id) {
            return Err(JsError::InvalidInput(
                "JavaScript semantic evidence context digest collision".into(),
            ));
        }
        let mut stored = context.as_object().cloned().unwrap_or_default();
        stored.insert("context_id".into(), json!(context_id));
        self.contexts.insert(context_id.clone(), Value::Object(stored));
        self.ids_by_canonical_context.insert(canonical, context_id.clone());
        Ok(EvidenceRef { context_id, location })
    }

    /// Resolve one already interned fact reference for derived evidence.
    pub fn resolve(&self, reference: &EvidenceRef) -> Result<Value, JsError> {
        let context = self.contexts.get(&reference.context_id).ok_or_else(|| {
            JsError::InvalidInput("Semantic evidence reference names an absent context".into())
        })?;
        let mut evidence: Map<String, Value> = context.as_object().cloned().unwrap_or_default();
        evidence.remove("context_id");
        evidence.insert("location".into(), reference.location.clone());
        Ok(Value::Object(evidence))
    }

    /// The deterministic context table (sorted by id).
    pub fn contexts(&self) -> Vec<Value> {
        let mut all: Vec<Value> = self.contexts.values().cloned().collect();
        all.sort_by(|a, b| {
            compare_code_points(
                a["context_id"].as_str().unwrap_or_default(),
                b["context_id"].as_str().unwrap_or_default(),
            )
        });
        all
    }

    pub fn clear(&mut self) {
        self.contexts.clear();
        self.ids_by_canonical_context.clear();
    }
}

/// `digestCanonicalValue` for graph commitments.
pub fn digest(value: &Value) -> Result<String, JsError> {
    Ok(canonical_sha256(value)?)
}

#[allow(dead_code)]
pub fn text_digest(value: &str) -> String {
    sha256_text(value)
}
