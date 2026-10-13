//! Application-graph domain pieces: coverage and evidence constructors, node identities, and the
//! accumulator that deduplicates nodes and edges (REA `javascriptApplicationEvidenceSchemas.ts`,
//! `javascriptApplicationGraph.ts`, `JavaScriptArtifactGraphEvidence.ts`,
//! `JavaScriptArtifactGraphAccumulator.ts`).

use std::collections::HashMap;

use serde_json::{json, Map, Value};

use crate::application::graph_seal::{create_edge, recreate_node};
use crate::error::JsError;
use crate::jsgraph::ast::SourceRange;

// ---- coverage ------------------------------------------------------------------------------

pub fn complete_coverage() -> Value {
    json!({ "status": "complete", "truncated": false, "omitted_count": 0, "limits": [] })
}

/// Partial, non-truncated coverage (`partialApplicationCoverage`).
pub fn partial_coverage(limits: Vec<Value>, omitted: Option<u64>) -> Value {
    json!({
        "status": "partial",
        "truncated": false,
        "omitted_count": omitted,
        "limits": limits,
    })
}

/// Limit-truncated coverage (`truncatedApplicationCoverage`).
pub fn truncated_coverage(limits: Vec<Value>, omitted: Option<u64>) -> Value {
    json!({
        "status": "partial",
        "truncated": true,
        "omitted_count": omitted,
        "limits": limits,
    })
}

pub fn coverage_is_complete(coverage: &Value) -> bool {
    coverage.get("status").and_then(Value::as_str) == Some("complete")
}

// ---- evidence ------------------------------------------------------------------------------

const EXTRACTOR_NAME: &str = "rea-javascript-artifact-reconstruction";

fn extractor(operation: &str) -> Value {
    json!({
        "name": EXTRACTOR_NAME,
        "version": "1",
        "executable_sha256": null,
        "operation": operation,
    })
}

fn artifact_reference(sha256: &str) -> Value {
    json!({ "available": true, "artifact_id": format!("art_{sha256}"), "sha256": sha256 })
}

fn range_value(path: &str, range: &SourceRange) -> Value {
    json!({
        "kind": "source-range",
        "source": path,
        "start": { "line": range.start.line, "column": range.start.column },
        "end": { "line": range.end.line, "column": range.end.column },
    })
}

/// Shared exact artifact location and bounded coverage for static evidence.
pub struct EvidenceInput<'a> {
    pub sha256: &'a str,
    pub path: &'a str,
    pub operation: &'a str,
    pub coverage: &'a Value,
    pub limitations: &'a [String],
    pub range: Option<&'a SourceRange>,
    pub confidence: Option<&'a str>,
}

impl<'a> EvidenceInput<'a> {
    pub fn new(sha256: &'a str, path: &'a str, operation: &'a str, coverage: &'a Value) -> Self {
        EvidenceInput {
            sha256,
            path,
            operation,
            coverage,
            limitations: &[],
            range: None,
            confidence: None,
        }
    }

    pub fn limitations(mut self, limitations: &'a [String]) -> Self {
        self.limitations = limitations;
        self
    }

    pub fn range(mut self, range: &'a SourceRange) -> Self {
        self.range = Some(range);
        self
    }

    pub fn confidence(mut self, confidence: &'a str) -> Self {
        self.confidence = Some(confidence);
        self
    }
}

/// Exact artifact-byte evidence for one safely inventoried local file.
pub fn artifact_observation_evidence(input: &EvidenceInput<'_>) -> Value {
    json!({
        "authority": "artifact-bytes",
        "state": "observed",
        "confidence": "exact",
        "artifact": artifact_reference(input.sha256),
        "location": { "available": true, "value": { "kind": "artifact-path", "path": input.path } },
        "extractor": extractor(input.operation),
        "coverage": input.coverage,
        "limitations": input.limitations,
        "evidence_ids": [],
    })
}

/// Exact AST syntax evidence with an actionable source range.
pub fn ast_observation_evidence(input: &EvidenceInput<'_>) -> Value {
    let mut limitations: Vec<String> = input.limitations.to_vec();
    if !coverage_is_complete(input.coverage) {
        limitations.push(
            "AST coverage is incomplete; omitted or dynamic facts must not be interpreted as absence."
                .into(),
        );
    }
    let range = input.range.expect("AST evidence requires a range");
    json!({
        "authority": "ast-static-analysis",
        "state": "observed",
        "confidence": "exact",
        "artifact": artifact_reference(input.sha256),
        "location": { "available": true, "value": range_value(input.path, range) },
        "extractor": extractor(input.operation),
        "coverage": input.coverage,
        "limitations": limitations,
        "evidence_ids": [],
    })
}

/// Explicit static relationship inference; never promoted to observation.
pub fn static_inference_evidence(input: &EvidenceInput<'_>) -> Value {
    let mut limitations =
        vec!["Static syntax does not prove that this relationship executes at runtime.".to_string()];
    limitations.extend(input.limitations.iter().cloned());
    let location = match input.range {
        None => json!({ "available": true, "value": { "kind": "artifact-path", "path": input.path } }),
        Some(range) => json!({ "available": true, "value": range_value(input.path, range) }),
    };
    json!({
        "authority": "static-relationship-inference",
        "state": "inferred",
        "confidence": input.confidence.unwrap_or("high"),
        "artifact": artifact_reference(input.sha256),
        "location": location,
        "extractor": extractor(input.operation),
        "coverage": input.coverage,
        "limitations": limitations,
        "evidence_ids": [],
    })
}

/// Unavailable AST fact that preserves a parse, approval, or limit gap.
pub fn unavailable_ast_evidence(input: &EvidenceInput<'_>, limitation: &str) -> Value {
    let mut limitations = vec![limitation.to_string()];
    limitations.extend(input.limitations.iter().cloned());
    json!({
        "authority": "ast-static-analysis",
        "state": "unavailable",
        "confidence": "unknown",
        "artifact": artifact_reference(input.sha256),
        "location": { "available": true, "value": { "kind": "artifact-path", "path": input.path } },
        "extractor": extractor(input.operation),
        "coverage": input.coverage,
        "limitations": limitations,
        "evidence_ids": [],
    })
}

// ---- identities ----------------------------------------------------------------------------

/// Stable identity for a fact scoped to one exact artifact.
pub fn artifact_local_identity(sha256: &str, namespace: &str, key: &str) -> Value {
    json!({
        "strategy": "artifact-local-key",
        "stability": "artifact-version",
        "artifact_sha256": sha256,
        "namespace": namespace,
        "key": key,
    })
}

pub fn content_digest_identity(sha256: &str) -> Value {
    json!({ "strategy": "content-digest", "stability": "global-exact", "sha256": sha256 })
}

pub fn canonical_path_identity(artifact_sha256: &str, path: &str) -> Value {
    json!({
        "strategy": "canonical-path",
        "stability": "artifact-version",
        "artifact_sha256": artifact_sha256,
        "path": path,
    })
}

// ---- nodes, edges, accumulator -------------------------------------------------------------

/// Handle to an accumulated node: enough to build edges and reuse the identity.
#[derive(Clone, Debug)]
pub struct NodeRef {
    pub node_id: String,
    pub kind: String,
    pub identity: Value,
}

/// One observation before its identifier is derived.
pub struct ObservationInput {
    pub label: Option<String>,
    pub source_map_reference: Value,
    pub properties: Map<String, Value>,
    pub evidence: Value,
}

impl ObservationInput {
    pub fn new(label: Option<String>, properties: Value, evidence: Value) -> ObservationInput {
        ObservationInput {
            label,
            source_map_reference: Value::Null,
            properties: match properties {
                Value::Object(map) => map,
                _ => Map::new(),
            },
            evidence,
        }
    }
}

/// Deduplicates graph entities while retaining distinct evidence observations.
#[derive(Default)]
pub struct Accumulator {
    nodes: HashMap<String, Value>,
    edges: HashMap<String, Value>,
}

impl Accumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create or merge one canonical node (`addNode`).
    pub fn add_node(
        &mut self,
        kind: &str,
        identity: Value,
        observations: Vec<ObservationInput>,
    ) -> Result<NodeRef, JsError> {
        // Labels must be nonempty: a legal empty value has no label rather than synthetic text.
        let observations: Vec<Value> = observations
            .into_iter()
            .map(|observation| {
                let label = match observation.label.as_deref() {
                    None | Some("") => Value::Null,
                    Some(text) => Value::String(text.to_string()),
                };
                json!({
                    "label": label,
                    "source_map_reference": observation.source_map_reference,
                    "properties": observation.properties,
                    "evidence": observation.evidence,
                })
            })
            .collect();
        let created = recreate_node(&json!({
            "kind": kind,
            "identity": identity,
            "observations": observations,
        }))?;
        let node_id = created["node_id"].as_str().unwrap_or_default().to_string();
        let reference = NodeRef {
            node_id: node_id.clone(),
            kind: kind.to_string(),
            identity: created["identity"].clone(),
        };
        match self.nodes.get_mut(&node_id) {
            None => {
                self.nodes.insert(node_id, created);
            }
            Some(existing) => {
                // Same node identity: merge observations by their semantic id, keep them sorted.
                let mut merged: Vec<Value> = existing["observations"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                for observation in created["observations"].as_array().cloned().unwrap_or_default() {
                    let id = observation["observation_id"].as_str().unwrap_or_default();
                    match merged
                        .iter_mut()
                        .find(|o| o["observation_id"].as_str() == Some(id))
                    {
                        Some(slot) => *slot = observation,
                        None => merged.push(observation),
                    }
                }
                merged.sort_by(|a, b| {
                    let left = a["observation_id"].as_str().unwrap_or_default();
                    let right = b["observation_id"].as_str().unwrap_or_default();
                    left.cmp(right)
                });
                existing["observations"] = Value::Array(merged);
            }
        }
        Ok(reference)
    }

    /// Create or replace one canonical edge by semantic identifier (`addEdge`).
    pub fn add_edge(
        &mut self,
        source: &str,
        target: &str,
        relation: &str,
        properties: Value,
        evidence: Value,
    ) -> Result<(), JsError> {
        let edge = create_edge(&json!({
            "source_node_id": source,
            "target_node_id": target,
            "relation": relation,
            "properties": properties,
            "evidence": evidence,
        }))?;
        let id = edge["edge_id"].as_str().unwrap_or_default().to_string();
        self.edges.insert(id, edge);
        Ok(())
    }

    pub fn nodes(&self) -> Vec<Value> {
        self.nodes.values().cloned().collect()
    }

    pub fn edges(&self) -> Vec<Value> {
        self.edges.values().cloned().collect()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}
