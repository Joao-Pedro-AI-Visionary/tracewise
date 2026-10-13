//! Semantic graph facts: nodes, relations, unknown frontiers, fingerprints and the mutable
//! projection state (REA `javascriptSemanticGraph.ts` creators and
//! `JavaScriptSemanticGraphConstruction.ts`).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::rc::Rc;

use serde_json::{json, Map, Value};

use crate::error::JsError;
use crate::jsgraph::app_graph::model::ArtifactFile;
use crate::jsgraph::ast::SourceRange;
use crate::jsgraph::ast_values::display_text;
use crate::jsgraph::util::compare_code_points;

use super::evidence::{
    digest, inferred_semantic_evidence, observed_semantic_evidence, unavailable_semantic_root_evidence,
    EvidenceRef, EvidenceRegistry,
};

/// One canonical semantic node.
#[derive(Debug)]
pub struct SemNode {
    pub node_id: String,
    pub kind: &'static str,
    pub artifact_sha256: String,
    pub module_path: String,
    pub source_range: Option<SourceRange>,
    pub role_key: String,
    pub function_node_id: Option<String>,
    pub label: Option<String>,
    pub properties: Map<String, Value>,
    pub evidence: EvidenceRef,
}

pub type NodeRef = Rc<SemNode>;

impl SemNode {
    fn identity_value(&self) -> Value {
        identity_value(&self.artifact_sha256, &self.module_path, self.source_range.as_ref(), &self.role_key)
    }

    /// The stored node object, with the application node ids bound at finish.
    pub fn to_value(&self, application_node_ids: &[String]) -> Value {
        json!({
            "kind": self.kind,
            "identity": self.identity_value(),
            "function_node_id": self.function_node_id,
            "application_node_ids": application_node_ids,
            "label": self.label,
            "properties": self.properties,
            "evidence": self.evidence.to_value(),
            "node_id": self.node_id,
        })
    }
}

fn identity_value(artifact_sha256: &str, module_path: &str, range: Option<&SourceRange>, role_key: &str) -> Value {
    json!({
        "artifact_sha256": artifact_sha256,
        "module_path": module_path,
        "source_range": range,
        "role_key": role_key,
    })
}

/// `javaScriptSemanticNodeId`.
pub fn semantic_node_id(
    kind: &str,
    artifact_sha256: &str,
    module_path: &str,
    range: Option<&SourceRange>,
    role_key: &str,
) -> Result<String, JsError> {
    Ok(format!(
        "jsrg_node_{}",
        digest(&json!({
            "kind": kind,
            "identity": identity_value(artifact_sha256, module_path, range, role_key),
        }))?
    ))
}

/// Input for one exact artifact-version semantic node.
pub struct NodeInput {
    pub kind: &'static str,
    pub role_key: String,
    pub location: Option<SourceRange>,
    pub label: Option<String>,
    pub function_node_id: Option<String>,
    pub properties: Map<String, Value>,
}

impl NodeInput {
    pub fn new(kind: &'static str, role_key: impl Into<String>, location: Option<SourceRange>, label: Option<String>) -> Self {
        NodeInput {
            kind,
            role_key: role_key.into(),
            location,
            label,
            function_node_id: None,
            properties: Map::new(),
        }
    }

    pub fn function(mut self, id: Option<String>) -> Self {
        self.function_node_id = id;
        self
    }

    pub fn properties(mut self, properties: Value) -> Self {
        if let Value::Object(map) = properties {
            self.properties = map;
        }
        self
    }
}

/// One directed static semantic relationship.
pub struct RelationInput<'a> {
    pub source: Option<&'a NodeRef>,
    pub target: Option<&'a NodeRef>,
    pub relation: &'static str,
    pub resolution: &'static str,
    pub evidence: Option<Value>,
    pub properties: Option<Value>,
}

impl<'a> RelationInput<'a> {
    pub fn new(
        source: Option<&'a NodeRef>,
        target: Option<&'a NodeRef>,
        relation: &'static str,
        resolution: &'static str,
    ) -> Self {
        RelationInput { source, target, relation, resolution, evidence: None, properties: None }
    }

    pub fn evidence(mut self, evidence: Value) -> Self {
        self.evidence = Some(evidence);
        self
    }

    pub fn properties(mut self, properties: Value) -> Self {
        self.properties = Some(properties);
        self
    }
}

/// Input of one unresolved frontier.
pub struct UnknownInput {
    pub node_id: Option<String>,
    pub family: &'static str,
    pub relation_kinds: Vec<&'static str>,
    pub reason: &'static str,
    pub detail: String,
    pub candidate_node_ids: Vec<String>,
    pub evidence: Value,
}

/// Mutable local projection state hidden from graph callers.
pub struct ProjectionState {
    pub nodes: HashMap<String, NodeRef>,
    pub relations: HashMap<String, Value>,
    pub unknowns: HashMap<String, Value>,
    pub evidence: EvidenceRegistry,
    pub roots: BTreeSet<String>,
    /// Remaining node budget for the file being projected (`None` = unbounded).
    pub file_node_budget: Option<i64>,
    pub file_nodes_dropped: bool,
}

impl ProjectionState {
    pub fn new() -> Self {
        ProjectionState {
            nodes: HashMap::new(),
            relations: HashMap::new(),
            unknowns: HashMap::new(),
            evidence: EvidenceRegistry::new(),
            roots: BTreeSet::new(),
            file_node_budget: None,
            file_nodes_dropped: false,
        }
    }

    fn construct_node(&mut self, file: &ArtifactFile, input: &NodeInput, node_id: String) -> Result<NodeRef, JsError> {
        let evidence = self
            .evidence
            .intern(&observed_semantic_evidence(file, input.location.as_ref()))?;
        Ok(Rc::new(SemNode {
            node_id,
            kind: input.kind,
            artifact_sha256: file.sha256.clone(),
            module_path: file.path.clone(),
            source_range: input.location,
            role_key: input.role_key.clone(),
            function_node_id: input.function_node_id.clone(),
            label: input.label.as_deref().map(display_text),
            properties: input.properties.clone(),
            evidence,
        }))
    }

    /// Reuse retained identities and reject exhausted budgets before allocation.
    pub fn retain_node(&mut self, file: &ArtifactFile, input: NodeInput) -> Result<Option<NodeRef>, JsError> {
        let node_id = semantic_node_id(
            input.kind,
            &file.sha256,
            &file.path,
            input.location.as_ref(),
            &input.role_key,
        )?;
        if let Some(existing) = self.nodes.get(&node_id) {
            return Ok(Some(existing.clone()));
        }
        if self.file_node_budget.is_some_and(|budget| budget <= 0) {
            self.file_nodes_dropped = true;
            return Ok(None);
        }
        let node = self.construct_node(file, &input, node_id)?;
        Ok(self.add_node(node))
    }

    /// Retain one canonical semantic node (`addSemanticGraphNode`).
    pub fn add_node(&mut self, node: NodeRef) -> Option<NodeRef> {
        if let Some(existing) = self.nodes.get(&node.node_id) {
            return Some(existing.clone());
        }
        if let Some(budget) = self.file_node_budget {
            if budget <= 0 {
                self.file_nodes_dropped = true;
                return None;
            }
            self.file_node_budget = Some(budget - 1);
        }
        self.nodes.insert(node.node_id.clone(), node.clone());
        Some(node)
    }

    /// Retain one non-self semantic relationship.
    pub fn add_relation(&mut self, input: RelationInput<'_>) -> Result<(), JsError> {
        let (Some(source), Some(target)) = (input.source, input.target) else {
            return Ok(());
        };
        if source.node_id == target.node_id {
            return Ok(());
        }
        let evidence = match input.evidence {
            Some(evidence) => evidence,
            None => inferred_semantic_evidence(&self.evidence.resolve(&source.evidence)?),
        };
        let reference = self.evidence.intern(&evidence)?;
        let semantic = json!({
            "source_node_id": source.node_id,
            "target_node_id": target.node_id,
            "relation": input.relation,
            "resolution": input.resolution,
            "properties": input.properties.unwrap_or_else(|| json!({})),
            "evidence": reference.to_value(),
        });
        let relation_id = format!("jsrg_relation_{}", digest(&semantic)?);
        if self.relations.contains_key(&relation_id) {
            return Ok(());
        }
        let mut stored = semantic.as_object().cloned().unwrap_or_default();
        stored.insert("relation_id".into(), json!(relation_id));
        self.relations.insert(relation_id, Value::Object(stored));
        Ok(())
    }

    /// Retain one unresolved frontier (`createJavaScriptSemanticGraphUnknown` + add).
    pub fn add_unknown(&mut self, input: UnknownInput) -> Result<(), JsError> {
        let mut kinds: Vec<&str> = input.relation_kinds.clone();
        kinds.sort_by(|a, b| compare_code_points(a, b));
        kinds.dedup();
        let mut candidates = input.candidate_node_ids.clone();
        candidates.sort_by(|a, b| compare_code_points(a, b));
        candidates.dedup();
        let reference = self.evidence.intern(&input.evidence)?;
        let semantic = json!({
            "node_id": input.node_id,
            "family": input.family,
            "relation_kinds": kinds,
            "reason": input.reason,
            "detail": input.detail,
            "candidate_node_ids": candidates,
            "evidence": reference.to_value(),
        });
        let unknown_id = format!("jsrg_unknown_{}", digest(&semantic)?);
        if self.unknowns.contains_key(&unknown_id) {
            return Ok(());
        }
        let mut stored = semantic.as_object().cloned().unwrap_or_default();
        stored.insert("unknown_id".into(), json!(unknown_id));
        self.unknowns.insert(unknown_id, Value::Object(stored));
        Ok(())
    }

    /// Add a truthful root when no source file could produce semantic IR.
    pub fn add_fallback_root(&mut self, root_artifact_sha256: &str) -> Result<(), JsError> {
        let evidence = self
            .evidence
            .intern(&unavailable_semantic_root_evidence(root_artifact_sha256))?;
        let node_id = semantic_node_id("module", root_artifact_sha256, "unknown-semantic-root", None, "artifact-root")?;
        let node = Rc::new(SemNode {
            node_id,
            kind: "module",
            artifact_sha256: root_artifact_sha256.to_string(),
            module_path: "unknown-semantic-root".into(),
            source_range: None,
            role_key: "artifact-root".into(),
            function_node_id: None,
            label: Some(display_text("unavailable semantic root")),
            properties: Map::new(),
            evidence,
        });
        if let Some(node) = self.add_node(node) {
            self.roots.insert(node.node_id.clone());
        }
        Ok(())
    }

    pub fn clear(&mut self) {
        self.nodes.clear();
        self.relations.clear();
        self.unknowns.clear();
        self.roots.clear();
        self.evidence.clear();
    }
}

impl Default for ProjectionState {
    fn default() -> Self {
        Self::new()
    }
}

/// Bind retained semantic identities to application nodes (`bindSemanticGraphApplicationNodes`).
pub fn application_node_ids_by_location(application_nodes: &[Value]) -> HashMap<String, Vec<String>> {
    let mut identifiers: HashMap<String, HashSet<String>> = HashMap::new();
    let mut add = |key: String, node_id: &str| {
        identifiers.entry(key).or_default().insert(node_id.to_string());
    };
    for node in application_nodes {
        let node_id = node["node_id"].as_str().unwrap_or_default();
        for observation in node["observations"].as_array().into_iter().flatten() {
            let evidence = &observation["evidence"];
            if evidence["artifact"]["available"] != Value::Bool(true) || evidence["location"]["available"] != Value::Bool(true) {
                continue;
            }
            let sha = evidence["artifact"]["sha256"].as_str().unwrap_or_default();
            let location = &evidence["location"]["value"];
            match location["kind"].as_str() {
                Some("artifact-path") => add(
                    location_key(sha, location["path"].as_str().unwrap_or_default(), None),
                    node_id,
                ),
                Some("source-range") => {
                    let range = format!(
                        "{}:{}-{}:{}",
                        location["start"]["line"], location["start"]["column"],
                        location["end"]["line"], location["end"]["column"]
                    );
                    add(
                        location_key(sha, location["source"].as_str().unwrap_or_default(), Some(&range)),
                        node_id,
                    )
                }
                _ => {}
            }
        }
    }
    identifiers
        .into_iter()
        .map(|(key, values)| {
            let mut sorted: Vec<String> = values.into_iter().collect();
            // JS default `.sort()` is UTF-16 code-unit order; ids are ASCII.
            sorted.sort();
            (key, sorted)
        })
        .collect()
}

pub fn location_key(artifact_sha256: &str, path: &str, range: Option<&str>) -> String {
    format!("{artifact_sha256}\u{0}{path}\u{0}{}", range.unwrap_or("artifact-path"))
}

pub fn node_location_key(node: &SemNode) -> String {
    let range = node.source_range.map(|r| {
        format!("{}:{}-{}:{}", r.start.line, r.start.column, r.end.line, r.end.column)
    });
    location_key(&node.artifact_sha256, &node.module_path, range.as_deref())
}
