//! `project_apple_application_graph` (port of REA `domain/apple/appleApplication.ts`,
//! `appleBundleAnatomy.ts`, `domain/nativeConvention.ts`, `domain/bridgeCandidateProjection.ts`,
//! `domain/artifactInventoryEvidence.ts` and `domain/artifactGraph.ts`).
//!
//! Execution-free: only artifact-inventory Evidence is read; no file of the application is opened.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tracewise_domain::canonical::canonical_sha256;
use tracewise_domain::evidence::Evidence;

use crate::error::{InputIssue, NativeError};

pub const OPERATION: &str = "project_apple_application_graph";

// ---------------------------------------------------------------------------
// Ordering helpers
// ---------------------------------------------------------------------------

/// JavaScript `<` on strings: UTF-16 code unit order (`compare` in REA).
pub fn js_cmp(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

/// `compareUnicodeCodePoints`: code point order.
fn code_point_cmp(left: &str, right: &str) -> Ordering {
    left.chars().cmp(right.chars())
}

fn input_error(message: impl Into<String>) -> NativeError {
    NativeError::Input {
        operation: OPERATION.to_string(),
        issues: vec![InputIssue::invalid(Vec::new(), message)],
    }
}

// ---------------------------------------------------------------------------
// Inventory model (domain/artifactGraph.ts; unknown keys are stripped like zod's `z.object`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Node {
    pub artifact_id: String,
    pub format: String,
    pub sha256: String,
    pub size: u64,
    pub media_type: Option<String>,
    pub architecture: Option<String>,
    pub content_state: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ByteRange {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Occurrence {
    pub occurrence_id: String,
    pub artifact_id: Option<String>,
    pub parent_occurrence_id: Option<String>,
    pub logical_path: String,
    pub entry_kind: String,
    pub artifact_kind: String,
    pub artifact_format: String,
    pub declared_size: Option<u64>,
    pub compressed_size: Option<u64>,
    pub executable: bool,
    pub encrypted: bool,
    pub hash_status: String,
    pub source_location: Option<ByteRange>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Edge {
    pub edge_id: String,
    pub ordinal: u64,
    pub parent_artifact_id: String,
    pub relation: String,
    pub occurrence_id: String,
    pub producer: Option<Command>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Command {
    pub tool: String,
    pub arguments: Vec<String>,
    pub tool_version: Option<String>,
    pub executable_sha256: Option<String>,
    pub exit_code: Option<i64>,
    pub effects: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Contradiction {
    pub contradiction_id: String,
    pub occurrence_id: String,
    pub parent_artifact_id: String,
    pub logical_path: String,
    pub declared_sha256: String,
    pub observed_sha256: String,
    pub entry_kind: String,
    pub unpacked: bool,
    pub trust: String,
    pub provenance: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub manifest_id: String,
    pub root_artifact_id: String,
    pub root_sha256: String,
    pub root_format: String,
    pub graph_sha256: String,
    pub node_count: u64,
    pub occurrence_count: u64,
    pub edge_count: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct InventoryPage {
    manifest: Manifest,
    nodes: Vec<Node>,
    occurrences: Vec<Occurrence>,
    edges: Vec<Edge>,
    #[allow(dead_code)]
    provenance: Vec<Command>,
    #[serde(default)]
    integrity_contradictions: Vec<Contradiction>,
    limitations: Vec<String>,
}

/// A merged inventory (`InventorySet`).
#[derive(Debug, Clone)]
pub struct InventorySet {
    pub manifest: Manifest,
    pub nodes: Vec<Node>,
    pub occurrences: Vec<Occurrence>,
    pub edges: Vec<Edge>,
    pub contradictions: Vec<Contradiction>,
    pub limitations: Vec<String>,
    pub complete: bool,
}

pub struct ParsedInventory {
    pub evidence: Vec<Evidence>,
    pub inventory: InventorySet,
}

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("regex"))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_prefixed(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('_'))
        .map(is_sha256)
        .unwrap_or(false)
}

const ARTIFACT_KINDS: &[&str] = &[
    "container",
    "executable",
    "dynamic-library",
    "framework",
    "native-addon",
    "javascript",
    "source-map",
    "plist",
    "entitlements",
    "resource",
    "universal-slice",
    "package-metadata",
    "unknown",
];
const ARTIFACT_FORMATS: &[&str] = &[
    "dmg",
    "zip",
    "pkg",
    "asar",
    "javascript-bundle",
    "source-map",
    "mach-o-universal",
    "mach-o",
    "elf",
    "pe",
    "dos-mz",
    "dos-com",
    "hopper",
    "analysis-database",
    "ipa",
    "apk",
    "msix",
    "appx",
    "plist",
    "entitlements",
    "directory",
    "file",
    "unknown",
];
const CONTENT_FORMATS: &[&str] = &[
    "zip",
    "mach-o-universal",
    "mach-o",
    "elf",
    "pe",
    "dos-mz",
    "plist",
    "directory",
    "file",
    "unknown",
];

/// `boundedRelativePathSchema`.
fn bounded_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && path.split('/').all(|part| !part.is_empty() && part != "..")
}

/// Structural validation of one page (the checks of `artifactInventoryResultSchema`).
fn validate_page_shape(page: &InventoryPage) -> Result<(), String> {
    let m = &page.manifest;
    if !is_prefixed(&m.manifest_id, "agm")
        || !is_prefixed(&m.root_artifact_id, "art")
        || !is_sha256(&m.root_sha256)
        || !ARTIFACT_FORMATS.contains(&m.root_format.as_str())
        || !is_sha256(&m.graph_sha256)
        || m.node_count < 1
        || m.occurrence_count < 1
    {
        return Err("manifest".to_string());
    }
    let max_safe = 9_007_199_254_740_991u64;
    for (index, node) in page.nodes.iter().enumerate() {
        if !is_prefixed(&node.artifact_id, "art")
            || !CONTENT_FORMATS.contains(&node.format.as_str())
            || !is_sha256(&node.sha256)
            || node.size > max_safe
            || node.media_type.as_deref() == Some("")
            || node.architecture.as_deref() == Some("")
            || !["materialized", "embedded", "virtual"].contains(&node.content_state.as_str())
        {
            return Err(format!("nodes.{index}"));
        }
    }
    for (index, occ) in page.occurrences.iter().enumerate() {
        let ok = is_prefixed(&occ.occurrence_id, "occ")
            && occ.artifact_id.as_deref().map(|id| is_prefixed(id, "art")).unwrap_or(true)
            && occ.parent_occurrence_id.as_deref().map(|id| is_prefixed(id, "occ")).unwrap_or(true)
            && bounded_relative_path_or_root(&occ.logical_path)
            && ["file", "directory", "symlink", "slice"].contains(&occ.entry_kind.as_str())
            && ARTIFACT_KINDS.contains(&occ.artifact_kind.as_str())
            && ARTIFACT_FORMATS.contains(&occ.artifact_format.as_str())
            && occ.declared_size.map(|v| v <= max_safe).unwrap_or(true)
            && occ.compressed_size.map(|v| v <= max_safe).unwrap_or(true)
            && ["verified", "mismatched", "not-hashed", "unavailable"].contains(&occ.hash_status.as_str());
        if !ok {
            return Err(format!("occurrences.{index}"));
        }
    }
    for (index, edge) in page.edges.iter().enumerate() {
        let ok = is_prefixed(&edge.edge_id, "edge")
            && is_prefixed(&edge.parent_artifact_id, "art")
            && is_prefixed(&edge.occurrence_id, "occ")
            && ["contains", "extracts", "slice-of", "embeds", "loads", "maps-source", "derived-from"]
                .contains(&edge.relation.as_str());
        if !ok {
            return Err(format!("edges.{index}"));
        }
    }
    for (index, item) in page.integrity_contradictions.iter().enumerate() {
        let ok = is_prefixed(&item.contradiction_id, "ic")
            && is_prefixed(&item.occurrence_id, "occ")
            && is_prefixed(&item.parent_artifact_id, "art")
            && bounded_relative_path_or_root(&item.logical_path)
            && is_sha256(&item.declared_sha256)
            && is_sha256(&item.observed_sha256)
            && ["file", "slice"].contains(&item.entry_kind.as_str())
            && item.trust == "observed-untrusted"
            && item.provenance == "container-integrity-metadata-versus-observed-bytes"
            && !item.limitations.is_empty();
        if !ok {
            return Err(format!("integrity_contradictions.{index}"));
        }
    }
    Ok(())
}

/// The root occurrence is `.`, which is not a bounded relative path in REA's schema either:
/// REA's inventory emits it, so the schema must accept it (`.` has no empty or `..` segment).
fn bounded_relative_path_or_root(path: &str) -> bool {
    bounded_relative_path(path)
}

// ---------------------------------------------------------------------------
// Identity functions (domain/artifactIdentity.ts)
// ---------------------------------------------------------------------------

fn digest(value: &Value) -> String {
    canonical_sha256(value).expect("canonical json")
}

fn artifact_id_for_content(sha256: &str) -> String {
    format!("art_{}", digest(&json!({ "sha256": sha256 })))
}

fn occurrence_id_for_location(root_artifact_id: &str, logical_path: &str, entry_kind: &str) -> String {
    if logical_path == "." {
        format!("occ_{}", digest(&json!({ "root": root_artifact_id })))
    } else {
        format!(
            "occ_{}",
            digest(&json!({
                "root_artifact_id": root_artifact_id,
                "logical_path": logical_path,
                "entry_kind": entry_kind,
            }))
        )
    }
}

fn artifact_graph_digest(
    nodes: &[Node],
    occurrences: &[Occurrence],
    edges: &[Edge],
    contradictions: &[Contradiction],
) -> String {
    digest(&json!({
        "nodes": nodes,
        "occurrences": occurrences,
        "edges": edges,
        "integrity_contradictions": contradictions,
    }))
}

fn artifact_manifest_id(root_artifact_id: &str, graph_sha256: &str) -> String {
    format!(
        "agm_{}",
        digest(&json!({ "root_artifact_id": root_artifact_id, "graph_sha256": graph_sha256 }))
    )
}

fn artifact_contradiction_id(root: &str, logical_path: &str, declared: &str, observed: &str) -> String {
    format!(
        "ic_{}",
        digest(&json!({
            "root_artifact_id": root,
            "logical_path": logical_path,
            "declared_sha256": declared,
            "observed_sha256": observed,
        }))
    )
}

fn artifact_edge_id(edge: &Edge, child_artifact_id: &str, logical_path: &str) -> String {
    format!(
        "edge_{}",
        digest(&json!({
            "parent_artifact_id": edge.parent_artifact_id,
            "child_artifact_id": child_artifact_id,
            "relation": edge.relation,
            "occurrence_id": edge.occurrence_id,
            "logical_path": logical_path,
        }))
    )
}

// ---------------------------------------------------------------------------
// Inventory parsing (domain/artifactInventoryEvidence.ts)
// ---------------------------------------------------------------------------

/// Parse, merge and verify inventory Evidence pages.
pub fn parse_artifact_inventory_evidence(inputs: &[Evidence]) -> Result<ParsedInventory, NativeError> {
    let mut pages: Vec<(Evidence, InventoryPage)> = Vec::new();
    for evidence in inputs {
        // parseEvidence: authenticate the semantic identifier.
        let computed = evidence
            .compute_id()
            .map_err(|error| input_error(error.to_string()))?;
        if computed != evidence.evidence_id {
            return Err(input_error(
                "A nested value failed validation at evidence_id: Evidence semantic identifier does not match its record",
            ));
        }
        let inventory_value: Option<Value> = if evidence.operation == "inventory_artifact" {
            Some(evidence.normalized_result.clone())
        } else if evidence.operation == "inspect_artifact" {
            evidence
                .normalized_result
                .get("substeps")
                .and_then(|steps| steps.get(0))
                .and_then(|step| step.get("evidence"))
                .and_then(|nested| nested.get("normalized_result"))
                .cloned()
        } else {
            None
        };
        let Some(inventory_value) = inventory_value else {
            return Err(input_error("Artifact comparison requires inspect_artifact Evidence"));
        };
        let inventory_evidence: Option<Evidence> = if evidence.operation == "inventory_artifact" {
            Some(evidence.clone())
        } else {
            evidence
                .normalized_result
                .get("substeps")
                .and_then(|steps| steps.get(0))
                .and_then(|step| step.get("evidence"))
                .and_then(|nested| serde_json::from_value(nested.clone()).ok())
        };
        let Some(inventory_evidence) = inventory_evidence else {
            return Err(input_error("Artifact comparison requires inspect_artifact Evidence"));
        };
        let page: InventoryPage = serde_json::from_value(inventory_value).map_err(|error| {
            input_error(format!("A nested value failed validation at its root: {error}"))
        })?;
        if let Err(path) = validate_page_shape(&page) {
            return Err(input_error(format!(
                "A nested value failed validation at {path}: Invalid inventory value"
            )));
        }
        match &inventory_evidence.subject {
            Some(subject)
                if subject.digest.sha256 == page.manifest.root_sha256
                    && subject.format == page.manifest.root_format => {}
            _ => {
                return Err(input_error(
                    "Artifact inventory Evidence subject does not match its root digest",
                ))
            }
        }
        validate_inventory_page(&page)?;
        pages.push((evidence.clone(), page));
    }
    assemble_inventory_set(pages)
}

fn assert_unique<'a>(values: impl Iterator<Item = &'a str>, label: &str) -> Result<(), NativeError> {
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(input_error(format!("Artifact inventory contains a duplicate {label}")));
        }
    }
    Ok(())
}

fn validate_inventory_page(page: &InventoryPage) -> Result<(), NativeError> {
    assert_unique(page.nodes.iter().map(|n| n.artifact_id.as_str()), "node ID")?;
    assert_unique(page.occurrences.iter().map(|o| o.occurrence_id.as_str()), "occurrence ID")?;
    assert_unique(page.occurrences.iter().map(|o| o.logical_path.as_str()), "logical path")?;
    assert_unique(page.edges.iter().map(|e| e.edge_id.as_str()), "edge ID")?;
    for node in &page.nodes {
        if node.artifact_id != artifact_id_for_content(&node.sha256) {
            return Err(input_error("Artifact node ID is not content-addressed"));
        }
    }
    Ok(())
}

fn merge_exact<V: PartialEq + Clone>(
    output: &mut BTreeMap<String, V>,
    key: &str,
    value: &V,
    label: &str,
) -> Result<(), NativeError> {
    if let Some(previous) = output.get(key) {
        if previous != value {
            return Err(input_error(format!("Artifact inventory has conflicting {label} pages")));
        }
    }
    output.insert(key.to_string(), value.clone());
    Ok(())
}

fn assemble_inventory_set(pages: Vec<(Evidence, InventoryPage)>) -> Result<ParsedInventory, NativeError> {
    let Some((_, first)) = pages.first() else {
        return Err(input_error("Artifact inventory requires Evidence pages"));
    };
    let first_manifest = first.manifest.clone();
    let first_contradictions = first.integrity_contradictions.clone();
    let mut nodes: BTreeMap<String, Node> = BTreeMap::new();
    let mut occurrences: BTreeMap<String, Occurrence> = BTreeMap::new();
    let mut paths: BTreeMap<String, Occurrence> = BTreeMap::new();
    let mut edges: BTreeMap<String, Edge> = BTreeMap::new();
    for (_, page) in &pages {
        if page.manifest != first_manifest {
            return Err(input_error("Artifact inventory pages do not share one manifest"));
        }
        if page.integrity_contradictions != first_contradictions {
            return Err(input_error(
                "Artifact inventory pages do not share integrity contradictions",
            ));
        }
        for node in &page.nodes {
            merge_exact(&mut nodes, &node.artifact_id, node, "node")?;
        }
        for occurrence in &page.occurrences {
            merge_exact(&mut occurrences, &occurrence.occurrence_id, occurrence, "occurrence")?;
            merge_exact(&mut paths, &occurrence.logical_path, occurrence, "logical path")?;
        }
        for edge in &page.edges {
            merge_exact(&mut edges, &edge.edge_id, edge, "edge")?;
        }
    }
    let mut node_list: Vec<Node> = nodes.into_values().collect();
    node_list.sort_by(|a, b| code_point_cmp(&a.artifact_id, &b.artifact_id));
    let mut occurrence_list: Vec<Occurrence> = occurrences.into_values().collect();
    occurrence_list.sort_by(|a, b| code_point_cmp(&a.logical_path, &b.logical_path));
    let mut edge_list: Vec<Edge> = edges.into_values().collect();
    edge_list.sort_by(|a, b| code_point_cmp(&a.edge_id, &b.edge_id));
    let mut limitations: Vec<String> = pages
        .iter()
        .flat_map(|(_, page)| page.limitations.iter().cloned())
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect();
    limitations.sort_by(|a, b| code_point_cmp(a, b));
    let complete = node_list.len() as u64 == first_manifest.node_count
        && occurrence_list.len() as u64 == first_manifest.occurrence_count
        && edge_list.len() as u64 == first_manifest.edge_count;
    let inventory = InventorySet {
        manifest: first_manifest,
        nodes: node_list,
        occurrences: occurrence_list,
        edges: edge_list,
        contradictions: first_contradictions,
        limitations,
        complete,
    };
    if inventory.complete {
        validate_complete_inventory(&inventory)?;
    }
    Ok(ParsedInventory {
        evidence: pages.into_iter().map(|(evidence, _)| evidence).collect(),
        inventory,
    })
}

fn validate_complete_inventory(inventory: &InventorySet) -> Result<(), NativeError> {
    let node_ids: HashSet<&str> = inventory.nodes.iter().map(|n| n.artifact_id.as_str()).collect();
    let occurrence_ids: HashSet<&str> = inventory.occurrences.iter().map(|o| o.occurrence_id.as_str()).collect();
    let root_node = inventory
        .nodes
        .iter()
        .find(|n| n.artifact_id == inventory.manifest.root_artifact_id);
    if root_node.map(|n| n.sha256.as_str()) != Some(inventory.manifest.root_sha256.as_str()) {
        return Err(input_error("Artifact root node does not match its manifest digest"));
    }
    let root_occurrence = inventory.occurrences.iter().find(|o| o.logical_path == ".");
    match root_occurrence {
        Some(root)
            if root.artifact_id.as_deref() == Some(inventory.manifest.root_artifact_id.as_str())
                && root.artifact_format == inventory.manifest.root_format => {}
        _ => {
            return Err(input_error(
                "Artifact root occurrence does not match its manifest representation",
            ))
        }
    }
    for occurrence in &inventory.occurrences {
        if let Some(id) = &occurrence.artifact_id {
            if !node_ids.contains(id.as_str()) {
                return Err(input_error("Artifact occurrence references a missing node"));
            }
        }
        if let Some(parent) = &occurrence.parent_occurrence_id {
            if !occurrence_ids.contains(parent.as_str()) {
                return Err(input_error("Artifact occurrence references a missing parent"));
            }
        }
        let expected = occurrence_id_for_location(
            &inventory.manifest.root_artifact_id,
            &occurrence.logical_path,
            &occurrence.entry_kind,
        );
        if occurrence.occurrence_id != expected {
            return Err(input_error("Artifact occurrence ID does not match its identity"));
        }
    }
    let by_id: HashMap<&str, &Occurrence> = inventory
        .occurrences
        .iter()
        .map(|o| (o.occurrence_id.as_str(), o))
        .collect();
    for edge in &inventory.edges {
        let occurrence = by_id.get(edge.occurrence_id.as_str());
        let child = occurrence.and_then(|o| o.artifact_id.as_deref());
        let (Some(occurrence), Some(child)) = (occurrence, child) else {
            return Err(input_error("Artifact edge references a missing graph member"));
        };
        if !node_ids.contains(edge.parent_artifact_id.as_str()) || !node_ids.contains(child) {
            return Err(input_error("Artifact edge references a missing graph member"));
        }
        if edge.edge_id != artifact_edge_id(edge, child, &occurrence.logical_path) {
            return Err(input_error("Artifact edge ID does not match its identity"));
        }
    }
    for contradiction in &inventory.contradictions {
        if !node_ids.contains(contradiction.parent_artifact_id.as_str())
            || !occurrence_ids.contains(contradiction.occurrence_id.as_str())
        {
            return Err(input_error("Integrity contradiction references a missing graph member"));
        }
        let expected = artifact_contradiction_id(
            &inventory.manifest.root_artifact_id,
            &contradiction.logical_path,
            &contradiction.declared_sha256,
            &contradiction.observed_sha256,
        );
        if contradiction.contradiction_id != expected {
            return Err(input_error("Integrity contradiction ID does not match its identity"));
        }
    }
    let graph_sha256 = artifact_graph_digest(
        &inventory.nodes,
        &inventory.occurrences,
        &inventory.edges,
        &inventory.contradictions,
    );
    if graph_sha256 != inventory.manifest.graph_sha256 {
        return Err(input_error("Artifact graph commitment does not match its members"));
    }
    if artifact_manifest_id(&inventory.manifest.root_artifact_id, &graph_sha256) != inventory.manifest.manifest_id {
        return Err(input_error("Artifact manifest ID does not match its commitment"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Anatomy (domain/apple/appleBundleAnatomy.ts)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Component {
    pub path: String,
    pub artifact_id: String,
    pub sha256: String,
    pub format: String,
}

#[derive(Debug, Clone)]
struct Entry {
    path: String,
    kind: String,
    component: Option<Component>,
}

fn lower(value: &str) -> String {
    value.to_lowercase()
}

fn anatomy_name_is(actual: &str, expected: &str) -> bool {
    lower(actual) == lower(expected)
}

fn is_sidecar(path: &str) -> bool {
    let segments: Vec<&str> = path.split('/').collect();
    segments.contains(&"__MACOSX") || segments.last().copied().unwrap_or("").starts_with("._")
}

fn is_within(path: &str, root: &str) -> bool {
    root == "." || path == root || path.starts_with(&format!("{root}/"))
}

fn is_mach_o_format(format: &str) -> bool {
    format == "mach-o" || format == "mach-o-universal"
}

fn anatomy_child(names: Option<&BTreeSet<String>>, expected: &str) -> Option<String> {
    let names = names?;
    let mut exact: Option<&String> = None;
    let mut folded: Option<&String> = None;
    for name in names {
        if name == expected {
            exact = Some(name);
        } else if anatomy_name_is(name, expected)
            && folded.map(|current| js_cmp(name, current) == Ordering::Less).unwrap_or(true)
        {
            folded = Some(name);
        }
    }
    exact.or(folded).cloned()
}

fn anatomy_tail_matches(path: &str, expected: &[&str]) -> bool {
    let actual: Vec<&str> = path.split('/').collect();
    if actual.len() < expected.len() {
        return false;
    }
    let tail = &actual[actual.len() - expected.len()..];
    expected.iter().zip(tail).all(|(name, segment)| {
        if segment.is_empty() {
            return false;
        }
        *name == "*" || anatomy_name_is(segment, name)
    })
}

fn app_suffix() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(&CELL, r"(?i)\.app$")
}

fn bundle_extension() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\.(?:app|appex|xpc|framework|systemextension|dext|bundle|plugin|qlgenerator|mdimporter)$",
    )
}

fn application_roots(entries: &[Entry], subject_name: &str, subject_format: &str) -> Vec<String> {
    if subject_format == "directory" && app_suffix().is_match(subject_name) {
        return vec![".".to_string()];
    }
    let mut found: Vec<String> = Vec::new();
    let mut add = |value: String| {
        if !found.contains(&value) {
            found.push(value);
        }
    };
    for entry in entries {
        if is_sidecar(&entry.path) {
            continue;
        }
        let segments: Vec<&str> = entry.path.split('/').collect();
        let app = segments.get(1).copied();
        if anatomy_name_is(segments.first().copied().unwrap_or(""), "Payload")
            && app.map(|a| app_suffix().is_match(a)).unwrap_or(false)
        {
            add(format!("{}/{}", segments[0], app.unwrap()));
            continue;
        }
        let index = segments.iter().enumerate().position(|(position, segment)| {
            app_suffix().is_match(segment)
                && anatomy_name_is(segments.get(position + 1).copied().unwrap_or(""), "Contents")
        });
        if let Some(index) = index {
            add(segments[..=index].join("/"));
        }
    }
    let mut roots: Vec<String> = found
        .iter()
        .filter(|root| !found.iter().any(|other| other != *root && is_within(root, other)))
        .cloned()
        .collect();
    roots.sort_by(|a, b| js_cmp(a, b));
    roots
}

#[derive(Debug, Clone, Serialize)]
pub struct Bundle {
    pub path: String,
    pub parent_path: Option<String>,
    pub layout: String,
    pub role: String,
    pub role_basis: String,
    pub info_plist_path: Option<String>,
    pub executable_candidates: Vec<String>,
    pub signing_paths: Vec<String>,
}

struct Tree {
    children: HashMap<String, BTreeSet<String>>,
    files: HashMap<String, Component>,
    directories: HashSet<String>,
}

fn join_path(directory: &str, name: &str) -> String {
    if directory.is_empty() {
        name.to_string()
    } else {
        format!("{directory}/{name}")
    }
}

fn index_tree(entries: &[Entry]) -> Tree {
    let mut children: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut files = HashMap::new();
    let mut directories = HashSet::new();
    for entry in entries {
        if is_sidecar(&entry.path) {
            continue;
        }
        if entry.kind == "file" {
            if let Some(component) = &entry.component {
                files.insert(entry.path.clone(), component.clone());
            }
        }
        if entry.kind == "directory" {
            directories.insert(entry.path.clone());
        }
        let mut parent = String::new();
        for segment in entry.path.split('/') {
            children.entry(parent.clone()).or_default().insert(segment.to_string());
            parent = join_path(&parent, segment);
            if parent != entry.path {
                directories.insert(parent.clone());
            }
        }
    }
    Tree { children, files, directories }
}

fn directory_of(bundle: &str) -> String {
    if bundle == "." {
        String::new()
    } else {
        bundle.to_string()
    }
}

fn enclosing_bundle(path: &str, bundles: &BTreeSet<String>) -> Option<String> {
    if path == "." {
        return None;
    }
    let segments: Vec<&str> = path.split('/').collect();
    for length in (1..segments.len()).rev() {
        let candidate = segments[..length].join("/");
        if bundles.contains(&candidate) {
            return Some(candidate);
        }
    }
    if bundles.contains(".") {
        Some(".".to_string())
    } else {
        None
    }
}

fn bundle_layout(bundle: &str, tree: &Tree) -> &'static str {
    let names = tree.children.get(&directory_of(bundle));
    if anatomy_child(names, "Contents").is_some() {
        return "macos-deep";
    }
    if anatomy_child(names, "Versions").is_some() {
        return "versioned-framework";
    }
    "shallow"
}

fn bundle_role(bundle: &str) -> &'static str {
    let segments: Vec<&str> = bundle.split('/').collect();
    let name = lower(segments.last().copied().unwrap_or(""));
    let container = if segments.len() >= 2 { Some(segments[segments.len() - 2]) } else { None };
    if name.ends_with(".appex") {
        return "app-extension";
    }
    if name.ends_with(".xpc") {
        return "xpc-service";
    }
    if name.ends_with(".framework") {
        return "framework";
    }
    if name.ends_with(".systemextension") {
        return "system-extension";
    }
    if name.ends_with(".dext") {
        return "driver-extension";
    }
    if name.ends_with(".bundle") {
        if anatomy_name_is(container.unwrap_or(""), "PlugIns") {
            return "plug-in";
        }
        return if anatomy_name_is(container.unwrap_or(""), "Resources") {
            "resource-bundle"
        } else {
            "bundle"
        };
    }
    if !name.ends_with(".app") {
        return "plug-in";
    }
    let third = if segments.len() >= 3 { Some(segments[segments.len() - 3]) } else { None };
    if anatomy_name_is(container.unwrap_or(""), "LoginItems") && anatomy_name_is(third.unwrap_or(""), "Library") {
        return "login-item";
    }
    if anatomy_name_is(container.unwrap_or(""), "Helpers") {
        return "helper-application";
    }
    "nested-application"
}

fn direct_files(directory: &str, tree: &Tree) -> Vec<String> {
    let mut out: Vec<String> = tree
        .children
        .get(directory)
        .map(|names| {
            names
                .iter()
                .map(|name| join_path(directory, name))
                .filter(|path| tree.files.contains_key(path))
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| js_cmp(a, b));
    out
}

fn named_child(tree: &Tree, directory: &str, expected: &str) -> Option<String> {
    anatomy_child(tree.children.get(directory), expected).map(|name| join_path(directory, &name))
}

fn content_directories(bundle: &str, layout: &str, tree: &Tree) -> Vec<String> {
    let directory = directory_of(bundle);
    if layout == "macos-deep" {
        return named_child(tree, &directory, "Contents").into_iter().collect();
    }
    if layout == "shallow" {
        return vec![directory];
    }
    let Some(versions) = named_child(tree, &directory, "Versions") else {
        return Vec::new();
    };
    let mut out: Vec<String> = tree
        .children
        .get(&versions)
        .map(|names| {
            names
                .iter()
                .filter(|version| !anatomy_name_is(version, "Current"))
                .map(|version| join_path(&versions, version))
                .filter(|version| tree.directories.contains(version))
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| js_cmp(a, b));
    out
}

fn info_plist_path(bundle: &str, layout: &str, tree: &Tree) -> Option<String> {
    let directories = content_directories(bundle, layout, tree);
    if directories.len() != 1 {
        return None;
    }
    let directory = &directories[0];
    let parent = if layout == "versioned-framework" {
        named_child(tree, directory, "Resources")?
    } else {
        directory.clone()
    };
    let info = named_child(tree, &parent, "Info.plist")?;
    if tree.files.contains_key(&info) {
        Some(info)
    } else {
        None
    }
}

fn executable_candidates(bundle: &str, layout: &str, tree: &Tree) -> Vec<String> {
    content_directories(bundle, layout, tree)
        .iter()
        .flat_map(|directory| {
            let executable_directory = if layout == "macos-deep" {
                named_child(tree, directory, "MacOS")
            } else {
                Some(directory.clone())
            };
            match executable_directory {
                Some(dir) => direct_files(&dir, tree),
                None => Vec::new(),
            }
        })
        .filter(|path| {
            tree.files
                .get(path)
                .map(|component| is_mach_o_format(&component.format))
                .unwrap_or(false)
        })
        .collect()
}

fn signing_paths(bundle: &str, layout: &str, tree: &Tree) -> Vec<String> {
    let mut out: Vec<String> = content_directories(bundle, layout, tree)
        .iter()
        .flat_map(|directory| {
            let signature = named_child(tree, directory, "_CodeSignature");
            vec![
                signature.and_then(|sig| named_child(tree, &sig, "CodeResources")),
                named_child(tree, directory, "embedded.provisionprofile"),
                named_child(tree, directory, "embedded.mobileprovision"),
            ]
        })
        .flatten()
        .filter(|path| tree.files.contains_key(path))
        .collect();
    out.sort_by(|a, b| js_cmp(a, b));
    out
}

fn detect_bundles(entries: &[Entry], roots: &[String]) -> Vec<Bundle> {
    let mut paths: BTreeSet<String> = roots.iter().cloned().collect();
    for entry in entries {
        if is_sidecar(&entry.path) {
            continue;
        }
        let Some(root) = roots.iter().find(|candidate| is_within(&entry.path, candidate)) else {
            continue;
        };
        let segments: Vec<&str> = entry.path.split('/').collect();
        let start = if root == "." { 0 } else { root.split('/').count() };
        for index in start..segments.len() {
            let leaf = index == segments.len() - 1;
            if bundle_extension().is_match(segments[index]) && (!leaf || entry.kind == "directory") {
                paths.insert(segments[..=index].join("/"));
            }
        }
    }
    let tree = index_tree(entries);
    let mut sorted: Vec<String> = paths.iter().cloned().collect();
    sorted.sort_by(|a, b| js_cmp(a, b));
    sorted
        .into_iter()
        .map(|path| {
            let layout = bundle_layout(&path, &tree);
            Bundle {
                parent_path: enclosing_bundle(&path, &paths),
                role: if roots.contains(&path) { "application".to_string() } else { bundle_role(&path).to_string() },
                role_basis: "path-convention".to_string(),
                info_plist_path: info_plist_path(&path, layout, &tree),
                executable_candidates: executable_candidates(&path, layout, &tree),
                signing_paths: signing_paths(&path, layout, &tree),
                layout: layout.to_string(),
                path,
            }
        })
        .collect()
}

fn platforms_of(bundles: &[Bundle]) -> Vec<&'static str> {
    let mut platforms: BTreeSet<&'static str> = BTreeSet::new();
    for bundle in bundles {
        if bundle.role != "application" {
            continue;
        }
        if bundle.layout == "macos-deep" {
            platforms.insert("macos");
        } else if bundle.layout == "shallow" && bundle.info_plist_path.is_some() {
            platforms.insert("ios");
        }
    }
    platforms.into_iter().collect()
}

// ---------------------------------------------------------------------------
// Native conventions (domain/nativeConvention.ts)
// ---------------------------------------------------------------------------

fn native_runtime_convention(path: &str) -> Option<&'static str> {
    const REACT_NATIVE: &[&str] = &[
        "react.framework",
        "reactnative.framework",
        "libreactnative.so",
        "libreactnativejni.so",
        "libhermes_executor.so",
        "libhermes.so",
        "hermes.framework",
    ];
    const FLUTTER: &[&str] = &["libflutter.so", "flutter.framework"];
    const UNITY: &[&str] = &["libunity.so", "unityframework.framework"];
    for segment in path.split('/') {
        let folded = lower(segment);
        if REACT_NATIVE.contains(&folded.as_str()) {
            return Some("react-native");
        }
        if FLUTTER.contains(&folded.as_str()) {
            return Some("flutter");
        }
        if UNITY.contains(&folded.as_str()) {
            return Some("unity");
        }
    }
    None
}

fn is_swift_runtime_library(path: &str) -> bool {
    static CELL: OnceLock<Regex> = OnceLock::new();
    let pattern = re(&CELL, r"^libswift[^\n\r  ]+\.dylib$");
    path.split('/').any(|segment| pattern.is_match(&lower(segment)))
}

// ---------------------------------------------------------------------------
// Bridge candidate budget (domain/bridgeCandidateProjection.ts)
// ---------------------------------------------------------------------------

const MAX_BRIDGE_CANDIDATE_JSON_BYTES: u64 = 2 * 1024 * 1024;

fn json_len(text: &str) -> u64 {
    serde_json::to_string(text).expect("string json").len() as u64
}

struct CandidateGroup<'a> {
    left: Vec<&'a Component>,
    right: Vec<&'a Component>,
}

fn bridge_basis(path: &str) -> &'static str {
    match native_runtime_convention(path) {
        Some("react-native") => "react-native-convention",
        Some("flutter") => "flutter-convention",
        Some("unity") => "unity-convention",
        _ => "javascript-and-native-content",
    }
}

type Prepared<'a> = (Vec<(&'a Component, u64)>, Vec<(&'a Component, u64)>);

fn project_cartesian_candidates(groups: &[CandidateGroup<'_>]) -> (Vec<Value>, Value) {
    let total: u64 = groups.iter().map(|g| (g.left.len() * g.right.len()) as u64).sum();
    let prepared: Vec<Prepared<'_>> = groups
        .iter()
        .map(|group| {
            let left = group.left.iter().map(|c| (*c, json_len(&c.path))).collect();
            let right = group
                .right
                .iter()
                .map(|c| {
                    let empty = format!(
                        "{{\"source_path\":\"\",\"native_path\":{},\"basis\":{}}}",
                        serde_json::to_string(&c.path).unwrap(),
                        serde_json::to_string(bridge_basis(&c.path)).unwrap()
                    );
                    (*c, empty.len() as u64 - 2)
                })
                .collect();
            (left, right)
        })
        .collect();
    let mut estimated_full: u64 = 2 + total.saturating_sub(1);
    for (left, right) in &prepared {
        let row_overhead: u64 = right.iter().map(|(_, bytes)| *bytes).sum();
        let path_bytes: u64 = left.iter().map(|(_, bytes)| *bytes).sum();
        estimated_full += left.len() as u64 * row_overhead + right.len() as u64 * path_bytes;
    }
    let emit_all = estimated_full <= MAX_BRIDGE_CANDIDATE_JSON_BYTES;
    let mut candidates: Vec<Value> = Vec::new();
    let mut retained: u64 = 2;
    'outer: for (left, right) in &prepared {
        for (left_component, path_bytes) in left {
            for (right_component, row_overhead) in right {
                let candidate_bytes = row_overhead + path_bytes;
                let additional = candidate_bytes + if candidates.is_empty() { 0 } else { 1 };
                if !emit_all && retained + additional > MAX_BRIDGE_CANDIDATE_JSON_BYTES {
                    break 'outer;
                }
                candidates.push(json!({
                    "source_path": left_component.path,
                    "native_path": right_component.path,
                    "basis": bridge_basis(&right_component.path),
                }));
                retained += additional;
            }
        }
    }
    let coverage = json!({
        "status": if candidates.len() as u64 == total { "complete" } else { "partial" },
        "total_candidates": total,
        "emitted_candidates": candidates.len(),
        "omitted_candidates": total - candidates.len() as u64,
    });
    (candidates, coverage)
}

fn identify_bridge_candidates(
    scripts: &[Component],
    native: &[Component],
    roots: &[String],
) -> (Vec<Value>, Value) {
    let owner = |path: &str| roots.iter().find(|root| is_within(path, root)).cloned();
    let mut script_groups: Vec<(Option<String>, Vec<&Component>)> = Vec::new();
    for script in scripts {
        let root = owner(&script.path);
        match script_groups.last_mut() {
            Some((last_root, left)) if *last_root == root => left.push(script),
            _ => script_groups.push((root, vec![script])),
        }
    }
    let mut native_by_root: HashMap<Option<String>, Vec<&Component>> = HashMap::new();
    for item in native {
        native_by_root.entry(owner(&item.path)).or_default().push(item);
    }
    let groups: Vec<CandidateGroup<'_>> = script_groups
        .into_iter()
        .map(|(root, left)| CandidateGroup {
            right: native_by_root.get(&root).cloned().unwrap_or_default(),
            left,
        })
        .collect();
    project_cartesian_candidates(&groups)
}

// ---------------------------------------------------------------------------
// Projection (domain/apple/appleApplication.ts)
// ---------------------------------------------------------------------------

const APPLE_ROOT_FORMATS: &[&str] = &["ipa", "directory", "zip", "dmg"];

fn deduplicate_components(values: Vec<Component>) -> Vec<Component> {
    let mut by_path: BTreeMap<String, Component> = BTreeMap::new();
    for value in values {
        by_path.insert(value.path.clone(), value);
    }
    let mut out: Vec<Component> = by_path.into_values().collect();
    out.sort_by(|a, b| js_cmp(&a.path, &b.path));
    out
}

fn last_segment(path: &str) -> &str {
    path.split('/').next_back().unwrap_or("")
}

fn framework_segment() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(&CELL, r"\.framework/")
}

fn native_library_suffix() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(&CELL, r"(?i)\.(?:dylib|so)$")
}

/// The projection result plus the facts the Evidence wrapper needs.
pub struct AppleProjection {
    pub result: Value,
    pub root_sha256: String,
    pub source_evidence_ids: Vec<String>,
    pub limitations: Vec<String>,
}

pub fn project_apple_application(parsed: &ParsedInventory) -> Result<AppleProjection, NativeError> {
    let inventory = &parsed.inventory;
    let root_format = APPLE_ROOT_FORMATS
        .iter()
        .find(|candidate| **candidate == inventory.manifest.root_format)
        .copied()
        .ok_or_else(|| {
            input_error(format!(
                "Apple application projection requires IPA, directory, ZIP, or DMG inventory Evidence (got {})",
                inventory.manifest.root_format
            ))
        })?;
    let nodes: HashMap<&str, &Node> = inventory.nodes.iter().map(|n| (n.artifact_id.as_str(), n)).collect();
    let mut entries: Vec<Entry> = Vec::new();
    for occurrence in inventory.occurrences.iter().filter(|o| o.logical_path != ".") {
        match &occurrence.artifact_id {
            None => entries.push(Entry {
                path: occurrence.logical_path.clone(),
                kind: occurrence.entry_kind.clone(),
                component: None,
            }),
            Some(id) => {
                let node = nodes
                    .get(id.as_str())
                    .ok_or_else(|| input_error("Apple application occurrence has no artifact node"))?;
                entries.push(Entry {
                    path: occurrence.logical_path.clone(),
                    kind: occurrence.entry_kind.clone(),
                    component: Some(Component {
                        path: occurrence.logical_path.clone(),
                        artifact_id: node.artifact_id.clone(),
                        sha256: node.sha256.clone(),
                        format: occurrence.artifact_format.clone(),
                    }),
                });
            }
        }
    }
    let inventoried: Vec<Component> = entries.iter().filter_map(|e| e.component.clone()).collect();
    let subject_name = parsed
        .evidence
        .first()
        .and_then(|e| e.subject.as_ref())
        .map(|s| s.name.clone())
        .unwrap_or_default();
    let roots = application_roots(&entries, &subject_name, root_format);
    let (all, unattributed) = if root_format == "ipa" {
        (inventoried.clone(), 0usize)
    } else {
        let visible: Vec<Component> = inventoried.iter().filter(|c| !is_sidecar(&c.path)).cloned().collect();
        let attributed: Vec<Component> = visible
            .iter()
            .filter(|c| roots.iter().any(|root| is_within(&c.path, root)))
            .cloned()
            .collect();
        let unattributed = visible.len() - attributed.len();
        (attributed, unattributed)
    };
    let bundles = detect_bundles(&entries, &roots);
    let within_app = |path: &str| roots.iter().any(|root| is_within(path, root));
    let matching = |predicate: &dyn Fn(&str) -> bool| -> Vec<Component> {
        entries
            .iter()
            .filter_map(|entry| match &entry.component {
                Some(component)
                    if entry.kind == "file"
                        && !is_sidecar(&entry.path)
                        && within_app(&entry.path)
                        && predicate(&entry.path) =>
                {
                    Some(component.clone())
                }
                _ => None,
            })
            .collect()
    };
    let bundle_metadata: Vec<Component> =
        all.iter().filter(|c| anatomy_name_is(last_segment(&c.path), "Info.plist")).cloned().collect();
    let executables: Vec<Component> = all
        .iter()
        .filter(|c| within_app(&c.path) && is_mach_o_format(&c.format))
        .cloned()
        .collect();
    let frameworks: Vec<Component> = all.iter().filter(|c| framework_segment().is_match(&c.path)).cloned().collect();
    let native_libraries: Vec<Component> =
        all.iter().filter(|c| native_library_suffix().is_match(&c.path)).cloned().collect();
    let javascript: Vec<Component> = all.iter().filter(|c| c.format == "javascript-bundle").cloned().collect();
    let signing: Vec<Component> = all
        .iter()
        .filter(|c| {
            anatomy_tail_matches(&c.path, &["_CodeSignature", "CodeResources"])
                || anatomy_name_is(last_segment(&c.path), "embedded.mobileprovision")
                || anatomy_name_is(last_segment(&c.path), "embedded.provisionprofile")
        })
        .cloned()
        .collect();
    let privileged_helpers =
        matching(&|path| anatomy_tail_matches(path, &["Contents", "Library", "LaunchServices", "*"]));
    let launchd_plists: Vec<Value> = matching(&|path| {
        path.ends_with(".plist")
            && (anatomy_tail_matches(path, &["Contents", "Library", "LaunchAgents", "*"])
                || anatomy_tail_matches(path, &["Contents", "Library", "LaunchDaemons", "*"]))
    })
    .into_iter()
    .map(|component| {
        let daemon = component.path.split('/').any(|segment| anatomy_name_is(segment, "LaunchDaemons"));
        let mut value = serde_json::to_value(&component).expect("component json");
        value["domain"] = json!(if daemon { "daemon" } else { "agent" });
        value
    })
    .collect();
    let helpers = matching(&|path| anatomy_tail_matches(path, &["Contents", "Helpers", "*"]));

    let mut families: BTreeSet<&'static str> = BTreeSet::new();
    if all.iter().any(|c| is_mach_o_format(&c.format)) {
        families.insert("native");
    }
    if all.iter().any(|c| is_swift_runtime_library(&c.path)) {
        families.insert("swift-objective-c");
    }
    if all.iter().any(|c| c.format == "javascript-bundle") {
        families.insert("javascript");
    }
    for component in &all {
        if let Some(convention) = native_runtime_convention(&component.path) {
            families.insert(convention);
        }
    }
    let mut runtime_families: Vec<&'static str> = families.into_iter().collect();
    runtime_families.sort_by(|a, b| js_cmp(a, b));

    let native_for_bridge = deduplicate_components(
        executables.iter().chain(native_libraries.iter()).cloned().collect(),
    );
    let (bridge_candidates, bridge_coverage) = identify_bridge_candidates(&javascript, &native_for_bridge, &roots);

    let uninventoried_image = root_format == "dmg" && inventory.occurrences.len() == 1;
    let complete = inventory.complete && !uninventoried_image;
    let sidecars = entries.iter().any(|e| is_sidecar(&e.path));
    let symlink_present = entries.iter().any(|e| e.kind == "symlink");
    let bridge_partial = bridge_coverage["status"] == "partial";
    let limitations = projection_limitations(
        inventory.complete,
        uninventoried_image,
        &roots,
        &bundles,
        sidecars,
        symlink_present,
        unattributed,
        &bridge_coverage,
    );

    let mut source_evidence_ids: Vec<String> =
        parsed.evidence.iter().map(|e| e.evidence_id.clone()).collect();
    source_evidence_ids.sort_by(|a, b| js_cmp(a, b));
    let mut symlinks: Vec<String> =
        entries.iter().filter(|e| e.kind == "symlink").map(|e| e.path.clone()).collect();
    symlinks.sort_by(|a, b| js_cmp(a, b));

    let without_id = json!({
        "root_sha256": inventory.manifest.root_sha256,
        "root_format": root_format,
        "platforms": platforms_of(&bundles),
        "source_evidence_ids": source_evidence_ids,
        "application_roots": roots,
        "bundles": bundles,
        "components": {
            "bundle_metadata": bundle_metadata,
            "executables": executables,
            "frameworks": frameworks,
            "native_libraries": native_libraries,
            "javascript": javascript,
            "signing": signing,
            "privileged_helpers": privileged_helpers,
            "launchd_plists": launchd_plists,
            "helpers": helpers,
        },
        "symlinks": symlinks,
        "runtime_families": runtime_families,
        "bridge_candidates": bridge_candidates,
        "bridge_candidate_coverage": bridge_coverage,
        "coverage": {
            "status": if complete && !bridge_partial { "complete-within-inventory" } else { "partial" },
            "inventory_complete": inventory.complete,
        },
        "limitations": limitations,
    });
    let projection_id = format!("aap_{}", digest(&without_id));
    let mut result = Map::new();
    result.insert("projection_id".to_string(), json!(projection_id));
    for (key, value) in without_id.as_object().expect("object") {
        result.insert(key.clone(), value.clone());
    }
    Ok(AppleProjection {
        result: Value::Object(result),
        root_sha256: inventory.manifest.root_sha256.clone(),
        source_evidence_ids,
        limitations,
    })
}

#[allow(clippy::too_many_arguments)]
fn projection_limitations(
    complete: bool,
    uninventoried_image: bool,
    roots: &[String],
    bundles: &[Bundle],
    sidecars: bool,
    symlinks: bool,
    unattributed: usize,
    bridge_coverage: &Value,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if !complete {
        out.push("Source inventory pages are incomplete; absence is unknown.".to_string());
    }
    if uninventoried_image {
        out.push("The DMG's contents were not inventoried on this host; bundle absence is unknown.".to_string());
    }
    if roots.is_empty() {
        out.push(
            "No application bundle (Payload/*.app or *.app/Contents) was present in the supplied inventory pages."
                .to_string(),
        );
    }
    if bundles
        .iter()
        .any(|b| b.layout == "versioned-framework" && b.info_plist_path.is_none())
    {
        out.push("A versioned framework has several version directories or no Versions/*/Resources/Info.plist; the Info.plist that Versions/Current selects is unknown because symlink targets are not inventoried.".to_string());
    }
    if symlinks {
        out.push("Symlinks are reported by path only; their targets are not inventoried, so bundles are reported at their real paths.".to_string());
    }
    if unattributed > 0 {
        out.push(format!(
            "{unattributed} inventoried entries outside every application root are not attributed to the application."
        ));
    }
    if sidecars {
        out.push("AppleDouble sidecar entries (._* files and __MACOSX/) describe neighbouring files and are excluded from bundle roles.".to_string());
    }
    if bridge_coverage["status"] == "partial" {
        out.push(format!(
            "Bridge candidate pairs exceeded the projection safety budget; {} hypotheses are omitted. Component arrays still include every component from the supplied inventory pages.",
            bridge_coverage["omitted_candidates"]
        ));
    }
    out.extend(
        [
            "Bundle roles follow path conventions. Read each info_plist_path with inspect_plist for CFBundleExecutable, identifiers, and declared services.",
            "Bundle identifiers and signing claims require dedicated plist and CMS parsing; this projection reports only exact paths and hashes.",
            "Runtime families are inferred from inventory formats and bounded framework path conventions, not observed runtime loading.",
            "Generic framework and dylib paths do not establish Swift or Objective-C; this inventory projection does not decode language metadata.",
            "Bridge candidates are path-based hypotheses, not observed runtime calls.",
            "A bridge basis is inferred from the native path and is repeated for every managed component.",
        ]
        .map(String::from),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracewise_domain::evidence::{
        create_evidence, DigestSha256, EvidenceAuthority, EvidenceConfidence, EvidenceObservation,
        EvidenceProvider, EvidenceSubject,
    };

    /// Root-only DMG inventory, as REA produces on hosts that cannot mount disk images.
    /// [Não verificável] against the oracle: REA's DMG reader needs macOS `hdiutil`.
    #[test]
    fn dmg_without_mounted_contents_is_partial() {
        let sha = "ab".repeat(32);
        let artifact_id = artifact_id_for_content(&sha);
        let occurrence_id = occurrence_id_for_location(&artifact_id, ".", "file");
        let node = Node {
            artifact_id: artifact_id.clone(),
            format: "file".to_string(),
            sha256: sha.clone(),
            size: 1024,
            media_type: None,
            architecture: None,
            content_state: "materialized".to_string(),
            limitations: Vec::new(),
        };
        let occurrence = Occurrence {
            occurrence_id,
            artifact_id: Some(artifact_id.clone()),
            parent_occurrence_id: None,
            logical_path: ".".to_string(),
            entry_kind: "file".to_string(),
            artifact_kind: "container".to_string(),
            artifact_format: "dmg".to_string(),
            declared_size: Some(1024),
            compressed_size: None,
            executable: false,
            encrypted: false,
            hash_status: "verified".to_string(),
            source_location: None,
            limitations: Vec::new(),
        };
        let graph_sha256 = artifact_graph_digest(std::slice::from_ref(&node), std::slice::from_ref(&occurrence), &[], &[]);
        let manifest = Manifest {
            manifest_id: artifact_manifest_id(&artifact_id, &graph_sha256),
            root_artifact_id: artifact_id,
            root_sha256: sha.clone(),
            root_format: "dmg".to_string(),
            graph_sha256,
            node_count: 1,
            occurrence_count: 1,
            edge_count: 0,
        };
        let inventory = json!({
            "manifest": manifest,
            "nodes": [node],
            "occurrences": [occurrence],
            "edges": [],
            "provenance": [],
            "integrity_contradictions": [],
            "limitations": [],
        });
        let evidence = create_evidence(
            Some(EvidenceSubject {
                name: "Fixture.dmg".to_string(),
                digest: DigestSha256 { sha256: sha },
                format: "dmg".to_string(),
                architecture: None,
                local_path: "/tmp/Fixture.dmg".to_string(),
            }),
            EvidenceProvider { id: "rea-artifact-graph".into(), name: "REA safe artifact graph provider".into(), version: Some("1".into()) },
            EvidenceObservation {
                predicate_type: None,
                operation: "inventory_artifact".to_string(),
                parameters: json!({}),
                normalized_result: inventory,
                raw_result: None,
                analysis_profile: None,
                confidence: Some(EvidenceConfidence::Observed),
                authority: Some(EvidenceAuthority::ShippedArtifact),
                environment: None,
                limitations: Some(Vec::new()),
                locations: None,
                evidence_links: None,
            },
        )
        .expect("evidence");
        let parsed = parse_artifact_inventory_evidence(&[evidence]).expect("inventory");
        let projection = project_apple_application(&parsed).expect("projection");
        assert_eq!(projection.result["root_format"], "dmg");
        assert_eq!(projection.result["coverage"]["status"], "partial");
        assert_eq!(projection.result["coverage"]["inventory_complete"], true);
        assert!(projection
            .limitations
            .iter()
            .any(|text| text.starts_with("The DMG's contents were not inventoried on this host")));
        assert!(projection
            .limitations
            .iter()
            .any(|text| text.starts_with("No application bundle")));
    }

    #[test]
    fn js_order_matches_utf16_code_units() {
        // U+FF5E (BMP) sorts after U+1F600 (astral, surrogate pair D83D..) in UTF-16 order.
        assert_eq!(js_cmp("\u{ff5e}", "\u{1f600}"), Ordering::Greater);
        assert_eq!(code_point_cmp("\u{ff5e}", "\u{1f600}"), Ordering::Less);
    }
}
