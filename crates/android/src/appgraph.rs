//! `project_android_application_graph`: execution-free Android application
//! inventory over authenticated APK inventory Evidence (REA
//! `domain/android/androidApplication.ts`, `domain/artifactInventoryEvidence.ts`,
//! `domain/artifactIdentity.ts`, `domain/bridgeCandidateProjection.ts`,
//! `domain/nativeConvention.ts`).

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;
use serde_json::{json, Value};
use tracewise_domain::canonical::canonical_sha256;
use tracewise_domain::evidence::Evidence;

/// Failure kinds mirror REA's `TypeError` (input) and protocol errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionError {
    Input(Vec<String>),
    Protocol(String),
}

type PR<T> = Result<T, ProjectionError>;

fn input(message: impl Into<String>) -> ProjectionError {
    ProjectionError::Input(vec![message.into()])
}

fn digest(value: &Value) -> PR<String> {
    canonical_sha256(value).map_err(|e| ProjectionError::Protocol(e.to_string()))
}

fn canonical_text(value: &Value) -> PR<String> {
    tracewise_domain::canonical::canonical_json(value).map_err(|e| ProjectionError::Protocol(e.to_string()))
}

/// `artifactIdForContent`.
pub fn artifact_id_for_content(sha256: &str) -> PR<String> {
    Ok(format!("art_{}", digest(&json!({ "sha256": sha256 }))?))
}

fn occurrence_id_for_location(root_artifact_id: &str, logical_path: &str, entry_kind: &str) -> PR<String> {
    if logical_path == "." {
        Ok(format!("occ_{}", digest(&json!({ "root": root_artifact_id }))?))
    } else {
        Ok(format!(
            "occ_{}",
            digest(&json!({ "root_artifact_id": root_artifact_id, "logical_path": logical_path, "entry_kind": entry_kind }))?
        ))
    }
}

fn artifact_edge_id(edge: &Value, occurrence: &Value) -> PR<String> {
    Ok(format!(
        "edge_{}",
        digest(&json!({
            "parent_artifact_id": edge["parent_artifact_id"],
            "child_artifact_id": occurrence["artifact_id"],
            "relation": edge["relation"],
            "occurrence_id": edge["occurrence_id"],
            "logical_path": occurrence["logical_path"],
        }))?
    ))
}

struct Inventory {
    manifest: Value,
    nodes: Vec<Value>,
    occurrences: Vec<Value>,
    edges: Vec<Value>,
    contradictions: Value,
    complete: bool,
}

fn arr<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value.get(key).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

fn merge_exact(map: &mut BTreeMap<String, Value>, key: String, value: Value, label: &str) -> PR<()> {
    if let Some(previous) = map.get(&key) {
        if canonical_text(previous)? != canonical_text(&value)? {
            return Err(input(format!("Artifact inventory has conflicting {label} pages")));
        }
    }
    map.insert(key, value);
    Ok(())
}

fn assert_unique(values: Vec<&str>, label: &str) -> PR<()> {
    let set: BTreeSet<&str> = values.iter().copied().collect();
    if set.len() != values.len() {
        return Err(input(format!("Artifact inventory contains a duplicate {label}")));
    }
    Ok(())
}

fn validate_page(inventory: &Value) -> PR<()> {
    assert_unique(arr(inventory, "nodes").iter().filter_map(|n| n["artifact_id"].as_str()).collect(), "node ID")?;
    assert_unique(arr(inventory, "occurrences").iter().filter_map(|n| n["occurrence_id"].as_str()).collect(), "occurrence ID")?;
    assert_unique(arr(inventory, "occurrences").iter().filter_map(|n| n["logical_path"].as_str()).collect(), "logical path")?;
    assert_unique(arr(inventory, "edges").iter().filter_map(|n| n["edge_id"].as_str()).collect(), "edge ID")?;
    for node in arr(inventory, "nodes") {
        if node["artifact_id"].as_str() != Some(artifact_id_for_content(node["sha256"].as_str().unwrap_or_default())?.as_str()) {
            return Err(input("Artifact node ID is not content-addressed"));
        }
    }
    Ok(())
}

struct Page {
    evidence: Evidence,
    inventory: Value,
}

fn parse_page(raw: &Value) -> PR<Page> {
    let evidence = tracewise_managed::workflows::parse_evidence(raw).map_err(|e| input(e.to_string()))?;
    let inventory_evidence: Value = if evidence.operation == "inventory_artifact" {
        serde_json::to_value(&evidence).map_err(|e| ProjectionError::Protocol(e.to_string()))?
    } else if evidence.operation == "inspect_artifact" {
        evidence.normalized_result["substeps"]
            .as_array()
            .and_then(|s| s.first())
            .and_then(|s| s.get("evidence"))
            .cloned()
            .ok_or_else(|| input("Artifact comparison requires inspect_artifact Evidence"))?
    } else {
        return Err(input("Artifact comparison requires inspect_artifact Evidence"));
    };
    let mut inventory = inventory_evidence["normalized_result"].clone();
    let problems = crate::schema::validate_inventory(&inventory);
    if !problems.is_empty() {
        return Err(ProjectionError::Input(
            problems
                .into_iter()
                .map(|(path, message)| {
                    format!("A nested value failed validation at {}: {message}", if path.is_empty() { "its root".to_string() } else { path })
                })
                .collect(),
        ));
    }
    if let Some(object) = inventory.as_object_mut() {
        object.entry("integrity_contradictions").or_insert(json!([]));
    }
    let subject = &inventory_evidence["subject"];
    if subject.is_null()
        || subject["digest"]["sha256"] != inventory["manifest"]["root_sha256"]
        || subject["format"] != inventory["manifest"]["root_format"]
    {
        return Err(input("Artifact inventory Evidence subject does not match its root digest"));
    }
    validate_page(&inventory)?;
    Ok(Page { evidence, inventory })
}

fn compare_code_points(a: &str, b: &str) -> std::cmp::Ordering {
    a.cmp(b)
}

fn assemble(pages: &[Page]) -> PR<Inventory> {
    let first = pages.first().ok_or_else(|| input("Artifact inventory requires Evidence pages"))?;
    let manifest_json = canonical_text(&first.inventory["manifest"])?;
    let mut nodes: BTreeMap<String, Value> = BTreeMap::new();
    let mut occurrences: BTreeMap<String, Value> = BTreeMap::new();
    let mut paths: BTreeMap<String, Value> = BTreeMap::new();
    let mut edges: BTreeMap<String, Value> = BTreeMap::new();
    for page in pages {
        if canonical_text(&page.inventory["manifest"])? != manifest_json {
            return Err(input("Artifact inventory pages do not share one manifest"));
        }
        if canonical_text(&page.inventory["integrity_contradictions"])? != canonical_text(&first.inventory["integrity_contradictions"])? {
            return Err(input("Artifact inventory pages do not share integrity contradictions"));
        }
        for node in arr(&page.inventory, "nodes") {
            merge_exact(&mut nodes, node["artifact_id"].as_str().unwrap_or_default().to_string(), node.clone(), "node")?;
        }
        for occurrence in arr(&page.inventory, "occurrences") {
            merge_exact(&mut occurrences, occurrence["occurrence_id"].as_str().unwrap_or_default().to_string(), occurrence.clone(), "occurrence")?;
            merge_exact(&mut paths, occurrence["logical_path"].as_str().unwrap_or_default().to_string(), occurrence.clone(), "logical path")?;
        }
        for edge in arr(&page.inventory, "edges") {
            merge_exact(&mut edges, edge["edge_id"].as_str().unwrap_or_default().to_string(), edge.clone(), "edge")?;
        }
    }
    let mut node_values: Vec<Value> = nodes.into_values().collect();
    node_values.sort_by(|a, b| compare_code_points(a["artifact_id"].as_str().unwrap_or_default(), b["artifact_id"].as_str().unwrap_or_default()));
    let mut occurrence_values: Vec<Value> = occurrences.into_values().collect();
    occurrence_values.sort_by(|a, b| compare_code_points(a["logical_path"].as_str().unwrap_or_default(), b["logical_path"].as_str().unwrap_or_default()));
    let mut edge_values: Vec<Value> = edges.into_values().collect();
    edge_values.sort_by(|a, b| compare_code_points(a["edge_id"].as_str().unwrap_or_default(), b["edge_id"].as_str().unwrap_or_default()));
    let manifest = first.inventory["manifest"].clone();
    let complete = node_values.len() as u64 == manifest["node_count"].as_u64().unwrap_or(u64::MAX)
        && occurrence_values.len() as u64 == manifest["occurrence_count"].as_u64().unwrap_or(u64::MAX)
        && edge_values.len() as u64 == manifest["edge_count"].as_u64().unwrap_or(u64::MAX);
    let inventory = Inventory {
        manifest,
        nodes: node_values,
        occurrences: occurrence_values,
        edges: edge_values,
        contradictions: first.inventory["integrity_contradictions"].clone(),
        complete,
    };
    if inventory.complete {
        validate_complete(&inventory)?;
    }
    Ok(inventory)
}

fn validate_complete(inventory: &Inventory) -> PR<()> {
    let node_ids: BTreeSet<&str> = inventory.nodes.iter().filter_map(|n| n["artifact_id"].as_str()).collect();
    let occurrence_ids: BTreeSet<&str> = inventory.occurrences.iter().filter_map(|n| n["occurrence_id"].as_str()).collect();
    let root_id = inventory.manifest["root_artifact_id"].as_str().unwrap_or_default();
    let root_node = inventory.nodes.iter().find(|n| n["artifact_id"].as_str() == Some(root_id));
    if root_node.map(|n| &n["sha256"]) != Some(&inventory.manifest["root_sha256"]) {
        return Err(input("Artifact root node does not match its manifest digest"));
    }
    let root_occurrence = inventory.occurrences.iter().find(|o| o["logical_path"] == ".");
    if root_occurrence.map(|o| &o["artifact_id"]) != Some(&json!(root_id))
        || root_occurrence.map(|o| &o["artifact_format"]) != Some(&inventory.manifest["root_format"])
    {
        return Err(input("Artifact root occurrence does not match its manifest representation"));
    }
    for occurrence in &inventory.occurrences {
        if let Some(artifact) = occurrence["artifact_id"].as_str() {
            if !node_ids.contains(artifact) {
                return Err(input("Artifact occurrence references a missing node"));
            }
        }
        if let Some(parent) = occurrence["parent_occurrence_id"].as_str() {
            if !occurrence_ids.contains(parent) {
                return Err(input("Artifact occurrence references a missing parent"));
            }
        }
        let expected = occurrence_id_for_location(
            root_id,
            occurrence["logical_path"].as_str().unwrap_or_default(),
            occurrence["entry_kind"].as_str().unwrap_or_default(),
        )?;
        if occurrence["occurrence_id"].as_str() != Some(expected.as_str()) {
            return Err(input("Artifact occurrence ID does not match its identity"));
        }
    }
    let by_id: BTreeMap<&str, &Value> =
        inventory.occurrences.iter().filter_map(|o| o["occurrence_id"].as_str().map(|id| (id, o))).collect();
    for edge in &inventory.edges {
        let occurrence = edge["occurrence_id"].as_str().and_then(|id| by_id.get(id)).copied();
        let linked = node_ids.contains(edge["parent_artifact_id"].as_str().unwrap_or_default())
            && occurrence.and_then(|o| o["artifact_id"].as_str()).is_some_and(|a| node_ids.contains(a));
        if !linked {
            return Err(input("Artifact edge references a missing graph member"));
        }
        let occurrence = occurrence.expect("checked above");
        if edge["edge_id"].as_str() != Some(artifact_edge_id(edge, occurrence)?.as_str()) {
            return Err(input("Artifact edge ID does not match its identity"));
        }
    }
    for contradiction in inventory.contradictions.as_array().into_iter().flatten() {
        if !node_ids.contains(contradiction["parent_artifact_id"].as_str().unwrap_or_default())
            || !occurrence_ids.contains(contradiction["occurrence_id"].as_str().unwrap_or_default())
        {
            return Err(input("Integrity contradiction references a missing graph member"));
        }
        let expected = format!(
            "ic_{}",
            digest(&json!({
                "root_artifact_id": root_id,
                "logical_path": contradiction["logical_path"],
                "declared_sha256": contradiction["declared_sha256"],
                "observed_sha256": contradiction["observed_sha256"],
            }))?
        );
        if contradiction["contradiction_id"].as_str() != Some(expected.as_str()) {
            return Err(input("Integrity contradiction ID does not match its identity"));
        }
    }
    let graph_sha256 = digest(&json!({
        "nodes": inventory.nodes,
        "occurrences": inventory.occurrences,
        "edges": inventory.edges,
        "integrity_contradictions": inventory.contradictions,
    }))?;
    if inventory.manifest["graph_sha256"].as_str() != Some(graph_sha256.as_str()) {
        return Err(input("Artifact graph commitment does not match its members"));
    }
    let manifest_id = format!("agm_{}", digest(&json!({ "root_artifact_id": root_id, "graph_sha256": graph_sha256 }))?);
    if inventory.manifest["manifest_id"].as_str() != Some(manifest_id.as_str()) {
        return Err(input("Artifact manifest ID does not match its commitment"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Projection
// ---------------------------------------------------------------------------

const MAX_BRIDGE_CANDIDATE_JSON_BYTES: usize = 2 * 1024 * 1024;

fn native_runtime_convention(path: &str) -> Option<&'static str> {
    const REACT: [&str; 7] = [
        "react.framework",
        "reactnative.framework",
        "libreactnative.so",
        "libreactnativejni.so",
        "libhermes_executor.so",
        "libhermes.so",
        "hermes.framework",
    ];
    for segment in path.split('/') {
        let folded = segment.to_lowercase();
        if REACT.contains(&folded.as_str()) {
            return Some("react-native");
        }
        if folded == "libflutter.so" || folded == "flutter.framework" {
            return Some("flutter");
        }
        if folded == "libunity.so" || folded == "unityframework.framework" {
            return Some("unity");
        }
    }
    None
}

fn bridge_basis(path: &str, jni: &Regex) -> &'static str {
    match native_runtime_convention(path) {
        Some("react-native") => "react-native-convention",
        Some("flutter") => "flutter-convention",
        Some("unity") => "unity-convention",
        _ if jni.is_match(path) => "jni-library-convention",
        _ => "managed-and-native-content",
    }
}

fn json_len(value: &Value) -> usize {
    serde_json::to_string(value).map(|s| s.len()).unwrap_or(0)
}

/// `projectCartesianCandidates` for the single managed-by-native group.
fn bridge_candidates(managed: &[Value], native: &[Value]) -> (Vec<Value>, Value) {
    let jni = Regex::new(r"(?i)(?:^|/)lib/[^/]+/lib[^/]+\.so$").expect("regex");
    let total = managed.len() * native.len();
    let left: Vec<(&str, usize)> = managed
        .iter()
        .map(|m| {
            let path = m["path"].as_str().unwrap_or_default();
            (path, json_len(&json!(path)))
        })
        .collect();
    let right: Vec<(&str, &'static str, usize)> = native
        .iter()
        .map(|n| {
            let path = n["path"].as_str().unwrap_or_default();
            let basis = bridge_basis(path, &jni);
            let empty = json!({ "managed_path": "", "native_path": path, "basis": basis });
            (path, basis, json_len(&empty) - 2)
        })
        .collect();
    let mut estimated = 2 + total.saturating_sub(1);
    estimated += left.len() * right.iter().map(|r| r.2).sum::<usize>() + right.len() * left.iter().map(|l| l.1).sum::<usize>();
    let emit_all = estimated <= MAX_BRIDGE_CANDIDATE_JSON_BYTES;
    let mut candidates = Vec::new();
    let mut retained = 2usize;
    'outer: for (managed_path, path_bytes) in &left {
        for (native_path, basis, row_overhead) in &right {
            let candidate_bytes = row_overhead + path_bytes;
            let additional = candidate_bytes + usize::from(!candidates.is_empty());
            if !emit_all && retained + additional > MAX_BRIDGE_CANDIDATE_JSON_BYTES {
                break 'outer;
            }
            candidates.push(json!({ "managed_path": managed_path, "native_path": native_path, "basis": basis }));
            retained += additional;
        }
    }
    let coverage = json!({
        "status": if candidates.len() == total { "complete" } else { "partial" },
        "total_candidates": total,
        "emitted_candidates": candidates.len(),
        "omitted_candidates": total - candidates.len(),
    });
    (candidates, coverage)
}

fn matches(pattern: &'static str, path: &str) -> bool {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<HashMap<&'static str, Regex>>> = OnceLock::new();
    let mut cache = CACHE.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
    cache.entry(pattern).or_insert_with(|| Regex::new(pattern).expect("regex")).is_match(path)
}

/// Project exact APK paths and hashes without decoding or executing target code.
pub fn project_android_application(inventory_evidence: &[Value]) -> PR<(Value, Vec<String>, Option<Value>)> {
    if inventory_evidence.is_empty() {
        return Err(input("inventory_evidence must contain at least one Evidence record"));
    }
    let pages: Vec<Page> = inventory_evidence.iter().map(parse_page).collect::<PR<_>>()?;
    let inventory = assemble(&pages)?;
    if inventory.manifest["root_format"] != "apk" {
        return Err(input(format!(
            "Android application projection requires APK inventory Evidence; the inventory root format is {}. APK is chosen for a ZIP archive whose name ends in .apk.",
            inventory.manifest["root_format"].as_str().unwrap_or_default()
        )));
    }
    let nodes: BTreeMap<&str, &Value> = inventory.nodes.iter().filter_map(|n| n["artifact_id"].as_str().map(|id| (id, n))).collect();
    let mut all: Vec<Value> = Vec::new();
    for occurrence in &inventory.occurrences {
        let Some(artifact_id) = occurrence["artifact_id"].as_str() else { continue };
        if occurrence["logical_path"] == "." {
            continue;
        }
        let Some(node) = nodes.get(artifact_id) else {
            return Err(input("Android application occurrence has no artifact node"));
        };
        all.push(json!({
            "path": occurrence["logical_path"],
            "artifact_id": node["artifact_id"],
            "sha256": node["sha256"],
            "format": occurrence["artifact_format"],
        }));
    }
    let path_of = |c: &Value| c["path"].as_str().unwrap_or_default().to_string();
    let select = |pred: &dyn Fn(&Value) -> bool| -> Vec<Value> { all.iter().filter(|c| pred(c)).cloned().collect() };
    let manifests = select(&|c| matches(r"(?:^|/)AndroidManifest\.xml$", &path_of(c)));
    let resources = select(&|c| matches(r"(?:^|/)resources\.arsc$", &path_of(c)));
    let dex = select(&|c| matches(r"(?i)(?:^|/)[^/]+\.dex$", &path_of(c)));
    let jvm_classes = select(&|c| matches(r"(?i)(?:^|/)[^/]+\.class$", &path_of(c)));
    let native_libraries = select(&|c| c["format"] == "elf" || matches(r"(?i)(?:^|/)lib/[^/]+/[^/]+\.so$", &path_of(c)));
    let javascript = select(&|c| c["format"] == "javascript-bundle");
    let signing = select(&|c| matches(r"(?i)^META-INF/[^/]+\.(?:MF|RSA|DSA|EC|SF)$", &path_of(c)));
    let managed: Vec<Value> = dex.iter().chain(jvm_classes.iter()).cloned().collect();
    let (candidates, candidate_coverage) = bridge_candidates(&managed, &native_libraries);
    let mut limitations: Vec<String> = Vec::new();
    if !inventory.complete {
        limitations.push("Source inventory pages are incomplete; absence is unknown.".to_string());
    }
    limitations.push("Manifest, resource, signing, and bytecode semantics require a dedicated Android provider; this projection reports exact inventory paths and hashes only.".to_string());
    limitations.push("Runtime families are inferred from inventory formats and paths; filename suffixes do not establish valid DEX or JVM class bytes.".to_string());
    limitations.push("Bridge candidates are path-based hypotheses, not decoded JNI declarations or observed runtime calls.".to_string());
    limitations.push("A bridge basis is inferred from the native path and is repeated for every managed component.".to_string());
    limitations.push("ZIP inventory cannot see the APK Signing Block, so an empty signing array does not mean the APK is unsigned.".to_string());
    if !all.iter().any(|c| c["path"] == "AndroidManifest.xml") {
        limitations.push("No root AndroidManifest.xml occurrence was observed. The APK family comes from the .apk suffix of a ZIP archive, so these bytes may not be an APK.".to_string());
    }
    if candidate_coverage["status"] == "partial" {
        limitations.push(format!(
            "Bridge candidate pairs exceeded the projection safety budget; {} hypotheses are omitted. Component arrays still include every component from the supplied inventory pages.",
            candidate_coverage["omitted_candidates"]
        ));
    }
    let mut families: BTreeSet<&str> = BTreeSet::new();
    if all.iter().any(|c| path_of(c).to_lowercase().ends_with(".dex")) {
        families.insert("dalvik-art");
    }
    if all.iter().any(|c| path_of(c).to_lowercase().ends_with(".class")) {
        families.insert("java-kotlin");
    }
    if all.iter().any(|c| c["format"] == "elf") {
        families.insert("native");
    }
    if all.iter().any(|c| c["format"] == "javascript-bundle") {
        families.insert("javascript");
    }
    for component in &all {
        if let Some(convention) = native_runtime_convention(&path_of(component)) {
            families.insert(convention);
        }
    }
    let mut source_ids: Vec<String> = pages.iter().map(|p| p.evidence.evidence_id.clone()).collect();
    source_ids.sort();
    let without_id = json!({
        "root_sha256": inventory.manifest["root_sha256"],
        "root_format": "apk",
        "source_evidence_ids": source_ids,
        "components": {
            "manifests": manifests,
            "resources": resources,
            "dex": dex,
            "jvm_classes": jvm_classes,
            "native_libraries": native_libraries,
            "javascript": javascript,
            "signing": signing,
        },
        "runtime_families": families.into_iter().collect::<Vec<_>>(),
        "bridge_candidates": candidates,
        "bridge_candidate_coverage": candidate_coverage,
        "coverage": {
            "status": if inventory.complete && candidate_coverage["status"] == "complete" { "complete-within-inventory" } else { "partial" },
            "inventory_complete": inventory.complete,
        },
        "limitations": limitations,
    });
    let projection_id = digest(&without_id)?;
    let mut result = without_id;
    result["projection_id"] = json!(format!("adp_{projection_id}"));
    let first_subject = serde_json::to_value(&pages[0].evidence.subject).ok().filter(|s| !s.is_null());
    Ok((result, source_ids, first_subject))
}
