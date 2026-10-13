//! `compare_javascript_export_shapes` — exact static return-shape comparison.

use serde_json::{json, Value};
use tracewise_domain::evidence::Evidence;

use crate::error::JsError;
use crate::unicode::{compare_unicode_code_points, unique_sorted};

use super::feature_trace::application_graph;
use super::graph_seal::{canonical_text, digest_prefixed};
use super::workflow::workflow_evidence;

const INERT_LIMITATION: &str =
    "Return shapes are inferred from inert syntax and do not prove runtime behavior.";
const PAIRING_LIMITATION: &str =
    "Return variants are paired only by unique exact literal discriminants, never by source order.";
const DYNAMIC_LIMITATION: &str =
    "Dynamic values, incomplete object coverage, and ambiguous variants remain unknown.";
const PROBE_LIMITATION: &str = "This static comparison cannot establish runtime semantics; run behavioral probes directly against the relevant application versions when that evidence is required.";
const TRUNCATED_LIMITATION: &str =
    "Comparison output or source return-shape recovery reached an explicit limit.";
const PARTIAL_LIMITATION: &str =
    "At least one selector, graph, return shape, or property boundary is incomplete.";

pub fn compare_javascript_export_shapes(
    left: &Evidence,
    right: &Evidence,
    left_module_path: &str,
    left_export_name: &str,
    right_module_path: &str,
    right_export_name: &str,
) -> Result<Evidence, JsError> {
    if left.evidence_id == right.evidence_id {
        return Err(JsError::InvalidInput(
            "JavaScript export shape Evidence must be distinct".into(),
        ));
    }
    require_text("left_module_path", left_module_path)?;
    require_text("left_export_name", left_export_name)?;
    require_text("right_module_path", right_module_path)?;
    require_text("right_export_name", right_export_name)?;
    let left_graph = application_graph(left)?;
    let right_graph = application_graph(right)?;
    let left_selected = select_export(left, left_graph, left_module_path, left_export_name)?;
    let right_selected = select_export(right, right_graph, right_module_path, right_export_name)?;
    let left_shapes = retained_shapes(&left_selected);
    let right_shapes = retained_shapes(&right_selected);
    let pairing = pair_variants(&left_shapes, &right_shapes)?;
    let evidence_links = vec![left.evidence_id.clone(), right.evidence_id.clone()];
    let mut changes = build_changes(
        &left_selected,
        &right_selected,
        &pairing,
        &left_shapes,
        &right_shapes,
        &evidence_links,
    )?;
    sort_changes(&mut changes)?;
    let inventories = build_inventories(&pairing, &left_shapes, &right_shapes);
    let coverage = comparison_coverage(
        left_graph,
        right_graph,
        &left_selected,
        &right_selected,
        &left_shapes,
        &right_shapes,
        &pairing,
        &changes,
    );
    let status = coverage["status"].as_str().unwrap_or("partial");
    let limitations = comparison_limitations(&left_selected, &right_selected, status);
    let mut semantic = json!({
        "left": left_selected.selection,
        "right": right_selected.selection,
        "property_inventories": inventories,
        "summary": summarize(&changes),
        "changes": changes,
        "coverage": coverage,
        "evidence_links": evidence_links,
        "limitations": limitations,
    });
    let comparison_id = digest_prefixed("jesc_", &semantic)?;
    semantic
        .as_object_mut()
        .expect("object")
        .insert("comparison_id".into(), json!(comparison_id));
    let result_limitations = string_list(semantic.get("limitations").unwrap_or(&Value::Null));
    workflow_evidence(
        "compare_javascript_export_shapes",
        "rea.javascript-export-shape-comparison",
        json!({
            "left_evidence_id": left.evidence_id,
            "right_evidence_id": right.evidence_id,
            "left_module_path": left_module_path,
            "left_export_name": left_export_name,
            "right_module_path": right_module_path,
            "right_export_name": right_export_name,
        }),
        semantic,
        result_limitations,
        vec![left.evidence_id.clone(), right.evidence_id.clone()],
    )
}

struct Selected {
    selection: Value,
    projection: Option<Value>,
    observation_complete: bool,
    limitations: Vec<String>,
}

fn select_export(
    evidence: &Evidence,
    graph: &Value,
    module_path: &str,
    export_name: &str,
) -> Result<Selected, JsError> {
    let candidates = export_candidates(graph);
    let exact: Vec<&ExportCandidate> = candidates
        .iter()
        .filter(|candidate| candidate.module_path == module_path && candidate.export_name == export_name)
        .collect();
    let one: Vec<&ExportCandidate> = candidates
        .iter()
        .filter(|candidate| candidate.module_path == module_path || candidate.export_name == export_name)
        .collect();
    let pool: Vec<&ExportCandidate> = if !exact.is_empty() {
        exact.clone()
    } else if !one.is_empty() {
        one
    } else {
        candidates.iter().collect()
    };
    let base = selector_base(evidence, graph, module_path, export_name, &pool);
    if exact.is_empty() {
        return Ok(unresolved(
            base,
            "missing",
            Value::Null,
            vec![format!("No exact export binding matched {module_path}:{export_name}.")],
        ));
    }
    if exact.len() > 1 {
        return Ok(unresolved(
            base,
            "ambiguous",
            Value::Null,
            vec![format!(
                "Multiple exact export bindings matched {module_path}:{export_name}; none was selected."
            )],
        ));
    }
    let selected = exact[0];
    if !selected.trusted {
        return Ok(unresolved(
            base,
            "unavailable",
            json!(selected.node["node_id"].as_str().unwrap_or("")),
            vec!["The exact export binding lacks the expected static-analysis authority.".to_string()],
        ));
    }
    match return_shape_for(&selected.node, module_path, export_name) {
        ReturnShape::Unavailable(reason) => Ok(unresolved(
            base,
            "unavailable",
            json!(selected.node["node_id"].as_str().unwrap_or("")),
            vec![reason],
        )),
        ReturnShape::Ready { projection, observation_complete } => {
            let mut selection = base;
            selection["status"] = json!("selected");
            selection["selected_node_id"] = selected.node["node_id"].clone();
            Ok(Selected {
                selection,
                projection: Some(projection),
                observation_complete,
                limitations: Vec::new(),
            })
        }
    }
}

fn unresolved(mut base: Value, status: &str, selected_node_id: Value, limitations: Vec<String>) -> Selected {
    base["status"] = json!(status);
    base["selected_node_id"] = selected_node_id;
    Selected {
        selection: base,
        projection: None,
        observation_complete: false,
        limitations,
    }
}

fn selector_base(
    evidence: &Evidence,
    graph: &Value,
    module_path: &str,
    export_name: &str,
    candidates: &[&ExportCandidate],
) -> Value {
    json!({
        "evidence_id": evidence.evidence_id,
        "graph_id": graph["graph_id"],
        "requested_module_path": module_path,
        "requested_export_name": export_name,
        "candidates": candidates.iter().map(|candidate| json!({
            "node_id": candidate.node["node_id"],
            "module_path": candidate.module_path,
            "export_name": candidate.export_name,
            "matches_requested_module": candidate.module_path == module_path,
            "matches_requested_export": candidate.export_name == export_name,
        })).collect::<Vec<_>>(),
        "omitted_candidates": 0,
    })
}

struct ExportCandidate {
    node: Value,
    module_path: String,
    export_name: String,
    trusted: bool,
}

fn export_candidates(graph: &Value) -> Vec<ExportCandidate> {
    let mut candidates: Vec<ExportCandidate> = Vec::new();
    let nodes = graph["nodes"].as_array().cloned().unwrap_or_default();
    for node in nodes {
        let Some(observations) = node["observations"].as_array() else {
            continue;
        };
        for observation in observations {
            let properties = &observation["properties"];
            if properties["semantic_role"].as_str() != Some("export-binding") {
                continue;
            }
            let Some(module_path) = properties["module_path"].as_str() else {
                continue;
            };
            let Some(export_name) = properties["exported_name"].as_str() else {
                continue;
            };
            let trusted = observation["evidence"]["authority"].as_str() == Some("ast-static-analysis")
                && observation["evidence"]["state"].as_str() == Some("observed")
                && observation["evidence"]["extractor"]["operation"].as_str() == Some("recover-module-export");
            let key = format!(
                "{}\0{}\0{}",
                node["node_id"].as_str().unwrap_or(""),
                module_path,
                export_name
            );
            if let Some(existing) = candidates.iter_mut().find(|candidate| {
                format!(
                    "{}\0{}\0{}",
                    candidate.node["node_id"].as_str().unwrap_or(""),
                    candidate.module_path,
                    candidate.export_name
                ) == key
            }) {
                existing.trusted = existing.trusted || trusted;
            } else {
                candidates.push(ExportCandidate {
                    node: node.clone(),
                    module_path: module_path.to_string(),
                    export_name: export_name.to_string(),
                    trusted,
                });
            }
        }
    }
    candidates.sort_by(|left, right| {
        compare_unicode_code_points(
            &format!("{}\0{}\0{}", left.module_path, left.export_name, left.node["node_id"].as_str().unwrap_or("")),
            &format!("{}\0{}\0{}", right.module_path, right.export_name, right.node["node_id"].as_str().unwrap_or("")),
        )
    });
    candidates
}

enum ReturnShape {
    Ready { projection: Value, observation_complete: bool },
    Unavailable(String),
}

fn return_shape_for(node: &Value, module_path: &str, export_name: &str) -> ReturnShape {
    let observations = node["observations"].as_array().cloned().unwrap_or_default();
    let role: Vec<Value> = observations
        .into_iter()
        .filter(|observation| observation["properties"]["semantic_role"].as_str() == Some("export-return-shapes"))
        .collect();
    if role.iter().any(|observation| !projection_well_formed(&observation["properties"])) {
        return ReturnShape::Unavailable("The export return-shape observation is malformed.".into());
    }
    let matching: Vec<&Value> = role
        .iter()
        .filter(|observation| {
            observation["properties"]["module_path"].as_str() == Some(module_path)
                && observation["properties"]["exported_name"].as_str() == Some(export_name)
        })
        .collect();
    if matching.len() != 1 {
        return ReturnShape::Unavailable(if matching.is_empty() {
            "No exact static return-shape observation is available for the selected export.".into()
        } else {
            "Multiple static return-shape observations matched the selected export.".into()
        });
    }
    let observation = matching[0];
    let trusted = observation["evidence"]["authority"].as_str() == Some("static-relationship-inference")
        && observation["evidence"]["state"].as_str() == Some("inferred")
        && observation["evidence"]["extractor"]["operation"].as_str() == Some("recover-export-return-shapes");
    if !trusted {
        return ReturnShape::Unavailable(
            "The return-shape observation lacks the expected static-inference authority.".into(),
        );
    }
    let complete = observation["evidence"]["coverage"]["status"].as_str() == Some("complete")
        && observation["evidence"]["coverage"]["truncated"].as_bool() != Some(true);
    ReturnShape::Ready {
        projection: observation["properties"].clone(),
        observation_complete: complete,
    }
}

fn projection_well_formed(properties: &Value) -> bool {
    properties["static_return_shapes"].is_array()
        && properties["return_shape_coverage"].is_object()
        && properties["module_path"].as_str().is_some()
        && properties["exported_name"].as_str().is_some()
        && properties["callable_id"].as_str().is_some()
        && properties["callable_kind"].as_str().is_some()
}

fn retained_shapes(selected: &Selected) -> Vec<Value> {
    selected
        .projection
        .as_ref()
        .and_then(|projection| projection["static_return_shapes"].as_array().cloned())
        .unwrap_or_default()
}

struct Pairing {
    pairs: Vec<VariantPair>,
    unpaired_left: Vec<usize>,
    unpaired_right: Vec<usize>,
}

struct VariantPair {
    left_index: usize,
    right_index: usize,
    discriminant: Value,
}

fn pair_variants(left: &[Value], right: &[Value]) -> Result<Pairing, JsError> {
    let left_keys = discriminant_occurrences(left)?;
    let right_keys = discriminant_occurrences(right)?;
    let mut edges: std::collections::HashMap<String, Vec<Value>> = std::collections::HashMap::new();
    let mut left_targets: std::collections::HashMap<usize, Vec<usize>> = std::collections::HashMap::new();
    let mut right_targets: std::collections::HashMap<usize, Vec<usize>> = std::collections::HashMap::new();
    for (key, left_occurrence) in &left_keys {
        let Some(right_occurrence) = right_keys.get(key) else {
            continue;
        };
        if left_occurrence.indexes.len() != 1 || right_occurrence.indexes.len() != 1 {
            continue;
        }
        let left_index = left_occurrence.indexes[0];
        let right_index = right_occurrence.indexes[0];
        let edge_key = format!("{left_index}:{right_index}");
        edges
            .entry(edge_key)
            .or_default()
            .push(left_occurrence.discriminant.clone());
        push_unique(left_targets.entry(left_index).or_default(), right_index);
        push_unique(right_targets.entry(right_index).or_default(), left_index);
    }
    let mut pairs = Vec::new();
    let mut left_indexes: Vec<usize> = left_targets.keys().copied().collect();
    left_indexes.sort_unstable();
    for left_index in left_indexes {
        let targets = &left_targets[&left_index];
        if targets.len() != 1 {
            continue;
        }
        let right_index = targets[0];
        let Some(back) = right_targets.get(&right_index) else {
            continue;
        };
        if back.len() != 1 || !back.contains(&left_index) {
            continue;
        }
        let mut discriminants = edges
            .get(&format!("{left_index}:{right_index}"))
            .cloned()
            .unwrap_or_default();
        discriminants.sort_by(compare_values);
        let Some(discriminant) = discriminants.into_iter().next() else {
            continue;
        };
        pairs.push(VariantPair {
            left_index,
            right_index,
            discriminant,
        });
    }
    pairs.sort_by(|left, right| compare_values(&left.discriminant, &right.discriminant));
    let paired_left: std::collections::HashSet<usize> = pairs.iter().map(|pair| pair.left_index).collect();
    let paired_right: std::collections::HashSet<usize> = pairs.iter().map(|pair| pair.right_index).collect();
    Ok(Pairing {
        pairs,
        unpaired_left: (0..left.len()).filter(|index| !paired_left.contains(index)).collect(),
        unpaired_right: (0..right.len()).filter(|index| !paired_right.contains(index)).collect(),
    })
}

struct Occurrence {
    discriminant: Value,
    indexes: Vec<usize>,
}

fn discriminant_occurrences(shapes: &[Value]) -> Result<std::collections::BTreeMap<String, Occurrence>, JsError> {
    let mut output = std::collections::BTreeMap::new();
    for (index, shape) in shapes.iter().enumerate() {
        let Some(fields) = shape["fields"].as_array() else {
            continue;
        };
        for field in fields {
            if field_presence(shape, Some(field), field["path"].as_str().unwrap_or("")) != "present" {
                continue;
            }
            let Some(value) = literal_value(field) else {
                continue;
            };
            let discriminant = json!({ "path": field["path"], "value": value });
            let key = canonical_text(&discriminant)?;
            output
                .entry(key)
                .and_modify(|occurrence: &mut Occurrence| occurrence.indexes.push(index))
                .or_insert(Occurrence {
                    discriminant,
                    indexes: vec![index],
                });
        }
    }
    Ok(output)
}

fn build_changes(
    left: &Selected,
    right: &Selected,
    pairing: &Pairing,
    left_shapes: &[Value],
    right_shapes: &[Value],
    evidence_links: &[String],
) -> Result<Vec<Value>, JsError> {
    if left.selection["status"].as_str() != Some("selected")
        || right.selection["status"].as_str() != Some("selected")
    {
        return Ok(vec![change_with_id(&json!({
            "status": "unknown",
            "path": "",
            "discriminant": Value::Null,
            "presence": { "left": "unknown-coverage", "right": "unknown-coverage" },
            "left": selection_availability(&left.selection, "left"),
            "right": selection_availability(&right.selection, "right"),
            "left_source_range": Value::Null,
            "right_source_range": Value::Null,
            "evidence_links": evidence_links,
            "limitations": ["Both selectors must resolve one exact export with trusted static return shapes before comparison."],
        }))?]);
    }
    if left_shapes.is_empty() || right_shapes.is_empty() {
        return Ok(vec![change_with_id(&json!({
            "status": "unknown",
            "path": "",
            "discriminant": Value::Null,
            "presence": { "left": "unknown-coverage", "right": "unknown-coverage" },
            "left": empty_availability(left_shapes, "left"),
            "right": empty_availability(right_shapes, "right"),
            "left_source_range": Value::Null,
            "right_source_range": Value::Null,
            "evidence_links": evidence_links,
            "limitations": ["At least one selected export has no retained direct return shape."],
        }))?]);
    }
    let mut changes = Vec::new();
    for pair in &pairing.pairs {
        let Some(left_shape) = left_shapes.get(pair.left_index) else {
            continue;
        };
        let Some(right_shape) = right_shapes.get(pair.right_index) else {
            continue;
        };
        changes.extend(diff_pair(left_shape, right_shape, &pair.discriminant, evidence_links)?);
    }
    for index in &pairing.unpaired_left {
        if let Some(shape) = left_shapes.get(*index) {
            changes.push(unpaired_change("left", shape, evidence_links)?);
        }
    }
    for index in &pairing.unpaired_right {
        if let Some(shape) = right_shapes.get(*index) {
            changes.push(unpaired_change("right", shape, evidence_links)?);
        }
    }
    Ok(changes)
}

fn diff_pair(
    left: &Value,
    right: &Value,
    discriminant: &Value,
    evidence_links: &[String],
) -> Result<Vec<Value>, JsError> {
    let left_fields = field_map(left);
    let right_fields = field_map(right);
    let mut paths = Vec::new();
    paths.extend(left_fields.keys().cloned());
    paths.extend(right_fields.keys().cloned());
    paths.extend(coverage_paths(left));
    paths.extend(coverage_paths(right));
    let paths = unique_sorted(&paths);
    let mut changes = Vec::new();
    for path in paths {
        let left_field = field_at_path(left, &left_fields, &path);
        let right_field = field_at_path(right, &right_fields, &path);
        let Some(status) = field_change_status(left, right, &path, left_field.as_ref(), right_field.as_ref())? else {
            continue;
        };
        let limitations: Vec<&str> = if status == "unknown" {
            vec!["The static value or relevant parent-property coverage is incomplete."]
        } else {
            Vec::new()
        };
        changes.push(change_with_id(&json!({
            "status": status,
            "path": path,
            "discriminant": discriminant,
            "presence": {
                "left": field_presence(left, left_field.as_ref(), &path),
                "right": field_presence(right, right_field.as_ref(), &path),
            },
            "left": field_availability(left_field.as_ref()),
            "right": field_availability(right_field.as_ref()),
            "left_source_range": left["source_range"].clone(),
            "right_source_range": right["source_range"].clone(),
            "evidence_links": evidence_links,
            "limitations": limitations,
        }))?);
    }
    Ok(changes)
}

fn field_map(shape: &Value) -> std::collections::BTreeMap<String, Value> {
    let mut map = std::collections::BTreeMap::new();
    if let Some(fields) = shape["fields"].as_array() {
        for field in fields {
            if let Some(path) = field["path"].as_str() {
                map.insert(path.to_string(), field.clone());
            }
        }
    }
    map
}

fn coverage_paths(shape: &Value) -> Vec<String> {
    shape["property_coverage"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item["path"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn field_at_path(
    shape: &Value,
    fields: &std::collections::BTreeMap<String, Value>,
    path: &str,
) -> Option<Value> {
    if let Some(field) = fields.get(path) {
        return Some(field.clone());
    }
    let covered = shape["property_coverage"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item["path"].as_str() == Some(path)));
    if !covered {
        return None;
    }
    Some(json!({
        "path": path,
        "presence": "present",
        "state": "unknown",
        "value": Value::Null,
        "reason": "A static container is retained at this path, but no primitive field value is projected.",
    }))
}

fn field_change_status(
    left_shape: &Value,
    right_shape: &Value,
    path: &str,
    left_field: Option<&Value>,
    right_field: Option<&Value>,
) -> Result<Option<&'static str>, JsError> {
    let left_presence = field_presence(left_shape, left_field, path);
    let right_presence = field_presence(right_shape, right_field, path);
    if let (Some(left_field), Some(right_field)) = (left_field, right_field) {
        if canonical_text(left_field)? == canonical_text(right_field)? {
            return Ok(None);
        }
    }
    if left_presence == "absent" && right_presence == "absent" {
        return Ok(None);
    }
    if left_presence == "unknown-coverage" || right_presence == "unknown-coverage" {
        return Ok(Some("unknown"));
    }
    if left_presence == "absent" {
        return Ok(Some("added"));
    }
    if right_presence == "absent" {
        return Ok(Some("removed"));
    }
    if let (Some(left_field), Some(right_field)) = (left_field, right_field) {
        let unknown = left_field["state"].as_str() == Some("unknown")
            || right_field["state"].as_str() == Some("unknown");
        return Ok(Some(if unknown { "unknown" } else { "changed" }));
    }
    Ok(None)
}

fn field_presence(shape: &Value, field: Option<&Value>, path: &str) -> &'static str {
    if let Some(field) = field {
        return match field["presence"].as_str() {
            Some("absent") => "absent",
            Some("unknown-coverage") => "unknown-coverage",
            _ => "present",
        };
    }
    if property_coverage_complete(shape, parent_pointer(path)) {
        "absent"
    } else {
        "unknown-coverage"
    }
}

fn property_coverage_complete(shape: &Value, path: Option<&str>) -> bool {
    let Some(path) = path else {
        return false;
    };
    shape["property_coverage"].as_array().is_some_and(|items| {
        items.iter().any(|coverage| {
            coverage["path"].as_str() == Some(path) && coverage["status"].as_str() == Some("complete")
        })
    })
}

fn parent_pointer(path: &str) -> Option<&str> {
    if path.is_empty() {
        return None;
    }
    let separator = path.rfind('/')?;
    Some(&path[..separator])
}

fn field_availability(field: Option<&Value>) -> Value {
    let Some(field) = field else {
        return json!({ "availability": "absent" });
    };
    if field["presence"].as_str() == Some("absent") {
        return json!({ "availability": "absent" });
    }
    if field["state"].as_str() == Some("unknown") {
        return json!({
            "availability": "unknown",
            "reason": field["reason"].as_str().unwrap_or("Static field value is unknown."),
        });
    }
    if field["state"].as_str() == Some("union") {
        return json!({ "availability": "union", "values": primitive_array(&field["value"]) });
    }
    if let Some(value) = literal_value(field) {
        json!({ "availability": "literal", "value": value })
    } else {
        json!({
            "availability": "unknown",
            "reason": "Static literal field failed its projection boundary.",
        })
    }
}

fn selection_availability(selection: &Value, side: &str) -> Value {
    json!({
        "availability": "unknown",
        "reason": format!("{} export selection is {}.", capitalize(side), selection["status"].as_str().unwrap_or("unknown")),
    })
}

fn empty_availability(shapes: &[Value], side: &str) -> Value {
    let reason = if shapes.is_empty() {
        format!("{} export has no retained direct return shape.", capitalize(side))
    } else {
        format!("{side_cap} export return shape cannot be paired without an opposite variant.", side_cap = capitalize(side))
    };
    json!({ "availability": "unknown", "reason": reason })
}

fn unpaired_change(side: &str, shape: &Value, evidence_links: &[String]) -> Result<Value, JsError> {
    change_with_id(&json!({
        "status": "unknown",
        "path": "",
        "discriminant": Value::Null,
        "presence": { "left": "unknown-coverage", "right": "unknown-coverage" },
        "left": {
            "availability": "unknown",
            "reason": if side == "left" {
                "Left return variant has no unique exact cross-version pairing."
            } else {
                "No left return variant was uniquely paired with this right variant."
            },
        },
        "right": {
            "availability": "unknown",
            "reason": if side == "right" {
                "Right return variant has no unique exact cross-version pairing."
            } else {
                "No right return variant was uniquely paired with this left variant."
            },
        },
        "left_source_range": if side == "left" { shape["source_range"].clone() } else { Value::Null },
        "right_source_range": if side == "right" { shape["source_range"].clone() } else { Value::Null },
        "evidence_links": evidence_links,
        "limitations": ["The return variant was not paired because no reciprocal unique literal discriminant exists."],
    }))
}

fn change_with_id(semantic: &Value) -> Result<Value, JsError> {
    let mut change = semantic.clone();
    let change_id = digest_prefixed("jesc_change_", semantic)?;
    change
        .as_object_mut()
        .expect("object")
        .insert("change_id".into(), json!(change_id));
    Ok(change)
}

fn literal_value(field: &Value) -> Option<Value> {
    if field["state"].as_str() == Some("literal") && is_primitive(&field["value"]) {
        Some(field["value"].clone())
    } else {
        None
    }
}

fn primitive_array(value: &Value) -> Vec<Value> {
    value
        .as_array()
        .map(|items| items.iter().filter(|item| is_primitive(item)).cloned().collect())
        .unwrap_or_default()
}

fn is_primitive(value: &Value) -> bool {
    value.is_null() || value.is_string() || value.is_number() || value.is_boolean()
}

fn capitalize(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

fn build_inventories(pairing: &Pairing, left: &[Value], right: &[Value]) -> Vec<Value> {
    let left_pairs: std::collections::HashMap<usize, &VariantPair> =
        pairing.pairs.iter().map(|pair| (pair.left_index, pair)).collect();
    let right_pairs: std::collections::HashMap<usize, &VariantPair> =
        pairing.pairs.iter().map(|pair| (pair.right_index, pair)).collect();
    let mut inventories = Vec::new();
    for (index, shape) in left.iter().enumerate() {
        inventories.push(inventory_for("left", index, shape, left_pairs.get(&index).copied()));
    }
    for (index, shape) in right.iter().enumerate() {
        inventories.push(inventory_for("right", index, shape, right_pairs.get(&index).copied()));
    }
    inventories
}

fn inventory_for(side: &str, index: usize, shape: &Value, pair: Option<&VariantPair>) -> Value {
    let mut properties = Vec::new();
    if let Some(fields) = shape["fields"].as_array() {
        for field in fields {
            let path = field["path"].as_str().unwrap_or("");
            if field_presence(shape, Some(field), path) == "present" {
                properties.push(path.to_string());
            }
        }
    }
    properties.extend(coverage_paths(shape));
    let properties = unique_sorted(&properties)
        .into_iter()
        .filter(|path| !path.is_empty())
        .collect::<Vec<_>>();
    let property_coverage = shape["property_coverage"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| json!({ "path": item["path"], "status": item["status"] }))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "side": side,
        "variant_index": index,
        "discriminant": pair.map(|pair| pair.discriminant.clone()).unwrap_or(Value::Null),
        "paired": pair.is_some(),
        "source_range": shape["source_range"].clone(),
        "properties": properties,
        "property_coverage": property_coverage,
    })
}

fn has_partial_property_coverage(shapes: &[Value]) -> bool {
    shapes.iter().any(|shape| {
        shape["property_coverage"].as_array().is_some_and(|items| {
            items.iter().any(|coverage| coverage["status"].as_str() == Some("partial"))
        }) || shape["fields"].as_array().is_some_and(|fields| {
            fields.iter().any(|field| {
                field_presence(shape, Some(field), field["path"].as_str().unwrap_or("")) == "unknown-coverage"
            })
        })
    })
}

#[allow(clippy::too_many_arguments)]
fn comparison_coverage(
    left_graph: &Value,
    right_graph: &Value,
    left: &Selected,
    right: &Selected,
    left_shapes: &[Value],
    right_shapes: &[Value],
    pairing: &Pairing,
    changes: &[Value],
) -> Value {
    let left_source = left.projection.as_ref().map(|projection| &projection["return_shape_coverage"]);
    let right_source = right.projection.as_ref().map(|projection| &projection["return_shape_coverage"]);
    let omitted_candidates = left.selection["omitted_candidates"].as_u64().unwrap_or(0)
        + right.selection["omitted_candidates"].as_u64().unwrap_or(0);
    let truncated = omitted_candidates > 0 || source_truncated(left) || source_truncated(right);
    let partial = selection_partial(left)
        || selection_partial(right)
        || left_graph["coverage"]["status"].as_str() != Some("complete")
        || right_graph["coverage"]["status"].as_str() != Some("complete")
        || has_partial_property_coverage(left_shapes)
        || has_partial_property_coverage(right_shapes)
        || !pairing.unpaired_left.is_empty()
        || !pairing.unpaired_right.is_empty()
        || changes.iter().any(|change| change["status"].as_str() == Some("unknown"));
    let status = if truncated {
        "truncated"
    } else if partial {
        "partial"
    } else {
        "complete-within-inputs"
    };
    json!({
        "status": status,
        "left_graph_status": left_graph["coverage"]["status"],
        "right_graph_status": right_graph["coverage"]["status"],
        "paired_variants": pairing.pairs.len(),
        "unpaired_left_variants": pairing.unpaired_left.len(),
        "unpaired_right_variants": pairing.unpaired_right.len(),
        "omitted_left_variants": 0,
        "omitted_right_variants": 0,
        "left_source_omitted_variants": left_source.map(|coverage| coverage["omitted_return_sites"].clone()).unwrap_or(Value::Null),
        "right_source_omitted_variants": right_source.map(|coverage| coverage["omitted_return_sites"].clone()).unwrap_or(Value::Null),
        "left_omitted_fields": left_source.and_then(|coverage| coverage["omitted_fields"].as_u64()).unwrap_or(0),
        "right_omitted_fields": right_source.and_then(|coverage| coverage["omitted_fields"].as_u64()).unwrap_or(0),
        "left_omitted_property_coverage": left_source.and_then(|coverage| coverage["omitted_property_coverage"].as_u64()).unwrap_or(0),
        "right_omitted_property_coverage": right_source.and_then(|coverage| coverage["omitted_property_coverage"].as_u64()).unwrap_or(0),
        "omitted_candidates": omitted_candidates,
        "omitted_changes": 0,
    })
}

fn source_truncated(selected: &Selected) -> bool {
    let Some(projection) = &selected.projection else {
        return false;
    };
    let coverage = &projection["return_shape_coverage"];
    coverage["status"].as_str() == Some("truncated")
        || coverage["omitted_fields"].as_u64().unwrap_or(0) > 0
        || coverage["omitted_property_coverage"].as_u64().unwrap_or(0) > 0
        || coverage["projection_complete"].as_bool() == Some(false)
}

fn selection_partial(selected: &Selected) -> bool {
    let coverage_complete = selected.projection.as_ref().is_some_and(|projection| {
        let coverage = &projection["return_shape_coverage"];
        coverage["status"].as_str() == Some("complete") && coverage["projection_complete"].as_bool() == Some(true)
    });
    selected.selection["status"].as_str() != Some("selected") || !selected.observation_complete || !coverage_complete
}

fn comparison_limitations(left: &Selected, right: &Selected, status: &str) -> Vec<String> {
    let mut limitations = vec![
        INERT_LIMITATION.to_string(),
        PAIRING_LIMITATION.to_string(),
        DYNAMIC_LIMITATION.to_string(),
        PROBE_LIMITATION.to_string(),
    ];
    limitations.extend(left.limitations.clone());
    limitations.extend(right.limitations.clone());
    if status == "truncated" {
        limitations.push(TRUNCATED_LIMITATION.to_string());
    }
    if status == "partial" {
        limitations.push(PARTIAL_LIMITATION.to_string());
    }
    unique_sorted(&limitations)
}

fn summarize(changes: &[Value]) -> Value {
    json!({
        "added": count_status(changes, "added"),
        "removed": count_status(changes, "removed"),
        "changed": count_status(changes, "changed"),
        "unknown": count_status(changes, "unknown"),
    })
}

fn count_status(changes: &[Value], status: &str) -> usize {
    changes.iter().filter(|change| change["status"].as_str() == Some(status)).count()
}

fn sort_changes(changes: &mut [Value]) -> Result<(), JsError> {
    let mut keyed = Vec::new();
    for (index, change) in changes.iter().enumerate() {
        let key = canonical_text(&json!({
            "discriminant": change["discriminant"],
            "path": change["path"],
            "status": change["status"],
            "left_source_range": change["left_source_range"],
            "right_source_range": change["right_source_range"],
            "change_id": change["change_id"],
        }))?;
        keyed.push((key, index, change.clone()));
    }
    keyed.sort_by(|left, right| compare_unicode_code_points(&left.0, &right.0).then(left.1.cmp(&right.1)));
    for (slot, (_, _, change)) in changes.iter_mut().zip(keyed) {
        *slot = change;
    }
    Ok(())
}

fn compare_values(left: &Value, right: &Value) -> std::cmp::Ordering {
    let left_key = canonical_text(left).unwrap_or_default();
    let right_key = canonical_text(right).unwrap_or_default();
    compare_unicode_code_points(&left_key, &right_key)
}

fn push_unique(values: &mut Vec<usize>, value: usize) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn require_text(name: &str, value: &str) -> Result<(), JsError> {
    if value.is_empty() {
        return Err(JsError::InvalidInput(format!("{name} is required")));
    }
    Ok(())
}

fn string_list(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| items.iter().filter_map(|item| item.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}
