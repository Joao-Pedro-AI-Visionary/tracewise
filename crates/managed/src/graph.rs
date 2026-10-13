//! Provider-neutral application graph construction and the managed-code
//! projection (REA `javascriptApplicationGraph.ts` factories and
//! `managedApplicationGraph*.ts`).

use std::cmp::Ordering;

use serde_json::{json, Map, Value};
use tracewise_domain::canonical::{canonical_json, canonical_sha256};

use crate::workflows::{input_error, parse_managed_inspection_evidence, sha256_canonical, token_scopes_match, WorkflowError, WR};

fn protocol(error: impl std::fmt::Display) -> WorkflowError {
    WorkflowError::Protocol(error.to_string())
}

fn digest(value: &Value) -> WR<String> {
    canonical_sha256(value).map_err(protocol)
}

/// Strings in Unicode code point order (UTF-8 byte order is identical).
pub fn compare_code_points(left: &str, right: &str) -> Ordering {
    left.cmp(right)
}

pub fn unique_sorted(values: &[String]) -> Vec<String> {
    let mut out: Vec<String> = values.to_vec();
    out.sort_by(|a, b| compare_code_points(a, b));
    out.dedup();
    out
}

fn string_list(value: &Value) -> Vec<String> {
    value.as_array().map(|items| items.iter().filter_map(|i| i.as_str().map(str::to_string)).collect()).unwrap_or_default()
}

fn normalize_limits(limits: &[Value]) -> WR<Vec<Value>> {
    let mut keyed: Vec<(String, Value)> = Vec::new();
    for limit in limits {
        let key = canonical_json(limit).map_err(protocol)?;
        if !keyed.iter().any(|(existing, _)| *existing == key) {
            keyed.push((key, limit.clone()));
        }
    }
    keyed.sort_by(|a, b| compare_code_points(&a.0, &b.0));
    Ok(keyed.into_iter().map(|(_, v)| v).collect())
}

fn normalize_coverage(coverage: &Value) -> WR<Value> {
    let mut coverage = coverage.clone();
    let limits = coverage.get("limits").and_then(Value::as_array).cloned().unwrap_or_default();
    if let Some(object) = coverage.as_object_mut() {
        object.insert("limits".into(), json!(normalize_limits(&limits)?));
    }
    Ok(coverage)
}

pub fn normalize_evidence(evidence: &Value) -> WR<Value> {
    let mut evidence = evidence.clone();
    let coverage = evidence.get("coverage").cloned();
    if let Some(object) = evidence.as_object_mut() {
        if let Some(coverage) = coverage {
            object.insert("coverage".into(), normalize_coverage(&coverage)?);
        }
        let limitations = string_list(object.get("limitations").unwrap_or(&Value::Null));
        object.insert("limitations".into(), json!(unique_sorted(&limitations)));
        let ids = string_list(object.get("evidence_ids").unwrap_or(&Value::Null));
        object.insert("evidence_ids".into(), json!(unique_sorted(&ids)));
    }
    Ok(evidence)
}

/// `createJavaScriptApplicationNode`.
pub fn create_node(kind: &str, identity: Value, observations: Vec<Value>) -> WR<Value> {
    let mut identity = identity;
    if identity["strategy"] == "structural-fingerprint" {
        let basis = unique_sorted(&string_list(&identity["basis"]));
        identity["basis"] = json!(basis);
    }
    let node_id = format!("jag_node_{}", digest(&json!({ "kind": kind, "identity": identity }))?);
    let mut built = Vec::new();
    for observation in observations {
        let mut semantic = Map::new();
        semantic.insert("label".into(), observation.get("label").cloned().unwrap_or(Value::Null));
        semantic.insert("source_map_reference".into(), observation.get("source_map_reference").cloned().unwrap_or(Value::Null));
        semantic.insert("properties".into(), observation.get("properties").cloned().unwrap_or_else(|| json!({})));
        semantic.insert("evidence".into(), normalize_evidence(&observation["evidence"])?);
        semantic.insert(
            "identifier_strategy".into(),
            json!({ "strategy": "semantic-content-sha256", "stability": "observation-exact" }),
        );
        let mut hashed = semantic.clone();
        hashed.insert("node_id".into(), json!(node_id));
        let observation_id = format!("jag_observation_{}", digest(&Value::Object(hashed))?);
        semantic.insert("observation_id".into(), json!(observation_id));
        built.push(Value::Object(semantic));
    }
    built.sort_by(|a, b| compare_code_points(a["observation_id"].as_str().unwrap_or(""), b["observation_id"].as_str().unwrap_or("")));
    Ok(json!({ "node_id": node_id, "kind": kind, "identity": identity, "observations": built }))
}

/// `createJavaScriptApplicationEdge`.
pub fn create_edge(source: &str, target: &str, relation: &str, properties: Value, evidence: &Value) -> WR<Value> {
    let mut semantic = Map::new();
    semantic.insert("source_node_id".into(), json!(source));
    semantic.insert("target_node_id".into(), json!(target));
    semantic.insert("relation".into(), json!(relation));
    semantic.insert("properties".into(), properties);
    semantic.insert("evidence".into(), normalize_evidence(evidence)?);
    semantic.insert(
        "identifier_strategy".into(),
        json!({ "strategy": "semantic-content-sha256", "stability": "relationship-exact" }),
    );
    let edge_id = format!("jag_edge_{}", digest(&Value::Object(semantic.clone()))?);
    semantic.insert("edge_id".into(), json!(edge_id));
    Ok(Value::Object(semantic))
}

/// `createJavaScriptApplicationGraph`: sort, normalize and derive the graph id.
pub fn create_graph(root_node_ids: &[String], nodes: Vec<Value>, edges: Vec<Value>, coverage: &Value, limitations: &[String]) -> WR<Value> {
    let mut nodes = nodes;
    nodes.sort_by(|a, b| compare_code_points(a["node_id"].as_str().unwrap_or(""), b["node_id"].as_str().unwrap_or("")));
    let mut edges = edges;
    edges.sort_by(|a, b| compare_code_points(a["edge_id"].as_str().unwrap_or(""), b["edge_id"].as_str().unwrap_or("")));
    let coverage = normalize_coverage(coverage)?;
    let limitations = unique_sorted(limitations);
    let roots = unique_sorted(root_node_ids);
    if roots.is_empty() {
        return Err(input_error("application graph requires a root node"));
    }
    let content = json!({
        "schema": "JavaScriptApplicationGraph",
        "root_node_ids": roots,
        "nodes": nodes,
        "edges": edges,
        "coverage": coverage,
        "limitations": limitations,
    });
    let graph_id = format!("jag_{}", digest(&content)?);
    let mut graph = content;
    graph["graph_id"] = json!(graph_id);
    Ok(graph)
}

// ---------------------------------------------------------------------------
// Managed projection
// ---------------------------------------------------------------------------

fn complete_coverage() -> Value {
    json!({ "status": "complete", "truncated": false, "omitted_count": 0, "limits": [] })
}

fn source_coverage(state: &str) -> Value {
    if state == "complete" {
        complete_coverage()
    } else {
        json!({ "status": state, "truncated": false, "omitted_count": null, "limits": [] })
    }
}

fn graph_artifact_path(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or(path);
    let sanitized: String =
        name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' { c } else { '_' }).collect();
    format!("managed/{}", if sanitized.is_empty() { "artifact.pe".to_string() } else { sanitized })
}

struct State {
    nodes: Vec<Value>,
    edges: Vec<Value>,
    artifact_sha256: String,
    artifact_path: String,
    evidence_links: Vec<String>,
    type_nodes: std::collections::HashMap<String, String>,
    method_nodes: std::collections::HashMap<String, String>,
    field_nodes: std::collections::HashMap<String, String>,
}

fn managed_evidence(state: &State, operation: &str, coverage: Value, evidence_ids: &[String]) -> Value {
    let partial = coverage["status"] != "complete";
    json!({
        "authority": "managed-static-analysis",
        "state": "observed",
        "confidence": "exact",
        "artifact": {
            "available": true,
            "artifact_id": format!("art_{}", state.artifact_sha256),
            "sha256": state.artifact_sha256,
        },
        "location": {
            "available": true,
            "value": { "kind": "artifact-path", "path": graph_artifact_path(&state.artifact_path) },
        },
        "extractor": {
            "name": "rea-dotnet-static",
            "version": "1",
            "operation": operation,
            "executable_sha256": null,
        },
        "coverage": coverage,
        "limitations": if partial {
            json!(["The source managed Evidence slice is incomplete; unreturned or unavailable items remain unobserved."])
        } else { json!([]) },
        "evidence_ids": evidence_ids,
    })
}

fn source_evidence(state: &State, operation: &str, evidence_id: &str, coverage_state: &str) -> Value {
    managed_evidence(state, operation, source_coverage(coverage_state), &[evidence_id.to_string()])
}

fn projected_evidence(state: &State, operation: &str, coverage: Option<Value>) -> Value {
    managed_evidence(state, operation, coverage.unwrap_or_else(complete_coverage), &state.evidence_links)
}

fn artifact_local_identity(artifact_sha256: &str, namespace: &str, key: &str) -> Value {
    json!({
        "strategy": "artifact-local-key",
        "stability": "artifact-version",
        "artifact_sha256": artifact_sha256,
        "namespace": namespace,
        "key": key,
    })
}

fn node_id_of(node: &Value) -> String {
    node["node_id"].as_str().unwrap_or_default().to_string()
}

fn add_contains_edge(state: &mut State, source: &str, target: &str, kind: &str, coverage: Value) -> WR<()> {
    let evidence = projected_evidence(state, "project-managed-contains", Some(coverage));
    let edge = create_edge(source, target, "contains", json!({ "kind": kind }), &evidence)?;
    state.edges.push(edge);
    Ok(())
}

struct Parsed {
    artifact: Option<(String, Value)>,
    members: Option<(String, Value)>,
    boundaries: Option<(String, Value)>,
}

fn string_at<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or_default()
}

fn add_artifact_node(state: &mut State) -> WR<String> {
    let label = state.artifact_path.rsplit('/').next().unwrap_or(&state.artifact_path).to_string();
    let evidence = projected_evidence(state, "project-managed-artifact", None);
    let node = create_node(
        "artifact",
        json!({ "strategy": "content-digest", "stability": "global-exact", "sha256": state.artifact_sha256 }),
        vec![json!({
            "label": label,
            "properties": { "format": "pe", "source": "managed-application-graph" },
            "evidence": evidence,
        })],
    )?;
    let id = node_id_of(&node);
    state.nodes.push(node);
    Ok(id)
}

struct ModuleSource<'a> {
    module: &'a Value,
    evidence_id: &'a str,
    operation: &'static str,
    coverage_state: &'a str,
}

fn select_module_source<'a>(parsed: &'a Parsed) -> Option<ModuleSource<'a>> {
    let mut sources: Vec<ModuleSource> = Vec::new();
    for (entry, operation) in [
        (&parsed.artifact, "inspect_managed_artifact"),
        (&parsed.members, "inspect_managed_members"),
        (&parsed.boundaries, "inspect_managed_native_boundaries"),
    ] {
        if let Some((evidence_id, result)) = entry {
            if !result["module"].is_null() {
                sources.push(ModuleSource {
                    module: &result["module"],
                    evidence_id,
                    operation,
                    coverage_state: result["coverage"]["state"].as_str().unwrap_or("partial"),
                });
            }
        }
    }
    let position = sources.iter().position(|s| !s.module["mvid"].is_null());
    match position {
        Some(index) => Some(sources.swap_remove(index)),
        None => sources.into_iter().next(),
    }
}

fn add_artifact_identity_nodes(state: &mut State, artifact_node: &str, parsed: &Parsed) -> WR<()> {
    if let Some((evidence_id, result)) = &parsed.artifact {
        if !result["assembly"].is_null() {
            let facts = &result["assembly"];
            let evidence = source_evidence(
                state,
                "inspect_managed_artifact",
                evidence_id,
                result["coverage"]["state"].as_str().unwrap_or("partial"),
            );
            let coverage = evidence["coverage"].clone();
            let node = create_node(
                "managed-assembly",
                artifact_local_identity(&state.artifact_sha256, "managed-assembly", string_at(facts, "token")),
                vec![json!({
                    "label": facts["name"],
                    "properties": {
                        "name": facts["name"],
                        "version": facts["version"],
                        "culture": facts["culture"],
                        "public_key_kind": facts["public_key"]["kind"],
                    },
                    "evidence": evidence,
                })],
            )?;
            let id = node_id_of(&node);
            state.nodes.push(node);
            add_contains_edge(state, artifact_node, &id, "declares-managed-assembly", coverage)?;
        }
    }
    if let Some(source) = select_module_source(parsed) {
        let module = source.module;
        let evidence = source_evidence(state, source.operation, source.evidence_id, source.coverage_state);
        let coverage = evidence["coverage"].clone();
        let key = match module["mvid"].as_str() {
            Some(mvid) => mvid.to_lowercase(),
            None => string_at(module, "token").to_string(),
        };
        let node = create_node(
            "managed-module",
            artifact_local_identity(&state.artifact_sha256, "managed-module", &key),
            vec![json!({
                "label": module["name"],
                "properties": {
                    "name": module["name"],
                    "mvid": module["mvid"],
                    "generation": module["generation"],
                    "token": module["token"],
                },
                "evidence": evidence,
            })],
        )?;
        let id = node_id_of(&node);
        state.nodes.push(node);
        add_contains_edge(state, artifact_node, &id, "declares-managed-module", coverage)?;
    }
    Ok(())
}

fn qualified_label(declaring_type: &Value, name: &Value) -> Value {
    match declaring_type.as_str() {
        None => name.clone(),
        Some(declaring) => json!(format!("{declaring}.{}", name.as_str().unwrap_or_default())),
    }
}

fn add_member_nodes(state: &mut State, artifact_node: &str, parsed: &Parsed) -> WR<()> {
    let Some((evidence_id, members)) = &parsed.members else {
        return Ok(());
    };
    let coverage_state = members["coverage"]["state"].as_str().unwrap_or("partial");
    let source = source_evidence(state, "inspect_managed_members", evidence_id, coverage_state);
    let member_coverage = source_coverage(coverage_state);
    let empty = Vec::new();
    for item in members["types"].as_array().unwrap_or(&empty) {
        let node = create_node(
            "managed-type",
            artifact_local_identity(&state.artifact_sha256, "managed-type-token", string_at(item, "token")),
            vec![json!({
                "label": item["full_name"],
                "properties": {
                    "token": item["token"],
                    "namespace": item["namespace"],
                    "name": item["name"],
                    "full_name": item["full_name"],
                    "flags": item["flags"],
                    "extends_token": item["extends_token"],
                },
                "evidence": source,
            })],
        )?;
        let id = node_id_of(&node);
        state.nodes.push(node);
        state.type_nodes.insert(string_at(item, "token").to_string(), id.clone());
        add_contains_edge(state, artifact_node, &id, "declares-managed-type", member_coverage.clone())?;
    }
    for item in members["methods"].as_array().unwrap_or(&empty) {
        let node = create_node(
            "managed-method",
            artifact_local_identity(&state.artifact_sha256, "managed-method-token", string_at(item, "token")),
            vec![json!({
                "label": qualified_label(&item["declaring_type"], &item["name"]),
                "properties": {
                    "token": item["token"],
                    "declaring_type_token": item["declaring_type_token"],
                    "declaring_type": item["declaring_type"],
                    "name": item["name"],
                    "rva": item["rva"],
                    "signature_sha256": item["signature"]["raw_sha256"],
                    "signature_status": item["signature"]["parse_status"],
                    "body_status": item["body"]["status"],
                    "normalized_il_sha256": item["body"]["normalized_il_sha256"],
                    "il_size": item["body"]["il_size"],
                },
                "evidence": source,
            })],
        )?;
        let id = node_id_of(&node);
        state.nodes.push(node);
        state.method_nodes.insert(string_at(item, "token").to_string(), id.clone());
        let owner = item["declaring_type_token"]
            .as_str()
            .and_then(|t| state.type_nodes.get(t).cloned())
            .unwrap_or_else(|| artifact_node.to_string());
        add_contains_edge(state, &owner, &id, "declares-managed-method", member_coverage.clone())?;
    }
    for item in members["fields"].as_array().unwrap_or(&empty) {
        let node = create_node(
            "managed-field",
            artifact_local_identity(&state.artifact_sha256, "managed-field-token", string_at(item, "token")),
            vec![json!({
                "label": qualified_label(&item["declaring_type"], &item["name"]),
                "properties": {
                    "token": item["token"],
                    "declaring_type_token": item["declaring_type_token"],
                    "declaring_type": item["declaring_type"],
                    "name": item["name"],
                    "flags": item["flags"],
                    "signature_sha256": item["signature"]["raw_sha256"],
                    "signature_status": item["signature"]["parse_status"],
                },
                "evidence": source,
            })],
        )?;
        let id = node_id_of(&node);
        state.nodes.push(node);
        state.field_nodes.insert(string_at(item, "token").to_string(), id.clone());
        let owner = item["declaring_type_token"]
            .as_str()
            .and_then(|t| state.type_nodes.get(t).cloned())
            .unwrap_or_else(|| artifact_node.to_string());
        add_contains_edge(state, &owner, &id, "declares-managed-field", member_coverage.clone())?;
    }
    Ok(())
}

fn add_boundary_nodes(state: &mut State, artifact_node: &str, parsed: &Parsed) -> WR<()> {
    let Some((boundary_id, boundaries)) = &parsed.boundaries else {
        return Ok(());
    };
    let coverage_state = boundaries["coverage"]["state"].as_str().unwrap_or("partial");
    let coverage = source_coverage(coverage_state);
    let source = source_evidence(state, "inspect_managed_native_boundaries", boundary_id, coverage_state);
    let can_join = parsed.members.as_ref().is_some_and(|(_, members)| {
        token_scopes_match(
            members["identity_scope"]["requires_mvid"].as_str(),
            boundaries["identity_scope"]["requires_mvid"].as_str(),
        )
    });
    let empty = Vec::new();
    for pinvoke in boundaries["pinvoke_imports"].as_array().unwrap_or(&empty) {
        let node = create_node(
            "managed-pinvoke-import",
            artifact_local_identity(&state.artifact_sha256, "managed-pinvoke-token", string_at(pinvoke, "token")),
            vec![json!({
                "label": pinvoke["import_name"],
                "properties": {
                    "token": pinvoke["token"],
                    "member_token": pinvoke["member_token"],
                    "member_name": pinvoke["member_name"],
                    "import_name": pinvoke["import_name"],
                    "import_scope_name": pinvoke["import_scope_name"],
                    "char_set": pinvoke["char_set"],
                    "call_convention": pinvoke["call_convention"],
                    "verification": pinvoke["verification"],
                },
                "evidence": source,
            })],
        )?;
        let id = node_id_of(&node);
        state.nodes.push(node);
        let method = match pinvoke["member_token"].as_str() {
            Some(token) if can_join => state.method_nodes.get(token).cloned(),
            _ => None,
        };
        let member_evidence_id = if method.is_some() { parsed.members.as_ref().map(|(id, _)| id.clone()) } else { None };
        let owner = method.unwrap_or_else(|| artifact_node.to_string());
        let mut ids = vec![boundary_id.clone()];
        if let Some(member) = member_evidence_id {
            ids.push(member);
        }
        let evidence = managed_evidence(state, "inspect_managed_native_boundaries", coverage.clone(), &ids);
        let edge = create_edge(
            &owner,
            &id,
            "imports",
            json!({
                "kind": "managed-pinvoke",
                "import_name": pinvoke["import_name"],
                "import_scope_name": pinvoke["import_scope_name"],
            }),
            &evidence,
        )?;
        state.edges.push(edge);
    }
    for implementation in boundaries["native_implementations"].as_array().unwrap_or(&empty) {
        let node = create_node(
            "managed-native-implementation",
            artifact_local_identity(
                &state.artifact_sha256,
                "managed-native-implementation-token",
                string_at(implementation, "token"),
            ),
            vec![json!({
                "label": implementation["name"],
                "properties": {
                    "token": implementation["token"],
                    "name": implementation["name"],
                    "rva": implementation["rva"],
                    "code_type": implementation["code_type"],
                    "managed_kind": implementation["managed_kind"],
                    "pinvoke_declared": implementation["pinvoke_declared"],
                    "boundary_kind": implementation["boundary_kind"],
                    "body_interpretation": implementation["body_interpretation"],
                },
                "evidence": source,
            })],
        )?;
        let id = node_id_of(&node);
        state.nodes.push(node);
        let owner = if can_join { state.method_nodes.get(string_at(implementation, "token")).cloned() } else { None }
            .unwrap_or_else(|| artifact_node.to_string());
        add_contains_edge(state, &owner, &id, "declares-managed-native-implementation", coverage.clone())?;
    }
    Ok(())
}

fn assert_consistent_module_identity(parsed: &Parsed) -> WR<()> {
    let results: Vec<&Value> =
        [&parsed.artifact, &parsed.members, &parsed.boundaries].into_iter().flatten().map(|(_, r)| r).collect();
    let mut claims: Vec<String> = Vec::new();
    for result in &results {
        if let Some(mvid) = result["module"]["mvid"].as_str() {
            claims.push(mvid.to_lowercase());
        }
        if let Some(mvid) = result["identity_scope"]["requires_mvid"].as_str() {
            claims.push(mvid.to_lowercase());
        }
    }
    // Same ordering of sources as the REA checks; only the distinct count matters.
    claims.sort();
    claims.dedup();
    if claims.len() > 1 {
        return Err(input_error("Managed graph inputs report conflicting known module MVIDs or token scopes"));
    }
    let modules: Vec<&Value> = results.iter().map(|r| &r["module"]).filter(|m| !m.is_null()).collect();
    for field in ["name", "generation", "token", "row_offset"] {
        let mut values: Vec<&Value> = Vec::new();
        for module in &modules {
            if !values.contains(&&module[field]) {
                values.push(&module[field]);
            }
        }
        if values.len() > 1 {
            return Err(input_error(format!("Managed graph inputs report conflicting module {field} values")));
        }
    }
    for field in ["enc_id", "enc_base_id"] {
        let mut values: Vec<String> = modules.iter().filter_map(|m| m[field].as_str().map(str::to_lowercase)).collect();
        values.sort();
        values.dedup();
        if values.len() > 1 {
            return Err(input_error(format!("Managed graph inputs report conflicting module {field} values")));
        }
    }
    Ok(())
}

fn count_nodes(nodes: &[Value], kind: &str) -> usize {
    nodes.iter().filter(|n| n["kind"] == kind).count()
}

/// Project authenticated managed Evidence records into the application graph.
pub fn project_managed_application_graph(
    managed_artifact: Option<&Value>,
    managed_members: Option<&Value>,
    managed_native_boundaries: Option<&Value>,
) -> WR<Value> {
    if managed_artifact.is_none() && managed_members.is_none() && managed_native_boundaries.is_none() {
        return Err(input_error("At least one managed artifact, member, or native-boundary Evidence record is required"));
    }
    let parse = |raw: Option<&Value>, operation: &str| -> WR<Option<(String, Value)>> {
        match raw {
            None => Ok(None),
            Some(raw) => {
                let (evidence, result) = parse_managed_inspection_evidence(raw, operation)?;
                Ok(Some((evidence.evidence_id, result)))
            }
        }
    };
    let parsed = Parsed {
        artifact: parse(managed_artifact, "inspect_managed_artifact")?,
        members: parse(managed_members, "inspect_managed_members")?,
        boundaries: parse(managed_native_boundaries, "inspect_managed_native_boundaries")?,
    };
    let chosen = parsed
        .artifact
        .as_ref()
        .or(parsed.members.as_ref())
        .or(parsed.boundaries.as_ref())
        .map(|(_, r)| r)
        .ok_or_else(|| input_error("Managed graph projection requires managed Evidence"))?;
    let artifact_sha = string_at(&chosen["artifact"], "sha256").to_string();
    let artifact_path = string_at(&chosen["artifact"], "path").to_string();
    for (_, result) in [&parsed.artifact, &parsed.members, &parsed.boundaries].into_iter().flatten() {
        if string_at(&result["artifact"], "sha256") != artifact_sha {
            return Err(input_error("Managed graph projection inputs must describe the same artifact SHA-256"));
        }
    }
    assert_consistent_module_identity(&parsed)?;
    let evidence_links: Vec<String> =
        [&parsed.artifact, &parsed.members, &parsed.boundaries].into_iter().flatten().map(|(id, _)| id.clone()).collect();
    let mut state = State {
        nodes: Vec::new(),
        edges: Vec::new(),
        artifact_sha256: artifact_sha.clone(),
        artifact_path,
        evidence_links: evidence_links.clone(),
        type_nodes: Default::default(),
        method_nodes: Default::default(),
        field_nodes: Default::default(),
    };
    let artifact_node = add_artifact_node(&mut state)?;
    add_artifact_identity_nodes(&mut state, &artifact_node, &parsed)?;
    add_member_nodes(&mut state, &artifact_node, &parsed)?;
    add_boundary_nodes(&mut state, &artifact_node, &parsed)?;

    let partial_input = [
        parsed.members.as_ref().map(|(_, r)| &r["coverage"]["state"]),
        parsed.boundaries.as_ref().map(|(_, r)| &r["coverage"]["state"]),
        parsed.artifact.as_ref().map(|(_, r)| &r["coverage"]["state"]),
    ]
    .into_iter()
    .flatten()
    .any(|state| state != "complete");
    let unscoped = match (&parsed.members, &parsed.boundaries) {
        (Some((_, members)), Some((_, boundaries))) => {
            (boundaries["pinvoke_imports"].as_array().is_some_and(|i| i.iter().any(|p| !p["member_token"].is_null()))
                || boundaries["native_implementations"].as_array().is_some_and(|i| !i.is_empty()))
                && !token_scopes_match(
                    members["identity_scope"]["requires_mvid"].as_str(),
                    boundaries["identity_scope"]["requires_mvid"].as_str(),
                )
        }
        _ => false,
    };
    let mut limitations = vec![
        "Managed graph projection preserves static metadata observations only; it does not execute managed code, load assemblies, or map managed tokens to native addresses.".to_string(),
    ];
    if parsed.members.is_none() {
        limitations.push("Managed member Evidence was not supplied; type, method, and field nodes are absent.".into());
    }
    if parsed.artifact.is_none() {
        limitations.push("Managed artifact Evidence was not supplied; assembly identity observations are absent.".into());
    }
    if parsed.boundaries.is_none() {
        limitations.push("Managed native-boundary Evidence was not supplied; P/Invoke and native-implementation nodes are absent.".into());
    }
    if partial_input {
        limitations.push("At least one supplied managed Evidence record has partial coverage.".into());
    }
    if unscoped {
        limitations.push("Managed boundary tokens were not linked to member nodes because matching module MVID scope was not established.".into());
    }
    let graph_coverage = if partial_input || unscoped {
        json!({ "status": "partial", "truncated": false, "omitted_count": null, "limits": [] })
    } else {
        complete_coverage()
    };
    let graph = create_graph(std::slice::from_ref(&artifact_node), state.nodes, state.edges, &graph_coverage, &limitations)?;
    let nodes = graph["nodes"].as_array().cloned().unwrap_or_default();
    let without_id = json!({
        "root_artifact_sha256": artifact_sha,
        "source_evidence": {
            "managed_artifact_evidence_id": parsed.artifact.as_ref().map(|(id, _)| id),
            "managed_members_evidence_id": parsed.members.as_ref().map(|(id, _)| id),
            "managed_native_boundaries_evidence_id": parsed.boundaries.as_ref().map(|(id, _)| id),
        },
        "summary": {
            "graph_nodes": nodes.len(),
            "graph_edges": graph["edges"].as_array().map(Vec::len).unwrap_or(0),
            "assemblies": count_nodes(&nodes, "managed-assembly"),
            "modules": count_nodes(&nodes, "managed-module"),
            "types": count_nodes(&nodes, "managed-type"),
            "methods": count_nodes(&nodes, "managed-method"),
            "fields": count_nodes(&nodes, "managed-field"),
            "pinvoke_imports": count_nodes(&nodes, "managed-pinvoke-import"),
            "native_implementations": count_nodes(&nodes, "managed-native-implementation"),
        },
        "graph": graph,
        "coverage": { "status": if partial_input || unscoped { "partial" } else { "complete-within-inputs" } },
        "evidence_links": evidence_links,
        "limitations": limitations,
    });
    let projection_id = sha256_canonical(&without_id)?;
    let mut result = without_id;
    result["projection_id"] = json!(format!("magp_{projection_id}"));
    Ok(result)
}
