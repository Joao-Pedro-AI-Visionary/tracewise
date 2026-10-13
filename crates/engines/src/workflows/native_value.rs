//! Bounded high-p-code def-use graphs across exactly referenced call destinations
//! (port of `NativeValueTrace.ts`).

use std::collections::{HashSet, VecDeque};

use serde_json::{json, Value};
use tracewise_domain::evidence::{
    create_evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation, EvidenceProvider,
};

use crate::error::AnalysisError;

use super::Env;

const NODE_BYTES: usize = 8 * 1024 * 1024;
const OUTPUT_BYTES: usize = 32 * 1024 * 1024;

struct Binding {
    caller: String,
    callee: String,
    call: String,
    argument_count: usize,
    output: bool,
    evidence_id: String,
}

fn number(input: &Value, key: &str, default: u64) -> u64 {
    input.get(key).and_then(Value::as_u64).unwrap_or(default)
}

pub async fn trace(env: &Env<'_>, input: &Value) -> Result<Value, AnalysisError> {
    let seed = input.get("procedure").and_then(Value::as_str).unwrap_or_default().to_string();
    let max_depth = number(input, "max_depth", 3);
    let max_functions = number(input, "max_functions", 16);
    let max_call_sites = number(input, "max_call_sites", 256);
    let max_nodes = number(input, "max_nodes", 5000) as usize;
    let max_edges = number(input, "max_edges", 10000) as usize;
    let offset = number(input, "offset", 0) as usize;
    let limit = number(input, "limit", 1000) as usize;

    let mut nodes: Vec<Value> = Vec::new();
    let mut node_ids: HashSet<String> = HashSet::new();
    let mut edges: Vec<Value> = Vec::new();
    let mut procedures: Vec<Value> = Vec::new();
    let mut unknowns: Vec<Value> = Vec::new();
    let mut bindings: Vec<Binding> = Vec::new();
    let mut pending: VecDeque<(String, u64)> = VecDeque::from([(seed.clone(), 0)]);
    let mut visited: HashSet<String> = HashSet::new();
    let mut target_sha256: Option<String> = None;
    let mut truncated = false;
    let mut decompilations = 0u64;
    let mut call_sites = 0u64;
    let mut bytes = 0usize;

    let unknown = |procedure: &str, address: Option<&str>, reason: &str| {
        json!({ "procedure": procedure, "address": address, "reason": reason })
    };

    'outer: while let Some((procedure, depth)) = pending.pop_front() {
        if env.ctx.cancel.is_cancelled() {
            return Err(AnalysisError::cancelled("trace_native_values"));
        }
        if visited.contains(&procedure) {
            continue;
        }
        if decompilations >= max_functions {
            truncated = true;
            unknowns.push(unknown(&procedure, None, "decompilation budget reached"));
            break;
        }
        let execution = env.execute("analyze_function", json!({ "procedure": procedure })).await;
        decompilations += 1;
        let execution = match execution {
            Ok(execution) => execution,
            Err(error) => {
                if error.is_cancelled() {
                    return Err(error);
                }
                unknowns.push(unknown(&procedure, None, &error.message()));
                continue;
            }
        };
        let dossier = &execution.result;
        let address = dossier["procedure"]["address"].as_str().map(str::to_string);
        let (Some(address), Some(subject)) = (address, env.subject.clone()) else {
            return Err(AnalysisError::output(
                "trace_native_values",
                "Function dossier lacks validated facts or artifact identity",
            ));
        };
        if !dossier.is_object() {
            return Err(AnalysisError::output(
                "trace_native_values",
                "Function dossier lacks validated facts or artifact identity",
            ));
        }
        if visited.contains(&address) {
            continue;
        }
        visited.insert(procedure.clone());
        visited.insert(address.clone());
        let sha = subject.digest.sha256.clone();
        if target_sha256.is_none() {
            target_sha256 = Some(sha.clone());
        }
        if target_sha256.as_deref() != Some(sha.as_str()) {
            return Err(AnalysisError::output(
                "trace_native_values",
                "Cross-function target digest mismatch",
            ));
        }
        let evidence = create_evidence(
            Some(subject),
            EvidenceProvider {
                id: execution.provider.id.clone(),
                name: execution.provider.name.clone(),
                version: execution.provider.version.clone(),
            },
            EvidenceObservation {
                predicate_type: None,
                operation: "analyze_function".to_string(),
                parameters: json!({ "procedure": procedure }),
                normalized_result: execution.result.clone(),
                raw_result: execution.raw_result.clone(),
                analysis_profile: execution
                    .analysis_profile
                    .as_ref()
                    .and_then(|p| serde_json::to_value(p).ok()),
                confidence: Some(EvidenceConfidence::Observed),
                authority: Some(EvidenceAuthority::ShippedArtifact),
                environment: None,
                limitations: Some(execution.limitations.clone()),
                locations: Some(execution.locations.clone()),
                evidence_links: None,
            },
        )
        .map_err(|e| AnalysisError::output("trace_native_values", e.to_string()))?;
        let evidence_id = evidence.evidence_id.clone();
        procedures.push(json!({
            "address": address,
            "depth": depth,
            "evidence_id": evidence_id,
            "provider": execution.provider.id,
            "analysis_profile_digest": execution.analysis_profile.as_ref().map(|p| p.digest.clone()),
        }));
        let flow = &dossier["native_value_flow"];
        if flow.is_null() || flow["available"] != json!(true) {
            let reason = flow
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("Provider has no native def-use model");
            unknowns.push(unknown(&address, None, reason));
            continue;
        }
        if flow["truncated"] == json!(true) {
            truncated = true;
            unknowns.push(unknown(&address, None, "Provider p-code was truncated"));
        }
        let qualified = |id: &str| format!("{address}/{id}");
        let mut ids: HashSet<String> = HashSet::new();
        let operations = flow["operations"].as_array().cloned().unwrap_or_default();
        for operation in &operations {
            let membership = operation["block_membership"].as_str().unwrap_or_default();
            if membership == "detached" || (membership == "unavailable" && operation["is_dead"] == json!(true)) {
                continue;
            }
            let id = operation["id"].as_str().unwrap_or_default();
            let node = json!({
                "id": qualified(id),
                "procedure": address,
                "evidence_id": evidence_id,
                "operation": operation,
                "kind": "operation",
                "parameter": Value::Null,
            });
            let size = serde_json::to_string(&node).map(|s| s.len()).unwrap_or(0);
            if nodes.len() >= max_nodes || bytes + size > NODE_BYTES {
                truncated = true;
                break;
            }
            bytes += size;
            ids.insert(id.to_string());
            node_ids.insert(qualified(id));
            nodes.push(node);
        }
        for parameter in flow["parameters"].as_array().cloned().unwrap_or_default() {
            if nodes.len() >= max_nodes {
                truncated = true;
                break;
            }
            let ordinal = parameter["ordinal"].as_u64().unwrap_or(0);
            let id = format!("{address}/parameter:{ordinal}");
            node_ids.insert(id.clone());
            nodes.push(json!({
                "id": id,
                "procedure": address,
                "evidence_id": evidence_id,
                "kind": "parameter",
                "operation": Value::Null,
                "parameter": parameter,
            }));
        }
        for usage in flow["parameter_uses"].as_array().cloned().unwrap_or_default() {
            let use_id = usage["use"].as_str().unwrap_or_default();
            let ordinal = usage["ordinal"].as_u64().unwrap_or(0);
            let parameter_node = format!("{address}/parameter:{ordinal}");
            if !ids.contains(use_id) || !node_ids.contains(&parameter_node) {
                continue;
            }
            if edges.len() >= max_edges {
                truncated = true;
                break;
            }
            edges.push(json!({
                "source": parameter_node,
                "target": qualified(use_id),
                "input_index": usage["input_index"],
                "kind": "parameter-use",
                "status": "derived",
                "evidence_id": evidence_id,
            }));
        }
        for edge in flow["def_use"].as_array().cloned().unwrap_or_default() {
            let definition = edge["definition"].as_str().unwrap_or_default();
            let use_id = edge["use"].as_str().unwrap_or_default();
            if !ids.contains(definition) || !ids.contains(use_id) {
                continue;
            }
            if edges.len() >= max_edges {
                truncated = true;
                break;
            }
            edges.push(json!({
                "source": qualified(definition),
                "target": qualified(use_id),
                "input_index": edge["input_index"],
                "kind": "def-use",
                "status": "derived",
                "evidence_id": evidence_id,
            }));
        }
        for operation in &operations {
            let id = operation["id"].as_str().unwrap_or_default();
            let opcode = operation["opcode"].as_str().unwrap_or_default();
            if !ids.contains(id) || !(opcode == "CALL" || opcode == "CALLIND") {
                continue;
            }
            let operation_address = operation["address"].as_str().unwrap_or_default();
            if call_sites >= max_call_sites {
                truncated = true;
                unknowns.push(unknown(&address, Some(operation_address), "Call-site resolution budget reached"));
                break;
            }
            call_sites += 1;
            let resolved = env
                .execute("resolve_native_call_targets", json!({ "address": operation_address }))
                .await;
            let resolved = match resolved {
                Ok(resolved) => resolved,
                Err(error) => {
                    if error.is_cancelled() {
                        return Err(error);
                    }
                    unknowns.push(unknown(&address, Some(operation_address), &error.message()));
                    continue;
                }
            };
            let targets_value = &resolved.result;
            let target_list = match targets_value["targets"].as_array() {
                Some(list) if targets_value.is_object() => list.clone(),
                _ => {
                    return Err(AnalysisError::output(
                        "resolve_native_call_targets",
                        "Invalid static call resolution",
                    ))
                }
            };
            if target_list.is_empty() {
                let status = targets_value["status"].as_str().unwrap_or_default();
                unknowns.push(unknown(&address, Some(operation_address), &format!("Call target {status}")));
            }
            for target in target_list {
                if edges.len() >= max_edges {
                    truncated = true;
                    break;
                }
                let destination = target["procedure"]
                    .as_str()
                    .or_else(|| target["address"].as_str())
                    .unwrap_or_default()
                    .to_string();
                let status = target["status"].as_str().unwrap_or_default().to_string();
                edges.push(json!({
                    "source": qualified(id),
                    "target": destination,
                    "input_index": Value::Null,
                    "kind": "call",
                    "status": status,
                    "evidence_id": evidence_id,
                }));
                if status != "candidate" {
                    bindings.push(Binding {
                        caller: address.clone(),
                        callee: destination.clone(),
                        call: qualified(id),
                        argument_count: operation["inputs"].as_array().map(|i| i.len().saturating_sub(1)).unwrap_or(0),
                        output: !operation["output"].is_null(),
                        evidence_id: evidence_id.clone(),
                    });
                }
                if depth < max_depth && status != "candidate" {
                    pending.push_back((destination, depth + 1));
                } else if !visited.contains(&destination) {
                    truncated = true;
                    unknowns.push(unknown(
                        &address,
                        Some(operation_address),
                        if status == "candidate" {
                            "Ambiguous call candidates were not traversed"
                        } else {
                            "Call depth budget reached"
                        },
                    ));
                }
            }
        }
        if truncated && (nodes.len() >= max_nodes || edges.len() >= max_edges || bytes >= NODE_BYTES) {
            break 'outer;
        }
    }

    let Some(target_sha256) = target_sha256 else {
        return Err(AnalysisError::output(
            "trace_native_values",
            "No seed function could be analyzed",
        ));
    };

    for binding in &bindings {
        let parameters: Vec<&Value> = nodes
            .iter()
            .filter(|n| n["procedure"] == json!(binding.callee) && n["kind"] == json!("parameter"))
            .collect();
        if parameters.is_empty() {
            unknowns.push(unknown(
                &binding.caller,
                None,
                &format!("Parameter bindings for {} are unavailable or omitted", binding.callee),
            ));
        }
        for node in parameters {
            let ordinal = node["parameter"]["ordinal"].as_u64();
            match ordinal {
                Some(o) if (o as usize) < binding.argument_count => {
                    if edges.len() >= max_edges {
                        truncated = true;
                        break;
                    }
                    edges.push(json!({
                        "source": binding.call,
                        "target": node["id"],
                        "input_index": o + 1,
                        "kind": "argument-binding",
                        "status": "derived",
                        "evidence_id": binding.evidence_id,
                    }));
                }
                other => {
                    let shown = other.map(|o| o.to_string()).unwrap_or_else(|| "unknown".to_string());
                    unknowns.push(unknown(
                        &binding.caller,
                        None,
                        &format!("Argument {shown} for {} was not recovered", binding.callee),
                    ));
                }
            }
        }
        if binding.output {
            let returns: Vec<Value> = nodes
                .iter()
                .filter(|n| {
                    n["procedure"] == json!(binding.callee)
                        && n["operation"]["opcode"] == json!("RETURN")
                        && n["operation"]["inputs"].as_array().map(|i| i.len() > 1).unwrap_or(false)
                })
                .cloned()
                .collect();
            for node in returns {
                if edges.len() >= max_edges {
                    truncated = true;
                    break;
                }
                edges.push(json!({
                    "source": node["id"],
                    "target": binding.call,
                    "input_index": 1,
                    "kind": "return-binding",
                    "status": "derived",
                    "evidence_id": node["evidence_id"],
                }));
            }
        }
    }

    let end = (offset + limit).min(nodes.len());
    let page: Vec<Value> = if offset < nodes.len() { nodes[offset..end].to_vec() } else { Vec::new() };
    let page_ids: HashSet<&str> = page.iter().filter_map(|n| n["id"].as_str()).collect();
    let page_edges: Vec<Value> = edges
        .iter()
        .filter(|e| e["source"].as_str().map(|s| page_ids.contains(s)).unwrap_or(false))
        .cloned()
        .collect();
    let next_offset = if offset + page.len() < nodes.len() {
        json!(offset + page.len())
    } else {
        Value::Null
    };
    let result = json!({
        "seed": seed,
        "target_sha256": target_sha256,
        "nodes": page,
        "edges": page_edges,
        "procedures": procedures,
        "unknowns": unknowns,
        "total_nodes": nodes.len(),
        "total_edges": edges.len(),
        "decompilations": decompilations,
        "next_offset": next_offset,
        "truncated": truncated || page.len() != nodes.len(),
        "limitations": [
            "Static decompiler def-use graphs cover recovered block members; when membership is unavailable they exclude operations marked dead. Logical CALL argument positions bind to recovered HighParam ordinals and RETURN values bind to recovered CALL outputs; these are decompiler-derived dependencies, not original source or runtime observations. Missing parameters, variadic arguments and alias dependencies remain unknown.",
            "LOAD and STORE are memory operations; object fields, persistent state and RNG semantics are not inferred from names or pseudocode.",
            "Traversal caps depth, decompilations, call-site resolutions, nodes, edges and node payloads (8 MiB). Complete serialized output is bounded to 32 MiB. Pagination reruns analysis and returns edges whose source is on the node page; endpoints outside the page retain stable identities.",
        ],
    });
    if serde_json::to_string(&result).map(|s| s.len()).unwrap_or(0) > OUTPUT_BYTES {
        return Err(AnalysisError::output(
            "trace_native_values",
            "Graph output exceeds 32 MiB; lower max_nodes, max_edges or page limit",
        ));
    }
    Ok(result)
}
