//! Bounded caller/callee traversal (port of `CallPathTracing.ts`).

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::error::AnalysisError;

use super::{parse_related_addresses, Env};

struct Node {
    depth: usize,
    path: Vec<String>,
}

/// Trace direct caller/callee relationships until the graph is exhausted or the goal is reached.
pub async fn trace(env: &Env<'_>, input: &Value) -> Result<Value, AnalysisError> {
    let start_input = input.get("start").and_then(Value::as_str).unwrap_or_default();
    let forward = input.get("direction").and_then(Value::as_str).unwrap_or("forward") == "forward";
    let start = env.resolve_procedure_address(start_input).await?;
    let goal = match input.get("goal").and_then(Value::as_str) {
        Some(goal) => Some(env.resolve_procedure_address(goal).await?),
        None => None,
    };
    let (relation, tool) = if forward {
        ("callees", "procedure_callees")
    } else {
        ("callers", "procedure_callers")
    };
    // `visited` keeps insertion order for stable queue handling; sorting happens in the projection.
    let mut visited: Vec<(String, Node)> = vec![(
        start.clone(),
        Node {
            depth: 0,
            path: vec![start.clone()],
        },
    )];
    let mut index_of: BTreeMap<String, usize> = BTreeMap::from([(start.clone(), 0)]);
    let mut queue: Vec<String> = vec![start.clone()];
    let mut queue_index = 0;
    let mut edges: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut edge_order: Vec<(String, String, usize)> = Vec::new();
    let mut failures: Vec<Value> = Vec::new();
    let mut residual: Vec<String> = Vec::new();
    let mut traversal_path: Vec<String> = if goal.as_deref() == Some(start.as_str()) {
        vec![start.clone()]
    } else {
        Vec::new()
    };

    while queue_index < queue.len() && traversal_path.is_empty() {
        let address = queue[queue_index].clone();
        queue_index += 1;
        let Some(&position) = index_of.get(&address) else {
            continue;
        };
        let (current_depth, current_path) = {
            let node = &visited[position].1;
            (node.depth, node.path.clone())
        };
        let result = env.call(tool, json!({ "procedure": address })).await;
        let result = match result {
            Ok(value) => value,
            Err(error) => {
                failures.push(json!({ "address": address, "error": error.project() }));
                let note = format!("Call relationships were unavailable for {address}.");
                if !residual.contains(&note) {
                    residual.push(note);
                }
                continue;
            }
        };
        let related = match parse_related_addresses(&result, relation) {
            Ok(list) => list,
            Err(error) => {
                failures.push(json!({ "address": address, "error": error.project() }));
                let note = format!("Call relationships were unreadable for {address}.");
                if !residual.contains(&note) {
                    residual.push(note);
                }
                continue;
            }
        };
        let mut found = false;
        for related_address in sorted_unique(&related) {
            let (source, target) = if forward {
                (address.clone(), related_address.clone())
            } else {
                (related_address.clone(), address.clone())
            };
            if let std::collections::btree_map::Entry::Vacant(slot) = edges.entry((source.clone(), target.clone())) {
                slot.insert(current_depth + 1);
                edge_order.push((source, target, current_depth + 1));
            }
            let path = match index_of.get(&related_address) {
                Some(&p) => visited[p].1.path.clone(),
                None => {
                    let mut p = current_path.clone();
                    p.push(related_address.clone());
                    p
                }
            };
            if index_of.contains_key(&related_address) {
                if goal.as_deref() == Some(related_address.as_str()) {
                    traversal_path = path;
                    found = true;
                    break;
                }
                continue;
            }
            index_of.insert(related_address.clone(), visited.len());
            visited.push((
                related_address.clone(),
                Node {
                    depth: current_depth + 1,
                    path: path.clone(),
                },
            ));
            if goal.as_deref() == Some(related_address.as_str()) {
                traversal_path = path;
                found = true;
                break;
            }
            queue.push(related_address);
        }
        if found {
            break;
        }
    }

    let mut nodes: Vec<(usize, String)> = visited.iter().map(|(a, n)| (n.depth, a.clone())).collect();
    nodes.sort_by(|l, r| l.0.cmp(&r.0).then_with(|| l.1.cmp(&r.1)));
    let mut edge_list: Vec<(String, String, usize)> = edge_order;
    edge_list.sort_by(|l, r| l.2.cmp(&r.2).then_with(|| l.0.cmp(&r.0)).then_with(|| l.1.cmp(&r.1)));
    let goal_status = match (&goal, traversal_path.is_empty()) {
        (None, _) => "not_requested",
        (Some(_), false) => "reached",
        (Some(_), true) => "not_reached",
    };
    Ok(json!({
        "start": start,
        "goal": goal,
        "direction": if forward { "forward" } else { "backward" },
        "goal_status": goal_status,
        "nodes": nodes.iter().map(|(depth, address)| json!({ "address": address, "depth": depth })).collect::<Vec<_>>(),
        "edges": edge_list.iter().map(|(source, target, depth)| json!({
            "source_address": source,
            "target_address": target,
            "discovery_depth": depth,
        })).collect::<Vec<_>>(),
        "traversal_path": traversal_path,
        "failures": failures,
        "traversal": { "nodes_visited": visited.len() },
        "truncated": !residual.is_empty(),
        "residual_unknowns": residual,
        "limitations": ["Direct provider call relationships may omit unresolved indirect calls."],
    }))
}

fn sorted_unique(addresses: &[String]) -> Vec<String> {
    let mut sorted: Vec<String> = addresses.to_vec();
    sorted.sort();
    sorted.dedup();
    sorted
}
