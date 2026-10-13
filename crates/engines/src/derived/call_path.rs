//! `build_call_path`: every shortest direct-callee path between two canonical addresses,
//! reconstructed inline from complete `analyze_function` Evidence records.
//!
//! Port of REA's `callPath.ts`. Missing dossiers and provider mixing stay `unknown`; every
//! node and edge cites the Evidence it comes from.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Value};

use super::dossier::{parse_function_evidence, FunctionSnapshot};
use super::util::sorted_unique;
use super::DerivedError;

const INPUT_PATTERN: &str = r"^(?:(?:[A-Za-z0-9._~\x2d]|%[0-9a-fA-F]{2})+:)?0[xX][0-9a-fA-F]+$";

fn input_address_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(INPUT_PATTERN).expect("valid pattern"))
}

/// `parseCallPathAddress`: validate and normalize a hexadecimal offset, keeping its optional
/// address space (percent escapes upper-cased, offset lower-cased without leading zeros).
pub fn parse_call_path_address(input: &str) -> Result<String, DerivedError> {
    if !input_address_pattern().is_match(input) {
        return Err(DerivedError::Input(format!(
            "at the document root: Invalid string: must match pattern /{INPUT_PATTERN}/u"
        )));
    }
    let separator = input.rfind(':').map_or(0, |index| index + 1);
    let (space, offset) = input.split_at(separator);
    let mut normalized = String::with_capacity(input.len());
    let mut chars = space.chars();
    while let Some(c) = chars.next() {
        normalized.push(c);
        if c == '%' {
            // The pattern guarantees two hexadecimal digits after every percent sign.
            for _ in 0..2 {
                if let Some(digit) = chars.next() {
                    normalized.push(digit.to_ascii_uppercase());
                }
            }
        }
    }
    let digits = offset[2..].trim_start_matches('0').to_ascii_lowercase();
    normalized.push_str("0x");
    normalized.push_str(if digits.is_empty() { "0" } else { &digits });
    Ok(normalized)
}

/// Minimal directed caller-to-callee adjacency.
#[derive(Default)]
struct CallGraph {
    successors: BTreeMap<String, BTreeSet<String>>,
    predecessors: HashMap<String, Vec<String>>,
}

impl CallGraph {
    fn merge_node(&mut self, node: &str) {
        self.successors.entry(node.to_string()).or_default();
        self.predecessors.entry(node.to_string()).or_default();
    }

    fn merge_edge(&mut self, source: &str, target: &str) {
        self.merge_node(source);
        self.merge_node(target);
        self.successors.get_mut(source).expect("merged").insert(target.to_string());
        let predecessors = self.predecessors.get_mut(target).expect("merged");
        if !predecessors.iter().any(|existing| existing == source) {
            predecessors.push(source.to_string());
        }
    }

    fn has_node(&self, node: &str) -> bool {
        self.successors.contains_key(node)
    }

    fn out_degree(&self, node: &str) -> usize {
        self.successors.get(node).map_or(0, BTreeSet::len)
    }

    /// Sorted by code point, which is the only order the search ever uses.
    fn out_neighbors(&self, node: &str) -> Vec<String> {
        self.successors.get(node).map(|set| set.iter().cloned().collect()).unwrap_or_default()
    }

    fn in_neighbors(&self, node: &str) -> &[String] {
        self.predecessors.get(node).map_or(&[], Vec::as_slice)
    }
}

/// Shortest remaining distance for every node that can reach the goal.
fn distances_to_goal(graph: &CallGraph, goal: &str) -> HashMap<String, usize> {
    let mut depth = HashMap::new();
    if !graph.has_node(goal) {
        return depth;
    }
    depth.insert(goal.to_string(), 0);
    let mut queue = VecDeque::from([goal.to_string()]);
    while let Some(node) = queue.pop_front() {
        let next = depth[&node] + 1;
        for neighbor in graph.in_neighbors(&node) {
            if !depth.contains_key(neighbor) {
                depth.insert(neighbor.clone(), next);
                queue.push_back(neighbor.clone());
            }
        }
    }
    depth
}

struct Search {
    reached: HashMap<String, usize>,
    exhaustive: bool,
    limitations: Vec<String>,
}

fn inspect_search(graph: &CallGraph, snapshots: &Snapshots, start: &str, goal: &str) -> Search {
    if !graph.has_node(start) {
        return Search {
            reached: HashMap::new(),
            exhaustive: false,
            limitations: vec![format!("No analyze_function Evidence was supplied for start {start}")],
        };
    }
    let mut reached = HashMap::from([(start.to_string(), 0usize)]);
    let mut queue = VecDeque::from([start.to_string()]);
    let mut limitations = Vec::new();
    while let Some(node) = queue.pop_front() {
        let depth = reached[&node];
        if node == goal {
            continue;
        }
        if snapshots.get(&node).is_none() {
            limitations.push(format!("No analyze_function Evidence covers reachable function {node}"));
            continue;
        }
        for neighbor in graph.out_neighbors(&node) {
            if !reached.contains_key(&neighbor) {
                reached.insert(neighbor.clone(), depth + 1);
                queue.push_back(neighbor);
            }
        }
    }
    Search {
        reached,
        exhaustive: limitations.is_empty(),
        limitations,
    }
}

/// Enumerate every shortest path with the same depth-first order as REA.
fn enumerate_paths(graph: &CallGraph, start: &str, goal: &str, distances: &HashMap<String, usize>) -> Vec<Vec<String>> {
    struct Frame {
        neighbors: Vec<String>,
        next_index: usize,
    }
    let frame = |node: &str| -> Frame {
        let neighbors = match distances.get(node) {
            Some(&distance) if distance > 0 => graph
                .out_neighbors(node)
                .into_iter()
                .filter(|neighbor| distances.get(neighbor) == Some(&(distance - 1)))
                .collect(),
            _ => Vec::new(),
        };
        Frame { neighbors, next_index: 0 }
    };
    let mut output = Vec::new();
    let mut path = vec![start.to_string()];
    let mut pending = vec![frame(start)];
    while let Some(current) = pending.last_mut() {
        if path.last().map(String::as_str) == Some(goal) {
            output.push(path.clone());
            pending.pop();
            path.pop();
            continue;
        }
        let Some(neighbor) = current.neighbors.get(current.next_index).cloned() else {
            pending.pop();
            path.pop();
            continue;
        };
        current.next_index += 1;
        pending.push(frame(&neighbor));
        path.push(neighbor);
    }
    output
}

/// Parsed snapshots in insertion order, addressable by canonical entry address.
struct Snapshots {
    order: Vec<String>,
    by_address: HashMap<String, FunctionSnapshot>,
}

impl Snapshots {
    fn get(&self, address: &str) -> Option<&FunctionSnapshot> {
        self.by_address.get(address)
    }

    fn values(&self) -> impl Iterator<Item = &FunctionSnapshot> {
        self.order.iter().filter_map(|address| self.by_address.get(address))
    }
}

fn parse_snapshots(functions: &[Value]) -> Result<Snapshots, DerivedError> {
    let mut snapshots = Snapshots {
        order: Vec::new(),
        by_address: HashMap::new(),
    };
    for group in functions {
        let snapshot = parse_function_evidence(group)?;
        let address = parse_call_path_address(snapshot.address())?;
        for callee in snapshot.field("callees") {
            parse_call_path_address(callee["address"].as_str().unwrap_or(""))?;
        }
        if snapshots.by_address.contains_key(&address) {
            return Err(DerivedError::Input(format!("Duplicate function Evidence for {address}")));
        }
        snapshots.order.push(address.clone());
        snapshots.by_address.insert(address, snapshot);
    }
    Ok(snapshots)
}

fn assert_compatible(snapshots: &Snapshots) -> Result<(), DerivedError> {
    let Some(first) = snapshots.values().next() else {
        return Ok(());
    };
    for snapshot in snapshots.values() {
        if snapshot.subject.digest.sha256 != first.subject.digest.sha256
            || snapshot.subject.format != first.subject.format
            || snapshot.subject.architecture != first.subject.architecture
        {
            return Err(DerivedError::Input("Call-path Evidence mixes artifact subjects".into()));
        }
        let (a, b) = (&snapshot.evidence.provider, &first.evidence.provider);
        if a.id != b.id || a.name != b.name || a.version != b.version {
            return Err(DerivedError::Input("Call-path Evidence mixes providers".into()));
        }
    }
    Ok(())
}

fn create_graph(snapshots: &Snapshots) -> Result<CallGraph, DerivedError> {
    let mut graph = CallGraph::default();
    for address in &snapshots.order {
        let snapshot = &snapshots.by_address[address];
        graph.merge_node(address);
        for callee in snapshot.field("callees") {
            let callee_address = parse_call_path_address(callee["address"].as_str().unwrap_or(""))?;
            graph.merge_node(&callee_address);
            graph.merge_edge(address, &callee_address);
        }
    }
    Ok(graph)
}

fn snapshot_links(snapshot: Option<&FunctionSnapshot>) -> Result<Vec<String>, DerivedError> {
    snapshot
        .map(|snapshot| vec![snapshot.evidence.evidence_id.clone()])
        .ok_or_else(|| DerivedError::Input("Every call-path claim requires supporting Evidence".into()))
}

fn cite_path(addresses: &[String], snapshots: &Snapshots) -> Result<Value, DerivedError> {
    let mut edges = Vec::new();
    for pair in addresses.windows(2) {
        edges.push(json!({
            "source": pair[0],
            "target": pair[1],
            "evidence_links": snapshot_links(snapshots.get(&pair[0]))?,
        }));
    }
    let mut nodes = Vec::new();
    for (index, address) in addresses.iter().enumerate() {
        let snapshot = snapshots.get(address);
        let supporting = snapshot.or_else(|| {
            if index > 0 {
                snapshots.get(&addresses[index - 1])
            } else {
                None
            }
        });
        nodes.push(json!({
            "address": address,
            "name": snapshot.map_or(Value::Null, |s| json!(s.name())),
            "evidence_links": snapshot_links(supporting)?,
        }));
    }
    let mut links: Vec<String> = Vec::new();
    for item in edges.iter().chain(nodes.iter()) {
        for link in item["evidence_links"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            if !links.iter().any(|existing| existing == link) {
                links.push(link.to_string());
            }
        }
    }
    Ok(json!({
        "hops": edges.len(),
        "nodes": nodes,
        "edges": edges,
        "evidence_links": links,
    }))
}

/// Reconstruct direct-callee paths from explicit `analyze_function` Evidence. `start` and
/// `goal` are already canonical addresses (see [`parse_call_path_address`]).
pub fn build_call_path(functions: &[Value], start: &str, goal: &str) -> Result<Value, DerivedError> {
    let snapshots = parse_snapshots(functions)?;
    assert_compatible(&snapshots)?;
    if snapshots.get(start).is_none() {
        return Err(DerivedError::Input(format!(
            "No analyze_function Evidence was supplied for start {start}"
        )));
    }
    let graph = create_graph(&snapshots)?;
    let search = inspect_search(&graph, &snapshots, start, goal);
    let distances = distances_to_goal(&graph, goal);
    let paths: Vec<Value> = if distances.contains_key(start) {
        enumerate_paths(&graph, start, goal, &distances)
            .iter()
            .map(|path| cite_path(path, &snapshots))
            .collect::<Result<_, _>>()?
    } else {
        Vec::new()
    };
    let explored = json!({
        "nodes": search.reached.len(),
        "edges": search.reached.keys().map(|node| graph.out_degree(node)).sum::<usize>(),
        "depth_reached": search.reached.values().copied().max().unwrap_or(0),
    });
    let mut evidence_links = Vec::new();
    for snapshot in snapshots.values() {
        evidence_links.extend(snapshot_links(Some(snapshot))?);
    }
    let context = json!({
        "start": start,
        "goal": goal,
        "explored": explored,
        "evidence_links": sorted_unique(evidence_links),
        "limitations": sorted_unique(search.limitations.clone()),
    });
    let mut result = context.as_object().cloned().unwrap_or_default();
    if let Some(shortest) = paths.first().map(|path| path["hops"].clone()) {
        result.insert("status".into(), json!("found"));
        result.insert("shortest_hops".into(), shortest);
        result.insert("search_scope".into(), json!({ "exhaustive": search.exhaustive }));
        result.insert("paths".into(), Value::Array(paths));
    } else {
        result.insert("status".into(), json!(if search.exhaustive { "not_found" } else { "unknown" }));
        result.insert("shortest_hops".into(), Value::Null);
        result.insert("search_scope".into(), json!({ "exhaustive": search.exhaustive }));
        result.insert("paths".into(), json!([]));
    }
    Ok(Value::Object(result))
}

/// The residual Unknown REA registers when the path could not be established.
pub fn unknown_input(evidence_id: &str) -> Value {
    json!({
        "question": "Can the requested call path be established from complete analysis?",
        "severity": "high",
        "domain": "call-path",
        "supporting_evidence_ids": [evidence_id],
        "contradicting_evidence_ids": [],
        "required_authority": "shipped-artifact",
        "required_confidence": "derived",
        "required_environment": null,
        "recommended_probes": [{
            "operation": "analyze_function",
            "rationale": "Collect complete callee dossiers for the reported frontier addresses.",
        }],
        "relationships": [],
    })
}
