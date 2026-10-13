//! Source-range lookups over one file's IR (REA `JavaScriptSemanticGraphProjection.ts`) and the
//! container/slot helpers of `javascriptSemanticSlots.ts`.

use std::collections::HashMap;

use crate::jsgraph::ast::{SourcePoint, SourceRange};
use crate::jsgraph::ir::{
    SemanticCallSite, SemanticCallable, SemanticProperty, SemanticValue, SlotPresence,
};

use super::construction::NodeRef;

fn point_compare(left: &SourcePoint, right: &SourcePoint) -> i64 {
    if left.line != right.line {
        left.line as i64 - right.line as i64
    } else {
        left.column as i64 - right.column as i64
    }
}

fn contains(outer: &SourceRange, inner: &SourceRange) -> bool {
    point_compare(&outer.start, &inner.start) <= 0 && point_compare(&outer.end, &inner.end) >= 0
}

fn range_key(range: &SourceRange) -> String {
    format!(
        "{}:{}-{}:{}",
        range.start.line, range.start.column, range.end.line, range.end.column
    )
}

struct Tree {
    entry: usize,
    minimum_start: SourcePoint,
    maximum_start: SourcePoint,
    minimum_end: SourcePoint,
    maximum_end: SourcePoint,
    left: Option<Box<Tree>>,
    right: Option<Box<Tree>>,
}

/// Balanced index over entries sorted by start (the recursion follows the index, not nesting).
fn build_tree(ranges: &[SourceRange], order: &[usize], start: usize, end: usize) -> Option<Box<Tree>> {
    if start >= end {
        return None;
    }
    let middle = (start + end) / 2;
    let entry = order[middle];
    let left = build_tree(ranges, order, start, middle);
    let right = build_tree(ranges, order, middle + 1, end);
    let range = &ranges[entry];
    let mut minimum_end = range.end;
    let mut maximum_end = range.end;
    for child in [&left, &right].into_iter().flatten() {
        if point_compare(&child.minimum_end, &minimum_end) < 0 {
            minimum_end = child.minimum_end;
        }
        if point_compare(&child.maximum_end, &maximum_end) > 0 {
            maximum_end = child.maximum_end;
        }
    }
    Some(Box::new(Tree {
        entry,
        minimum_start: left.as_ref().map_or(range.start, |l| l.minimum_start),
        maximum_start: right.as_ref().map_or(range.start, |r| r.maximum_start),
        minimum_end,
        maximum_end,
        left,
        right,
    }))
}

fn sorted_order(ranges: &[SourceRange]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..ranges.len()).collect();
    order.sort_by(|a, b| {
        point_compare(&ranges[*a].start, &ranges[*b].start)
            .cmp(&0)
            .then(a.cmp(b))
    });
    order
}

/// Innermost retained callable containing a location.
pub struct CallableOwnerLookup {
    ranges: Vec<SourceRange>,
    callable_ids: Vec<String>,
    tree: Option<Box<Tree>>,
    nodes: HashMap<String, NodeRef>,
}

impl CallableOwnerLookup {
    pub fn new(callables: &[SemanticCallable], nodes: &HashMap<String, NodeRef>) -> Self {
        let ranges: Vec<SourceRange> = callables.iter().map(|c| c.location).collect();
        let callable_ids: Vec<String> = callables.iter().map(|c| c.callable_id.clone()).collect();
        let order = sorted_order(&ranges);
        let tree = build_tree(&ranges, &order, 0, order.len());
        CallableOwnerLookup { ranges, callable_ids, tree, nodes: nodes.clone() }
    }

    pub fn at(&self, location: Option<&SourceRange>) -> Option<NodeRef> {
        let location = location?;
        let tree = self.tree.as_ref()?;
        if self.nodes.is_empty() {
            return None;
        }
        let mut pending: Vec<&Tree> = vec![tree];
        let mut best: Option<usize> = None;
        let mut result: Option<NodeRef> = None;
        while let Some(current) = pending.pop() {
            if point_compare(&current.minimum_start, &location.start) > 0
                || point_compare(&current.maximum_end, &location.end) < 0
            {
                continue;
            }
            let candidate = current.entry;
            if contains(&self.ranges[candidate], location) {
                let node = self.nodes.get(&self.callable_ids[candidate]);
                let rank = match best {
                    None => 1,
                    Some(best) => {
                        let by_priority = point_compare(&self.ranges[candidate].start, &self.ranges[best].start);
                        if by_priority != 0 {
                            by_priority
                        } else {
                            best as i64 - candidate as i64
                        }
                    }
                };
                if let (Some(node), true) = (node, rank > 0) {
                    best = Some(candidate);
                    result = Some(node.clone());
                }
            }
            if let Some(left) = &current.left {
                pending.push(left);
            }
            if let Some(right) = &current.right {
                pending.push(right);
            }
        }
        result
    }
}

/// Nodes whose source range lies inside a query range, in producer order.
pub struct NodeRangeLookup {
    nodes: Vec<NodeRef>,
    ranges: Vec<SourceRange>,
    orders: Vec<usize>,
    tree: Option<Box<Tree>>,
}

impl NodeRangeLookup {
    pub fn new(nodes: &[NodeRef]) -> Self {
        let mut kept: Vec<NodeRef> = Vec::new();
        let mut ranges: Vec<SourceRange> = Vec::new();
        let mut orders: Vec<usize> = Vec::new();
        for (order, node) in nodes.iter().enumerate() {
            if let Some(range) = node.source_range {
                kept.push(node.clone());
                ranges.push(range);
                orders.push(order);
            }
        }
        let sorted = sorted_order(&ranges);
        let tree = build_tree(&ranges, &sorted, 0, sorted.len());
        NodeRangeLookup { nodes: kept, ranges, orders, tree }
    }

    pub fn within(&self, range: &SourceRange) -> Vec<NodeRef> {
        let Some(tree) = &self.tree else {
            return Vec::new();
        };
        let mut pending: Vec<&Tree> = vec![tree];
        let mut matches: Vec<usize> = Vec::new();
        while let Some(current) = pending.pop() {
            if point_compare(&current.maximum_start, &range.start) < 0
                || point_compare(&current.minimum_end, &range.end) > 0
            {
                continue;
            }
            if contains(range, &self.ranges[current.entry]) {
                matches.push(current.entry);
            }
            if let Some(left) = &current.left {
                pending.push(left);
            }
            if let Some(right) = &current.right {
                pending.push(right);
            }
        }
        matches.sort_by_key(|entry| self.orders[*entry]);
        matches.into_iter().map(|entry| self.nodes[entry].clone()).collect()
    }
}

/// Exact call ranges, preserving the first producer occurrence.
pub struct CallSiteLookup {
    nodes: HashMap<String, NodeRef>,
    ids: HashMap<String, String>,
}

impl CallSiteLookup {
    pub fn new(call_sites: &[SemanticCallSite], nodes: &HashMap<String, NodeRef>) -> Self {
        let mut ids: HashMap<String, String> = HashMap::new();
        for call in call_sites {
            ids.entry(range_key(&call.location)).or_insert_with(|| call.call_site_id.clone());
        }
        CallSiteLookup { nodes: nodes.clone(), ids }
    }

    pub fn at(&self, range: &SourceRange) -> Option<NodeRef> {
        self.ids.get(&range_key(range)).and_then(|id| self.nodes.get(id)).cloned()
    }
}

// ---- javascriptSemanticSlots.ts ---------------------------------------------------------------

/// Static container inventory; partial siblings do not weaken retained slots.
pub struct Container<'a> {
    pub slots: &'a [SemanticProperty],
    /// `complete` or `partial`.
    pub status: &'static str,
    pub omitted: Option<u64>,
}

pub fn semantic_container(value: &SemanticValue) -> Option<Container<'_>> {
    match value {
        SemanticValue::Object { properties, unknown_properties, omitted_properties } => Some(Container {
            slots: properties,
            status: if *unknown_properties { "partial" } else { "complete" },
            omitted: if *unknown_properties { *omitted_properties } else { Some(0) },
        }),
        SemanticValue::Array { items, unknown_items, omitted_items } => Some(Container {
            slots: items,
            status: if *unknown_items { "partial" } else { "complete" },
            omitted: if *unknown_items { *omitted_items } else { Some(0) },
        }),
        _ => None,
    }
}

/// JSON Pointer encoding of a static property path (empty keys preserved).
pub fn semantic_property_pointer(path: &[String]) -> String {
    path.iter()
        .map(|key| format!("/{}", key.replace('~', "~0").replace('/', "~1")))
        .collect()
}

fn value_status(value: &SemanticValue) -> &'static str {
    match value {
        SemanticValue::Literal { .. } => "literal",
        SemanticValue::Union { .. } => "union",
        SemanticValue::Object { .. } => "object",
        SemanticValue::Array { .. } => "array",
        SemanticValue::Unknown { .. } => "unknown",
        SemanticValue::Ambiguous { .. } => "ambiguous",
        SemanticValue::Cycle { .. } => "cycle",
    }
}

pub fn value_status_text(value: &SemanticValue) -> &'static str {
    value_status(value)
}

/// Resolve a full static own-property path without conflating missing siblings.
pub fn semantic_slot_at_path(value: &SemanticValue, path: &[String]) -> SemanticProperty {
    let leaf_name = path.last().cloned().unwrap_or_default();
    let mut current = SemanticProperty {
        name: String::new(),
        presence: SlotPresence::Present,
        value: value.clone(),
    };
    for (index, name) in path.iter().enumerate() {
        let container = semantic_container(&current.value);
        if current.presence != SlotPresence::Present || container.is_none() {
            let blocked_value = match &current.value {
                SemanticValue::Unknown { reason, resource_limit } => SemanticValue::Unknown {
                    reason: format!(
                        "{reason} Cannot continue {} through receiver {}.",
                        semantic_property_pointer(path),
                        semantic_property_pointer(&path[..index])
                    ),
                    resource_limit: *resource_limit,
                },
                SemanticValue::Ambiguous { reason, resource_limit } => SemanticValue::Ambiguous {
                    reason: format!(
                        "{reason} Cannot continue {} through receiver {}.",
                        semantic_property_pointer(path),
                        semantic_property_pointer(&path[..index])
                    ),
                    resource_limit: *resource_limit,
                },
                SemanticValue::Cycle { reason, resource_limit } => SemanticValue::Cycle {
                    reason: format!(
                        "{reason} Cannot continue {} through receiver {}.",
                        semantic_property_pointer(path),
                        semantic_property_pointer(&path[..index])
                    ),
                    resource_limit: *resource_limit,
                },
                other => SemanticValue::Unknown {
                    reason: format!(
                        "Cannot resolve {} through {} receiver {}.",
                        semantic_property_pointer(path),
                        value_status(other),
                        semantic_property_pointer(&path[..index])
                    ),
                    resource_limit: None,
                },
            };
            return SemanticProperty {
                name: leaf_name,
                presence: SlotPresence::UnknownCoverage,
                value: blocked_value,
            };
        }
        let container = container.expect("checked above");
        // Array position inventories omit the intrinsic `length` slot.
        if matches!(current.value, SemanticValue::Array { .. }) && name == "length" {
            current = SemanticProperty {
                name: name.clone(),
                presence: SlotPresence::Present,
                value: SemanticValue::Unknown {
                    reason: "Array length is present but its value is not retained.".into(),
                    resource_limit: None,
                },
            };
            continue;
        }
        let observed = container.slots.iter().find(|slot| &slot.name == name).cloned();
        current = observed.unwrap_or_else(|| SemanticProperty {
            name: name.clone(),
            presence: if container.status == "complete" {
                SlotPresence::Absent
            } else {
                SlotPresence::UnknownCoverage
            },
            value: SemanticValue::Unknown {
                reason: format!("Own property {name} was not observed."),
                resource_limit: None,
            },
        });
    }
    current
}
