//! Port of `javascriptSemanticMutationValues.ts`: invalidate slots that mutations or escapes
//! can reach.

use std::collections::{HashMap, HashSet};

use crate::jsgraph::ir::{SemanticProperty, SemanticValue, SlotPresence};

use super::property_paths::{semantic_property_path_key_matches, PathKey, PropertyPath};
use super::value_types::unknown;

/// Invalidate escaped object references without rewriting their containing slots.
pub fn invalidate_semantic_escaped_path(value: &SemanticValue, path: &[PathKey]) -> SemanticValue {
    if !matches!(value, SemanticValue::Object { .. } | SemanticValue::Array { .. }) {
        return value.clone();
    }
    let Some((key, remaining)) = path.split_first() else {
        return unknown("This object reference may have been mutated by a call.");
    };
    let invalidate_child = |property: &SemanticProperty| -> SemanticProperty {
        if semantic_property_path_key_matches(key, &property.name) {
            SemanticProperty {
                value: invalidate_semantic_escaped_path(&property.value, remaining),
                ..property.clone()
            }
        } else {
            property.clone()
        }
    };
    match value {
        SemanticValue::Object { properties, unknown_properties, omitted_properties } => SemanticValue::Object {
            properties: properties.iter().map(invalidate_child).collect(),
            unknown_properties: *unknown_properties,
            omitted_properties: *omitted_properties,
        },
        SemanticValue::Array { items, unknown_items, omitted_items } => SemanticValue::Array {
            items: items.iter().map(invalidate_child).collect(),
            unknown_items: *unknown_items,
            omitted_items: *omitted_items,
        },
        _ => unreachable!("object or array checked above"),
    }
}

/// Invalidate only slots that explicit mutations can affect, as if applying each path in order.
/// Paths are grouped per slot so that many writes to one object cost one pass over its slots
/// rather than one pass per write.
pub fn invalidate_semantic_mutation_paths(value: &SemanticValue, paths: &[PropertyPath]) -> SemanticValue {
    if paths.is_empty() {
        return value.clone();
    }
    // An unknown key or a replaced value leaves nothing that a later path can restore, wherever
    // it occurs in the sequence.
    if !matches!(value, SemanticValue::Object { .. } | SemanticValue::Array { .. })
        || paths.iter().any(|path| matches!(path.first(), None | Some(PathKey::Null)))
    {
        return unknown("This property may have been mutated.");
    }
    // Writing an array length discards every item known before it.
    let is_array = matches!(value, SemanticValue::Array { .. });
    let reset: isize = if is_array {
        paths
            .iter()
            .rposition(|path| matches!(path.first(), Some(PathKey::Name(name)) if name == "length"))
            .map_or(-1, |position| position as isize)
    } else {
        -1
    };
    let empty_array;
    let base: &SemanticValue = if reset < 0 {
        value
    } else {
        empty_array = SemanticValue::Array { items: Vec::new(), unknown_items: true, omitted_items: None };
        &empty_array
    };
    let slots: &[SemanticProperty] = match base {
        SemanticValue::Object { properties, .. } => properties,
        SemanticValue::Array { items, .. } => items,
        _ => unreachable!("object or array checked above"),
    };
    let mut slots_by_name: HashMap<&str, Vec<usize>> = HashMap::new();
    for (index, property) in slots.iter().enumerate() {
        slots_by_name.entry(property.name.as_str()).or_default().push(index);
    }
    let mut slot_paths: HashMap<usize, Vec<PropertyPath>> = HashMap::new();
    let mut replaced_slots: HashSet<usize> = HashSet::new();
    // An added slot is already unknown, so later paths that select it are inert.
    let mut added: Vec<String> = Vec::new();
    let mut added_seen: HashSet<String> = HashSet::new();
    let mut select = |index: usize, remaining: &[PathKey]| {
        slot_paths.entry(index).or_default().push(remaining.to_vec());
        if remaining.is_empty() {
            replaced_slots.insert(index);
        }
    };
    for path in &paths[(reset + 1) as usize..] {
        let Some((key, remaining)) = path.split_first() else { continue };
        if matches!(key, PathKey::Null) {
            continue;
        }
        if key.is_selection() {
            for (index, property) in slots.iter().enumerate() {
                if semantic_property_path_key_matches(key, &property.name) {
                    select(index, remaining);
                }
            }
            continue;
        }
        let name = key.js_string();
        match slots_by_name.get(name.as_str()) {
            None => {
                if added_seen.insert(name.clone()) {
                    added.push(name);
                }
            }
            Some(indexes) => {
                for &index in indexes {
                    select(index, remaining);
                }
            }
        }
    }
    let mut properties: Vec<SemanticProperty> = slots
        .iter()
        .enumerate()
        .map(|(index, property)| match slot_paths.get(&index) {
            None => property.clone(),
            Some(selected) => SemanticProperty {
                name: property.name.clone(),
                presence: if replaced_slots.contains(&index) {
                    SlotPresence::UnknownCoverage
                } else {
                    property.presence
                },
                value: invalidate_semantic_mutation_paths(&property.value, selected),
            },
        })
        .collect();
    for name in added {
        properties.push(SemanticProperty {
            name,
            value: unknown("This property may have been mutated."),
            presence: SlotPresence::UnknownCoverage,
        });
    }
    match base {
        SemanticValue::Object { unknown_properties, omitted_properties, .. } => SemanticValue::Object {
            properties,
            unknown_properties: *unknown_properties,
            omitted_properties: *omitted_properties,
        },
        SemanticValue::Array { unknown_items, omitted_items, .. } => SemanticValue::Array {
            items: properties,
            unknown_items: *unknown_items,
            omitted_items: *omitted_items,
        },
        _ => unreachable!("object or array checked above"),
    }
}
