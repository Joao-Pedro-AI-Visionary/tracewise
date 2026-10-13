//! Port of `javascriptSemanticSlots.ts`: static container inventory and own-slot paths.

use std::borrow::Cow;

use crate::jsgraph::ir::{SemanticProperty, SemanticValue, SlotPresence};

use super::value_types::{reason_of, status_of, unknown, with_reason};

/// Coverage of a container: partial siblings do not weaken retained slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainerCoverage {
    Complete,
    Partial { omitted: Option<u64> },
}

/// Static container inventory (`JavaScriptSemanticContainer`).
pub struct SemanticContainer<'v> {
    pub slots: &'v [SemanticProperty],
    pub coverage: ContainerCoverage,
}

/// Read the same slot inventory for object, array, and return projections.
pub fn semantic_container(value: &SemanticValue) -> Option<SemanticContainer<'_>> {
    match value {
        SemanticValue::Object { properties, unknown_properties, omitted_properties } => {
            Some(SemanticContainer {
                slots: properties,
                coverage: if *unknown_properties {
                    ContainerCoverage::Partial { omitted: *omitted_properties }
                } else {
                    ContainerCoverage::Complete
                },
            })
        }
        SemanticValue::Array { items, unknown_items, omitted_items } => Some(SemanticContainer {
            slots: items,
            coverage: if *unknown_items {
                ContainerCoverage::Partial { omitted: *omitted_items }
            } else {
                ContainerCoverage::Complete
            },
        }),
        _ => None,
    }
}

/// Encode path segments as an unambiguous JSON Pointer, preserving empty keys.
pub fn semantic_property_pointer(path: &[String]) -> String {
    path.iter()
        .map(|key| format!("/{}", key.replace('~', "~0").replace('/', "~1")))
        .collect()
}

/// The slot reached by [`semantic_slot_at_path`]: presence plus the (possibly borrowed) value.
pub struct SlotRef<'v> {
    pub presence: SlotPresence,
    pub value: Cow<'v, SemanticValue>,
}

/// Resolve a full static own-property path without conflating missing siblings.
pub fn semantic_slot_at_path<'v>(value: &'v SemanticValue, path: &[String]) -> SlotRef<'v> {
    let mut current = SlotRef { presence: SlotPresence::Present, value: Cow::Borrowed(value) };
    for (index, name) in path.iter().enumerate() {
        let container_missing = semantic_container(&current.value).is_none();
        if current.presence != SlotPresence::Present || container_missing {
            let fallback = match reason_of(&current.value) {
                Some(reason) => with_reason(
                    &current.value,
                    format!(
                        "{reason} Cannot continue {} through receiver {}.",
                        semantic_property_pointer(path),
                        semantic_property_pointer(&path[..index])
                    ),
                ),
                None => unknown(format!(
                    "Cannot resolve {} through {} receiver {}.",
                    semantic_property_pointer(path),
                    status_of(&current.value),
                    semantic_property_pointer(&path[..index])
                )),
            };
            return SlotRef { presence: SlotPresence::UnknownCoverage, value: Cow::Owned(fallback) };
        }
        // Array position inventories omit the intrinsic non-enumerable length slot.
        if matches!(current.value.as_ref(), SemanticValue::Array { .. }) && name == "length" {
            current = SlotRef {
                presence: SlotPresence::Present,
                value: Cow::Owned(unknown("Array length is present but its value is not retained.")),
            };
            continue;
        }
        current = match current.value {
            Cow::Borrowed(borrowed) => {
                let container = semantic_container(borrowed).expect("container checked");
                match container.slots.iter().find(|slot| &slot.name == name) {
                    Some(slot) => SlotRef { presence: slot.presence, value: Cow::Borrowed(&slot.value) },
                    None => absent_slot(&container, name),
                }
            }
            Cow::Owned(owned) => {
                let container = semantic_container(&owned).expect("container checked");
                match container.slots.iter().find(|slot| &slot.name == name) {
                    Some(slot) => SlotRef { presence: slot.presence, value: Cow::Owned(slot.value.clone()) },
                    None => absent_slot(&container, name),
                }
            }
        };
    }
    current
}

fn absent_slot<'v>(container: &SemanticContainer<'_>, name: &str) -> SlotRef<'v> {
    SlotRef {
        presence: if container.coverage == ContainerCoverage::Complete {
            SlotPresence::Absent
        } else {
            SlotPresence::UnknownCoverage
        },
        value: Cow::Owned(unknown(format!("Own property {name} was not observed."))),
    }
}
