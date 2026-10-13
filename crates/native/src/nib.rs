//! NIBArchive decoding and view-hierarchy projection (port of REA
//! `artifacts/apple/NibArchive.ts` and `NibViewHierarchy.ts`).

use std::collections::{HashMap, HashSet};

use base64::Engine;
use indexmap::IndexMap;
use serde_json::{json, Map, Value};

use crate::plistjs::{js_number, BudgetExceeded, DecodeBudget};

const MAGIC: &[u8] = b"NIBArchive";
const DEFAULT_DECODE_BUDGET_BYTES: f64 = 128.0 * 1024.0 * 1024.0;

#[derive(Debug, Clone, PartialEq)]
pub enum NibError {
    Budget(BudgetExceeded),
    /// A `TypeError` with the original message.
    Type(String),
}

impl From<BudgetExceeded> for NibError {
    fn from(value: BudgetExceeded) -> Self {
        NibError::Budget(value)
    }
}

fn type_error(message: impl Into<String>) -> NibError {
    NibError::Type(message.into())
}

pub struct NibObject {
    pub id: usize,
    pub class_name: String,
    pub values: IndexMap<String, Value>,
}

pub struct NibArchive {
    pub objects: Vec<NibObject>,
    pub classes: Vec<String>,
}

struct ObjectRecord {
    class_index: usize,
    value_start: usize,
    value_count: usize,
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, NibError> {
    ensure_range(offset, 4, bytes.len(), "header")?;
    Ok(u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]]))
}

fn checked_end(start: usize, length: usize, limit: usize, label: &str) -> Result<usize, NibError> {
    match start.checked_add(length) {
        Some(end) if end <= limit => Ok(end),
        _ => Err(type_error(format!("NIBArchive {label} exceeds its table"))),
    }
}

fn ensure_range(start: usize, length: usize, limit: usize, label: &str) -> Result<(), NibError> {
    checked_end(start, length, limit, label).map(|_| ())
}

fn read_count(bytes: &[u8], offset: usize, label: &str) -> Result<usize, NibError> {
    let count = read_u32(bytes, offset)? as usize;
    if count > bytes.len() {
        return Err(type_error(format!("NIBArchive {label} count exceeds the archive length")));
    }
    Ok(count)
}

fn read_offset(bytes: &[u8], offset: usize, file_length: usize, label: &str) -> Result<usize, NibError> {
    let value = read_u32(bytes, offset)? as usize;
    if value < 50 || value > file_length {
        return Err(type_error(format!("NIBArchive {label} table offset is invalid")));
    }
    Ok(value)
}

fn read_varint(bytes: &[u8], cursor: &mut usize, end: usize) -> Result<usize, NibError> {
    let mut value: f64 = 0.0;
    let mut shift = 0u32;
    for _ in 0..5 {
        ensure_range(*cursor, 1, end, "variable integer")?;
        let byte = bytes[*cursor];
        *cursor += 1;
        value += f64::from(byte & 0x7f) * 2f64.powi(shift as i32);
        if byte & 0x80 != 0 {
            if value > f64::from(0x7fff_ffffu32) {
                return Err(type_error("NIBArchive variable integer is out of range"));
            }
            return Ok(value as usize);
        }
        shift += 7;
    }
    Err(type_error("NIBArchive variable integer is too long"))
}

fn decode_utf8(bytes: &[u8], start: usize, end: usize, label: &str) -> Result<String, NibError> {
    String::from_utf8(bytes[start..end].to_vec()).map_err(|_| type_error(format!("NIBArchive {label} is not valid UTF-8")))
}

/// Decode Apple's length-prefixed NIBArchive representation without loading UI classes.
pub fn decode_nib_archive(bytes: &[u8], budget: Option<&mut DecodeBudget>) -> Result<NibArchive, NibError> {
    let mut default_budget = DecodeBudget::new(DEFAULT_DECODE_BUDGET_BYTES);
    let budget = match budget {
        Some(b) => b,
        None => &mut default_budget,
    };
    if bytes.len() < 50 || &bytes[..MAGIC.len()] != MAGIC {
        return Err(type_error("NIBArchive magic or header is invalid"));
    }
    let format_version = read_u32(bytes, 10)?;
    let _coder_version = read_u32(bytes, 14)?;
    if format_version != 1 {
        return Err(type_error(format!("Unsupported NIBArchive format version {format_version}")));
    }
    let object_count = read_count(bytes, 18, "object")?;
    let objects_offset = read_offset(bytes, 22, bytes.len(), "object")?;
    let key_count = read_count(bytes, 26, "key")?;
    let keys_offset = read_offset(bytes, 30, bytes.len(), "key")?;
    let value_count = read_count(bytes, 34, "value")?;
    let values_offset = read_offset(bytes, 38, bytes.len(), "value")?;
    let class_count = read_count(bytes, 42, "class")?;
    let classes_offset = read_offset(bytes, 46, bytes.len(), "class")?;
    // assertOrderedOffsets
    let mut previous = 50;
    for offset in [objects_offset, keys_offset, values_offset, classes_offset] {
        if offset < previous || offset > bytes.len() {
            return Err(type_error("NIBArchive table offsets are out of order"));
        }
        previous = offset;
    }
    let projected_field_count = preflight_projected_field_count(
        bytes,
        objects_offset,
        keys_offset,
        object_count,
        value_count,
        class_count,
        budget.remaining_bytes(),
    )?;
    budget.reserve(
        object_count as f64 * 96.0 + projected_field_count as f64 * 96.0,
        "NIBArchive object and projected field counts exceed the aggregate Interface Builder decode budget",
    )?;
    let object_records = parse_objects(bytes, objects_offset, keys_offset, object_count, value_count, class_count)?;
    let keys = parse_strings(bytes, keys_offset, values_offset, key_count, "key", budget)?;
    let classes = parse_classes(bytes, classes_offset, bytes.len(), class_count, budget)?;
    let needed = value_indexes(&object_records, value_count)?;
    let values = parse_values(bytes, values_offset, classes_offset, value_count, key_count, &needed, budget)?;
    for (_, value) in values.values() {
        if let Some(reference) = value.get("$nib_object_ref").and_then(Value::as_f64) {
            if reference >= object_count as f64 {
                return Err(type_error("NIBArchive object reference is outside the object table"));
            }
        }
    }
    let mut objects = Vec::new();
    for (id, record) in object_records.iter().enumerate() {
        let Some(class_name) = classes.get(record.class_index) else {
            continue;
        };
        let mut fields: IndexMap<String, Value> = IndexMap::new();
        for index in record.value_start..record.value_start + record.value_count {
            let Some((key_index, value)) = values.get(&index) else {
                continue;
            };
            if let Some(key) = keys.get(*key_index) {
                fields.insert(key.clone(), value.clone());
            }
        }
        objects.push(NibObject {
            id,
            class_name: class_name.clone(),
            values: fields,
        });
    }
    Ok(NibArchive { objects, classes })
}

fn parse_objects(
    bytes: &[u8],
    start: usize,
    end: usize,
    count: usize,
    value_count: usize,
    class_count: usize,
) -> Result<Vec<ObjectRecord>, NibError> {
    let mut cursor = start;
    let mut output = Vec::new();
    for index in 0..count {
        let class_index = read_varint(bytes, &mut cursor, end)?;
        let value_start = read_varint(bytes, &mut cursor, end)?;
        let count_for_object = read_varint(bytes, &mut cursor, end)?;
        if class_index >= class_count || value_start > value_count || count_for_object > value_count - value_start {
            return Err(type_error(format!("NIBArchive object {index} references an invalid table range")));
        }
        output.push(ObjectRecord {
            class_index,
            value_start,
            value_count: count_for_object,
        });
    }
    if cursor > end {
        return Err(type_error("NIBArchive object table overlaps the next table"));
    }
    Ok(output)
}

fn preflight_projected_field_count(
    bytes: &[u8],
    start: usize,
    end: usize,
    object_count: usize,
    value_count: usize,
    class_count: usize,
    max_bytes: f64,
) -> Result<usize, NibError> {
    let exceeded = |message: &str| {
        NibError::Budget(BudgetExceeded {
            reason: "aggregate_decode_budget_exhausted",
            message: message.to_string(),
        })
    };
    if object_count as f64 * 96.0 > max_bytes {
        return Err(exceeded("NIBArchive object count exceeds the aggregate Interface Builder decode budget"));
    }
    let mut cursor = start;
    let mut projected = 0usize;
    for index in 0..object_count {
        let class_index = read_varint(bytes, &mut cursor, end)?;
        let value_start = read_varint(bytes, &mut cursor, end)?;
        let field_count = read_varint(bytes, &mut cursor, end)?;
        if class_index >= class_count || value_start > value_count || field_count > value_count - value_start {
            return Err(type_error(format!("NIBArchive object {index} references an invalid table range")));
        }
        projected += field_count;
        if projected as f64 * 96.0 > max_bytes - object_count as f64 * 96.0 {
            return Err(exceeded(
                "NIBArchive projected field ranges exceed the aggregate Interface Builder decode budget",
            ));
        }
    }
    Ok(projected)
}

fn parse_strings(
    bytes: &[u8],
    start: usize,
    end: usize,
    count: usize,
    label: &str,
    budget: &mut DecodeBudget,
) -> Result<Vec<String>, NibError> {
    let mut cursor = start;
    let mut output = Vec::new();
    for index in 0..count {
        let length = read_varint(bytes, &mut cursor, end)?;
        let next = checked_end(cursor, length, end, &format!("{label} {index}"))?;
        budget.reserve(
            32.0 + length as f64 * 2.0,
            &format!("NIBArchive {label} strings exceed the aggregate Interface Builder decode budget"),
        )?;
        output.push(decode_utf8(bytes, cursor, next, &format!("{label} {index}"))?);
        cursor = next;
    }
    Ok(output)
}

fn parse_classes(
    bytes: &[u8],
    start: usize,
    end: usize,
    count: usize,
    budget: &mut DecodeBudget,
) -> Result<Vec<String>, NibError> {
    let mut cursor = start;
    let mut output = Vec::new();
    for index in 0..count {
        let length = read_varint(bytes, &mut cursor, end)?;
        let extra_count = read_varint(bytes, &mut cursor, end)?;
        if extra_count > 16 {
            return Err(type_error(format!("NIBArchive class {index} has too many extension values")));
        }
        ensure_range(cursor, extra_count * 4, end, &format!("class {index} extensions"))?;
        cursor += extra_count * 4;
        let next = checked_end(cursor, length, end, &format!("class {index}"))?;
        budget.reserve(
            32.0 + length as f64 * 2.0,
            "NIBArchive class names exceed the aggregate Interface Builder decode budget",
        )?;
        let name = decode_utf8(bytes, cursor, next, &format!("class {index}"))?;
        cursor = next;
        output.push(name.trim_end_matches('\0').to_string());
    }
    Ok(output)
}

fn value_indexes(objects: &[ObjectRecord], total: usize) -> Result<HashSet<usize>, NibError> {
    let mut indexes = HashSet::new();
    for object in objects {
        for index in object.value_start..object.value_start + object.value_count {
            indexes.insert(index);
        }
    }
    if indexes.len() > total {
        return Err(type_error("NIBArchive object value ranges exceed the value table"));
    }
    Ok(indexes)
}

fn parse_values(
    bytes: &[u8],
    start: usize,
    end: usize,
    count: usize,
    key_count: usize,
    needed: &HashSet<usize>,
    budget: &mut DecodeBudget,
) -> Result<HashMap<usize, (usize, Value)>, NibError> {
    let mut cursor = start;
    let mut output = HashMap::new();
    for index in 0..count {
        let key_index = read_varint(bytes, &mut cursor, end)?;
        if key_index >= key_count {
            return Err(type_error(format!("NIBArchive value {index} references an invalid key")));
        }
        ensure_range(cursor, 1, end, &format!("value {index} type"))?;
        let value_type = bytes[cursor];
        cursor += 1;
        if !needed.contains(&index) {
            skip_value(bytes, &mut cursor, end, value_type, index)?;
            continue;
        }
        budget.reserve(64.0, "NIBArchive decoded values exceed the aggregate Interface Builder decode budget")?;
        let value = read_value(bytes, &mut cursor, end, value_type, index, budget)?;
        output.insert(index, (key_index, value));
    }
    if cursor > end {
        return Err(type_error("NIBArchive value table overlaps the next table"));
    }
    Ok(output)
}

fn read_value(
    bytes: &[u8],
    cursor: &mut usize,
    end: usize,
    value_type: u8,
    index: usize,
    budget: &mut DecodeBudget,
) -> Result<Value, NibError> {
    let label = format!("value {index}");
    Ok(match value_type {
        0 => {
            ensure_range(*cursor, 1, end, &label)?;
            let value = bytes[*cursor] as i8;
            *cursor += 1;
            json!(value)
        }
        1 => {
            ensure_range(*cursor, 2, end, &label)?;
            let value = i16::from_le_bytes([bytes[*cursor], bytes[*cursor + 1]]);
            *cursor += 2;
            json!(value)
        }
        2 => {
            ensure_range(*cursor, 4, end, &label)?;
            let value = i32::from_le_bytes(bytes[*cursor..*cursor + 4].try_into().expect("4 bytes"));
            *cursor += 4;
            json!(value)
        }
        3 => {
            ensure_range(*cursor, 8, end, &label)?;
            let value = i64::from_le_bytes(bytes[*cursor..*cursor + 8].try_into().expect("8 bytes"));
            *cursor += 8;
            if (-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&value) {
                json!(value)
            } else {
                Value::String(value.to_string())
            }
        }
        4 => Value::Bool(true),
        5 => Value::Bool(false),
        6 => {
            ensure_range(*cursor, 4, end, &label)?;
            let value = f32::from_le_bytes(bytes[*cursor..*cursor + 4].try_into().expect("4 bytes"));
            *cursor += 4;
            if value.is_finite() {
                js_number(f64::from(value))
            } else {
                Value::Null
            }
        }
        7 => {
            ensure_range(*cursor, 8, end, &label)?;
            let value = f64::from_le_bytes(bytes[*cursor..*cursor + 8].try_into().expect("8 bytes"));
            *cursor += 8;
            if value.is_finite() {
                js_number(value)
            } else {
                Value::Null
            }
        }
        8 => {
            let length = read_varint(bytes, cursor, end)?;
            let next = checked_end(*cursor, length, end, &format!("value {index} data"))?;
            budget.reserve(
                32.0 + 4.0 * (length as f64 / 3.0).ceil(),
                &format!("NIBArchive data value {index} exceeds the aggregate Interface Builder decode budget"),
            )?;
            let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes[*cursor..next]);
            *cursor = next;
            json!({"$nib_data_base64": encoded})
        }
        9 => Value::Null,
        10 => {
            ensure_range(*cursor, 4, end, &format!("value {index} reference"))?;
            let object_index = u32::from_le_bytes(bytes[*cursor..*cursor + 4].try_into().expect("4 bytes"));
            *cursor += 4;
            json!({"$nib_object_ref": object_index})
        }
        other => return Err(type_error(format!("NIBArchive value {index} has unsupported type {other}"))),
    })
}

fn skip_value(bytes: &[u8], cursor: &mut usize, end: usize, value_type: u8, index: usize) -> Result<(), NibError> {
    let label = format!("value {index}");
    match value_type {
        0 => {
            ensure_range(*cursor, 1, end, &label)?;
            *cursor += 1;
        }
        1 => {
            ensure_range(*cursor, 2, end, &label)?;
            *cursor += 2;
        }
        2 | 10 | 6 => {
            ensure_range(*cursor, 4, end, &label)?;
            *cursor += 4;
        }
        3 | 7 => {
            ensure_range(*cursor, 8, end, &label)?;
            *cursor += 8;
        }
        4 | 5 | 9 => {}
        8 => {
            let length = read_varint(bytes, cursor, end)?;
            *cursor = checked_end(*cursor, length, end, &format!("value {index} data"))?;
        }
        other => return Err(type_error(format!("NIBArchive value {index} has unsupported type {other}"))),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// NibViewHierarchy.ts
// ---------------------------------------------------------------------------

/// A hierarchy node tree as nested `{ objectID, children }` JSON.
#[derive(Clone, Debug)]
pub struct HierarchyNode {
    pub object_id: String,
    pub children: Vec<HierarchyNode>,
}

impl HierarchyNode {
    pub fn to_value(&self) -> Value {
        json!({
            "objectID": self.object_id,
            "children": self.children.iter().map(HierarchyNode::to_value).collect::<Vec<_>>(),
        })
    }
}

fn reference(value: Option<&Value>) -> Option<usize> {
    let object = value?.as_object()?;
    let number = object.get("$nib_object_ref")?.as_f64()?;
    // Only non-negative integral references are valid object ids.
    if number >= 0.0 && number.fract() == 0.0 {
        Some(number as usize)
    } else {
        None
    }
}

fn invalid_reference(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(v) => reference(Some(v)).is_none(),
    }
}

struct Parents {
    parents: IndexMap<usize, usize>,
    involved: Vec<usize>,
    involved_set: HashSet<usize>,
    invalid: usize,
}

fn collect_nib_parents(objects: &[NibObject], retained: &HashSet<usize>) -> Parents {
    let mut out = Parents {
        parents: IndexMap::new(),
        involved: Vec::new(),
        involved_set: HashSet::new(),
        invalid: 0,
    };
    let involve = |out: &mut Parents, id: usize| {
        if out.involved_set.insert(id) {
            out.involved.push(id);
        }
    };
    for object in objects {
        if !retained.contains(&object.id) {
            continue;
        }
        let window_view = object.values.get("NSWindowView");
        let child = reference(window_view);
        let is_window_template = object.class_name.trim_end_matches('\0') == "NSWindowTemplate";
        if is_window_template && invalid_reference(window_view) {
            out.invalid += 1;
        }
        if is_window_template {
            if let Some(child) = child {
                out.parents.insert(child, object.id);
                involve(&mut out, object.id);
                involve(&mut out, child);
            }
        }
        let super_view = object.values.get("NSSuperview");
        let parent = reference(super_view);
        if invalid_reference(super_view) {
            out.invalid += 1;
        }
        let Some(parent) = parent else { continue };
        out.parents.insert(object.id, parent);
        involve(&mut out, object.id);
        if retained.contains(&parent) {
            involve(&mut out, parent);
        }
    }
    out
}

pub struct ViewHierarchy {
    pub hierarchy: Option<Vec<HierarchyNode>>,
    pub omitted: usize,
}

/// Project encoded view parents; archive owners are not inferred view parents.
pub fn project_nib_view_hierarchy(
    objects: &[NibObject],
    retained: &HashSet<usize>,
    reserve_node: &mut dyn FnMut() -> bool,
    max_nodes: usize,
) -> ViewHierarchy {
    let collected = collect_nib_parents(objects, retained);
    if collected.parents.is_empty() {
        return ViewHierarchy {
            hierarchy: None,
            omitted: collected.invalid,
        };
    }
    let mut children: IndexMap<usize, Vec<usize>> = IndexMap::new();
    for (child, parent) in &collected.parents {
        if !retained.contains(parent) || !retained.contains(child) {
            continue;
        }
        children.entry(*parent).or_default().push(*child);
    }
    // Build with an arena so pending entries can append to a parent's child list.
    struct Arena {
        object_id: Vec<String>,
        children: Vec<Vec<usize>>,
    }
    let mut arena = Arena {
        object_id: Vec::new(),
        children: Vec::new(),
    };
    let mut roots: Vec<usize> = Vec::new();
    #[derive(Clone, Copy)]
    enum Output {
        Roots,
        Node(usize),
    }
    struct Pending {
        id: usize,
        depth: usize,
        output: Output,
    }
    let mut pending: Vec<Pending> = Vec::new();
    for id in &collected.involved {
        if !collected.parents.contains_key(id) {
            pending.push(Pending {
                id: *id,
                depth: 0,
                output: Output::Roots,
            });
        }
    }
    let mut visited: HashSet<usize> = HashSet::new();
    while let Some(item) = pending.pop() {
        if visited.contains(&item.id) || item.depth > 128 || visited.len() >= max_nodes || !reserve_node() {
            continue;
        }
        visited.insert(item.id);
        let node_index = arena.object_id.len();
        arena.object_id.push(item.id.to_string());
        arena.children.push(Vec::new());
        match item.output {
            Output::Roots => roots.push(node_index),
            Output::Node(parent) => arena.children[parent].push(node_index),
        }
        if let Some(kids) = children.get(&item.id) {
            for child in kids.iter().rev() {
                pending.push(Pending {
                    id: *child,
                    depth: item.depth + 1,
                    output: Output::Node(node_index),
                });
            }
        }
    }
    fn build(arena: &Arena, index: usize) -> HierarchyNode {
        HierarchyNode {
            object_id: arena.object_id[index].clone(),
            children: arena.children[index].iter().map(|c| build(arena, *c)).collect(),
        }
    }
    ViewHierarchy {
        hierarchy: Some(roots.iter().map(|r| build(&arena, *r)).collect()),
        omitted: collected.involved.len() - visited.len() + collected.invalid,
    }
}

/// Add encoded parent links once; conflicting legacy parents remain unknown.
pub fn merge_nib_hierarchies(
    legacy: Vec<HierarchyNode>,
    recovered: &[HierarchyNode],
    reserve_node: &mut dyn FnMut() -> bool,
    max_nodes: usize,
) -> (Vec<HierarchyNode>, usize) {
    #[derive(Clone, Copy, PartialEq)]
    enum Owner {
        Root,
        Node(usize),
    }
    struct Arena {
        object_id: Vec<String>,
        children: Vec<Vec<usize>>,
    }
    let mut arena = Arena {
        object_id: Vec::new(),
        children: Vec::new(),
    };
    fn import(arena: &mut Arena, node: &HierarchyNode) -> usize {
        let index = arena.object_id.len();
        arena.object_id.push(node.object_id.clone());
        arena.children.push(Vec::new());
        let kids: Vec<usize> = node.children.iter().map(|child| import(arena, child)).collect();
        arena.children[index] = kids;
        index
    }
    let mut legacy_roots: Vec<usize> = legacy.iter().map(|node| import(&mut arena, node)).collect();
    let mut existing: HashMap<String, usize> = HashMap::new();
    let mut owners: HashMap<String, Owner> = HashMap::new();
    let mut parents: HashMap<String, String> = HashMap::new();
    struct Entry {
        node: usize,
        output: Owner,
        parent: Option<String>,
    }
    let mut pending: Vec<Entry> = legacy_roots
        .iter()
        .map(|node| Entry {
            node: *node,
            output: Owner::Root,
            parent: None,
        })
        .collect();
    while let Some(entry) = pending.pop() {
        let id = arena.object_id[entry.node].clone();
        if existing.contains_key(&id) {
            continue;
        }
        existing.insert(id.clone(), entry.node);
        owners.insert(id.clone(), entry.output);
        if let Some(parent) = &entry.parent {
            parents.insert(id.clone(), parent.clone());
        }
        for child in arena.children[entry.node].clone() {
            pending.push(Entry {
                node: child,
                output: Owner::Node(entry.node),
                parent: Some(id.clone()),
            });
        }
    }
    let mut omitted = 0usize;
    struct Addition<'a> {
        node: &'a HierarchyNode,
        output: Owner,
        parent: Option<String>,
    }
    let mut additions: Vec<Addition<'_>> = recovered
        .iter()
        .map(|node| Addition {
            node,
            output: Owner::Root,
            parent: None,
        })
        .collect();
    while let Some(entry) = additions.pop() {
        let id = entry.node.object_id.clone();
        let target: usize;
        if let Some(&found) = existing.get(&id) {
            target = found;
            if entry.parent.is_some() && owners.get(&id) != Some(&entry.output) {
                let owner = owners.get(&id).copied();
                let cycle = entry
                    .parent
                    .as_ref()
                    .map(|parent| would_cycle(&id, parent, &parents))
                    .unwrap_or(false);
                if owner != Some(Owner::Root) || cycle {
                    omitted += 1;
                } else {
                    if let Some(position) = legacy_roots.iter().position(|r| *r == target) {
                        legacy_roots.remove(position);
                    }
                    match entry.output {
                        Owner::Root => legacy_roots.push(target),
                        Owner::Node(parent_index) => arena.children[parent_index].push(target),
                    }
                    owners.insert(id.clone(), entry.output);
                    if let Some(parent) = &entry.parent {
                        parents.insert(id.clone(), parent.clone());
                    }
                }
            }
        } else {
            if existing.len() >= max_nodes || !reserve_node() {
                omitted += 1;
                continue;
            }
            target = arena.object_id.len();
            arena.object_id.push(id.clone());
            arena.children.push(Vec::new());
            existing.insert(id.clone(), target);
            match entry.output {
                Owner::Root => legacy_roots.push(target),
                Owner::Node(parent_index) => arena.children[parent_index].push(target),
            }
            owners.insert(id.clone(), entry.output);
            if let Some(parent) = &entry.parent {
                parents.insert(id.clone(), parent.clone());
            }
        }
        for node in entry.node.children.iter().rev() {
            additions.push(Addition {
                node,
                output: Owner::Node(target),
                parent: Some(id.clone()),
            });
        }
    }
    fn build(arena: &Arena, index: usize) -> HierarchyNode {
        HierarchyNode {
            object_id: arena.object_id[index].clone(),
            children: arena.children[index].iter().map(|c| build(arena, *c)).collect(),
        }
    }
    (legacy_roots.iter().map(|r| build(&arena, *r)).collect(), omitted)
}

fn would_cycle(child: &str, parent: &str, parents: &HashMap<String, String>) -> bool {
    let mut seen: HashSet<String> = HashSet::new();
    let mut current: Option<String> = Some(parent.to_string());
    while let Some(candidate) = current {
        if seen.contains(&candidate) {
            break;
        }
        if candidate == child {
            return true;
        }
        seen.insert(candidate.clone());
        current = parents.get(&candidate).cloned();
    }
    false
}

/// Shared helper for projecting NIB values: an object map into JSON.
pub fn values_to_map(values: &IndexMap<String, Value>) -> Map<String, Value> {
    let mut map = Map::new();
    for (key, value) in values {
        map.insert(key.clone(), value.clone());
    }
    map
}
