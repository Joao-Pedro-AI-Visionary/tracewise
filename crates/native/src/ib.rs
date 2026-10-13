//! `decode_interface_builder` (port of REA `domain/apple/interfaceBuilderGraph.ts`,
//! `interfaceBuilderKeyedArchive.ts` and `artifacts/apple/InterfaceBuilderAnalysis.ts`).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;

use base64::Engine;
use indexmap::IndexMap;
use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::dylib::open_nofollow;
use crate::error::{ArtifactReason, NativeError, NativeResult};
use crate::nib::{
    decode_nib_archive, merge_nib_hierarchies, project_nib_view_hierarchy, HierarchyNode, NibArchive, NibError,
    NibObject,
};
use crate::plistjs::{
    decode_xml_plist_text, estimate_property_list_decode_bytes, js_order_map, omitted_prototype_keys_limitation,
    parse_binary, parse_xml_property_list, project_plist_value, BudgetExceeded, DecodeBudget, ExpansionFailure,
};

const OPERATION: &str = "decode_interface_builder";
const MAX_AGGREGATE_INPUT_BYTES: f64 = 32.0 * 1024.0 * 1024.0;
const MAX_AGGREGATE_DECODE_BYTES: f64 = 256.0 * 1024.0 * 1024.0;
const MAX_REPORTED_OMITTED_ARCHIVES: usize = 64;

fn cached_regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("static regex"))
}

fn empty_map() -> &'static Map<String, Value> {
    static EMPTY: OnceLock<Map<String, Value>> = OnceLock::new();
    EMPTY.get_or_init(Map::new)
}

/// Coerce unknown values to a string-keyed record; non-objects become `{}`.
fn record(value: Option<&Value>) -> &Map<String, Value> {
    match value {
        Some(Value::Object(map)) => map,
        _ => empty_map(),
    }
}

/// First non-empty string among the candidates, otherwise None.
fn first_string(values: &[Option<&Value>]) -> Option<String> {
    for value in values.iter().flatten() {
        if let Value::String(text) = value {
            if !text.is_empty() {
                return Some(text.clone());
            }
        }
    }
    None
}

fn js_string_of_number(value: f64) -> String {
    match crate::plistjs::js_number(value) {
        Value::Number(n) => n.to_string(),
        _ => "NaN".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct InterfaceBuilderLimits {
    pub max_documents: usize,
    pub max_objects: usize,
    pub max_connections: usize,
}

impl Default for InterfaceBuilderLimits {
    fn default() -> Self {
        Self {
            max_documents: 64,
            max_objects: 20_000,
            max_connections: 40_000,
        }
    }
}

// ---------------------------------------------------------------------------
// interfaceBuilderKeyedArchive.ts
// ---------------------------------------------------------------------------

pub struct IbObject {
    pub id: String,
    pub kind: &'static str,
    pub class_name: Option<String>,
    pub name: String,
    pub attributes: Map<String, Value>,
}

pub struct IbConnection {
    pub id: String,
    pub kind: &'static str,
    pub source_id: String,
    pub destination_id: Option<String>,
    pub label: Option<String>,
    pub attributes: Map<String, Value>,
}

pub struct IbRecords {
    pub objects: Vec<IbObject>,
    pub connections: Vec<IbConnection>,
    pub hierarchy: Vec<Value>,
    pub classes: Map<String, Value>,
    pub object_count: usize,
    pub omitted_objects: usize,
    pub omitted_connections: usize,
    pub omitted_hierarchy_references: usize,
}

fn classify_object(class_name: Option<&str>) -> &'static str {
    let value = class_name.unwrap_or("").to_lowercase();
    if value.contains("constraint") {
        return "constraint";
    }
    if value.contains("layoutguide") {
        return "layout_guide";
    }
    if value.contains("placeholder") || value.contains("firstresponder") || value == "uiproxyobject" {
        return "placeholder";
    }
    if value.contains("image") || value.contains("color") || value.contains("font") {
        return "resource";
    }
    if value.contains("external") {
        return "external_object";
    }
    if value.contains("viewcontroller") || value.contains("windowcontroller") {
        return "view_controller";
    }
    if value.contains("button")
        || value.contains("control")
        || value.contains("textfield")
        || value.contains("slider")
        || value.contains("menuitem")
    {
        return "control";
    }
    if value.contains("view") || value.contains("window") || value.contains("cell") {
        return "view";
    }
    "other"
}

fn classify_connection(kind: &str) -> &'static str {
    let value = kind.to_lowercase();
    if value.contains("outlet") {
        "outlet"
    } else if value.contains("action") {
        "action"
    } else if value.contains("segue") {
        "segue"
    } else {
        "other"
    }
}

fn archive_uid(value: Option<&Value>) -> Option<f64> {
    let object = match value {
        Some(Value::Object(map)) => map,
        _ => return None,
    };
    if object.len() != 1 {
        return None;
    }
    let marker = if object.contains_key("UID") {
        object.get("UID")
    } else {
        object.get("CF$UID")
    };
    let number = marker.and_then(Value::as_f64)?;
    if number.is_finite() && number.fract() == 0.0 {
        Some(number)
    } else {
        None
    }
}

struct KeyedTable<'a> {
    table: &'a [Value],
}

fn hierarchy_key(key: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    cached_regex(&RE, r"(?i)(?:subviews|contentview|childviewcontrollers|children|views)$").is_match(key)
}

impl KeyedTable<'_> {
    fn at(&self, uid: f64) -> Option<&Value> {
        if uid >= 0.0 && uid.fract() == 0.0 && (uid as usize) < self.table.len() {
            self.table.get(uid as usize)
        } else {
            None
        }
    }

    fn class_name_of(&self, value: &Value) -> Option<String> {
        let class_reference = record(Some(value)).get("$class");
        let uid = archive_uid(class_reference);
        let descriptor = match uid {
            None => class_reference,
            Some(u) => self.at(u),
        };
        first_string(&[record(descriptor).get("$classname")])
    }

    fn archived_string(&self, target: &Value) -> Option<String> {
        if let Value::String(text) = target {
            return Some(text.clone());
        }
        let text = record(Some(target)).get("NS.string")?;
        let Value::String(text) = text else { return None };
        static RE: OnceLock<Regex> = OnceLock::new();
        if cached_regex(&RE, r"^NS(?:Mutable)?String$").is_match(self.class_name_of(target).as_deref().unwrap_or("")) {
            Some(text.clone())
        } else {
            None
        }
    }

    fn text(&self, value: Option<&Value>) -> Option<String> {
        let uid = archive_uid(value);
        match uid {
            None => first_string(&[value]),
            Some(u) => {
                let target = self.at(u)?;
                let archived = self.archived_string(target)?;
                first_string(&[Some(&Value::String(archived))])
            }
        }
    }

    fn authored_id(&self, item: &Map<String, Value>) -> Option<String> {
        first_string(&[
            self.text(item.get("objectID")).map(Value::String).as_ref(),
            self.text(item.get("object-id")).map(Value::String).as_ref(),
        ])
    }

    fn reference(&self, uid: f64) -> Value {
        let target = if uid == 0.0 { None } else { self.at(uid) };
        let Some(target) = target else { return Value::Null };
        if target.is_null() {
            return Value::Null;
        }
        if !target.is_object() && !target.is_array() {
            return target.clone();
        }
        if let Some(string) = self.archived_string(target) {
            return Value::String(string);
        }
        let object_id = self.authored_id(record(Some(target)));
        let mut stub = Map::new();
        stub.insert("archiveUID".into(), crate::plistjs::js_number(uid));
        if let Some(object_id) = object_id {
            stub.insert("objectID".into(), Value::String(object_id));
        }
        stub.insert(
            "className".into(),
            self.class_name_of(target).map(Value::String).unwrap_or(Value::Null),
        );
        Value::Object(stub)
    }

    fn resolve(&self, value: &Value) -> Value {
        if let Some(uid) = archive_uid(Some(value)) {
            return self.reference(uid);
        }
        match value {
            Value::Array(items) => Value::Array(items.iter().map(|item| self.resolve(item)).collect()),
            Value::Object(map) => {
                let mut output = Map::new();
                for (key, child) in js_order_map(map) {
                    if key == "$class" {
                        output.insert(
                            "className".into(),
                            self.class_name_of(value).map(Value::String).unwrap_or(Value::Null),
                        );
                    } else {
                        output.insert(key.clone(), self.resolve(child));
                    }
                }
                Value::Object(output)
            }
            other => other.clone(),
        }
    }

    fn archived_array_class(&self, class_reference: Option<&Value>) -> bool {
        let uid = archive_uid(class_reference);
        let descriptor = record(match uid {
            None => class_reference,
            Some(u) => self.at(u),
        });
        match descriptor.get("$classes") {
            Some(Value::Array(names)) => names
                .iter()
                .filter_map(Value::as_str)
                .any(|name| name == "NSArray" || name == "NSMutableArray"),
            _ => false,
        }
    }

    fn hierarchy(&self, start: Option<&Value>) -> (Vec<Value>, usize) {
        let Some(start) = start else {
            return (Vec::new(), 0);
        };
        let mut arena = HierArena::default();
        let mut omitted_references = 0usize;
        let mut visited: HashSet<i64> = HashSet::new();
        let mut pending: Vec<(Value, Slot)> = vec![(start.clone(), Slot::Root)];
        while let Some((value, output)) = pending.pop() {
            if let Some(uid) = archive_uid(Some(&value)) {
                if uid == 0.0 {
                    continue;
                }
                let Some(target) = self.at(uid) else {
                    omitted_references += 1;
                    continue;
                };
                let key = uid as i64;
                if visited.contains(&key) {
                    continue;
                }
                visited.insert(key);
                if let Value::Array(items) = target {
                    for item in items.iter().rev() {
                        pending.push((item.clone(), output));
                    }
                    continue;
                }
                let Value::Object(item) = target else { continue };
                if self.archived_array_class(item.get("$class")) {
                    if let Some(Value::Array(members)) = item.get("NS.objects") {
                        for member in members.iter().rev() {
                            pending.push((member.clone(), output));
                        }
                    }
                    continue;
                }
                self.append_node(item, Some(key), output, &mut arena, &mut pending);
                continue;
            }
            match &value {
                Value::Array(items) => {
                    for item in items.iter().rev() {
                        pending.push((item.clone(), output));
                    }
                }
                Value::Object(item) => {
                    self.append_node(item, None, output, &mut arena, &mut pending);
                }
                _ => {}
            }
        }
        fn build(arena: &HierArena, index: usize) -> Value {
            json!({
                "objectID": arena.object_id[index],
                "children": arena.children[index].iter().map(|c| build(arena, *c)).collect::<Vec<_>>(),
            })
        }
        let items = arena.roots.iter().map(|r| build(&arena, *r)).collect();
        (items, omitted_references)
    }

    fn append_node(
        &self,
        item: &Map<String, Value>,
        uid: Option<i64>,
        output: Slot,
        arena: &mut HierArena,
        pending: &mut Vec<(Value, Slot)>,
    ) {
        let text_id = self.text(item.get("id")).map(Value::String);
        let authored = self.authored_id(item).map(Value::String);
        let uid_text = uid.map(|u| Value::String(u.to_string()));
        let object_id = first_string(&[authored.as_ref(), text_id.as_ref(), uid_text.as_ref()]);
        let entries: Vec<(&String, &Value)> = js_order_map(item);
        match object_id {
            None => {
                for (key, child) in entries.iter().rev() {
                    if hierarchy_key(key) {
                        pending.push(((*child).clone(), output));
                    }
                }
            }
            Some(object_id) => {
                let index = arena.push_node(object_id, output);
                for (key, child) in entries.iter().rev() {
                    if hierarchy_key(key) {
                        pending.push(((*child).clone(), Slot::Node(index)));
                    }
                }
            }
        }
    }
}

/// Output slot used by the keyed-archive hierarchy walk.
#[derive(Clone, Copy)]
enum Slot {
    Root,
    Node(usize),
}

#[derive(Default)]
struct HierArena {
    object_id: Vec<String>,
    children: Vec<Vec<usize>>,
    roots: Vec<usize>,
}

impl HierArena {
    fn push_node(&mut self, object_id: String, output: Slot) -> usize {
        let index = self.object_id.len();
        self.object_id.push(object_id);
        self.children.push(Vec::new());
        match output {
            Slot::Root => self.roots.push(index),
            Slot::Node(parent) => self.children[parent].push(index),
        }
        index
    }
}

fn first_object_reference(values: &[Option<Value>]) -> Option<String> {
    for value in values {
        let direct = first_string(&[value.as_ref()]);
        if direct.is_some() {
            return direct;
        }
        let item = record(value.as_ref());
        let archive_uid_text = item
            .get("archiveUID")
            .and_then(Value::as_f64)
            .map(|n| Value::String(js_string_of_number(n)));
        let object_id = first_string(&[
            item.get("objectID"),
            item.get("object-id"),
            item.get("id"),
            item.get("identifier"),
            archive_uid_text.as_ref(),
        ]);
        if object_id.is_some() {
            return object_id;
        }
    }
    None
}

fn archived_object_reference(value: Option<&Value>) -> Option<Value> {
    let item = record(value);
    let uid = item.get("archiveUID").and_then(Value::as_f64)?;
    let id = first_string(&[item.get("objectID"), item.get("object-id")]).unwrap_or_else(|| js_string_of_number(uid));
    Some(Value::String(id))
}

fn json_safe_record(map: &Map<String, Value>) -> Map<String, Value> {
    map.clone()
}

fn parse_keyed_archive(root: &Map<String, Value>) -> Option<IbRecords> {
    if root.get("$archiver") != Some(&Value::String("NSKeyedArchiver".to_string())) {
        return None;
    }
    let Some(Value::Array(table)) = root.get("$objects") else {
        return None;
    };
    let keyed = KeyedTable { table };
    let mut objects: Vec<IbObject> = Vec::new();
    let mut connections: Vec<IbConnection> = Vec::new();
    let mut object_count = 0usize;
    let mut omitted_connections = 0usize;
    static CONNECTION_RE: OnceLock<Regex> = OnceLock::new();
    static CONTROL_RE: OnceLock<Regex> = OnceLock::new();
    let connection_re = cached_regex(&CONNECTION_RE, r"(?i)(?:Outlet|Connection|Segue|ActionConnection|ControlConnector)");
    let control_re = cached_regex(&CONTROL_RE, r"(?i)ControlConnector");
    for (index, raw) in table.iter().enumerate() {
        if index == 0 {
            continue;
        }
        let resolved_value = keyed.resolve(raw);
        let resolved = record(Some(&resolved_value));
        let Some(class_name) = first_string(&[resolved.get("className")]) else {
            continue;
        };
        object_count += 1;
        let mut fields: Map<String, Value> = Map::new();
        for (key, value) in js_order_map(resolved) {
            if key != "className" {
                fields.insert(key.clone(), value.clone());
            }
        }
        let authored_id = first_string(&[fields.get("objectID"), fields.get("object-id")]);
        let object_id = authored_id.unwrap_or_else(|| match fields.get("archiveUID").and_then(Value::as_f64) {
            Some(uid) => js_string_of_number(uid),
            None => index.to_string(),
        });
        let kind = classify_object(Some(&class_name));
        if objects.len() < 20_000 {
            let name = first_string(&[
                fields.get("label"),
                fields.get("title"),
                fields.get("identifier"),
                fields.get("accessibilityLabel"),
                Some(&Value::String(class_name.clone())),
            ])
            .unwrap_or_else(|| format!("object {index}"));
            objects.push(IbObject {
                id: object_id.clone(),
                kind,
                class_name: Some(class_name.clone()),
                name,
                attributes: json_safe_record(&fields),
            });
        }
        if connection_re.is_match(&class_name) {
            let control_action = control_re.is_match(&class_name);
            let source = first_object_reference(&[
                if control_action { fields.get("destination").cloned() } else { fields.get("source").cloned() },
                archived_object_reference(fields.get("NSSource")),
                if control_action { fields.get("to").cloned() } else { fields.get("from").cloned() },
                if control_action { fields.get("target").cloned() } else { fields.get("owner").cloned() },
            ]);
            let Some(source) = source else { continue };
            let kind = if control_action { "action" } else { classify_connection(&class_name) };
            let destination = first_object_reference(&[
                if control_action { fields.get("source").cloned() } else { fields.get("destination").cloned() },
                archived_object_reference(fields.get("NSDestination")),
                if control_action { fields.get("from").cloned() } else { fields.get("to").cloned() },
                if control_action { fields.get("owner").cloned() } else { fields.get("target").cloned() },
            ]);
            let label = first_string(&[
                fields.get("label"),
                fields.get("NSLabel"),
                fields.get("selector"),
                fields.get("identifier"),
                fields.get("action"),
            ]);
            let parsed = IbConnection {
                id: format!("archive:{object_id}"),
                kind,
                source_id: source,
                destination_id: destination,
                label,
                attributes: json_safe_record(&fields),
            };
            if connections.len() < 40_000 {
                connections.push(parsed);
            } else {
                omitted_connections += 1;
            }
        }
    }
    let top = record(root.get("$top"));
    let start = match top.get("root") {
        Some(Value::Null) | None => top.get("UITopLevelObjectsKey"),
        other => other,
    };
    let (hierarchy, omitted_references) = keyed.hierarchy(start);
    let mut classes = Map::new();
    for raw in table {
        let item = record(Some(raw));
        if let Some(name) = first_string(&[item.get("$classname")]) {
            let superclasses = match item.get("$classes") {
                Some(Value::Array(items)) => Value::Array(items.clone()),
                _ => json!([]),
            };
            classes.insert(name, json!({ "superclasses": superclasses }));
        }
    }
    Some(IbRecords {
        omitted_objects: object_count.saturating_sub(20_000),
        objects,
        connections,
        hierarchy,
        classes,
        object_count,
        omitted_connections,
        omitted_hierarchy_references: omitted_references,
    })
}

/// Parse ibtool dictionaries or compiled keyed archives into typed records.
pub fn parse_interface_builder_records(value: &Value) -> IbRecords {
    let root = record(Some(value));
    if let Some(keyed) = parse_keyed_archive(root) {
        return keyed;
    }
    let objects_raw = record(root.get("com.apple.ibtool.document.objects"));
    let connections_raw = record(root.get("com.apple.ibtool.document.connections"));
    let hierarchy_raw = root.get("com.apple.ibtool.document.hierarchy");
    let classes_raw = record(root.get("com.apple.ibtool.document.classes"));
    let mut objects: Vec<IbObject> = Vec::new();
    let mut connections: Vec<IbConnection> = Vec::new();
    let mut omitted_connections = 0usize;
    let object_entries = js_order_map(objects_raw);
    for (id, raw) in object_entries.iter().take(20_000) {
        let attributes = record(Some(raw));
        let class_name = first_string(&[attributes.get("customClass"), attributes.get("class"), attributes.get("isa")]);
        let class_value = class_name.clone().map(Value::String);
        let label = first_string(&[
            attributes.get("label"),
            attributes.get("title"),
            attributes.get("name"),
            class_value.as_ref(),
        ]);
        let mut carried: HashSet<&str> = HashSet::new();
        if class_name.is_some() && attributes.get("customClass") == class_value.as_ref() {
            carried.insert("customClass");
        } else if class_name.is_none() && attributes.get("customClass").is_none() {
            // `undefined === null` is false: nothing is carried.
        }
        if label.is_some() && attributes.get("label") == label.clone().map(Value::String).as_ref() {
            carried.insert("label");
        }
        if attributes.get("objectID") == Some(&Value::String((*id).clone())) {
            carried.insert("objectID");
        }
        let mut kept = Map::new();
        for (key, value) in js_order_map(attributes) {
            if !carried.contains(key.as_str()) {
                kept.insert(key.clone(), value.clone());
            }
        }
        objects.push(IbObject {
            id: (*id).clone(),
            kind: classify_object(class_name.as_deref()),
            class_name: class_name.clone(),
            name: label.unwrap_or_else(|| (*id).clone()),
            attributes: json_safe_record(&kept),
        });
    }
    for (source_id, raw_connections) in js_order_map(connections_raw) {
        let Value::Array(raw_connections) = raw_connections else {
            continue;
        };
        for (index, raw) in raw_connections.iter().enumerate() {
            if connections.len() >= 40_000 {
                omitted_connections += raw_connections.len() - index;
                break;
            }
            let item = record(Some(raw));
            let kind = first_string(&[item.get("type"), item.get("connectionType")]).unwrap_or_else(|| "unknown".to_string());
            let destination = first_string(&[item.get("destination-id"), item.get("destinationId")]);
            let label = first_string(&[item.get("label"), item.get("selector"), item.get("identifier")]);
            connections.push(IbConnection {
                id: format!("{source_id}:connection:{index}"),
                kind: classify_connection(&kind),
                source_id: source_id.clone(),
                destination_id: destination,
                label,
                attributes: json_safe_record(item),
            });
        }
    }
    let hierarchy = match hierarchy_raw {
        Some(Value::Array(items)) => items.iter().take(20_000).cloned().collect(),
        _ => Vec::new(),
    };
    IbRecords {
        omitted_objects: object_entries.len().saturating_sub(20_000),
        object_count: object_entries.len(),
        objects,
        connections,
        hierarchy,
        classes: classes_raw.clone(),
        omitted_connections,
        omitted_hierarchy_references: 0,
    }
}

// ---------------------------------------------------------------------------
// interfaceBuilderGraph.ts
// ---------------------------------------------------------------------------

pub struct IbDocumentInput {
    pub relative_path: String,
    pub archive_sha256: String,
    pub document_kind: &'static str,
    pub raw: Value,
}

struct GraphBuilder {
    limits: InterfaceBuilderLimits,
    nodes: IndexMap<String, Value>,
    edges: Vec<Value>,
    truncated: bool,
    omitted_connections: usize,
    omitted_graph_nodes: usize,
}

struct DocContext<'a> {
    relative_path: &'a str,
    archive_sha256: &'a str,
    prefix: String,
    connection_edge_count: usize,
    hierarchy_edge_count: usize,
    document_omitted_connections: usize,
    document_omitted_hierarchy_edges: usize,
}

impl DocContext<'_> {
    fn graph_id(&self, kind: &str, parts: &[Value]) -> String {
        format!(
            "{}{}:{}",
            self.prefix,
            kind,
            serde_json::to_string(&Value::Array(parts.to_vec())).unwrap_or_default()
        )
    }

    fn evidence_for(&self, description: &str) -> Value {
        json!([{
            "kind": "interface_builder_resource",
            "description": description,
            "location": {"address": null, "file_offset": null},
            "artifact_path": self.relative_path,
            "artifact_sha256": self.archive_sha256,
        }])
    }
}

impl GraphBuilder {
    fn add_node(&mut self, node: Value) -> bool {
        let id = node["id"].as_str().unwrap_or("").to_string();
        if self.nodes.contains_key(&id) {
            return true;
        }
        if self.nodes.len() >= self.limits.max_objects {
            self.truncated = true;
            self.omitted_graph_nodes += 1;
            return false;
        }
        self.nodes.insert(id, node);
        true
    }

    fn add_edge(&mut self, context: &mut DocContext<'_>, edge: Value, is_hierarchy: bool) {
        let over = if is_hierarchy {
            context.hierarchy_edge_count >= self.limits.max_objects
        } else {
            context.connection_edge_count >= self.limits.max_connections * 3
        };
        if over {
            self.truncated = true;
            if is_hierarchy {
                context.document_omitted_hierarchy_edges += 1;
            } else {
                self.omitted_connections += 1;
                context.document_omitted_connections += 1;
            }
            return;
        }
        self.edges.push(edge);
        if is_hierarchy {
            context.hierarchy_edge_count += 1;
        } else {
            context.connection_edge_count += 1;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn connect(
        &mut self,
        context: &mut DocContext<'_>,
        id: String,
        from: &str,
        to: Option<&str>,
        relation: &str,
        description: &str,
        reason: Option<&str>,
    ) {
        if !self.nodes.contains_key(from) {
            self.truncated = true;
            if relation == "contains" && id.contains(":hierarchy:") {
                context.document_omitted_hierarchy_edges += 1;
            } else {
                self.omitted_connections += 1;
                context.document_omitted_connections += 1;
            }
            return;
        }
        let evidence = context.evidence_for(description);
        let unresolved_endpoint = matches!(to, Some(target) if !self.nodes.contains_key(target));
        if unresolved_endpoint {
            self.truncated = true;
        }
        let edge_to = if unresolved_endpoint { None } else { to };
        let edge_reason = if unresolved_endpoint {
            "endpoint_omitted_by_object_limit"
        } else {
            reason.unwrap_or("destination_unresolved")
        };
        let is_hierarchy = relation == "contains" && id.contains(":hierarchy:");
        let edge = match edge_to {
            None => json!({
                "id": id,
                "from": from,
                "to": null,
                "relation": relation,
                "resolution": "unresolved",
                "reason": edge_reason,
                "evidence": evidence,
                "limitations": [],
            }),
            Some(target) => json!({
                "id": id,
                "from": from,
                "to": target,
                "relation": relation,
                "resolution": "observed",
                "evidence": evidence,
                "limitations": [],
            }),
        };
        self.add_edge(context, edge, is_hierarchy);
    }
}

/// Build the graph returned by the static Interface Builder archive decoder.
pub fn build_interface_builder_analysis(
    target_sha256: &str,
    tool_version: &str,
    documents: &[IbDocumentInput],
    limits: InterfaceBuilderLimits,
) -> Value {
    let mut builder = GraphBuilder {
        limits,
        nodes: IndexMap::new(),
        edges: Vec::new(),
        truncated: false,
        omitted_connections: 0,
        omitted_graph_nodes: 0,
    };
    let mut coverage: Vec<Value> = Vec::new();
    let mut summaries: Vec<Value> = Vec::new();
    let mut omitted_objects = 0usize;
    let mut omitted_hierarchy_references = 0usize;
    for document in documents.iter().take(limits.max_documents) {
        let parsed = parse_interface_builder_records(&document.raw);
        let mut context = DocContext {
            relative_path: &document.relative_path,
            archive_sha256: &document.archive_sha256,
            prefix: format!(
                "ib:{}:",
                serde_json::to_string(&document.relative_path).unwrap_or_default()
            ),
            connection_edge_count: 0,
            hierarchy_edge_count: 0,
            document_omitted_connections: 0,
            document_omitted_hierarchy_edges: 0,
        };
        let root_id = format!("{}root", context.prefix);
        let object_ids: HashSet<&str> = parsed.objects.iter().map(|o| o.id.as_str()).collect();
        builder.add_node(json!({
            "id": root_id,
            "kind": if document.document_kind == "nib" { "scene" } else { "storyboard" },
            "name": document.relative_path,
            "location": null,
            "attributes": {"document_kind": document.document_kind},
            "evidence": context.evidence_for("compiled document"),
        }));
        let mut document_object_count = 0usize;
        for object in parsed.objects.iter().take(limits.max_objects) {
            let id = context.graph_id("object", &[json!(object.id)]);
            let kind = if object.kind == "other" { "unknown" } else { object.kind };
            let mut attributes = object.attributes.clone();
            attributes.insert("interface_builder_object_id".into(), json!(object.id));
            attributes.insert("class_name".into(), json!(object.class_name));
            let added = builder.add_node(json!({
                "id": id,
                "kind": kind,
                "name": object.name,
                "location": null,
                "attributes": attributes,
                "evidence": context.evidence_for(&format!("object {}", object.id)),
            }));
            if !added {
                break;
            }
            document_object_count += 1;
        }
        let object_node_id = |context: &DocContext<'_>, object_id: &str| context.graph_id("object", &[json!(object_id)]);
        let mut hierarchy_count = 0usize;
        let mut hierarchy_truncated = false;
        for hierarchy in &parsed.hierarchy {
            let mut pending: Vec<(Value, String)> = vec![(hierarchy.clone(), root_id.clone())];
            while let Some((value, parent_id)) = pending.pop() {
                // The limit check precedes the pop in the original; both orders are equivalent
                // because the check depends only on hierarchy_count.
                if hierarchy_count >= limits.max_objects {
                    builder.truncated = true;
                    hierarchy_truncated = true;
                    break;
                }
                if let Value::Array(items) = &value {
                    for item in items.iter().rev() {
                        pending.push((item.clone(), parent_id.clone()));
                    }
                    continue;
                }
                let Value::Object(item) = &value else { continue };
                let archive_uid_text = item
                    .get("archiveUID")
                    .and_then(Value::as_f64)
                    .map(|n| Value::String(js_string_of_number(n)));
                let object_id = first_string(&[
                    item.get("objectID"),
                    item.get("object-id"),
                    item.get("id"),
                    archive_uid_text.as_ref(),
                ]);
                let mut next_parent = parent_id.clone();
                if let Some(object_id) = object_id {
                    let known = object_ids.contains(object_id.as_str());
                    let child_id = if known {
                        object_node_id(&context, &object_id)
                    } else {
                        context.graph_id("unknown", &[json!(object_id)])
                    };
                    if !known {
                        let added = builder.add_node(json!({
                            "id": child_id,
                            "kind": "unknown",
                            "name": first_string(&[item.get("label"), item.get("name")]).unwrap_or_else(|| object_id.clone()),
                            "location": null,
                            "attributes": {"interface_builder_object_id": object_id},
                            "evidence": context.evidence_for(&format!("hierarchy item {object_id}")),
                        }));
                        if !added {
                            hierarchy_truncated = true;
                        }
                    }
                    let edge_id = context.graph_id("hierarchy", &[json!(parent_id), json!(child_id)]);
                    builder.connect(
                        &mut context,
                        edge_id,
                        &parent_id,
                        Some(&child_id),
                        "contains",
                        &format!("hierarchy {object_id}"),
                        None,
                    );
                    next_parent = child_id;
                    hierarchy_count += 1;
                }
                pending.push((item.get("children").cloned().unwrap_or(Value::Null), next_parent));
            }
        }
        for (index, item) in parsed.connections.iter().take(limits.max_connections).enumerate() {
            let source_id = object_node_id(&context, &item.source_id);
            if !builder.nodes.contains_key(&source_id) {
                builder.add_node(json!({
                    "id": source_id,
                    "kind": "unknown",
                    "name": item.source_id,
                    "location": null,
                    "attributes": {"interface_builder_object_id": item.source_id},
                    "evidence": context.evidence_for(&format!("connection source {}", item.source_id)),
                }));
            }
            let destination_id = item.destination_id.as_ref().map(|d| object_node_id(&context, d));
            let label_text = item.label.clone().unwrap_or_else(|| item.id.clone());
            let destination_missing = destination_id
                .as_ref()
                .map(|d| !builder.nodes.contains_key(d))
                .unwrap_or(true);
            let destination_text = item.destination_id.clone();
            match item.kind {
                "action" => {
                    let action_id = context.graph_id("action", &[json!(item.id)]);
                    let selector_id = item
                        .label
                        .as_ref()
                        .map(|label| context.graph_id("selector", &[json!(item.destination_id), json!(label)]));
                    let mut attributes = Map::new();
                    attributes.insert("selector".into(), json!(item.label));
                    attributes.insert("destination_id".into(), json!(item.destination_id));
                    for (key, value) in &item.attributes {
                        attributes.insert(key.clone(), value.clone());
                    }
                    builder.add_node(json!({
                        "id": action_id,
                        "kind": "action",
                        "name": item.label.clone().unwrap_or_else(|| "unlabeled action".to_string()),
                        "location": null,
                        "attributes": attributes,
                        "evidence": context.evidence_for(&format!("action {}", item.id)),
                    }));
                    let edge = context.graph_id("action-edge", &[json!(item.id), json!("source")]);
                    builder.connect(
                        &mut context,
                        edge,
                        &source_id,
                        Some(&action_id),
                        "target_action",
                        &format!("action source {}", item.source_id),
                        None,
                    );
                    if let Some(selector_id) = &selector_id {
                        builder.add_node(json!({
                            "id": selector_id,
                            "kind": "objc_selector",
                            "name": item.label.clone().unwrap_or_else(|| "unknown selector".to_string()),
                            "location": null,
                            "attributes": {"destination_id": item.destination_id},
                            "evidence": context.evidence_for(&format!("selector {}", item.label.clone().unwrap_or_else(|| "null".to_string()))),
                        }));
                        let edge = context.graph_id("action-edge", &[json!(item.id), json!("selector")]);
                        builder.connect(
                            &mut context,
                            edge,
                            &action_id,
                            Some(selector_id),
                            "target_action",
                            &format!("selector {}", item.label.clone().unwrap_or_default()),
                            None,
                        );
                    }
                    let destination_edge = context.graph_id("action-edge", &[json!(item.id), json!("destination")]);
                    let destination_label = destination_text.clone().unwrap_or_else(|| "missing".to_string());
                    if destination_missing {
                        builder.connect(
                            &mut context,
                            destination_edge,
                            &action_id,
                            None,
                            "target_action",
                            &format!("action destination {destination_label}"),
                            Some("destination_object_missing_or_external"),
                        );
                    } else {
                        builder.connect(
                            &mut context,
                            destination_edge,
                            &action_id,
                            destination_id.as_deref(),
                            "target_action",
                            &format!("action destination {}", destination_text.clone().unwrap_or_default()),
                            None,
                        );
                    }
                }
                "outlet" => {
                    let outlet_id = context.graph_id("outlet", &[json!(item.id)]);
                    builder.add_node(json!({
                        "id": outlet_id,
                        "kind": "outlet",
                        "name": label_text,
                        "location": null,
                        "attributes": item.attributes,
                        "evidence": context.evidence_for(&format!("outlet {}", item.id)),
                    }));
                    let edge = context.graph_id("outlet-edge", &[json!(item.id), json!("source")]);
                    builder.connect(
                        &mut context,
                        edge,
                        &source_id,
                        Some(&outlet_id),
                        "contains",
                        &format!("outlet source {}", item.source_id),
                        None,
                    );
                    let destination_edge = context.graph_id("outlet-edge", &[json!(item.id), json!("destination")]);
                    if destination_missing {
                        builder.connect(
                            &mut context,
                            destination_edge,
                            &outlet_id,
                            None,
                            "outlet_to",
                            &format!("outlet {label_text}"),
                            Some("destination_object_missing_or_external"),
                        );
                    } else {
                        builder.connect(
                            &mut context,
                            destination_edge,
                            &outlet_id,
                            destination_id.as_deref(),
                            "outlet_to",
                            &format!("outlet {label_text}"),
                            None,
                        );
                    }
                }
                "segue" => {
                    let segue_edge = context.graph_id("segue", &[json!(index)]);
                    let description = format!("segue {label_text}");
                    if destination_missing {
                        builder.connect(
                            &mut context,
                            segue_edge,
                            &source_id,
                            None,
                            "segue_to",
                            &description,
                            Some("destination_scene_missing"),
                        );
                    } else {
                        builder.connect(
                            &mut context,
                            segue_edge,
                            &source_id,
                            destination_id.as_deref(),
                            "segue_to",
                            &description,
                            None,
                        );
                    }
                }
                other => {
                    let edge = context.graph_id("unknown-connection", &[json!(index)]);
                    builder.connect(
                        &mut context,
                        edge,
                        &source_id,
                        None,
                        "contains",
                        &format!("connection type {other}"),
                        Some("unsupported_connection_type"),
                    );
                }
            }
        }
        let objects_truncated = parsed.omitted_objects > 0 || parsed.objects.len() > document_object_count;
        let parser_omitted_hierarchy_references = parsed.omitted_hierarchy_references;
        omitted_hierarchy_references += parser_omitted_hierarchy_references;
        let parser_omitted_connections = parsed.omitted_connections;
        let connections_truncated =
            parser_omitted_connections > 0 || parsed.connections.len() > limits.max_connections;
        omitted_objects += parsed.omitted_objects + parsed.objects.len().saturating_sub(document_object_count);
        builder.omitted_connections +=
            parsed.connections.len().saturating_sub(limits.max_connections) + parser_omitted_connections;
        summaries.push(json!({
            "relative_path": document.relative_path,
            "archive_sha256": document.archive_sha256,
            "document_kind": document.document_kind,
            "object_count": parsed.object_count,
            "connection_count": parsed.connections.len() + parser_omitted_connections,
            "hierarchy_complete": !parsed.hierarchy.is_empty() && !builder.truncated && parser_omitted_hierarchy_references == 0,
        }));
        let partial_connections = connections_truncated || context.document_omitted_connections > 0;
        let hierarchy_status;
        let hierarchy_reason: Value;
        if parser_omitted_hierarchy_references > 0 {
            hierarchy_status = "partial";
            hierarchy_reason = json!("archive_hierarchy_references_missing");
        } else if parsed.hierarchy.is_empty() {
            hierarchy_status = "unsupported";
            hierarchy_reason = json!("archive_hierarchy_not_decoded");
        } else if hierarchy_truncated || context.document_omitted_hierarchy_edges > 0 {
            hierarchy_status = "partial";
            hierarchy_reason = json!("graph_limit_reached");
        } else {
            hierarchy_status = "complete";
            hierarchy_reason = Value::Null;
        }
        coverage.push(json!({
            "facet": format!("objects:{}", document.relative_path),
            "status": if objects_truncated { "partial" } else { "complete" },
            "reason": if objects_truncated { json!("object_limit_reached") } else { Value::Null },
            "examined": document_object_count,
            "omitted": parsed.omitted_objects + parsed.objects.len().saturating_sub(document_object_count),
        }));
        coverage.push(json!({
            "facet": format!("connections:{}", document.relative_path),
            "status": if partial_connections { "partial" } else { "complete" },
            "reason": if partial_connections { json!("connection_limit_reached") } else { Value::Null },
            "examined": parsed.connections.len().min(limits.max_connections),
            "omitted": parsed.connections.len().saturating_sub(limits.max_connections)
                + context.document_omitted_connections + parser_omitted_connections,
        }));
        coverage.push(json!({
            "facet": format!("hierarchy:{}", document.relative_path),
            "status": hierarchy_status,
            "reason": hierarchy_reason,
            "examined": hierarchy_count,
            "omitted": context.document_omitted_hierarchy_edges + parser_omitted_hierarchy_references,
        }));
        coverage.push(json!({
            "facet": format!("classes:{}", document.relative_path),
            "status": if parsed.classes.is_empty() { "unsupported" } else { "complete" },
            "reason": if parsed.classes.is_empty() { json!("archive_class_table_not_decoded") } else { Value::Null },
            "examined": parsed.classes.len(),
            "omitted": 0,
        }));
    }
    if documents.len() > limits.max_documents {
        builder.truncated = true;
        coverage.push(json!({
            "facet": "documents",
            "status": "partial",
            "reason": "document_limit_reached",
            "examined": limits.max_documents,
            "omitted": documents.len() - limits.max_documents,
        }));
    }
    if builder.omitted_graph_nodes > 0 {
        coverage.push(json!({
            "facet": "graph_nodes",
            "status": "partial",
            "reason": "max_objects_reached",
            "examined": builder.nodes.len(),
            "omitted": builder.omitted_graph_nodes,
        }));
    }
    let truncated = builder.truncated
        || omitted_objects > 0
        || builder.omitted_connections > 0
        || omitted_hierarchy_references > 0;
    json!({
        "target_sha256": target_sha256,
        "documents": summaries,
        "graph": {
            "target_sha256": target_sha256,
            "provider": {"id": "rea-artifact-graph", "version": "1", "tool_version": tool_version},
            "nodes": builder.nodes.values().cloned().collect::<Vec<_>>(),
            "edges": builder.edges,
            "coverage": coverage,
            "truncated": truncated,
        },
        "limitations": [
            "The graph reflects recognized Interface Builder archive fields and connections; omitted private or unrecognized archive fields remain unknown.",
            "A target-action selector is an Interface Builder observation and does not prove that the binary contains a matching implementation.",
            "Decoded constraints, runtime visibility, dynamic UI creation, and pixel geometry are not inferred from these archives.",
        ],
    })
}

// ---------------------------------------------------------------------------
// InterfaceBuilderAnalysis.ts
// ---------------------------------------------------------------------------

struct NibProjection {
    raw: Value,
    omitted: usize,
}

fn normalize_class_name(value: &str) -> String {
    value.trim_end_matches('\0').to_string()
}

fn nib_reference(value: Option<&Value>) -> Option<usize> {
    let object = value?.as_object()?;
    let number = object.get("$nib_object_ref")?.as_f64()?;
    if number >= 0.0 && number.fract() == 0.0 {
        Some(number as usize)
    } else {
        None
    }
}

struct NibProjector<'a> {
    by_id: HashMap<usize, &'a NibObject>,
    budget: &'a mut DecodeBudget,
    decoded_strings: HashMap<usize, Option<String>>,
    runtime_classes: HashMap<usize, Option<String>>,
}

impl<'a> NibProjector<'a> {
    fn decoded_string(&mut self, object_id: usize, object: &NibObject) -> Result<Option<String>, BudgetExceeded> {
        if let Some(known) = self.decoded_strings.get(&object_id) {
            return Ok(known.clone());
        }
        let data = object.values.get("NS.bytes");
        let encoded = data
            .and_then(Value::as_object)
            .and_then(|map| map.get("$nib_data_base64"))
            .and_then(Value::as_str);
        let Some(encoded) = encoded else {
            self.decoded_strings.insert(object_id, None);
            return Ok(None);
        };
        self.budget.reserve(
            64.0 + encoded.encode_utf16().count() as f64 * 2.0,
            "NIBArchive string projection exceeds the aggregate Interface Builder decode budget",
        )?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap_or_default();
        let value = String::from_utf8_lossy(&bytes).into_owned();
        self.decoded_strings.insert(object_id, Some(value.clone()));
        Ok(Some(value))
    }

    fn dereference(&mut self, value: Option<&Value>) -> Result<Option<Value>, BudgetExceeded> {
        let Some(value) = value else { return Ok(None) };
        let Value::Object(map) = value else {
            return Ok(Some(value.clone()));
        };
        if let Some(Value::String(encoded)) = map.get("$nib_data_base64") {
            self.budget.reserve_base64_json_string_occurrence(encoded)?;
            return Ok(Some(value.clone()));
        }
        let Some(reference) = map.get("$nib_object_ref").and_then(Value::as_f64) else {
            return Ok(Some(value.clone()));
        };
        let reference_id = reference as usize;
        let Some(target) = self.by_id.get(&reference_id).copied() else {
            return Ok(None);
        };
        if normalize_class_name(&target.class_name) == "NSString" {
            if let Some(string) = self.decoded_string(reference_id, target)? {
                self.budget.reserve_json_string_occurrence(&string)?;
                return Ok(Some(Value::String(string)));
            }
        }
        Ok(Some(json!({"objectID": reference_id.to_string()})))
    }

    fn referenced_string(&mut self, value: Option<&Value>) -> Result<Option<String>, BudgetExceeded> {
        let Some(reference) = nib_reference(value) else {
            return Ok(None);
        };
        let Some(target) = self.by_id.get(&reference).copied() else {
            return Ok(None);
        };
        if normalize_class_name(&target.class_name) != "NSString" {
            return Ok(None);
        }
        let Some(string) = self.decoded_string(reference, target)? else {
            return Ok(None);
        };
        self.budget.reserve_json_string_occurrence(&string)?;
        Ok(Some(string))
    }

    fn runtime_class(&mut self, object_id: usize) -> Result<Option<String>, BudgetExceeded> {
        if let Some(known) = self.runtime_classes.get(&object_id) {
            return Ok(known.clone());
        }
        let Some(object) = self.by_id.get(&object_id).copied() else {
            return Ok(None);
        };
        let stored = normalize_class_name(&object.class_name);
        let resolved = if stored == "NSClassSwapper" {
            self.referenced_string(object.values.get("NSClassName"))?.unwrap_or(stored)
        } else if stored == "UIClassSwapper" {
            self.referenced_string(object.values.get("UIClassName"))?.unwrap_or(stored)
        } else {
            stored
        };
        self.runtime_classes.insert(object_id, Some(resolved.clone()));
        Ok(Some(resolved))
    }
}

fn project_nib_archive(
    archive: &NibArchive,
    budget: &mut DecodeBudget,
    max_hierarchy_nodes: usize,
) -> Result<NibProjection, BudgetExceeded> {
    let by_id: HashMap<usize, &NibObject> = archive.objects.iter().map(|o| (o.id, o)).collect();
    let mut projected_fields = 0usize;
    for object in &archive.objects {
        projected_fields += object.values.len();
    }
    budget.reserve(
        archive.objects.len() as f64 * 128.0 + projected_fields as f64 * 128.0,
        "NIBArchive graph projection exceeds the aggregate Interface Builder decode budget",
    )?;
    budget.reserve(
        archive.classes.len() as f64 * 96.0,
        "NIBArchive class projection exceeds the aggregate Interface Builder decode budget",
    )?;
    let mut projector = NibProjector {
        by_id,
        budget,
        decoded_strings: HashMap::new(),
        runtime_classes: HashMap::new(),
    };
    static EXCLUDE: OnceLock<Regex> = OnceLock::new();
    let exclude = cached_regex(
        &EXCLUDE,
        r"^(?:NSObject|NSIBObjectData|NSString|NSMutableString|NSNumber|NSArray|NSMutableArray|NSSet|NSMutableSet|NSDictionary|NSMutableDictionary|NSApplication|NSNib[^\n\r\u{2028}\u{2029}]*Connector|UIRuntime[A-Za-z0-9_]*Connection)$",
    );
    static NAME_KEY: OnceLock<Regex> = OnceLock::new();
    let name_key = cached_regex(&NAME_KEY, r"(?i)(?:title|label|identifier|accessibility|name|contents)");
    let mut objects = Map::new();
    let mut retained: Vec<usize> = Vec::new();
    for object in &archive.objects {
        let name = projector.runtime_class(object.id)?.unwrap_or_default();
        if exclude.is_match(&name) {
            continue;
        }
        let class_name = projector
            .runtime_class(object.id)?
            .unwrap_or_else(|| normalize_class_name(&object.class_name));
        projector.budget.reserve_json_string_occurrence(&class_name)?;
        let mut label = class_name.clone();
        for (key, value) in js_order_ivalues(&object.values) {
            if !name_key.is_match(key) {
                continue;
            }
            let resolved = projector.dereference(Some(value))?;
            if let Some(Value::String(text)) = resolved {
                label = text;
                break;
            }
        }
        projector.budget.reserve_json_string_occurrence(&label)?;
        let mut nib_values = Map::new();
        for (key, value) in js_order_ivalues(&object.values) {
            projector.budget.reserve_json_property_name_occurrence(key)?;
            let resolved = projector.dereference(Some(value))?.unwrap_or(Value::Null);
            nib_values.insert(key.clone(), resolved);
        }
        objects.insert(
            object.id.to_string(),
            json!({
                "customClass": class_name,
                "label": label,
                "objectID": object.id.to_string(),
                "nibValues": nib_values,
            }),
        );
        retained.push(object.id);
    }
    let retained_set: HashSet<usize> = retained.iter().copied().collect();
    let mut connections: Map<String, Value> = Map::new();
    static UIKIT: OnceLock<Regex> = OnceLock::new();
    let uikit_re = cached_regex(&UIKIT, r"^UIRuntime[A-Za-z0-9_]*Connection$");
    for object in &archive.objects {
        let class_name = normalize_class_name(&object.class_name);
        let ui_kit = uikit_re.is_match(&class_name);
        if !ui_kit && !class_name.contains("Connector") {
            continue;
        }
        let values = &object.values;
        let source = nib_reference(values.get(if ui_kit { "UISource" } else { "NSSource" }));
        let Some(source) = source else { continue };
        let destination = nib_reference(values.get(if ui_kit { "UIDestination" } else { "NSDestination" }));
        let label = projector.referenced_string(values.get(if ui_kit { "UILabel" } else { "NSLabel" }))?;
        let kind = if class_name.contains("Outlet") {
            "outlet".to_string()
        } else if class_name.contains("Control") || class_name.contains("Event") {
            "action".to_string()
        } else {
            class_name.clone()
        };
        projector.budget.reserve_json_string_occurrence(&kind)?;
        let mut entry = Map::new();
        entry.insert("type".into(), json!(kind));
        entry.insert(
            "destination-id".into(),
            destination.map(|d| json!(d.to_string())).unwrap_or(Value::Null),
        );
        entry.insert("label".into(), label.map(Value::String).unwrap_or(Value::Null));
        entry.insert("source_id".into(), json!(source.to_string()));
        entry.insert("archive_object_id".into(), json!(object.id.to_string()));
        if let Some(mask) = values.get("UIEventMask").filter(|v| v.is_number()) {
            entry.insert("ui_event_mask".into(), mask.clone());
        }
        let list = connections
            .entry(source.to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Value::Array(items) = list {
            items.push(Value::Object(entry));
        }
    }
    // Legacy hierarchy walk.
    let mut hierarchy_omitted = 0usize;
    let mut hierarchy_node_count = 0usize;
    fn hierarchy_for(
        projector: &mut NibProjector<'_>,
        object_id: usize,
        seen: &HashSet<usize>,
        depth: usize,
        max_nodes: usize,
        node_count: &mut usize,
        omitted: &mut usize,
    ) -> Option<HierarchyNode> {
        if depth > 32 || seen.contains(&object_id) {
            *omitted += 1;
            return None;
        }
        if *node_count >= max_nodes {
            *omitted += 1;
            return None;
        }
        if !projector.budget.try_reserve(128.0) {
            *omitted += 1;
            return None;
        }
        let Some(object) = projector.by_id.get(&object_id).copied() else {
            *omitted += 1;
            return None;
        };
        *node_count += 1;
        let mut next_seen = seen.clone();
        next_seen.insert(object_id);
        let mut children: Vec<HierarchyNode> = Vec::new();
        static KEY: OnceLock<Regex> = OnceLock::new();
        let key_re = cached_regex(&KEY, r"(?i)(?:subviews|contentview|childviewcontrollers|view)$");
        static ARRAYISH: OnceLock<Regex> = OnceLock::new();
        let arrayish = cached_regex(&ARRAYISH, r"(?i)array|set");
        for (key, value) in js_order_ivalues(&object.values) {
            if !key_re.is_match(key) {
                continue;
            }
            let Some(direct) = nib_reference(Some(value)) else {
                continue;
            };
            let Some(target) = projector.by_id.get(&direct).copied() else {
                *omitted += 1;
                continue;
            };
            if arrayish.is_match(&target.class_name) {
                for candidate in js_order_ivalues(&target.values).into_iter().map(|(_, v)| v) {
                    let child = nib_reference(Some(candidate));
                    let nested = child.and_then(|c| {
                        hierarchy_for(projector, c, &next_seen, depth + 1, max_nodes, node_count, omitted)
                    });
                    if let Some(nested) = nested {
                        children.push(nested);
                    }
                }
            } else if let Some(nested) =
                hierarchy_for(projector, direct, &next_seen, depth + 1, max_nodes, node_count, omitted)
            {
                children.push(nested);
            }
        }
        Some(HierarchyNode {
            object_id: object_id.to_string(),
            children,
        })
    }
    let ib_data = archive
        .objects
        .iter()
        .find(|o| normalize_class_name(&o.class_name) == "NSIBObjectData");
    let root_id = nib_reference(ib_data.and_then(|o| o.values.get("NSRoot")));
    let mut hierarchy: Vec<HierarchyNode> = Vec::new();
    if let Some(root_id) = root_id {
        if let Some(root) = hierarchy_for(
            &mut projector,
            root_id,
            &HashSet::new(),
            0,
            max_hierarchy_nodes,
            &mut hierarchy_node_count,
            &mut hierarchy_omitted,
        ) {
            hierarchy.push(root);
        }
    }
    let object_keys: HashSet<usize> = objects.keys().filter_map(|k| k.parse::<usize>().ok()).collect();
    let _ = &retained_set;
    let view_hierarchy = {
        let budget_ref: &mut DecodeBudget = projector.budget;
        let mut reserve = || budget_ref.try_reserve(128.0);
        project_nib_view_hierarchy(&archive.objects, &object_keys, &mut reserve, max_hierarchy_nodes)
    };
    let (merged, merged_omitted) = {
        let budget_ref: &mut DecodeBudget = projector.budget;
        let mut reserve = || budget_ref.try_reserve(96.0);
        merge_nib_hierarchies(
            hierarchy,
            view_hierarchy.hierarchy.as_deref().unwrap_or(&[]),
            &mut reserve,
            max_hierarchy_nodes,
        )
    };
    let mut classes = Map::new();
    for name in &archive.classes {
        let class_name = normalize_class_name(name);
        projector.budget.reserve_json_property_name_occurrence(&class_name)?;
        classes.insert(class_name, json!({}));
    }
    Ok(NibProjection {
        omitted: view_hierarchy.omitted + hierarchy_omitted + merged_omitted,
        raw: json!({
            "com.apple.ibtool.document.objects": objects,
            "com.apple.ibtool.document.connections": connections,
            "com.apple.ibtool.document.hierarchy": merged.iter().map(HierarchyNode::to_value).collect::<Vec<_>>(),
            "com.apple.ibtool.document.classes": classes,
        }),
    })
}

fn js_order_ivalues(values: &IndexMap<String, Value>) -> Vec<(&String, &Value)> {
    crate::plistjs::js_order(values)
}

struct FileEntry {
    path: String,
    absolute: std::path::PathBuf,
    size: u64,
}

fn artifact_io(detail: String) -> NativeError {
    NativeError::artifact(OPERATION, ArtifactReason::Io, detail)
}

fn walk_candidates(root: &Path, max_documents: usize) -> NativeResult<(Vec<FileEntry>, Vec<FileEntry>, usize, usize)> {
    let capacity = max_documents + MAX_REPORTED_OMITTED_ARCHIVES;
    let mut candidates: Vec<FileEntry> = Vec::new();
    let mut total = 0usize;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        crate::cancel::checkpoint("decode_interface_builder")?;
        let reader = fs::read_dir(&directory)
            .map_err(|e| artifact_io(format!("Could not open directory at {} ({})", directory.display(), io_code(&e))))?;
        for child in reader {
            let child = child
                .map_err(|e| artifact_io(format!("Could not read directory at {} ({})", directory.display(), io_code(&e))))?;
            let absolute = child.path();
            let metadata = fs::symlink_metadata(&absolute)
                .map_err(|e| artifact_io(format!("Could not inspect entry at {} ({})", absolute.display(), io_code(&e))))?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                pending.push(absolute);
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            let relative = absolute
                .strip_prefix(root)
                .map(|p| {
                    p.components()
                        .map(|c| c.as_os_str().to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                        .join("/")
                })
                .unwrap_or_default();
            let lower = relative.to_lowercase();
            if !(lower.ends_with(".nib") || lower.ends_with("/objects.nib")) {
                continue;
            }
            total += 1;
            let entry = FileEntry {
                path: relative,
                absolute,
                size: metadata.len(),
            };
            let position = candidates.partition_point(|existing| existing.path.as_str() < entry.path.as_str());
            candidates.insert(position, entry);
            if candidates.len() > capacity {
                candidates.pop();
            }
        }
    }
    let omitted_samples: Vec<FileEntry> = if candidates.len() > max_documents {
        candidates.split_off(max_documents)
    } else {
        Vec::new()
    };
    let omitted = total.saturating_sub(max_documents);
    let unreported = total.saturating_sub(max_documents).saturating_sub(omitted_samples.len());
    Ok((candidates, omitted_samples, omitted, unreported))
}

fn io_code(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::NotFound => "ENOENT",
        std::io::ErrorKind::PermissionDenied => "EACCES",
        _ => "EIO",
    }
}

enum DecodeFailure {
    Budget(BudgetExceeded),
    Invalid(String),
}

impl From<NibError> for DecodeFailure {
    fn from(error: NibError) -> Self {
        match error {
            NibError::Budget(b) => DecodeFailure::Budget(b),
            NibError::Type(message) => DecodeFailure::Invalid(message),
        }
    }
}

impl From<BudgetExceeded> for DecodeFailure {
    fn from(value: BudgetExceeded) -> Self {
        DecodeFailure::Budget(value)
    }
}

impl From<ExpansionFailure> for DecodeFailure {
    fn from(value: ExpansionFailure) -> Self {
        match value {
            ExpansionFailure::Budget { message, .. } => DecodeFailure::Budget(BudgetExceeded {
                reason: "aggregate_decode_budget_exhausted",
                message,
            }),
            ExpansionFailure::Malformed(message) => DecodeFailure::Invalid(message),
        }
    }
}

impl From<crate::plistjs::PlistError> for DecodeFailure {
    fn from(value: crate::plistjs::PlistError) -> Self {
        DecodeFailure::Invalid(value.message)
    }
}

/// Decode compiled Interface Builder archives from a local app bundle.
pub fn analyze_interface_builder_bundle(
    bundle_path: &Path,
    target_sha256: &str,
    limits: InterfaceBuilderLimits,
) -> NativeResult<Value> {
    let root = fs::canonicalize(bundle_path)
        .map_err(|e| artifact_io(format!("Could not resolve artifact root at {} ({})", bundle_path.display(), io_code(&e))))?;
    let mut documents: Vec<IbDocumentInput> = Vec::new();
    let mut invalid: Vec<String> = Vec::new();
    let mut omitted_archives: Vec<(String, String)> = Vec::new();
    let mut unreported_omitted_archives = 0usize;
    let mut incomplete_hierarchies: IndexMap<String, usize> = IndexMap::new();
    let mut prototype_key_omissions: IndexMap<String, usize> = IndexMap::new();
    let mut attempted = 0usize;
    let mut aggregate_input_bytes = 0f64;
    let mut decode_budget = DecodeBudget::new(MAX_AGGREGATE_DECODE_BYTES);
    let record_omitted = |omitted_archives: &mut Vec<(String, String)>, unreported: &mut usize, path: &str, reason: &str| {
        if omitted_archives.len() < MAX_REPORTED_OMITTED_ARCHIVES {
            omitted_archives.push((path.to_string(), reason.to_string()));
        } else {
            *unreported += 1;
        }
    };
    let (selected, omitted_samples, mut omitted, unreported_selection) = walk_candidates(&root, limits.max_documents)?;
    for entry in &omitted_samples {
        record_omitted(&mut omitted_archives, &mut unreported_omitted_archives, &entry.path, "max_documents");
    }
    unreported_omitted_archives += unreported_selection;
    for entry in &selected {
        let remaining_input_bytes = MAX_AGGREGATE_INPUT_BYTES - aggregate_input_bytes;
        if entry.size as f64 > remaining_input_bytes {
            omitted += 1;
            record_omitted(
                &mut omitted_archives,
                &mut unreported_omitted_archives,
                &entry.path,
                "aggregate_decode_budget_exhausted",
            );
            continue;
        }
        attempted += 1;
        let outcome = (|| -> Result<Option<IbDocumentInput>, DecodeFailure> {
            let bytes = read_entry(&entry.absolute, remaining_input_bytes)?;
            aggregate_input_bytes += bytes.len() as f64;
            let is_nib = bytes.len() >= 10 && &bytes[..10] == b"NIBArchive";
            let mut nib: Option<NibProjection> = None;
            let mut xml_text: Option<String> = None;
            if is_nib {
                let mut document_budget = DecodeBudget::new(decode_budget.remaining_bytes());
                let archive = decode_nib_archive(&bytes, Some(&mut document_budget))?;
                nib = Some(project_nib_archive(&archive, &mut document_budget, limits.max_objects)?);
                decode_budget.reserve(
                    document_budget.used_bytes(),
                    "NIBArchive representation exceeds the aggregate Interface Builder decode budget",
                )?;
            } else {
                let binary = bytes.len() >= 8 && &bytes[..8] == b"bplist00";
                if !binary {
                    xml_text = Some(decode_xml_plist_text(&bytes)?);
                }
                let reservation =
                    estimate_property_list_decode_bytes(&bytes, decode_budget.remaining_bytes(), xml_text.as_deref())?;
                decode_budget.reserve(
                    reservation,
                    "plist representation exceeds the aggregate Interface Builder decode budget",
                )?;
            }
            let (raw, omitted_prototype_keys) = match nib {
                Some(projection) => {
                    if projection.omitted > 0 {
                        incomplete_hierarchies.insert(entry.path.clone(), projection.omitted);
                    }
                    (projection.raw, 0usize)
                }
                None => {
                    let binary = bytes.len() >= 8 && &bytes[..8] == b"bplist00";
                    let (value, omitted_keys) = if binary {
                        (parse_binary(&bytes)?, 0)
                    } else {
                        let text = match &xml_text {
                            Some(text) => text.clone(),
                            None => decode_xml_plist_text(&bytes)?,
                        };
                        parse_xml_property_list(&text)?
                    };
                    (project_plist_value(&value)?.value, omitted_keys)
                }
            };
            if omitted_prototype_keys > 0 {
                prototype_key_omissions.insert(entry.path.clone(), omitted_prototype_keys);
            }
            let document_hash = hex::encode(Sha256::digest(&bytes));
            Ok(Some(IbDocumentInput {
                relative_path: entry.path.clone(),
                archive_sha256: document_hash,
                document_kind: if entry.path.contains(".storyboardc/") {
                    "storyboard_scene"
                } else {
                    "nib"
                },
                raw,
            }))
        })();
        match outcome {
            Ok(Some(document)) => documents.push(document),
            Ok(None) => {}
            Err(DecodeFailure::Budget(budget)) => {
                omitted += 1;
                record_omitted(&mut omitted_archives, &mut unreported_omitted_archives, &entry.path, budget.reason);
            }
            Err(DecodeFailure::Invalid(message)) => {
                invalid.push(format!("{}: {}", entry.path, message));
            }
        }
    }
    let result = build_interface_builder_analysis(target_sha256, "rea-interface-builder/1", &documents, limits);
    Ok(finalize_hierarchy_coverage(
        result,
        &incomplete_hierarchies,
        &prototype_key_omissions,
        &invalid,
        &omitted_archives,
        unreported_omitted_archives,
        attempted,
        omitted,
    ))
}

fn read_entry(path: &Path, max_input_bytes: f64) -> Result<Vec<u8>, DecodeFailure> {
    let mut file = open_nofollow(path).map_err(|e| DecodeFailure::Invalid(format!("could not open: {e}")))?;
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    if size as f64 > max_input_bytes {
        return Err(DecodeFailure::Budget(BudgetExceeded {
            reason: "aggregate_decode_budget_exhausted",
            message: "archive exceeds the aggregate Interface Builder decode budget".to_string(),
        }));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(max_input_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| DecodeFailure::Invalid(format!("could not read: {e}")))?;
    if bytes.len() as f64 > max_input_bytes {
        return Err(DecodeFailure::Budget(BudgetExceeded {
            reason: "aggregate_decode_budget_exhausted",
            message: "archive exceeded the aggregate Interface Builder decode budget".to_string(),
        }));
    }
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
fn finalize_hierarchy_coverage(
    mut result: Value,
    incomplete_hierarchies: &IndexMap<String, usize>,
    prototype_key_omissions: &IndexMap<String, usize>,
    invalid: &[String],
    omitted_archives: &[(String, String)],
    unreported_omitted_archives: usize,
    attempted: usize,
    omitted: usize,
) -> Value {
    let archive_decode_partial = !invalid.is_empty() || !prototype_key_omissions.is_empty() || !omitted_archives.is_empty();
    // documents
    if let Some(documents) = result.get_mut("documents").and_then(Value::as_array_mut) {
        for document in documents {
            let path = document["relative_path"].as_str().unwrap_or("").to_string();
            let complete = document["hierarchy_complete"].as_bool().unwrap_or(false)
                && !incomplete_hierarchies.contains_key(&path);
            document["hierarchy_complete"] = json!(complete);
        }
    }
    let graph = result.get_mut("graph").and_then(Value::as_object_mut).expect("graph");
    let existing_truncated = graph.get("truncated").and_then(Value::as_bool).unwrap_or(false);
    let mut coverage: Vec<Value> = graph
        .get("coverage")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|facet| {
            let name = facet["facet"].as_str().unwrap_or("").to_string();
            if let Some(path) = name.strip_prefix("hierarchy:") {
                if let Some(omitted_count) = incomplete_hierarchies.get(path) {
                    let mut facet = facet.clone();
                    facet["status"] = json!("partial");
                    facet["reason"] = json!("serialized_view_hierarchy_incomplete");
                    facet["omitted"] = json!(facet["omitted"].as_u64().unwrap_or(0) + *omitted_count as u64);
                    return facet;
                }
            }
            facet
        })
        .collect();
    let reason: Value = if omitted_archives.iter().any(|(_, r)| r == "aggregate_decode_budget_exhausted") {
        json!("aggregate_decode_budget_exhausted")
    } else if omitted_archives.iter().any(|(_, r)| r == "max_documents") {
        json!("document_limit_reached")
    } else if !omitted_archives.is_empty() {
        json!("archive_decode_budget_exhausted")
    } else if !invalid.is_empty() {
        json!("one_or_more_archives_invalid")
    } else if !prototype_key_omissions.is_empty() {
        json!("dictionary_entries_omitted")
    } else {
        Value::Null
    };
    coverage.push(json!({
        "facet": "archive_decode",
        "status": if archive_decode_partial { "partial" } else { "complete" },
        "reason": reason,
        "examined": attempted,
        "omitted": omitted,
    }));
    graph.insert("coverage".into(), Value::Array(coverage));
    graph.insert(
        "truncated".into(),
        json!(existing_truncated || omitted > 0 || archive_decode_partial || !incomplete_hierarchies.is_empty()),
    );
    let mut limitations: Vec<Value> = result["limitations"].as_array().cloned().unwrap_or_default();
    limitations.push(json!("Compiled Interface Builder archives are private serialized object graphs. The decoder reports only recognized keyed-archive objects and connections; unrecognized object classes and fields remain unknown."));
    if !incomplete_hierarchies.is_empty() {
        limitations.push(json!("Some serialized hierarchy links could not be projected within the bounded hierarchy; their parentage remains unknown."));
    }
    if !invalid.is_empty() {
        limitations.push(json!(format!(
            "Some Interface Builder archives could not be decoded: {}",
            invalid.iter().take(16).cloned().collect::<Vec<_>>().join("; ")
        )));
    }
    for (path, count) in prototype_key_omissions {
        limitations.push(json!(format!("{path}: {}", omitted_prototype_keys_limitation(*count))));
    }
    for (path, reason) in omitted_archives {
        limitations.push(json!(format!("{path}: omitted because {}.", reason.replace('_', " "))));
    }
    if unreported_omitted_archives != 0 {
        limitations.push(json!(format!(
            "{unreported_omitted_archives} additional omitted archive path(s) and their reasons were not retained; reporting is bounded to {MAX_REPORTED_OMITTED_ARCHIVES} paths."
        )));
    }
    result["limitations"] = Value::Array(limitations);
    result
}
