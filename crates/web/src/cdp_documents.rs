//! Frame, resource, DOM, and accessibility projections
//! (port of REA browser/CdpCaptureDocuments.ts).

use serde_json::{json, Map, Value};
use url::Url;

use crate::cdp_completeness::CdpCaptureCompleteness;
use crate::cdp_values::{
    allowed_url, cdp_str, exclusion_reason_for_url, finite_f64, record, records,
};

const DOM_URL_ATTRIBUTES: &[&str] = &["href", "src", "action", "formaction", "poster"];
const AGENT_RELS: &[&str] = &["mcp", "model-context", "ai-plugin", "service-desc"];
const AX_STATES: &[&str] = &[
    "atomic",
    "autocomplete",
    "busy",
    "checked",
    "disabled",
    "editable",
    "expanded",
    "focusable",
    "focused",
    "hasPopup",
    "hidden",
    "invalid",
    "level",
    "live",
    "modal",
    "multiline",
    "multiselectable",
    "orientation",
    "pressed",
    "readonly",
    "required",
    "selected",
    "valuemax",
    "valuemin",
];

pub struct DomCapture {
    pub total: i64,
    pub nodes: Vec<Value>,
    pub urls: Vec<Value>,
    pub agent_hints: Vec<Value>,
    pub excluded_urls: i64,
}

pub struct AxCapture {
    pub total: i64,
    pub nodes: Vec<Value>,
    pub text_capture: Value,
    pub tree_incomplete: bool,
}

pub fn main_frame_url(result: &Map<String, Value>) -> Option<String> {
    let frame = result.get("frameTree").and_then(record)?.get("frame")?;
    cdp_str(frame.get("url")?).map(str::to_string)
}

pub fn main_frame_id(result: &Map<String, Value>) -> Option<String> {
    let frame = result.get("frameTree").and_then(record)?.get("frame")?;
    cdp_str(frame.get("id")?).map(str::to_string)
}

pub fn frame_document_key(result: &Map<String, Value>) -> Option<String> {
    let frame = result.get("frameTree").and_then(record)?.get("frame")?.as_object()?;
    let id = frame.get("loaderId").and_then(cdp_str).unwrap_or("");
    let url = frame.get("url").and_then(cdp_str).unwrap_or("");
    Some(format!("{id}\0{url}"))
}

/// Normalize every allowed frame. The main frame is first.
pub fn capture_frames(
    result: &Map<String, Value>,
    allowed_origins: &[String],
    completeness: Option<&mut CdpCaptureCompleteness>,
) -> Vec<Value> {
    let Some(root) = result.get("frameTree").and_then(record) else {
        if let Some(completeness) = completeness {
            completeness.exclude("frames", "invalid_protocol_value", Some(1));
        }
        return Vec::new();
    };
    let mut completeness = completeness;
    let mut items = Vec::new();
    for tree in walk_frames(root) {
        let Some(frame) = tree.get("frame").and_then(record) else {
            exclude(completeness.as_mut(), "frames", "invalid_protocol_value");
            continue;
        };
        let Some(frame_id) = frame.get("id").and_then(cdp_str) else {
            exclude(completeness.as_mut(), "frames", "invalid_protocol_value");
            continue;
        };
        let raw_url = frame.get("url").and_then(cdp_str);
        let Some(sanitized) = allowed_url(raw_url, allowed_origins) else {
            exclude(completeness.as_mut(), "frames", exclusion_reason_for_url(raw_url));
            continue;
        };
        let Some(origin) = sanitized.origin else {
            exclude(completeness.as_mut(), "frames", exclusion_reason_for_url(raw_url));
            continue;
        };
        items.push(json!({
            "frame_id": frame_id,
            "parent_frame_id": frame.get("parentId").and_then(cdp_str),
            "url": sanitized.url,
            "origin": origin,
        }));
    }
    items
}

pub struct CapturedResource {
    pub raw_url: String,
    pub public: Value,
}

pub fn capture_resources(
    result: &Map<String, Value>,
    allowed_origins: &[String],
    completeness: &mut CdpCaptureCompleteness,
) -> Vec<CapturedResource> {
    let Some(root) = result.get("frameTree").and_then(record) else {
        completeness.exclude("resources", "invalid_protocol_value", Some(1));
        return Vec::new();
    };
    let mut items = Vec::new();
    for tree in walk_frames(root) {
        let Some(resources) = tree.get("resources").and_then(Value::as_array) else {
            continue;
        };
        for resource in resources {
            let Some(resource) = resource.as_object() else {
                completeness.exclude("resources", "invalid_protocol_value", Some(1));
                continue;
            };
            let raw = resource.get("url").and_then(cdp_str);
            let Some(sanitized) = allowed_url(raw, allowed_origins) else {
                completeness.exclude("resources", exclusion_reason_for_url(raw), Some(1));
                continue;
            };
            let Some(origin) = sanitized.origin else {
                completeness.exclude("resources", exclusion_reason_for_url(raw), Some(1));
                continue;
            };
            let content_size = resource
                .get("contentSize")
                .and_then(finite_f64)
                .map(|size| crate::cdp_values::json_number(size.max(0.0)))
                .unwrap_or(Value::Null);
            items.push(CapturedResource {
                raw_url: raw.unwrap_or("").to_string(),
                public: json!({
                    "url": sanitized.url,
                    "origin": origin,
                    "type": resource.get("type").and_then(cdp_str).unwrap_or("Other"),
                    "mime_type": resource.get("mimeType").and_then(cdp_str).unwrap_or(""),
                    "content_size": content_size,
                }),
            });
        }
    }
    items
}

pub fn capture_dom(
    result: &Map<String, Value>,
    allowed_origins: &[String],
    completeness: &mut CdpCaptureCompleteness,
) -> DomCapture {
    let strings: Vec<String> = result
        .get("strings")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|value| value.as_str().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default();
    let mut capture = DomCapture {
        total: 0,
        nodes: Vec::new(),
        urls: Vec::new(),
        agent_hints: Vec::new(),
        excluded_urls: 0,
    };
    for document in records(result.get("documents").unwrap_or(&Value::Null)) {
        let document_url = indexed_string(&strings, document.get("documentURL"));
        if allowed_url(Some(document_url.as_str()).filter(|s| !s.is_empty()), allowed_origins).is_none()
        {
            completeness.exclude(
                "dom",
                exclusion_reason_for_url(if document_url.is_empty() {
                    None
                } else {
                    Some(document_url.as_str())
                }),
                Some(1),
            );
            continue;
        }
        let base_url = {
            let base = indexed_string(&strings, document.get("baseURL"));
            if base.is_empty() { document_url.clone() } else { base }
        };
        let Some(document_nodes) = document.get("nodes").and_then(record) else {
            continue;
        };
        let node_types = number_array(document_nodes.get("nodeType"));
        let node_names = number_array(document_nodes.get("nodeName"));
        let node_values = number_array(document_nodes.get("nodeValue"));
        let parents = number_array(document_nodes.get("parentIndex"));
        let attributes = document_nodes.get("attributes").and_then(Value::as_array);
        let base_index = capture.nodes.len() as i64;
        capture.total += node_types.len() as i64;
        #[allow(clippy::needless_range_loop)]
        for index in 0..node_types.len() {
            let attribute_indexes = attributes
                .and_then(|items| items.get(index))
                .map(|value| number_array(Some(value)))
                .unwrap_or_default();
            let parent = parents.get(index).copied().unwrap_or(-1.0).trunc() as i64;
            let node_index = capture.nodes.len() as i64;
            let node_name = indexed_at(&strings, node_names.get(index).copied());
            let mut seen = std::collections::BTreeSet::new();
            let mut attribute_names = Vec::new();
            for (pair, value) in attribute_indexes.iter().enumerate() {
                if pair % 2 != 0 {
                    continue;
                }
                let name = indexed_at(&strings, Some(*value));
                if seen.insert(name.clone()) {
                    attribute_names.push(name);
                }
            }
            capture.nodes.push(json!({
                "index": node_index,
                "parent_index": if parent < 0 { -1 } else { base_index + parent },
                "node_type": (node_types[index]).trunc().max(0.0) as i64,
                "node_name": node_name,
                "node_value_length": indexed_at(&strings, node_values.get(index).copied()).encode_utf16().count() as i64,
                "attribute_names": attribute_names,
            }));
            let metadata_base = if node_name.eq_ignore_ascii_case("base") {
                document_url.as_str()
            } else {
                base_url.as_str()
            };
            push_dom_metadata(
                &mut capture,
                completeness,
                &strings,
                &attribute_indexes,
                metadata_base,
                &document_url,
                node_index,
                &node_name,
                allowed_origins,
            );
        }
    }
    capture
}

pub fn capture_accessibility(results: &[Value], include_text: bool, unavailable: bool) -> AxCapture {
    let mut nodes_raw = Vec::new();
    for result in results {
        if let Some(list) = result.get("nodes") {
            nodes_raw.extend(records(list));
        }
    }
    let node_ids: std::collections::BTreeSet<&str> = nodes_raw
        .iter()
        .filter_map(|node| node.get("nodeId").and_then(cdp_str))
        .collect();
    let mut excluded_fields = 0_i64;
    let mut tree_incomplete = false;
    let nodes: Vec<Value> = nodes_raw
        .iter()
        .map(|node| {
            if let Some(children) = node.get("childIds").and_then(Value::as_array) {
                if children.iter().any(|child| {
                    child
                        .as_str()
                        .is_some_and(|id| !node_ids.contains(id))
                }) {
                    tree_incomplete = true;
                }
            }
            let name = ax_captured(node.get("name"), include_text, &mut excluded_fields);
            let description = ax_captured(node.get("description"), include_text, &mut excluded_fields);
            json!({
                "node_id": node.get("nodeId").and_then(cdp_str).unwrap_or(""),
                "parent_id": node.get("parentId").and_then(cdp_str),
                "role": node.get("role").and_then(ax_text),
                "name": name,
                "description": description,
                "ignored": node.get("ignored").and_then(Value::as_bool).unwrap_or(false),
                "states": accessibility_states(node.get("properties")),
            })
        })
        .collect();
    let retained_bytes: i64 = nodes
        .iter()
        .map(|node| {
            utf8_len(node.get("name")) + utf8_len(node.get("description"))
        })
        .sum();
    let status = if unavailable {
        "unavailable"
    } else if include_text {
        "included"
    } else {
        "not_approved"
    };
    AxCapture {
        total: nodes.len() as i64,
        nodes,
        tree_incomplete,
        text_capture: json!({
            "status": status,
            "retained_bytes": retained_bytes,
            "excluded_fields": excluded_fields,
        }),
    }
}

fn ax_captured(value: Option<&Value>, include_text: bool, excluded_fields: &mut i64) -> Value {
    let Some(raw) = value.and_then(ax_text) else {
        return Value::Null;
    };
    if !include_text {
        *excluded_fields += 1;
        return Value::Null;
    }
    Value::String(raw)
}

fn ax_text(value: &Value) -> Option<String> {
    value
        .get("value")
        .and_then(cdp_str)
        .map(str::to_string)
}

fn accessibility_states(value: Option<&Value>) -> Vec<Value> {
    let mut states = std::collections::BTreeMap::new();
    for property in records(value.unwrap_or(&Value::Null)) {
        let Some(name) = property.get("name").and_then(cdp_str) else {
            continue;
        };
        if !AX_STATES.contains(&name) {
            continue;
        }
        let Some(raw) = property.get("value").and_then(|v| v.get("value")) else {
            continue;
        };
        let state = match raw {
            Value::Bool(flag) => Value::Bool(*flag),
            Value::Number(_) => crate::cdp_values::json_number(finite_f64(raw).unwrap_or(0.0)),
            Value::String(text) => Value::String(text.clone()),
            _ => continue,
        };
        states.insert(name.to_string(), state);
    }
    states
        .into_iter()
        .map(|(name, value)| json!({ "name": name, "value": value }))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn push_dom_metadata(
    capture: &mut DomCapture,
    completeness: &mut CdpCaptureCompleteness,
    strings: &[String],
    attributes: &[f64],
    base_url: &str,
    document_url: &str,
    node_index: i64,
    node_name: &str,
    allowed_origins: &[String],
) {
    let mut pairs = std::collections::BTreeMap::new();
    let mut index = 0;
    while index + 1 < attributes.len() {
        let name = indexed_at(strings, Some(attributes[index]));
        let value = indexed_at(strings, Some(attributes[index + 1]));
        pairs.entry(name).or_insert(value);
        index += 2;
    }
    let tag = node_name.to_ascii_lowercase();
    for attribute in DOM_URL_ATTRIBUTES {
        let Some(value) = pairs.get(*attribute) else {
            continue;
        };
        let uses_document = (tag == "form"
            && *attribute == "action"
            && value.chars().all(|ch| matches!(ch, '\t' | '\n' | '\u{000c}' | '\r' | ' ')))
            || ((tag == "button" || tag == "input") && *attribute == "formaction" && value.is_empty());
        let raw = if uses_document { document_url } else { value.as_str() };
        let (scope, url) = dom_destination(raw, base_url, allowed_origins);
        capture.urls.push(json!({
            "node_index": node_index,
            "attribute": attribute,
            "url": url,
            "destination_scope": scope,
        }));
        if scope != "approved" {
            capture.excluded_urls += 1;
            let reason = if scope == "outside_policy" {
                "disallowed_origin"
            } else {
                "unsupported_url"
            };
            completeness.exclude("metadata", reason, Some(1));
        }
    }
    if tag == "link" {
        let rels: Vec<&str> = pairs
            .get("rel")
            .map(|rel| rel.split_whitespace().filter(|part| AGENT_RELS.contains(part)).collect())
            .unwrap_or_default();
        let href = capture
            .urls
            .iter()
            .rev()
            .find(|url| url["node_index"] == node_index && url["attribute"] == "href")
            .and_then(|url| url.get("url").cloned())
            .unwrap_or(Value::Null);
        for declaration in rels {
            capture.agent_hints.push(json!({
                "mechanism": "dom_link_rel",
                "declaration": declaration,
                "url": href.clone(),
                "trust": "page-declared-untrusted",
            }));
        }
    }
}

fn dom_destination(value: &str, base_url: &str, allowed_origins: &[String]) -> (&'static str, Value) {
    let Ok(base) = Url::parse(base_url) else {
        return ("unsupported", Value::Null);
    };
    let Ok(parsed) = base.join(value) else {
        return ("unsupported", Value::Null);
    };
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return ("unsupported", Value::Null);
    }
    match allowed_url(Some(parsed.as_str()), allowed_origins) {
        Some(allowed) => ("approved", Value::String(allowed.url)),
        None => ("outside_policy", Value::Null),
    }
}

fn walk_frames(root: &Map<String, Value>) -> Vec<&Map<String, Value>> {
    let mut pending = vec![root];
    let mut ordered = Vec::new();
    while let Some(tree) = pending.pop() {
        if let Some(children) = tree.get("childFrames").and_then(Value::as_array) {
            for child in children.iter().rev() {
                if let Some(child) = child.as_object() {
                    pending.push(child);
                }
            }
        }
        ordered.push(tree);
    }
    ordered
}

fn exclude(
    completeness: Option<&mut &mut CdpCaptureCompleteness>,
    section: &'static str,
    reason: &'static str,
) {
    if let Some(completeness) = completeness {
        completeness.exclude(section, reason, Some(1));
    }
}

fn number_array(value: Option<&Value>) -> Vec<f64> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(finite_f64).collect())
        .unwrap_or_default()
}

fn indexed_string(strings: &[String], index: Option<&Value>) -> String {
    indexed_at(strings, index.and_then(finite_f64))
}

fn indexed_at(strings: &[String], index: Option<f64>) -> String {
    let Some(index) = index else {
        return String::new();
    };
    if !index.is_finite() || index < 0.0 {
        return String::new();
    }
    strings
        .get(index.trunc() as usize)
        .cloned()
        .unwrap_or_default()
}

fn utf8_len(value: Option<&Value>) -> i64 {
    value.and_then(Value::as_str).map(|text| text.len() as i64).unwrap_or(0)
}
