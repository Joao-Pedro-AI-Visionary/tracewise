use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracewise_domain::canonical_sha256;
use tracewise_domain::evidence::{
    create_evidence, Evidence, EvidenceAuthority, EvidenceConfidence, EvidenceObservation,
    EvidenceProvider,
};

use crate::error::WebError;

const CDP_BROWSER_PROVIDER_ID: &str = "rea-cdp-browser";
const CDP_BROWSER_PROVIDER_NAME: &str = "REA Chrome DevTools Protocol observation provider";
const CDP_BROWSER_PROVIDER_VERSION: &str = "2";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CaptureSnapshot {
    pub inspection: Value,
    #[serde(default)]
    pub webmcp: Option<Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CompareWebCapturesInput {
    pub before: CaptureSnapshot,
    pub after: CaptureSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebCaptureChange {
    pub identity: String,
    pub change: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebCaptureDimension {
    pub status: String,
    pub total_changes: usize,
    pub changes: Vec<WebCaptureChange>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebCaptureTarget {
    pub target_id: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebCaptureDimensions {
    pub dom_structure: WebCaptureDimension,
    pub scripts: WebCaptureDimension,
    pub resources: WebCaptureDimension,
    pub network: WebCaptureDimension,
    pub metadata: WebCaptureDimension,
    pub webmcp: WebCaptureDimension,
    pub accessibility: WebCaptureDimension,
    pub storage: WebCaptureDimension,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebCaptureDiff {
    pub overall_status: String,
    pub before_target: WebCaptureTarget,
    pub after_target: WebCaptureTarget,
    pub dimensions: WebCaptureDimensions,
    pub limitations: Vec<String>,
}

fn limitations() -> Vec<String> {
    vec![
        "A changed status proves an observed difference; an unknown status means absence could not be established from capture completeness.".to_string(),
        "Network comparison covers only activity observed after each CDP attachment.".to_string(),
        "Accessibility roles, ignored state, text, and hierarchy are compared only when the accessibility tree was fully captured and text capture was selected and not truncated.".to_string(),
        "Storage key inventories are compared only when selected and complete; usage and quota are compared only when reported. Redacted content is compared through complete SHA-256 fingerprints.".to_string(),
    ]
}

fn get_incomplete_sections(completeness: &Value) -> HashSet<String> {
    let mut set = HashSet::new();
    for key in &[
        "policy_filtered_sections",
        "attach_limited_sections",
        "truncated_sections",
        "unavailable_sections",
    ] {
        if let Some(arr) = completeness.get(key).and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    set.insert(s.to_string());
                }
            }
        }
    }
    set
}

fn sections_complete(inspection: &Value, sections: &[&str]) -> bool {
    let completeness = match inspection.get("completeness") {
        Some(c) => c,
        None => return false,
    };
    let incomplete = get_incomplete_sections(completeness);
    sections.iter().all(|s| !incomplete.contains(*s))
}

fn compare_identities(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> Vec<WebCaptureChange> {
    let mut changes = Vec::new();
    for (identity, fingerprint) in before {
        match after.get(identity) {
            None => changes.push(WebCaptureChange {
                identity: identity.clone(),
                change: "removed".to_string(),
            }),
            Some(next) if next != fingerprint => changes.push(WebCaptureChange {
                identity: identity.clone(),
                change: "modified".to_string(),
            }),
            _ => {}
        }
    }
    for identity in after.keys() {
        if !before.contains_key(identity) {
            changes.push(WebCaptureChange {
                identity: identity.clone(),
                change: "added".to_string(),
            });
        }
    }
    changes.sort_by(|left, right| {
        left.identity
            .cmp(&right.identity)
            .then_with(|| left.change.cmp(&right.change))
    });
    changes
}

fn compare_dimension(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
    complete: bool,
    reason: &str,
) -> WebCaptureDimension {
    let all: Vec<WebCaptureChange> = compare_identities(before, after)
        .into_iter()
        .filter(|c| complete || c.change == "modified")
        .collect();

    if !all.is_empty() {
        WebCaptureDimension {
            status: "changed".to_string(),
            total_changes: all.len(),
            changes: all,
            reason: None,
        }
    } else if complete {
        WebCaptureDimension {
            status: "unchanged".to_string(),
            total_changes: 0,
            changes: Vec::new(),
            reason: None,
        }
    } else {
        WebCaptureDimension {
            status: "unknown".to_string(),
            total_changes: 0,
            changes: Vec::new(),
            reason: Some(reason.to_string()),
        }
    }
}

fn dom_dimension(before: &Value, after: &Value) -> Result<WebCaptureDimension, WebError> {
    let proj = |inspection: &Value| -> Result<String, WebError> {
        let mut frames: Vec<Value> = inspection
            .get("frames")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|f| {
                json!({
                    "url": f.get("url").unwrap_or(&Value::Null),
                    "origin": f.get("origin").unwrap_or(&Value::Null),
                })
            })
            .collect();

        frames.sort_by(|left, right| {
            let left_url = left.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let right_url = right.get("url").and_then(|v| v.as_str()).unwrap_or("");
            left_url
                .cmp(right_url)
                .then_with(|| {
                    let left_orig = left.get("origin").and_then(|v| v.as_str()).unwrap_or("");
                    let right_orig = right.get("origin").and_then(|v| v.as_str()).unwrap_or("");
                    left_orig.cmp(right_orig)
                })
                .then_with(|| {
                    let left_is_not_null =
                        if left.get("origin").is_some_and(|v| !v.is_null()) {
                            1
                        } else {
                            0
                        };
                    let right_is_not_null =
                        if right.get("origin").is_some_and(|v| !v.is_null()) {
                            1
                        } else {
                            0
                        };
                    left_is_not_null.cmp(&right_is_not_null)
                })
        });

        let nodes: Vec<Value> = inspection
            .get("dom")
            .and_then(|d| d.get("nodes"))
            .and_then(|n| n.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|mut node| {
                if let Some(obj) = node.as_object_mut() {
                    obj.remove("index");
                }
                node
            })
            .collect();

        let val = json!({
            "frames": frames,
            "nodes": nodes,
        });
        canonical_sha256(&val).map_err(WebError::from)
    };

    let before_hash = proj(before)?;
    let after_hash = proj(after)?;

    let mut before_map = BTreeMap::new();
    before_map.insert("document".to_string(), before_hash);

    let mut after_map = BTreeMap::new();
    after_map.insert("document".to_string(), after_hash);

    let complete = sections_complete(before, &["frames", "dom"])
        && sections_complete(after, &["frames", "dom"]);

    Ok(compare_dimension(
        &before_map,
        &after_map,
        complete,
        "DOM or frame capture was incomplete in at least one observation.",
    ))
}

fn scripts_dimension(before: &Value, after: &Value) -> Result<WebCaptureDimension, WebError> {
    let script_map = |inspection: &Value| -> Result<BTreeMap<String, String>, WebError> {
        let mut map = BTreeMap::new();
        let items = inspection
            .get("scripts")
            .and_then(|s| s.get("items"))
            .and_then(|i| i.as_array());

        if let Some(items) = items {
            for item in items {
                let script_key = item
                    .get("script_key")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let proj = json!({
                    "script_key": item.get("script_key"),
                    "url": item.get("url"),
                    "cdp_hash": item.get("cdp_hash"),
                    "length": item.get("length"),
                    "is_module": item.get("is_module"),
                    "language": item.get("language"),
                    "source_map_url": item.get("source_map_url"),
                });
                let digest = canonical_sha256(&proj).map_err(WebError::from)?;
                map.insert(script_key, digest);
            }
        }
        Ok(map)
    };

    let before_map = script_map(before)?;
    let after_map = script_map(after)?;
    let complete = sections_complete(before, &["scripts"]) && sections_complete(after, &["scripts"]);

    Ok(compare_dimension(
        &before_map,
        &after_map,
        complete,
        "Script inventory was incomplete in at least one observation.",
    ))
}

fn resources_dimension(before: &Value, after: &Value) -> Result<WebCaptureDimension, WebError> {
    let resource_map = |inspection: &Value| -> Result<BTreeMap<String, String>, WebError> {
        let mut map = BTreeMap::new();
        let items = inspection.get("resources").and_then(|r| r.as_array());
        if let Some(items) = items {
            for item in items {
                let key = item
                    .get("resource_key")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let digest = canonical_sha256(item).map_err(WebError::from)?;
                map.insert(key, digest);
            }
        }
        Ok(map)
    };

    let before_map = resource_map(before)?;
    let after_map = resource_map(after)?;
    let complete = sections_complete(before, &["resources"]) && sections_complete(after, &["resources"]);

    Ok(compare_dimension(
        &before_map,
        &after_map,
        complete,
        "Resource inventory was incomplete in at least one observation.",
    ))
}

#[derive(Debug, Clone, Copy)]
struct BodyShapeSources {
    request: bool,
    response: bool,
}

fn body_shapes_selected(inspection: &Value) -> bool {
    let excluded_not_approved = inspection
        .get("completeness")
        .and_then(|c| c.get("excluded"))
        .and_then(|e| e.as_array())
        .is_some_and(|arr| {
            arr.iter().any(|e| {
                e.get("section").and_then(|v| v.as_str()) == Some("json_body_shapes")
                    && e.get("reason").and_then(|v| v.as_str()) == Some("not_approved")
            })
        });

    if excluded_not_approved {
        return false;
    }

    let requests = inspection
        .get("network")
        .and_then(|n| n.get("requests"))
        .and_then(|r| r.as_array());

    match requests {
        None => true,
        Some(reqs) if reqs.is_empty() => true,
        Some(reqs) => reqs.iter().any(|r| {
            r.get("body_shapes")
                .and_then(|b| b.get("status"))
                .and_then(|s| s.as_str())
                != Some("not_approved")
        }),
    }
}

fn network_identity(req: &Value) -> Result<String, WebError> {
    let id_val = json!({
        "method": req.get("method"),
        "url": req.get("url"),
        "resource_type": req.get("resource_type"),
    });
    let digest = canonical_sha256(&id_val).map_err(WebError::from)?;
    Ok(format!("net_{digest}"))
}

fn network_dimension(before: &Value, after: &Value) -> Result<WebCaptureDimension, WebError> {
    let selected = body_shapes_selected(before) && body_shapes_selected(after);
    let mut sources: BTreeMap<String, BodyShapeSources> = BTreeMap::new();

    if selected {
        let observed_sources = |inspection: &Value| -> Result<BTreeMap<String, BodyShapeSources>, WebError> {
            let mut result: BTreeMap<String, BodyShapeSources> = BTreeMap::new();
            if let Some(reqs) = inspection
                .get("network")
                .and_then(|n| n.get("requests"))
                .and_then(|r| r.as_array())
            {
                for req in reqs {
                    let identity = network_identity(req)?;
                    let prev = result.get(&identity).copied();
                    let has_req_shape = req
                        .get("body_shapes")
                        .and_then(|b| b.get("request"))
                        .is_some_and(|v| !v.is_null());
                    let has_resp_shape = req
                        .get("body_shapes")
                        .and_then(|b| b.get("response"))
                        .is_some_and(|v| !v.is_null());

                    result.insert(
                        identity,
                        BodyShapeSources {
                            request: prev.is_none_or(|p| p.request) && has_req_shape,
                            response: prev.is_none_or(|p| p.response) && has_resp_shape,
                        },
                    );
                }
            }
            Ok(result)
        };

        let left = observed_sources(before)?;
        let right = observed_sources(after)?;

        for (identity, coverage) in left {
            let next = right.get(&identity);
            sources.insert(
                identity,
                BodyShapeSources {
                    request: coverage.request && next.is_some_and(|n| n.request),
                    response: coverage.response && next.is_some_and(|n| n.response),
                },
            );
        }
    }

    let shapes_complete = !selected || [before, after].iter().all(|inspection| {
        sections_complete(inspection, &["json_body_shapes"])
            && inspection
                .get("network")
                .and_then(|n| n.get("requests"))
                .and_then(|r| r.as_array())
                .is_none_or(|reqs| {
                    reqs.iter().all(|r| {
                        r.get("body_shapes")
                            .and_then(|b| b.get("status"))
                            .and_then(|s| s.as_str())
                            == Some("included")
                    })
                })
    });

    let network_map = |inspection: &Value| -> Result<BTreeMap<String, String>, WebError> {
        let mut grouped: BTreeMap<String, Vec<Value>> = BTreeMap::new();
        if let Some(reqs) = inspection
            .get("network")
            .and_then(|n| n.get("requests"))
            .and_then(|r| r.as_array())
        {
            for req in reqs {
                let identity = network_identity(req)?;
                let shapes = sources.get(&identity);

                let redirects: Vec<Value> = req
                    .get("redirects")
                    .and_then(|r| r.as_array())
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|mut r| {
                        if let Some(obj) = r.as_object_mut() {
                            obj.remove("request_timestamp");
                            obj.remove("redirect_event_timestamp");
                        }
                        r
                    })
                    .collect();

                let mut val_obj = serde_json::Map::new();
                if let Some(s) = req.get("status") {
                    val_obj.insert("status".to_string(), s.clone());
                }
                if let Some(m) = req.get("mime_type") {
                    val_obj.insert("mime_type".to_string(), m.clone());
                }
                if let Some(e) = req.get("encoded_data_length") {
                    val_obj.insert("encoded_data_length".to_string(), e.clone());
                }
                val_obj.insert("redirects".to_string(), Value::Array(redirects));
                if let Some(i) = req.get("initiator") {
                    val_obj.insert("initiator".to_string(), i.clone());
                }

                if shapes.is_some_and(|s| s.request) {
                    if let Some(rs) = req.get("body_shapes").and_then(|b| b.get("request")) {
                        val_obj.insert("request_shape".to_string(), rs.clone());
                    }
                }
                if shapes.is_some_and(|s| s.response) {
                    if let Some(rs) = req.get("body_shapes").and_then(|b| b.get("response")) {
                        val_obj.insert("response_shape".to_string(), rs.clone());
                    }
                }

                grouped.entry(identity).or_default().push(Value::Object(val_obj));
            }
        }

        let mut res = BTreeMap::new();
        for (identity, values) in grouped {
            let mut hashes = Vec::new();
            for v in values {
                hashes.push(canonical_sha256(&v).map_err(WebError::from)?);
            }
            hashes.sort();
            let final_digest = canonical_sha256(&hashes).map_err(WebError::from)?;
            res.insert(identity, final_digest);
        }
        Ok(res)
    };

    let before_map = network_map(before)?;
    let after_map = network_map(after)?;

    let complete = sections_complete(before, &["network_requests"])
        && sections_complete(after, &["network_requests"])
        && shapes_complete;

    Ok(compare_dimension(
        &before_map,
        &after_map,
        complete,
        "Network capture or selected JSON body-shape coverage is attach-window limited, unavailable, or incomplete.",
    ))
}

fn metadata_dimension(before: &Value, after: &Value) -> Result<WebCaptureDimension, WebError> {
    let proj = |inspection: &Value| -> Result<String, WebError> {
        let meta = inspection.get("metadata").unwrap_or(&Value::Null);

        let mut responses: Vec<String> = Vec::new();
        if let Some(resps) = meta.get("responses").and_then(|r| r.as_array()) {
            for r in resps {
                let mut r_clone = r.clone();
                if let Some(obj) = r_clone.as_object_mut() {
                    obj.remove("request_id");
                }
                responses.push(canonical_sha256(&r_clone).map_err(WebError::from)?);
            }
        }
        responses.sort();

        let mut dom_urls: Vec<String> = Vec::new();
        if let Some(urls) = meta.get("dom_urls").and_then(|u| u.as_array()) {
            for u in urls {
                dom_urls.push(canonical_sha256(u).map_err(WebError::from)?);
            }
        }
        dom_urls.sort();

        let mut agent_hints: Vec<String> = Vec::new();
        if let Some(hints) = meta.get("agent_hints").and_then(|h| h.as_array()) {
            for h in hints {
                agent_hints.push(canonical_sha256(h).map_err(WebError::from)?);
            }
        }
        agent_hints.sort();

        let excluded_dom_urls = meta
            .get("excluded_dom_urls")
            .cloned()
            .unwrap_or(Value::Array(Vec::new()));
        let headers_allowlisted = meta
            .get("headers_allowlisted")
            .cloned()
            .unwrap_or(Value::Array(Vec::new()));

        let val = json!({
            "responses": responses,
            "dom_urls": dom_urls,
            "agent_hints": agent_hints,
            "excluded_dom_urls": excluded_dom_urls,
            "headers_allowlisted": headers_allowlisted,
        });

        canonical_sha256(&val).map_err(WebError::from)
    };

    let before_hash = proj(before)?;
    let after_hash = proj(after)?;

    let mut before_map = BTreeMap::new();
    before_map.insert("metadata".to_string(), before_hash);

    let mut after_map = BTreeMap::new();
    after_map.insert("metadata".to_string(), after_hash);

    let complete = sections_complete(before, &["metadata"]) && sections_complete(after, &["metadata"]);

    Ok(compare_dimension(
        &before_map,
        &after_map,
        complete,
        "Safe metadata capture was incomplete in at least one observation.",
    ))
}

fn webmcp_dimension(before_webmcp: Option<&Value>, after_webmcp: Option<&Value>) -> Result<WebCaptureDimension, WebError> {
    let webmcp_map = |disc: Option<&Value>| -> Result<BTreeMap<String, String>, WebError> {
        let mut map = BTreeMap::new();
        if let Some(disc) = disc {
            if let Some(items) = disc
                .get("tools")
                .and_then(|t| t.get("items"))
                .and_then(|i| i.as_array())
            {
                for item in items {
                    let key = item
                        .get("tool_key")
                        .and_then(|k| k.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let digest = canonical_sha256(item).map_err(WebError::from)?;
                    map.insert(key, digest);
                }
            }
        }
        Ok(map)
    };

    let webmcp_complete = |disc: Option<&Value>| -> bool {
        match disc {
            Some(disc) => {
                let status_available = disc.get("status").and_then(|s| s.as_str()) == Some("available");
                let incomplete = disc
                    .get("completeness")
                    .map(get_incomplete_sections)
                    .unwrap_or_default();
                status_available && !incomplete.contains("webmcp_tools")
            }
            None => false,
        }
    };

    let before_map = webmcp_map(before_webmcp)?;
    let after_map = webmcp_map(after_webmcp)?;

    let complete = webmcp_complete(before_webmcp) && webmcp_complete(after_webmcp);

    Ok(compare_dimension(
        &before_map,
        &after_map,
        complete,
        "WebMCP discovery was unavailable or incomplete in at least one capture.",
    ))
}

fn accessibility_dimension(before: &Value, after: &Value) -> Result<WebCaptureDimension, WebError> {
    let access_comparable = |inspection: &Value| {
        let access = inspection.get("accessibility").unwrap_or(&Value::Null);
        let tc = access.get("text_capture").unwrap_or(&Value::Null);
        let text = tc.get("status").and_then(|s| s.as_str()) == Some("included")
            && tc.get("excluded_fields").and_then(|f| f.as_u64()) == Some(0);

        let total_nodes = access.get("total_nodes").and_then(|t| t.as_u64());
        let nodes_len = access.get("nodes").and_then(|n| n.as_array()).map(|a| a.len() as u64);
        let nodes = total_nodes.is_some() && total_nodes == nodes_len;

        let complete = text && nodes && sections_complete(inspection, &["accessibility"]);
        (text, nodes, complete)
    };

    let (before_text, before_nodes, before_complete) = access_comparable(before);
    let (after_text, after_nodes, after_complete) = access_comparable(after);

    let text_comparable = before_text && after_text;
    let nodes_comparable = before_nodes && after_nodes;

    let proj = |inspection: &Value| -> Result<String, WebError> {
        let access = inspection.get("accessibility").unwrap_or(&Value::Null);
        let total_nodes = access.get("total_nodes").cloned().unwrap_or(Value::Null);

        if !nodes_comparable {
            let val = json!({ "total_nodes": total_nodes });
            return canonical_sha256(&val).map_err(WebError::from);
        }

        let nodes_arr = access
            .get("nodes")
            .and_then(|n| n.as_array())
            .cloned()
            .unwrap_or_default();

        let mut node_indexes = BTreeMap::new();
        for (idx, node) in nodes_arr.iter().enumerate() {
            if let Some(id) = node.get("node_id").and_then(|v| v.as_str()) {
                node_indexes.insert(id.to_string(), idx as i64);
            }
        }

        let mut projected_nodes = Vec::new();
        for node in nodes_arr {
            let parent_index = match node.get("parent_id") {
                None => Value::Null,
                Some(v) if v.is_null() => Value::Null,
                Some(v) => {
                    let pid = v.as_str().unwrap_or_default();
                    json!(node_indexes.get(pid).copied().unwrap_or(-1))
                }
            };

            let mut node_obj = serde_json::Map::new();
            node_obj.insert("parent_index".to_string(), parent_index);
            if let Some(r) = node.get("role") {
                node_obj.insert("role".to_string(), r.clone());
            }
            if let Some(i) = node.get("ignored") {
                node_obj.insert("ignored".to_string(), i.clone());
            }
            if let Some(s) = node.get("states") {
                node_obj.insert("states".to_string(), s.clone());
            }
            if text_comparable {
                if let Some(n) = node.get("name") {
                    node_obj.insert("name".to_string(), n.clone());
                }
                if let Some(d) = node.get("description") {
                    node_obj.insert("description".to_string(), d.clone());
                }
            }
            projected_nodes.push(Value::Object(node_obj));
        }

        let val = json!({
            "total_nodes": total_nodes,
            "nodes": projected_nodes,
        });
        canonical_sha256(&val).map_err(WebError::from)
    };

    let before_hash = proj(before)?;
    let after_hash = proj(after)?;

    let mut before_map = BTreeMap::new();
    before_map.insert("accessibility_tree".to_string(), before_hash);

    let mut after_map = BTreeMap::new();
    after_map.insert("accessibility_tree".to_string(), after_hash);

    let complete = before_complete && after_complete;

    Ok(compare_dimension(
        &before_map,
        &after_map,
        complete,
        "Accessibility tree or text capture was incomplete in at least one observation.",
    ))
}

fn storage_dimension(before: &Value, after: &Value) -> Result<WebCaptureDimension, WebError> {
    let storage_keys_comparable = |inspection: &Value| sections_complete(inspection, &["storage_keys"]);

    let before_keys_complete = storage_keys_comparable(before);
    let after_keys_complete = storage_keys_comparable(after);
    let keys_complete = before_keys_complete && after_keys_complete;

    let before_storage = before.get("storage").unwrap_or(&Value::Null);
    let after_storage = after.get("storage").unwrap_or(&Value::Null);

    let usage_complete = before_storage.get("usage_bytes").is_some_and(|v| !v.is_null())
        && after_storage.get("usage_bytes").is_some_and(|v| !v.is_null())
        && before_storage.get("quota_bytes").is_some_and(|v| !v.is_null())
        && after_storage.get("quota_bytes").is_some_and(|v| !v.is_null());

    let complete_storage_fingerprints = |storage: &Value| -> BTreeMap<String, Value> {
        let mut map = BTreeMap::new();
        if let Some(fps) = storage.get("content_fingerprints").and_then(|f| f.as_array()) {
            for fp in fps {
                if fp.get("complete").and_then(|c| c.as_bool()) == Some(true) {
                    let scope = fp.get("scope").and_then(|s| s.as_str()).unwrap_or("");
                    let id_sha = fp.get("identity_sha256").and_then(|s| s.as_str()).unwrap_or("");
                    let identity = format!("{scope}:{id_sha}");
                    let val_sha = fp.get("value_sha256").cloned().unwrap_or(Value::Null);
                    map.insert(identity, val_sha);
                }
            }
        }
        map
    };

    let before_complete_fps = complete_storage_fingerprints(before_storage);
    let after_complete_fps = complete_storage_fingerprints(after_storage);

    let before_fps_complete = before_storage
        .get("fingerprints_complete")
        .and_then(|b| b.as_bool())
        == Some(true);
    let after_fps_complete = after_storage
        .get("fingerprints_complete")
        .and_then(|b| b.as_bool())
        == Some(true);

    let comparable_fingerprints: HashSet<String> = if before_fps_complete && after_fps_complete {
        before_complete_fps
            .keys()
            .chain(after_complete_fps.keys())
            .cloned()
            .collect()
    } else {
        before_complete_fps
            .keys()
            .filter(|k| after_complete_fps.contains_key(*k))
            .cloned()
            .collect()
    };

    let storage_map = |storage: &Value| -> Result<BTreeMap<String, String>, WebError> {
        let mut map = BTreeMap::new();

        let mut summary_obj = serde_json::Map::new();
        if let Some(orig) = storage.get("origin") {
            summary_obj.insert("origin".to_string(), orig.clone());
        }
        if let Some(red) = storage.get("values_redacted") {
            summary_obj.insert("values_redacted".to_string(), red.clone());
        }
        if usage_complete {
            if let Some(u) = storage.get("usage_bytes") {
                summary_obj.insert("usage_bytes".to_string(), u.clone());
            }
            if let Some(q) = storage.get("quota_bytes") {
                summary_obj.insert("quota_bytes".to_string(), q.clone());
            }
        }
        let summary_digest = canonical_sha256(&Value::Object(summary_obj)).map_err(WebError::from)?;
        map.insert("storage:summary".to_string(), summary_digest);

        if keys_complete {
            let mut add = |kind: &str, field: &str| -> Result<(), WebError> {
                if let Some(arr) = storage.get(field).and_then(|a| a.as_array()) {
                    for key_val in arr {
                        let key_str = key_val.as_str().unwrap_or_default();
                        let digest = canonical_sha256(&key_str).map_err(WebError::from)?;
                        map.insert(format!("storage:{kind}:{key_str}"), digest);
                    }
                }
                Ok(())
            };
            add("local_storage", "local_storage_keys")?;
            add("session_storage", "session_storage_keys")?;
            add("indexed_db", "indexed_db_names")?;
            add("cache", "cache_names")?;

            if let Some(fps) = storage.get("content_fingerprints").and_then(|f| f.as_array()) {
                for fp in fps {
                    let scope = fp.get("scope").and_then(|s| s.as_str()).unwrap_or("");
                    let id_sha = fp.get("identity_sha256").and_then(|s| s.as_str()).unwrap_or("");
                    let identity = format!("{scope}:{id_sha}");
                    if comparable_fingerprints.contains(&identity) {
                        let val_sha = fp.get("value_sha256").cloned().unwrap_or(Value::Null);
                        let digest = canonical_sha256(&val_sha).map_err(WebError::from)?;
                        map.insert(format!("storage:content:{identity}"), digest);
                    }
                }
            }
        }

        Ok(map)
    };

    let before_map = storage_map(before_storage)?;
    let after_map = storage_map(after_storage)?;

    let complete = keys_complete && usage_complete && before_fps_complete && after_fps_complete;

    Ok(compare_dimension(
        &before_map,
        &after_map,
        complete,
        "Storage fingerprints, inventories, usage, or quota were unavailable or truncated in at least one observation.",
    ))
}

pub fn compare_web_captures(input: CompareWebCapturesInput) -> Result<Evidence, WebError> {
    let before = &input.before.inspection;
    let after = &input.after.inspection;

    let dom_dim = dom_dimension(before, after)?;
    let scripts_dim = scripts_dimension(before, after)?;
    let resources_dim = resources_dimension(before, after)?;
    let network_dim = network_dimension(before, after)?;
    let metadata_dim = metadata_dimension(before, after)?;
    let webmcp_dim = webmcp_dimension(input.before.webmcp.as_ref(), input.after.webmcp.as_ref())?;
    let access_dim = accessibility_dimension(before, after)?;
    let storage_dim = storage_dimension(before, after)?;

    let statuses = [
        &dom_dim.status,
        &scripts_dim.status,
        &resources_dim.status,
        &network_dim.status,
        &metadata_dim.status,
        &webmcp_dim.status,
        &access_dim.status,
        &storage_dim.status,
    ];

    let overall_status = if statuses.iter().any(|s| *s == "changed") {
        "changed".to_string()
    } else if statuses.iter().any(|s| *s == "unknown") {
        "unknown".to_string()
    } else {
        "unchanged".to_string()
    };

    let before_target = WebCaptureTarget {
        target_id: before
            .get("target")
            .and_then(|t| t.get("target_id"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        url: before
            .get("target")
            .and_then(|t| t.get("url"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
    };

    let after_target = WebCaptureTarget {
        target_id: after
            .get("target")
            .and_then(|t| t.get("target_id"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        url: after
            .get("target")
            .and_then(|t| t.get("url"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
    };

    let dimensions = WebCaptureDimensions {
        dom_structure: dom_dim,
        scripts: scripts_dim,
        resources: resources_dim,
        network: network_dim,
        metadata: metadata_dim,
        webmcp: webmcp_dim,
        accessibility: access_dim,
        storage: storage_dim,
    };

    let normalized_result = WebCaptureDiff {
        overall_status,
        before_target,
        after_target,
        dimensions,
        limitations: limitations(),
    };

    let mut envelope_limitations = vec![
        "Artifact identity is unavailable for this observation.".to_string(),
    ];
    envelope_limitations.extend(limitations());

    let provider = EvidenceProvider {
        id: CDP_BROWSER_PROVIDER_ID.to_string(),
        name: CDP_BROWSER_PROVIDER_NAME.to_string(),
        version: Some(CDP_BROWSER_PROVIDER_VERSION.to_string()),
    };

    let parameters = json!({
        "before_target_id": before.get("target").and_then(|t| t.get("target_id")),
        "before_capture_ended_at": before.get("capture_window").and_then(|c| c.get("ended_at")),
        "after_target_id": after.get("target").and_then(|t| t.get("target_id")),
        "after_capture_ended_at": after.get("capture_window").and_then(|c| c.get("ended_at")),
    });

    let observation = EvidenceObservation {
        predicate_type: Some("rea.web-capture-diff".to_string()),
        operation: "compare_web_captures".to_string(),
        parameters,
        normalized_result: serde_json::to_value(normalized_result)?,
        raw_result: None,
        analysis_profile: None,
        confidence: Some(EvidenceConfidence::Observed),
        authority: Some(EvidenceAuthority::ExternalService),
        environment: None,
        limitations: Some(envelope_limitations),
        locations: Some(vec![]),
        evidence_links: Some(vec![]),
    };

    create_evidence(None, provider, observation).map_err(WebError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_web_captures_against_oracle() {
        let before_str =
            std::fs::read_to_string("/workspace/tracewise/fixtures/web/capture_before.json").unwrap();
        let after_str =
            std::fs::read_to_string("/workspace/tracewise/fixtures/web/capture_after.json").unwrap();

        let before_val: Value = serde_json::from_str(&before_str).unwrap();
        let after_val: Value = serde_json::from_str(&after_str).unwrap();

        let ev = compare_web_captures(CompareWebCapturesInput {
            before: CaptureSnapshot {
                inspection: before_val,
                webmcp: None,
            },
            after: CaptureSnapshot {
                inspection: after_val,
                webmcp: None,
            },
        })
        .unwrap();

        let oracle_str = std::fs::read_to_string(
            "/workspace/tracewise/fixtures/web/oracle_compare_web_captures.json",
        )
        .unwrap();
        let oracle: Value = serde_json::from_str(&oracle_str).unwrap();
        let oracle_sc = &oracle["structuredContent"];

        let ev_val = serde_json::to_value(&ev).unwrap();

        assert_eq!(ev_val["evidence_id"], oracle_sc["evidence_id"]);
        assert_eq!(ev_val["parameters"], oracle_sc["parameters"]);
        assert_eq!(ev_val["normalized_result"], oracle_sc["normalized_result"]);
        assert_eq!(ev_val, *oracle_sc);
    }
}
