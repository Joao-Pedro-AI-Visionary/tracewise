//! Replay cases from redacted capture evidence.
//!
//! The capture is read only after `inspect_web_network_capture` has removed
//! credential headers. Samples that do not match an operation, or that lack a
//! JSON body the operation requires, are left out of the fixture.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};
use tracewise_domain::evidence::Evidence;

use crate::api_client_model::OpMeta;
use crate::error::WebError;

pub(crate) fn samples_from_evidence(
    metas: &[OpMeta],
    evidence: &Evidence,
) -> Result<Vec<Value>, WebError> {
    let records = evidence
        .normalized_result
        .get("records")
        .and_then(|value| value.as_array())
        .ok_or_else(|| {
            WebError::Format(format!(
                "Evidence {} has no capture records to replay.",
                evidence.evidence_id
            ))
        })?;
    let mut samples = Vec::new();
    for record in records {
        let Some(reported) = record.get("reported") else {
            continue;
        };
        if reported.is_null() {
            continue;
        }
        if let Some(sample) = sample_from_reported(metas, reported)? {
            samples.push(sample);
        }
    }
    Ok(samples)
}

fn sample_from_reported(metas: &[OpMeta], reported: &Value) -> Result<Option<Value>, WebError> {
    let Some(request) = reported.get("request") else {
        return Ok(None);
    };
    let Some(response) = reported.get("response") else {
        return Ok(None);
    };
    let method = request
        .get("method")
        .and_then(|value| value.as_str())
        .unwrap_or("GET")
        .to_ascii_uppercase();
    let Some(url) = request_url(request)? else {
        return Ok(None);
    };
    let Ok(parsed) = url::Url::parse(&url) else {
        return Ok(None);
    };
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Ok(None);
    }
    let path = parsed.path().to_string();
    let Some(meta) = best_match(metas, &method, &path) else {
        return Ok(None);
    };
    let Some(raw_params) = match_template(&meta.path, &path) else {
        return Ok(None);
    };
    let status = response
        .get("status")
        .and_then(|value| value.as_u64())
        .or_else(|| response.get("status_code").and_then(|value| value.as_u64()))
        .unwrap_or(0);
    if status == 0 || status > u64::from(u16::MAX) {
        return Ok(None);
    }
    let status = status as u16;
    if !meta.statuses.is_empty() && !meta.statuses.contains(&status) {
        return Ok(None);
    }

    let mut path_values = Map::new();
    for (name, raw) in &raw_params {
        let kind = meta
            .path_types
            .iter()
            .find(|(param, _)| param == name)
            .map(|(_, kind)| kind.as_str())
            .unwrap_or("string");
        path_values.insert(name.clone(), coerce(raw, kind));
    }
    for (name, _) in &meta.path_types {
        if !path_values.contains_key(name) {
            return Ok(None);
        }
    }

    let query_raw = query_pairs(request, &parsed);
    let mut query = Map::new();
    let mut query_pairs_json = Vec::new();
    for (name, kind, required) in &meta.query_types {
        let Some(raw) = query_raw.get(name) else {
            if *required {
                return Ok(None);
            }
            continue;
        };
        let value = coerce(raw, kind);
        query_pairs_json.push(json!([name, encode_query(&value)]));
        query.insert(name.clone(), value);
    }

    let body = json_body(request.get("postData")).or_else(|| json_body(request.get("content")));
    if meta.has_json_body && body.is_none() {
        return Ok(None);
    }
    if meta.body_required && body.is_none() {
        return Ok(None);
    }
    let response_body = json_body(response.get("content"));
    let Some(response_body) = response_body else {
        return Ok(None);
    };

    Ok(Some(json!({
        "operation_id": meta.operation_id,
        "method": meta.method,
        "concrete_path": path,
        "base_url": parsed.origin().ascii_serialization(),
        "status": status,
        "path_params": Value::Object(path_values),
        "query": Value::Object(query),
        "query_pairs": query_pairs_json,
        "body": body.unwrap_or(Value::Null),
        "response": response_body,
    })))
}

fn best_match<'a>(metas: &'a [OpMeta], method: &str, path: &str) -> Option<&'a OpMeta> {
    let mut best: Option<&OpMeta> = None;
    let mut best_score = 0usize;
    for meta in metas {
        if meta.method != method {
            continue;
        }
        if match_template(&meta.path, path).is_none() {
            continue;
        }
        let score = specificity(&meta.path);
        if best.is_none() || score > best_score {
            best = Some(meta);
            best_score = score;
        }
    }
    best
}

fn specificity(template: &str) -> usize {
    template
        .split('/')
        .filter(|segment| !segment.is_empty() && !segment.starts_with('{'))
        .count()
}

pub(crate) fn match_template(template: &str, path: &str) -> Option<Vec<(String, String)>> {
    let left: Vec<&str> = template.split('/').collect();
    let right: Vec<&str> = path.split('/').collect();
    if left.len() != right.len() {
        return None;
    }
    let mut params = Vec::new();
    for (pattern, actual) in left.into_iter().zip(right) {
        if let Some(name) = pattern
            .strip_prefix('{')
            .and_then(|rest| rest.strip_suffix('}'))
        {
            if actual.is_empty() {
                return None;
            }
            params.push((name.to_string(), actual.to_string()));
        } else if pattern != actual {
            return None;
        }
    }
    Some(params)
}

fn query_pairs(request: &Value, parsed: &url::Url) -> BTreeMap<String, String> {
    let mut pairs = BTreeMap::new();
    if let Some(items) = request.get("queryString").and_then(|value| value.as_array()) {
        if !items.is_empty() {
            for item in items {
                let Some(name) = item.get("name").and_then(|value| value.as_str()) else {
                    continue;
                };
                let Some(value) = item.get("value").and_then(scalar_string) else {
                    continue;
                };
                pairs.insert(name.to_string(), value);
            }
            return pairs;
        }
    }
    for (name, value) in parsed.query_pairs() {
        pairs.insert(name.into_owned(), value.into_owned());
    }
    pairs
}

fn json_body(container: Option<&Value>) -> Option<Value> {
    let text = container?.get("text").and_then(scalar_string)?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    serde_json::from_str(trimmed).ok()
}

fn coerce(raw: &str, kind: &str) -> Value {
    match kind {
        "integer" => raw
            .parse::<i64>()
            .map(|value| json!(value))
            .or_else(|_| raw.parse::<u64>().map(|value| json!(value)))
            .unwrap_or_else(|_| json!(raw)),
        "number" => raw
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number)
            .unwrap_or_else(|| json!(raw)),
        "boolean" => match raw {
            "true" => json!(true),
            "false" => json!(false),
            _ => json!(raw),
        },
        _ => json!(raw),
    }
}

fn encode_query(value: &Value) -> String {
    match value {
        Value::Bool(flag) => {
            if *flag {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.clone(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

fn request_url(request: &Value) -> Result<Option<String>, WebError> {
    if let Some(url) = request.get("url").and_then(|value| value.as_str()) {
        if url.is_empty() {
            return Ok(None);
        }
        return Ok(Some(url.to_string()));
    }
    let Some(path) = request.get("path").and_then(|value| value.as_str()) else {
        return Ok(None);
    };
    let scheme = request
        .get("scheme")
        .and_then(|value| value.as_str())
        .unwrap_or("http");
    let host = request
        .get("host")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if host.is_empty() {
        return Ok(None);
    }
    let port = request.get("port").and_then(|value| value.as_u64());
    let default_port =
        (scheme == "http" && port == Some(80)) || (scheme == "https" && port == Some(443));
    let port_text = match port {
        Some(port) if !default_port => format!(":{port}"),
        _ => String::new(),
    };
    let path = if path.starts_with('/') || path.starts_with('?') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    Ok(Some(format!("{scheme}://{host}{port_text}{path}")))
}

fn scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}
