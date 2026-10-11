//! Untrusted CDP value readers (port of the helpers in REA browser/CdpCaptureValues.ts).

use serde_json::{Map, Value};

use crate::browser_observation::{allowed_sanitized_url, sanitize_browser_url, SanitizedBrowserUrl};

pub fn record(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

pub fn records(value: &Value) -> Vec<&Map<String, Value>> {
    value
        .as_array()
        .map(|items| items.iter().filter_map(Value::as_object).collect())
        .unwrap_or_default()
}

pub fn cdp_str(value: &Value) -> Option<&str> {
    value.as_str()
}

pub fn finite_f64(value: &Value) -> Option<f64> {
    value.as_f64().filter(|number| number.is_finite()).or_else(|| {
        value
            .as_i64()
            .map(|number| number as f64)
            .or_else(|| value.as_u64().filter(|number| *number <= i64::MAX as u64).map(|number| number as f64))
    })
}

/// Whole JSON number that fits in `i64`, rejecting fractional values.
pub fn safe_integer(value: &Value) -> Option<i64> {
    if let Some(number) = value.as_i64() {
        return Some(number);
    }
    value.as_u64().and_then(|number| i64::try_from(number).ok())
}

pub fn json_number(number: f64) -> Value {
    if number.is_finite() && number.fract() == 0.0 && number.abs() <= i64::MAX as f64 {
        Value::from(number as i64)
    } else if let Some(number) = serde_json::Number::from_f64(number) {
        Value::Number(number)
    } else {
        Value::Null
    }
}

/// `Math.max(0, Math.trunc(n))`, or null when the value is not a finite number.
pub fn integer_or_null(value: &Value) -> Value {
    match finite_f64(value) {
        Some(number) => Value::from(number.trunc().max(0.0) as i64),
        None => Value::Null,
    }
}

pub fn is_http_url(value: &str) -> bool {
    url::Url::parse(value)
        .ok()
        .is_some_and(|url| url.scheme() == "http" || url.scheme() == "https")
}

pub fn allowed_url(value: Option<&str>, allowed_origins: &[String]) -> Option<SanitizedBrowserUrl> {
    allowed_sanitized_url(value, allowed_origins)
}

pub fn exclusion_reason_for_url(value: Option<&str>) -> &'static str {
    match value {
        None | Some("") => "unattributed_origin",
        Some(url) if is_http_url(url) => "disallowed_origin",
        Some(_) => "unsupported_url",
    }
}

pub fn execution_context_key(value: &Value) -> Option<String> {
    let number = finite_f64(value)?;
    if number.fract() != 0.0 || !(0.0..=(i64::MAX as f64)).contains(&number) {
        return None;
    }
    Some((number as i64).to_string())
}

/// Credential headers are dropped before any metadata allowlist reads them.
pub fn is_credential_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "cookie" | "set-cookie" | "authorization" | "proxy-authorization"
    )
}

/// Header map with cookies and Authorization removed. Values are not rewritten
/// into another field; they are absent from captured network data.
pub fn redact_credential_headers(headers: &Map<String, Value>) -> Map<String, Value> {
    headers
        .iter()
        .filter(|(name, _)| !is_credential_header(name))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

pub fn header_map(value: &Value) -> Map<String, Value> {
    let Some(object) = value.as_object() else {
        return Map::new();
    };
    let mut headers = Map::new();
    for (name, raw) in redact_credential_headers(object) {
        let text = match &raw {
            Value::String(text) => Some(text.clone()),
            Value::Number(number) if number.as_f64().is_some_and(f64::is_finite) => Some(number.to_string()),
            _ => None,
        };
        if let Some(text) = text {
            headers.insert(name.to_ascii_lowercase(), Value::String(text));
        }
    }
    headers
}

pub fn header_get<'a>(headers: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(Value::as_str)
}

pub fn scope_of_url(value: Option<&str>, allowed_origins: &[String]) -> (&'static str, Option<String>) {
    if let Some(allowed) = allowed_url(value, allowed_origins) {
        return ("approved", Some(allowed.url));
    }
    if value.is_some_and(is_http_url) {
        ("outside_policy", None)
    } else {
        ("unsupported", None)
    }
}

pub fn sanitized_origin(value: &str) -> Option<String> {
    sanitize_browser_url(value).origin
}
