//! Path normalization shared with REA source-to-bundle matching.

use std::collections::HashSet;

use serde_json::Value;

use crate::error::JsError;
use crate::unicode::compare_unicode_code_points;

pub(crate) struct CurrentPath {
    pub(crate) kind: &'static str,
    pub(crate) value: String,
    pub(crate) allow_suffix: bool,
}

pub(crate) fn add_path(paths: &mut Vec<CurrentPath>, kind: &'static str, raw: &str) {
    if let Some(value) = normalize_current_path(raw) {
        paths.push(CurrentPath {
            kind,
            value,
            allow_suffix: true,
        });
    }
}

fn normalize_current_path(raw: &str) -> Option<String> {
    let scheme = regex_scheme(raw);
    let without_query = if scheme {
        raw.split(['?', '#']).next().unwrap_or(raw)
    } else {
        raw
    };
    let portable = strip_scheme_prefix(without_query).replace('\\', "/");
    let mut parts = Vec::new();
    for part in portable.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            if parts.is_empty() {
                return None;
            }
            parts.pop();
        } else {
            parts.push(part);
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

fn regex_scheme(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    let mut index = 1;
    while index < bytes.len() {
        let b = bytes[index];
        if b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.' {
            index += 1;
            continue;
        }
        break;
    }
    raw[index..].starts_with("://")
}

fn strip_scheme_prefix(raw: &str) -> &str {
    if !regex_scheme(raw) {
        return raw;
    }
    let start = raw.find("://").unwrap_or(0) + 3;
    let bytes = raw.as_bytes();
    let mut index = start;
    while index < bytes.len() && bytes[index] == b'/' {
        index += 1;
    }
    &raw[index..]
}

pub(crate) fn unique_paths(paths: Vec<CurrentPath>) -> Vec<CurrentPath> {
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    for path in paths {
        let key = format!("{}\u{0}{}\u{0}{}", path.kind, path.value, path.allow_suffix);
        if seen.insert(key) {
            unique.push(path);
        }
    }
    unique.sort_by(|left, right| {
        compare_unicode_code_points(
            &format!("{}\u{0}{}", left.kind, left.value),
            &format!("{}\u{0}{}", right.kind, right.value),
        )
    });
    unique
}

pub(crate) fn path_suffixes(path: &str) -> Vec<String> {
    let parts: Vec<&str> = path.split('/').collect();
    (0..parts.len()).map(|index| parts[index..].join("/")).collect()
}

pub(crate) fn posix_basename(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

pub(crate) fn posix_extname(path: &str) -> String {
    let base = posix_basename(path);
    match base.rfind('.') {
        Some(index) if index > 0 => base[index..].to_lowercase(),
        _ => String::new(),
    }
}

pub(crate) fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub(crate) fn required_str(value: &Value, field: &str) -> Result<String, JsError> {
    value
        .get(field)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| JsError::InvalidInput(format!("{field} is required")))
}

pub(crate) fn string_array(value: &Value, field: &str) -> Result<Vec<String>, JsError> {
    let Some(items) = value.as_array() else {
        return Err(JsError::InvalidInput(format!("{field} must be an array")));
    };
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or_else(|| JsError::InvalidInput(format!("{field} must contain strings")))
        })
        .collect()
}
