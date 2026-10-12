//! Runtime location authorization (port of REA inspector/JavaScriptRuntimeScope.ts
//! and browser/ElectronFileScope.ts).

use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde_json::{json, Value};
use tracewise_web::browser_observation::{parse_exact_origin, sanitize_browser_url};
use url::Url;

/// Maximum ASAR JSON header admitted while resolving packaged file URLs.
const MAX_ASAR_HEADER_BYTES: u64 = 64 * 1024 * 1024;

/// Authorized runtime location, or the canonical denial bucket.
#[derive(Debug, Clone, PartialEq)]
pub enum LocationDecision {
    Allowed(Value),
    Denied,
}

/// Resolve a protocol location exposed by the explicitly selected Inspector endpoint.
pub fn authorize_runtime_location(value: &str) -> LocationDecision {
    if value.starts_with("file:") {
        return match authorized_electron_file(value) {
            Some(path) => LocationDecision::Allowed(json!({ "kind": "file", "file_path": path })),
            None => LocationDecision::Denied,
        };
    }
    project_reported_runtime_url(value)
}

/// Project non-file Inspector URLs without filesystem access.
pub fn project_reported_runtime_url(value: &str) -> LocationDecision {
    if value.starts_with("node:") {
        return LocationDecision::Allowed(json!({ "kind": "builtin", "specifier": value }));
    }
    let Ok(url) = Url::parse(value) else {
        return LocationDecision::Denied;
    };
    if url.scheme() != "http" && url.scheme() != "https" {
        return LocationDecision::Denied;
    }
    let Some(origin) = parse_exact_origin(&url.origin().ascii_serialization()) else {
        return LocationDecision::Denied;
    };
    LocationDecision::Allowed(json!({
        "kind": "url",
        "origin": origin,
        "sanitized_url": sanitize_browser_url(value).url,
    }))
}

/// Interpret Node's lossy discovery metadata separately from scriptParsed URLs.
pub fn authorize_runtime_target_location(value: &str, target_type: &str, product: &str) -> LocationDecision {
    let node_product = product.get(..9).is_some_and(|prefix| prefix.eq_ignore_ascii_case("node.js/v"));
    if target_type != "node" || !node_product || !value.starts_with("file://") {
        return authorize_runtime_location(value);
    }
    let reported = &value["file://".len()..];
    if !reported.starts_with('/') && !is_windows_drive_report(reported) {
        return authorize_runtime_location(value);
    }
    // Node concatenates the pathname, then replaces quotes and backslashes with
    // underscores. A remaining underscore cannot prove which pathname was used.
    if !cfg!(windows) && !reported.contains(['_', '"', '\\']) && reported.starts_with('/') {
        if let Ok(url) = Url::from_file_path(reported) {
            let decision = authorize_runtime_location(url.as_str());
            if matches!(decision, LocationDecision::Allowed(_)) {
                return decision;
            }
        }
    }
    LocationDecision::Allowed(json!({
        "kind": "unresolved",
        "reported_url": value,
        "reason": "unverifiable-file-location",
    }))
}

fn is_windows_drive_report(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\' | b'_')
}

/// Resolve one local file URL while rejecting remote hosts and encoded separators.
pub fn authorized_electron_file(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") {
        return None;
    }
    let url = Url::parse(value).ok()?;
    if url.scheme() != "file"
        || url.host_str().is_some_and(|host| !host.is_empty())
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    let path = url.to_file_path().ok()?;
    if !path.is_absolute() || path.to_string_lossy().contains('\0') {
        return None;
    }
    if std::fs::metadata(&path).map(|m| m.is_file()).unwrap_or(false) {
        return std::fs::canonicalize(&path)
            .ok()
            .map(|p| p.to_string_lossy().into_owned());
    }
    // Electron serves packaged pages from inside app.asar, which the host
    // filesystem cannot stat; resolve those through the archive header.
    authorized_asar_member(&path)
}

/// Resolve `<archive>.asar/<member>` the way Electron's file protocol does.
fn authorized_asar_member(path: &Path) -> Option<String> {
    let segments: Vec<String> = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    for index in 0..segments.len().saturating_sub(1) {
        if !segments[index].to_lowercase().ends_with(".asar") {
            continue;
        }
        let mut archive = PathBuf::from("/");
        for part in &segments[..=index] {
            archive.push(part);
        }
        let member = &segments[index + 1..];
        if member.iter().any(|part| part.is_empty() || part == "." || part == "..") {
            return None;
        }
        match std::fs::metadata(&archive) {
            Ok(metadata) if metadata.is_file() => {}
            _ => continue,
        }
        let canonical = std::fs::canonicalize(&archive).ok()?;
        let files = asar_files(&canonical)?;
        if !is_asar_regular_file(&files, member) {
            return None;
        }
        let mut resolved = canonical;
        for part in member {
            resolved.push(part);
        }
        return Some(resolved.to_string_lossy().into_owned());
    }
    None
}

/// Read the two Chromium pickle headers before allocating the JSON header.
fn asar_files(archive: &Path) -> Option<Value> {
    let mut file = File::open(archive).ok()?;
    let mut prefix = [0u8; 16];
    file.read_exact(&mut prefix).ok()?;
    let word = |offset: usize| u32::from_le_bytes([prefix[offset], prefix[offset + 1], prefix[offset + 2], prefix[offset + 3]]);
    if word(0) != 4 {
        return None;
    }
    let json_bytes = u64::from(word(12));
    if json_bytes == 0 || json_bytes > MAX_ASAR_HEADER_BYTES || json_bytes + 8 > u64::from(word(4)) + 8 {
        return None;
    }
    let mut json = vec![0u8; usize::try_from(json_bytes).ok()?];
    file.read_exact(&mut json).ok()?;
    let parsed: Value = serde_json::from_str(std::str::from_utf8(&json).ok()?).ok()?;
    let files = parsed.get("files")?;
    files.is_object().then(|| files.clone())
}

fn is_asar_regular_file(files: &Value, member: &[String]) -> bool {
    let mut node = json!({ "files": files });
    for part in member {
        let Some(child) = node.get("files").and_then(Value::as_object).and_then(|children| children.get(part)) else {
            return false;
        };
        node = child.clone();
    }
    node.is_object()
        && node.get("size").is_some_and(Value::is_number)
        && node.get("files").is_none()
        && node.get("link").is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_and_http_locations_project_without_filesystem_access() {
        assert_eq!(
            project_reported_runtime_url("node:internal/main"),
            LocationDecision::Allowed(json!({"kind": "builtin", "specifier": "node:internal/main"}))
        );
        assert_eq!(
            project_reported_runtime_url("https://u:p@example.com/a.js?x=1"),
            LocationDecision::Allowed(json!({
                "kind": "url",
                "origin": "https://example.com",
                "sanitized_url": "https://example.com/a.js?x=1",
            }))
        );
        assert_eq!(project_reported_runtime_url("evalmachine.<anonymous>"), LocationDecision::Denied);
        assert_eq!(project_reported_runtime_url(""), LocationDecision::Denied);
    }

    #[test]
    fn node_discovery_with_underscore_stays_unresolved() {
        let decision = authorize_runtime_target_location("file:///tmp/a_b.js", "node", "node.js/v22.0.0");
        assert_eq!(
            decision,
            LocationDecision::Allowed(json!({
                "kind": "unresolved",
                "reported_url": "file:///tmp/a_b.js",
                "reason": "unverifiable-file-location",
            }))
        );
    }

    #[test]
    fn encoded_separators_and_remote_hosts_are_rejected() {
        assert_eq!(authorized_electron_file("file:///tmp%2Fx"), None);
        assert_eq!(authorized_electron_file("file://host/tmp/x"), None);
    }
}
