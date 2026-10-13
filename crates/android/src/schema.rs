//! A small structural validator that reproduces the zod issue wording REA
//! reports for nested values (used for artifact inventory pages).

use serde_json::Value;

#[derive(Clone, Copy)]
pub enum Rule {
    Str,
    StrMin1,
    Digest,
    Prefixed(&'static str),
    Uint { min: u64 },
    Bool,
    Enum(&'static [&'static str]),
    RelativePath,
    StrArray,
    Nullable(&'static Rule),
}

fn received(value: Option<&Value>) -> &'static str {
    match value {
        None => "undefined",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    }
}

fn is_hex64(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{path}.{key}")
    }
}

fn issue(issues: &mut Vec<(String, String)>, path: &str, message: String) {
    issues.push((path.to_string(), message));
}

pub fn check(issues: &mut Vec<(String, String)>, path: &str, value: Option<&Value>, rule: Rule) {
    match rule {
        Rule::Nullable(inner) => {
            if matches!(value, Some(Value::Null)) {
                return;
            }
            check(issues, path, value, *inner);
        }
        Rule::Str | Rule::StrMin1 | Rule::Digest | Rule::Prefixed(_) | Rule::RelativePath | Rule::Enum(_) => {
            let Some(Value::String(text)) = value else {
                let expected = if matches!(rule, Rule::Enum(_)) { None } else { Some("string") };
                match (rule, expected) {
                    (Rule::Enum(options), _) => issue(
                        issues,
                        path,
                        format!("Invalid option: expected one of {}", options.iter().map(|o| format!("\"{o}\"")).collect::<Vec<_>>().join("|")),
                    ),
                    _ => issue(issues, path, format!("Invalid input: expected string, received {}", received(value))),
                }
                return;
            };
            match rule {
                Rule::StrMin1 if text.is_empty() => issue(issues, path, "Too small: expected string to have >=1 characters".to_string()),
                Rule::Digest if !is_hex64(text) => issue(issues, path, "Invalid string: must match pattern /^[a-f0-9]{64}$/u".to_string()),
                Rule::Prefixed(prefix) => {
                    let ok = text.strip_prefix(prefix).and_then(|r| r.strip_prefix('_')).is_some_and(is_hex64);
                    if !ok {
                        issue(issues, path, format!("Expected a {prefix}_ prefixed lowercase sha256 digest"));
                    }
                }
                Rule::RelativePath => {
                    if text.is_empty() {
                        issue(issues, path, "Too small: expected string to have >=1 characters".to_string());
                    } else if text.starts_with('/') || text.contains('\\') || text.split('/').any(|p| p.is_empty() || p == "..") {
                        issue(issues, path, "Expected a normalized relative POSIX path without traversal".to_string());
                    }
                }
                Rule::Enum(options) if !options.contains(&text.as_str()) => issue(
                    issues,
                    path,
                    format!("Invalid option: expected one of {}", options.iter().map(|o| format!("\"{o}\"")).collect::<Vec<_>>().join("|")),
                ),
                _ => {}
            }
        }
        Rule::Uint { min } => match value {
            Some(Value::Number(n)) if n.is_u64() || n.is_i64() => {
                let v = n.as_i64().unwrap_or(i64::MAX);
                if v < min as i64 {
                    issue(issues, path, format!("Too small: expected number to be >={min}"));
                }
            }
            Some(Value::Number(_)) => issue(issues, path, "Invalid input: expected int, received number".to_string()),
            other => issue(issues, path, format!("Invalid input: expected number, received {}", received(other))),
        },
        Rule::Bool => {
            if !matches!(value, Some(Value::Bool(_))) {
                issue(issues, path, format!("Invalid input: expected boolean, received {}", received(value)));
            }
        }
        Rule::StrArray => match value {
            Some(Value::Array(items)) => {
                for (index, item) in items.iter().enumerate() {
                    check(issues, &join(path, &index.to_string()), Some(item), Rule::Str);
                }
            }
            other => issue(issues, path, format!("Invalid input: expected array, received {}", received(other))),
        },
    }
}

pub fn object<'a>(issues: &mut Vec<(String, String)>, path: &str, value: Option<&'a Value>) -> Option<&'a serde_json::Map<String, Value>> {
    match value {
        Some(Value::Object(map)) => Some(map),
        other => {
            issue(issues, path, format!("Invalid input: expected object, received {}", received(other)));
            None
        }
    }
}

pub fn array<'a>(issues: &mut Vec<(String, String)>, path: &str, value: Option<&'a Value>) -> Option<&'a Vec<Value>> {
    match value {
        Some(Value::Array(items)) => Some(items),
        other => {
            issue(issues, path, format!("Invalid input: expected array, received {}", received(other)));
            None
        }
    }
}

pub const ARTIFACT_FORMATS: &[&str] = &[
    "dmg", "zip", "pkg", "asar", "javascript-bundle", "source-map", "mach-o-universal", "mach-o", "elf", "pe", "dos-mz", "dos-com",
    "hopper", "analysis-database", "ipa", "apk", "msix", "appx", "plist", "entitlements", "directory", "file", "unknown",
];
pub const CONTENT_FORMATS: &[&str] = &["zip", "mach-o-universal", "mach-o", "elf", "pe", "dos-mz", "plist", "directory", "file", "unknown"];
pub const ARTIFACT_KINDS: &[&str] = &[
    "container", "executable", "dynamic-library", "framework", "native-addon", "javascript", "source-map", "plist", "entitlements",
    "resource", "universal-slice", "package-metadata", "unknown",
];

const NULLABLE_DECLARED: Rule = Rule::Nullable(&Rule::Uint { min: 0 });
const NULLABLE_OCC: Rule = Rule::Nullable(&Rule::Prefixed("occ"));
const NULLABLE_ART: Rule = Rule::Nullable(&Rule::Prefixed("art"));
const NULLABLE_STR: Rule = Rule::Nullable(&Rule::StrMin1);

/// Validate one `inventory_artifact` result; issues come back as (path, message).
pub fn validate_inventory(inventory: &Value) -> Vec<(String, String)> {
    let mut issues = Vec::new();
    let Some(root) = object(&mut issues, "", Some(inventory)) else { return issues };
    if let Some(manifest) = object(&mut issues, "manifest", root.get("manifest")) {
        check(&mut issues, "manifest.manifest_id", manifest.get("manifest_id"), Rule::Prefixed("agm"));
        check(&mut issues, "manifest.root_artifact_id", manifest.get("root_artifact_id"), Rule::Prefixed("art"));
        check(&mut issues, "manifest.root_sha256", manifest.get("root_sha256"), Rule::Digest);
        check(&mut issues, "manifest.root_format", manifest.get("root_format"), Rule::Enum(ARTIFACT_FORMATS));
        check(&mut issues, "manifest.graph_sha256", manifest.get("graph_sha256"), Rule::Digest);
        check(&mut issues, "manifest.node_count", manifest.get("node_count"), Rule::Uint { min: 1 });
        check(&mut issues, "manifest.occurrence_count", manifest.get("occurrence_count"), Rule::Uint { min: 1 });
        check(&mut issues, "manifest.edge_count", manifest.get("edge_count"), Rule::Uint { min: 0 });
    }
    if let Some(nodes) = array(&mut issues, "nodes", root.get("nodes")) {
        for (index, node) in nodes.iter().enumerate() {
            let base = format!("nodes.{index}");
            let Some(node) = object(&mut issues, &base, Some(node)) else { continue };
            check(&mut issues, &join(&base, "artifact_id"), node.get("artifact_id"), Rule::Prefixed("art"));
            check(&mut issues, &join(&base, "format"), node.get("format"), Rule::Enum(CONTENT_FORMATS));
            check(&mut issues, &join(&base, "sha256"), node.get("sha256"), Rule::Digest);
            check(&mut issues, &join(&base, "size"), node.get("size"), Rule::Uint { min: 0 });
            check(&mut issues, &join(&base, "media_type"), node.get("media_type"), NULLABLE_STR);
            check(&mut issues, &join(&base, "architecture"), node.get("architecture"), NULLABLE_STR);
            check(&mut issues, &join(&base, "content_state"), node.get("content_state"), Rule::Enum(&["materialized", "embedded", "virtual"]));
            check(&mut issues, &join(&base, "limitations"), node.get("limitations"), Rule::StrArray);
        }
    }
    if let Some(occurrences) = array(&mut issues, "occurrences", root.get("occurrences")) {
        for (index, occurrence) in occurrences.iter().enumerate() {
            let base = format!("occurrences.{index}");
            let Some(o) = object(&mut issues, &base, Some(occurrence)) else { continue };
            check(&mut issues, &join(&base, "occurrence_id"), o.get("occurrence_id"), Rule::Prefixed("occ"));
            check(&mut issues, &join(&base, "artifact_id"), o.get("artifact_id"), NULLABLE_ART);
            check(&mut issues, &join(&base, "parent_occurrence_id"), o.get("parent_occurrence_id"), NULLABLE_OCC);
            check(&mut issues, &join(&base, "logical_path"), o.get("logical_path"), Rule::RelativePath);
            check(&mut issues, &join(&base, "entry_kind"), o.get("entry_kind"), Rule::Enum(&["file", "directory", "symlink", "slice"]));
            check(&mut issues, &join(&base, "artifact_kind"), o.get("artifact_kind"), Rule::Enum(ARTIFACT_KINDS));
            check(&mut issues, &join(&base, "artifact_format"), o.get("artifact_format"), Rule::Enum(ARTIFACT_FORMATS));
            check(&mut issues, &join(&base, "declared_size"), o.get("declared_size"), NULLABLE_DECLARED);
            check(&mut issues, &join(&base, "compressed_size"), o.get("compressed_size"), NULLABLE_DECLARED);
            check(&mut issues, &join(&base, "executable"), o.get("executable"), Rule::Bool);
            check(&mut issues, &join(&base, "encrypted"), o.get("encrypted"), Rule::Bool);
            check(&mut issues, &join(&base, "hash_status"), o.get("hash_status"), Rule::Enum(&["verified", "mismatched", "not-hashed", "unavailable"]));
            check(&mut issues, &join(&base, "limitations"), o.get("limitations"), Rule::StrArray);
        }
    }
    if let Some(edges) = array(&mut issues, "edges", root.get("edges")) {
        for (index, edge) in edges.iter().enumerate() {
            let base = format!("edges.{index}");
            let Some(e) = object(&mut issues, &base, Some(edge)) else { continue };
            check(&mut issues, &join(&base, "edge_id"), e.get("edge_id"), Rule::Prefixed("edge"));
            check(&mut issues, &join(&base, "ordinal"), e.get("ordinal"), Rule::Uint { min: 0 });
            check(&mut issues, &join(&base, "parent_artifact_id"), e.get("parent_artifact_id"), Rule::Prefixed("art"));
            check(
                &mut issues,
                &join(&base, "relation"),
                e.get("relation"),
                Rule::Enum(&["contains", "extracts", "slice-of", "embeds", "loads", "maps-source", "derived-from"]),
            );
            check(&mut issues, &join(&base, "occurrence_id"), e.get("occurrence_id"), Rule::Prefixed("occ"));
        }
    }
    array(&mut issues, "provenance", root.get("provenance"));
    check(&mut issues, "limitations", root.get("limitations"), Rule::StrArray);
    issues
}
