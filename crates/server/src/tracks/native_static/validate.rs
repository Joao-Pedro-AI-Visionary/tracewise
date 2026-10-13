//! Minimal input validator that reproduces the MCP layer messages REA's
//! zod-based schemas produce (`Input validation error: Invalid arguments for
//! tool X: ...`). Only the constraint kinds used by the native tools exist.

use serde_json::Value;

pub enum Kind {
    /// String with a minimum length.
    Str { min: usize },
    /// Integer within `[min, max]`.
    Int { min: i64, max: i64 },
    /// One of a closed set of strings.
    Enum(&'static [&'static str]),
    Bool,
    /// Non-empty array of root-relative paths.
    RelativePaths,
    /// Local filesystem path: a non-empty string without NUL.
    LocalPath,
    /// Non-empty array of single-line Swift symbols.
    SwiftSymbols,
    /// Non-empty array of Evidence records (`evidenceSchema`, strict at the top level).
    EvidenceList,
}

pub struct Field {
    pub name: &'static str,
    pub kind: Kind,
    pub required: bool,
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

/// Normalized path below the analyzed root (`ROOT_RELATIVE_PATH` of REA).
pub fn is_root_relative_path(path: &str) -> bool {
    if path.is_empty() || path.contains('\\') || path.contains('\0') || path.starts_with('/') || path.ends_with('/') {
        return false;
    }
    path.split('/').all(|segment| {
        if segment.is_empty() || segment == "." || segment == ".." {
            return false;
        }
        true
    })
}

const ROOT_PATH_MESSAGE: &str = "Use a normalized path relative to the analyzed root, without a leading or trailing '/', '//', or '.' and '..' segments";

fn check(prefix: &str, kind: &Kind, value: Option<&Value>, issues: &mut Vec<String>) {
    let label = |message: String| {
        if prefix.is_empty() {
            message
        } else {
            format!("{prefix}: {message}")
        }
    };
    match kind {
        Kind::Str { min } => match value {
            Some(Value::String(text)) => {
                if text.encode_utf16().count() < *min {
                    issues.push(label(format!(
                        "Too small: expected string to have >={min} characters"
                    )));
                }
            }
            other => issues.push(label(format!(
                "Invalid input: expected string, received {}",
                received(other)
            ))),
        },
        Kind::Int { min, max } => match value {
            Some(Value::Number(number)) => {
                let float = number.as_f64().unwrap_or(f64::NAN);
                if float.fract() != 0.0 {
                    issues.push(label("Invalid input: expected int, received number".to_string()));
                } else if float < *min as f64 {
                    issues.push(label(format!("Too small: expected number to be >={min}")));
                } else if float > *max as f64 {
                    issues.push(label(format!("Too big: expected number to be <={max}")));
                }
            }
            other => issues.push(label(format!(
                "Invalid input: expected number, received {}",
                received(other)
            ))),
        },
        Kind::Enum(options) => match value {
            Some(Value::String(text)) if options.contains(&text.as_str()) => {}
            _ => issues.push(label(format!(
                "Invalid option: expected one of {}",
                options
                    .iter()
                    .map(|o| format!("\"{o}\""))
                    .collect::<Vec<_>>()
                    .join("|")
            ))),
        },
        Kind::Bool => {
            if !matches!(value, Some(Value::Bool(_))) {
                issues.push(label(format!(
                    "Invalid input: expected boolean, received {}",
                    received(value)
                )));
            }
        }
        Kind::LocalPath => match value {
            Some(Value::String(text)) => {
                if text.is_empty() {
                    issues.push(label("Too small: expected string to have >=1 characters".to_string()));
                } else if text.contains('\0') {
                    issues.push(label("Local filesystem paths cannot contain NUL".to_string()));
                }
            }
            other => issues.push(label(format!(
                "Invalid input: expected string, received {}",
                received(other)
            ))),
        },
        Kind::SwiftSymbols => match value {
            Some(Value::Array(items)) => {
                if items.is_empty() {
                    issues.push(label("Too small: expected array to have >=1 items".to_string()));
                }
                for (index, item) in items.iter().enumerate() {
                    let item_prefix = if prefix.is_empty() {
                        index.to_string()
                    } else {
                        format!("{prefix}.{index}")
                    };
                    match item {
                        Value::String(text) => {
                            if text.is_empty() {
                                issues.push(format!("{item_prefix}: Too small: expected string to have >=1 characters"));
                            }
                            if text.contains('\n') {
                                issues.push(format!("{item_prefix}: Each Swift symbol must be one line."));
                            }
                            if text.contains('\0') {
                                issues.push(format!("{item_prefix}: Swift symbols cannot contain NUL."));
                            }
                        }
                        other => issues.push(format!(
                            "{item_prefix}: Invalid input: expected string, received {}",
                            received(Some(other))
                        )),
                    }
                }
            }
            other => issues.push(label(format!(
                "Invalid input: expected array, received {}",
                received(other)
            ))),
        },
        Kind::EvidenceList => match value {
            Some(Value::Array(items)) => {
                if items.is_empty() {
                    issues.push(label("Too small: expected array to have >=1 items".to_string()));
                }
                for (index, item) in items.iter().enumerate() {
                    let item_prefix = if prefix.is_empty() {
                        index.to_string()
                    } else {
                        format!("{prefix}.{index}")
                    };
                    evidence_item(&item_prefix, item, issues);
                }
            }
            other => issues.push(label(format!(
                "Invalid input: expected array, received {}",
                received(other)
            ))),
        },
        Kind::RelativePaths => match value {
            Some(Value::Array(items)) => {
                if items.is_empty() {
                    issues.push(label("Too small: expected array to have >=1 items".to_string()));
                }
                for (index, item) in items.iter().enumerate() {
                    let item_prefix = if prefix.is_empty() {
                        index.to_string()
                    } else {
                        format!("{prefix}.{index}")
                    };
                    match item {
                        Value::String(text) => {
                            if text.is_empty() {
                                issues.push(format!("{item_prefix}: Too small: expected string to have >=1 characters"));
                            } else if !is_root_relative_path(text) {
                                issues.push(format!("{item_prefix}: {ROOT_PATH_MESSAGE}"));
                            }
                        }
                        other => issues.push(format!(
                            "{item_prefix}: Invalid input: expected string, received {}",
                            received(Some(other))
                        )),
                    }
                }
            }
            other => issues.push(label(format!(
                "Invalid input: expected array, received {}",
                received(other)
            ))),
        },
    }
}

/// Validate `args` against a strict object schema; returns the REA error text on failure.
pub fn validate(tool: &str, args: &Value, fields: &[Field]) -> Result<(), String> {
    let mut issues: Vec<String> = Vec::new();
    let Some(object) = args.as_object() else {
        return Err(format!(
            "Input validation error: Invalid arguments for tool {tool}: Invalid input: expected object, received {}",
            received(Some(args))
        ));
    };
    let unknown: Vec<&String> = object
        .keys()
        .filter(|key| !fields.iter().any(|f| f.name == key.as_str()))
        .collect();
    if unknown.len() == 1 {
        issues.push(format!("Unrecognized key: \"{}\"", unknown[0]));
    } else if unknown.len() > 1 {
        issues.push(format!(
            "Unrecognized keys: {}",
            unknown.iter().map(|k| format!("\"{k}\"")).collect::<Vec<_>>().join(", ")
        ));
    }
    for field in fields {
        let value = object.get(field.name);
        if value.is_none() {
            if field.required && matches!(field.kind, Kind::Enum(_)) {
                check(field.name, &field.kind, None, &mut issues);
            } else if field.required {
                issues.push(format!(
                    "{}: Invalid input: expected {}, received undefined",
                    field.name,
                    match field.kind {
                        Kind::Str { .. } | Kind::LocalPath => "string",
                        Kind::Int { .. } => "number",
                        Kind::Enum(_) => "string",
                        Kind::Bool => "boolean",
                        Kind::RelativePaths | Kind::EvidenceList | Kind::SwiftSymbols => "array",
                    }
                ));
            }
            continue;
        }
        check(field.name, &field.kind, value, &mut issues);
    }
    if issues.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Input validation error: Invalid arguments for tool {tool}: {}",
            issues.join(", ")
        ))
    }
}

// ---------------------------------------------------------------------------
// Evidence records (`evidenceSchema` of REA, domain/evidence.ts)
// ---------------------------------------------------------------------------

const SUBJECT_FORMATS: &[&str] = &[
    "hopper", "analysis-database", "mach-o", "elf", "pe", "dos-mz", "dos-com", "zip", "ipa", "apk", "msix",
    "appx", "asar", "dmg", "pkg", "plist", "javascript", "source-map", "directory", "file", "unknown",
    "mach-o-universal", "javascript-bundle", "entitlements",
];
const ARCHITECTURES: &[&str] = &["x86", "x86_64", "arm", "arm64", "mips"];
const CONFIDENCE: &[&str] = &["observed", "derived", "inferred"];
const AUTHORITY: &[&str] = &[
    "shipped-artifact", "controlled-replay", "historical-reference", "external-service", "analyst-inference",
];
const ISOLATION: &[&str] = &["none", "process", "container", "virtual-machine"];
const EVIDENCE_KEYS: &[&str] = &[
    "evidence_id", "subject", "provider", "analysis_profile", "predicate_type", "operation", "parameters",
    "raw_result", "normalized_result", "confidence", "authority", "environment", "limitations", "locations",
    "evidence_links",
];

fn is_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn prefixed_digest(prefix: &str, text: &str) -> bool {
    text.strip_prefix(prefix).and_then(|rest| rest.strip_prefix('_')).map(is_sha256).unwrap_or(false)
}

fn string_field(prefix: &str, name: &str, value: Option<&Value>, min1: bool, issues: &mut Vec<String>) {
    let path = format!("{prefix}.{name}");
    match value {
        Some(Value::String(text)) => {
            if min1 && text.is_empty() {
                issues.push(format!("{path}: Too small: expected string to have >=1 characters"));
            }
        }
        other => issues.push(format!("{path}: Invalid input: expected string, received {}", received(other))),
    }
}

fn enum_field(
    prefix: &str,
    name: &str,
    value: Option<&Value>,
    options: &[&str],
    nullable: bool,
    issues: &mut Vec<String>,
) {
    let path = format!("{prefix}.{name}");
    match value {
        Some(Value::String(text)) if options.contains(&text.as_str()) => {}
        Some(Value::Null) if nullable => {}
        _ => issues.push(format!(
            "{path}: Invalid option: expected one of {}",
            options.iter().map(|o| format!("\"{o}\"")).collect::<Vec<_>>().join("|")
        )),
    }
}

fn evidence_item(prefix: &str, value: &Value, issues: &mut Vec<String>) {
    let Some(object) = value.as_object() else {
        issues.push(format!("{prefix}: Invalid input: expected object, received {}", received(Some(value))));
        return;
    };
    match object.get("evidence_id") {
        Some(Value::String(text)) => {
            if !prefixed_digest("ev", text) {
                issues.push(format!("{prefix}.evidence_id: Expected a ev_ prefixed lowercase sha256 digest"));
            }
        }
        other => issues.push(format!(
            "{prefix}.evidence_id: Invalid input: expected string, received {}",
            received(other)
        )),
    }
    match object.get("subject") {
        Some(Value::Null) => {}
        Some(Value::Object(subject)) => {
            let path = format!("{prefix}.subject");
            string_field(&path, "name", subject.get("name"), true, issues);
            match subject.get("digest") {
                Some(Value::Object(digest)) => match digest.get("sha256") {
                    Some(Value::String(text)) => {
                        if !is_sha256(text) {
                            issues.push(format!(
                                "{path}.digest.sha256: Invalid string: must match pattern /^[a-f0-9]{{64}}$/u"
                            ));
                        }
                    }
                    other => issues.push(format!(
                        "{path}.digest.sha256: Invalid input: expected string, received {}",
                        received(other)
                    )),
                },
                other => issues.push(format!(
                    "{path}.digest: Invalid input: expected object, received {}",
                    received(other)
                )),
            }
            enum_field(&path, "format", subject.get("format"), SUBJECT_FORMATS, false, issues);
            enum_field(&path, "architecture", subject.get("architecture"), ARCHITECTURES, true, issues);
            match subject.get("local_path") {
                Some(Value::String(_)) => {}
                other => issues.push(format!(
                    "{path}.local_path: Invalid input: expected string, received {}",
                    received(other)
                )),
            }
        }
        other => issues.push(format!("{prefix}.subject: Invalid input: expected object, received {}", received(other))),
    }
    match object.get("provider") {
        Some(Value::Object(provider)) => {
            let path = format!("{prefix}.provider");
            string_field(&path, "id", provider.get("id"), true, issues);
            string_field(&path, "name", provider.get("name"), true, issues);
            match provider.get("version") {
                Some(Value::String(_)) | Some(Value::Null) => {}
                other => issues.push(format!(
                    "{path}.version: Invalid input: expected string, received {}",
                    received(other)
                )),
            }
        }
        other => issues.push(format!("{prefix}.provider: Invalid input: expected object, received {}", received(other))),
    }
    match object.get("analysis_profile") {
        Some(Value::Null) | Some(Value::Object(_)) => {}
        other => issues.push(format!(
            "{prefix}.analysis_profile: Invalid input: expected object, received {}",
            received(other)
        )),
    }
    string_field(prefix, "predicate_type", object.get("predicate_type"), true, issues);
    string_field(prefix, "operation", object.get("operation"), true, issues);
    match object.get("parameters") {
        Some(Value::Object(_)) => {}
        None => issues.push(format!("{prefix}.parameters: Invalid input: expected nonoptional, received undefined")),
        Some(_) => issues.push(format!("{prefix}.parameters: Expected JSON object")),
    }
    for name in ["raw_result", "normalized_result"] {
        if object.get(name).is_none() {
            issues.push(format!("{prefix}.{name}: Invalid input: expected nonoptional, received undefined"));
        }
    }
    enum_field(prefix, "confidence", object.get("confidence"), CONFIDENCE, false, issues);
    enum_field(prefix, "authority", object.get("authority"), AUTHORITY, false, issues);
    match object.get("environment") {
        Some(Value::Null) => {}
        Some(Value::Object(environment)) => {
            let path = format!("{prefix}.environment");
            string_field(&path, "id", environment.get("id"), true, issues);
            string_field(&path, "platform", environment.get("platform"), true, issues);
            string_field(&path, "architecture", environment.get("architecture"), true, issues);
            enum_field(&path, "isolation", environment.get("isolation"), ISOLATION, false, issues);
        }
        other => issues.push(format!(
            "{prefix}.environment: Invalid input: expected object, received {}",
            received(other)
        )),
    }
    match object.get("limitations") {
        Some(Value::Array(items)) => {
            for (index, item) in items.iter().enumerate() {
                if !item.is_string() {
                    issues.push(format!(
                        "{prefix}.limitations.{index}: Invalid input: expected string, received {}",
                        received(Some(item))
                    ));
                }
            }
        }
        other => issues.push(format!(
            "{prefix}.limitations: Invalid input: expected array, received {}",
            received(other)
        )),
    }
    match object.get("locations") {
        Some(Value::Array(items)) => {
            for (index, item) in items.iter().enumerate() {
                let kind = item.get("kind").and_then(Value::as_str);
                if !matches!(
                    kind,
                    Some("address" | "address-range" | "artifact-path" | "file-offset" | "file-offset-range")
                ) {
                    issues.push(format!(
                        "{prefix}.locations.{index}.kind: Invalid discriminator value. Expected 'address' | 'address-range' | 'artifact-path' | 'file-offset' | 'file-offset-range'"
                    ));
                }
            }
        }
        other => issues.push(format!(
            "{prefix}.locations: Invalid input: expected array, received {}",
            received(other)
        )),
    }
    match object.get("evidence_links") {
        Some(Value::Array(items)) => {
            for (index, item) in items.iter().enumerate() {
                match item {
                    Value::String(text) if prefixed_digest("ev", text) => {}
                    Value::String(_) => issues.push(format!(
                        "{prefix}.evidence_links.{index}: Expected a ev_ prefixed lowercase sha256 digest"
                    )),
                    other => issues.push(format!(
                        "{prefix}.evidence_links.{index}: Invalid input: expected string, received {}",
                        received(Some(other))
                    )),
                }
            }
        }
        other => issues.push(format!(
            "{prefix}.evidence_links: Invalid input: expected array, received {}",
            received(other)
        )),
    }
    let unknown: Vec<&String> = object.keys().filter(|key| !EVIDENCE_KEYS.contains(&key.as_str())).collect();
    if unknown.len() == 1 {
        issues.push(format!("{prefix}: Unrecognized key: \"{}\"", unknown[0]));
    } else if unknown.len() > 1 {
        issues.push(format!(
            "{prefix}: Unrecognized keys: {}",
            unknown.iter().map(|k| format!("\"{k}\"")).collect::<Vec<_>>().join(", ")
        ));
    }
}
