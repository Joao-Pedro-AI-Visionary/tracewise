//! Admission schemas for the 24 adb tools.
//!
//! Hand port of REA's `adbInputSchemas` (zod 4, strict objects). The error text
//! reproduces what the MCP layer returns for rejected arguments:
//! `Input validation error: Invalid arguments for tool <name>: <issue>, <issue>`
//! where an issue is `<path>: <message>` (or just the message for an
//! unrecognized key at the object root). Defaults are applied to the returned
//! input, which becomes the Evidence `parameters`.

use serde_json::{json, Map, Value};

pub type StrTest = fn(&str) -> bool;

/// One zod-like schema node.
#[derive(Clone)]
pub enum Kind {
    /// `z.string()` with length bounds (UTF-16 units) and custom checks that all run.
    Str { min: Option<usize>, max: Option<usize>, checks: Vec<(StrTest, &'static str)> },
    /// `z.number().int()` with optional bounds. `exclusive_min` renders `>`;
    /// `safe` adds zod's `.safe()` (the implicit safe-integer bounds are reported twice).
    Int { min: Option<i64>, exclusive_min: bool, max: Option<i64>, safe: bool },
    Bool,
    Enum(&'static [&'static str]),
    Array { item: Box<Kind>, min: Option<usize>, max: Option<usize> },
    /// `z.strictObject`.
    Object(Vec<Prop>),
    /// `z.discriminatedUnion(tag, ...)` of strict objects.
    Union { tag: &'static str, variants: Vec<(&'static str, Vec<Prop>)> },
    /// `z.record(key, value)`.
    Record { key: Box<Kind>, value: Box<Kind> },
}

#[derive(Clone)]
pub struct Prop {
    name: &'static str,
    kind: Kind,
    optional: bool,
    default: Option<Value>,
}

pub fn prop(name: &'static str, kind: Kind) -> Prop {
    Prop { name, kind, optional: false, default: None }
}

pub fn optional(name: &'static str, kind: Kind) -> Prop {
    Prop { name, kind, optional: true, default: None }
}

pub fn with_default(name: &'static str, kind: Kind, default: Value) -> Prop {
    Prop { name, kind, optional: false, default: Some(default) }
}

/// `z.number().int().min(min).max(max)`.
pub fn int(min: Option<i64>, max: Option<i64>) -> Kind {
    Kind::Int { min, exclusive_min: false, max, safe: false }
}

/// `z.number().int().positive()`.
pub fn positive_int() -> Kind {
    Kind::Int { min: Some(0), exclusive_min: true, max: None, safe: false }
}

pub fn string(min: Option<usize>, max: Option<usize>, checks: Vec<(StrTest, &'static str)>) -> Kind {
    Kind::Str { min, max, checks }
}

/// JavaScript `\s` (also what `String.prototype.trim` strips, plus NUL handling elsewhere).
pub fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{0009}'..='\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
            | '\u{FEFF}'
    )
}

fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

fn serial_ok(text: &str) -> bool {
    // /^[^\x00\s"']+$/u (the `+` is enforced by the min(1) check as well).
    !text.is_empty() && !text.chars().any(|c| c == '\0' || is_js_whitespace(c) || c == '"' || c == '\'')
}

fn package_ok(text: &str) -> bool {
    // /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*$/u
    if text.is_empty() {
        return false;
    }
    text.split('.').all(|segment| {
        let mut chars = segment.chars();
        matches!(chars.next(), Some(first) if first.is_ascii_alphabetic())
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

fn no_nul(text: &str) -> bool {
    !text.contains('\0')
}

fn absolute_no_nul(text: &str) -> bool {
    text.starts_with('/') && !text.contains('\0')
}

fn key_ok(text: &str) -> bool {
    // /^[A-Za-z0-9._\x2d]+$/u
    !text.is_empty() && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

fn identifier_ok(text: &str) -> bool {
    // IDENTIFIER_PATTERN = /^[A-Za-z][A-Za-z0-9._\x2d]*$/u
    let mut chars = text.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

fn data_uri_ok(text: &str) -> bool {
    // /^[^\x00\s]+$/u
    !text.is_empty() && !text.chars().any(|c| c == '\0' || is_js_whitespace(c))
}

fn component_ok(text: &str) -> bool {
    // /^[A-Za-z0-9._\x2d]+(\/[A-Za-z0-9._\x2d]*)?$/u
    let part_ok = |s: &str| s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-');
    match text.split_once('/') {
        None => !text.is_empty() && part_ok(text),
        Some((head, tail)) => !head.is_empty() && part_ok(head) && part_ok(tail),
    }
}

fn str_kind(min: Option<usize>, max: Option<usize>, checks: Vec<(StrTest, &'static str)>) -> Kind {
    string(min, max, checks)
}

fn serial() -> Prop {
    prop(
        "serial",
        str_kind(
            Some(1),
            Some(256),
            vec![(serial_ok as StrTest, "Device serial cannot contain whitespace or quotes")],
        ),
    )
}

fn package() -> Kind {
    str_kind(
        Some(1),
        Some(256),
        vec![(package_ok as StrTest, "Package name must be dot-separated Java identifiers")],
    )
}

fn local_path() -> Kind {
    str_kind(Some(1), None, vec![(no_nul as StrTest, "Local filesystem paths cannot contain NUL")])
}

fn device_path() -> Kind {
    str_kind(Some(1), None, vec![(absolute_no_nul as StrTest, "Device path must be absolute")])
}

fn key_string(message: &'static str) -> Kind {
    str_kind(Some(1), Some(256), vec![(key_ok as StrTest, message)])
}

fn schema_for(operation: &str) -> Option<Vec<Prop>> {
    Some(match operation {
        "inspect_adb_client" | "list_adb_devices" => vec![],
        "inspect_adb_device"
        | "list_adb_processes"
        | "list_adb_features"
        | "list_adb_services"
        | "inspect_adb_display"
        | "inspect_adb_window" => vec![serial()],
        "list_adb_packages" => vec![
            serial(),
            with_default("scope", Kind::Enum(&["all", "third_party", "system"]), json!("all")),
        ],
        "pull_adb_package" => vec![serial(), prop("package", package()), prop("output_directory", local_path())],
        "read_adb_logcat" => vec![
            serial(),
            with_default("count", int(Some(1), Some(10_000)), json!(500)),
            with_default("buffer", Kind::Enum(&["main", "system", "radio", "events", "crash"]), json!("main")),
            optional("pid", positive_int()),
        ],
        "inspect_adb_package" | "uninstall_adb_package" | "start_adb_app" | "stop_adb_app" => {
            vec![serial(), prop("package", package())]
        }
        "pull_adb_file" => vec![serial(), prop("device_path", device_path()), prop("output_directory", local_path())],
        "push_adb_file" => vec![
            serial(),
            prop("local_path", local_path()),
            prop("device_path", device_path()),
            with_default("overwrite", Kind::Bool, json!(false)),
        ],
        "capture_adb_screen" | "collect_adb_bugreport" => vec![serial(), prop("output_directory", local_path())],
        "list_adb_directory" => vec![serial(), prop("device_path", device_path())],
        "read_adb_setting" => vec![
            serial(),
            prop("namespace", Kind::Enum(&["system", "secure", "global"])),
            prop("key", key_string("Setting keys are restricted to identifiers")),
        ],
        "resolve_adb_packages" => vec![serial(), prop("query", str_kind(Some(2), Some(256), vec![]))],
        "install_adb_package" => vec![
            serial(),
            prop("apk_path", local_path()),
            with_default("replace", Kind::Bool, json!(false)),
        ],
        "start_adb_activity" => vec![
            serial(),
            prop(
                "action",
                str_kind(
                    Some(1),
                    Some(256),
                    vec![(
                        identifier_ok as StrTest,
                        "Intent action must be a dotted identifier such as android.intent.action.VIEW",
                    )],
                ),
            ),
            optional(
                "data_uri",
                str_kind(
                    Some(1),
                    Some(2048),
                    vec![(data_uri_ok as StrTest, "Data URI cannot contain whitespace or NUL")],
                ),
            ),
            optional(
                "component",
                str_kind(
                    Some(1),
                    Some(512),
                    vec![(component_ok as StrTest, "Component must be package/activity form")],
                ),
            ),
            with_default(
                "extras",
                Kind::Array {
                    item: Box::new(Kind::Object(vec![
                        prop("key", key_string("Extra keys are identifiers")),
                        prop("type", Kind::Enum(&["string", "boolean", "int", "long", "float"])),
                        prop(
                            "value",
                            str_kind(
                                Some(1),
                                Some(2048),
                                vec![(no_nul as StrTest, "Extra values cannot contain NUL")],
                            ),
                        ),
                    ])),
                    min: None,
                    max: Some(16),
                },
                json!([]),
            ),
        ],
        _ => return None,
    })
}

fn received(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn path_text(path: &[String]) -> String {
    path.join(".")
}

fn push_issue(issues: &mut Vec<String>, path: &[String], message: String) {
    if path.is_empty() {
        issues.push(message);
    } else {
        issues.push(format!("{}: {}", path_text(path), message));
    }
}

const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

fn option_list(options: &[&str]) -> String {
    options.iter().map(|o| format!("\"{o}\"")).collect::<Vec<_>>().join("|")
}

fn expected_for_undefined(kind: &Kind) -> String {
    match kind {
        Kind::Str { .. } => "Invalid input: expected string, received undefined".to_string(),
        Kind::Int { .. } => "Invalid input: expected number, received undefined".to_string(),
        Kind::Bool => "Invalid input: expected boolean, received undefined".to_string(),
        Kind::Array { .. } => "Invalid input: expected array, received undefined".to_string(),
        Kind::Object(_) | Kind::Union { .. } => "Invalid input: expected object, received undefined".to_string(),
        Kind::Record { .. } => "Invalid input: expected record, received undefined".to_string(),
        Kind::Enum(options) => format!("Invalid option: expected one of {}", option_list(options)),
    }
}

fn check_kind(kind: &Kind, value: &Value, path: &mut Vec<String>, issues: &mut Vec<String>) -> Value {
    match kind {
        Kind::Str { min, max, checks } => {
            let Some(text) = value.as_str() else {
                push_issue(
                    issues,
                    path,
                    format!("Invalid input: expected string, received {}", received(value)),
                );
                return value.clone();
            };
            let length = utf16_len(text);
            if let Some(min) = min {
                if length < *min {
                    push_issue(
                        issues,
                        path,
                        format!("Too small: expected string to have >={min} characters"),
                    );
                }
            }
            if let Some(max) = max {
                if length > *max {
                    push_issue(issues, path, format!("Too big: expected string to have <={max} characters"));
                }
            }
            for (test, message) in checks {
                if !test(text) {
                    push_issue(issues, path, (*message).to_string());
                }
            }
            value.clone()
        }
        Kind::Int { min, exclusive_min, max, safe } => {
            let Some(number) = value.as_f64().filter(|_| value.is_number()) else {
                push_issue(
                    issues,
                    path,
                    format!("Invalid input: expected number, received {}", received(value)),
                );
                return value.clone();
            };
            if number.fract() != 0.0 || !number.is_finite() {
                push_issue(issues, path, "Invalid input: expected int, received number".to_string());
                return value.clone();
            }
            // `.int()` carries the implicit safe-integer bounds; `.safe()` repeats them.
            let repeats = if *safe { 2 } else { 1 };
            if number > MAX_SAFE {
                for _ in 0..repeats {
                    push_issue(issues, path, "Too big: expected int to be <=9007199254740991".to_string());
                }
            }
            if number < -MAX_SAFE {
                for _ in 0..repeats {
                    push_issue(issues, path, "Too small: expected int to be >=-9007199254740991".to_string());
                }
            }
            if let Some(min) = min {
                let below = if *exclusive_min { number <= *min as f64 } else { number < *min as f64 };
                if below {
                    let op = if *exclusive_min { ">" } else { ">=" };
                    push_issue(issues, path, format!("Too small: expected number to be {op}{min}"));
                }
            }
            if let Some(max) = max {
                if number > *max as f64 {
                    push_issue(issues, path, format!("Too big: expected number to be <={max}"));
                }
            }
            // Integral floats such as 5.0 are the JavaScript number 5.
            if value.is_i64() || value.is_u64() {
                value.clone()
            } else {
                json!(number as i64)
            }
        }
        Kind::Bool => {
            if !value.is_boolean() {
                push_issue(
                    issues,
                    path,
                    format!("Invalid input: expected boolean, received {}", received(value)),
                );
            }
            value.clone()
        }
        Kind::Enum(options) => {
            match value.as_str() {
                Some(text) if options.contains(&text) => {}
                _ => push_issue(issues, path, format!("Invalid option: expected one of {}", option_list(options))),
            }
            value.clone()
        }
        Kind::Array { item, min, max } => {
            let Some(items) = value.as_array() else {
                push_issue(
                    issues,
                    path,
                    format!("Invalid input: expected array, received {}", received(value)),
                );
                return value.clone();
            };
            if let Some(min) = min {
                if items.len() < *min {
                    push_issue(issues, path, format!("Too small: expected array to have >={min} items"));
                }
            }
            if let Some(max) = max {
                if items.len() > *max {
                    push_issue(issues, path, format!("Too big: expected array to have <={max} items"));
                }
            }
            let mut out = Vec::with_capacity(items.len());
            for (index, element) in items.iter().enumerate() {
                path.push(index.to_string());
                out.push(check_kind(item, element, path, issues));
                path.pop();
            }
            Value::Array(out)
        }
        Kind::Object(props) => {
            let Some(object) = value.as_object() else {
                push_issue(
                    issues,
                    path,
                    format!("Invalid input: expected object, received {}", received(value)),
                );
                return value.clone();
            };
            check_object(props, None, object, path, issues)
        }
        Kind::Union { tag, variants } => {
            let Some(object) = value.as_object() else {
                push_issue(
                    issues,
                    path,
                    format!("Invalid input: expected object, received {}", received(value)),
                );
                return value.clone();
            };
            let selected = object
                .get(*tag)
                .and_then(Value::as_str)
                .and_then(|name| variants.iter().find(|(variant, _)| *variant == name));
            match selected {
                Some((_, props)) => check_object(props, Some(tag), object, path, issues),
                None => {
                    let list = variants.iter().map(|(name, _)| format!("'{name}'")).collect::<Vec<_>>().join(" | ");
                    path.push((*tag).to_string());
                    push_issue(issues, path, format!("Invalid discriminator value. Expected {list}"));
                    path.pop();
                    value.clone()
                }
            }
        }
        Kind::Record { key, value: value_kind } => {
            let Some(object) = value.as_object() else {
                push_issue(
                    issues,
                    path,
                    format!("Invalid input: expected record, received {}", received(value)),
                );
                return value.clone();
            };
            let mut out = Map::new();
            for (name, entry) in object {
                path.push(name.clone());
                let mut key_issues = Vec::new();
                check_kind(key, &Value::String(name.clone()), &mut Vec::new(), &mut key_issues);
                if key_issues.is_empty() {
                    out.insert(name.clone(), check_kind(value_kind, entry, path, issues));
                } else {
                    push_issue(issues, path, "Invalid key in record".to_string());
                }
                path.pop();
            }
            Value::Object(out)
        }
    }
}

/// `tag` names a discriminator key that is known to the object and copied through.
fn check_object(
    props: &[Prop],
    tag: Option<&str>,
    object: &Map<String, Value>,
    path: &mut Vec<String>,
    issues: &mut Vec<String>,
) -> Value {
    let mut out = Map::new();
    if let Some(tag) = tag {
        if let Some(value) = object.get(tag) {
            out.insert(tag.to_string(), value.clone());
        }
    }
    for property in props {
        path.push(property.name.to_string());
        match object.get(property.name) {
            None => {
                if let Some(default) = &property.default {
                    out.insert(property.name.to_string(), default.clone());
                } else if !property.optional {
                    // The undefined value reaches the type check.
                    push_issue(issues, path, expected_for_undefined(&property.kind));
                }
            }
            Some(value) => {
                let checked = check_kind(&property.kind, value, path, issues);
                out.insert(property.name.to_string(), checked);
            }
        }
        path.pop();
    }
    let unknown: Vec<&String> = object
        .keys()
        .filter(|key| Some(key.as_str()) != tag && !props.iter().any(|p| p.name == key.as_str()))
        .collect();
    if unknown.len() == 1 {
        push_issue(issues, path, format!("Unrecognized key: \"{}\"", unknown[0]));
    } else if unknown.len() > 1 {
        let list = unknown.iter().map(|k| format!("\"{k}\"")).collect::<Vec<_>>().join(", ");
        push_issue(issues, path, format!("Unrecognized keys: {list}"));
    }
    Value::Object(out)
}

/// Validate `arguments` against an explicit strict-object schema. The returned
/// object carries defaults. `Err` holds the exact tool-result text REA's MCP
/// layer produces for rejected input.
pub fn validate_props(tool: &str, props: &[Prop], arguments: &Value) -> Result<Map<String, Value>, String> {
    let mut object = arguments.as_object().cloned().unwrap_or_default();
    // `_meta` carries protocol metadata (progress tokens), not tool input.
    object.remove("_meta");
    let mut issues = Vec::new();
    let value = check_object(props, None, &object, &mut Vec::new(), &mut issues);
    if issues.is_empty() {
        Ok(value.as_object().cloned().unwrap_or_default())
    } else {
        Err(format!("Input validation error: Invalid arguments for tool {tool}: {}", issues.join(", ")))
    }
}

/// Validate `arguments` for one adb `operation` (see [`validate_props`]).
pub fn validate(operation: &str, arguments: &Value) -> Result<Map<String, Value>, String> {
    let props = schema_for(operation).ok_or_else(|| format!("Unknown tool: '{operation}'"))?;
    validate_props(operation, &props, arguments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_whitespace_rule_matches_javascript() {
        assert!(!serial_ok("a b"));
        assert!(!serial_ok("a\u{feff}"));
        assert!(serial_ok("a\u{0085}b"));
        assert!(!serial_ok("a'b"));
    }

    #[test]
    fn applies_defaults_and_reports_unknown_keys() {
        let ok = validate("read_adb_logcat", &json!({"serial": "x"})).unwrap();
        assert_eq!(ok["count"], 500);
        assert_eq!(ok["buffer"], "main");
        let err = validate("inspect_adb_client", &json!({"a": 1})).unwrap_err();
        assert!(err.ends_with("Unrecognized key: \"a\""));
    }
}
