//! Contract-level input parsing for the engines tools.
//!
//! REA's MCP layer parses every tool input with the tool's zod schema before any
//! provider sees it: unknown keys are rejected, defaults are applied and the
//! defaulted object is what Evidence records as `parameters`. The catalog's JSON
//! Schemas carry the same constraints and defaults, so this module derives the
//! behavior from them.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde_json::{Map, Value};

struct Catalog {
    tools: HashMap<String, Value>,
}

fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        let mut tools = HashMap::new();
        for raw in [
            tracewise_contracts::PHASE5_TOOLS_JSON,
            tracewise_contracts::PHASE5B_TOOLS_JSON,
        ] {
            let parsed: Value = serde_json::from_str(raw).expect("engine tool catalog is valid JSON");
            for tool in parsed["tools"].as_array().cloned().unwrap_or_default() {
                if let Some(name) = tool["name"].as_str() {
                    tools.insert(name.to_string(), tool.clone());
                }
            }
        }
        Catalog { tools }
    })
}

/// Names of every engines tool known to the catalog.
pub fn tool_names() -> Vec<String> {
    catalog().tools.keys().cloned().collect()
}

pub fn tool_definition(name: &str) -> Option<&'static Value> {
    catalog().tools.get(name)
}

fn resolve<'a>(root: &'a Value, schema: &'a Value) -> &'a Value {
    let mut current = schema;
    for _ in 0..16 {
        let Some(reference) = current.get("$ref").and_then(|r| r.as_str()) else {
            return current;
        };
        let Some(name) = reference.strip_prefix("#/$defs/") else {
            return current;
        };
        match root.get("$defs").and_then(|d| d.get(name)) {
            Some(next) => current = next,
            None => return current,
        }
    }
    current
}

/// A default declared on the property or on any schema it references.
fn declared_default(root: &Value, schema: &Value) -> Option<Value> {
    let mut current = schema;
    for _ in 0..16 {
        if let Some(d) = current.get("default") {
            return Some(d.clone());
        }
        let reference = current.get("$ref").and_then(|r| r.as_str())?;
        let name = reference.strip_prefix("#/$defs/")?;
        current = root.get("$defs")?.get(name)?;
    }
    None
}

fn js_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn validate_value(
    root: &Value,
    schema: &Value,
    value: &Value,
    path: &str,
    issues: &mut Vec<String>,
) {
    let schema = resolve(root, schema);
    let label = |message: String| {
        if path.is_empty() {
            message
        } else {
            format!("{path}: {message}")
        }
    };
    if let Some(any) = schema.get("anyOf").and_then(|a| a.as_array()) {
        let mut local_best: Option<Vec<String>> = None;
        for alternative in any {
            let mut sub = Vec::new();
            validate_value(root, alternative, value, path, &mut sub);
            if sub.is_empty() {
                return;
            }
            if local_best.is_none() {
                local_best = Some(sub);
            }
        }
        issues.push(label("Invalid input".to_string()));
        return;
    }
    let declared = schema.get("type").and_then(|t| t.as_str());
    let actual = js_type(value);
    let integer = value.as_f64().map(|n| n.fract() == 0.0).unwrap_or(false);
    let type_ok = match declared {
        None => true,
        Some("integer") => value.is_number() && integer,
        Some("number") => value.is_number(),
        Some(other) => other == actual,
    };
    if !type_ok {
        let expected = declared.unwrap_or("value");
        issues.push(label(format!(
            "Invalid input: expected {expected}, received {actual}"
        )));
        return;
    }
    if let Some(options) = schema.get("enum").and_then(|e| e.as_array()) {
        if !options.contains(value) {
            let list: Vec<String> = options.iter().map(|o| o.to_string()).collect();
            issues.push(label(format!("Invalid option: expected one of {}", list.join("|"))));
            return;
        }
    }
    match value {
        Value::String(text) => {
            if let Some(min) = schema.get("minLength").and_then(|m| m.as_u64()) {
                if (text.chars().count() as u64) < min {
                    issues.push(label(format!(
                        "Too small: expected string to have >={min} characters"
                    )));
                }
            }
            if let Some(pattern) = schema.get("pattern").and_then(|p| p.as_str()) {
                if let Ok(re) = regex::Regex::new(pattern) {
                    if !re.is_match(text) {
                        issues.push(label(format!(
                            "Invalid string: must match pattern /{pattern}/"
                        )));
                    }
                }
            }
        }
        Value::Number(n) => {
            let n = n.as_f64().unwrap_or(0.0);
            if let Some(min) = schema.get("minimum").and_then(|m| m.as_f64()) {
                if n < min {
                    issues.push(label(format!("Too small: expected number to be >={}", fmt_num(min))));
                }
            }
            if let Some(max) = schema.get("maximum").and_then(|m| m.as_f64()) {
                if n > max {
                    issues.push(label(format!("Too big: expected number to be <={}", fmt_num(max))));
                }
            }
        }
        Value::Array(items) => {
            if let Some(min) = schema.get("minItems").and_then(|m| m.as_u64()) {
                if (items.len() as u64) < min {
                    issues.push(label(format!("Too small: expected array to have >={min} items")));
                }
            }
            if let Some(item_schema) = schema.get("items") {
                for (index, item) in items.iter().enumerate() {
                    let child = if path.is_empty() {
                        index.to_string()
                    } else {
                        format!("{path}.{index}")
                    };
                    validate_value(root, item_schema, item, &child, issues);
                }
            }
        }
        Value::Object(object) => {
            validate_object(root, schema, object, path, issues);
        }
        _ => {}
    }
}

fn fmt_num(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

fn validate_object(
    root: &Value,
    schema: &Value,
    object: &Map<String, Value>,
    path: &str,
    issues: &mut Vec<String>,
) {
    let properties = schema.get("properties").and_then(|p| p.as_object());
    let required: Vec<&str> = schema
        .get("required")
        .and_then(|r| r.as_array())
        .map(|r| r.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if let Some(properties) = properties {
        for key in &required {
            if !object.contains_key(*key) {
                let property_schema = properties.get(*key).map(|s| resolve(root, s));
                let expected = property_schema
                    .and_then(|s| s.get("type"))
                    .and_then(|t| t.as_str())
                    .unwrap_or("value");
                let child = if path.is_empty() {
                    (*key).to_string()
                } else {
                    format!("{path}.{key}")
                };
                issues.push(format!(
                    "{child}: Invalid input: expected {expected}, received undefined"
                ));
            }
        }
        for (key, value) in object {
            match properties.get(key) {
                Some(property_schema) => {
                    let child = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    };
                    validate_value(root, property_schema, value, &child, issues);
                }
                None => {
                    if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                        issues.push(if path.is_empty() {
                            format!("Unrecognized key: \"{key}\"")
                        } else {
                            format!("{path}: Unrecognized key: \"{key}\"")
                        });
                    }
                }
            }
        }
    }
}

/// Parse and default one tool input the way REA's MCP layer does.
///
/// On failure the returned message is the SDK's `Input validation error` text.
pub fn parse_contract_input(tool: &str, arguments: &Value) -> Result<Value, String> {
    let Some(definition) = tool_definition(tool) else {
        return Err(format!("Tool {tool} not found"));
    };
    let schema = &definition["inputSchema"];
    let empty = Map::new();
    let object = match arguments {
        Value::Object(o) => o,
        Value::Null => &empty,
        other => {
            return Err(format!(
                "Input validation error: Invalid arguments for tool {tool}: Invalid input: expected object, received {}",
                js_type(other)
            ))
        }
    };
    let mut issues = Vec::new();
    validate_object(schema, schema, object, "", &mut issues);
    if !issues.is_empty() {
        return Err(format!(
            "Input validation error: Invalid arguments for tool {tool}: {}",
            issues.join("; ")
        ));
    }
    if let Some(message) = cross_field_refinement(tool, object) {
        return Err(format!(
            "Input validation error: Invalid arguments for tool {tool}: {message}"
        ));
    }
    let mut out = object.clone();
    if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
        for (key, property_schema) in properties {
            if !out.contains_key(key) {
                if let Some(default) = declared_default(schema, property_schema) {
                    out.insert(key.clone(), default);
                }
            }
        }
    }
    Ok(Value::Object(out))
}

/// Output schema of a tool, with its `$defs` kept attached for validation.
pub fn output_schema(tool: &str) -> Option<&'static Value> {
    tool_definition(tool).map(|t| &t["outputSchema"])
}

/// Cross-field constraints that zod expresses with `.refine` and JSON Schema cannot.
fn cross_field_refinement(tool: &str, object: &Map<String, Value>) -> Option<&'static str> {
    let present = |key: &str| object.get(key).map(|v| !v.is_null()).unwrap_or(false);
    match tool {
        "inspect_native_data_type" if present("type") == present("address") => {
            Some("Supply exactly one of type or address")
        }
        "annotate_native_function"
            if !object.contains_key("name")
                && !object.contains_key("comment")
                && !object.contains_key("inline_comment") =>
        {
            Some("Supply at least one annotation change")
        }
        "set_addresses_names"
            if object.get("names").and_then(Value::as_object).map(|n| n.is_empty()).unwrap_or(false) =>
        {
            Some("Supply at least one address name")
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn applies_catalog_defaults() {
        let parsed = parse_contract_input("read_bytes", &json!({ "address": "0x10" })).unwrap();
        assert_eq!(parsed, json!({ "address": "0x10", "length": 256 }));
        let parsed = parse_contract_input("search_strings", &json!({ "pattern": "x" })).unwrap();
        assert_eq!(parsed, json!({ "pattern": "x", "mode": "literal", "case_sensitive": false }));
    }

    #[test]
    fn rejects_like_the_sdk() {
        let message = parse_contract_input("read_bytes", &json!({})).unwrap_err();
        assert_eq!(
            message,
            "Input validation error: Invalid arguments for tool read_bytes: address: Invalid input: expected string, received undefined"
        );
        let message = parse_contract_input("read_bytes", &json!({ "address": "0x1", "bogus": 1 })).unwrap_err();
        assert!(message.ends_with("Unrecognized key: \"bogus\""));
        let message = parse_contract_input("read_bytes", &json!({ "address": "0x1", "length": 0 })).unwrap_err();
        assert!(message.ends_with("length: Too small: expected number to be >=1"));
        let message = parse_contract_input("inspect_native_data_type", &json!({})).unwrap_err();
        assert!(message.ends_with("Supply exactly one of type or address"));
    }

    #[test]
    fn every_engines_tool_is_in_the_catalog() {
        assert_eq!(tool_names().len(), 57);
    }
}
