//! Key order of REA's JSON output.
//!
//! REA builds results through zod parsing, so every object leaves the server with its keys in
//! the order of the schema, which the catalog's `outputSchema` preserves. JSON consumers do not
//! see the order, but the text copy of a tool result does, and the MCP response budget counts
//! bytes part by part (see `delivery.rs`), so the numbers it reports depend on it.
//! [`reorder_to_schema`] puts an Evidence value in schema order; keys the schema does not
//! describe keep their relative order after the described ones.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde_json::{Map, Value};

struct Catalog {
    schemas: HashMap<String, Value>,
}

fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        let mut schemas = HashMap::new();
        let tools = tracewise_contracts::all_tools_value();
        for tool in tools["tools"].as_array().into_iter().flatten() {
            if let (Some(name), Some(schema)) = (tool["name"].as_str(), tool.get("outputSchema")) {
                schemas.insert(name.to_string(), schema.clone());
            }
        }
        Catalog { schemas }
    })
}

/// Reorder `value` (the Evidence a tool returns) like REA's zod output for `tool`.
pub fn reorder_to_schema(value: Value, tool: &str) -> Value {
    match catalog().schemas.get(tool) {
        Some(schema) => {
            let defs = schema.get("$defs");
            walk(value, schema, defs, 0)
        }
        None => value,
    }
}

fn resolve<'a>(schema: &'a Value, defs: Option<&'a Value>) -> &'a Value {
    let mut current = schema;
    for _ in 0..32 {
        let Some(reference) = current.get("$ref").and_then(Value::as_str) else { break };
        let Some(name) = reference.strip_prefix("#/$defs/") else { break };
        match defs.and_then(|d| d.get(name)) {
            Some(target) => current = target,
            None => break,
        }
    }
    current
}

/// Does `value` satisfy the `const`/`enum` discriminators of an object alternative?
fn discriminators_match(properties: &Map<String, Value>, defs: Option<&Value>, value: &Map<String, Value>) -> bool {
    for (key, property) in properties {
        let property = resolve(property, defs);
        if let Some(expected) = property.get("const") {
            match value.get(key) {
                Some(actual) if actual == expected => {}
                _ => return false,
            }
        } else if let Some(options) = property.get("enum").and_then(Value::as_array) {
            if let Some(actual) = value.get(key) {
                if !options.contains(actual) {
                    return false;
                }
            }
        }
    }
    true
}

/// The alternative of a union that describes `value`.
fn pick<'a>(alternatives: &'a [Value], defs: Option<&'a Value>, value: &Value) -> Option<&'a Value> {
    let mut best: Option<(&Value, usize)> = None;
    for alternative in alternatives {
        let resolved = resolve(alternative, defs);
        let score = match (value, resolved.get("properties").and_then(Value::as_object)) {
            (Value::Object(object), Some(properties)) => {
                if !discriminators_match(properties, defs, object) {
                    continue;
                }
                object.keys().filter(|key| properties.contains_key(*key)).count()
            }
            (Value::Object(_), None) => {
                if resolved.get("type").and_then(Value::as_str).is_some_and(|t| t != "object") {
                    continue;
                }
                0
            }
            (Value::Array(_), _) => {
                if resolved.get("type").and_then(Value::as_str) != Some("array") {
                    continue;
                }
                1
            }
            _ => 0,
        };
        if best.is_none_or(|(_, top)| score > top) {
            best = Some((resolved, score));
        }
    }
    best.map(|(alternative, _)| alternative)
}

fn walk(value: Value, schema: &Value, defs: Option<&Value>, depth: usize) -> Value {
    if depth > 200 {
        return value;
    }
    let mut schema = resolve(schema, defs);
    let union = schema
        .get("anyOf")
        .or_else(|| schema.get("oneOf"))
        .and_then(Value::as_array);
    if let Some(alternatives) = union {
        match pick(alternatives, defs, &value) {
            Some(alternative) => schema = alternative,
            None => return value,
        }
        // A picked alternative may itself be a reference or union.
        return walk(value, schema, defs, depth + 1);
    }
    match value {
        Value::Object(map) => {
            let properties = schema.get("properties").and_then(Value::as_object);
            let additional = schema.get("additionalProperties").filter(|v| v.is_object());
            let mut remaining = map;
            let mut out = Map::new();
            if let Some(properties) = properties {
                for (key, property) in properties {
                    if let Some(item) = remaining.remove(key) {
                        out.insert(key.clone(), walk(item, property, defs, depth + 1));
                    }
                }
            }
            for (key, item) in remaining {
                let item = match additional {
                    Some(additional) => walk(item, additional, defs, depth + 1),
                    None => item,
                };
                out.insert(key, item);
            }
            Value::Object(out)
        }
        Value::Array(items) => match schema.get("items") {
            Some(item_schema) if item_schema.is_object() => Value::Array(
                items.into_iter().map(|item| walk(item, item_schema, defs, depth + 1)).collect(),
            ),
            _ => Value::Array(items),
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn described_keys_follow_the_schema_and_unknown_keys_follow() {
        let ordered = reorder_to_schema(
            json!({"normalized_result": {}, "evidence_id": "ev_x", "extra": 1, "subject": null}),
            "trace_application_feature",
        );
        let keys: Vec<&str> = ordered.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, ["evidence_id", "subject", "normalized_result", "extra"]);
    }
}
