//! JSON Schema fragments inferred from captured bodies.
//!
//! `required` is the intersection of keys seen in every sample, which is an
//! inference even when a field was observed. Templated path parameters and
//! types parsed out of query strings are inferences too. A field copied from
//! one JSON value keeps confidence `observed`.

use serde_json::{json, Map, Value};

use crate::error::WebError;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EvidenceRef {
    pub evidence_id: String,
    pub ordinal: u64,
}

pub fn evidence_array(refs: &[EvidenceRef]) -> Value {
    let mut refs = refs.to_vec();
    refs.sort();
    refs.dedup();
    Value::Array(
        refs.into_iter()
            .map(|r| {
                json!({
                    "evidence_id": r.evidence_id,
                    "ordinal": r.ordinal,
                })
            })
            .collect(),
    )
}

pub fn annotate(mut schema: Map<String, Value>, refs: &[EvidenceRef], confidence: &str) -> Value {
    schema.insert(
        "x-tracewise-evidence".to_string(),
        evidence_array(refs),
    );
    schema.insert(
        "x-tracewise-confidence".to_string(),
        Value::String(confidence.to_string()),
    );
    Value::Object(schema)
}

pub fn schema_from_samples(samples: &[(Value, EvidenceRef)]) -> Result<Value, WebError> {
    if samples.is_empty() {
        return Ok(annotate(Map::new(), &[], "inferred"));
    }
    let mut kinds = std::collections::BTreeSet::new();
    for (value, _) in samples {
        kinds.insert(json_kind(value));
    }
    if kinds.len() == 1 {
        let kind = kinds.iter().next().copied().expect("kind set is non-empty");
        return schema_for_kind(kind, samples);
    }
    if kinds.len() == 2 && kinds.contains("integer") && kinds.contains("number") {
        let refs: Vec<_> = samples.iter().map(|(_, ev)| ev.clone()).collect();
        let mut schema = Map::new();
        schema.insert("type".to_string(), Value::String("number".to_string()));
        return Ok(annotate(schema, &refs, "inferred"));
    }
    let mut variants = Vec::new();
    for kind in &kinds {
        let subset: Vec<_> = samples
            .iter()
            .filter(|(value, _)| json_kind(value) == *kind)
            .cloned()
            .collect();
        variants.push(schema_for_kind(kind, &subset)?);
    }
    let refs: Vec<_> = samples.iter().map(|(_, ev)| ev.clone()).collect();
    let mut schema = Map::new();
    schema.insert("anyOf".to_string(), Value::Array(variants));
    Ok(annotate(schema, &refs, "inferred"))
}

fn schema_for_kind(kind: &str, samples: &[(Value, EvidenceRef)]) -> Result<Value, WebError> {
    let refs: Vec<_> = samples.iter().map(|(_, ev)| ev.clone()).collect();
    match kind {
        "object" => merge_objects(samples, &refs),
        "array" => Ok(merge_arrays(samples, &refs)?),
        "null" | "boolean" | "integer" | "number" | "string" => {
            let mut schema = Map::new();
            schema.insert("type".to_string(), Value::String(kind.to_string()));
            Ok(annotate(schema, &refs, "observed"))
        }
        other => Err(WebError::Format(format!(
            "Cannot infer a schema for JSON kind '{other}'."
        ))),
    }
}

fn merge_objects(samples: &[(Value, EvidenceRef)], refs: &[EvidenceRef]) -> Result<Value, WebError> {
    let objects: Vec<(&Map<String, Value>, &EvidenceRef)> = samples
        .iter()
        .filter_map(|(value, ev)| value.as_object().map(|obj| (obj, ev)))
        .collect();
    let mut keys = std::collections::BTreeSet::new();
    for (obj, _) in &objects {
        for key in obj.keys() {
            keys.insert(key.clone());
        }
    }
    let mut properties = Map::new();
    let mut required = Vec::new();
    for key in keys {
        let mut present = Vec::new();
        for (obj, ev) in &objects {
            if let Some(value) = obj.get(&key) {
                present.push((value.clone(), (*ev).clone()));
            }
        }
        if present.len() == objects.len() {
            required.push(key.clone());
        }
        properties.insert(key, schema_from_samples(&present)?);
    }
    let mut schema = Map::new();
    schema.insert("type".to_string(), Value::String("object".to_string()));
    schema.insert("properties".to_string(), Value::Object(properties));
    if !required.is_empty() {
        schema.insert("required".to_string(), json!(required));
    }
    // Required-ness is inferred: a key is required only because every sample had it.
    Ok(annotate(schema, refs, "inferred"))
}

fn merge_arrays(samples: &[(Value, EvidenceRef)], refs: &[EvidenceRef]) -> Result<Value, WebError> {
    let mut elements = Vec::new();
    for (value, ev) in samples {
        if let Some(items) = value.as_array() {
            for item in items {
                elements.push((item.clone(), ev.clone()));
            }
        }
    }
    let mut schema = Map::new();
    schema.insert("type".to_string(), Value::String("array".to_string()));
    if elements.is_empty() {
        schema.insert("items".to_string(), annotate(Map::new(), refs, "inferred"));
        return Ok(annotate(schema, refs, "inferred"));
    }
    schema.insert("items".to_string(), schema_from_samples(&elements)?);
    Ok(annotate(schema, refs, "observed"))
}

pub fn stringly_schema(values: &[String], refs: &[EvidenceRef], format: Option<&str>) -> Value {
    let kind = if !values.is_empty() && values.iter().all(|v| is_integer_token(v)) {
        "integer"
    } else if !values.is_empty() && values.iter().all(|v| v.parse::<f64>().is_ok()) {
        "number"
    } else if !values.is_empty() && values.iter().all(|v| v == "true" || v == "false") {
        "boolean"
    } else {
        "string"
    };
    let mut schema = Map::new();
    schema.insert("type".to_string(), Value::String(kind.to_string()));
    if kind == "string" {
        if let Some(format) = format {
            schema.insert("format".to_string(), Value::String(format.to_string()));
        }
    }
    // Query strings and path templates do not declare types; the type is inferred.
    annotate(schema, refs, "inferred")
}

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) => {
            if number.is_i64() || number.is_u64() {
                "integer"
            } else {
                "number"
            }
        }
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

pub fn is_integer_token(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| c.is_ascii_digit())
}

pub fn is_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    let groups = [8usize, 4, 4, 4, 12];
    let mut index = 0;
    for (group_index, group) in groups.iter().enumerate() {
        if group_index > 0 {
            if bytes.get(index) != Some(&b'-') {
                return false;
            }
            index += 1;
        }
        for _ in 0..*group {
            if !bytes.get(index).is_some_and(|c| c.is_ascii_hexdigit()) {
                return false;
            }
            index += 1;
        }
    }
    index == bytes.len()
}

pub fn is_param_segment(segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }
    if is_integer_token(segment) || is_uuid(segment) {
        return true;
    }
    // Short hex-looking words such as "cafe" stay literal path segments.
    segment.len() >= 8 && segment.chars().all(|c| c.is_ascii_hexdigit())
}
