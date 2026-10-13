//! Caller input for IDA operations (port of `IdaInput.ts`).
//!
//! The MCP layer has already applied the tool contract to direct calls; composed workflows
//! reach the provider with parameters they built themselves, so the contract's argument
//! rules are applied here too, followed by IDA's own explicit-address boundary.

use serde_json::{json, Map, Value};

use crate::error::{AnalysisError, InputIssue};

use super::protocol::normalize_address;
use super::search;

fn issue(path: &str, reason: &'static str) -> InputIssue {
    InputIssue {
        path: vec![json!(path)],
        reason,
        message: None,
        expected: None,
        minimum: None,
        maximum: None,
    }
}

fn with_message(mut issue: InputIssue, message: &str) -> InputIssue {
    issue.message = Some(message.to_string());
    issue
}

/// What the contract of one operation admits, in schema order.
struct Shape {
    string_fields: &'static [(&'static str, bool)],
    search: bool,
}

fn shape(operation: &str) -> Option<Shape> {
    match operation {
        "list_procedures" => Some(Shape {
            string_fields: &[("document", false)],
            search: false,
        }),
        "list_strings" | "xrefs" => Some(Shape {
            string_fields: &[("document", false), ("address", false)],
            search: false,
        }),
        "search_procedures" | "search_strings" => Some(Shape {
            string_fields: &[("pattern", true), ("document", false)],
            search: true,
        }),
        "procedure_address"
        | "procedure_pseudo_code"
        | "procedure_assembly"
        | "procedure_callers"
        | "procedure_callees"
        | "read_function_instructions" => Some(Shape {
            string_fields: &[("procedure", true), ("document", false)],
            search: false,
        }),
        "analyze_function" => Some(Shape {
            string_fields: &[("procedure", true)],
            search: false,
        }),
        _ => None,
    }
}

/// Apply the named public contract (arguments, types, defaults).
fn contract(
    operation: &str,
    parameters: &Map<String, Value>,
) -> Result<Map<String, Value>, Vec<InputIssue>> {
    let Some(shape) = shape(operation) else {
        return Err(Vec::new());
    };
    let mut issues = Vec::new();
    let mut out = Map::new();
    for (field, required) in shape.string_fields {
        match parameters.get(*field) {
            None if *required => {
                let mut missing = issue(field, "missing_argument");
                missing.expected = Some(json!("string"));
                issues.push(missing);
            }
            None => {}
            Some(Value::String(text)) => {
                if *field == "pattern" && text.is_empty() {
                    let mut small = issue(field, "out_of_range");
                    small.minimum = Some(1.0);
                    issues.push(small);
                } else {
                    out.insert((*field).to_string(), Value::String(text.clone()));
                }
            }
            Some(_) => {
                let mut wrong = issue(field, "invalid_type");
                wrong.expected = Some(json!("string"));
                issues.push(wrong);
            }
        }
    }
    if shape.search {
        match parameters.get("mode") {
            None => {
                out.insert("mode".into(), json!("literal"));
            }
            Some(Value::String(mode)) if mode == "literal" || mode == "regex" => {
                out.insert("mode".into(), json!(mode));
            }
            Some(Value::String(_)) => {
                let mut wrong = issue("mode", "invalid_value");
                wrong.expected = Some(json!(["literal", "regex"]));
                issues.push(wrong);
            }
            Some(_) => {
                let mut wrong = issue("mode", "invalid_type");
                wrong.expected = Some(json!("string"));
                issues.push(wrong);
            }
        }
        match parameters.get("case_sensitive") {
            None => {
                out.insert("case_sensitive".into(), json!(false));
            }
            Some(Value::Bool(flag)) => {
                out.insert("case_sensitive".into(), json!(flag));
            }
            Some(_) => {
                let mut wrong = issue("case_sensitive", "invalid_type");
                wrong.expected = Some(json!("boolean"));
                issues.push(wrong);
            }
        }
    }
    let known: Vec<&str> = shape
        .string_fields
        .iter()
        .map(|(field, _)| *field)
        .chain(if shape.search {
            vec!["mode", "case_sensitive"]
        } else {
            vec![]
        })
        .collect();
    for key in parameters.keys() {
        if !known.contains(&key.as_str()) {
            issues.push(issue(key, "unknown_argument"));
        }
    }
    if issues.is_empty() {
        Ok(out)
    } else {
        Err(issues)
    }
}

/// Apply the contract and IDA's explicit-address boundary before any startup.
pub fn parse_ida_input(operation: &str, parameters: &Value) -> Result<Value, AnalysisError> {
    let empty = Map::new();
    let object = match parameters {
        Value::Object(map) => map,
        Value::Null => &empty,
        _ => {
            return Err(AnalysisError::Input {
                operation: operation.to_string(),
                issues: Vec::new(),
            })
        }
    };
    let parsed = contract(operation, object).map_err(|issues| AnalysisError::Input {
        operation: operation.to_string(),
        issues,
    })?;
    let fail = |issue: InputIssue| AnalysisError::Input {
        operation: operation.to_string(),
        issues: vec![issue],
    };
    if operation == "xrefs" && !matches!(object.get("address"), Some(Value::String(_))) {
        return Err(fail(with_message(
            issue("address", "missing_argument"),
            "IDA requires an explicit hexadecimal address.",
        )));
    }
    if let Some(Value::String(address)) = object.get("address") {
        if normalize_address(address).is_none() {
            return Err(fail(with_message(
                issue("address", "invalid_format"),
                "IDA requires a hexadecimal address.",
            )));
        }
    }
    if matches!(object.get("procedure"), Some(Value::String(text)) if text.is_empty()) {
        return Err(fail(with_message(
            issue("procedure", "invalid_value"),
            "Supply a function name or address.",
        )));
    }
    if parsed.get("mode") == Some(&json!("regex")) {
        if let Some(Value::String(pattern)) = parsed.get("pattern") {
            let case_sensitive = parsed.get("case_sensitive") == Some(&json!(true));
            if search::compile(pattern, case_sensitive).is_none() {
                return Err(fail(with_message(
                    issue("pattern", "invalid_format"),
                    "Supply a valid regular expression.",
                )));
            }
        }
    }
    Ok(Value::Object(parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reasons(error: AnalysisError) -> Vec<String> {
        match error {
            AnalysisError::Input { issues, .. } => issues
                .iter()
                .map(|i| format!("{:?}:{}", i.path, i.reason))
                .collect(),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn contract_rejects_unknown_null_and_missing_arguments() {
        let unknown = parse_ida_input("list_procedures", &json!({ "x": 1 })).unwrap_err();
        assert_eq!(reasons(unknown), vec![r#"[String("x")]:unknown_argument"#]);
        let null = parse_ida_input("list_strings", &json!({ "address": null })).unwrap_err();
        assert_eq!(reasons(null), vec![r#"[String("address")]:invalid_type"#]);
        let missing = parse_ida_input("procedure_address", &json!({})).unwrap_err();
        assert_eq!(
            reasons(missing),
            vec![r#"[String("procedure")]:missing_argument"#]
        );
        // `analyze_function` does not admit a document.
        let document = parse_ida_input(
            "analyze_function",
            &json!({ "procedure": "main", "document": "x" }),
        )
        .unwrap_err();
        assert_eq!(
            reasons(document),
            vec![r#"[String("document")]:unknown_argument"#]
        );
    }

    #[test]
    fn explicit_address_boundary_and_defaults() {
        let missing = parse_ida_input("xrefs", &json!({})).unwrap_err();
        assert_eq!(
            reasons(missing),
            vec![r#"[String("address")]:missing_argument"#]
        );
        let bad = parse_ida_input("xrefs", &json!({ "address": "zz" })).unwrap_err();
        assert_eq!(reasons(bad), vec![r#"[String("address")]:invalid_format"#]);
        let empty = parse_ida_input("procedure_address", &json!({ "procedure": "" })).unwrap_err();
        assert_eq!(
            reasons(empty),
            vec![r#"[String("procedure")]:invalid_value"#]
        );
        let parsed = parse_ida_input("search_strings", &json!({ "pattern": "a" })).unwrap();
        assert_eq!(
            parsed,
            json!({ "pattern": "a", "mode": "literal", "case_sensitive": false })
        );
        let regex = parse_ida_input(
            "search_strings",
            &json!({ "pattern": "(", "mode": "regex" }),
        )
        .unwrap_err();
        assert_eq!(
            reasons(regex),
            vec![r#"[String("pattern")]:invalid_format"#]
        );
    }
}
