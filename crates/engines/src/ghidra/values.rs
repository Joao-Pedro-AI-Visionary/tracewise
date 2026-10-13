//! Provider-level request parsing and bridge-result checks for Ghidra (port of the
//! input schemas and result contracts in `GhidraInventoryValues.ts` and
//! `GhidraFunctionValues.ts`).
//!
//! The Java bridge already emits the strict shapes REA's zod contracts describe, so the
//! normalized result is the bridge value once its top-level contract holds.

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::error::{AnalysisError, InputIssue};

use super::capabilities::{is_function_operation, is_inventory_operation};

const ADDRESS_MESSAGE: &str = "Use hexadecimal digits, optionally prefixed with 0x, or an encoded address-space name followed by :0x and hexadecimal digits";

fn address_regex() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(?:(?:0[xX])?[0-9a-fA-F]+|(?:[A-Za-z0-9._~-]|%[0-9a-fA-F]{2})+:0[xX][0-9a-fA-F]+)$")
            .unwrap()
    })
}

/// Canonical address as the bridge prints it.
pub fn canonical_address_regex() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(?:0x[0-9a-f]+|(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})+:0x[0-9a-f]+)$").unwrap()
    })
}

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

struct Parser<'a> {
    operation: &'a str,
    input: &'a Map<String, Value>,
    allowed: Vec<&'static str>,
    issues: Vec<InputIssue>,
    out: Map<String, Value>,
}

impl<'a> Parser<'a> {
    fn new(operation: &'a str, input: &'a Map<String, Value>, allowed: &[&'static str]) -> Self {
        let mut issues = Vec::new();
        for key in input.keys() {
            if !allowed.contains(&key.as_str()) {
                issues.push(InputIssue {
                    path: vec![json!(key)],
                    reason: "unknown_argument",
                    message: None,
                    expected: None,
                    minimum: None,
                    maximum: None,
                });
            }
        }
        Self {
            operation,
            input,
            allowed: allowed.to_vec(),
            issues,
            out: Map::new(),
        }
    }

    fn string(&mut self, key: &'static str, required: bool, nullable_default: bool) -> Option<String> {
        match self.input.get(key) {
            None | Some(Value::Null) if !required => {
                if nullable_default {
                    self.out.insert(key.to_string(), Value::Null);
                }
                None
            }
            None => {
                let mut i = issue(key, "missing_argument");
                i.expected = Some(json!("string"));
                self.issues.push(i);
                None
            }
            Some(Value::String(text)) => {
                if text.is_empty() {
                    let mut i = issue(key, "out_of_range");
                    i.minimum = Some(1.0);
                    self.issues.push(i);
                    None
                } else {
                    Some(text.clone())
                }
            }
            Some(_) => {
                let mut i = issue(key, "invalid_type");
                i.expected = Some(json!("string"));
                self.issues.push(i);
                None
            }
        }
    }

    fn document(&mut self) {
        if let Some(text) = self.string("document", false, true) {
            self.out.insert("document".into(), json!(text));
        }
    }

    fn address(&mut self, key: &'static str, required: bool) {
        if let Some(text) = self.string(key, required, !required) {
            if address_regex().is_match(&text) {
                self.out.insert(key.to_string(), json!(text));
            } else {
                let mut i = issue(key, "invalid_format");
                i.expected = Some(json!("regex"));
                i.message = Some(ADDRESS_MESSAGE.to_string());
                self.issues.push(i);
            }
        }
    }

    fn plain(&mut self, key: &'static str) {
        if let Some(text) = self.string(key, true, false) {
            self.out.insert(key.to_string(), json!(text));
        }
    }

    fn finish(self) -> Result<Map<String, Value>, AnalysisError> {
        let _ = &self.allowed;
        if self.issues.is_empty() {
            Ok(self.out)
        } else {
            Err(AnalysisError::Input {
                operation: self.operation.to_string(),
                issues: self.issues,
            })
        }
    }
}

/// Validate and default one provider request before it crosses the socket.
pub fn parse_input(operation: &str, value: &Value) -> Result<Value, AnalysisError> {
    let empty = Map::new();
    let input = value.as_object().unwrap_or(&empty);
    let mut parser;
    match operation {
        "inspect_native_load_image" | "list_documents" => {
            parser = Parser::new(operation, input, &[]);
        }
        "read_bytes" => {
            parser = Parser::new(operation, input, &["document", "address", "length"]);
            parser.document();
            parser.address("address", true);
            let length = match input.get("length") {
                None | Some(Value::Null) => Some(256u64),
                Some(Value::Number(n)) => match n.as_u64() {
                    Some(v) if v >= 1 && n.as_f64().map(|f| f.fract() == 0.0).unwrap_or(false) => Some(v),
                    _ => {
                        let mut i = issue("length", "out_of_range");
                        i.minimum = Some(1.0);
                        parser.issues.push(i);
                        None
                    }
                },
                Some(_) => {
                    let mut i = issue("length", "invalid_type");
                    i.expected = Some(json!("number"));
                    parser.issues.push(i);
                    None
                }
            };
            if let Some(length) = length {
                parser.out.insert("length".into(), json!(length));
            }
        }
        "address_to_file_offset" | "address_name" | "resolve_containing_procedure"
        | "inspect_native_instruction" | "resolve_native_call_targets" | "xrefs" => {
            parser = Parser::new(operation, input, &["document", "address"]);
            parser.document();
            parser.address("address", true);
        }
        "list_names" | "list_strings" => {
            parser = Parser::new(operation, input, &["document", "address"]);
            parser.document();
            parser.address("address", false);
        }
        "list_procedures" | "list_segments" => {
            parser = Parser::new(operation, input, &["document"]);
            parser.document();
        }
        "procedure_address" | "procedure_assembly" | "procedure_callees" | "procedure_callers"
        | "procedure_info" | "procedure_pseudo_code" | "read_function_instructions" => {
            parser = Parser::new(operation, input, &["document", "procedure"]);
            parser.document();
            parser.plain("procedure");
        }
        "procedure_references" => {
            parser = Parser::new(operation, input, &["document", "procedure", "direction"]);
            parser.document();
            parser.plain("procedure");
            match input.get("direction") {
                None => {
                    parser.out.insert("direction".into(), json!("outgoing"));
                }
                Some(Value::String(d)) if d == "incoming" || d == "outgoing" => {
                    parser.out.insert("direction".into(), json!(d));
                }
                Some(_) => {
                    let mut i = issue("direction", "invalid_value");
                    i.expected = Some(json!(["incoming", "outgoing"]));
                    parser.issues.push(i);
                }
            }
        }
        "search_procedures" | "search_strings" => {
            parser = Parser::new(operation, input, &["pattern", "mode", "case_sensitive", "document"]);
            parser.document();
            parser.plain("pattern");
            match input.get("mode") {
                None => {
                    parser.out.insert("mode".into(), json!("literal"));
                }
                Some(Value::String(m)) if m == "literal" || m == "regex" => {
                    parser.out.insert("mode".into(), json!(m));
                }
                Some(_) => {
                    let mut i = issue("mode", "invalid_value");
                    i.expected = Some(json!(["literal", "regex"]));
                    parser.issues.push(i);
                }
            }
            match input.get("case_sensitive") {
                None => {
                    parser.out.insert("case_sensitive".into(), json!(false));
                }
                Some(Value::Bool(b)) => {
                    parser.out.insert("case_sensitive".into(), json!(b));
                }
                Some(_) => {
                    let mut i = issue("case_sensitive", "invalid_type");
                    i.expected = Some(json!("boolean"));
                    parser.issues.push(i);
                }
            }
        }
        "set_address_name" => {
            parser = Parser::new(operation, input, &["document", "address", "name"]);
            parser.document();
            parser.address("address", true);
            parser.plain("name");
        }
        "set_addresses_names" => {
            parser = Parser::new(operation, input, &["document", "names"]);
            parser.document();
            match input.get("names") {
                Some(Value::Object(names)) => {
                    let mut ok = true;
                    for (address, name) in names {
                        if !address_regex().is_match(address) {
                            let mut i = issue("names", "invalid_format");
                            i.path = vec![json!("names"), json!(address)];
                            i.expected = Some(json!("regex"));
                            i.message = Some(ADDRESS_MESSAGE.to_string());
                            parser.issues.push(i);
                            ok = false;
                        }
                        match name.as_str() {
                            Some(n) if !n.is_empty() => {}
                            _ => {
                                let mut i = issue("names", "invalid_type");
                                i.path = vec![json!("names"), json!(address)];
                                i.expected = Some(json!("string"));
                                parser.issues.push(i);
                                ok = false;
                            }
                        }
                    }
                    if names.is_empty() {
                        parser.issues.push(InputIssue::invalid_value(
                            vec![],
                            "Supply at least one address name",
                        ));
                    } else if ok {
                        parser.out.insert("names".into(), Value::Object(names.clone()));
                    }
                }
                None => {
                    let mut i = issue("names", "missing_argument");
                    i.expected = Some(json!("record"));
                    parser.issues.push(i);
                }
                Some(_) => {
                    let mut i = issue("names", "invalid_type");
                    i.expected = Some(json!("record"));
                    parser.issues.push(i);
                }
            }
        }
        "annotate_native_function" => {
            parser = Parser::new(
                operation,
                input,
                &["procedure", "name", "comment", "inline_comment"],
            );
            parser.plain("procedure");
            if let Some(name) = parser.string("name", false, false) {
                parser.out.insert("name".into(), json!(name));
            }
            for key in ["comment", "inline_comment"] {
                match input.get(key) {
                    None => {}
                    Some(Value::String(text)) => {
                        parser.out.insert(key.to_string(), json!(text));
                    }
                    Some(_) => {
                        let mut i = issue(key, "invalid_type");
                        i.expected = Some(json!("string"));
                        parser.issues.push(i);
                    }
                }
            }
            if parser.issues.is_empty()
                && !input.contains_key("name")
                && !input.contains_key("comment")
                && !input.contains_key("inline_comment")
            {
                parser.issues.push(InputIssue::invalid_value(
                    vec![],
                    "Supply at least one annotation change",
                ));
            }
        }
        "inspect_native_data_type" => {
            parser = Parser::new(operation, input, &["document", "type", "address"]);
            parser.document();
            let by_type = parser.string("type", false, true);
            parser.address("address", false);
            let by_address = parser.out.get("address").map(|v| !v.is_null()).unwrap_or(false);
            if let Some(t) = &by_type {
                parser.out.insert("type".into(), json!(t));
            }
            if parser.issues.is_empty() && by_type.is_some() == by_address {
                parser.issues.push(InputIssue::invalid_value(
                    vec![],
                    "Supply exactly one of type or address",
                ));
            }
        }
        "analyze_function" => {
            parser = Parser::new(operation, input, &["procedure"]);
            parser.plain("procedure");
        }
        other => {
            return Err(AnalysisError::capability_unavailable(
                "ghidra",
                other,
                "The Ghidra adapter does not declare this operation.",
            ))
        }
    }
    Ok(Value::Object(parser.finish()?))
}

/// Require the exact top-level contract of the bridge result before creating Evidence.
pub fn check_result(operation: &str, value: &Value) -> Result<(), AnalysisError> {
    let message = if is_inventory_operation(operation) {
        "Ghidra bridge output did not match the inventory contract"
    } else if is_function_operation(operation) {
        "Ghidra bridge output did not match the function-analysis contract"
    } else {
        "Ghidra bridge output did not match the operation contract"
    };
    let ok = match operation {
        "address_name" => value.is_string() || value.is_null(),
        "list_documents" => value
            .as_array()
            .map(|a| a.len() == 1 && a[0].as_str().map(|s| !s.is_empty()).unwrap_or(false))
            .unwrap_or(false),
        "list_names" | "list_procedures" | "list_segments" | "list_strings" | "search_procedures"
        | "search_strings" => value.as_array().map(|a| a.iter().all(Value::is_object)).unwrap_or(false),
        "procedure_address" => value
            .as_str()
            .map(|s| canonical_address_regex().is_match(s))
            .unwrap_or(false),
        "procedure_assembly" => value.is_string(),
        "procedure_pseudo_code" => value.is_string() || value.is_null(),
        "procedure_callees" | "procedure_callers" | "xrefs" => value
            .as_array()
            .map(|a| a.iter().all(|v| v.as_str().map(|s| canonical_address_regex().is_match(s)).unwrap_or(false)))
            .unwrap_or(false),
        "set_address_name" => value.is_boolean(),
        "set_addresses_names" => value
            .as_object()
            .map(|o| o.values().all(Value::is_boolean))
            .unwrap_or(false),
        "read_bytes" => value.as_object().map(|o| {
            let returned = o.get("returned_bytes").and_then(Value::as_u64);
            let requested = o.get("requested_bytes").and_then(Value::as_u64);
            let hex = o.get("bytes_hex").and_then(Value::as_str);
            let complete = o.get("complete").and_then(Value::as_bool);
            match (returned, requested, hex, complete) {
                (Some(r), Some(q), Some(h), Some(c)) => {
                    r * 2 == h.len() as u64 && r <= q && c == (r == q)
                }
                _ => false,
            }
        }).unwrap_or(false),
        "address_to_file_offset" => value.as_object().map(|o| {
            o.get("address").map(Value::is_string).unwrap_or(false)
                && o.get("file_offset").map(Value::is_u64).unwrap_or(false)
        }).unwrap_or(false),
        _ => value.is_object(),
    };
    if ok {
        Ok(())
    } else {
        Err(AnalysisError::output(operation, message))
    }
}
