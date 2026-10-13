//! MCP response budget (REA `server/toolResult.ts`, `server/toolResultEncoding.ts`,
//! `domain/jsonSerialization.ts`, `config/mcpResponseBudget.ts`).
//!
//! REA refuses to deliver an Evidence result whose repeated wire representation (structured
//! content plus the escaped text copy) does not fit the stdio receive buffer, and answers a
//! `resource_constraint` error that names how far the encoder got. The accounting is reproduced
//! step for step, including the part boundaries (16 K code units per JSON part, regrouped to at
//! most 64 K), because `response_bytes_at_least` is the running total at the first part that
//! crosses the limit.

use serde_json::{json, Value};
use tracewise_js::jsgraph::util::js_number_to_string;
use tracewise_native::error::NativeError;

/// `STDIO_DEFAULT_MAX_BUFFER_SIZE` of the pinned MCP SDK.
const DEFAULT_RECEIVE_BUFFER: u64 = 10_485_760;
/// `buffer.constants.MAX_STRING_LENGTH - 1024` on Node 22 (`2^29 - 24 - 1024`).
const RESULT_STRING_LIMIT: u64 = 536_870_888 - 1024;
const PART_CHARACTERS: usize = 16 * 1024;
const REGROUP_CHARACTERS: usize = 64 * 1024;
const LONG_STRING_UNITS: usize = 8192;

/// Why a result does not fit.
#[derive(Debug, PartialEq, Eq)]
pub struct Overflow {
    pub bytes_at_least: u64,
    pub code_units_at_least: u64,
    pub constraint: &'static str,
}

/// Response budget in bytes: `REA_MCP_MAX_RESPONSE_BYTES` (at least 10 MiB) or the SDK default.
fn maximum_response_bytes() -> u64 {
    std::env::var("REA_MCP_MAX_RESPONSE_BYTES")
        .ok()
        .and_then(|text| text.parse::<u64>().ok())
        .filter(|bytes| *bytes >= 10 * 1024 * 1024 && *bytes < (1 << 53))
        .unwrap_or(DEFAULT_RECEIVE_BUFFER)
}

pub fn result_budget_bytes() -> u64 {
    maximum_response_bytes() - 1024
}

fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

/// UTF-8 and UTF-16 sizes of `JSON.stringify(text)` (quotes included).
fn escaped_sizes(text: &str) -> (u64, u64) {
    let (mut bytes, mut units) = (2u64, 2u64);
    for ch in text.chars() {
        let (b, u) = match ch {
            '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => (2, 2),
            c if (c as u32) < 0x20 => (6, 6),
            c => (c.len_utf8() as u64, c.len_utf16() as u64),
        };
        bytes += b;
        units += u;
    }
    (bytes, units)
}

struct Accounting {
    structured: bool,
    budget: u64,
    bytes: u64,
    units: u64,
    failure: Option<Overflow>,
}

impl Accounting {
    /// One regrouped part (`bufferedJsonParts`) reaches `encodeToolResult`.
    fn part(&mut self, part: &str) {
        if self.failure.is_some() {
            return;
        }
        let (escaped_bytes, escaped_units) = escaped_sizes(part);
        let raw_bytes = if self.structured { part.len() as u64 } else { 0 };
        let raw_units = if self.structured { utf16_len(part) as u64 } else { 0 };
        self.bytes += raw_bytes + escaped_bytes - 2;
        self.units += raw_units + escaped_units - 2;
        if self.bytes > self.budget || self.units > RESULT_STRING_LIMIT {
            self.failure = Some(Overflow {
                bytes_at_least: self.bytes,
                code_units_at_least: self.units,
                constraint: if self.units > RESULT_STRING_LIMIT { "string-length" } else { "receive-buffer" },
            });
        }
    }
}

/// `jsonParts` feeding `bufferedJsonParts`.
struct Encoder<'a> {
    account: &'a mut Accounting,
    /// `encodeValue` buffer.
    buffer: String,
    buffer_units: usize,
    /// `bufferedJsonParts` buffer.
    regroup: String,
    regroup_units: usize,
}

impl Encoder<'_> {
    fn stopped(&self) -> bool {
        self.account.failure.is_some()
    }

    fn add(&mut self, text: &str) {
        self.buffer.push_str(text);
        self.buffer_units += utf16_len(text);
    }

    /// `yield buffer` of `encodeValue`.
    fn yield_part(&mut self, part: &str, part_units: usize) {
        if self.regroup_units + part_units > REGROUP_CHARACTERS && !self.regroup.is_empty() {
            let out = std::mem::take(&mut self.regroup);
            self.regroup_units = 0;
            self.account.part(&out);
        }
        self.regroup.push_str(part);
        self.regroup_units += part_units;
    }

    fn flush_buffer(&mut self) {
        if !self.buffer.is_empty() {
            let part = std::mem::take(&mut self.buffer);
            let units = self.buffer_units;
            self.buffer_units = 0;
            self.yield_part(&part, units);
        }
    }

    fn check_buffer(&mut self) {
        if self.buffer_units >= PART_CHARACTERS {
            self.flush_buffer();
        }
    }

    /// `encodeString` for a string longer than 8192 code units.
    fn long_string(&mut self, text: &str) {
        self.yield_part("\"", 1);
        let units: Vec<u16> = text.encode_utf16().collect();
        let mut start = 0;
        while start < units.len() {
            let mut end = (start + LONG_STRING_UNITS).min(units.len());
            let last = units[end - 1];
            if end < units.len() && (0xd800..=0xdbff).contains(&last) && (0xdc00..=0xdfff).contains(&units[end]) {
                end -= 1;
            }
            let slice = String::from_utf16_lossy(&units[start..end]);
            let quoted = serde_json::to_string(&slice).unwrap_or_default();
            let inner = &quoted[1..quoted.len() - 1];
            self.yield_part(inner, utf16_len(inner));
            start = end;
            if self.stopped() {
                return;
            }
        }
        self.yield_part("\"", 1);
    }

    fn value(&mut self, value: &Value) {
        if self.stopped() {
            return;
        }
        match value {
            Value::String(text) if utf16_len(text) > LONG_STRING_UNITS => {
                self.flush_buffer();
                self.long_string(text);
            }
            Value::String(text) => self.add(&serde_json::to_string(text).unwrap_or_default()),
            Value::Null => self.add("null"),
            Value::Bool(flag) => self.add(if *flag { "true" } else { "false" }),
            Value::Number(number) => {
                let text = match number.as_f64() {
                    Some(float) if number.is_f64() => js_number_to_string(float),
                    _ => number.to_string(),
                };
                self.add(&text);
            }
            Value::Array(items) => {
                self.add("[");
                self.check_buffer();
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        self.add(",");
                    }
                    self.value(item);
                    if self.stopped() {
                        return;
                    }
                }
                self.add("]");
                self.check_buffer();
                return;
            }
            Value::Object(map) => {
                self.add("{");
                self.check_buffer();
                for (index, (key, item)) in map.iter().enumerate() {
                    if index > 0 {
                        self.add(",");
                    }
                    if utf16_len(key) <= LONG_STRING_UNITS {
                        self.add(&serde_json::to_string(key).unwrap_or_default());
                    } else {
                        self.flush_buffer();
                        self.long_string(key);
                    }
                    self.add(":");
                    self.value(item);
                    if self.stopped() {
                        return;
                    }
                }
                self.add("}");
                self.check_buffer();
                return;
            }
        }
        self.check_buffer();
    }
}

/// `encodeToolResult`: does the complete response fit?
pub fn check_budget(value: &Value, budget_bytes: u64, structured: bool) -> Result<(), Overflow> {
    let envelope = if structured {
        r#"{"content":[{"type":"text","text":""}],"structuredContent":null}"#.len() as u64 - 4
    } else {
        r#"{"content":[{"type":"text","text":""}]}"#.len() as u64
    };
    let mut account =
        Accounting { structured, budget: budget_bytes, bytes: envelope, units: envelope, failure: None };
    {
        let mut encoder = Encoder {
            account: &mut account,
            buffer: String::new(),
            buffer_units: 0,
            regroup: String::new(),
            regroup_units: 0,
        };
        encoder.value(value);
        if !encoder.stopped() {
            encoder.flush_buffer();
            let rest = std::mem::take(&mut encoder.regroup);
            if !rest.is_empty() {
                encoder.account.part(&rest);
            }
        }
    }
    match account.failure {
        Some(overflow) => Err(overflow),
        None => Ok(()),
    }
}

/// The error REA answers when a retained Evidence does not fit the response budget.
pub fn budget_error(operation: &str, evidence_id: &str, overflow: &Overflow) -> NativeError {
    let advice = "Export retained evidence to consume the complete analysis, or use complete CLI JSON output.";
    let reason = if overflow.constraint == "string-length" {
        format!(
            "The operation completed, but its complete MCP response exceeds Node's single-string representation limit. {advice}"
        )
    } else {
        format!(
            "The operation completed, but its complete MCP response exceeds the stdio response budget. The analysis result was not truncated. {advice}"
        )
    };
    NativeError::Resource {
        operation: operation.to_string(),
        resource: "transport".to_string(),
        reason,
        reported_limits: json!({
            "boundary": "mcp-response",
            "default_receive_buffer_bytes": DEFAULT_RECEIVE_BUFFER,
            "result_budget_bytes": result_budget_bytes(),
            "max_string_code_units": RESULT_STRING_LIMIT,
            "response_bytes_at_least": overflow.bytes_at_least,
            "response_code_units_at_least": overflow.code_units_at_least,
            "constraint": overflow.constraint,
            "evidence_id": evidence_id,
            "evidence_reference": { "kind": "retained-evidence", "evidence_id": evidence_id },
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_results_fit() {
        assert!(check_budget(&json!({"a": [1, 2, {"b": "x"}]}), 10_000, true).is_ok());
    }

    #[test]
    fn a_result_over_the_budget_reports_the_running_total_at_the_part_that_crossed() {
        let big = json!({"text": "x".repeat(200_000)});
        let overflow = check_budget(&big, 100_000, true).unwrap_err();
        assert_eq!(overflow.constraint, "receive-buffer");
        // The first parts are the opening "{", the key and the quote, then 8192-unit pieces
        // regrouped to at most 64 K; the total only grows by whole regrouped parts.
        assert!(overflow.bytes_at_least > 100_000);
    }

    #[test]
    fn text_only_errors_count_the_escaped_copy_once() {
        let value = json!({"error": "a\"b"});
        assert!(check_budget(&value, 1000, false).is_ok());
    }
}
