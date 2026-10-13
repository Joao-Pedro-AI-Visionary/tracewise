//! Producer-side value contracts of the upstream IDA MCP servers
//! (port of `IdaProtocolValues.ts` and the result decoding of `IdaMcpConnection.ts`).
//!
//! REA validates every upstream answer with zod. This module keeps the same contracts and
//! reproduces zod 4's issue wording (`path: message; ...`, `$` for the root), because the
//! rendered text becomes the `reason` of an output error the caller sees.

use serde_json::{Map, Value};

/// A produced-data failure, with the issue wording zod 4 would give.
#[derive(Debug, Clone, PartialEq)]
pub struct Issue {
    pub path: Vec<String>,
    pub message: String,
    /// Type and literal mismatches abort a union branch; failed checks (length, pattern,
    /// range) only continue it.
    pub aborts: bool,
}

/// Parse one whole upstream value with a schema, failing with zod's rendered issues.
pub fn parse_value<T>(
    value: &Value,
    schema: impl Fn(Option<&Value>, &[String], &mut Issues) -> Option<T>,
) -> Result<T, super::connection::IdaFault> {
    let mut issues = Vec::new();
    match schema(Some(value), &[], &mut issues) {
        Some(parsed) if issues.is_empty() => Ok(parsed),
        _ => Err(super::connection::IdaFault::Malformed(render(&issues))),
    }
}

/// All issues of one parse, rendered like `ZodError.issues.map(...).join("; ")`.
pub fn render(issues: &[Issue]) -> String {
    issues
        .iter()
        .map(|issue| {
            let path = if issue.path.is_empty() {
                "$".to_string()
            } else {
                issue.path.join(".")
            };
            format!("{path}: {}", issue.message)
        })
        .collect::<Vec<_>>()
        .join("; ")
}

pub type Issues = Vec<Issue>;

fn push(issues: &mut Issues, path: &[String], message: String, aborts: bool) {
    issues.push(Issue {
        path: path.to_vec(),
        message,
        aborts,
    });
}

pub fn child(path: &[String], key: impl ToString) -> Vec<String> {
    let mut out = path.to_vec();
    out.push(key.to_string());
    out
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

fn mismatch(issues: &mut Issues, path: &[String], expected: &str, value: Option<&Value>) {
    push(
        issues,
        path,
        format!(
            "Invalid input: expected {expected}, received {}",
            received(value)
        ),
        true,
    );
}

// ------------------------------------------------------------------ primitives

pub fn string(value: Option<&Value>, path: &[String], issues: &mut Issues) -> Option<String> {
    match value {
        Some(Value::String(text)) => Some(text.clone()),
        other => {
            mismatch(issues, path, "string", other);
            None
        }
    }
}

pub fn string_min1(value: Option<&Value>, path: &[String], issues: &mut Issues) -> Option<String> {
    let text = string(value, path, issues)?;
    if text.is_empty() {
        push(
            issues,
            path,
            "Too small: expected string to have >=1 characters".to_string(),
            false,
        );
        return None;
    }
    Some(text)
}

pub fn boolean(value: Option<&Value>, path: &[String], issues: &mut Issues) -> Option<bool> {
    match value {
        Some(Value::Bool(flag)) => Some(*flag),
        other => {
            mismatch(issues, path, "boolean", other);
            None
        }
    }
}

/// `z.number().int().nonnegative()`.
pub fn uint(value: Option<&Value>, path: &[String], issues: &mut Issues) -> Option<u64> {
    let Some(Value::Number(number)) = value else {
        mismatch(issues, path, "number", value);
        return None;
    };
    let as_float = number.as_f64().unwrap_or(f64::NAN);
    if as_float.fract() != 0.0 || !as_float.is_finite() {
        push(
            issues,
            path,
            "Invalid input: expected int, received number".to_string(),
            false,
        );
        return None;
    }
    if as_float < 0.0 {
        push(
            issues,
            path,
            "Too small: expected number to be >=0".to_string(),
            false,
        );
        return None;
    }
    Some(as_float as u64)
}

/// A hexadecimal coordinate, normalized to lowercase `0x` form without leading zeros.
pub fn normalize_address(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let digits = lower.strip_prefix("0x").unwrap_or(&lower);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let trimmed = digits.trim_start_matches('0');
    Some(format!(
        "0x{}",
        if trimmed.is_empty() { "0" } else { trimmed }
    ))
}

/// `idaAddressSchema`.
pub fn address(value: Option<&Value>, path: &[String], issues: &mut Issues) -> Option<String> {
    let text = string(value, path, issues)?;
    match normalize_address(&text) {
        Some(normalized) => Some(normalized),
        None => {
            push(
                issues,
                path,
                "Invalid string: must match pattern /^(?:0x)?[0-9a-f]+$/iu".to_string(),
                false,
            );
            None
        }
    }
}

pub fn object<'a>(
    value: Option<&'a Value>,
    path: &[String],
    issues: &mut Issues,
) -> Option<&'a Map<String, Value>> {
    match value {
        Some(Value::Object(map)) => Some(map),
        other => {
            mismatch(issues, path, "object", other);
            None
        }
    }
}

pub fn array<'a>(
    value: Option<&'a Value>,
    path: &[String],
    issues: &mut Issues,
) -> Option<&'a Vec<Value>> {
    match value {
        Some(Value::Array(items)) => Some(items),
        other => {
            mismatch(issues, path, "array", other);
            None
        }
    }
}

/// `.length(1)` on an array of objects.
pub fn exactly_one<'a>(
    value: Option<&'a Value>,
    path: &[String],
    issues: &mut Issues,
) -> Option<&'a Value> {
    let items = array(value, path, issues)?;
    match items.len() {
        1 => Some(&items[0]),
        0 => {
            push(
                issues,
                path,
                "Too small: expected array to have >=1 items".to_string(),
                false,
            );
            None
        }
        _ => {
            push(
                issues,
                path,
                "Too big: expected array to have <=1 items".to_string(),
                false,
            );
            None
        }
    }
}

fn each<T>(
    items: &[Value],
    path: &[String],
    issues: &mut Issues,
    parse: impl Fn(Option<&Value>, &[String], &mut Issues) -> Option<T>,
) -> Option<Vec<T>> {
    let mut out = Vec::with_capacity(items.len());
    let mut ok = true;
    for (index, item) in items.iter().enumerate() {
        match parse(Some(item), &child(path, index), issues) {
            Some(parsed) => out.push(parsed),
            None => ok = false,
        }
    }
    ok.then_some(out)
}

pub fn array_of<T>(
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
    parse: impl Fn(Option<&Value>, &[String], &mut Issues) -> Option<T>,
) -> Option<Vec<T>> {
    let items = array(value, path, issues)?;
    each(items, path, issues, parse)
}

/// `.nullable()`: `Some(None)` is an accepted null.
pub fn nullable<T>(
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
    parse: impl Fn(Option<&Value>, &[String], &mut Issues) -> Option<T>,
) -> Option<Option<T>> {
    match value {
        Some(Value::Null) => Some(None),
        other => parse(other, path, issues).map(Some),
    }
}

/// `.optional()`: absent is accepted, null is not.
pub fn optional<T>(
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
    parse: impl Fn(Option<&Value>, &[String], &mut Issues) -> Option<T>,
) -> Option<Option<T>> {
    match value {
        None => Some(None),
        other => parse(other, path, issues).map(Some),
    }
}

/// `.nullish()`.
pub fn nullish<T>(
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
    parse: impl Fn(Option<&Value>, &[String], &mut Issues) -> Option<T>,
) -> Option<Option<T>> {
    match value {
        None | Some(Value::Null) => Some(None),
        other => parse(other, path, issues).map(Some),
    }
}

/// `z.union([a, b])` with zod 4's reporting rule: exactly one branch that only failed
/// checks surfaces its own issues, otherwise a single `Invalid input`.
pub fn union2<T>(
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
    first: impl Fn(Option<&Value>, &[String], &mut Issues) -> Option<T>,
    second: impl Fn(Option<&Value>, &[String], &mut Issues) -> Option<T>,
) -> Option<T> {
    let mut left = Vec::new();
    if let Some(parsed) = first(value, path, &mut left) {
        if left.is_empty() {
            return Some(parsed);
        }
    }
    let mut right = Vec::new();
    if let Some(parsed) = second(value, path, &mut right) {
        if right.is_empty() {
            return Some(parsed);
        }
    }
    let branches = [left, right];
    let non_aborted: Vec<&Issues> = branches
        .iter()
        .filter(|branch| branch.iter().all(|issue| !issue.aborts))
        .collect();
    if non_aborted.len() == 1 {
        issues.extend(non_aborted[0].iter().cloned());
    } else {
        push(issues, path, "Invalid input".to_string(), true);
    }
    None
}

// ------------------------------------------------------------------ schemas

/// A function observation; `size` is an enclosing span, never a complete body.
#[derive(Debug, Clone, PartialEq)]
pub struct IdaFunction {
    pub address: String,
    pub name: String,
    pub size: String,
}

fn function_with(
    key: &'static str,
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
) -> Option<IdaFunction> {
    let map = object(value, path, issues)?;
    let address = address(map.get(key), &child(path, key), issues);
    let name = string_min1(map.get("name"), &child(path, "name"), issues);
    let size = string(map.get("size"), &child(path, "size"), issues);
    Some(IdaFunction {
        address: address?,
        name: name?,
        size: size?,
    })
}

/// `idaFunctionSchema`: `address` (legacy) or `addr` (modern) spelling.
pub fn function(
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
) -> Option<IdaFunction> {
    union2(
        value,
        path,
        issues,
        |v, p, i| function_with("address", v, p, i),
        |v, p, i| function_with("addr", v, p, i),
    )
}

/// `legacyMetadataSchema` (passthrough).
#[derive(Debug, Clone)]
pub struct LegacyMetadata {
    pub path: String,
    pub sha256: String,
    pub base: String,
}

pub fn legacy_metadata(
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
) -> Option<LegacyMetadata> {
    let map = object(value, path, issues)?;
    let file = string_min1(map.get("path"), &child(path, "path"), issues);
    let module = string(map.get("module"), &child(path, "module"), issues);
    let sha = map.get("sha256");
    let sha256 = match string(sha, &child(path, "sha256"), issues) {
        Some(text) => {
            if text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
                Some(text)
            } else {
                push(
                    issues,
                    &child(path, "sha256"),
                    "Invalid string: must match pattern /^[0-9a-f]{64}$/iu".to_string(),
                    false,
                );
                None
            }
        }
        None => None,
    };
    let base = address(map.get("base"), &child(path, "base"), issues);
    module?;
    Some(LegacyMetadata {
        path: file?,
        sha256: sha256?,
        base: base?,
    })
}

/// `modernHealthSchema` (passthrough).
#[derive(Debug, Clone)]
pub struct ModernHealth {
    pub input_path: String,
    pub idb_path: Option<String>,
    pub imagebase: String,
    pub auto_analysis_ready: Option<bool>,
}

pub fn modern_health(
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
) -> Option<ModernHealth> {
    let map = object(value, path, issues)?;
    let status_path = child(path, "status");
    let status_ok = match map.get("status") {
        Some(Value::String(s)) if s == "ok" => true,
        other => {
            let _ = other;
            push(
                issues,
                &status_path,
                "Invalid input: expected \"ok\"".to_string(),
                true,
            );
            false
        }
    };
    let input_path = string_min1(map.get("input_path"), &child(path, "input_path"), issues);
    let idb_path = nullable(
        map.get("idb_path"),
        &child(path, "idb_path"),
        issues,
        string,
    );
    let imagebase = address(map.get("imagebase"), &child(path, "imagebase"), issues);
    let ready = nullable(
        map.get("auto_analysis_ready"),
        &child(path, "auto_analysis_ready"),
        issues,
        boolean,
    );
    let module = string(map.get("module"), &child(path, "module"), issues);
    if !status_ok {
        return None;
    }
    module?;
    Some(ModernHealth {
        input_path: input_path?,
        idb_path: idb_path?,
        imagebase: imagebase?,
        auto_analysis_ready: ready?,
    })
}

/// An upstream cursor either finishes or names the next offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cursor {
    Next(u64),
    Done,
}

pub fn cursor(value: Option<&Value>, path: &[String], issues: &mut Issues) -> Option<Cursor> {
    union2(
        value,
        path,
        issues,
        |v, p, i| {
            let map = object(v, p, i)?;
            uint(map.get("next"), &child(p, "next"), i).map(Cursor::Next)
        },
        |v, p, i| {
            let map = object(v, p, i)?;
            match map.get("done") {
                Some(Value::Bool(true)) => Some(Cursor::Done),
                _ => {
                    push(
                        i,
                        &child(p, "done"),
                        "Invalid input: expected true".to_string(),
                        true,
                    );
                    None
                }
            }
        },
    )
}

/// `legacyPageSchema` / one element of `modernPageSchema`.
#[derive(Debug, Clone)]
pub struct Page {
    pub data: Vec<Value>,
    pub next_offset: Option<u64>,
}

pub fn page(value: Option<&Value>, path: &[String], issues: &mut Issues) -> Option<Page> {
    let map = object(value, path, issues)?;
    let data = array(map.get("data"), &child(path, "data"), issues).cloned();
    let next = nullable(
        map.get("next_offset"),
        &child(path, "next_offset"),
        issues,
        uint,
    );
    Some(Page {
        data: data?,
        next_offset: next?,
    })
}

pub fn modern_page(value: Option<&Value>, path: &[String], issues: &mut Issues) -> Option<Page> {
    let only = exactly_one(value, path, issues)?;
    page(Some(only), &child(path, 0), issues)
}

/// One modern lookup answer.
#[derive(Debug, Clone)]
pub struct Lookup {
    pub function: Option<IdaFunction>,
    pub error: Option<String>,
}

pub fn modern_lookup(
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
) -> Option<Lookup> {
    let only = exactly_one(value, path, issues)?;
    let item_path = child(path, 0);
    let map = object(Some(only), &item_path, issues)?;
    let query = string(map.get("query"), &child(&item_path, "query"), issues);
    let function = nullable(map.get("fn"), &child(&item_path, "fn"), issues, function);
    let error = nullable(
        map.get("error"),
        &child(&item_path, "error"),
        issues,
        string,
    );
    query?;
    Some(Lookup {
        function: function?,
        error: error?,
    })
}

#[derive(Debug, Clone)]
pub struct Instruction {
    pub address: String,
    pub instruction: String,
}

fn instruction_with(
    key: &'static str,
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
) -> Option<Instruction> {
    let map = object(value, path, issues)?;
    let address = address(map.get(key), &child(path, key), issues);
    let instruction = string(map.get("instruction"), &child(path, "instruction"), issues);
    let comments = nullish(
        map.get("comments"),
        &child(path, "comments"),
        issues,
        |v, p, i| array_of(v, p, i, string),
    );
    comments?;
    Some(Instruction {
        address: address?,
        instruction: instruction?,
    })
}

fn instruction(value: Option<&Value>, path: &[String], issues: &mut Issues) -> Option<Instruction> {
    union2(
        value,
        path,
        issues,
        |v, p, i| instruction_with("address", v, p, i),
        |v, p, i| instruction_with("addr", v, p, i),
    )
}

/// `disassemblySchema`.
#[derive(Debug, Clone)]
pub struct Disassembly {
    pub name: String,
    pub start_ea: String,
    pub lines: Vec<Instruction>,
    pub return_type: Option<String>,
    pub arguments: Option<Vec<(String, String)>>,
}

pub fn disassembly(
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
) -> Option<Disassembly> {
    let map = object(value, path, issues)?;
    let name = string(map.get("name"), &child(path, "name"), issues);
    let start_ea = address(map.get("start_ea"), &child(path, "start_ea"), issues);
    let lines = array_of(map.get("lines"), &child(path, "lines"), issues, instruction);
    let return_type = nullish(
        map.get("return_type"),
        &child(path, "return_type"),
        issues,
        string,
    );
    let arguments = nullish(
        map.get("arguments"),
        &child(path, "arguments"),
        issues,
        |v, p, i| {
            array_of(v, p, i, |v, p, i| {
                let map = object(v, p, i)?;
                let name = string(map.get("name"), &child(p, "name"), i);
                let kind = string(map.get("type"), &child(p, "type"), i);
                Some((name?, kind?))
            })
        },
    );
    Some(Disassembly {
        name: name?,
        start_ea: start_ea?,
        lines: lines?,
        return_type: return_type?,
        arguments: arguments?,
    })
}

/// `modernDisassemblySchema`.
pub struct ModernDisassembly {
    pub asm: Option<Disassembly>,
    pub error: Option<String>,
    pub cursor: Cursor,
}

pub fn modern_disassembly(
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
) -> Option<ModernDisassembly> {
    let map = object(value, path, issues)?;
    let asm = nullable(map.get("asm"), &child(path, "asm"), issues, disassembly);
    let error = optional(map.get("error"), &child(path, "error"), issues, string);
    let cursor = cursor(map.get("cursor"), &child(path, "cursor"), issues);
    Some(ModernDisassembly {
        asm: asm?,
        error: error?,
        cursor: cursor?,
    })
}

/// `modernDecompileSchema`.
pub struct ModernDecompile {
    pub code: Option<String>,
    pub error: Option<String>,
    pub cursor: Cursor,
}

pub fn modern_decompile(
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
) -> Option<ModernDecompile> {
    let map = object(value, path, issues)?;
    let code = nullable(map.get("code"), &child(path, "code"), issues, string);
    let error = optional(map.get("error"), &child(path, "error"), issues, string);
    let cursor = cursor(map.get("cursor"), &child(path, "cursor"), issues);
    let line_count = optional(
        map.get("line_count"),
        &child(path, "line_count"),
        issues,
        uint,
    );
    let total_lines = optional(
        map.get("total_lines"),
        &child(path, "total_lines"),
        issues,
        uint,
    );
    line_count?;
    total_lines?;
    Some(ModernDecompile {
        code: code?,
        error: error?,
        cursor: cursor?,
    })
}

/// `legacyStringSchema`.
pub fn legacy_string(
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
) -> Option<(String, String)> {
    let map = object(value, path, issues)?;
    let addr = address(map.get("address"), &child(path, "address"), issues);
    let text = string(map.get("string"), &child(path, "string"), issues);
    let length = uint(map.get("length"), &child(path, "length"), issues);
    length?;
    Some((addr?, text?))
}

/// `modernStringsSchema`.
pub fn modern_strings(
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
) -> Option<(Vec<(String, String)>, Cursor)> {
    let map = object(value, path, issues)?;
    let matches = array_of(
        map.get("matches"),
        &child(path, "matches"),
        issues,
        |v, p, i| {
            let item = object(v, p, i)?;
            let addr = address(item.get("addr"), &child(p, "addr"), i);
            let text = string(item.get("string"), &child(p, "string"), i);
            Some((addr?, text?))
        },
    );
    let cursor = cursor(map.get("cursor"), &child(path, "cursor"), issues);
    Some((matches?, cursor?))
}

/// One cross reference: source address, kind, enclosing function.
#[derive(Debug, Clone)]
pub struct Xref {
    pub address: String,
    pub kind: String,
}

/// `legacyXrefsSchema`.
pub fn legacy_xrefs(
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
) -> Option<Vec<Xref>> {
    array_of(value, path, issues, |v, p, i| {
        let map = object(v, p, i)?;
        let addr = address(map.get("address"), &child(p, "address"), i);
        let kind = string(map.get("type"), &child(p, "type"), i);
        let function = nullable(map.get("function"), &child(p, "function"), i, function);
        function?;
        Some(Xref {
            address: addr?,
            kind: kind?,
        })
    })
}

/// `modernXrefsSchema`.
pub struct ModernXrefs {
    pub xrefs: Option<Vec<Xref>>,
    pub error: Option<String>,
    pub more: Option<bool>,
}

pub fn modern_xrefs(
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
) -> Option<ModernXrefs> {
    let only = exactly_one(value, path, issues)?;
    let item_path = child(path, 0);
    let map = object(Some(only), &item_path, issues)?;
    let xrefs = nullable(
        map.get("xrefs"),
        &child(&item_path, "xrefs"),
        issues,
        |v, p, i| {
            array_of(v, p, i, |v, p, i| {
                let item = object(v, p, i)?;
                let addr = address(item.get("addr"), &child(p, "addr"), i);
                let kind = string(item.get("type"), &child(p, "type"), i);
                let function = nullable(item.get("fn"), &child(p, "fn"), i, function);
                function?;
                Some(Xref {
                    address: addr?,
                    kind: kind?,
                })
            })
        },
    );
    let error = optional(
        map.get("error"),
        &child(&item_path, "error"),
        issues,
        string,
    );
    let more = optional(map.get("more"), &child(&item_path, "more"), issues, boolean);
    Some(ModernXrefs {
        xrefs: xrefs?,
        error: error?,
        more: more?,
    })
}

/// A callee as the modern `callees` tool reports it.
#[derive(Debug, Clone)]
pub struct ModernCallee {
    pub address: String,
    pub name: String,
    pub external: bool,
}

pub struct ModernCallees {
    pub callees: Option<Vec<ModernCallee>>,
    pub error: Option<String>,
    pub more: Option<bool>,
}

pub fn modern_callees(
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
) -> Option<ModernCallees> {
    let only = exactly_one(value, path, issues)?;
    let item_path = child(path, 0);
    let map = object(Some(only), &item_path, issues)?;
    let callees = nullable(
        map.get("callees"),
        &child(&item_path, "callees"),
        issues,
        |v, p, i| {
            array_of(v, p, i, |v, p, i| {
                let item = object(v, p, i)?;
                let addr = address(item.get("addr"), &child(p, "addr"), i);
                let name = string(item.get("name"), &child(p, "name"), i);
                let kind_path = child(p, "type");
                let external = match item.get("type") {
                    Some(Value::String(kind)) if kind == "internal" => Some(false),
                    Some(Value::String(kind)) if kind == "external" => Some(true),
                    _ => {
                        push(
                            i,
                            &kind_path,
                            "Invalid option: expected one of \"internal\"|\"external\"".to_string(),
                            true,
                        );
                        None
                    }
                };
                Some(ModernCallee {
                    address: addr?,
                    name: name?,
                    external: external?,
                })
            })
        },
    );
    let error = optional(
        map.get("error"),
        &child(&item_path, "error"),
        issues,
        string,
    );
    let more = optional(map.get("more"), &child(&item_path, "more"), issues, boolean);
    Some(ModernCallees {
        callees: callees?,
        error: error?,
        more: more?,
    })
}

/// `legacyCalleesSchema` (passthrough): address, name and the optional upstream `type`.
#[derive(Debug, Clone)]
pub struct LegacyCallee {
    pub address: String,
    pub name: String,
    pub external: bool,
}

pub fn legacy_callees(
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
) -> Option<Vec<LegacyCallee>> {
    array_of(value, path, issues, |v, p, i| {
        let map = object(v, p, i)?;
        let addr = address(map.get("address"), &child(p, "address"), i);
        let name = string(map.get("name"), &child(p, "name"), i);
        let external = matches!(map.get("type"), Some(Value::String(kind)) if kind == "external");
        Some(LegacyCallee {
            address: addr?,
            name: name?,
            external,
        })
    })
}

/// `z.array(idaFunctionSchema)`.
pub fn functions(
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
) -> Option<Vec<IdaFunction>> {
    array_of(value, path, issues, function)
}

/// Opening a database: the session the worker registered.
#[derive(Debug, Clone)]
pub struct OpenedSession {
    pub session_id: String,
    pub input_path: String,
}

pub fn open_database(
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
) -> Option<OpenedSession> {
    let map = object(value, path, issues)?;
    let success_ok = matches!(map.get("success"), Some(Value::Bool(true)));
    if !success_ok {
        push(
            issues,
            &child(path, "success"),
            "Invalid input: expected true".to_string(),
            true,
        );
    }
    let session_path = child(path, "session");
    let session = object(map.get("session"), &session_path, issues).and_then(|session| {
        let id = string_min1(
            session.get("session_id"),
            &child(&session_path, "session_id"),
            issues,
        );
        let input = string_min1(
            session.get("input_path"),
            &child(&session_path, "input_path"),
            issues,
        );
        Some(OpenedSession {
            session_id: id?,
            input_path: input?,
        })
    });
    if !success_ok {
        return None;
    }
    session
}

#[derive(Debug, Clone)]
pub struct DatabaseEntry {
    pub session_id: String,
    pub input_path: String,
    pub owned: bool,
    pub worker: bool,
    pub is_active: bool,
}

pub fn database_list(
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
) -> Option<Vec<DatabaseEntry>> {
    let map = object(value, path, issues)?;
    let sessions_path = child(path, "sessions");
    array_of(map.get("sessions"), &sessions_path, issues, |v, p, i| {
        let item = object(v, p, i)?;
        let id = string(item.get("session_id"), &child(p, "session_id"), i);
        let input = string(item.get("input_path"), &child(p, "input_path"), i);
        let owned = boolean(item.get("owned"), &child(p, "owned"), i);
        let backend = backend(item.get("backend"), &child(p, "backend"), i);
        let active = boolean(item.get("is_active"), &child(p, "is_active"), i);
        Some(DatabaseEntry {
            session_id: id?,
            input_path: input?,
            owned: owned?,
            worker: backend? == "worker",
            is_active: active?,
        })
    })
}

fn backend(value: Option<&Value>, path: &[String], issues: &mut Issues) -> Option<String> {
    match value {
        Some(Value::String(kind)) if kind == "worker" || kind == "gui" => Some(kind.clone()),
        _ => {
            push(
                issues,
                path,
                "Invalid option: expected one of \"worker\"|\"gui\"".to_string(),
                true,
            );
            None
        }
    }
}

/// Result of `idb_close`.
#[derive(Debug, Clone)]
pub struct ClosedDatabase {
    pub session_id: String,
    pub saved: Option<bool>,
    pub owned: bool,
    pub worker: bool,
}

pub fn close_database(
    value: Option<&Value>,
    path: &[String],
    issues: &mut Issues,
) -> Option<ClosedDatabase> {
    let map = object(value, path, issues)?;
    let success_ok = matches!(map.get("success"), Some(Value::Bool(true)));
    if !success_ok {
        push(
            issues,
            &child(path, "success"),
            "Invalid input: expected true".to_string(),
            true,
        );
    }
    let id = string(map.get("session_id"), &child(path, "session_id"), issues);
    let saved = nullish(map.get("saved"), &child(path, "saved"), issues, boolean);
    let owned = boolean(map.get("owned"), &child(path, "owned"), issues);
    let kind = backend(map.get("backend"), &child(path, "backend"), issues);
    if !success_ok {
        return None;
    }
    Some(ClosedDatabase {
        session_id: id?,
        saved: saved?,
        owned: owned?,
        worker: kind? == "worker",
    })
}

// ------------------------------------------------------------------ MCP result decoding

/// Why an upstream tool result cannot establish an observation.
#[derive(Debug, Clone, PartialEq)]
pub enum DecodeFailure {
    /// `AnalysisProtocolError`.
    Protocol(String),
    /// A zod failure of the result envelope.
    Malformed(String),
}

/// Decode Python FastMCP's scalar wrapper without dropping structured dictionaries
/// (port of `decodeIdaToolResult`). `raw` is the MCP `CallToolResult` as JSON.
pub fn decode_tool_result(raw: &Value) -> Result<Value, DecodeFailure> {
    let mut issues = Vec::new();
    let path: Vec<String> = Vec::new();
    let root = object(Some(raw), &path, &mut issues);
    let mut blocks: Vec<String> = Vec::new();
    let mut is_error = false;
    let mut structured: Option<&Map<String, Value>> = None;
    let mut truncated = false;
    let mut hint: Option<String> = None;
    if let Some(root) = root {
        if let Some(flag) = optional(
            root.get("isError"),
            &child(&path, "isError"),
            &mut issues,
            boolean,
        ) {
            is_error = flag.unwrap_or(false);
        }
        match root.get("structuredContent") {
            None => {}
            Some(Value::Object(map)) => structured = Some(map),
            other => mismatch(
                &mut issues,
                &child(&path, "structuredContent"),
                "record",
                other,
            ),
        }
        let content_path = child(&path, "content");
        if let Some(items) = array(root.get("content"), &content_path, &mut issues) {
            for (index, item) in items.iter().enumerate() {
                let item_path = child(&content_path, index);
                let Some(block) = object(Some(item), &item_path, &mut issues) else {
                    continue;
                };
                let kind = string(block.get("type"), &child(&item_path, "type"), &mut issues);
                let text = optional(
                    block.get("text"),
                    &child(&item_path, "text"),
                    &mut issues,
                    string,
                );
                if let (Some(kind), Some(Some(text))) = (kind, text) {
                    if kind == "text" {
                        blocks.push(text);
                    }
                }
            }
        }
        if let Some(meta) = root.get("_meta") {
            if let Some(ida) = meta.get("ida_mcp") {
                truncated = ida.get("output_truncated") == Some(&Value::Bool(true));
                hint = ida
                    .get("download_hint")
                    .and_then(Value::as_str)
                    .map(str::to_string);
            }
        }
    }
    if !issues.is_empty() {
        return Err(DecodeFailure::Malformed(render(&issues)));
    }
    if is_error {
        return Err(DecodeFailure::Protocol(format!(
            "IDA MCP tool failed: {}",
            blocks.join("\n")
        )));
    }
    if truncated {
        return Err(DecodeFailure::Protocol(format!(
            "IDA MCP truncated its output; the preview cannot establish a complete observation. {}",
            hint.unwrap_or_else(|| {
                "Use the upstream output download workflow to retrieve the full result.".to_string()
            })
        )));
    }
    if let Some(map) = structured {
        if map.len() == 1 {
            if let Some(inner) = map.get("result") {
                return Ok(inner.clone());
            }
        }
        return Ok(Value::Object(map.clone()));
    }
    if blocks.len() != 1 {
        return Err(DecodeFailure::Protocol(
            "IDA MCP omitted a single structured or text result; unsupported content cannot establish an empty observation."
                .to_string(),
        ));
    }
    let text = &blocks[0];
    Ok(serde_json::from_str::<Value>(text).unwrap_or_else(|_| Value::String(text.clone())))
}
