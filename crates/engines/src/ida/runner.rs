//! Analyst questions as a closed set of read-only upstream requests
//! (port of `IdaOperationRunner.ts`).
//!
//! Two upstream tool families exist: the legacy 1.4 profile (attached mode) and the modern
//! database-supervisor profile (headless mode). Neither is ever asked to mutate anything.

use serde_json::{json, Value};
use tracewise_domain::evidence::EvidenceLocation;

use crate::error::AnalysisError;
use crate::provider::tokio_util_lite::CancelToken;

use super::capabilities::ida_limitations;
use super::connection::{scoped, IdaConnection, IdaFault};
use super::protocol::{self as p, parse_value as parse, Cursor, IdaFunction};
use super::search;

const UNKNOWN_BODY_REASON: &str = "IDA MCP does not report complete function body ranges.";

/// Which upstream tool family answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Legacy,
    Modern,
}

fn unknown_body() -> Value {
    json!({ "available": false, "reason": UNKNOWN_BODY_REASON })
}

/// A procedure identity with the facets this adapter cannot observe left unknown.
fn identity(address: &str, name: &str) -> Value {
    json!({
        "address": address,
        "name": name,
        "classification": Value::Null,
        "body": unknown_body(),
    })
}

fn identity_of(function: &IdaFunction) -> Value {
    identity(&function.address, &function.name)
}

fn instruction_lines(assembly: &p::Disassembly) -> Vec<String> {
    assembly
        .lines
        .iter()
        .map(|line| format!("{}: {}", line.address, line.instruction))
        .collect()
}

/// Insertion-ordered map where a repeated key keeps its first position (a JS `Map`).
#[derive(Default)]
struct OrderedIdentities(Vec<(String, Value)>);

impl OrderedIdentities {
    fn set(&mut self, key: String, value: Value) {
        match self.0.iter_mut().find(|(existing, _)| *existing == key) {
            Some(slot) => slot.1 = value,
            None => self.0.push((key, value)),
        }
    }
}

pub struct Runner<'a> {
    connection: &'a dyn IdaConnection,
    protocol: Protocol,
    database: Option<String>,
    cancel: &'a CancelToken,
    /// Every upstream observation of this run: tool, scoped arguments, decoded result.
    pub raw: Vec<Value>,
    pub locations: Vec<EvidenceLocation>,
    pub limitations: Vec<String>,
}

impl<'a> Runner<'a> {
    pub fn new(
        connection: &'a dyn IdaConnection,
        protocol: Protocol,
        database: Option<String>,
        cancel: &'a CancelToken,
    ) -> Self {
        Self {
            connection,
            protocol,
            database,
            cancel,
            raw: Vec::new(),
            locations: Vec::new(),
            limitations: Vec::new(),
        }
    }

    fn legacy(&self) -> bool {
        self.protocol == Protocol::Legacy
    }

    async fn call(&mut self, tool: &str, args: Value) -> Result<Value, IdaFault> {
        if self.cancel.is_cancelled() {
            return Err(IdaFault::analysis(AnalysisError::cancelled(tool)));
        }
        let arguments = scoped(&args, self.database.as_deref());
        let result = self.connection.call(tool, &arguments).await?;
        self.raw
            .push(json!({ "tool": tool, "arguments": arguments, "result": result }));
        if self.cancel.is_cancelled() {
            return Err(IdaFault::analysis(AnalysisError::cancelled(tool)));
        }
        Ok(result)
    }

    async fn functions(&mut self) -> Result<Vec<IdaFunction>, IdaFault> {
        let mut result = Vec::new();
        let mut offset = Some(0u64);
        while let Some(current) = offset {
            let page = if self.legacy() {
                let value = self
                    .call("list_functions", json!({ "offset": current, "count": 100 }))
                    .await?;
                parse(&value, p::page)?
            } else {
                let value = self
                    .call(
                        "list_funcs",
                        json!({ "queries": { "offset": current, "count": 100 } }),
                    )
                    .await?;
                parse(&value, p::modern_page)?
            };
            for item in &page.data {
                result.push(parse(item, p::function)?);
            }
            offset = page.next_offset;
            if matches!(offset, Some(next) if next <= current) {
                return Err(IdaFault::protocol(
                    "IDA MCP function pagination did not advance.",
                ));
            }
        }
        Ok(result)
    }

    pub async fn resolve(&mut self, query: &str) -> Result<IdaFunction, IdaFault> {
        if !self.legacy() {
            let value = self
                .call("lookup_funcs", json!({ "queries": [query] }))
                .await?;
            let item = parse(&value, p::modern_lookup)?;
            return match (item.function, item.error) {
                (Some(function), None) => Ok(function),
                (_, error) => Err(IdaFault::protocol(format!(
                    "IDA function lookup failed for {query}: {}",
                    error.unwrap_or_else(|| "missing function".to_string())
                ))),
            };
        }
        let explicit = if query
            .get(..2)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("0x"))
        {
            p::normalize_address(query)
        } else {
            None
        };
        let value = match &explicit {
            Some(address) => {
                self.call("get_function_by_address", json!({ "address": address }))
                    .await?
            }
            None => {
                self.call("get_function_by_name", json!({ "name": query }))
                    .await?
            }
        };
        let found = parse(&value, p::function)?;
        // Legacy producers may echo an interior query or call site in `address`. Resolve the
        // reported symbol again to obtain its actual entry, never infer it from the size.
        let value = self
            .call("get_function_by_name", json!({ "name": found.name }))
            .await?;
        let entry = parse(&value, p::function)?;
        if entry.name != found.name {
            return Err(IdaFault::protocol(
                "IDA function identity changed during lookup.",
            ));
        }
        Ok(entry)
    }

    async fn strings(&mut self) -> Result<Vec<(String, String)>, IdaFault> {
        let mut result = Vec::new();
        let mut offset = Some(0u64);
        while let Some(current) = offset {
            if self.legacy() {
                let value = self
                    .call("list_strings", json!({ "offset": current, "count": 100 }))
                    .await?;
                let page = parse(&value, p::page)?;
                for item in &page.data {
                    result.push(parse(item, p::legacy_string)?);
                }
                offset = page.next_offset;
            } else {
                let value = self
                    .call(
                        "find_regex",
                        json!({ "pattern": "(?s).*", "offset": current, "limit": 100 }),
                    )
                    .await?;
                let (matches, cursor) = parse(&value, p::modern_strings)?;
                result.extend(matches);
                offset = next_offset(cursor, current)?;
            }
            if matches!(offset, Some(next) if next <= current) {
                return Err(IdaFault::protocol(
                    "IDA MCP string pagination did not advance.",
                ));
            }
        }
        Ok(result)
    }

    async fn assembly(&mut self, function: &IdaFunction) -> Result<p::Disassembly, IdaFault> {
        if self.legacy() {
            let value = self
                .call(
                    "disassemble_function",
                    json!({ "start_address": function.address }),
                )
                .await?;
            let assembly = parse(&value, p::disassembly)?;
            verify_assembly(function, &assembly)?;
            return Ok(assembly);
        }
        let mut result: Option<p::Disassembly> = None;
        let mut offset = Some(0u64);
        while let Some(current) = offset {
            let value = self
                .call(
                    "disasm",
                    json!({ "addr": function.address, "offset": current, "max_instructions": 100 }),
                )
                .await?;
            let page = parse(&value, p::modern_disassembly)?;
            let assembly = match (page.asm, page.error) {
                (Some(asm), None) => asm,
                (_, error) => {
                    return Err(IdaFault::protocol(format!(
                        "IDA disassembly failed: {}",
                        error.unwrap_or_else(|| "missing assembly".to_string())
                    )))
                }
            };
            verify_assembly(function, &assembly)?;
            match result.as_mut() {
                None => result = Some(assembly),
                Some(existing) => existing.lines.extend(assembly.lines),
            }
            offset = next_offset(page.cursor, current)?;
        }
        result.ok_or_else(|| IdaFault::protocol("IDA omitted assembly."))
    }

    async fn pseudocode(&mut self, function: &IdaFunction) -> Result<Option<String>, IdaFault> {
        if self.legacy() {
            let value = self
                .call("decompile_function", json!({ "address": function.address }))
                .await?;
            return parse(&value, |v, path, issues| {
                p::nullable(v, path, issues, p::string)
            });
        }
        let mut result: Vec<String> = Vec::new();
        let mut offset = Some(0u64);
        while let Some(current) = offset {
            let value = self
                .call(
                    "decompile",
                    json!({ "addr": function.address, "offset": current, "max_lines": 100 }),
                )
                .await?;
            let page = parse(&value, p::modern_decompile)?;
            let code = match (page.code, page.error) {
                (Some(code), None) => code,
                (_, error) => {
                    return Err(IdaFault::protocol(format!(
                        "IDA decompilation failed: {}",
                        error.unwrap_or_else(|| "missing code".to_string())
                    )))
                }
            };
            result.push(code);
            offset = next_offset(page.cursor, current)?;
        }
        Ok(Some(result.join("\n")))
    }

    async fn xrefs(&mut self, address: &str) -> Result<Vec<p::Xref>, IdaFault> {
        if self.legacy() {
            let value = self
                .call("get_xrefs_to", json!({ "address": address }))
                .await?;
            return parse(&value, p::legacy_xrefs);
        }
        let value = self
            .call("xrefs_to", json!({ "addrs": [address], "limit": 1000 }))
            .await?;
        let page = parse(&value, p::modern_xrefs)?;
        let xrefs = match (page.xrefs, page.error) {
            (Some(xrefs), None) => xrefs,
            (_, error) => {
                return Err(IdaFault::protocol(format!(
                    "IDA xrefs failed: {}",
                    error.unwrap_or_else(|| "missing references".to_string())
                )))
            }
        };
        if page.more == Some(true) {
            self.limitations.push(
                "Upstream xrefs_to capped results at 1000 references; additional references remain unknown."
                    .to_string(),
            );
        }
        Ok(xrefs)
    }

    /// Callers or callees as procedure identities: externals first as reported, then the
    /// resolved internal entries, each address once.
    async fn relationships(
        &mut self,
        function: &IdaFunction,
        callers: bool,
    ) -> Result<Vec<Value>, IdaFault> {
        let mut queries: Vec<String> = Vec::new();
        let mut result = OrderedIdentities::default();
        if self.legacy() {
            let tool = if callers {
                "get_callers"
            } else {
                "get_callees"
            };
            let value = self
                .call(tool, json!({ "function_address": function.address }))
                .await?;
            if callers {
                for item in parse(&value, p::functions)? {
                    queries.push(item.name);
                }
            } else {
                for item in parse(&value, p::legacy_callees)? {
                    if item.external {
                        let identity = identity(&item.address, &item.name);
                        result.set(item.address, identity);
                    } else {
                        queries.push(item.name);
                    }
                }
            }
        } else if callers {
            self.limitations.push(
                "Modern upstream xrefs classify references as code or data, without proving call edges. Direct callers are unavailable in this profile."
                    .to_string(),
            );
            return Ok(Vec::new());
        } else {
            let value = self
                .call(
                    "callees",
                    json!({ "addrs": [function.address], "limit": 500 }),
                )
                .await?;
            let page = parse(&value, p::modern_callees)?;
            let callees = match (page.callees, page.error) {
                (Some(callees), None) => callees,
                (_, error) => {
                    return Err(IdaFault::protocol(format!(
                        "IDA callees failed: {}",
                        error.unwrap_or_else(|| "missing callees".to_string())
                    )))
                }
            };
            if page.more == Some(true) {
                self.limitations.push(
                    "Upstream callees capped results at 500; additional callees remain unknown."
                        .to_string(),
                );
            }
            for item in callees {
                if item.external {
                    let identity = identity(&item.address, &item.name);
                    result.set(item.address, identity);
                } else {
                    queries.push(item.address);
                }
            }
        }
        let mut seen: Vec<String> = Vec::new();
        for query in queries {
            if seen.contains(&query) {
                continue;
            }
            seen.push(query.clone());
            let resolved = self.resolve(&query).await?;
            result.set(resolved.address.clone(), identity_of(&resolved));
        }
        Ok(result.0.into_iter().map(|(_, value)| value).collect())
    }

    pub async fn run(&mut self, operation: &str, parameters: &Value) -> Result<Value, IdaFault> {
        match operation {
            "list_procedures" | "search_procedures" => {
                let items: Vec<(String, String)> = self
                    .functions()
                    .await?
                    .into_iter()
                    .map(|function| (function.address, function.name))
                    .collect();
                return if operation == "list_procedures" {
                    Ok(listing(&items))
                } else {
                    search_items(&items, parameters)
                };
            }
            "list_strings" | "search_strings" => {
                let items = self.strings().await?;
                if operation == "search_strings" {
                    return search_items(&items, parameters);
                }
                return Ok(match parameters.get("address").and_then(Value::as_str) {
                    None => listing(&items),
                    Some(address) => {
                        let wanted = p::normalize_address(address).unwrap_or_default();
                        let kept: Vec<(String, String)> = items
                            .into_iter()
                            .filter(|(candidate, _)| *candidate == wanted)
                            .collect();
                        listing(&kept)
                    }
                });
            }
            "xrefs" => {
                let address = parameters
                    .get("address")
                    .and_then(Value::as_str)
                    .and_then(p::normalize_address)
                    .ok_or_else(|| {
                        IdaFault::protocol("IDA requires an explicit hexadecimal address.")
                    })?;
                self.locations.push(EvidenceLocation::Address {
                    address: address.clone(),
                });
                let xrefs = self.xrefs(&address).await?;
                return Ok(Value::Array(
                    xrefs.into_iter().map(|x| json!(x.address)).collect(),
                ));
            }
            _ => {}
        }
        let procedure = match parameters.get("procedure") {
            Some(Value::String(text)) if !text.is_empty() => text.clone(),
            other => {
                let mut issues = Vec::new();
                p::string_min1(other, &[], &mut issues);
                return Err(IdaFault::Malformed(p::render(&issues)));
            }
        };
        let function = self.resolve(&procedure).await?;
        self.locations.push(EvidenceLocation::Address {
            address: function.address.clone(),
        });
        match operation {
            "procedure_address" => Ok(json!(function.address)),
            "procedure_pseudo_code" => Ok(self
                .pseudocode(&function)
                .await?
                .map(Value::String)
                .unwrap_or(Value::Null)),
            "procedure_assembly" => Ok(json!(
                instruction_lines(&self.assembly(&function).await?).join("\n")
            )),
            "procedure_callers" => {
                if !self.legacy() {
                    return Err(IdaFault::protocol(
                        "This IDA MCP profile cannot distinguish direct callers from other code references.",
                    ));
                }
                let callers = self.relationships(&function, true).await?;
                Ok(addresses(&callers))
            }
            "procedure_callees" => {
                let callees = self.relationships(&function, false).await?;
                Ok(addresses(&callees))
            }
            "read_function_instructions" => {
                let instructions = instruction_lines(&self.assembly(&function).await?);
                Ok(json!({
                    "procedure": identity_of(&function),
                    "instructions": instructions,
                    "limitations": ida_limitations(),
                }))
            }
            "analyze_function" => self.dossier(&function).await,
            other => Err(IdaFault::protocol(format!(
                "IDA operation {other} is not supported."
            ))),
        }
    }

    async fn dossier(&mut self, function: &IdaFunction) -> Result<Value, IdaFault> {
        let assembly = self.assembly(function).await?;
        let pseudocode = self.pseudocode(function).await?;
        let callers = self.relationships(function, true).await?;
        let callees = self.relationships(function, false).await?;
        let signature = match (&assembly.return_type, &assembly.arguments) {
            (Some(return_type), Some(arguments)) => Value::String(format!(
                "{return_type} {}({})",
                function.name,
                arguments
                    .iter()
                    .map(|(name, kind)| format!("{kind} {name}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            _ => Value::Null,
        };
        let mut procedure = identity_of(function);
        procedure["signature"] = signature;
        procedure["locals"] = json!([]);
        let mut limitations = ida_limitations();
        limitations.extend(self.limitations.iter().cloned());
        limitations.push(
            "Stack frame records are not evidence of source locals. Rendered comments do not identify regular versus inline origin."
                .to_string(),
        );
        if pseudocode.is_none() {
            limitations.push("Pseudocode is unavailable.".to_string());
        }
        Ok(json!({
            "procedure": procedure,
            "pseudocode": pseudocode.unwrap_or_default(),
            "assembly": instruction_lines(&assembly),
            "comments": [],
            "callers": callers,
            "callees": callees,
            "incoming_references": [],
            "outgoing_references": [],
            "referenced_strings": [],
            "referenced_names": [],
            "basic_blocks": [],
            "native_api": Value::Null,
            "native_value_flow": Value::Null,
            "limitations": limitations,
        }))
    }
}

fn verify_assembly(function: &IdaFunction, assembly: &p::Disassembly) -> Result<(), IdaFault> {
    if assembly.start_ea != function.address || assembly.name != function.name {
        return Err(IdaFault::protocol(
            "IDA disassembly identifies a different function than the resolved entry.",
        ));
    }
    Ok(())
}

/// An upstream cursor must either finish or advance strictly to avoid replay loops.
fn next_offset(cursor: Cursor, current: u64) -> Result<Option<u64>, IdaFault> {
    match cursor {
        Cursor::Done => Ok(None),
        Cursor::Next(next) if next <= current => Err(IdaFault::protocol(
            "IDA MCP pagination did not advance its offset.",
        )),
        Cursor::Next(next) => Ok(Some(next)),
    }
}

fn addresses(identities: &[Value]) -> Value {
    Value::Array(
        identities
            .iter()
            .map(|identity| identity["address"].clone())
            .collect(),
    )
}

fn listing(items: &[(String, String)]) -> Value {
    Value::Array(
        items
            .iter()
            .map(|(address, value)| json!({ "address": address, "value": value }))
            .collect(),
    )
}

fn search_items(items: &[(String, String)], parameters: &Value) -> Result<Value, IdaFault> {
    let pattern = parameters
        .get("pattern")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let case_sensitive = parameters.get("case_sensitive") == Some(&json!(true));
    let regex_mode = parameters.get("mode") == Some(&json!("regex"));
    let kept: Vec<(String, String)> = if regex_mode {
        let regex = search::compile(pattern, case_sensitive).ok_or_else(|| {
            IdaFault::analysis(AnalysisError::Input {
                operation: "search".to_string(),
                issues: Vec::new(),
            })
        })?;
        items
            .iter()
            .filter(|(_, value)| search::is_match(&regex, value))
            .cloned()
            .collect()
    } else {
        items
            .iter()
            .filter(|(_, value)| search::literal_matches(value, pattern, case_sensitive))
            .cloned()
            .collect()
    };
    Ok(listing(&kept))
}
