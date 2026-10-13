//! Type, field, method and member-reference rows plus signature decoding
//! (REA `ManagedMemberInspectorCore` and `ManagedMemberRows`).

use std::collections::HashMap;

use serde_json::{json, Value};

use crate::cil::{method_body, ParsedInstruction};
use crate::common::{failure, swallow, Buf, Failure, Issue, R};
use crate::heaps::{
    metadata_coded_token, metadata_coded_token_invalid_reason, metadata_row_cursor, metadata_token, read_metadata_blob,
    read_metadata_string, sha256_bytes, tables,
};
use crate::layout::{Coded, MetadataLayout};
use crate::pe::PeLayout;

#[derive(Debug, Clone)]
pub struct TypeRange {
    pub token: String,
    pub full_name: Option<String>,
    pub field_start: i64,
    pub field_end: i64,
    pub method_start: i64,
    pub method_end: i64,
}

fn full_name(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_string()
    } else {
        format!("{namespace}.{name}")
    }
}

fn row_range(table_rows: i64, start: i64, next_start: i64) -> (Option<i64>, Option<i64>, i64) {
    let total = table_rows;
    if total == 0 || start == 0 {
        return (None, None, 0);
    }
    let end = (if next_start == 0 { total + 1 } else { next_start }).min(total + 1);
    if start >= end {
        return (None, None, 0);
    }
    (Some(start), Some(end - 1), end - start)
}

fn read_type_range(bytes: &Buf, layout: &MetadataLayout, row: i64, issues: &mut Vec<Issue>) -> R<TypeRange> {
    let methods = layout.table(6).map(|t| t.row_count).unwrap_or(0);
    let fields = layout.table(4).map(|t| t.row_count).unwrap_or(0);
    let mut cursor = metadata_row_cursor(bytes, layout, 2, row)?;
    cursor.u32()?;
    let name_index = cursor.index(layout.string_index_size)?;
    let namespace_index = cursor.index(layout.string_index_size)?;
    let declared_name = swallow(
        (|| -> R<String> {
            let namespace = read_metadata_string(bytes, layout, namespace_index, layout.strings.size)?;
            let name = read_metadata_string(bytes, layout, name_index, layout.strings.size)?;
            Ok(full_name(&namespace, &name))
        })(),
        issues,
    )?;
    cursor.index(layout.coded_index_size(Coded::TypeDefOrRef))?;
    let field_start = cursor.index(layout.table_index_size(4))?;
    let method_start = cursor.index(layout.table_index_size(6))?;
    let mut next_field = fields + 1;
    let mut next_method = methods + 1;
    if let Some(type_table) = layout.table(2) {
        if row < type_table.row_count {
            let mut next = metadata_row_cursor(bytes, layout, 2, row + 1)?;
            next.u32()?;
            next.index(layout.string_index_size)?;
            next.index(layout.string_index_size)?;
            next.index(layout.coded_index_size(Coded::TypeDefOrRef))?;
            next_field = next.index(layout.table_index_size(4))?;
            next_method = next.index(layout.table_index_size(6))?;
        }
    }
    Ok(TypeRange {
        token: metadata_token(2, row),
        full_name: declared_name,
        field_start,
        field_end: next_field,
        method_start,
        method_end: next_method,
    })
}

pub fn type_ranges(bytes: &Buf, layout: &MetadataLayout, issues: &mut Vec<Issue>) -> R<Vec<TypeRange>> {
    let total = layout.table(2).map(|t| t.row_count).unwrap_or(0);
    let mut ranges = Vec::new();
    for row in 1..=total {
        ranges.push(read_type_range(bytes, layout, row, issues)?);
    }
    Ok(ranges)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    Field,
    Method,
}

pub struct DeclaringLookup<'a> {
    ranges: &'a [TypeRange],
    owner: Owner,
    ordered: bool,
}

impl<'a> DeclaringLookup<'a> {
    pub fn new(ranges: &'a [TypeRange], owner: Owner) -> Self {
        let span = |r: &TypeRange| match owner {
            Owner::Field => (r.field_start, r.field_end),
            Owner::Method => (r.method_start, r.method_end),
        };
        let mut ordered = true;
        let mut previous_end: Option<i64> = None;
        for range in ranges {
            let (start, end) = span(range);
            if !(start <= end && previous_end.is_none_or(|p| p <= start)) {
                ordered = false;
                break;
            }
            previous_end = Some(end);
        }
        Self { ranges, owner, ordered }
    }

    fn span(&self, r: &TypeRange) -> (i64, i64) {
        match self.owner {
            Owner::Field => (r.field_start, r.field_end),
            Owner::Method => (r.method_start, r.method_end),
        }
    }

    pub fn find(&self, row: i64) -> Option<(&'a str, Option<&'a str>)> {
        let result = |r: &'a TypeRange| (r.token.as_str(), r.full_name.as_deref());
        if !self.ordered {
            // Malformed metadata can overlap or reverse ranges. Retain the original
            // first-match interpretation rather than guessing a different owner.
            return self.ranges.iter().find(|r| {
                let (start, end) = self.span(r);
                row >= start && row < end
            }).map(result);
        }
        let (mut first, mut end) = (0usize, self.ranges.len());
        while first < end {
            let middle = first + (end - first) / 2;
            let entry = &self.ranges[middle];
            let (start, stop) = self.span(entry);
            if row >= start && row < stop {
                return Some(result(entry));
            }
            if row < start {
                end = middle;
            } else {
                first = middle + 1;
            }
        }
        None
    }
}

pub fn parse_types(
    bytes: &Buf,
    layout: &MetadataLayout,
    ranges: &[TypeRange],
) -> R<(Vec<Value>, Vec<Issue>)> {
    let total = layout.table(2).map(|t| t.row_count).unwrap_or(0);
    let fields_rows = layout.table_row_count(4);
    let methods_rows = layout.table_row_count(6);
    let mut items = Vec::new();
    let mut issues: Vec<Issue> = Vec::new();
    for row in 1..=total {
        let mut local: Vec<Issue> = Vec::new();
        let result = (|| -> R<Value> {
            let mut cursor = metadata_row_cursor(bytes, layout, 2, row)?;
            let flags = cursor.u32()?;
            let name_index = cursor.index(layout.string_index_size)?;
            let name = read_metadata_string(bytes, layout, name_index, layout.strings.size)?;
            let namespace_index = cursor.index(layout.string_index_size)?;
            let namespace = read_metadata_string(bytes, layout, namespace_index, layout.strings.size)?;
            let extends_offset = cursor.offset();
            let extends_raw = cursor.index(layout.coded_index_size(Coded::TypeDefOrRef))?;
            let field_start = cursor.index(layout.table_index_size(4))?;
            let method_start = cursor.index(layout.table_index_size(6))?;
            let next_range = ranges.get(row as usize);
            let field_range = row_range(fields_rows, field_start, next_range.map(|r| r.field_start).unwrap_or(0));
            let method_range = row_range(methods_rows, method_start, next_range.map(|r| r.method_start).unwrap_or(0));
            let type_tables = tables(&[2, 1, 27]);
            if let Some(reason) = metadata_coded_token_invalid_reason(extends_raw, 2, &type_tables, &layout.row_counts) {
                local.push(Issue {
                    code: "invalid-row",
                    scope: format!("metadata.TypeDef:{}", metadata_token(2, row)),
                    offset: Some(extends_offset),
                    detail: format!("TypeDef Extends coded index 0x{extends_raw:x} is invalid: {reason}"),
                });
            }
            Ok(json!({
                "token": metadata_token(2, row),
                "row_offset": cursor.start,
                "namespace": namespace,
                "name": name,
                "full_name": full_name(&namespace, &name),
                "flags": flags,
                "extends_token": metadata_coded_token(extends_raw, 2, &type_tables, &layout.row_counts),
                "field_list": { "first_row": field_range.0, "last_row": field_range.1, "count": field_range.2 },
                "method_list": { "first_row": method_range.0, "last_row": method_range.1, "count": method_range.2 },
            }))
        })();
        issues.append(&mut local);
        if let Some(item) = swallow(result, &mut issues)? {
            items.push(item);
        }
    }
    Ok((items, issues))
}

fn read_compressed(bytes: &[u8], offset: usize) -> R<(i64, usize)> {
    let Some(first) = bytes.get(offset).copied() else {
        return Err(failure("invalid-blob", "signature", "truncated compressed integer", Some(offset as i64)));
    };
    let first = first as i64;
    if first & 0x80 == 0 {
        return Ok((first, offset + 1));
    }
    if first & 0xc0 == 0x80 {
        if let Some(second) = bytes.get(offset + 1) {
            return Ok((((first & 0x3f) << 8) | *second as i64, offset + 2));
        }
    }
    if first & 0xe0 == 0xc0 {
        if let (Some(b1), Some(b2), Some(b3)) = (bytes.get(offset + 1), bytes.get(offset + 2), bytes.get(offset + 3)) {
            return Ok((
                (first & 0x1f) * 0x0100_0000 + *b1 as i64 * 0x01_0000 + *b2 as i64 * 0x0100 + *b3 as i64,
                offset + 4,
            ));
        }
    }
    Err(failure("invalid-blob", "signature", "reserved compressed integer", Some(offset as i64)))
}

fn element_type(kind: u8) -> Option<&'static str> {
    Some(match kind {
        0x01 => "void",
        0x02 => "bool",
        0x03 => "char",
        0x04 => "i1",
        0x05 => "u1",
        0x06 => "i2",
        0x07 => "u2",
        0x08 => "i4",
        0x09 => "u4",
        0x0a => "i8",
        0x0b => "u8",
        0x0c => "r4",
        0x0d => "r8",
        0x0e => "string",
        0x18 => "native-int",
        0x19 => "native-uint",
        0x1c => "object",
        _ => return None,
    })
}

fn read_type_signature(blob: &[u8], offset: usize) -> R<(String, usize)> {
    let mut suffixes: Vec<&str> = Vec::new();
    let mut cursor = offset;
    let mut kind = blob.get(cursor).copied();
    while matches!(kind, Some(0x0f) | Some(0x10) | Some(0x1d)) {
        suffixes.push(match kind {
            Some(0x0f) => "*",
            Some(0x10) => "&",
            _ => "[]",
        });
        cursor += 1;
        kind = blob.get(cursor).copied();
    }
    let Some(kind) = kind else {
        return Err(failure("invalid-blob", "signature", "truncated type signature", Some(cursor as i64)));
    };
    let (value, next);
    if let Some(named) = element_type(kind) {
        value = named.to_string();
        next = cursor + 1;
    } else if kind == 0x11 || kind == 0x12 {
        let (token, after) = read_compressed(blob, cursor + 1)?;
        value = format!("{}:{}", if kind == 0x11 { "valuetype" } else { "class" }, token);
        next = after;
    } else if kind == 0x1e || kind == 0x13 {
        let (variable, after) = read_compressed(blob, cursor + 1)?;
        value = format!("{}:{}", if kind == 0x1e { "mvar" } else { "var" }, variable);
        next = after;
    } else {
        return Err(failure(
            "unsupported-signature",
            "signature",
            format!("unsupported element type 0x{kind:x}"),
            Some(cursor as i64),
        ));
    }
    suffixes.reverse();
    Ok((format!("{}{}", value, suffixes.concat()), next))
}

fn calling_convention(value: u8) -> String {
    let base = value & 0x0f;
    let mut flags: Vec<&str> = Vec::new();
    if value & 0x20 != 0 {
        flags.push("has-this");
    }
    if value & 0x40 != 0 {
        flags.push("explicit-this");
    }
    if value & 0x10 != 0 {
        flags.push("generic");
    }
    let name = match base {
        0 => "default".to_string(),
        5 => "vararg".to_string(),
        6 => "field".to_string(),
        other => format!("unknown:{other}"),
    };
    if flags.is_empty() {
        name
    } else {
        format!("{} {}", name, flags.join(" "))
    }
}

/// Decode a metadata signature blob.
pub fn signature(blob: &[u8], raw_sha256: Option<String>) -> Value {
    let raw_sha = raw_sha256.unwrap_or_else(|| sha256_bytes(blob));
    let attempt = || -> R<Value> {
        if blob.is_empty() {
            return Err(failure("invalid-blob", "signature", "empty signature", Some(0)));
        }
        let first = blob[0];
        if first & 0x0f == 6 {
            let (field_type, next) = read_type_signature(blob, 1)?;
            return Ok(json!({
                "raw_length": blob.len(),
                "raw_sha256": raw_sha,
                "kind": "field",
                "parse_status": if next == blob.len() { "decoded" } else { "partial" },
                "calling_convention": calling_convention(first),
                "generic_parameter_count": null,
                "parameter_count": null,
                "return_type": null,
                "parameter_types": [],
                "field_type": field_type,
                "issue": if next == blob.len() { Value::Null } else { json!("Trailing signature data") },
            }));
        }
        let mut offset = 1usize;
        let mut generic_count: Option<i64> = None;
        if first & 0x10 != 0 {
            let (value, next) = read_compressed(blob, offset)?;
            generic_count = Some(value);
            offset = next;
        }
        let (parameter_count, next) = read_compressed(blob, offset)?;
        offset = next;
        let (return_type, next) = read_type_signature(blob, offset)?;
        offset = next;
        let mut parameters = Vec::new();
        let mut index = 0;
        while index < parameter_count {
            let (parameter, next) = read_type_signature(blob, offset)?;
            parameters.push(parameter);
            offset = next;
            index += 1;
        }
        Ok(json!({
            "raw_length": blob.len(),
            "raw_sha256": raw_sha,
            "kind": "method",
            "parse_status": if offset == blob.len() { "decoded" } else { "partial" },
            "calling_convention": calling_convention(first),
            "generic_parameter_count": generic_count,
            "parameter_count": parameter_count,
            "return_type": return_type,
            "parameter_types": parameters,
            "field_type": null,
            "issue": if offset == blob.len() { Value::Null } else { json!("Trailing signature data") },
        }))
    };
    match attempt() {
        Ok(value) => value,
        Err(Failure::Reader(issue)) => json!({
            "raw_length": blob.len(),
            "raw_sha256": raw_sha,
            "kind": "unknown",
            "parse_status": if issue.code == "unsupported-signature" { "unsupported" } else { "malformed" },
            "calling_convention": null,
            "generic_parameter_count": null,
            "parameter_count": null,
            "return_type": null,
            "parameter_types": [],
            "field_type": null,
            "issue": issue.detail,
        }),
        Err(Failure::Range(message)) => json!({
            "raw_length": blob.len(),
            "raw_sha256": raw_sha,
            "kind": "unknown",
            "parse_status": "malformed",
            "calling_convention": null,
            "generic_parameter_count": null,
            "parameter_count": null,
            "return_type": null,
            "parameter_types": [],
            "field_type": null,
            "issue": message,
        }),
    }
}

fn budgeted_signature(bytes: &[u8], layout: &MetadataLayout) -> R<Value> {
    layout.budget.reserve(bytes.len() as u64 * 256, Some(layout.blob.offset))?;
    let digest = layout.budget.digest(bytes, false)?;
    Ok(signature(bytes, Some(digest)))
}

pub struct CoreName {
    pub name: String,
}

pub struct MethodCore {
    pub name: String,
}

pub struct ParsedFields {
    pub fields: Vec<Value>,
    pub core: HashMap<String, String>,
    pub issues: Vec<Issue>,
}

pub fn parse_fields(bytes: &Buf, layout: &MetadataLayout, ranges: &[TypeRange]) -> R<ParsedFields> {
    let mut fields = Vec::new();
    let mut core = HashMap::new();
    let mut issues = Vec::new();
    let total = layout.table(4).map(|t| t.row_count).unwrap_or(0);
    let lookup = DeclaringLookup::new(ranges, Owner::Field);
    for row in 1..=total {
        let result = (|| -> R<(Value, String, String)> {
            let mut cursor = metadata_row_cursor(bytes, layout, 4, row)?;
            let flags = cursor.u16()?;
            let name_index = cursor.index(layout.string_index_size)?;
            let name = read_metadata_string(bytes, layout, name_index, layout.strings.size)?;
            let sig_index = cursor.index(layout.blob_index_size)?;
            let sig = read_metadata_blob(bytes, layout, sig_index, layout.blob.size)?;
            let declared = lookup.find(row);
            let token = metadata_token(4, row);
            let value = json!({
                "token": token,
                "row_offset": cursor.start,
                "declaring_type_token": declared.map(|d| d.0),
                "declaring_type": declared.and_then(|d| d.1),
                "name": name,
                "flags": flags,
                "signature": budgeted_signature(sig, layout)?,
            });
            Ok((value, token, name))
        })();
        if let Some((value, token, name)) = swallow(result, &mut issues)? {
            fields.push(value);
            core.insert(token, name);
        }
    }
    Ok(ParsedFields { fields, core, issues })
}

pub struct ParsedMemberRefs {
    pub refs: Vec<Value>,
    pub core: HashMap<String, String>,
    pub issues: Vec<Issue>,
}

pub fn parse_member_refs(bytes: &Buf, layout: &MetadataLayout) -> R<ParsedMemberRefs> {
    let mut refs = Vec::new();
    let mut core = HashMap::new();
    let mut issues: Vec<Issue> = Vec::new();
    let total = layout.table(10).map(|t| t.row_count).unwrap_or(0);
    let parent_tables = tables(&[2, 1, 26, 6, 27]);
    for row in 1..=total {
        let mut local: Vec<Issue> = Vec::new();
        let result = (|| -> R<(Value, String, String)> {
            let mut cursor = metadata_row_cursor(bytes, layout, 10, row)?;
            let parent_raw = cursor.index(layout.coded_index_size(Coded::MemberRefParent))?;
            let name_index = cursor.index(layout.string_index_size)?;
            let name = read_metadata_string(bytes, layout, name_index, layout.strings.size)?;
            let sig_index = cursor.index(layout.blob_index_size)?;
            let sig = read_metadata_blob(bytes, layout, sig_index, layout.blob.size)?;
            let token = metadata_token(10, row);
            let parent_reason = metadata_coded_token_invalid_reason(parent_raw, 3, &parent_tables, &layout.row_counts);
            if parent_reason.is_some() || parent_raw == 0 {
                local.push(Issue {
                    code: "invalid-row",
                    scope: format!("metadata.MemberRef:{token}"),
                    offset: Some(cursor.start),
                    detail: match parent_reason {
                        None => "MemberRef parent coded index 0x0 is null, but the Class column must reference a row".to_string(),
                        Some(reason) => format!("MemberRef parent coded index 0x{parent_raw:x} is invalid: {reason}"),
                    },
                });
            }
            let value = json!({
                "token": token,
                "row_offset": cursor.start,
                "parent_token": metadata_coded_token(parent_raw, 3, &parent_tables, &layout.row_counts),
                "name": name,
                "signature": budgeted_signature(sig, layout)?,
            });
            Ok((value, token, name))
        })();
        issues.append(&mut local);
        if let Some((value, token, name)) = swallow(result, &mut issues)? {
            refs.push(value);
            core.insert(token, name);
        }
    }
    Ok(ParsedMemberRefs { refs, core, issues })
}

pub struct MethodRecord {
    pub token: String,
    pub name: String,
    pub declaring_type: Option<String>,
    pub json: Value,
    pub anchors: Vec<ParsedInstruction>,
}

pub struct ParsedMethods {
    pub methods: Vec<MethodRecord>,
    pub core: HashMap<String, String>,
    pub issues: Vec<Issue>,
}

pub fn parse_methods(bytes: &Buf, layout: &MetadataLayout, pe: &PeLayout, ranges: &[TypeRange]) -> R<ParsedMethods> {
    let mut methods = Vec::new();
    let mut core = HashMap::new();
    let mut issues = Vec::new();
    let total = layout.table(6).map(|t| t.row_count).unwrap_or(0);
    let lookup = DeclaringLookup::new(ranges, Owner::Method);
    for row in 1..=total {
        let result = (|| -> R<MethodRecord> {
            let mut cursor = metadata_row_cursor(bytes, layout, 6, row)?;
            let rva = cursor.u32()?;
            let impl_flags = cursor.u16()?;
            let flags = cursor.u16()?;
            let name_index = cursor.index(layout.string_index_size)?;
            let name = read_metadata_string(bytes, layout, name_index, layout.strings.size)?;
            let sig_index = cursor.index(layout.blob_index_size)?;
            let sig = read_metadata_blob(bytes, layout, sig_index, layout.blob.size)?;
            cursor.index(layout.table_index_size(8))?;
            let declared = lookup.find(row);
            let token = metadata_token(6, row);
            let signature = budgeted_signature(sig, layout)?;
            let body = method_body(bytes, pe, rva, impl_flags, flags, Some(&layout.budget))?;
            let json = json!({
                "token": token,
                "row_offset": cursor.start,
                "declaring_type_token": declared.map(|d| d.0),
                "declaring_type": declared.and_then(|d| d.1),
                "name": name,
                "rva": rva,
                "impl_flags": impl_flags,
                "flags": flags,
                "signature": signature,
                "body": body.json,
            });
            Ok(MethodRecord {
                token,
                name,
                declaring_type: declared.and_then(|d| d.1).map(str::to_string),
                json,
                anchors: body.anchors,
            })
        })();
        if let Some(record) = swallow(result, &mut issues)? {
            core.insert(record.token.clone(), record.name.clone());
            methods.push(record);
        }
    }
    Ok(ParsedMethods { methods, core, issues })
}

fn target_kind(token: &str) -> &'static str {
    if token.starts_with("0x06") {
        "method-def"
    } else if token.starts_with("0x0a") {
        "member-ref"
    } else if token.starts_with("0x2b") {
        "method-spec"
    } else {
        "unknown"
    }
}

pub fn edges(
    methods: &[MethodRecord],
    method_core: &HashMap<String, String>,
    field_core: &HashMap<String, String>,
    ref_core: &HashMap<String, String>,
) -> (Vec<Value>, Vec<Value>) {
    let mut call_edges = Vec::new();
    let mut field_accesses = Vec::new();
    for method in methods {
        let qualified = match &method.declaring_type {
            None => method.name.clone(),
            Some(declaring) => format!("{declaring}.{}", method.name),
        };
        for anchor in &method.anchors {
            if anchor.opcode == "ldtoken" {
                continue;
            }
            let Some(operand) = anchor.operand.as_ref() else { continue };
            if anchor.operand_kind == "method" {
                let named = method_core.get(operand).or_else(|| ref_core.get(operand));
                call_edges.push(json!({
                    "caller_token": method.token,
                    "caller": qualified,
                    "opcode": anchor.opcode,
                    "target_token": operand,
                    "target_kind": target_kind(operand),
                    "target_name": named,
                }));
            }
            if anchor.operand_kind == "field" {
                field_accesses.push(json!({
                    "method_token": method.token,
                    "method": qualified,
                    "opcode": anchor.opcode,
                    "field_token": operand,
                    "field_name": field_core.get(operand),
                }));
            }
        }
    }
    (call_edges, field_accesses)
}
