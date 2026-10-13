//! CIL method bodies: header, instruction decoding, exception regions
//! (REA `ManagedMethodBodyReader`, `ManagedMemberInstructionDecoder`,
//! `ManagedExceptionRegionValidation`).

use std::collections::{BTreeSet, HashMap};

use serde_json::{json, Value};

use crate::budget::Budget;
use crate::common::{js_number_to_string, Buf, Failure, R};
use crate::heaps::sha256_bytes;
use crate::opcodes::OPCODES;
use crate::pe::PeLayout;

const PREFIX_OPCODES: [&str; 5] = ["unaligned.", "volatile.", "tail.", "constrained.", "readonly."];

#[derive(Debug, Clone)]
pub struct ParsedInstruction {
    pub offset: i64,
    pub opcode: &'static str,
    pub operand_kind: &'static str,
    pub operand: Option<String>,
}

fn token_kind(token: &str) -> &'static str {
    if token.starts_with("0x06") || token.starts_with("0x0a") || token.starts_with("0x2b") {
        return "method";
    }
    if token.starts_with("0x04") {
        return "field";
    }
    if token.starts_with("0x70") {
        return "string";
    }
    if token.starts_with("0x11") {
        return "signature";
    }
    if token.starts_with("0x01") || token.starts_with("0x02") || token.starts_with("0x1b") {
        return "type";
    }
    "token"
}

struct Operand {
    next: i64,
    anchor_kind: &'static str,
    value: Option<String>,
}

fn read_operand(il: &Buf, offset: i64, kind: &str) -> R<Operand> {
    let fixed = |next: i64, anchor_kind: &'static str, value: String| Ok(Operand { next, anchor_kind, value: Some(value) });
    match kind {
        "none" => Ok(Operand { next: offset, anchor_kind: "none", value: None }),
        "short-var" => fixed(offset + 1, "variable", il.u8(offset)?.to_string()),
        "var" => fixed(offset + 2, "variable", il.u16(offset)?.to_string()),
        "short-i" => fixed(offset + 1, "constant", il.i8(offset)?.to_string()),
        "i" => fixed(offset + 4, "constant", il.i32(offset)?.to_string()),
        "i8" => fixed(offset + 8, "constant", il.i64(offset)?.to_string()),
        "r4" => fixed(offset + 4, "constant", js_number_to_string(f64::from(il.f32(offset)?))),
        "r8" => fixed(offset + 8, "constant", js_number_to_string(il.f64(offset)?)),
        "short-branch" => fixed(offset + 1, "branch", (offset + 1 + il.i8(offset)? as i64).to_string()),
        "branch" => fixed(offset + 4, "branch", (offset + 4 + il.i32(offset)? as i64).to_string()),
        "switch" => {
            let count = il.u32(offset)? as i64;
            fixed(offset + 4 + count * 4, "switch", count.to_string())
        }
        other => {
            let raw = il.u32(offset)?;
            let token = format!("0x{raw:08x}");
            match other {
                "method" => fixed(offset + 4, "method", token),
                "field" => fixed(offset + 4, "field", token),
                "type" => fixed(offset + 4, "type", token),
                "string" => fixed(offset + 4, "string", token),
                "signature" => fixed(offset + 4, "signature", token),
                "token" => {
                    let anchor_kind = token_kind(&token);
                    fixed(offset + 4, anchor_kind, token)
                }
                _ => Ok(Operand { next: offset, anchor_kind: "unknown", value: None }),
            }
        }
    }
}

pub struct Decoded {
    pub parsed: Vec<ParsedInstruction>,
    pub instruction_starts: Vec<i64>,
    pub count: usize,
    pub truncated: i64,
    pub issue: Option<String>,
}

fn opcode_table() -> &'static HashMap<u16, (&'static str, &'static str)> {
    use std::sync::OnceLock;
    static TABLE: OnceLock<HashMap<u16, (&'static str, &'static str)>> = OnceLock::new();
    TABLE.get_or_init(|| OPCODES.iter().map(|(code, name, operand)| (*code, (*name, *operand))).collect())
}

pub fn decode_instructions(il: &Buf) -> Decoded {
    let table = opcode_table();
    let mut parsed: Vec<ParsedInstruction> = Vec::new();
    let mut starts: Vec<i64> = Vec::new();
    let mut offset: i64 = 0;
    let mut prefix_start: Option<i64> = None;
    let length = il.len();
    let mut run = || -> R<Option<String>> {
        while offset < length {
            let start = offset;
            let first = il.u8(offset)?;
            offset += 1;
            let code: u16 = if first == 0xfe {
                let second = il.u8(offset)?;
                offset += 1;
                0xfe00 + second as u16
            } else {
                first as u16
            };
            let Some((name, operand_kind)) = table.get(&code).copied() else {
                return Ok(Some(format!("Unsupported CIL opcode 0x{code:x} at IL offset {start}")));
            };
            let operand = read_operand(il, offset, operand_kind)?;
            if operand.next < offset || operand.next > length {
                return Ok(Some(format!("Instruction {name} at IL offset {start} leaves method body")));
            }
            offset = operand.next;
            if PREFIX_OPCODES.contains(&name) {
                prefix_start.get_or_insert(start);
            } else {
                starts.push(prefix_start.unwrap_or(start));
                prefix_start = None;
            }
            parsed.push(ParsedInstruction { offset: start, opcode: name, operand_kind: operand.anchor_kind, operand: operand.value });
        }
        Ok(None)
    };
    let issue = match run() {
        Ok(found) => found,
        Err(failure) => Some(failure.message().to_string()),
    };
    let truncated = if offset < length && issue.is_none() { 1 } else { 0 };
    let count = parsed.len();
    Decoded { parsed, instruction_starts: starts, count, truncated, issue }
}

#[derive(Debug, Clone)]
pub struct ExceptionRegion {
    pub flags: u32,
    pub try_offset: i64,
    pub try_length: i64,
    pub handler_offset: i64,
    pub handler_length: i64,
    pub class_token: Option<String>,
    pub filter_offset: Option<i64>,
}

impl ExceptionRegion {
    fn to_json(&self) -> Value {
        json!({
            "flags": self.flags,
            "try_offset": self.try_offset,
            "try_length": self.try_length,
            "handler_offset": self.handler_offset,
            "handler_length": self.handler_length,
            "class_token": self.class_token,
            "filter_offset": self.filter_offset,
        })
    }
}

pub struct RegionParse {
    pub malformed: Option<String>,
    pub regions: Vec<ExceptionRegion>,
}

fn malformed_regions(issue: &str, regions: Vec<ExceptionRegion>) -> RegionParse {
    RegionParse { malformed: Some(issue.to_string()), regions }
}

fn read_exception_clauses(bytes: &Buf, start: i64, count: i64, fat: bool) -> R<Vec<ExceptionRegion>> {
    let mut regions = Vec::new();
    let clause_size = if fat { 24 } else { 12 };
    for index in 0..count {
        let clause = start + index * clause_size;
        let flags = if fat { bytes.u32(clause)? } else { bytes.u16(clause)? as u32 };
        let extra = bytes.u32(clause + if fat { 20 } else { 8 })?;
        regions.push(ExceptionRegion {
            flags,
            try_offset: if fat { bytes.u32(clause + 4)? as i64 } else { bytes.u16(clause + 2)? as i64 },
            try_length: if fat { bytes.u32(clause + 8)? as i64 } else { bytes.u8(clause + 4)? as i64 },
            handler_offset: if fat { bytes.u32(clause + 12)? as i64 } else { bytes.u16(clause + 5)? as i64 },
            handler_length: if fat { bytes.u32(clause + 16)? as i64 } else { bytes.u8(clause + 7)? as i64 },
            class_token: if flags == 0 { Some(format!("0x{extra:08x}")) } else { None },
            filter_offset: if flags == 1 { Some(extra as i64) } else { None },
        });
    }
    Ok(regions)
}

pub fn parse_exception_regions(bytes: &Buf, offset: i64, method_end: i64, budget: Option<&Budget>) -> R<RegionParse> {
    let mut regions: Vec<ExceptionRegion> = Vec::new();
    let mut section_offset = offset;
    let mut has_more = true;
    while has_more {
        if section_offset < 0 || section_offset > method_end - 4 || section_offset > bytes.len() - 4 {
            return Ok(malformed_regions("Exception section header leaves artifact", regions));
        }
        let kind = bytes.u8(section_offset)?;
        if kind & 0x3f != 1 {
            return Ok(malformed_regions(&format!("Unsupported method data section kind {}", kind & 0x3f), regions));
        }
        let fat = kind & 0x40 != 0;
        let size = if fat {
            bytes.u8(section_offset + 1)? as i64
                | ((bytes.u8(section_offset + 2)? as i64) << 8)
                | ((bytes.u8(section_offset + 3)? as i64) << 16)
        } else {
            bytes.u8(section_offset + 1)? as i64
        };
        let clause_size = if fat { 24 } else { 12 };
        if size < 4 || section_offset > method_end - size || section_offset > bytes.len() - size {
            return Ok(malformed_regions("Exception section size leaves artifact", regions));
        }
        if (size - 4) % clause_size != 0 {
            return Ok(malformed_regions("Exception section size does not contain whole clauses", regions));
        }
        if !fat && (bytes.at(section_offset + 2) != Some(0) || bytes.at(section_offset + 3) != Some(0)) {
            return Ok(malformed_regions("Small exception section reserved bytes are nonzero", regions));
        }
        let count = (size - 4) / clause_size;
        if let Some(budget) = budget {
            budget.reserve(count as u64 * 256, Some(section_offset))?;
        }
        regions.extend(read_exception_clauses(bytes, section_offset + 4, count, fat)?);
        has_more = kind & 0x80 != 0;
        section_offset += size;
    }
    Ok(RegionParse { malformed: None, regions })
}

fn clause_flags_issue(region: &ExceptionRegion) -> Option<String> {
    if [0, 1, 2, 4].contains(&region.flags) {
        None
    } else {
        Some(format!("Exception clause has unsupported flags 0x{:x}", region.flags))
    }
}

fn method_extent_issue(start: i64, length: i64, il_size: i64, name: &str) -> Option<String> {
    if start <= il_size && length <= il_size - start {
        None
    } else {
        Some(format!("Exception clause {name} range leaves the method IL body"))
    }
}

fn boundary_issue(start: i64, length: i64, boundaries: &BTreeSet<i64>, name: &str) -> Option<String> {
    if boundaries.contains(&start) && boundaries.contains(&(start + length)) {
        None
    } else {
        Some(format!("Exception clause {name} range does not align with CIL instruction boundaries"))
    }
}

fn filter_ordering_issue(region: &ExceptionRegion, il_size: i64) -> Option<String> {
    if region.flags != 1 {
        return None;
    }
    match region.filter_offset {
        Some(offset) if offset < il_size && offset < region.handler_offset => None,
        _ => Some("Exception clause filter must start before its handler within the method IL body".to_string()),
    }
}

fn clause_issue(region: &ExceptionRegion, il_size: i64, boundaries: &BTreeSet<i64>) -> Option<String> {
    clause_flags_issue(region)
        .or_else(|| method_extent_issue(region.try_offset, region.try_length, il_size, "try"))
        .or_else(|| boundary_issue(region.try_offset, region.try_length, boundaries, "try"))
        .or_else(|| method_extent_issue(region.handler_offset, region.handler_length, il_size, "handler"))
        .or_else(|| boundary_issue(region.handler_offset, region.handler_length, boundaries, "handler"))
        .or_else(|| match (region.flags, region.filter_offset) {
            (1, Some(filter)) => boundary_issue(filter, 0, boundaries, "filter"),
            _ => None,
        })
        .or_else(|| filter_ordering_issue(region, il_size))
}

/// Validate EH extents and instruction boundaries while retaining each clause.
pub fn validate_exception_region_ranges(parsed: RegionParse, il_size: i64, offsets: &[i64]) -> RegionParse {
    if parsed.malformed.is_some() {
        return parsed;
    }
    let mut boundaries: BTreeSet<i64> = offsets.iter().copied().collect();
    boundaries.insert(il_size);
    for region in &parsed.regions {
        if let Some(issue) = clause_issue(region, il_size, &boundaries) {
            return RegionParse { malformed: Some(issue), regions: parsed.regions };
        }
    }
    parsed
}

struct BodyHeader {
    format: &'static str,
    size: i64,
    flags: i64,
    max_stack: i64,
    il_size: i64,
    local_sig: i64,
}

fn read_method_body_header(bytes: &Buf, offset: i64) -> R<BodyHeader> {
    let first = bytes.u8(offset)?;
    if first & 3 == 2 {
        return Ok(BodyHeader { format: "tiny", size: 1, flags: 0, max_stack: 8, il_size: (first >> 2) as i64, local_sig: 0 });
    }
    if first & 3 != 3 {
        return Err(Failure::Range("Unsupported method body header".to_string()));
    }
    if offset > bytes.len() - 12 {
        return Err(Failure::Range("Fat method body header leaves artifact".to_string()));
    }
    let flags_and_size = bytes.u16(offset)? as i64;
    let header_dwords = flags_and_size >> 12;
    if header_dwords < 3 {
        return Err(Failure::Range("Fat method body header is smaller than 12 bytes".to_string()));
    }
    let size = header_dwords * 4;
    if offset > bytes.len() - size {
        return Err(Failure::Range("Method body header leaves artifact".to_string()));
    }
    Ok(BodyHeader {
        format: "fat",
        size,
        flags: flags_and_size & 0x0fff,
        max_stack: bytes.u16(offset + 2)? as i64,
        il_size: bytes.u32(offset + 4)? as i64,
        local_sig: bytes.u32(offset + 8)? as i64,
    })
}

pub fn empty_method_body(rva: i64, status: &str, issue: Option<String>) -> Value {
    json!({
        "status": status,
        "header_format": if status == "absent" { "none" } else { "unknown" },
        "rva": rva,
        "file_offset": null,
        "max_stack": null,
        "init_locals": null,
        "local_var_sig_token": null,
        "il_size": 0,
        "il_sha256": null,
        "normalized_il_sha256": null,
        "instruction_count": 0,
        "decoded_instruction_count": 0,
        "truncated_instructions": 0,
        "opcode_counts": {},
        "anchors": [],
        "exception_regions": [],
        "issue": issue,
    })
}

/// A decoded method body plus the anchors the edge builder needs.
pub struct MethodBody {
    pub json: Value,
    pub anchors: Vec<ParsedInstruction>,
}

fn body_json_from(result: R<(Value, Vec<ParsedInstruction>)>, rva: i64) -> R<MethodBody> {
    match result {
        Ok((json, anchors)) => Ok(MethodBody { json, anchors }),
        Err(Failure::Reader(issue)) if issue.code == "resource-limit" => Err(Failure::Reader(issue)),
        Err(failure) => {
            Ok(MethodBody { json: empty_method_body(rva, "malformed", Some(failure.message().to_string())), anchors: vec![] })
        }
    }
}

/// Decode admitted managed CIL, retaining unavailable implementation metadata as partial.
pub fn method_body(
    bytes: &Buf,
    pe: &PeLayout,
    rva: i64,
    impl_flags: i64,
    flags: i64,
    budget: Option<&Budget>,
) -> R<MethodBody> {
    if rva == 0 {
        return Ok(MethodBody { json: empty_method_body(rva, "absent", None), anchors: vec![] });
    }
    if impl_flags & 7 != 0 || flags & 0x2000 != 0 {
        return Ok(MethodBody {
            json: empty_method_body(
                rva,
                "partial",
                Some("CIL decoding is unavailable for native, runtime, unmanaged, or P/Invoke implementations".to_string()),
            ),
            anchors: vec![],
        });
    }
    let attempt = || -> R<(Value, Vec<ParsedInstruction>)> {
        let offset = pe.rva_to_offset(rva, 1, "method.body")?;
        let method_extent = pe.rva_available_bytes(rva, "method.body")?;
        let header = read_method_body_header(bytes, offset)?;
        if header.size > method_extent || header.il_size > method_extent - header.size {
            return Err(Failure::Range("Method body leaves file-backed PE section data".to_string()));
        }
        let il_offset = offset + header.size;
        if il_offset > bytes.len() - header.il_size {
            return Err(Failure::Range("Method IL bytes leave artifact".to_string()));
        }
        let il = bytes.sub(il_offset, il_offset + header.il_size);
        // One byte can produce an instruction record, start index, normalized tuple,
        // and anchor. Reserve conservative bookkeeping capacity before decoding.
        if let Some(budget) = budget {
            budget.reserve(il.len() as u64 * 256, Some(il_offset))?;
        }
        let decoded = decode_instructions(&il);
        let mut opcode_counts = serde_json::Map::new();
        for instruction in &decoded.parsed {
            let entry = opcode_counts.entry(instruction.opcode.to_string()).or_insert(json!(0));
            *entry = json!(entry.as_i64().unwrap_or(0) + 1);
        }
        let anchors: Vec<ParsedInstruction> =
            decoded.parsed.iter().filter(|i| i.operand_kind != "none").cloned().collect();
        let normalized = serde_json::to_string(
            &decoded
                .parsed
                .iter()
                .map(|i| json!([i.opcode, i.operand_kind, i.operand]))
                .collect::<Vec<Value>>(),
        )
        .unwrap_or_default();
        let method_end = il_offset + header.il_size;
        let section_offset = (method_end + 3) & !3;
        let exception_regions = if header.format == "fat" && header.flags & 8 != 0 {
            let parsed = parse_exception_regions(bytes, section_offset, offset + method_extent, budget)?;
            Some(validate_exception_region_ranges(parsed, header.il_size, &decoded.instruction_starts))
        } else {
            None
        };
        let region_malformed = exception_regions.as_ref().and_then(|r| r.malformed.clone());
        let status = if decoded.issue.is_some() || region_malformed.is_some() {
            "malformed"
        } else if decoded.truncated > 0 {
            "partial"
        } else {
            "present"
        };
        let issue = decoded
            .issue
            .clone()
            .or(region_malformed)
            .or(if decoded.truncated > 0 {
                Some("Instruction decoding stopped before the end of the method body".to_string())
            } else {
                None
            });
        let body = json!({
            "status": status,
            "header_format": header.format,
            "rva": rva,
            "file_offset": offset,
            "max_stack": header.max_stack,
            "init_locals": header.flags & 0x10 != 0,
            "local_var_sig_token": if header.local_sig == 0 { Value::Null } else { Value::String(format!("0x{:08x}", header.local_sig)) },
            "il_size": header.il_size,
            "il_sha256": sha256_bytes(il.bytes()),
            "normalized_il_sha256": if status == "present" { Value::String(sha256_bytes(normalized.as_bytes())) } else { Value::Null },
            "instruction_count": decoded.count,
            "decoded_instruction_count": decoded.parsed.len(),
            "truncated_instructions": decoded.truncated,
            "opcode_counts": Value::Object(opcode_counts),
            "anchors": anchors.iter().map(|a| json!({
                "il_offset": a.offset,
                "opcode": a.opcode,
                "operand_kind": a.operand_kind,
                "operand": a.operand,
            })).collect::<Vec<Value>>(),
            "exception_regions": exception_regions.map(|r| r.regions.iter().map(ExceptionRegion::to_json).collect::<Vec<Value>>()).unwrap_or_default(),
            "issue": issue,
        });
        Ok((body, anchors))
    };
    body_json_from(attempt(), rva)
}
