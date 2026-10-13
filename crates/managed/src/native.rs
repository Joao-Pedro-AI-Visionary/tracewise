//! `inspect_managed_native_boundaries` (REA `ManagedNativeBoundaryInspector`
//! and `ManagedNativeBoundaryHelpers`).

use std::collections::{HashMap, HashSet};

use serde_json::{json, Value};

use crate::budget::Budget;
use crate::common::{issues_json, swallow, Buf, Failure, Issue, R};
use crate::heaps::{
    metadata_coded_token, metadata_coded_token_invalid_reason, metadata_row_cursor, metadata_token, read_metadata_string,
    tables,
};
use crate::inventory::{read_metadata_inventory, read_resource_directory, table_row_counts, Inventory};
use crate::layout::{read_metadata_layout, Coded, MetadataLayout};
use crate::pe::{read_pe_layout, PeLayout};
use crate::ManagedTarget;

#[derive(Clone)]
struct MemberCore {
    token: String,
    row_offset: i64,
    kind: &'static str,
    name: String,
    flags: i64,
    impl_flags: Option<i64>,
    rva: Option<i64>,
}

fn flags_hex(value: i64) -> String {
    format!("0x{value:04x}")
}

fn parse_module_refs(bytes: &Buf, layout: &MetadataLayout, extent: i64, issues: &mut Vec<Issue>) -> R<Vec<Value>> {
    let mut refs = Vec::new();
    let total = layout.table(26).map(|t| t.row_count).unwrap_or(0);
    for row in 1..=total {
        let result = (|| -> R<Value> {
            let mut cursor = metadata_row_cursor(bytes, layout, 26, row)?;
            let name_index = cursor.index(layout.string_index_size)?;
            Ok(json!({
                "token": metadata_token(26, row),
                "row_offset": cursor.start,
                "name": read_metadata_string(bytes, layout, name_index, extent)?,
            }))
        })();
        if let Some(value) = swallow(result, issues)? {
            refs.push(value);
        }
    }
    Ok(refs)
}

fn parse_fields(
    bytes: &Buf,
    layout: &MetadataLayout,
    extent: i64,
    issues: &mut Vec<Issue>,
    out: &mut Vec<MemberCore>,
) -> R<()> {
    let total = layout.table(4).map(|t| t.row_count).unwrap_or(0);
    for row in 1..=total {
        let result = (|| -> R<MemberCore> {
            let mut cursor = metadata_row_cursor(bytes, layout, 4, row)?;
            let flags = cursor.u16()?;
            let name_index = cursor.index(layout.string_index_size)?;
            let name = read_metadata_string(bytes, layout, name_index, extent)?;
            cursor.index(layout.blob_index_size)?;
            Ok(MemberCore {
                token: metadata_token(4, row),
                row_offset: cursor.start,
                kind: "field",
                name,
                flags,
                impl_flags: None,
                rva: None,
            })
        })();
        if let Some(member) = swallow(result, issues)? {
            out.push(member);
        }
    }
    Ok(())
}

fn parse_methods(
    bytes: &Buf,
    layout: &MetadataLayout,
    extent: i64,
    issues: &mut Vec<Issue>,
    out: &mut Vec<MemberCore>,
) -> R<()> {
    let total = layout.table(6).map(|t| t.row_count).unwrap_or(0);
    for row in 1..=total {
        let result = (|| -> R<MemberCore> {
            let mut cursor = metadata_row_cursor(bytes, layout, 6, row)?;
            let rva = cursor.u32()?;
            let impl_flags = cursor.u16()?;
            let flags = cursor.u16()?;
            let name_index = cursor.index(layout.string_index_size)?;
            let name = read_metadata_string(bytes, layout, name_index, extent)?;
            cursor.index(layout.blob_index_size)?;
            cursor.index(layout.table_index_size(8))?;
            Ok(MemberCore {
                token: metadata_token(6, row),
                row_offset: cursor.start,
                kind: "method",
                name,
                flags,
                impl_flags: Some(impl_flags),
                rva: Some(rva),
            })
        })();
        if let Some(member) = swallow(result, issues)? {
            out.push(member);
        }
    }
    Ok(())
}

fn char_set(flags: i64) -> &'static str {
    match flags & 0x0006 {
        0x0000 => "not-specified",
        0x0002 => "ansi",
        0x0004 => "unicode",
        0x0006 => "auto",
        _ => "unknown",
    }
}

fn call_convention(flags: i64) -> &'static str {
    match flags & 0x0700 {
        0x0000 => "not-specified",
        0x0100 => "winapi",
        0x0200 => "cdecl",
        0x0300 => "stdcall",
        0x0400 => "thiscall",
        0x0500 => "fastcall",
        _ => "unknown",
    }
}

fn best_fit(flags: i64) -> &'static str {
    match flags & 0x0030 {
        0x0000 => "assembly-default",
        0x0010 => "enabled",
        0x0020 => "disabled",
        _ => "unknown",
    }
}

fn throw_on_unmappable(flags: i64) -> &'static str {
    match flags & 0x3000 {
        0x0000 => "assembly-default",
        0x1000 => "enabled",
        0x2000 => "disabled",
        _ => "unknown",
    }
}

fn parse_impl_maps(
    bytes: &Buf,
    layout: &MetadataLayout,
    extent: i64,
    modules: &[Value],
    members: &HashMap<String, MemberCore>,
    issues: &mut Vec<Issue>,
) -> R<Vec<Value>> {
    let module_names: HashMap<&str, &Value> =
        modules.iter().map(|m| (m["token"].as_str().unwrap_or_default(), m)).collect();
    let mut imports = Vec::new();
    let total = layout.table(28).map(|t| t.row_count).unwrap_or(0);
    let forwarded_tables = tables(&[4, 6]);
    for row in 1..=total {
        let mut local: Vec<Issue> = Vec::new();
        let result = (|| -> R<Value> {
            let mut cursor = metadata_row_cursor(bytes, layout, 28, row)?;
            let mapping_flags = cursor.u16()?;
            let forwarded_offset = cursor.offset();
            let forwarded_raw = cursor.index(layout.coded_index_size(Coded::MemberForwarded))?;
            let reason =
                metadata_coded_token_invalid_reason(forwarded_raw, 1, &forwarded_tables, &layout.row_counts);
            if reason.is_some() || forwarded_raw == 0 {
                local.push(Issue {
                    code: "invalid-row",
                    scope: format!("metadata.ImplMap:{}", metadata_token(28, row)),
                    offset: Some(forwarded_offset),
                    detail: match reason {
                        None => "ImplMap MemberForwarded coded index 0x0 is null, but the column must reference a Field or MethodDef row".to_string(),
                        Some(reason) => format!("ImplMap MemberForwarded coded index 0x{forwarded_raw:x} is invalid: {reason}"),
                    },
                });
            }
            let member_token = metadata_coded_token(forwarded_raw, 1, &forwarded_tables, &layout.row_counts);
            let import_index = cursor.index(layout.string_index_size)?;
            let import_name = read_metadata_string(bytes, layout, import_index, extent)?;
            let scope_offset = cursor.offset();
            let scope_row = cursor.index(layout.table_index_size(26))?;
            let module_count = layout.table(26).map(|t| t.row_count).unwrap_or(0);
            let valid_scope = scope_row > 0 && scope_row <= module_count;
            if !valid_scope {
                local.push(Issue {
                    code: "invalid-row",
                    scope: format!("metadata.ImplMap:{}", metadata_token(28, row)),
                    offset: Some(scope_offset),
                    detail: format!(
                        "ImplMap ImportScope row {scope_row} must reference a ModuleRef row between 1 and {module_count}"
                    ),
                });
            }
            let scope_token = if valid_scope { Some(metadata_token(26, scope_row)) } else { None };
            let member = member_token.as_ref().and_then(|t| members.get(t));
            Ok(json!({
                "token": metadata_token(28, row),
                "row_offset": cursor.start,
                "mapping_flags": mapping_flags,
                "mapping_flags_hex": flags_hex(mapping_flags),
                "member_token": member_token,
                "member_kind": member.map(|m| m.kind).unwrap_or("unknown"),
                "member_name": member.map(|m| m.name.clone()),
                "import_name": import_name,
                "import_scope_token": scope_token,
                "import_scope_name": scope_token.as_ref().and_then(|t| module_names.get(t.as_str())).map(|m| m["name"].clone()),
                "no_mangle": mapping_flags & 0x0001 != 0,
                "char_set": char_set(mapping_flags),
                "call_convention": call_convention(mapping_flags),
                "supports_last_error": mapping_flags & 0x0040 != 0,
                "best_fit": best_fit(mapping_flags),
                "throw_on_unmappable_char": throw_on_unmappable(mapping_flags),
                "verification": "managed-declaration-only",
            }))
        })();
        issues.append(&mut local);
        if let Some(value) = swallow(result, issues)? {
            imports.push(value);
        }
    }
    Ok(imports)
}

fn code_type_for(impl_flags: i64) -> &'static str {
    match impl_flags & 0x0003 {
        0x0000 => "il",
        0x0001 => "native",
        0x0002 => "optil",
        _ => "runtime",
    }
}

fn managed_kind_for(impl_flags: i64) -> &'static str {
    if impl_flags & 0x0004 == 0 {
        "managed"
    } else {
        "unmanaged"
    }
}

fn boundary_kind(pinvoke_declared: bool, code_type: &str, managed_kind: &str) -> &'static str {
    if pinvoke_declared {
        "pinvoke"
    } else if code_type == "native" {
        "native-body"
    } else if code_type == "runtime" {
        "runtime-provided"
    } else if managed_kind == "unmanaged" {
        "unmanaged-method"
    } else {
        "mixed-or-unknown"
    }
}

fn native_implementations(members: &[MemberCore], pinvoke_tokens: &HashSet<String>) -> Vec<Value> {
    let mut out = Vec::new();
    for method in members {
        if method.kind != "method" {
            continue;
        }
        let impl_flags = method.impl_flags.unwrap_or(0);
        let code_type = code_type_for(impl_flags);
        let managed_kind = managed_kind_for(impl_flags);
        let pinvoke_declared = pinvoke_tokens.contains(&method.token) || method.flags & 0x2000 != 0;
        if !pinvoke_declared && code_type == "il" && managed_kind == "managed" {
            continue;
        }
        let rva = method.rva.unwrap_or(0);
        out.push(json!({
            "token": method.token,
            "row_offset": method.row_offset,
            "name": method.name,
            "rva": rva,
            "flags": method.flags,
            "impl_flags": impl_flags,
            "code_type": code_type,
            "managed_kind": managed_kind,
            "pinvoke_declared": pinvoke_declared,
            "boundary_kind": boundary_kind(pinvoke_declared, code_type, managed_kind),
            "body_interpretation": if code_type == "il" && managed_kind == "managed" && !pinvoke_declared {
                "managed-cil"
            } else if method.rva == Some(0) || method.rva.is_none() {
                "not-file-backed"
            } else {
                "native-or-runtime"
            },
        }));
    }
    out
}

fn cli_native(pe: &PeLayout) -> Value {
    let Some(cli) = pe.cli.as_ref() else {
        return Value::Null;
    };
    json!({
        "il_only": cli.flags & 0x1 != 0,
        "requires_32bit": cli.flags & 0x2 != 0,
        "strong_name_signed": cli.flags & 0x8 != 0,
        "native_entry_point": cli.flags & 0x10 != 0,
        "ready_to_run_signature": cli.ready_to_run_signature,
        "managed_native_header_rva": cli.managed_native_header.rva,
        "managed_native_header_size": cli.managed_native_header.size,
    })
}

fn boundary_summary(native: &Value, module_refs: usize, imports: usize, implementations: usize) -> Value {
    let mixed = if native.is_null() {
        Value::Null
    } else {
        json!(
            native["managed_native_header_rva"] != 0
                || native["managed_native_header_size"] != 0
                || native["native_entry_point"] == true
        )
    };
    json!({
        "module_ref_count": module_refs,
        "pinvoke_import_count": imports,
        "native_implementation_count": implementations,
        "ready_to_run": if native.is_null() { Value::Null } else { native["ready_to_run_signature"].clone() },
        "mixed_mode_or_native_header": mixed,
    })
}

fn empty_inspection(
    target: &ManagedTarget,
    bytes: &[u8],
    classification: &str,
    native: Value,
    issues: &[Issue],
) -> R<Value> {
    let status = if issues.iter().any(|i| i.code == "resource-limit") {
        "partial"
    } else if classification == "malformed" {
        "malformed"
    } else {
        "absent"
    };
    let value = json!({
        "artifact": { "path": target.path, "sha256": target.sha256, "byte_length": bytes.len(), "format": "pe" },
        "module": null,
        "metadata": { "status": status, "version": null, "table_row_counts": {} },
        "identity_scope": {
            "token_identity": "build-local",
            "requires_artifact_sha256": target.sha256,
            "requires_mvid": null,
        },
        "cli_native": native,
        "module_refs": [],
        "pinvoke_imports": [],
        "native_implementations": [],
        "summary": boundary_summary(&native, 0, 0, 0),
        "coverage": { "state": "unavailable", "issues": issues_json(issues) },
        "limitations": [
            "No CLI metadata was admitted; native boundary declarations are unavailable.",
            "Static inspection does not load or execute target code, so native export resolution is not performed.",
        ],
    });
    Budget::new().admit(value)
}

/// Inspect managed/native boundary declarations from PE metadata without execution.
pub fn inspect_managed_native_boundaries_bytes(bytes: &[u8], target: &ManagedTarget) -> Result<Value, Failure> {
    let pe = match read_pe_layout(bytes) {
        Ok(pe) => pe,
        Err(Failure::Reader(issue)) => {
            return empty_inspection(target, bytes, "malformed", Value::Null, std::slice::from_ref(&issue))
        }
        Err(other) => return Err(other),
    };
    let Some(cli) = pe.cli.as_ref() else {
        let issues: Vec<Issue> = pe.cli_issue.iter().cloned().collect();
        return empty_inspection(
            target,
            bytes,
            if pe.cli_directory_present { "malformed" } else { "not-managed" },
            Value::Null,
            &issues,
        );
    };
    let buf = Buf(bytes);
    let mut issues: Vec<Issue> = Vec::new();
    let inventory_result = (|| -> R<(MetadataLayout, Inventory)> {
        let metadata_offset = pe.rva_to_offset(cli.metadata.rva, cli.metadata.size, "cli.metadata")?;
        let layout = read_metadata_layout(bytes, metadata_offset, cli.metadata.size)?;
        let resource_directory = read_resource_directory(&pe, &mut issues)?;
        let inventory = read_metadata_inventory(&buf, &layout, resource_directory)?;
        Ok((layout, inventory))
    })();
    let (layout, inventory) = match inventory_result {
        Ok(pair) => pair,
        Err(Failure::Reader(issue)) => {
            return empty_inspection(target, bytes, "malformed", cli_native(&pe), std::slice::from_ref(&issue))
        }
        Err(other) => return Err(other),
    };
    let attempt = |issues: &mut Vec<Issue>| -> R<Value> {
        let extent = layout.strings.size.max(layout.blob.size);
        issues.extend(inventory.issues.iter().cloned());
        let module_refs = parse_module_refs(&buf, &layout, extent, issues)?;
        let mut members_list: Vec<MemberCore> = Vec::new();
        parse_fields(&buf, &layout, extent, issues, &mut members_list)?;
        parse_methods(&buf, &layout, extent, issues, &mut members_list)?;
        let mut members: HashMap<String, MemberCore> = HashMap::new();
        for member in &members_list {
            members.insert(member.token.clone(), member.clone());
        }
        let imports = parse_impl_maps(&buf, &layout, extent, &module_refs, &members, issues)?;
        let pinvoke_tokens: HashSet<String> =
            imports.iter().filter_map(|i| i["member_token"].as_str().map(str::to_string)).collect();
        // `members.values()` iterates insertion order of the Map (fields before methods, last write wins).
        let mut ordered: Vec<MemberCore> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for member in &members_list {
            if seen.insert(member.token.clone()) {
                ordered.push(members[&member.token].clone());
            }
        }
        let implementations = native_implementations(&ordered, &pinvoke_tokens);
        let native = cli_native(&pe);
        let summary = boundary_summary(&native, module_refs.len(), imports.len(), implementations.len());
        let value = json!({
            "artifact": { "path": target.path, "sha256": target.sha256, "byte_length": bytes.len(), "format": "pe" },
            "module": inventory.module,
            "metadata": {
                "status": if issues.is_empty() { "complete" } else { "partial" },
                "version": layout.version,
                "table_row_counts": table_row_counts(&layout),
            },
            "identity_scope": {
                "token_identity": "build-local",
                "requires_artifact_sha256": target.sha256,
                "requires_mvid": inventory.module.as_ref().and_then(|m| m["mvid"].as_str()),
            },
            "cli_native": native,
            "module_refs": module_refs,
            "pinvoke_imports": imports,
            "native_implementations": implementations,
            "summary": summary,
            "coverage": {
                "state": if issues.is_empty() { "complete" } else { "partial" },
                "issues": issues_json(issues),
            },
            "limitations": [
                "P/Invoke rows prove managed import declarations only; this inspection does not verify that a native library, export, thunk, or provider-qualified function exists.",
                "Managed metadata tokens are build-local coordinates and are only meaningful with the reported artifact SHA-256 and MVID.",
                "ReadyToRun, NativeAOT, C++/CLI, and IL2CPP native semantics require separately selected native-provider evidence; this tool does not translate managed tokens into native addresses.",
            ],
        });
        layout.budget.admit(value)
    };
    match attempt(&mut issues) {
        Ok(value) => Ok(value),
        Err(Failure::Reader(issue)) => {
            let mut all = issues.clone();
            all.push(issue);
            empty_inspection(target, bytes, "malformed", cli_native(&pe), &all)
        }
        Err(other) => Err(other),
    }
}
