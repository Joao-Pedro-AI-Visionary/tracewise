//! Identity-table inventory (REA `ManagedMetadataInventory` and
//! `ManagedMetadataInventoryRows`): module, assembly, references, resources and
//! custom attributes.

use serde_json::{json, Value};

use crate::common::{failure, js_sort, read_value, unique_issues, Buf, Failure, Issue, R};
use crate::heaps::{
    metadata_coded_token, metadata_coded_token_invalid_reason, metadata_row_cursor, metadata_token,
    read_metadata_blob, read_metadata_guid, read_metadata_string, tables,
};
use crate::layout::{metadata_row_offset, Coded, MetadataLayout, HAS_CUSTOM_ATTRIBUTE_TABLES, METADATA_TABLE_NAMES};
use crate::pe::PeLayout;

#[derive(Debug, Clone, Copy)]
pub struct ResourceDirectory {
    pub offset: i64,
    pub size: i64,
}

/// Map optional embedded resources without discarding admitted CLI metadata.
pub fn read_resource_directory(pe: &PeLayout, issues: &mut Vec<Issue>) -> R<Option<ResourceDirectory>> {
    let Some(cli) = pe.cli.as_ref() else {
        return Ok(None);
    };
    let resources = cli.resources;
    if resources.rva == 0 && resources.size == 0 {
        return Ok(None);
    }
    read_value(
        || {
            Ok(ResourceDirectory {
                offset: pe.rva_to_offset(resources.rva, resources.size, "cli.resources")?,
                size: resources.size,
            })
        },
        issues,
    )
}

pub struct Inventory {
    pub module: Option<Value>,
    pub assembly: Option<Value>,
    pub target_frameworks: Vec<String>,
    pub reference_names: Vec<String>,
    pub references: Vec<Value>,
    pub resources: Vec<Value>,
    pub attributes: Vec<Value>,
    pub issues: Vec<Issue>,
}

fn heap_extent(layout: &MetadataLayout) -> i64 {
    layout.strings.size.max(layout.blob.size)
}

fn public_key_identity(bytes: &[u8], kind: &str, layout: &MetadataLayout) -> R<Value> {
    let none = bytes.is_empty();
    let sha256 = if none { Value::Null } else { Value::String(layout.budget.digest(bytes, false)?) };
    let token = if none {
        Value::Null
    } else if kind == "public-key" {
        let sha1 = layout.budget.digest(bytes, true)?;
        let raw = hex::decode(&sha1).unwrap_or_default();
        let mut tail: Vec<u8> = raw[raw.len().saturating_sub(8)..].to_vec();
        tail.reverse();
        Value::String(hex::encode(tail))
    } else if bytes.len() == 8 {
        Value::String(hex::encode(bytes))
    } else {
        Value::Null
    };
    Ok(json!({
        "kind": if none { "none" } else { kind },
        "byte_length": bytes.len(),
        "sha256": sha256,
        "token": token,
    }))
}

pub fn read_module(bytes: &Buf, layout: &MetadataLayout, extent: i64) -> R<Option<Value>> {
    let Some(table) = layout.table(0) else {
        return Ok(None);
    };
    if table.row_count == 0 {
        return Ok(None);
    }
    let table_offset = table.offset;
    let mut cursor = metadata_row_cursor(bytes, layout, 0, 1)?;
    let generation = cursor.u16()?;
    let name_index = cursor.index(layout.string_index_size)?;
    let name = read_metadata_string(bytes, layout, name_index, extent)?;
    let mvid_index = cursor.index(layout.guid_index_size)?;
    let mvid = read_metadata_guid(bytes, layout, mvid_index)?;
    let enc_index = cursor.index(layout.guid_index_size)?;
    let enc_id = read_metadata_guid(bytes, layout, enc_index)?;
    let enc_base_index = cursor.index(layout.guid_index_size)?;
    let enc_base_id = read_metadata_guid(bytes, layout, enc_base_index)?;
    Ok(Some(json!({
        "name": name,
        "generation": generation,
        "mvid": mvid,
        "enc_id": enc_id,
        "enc_base_id": enc_base_id,
        "token": metadata_token(0, 1),
        "row_offset": table_offset,
    })))
}

fn version_string(cursor: &mut crate::heaps::RowCursor) -> R<String> {
    let a = cursor.u16()?;
    let b = cursor.u16()?;
    let c = cursor.u16()?;
    let d = cursor.u16()?;
    Ok(format!("{a}.{b}.{c}.{d}"))
}

pub fn read_assembly(bytes: &Buf, layout: &MetadataLayout, extent: i64) -> R<Option<Value>> {
    let Some(table) = layout.table(32) else {
        return Ok(None);
    };
    if table.row_count == 0 {
        return Ok(None);
    }
    let table_offset = table.offset;
    let mut cursor = metadata_row_cursor(bytes, layout, 32, 1)?;
    let hash_algorithm = cursor.u32()?;
    let version = version_string(&mut cursor)?;
    let flags = cursor.u32()?;
    let key_index = cursor.index(layout.blob_index_size)?;
    let key = read_metadata_blob(bytes, layout, key_index, extent)?;
    let name_index = cursor.index(layout.string_index_size)?;
    let name = read_metadata_string(bytes, layout, name_index, extent)?;
    let culture_index = cursor.index(layout.string_index_size)?;
    let culture = read_metadata_string(bytes, layout, culture_index, extent)?;
    let kind = if flags & 1 == 0 { "public-key-token" } else { "public-key" };
    Ok(Some(json!({
        "name": name,
        "version": version,
        "culture": if culture.is_empty() { Value::Null } else { Value::String(culture) },
        "flags": flags,
        "hash_algorithm": hash_algorithm,
        "public_key": public_key_identity(key, kind, layout)?,
        "token": metadata_token(32, 1),
        "row_offset": table_offset,
    })))
}

pub fn read_assembly_reference(bytes: &Buf, layout: &MetadataLayout, row: i64, extent: i64) -> R<Value> {
    let mut cursor = metadata_row_cursor(bytes, layout, 35, row)?;
    let version = version_string(&mut cursor)?;
    let flags = cursor.u32()?;
    let key_index = cursor.index(layout.blob_index_size)?;
    let key_or_token = read_metadata_blob(bytes, layout, key_index, extent)?;
    let name_index = cursor.index(layout.string_index_size)?;
    let name = read_metadata_string(bytes, layout, name_index, extent)?;
    let culture_index = cursor.index(layout.string_index_size)?;
    let culture = read_metadata_string(bytes, layout, culture_index, extent)?;
    let hash_index = cursor.index(layout.blob_index_size)?;
    let hash_value = read_metadata_blob(bytes, layout, hash_index, extent)?;
    let kind = if flags & 1 == 0 { "public-key-token" } else { "public-key" };
    let key_identity = public_key_identity(key_or_token, kind, layout)?;
    let hash_sha = if hash_value.is_empty() { Value::Null } else { Value::String(layout.budget.digest(hash_value, false)?) };
    Ok(json!({
        "name": name,
        "version": version,
        "culture": if culture.is_empty() { Value::Null } else { Value::String(culture) },
        "flags": flags,
        "public_key_or_token": key_identity,
        "hash_value_sha256": hash_sha,
        "hash_value_length": hash_value.len(),
        "token": metadata_token(35, row),
        "row_offset": metadata_row_offset(layout, 35, row)?,
    }))
}

fn full_type_name(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_string()
    } else {
        format!("{namespace}.{name}")
    }
}

fn read_type_name(bytes: &Buf, layout: &MetadataLayout, table: usize, row: i64, extent: i64) -> R<Option<String>> {
    match layout.table(table) {
        Some(descriptor) if row >= 1 && row <= descriptor.row_count => {}
        _ => return Ok(None),
    }
    let mut cursor = metadata_row_cursor(bytes, layout, table, row)?;
    if table == 1 {
        cursor.index(layout.coded_index_size(Coded::ResolutionScope))?;
    } else {
        cursor.u32()?;
    }
    let name_index = cursor.index(layout.string_index_size)?;
    let name = read_metadata_string(bytes, layout, name_index, extent)?;
    let namespace_index = cursor.index(layout.string_index_size)?;
    let namespace = read_metadata_string(bytes, layout, namespace_index, extent)?;
    Ok(Some(full_type_name(&namespace, &name)))
}

fn method_list_for_type(bytes: &Buf, layout: &MetadataLayout, row: i64) -> R<i64> {
    let mut cursor = metadata_row_cursor(bytes, layout, 2, row)?;
    cursor.u32()?;
    cursor.index(layout.string_index_size)?;
    cursor.index(layout.string_index_size)?;
    cursor.index(layout.coded_index_size(Coded::TypeDefOrRef))?;
    cursor.index(layout.table_index_size(4))?;
    cursor.index(layout.table_index_size(6))
}

fn declaring_type_for_method(bytes: &Buf, layout: &MetadataLayout, method_row: i64, extent: i64) -> R<Option<String>> {
    let (Some(types), Some(methods)) = (layout.table(2), layout.table(6)) else {
        return Ok(None);
    };
    let (type_rows, method_rows) = (types.row_count, methods.row_count);
    for row in 1..=type_rows {
        let mut cursor = metadata_row_cursor(bytes, layout, 2, row)?;
        cursor.u32()?;
        let name_index = cursor.index(layout.string_index_size)?;
        let namespace_index = cursor.index(layout.string_index_size)?;
        cursor.index(layout.coded_index_size(Coded::TypeDefOrRef))?;
        cursor.index(layout.table_index_size(4))?;
        let method_start = cursor.index(layout.table_index_size(6))?;
        let method_end = if row == type_rows { method_rows + 1 } else { method_list_for_type(bytes, layout, row + 1)? };
        if method_row < method_start || method_row >= method_end {
            continue;
        }
        let name = read_metadata_string(bytes, layout, name_index, extent)?;
        let namespace = read_metadata_string(bytes, layout, namespace_index, extent)?;
        return Ok(Some(full_type_name(&namespace, &name)));
    }
    Ok(None)
}

fn attribute_type_name(bytes: &Buf, layout: &MetadataLayout, raw_type: i64, extent: i64) -> R<Option<String>> {
    let tag = raw_type & 7;
    let row = raw_type / 8;
    if row == 0 {
        return Ok(None);
    }
    if tag == 2 {
        return declaring_type_for_method(bytes, layout, row, extent);
    }
    if tag != 3 {
        return Ok(None);
    }
    match layout.table(10) {
        Some(member_refs) if row <= member_refs.row_count => {}
        _ => return Ok(None),
    }
    let mut cursor = metadata_row_cursor(bytes, layout, 10, row)?;
    let parent = cursor.index(layout.coded_index_size(Coded::MemberRefParent))?;
    let parent_tag = parent & 7;
    let parent_row = parent / 8;
    match parent_tag {
        0 => read_type_name(bytes, layout, 2, parent_row, extent),
        1 => read_type_name(bytes, layout, 1, parent_row, extent),
        3 => declaring_type_for_method(bytes, layout, parent_row, extent),
        _ => Ok(None),
    }
}

fn decode_compressed_length(blob: &[u8], offset: usize) -> Option<(usize, usize)> {
    let first = *blob.get(offset)? as usize;
    if first & 0x80 == 0 {
        return Some((first, 1));
    }
    if first & 0xc0 == 0x80 {
        if let Some(second) = blob.get(offset + 1) {
            return Some((((first & 0x3f) << 8) | *second as usize, 2));
        }
    }
    if first & 0xe0 == 0xc0 {
        if let (Some(b1), Some(b2), Some(b3)) = (blob.get(offset + 1), blob.get(offset + 2), blob.get(offset + 3)) {
            return Some((
                (first & 0x1f) * 0x0100_0000 + *b1 as usize * 0x01_0000 + *b2 as usize * 0x0100 + *b3 as usize,
                4,
            ));
        }
    }
    None
}

fn decode_fixed_string(blob: &[u8], layout: &MetadataLayout) -> R<Option<String>> {
    if blob.len() < 3 || u16::from_le_bytes([blob[0], blob[1]]) != 1 || blob[2] == 0xff {
        return Ok(None);
    }
    let Some((length, prefix)) = decode_compressed_length(blob, 2) else {
        return Ok(None);
    };
    let start = 2 + prefix;
    if start as i64 > blob.len() as i64 - length as i64 {
        return Ok(None);
    }
    layout.budget.reserve_string(length as u64, Some(layout.blob.offset))?;
    Ok(std::str::from_utf8(&blob[start..start + length]).ok().map(str::to_string))
}

pub fn read_custom_attribute(bytes: &Buf, layout: &MetadataLayout, row: i64, extent: i64) -> R<Value> {
    let mut cursor = metadata_row_cursor(bytes, layout, 12, row)?;
    let parent_raw = cursor.index(layout.coded_index_size(Coded::HasCustomAttribute))?;
    let type_offset = cursor.offset();
    let type_raw = cursor.index(layout.coded_index_size(Coded::CustomAttributeType))?;
    let value_index = cursor.index(layout.blob_index_size)?;
    let value = read_metadata_blob(bytes, layout, value_index, extent)?;
    let parent_tables = tables(&HAS_CUSTOM_ATTRIBUTE_TABLES);
    let parent = metadata_coded_token(parent_raw, 5, &parent_tables, &layout.row_counts);
    let parent_reason = metadata_coded_token_invalid_reason(parent_raw, 5, &parent_tables, &layout.row_counts);
    let Some(parent) = parent else {
        return Err(failure(
            "invalid-row",
            format!("metadata.CustomAttribute:{}", metadata_token(12, row)),
            format!(
                "CustomAttribute parent coded index 0x{:x} is invalid{}",
                parent_raw,
                match parent_reason {
                    None => " because the required parent is null".to_string(),
                    Some(reason) => format!(": {reason}"),
                }
            ),
            Some(cursor.start),
        ));
    };
    let type_tables: Vec<Option<i64>> = vec![None, None, Some(6), Some(10)];
    let type_reason = metadata_coded_token_invalid_reason(type_raw, 3, &type_tables, &layout.row_counts);
    if type_reason.is_some() || type_raw == 0 {
        return Err(failure(
            "invalid-row",
            format!("metadata.CustomAttribute:{}", metadata_token(12, row)),
            match type_reason {
                None => "CustomAttribute constructor coded index 0x0 is null, but Type must reference a MethodDef or MemberRef row".to_string(),
                Some(reason) => format!("CustomAttribute constructor coded index 0x{type_raw:x} is invalid: {reason}"),
            },
            Some(type_offset),
        ));
    }
    let type_name = attribute_type_name(bytes, layout, type_raw, extent)?;
    let value_sha256 = layout.budget.digest(value, false)?;
    let decoded = if type_name.as_deref() == Some("System.Runtime.Versioning.TargetFrameworkAttribute") {
        decode_fixed_string(value, layout)?
    } else {
        None
    };
    Ok(json!({
        "parent_token": parent,
        "constructor_token": metadata_coded_token(type_raw, 3, &type_tables, &layout.row_counts),
        "type_name": type_name,
        "value_length": value.len(),
        "value_sha256": value_sha256,
        "decoded_fixed_string": decoded,
        "token": metadata_token(12, row),
        "row_offset": cursor.start,
    }))
}

pub fn read_resource(
    bytes: &Buf,
    layout: &MetadataLayout,
    row: i64,
    directory: Option<ResourceDirectory>,
    issues: &mut Vec<Issue>,
) -> R<Value> {
    let mut cursor = metadata_row_cursor(bytes, layout, 40, row)?;
    let declared_offset = cursor.u32()?;
    let flags = cursor.u32()?;
    let name_index = cursor.index(layout.string_index_size)?;
    let name = read_metadata_string(bytes, layout, name_index, layout.strings.size.max(layout.blob.size))?;
    let implementation_offset = cursor.offset();
    let implementation_raw = cursor.index(layout.coded_index_size(Coded::Implementation))?;
    let impl_tables = tables(&[38, 35, 39]);
    let implementation_token = metadata_coded_token(implementation_raw, 2, &impl_tables, &layout.row_counts);
    let implementation_reason =
        metadata_coded_token_invalid_reason(implementation_raw, 2, &impl_tables, &layout.row_counts);
    let scope = format!("metadata.ManifestResource:{}", metadata_token(40, row));
    if let Some(reason) = implementation_reason {
        issues.push(Issue {
            code: "invalid-row",
            scope: scope.clone(),
            offset: Some(implementation_offset),
            detail: format!("ManifestResource implementation coded index 0x{implementation_raw:x} is invalid: {reason}"),
        });
    }
    let mut data_length: Option<i64> = None;
    let mut data_sha256: Option<String> = None;
    if implementation_raw == 0 {
        match directory {
            Some(dir) if declared_offset <= dir.size - 4 => {
                let start = dir.offset + declared_offset;
                let length = bytes.u32(start)? as i64;
                data_length = Some(length);
                if length > dir.size - declared_offset - 4 {
                    issues.push(Issue {
                        code: "invalid-resource",
                        scope,
                        offset: Some(start),
                        detail: "Embedded resource length leaves the CLI resources directory".to_string(),
                    });
                } else {
                    let slice = bytes.sub(start + 4, start + 4 + length);
                    data_sha256 = Some(layout.budget.digest(slice.bytes(), false)?);
                }
            }
            other => {
                issues.push(Issue {
                    code: "invalid-resource",
                    scope,
                    offset: other.map(|d| d.offset).or(None),
                    detail: "Embedded resource offset leaves the CLI resources directory".to_string(),
                });
            }
        }
    }
    let visibility = match flags & 7 {
        1 => "public",
        2 => "private",
        _ => "unknown",
    };
    Ok(json!({
        "name": name,
        "flags": flags,
        "visibility": visibility,
        "implementation_token": implementation_token,
        "embedded": implementation_raw == 0,
        "declared_offset": declared_offset,
        "data_length": data_length,
        "data_sha256": data_sha256,
        "token": metadata_token(40, row),
        "row_offset": cursor.start,
    }))
}

fn validate_identity_table_counts(layout: &MetadataLayout, issues: &mut Vec<Issue>) {
    let module_rows = layout.table(0).map(|t| t.row_count).unwrap_or(0);
    if module_rows != 1 {
        issues.push(Issue {
            code: "invalid-row",
            scope: "metadata.Module".to_string(),
            offset: layout.table(0).map(|t| t.offset),
            detail: format!("Module table must contain exactly one row; found {module_rows}"),
        });
    }
    let assembly_rows = layout.table(32).map(|t| t.row_count).unwrap_or(0);
    if assembly_rows > 1 {
        issues.push(Issue {
            code: "invalid-row",
            scope: "metadata.Assembly".to_string(),
            offset: layout.table(32).map(|t| t.offset),
            detail: format!("Assembly table can contain at most one row; found {assembly_rows}"),
        });
    }
}

/// Inventory identity tables without CLR reflection or execution.
pub fn read_metadata_inventory(
    bytes: &Buf,
    layout: &MetadataLayout,
    resource_directory: Option<ResourceDirectory>,
) -> R<Inventory> {
    let mut issues: Vec<Issue> = Vec::new();
    validate_identity_table_counts(layout, &mut issues);
    let extent = heap_extent(layout);
    let module = read_value(|| read_module(bytes, layout, extent), &mut issues)?.flatten();
    let assembly = read_value(|| read_assembly(bytes, layout, extent), &mut issues)?.flatten();

    // references
    let mut references = Vec::new();
    {
        let total = layout.table(35).map(|t| t.row_count).unwrap_or(0);
        for row in 1..=total {
            if let Some(reference) = read_value(|| read_assembly_reference(bytes, layout, row, extent), &mut issues)? {
                references.push(reference);
            }
        }
    }
    let mut reference_names: Vec<String> = Vec::new();
    for reference in &references {
        let name = reference["name"].as_str().unwrap_or_default().to_string();
        if !reference_names.contains(&name) {
            reference_names.push(name);
        }
    }
    js_sort(&mut reference_names);

    // resources
    let mut resources = Vec::new();
    {
        let total = layout.table(40).map(|t| t.row_count).unwrap_or(0);
        for row in 1..=total {
            match read_resource(bytes, layout, row, resource_directory, &mut issues) {
                Ok(resource) => resources.push(resource),
                Err(Failure::Reader(issue)) if issue.code != "resource-limit" => issues.push(issue),
                Err(other) => return Err(other),
            }
        }
    }

    // attributes
    let attributes = {
        let total = layout.table(12).map(|t| t.row_count).unwrap_or(0);
        let mut items = Vec::new();
        for row in 1..=total {
            if let Some(attribute) = read_value(|| read_custom_attribute(bytes, layout, row, extent), &mut issues)? {
                items.push(attribute);
            }
        }
        items
    };
    let mut frameworks: Vec<String> = Vec::new();
    for attribute in &attributes {
        if attribute["parent_token"] == metadata_token(32, 1)
            && attribute["type_name"] == "System.Runtime.Versioning.TargetFrameworkAttribute"
        {
            if let Some(text) = attribute["decoded_fixed_string"].as_str() {
                if !frameworks.iter().any(|f| f == text) {
                    frameworks.push(text.to_string());
                }
            }
        }
    }
    js_sort(&mut frameworks);

    Ok(Inventory {
        module,
        assembly,
        target_frameworks: frameworks,
        reference_names,
        references,
        resources,
        attributes,
        issues: unique_issues(&issues),
    })
}

/// Stable table-name/count projection for caller-visible coverage.
pub fn table_row_counts(layout: &MetadataLayout) -> Value {
    let mut map = serde_json::Map::new();
    for table in layout.tables.values() {
        let name = METADATA_TABLE_NAMES.get(table.index).copied().map(str::to_string).unwrap_or_else(|| format!("Table{}", table.index));
        map.insert(name, json!(table.row_count));
    }
    Value::Object(map)
}
