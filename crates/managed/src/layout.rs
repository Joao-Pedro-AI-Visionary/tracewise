//! ECMA-335 metadata root, stream and table layout (REA `ManagedMetadataLayout`
//! and `ManagedMetadataRowSizes`).

use std::collections::BTreeMap;

use crate::budget::Budget;
use crate::common::{failure, js_sort, Buf, R};

pub const METADATA_TABLE_NAMES: [&str; 45] = [
    "Module",
    "TypeRef",
    "TypeDef",
    "FieldPtr",
    "Field",
    "MethodPtr",
    "MethodDef",
    "ParamPtr",
    "Param",
    "InterfaceImpl",
    "MemberRef",
    "Constant",
    "CustomAttribute",
    "FieldMarshal",
    "DeclSecurity",
    "ClassLayout",
    "FieldLayout",
    "StandAloneSig",
    "EventMap",
    "EventPtr",
    "Event",
    "PropertyMap",
    "PropertyPtr",
    "Property",
    "MethodSemantics",
    "MethodImpl",
    "ModuleRef",
    "TypeSpec",
    "ImplMap",
    "FieldRVA",
    "ENCLog",
    "ENCMap",
    "Assembly",
    "AssemblyProcessor",
    "AssemblyOS",
    "AssemblyRef",
    "AssemblyRefProcessor",
    "AssemblyRefOS",
    "File",
    "ExportedType",
    "ManifestResource",
    "NestedClass",
    "GenericParam",
    "MethodSpec",
    "GenericParamConstraint",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coded {
    TypeDefOrRef,
    HasConstant,
    HasCustomAttribute,
    HasFieldMarshal,
    HasDeclSecurity,
    MemberRefParent,
    HasSemantics,
    MethodDefOrRef,
    MemberForwarded,
    Implementation,
    CustomAttributeType,
    ResolutionScope,
    TypeOrMethodDef,
}

pub const HAS_CUSTOM_ATTRIBUTE_TABLES: [i64; 22] =
    [6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43];

impl Coded {
    fn descriptor(self) -> (u32, &'static [i64]) {
        match self {
            Coded::TypeDefOrRef => (2, &[2, 1, 27]),
            Coded::HasConstant => (2, &[4, 8, 23]),
            Coded::HasCustomAttribute => (5, &HAS_CUSTOM_ATTRIBUTE_TABLES),
            Coded::HasFieldMarshal => (1, &[4, 8]),
            Coded::HasDeclSecurity => (2, &[2, 6, 32]),
            Coded::MemberRefParent => (3, &[2, 1, 26, 6, 27]),
            Coded::HasSemantics => (1, &[20, 23]),
            Coded::MethodDefOrRef => (1, &[6, 10]),
            Coded::MemberForwarded => (1, &[4, 6]),
            Coded::Implementation => (2, &[38, 35, 39]),
            Coded::CustomAttributeType => (3, &[6, 10]),
            Coded::ResolutionScope => (2, &[0, 26, 35, 1]),
            Coded::TypeOrMethodDef => (1, &[2, 6]),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Stream {
    pub offset: i64,
    pub size: i64,
}

#[derive(Debug, Clone)]
pub struct TableLayout {
    pub index: usize,
    pub name: &'static str,
    pub row_count: i64,
    pub row_size: i64,
    pub offset: i64,
}

pub struct MetadataLayout {
    pub root_offset: i64,
    pub size: i64,
    pub version: String,
    pub stream_names: Vec<String>,
    pub strings: Stream,
    pub guid: Stream,
    pub blob: Stream,
    pub tables: BTreeMap<usize, TableLayout>,
    pub row_counts: Vec<i64>,
    pub string_index_size: i64,
    pub guid_index_size: i64,
    pub blob_index_size: i64,
    pub budget: Budget,
}

fn require_range(bytes: &Buf, offset: i64, length: i64, scope: &str) -> R<()> {
    if offset < 0 || length < 0 || offset > bytes.len() - length {
        return Err(failure(
            "invalid-metadata-root",
            scope,
            format!("{scope} leaves the metadata byte range"),
            if offset >= 0 { Some(offset) } else { None },
        ));
    }
    Ok(())
}

fn align4(value: i64) -> i64 {
    (value + 3) & !3
}

fn read_stream_name(bytes: &Buf, offset: i64) -> R<(String, i64)> {
    let end_limit = bytes.len().min(offset + 32);
    let mut end = offset;
    while end < end_limit && bytes.at(end) != Some(0) {
        end += 1;
    }
    if end == end_limit {
        return Err(failure(
            "invalid-stream",
            "metadata.stream-name",
            "Metadata stream name is missing a bounded terminator",
            Some(offset),
        ));
    }
    let name_bytes = &bytes.0[offset as usize..end as usize];
    if name_bytes.iter().any(|b| *b < 0x20 || *b > 0x7e) {
        return Err(failure(
            "invalid-stream",
            "metadata.stream-name",
            "Metadata stream name is not printable ASCII",
            Some(offset),
        ));
    }
    Ok((String::from_utf8_lossy(name_bytes).into_owned(), align4(end + 1)))
}

fn coded_size(name: Coded, row_counts: &[i64]) -> i64 {
    let (bits, tables) = name.descriptor();
    let mut maximum = 0;
    for table in tables {
        maximum = maximum.max(row_counts.get(*table as usize).copied().unwrap_or(0));
    }
    if maximum < (1i64 << (16 - bits)) {
        2
    } else {
        4
    }
}

fn table_size(index: usize, rows: &[i64]) -> i64 {
    if rows.get(index).copied().unwrap_or(0) < 0x1_0000 {
        2
    } else {
        4
    }
}

struct RowSizeContext<'a> {
    rows: &'a [i64],
    string: i64,
    guid: i64,
    blob: i64,
}

impl RowSizeContext<'_> {
    fn t(&self, index: usize) -> i64 {
        table_size(index, self.rows)
    }
    fn c(&self, name: Coded) -> i64 {
        coded_size(name, self.rows)
    }
}

fn compute_row_size(table: usize, x: &RowSizeContext) -> R<i64> {
    let s = x.string;
    let g = x.guid;
    let b = x.blob;
    Ok(match table {
        0 => 2 + s + g * 3,
        1 => x.c(Coded::ResolutionScope) + s * 2,
        2 => 4 + s * 2 + x.c(Coded::TypeDefOrRef) + x.t(4) + x.t(6),
        3 => x.t(4),
        4 => 2 + s + b,
        5 => x.t(6),
        6 => 8 + s + b + x.t(8),
        7 => x.t(8),
        8 => 4 + s,
        9 => x.t(2) + x.c(Coded::TypeDefOrRef),
        10 => x.c(Coded::MemberRefParent) + s + b,
        11 => 2 + x.c(Coded::HasConstant) + b,
        12 => x.c(Coded::HasCustomAttribute) + x.c(Coded::CustomAttributeType) + b,
        13 => x.c(Coded::HasFieldMarshal) + b,
        14 => 2 + x.c(Coded::HasDeclSecurity) + b,
        15 => 6 + x.t(2),
        16 => 4 + x.t(4),
        17 => b,
        18 => x.t(2) + x.t(20),
        19 => x.t(20),
        20 => 2 + s + x.c(Coded::TypeDefOrRef),
        21 => x.t(2) + x.t(23),
        22 => x.t(23),
        23 => 2 + s + b,
        24 => 2 + x.t(6) + x.c(Coded::HasSemantics),
        25 => x.t(2) + x.c(Coded::MethodDefOrRef) * 2,
        26 => s,
        27 => b,
        28 => 2 + x.c(Coded::MemberForwarded) + s + x.t(26),
        29 => 4 + x.t(4),
        30 => 8,
        31 => 4,
        32 => 16 + b + s * 2,
        33 => 4,
        34 => 12,
        35 => 12 + b * 2 + s * 2,
        36 => 4 + x.t(35),
        37 => 12 + x.t(35),
        38 => 4 + s + b,
        39 => 8 + s * 2 + x.c(Coded::Implementation),
        40 => 8 + s + x.c(Coded::Implementation),
        41 => x.t(2) * 2,
        42 => 4 + x.c(Coded::TypeOrMethodDef) + s,
        43 => x.c(Coded::MethodDefOrRef) + b,
        44 => x.t(42) + x.c(Coded::TypeDefOrRef),
        other => {
            return Err(failure(
                "invalid-tables",
                "metadata.tables",
                format!("Metadata table {other} is unsupported"),
                None,
            ))
        }
    })
}

struct ParsedStreams {
    streams: BTreeMap<String, Stream>,
    version: String,
}

fn read_metadata_streams(bytes: &Buf, root_offset: i64, budget: &Budget) -> R<ParsedStreams> {
    if bytes.u32(0)? != 0x424a_5342 {
        return Err(failure(
            "invalid-metadata-root",
            "metadata.signature",
            "CLI metadata signature is not BSJB",
            Some(root_offset),
        ));
    }
    let version_length = bytes.u32(12)? as i64;
    require_range(bytes, 16, version_length, "metadata.version")?;
    let version_bytes = bytes.sub(16, 16 + version_length);
    let zero = version_bytes.bytes().iter().position(|b| *b == 0);
    let decoded = zero.unwrap_or(version_bytes.bytes().len());
    budget.reserve_string(decoded as u64, Some(root_offset + 16))?;
    let version = String::from_utf8_lossy(&version_bytes.bytes()[..decoded]).into_owned();
    let mut cursor = align4(16 + version_length);
    require_range(bytes, cursor, 4, "metadata.stream-count")?;
    let stream_count = bytes.u16(cursor + 2)?;
    if stream_count == 0 || stream_count > 64 {
        return Err(failure(
            "invalid-stream",
            "metadata.stream-count",
            "Metadata stream count is outside the admitted range",
            Some(root_offset + cursor + 2),
        ));
    }
    cursor += 4;
    let mut streams = BTreeMap::new();
    for _ in 0..stream_count {
        require_range(bytes, cursor, 8, "metadata.stream-header")?;
        let relative_offset = bytes.u32(cursor)? as i64;
        let stream_size = bytes.u32(cursor + 4)? as i64;
        let (name, next) = read_stream_name(bytes, cursor + 8)?;
        if streams.contains_key(&name) {
            return Err(failure(
                "invalid-stream",
                "metadata.stream-header",
                format!("Duplicate metadata stream {name}"),
                Some(root_offset + cursor),
            ));
        }
        require_range(bytes, relative_offset, stream_size, &format!("metadata.{name}"))?;
        streams.insert(name, Stream { offset: root_offset + relative_offset, size: stream_size });
        cursor = next;
    }
    Ok(ParsedStreams { streams, version })
}

struct TablesHeader {
    table_bytes_offset: i64,
    table_bytes_len: i64,
    tables_offset: i64,
    string: i64,
    guid: i64,
    blob: i64,
    valid: u64,
}

fn stream_by_name<'a>(streams: &'a BTreeMap<String, Stream>, names: &[&str]) -> Option<&'a Stream> {
    names.iter().find_map(|name| streams.get(*name))
}

fn require_stream(streams: &BTreeMap<String, Stream>, name: &str) -> R<Stream> {
    streams.get(name).copied().ok_or_else(|| {
        failure(
            "missing-stream",
            format!("metadata.{name}"),
            format!("Required metadata stream {name} is absent"),
            None,
        )
    })
}

fn read_tables_header(artifact: &Buf, streams: &BTreeMap<String, Stream>) -> R<TablesHeader> {
    let Some(tables_stream) = stream_by_name(streams, &["#~", "#-"]) else {
        return Err(failure(
            "missing-stream",
            "metadata.tables",
            "Required metadata table stream #~ or #- is absent",
            None,
        ));
    };
    let table_bytes = artifact.sub(tables_stream.offset, tables_stream.offset + tables_stream.size);
    // requireRange(tableBytes, 0, 24) throws the metadata-root flavour.
    require_range(&table_bytes, 0, 24, "metadata.tables-header")?;
    let heap_sizes = table_bytes.u8(6).unwrap_or(0);
    let valid = table_bytes.u64(8)?;
    let supported_mask: u64 = (1u64 << METADATA_TABLE_NAMES.len()) - 1;
    if valid & !supported_mask != 0 {
        return Err(failure(
            "invalid-tables",
            "metadata.valid-mask",
            "Metadata valid mask names unsupported tables outside the admitted ECMA-335 range",
            Some(tables_stream.offset + 8),
        ));
    }
    Ok(TablesHeader {
        table_bytes_offset: tables_stream.offset,
        table_bytes_len: table_bytes.len(),
        tables_offset: tables_stream.offset,
        string: if heap_sizes & 0x01 == 0 { 2 } else { 4 },
        guid: if heap_sizes & 0x02 == 0 { 2 } else { 4 },
        blob: if heap_sizes & 0x04 == 0 { 2 } else { 4 },
        valid,
    })
}

fn read_row_counts(table_bytes: &Buf, valid: u64) -> R<Vec<i64>> {
    let mut row_counts = vec![0i64; METADATA_TABLE_NAMES.len()];
    let mut cursor: i64 = 24;
    for (index, slot) in row_counts.iter_mut().enumerate() {
        if valid & (1u64 << index) == 0 {
            continue;
        }
        require_range(table_bytes, cursor, 4, "metadata.table-row-count")?;
        *slot = table_bytes.u32(cursor)? as i64;
        cursor += 4;
    }
    Ok(row_counts)
}

/// Parse ECMA-335 stream and table layout with checked byte extents.
pub fn read_metadata_layout(artifact: &[u8], root_offset: i64, size: i64) -> R<MetadataLayout> {
    let artifact = Buf(artifact);
    if size < 20 || root_offset < 0 || root_offset > artifact.len() - size {
        return Err(failure(
            "invalid-metadata-root",
            "metadata.root",
            "CLI metadata directory leaves the artifact byte range",
            Some(root_offset),
        ));
    }
    let bytes = artifact.sub(root_offset, root_offset + size);
    let budget = Budget::new();
    let ParsedStreams { streams, version } = read_metadata_streams(&bytes, root_offset, &budget)?;
    let header = read_tables_header(&artifact, &streams)?;
    let table_bytes =
        artifact.sub(header.table_bytes_offset, header.table_bytes_offset + header.table_bytes_len);
    let row_counts = read_row_counts(&table_bytes, header.valid)?;
    // buildMetadataTables
    let context = RowSizeContext { rows: &row_counts, string: header.string, guid: header.guid, blob: header.blob };
    let mut tables = BTreeMap::new();
    let mut table_cursor: i64 = 24;
    for index in 0..METADATA_TABLE_NAMES.len() {
        if header.valid & (1u64 << index) != 0 {
            table_cursor += 4;
        }
    }
    for index in 0..METADATA_TABLE_NAMES.len() {
        let count = row_counts[index];
        if header.valid & (1u64 << index) == 0 {
            continue;
        }
        let size_of_row = compute_row_size(index, &context)?;
        let byte_length = count.checked_mul(size_of_row).filter(|v| *v <= (1i64 << 53)).ok_or_else(|| {
            failure(
                "invalid-tables",
                "metadata.tables",
                "Metadata table byte size overflowed",
                Some(header.tables_offset + table_cursor),
            )
        })?;
        require_range(&table_bytes, table_cursor, byte_length, "metadata.table-data")?;
        tables.insert(
            index,
            TableLayout {
                index,
                name: METADATA_TABLE_NAMES[index],
                row_count: count,
                row_size: size_of_row,
                offset: header.tables_offset + table_cursor,
            },
        );
        table_cursor += byte_length;
    }
    let mut stream_names: Vec<String> = streams.keys().cloned().collect();
    js_sort(&mut stream_names);
    Ok(MetadataLayout {
        root_offset,
        size,
        version,
        stream_names,
        strings: require_stream(&streams, "#Strings")?,
        guid: require_stream(&streams, "#GUID")?,
        blob: require_stream(&streams, "#Blob")?,
        tables,
        row_counts,
        string_index_size: header.string,
        guid_index_size: header.guid,
        blob_index_size: header.blob,
        budget,
    })
}

impl MetadataLayout {
    pub fn table(&self, index: usize) -> Option<&TableLayout> {
        self.tables.get(&index)
    }

    pub fn table_index_size(&self, index: usize) -> i64 {
        table_size(index, &self.row_counts)
    }

    pub fn coded_index_size(&self, name: Coded) -> i64 {
        coded_size(name, &self.row_counts)
    }

    pub fn row_count(&self, table: usize) -> i64 {
        self.row_counts.get(table).copied().unwrap_or(0)
    }

    pub fn table_row_count(&self, index: usize) -> i64 {
        self.table(index).map(|t| t.row_count).unwrap_or(0)
    }
}

/// Resolve a one-based metadata row to its exact file offset.
pub fn metadata_row_offset(layout: &MetadataLayout, table: usize, row: i64) -> R<i64> {
    match layout.table(table) {
        Some(descriptor) if row >= 1 && row <= descriptor.row_count => {
            Ok(descriptor.offset + (row - 1) * descriptor.row_size)
        }
        _ => Err(failure(
            "invalid-row",
            format!("metadata.{}", METADATA_TABLE_NAMES.get(table).copied().map(str::to_string).unwrap_or_else(|| table.to_string())),
            format!("Metadata row {row} is outside its table"),
            None,
        )),
    }
}
