//! Metadata heaps and row cursors (REA `ManagedMetadataHeaps`).

use sha2::{Digest, Sha256};

use crate::common::{failure, Buf, R};
use crate::layout::{metadata_row_offset, MetadataLayout};

fn require_range(bytes: &Buf, offset: i64, length: i64, scope: &str) -> R<()> {
    if offset < 0 || length < 0 || offset > bytes.len() - length {
        return Err(failure(
            "invalid-row",
            scope,
            format!("{scope} leaves the artifact byte range"),
            if offset >= 0 { Some(offset) } else { None },
        ));
    }
    Ok(())
}

/// Cursor for checked fixed-width metadata row decoding.
pub struct RowCursor<'a> {
    bytes: Buf<'a>,
    pub start: i64,
    end: i64,
    scope: String,
    offset: i64,
}

impl<'a> RowCursor<'a> {
    pub fn offset(&self) -> i64 {
        self.offset
    }

    fn require(&self, length: i64) -> R<()> {
        if self.offset < self.start || self.offset > self.end - length {
            return Err(failure(
                "invalid-row",
                self.scope.clone(),
                format!("{} row ended before all declared columns", self.scope),
                Some(self.offset),
            ));
        }
        Ok(())
    }

    pub fn u16(&mut self) -> R<i64> {
        self.require(2)?;
        let value = self.bytes.u16(self.offset)?;
        self.offset += 2;
        Ok(value as i64)
    }

    pub fn u32(&mut self) -> R<i64> {
        self.require(4)?;
        let value = self.bytes.u32(self.offset)?;
        self.offset += 4;
        Ok(value as i64)
    }

    pub fn index(&mut self, size: i64) -> R<i64> {
        if size == 2 {
            self.u16()
        } else {
            self.u32()
        }
    }
}

fn compressed_length(bytes: &Buf, offset: i64, scope: &str) -> R<(i64, i64)> {
    require_range(bytes, offset, 1, scope)?;
    let first = bytes.at(offset).unwrap_or(0) as i64;
    let at = |o: i64| bytes.at(o).unwrap_or(0) as i64;
    if first & 0x80 == 0 {
        return Ok((first, 1));
    }
    if first & 0xc0 == 0x80 {
        require_range(bytes, offset, 2, scope)?;
        return Ok((((first & 0x3f) << 8) | at(offset + 1), 2));
    }
    if first & 0xe0 == 0xc0 {
        require_range(bytes, offset, 4, scope)?;
        return Ok((
            (first & 0x1f) * 0x0100_0000 + at(offset + 1) * 0x01_0000 + at(offset + 2) * 0x0100 + at(offset + 3),
            4,
        ));
    }
    Err(failure(
        "invalid-blob",
        scope,
        "Metadata blob uses a reserved compressed-length prefix",
        Some(offset),
    ))
}

/// Read one UTF-8 value from #Strings within its PE/CLI stream extent.
pub fn read_metadata_string(bytes: &Buf, layout: &MetadataLayout, index: i64, heap_extent: i64) -> R<String> {
    if index == 0 {
        return Ok(String::new());
    }
    if index < 0 || index >= layout.strings.size {
        return Err(failure(
            "invalid-heap-index",
            "metadata.#Strings",
            "String heap index is outside #Strings",
            Some(layout.strings.offset + index.max(0)),
        ));
    }
    let start = layout.strings.offset + index;
    if let Some((value, encoded)) = layout.budget.cached_string(index) {
        if encoded <= heap_extent {
            layout.budget.reserve_string(encoded as u64, Some(start))?;
            return Ok(value);
        }
    }
    let maximum = (layout.strings.offset + layout.strings.size).min(start + heap_extent + 1);
    let mut end = start;
    while end < maximum && bytes.at(end) != Some(0) {
        end += 1;
    }
    if end == maximum {
        return Err(failure(
            "invalid-string",
            "metadata.#Strings",
            "String heap item has no terminator within #Strings",
            Some(start),
        ));
    }
    layout.budget.reserve_string((end - start) as u64, Some(start))?;
    match std::str::from_utf8(&bytes.0[start as usize..end as usize]) {
        Ok(value) => {
            layout.budget.cache_string(index, value.to_string(), end - start);
            Ok(value.to_string())
        }
        Err(_) => Err(failure(
            "invalid-string",
            "metadata.#Strings",
            "String heap item is not valid UTF-8",
            Some(start),
        )),
    }
}

/// Read one #Blob item while validating its encoded extent against the heap.
pub fn read_metadata_blob<'a>(bytes: &Buf<'a>, layout: &MetadataLayout, index: i64, heap_extent: i64) -> R<&'a [u8]> {
    if index == 0 {
        return Ok(&[]);
    }
    if index < 0 || index >= layout.blob.size {
        return Err(failure(
            "invalid-heap-index",
            "metadata.#Blob",
            "Blob heap index is outside #Blob",
            Some(layout.blob.offset + index.max(0)),
        ));
    }
    let start = layout.blob.offset + index;
    let (length, prefix) = compressed_length(bytes, start, "metadata.#Blob")?;
    if length > heap_extent {
        return Err(failure("invalid-blob", "metadata.#Blob", "Blob length exceeds the admitted heap extent", Some(start)));
    }
    let content = start + prefix;
    if content > layout.blob.offset + layout.blob.size - length {
        return Err(failure("invalid-blob", "metadata.#Blob", "Blob heap item leaves #Blob", Some(start)));
    }
    Ok(&bytes.0[content as usize..(content + length) as usize])
}

/// Read one conventional GUID value from the one-based #GUID heap.
pub fn read_metadata_guid(bytes: &Buf, layout: &MetadataLayout, index: i64) -> R<Option<String>> {
    if index == 0 {
        return Ok(None);
    }
    let relative = (index - 1) * 16;
    if relative < 0 || relative > layout.guid.size - 16 {
        return Err(failure(
            "invalid-guid",
            "metadata.#GUID",
            "GUID heap index is outside #GUID",
            Some(layout.guid.offset + relative.max(0)),
        ));
    }
    let offset = layout.guid.offset + relative;
    let part1 = format!("{:08x}", bytes.u32(offset)?);
    let part2 = format!("{:04x}", bytes.u16(offset + 4)?);
    let part3 = format!("{:04x}", bytes.u16(offset + 6)?);
    let part4 = hex::encode(bytes.sub(offset + 8, offset + 10).0);
    let part5 = hex::encode(bytes.sub(offset + 10, offset + 16).0);
    Ok(Some(format!("{part1}-{part2}-{part3}-{part4}-{part5}")))
}

/// Format one metadata table/row pair as an exact build-local token.
pub fn metadata_token(table: i64, row: i64) -> String {
    format!("0x{:08x}", table * 0x0100_0000 + row)
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Create a cursor bounded to one admitted metadata table row.
pub fn metadata_row_cursor<'a>(bytes: &Buf<'a>, layout: &MetadataLayout, table: usize, row: i64) -> R<RowCursor<'a>> {
    let start = metadata_row_offset(layout, table, row)?;
    let Some(descriptor) = layout.table(table) else {
        return Err(failure("invalid-row", format!("metadata.{table}"), "Metadata table is absent", Some(start)));
    };
    // Reserve per-row object/index bookkeeping before readers retain decoded facts.
    layout.budget.reserve(256, Some(start))?;
    Ok(RowCursor {
        bytes: *bytes,
        start,
        end: start + descriptor.row_size,
        scope: format!("metadata.{}", descriptor.name),
        offset: start,
    })
}

/// Decode a metadata coded index without signed 32-bit coercion.
pub fn metadata_coded_token(raw: i64, bits: u32, tables: &[Option<i64>], row_counts: &[i64]) -> Option<String> {
    if raw == 0 {
        return None;
    }
    let tag = (raw & ((1i64 << bits) - 1)) as usize;
    let row = raw >> bits;
    let table = tables.get(tag).copied().flatten()?;
    if row == 0 || row > row_counts.get(table as usize).copied().unwrap_or(0) {
        return None;
    }
    Some(metadata_token(table, row))
}

/// Explain why a non-null coded index cannot name an admitted metadata row.
pub fn metadata_coded_token_invalid_reason(
    raw: i64,
    bits: u32,
    tables: &[Option<i64>],
    row_counts: &[i64],
) -> Option<String> {
    if raw == 0 {
        return None;
    }
    let tag = (raw & ((1i64 << bits) - 1)) as usize;
    let row = raw >> bits;
    let Some(table) = tables.get(tag).copied().flatten() else {
        return Some(format!("coded index tag {tag} is not defined"));
    };
    if row == 0 {
        return Some(format!("coded index selects row zero in table {table}"));
    }
    let count = row_counts.get(table as usize).copied().unwrap_or(0);
    if row > count {
        Some(format!("coded index selects row {row} in table {table}, which has {count} rows"))
    } else {
        None
    }
}

/// Table lists in `Option` form for the coded-index helpers.
pub fn tables(values: &[i64]) -> Vec<Option<i64>> {
    values.iter().map(|v| Some(*v)).collect()
}
