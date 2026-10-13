//! Imports, exports and exported symbol names of a Mach-O slice, decoded from the binding
//! information (chained fixups or bind opcodes), the export trie and the symbol table.
//!
//! These replace `dyld_info -imports`, `dyld_info -exports` and `nm -gjU`, whose rows REA parses
//! (`native/parsers/dyldInfo.ts`). The structures below carry what those rows carry.

use std::collections::HashSet;

use crate::macho_image::{Bytes, Image, MachoResult};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImportRow {
    pub name: String,
    pub weak: bool,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportKind {
    Regular,
    Absolute,
    ThreadLocal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportRow {
    pub name: String,
    pub kind: ExportKind,
    /// Image offset (regular) or absolute value.
    pub value: u64,
    pub weak_definition: bool,
    pub reexport: Option<ReexportSource>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReexportSource {
    pub library: Option<String>,
}

#[derive(Debug, Default)]
pub struct SymbolInventory {
    pub imports: Vec<ImportRow>,
    pub exports: Vec<ExportRow>,
    /// Names `nm -gjU` would print (external, defined).
    pub nm_exports: Vec<String>,
    /// Problems found while decoding; the corresponding list may be incomplete.
    pub notes: Vec<String>,
}

const LC_LOAD_DYLIB: u32 = 0xc;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000_0023;
const LC_SYMTAB: u32 = 0x2;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;

const MAX_ENTRIES: usize = 2_000_000;

/// The `dyld_info` short name of a library: leaf name up to the first `.`.
pub fn library_short_name(install_name: &str) -> String {
    let leaf = install_name.rsplit('/').next().unwrap_or(install_name);
    let stem = leaf.split('.').next().unwrap_or(leaf);
    if stem.is_empty() {
        leaf.to_string()
    } else {
        stem.to_string()
    }
}

fn dylib_names(image: &Image<'_>) -> Vec<String> {
    let bytes = image.bytes();
    let mut names = Vec::new();
    for command in &image.commands {
        if matches!(
            command.cmd,
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB | LC_LOAD_UPWARD_DYLIB
        ) {
            let offset = bytes.u32(command.offset + 8).unwrap_or(0) as usize;
            let start = command.offset + offset;
            let name = bytes.cstring(start).unwrap_or_default();
            names.push(name);
        }
    }
    names
}

fn ordinal_source(libraries: &[String], ordinal: i64) -> String {
    match ordinal {
        0 => "self".to_string(),
        -1 => "main-executable".to_string(),
        -2 => "flat-namespace".to_string(),
        -3 => "<weak-def-coalesce>".to_string(),
        n if n > 0 => libraries
            .get((n - 1) as usize)
            .map(|name| library_short_name(name))
            .unwrap_or_else(|| format!("ordinal {n}")),
        n => format!("ordinal {n}"),
    }
}

// ---------------------------------------------------------------------------
// LEB128
// ---------------------------------------------------------------------------

fn uleb(data: &[u8], cursor: &mut usize) -> MachoResult<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *data
            .get(*cursor)
            .ok_or_else(|| crate::macho_image::MachoError("ULEB128 passes the end of its data".into()))?;
        *cursor += 1;
        if shift < 64 {
            result |= u64::from(byte & 0x7f) << shift;
        }
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        if shift > 70 {
            return crate::macho_image::fail("ULEB128 is too long");
        }
    }
}

fn sleb(data: &[u8], cursor: &mut usize) -> MachoResult<i64> {
    let mut result = 0i64;
    let mut shift = 0u32;
    loop {
        let byte = *data
            .get(*cursor)
            .ok_or_else(|| crate::macho_image::MachoError("SLEB128 passes the end of its data".into()))?;
        *cursor += 1;
        if shift < 64 {
            result |= i64::from(byte & 0x7f) << shift;
        }
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 64 && byte & 0x40 != 0 {
                result |= -1i64 << shift;
            }
            return Ok(result);
        }
        if shift > 70 {
            return crate::macho_image::fail("SLEB128 is too long");
        }
    }
}

fn cstring_at(data: &[u8], cursor: &mut usize) -> MachoResult<String> {
    let tail = data
        .get(*cursor..)
        .ok_or_else(|| crate::macho_image::MachoError("string passes the end of its data".into()))?;
    let end = tail
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| crate::macho_image::MachoError("unterminated string".into()))?;
    let text = String::from_utf8_lossy(&tail[..end]).into_owned();
    *cursor += end + 1;
    Ok(text)
}

// ---------------------------------------------------------------------------
// Export trie
// ---------------------------------------------------------------------------

/// Maximum number of trie nodes visited (a node reachable by several paths counts per path).
const MAX_TRIE_VISITS: usize = 1_000_000;

enum TrieStep {
    Enter(usize, String),
    Exit(usize),
}

pub fn read_export_trie(data: &[u8], libraries: &[String]) -> MachoResult<Vec<ExportRow>> {
    let mut rows = Vec::new();
    // Nodes on the path from the root to the node being expanded: reaching one again is a cycle
    // (for example `00 01 00 00`: an empty label leading back to the root), which would never
    // terminate. Shared suffixes (a DAG) stay legal and are bounded by the visit budget.
    let mut on_path: HashSet<usize> = HashSet::new();
    let mut visits = 0usize;
    let mut stack: Vec<TrieStep> = vec![TrieStep::Enter(0, String::new())];
    while let Some(step) = stack.pop() {
        let (offset, prefix) = match step {
            TrieStep::Exit(offset) => {
                on_path.remove(&offset);
                continue;
            }
            TrieStep::Enter(offset, prefix) => (offset, prefix),
        };
        if offset >= data.len() {
            return crate::macho_image::fail(format!("export trie node offset {offset} passes the end"));
        }
        if !on_path.insert(offset) {
            return crate::macho_image::fail(format!("export trie node {offset} is its own ancestor"));
        }
        visits += 1;
        if visits.is_multiple_of(256) && crate::cancel::cancelled() {
            return crate::macho_image::fail("cancelled");
        }
        if visits > MAX_TRIE_VISITS || rows.len() > MAX_ENTRIES || stack.len() > MAX_ENTRIES {
            return crate::macho_image::fail("export trie exceeds the node budget");
        }
        stack.push(TrieStep::Exit(offset));
        let mut cursor = offset;
        let terminal_size = uleb(data, &mut cursor)? as usize;
        let children_start = cursor
            .checked_add(terminal_size)
            .ok_or_else(|| crate::macho_image::MachoError("export trie terminal size overflows".into()))?;
        if terminal_size != 0 {
            let flags = uleb(data, &mut cursor)?;
            if flags & 0x08 != 0 {
                let ordinal = uleb(data, &mut cursor)?;
                let import_name = cstring_at(data, &mut cursor)?;
                let _ = import_name;
                let library = if ordinal == 0 {
                    None
                } else {
                    libraries.get(ordinal as usize - 1).map(|n| library_short_name(n))
                };
                rows.push(ExportRow {
                    name: prefix.clone(),
                    kind: ExportKind::Regular,
                    value: 0,
                    weak_definition: flags & 0x04 != 0,
                    reexport: Some(ReexportSource { library }),
                });
            } else {
                let value = uleb(data, &mut cursor)?;
                if flags & 0x10 != 0 {
                    let _resolver = uleb(data, &mut cursor)?;
                }
                let kind = match flags & 0x03 {
                    2 => ExportKind::Absolute,
                    1 => ExportKind::ThreadLocal,
                    _ => ExportKind::Regular,
                };
                rows.push(ExportRow {
                    name: prefix.clone(),
                    kind,
                    value,
                    weak_definition: flags & 0x04 != 0,
                    reexport: None,
                });
            }
        }
        let mut cursor = children_start;
        let child_count = *data
            .get(cursor)
            .ok_or_else(|| crate::macho_image::MachoError("export trie child count passes the end".into()))?;
        cursor += 1;
        // Children are pushed in reverse so the walk visits them in label order.
        let mut children: Vec<(usize, String)> = Vec::new();
        for _ in 0..child_count {
            let label = cstring_at(data, &mut cursor)?;
            let child = uleb(data, &mut cursor)? as usize;
            children.push((child, format!("{prefix}{label}")));
        }
        for (child, name) in children.into_iter().rev() {
            if name.len() > 4096 {
                return crate::macho_image::fail("export name is too long");
            }
            stack.push(TrieStep::Enter(child, name));
        }
    }
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Chained fixups imports
// ---------------------------------------------------------------------------

pub fn read_chained_imports(data: &[u8], libraries: &[String], big: bool) -> MachoResult<Vec<ImportRow>> {
    let bytes = Bytes::new(data, big);
    let imports_offset = bytes.u32(8)? as usize;
    let symbols_offset = bytes.u32(12)? as usize;
    let imports_count = bytes.u32(16)? as usize;
    let imports_format = bytes.u32(20)?;
    if imports_count > MAX_ENTRIES {
        return crate::macho_image::fail("chained fixups declare too many imports");
    }
    let stride = match imports_format {
        1 => 4,
        2 => 8,
        3 => 16,
        other => return crate::macho_image::fail(format!("unknown chained import format {other}")),
    };
    let mut rows = Vec::new();
    for index in 0..imports_count {
        let at = imports_offset + index * stride;
        let (ordinal, weak, name_offset): (i64, bool, usize) = if imports_format == 3 {
            let raw = bytes.u64(at)?;
            let lib = (raw & 0xffff) as u16;
            // 16-bit ordinals: values >= 0xfff0 are negative special ordinals.
            let ordinal = if lib >= 0xfff0 { i64::from(lib as i16) } else { i64::from(lib) };
            (ordinal, (raw >> 16) & 1 != 0, (raw >> 32) as usize)
        } else {
            let raw = bytes.u32(at)?;
            let lib = (raw & 0xff) as u8;
            let ordinal = if lib >= 0xf0 { i64::from(lib as i8) } else { i64::from(lib) };
            (ordinal, (raw >> 8) & 1 != 0, (raw >> 9) as usize)
        };
        let mut cursor = symbols_offset + name_offset;
        let name = cstring_at(data, &mut cursor)?;
        rows.push(ImportRow { name, weak, source: ordinal_source(libraries, ordinal) });
    }
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Bind opcodes
// ---------------------------------------------------------------------------

fn read_bind_opcodes(
    data: &[u8],
    libraries: &[String],
    weak_info: bool,
    rows: &mut Vec<ImportRow>,
) -> MachoResult<()> {
    let mut cursor = 0usize;
    let mut ordinal: i64 = 0;
    let mut name = String::new();
    let mut flags: u8 = 0;
    let mut have_symbol = false;
    // Deduplicate in O(1) per record (rows from earlier streams count as already seen).
    let mut seen: HashSet<ImportRow> = rows.iter().cloned().collect();
    let mut emit = |rows: &mut Vec<ImportRow>, name: &str, ordinal: i64, flags: u8, have: bool| {
        if !have {
            return;
        }
        let source = if weak_info { "<weak-def-coalesce>".to_string() } else { ordinal_source(libraries, ordinal) };
        let row = ImportRow { name: name.to_string(), weak: flags & 1 != 0, source };
        if seen.insert(row.clone()) {
            rows.push(row);
        }
    };
    while cursor < data.len() {
        let byte = data[cursor];
        cursor += 1;
        let opcode = byte & 0xf0;
        let immediate = byte & 0x0f;
        match opcode {
            0x00 => {
                // BIND_OPCODE_DONE ends a stream of lazy bindings only at the very end; lazy
                // streams separate records with it, so keep reading.
            }
            0x10 => ordinal = i64::from(immediate),
            0x20 => ordinal = uleb(data, &mut cursor)? as i64,
            0x30 => {
                ordinal = if immediate == 0 { 0 } else { i64::from((0xf0 | immediate) as i8) };
            }
            0x40 => {
                flags = immediate;
                name = cstring_at(data, &mut cursor)?;
                have_symbol = true;
            }
            0x50 => {}
            0x60 => {
                sleb(data, &mut cursor)?;
            }
            0x70 => {
                uleb(data, &mut cursor)?;
            }
            0x80 => {
                uleb(data, &mut cursor)?;
            }
            0x90 | 0xb0 => emit(rows, &name, ordinal, flags, have_symbol),
            0xa0 => {
                uleb(data, &mut cursor)?;
                emit(rows, &name, ordinal, flags, have_symbol);
            }
            0xc0 => {
                uleb(data, &mut cursor)?;
                uleb(data, &mut cursor)?;
                emit(rows, &name, ordinal, flags, have_symbol);
            }
            0xd0 => match immediate {
                0 => {
                    uleb(data, &mut cursor)?;
                }
                1 => emit(rows, &name, ordinal, flags, have_symbol),
                other => return crate::macho_image::fail(format!("unknown threaded bind opcode {other}")),
            },
            other => return crate::macho_image::fail(format!("unknown bind opcode 0x{other:02x}")),
        }
        if rows.len() > MAX_ENTRIES {
            return crate::macho_image::fail("bind information exceeds the entry budget");
        }
        if weak_info && opcode == 0x00 {
            // Weak bind info is a single stream.
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Symbol table
// ---------------------------------------------------------------------------

fn read_nm_exports(image: &Image<'_>, symtab_at: usize) -> MachoResult<Vec<String>> {
    let bytes = image.bytes();
    let symoff = bytes.u32(symtab_at + 8)? as usize;
    let nsyms = bytes.u32(symtab_at + 12)? as usize;
    let stroff = bytes.u32(symtab_at + 16)? as usize;
    let strsize = bytes.u32(symtab_at + 20)? as usize;
    if nsyms > MAX_ENTRIES {
        return crate::macho_image::fail("symbol table declares too many symbols");
    }
    let entry = if image.header.is64 { 16 } else { 12 };
    let strings = bytes.slice(stroff, strsize)?;
    let string_bytes = Bytes::new(strings, image.header.big);
    let mut names = Vec::new();
    for index in 0..nsyms {
        let at = symoff + index * entry;
        let n_strx = bytes.u32(at)? as usize;
        let n_type = bytes.u8(at + 4)?;
        if n_type & 0xe0 != 0 || n_type & 0x01 == 0 || n_type & 0x0e == 0 {
            continue;
        }
        if n_strx == 0 || n_strx >= strings.len() {
            continue;
        }
        names.push(string_bytes.cstring(n_strx)?);
    }
    Ok(names)
}

/// Decode everything the three Apple inventory commands provide.
pub fn read_symbols(image: &Image<'_>) -> SymbolInventory {
    let mut inventory = SymbolInventory::default();
    let bytes = image.bytes();
    let libraries = dylib_names(image);
    let mut chained: Option<(u32, u32)> = None;
    let mut trie: Option<(u32, u32)> = None;
    let mut dyld_info: Option<usize> = None;
    let mut symtab: Option<usize> = None;
    for command in &image.commands {
        let at = command.offset;
        match command.cmd {
            LC_DYLD_CHAINED_FIXUPS => {
                if let (Ok(off), Ok(size)) = (bytes.u32(at + 8), bytes.u32(at + 12)) {
                    chained = Some((off, size));
                }
            }
            LC_DYLD_EXPORTS_TRIE => {
                if let (Ok(off), Ok(size)) = (bytes.u32(at + 8), bytes.u32(at + 12)) {
                    trie = Some((off, size));
                }
            }
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => dyld_info = Some(at),
            LC_SYMTAB => symtab = Some(at),
            _ => {}
        }
    }
    let region = |offset: u32, size: u32| -> Option<&[u8]> {
        if size == 0 {
            return None;
        }
        image.data.get(offset as usize..(offset as usize).checked_add(size as usize)?)
    };
    if let Some((off, size)) = chained {
        match region(off, size) {
            Some(data) => match read_chained_imports(data, &libraries, image.header.big) {
                Ok(rows) => {
                    for row in rows {
                        if !inventory.imports.contains(&row) {
                            inventory.imports.push(row);
                        }
                    }
                }
                Err(error) => inventory.notes.push(format!("Chained fixups could not be decoded: {error}.")),
            },
            None if size != 0 => inventory.notes.push("Chained fixups lie outside the image.".to_string()),
            None => {}
        }
    }
    if let Some(at) = dyld_info {
        let word = |index: usize| bytes.u32(at + 8 + index * 4).unwrap_or(0);
        let (bind_off, bind_size) = (word(2), word(3));
        let (weak_off, weak_size) = (word(4), word(5));
        let (lazy_off, lazy_size) = (word(6), word(7));
        let (export_off, export_size) = (word(8), word(9));
        for (offset, size, weak, label) in [
            (bind_off, bind_size, false, "binding"),
            (weak_off, weak_size, true, "weak binding"),
            (lazy_off, lazy_size, false, "lazy binding"),
        ] {
            if let Some(data) = region(offset, size) {
                if let Err(error) = read_bind_opcodes(data, &libraries, weak, &mut inventory.imports) {
                    inventory.notes.push(format!("The {label} information could not be decoded: {error}."));
                }
            } else if size != 0 {
                inventory.notes.push(format!("The {label} information lies outside the image."));
            }
        }
        if trie.is_none() {
            trie = Some((export_off, export_size));
        }
    }
    if let Some((off, size)) = trie {
        match region(off, size) {
            Some(data) => match read_export_trie(data, &libraries) {
                Ok(rows) => inventory.exports = rows,
                Err(error) => inventory.notes.push(format!("The export trie could not be decoded: {error}.")),
            },
            None if size != 0 => inventory.notes.push("The export trie lies outside the image.".to_string()),
            None => {}
        }
    }
    if let Some(at) = symtab {
        match read_nm_exports(image, at) {
            Ok(names) => inventory.nm_exports = names,
            Err(error) => inventory.notes.push(format!("The symbol table could not be decoded: {error}.")),
        }
    }
    inventory
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs the walk on a worker thread so a regression shows up as a failed timeout instead of a hung test.
    fn walk_with_timeout(data: Vec<u8>) -> MachoResult<Vec<ExportRow>> {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(read_export_trie(&data, &[]));
        });
        receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("export trie walk did not terminate")
    }

    #[test]
    fn a_self_referencing_trie_is_rejected_instead_of_looping() {
        // terminal size 0, one child, empty label, child offset 0 (the root itself).
        let result = walk_with_timeout(vec![0x00, 0x01, 0x00, 0x00]);
        let error = result.expect_err("a cycle must be rejected");
        assert!(error.0.contains("its own ancestor"), "{}", error.0);
    }

    #[test]
    fn a_two_node_cycle_is_rejected() {
        // root -> "a" -> node 5, node 5 -> "b" -> root.
        let data = vec![0x00, 0x01, b'a', 0x00, 0x05, 0x00, 0x01, b'b', 0x00, 0x00];
        assert!(walk_with_timeout(data).is_err());
    }

    #[test]
    fn a_shared_suffix_stays_legal() {
        // root has two children (a, b) that both lead to the terminal node at offset 12.
        let mut data = vec![0x00, 0x02, b'a', 0x00, 0x0c, b'b', 0x00, 0x0c, 0, 0, 0, 0];
        data.extend_from_slice(&[0x03, 0x00, 0x10, 0x00, 0x00]);
        let rows = walk_with_timeout(data).unwrap();
        assert_eq!(rows.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), ["a", "b"]);
    }

    #[test]
    fn duplicate_bind_records_are_deduplicated() {
        let mut rows = Vec::new();
        // SET_SYMBOL "_a" (0x40), DO_BIND (0x90) twice.
        let data = [0x40, b'_', b'a', 0x00, 0x90, 0x90];
        read_bind_opcodes(&data, &[], false, &mut rows).unwrap();
        assert_eq!(rows.len(), 1);
    }
}
