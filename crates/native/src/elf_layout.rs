//! `inspect_binary_layout`: ELF64 x86-64 EXEC/DYN/REL layout (port of REA
//! `bridge/pwntools/layout_impl.py`, which wraps pyelftools 0.33 and pwntools
//! 4.15.0). The port reads the file itself; it never imports or executes pwntools
//! or Unicorn.
//!
//! The order of the upstream constructor is preserved because it decides which
//! failures are warnings and which abort the inspection: segments, the load-memory
//! interval tree, symbols (warning), GOT (warning), PLT (warning), then the function
//! table, which re-reads the symbols and raises. The pwntools-derived convenience
//! maps (`linkage.got`, `linkage.plt`) and the mitigation indicators follow the
//! upstream algorithms. PLT discovery, which pwntools performs by emulating at most
//! five instructions from every 4-byte aligned address of `.plt`, `.plt.got` and
//! `.plt.sec` in Unicorn, is reproduced with the `iced-x86` decoder and a small
//! interpreter (see `plt_target`).

use std::collections::HashMap;
use std::sync::OnceLock;

use base64::Engine;
use indexmap::IndexMap;
use serde_json::{json, Value};

const ENUMS_JSON: &str = include_str!("../data/elf_enums.json");

pub struct LayoutFailure {
    pub reason: &'static str,
    pub message: String,
    /// Warnings pwntools logged before the failure.
    pub stderr: String,
}

type R<T> = Result<T, LayoutFailure>;
/// Failure inside the unchanged upstream parser, as the exception text.
type S<T> = Result<T, String>;

fn fail<T>(reason: &'static str, message: impl Into<String>) -> R<T> {
    Err(LayoutFailure {
        reason,
        message: message.into(),
        stderr: String::new(),
    })
}

/// Structural failure raised inside the unchanged upstream parser after the first checks.
fn upstream_failure(message: impl AsRef<str>) -> LayoutFailure {
    LayoutFailure {
        reason: "format",
        message: format!(
            "Selected ELF failed unchanged upstream structural parsing: {}",
            message.as_ref()
        ),
        stderr: String::new(),
    }
}

// ---------------------------------------------------------------------------
// pyelftools enumerations
// ---------------------------------------------------------------------------

pub(crate) struct EnumTable {
    names: HashMap<i64, &'static str>,
    values: HashMap<String, i64>,
}

impl EnumTable {
    fn from(entries: &Value) -> Self {
        let mut names: HashMap<i64, &'static str> = HashMap::new();
        let mut values = HashMap::new();
        for entry in entries.as_array().cloned().unwrap_or_default() {
            let name = entry[0].as_str().unwrap_or("").to_string();
            let value = entry[1].as_i64().unwrap_or(0);
            // Process-wide table, built once: the strings are intentionally leaked.
            names.insert(value, Box::leak(name.clone().into_boxed_str()));
            values.insert(name, value);
        }
        Self { names, values }
    }

    pub(crate) fn scalar(&self, value: i64) -> Value {
        match self.names.get(&value) {
            Some(name) => Value::String((*name).to_string()),
            None => json!(value),
        }
    }

    pub(crate) fn name(&self, value: i64) -> Option<&'static str> {
        self.names.get(&value).copied()
    }

    fn value(&self, name: &str) -> Option<i64> {
        self.values.get(name).copied()
    }
}

struct Enums {
    e_type: EnumTable,
    e_machine: EnumTable,
    p_type: EnumTable,
    sh_type: EnumTable,
    st_bind: EnumTable,
    st_type: EnumTable,
    st_visibility: EnumTable,
    st_shndx: EnumTable,
    d_tag: EnumTable,
    core_note: EnumTable,
}

pub(crate) fn enums_p_type() -> &'static EnumTable {
    &enums().p_type
}

pub(crate) fn enums_core_note() -> &'static EnumTable {
    &enums().core_note
}

fn enums() -> &'static Enums {
    static ENUMS: OnceLock<Enums> = OnceLock::new();
    ENUMS.get_or_init(|| {
        let raw: Value = serde_json::from_str(ENUMS_JSON).expect("bundled enum tables");
        Enums {
            e_type: EnumTable::from(&raw["e_type"]),
            e_machine: EnumTable::from(&raw["e_machine"]),
            p_type: EnumTable::from(&raw["p_type"]),
            sh_type: EnumTable::from(&raw["sh_type"]),
            st_bind: EnumTable::from(&raw["st_bind"]),
            st_type: EnumTable::from(&raw["st_type"]),
            st_visibility: EnumTable::from(&raw["st_visibility"]),
            st_shndx: EnumTable::from(&raw["st_shndx"]),
            d_tag: EnumTable::from(&raw["d_tag"]),
            core_note: EnumTable::from(&raw["core_note_type"]),
        }
    })
}

// ---------------------------------------------------------------------------
// Raw structures and construct-style parsing
// ---------------------------------------------------------------------------

fn hex(value: u64) -> String {
    format!("0x{value:x}")
}

/// `struct_parse` over a fixed layout: position past the end is a `ValueError`,
/// a short field is a construct `FieldError`.
pub(crate) fn walk(data: &[u8], at: u64, fields: &[usize]) -> S<()> {
    if at > data.len() as u64 {
        return Err("seek out of range".to_string());
    }
    let mut position = at as usize;
    for size in fields {
        let have = data.len().saturating_sub(position).min(*size);
        if have < *size {
            return Err(format!("expected {size}, found {have}"));
        }
        position += size;
    }
    Ok(())
}

pub(crate) fn le16(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([data[at], data[at + 1]])
}
pub(crate) fn le32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}
pub(crate) fn le64(data: &[u8], at: usize) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&data[at..at + 8]);
    u64::from_le_bytes(word)
}

#[derive(Clone)]
struct Ehdr {
    e_type: u16,
    e_machine: u16,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[derive(Clone)]
struct Shdr {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

#[derive(Clone)]
struct Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

struct Sym {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
}

struct Rel {
    r_offset: u64,
    r_info: u64,
    r_addend: Option<i64>,
}

impl Rel {
    fn sym(&self) -> u64 {
        self.r_info >> 32
    }
    fn kind(&self) -> u64 {
        self.r_info & 0xffff_ffff
    }
}

const SHDR_SIZE: u64 = 64;
const PHDR_SIZE: u64 = 56;
const SYM_SIZE: u64 = 24;

fn parse_ehdr(data: &[u8]) -> Ehdr {
    Ehdr {
        e_type: le16(data, 16),
        e_machine: le16(data, 18),
        e_entry: le64(data, 24),
        e_phoff: le64(data, 32),
        e_shoff: le64(data, 40),
        e_phentsize: le16(data, 54),
        e_phnum: le16(data, 56),
        e_shentsize: le16(data, 58),
        e_shnum: le16(data, 60),
        e_shstrndx: le16(data, 62),
    }
}

fn parse_shdr(data: &[u8], at: u64) -> S<Shdr> {
    walk(data, at, &[4, 4, 8, 8, 8, 8, 4, 4, 8, 8])?;
    let at = at as usize;
    Ok(Shdr {
        sh_name: le32(data, at),
        sh_type: le32(data, at + 4),
        sh_flags: le64(data, at + 8),
        sh_addr: le64(data, at + 16),
        sh_offset: le64(data, at + 24),
        sh_size: le64(data, at + 32),
        sh_link: le32(data, at + 40),
        sh_info: le32(data, at + 44),
        sh_addralign: le64(data, at + 48),
        sh_entsize: le64(data, at + 56),
    })
}

fn parse_phdr(data: &[u8], at: u64) -> S<Phdr> {
    walk(data, at, &[4, 4, 8, 8, 8, 8, 8, 8])?;
    let at = at as usize;
    Ok(Phdr {
        p_type: le32(data, at),
        p_flags: le32(data, at + 4),
        p_offset: le64(data, at + 8),
        p_vaddr: le64(data, at + 16),
        p_paddr: le64(data, at + 24),
        p_filesz: le64(data, at + 32),
        p_memsz: le64(data, at + 40),
        p_align: le64(data, at + 48),
    })
}

fn parse_sym(data: &[u8], at: u64) -> S<Sym> {
    walk(data, at, &[4, 1, 1, 2, 8, 8])?;
    let at = at as usize;
    Ok(Sym {
        st_name: le32(data, at),
        st_info: data[at + 4],
        st_other: data[at + 5],
        st_shndx: le16(data, at + 6),
        st_value: le64(data, at + 8),
        st_size: le64(data, at + 16),
    })
}

fn parse_rel(data: &[u8], at: u64, rela: bool) -> S<Rel> {
    let fields: &[usize] = if rela { &[8, 8, 8] } else { &[8, 8] };
    walk(data, at, fields)?;
    let at = at as usize;
    Ok(Rel {
        r_offset: le64(data, at),
        r_info: le64(data, at + 8),
        r_addend: if rela { Some(le64(data, at + 16) as i64) } else { None },
    })
}

// ---------------------------------------------------------------------------
// Name and range helpers (layout_impl.py)
// ---------------------------------------------------------------------------

fn file_range(offset: u64, size: u64, length: usize) -> bool {
    let length = length as u64;
    offset <= length && size <= length - offset
}

fn location(offset: u64, size: u64, length: usize) -> R<Value> {
    if !file_range(offset, size, length) {
        return fail("format", "ELF contains a file-backed range outside the selected snapshot.");
    }
    Ok(json!({"offset": hex(offset), "bytes": hex(size)}))
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// pyelftools `StringTableSection.get_string`: unbounded by the table size.
fn get_string(data: &[u8], table_offset: u64, offset: u64) -> S<String> {
    let start = table_offset.wrapping_add(offset);
    if start > data.len() as u64 || table_offset.checked_add(offset).is_none() {
        return Err("seek out of range".to_string());
    }
    let start = start as usize;
    if start == data.len() {
        return Ok(String::new());
    }
    match data[start..].iter().position(|b| *b == 0) {
        Some(0) | None => Ok(String::new()),
        Some(end) => Ok(String::from_utf8_lossy(&data[start..start + end]).into_owned()),
    }
}

fn name_in_table(
    display: Option<&str>,
    table_start: u64,
    table_size: u64,
    offset: u64,
    content: &[u8],
) -> R<Value> {
    location(table_start, table_size, content.len())?;
    if offset >= table_size {
        return fail(
            "format",
            format!("ELF name offset {offset} lies outside its declared string table of {table_size} bytes at file offset {table_start}."),
        );
    }
    let start = table_start + offset;
    let limit = table_start + table_size;
    let end = match content[start as usize..limit as usize].iter().position(|b| *b == 0) {
        Some(position) => start as usize + position,
        None => return fail("format", "ELF name lacks a terminator within its reported string table."),
    };
    let raw = &content[start as usize..end];
    Ok(json!({
        "display": match display {
            Some(text) => text.to_string(),
            None => String::from_utf8_lossy(raw).into_owned(),
        },
        "bytes_base64": b64(raw),
        "location": location(start, raw.len() as u64 + 1, content.len())?,
        "unknown_reason": null,
    }))
}

// ---------------------------------------------------------------------------
// RELR decoding (pyelftools RelrRelocationTable)
// ---------------------------------------------------------------------------

fn relr_offsets(data: &[u8], offset: u64, size: u64) -> S<Vec<u64>> {
    let mut out = Vec::new();
    if size == 0 {
        return Ok(out);
    }
    let limit = offset.saturating_add(size);
    let mut relr = offset;
    let mut base: Option<u64> = None;
    while relr < limit {
        walk(data, relr, &[8])?;
        let mut entry = le64(data, relr as usize);
        if entry & 1 == 0 {
            base = Some(entry.wrapping_add(8));
            out.push(entry);
        } else {
            let Some(mut current) = base else {
                return Err("RELR bitmap without base address".to_string());
            };
            let mut i = 0u64;
            loop {
                entry >>= 1;
                if entry == 0 {
                    break;
                }
                if entry & 1 != 0 {
                    out.push(current.wrapping_add(i * 8));
                }
                i += 1;
            }
            current = current.wrapping_add((8 * 8 - 1) * 8);
            base = Some(current);
        }
        relr += 8;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Parsed image
// ---------------------------------------------------------------------------

struct Image<'a> {
    data: &'a [u8],
    header: Ehdr,
    sections: Vec<Shdr>,
    names: Vec<String>,
    segments: Vec<Phdr>,
    section_name_index: u64,
}

fn type_name(section: &Shdr) -> &'static str {
    enums().sh_type.name(i64::from(section.sh_type)).unwrap_or("")
}

fn is_symbol_table(section: &Shdr) -> bool {
    matches!(type_name(section), "SHT_SYMTAB" | "SHT_DYNSYM" | "SHT_SUNW_LDYNSYM")
}

impl Image<'_> {
    /// Section index by name; later duplicates win (pyelftools `_section_name_map`).
    fn section_by_name(&self, name: &str) -> Option<usize> {
        let mut found = None;
        for (index, candidate) in self.names.iter().enumerate() {
            if candidate == name {
                found = Some(index);
            }
        }
        found
    }

    fn sym_count(&self, section: &Shdr) -> u64 {
        section.sh_size / section.sh_entsize.max(1)
    }

    fn read_sym(&self, section: &Shdr, n: u64) -> S<Sym> {
        parse_sym(self.data, section.sh_offset.saturating_add(n.saturating_mul(section.sh_entsize)))
    }

    fn sym_name(&self, table: &Shdr, symbol: &Sym) -> S<String> {
        let strings = &self.sections[table.sh_link as usize];
        get_string(self.data, strings.sh_offset, u64::from(symbol.st_name))
    }

    /// Entries of a dynamic table up to and including DT_NULL.
    fn dynamic_tags(&self, offset: u64) -> S<Vec<(i64, u64)>> {
        let mut tags = Vec::new();
        let mut index = 0u64;
        loop {
            let at = offset.saturating_add(index * 16);
            walk(self.data, at, &[8, 8])?;
            let tag = le64(self.data, at as usize) as i64;
            let value = le64(self.data, at as usize + 8);
            tags.push((tag, value));
            if tag == 0 {
                return Ok(tags);
            }
            index += 1;
        }
    }

    fn dynamic_section_tags(&self) -> S<Option<Vec<(i64, u64)>>> {
        let Some(index) = self.section_by_name(".dynamic") else {
            return Ok(None);
        };
        let section = &self.sections[index];
        if type_name(section) != "SHT_DYNAMIC" {
            return Ok(None);
        }
        Ok(Some(self.dynamic_tags(section.sh_offset)?))
    }

    fn dynamic_value(&self, tag_name: &str) -> S<Option<u64>> {
        let Some(tags) = self.dynamic_section_tags()? else {
            return Ok(None);
        };
        let Some(wanted) = enums().d_tag.value(tag_name) else {
            return Ok(None);
        };
        Ok(tags.iter().find(|(tag, _)| *tag == wanted).map(|(_, value)| *value))
    }

    fn dynamic_has(&self, tag_name: &str) -> S<bool> {
        let Some(tags) = self.dynamic_section_tags()? else {
            return Ok(false);
        };
        let Some(wanted) = enums().d_tag.value(tag_name) else {
            return Ok(false);
        };
        Ok(tags.iter().any(|(tag, _)| *tag == wanted))
    }
}

fn read_relocations(data: &[u8], section: &Shdr, rela: bool) -> S<Vec<Rel>> {
    let entry_size: u64 = if rela { 24 } else { 16 };
    let count = section.sh_size / entry_size;
    let mut out = Vec::new();
    for n in 0..count {
        out.push(parse_rel(data, section.sh_offset.saturating_add(n * entry_size), rela)?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub struct ElfLayout {
    /// The adapter payload (everything but `artifact` and `diagnostics`).
    pub payload: Value,
    /// Warnings pwntools logs to stderr for this image.
    pub stderr: String,
}

fn section_header_offset(header: &Ehdr, n: u64) -> S<u64> {
    if header.e_shoff > 0 && u64::from(header.e_shentsize) < SHDR_SIZE {
        return Err(format!("Too small e_shentsize: {}", header.e_shentsize));
    }
    Ok(header.e_shoff.saturating_add(n.saturating_mul(u64::from(header.e_shentsize))))
}

/// pyelftools `_get_section_header`.
fn read_section_header(data: &[u8], header: &Ehdr, n: u64) -> S<Shdr> {
    let at = section_header_offset(header, n)?;
    if at > data.len() as u64 {
        return Err(format!("Reading section {n} at offset {at} past EOF {}", data.len()));
    }
    parse_shdr(data, at)
}

/// The first failure `iter_sections()` would raise, if any (header, name, type-specific asserts).
fn first_section_error(data: &[u8], header: &Ehdr, count: u64, name_table: Option<u64>) -> (Vec<Shdr>, Option<String>) {
    let e = enums();
    let mut sections: Vec<Shdr> = Vec::new();
    for n in 0..count {
        let section = match read_section_header(data, header, n) {
            Ok(section) => section,
            Err(message) => return (sections, Some(message)),
        };
        if let Some(table) = name_table {
            if let Err(message) = get_string(data, table, u64::from(section.sh_name)) {
                sections.push(section);
                return (sections, Some(message));
            }
        }
        let kind = e.sh_type.name(i64::from(section.sh_type)).unwrap_or("");
        let error = match kind {
            "SHT_SYMTAB" | "SHT_DYNSYM" | "SHT_SUNW_LDYNSYM" => {
                match read_section_header(data, header, u64::from(section.sh_link)) {
                    Err(message) => Some(message),
                    Ok(link) if e.sh_type.name(i64::from(link.sh_type)) != Some("SHT_STRTAB") => Some(format!(
                        "SHT_SYMTAB section points at section {} of type {}, expected SHT_STRTAB",
                        section.sh_link,
                        e.sh_type.name(i64::from(link.sh_type)).map(str::to_string).unwrap_or_else(|| link.sh_type.to_string())
                    )),
                    Ok(_) if section.sh_entsize == 0 => {
                        Some("Expected entry size of section '' to be > 0".to_string())
                    }
                    Ok(_) if section.sh_size % section.sh_entsize != 0 => {
                        Some("Expected section size to be a multiple of entry size in section ''".to_string())
                    }
                    Ok(_) => None,
                }
            }
            "SHT_REL" | "SHT_RELA" => {
                let expected = if kind == "SHT_RELA" { 24 } else { 16 };
                if section.sh_entsize != expected {
                    Some(format!("Expected sh_entsize of {kind} section to be {expected}"))
                } else {
                    None
                }
            }
            "SHT_RELR" => {
                if section.sh_entsize != 8 {
                    Some(format!("Expected RELR entry size to be 8, got {}", section.sh_entsize))
                } else {
                    None
                }
            }
            "SHT_DYNAMIC" => read_section_header(data, header, u64::from(section.sh_link)).err(),
            _ => None,
        };
        sections.push(section);
        if error.is_some() {
            return (sections, error);
        }
    }
    (sections, None)
}

fn symbol_value_meaning(
    image_type: &str,
    st_type: Option<&str>,
    shndx: u16,
    sections: &[Shdr],
) -> &'static str {
    if st_type == Some("STT_FILE") {
        return "no-address";
    }
    if shndx == 0 {
        return "undefined";
    }
    if shndx == 0xfff2 {
        return "alignment";
    }
    if shndx == 0xfff1 {
        return "absolute-value";
    }
    let index = usize::from(shndx);
    if !(0 < index && index < sections.len()) || index >= 0xff00 {
        return "unknown-section-index";
    }
    if type_name(&sections[index]) == "SHT_NULL" {
        return "unknown-section-index";
    }
    if image_type == "ET_REL" {
        return "section-offset";
    }
    if st_type == Some("STT_TLS") {
        return "tls-offset";
    }
    "linked-virtual-address"
}

fn relocation_target(image_type: &str, section_index: u32, offset: u64, sections: &[Shdr]) -> Value {
    if image_type != "ET_REL" {
        return json!({"kind": "linked-virtual-address", "address": hex(offset)});
    }
    let index = section_index as usize;
    let null_type = sections.get(index).map(|s| type_name(s) == "SHT_NULL").unwrap_or(true);
    if section_index == 0 || null_type {
        return json!({
            "kind": "unknown-section",
            "reported_section_index": section_index,
            "offset": hex(offset),
            "unknown_reason": if section_index == 0 { "undefined-section-reference" } else { "inactive-section-header" },
        });
    }
    json!({"kind": "section-offset", "section_index": section_index, "offset": hex(offset)})
}

fn scalar(table: &EnumTable, value: i64) -> Value {
    table.scalar(value)
}

pub fn inspect_elf(content: &[u8]) -> R<ElfLayout> {
    if content.len() < 4 || &content[..4] != b"\x7fELF" {
        return fail("format", "Selected object does not contain an ELF header.");
    }
    if content.len() < 16 {
        return fail("format", "Selected ELF identification is truncated.");
    }
    if content[4] != 2 || content[5] != 1 {
        return fail("unsupported-target", "Initial layout profile requires ELF64 little-endian objects.");
    }
    if content.len() < 64 {
        return fail("format", "Selected ELF64 header is truncated.");
    }
    if u16::from_le_bytes([content[18], content[19]]) != 62 {
        return fail("unsupported-target", "Initial layout profile requires x86-64 ELF objects.");
    }
    if ![1u16, 2, 3].contains(&u16::from_le_bytes([content[16], content[17]])) {
        return fail(
            "unsupported-target",
            "Selected ELF type is outside the EXEC/DYN/REL layout profile; recorded core analysis is separate.",
        );
    }
    let header = parse_ehdr(content);
    let length = content.len();
    // ---- first guarded block: pyelftools header handling, raw exception text ----------------
    let raw = |message: String| LayoutFailure {
        reason: "format",
        message,
        stderr: String::new(),
    };
    let section_count: u64 = if header.e_shoff == 0 {
        0
    } else if header.e_shnum == 0 {
        read_section_header(content, &header, 0).map_err(raw)?.sh_size
    } else {
        u64::from(header.e_shnum)
    };
    if header.e_shstrndx == 0xffff && section_count == 0 {
        return fail("format", "ELF extended section-name index requires a declared section-zero header.");
    }
    let raw_name_index = header.e_shstrndx;
    if (0xff00..0xffff).contains(&raw_name_index) {
        return fail(
            "format",
            format!("ELF section-name index {raw_name_index} is reserved and cannot directly reference a section."),
        );
    }
    let section_name_index: u64 = if raw_name_index == 0xffff {
        u64::from(read_section_header(content, &header, 0).map_err(raw)?.sh_link)
    } else {
        u64::from(raw_name_index)
    };
    if raw_name_index == 0xffff && section_name_index < 0xff00 {
        return fail(
            "format",
            format!("ELF SHN_XINDEX resolves to ordinary index {section_name_index}; the escape requires an index at least SHN_LORESERVE (0xff00)."),
        );
    }
    if section_name_index != 0 {
        if section_name_index >= section_count {
            return fail(
                "format",
                format!("ELF section-name table index {section_name_index} lies outside the declared section count {section_count}."),
            );
        }
        let names_header = read_section_header(content, &header, section_name_index).map_err(raw)?;
        if enums().sh_type.name(i64::from(names_header.sh_type)) != Some("SHT_STRTAB") {
            return fail(
                "format",
                format!("ELF section-name table {section_name_index} is not SHT_STRTAB."),
            );
        }
        location(names_header.sh_offset, names_header.sh_size, length)?;
    }

    // ---- pwntools constructor ----------------------------------------------------------------
    let e = enums();
    let name_table: Option<u64> = if section_name_index == 0 {
        None
    } else {
        Some(read_section_header(content, &header, section_name_index).map_err(raw)?.sh_offset)
    };
    let (sections, sections_error) = first_section_error(content, &header, section_count, name_table);
    let names: Vec<String> = sections
        .iter()
        .map(|section| match name_table {
            Some(table) => get_string(content, table, u64::from(section.sh_name)).unwrap_or_default(),
            None => String::new(),
        })
        .collect();
    // Segments (DynamicSegment construction iterates the sections).
    let segment_count: u64 = if header.e_phnum < 0xffff {
        u64::from(header.e_phnum)
    } else {
        match sections.first() {
            Some(first) => u64::from(first.sh_info),
            None => 0,
        }
    };
    let mut segments: Vec<Phdr> = Vec::new();
    for n in 0..segment_count {
        if header.e_phoff > 0 && u64::from(header.e_phentsize) < PHDR_SIZE {
            return Err(upstream_failure(format!("Too small e_phentsize: {}", header.e_phentsize)));
        }
        let at = header.e_phoff.saturating_add(n.saturating_mul(u64::from(header.e_phentsize)));
        let segment = parse_phdr(content, at).map_err(upstream_failure)?;
        if e.p_type.name(i64::from(segment.p_type)) == Some("PT_DYNAMIC") {
            if let Some(message) = &sections_error {
                return Err(upstream_failure(message));
            }
            for section in &sections {
                if type_name(section) == "SHT_DYNAMIC" && section.sh_offset == segment.p_offset {
                    read_section_header(content, &header, u64::from(section.sh_link)).map_err(upstream_failure)?;
                    break;
                }
            }
        }
        segments.push(segment);
    }
    // Load-memory interval tree: a PT_LOAD whose memory image ends before its file image is a null interval.
    for segment in &segments {
        if e.p_type.name(i64::from(segment.p_type)) != Some("PT_LOAD") {
            continue;
        }
        let start = u128::from(segment.p_vaddr);
        let stop_data = start + u128::from(segment.p_filesz);
        let stop_mem = start + u128::from(segment.p_memsz);
        if stop_data > stop_mem {
            return Err(upstream_failure(format!(
                "IntervalTree: Null Interval objects not allowed in IntervalTree: Interval({stop_data}, {stop_mem}, b'\\x00')"
            )));
        }
    }
    let image = Image {
        data: content,
        header: header.clone(),
        sections,
        names,
        segments,
        section_name_index,
    };
    build_layout(&image, sections_error)
}

fn build_layout(image: &Image<'_>, sections_error: Option<String>) -> R<ElfLayout> {
    let content = image.data;
    let length = content.len();
    let header = &image.header;
    let e = enums();
    let image_type = e.e_type.name(i64::from(header.e_type)).unwrap_or("").to_string();
    let all_sections = &image.sections;
    let section_name_index = image.section_name_index;
    let mut warnings: Vec<String> = Vec::new();
    let stderr_of = |warnings: &[String]| -> String { warnings.iter().map(|w| format!("{w}\n")).collect() };
    let upstream_with = |message: String, warnings: &[String]| -> LayoutFailure {
        let mut failure = upstream_failure(message);
        failure.stderr = stderr_of(warnings);
        failure
    };

    // pwntools state.
    let mut symbols: IndexMap<String, u64> = IndexMap::new();
    let mut got: IndexMap<String, u64> = IndexMap::new();
    let mut plt: IndexMap<String, u64> = IndexMap::new();

    let elftype = image_type.trim_start_matches("ET_").to_string();
    let load_addr = if elftype != "DYN" {
        let mut address = 0u64;
        for segment in &image.segments {
            if e.p_type.name(i64::from(segment.p_type)) != Some("PT_LOAD") || segment.p_vaddr == 0 {
                continue;
            }
            if segment.p_vaddr < address || address == 0 {
                address = segment.p_vaddr;
            }
        }
        address
    } else {
        0
    };
    let has_interp = image
        .segments
        .iter()
        .any(|s| e.p_type.name(i64::from(s.p_type)).map(|n| n.contains("INTERP")).unwrap_or(false));
    let mut statically_linked = elftype == "EXEC" && load_addr != 0;
    let mut executable = elftype == "EXEC";
    if has_interp {
        executable = true;
        statically_linked = false;
    }

    // _populate_symbols
    let mut symbol_error: Option<String> = sections_error.clone();
    if sections_error.is_none() {
        'tables: for section in all_sections.iter().filter(|s| is_symbol_table(s)) {
            for entry in 0..image.sym_count(section) {
                let raw = match image.read_sym(section, entry) {
                    Ok(raw) => raw,
                    Err(message) => {
                        symbol_error = Some(message);
                        break 'tables;
                    }
                };
                let name = match image.sym_name(section, &raw) {
                    Ok(name) => name,
                    Err(message) => {
                        symbol_error = Some(message);
                        break 'tables;
                    }
                };
                if name.is_empty() || raw.st_shndx == 0 {
                    continue;
                }
                symbols.insert(name, raw.st_value);
            }
        }
    }
    if let Some(message) = &symbol_error {
        warnings.push(format!("Could not populate symbols: {message}"));
    }

    // _populate_got
    let mut got_error: Option<String> = sections_error.clone();
    if !statically_linked && sections_error.is_none() {
        let mut reverse: HashMap<u64, Vec<String>> = HashMap::new();
        for (name, address) in &symbols {
            reverse.entry(*address).or_default().push(name.clone());
        }
        'got: for section in all_sections.iter() {
            let kind = type_name(section);
            if kind != "SHT_REL" && kind != "SHT_RELA" {
                continue;
            }
            if section.sh_link == 0 {
                continue;
            }
            let table = match read_section_header(content, header, u64::from(section.sh_link)) {
                Ok(table) => table,
                Err(message) => {
                    got_error = Some(message);
                    break 'got;
                }
            };
            let relocations = match read_relocations(content, section, kind == "SHT_RELA") {
                Ok(relocations) => relocations,
                Err(message) => {
                    got_error = Some(message);
                    break 'got;
                }
            };
            for rel in relocations {
                if rel.sym() == 0 && rel.r_addend.is_some() {
                    let relocated = rel.r_addend.unwrap_or(0) as u64;
                    if let Some(names) = reverse.get(&relocated) {
                        for name in names {
                            got.insert(name.clone(), rel.r_offset);
                        }
                    }
                    continue;
                }
                if !is_symbol_table(&table) {
                    got_error = Some("'Section' object has no attribute 'get_symbol'".to_string());
                    break 'got;
                }
                let symbol = match image.read_sym(&table, rel.sym()) {
                    Ok(symbol) => symbol,
                    Err(message) => {
                        got_error = Some(message);
                        break 'got;
                    }
                };
                let name = match image.sym_name(&table, &symbol) {
                    Ok(name) => name,
                    Err(message) => {
                        got_error = Some(message);
                        break 'got;
                    }
                };
                if !name.is_empty() {
                    got.insert(name, rel.r_offset);
                }
            }
        }
        if got_error.is_none() && got.is_empty() {
            warnings.push("Did not find any GOT entries".to_string());
        }
    }
    if let Some(message) = &got_error {
        if !statically_linked {
            warnings.push(format!("Could not populate GOT: {message}"));
        }
    }

    // _populate_plt
    if !statically_linked && !got.is_empty() {
        let mut inverse: HashMap<u64, String> = HashMap::new();
        for (name, address) in &got {
            inverse.insert(*address, name.clone());
        }
        for (name, address) in &symbols {
            inverse.insert(*address, name.clone());
        }
        for section_name in [".plt", ".plt.got", ".plt.sec"] {
            let Some(section_index) = image.section_by_name(section_name) else {
                continue;
            };
            let section = &all_sections[section_index];
            let start = section.sh_offset as usize;
            let size = if type_name(section) == "SHT_NOBITS" { 0 } else { section.sh_size as usize };
            let data = content.get(start..start.saturating_add(size).min(length)).unwrap_or(&[]);
            let address = section.sh_addr;
            let region_start = address & !0xfff;
            let region_end = (address + data.len() as u64 + 0xfff) & !0xfff;
            if region_end < region_start || region_end - region_start > 64 * 1024 * 1024 {
                warnings.push("Could not populate PLT: section exceeds the emulation window".to_string());
                continue;
            }
            let mut region = vec![0u8; (region_end - region_start) as usize];
            region[(address - region_start) as usize..(address - region_start) as usize + data.len()]
                .copy_from_slice(data);
            let mut found: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
            let mut pc = address;
            while pc < address + data.len() as u64 {
                let target = plt_target(region_start, &region, pc).unwrap_or(0);
                if inverse.contains_key(&target) {
                    found.insert(pc, target);
                }
                pc += 4;
            }
            for (pc, target) in found {
                plt.insert(inverse[&target].clone(), pc);
            }
        }
    }

    // _populate_functions re-reads every symbol table and raises what the symbol pass only logged.
    if let Some(message) = sections_error.or(symbol_error) {
        return Err(upstream_with(message, &warnings));
    }

    // ---- layout_impl.py ------------------------------------------------------------------------
    let mut sections_json: Vec<Value> = Vec::new();
    let mut segments_json: Vec<Value> = Vec::new();
    let mut symbols_json: Vec<Value> = Vec::new();
    let mut relocations_json: Vec<Value> = Vec::new();
    let mut packed_json: Vec<Value> = Vec::new();
    let mut needed: Vec<Value> = Vec::new();
    let mut interpreters: Vec<Value> = Vec::new();

    let shstrings: Option<&Shdr> = if !all_sections.is_empty() && section_name_index != 0 {
        all_sections.get(section_name_index as usize)
    } else {
        None
    };
    let layout = (|| -> R<()> {
        for (index, section) in all_sections.iter().enumerate() {
            let kind = type_name(section);
            let backing = kind != "SHT_NOBITS" && kind != "SHT_NULL";
            if backing {
                location(section.sh_offset, section.sh_size, length)?;
            }
            let display = image.names[index].as_str();
            let name_value = match shstrings {
                Some(table) if type_name(table) == "SHT_STRTAB" => {
                    name_in_table(Some(display), table.sh_offset, table.sh_size, u64::from(section.sh_name), content)?
                }
                Some(_) => json!({
                    "display": display,
                    "bytes_base64": null,
                    "location": null,
                    "unknown_reason": "Referenced string table could not be resolved.",
                }),
                None => json!({
                    "display": "",
                    "bytes_base64": null,
                    "location": null,
                    "unknown_reason": "ELF declares no section-name table (SHN_UNDEF index 0).",
                }),
            };
            sections_json.push(json!({
                "index": index,
                "name": name_value,
                "name_offset": hex(u64::from(section.sh_name)),
                "type": scalar(&e.sh_type, i64::from(section.sh_type)),
                "header_location": location(
                    header.e_shoff.saturating_add((index as u64).saturating_mul(u64::from(header.e_shentsize))),
                    u64::from(header.e_shentsize),
                    length,
                )?,
                "address": hex(section.sh_addr),
                "offset": hex(section.sh_offset),
                "size": hex(section.sh_size),
                "alignment": hex(section.sh_addralign),
                "flags": hex(section.sh_flags),
                "link": section.sh_link,
                "info": section.sh_info,
                "entry_size": hex(section.sh_entsize),
                "file_backing": if backing { "file" } else { "none" },
            }));
            if kind == "SHT_SYMTAB" || kind == "SHT_DYNSYM" {
                if section.sh_entsize < SYM_SIZE {
                    return fail("format", "ELF symbol entry is smaller than the decoded Elf64_Sym structure.");
                }
                let link = section.sh_link as usize;
                if link >= all_sections.len() || type_name(&all_sections[link]) != "SHT_STRTAB" {
                    return fail("format", format!("ELF symbol table {index} links to invalid string table {link}."));
                }
                let strings = &all_sections[link];
                for entry in 0..image.sym_count(section) {
                    let raw = image.read_sym(section, entry).map_err(upstream_failure)?;
                    let display = image.sym_name(section, &raw).map_err(upstream_failure)?;
                    let st_type_value = i64::from(raw.st_info & 0xf);
                    let st_type_name = e.st_type.name(st_type_value);
                    symbols_json.push(json!({
                        "table_index": index,
                        "entry_index": entry,
                        "name": name_in_table(Some(&display), strings.sh_offset, strings.sh_size, u64::from(raw.st_name), content)?,
                        "name_offset": hex(u64::from(raw.st_name)),
                        "location": location(section.sh_offset.saturating_add(entry.saturating_mul(section.sh_entsize)), section.sh_entsize, length)?,
                        "value": hex(raw.st_value),
                        "value_meaning": symbol_value_meaning(&image_type, st_type_name, raw.st_shndx, all_sections),
                        "size": hex(raw.st_size),
                        "binding": scalar(&e.st_bind, i64::from(raw.st_info >> 4)),
                        "type": scalar(&e.st_type, st_type_value),
                        "visibility": scalar(&e.st_visibility, i64::from(raw.st_other & 0x7)),
                        "section_index": scalar(&e.st_shndx, i64::from(raw.st_shndx)),
                    }));
                }
            }
            if kind == "SHT_REL" || kind == "SHT_RELA" {
                if image_type == "ET_REL" && section.sh_info as usize >= all_sections.len() {
                    return fail(
                        "format",
                        format!("ELF relocation section {index} references missing target section {}.", section.sh_info),
                    );
                }
                let mut symbol_table: Option<&Shdr> = None;
                if section.sh_link != 0 {
                    let link = section.sh_link as usize;
                    if link >= all_sections.len() || !matches!(type_name(&all_sections[link]), "SHT_SYMTAB" | "SHT_DYNSYM") {
                        return fail(
                            "format",
                            format!("ELF relocation section {index} links to invalid symbol table {link}."),
                        );
                    }
                    symbol_table = Some(&all_sections[link]);
                }
                for (entry, raw) in read_relocations(content, section, kind == "SHT_RELA")
                    .map_err(upstream_failure)?
                    .iter()
                    .enumerate()
                {
                    if raw.sym() != 0 {
                        let missing = match symbol_table {
                            None => true,
                            Some(table) => raw.sym() >= image.sym_count(table),
                        };
                        if missing {
                            return fail(
                                "format",
                                format!(
                                    "ELF relocation section {index} entry {entry} references missing symbol {} in table {}.",
                                    raw.sym(),
                                    section.sh_link
                                ),
                            );
                        }
                    }
                    relocations_json.push(json!({
                        "section_index": index,
                        "entry_index": entry,
                        "reported_offset": hex(raw.r_offset),
                        "target": relocation_target(&image_type, section.sh_info, raw.r_offset, all_sections),
                        "location": location(
                            section.sh_offset.saturating_add((entry as u64).saturating_mul(section.sh_entsize)),
                            section.sh_entsize,
                            length,
                        )?,
                        "type": raw.kind(),
                        "symbol_table_index": section.sh_link,
                        "symbol_index": raw.sym(),
                        "symbol_reference_meaning": if raw.sym() == 0 { "zero-symbol-value" } else { "symbol-table-entry" },
                        "addend": raw.r_addend.map(|a| a.to_string()),
                    }));
                }
            }
            if kind == "SHT_RELR" {
                let entries = relr_offsets(content, section.sh_offset, section.sh_size).map_err(upstream_failure)?;
                let end = (section.sh_offset.saturating_add(section.sh_size) as usize).min(length);
                packed_json.push(json!({
                    "section_index": index,
                    "location": location(section.sh_offset, section.sh_size, length)?,
                    "encoded_bytes_base64": b64(content.get(section.sh_offset as usize..end).unwrap_or(&[])),
                    "entries": entries.iter().enumerate().map(|(decoded, offset)| json!({
                        "decoded_index": decoded,
                        "reported_offset": hex(*offset),
                    })).collect::<Vec<_>>(),
                    "offset_meaning": if image_type == "ET_REL" { "unknown" } else { "linked-virtual-address" },
                    "evidence_kind": "derived",
                    "entry_source_locations": null,
                    "addends": null,
                }));
            }
        }

        for (index, segment) in image.segments.iter().enumerate() {
            let kind = e.p_type.name(i64::from(segment.p_type)).unwrap_or("");
            let backing = kind != "PT_NULL" && segment.p_filesz != 0;
            if backing {
                location(segment.p_offset, segment.p_filesz, length)?;
            }
            if kind == "PT_LOAD" && segment.p_memsz < segment.p_filesz {
                return fail("format", "ELF load segment memory size is smaller than its file size.");
            }
            segments_json.push(json!({
                "index": index,
                "type": scalar(&e.p_type, i64::from(segment.p_type)),
                "offset": hex(segment.p_offset),
                "header_location": location(
                    header.e_phoff.saturating_add((index as u64).saturating_mul(u64::from(header.e_phentsize))),
                    u64::from(header.e_phentsize),
                    length,
                )?,
                "file_size": hex(segment.p_filesz),
                "memory_size": hex(segment.p_memsz),
                "virtual_address": hex(segment.p_vaddr),
                "physical_address": hex(segment.p_paddr),
                "alignment": hex(segment.p_align),
                "flags": hex(u64::from(segment.p_flags)),
                "file_backing": if backing { "file" } else { "none" },
                "permissions": if kind == "PT_NULL" { Value::Null } else { json!({
                    "read": segment.p_flags & 4 != 0,
                    "write": segment.p_flags & 2 != 0,
                    "execute": segment.p_flags & 1 != 0,
                }) },
            }));
            if kind == "PT_DYNAMIC" {
                let tag_count = segment.p_filesz / 16;
                let mut tags: Vec<(i64, u64)> = Vec::new();
                let mut terminated = false;
                for tag_index in 0..tag_count {
                    let at = segment.p_offset.saturating_add(tag_index * 16);
                    walk(content, at, &[8, 8]).map_err(upstream_failure)?;
                    let tag = le64(content, at as usize) as i64;
                    let value = le64(content, at as usize + 8);
                    tags.push((tag, value));
                    if tag == 0 {
                        terminated = true;
                        break;
                    }
                }
                if !terminated {
                    return fail(
                        "format",
                        format!("ELF dynamic segment {index} has no complete DT_NULL terminator within its reported file range."),
                    );
                }
                let needed_tag = e.d_tag.value("DT_NEEDED").unwrap_or(1);
                for (tag, value) in &tags {
                    if *tag == needed_tag {
                        needed.push(dynamic_name_reference(&tags, *value, &image.segments, content)?);
                    }
                }
            }
            if kind == "PT_INTERP" {
                let start = (segment.p_offset as usize).min(length);
                let end = (segment.p_offset.saturating_add(segment.p_filesz) as usize).min(length);
                let raw = &content[start..end];
                let Some(nul) = raw.iter().position(|b| *b == 0) else {
                    return fail("format", "ELF interpreter lacks a reported terminator.");
                };
                interpreters.push(json!({
                    "display": String::from_utf8_lossy(&raw[..nul]).into_owned(),
                    "bytes_base64": b64(&raw[..nul]),
                    "location": location(segment.p_offset, nul as u64 + 1, length)?,
                    "unknown_reason": null,
                }));
            }
        }
        Ok(())
    })();
    if let Err(mut failure) = layout {
        failure.stderr = stderr_of(&warnings);
        return Err(failure);
    }

    // Synthetic symbols (used for the canary heuristic).
    let mut canary_names: std::collections::HashSet<String> = symbols.keys().cloned().collect();
    for name in got.keys().chain(plt.keys()) {
        canary_names.insert(name.clone());
    }

    // Mitigations.
    let pie = elftype == "DYN";
    let gnu_stack = image
        .segments
        .iter()
        .filter(|s| e.p_type.name(i64::from(s.p_type)).map(|n| n.contains("GNU_STACK")).unwrap_or(false))
        .map(|s| s.p_flags & 1 != 0)
        .collect::<Vec<_>>();
    let nx: Value = if !executable {
        json!(true)
    } else {
        match gnu_stack.last() {
            Some(false) => json!(true),
            _ => Value::Null,
        }
    };
    let execstack = if !executable {
        false
    } else {
        match gnu_stack.first() {
            Some(flag) => *flag,
            None => true,
        }
    };
    let canary = canary_names.contains("__stack_chk_fail");
    let has_relro = image
        .segments
        .iter()
        .any(|s| e.p_type.name(i64::from(s.p_type)).map(|n| n.contains("GNU_RELRO")).unwrap_or(false));
    let relro: Value = if !has_relro {
        Value::Null
    } else {
        let bind_now = image.dynamic_has("DT_BIND_NOW").map_err(|m| upstream_with(m, &warnings))?;
        let flags = image.dynamic_value("DT_FLAGS").map_err(|m| upstream_with(m, &warnings))?;
        let flags_1 = image.dynamic_value("DT_FLAGS_1").map_err(|m| upstream_with(m, &warnings))?;
        if bind_now
            || flags.map(|f| f != 0 && f & 0x8 != 0).unwrap_or(false)
            || flags_1.map(|f| f != 0 && f & 0x1 != 0).unwrap_or(false)
        {
            json!("Full")
        } else {
            json!("Partial")
        }
    };

    let mut limitations: Vec<Value> = vec![
        json!("PT_NULL payload fields are unused and retain their reported numbers without file-byte or permission claims. Zero-file-size segments provide no file bytes."),
        json!("SHN_XINDEX symbol values remain unresolved in this upstream representation; an external index table does not establish a resolved index in this report."),
        json!("Reported values preserve linked addresses, section offsets, TLS offsets, alignment and absolute values separately. Runtime load base and library paths are unknown."),
        json!("Names are display strings plus raw bytes and file ranges where resolvable; section/table/entry indices preserve identity and duplicates. Name ranges include their terminating NUL; raw name bytes exclude it."),
        json!("Ordinary relocation rows cover REL/RELA. RELR tables retain complete encoded bytes and upstream-decoded offsets as derived evidence; per-offset packed-word locations and implicit addends remain unknown. Relocation inventory completeness is unknown, including other encodings and missing section tables."),
        json!("Relocation symbol index zero uses a zero symbol value without a table lookup. Positive indices reference validated original symbol-table entries; raw table and symbol indices remain reported."),
        json!("Relocatable relocation targets with SHN_UNDEF or inactive SHT_NULL headers retain their reported section index/offset as unknown; they do not establish an associated target section."),
        json!("GOT/PLT are derived upstream convenience maps; PLT inference can emulate selected instructions in Unicorn. They do not establish target runtime behavior; aliases may collapse and warnings may indicate incomplete coverage. Their completeness is unknown."),
        json!("Mitigations are upstream static heuristics, not runtime protection. ET_DYN does not prove an executable; absent canary symbols do not prove every function unprotected."),
        json!("This profile inspects ELF EXEC/DYN/REL layout only. It does not analyze recorded cores, resolve loaded libraries, launch the target as a host process or start a debugger."),
        json!("Symbol/relocation inventories reflect original section tables. A sectionless image can still report dynamic dependency names; missing tables do not prove absence of dynamic symbols or relocations."),
    ];
    if !all_sections.is_empty() && section_name_index == 0 {
        limitations.push(json!("Absent section-name table: section-dependent RELRO/canary heuristics may be incomplete; protection coverage is unknown."));
    }
    if all_sections.is_empty() {
        limitations.push(json!("Sectionless images lack the .dynamic section and symbol tables used by upstream heuristics. RELRO/canary indicators may be incomplete; their values remain reported static candidates, with protection coverage unknown."));
    }
    limitations.push(json!(IN_PROCESS_LIMITATION));
    let entry_meaning = if image_type == "ET_REL" {
        "not-applicable"
    } else if header.e_entry == 0 {
        "absent"
    } else {
        "linked-virtual-address"
    };
    let payload = json!({
        "format": "elf",
        "architecture": {
            "machine": e.e_machine.name(i64::from(header.e_machine)).unwrap_or(""),
            "bits": 64,
            "byte_order": "little",
        },
        "image_type": image_type,
        "entry_point": {
            "reported_value": hex(header.e_entry),
            "meaning": entry_meaning,
            "execution_status": "unknown",
        },
        "runtime_load_base": null,
        "sections": sections_json,
        "segments": segments_json,
        "symbols": symbols_json,
        "relocations": relocations_json,
        "packed_relative_relocations": packed_json,
        "relocation_inventory_completeness": "unknown",
        "linkage": {
            "needed_libraries": needed,
            "interpreters": interpreters,
            "got": got.iter().map(|(name, value)| json!({"display_name": name, "address": hex(*value)})).collect::<Vec<_>>(),
            "plt": plt.iter().map(|(name, value)| json!({"display_name": name, "address": hex(*value)})).collect::<Vec<_>>(),
            "convenience_maps_completeness": "unknown",
            "runtime_library_paths": null,
        },
        "mitigations": {
            "evidence_kind": "inferred",
            "position_independent": pie,
            "nx_indicator": nx,
            "executable_stack_indicator": execstack,
            "stack_canary_indicator": canary,
            "relro": relro,
        },
        "limitations": limitations,
    });
    Ok(ElfLayout {
        payload,
        stderr: stderr_of(&warnings),
    })
}

/// Honest statement of how the maps were derived (replaces REA's Python resource-limit sentence).
pub const IN_PROCESS_LIMITATION: &str = "The layout was decoded in-process by the Rust port of the pwntools 4.15.0/pyelftools 0.33 adapter. PLT discovery decodes instructions with iced-x86 and a small interpreter instead of emulating them in Unicorn, so linkage.plt for atypical stubs may differ from pwntools.";
// ---------------------------------------------------------------------------
// PLT discovery
// ---------------------------------------------------------------------------

/// Address read by the first memory access of at most five instructions starting at `start`
/// inside the page-aligned mapping of a PLT section; `None` when nothing is read (target 0).
fn plt_target(region_start: u64, region: &[u8], start: u64) -> Option<u64> {
    use iced_x86::{ConditionCode, Decoder, DecoderOptions, FlowControl, InstructionInfoFactory, Mnemonic, OpAccess, Register};
    let mut registers: HashMap<Register, u64> = HashMap::new();
    let mut tainted: std::collections::HashSet<Register> = std::collections::HashSet::new();
    let mut factory = InstructionInfoFactory::new();
    let mut ip = start;
    let region_end = region_start + region.len() as u64;
    for _ in 0..5 {
        if ip < region_start || ip >= region_end {
            return None;
        }
        let slice = &region[(ip - region_start) as usize..];
        let mut decoder = Decoder::with_ip(64, slice, ip, DecoderOptions::NONE);
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return None;
        }
        let info = factory.info(&instruction).clone();
        // Memory reads first: the engine reports the access address and stops.
        let mut unknown_register = false;
        let mut value_of = |register: Register, _element: usize, _size: usize| -> Option<u64> {
            let full = register.full_register();
            if register == Register::None {
                return Some(0);
            }
            if tainted.contains(&full) {
                unknown_register = true;
                return Some(0);
            }
            if register == Register::RIP || register == Register::EIP {
                return Some(instruction.next_ip());
            }
            Some(registers.get(&full).copied().unwrap_or(0))
        };
        let mut write_outside = false;
        let mut read_address: Option<u64> = None;
        for used in info.used_memory() {
            let address = used.virtual_address(0, &mut value_of).unwrap_or(0xdead_beef_dead_beef);
            match used.access() {
                OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                    if read_address.is_none() {
                        read_address = Some(address);
                    }
                }
                OpAccess::Write | OpAccess::CondWrite if address < region_start || address >= region_end => {
                    write_outside = true;
                }
                _ => {}
            }
        }
        if let Some(address) = read_address {
            return Some(if unknown_register { 0xdead_beef_dead_beef } else { address });
        }
        if write_outside {
            return None;
        }
        // Register effects (only what PLT stubs and padding can plausibly do).
        match instruction.mnemonic() {
            Mnemonic::Mov
                if instruction.op0_kind() == iced_x86::OpKind::Register
                    && matches!(
                        instruction.op1_kind(),
                        iced_x86::OpKind::Immediate8
                            | iced_x86::OpKind::Immediate16
                            | iced_x86::OpKind::Immediate32
                            | iced_x86::OpKind::Immediate64
                            | iced_x86::OpKind::Immediate8to32
                            | iced_x86::OpKind::Immediate8to64
                            | iced_x86::OpKind::Immediate32to64
                    ) =>
            {
                let register = instruction.op0_register().full_register();
                registers.insert(register, instruction.immediate(1));
                tainted.remove(&register);
            }
            Mnemonic::Xor
                if instruction.op0_kind() == iced_x86::OpKind::Register
                    && instruction.op1_kind() == iced_x86::OpKind::Register
                    && instruction.op0_register() == instruction.op1_register() =>
            {
                let register = instruction.op0_register().full_register();
                registers.insert(register, 0);
                tainted.remove(&register);
            }
            Mnemonic::Nop | Mnemonic::Endbr64 | Mnemonic::Endbr32 | Mnemonic::Pause | Mnemonic::Fnop => {}
            _ => {
                for used in info.used_registers() {
                    if matches!(
                        used.access(),
                        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
                    ) {
                        tainted.insert(used.register().full_register());
                    }
                }
            }
        }
        match instruction.flow_control() {
            FlowControl::Next => ip = instruction.next_ip(),
            FlowControl::UnconditionalBranch => ip = instruction.near_branch_target(),
            FlowControl::ConditionalBranch => {
                // Flags start cleared: ZF=CF=SF=OF=PF=0.
                let taken = match instruction.condition_code() {
                    ConditionCode::None => matches!(instruction.mnemonic(), Mnemonic::Jrcxz | Mnemonic::Jecxz | Mnemonic::Jcxz),
                    ConditionCode::o | ConditionCode::b | ConditionCode::e | ConditionCode::be | ConditionCode::s
                    | ConditionCode::p | ConditionCode::l | ConditionCode::le => false,
                    ConditionCode::no | ConditionCode::ae | ConditionCode::ne | ConditionCode::a | ConditionCode::ns
                    | ConditionCode::np | ConditionCode::ge | ConditionCode::g => true,
                };
                ip = if taken { instruction.near_branch_target() } else { instruction.next_ip() };
            }
            FlowControl::IndirectBranch => {
                // Memory forms returned above; a register target is unmapped unless known.
                let register = instruction.op0_register().full_register();
                if instruction.op0_kind() == iced_x86::OpKind::Register && !tainted.contains(&register) {
                    ip = registers.get(&register).copied().unwrap_or(0);
                } else {
                    return None;
                }
            }
            _ => return None,
        }
    }
    None
}
fn dynamic_name_reference(tags: &[(i64, u64)], offset: u64, segments: &[Phdr], content: &[u8]) -> R<Value> {
    let e = enums();
    let strtab = e.d_tag.value("DT_STRTAB").unwrap_or(5);
    let strsz = e.d_tag.value("DT_STRSZ").unwrap_or(10);
    let starts: Vec<u64> = tags.iter().filter(|(t, _)| *t == strtab).map(|(_, v)| *v).collect();
    let sizes: Vec<u64> = tags.iter().filter(|(t, _)| *t == strsz).map(|(_, v)| *v).collect();
    if starts.is_empty() || sizes.is_empty() {
        return fail("format", "ELF dependency requires DT_STRTAB and DT_STRSZ.");
    }
    if starts.len() != 1 || sizes.len() != 1 {
        return fail(
            "unsupported-target",
            format!(
                "ELF dependency string-table tags are ambiguous: {{'DT_STRTAB': {:?}, 'DT_STRSZ': {:?}}}",
                starts, sizes
            ),
        );
    }
    if offset >= sizes[0] {
        return fail(
            "format",
            format!("ELF dependency name offset {offset} lies outside declared DT_STRSZ {}.", sizes[0]),
        );
    }
    let mut offsets: Vec<u64> = Vec::new();
    for segment in segments {
        if e.p_type.name(i64::from(segment.p_type)) != Some("PT_LOAD") {
            continue;
        }
        if starts[0] >= segment.p_vaddr && starts[0] + sizes[0] <= segment.p_vaddr + segment.p_filesz {
            let candidate = segment.p_offset + starts[0] - segment.p_vaddr;
            if !offsets.contains(&candidate) {
                offsets.push(candidate);
            }
        }
    }
    if offsets.len() != 1 {
        offsets.sort_unstable();
        return fail(
            "unsupported-target",
            format!(
                "Dynamic string table lacks a unique file-backed mapping: {{'DT_STRTAB': {:?}, 'DT_STRSZ': {:?}, 'candidate_file_offsets': {:?}}}",
                starts, sizes, offsets
            ),
        );
    }
    name_in_table(None, offsets[0], sizes[0], offset, content)
}

// ---------------------------------------------------------------------------
// Summary view (REA `domain/analysisView/binaryLayoutView.ts`)
// ---------------------------------------------------------------------------

fn unique_sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

/// The unsigned `summary` view of a complete layout report; the caller attaches `view_digest`.
pub fn layout_summary_view(
    parent_evidence_id: &str,
    parent_limitations: &[String],
    report: &Value,
) -> Value {
    let count = |key: &str| report[key].as_array().map(Vec::len).unwrap_or(0);
    let total = count("sections") + count("segments") + count("symbols") + count("relocations");
    let layout_limitations: Vec<String> = report["limitations"]
        .as_array()
        .map(|items| items.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let mut limitations = parent_limitations.to_vec();
    limitations.extend(layout_limitations.iter().cloned());
    let mut unknowns = vec![
        "runtime_load_base is unknown".to_string(),
        "entry_point.execution_status is unknown".to_string(),
        "relocation_inventory_completeness is unknown".to_string(),
        "linkage.convenience_maps_completeness is unknown".to_string(),
        "linkage.runtime_library_paths are unknown".to_string(),
    ];
    if report["mitigations"]["nx_indicator"].is_null() {
        unknowns.push("mitigations.nx_indicator is unknown".to_string());
    }
    if report["mitigations"]["relro"].is_null() {
        unknowns.push("mitigations.relro is unknown".to_string());
    }
    json!({
        "kind": "summary",
        "view": {"kind": "summary"},
        "summary": {
            "bytes": report["artifact"]["bytes"],
            "format": report["format"],
            "architecture": report["architecture"],
            "image_type": report["image_type"],
            "entry": report["entry_point"],
            "counts": {
                "sections": count("sections"),
                "segments": count("segments"),
                "symbols": count("symbols"),
                "relocations": count("relocations"),
            },
            "limitation_count": layout_limitations.len(),
        },
        "coverage": {
            "status": "complete-within-view",
            "examined": total,
            "total": total,
            "next_offset": null,
            "exhausted": true,
        },
        "parent_evidence_id": parent_evidence_id,
        "parent_operation": "inspect_binary_layout",
        "parent_digest": parent_evidence_id.get(3..).unwrap_or(""),
        "artifact": {
            "path": report["artifact"]["path"],
            "sha256": report["artifact"]["sha256"],
        },
        "limitations": unique_sorted(limitations),
        "unknowns": unique_sorted(unknowns),
    })
}

