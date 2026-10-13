//! `otool -h -l` text for a Mach-O slice, and the parser REA applies to it
//! (`native/parsers/otool.ts`).
//!
//! The text is produced from the file bytes in the non-verbose layout of cctools `otool`
//! (numeric header, numeric platform/tool ids, symbolic command names), so that the REA parser
//! derives the same normalized fields from native bytes as from the Apple tool's output.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::macho_image::{Bytes, Image, MachoResult};

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

pub const LC_REQ_DYLD: u32 = 0x8000_0000;

/// Symbolic load command name, or `None` for unknown commands.
pub fn load_command_name(cmd: u32) -> Option<&'static str> {
    Some(match cmd {
        0x1 => "LC_SEGMENT",
        0x2 => "LC_SYMTAB",
        0x3 => "LC_SYMSEG",
        0x4 => "LC_THREAD",
        0x5 => "LC_UNIXTHREAD",
        0x6 => "LC_LOADFVMLIB",
        0x7 => "LC_IDFVMLIB",
        0x8 => "LC_IDENT",
        0x9 => "LC_FVMFILE",
        0xa => "LC_PREPAGE",
        0xb => "LC_DYSYMTAB",
        0xc => "LC_LOAD_DYLIB",
        0xd => "LC_ID_DYLIB",
        0xe => "LC_LOAD_DYLINKER",
        0xf => "LC_ID_DYLINKER",
        0x10 => "LC_PREBOUND_DYLIB",
        0x11 => "LC_ROUTINES",
        0x12 => "LC_SUB_FRAMEWORK",
        0x13 => "LC_SUB_UMBRELLA",
        0x14 => "LC_SUB_CLIENT",
        0x15 => "LC_SUB_LIBRARY",
        0x16 => "LC_TWOLEVEL_HINTS",
        0x17 => "LC_PREBIND_CKSUM",
        0x8000_0018 => "LC_LOAD_WEAK_DYLIB",
        0x19 => "LC_SEGMENT_64",
        0x1a => "LC_ROUTINES_64",
        0x1b => "LC_UUID",
        0x8000_001c => "LC_RPATH",
        0x1d => "LC_CODE_SIGNATURE",
        0x1e => "LC_SEGMENT_SPLIT_INFO",
        0x8000_001f => "LC_REEXPORT_DYLIB",
        0x20 => "LC_LAZY_LOAD_DYLIB",
        0x21 => "LC_ENCRYPTION_INFO",
        0x22 => "LC_DYLD_INFO",
        0x8000_0022 => "LC_DYLD_INFO_ONLY",
        0x8000_0023 => "LC_LOAD_UPWARD_DYLIB",
        0x24 => "LC_VERSION_MIN_MACOSX",
        0x25 => "LC_VERSION_MIN_IPHONEOS",
        0x26 => "LC_FUNCTION_STARTS",
        0x27 => "LC_DYLD_ENVIRONMENT",
        0x8000_0028 => "LC_MAIN",
        0x29 => "LC_DATA_IN_CODE",
        0x2a => "LC_SOURCE_VERSION",
        0x2b => "LC_DYLIB_CODE_SIGN_DRS",
        0x2c => "LC_ENCRYPTION_INFO_64",
        0x2d => "LC_LINKER_OPTION",
        0x2e => "LC_LINKER_OPTIMIZATION_HINT",
        0x2f => "LC_VERSION_MIN_TVOS",
        0x30 => "LC_VERSION_MIN_WATCHOS",
        0x31 => "LC_NOTE",
        0x32 => "LC_BUILD_VERSION",
        0x8000_0033 => "LC_DYLD_EXPORTS_TRIE",
        0x8000_0034 => "LC_DYLD_CHAINED_FIXUPS",
        0x8000_0035 => "LC_FILESET_ENTRY",
        0x36 => "LC_ATOM_INFO",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/// `ctime(3)` text of a UTC time stamp, without the trailing newline.
pub fn ctime_utc(seconds: u32) -> String {
    let days = i64::from(seconds / 86_400);
    let rest = seconds % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    let weekday = WEEKDAYS[(days.rem_euclid(7)) as usize];
    format!(
        "{} {} {:2} {:02}:{:02}:{:02} {}",
        weekday,
        MONTHS[(month - 1) as usize],
        day,
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60,
        year
    )
}

fn version_xyz(value: u32) -> String {
    format!("{}.{}.{}", value >> 16, (value >> 8) & 0xff, value & 0xff)
}

/// `a.b` or `a.b.c` (cctools omits a zero patch level).
fn version_ab(value: u32) -> String {
    let patch = value & 0xff;
    if patch != 0 {
        format!("{}.{}.{}", value >> 16, (value >> 8) & 0xff, patch)
    } else {
        format!("{}.{}", value >> 16, (value >> 8) & 0xff)
    }
}

fn source_version(value: u64) -> String {
    let a = (value >> 40) & 0xff_ffff;
    let b = (value >> 30) & 0x3ff;
    let c = (value >> 20) & 0x3ff;
    let d = (value >> 10) & 0x3ff;
    let e = value & 0x3ff;
    if e != 0 {
        format!("{a}.{b}.{c}.{d}.{e}")
    } else if d != 0 {
        format!("{a}.{b}.{c}.{d}")
    } else if c != 0 {
        format!("{a}.{b}.{c}")
    } else {
        format!("{a}.{b}")
    }
}

fn uuid_text(raw: &[u8]) -> String {
    let hex: Vec<String> = raw.iter().map(|b| format!("{b:02X}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        hex[0..4].concat(),
        hex[4..6].concat(),
        hex[6..8].concat(),
        hex[8..10].concat(),
        hex[10..16].concat()
    )
}

/// Right-align labels to `longest label + 1` columns, as otool does for most commands.
fn block(lines: &[(&str, String)]) -> Vec<String> {
    let width = lines.iter().map(|(label, _)| label.len()).max().unwrap_or(0) + 1;
    lines.iter().map(|(label, value)| format!("{label:>width$} {value}")).collect()
}

fn offset_string(bytes: &Bytes<'_>, command_at: usize, command_size: usize, field_offset_at: usize) -> MachoResult<(String, u32)> {
    let offset = bytes.u32(field_offset_at)?;
    let start = command_at + offset as usize;
    let end = command_at + command_size;
    if start > end {
        return Ok((String::new(), offset));
    }
    let region = bytes.slice(start, end - start)?;
    let stop = region.iter().position(|b| *b == 0).unwrap_or(region.len());
    Ok((String::from_utf8_lossy(&region[..stop]).into_owned(), offset))
}

fn section_type_notes(flags: u32) -> (bool, bool) {
    // (reserved1 indexes the indirect symbol table, reserved2 is a stub size)
    let kind = flags & 0xff;
    let indirect = matches!(kind, 0x08 | 0x06 | 0x07 | 0x10 | 0x15);
    (indirect, kind == 0x08)
}

fn thread_state_name(cputype: u32, flavor: u32) -> Option<&'static str> {
    match (cputype, flavor) {
        (0x0100_0007, 4) => Some("x86_THREAD_STATE64"),
        (7, 1) => Some("i386_THREAD_STATE"),
        (0x0100_000c, 6) => Some("ARM_THREAD_STATE64"),
        (12, 1) => Some("ARM_THREAD_STATE"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Printer
// ---------------------------------------------------------------------------

/// `otool -h -l` output of one slice, starting with the (caller supplied) path line.
pub fn print_header_and_commands(image: &Image<'_>, path_line: &str) -> MachoResult<String> {
    let mut out: Vec<String> = Vec::new();
    out.push(format!("{path_line}:"));
    let header = &image.header;
    out.push("Mach header".to_string());
    out.push("      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags".to_string());
    out.push(format!(
        " 0x{:08x} {:>8} {:>10}  0x{:02x} {:>11} {:>5} {:>10} 0x{:08x}",
        header.magic,
        header.cputype as i32,
        (header.cpusubtype & !0xff00_0000) as i32,
        (header.cpusubtype >> 24) & 0xff,
        header.filetype,
        header.ncmds,
        header.sizeofcmds,
        header.flags
    ));
    out.extend(print_load_commands(image)?);
    Ok(out.join("\n") + "\n")
}

/// The `Load command N` blocks of `otool -l`.
pub fn print_load_commands(image: &Image<'_>) -> MachoResult<Vec<String>> {
    let bytes = image.bytes();
    let mut out: Vec<String> = Vec::new();
    for command in &image.commands {
        out.push(format!("Load command {}", command.index));
        let at = command.offset;
        let size = command.cmdsize as usize;
        let name = load_command_name(command.cmd)
            .map(String::from)
            .unwrap_or_else(|| format!("?(0x{:08x})", command.cmd));
        let cmd = ("cmd", name);
        let cmdsize = ("cmdsize", command.cmdsize.to_string());
        let mut lines: Vec<(&str, String)> = vec![cmd, cmdsize];
        let mut extra: Vec<String> = Vec::new();
        let mut custom: Option<Vec<String>> = None;
        match command.cmd {
            0x19 | 0x1 => {
                let wide = command.cmd == 0x19;
                let (vmaddr, vmsize, fileoff, filesize, rest) = if wide {
                    (bytes.u64(at + 24)?, bytes.u64(at + 32)?, bytes.u64(at + 40)?, bytes.u64(at + 48)?, at + 56)
                } else {
                    (
                        u64::from(bytes.u32(at + 24)?),
                        u64::from(bytes.u32(at + 28)?),
                        u64::from(bytes.u32(at + 32)?),
                        u64::from(bytes.u32(at + 36)?),
                        at + 40,
                    )
                };
                let maxprot = bytes.u32(rest)?;
                let initprot = bytes.u32(rest + 4)?;
                let nsects = bytes.u32(rest + 8)?;
                let flags = bytes.u32(rest + 12)?;
                lines.push(("segname", bytes.name16(at + 8)?));
                lines.push(("vmaddr", if wide { format!("0x{vmaddr:016x}") } else { format!("0x{vmaddr:08x}") }));
                lines.push(("vmsize", if wide { format!("0x{vmsize:016x}") } else { format!("0x{vmsize:08x}") }));
                lines.push(("fileoff", fileoff.to_string()));
                lines.push(("filesize", filesize.to_string()));
                lines.push(("maxprot", format!("0x{maxprot:08x}")));
                lines.push(("initprot", format!("0x{initprot:08x}")));
                lines.push(("nsects", nsects.to_string()));
                lines.push(("flags", format!("0x{flags:x}")));
                let section_size = if wide { 80 } else { 68 };
                let mut section_at = rest + 16;
                for _ in 0..nsects {
                    let sectname = bytes.name16(section_at)?;
                    let segname = bytes.name16(section_at + 16)?;
                    let (addr, ssize, soffset, align, reloff, nreloc, sflags, r1, r2) = if wide {
                        (
                            bytes.u64(section_at + 32)?,
                            bytes.u64(section_at + 40)?,
                            bytes.u32(section_at + 48)?,
                            bytes.u32(section_at + 52)?,
                            bytes.u32(section_at + 56)?,
                            bytes.u32(section_at + 60)?,
                            bytes.u32(section_at + 64)?,
                            bytes.u32(section_at + 68)?,
                            bytes.u32(section_at + 72)?,
                        )
                    } else {
                        (
                            u64::from(bytes.u32(section_at + 32)?),
                            u64::from(bytes.u32(section_at + 36)?),
                            bytes.u32(section_at + 40)?,
                            bytes.u32(section_at + 44)?,
                            bytes.u32(section_at + 48)?,
                            bytes.u32(section_at + 52)?,
                            bytes.u32(section_at + 56)?,
                            bytes.u32(section_at + 60)?,
                            bytes.u32(section_at + 64)?,
                        )
                    };
                    let (indirect, stubs) = section_type_notes(sflags);
                    let mut section = vec![
                        ("sectname", sectname),
                        ("segname", segname),
                        ("addr", if wide { format!("0x{addr:016x}") } else { format!("0x{addr:08x}") }),
                        ("size", if wide { format!("0x{ssize:016x}") } else { format!("0x{ssize:08x}") }),
                        ("offset", soffset.to_string()),
                        (
                            "align",
                            if align < 32 { format!("2^{align} ({})", 1u64 << align) } else { format!("2^{align} (overflow)") },
                        ),
                        ("reloff", reloff.to_string()),
                        ("nreloc", nreloc.to_string()),
                        ("flags", format!("0x{sflags:08x}")),
                        ("reserved1", if indirect { format!("{r1} (index into indirect symbol table)") } else { r1.to_string() }),
                        ("reserved2", if stubs { format!("{r2} (size of stubs)") } else { r2.to_string() }),
                    ];
                    if wide {
                        // cctools prints reserved3 for 64-bit sections only when it is non-zero.
                        let r3 = bytes.u32(section_at + 76).unwrap_or(0);
                        if r3 != 0 {
                            section.push(("reserved3", r3.to_string()));
                        }
                    }
                    extra.push("Section".to_string());
                    extra.extend(block(&section));
                    section_at += section_size;
                }
            }
            0x2 => {
                lines.push(("symoff", bytes.u32(at + 8)?.to_string()));
                lines.push(("nsyms", bytes.u32(at + 12)?.to_string()));
                lines.push(("stroff", bytes.u32(at + 16)?.to_string()));
                lines.push(("strsize", bytes.u32(at + 20)?.to_string()));
            }
            0xb => {
                for (index, label) in [
                    "ilocalsym",
                    "nlocalsym",
                    "iextdefsym",
                    "nextdefsym",
                    "iundefsym",
                    "nundefsym",
                    "tocoff",
                    "ntoc",
                    "modtaboff",
                    "nmodtab",
                    "extrefsymoff",
                    "nextrefsyms",
                    "indirectsymoff",
                    "nindirectsyms",
                    "extreloff",
                    "nextrel",
                    "locreloff",
                    "nlocrel",
                ]
                .iter()
                .enumerate()
                {
                    lines.push((label, bytes.u32(at + 8 + index * 4)?.to_string()));
                }
            }
            0xc | 0xd | 0x8000_0018 | 0x8000_001f | 0x20 | 0x8000_0023 => {
                let (text, offset) = offset_string(&bytes, at, size, at + 8)?;
                let timestamp = bytes.u32(at + 12)?;
                let current = bytes.u32(at + 16)?;
                let compatibility = bytes.u32(at + 20)?;
                let mut printed = block(&[("cmd", lines[0].1.clone()), ("cmdsize", command.cmdsize.to_string())]);
                // cctools aligns these commands on a 13-column label field, versions on 21.
                printed = printed
                    .into_iter()
                    .map(|line| {
                        let trimmed = line.trim_start().to_string();
                        let label = trimmed.split(' ').next().unwrap_or("").to_string();
                        let rest = trimmed[label.len()..].to_string();
                        format!("{label:>13}{rest}")
                    })
                    .collect();
                printed.push(format!("{:>13} {text} (offset {offset})", "name"));
                printed.push(format!("{:>13} {timestamp} {}", "time stamp", ctime_utc(timestamp)));
                printed.push(format!("{:>21} {}", "current version", version_xyz(current)));
                printed.push(format!("{:>21} {}", "compatibility version", version_xyz(compatibility)));
                custom = Some(printed);
            }
            0xe | 0xf | 0x27 => {
                let (text, offset) = offset_string(&bytes, at, size, at + 8)?;
                lines.push(("name", format!("{text} (offset {offset})")));
            }
            0x8000_001c => {
                let (text, offset) = offset_string(&bytes, at, size, at + 8)?;
                lines.push(("path", format!("{text} (offset {offset})")));
            }
            0x12..=0x15 => {
                let (text, offset) = offset_string(&bytes, at, size, at + 8)?;
                let label = match command.cmd {
                    0x12 => "umbrella",
                    0x13 => "sub_umbrella",
                    0x14 => "client",
                    _ => "sub_library",
                };
                lines.push((label, format!("{text} (offset {offset})")));
            }
            0x1b => {
                lines.push(("uuid", uuid_text(bytes.slice(at + 8, 16)?)));
            }
            0x32 => {
                lines.push(("platform", bytes.u32(at + 8)?.to_string()));
                lines.push(("minos", version_ab(bytes.u32(at + 12)?)));
                lines.push(("sdk", version_ab(bytes.u32(at + 16)?)));
                let ntools = bytes.u32(at + 20)?;
                lines.push(("ntools", ntools.to_string()));
                let mut tools: Vec<(&str, String)> = Vec::new();
                for index in 0..ntools as usize {
                    if 24 + (index + 1) * 8 > size {
                        break;
                    }
                    tools.push(("tool", bytes.u32(at + 24 + index * 8)?.to_string()));
                    tools.push(("version", version_ab(bytes.u32(at + 28 + index * 8)?)));
                }
                lines.extend(tools);
            }
            0x24 | 0x25 | 0x2f | 0x30 => {
                lines.push(("version", version_ab(bytes.u32(at + 8)?)));
                lines.push(("sdk", version_ab(bytes.u32(at + 12)?)));
            }
            0x2a => {
                lines.push(("version", source_version(bytes.u64(at + 8)?)));
            }
            0x8000_0028 => {
                lines.push(("entryoff", bytes.u64(at + 8)?.to_string()));
                lines.push(("stacksize", bytes.u64(at + 16)?.to_string()));
            }
            0x1d | 0x1e | 0x26 | 0x29 | 0x2b | 0x2e | 0x8000_0033 | 0x8000_0034 | 0x36 => {
                lines.push(("dataoff", bytes.u32(at + 8)?.to_string()));
                lines.push(("datasize", bytes.u32(at + 12)?.to_string()));
            }
            0x22 | 0x8000_0022 => {
                for (index, label) in [
                    "rebase_off",
                    "rebase_size",
                    "bind_off",
                    "bind_size",
                    "weak_bind_off",
                    "weak_bind_size",
                    "lazy_bind_off",
                    "lazy_bind_size",
                    "export_off",
                    "export_size",
                ]
                .iter()
                .enumerate()
                {
                    lines.push((label, bytes.u32(at + 8 + index * 4)?.to_string()));
                }
            }
            0x21 | 0x2c => {
                lines.push(("cryptoff", bytes.u32(at + 8)?.to_string()));
                lines.push(("cryptsize", bytes.u32(at + 12)?.to_string()));
                lines.push(("cryptid", bytes.u32(at + 16)?.to_string()));
                if command.cmd == 0x2c {
                    lines.push(("pad", bytes.u32(at + 20)?.to_string()));
                }
            }
            0x11 | 0x1a => {
                let wide = command.cmd == 0x1a;
                let step = if wide { 8 } else { 4 };
                let mut names = vec!["init_address", "init_module", "reserved1", "reserved2", "reserved3", "reserved4", "reserved5", "reserved6"];
                for (index, label) in names.drain(..).enumerate() {
                    let value = if wide { bytes.u64(at + 8 + index * step)? } else { u64::from(bytes.u32(at + 8 + index * step)?) };
                    lines.push((label, if index == 0 { format!("0x{value:x}") } else { value.to_string() }));
                }
            }
            0x2d => {
                let count = bytes.u32(at + 8)?;
                lines.push(("count", count.to_string()));
                let mut cursor = at + 12;
                for _ in 0..count {
                    let text = bytes.cstring(cursor)?;
                    let consumed = text.len() + 1;
                    extra.push(format!("  string #{} {text}", extra.len() + 1));
                    cursor += consumed;
                }
            }
            0x31 => {
                lines.push(("data_owner", bytes.name16(at + 8)?));
                lines.push(("offset", bytes.u64(at + 24)?.to_string()));
                lines.push(("size", bytes.u64(at + 32)?.to_string()));
            }
            0x4 | 0x5 => {
                let mut cursor = at + 8;
                let end = at + size;
                while cursor + 8 <= end {
                    let flavor = bytes.u32(cursor)?;
                    let count = bytes.u32(cursor + 4)?;
                    let label = thread_state_name(image.header.cputype, flavor)
                        .map(String::from)
                        .unwrap_or_else(|| flavor.to_string());
                    extra.push(format!("     flavor {label}"));
                    extra.push(format!("      count {count}"));
                    let words = (count as usize * 4).min(end.saturating_sub(cursor + 8));
                    let state = bytes.slice(cursor + 8, words)?;
                    for (row, chunk) in state.chunks(8).enumerate() {
                        let mut value = 0u64;
                        for (i, b) in chunk.iter().enumerate() {
                            let shift = if image.header.big { (chunk.len() - 1 - i) * 8 } else { i * 8 };
                            value |= u64::from(*b) << shift;
                        }
                        extra.push(format!("\t  r{row:<3} 0x{value:016x}"));
                    }
                    cursor += 8 + count as usize * 4;
                    if count == 0 {
                        break;
                    }
                }
            }
            _ => {}
        }
        match custom {
            Some(printed) => out.extend(printed),
            None => {
                // The first two lines share the command's own alignment.
                let printed = block(&lines);
                out.extend(printed);
            }
        }
        out.extend(extra);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Parser (native/parsers/otool.ts)
// ---------------------------------------------------------------------------

fn numeric_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"^(?:0x[a-fA-F0-9]+|\d+)$").unwrap())
}

const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

/// `numeric()` of the TS parser: whole decimal/hex literal that is a safe non-negative integer.
fn numeric(value: &str) -> Option<f64> {
    if !numeric_pattern().is_match(value) {
        return None;
    }
    let parsed = if let Some(hex) = value.strip_prefix("0x") {
        parse_int_f64(hex, 16)
    } else {
        parse_int_f64(value, 10)
    };
    // JavaScript parseInt rounds beyond 2^53; Number.isSafeInteger rejects those.
    if parsed.is_finite() && (0.0..=MAX_SAFE).contains(&parsed) && parsed.fract() == 0.0 {
        Some(parsed)
    } else {
        None
    }
}

fn parse_int_f64(digits: &str, radix: u32) -> f64 {
    let mut value = 0f64;
    for ch in digits.chars() {
        let digit = ch.to_digit(radix).unwrap_or(0);
        value = value * f64::from(radix) + f64::from(digit);
    }
    value
}

#[derive(Clone, Debug, PartialEq)]
enum Field {
    Text(String),
    Number(f64),
}

fn field_value(field: &Field) -> Value {
    match field {
        Field::Text(text) => Value::String(text.clone()),
        Field::Number(number) => crate::plistjs::js_number(*number),
    }
}

type Fields = Vec<(String, Field)>;

fn lookup<'a>(fields: &'a Fields, name: &str) -> Option<&'a Field> {
    // Later duplicates win, as with an object assignment.
    fields.iter().rev().find(|(key, _)| key == name).map(|(_, field)| field)
}

fn string_field(fields: &Fields, name: &str) -> Option<String> {
    match lookup(fields, name)? {
        Field::Text(text) => Some(text.clone()),
        Field::Number(number) => Some(js_number_text(*number)),
    }
}

fn js_number_text(number: f64) -> String {
    if number.fract() == 0.0 && number.abs() < 1e21 {
        format!("{}", number as i128)
    } else {
        format!("{number}")
    }
}

fn number_field(fields: &Fields, name: &str) -> Option<f64> {
    match lookup(fields, name)? {
        Field::Number(number) => Some(*number),
        Field::Text(text) => numeric(text),
    }
}

fn hex_field(fields: &Fields, name: &str) -> Option<String> {
    let value = string_field(fields, name)?;
    if !numeric_pattern().is_match(&value) {
        return None;
    }
    let big = if let Some(hex) = value.strip_prefix("0x") {
        u128::from_str_radix(hex, 16).ok()?
    } else {
        value.parse::<u128>().ok()?
    };
    Some(format!("0x{big:x}"))
}

fn field_regex() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"^((?:time stamp)|\S+(?:\s+version)?)\s+(.+)$").unwrap())
}

fn parse_fields(block: &str) -> Fields {
    let mut fields: Fields = Vec::new();
    for raw in block.split('\n').skip(1) {
        let line = raw.trim();
        let Some(captures) = field_regex().captures(line) else { continue };
        let key = captures.get(1).unwrap().as_str();
        let value = captures.get(2).unwrap().as_str().trim();
        let parsed = if key == "segname" || key == "sectname" {
            Field::Text(value.to_string())
        } else {
            match numeric(value) {
                Some(number) => Field::Number(number),
                None => Field::Text(value.to_string()),
            }
        };
        if let Some(existing) = fields.iter_mut().find(|(k, _)| k == key) {
            existing.1 = parsed;
        } else {
            fields.push((key.to_string(), parsed));
        }
    }
    fields
}

fn permissions(raw: Option<String>) -> Value {
    let Some(raw) = raw else {
        return json!({"read": null, "write": null, "execute": null, "raw": null});
    };
    if let Some(number) = numeric(&raw) {
        let bits = number as u64;
        return json!({
            "read": bits & 1 != 0,
            "write": bits & 2 != 0,
            "execute": bits & 4 != 0,
            "raw": raw,
        });
    }
    let symbolic = Regex::new(r"^[r-][w-][x-]$").unwrap();
    if symbolic.is_match(&raw) {
        let chars: Vec<char> = raw.chars().collect();
        return json!({
            "read": chars[0] == 'r',
            "write": chars[1] == 'w',
            "execute": chars[2] == 'x',
            "raw": raw,
        });
    }
    json!({"read": null, "write": null, "execute": null, "raw": raw})
}

fn section_alignment(raw: Option<String>) -> Value {
    let Some(raw) = raw else { return Value::Null };
    static CELL: OnceLock<Regex> = OnceLock::new();
    let pattern = CELL.get_or_init(|| Regex::new(r"^2\^(\d+)(?:\s+\(\d+\))?$").unwrap());
    let candidate = pattern.captures(&raw).map(|c| c.get(1).unwrap().as_str().to_string()).unwrap_or(raw);
    match numeric(&candidate) {
        Some(exponent) if exponent <= 52.0 => crate::plistjs::js_number(2f64.powf(exponent)),
        _ => Value::Null,
    }
}

fn opt_number(value: Option<f64>) -> Value {
    value.map(crate::plistjs::js_number).unwrap_or(Value::Null)
}

fn opt_string(value: Option<String>) -> Value {
    value.map(Value::String).unwrap_or(Value::Null)
}

fn strip_offset_suffix(value: Option<String>) -> String {
    match value {
        None => "unknown".to_string(),
        Some(text) => {
            static CELL: OnceLock<Regex> = OnceLock::new();
            let pattern = CELL.get_or_init(|| Regex::new(r"\s+\(offset\s+\d+\)$").unwrap());
            pattern.replace(&text, "").into_owned()
        }
    }
}

/// Result of parsing `otool -h -l` text.
pub struct ParsedLoadCommands {
    pub file_type: Option<String>,
    pub flags: Vec<String>,
    pub uuid: Option<String>,
    pub commands: Vec<Value>,
    pub segments: Vec<Value>,
    pub dependencies: Vec<Value>,
    pub entrypoints: Vec<Value>,
    pub builds: Vec<Value>,
    /// Kinds seen, for the thread-entrypoint determination.
    pub kinds: Vec<String>,
}

pub fn parse_otool(raw: &str) -> ParsedLoadCommands {
    let output = raw.replace("\r\n", "\n");
    let header = parse_header(&output);
    let mut flags: Vec<String> = header.as_ref().map(|(_, flags)| flags.clone()).unwrap_or_default();
    let mut parsed = ParsedLoadCommands {
        file_type: header.as_ref().and_then(|(file_type, _)| file_type.clone()),
        flags: Vec::new(),
        uuid: None,
        commands: Vec::new(),
        segments: Vec::new(),
        dependencies: Vec::new(),
        entrypoints: Vec::new(),
        builds: Vec::new(),
        kinds: Vec::new(),
    };
    // Split before each line `Load command <n>`.
    let marker = Regex::new(r"(?m)^Load command \d+$").unwrap();
    let starts: Vec<usize> = marker.find_iter(&output).map(|m| m.start()).collect();
    let mut blocks: Vec<&str> = Vec::new();
    if starts.is_empty() {
        blocks.push(&output);
    } else {
        if starts[0] > 0 {
            blocks.push(&output[..starts[0]]);
        }
        for (i, start) in starts.iter().enumerate() {
            let end = starts.get(i + 1).copied().unwrap_or(output.len());
            blocks.push(&output[*start..end]);
        }
    }
    for block in blocks {
        parse_load_command(block, &mut parsed, &mut flags);
    }
    flags.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    flags.dedup();
    parsed.flags = flags;
    parsed
}

fn parse_header(output: &str) -> Option<(Option<String>, Vec<String>)> {
    let lines: Vec<&str> = output.split('\n').map(str::trim).collect();
    let magic = Regex::new(r"(?:^|\s)magic\s").unwrap();
    let columns_line = lines.iter().position(|line| magic.is_match(line))?;
    let columns: Vec<&str> = lines[columns_line].split_whitespace().collect();
    let data_line = lines[columns_line + 1..].iter().find(|line| !line.is_empty())?;
    let values: Vec<&str> = data_line.split_whitespace().collect();
    let file_type_index = columns.iter().position(|c| *c == "filetype");
    let flags_index = columns.iter().position(|c| *c == "flags");
    let complete = values.len() >= columns.len();
    let file_type_value_index: Option<usize> = match (flags_index, file_type_index) {
        (Some(flags), Some(file_type)) if file_type > flags => {
            (values.len() + file_type).checked_sub(columns.len())
        }
        (_, Some(file_type)) => Some(file_type),
        _ => None,
    };
    let flags_end: i64 = match flags_index {
        Some(flags) => values.len() as i64 - (columns.len() as i64 - flags as i64 - 1),
        None => 0,
    };
    let file_type = if complete {
        file_type_value_index.and_then(|i| values.get(i)).map(|v| v.to_string())
    } else {
        None
    };
    let flags: Vec<String> = match flags_index {
        Some(index) if complete && (index as i64) < flags_end => values[index..flags_end as usize]
            .iter()
            .filter(|v| !v.is_empty())
            .map(|v| v.to_string())
            .collect(),
        _ => Vec::new(),
    };
    Some((file_type, flags))
}

fn parse_load_command(block: &str, state: &mut ParsedLoadCommands, flags: &mut Vec<String>) {
    let _ = flags;
    static INDEX: OnceLock<Regex> = OnceLock::new();
    let index_pattern = INDEX.get_or_init(|| Regex::new(r"^Load command (\d+)").unwrap());
    let Some(captures) = index_pattern.captures(block) else { return };
    let index: u64 = captures.get(1).unwrap().as_str().parse().unwrap_or(0);
    static SECTION_SPLIT: OnceLock<Regex> = OnceLock::new();
    let section_split = SECTION_SPLIT.get_or_init(|| Regex::new(r"\n\s*Section\n").unwrap());
    let header = section_split.split(block).next().unwrap_or(block);
    let fields = parse_fields(header);
    let kind = string_field(&fields, "cmd").unwrap_or_else(|| "unknown".to_string());
    let mut field_map = Map::new();
    for (key, field) in &fields {
        field_map.insert(key.clone(), field_value(field));
    }
    state.commands.push(json!({"index": index, "kind": kind, "fields": Value::Object(field_map)}));
    state.kinds.push(kind.clone());
    if kind == "LC_UUID" {
        if let Some(uuid) = string_field(&fields, "uuid") {
            state.uuid = Some(uuid);
        }
    }
    if kind == "LC_MAIN" {
        if let Some(entry) = number_field(&fields, "entryoff") {
            state.entrypoints.push(json!({"file_offset": crate::plistjs::js_number(entry)}));
        }
    }
    collect_build(&kind, block, &fields, state);
    collect_dependency(&kind, &fields, state);
    if kind == "LC_SEGMENT" || kind == "LC_SEGMENT_64" {
        state.segments.push(parse_segment(block, &fields));
    }
}

fn collect_build(kind: &str, block: &str, fields: &Fields, state: &mut ParsedLoadCommands) {
    if kind == "LC_BUILD_VERSION" {
        state.builds.push(json!({
            "platform": opt_string(string_field(fields, "platform")),
            "minimum_os": opt_string(string_field(fields, "minos")),
            "sdk": opt_string(string_field(fields, "sdk")),
            "tools": parse_build_tools(block),
        }));
        return;
    }
    if let Some(platform) = kind.strip_prefix("LC_VERSION_MIN_") {
        state.builds.push(json!({
            "platform": if platform.is_empty() { Value::Null } else { Value::String(platform.to_string()) },
            "minimum_os": opt_string(string_field(fields, "version")),
            "sdk": opt_string(string_field(fields, "sdk")),
            "tools": [],
        }));
    }
}

fn collect_dependency(kind: &str, fields: &Fields, state: &mut ParsedLoadCommands) {
    if !kind.starts_with("LC_LOAD_") && kind != "LC_ID_DYLIB" && kind != "LC_REEXPORT_DYLIB" && kind != "LC_LAZY_LOAD_DYLIB" {
        return;
    }
    state.dependencies.push(json!({
        "path": strip_offset_suffix(string_field(fields, "name")),
        "kind": kind,
        "current_version": opt_string(string_field(fields, "current version")),
        "compatibility_version": opt_string(string_field(fields, "compatibility version")),
    }));
}

fn parse_segment(block: &str, fields: &Fields) -> Value {
    json!({
        "name": string_field(fields, "segname").unwrap_or_else(|| "unknown".to_string()),
        "vm_address": opt_string(hex_field(fields, "vmaddr")),
        "vm_size": opt_number(number_field(fields, "vmsize")),
        "file_offset": opt_number(number_field(fields, "fileoff")),
        "file_size": opt_number(number_field(fields, "filesize")),
        "maximum_permissions": permissions(string_field(fields, "maxprot")),
        "initial_permissions": permissions(string_field(fields, "initprot")),
        "sections": parse_sections(block),
    })
}

fn parse_sections(block: &str) -> Vec<Value> {
    // Split before every `\n<ws>Section\n`, keeping the delimiter with the following part.
    static CELL: OnceLock<Regex> = OnceLock::new();
    let delimiter = CELL.get_or_init(|| Regex::new(r"\n\s*Section\n").unwrap());
    let starts: Vec<usize> = delimiter.find_iter(block).map(|m| m.start()).collect();
    let mut sections = Vec::new();
    for (i, start) in starts.iter().enumerate() {
        let end = starts.get(i + 1).copied().unwrap_or(block.len());
        let section_block = &block[*start..end];
        let fields = parse_fields(&format!("Section{section_block}"));
        let flags: Vec<Value> = string_field(&fields, "flags")
            .unwrap_or_default()
            .split_whitespace()
            .map(|f| Value::String(f.to_string()))
            .collect();
        sections.push(json!({
            "segment": string_field(&fields, "segname").unwrap_or_else(|| "unknown".to_string()),
            "name": string_field(&fields, "sectname").unwrap_or_else(|| "unknown".to_string()),
            "address": opt_string(hex_field(&fields, "addr")),
            "size": opt_number(number_field(&fields, "size")),
            "file_offset": opt_number(number_field(&fields, "offset")),
            "alignment": section_alignment(string_field(&fields, "align")),
            "flags": flags,
        }));
    }
    sections
}

fn parse_build_tools(block: &str) -> Vec<Value> {
    let lines: Vec<&str> = block.split('\n').map(str::trim).collect();
    let tool = Regex::new(r"^tool\s+(.+)$").unwrap();
    let version = Regex::new(r"^version\s+(.+)$").unwrap();
    let mut tools = Vec::new();
    for index in 0..lines.len().saturating_sub(1) {
        let name = tool.captures(lines[index]).map(|c| c.get(1).unwrap().as_str().to_string());
        let ver = version.captures(lines[index + 1]).map(|c| c.get(1).unwrap().as_str().to_string());
        if let (Some(name), Some(ver)) = (name, ver) {
            tools.push(json!({"name": name, "version": ver}));
        }
    }
    tools
}
