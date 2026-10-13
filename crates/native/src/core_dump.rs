//! `inspect_recorded_crash`: Linux x86-64 ELF core recording (port of REA
//! `bridge/pwntools/recorded_crash_impl.py`, which wraps pyelftools 0.33 and the
//! pwntools `elf_prstatus_amd64` / `elf_siginfo_64` ctypes layouts).
//!
//! Nothing is launched or attached: segments, raw notes and the Linux `CORE`
//! `NT_PRSTATUS` / `NT_SIGINFO` interpretations are decoded from the file bytes.

use base64::Engine;
use serde_json::{json, Value};

use crate::elf_layout::{enums_p_type, enums_core_note, le16, le32, le64, walk};

pub struct CoreFailure {
    pub reason: &'static str,
    pub message: String,
}

type R<T> = Result<T, CoreFailure>;

fn fail<T>(reason: &'static str, message: impl Into<String>) -> R<T> {
    Err(CoreFailure {
        reason,
        message: message.into(),
    })
}

fn upstream<T>(message: impl AsRef<str>) -> R<T> {
    fail(
        "format",
        format!(
            "Recorded core failed unchanged upstream structural parsing: {}",
            message.as_ref()
        ),
    )
}

fn hex(value: u64) -> String {
    format!("0x{value:x}")
}

fn encoded(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn location(offset: u64, size: u64, limit: u64) -> R<Value> {
    if offset > limit || size > limit - offset {
        return fail("format", "Recorded source range exceeds its declared container.");
    }
    Ok(json!({"offset": hex(offset), "bytes": hex(size)}))
}

/// Complete register identities in the supported Linux amd64 PRSTATUS ABI order.
pub const LINUX_AMD64_REGISTERS: [&str; 27] = [
    "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi",
    "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs",
];
const PR_REG_OFFSET: u64 = 112;
const PRSTATUS_SIZE: usize = 336;
const SIGINFO_SIZE: usize = 32;

/// Honest statement of how the core was decoded (replaces REA's Python resource-limit sentence).
pub const IN_PROCESS_LIMITATION: &str = "The core was decoded in-process by the Rust port of the pwntools 4.15.0/pyelftools 0.33 adapter. GDB/pwndbg mapping candidates (include_debugger_context) are not provided by this port.";

pub struct CoreReport {
    /// The decoder payload (everything but artifact, debugger and diagnostics).
    pub payload: Value,
}

pub fn inspect_core(content: &[u8]) -> R<CoreReport> {
    if content.len() < 16 || &content[..4] != b"\x7fELF" {
        return fail("format", "Selected recording lacks a complete ELF identification.");
    }
    if content[4] != 2 || content[5] != 1 {
        return fail("unsupported-target", "Initial recorded-core profile requires ELF64 little-endian.");
    }
    if content.len() < 64 {
        return fail("format", "Selected ELF64 core header is truncated.");
    }
    if content[6] != 1 {
        return fail("format", "ELF identification version is not EV_CURRENT.");
    }
    if le32(content, 20) != 1 {
        return fail("format", "ELF header version is not EV_CURRENT.");
    }
    if (content[7] != 0 && content[7] != 3) || content[8] != 0 {
        return fail(
            "unsupported-target",
            format!(
                "Initial recorded-core profile requires System V or GNU/Linux OSABI with ABI version zero; selected OSABI={}, ABI version={}.",
                content[7], content[8]
            ),
        );
    }
    if le16(content, 16) != 4 || le16(content, 18) != 62 {
        return fail("unsupported-target", "Initial recorded-core profile requires x86-64 ET_CORE.");
    }
    let length = content.len() as u64;
    let e_phoff = le64(content, 32);
    let e_shoff = le64(content, 40);
    let e_phentsize = u64::from(le16(content, 54));
    let e_phnum = le16(content, 56);
    let e_shentsize = u64::from(le16(content, 58));
    let count: u64 = if e_phnum < 0xffff {
        u64::from(e_phnum)
    } else {
        // Section header zero carries the real count in sh_info.
        if e_shoff > 0 && e_shentsize < 64 {
            return upstream(format!("Too small e_shentsize: {e_shentsize}"));
        }
        if e_shoff > length {
            return upstream(format!("Reading section 0 at offset {e_shoff} past EOF {length}"));
        }
        walk(content, e_shoff, &[4, 4, 8, 8, 8, 8, 4, 4, 8, 8]).or_else(upstream)?;
        u64::from(le32(content, e_shoff as usize + 44))
    };
    if count > 0 && e_phentsize < 56 {
        return fail("format", "Program-header entry is shorter than the required ELF64 structure.");
    }
    location(e_phoff, count.saturating_mul(e_phentsize), length)?;
    let p_type = enums_p_type();
    let note_type = enums_core_note();
    let mut segments: Vec<Value> = Vec::new();
    let mut notes: Vec<Value> = Vec::new();
    let mut padding: Vec<Value> = Vec::new();
    let mut threads: Vec<Value> = Vec::new();
    let mut signals: Vec<Value> = Vec::new();
    for segment_index in 0..count {
        let at = e_phoff.saturating_add(segment_index.saturating_mul(e_phentsize));
        if let Err(message) = walk(content, at, &[4, 4, 8, 8, 8, 8, 8, 8]) {
            return upstream(message);
        }
        let at = at as usize;
        let kind_value = le32(content, at);
        let p_offset = le64(content, at + 8);
        let p_vaddr = le64(content, at + 16);
        let p_paddr = le64(content, at + 24);
        let p_filesz = le64(content, at + 32);
        let p_memsz = le64(content, at + 40);
        let p_align = le64(content, at + 48);
        let p_flags = u64::from(le32(content, at + 4));
        let kind = p_type.name(i64::from(kind_value)).unwrap_or("");
        let backing = kind != "PT_NULL" && p_filesz > 0;
        if backing {
            location(p_offset, p_filesz, length)?;
        }
        if kind == "PT_LOAD" && p_filesz > p_memsz {
            return fail("format", "Recorded PT_LOAD file bytes exceed memory size.");
        }
        segments.push(json!({
            "index": segment_index,
            "type": p_type.scalar(i64::from(kind_value)),
            "header_location": location(
                e_phoff + segment_index * e_phentsize,
                e_phentsize,
                length,
            )?,
            "offset": hex(p_offset),
            "file_size": hex(p_filesz),
            "memory_size": hex(p_memsz),
            "virtual_address": hex(p_vaddr),
            "physical_address": hex(p_paddr),
            "alignment": hex(p_align),
            "flags": hex(p_flags),
            "file_backing": if backing { "file" } else { "none" },
        }));
        if kind != "PT_NOTE" || p_filesz == 0 {
            continue;
        }
        let mut position = p_offset;
        let end = p_offset + p_filesz;
        while position < end {
            if end - position < 12 {
                let raw = &content[position as usize..end as usize];
                if raw.iter().any(|b| *b != 0) {
                    return fail("format", "Nonzero trailing note bytes lack a complete note header.");
                }
                padding.push(json!({
                    "segment_index": segment_index,
                    "location": location(position, raw.len() as u64, end)?,
                    "bytes_base64": encoded(raw),
                }));
                break;
            }
            if let Err(message) = walk(content, position, &[4, 4, 4]) {
                return upstream(message);
            }
            let namesz = u64::from(le32(content, position as usize));
            let descsz = u64::from(le32(content, position as usize + 4));
            let type_raw = le32(content, position as usize + 8);
            let owner_start = position + 12;
            let descriptor_start = owner_start + namesz.div_ceil(4) * 4;
            let note_end = descriptor_start + descsz.div_ceil(4) * 4;
            location(position, note_end - position, end)?;
            let owner = &content[owner_start as usize..((owner_start + namesz) as usize).min(content.len())];
            if !owner.is_empty() && !owner.contains(&0) {
                return fail("format", "Declared note owner has no NUL terminator.");
            }
            let display: Value = if owner.is_empty() {
                Value::Null
            } else {
                let first = owner.split(|b| *b == 0).next().unwrap_or(&[]);
                Value::String(String::from_utf8_lossy(first).into_owned())
            };
            let descriptor_end = ((descriptor_start + descsz) as usize).min(content.len());
            let descriptor = &content[(descriptor_start as usize).min(content.len())..descriptor_end];
            let note_index = notes.len();
            notes.push(json!({
                "index": note_index,
                "segment_index": segment_index,
                "type": note_type.scalar(i64::from(type_raw)),
                "location": location(position, note_end - position, end)?,
                "owner_location": location(owner_start, owner.len() as u64, end)?,
                "owner_bytes_base64": encoded(owner),
                "owner_display": display,
                "descriptor_location": location(descriptor_start, descriptor.len() as u64, end)?,
                "descriptor_bytes_base64": encoded(descriptor),
            }));
            position = note_end;
            // Only the initial Linux CORE ABI is interpreted. Other owners retain exact bytes.
            if owner != b"CORE\0" {
                continue;
            }
            match note_type.name(i64::from(type_raw)) {
                Some("NT_PRSTATUS") => {
                    if descriptor.len() < PRSTATUS_SIZE {
                        return fail("format", "Linux amd64 NT_PRSTATUS descriptor is truncated.");
                    }
                    let mut registers: Vec<Value> = Vec::new();
                    for (position_in_abi, name) in LINUX_AMD64_REGISTERS.iter().enumerate() {
                        let relative = PR_REG_OFFSET + position_in_abi as u64 * 8;
                        registers.push(json!({
                            "name": name,
                            "value": hex(le64(descriptor, relative as usize)),
                            "location": location(descriptor_start + relative, 8, end)?,
                        }));
                    }
                    threads.push(json!({
                        "note_index": note_index,
                        "historical_pid": le32(descriptor, 32) as i32,
                        "recorded_current_signal": le16(descriptor, 12) as i16,
                        "registers": registers,
                    }));
                }
                Some("NT_SIGINFO") => {
                    if descriptor.len() < SIGINFO_SIZE {
                        return fail("format", "Linux amd64 NT_SIGINFO descriptor is truncated.");
                    }
                    let number = le32(descriptor, 0) as i32;
                    let errno = le32(descriptor, 4) as i32;
                    let code = le32(descriptor, 8) as i32;
                    let known = number == 11 && (code == 1 || code == 2);
                    signals.push(json!({
                        "note_index": note_index,
                        "number": number,
                        "code": code,
                        "errno": errno,
                        "fault_address": if known { Value::String(hex(le64(descriptor, 16))) } else { Value::Null },
                        "fault_address_meaning": if known { "recorded-sigsegv-address" } else { "unknown" },
                        "thread_association": "unknown",
                    }));
                }
                _ => {}
            }
        }
    }
    Ok(CoreReport {
        payload: json!({
            "format": "elf-core",
            "architecture": "x86_64-little-endian",
            "target_execution": "not-performed",
            "live_process_identity": "unknown",
            "segments": segments,
            "notes": notes,
            "note_padding": padding,
            "threads": threads,
            "signals": signals,
            "note_interpretation_completeness": "unknown",
            "limitations": [
                "The initial Linux note profile accepts System V/unspecified or GNU/Linux OSABI with ABI version zero; an unspecified OSABI alone does not prove operating-system origin.",
                "Historical PID and signal values are recorded metadata, not current process identity or attach authority.",
                "Only exact Linux CORE NT_PRSTATUS/NT_SIGINFO owners are interpreted; every descriptor and owner retains original bytes. Other note semantics remain unknown.",
                "NT_SIGINFO thread association is unknown. Only SIGSEGV SEGV_MAPERR/SEGV_ACCERR initially establish a fault-address union meaning.",
                "PT_LOAD file bytes are recorded bytes. Undumped memory and current executable/library identity remain unknown; no current host file is resolved from a recorded pathname.",
                "Missing notes/registers/signals do not establish their absence at the original crash. Full unwinding, executable pairing and live control are not provided.",
                IN_PROCESS_LIMITATION,
            ],
        }),
    })
}
