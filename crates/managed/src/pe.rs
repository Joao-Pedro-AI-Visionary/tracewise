//! PE and CLI header reader (REA `ManagedPeReader`).

use crate::common::{failure, Buf, Failure, Issue, R};

#[derive(Debug, Clone, Copy)]
pub struct PeSection {
    pub virtual_address: i64,
    pub virtual_size: i64,
    pub raw_offset: i64,
    pub raw_size: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct PeDataDirectory {
    pub rva: i64,
    pub size: i64,
}

#[derive(Debug, Clone)]
pub struct CliHeader {
    pub header_offset: i64,
    pub header_size: i64,
    pub runtime_major: u16,
    pub runtime_minor: u16,
    pub metadata: PeDataDirectory,
    pub flags: u32,
    pub entry_point: u32,
    pub resources: PeDataDirectory,
    pub strong_name: PeDataDirectory,
    pub managed_native_header: PeDataDirectory,
    pub ready_to_run_signature: bool,
}

pub struct PeLayout<'a> {
    bytes: Buf<'a>,
    pub machine: u16,
    pub architecture: &'static str,
    pub optional_header: &'static str,
    pub section_count: u16,
    pub characteristics: u16,
    pub sections: Vec<PeSection>,
    pub cli: Option<CliHeader>,
    pub cli_directory_present: bool,
    pub cli_issue: Option<Issue>,
}

struct Coff {
    coff: i64,
    machine: u16,
    section_count: u16,
    optional_size: u16,
    characteristics: u16,
}

struct Optional {
    optional_offset: i64,
    optional_header: &'static str,
    directory_count_offset: i64,
    directory_offset: i64,
}

fn require_range(bytes: &Buf, offset: i64, length: i64, scope: &str) -> R<()> {
    if offset < 0 || length < 0 || offset > bytes.len() - length {
        return Err(failure(
            "invalid-directory",
            scope,
            format!("{scope} leaves the artifact byte range"),
            if offset >= 0 { Some(offset) } else { None },
        ));
    }
    Ok(())
}

fn add(left: i64, right: i64, scope: &str) -> R<i64> {
    match left.checked_add(right) {
        Some(sum) if sum >= left && sum <= (1i64 << 53) => Ok(sum),
        _ => Err(failure(
            "invalid-directory",
            scope,
            format!("{scope} offset arithmetic overflowed"),
            Some(left),
        )),
    }
}

fn architecture_for(machine: u16) -> R<&'static str> {
    match machine {
        0x014c => Ok("x86"),
        0x8664 => Ok("x86_64"),
        0x01c0 | 0x01c2 | 0x01c4 => Ok("arm"),
        0xaa64 => Ok("arm64"),
        other => Err(failure(
            "invalid-directory",
            "pe.machine",
            format!("Unsupported PE machine 0x{other:04x}"),
            None,
        )),
    }
}

struct Resolved {
    offset: i64,
    available: i64,
}

fn mapped_size(section: &PeSection) -> i64 {
    section.virtual_size.max(section.raw_size)
}

/// Resolve one section identity for both exact reads and available-byte queries.
fn resolve_rva(bytes: &Buf, sections: &[PeSection], rva: i64, size: i64, scope: &str) -> R<Resolved> {
    if rva < 0 || size < 0 || rva > 0xffff_ffff || (size > 0 && size > 0x1_0000_0000 - rva) {
        return Err(failure("invalid-directory", scope, format!("{scope} has an invalid RVA range"), None));
    }
    let selected = sections.iter().position(|section| {
        let within = rva - section.virtual_address;
        let mapped = mapped_size(section);
        mapped > 0 && within >= 0 && within <= mapped && size <= mapped - within
    });
    let Some(selected_index) = selected else {
        return Err(failure(
            "invalid-directory",
            scope,
            format!("{scope} RVA is not covered by one PE section"),
            None,
        ));
    };
    let selected = sections[selected_index];
    for (index, section) in sections.iter().enumerate() {
        if index == selected_index || mapped_size(section) == 0 {
            continue;
        }
        let end = section.virtual_address + mapped_size(section);
        let intersects = if size == 0 {
            rva >= section.virtual_address && rva < end
        } else {
            rva < end && rva + size > section.virtual_address
        };
        if intersects {
            return Err(failure(
                "invalid-directory",
                scope,
                format!("{scope} RVA range has ambiguous overlapping PE section mappings"),
                None,
            ));
        }
    }
    let within = rva - selected.virtual_address;
    if within > selected.raw_size || size > selected.raw_size - within {
        return Err(failure(
            "invalid-directory",
            scope,
            format!("{scope} occupies virtual bytes without file-backed data"),
            None,
        ));
    }
    let offset = add(selected.raw_offset, within, scope)?;
    require_range(bytes, offset, size, scope)?;
    let mut available = (selected.raw_size - within).min(bytes.len() - offset).min(0x1_0000_0000 - rva);
    // A future overlap ends the uniquely mapped extent even if the current byte is unique.
    for (index, section) in sections.iter().enumerate() {
        if index != selected_index && section.virtual_address > rva && mapped_size(section) > 0 {
            available = available.min(section.virtual_address - rva);
        }
    }
    Ok(Resolved { offset, available })
}

fn map_rva(bytes: &Buf, sections: &[PeSection], rva: i64, size: i64, scope: &str) -> R<i64> {
    if rva == 0 && size == 0 {
        Ok(0)
    } else {
        Ok(resolve_rva(bytes, sections, rva, size, scope)?.offset)
    }
}

fn read_directory(bytes: &Buf, offset: i64) -> R<PeDataDirectory> {
    require_range(bytes, offset, 8, "pe.data-directory")?;
    Ok(PeDataDirectory { rva: bytes.u32(offset)? as i64, size: bytes.u32(offset + 4)? as i64 })
}

fn read_cli_header(bytes: &Buf, sections: &[PeSection], directory: PeDataDirectory) -> R<CliHeader> {
    if directory.size < 72 {
        return Err(failure("invalid-cli-header", "cli.header", "CLI header is shorter than the required 72 bytes", None));
    }
    let offset = map_rva(bytes, sections, directory.rva, 72, "cli.header")?;
    let header_size = bytes.u32(offset)? as i64;
    if header_size < 72 || header_size > directory.size {
        return Err(failure(
            "invalid-cli-header",
            "cli.header",
            "CLI header size is outside its PE data directory",
            Some(offset),
        ));
    }
    let metadata = read_directory(bytes, offset + 8)?;
    if metadata.rva == 0 || metadata.size == 0 {
        return Err(failure("invalid-cli-header", "cli.metadata", "CLI metadata directory is absent", Some(offset + 8)));
    }
    let flags = bytes.u32(offset + 16)?;
    let managed_native_header = read_directory(bytes, offset + 64)?;
    let mut ready_to_run_signature = false;
    if managed_native_header.rva != 0 && managed_native_header.size >= 4 {
        let native_offset = map_rva(bytes, sections, managed_native_header.rva, 4, "cli.managed-native-header")?;
        ready_to_run_signature = bytes.u32(native_offset)? == 0x0052_5452;
    }
    Ok(CliHeader {
        header_offset: offset,
        header_size,
        runtime_major: bytes.u16(offset + 4)?,
        runtime_minor: bytes.u16(offset + 6)?,
        metadata,
        flags,
        entry_point: bytes.u32(offset + 20)?,
        resources: read_directory(bytes, offset + 24)?,
        strong_name: read_directory(bytes, offset + 32)?,
        managed_native_header,
        ready_to_run_signature,
    })
}

fn read_coff(bytes: &Buf) -> R<Coff> {
    let pe_offset = bytes.u32(0x3c)? as i64;
    require_range(bytes, pe_offset, 24, "pe.coff-header")?;
    if bytes.u32(pe_offset)? != 0x0000_4550 {
        return Err(failure("invalid-directory", "pe.signature", "PE signature is invalid", Some(pe_offset)));
    }
    let coff = pe_offset + 4;
    let machine = bytes.u16(coff)?;
    let section_count = bytes.u16(coff + 2)?;
    if section_count == 0 {
        return Err(failure("invalid-directory", "pe.sections", "PE section count must be positive", Some(coff + 2)));
    }
    Ok(Coff {
        coff,
        machine,
        section_count,
        optional_size: bytes.u16(coff + 16)?,
        characteristics: bytes.u16(coff + 18)?,
    })
}

fn read_optional(bytes: &Buf, coff: &Coff) -> R<Optional> {
    let optional_offset = coff.coff + 20;
    require_range(bytes, optional_offset, coff.optional_size as i64, "pe.optional-header")?;
    if coff.optional_size < 96 {
        return Err(failure(
            "invalid-directory",
            "pe.optional-header",
            "PE optional header is too short",
            Some(optional_offset),
        ));
    }
    let magic = bytes.u16(optional_offset)?;
    let optional_header = match magic {
        0x010b => "pe32",
        0x020b => "pe32-plus",
        _ => {
            return Err(failure(
                "invalid-directory",
                "pe.optional-header",
                "PE optional header magic is unsupported",
                Some(optional_offset),
            ))
        }
    };
    Ok(Optional {
        optional_offset,
        optional_header,
        directory_count_offset: optional_offset + if optional_header == "pe32" { 92 } else { 108 },
        directory_offset: optional_offset + if optional_header == "pe32" { 96 } else { 112 },
    })
}

fn read_sections(bytes: &Buf, coff: &Coff, optional: &Optional) -> R<Vec<PeSection>> {
    let section_offset = add(optional.optional_offset, coff.optional_size as i64, "pe.sections")?;
    require_range(bytes, section_offset, coff.section_count as i64 * 40, "pe.sections")?;
    let mut sections = Vec::new();
    for index in 0..coff.section_count as i64 {
        let offset = section_offset + index * 40;
        let section = PeSection {
            virtual_size: bytes.u32(offset + 8)? as i64,
            virtual_address: bytes.u32(offset + 12)? as i64,
            raw_size: bytes.u32(offset + 16)? as i64,
            raw_offset: bytes.u32(offset + 20)? as i64,
        };
        if section.raw_size > 0 {
            require_range(bytes, section.raw_offset, section.raw_size, "pe.section-data")?;
        }
        sections.push(section);
    }
    Ok(sections)
}

fn read_cli_directory(bytes: &Buf, coff: &Coff, optional: &Optional) -> R<PeDataDirectory> {
    require_range(bytes, optional.directory_count_offset, 4, "pe.data-directories")?;
    let count = bytes.u32(optional.directory_count_offset)?;
    if count <= 14 || (coff.optional_size as i64) < optional.directory_offset - optional.optional_offset + 120 {
        return Ok(PeDataDirectory { rva: 0, size: 0 });
    }
    read_directory(bytes, optional.directory_offset + 14 * 8)
}

/// Parse the file-backed PE and CLI layout without loading target code.
pub fn read_pe_layout<'a>(bytes: &'a [u8]) -> R<PeLayout<'a>> {
    let buf = Buf(bytes);
    require_range(&buf, 0, 64, "pe.dos-header")?;
    if bytes[0] != 0x4d || bytes[1] != 0x5a {
        return Err(failure("invalid-directory", "pe.dos-header", "Artifact does not start with an MZ header", Some(0)));
    }
    let coff = read_coff(&buf)?;
    let optional = read_optional(&buf, &coff)?;
    let sections = read_sections(&buf, &coff, &optional)?;
    let cli_directory = read_cli_directory(&buf, &coff, &optional)?;
    let cli_directory_present = cli_directory.rva != 0 || cli_directory.size != 0;
    let mut cli = None;
    let mut cli_issue = None;
    if cli_directory_present {
        match read_cli_header(&buf, &sections, cli_directory) {
            Ok(header) => cli = Some(header),
            Err(Failure::Reader(issue)) => cli_issue = Some(issue),
            Err(other) => return Err(other),
        }
    }
    Ok(PeLayout {
        bytes: buf,
        machine: coff.machine,
        architecture: architecture_for(coff.machine)?,
        optional_header: optional.optional_header,
        section_count: coff.section_count,
        characteristics: coff.characteristics,
        sections,
        cli,
        cli_directory_present,
        cli_issue,
    })
}

impl<'a> PeLayout<'a> {
    pub fn rva_to_offset(&self, rva: i64, size: i64, scope: &str) -> R<i64> {
        map_rva(&self.bytes, &self.sections, rva, size, scope)
    }

    pub fn rva_available_bytes(&self, rva: i64, scope: &str) -> R<i64> {
        Ok(resolve_rva(&self.bytes, &self.sections, rva, 1, scope)?.available)
    }
}
