//! Dylib-loading facts of Mach-O images (port of REA `MachoLoadCommandReader.ts`
//! and `domain/apple/machoContainer.ts`). Headers and load commands only; no
//! code is read or executed.

use serde::Serialize;

/// Read `length` bytes at `offset`; shorter results mean end of file.
pub trait ReadAt {
    fn read_at(&self, offset: u64, length: usize) -> std::io::Result<Vec<u8>>;
}

impl ReadAt for [u8] {
    fn read_at(&self, offset: u64, length: usize) -> std::io::Result<Vec<u8>> {
        let start = (offset as usize).min(self.len());
        let end = start.saturating_add(length).min(self.len());
        Ok(self[start..end].to_vec())
    }
}

impl ReadAt for std::fs::File {
    fn read_at(&self, offset: u64, length: usize) -> std::io::Result<Vec<u8>> {
        use std::os::unix::fs::FileExt;
        let mut buffer = vec![0u8; length];
        let mut filled = 0usize;
        while filled < length {
            let count = FileExt::read_at(self, &mut buffer[filled..], offset + filled as u64)?;
            if count == 0 {
                break;
            }
            filled += count;
        }
        buffer.truncate(filled);
        Ok(buffer)
    }
}

pub const MAX_LOAD_COMMAND_BYTES: u64 = 16 * 1024 * 1024;
const MAX_FAT_ARCHITECTURES: u32 = 128;
const KNOWN_CPU_TYPES: [u32; 7] = [7, 0x0100_0007, 12, 0x0100_000c, 0x0200_000c, 18, 0x0100_0012];

pub const MH_MAGIC: u32 = 0xfeed_face;
pub const MH_MAGIC_64: u32 = 0xfeed_facf;
pub const MH_CIGAM: u32 = 0xcefa_edfe;
pub const MH_CIGAM_64: u32 = 0xcffa_edfe;
pub const FAT_MAGIC: u32 = 0xcafe_babe;
pub const FAT_MAGIC_64: u32 = 0xcafe_babf;
pub const FAT_CIGAM: u32 = 0xbeba_feca;
pub const FAT_CIGAM_64: u32 = 0xbfba_feca;

const LC_ID_DYLIB: u32 = 0xd;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000_0023;
const LC_RPATH: u32 = 0x8000_001c;
const LC_DYLD_ENVIRONMENT: u32 = 0x27;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_VERSION_MIN_MACOSX: u32 = 0x24;
const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
const LC_VERSION_MIN_TVOS: u32 = 0x2f;
const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
const LC_BUILD_VERSION: u32 = 0x32;

const PLATFORM_MACOS: u32 = 1;
const PLATFORM_IOS: u32 = 2;
const PLATFORM_TVOS: u32 = 3;
const PLATFORM_WATCHOS: u32 = 4;
const PLATFORM_IOSSIMULATOR: u32 = 7;
const PLATFORM_TVOSSIMULATOR: u32 = 8;
const PLATFORM_WATCHOSSIMULATOR: u32 = 9;

const CPU_TYPE_I386: u32 = 7;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;

const DYLIB_USE_MARKER: u32 = 0x1a74_1800;
const DYLIB_USE_WEAK_LINK: u32 = 0x1;
const DYLIB_USE_REEXPORT: u32 = 0x2;
const DYLIB_USE_UPWARD: u32 = 0x4;
const DYLIB_USE_DELAYED_INIT: u32 = 0x8;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MachoDependency {
    pub command: &'static str,
    pub encoding: &'static str,
    pub install_name: String,
    pub weak: bool,
    pub upward: bool,
    pub reexport: bool,
    pub delayed_init: bool,
    pub current_version: String,
    pub compatibility_version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MachoSlice {
    pub architecture: String,
    pub slice_offset: u64,
    pub slice_size: u64,
    pub cpu_type: u32,
    pub cpu_subtype: u32,
    pub fat_cpu_type: Option<u32>,
    pub fat_cpu_subtype: Option<u32>,
    pub fat_alignment_exponent: Option<u32>,
    pub file_type: &'static str,
    pub file_type_code: u32,
    pub platform: Option<u32>,
    pub platforms: Vec<u32>,
    pub install_name: Option<String>,
    pub dependencies: Vec<MachoDependency>,
    pub rpaths: Vec<String>,
    pub dyld_environment: Vec<String>,
    pub code_signature_present: bool,
}

/// Header parse of one file; malformed and unsupported images keep their reason.
#[derive(Debug, Clone, PartialEq)]
pub enum ImageFacts {
    Parsed(Vec<MachoSlice>),
    Malformed(String),
    Unsupported(String),
    NotMachO,
}

enum Issue {
    Malformed(String),
    Unsupported(String),
    Io(std::io::Error),
}

impl From<std::io::Error> for Issue {
    fn from(error: std::io::Error) -> Self {
        Issue::Io(error)
    }
}

fn malformed(message: impl Into<String>) -> Issue {
    Issue::Malformed(message.into())
}

fn be32(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn rd32(bytes: &[u8], at: usize, little: bool) -> u32 {
    let word = [bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]];
    if little {
        u32::from_le_bytes(word)
    } else {
        u32::from_be_bytes(word)
    }
}

fn rd64(bytes: &[u8], at: usize, little: bool) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    if little {
        u64::from_le_bytes(word)
    } else {
        u64::from_be_bytes(word)
    }
}

/// Report whether the first bytes carry a Mach-O or FAT magic number.
pub fn has_macho_magic(head: &[u8]) -> bool {
    if head.len() < 4 {
        return false;
    }
    matches!(
        be32(head, 0),
        MH_MAGIC | MH_MAGIC_64 | MH_CIGAM | MH_CIGAM_64 | FAT_MAGIC | FAT_MAGIC_64 | FAT_CIGAM | FAT_CIGAM_64
    )
}

/// One entry of a FAT architecture table.
#[derive(Debug, Clone, Copy)]
pub struct FatSliceDeclaration {
    pub index: usize,
    pub offset: u64,
    pub size: u64,
    pub alignment_exponent: u32,
    pub cpu_type: u32,
    pub cpu_subtype: u32,
}

pub fn read_fat_slice_declarations(
    table: &[u8],
    count: usize,
    wide: bool,
    little_endian: bool,
) -> Result<Vec<FatSliceDeclaration>, String> {
    let entry_size = if wide { 32 } else { 20 };
    if table.len() < count * entry_size {
        return Err("FAT table is truncated".to_string());
    }
    let mut slices = Vec::with_capacity(count);
    for index in 0..count {
        let base = index * entry_size;
        let (offset, size) = if wide {
            (rd64(table, base + 8, little_endian), rd64(table, base + 16, little_endian))
        } else {
            (
                u64::from(rd32(table, base + 8, little_endian)),
                u64::from(rd32(table, base + 12, little_endian)),
            )
        };
        if offset > 9_007_199_254_740_991 || size > 9_007_199_254_740_991 {
            return Err("FAT offset or size exceeds the safe range".to_string());
        }
        slices.push(FatSliceDeclaration {
            index,
            offset,
            size,
            alignment_exponent: rd32(table, base + if wide { 24 } else { 16 }, little_endian),
            cpu_type: rd32(table, base, little_endian),
            cpu_subtype: rd32(table, base + 4, little_endian),
        });
    }
    Ok(slices)
}

pub fn validate_fat_slice(
    declaration: &FatSliceDeclaration,
    container_size: u64,
    table_end: u64,
    embedded: Option<(u32, u32)>,
) -> Option<String> {
    let FatSliceDeclaration {
        index,
        offset,
        size,
        alignment_exponent,
        cpu_type,
        cpu_subtype,
    } = *declaration;
    if size == 0 || offset < table_end {
        return Some(format!("FAT architecture {index} has an invalid slice range"));
    }
    if offset > container_size || size > container_size - offset {
        return Some(format!("FAT architecture {index} slice range extends beyond the file"));
    }
    if alignment_exponent > 52 {
        return Some(format!(
            "FAT architecture {index} alignment exponent {alignment_exponent} is unsupported"
        ));
    }
    if offset % (1u64 << alignment_exponent) != 0 {
        return Some(format!(
            "FAT architecture {index} offset is not aligned to 2^{alignment_exponent}"
        ));
    }
    if let Some((embedded_type, embedded_subtype)) = embedded {
        if embedded_type != cpu_type || embedded_subtype != cpu_subtype {
            return Some(format!(
                "FAT architecture {index} CPU type/subtype disagrees with its Mach-O header"
            ));
        }
    }
    None
}

fn legacy_version_min_platform(command: u32, cpu_type: u32) -> Option<u32> {
    let is_intel = cpu_type == CPU_TYPE_I386 || cpu_type == CPU_TYPE_X86_64;
    match command {
        LC_VERSION_MIN_MACOSX => Some(PLATFORM_MACOS),
        LC_VERSION_MIN_IPHONEOS => Some(if is_intel { PLATFORM_IOSSIMULATOR } else { PLATFORM_IOS }),
        LC_VERSION_MIN_TVOS => Some(if cpu_type == CPU_TYPE_X86_64 {
            PLATFORM_TVOSSIMULATOR
        } else {
            PLATFORM_TVOS
        }),
        LC_VERSION_MIN_WATCHOS => Some(if is_intel {
            PLATFORM_WATCHOSSIMULATOR
        } else {
            PLATFORM_WATCHOS
        }),
        _ => None,
    }
}

/// Decode every slice's dylib-loading load commands without reading code.
pub fn read_macho_image(reader: &dyn ReadAt, size: u64) -> std::io::Result<ImageFacts> {
    match read_image_inner(reader, size) {
        Ok(facts) => Ok(facts),
        Err(Issue::Malformed(reason)) => Ok(ImageFacts::Malformed(reason)),
        Err(Issue::Unsupported(reason)) => Ok(ImageFacts::Unsupported(reason)),
        Err(Issue::Io(error)) => Err(error),
    }
}

fn read_image_inner(reader: &dyn ReadAt, size: u64) -> Result<ImageFacts, Issue> {
    let head = reader.read_at(0, size.min(8) as usize)?;
    if head.len() < 8 {
        return Ok(if has_macho_magic(&head) {
            ImageFacts::Malformed("Mach-O header is truncated".to_string())
        } else {
            ImageFacts::NotMachO
        });
    }
    let magic = be32(&head, 0);
    if matches!(magic, FAT_MAGIC | FAT_MAGIC_64 | FAT_CIGAM | FAT_CIGAM_64) {
        let little = magic == FAT_CIGAM || magic == FAT_CIGAM_64;
        let count = rd32(&head, 4, little);
        let wide = magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64;
        if count == 0 {
            return Ok(ImageFacts::Malformed("FAT header declares no architectures".to_string()));
        }
        let entry_size: u64 = if wide { 32 } else { 20 };
        if count > MAX_FAT_ARCHITECTURES || 8 + u64::from(count) * entry_size > size {
            return Ok(ImageFacts::NotMachO);
        }
        let table_end = 8 + u64::from(count) * entry_size;
        let table = read_exact(reader, 8, (u64::from(count) * entry_size) as usize, "FAT table")?;
        let declarations = read_fat_slice_declarations(&table, count as usize, wide, little)
            .map_err(Issue::Malformed)?;
        if !declarations.iter().any(|d| KNOWN_CPU_TYPES.contains(&d.cpu_type)) {
            let mut has_header = false;
            for declaration in &declarations {
                if validate_fat_slice(declaration, size, table_end, None).is_some() {
                    continue;
                }
                let bytes = reader.read_at(declaration.offset, 4)?;
                if bytes.len() < 4 {
                    continue;
                }
                if matches!(be32(&bytes, 0), MH_MAGIC | MH_MAGIC_64 | MH_CIGAM | MH_CIGAM_64) {
                    has_header = true;
                    break;
                }
            }
            if !has_header {
                return Ok(ImageFacts::NotMachO);
            }
        }
        let mut slices = Vec::new();
        for declaration in &declarations {
            if let Some(issue) = validate_fat_slice(declaration, size, table_end, None) {
                return Err(if issue.contains("unsupported") {
                    Issue::Unsupported(issue)
                } else {
                    Issue::Malformed(issue)
                });
            }
            let slice = read_slice(
                reader,
                declaration.offset,
                declaration.size,
                Some((declaration.cpu_type, declaration.cpu_subtype, declaration.alignment_exponent)),
            )?;
            if let Some(issue) =
                validate_fat_slice(declaration, size, table_end, Some((slice.cpu_type, slice.cpu_subtype)))
            {
                return Err(Issue::Malformed(issue));
            }
            slices.push(slice);
        }
        return Ok(ImageFacts::Parsed(slices));
    }
    if magic == MH_CIGAM || magic == MH_CIGAM_64 {
        return Ok(ImageFacts::Parsed(vec![read_slice(reader, 0, size, None)?]));
    }
    if magic == MH_MAGIC || magic == MH_MAGIC_64 {
        return Err(Issue::Unsupported("big-endian Mach-O images are not supported".to_string()));
    }
    Ok(ImageFacts::NotMachO)
}

fn read_exact(reader: &dyn ReadAt, offset: u64, length: usize, label: &str) -> Result<Vec<u8>, Issue> {
    let bytes = reader.read_at(offset, length)?;
    if bytes.len() < length {
        return Err(malformed(format!("{label} is truncated")));
    }
    Ok(bytes)
}

fn read_slice(
    reader: &dyn ReadAt,
    base: u64,
    length: u64,
    fat: Option<(u32, u32, u32)>,
) -> Result<MachoSlice, Issue> {
    let header = read_exact(reader, base, 28, "Mach-O header")?;
    let magic = rd32(&header, 0, true);
    if magic == MH_MAGIC_64 || magic == MH_MAGIC {
        let wide = magic == MH_MAGIC_64;
        let header_size: u64 = if wide { 32 } else { 28 };
        let command_count = rd32(&header, 16, true);
        let command_bytes = u64::from(rd32(&header, 20, true));
        if command_bytes > MAX_LOAD_COMMAND_BYTES {
            return Err(Issue::Unsupported(format!(
                "load commands occupy {command_bytes} bytes, above the {MAX_LOAD_COMMAND_BYTES}-byte limit"
            )));
        }
        if header_size + command_bytes > length {
            return Err(malformed("load commands extend beyond the Mach-O slice"));
        }
        let commands = read_exact(reader, base + header_size, command_bytes as usize, "load commands")?;
        let mut slice = decode_commands(
            &commands,
            wide,
            rd32(&header, 4, true),
            rd32(&header, 8, true),
            rd32(&header, 12, true),
            command_count,
            base,
            length,
            fat,
        )?;
        let mut distinct: Vec<u32> = Vec::new();
        for platform in &slice.platforms {
            if !distinct.contains(platform) {
                distinct.push(*platform);
            }
        }
        slice.platform = if distinct.len() == 1 { Some(distinct[0]) } else { None };
        return Ok(slice);
    }
    if magic == MH_MAGIC.swap_bytes() || magic == MH_MAGIC_64.swap_bytes() {
        return Err(Issue::Unsupported("big-endian Mach-O slices are not supported".to_string()));
    }
    Err(malformed(format!("slice at offset {base} has no Mach-O header")))
}

#[allow(clippy::too_many_arguments)]
fn decode_commands(
    bytes: &[u8],
    wide: bool,
    cpu_type: u32,
    cpu_subtype: u32,
    file_type: u32,
    command_count: u32,
    slice_offset: u64,
    slice_size: u64,
    fat: Option<(u32, u32, u32)>,
) -> Result<MachoSlice, Issue> {
    let alignment = if wide { 8 } else { 4 };
    let mut slice = MachoSlice {
        architecture: architecture_name(cpu_type, cpu_subtype),
        slice_offset,
        slice_size,
        cpu_type,
        cpu_subtype,
        fat_cpu_type: fat.map(|f| f.0),
        fat_cpu_subtype: fat.map(|f| f.1),
        fat_alignment_exponent: fat.map(|f| f.2),
        file_type: file_type_name(file_type),
        file_type_code: file_type,
        platform: None,
        platforms: Vec::new(),
        install_name: None,
        dependencies: Vec::new(),
        rpaths: Vec::new(),
        dyld_environment: Vec::new(),
        code_signature_present: false,
    };
    let mut offset = 0usize;
    for index in 0..command_count {
        if offset + 8 > bytes.len() {
            return Err(malformed(format!("load command {index} starts beyond sizeofcmds")));
        }
        let command = rd32(bytes, offset, true);
        let size = rd32(bytes, offset + 4, true) as usize;
        if size < 8 || !size.is_multiple_of(alignment) || offset + size > bytes.len() {
            return Err(malformed(format!(
                "load command {index} at offset {offset} has invalid cmdsize {size}"
            )));
        }
        decode_command(command, &bytes[offset..offset + size], index, &mut slice)?;
        offset += size;
    }
    if offset != bytes.len() {
        return Err(malformed(format!(
            "load commands declare {command_count} commands but sizeofcmds holds {} bytes",
            bytes.len()
        )));
    }
    Ok(slice)
}

fn decode_command(command: u32, body: &[u8], index: u32, slice: &mut MachoSlice) -> Result<(), Issue> {
    match command {
        LC_ID_DYLIB => {
            slice.install_name = Some(command_string(body, 24, index)?);
            return Ok(());
        }
        LC_RPATH => {
            slice.rpaths.push(command_string(body, 12, index)?);
            return Ok(());
        }
        LC_DYLD_ENVIRONMENT => {
            slice.dyld_environment.push(command_string(body, 12, index)?);
            return Ok(());
        }
        LC_CODE_SIGNATURE => {
            if body.len() < 16 {
                return Err(malformed(format!(
                    "load command {index} is too short for LC_CODE_SIGNATURE"
                )));
            }
            slice.code_signature_present = true;
            return Ok(());
        }
        LC_BUILD_VERSION => {
            if body.len() < 24 {
                return Err(malformed(format!(
                    "load command {index} is too short for LC_BUILD_VERSION"
                )));
            }
            slice.platforms.push(rd32(body, 8, true));
            return Ok(());
        }
        _ => {}
    }
    if let Some(platform) = legacy_version_min_platform(command, slice.cpu_type) {
        if body.len() < 16 {
            return Err(malformed(format!(
                "load command {index} is too short for a version-min command"
            )));
        }
        slice.platforms.push(platform);
        return Ok(());
    }
    let name = match command {
        LC_LOAD_DYLIB => Some("LC_LOAD_DYLIB"),
        LC_LOAD_WEAK_DYLIB => Some("LC_LOAD_WEAK_DYLIB"),
        LC_REEXPORT_DYLIB => Some("LC_REEXPORT_DYLIB"),
        LC_LAZY_LOAD_DYLIB => Some("LC_LAZY_LOAD_DYLIB"),
        LC_LOAD_UPWARD_DYLIB => Some("LC_LOAD_UPWARD_DYLIB"),
        _ => None,
    };
    if let Some(name) = name {
        slice.dependencies.push(decode_dependency(name, body, index)?);
    }
    Ok(())
}

fn decode_dependency(command: &'static str, body: &[u8], index: u32) -> Result<MachoDependency, Issue> {
    if body.len() < 24 {
        return Err(malformed(format!(
            "load command {index} is too short for a dylib command"
        )));
    }
    let name_offset = rd32(body, 8, true);
    let uses_flags = name_offset == 28 && body.len() >= 28 && rd32(body, 12, true) == DYLIB_USE_MARKER;
    let flags = if uses_flags { rd32(body, 24, true) } else { 0 };
    Ok(MachoDependency {
        command,
        encoding: if uses_flags { "dylib_use_command" } else { "dylib_command" },
        install_name: command_string(body, if uses_flags { 28 } else { 24 }, index)?,
        weak: command == "LC_LOAD_WEAK_DYLIB" || flags & DYLIB_USE_WEAK_LINK != 0,
        upward: command == "LC_LOAD_UPWARD_DYLIB" || flags & DYLIB_USE_UPWARD != 0,
        reexport: command == "LC_REEXPORT_DYLIB" || flags & DYLIB_USE_REEXPORT != 0,
        delayed_init: flags & DYLIB_USE_DELAYED_INIT != 0,
        current_version: version(rd32(body, 16, true)),
        compatibility_version: version(rd32(body, 20, true)),
    })
}

fn command_string(body: &[u8], minimum_offset: u32, index: u32) -> Result<String, Issue> {
    if body.len() < 12 {
        return Err(malformed(format!(
            "load command {index} is too short to hold a string offset"
        )));
    }
    let offset = rd32(body, 8, true);
    if offset < minimum_offset || offset as usize >= body.len() {
        return Err(malformed(format!(
            "load command {index} has string offset {offset} outside the command"
        )));
    }
    let offset = offset as usize;
    let end = body[offset..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|position| offset + position)
        .ok_or_else(|| malformed(format!("load command {index} has an unterminated string")))?;
    String::from_utf8(body[offset..end].to_vec())
        .map_err(|_| malformed(format!("load command {index} has a string that is not UTF-8")))
}

const CPU_ARCH_ABI64: u32 = 0x0100_0000;
const CPU_ARCH_ABI64_32: u32 = 0x0200_0000;
const CPU_TYPE_X86: u32 = 7;
const CPU_TYPE_ARM: u32 = 12;
const CPU_SUBTYPE_MASK: u32 = 0xff00_0000;
const CPU_SUBTYPE_ARM64E: u32 = 2;
const CPU_SUBTYPE_X86_64_H: u32 = 8;

pub fn architecture_name(cpu_type: u32, cpu_subtype: u32) -> String {
    let subtype = cpu_subtype & !CPU_SUBTYPE_MASK;
    if cpu_type == (CPU_TYPE_ARM | CPU_ARCH_ABI64) {
        return if subtype == CPU_SUBTYPE_ARM64E { "arm64e" } else { "arm64" }.to_string();
    }
    if cpu_type == (CPU_TYPE_ARM | CPU_ARCH_ABI64_32) {
        return "arm64_32".to_string();
    }
    if cpu_type == (CPU_TYPE_X86 | CPU_ARCH_ABI64) {
        return if subtype == CPU_SUBTYPE_X86_64_H { "x86_64h" } else { "x86_64" }.to_string();
    }
    if cpu_type == CPU_TYPE_X86 {
        return "i386".to_string();
    }
    if cpu_type == CPU_TYPE_ARM {
        return "arm".to_string();
    }
    format!("cpu-{cpu_type:x}")
}

fn file_type_name(file_type: u32) -> &'static str {
    match file_type {
        2 => "execute",
        6 => "dylib",
        8 => "bundle",
        _ => "other",
    }
}

fn version(value: u32) -> String {
    format!("{}.{}.{}", value >> 16, (value >> 8) & 0xff, value & 0xff)
}
