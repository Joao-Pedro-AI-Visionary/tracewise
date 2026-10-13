//! Binary target resolution (port of the parts of REA `BinaryTargetResolver`,
//! `binaryTarget.ts` and `dosMz.ts` that decide whether a path is a PE image).
//!
//! REA classifies the target before any provider runs, so a malformed PE
//! header, an unsupported architecture or a non-PE format is reported from
//! here and never reaches the managed inspectors.

use std::io::ErrorKind;
use std::path::Path;

use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct ResolveError {
    pub path: String,
    pub reason: String,
    pub constraint: Option<&'static str>,
}

#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    /// Canonical path (REA `target.path`).
    pub path: String,
    pub sha256: String,
    /// REA `BinaryTarget.format`: `pe`, `elf`, `mach-o`, `dos-mz`, `zip`, `javascript`, ...
    pub format: String,
    pub architecture: Option<String>,
    /// The first `min(size, retain_limit)` bytes of the file.
    pub bytes: Vec<u8>,
    /// Real size of the file in bytes (it may exceed `bytes.len()`).
    pub size: u64,
}

/// Bytes a full-image provider (managed PE inspection) may retain in memory.
pub const DEFAULT_RETAIN_LIMIT: u64 = 128 * 1024 * 1024;

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn u32be(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// `mzWindowsHeaderOffset`.
pub fn mz_windows_header_offset(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 64 {
        return None;
    }
    let header_bytes = u16le(bytes, 8) as u32 * 16;
    if header_bytes != 0 && header_bytes < 64 {
        return None;
    }
    let relocation_count = u16le(bytes, 6) as u32;
    let table_start = u16le(bytes, 24) as u32;
    if header_bytes != 0 && relocation_count > 0 && table_start < 64 && table_start + relocation_count * 4 > 60 {
        return None;
    }
    let offset = u32le(bytes, 60);
    if offset == 0 {
        None
    } else {
        Some(offset)
    }
}

fn parse_dos_mz_header(bytes: &[u8], file_size: u64) -> Result<(), String> {
    if bytes.len() < 28 || &bytes[0..2] != b"MZ" {
        return Err("invalid or truncated DOS MZ header".into());
    }
    if file_size < bytes.len() as u64 {
        return Err("invalid DOS MZ file length".into());
    }
    if mz_windows_header_offset(bytes).is_some() {
        return Err("MZ declares a Windows new header; it is not a DOS-only image".into());
    }
    let last_page_bytes = u16le(bytes, 2) as u64;
    let pages = u16le(bytes, 4) as u64;
    if pages == 0 || last_page_bytes > 511 {
        return Err("invalid DOS MZ page count or final-page size".into());
    }
    let image_bytes = (pages - 1) * 512 + if last_page_bytes == 0 { 512 } else { last_page_bytes };
    let header_bytes = u16le(bytes, 8) as u64 * 16;
    if header_bytes < 28 || header_bytes >= image_bytes {
        return Err("invalid DOS MZ header size or empty load module".into());
    }
    if image_bytes > file_size {
        return Err("truncated DOS MZ load module".into());
    }
    let relocation_count = u16le(bytes, 6) as u64;
    let relocation_table_offset = u16le(bytes, 24) as u64;
    let table_end = relocation_table_offset + relocation_count * 4;
    if relocation_count > 0 && (relocation_table_offset < 28 || table_end > header_bytes) {
        return Err("DOS MZ relocation table lies outside its header".into());
    }
    if relocation_count > 0 && table_end > bytes.len() as u64 {
        return Err("truncated DOS MZ relocation table".into());
    }
    let module_bytes = image_bytes - header_bytes;
    for index in 0..relocation_count {
        let record = (relocation_table_offset + index * 4) as usize;
        let offset = u16le(bytes, record) as u64;
        let segment = u16le(bytes, record + 2) as u64;
        if segment * 16 + offset + 2 > module_bytes {
            return Err(format!("DOS MZ relocation {index} points outside its load module"));
        }
    }
    let entry_offset = u16le(bytes, 20) as u64;
    let entry_segment = u16le(bytes, 22) as u64;
    if entry_segment * 16 + entry_offset >= module_bytes {
        return Err("DOS MZ entry point lies outside its initialized load module".into());
    }
    Ok(())
}

fn pe_architecture(machine: u16) -> Option<&'static str> {
    match machine {
        0x14c => Some("x86"),
        0x8664 => Some("x86_64"),
        0x1c0 | 0x1c2 | 0x1c4 => Some("arm"),
        0xaa64 => Some("arm64"),
        _ => None,
    }
}

fn pe_managed_status(optional: &[u8], architecture: &str) -> Result<bool, String> {
    if optional.len() < 2 {
        return Err("truncated PE optional header".into());
    }
    let magic = u16le(optional, 0);
    let expected = if architecture == "x86_64" || architecture == "arm64" { 0x20b } else { 0x10b };
    if magic != expected {
        return Err("PE optional-header magic does not match its architecture".into());
    }
    let directory_offset: usize = if magic == 0x20b { 112 } else { 96 };
    let count_offset = directory_offset - 4;
    if optional.len() < count_offset + 4 {
        return Err("truncated PE optional header".into());
    }
    let count = u32le(optional, count_offset) as usize;
    let required = directory_offset + count * 8;
    if required > optional.len() {
        return Err("truncated PE data-directory table".into());
    }
    if count <= 14 {
        return Ok(false);
    }
    let cli = directory_offset + 14 * 8;
    Ok(u32le(optional, cli) != 0 || u32le(optional, cli + 4) != 0)
}

/// `parsePeRecord`: returns the architecture.
fn parse_pe_record(record: &[u8]) -> Result<&'static str, String> {
    if record.len() < 24 || &record[0..4] != b"PE\0\0" {
        return Err("invalid or truncated PE header".into());
    }
    let architecture = pe_architecture(u16le(record, 4)).ok_or_else(|| "unsupported PE architecture".to_string())?;
    let optional_size = u16le(record, 20) as usize;
    if optional_size > 4096 || record.len() < 24 + optional_size {
        return Err("invalid or truncated PE optional header".into());
    }
    pe_managed_status(&record[24..24 + optional_size], architecture)?;
    Ok(architecture)
}

fn read_pe_metadata(bytes: &[u8], offset: u32) -> Result<(&'static str, &'static str), String> {
    // The probe in REA reads from the file; `bytes` is the whole file here.
    let offset = offset as usize;
    if bytes.len() < offset + 24 {
        return Err("invalid or truncated PE header".into());
    }
    let signature = &bytes[offset..offset + 2];
    for name in ["NE", "LE", "LX"] {
        if signature == name.as_bytes() {
            return Err(format!("unsupported {name} executable in MZ image"));
        }
    }
    let optional_size = u16le(bytes, offset + 20) as usize;
    if optional_size > 4096 {
        return Err("invalid PE optional header size".into());
    }
    if bytes.len() < offset + 24 + optional_size {
        return Err("invalid or truncated PE header".into());
    }
    let architecture = parse_pe_record(&bytes[offset..offset + 24 + optional_size])?;
    Ok(("pe", architecture))
}

fn elf_architecture(machine: u16) -> Option<&'static str> {
    match machine {
        3 => Some("x86"),
        62 => Some("x86_64"),
        8 => Some("mips"),
        40 => Some("arm"),
        183 => Some("arm64"),
        _ => None,
    }
}

fn mach_architecture(cpu: u32) -> Option<&'static str> {
    match cpu {
        7 => Some("x86"),
        0x0100_0007 => Some("x86_64"),
        12 => Some("arm"),
        0x0100_000c => Some("arm64"),
        _ => None,
    }
}

fn parse_elf(bytes: &[u8], file_size: u64) -> Result<(&'static str, &'static str), String> {
    if bytes.len() < 6 {
        return Err("truncated ELF header".into());
    }
    if bytes[4] != 1 && bytes[4] != 2 {
        return Err("unsupported ELF class".into());
    }
    let little = bytes[5] == 1;
    if !little && bytes[5] != 2 {
        return Err("unsupported ELF endianness".into());
    }
    let header_size = if bytes[4] == 1 { 52 } else { 64 };
    if bytes.len() < header_size {
        return Err(format!(
            "truncated ELF header: an ELF{} header needs {} bytes; the file has {}",
            if bytes[4] == 1 { 32 } else { 64 },
            header_size,
            file_size
        ));
    }
    let machine = if little { u16le(bytes, 18) } else { u16::from_be_bytes([bytes[18], bytes[19]]) };
    let architecture = elf_architecture(machine).ok_or_else(|| "unsupported ELF architecture".to_string())?;
    Ok(("elf", architecture))
}

fn parse_thin_macho(bytes: &[u8], magic: u32, file_size: u64) -> Result<(&'static str, &'static str), String> {
    let is64 = magic == 0xfeedfacf || magic == 0xcffaedfe;
    let header_size = if is64 { 32 } else { 28 };
    if bytes.len() < header_size {
        return Err(format!(
            "truncated Mach-O header: a {}-bit header needs {} bytes; the file has {}",
            if is64 { 64 } else { 32 },
            header_size,
            file_size
        ));
    }
    let little = magic == 0xcefaedfe || magic == 0xcffaedfe;
    let read = |o: usize| if little { u32le(bytes, o) } else { u32be(bytes, o) };
    let architecture = mach_architecture(read(4)).ok_or_else(|| "unsupported Mach-O architecture".to_string())?;
    let command_bytes = read(20) as u64;
    if header_size as u64 + command_bytes > file_size {
        return Err(format!(
            "truncated Mach-O load commands: the header declares {command_bytes} bytes after its {header_size}-byte header; the file has {file_size}"
        ));
    }
    Ok(("mach-o", architecture))
}

fn parse_fat_macho(bytes: &[u8], magic: u32, file_size: u64) -> Result<(&'static str, &'static str), String> {
    let little = magic == 0xbebafeca || magic == 0xbfbafeca;
    let is64 = magic == 0xcafebabf || magic == 0xbfbafeca;
    if bytes.len() < 8 {
        return Err("truncated FAT header".into());
    }
    let read = |o: usize| if little { u32le(bytes, o) } else { u32be(bytes, o) };
    let count = read(4) as usize;
    let entry_size = if is64 { 32 } else { 20 };
    if count == 0 || count > 128 || bytes.len() < 8 + count * entry_size {
        return Err("truncated or invalid FAT architecture table".into());
    }
    let mut architectures: Vec<&'static str> = Vec::new();
    let mut slice_ends: Vec<(&'static str, u128)> = Vec::new();
    for index in 0..count {
        let entry = 8 + index * entry_size;
        let Some(architecture) = mach_architecture(read(entry)) else { continue };
        if architectures.contains(&architecture) {
            continue;
        }
        architectures.push(architecture);
        let (offset, size) = if is64 {
            let rd = |o: usize| -> u128 {
                let mut raw = [0u8; 8];
                raw.copy_from_slice(&bytes[o..o + 8]);
                (if little { u64::from_le_bytes(raw) } else { u64::from_be_bytes(raw) }) as u128
            };
            (rd(entry + 8), rd(entry + 16))
        } else {
            (read(entry + 8) as u128, read(entry + 12) as u128)
        };
        slice_ends.push((architecture, offset + size));
    }
    let preferred = match std::env::consts::ARCH {
        "aarch64" => Some("arm64"),
        "x86_64" => Some("x86_64"),
        "x86" => Some("x86"),
        "arm" => Some("arm"),
        _ => None,
    };
    let host = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        "x86" => "ia32",
        other => other,
    };
    let Some(preferred) = preferred.filter(|p| architectures.contains(p)) else {
        return Err(format!("FAT binary has no host-compatible {host} architecture"));
    };
    let end = slice_ends.iter().find(|(a, _)| *a == preferred).map(|(_, e)| *e).unwrap_or(0);
    if end > file_size as u128 {
        return Err(format!("truncated FAT slice: the {preferred} slice ends at byte {end}; the file has {file_size}"));
    }
    Ok(("mach-o", preferred))
}

fn parse_mz(bytes: &[u8], file_size: u64) -> Result<(&'static str, &'static str), String> {
    if let Some(offset) = mz_windows_header_offset(bytes) {
        if offset < 64 || offset as usize > bytes.len().wrapping_sub(24) || bytes.len() < 24 {
            return Err("invalid or truncated Windows executable header in MZ image".into());
        }
        let signature = &bytes[offset as usize..offset as usize + 2];
        for name in ["NE", "LE", "LX"] {
            if signature == name.as_bytes() {
                return Err(format!("unsupported {name} executable in MZ image"));
            }
        }
        let architecture = parse_pe_record(&bytes[offset as usize..])?;
        return Ok(("pe", architecture));
    }
    parse_dos_mz_header(bytes, file_size)?;
    Ok(("dos-mz", "x86"))
}

fn parse_executable_header(bytes: &[u8], file_size: u64) -> Result<(&'static str, &'static str), String> {
    if bytes.len() >= 4 && bytes[0..4] == [0x7f, 0x45, 0x4c, 0x46] {
        return parse_elf(bytes, file_size);
    }
    if bytes.len() >= 2 && bytes[0] == 0x4d && bytes[1] == 0x5a {
        return parse_mz(bytes, file_size);
    }
    if bytes.len() < 8 {
        return Err("truncated or unsupported binary header".into());
    }
    let magic = u32be(bytes, 0);
    if [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].contains(&magic) {
        return parse_thin_macho(bytes, magic, file_size);
    }
    if [0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca].contains(&magic) {
        return parse_fat_macho(bytes, magic, file_size);
    }
    Err("unsupported binary format".into())
}

fn read_executable_metadata(bytes: &[u8], file_size: u64) -> Result<(&'static str, &'static str), String> {
    let prefix = &bytes[..bytes.len().min(4096)];
    if prefix.len() >= 2 && prefix[0] == 0x4d && prefix[1] == 0x5a {
        if let Some(offset) = mz_windows_header_offset(prefix) {
            if offset < 64 {
                return Err("invalid Windows new-header offset in MZ image".into());
            }
            return read_pe_metadata(bytes, offset);
        }
        let table_end = if prefix.len() >= 28 { u16le(prefix, 24) as usize + u16le(prefix, 6) as usize * 4 } else { 0 };
        let header_bytes = if prefix.len() >= 28 { u16le(prefix, 8) as usize * 16 } else { 0 };
        if table_end > prefix.len() && table_end <= header_bytes && table_end as u64 <= file_size {
            return parse_executable_header(&bytes[..table_end.min(bytes.len())], file_size);
        }
        return parse_executable_header(prefix, file_size);
    }
    if prefix.len() >= 8 {
        let magic = u32be(prefix, 0);
        if [0xcafebabf, 0xbfbafeca].contains(&magic) {
            let little = magic == 0xbfbafeca;
            let count = if little { u32le(prefix, 4) } else { u32be(prefix, 4) } as usize;
            let required = 8 + count * 32;
            if count <= 128 && required > prefix.len() {
                return parse_executable_header(&bytes[..required.min(bytes.len())], file_size);
            }
        }
    }
    parse_executable_header(prefix, file_size)
}

fn zip_signature(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && bytes[0] == 0x50
        && bytes[1] == 0x4b
        && ((bytes[2] == 0x03 && bytes[3] == 0x04) || (bytes[2] == 0x05 && bytes[3] == 0x06) || (bytes[2] == 0x07 && bytes[3] == 0x08))
}

fn artifact_format(path: &str, bytes: &[u8], file_size: u64, tail: &[u8]) -> Option<String> {
    let lower = path.to_lowercase();
    let magic = &bytes[..bytes.len().min(8)];
    if zip_signature(magic) {
        let format = if lower.ends_with(".zip") {
            "zip"
        } else if lower.ends_with(".ipa") {
            "ipa"
        } else if lower.ends_with(".apk") {
            "apk"
        } else if lower.ends_with(".msix") || lower.ends_with(".msixbundle") {
            "msix"
        } else if lower.ends_with(".appx") || lower.ends_with(".appxbundle") {
            "appx"
        } else {
            "zip"
        };
        return Some(format.to_string());
    }
    if lower.ends_with(".asar") {
        return Some("asar".into());
    }
    if lower.ends_with(".plist") {
        return Some("plist".into());
    }
    if lower.ends_with(".map") {
        return Some("source-map".into());
    }
    let is_js = lower.ends_with(".js") || lower.ends_with(".mjs") || lower.ends_with(".cjs");
    if is_js {
        return Some("javascript".into());
    }
    if lower.ends_with(".pkg") && magic.len() >= 4 && &magic[0..4] == b"xar!" {
        return Some("pkg".into());
    }
    if lower.ends_with(".dmg") && file_size >= 512 && tail.len() >= 512 && &tail[tail.len() - 512..tail.len() - 508] == b"koly" {
        return Some("dmg".into());
    }
    None
}

fn node_fs_reason(error: &std::io::Error, candidate: &str) -> String {
    match error.kind() {
        ErrorKind::NotFound => format!(
            "target does not exist or a path component is not a directory: ENOENT: no such file or directory, access '{candidate}'"
        ),
        ErrorKind::PermissionDenied => {
            format!("permission denied while reading target: EACCES: permission denied, access '{candidate}'")
        }
        _ => match error.raw_os_error() {
            Some(20) => format!(
                "target does not exist or a path component is not a directory: ENOTDIR: not a directory, access '{candidate}'"
            ),
            Some(21) => "target is a directory, not a readable file: EISDIR: illegal operation on a directory, read".to_string(),
            Some(code) => format!("target could not be read (errno {code}): {error}"),
            None => format!("target could not be read: {error}"),
        },
    }
}


const CHUNK: usize = 64 * 1024;

#[cfg(unix)]
fn open_regular(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    // O_NONBLOCK keeps a FIFO from blocking the open; O_NOCTTY and O_NOFOLLOW as in REA.
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_regular(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

#[cfg(unix)]
fn read_at(file: &std::fs::File, buffer: &mut [u8], position: u64) -> std::io::Result<usize> {
    use std::os::unix::fs::FileExt;
    file.read_at(buffer, position)
}

#[cfg(not(unix))]
fn read_at(file: &std::fs::File, buffer: &mut [u8], position: u64) -> std::io::Result<usize> {
    use std::os::windows::fs::FileExt;
    file.seek_read(buffer, position)
}

#[cfg(unix)]
fn same_state(expected: &std::fs::Metadata, observed: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    observed.is_file()
        && expected.dev() == observed.dev()
        && expected.ino() == observed.ino()
        && expected.size() == observed.size()
        && expected.mode() == observed.mode()
        && expected.mtime() == observed.mtime()
        && expected.mtime_nsec() == observed.mtime_nsec()
        && expected.ctime() == observed.ctime()
        && expected.ctime_nsec() == observed.ctime_nsec()
}

#[cfg(not(unix))]
fn same_state(expected: &std::fs::Metadata, observed: &std::fs::Metadata) -> bool {
    observed.is_file() && expected.len() == observed.len() && expected.modified().ok() == observed.modified().ok()
}

/// Resolve and classify a readable local target before a provider is selected,
/// retaining at most [`DEFAULT_RETAIN_LIMIT`] bytes of it.
pub fn resolve_target(input: &str) -> Result<ResolvedTarget, ResolveError> {
    resolve_target_bounded(input, DEFAULT_RETAIN_LIMIT)
}

/// Resolve a target, streaming its SHA-256 and keeping only the first
/// `retain_limit` bytes (REA `parseBinaryTarget`: the file is opened without
/// following links, must be a regular file, is hashed in 64 KiB reads limited to
/// `size + 1` bytes, and is re-checked for changes afterwards).
pub fn resolve_target_bounded(input: &str, retain_limit: u64) -> Result<ResolvedTarget, ResolveError> {
    let candidate = if Path::new(input).is_absolute() {
        input.to_string()
    } else {
        std::env::current_dir().map(|cwd| cwd.join(input).to_string_lossy().into_owned()).unwrap_or_else(|_| input.to_string())
    };
    let fail = |reason: String| ResolveError { path: candidate.clone(), reason, constraint: None };
    // access(R_OK) + realpath
    let canonical = std::fs::canonicalize(&candidate).map_err(|e| fail(node_fs_reason(&e, &candidate)))?;
    let canonical_text = canonical.to_string_lossy().into_owned();
    let metadata = std::fs::metadata(&canonical).map_err(|e| fail(node_fs_reason(&e, &candidate)))?;
    if metadata.is_dir() {
        let is_app = canonical.extension().map(|e| e.to_string_lossy().eq_ignore_ascii_case("app")).unwrap_or(false);
        return Err(ResolveError {
            path: canonical_text,
            reason: if is_app {
                "app bundle executable resolution is not supported by this provider".into()
            } else {
                "this opening route requires a file or app bundle".into()
            },
            constraint: if is_app { None } else { Some("directory_requires_file") },
        });
    }
    let file = open_regular(&canonical).map_err(|e| fail(node_fs_reason(&e, &candidate)))?;
    let initial = file.metadata().map_err(|e| fail(node_fs_reason(&e, &candidate)))?;
    if !initial.is_file() {
        return Err(fail("target is not a regular file".to_string()));
    }
    let size = initial.len();
    let keep = size.min(retain_limit) as usize;
    let mut retained: Vec<u8> = Vec::with_capacity(keep.min(CHUNK * 16));
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; CHUNK];
    let mut position: u64 = 0;
    loop {
        let wanted = (size - position.min(size) + 1).min(CHUNK as u64) as usize;
        let read = read_at(&file, &mut buffer[..wanted], position).map_err(|e| fail(node_fs_reason(&e, &candidate)))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        if (retained.len() as u64) < retain_limit {
            let room = (retain_limit - retained.len() as u64).min(read as u64) as usize;
            retained.extend_from_slice(&buffer[..room]);
        }
        position += read as u64;
        if position > size {
            return Err(fail("target grew while being read".to_string()));
        }
    }
    let unchanged = file.metadata().ok().is_some_and(|now| same_state(&initial, &now))
        && std::fs::symlink_metadata(&canonical).ok().is_some_and(|now| same_state(&initial, &now));
    if !unchanged || position != size {
        return Err(fail("target changed while being read".to_string()));
    }
    let sha256 = hex::encode(hasher.finalize());
    let tail: Vec<u8> = if size as usize <= retained.len() && retained.len() as u64 == size {
        retained[retained.len().saturating_sub(512)..].to_vec()
    } else if size >= 512 {
        let mut tail = vec![0u8; 512];
        match read_at(&file, &mut tail, size - 512) {
            Ok(512) => tail,
            _ => Vec::new(),
        }
    } else {
        Vec::new()
    };
    let lower = canonical_text.to_lowercase();
    let classified: Result<(String, Option<String>), String> = if lower.ends_with(".hop") {
        Ok(("analysis-database".into(), None))
    } else if let Some(format) = artifact_format(&canonical_text, &retained, size, &tail) {
        Ok((format, None))
    } else {
        read_executable_metadata(&retained, size).map(|(format, architecture)| (format.to_string(), Some(architecture.to_string())))
    };
    match classified {
        Ok((format, architecture)) => {
            Ok(ResolvedTarget { path: canonical_text, sha256, format, architecture, bytes: retained, size })
        }
        Err(reason) => Err(ResolveError { path: canonical_text, reason, constraint: None }),
    }
}
