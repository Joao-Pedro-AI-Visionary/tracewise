//! Private snapshots, reports and staging inventory (port of REA `FirmwareFiles.ts`).

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::{InputIssue, ToolError};
use crate::firmware::collate::{locale_compare, utf16_order};
use crate::firmware::release::{INPUT_BYTES, REPORT_BYTES};
use crate::firmware::FwFailure;
use crate::fsutil::{is_absolute, node_io_error, relative, resolve};

/// One regular file or unpublished filesystem entry in a private extraction.
#[derive(Debug, Clone)]
pub struct FirmwareEntry {
    pub relative_path: String,
    pub path: String,
    pub size: u64,
    /// `file`, `symlink` or `special`.
    pub kind: &'static str,
    pub link_target: Option<String>,
}

fn open_nofollow(path: &str) -> std::io::Result<File> {
    OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)
}

/// `hashFirmwareFile`: SHA-256 of one regular file, never following a final symlink.
pub fn hash_file(path: &str) -> Result<String, String> {
    let mut file = open_nofollow(path).map_err(|e| node_io_error(&e, "open", path))?;
    let meta = file.metadata().map_err(|e| node_io_error(&e, "fstat", path))?;
    if !meta.is_file() {
        return Err(format!("Not a regular file: {path}"));
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|e| node_io_error(&e, "read", path))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[derive(Debug, Clone)]
pub struct Selection {
    pub offset: u64,
    pub length: u64,
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    /// `resolve(request.input.path)`: the evidence subject path.
    pub subject_path: String,
    pub sha256: String,
    pub size: u64,
    pub input_path: String,
    pub selection: Selection,
}

fn input_issue(operation: &str, path: &str, message: String) -> FwFailure {
    FwFailure::Typed(ToolError::Input {
        operation: operation.to_string(),
        issues: vec![InputIssue { path: vec![json!(path)], reason: "out_of_range", message: Some(message) }],
    })
}

/// `snapshotFirmware`: copy and identify the exact bytes the providers consume.
pub fn snapshot(
    operation: &str,
    path: &str,
    range: Option<(u64, u64)>,
    root: &str,
) -> Result<Snapshot, FwFailure> {
    let source_path = resolve(path);
    let source = std::fs::canonicalize(&source_path)
        .map_err(|e| FwFailure::Other(node_io_error(&e, "realpath", &source_path)))?
        .to_string_lossy()
        .into_owned();
    let mut handle = open_nofollow(&source).map_err(|e| FwFailure::Other(node_io_error(&e, "open", &source)))?;
    let stat = handle.metadata().map_err(|e| FwFailure::Other(node_io_error(&e, "fstat", &source)))?;
    if !stat.is_file() || stat.len() == 0 || stat.len() > INPUT_BYTES {
        return Err(input_issue(
            operation,
            "path",
            format!("Firmware must be a nonempty regular file no larger than {INPUT_BYTES} bytes"),
        ));
    }
    let full_path = format!("{root}/firmware.bin");
    let mut hasher = Sha256::new();
    let mut size: u64 = 0;
    {
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&full_path)
            .map_err(|e| FwFailure::Other(node_io_error(&e, "open", &full_path)))?;
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = handle.read(&mut buffer).map_err(|e| FwFailure::Other(node_io_error(&e, "read", &source)))?;
            if read == 0 {
                break;
            }
            size += read as u64;
            if size > INPUT_BYTES {
                return Err(FwFailure::Other("Firmware grew beyond the input byte budget".to_string()));
            }
            hasher.update(&buffer[..read]);
            out.write_all(&buffer[..read]).map_err(|e| FwFailure::Other(node_io_error(&e, "write", &full_path)))?;
        }
    }
    std::fs::set_permissions(&full_path, std::fs::Permissions::from_mode(0o400))
        .map_err(|e| FwFailure::Other(node_io_error(&e, "chmod", &full_path)))?;
    let sha256 = hex::encode(hasher.finalize());
    let (offset, length) = range.unwrap_or((0, size));
    if length == 0 || offset > size || length > size - offset {
        return Err(input_issue(
            operation,
            "range",
            format!("Selected range must be within the {size}-byte firmware file"),
        ));
    }
    let mut input_path = full_path.clone();
    let mut selection_sha = sha256.clone();
    if range.is_some() {
        input_path = format!("{root}/selected.bin");
        let mut source_file =
            File::open(&full_path).map_err(|e| FwFailure::Other(node_io_error(&e, "open", &full_path)))?;
        std::io::Seek::seek(&mut source_file, std::io::SeekFrom::Start(offset))
            .map_err(|e| FwFailure::Other(node_io_error(&e, "read", &full_path)))?;
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&input_path)
            .map_err(|e| FwFailure::Other(node_io_error(&e, "open", &input_path)))?;
        let mut remaining = length;
        let mut buffer = vec![0u8; 64 * 1024];
        while remaining > 0 {
            let want = std::cmp::min(buffer.len() as u64, remaining) as usize;
            let read = source_file
                .read(&mut buffer[..want])
                .map_err(|e| FwFailure::Other(node_io_error(&e, "read", &full_path)))?;
            if read == 0 {
                break;
            }
            out.write_all(&buffer[..read]).map_err(|e| FwFailure::Other(node_io_error(&e, "write", &input_path)))?;
            remaining -= read as u64;
        }
        drop(out);
        std::fs::set_permissions(&input_path, std::fs::Permissions::from_mode(0o400))
            .map_err(|e| FwFailure::Other(node_io_error(&e, "chmod", &input_path)))?;
        selection_sha = hash_file(&input_path).map_err(FwFailure::Other)?;
    }
    Ok(Snapshot {
        subject_path: source_path,
        sha256,
        size,
        input_path,
        selection: Selection { offset, length, sha256: selection_sha },
    })
}

/// `readFirmwareReport`: a complete, bounded JSON report. Errors carry the
/// REA `AnalysisOutputError` reason or a raw Node filesystem message.
pub enum ReportError {
    Output(String),
    Other(String),
}

pub fn read_report(path: &str) -> Result<Value, ReportError> {
    let mut file = open_nofollow(path).map_err(|e| ReportError::Other(node_io_error(&e, "open", path)))?;
    let meta = file.metadata().map_err(|e| ReportError::Other(node_io_error(&e, "fstat", path)))?;
    if !meta.is_file() {
        return Err(ReportError::Output("Report is not a regular file".to_string()));
    }
    let mut bytes = Vec::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|e| ReportError::Other(node_io_error(&e, "read", path)))?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.len() > REPORT_BYTES {
            return Err(ReportError::Output(format!("Report exceeded {REPORT_BYTES} bytes")));
        }
    }
    let invalid = || ReportError::Output("Tool report is not valid complete JSON".to_string());
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
    serde_json::from_str(text).map_err(|_| invalid())
}

fn lstat_or_none(path: &Path) -> std::io::Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// `inventoryFirmwareOutput`: enumerate private output without following
/// links, enforcing aggregate staging budgets. Errors are `Output` reasons or
/// raw filesystem messages.
pub fn inventory(root: &str, max_bytes: u64, max_entries: u64) -> Result<Vec<FirmwareEntry>, ReportError> {
    let mut entries: Vec<FirmwareEntry> = Vec::new();
    let mut pending: Vec<String> = vec![root.to_string()];
    let mut bytes: u64 = 0;
    let mut count: u64 = 0;
    while let Some(directory) = pending.pop() {
        let dir_path = Path::new(&directory);
        let meta = lstat_or_none(dir_path).map_err(|e| ReportError::Other(node_io_error(&e, "lstat", &directory)))?;
        match meta {
            Some(m) if m.is_dir() && !m.file_type().is_symlink() => {}
            _ => continue,
        }
        let listing = match std::fs::read_dir(dir_path) {
            Ok(listing) => listing,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(ReportError::Other(node_io_error(&error, "opendir", &directory))),
        };
        let mut names: Vec<String> = Vec::new();
        for entry in listing {
            let entry = entry.map_err(|e| ReportError::Other(node_io_error(&e, "scandir", &directory)))?;
            count += 1;
            if count > max_entries {
                return Err(ReportError::Output(format!("Staging entry budget exceeded ({max_entries})")));
            }
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
        names.sort_by(|a, b| utf16_order(a, b));
        for name in names {
            let path = format!("{directory}/{name}");
            let stat = lstat_or_none(Path::new(&path)).map_err(|e| ReportError::Other(node_io_error(&e, "lstat", &path)))?;
            let Some(stat) = stat else { continue };
            if stat.is_dir() {
                pending.push(path);
                continue;
            }
            if stat.is_file() {
                bytes += stat.len();
            }
            if bytes > max_bytes {
                return Err(ReportError::Output(format!("Staging byte budget exceeded ({max_bytes})")));
            }
            let is_link = stat.file_type().is_symlink();
            let kind = if is_link {
                "symlink"
            } else if stat.is_file() {
                "file"
            } else {
                "special"
            };
            let link_target = if is_link {
                Some(
                    std::fs::read_link(&path)
                        .map_err(|e| ReportError::Other(node_io_error(&e, "readlink", &path)))?
                        .to_string_lossy()
                        .into_owned(),
                )
            } else {
                None
            };
            entries.push(FirmwareEntry {
                relative_path: relative(root, &path),
                path,
                size: stat.len(),
                kind,
                link_target,
            });
        }
    }
    entries.sort_by(|a, b| locale_compare(&a.relative_path, &b.relative_path));
    Ok(entries)
}

/// `firmwareLogicalPath`: bind a producer path to the input or the private tree.
pub fn logical_path(path: &str, input_path: &str, output_root: &str) -> Result<String, String> {
    if path == input_path {
        return Ok("$input".to_string());
    }
    let rel = relative(output_root, path);
    if !is_absolute(path) || rel == ".." || rel.starts_with("../") || is_absolute(&rel) {
        return Err(format!("Provider reported a path outside its owned output: {path}"));
    }
    Ok(if rel.is_empty() { "$output".to_string() } else { format!("$output/{rel}") })
}
