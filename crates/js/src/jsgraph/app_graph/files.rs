//! Read the inventoried relevant files of an application root (REA
//! `artifacts/javascript/JavaScriptArtifactFiles.ts`).
//!
//! The inventory decides which files exist and what their digests are; this pass re-reads those
//! bytes, fails if any entry changed after inventory, and decodes text.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use crate::error::JsError;
use crate::jsgraph::error::AnalysisFailure;
use crate::hash::hash_bytes;
use crate::jsgraph::control::Cancel;
use crate::paths::normalize_artifact_path;
use crate::readers::{create_reader, ArtifactReader};
use crate::types::ArtifactInventoryResult;
use crate::unicode::compare_unicode_code_points;

use super::model::{ArtifactFile, FileKind, FileSet};

struct Expected {
    sha256: String,
    bytes: u64,
    inventory_artifact_id: String,
    kind: FileKind,
}

/// Read all relevant textual entries through an already inventoried root.
pub fn read_artifact_files(
    root: &Path,
    inventory: &ArtifactInventoryResult,
    cancel: &Cancel,
) -> Result<FileSet, AnalysisFailure> {
    let format = inventory.manifest.root_format.as_str();
    let nodes: HashMap<&str, _> = inventory
        .nodes
        .iter()
        .map(|node| (node.artifact_id.as_str(), node))
        .collect();
    let mut expected: HashMap<String, Expected> = HashMap::new();
    for occurrence in &inventory.occurrences {
        if occurrence.logical_path == "." {
            continue;
        }
        let nested_asar = occurrence.entry_kind == "file"
            && occurrence.logical_path.to_lowercase().ends_with(".asar");
        if nested_asar && format != "asar" {
            // REA expands ASAR files found inside a directory root into containers; this port's
            // inventory does not, so a file set built here would silently miss their entries.
            return Err(AnalysisFailure::Unsupported {
                what: format!(
                    "nested ASAR container {} inside a directory application; extract it or analyze the .asar file directly",
                    occurrence.logical_path
                ),
            });
        }
        let Some(artifact_id) = occurrence.artifact_id.as_deref() else {
            continue;
        };
        let node = nodes.get(artifact_id).ok_or_else(|| {
            JsError::Integrity(format!(
                "Artifact inventory node is missing: {}",
                occurrence.logical_path
            ))
        })?;
        if occurrence.entry_kind != "file" {
            continue;
        }
        let Some(kind) = FileKind::for_path(&occurrence.logical_path) else {
            continue;
        };
        expected.insert(
            occurrence.logical_path.clone(),
            Expected {
                sha256: node.sha256.clone(),
                bytes: node.size,
                inventory_artifact_id: node.artifact_id.clone(),
                kind,
            },
        );
    }

    let root_sha256 = inventory.manifest.root_sha256.clone();
    let reader = create_reader(root, format)?
        .ok_or_else(|| JsError::Format(format!("{format} applications have no entry reader")))?;
    if format == "asar" {
        // The container bytes are re-verified like every entry.
        let bytes = std::fs::read(root)?;
        let digest = hash_bytes(&bytes);
        if digest.sha256 != root_sha256 {
            return Err(JsError::Integrity("Artifact entry changed after inventory: .".into()).into());
        }
    }

    let mut files: Vec<ArtifactFile> = Vec::new();
    let mut text_bytes = 0u64;
    let mut invalid_utf8 = 0u64;
    for entry in reader.list_entries()? {
        cancel.check()?;
        let path = normalize_artifact_path(&entry.path)?;
        let Some(wanted) = expected.get(&path) else {
            continue;
        };
        if entry.kind != "file" {
            continue;
        }
        let bytes = read_entry_bytes(reader.as_ref(), &entry)?;
        let digest = hash_bytes(&bytes);
        if digest.sha256 != wanted.sha256 || bytes.len() as u64 != wanted.bytes {
            return Err(JsError::Integrity(format!("Artifact entry changed after inventory: {path}")).into());
        }
        let (text, reason) = if wanted.kind == FileKind::NativeAddon {
            (None, Some("not-applicable"))
        } else {
            text_bytes += bytes.len() as u64;
            match decode_text(bytes, wanted.kind) {
                Some(text) => (Some(text), None),
                None => {
                    invalid_utf8 += 1;
                    (None, Some("invalid-utf8"))
                }
            }
        };
        files.push(ArtifactFile {
            path,
            container_sha256: root_sha256.clone(),
            sha256: wanted.sha256.clone(),
            bytes: wanted.bytes,
            inventory_artifact_id: wanted.inventory_artifact_id.clone(),
            kind: wanted.kind,
            unpacked: entry.unpacked,
            text,
            text_reason: reason,
        });
    }
    files.sort_by(|a, b| compare_unicode_code_points(&a.path, &b.path));
    let visited: std::collections::HashSet<&str> = files.iter().map(|f| f.path.as_str()).collect();
    for path in expected.keys() {
        if !visited.contains(path.as_str()) {
            return Err(JsError::Integrity(format!(
                "Relevant artifact entry disappeared after inventory: {path}"
            ))
            .into());
        }
    }
    Ok(FileSet {
        files,
        containers: Vec::new(),
        text_bytes_read: text_bytes,
        invalid_utf8_files: invalid_utf8,
    })
}

/// Read one entry; directory files are opened without following a final symlink.
fn read_entry_bytes(
    reader: &dyn ArtifactReader,
    entry: &crate::readers::ArtifactEntry,
) -> Result<Vec<u8>, JsError> {
    if reader.format() == "directory" {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&entry.adapter_key)
            .map_err(|error| JsError::Io(error.to_string()))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|error| JsError::Io(error.to_string()))?;
        return Ok(bytes);
    }
    reader.read_entry(entry)
}

/// `TextDecoder("utf-8", { fatal: true, ignoreBOM })`: JavaScript and HTML keep a leading BOM.
fn decode_text(bytes: Vec<u8>, kind: FileKind) -> Option<String> {
    let text = String::from_utf8(bytes).ok()?;
    let keep_bom = matches!(kind, FileKind::Javascript | FileKind::Html);
    if !keep_bom {
        if let Some(stripped) = text.strip_prefix('\u{feff}') {
            return Some(stripped.to_string());
        }
    }
    Some(text)
}
