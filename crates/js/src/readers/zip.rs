use super::{ArtifactEntry, ArtifactReader};
use crate::error::JsError;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use zip::read::ZipArchive;

pub struct ZipArtifactReader {
    path: PathBuf,
    format: String,
    entries: Vec<ArtifactEntry>,
}

impl ZipArtifactReader {
    pub fn new(path: &Path, format: &str) -> Result<Self, JsError> {
        let file = File::open(path)?;
        let mut archive = ZipArchive::new(file).map_err(|e| JsError::Format(e.to_string()))?;
        let mut entries = Vec::new();
        for i in 0..archive.len() {
            let entry = archive
                .by_index(i)
                .map_err(|e| JsError::Format(e.to_string()))?;
            let name = entry.name().to_string();
            if name.ends_with('/') {
                let path = name.trim_end_matches('/').to_string();
                if path.is_empty() {
                    continue;
                }
                entries.push(ArtifactEntry {
                    path,
                    kind: "directory".to_string(),
                    declared_size: None,
                    compressed_size: None,
                    executable: entry
                        .unix_mode()
                        .map(|m| m & 0o111 != 0)
                        .unwrap_or(false),
                    encrypted: false,
                    declared_sha256: None,
                    unpacked: false,
                    limitations: vec![],
                    adapter_key: name,
                });
            } else {
                let symlink = entry.unix_mode().map(|m| m & 0o170000 == 0o120000).unwrap_or(false);
                entries.push(ArtifactEntry {
                    path: name.clone(),
                    kind: if symlink {
                        "symlink".to_string()
                    } else {
                        "file".to_string()
                    },
                    declared_size: Some(entry.size()),
                    compressed_size: Some(entry.compressed_size()),
                    executable: entry.unix_mode().map(|m| m & 0o111 != 0).unwrap_or(false),
                    encrypted: false,
                    declared_sha256: None,
                    unpacked: false,
                    limitations: if symlink {
                        vec!["Archive symlink target was not read.".to_string()]
                    } else {
                        vec![]
                    },
                    adapter_key: name,
                });
            }
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(Self {
            path: path.to_path_buf(),
            format: format.to_string(),
            entries,
        })
    }
}

impl ArtifactReader for ZipArtifactReader {
    fn format(&self) -> &str {
        &self.format
    }

    fn list_entries(&self) -> Result<Vec<ArtifactEntry>, JsError> {
        Ok(self.entries.clone())
    }

    fn read_entry(&self, entry: &ArtifactEntry) -> Result<Vec<u8>, JsError> {
        if entry.kind != "file" {
            return Err(JsError::Format("ZIP entry is not a regular file".to_string()));
        }
        let file = File::open(&self.path)?;
        let mut archive = ZipArchive::new(file).map_err(|e| JsError::Format(e.to_string()))?;
        let mut zip_entry = archive
            .by_name(&entry.adapter_key)
            .map_err(|e| JsError::Format(e.to_string()))?;
        let mut buf = Vec::new();
        zip_entry
            .read_to_end(&mut buf)
            .map_err(|e| JsError::Io(e.to_string()))?;
        Ok(buf)
    }
}
