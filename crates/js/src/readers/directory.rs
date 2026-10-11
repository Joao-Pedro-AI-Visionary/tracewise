use super::{ArtifactEntry, ArtifactReader};
use crate::error::JsError;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub struct DirectoryArtifactReader {
    root: PathBuf,
}

impl DirectoryArtifactReader {
    pub fn new(path: &Path) -> Result<Self, JsError> {
        Ok(Self {
            root: std::fs::canonicalize(path)?,
        })
    }
}

impl ArtifactReader for DirectoryArtifactReader {
    fn format(&self) -> &str {
        "directory"
    }

    fn list_entries(&self) -> Result<Vec<ArtifactEntry>, JsError> {
        let mut entries = Vec::new();
        for entry in WalkDir::new(&self.root)
            .follow_links(false)
            .sort_by(|a, b| a.path().cmp(b.path()))
        {
            let entry = entry.map_err(|e| JsError::Io(e.to_string()))?;
            let rel = entry
                .path()
                .strip_prefix(&self.root)
                .map_err(|e| JsError::Io(e.to_string()))?;
            if rel.as_os_str().is_empty() {
                continue;
            }
            let path = rel.to_string_lossy().replace('\\', "/");
            let meta = entry.metadata().map_err(|e| JsError::Io(e.to_string()))?;
            let kind = if meta.is_dir() {
                "directory"
            } else if meta.is_symlink() {
                "symlink"
            } else if meta.is_file() {
                "file"
            } else {
                continue;
            };
            entries.push(ArtifactEntry {
                path,
                kind: kind.to_string(),
                declared_size: if kind == "file" {
                    Some(meta.len())
                } else {
                    None
                },
                compressed_size: None,
                executable: meta.permissions().mode() & 0o111 != 0,
                encrypted: false,
                declared_sha256: None,
                unpacked: false,
                limitations: if kind == "symlink" {
                    vec!["Symlink target was not followed or disclosed.".to_string()]
                } else {
                    vec![]
                },
                adapter_key: entry.path().to_string_lossy().to_string(),
            });
        }
        Ok(entries)
    }

    fn read_entry(&self, entry: &ArtifactEntry) -> Result<Vec<u8>, JsError> {
        if entry.kind != "file" {
            return Err(JsError::Format("Not a regular file".to_string()));
        }
        std::fs::read(&entry.adapter_key).map_err(|e| JsError::Io(e.to_string()))
    }
}
