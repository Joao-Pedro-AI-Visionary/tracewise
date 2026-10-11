use super::{ArtifactEntry, ArtifactReader};
use crate::classify::has_asar_header;
use crate::error::JsError;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

struct AsarFileMeta {
    size: u64,
    offset: u64,
    #[allow(dead_code)]
    integrity_hash: Option<String>,
    unpacked: bool,
}

pub struct AsarArtifactReader {
    path: PathBuf,
    data_offset: u64,
    entries: Vec<ArtifactEntry>,
    file_meta: BTreeMap<String, AsarFileMeta>,
}

impl AsarArtifactReader {
    pub fn new(path: &Path) -> Result<Self, JsError> {
        let data = std::fs::read(path)?;
        if !has_asar_header(&data) {
            return Err(JsError::Format("Invalid ASAR header".to_string()));
        }
        let header_bytes = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as u64;
        let json_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
        let header_json: Value = serde_json::from_slice(&data[16..16 + json_len])
            .map_err(|e| JsError::Format(e.to_string()))?;
        let data_offset = 8 + header_bytes;
        let mut entries = Vec::new();
        let mut file_meta = BTreeMap::new();
        if let Some(files) = header_json.get("files").and_then(|v| v.as_object()) {
            walk_asar_tree(files, "", &mut entries, &mut file_meta);
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(Self {
            path: path.to_path_buf(),
            data_offset,
            entries,
            file_meta,
        })
    }
}

fn walk_asar_tree(
    files: &serde_json::Map<String, Value>,
    prefix: &str,
    entries: &mut Vec<ArtifactEntry>,
    file_meta: &mut BTreeMap<String, AsarFileMeta>,
) {
    for (name, value) in files {
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{}/{}", prefix, name)
        };
        if let Some(nested) = value.get("files").and_then(|v| v.as_object()) {
            entries.push(ArtifactEntry {
                path: path.clone(),
                kind: "directory".to_string(),
                declared_size: None,
                compressed_size: None,
                executable: false,
                encrypted: false,
                declared_sha256: None,
                unpacked: false,
                limitations: vec![],
                adapter_key: path.clone(),
            });
            walk_asar_tree(nested, &path, entries, file_meta);
        } else {
            let size = value.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
            let offset = value
                .get("offset")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let integrity_hash = value
                .get("integrity")
                .and_then(|i| i.get("hash"))
                .and_then(|h| h.as_str())
                .filter(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()));
            let unpacked = value.get("unpacked").and_then(|v| v.as_bool()).unwrap_or(false);
            let limitations = if value.get("link").is_some() {
                vec!["ASAR symlink target was not followed or disclosed.".to_string()]
            } else {
                vec![]
            };
            let kind = if value.get("link").is_some() {
                "symlink"
            } else {
                "file"
            };
            entries.push(ArtifactEntry {
                path: path.clone(),
                kind: kind.to_string(),
                declared_size: Some(size),
                compressed_size: None,
                executable: value
                    .get("executable")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                encrypted: false,
                declared_sha256: integrity_hash.map(|s| s.to_string()),
                unpacked,
                limitations,
                adapter_key: path.clone(),
            });
            if kind == "file" {
                file_meta.insert(
                    path,
                    AsarFileMeta {
                        size,
                        offset,
                        integrity_hash: integrity_hash.map(|s| s.to_string()),
                        unpacked,
                    },
                );
            }
        }
    }
}

impl ArtifactReader for AsarArtifactReader {
    fn format(&self) -> &str {
        "asar"
    }

    fn list_entries(&self) -> Result<Vec<ArtifactEntry>, JsError> {
        Ok(self.entries.clone())
    }

    fn read_entry(&self, entry: &ArtifactEntry) -> Result<Vec<u8>, JsError> {
        if entry.kind != "file" {
            return Err(JsError::Format("Not a regular file".to_string()));
        }
        let meta = self
            .file_meta
            .get(&entry.path)
            .ok_or_else(|| JsError::Format("Unknown ASAR entry".to_string()))?;
        if meta.unpacked {
            let companion = format!("{}.unpacked/{}", self.path.display(), entry.path);
            return std::fs::read(&companion).map_err(|e| JsError::Io(e.to_string()));
        }
        let mut file = File::open(&self.path)?;
        let start = self.data_offset + meta.offset;
        file.seek(std::io::SeekFrom::Start(start))
            .map_err(|e| JsError::Io(e.to_string()))?;
        let mut buf = vec![0u8; meta.size as usize];
        file.read_exact(&mut buf).map_err(|e| JsError::Io(e.to_string()))?;
        Ok(buf)
    }
}
