mod asar;
mod directory;
mod zip;

use crate::error::JsError;
use crate::types::ZIP_NON_ENTRY_TAIL_LIMITATION;
use std::path::Path;

pub use asar::AsarArtifactReader;
pub use directory::DirectoryArtifactReader;
pub use zip::ZipArtifactReader;

#[derive(Debug, Clone)]
pub struct ArtifactEntry {
    pub path: String,
    pub kind: String,
    pub declared_size: Option<u64>,
    pub compressed_size: Option<u64>,
    pub executable: bool,
    pub encrypted: bool,
    pub declared_sha256: Option<String>,
    pub unpacked: bool,
    pub limitations: Vec<String>,
    pub adapter_key: String,
}

#[allow(dead_code)]
pub trait ArtifactReader {
    fn format(&self) -> &str;
    fn list_entries(&self) -> Result<Vec<ArtifactEntry>, JsError>;
    fn read_entry(&self, entry: &ArtifactEntry) -> Result<Vec<u8>, JsError>;
    fn provenance(&self) -> Vec<serde_json::Value> {
        Vec::new()
    }
}

pub fn create_reader(path: &Path, format: &str) -> Result<Option<Box<dyn ArtifactReader>>, JsError> {
    match format {
        "directory" => Ok(Some(Box::new(DirectoryArtifactReader::new(path)?))),
        "zip" | "ipa" | "apk" | "msix" | "appx" => {
            Ok(Some(Box::new(ZipArtifactReader::new(path, format)?)))
        }
        "asar" => Ok(Some(Box::new(AsarArtifactReader::new(path)?))),
        _ => Ok(None),
    }
}

pub fn inventory_limitations(format: &str, has_reader: bool) -> Vec<String> {
    if has_reader && matches!(format, "zip" | "ipa" | "apk" | "msix" | "appx") {
        return vec![ZIP_NON_ENTRY_TAIL_LIMITATION.to_string()];
    }
    if !has_reader {
        return vec!["Artifact has no child container entries.".to_string()];
    }
    Vec::new()
}

